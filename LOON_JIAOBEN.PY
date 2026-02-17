#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

# 规则源配置列表
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"},
    {"name": "Advertising", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list"},
    {"name": "Advertising_Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising_Domain.list"},
    {"name": "Privacy", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy.list"},
    {"name": "Privacy_Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy_Domain.list"},
]

OUTPUT_FILE = "Loon_rules.txt"
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"

def get_beijing_time():
    """获取当前北京时间"""
    utc_now = datetime.utcnow()
    beijing_time = utc_now + timedelta(hours=8)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')

def is_valid_domain(domain):
    """验证域名格式"""
    if not domain or len(domain) > 253: return False
    if not re.match(r'^[a-z0-9\-\.]+$', domain): return False
    if '..' in domain or domain.startswith('.') or domain.endswith('.'): return False
    labels = domain.split('.')
    if len(labels) < 2: return False
    for label in labels:
        if not 1 <= len(label) <= 63 or label.startswith('-') or label.endswith('-'): return False
    return not labels[-1].isdigit()

def is_valid_ip_cidr(ip_str):
    """验证IPv4 CIDR格式"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, ip_str): return False
    try:
        ip_part, mask_part = ip_str.split('/')
        mask = int(mask_part)
        return 0 <= mask <= 32 and all(0 <= int(p) <= 255 for p in ip_part.split('.'))
    except: return False

def is_valid_pure_ip(ip_str):
    """验证纯IPv4地址"""
    if '/' in ip_str or not re.match(r'^[\d\.]+$', ip_str): return False
    parts = ip_str.split('.')
    if len(parts) != 4: return False
    try:
        return all(0 <= int(part) <= 255 and not (len(part) > 1 and part[0] == '0') for part in parts)
    except: return False

def parse_loon_rule(line):
    """解析Loon规则行"""
    parts = line.split(',')
    if len(parts) < 2: return None
    return (parts[0].strip().upper(), parts[1].strip(), [p.strip() for p in parts[2:]])

def normalize_rule(rule_type, value, params):
    """规范化参数"""
    other = [p for p in params if p.lower() != 'no-resolve']
    if any(p.lower() == 'no-resolve' for p in params): other.append('no-resolve')
    return f"{rule_type},{value},{','.join(other)}" if other else f"{rule_type},{value}"

def process_line_smart(line):
    """智能转换格式"""
    line = line.strip()
    if not line or any(line.startswith(x) for x in ('#', '!', '[')): return None
    prefixes = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'IP-CIDR6,')
    if any(line.upper().startswith(p) for p in prefixes):
        p = parse_loon_rule(line)
        return normalize_rule(p[0], p[1], p[2]) if p else None
    if is_valid_ip_cidr(line): return f"IP-CIDR,{line}"
    if is_valid_pure_ip(line): return f"DOMAIN,{line}"
    if line.startswith('.'):
        d = line[1:].lower()
        return f"DOMAIN-SUFFIX,{d}" if is_valid_domain(d) else None
    d = line.lower()
    return f"DOMAIN,{d}" if is_valid_domain(d) else None

def dedup_rules(rules, total_extracted):
    """
    全局去重与优化。
    逻辑：最终保留数 = 总提取数 - 冗余数。
    """
    # 1. 跨源完全相同去重
    seen_keys = {}
    unique_list = []
    for rule in rules:
        p = parse_loon_rule(rule)
        if not p: continue
        # 唯一键：类型 + 值 + 排序后的参数
        key = (p[0], p[1].lower(), tuple(sorted([x.lower() for x in p[2]])))
        if key not in seen_keys:
            seen_keys[key] = True
            unique_list.append(rule)

    # 2. 逻辑包含去重
    ip_raw, domain_raw, suffix_raw, other_raw = [], [], [], []
    for rule in unique_list:
        p = parse_loon_rule(rule)
        rtype, rval = p[0], p[1].lower()
        if rtype == 'IP-CIDR':
            parts = rval.split('/')
            ip_int = sum(int(b) << (24 - 8 * i) for i, b in enumerate(parts[0].split('.')))
            ip_raw.append({'int': ip_int, 'mask': int(parts[1]), 'raw': rule})
        elif rtype == 'DOMAIN': domain_raw.append((rval, rule))
        elif rtype == 'DOMAIN-SUFFIX': suffix_raw.append((rval, rule))
        else: other_raw.append(rule)

    # IP 包含关系
    ip_raw.sort(key=lambda x: x['mask'])
    kept_ip = []
    for item in ip_raw:
        if not any(item['int'] >> (32 - k['mask']) == k['int'] >> (32 - k['mask']) for k in kept_ip):
            kept_ip.append(item)

    # 后缀保护与包含关系 (只保留标签数 >= 2 的后缀)
    suffix_raw = [s for s in suffix_raw if len(s[0].split('.')) >= 2]
    suffix_raw.sort(key=lambda x: len(x[0].split('.')))
    kept_suffix_set = set()
    final_suffixes = []
    for d, r in suffix_raw:
        parts = d.split('.')
        if not any('.'.join(parts[i:]) in kept_suffix_set for i in range(1, len(parts) - 1)):
            kept_suffix_set.add(d)
            final_suffixes.append(r)

    # 精确域名优化
    final_domains = []
    for d, r in domain_raw:
        parts = d.split('.')
        # 检查是否被后缀覆盖
        if any('.'.join(parts[i:]) in kept_suffix_set for i in range(len(parts) - 1)):
            continue
        # 检查是否被IP覆盖
        if re.match(r'^[\d\.]+$', d) and d.count('.') == 3:
            ip_v = sum(int(b) << (24 - 8 * i) for i, b in enumerate(d.split('.')))
            if any(ip_v >> (32 - k['mask']) == k['int'] >> (32 - k['mask']) for k in kept_ip):
                continue
        final_domains.append(r)

    final_rules = final_domains + final_suffixes + other_raw + [x['raw'] for x in kept_ip]
    
    # 计算逻辑：冗余数 = 原始总提取 - 最终保留条数
    total_redundant = total_extracted - len(final_rules)
    return final_rules, total_redundant

def main():
    print(f"[{get_beijing_time()}] 🚀 启动抓取...")
    all_extracted_rules = []
    source_stats = []
    
    for src in RULE_SOURCES:
        try:
            resp = requests.get(src['url'], timeout=30)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            # 模拟代码1风格：源内简单去重
            source_processed = [r for r in (process_line_smart(l) for l in lines) if r]
            unique_in_source = []
            seen = set()
            for r in source_processed:
                if r not in seen:
                    seen.add(r); unique_in_source.append(r)
            
            all_extracted_rules.extend(unique_in_source)
            source_stats.append({"name": src['name'], "raw": len(lines), "valid": len(unique_in_source)})
            print(f"   源: {src['name']} | 原始: {len(lines)} | 提取: {len(unique_in_source)}")
        except Exception as e:
            print(f"❌ {src['name']} 失败")

    total_extracted_count = len(all_extracted_rules)
    final_rules, total_removed = dedup_rules(all_extracted_rules, total_extracted_count)
    
    # 简单排序
    priority = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    final_rules.sort(key=lambda r: (priority.get(r.split(',')[0].upper(), 99), r.lower()))

    header = [
        f"# Loon_AD刺客",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: {len(final_rules)} 条",
        f"# 优化: 移除 {total_removed} 条冗余规则",
        f"# 订阅地址: {SUBSCRIBE_URL}",
        "# " + "="*58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_rules))
    print(f"[{get_beijing_time()}] 🎉 完成！优化移除: {total_removed}")

if __name__ == "__main__":
    main()
