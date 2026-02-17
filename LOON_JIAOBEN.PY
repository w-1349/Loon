#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

# 规则源配置列表，按优先级排序
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"},
    {"name": "Advertising", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list"},
    {"name": "Advertising_Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising_Domain.list"},
    {"name": "Privacy", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy.list"},
    {"name": "Privacy_Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy_Domain.list"},
]

# 输出文件路径
OUTPUT_FILE = "Loon_rules.txt"
# 订阅地址
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"


def get_beijing_time():
    """
    获取当前北京时间
    Returns:
        str: 格式化后的北京时间字符串，格式为 'YYYY-MM-DD HH:MM:SS'
    """
    utc_now = datetime.utcnow()
    beijing_time = utc_now + timedelta(hours=8)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')


def is_valid_domain(domain):
    """
    验证字符串是否为有效的域名格式
    验证规则：
    - 长度不超过253个字符
    - 只能包含小写字母、数字、连字符和点号
    - 不能以点号开头或结尾，不能包含连续点号
    - 至少包含两个标签（如：example.com）
    - 每个标签长度1-63字符，不能以连字符开头或结尾
    - 顶级域名不能全是数字
    """
    if not domain or len(domain) > 253:
        return False
    if not re.match(r'^[a-z0-9\-\.]+$', domain):
        return False
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not 1 <= len(label) <= 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    if labels[-1].isdigit():
        return False
    return True


def is_valid_ip_cidr(ip_str):
    """验证字符串是否为有效的IPv4 CIDR格式"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, ip_str):
        return False
    try:
        ip_part, mask_part = ip_str.split('/')
        mask = int(mask_part)
        if not (0 <= mask <= 32):
            return False
        parts = ip_part.split('.')
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except:
        return False


def is_valid_pure_ip(ip_str):
    """验证字符串是否为有效的纯IPv4地址"""
    if '/' in ip_str:
        return False
    if not re.match(r'^[\d\.]+$', ip_str):
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        for part in parts:
            if not part:
                return False
            num = int(part)
            if not 0 <= num <= 255:
                return False
            if len(part) > 1 and part[0] == '0':
                return False
        return True
    except ValueError:
        return False


def is_loon_format(line):
    """检查行是否为Loon规则格式"""
    upper_line = line.upper()
    prefixes = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'IP-CIDR6,')
    return any(upper_line.startswith(prefix) for prefix in prefixes)


def parse_loon_rule(line):
    """解析Loon规则行，提取规则类型、值和参数"""
    parts = line.split(',')
    if len(parts) < 2:
        return None
    rule_type = parts[0].strip().upper()
    value = parts[1].strip()
    params = [p.strip() for p in parts[2:]] if len(parts) > 2 else []
    return (rule_type, value, params)


def normalize_rule(rule_type, value, params):
    """规范化规则格式，统一参数顺序"""
    other_params = [p for p in params if p.lower() != 'no-resolve']
    has_no_resolve = any(p.lower() == 'no-resolve' for p in params)
    final_params = other_params.copy()
    if has_no_resolve:
        final_params.append('no-resolve')
    if final_params:
        return f"{rule_type},{value},{','.join(final_params)}"
    return f"{rule_type},{value}"


def process_line_smart(line):
    """智能处理行，支持多种输入格式自动识别并转换为Loon格式"""
    line = line.strip()
    if not line or any(line.startswith(x) for x in ('#', '!', '[')):
        return None
    if is_loon_format(line):
        parsed = parse_loon_rule(line)
        if parsed:
            return normalize_rule(parsed[0], parsed[1], parsed[2])
    if is_valid_ip_cidr(line):
        return f"IP-CIDR,{line}"
    if is_valid_pure_ip(line):
        return f"DOMAIN,{line}"
    if line.startswith('.'):
        domain = line[1:].lower()
        if is_valid_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"
    domain = line.lower()
    if is_valid_domain(domain):
        return f"DOMAIN,{domain}"
    return None


def get_rule_priority(rule):
    """获取规则的排序优先级"""
    parsed = parse_loon_rule(rule)
    if not parsed: return 99
    priority_map = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    return priority_map.get(parsed[0], 99)


def dedup_rules(rules):
    """
    对规则列表进行多层去重和优化
    使用哈希查表法确保高性能处理
    """
    # 第一层：完全相同去重
    unique_rules = []
    seen_keys = set()
    for rule in rules:
        p = parse_loon_rule(rule)
        if not p: continue
        key = (p[0], p[1].lower(), tuple(sorted([x.lower() for x in p[2]])))
        if key not in seen_keys:
            seen_keys.add(key)
            unique_rules.append(rule)
    
    # 分类收集
    ip_cidr_list = []
    domain_list = []
    suffix_list = []
    other_list = []

    for rule in unique_rules:
        p = parse_loon_rule(rule)
        rtype, rval = p[0], p[1].lower()
        if rtype == 'IP-CIDR':
            parts = rval.split('/')
            ip_int = sum(int(b) << (24 - 8 * i) for i, b in enumerate(parts[0].split('.')))
            ip_cidr_list.append({'int': ip_int, 'mask': int(parts[1]), 'raw': rule})
        elif rtype == 'DOMAIN': domain_list.append((rval, rule))
        elif rtype == 'DOMAIN-SUFFIX': suffix_list.append((rval, rule))
        else: other_list.append(rule)

    # 第二层：IP-CIDR 去重 (升序：大范围在前)
    ip_cidr_list.sort(key=lambda x: x['mask'])
    kept_ip = []
    removed_count = 0
    for item in ip_cidr_list:
        is_covered = any(item['int'] >> (32 - k['mask']) == k['int'] >> (32 - k['mask']) for k in kept_ip)
        if is_covered: removed_count += 1
        else: kept_ip.append(item)

    # 第三层：后缀及域名去重 (哈希路径匹配优化)
    # 过滤单标签后缀 (例如 .com)，只处理多标签后缀
    valid_suffixes = [s for s in suffix_list if len(s[0].split('.')) >= 2]
    valid_suffixes.sort(key=lambda x: len(x[0].split('.')))
    
    kept_suffix_set = set()
    final_suffix_rules = []
    for d, r in valid_suffixes:
        parts = d.split('.')
        # 检查父域是否已在后缀规则中
        if any('.'.join(parts[i:]) in kept_suffix_set for i in range(1, len(parts) - 1)):
            removed_count += 1
        else:
            kept_suffix_set.add(d)
            final_suffix_rules.append(r)

    # 精确域名被后缀覆盖去重
    final_domain_rules = []
    for d, r in domain_list:
        parts = d.split('.')
        if any('.'.join(parts[i:]) in kept_suffix_set for i in range(len(parts) - 1)):
            removed_count += 1
        else:
            # 跨类型去重：被IP范围覆盖的纯IP域名
            ip_val = sum(int(b) << (24 - 8 * i) for i, b in enumerate(d.split('.'))) if re.match(r'^[\d\.]+$', d) and d.count('.') == 3 else None
            is_ip_covered = False
            if ip_val:
                is_ip_covered = any(ip_val >> (32 - k['mask']) == k['int'] >> (32 - k['mask']) for k in kept_ip)
            
            if is_ip_covered: removed_count += 1
            else: final_domain_rules.append(r)

    # 合并结果
    final_rules = final_domain_rules + final_suffix_rules + other_list + [x['raw'] for x in kept_ip]
    return final_rules, removed_count


def main():
    """主函数：执行规则拉取、优化及写入"""
    print(f"[{get_beijing_time()}] 🚀 启动规则抓取...")
    all_rules = []
    source_stats = []
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}

    for src in RULE_SOURCES:
        try:
            print(f"📥 拉取: {src['name']}...", flush=True)
            resp = requests.get(src['url'], timeout=30, headers=headers)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            processed = [r for r in (process_line_smart(l) for l in lines) if r]
            
            # 源内去重并统计
            unique_p = []
            seen = set()
            for r in processed:
                p = parse_loon_rule(r)
                k = (p[0], p[1].lower())
                if k not in seen:
                    seen.add(k); unique_p.append(r)
            
            all_rules.extend(unique_p)
            source_stats.append({"name": src['name'], "raw": len(lines), "valid": len(unique_p)})
            print(f"✅ 完成 ({len(unique_p)} 条)", flush=True)
        except Exception as e:
            print(f"❌ 失败: {e}", flush=True)

    print(f"🔄 执行全局去重与高性能优化...", flush=True)
    final_rules, total_removed = dedup_rules(all_rules)
    final_rules.sort(key=lambda r: (get_rule_priority(r), r.lower()))

    # 构建文件头部信息
    header = [
        f"# Loon_AD刺客",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: {len(final_rules)} 条",
        f"# 优化: 移除 {total_removed} 条冗余规则",
        f"# 订阅地址: {SUBSCRIBE_URL}",
        "# " + "=" * 58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 有效 {s['valid']}")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_rules))
    
    print(f"[{get_beijing_time()}] 🎉 任务完成，已保存至 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
