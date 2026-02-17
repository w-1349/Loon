#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

# 规则源配置
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"},
    {"name": "blackmatrix7-Advertising", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list"},
    {"name": "blackmatrix7-Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising_Domain.list"},
    {"name": "blackmatrix7-Privacy", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy.list"},
    {"name": "blackmatrix7-Privacy_Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy_Domain.list"},
]

OUTPUT_FILE = "Loon_rules.txt"
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"

def get_beijing_time():
    """获取北京时间"""
    utc_now = datetime.utcnow()
    beijing_time = utc_now + timedelta(hours=8)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')

def is_valid_domain(domain):
    """校验域名格式"""
    if not domain or len(domain) > 253: return False
    if not re.match(r'^[a-z0-9\-\.]+$', domain): return False
    if '..' in domain or domain.startswith('.') or domain.endswith('.'): return False
    labels = domain.split('.')
    if len(labels) < 2: return False
    for label in labels:
        if not 1 <= len(label) <= 63 or label.startswith('-') or label.endswith('-'): return False
    return not labels[-1].isdigit()

def is_valid_ip_cidr(ip_str):
    """校验IPv4 CIDR"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, ip_str): return False
    try:
        ip_part, mask_part = ip_str.split('/')
        return 0 <= int(mask_part) <= 32 and all(0 <= int(p) <= 255 for p in ip_part.split('.'))
    except: return False

def is_valid_ip_cidr6(ip_str):
    """校验IPv6 CIDR"""
    if '/' not in ip_str: return False
    try:
        ip_part, mask_part = ip_str.rsplit('/', 1)
        return 0 <= int(mask_part) <= 128 and ':' in ip_part
    except: return False

def is_valid_pure_ip(ip_str):
    """校验纯IPv4"""
    if '/' in ip_str or not re.match(r'^[\d\.]+$', ip_str): return False
    parts = ip_str.split('.')
    if len(parts) != 4: return False
    try:
        return all(0 <= int(p) <= 255 and not (len(p)>1 and p[0]=='0') for p in parts)
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
    if is_valid_ip_cidr6(line): return f"IP-CIDR6,{line}"
    if is_valid_pure_ip(line): return f"DOMAIN,{line}"
    if line.startswith('.'):
        d = line[1:].lower()
        return f"DOMAIN-SUFFIX,{d}" if is_valid_domain(d) else None
    d = line.lower()
    return f"DOMAIN,{d}" if is_valid_domain(d) else None

def ip_to_int(ip_str):
    """IP转整数"""
    try:
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except: return None

def dedup_rules(rules):
    """高性能去重逻辑"""
    # 1. 基础完全重复去重
    seen_keys = {}
    unique_rules = []
    dup_removed = 0
    for rule in rules:
        p = parse_loon_rule(rule)
        key = (p[0], p[1].lower(), tuple(sorted([x.lower() for x in p[2]])))
        if key not in seen_keys:
            seen_keys[key] = True
            unique_rules.append(rule)
        else: dup_removed += 1
    
    # 分类
    ip_raw, ip6_raw, dom_raw, suf_raw, key_raw = [], [], [], [], []
    for rule in unique_rules:
        p = parse_loon_rule(rule)
        rtype, rval = p[0], p[1].lower()
        if rtype == 'IP-CIDR':
            ip_s, mask_s = rval.split('/')
            ip_raw.append((ip_to_int(ip_s), int(mask_s), rule))
        elif rtype == 'IP-CIDR6': ip6_raw.append(rule)
        elif rtype == 'DOMAIN': dom_raw.append((rval, rule))
        elif rtype == 'DOMAIN-SUFFIX': suf_raw.append((rval, rule))
        elif rtype == 'DOMAIN-KEYWORD': key_raw.append(rule)

    # 2. IP包含去重
    ip_raw.sort(key=lambda x: x[1])
    kept_ip, ip_rem = [], 0
    for ip_i, m, r in ip_raw:
        if any((ip_i >> (32-k[1])) == (k[0] >> (32-k[1])) for k in kept_ip):
            ip_rem += 1
        else: kept_ip.append((ip_i, m, r))

    # 3. 后缀包含去重 (Hash优化)
    suf_raw = [s for s in suf_raw if len(s[0].split('.')) >= 2]
    suf_raw.sort(key=lambda x: len(x[0].split('.')))
    kept_suf_set, final_suf, suf_rem = set(), [], 0
    for d, r in suf_raw:
        parts = d.split('.')
        if any('.'.join(parts[i:]) in kept_suf_set for i in range(1, len(parts)-1)):
            suf_rem += 1
        else: kept_suf_set.add(d); final_suf.append(r)

    # 4. 域名被后缀包含
    final_dom, dom_rem = [], 0
    for d, r in dom_raw:
        if any('.'.join(d.split('.')[i:]) in kept_suf_set for i in range(len(d.split('.'))-1)):
            dom_rem += 1
        else: final_dom.append((d, r))

    # 5. 跨类型去重 (IP域名被CIDR覆盖)
    final_dom_rules, cross_rem = [], 0
    for d, r in final_dom:
        ip_v = ip_to_int(d)
        if ip_v and any((ip_v >> (32-k[1])) == (k[0] >> (32-k[1])) for k in kept_ip):
            cross_rem += 1
        else: final_dom_rules.append(r)

    res = final_dom_rules + final_suf + key_raw + [x[2] for x in kept_ip] + ip6_raw
    total_rem = dup_removed + ip_rem + suf_rem + dom_rem + cross_rem
    return res, total_rem

def main():
    print(f"[{get_beijing_time()}] 🚀 启动...")
    all_rules, source_stats = [], []
    
    for src in RULE_SOURCES:
        try:
            resp = requests.get(src['url'], timeout=30)
            lines = resp.text.splitlines()
            processed = [r for r in (process_line_smart(l) for l in lines) if r]
            # 源内去重统计
            seen = set()
            unique_src = []
            for r in processed:
                if r not in seen: seen.add(r); unique_src.append(r)
            all_rules.extend(unique_src)
            source_stats.append({"name": src['name'], "raw": len(lines), "valid": len(unique_src)})
            print(f"✅ {src['name']} 提取: {len(unique_src)}")
        except: print(f"❌ {src['name']} 失败")

    final, rem_count = dedup_rules(all_rules)
    
    # 排序逻辑
    prio = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    final.sort(key=lambda r: (prio.get(r.split(',')[0].upper(), 99), r.lower()))

    # --- 关键：各项规则分类统计 ---
    type_stats = {}
    for r in final:
        rtype = r.split(',')[0].upper()
        type_stats[rtype] = type_stats.get(rtype, 0) + 1

    header = [
        f"# Loon_AD刺客",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: {len(final)} 条",
        f"# 优化: 移除 {rem_count} 条冗余规则",
        f"# 订阅地址: {SUBSCRIBE_URL}",
        "# " + "="*58
    ]
    # 写入每个源的统计
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")
    
    header.append("# " + "-"*58)
    # 写入各项规则类型的详细统计 (核心修正处)
    for t in sorted(type_stats.keys(), key=lambda x: prio.get(x, 99)):
        header.append(f"# {t}: {type_stats[t]} 条")
    header.append("# " + "="*58)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final))
    print(f"[{get_beijing_time()}] 🎉 任务完成！")

if __name__ == "__main__":
    main()
