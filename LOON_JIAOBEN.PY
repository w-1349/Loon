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
# 订阅地址显示
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"


def get_beijing_time():
    """获取并格式化当前北京时间"""
    utc_now = datetime.utcnow()
    beijing_time = utc_now + timedelta(hours=8) # UTC+8
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')


def is_valid_domain(domain):
    """验证域名格式合法性"""
    if not domain or len(domain) > 253: return False
    if not re.match(r'^[a-z0-9\-\.]+$', domain): return False # 只允许合法字符
    if '..' in domain or domain.startswith('.') or domain.endswith('.'): return False
    labels = domain.split('.')
    if len(labels) < 2: return False # 至少要有二级域名
    for label in labels:
        if not 1 <= len(label) <= 63 or label.startswith('-') or label.endswith('-'):
            return False
    if labels[-1].isdigit(): return False # 顶级域名不能是数字
    return True


def is_valid_ip_cidr(ip_str):
    """验证IPv4 CIDR格式"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, ip_str): return False
    try:
        ip_part, mask_part = ip_str.split('/')
        mask = int(mask_part)
        if not (0 <= mask <= 32): return False
        return all(0 <= int(part) <= 255 for part in ip_part.split('.'))
    except: return False


def is_valid_ip_cidr6(ip_str):
    """验证IPv6 CIDR格式"""
    if '/' not in ip_str: return False
    try:
        ip_part, mask_part = ip_str.rsplit('/', 1)
        mask = int(mask_part)
        return 0 <= mask <= 128 and ':' in ip_part
    except: return False


def is_valid_pure_ip(ip_str):
    """验证纯IPv4地址格式"""
    if '/' in ip_str or not re.match(r'^[\d\.]+$', ip_str): return False
    parts = ip_str.split('.')
    if len(parts) != 4: return False
    try:
        return all(0 <= int(p) <= 255 and not (len(p)>1 and p[0]=='0') for p in parts)
    except: return False


def is_loon_format(line):
    """检查是否已经是Loon标准的规则前缀"""
    prefixes = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'IP-CIDR6,')
    return any(line.upper().startswith(p) for p in prefixes)


def parse_loon_rule(line):
    """解析Loon规则行，拆分为类型、值、参数"""
    parts = line.split(',')
    if len(parts) < 2: return None
    rule_type = parts[0].strip().upper()
    value = parts[1].strip()
    params = [p.strip() for p in parts[2:]] if len(parts) > 2 else []
    return (rule_type, value, params)


def normalize_rule(rule_type, value, params):
    """统一规范化规则输出，保持no-resolve在最后"""
    other_params = [p for p in params if p.lower() != 'no-resolve']
    has_no_resolve = any(p.lower() == 'no-resolve' for p in params)
    if has_no_resolve: other_params.append('no-resolve')
    return f"{rule_type},{value},{','.join(other_params)}" if other_params else f"{rule_type},{value}"


def process_loon_line(line):
    """详细校验并处理Loon格式规则"""
    parsed = parse_loon_rule(line)
    if not parsed: return None
    rule_type, value, params = parsed
    if rule_type in ('DOMAIN', 'DOMAIN-SUFFIX'):
        if not is_valid_pure_ip(value) and not is_valid_domain(value): return None
    elif rule_type == 'IP-CIDR' and not is_valid_ip_cidr(value): return None
    return normalize_rule(rule_type, value, params)


def process_line_smart(line):
    """智能识别非标格式并转换为Loon标准"""
    line = line.strip()
    if not line or any(line.startswith(x) for x in ('#', '!', '[')): return None
    if is_loon_format(line): return process_loon_line(line)
    if is_valid_ip_cidr(line): return f"IP-CIDR,{line}"
    if is_valid_ip_cidr6(line): return f"IP-CIDR6,{line}"
    if is_valid_pure_ip(line): return f"DOMAIN,{line}"
    if line.startswith('.'): # 处理 .example.com 格式
        d = line[1:].lower()
        return f"DOMAIN-SUFFIX,{d}" if is_valid_domain(d) else None
    d = line.lower()
    return f"DOMAIN,{d}" if is_valid_domain(d) else None


def get_rule_key(rule):
    """生成唯一键用于彻底去重"""
    p = parse_loon_rule(rule)
    if not p: return rule
    return (p[0], p[1].lower(), tuple(sorted([x.lower() for x in p[2]])))


def get_rule_priority(rule):
    """定义输出时的排序优先级"""
    p = parse_loon_rule(rule)
    priority_map = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    return priority_map.get(p[0] if p else '', 99)


def ip_to_int(ip_str):
    """IPv4转整数，便于计算网段包含关系"""
    try:
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except: return None


def dedup_rules(rules):
    """
    核心去重优化函数（性能补丁版）
    """
    # 1. 完全相同规则去重
    seen_keys = {}
    unique_rules = []
    dup_removed = 0
    for rule in rules:
        key = get_rule_key(rule)
        if key not in seen_keys:
            seen_keys[key] = True
            unique_rules.append(rule)
        else: dup_removed += 1
    
    # 分类存放以便后续逻辑判断
    ip_cidr_list = []
    ip_cidr6_list = []
    domain_list = []
    suffix_list = []
    keyword_list = []
    
    for rule in unique_rules:
        p = parse_loon_rule(rule)
        if not p: continue
        rtype, rval = p[0], p[1].lower()
        if rtype == 'IP-CIDR':
            ip_s, mask_s = rval.split('/')
            ip_cidr_list.append((ip_to_int(ip_s), int(mask_s), rule))
        elif rtype == 'IP-CIDR6': ip_cidr6_list.append(rule)
        elif rtype == 'DOMAIN': domain_list.append((rval, rule))
        elif rtype == 'DOMAIN-SUFFIX': suffix_list.append((rval, rule))
        elif rtype == 'DOMAIN-KEYWORD': keyword_list.append(rule)

    # 2. IP-CIDR 包含去重（大网段剔除小网段）
    ip_cidr_list.sort(key=lambda x: x[1]) # 按掩码从小到大排
    kept_ip = []
    ip_removed = 0
    for ip_int, mask, rule in ip_cidr_list:
        is_covered = False
        for k_ip, k_mask, _ in kept_ip:
            if (ip_int >> (32-k_mask)) == (k_ip >> (32-k_mask)):
                is_covered = True; break
        if is_covered: ip_removed += 1
        else: kept_ip.append((ip_int, mask, rule))

    # 3. 后缀包含去重（性能核心：使用Hash查找代替全量扫描）
    suffix_list = [(d, r) for d, r in suffix_list if len(d.split('.')) >= 2]
    suffix_list.sort(key=lambda x: len(x[0].split('.'))) # 短域名在前
    kept_suffix_set = set() # 记录已保留的域名集合
    final_suffixes = []
    suffix_removed = 0
    for domain, rule in suffix_list:
        parts = domain.split('.')
        is_redun = False
        # 从当前域名的上一级开始向上逐级检查
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in kept_suffix_set: # O(1) 效率查找
                is_redun = True; break
        if is_redun: suffix_removed += 1
        else:
            kept_suffix_set.add(domain)
            final_suffixes.append(rule)

    # 4. 域名被后缀包含去重
    final_domains = []
    dom_in_suf_removed = 0
    for domain, rule in domain_list:
        parts = domain.split('.')
        is_cov = False
        # 检查该域名的任一级后缀是否已在拦截列表中
        for i in range(len(parts) - 1):
            suf = '.'.join(parts[i:])
            if suf in kept_suffix_set:
                is_cov = True; break
        if is_cov: dom_in_suf_removed += 1
        else: final_domains.append((domain, rule))

    # 5. 跨类型去重：纯IP域名被IP-CIDR覆盖检查
    final_dom_rules = []
    cross_removed = 0
    for domain, rule in final_domains:
        ip_v = ip_to_int(domain)
        is_ip_cov = False
        if ip_v is not None:
            for k_ip, k_mask, _ in kept_ip:
                if (ip_v >> (32-k_mask)) == (k_ip >> (32-k_mask)):
                    is_ip_cov = True; break
        if is_ip_cov: cross_removed += 1
        else: final_dom_rules.append(rule)

    # 合并所有分类好的规则
    final_rules = final_dom_rules + final_suffixes + keyword_list + [r for _,_,r in kept_ip] + ip_cidr6_list
    total_removed = dup_removed + ip_removed + suffix_removed + dom_in_suf_removed + cross_removed
    return final_rules, total_removed


def main():
    print(f"[{get_beijing_time()}] 🚀 脚本启动")
    all_rules = []
    source_stats = []
    
    for src in RULE_SOURCES:
        try:
            print(f"📥 抓取源: {src['name']}...", flush=True)
            resp = requests.get(src['url'], timeout=30)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            processed = [r for r in (process_line_smart(l) for l in lines) if r]
            
            # 源内初步去重统计
            seen = set()
            unique_src = []
            for r in processed:
                if r not in seen:
                    seen.add(r); unique_src.append(r)
            
            source_stats.append({"name": src['name'], "raw": len(lines), "valid": len(unique_src)})
            all_rules.extend(unique_src)
            print(f"   提取成功: {len(unique_src)} 条")
        except Exception as e:
            print(f"❌ 抓取失败: {src['name']} -> {e}")

    print(f"🔄 开始全局优化与去重...", flush=True)
    final, removed_count = dedup_rules(all_rules)
    final.sort(key=lambda r: (get_rule_priority(r), r.lower()))

    # 构建汇总头部
    header = [
        f"# Loon_AD刺客",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: {len(final)} 条",
        f"# 优化: 移除 {removed_count} 条冗余规则",
        f"# 订阅地址: {SUBSCRIBE_URL}",
        "# " + "="*58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final))
    
    print(f"[{get_beijing_time()}] 🎉 任务圆满完成！")

if __name__ == "__main__":
    main()
