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
    
    Args:
        domain (str): 待验证的域名字符串
        
    Returns:
        bool: 是否为有效域名
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
    """
    验证字符串是否为有效的IPv4 CIDR格式（如：192.168.1.0/24）
    
    Args:
        ip_str (str): 待验证的IP CIDR字符串
        
    Returns:
        bool: 是否为有效的IPv4 CIDR格式
    """
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


def is_valid_ip_cidr6(ip_str):
    """
    验证字符串是否为有效的IPv6 CIDR格式（如：2001:db8::/32）
    
    Args:
        ip_str (str): 待验证的IPv6 CIDR字符串
        
    Returns:
        bool: 是否为有效的IPv6 CIDR格式
    """
    if '/' not in ip_str:
        return False
    try:
        ip_part, mask_part = ip_str.rsplit('/', 1)
        mask = int(mask_part)
        if not (0 <= mask <= 128):
            return False
        if ':' not in ip_part:
            return False
        return True
    except:
        return False


def is_valid_pure_ip(ip_str):
    """
    验证字符串是否为有效的纯IPv4地址（不含CIDR掩码）
    
    Args:
        ip_str (str): 待验证的IP地址字符串
        
    Returns:
        bool: 是否为有效的纯IPv4地址
    """
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
    """
    检查行是否为Loon规则格式（以特定前缀开头）
    
    支持的前缀：DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6
    
    Args:
        line (str): 待检查的行字符串
        
    Returns:
        bool: 是否为Loon规则格式
    """
    upper_line = line.upper()
    prefixes = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'IP-CIDR6,')
    for prefix in prefixes:
        if upper_line.startswith(prefix):
            return True
    return False


def parse_loon_rule(line):
    """
    解析Loon规则行，提取规则类型、值和参数
    
    Args:
        line (str): Loon规则行，格式如 "DOMAIN,example.com,REJECT"
        
    Returns:
        tuple: (rule_type, value, params) 或 None（解析失败时）
    """
    parts = line.split(',')
    if len(parts) < 2:
        return None
    rule_type = parts[0].strip().upper()
    value = parts[1].strip()
    params = [p.strip() for p in parts[2:]] if len(parts) > 2 else []
    return (rule_type, value, params)


def normalize_rule(rule_type, value, params):
    """
    规范化规则格式，统一参数顺序（no-resolve参数始终放在最后）
    
    Args:
        rule_type (str): 规则类型
        value (str): 规则值
        params (list): 参数列表
        
    Returns:
        str: 规范化后的规则字符串
    """
    other_params = [p for p in params if p.lower() != 'no-resolve']
    has_no_resolve = any(p.lower() == 'no-resolve' for p in params)
    final_params = other_params.copy()
    if has_no_resolve:
        final_params.append('no-resolve')
    if final_params:
        return f"{rule_type},{value},{','.join(final_params)}"
    return f"{rule_type},{value}"


def process_loon_line(line):
    """
    处理Loon格式的规则行，验证并规范化
    
    Args:
        line (str): 输入的规则行
        
    Returns:
        str: 处理后的规则字符串，或None（无效规则）
    """
    parsed = parse_loon_rule(line)
    if parsed is None:
        return None
    rule_type, value, params = parsed
    valid_types = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6'}
    if rule_type not in valid_types:
        return None
    domain_types = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'}
    if rule_type in domain_types:
        params = [p for p in params if p.lower() != 'no-resolve']
    if rule_type in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
        value_lower = value.lower()
        is_ip = is_valid_pure_ip(value_lower)
        is_domain = is_valid_domain(value_lower)
        if not is_ip and not is_domain:
            return None
    elif rule_type == 'IP-CIDR':
        if not is_valid_ip_cidr(value):
            return None
    elif rule_type == 'IP-CIDR6':
        if not is_valid_ip_cidr6(value):
            return None
    return normalize_rule(rule_type, value, params)


def process_line_smart(line):
    """
    智能处理行，支持多种输入格式自动识别并转换为Loon格式
    
    支持的输入格式：
    - Loon原生格式：直接处理
    - IPv4 CIDR：转换为 IP-CIDR,xxx
    - IPv6 CIDR：转换为 IP-CIDR6,xxx
    - 纯IP地址：转换为 DOMAIN,xxx
    - 以点开头的域名：去除点后转换为 DOMAIN-SUFFIX,xxx
    - 普通域名：转换为 DOMAIN,xxx
    
    Args:
        line (str): 输入的行字符串
        
    Returns:
        str: 转换后的Loon规则，或None（无法识别）
    """
    line = line.strip()
    if not line:
        return None
    if line.startswith('#') or line.startswith('!') or line.startswith('['):
        return None
    if is_loon_format(line):
        return process_loon_line(line)
    if is_valid_ip_cidr(line):
        return f"IP-CIDR,{line}"
    if is_valid_ip_cidr6(line):
        return f"IP-CIDR6,{line}"
    if is_valid_pure_ip(line):
        return f"DOMAIN,{line}"
    if line.startswith('.'):
        domain = line[1:].lower()
        if is_valid_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"
        return None
    domain = line.lower()
    if is_valid_domain(domain):
        return f"DOMAIN,{domain}"
    return None


def get_rule_key(rule):
    """
    生成规则的唯一标识键，用于去重比较
    
    Args:
        rule (str): 规则字符串
        
    Returns:
        tuple: 包含规则类型、小写值、排序后的参数元组、是否有no-resolve标志的元组
    """
    parsed = parse_loon_rule(rule)
    if parsed is None:
        return rule
    rule_type, value, params = parsed
    value_lower = value.lower()
    has_no_resolve = any(p.lower() == 'no-resolve' for p in params)
    other_params = sorted([p.lower() for p in params if p.lower() != 'no-resolve'])
    return (rule_type.upper(), value_lower, tuple(other_params), has_no_resolve)


def get_rule_priority(rule):
    """
    获取规则的排序优先级，用于最终输出排序
    
    优先级顺序（数字越小越靠前）：
    1: DOMAIN (域名)
    2: DOMAIN-SUFFIX (域名后缀)
    3: DOMAIN-KEYWORD (域名关键字)
    4: IP-CIDR (IPv4 CIDR)
    5: IP-CIDR6 (IPv6 CIDR)
    
    Args:
        rule (str): 规则字符串
        
    Returns:
        int: 优先级数值
    """
    parsed = parse_loon_rule(rule)
    if parsed is None:
        return 99
    rule_type = parsed[0]
    priority_map = {
        'DOMAIN': 1,
        'DOMAIN-SUFFIX': 2,
        'DOMAIN-KEYWORD': 3,
        'IP-CIDR': 4,
        'IP-CIDR6': 5,
    }
    return priority_map.get(rule_type, 99)


def ip_to_int(ip_str):
    """
    将IPv4地址字符串转换为整数，用于IP范围计算
    
    Args:
        ip_str (str): IPv4地址字符串
        
    Returns:
        int: IP地址对应的整数，转换失败返回None
    """
    try:
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except:
        return None


def remove_ip_domain_redundant(domain_rules_with_value, ip_cidr_list):
    """
    移除被IP-CIDR范围覆盖的纯IP域名规则
    
    例如：如果存在 IP-CIDR,192.168.1.0/24，则移除 DOMAIN,192.168.1.100
    
    Args:
        domain_rules_with_value (list): 域名规则列表，元素为 (domain, rule) 元组
        ip_cidr_list (list): IP-CIDR规则列表，元素为 (ip_int, mask, rule) 元组
        
    Returns:
        tuple: (保留的规则列表, 移除的规则数量)
    """
    if not domain_rules_with_value or not ip_cidr_list:
        return [r for _, r in domain_rules_with_value], 0
    removed = 0
    kept_rules = []
    for domain, rule in domain_rules_with_value:
        ip_int = ip_to_int(domain)
        if ip_int is None:
            kept_rules.append(rule)
            continue
        is_covered = False
        for kept_ip, kept_mask, _ in ip_cidr_list:
            shift = 32 - kept_mask
            if shift < 0:
                continue
            if (ip_int >> shift) == (kept_ip >> shift):
                is_covered = True
                break
        if is_covered:
            removed += 1
        else:
            kept_rules.append(rule)
    return kept_rules, removed


def dedup_rules(rules):
    """
    对规则列表进行多层去重和优化
    
    去重流程：
    1. 完全相同规则去重
    2. IP-CIDR包含关系去重（移除被更大范围包含的子网）
    3. DOMAIN被DOMAIN-SUFFIX包含去重
    4. DOMAIN-SUFFIX内部包含去重（移除被子后缀包含的规则）
    5. 跨类型去重（移除被IP-CIDR覆盖的纯IP域名）
    
    Args:
        rules (list): 原始规则字符串列表
        
    Returns:
        tuple: (去重后的规则列表, 总共移除的规则数量)
    """
    # 第一层：完全相同去重
    seen_keys = {}
    unique_rules = []
    dup_removed = 0
    for rule in rules:
        key = get_rule_key(rule)
        if key not in seen_keys:
            seen_keys[key] = rule
            unique_rules.append(rule)
        else:
            dup_removed += 1
    rules = unique_rules
    
    # 分类收集各类规则
    ip_cidr_rules = []      # IPv4 CIDR规则
    ip_cidr6_rules = []     # IPv6 CIDR规则
    domain_rules = []       # 精确域名规则
    suffix_rules = []       # 域名后缀规则
    keyword_rules = []      # 域名关键字规则
    
    for rule in rules:
        parsed = parse_loon_rule(rule)
        if parsed is None:
            continue
        rule_type, value, params = parsed
        if rule_type == 'IP-CIDR':
            try:
                ip_str, mask_str = value.split('/')
                mask = int(mask_str)
                ip_parts = ip_str.split('.')
                ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
                ip_cidr_rules.append((ip_int, mask, rule))
            except:
                pass
        elif rule_type == 'IP-CIDR6':
            ip_cidr6_rules.append((value.lower(), rule))
        elif rule_type == 'DOMAIN':
            domain_rules.append((value.lower(), rule))
        elif rule_type == 'DOMAIN-SUFFIX':
            suffix_rules.append((value.lower(), rule))
        elif rule_type == 'DOMAIN-KEYWORD':
            keyword_rules.append((value.lower(), rule))
    
    # 第二层：IP-CIDR包含去重（按掩码从大到小排序，保留大范围）
    ip_cidr_rules.sort(key=lambda x: -x[1])
    kept_ip_cidr = []
    removed_ip_count = 0
    for ip_int, mask, rule in ip_cidr_rules:
        is_covered = False
        for kept_ip, kept_mask, _ in kept_ip_cidr:
            if kept_mask <= mask:
                continue
            shift = 32 - kept_mask
            if shift < 0:
                continue
            if (ip_int >> shift) == (kept_ip >> shift):
                is_covered = True
                break
        if is_covered:
            removed_ip_count += 1
        else:
            kept_ip_cidr.append((ip_int, mask, rule))
    
    # 第三层.1：DOMAIN被SUFFIX包含去重
    suffix_domains = set(d for d, _ in suffix_rules)
    final_domain_rules = []
    removed_domain_count = 0
    for domain, rule in domain_rules:
        parts = domain.split('.')
        is_covered = False
        for i in range(len(parts)):
            suffix = '.'.join(parts[i:])
            if suffix in suffix_domains:
                is_covered = True
                break
        if is_covered:
            removed_domain_count += 1
        else:
            final_domain_rules.append(rule)
    
    # 第三层.2：SUFFIX内部包含去重（按标签数排序，保留父后缀）
    suffix_rules.sort(key=lambda x: len(x[0].split('.')))
    kept_suffix_domains = set()
    final_suffix_rules = []
    redundant_suffix_count = 0
    for domain, rule in suffix_rules:
        parts = domain.split('.')
        is_redundant = False
        for i in range(1, len(parts)):
            parent_suffix = '.'.join(parts[i:])
            if parent_suffix in kept_suffix_domains:
                is_redundant = True
                break
        if is_redundant:
            redundant_suffix_count += 1
        else:
            kept_suffix_domains.add(domain)
            final_suffix_rules.append(rule)
    
    # 跨类型去重：移除被IP-CIDR覆盖的纯IP域名
    final_domain_rules_with_value = [(d, r) for d, r in domain_rules if r in final_domain_rules]
    final_domain_rules, cross_removed = remove_ip_domain_redundant(final_domain_rules_with_value, kept_ip_cidr)
    
    # 合并结果：按域名 -> 后缀 -> 关键字 -> IPv4 -> IPv6的顺序
    final_rules = []
    # DOMAIN规则（精确域名）
    final_rules.extend(final_domain_rules)
    # DOMAIN-SUFFIX规则（域名后缀）
    final_rules.extend(final_suffix_rules)
    # DOMAIN-KEYWORD规则（域名关键字）
    final_rules.extend([r for _, r in keyword_rules])
    # IP-CIDR规则（IPv4）
    final_rules.extend([r for _, _, r in kept_ip_cidr])
    # IP-CIDR6规则（IPv6）
    final_rules.extend([r for _, r in ip_cidr6_rules])
    
    total_removed = dup_removed + removed_ip_count + removed_domain_count + redundant_suffix_count + cross_removed
    return final_rules, total_removed


def main():
    """
    主函数：协调整个规则抓取、处理和输出流程
    
    流程：
    1. 从各源拉取规则
    2. 解析和验证规则
    3. 全局去重优化
    4. 按类型排序输出
    5. 生成统计信息并写入文件
    """
    print(f"[{get_beijing_time()}] 🚀 启动规则抓取...")
    print("=" * 60, flush=True)
    
    all_rules = []          # 存储所有提取的规则
    source_stats = []       # 存储各源的统计信息
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}
    
    # 遍历所有规则源
    for src in RULE_SOURCES:
        try:
            print(f"📥 拉取: {src['name']}...", flush=True)
            resp = requests.get(src['url'], timeout=30, headers=headers)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            # 智能处理每一行
            processed = [r for r in (process_line_smart(l) for l in lines) if r is not None]
            
            # 源内去重
            seen = set()
            unique_processed = []
            for r in processed:
                key = get_rule_key(r)
                if key not in seen:
                    seen.add(key)
                    unique_processed.append(r)
            
            print(f"   原始: {len(lines)} | 提取: {len(unique_processed)}", flush=True)
            source_stats.append({"name": src['name'], "raw": len(lines), "valid": len(unique_processed)})
            all_rules.extend(unique_processed)
            print(f"✅ 完成", flush=True)
        except Exception as e:
            print(f"❌ 失败: {e}", flush=True)
            import traceback
            traceback.print_exc()
    
    print("=" * 60, flush=True)
    print(f"🔄 全局去重优化（总计 {len(all_rules)} 条）...", flush=True)
    
    # 执行全局去重
    final_rules, total_removed = dedup_rules(all_rules)
    
    # 按优先级和字母顺序排序
    final_rules.sort(key=lambda r: (get_rule_priority(r), r.lower()))
    
    # 统计各类型规则数量
    type_counts = {}
    for r in final_rules:
        parsed = parse_loon_rule(r)
        if parsed:
            t = parsed[0]
            type_counts[t] = type_counts.get(t, 0) + 1
    
    print(f"\n📊 最终结果: {len(final_rules)} 条", flush=True)
    for t, c in sorted(type_counts.items(), key=lambda x: get_rule_priority(f"{x[0]},")):
        print(f"   • {t}: {c} 条", flush=True)
    
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
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")
    header.append("# " + "-" * 58)
    for t, c in sorted(type_counts.items(), key=lambda x: get_rule_priority(f"{x[0]},")):
        header.append(f"# {t}: {c}")
    header.append("# " + "=" * 58)
    
    # 写入输出文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_rules))
    
    print(f"\n💾 已保存: {OUTPUT_FILE}", flush=True)
    print(f"[{get_beijing_time()}] 🎉 完成!", flush=True)


if __name__ == "__main__":
    main()
