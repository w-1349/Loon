#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 导入HTTP请求库
import requests
# 导入正则表达式库
import re
# 导入时间处理模块
from datetime import datetime, timedelta

# 上游规则源配置列表
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"},
    {"name": "blackmatrix7-Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising_Domain.list"},
    {"name": "blackmatrix7-Advertising", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list"},
]

# 输出文件名
OUTPUT_FILE = "Loon_rules.txt"
# 订阅地址用于文件头
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"


def get_beijing_time():
    # 获取UTC时间
    utc_now = datetime.utcnow()
    # 加8小时转为北京时间
    beijing_time = utc_now + timedelta(hours=8)
    # 格式化时间字符串
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')


def is_valid_domain(domain):
    # 检查空值或超长
    if not domain or len(domain) > 253:
        return False
    # 检查合法字符
    if not re.match(r'^[a-z0-9\-\.]+$', domain):
        return False
    # 检查连续点或首尾点
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    # 分割各级标签
    labels = domain.split('.')
    # 至少两级
    if len(labels) < 2:
        return False
    # 检查每级标签
    for label in labels:
        # 长度检查
        if not 1 <= len(label) <= 63:
            return False
        # 横杠位置检查
        if label.startswith('-') or label.endswith('-'):
            return False
    # 顶级域名不能纯数字
    if labels[-1].isdigit():
        return False
    return True


def is_valid_ip_cidr(ip_str):
    # IPv4 CIDR正则
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    # 正则匹配检查
    if not re.match(pattern, ip_str):
        return False
    try:
        # 分割IP和掩码
        ip_part, mask_part = ip_str.split('/')
        # 掩码转整数
        mask = int(mask_part)
        # 掩码范围检查
        if not (0 <= mask <= 32):
            return False
        # 分割IP四段
        parts = ip_part.split('.')
        # 每段范围检查
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except:
        return False


def is_valid_ip_cidr6(ip_str):
    # 必须含斜杠
    if '/' not in ip_str:
        return False
    try:
        # 从右分割避免冒号干扰
        ip_part, mask_part = ip_str.rsplit('/', 1)
        # 掩码转整数
        mask = int(mask_part)
        # IPv6掩码范围
        if not (0 <= mask <= 128):
            return False
        # 必须含冒号
        if ':' not in ip_part:
            return False
        return True
    except:
        return False


def is_valid_pure_ip(ip_str):
    # 不能有斜杠
    if '/' in ip_str:
        return False
    # 只允许数字和点
    if not re.match(r'^[\d\.]+$', ip_str):
        return False
    # 分割四段
    parts = ip_str.split('.')
    # 必须四段
    if len(parts) != 4:
        return False
    try:
        # 检查每段
        for part in parts:
            # 不能为空
            if not part:
                return False
            # 转整数
            num = int(part)
            # 范围0-255
            if not 0 <= num <= 255:
                return False
            # 禁止前导零
            if len(part) > 1 and part[0] == '0':
                return False
        return True
    except ValueError:
        return False


def is_loon_format(line):
    # 转大写比较
    upper_line = line.upper()
    # 定义所有前缀
    prefixes = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'IP-CIDR6,')
    # 检查是否匹配任一前缀
    for prefix in prefixes:
        if upper_line.startswith(prefix):
            return True
    return False


def parse_loon_rule(line):
    # 逗号分割
    parts = line.split(',')
    # 至少两部分
    if len(parts) < 2:
        return None
    # 提取类型
    rule_type = parts[0].strip().upper()
    # 提取值
    value = parts[1].strip()
    # 提取参数
    params = [p.strip() for p in parts[2:]] if len(parts) > 2 else []
    return (rule_type, value, params)


def normalize_rule(rule_type, value, params):
    # 分离no-resolve
    other_params = [p for p in params if p.lower() != 'no-resolve']
    # 检查是否有no-resolve
    has_no_resolve = any(p.lower() == 'no-resolve' for p in params)
    # 重组参数
    final_params = other_params.copy()
    if has_no_resolve:
        final_params.append('no-resolve')
    # 有参数则拼接
    if final_params:
        return f"{rule_type},{value},{','.join(final_params)}"
    return f"{rule_type},{value}"


def process_loon_line(line):
    # 解析规则
    parsed = parse_loon_rule(line)
    if parsed is None:
        return None
    # 解包
    rule_type, value, params = parsed
    # 支持类型集合
    valid_types = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6'}
    # 类型检查
    if rule_type not in valid_types:
        return None
    # 域名类型清洗no-resolve
    domain_types = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'}
    if rule_type in domain_types:
        params = [p for p in params if p.lower() != 'no-resolve']
    # 根据类型验证值
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
    # 标准化输出
    return normalize_rule(rule_type, value, params)


def process_line_smart(line):
    # 去空白
    line = line.strip()
    # 跳过空行
    if not line:
        return None
    # 跳过注释
    if line.startswith('#') or line.startswith('!') or line.startswith('['):
        return None
    # Loon格式处理
    if is_loon_format(line):
        return process_loon_line(line)
    # IPv4 CIDR处理
    if is_valid_ip_cidr(line):
        return f"IP-CIDR,{line}"
    # IPv6 CIDR处理
    if is_valid_ip_cidr6(line):
        return f"IP-CIDR6,{line}"
    # 纯IPv4处理
    if is_valid_pure_ip(line):
        return f"DOMAIN,{line}"
    # 带点域名处理
    if line.startswith('.'):
        domain = line[1:].lower()
        if is_valid_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"
        return None
    # 普通域名处理
    domain = line.lower()
    if is_valid_domain(domain):
        return f"DOMAIN,{domain}"
    return None


def get_rule_key(rule):
    # 解析规则
    parsed = parse_loon_rule(rule)
    if parsed is None:
        return rule
    # 解包
    rule_type, value, params = parsed
    # 值转小写
    value_lower = value.lower()
    # 检查no-resolve
    has_no_resolve = any(p.lower() == 'no-resolve' for p in params)
    # 其他参数排序
    other_params = sorted([p.lower() for p in params if p.lower() != 'no-resolve'])
    # 返回四元组键
    return (rule_type.upper(), value_lower, tuple(other_params), has_no_resolve)


def get_rule_priority(rule):
    # 解析规则
    parsed = parse_loon_rule(rule)
    if parsed is None:
        return 99
    # 提取类型
    rule_type = parsed[0]
    # 优先级映射
    priority_map = {
        'DOMAIN-KEYWORD': 1,
        'DOMAIN': 2,
        'DOMAIN-SUFFIX': 3,
        'IP-CIDR': 4,
        'IP-CIDR6': 5,
    }
    return priority_map.get(rule_type, 99)


def ip_to_int(ip_str):
    # 尝试转换
    try:
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except:
        return None


def remove_ip_domain_redundant(domain_rules_with_value, ip_cidr_list):
    # 空检查
    if not domain_rules_with_value or not ip_cidr_list:
        return [r for _, r in domain_rules_with_value], 0
    # 初始化
    removed = 0
    kept_rules = []
    # 遍历域名规则
    for domain, rule in domain_rules_with_value:
        # 转IP整数
        ip_int = ip_to_int(domain)
        # 不是IP则保留
        if ip_int is None:
            kept_rules.append(rule)
            continue
        # 检查是否被IP段包含
        is_covered = False
        for kept_ip, kept_mask, _ in ip_cidr_list:
            shift = 32 - kept_mask
            if shift < 0:
                continue
            if (ip_int >> shift) == (kept_ip >> shift):
                is_covered = True
                break
        # 决定保留或移除
        if is_covered:
            removed += 1
        else:
            kept_rules.append(rule)
    return kept_rules, removed


def dedup_rules(rules):
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
    
    # 分类收集
    ip_cidr_rules = []
    ip_cidr6_rules = []
    domain_rules = []
    suffix_rules = []
    keyword_rules = []
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
    
    # 第二层：IP-CIDR包含去重
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
    
    # 第三层.1：DOMAIN被SUFFIX包含
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
    
    # 第三层.2：SUFFIX内部包含
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
    
    # 跨类型去重
    final_domain_rules_with_value = [(d, r) for d, r in domain_rules if r in final_domain_rules]
    final_domain_rules, cross_removed = remove_ip_domain_redundant(final_domain_rules_with_value, kept_ip_cidr)
    
    # 合并结果
    final_rules = []
    final_rules.extend(keyword_rules)
    final_rules.extend(final_domain_rules)
    final_rules.extend(final_suffix_rules)
    final_rules.extend([r for _, _, r in kept_ip_cidr])
    final_rules.extend([r for _, r in ip_cidr6_rules])
    
    total_removed = dup_removed + removed_ip_count + removed_domain_count + redundant_suffix_count + cross_removed
    return final_rules, total_removed


def main():
    # 打印启动信息
    print(f"[{get_beijing_time()}] 🚀 启动规则抓取...")
    print("=" * 60, flush=True)
    
    # 初始化
    all_rules = []
    source_stats = []
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}
    
    # 遍历各源
    for src in RULE_SOURCES:
        try:
            print(f"📥 拉取: {src['name']}...", flush=True)
            resp = requests.get(src['url'], timeout=30, headers=headers)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            processed = [r for r in (process_line_smart(l) for l in lines) if r is not None]
            
            # 单源去重
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
    
    # 全局去重
    print("=" * 60, flush=True)
    print(f"🔄 全局去重优化（总计 {len(all_rules)} 条）...", flush=True)
    final_rules, total_removed = dedup_rules(all_rules)
    final_rules.sort(key=lambda r: (get_rule_priority(r), r.lower()))
    
    # 统计
    type_counts = {}
    for r in final_rules:
        parsed = parse_loon_rule(r)
        if parsed:
            t = parsed[0]
            type_counts[t] = type_counts.get(t, 0) + 1
    
    print(f"\n📊 最终结果: {len(final_rules)} 条", flush=True)
    for t, c in sorted(type_counts.items(), key=lambda x: get_rule_priority(f"{x[0]},")):
        print(f"   • {t}: {c} 条", flush=True)
    
    # 构建文件头
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
    
    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_rules))
    
    print(f"\n💾 已保存: {OUTPUT_FILE}", flush=True)
    print(f"[{get_beijing_time()}] 🎉 完成!", flush=True)


if __name__ == "__main__":
    main()
