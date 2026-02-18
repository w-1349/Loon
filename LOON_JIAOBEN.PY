#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import time
from datetime import datetime, timedelta

# 规则源配置
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"},
    {"name": "ADG", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list"},
    {"name": "ADG_Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising_Domain.list"},
    {"name": "Privacy", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy.list"},
    {"name": "Privacy_Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Privacy/Privacy_Domain.list"},
]

OUTPUT_FILE = "Loon_rules.txt"
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"

# 重试配置
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]


def get_beijing_time():
    """获取北京时间"""
    utc_now = datetime.utcnow()
    beijing_time = utc_now + timedelta(hours=8)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')


def log(msg, level="INFO"):
    """输出日志带时间戳"""
    timestamp = get_beijing_time()
    prefix = {"INFO": "ℹ️", "OK": "✅", "ERROR": "❌", "WARN": "⚠️", "DEBUG": "🔍"}.get(level, "•")
    print(f"[{timestamp}] {prefix} {msg}", flush=True)


def is_valid_domain(domain):
    """校验域名格式"""
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
    return not labels[-1].isdigit()


def is_valid_ip_cidr(ip_str):
    """校验IPv4 CIDR"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, ip_str):
        return False
    try:
        ip_part, mask_part = ip_str.split('/')
        return 0 <= int(mask_part) <= 32 and all(0 <= int(p) <= 255 for p in ip_part.split('.'))
    except:
        return False


def is_valid_ip_cidr6(ip_str):
    """校验IPv6 CIDR"""
    if '/' not in ip_str:
        return False
    try:
        ip_part, mask_part = ip_str.rsplit('/', 1)
        return 0 <= int(mask_part) <= 128 and ':' in ip_part
    except:
        return False


def is_valid_pure_ip(ip_str):
    """校验纯IPv4"""
    if '/' in ip_str or not re.match(r'^[\d\.]+$', ip_str):
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 and not (len(p) > 1 and p[0] == '0') for p in parts)
    except:
        return False


def parse_loon_rule(line):
    """解析Loon规则行"""
    parts = line.split(',')
    if len(parts) < 2:
        return None
    return (parts[0].strip().upper(), parts[1].strip(), [p.strip() for p in parts[2:]])


def normalize_rule(rule_type, value, params):
    """规范化参数"""
    other = [p for p in params if p.lower() != 'no-resolve']
    if any(p.lower() == 'no-resolve' for p in params):
        other.append('no-resolve')
    return f"{rule_type},{value},{','.join(other)}" if other else f"{rule_type},{value}"


def process_line_smart(line):
    """智能转换格式"""
    line = line.strip()
    if not line or any(line.startswith(x) for x in ('#', '!', '[')):
        return None
    
    prefixes = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'IP-CIDR6,')
    
    if any(line.upper().startswith(p) for p in prefixes):
        p = parse_loon_rule(line)
        if not p:
            return None
        rtype, rval, rparams = p
        if rtype in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
            rparams = [x for x in rparams if x.lower() != 'no-resolve']
        return normalize_rule(rtype, rval, rparams)
    
    if is_valid_ip_cidr(line):
        return f"IP-CIDR,{line}"
    
    if is_valid_ip_cidr6(line):
        return f"IP-CIDR6,{line}"
    
    if is_valid_pure_ip(line):
        return f"DOMAIN,{line}"
    
    if line.startswith('.'):
        d = line[1:].lower()
        return f"DOMAIN-SUFFIX,{d}" if is_valid_domain(d) else None
    
    d = line.lower()
    return f"DOMAIN,{d}" if is_valid_domain(d) else None


def ip_to_int(ip_str):
    """IP转整数，增加长度检查防止IndexError"""
    try:
        parts = ip_str.split('.')
        # 安全检查：必须为4段
        if len(parts) != 4:
            return None
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except:
        return None


def fetch_with_retry(url, name):
    """带重试机制的HTTP请求"""
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}
    
    for attempt in range(MAX_RETRIES):
        try:
            start_time = time.time()
            resp = requests.get(url, timeout=30, headers=headers)
            resp.raise_for_status()
            elapsed = time.time() - start_time
            
            content_length = len(resp.content)
            lines_count = len(resp.text.splitlines())
            
            log(f"下载成功: {content_length/1024:.1f}KB, {lines_count} 行, 耗时 {elapsed:.2f}s", "DEBUG")
            return resp.text, lines_count, None
            
        except requests.exceptions.Timeout:
            error_msg = f"连接超时 (attempt {attempt + 1}/{MAX_RETRIES})"
            log(error_msg, "WARN")
        except requests.exceptions.ConnectionError as e:
            error_msg = f"连接错误: {str(e)[:50]} (attempt {attempt + 1}/{MAX_RETRIES})"
            log(error_msg, "WARN")
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP错误 {e.response.status_code}: {str(e)[:50]}"
            log(error_msg, "ERROR")
            if 400 <= e.response.status_code < 500:
                return None, 0, error_msg
        except Exception as e:
            error_msg = f"未知错误: {str(e)[:50]} (attempt {attempt + 1}/{MAX_RETRIES})"
            log(error_msg, "WARN")
        
        if attempt < MAX_RETRIES - 1:
            delay = RETRY_DELAYS[attempt]
            log(f"{delay}秒后重试...", "DEBUG")
            time.sleep(delay)
    
    return None, 0, f"重试{MAX_RETRIES}次后失败"


def dedup_rules(rules):
    """高性能去重逻辑"""
    
    # 第一层：完全相同去重
    seen_keys = {}
    unique_rules = []
    dup_removed = 0
    
    for rule in rules:
        p = parse_loon_rule(rule)
        if not p:
            continue
        key = (p[0], p[1].lower(), tuple(sorted([x.lower() for x in p[2] if x.lower() != 'no-resolve'])))
        if key not in seen_keys:
            seen_keys[key] = True
            unique_rules.append(rule)
        else:
            dup_removed += 1
    
    rules = unique_rules
    
    # 分类收集
    ip_raw, ip6_raw, dom_raw, suf_raw, key_raw = [], [], [], [], []
    
    for rule in rules:
        p = parse_loon_rule(rule)
        if not p:
            continue
        rtype, rval = p[0], p[1].lower()
        
        if rtype == 'IP-CIDR':
            ip_s, mask_s = rval.split('/')
            ip_int = ip_to_int(ip_s)
            if ip_int is not None:
                ip_raw.append((ip_int, int(mask_s), rule))
        elif rtype == 'IP-CIDR6':
            ip6_raw.append(rule)
        elif rtype == 'DOMAIN':
            dom_raw.append((rval, rule))
        elif rtype == 'DOMAIN-SUFFIX':
            suf_raw.append((rval, rule))
        elif rtype == 'DOMAIN-KEYWORD':
            key_raw.append(rule)
    
    # 第二层：IP-CIDR包含去重（升序，大网段优先保留）
    ip_raw.sort(key=lambda x: x[1])
    kept_ip, ip_rem = [], 0
    
    for ip_i, m, r in ip_raw:
        is_covered = False
        for kept_ip_int, kept_mask, _ in kept_ip:
            shift = 32 - kept_mask
            if shift >= 0 and (ip_i >> shift) == (kept_ip_int >> shift):
                is_covered = True
                break
        if is_covered:
            ip_rem += 1
        else:
            kept_ip.append((ip_i, m, r))
    
    # 第三层：后缀去重（短优先，父级先保留）
    suf_raw.sort(key=lambda x: len(x[0].split('.')))
    kept_suf_set, final_suf, suf_rem = set(), [], 0
    
    for d, r in suf_raw:
        parts = d.split('.')
        is_redundant = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in kept_suf_set:
                is_redundant = True
                break
        
        if is_redundant:
            suf_rem += 1
        else:
            kept_suf_set.add(d)
            final_suf.append(r)
    
    # 第四层：域名被后缀包含
    final_dom, dom_rem = [], 0
    
    for d, r in dom_raw:
        parts = d.split('.')
        is_covered = False
        for i in range(len(parts) - 1):
            suffix = '.'.join(parts[i:])
            if suffix in kept_suf_set:
                is_covered = True
                break
        
        if is_covered:
            dom_rem += 1
        else:
            final_dom.append((d, r))
    
    # 第五层：跨类型去重（纯IP域名被CIDR覆盖）
    final_dom_rules, cross_rem = [], 0
    
    for d, r in final_dom:
        ip_v = ip_to_int(d)
        if ip_v is None:
            final_dom_rules.append(r)
            continue
        
        is_covered = False
        for kept_ip_int, kept_mask, _ in kept_ip:
            shift = 32 - kept_mask
            if shift >= 0 and (ip_v >> shift) == (kept_ip_int >> shift):
                is_covered = True
                break
        
        if is_covered:
            cross_rem += 1
        else:
            final_dom_rules.append(r)
    
    # 合并结果：域名 -> 后缀 -> 关键字 -> IPv4 -> IPv6
    res = final_dom_rules + final_suf + key_raw + [x[2] for x in kept_ip] + ip6_raw
    total_rem = dup_removed + ip_rem + suf_rem + dom_rem + cross_rem
    
    return res, total_rem


def format_source_stats(source_stats):
    """格式化源统计信息，对齐输出"""
    if not source_stats:
        return []
    
    max_name_len = max(len(s['name']) for s in source_stats)
    name_width = max(max_name_len, 10)
    
    lines = []
    lines.append("# " + "=" * (name_width + 25))
    lines.append(f"# {'名称':<{name_width}} {'原始':>8} {'提取':>8} {'丢弃':>8}")
    lines.append("# " + "-" * (name_width + 25))
    
    for s in source_stats:
        name = s['name']
        raw = s['raw']
        valid = s['valid']
        dropped = raw - valid
        lines.append(f"# {name:<{name_width}} {raw:>8} {valid:>8} {dropped:>8}")
    
    lines.append("# " + "=" * (name_width + 25))
    return lines


def main():
    """主函数"""
    log("启动规则抓取...", "INFO")
    all_rules, source_stats = [], []
    
    total_start = time.time()
    
    for idx, src in enumerate(RULE_SOURCES, 1):
        log(f"[{idx}/{len(RULE_SOURCES)}] 开始拉取: {src['name']}")
        log(f"    URL: {src['url'][:60]}...", "DEBUG")
        
        content, lines_count, error = fetch_with_retry(src['url'], src['name'])
        
        if error:
            log(f"{src['name']} 失败: {error}", "ERROR")
            source_stats.append({
                "name": src['name'],
                "raw": 0,
                "valid": 0,
                "error": error
            })
            continue
        
        proc_start = time.time()
        processed = [r for r in (process_line_smart(l) for l in content.splitlines()) if r]
        proc_time = time.time() - proc_start
        
        fmt_stats = {"DOMAIN": 0, "DOMAIN-SUFFIX": 0, "DOMAIN-KEYWORD": 0, "IP-CIDR": 0, "IP-CIDR6": 0, "other": 0}
        for r in processed:
            p = parse_loon_rule(r)
            if p and p[0] in fmt_stats:
                fmt_stats[p[0]] += 1
            else:
                fmt_stats["other"] += 1
        
        log(f"    格式识别: D={fmt_stats['DOMAIN']}, D-S={fmt_stats['DOMAIN-SUFFIX']}, "
            f"D-K={fmt_stats['DOMAIN-KEYWORD']}, IP4={fmt_stats['IP-CIDR']}, IP6={fmt_stats['IP-CIDR6']}", "DEBUG")
        
        dedup_start = time.time()
        seen = set()
        unique_src = []
        for r in processed:
            if r not in seen:
                seen.add(r)
                unique_src.append(r)
        dedup_time = time.time() - dedup_start
        
        dropped = len(processed) - len(unique_src)
        log(f"    处理完成: {len(unique_src)} 条 (识别耗时 {proc_time:.2f}s, 去重耗时 {dedup_time:.2f}s, 丢弃 {dropped} 条)", "DEBUG")
        
        all_rules.extend(unique_src)
        source_stats.append({
            "name": src['name'],
            "raw": lines_count,
            "valid": len(unique_src)
        })
        log(f"{src['name']} 完成: {len(unique_src)} 条", "OK")
        
        if idx < len(RULE_SOURCES):
            time.sleep(0.5)
    
    total_elapsed = time.time() - total_start
    log(f"所有源处理完成，总计 {len(all_rules)} 条，耗时 {total_elapsed:.2f}s", "INFO")
    
    log("开始全局去重...", "INFO")
    dedup_start = time.time()
    final, rem_count = dedup_rules(all_rules)
    dedup_time = time.time() - dedup_start
    log(f"全局去重完成: {len(final)} 条 (移除 {rem_count} 条，耗时 {dedup_time:.2f}s)", "INFO")
    
    prio = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    final.sort(key=lambda r: (prio.get(parse_loon_rule(r)[0], 99), r.lower()))
    
    type_stats = {}
    for r in final:
        p = parse_loon_rule(r)
        if p:
            rtype = p[0]
            type_stats[rtype] = type_stats.get(rtype, 0) + 1
    
    header = [
        f"# Loon_AD刺客",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: {len(final)} 条",
        f"# 优化: 移除 {rem_count} 条冗余规则",
        f"# 订阅地址: {SUBSCRIBE_URL}",
    ]
    
    header.extend(format_source_stats(source_stats))
    
    header.append("# " + "-" * 40)
    for t in sorted(type_stats.keys(), key=lambda x: prio.get(x, 99)):
        header.append(f"# {t}: {type_stats[t]} 条")
    header.append("# " + "=" * 40)
    
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header) + '\n\n' + '\n'.join(final))
        log(f"文件已保存: {OUTPUT_FILE} ({len(final)} 条规则)", "OK")
    except Exception as e:
        log(f"文件保存失败: {e}", "ERROR")
        return
    
    log("任务完成！", "OK")


if __name__ == "__main__":
    main()
