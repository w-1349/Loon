#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import time
import ipaddress
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ================= 配置区 =================
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

# 危险关键字/公共后缀黑名单（两步验证：Keyword查包含，Suffix查相等）
INVALID_KEYWORDS = {
    'com', 'net', 'cn', 'org', 'io', 'co', 'tv', 'cc', 'app', 'dev',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'com.hk',
    'ads', 'api', 'cdn', 'static', 'www', 'download', 'upload'
}
# ==========================================

def get_beijing_time():
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def log(msg, level="INFO"):
    timestamp = get_beijing_time()
    prefix = {"INFO": "ℹ️", "OK": "✅", "ERROR": "❌", "WARN": "⚠️", "DEBUG": "🔍"}.get(level, "•")
    print(f"[{timestamp}] {prefix} {msg}", flush=True)

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({"User-Agent": "Mozilla/5.0 LoonRuleEngine/3.5"})
    return session

def is_valid_domain(domain):
    """修复：支持纯IP作为域名"""
    if not domain or len(domain) > 253: 
        return False
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
        return True
    if not re.match(r'^[a-z0-9\-\.]+$', domain): 
        return False
    labels = domain.split('.')
    return len(labels) >= 2 and not labels[-1].isdigit()

def is_dangerous_keyword(rval):
    """修复：精确的单词边界检测"""
    rval = rval.lower()
    for k in INVALID_KEYWORDS:
        if rval == k:
            return True
        if k in rval:
            idx = rval.find(k)
            before = rval[idx-1] if idx > 0 else ''
            after = rval[idx+len(k)] if idx+len(k) < len(rval) else ''
            if (not before or not before.isalnum()) and \
               (not after or not after.isalnum()):
                return True
    return False

def parse_loon_rule(line):
    """解析Loon规则，过滤空参数"""
    parts = line.split(',')
    if len(parts) < 2: 
        return None
    params = [p.strip().lower() for p in parts[2:] if p.strip()]
    return (parts[0].strip().upper(), parts[1].strip(), params)

def normalize_rule_smart(rtype, rval, rparams):
    """
    按用户需求：
    - 域名类：剔除所有参数
    - IP类：仅保留 no-resolve
    """
    rval = rval.lower()
    if rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        return f"{rtype},{rval}"
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        if "no-resolve" in rparams:
            return f"{rtype},{rval},no-resolve"
        return f"{rtype},{rval}"
    return f"{rtype},{rval}"

def is_covered_by_trie(val, trie):
    """高效字典树匹配"""
    node = trie
    for part in val.split('.')[::-1]:
        if part not in node: 
            return False
        node = node[part]
        if "#" in node: 
            return True
    return False

def dedup_engine(rules):
    """极致去重引擎"""
    stats = {'danger': 0, 'logic': 0, 'exact': 0}
    seen = set()
    unique_base = []
    
    for r in rules:
        p = parse_loon_rule(r)
        if not p: 
            continue
        norm = normalize_rule_smart(*p)
        if norm not in seen:
            seen.add(norm)
            unique_base.append(p)
        else: 
            stats['exact'] += 1

    key_rules, suf_raw, dom_raw, ip_raw, ip6_rules = [], [], [], [], []

    for rtype, rval, rparams in unique_base:
        if rtype == 'DOMAIN-KEYWORD':
            if is_dangerous_keyword(rval):
                stats['danger'] += 1
                continue
            key_rules.append(f"{rtype},{rval}")
            
        elif rtype == 'DOMAIN-SUFFIX':
            if rval in INVALID_KEYWORDS:
                stats['danger'] += 1
                continue
            suf_raw.append((f"{rtype},{rval}", rval))
            
        elif rtype == 'DOMAIN':
            dom_raw.append((f"{rtype},{rval}", rval))
            
        elif rtype == 'IP-CIDR':
            try:
                net = ipaddress.IPv4Network(rval, strict=False)
                ip_raw.append((normalize_rule_smart(rtype, rval, rparams), net))
            except: 
                continue
                
        elif rtype == 'IP-CIDR6':
            ip6_rules.append(normalize_rule_smart(rtype, rval, rparams))

    # 域名去重
    suf_raw.sort(key=lambda x: len(x[1].split('.')))
    trie, final_suf = {}, []
    for rule_str, val in suf_raw:
        if not is_covered_by_trie(val, trie):
            final_suf.append(rule_str)
            node = trie
            for part in val.split('.')[::-1]: 
                node = node.setdefault(part, {})
            node["#"] = True
        else: 
            stats['logic'] += 1

    final_dom = []
    for r, v in dom_raw:
        if is_covered_by_trie(v, trie): 
            stats['logic'] += 1
        else: 
            final_dom.append(r)

    # IP去重
    ip_raw.sort(key=lambda x: x[1].prefixlen)
    kept_ip_nets, final_ip = [], []
    for rule_str, net in ip_raw:
        if not any(k_net.supernet_of(net) for k_net in kept_ip_nets):
            final_ip.append(rule_str)
            kept_ip_nets.append(net)
        else: 
            stats['logic'] += 1

    # 跨类型去重
    final_dom_clean = []
    for r_str in final_dom:
        parts = r_str.split(',')
        if len(parts) < 2:
            final_dom_clean.append(r_str)
            continue
        v = parts[1]
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v):
            try:
                ip_obj = ipaddress.IPv4Address(v)
                if any(ip_obj in k_net for k_net in kept_ip_nets):
                    stats['logic'] += 1
                    continue
            except:
                pass
        final_dom_clean.append(r_str)

    res = final_dom_clean + final_suf + key_rules + final_ip + ip6_rules
    return res, stats

def format_source_stats(source_stats):
    """格式化源统计"""
    max_name_len = max(len(s['name']) for s in source_stats)
    width = max(max_name_len, 10)
    lines = ["# " + "=" * (width + 25)]
    lines.append(f"# {'名称':<{width}} {'原始':>8} {'提取':>8} {'丢弃':>8}")
    lines.append("# " + "-" * (width + 25))
    for s in source_stats:
        lines.append(f"# {s['name']:<{width}} {s['raw']:>8} {s['valid']:>8} {s['raw']-s['valid']:>8}")
    lines.append("# " + "=" * (width + 25))
    return lines

def format_type_stats(final_list):
    """新增：统计各类型规则数量"""
    type_count = {}
    for rule in final_list:
        rtype = rule.split(',')[0] if ',' in rule else 'UNKNOWN'
        type_count[rtype] = type_count.get(rtype, 0) + 1
    
    # 按优先级排序
    prio_order = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'UNKNOWN']
    lines = ["# 类型分布统计:"]
    total = len(final_list)
    
    for t in prio_order:
        if t in type_count:
            count = type_count[t]
            pct = count / total * 100 if total > 0 else 0
            lines.append(f"#   {t:<15} {count:>6} 条 ({pct:>5.1f}%)")
    
    lines.append("# " + "-" * 30)
    lines.append(f"#   {'TOTAL':<15} {total:>6} 条")
    return lines

def main():
    log("🚀 启动规则抓取任务...", "INFO")
    session, all_rules, source_stats = create_session(), [], []
    total_start = time.time()

    for idx, src in enumerate(RULE_SOURCES, 1):
        log(f"[{idx}/{len(RULE_SOURCES)}] 正在请求: {src['name']}")
        try:
            resp = session.get(src['url'], timeout=20)
            resp.raise_for_status()
            raw_lines = resp.text.splitlines()
            processed = []
            for l in raw_lines:
                l = l.strip()
                if not l or any(l.startswith(x) for x in ('#', '!', '[')): 
                    continue
                
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', l): 
                    processed.append(f"IP-CIDR,{l}")
                elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', l): 
                    processed.append(f"DOMAIN,{l}")
                elif l.startswith('.'): 
                    processed.append(f"DOMAIN-SUFFIX,{l[1:]}")
                elif ',' not in l and is_valid_domain(l): 
                    processed.append(f"DOMAIN,{l}")
                else: 
                    processed.append(l)

            all_rules.extend(processed)
            source_stats.append({"name": src['name'], "raw": len(raw_lines), "valid": len(processed)})
            log(f"    完成: 提取 {len(processed)} 条", "OK")
        except Exception as e:
            log(f"    失败: {src['name']} ({e})", "ERROR")

    log("清理冗余逻辑中...", "INFO")
    final_list, stats = dedup_engine(all_rules)
    
    # 排序
    prio = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    final_list.sort(key=lambda x: (prio.get(x.split(',')[0], 99), x.lower()))

    # 构建头部（新增类型统计）
    header = [
        f"# Loon_AD刺客 (修复优化版 v3.7)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 规则统计: {len(final_list)} 条",
        f"# 压缩优化: 剔除危险 {stats['danger']} | 逻辑重复 {stats['logic']} | 完全重复 {stats['exact']}",
        f"# 订阅地址: {SUBSCRIBE_URL}",
    ]
    header.extend(format_source_stats(source_stats))
    # 新增：类型分布统计
    header.extend(format_type_stats(final_list))
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_list))
    
    log(f"任务完成！保存至 {OUTPUT_FILE}，总耗时 {time.time()-total_start:.1f}s", "OK")

if __name__ == "__main__":
    main()
