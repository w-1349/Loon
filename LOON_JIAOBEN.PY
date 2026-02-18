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
REMOVED_LOG_FILE = "Loon_rules.log"
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"

INVALID_KEYWORDS = {
    'com', 'net', 'cn', 'org', 'io', 'co', 'tv', 'cc', 'app', 'dev', 'top', 'xyz', 'info',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'com.hk', 'net.hk', 'org.hk', 'com.tw', 'net.tw', 'org.tw',
    'com.sg', 'com.jp', 'co.uk', 'org.uk', 'com.au', 'com.mo'
}
# ==========================================

def get_beijing_time():
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def log(msg, level="INFO"):
    timestamp = get_beijing_time()
    prefix = {"INFO": "ℹ️", "OK": "✅", "ERROR": "❌"}.get(level, "•")
    print(f"[{timestamp}] {prefix} {msg}", flush=True)

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({"User-Agent": "Mozilla/5.0 LoonRuleEngine/3.5"})
    return session

def is_valid_domain(domain):
    if not domain or len(domain) > 253: return False
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain): return True
    if not re.match(r'^[a-z0-9\-\.]+$', domain): return False
    labels = domain.split('.')
    return len(labels) >= 2 and not labels[-1].isdigit()

def is_dangerous_rule(rval):
    return rval.lower() in INVALID_KEYWORDS

def parse_loon_rule(line):
    parts = line.split(',')
    if len(parts) < 2: return None
    params = [p.strip().lower() for p in parts[2:] if p.strip()]
    return (parts[0].strip().upper(), parts[1].strip(), params)

def normalize_rule_smart(rtype, rval, rparams):
    rval = rval.lower()
    if rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        return f"{rtype},{rval}"
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        return f"{rtype},{rval},no-resolve" if "no-resolve" in rparams else f"{rtype},{rval}"
    return f"{rtype},{rval}"

def get_trie_reason(val, trie):
    node = trie
    parts = val.split('.')[::-1]
    match_path = []
    for part in parts:
        if part not in node: return None
        node = node[part]
        match_path.append(part)
        if "#" in node:
            return ".".join(match_path[::-1])
    return None

def dedup_engine(rules):
    stats = {'danger': 0, 'logic': 0, 'exact': 0}
    seen, unique_base, log_logic = set(), [], []

    for r in rules:
        p = parse_loon_rule(r)
        if not p: continue
        norm = normalize_rule_smart(*p)
        if norm not in seen:
            seen.add(norm)
            unique_base.append(p)
        else: stats['exact'] += 1

    key_rules, suf_raw, dom_raw, ip_raw, ip6_rules = [], [], [], [], []

    for rtype, rval, rparams in unique_base:
        raw_str = normalize_rule_smart(rtype, rval, rparams)
        if is_dangerous_rule(rval):
            stats['danger'] += 1
            log_logic.append(f"[危险拦截] {raw_str:<45} # 命中 SLD 防护")
            continue
        if rtype == 'DOMAIN-KEYWORD': key_rules.append(raw_str)
        elif rtype == 'DOMAIN-SUFFIX': suf_raw.append((raw_str, rval))
        elif rtype == 'DOMAIN': dom_raw.append((raw_str, rval))
        elif rtype == 'IP-CIDR':
            try:
                net = ipaddress.IPv4Network(rval, strict=False)
                ip_raw.append((raw_str, net))
            except: continue
        elif rtype == 'IP-CIDR6': ip6_rules.append(raw_str)

    suf_raw.sort(key=lambda x: len(x[1].split('.')))
    trie, final_suf = {}, []
    for rule_str, val in suf_raw:
        reason = get_trie_reason(val, trie)
        if not reason:
            final_suf.append(rule_str)
            node = trie
            for part in val.split('.')[::-1]: node = node.setdefault(part, {})
            node["#"] = True
        else:
            stats['logic'] += 1
            log_logic.append(f"[逻辑覆盖] {rule_str:<45} # 溯源: DOMAIN-SUFFIX,{reason}")

    final_dom = []
    for r_str, v in dom_raw:
        reason = get_trie_reason(v, trie)
        if reason:
            stats['logic'] += 1
            log_logic.append(f"[逻辑覆盖] {r_str:<45} # 溯源: DOMAIN-SUFFIX,{reason}")
        else: final_dom.append(r_str)

    ip_raw.sort(key=lambda x: x[1].prefixlen)
    kept_ip_nets, final_ip = [], []
    for rule_str, net in ip_raw:
        parent_net = next((k for k in kept_ip_nets if k.supernet_of(net)), None)
        if parent_net:
            stats['logic'] += 1
            log_logic.append(f"[逻辑覆盖] {rule_str:<45} # 溯源: IP-CIDR,{parent_net}")
        else:
            final_ip.append(rule_str)
            kept_ip_nets.append(net)

    final_dom_clean = []
    for r_str in final_dom:
        v = r_str.split(',')[1]
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v):
            try:
                ip_obj = ipaddress.IPv4Address(v)
                covered_by = next((k for k in kept_ip_nets if ip_obj in k), None)
                if covered_by:
                    stats['logic'] += 1
                    log_logic.append(f"[逻辑覆盖] {r_str:<45} # 溯源: IP-CIDR,{covered_by}")
                    continue
            except: pass
        final_dom_clean.append(r_str)

    res = final_dom_clean + final_suf + key_rules + final_ip + ip6_rules
    return res, stats, log_logic

def format_source_stats(source_stats):
    max_name_len = max(len(s['name']) for s in source_stats)
    width = max(max_name_len, 10)
    lines = ["# " + "=" * (width + 35)]
    lines.append(f"# {'名称':<{width}} {'原始规模':>10} {'有效提取':>10} {'物理去重':>10}")
    lines.append("# " + "-" * (width + 35))
    for s in source_stats:
        lines.append(f"# {s['name']:<{width}} {s['raw']:>10} {s['valid']:>10} {s['raw']-s['valid']:>10}")
    lines.append("# " + "=" * (width + 35))
    return lines

def main():
    log("🚀 启动自动化精简任务...", "INFO")
    session, all_rules, source_stats = create_session(), [], []
    total_start = time.time()

    for idx, src in enumerate(RULE_SOURCES, 1):
        log(f"[{idx}/{len(RULE_SOURCES)}] 同步: {src['name']}")
        try:
            resp = session.get(src['url'], timeout=20)
            resp.raise_for_status()
            raw_lines = resp.text.splitlines()
            processed = []
            for l in raw_lines:
                l = l.strip()
                if not l or any(l.startswith(x) for x in ('#', '!', '[')): continue
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', l): processed.append(f"IP-CIDR,{l}")
                elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', l): processed.append(f"DOMAIN,{l}")
                elif l.startswith('.'): processed.append(f"DOMAIN-SUFFIX,{l[1:]}")
                elif ',' not in l and is_valid_domain(l): processed.append(f"DOMAIN,{l}")
                else: processed.append(l)
            all_rules.extend(processed)
            source_stats.append({"name": src['name'], "raw": len(raw_lines), "valid": len(processed)})
        except Exception as e:
            log(f"失败: {src['name']} ({e})", "ERROR")

    final_list, stats, log_logic = dedup_engine(all_rules)
    
    # --- 关键修复：分类统计逻辑 ---
    type_counts = {}
    for r in final_list:
        rtype = r.split(',')[0]
        type_counts[rtype] = type_counts.get(rtype, 0) + 1
    
    # 结果排序
    prio = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    final_list.sort(key=lambda x: (prio.get(x.split(',')[0], 99), x.lower()))

    # --- 关键修复：构建带有详细统计的文件头 ---
    header = [
        f"# Loon 刺客合集 (全量审计增强版)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 总计保留: {len(final_list)} 条规则",
        f"# 类型分布: " + " | ".join([f"{k}: {v}" for k, v in sorted(type_counts.items())]),
        f"# 压缩分析: 逻辑精简 {stats['logic']} | 危险防御 {stats['danger']} | 物理重复 {stats['exact']}",
        f"# 订阅地址: {SUBSCRIBE_URL}",
    ]
    header.extend(format_source_stats(source_stats))
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_list))
    
    with open(REMOVED_LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Loon 自动化审计日志 - {get_beijing_time()}\n")
        f.write(f"# ----------------------------------------------------------\n")
        f.write(f"# 最终规则总数: {len(final_list)}\n")
        f.write(f"# 逻辑精简总数: {len(log_logic)} (A 被 B 覆盖的溯源记录)\n")
        f.write(f"# ----------------------------------------------------------\n\n")
        f.write('\n'.join(log_logic) if log_logic else "无逻辑冲突。")

    log(f"✅ 处理完成！最终规则数: {len(final_list)} 条", "OK")

if __name__ == "__main__":
    main()
