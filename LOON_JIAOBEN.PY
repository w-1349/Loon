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
REMOVED_LOG_FILE = "loon_rules.log"
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"

# 严谨危险词库：仅当规则【完全等于】这些词时触发拦截
# 包含顶级域名 (TLD) 与常见的国家/地区级二后缀 (SLD)
INVALID_KEYWORDS = {
    'com', 'net', 'cn', 'org', 'io', 'co', 'tv', 'cc', 'app', 'dev', 'top', 'xyz', 'info',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'com.hk', 'net.hk', 'org.hk', 'com.tw', 'net.tw', 'org.tw',
    'com.sg', 'com.jp', 'co.uk', 'org.uk', 'com.au', 'com.mo'
}
# ==========================================

def get_beijing_time():
    """获取当前格式化的北京时间"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def log(msg, level="INFO"):
    """状态日志打印"""
    timestamp = get_beijing_time()
    prefix = {"INFO": "ℹ️", "OK": "✅", "ERROR": "❌"}.get(level, "•")
    print(f"[{timestamp}] {prefix} {msg}", flush=True)

def create_session():
    """建立带自动重试机制的 HTTP 会话"""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({"User-Agent": "Mozilla/5.0 LoonRuleEngine/3.5"})
    return session

def is_valid_domain(domain):
    """验证域名格式，区分 IP 和标准域名"""
    if not domain or len(domain) > 253: return False
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain): return True
    if not re.match(r'^[a-z0-9\-\.]+$', domain): return False
    labels = domain.split('.')
    return len(labels) >= 2 and not labels[-1].isdigit()

def is_dangerous_rule(rval):
    """
    全等匹配判定。
    防止屏蔽整个 com.cn 或 cn 等后缀导致的大规模访问故障。
    """
    return rval.lower() in INVALID_KEYWORDS

def parse_loon_rule(line):
    """解析 Loon 原始规则行"""
    parts = line.split(',')
    if len(parts) < 2: return None
    params = [p.strip().lower() for p in parts[2:] if p.strip()]
    return (parts[0].strip().upper(), parts[1].strip(), params)

def normalize_rule_smart(rtype, rval, rparams):
    """标准化规则格式"""
    rval = rval.lower()
    if rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        return f"{rtype},{rval}"
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        return f"{rtype},{rval},no-resolve" if "no-resolve" in rparams else f"{rtype},{rval}"
    return f"{rtype},{rval}"

def is_covered_by_trie(val, trie):
    """使用字典树快速判定后缀包含关系"""
    node = trie
    for part in val.split('.')[::-1]:
        if part not in node: return False
        node = node[part]
        if "#" in node: return True
    return False

def dedup_engine(rules):
    """
    深度精简引擎。
    逻辑：去重相同规则 -> 危险判定 -> 后缀包含判定 -> CIDR 网段判定
    """
    stats = {'danger': 0, 'logic': 0, 'exact': 0}
    seen = set()
    unique_base = []
    log_logic = []

    # 1. 物理层去重（跨源完全重复项）
    for r in rules:
        p = parse_loon_rule(r)
        if not p: continue
        norm = normalize_rule_smart(*p)
        if norm not in seen:
            seen.add(norm)
            unique_base.append(p)
        else: 
            stats['exact'] += 1

    key_rules, suf_raw, dom_raw, ip_raw, ip6_rules = [], [], [], [], []

    # 2. 危险拦截与规则分类
    for rtype, rval, rparams in unique_base:
        raw_str = normalize_rule_smart(rtype, rval, rparams)
        
        if is_dangerous_rule(rval):
            stats['danger'] += 1
            log_logic.append(f"[危险拦截] {raw_str} (因试图屏蔽基础域名后缀已被剔除)")
            continue

        if rtype == 'DOMAIN-KEYWORD':
            key_rules.append(raw_str)
        elif rtype == 'DOMAIN-SUFFIX':
            suf_raw.append((raw_str, rval))
        elif rtype == 'DOMAIN':
            dom_raw.append((raw_str, rval))
        elif rtype == 'IP-CIDR':
            try:
                net = ipaddress.IPv4Network(rval, strict=False)
                ip_raw.append((raw_str, net))
            except: continue
        elif rtype == 'IP-CIDR6':
            ip6_rules.append(raw_str)

    # 3. DOMAIN-SUFFIX 内部包含判定 (Trie 算法)
    suf_raw.sort(key=lambda x: len(x[1].split('.')))
    trie, final_suf = {}, []
    for rule_str, val in suf_raw:
        if not is_covered_by_trie(val, trie):
            final_suf.append(rule_str)
            node = trie
            for part in val.split('.')[::-1]: node = node.setdefault(part, {})
            node["#"] = True
        else: 
            stats['logic'] += 1
            log_logic.append(f"[逻辑覆盖] {rule_str:<45} # 被更短的后缀涵盖")

    # 4. DOMAIN 类型被后缀涵盖判定
    final_dom = []
    for r, v in dom_raw:
        if is_covered_by_trie(v, trie): 
            stats['logic'] += 1
            log_logic.append(f"[逻辑覆盖] {r:<45} # 已被后缀规则包含")
        else: 
            final_dom.append(r)

    # 5. IP-CIDR 网段覆盖判定
    ip_raw.sort(key=lambda x: x[1].prefixlen)
    kept_ip_nets, final_ip = [], []
    for rule_str, net in ip_raw:
        is_covered = False
        for k_net in kept_ip_nets:
            if k_net.supernet_of(net):
                is_covered = True
                log_logic.append(f"[逻辑覆盖] {rule_str:<45} # 被大网段 {k_net} 包含")
                break
        if not is_covered:
            final_ip.append(rule_str)
            kept_ip_nets.append(net)
        else: 
            stats['logic'] += 1

    # 6. 纯 IP 跨类覆盖逻辑判定
    final_dom_clean = []
    for r_str in final_dom:
        v = r_str.split(',')[1]
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v):
            try:
                ip_obj = ipaddress.IPv4Address(v)
                if any(ip_obj in k_net for k_net in kept_ip_nets):
                    stats['logic'] += 1
                    log_logic.append(f"[逻辑覆盖] {r_str:<45} # 该 IP 已在网段规则中")
                    continue
            except: pass
        final_dom_clean.append(r_str)

    res = final_dom_clean + final_suf + key_rules + final_ip + ip6_rules
    return res, stats, log_logic

def format_source_stats(source_stats):
    """格式化统计表格"""
    max_name_len = max(len(s['name']) for s in source_stats)
    width = max(max_name_len, 10)
    lines = ["# " + "=" * (width + 25)]
    lines.append(f"# {'名称':<{width}} {'原始':>8} {'有效':>8} {'物理去重':>8}")
    lines.append("# " + "-" * (width + 25))
    for s in source_stats:
        lines.append(f"# {s['name']:<{width}} {s['raw']:>8} {s['valid']:>8} {s['raw']-s['valid']:>8}")
    lines.append("# " + "=" * (width + 25))
    return lines

def main():
    log("🚀 启动规则合并任务 (SLD 防护增强版)...", "INFO")
    session, all_rules, source_stats = create_session(), [], []
    total_start = time.time()

    # 数据同步阶段
    for idx, src in enumerate(RULE_SOURCES, 1):
        log(f"[{idx}/{len(RULE_SOURCES)}] 同步中: {src['name']}")
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
            log(f"同步失败: {src['name']} ({e})", "ERROR")

    # 逻辑分析阶段
    log("正在分析去重逻辑并应用 SLD 防护...", "INFO")
    final_list, stats, log_logic = dedup_engine(all_rules)
    
    # 结果排序 (DOMAIN > SUFFIX > KEYWORD > IP)
    prio = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    final_list.sort(key=lambda x: (prio.get(x.split(',')[0], 99), x.lower()))

    # 文件头构建
    header = [
        f"# Loon 刺客合集 (严谨精简版)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 压缩优化: 危险拦截 {stats['danger']} | 逻辑去重 {stats['logic']} | 跨源物理去重 {stats['exact']}",
        f"# 订阅地址: {SUBSCRIBE_URL}",
    ]
    header.extend(format_source_stats(source_stats))
    
    # 输出结果
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_list))
    
    # 输出日志
    with open(REMOVED_LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Loon 过滤日志 - {get_beijing_time()}\n")
        f.write(f"# ----------------------------------------------------------\n")
        f.write(f"# 逻辑精简总数: {len(log_logic)} 条\n")
        f.write(f"# 物理重复总数: {stats['exact']} 条\n")
        f.write(f"# ----------------------------------------------------------\n\n")
        f.write('\n'.join(log_logic) if log_logic else "本次未发现逻辑冲突项。")

    log(f"✅ 处理完成！保留规则 {len(final_list)} 条 | 耗时: {time.time()-total_start:.1f}s", "OK")

if __name__ == "__main__":
    main()
