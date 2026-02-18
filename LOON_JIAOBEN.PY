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
REMOVED_LOG_FILE = "loon_removed_details.log"  # 过滤明细日志
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"

# 危险关键字：防止误删基础域名后缀或关键基础设施
INVALID_KEYWORDS = {
    'com', 'net', 'cn', 'org', 'io', 'co', 'tv', 'cc', 'app', 'dev',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'com.hk',
    'ads', 'api', 'cdn', 'static', 'www', 'download', 'upload'
}
# ==========================================

def get_beijing_time():
    """获取当前的北京时间"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def log(msg, level="INFO"):
    """美化控制台输出"""
    timestamp = get_beijing_time()
    prefix = {"INFO": "ℹ️", "OK": "✅", "ERROR": "❌", "WARN": "⚠️"}.get(level, "•")
    print(f"[{timestamp}] {prefix} {msg}", flush=True)

def create_session():
    """配置带重试机制的 HTTP 请求会话"""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({"User-Agent": "Mozilla/5.0 LoonRuleEngine/3.5"})
    return session

def is_valid_domain(domain):
    """验证域名是否合法（支持纯 IP 识别）"""
    if not domain or len(domain) > 253: return False
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain): return True
    if not re.match(r'^[a-z0-9\-\.]+$', domain): return False
    labels = domain.split('.')
    return len(labels) >= 2 and not labels[-1].isdigit()

def is_dangerous_keyword(rval):
    """精确检测危险关键字，避免误伤子域名（如 api-ads.com 不应被拦截）"""
    rval = rval.lower()
    for k in INVALID_KEYWORDS:
        if rval == k: return True
        if k in rval:
            idx = rval.find(k)
            before = rval[idx-1] if idx > 0 else ''
            after = rval[idx+len(k)] if idx+len(k) < len(rval) else ''
            if (not before or not before.isalnum()) and (not after or not after.isalnum()):
                return True
    return False

def parse_loon_rule(line):
    """将 Loon 规则行解析为 (类型, 值, 参数列表)"""
    parts = line.split(',')
    if len(parts) < 2: return None
    params = [p.strip().lower() for p in parts[2:] if p.strip()]
    return (parts[0].strip().upper(), parts[1].strip(), params)

def normalize_rule_smart(rtype, rval, rparams):
    """标准化输出：域名类剥离冗余参数，IP类保留 no-resolve"""
    rval = rval.lower()
    if rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        return f"{rtype},{rval}"
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        return f"{rtype},{rval},no-resolve" if "no-resolve" in rparams else f"{rtype},{rval}"
    return f"{rtype},{rval}"

def is_covered_by_trie(val, trie):
    """
    核心算法：通过后缀字典树(Trie)反向匹配。
    逻辑：如果字典树中已存在 example.com，则 sub.example.com 会返回 True。
    """
    node = trie
    for part in val.split('.')[::-1]: # 从顶级域名开始逐级往左查
        if part not in node: return False
        node = node[part]
        if "#" in node: return True # 命中终止符，说明已被父域涵盖
    return False

def dedup_engine(rules):
    """极致去重引擎：处理完全重复、逻辑包含、危险拦截"""
    stats = {'danger': 0, 'logic': 0, 'exact': 0}
    seen = set()
    unique_base = []
    log_logic = [] # 记录有价值的逻辑过滤

    # 1. 第一阶段：剔除完全相同的物理行
    for r in rules:
        p = parse_loon_rule(r)
        if not p: continue
        norm = normalize_rule_smart(*p)
        if norm not in seen:
            seen.add(norm)
            unique_base.append(p)
        else: 
            stats['exact'] += 1 # 完全重复不进详细日志，仅计数

    key_rules, suf_raw, dom_raw, ip_raw, ip6_rules = [], [], [], [], []

    # 2. 第二阶段：分类与危险关键字过滤
    for rtype, rval, rparams in unique_base:
        raw_str = normalize_rule_smart(rtype, rval, rparams)
        if rtype == 'DOMAIN-KEYWORD':
            if is_dangerous_keyword(rval):
                stats['danger'] += 1
                log_logic.append(f"[危险拦截] {raw_str} (命中关键字黑名单)")
                continue
            key_rules.append(raw_str)
        elif rtype == 'DOMAIN-SUFFIX':
            if rval in INVALID_KEYWORDS:
                stats['danger'] += 1
                log_logic.append(f"[危险拦截] {raw_str} (禁止顶级域名后缀)")
                continue
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

    # 3. 第三阶段：域名后缀包含去重
    # 
    suf_raw.sort(key=lambda x: len(x[1].split('.'))) # 按域名长度排序，优先处理父域
    trie, final_suf = {}, []
    for rule_str, val in suf_raw:
        if not is_covered_by_trie(val, trie):
            final_suf.append(rule_str)
            # 将新域名加入 Trie 树
            node = trie
            for part in val.split('.')[::-1]: node = node.setdefault(part, {})
            node["#"] = True # 设置终止符
        else: 
            stats['logic'] += 1
            log_logic.append(f"[逻辑覆盖] {rule_str:<40} # 已被上级后缀规则涵盖")

    # 4. 第四阶段：精确域名包含去重
    final_dom = []
    for r, v in dom_raw:
        if is_covered_by_trie(v, trie): 
            stats['logic'] += 1
            log_logic.append(f"[逻辑覆盖] {r:<40} # 已被后缀规则(DOMAIN-SUFFIX)涵盖")
        else: 
            final_dom.append(r)

    # 5. 第五阶段：IP CIDR 掩码包含去重 (大网段覆盖小网段)
    ip_raw.sort(key=lambda x: x[1].prefixlen) # 按掩码长度排序，优先处理大网段
    kept_ip_nets, final_ip = [], []
    for rule_str, net in ip_raw:
        is_covered = False
        for k_net in kept_ip_nets:
            if k_net.supernet_of(net):
                is_covered = True
                log_logic.append(f"[逻辑覆盖] {rule_str:<40} # 已被大网段 {k_net} 涵盖")
                break
        if not is_covered:
            final_ip.append(rule_str)
            kept_ip_nets.append(net)
        else: 
            stats['logic'] += 1

    # 6. 第六阶段：跨类型去重 (检测域名中的 IP 是否在已有网段中)
    final_dom_clean = []
    for r_str in final_dom:
        v = r_str.split(',')[1]
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v): # 如果 DOMAIN 里的值是纯 IP
            try:
                ip_obj = ipaddress.IPv4Address(v)
                if any(ip_obj in k_net for k_net in kept_ip_nets):
                    stats['logic'] += 1
                    log_logic.append(f"[逻辑覆盖] {r_str:<40} # 该 IP 已在网段规则中")
                    continue
            except: pass
        final_dom_clean.append(r_str)

    res = final_dom_clean + final_suf + key_rules + final_ip + ip6_rules
    return res, stats, log_logic

def format_source_stats(source_stats):
    """格式化生成源统计表"""
    max_name_len = max(len(s['name']) for s in source_stats)
    width = max(max_name_len, 10)
    lines = ["# " + "=" * (width + 25)]
    lines.append(f"# {'名称':<{width}} {'原始规模':>8} {'提取条数':>8} {'无效过滤':>8}")
    lines.append("# " + "-" * (width + 25))
    for s in source_stats:
        lines.append(f"# {s['name']:<{width}} {s['raw']:>8} {s['valid']:>8} {s['raw']-s['valid']:>8}")
    lines.append("# " + "=" * (width + 25))
    return lines

def main():
    log("🚀 启动 Loon 规则自动化任务...", "INFO")
    session, all_rules, source_stats = create_session(), [], []
    total_start = time.time()

    # 1. 同步数据源
    for idx, src in enumerate(RULE_SOURCES, 1):
        log(f"[{idx}/{len(RULE_SOURCES)}] 正在拉取: {src['name']}")
        try:
            resp = session.get(src['url'], timeout=20)
            resp.raise_for_status()
            raw_lines = resp.text.splitlines()
            processed = []
            for l in raw_lines:
                l = l.strip()
                if not l or any(l.startswith(x) for x in ('#', '!', '[')): continue
                # 规则预处理：将纯域名、纯网段自动转换为 Loon 格式
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', l): processed.append(f"IP-CIDR,{l}")
                elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', l): processed.append(f"DOMAIN,{l}")
                elif l.startswith('.'): processed.append(f"DOMAIN-SUFFIX,{l[1:]}")
                elif ',' not in l and is_valid_domain(l): processed.append(f"DOMAIN,{l}")
                else: processed.append(l)
            all_rules.extend(processed)
            source_stats.append({"name": src['name'], "raw": len(raw_lines), "valid": len(processed)})
        except Exception as e:
            log(f"同步失败: {src['name']} ({e})", "ERROR")

    # 2. 执行算法逻辑
    log("正在分析域名字典树与 IP 碰撞逻辑...", "INFO")
    final_list, stats, log_logic = dedup_engine(all_rules)
    
    # 3. 对最终结果进行排序，使生成的规则整洁美观
    prio = {'DOMAIN': 1, 'DOMAIN-SUFFIX': 2, 'DOMAIN-KEYWORD': 3, 'IP-CIDR': 4, 'IP-CIDR6': 5}
    final_list.sort(key=lambda x: (prio.get(x.split(',')[0], 99), x.lower()))

    # 4. 构建文件头部注释
    header = [
        f"# Loon 刺客规则 (自动化版)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 压缩优化: 拦截危险 {stats['danger']} | 逻辑重复 {stats['logic']} | 跨源完全重复 {stats['exact']}",
        f"# 订阅地址: {SUBSCRIBE_URL}",
    ]
    header.extend(format_source_stats(source_stats))
    
    # 5. 持久化存储
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n' + '\n'.join(final_list))
    
    # 6. 生成过滤日志（仅包含逻辑过滤，页尾显示完全重复数）
    with open(REMOVED_LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Loon 过滤日志 - {get_beijing_time()}\n" + "="*80 + "\n")
        f.write(f"# 逻辑过滤总数: {len(log_logic)} 条 (详情如下)\n")
        f.write(f"# 完全重复总数: {stats['exact']} 条 (明细已省略)\n")
        f.write("="*80 + "\n\n")
        f.write('\n'.join(log_logic))
    
    log(f"✅ 任务成功！生成规则 {len(final_list)} 条 | 耗时 {time.time()-total_start:.1f}s", "OK")

if __name__ == "__main__":
    main()
