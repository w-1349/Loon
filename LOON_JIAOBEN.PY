#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# —— 核心配置区 ——
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://adrules.top/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"}
]
OUTPUT_FILE = "Loon_rules.txt"
# 自动适配你的 Loon 仓库地址
SUBSCRIBE_URL = "https://raw.githubusercontent.com/ddcm1349/Loon/main/Loon_rules.txt"

def create_retry_session():
    """创建稳定请求会话"""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session

def clean_domain(line, source_name):
    """
    高效清洗逻辑：
    1. 针对 anti-ad: 识别开头的 . 直接提取域名部分
    2. 针对 AdRules: 识别 DOMAIN 或 DOMAIN-SUFFIX 并提取
    """
    line = line.strip()
    if not line or line.startswith(('#', '!', '[')): 
        return None

    # 逻辑 A：如果这一行包含逗号 (常见于 AdRules 的 DOMAIN, 或 DOMAIN-SUFFIX,)
    if ',' in line:
        parts = line.split(',')
        for part in parts:
            p = part.strip()
            # 只要包含点且不是纯大写指令，它就是域名
            if '.' in p and not p.isupper():
                line = p
                break
    
    # 逻辑 B：处理开头的 . (常见于 anti-ad)
    line = line.lstrip('.')
    
    # 统一转小写并去除可能存在的干扰
    line = line.lower().split('^')[0].split('/')[0]
    
    # 最终验证合法性
    if '.' in line and re.match(r'^[a-z0-9\-\.]+$', line):
        return line
    return None

def compress_domains(domain_list):
    """子域名冗余压缩：若有 abc.com 则剔除 sub.abc.com"""
    sorted_domains = sorted(list(domain_list), key=len)
    final_list = []
    redundant_count = 0
    for domain in sorted_domains:
        is_redundant = False
        for root in final_list:
            if domain.endswith('.' + root) or domain == root:
                is_redundant = True
                redundant_count += 1
                break
        if not is_redundant:
            final_list.append(domain)
    return final_list, redundant_count

def main():
    session = create_retry_session()
    source_stats = []
    all_valid_domains = []
    global_raw_total = 0

    print("="*50 + "\n🚀 开始执行 Loon 规则高效合并\n" + "="*50)

    for src in RULE_SOURCES:
        try:
            print(f"📥 正在拉取【{src['name']}】...")
            resp = session.get(src['url'], timeout=30)
            lines = resp.text.splitlines()
            
            raw_count = len(lines)
            valid_list = []
            for l in lines:
                domain = clean_domain(l, src['name'])
                if domain:
                    valid_list.append(domain)
            
            # 源内去重
            unique_src = list(dict.fromkeys(valid_list))
            inner_dedup = len(valid_list) - len(unique_src)
            
            source_stats.append({
                "name": src['name'],
                "url": src['url'],
                "raw": raw_count,
                "valid": len(valid_list),
                "unique": len(unique_src),
                "inner_dedup": inner_dedup
            })
            
            all_valid_domains.extend(unique_src)
            global_raw_total += raw_count
            print(f"✅ 【{src['name']}】提取成功: {len(unique_src)} 条")

        except Exception as e:
            print(f"❌ 【{src['name']}】拉取失败: {e}")

    # 全局去重与压缩
    unique_global = list(dict.fromkeys(all_valid_domains))
    cross_dedup = len(all_valid_domains) - len(unique_global)
    final_domains, compressed_count = compress_domains(unique_global)
    
    # 时间同步
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

    # —— 构建详细统计注释 ——
    header = [
        f"# Loon 域名集合 (DOMAIN-SET) 高效合并版",
        f"# 生成时间 (北京时间) : {beijing_time}",
        f"# 规则源地址:",
    ]
    for i, s in enumerate(source_stats, 1):
        header.append(f"#   {i}. {s['name']} 规则: {s['url']}")
    header.append(f"#   本规则订阅地址: {SUBSCRIBE_URL}")
    header.append("# " + "="*72)
    
    header.append("# 【各规则源单独统计】")
    for i, s in enumerate(source_stats, 1):
        header.append(f"#   {i}. {s['name']} | 原始行: {s['raw']} | 有效域名: {s['valid']} | 源内去重: {s['inner_dedup']}")
    header.append("# " + "="*72)

    header.append("# 【全局合并统计】")
    header.append(f"# 原始总行数汇总: {global_raw_total} 条")
    header.append(f"# 跨源重复去重数: {cross_dedup} 条 | 子域冗余压缩数: {compressed_count} 条")
    header.append(f"# 最终全局保留总数: {len(final_domains)} 条")
    header.append("# " + "="*72 + "\n")

    # 写入文件，统一采用 . 前缀实现高效后缀匹配
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))
        f.write('\n'.join([f".{d}" for d in sorted(final_domains)]))

    print(f"\n📊 任务完成！最终保留: {len(final_domains)} 条")

if __name__ == "__main__":
    main()
