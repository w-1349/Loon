#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Loon 域名集合自动化合并工具 - 纯净域名版
✅ 移除前缀点，保持文件清爽
📊 包含：原始统计、有效提取、源内去重、子域压缩、跨源去重
"""

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
# 自动适配你的仓库地址
SUBSCRIBE_URL = "https://raw.githubusercontent.com/ddcm1349/Loon/main/Loon_rules.txt"

def create_retry_session():
    """创建稳定请求会话，防止拉取时网络波动"""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session

def clean_domain(line):
    """
    通用清洗逻辑：
    从 DOMAIN, / DOMAIN-SUFFIX, / || / . 中精准抠出域名主体
    """
    line = line.strip()
    if not line or line.startswith(('#', '!', '[')): 
        return None

    # 1. 处理逗号分隔格式 (针对 AdRules 的 DOMAIN/DOMAIN-SUFFIX)
    if ',' in line:
        parts = line.split(',')
        for part in parts:
            p = part.strip()
            # 包含点且不是指令（全大写）则为域名
            if '.' in p and not p.isupper() and not p.startswith('/'):
                line = p
                break
    
    # 2. 移除常见的 Adblock 语法和前缀符号
    if line.startswith('||'):
        line = line[2:].split('^')[0]
    
    # 3. 统一去除前缀点，并全部转为小写
    line = line.lstrip('.').lower().split('/')[0].split('^')[0]
    
    # 4. 合法性正则验证
    if '.' in line and re.match(r'^[a-z0-9\-\.]+$', line):
        return line
    return None

def compress_domains(domain_list):
    """
    子域名冗余压缩逻辑：
    即使输出不带点，逻辑依然保留：有 google.com 就不留 ads.google.com
    """
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

    print("="*50 + "\n🚀 开始执行 Loon 规则纯净版合并\n" + "="*50)

    for src in RULE_SOURCES:
        try:
            print(f"📥 正在拉取【{src['name']}】...")
            resp = session.get(src['url'], timeout=30)
            lines = resp.text.splitlines()
            
            raw_count = len(lines)
            valid_list = [d for d in (clean_domain(l) for l in lines) if d]
            
            # 源内去重统计
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
            print(f"✅ 【{src['name']}】已提取: {len(unique_src)} 条有效域名")

        except Exception as e:
            print(f"❌ 【{src['name']}】拉取失败: {e}")

    # 全局去重与冗余压缩
    unique_global = list(dict.fromkeys(all_valid_domains))
    cross_dedup = len(all_valid_domains) - len(unique_global)
    final_domains, compressed_count = compress_domains(unique_global)
    
    # 北京时间获取
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

    # —— 构建详细报表头 ——
    header = [
        f"# Loon 域名集合 (DOMAIN-SET) 纯净合并版",
        f"# 生成时间 (北京时间) : {beijing_time}",
        f"# 规则源地址:",
    ]
    for i, s in enumerate(source_stats, 1):
        header.append(f"#   {i}. {s['name']} 规则: {s['url']}")
    header.append(f"#   本规则订阅地址: {SUBSCRIBE_URL}")
    header.append("# " + "="*72)
    
    header.append("# 【各规则源单独统计】")
    for i, s in enumerate(source_stats, 1):
        header.append(f"#   {i}. {s['name']} | 原始行: {s['raw']} | 有效提取: {s['valid']} | 源内去重: {s['inner_dedup']}")
    header.append("# " + "="*72)

    header.append("# 【全局合并统计】")
    header.append(f"# 原始总行数汇总: {global_raw_total} 条")
    header.append(f"# 跨源重复去重数: {cross_dedup} 条 | 子域冗余压缩数: {compressed_count} 条")
    header.append(f"# 最终全局保留总数: {len(final_domains)} 条")
    header.append("# " + "="*72 + "\n")

    # —— 写入文件：不再添加前缀点 ——
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))
        # 直接按字母排序写入纯域名
        f.write('\n'.join(sorted(final_domains)))

    print(f"\n📊 任务圆满完成！最终生成规则: {len(final_domains)} 条")

if __name__ == "__main__":
    main()
