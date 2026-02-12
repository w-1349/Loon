#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

# —— 核心配置区 ——
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"}
]
OUTPUT_FILE = "Loon_rules.txt"

def get_beijing_time():
    """生成北京时间字符串"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def process_line(line):
    """
    分拣逻辑：
    1. 带 '.' 开头 -> DOMAIN-SUFFIX
    2. 不带 '.' 开头 -> DOMAIN
    """
    line = line.strip()
    if not line or line.startswith(('#', '!', '[')) or '/' in line or '$' in line:
        return None

    is_suffix = line.startswith('.')
    raw_domain = line
    
    if ',' in line:
        parts = line.split(',')
        for p in parts:
            p = p.strip()
            if '.' in p and not p.isupper():
                raw_domain = p
                break

    clean_domain = raw_domain.lstrip('.').lower().split('^')[0].split(':')[0]

    if '.' in clean_domain and re.match(r'^[a-z0-9\-\.]+$', clean_domain):
        if not clean_domain.split('.')[-1].isdigit():
            return f"DOMAIN-SUFFIX,{clean_domain}" if is_suffix else f"DOMAIN,{clean_domain}"
            
    return None

def main():
    all_rules = []
    source_stats = []
    
    print(f"[{get_beijing_time()}] 🚀 任务启动：执行分拣与详细统计...")
    print("=" * 60)

    for src in RULE_SOURCES:
        try:
            print(f"📥 正在拉取: {src['name']}...")
            resp = requests.get(src['url'], timeout=30)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            
            raw_count = len(lines)
            temp_list = [r for r in (process_line(l) for l in lines) if r]
            unique_src = list(dict.fromkeys(temp_list))
            
            print(f"   📊 {src['name']} 统计:")
            print(f"      ├─ 原始行数: {raw_count}")
            print(f"      └─ 有效去重: {len(unique_src)}")
            
            source_stats.append({"name": src['name'], "raw": raw_count, "unique": len(unique_src)})
            all_rules.extend(unique_src)
            print(f"✅ {src['name']} 处理完毕\n")

        except Exception as e:
            print(f"❌ {src['name']} 出错: {e}\n")

    print("=" * 60)
    print("🔄 正在进行全局去重与类型汇总...")
    
    # 全局去重
    final_rules = sorted(list(set(all_rules)))
    
    # 核心统计：计算 DOMAIN 和 DOMAIN-SUFFIX 的数量
    do_count = sum(1 for r in final_rules if r.startswith("DOMAIN,"))
    su_count = sum(1 for r in final_rules if r.startswith("DOMAIN-SUFFIX,"))
    final_count = len(final_rules)

    print(f"📊 全局合并结果:")
    print(f"   ├─ 最终总条数: {final_count}")
    print(f"   ├─ DOMAIN (精准匹配): {do_count}")
    print(f"   └─ DOMAIN-SUFFIX (后缀匹配): {su_count}")

    # 写入文件
    header = [
        f"# Loon 域名集合 (精细统计版)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 最终总条数: {final_count}",
        f"# 其中 DOMAIN: {do_count} 条",
        f"# 其中 DOMAIN-SUFFIX: {su_count} 条",
        "# " + "="*58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始: {s['raw']} | 有效: {s['unique']}")
    header.append("# " + "="*58 + "\n")

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))
        f.write('\n'.join(final_rules))

    print("=" * 60)
    print(f"💾 文件已保存: {OUTPUT_FILE}")
    print(f"[{get_beijing_time()}] 🎉 统计任务圆满完成！")

if __name__ == "__main__":
    main()
