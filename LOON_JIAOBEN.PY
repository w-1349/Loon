#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"}
]
OUTPUT_FILE = "Loon_rules.txt"

def get_beijing_time():
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def is_valid_domain(domain):
    """严格的域名验证"""
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
    
    # 排除 IP 地址（最后一段纯数字）
    if labels[-1].isdigit():
        return False
    
    return True

def process_line(line):
    line = line.strip()
    
    if not line or line.startswith(('!', '#', '[')):
        return None

    upper = line.upper()
    
    # 精确匹配已有前缀的规则
    if upper.startswith("DOMAIN-SUFFIX,"):
        return line
    if upper.startswith("DOMAIN,"):
        return line

    # .开头 -> DOMAIN-SUFFIX
    if line.startswith('.'):
        domain = line[1:].lower()
        if is_valid_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"
        return None

    # 纯域名 -> DOMAIN
    domain = line.lower()
    if is_valid_domain(domain):
        return f"DOMAIN,{domain}"

    return None

def main():
    all_rules = []
    source_stats = []
    
    print(f"[{get_beijing_time()}] 🚀 启动精简分拣...")
    print("=" * 60)

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}

    for src in RULE_SOURCES:
        try:
            print(f"📥 拉取: {src['name']}...")
            resp = requests.get(src['url'], timeout=30, headers=headers)
            resp.raise_for_status()
            
            lines = resp.text.splitlines()
            processed = [r for r in (process_line(l) for l in lines) if r]
            unique = list(dict.fromkeys(processed))
            
            print(f"   原始: {len(lines)} | 有效: {len(unique)}")
            source_stats.append({
                "name": src['name'], 
                "raw": len(lines), 
                "valid": len(unique)
            })
            all_rules.extend(unique)
            print(f"✅ 完成\n")

        except Exception as e:
            print(f"❌ 失败: {e}\n")

    print("=" * 60)
    print("🔄 全局去重与分类...")
    
    # 去重并分类
    seen = set()
    suffix_rules = []
    domain_rules = []
    
    for rule in all_rules:
        if rule in seen:
            continue
        seen.add(rule)
        if rule.upper().startswith("DOMAIN-SUFFIX,"):
            suffix_rules.append(rule)
        else:
            domain_rules.append(rule)
    
    suffix_rules.sort()
    domain_rules.sort()
    final_rules = suffix_rules + domain_rules
    
    print(f"📊 总计: {len(final_rules)} (DOMAIN-SUFFIX: {len(suffix_rules)}, DOMAIN: {len(domain_rules)})")

    # 构建文件头
    header = [
        f"# Loon 域名集合 (Lite Mode)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: 总计 {len(final_rules)} | DOMAIN-SUFFIX {len(suffix_rules)} | DOMAIN {len(domain_rules)}",
        "# " + "=" * 58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")
    header.append("# " + "=" * 58)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(final_rules))

    print(f"💾 已保存: {OUTPUT_FILE}")
    print(f"[{get_beijing_time()}] 🎉 完成!")

if __name__ == "__main__":
    main()
