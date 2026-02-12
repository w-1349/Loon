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
    if labels[-1].isdigit():
        return False
    return True

def process_line(line):
    line = line.strip()
    if not line or line.startswith(('!', '#', '[')):
        return None

    upper = line.upper()
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

def remove_redundant_suffix_rules(rules):
    """
    移除被其他 DOMAIN-SUFFIX 规则包含的冗余规则
    例如: baidu.com 包含 1.baidu.com, www.baidu.com 等
    """
    # 分离 DOMAIN 和 DOMAIN-SUFFIX
    domain_rules = []
    suffix_domains = []  # 只存域名部分
    
    for rule in rules:
        upper = rule.upper()
        if upper.startswith("DOMAIN-SUFFIX,"):
            # 提取域名部分
            domain = rule[14:].strip().lower()  # len("DOMAIN-SUFFIX,") = 14
            suffix_domains.append((domain, rule))
        elif upper.startswith("DOMAIN,"):
            domain_rules.append(rule)
    
    # 按域名层级排序（短的在前，长的在后）
    # 这样先检查短域名，可以更快排除长域名
    suffix_domains.sort(key=lambda x: len(x[0].split('.')))
    
    # 使用 Trie 或简单集合来判断包含关系
    # 优化：将域名按后缀树结构组织
    kept_domains = set()
    redundant = []
    kept_rules = []
    
    for domain, rule in suffix_domains:
        # 检查是否被已有的某个域名包含
        # 例如 domain = "1.baidu.com", 检查是否有 "baidu.com" 或 "com" 已被保留
        parts = domain.split('.')
        is_redundant = False
        
        # 检查所有可能的后缀
        for i in range(len(parts) - 1):  # 至少保留一级，不检查空后缀
            suffix = '.'.join(parts[i:])
            if suffix in kept_domains:
                is_redundant = True
                redundant.append((domain, suffix))
                break
        
        if not is_redundant:
            kept_domains.add(domain)
            kept_rules.append(rule)
    
    print(f"   DOMAIN-SUFFIX 去重: {len(suffix_domains)} -> {len(kept_rules)} (移除 {len(redundant)} 条)")
    if redundant[:5]:
        print(f"   冗余示例: {redundant[:3]}")
    
    return kept_rules, domain_rules, redundant

def main():
    all_rules = []
    source_stats = []
    
    print(f"[{get_beijing_time()}] 🚀 启动智能去重模式...")
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
    print("🔄 执行后缀包含去重...")
    
    # 全局去重
    seen = set()
    unique_rules = []
    for r in all_rules:
        if r not in seen:
            seen.add(r)
            unique_rules.append(r)
    
    print(f"   基础去重后: {len(unique_rules)}")
    
    # 执行智能后缀去重
    suffix_rules, domain_rules, redundant = remove_redundant_suffix_rules(unique_rules)
    
    # 最终排序：DOMAIN-SUFFIX 在前，按字母序
    suffix_rules.sort()
    domain_rules.sort()
    final_rules = suffix_rules + domain_rules
    
    print(f"\n📊 最终统计:")
    print(f"   总规则: {len(final_rules)}")
    print(f"   ├─ DOMAIN-SUFFIX: {len(suffix_rules)}")
    print(f"   └─ DOMAIN: {len(domain_rules)}")

    # 构建文件头
    header = [
        f"# Loon 域名集合 (Smart Dedup)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: 总计 {len(final_rules)} | DOMAIN-SUFFIX {len(suffix_rules)} | DOMAIN {len(domain_rules)}",
        f"# 优化: 移除 {len(redundant)} 条被包含的冗余后缀规则",
        "# " + "=" * 58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")
    header.append("# " + "=" * 58)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(final_rules))

    print(f"\n💾 已保存: {OUTPUT_FILE}")
    print(f"[{get_beijing_time()}] 🎉 完成!")

if __name__ == "__main__":
    main()
