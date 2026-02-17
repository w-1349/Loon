#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"}
    {"name": "Advertising", "url": "https://rule.kelee.one/Loon/Advertising.lsr"}
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

def process_adrules_line(line):
    """AdRules 源：原生 Loon 格式，直接保留"""
    line = line.strip()
    if not line or line.startswith(('#', '!', '[')):
        return None
    
    upper = line.upper()
    if upper.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'DOMAIN-SET,')):
        return line
    
    return None

def process_antiad_line(line):
    """anti-ad 源：需要转换"""
    line = line.strip()
    if not line or line.startswith(('#', '!', '[')):
        return None
    
    upper = line.upper()
    if upper.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,')):
        return line
    
    if line.startswith('.'):
        domain = line[1:].lower()
        if is_valid_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"
        return None
    
    domain = line.lower()
    if is_valid_domain(domain):
        return f"DOMAIN,{domain}"
    
    return None

def dedup_rules(rules):
    """
    两步全局去重：
    1. 完全相同去重（跨源）
    2. 包含关系去重（DOMAIN 被 SUFFIX 包含，SUFFIX 被 SUFFIX 包含）
    """
    
    # 第零步：全局完全相同去重
    unique_rules = list(dict.fromkeys(rules))
    dup_removed = len(rules) - len(unique_rules)
    rules = unique_rules
    
    # 第一步：分类收集
    domain_rules = []
    suffix_rules = []
    other_rules = []
    
    for rule in rules:
        upper = rule.upper()
        if upper.startswith('DOMAIN,'):
            domain = rule[7:].strip().lower()
            domain_rules.append((domain, rule))
        elif upper.startswith('DOMAIN-SUFFIX,'):
            domain = rule[14:].strip().lower()
            suffix_rules.append((domain, rule))
        else:
            other_rules.append(rule)
    
    # 第二步：DOMAIN 被 SUFFIX 包含去重
    suffix_domains = set(d for d, _ in suffix_rules)
    
    final_domain_rules = []
    removed_domain_count = 0
    
    for domain, rule in domain_rules:
        parts = domain.split('.')
        is_covered = False
        
        for i in range(len(parts)):
            suffix = '.'.join(parts[i:])
            if suffix in suffix_domains:
                is_covered = True
                break
        
        if is_covered:
            removed_domain_count += 1
        else:
            final_domain_rules.append(rule)
    
    # 第三步：SUFFIX 内部包含去重
    suffix_rules.sort(key=lambda x: len(x[0].split('.')))
    
    kept_suffix_domains = set()
    final_suffix_rules = []
    redundant_suffix_count = 0
    
    for domain, rule in suffix_rules:
        parts = domain.split('.')
        is_redundant = False
        
        for i in range(1, len(parts)):
            suffix = '.'.join(parts[i:])
            if suffix in kept_suffix_domains:
                is_redundant = True
                break
        
        if is_redundant:
            redundant_suffix_count += 1
        else:
            kept_suffix_domains.add(domain)
            final_suffix_rules.append(rule)
    
    # 合并结果
    final_rules = final_suffix_rules + final_domain_rules + other_rules
    total_removed = dup_removed + removed_domain_count + redundant_suffix_count
    
    return final_rules, total_removed

def main():
    print(f"[{get_beijing_time()}] 🚀 启动规则抓取...")
    print("=" * 60, flush=True)

    all_rules = []
    source_stats = []
    
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}

    for src in RULE_SOURCES:
        try:
            print(f"📥 拉取: {src['name']}...", flush=True)
            resp = requests.get(src['url'], timeout=30, headers=headers)
            resp.raise_for_status()
            
            lines = resp.text.splitlines()
            
            if src['name'] == 'AdRules':
                processed = [r for r in (process_adrules_line(l) for l in lines) if r]
            else:
                processed = [r for r in (process_antiad_line(l) for l in lines) if r]
            
            # 单源去重
            unique_processed = list(dict.fromkeys(processed))
            
            print(f"   原始: {len(lines)} | 提取: {len(unique_processed)}", flush=True)
            
            source_stats.append({
                "name": src['name'], 
                "raw": len(lines), 
                "valid": len(unique_processed)
            })
            all_rules.extend(unique_processed)
            print(f"✅ 完成", flush=True)

        except Exception as e:
            print(f"❌ 失败: {e}", flush=True)
            import traceback
            traceback.print_exc()

    print("=" * 60, flush=True)
    print(f"🔄 全局去重优化（总计 {len(all_rules)} 条）...", flush=True)
    
    # 执行去重
    final_rules, total_removed = dedup_rules(all_rules)
    
    # 排序输出
    suffix_part = sorted([r for r in final_rules if r.upper().startswith('DOMAIN-SUFFIX,')])
    domain_part = sorted([r for r in final_rules if r.upper().startswith('DOMAIN,')])
    other_part = sorted([r for r in final_rules if not r.upper().startswith(('DOMAIN,', 'DOMAIN-SUFFIX,'))])
    final_rules = suffix_part + domain_part + other_part
    
    print(f"\n📊 最终结果: {len(final_rules)} 条", flush=True)

    # 构建文件头（精简版）
    header = [
        f"# Loon_AD刺客",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: {len(final_rules)} 条",
        f"# 优化: 移除 {total_removed} 条冗余规则",
        f"# 订阅地址: https://ddcm1349.github.io/Loon/Loon_rules.txt",
        "# " + "=" * 58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")
    header.append("# " + "=" * 58)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(final_rules))

    print(f"\n💾 已保存: {OUTPUT_FILE}", flush=True)
    print(f"[{get_beijing_time()}] 🎉 完成!", flush=True)

if __name__ == "__main__":
    main()
