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
    去重逻辑：
    1. 收集所有 DOMAIN-SUFFIX 的域名
    2. 如果 DOMAIN 的域名被某个 DOMAIN-SUFFIX 包含，则删除该 DOMAIN
       例如：DOMAIN-SUFFIX,baidu.com 包含 DOMAIN,baidu.com、DOMAIN,www.baidu.com、DOMAIN,1.baidu.com 等
    3. DOMAIN-SUFFIX 内部做包含去重（短的包含长的）
    """
    
    # 第一步：分类收集
    domain_rules = []      # (域名, 原规则)
    suffix_rules = []      # (域名, 原规则)
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
    
    # 第二步：收集所有 SUFFIX 域名用于检查
    suffix_domains = set(d for d, _ in suffix_rules)
    
    # 第三步：过滤 DOMAIN 规则（关键逻辑：检查是否被 SUFFIX 包含）
    final_domain_rules = []
    removed_domain_count = 0
    removed_domain_examples = []
    
    for domain, rule in domain_rules:
        # 检查这个 DOMAIN 是否被某个 SUFFIX 包含
        # 例如 domain="www.baidu.com"，检查后缀："www.baidu.com"、"baidu.com"、"com"
        parts = domain.split('.')
        is_covered = False
        cover_by = None
        
        for i in range(len(parts)):
            suffix = '.'.join(parts[i:])
            if suffix in suffix_domains:
                is_covered = True
                cover_by = suffix
                break
        
        if is_covered:
            removed_domain_count += 1
            if len(removed_domain_examples) < 3:
                removed_domain_examples.append(f"{domain}⊂{cover_by}")
            # 丢弃这条 DOMAIN 规则
        else:
            final_domain_rules.append(rule)
    
    print(f"   DOMAIN: {len(domain_rules)} -> {len(final_domain_rules)} (移除 {removed_domain_count} 条被SUFFIX包含的)")
    if removed_domain_examples:
        print(f"      示例: {', '.join(removed_domain_examples)}")
    
    # 第四步：SUFFIX 内部包含去重（短的包含长的）
    suffix_rules.sort(key=lambda x: len(x[0].split('.')))
    
    kept_suffix_domains = set()
    final_suffix_rules = []
    redundant_suffix_count = 0
    redundant_suffix_examples = []
    
    for domain, rule in suffix_rules:
        parts = domain.split('.')
        is_redundant = False
        cover_by = None
        
        # 检查是否被已保留的 SUFFIX 包含
        for i in range(1, len(parts)):
            suffix = '.'.join(parts[i:])
            if suffix in kept_suffix_domains:
                is_redundant = True
                cover_by = suffix
                break
        
        if is_redundant:
            redundant_suffix_count += 1
            if len(redundant_suffix_examples) < 3:
                redundant_suffix_examples.append(f"{domain}⊂{cover_by}")
        else:
            kept_suffix_domains.add(domain)
            final_suffix_rules.append(rule)
    
    print(f"   DOMAIN-SUFFIX: {len(suffix_rules)} -> {len(final_suffix_rules)} (移除 {redundant_suffix_count} 条)")
    if redundant_suffix_examples:
        print(f"      示例: {', '.join(redundant_suffix_examples)}")
    
    # 合并结果：先 SUFFIX，再 DOMAIN，再 other
    final_rules = final_suffix_rules + final_domain_rules + other_rules
    
    total_removed = removed_domain_count + redundant_suffix_count
    
    return final_rules, len(final_suffix_rules), len(final_domain_rules), total_removed

def main():
    all_rules = []
    source_stats = []
    
    print(f"[{get_beijing_time()}] 🚀 启动规则抓取...")
    print("=" * 60)

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}

    for src in RULE_SOURCES:
        try:
            print(f"📥 拉取: {src['name']}...")
            resp = requests.get(src['url'], timeout=30, headers=headers)
            resp.raise_for_status()
            
            lines = resp.text.splitlines()
            
            if src['name'] == 'AdRules':
                processed = [r for r in (process_adrules_line(l) for l in lines) if r]
            else:
                processed = [r for r in (process_antiad_line(l) for l in lines) if r]
            
            # 单源统计
            suffix_raw = sum(1 for r in processed if r.upper().startswith('DOMAIN-SUFFIX,'))
            domain_raw = sum(1 for r in processed if r.upper().startswith('DOMAIN,'))
            
            print(f"   原始: {len(lines)} | 提取: {len(processed)} (S:{suffix_raw}/D:{domain_raw})")
            
            source_stats.append({
                "name": src['name'], 
                "raw": len(lines), 
                "valid": len(processed),
                "suffix": suffix_raw,
                "domain": domain_raw
            })
            all_rules.extend(processed)
            print(f"✅ 完成\n")

        except Exception as e:
            print(f"❌ 失败: {e}\n")

    print("=" * 60)
    print(f"🔄 全局去重优化（总计 {len(all_rules)} 条）...")
    
    # 执行去重
    final_rules, final_suffix, final_domain, total_removed = dedup_rules(all_rules)
    
    # 排序输出
    suffix_part = sorted([r for r in final_rules if r.upper().startswith('DOMAIN-SUFFIX,')])
    domain_part = sorted([r for r in final_rules if r.upper().startswith('DOMAIN,')])
    other_part = sorted([r for r in final_rules if not r.upper().startswith(('DOMAIN,', 'DOMAIN-SUFFIX,'))])
    final_rules = suffix_part + domain_part + other_part
    
    print(f"\n📊 最终结果:")
    print(f"   总计: {len(final_rules)} 条")
    print(f"   ├─ DOMAIN-SUFFIX: {final_suffix}")
    print(f"   └─ DOMAIN: {final_domain}")

    # 构建文件头
    header = [
        f"# Loon 域名集合 (Smart Dedup)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计: 总计 {len(final_rules)} | DOMAIN-SUFFIX {final_suffix} | DOMAIN {final_domain}",
        f"# 优化: 共移除 {total_removed} 条冗余规则",
        "# " + "=" * 58
    ]
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']} (S:{s['suffix']}/D:{s['domain']})")
    header.append("# " + "=" * 58)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(final_rules))

    print(f"\n💾 已保存: {OUTPUT_FILE}")
    print(f"[{get_beijing_time()}] 🎉 完成!")

if __name__ == "__main__":
    main()
