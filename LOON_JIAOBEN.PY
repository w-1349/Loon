def dedup_rules(rules):
    """
    两步全局去重：
    1. 完全相同去重（跨源）
    2. 包含关系去重（DOMAIN 被 SUFFIX 包含，SUFFIX 被 SUFFIX 包含）
    """
    
    # ===== 第零步：全局完全相同去重（关键！）=====
    # 先用 set 去重完全相同的规则字符串
    unique_rules = list(dict.fromkeys(rules))
    if len(unique_rules) != len(rules):
        print(f"   完全相同去重: {len(rules)} -> {len(unique_rules)} (移除 {len(rules) - len(unique_rules)} 条)")
    rules = unique_rules
    
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
    
    # 第二步：DOMAIN 被 SUFFIX 包含去重
    suffix_domains = set(d for d, _ in suffix_rules)
    
    final_domain_rules = []
    removed_domain_count = 0
    removed_domain_examples = []
    
    for domain, rule in domain_rules:
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
        else:
            final_domain_rules.append(rule)
    
    print(f"   DOMAIN: {len(domain_rules)} -> {len(final_domain_rules)} (移除 {removed_domain_count} 条被SUFFIX包含的)")
    if removed_domain_examples:
        print(f"      示例: {', '.join(removed_domain_examples)}")
    
    # 第三步：SUFFIX 内部包含去重
    suffix_rules.sort(key=lambda x: len(x[0].split('.')))
    
    kept_suffix_domains = set()
    final_suffix_rules = []
    redundant_suffix_count = 0
    redundant_suffix_examples = []
    
    for domain, rule in suffix_rules:
        parts = domain.split('.')
        is_redundant = False
        cover_by = None
        
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
    
    # 合并结果
    final_rules = final_suffix_rules + final_domain_rules + other_rules
    total_removed = (len(rules) - len(unique_rules)) + removed_domain_count + redundant_suffix_count
    
    return final_rules, len(final_suffix_rules), len(final_domain_rules), total_removed
