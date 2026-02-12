#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

# —— 核心配置区 ——
RULE_SOURCES = [
    # 建议使用 raw 链接
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"}
]
OUTPUT_FILE = "Loon_rules.txt"

def get_beijing_time():
    """获取北京时间"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def is_valid_domain(domain):
    """
    校验是否为纯净域名
    排除: IP地址、包含/或^等特殊符号的字符串
    """
    if not domain: return False
    # 必须包含点，且只能由字母、数字、点、中划线组成
    if '.' in domain and re.match(r'^[a-z0-9\-\.]+$', domain):
        # 排除 IP 地址 (最后一段是数字)
        if not domain.split('.')[-1].isdigit():
            return True
    return False

def process_line(line):
    """
    【精简版分拣逻辑】
    不处理 AGH (||/@@) 语法，严格执行三条规则
    """
    line = line.strip()
    
    # 1. 基础过滤：跳过空行、注释
    if not line or line.startswith(('!', '#', '[')):
        return None

    # ---------------------------------------------------------
    # 规则 1: 原生带有 DOMAIN 或 DOMAIN-SUFFIX 前缀 -> 保持不变
    # ---------------------------------------------------------
    upper_line = line.upper()
    if upper_line.startswith("DOMAIN-SUFFIX") or upper_line.startswith("DOMAIN"):
        return line

    # ---------------------------------------------------------
    # 规则 2: 原生带 . 开头 -> 替换为 DOMAIN-SUFFIX
    # ---------------------------------------------------------
    if line.startswith('.'):
        # 去掉开头的点，清洗并验证
        clean_domain = line.lstrip('.').strip().lower()
        if is_valid_domain(clean_domain):
            return f"DOMAIN-SUFFIX,{clean_domain}"

    # ---------------------------------------------------------
    # 规则 3: 无前缀且是合法域名 -> 添加 DOMAIN
    # ---------------------------------------------------------
    # 验证整行是否为一个干净的域名
    clean_domain = line.strip().lower()
    if is_valid_domain(clean_domain):
        return f"DOMAIN,{clean_domain}"

    # 其他不符合格式的行（包括 || 开头的 AGH 规则）将被丢弃
    return None

def main():
    all_rules = []
    source_stats = []
    
    print(f"[{get_beijing_time()}] 🚀 脚本启动：执行精简版分拣逻辑 (无AGH转换)...")
    print("=" * 60)

    for src in RULE_SOURCES:
        try:
            print(f"📥 正在拉取: {src['name']}...")
            resp = requests.get(src['url'], timeout=30)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            
            # 处理每一行
            processed_list = [r for r in (process_line(l) for l in lines) if r]
            
            # 源内去重
            unique_src = list(dict.fromkeys(processed_list))
            
            print(f"   📊 {src['name']} 数据:")
            print(f"      ├─ 原始行数: {len(lines)}")
            print(f"      └─ 有效提取: {len(unique_src)}")
            
            source_stats.append({
                "name": src['name'], 
                "raw": len(lines), 
                "unique": len(unique_src)
            })
            all_rules.extend(unique_src)
            print(f"✅ {src['name']} 处理完毕\n")

        except Exception as e:
            print(f"❌ {src['name']} 失败: {e}\n")

    print("=" * 60)
    print("🔄 正在进行全局去重与分类统计...")
    
    # 全局去重
    final_rules = sorted(list(set(all_rules)))
    final_total = len(final_rules)
    
    # —— 核心统计：分别计算 DOMAIN 和 DOMAIN-SUFFIX ——
    count_domain = 0
    count_suffix = 0
    
    for rule in final_rules:
        # 统一转大写前缀判断，防止源文件大小写不一致
        upper_rule = rule.upper()
        if upper_rule.startswith('DOMAIN-SUFFIX'):
            count_suffix += 1
        elif upper_rule.startswith('DOMAIN'):
            count_domain += 1
            
    print(f"📊 全局统计结果:")
    print(f"   ├─ 总规则数: {final_total}")
    print(f"   ├─ DOMAIN (精准匹配): {count_domain} 条")
    print(f"   └─ DOMAIN-SUFFIX (后缀匹配): {count_suffix} 条")

    # 构建文件头
    header = [
        f"# Loon 域名集合 (Lite Mode)",
        f"# 生成时间: {get_beijing_time()}",
        f"# 统计摘要:",
        f"#   - 总条数: {final_total}",
        f"#   - DOMAIN: {count_domain}",
        f"#   - DOMAIN-SUFFIX: {count_suffix}",
        "# " + "="*58
    ]
    
    # 添加分源统计注释
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始: {s['raw']} | 提取: {s['unique']}")
        
    header.append("# " + "="*58 + "\n")

    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))
        f.write('\n'.join(final_rules))

    print(f"💾 文件已保存至: {OUTPUT_FILE}")
    print(f"[{get_beijing_time()}] 🎉 任务完成！")

if __name__ == "__main__":
    main()
