#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from datetime import datetime, timedelta

# —— 核心配置区 ——
# 使用 GitHub Raw 链接确保稳定性
RULE_SOURCES = [
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"}
]
OUTPUT_FILE = "Loon_rules.txt"

def get_beijing_time():
    """获取北京时间用于报表展示"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def process_to_loon_format(line):
    """
    核心清洗逻辑：
    1. 识别原始前缀：带点(.)转 DOMAIN-SUFFIX，不带点转 DOMAIN
    2. 剔除所有 Adblock 语法符号和非法干扰项
    """
    line = line.strip()
    
    # 基础过滤：跳过空行、注释、规则集标题、正则、带$的复杂修饰符
    if not line or line.startswith(('!', '#', '[')) or '/' in line or '$' in line:
        return None

    # 【关键逻辑】判断原始行是否以点开头 (针对 anti-ad 等源)
    # 或者本来就显式包含 DOMAIN-SUFFIX
    is_suffix = line.startswith('.') or "DOMAIN-SUFFIX" in line
    
    # 提取域名主体：剥离前缀符号 (|| 或 @@||)
    temp = line
    if temp.startswith('@@||'): temp = temp[4:]
    elif temp.startswith('||'): temp = temp[2:]
    
    # 如果是原本就带前缀的格式 (DOMAIN-SUFFIX,example.com)，提取出 example.com
    if ',' in temp:
        parts = temp.split(',')
        for part in parts:
            p = part.strip()
            if '.' in p and not p.isupper():
                temp = p
                break
    
    # 彻底净化域名：去除左侧所有点、转小写、截断端口和行尾符号
    domain = temp.lstrip('.').lower().split('^')[0].split(':')[0].split('/')[0]

    # 合法性校验：必须包含点号，且字符合法
    if not ('.' in domain and re.match(r'^[a-z0-9\-\.]+$', domain)):
        return None
    
    # 排除纯 IP 地址，防止解析错误
    if domain.split('.')[-1].isdigit():
        return None

    # —— 根据逻辑输出对应格式 ——
    if is_suffix:
        return f"DOMAIN-SUFFIX,{domain}"
    else:
        return f"DOMAIN,{domain}"

def main():
    all_rules = []
    source_stats = []
    
    print("🚀 开始转换规则：正在执行【带点转 SUFFIX / 无点转 DOMAIN】逻辑...")

    for src in RULE_SOURCES:
        try:
            print(f"📥 正在拉取: {src['name']}...")
            resp = requests.get(src['url'], timeout=30)
            lines = resp.text.splitlines()
            
            # 执行转换
            formatted_list = [r for r in (process_to_loon_format(l) for l in lines) if r]
            # 源内去重
            unique_src = list(dict.fromkeys(formatted_list))
            
            source_stats.append({
                "name": src['name'],
                "url": src['url'],
                "raw": len(lines),
                "unique": len(unique_src)
            })
            all_rules.extend(unique_src)
        except Exception as e:
            print(f"❌ {src['name']} 获取失败: {e}")

    # 全局去重并排序
    final_rules = sorted(list(set(all_rules)))
    duplicate_count = len(all_rules) - len(final_rules)

    # 构建带统计信息的报表头部
    beijing_time = get_beijing_time()
    header = [
        f"# Loon 域名集合 (稳健转换版)",
        f"# 生成时间: {beijing_time} (北京时间)",
        f"# 逻辑说明: 原始带点 -> DOMAIN-SUFFIX | 原始无点 -> DOMAIN",
        f"# 最终总数: {len(final_rules)} 条",
        "# " + "="*65,
        "# 【分源提取统计】"
    ]
    for s in source_stats:
        header.append(f"# - {s['name']}: 原始行 {s['raw']} | 有效去重项 {s['unique']}")
    
    header.append(f"# 【全局去重汇总】: 跨源共剔除 {duplicate_count} 条重复规则")
    header.append("# " + "="*65 + "\n")

    # 写入最终文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))
        f.write('\n'.join(final_rules))

    print(f"✅ 处理完成！已生成 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
