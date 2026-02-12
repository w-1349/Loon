#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests  # 导入网络请求库，用于下载远程规则
import re        # 导入正则表达式库，用于匹配域名格式
from datetime import datetime, timedelta  # 导入时间模块，用于生成北京时间
from requests.adapters import HTTPAdapter  # 导入适配器，用于设置重试策略
from urllib3.util.retry import Retry     # 导入重试逻辑模块

# —— 配置区 ——
RULE_SOURCES = [
    {"name": "anti-AD", "url": "https://anti-ad.net/surge2.txt"},      # 第一个规则源：anti-AD
    {"name": "AdRules", "url": "https://adrules.top/adrules.list"}     # 第二个规则源：AdRules
]
OUTPUT_FILE = "Loon_rules.txt"  # 最终生成的本地文件名

def create_retry_session():
    """创建带重试机制的会话，防止网络波动导致下载失败"""
    session = requests.Session()  # 实例化请求会话
    # 定义重试规则：总共重试3次，间隔1秒递增，针对429/500/502/503/504状态码重试
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))  # 为HTTPS请求挂载重试
    return session

def clean_domain(line):
    """清洗每一行原始文本，提取纯域名"""
    line = line.strip()  # 去除行首尾空格
    # 如果是空行、注释(#或!)、或者是Loon不识别的标记，直接跳过
    if not line or line.startswith(('#', '!', '[', 'PROCESS-NAME')): 
        return None
    
    # 如果这一行包含逗号（例如 DOMAIN-SUFFIX,google.com,REJECT）
    if ',' in line:
        parts = line.split(',')  # 按逗号分割字符串
        for part in parts:
            part = part.strip()  # 去除片段空格
            # 识别域名：包含点号且不是纯大写（排除REJECT等指令）
            if '.' in part and not part.isupper():
                line = part
                break
    
    line = line.strip('.').lower()  # 统一去掉前后的点并转为小写
    # 正则校验：只允许字母、数字、中划线和点号
    return line if re.match(r'^[a-z0-9\-\.]+$', line) else None

def compress_domains(domain_list):
    """核心压缩算法：后缀匹配去重（核心性能优化）"""
    # 按照域名字符串长度从短到长排序（例如先处理 google.com，再处理 ads.google.com）
    sorted_domains = sorted(list(domain_list), key=len)
    final_list = []      # 存储压缩后的最终列表
    redundant_count = 0  # 冗余计数器
    
    for domain in sorted_domains:
        is_redundant = False  # 初始标记为非冗余
        for root in final_list:
            # 如果当前域名是以“点+已存域名”结尾，或者是已存域名本身
            # 例如：ads.google.com 以 .google.com 结尾，说明它是冗余的
            if domain.endswith('.' + root) or domain == root:
                is_redundant = True
                redundant_count += 1
                break
        if not is_redundant:
            final_list.append(domain)  # 只有非冗余的域名才加入最终名单
    return final_list, redundant_count

def main():
    """主执行逻辑"""
    session = create_retry_session()  # 获取带重试的请求会话
    all_raw_domains = []             # 存储所有源合并后的原始域名
    source_reports = []              # 存储各源的统计报告
    global_stats = {"raw_lines": 0}  # 全局行数统计

    print("="*50 + "\n🚀 开始处理 Loon 规则合并\n" + "="*50)
    
    for src in RULE_SOURCES:
        try:
            print(f"📥 正在拉取【{src['name']}】...")
            resp = session.get(src['url'], timeout=30)  # 下载规则
            lines = resp.text.splitlines()            # 按行切分内容
            # 清洗每一行，并将非空的域名存入列表
            src_valid = [d for d in (clean_domain(l) for l in lines) if d]
            # 源内去重（防止单文件内重复）
            unique_src = list(dict.fromkeys(src_valid))
            
            # 记录该源统计数据
            source_reports.append({"name": src['name'], "raw": len(lines), "valid": len(src_valid)})
            all_raw_domains.extend(unique_src)  # 加入全局大池子
            global_stats["raw_lines"] += len(lines)
            print(f"✅ 拉取成功: {src['name']} | 有效域名: {len(src_valid)}")
        except Exception as e:
            print(f"❌ 拉取失败: {src['name']} | 错误信息: {e}")

    # 全局跨源去重
    unique_global = list(dict.fromkeys(all_raw_domains))
    cross_dedup = len(all_raw_domains) - len(unique_global)  # 计算跨源重复了多少
    
    # 执行子域压缩算法（核心优化）
    final_domains, compressed_count = compress_domains(unique_global)
    
    # 计算北京时间（UTC+8）
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

    # 构建文件头部注释
    header = [
        f"# Loon 域名集合 (DOMAIN-SET)",
        f"# 生成时间: {beijing_time}",
        f"# " + "="*30
    ]
    for r in source_reports:
        header.append(f"# {r['name']}: {r['valid']} 条")
    header.append(f"# 跨源去重: {cross_dedup} | 子域冗余压缩: {compressed_count}")
    header.append(f"# " + "="*30 + "\n")

    # 写入文件：统一加上点号(.)前缀，并按字母排序
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(header + [f".{d}" for d in sorted(final_domains)]))
    
    # 打印最终统计到 GitHub Action 日志中
    print(f"\n📊 统计汇总:")
    print(f"- 原始总行数: {global_stats['raw_lines']}")
    print(f"- 跨源重复项: {cross_dedup}")
    print(f"- 子域压缩项: {compressed_count}")
    print(f"- 最终保留数: {len(final_domains)}")
    print(f"🚀 文件已保存为: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()  # 执行脚本
