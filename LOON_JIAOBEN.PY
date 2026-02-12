#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests  # 用于拉取远程规则文件
import re        # 用于验证域名合法性
from datetime import datetime, timedelta  # 用于生成北京时间统计

# —— 核心配置区 ——
# 你的 AGH 原始规则源地址
AGH_SOURCE_URL = "https://ddcm1349.github.io/AGH/adguard_rules.txt"

# 按照你的要求设定的黑白名单文件名
BLACKLIST_FILE = "Loon_黑名单.txt"
WHITELIST_FILE = "Loon_白名单.txt"

def get_beijing_time():
    """获取并格式化当前的北京时间"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def extract_domain(line):
    """
    分拣提取逻辑：
    从 AGH 语法中识别出域名，并区分黑白名单
    """
    line = line.strip()
    
    # 1. 基础过滤：跳过空行、注释(! #)、规则集标记([)、正则(/)以及带$的复杂修饰符
    if not line or line.startswith(('!', '#', '[')) or '/' in line or '$' in line:
        return None, None

    is_whitelist = False
    temp_line = line

    # 2. 识别白名单：若以 @@ 开头则标记为白名单，并剥离符号
    if temp_line.startswith('@@'):
        is_whitelist = True
        temp_line = temp_line[2:]

    # 3. 处理 AGH 标志性的 || 前缀，并截断结尾的分隔符 ^
    if temp_line.startswith('||'):
        temp_line = temp_line[2:].split('^')[0]
    
    # 4. 兼容处理：针对包含 DOMAIN, 或 DOMAIN-SUFFIX, 的行
    elif ',' in temp_line:
        parts = temp_line.split(',')
        for part in parts:
            p = part.strip()
            # 包含点且不是全大写指令（如 REJECT）则认定为域名
            if '.' in p and not p.isupper():
                temp_line = p
                break
    
    # 5. 纯净化处理：去掉左侧前导点、转小写、移除端口号和多余符号
    domain = temp_line.lstrip('.').lower().split(':')[0].split('^')[0]

    # 6. 合法性检查：确保是合规的域名格式，且排除纯 IP 地址
    if '.' in domain and re.match(r'^[a-z0-9\-\.]+$', domain):
        if not domain.split('.')[-1].isdigit():
            return domain, is_whitelist
    
    return None, None

def save_to_file(filename, title, domains):
    """将提取到的列表保存为文件，并写入详细的统计报表头"""
    beijing_time = get_beijing_time()
    header = [
        f"# {title}",
        f"# 生成时间: {beijing_time} (北京时间)",
        f"# 提取总数: {len(domains)} 条",
        f"# 来源地址: {AGH_SOURCE_URL}",
        "#" + "="*65 + "\n"
    ]
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))  # 写入统计头
        f.write('\n'.join(sorted(domains)))  # 写入排序后的纯域名列表

def main():
    """主程序逻辑"""
    print(f"🚀 正在拉取源文件: {AGH_SOURCE_URL}")
    
    try:
        resp = requests.get(AGH_SOURCE_URL, timeout=30)
        resp.raise_for_status()
        lines = resp.text.splitlines()
    except Exception as e:
        print(f"❌ 拉取失败: {e}")
        return

    black_list = []  # 黑名单临时容器
    white_list = []  # 白名单临时容器

    # 遍历原始规则进行分拣
    for line in lines:
        domain, is_white = extract_domain(line)
        if domain:
            if is_white:
                white_list.append(domain)
            else:
                black_list.append(domain)

    # 确保最终结果去重（集合去重）
    black_list = list(dict.fromkeys(black_list))
    white_list = list(dict.fromkeys(white_list))

    # 执行保存操作
    save_to_file(BLACKLIST_FILE, "Loon 域名黑名单 (BLACKLIST)", black_list)
    save_to_file(WHITELIST_FILE, "Loon 域名白名单 (WHITELIST)", white_list)

    print(f"✅ 处理完成！")
    print(f"📊 黑名单: {len(black_list)} 条 -> {BLACKLIST_FILE}")
    print(f"📊 白名单: {len(white_list)} 条 -> {WHITELIST_FILE}")

if __name__ == "__main__":
    main()
