#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 上面两行是 Shebang 和编码声明
# Shebang 告诉系统使用 /usr/bin/env 查找 python3 解释器来运行此脚本
# -*- coding: utf-8 -*- 声明文件使用 UTF-8 编码，支持中文

import requests
# 导入 requests 库，用于发送 HTTP 请求获取规则文件

import re
# 导入正则表达式模块，用于字符串模式匹配和验证

import ipaddress
# 导入 IP 地址处理模块，用于判断字符串是否为 IP 地址

import tempfile
# 导入临时文件模块，用于安全地写入文件（原子写入）

import os
# 导入操作系统接口模块，用于文件操作如重命名

from datetime import datetime, timedelta
# 从 datetime 模块导入 datetime 类（处理日期时间）和 timedelta 类（时间差计算）

from requests.adapters import HTTPAdapter
# 从 requests.adapters 导入 HTTPAdapter，用于配置请求适配器（重试机制）

from urllib3.util.retry import Retry
# 从 urllib3.util.retry 导入 Retry，用于设置重试策略

# —— 核心配置区 ——
# 下面的变量是脚本的全局配置，可以根据需要修改

RULE_SOURCES = [
    # RULE_SOURCES 是一个列表，包含所有规则源的配置
    # 每个元素是一个字典，包含规则源的名称和 URL 地址
    {"name": "AdRules", "url": "https://adrules.top/adrules.list"},
    # 第一个规则源：AdRules，地址是 https://adrules.top/adrules.list
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"}
    # 第二个规则源：anti-ad，地址是 https://anti-ad.net/surge2.txt
]
OUTPUT_FILE = "Loon_rules.txt"
# OUTPUT_FILE 定义输出文件的名称，最终合并后的规则会保存到这个文件

SUBSCRIBE_URL = "https://raw.githubusercontent.com/ddcm1349/Loon/main/Loon_rules.txt"
# SUBSCRIBE_URL 是规则的订阅地址，会写入到输出文件的注释中供参考

# 正则预编译
# 预编译正则表达式可以提高性能，避免每次使用时重新编译

DOMAIN_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$', re.I)
# DOMAIN_PATTERN 是用于验证域名合法性的正则表达式
# 解释：
# ^ 表示字符串开始
# [a-z0-9] 第一个字符必须是字母或数字
# ([a-z0-9\-]{0,61}[a-z0-9])? 中间部分可以是0-61个字母/数字/横线，但必须以字母或数字结尾
# (\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)* 点号后跟类似的模式，可以重复多次（子域名）
# \.[a-z]{2,}$ 最后必须是以点号开头，后跟至少2个字母的顶级域名（如 .com, .cn）
# re.I 表示忽略大小写

IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
# IP_PATTERN 用于匹配 IP 地址格式
# ^\d{1,3}\. 表示以1-3位数字开头，后跟点号，重复4次（IPv4 格式）

def create_retry_session():
    """
    创建带有重试机制的 HTTP 会话
    返回: 配置好的 requests.Session 对象
    """
    session = requests.Session()
    # 创建一个 Session 对象，Session 可以复用连接，提高性能
    
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    # 创建重试策略对象：
    # total=3 表示最多重试3次
    # backoff_factor=1 表示重试间隔时间，1秒、2秒、4秒递增
    # status_forcelist 表示遇到这些 HTTP 状态码时会触发重试：
    #   429: 请求过多
    #   500: 服务器内部错误
    #   502: 网关错误
    #   503: 服务不可用
    #   504: 网关超时
    
    session.mount("https://", HTTPAdapter(max_retries=retry))
    # 为所有 https:// 开头的 URL 挂载适配器，应用重试策略
    
    return session
    # 返回配置好的会话对象

def is_valid_domain(domain):
    """
    RFC 合规的域名验证函数
    参数: domain - 待验证的域名字符串
    返回: True 如果合法，False 如果不合法
    """
    if not domain or len(domain) > 253:
        # 检查：域名不能为空，且总长度不能超过253个字符（RFC 规定）
        return False
        # 不满足条件，返回 False
    
    if not DOMAIN_PATTERN.match(domain):
        # 使用预编译的正则表达式匹配域名
        # 如果不匹配，说明格式不符合域名规范
        return False
    
    # 检查标签长度（每个点号分隔的部分称为标签，如 www.example.com 有3个标签）
    return all(len(label) <= 63 for label in domain.split('.'))
    # domain.split('.') 将域名按点号分割成列表
    # for label in ... 遍历每个标签
    # len(label) <= 63 检查每个标签长度不超过63（RFC 规定）
    # all(...) 如果所有标签都满足条件返回 True，否则返回 False

def clean_domain(line, source_name):
    """
    增强版域名清洗函数
    从原始规则行中提取有效的域名
    参数: line - 原始行内容，source_name - 规则源名称（用于调试）
    返回: 清洗后的域名，或 None 如果无法提取
    """
    line = line.strip()
    # 去除行首尾的空白字符（空格、制表符、换行等）
    
    if not line or line.startswith(('#', '!', '[', '/')):
        # 检查：如果行为空，或以 # ! [ / 开头，说明是注释行或无效行
        return None
        # 返回 None 表示跳过此行
    
    original = line
    # 保存原始行内容（调试用，当前未使用）
    
    # 处理 AdRules 格式 (DOMAIN,xxx.com) 或 (DOMAIN-SUFFIX,xxx.com)
    if ',' in line:
        # 如果行中包含逗号，可能是 AdRules 格式
        parts = [p.strip() for p in line.split(',')]
        # 按逗号分割，并用列表推导式去除每个部分的空白
        
        # 找最像域名的部分
        for part in parts:
            # 遍历分割后的每个部分
            part = part.lower().strip('.')
            # 转换为小写，并去除首尾的点和空白
            
            if is_valid_domain(part):
                # 使用 is_valid_domain 函数验证这部分是否为合法域名
                return part
                # 如果是，直接返回这个域名
        
        return None
        # 如果遍历完所有部分都没有找到合法域名，返回 None
    
    # 处理 anti-ad 格式 (.xxx.com)
    line = line.lstrip('.').lower()
    # lstrip('.') 去除行首的所有点号（anti-ad 格式域名前可能有 .）
    # lower() 转换为小写，统一格式
    
    line = line.split('^')[0].split('/')[0].split(':')[0]
    # 连续使用 split 去除可能的修饰符：
    # split('^')[0] 去除 ^ 及其后面的内容（如 ad.com^important）
    # split('/')[0] 去除 / 及其后面的内容（如 ad.com/path）
    # split(':')[0] 去除 : 及其后面的内容（如 ad.com:8080）
    
    # 排除 IP
    if IP_PATTERN.match(line):
        # 如果匹配 IP 地址格式
        return None
        # 返回 None，因为我们要的是域名，不是 IP
    
    if is_valid_domain(line):
        # 最后验证是否为合法域名
        return line
        # 是则返回
    
    return None
    # 否则返回 None

def compress_domains(domain_list):
    """
    O(n log n) 子域名压缩函数
    如果列表中有 example.com，则删除所有 *.example.com 的子域名
    参数: domain_list - 域名列表
    返回: (压缩后的列表, 被删除的数量)
    """
    # 按层级排序（短的在前，层级少的在前）
    sorted_domains = sorted(set(domain_list), key=lambda x: (x.count('.'), len(x)))
    # set(domain_list) 先去重
    # sorted 排序，key 是一个 lambda 函数：
    #   x.count('.') 计算点号数量（层级），层级少的排前面
    #   len(x) 长度，长度短的排前面
    # 这样 example.com 会排在 www.example.com 前面
    
    roots = set()
    # 创建一个集合，用于存储已经保留的"根"域名
    # 使用集合是因为查找速度快（O(1)）
    
    final = []
    # 最终保留的域名列表
    
    redundant = 0
    # 记录被剔除的冗余域名数量
    
    for domain in sorted_domains:
        # 遍历排序后的域名列表
        
        parts = domain.split('.')
        # 将域名按点号分割成列表，如 ['www', 'example', 'com']
        
        # 检查是否存在父域名
        is_redundant = False
        # 标记是否为冗余域名
        
        for i in range(1, len(parts)):
            # 从第1个位置开始遍历，生成所有可能的父域名
            # 如 www.example.com 会检查 example.com 和 com
            
            parent = '.'.join(parts[i:])
            # 用点号连接从第 i 个位置到末尾的部分，生成父域名
            
            if parent in roots:
                # 如果父域名已经在 roots 集合中
                is_redundant = True
                # 标记为冗余
                redundant += 1
                # 计数加1
                break
                # 跳出循环，不需要继续检查
        
        if not is_redundant:
            # 如果不是冗余域名
            final.append(domain)
            # 添加到最终列表
            roots.add(domain)
            # 同时添加到 roots 集合，供后续域名检查
    
    return final, redundant
    # 返回最终列表和被剔除的数量

def main():
    """
    主函数，程序入口
    """
    session = create_retry_session()
    # 创建带有重试机制的 HTTP 会话
    
    source_stats = []
    # 列表，存储每个规则源的统计信息
    
    all_domains = []
    # 列表，存储所有提取的域名（去重前）
    
    global_raw = 0
    # 整数，记录所有源的原始行数总和

    print("=" * 60)
    # 打印60个等号作为分隔线
    print("🚀 Loon 规则高效合并工具")
    # 打印程序标题
    print("=" * 60)
    # 打印分隔线

    for src in RULE_SOURCES:
        # 遍历配置中的每个规则源
        
        try:
            # 开始异常处理块，捕获可能的网络错误
            
            print(f"\n📥 拉取【{src['name']}】...")
            # 打印正在拉取的规则源名称
            
            resp = session.get(src['url'], timeout=30)
            # 发送 GET 请求获取规则文件，timeout=30 表示30秒超时
            
            resp.raise_for_status()
            # 检查响应状态，如果不是 2xx 会抛出异常
            
            lines = resp.text.splitlines()
            # 将响应文本按行分割成列表
            
            valid = []
            # 存储当前源提取的有效域名
            
            for line in lines:
                # 遍历每一行
                
                domain = clean_domain(line, src['name'])
                # 调用清洗函数提取域名
                
                if domain:
                    # 如果提取成功（不为 None）
                    valid.append(domain)
                    # 添加到有效列表
            
            unique = list(dict.fromkeys(valid))
            # dict.fromkeys(valid) 利用字典键的唯一性去重，同时保持顺序
            # 再转回列表
            
            source_stats.append({
                # 将统计信息添加到 source_stats 列表
                "name": src['name'],      # 规则源名称
                "raw": len(lines),        # 原始行数
                "valid": len(valid),      # 有效域名数
                "unique": len(unique),    # 去重后的数量
                "dedup": len(valid) - len(unique)  # 源内去重数量
            })
            
            all_domains.extend(unique)
            # 将当前源的去重域名添加到总列表
            
            global_raw += len(lines)
            # 累加原始行数
            
            print(f"✅ {src['name']}: {len(unique)} 条有效规则")
            # 打印成功信息和数量

        except Exception as e:
            # 捕获所有异常
            
            print(f"❌ 【{src['name']}】失败: {e}")
            # 打印错误信息

    if not all_domains:
        # 如果所有源都失败，all_domains 为空
        
        print("⚠️ 未获取到任何规则，退出")
        # 打印警告
        
        return
        # 结束函数

    # 全局处理
    global_unique = list(dict.fromkeys(all_domains))
    # 对所有源的域名进行全局去重（保持顺序）
    
    cross_dedup = len(all_domains) - len(global_unique)
    # 计算跨源重复的数量（合并前总数 - 去重后数量）
    
    final_domains, compressed = compress_domains(global_unique)
    # 调用压缩函数，剔除子域名冗余
    
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    # 获取当前 UTC 时间，加8小时转为北京时间
    # strftime 格式化为字符串：年-月-日 时:分:秒

    # 构建头部注释
    header_lines = [
        # 列表，存储头部注释的每一行
        "# Loon DOMAIN-SET 规则集",
        # 文件标题
        f"# 生成时间: {beijing_time} (UTC+8)",
        # 生成时间，使用 f-string 插入变量
        f"# 订阅地址: {SUBSCRIBE_URL}",
        # 订阅地址
        "#",
        # 空注释行
        "# 【规则源详情】"
        # 统计信息标题
    ]
    
    for i, s in enumerate(source_stats, 1):
        # enumerate 枚举列表，1 表示从1开始计数
        # i 是序号，s 是统计字典
        
        header_lines.append(f"# {i}. {s['name']}")
        # 添加规则源名称
        
        header_lines.append(f"#    原始: {s['raw']} | 有效: {s['valid']} | 源内去重: {s['dedup']}")
        # 添加详细统计
    
    header_lines.extend([
        # extend 批量添加列表元素
        "#",
        "# 【全局统计】",
        f"# 原始总行数: {global_raw}",
        f"# 跨源去重: {cross_dedup} | 子域压缩: {compressed}",
        f"# 最终规则: {len(final_domains)}",
        "#" + "=" * 50
        # 分隔线
    ])

    # 准备文件内容
    content = '\n'.join(header_lines) + '\n' + '\n'.join(f".{d}" for d in sorted(final_domains))
    # 分步解释：
    # '\n'.join(header_lines) 将头部列表用换行符连接成字符串
    # '\n'.join(f".{d}" for d in sorted(final_domains)) 将域名列表排序后，每个前加 . 再用换行连接
    # 中间用 + '\n' + 连接头部和域名部分
    
    try:
        # 异常处理块
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp:
            # 创建临时文件：
            # mode='w' 写入模式
            # delete=False 关闭后不自动删除（我们需要手动移动它）
            # encoding='utf-8' 使用 UTF-8 编码
            
            tmp.write(content)
            # 写入内容
            
            temp_path = tmp.name
            # 获取临时文件的路径
        
        os.replace(temp_path, OUTPUT_FILE)
        # 原子替换：将临时文件移动到最终位置
        # 这是原子操作，不会出现文件写一半的情况
        
        print(f"\n{'=' * 60}")
        # 打印分隔线
        
        print(f"✅ 完成！输出: {OUTPUT_FILE}")
        # 打印成功信息和文件名
        
        print(f"📊 最终规则数: {len(final_domains)} (压缩率: {(1-len(final_domains)/global_raw)*100:.1f}%)")
        # 打印统计信息，压缩率计算公式：(1 - 最终数/原始数) * 100，保留1位小数
        
        print(f"{'=' * 60}")
        # 打印分隔线
        
    except Exception as e:
        # 捕获文件操作异常
        
        print(f"❌ 写入失败: {e}")
        # 打印错误

if __name__ == "__main__":
    # 这是一个标准的 Python 入口检查
    # 当脚本直接运行（不是被导入）时，__name__ 等于 "__main__"
    
    main()
    # 调用主函数
