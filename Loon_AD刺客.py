#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 导入 requests 库，用于发送 HTTP 请求下载规则文件
import requests
# 导入 re 库，用于正则表达式匹配
import re
# 从 datetime 模块导入 datetime 和 timedelta，用于处理时间
from datetime import datetime, timedelta

# ==================== 配置区域 ====================

# 定义上游规则源列表，每个源包含名称和 URL
RULE_SOURCES = [
    # 第一个源：AdRules，GitHub 上的广告规则
    {"name": "AdRules", "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"},
    # 第二个源：anti-ad，anti-ad 项目的规则
    {"name": "anti-ad", "url": "https://anti-ad.net/surge2.txt"},
    # 第三个源：blackmatrix7 的域名规则
    {"name": "Advertising-Domain", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising_Domain.list"},
    # 第四个源：blackmatrix7 的广告规则
    {"name": "Advertising", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list"},
]

# 定义输出文件名
OUTPUT_FILE = "Loon_rules.txt"

# 定义订阅地址，用于文件头显示
SUBSCRIBE_URL = "https://ddcm1349.github.io/Loon/Loon_rules.txt"


def get_beijing_time():
    # 获取当前 UTC 时间
    utc_now = datetime.utcnow()
    # 加上 8 小时得到北京时间
    beijing_time = utc_now + timedelta(hours=8)
    # 格式化为字符串返回，格式：年-月-日 时:分:秒
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')


def is_valid_domain(domain):
    # 检查域名是否为空，或者长度超过 253 字符（RFC 限制）
    if not domain or len(domain) > 253:
        # 不合法，返回 False
        return False
    
    # 使用正则表达式检查域名字符，只允许小写字母、数字、横杠、点号
    if not re.match(r'^[a-z0-9\-\.]+$', domain):
        # 包含非法字符，返回 False
        return False
    
    # 检查是否有连续点号，或者以点开头/结尾（非法格式）
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        # 格式错误，返回 False
        return False
    
    # 按点号分割域名成各级标签
    labels = domain.split('.')
    
    # 检查是否至少有两级（如 example.com）
    if len(labels) < 2:
        # 只有一级，不合法
        return False
    
    # 遍历每一级标签进行检查
    for label in labels:
        # 检查标签长度是否在 1-63 字符之间
        if not 1 <= len(label) <= 63:
            # 长度不合法
            return False
        
        # 检查标签是否以横杠开头或结尾
        if label.startswith('-') or label.endswith('-'):
            # 横杠位置不合法
            return False
    
    # 检查最后一级（顶级域名）是否为纯数字
    if labels[-1].isdigit():
        # 顶级域名不能是纯数字
        return False
    
    # 所有检查通过，返回 True
    return True


def is_valid_ip_cidr(ip_str):
    # 定义正则表达式：匹配 x.x.x.x/xx 格式
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    
    # 检查字符串是否匹配正则
    if not re.match(pattern, ip_str):
        # 格式不匹配，返回 False
        return False
    
    # 尝试分割 IP 和掩码
    try:
        # 按斜杠分割，左边是 IP，右边是掩码
        ip_part, mask_part = ip_str.split('/')
        # 将掩码转为整数
        mask = int(mask_part)
        
        # 检查掩码是否在 0-32 范围内
        if not (0 <= mask <= 32):
            # 掩码不合法
            return False
        
        # 将 IP 按点号分割成四段
        parts = ip_part.split('.')
        
        # 遍历每一段
        for part in parts:
            # 转换为整数
            num = int(part)
            # 检查是否在 0-255 范围内
            if not 0 <= num <= 255:
                # 超出范围
                return False
        
        # 所有检查通过
        return True
    
    # 捕获任何异常（如转换失败）
    except:
        # 出现异常，返回 False
        return False


def is_valid_ip_cidr6(ip_str):
    # 检查是否包含斜杠（CIDR 必须有掩码）
    if '/' not in ip_str:
        # 没有斜杠，不是 CIDR 格式
        return False
    
    # 尝试解析
    try:
        # 从右边分割，避免 IPv6 地址中的冒号干扰
        ip_part, mask_part = ip_str.rsplit('/', 1)
        # 将掩码转为整数
        mask = int(mask_part)
        
        # 检查掩码是否在 0-128 范围内（IPv6 是 128 位）
        if not (0 <= mask <= 128):
            # 掩码不合法
            return False
        
        # 检查是否包含冒号（IPv6 必须有冒号）
        if ':' not in ip_part:
            # 没有冒号，不是 IPv6
            return False
        
        # 简化检查通过（完整 IPv6 验证较复杂，这里做基础检查）
        return True
    
    # 捕获任何异常
    except:
        # 出现异常，返回 False
        return False


def is_valid_pure_ip(ip_str):
    # 检查是否包含斜杠，纯 IP 不能有掩码
    if '/' in ip_str:
        # 有斜杠，不是纯 IP
        return False
    
    # 使用正则快速检查：只允许数字和点号
    if not re.match(r'^[\d\.]+$', ip_str):
        # 包含其他字符
        return False
    
    # 按点号分割
    parts = ip_str.split('.')
    
    # 检查是否恰好 4 段（IPv4 标准）
    if len(parts) != 4:
        # 不是 4 段
        return False
    
    # 尝试验证每一段
    try:
        # 遍历 4 段
        for part in parts:
            # 检查是否为空（如 "1.2.3." 这种）
            if not part:
                # 空段
                return False
            
            # 转为整数
            num = int(part)
            
            # 检查范围 0-255
            if not 0 <= num <= 255:
                # 超出范围
                return False
            
            # 检查前导零（如 "01" 不合法）
            if len(part) > 1 and part[0] == '0':
                # 有前导零
                return False
        
        # 所有检查通过
        return True
    
    # 转换失败（如包含非数字）
    except ValueError:
        # 不是纯数字
        return False


def is_loon_format(line):
    # 将行转为大写，用于不区分大小写的比较
    upper_line = line.upper()
    
    # 定义 Loon 格式的所有前缀
    prefixes = (
        'DOMAIN,',           # 精确域名
        'DOMAIN-SUFFIX,',    # 域名后缀
        'DOMAIN-KEYWORD,',   # 域名关键词
        'IP-CIDR,',          # IPv4 段
        'IP-CIDR6,',         # IPv6 段
    )
    
    # 检查是否以任意一个前缀开头
    for prefix in prefixes:
        if upper_line.startswith(prefix):
            # 匹配成功，是 Loon 格式
            return True
    
    # 都不匹配
    return False


def parse_loon_rule(line):
    # 按逗号分割成行
    parts = line.split(',')
    
    # 检查是否至少有两部分（类型和值）
    if len(parts) < 2:
        # 格式不完整，返回 None
        return None
    
    # 提取规则类型（去空格，转大写标准化）
    rule_type = parts[0].strip().upper()
    
    # 提取规则值（去空格）
    value = parts[1].strip()
    
    # 提取参数（如果有第三部分及以后）
    if len(parts) > 2:
        # 遍历剩余部分，去空格
        params = [p.strip() for p in parts[2:]]
    else:
        # 没有参数，设为空列表
        params = []
    
    # 返回三元组
    return (rule_type, value, params)


def normalize_rule(rule_type, value, params):
    # 分离 no-resolve 参数和其他参数
    # 遍历参数，保留不是 no-resolve 的
    other_params = []
    for p in params:
        # 转为小写比较，实现不区分大小写
        if p.lower() != 'no-resolve':
            other_params.append(p)
    
    # 检查原参数中是否有 no-resolve（任何大小写）
    has_no_resolve = False
    for p in params:
        if p.lower() == 'no-resolve':
            has_no_resolve = True
            break
    
    # 重组参数列表：其他参数 + no-resolve（如果有）
    final_params = other_params.copy()
    if has_no_resolve:
        final_params.append('no-resolve')
    
    # 如果有参数，拼接成完整规则字符串
    if final_params:
        # 用逗号连接参数
        params_str = ','.join(final_params)
        # 返回：类型,值,参数
        return f"{rule_type},{value},{params_str}"
    
    # 没有参数，返回简单格式
    return f"{rule_type},{value}"


def process_loon_line(line):
    # 调用解析函数，得到类型、值、参数
    parsed = parse_loon_rule(line)
    
    # 检查解析是否成功
    if parsed is None:
        # 解析失败，返回 None
        return None
    
    # 解包三元组
    rule_type, value, params = parsed
    
    # 定义支持的规则类型集合
    valid_types = {
        'DOMAIN',
        'DOMAIN-SUFFIX',
        'DOMAIN-KEYWORD',
        'IP-CIDR',
        'IP-CIDR6',
    }
    
    # 检查类型是否在支持列表中
    if rule_type not in valid_types:
        # 不支持的类型，丢弃
        return None
    
    # 定义域名类型集合（需要清洗 no-resolve 的）
    domain_types = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'}
    
    # 检查是否是域名类型
    if rule_type in domain_types:
        # 过滤掉 no-resolve 参数（域名规则不需要）
        new_params = []
        for p in params:
            if p.lower() != 'no-resolve':
                new_params.append(p)
        params = new_params
    
    # 根据类型进行值验证
    if rule_type in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
        # 域名类型：允许纯 IP 格式或合法域名
        value_lower = value.lower()
        # 检查是否是合法纯 IP
        is_ip = is_valid_pure_ip(value_lower)
        # 检查是否是合法域名
        is_domain = is_valid_domain(value_lower)
        # 两者都不是则丢弃
        if not is_ip and not is_domain:
            return None
    
    elif rule_type == 'IP-CIDR':
        # IPv4 段：验证 CIDR 格式
        if not is_valid_ip_cidr(value):
            return None
    
    elif rule_type == 'IP-CIDR6':
        # IPv6 段：验证 CIDR 格式
        if not is_valid_ip_cidr6(value):
            return None
    
    # 调用标准化函数，生成最终规则字符串
    return normalize_rule(rule_type, value, params)


def process_line_smart(line):
    # 去除行首尾的空白字符（空格、换行、制表符等）
    line = line.strip()
    
    # 检查是否为空行
    if not line:
        # 空行，返回 None
        return None
    
    # 检查是否是注释行（以 #、!、[ 开头）
    if line.startswith('#') or line.startswith('!') or line.startswith('['):
        # 注释行，返回 None
        return None
    
    # 检查是否已经是 Loon 格式
    if is_loon_format(line):
        # 是 Loon 格式，调用专门处理函数
        return process_loon_line(line)
    
    # 检查是否是 IPv4 CIDR 格式（带掩码）
    if is_valid_ip_cidr(line):
        # 是 IPv4 段，添加 IP-CIDR 前缀
        return f"IP-CIDR,{line}"
    
    # 检查是否是 IPv6 CIDR 格式（带掩码）
    if is_valid_ip_cidr6(line):
        # 是 IPv6 段，添加 IP-CIDR6 前缀
        return f"IP-CIDR6,{line}"
    
    # 检查是否是纯 IPv4 地址（无掩码）
    if is_valid_pure_ip(line):
        # 是纯 IP，转为 DOMAIN 格式（兼容可莉规则）
        return f"DOMAIN,{line}"
    
    # 检查是否以点开头（如 .google.com）
    if line.startswith('.'):
        # 去掉开头的点
        domain = line[1:]
        # 转为小写
        domain = domain.lower()
        # 验证是否为合法域名
        if is_valid_domain(domain):
            # 合法，转为 DOMAIN-SUFFIX
            return f"DOMAIN-SUFFIX,{domain}'
        # 不合法，返回 None
        return None
    
    # 尝试作为普通域名处理
    domain = line.lower()
    # 验证域名合法性
    if is_valid_domain(domain):
        # 合法，转为 DOMAIN
        return f"DOMAIN,{domain}'
    
    # 所有识别方式都失败，返回 None（丢弃）
    return None


def get_rule_key(rule):
    # 解析规则字符串
    parsed = parse_loon_rule(rule)
    
    # 检查解析是否成功
    if parsed is None:
        # 解析失败，用原字符串作为键
        return rule
    
    # 解包
    rule_type, value, params = parsed
    
    # 值转为小写，实现大小写不敏感比较
    value_lower = value.lower()
    
    # 检查是否有 no-resolve 参数
    has_no_resolve = False
    for p in params:
        if p.lower() == 'no-resolve':
            has_no_resolve = True
            break
    
    # 收集其他参数（排除 no-resolve），并排序
    other_params = []
    for p in params:
        if p.lower() != 'no-resolve':
            other_params.append(p.lower())
    other_params.sort()
    
    # 返回四元组作为唯一键
    return (rule_type.upper(), value_lower, tuple(other_params), has_no_resolve)


def get_rule_priority(rule):
    # 解析规则
    parsed = parse_loon_rule(rule)
    
    # 检查解析是否成功
    if parsed is None:
        # 未知类型，返回大数字排最后
        return 99
    
    # 提取类型
    rule_type = parsed[0]
    
    # 定义优先级映射，数字越小越靠前
    priority_map = {
        'DOMAIN-KEYWORD': 1,   # 关键字匹配优先
        'DOMAIN': 2,           # 精确域名次之
        'DOMAIN-SUFFIX': 3,    # 后缀匹配再次
        'IP-CIDR': 4,          # IPv4 段
        'IP-CIDR6': 5,         # IPv6 段最后
    }
    
    # 返回对应优先级，找不到则返回 99
    return priority_map.get(rule_type, 99)


def ip_to_int(ip_str):
    # 尝试转换
    try:
        # 按点号分割成四段
        parts = ip_str.split('.')
        # 将四段转为整数，并组合成 32 位整数
        # 第一段左移 24 位，第二段左移 16 位，第三段左移 8 位，第四段不变
        result = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        # 返回结果
        return result
    # 捕获任何异常
    except:
        # 转换失败，返回 None
        return None


def remove_ip_domain_redundant(domain_rules_with_value, ip_cidr_list):
    # 检查输入是否为空
    if not domain_rules_with_value:
        # 没有域名规则，直接返回空列表和 0
        return [], 0
    
    # 检查 IP 列表是否为空
    if not ip_cidr_list:
        # 没有 IP 规则，所有域名规则都保留
        rules_only = []
        for domain, rule in domain_rules_with_value:
            rules_only.append(rule)
        return rules_only, 0
    
    # 初始化计数器
    removed = 0
    # 初始化保留列表
    kept_rules = []
    
    # 遍历每个域名规则
    for domain, rule in domain_rules_with_value:
        # 尝试将域名转为 IP 整数
        ip_int = ip_to_int(domain)
        
        # 检查是否是纯 IP 格式
        if ip_int is None:
            # 不是 IP（是普通域名），直接保留
            kept_rules.append(rule)
            # 跳过检查，继续下一个
            continue
        
        # 标记是否被包含
        is_covered = False
        
        # 遍历所有 IP-CIDR 规则
        for kept_ip, kept_mask, _ in ip_cidr_list:
            # 计算需要右移的位数
            shift = 32 - kept_mask
            
            # 检查是否溢出
            if shift < 0:
                # 掩码异常，跳过
                continue
            
            # 比较网络位：右移后相等则在同一网段
            if (ip_int >> shift) == (kept_ip >> shift):
                # 被包含
                is_covered = True
                # 找到包含者，跳出循环
                break
        
        # 根据是否被包含决定保留或丢弃
        if is_covered:
            # 被 IP 段包含，计数+1
            removed += 1
            # 不加入保留列表（即丢弃）
        else:
            # 未被包含，保留
            kept_rules.append(rule)
    
    # 返回保留的规则列表和移除数量
    return kept_rules, removed


def dedup_rules(rules):
    # ========== 第1层：完全相同去重 ==========
    
    # 创建字典，用于记录已见过的键
    seen_keys = {}
    # 创建列表，存储去重后的规则
    unique_rules = []
    # 计数器：重复的规则数
    dup_removed = 0
    
    # 遍历所有规则
    for rule in rules:
        # 生成唯一键
        key = get_rule_key(rule)
        
        # 检查是否已存在
        if key not in seen_keys:
            # 不存在，记录并保留
            seen_keys[key] = rule
            unique_rules.append(rule)
        else:
            # 已存在，是重复，计数+1
            dup_removed += 1
    
    # 更新规则列表为去重后的
    rules = unique_rules
    
    # ========== 分类收集 ==========
    
    # 创建列表存储各类规则
    ip_cidr_rules = []      # IPv4 段，存储 (ip整数, 掩码, 原规则)
    ip_cidr6_rules = []     # IPv6 段，存储 (值小写, 原规则)
    domain_rules = []       # 精确域名，存储 (值小写, 原规则)
    suffix_rules = []       # 域名后缀，存储 (值小写, 原规则)
    keyword_rules = []      # 域名关键词，存储 (值小写, 原规则)
    
    # 遍历规则进行分类
    for rule in rules:
        # 解析规则
        parsed = parse_loon_rule(rule)
        
        # 检查解析是否成功
        if parsed is None:
            # 解析失败，跳过
            continue
        
        # 解包
        rule_type, value, params = parsed
        
        # 根据类型分类
        if rule_type == 'IP-CIDR':
            # IPv4 段，需要转为整数
            try:
                # 分割 IP 和掩码
                ip_str, mask_str = value.split('/')
                # 掩码转整数
                mask = int(mask_str)
                # 分割 IP 四段
                ip_parts = ip_str.split('.')
                # 转为 32 位整数
                ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
                # 添加到列表
                ip_cidr_rules.append((ip_int, mask, rule))
            except:
                # 转换失败，丢弃
                pass
        
        elif rule_type == 'IP-CIDR6':
            # IPv6 段，直接存小写值
            ip_cidr6_rules.append((value.lower(), rule))
        
        elif rule_type == 'DOMAIN':
            # 精确域名
            domain_rules.append((value.lower(), rule))
        
        elif rule_type == 'DOMAIN-SUFFIX':
            # 域名后缀
            suffix_rules.append((value.lower(), rule))
        
        elif rule_type == 'DOMAIN-KEYWORD':
            # 域名关键词
            keyword_rules.append((value.lower(), rule))
    
    # ========== 第2层：IP-CIDR 包含去重 ==========
    
    # 按掩码从大到小排序（更具体的优先）
    ip_cidr_rules.sort(key=lambda x: -x[1])
    
    # 创建列表存储保留的 IP 规则
    kept_ip_cidr = []
    # 计数器
    removed_ip_count = 0
    
    # 遍历每个 IP 规则
    for ip_int, mask, rule in ip_cidr_rules:
        # 标记是否被包含
        is_covered = False
        
        # 与已保留的规则比较
        for kept_ip, kept_mask, _ in kept_ip_cidr:
            # 只有更大的掩码（更小的网段）才可能包含当前
            if kept_mask <= mask:
                continue
            
            # 计算右移位数
            shift = 32 - kept_mask
            
            # 检查溢出
            if shift < 0:
                continue
            
            # 比较网络位
            if (ip_int >> shift) == (kept_ip >> shift):
                # 被包含
                is_covered = True
                break
        
        # 决定保留或丢弃
        if is_covered:
            removed_ip_count += 1
        else:
            kept_ip_cidr.append((ip_int, mask, rule))
    
    # ========== 第3层.1：DOMAIN 被 SUFFIX 包含 ==========
    
    # 创建集合，存储所有后缀（用于快速查找）
    suffix_domains = set()
    for domain, _ in suffix_rules:
        suffix_domains.add(domain)
    
    # 创建列表存储保留的 DOMAIN
    final_domain_rules = []
    # 计数器
    removed_domain_count = 0
    
    # 遍历每个 DOMAIN 规则
    for domain, rule in domain_rules:
        # 分割成各级
        parts = domain.split('.')
        # 标记是否被包含
        is_covered = False
        
        # 检查所有后缀
        for i in range(len(parts)):
            # 生成后缀
            suffix = '.'.join(parts[i:])
            # 检查是否在 suffix 集合中
            if suffix in suffix_domains:
                # 被后缀规则包含
                is_covered = True
                break
        
        # 决定保留或丢弃
        if is_covered:
            removed_domain_count += 1
        else:
            final_domain_rules.append(rule)
    
    # ========== 第3层.2：SUFFIX 内部包含 ==========
    
    # 按层级排序（短的优先，即范围大的优先）
    suffix_rules.sort(key=lambda x: len(x[0].split('.')))
    
    # 创建集合存储已保留的后缀
    kept_suffix_domains = set()
    # 创建列表存储保留的规则
    final_suffix_rules = []
    # 计数器
    redundant_suffix_count = 0
    
    # 遍历每个 SUFFIX 规则
    for domain, rule in suffix_rules:
        # 分割
        parts = domain.split('.')
        # 标记是否冗余
        is_redundant = False
        
        # 检查所有父级后缀（从1开始，跳过自己）
        for i in range(1, len(parts)):
            # 生成父级后缀
            parent_suffix = '.'.join(parts[i:])
            # 检查是否已保留
            if parent_suffix in kept_suffix_domains:
                # 被父级包含，冗余
                is_redundant = True
                break
        
        # 决定保留或丢弃
        if is_redundant:
            redundant_suffix_count += 1
        else:
            # 保留，并加入已保留集合
            kept_suffix_domains.add(domain)
            final_suffix_rules.append(rule)
    
    # ========== 新增：跨类型去重 ==========
    
    # 重建 domain_rules_with_value（只包含通过前面过滤的）
    final_domain_rules_with_value = []
    for domain, rule in domain_rules:
        # 检查是否在保留列表中
        if rule in final_domain_rules:
            final_domain_rules_with_value.append((domain, rule))
    
    # 调用跨类型去重函数
    final_domain_rules, cross_removed = remove_ip_domain_redundant(
        final_domain_rules_with_value, kept_ip_cidr
    )
    
    # ========== 合并结果 ==========
    
    # 按优先级顺序合并
    final_rules = []
    # 1. 关键字
    for rule in keyword_rules:
        final_rules.append(rule)
    # 2. 精确域名（已跨类型去重）
    for rule in final_domain_rules:
        final_rules.append(rule)
    # 3. 后缀
    for rule in final_suffix_rules:
        final_rules.append(rule)
    # 4. IPv4 段
    for _, _, rule in kept_ip_cidr:
        final_rules.append(rule)
    # 5. IPv6 段
    for _, rule in ip_cidr6_rules:
        final_rules.append(rule)
    
    # 计算总移除数
    total_removed = dup_removed + removed_ip_count + removed_domain_count + redundant_suffix_count + cross_removed
    
    # 返回结果
    return final_rules, total_removed


def main():
    # 打印启动信息
    print(f"[{get_beijing_time()}] 🚀 启动规则抓取...")
    # 打印分隔线
    print("=" * 60, flush=True)

    # 创建列表存储所有规则
    all_rules = []
    # 创建列表存储各源统计
    source_stats = []
    # 定义 HTTP 请求头
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; RuleFetcher/1.0)'}

    # 遍历每个上游源
    for src in RULE_SOURCES:
        # 异常处理
        try:
            # 打印拉取信息
            print(f"📥 拉取: {src['name']}...", flush=True)
            # 发送 HTTP GET 请求
            resp = requests.get(src['url'], timeout=30, headers=headers)
            # 检查 HTTP 状态码，非 200 会抛出异常
            resp.raise_for_status()
            
            # 按行分割响应内容
            lines = resp.text.splitlines()
            # 逐行处理，过滤掉 None（即不识别的行）
            processed = []
            for line in lines:
                result = process_line_smart(line)
                if result is not None:
                    processed.append(result)
            
            # 单源去重
            seen = set()           # 用于记录已见过的键
            unique_processed = []  # 存储去重后的规则
            
            for r in processed:
                # 生成键
                key = get_rule_key(r)
                # 检查是否已存在
                if key not in seen:
                    # 不存在，加入集合和列表
                    seen.add(key)
                    unique_processed.append(r)
            
            # 打印统计信息
            print(f"   原始: {len(lines)} | 提取: {len(unique_processed)}", flush=True)
            
            # 记录统计
            source_stats.append({
                "name": src['name'],      # 源名称
                "raw": len(lines),         # 原始行数
                "valid": len(unique_processed)  # 有效规则数
            })
            
            # 添加到总列表
            all_rules.extend(unique_processed)
            # 打印完成标记
            print(f"✅ 完成", flush=True)

        # 捕获异常
        except Exception as e:
            # 打印错误信息
            print(f"❌ 失败: {e}", flush=True)
            # 导入 traceback 模块
            import traceback
            # 打印详细错误堆栈
            traceback.print_exc()

    # 打印分隔线
    print("=" * 60, flush=True)
    # 打印全局去重信息
    print(f"🔄 全局去重优化（总计 {len(all_rules)} 条）...", flush=True)
    
    # 调用全局去重函数
    final_rules, total_removed = dedup_rules(all_rules)
    # 按优先级和字母顺序排序
    final_rules.sort(key=lambda r: (get_rule_priority(r), r.lower()))
    
    # 创建字典统计各类型数量
    type_counts = {}
    for r in final_rules:
        # 解析规则
        parsed = parse_loon_rule(r)
        if parsed:
            # 提取类型
            t = parsed[0]
            # 计数
            if t in type_counts:
                type_counts[t] += 1
            else:
                type_counts[t] = 1
    
    # 打印最终结果统计
    print(f"\n📊 最终结果: {len(final_rules)} 条", flush=True)
    # 按优先级排序打印各类型
    for t, c in sorted(type_counts.items(), key=lambda x: get_rule_priority(f"{x[0]},")):
        print(f"   • {t}: {c} 条", flush=True)

    # 构建文件头
    header = []
    header.append(f"# Loon_AD刺客")
    header.append(f"# 生成时间: {get_beijing_time()}")
    header.append(f"# 统计: {len(final_rules)} 条")
    header.append(f"# 优化: 移除 {total_removed} 条冗余规则")
    header.append(f"# 订阅地址: {SUBSCRIBE_URL}")  # 订阅地址
    header.append("# " + "=" * 58)
    
    # 添加各源统计
    for s in source_stats:
        header.append(f"# 源: {s['name']} | 原始 {s['raw']} | 提取 {s['valid']}")
    
    # 添加分隔线
    header.append("# " + "-" * 58)
    # 添加各类型统计
    for t, c in sorted(type_counts.items(), key=lambda x: get_rule_priority(f"{x[0]},")):
        header.append(f"# {t}: {c}")
    # 添加结束分隔线
    header.append("# " + "=" * 58)

    # 打开文件写入
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # 写入文件头（换行连接）
        f.write('\n'.join(header))
        # 写入两个空行
        f.write('\n\n')
        # 写入规则（换行连接）
        f.write('\n'.join(final_rules))

    # 打印保存信息
    print(f"\n💾 已保存: {OUTPUT_FILE}", flush=True)
    # 打印完成信息
    print(f"[{get_beijing_time()}] 🎉 完成!", flush=True)


# 脚本入口
if __name__ == "__main__":
    # 调用主函数
    main()
