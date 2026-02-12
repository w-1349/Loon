#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests  # 导入网络请求库，用于下载远程规则文件
import re        # 导入正则表达式库，用于精准匹配域名字符
from datetime import datetime, timedelta  # 导入时间模块，用于生成北京时间
from requests.adapters import HTTPAdapter  # 导入适配器，用于配置请求重试
from urllib3.util.retry import Retry     # 导入重试策略模块

# —— 核心配置区 ——
RULE_SOURCES = [
    {"name": "anti-AD", "url": "https://anti-ad.net/surge2.txt"},      # 规则源1：纯域名带点格式
    {"name": "AdRules", "url": "https://adrules.top/adrules.list"}     # 规则源2：DOMAIN-SUFFIX格式
]
OUTPUT_FILE = "Loon_rules.txt"  # 最终生成的合并文件名

def create_retry_session():
    """创建带自动重试机制的网络请求会话，增强稳定性"""
    session = requests.Session()  # 实例化一个新的请求会话
    # 配置重试参数：总共重试3次，间隔时间随重试次数递增，针对特定的服务器错误码进行重试
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))  # 为HTTPS协议挂载重试策略
    return session

def clean_domain(line):
    """
    核心清洗函数：将不同格式的行统一转换为标准纯域名
    支持处理：.example.com 和 DOMAIN-SUFFIX,example.com
    """
    line = line.strip()  # 去除每一行前后的空格或换行符
    
    # 1. 排除无效行：跳过空行、以 # 或 ! 或 [ 开头的注释/标题行
    if not line or line.startswith(('#', '!', '[')): 
        return None
    
    # 2. 处理 AdRules 格式：如果包含逗号，说明带有 DOMAIN-SUFFIX 标记
    if ',' in line:
        # 使用逗号分割，取逗号后面的部分（即真实的域名部分）
        parts = line.split(',')
        for part in parts:
            part = part.strip()
            # 逻辑判断：包含点号且不是全大写的指令（如 REJECT），则认定为域名
            if '.' in part and not part.isupper():
                line = part
                break
    
    # 3. 统一化处理：去掉域名最左侧的域名点（例如 .google.com 变为 google.com），并转为小写
    line = line.lstrip('.').lower()
    
    # 4. 合法性校验：使用正则表达式确保剩下的字符只包含字母、数字、中划线和点号
    if re.match(r'^[a-z0-9\-\.]+$', line) and '.' in line:
        return line
    return None

def compress_domains(domain_list):
    """
    子域名压缩算法：后缀匹配去重（DOMAIN-SET 专属优化）
    原理：如果已经有了 google.com，那么 ads.google.com 就是多余的冗余规则
    """
    # 按域名长度从小到大排序，优先处理短的“根域名”
    sorted_domains = sorted(list(domain_list), key=len)
    final_list = []      # 用于存储最终精简后的域名列表
    redundant_count = 0  # 冗余记录计数器
    
    for domain in sorted_domains:
        is_redundant = False
        # 将当前域名与已经存入最终列表的根域名进行对比
        for root in final_list:
            # 如果当前域名以“.根域名”结尾，说明它是该根域名的子域名，属于冗余
            if domain.endswith('.' + root) or domain == root:
                is_redundant = True
                redundant_count += 1
                break
        if not is_redundant:
            final_list.append(domain)  # 只有非冗余的域名才会被保留
    return final_list, redundant_count

def main():
    """脚本执行主逻辑"""
    session = create_retry_session()  # 获取带重试功能的会话
    all_raw_domains = []             # 汇总所有源的原始有效域名列表
    source_reports = []              # 存储每个源的统计数据报告
    global_stats = {"raw_lines": 0}  # 统计所有源的总行数

    print("="*50 + "\n🚀 开始执行 Loon 域名集合合并任务\n" + "="*50)
    
    for src in RULE_SOURCES:
        try:
            print(f"📥 正在拉取规则源【{src['name']}】...")
            resp = session.get(src['url'], timeout=30)  # 发起网络请求下载文件
            lines = resp.text.splitlines()            # 将下载的内容按行切分
            
            # 清洗当前源的所有行，并过滤掉 None 值
            src_valid = [d for d in (clean_domain(l) for l in lines) if d]
            # 执行源内去重，确保单个源文件内没有重复项
            unique_src = list(dict.fromkeys(src_valid))
            
            # 记录当前源的详细统计数据
            source_reports.append({"name": src['name'], "raw": len(lines), "valid": len(src_valid)})
            all_raw_domains.extend(unique_src)  # 将处理后的域名加入全局汇总池
            global_stats["raw_lines"] += len(lines)
            print(f"✅ 拉取成功: {src['name']} | 有效域名总数: {len(src_valid)}")
        except Exception as e:
            print(f"❌ 拉取失败: {src['name']} | 错误原因: {e}")

    # 第一阶段去重：跨源完全重复项去重
    unique_global = list(dict.fromkeys(all_raw_domains))
    cross_dedup = len(all_raw_domains) - len(unique_global)  # 计算跨源重复的数量
    
    # 第二阶段去重：执行子域名包含关系压缩（后缀匹配精简）
    final_domains, compressed_count = compress_domains(unique_global)
    
    # 获取当前北京时间 (UTC+8) 用于头部注释
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

    # 构建生成的规则文件头部注释信息
    header = [
        f"# Loon 域名集合 (DOMAIN-SET) 合并版",
        f"# 生成时间: {beijing_time} (北京时间)",
        f"# " + "="*40
    ]
    for r in source_reports:
        header.append(f"# 源【{r['name']}】: 提取有效规则 {r['valid']} 条")
    header.append(f"# 跨源去重: {cross_dedup} 条 | 子域冗余压缩: {compressed_count} 条")
    header.append(f"# 最终合并总数: {len(final_domains)} 条")
    header.append(f"# " + "="*40 + "\n")

    # 最终输出：统一为带点前缀格式（.example.com），按字母顺序排列并写入文件
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(header + [f".{d}" for d in sorted(final_domains)]))
    
    # 在控制台打印最终统计汇总，方便在 GitHub Actions 日志中直接查看
    print(f"\n📊 最终合并统计汇总:")
    print(f"- 原始总行数汇总: {global_stats['raw_lines']}")
    print(f"- 跨源重复项已剔除: {cross_dedup}")
    print(f"- 子域冗余项已压缩: {compressed_count}")
    print(f"- 最终输出文件总量: {len(final_domains)}")
    print(f"🚀 文件处理完成，已保存为: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()  # 运行主程序
