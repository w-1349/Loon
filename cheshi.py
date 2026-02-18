#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Loon 规则源抓取测试工具
测试目标: https://rule.kelee.one/Loon/Advertising.lsr
测试方法: 模拟 Loon/Quantumult X/Surge 的请求特征
"""

import requests
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 测试目标
TEST_URL = "https://rule.kelee.one/Loon/Advertising.lsr"

# 各种代理工具的请求头模拟
USER_AGENTS = {
    # 1. 模拟 Loon [^12^][^13^]
    "loon": {
        "User-Agent": "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    # 2. 模拟 Quantumult X [^14^]
    "quanx": {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    # 3. 模拟 Surge
    "surge": {
        "User-Agent": "Surge/4.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    # 4. 模拟 Shadowrocket
    "shadowrocket": {
        "User-Agent": "Shadowrocket/2.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    # 5. 标准浏览器
    "browser": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    # 6. GitHub Actions 默认
    "github": {
        "User-Agent": "GitHubActionsRunner/2.0",
        "Accept": "*/*",
    }
}

def create_session(headers):
    """创建带重试的会话"""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update(headers)
    return session

def test_fetch(name, headers, timeout=30):
    """测试单个请求头"""
    print(f"\n{'='*60}")
    print(f"测试: {name}")
    print(f"User-Agent: {headers.get('User-Agent', 'N/A')[:50]}...")
    print(f"{'='*60}")
    
    try:
        session = create_session(headers)
        start = time.time()
        resp = session.get(TEST_URL, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - start
        
        print(f"状态码: {resp.status_code}")
        print(f"耗时: {elapsed:.2f}s")
        print(f"内容长度: {len(resp.text)} 字符")
        print(f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}")
        
        if resp.status_code == 200:
            # 显示前10行内容预览
            lines = resp.text.split('\n')[:10]
            print(f"\n内容预览 (前10行):")
            for i, line in enumerate(lines, 1):
                print(f"  {i}: {line[:80]}")
            
            # 检查是否是规则文件
            if any(kw in resp.text for kw in ['DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'REJECT', 'PROXY']):
                print(f"\n✅ 成功获取规则文件!")
                return True, resp.text
            else:
                print(f"\n⚠️ 返回内容可能不是规则文件")
                return False, resp.text
        else:
            print(f"\n❌ 请求失败: HTTP {resp.status_code}")
            return False, None
            
    except requests.exceptions.Timeout:
        print(f"\n❌ 请求超时 (> {timeout}s)")
        return False, None
    except requests.exceptions.ConnectionError as e:
        print(f"\n❌ 连接错误: {e}")
        return False, None
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        return False, None

def test_with_referer(name, base_headers, referer):
    """测试添加 Referer"""
    headers = base_headers.copy()
    headers["Referer"] = referer
    print(f"\n添加 Referer: {referer}")
    return test_fetch(f"{name}+Referer", headers)

def main():
    print("=" * 60)
    print("Loon 规则源抓取测试工具")
    print(f"目标: {TEST_URL}")
    print("=" * 60)
    
    results = {}
    
    # 1. 基础测试 - 各种 User-Agent
    for name, headers in USER_AGENTS.items():
        success, content = test_fetch(name, headers)
        results[name] = {"success": success, "content": content}
        time.sleep(1)  # 避免请求过快
    
    # 2. 如果基础测试失败，尝试添加 Referer
    if not any(r["success"] for r in results.values()):
        print("\n" + "=" * 60)
        print("基础测试全部失败，尝试添加 Referer...")
        print("=" * 60)
        
        referers = [
            "https://www.nsloon.com/",
            "https://loon0x00.github.io/",
            "https://github.com/",
            "https://raw.githubusercontent.com/",
        ]
        
        for referer in referers:
            success, content = test_with_referer("loon", USER_AGENTS["loon"], referer)
            if success:
                results[f"loon+{referer}"] = {"success": True, "content": content}
                break
            time.sleep(1)
    
    # 3. 总结
    print("\n" + "=" * 60)
    print("测试结果总结")
    print("=" * 60)
    
    for name, result in results.items():
        status = "✅ 成功" if result["success"] else "❌ 失败"
        print(f"{status}: {name}")
    
    # 找出成功的方案
    successful = [(name, r["content"]) for name, r in results.items() if r["success"]]
    
    if successful:
        print(f"\n🎉 找到 {len(successful)} 个成功的请求方案!")
        best_name, best_content = successful[0]
        print(f"推荐使用: {best_name}")
        
        # 保存结果
        output_file = f"test_result_{best_name}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(best_content)
        print(f"结果已保存: {output_file}")
        
        # 统计规则数量
        lines = best_content.split('\n')
        domain_count = sum(1 for l in lines if l.startswith('DOMAIN'))
        suffix_count = sum(1 for l in lines if l.startswith('DOMAIN-SUFFIX'))
        keyword_count = sum(1 for l in lines if l.startswith('DOMAIN-KEYWORD'))
        ip_count = sum(1 for l in lines if l.startswith('IP-CIDR'))
        
        print(f"\n规则统计:")
        print(f"  DOMAIN: {domain_count}")
        print(f"  DOMAIN-SUFFIX: {suffix_count}")
        print(f"  DOMAIN-KEYWORD: {keyword_count}")
        print(f"  IP-CIDR: {ip_count}")
        print(f"  总计: {len([l for l in lines if l.strip() and not l.startswith('#')])}")
        
    else:
        print("\n💥 所有测试方案均失败")
        print("可能原因:")
        print("  1. 规则源需要特定的 TLS/SSL 指纹")
        print("  2. 规则源需要特定的 IP 地区 (仅允许特定国家访问)")
        print("  3. 规则源已失效或地址变更")
        print("  4. 需要特殊的 Cookie 或 Token 认证")
        print("\n建议:")
        print("  - 在本地 Loon 应用中查看实际的请求头")
        print("  - 使用 Charles/Fiddler 抓包获取真实请求特征")
        print("  - 尝试通过代理服务器访问")

if __name__ == "__main__":
    main()
