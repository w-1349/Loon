#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Loon 规则源高级绕过测试
针对 rule.kelee.one 的 403 防护
技术：TLS伪装、HTTP/2、头伪造、路径混淆
"""

import requests
import urllib3
import time
import os
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 禁用警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_URL = "https://rule.kelee.one/Loon/Advertising.lsr"

# 高级绕过方案
BYPASS_TECHNIQUES = {
    # 1. 基础 Loon 模拟
    "loon_basic": {
        "headers": {
            "User-Agent": "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh-Hans;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }
    },
    
    # 2. 添加 IP 伪造头（尝试绕过 IP 限制）[^18^]
    "ip_spoof": {
        "headers": {
            "User-Agent": "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh-Hans;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "X-Forwarded-For": "223.5.5.5",  # 阿里云 DNS，国内 IP
            "X-Real-IP": "223.5.5.5",
            "X-Originating-IP": "223.5.5.5",
            "CF-Connecting-IP": "223.5.5.5",
        }
    },
    
    # 3. 模拟 Cloudflare 合法客户端
    "cloudflare_client": {
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    },
    
    # 4. 尝试路径混淆 [^17^]
    "path_fuzz": {
        "url": "https://rule.kelee.one/Loon//Advertising.lsr",  # 双斜杠
        "headers": {
            "User-Agent": "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Accept": "*/*",
        }
    },
    
    # 5. 尝试大小写混淆 [^17^]
    "case_fuzz": {
        "url": "https://rule.kelee.one/Loon/ADVERTISING.lsr",  # 大写
        "headers": {
            "User-Agent": "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Accept": "*/*",
        }
    },
    
    # 6. 尝试添加查询参数（绕过缓存/过滤）
    "query_param": {
        "url": "https://rule.kelee.one/Loon/Advertising.lsr?v=1&t=" + str(int(time.time())),
        "headers": {
            "User-Agent": "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Accept": "*/*",
        }
    },
    
    # 7. 模拟 GitHub Raw（如果源允许 GitHub 引用）
    "github_raw": {
        "headers": {
            "User-Agent": "github-camo (ba2fed7e)",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
        }
    },
    
    # 8. 使用 HTTP/1.0（某些防护对 1.1 更严格）[^22^]
    "http10": {
        "headers": {
            "User-Agent": "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Accept": "*/*",
        },
        "http_version": "HTTP/1.0"
    },
}

def create_session(headers, http_version=None):
    """创建会话，可选 HTTP 版本"""
    session = requests.Session()
    
    # 强制使用 HTTP/1.0 或 HTTP/1.1
    if http_version == "HTTP/1.0":
        session.headers["Connection"] = "close"
    
    # 使用适配器
    adapter = HTTPAdapter(
        max_retries=Retry(total=2, backoff_factor=1),
        pool_connections=10,
        pool_maxsize=10,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    session.headers.update(headers)
    return session

def test_technique(name, config):
    """测试单个绕过技术"""
    print(f"\n{'='*60}")
    print(f"测试: {name}")
    print(f"{'='*60}")
    
    url = config.get("url", TEST_URL)
    headers = config.get("headers", {})
    http_version = config.get("http_version")
    
    print(f"URL: {url[:70]}...")
    print(f"User-Agent: {headers.get('User-Agent', 'N/A')[:50]}...")
    
    try:
        session = create_session(headers, http_version)
        
        start = time.time()
        resp = session.get(
            url, 
            timeout=30, 
            allow_redirects=True,
            verify=True,  # 验证 SSL
        )
        elapsed = time.time() - start
        
        print(f"状态码: {resp.status_code}")
        print(f"耗时: {elapsed:.2f}s")
        print(f"Server: {resp.headers.get('Server', 'N/A')}")
        print(f"CF-Ray: {resp.headers.get('CF-RAY', 'N/A')[:20]}...")  # Cloudflare 标识
        
        if resp.status_code == 200:
            content_preview = resp.text[:500]
            print(f"\n内容预览:\n{content_preview}")
            
            # 验证是否是规则文件
            is_rule = any(kw in resp.text for kw in ['DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'REJECT', 'PROXY', 'FINAL'])
            if is_rule:
                print(f"\n✅ 成功获取规则文件! ({len(resp.text)} 字符)")
                return True, resp.text
            else:
                print(f"\n⚠️ 返回内容不是规则文件")
                return False, resp.text
        else:
            print(f"\n❌ 失败: HTTP {resp.status_code}")
            # 打印响应头帮助调试
            if 'CF-RAY' in resp.headers:
                print("提示: 这是 Cloudflare 防护，可能需要更强的绕过")
            return False, None
            
    except requests.exceptions.SSLError as e:
        print(f"\n❌ SSL 错误: {e}")
        return False, None
    except requests.exceptions.ProxyError as e:
        print(f"\n❌ 代理错误: {e}")
        return False, None
    except Exception as e:
        print(f"\n❌ 错误: {type(e).__name__}: {e}")
        return False, None

def test_with_curl():
    """尝试使用 curl 命令（如果可用）"""
    print(f"\n{'='*60}")
    print("测试: 系统 curl 命令")
    print(f"{'='*60}")
    
    import subprocess
    
    curl_cmd = [
        "curl", "-v", "-L", "-A", 
        "Loon/3.5 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        "--connect-timeout", "30",
        "--max-time", "60",
        TEST_URL
    ]
    
    try:
        result = subprocess.run(
            curl_cmd, 
            capture_output=True, 
            text=True, 
            timeout=60
        )
        
        print(f"返回码: {result.returncode}")
        print(f"stderr: {result.stderr[:500]}...")
        
        if result.returncode == 0 and result.stdout:
            print(f"内容长度: {len(result.stdout)} 字符")
            if any(kw in result.stdout for kw in ['DOMAIN', 'DOMAIN-SUFFIX']):
                print("✅ curl 成功获取规则!")
                return True, result.stdout
        return False, None
    except FileNotFoundError:
        print("❌ 系统中没有 curl 命令")
        return False, None
    except Exception as e:
        print(f"❌ curl 错误: {e}")
        return False, None

def main():
    print("=" * 70)
    print("Loon 规则源高级绕过测试")
    print(f"目标: {TEST_URL}")
    print(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    results = {}
    
    # 测试所有绕过技术
    for name, config in BYPASS_TECHNIQUES.items():
        success, content = test_technique(name, config)
        results[name] = {"success": success, "content": content}
        time.sleep(2)  # 避免触发频率限制
    
    # 尝试 curl（如果其他方法都失败）
    if not any(r["success"] for r in results.values()):
        success, content = test_with_curl()
        results["curl"] = {"success": success, "content": content}
    
    # 总结
    print("\n" + "=" * 70)
    print("测试结果总结")
    print("=" * 70)
    
    for name, result in results.items():
        status = "✅ 成功" if result["success"] else "❌ 失败"
        content_len = len(result["content"]) if result["content"] else 0
        print(f"{status}: {name:<20} ({content_len:>6} 字符)")
    
    # 保存最佳结果
    successful = [(name, r["content"]) for name, r in results.items() if r["success"]]
    
    if successful:
        best_name, best_content = successful[0]
        print(f"\n🎉 最佳方案: {best_name}")
        
        # 保存文件
        output_file = f"success_{best_name}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(best_content)
        print(f"📁 已保存: {output_file}")
        
        # 统计
        lines = best_content.split('\n')
        stats = {
            'DOMAIN': sum(1 for l in lines if l.startswith('DOMAIN,')),
            'DOMAIN-SUFFIX': sum(1 for l in lines if l.startswith('DOMAIN-SUFFIX,')),
            'DOMAIN-KEYWORD': sum(1 for l in lines if l.startswith('DOMAIN-KEYWORD,')),
            'IP-CIDR': sum(1 for l in lines if l.startswith('IP-CIDR')),
            'TOTAL': len([l for l in lines if l.strip() and not l.startswith('#')]),
        }
        print(f"\n规则统计:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        
        # 生成 GitHub Actions 输出
        if os.environ.get('GITHUB_ACTIONS'):
            print(f"\n::set-output name=success::true")
            print(f"::set-output name=method::{best_name}")
            print(f"::set-output name=count::{stats['TOTAL']}")
        
        return 0
    else:
        print("\n💥 所有绕过技术均失败")
        print("\n可能原因:")
        print("  1. Cloudflare 的 TLS 指纹检测（需要 curl-impersonate）")
        print("  2. 严格的 IP 地区限制（仅允许中国大陆访问）")
        print("  3. 需要特定的 Cookie 或 Token")
        print("  4. 规则源已失效")
        print("\n建议:")
        print("  - 在本地使用 Stream/Thor 抓包 Loon 的真实请求")
        print("  - 尝试使用 curl-impersonate 或 selenium")
        print("  - 联系规则源作者获取镜像地址")
        
        # 保存错误日志
        with open("fail_log.txt", 'w') as f:
            f.write(f"Failed at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            for name, r in results.items():
                f.write(f"{name}: {r['success']}\n")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())
