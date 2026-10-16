#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网络探测原语（仅保留代理层原语，2026-10-15 重构）

connect_check    向代理发原始 CONNECT，拿代理层响应码/X-Squid-Error
                 （层0健康检查 + 执行后复测观察用）
wait_proxy_ready reconfigure 后等待监听端口恢复（kid 重绑 30~50ms 窗口）
resolve_ok       域名能否在本机解析（准入判定：解析不出=死条目→驳回）

直连探测 / 国内外归属 / 经代理完整GET 均已随"准入控制不判断可达性"删除。
"""

import time
import socket
import ssl
import threading
import logging

log = logging.getLogger("netprobe")


def resolve_ok(domain, timeout=3.0, attempts=2):
    """域名能否在本机解析（与 squid 建隧道同一解析环境）。

    解析出任意 A/AAAA 即算可解析（不判断可达性）。getaddrinfo 没有超时
    参数，用 daemon 线程 + Event 限时，失败/超时重试 attempts-1 次抗
    瞬时抖动；daemon 线程不会阻塞进程退出。整体 DNS 故障时钉钉拉取
    （同样依赖解析）会先失败、记录原样保留，不会造成批量误驳。
    """
    for _ in range(attempts):
        done, ok = threading.Event(), []

        def _lookup():
            try:
                socket.getaddrinfo(domain, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
                ok.append(True)
            except OSError:
                ok.append(False)
            finally:
                done.set()

        threading.Thread(target=_lookup, daemon=True).start()
        if done.wait(timeout) and ok and ok[0]:
            return True
    return False


def connect_check(target, proxy_host='127.0.0.1', proxy_port=13128,
                  timeout=8, proxy_auth=None, proxy_tls=False):
    """向代理发原始 CONNECT，返回代理层判定：

    {'status': 200/403/..., 'denied': bool, 'x_squid_error': str|None,
     'error': str|None}
    denied=True 即代理层 ACL 拒绝（403 出现在 CONNECT 阶段只可能来自代理自身）。
    proxy_tls=True 用于 squid https_port（TLS封装的代理端口，常见自签证书）。
    """
    req = 'CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n' % (target, target)
    if proxy_auth:
        import base64
        token = base64.b64encode(proxy_auth.encode()).decode()
        req += 'Proxy-Authorization: Basic %s\r\n' % token
    req += '\r\n'

    sock = None
    try:
        sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
        if proxy_tls:
            # 代理是本机/内网节点，证书多为自签：不校验代理证书；
            # 隧道内目标的安全由端到端 TLS 保证，与代理层证书无关
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=proxy_host)
        sock.sendall(req.encode())
        buf = b''
        while b'\r\n\r\n' not in buf and len(buf) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        return {'status': None, 'denied': False, 'x_squid_error': None,
                'error': '代理连接超时'}
    except OSError as e:   # 含 ssl.SSLError（其子类）
        return {'status': None, 'denied': False, 'x_squid_error': None,
                'error': '代理连接失败，%s' % e}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    head = buf.decode('utf-8', errors='replace')
    status_line = head.split('\r\n', 1)[0]
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError):
        return {'status': None, 'denied': False, 'x_squid_error': None,
                'error': '无法解析代理响应，%r' % status_line[:120]}
    x_err = None
    for line in head.split('\r\n'):
        if line.lower().startswith('x-squid-error:'):
            x_err = line.split(':', 1)[1].strip()
    return {'status': status, 'denied': status == 403,
            'x_squid_error': x_err, 'error': None}


def wait_proxy_ready(proxy_host='127.0.0.1', proxy_port=13128, timeout=5.0):
    """等待代理恢复接受连接。

    squid reconfigure 期间 kid 会先关闭监听端口再重绑（2026-09-20 实测 squid 6.14
    窗口约 30~50ms，期间连接 100% 被拒）。reconfigure 命令返回不代表端口已恢复，
    复测/探测前必须等就绪。返回是否就绪。
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((proxy_host, int(proxy_port)), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.02)
    return False
