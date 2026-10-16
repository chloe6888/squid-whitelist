#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fake_proxy —— 模拟 squid 的 CONNECT 行为（本地测试用）

- 监听 127.0.0.1:$FAKE_PROXY_PORT（默认13128）
- 按 FAKE_PROXY_LIST 指向的白名单文件做匹配，每次请求重读文件
  → 模拟"reconfigure 后新规则即时生效"
- 语义对齐：真实 squid 6.14 dstdomain 实测（2026-09-20）——裸条目仅精确匹配，
  点前缀 .example.com 覆盖裸域+全部子域。生产链路只写点前缀（store_format=dot_prefix），
  本桩对每条规则按点前缀语义匹配，与生产写入形态等价
- 命中 → 200 Connection established，并建立真实隧道双向转发（观察性 CONNECT
  只取状态行，隧道能力保留以备扩展）；未命中 → 403 + X-Squid-Error: ERR_ACCESS_DENIED
- 存在 FAKE_PROXY_DENY_FILE 文件时全部拒绝（用于演练代理全拒场景）

可独立运行：python3 fake_proxy.py
也可被 sim_test.py 作为线程内嵌。
"""

import os
import socket
import threading

HOST = '127.0.0.1'


class FakeSquidProxy:
    def __init__(self, list_file, port=13128, deny_file=None):
        self.list_file = list_file
        self.port = port
        self.deny_file = deny_file
        self._srv = None
        self._thread = None

    # ---- 白名单判定（点前缀语义：裸域+全部子域；生产只写点前缀条目） ----
    def _allowed(self, host):
        if self.deny_file and os.path.exists(self.deny_file):
            return False
        host = host.lower().strip().lstrip('.')
        try:
            with open(self.list_file, encoding='utf-8') as f:
                rules = f.read().split()
        except OSError:
            rules = []
        for r in rules:
            r = r.lower().lstrip('.')
            if host == r or host.endswith('.' + r):
                return True
        return False

    def _handle(self, conn):
        upstream = None
        try:
            buf = b''
            while b'\r\n\r\n' not in buf and len(buf) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            parts = buf.split(b'\r\n')[0].decode(errors='replace').split()
            hostport = parts[1] if len(parts) > 1 else ':'
            host, _, port = hostport.rpartition(':')
            port = int(port) if port.isdigit() else 443
            if self._allowed(host):
                # 200 后建立真实隧道并双向转发（对齐真实代理行为；上层
                # connect_check 只取状态行即断开）
                conn.sendall(b'HTTP/1.1 200 Connection established\r\n'
                             b'Server: fakesquid\r\n\r\n')
                upstream = socket.create_connection((host, port), timeout=15)
                self._relay(conn, upstream)
            else:
                conn.sendall(b'HTTP/1.1 403 Forbidden\r\nServer: fakesquid\r\n'
                             b'X-Squid-Error: ERR_ACCESS_DENIED 0\r\n'
                             b'Content-Length: 0\r\n\r\n')
        except OSError:
            pass
        finally:
            for s in (conn, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    @staticmethod
    def _relay(a, b):
        """双向泵：任一方断开/出错即结束（与真实代理的隧道行为一致）。"""
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        t = threading.Thread(target=pump, args=(b, a), daemon=True)
        t.start()
        pump(a, b)

    def _serve(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return  # socket closed -> stop
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    # ---- 生命周期 ----
    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((HOST, self.port))
        self._srv.listen(16)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        if self._srv:
            self._srv.close()


if __name__ == '__main__':
    p = FakeSquidProxy(os.environ.get('FAKE_PROXY_LIST', '/tmp/fake_whitelist'),
                       int(os.environ.get('FAKE_PROXY_PORT', '13128')),
                       os.environ.get('FAKE_PROXY_DENY_FILE'))
    p.start()
    print('fake squid proxy on %s:%d, list=%s' % (HOST, p.port, p.list_file))
    threading.Event().wait()
