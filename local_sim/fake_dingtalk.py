#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fake_dingtalk —— 本地假钉钉AI表格服务（dingtalk_client.py 联调用）

模拟与真实 API 同路径/同方法/同响应形态的 4 个端点：
  GET  {oapi_base}/gettoken?appkey=..&appsecret=..
  GET  {api_base}/v1.0/notable/bases/{baseId}/sheets/{sheetId}/fields?operatorId=..
  GET  {api_base}/v1.0/notable/bases/{baseId}/sheets/{sheetId}/records?operatorId=..
             &maxResults=..&nextToken=..          （数字游标真分页）
  PUT  {api_base}/v1.0/notable/bases/{baseId}/sheets/{sheetId}/records?operatorId=..

行为要点：
  - 凭证匹配才发 token（默认 testkey/testsecret）
  - 校验 x-acs-dingtalk-access-token 头，错误/缺失 → 401
  - 对齐 2026-09-20 真实表格联调结论：
      读侧 records 的 fields 键为【字段名】（非 fieldId）
      写侧单选(singleSelect)只接受纯字符串；{"name":X} 整体 400 拒绝（'[object Object]'）
      写入按键为 fieldId，服务端落库转成 {字段名: {"name","id"}} 形态
  - PUT 应用到内存记录，供读回验证
  - fail 注入：fail={'token':1,'fields':1,'records':1,'put_status':500} 分别触发对应错误
  - .log 记录每次请求 (method, 完整path, token, body)，供断言调用次数/鉴权头/payload

用法（独立起服务）：
  python3 fake_dingtalk.py [port]
"""

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST = '127.0.0.1'

# 默认字段表（type=select 的字段 PUT 后以 {"name":X} 形态存储，模拟服务端规范化）
FIELDS = [
    {'id': 'fld01', 'name': '域名', 'type': 'text'},
    {'id': 'fld02', 'name': '申请人', 'type': 'person'},
    {'id': 'fld03', 'name': '访问用途', 'type': 'text'},
    {'id': 'fld04', 'name': '申请日期', 'type': 'datetime'},
    {'id': 'fld05', 'name': '状态', 'type': 'select'},
    {'id': 'fld06', 'name': '结论', 'type': 'text'},
]


def default_records():
    """默认 5 条记录（2待处理/已放通×2/驳回）。fields 键=字段名（对齐真实API）。
    三状态收敛(2026-09-28)：仿冒→驳回；已覆盖→已放通。"""
    ms = 1760000000000
    return [
        {'id': 'recP1', 'fields': {
            '域名': '[trusted-research-data.com](https://trusted-research-data.com)',
            '申请人': [{'unionId': 'u1', 'name': '张三'}],
            '访问用途': '下载科研数据', '申请日期': ms,
            '状态': {'name': '待处理', 'id': 'opt1'}, '结论': ''}},
        {'id': 'recP2', 'fields': {
            '域名': '[www.baidu.com](https://www.baidu.com)',
            '申请人': [{'unionId': 'u2', 'name': '王工'}],
            '访问用途': '搜索资料', '申请日期': ms,
            '状态': {'name': '待处理', 'id': 'opt1'}, '结论': ''}},
        {'id': 'recA1', 'fields': {
            '域名': '[example-1.com](https://example-1.com)',
            '申请人': [{'unionId': 'u1', 'name': '张三'}],
            '访问用途': '查阅文档', '申请日期': ms,
            '状态': {'name': '已放通', 'id': 'opt2'},
            '结论': '已加入白名单并生效(复测HTTP 200)'}},
        {'id': 'recM1', 'fields': {
            '域名': '[aliyum.com](https://aliyum.com)',
            '申请人': [{'unionId': 'u2', 'name': '王工'}],
            '访问用途': '下载官方文档', '申请日期': ms,
            '状态': {'name': '驳回', 'id': 'opt4'},
            '结论': '疑似笔误/仿冒，不予放通（与 aliyun.com 知名域名 编辑距离1），'
                    '如确认无误请联系管理员'}},
        {'id': 'recR1', 'fields': {
            '域名': 'www.openai.com',
            '申请人': [{'unionId': 'u1', 'name': '张三'}],
            '访问用途': '查阅API文档', '申请日期': ms,
            '状态': {'name': '已放通', 'id': 'opt2'},
            '结论': '已被现有规则覆盖(.openai.com)，可直接使用'}},
    ]


class FakeDingtalk:
    def __init__(self, app_key='testkey', app_secret='testsecret',
                 fields=None, records=None):
        self.app_key = app_key
        self.app_secret = app_secret
        self.token = 'FAKE_TOKEN_ABC123'
        self.fields = fields if fields is not None else copy.deepcopy(FIELDS)
        self.records = records if records is not None else default_records()
        self.fail = {}      # {'token':1,'fields':1,'records':1,'put_status':500}
        self.log = []       # [(method, 完整path, token, body)]
        self._srv = None
        self._thread = None

    @property
    def port(self):
        return self._srv.server_port

    def _field_def(self, fid):
        for f in self.fields:
            if f['id'] == fid:
                return f
        return None

    def start(self, port=0):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):          # 静音默认访问日志
                pass

            def _send(self, code, obj):
                body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                u = urlparse(self.path)
                q = parse_qs(u.query)
                tok = self.headers.get('x-acs-dingtalk-access-token')
                app.log.append(('GET', self.path, tok, None))

                if u.path == '/gettoken':
                    if app.fail.get('token'):
                        return self._send(200, {'errcode': 500, 'errmsg': 'mock: token fail'})
                    if (q.get('appkey', [''])[0] != app.app_key
                            or q.get('appsecret', [''])[0] != app.app_secret):
                        return self._send(200, {'errcode': 40035, 'errmsg': 'appkey不存在'})
                    return self._send(200, {'errcode': 0, 'access_token': app.token})

                if tok != app.token:
                    return self._send(401, {'code': 'InvalidAuthentication',
                                            'message': 'invalid access token'})
                if u.path.endswith('/fields'):
                    if app.fail.get('fields'):
                        return self._send(200, {'code': 'mock', 'message': 'fields fail'})
                    return self._send(200, {'value': app.fields})
                if u.path.endswith('/records'):
                    if app.fail.get('records'):
                        return self._send(200, {'code': 'mock', 'message': 'records fail'})
                    size = int(q.get('maxResults', ['100'])[0])
                    cursor = int(q.get('nextToken', ['0'])[0] or 0)
                    page = app.records[cursor:cursor + size]
                    more = cursor + size < len(app.records)
                    return self._send(200, {
                        'records': page, 'hasMore': more,
                        'nextToken': str(cursor + size) if more else ''})
                return self._send(404, {'code': 'NotFound', 'message': u.path})

            def do_PUT(self):
                tok = self.headers.get('x-acs-dingtalk-access-token')
                n = int(self.headers.get('Content-Length') or 0)
                try:
                    body = json.loads(self.rfile.read(n) or b'{}')
                except ValueError:
                    body = {}
                app.log.append(('PUT', self.path, tok, body))
                if tok != app.token:
                    return self._send(401, {'code': 'InvalidAuthentication',
                                            'message': 'invalid access token'})
                code = app.fail.get('put_status', 200)
                if code != 200:
                    return self._send(code, {'code': 'mock', 'message': 'put fail'})
                # 先整体校验再应用（对齐真实服务端：任一值非法则整个请求 400，零副作用）
                planned = []
                for r in body.get('records', []):
                    rec = next((x for x in app.records if x['id'] == r.get('id')), None)
                    if not rec:
                        continue
                    for fid, val in (r.get('fields') or {}).items():
                        fdef = app._field_def(fid)
                        is_select = bool(fdef) and fdef.get('type') == 'select'
                        if is_select and not isinstance(val, str):
                            return self._send(400, {
                                'code': 'invalidRequest.inputArgs.invalid',
                                'message': "the value '[object Object]' is invalid"
                                           " for field '%s'" % fid})
                        # 写入用 fieldId，落库转字段名键（对齐真实API读写形态差异）
                        planned.append((rec, fdef['name'] if fdef else fid, val, is_select))
                for rec, key, val, is_select in planned:
                    rec['fields'][key] = ({'name': val, 'id': 'opt_%s' % val}
                                          if is_select else val)
                return self._send(200, {'ok': True})

        self._srv = ThreadingHTTPServer((HOST, port), Handler)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None


if __name__ == '__main__':
    import sys
    p = FakeDingtalk().start(int(sys.argv[1]) if len(sys.argv) > 1 else 18080)
    print('fake dingtalk on http://%s:%d (appkey=testkey appsecret=testsecret)'
          % (HOST, p.port))
    threading.Event().wait()
