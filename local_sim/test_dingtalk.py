#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dingtalk_client.py 联调测试 —— 本地假钉钉服务验证客户端行为

覆盖：
  T1 flatten_value 纯函数（单选/人员/时间戳/Markdown链接/其他）
  T2 token：获取 / 全流程缓存复用 / 过期刷新 / 凭证错误 / 服务端错误
  T3 鉴权头与 URL 组装（base/sheet/operatorId、token 头）
  T4 字段映射：加载 / 缺失字段报错 / 服务端错误
  T5 读：翻页拼接 / 单页即停 / list_pending 过滤 / 拍平内容 / 接口异常 /
        nextToken重复防护 / 页数上限防护
  T6 写：payload 用 fieldId / 单选纯字符串（锁定形态）/ 仅写结论 / 空参数不发请求 /
        自定义结论字段名 / HTTP 错误上抛 / 写后读回生效（自愈闭环）
  T7 调试 CLI（子进程）：--check 冒烟 / --probe-write 联调往返

用法：python3 local_sim/test_dingtalk.py
"""

import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wlcore.dingtalk_client import DingTalkTable, flatten_value      # noqa: E402
from fake_dingtalk import FakeDingtalk                        # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    tag = 'ok  ' if cond else 'FAIL'
    if cond:
        PASS += 1
    else:
        FAIL += 1
    print('%s %s%s' % (tag, name, ('  | ' + str(detail)) if (detail and not cond) else ''))


@contextmanager
def server(**kw):
    s = FakeDingtalk(**kw).start()
    try:
        yield s
    finally:
        s.stop()


def cfg_of(srv, **over):
    cfg = {'app_key': 'testkey', 'app_secret': 'testsecret',
           'base_id': 'BASE1', 'sheet_id': 'SHEET1', 'operator_id': 'OP1',
           'timeout': 5,
           'api_base': 'http://127.0.0.1:%d' % srv.port,
           'oapi_base': 'http://127.0.0.1:%d' % srv.port}
    cfg.update(over)
    return cfg


def raises(fn, want):
    try:
        fn()
        return False
    except RuntimeError as e:
        return want in str(e)


# ================================================================

def t1_flatten():
    print('== T1 flatten_value 纯函数 ==')
    check('单选对象取name', flatten_value({'name': '待处理', 'id': 'x'}) == '待处理')
    check('人员数组拼接',
          flatten_value([{'name': '张三'}, {'name': '王工'}]) == '张三、王工')
    check('Markdown链接取文本',
          flatten_value('[www.baidu.com](https://www.baidu.com)') == 'www.baidu.com')
    ms = 1760000000000
    check('毫秒时间戳格式化',
          flatten_value(ms) == time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ms / 1000)))
    check('普通字符串原样', flatten_value('abc') == 'abc')
    check('小整数原样', flatten_value(1000) == 1000)
    check('None原样', flatten_value(None) is None)


def t2_token():
    print('== T2 token 获取/缓存/刷新/错误 ==')
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        check('获取token', t._get_token() == 'FAKE_TOKEN_ABC123')
        t.ensure_field_map()
        t.list_records(page_size=2)
        t.update_record('recP1', status='已放通', conclusion='x')
        n = sum(1 for e in srv.log if e[1].startswith('/gettoken'))
        check('全流程仅取1次token(缓存复用)', n == 1, n)
        t._token_ts -= 7001                      # 模拟过期
        t._get_token()
        n = sum(1 for e in srv.log if e[1].startswith('/gettoken'))
        check('过期后重新获取', n == 2, n)

    with server() as srv:
        t = DingTalkTable(cfg_of(srv, app_key='wrong', app_secret='wrong'))
        check('凭证错误→RuntimeError(获取token失败)',
              raises(lambda: t._get_token(), '获取token失败'))

    with server() as srv:
        srv.fail['token'] = 1
        t = DingTalkTable(cfg_of(srv))
        check('服务端errcode≠0→RuntimeError',
              raises(lambda: t._get_token(), '获取token失败'))


def t3_auth_and_url():
    print('== T3 鉴权头/URL组装 ==')
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        t.list_pending('待处理')
        api_calls = [e for e in srv.log if not e[1].startswith('/gettoken')]
        check('API调用均携带token头',
              all(e[2] == 'FAKE_TOKEN_ABC123' for e in api_calls),
              [e[2] for e in api_calls])
        check('路径含base/sheet',
              all(e[1].startswith('/v1.0/notable/bases/BASE1/sheets/SHEET1')
                  for e in api_calls), [e[1] for e in api_calls])
        check('operatorId参数存在',
              all('operatorId=OP1' in e[1] for e in api_calls))


def t4_fieldmap():
    print('== T4 字段映射 ==')
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        t.ensure_field_map()
        check('id→name', t._id2name.get('fld05') == '状态', t._id2name)
        check('name→id', t._name2id.get('结论') == 'fld06', t._name2id)
    with server() as srv:
        srv.fail['fields'] = 1
        t = DingTalkTable(cfg_of(srv))
        check('字段接口异常→RuntimeError',
              raises(lambda: t.ensure_field_map(), '获取字段列表失败'))
    with server() as srv:
        t = DingTalkTable(cfg_of(srv, status_field='不存在的字段'))
        t.ensure_field_map()
        ok = raises(lambda: t.update_record('recP1', status='已放通'), '表中不存在字段')
        no_put = not any(e[0] == 'PUT' for e in srv.log)
        check('状态字段缺失→RuntimeError且未发PUT', ok and no_put)


def t5_read():
    print('== T5 读路径 ==')
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        recs = t.list_records(page_size=2)
        n_get = sum(1 for e in srv.log if '/records?' in e[1])
        check('翻页拼接(5条/页2→3次请求)', len(recs) == 5 and n_get == 3,
              (len(recs), n_get))
        check('顺序保持',
              [r['id'] for r in recs] == ['recP1', 'recP2', 'recA1', 'recM1', 'recR1'])
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        recs = t.list_records(page_size=100)
        n_get = sum(1 for e in srv.log if '/records?' in e[1])
        check('单页即停', len(recs) == 5 and n_get == 1, (len(recs), n_get))
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        pend = t.list_pending('待处理')
        check('待处理过滤', [p['recordId'] for p in pend] == ['recP1', 'recP2'])
        f = pend[0]['flat']
        check('拍平:域名提取md链接', f['域名'] == 'trusted-research-data.com', f)
        check('拍平:申请人', f['申请人'] == '张三')
        check('拍平:状态单选', f['状态'] == '待处理')
        check('拍平:日期格式化',
              f['申请日期'] == time.strftime('%Y-%m-%d %H:%M:%S',
                                              time.localtime(1760000000000 / 1000)))
    with server(records=[{'id': 'rp1', 'fields': {'域名': 'a.com', '状态': '待处理'}},
                         {'id': 'rp2', 'fields': {'域名': 'b.com', '状态': '处理中'}},
                         {'id': 'rp3', 'fields': {'域名': 'c.com', '状态': '驳回'}}]) as srv:
        t = DingTalkTable(cfg_of(srv))
        pend = t.list_pending(['待处理', '处理中'])
        check('多状态拉取(待处理+处理中回收)',
              sorted(p['recordId'] for p in pend) == ['rp1', 'rp2'],
              [p['recordId'] for p in pend])
    with server() as srv:
        srv.fail['records'] = 1
        t = DingTalkTable(cfg_of(srv))
        check('记录接口异常→RuntimeError',
              raises(lambda: t.list_records(), '列出记录失败'))
    with server() as srv:
        srv.fail['records_loop'] = 1        # 服务端恒返回同一 nextToken
        t = DingTalkTable(cfg_of(srv))
        check('nextToken重复→RuntimeError(死循环防护)',
              raises(lambda: t.list_records(), 'nextToken重复'))
    with server(records=[{'id': 'r%d' % i, 'fields': {'状态': '待处理'}}
                         for i in range(7)]) as srv:
        t = DingTalkTable(cfg_of(srv))
        check('超过页数上限→RuntimeError(5000条防护)',
              raises(lambda: t.list_records(page_size=2, max_pages=3), '分页超过'))


def t6_write():
    print('== T6 写路径 ==')
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        t.update_record('recP1', status='已放通', conclusion='已加入白名单并生效')
        put = next(e for e in srv.log if e[0] == 'PUT')
        rec = put[3]['records'][0]
        flds = rec['fields']
        check('payload:recordId', rec['id'] == 'recP1', rec)
        check('payload:键为fieldId', set(flds) == {'fld05', 'fld06'}, flds)
        check('payload:单选纯字符串形态(联调锁定)', flds['fld05'] == '已放通', flds)
        check('payload:结论纯文本', flds['fld06'] == '已加入白名单并生效')
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        # 单选写形态已固定纯字符串：确认配置残留 select_write_format 键也被忽略
        t.cfg['select_write_format'] = 'name'
        t.update_record('recP1', status='已放通')
        put = next(e for e in srv.log if e[0] == 'PUT')
        check('残留配置键被忽略仍写纯字符串',
              put[3]['records'][0]['fields']['fld05'] == '已放通', put[3])
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        t.update_record('recP1', conclusion='仅结论')
        flds = next(e for e in srv.log if e[0] == 'PUT')[3]['records'][0]['fields']
        n_put = sum(1 for e in srv.log if e[0] == 'PUT')
        check('仅写结论:不含状态键', set(flds) == {'fld06'}, flds)
        check('空参数不发请求且返回True',
              t.update_record('recP1') is True and n_put == 1)
    with server(fields=[{'id': 'fld07', 'name': '处理结论', 'type': 'text'}],
                records=[{'id': 'rx', 'fields': {'处理结论': ''}}]) as srv:
        t = DingTalkTable(cfg_of(srv, conclusion_field='处理结论'))
        t.ensure_field_map()
        t.update_record('rx', conclusion='自定义结论字段')
        flds = next(e for e in srv.log if e[0] == 'PUT')[3]['records'][0]['fields']
        check('自定义结论字段名→正确fieldId', set(flds) == {'fld07'}, flds)
    with server() as srv:
        srv.fail['put_status'] = 500
        t = DingTalkTable(cfg_of(srv))
        check('写失败→RuntimeError上抛',
              raises(lambda: t.update_record('recP1', status='已放通'), '回写失败'))
    with server() as srv:
        t = DingTalkTable(cfg_of(srv))
        t.update_record('recP1', status='驳回', conclusion='已被现有规则覆盖')
        pend = t.list_pending('待处理')           # 读回：服务端已应用写入
        back = t.flatten_record(next(r for r in t.list_records() if r['id'] == 'recP1'))
        check('写后读回生效(自愈闭环)',
              [p['recordId'] for p in pend] == ['recP2'] and back['状态'] == '驳回')


def cli_config(srv):
    return """app_key: testkey
app_secret: testsecret
base_id: BASE1
sheet_id: SHEET1
operator_id: OP1
timeout: 5
status_field: "状态"
conclusion_field: "结论"
status_pending: "待处理"
status:
  approved: "已放通"
  rejected: "驳回"
  no_action: "驳回"
  already_ok: "已放通"
api_base: "http://127.0.0.1:%d"
oapi_base: "http://127.0.0.1:%d"
""" % (srv.port, srv.port)


def t7_cli():
    print('== T7 调试CLI（子进程） ==')
    with server() as srv:
        with tempfile.TemporaryDirectory() as td:
            cfgp = Path(td) / 'cli.yaml'
            cfgp.write_text(cli_config(srv), encoding='utf-8')

            def run(*extra):
                return subprocess.run(
                    [sys.executable, str(REPO / 'wlcore' / 'dingtalk_client.py'),
                     '--config', str(cfgp), *extra],
                    capture_output=True, text=True, timeout=60)

            p = run('--check')
            check('CLI --check 退出0', p.returncode == 0, p.stdout + p.stderr)
            check('CLI 输出字段映射', 'fld01 -> 域名' in p.stdout, p.stdout)
            check('CLI 输出待拉取计数与预览',
                  '待拉取（待处理/处理中）2 条' in p.stdout
                  and 'trusted-research-data.com' in p.stdout, p.stdout)
            p = run('--check', '--probe-write', 'recP1')
            check('CLI probe-write 报告写入生效',
                  p.returncode == 0 and '写入生效' in p.stdout
                  and '单选纯字符串写入正常' in p.stdout, p.stdout + p.stderr)
            st = next(r for r in srv.records if r['id'] == 'recP1')['fields']['状态']
            check('CLI probe-write 服务端已应用(状态→驳回)',
                  st.get('name') == '驳回', st)
            p = run('--check', '--probe-write', 'no-such-record')
            check('CLI probe-write 未知记录报错退出2', p.returncode == 2, p.stdout)


def main():
    t1_flatten()
    t2_token()
    t3_auth_and_url()
    t4_fieldmap()
    t5_read()
    t6_write()
    t7_cli()
    print('\n结果: %d 通过, %d 失败' % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
