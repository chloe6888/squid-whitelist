#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主入口纯逻辑单测：六态判定 / 结论组装 / 原因短语码表 / 凭证脱敏 / 审计轮转

此前这些点只有 sim E2E 间接覆盖，此处直接单测锁定边界。
两种跑法（pytest 非依赖，装了也能收）：
  python3 tests/test_main.py     # 直跑：分组输出 + 汇总 + 退出码
  pytest tests/
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from squid_whitelist import (DNS_REASON, REASON_SHORT, Audit, build_conclusion,
                             classify_domains, collect_secrets, decide_status,
                             redact_secrets, short_reason, write_heartbeat,
                             _redact_obj)
from wlcore.layers import validate_format

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print('  ok  %s' % name)
    else:
        FAIL += 1
        print('FAIL  %s  %s' % (name, detail))
        raise AssertionError(name)


L = {'pending': '待处理', 'processing': '处理中', 'approved': '已放通',
     'partial': '部分放通', 'rejected': '驳回', 'manual': '人工核查'}


# ---------------- 六态判定（纯函数） ----------------

def test_decide_status():
    print('== decide_status 六态 ==')
    check('待新增未落盘(执行失败)→人工核查',
          decide_status([], [], [], [], '系统暂时无法完成开通', ['x.com'], L)
          == (L['manual'], ''))
    check('dry-run不算未落盘(added已填)→已放通',
          decide_status(['x.com'], [], [], [], '', ['x.com'], L)
          == (L['approved'], ''))
    check('全成功→已放通',
          decide_status(['a.com'], ['b.com'], [], [], '', [], L) == (L['approved'], ''))
    check('成功+不合规→部分放通',
          decide_status(['a.com'], [], [('x.com', 'ip', 'r')], [], '', [], L)
          == (L['partial'], ''))
    check('格式类不合规→驳回+修改指引',
          decide_status([], [], [('x.com', 'ip', 'r')], [], '', [], L)
          == (L['rejected'], '；请修改后重新提交'))
    check('纯DNS不解析→驳回+原样重提指引',
          decide_status([], [], [('x.com', 'dns', DNS_REASON)], [], '', [], L)
          == (L['rejected'], '；域名无误仅未上线的话，稍后原样重新提交即可'))
    check('纯仿冒→驳回无追补',
          decide_status([], [], [], [('x.com', '与y高度相似')], '', [], L)
          == (L['rejected'], ''))
    check('DNS+格式混合→修改指引优先',
          decide_status([], [], [('a.com', 'dns', DNS_REASON),
                                ('1.2.3.4', 'ip', 'r')], [], '', [], L)
          == (L['rejected'], '；请修改后重新提交'))


# ---------------- 结论组装 ----------------

def test_build_conclusion():
    print('== build_conclusion ==')
    c = build_conclusion(['a.com'], ['b.com'], [('1.2.3.4', 'ip', '提交的是IP地址')],
                         [('x.com', '与y高度相似')])
    check('四组齐备顺序正确',
          c == '新增成功：a.com；已在白名单：b.com；域名不合规：1.2.3.4（IP地址）；'
               '疑似仿冒：x.com（与y高度相似）', c)
    check('空组不出现',
          build_conclusion([], [], [], []) == ''
          and build_conclusion(['a.com'], [], [], []) == '新增成功：a.com')
    check('extra 追加在尾', build_conclusion([], [], [], [], extra=['注记'])
          == '注记')


# ---------------- 原因码 → 结论短语 ----------------

def test_short_reason():
    print('== short_reason 码表 ==')
    check('未知码兜底不裸抛', short_reason('no-such-code') == '不合规')
    check('dns码即完整短语', short_reason('dns') == DNS_REASON)
    # validate_format 全部码都有映射：收集一批非法输入的码逐一核对
    samples = ['', 'a' * 300, 'a.com:80', 'u@a.com', '1.2.3.4', 'a b.com',
               'my_site.com', 'localhost', 'a..com', '-a.com', 'a.123',
               'x_y.example.com', 'a.com\nb.com']
    codes = {validate_format(s)[2] for s in samples}
    check('validate_format全码有短语映射',
          codes and all(c in REASON_SHORT for c in codes), codes)
    check('idn/dns合成码在表内', 'idn' in REASON_SHORT and 'dns' in REASON_SHORT)


# ---------------- 分流形态 ----------------

def test_classify_domains():
    print('== classify_domains 分流形态 ==')
    invalid, confirm, existing, pending = classify_domains(
        ['1.2.3.4', 'good.com', 'aliyum.com', 'xn--55qx5d.cn'],
        {'aliyun.com'}, {'.good.com'})
    check('invalid为(域名,码,完整原因)三元组',
          invalid == [('1.2.3.4', 'ip', '提交的是IP地址，请申请域名'),
                      ('xn--55qx5d.cn', 'idn', '国际化域名暂不支持')], invalid)
    check('confirm为(域名,依据)对', confirm
          and confirm[0][0] == 'aliyum.com' and '高度相似' in confirm[0][1], confirm)
    check('覆盖进existing、新进pending',
          existing == ['good.com'] and pending == [], (existing, pending))


# ---------------- 凭证脱敏 ----------------

def test_redact():
    print('== 凭证脱敏 ==')
    check('字符串替换', redact_secrets(
        'url?appkey=K1234567890&appsecret=S0987654321',
        ['K1234567890', 'S0987654321']) == 'url?appkey=***&appsecret=***')
    check('嵌套对象递归抹除', _redact_obj(
        {'a': 'x-K1234567890', 'b': ['K1234567890', 1], 'c': 2},
        ['K1234567890']) == {'a': 'x-***', 'b': ['***', 1], 'c': 2})
    check('空敏感集原样返回', _redact_obj({'a': 'b'}, []) == {'a': 'b'})
    cfg = {'dingtalk': {'app_key': 'K1234567890', 'app_secret': 'S0987654321'},
           'execution': {'proxy_auth': 'user:pw12345'}}
    check('collect_secrets收齐三类', collect_secrets(cfg)
          == ['K1234567890', 'S0987654321', 'user:pw12345'])
    check('过短值(<4)不收避免误杀', collect_secrets(
        {'dingtalk': {'app_key': 'x', 'app_secret': 'yy'}}) == [])
    check('无table属性安全缺省', collect_secrets(cfg, table=None)
          == collect_secrets(cfg))


def test_audit_and_heartbeat_redaction():
    print('== 审计/心跳脱敏与轮转 ==')
    with tempfile.TemporaryDirectory() as td:
        a = Audit(Path(td) / 'audit.jsonl',
                  secrets=['K1234567890', 'S0987654321'])
        a.event('fetch-failed', error='url?appkey=K1234567890&appsecret=S0987654321')
        line = (Path(td) / 'audit.jsonl').read_text(encoding='utf-8')
        ev = json.loads(line)
        check('审计行已抹除', 'K1234567890' not in line and 'S0987654321' not in line
              and ev['error'] == 'url?appkey=***&appsecret=***', line)
        check('非字符串值不受影响', 'fetch-failed' in ev['event'])

        hb = Path(td) / 'heartbeat'
        write_heartbeat(hb, {'result': 'fetch-failed',
                             'nested': ['K1234567890']},
                        secrets=['K1234567890'])
        txt = hb.read_text(encoding='utf-8')
        check('心跳payload递归抹除', 'K1234567890' not in txt and '***' in txt, txt)


def test_audit_rotation():
    print('== 审计轮转 ==')
    with tempfile.TemporaryDirectory() as td:
        # max_mb=0 → 每次写入前轮转（size<0 恒假）；keep=2 → 只留最近2份
        # （同秒内多次轮转同名覆盖合并，故断言区间而非精确值）
        a = Audit(Path(td) / 'audit.jsonl', max_mb=0, keep=2)
        for i in range(4):
            a.event('e%d' % i)
        rots = sorted((Path(td)).glob('audit.jsonl.rot.*'))
        check('轮转发生且不超keep份', 1 <= len(rots) <= 2, [r.name for r in rots])
        check('当前文件仍在追加', (Path(td) / 'audit.jsonl').exists()
              and 'e3' in (Path(td) / 'audit.jsonl').read_text(encoding='utf-8'))


_TESTS = [test_decide_status, test_build_conclusion, test_short_reason,
          test_classify_domains, test_redact,
          test_audit_and_heartbeat_redaction, test_audit_rotation]


def _run_all():
    for fn in _TESTS:
        try:
            fn()
        except AssertionError:
            pass          # 失败已打印，继续下一组（pytest 下由断言自然失败）
    print('\n结果: %d 通过, %d 失败' % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(_run_all())
