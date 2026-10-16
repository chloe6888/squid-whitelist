#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地模拟联调测试 —— 在无真实 squid/SSH/钉钉环境下验证全链路

组件：
  fake_proxy.py  线程内嵌，模拟 squid 的 CONNECT 行为（后缀匹配白名单）
  fake_squid.sh  squid 命令桩（parse/reconfigure 按调用序号可注入失败）
  whitelist_sync 以子进程真跑（SYNC_FETCH_CMD 测试钩子替代SSH拉取）

场景：
  T1 connect_check 原语（假代理：白名单200 / 非白名单403）
  T2 主节点批量原子事务 add_batch（成功 / 预检parse失败零触盘 / reconfigure失败回滚）
  T3 whitelist_sync 子进程真跑（更新 / no-op / 主端不可达 / 预检拒收 /
     reconfigure失败回滚 / 主删从删镜像 / --selftest）
  T4 E2E squid_whitelist 子进程（层0故障整批跳过 / 多域名四组结论六态 /
     处理中回收 / 两连写顺序 / mock零落盘）

用法：python3 local_sim/sim_test.py
"""

import fcntl
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wlcore.netprobe import connect_check, resolve_ok                       # noqa: E402
from wlcore.executor import NodeA                                           # noqa: E402
from squid_whitelist import Audit                                    # noqa: E402
from fake_proxy import FakeSquidProxy                                # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    tag = 'ok  ' if cond else 'FAIL'
    if cond:
        PASS += 1
    else:
        FAIL += 1
    print('%s %s%s' % (tag, name, ('  | ' + str(detail)) if (detail and not cond) else ''))


def stub_env(tmp, fail_at=0, fail_from=0):
    """fake_squid.sh 的运行环境（每次场景独立计数）。"""
    env = dict(os.environ)
    env['SQUID_LOG'] = str(tmp / 'squid.log')
    env['SQUID_COUNT_FILE'] = str(tmp / 'squid.count')
    env['SQUID_FAIL_AT'] = str(fail_at)
    env['SQUID_FAIL_FROM'] = str(fail_from or 999999)
    return env


STUB = 'bash %s' % (REPO / 'local_sim' / 'fake_squid.sh')


def pick_sim_port():
    """13128 可能被本机真实 squid 占用（生产端口），优先用之，占用则换隔离端口。"""
    import socket as _s
    for p in [int(os.environ.get('SIM_PROXY_PORT', 13128))] + list(range(13228, 13240)):
        with _s.socket() as s:
            try:
                s.bind(('127.0.0.1', p))
                return p
            except OSError:
                continue
    raise OSError('13128/13228-13239 均被占用')


SIM_PORT = pick_sim_port()


def make_conf(conf_path, wl_path):
    """最小 squid.conf：仅要求引用白名单路径（tmp.conf 派生的替换点）。"""
    conf_path.write_text(
        'acl allowed_domains dstdomain "%s"\nhttp_access allow allowed_domains\n'
        'http_access deny all\n' % wl_path, encoding='utf-8')
    return conf_path


# ================================================================ T1

def t1_connect(proxy):
    print('== T1 connect_check/resolve_ok 原语 ==')
    r = connect_check('example-1.com', '127.0.0.1', proxy.port, timeout=5)
    check('白名单域名 200', r.get('status') == 200, r)
    r = connect_check('blocked-foreign-site.com', '127.0.0.1', proxy.port, timeout=5)
    check('非白名单 403+denied+X-Squid-Error',
          r.get('status') == 403 and r.get('denied')
          and 'ERR_ACCESS_DENIED' in (r.get('x_squid_error') or ''), r)
    check('resolve_ok: 本机hosts域名可解析', resolve_ok('localhost', timeout=2, attempts=1))
    check('resolve_ok: 保留TLD不存在域名不可解析',
          not resolve_ok('nx-sim-no-such.invalid', timeout=2, attempts=1))


# ================================================================ T2

def node_a_cfg(wl, conf):
    return {
        'nodes': {'local': {'name': 'A', 'squid_port': SIM_PORT,
                            'squid_conf': str(conf), 'whitelist': str(wl)}},
        'execution': {'squid_cmd': STUB, 'store_format': 'dot_prefix',
                      'backup_keep': 5, 'proxy_auth': '', 'proxy_tls': False},
    }


def t2_add_batch(tmp, wl_shared):
    print('== T2 主节点批量原子事务 add_batch ==')
    base = 'example-1.com\nexample-2.com\n'

    def bak_n():
        return len(list(tmp.glob(wl_shared.name + '.bak.*')))

    def fresh(name, fail_at=0, fail_from=0):
        d = tmp / name
        d.mkdir()
        wl_shared.write_text(base)          # 与假代理共享同一份白名单
        conf = make_conf(d / 'squid.conf', wl_shared)
        os.environ.update(stub_env(d, fail_at, fail_from))
        return d, wl_shared, conf, Audit(d / 'audit.jsonl')

    # 成功路径：一次事务写入多个域名
    d, wl, conf, audit = fresh('ok')
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['new-1.example', 'new-2.example', 'example-1.com'])
    check('成功: ok', r['ok'], r)
    check('成功: added不含已覆盖', sorted(r['added']) == ['new-1.example', 'new-2.example'], r)
    check('成功: skipped含已覆盖', r['skipped'] == ['example-1.com'], r)
    check('成功: 文件已写入(现有行保留+新行排序追加)',
          wl.read_text() == base + '.new-1.example\n.new-2.example\n',
          repr(wl.read_text()))
    check('成功: 备份已生成', bak_n() == 1, bak_n())
    calls = (d / 'squid.log').read_text().splitlines()
    check('成功: 预检parse×1+reconfigure×1（批量=一次reload）',
          len(calls) == 2 and 'parse' in calls[0] and 'reconfigure' in calls[1], calls)
    obs = r.get('observe') or {}
    check('成功: 复测为观察项(经假代理200)', obs.get('new-1.example') == 200, obs)
    check('成功: tmp文件已清理', not (tmp / 'wl_global.txn').exists()
          and not (d / 'squid.conf.txn').exists())

    # 预检 parse 失败（第1次调用）→ 零触盘：正式文件/备份均未动
    d, wl, conf, audit = fresh('parsefail', fail_at=1)
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['roll-parse.com', 'roll-parse-2.com'])
    check('预检失败: 拒绝', not r['ok'] and '预检parse失败' in r['detail'], r)
    check('预检失败: 白名单零触盘', wl.read_text() == base, repr(wl.read_text()))
    check('预检失败: 无备份产生', bak_n() == 1, bak_n())
    check('预检失败: 审计有precheck-reject',
          'precheck-reject' in (d / 'audit.jsonl').read_text())

    # reconfigure 持续失败（含重试）→ 回滚
    d, wl, conf, audit = fresh('reloadfail', fail_from=2)
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['roll-reload.com'])
    check('reconfigure失败: 拒绝', not r['ok'] and 'reconfigure失败' in r['detail'], r)
    check('reconfigure失败: 文件回滚', wl.read_text() == base, repr(wl.read_text()))
    check('reconfigure失败: 审计有rollback', 'rollback' in (d / 'audit.jsonl').read_text())

    # 超集吸收（防线：主流程分流后执行端再核一遍）——子域条目被超集替换
    d, wl, conf, audit = fresh('superset')
    wl.write_text('www.superset-demo.com\n')
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['superset-demo.com'])
    check('超集吸收: 成功且子域条目被替换',
          r['ok'] and r['added'] == ['superset-demo.com']
          and r.get('replaced') == ['www.superset-demo.com']
          and wl.read_text() == '.superset-demo.com\n', (r, wl.read_text()))

    # 批内吸收：同批既有超集又有其子域时只写超集
    d, wl, conf, audit = fresh('batchabsorb')
    wl.write_text('keep-me.com\n')
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['ca-demo.com', 'www.ca-demo.com'])
    check('批内吸收: 只写超集且子域计入skipped',
          r['ok'] and r['added'] == ['ca-demo.com']
          and 'www.ca-demo.com' in r['skipped']
          and wl.read_text() == 'keep-me.com\n.ca-demo.com\n', (r, wl.read_text()))

    # conf 未引用白名单路径 → 中止
    d, wl, conf, audit = fresh('noconf')
    (d / 'squid.conf').write_text('http_port 13128\n', encoding='utf-8')
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['any.com'])
    check('conf未引用白名单: 中止', not r['ok'] and '未引用白名单路径' in r['detail'], r)


# ================================================================ T3

def t3_whitelist_sync(tmp):
    print('== T3 whitelist_sync（子进程真跑，SYNC_FETCH_CMD替代SSH） ==')
    sync = str(REPO / 'scripts' / 'whitelist_sync')

    def run_sync(d, fixture=None, fail_at=0, fail_from=0, fetch_cmd=None, args=()):
        d.mkdir(parents=True, exist_ok=True)
        wl = d / 'allowed_domains.list'
        conf = make_conf(d / 'squid.conf', wl)
        env = stub_env(d, fail_at, fail_from)
        env.update({'WHITELIST': str(wl), 'SQUID_CONF': str(conf),
                    'SQUID_BIN': STUB,
                    'BACKUP_KEEP': '5',
                    'SYNC_FETCH_CMD': fetch_cmd or ('cat %s' % fixture)})
        p = subprocess.run([sys.executable, sync] + list(args), env=env,
                           capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout.strip(), p.stderr.strip(), wl

    # a) 更新：拉到新规则 → 落地+reconfigure
    d = tmp / 'sync_a'
    d.mkdir()
    (d / 'fixture').write_text('.example-1.com\n.new-site.example\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('example-1.com\n', encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('更新: rc=0 且日志updated', rc == 0 and ' updated ' in out, (rc, out))
    check('更新: 本地已镜像(排序+点前缀)',
          wl.read_text() == '.example-1.com\n.new-site.example\n', repr(wl.read_text()))
    check('更新: 备份已生成', len(list(d.glob('allowed_domains.list.bak.*'))) == 1)

    # b) no-op：内容一致 → 零动作（squid调用数不再增长）
    count_before = (d / 'squid.count').read_text().strip()
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('no-op: rc=0 且日志synced', rc == 0 and ' synced ' in out, (rc, out))
    check('no-op: 未再调用squid(不写盘不reload)',
          (d / 'squid.count').read_text().strip() == count_before)

    # c) 主端不可达 → 本地不变
    (tmp / 'sync_c').mkdir()
    rc, out, _err, wl = run_sync(tmp / 'sync_c', fetch_cmd='exit 255')
    check('主端不可达: rc=1 日志master-unreachable',
          rc == 1 and 'master-unreachable' in out, (rc, out))

    # d) 预检拒收（第1次squid调用失败）→ 保持最后good版本
    d = tmp / 'sync_d'
    d.mkdir()
    (d / 'fixture').write_text('.evil.example\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('example-1.com\n', encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture', fail_at=1)
    check('预检拒收: rc=1 日志rejected', rc == 1 and 'rejected' in out, (rc, out))
    check('预检拒收: 本地保持不变', wl.read_text() == 'example-1.com\n', repr(wl.read_text()))
    check('预检拒收: 无备份', not list(d.glob('allowed_domains.list.bak.*')))

    # e) reconfigure 持续失败（含重试）→ 恢复备份
    d = tmp / 'sync_e'
    d.mkdir()
    (d / 'fixture').write_text('.example-1.com\n.new-2.example\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('example-1.com\n', encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture', fail_from=2)
    check('reconfigure失败: rc=1 已回滚', rc == 1 and 'failed' in out, (rc, out))
    check('reconfigure失败: 文件恢复原状', wl.read_text() == 'example-1.com\n',
          repr(wl.read_text()))

    # f) 全量镜像：主删 → 从删
    d = tmp / 'sync_f'
    d.mkdir()
    (d / 'fixture').write_text('.new-site.example\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('example-1.com\nnew-site.example\n',
                                            encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('主删从删: rc=0', rc == 0 and 'updated' in out, (rc, out))
    check('主删从删: example-1.com 已随之删除',
          wl.read_text() == '.new-site.example\n', repr(wl.read_text()))

    # g) --selftest：parse 防线自检
    d = tmp / 'sync_g'
    d.mkdir()
    (d / 'allowed_domains.list').write_text('example-1.com\n', encoding='utf-8')
    make_conf(d / 'squid.conf', d / 'allowed_domains.list')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture', fail_at=2, args=['--selftest'])
    check('selftest: rc=0 防线有效', rc == 0 and 'selftest ok' in out, (rc, out))

    # h) 形态保真：裸条目不被静默加点加宽（主=精确匹配/从=全子域的语义漂移防线）
    d = tmp / 'sync_h'
    d.mkdir()
    (d / 'fixture').write_text('bare-entry.com\n.dotted-entry.com\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('old.com\n', encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('形态保真: 裸条目原样镜像不加点',
          rc == 0 and wl.read_text() == 'bare-entry.com\n.dotted-entry.com\n',
          (rc, out, repr(wl.read_text())))
    (d / 'fixture').write_text('bare-entry.com\ndotted-entry.com\n', encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('形态变化触发更新(.x → x)',
          rc == 0 and 'updated' in out
          and wl.read_text() == 'bare-entry.com\ndotted-entry.com\n',
          (rc, out, repr(wl.read_text())))
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('形态一致后no-op', rc == 0 and ' synced ' in out, (rc, out))

    # i) whitelist_serve 输出保真：裸条目原样+stderr告警（不加点加宽）
    sd = tmp / 'serve_check'
    sd.mkdir()
    (sd / 'wl').write_text('# comment\nBare.Com\n.dotted.com\n\n', encoding='utf-8')
    p = subprocess.run([sys.executable, str(REPO / 'scripts' / 'whitelist_serve')],
                       env=dict(os.environ, WHITELIST_SERVE_PATH=str(sd / 'wl')),
                       capture_output=True, text=True, timeout=30)
    check('serve: 裸条目原样输出不加点(小写归一)',
          p.returncode == 0 and p.stdout == 'bare.com\n.dotted.com\n',
          (p.returncode, p.stdout, p.stderr))
    check('serve: 裸条目stderr告警', '裸条目' in p.stderr and 'bare.com' in p.stderr,
          p.stderr)

    # j) flock 防重叠：持锁时第二个sync立即busy退出（不写盘不reload）
    d = tmp / 'sync_j'
    d.mkdir()
    (d / 'fixture').write_text('.x.com\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('x.com\n', encoding='utf-8')
    wl = d / 'allowed_domains.list'
    lock_path = str(wl) + '.sync-lock'
    lk = open(lock_path, 'w')
    fcntl.lockf(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        rc, out, _err, _wl = run_sync(d, fixture=d / 'fixture')
        check('flock: 持锁时busy退出且零动作',
              rc == 0 and 'busy' in out and wl.read_text() == 'x.com\n', (rc, out))
    finally:
        fcntl.lockf(lk, fcntl.LOCK_UN)
        lk.close()
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('flock: 释放后正常同步', rc == 0 and 'updated' in out, (rc, out))


# ================================================================ T4

def write_sim_config(tmp, wl_abs, known_abs, dns_check=False):
    conf = make_conf(tmp / 'squid.conf', wl_abs)
    cfg = """dingtalk:
  app_key: x
  app_secret: x
  base_id: x
  sheet_id: x
  operator_id: x
  status_field: "状态"
  conclusion_field: "结论"
  status_pending: "待处理"
  status:
    processing: "处理中"
    approved: "已放通"
    partial: "部分放通"
    rejected: "驳回"
    manual: "人工核查"
nodes:
  local: {name: A, squid_port: %d, squid_conf: %s, whitelist: %s}
layer0:
  control_domains: [example-1.com, example-2.com]
  min_healthy: 1
  timeout: 5
layers: {max_per_run: 20, max_domains_per_record: 20, dns_check: %s, dns_timeout: 2}
execution: {auto: true, store_format: dot_prefix, backup_keep: 5, squid_cmd: "%s"}
paths:
  known_domains: %s
  audit_log: %s
  heartbeat: %s
  lock_file: %s
""" % (SIM_PORT, conf, wl_abs, 'true' if dns_check else 'false', STUB, known_abs,
       tmp / 'audit.jsonl', tmp / 'heartbeat', tmp / 'lock')
    p = tmp / 'sim.yaml'
    p.write_text(cfg, encoding='utf-8')
    return p


def run_gate(config, mock, extra=()):
    return subprocess.run([sys.executable, str(REPO / 'squid_whitelist.py'),
                           '--config', str(config), '--mock', str(mock)] + list(extra),
                          capture_output=True, text=True, timeout=180)


def t4_gate(tmp):
    print('== T4 E2E squid_whitelist 子进程（多域名/四组结论/六态） ==')
    # 相似度种子：独立于 data/known_domains.txt，保证演练确定性
    known = tmp / 'known.txt'
    known.write_text('aliyun.com\ngithub.com\nexample-corp.com\n', encoding='utf-8')

    # 4a) 层0故障：整批跳过，不占记录不回写
    d = tmp / 'gate_l0'
    d.mkdir()
    mock = d / 'mock.json'
    mock.write_text(json.dumps({
        'layer0': {'ok': False, 'reason': '本机squid异常(演练)'},
        'records': [{'recordId': 'x1', 'flat': {'域名': 'a.com', '状态': '待处理'}}],
    }), encoding='utf-8')
    cfg = write_sim_config(d, d / 'wl.list', known)
    p = run_gate(cfg, mock)
    hb = json.loads((d / 'heartbeat').read_text())
    check('层0失败: 退出0', p.returncode == 0, p.stderr[-300:])
    check('层0失败: heartbeat标记', hb.get('result') == 'layer0-failed', hb)
    audit_text = (d / 'audit.jsonl').read_text()
    check('层0失败: 不占记录不回写', 'mark-processing' not in audit_text
          and 'record-end' not in audit_text)

    # 4b) E2E：多域名四组分流 → 六态全出口 + 处理中回收
    d = tmp / 'gate_e2e'
    d.mkdir()
    mock = d / 'mock.json'

    def rec(rid, dom, status='待处理'):
        return {'recordId': rid, 'flat': {'域名': dom, '申请人': '张三',
                                          '访问用途': '测试', '状态': status, '结论': ''}}

    many = ', '.join('d%02d.com' % i for i in range(1, 26))   # 25个 → 截断到20

    mock.write_text(json.dumps({
        'layer0': {'ok': True},
        'whitelist': ['github.com', 'www.superset-demo.com'],
        'exec_fail': ['fail-x.com'],
        'records': [
            rec('e1', 'batch-a.com，batch-b.com; Batch-C.com'),        # 全新增→已放通
            rec('e2', 'batch-a.com, 1.2.3.4'),                          # 已存在+IP→部分放通
            rec('e3', 'xy com, baidu'),                                 # 全不合规→驳回
            rec('e4', '[aliyum.com](https://aliyum.com), github.com'),  # 疑似仿冒+已存在→部分放通
            rec('e5', 'fail-x.com, ok-y.com'),                          # 执行失败→人工核查
            rec('e6', 'recycle-me.com', status='处理中'),               # 处理中回收→已放通
            rec('e7', 'superset-demo.com'),                             # 超集吸收→已放通+合并提示
            rec('e8', many),                                            # 25个截断→已放通+分批提示
        ],
    }, ensure_ascii=False), encoding='utf-8')
    cfg = write_sim_config(d, d / 'wl.list', known)
    p = run_gate(cfg, mock)
    check('E2E: 退出0', p.returncode == 0, p.stderr[-500:])

    events = [json.loads(l) for l in (d / 'audit.jsonl').read_text().splitlines()]
    ends = {e['recordId']: e for e in events if e['event'] == 'record-end'}
    marks = [e for e in events if e.get('action') == 'mark-processing']

    def st(rid):
        return ends.get(rid, {}).get('status')

    def concl(rid):
        return ends.get(rid, {}).get('conclusion', '')

    check('E2E: 共8条record-end', len(ends) == 8, sorted(ends))
    check('E2E: 两连写①全部先占处理中', len(marks) == 8
          and all(m['recordId'] in ends for m in marks))
    check('E2E: 两连写顺序(mark先于end)',
          all(next(i for i, e in enumerate(events)
                   if e.get('action') == 'mark-processing'
                   and e['recordId'] == rid) <
              next(i for i, e in enumerate(events)
                   if e['event'] == 'record-end' and e['recordId'] == rid)
              for rid in ends))
    check('E2E: 全新增→已放通', st('e1') == '已放通', st('e1'))
    check('E2E: 新增组含全部域名(去重+小写)',
          '新增成功：batch-a.com、batch-b.com、batch-c.com' in concl('e1'), concl('e1'))
    check('E2E: 已存在+IP→部分放通', st('e2') == '部分放通', st('e2'))
    check('E2E: 部分放通结论四组', '已在白名单：batch-a.com' in concl('e2')
          and '域名不合规：1.2.3.4（IP地址）' in concl('e2'), concl('e2'))
    check('E2E: 全不合规→驳回', st('e3') == '驳回'
          and '缺少主域名后缀' in concl('e3') and '请修改后重新提交' in concl('e3'),
          (st('e3'), concl('e3')))
    check('E2E: 仿冒+已存在→部分放通', st('e4') == '部分放通'
          and '疑似仿冒：aliyum.com' in concl('e4') and '已在白名单：github.com' in concl('e4'),
          (st('e4'), concl('e4')))
    check('E2E: 仿冒结论引导联系管理员', '如确认无误请联系管理员' in concl('e4'))
    check('E2E: 执行失败→人工核查', st('e5') == '人工核查', st('e5'))
    check('E2E: 人工核查结论含待开通+转人工',
          '未能开通：fail-x.com、ok-y.com' in concl('e5')
          and '转人工处理' in concl('e5'), concl('e5'))
    check('E2E: 处理中回收→已放通', st('e6') == '已放通', st('e6'))
    check('E2E: 超集吸收→已放通+自动合并提示',
          st('e7') == '已放通' and '新增成功：superset-demo.com' in concl('e7')
          and '已自动合并子域条目：www.superset-demo.com' in concl('e7'),
          (st('e7'), concl('e7')))
    check('E2E: 超上限截断→已放通+分批提示',
          st('e8') == '已放通' and '分批提交' in concl('e8')
          and len(ends['e8']['added']) == 20, (st('e8'), concl('e8')[:120]))
    hb = json.loads((d / 'heartbeat').read_text())
    check('E2E: heartbeat ok 计数8', hb.get('result') == 'ok'
          and hb.get('total') == 8, hb)
    check('E2E: mock零落盘(白名单文件未生成)',
          not (d / 'wl.list').exists() or (d / 'wl.list').read_text() == '')

    # 4c) dry-run：不占记录、不写白名单，结论标注计划写入
    d = tmp / 'gate_dry'
    d.mkdir()
    mock = d / 'mock.json'
    mock.write_text(json.dumps({
        'layer0': {'ok': True},
        'whitelist': [],
        'records': [rec('y1', 'dry-run-site.com')],
    }, ensure_ascii=False), encoding='utf-8')
    cfg = write_sim_config(d, d / 'wl.list', known)
    p = run_gate(cfg, mock, extra=['--dry-run'])
    check('dry-run: 退出0', p.returncode == 0, p.stderr[-300:])
    audit_text = (d / 'audit.jsonl').read_text()
    ends = {json.loads(l)['recordId']: json.loads(l)
            for l in audit_text.splitlines() if '"record-end"' in l}
    check('dry-run: 不写处理中(mark absent)', 'mark-processing' not in audit_text)
    check('dry-run: 结论标注计划写入',
          ends.get('y1', {}).get('status') == '已放通'
          and '计划写入' in ends.get('y1', {}).get('conclusion', ''),
          ends.get('y1'))

    # 4d) DNS准入：无法解析→不合规→驳回；纯DNS驳回不提示"修改后重新提交"
    d = tmp / 'gate_dns'
    d.mkdir()
    mock = d / 'mock.json'
    mock.write_text(json.dumps({
        'layer0': {'ok': True},
        'whitelist': [],
        'records': [
            rec('d9', 'git.test, no-such-e9.invalid'),   # 全部无法解析→驳回
            rec('d10', '1.2.3.4, no-such-e9.invalid'),   # 格式+DNS混合→驳回+修改提示
        ],
    }, ensure_ascii=False), encoding='utf-8')
    cfg = write_sim_config(d, d / 'wl.list', known, dns_check=True)
    p = run_gate(cfg, mock)
    check('DNS: 退出0', p.returncode == 0, p.stderr[-300:])
    events = [json.loads(l) for l in (d / 'audit.jsonl').read_text().splitlines()]
    ends = {e['recordId']: e for e in events if e['event'] == 'record-end'}

    def st2(rid):
        return ends.get(rid, {}).get('status')

    def concl2(rid):
        return ends.get(rid, {}).get('conclusion', '')

    check('DNS: 纯无法解析→驳回+原因+原样重提指引',
          st2('d9') == '驳回' and '当前无法解析' in concl2('d9')
          and '请修改后重新提交' not in concl2('d9')
          and '原样重新提交' in concl2('d9'), (st2('d9'), concl2('d9')))
    check('DNS: 格式+DNS混合→驳回+修改提示',
          st2('d10') == '驳回' and '当前无法解析' in concl2('d10')
          and 'IP地址' in concl2('d10')
          and '请修改后重新提交' in concl2('d10'), (st2('d10'), concl2('d10')))
    check('DNS: 零新增不落盘',
          not (d / 'wl.list').exists()
          or (d / 'wl.list').read_text() == '')


_PROXY = None


def main():
    global _PROXY
    tmp = Path(tempfile.mkdtemp(prefix='squid_sim_'))
    wl_global = tmp / 'wl_global'
    wl_global.write_text('example-1.com\nexample-2.com\n')
    _PROXY = FakeSquidProxy(str(wl_global), port=SIM_PORT,
                            deny_file=str(tmp / 'deny_global'))
    _PROXY.start()
    print('假squid代理已启动 127.0.0.1:%d（白名单=%s）\n' % (SIM_PORT, wl_global))

    try:
        t1_connect(_PROXY)
        t2_add_batch(tmp, wl_global)
        t3_whitelist_sync(tmp)
        t4_gate(tmp)
    finally:
        _PROXY.stop()
        print('\n清理临时目录: %s' % tmp)
        shutil.rmtree(tmp, ignore_errors=True)

    print('结果: %d 通过, %d 失败' % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
