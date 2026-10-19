#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地模拟联调测试 —— 在无真实 squid/SSH/钉钉环境下验证全链路

组件：
  fake_proxy.py  线程内嵌，模拟 squid 的 CONNECT 行为（后缀匹配白名单）
  fake_squid.sh  squid 命令桩（parse/reconfigure 按调用序号可注入失败）
  whitelist_sync 以子进程真跑（SYNC_FETCH_CMD 测试钩子替代SSH拉取）

场景：
  T1 connect_check 原语（假代理：白名单200 / 非白名单403）
  T2 主节点批量原子事务 add_batch（成功 / 预检parse失败零触盘 / reconfigure失败回滚 /
     回滚成功删标记 / 标记写失败中止 / 补偿成败与dry-run只报告）
  T3 whitelist_sync 子进程真跑（更新 / no-op / 主端不可达 / 预检拒收 /
     reconfigure失败回滚 / 主删从删镜像 / --selftest /
     回滚成功删标记 / 崩溃注入(替换后reconfigure前被杀)与下轮补偿 / 补偿失败重试）
  T4 E2E squid_whitelist 子进程（层0故障整批跳过 / 多域名四组结论六态 /
     处理中回收 / 两连写顺序 / mock零落盘）
  T5 主节点 pending-reload 补偿（子进程真跑非mock：无标记零调用 /
     补偿成功删标记 / 补偿失败保留 / dry-run 零写入）
  T6 元数据契约（主NodeA.add_batch / 从whitelist_sync 两实现 × umask ×
     原权限：替换后属主/属组/权限位保留；回滚后权限位恢复）

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


def stub_env(tmp, fail_at=0, fail_from=0, fail_list=''):
    """fake_squid.sh 的运行环境（每次场景独立计数）。

    注入变量必须显式清除：stub_env 继承 os.environ，上轮场景（T2 的
    fresh() 会写回 os.environ）遗留的 FAIL_LIST/KILL 会波及后续所有场景。"""
    env = dict(os.environ)
    env['SQUID_LOG'] = str(tmp / 'squid.log')
    env['SQUID_COUNT_FILE'] = str(tmp / 'squid.count')
    env['SQUID_FAIL_AT'] = str(fail_at)
    env['SQUID_FAIL_FROM'] = str(fail_from or 999999)
    env.pop('SQUID_FAIL_LIST', None)
    if fail_list:
        env['SQUID_FAIL_LIST'] = str(fail_list)
    env.pop('SQUID_KILL_PARENT_AT', None)
    return env


STUB = 'bash %s' % (REPO / 'local_sim' / 'fake_squid.sh')


def set_stub_env(tmp, fail_at=0, fail_from=0, fail_list=''):
    """写入本进程 os.environ（T2/T5 in-process 场景用）。

    os.environ.update 不删除缺失键——条件注入变量（FAIL_LIST/KILL_PARENT）
    必须显式清掉，否则上轮场景遗留波及后续所有场景。"""
    for k in ('SQUID_FAIL_LIST', 'SQUID_KILL_PARENT_AT'):
        os.environ.pop(k, None)
    os.environ.update(stub_env(tmp, fail_at, fail_from, fail_list))


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
    marker = tmp / (wl_shared.name + '.pending-reload')

    def bak_n():
        # 备份统一在 whitelist-bak/ 子目录（与生产 executor 同一逻辑）
        return len(list((tmp / 'whitelist-bak').glob(wl_shared.name + '.bak.*')))

    def fresh(name, fail_at=0, fail_from=0, fail_list=''):
        d = tmp / name
        d.mkdir()
        wl_shared.write_text(base)          # 与假代理共享同一份白名单
        conf = make_conf(d / 'squid.conf', wl_shared)
        set_stub_env(d, fail_at, fail_from, fail_list)
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
    check('成功: 无pending-reload标记残留', not marker.exists())

    # 预检 parse 失败（第1次调用）→ 零触盘：正式文件/备份均未动
    d, wl, conf, audit = fresh('parsefail', fail_at=1)
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['roll-parse.com', 'roll-parse-2.com'])
    check('预检失败: 拒绝', not r['ok'] and '预检parse失败' in r['detail'], r)
    check('预检失败: 白名单零触盘', wl.read_text() == base, repr(wl.read_text()))
    check('预检失败: 无备份产生', bak_n() == 1, bak_n())
    check('预检失败: 审计有precheck-reject',
          'precheck-reject' in (d / 'audit.jsonl').read_text())

    # reconfigure 持续失败（含重试，回滚 reload 也失败）→ 回滚且标记保留
    d, wl, conf, audit = fresh('reloadfail', fail_from=2)
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['roll-reload.com'])
    check('reconfigure失败: 拒绝', not r['ok'] and 'reconfigure失败' in r['detail'], r)
    check('reconfigure失败: 文件回滚', wl.read_text() == base, repr(wl.read_text()))
    check('reconfigure失败: 审计有rollback', 'rollback' in (d / 'audit.jsonl').read_text())
    check('reconfigure失败(回滚reload也失败): 标记保留待补偿', marker.exists())
    # 补偿失败（squid 仍持续失败）→ 标记保留
    r = na.pending_reload_compensate()
    check('补偿失败: 只报告不抛异常', r['found'] and not r['compensated']
          and marker.exists(), r)
    # dry-run：发现标记只报告不动作（零写入承诺）
    marker.write_text('x')
    r = na.pending_reload_compensate(dry_run=True)
    check('补偿dry-run: 只报告不动标记',
          r['found'] and not r['compensated'] and marker.exists(), r)
    # squid 恢复后补偿成功：删标记；此前共6次调用（parse/reload/重试/回滚reload/
    # 补偿reload/补偿重试），成功补偿恰新增第7次且为 reconfigure
    set_stub_env(d)
    r = na.pending_reload_compensate()
    calls = (d / 'squid.log').read_text().splitlines()
    check('补偿成功: 删标记且恰一次reconfigure',
          r['found'] and r['compensated'] and not marker.exists()
          and len(calls) == 7 and 'reconfigure' in calls[6], (r, calls))

    # 回滚成功（reconfigure+重试失败、回滚 reload 成功）→ 删标记
    d, wl, conf, audit = fresh('rollbackok', fail_list='2,3')
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['roll-ok.com'])
    check('回滚成功: 拒绝且文件回滚', not r['ok'] and wl.read_text() == base,
          (r, repr(wl.read_text())))
    check('回滚成功: 标记已删(磁盘与运行配置恢复一致)', not marker.exists())

    # 标记写入失败（路径被目录占位）→ 在 replace 之前中止，零触盘
    d, wl, conf, audit = fresh('markerfail')
    marker.mkdir()                          # 占位使 os.open 必败
    na = NodeA(node_a_cfg(wl, conf), audit)
    r = na.add_batch(['marker-fail.com'])
    check('标记写失败: 中止且白名单零触盘',
          not r['ok'] and '标记写入失败' in r['detail']
          and wl.read_text() == base, (r, repr(wl.read_text())))
    marker.rmdir()

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

    def run_sync(d, fixture=None, fail_at=0, fail_from=0, fetch_cmd=None, args=(),
                 fail_list='', kill_parent_at=0):
        d.mkdir(parents=True, exist_ok=True)
        wl = d / 'allowed_domains.list'
        conf = make_conf(d / 'squid.conf', wl)
        env = stub_env(d, fail_at, fail_from, fail_list)
        env.update({'WHITELIST': str(wl), 'SQUID_CONF': str(conf),
                    'SQUID_BIN': STUB, 'SQUID_PORT': str(SIM_PORT),
                    'BACKUP_KEEP': '5',
                    'SYNC_FETCH_CMD': fetch_cmd or ('cat %s' % fixture)})
        if kill_parent_at:
            env['SQUID_KILL_PARENT_AT'] = str(kill_parent_at)
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
    check('更新: 备份已生成(whitelist-bak/子目录)',
          len(list((d / 'whitelist-bak').glob('allowed_domains.list.bak.*'))) == 1)
    check('更新: 无pending-reload标记残留',
          not (d / 'allowed_domains.list.pending-reload').exists())

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
    check('预检拒收: 无备份',
          not list((d / 'whitelist-bak').glob('allowed_domains.list.bak.*')))

    # e) reconfigure 持续失败（含重试，回滚 reload 也失败）→ 恢复备份且标记保留
    d = tmp / 'sync_e'
    d.mkdir()
    (d / 'fixture').write_text('.example-1.com\n.new-2.example\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('example-1.com\n', encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture', fail_from=2)
    check('reconfigure失败: rc=1 已回滚', rc == 1 and 'failed' in out, (rc, out))
    check('reconfigure失败: 文件恢复原状', wl.read_text() == 'example-1.com\n',
          repr(wl.read_text()))
    check('reconfigure失败(回滚reload也失败): 标记保留',
          (d / 'allowed_domains.list.pending-reload').exists())

    # e2) 回滚成功（reconfigure+重试失败、回滚 reload 成功）→ 删标记
    d = tmp / 'sync_e2'
    d.mkdir()
    (d / 'fixture').write_text('.example-1.com\n.new-3.example\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('example-1.com\n', encoding='utf-8')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture', fail_list='2,3')
    check('回滚成功: rc=1 已回滚', rc == 1 and 'failed' in out, (rc, out))
    check('回滚成功: 文件恢复原状', wl.read_text() == 'example-1.com\n',
          repr(wl.read_text()))
    check('回滚成功: 标记已删(磁盘与运行配置恢复一致)',
          not (d / 'allowed_domains.list.pending-reload').exists())

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

    # k) 崩溃注入：白名单已替换、reconfigure 生效前进程被 SIGKILL
    #    （桩第2次调用=首次reconfigure时 kill -9 父进程）
    d = tmp / 'sync_k'
    d.mkdir()
    (d / 'fixture').write_text('.example-1.com\n.crash-site.example\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('example-1.com\n', encoding='utf-8')
    marker = d / 'allowed_domains.list.pending-reload'
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture', kill_parent_at=2)
    check('崩溃注入: 进程被杀(returncode=-9)', rc == -9, rc)
    check('崩溃注入: 新内容已落盘(替换先于reconfigure)',
          wl.read_text() == '.crash-site.example\n.example-1.com\n',
          repr(wl.read_text()))
    check('崩溃注入: 标记保留', marker.exists())
    count_after_crash = int((d / 'squid.count').read_text().strip())
    # 下一轮：补偿恰一次 reconfigure（先于 fetch/no-op 判定），随后 no-op 收尾
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('崩溃补偿: 日志compensated且标记删除',
          'compensated' in out and not marker.exists(), out)
    check('崩溃补偿: 本地文件保持崩溃时内容',
          wl.read_text() == '.crash-site.example\n.example-1.com\n',
          repr(wl.read_text()))
    call_lines = [l for l in (d / 'squid.log').read_text().splitlines()
                  if l.startswith('call#')]
    new_calls = call_lines[count_after_crash:]
    check('崩溃补偿: 恰好多一次reconfigure(本轮唯一squid调用)',
          len(new_calls) == 1 and 'reconfigure' in new_calls[0], new_calls)
    check('崩溃补偿: 之后no-op(synced)', 'synced' in out, out)

    # l) 补偿失败：标记保留，本轮同步继续（此处收尾no-op），下轮重试成功
    d = tmp / 'sync_l'
    d.mkdir()
    (d / 'fixture').write_text('.example-1.com\n', encoding='utf-8')
    (d / 'allowed_domains.list').write_text('.example-1.com\n', encoding='utf-8')
    marker = d / 'allowed_domains.list.pending-reload'
    marker.write_text('x')
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture', fail_from=1)
    check('补偿失败: 日志compensate-failed且标记保留',
          'compensate-failed' in out and marker.exists(), out)
    check('补偿失败: 本轮同步继续(no-op收尾)', 'synced' in out and rc == 0, (rc, out))
    rc, out, _err, wl = run_sync(d, fixture=d / 'fixture')
    check('补偿重试: 成功且标记删除', 'compensated' in out and not marker.exists(), out)


# ================================================================ T4

def write_sim_config(tmp, wl_abs, known_abs, dns_check=False, dt_api_base=None):
    conf = make_conf(tmp / 'squid.conf', wl_abs)
    cfg = """dingtalk:
  app_key: x
  app_secret: x
  base_id: x
  sheet_id: x
  operator_id: x%s
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
""" % (('\n  api_base: %s' % dt_api_base) if dt_api_base else '',
       SIM_PORT, conf, wl_abs, 'true' if dns_check else 'false', STUB, known_abs,
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


# ================================================================ T5

def t5_master_compensate(tmp):
    """主节点 pending-reload 补偿（子进程真跑，非 mock）。

    钉钉 api_base 指向关闭端口 → 拉取必败（rc=1），但补偿在拉取之前执行，
    恰好隔离验证补偿环节本身。"""
    print('== T5 主节点 pending-reload 补偿（子进程真跑，非mock） ==')

    def setup(name):
        d = tmp / name
        d.mkdir()
        wl = d / 'allowed_domains.list'
        wl.write_text('.example-1.com\n')
        (d / 'known.txt').write_text('aliyun.com\n', encoding='utf-8')
        cfg = write_sim_config(d, wl, d / 'known.txt',
                               dt_api_base='http://127.0.0.1:9')
        return d, wl, cfg

    def run_main(cfg, extra=()):
        return subprocess.run([sys.executable, str(REPO / 'squid_whitelist.py'),
                               '--config', str(cfg)] + list(extra),
                              capture_output=True, text=True, timeout=180)

    def audit_events(d):
        return [json.loads(l) for l in (d / 'audit.jsonl').read_text().splitlines()]

    # a) 无标记：正常运行零额外 squid 调用（补偿承诺不伤常态路径）
    d, wl, cfg = setup('comp_a')
    set_stub_env(d)
    p = run_main(cfg)
    check('无标记: 拉取失败rc=1(钉钉指向关闭端口)', p.returncode == 1, p.returncode)
    check('无标记: 零squid调用(无额外reconfigure)', not (d / 'squid.log').exists())
    check('无标记: audit无pending-reload事件',
          not any(e['event'] == 'pending-reload' for e in audit_events(d)))

    # b) 有标记 → 层0之前补偿：恰一次 reconfigure，标记删除
    d, wl, cfg = setup('comp_b')
    marker = wl.with_name(wl.name + '.pending-reload')
    marker.write_text('x')
    set_stub_env(d)
    p = run_main(cfg)
    check('标记补偿: rc=1(拉取失败)但补偿已完成', p.returncode == 1, p.stderr[-300:])
    comp = [e for e in audit_events(d) if e['event'] == 'pending-reload']
    check('标记补偿: audit记录compensated=true', len(comp) == 1
          and comp[0]['compensated'] is True, comp)
    check('标记补偿: 标记已删除', not marker.exists())
    calls = (d / 'squid.log').read_text().splitlines()
    check('标记补偿: 恰一次reconfigure(补偿先于拉取)',
          len(calls) == 1 and 'reconfigure' in calls[0], calls)

    # c) 补偿失败（squid 持续失败）→ 标记保留，主流程不被中断
    d, wl, cfg = setup('comp_c')
    marker = wl.with_name(wl.name + '.pending-reload')
    marker.write_text('x')
    set_stub_env(d, fail_from=1)
    p = run_main(cfg)
    comp = [e for e in audit_events(d) if e['event'] == 'pending-reload']
    check('补偿失败: 标记保留且流程继续(rc=1来自拉取)',
          p.returncode == 1 and marker.exists()
          and len(comp) == 1 and comp[0]['compensated'] is False, (p.returncode, comp))

    # d) dry-run：发现标记只报告不补偿（零写入承诺）
    d, wl, cfg = setup('comp_d')
    marker = wl.with_name(wl.name + '.pending-reload')
    marker.write_text('x')
    set_stub_env(d)
    p = run_main(cfg, extra=['--dry-run'])
    comp = [e for e in audit_events(d) if e['event'] == 'pending-reload']
    check('dry-run: 标记保留零squid调用', marker.exists()
          and not (d / 'squid.log').exists())
    check('dry-run: audit记录未补偿', len(comp) == 1
          and comp[0]['compensated'] is False
          and 'dry-run' in comp[0]['detail'], comp)


# ================================================================ T6

def t6_metadata(tmp):
    """元数据契约：主从两条写入路径替换后属主/属组/权限位保留（2026-10-19）。

    矩阵 = 实现{主NodeA.add_batch, 从whitelist_sync} × umask{077,022} ×
    原权限{0640,0644}；属主预设 nobody（root 下才可验；非 root 或无 nobody
    则跳过属主断言只验权限位）。umask 必须 finally 恢复（进程全局，会波及
    后续场景）。回滚路径只断言权限位：copy2 备份保留 mode 不保留属主（备份
    属主=进程用户；生产主从均 root 运行，属主无漂移）。"""
    import pwd
    import stat as _stat
    print('== T6 元数据契约（主从两实现 × umask × 原权限） ==')
    is_root = os.geteuid() == 0
    try:
        _pw = pwd.getpwnam('nobody')
        uid, gid = _pw.pw_uid, _pw.pw_gid
    except KeyError:
        uid, gid = os.geteuid(), os.getegid()
    can_chown = is_root and (uid, gid) != (os.geteuid(), os.getegid())
    note = '' if can_chown else '（属主部分已跳过：非root或无nobody）'

    def set_meta(p, mode):
        os.chmod(p, mode)
        if can_chown:
            os.chown(p, uid, gid)

    MATRIX = [(um, md) for um in (0o077, 0o022) for md in (0o640, 0o644)]

    # a) 主节点 add_batch（in-process）：0o600 创建+fchown+fchmod 后替换
    for um, md in MATRIX:
        d = tmp / ('meta_a_%o_%o' % (um, md))
        d.mkdir()
        wl = d / 'allowed_domains.list'
        wl.write_text('example-1.com\n')
        conf = make_conf(d / 'squid.conf', wl)
        set_meta(wl, md)
        set_stub_env(d)
        old = os.umask(um)
        try:
            r = NodeA(node_a_cfg(wl, conf), Audit(d / 'audit.jsonl')) \
                .add_batch(['meta-%o.example' % md])
        finally:
            os.umask(old)
        st = wl.stat()
        check('主节点 umask=%03o 原%04o: 成功且权限位保留%s' % (um, md, note),
              r['ok'] and _stat.S_IMODE(st.st_mode) == md,
              (r.get('detail'), oct(_stat.S_IMODE(st.st_mode))))
        if can_chown:
            check('主节点 umask=%03o 原%04o: 属主属组保留' % (um, md),
                  (st.st_uid, st.st_gid) == (uid, gid),
                  (st.st_uid, st.st_gid, uid, gid))

    # b) 从节点 whitelist_sync（子进程真跑；umask 进程全局，子进程继承）
    sync = str(REPO / 'scripts' / 'whitelist_sync')
    for um, md in MATRIX:
        d = tmp / ('meta_b_%o_%o' % (um, md))
        d.mkdir()
        (d / 'fixture').write_text('.example-1.com\n.meta-site.example\n',
                                   encoding='utf-8')
        wl = d / 'allowed_domains.list'
        wl.write_text('example-1.com\n')
        conf = make_conf(d / 'squid.conf', wl)
        set_meta(wl, md)
        env = stub_env(d)
        env.update({'WHITELIST': str(wl), 'SQUID_CONF': str(conf),
                    'SQUID_BIN': STUB, 'SQUID_PORT': str(SIM_PORT),
                    'BACKUP_KEEP': '5',
                    'SYNC_FETCH_CMD': 'cat %s' % (d / 'fixture')})
        old = os.umask(um)
        try:
            p = subprocess.run([sys.executable, sync], env=env,
                               capture_output=True, text=True, timeout=60)
        finally:
            os.umask(old)
        st = wl.stat()
        check('从节点 umask=%03o 原%04o: 成功且权限位保留%s' % (um, md, note),
              p.returncode == 0 and ' updated ' in p.stdout
              and _stat.S_IMODE(st.st_mode) == md,
              (p.returncode, p.stdout[-120:], oct(_stat.S_IMODE(st.st_mode))))
        if can_chown:
            check('从节点 umask=%03o 原%04o: 属主属组保留' % (um, md),
                  (st.st_uid, st.st_gid) == (uid, gid),
                  (st.st_uid, st.st_gid, uid, gid))

    # c) 回滚：恢复备份后内容与权限位恢复（属主不断言，理由见 docstring）
    d = tmp / 'meta_rollback'
    d.mkdir()
    (d / 'fixture').write_text('.example-1.com\n.roll-meta.example\n',
                               encoding='utf-8')
    wl = d / 'allowed_domains.list'
    wl.write_text('example-1.com\n')
    conf = make_conf(d / 'squid.conf', wl)
    set_meta(wl, 0o640)
    env = stub_env(d, fail_list='2,3')
    env.update({'WHITELIST': str(wl), 'SQUID_CONF': str(conf),
                'SQUID_BIN': STUB, 'SQUID_PORT': str(SIM_PORT),
                'BACKUP_KEEP': '5', 'SYNC_FETCH_CMD': 'cat %s' % (d / 'fixture')})
    p = subprocess.run([sys.executable, sync], env=env,
                       capture_output=True, text=True, timeout=60)
    st = wl.stat()
    check('回滚: 内容与权限位恢复(0640)',
          p.returncode == 1 and 'failed' in p.stdout
          and wl.read_text() == 'example-1.com\n'
          and _stat.S_IMODE(st.st_mode) == 0o640,
          (p.returncode, p.stdout[-120:], repr(wl.read_text()),
           oct(_stat.S_IMODE(st.st_mode))))


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
        t5_master_compensate(tmp)
        t6_metadata(tmp)
    finally:
        _PROXY.stop()
        print('\n清理临时目录: %s' % tmp)
        shutil.rmtree(tmp, ignore_errors=True)

    print('结果: %d 通过, %d 失败' % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
