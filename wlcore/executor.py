#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""执行环节：主节点白名单批量原子写入（集群唯一写入点）

从节点不接收任何写入，由各自 whitelist_sync 拉取全量镜像（见 README 2.4）。

add_batch 事务（一条记录的全部待新增域名一次写入，全成或全败）：
  幂等预检/超集吸收 → 零触盘预检（tmp清单+tmp.conf，由 squid -k parse 裁决）
  → 备份 → 原子替换（含被吸收子域条目的剔除）→ reconfigure → 等端口就绪
  → CONNECT 复测（纯观察项）

2026-10-15 架构重构：
  - 单域 add → 批量 add_batch（一次备份+多行追加+一次 reconfigure）
  - 复测降级为观察项：403/502/504 均算写入成功（成败只看配置链，与目标站点无关）
  - 回滚条件只剩：预检 parse 失败 / reconfigure 失败
  - NodeB（SSH 推送）删除，改由从节点拉取同步
"""

import logging
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from wlcore.layers import parse_whitelist_text, plan_merge
from wlcore.netprobe import connect_check, wait_proxy_ready

log = logging.getLogger("executor")


def _squid_cmd_result(argv, timeout=30):
    """本地执行命令（参数列表，路径含空格安全）-> (rc, stdout+stderr 摘要)。"""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or '') + (p.stderr or '')
        return p.returncode, out.strip()[:500]
    except subprocess.TimeoutExpired:
        return 124, '命令超时'


class NodeA:
    """主节点（本机）白名单管理。"""

    def __init__(self, cfg, audit):
        n = cfg['nodes']['local']
        self.name = n.get('name', 'A')
        self.path = Path(n['whitelist'])
        self.conf = Path(n.get('squid_conf', '/etc/squid/squid.conf'))
        self.proxy_port = n.get('squid_port', 13128)
        ex = cfg.get('execution', {})
        self.squid_cmd = ex.get('squid_cmd', 'squid')
        # squid_cmd 可为带参数的完整命令（如 "bash stub.sh"）→ 预拆参数列表
        self._squid_argv = shlex.split(self.squid_cmd)
        # squid 6.14 实测：dstdomain 裸条目仅精确匹配（子域不放行），
        # 点前缀才覆盖裸域+全部子域 → 默认 dot_prefix
        self.store_format = ex.get('store_format', 'dot_prefix')
        self.backup_keep = ex.get('backup_keep', 20)
        # 备份统一存放目录：默认白名单同目录下 whitelist-bak/（自动创建），
        # 不再把 /etc/squid 堆满 .bak.*；子目录=同文件系统，回滚 replace
        # 原子性不变。.txn 临时文件仍留在白名单同目录（原子替换依赖）
        self.backup_dir = Path(ex.get('backup_dir')
                               or (self.path.parent / 'whitelist-bak'))
        self.proxy_auth = ex.get('proxy_auth') or None
        self.proxy_tls = bool(ex.get('proxy_tls', False))
        self.audit = audit

    # ---- 只读 ----
    def rules(self):
        try:
            return parse_whitelist_text(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            log.error("白名单文件不存在: %s", self.path)
            return set()

    def _rule_line(self, domain):
        return ('.' + domain) if self.store_format == 'dot_prefix' else domain

    # ---- 批量事务 ----
    def add_batch(self, domains):
        """批量原子写入。返回 {'ok','added','skipped','detail','rollback_ok'?,'observe'}

        ok=True 时 added=实际新增域名、skipped=执行时发现已被覆盖的域名；
        ok=False 时正式文件要么未被碰过（预检失败），要么已回滚。
        """
        domains = list(dict.fromkeys(str(d).lower().lstrip('.') for d in domains))
        # 单次读取：覆盖判定与行过滤基于同一快照（两读之间人工改动会使
        # absorb 集合与 kept 行过滤错位）
        text = self.path.read_text(encoding='utf-8')
        rules = parse_whitelist_text(text)
        # 1) 幂等预检 + 批内/超集吸收（执行前对照最新白名单再核一遍；正常
        #    情况下主流程分流时已处理，这里是防线；语义与分流共用 plan_merge）。
        #    超集吸收：squid 6.14 拒载"子域+超集"并存(FATAL "X is a subdomain
        #    of .Y")，而超集条目完整覆盖子域条目的匹配范围 → 替换零风险，
        #    事务内自动完成，无需人工处理
        todo, skipped, absorb = plan_merge(rules, domains)
        replaced = sorted(absorb)
        if not todo and not replaced:
            return {'ok': True, 'added': [], 'skipped': skipped, 'replaced': [],
                    'detail': '全部已被现有规则覆盖，未写入', 'observe': {}}

        tmp_wl = self.path.with_name(self.path.name + '.txn')
        tmp_conf = self.conf.with_name(self.conf.name + '.txn')
        try:
            # 2) 新清单全文：现有行剔除被吸收的子域条目（空行/注释保留）
            #    + 新规则排序追加（absorb 为原文形态，行过滤按裸名比对）
            absorb_bare = {r.lstrip('.') for r in absorb}
            kept = [ln for ln in text.splitlines()
                    if not ln.strip() or ln.strip().startswith('#')
                    or ln.strip().lower().lstrip('.') not in absorb_bare]
            new_rules = sorted({self._rule_line(d) for d in todo})
            tmp_wl.write_text(''.join(ln + '\n' for ln in kept)
                              + ''.join(r + '\n' for r in new_rules),
                              encoding='utf-8')
            # 3) 零触盘预检：临时 conf 仅替换 dstdomain 路径，
            #    一切组合冲突由 squid 自己 parse 裁决，正式文件不被碰
            conf_text = self.conf.read_text(encoding='utf-8')
            if str(self.path) not in conf_text:
                return {'ok': False, 'added': [], 'skipped': skipped,
                        'detail': 'squid.conf(%s) 未引用白名单路径 %s，中止'
                                  % (self.conf, self.path)}
            tmp_conf.write_text(conf_text.replace(str(self.path), str(tmp_wl)),
                                encoding='utf-8')
            rc, out = _squid_cmd_result(self._squid_argv
                                        + ['-f', str(tmp_conf), '-k', 'parse'])
            if rc != 0:
                self.audit.action('precheck-reject', node=self.name, output=out)
                return {'ok': False, 'added': [], 'skipped': skipped,
                        'detail': '预检parse失败(正式文件未修改)，%s' % out}
            # 4) 备份 → 原子替换（备份入 backup_dir 子目录，回滚用跨目录
            #    rename，同文件系统仍原子）
            ts = time.strftime('%Y%m%d-%H%M%S')
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            bak = self.backup_dir / ('%s.bak.%s' % (self.path.name, ts))
            shutil.copy2(self.path, bak)
            self._prune_backups()
            self.audit.action('backup', node=self.name, file=str(bak))
            tmp_wl.replace(self.path)
            self.audit.action('replace', node=self.name, rules=new_rules,
                              absorbed=replaced)
            # 5) reconfigure（失败重试一次）+ 等端口就绪（kid 重绑 30~50ms 窗口）
            rc, out = _squid_cmd_result(self._squid_argv + ['-k', 'reconfigure'])
            if rc != 0:
                time.sleep(0.5)
                rc, out = _squid_cmd_result(self._squid_argv + ['-k', 'reconfigure'])
            ready = wait_proxy_ready('127.0.0.1', self.proxy_port, timeout=5)
            if rc != 0 or not ready:
                rb = self._rollback(bak)
                return {'ok': False, 'added': [], 'skipped': skipped,
                        'detail': 'reconfigure失败(rc=%s, ready=%s)已回滚，%s'
                                  % (rc, ready, out),
                        'rollback_ok': rb}
            self.audit.action('reload', node=self.name)
            # 6) CONNECT 复测：纯观察项，任何结果都不回滚（成败只看配置链）。
            #    403/502/504 与目标站点/出口网络有关，与白名单写入无关。
            observe = {}
            for d in todo:
                r = connect_check(d, '127.0.0.1', self.proxy_port, timeout=8,
                                  proxy_auth=self.proxy_auth,
                                  proxy_tls=self.proxy_tls)
                observe[d] = r.get('status') if r.get('status') is not None \
                    else r.get('error')
            self.audit.action('observe', node=self.name, result=observe)
            detail = '已写入 %s 并reconfigure生效' % ','.join(new_rules)
            if replaced:
                detail += '（自动合并子域条目: %s）' % ','.join(replaced)
            return {'ok': True, 'added': todo, 'skipped': skipped,
                    'replaced': replaced, 'detail': detail, 'observe': observe}
        finally:
            for p in (tmp_wl, tmp_conf):
                try:
                    p.unlink()   # 成功路径 tmp_wl 已被 replace 消费，此处仅清残留
                except OSError:
                    pass

    def _rollback(self, bak):
        """恢复备份 → 再次reconfigure。返回回滚是否成功。"""
        try:
            bak.replace(self.path)
        except OSError as e:
            log.error("回滚失败(备份仍在磁盘): %s -> %s, %s", bak, self.path, e)
            self.audit.action('rollback-failed', node=self.name, file=str(bak),
                              error=str(e))
            return False
        rc, out = _squid_cmd_result(self._squid_argv + ['-k', 'reconfigure'])
        wait_proxy_ready('127.0.0.1', self.proxy_port, timeout=5)
        self.audit.action('rollback', node=self.name, reload_rc=rc)
        return rc == 0

    def _prune_backups(self):
        baks = sorted(self.backup_dir.glob(self.path.name + '.bak.*'))
        for old in baks[:-self.backup_keep] if self.backup_keep else []:
            try:
                old.unlink()
            except OSError:
                pass
