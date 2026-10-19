#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""squid_whitelist —— 域名白名单自动审批主入口（部署于主节点A，cron 驱动）

准入控制（2026-10-15 重构）：所有域名不分国内外，格式合规且白名单中
不存在即放通，不判断当前能否访问。

流程：层0本机squid健康预检（整批拦截） → 拉取 待处理+处理中（回收上轮中断）
     → 逐条：两连写"处理中" → 拆分 → 四组分流（不合规/疑似仿冒/已存在/待新增）
     → 批量原子执行 → 四组结论 + 六态状态回写。
     演练替身（MockNode/MockTable）在 mocks.py，仅 --mock 路径导入。

用法：
  python3 squid_whitelist.py --config config.yaml            # 生产（单次批处理）
  python3 squid_whitelist.py --dry-run                       # 只判定（不写表格、不写白名单）
  python3 squid_whitelist.py --mock data/mock_records.json   # 本地全路径演练（零副作用）
"""

__version__ = '1.1'

import os
import sys
import json
import fcntl
import logging
import argparse
import time
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime

import yaml

from wlcore.layers import (split_domains, validate_format, is_idn, check_similar,
                    registrable, plan_merge, load_domain_list)
from wlcore.netprobe import connect_check, resolve_ok
from wlcore.executor import NodeA

log = logging.getLogger("squid_whitelist")


# ================================================================ 凭证脱敏

def collect_secrets(cfg, table=None):
    """不得出现在日志/审计/心跳中的敏感值：钉钉 appkey/appsecret（gettoken
    把它们拼在 URL query 里，网络异常消息会带完整 URL）、代理认证口令、
    在用 access_token。过短值（<4字符）不参与抹除，避免把 'x' 这类
    占位符当敏感词全局误替换。"""
    vals = []
    dt = cfg.get('dingtalk') or {}
    for k in ('app_key', 'app_secret'):
        if dt.get(k):
            vals.append(str(dt[k]))
    pa = (cfg.get('execution') or {}).get('proxy_auth')
    if pa:
        vals.append(str(pa))
    if table is not None and hasattr(table, 'redaction_values'):
        vals += [str(v) for v in table.redaction_values()]
    return [v for v in vals if len(v) >= 4]


def redact_secrets(text, secrets):
    """把文本中的敏感值替换为 ***（日志/心跳等输出点用）。"""
    for s in secrets or ():
        text = text.replace(s, '***')
    return text


def _redact_obj(obj, secrets):
    """递归抹除 dict/list/字符串值中的敏感值（审计行/心跳 payload 用）。"""
    if not secrets:
        return obj
    if isinstance(obj, str):
        return redact_secrets(obj, secrets)
    if isinstance(obj, dict):
        return {k: _redact_obj(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_redact_obj(v, secrets) for v in obj]
    return obj


# ================================================================ 审计

class Audit:
    """jsonl 审计日志：每个事件一行，全程可追溯。

    超过 max_mb 自动轮转：audit.jsonl -> audit.jsonl.rot.<ts>，保留最近
    keep 份（cron 长期运行无界增长会拖垮磁盘；主进程 flock 单实例，
    rename 原子无并发问题）。

    凭证脱敏（2026-10-19）：写入前对行内字符串值统一抹除 secrets
    （appkey/appsecret/代理口令/token → ***）——网络异常消息含完整
    URL，审计不能成为二次泄漏点。"""

    def __init__(self, path, max_mb=16, keep=3, secrets=()):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = int(max_mb) * 1024 * 1024
        self.keep = int(keep)
        self.secrets = list(secrets)

    def event(self, event, **kw):
        self._rotate()
        line = {'ts': datetime.now().isoformat(timespec='seconds'), 'event': event}
        line.update(kw)
        line = _redact_obj(line, self.secrets)
        try:
            with self.path.open('a', encoding='utf-8') as f:
                f.write(json.dumps(line, ensure_ascii=False) + '\n')
        except OSError as e:
            log.error("审计写入失败: %s", e)

    def action(self, action, **kw):
        self.event('action', action=action, **kw)

    def _rotate(self):
        try:
            if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
                return
            rot = self.path.with_name('%s.rot.%s'
                                      % (self.path.name,
                                         time.strftime('%Y%m%d-%H%M%S')))
            os.replace(self.path, rot)
            log.info('审计轮转: %s', rot)
            olds = sorted(self.path.parent.glob(self.path.name + '.rot.*'))
            for old in olds[:-self.keep] if self.keep else []:
                try:
                    old.unlink()
                except OSError:
                    pass
        except OSError as e:
            log.error("审计轮转失败: %s", e)


# ================================================================ 层0

def layer0_check(cfg, mock, audit):
    """层0：本机 squid 健康预检（处理任何记录之前整批拦截，故障隔离）。

    对照域名 CONNECT 一次：任何代理应答（200/502/504…）= squid 活着——
    502/504 只说明目标不可达，代理本身在工作；403/407 = 白名单/认证配置坏了；
    连接失败/超时 = squid 挂了。后三者均判不健康 → 整批跳过，记录原地不动。
    """
    if mock is not None:
        ok = mock.get('layer0', {}).get('ok', True)
        reason = mock.get('layer0', {}).get('reason', '')
        audit.event('layer0', mocked=True, ok=ok, reason=reason)
        return ok, reason

    l0 = cfg.get('layer0', {})
    n = (cfg.get('nodes') or {}).get('local')
    if not n:
        reason = 'config 缺少 nodes.local（本机squid端口未知），无法做层0预检'
        audit.event('layer0', ok=False, reason=reason)
        return False, reason
    ex = cfg.get('execution', {})
    healthy, details = 0, []
    for d in l0.get('control_domains', []):
        r = connect_check(d, '127.0.0.1', n.get('squid_port', 13128),
                          timeout=l0.get('timeout', 8),
                          proxy_auth=ex.get('proxy_auth') or None,
                          proxy_tls=bool(ex.get('proxy_tls', False)))
        st = r.get('status')
        details.append('%s=%s' % (d, st if st is not None else r.get('error')))
        if st not in (None, 403, 407):
            healthy += 1
    need = l0.get('min_healthy', 1)
    if healthy < need:
        reason = '本机squid异常: 对照域名 %s，健康%d/<%d' % (
            ','.join(details), healthy, need)
        audit.event('layer0', ok=False, reason=reason)
        return False, reason
    audit.event('layer0', ok=True, detail=','.join(details))
    return True, ''


# ================================================================ 拆分分流

# DNS准入判定的不合规原因（自包含指引；后缀"请修改后重新提交"对其不适用）
DNS_REASON = '当前无法解析，若即将上线请稍后重新提交'


# 结论用短语映射（码→短语）。完整原因（含具体字符/标签名）只进审计
# record-end 的 invalid 对——结论面向申请人保持一句话可读，运维排查看审计。
# 码由 layers.validate_format 返回；idn/dns 两码在分流环节合成。
REASON_SHORT = {
    'empty': '域名为空',
    'too_long': '超长',
    'colon': '含端口',
    'userhost': '含账号',
    'ip': 'IP地址',
    'whitespace': '含空格',
    'bad_char': '含非法字符',
    'no_tld': '缺少主域名后缀',
    'empty_label': '格式错误',
    'label_hyphen': '格式错误',
    'label_bad': '格式错误',
    'tld_bad': '顶级域名不合法',
    'idn': '国际化域名暂不支持',
    'dns': DNS_REASON,          # 本身已是结论级短语
}


def short_reason(code):
    """码→结论短语（未知码兜底"不合规"：新码忘配映射不会裸抛）。"""
    return REASON_SHORT.get(code, '不合规')


def classify_domains(domains, known_seeds, whitelist_rules):
    """逐域名分流四组（纯内存，零网络探测）。

    返回 (invalid, confirm, existing, pending_new)：
      invalid 为 [(域名, 码, 完整原因)]（码→结论短语 short_reason，完整原因
      进审计）；confirm 为 [(域名, 依据)]；pending_new 保序。
    格式/IDN/相似度逐个判；覆盖与超集吸收统一走 layers.plan_merge
    （对照"白名单+同批待新增"，批内去重/消化，与执行环节同一套语义）。
    """
    invalid, confirm, valid = [], [], []
    reg_seeds = {registrable(r) for r in whitelist_rules if '.' in r}
    for d in domains:
        ok, reason, code = validate_format(d)
        if not ok:
            invalid.append((d, code, reason))
            continue
        if is_idn(d):
            invalid.append((d, 'idn', '国际化域名暂不支持'))
            continue
        # 相似度只对照白名单现状（同批其他待新增域名不参与，避免
        # batch-a/batch-b 这类同族域名互相比出"疑似仿冒"）
        suspect, detail = check_similar(d, known_seeds, reg_seeds)
        if suspect:
            confirm.append((d, detail + '，如确认无误请联系管理员'))
            continue
        valid.append(d)
    pending_new, existing, _absorb = plan_merge(whitelist_rules, valid)
    return invalid, confirm, existing, pending_new


def build_conclusion(added, existing, invalid, confirm, extra=()):
    """四组结论（无该组不出现），面向申请人；技术证据进审计 record-end。

    组名用事实性措辞，不使用与状态列相近的词；状态由状态列单独表达，
    结论不复述状态词（用户确认的格式）。超集冲突已改为自动吸收合并，
    不再作为独立结论组出现。
    """
    lines = []
    if added:
        lines.append('新增成功：' + '、'.join(added))
    if existing:
        lines.append('已在白名单：' + '、'.join(existing))
    if invalid:
        lines.append('域名不合规：' + '、'.join(
            '%s（%s）' % (d, short_reason(c)) for d, c, _r in invalid))
    if confirm:
        lines.append('疑似仿冒：' + '、'.join('%s（%s）' % pv for pv in confirm))
    lines.extend(extra)
    return '；'.join(lines)


def decide_status(added, existing, invalid, confirm, unwritten_note,
                  pending_new, labels):
    """六态判定（比例判定，决策R5/R7）-> (状态, 结论追补句)。纯函数可单测。

    追补句只出现在驳回态：格式类不合规引导修改，纯 DNS 不解析引导
    稍后原样重提（域名本身无误）。"""
    if unwritten_note and pending_new and not added:
        return labels['manual'], ''
    success = added + existing
    others = invalid + confirm
    if success and not others:
        return labels['approved'], ''
    if success and others:
        return labels['partial'], ''
    if any(c != 'dns' for _, c, _r in invalid):
        return labels['rejected'], '；请修改后重新提交'
    if invalid:
        return labels['rejected'], '；域名无误仅未上线的话，稍后原样重新提交即可'
    return labels['rejected'], ''


# ================================================================ 单记录处理

def process_record(rec, ctx):
    """处理单条申请：两连写占位 → 拆分分流 → DNS准入 → 批量执行
    → 四组结论 + 六态状态 → 终态回写。

    返回 {'outcome': 'skip'|'error'|'done', ...}：
      skip   占位失败（未计任何状态，记录原地不动，处理下一条）
      error  判定环节异常（记录停在"处理中"由下轮回收）
      done   走完终态（含回写失败 writeback_ok=False，同样停处理中回收）
    """
    rid = rec.get('recordId')
    flat = rec.get('flat', {})
    raw = flat.get('域名', '')
    t0 = time.time()

    # ---- 两连写①：先占住记录（崩溃/回写失败的记录停在"处理中"，下轮回收） ----
    if not ctx.dry_run:
        try:
            ctx.table.update_record(rid, status=ctx.labels['processing'])
            ctx.audit.action('mark-processing', recordId=rid)
        except Exception as e:
            log.error('标记处理中失败(record=%s，本轮跳过): %s', rid, e)
            ctx.audit.event('mark-processing-failed', recordId=rid, error=str(e))
            return {'outcome': 'skip'}

    # ---- 拆分 + 分流 ----
    try:
        domains, total = split_domains(raw, ctx.max_domains)
        invalid, confirm, existing, pending_new = classify_domains(
            domains, ctx.known_seeds, ctx.node.rules())
    except Exception as e:  # 单条异常不中断整批；停在处理中下轮回收
        log.exception('记录处理异常(%s)', rid)
        ctx.audit.event('record-error', recordId=rid, error=str(e))
        return {'outcome': 'error'}

    # ---- DNS 可解析性检查（仅待新增；节点本地解析=条目在这台代理上能否生效） ----
    if ctx.dns_check and pending_new:
        bad = [d for d in pending_new if not resolve_ok(d, timeout=ctx.dns_timeout)]
        if bad:
            invalid.extend((d, 'dns', DNS_REASON) for d in bad)
            pending_new = [d for d in pending_new if d not in bad]
            log.info('DNS无法解析(已归入不合规): %s', '、'.join(bad))

    extra = []
    if total > len(domains):
        extra.append('本次最多处理前%d个域名（共%d个），其余请分批提交'
                     % (len(domains), total))

    added, evidence = [], []
    unwritten_note = ''   # 非空 = 待新增未落盘（执行失败/等待管理员/dry-run）

    if not domains:
        conclusion = '未填写有效域名，请填写后重新提交'
        status_label = ctx.labels['rejected']
    else:
        if pending_new:
            if ctx.dry_run:
                added = pending_new
                extra.append('dry-run演练：以上新增为计划写入，未实际执行')
            elif not ctx.auto_exec:
                unwritten_note = '已确认可开通，等待管理员执行'
            else:
                try:
                    res = ctx.node.add_batch(pending_new)
                except Exception as e:  # 事务外抛≈未触盘；停在处理中下轮回收
                    log.exception('执行环节异常(record=%s)', rid)
                    unwritten_note = ('系统暂时无法完成开通（代理服务异常），'
                                      '已转人工处理')
                    evidence.append('执行环节异常: %s' % e)
                else:
                    if res['ok']:
                        added = res['added']
                        existing = existing + res['skipped']
                        evidence.append(res['detail'])
                        if res.get('replaced'):
                            extra.append('已自动合并子域条目：%s'
                                         '（被本次新增条目覆盖，访问范围'
                                         '扩大到全部子域）'
                                         % '、'.join(res['replaced']))
                        if res.get('observe'):
                            evidence.append('复测观察: %s' % json.dumps(
                                res['observe'], ensure_ascii=False))
                    else:
                        unwritten_note = ('系统暂时无法完成开通（代理服务异常），'
                                          '已转人工处理')
                        evidence.append(res['detail'])
                        if res.get('rollback_ok') is False:
                            unwritten_note += '；系统恢复未完全成功，需管理员处理'

        if unwritten_note and pending_new and not added:
            extra.append('未能开通：%s —— %s' % ('、'.join(pending_new), unwritten_note))

        conclusion = build_conclusion(added, existing, invalid, confirm, extra)
        status_label, tail = decide_status(added, existing, invalid, confirm,
                                           unwritten_note, pending_new,
                                           ctx.labels)
        conclusion += tail

    # ---- 两连写②：终态回写（失败则停在处理中，下轮回收重跑） ----
    write_ok = True
    if not ctx.dry_run:
        try:
            ctx.table.update_record(rid, status=status_label, conclusion=conclusion)
        except Exception as e:
            write_ok = False
            log.error('回写失败(record=%s，停在处理中下轮回收): %s', rid, e)

    return {'outcome': 'done', 'status': status_label,
            'audit': dict(
                recordId=rid, applicant=flat.get('申请人'),
                purpose=flat.get('访问用途'), raw=raw, domains=domains,
                added=added, existing=existing,
                invalid=[[d, r] for d, _c, r in invalid],   # 完整原因进审计
                confirm=[list(pv) for pv in confirm],
                status=status_label, conclusion=conclusion,
                evidence='；'.join(evidence), writeback_ok=write_ok,
                mock=ctx.mock, elapsed_ms=int((time.time() - t0) * 1000)),
            'log_line': '%s -> %s: %s' % (raw or '(空)', status_label, conclusion)}


# ================================================================ 主流程

def build_labels(dt):
    """六态文案（须与表格单选精确一致）。pending 新位置 status.pending，
    兼容旧写法 dingtalk.status_pending。"""
    status_cfg = dt.get('status', {})
    return {
        'pending': status_cfg.get('pending', dt.get('status_pending', '待处理')),
        'processing': status_cfg.get('processing', '处理中'),
        'approved': status_cfg.get('approved', '已放通'),
        'partial': status_cfg.get('partial', '部分放通'),
        'rejected': status_cfg.get('rejected', '驳回'),
        'manual': status_cfg.get('manual', '人工核查'),
    }


def acquire_lock(path):
    f = open(path, 'w')
    try:
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except OSError:
        log.warning('上一轮仍在运行（flock 冲突），本轮退出')
        return None


def write_heartbeat(path, payload, secrets=()):
    """心跳原子性无要求（纯提示文件），但与审计同一套脱敏。"""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(_redact_obj(payload, secrets),
                                         ensure_ascii=False), encoding='utf-8')
    except OSError as e:
        log.error('心跳写入失败: %s', e)


def main():
    # cron 等场景工作目录不可控（默认 $HOME）：统一切到脚本所在目录，
    # 使 config.yaml 与 data/ 等相对路径以部署目录为基准（显式绝对路径不受影响）
    os.chdir(Path(__file__).resolve().parent)
    ap = argparse.ArgumentParser(description='域名白名单自动审批')
    ap.add_argument('--config', default='config.yaml')
    ap.add_argument('--dry-run', action='store_true',
                    help='只判定（不回写表格、不执行白名单写入），用于上线前演练')
    ap.add_argument('--mock', metavar='FILE',
                    help='演练数据：层0/表格/主节点全部Mock零副作用；'
                         'JSON含 "table": "real" 时表格改走真实钉钉（读+回写），'
                         '其余仍Mock；whitelist 填 "real" 时只读主节点真实白名单'
                         '（保真演练，仍零写入）')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s [%(name)s] %(message)s')

    cfg = yaml.safe_load(Path(args.config).read_text(encoding='utf-8'))
    paths = cfg.get('paths', {})
    mock = json.loads(Path(args.mock).read_text(encoding='utf-8')) if args.mock else None
    dry_run = args.dry_run

    lock = acquire_lock(paths.get('lock_file', '/tmp/squid_whitelist.lock'))
    if lock is None:
        return 0

    audit = Audit(paths.get('audit_log', 'data/audit.jsonl'),
                  max_mb=paths.get('audit_max_mb', 16),
                  keep=paths.get('audit_keep', 3))
    audit.event('run-start', dry_run=dry_run, mock=bool(mock))

    labels = build_labels(cfg['dingtalk'])

    # ---- 组件装配（提前至层0之前：pending-reload 补偿需要 node） ----
    lay = cfg.get('layers', {})
    known_path = paths.get('known_domains', 'data/known_domains.txt')
    known_seeds = load_domain_list(known_path)
    if mock is not None:
        from wlcore.mocks import MockNode, MockTable, mock_whitelist
        node = MockNode(mock_whitelist(mock.get('whitelist'),
                                       cfg['nodes']['local'].get('whitelist')),
                        audit, mock.get('exec_fail') or [])
        if mock.get('table') == 'real':
            from wlcore.dingtalk_client import DingTalkTable
            table = DingTalkTable(cfg['dingtalk'])
        else:
            table = MockTable(mock)
    else:
        node = NodeA(cfg, audit)
        from wlcore.dingtalk_client import DingTalkTable
        table = DingTalkTable(cfg['dingtalk'])

    # 脱敏集合在组件装配后补挂（Audit 构造先于 table；mock 表无凭证）
    audit.secrets = collect_secrets(cfg, table)

    # ---- 种子清单缺失显式留痕（2026-10-19）----
    # 缺失/为空 = 仿冒检测整层静默失效（审批照常放行）——不能只留一条
    # warning 日志。默认降级运行（审计+告警日志留痕）；required 模式直接
    # 中止本轮，记录原地不动，防"无仿冒检测"状态下批量放行。
    if not known_seeds:
        required = bool(lay.get('known_domains_required', False))
        audit.event('known-domains-missing', path=str(known_path),
                    required=required)
        if required:
            log.error('知名域名种子清单缺失/为空且 known_domains_required=true，'
                      '本轮中止: %s', known_path)
            write_heartbeat(paths.get('heartbeat', 'data/heartbeat'),
                            {'ts': datetime.now().isoformat(timespec='seconds'),
                             'result': 'known-domains-missing',
                             'reason': 'seed清单缺失/为空且known_domains_required=true'},
                            secrets=audit.secrets)
            return 1
        log.warning('知名域名种子清单缺失或为空，仿冒检测降级运行: %s', known_path)

    # ---- pending-reload 补偿（层0之前）----
    # 上轮事务可能在"替换后、reconfigure 完成前"中断，磁盘清单与运行配置
    # 漂移且不会自愈：先补一次 reconfigure 对齐再干活。mock 演练不触盘
    # 天然无标记；dry-run 只报告不补偿（保持零写入）。补偿失败保留标记、
    # 不中断本轮——层0/后续 add_batch 自身的 reconfigure 会继续尝试收敛。
    if mock is None:
        comp = node.pending_reload_compensate(dry_run=dry_run)
        if comp['found']:
            log.warning('pending-reload: %s', comp['detail'])
            audit.event('pending-reload', compensated=comp['compensated'],
                        detail=comp['detail'])

    # ---- 层0 ----
    ok, reason = layer0_check(cfg, mock, audit)
    if not ok:
        log.error('层0预检失败，整批跳过（记录原地不动）：%s', reason)
        write_heartbeat(paths.get('heartbeat', 'data/heartbeat'),
                        {'ts': datetime.now().isoformat(timespec='seconds'),
                         'result': 'layer0-failed', 'reason': reason},
                        secrets=audit.secrets)
        return 0

    # ---- 拉取 待处理 + 处理中（上轮中断回收：写入幂等，重跑无副作用） ----
    try:
        records = table.list_pending([labels['pending'], labels['processing']])
    except Exception as e:
        # 异常消息可能含完整 gettoken URL（query 里是 appkey/appsecret）
        log.error('拉取待处理记录失败: %s', redact_secrets(str(e), audit.secrets))
        audit.event('fetch-failed', error=str(e))   # Audit 落盘前统一抹除
        write_heartbeat(paths.get('heartbeat', 'data/heartbeat'),
                        {'ts': datetime.now().isoformat(timespec='seconds'),
                         'result': 'fetch-failed', 'reason': str(e)},
                        secrets=audit.secrets)
        return 1

    records = records[:lay.get('max_per_run', 20)]
    ctx = SimpleNamespace(
        table=table, node=node, labels=labels, known_seeds=known_seeds,
        dry_run=dry_run, audit=audit, mock=bool(mock),
        auto_exec=cfg.get('execution', {}).get('auto', True),
        dns_check=lay.get('dns_check', True),
        dns_timeout=lay.get('dns_timeout', 3),
        max_domains=lay.get('max_domains_per_record', 20))
    log.info('本轮处理 %d 条（dry_run=%s）', len(records), dry_run)

    counts = {}
    for rec in records:
        res = process_record(rec, ctx)
        if res['outcome'] == 'skip':
            continue
        if res['outcome'] == 'error':
            counts['error'] = counts.get('error', 0) + 1
            continue
        counts[res['status']] = counts.get(res['status'], 0) + 1
        audit.event('record-end', **res['audit'])
        log.info('%s', res['log_line'])

    audit.event('run-end', total=len(records), counts=counts)
    write_heartbeat(paths.get('heartbeat', 'data/heartbeat'),
                    {'ts': datetime.now().isoformat(timespec='seconds'),
                     'result': 'ok', 'total': len(records), 'counts': counts},
                    secrets=audit.secrets)
    log.info('本轮完成: %s', json.dumps(counts, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
