#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""演练用测试替身（--mock 走此模块；不进生产路径，保持主入口精简）

MockTable  演练用钉钉表：读 mock 记录（待处理+处理中均会被拉起），回写仅打印
MockNode   演练用主节点：白名单为内存集合，add_batch 与真实执行器共用
           layers.plan_merge（同一套吸收语义，演练保真）；fail_domains
           任一命中 → 整批演练执行失败（覆盖"人工核查"写入路径）
mock_whitelist  mock 白名单来源：list → 原样；"real" → 只读主节点真实白名单
           （提高演练保真度：真实已覆盖的域名会正确判"已存在"，仍零写入）
"""

import logging
from pathlib import Path

from wlcore.layers import parse_whitelist_text, plan_merge

log = logging.getLogger("squid_whitelist")


class MockTable:
    """演练用钉钉表：读 mock 记录（待处理+处理中均会被拉起），回写仅打印。"""

    def __init__(self, mock):
        self.mock = mock

    def list_pending(self, labels):
        labels = {labels} if isinstance(labels, str) else set(labels)
        return [r for r in self.mock.get('records', [])
                if (r.get('flat') or {}).get('状态') in labels]

    def update_record(self, record_id, status=None, conclusion=None):
        log.info("[mock] 回写 record=%s 状态=%s 结论=%s", record_id, status, conclusion)
        return True


def mock_whitelist(val, real_path):
    """mock 白名单来源：list → 原样使用；"real" → 只读主节点真实白名单文件。"""
    if val == 'real':
        if not real_path:
            log.warning('主节点未配置 whitelist 路径，mock白名单按空集处理')
            return []
        try:
            return sorted(parse_whitelist_text(Path(real_path).read_text(encoding='utf-8')))
        except OSError as e:
            log.warning('读取真实白名单失败(%s): %s，按空集处理', real_path, e)
            return []
    return val or []


class MockNode:
    """演练用主节点：白名单取 mock 提供的列表，add_batch 仅更新内存。

    合并计划与真实执行器共用 layers.plan_merge，语义零漂移。"""

    def __init__(self, rules_list, audit, fail_domains=None):
        self.name = 'A(mock)'
        self._rules = {str(r).lower().lstrip('.') for r in rules_list or []}
        self.fail_domains = {str(d).lower() for d in (fail_domains or [])}
        self.audit = audit

    def rules(self):
        return set(self._rules)

    def add_batch(self, domains):
        domains = list(dict.fromkeys(str(d).lower().lstrip('.') for d in domains))
        hit = [d for d in domains if d in self.fail_domains]
        if hit:
            log.info("[mock] 演练执行失败: %s", ','.join(hit))
            self.audit.action('mock-add-fail', domains=list(domains), hit=hit)
            return {'ok': False, 'added': [], 'skipped': [],
                    'detail': '[mock]演练执行失败: %s' % ','.join(hit)}
        todo, skipped, absorb = plan_merge(self._rules, domains)
        self._rules -= absorb
        self._rules.update(todo)
        log.info("[mock] 计划批量写入: %s（含预检/备份/reconfigure事务）", ','.join(todo))
        self.audit.action('mock-add-batch', added=todo, skipped=skipped,
                          replaced=sorted(absorb))
        return {'ok': True, 'added': todo, 'skipped': skipped,
                'replaced': sorted(absorb),
                'detail': '[mock]演练写入', 'observe': {d: 'mock' for d in todo}}
