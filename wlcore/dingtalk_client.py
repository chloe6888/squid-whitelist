#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""钉钉 AI表格(notable) 客户端：拉取待处理记录 / 回写状态与结论

API 形态（2026-09-20 真实表格联调核实）：
  取 token : GET https://oapi.dingtalk.com/gettoken?appkey=..&appsecret=..
  字段列表 : GET /v1.0/notable/bases/{baseId}/sheets/{sheetId}/fields?operatorId=..
  列出记录 : GET /v1.0/notable/bases/{baseId}/sheets/{sheetId}/records?operatorId=..
             &maxResults=..&nextToken=..      （fields 键为【字段名】，非 fieldId）
  更新记录 : PUT  /v1.0/notable/bases/{baseId}/sheets/{sheetId}/records?operatorId=..
             body: {"records": [{"id": <recordId>, "fields": {<fieldId>: <value>}}]}
             写入键用 fieldId；单选字段值 = 纯字符串（联调锁定为 text 形态）

写入格式联调锁定结论（真实表格验证，2026-09-20）：单选 {"name":X} 会被
整体 400 拒绝（"the value '[object Object]' is invalid"）；纯字符串生效。
已固定为纯字符串写入，不留运行时开关——误配 name 形态即全量回写失败，
锁定结论留档于此与 README，不再暴露配置面。

调试 CLI（凭证填好后即可做 README 上线检查单的 P0 联调项）：
  python3 dingtalk_client.py --config config.yaml --check
      # 只读冒烟：token → 字段映射 → 记录状态分布 → 待处理预览
  python3 dingtalk_client.py --config config.yaml --check --probe-write <recordId>
      # 写路径联调：回写"驳回+测试结论"后读回验证（单选纯字符串写入往返）
"""

import json
import re
import sys
import time
import logging

import requests

log = logging.getLogger("dingtalk")


def flatten_value(val):
    """单选/人员/毫秒时间戳/Markdown链接 → 纯文本（早期 fetch_records.py 已验证规则沿用）。"""
    if isinstance(val, dict) and 'name' in val:
        return val['name']
    if isinstance(val, list) and val and isinstance(val[0], dict) and 'name' in val[0]:
        return "、".join(item['name'] for item in val)
    if isinstance(val, int) and val > 10 ** 12:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(val / 1000))
    if isinstance(val, str):
        m = re.match(r'^\[(.+?)\]\((.+?)\)$', val.strip())
        if m:
            return m.group(1)
        return val
    return val


class DingTalkTable:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg['base_id']
        self.sheet = cfg['sheet_id']
        self.operator = cfg['operator_id']
        self.timeout = cfg.get('timeout', 15)
        self.status_field = cfg.get('status_field', '状态')
        self.conclusion_field = cfg.get('conclusion_field', '结论')
        # API 地址可覆盖：默认真实钉钉；本地联调指向 local_sim/fake_dingtalk.py
        self.api_base = cfg.get('api_base', 'https://api.dingtalk.com').rstrip('/')
        self.oapi_base = cfg.get('oapi_base', 'https://oapi.dingtalk.com').rstrip('/')
        self._token = None
        self._token_ts = 0.0
        self._id2name, self._name2id = {}, {}

    # ---------------- 基础 ----------------

    def redaction_values(self):
        """日志脱敏用：凭证与在用 access_token（主入口 Audit/心跳集中抹除）。

        gettoken 把 appkey/appsecret 拼在 URL query，网络异常消息会带出
        完整 URL——这些值不得落审计/心跳/日志。"""
        return [str(v) for v in (self.cfg.get('app_key'),
                                 self.cfg.get('app_secret'),
                                 self._token) if v]

    def _get_token(self):
        now = time.time()
        if self._token and now - self._token_ts < 7000:   # 有效期7200s，提前刷新
            return self._token
        url = ('%s/gettoken?appkey=%s&appsecret=%s'
               % (self.oapi_base, self.cfg['app_key'], self.cfg['app_secret']))
        res = requests.get(url, timeout=self.timeout)
        data = res.json()
        if data.get('errcode') != 0:
            raise RuntimeError('获取token失败: %s' % res.text)
        self._token, self._token_ts = data['access_token'], now
        return self._token

    def _url(self, path):
        return ('%s/v1.0/notable/bases/%s/sheets/%s%s?operatorId=%s'
                % (self.api_base, self.base, self.sheet, path, self.operator))

    def _load_field_map(self):
        res = requests.get(url=self._url('/fields'),
                           headers={'x-acs-dingtalk-access-token': self._get_token()},
                           timeout=self.timeout)
        data = res.json()
        if 'value' not in data:
            hint = ('（operator_id 应为用户 unionId，而非 base/doc ID；'
                    '可用 --find-operator 查询）' if 'operatorId' in res.text else '')
            raise RuntimeError('获取字段列表失败: %s%s' % (res.text, hint))
        for f in data['value']:
            self._id2name[f['id']] = f['name']
            self._name2id[f['name']] = f['id']
        log.info('字段映射: %s', self._id2name)

    def ensure_field_map(self):
        if not self._name2id:
            self._load_field_map()

    # ---------------- 读 ----------------

    def list_records(self, page_size=100, max_pages=50):
        """分页拉取全部原始记录。

        两重防护：nextToken seen-set（服务端分页异常返回重复游标会死循环）；
        max_pages 上限（默认 50 页 × 100 条/页 = 5000 条，审批表不会超出）。"""
        self.ensure_field_map()
        out, next_token, seen = [], None, set()
        for _page in range(max_pages):
            url = self._url('/records') + '&maxResults=%d' % page_size
            if next_token:
                url += '&nextToken=%s' % next_token
            res = requests.get(url=url,
                               headers={'x-acs-dingtalk-access-token': self._get_token()},
                               timeout=self.timeout)
            data = res.json()
            if 'records' not in data:
                raise RuntimeError('列出记录失败: %s' % res.text)
            out.extend(data['records'])
            if not data.get('hasMore') or not data.get('nextToken'):
                return out
            next_token = data['nextToken']
            if next_token in seen:
                raise RuntimeError('nextToken重复(%r)，疑似服务端分页异常，中止'
                                   % next_token[:40])
            seen.add(next_token)
        raise RuntimeError('分页超过%d页(已取%d条)，疑似异常，中止'
                           % (max_pages, len(out)))

    def flatten_record(self, rec):
        """单条记录字段拍平：fieldId→字段名，值→纯文本。"""
        return {self._id2name.get(fid, fid): flatten_value(val)
                for fid, val in rec.get('fields', {}).items()}

    def list_pending(self, labels):
        """字段拍平后待处理记录列表。labels 为状态文案 str 或 iterable
        （主流程传 [待处理, 处理中]：处理中=上轮中断记录，回收重跑）。"""
        wanted = {labels} if isinstance(labels, str) else set(labels)
        self.ensure_field_map()
        pending = []
        for rec in self.list_records():
            flat = self.flatten_record(rec)
            if flat.get(self.status_field) in wanted:
                pending.append({'recordId': rec.get('id'), 'flat': flat})
        log.info('待处理记录 %d 条（状态 ∈ %s）', len(pending), '/'.join(sorted(wanted)))
        return pending

    # ---------------- 写 ----------------

    def update_record(self, record_id, status=None, conclusion=None):
        """回写状态与结论（单一锁定格式，失败上抛由调用方决定保持待处理）。"""
        self.ensure_field_map()
        fields = {}
        if status is not None:
            fid = self._name2id.get(self.status_field)
            if not fid:
                raise RuntimeError('表中不存在字段: %s' % self.status_field)
            # 联调锁定：单选写入=纯字符串（{"name":X} 形态被服务端 400 拒绝）
            fields[fid] = status
        if conclusion is not None:
            fid = self._name2id.get(self.conclusion_field)
            if not fid:
                raise RuntimeError('表中不存在字段: %s' % self.conclusion_field)
            fields[fid] = conclusion
        if not fields:
            return True

        body = {'records': [{'id': record_id, 'fields': fields}]}
        res = requests.put(url=self._url('/records'),
                           headers={'x-acs-dingtalk-access-token': self._get_token()},
                           json=body, timeout=self.timeout)
        if res.status_code != 200:
            raise RuntimeError('回写失败(record=%s) HTTP %s: %s'
                               % (record_id, res.status_code, res.text[:300]))
        return True


# ---------------- 调试 CLI（读冒烟 / 写联调） ----------------

def _cmd_resolve(dt_cfg, target):
    """给定 URL 或 token，逐个验证哪个能作为 notable baseId，并列出数据表。"""
    table = DingTalkTable(dt_cfg)
    token = table._get_token()
    cands = re.findall(r'[A-Za-z0-9]{16,}', target)   # URL 或裸 token 中的长随机段
    seen, order = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            order.append(c)
    if not order:
        print('无法从输入提取候选token: %r' % target)
        return 2
    headers = {'x-acs-dingtalk-access-token': token}
    for t in order:
        url = ('%s/v1.0/notable/bases/%s/sheets?operatorId=%s'
               % (table.api_base, t, table.operator))
        res = requests.get(url, headers=headers, timeout=table.timeout)
        try:
            data = res.json()
        except ValueError:
            data = {}
        if res.status_code == 200:
            print('候选 %s -> ✓ 可作为 baseId，数据表：' % t)
            print(json.dumps(data, ensure_ascii=False, indent=2))
            print('→ config.yaml: base_id=%s；sheet_id 从上面列表里挑' % t)
            return 0
        print('候选 %s -> HTTP %s: %s' % (t, res.status_code,
                                          json.dumps(data, ensure_ascii=False)[:200]))
    print('→ 全部候选不可用：请直接打开AI表格本体（不要从知识库/文档里点入），'
          '复制浏览器地址栏完整URL重试本命令')
    return 2


def _cmd_find_operator(dt_cfg):
    """用应用凭证查通讯录，列出成员 userid/unionId —— operator_id 应填 unionId。"""
    table = DingTalkTable(dt_cfg)
    token = table._get_token()
    dept = int(dt_cfg.get('root_dept_id', 1))
    url = '%s/topapi/v2/user/list?access_token=%s' % (table.oapi_base, token)
    users, cursor = [], 0
    while True:
        res = requests.post(url, json={'dept_id': dept, 'cursor': cursor, 'size': 100},
                            timeout=table.timeout)
        data = res.json()
        if data.get('errcode') != 0:
            print('通讯录查询失败: %s' % res.text)
            if data.get('errcode') in (60011, 60020, 88):
                print('→ 应用缺少通讯录读权限：钉钉开发者后台 → 应用 → 权限管理 →'
                      ' 开通"成员信息读权限"后重试')
            if data.get('errcode') == 60003:
                print('→ 根部门不是1：config.yaml 的 dingtalk.root_dept_id 填实际根部门ID')
            return 2
        r = data.get('result') or {}
        users.extend(r.get('list') or [])
        if not r.get('has_more'):
            break
        cursor = r.get('next_cursor') or 0
    if not users:
        print('部门 %d 下没有成员（可在 config.yaml 用 dingtalk.root_dept_id 指定其他部门）' % dept)
        return 2
    print('部门 %d 成员 %d 人：' % (dept, len(users)))
    for u in users:
        print('  name=%-12s userid=%s  unionId=%s'
              % (u.get('name', ''), u.get('userid', ''), u.get('unionid', '')))
    print('→ 把某个 unionId 填入 config.yaml 的 dingtalk.operator_id'
          '（该用户需为表格协作者）')
    return 0


def _cmd_check(dt_cfg, probe_write=None):
    """--check：只读冒烟；--probe-write：写一条记录并读回验证写入形态。"""
    from datetime import datetime
    table = DingTalkTable(dt_cfg)
    status_field = table.status_field

    print('[1] 获取 token ...')
    print('    access_token: %s...（已打码）' % table._get_token()[:8])

    print('[2] 加载字段映射 ...')
    table.ensure_field_map()
    for fid, name in table._id2name.items():
        print('    %s -> %s' % (fid, name))

    print('[3] 拉取全部记录 ...')
    records = table.list_records()
    flats = {r.get('id'): table.flatten_record(r) for r in records}
    dist = {}
    for f in flats.values():
        k = f.get(status_field, '(空)')
        dist[k] = dist.get(k, 0) + 1
    print('    共 %d 条，状态分布: %s' % (len(flats), json.dumps(dist, ensure_ascii=False)))

    pending_labels = [dt_cfg.get('status', {}).get('pending',
                                                   dt_cfg.get('status_pending', '待处理')),
                      dt_cfg.get('status', {}).get('processing', '处理中')]
    pending = [(rid, f) for rid, f in flats.items()
               if f.get(status_field) in pending_labels]
    print('[4] 待拉取（%s）%d 条（最多预览5条）:' % ('/'.join(pending_labels), len(pending)))
    for rid, f in pending[:5]:
        print('    %s  %-42s 申请人=%s 用途=%s'
              % (rid, str(f.get('域名', '')), f.get('申请人'), f.get('访问用途')))

    if not probe_write:
        return 0

    # ---- 写路径联调（README 上线检查单 P0 项：验证单选纯字符串写入往返） ----
    print('[5] 写路径联调 record=%s ...' % probe_write)
    if probe_write not in flats:
        print('    !! 记录不存在: %s（recordId 请从 [4] 列表中取）' % probe_write)
        return 2
    # 写路径联调用"驳回"做往返测试（状态单选六项之一，用驳回避免干扰在途记录）
    label = dt_cfg.get('status', {}).get('rejected', '驳回')
    mark = '钉钉写入格式联调测试 %s' % datetime.now().isoformat(timespec='seconds')
    table.update_record(probe_write, status=label, conclusion=mark)
    print('    PUT 完成(HTTP 200)，读回验证 ...')
    after = {r.get('id'): table.flatten_record(r) for r in table.list_records()}
    f = after.get(probe_write, {})
    if f.get(status_field) == label and mark in (f.get(table.conclusion_field) or ''):
        print('    ✓ 写入生效（状态=%s，结论已更新）——单选纯字符串写入正常'
              % label)
        return 0
    print('    !! 服务端接受但读回不一致: 状态=%r 结论=%r'
          % (f.get(status_field), f.get(table.conclusion_field)))
    return 2


def main():
    import argparse
    from pathlib import Path
    ap = argparse.ArgumentParser(description='钉钉AI表格客户端调试（读冒烟/写联调）')
    ap.add_argument('--config', default='config.yaml')
    ap.add_argument('--check', action='store_true',
                    help='只读冒烟：token/字段映射/记录状态分布/待处理预览')
    ap.add_argument('--find-operator', action='store_true',
                    help='列出通讯录成员的 unionId（operator_id 需为用户 unionId）')
    ap.add_argument('--resolve', metavar='URL_OR_TOKEN',
                    help='验证候选 ID 能否作为 baseId，并列出该表格的全部数据表')
    ap.add_argument('--probe-write', metavar='RECORD_ID',
                    help='写路径联调：回写状态+结论后读回验证，需配合 --check')
    args = ap.parse_args()
    if not (args.check or args.find_operator or args.resolve):
        ap.print_help()
        return 0
    import yaml
    cfg = yaml.safe_load(Path(args.config).read_text(encoding='utf-8'))
    # 兼容两种文件：主配置 config.yaml（取 dingtalk 段）或只含钉钉配置的最小 yaml
    dt_cfg = cfg.get('dingtalk', cfg) if isinstance(cfg, dict) else {}
    if args.find_operator:
        return _cmd_find_operator(dt_cfg)
    if args.resolve:
        return _cmd_resolve(dt_cfg, args.resolve)
    return _cmd_check(dt_cfg, probe_write=args.probe_write)


if __name__ == '__main__':
    sys.exit(main())
