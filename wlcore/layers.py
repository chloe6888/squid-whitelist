#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""域名判定纯逻辑（无副作用、可单测）

split_domains   多域名申请拆分（容错分隔符/Markdown壳/协议头/路径/端口/去重/截断）
validate_format / is_idn / check_similar   格式 / IDN / 相似域名（第1层）
is_covered / plan_merge / parse_whitelist_text
              白名单覆盖检查与合并计划（squid dstdomain 后缀语义，第2层）；
              plan_merge 供主流程分流/执行器防线/mock 三处共用同一套吸收语义

2026-10-15 架构重构：准入控制不判断可达性，国内外判定（GeoChecker）整层删除。
"""

import re
import string
import logging
from pathlib import Path

log = logging.getLogger("layers")

# ---------------------------------------------------------------- 常量

# 混淆字符归一化表（相似度算法①）
_CONFUSABLE_MULTI = (('rn', 'm'), ('vv', 'w'))
_CONFUSABLE_SINGLE = str.maketrans({
    '0': 'o', '1': 'l', 'i': 'l', '3': 'e', '4': 'a',
    '5': 's', '6': 'b', '7': 't', '8': 'b', '9': 'g',
})

_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
_MD_LINK_FULL_RE = re.compile(r'^\[(.+?)\]\((.+?)\)$')
_ASCII_OK = set(string.ascii_lowercase + string.digits + '.-')

# ---------------------------------------------------------------- 拆分与规范化


def normalize_domain(raw):
    """单个申请串 -> (候选域名, None) 或 (None, 原因)。

    容错剥离：Markdown链接、协议头、路径、query、锚点、尾部端口、
    首尾空白与点、转小写。更严格的非法性交给 validate_format 给出具体原因。
    """
    if raw is None:
        return None, "域名为空"
    s = str(raw).strip()
    if not s:
        return None, "域名为空"
    m = _MD_LINK_FULL_RE.match(s)                  # 整串即Markdown链接 → 取label
    if m:
        s = m.group(1).strip()
    if '://' in s:
        s = s.split('://', 1)[1]
    for sep in ('/', '?', '#'):
        s = s.split(sep, 1)[0]
    # 尾部端口 host:8080（单冒号且后随纯数字才剥，IPv6/残留账号交校验层拦截）
    m = re.match(r'^([^:@]+):(\d+)$', s)
    if m:
        s = m.group(1)
    s = s.strip().lower().strip('.')
    if not s:
        return None, "剥离协议/路径后域名为空"
    return s, None


# 容错分隔符：中英文逗号/分号/顿号/空白/换行（钉钉一格多域名混合任意格式）
_SPLIT_RE = re.compile(r'[\s,，;；、]+')
# 钉钉自动转换的 Markdown 链接（global：一格可含多个），取 label 丢 URL
_MD_LINK_RE = re.compile(r'\[([^\]]+)\]\((https?://[^)]+)\)')


def split_domains(raw, max_n=20):
    """申请格文本 -> (去重域名列表(保序, 最多 max_n), 去重后总数)。

    total > max_n 时截取前 max_n 个（调用方提示分批提交）。
    """
    if raw is None:
        return [], 0
    text = _MD_LINK_RE.sub(lambda m: ' %s ' % m.group(1), str(raw))
    seen, out = set(), []
    for tok in _SPLIT_RE.split(text):
        dom, _err = normalize_domain(tok)
        if dom and dom not in seen:
            seen.add(dom)
            out.append(dom)
    return out[:max_n], len(out)


# ---------------------------------------------------------------- 格式 / IDN / 相似度


def validate_format(domain):
    """格式校验 -> (ok, 完整原因, 码)。ok=False 时完整原因进审计，
    码经主入口 REASON_SHORT 映射为结论短语——两层文案不再靠子串匹配耦合
    （改措辞不会静默破坏短语映射）。"""
    if not domain:
        return False, "域名为空", 'empty'
    if len(domain) > 253:
        return False, "总长度超过253字符", 'too_long'
    if ':' in domain:
        return False, "包含端口或IPv6地址，请仅提交域名本体", 'colon'
    if '@' in domain:
        return False, "包含用户名部分(user@host)，请仅提交域名本体", 'userhost'
    # IP 字面量
    parts = domain.split('.')
    if all(p.isdigit() for p in parts if p) and len(parts) == 4:
        return False, "提交的是IP地址，请申请域名", 'ip'
    bad = set(domain) - _ASCII_OK
    if bad:
        # 不可见字符渲染成可读名称（空格等直接显示会看不出是什么）
        names = {' ': '空格', '\t': '制表符', '\n': '换行', '\r': '回车'}
        # 纯空白类字符与其它非法字符分开计码（结论短语分别为 含空格/含非法字符）
        code = 'whitespace' if bad <= set(names) else 'bad_char'
        return False, "含非法字符，%s" % ','.join(
            names.get(c, c) for c in sorted(bad)), code
    if len(parts) < 2:
        return False, "缺少顶级域名后缀（如 .com）", 'no_tld'
    for p in parts:
        if not p:
            return False, "存在空标签（连续的点）", 'empty_label'
        if not _LABEL_RE.match(p):
            if p.startswith('-') or p.endswith('-'):
                return False, "标签 '%s' 以连字符开头/结尾" % p, 'label_hyphen'
            return False, "标签 '%s' 含非法字符或超长" % p, 'label_bad'
    tld = parts[-1]
    if tld.isdigit() or len(tld) < 2:
        return False, "顶级域名 '%s' 不合法" % tld, 'tld_bad'
    return True, None, None


def is_idn(domain):
    """凡 xn-- 标签或非ASCII字符 → 一律拦截（覆盖混合脚本/同形词）。"""
    return any(not c.isascii() for c in domain) or any(
        lbl.startswith('xn--') for lbl in domain.split('.'))


def registrable(domain):
    """注册域 = 末两个标签。相似度比较对象。"""
    parts = domain.rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else domain


def confusable_normalize(s):
    """混淆字符归一化：rn→m、vv→w，数字/形近字母映射到同一规范形。"""
    for old, new in _CONFUSABLE_MULTI:
        s = s.replace(old, new)
    return s.translate(_CONFUSABLE_SINGLE)


def damerau_levenshtein(a, b):
    """Damerau-Levenshtein 编辑距离（含相邻转置）。"""
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1,
                          d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # 转置
    return d[la][lb]


def distance_threshold(n):
    """编辑距离阈值：知名清单档。注册域长度≤5→1，≤10→2，>10→3；
    再按相对比例收紧：距离不得超过长度的1/4（下限1）。

    极短注册域（如 hw.com）与任何同后缀知名短种（qq.com/jd.com）的编辑
    距离天然≤2，绝对阈值在该长度无区分度、必然大面积误报，故6~7字符
    实际收紧为1（生产案例：hw.com 被误判与 qq.com/jd.com 高度相似）。
    """
    limit = 1 if n <= 5 else (2 if n <= 10 else 3)
    return min(limit, max(1, n // 4))


def check_similar(domain, known_seeds, whitelist_seeds):
    """相似域名检测（种子集双档）。

    known_seeds     知名清单 → 全阈值（归一化相等 或 距离≤阈值）
    whitelist_seeds 白名单并集 → 仅强信号（归一化相等 或 距离=1）
    返回 (疑似?, 依据)。疑似时依据为证据短语（不含处置指引，由调用方组装结论）。

    与种子完全一致不算相似（覆盖与否由 is_covered 判定）——这也是仿冒
    用户确认闭环的入口：管理员在主节点手动加白后，用户重新提交即与
    白名单种子一致而放行。
    """
    reg = registrable(domain)
    if reg in known_seeds or reg in whitelist_seeds:
        return False, None

    best = None  # (优先级, 距离, 种子)

    def consider(seed, tier):
        nonlocal best
        if confusable_normalize(reg) == confusable_normalize(seed):
            cand = (tier, 0, seed)
        else:
            dist = damerau_levenshtein(reg, seed)
            limit = distance_threshold(len(reg)) if tier == 0 else 1
            if dist == 0 or dist > limit:
                return
            cand = (tier, dist, seed)
        if best is None or (cand[0], cand[1]) < (best[0], best[1]):
            best = cand

    for seed in known_seeds:
        consider(seed, tier=0)
    for seed in whitelist_seeds:
        consider(seed, tier=1)

    if best is None:
        return False, None
    tier, _dist, seed = best
    scope = '知名域名' if tier == 0 else '已放行域名'
    # 依据只述事实（"与xx高度相似"），"疑似仿冒"组名由结论组装层添加，
    # 避免组名与括号内原因重复
    return True, "与%s%s高度相似" % (scope, seed)


# ---------------------------------------------------------------- 覆盖检查


def is_covered(domain, rules):
    """squid dstdomain 形态感知语义（2026-10-16 真机 parse 实测对齐）：

    点前缀规则 '.r' 覆盖 r 与全部子域；裸规则 'r' 仅精确匹配 r
    （裸+子域并存 squid 可正常载入，正因裸条目不含子域语义）。
    方向性：申请比规则更宽（申请裸域、规则为子域）不算覆盖。
    返回 (是否覆盖, 命中的规则原文)。
    """
    for r in rules:
        s = r.lower().strip()
        if not s or s.startswith('#'):
            continue
        if s.startswith('.'):
            r2 = s.lstrip('.')
            if r2 and (domain == r2 or domain.endswith('.' + r2)):
                return True, r
        elif domain == s:
            return True, r
    return False, None


def plan_merge(rules, domains):
    """待新增域名对照规则集合的合并计划（唯一权威实现，三处共用：
    classify_domains 分流 / NodeA.add_batch 执行防线 / MockNode 演练）。

    返回 (todo, skipped, absorb)：
      todo     实际需写入的域名（批内被超集覆盖的子域不写，squid 拒载并存）
      skipped  无需写入：已被现有规则覆盖，或被同批超集覆盖
      absorb   因超集吸收应从现有规则剔除的子域条目（超集完整覆盖其匹配
               范围，替换零风险且无需人工处理）
    语义：d == r 或 d.endswith('.'+r) 为覆盖（方向性：申请比规则宽不算）。
    """
    todo, skipped = [], []
    for d in domains:
        if is_covered(d, rules)[0]:
            skipped.append(d)
        else:
            todo.append(d)
    # 批内吸收：批内某域是另一域的子域时只写超集（子域由超集条目覆盖）
    todo = [d for d in todo
            if not any(o != d and d.endswith('.' + o) for o in todo)]
    # 批内被超集覆盖的子域计入 skipped（写入后由超集条目覆盖）
    todo_set = set(todo)
    skip_set = set(skipped)
    skipped += [d for d in domains if d not in todo_set and d not in skip_set
                and any(o != d and d.endswith('.' + o) for o in todo_set)]
    absorb = {r for d in todo for r in rules
              if r.lstrip('.').endswith('.' + d)}   # 层级按裸名比对，保留原文形态
    return todo, skipped, absorb


def parse_whitelist_text(text):
    """解析白名单文件文本 -> 规则集合（覆盖判定/执行环节共用）。

    保留前导点形态：squid 6.14 真机 parse 实测，裸条目仅精确匹配、
    点前缀才覆盖裸域+全部子域——形态即语义（与 serve/sync 形态保真一致）。
    """
    out = set()
    for line in (text or '').splitlines():
        line = line.strip().lower()
        if line and not line.startswith('#'):
            out.add(line)
    return out


def load_domain_list(path):
    """读取域名清单文件 -> 规则集合（parse_whitelist_text 的文件版；
    文件不存在按空集处理并告警——种子清单缺失是运维问题但不应阻断批处理）。"""
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        log.warning("清单文件不存在(按空集处理): %s", path)
        return set()
    return parse_whitelist_text(p.read_text(encoding='utf-8'))
