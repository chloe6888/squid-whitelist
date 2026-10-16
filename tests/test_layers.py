#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""拆分/格式/相似度/覆盖 纯逻辑单测：python3 tests/test_layers.py（无依赖、不触网）"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wlcore.layers import (normalize_domain, split_domains, validate_format, is_idn,
                    confusable_normalize, damerau_levenshtein, check_similar,
                    distance_threshold, is_covered, plan_merge,
                    parse_whitelist_text, load_domain_list)

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print('  ok  %s' % name)
    else:
        FAIL += 1
        print('FAIL  %s  %s' % (name, detail))


# ---------------- 规范化 ----------------
print('== normalize_domain ==')
check('markdown链接', normalize_domain('[www.baidu.com](https://www.baidu.com)') == ('www.baidu.com', None))
check('协议+路径', normalize_domain('https://github.com/openai?tab=repos') == ('github.com', None))
check('大写+尾部点', normalize_domain('  GitHub.COM. ') == ('github.com', None))
check('前导点(泛域名语义等价，剥除)', normalize_domain('.example.com') == ('example.com', None))
check('端口剥除', normalize_domain('example.com:8080') == ('example.com', None))
check('协议+端口+路径', normalize_domain('http://Example.com:443/a') == ('example.com', None))
check('空值', normalize_domain('')[0] is None)

# ---------------- 拆分 ----------------
print('== split_domains ==')
out, total = split_domains('a.com, b.com；c.com，d.com;e.com')
check('容错分隔符(中英文逗号/分号/空白)',
      out == ['a.com', 'b.com', 'c.com', 'd.com', 'e.com'], out)
out, total = split_domains('[www.baidu.com](https://www.baidu.com)，[github.com](https://github.com)')
check('多个markdown链接剥壳', out == ['www.baidu.com', 'github.com'], out)
out, total = split_domains('https://x.com/a, y.com:8443，X.COM x.com z.com')
check('去重保序+归一化', out == ['x.com', 'y.com', 'z.com'] and total == 3, (out, total))
out, total = split_domains('n1.com,n2.com,n3.com,n4.com,n5.com', max_n=3)
check('截断到上限', out == ['n1.com', 'n2.com', 'n3.com'] and total == 5, (out, total))
out, total = split_domains('')
check('空输入', out == [] and total == 0)
out, total = split_domains('a.com  ,  , ，； b.com')
check('连续/混杂分隔符', out == ['a.com', 'b.com'], out)

# ---------------- 格式校验 ----------------
print('== validate_format ==')
check('合法域名', validate_format('www.example-1.com')[0])
check('IP被拒', not validate_format('192.168.1.1')[0])
check('端口被拒', not validate_format('example.com:8080')[0])
check('通配符被拒', not validate_format('*.example.com')[0])
check('下划线被拒', not validate_format('my_site.example.com')[0])
check('user@被拒', not validate_format('user@example.com')[0])
check('单标签被拒', not validate_format('localhost')[0])
check('连字符开头被拒', not validate_format('-bad.example.com')[0])
check('纯数字TLD被拒', not validate_format('example.123')[0])

# ---------------- IDN ----------------
print('== is_idn ==')
check('punycode识别', is_idn('xn--55qx5d.cn'))
check('unicode识别', is_idn('münchen.de'))
check('普通域名不误伤', not is_idn('www.example.com'))

# ---------------- 相似度 ----------------
print('== 相似度算法 ==')
check('转置距离=1', damerau_levenshtein('abcd', 'abdc') == 1)
check('插入距离=1', damerau_levenshtein('abc', 'abxc') == 1)
check('删除距离=1', damerau_levenshtein('abxc', 'abc') == 1)
check('rn混淆归一化', confusable_normalize('rnicrosoft') == confusable_normalize('microsoft'))
check('数字混淆归一化', confusable_normalize('g00gle') == confusable_normalize('google'))

KNOWN = {'aliyun.com', 'github.com', 'microsoft.com', 'example-corp.com'}
WL = {'internal-corp-app.com'}
s, d = check_similar('aliyum.com', KNOWN, WL)
check('aliyum↔aliyun 命中(知名档,距离1)', s and 'aliyun.com' in d, (s, d))
s, d = check_similar('githun.com', KNOWN, WL)
check('githun↔github 命中', s, (s, d))
s, d = check_similar('rnicrosoft.com', KNOWN, WL)
check('rnicrosoft 混淆命中', s, (s, d))
s, d = check_similar('internal-corp-apqz.com', KNOWN, WL)
check('白名单档距离2不命中(仅强信号)', not s, (s, d))
s, d = check_similar('internal-corp-apq.com', KNOWN, WL)
check('白名单档距离1命中', s, (s, d))
s, d = check_similar('aliyun.com', KNOWN, WL)
check('与种子完全一致不算相似(仿冒确认闭环入口)', not s, (s, d))
s, d = check_similar('unrelated-xyz.com', KNOWN, WL)
check('无关域名不命中', not s, (s, d))

# 短注册域按相对比例收紧（生产案例：hw.com 曾被误判）
check('阈值: ≤5长为1', distance_threshold(5) == 1)
check('阈值: 6~7长收紧为1', distance_threshold(6) == 1 and distance_threshold(7) == 1)
check('阈值: 8~10长为2', distance_threshold(8) == 2 and distance_threshold(10) == 2)
check('阈值: >10长为3', distance_threshold(12) == 3 and distance_threshold(20) == 3)
s, d = check_similar('hw.com', {'qq.com', 'jd.com'}, set())
check('hw.com↔qq.com 距离2不命中(相对收紧)', not s, (s, d))
s, d = check_similar('126.com', {'163.com'}, set())
check('126.com↔163.com 距离2不命中', not s, (s, d))
s, d = check_similar('hw.con', {'hw.com'}, set())
check('hw.con↔hw.com 距离1仍命中', s, (s, d))
s, d = check_similar('123.com', {'163.com'}, set())
check('123.com↔163.com 距离1仍命中', s, (s, d))

# ---------------- 覆盖判定 ----------------
print('== is_covered ==')
rules = {'.openai.com', 'github.com', 'www.example.com'}
check('点规则覆盖裸域', is_covered('openai.com', rules)[0])
check('点规则覆盖子域', is_covered('api.openai.com', rules)[0])
check('无点规则等价(后缀语义)', is_covered('www.github.com', rules)[0] and is_covered('github.com', rules)[0])
ok, r = is_covered('example.com', rules)
check('方向性:子域规则不覆盖裸域', not ok)
check('无关域名不覆盖', not is_covered('example.org', rules)[0])

# ---------------- 合并计划（覆盖/批内/超集吸收，分流与执行共用） ----------------
print('== plan_merge ==')
todo, skipped, absorb = plan_merge({'a.com'}, ['a.com', 'b.com'])
check('已覆盖进skipped未覆盖进todo',
      todo == ['b.com'] and skipped == ['a.com'] and absorb == set(), (todo, skipped, absorb))
todo, skipped, absorb = plan_merge({'www.x.com'}, ['x.com'])
check('超集吸收: 子域条目进absorb', todo == ['x.com'] and absorb == {'www.x.com'})
todo, skipped, absorb = plan_merge(set(), ['www.ca.com', 'ca-demo.com',
                                           'www.ca-demo.com', 'ca.com'])
check('批内吸收: 只写超集，子域进skipped',
      todo == ['ca-demo.com', 'ca.com']
      and sorted(skipped) == ['www.ca-demo.com', 'www.ca.com'],
      (todo, skipped))
todo, skipped, absorb = plan_merge({'sub.old.com'}, ['old.com', 'sub.old.com'])
check('子域同时被规则与批内超集覆盖不重复计',
      todo == ['old.com'] and skipped == ['sub.old.com']
      and absorb == {'sub.old.com'}, (todo, skipped, absorb))
todo, skipped, absorb = plan_merge({'a.com'}, [])
check('空批零动作', todo == [] and skipped == [] and absorb == set())
check('方向性: 规则子域不吸收申请裸域',
      plan_merge({'www.a.com'}, ['a.com'])[2] == {'www.a.com'}
      and plan_merge({'www.a.com'}, ['b.com'])[2] == set())

# ---------------- 白名单文本解析 ----------------
print('== parse_whitelist_text ==')
rules2 = parse_whitelist_text('# 注释\n.openai.com\n\nGitHub.COM\n  .baidu.com \n')
check('注释/空行/大小写/前导点', rules2 == {'openai.com', 'github.com', 'baidu.com'}, rules2)


# ---------------- 清单文件加载（parse_whitelist_text 文件版） ----------------
print('== load_domain_list ==')
import tempfile as _tf
import os as _os
with _tf.TemporaryDirectory() as _td:
    p = _os.path.join(_td, 'list.txt')
    with open(p, 'w', encoding='utf-8') as f:
        f.write('# seed\nGitHub.COM\n  .baidu.com \n\n')
    check('文件版等价文本版',
          load_domain_list(p) == parse_whitelist_text(open(p, encoding='utf-8').read()))
    check('不存在按空集(仅告警)', load_domain_list(_os.path.join(_td, 'nope.txt')) == set())
    check('空路径按空集', load_domain_list('') == set())

print('\n结果: %d 通过, %d 失败' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
