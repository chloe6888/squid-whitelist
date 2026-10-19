# 域名白名单自动审批系统（squid_whitelist）

> 所有域名（不分国内外）访问代理服务器均须通过白名单（**准入控制**）。用户在钉钉多维表提交域名申请（一条记录可填多个域名，逗号分隔），主节点脚本定时轮询“待处理”记录，**格式合规 + 白名单中不存在即放通，不判断当前能否访问**，写入主节点白名单并回写表格；从节点定期拉取主节点白名单做全量镜像，集群列表始终一致。

**主从分工**（从节点数量对主节点完全透明）：

| | 主节点 A | 从节点 B / C / …（可任意扩容） |
|---|---|---|
| 职责 | 审批 + 白名单**唯一写入点** | 白名单**只读镜像**（人工改动会被下次同步覆盖） |
| 定时 | cron */1 + flock 防重叠，每轮 ≤ `max_per_run=20` 条记录 | cron */5 全量拉取镜像 |
| 依赖 | Python ≥3.8 · requests + PyYAML · squid ≥5 | 仅 Python 标准库 · squid ≥5（有无 auth/TLS 均可） |

**设计原则**：

- **准入控制**：不探测可达性——格式合规且不在白名单即放通，仅要求待新增域名可解析
- **单一权威**：只有主节点写、主删从删；扩容从节点四步走，主节点零改动
- **批量原子**：一条记录的全部新增域名合并为一次事务，全成或全败
- **故障隔离**：squid 异常在层0整批拦截，记录原地保留待重试

**同步与生效**：全量镜像，主节点写入后约 5 分钟内全网一致（最长一个同步周期）。
实测环境：Ubuntu 24.04 · Python 3.12 · squid 6.14 · 主从多节点。

**回写效果示例**（结论四组格式，面向申请人）：

```
状态=已放通    新增成功：github.com、example.com
              已在白名单：www.python.org

状态=部分放通  新增成功：github.com
              已在白名单：www.python.org
              域名不合规：1.2.3.4（IP地址）
              疑似仿冒：aliyum.com（与知名域名aliyun.com高度相似，如确认无误请联系管理员）

状态=驳回      域名不合规：1.2.3.4（IP地址）、xy com（含空格）
              疑似仿冒：aliyum.com（与知名域名aliyun.com高度相似，如确认无误请联系管理员）

状态=人工核查  系统暂时无法完成开通（代理服务异常），已转人工处理
```

## 目录

| 章节 | 内容 |
|---|---|
| [一、系统架构](#一系统架构) | 1.1 部署拓扑 · 1.2 代码结构 · 1.3 核心组件与数据流 |
| [二、功能逻辑](#二功能逻辑) | 2.1 总体流程 · 2.2 状态机 · 2.3 域名处理流水线 · 2.4 主从同步机制 · 2.5 执行事务 |
| [三、配置说明](#三配置说明configyaml) | config.yaml 逐块说明 |
| [四、部署指南](#四部署指南) | 4.1 前置条件 → 4.2 主节点部署（代码+定时任务） → 4.3 从节点部署与扩容（含定时任务） → 4.4 生产前检查 |
| [五、测试与演练](#五测试与演练) | 测试矩阵 + mock 演练命令 |
| [六、运维手册](#六运维手册) | 6.1 用户确认闭环 · 6.2 排查速查 · 6.3 人工改动白名单 · 6.4 审计与监控 |
| [七、已知边界与后续规划](#七已知边界与后续规划) | 当前限制 · 路线图 |

## 快速开始

```bash
pip3 install -r requirements.txt                      # ① 依赖：requests + PyYAML（仅主节点）
# ② squid 已就绪（本 README 不含 squid 部署，运行前提见 4.1）
# ③ 填写 config.yaml（base_id/operator_id 用 4.2 调试命令反查）
python3 wlcore/dingtalk_client.py --config config.yaml --check    # ④ 验证钉钉连通（只读）
python3 squid_whitelist.py --config config.yaml --dry-run      # ⑤ 判定演练（零写入）
# ⑥ 表格状态单选加"处理中""部分放通"两选项 → 按 4.2 两阶段上 cron
# ⑦ 从节点按 4.3 部署（可后做，不影响主节点运行）
```

---

## 一、系统架构

### 1.1 部署拓扑

```
钉钉多维表(域名申请：域名(多个,逗号分隔)/申请人/访问用途/状态/结论)
        ▲ 拉取待处理/回写结论与状态
        │
┌───────┴────────────┐   SSH 只读拉取    ┌─────────────────────┐
│  主节点 A（唯一写入点）│ ◄────────────── │  从节点 B / C / D …  │
│  squid_whitelist    │  whitelist_serve │  whitelist_sync     │
│  (cron */1 + flock) │  (forced command │  (cron */5)         │
│    ↓ 只写本机白名单   │   零参数只读)     │    ↓ 全量镜像        │
│  squid :13128       │                 │  squid :13128       │
│  allowed_domains.list│                │  allowed_domains.list│
└────────────────────┘                 └─────────────────────┘
```

- **主节点是白名单唯一权威**：审批脚本只写主节点的 `/etc/squid/allowed_domains.list`；从节点数量对审批代码完全透明，扩到 4 台、8 台都不用改主节点任何配置
- **SSH 最小权限**：主节点 `authorized_keys` 用 `command=` 强制从节点只能调 `whitelist_serve`（零参数只读输出清单），共用一把受限密钥——从节点被攻破的最大损失仅为“白名单清单可读”
- **表格结构**：域名 / 申请人 / 访问用途 / 申请日期 / 状态(单选六项) / 结论。域名格值可能是钉钉自动转换的 Markdown 链接 `[www.baidu.com](https://...)`，多域名混合纯文本，拆分时统一剥离

### 1.2 代码结构

```
squid-whitelist/                     # 主节点A
├── squid_whitelist.py          # 主入口：层0+批内循环（拆分→分流→执行→回写）
├── wlcore/                     # 核心包（主入口依赖）
│   ├── layers.py               #   拆分/格式/IDN/相似度/覆盖判定/合并计划（纯逻辑，可单测）
│   ├── netprobe.py             #   CONNECT 原语 + 端口就绪等待 + DNS解析原语（层0/复测/DNS准入）
│   ├── executor.py             #   执行环节：批量原子事务（仅主节点本机）
│   ├── dingtalk_client.py      #   钉钉表格读记录+回写，附调试命令
│   └── mocks.py                #   演练测试替身（--mock 路径，不进生产链路）
├── scripts/                    # 独立部署件（自包含仅标准库，不依赖 wlcore）
│   ├── whitelist_serve         #   部署于主节点 /usr/local/bin：供从节点拉取的只读清单输出
│   └── whitelist_sync          #   部署于每个从节点 /usr/local/bin：拉取→比对→预检→镜像→reconfigure
├── tests/
│   └── test_layers.py          # 拆分/格式/相似度/覆盖 单测
├── local_sim/                  # 测试基建（无 squid/SSH/钉钉环境验证全链路）
│   ├── fake_proxy.py           #   模拟squid的CONNECT代理
│   ├── fake_squid.sh           #   squid命令桩（按调用序号注入失败/杀进程崩溃）
│   ├── fake_dingtalk.py        #   假钉钉API服务
│   ├── sim_test.py             #   集成测试
│   └── test_dingtalk.py        #   钉钉客户端测试
├── data/
│   ├── known_domains.txt       # 知名域名种子（人工维护，相似度检测）
│   ├── audit.jsonl             # 审计日志（运行时生成）
│   ├── heartbeat               # 心跳文件（运行时生成）
│   └── mock_records.json       # 演练数据
├── config.yaml                 # 真实配置（含凭证，gitignore；模板 config.example.yaml）
├── config.example.yaml
├── requirements.txt            # requests, PyYAML（从节点零依赖）
└── .gitignore
```

### 1.3 核心组件与数据流

```
钉钉表格 ◀─┤ DingTalkTable ├─▶ squid_whitelist.main ──▶ executor(NodeA.add_batch)
           │ (读+两连写)     │   (批内循环)              │  批量原子事务
                            ├─ layer0_check             └─▶ 主节点白名单(squid -k parse/reconfigure)
                            ├─ split_domains / classify_domain（拆分+四组分流）
                            ├─ Audit（审计事件流）
                            └─ 主节点白名单 ──whitelist_serve──▶ 从节点whitelist_sync ──▶ 各从节点白名单
```

| 模块 | 关键接口 | 职责 |
|---|---|---|
| `wlcore/layers.py` | `split_domains` / `validate_format` / `is_idn` / `check_similar` / `plan_merge` | 拆分归一、格式/IDN/相似度、覆盖判定与合并计划（分流/执行/mock 三处共用同一套吸收语义，纯逻辑） |
| `wlcore/netprobe.py` | `connect_check` / `wait_proxy_ready` / `resolve_ok` | CONNECT 原语（层0健康/复测观察）、端口就绪等待、DNS 可解析性（准入判定） |
| `wlcore/executor.py` | `NodeA.add_batch` | 批量原子事务：零触盘预检→备份（`whitelist-bak/`）→替换写入（含超集吸收）→reconfigure；失败回滚 |
| `wlcore/dingtalk_client.py` | `list_pending` / `update_record` | token 缓存、字段映射、翻页、按多状态过滤、单选纯字符串写入（锁定，无开关） |
| `scripts/whitelist_serve` | （零参数） | 输出主节点白名单归一化清单（每行一条/小写，**保留点前缀形态**） |
| `scripts/whitelist_sync` | （cron 驱动） | 拉取→比对（含形态）→预检→备份（`whitelist-bak/`）→全量镜像→reconfigure；flock 防重叠，日志一行制 |

---

## 二、功能逻辑

### 2.1 总体流程

```
cron 触发（*/1，flock 防重叠）
   │
   ▼
【补偿】pending-reload 遗留标记检查（层0之前）
   ├─ 标记存在 = 上轮事务在"替换后、reconfigure 完成前"中断 → 补一次
   │  reconfigure 使磁盘清单与运行配置对齐，成功后删标记
   └─ 失败保留标记下轮重试，不中断本轮；dry-run 只报告；mock 不涉及
   │
   ▼
【层0】本机 squid 健康预检（整批前一次性）
   ├─ 对照域名 CONNECT 13128：有响应(200/502/504)=健康
   │  （502/504 只说明目标不可达，代理本身在工作）
   └─ 403/407/连接失败 = squid 有病 → 整批跳过，记录原地不动，心跳记 layer0-failed
   │
   ▼
拉取 状态 ∈ {待处理, 处理中}（"处理中"=上轮中断的记录，自动回收重跑）
截取 max_per_run=20 条
   │
   ▼
批内逐条：回写"处理中" → 拆分分流 → 执行 → 回写终态（见 2.3）
   │
   ▼
心跳（run-end：本轮各状态计数）
```

设计准则：**故障隔离**——squid 故障在处理任何记录之前拦住；“处理中”回收让脚本崩溃/回写失败自愈（写入幂等，重跑无副作用）。

### 2.2 状态机（表格“状态”单选，六项）

- **待处理** = 用户提交后的初始状态，等脚本处理
- **处理中** = 脚本已接手（拉取后立即改写）；上轮中断的记录下轮自动回收重跑
- **已放通** = 全部域名已存在或新增成功
- **部分放通** = 部分域名处理成功（结论四组列明明细）
- **驳回** = 全部域名不合规（格式/无法解析）或疑似仿冒（需修改后重新提交 / 确认域名）
- **人工核查** = **仅**执行失败（squid 服务侧问题）；管理员修复后将记录改回“待处理”即重测

```
待处理 ──┬─ 层0失败(整批跳过，状态不变)                    → 下轮重试
（+处理中）─→ 处理中 ─┬─ 全部成功(新增∪已存在)            → 已放通
                      ├─ 部分成功                        → 部分放通
                      ├─ 全部不合规/疑似仿冒              → 驳回
                      ├─ 执行失败(squid服务侧)            → 人工核查
                      └─ 崩溃/回写失败(停在处理中)         → 下轮回收重跑（幂等自愈）
```

### 2.3 域名处理流水线（每条记录）

**第一步：拆分**（`layers.split_domains`）

```
输入（一格混合任意格式）：
  https://github.com，www.python.org; example.com，example.com 1.2.3.4
  ↓ 剥 Markdown 链接壳（钉钉自动转换的 [x](url) 格式）
  ↓ 按容错分隔符拆分：中英文逗号 / 分号 / 空白 / 换行
  ↓ 逐个归一化：去空格、转小写、剥协议头/路径/端口
  ↓ 去重（保持首现顺序）
输出：github.com, www.python.org, example.com, 1.2.3.4
超 max_domains_per_record=20 个：截取前 20，结论提示分批提交
```

**第二步：逐域名分流**（纯内存，零网络探测）

| 分流 | 条件 | 去向 |
|---|---|---|
| 不合规 | 格式校验失败（含空格/缺主域名/IP/端口残留/非法字符/超长）、IDN（xn-- 或非ASCII） | 结论“域名不合规”组带短语（`REASON_SHORT` 码表映射，改措辞不破坏映射）；**完整原因（含具体字符/标签）进审计 record-end 的 invalid 对** |
| 疑似仿冒 | 知名清单全阈值 + 白名单强信号双档种子（编辑距离阈值按注册域长度相对收紧） | 结论“疑似仿冒”组，引导用户确认（见 6.1） |
| 已存在 | `is_covered` 形态感知命中（点前缀=裸域+全部子域；裸=仅精确，squid 实测语义）（含同批前条记录刚新增的域名，跨记录去重） | 结论“已在白名单”组 |
| 待新增 | 其余（含超集吸收：白名单已有其子域条目时，新增超集并在同事务内自动替换子域条目） | 进入 DNS 检查与批量执行 |

**第三步：DNS 可解析性检查**（`netprobe.resolve_ok`，仅对待新增域名）

- 在主节点本地解析（与 squid 建隧道同一解析环境）——**解析不出 = 这台代理上的死条目**
- 失败重试 1 次抗抖动（每次限时 `dns_timeout=3s`）；解析不出的域名归入“域名不合规”组，原因“当前无法解析，若即将上线请稍后重新提交”
- 自保护：整机 DNS 故障时钉钉拉取（同样依赖解析）会先失败、记录原样保留，不会批量误驳
- 一键关闭：`layers.dns_check: false`

**第四步：批量原子执行**（见 2.5），失败则整条记录转人工核查。

**第五步：汇总回写**——四组结论（无该组不出现，单行"；"分隔）+ 六态状态。

### 2.4 主从同步机制

两台以上代理节点各自有白名单文件，**只有主节点被审批脚本写入**；从节点用拉取保持镜像：

```
主节点A                                    从节点B/C/D（各自每5分钟）
  │
  │ ① whitelist_sync 发起 SSH ──────▶ 连得上 = 拉取
  │ ② whitelist_serve 输出
  │    归一化清单（每行一条/小写/保留点前缀形态）
  │ ◀──────────────────────────── 清单文本
  │                                     ③ 与本地清单归一化比对（域名集合+点前缀形态）
  │                                        相等 → 日志一行 synced，不碰文件不碰服务
  │                                        不等 ↓
  │                                     ④ 零触盘预检：tmp清单+tmp.conf → squid -f tmp -k parse
  │                                        失败 → 拒绝落地（本地保持最后good版本）
  │                                     ⑤ 写 pending-reload 标记 → 备份 → 原子替换（元数据保留）
  │                                        → squid -k reconfigure + 等端口 → 删标记
  │                                        失败 → 恢复备份（回滚后 reconfigure 成功才删标记）
  │                                     ⑥ 日志一行（updated +N -M / 失败原因）
```

| 机制 | 说明 |
|---|---|
| 全量镜像 | 从节点白名单 = 主节点完整拷贝：**主删从删**；从节点上手工加的条目会被覆盖回主节点版本——这是特性，强制“删除/修改只在主节点一处做” |
| 语义保真 | 条目**点前缀形态原样镜像**：裸条目=仅精确匹配，点前缀=裸域+全部子域（squid 6.14 实测）。不静默加宽裸条目——否则主节点按精确匹配、从节点按全子域放行，同一规则两边行为漂移。serve 遇裸条目向 stderr 告警提示补点 |
| 单写者 | 分叉无从产生；主节点文件即使被改坏，从节点预检拒收，坏内容不扩散 |
| 防重叠 | flock（`allowed_domains.list.sync-lock`）：上一轮未结束（ssh/parse 慢场景）本轮直接 busy 退出，不并发写同一 tmp 文件 |
| 幂等 | 每次运行先比对（域名集合+形态），无变化**且无遗留标记**时零动作（不写盘不 reload）；有遗留 pending-reload 标记时先补一次 reconfigure 再比对（见 2.5） |
| 崩溃自愈 | 事务用 pending-reload 标记（白名单同目录）包夹"替换→reconfigure"段：进程在窗口内死亡，下轮 sync **一开始**（fetch 之前、不依赖主端可达）补一次 reconfigure 对齐并删标记——补偿先于 no-op 判定，否则主端无新变更时永远没有补偿机会 |
| 生效方式 | `squid -k reconfigure` 平滑重载（端口重绑窗口实测仅 30~50ms，不断活跃连接）。**严禁 restart**（秒级空窗+全量断流） |
| 依赖 | 同步链路不经过 squid 的 http_access：从节点**有无 basic auth、TLS 与否均可混布**，sync 零感知 |
| 监控 | 日志即心跳：每次运行向 `/var/log/whitelist_sync.log` 追加一行；静默落后时看最后一行时间戳即知 |

### 2.5 执行事务：批量原子 + 零触盘预检（主节点）

一条记录的全部“待新增”域名合并为**一次**事务，全成或全败：

```
构造新白名单全文 = (现有规则 − 被吸收的子域条目) ∪ 新增域名（排序去重）
   │              （超集吸收：申请 baidu.com 而已有 www.baidu.com 时，
   │               新增 .baidu.com 并剔除其覆盖的子域条目）
   ▼
写临时白名单 + 临时 squid.conf（仅 dstdomain 路径指向临时文件）
   │
   ▼
squid -f 临时conf -k parse        ← 执行前检查：由 squid 自己裁决一切组合冲突
   ├─ 失败 → 正式文件从未被碰（零触盘）→ 整条记录转人工核查（审计记 parse 输出）
   ▼ 通过
写 pending-reload 标记（白名单同目录 `.pending-reload`，文件+目录 fsync——
   断电时标记必须先于替换持久化；写失败即中止，正式文件未被碰）
→ 备份（时间戳快照，保留20份，统一存于白名单同目录 whitelist-bak/ 子目录）
→ 原子替换正式文件
   │
   ▼
squid -k reconfigure（失败重试一次）→ 等端口就绪（30~50ms 重绑窗口）→ 删标记
   ├─ 失败 → 恢复备份 → 人工核查（回滚后 reconfigure 成功才删标记）
   ▼
CONNECT 复测：逐域名一次，纯观察项
   （200/403/502/504 均算写入成功——成败只看配置链，与目标站点无关）
   结果只进审计 evidence
```

- **写入形态**：`store_format: dot_prefix`（`.example.com`）。squid 6.14 实测：裸条目仅精确匹配，点前缀才覆盖裸域+全部子域
- **元数据保留（2026-10-19）**：临时清单 `0o600` 显式创建（权限不由进程 umask 决定），属主/属组/权限位继承原文件（先 fchown 后 fchmod——chown 会清 setuid/sgid 位，顺序不能反），单次 fsync 同时落盘数据+元数据后原子替换——**替换前后文件属主/权限零漂移**（squid 以 root 读 ACL 文件时非 root 属主/收紧权限是隐患）。从节点 sync 同样实现：自包含不共用代码，一致性由契约测试锁定（主从两实现 × umask{077,022} × 原权限{0640,0644}，属主 nobody；非 root 环境自动降级只验权限位）
- **pending-reload 补偿（2026-10-19）**：替换后、reconfigure 完成前进程死亡，磁盘清单与运行配置漂移且**永不自愈**（表格已回写"已放通"而代理仍拒绝；从节点 no-op 提前退出挡死补偿）。主从事务均以标记包夹该窗口（事务序：写标记并 fsync → 备份 → 替换 → reconfigure → 等端口就绪 → 删标记）。主节点每轮层0之前、从节点每轮 sync 最前（fetch 之前）检查标记补一次 reconfigure。**删标记判据=reconfigure rc==0**——等端口就绪仅 best-effort 不参与判据，否则端口配置不符的节点会陷入每轮补偿循环；标记写失败在替换之前中止事务；补偿失败保留标记下轮重试、不中断本轮；dry-run 只报告不补偿（零写入）；mock 演练不触盘天然无标记
- **回滚条件只剩两个**：预检/parse 失败、reconfigure 失败——均与目标站点、出口 IP、网络状况完全无关
- **超集自动吸收**：申请 `example.com` 而白名单已有 `www.example.com` 时，squid 6.14 拒载“子域+超集并存”（FATAL `X is a subdomain of .Y`）——同事务内新增 `.example.com` 并剔除其覆盖的子域条目（超集完整覆盖子域的匹配范围，替换零风险、无需人工处理）；同批既有超集又有其子域时只写超集
- **审计**：recordId、申请人、每个域名的分流结果与原因、事务各步（含被吸收条目）、复测观察值、回写结果
- **凭证脱敏（2026-10-19）**：appkey/appsecret/代理口令/在用 token 在审计与心跳落盘前统一抹除为 `***`（网络异常消息会带出完整 gettoken URL，query 里就是凭证——审计/心跳不能成为二次泄漏点）；拉取失败的控制台日志同步打码；`--check` 的 token 打印收敛为前 8 位

---

## 三、配置说明（config.yaml）

| 配置块 | 关键项 | 说明 |
|---|---|---|
| `dingtalk` | `app_key/app_secret/base_id/sheet_id/operator_id` | 钉钉凭证（`--resolve <URL>` / `--find-operator` 反查） |
| | `status.*`（含 `pending`） | 状态文案，**须与表格单选精确一致**（六项：待处理/处理中/已放通/部分放通/驳回/人工核查）；`pending` 兼容旧写法顶层 `status_pending` |
| `nodes.local` | `squid_port` / `whitelist` | 主节点 squid 端口与白名单路径（**remote 段已删除**，从节点不受主节点管理） |
| `layer0` | `control_domains` / `min_healthy` | 对照域名（白名单内稳定域名）；判定=有响应即健康 |
| `layers` | `max_per_run` | 每轮记录上限 |
| | `max_domains_per_record` | 单记录域名上限（默认 20，超出截断+提示分批） |
| | `dns_check` / `dns_timeout` | 待新增域名 DNS 可解析性准入（默认开；解析不出=死条目→驳回）；单次解析限时秒数，失败自动重试1次 |
| | `known_domains_required` | 种子清单缺失/为空时：默认 `false`=降级运行（审计 `known-domains-missing` 留痕+告警日志）；`true`=中止本轮（记录原地不动，防"无仿冒检测"批量放行） |
| `execution` | `auto` | true=自动写入 \| false=仅判定回写不执行 |
| | `store_format` | 锁定 `dot_prefix` |
| | `proxy_auth` / `proxy_tls` | 本机探测凭证；**可为空**（无 basic auth 的主节点） |
| `paths` | 各数据文件路径 | 种子/审计/心跳/锁 |
| | `audit_max_mb` / `audit_keep` | 审计超限自动轮转阈值（默认 16MB）与保留份数（默认 3）：`audit.jsonl` → `audit.jsonl.rot.<ts>` |

> 单选字段写入形态已**固定为纯字符串**（联调锁定：`{"name":X}` 被服务端 400 拒绝），不再是配置项——锁定结论留档于 `dingtalk_client.py` 头注。

---

## 四、部署指南

### 4.1 前置条件

| 项 | 要求 |
|---|---|
| 主节点A | Linux、root、Python≥3.8、squid≥5；出口可达 api.dingtalk.com / oapi.dingtalk.com |
| 从节点 | squid≥5、Python≥3（仅标准库）；**有无 basic auth / TLS 均可**，可与主节点不同 |
| 钉钉侧 | 企业内部应用 + 一张多维表，列为：域名/申请人/访问用途/申请日期/状态(单选**六项**)/结论 |

squid 本身的安装与初始化不在本 README 范围（各节点认证方式可异构）。本系统运行仅依赖以下环境事实：

- `squid.conf` 引用白名单文件：`acl allowed_domains dstdomain "/etc/squid/allowed_domains.list"`，且 ★ `allowed_domains` 是 allow 的**必要条件**、`deny all` 兜底——**严禁绕过白名单的直通行**（如 `http_access allow localhost`），否则层0健康检查与准入控制失效
- `/etc/squid/allowed_domains.list` 文件已存在（空文件即可，从节点首次 sync 自动镜像）
- 带 basic auth 的节点：`/etc/squid/passwd` 保持 **644**（helper 以 proxy 用户运行，640 会启动即崩且不易察觉）；主节点密码须与 `config.yaml` 的 `execution.proxy_auth` 一致

### 4.2 主节点部署（代码 + 定时任务）

```bash
# ① 部署代码（排除运行时产物）
rsync -av --exclude='data/audit.jsonl' --exclude='data/heartbeat' \
  --exclude='__pycache__' <源机>:~/squid-whitelist/ /opt/squid-whitelist/
cd /opt/squid-whitelist && pip3 install -r requirements.txt
# ② 填写配置（base_id/operator_id 用下面两条调试命令反查）
cp config.example.yaml config.yaml
python3 wlcore/dingtalk_client.py --config config.yaml --resolve '<表格完整URL>'
python3 wlcore/dingtalk_client.py --config config.yaml --find-operator
python3 wlcore/dingtalk_client.py --config config.yaml --check   # 只读冒烟：token/字段映射/待处理预览
python3 squid_whitelist.py --config config.yaml --dry-run        # 判定演练（零写入）
# ③ 部署只读清单输出（供从节点拉取）
cp scripts/whitelist_serve /usr/local/bin/ && chmod 755 /usr/local/bin/whitelist_serve
```

`data/known_domains.txt`（相似度种子，约60-100条）随仓库自带，人工低频维护。

**定时任务（两阶段上线）**——观察期只判定不写入，人工复核结论后切生产：

```bash
# 阶段1·观察期（1~2天）：只判定不写入（连“处理中”都不写）
*/1 * * * * root /usr/bin/python3 /opt/squid-whitelist/squid_whitelist.py --dry-run \
    >> /var/log/squid_whitelist.log 2>&1
# 阶段2·生产（复核阶段1结论后切换）
#*/1 * * * * root /usr/bin/python3 /opt/squid-whitelist/squid_whitelist.py \
#    >> /var/log/squid_whitelist.log 2>&1
```

要点：脚本免 `cd`（启动即 chdir 到脚本目录）；`/etc/cron.d/` 与 `crontab -e` 格式差异注意第6字段用户名；日志可配 logrotate 轮转。

### 4.3 从节点部署与扩容（四步，主节点零改动）

```bash
# ① 新节点 squid 就绪（运行前提见 4.1；白名单文件留空，首次 sync 自动镜像）
# ② 部署同步 agent（自包含仅标准库，零依赖）
scp scripts/whitelist_sync root@<新节点>:/usr/local/bin/
ssh root@<新节点> chmod 755 /usr/local/bin/whitelist_sync
# ③ 共用受限密钥（所有从节点同一把）：主节点 authorized_keys 追加
command="/usr/local/bin/whitelist_serve",no-pty,no-X11-forwarding,no-agent-forwarding,no-port-forwarding,no-user-rc,from="<从节点IP>" ssh-ed25519 AAAA... replicas
# ④ 手动跑一次验证 + 与主节点比对，通过后上定时任务
ssh root@<新节点> MASTER_HOST=<A地址> MASTER_KEY=/root/.ssh/id_ed25519 /usr/local/bin/whitelist_sync
ssh root@<新节点> "diff <(sort /etc/squid/allowed_domains.list) <(ssh <A> whitelist_serve|sort)"   # 应一致
```

**MASTER_HOST 填址两坑（2026-10-16 节点B实装踩过）**：

1. `<A地址>` 必须是**该从节点可路由到 A 的地址**——跨 VPC 时两边私网 IP 可能撞车（本环境 A/B 内网同为 `10.1.0.6`，从节点连它会连到自己），必须用 A 公网 IP；
2. 首次连接需先把 **A 的主机密钥指纹核对后**写入从节点 `known_hosts`（sync 的 SSH 是 BatchMode，不交互确认，未收录直接报 `Host key verification failed`）：

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub              # A 上看真实指纹
ssh root@<新节点> 'ssh-keyscan -t ed25519 <A地址> | ssh-keygen -lf -   # 两者一致才可入known_hosts'
```

**定时任务（同步）**：

```bash
*/5 * * * * root MASTER_HOST=<A地址> MASTER_KEY=/root/.ssh/id_ed25519 /usr/local/bin/whitelist_sync >> /var/log/whitelist_sync.log 2>&1
```

本机 squid 端口非 13128 时在 cron 行加 `SQUID_PORT=<端口>`（reconfigure 后等端口就绪用；不设只影响该等待的准确性，不影响同步成败与删标记判据）。

日志一行制（日志即心跳）：每次运行追加一行，静默落后时看最后一行时间戳即知（排查见 6.2）。

### 4.4 生产前检查

- 表格单选确认为**六项**，文案与 config.yaml 精确一致（缺“处理中/部分放通”→写入被拒→记录停处理中，补齐后自愈）
- `layer0.control_domains` 为白名单内稳定域名
- 主节点 squid 骨架符合 4.1 ★（白名单是 allow 必要条件、无直通行）
- 带 auth 的主节点：passwd 权限 644、config proxy_auth 同步、200/403/407 三返回码验证
- 每台从节点手动跑一次 sync：首次镜像成功、二次 no-op、`--selftest` 坏内容拒收
- dry-run 跑一轮真实数据，人工复核结论后再放开

---

## 五、测试与演练

| 命令 | 覆盖内容 |
|---|---|
| `python3 tests/test_layers.py` | 拆分（容错/Markdown/端口/去重/截断）、格式、IDN、相似度（含短域相对阈值）、覆盖方向性、合并计划 plan_merge（覆盖/批内/超集吸收）、清单文件加载 |
| `python3 local_sim/sim_test.py` | 全链路：批量事务（成功/预检零触盘/回滚/超集吸收/批内吸收）、pending-reload（标记写失败中止/回滚成败删标记/**崩溃注入(替换后reconfigure前被杀)下轮补偿**/补偿失败重试/主从两侧/dry-run 零写入）、**元数据契约（主从两实现 × umask × 原权限：替换后属主/权限保留，回滚权限恢复）**、**凭证脱敏（fetch 失败时 appkey/appsecret 不落审计/心跳/日志）**、DNS 准入 E2E、whitelist_sync 子进程真跑（no-op/更新/拒收/master不可达/**形态保真不加点加宽**/**flock 防重叠**/selftest）、serve 输出保真、E2E 多域名六态全出口、处理中回收 |
| `python3 local_sim/test_dingtalk.py` | 钉钉客户端：token/映射/翻页/多状态过滤/text写入闭环/**nextToken重复与页数上限防护** |
| `python3 squid_whitelist.py --mock data/mock_records.json` | mock 全路径演练：六态全出口零副作用 |
| `python3 squid_whitelist.py --dry-run` | 真实数据演练：只判定零写入 |

---

## 六、运维手册

### 6.1 “疑似仿冒”域名的用户闭环（仿冒/超集冲突）

```
结论提示"疑似仿冒，如确认无误请联系管理员"
  ├─ 用户填错了 → 修改域名重新提交 → 正常放通
  └─ 用户确认无误 → 联系管理员 → 管理员在【主节点】手动加 .aliyum.com（唯一动作）
                      → 用户重新提交 → 与白名单种子一致不再判仿冒 → 已存在 → 已放通 ✓
超集冲突：管理员在主节点清理冗余子域条目（如删 www.example.com 留 .example.com）
          → 用户重新提交 → 正常放通
```

### 6.2 排查速查

| 现象 | 定位 | 处置 |
|---|---|---|
| 心跳 `layer0-failed` | 层0：对照域名 403/407/连接失败 | 407→认证问题（passwd 644/杀helper/同步config）；连接失败→squid进程；403→白名单文件异常或ACL被改 |
| 记录长期"处理中" | 脚本反复崩溃或回写失败 | 日志查异常栈；audit 查 writeback_ok=false；表格选项是否缺"处理中/部分放通" |
| 从节点不生效 | `/var/log/whitelist_sync.log` 最后一行 | master-unreachable→SSH/密钥；rejected→主节点文件被改坏；busy→上一轮卡住（查ssh/parse耗时）；时间戳过旧→cron没跑 |
| 从节点白名单与主不一致 | diff 两边 | 手动跑一次 sync；确认无人工单边改动（会被自动覆盖，若被绕过说明 sync 没在跑） |
| audit 频繁 `pending-reload`（compensated=false）/ sync 日志 `compensate-failed` | 上轮事务中断后，补偿 reconfigure 一直失败 | 先解决 reconfigure 本身（看事件 detail / 日志输出：squid 进程、conf 错误）；成功后标记自动删除，无需手工清理 |
| 手工验证代理放行（任一节点） | `curl --proxy-insecure -x https://user:pass@127.0.0.1:13128 -sI https://域名/ -o /dev/null -w '%{http_code}\n'`（无 auth/TLS 节点改 `-x http://...`） | 200=放行；403=不在白名单；其余=出口/站点问题 |
| 申请已放通但用户不通 | 白名单已含 → 站点封该节点出口 IP 或用户节点未同步（≤5分钟窗口） | 等同步窗口；持续不通=站点对出口IP的封锁，非白名单问题，考虑换出口 |

### 6.3 人工改动白名单的正确步骤

1. **只改主节点**——增删都只动 A 的 `/etc/squid/allowed_domains.list`，从节点 5 分钟内自动镜像（含删除）
2. 新增条目**统一带点前缀**（`.example.com`）：点前缀=裸域+全部子域；裸条目仅精确匹配且会在 serve 拉取时 stderr 告警（系统不再替你加宽语义）
3. 改后 `squid -k parse` 校验 → `squid -k reconfigure` 生效。**不要 restart**
4. 在从节点手工加条目会被下次 sync 覆盖——**从节点文件视为只读缓存**
5. 删除某条目=全集群自动删除（全量镜像语义），确认清楚再删

### 6.4 审计与监控

- 主节点审计 `data/audit.jsonl`：`record-end` 含每记录全部域名分流明细/事务步骤/复测观察/回写结果
- 审计自动轮转：超过 `paths.audit_max_mb`（默认 16MB）重命名为 `audit.jsonl.rot.<时间戳>`，保留最近 `audit_keep`（默认 3）份，旧份自动清理；排查历史时按时间戳找轮转文件
- 主节点心跳 + watchdog cron 同旧版；从节点看各自 sync 日志末行

---

## 七、已知边界与后续规划

### 7.1 已知边界

- “已放通”指主节点已生效，从节点最长一个同步周期（*/5 ≈ 5 分钟）后生效
- 主节点单点：A 故障时从节点**继续服务**（保持最后版本），仅审批暂停、新记录堆积待处理
- 仿冒检测是启发式（混淆归一化+编辑距离双档），不保证全覆盖；确认闭环依赖人工加白
- 无 basic auth 的从节点，准入完全依赖 `allowed_clients` src 限制
- 不判断域名可达性（设计决策）：加白后站点自身故障不属白名单问题，结论不承诺站点可用。唯一例外是准入前的 DNS 可解析性检查（`dns_check`，死条目防护——解析不出的条目在这台代理上永不开通），与“不判断可达性”的边界：**只问域名是否存在，不问站点是否可用**

### 7.2 后续规划

- 申请人通知（钉钉工作通知/机器人）
- 审计聚合报表（各分流占比/成功率/耗时）
- 从节点同步状态集中监控（节点数增多、单看日志不够时再上）
- `known_domains.txt` 种子维护流程

**明确不做**：不判断域名可达性 · 不用打分模型替代规则 · 不加更多重试 · 不给从节点加写通道
