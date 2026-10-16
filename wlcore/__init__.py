# -*- coding: utf-8 -*-
"""squid-whitelist 核心包：纯逻辑 / 执行器 / 探测 / 钉钉客户端 / mock 替身。

主入口为仓库根的 squid_whitelist.py（cron 每分钟调用）；
whitelist_serve / whitelist_sync 是独立部署件（scripts/，仅标准库，不依赖本包）。
"""
