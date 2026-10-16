#!/bin/bash
# fake_squid.sh —— squid 命令桩（本地模拟测试用）
# 记录每次调用；失败注入两种模式：
#   SQUID_FAIL_AT=N    第 N 次调用返回非零（模拟瞬时失败，如单次parse/reload失败）
#   SQUID_FAIL_FROM=N  第 N 次起全部返回非零（模拟持续失败，覆盖回滚路径）
LOG="${SQUID_LOG:?SQUID_LOG not set}"
COUNT_FILE="${SQUID_COUNT_FILE:?SQUID_COUNT_FILE not set}"

n=$(cat "$COUNT_FILE" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$COUNT_FILE"
echo "call#$n args:$*" >> "$LOG"

if [ "${SQUID_FAIL_AT:-0}" -eq "$n" ]; then
    echo "simulated squid failure at call #$n" >&2
    exit 1
fi
if [ "${SQUID_FAIL_FROM:-999999}" -le "$n" ]; then
    echo "simulated squid failure from call #$n onward" >&2
    exit 1
fi
exit 0
