#!/bin/bash
# fake_squid.sh —— squid 命令桩（本地模拟测试用）
# 记录每次调用；失败/崩溃注入模式：
#   SQUID_FAIL_AT=N     第 N 次调用返回非零（模拟瞬时失败，如单次parse/reload失败）
#   SQUID_FAIL_FROM=N   第 N 次起全部返回非零（模拟持续失败，覆盖回滚路径）
#   SQUID_FAIL_LIST=2,3 仅列表内序号返回非零（精确注入：reconfigure+重试失败
#                       而回滚 reload 成功这类组合）
#   SQUID_KILL_PARENT_AT=N  第 N 次调用时 kill -9 父进程——模拟"白名单已替换、
#                       reconfigure 生效前"进程崩溃（pending-reload 场景）。
#                       只能用于子进程被测对象（sync/gate），in-process 用例
#                       （T2 add_batch）设它会误杀整个测试运行。
LOG="${SQUID_LOG:?SQUID_LOG not set}"
COUNT_FILE="${SQUID_COUNT_FILE:?SQUID_COUNT_FILE not set}"

n=$(cat "$COUNT_FILE" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$COUNT_FILE"
echo "call#$n args:$*" >> "$LOG"

if [ "${SQUID_KILL_PARENT_AT:-0}" -eq "$n" ]; then
    # 先记日志再杀：该次调用须可断言
    echo "kill parent at call #$n" >> "$LOG"
    kill -9 "$PPID"
    exit 1
fi
if [ "${SQUID_FAIL_AT:-0}" -eq "$n" ]; then
    echo "simulated squid failure at call #$n" >&2
    exit 1
fi
case ",${SQUID_FAIL_LIST:-}," in
    *",$n,"*) echo "simulated squid failure at call #$n (list)" >&2; exit 1 ;;
esac
if [ "${SQUID_FAIL_FROM:-999999}" -le "$n" ]; then
    echo "simulated squid failure from call #$n onward" >&2
    exit 1
fi
exit 0
