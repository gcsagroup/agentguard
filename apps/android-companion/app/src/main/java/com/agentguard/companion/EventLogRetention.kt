package com.agentguard.companion

/**
 * 原始事件 JSONL 的保留策略(报告 P1-6:「无限 append,没有轮转、保留期和清除入口」)。
 *
 * 纯函数:给一组文件的 (名字, 大小, 修改时间),决定哪些该删。规则,按顺序:
 *  1. 超过保留期([MAX_AGE_MS])的删;
 *  2. 数量超过 [MAX_FILES] 的,删最旧的;
 *  3. 总大小超过 [MAX_TOTAL_BYTES] 的,从最旧的删起直到降到上限以下。
 * 当前会话的文件永不删(它还在写)。单文件超过 [MAX_FILE_BYTES] 时由 [EnvelopeSink] 换名续写,
 * 这里只管"留多少"。
 */
object EventLogRetention {
    const val MAX_AGE_MS: Long = 14L * 24 * 60 * 60 * 1000
    const val MAX_FILES: Int = 20
    const val MAX_TOTAL_BYTES: Long = 50L * 1024 * 1024
    const val MAX_FILE_BYTES: Long = 5L * 1024 * 1024

    data class Entry(val name: String, val bytes: Long, val modifiedMs: Long)

    /** 返回该删的文件名。`keepName` 是当前会话正在写的文件,永不入选。 */
    fun select(entries: List<Entry>, nowMs: Long, keepName: String?): List<String> {
        val candidates = entries.filter { it.name != keepName }
        val doomed = LinkedHashSet<String>()
        for (e in candidates) {
            if (nowMs - e.modifiedMs > MAX_AGE_MS) doomed.add(e.name)
        }
        // 剩下的按新→旧排,保留最新 MAX_FILES 个(当前会话文件算一个名额)。
        val remaining = candidates.filter { it.name !in doomed }.sortedByDescending { it.modifiedMs }
        val budgetFiles = MAX_FILES - (if (keepName != null) 1 else 0)
        remaining.drop(budgetFiles.coerceAtLeast(0)).forEach { doomed.add(it.name) }
        // 总量:从最旧的删起。
        var total = entries.filter { it.name !in doomed }.sumOf { it.bytes }
        for (e in remaining.asReversed()) {
            if (total <= MAX_TOTAL_BYTES) break
            if (e.name in doomed) continue
            doomed.add(e.name)
            total -= e.bytes
        }
        return doomed.toList()
    }
}
