"""字段级规则：系统保留字段。

field-adjust 各子命令共用：保留字段不可被删除（delete），也不可
作为合并目标（merge）——写入会破坏子规则分流等核心结构。
"""

RESERVED_FIELDS = {"original_log", "rule_name_list", "日志类型"}
