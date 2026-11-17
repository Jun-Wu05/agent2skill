"""事件名称/事件级别的确定性绑定规则（单一事实源）。

21 个合法事件分类名 + 级别绑定查表 + 级别码值表。LLM（宿主 agent）只
负责选分类名，级别由查表写入。field-adjust 的事件名称守卫与后续
field-mapping 的事件名称标注都消费本模块，禁止在技能脚本内复制此表。
"""

from __future__ import annotations

from typing import Any

EVENT_NAME_FIELD = "事件名称"
EVENT_LEVEL_FIELD = "事件级别"

THREAT_EVENT_NAMES: tuple[str, ...] = (
    "网络攻击",
    "病毒检测",
    "邮件告警",
    "终端告警",
    "蜜罐告警",
    "其他告警",
)
"""威胁组 6 值：事件级别绑定「提醒」；「其他告警」为组内兜底类。"""

NON_THREAT_EVENT_NAMES: tuple[str, ...] = (
    "登录事件",
    "审计事件",
    "会话操作",
    "进程操作",
    "用户操作",
    "资源监控",
    "邮件操作",
    "dns查询",
    "dns响应",
    "数据库操作",
    "ssh连接",
    "认证事件",
    "telnet连接",
    "网络连接",
    "web访问",
)
"""非威胁组 15 值：事件级别绑定「信息」；无兜底类，判定失败不写入。"""

THREAT_EVENT_LEVEL = "提醒"
NON_THREAT_EVENT_LEVEL = "信息"

EVENT_NAME_LEVEL_BINDING: dict[str, str] = {
    **{name: THREAT_EVENT_LEVEL for name in THREAT_EVENT_NAMES},
    **{name: NON_THREAT_EVENT_LEVEL for name in NON_THREAT_EVENT_NAMES},
}
"""事件名称 → 事件级别 的确定性查表；绑定关系不由 LLM 决定。"""

EVENT_LEVEL_CODE_BINDING: dict[str, str] = {
    "信息": "0",
    "提醒": "1",
    "警告": "2",
    "严重": "3",
    "紧急": "4",
}
"""事件级别显示值 → 整型码值（标准目录声明 event_level 为整型）。"""

ALL_EVENT_NAMES = frozenset(EVENT_NAME_LEVEL_BINDING)


def read_entity_event_name(entity: Any) -> str | None:
    """读取单条 entity 已标注的事件名称（addFields 固定值优先，normalize 兜底）。

    值不在 21 名绑定表内（含空值）视为未标注，返回 None。
    事件组寻址（威胁/非威胁批处理）与事件标注事实读取共用本函数。
    """
    parser = entity.get("parser") or {}
    for filter_item in parser.get("filter") or []:
        if (
            isinstance(filter_item, dict)
            and filter_item.get("name") == "addFields"
            and filter_item.get("id") == ""
            and isinstance(filter_item.get("fields"), dict)
            and EVENT_NAME_FIELD in filter_item["fields"]
        ):
            value = filter_item["fields"][EVENT_NAME_FIELD]
            if value in EVENT_NAME_LEVEL_BINDING:
                return str(value)
    for entry in entity.get("normalize") or []:
        if isinstance(entry, dict) and entry.get("index") == EVENT_NAME_FIELD:
            result = entry.get("result") or [""]
            value = str(result[0]) if result else ""
            if value in EVENT_NAME_LEVEL_BINDING:
                return value
    return None


def event_name_normalize_metadata(event_name: str) -> dict[str, Any]:
    """【事件名称】的 normalize 标准元数据。"""
    return {
        "field": "event_name",
        "entity": "事件",
        "sim": True,
        "core": False,
        "mappings": [
            {"mappingType": "EQUAL", "mappingValue": event_name, "orgValue": event_name}
        ],
        "value": event_name,
    }


def event_level_normalize_metadata(event_level: str) -> dict[str, Any]:
    """【事件级别】的 normalize 标准元数据。"""
    code = EVENT_LEVEL_CODE_BINDING[event_level]
    return {
        "field": "event_level",
        "entity": "事件",
        "sim": True,
        "core": False,
        "mappings": [
            {"mappingType": "EQUAL", "mappingValue": code, "orgValue": event_level}
        ],
        "value": code,
    }
