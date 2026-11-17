"""event_binding 事件名称读取测试。

覆盖 read_entity_event_name：addFields 固定值优先、normalize 兜底、
非法值视为未标注。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(SKILLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared.event_binding import (  # noqa: E402
    EVENT_NAME_FIELD,
    read_entity_event_name,
)


def make_entity(*, addfields=None, normalize=None) -> dict:
    filters = None
    if addfields is not None:
        filters = [{"name": "addFields", "id": "", "fields": addfields}]
    return {
        "name": "rule_a",
        "parser": {"name": "json", "filter": filters},
        "normalize": normalize or [],
    }


def norm_entry(index: str, result) -> dict:
    return {"index": index, "result": result, "mappings": []}


class ReadEntityEventNameTest(unittest.TestCase):
    """read_entity_event_name() 读取逻辑。"""

    def test_reads_from_addfields_fixed_value(self):
        entity = make_entity(addfields={EVENT_NAME_FIELD: "终端告警"})
        self.assertEqual(read_entity_event_name(entity), "终端告警")

    def test_reads_from_normalize_fallback(self):
        entity = make_entity(normalize=[norm_entry(EVENT_NAME_FIELD, ["登录事件"])])
        self.assertEqual(read_entity_event_name(entity), "登录事件")

    def test_addfields_takes_priority_over_normalize(self):
        entity = make_entity(
            addfields={EVENT_NAME_FIELD: "网络攻击"},
            normalize=[norm_entry(EVENT_NAME_FIELD, ["登录事件"])],
        )
        self.assertEqual(read_entity_event_name(entity), "网络攻击")

    def test_invalid_addfields_value_falls_back_to_normalize(self):
        entity = make_entity(
            addfields={EVENT_NAME_FIELD: "自造分类"},
            normalize=[norm_entry(EVENT_NAME_FIELD, ["dns查询"])],
        )
        self.assertEqual(read_entity_event_name(entity), "dns查询")

    def test_unannotated_entity_returns_none(self):
        self.assertIsNone(read_entity_event_name(make_entity()))

    def test_value_outside_binding_table_returns_none(self):
        entity = make_entity(normalize=[norm_entry(EVENT_NAME_FIELD, ["不存在的分类"])])
        self.assertIsNone(read_entity_event_name(entity))


if __name__ == "__main__":
    unittest.main()
