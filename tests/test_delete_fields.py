"""delete_fields 单元与端到端测试。

覆盖 delete_field 核心行为、删除守卫链与文件契约端到端。
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SKILLS / "field-adjust" / "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import delete_fields  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from field_adjust_helpers import make_entity, norm_entry  # noqa: E402


class DeleteFieldCoreTest(unittest.TestCase):
    """delete_field() 纯函数核心行为。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_a",
                normalize=[
                    norm_entry("src_ip", ["10.0.0.1"]),
                    norm_entry("主机ip", ["1.1.1.1"]),
                ],
                filters=[
                    {
                        "name": "addFields",
                        "id": "",
                        "fields": {"主机ip": "1.1.1.1", "备注": "x"},
                    }
                ],
            ),
            make_entity(
                "rule_b",
                normalize=[
                    norm_entry("src_ip", ["1.2.3.4"]),
                    norm_entry("dst_ip", ["2.3.4.5"]),
                ],
            ),
            make_entity("rule_empty"),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result["data"]

    def test_deletes_normalize_entry_and_writes_removefields(self):
        updated = self._ok(delete_fields.delete_field(self.data, ["主机ip"]))
        rule_a = updated[0]
        indexes = [e["index"] for e in rule_a["normalize"]]
        self.assertNotIn("主机ip", indexes)
        self.assertIn("src_ip", indexes)
        remove_filter = rule_a["parser"]["filter"][-1]
        self.assertEqual(remove_filter["name"], "removeFields")
        self.assertEqual(remove_filter["id"], "")
        self.assertEqual(remove_filter["fields"], ["主机ip"])

    def test_multiple_fields_across_entities(self):
        result = delete_fields.delete_field(self.data, ["src_ip", "dst_ip"])
        self.assertIn("成功从 2 个 entity 删除 3 个字段", result["message"])
        updated = result["data"]
        self.assertNotIn(
            "src_ip", [e["index"] for e in updated[0]["normalize"]]
        )
        self.assertNotIn(
            "src_ip", [e["index"] for e in updated[1]["normalize"]]
        )
        self.assertNotIn(
            "dst_ip", [e["index"] for e in updated[1]["normalize"]]
        )

    def test_addfields_binding_cleaned_partially(self):
        updated = self._ok(delete_fields.delete_field(self.data, ["主机ip"]))
        kept = [
            f for f in updated[0]["parser"]["filter"]
            if f.get("name") == "addFields" and f.get("id") == ""
        ]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["fields"], {"备注": "x"})

    def test_addfields_filter_removed_when_emptied(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("主机ip", ["1.1.1.1"])],
                filters=[
                    {"name": "addFields", "id": "", "fields": {"主机ip": "1.1.1.1"}},
                ],
            )
        ]
        updated = self._ok(delete_fields.delete_field(data, ["主机ip"]))
        names = [f.get("name") for f in updated[0]["parser"]["filter"]]
        self.assertNotIn("addFields", names)
        self.assertIn("removeFields", names)

    def test_merges_into_existing_removefields(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("src_ip", ["1"])],
                filters=[
                    {"name": "removeFields", "id": "", "fields": ["旧字段"]},
                ],
            )
        ]
        updated = self._ok(delete_fields.delete_field(data, ["src_ip"]))
        remove_filter = updated[0]["parser"]["filter"][0]
        self.assertEqual(remove_filter["fields"], ["旧字段", "src_ip"])

    def test_merges_into_existing_removefields_with_null_fields(self):
        # 已有 removeFields 过滤器的 fields 键为 null：视作空列表合并
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("src_ip", ["1"])],
                filters=[
                    {"name": "removeFields", "id": "", "fields": None},
                ],
            )
        ]
        updated = self._ok(delete_fields.delete_field(data, ["src_ip"]))
        remove_filter = updated[0]["parser"]["filter"][0]
        self.assertEqual(remove_filter["fields"], ["src_ip"])

    def test_missing_field_success_with_not_found(self):
        result = delete_fields.delete_field(self.data, ["不存在"])
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["not_found"], ["不存在"])
        self.assertIn("未找到字段: 不存在（不存在于任何子规则）", result["message"])
        # 字段在任何子规则都没有时不计入删除数
        self.assertIn("成功从 0 个 entity 删除 0 个字段", result["message"])

    def test_target_scope_and_passthrough(self):
        result = delete_fields.delete_field(self.data, ["src_ip"], ["rule_a"])
        self.assertIn("目标 1 个", result["message"])
        updated = result["data"]
        self.assertNotIn("src_ip", [e["index"] for e in updated[0]["normalize"]])
        # 名单外 entity 原样透传
        self.assertIn("src_ip", [e["index"] for e in updated[1]["normalize"]])
        self.assertEqual(len(updated[1]["normalize"]), 2)

    def test_entity_without_normalize_skipped_and_counted(self):
        result = delete_fields.delete_field(self.data, ["src_ip"])
        self.assertIn("跳过 1 个无 normalize 的 entity", result["message"])
        self.assertEqual(result["data"][2]["normalize"], [])

    def test_null_filter_initialized(self):
        data = [make_entity("rule_b", normalize=[norm_entry("src_ip", ["1"])])]
        updated = self._ok(delete_fields.delete_field(data, ["src_ip"]))
        self.assertEqual(
            [f["name"] for f in updated[0]["parser"]["filter"]], ["removeFields"]
        )

    def test_input_not_mutated(self):
        snapshot = json.dumps(self.data, ensure_ascii=False)
        delete_fields.delete_field(self.data, ["主机ip", "src_ip"])
        self.assertEqual(json.dumps(self.data, ensure_ascii=False), snapshot)

    def test_empty_data_error(self):
        result = delete_fields.delete_field([], ["x"])
        self.assertEqual(result["status"], "error")

    def test_empty_fields_error(self):
        result = delete_fields.delete_field(self.data, [])
        self.assertEqual(result["status"], "error")

    def test_reserved_field_rejected(self):
        result = delete_fields.delete_field(self.data, ["original_log"])
        self.assertEqual(result["status"], "error")
        self.assertIn("系统保留字段", result["message"])


class DeleteFieldGuardedTest(unittest.TestCase):
    """delete_field_guarded() 守卫链：寻址、保留字段、绑定对联动、悬空引用。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_threat",
                normalize=[
                    norm_entry("src_ip", ["1"]),
                    norm_entry(EVENT_NAME_FIELD, ["终端告警"]),
                    norm_entry(EVENT_LEVEL_FIELD, ["提醒"]),
                ],
            ),
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("dst_ip", ["2"]),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            ),
            make_entity("rule_plain", normalize=[norm_entry("src_ip", ["3"])]),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result

    def test_delete_event_name_expands_binding_pair(self):
        result = self._ok(delete_fields.delete_field_guarded(self.data, [EVENT_NAME_FIELD]))
        self.assertIn("已联动删除绑定对（事件名称+事件级别）", result["message"])
        rule = result["data"][0]
        indexes = [e["index"] for e in rule["normalize"]]
        self.assertNotIn(EVENT_NAME_FIELD, indexes)
        self.assertNotIn(EVENT_LEVEL_FIELD, indexes)
        remove_filter = rule["parser"]["filter"][-1]
        self.assertEqual(remove_filter["fields"], [EVENT_NAME_FIELD, EVENT_LEVEL_FIELD])

    def test_delete_event_level_expands_binding_pair(self):
        result = self._ok(delete_fields.delete_field_guarded(self.data, [EVENT_LEVEL_FIELD]))
        self.assertIn("已联动删除绑定对（事件名称+事件级别）", result["message"])
        indexes = [e["index"] for e in result["data"][0]["normalize"]]
        self.assertNotIn(EVENT_NAME_FIELD, indexes)
        self.assertNotIn(EVENT_LEVEL_FIELD, indexes)

    def test_merger_dangling_reference_rejected(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])],
                filters=[{"name": "merger", "id": "", "fields": ["a", "b"]}],
            )
        ]
        result = delete_fields.delete_field_guarded(data, ["a"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "field_reference_conflict")
        self.assertIn("请先解除引用再删除", result["message"])
        self.assertIn("rule_a: merger 源字段引用 ['a']", result["message"])

    def test_placeholder_dangling_reference_rejected(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("a", ["1"])],
                filters=[
                    {"name": "addFields", "id": "", "fields": {"汇总": "%{a}"}},
                ],
            )
        ]
        result = delete_fields.delete_field_guarded(data, ["a"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "field_reference_conflict")
        self.assertIn("rule_a: %{a} 引用", result["message"])

    def test_dangling_check_scoped_to_targets(self):
        data = [
            make_entity("rule_a", normalize=[norm_entry("a", ["1"])]),
            make_entity(
                "rule_b",
                normalize=[norm_entry("a", ["2"])],
                filters=[{"name": "merger", "id": "", "fields": ["a"]}],
            ),
        ]
        # 引用在名单外的 rule_b：目标 rule_a 的删除不受影响
        result = self._ok(
            delete_fields.delete_field_guarded(data, ["a"], target_names=["rule_a"])
        )
        self.assertNotIn("a", [e["index"] for e in result["data"][0]["normalize"]])

    def test_group_threat_selects_annotated_threat_only(self):
        result = self._ok(
            delete_fields.delete_field_guarded(self.data, ["src_ip"], group="threat")
        )
        self.assertIn("目标 1 个", result["message"])
        # 威胁组 rule_threat 被删，未标注的 rule_plain 原样透传
        self.assertNotIn("src_ip", [e["index"] for e in result["data"][0]["normalize"]])
        self.assertIn("src_ip", [e["index"] for e in result["data"][2]["normalize"]])

    def test_group_non_threat_selects_annotated_non_threat_only(self):
        result = self._ok(
            delete_fields.delete_field_guarded(self.data, ["dst_ip"], group="non-threat")
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertNotIn("dst_ip", [e["index"] for e in result["data"][1]["normalize"]])

    def test_group_without_annotation_reports_event_annotation_required(self):
        data = [make_entity("rule_a", normalize=[norm_entry("src_ip", ["1"])])]
        result = delete_fields.delete_field_guarded(data, ["src_ip"], group="threat")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "event_annotation_required")
        self.assertIn("添加字段", result["message"])
        self.assertIn(EVENT_NAME_FIELD, result["message"])

    def test_group_without_match_reports_rule_name_not_found(self):
        # 只有非威胁标注，选威胁组 → 组内无匹配
        data = [
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("src_ip", ["1"]),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            )
        ]
        result = delete_fields.delete_field_guarded(data, ["src_ip"], group="threat")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("没有属于威胁组的子规则", result["message"])

    def test_target_unknown_name_rejected(self):
        result = delete_fields.delete_field_guarded(
            self.data, ["src_ip"], target_names=["rule_z"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("未找到子规则: rule_z", result["message"])
        self.assertIn("可用子规则: rule_threat、rule_normal、rule_plain", result["message"])

    def test_target_takes_precedence_over_group(self):
        # target 指向威胁组规则而 group 选非威胁组：target 优先
        result = self._ok(
            delete_fields.delete_field_guarded(
                self.data, ["src_ip"], target_names=["rule_threat"], group="non-threat"
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertNotIn("src_ip", [e["index"] for e in result["data"][0]["normalize"]])

    def test_reserved_field_rejected_with_code(self):
        result = delete_fields.delete_field_guarded(self.data, ["original_log"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "reserved_field_rejected")
        self.assertIn("系统保留字段", result["message"])

    def test_empty_data_invalid_input(self):
        result = delete_fields.delete_field_guarded([], ["x"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_empty_fields_invalid_input(self):
        result = delete_fields.delete_field_guarded(self.data, [])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_not_found_reported_once(self):
        result = self._ok(delete_fields.delete_field_guarded(self.data, ["不存在字段"]))
        self.assertEqual(result["message"].count("未找到字段"), 1)


class CliEndToEndTest(unittest.TestCase):
    """文件契约端到端：Base64 输入 → 修改后 JSON + 平台可导入 Base64 输出。

    以进程内调用 main() + stdout 重定向实现，避免子进程管道
    （受限环境下 EPERM），任何环境可跑；真实 CLI 演示见 SKILL.md。
    """

    FIXTURE = ROOT / "testdata" / "sample_config.json"

    def setUp(self):
        (ROOT / ".tmp_tests").mkdir(exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(dir=str(ROOT / ".tmp_tests")))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)
        tmp_root = ROOT / ".tmp_tests"
        if tmp_root.is_dir() and not any(tmp_root.iterdir()):
            tmp_root.rmdir()

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = delete_fields.main([*argv])
        return code, buf.getvalue()

    def test_e2e_delete_field_on_base64_input(self):
        payload = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        b64_file = self._tmp / "config.b64.txt"
        b64_file.write_text(
            base64.b64encode(
                json.dumps(payload, ensure_ascii=False).encode("utf-8")
            ).decode("ascii"),
            encoding="utf-8",
        )
        output = self._tmp / "out_modified.json"
        code, stdout = self._run(
            "--input", str(b64_file),
            "--fields", "src_ip",
            "--output", str(output),
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "success")
        self.assertIn("成功从 1 个 entity 删除 1 个字段", report["message"])
        self.assertIn("跳过 1 个无 normalize", report["message"])
        # 修改后 JSON：src_ip 条目消失，removeFields 写入
        updated = json.loads(output.read_text(encoding="utf-8"))
        self.assertNotIn("src_ip", [e["index"] for e in updated[0]["normalize"]])
        self.assertEqual(updated[0]["parser"]["filter"][-1]["name"], "removeFields")
        # 平台可导入 Base64 导出文件
        export = Path(report["export"])
        self.assertTrue(export.exists())
        self.assertRegex(export.name, r"^fieldadjusted_config_\d{8}_\d{4}\.txt$")
        decoded = json.loads(base64.b64decode(export.read_text(encoding="utf-8")))
        self.assertEqual(decoded, updated)

    def test_e2e_reserved_field_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--fields", "original_log",
            "--output", str(self._tmp / "o.json"),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "reserved_field_rejected")

    def test_e2e_unknown_target_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--fields", "src_ip",
            "--target", "不存在的规则",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "rule_name_not_found")

    def test_e2e_missing_input_reports_config_required(self):
        code, stdout = self._run(
            "--input", str(self._tmp / "nope.txt"), "--fields", "x"
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "config_required")


if __name__ == "__main__":
    unittest.main()
