"""merge_fields 单元与端到端测试。

覆盖 merge_field 核心行为、合并守卫链与文件契约端到端。
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

import merge_fields  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from field_adjust_helpers import make_entity, norm_entry  # noqa: E402


class MergeFieldCoreTest(unittest.TestCase):
    """merge_field() 纯函数核心行为。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_a",
                normalize=[
                    norm_entry("a", ["1"]),
                    norm_entry("b", ["2"]),
                ],
            ),
            make_entity(
                "rule_b",
                normalize=[
                    norm_entry("a", ["x"]),
                ],
            ),
            make_entity("rule_empty"),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result["data"]

    def test_merges_two_fields_into_new_field(self):
        updated = self._ok(merge_fields.merge_field(self.data, ["a", "b"], "c", "-"))
        rule_a = updated[0]
        merger = rule_a["parser"]["filter"][-1]
        self.assertEqual(merger["name"], "merger")
        self.assertEqual(merger["field"], "c")
        self.assertEqual(merger["sep"], "-")
        self.assertEqual(merger["id"], "")
        self.assertEqual(merger["fields"], ["a", "b"])
        preview = rule_a["normalize"][-1]
        self.assertEqual(preview["index"], "c")
        self.assertEqual(preview["result"], ["1-2"])
        self.assertEqual(preview["mappings"], [])
        # 源字段条目保留（merger 运行时依赖源字段）
        indexes = [e["index"] for e in rule_a["normalize"]]
        self.assertIn("a", indexes)
        self.assertIn("b", indexes)

    def test_sep_defaults_to_empty_string(self):
        updated = self._ok(merge_fields.merge_field(self.data, ["a", "b"], "c"))
        merger = updated[0]["parser"]["filter"][-1]
        self.assertEqual(merger["sep"], "")
        self.assertEqual(updated[0]["normalize"][-1]["result"], ["12"])

    def test_missing_source_skips_entity_and_reports(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "c")
        self.assertEqual(result["status"], "success")
        self.assertIn("成功合并 1 个 entity", result["message"])
        self.assertIn("rule_b（缺 b）", result["message"])
        # 缺源的 rule_b 原样保留，未写入 merger
        self.assertEqual(result["data"][1]["parser"]["filter"], None)

    def test_target_exists_skips_entity_and_reports(self):
        data = [
            make_entity("rule_a", normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])]),
            make_entity(
                "rule_c",
                normalize=[norm_entry("a", ["3"]), norm_entry("b", ["4"]), norm_entry("c", ["旧"])],
            ),
        ]
        result = merge_fields.merge_field(data, ["a", "b"], "c")
        self.assertEqual(result["status"], "success")
        self.assertIn("rule_c（目标 'c' 已存在）", result["message"])
        self.assertIn("成功合并 1 个 entity", result["message"])
        self.assertEqual(result["data"][1]["normalize"][-1]["result"], ["旧"])

    def test_all_missing_source_reports_field_not_found(self):
        result = merge_fields.merge_field(self.data, ["a", "z"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "field_not_found")
        # 只点名真正缺失的源字段（a 在子规则里存在，不背锅）
        self.assertIn("源字段 z 不存在", result["message"])
        # 消息附全部子规则字段并集预览，帮助定位名字错误
        self.assertIn("并集", result["message"])
        self.assertIn("a", result["message"])
        self.assertIn("b", result["message"])

    def test_existing_merger_for_target_updated_in_place(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])],
                filters=[
                    {"name": "addFields", "id": "", "fields": {"x": "1"}},
                    {"name": "merger", "id": "", "field": "c", "sep": "+", "fields": ["x", "y"]},
                ],
            )
        ]
        updated = self._ok(merge_fields.merge_field(data, ["a", "b"], "c", "-"))
        filters = updated[0]["parser"]["filter"]
        self.assertEqual(len(filters), 2)
        merger = filters[1]
        self.assertEqual(merger["fields"], ["a", "b"])
        self.assertEqual(merger["sep"], "-")

    def test_null_filter_initialized(self):
        data = [
            make_entity("rule_a", normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])]),
        ]
        updated = self._ok(merge_fields.merge_field(data, ["a", "b"], "c"))
        self.assertEqual(
            [f["name"] for f in updated[0]["parser"]["filter"]], ["merger"]
        )

    def test_target_scope_and_passthrough(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "c", "", ["rule_a"])
        self.assertIn("目标 1 个", result["message"])
        updated = result["data"]
        self.assertEqual(updated[0]["parser"]["filter"][-1]["name"], "merger")
        # 名单外 entity 原样透传
        self.assertEqual(updated[1]["parser"]["filter"], None)

    def test_entity_without_normalize_skipped_and_counted(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "c")
        self.assertIn("跳过 1 个无 normalize 的 entity", result["message"])
        self.assertEqual(result["data"][2]["normalize"], [])

    def test_input_not_mutated(self):
        snapshot = json.dumps(self.data, ensure_ascii=False)
        merge_fields.merge_field(self.data, ["a", "b"], "c", "-")
        self.assertEqual(json.dumps(self.data, ensure_ascii=False), snapshot)

    def test_empty_data_error(self):
        result = merge_fields.merge_field([], ["a", "b"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_fewer_than_two_sources_error(self):
        result = merge_fields.merge_field(self.data, ["a"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("至少需要 2 个源字段", result["message"])

    def test_empty_target_field_error(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")


class MergeFieldGuardedTest(unittest.TestCase):
    """merge_field_guarded() 守卫链：寻址、保留字段、事件字段、自引用。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_threat",
                normalize=[
                    norm_entry("a", ["1"]),
                    norm_entry("b", ["2"]),
                    norm_entry(EVENT_NAME_FIELD, ["终端告警"]),
                    norm_entry(EVENT_LEVEL_FIELD, ["提醒"]),
                ],
            ),
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("a", ["x"]),
                    norm_entry("b", ["y"]),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            ),
            make_entity("rule_plain", normalize=[norm_entry("a", ["3"])]),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result

    def test_guarded_merge_applies_to_all(self):
        result = self._ok(
            merge_fields.merge_field_guarded(self.data, ["a", "b"], "c", "-")
        )
        for rule in result["data"][:2]:
            self.assertEqual(rule["parser"]["filter"][-1]["name"], "merger")
        # rule_plain 缺 b，跳过并报告
        self.assertIn("rule_plain（缺 b）", result["message"])

    def test_reserved_target_rejected(self):
        for reserved in ("original_log", "rule_name_list", "日志类型"):
            result = merge_fields.merge_field_guarded(self.data, ["a", "b"], reserved)
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["code"], "reserved_field_rejected")
            self.assertIn("系统保留字段", result["message"])

    def test_event_name_target_rejected(self):
        result = merge_fields.merge_field_guarded(self.data, ["a", "b"], EVENT_NAME_FIELD)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_event_name")
        self.assertIn("添加字段", result["message"])

    def test_event_level_target_rejected(self):
        result = merge_fields.merge_field_guarded(self.data, ["a", "b"], EVENT_LEVEL_FIELD)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_event_name")
        self.assertIn("添加字段", result["message"])

    def test_self_reference_rejected(self):
        result = merge_fields.merge_field_guarded(self.data, ["a", "b"], "a")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("自引用", result["message"])

    def test_empty_data_invalid_input(self):
        result = merge_fields.merge_field_guarded([], ["a", "b"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_fewer_than_two_sources_invalid_input(self):
        result = merge_fields.merge_field_guarded(self.data, ["a"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_empty_sources_invalid_input(self):
        result = merge_fields.merge_field_guarded(self.data, [], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_empty_target_field_invalid_input(self):
        result = merge_fields.merge_field_guarded(self.data, ["a", "b"], "")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_unknown_target_rejected(self):
        result = merge_fields.merge_field_guarded(
            self.data, ["a", "b"], "c", target_names=["rule_z"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("未找到子规则: rule_z", result["message"])
        self.assertIn(
            "可用子规则: rule_threat、rule_normal、rule_plain", result["message"]
        )

    def test_group_threat_selects_annotated_threat_only(self):
        result = self._ok(
            merge_fields.merge_field_guarded(
                self.data, ["a", "b"], "c", group="threat"
            )
        )
        self.assertIn("目标 1 个", result["message"])
        # 威胁组 rule_threat 合并，未标注的 rule_plain 原样透传
        self.assertEqual(result["data"][0]["parser"]["filter"][-1]["name"], "merger")
        self.assertEqual(result["data"][2]["parser"]["filter"], None)

    def test_group_non_threat_selects_annotated_non_threat_only(self):
        result = self._ok(
            merge_fields.merge_field_guarded(
                self.data, ["a", "b"], "c", group="non-threat"
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(result["data"][1]["parser"]["filter"][-1]["name"], "merger")
        self.assertEqual(result["data"][0]["parser"]["filter"], None)

    def test_group_without_annotation_reports_event_annotation_required(self):
        data = [make_entity("rule_a", normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])])]
        result = merge_fields.merge_field_guarded(data, ["a", "b"], "c", group="threat")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "event_annotation_required")
        self.assertIn("添加字段", result["message"])

    def test_group_without_match_reports_rule_name_not_found(self):
        data = [
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("a", ["1"]),
                    norm_entry("b", ["2"]),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            )
        ]
        result = merge_fields.merge_field_guarded(data, ["a", "b"], "c", group="threat")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("没有属于威胁组的子规则", result["message"])

    def test_target_takes_precedence_over_group(self):
        # target 指向威胁组规则而 group 选非威胁组：target 优先
        result = self._ok(
            merge_fields.merge_field_guarded(
                self.data, ["a", "b"], "c", target_names=["rule_threat"],
                group="non-threat",
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(result["data"][0]["parser"]["filter"][-1]["name"], "merger")


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
            code = merge_fields.main([*argv])
        return code, buf.getvalue()

    def test_e2e_merge_on_base64_input(self):
        payload = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        b64_file = self._tmp / "config.b64.txt"
        b64_file.write_text(
            base64.b64encode(
                json.dumps(payload, ensure_ascii=False).encode("utf-8")
            ).decode("ascii"),
            encoding="utf-8",
        )
        output = self._tmp / "out.modified.json"
        code, stdout = self._run(
            "--input", str(b64_file),
            "--sources", "src_ip,original_log",
            "--target-field", "合并字段",
            "--sep", "-",
            "--output", str(output),
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "success")
        self.assertIn("成功合并 1 个 entity 的字段为 '合并字段'", report["message"])
        # 缺 src_ip 的 IPS 子规则按名报告跳过
        self.assertIn("某厂_IPS_json_子规则（缺 src_ip）", report["message"])
        # 修改后 JSON：AUDIT 子规则写入 merger 与 normalize 预览条目
        updated = json.loads(output.read_text(encoding="utf-8"))
        merger = updated[0]["parser"]["filter"][-1]
        self.assertEqual(merger["name"], "merger")
        self.assertEqual(merger["field"], "合并字段")
        self.assertEqual(merger["sep"], "-")
        self.assertEqual(merger["fields"], ["src_ip", "original_log"])
        preview = updated[0]["normalize"][-1]
        self.assertEqual(preview["index"], "合并字段")
        original_log_preview = next(
            e["result"][0] for e in updated[0]["normalize"] if e["index"] == "original_log"
        )
        self.assertEqual(preview["result"], ["10.1.1.5-" + original_log_preview])
        # 平台可导入 Base64 导出文件
        export = Path(report["export"])
        self.assertTrue(export.exists())
        self.assertRegex(export.name, r"^fieldadjusted_config_\d{8}_\d{4}\.txt$")
        decoded = json.loads(base64.b64decode(export.read_text(encoding="utf-8")))
        self.assertEqual(decoded, updated)

    def test_e2e_reserved_target_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--sources", "src_ip,original_log",
            "--target-field", "original_log",
            "--output", str(self._tmp / "o.json"),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "reserved_field_rejected")

    def test_e2e_field_not_found_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--sources", "src_ip,不存在字段",
            "--target-field", "合并字段",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "field_not_found")
        self.assertIn("并集", report["message"])

    def test_e2e_unknown_target_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--sources", "src_ip,original_log",
            "--target-field", "合并字段",
            "--target", "不存在的规则",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "rule_name_not_found")

    def test_e2e_missing_input_reports_config_required(self):
        code, stdout = self._run(
            "--input", str(self._tmp / "nope.txt"),
            "--sources", "a,b",
            "--target-field", "c",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "config_required")


if __name__ == "__main__":
    unittest.main()
