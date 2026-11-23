"""add_fields 单元与端到端测试。

覆盖 add_field 核心行为、事件名称绑定守卫与文件契约端到端。
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

import add_fields  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from field_adjust_helpers import make_entity, norm_entry  # noqa: E402


class AddFieldCoreTest(unittest.TestCase):
    """add_field() 纯函数核心行为。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("src_ip", ["10.0.0.1"])],
                filters=[
                    {
                        "name": "addFields",
                        "id": "additional_fields_filter",
                        "fields": {"product": ""},
                    }
                ],
            ),
            make_entity("rule_b", normalize=[norm_entry("dst_ip", ["1.2.3.4"])]),
            make_entity("rule_empty"),
        ]

    def _added(self, result):
        self.assertEqual(result["status"], "success")
        return result["data"]

    def test_adds_normalize_entry_and_addfields_filter(self):
        updated = self._added(add_fields.add_field(self.data, "主机ip", "1.1.1.1"))
        rule_a = updated[0]
        new_entry = rule_a["normalize"][-1]
        self.assertEqual(new_entry["index"], "主机ip")
        self.assertEqual(new_entry["result"], ["1.1.1.1"])
        added_filter = rule_a["parser"]["filter"][-1]
        self.assertEqual(added_filter["name"], "addFields")
        self.assertEqual(added_filter["id"], "")
        self.assertEqual(added_filter["fields"], {"主机ip": "1.1.1.1"})
        # 系统保留的 additional_fields_filter 保持在最前
        self.assertEqual(rule_a["parser"]["filter"][0]["id"], "additional_fields_filter")

    def test_empty_value_gives_empty_result(self):
        updated = self._added(add_fields.add_field(self.data, "备注"))
        self.assertEqual(updated[0]["normalize"][-1]["result"], [])
        self.assertEqual(updated[0]["parser"]["filter"][-1]["fields"], {"备注": ""})

    def test_reference_value_kept_verbatim(self):
        updated = self._added(add_fields.add_field(self.data, "请求头", "%{reqheader}"))
        self.assertEqual(updated[0]["normalize"][-1]["result"], ["%{reqheader}"])
        self.assertEqual(
            updated[0]["parser"]["filter"][-1]["fields"], {"请求头": "%{reqheader}"}
        )

    def test_field_conflict_without_skip(self):
        result = add_fields.add_field(self.data, "src_ip", "x")
        self.assertEqual(result["status"], "error")
        self.assertIn("已存在", result["message"])

    def test_skip_existing_skips_and_counts(self):
        result = add_fields.add_field(self.data, "src_ip", "x", skip_existing=True)
        self.assertEqual(result["status"], "success")
        self.assertIn("已存在该字段，跳过", result["message"])
        # rule_a 原样保留，rule_b 正常添加
        self.assertEqual(result["data"][0]["normalize"][-1]["index"], "src_ip")
        self.assertEqual(result["data"][1]["normalize"][-1]["index"], "src_ip")

    def test_entity_without_normalize_skipped_and_counted(self):
        result = add_fields.add_field(self.data, "主机ip", "1.1.1.1")
        self.assertIn("跳过 1 个无 normalize 的 entity", result["message"])
        # 空规则未被修改
        self.assertEqual(result["data"][2]["normalize"], [])

    def test_target_names_filter_scope(self):
        result = add_fields.add_field(
            self.data, "主机ip", "1.1.1.1", target_names=["rule_a"]
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(result["data"][0]["normalize"][-1]["index"], "主机ip")
        # 名单外 entity 原样透传
        self.assertEqual(result["data"][1]["normalize"][0]["index"], "dst_ip")
        self.assertEqual(len(result["data"][1]["normalize"]), 1)

    def test_removefields_marker_for_same_field_revoked(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("src_ip", ["1"])],
                filters=[
                    {"name": "removeFields", "id": "", "fields": ["主机ip", "旧字段"]},
                ],
            )
        ]
        updated = self._added(add_fields.add_field(data, "主机ip", "1.1.1.1"))
        remove_filter = updated[0]["parser"]["filter"][0]
        self.assertEqual(remove_filter["fields"], ["旧字段"])

    def test_input_not_mutated(self):
        snapshot = json.dumps(self.data, ensure_ascii=False)
        add_fields.add_field(self.data, "主机ip", "1.1.1.1")
        self.assertEqual(json.dumps(self.data, ensure_ascii=False), snapshot)

    def test_empty_data_error(self):
        result = add_fields.add_field([], "x")
        self.assertEqual(result["status"], "error")

    def test_empty_field_name_error(self):
        result = add_fields.add_field(self.data, "")
        self.assertEqual(result["status"], "error")


class EventNameGuardTest(unittest.TestCase):
    """事件名称绑定守卫。"""

    def setUp(self):
        self.data = [make_entity("rule_a", normalize=[norm_entry("src_ip", ["1"])])]

    def _last_filter(self, entity) -> dict:
        return entity["parser"]["filter"][-1]

    def test_valid_event_name_links_level(self):
        result = add_fields.add_field_guarded(self.data, "事件名称", "终端告警")
        self.assertEqual(result["status"], "success")
        self.assertIn("联动写入【事件级别】=提醒", result["message"])
        rule = result["data"][0]
        indexes = [e["index"] for e in rule["normalize"]]
        self.assertIn(EVENT_NAME_FIELD, indexes)
        self.assertIn(EVENT_LEVEL_FIELD, indexes)
        # 标准元数据
        name_entry = next(e for e in rule["normalize"] if e["index"] == EVENT_NAME_FIELD)
        self.assertEqual(name_entry["field"], "event_name")
        self.assertEqual(name_entry["entity"], "事件")
        self.assertEqual(name_entry["value"], "终端告警")
        level_entry = next(e for e in rule["normalize"] if e["index"] == EVENT_LEVEL_FIELD)
        self.assertEqual(level_entry["field"], "event_level")
        self.assertEqual(level_entry["value"], "1")  # 提醒 → 码值 1
        # addFields filter 承载两字段（名称/级别各一个 filter）
        added_fields = {}
        for f in rule["parser"]["filter"]:
            if f.get("name") == "addFields" and f.get("id") == "":
                added_fields.update(f.get("fields", {}))
        self.assertEqual(added_fields, {EVENT_NAME_FIELD: "终端告警", EVENT_LEVEL_FIELD: "提醒"})

    def test_non_threat_name_binds_info_level(self):
        result = add_fields.add_field_guarded(self.data, "事件名称", "登录事件")
        self.assertIn("【事件级别】=信息", result["message"])

    def test_invalid_event_name_rejected(self):
        result = add_fields.add_field_guarded(self.data, "事件名称", "不存在的分类")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_event_name")

    def test_reference_event_name_rejected(self):
        result = add_fields.add_field_guarded(self.data, "事件名称", "%{src_ip}")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_event_name")

    def test_existing_level_conflict(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("src_ip", ["1"])],
                filters=[
                    {
                        "name": "addFields",
                        "id": "",
                        "fields": {EVENT_LEVEL_FIELD: "提醒"},
                    }
                ],
            )
        ]
        result = add_fields.add_field_guarded(data, "事件名称", "网络攻击")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "event_level_conflict")

    def test_skip_existing_bypasses_conflict_check(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[
                    norm_entry("src_ip", ["1"]),
                    norm_entry(EVENT_NAME_FIELD, ["终端告警"], field="event_name"),
                ],
            )
        ]
        result = add_fields.add_field_guarded(
            data, "事件名称", "网络攻击", skip_existing=True
        )
        self.assertEqual(result["status"], "success")
        self.assertIn("已存在该字段，跳过", result["message"])

    def test_direct_level_add_rejected(self):
        result = add_fields.add_field_guarded(self.data, "事件级别", "提醒")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "event_level_direct_add_rejected")

    def test_plain_field_gets_field_conflict_code(self):
        data = [make_entity("rule_a", normalize=[norm_entry("src_ip", ["1"])])]
        result = add_fields.add_field_guarded(data, "src_ip", "x")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "field_conflict")


class TargetScopeGuardTest(unittest.TestCase):
    """target 寻址校验（未知名拒绝，与 delete 等子命令行为一致）。"""

    def setUp(self):
        self.data = [
            make_entity("rule_a", normalize=[norm_entry("src_ip", ["1"])]),
            make_entity("rule_b", normalize=[norm_entry("dst_ip", ["2"])]),
        ]

    def test_unknown_target_rejected_with_available_hint(self):
        result = add_fields.add_field_guarded(
            self.data, "主机ip", "1.1.1.1", target_names=["不存在的规则"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("未找到子规则: 不存在的规则", result["message"])
        self.assertIn("可用子规则: rule_a、rule_b", result["message"])

    def test_mixed_target_with_unknown_name_still_rejected(self):
        result = add_fields.add_field_guarded(
            self.data, "主机ip", "1.1.1.1", target_names=["rule_a", "打错的规则"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("打错的规则", result["message"])

    def test_known_target_still_applies(self):
        result = add_fields.add_field_guarded(
            self.data, "主机ip", "1.1.1.1", target_names=["rule_a"]
        )
        self.assertEqual(result["status"], "success")
        self.assertIn("目标 1 个", result["message"])
        # 名单外 entity 原样透传
        self.assertEqual(result["data"][1]["normalize"][0]["index"], "dst_ip")
        self.assertEqual(len(result["data"][1]["normalize"]), 1)

    def test_scope_check_precedes_event_field_guards(self):
        # 寻址校验先于事件字段拦截报错（#12 裁决；空校验层不涉足，
        # 见 ValidateArgsGuardTest）
        result = add_fields.add_field_guarded(
            self.data, "事件级别", "提醒", target_names=["不存在的规则"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")


    def test_event_name_path_also_validates_targets(self):
        result = add_fields.add_field_guarded(
            self.data, "事件名称", "终端告警", target_names=["不存在的规则"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")


class ValidateArgsGuardTest(unittest.TestCase):
    """空校验层（#13 欠账 2：对齐其余四子命令的 _validate_*_args 结构）。

    三个边缘组合的裁决见 #13 票面：空数据 / 空字段名先于寻址解析与
    事件字段守卫报 invalid_input。
    """

    def setUp(self):
        self.data = [make_entity("rule_a", normalize=[norm_entry("src_ip", ["1"])])]

    def test_empty_data_reports_invalid_input(self):
        result = add_fields.add_field_guarded([], "主机ip", "1.1.1.1")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("输入数据为空", result["message"])

    def test_empty_field_name_reports_invalid_input(self):
        result = add_fields.add_field_guarded(self.data, "", "x")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("字段名不能为空", result["message"])

    def test_empty_data_precedes_scope_resolution(self):
        result = add_fields.add_field_guarded(
            [], "主机ip", "1.1.1.1", target_names=["不存在的规则"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("输入数据为空", result["message"])

    def test_empty_field_name_precedes_scope_resolution(self):
        result = add_fields.add_field_guarded(
            self.data, "", "x", target_names=["不存在的规则"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("字段名不能为空", result["message"])

    def test_empty_data_precedes_event_name_guard(self):
        result = add_fields.add_field_guarded([], "事件名称", "不存在的分类")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("输入数据为空", result["message"])

    def test_empty_data_precedes_event_level_direct_add_guard(self):
        # 「空数据+直接添加事件级别」原报 event_level_direct_add_rejected，
        # 空校验层置最前后归位 invalid_input（#13 票面补记）
        result = add_fields.add_field_guarded([], "事件级别", "提醒")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("输入数据为空", result["message"])

    def test_empty_data_precedes_reference_event_name_guard(self):
        # 「空数据+引用型事件名称」原报 invalid_event_name，同上归位
        result = add_fields.add_field_guarded([], "事件名称", "%{src_ip}")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("输入数据为空", result["message"])


class CliEndToEndTest(unittest.TestCase):
    """文件契约端到端：Base64 输入 → 修改后 JSON + 平台可导入 Base64 输出。

    以进程内调用 main() + stdout 重定向实现，避免子进程管道
    （受限环境下 EPERM），任何环境可跑；真实 CLI 演示见 SKILL.md。
    """

    FIXTURE = ROOT / "testdata" / "sample_config.json"

    def setUp(self):
        (ROOT / ".tmp_tests").mkdir(exist_ok=True)
        self._tmp = Path(
            tempfile.mkdtemp(dir=str(ROOT / ".tmp_tests"))
        )
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)
        # 清理临时目录被删后的空壳
        tmp_root = ROOT / ".tmp_tests"
        if tmp_root.is_dir() and not any(tmp_root.iterdir()):
            tmp_root.rmdir()

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = add_fields.main([*argv])
        return code, buf.getvalue()

    def test_e2e_add_field_on_base64_input(self):
        payload = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        b64_file = self._tmp / "config.b64.txt"
        b64_file.write_text(
            base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii"),
            encoding="utf-8",
        )
        output = self._tmp / "out_modified.json"
        code, stdout = self._run(
            "--input", str(b64_file),
            "--field", "主机ip", "--value", "1.1.1.1",
            "--output", str(output),
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "success")
        self.assertIn("成功为 2 个 entity", report["message"])
        self.assertIn("跳过 1 个无 normalize", report["message"])
        # 修改后 JSON
        updated = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(updated[0]["normalize"][-1]["index"], "主机ip")
        # 平台可导入 Base64 导出文件
        export = Path(report["export"])
        self.assertTrue(export.exists())
        self.assertRegex(export.name, r"^fieldadjusted_config_\d{8}_\d{4}\.txt$")
        decoded = json.loads(base64.b64decode(export.read_text(encoding="utf-8")))
        self.assertEqual(decoded, updated)

    def test_e2e_missing_input_reports_config_required(self):
        code, stdout = self._run("--input", str(self._tmp / "nope.txt"), "--field", "x")
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "config_required")

    def test_e2e_field_conflict_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE), "--field", "src_ip", "--value", "x",
            "--output", str(self._tmp / "o.json"),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "field_conflict")

    def test_e2e_unknown_target_reports_rule_name_not_found(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE), "--field", "主机ip", "--value", "1.1.1.1",
            "--target", "不存在的规则",
            "--output", str(self._tmp / "o.json"),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "rule_name_not_found")
        self.assertIn("可用子规则", report["message"])

    def test_e2e_mixed_target_with_unknown_name_rejected(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE), "--field", "主机ip", "--value", "1.1.1.1",
            "--target", "某厂_AUDIT_json_子规则,打错的规则",
            "--output", str(self._tmp / "o.json"),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "rule_name_not_found")
        # 未失败产物不落盘
        self.assertFalse((self._tmp / "o.json").exists())

    def test_e2e_valid_target_scopes_output(self):
        output = self._tmp / "scoped_modified.json"
        code, stdout = self._run(
            "--input", str(self.FIXTURE), "--field", "主机ip", "--value", "1.1.1.1",
            "--target", "某厂_AUDIT_json_子规则",
            "--output", str(output), "--no-export",
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "success")
        self.assertIn("目标 1 个", report["message"])
        updated = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(updated[0]["normalize"][-1]["index"], "主机ip")
        # 名单外 entity 原样透传
        self.assertEqual(updated[1]["normalize"][0]["index"], "dst_ip")

    def test_e2e_empty_target_list_rejected(self):
        """--target 全为分隔符/空白 → 空名单整单拒绝（#13 欠账 1），无产物。"""
        output = self._tmp / "o.json"
        code, stdout = self._run(
            "--input", str(self.FIXTURE), "--field", "主机ip", "--value", "1.1.1.1",
            "--target", " , ,",
            "--output", str(output),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "invalid_input")
        self.assertIn("空名单", report["message"])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
