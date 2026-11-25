"""mapping_adjust CLI 端到端测试：配置 + --set/--clear → 手动映射调整的文件契约。

接缝：field-mapping/scripts/mapping_adjust.py 的 main(argv)——
stdout JSON（status/message/output/export/sets/clears 或
status/error/code/message）+ <输入名>_adjusted.json 产物 +
mappingadjusted_config Base64 导出 + 退出码。
手动调整 = 对已有字段归属映射的设置（改判）与清除：
- set 写归属四件 field=目录规范名 / entity=目录首个对象 / sim=True / core=False；
- clear 置空四件、条目与值映射保留（与取消值映射镜像对称）；
- 守卫链整单拒绝（黑名单/目录外/排除索引/占用/值映射在身），不降级；
- 幂等：set 同值成功计 unchanged，clear 无可清报 mapping_not_found。
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
SCRIPTS = SKILLS / "field-mapping" / "scripts"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SCRIPTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import mapping_adjust  # noqa: E402


def make_entry(index, field=None, mappings=None, entity=None, sim=None, core=None):
    return {
        "mappings": mappings if mappings is not None else [],
        "field": field,
        "sim": sim,
        "result": [],
        "info": None,
        "entity": entity,
        "required": False,
        "core": core,
        "value": None,
        "index": index,
    }


def make_entity(name="规则A", entries=(), event_name=None):
    filters = []
    if event_name is not None:
        filters.append({"name": "addFields", "id": "", "fields": {"事件名称": event_name}})
    return {
        "name": name,
        "parser": {"name": "kv", "tab": "=", "delimit": "\\s", "filter": filters},
        "normalize": list(entries),
        "sample": "",
    }


MAPPING = {"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"}


class MappingAdjustCliTest(unittest.TestCase):
    def setUp(self):
        tmp_root = ROOT / ".tmp_tests"
        tmp_root.mkdir(exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(dir=str(tmp_root)))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        tmp_root = ROOT / ".tmp_tests"
        if tmp_root.is_dir() and not any(tmp_root.iterdir()):
            tmp_root.rmdir()

    def _config(self, entities, name="config.json"):
        path = self._tmp / name
        path.write_text(
            json.dumps(entities, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = mapping_adjust.main([*argv])
        return code, json.loads(buf.getvalue())

    def _read_output(self, payload):
        return json.loads(Path(payload["output"]).read_text(encoding="utf-8"))

    # ---------- set ----------

    def test_set_writes_attribution(self):
        config = self._config(
            [make_entity(entries=[make_entry("src_ip")])]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=源地址")
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")
        self.assertTrue(payload["output"].endswith("_adjusted.json"))
        result = self._read_output(payload)
        entry = result[0]["normalize"][0]
        self.assertEqual(entry["field"], "src_address")
        self.assertEqual(entry["entity"], "流量")
        self.assertTrue(entry["sim"])
        self.assertFalse(entry["core"])
        detail = payload["sets"][0]
        self.assertEqual(detail["field"], "src_ip")
        self.assertEqual(detail["standard"], "源地址")
        self.assertEqual(detail["changed"], 1)
        self.assertEqual(detail["unchanged"], 0)

    def test_set_rejudge_records_previous_value(self):
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("src_ip", field="目的地址", entity="流量", sim=True, core=False)
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=源地址")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["field"], "src_address")
        self.assertEqual(payload["sets"][0]["previous_values"], ["目的地址"])

    def test_set_by_standard_name(self):
        config = self._config(
            [
                make_entity(
                    entries=[make_entry("src_ip", field="目的地址", entity="流量", sim=True, core=False)]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "目的地址=源地址")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["field"], "src_address")
        self.assertEqual(result[0]["normalize"][0]["index"], "src_ip")

    def test_set_hits_same_index_across_entities(self):
        config = self._config(
            [
                make_entity(name="r1", entries=[make_entry("src_ip")]),
                make_entity(name="r2", entries=[make_entry("src_ip")]),
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=源地址")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["field"], "src_address")
        self.assertEqual(result[1]["normalize"][0]["field"], "src_address")
        self.assertEqual(payload["sets"][0]["changed"], 2)

    def test_set_idempotent_counts_unchanged(self):
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("src_ip", field="src_address", entity="流量", sim=True, core=False)
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=源地址")
        self.assertEqual(code, 0)
        detail = payload["sets"][0]
        self.assertEqual(detail["changed"], 0)
        self.assertEqual(detail["unchanged"], 1)

    def test_set_multiple_specs_in_one_run(self):
        config = self._config(
            [
                make_entity(
                    entries=[make_entry("src_ip"), make_entry("dst_ip")]
                )
            ]
        )
        code, payload = self._run(
            "--input", str(config),
            "--set", "src_ip=源地址", "--set", "dst_ip=目的地址",
        )
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["field"], "src_address")
        self.assertEqual(result[0]["normalize"][1]["field"], "dst_address")
        self.assertEqual(len(payload["sets"]), 2)

    def test_set_malformed_spec_rejected(self):
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        code, payload = self._run("--input", str(config), "--set", "src_ip")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_no_action_rejected(self):
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        code, payload = self._run("--input", str(config))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_set_target_not_found_with_vocab_hint(self):
        config = self._config(
            [make_entity(entries=[make_entry("src_ip", field="源地址")])]
        )
        code, payload = self._run("--input", str(config), "--set", "no_such=源地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "field_not_found")
        self.assertIn("src_ip(源地址)", payload["message"])

    def test_set_standard_not_in_catalog_rejected(self):
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        code, payload = self._run("--input", str(config), "--set", "src_ip=来源地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_set_blacklist_rejected_with_chain_hint(self):
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        for name in ("事件名称", "事件级别", "日志类型", "威胁类型"):
            code, payload = self._run("--input", str(config), "--set", f"src_ip={name}")
            self.assertEqual(code, 1, name)
            self.assertEqual(payload["code"], "invalid_input", name)
            self.assertIn(name, payload["message"])

    def test_set_excluded_index_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("事件名称", field="事件名称")])]
        )
        code, payload = self._run("--input", str(config), "--set", "事件名称=源地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "reserved_field_rejected")

    def test_set_with_existing_mappings_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("src_ip", mappings=[MAPPING])])]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=源地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("值映射", payload["message"])

    def test_set_occupied_by_other_rejected(self):
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("other_ip", field="源地址", entity="流量", sim=True, core=False),
                        make_entry("src_ip"),
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=源地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "mapping_target_occupied")
        self.assertIn("other_ip", payload["message"])

    def test_set_same_batch_duplicate_standard_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("a"), make_entry("b")])]
        )
        code, payload = self._run(
            "--input", str(config), "--set", "a=源地址", "--set", "b=源地址",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "mapping_target_occupied")

    def test_set_duplicate_target_field_rejected(self):
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        code, payload = self._run(
            "--input", str(config), "--set", "src_ip=源地址", "--set", "src_ip=目的地址",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_set_and_clear_same_target_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("src_ip", field="目的地址")])]
        )
        code, payload = self._run(
            "--input", str(config), "--set", "src_ip=源地址", "--clear", "src_ip",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_set_and_clear_entry_overlap_rejected(self):
        # 双侧寻址绕过字符串判重：index 与标准字段名指向同一条目 → 按命中条目拒绝
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("src_ip", field="src_address", entity="流量", sim=True, core=False)
                    ]
                )
            ]
        )
        code, payload = self._run(
            "--input", str(config), "--set", "src_ip=目的地址", "--clear", "src_address",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertEqual(list(self._tmp.glob("*_adjusted.json")), [])

    def test_set_specs_entry_overlap_rejected(self):
        # 两个 set 目标经不同寻址方式命中同一条目 → 拒绝（后写覆盖先写）
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("src_ip", field="src_address", entity="流量", sim=True, core=False)
                    ]
                )
            ]
        )
        code, payload = self._run(
            "--input", str(config),
            "--set", "src_ip=目的地址", "--set", "src_address=事件结果",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_set_cross_form_occupied_rejected(self):
        # 占用键经目录归一（中英文别名互通）：配置持英文别名 host_name，
        # set 中文名「主机名称」也能识别为同一标准 → 拒绝并报占用者
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("other_ip", field="host_name", entity="流量", sim=True, core=False),
                        make_entry("src_ip"),
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=主机名称")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "mapping_target_occupied")
        self.assertIn("other_ip", payload["message"])

    def test_set_cross_form_same_batch_duplicate_rejected(self):
        # 同批两个 set 经中英文名指向同一标准 → 归一后判重拒绝
        config = self._config(
            [make_entity(entries=[make_entry("a"), make_entry("b")])]
        )
        code, payload = self._run(
            "--input", str(config), "--set", "a=主机IP", "--set", "b=host_ip",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "mapping_target_occupied")

    def test_blacklist_english_alias_rejected(self):
        # 黑名单按规范名判定：英文名 event_name 同样拦截（事件名称）
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        code, payload = self._run("--input", str(config), "--set", "src_ip=event_name")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("事件名称", payload["message"])

    def test_set_mixed_index_field_hits_rejected(self):
        # 目标名既是某条目 index 又是另一条目 field：命中多个原始字段 → 歧义拒绝
        # （否则占用按自身判非冲突，写回后两个原始字段同持一个标准字段）
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("源地址"),
                        make_entry("client_ip", field="源地址", entity="流量", sim=True, core=False),
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "源地址=目的地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "field_name_ambiguous")
        self.assertIn("client_ip", payload["message"])

    def test_set_standard_name_ambiguous_rejected(self):
        config = self._config(
            [
                make_entity(name="r1", entries=[make_entry("ip1", field="源地址")]),
                make_entity(name="r2", entries=[make_entry("ip2", field="源地址")]),
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "源地址=目的地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "field_name_ambiguous")
        self.assertIn("ip1", payload["message"])
        self.assertIn("ip2", payload["message"])

    # ---------- clear ----------

    def test_clear_clears_attribution_keeps_mappings(self):
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry(
                            "src_ip", field="源地址", entity="流量", sim=True, core=False,
                            mappings=[MAPPING],
                        )
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--clear", "src_ip")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        entry = result[0]["normalize"][0]
        self.assertIsNone(entry["field"])
        self.assertIsNone(entry["entity"])
        self.assertIsNone(entry["sim"])
        self.assertIsNone(entry["core"])
        self.assertEqual(entry["mappings"], [MAPPING])  # 值映射保留
        self.assertEqual(entry["index"], "src_ip")  # 条目保留
        detail = payload["clears"][0]
        self.assertEqual(detail["cleared"], 1)
        self.assertEqual(detail["previous_values"], ["源地址"])

    def test_clear_by_standard_name(self):
        config = self._config(
            [
                make_entity(
                    entries=[make_entry("src_ip", field="src_address", entity="流量", sim=True, core=False)]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--clear", "src_address")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertIsNone(result[0]["normalize"][0]["field"])

    def test_clear_threat_attribution_allowed(self):
        # 链路产物与手工维护共存：威胁类型归属可手工清除，值映射保留
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry(
                            "attack_name", field="威胁类型", entity="威胁", sim=True, core=False,
                            mappings=[MAPPING],
                        )
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--clear", "威胁类型")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        entry = result[0]["normalize"][0]
        self.assertIsNone(entry["field"])
        self.assertEqual(entry["mappings"], [MAPPING])

    def test_clear_excluded_index_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("日志类型", field="网络设备")])]
        )
        code, payload = self._run("--input", str(config), "--clear", "日志类型")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "reserved_field_rejected")

    def test_clear_no_attribution_rejected(self):
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        code, payload = self._run("--input", str(config), "--clear", "src_ip")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "mapping_not_found")

    def test_clear_empty_list_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("src_ip", field="源地址")])]
        )
        code, payload = self._run("--input", str(config), "--clear", " , ")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    # ---------- 作用域 ----------

    def test_target_scoping_limits_writes(self):
        config = self._config(
            [
                make_entity(name="r1", entries=[make_entry("src_ip")]),
                make_entity(name="r2", entries=[make_entry("src_ip")]),
            ]
        )
        code, payload = self._run(
            "--input", str(config), "--set", "src_ip=源地址", "--target", "r2",
        )
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertIsNone(result[0]["normalize"][0]["field"])  # r1 不动
        self.assertEqual(result[1]["normalize"][0]["field"], "src_address")
        self.assertEqual(payload["sets"][0]["changed"], 1)

    def test_target_unknown_rejected(self):
        config = self._config([make_entity(name="r1", entries=[make_entry("src_ip")])])
        code, payload = self._run(
            "--input", str(config), "--set", "src_ip=源地址", "--target", "nope",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "rule_name_not_found")

    def test_group_scoping_threat_only(self):
        config = self._config(
            [
                make_entity(name="threat_r", entries=[make_entry("src_ip")], event_name="网络攻击"),
                make_entity(name="plain_r", entries=[make_entry("src_ip")], event_name="远程登录"),
            ]
        )
        code, payload = self._run(
            "--input", str(config), "--set", "src_ip=源地址", "--group", "threat",
        )
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["field"], "src_address")
        self.assertIsNone(result[1]["normalize"][0]["field"])

    # ---------- 原子性与 IO ----------

    def test_atomic_reject_produces_no_output(self):
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("other_ip", field="源地址"),
                        make_entry("src_ip"),
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--set", "src_ip=源地址")
        self.assertEqual(code, 1)
        self.assertEqual(list(self._tmp.glob("*_adjusted.json")), [])

    def test_no_export_flag(self):
        config = self._config([make_entity(entries=[make_entry("src_ip")])])
        code, payload = self._run(
            "--input", str(config), "--set", "src_ip=源地址", "--no-export",
        )
        self.assertEqual(code, 0)
        self.assertIsNone(payload["export"])
        self.assertEqual(list(self._tmp.glob("mappingadjusted_config_*.txt")), [])

    def test_config_load_error(self):
        code, payload = self._run("--input", str(self._tmp / "nope.json"), "--set", "a=源地址")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "config_required")


if __name__ == "__main__":
    unittest.main()
