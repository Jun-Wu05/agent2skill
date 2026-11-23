"""_shared/cli.py CLI 骨架单元测试。

骨架是五子命令 main() 同形部分的单一事实源；本套件用最小假命令
（CliSpec + 直通适配器）直接测 run_cli 的文件契约：公共参数解析、
target 逗号解析与空名单拒绝、ConfigIOError 与守卫错误两条错误路径、
成功路径的落盘与 stdout payload、导出开关、--group 开关。
五子命令的行为回归由各自 CLI 端到端测试承担。
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
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared import cli  # noqa: E402
from field_adjust_helpers import make_entity, norm_entry  # noqa: E402


def _make_spec(execute=None, with_group=True):
    """最小假命令：专属参数只有 --field，其余全部走骨架。"""

    def _execute(args, data, target_names):
        if execute is not None:
            return execute(args, data, target_names)
        return {"status": "success", "data": data, "message": f"count={len(data)}"}

    return cli.CliSpec(
        prog="fake_cmd.py",
        description="测试用最小子命令",
        arguments=(
            (("--field", "-f"), {"required": True, "help": "字段名"}),
        ),
        execute=_execute,
        with_group=with_group,
    )


class RunCliContractTest(unittest.TestCase):
    """run_cli 的文件契约（与五子命令 main() 的可观察行为一致）。"""

    def setUp(self):
        (ROOT / ".tmp_tests").mkdir(exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(dir=str(ROOT / ".tmp_tests")))
        self.addCleanup(self._cleanup)
        self.config = self._write_config(
            [make_entity("rule_a", normalize=[norm_entry("src_ip", ["10.0.0.1"])])]
        )

    def _cleanup(self):
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)
        # 清理临时目录被删后的空壳
        tmp_root = ROOT / ".tmp_tests"
        if tmp_root.is_dir() and not any(tmp_root.iterdir()):
            tmp_root.rmdir()

    def _write_config(self, entities):
        path = self._tmp / "config.json"
        path.write_text(json.dumps(entities, ensure_ascii=False), encoding="utf-8")
        return path

    def _run(self, spec, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.run_cli(spec, [*argv])
        return code, buf.getvalue()

    def test_common_arguments_parsed(self):
        """公共参数（--group 缺省 all / --no-export 缺省 False）与专属参数都到适配器。"""
        seen = {}

        def execute(args, data, target_names):
            seen.update(
                group=args.group,
                no_export=args.no_export,
                field=args.field,
                entities=len(data),
            )
            return {"status": "success", "data": data, "message": "ok"}

        code, _ = self._run(
            _make_spec(execute), "--input", str(self.config), "--field", "主机ip"
        )
        self.assertEqual(code, 0)
        self.assertEqual(seen["group"], "all")
        self.assertFalse(seen["no_export"])
        self.assertEqual(seen["field"], "主机ip")
        self.assertEqual(seen["entities"], 1)

    def test_target_comma_list_parsed(self):
        """--target 逗号分隔去空白；缺省时适配器收到 None。"""
        seen = {}

        def execute(args, data, target_names):
            seen["target_names"] = target_names
            return {"status": "success", "data": data, "message": "ok"}

        code, _ = self._run(
            _make_spec(execute),
            "--input", str(self.config), "--field", "x",
            "--target", "rule_a , rule_b",
        )
        self.assertEqual(code, 0)
        self.assertEqual(seen["target_names"], ["rule_a", "rule_b"])

        code, _ = self._run(
            _make_spec(execute), "--input", str(self.config), "--field", "x"
        )
        self.assertEqual(code, 0)
        self.assertIsNone(seen["target_names"])

    def test_empty_target_list_rejected(self):
        """--target 全为分隔符/空白 → invalid_input 整单拒绝，不进适配器。"""
        seen = {"called": False}

        def execute(args, data, target_names):
            seen["called"] = True
            return {"status": "success", "data": data, "message": "ok"}

        output = self._tmp / "o.json"
        code, stdout = self._run(
            _make_spec(execute),
            "--input", str(self.config), "--field", "x",
            "--target", " , ,",
            "--output", str(output),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["code"], "invalid_input")
        self.assertIn("空名单", report["message"])
        self.assertFalse(seen["called"])
        self.assertFalse(output.exists())

    def test_empty_string_target_rejected(self):
        """--target ""（如脚本变量未赋值，用户裁决同样拒绝）→ invalid_input。"""
        seen = {"called": False}

        def execute(args, data, target_names):
            seen["called"] = True
            return {"status": "success", "data": data, "message": "ok"}

        code, stdout = self._run(
            _make_spec(execute),
            "--input", str(self.config), "--field", "x",
            "--target", "",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "invalid_input")
        self.assertIn("空名单", report["message"])
        self.assertFalse(seen["called"])

    def test_config_io_error_exit(self):
        """输入文件不可读 → ConfigIOError 契约（code 透传、退出 1）。"""
        code, stdout = self._run(
            _make_spec(), "--input", str(self._tmp / "nope.txt"), "--field", "x"
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "config_required")

    def test_execute_error_printed_and_exit_1(self):
        """适配器返回错误 → 原样打印、退出 1、无产物落盘。"""

        def execute(args, data, target_names):
            return {"status": "error", "code": "boom", "message": "领域守卫拒绝"}

        output = self._tmp / "o.json"
        code, stdout = self._run(
            _make_spec(execute),
            "--input", str(self.config), "--field", "x",
            "--output", str(output),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report, {"status": "error", "code": "boom", "message": "领域守卫拒绝"})
        self.assertFalse(output.exists())

    def test_success_default_output_and_export(self):
        """成功路径：缺省 <输入名>_modified.json + 平台可导入 Base64 导出 + payload 契约。"""
        code, stdout = self._run(
            _make_spec(), "--input", str(self.config), "--field", "x"
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["message"], "count=1")
        default_output = self._tmp / "config_modified.json"
        self.assertEqual(Path(report["output"]), default_output)
        updated = json.loads(default_output.read_text(encoding="utf-8"))
        self.assertEqual(updated[0]["name"], "rule_a")
        export = Path(report["export"])
        self.assertTrue(export.exists())
        self.assertRegex(export.name, r"^fieldadjusted_config_\d{8}_\d{4}\.txt$")
        decoded = json.loads(base64.b64decode(export.read_text(encoding="utf-8")))
        self.assertEqual(decoded, updated)

    def test_no_export_flag(self):
        """--no-export → 不产出 Base64 导出，payload 的 export 为 null。"""
        code, stdout = self._run(
            _make_spec(),
            "--input", str(self.config), "--field", "x",
            "--no-export", "--output", str(self._tmp / "o.json"),
        )
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        self.assertIsNone(report["export"])
        exports = list(self._tmp.glob("fieldadjusted_config_*.txt"))
        self.assertEqual(exports, [])

    def test_explicit_output_path(self):
        """--output 显式路径优先于缺省命名。"""
        output = self._tmp / "explicit.json"
        code, stdout = self._run(
            _make_spec(),
            "--input", str(self.config), "--field", "x",
            "--output", str(output), "--no-export",
        )
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        self.assertEqual(Path(report["output"]), output)
        self.assertTrue(output.exists())

    def test_with_group_false_rejects_group_option(self):
        """with_group=False 的命令（如 add）不接受 --group。"""
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                cli.run_cli(
                    _make_spec(with_group=False),
                    [
                        "--input", str(self.config),
                        "--field", "x",
                        "--group", "threat",
                    ],
                )
        self.assertEqual(ctx.exception.code, 2)

    def test_group_choice_validated(self):
        """--group 取值受 choices 约束，非法值直接 argparse 报错。"""
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                cli.run_cli(
                    _make_spec(),
                    [
                        "--input", str(self.config),
                        "--field", "x",
                        "--group", "bogus",
                    ],
                )
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
