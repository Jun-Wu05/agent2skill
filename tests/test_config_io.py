"""config_io 单元测试：配置族解码/编码契约。"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "skills" / "parser-skills")):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared import config_io  # noqa: E402


def _b64(payload) -> str:
    return base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii")


class DecodeConfigTextTest(unittest.TestCase):
    def test_native_json_array(self):
        payload = [{"name": "r1", "normalize": []}]
        self.assertEqual(config_io.decode_config_text(json.dumps(payload)), payload)

    def test_base64_encoded_json(self):
        payload = [{"name": "规则甲", "normalize": [{"index": "原始日志"}]}]
        text = _b64(payload)
        # 含换行/空白的 Base64 清洗后仍可解码
        spaced = text[:10] + "\n" + text[10:] + "  "
        self.assertEqual(config_io.decode_config_text(spaced), payload)

    def test_missing_padding_tolerated(self):
        payload = [{"name": "r1"}]
        text = _b64(payload)
        stripped = text.rstrip("=")
        self.assertEqual(config_io.decode_config_text(stripped), payload)

    def test_empty_text_rejected(self):
        with self.assertRaises(config_io.ConfigIOError) as ctx:
            config_io.decode_config_text("   \n  ")
        self.assertEqual(ctx.exception.code, "invalid_config")

    def test_garbage_rejected(self):
        with self.assertRaises(config_io.ConfigIOError) as ctx:
            config_io.decode_config_text("这不是配置{{{")
        self.assertEqual(ctx.exception.code, "invalid_config")

    def test_non_array_root_rejected(self):
        with self.assertRaises(config_io.ConfigIOError) as ctx:
            config_io.decode_config_text(json.dumps({"normalize": []}))
        self.assertEqual(ctx.exception.code, "invalid_config")


class LoadEntitiesTest(unittest.TestCase):
    def test_missing_file_config_required(self):
        with self.assertRaises(config_io.ConfigIOError) as ctx:
            config_io.load_entities(ROOT / "testdata" / "no_such_file.txt")
        self.assertEqual(ctx.exception.code, "config_required")

    def test_load_sample_fixture(self):
        entities = config_io.load_entities(ROOT / "testdata" / "sample_config.json")
        self.assertIsInstance(entities, list)
        self.assertEqual(len(entities), 3)
        self.assertEqual(entities[0]["name"], "某厂_AUDIT_json_子规则")


class EncodeConfigTest(unittest.TestCase):
    def test_b64_roundtrip_preserves_chinese(self):
        payload = [{"name": "某厂_AUDIT_json_子规则", "normalize": [{"index": "原始日志"}]}]
        encoded = config_io.encode_config_b64(payload)
        decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
        self.assertEqual(decoded, payload)

    def test_save_entities_writes_utf8_json(self):
        import tempfile

        payload = [{"name": "中文规则", "normalize": []}]
        (ROOT / ".tmp_tests").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(ROOT / ".tmp_tests")) as tmp:
            target = Path(tmp) / "out.json"
            config_io.save_entities(payload, target)
            text = target.read_text(encoding="utf-8")
            self.assertIn("中文规则", text)  # ensure_ascii=False
            self.assertEqual(json.loads(text), payload)


if __name__ == "__main__":
    unittest.main()
