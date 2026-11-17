"""配置族输入/输出：Base64 txt / 原生 JSON / TXT 的确定性解码与编码。

解码采用「先原生 JSON、后 Base64→JSON」的 Try-Decode + JSON 验证策略。
所有技能的配置族文件读写必须经过本模块，禁止在技能脚本内复制解码逻辑。
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

_BASE64_CHARSET = re.compile(r"^[A-Za-z0-9+/=\s]+$")


class ConfigIOError(Exception):
    """配置读写失败。code 为稳定错误码，message 面向用户。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _decode_base64_text(text: str) -> str:
    """解码单个 Base64 文本内容（清洗空白、容忍缺省 padding）。"""
    cleaned = "".join(text.split())
    if not cleaned:
        return ""
    if not _BASE64_CHARSET.match(cleaned):
        raise ValueError("输入包含非Base64字符，可能是原始文本而非Base64编码")
    missing_padding = len(cleaned) % 4
    if missing_padding:
        cleaned += "=" * (4 - missing_padding)
    decoded_bytes = base64.b64decode(cleaned.encode("ascii"))
    return decoded_bytes.decode("utf-8", errors="replace")


def decode_config_text(text: str) -> list:
    """把配置族文本解码为 mapping entities（JSON 数组）。

    顺序：先按原生 JSON 解析；失败再按 Base64 → JSON 尝试
    （Try-Decode + JSON 验证）。两者都失败抛 ConfigIOError。
    根对象必须是 JSON 数组。
    """
    stripped = (text or "").strip()
    if not stripped:
        raise ConfigIOError("invalid_config", "配置内容为空")
    payload: Any = None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            payload = json.loads(_decode_base64_text(stripped))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConfigIOError(
                "invalid_config",
                f"无法解析为 JSON 或 Base64 编码的 JSON：{exc}",
            ) from exc
    if not isinstance(payload, list):
        raise ConfigIOError(
            "invalid_config",
            "配置根对象必须是 JSON 数组（mapping entities），"
            f"实际是 {type(payload).__name__}",
        )
    return payload


def load_entities(path: str | Path) -> list:
    """从文件加载 mapping entities。文件缺失抛 config_required。"""
    file_path = Path(path)
    if not file_path.is_file():
        raise ConfigIOError("config_required", f"找不到配置文件: {file_path}")
    text = file_path.read_text(encoding="utf-8")
    return decode_config_text(text)


def encode_config_b64(entities: list) -> str:
    """把配置编码为平台可导入的 Base64 文本（紧凑 JSON → UTF-8 → Base64）。"""
    return base64.b64encode(
        json.dumps(entities, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")


def save_entities(entities: list, path: str | Path) -> Path:
    """把 entities 写为 UTF-8 JSON 文件（缩进 2，保留中文）。"""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(
        json.dumps(entities, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return file_path
