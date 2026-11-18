"""field-adjust 子命令测试共用的夹具构造器。

add / delete / merge 的测试文件共用，禁止在各测试文件内复制。
"""

from __future__ import annotations


def make_entity(name: str, *, normalize=None, filters=None) -> dict:
    return {
        "name": name,
        "parser": {"name": "json", "filter": filters},
        "normalize": normalize if normalize is not None else [],
    }


def norm_entry(index: str, result=None, field=None) -> dict:
    return {
        "mappings": [],
        "field": field,
        "sim": None,
        "result": result if result is not None else [],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": None,
        "index": index,
    }
