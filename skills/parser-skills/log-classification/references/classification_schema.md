# log-classification 数据契约（三份 JSON 的字段说明）

阶段①（feature_stats.py）与阶段②（classify_finalize.py）之间、以及下游 field-mapping 消费的全部文件契约。字段名是稳定接口，改名即破坏衔接。

## stats.json（阶段①产物，`<输入名>_stats.json`）

| 字段 | 类型 | 说明 |
|---|---|---|
| `log_format` | `"json" \| "kv"` | 宿主 agent 识别结论 |
| `format_context` | `{field_delimit, kv_delimit}` | 有效分隔符（数据裁决后）；json 时两项为 null |
| `header_end_marker` | str | 有效日志头标记（无效标记被裁决置空） |
| `feature_field` | str | 分类特征字段（JSON 可为点分路径） |
| `total_lines` / `matched_lines` / `unmatched_lines` | int | 行级统计（跳过空行） |
| `coverage` | float | matched / total |
| `value_count` / `top_values` | int / [str] | 去重特征值个数 / 前 20（计数降序） |
| `values` | {value → {count, samples}} | 每个特征值的计数与样本（≤3 条，≤300 字符，原始行） |
| `unmatched_samples` | [str] | 未匹配行样本（≤3 条） |
| `adjudications` | [{kind, from, to, reason}] | 数据裁决记录：`field_delimit` / `kv_delimit` / `header_end_marker` |
| `input` / `sheet` | str | 源文件与工作表名 |

## labels.json（宿主 agent 语义层，第 4 步产物）

```json
{"classification_details": [{"logtype": "<特征值>", "meaning": "<业务含义>"}]}
```

裸数组形态同样接受。`logtype` 必须严格等于 stats 中的特征值（臆造被裁剪、遗漏被回填，结果记入分类结果的 `sanitized` 字段）。

## classified.json（阶段②产物，`<输入名>_classified.json`）

平台兼容 schema：

| 字段 | 说明 |
|---|---|
| `status` | 固定 `"SUCCESS"`（收口失败走 stdout error + 退出码 1，不落盘） |
| `log_format` / `log_format_detail` | `"JSON"` / `"KV"` + 纯/日志头变体 |
| `feature_field` / `feature_identifier` | 特征字段 / JSON body 双捕获组正则（kv 为空串） |
| `feature_count` | classification_details 长度 |
| `total_valid_lines` / `covered_lines` / `coverage` | 行级统计（coverage 为四字段块：total/matched/unmatched_lines/unmatched_samples） |
| `classification_details` | [{logtype, meaning, count, sample, real_samples}]，按计数降序；sample=完整命中行，real_samples=日志体 |
| `analysis` | {has_json_structure, has_cef_prefix, has_key_value_pairs, has_delimited_structure, delimit, tab} |
| `categorical_features` / `Diversion_method` | 特征字段 / 固定「日志类型」 |
| `feature_body_group` / `feature_value_group` | 固定 0（syslog+KV header 正则留待 field-mapping） |
| `sanitized` | {trimmed, backfilled}——集合对齐记录 |
| `input` / `sheet` | 源文件与工作表名 |

## subrules.json（阶段②产物，`<输入名>_subrules.json`）

mapping entities 数组，每特征值一条白板子规则：

- 骨架 = `_shared/rule_gen.py` 的子规则模板（subResolver=1、addFields 固定四件套 product/event_name/event_level/log_vendor 全空、deviceType、entities=["日志"]）
- `name`：`{logtype}_{feature_field}_json_子规则` / `{logtype}_kv_子规则`
- `parser`：json → `name="json"`；kv → `delimitWithKeyMap` + `tab`/`delimit`（语义化转义：space→`\s`）
- `filter`：addFields 基座 +（kv）`{"fields": {"日志类型": logtype}, "name": "addFields"}`
- `normalize`：json → 按 real_samples 展开（dict 展开 1 层 parent.child + original_log，字母序）；kv → 该类型日志行的字段名并集（字母序，result 空）+ 末尾日志类型条目
- `sample` = real_samples；`id`/`createtime`/`lasttime` 每次生成新值

Base64 导出（`unmappedconfig_subrules_YYYYMMDD_HHMM.txt`）= 该数组的紧凑 JSON → UTF-8 → Base64，与子规则 JSON 内容等同。
