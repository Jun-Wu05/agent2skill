# 威胁类型链路契约（threat_schema）

两个脚本的全部文件契约。字段名即接口，改名即破坏；错误码与守卫语义见 [guide.md](../guide.md)。

## 1. 工作单 JSON（`<输入名>_threat_worklist.json`，threat_worklist.py 产物）

| 字段 | 类型 | 说明 |
|---|---|---|
| `input` / `log_input` | str | 配置与日志表路径（回溯用） |
| `log_format` | `"json" \| "kv"` | 日志体格式（agent 判定结论） |
| `header_end_marker` | str | KV 日志头标记；json 格式恒空串 |
| `threat_rules` | str[] | 威胁组子规则名（事件标注自动寻址，配置序） |
| `rule_count` | int | 威胁子规则数 |
| `threat_field_states` | {规则名: 三态} | 各子规则威胁类型字段现状：`absent` / `chain`（链路自产，`%{}` 引用绑定）/ `existing`（存量条目） |
| `candidates` | object[] | 候选字段值画像（字段池并集，威胁子规则序内首现序） |
| `whitelist` | str[] | 威胁类型标准枚举白名单（标准字段目录单一事实源） |

`candidates[]` 元素：

| 字段 | 类型 | 说明 |
|---|---|---|
| `field` | str | 候选字段名（normalize index） |
| `present_in_rules` | str[] | 该字段出现在哪些威胁子规则的字段池 |
| `present_rule_count` | int | 覆盖子规则数 |
| `matched_lines` | int | 全日志命中行数（0＝该字段在日志中无取值） |
| `unique_count` | int | 唯一值数（全量） |
| `values` | str[] | 值列表（首现序，`--max-values` 截断） |
| `value_counts` | {值: 计数} | 每值计数（**全量不截断**，键序=首现序；收口的声明值集来源） |
| `samples` | {值: 首条日志行} | 每值首条样本（截断至 `values`） |
| `code_only_values` | str[] | 无语义数字代码值（数字+`-_.:/`） |
| `all_code_only` | bool | 值列表全部为无语义数字代码（空值集为 false） |
| `truncated` | bool | 值列表是否被 `--max-values` 截断 |

stdout 摘要：`status` / `message`（含无取值候选提示；json 格式下 `--header-end-marker` 已忽略提示）/ `output` / `threat_rules` / `candidate_count` / `whitelist_size`。

## 2. 分组判定 JSON（宿主 agent 产物，threat_finalize.py `--judgments` 输入）

```json
{"groups": [{"source_field": "threat_name",
             "rules": ["规则A", "规则B"],
             "pairs": [{"mappingType": "REGULAR", "orgValue": "(?i).*挖矿.*",
                        "mappingValue": "挖矿木马"}]}],
 "skipped_rules": ["规则C"]}
```

| 字段 | 约束 |
|---|---|
| `groups[]` | 至少一组；裸数组视为纯 groups |
| `groups[].source_field` | 必须在工作单候选字段中，且在该组每条子规则的字段池中 |
| `groups[].rules` | 必须是威胁组子规则；全部 groups + skipped_rules 恰好划分 `threat_rules`（不重不漏） |
| `groups[].pairs` | 归一规则同枚举映射表（EQUAL 缺省 / REGULAR 自动 `.*` 包裹，行首 `(?i)` 保留）；组内同 orgValue 首现胜出；每行 `mappingValue` 必须在白名单内 |
| `skipped_rules` | 用户裁决跳过的威胁子规则（如实记录，可省） |

覆盖校验（每组独立，任一违规整单拒绝 `threat_mapping_coverage_rejected`）：组的声明值集＝工作单该字段 `value_counts` 全量键；每个声明值恰被一行命中、每行至少命中一个声明值。另有跨组一致性校验：同一声明值出现在多个组的值集时，各组解析出的映射值必须一致（`invalid_input` / `value_mapped_inconsistently`）。

## 3. 产物（threat_finalize.py）

- `<输入名>_threatfilled.json`：修改后配置（规则数组，与输入同构）
- `threatmapping_config_{时间戳}.txt`：平台可导入 Base64 导出（`--no-export` 关闭）

写回语义（按子规则三态，原子：全部校验通过才落盘）：

- `chain`：清除该子规则全部威胁类型条目与绑定 → 追加唯一新绑定 `威胁类型: %{来源字段}` 与新条目（mappings 全量重建；`field=threat_type / entity=威胁 / sim=true / core=false`，`result` 按样本数复制 `%{来源字段}`）
- `absent`：同 chain 的追加写法（无旧物可清）
- `existing`：条目原状保留；先解绑其固定值绑定（`%{}` 引用保留），再按 orgValue 合并更新 mappings（同 orgValue 原地更新、新值追加、未提及保留）

## 4. stdout 摘要（threat_finalize.py）

| 字段 | 类型 | 说明 |
|---|---|---|
| `status` / `message` | — | 成功消息含写入行数 / 整体重建子规则数 / 解绑数 / 分组与覆盖数；零变更为幂等提示 |
| `output` / `export` | str | 产物路径（export 可为 null） |
| `groups[]` | object[] | 每组：`source_field` / `declared_count` / `pair_count` / `duplicates` / `rules[]` |
| `groups[].rules[]` | object[] | 每条子规则：`rule` / `state`（三态）/ `added` / `updated` / `unchanged` / `unbound` / `rebuilt` |
| `skipped_rules` | str[] | 用户裁决跳过的子规则 |
| `whitelist_size` | int | 白名单值数 |

失败（退出码 1）：`status: error` + `code` + `message`（覆盖校验附规则标识与具体值/行，修正判定后重跑安全——整单拒绝不写一行）。
