# 字段调整 - 数据结构参考

## 整体结构

Base64 解码后是一个 JSON 数组，每个元素是一个 mapping entity：

```json
[
  {
    "name": "规则名称",
    "normalize": [...],
    "parser": {
      "name": "json",
      "filter": [...]
    }
  }
]
```

## normalize 条目结构

```json
{
  "mappings": [],
  "field": null,
  "sim": null,
  "result": ["字段值"],
  "info": null,
  "entity": null,
  "required": false,
  "core": null,
  "value": null,
  "index": "字段名"
}
```

## addFields 过滤器结构

### 添加固定值字段
```json
{
  "name": "addFields",
  "id": "",
  "fields": {
    "主机ip": "1.1.1.1"
  }
}
```

### 添加引用字段（引用已有字段的值）
```json
{
  "name": "addFields",
  "id": "",
  "fields": {
    "请求头": "%{reqheader}"
  }
}
```

引用语法：
- `%{index}` — 其中 index 是已有字段的 normalize index
- 解析时，`%{reqheader}` 会被替换为 index="reqheader" 的字段的实际值

## removeFields 过滤器结构

删除字段时写入，声明从最终结果中移除的字段：

```json
{
  "name": "removeFields",
  "id": "",
  "fields": ["src_ip", "备注"]
}
```

已有 removeFields 过滤器时合并（去重追加），不新建第二个。

## merger 过滤器结构

合并字段时写入，声明运行时把多个源字段的值按分隔符拼接为新字段：

```json
{
  "name": "merger",
  "field": "合并字段",
  "sep": "-",
  "id": "",
  "fields": ["源字段A", "源字段B"]
}
```

- `field`：合并产出的目标字段名；`fields`：源字段列表（运行时按 `sep` 拼接源字段值）
- 已有同目标的 merger 时原地更新（新源字段列表与分隔符覆盖旧值），不新建第二个
- 源字段的 normalize 条目保留不删——merger 运行时读取源字段现场拼接

## 合并示例 - 完整输入输出

### 输入数据
normalize:
```json
[
  {"index": "a", "result": ["1"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null},
  {"index": "b", "result": ["2"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null}
]
```

### 合并指令
"把 a 和 b 用 - 合并成 c"

### 输出数据
normalize 追加预览条目（result 为源字段样本值按序拼接）：
```json
{"index": "c", "result": ["1-2"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null}
```

filter 新增：
```json
{"name": "merger", "field": "c", "sep": "-", "id": "", "fields": ["a", "b"]}
```

源字段 a、b 的条目原样保留。

## 删除示例 - 完整输入输出

### 输入数据
normalize:
```json
[
  {"index": "src_ip", "result": ["10.0.0.1"], "mappings": [], "field": "源地址", "sim": 0.99, "info": null, "entity": "网络", "required": false, "core": true, "value": null},
  {"index": "主机ip", "result": ["1.1.1.1"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null}
]
```

filter:
```json
[
  {"name": "addFields", "id": "additional_fields_filter", "fields": {"product": ""}},
  {"name": "addFields", "id": "", "fields": {"主机ip": "1.1.1.1", "备注": "x"}}
]
```

### 删除指令
"删除字段 主机ip"

### 输出数据
normalize 移除 `index=主机ip` 的条目，只剩 src_ip；filter 变为：
```json
[
  {"name": "addFields", "id": "additional_fields_filter", "fields": {"product": ""}},
  {"name": "addFields", "id": "", "fields": {"备注": "x"}},
  {"name": "removeFields", "id": "", "fields": ["主机ip"]}
]
```

同名 addFields 键被清掉、过滤器还有其他键时保留；若清空则整个空 addFields 过滤器被删除。

## 添加示例 - 完整输入输出

### 输入数据
normalize:
```json
[
  {"index": "a", "result": ["1"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null},
  {"index": "b", "result": ["2"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null},
  {"index": "original_log", "result": ["{\"a\":1,\"b\":\"2\"}"], "field": "original_log", "sim": true, "entity": "日志", "required": false, "core": false, "mappings": [], "info": null, "value": null}
]
```

filter:
```json
[
  {"name": "addFields", "id": "additional_fields_filter", "fields": {"product": "", "event_name": "", "event_level": "", "log_vendor": ""}}
]
```

### 添加指令
"添加字段 主机ip，值为 1.1.1.1"

### 输出数据
normalize 新增：
```json
{"index": "主机ip", "result": ["1.1.1.1"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null}
```

filter 新增：
```json
{"name": "addFields", "id": "", "fields": {"主机ip": "1.1.1.1"}}
```

## 引用字段示例

### 用户指令
"新增字段请求头，引用 reqheader 的值"

### 输出
filter 新增：
```json
{"name": "addFields", "id": "", "fields": {"请求头": "%{reqheader}"}}
```

normalize 新增：
```json
{"index": "请求头", "result": ["%{reqheader}"], ...}
```

## 注意事项

- `result` 的值与 addFields filter 中的 value 保持一致
- 引用格式 `%{index}` 作为字符串原封不动地存储在 result 和 filter 中
- 解析器在执行时会将 `%{index}` 替换为对应字段的实际值
- addFields filter 数组中第一个元素通常是系统保留的 `additional_fields_filter`（id 为 "additional_fields_filter"），用户新增的 addFields 追加在其后
- 删除只处理目标 entity；`original_log` / `rule_name_list` / `日志类型` 为系统保留字段，删除被拒绝
- 删除【事件名称】或【事件级别】任一时自动扩展为删除两者（绑定对不拆散）
- 合并目标为系统保留字段或【事件名称】/【事件级别】时被拒绝；目标字段与源字段重名（自引用）被拒绝
- 合并的 per-entity 自适应：缺任一源或目标已存在的子规则跳过并按名报告；所有目标子规则都缺源字段时报 `field_not_found`（附字段并集预览）
