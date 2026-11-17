# 添加字段 - 数据结构参考

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
