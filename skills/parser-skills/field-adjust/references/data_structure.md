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

## base64 解码过滤器结构

base64 解码启用时写入（addFields 的一种），声明运行时对指定字段原地覆盖为解码值：

```json
{
  "fields": {
    "req_header": "<%@com.hansight.dataviewer.utils.Base64@Base64Decode(req_header)%>",
    "req_body": "<%@com.hansight.dataviewer.utils.Base64@Base64Decode(req_body)%>"
  },
  "name": "addFields",
  "id": ""
}
```

- key = 原字段名，值 = 固定 OGNL 解码语句，运行时由解析器解码后**原地覆盖**该字段的值——不新增字段、normalize 不动（与添加字段的双写语义不同）
- 识别条件：`name=addFields`、`id=""` 且**全部**值含 `Base64Decode(`——重复调用合并进该过滤器（幂等）；固定值与 OGNL 混合的 addFields 过滤器不算解码过滤器，会另建新的
- `original_log` / `rule_name_list` / `日志类型` 与【事件名称】/【事件级别】拒绝解码

## customFunction 过滤器结构（正则提取）

正则提取字段时写入，声明运行时按正则从被提取字段的值中提取第一个匹配项为新字段：

```json
{
  "custom_name": "extractRegexField",
  "fields": [
    {
      "functionName": "extractRegexField",
      "ognl": "<%@com.hansight.dataviewer.utils.ognl.OgnlUtils@regexExtraction(arg2,\"arg3\")%>",
      "functionViewName": "正则提取",
      "fieldName": "",
      "args": [
        {"name": "新增字段", "args": "arg1", "detail": "新增字段名称", "type": "field", "value": "提取用户"},
        {"name": "被提取字段", "args": "arg2", "detail": "字符格式字段", "type": "args", "value": "original_log"},
        {"name": "正则表达式", "args": "arg3", "detail": "只提取第一个匹配项", "type": "args", "value": "[\\S\\s]*\"user\":\"(.*?)\"[\\S\\s]*"}
      ]
    }
  ],
  "name": "customFunction",
  "id": ""
}
```

- `ognl` 为固定语句（字面量 `arg2` / `"arg3"` 指向同条目 args 数组的对应位置，不替换）
- 识别条件：`name=customFunction` 且 `id=""`——重复调用合并进该过滤器；args 中 arg1 与新字段同名的函数条目**原地覆盖**（新正则生效），不重复追加
- normalize 同步追加预览条目：`result` 为被提取字段样本值经正则**全匹配**后的第一个捕获组（无捕获组取整条），`index` 为新字段名——这是双写语义（与 base64 解码的原地覆盖不同）
- 正则必须可编译且有样本时必须全匹配整条样本，否则整体拒绝；新增字段名撞系统保留字段或【事件名称】/【事件级别】被拒（被提取字段不受限，original_log 合法）

## base64 解码示例 - 完整输入输出

### 输入数据
normalize:
```json
[
  {"index": "req_header", "result": ["aGVsbG8="], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null},
  {"index": "req_body", "result": ["d29ybGQ="], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null}
]
```

### 解码指令
"base64 解码 req_header 和 req_body"

### 输出数据
normalize **不变**（原地覆盖、不双写）；filter 新增：
```json
{"fields": {"req_header": "<%@com.hansight.dataviewer.utils.Base64@Base64Decode(req_header)%>", "req_body": "<%@com.hansight.dataviewer.utils.Base64@Base64Decode(req_body)%>"}, "name": "addFields", "id": ""}
```

再次执行「base64 解码 req_content」时合并进同一过滤器，不新建第二个。

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

## 正则提取示例 - 完整输入输出

### 输入数据
normalize:
```json
[
  {"index": "original_log", "result": ["{\"src_ip\":\"10.1.1.5\",\"user\":\"admin\"}"], "field": "原始日志", "sim": true, "entity": "日志", "required": false, "core": false, "mappings": [], "info": null, "value": null}
]
```

### 提取指令
"从原始日志里提取 user"（正则由 agent 按样本生成：`[\S\s]*"user":"(.*?)"[\S\s]*`，全匹配样本整条，取第一个捕获组）

### 输出数据
normalize 追加预览条目（result 为第一个捕获组）：
```json
{"index": "user", "result": ["admin"], "mappings": [], "field": null, "sim": null, "info": null, "entity": null, "required": false, "core": null, "value": null}
```

filter 追加 customFunction 过滤器（结构见上文「customFunction 过滤器结构（正则提取）」，arg1=user / arg2=original_log / arg3=正则）。

再次对同一新字段提取（arg1 同名）时函数条目原地覆盖、normalize 不再追加；新字段名已存在于该子规则字段集时报 `field_conflict`。

## 注意事项

- `result` 的值与 addFields filter 中的 value 保持一致
- 引用格式 `%{index}` 作为字符串原封不动地存储在 result 和 filter 中
- 解析器在执行时会将 `%{index}` 替换为对应字段的实际值
- addFields filter 数组中第一个元素通常是系统保留的 `additional_fields_filter`（id 为 "additional_fields_filter"），用户新增的 addFields 追加在其后
- 删除只处理目标 entity；`original_log` / `rule_name_list` / `日志类型` 为系统保留字段，删除被拒绝
- 删除【事件名称】或【事件级别】任一时自动扩展为删除两者（绑定对不拆散）
- 合并目标为系统保留字段或【事件名称】/【事件级别】时被拒绝；目标字段与源字段重名（自引用）被拒绝
- 合并的 per-entity 自适应：缺任一源或目标已存在的子规则跳过并按名报告；所有目标子规则都缺源字段时报 `field_not_found`（附字段并集预览）
- base64 解码的 per-entity 自适应：缺任一要解码字段的子规则跳过并按名报告；所有目标子规则都缺该字段时报 `field_not_found`（只点名真正缺失的字段 + 并集预览）
- 正则提取的 per-entity 自适应：缺被提取字段的子规则跳过并按名报告；所有目标子规则都缺被提取字段时报 `field_not_found`（附字段并集预览）；正则无法全匹配有样本子规则的样本整条时**整体拒绝**（`pattern_mismatch`）
