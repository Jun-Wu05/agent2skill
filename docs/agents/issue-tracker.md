# Issue tracker：GitHub

本仓库的 issue 与 spec 都以 GitHub issue 的形式存在。所有操作使用 `gh` CLI。

## 约定

- **创建 issue**：`gh issue create --title "..." --body "..."`。多行正文用 heredoc。
- **读取 issue**：`gh issue view <number> --comments`，用 `jq` 过滤评论并同时取标签。
- **列出 issue**：`gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`，按需加 `--label` 与 `--state` 过滤。
- **评论**：`gh issue comment <number> --body "..."`
- **打/摘标签**：`gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **关闭**：`gh issue close <number> --comment "..."`

仓库从 `git remote -v` 推断；在 clone 内运行时 `gh` 会自动识别。

## Pull requests 作为 triage 面

**PRs as a request surface: no.**（如果本仓库把外部 PR 当作功能请求处理，把此项改为 `yes`；`/triage` 会读取这个开关。）

设为 `yes` 时，PR 与 issue 走同一套标签与状态，使用对应的 `gh pr` 命令：

- **读 PR**：`gh pr view <number> --comments`，diff 用 `gh pr diff <number>`。
- **为 triage 列出外部 PR**：`gh pr list --state open --json number,title,body,labels,author,authorAssociation,comments`，只保留 `authorAssociation` 为 `CONTRIBUTOR`、`FIRST_TIME_CONTRIBUTOR` 或 `NONE` 的（丢弃 `OWNER`/`MEMBER`/`COLLABORATOR`）。
- **评论/打标签/关闭**：`gh pr comment`、`gh pr edit --add-label`/`--remove-label`、`gh pr close`。

GitHub 的 issue 和 PR 共用一套编号，所以裸的 `#42` 可能是任意一种：先用 `gh pr view 42`，失败再回退 `gh issue view 42`。

## 当技能说 "publish to the issue tracker"

创建一个 GitHub issue。

## 当技能说 "fetch the relevant ticket"

运行 `gh issue view <number> --comments`。

## Wayfinder 操作

供 `/wayfinder` 使用。**地图（map）** 是一张带 `wayfinder:map` 标签的 issue，**子票（child）** 是普通 issue。

- **Map**：一张标签为 `wayfinder:map` 的 issue，正文承载 Notes / Decisions-so-far / Fog。`gh issue create --label wayfinder:map`。
- **子票**：以 GitHub sub-issue 的形式挂到地图上（对 sub-issues 端点调 `gh api`）。若 sub-issues 不可用，把子票加进地图正文里的 task list，并在子票正文顶部写 `Part of #<map>`。标签：`wayfinder:<type>`（`research`/`prototype`/`grilling`/`task`）。一旦被认领，把票 assign 给驱动的开发。
- **Blocking**：GitHub 的**原生 issue dependencies**，是 UI 可见的规范表示。加边用 `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`，其中 `<blocker-db-id>` 是阻塞方的数字 **database id**（`gh api repos/<owner>/<repo>/issues/<n> --jq .id`，不是 `#number` 也不是 `node_id`）。GitHub 会通过 `issue_dependencies_summary.blocked_by` 上报（只算 open 的阻塞者，是实时门禁）。若 dependencies 不可用，回退为在子票正文顶部写 `Blocked by: #<n>, #<n>`。所有阻塞者都关闭后，票才算解除阻塞。
- **Frontier 查询**：列出地图的 open 子票（`gh issue list --state open`，按地图的 sub-issues / task list 范围过滤），去掉有 open 阻塞者（`issue_dependencies_summary.blocked_by > 0`，或 `Blocked by` 行里有 open issue）或有 assignee 的；按地图顺序第一个胜出。
- **认领**：`gh issue edit <n> --add-assignee @me`，这是本会话的第一个写操作。
- **解决**：`gh issue comment <n> --body "<answer>"`，然后 `gh issue close <n>`，最后把上下文指针（gist + 链接）追加到地图的 Decisions-so-far。
