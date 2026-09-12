# auto-sub — 免费节点自动订阅工厂

一次配置、长期自动更新：多源抓取 → 解析 → 去重 → TCP粗筛 → Xray真实测速滤活 → 产出干净订阅 → CDN发布 → v2rayN 自动拉取。

## 工作链路

```
config/sources.txt (8个公开源)
        │  GitHub Actions 每6小时自动运行 (也可手动 Run workflow)
        ▼
scripts/collect.py   抓取 / base64解码 / Clash转换 / 指纹去重  → sub/all.txt
        ▼
scripts/speedtest.py TCP粗筛 + Xray经节点实测(generate_204/2MB) → sub/live.txt
        ▼
自动 commit 回仓库 → jsDelivr/raw CDN 发布
        ▼
v2rayN 订阅该URL, 每12小时自动更新 (双层自动)
```

## 目录
- `config/sources.txt` 上游源清单，每行一个URL，#注释，增删源改这里
- `scripts/collect.py` 抓取/解析/去重（纯标准库）
- `scripts/speedtest.py` 测速滤活（纯标准库 + 运行时下载的Xray）
- `.github/workflows/update.yml` 定时工作流
- `sub/all.txt|all.b64` 去重全量；`sub/live.txt|live.b64` 测速存活版（**v2rayN订这个**）
- `sub/*.stats.json` 每次运行统计

## v2rayN 订阅地址（订 live.b64）
- 主(jsDelivr)：`https://cdn.jsdelivr.net/gh/niuniumen/auto-sub@main/sub/live.b64`
- 备1(fastly)：`https://fastly.jsdelivr.net/gh/niuniumen/auto-sub@main/sub/live.b64`
- 备2(raw)：`https://raw.githubusercontent.com/niuniumen/auto-sub/main/sub/live.b64`
- 备3(镜像)：`https://ghfast.top/https://raw.githubusercontent.com/niuniumen/auto-sub/main/sub/live.b64`

## 手动立即更新一次
仓库 Actions 页 → auto-sub → Run workflow；或本地：`gh workflow run auto-sub`

## 客观说明（重要）
1. Actions runner 在海外，其测速是“海外到节点”视角，价值在于**自动滤掉死节点、去重、定时更新**，不等于西安本地速度；本地最快接入仍可配合 CloudflareST 优选。
2. 免费节点带宽/稳定性有天花板，本项目只省“手动找节点/更新订阅”的维护成本，不改变免费节点本身质量。
3. 免费 Actions 的 schedule 整点可能延迟或偶发跳过，故同时保留手动触发 + v2rayN 侧定时拉取双保险。
4. 本仓库只聚合**公开免费源**，不含任何个人订阅/token/账号信息。
