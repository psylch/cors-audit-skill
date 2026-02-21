# cors-audit-skill

[English](README.md)

一个 [Claude Code](https://docs.anthropic.com/en/docs/claude-code) 技能，用于架构级 CORS 跨域审计。与只关注代码配置的工具不同，这个 skill 审计**整个请求链路**——网关、后端、前端——捕捉单层工具发现不了的问题。

诞生于真实的生产调试经历：Caddy + FastAPI 双层重复 `Access-Control-Allow-Origin` 头、微应用嵌入跨域失败、环境配置不一致等问题。

| 覆盖内容 | 方式 |
|---------|------|
| **重复 CORS 头** | 检测网关 + 后端同时设置 header（最常见的 CORS bug） |
| **网关配置** | 验证 Caddyfile、nginx.conf 的 CORS 配置 |
| **微应用嵌入** | Qiankun / single-spa 的 Origin 和 URL 路径陷阱 |
| **环境分离** | 开发 vs 生产 CORS 策略审计 |
| **多源 API** | 动态 Origin 反射方案 |
| **自动化验证** | 内置 Python 脚本测试线上端点和静态配置 |

## 安装

### 通过 `npx skills`（推荐）

```bash
npx skills add psylch/cors-audit-skill -g -y
```

### 通过 Plugin Marketplace

在 Claude Code 中：

```
/plugin marketplace add psylch/cors-audit-skill
/plugin install cors-audit@psylch-cors-audit-skill
```

### 手动安装

```bash
git clone https://github.com/psylch/cors-audit-skill.git ~/.claude/skills/cors-audit-skill
```

安装后重启 Claude Code。

## 前置条件

- **Python 3.7+**（验证脚本仅使用标准库，无需 pip install）
- 一个需要审计 CORS 的 Web 项目

## 使用方式

在 Claude Code 中使用以下触发词：

```
audit CORS configuration
check CORS headers
diagnose cross-origin issue
CORS 走查
跨域问题排查
```

Skill 引导 Claude 执行 6 阶段审计流程：

1. **架构发现** — 识别所有网络层并分类架构模式
2. **配置收集** — 从每层收集 CORS 配置 + 运行静态验证
3. **单层规则** — 验证只有一层设置 CORS 头 + 线上重复检测
4. **最佳实践验证** — 检查 Origin 策略、预检、凭证、头部
5. **环境验证** — 开发/生产/微应用场景专项检查
6. **报告** — 按严重程度分类的问题清单和修复建议

## 验证脚本

内置的 `scripts/validate_cors.py` 自动化关键检查：

```bash
# 测试线上端点（检测重复头、预检问题、Origin 策略）
python scripts/validate_cors.py --url https://api.example.com/health --origin https://app.example.com

# 验证静态配置文件（Caddyfile、nginx.conf 或 JSON 策略）
python scripts/validate_cors.py --config path/to/Caddyfile

# 批量测试多个端点
python scripts/validate_cors.py --url-file endpoints.txt --origin https://app.example.com

# JSON 输出（可接入 CI）
python scripts/validate_cors.py --url https://api.example.com/health --origin https://app.example.com --format json --output report.json
```

退出码：`0` = 通过，`2` = 存在严重问题。零外部依赖。

## 覆盖的架构模式

| 模式 | 示例 | CORS 策略 |
|------|------|----------|
| **同域** | 单体应用同时提供 HTML 和 API | 不需要 CORS |
| **简单跨域** | `app.com` → `api.com` | 后端处理 CORS |
| **网关代理** | Caddy/Nginx 统一入口 | 网关处理 CORS，后端关闭 |
| **微应用嵌入** | Qiankun 嵌入宿主站 | 网关允许宿主域名 |
| **多消费者 API** | 多个前端 → 一个 API | 动态 Origin 反射 |

## 文件结构

```
cors-audit-skill/
├── .claude-plugin/
│   ├── marketplace.json
│   └── plugin.json
├── skills/
│   └── cors-audit/
│       ├── SKILL.md                        # 6 阶段审计流程
│       ├── scripts/
│       │   └── validate_cors.py            # 自动化验证脚本（纯标准库）
│       └── references/
│           ├── architecture_patterns.md    # 5 种架构模式及配置示例
│           └── cors_checklist.md           # 30+ 审计项（含通过/失败标准）
├── README.md
├── README.zh.md
└── LICENSE
```

## 许可证

MIT
