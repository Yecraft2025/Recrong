# Recrong 🐢

![Recrong Logo](./recrong-p/favicon.png)

**短信调度系统 | SMS Scheduling System**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Cloudflare-orange)](https://workers.cloudflare.com/)

[查看演示](https://recrong.yecraft.com/) | [提交反馈](https://github.com/Yecraft2025/Recrong/issues)

**免责声明**：Recrong 仅作为任务调度工具，不提供短信通道服务。用户需自行对配置的第三方 API Key 及发送的内容负责。

---

## 📖 简介 (Introduction)

**Recrong** 是一个基于 Web 的轻量级短信任务调度工具。它允许用户设置一次性或周期性的短信发送任务，并通过配置第三方短信 API 自动触发发送。

项目采用 **前后端分离** 架构，基于 **Serverless** 生态构建，稳定且安全。

> 🐢 **设计理念**：像乌龟一样稳重、长久，但关键时刻像兔子一样迅速。

## ✨ 核心特性 (Features)

*   **☁️ 云原生架构**：后端运行在 Workers，由 D1 数据库驱动。
*   **🔄 灵活调度**：支持单次任务和周期循环任务。
*   **⚡ 立即触发**：支持触发功能，紧急消息无需等待 Cron 周期。
*   **🛡️ 安全隐私**：
    *   密码采用高强度哈希存储。
    *   集成 Turnstile 人机验证。
    *   敏感数据隔离存储。
*   **⏳ 浏览器定时器**：提供无需后端的临时倒计时发送功能。

## 🛠️ 技术栈 (Tech Stack)

*   **Frontend**: HTML5, CSS3 (Inter Font), Vanilla JavaScript (No Framework).
*   **Backend**: Cloudflare Workers.
*   **Database**: Cloudflare D1 (SQLite).
*   **Deployment**: GitHub Actions & Cloudflare Pages.

## 📂 项目结构

```text
.
├── .cloudflare/             # 部署配置文件
├── recrong-p/               # 静态页面
│   ├── config.js            # 配置文件
│   ├── i18n.js              # 中英语言
│   └── ...
└── recrong-w/               # Worker 代码
│   ├── src/index.js         # API 核心逻辑
│   ├── schema.sql           # 数据库结构
│   └── ...
└── wrangler.toml        # Worker 配置文件
```

## 🚀 部署指南 (Deployment)

### 1. 创建 D1 数据库

>  本项目依赖 Cloudflare D1 数据库存储业务数据，请先完成数据库创建。

操作路径：

> Cloudflare 控制台 → **存储和数据库** → **D1 SQL 数据库** → **创建数据库**

创建时请按下表配置：

| 参数               | 配置说明               |
| ------------------ | ---------------------- |
| 数据库名称         | 自定义                 |
| 数据库结构定义文件 | `recrong-w/schema.sql` |

### 2. 部署 workers（后端服务）

点击下方按钮可一键部署 Workers：

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Yecraft2025/Recrong)

部署过程中请按以下说明填写配置项：

| 参数名称         | 配置说明                                         |
| ---------------- | ------------------------------------------------ |
| 项目名称         | 自定义                                           |
| Select D1 数据库 | 选择上一步的创建的 D1 数据库                     |
| ALLOWED_ORIGINS  | 允许访问的前端域名（可暂时留空，后续可修改）     |
| JWT_SECRET       | 自行生成一个安全字符串（如不熟悉可使用 AI 生成） |

> ⚠️ 其余配置项建议保持默认，**除非明确了解修改后的影响**。

部署完成后：

- 可选择绑定自定义域名
- 若未绑定域名，可使用 `workers.dev` 提供的地址作为**后端 API URL**

请妥善保存该 URL，后续前端配置将使用。

### 3. 部署 pages （前端）

#### 1) Fork 项目仓库

首先 Fork 本项目到你自己的 GitHub 账号。

#### 2) 修改前端配置

在 Fork 后的仓库中，打开：

```
recrong-p/config.js
```

将其中的 `API_BASE_URL` 修改为上一步部署得到的**后端 API URL**。

#### 3) 部署到 Cloudflare Pages

操作路径：

> Cloudflare 控制台 → **Pages** → **导入现有 Git 存储库** → 选择 GitHub → 授权并选择你的仓库

部署参数如下：

| 参数名称     | 配置说明    |
| ------------ | ----------- |
| 项目名称     | 自定义      |
| 生产分支     | `main`      |
| 框架预设     | 无          |
| 构建命令     | 留空        |
| 构建输出目录 | `recrong-p` |

部署完成后，可根据需要绑定自定义域名。

### 4. 配置跨域访问（重要）

前端部署完成后，请返回 **Workers** 项目：

- 将环境变量 / 机密中的 `ALLOWED_ORIGINS`
- 修改为 **Cloudflare Pages 前端访问域名**

以确保前后端跨域请求正常工作。

## 🤝 贡献 (Contributing)

欢迎提交 Issue 或 Pull Request！

1. Fork 本仓库。
2. 创建新的分支 (git checkout -b feature/AmazingFeature)。
3. 提交更改 (git commit -m 'Add some AmazingFeature')。
4. 推送到分支 (git push origin feature/AmazingFeature)。
5. 提交 Pull Request。

## 📄 版权与协议 (License)

本项目采用 **MIT 协议** 开源。
详见 [LICENSE](https://www.google.com/url?sa=E&q=LICENSE) 文件。

Copyright © 2025 Recrong. All rights reserved.
