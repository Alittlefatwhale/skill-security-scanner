---
name: skill-security-scanner
description: 此技能用于扫描和审查其他 Claude Code Skills 是否存在恶意代码、安全漏洞或提示注入攻击。在安装或使用任何第三方skill之前，应使用此工具进行安全审计。
allowed-tools: Bash
---

# Skill Security Scanner - 技能安全扫描器

## 概述

Skill Security Scanner 是一个安全审计工具，用于检测 Claude Code Skills 中潜在的恶意行为。它可以识别反向Shell、数据窃取、命令执行、提示注入等多种安全威胁。

## 何时使用此技能

在以下场景使用此技能：

- 📥 **安装新Skill前**：审查第三方skill是否包含恶意代码
- 🔍 **定期安全审计**：检查现有skills是否被篡改
- ⚠️ **可疑行为调查**：当skill表现异常时进行深度检查
- 📋 **代码审查辅助**：快速识别安全相关的代码模式

## 快速开始

### 扫描单个Skill

```bash
python3 scripts/scan.py <skill目录路径>
```

### 扫描示例

```bash
# 扫描math-calculator技能
python3 scripts/scan.py ../math-calculator

# 输出JSON格式报告
python3 scripts/scan.py ../math-calculator --json

# 扫描单个文件
python3 scripts/scan.py ../math-calculator/scripts/calculate.py
```

## 检测能力

### 🔴 严重威胁 (CRITICAL)

| 威胁类型 | 说明 |
|---------|------|
| 反向Shell | socket连接 + dup2重定向 + shell执行 |
| 远程代码执行 | curl/wget 管道到 bash/sh |
| 键盘记录 | pynput, keyboard库等监控软件 |

### 🟠 高危威胁 (HIGH)

| 威胁类型 | 说明 |
|---------|------|
| 危险命令执行 | os.system, subprocess, eval, exec |
| 敏感文件访问 | .ssh/, .aws/, /etc/passwd 等 |
| 凭证窃取 | 读取私钥、密码文件 |
| 持久化机制 | crontab, 启动项修改 |

### 🟡 中危威胁 (MEDIUM)

| 威胁类型 | 说明 |
|---------|------|
| 网络连接 | socket, requests, urllib |
| 环境变量访问 | 可能窃取API密钥 |
| 代码混淆 | base64解码, 十六进制字符串 |
| 隐藏指令 | HTML/Markdown注释中的代码 |

### 🔵 低危/信息 (LOW/INFO)

| 威胁类型 | 说明 |
|---------|------|
| 提示注入 | 试图覆盖AI指令 |
| 输出控制 | 强制特定输出格式 |
| 角色劫持 | 定义AI角色的尝试 |
| 硬编码IP | 需要验证地址合法性 |

## 使用示例

### 场景1：审查新下载的Skill

```bash
# 下载了一个新skill后，先进行安全扫描
python3 scripts/scan.py /path/to/new-skill

# 查看输出，如果有 CRITICAL 或 HIGH 级别的发现，不要使用该skill
```

### 场景2：批量检查所有Skills

```bash
# 扫描skills目录下的所有技能
for skill in ../*/; do
    echo "=== Scanning $skill ==="
    python3 scripts/scan.py "$skill"
    echo ""
done
```

### 场景3：CI/CD集成

```bash
# 使用退出码判断风险等级
python3 scripts/scan.py ./target-skill
exit_code=$?

# 退出码说明:
# 0 = SAFE (安全)
# 1 = LOW (低风险)
# 2 = MEDIUM (中风险)
# 3 = HIGH (高风险)
# 4 = CRITICAL (严重风险)

if [ $exit_code -ge 3 ]; then
    echo "⛔ 发现高危安全问题，拒绝部署"
    exit 1
fi
```

## 报告解读

扫描完成后会生成详细报告：

```
╔══════════════════════════════════════════════════════════════╗
║              🚨 SKILL 安全扫描报告                           ║
╠══════════════════════════════════════════════════════════════╣
║  📊 扫描统计:                                                ║
║     🔴 CRITICAL: 1                                           ║
║     🔵 LOW: 1                                                ║
╠══════════════════════════════════════════════════════════════╣

────────────────────────────────────────────────────────────────
[1] 🔴 CRITICAL - 反向Shell
────────────────────────────────────────────────────────────────
📁 文件: scripts/calculate.py
📍 行号: 32
📝 描述: 检测到反向Shell代码，攻击者可获得系统控制权
💻 代码: import socket,subprocess,os;s=socket.socket...
💡 建议: 立即删除此skill，检查系统是否已被入侵
```

## 局限性

⚠️ **重要提示**：此扫描器使用模式匹配，存在以下局限：

1. **无法检测高度混淆的代码** - 如使用多层编码或加密
2. **可能存在误报** - 合法代码也可能触发警告
3. **新型攻击** - 无法检测未知的攻击模式
4. **逻辑漏洞** - 无法分析代码的运行时行为

**建议**：自动扫描结合人工审查，双重保障安全。

## 文件结构

```
skill-security-scanner/
├── SKILL.md           # 本说明文档
└── scripts/
    └── scan.py        # 安全扫描脚本
```

