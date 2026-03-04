# 敏感数据脱敏功能 - 集成指南

## 概述

此功能实现了在日志中自动检测和脱敏敏感信息的能力，包括API密钥、令牌、密码和其它敏感数据。

## 配置

在您的配置文件（`~/.picoclaw/config.json`）中添加以下选项:

### 基本配置

```json
{
  "sensitive_data_masking_enabled": true
}
```

### 高级配置（包含自定义规则）

```json
{
  "sensitive_data_masking_enabled": true,
  "sensitive_rules": [
    {
      "name": "custom_api_key",
      "pattern": "custom_[A-Za-z0-9_]{8,}",
      "replacement": "REDACTED_CUSTOM_KEY",
      "description": "Custom API key format",
      "enabled": true
    },
    {
      "name": "ssh_private_key",
      "pattern": "-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9+/\\s=]+-----END OPENSSH PRIVATE KEY-----",
      "replacement": "-----BEGIN OPENSSH PRIVATE KEY----- REDACTED -----END OPENSSH PRIVATE KEY-----",
      "description": "SSH private key",
      "enabled": true
    }
  ]
}
```

## 环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `PICOCLAW_SENSITIVE_DATA_MASKING_ENABLED` | 是否启用敏感数据遮蔽 | `true` |

## 支持的规则

默认情况下，系统会自动检测以下类型的敏感数据：

- OpenAI API密钥（格式: `sk-...`)
- Anthropic API密钥（格式: `sk-ant-...`）
- Bearer Tokens
- 各种认证头信息
- 数据库连接字符串
- 密码字段（password, pwd, pass等）

## 自定义规则

您可以添加自己的规则来捕捉特有的敏感信息格式。
规则使用正则表达式定义，支持以下字段：

- `name`: 规则名称
- `pattern`: 正则表达式模式
- `replacement`: 替换文本（可包含捕获组引用）
- `description`: 可选的描述
- `enabled`: 是否启用此规则

## 实现细节

该功能集成到了现有的日志系统中。每个日志消息和字段在输出前都会通过敏感数据检测器进行处理。这确保了无论是控制台输出还是文件日志都会包含脱敏数据。

### 性能影响

该系统的性能影响很小，仅在写日志时进行一次正则匹配操作。
默认提供的规则数量有限，不会显著影响性能。