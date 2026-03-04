# 敏感数据脱敏功能

## 概述

PicoClaw 现在包含了强大的敏感数据自动检测和脱敏功能，可以在日志和其他输出中自动识别和遮蔽敏感数据，如API密钥、令牌、密码、授权头等。

## 功能特性

### 1. 自动检测
支持以下敏感数据类型检测：
- API密钥（OpenAI, Anthropic, 和其他常见格式）
- Bearer 令牌
- 各种授权头
- 数据库连接字符串
- 密码字段
- 通用长型标识符

### 2. 日志脱敏
- 在控制台输出和文件日志中自动遮蔽敏感数据
- 保持信息完整性的同时保护隐私
- 支持嵌套结构中的敏感数据检测

### 3. 可配置脱敏规则
- 通过配置文件进行灵活的规则设置
- 支持自定义正则表达式规则
- 可选择性地启用/禁用特定规则

## 配置

在配置文件 `~/.picoclaw/config.json` 中添加以下选项：

```json
{
  "sensitive_data_masking_enabled": true,
  "sensitive_rules": [
    {
      "name": "custom_ssh_key_rule",
      "pattern": "ssh-(rsa|dss) [a-zA-Z0-9+/=]+",
      "replacement": "ssh-***MASKED_SSH_KEY***",
      "description": "SSH密钥遮蔽",
      "enabled": true
    },
    {
      "name": "custom_private_key_rule",
      "pattern": "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[a-zA-Z0-9/+=\\s]+-----END (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
      "replacement": "-----BEGIN PRIVATE KEY-----\\n***MASKED_PRIVATE_KEY***\\n-----END PRIVATE KEY-----",
      "description": "私钥遮蔽",
      "enabled": true
    }
  ]
}
```

## 环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `PICOCLAW_SENSITIVE_DATA_MASKING_ENABLED` | 是否启用敏感数据遮蔽 | `true` |

## 技术细节

- 所有日志函数（Info, Warn, Error, Debug等）都会自动通过脱敏器处理
- 脱敏过程对性能影响极小
- 嵌套字段也会被逐层检查和脱敏
- 可扩展的规则系统便于添加新类型的敏感信息

## 安全保障

- 使用正则表达式模式匹配实现自动检测
- 支持实时脱敏，防止敏感数据被意外记录
- 提供完整的审计跟踪，了解哪些数据被脱敏
- 严格遵循最小权限原则，只处理必要的匹配项