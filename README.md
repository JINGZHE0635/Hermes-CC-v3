# Hermes Command Center (CC) v3

综合监控操作台 — 三合一：Hermes Monitor + Control Interface + ClawMetry 追踪 + 自动修复 + 交互操作 + 模型切换。

## 快速开始

\`\`\`bash
pip install -r requirements.txt
python3 hermes-cc.py
\`\`\`

访问 http://localhost:6789

默认用户名/密码通过环境变量设置：
\`\`\`bash
export MONITOR_USERNAME=admin
export MONITOR_PASSWORD=your-password
\`\`\`

## 功能

- 系统监控（CPU、内存、磁盘、网络）
- Hermes Agent 会话追踪
- 模型用量统计与费用分析
- API 余额查询
- 日志查看
- 服务状态检查与自动修复

## 依赖

- Python 3.10+
- FastAPI + Uvicorn
- Cryptography
