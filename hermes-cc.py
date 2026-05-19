#!/usr/bin/env python3
"""
Hermes Command Center v2.0 — 综合监控操作台

三合一：Hermes Monitor + Control Interface + ClawMetry 追踪
+ 自动修复 + 交互操作 + 模型切换

Usage:
  hermes-cc.py                  # 启动 Web 面板 (默认 6789)
  hermes-cc.py --port 8888      # 指定端口
  hermes-cc.py --check          # CLI 检查
  hermes-cc.py --alert          # QQ 告警推送
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import time
import traceback
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from cryptography.fernet import Fernet

# ── 加密 ──
_ENCRYPTION_KEY_FILE = Path.home() / ".hermes" / "memory" / ".encryption_key"
def _get_cipher():
    if _ENCRYPTION_KEY_FILE.exists():
        key = _ENCRYPTION_KEY_FILE.read_bytes()
    else:
        key = Fernet.generate_key()
        _ENCRYPTION_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _ENCRYPTION_KEY_FILE.write_bytes(key)
        os.chmod(_ENCRYPTION_KEY_FILE, 0o600)
    return Fernet(key)

def _encrypt(plain: str) -> str:
    if not plain:
        return ""
    return _get_cipher().encrypt(plain.encode()).decode()

def _decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _get_cipher().decrypt(token.encode()).decode()
    except Exception:
        # fallback for plaintext keys from before encryption was added
        return token

# ── 路径 ──
HERMES_HOME = Path.home() / ".hermes"
LOG_DIR = HERMES_HOME / "logs"
SCRIPTS_DIR = HERMES_HOME / "scripts"
MONITOR_DB = HERMES_HOME / "memory" / "monitor.db"
AGENT_DIR = HERMES_HOME / "hermes-agent"
VENV_PY = str(AGENT_DIR / "venv" / "bin" / "python3")
HERMES_BIN = str(Path.home() / ".local" / "bin")
MONITOR_DB.parent.mkdir(parents=True, exist_ok=True)

def env_with_path():
    """返回包含 hermes 命令路径的环境变量"""
    e = dict(os.environ)
    e["PATH"] = f"{HERMES_BIN}:{AGENT_DIR}/venv/bin:{e.get('PATH', '')}"
    return e

# ── 登录 ──
MONITOR_USERNAME = os.environ.get("MONITOR_USERNAME") or "admin"
MONITOR_PASSWORD = os.environ.get("MONITOR_PASSWORD") or "hermes123"
MONITOR_TOKEN_SALT = "hermes-cc-v2-salt"

def hash_password(pw: str) -> str:
    return hashlib.sha256((pw + MONITOR_TOKEN_SALT).encode()).hexdigest()[:16]

def check_login(username: str, password: str) -> bool:
    return username == MONITOR_USERNAME and password == MONITOR_PASSWORD

def verify_token(token: str) -> bool:
    expected = hash_password(MONITOR_PASSWORD)
    return secrets.compare_digest(token, expected)

CONFIG = {
    "web_port": 6789,
    "refresh_interval": 15,
    "check_interval": 60,
    "alert_cooldown": 300,
    "history_retention_days": 7,
    "error_threshold": 5,
    "disk_warn_pct": 80, "disk_crit_pct": 92,
    "mem_warn_pct": 85, "mem_crit_pct": 95,
    "t1_warn_pct": 95,
    "t1_user_warn_pct": 90,
}

# ═══════════════════════════════════════════════════════════
# DB
# ═══════════════════════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(str(MONITOR_DB), check_same_thread=False)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, data TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_sn_ts ON snapshots(ts);
        CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, type TEXT NOT NULL, message TEXT NOT NULL, level TEXT DEFAULT 'warn', acknowledged INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_al_ts ON alerts(ts);
        CREATE TABLE IF NOT EXISTS alert_cooldown (type TEXT PRIMARY KEY, last_alert INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, action TEXT NOT NULL, target TEXT, result TEXT, status TEXT DEFAULT 'done');
        CREATE TABLE IF NOT EXISTS sessions_track (id TEXT PRIMARY KEY, ts TEXT NOT NULL, model TEXT, messages INTEGER DEFAULT 0, tokens INTEGER DEFAULT 0, tool_calls INTEGER DEFAULT 0, duration_sec REAL DEFAULT 0, status TEXT DEFAULT 'active');
        DELETE FROM snapshots WHERE ts < datetime('now', '-7 days');
    """)
    conn.commit()
    return conn

# ═══════════════════════════════════════════════════════════
# SERVICE DETECTION
# ═══════════════════════════════════════════════════════════

_SERVICE_DEFS = [
    ("gateway", "🔁", "消息网关 (QQ/TG/飞书)", ["gateway"], True),
    ("daemon", "⚙️", "后台调度器", ["daemon.py"], True),
    ("proxy", "🔌", "智能代理", ["smart-proxy"], True),
    ("cli", "💻", "当前会话", ["hermes_cli.main"], False),
    ("tat", "🛡️", "TAT 安全代理", ["tat_agent"], True),
    ("launcher", "🤖", "分身调度器", ["agent-launcher"], False),
    ("dashboard", "📊", "Web 面板 (9119)", ["hermes.*dashboard"], False),
]

def check_process(keywords: List[str]) -> Dict:
    try:
        for kw in keywords:
            r = subprocess.run(["pgrep", "-f", kw], capture_output=True, text=True, timeout=5)
            pids = r.stdout.strip().split()
            if pids and pids[0]:
                mr = subprocess.run(["ps", "-o", "rss=", "-p", pids[0]], capture_output=True, text=True, timeout=3)
                mem_kb = int(mr.stdout.strip()) if mr.stdout.strip().isdigit() else 0
                # CPU
                cr = subprocess.run(["ps", "-o", "%cpu=", "-p", pids[0]], capture_output=True, text=True, timeout=3)
                cpu = cr.stdout.strip() or "0"
                return {"active": True, "pids": pids[:5], "count": len(pids), "memory_mb": round(mem_kb / 1024), "cpu": cpu}
    except Exception:
        pass
    return {"active": False, "pids": [], "count": 0, "memory_mb": 0, "cpu": "0"}

def get_all_services() -> Dict:
    svcs = {}
    for name, icon, desc, kws, essential in _SERVICE_DEFS:
        info = check_process(kws)
        info["essential"] = essential
        svcs[name] = {"name": name.capitalize(), "icon": icon, "desc": desc, **info}
    return svcs

# ═══════════════════════════════════════════════════════════
# SYSTEM
# ═══════════════════════════════════════════════════════════

def get_system_stats() -> Dict:
    import psutil
    cpu_pct = psutil.cpu_percent(interval=0.3)
    cpu_load = psutil.getloadavg()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    boot = datetime.fromtimestamp(psutil.boot_time())
    up = datetime.now() - boot
    return {
        "cpu_pct": round(cpu_pct, 1), "cpu_load": [round(x,2) for x in cpu_load],
        "mem_pct": round(mem.percent,1), "mem_used_gb": round(mem.used/1024**3,1),
        "mem_total_gb": round(mem.total/1024**3,1), "mem_avail_gb": round(mem.available/1024**3,1),
        "disk_pct": round(disk.percent,1), "disk_used_gb": round(disk.used/1024**3,1),
        "disk_total_gb": round(disk.total/1024**3,1), "disk_free_gb": round(disk.free/1024**3,1),
        "net_sent_mb": round(net.bytes_sent/1024**2,1), "net_recv_mb": round(net.bytes_recv/1024**2,1),
        "uptime_days": up.days, "uptime_hours": up.seconds//3600,
    }

# ═══════════════════════════════════════════════════════════
# LOG SCANNER
# ═══════════════════════════════════════════════════════════

def scan_logs(minutes: int = 30) -> Dict:
    results = {"errors": [], "warnings": [], "error_count": 0, "warning_count": 0, "by_file": {}}
    patterns = [
        (r"(?i)(error|critical|fatal|exception|traceback)", "error"),
        (r"(?i)(timeout|timed ?out)", "timeout"),
        (r"(?i)(connection refused|connection reset)", "connection"),
        (r"(?i)(rate limit|429)", "ratelimit"),
        (r"(?i)(OOM|out of memory|cannot allocate)", "oom"),
    ]
    for lf in sorted(LOG_DIR.glob("*.log")):
        if lf.name == "monitor.log" or "diag" in lf.name or "shutdown" in lf.name or lf.name.startswith("backup-"):
            continue
        if not lf.exists() or lf.stat().st_size == 0:
            continue
        try:
            r = subprocess.run(["tail", "-500", str(lf)], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if not line.strip():
                    continue
                if re.search(r"(?i)\bWARNING\b", line):
                    results["warnings"].append(line[:200])
                    results["warning_count"] += 1
                    results["by_file"][lf.name] = results["by_file"].get(lf.name, 0) + 1
                for pat, cat in patterns:
                    if re.search(pat, line):
                        results["errors"].append({"file": lf.name, "text": line[:250], "cat": cat})
                        results["error_count"] += 1
                        results["by_file"][lf.name] = results["by_file"].get(lf.name, 0) + 1
                        break
        except Exception:
            pass
    results["errors"] = results["errors"][:30]
    results["warnings"] = results["warnings"][:20]
    return results

# ═══════════════════════════════════════════════════════════
# MEMORY / TOKEN
# ═══════════════════════════════════════════════════════════

def get_memory_stats() -> Dict:
    mf = HERMES_HOME / "memories" / "MEMORY.md"
    uf = HERMES_HOME / "memories" / "USER.md"
    r = {"t1_mem_chars": 0, "t1_user_chars": 0, "t1_mem_max": 6000, "t1_user_max": 2000, "t2_count": 0}
    if mf.exists(): r["t1_mem_chars"] = len(mf.read_text(encoding="utf-8"))
    if uf.exists(): r["t1_user_chars"] = len(uf.read_text(encoding="utf-8"))
    try:
        db = HERMES_HOME / "memory" / "memory.db"
        if db.exists():
            c = sqlite3.connect(str(db)).cursor()
            r["t2_count"] = c.execute("SELECT count(*) FROM memories").fetchone()[0]
    except: pass
    r["t1_mem_pct"] = round(r["t1_mem_chars"] / r["t1_mem_max"] * 100, 1)
    r["t1_user_pct"] = round(r["t1_user_chars"] / r["t1_user_max"] * 100, 1)
    return r

def get_token_info() -> Dict:
    r = {"balance": "?", "today_cost": "?", "month_cost": "?", "model": "?", "provider": "?"}
    try:
        # Read current model from config.yaml
        cf = HERMES_HOME / "config.yaml"
        if cf.exists():
            import yaml
            with open(cf) as f:
                cfg = yaml.safe_load(f) or {}
            mc = cfg.get("model", {})
            r["model"] = mc.get("default", "?")
            r["provider"] = mc.get("provider", "?")
        # Read balance from .env
        env = HERMES_HOME / ".env"
        if env.exists():
            for line in env.read_text().splitlines():
                if "DEEPSEEK_BALANCE" in line.upper() or "BALANCE" in line.upper():
                    r["balance"] = line.split("=",1)[-1].strip().strip('"\'')
    except Exception as e:
        r["model"] = str(e)[:50]
    return r

# ═══════════════════════════════════════════════════════════
# TOKEN COST ANALYSIS (v3.1 — revamped parser)
# ═══════════════════════════════════════════════════════════

MODEL_PRICING = {
    "deepseek-v4-pro": {"input": 2.86, "output": 8.57, "unit": "¥/M tokens"},
    "deepseek-v4-flash": {"input": 0.29, "output": 1.14, "unit": "¥/M tokens"},
    "deepseek-coder": {"input": 0.29, "output": 1.14, "unit": "¥/M tokens"},
    "gpt-5.5": {"input": 3.57, "output": 14.29, "unit": "¥/M tokens"},
    "gpt-5.4": {"input": 2.14, "output": 8.57, "unit": "¥/M tokens"},
    "gpt-5.4-mini": {"input": 0.43, "output": 1.71, "unit": "¥/M tokens"},
    "gpt-5.3-codex": {"input": 0.43, "output": 1.71, "unit": "¥/M tokens"},
    "glm-4v-flash": {"input": 0, "output": 0, "unit": "免费"},
    "qwen3.6-plus": {"input": 0, "output": 0, "unit": "免费(1M上下文)"},
}

TOKEN_MODEL_ALIASES = {
    "deepseek-v4-pro": "Pro",
    "deepseek-v4-flash": "Flash", 
    "deepseek-coder": "Coder",
    "gpt-5.5": "GPT-5.5",
    "gpt-5.4": "GPT-5.4",
    "gpt-5.4-mini": "GPT-5.4M",
    "gpt-5.3-codex": "Codex",
    "glm-4v-flash": "GLM-4V",
    "qwen3.6-plus": "Qwen3.6+",
}

def get_token_costs() -> Dict:
    """Parse agent.log API call lines: model=X in=N out=N total=N"""
    today = datetime.now().strftime("%Y-%m-%d")
    week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    month_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

    result = {
        "today": {"total_tokens": 0, "total_cost": 0.0, "by_model": {}},
        "week": {"total_tokens": 0, "total_cost": 0.0, "by_model": {}},
        "month": {"total_tokens": 0, "total_cost": 0.0, "by_model": {}},
        "daily": {},
    }

    try:
        lf = LOG_DIR / "agent.log"
        if not lf.exists():
            return result

        # Use tail + grep for performance
        r = subprocess.run(
            ["grep", "API call #", str(lf)],
            capture_output=True, text=True, timeout=15
        )
        lines = r.stdout.splitlines()

        # Parse: "API call #N: model=DEEPSEEK-V4-PRO ... in=22337 out=215 total=22552"
        api_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2}).*API call.*model=([\w.-]+).*in=(\d+)\s+out=(\d+)\s+total=(\d+)"
        )

        for line in lines[-10000:]:
            m = api_pattern.search(line)
            if not m:
                continue
            line_date = m.group(1)
            model_name = m.group(2).lower()
            in_tokens = int(m.group(3))
            # out_tokens = int(m.group(4))  # not used separately
            total_tokens = int(m.group(5))

            if not line_date or total_tokens <= 0:
                continue

            # Short alias for display
            model_alias = TOKEN_MODEL_ALIASES.get(model_name, model_name)

            # Calculate cost: input tokens * input_price + output tokens * output_price
            pricing = MODEL_PRICING.get(model_name, {"input": 0.5, "output": 2})
            cost = (in_tokens * pricing["input"] + (total_tokens - in_tokens) * pricing["output"]) / 1_000_000

            def add_to_period(pd):
                pd["total_tokens"] += total_tokens
                pd["total_cost"] = round(pd["total_cost"] + cost, 4)
                if model_alias not in pd["by_model"]:
                    pd["by_model"][model_alias] = {"tokens": 0, "cost": 0.0, "calls": 0}
                pd["by_model"][model_alias]["tokens"] += total_tokens
                pd["by_model"][model_alias]["cost"] = round(pd["by_model"][model_alias]["cost"] + cost, 4)
                pd["by_model"][model_alias]["calls"] += 1

            # Today / Week / Month
            if line_date == today:
                add_to_period(result["today"])
            if line_date >= week_ago:
                add_to_period(result["week"])
            if line_date >= month_ago:
                add_to_period(result["month"])

            # Daily
            if line_date not in result["daily"]:
                result["daily"][line_date] = {"total_tokens": 0, "total_cost": 0.0, "by_model": {}}
            add_to_period(result["daily"][line_date])

    except Exception as e:
        result["error"] = str(e)[:100]

    return result

# ═══════════════════════════════════════════════════════════
# NETWORK HISTORY (v3.0 — from hermes-monitor)
# ═══════════════════════════════════════════════════════════

def get_network_history(conn, hours: int = 24) -> List:
    """从 DB 快照中提取网络流量历史"""
    cut = (datetime.now() - timedelta(hours=hours)).isoformat()
    try:
        rows = conn.cursor().execute(
            "SELECT ts, data FROM snapshots WHERE ts > ? ORDER BY ts", (cut,)
        ).fetchall()
        history = []
        for row in rows:
            d = json.loads(row[1])
            sys_ = d.get("system", {})
            history.append({
                "ts": row[0],
                "net_sent_mb": sys_.get("net_sent_mb", 0),
                "net_recv_mb": sys_.get("net_recv_mb", 0),
            })
        return history
    except: return []

# ═══════════════════════════════════════════════════════════
# SESSION TRACKING (ClawMetry-style)
# ═══════════════════════════════════════════════════════════

def track_sessions(conn) -> Dict:
    """从 agent.log 提取会话信息 — 解析 conversation turn 和 Turn ended"""
    c = conn.cursor()
    today = datetime.now().strftime("%Y-%m-%d")
    result = {"active": 0, "today": 0, "total_tokens": 0, "total_calls": 0, "recent": []}
    try:
        lf = LOG_DIR / "agent.log"
        if not lf.exists():
            return result

        # Collect all conversation turns and turn ends
        r = subprocess.run(
            ["grep", "-E", r"(conversation turn:|Turn ended:|API call #)",
             str(lf)], capture_output=True, text=True, timeout=15
        )
        lines = r.stdout.splitlines()

        # Parse unique sessions
        sessions = set()
        today_sessions = set()
        total_tokens = 0
        total_calls = 0
        recent_sessions = []

        api_pattern = re.compile(r"total=(\d+)")
        turn_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2}).*Turn ended.*api_calls=(\d+).*session=(\S+)"
        )
        start_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2}).*conversation turn:.*session=(\S+)"
        )

        for line in lines:
            # Count API call tokens
            m = api_pattern.search(line)
            if m:
                total_tokens += int(m.group(1))
                total_calls += 1

            # Track sessions from "conversation turn" starts
            m = start_pattern.search(line)
            if m:
                date = m.group(1)
                sid = m.group(2)
                sessions.add(sid)
                if date == today:
                    today_sessions.add(sid)
                if len(recent_sessions) < 5:
                    recent_sessions.append({
                        "sid": sid, "date": date,
                        "line": line[11:150] if len(line) > 11 else line[:150]
                    })

        result["today"] = len(today_sessions)
        result["active"] = len(sessions)  # total unique sessions in log
        result["total_tokens"] = total_tokens
        result["total_calls"] = total_calls
        result["recent"] = recent_sessions

    except Exception as e:
        result["error"] = str(e)[:100]

    return result

# ═══════════════════════════════════════════════════════════
# MODEL MANAGEMENT
# ═══════════════════════════════════════════════════════════

def list_models() -> List[Dict]:
    """获取可用模型列表"""
    models = []
    try:
        r = subprocess.run(["hermes", "model", "list", "--json"], capture_output=True, text=True, timeout=15,
                          env=env_with_path(), cwd=str(AGENT_DIR))
        if r.stdout.strip():
            data = json.loads(r.stdout)
            if isinstance(data, list):
                return data
    except: pass
    # Fallback: known models
    return [
        {"name": "deepseek-v4-flash", "provider": "deepseek", "cost": "¥2/M"},
        {"name": "deepseek-v4-pro", "provider": "deepseek", "cost": "¥16/M"},
        {"name": "deepseek-coder", "provider": "deepseek", "cost": "¥2/M"},
        {"name": "gpt-5.5", "provider": "nimabo", "cost": "¥?"},
        {"name": "gpt-5.4-mini", "provider": "nimabo", "cost": "¥?"},
        {"name": "glm-4v-flash", "provider": "zhipu", "cost": "免费"},
        {"name": "qwen3.6-plus", "provider": "alibaba", "cost": "免费(1M)"},
    ]

def switch_model(model_name: str, provider: str = None) -> Dict:
    """切换模型"""
    try:
        # Set model name
        r1 = subprocess.run(
            ["hermes", "config", "set", "model.default", model_name],
            capture_output=True, text=True, timeout=15, env=env_with_path(),
            cwd=str(AGENT_DIR)
        )
        # Set provider if given
        if provider:
            r2 = subprocess.run(
                ["hermes", "config", "set", "model.default_provider", provider],
                capture_output=True, text=True, timeout=15, env=env_with_path(),
                cwd=str(AGENT_DIR)
            )
            output = (r1.stdout + r2.stdout + r1.stderr + r2.stderr)[:200]
            success = r1.returncode == 0 and r2.returncode == 0
        else:
            output = (r1.stdout + r1.stderr)[:200]
            success = r1.returncode == 0
        return {"success": success, "output": output, "model": model_name}
    except Exception as e:
        return {"success": False, "output": str(e), "model": model_name}

# ═══════════════════════════════════════════════════════════
# AUTO-FIX ENGINE
# ═══════════════════════════════════════════════════════════

_AUTO_FIX_RULES = [
    {"id": "fix_gateway", "name": "Gateway 自动重启", "enabled": True,
     "condition": lambda s: not s["services"].get("gateway", {}).get("active"),
     "action": "systemctl --user restart hermes-gateway 2>/dev/null || true",
     "desc": "Gateway 离线时自动拉起来"},
    {"id": "fix_daemon", "name": "Daemon 自动重启", "enabled": True,
     "condition": lambda s: not s["services"].get("daemon", {}).get("active"),
     "action": f"cd {AGENT_DIR} && {VENV_PY} daemon.py restart 2>/dev/null || true",
     "desc": "Daemon 离线时自动拉起来"},
    {"id": "compact_memory", "name": "T1 记忆自动压缩", "enabled": True,
     "condition": lambda s: s.get("memory", {}).get("t1_mem_pct", 0) > 97,
     "action": f"{VENV_PY} {SCRIPTS_DIR}/memory-compactor.py --apply 2>/dev/null || true",
     "desc": "T1 记忆 > 90% 时自动压缩"},
    {"id": "clean_logs", "name": "日志自动清理", "enabled": True,
     "condition": lambda s: s.get("system", {}).get("disk_pct", 0) > CONFIG["disk_crit_pct"],
     "action": f"find {LOG_DIR} -name '*.log' -size +50M -exec truncate -s 10M {{}} \\; 2>/dev/null || true",
     "desc": "磁盘 > 92% 时截断大日志"},
    {"id": "switch_cheap", "name": "自动切廉价模型", "enabled": False,
     "condition": lambda s: False,  # 手动触发
     "action": f"hermes config set model.default deepseek-v4-flash 2>/dev/null || true",
     "desc": "手动切换到 Flash 省钱模式"},
]

def run_auto_fix(snapshot: Dict, conn) -> List[Dict]:
    """执行自动修复规则"""
    fixes = []
    for rule in _AUTO_FIX_RULES:
        if not rule["enabled"]:
            continue
        try:
            if rule["condition"](snapshot):
                r = subprocess.run(rule["action"], shell=True, capture_output=True, text=True, timeout=30)
                result = "ok" if r.returncode == 0 else f"fail: {r.stderr[:100]}"
                fixes.append({"rule": rule["id"], "name": rule["name"], "result": result, "output": r.stdout[:100]})
                c = conn.cursor()
                c.execute("INSERT INTO actions (ts, action, target, result, status) VALUES (?,?,?,?,?)",
                          (datetime.now().isoformat(), rule["id"], rule["name"], result, "done"))
                conn.commit()
        except Exception as e:
            fixes.append({"rule": rule["id"], "name": rule["name"], "result": f"error: {str(e)[:50]}"})
    return fixes

def execute_action(action_id: str, target: str = None) -> Dict:
    """手动执行操作"""
    actions = {
        "restart_gateway": "systemctl --user restart hermes-gateway 2>/dev/null && echo ok || echo fail",
        "restart_daemon": f"cd {AGENT_DIR} && {VENV_PY} daemon.py restart 2>/dev/null && echo ok || echo fail",
        "restart_monitor": "systemctl --user restart hermes-monitor 2>/dev/null && echo ok || echo fail",
        "compact_memory": f"{VENV_PY} {SCRIPTS_DIR}/memory-compactor.py --apply 2>/dev/null && echo ok || echo fail",
        "clean_logs": f"find {LOG_DIR} -name '*.log' -size +20M | head -3 | while read f; do truncate -s 5M \"$f\"; done; echo ok",
        "health_check": f"{SCRIPTS_DIR}/health-check.sh 2>/dev/null && echo ok || echo fail",
        "run_backup": f"{SCRIPTS_DIR}/backup-daily.sh 2>/dev/null && echo ok || echo fail",
        "switch_flash": f"export PATH={HERMES_BIN}:{AGENT_DIR}/venv/bin:$PATH && cd {AGENT_DIR} && hermes config set model.default deepseek-v4-flash 2>/dev/null && echo ok || echo fail",
        "switch_pro": f"export PATH={HERMES_BIN}:{AGENT_DIR}/venv/bin:$PATH && cd {AGENT_DIR} && hermes config set model.default deepseek-v4-pro 2>/dev/null && echo ok || echo fail",
        "reload_gateway": "pkill -HUP -f 'gateway.*run' 2>/dev/null; echo ok",
        "restart_launcher": f"pkill -f agent-launcher 2>/dev/null; sleep 1; cd {AGENT_DIR} && {VENV_PY} {SCRIPTS_DIR}/agent-launcher.py run 2>/dev/null & sleep 2 && echo ok || echo fail",
        "restart_dashboard": f"pkill -f 'hermes.*dashboard.*--port' 2>/dev/null; sleep 1; cd {AGENT_DIR} && {VENV_PY} -m hermes_cli.main dashboard --skip-build 2>/dev/null & sleep 2 && echo ok || echo fail",
    }
    cmd = actions.get(action_id)
    if not cmd:
        return {"success": False, "error": f"Unknown action: {action_id}"}
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        ok = "ok" in r.stdout.lower()
        return {"success": ok, "output": (r.stdout + r.stderr)[:200]}
    except Exception as e:
        return {"success": False, "error": str(e)[:100]}

# ═══════════════════════════════════════════════════════════
# SNAPSHOT
# ═══════════════════════════════════════════════════════════

def take_snapshot(conn=None) -> Dict:
    t0 = time.time()
    snap = {
        "ts": datetime.now().isoformat(),
        "services": get_all_services(),
        "system": get_system_stats(),
        "logs": scan_logs(),
        "memory": get_memory_stats(),
        "token": get_token_info(),
    }

    # Health score
    score = 100
    issues = []
    for n, s in snap["services"].items():
        if not s.get("active") and s.get("essential", True):
            score -= 10; issues.append(f"{s['name']} 离线")
        elif not s.get("active") and not s.get("essential", True):
            pass  # 非核心服务离线不告警
    sys_ = snap["system"]
    if sys_["disk_pct"] > CONFIG["disk_warn_pct"]: score -= 10; issues.append(f"磁盘 {sys_['disk_pct']}%")
    if sys_["disk_pct"] > CONFIG["disk_crit_pct"]: score -= 10
    if sys_["mem_pct"] > CONFIG["mem_warn_pct"]: score -= 10; issues.append(f"内存 {sys_['mem_pct']}%")
    if sys_["mem_pct"] > CONFIG["mem_crit_pct"]: score -= 10
    if sys_["cpu_pct"] > 90: score -= 5; issues.append(f"CPU {sys_['cpu_pct']}%")
    ec = snap["logs"]["error_count"]
    if ec > CONFIG["error_threshold"]: score -= min(20, ec*2); issues.append(f"日志 {ec} 条 ERROR")
    mem = snap["memory"]
    if mem["t1_mem_pct"] > CONFIG["t1_warn_pct"]: score -= 10; issues.append(f"T1 {mem['t1_mem_pct']}%")
    if mem.get("t1_user_pct", 0) > CONFIG.get("t1_user_warn_pct", 90): score -= 5
    score = max(0, min(100, score))
    level = "healthy" if score >= 80 else ("warning" if score >= 50 else "critical")
    snap["health"] = {"score": score, "level": level, "issues": issues[:10], "issue_count": len(issues)}
    snap["elapsed_ms"] = round((time.time()-t0)*1000)

    # Save
    if conn:
        c = conn.cursor()
        c.execute("INSERT INTO snapshots (ts, data) VALUES (?,?)", (snap["ts"], json.dumps(snap, ensure_ascii=False)))
        conn.commit()

    return snap

# ═══════════════════════════════════════════════════════════
# HEALTH HISTORY
# ═══════════════════════════════════════════════════════════

def get_health_history(conn, hours=24) -> List:
    cut = (datetime.now() - timedelta(hours=hours)).isoformat()
    rows = conn.cursor().execute("SELECT ts, data FROM snapshots WHERE ts > ? ORDER BY ts", (cut,)).fetchall()
    return [{"ts": r[0], "score": json.loads(r[1])["health"]["score"], "level": json.loads(r[1])["health"]["level"]} for r in rows]

# ═══════════════════════════════════════════════════════════
# ALERT ENGINE
# ═══════════════════════════════════════════════════════════

def check_alerts(snap, conn) -> List:
    alerts = []
    now = int(time.time())
    c = conn.cursor()

    def should(t): return not c.execute("SELECT 1 FROM alert_cooldown WHERE type=? AND last_alert>?", (t, now-CONFIG["alert_cooldown"])).fetchone()
    def mark(t): c.execute("INSERT OR REPLACE INTO alert_cooldown VALUES(?,?)", (t, now)); conn.commit()

    for n, s in snap["services"].items():
        if not s.get("active") and s.get("essential", True) and should(f"svc_{n}"):
            alerts.append({"type": f"svc_{n}", "message": f"❌ {s['name']} 离线", "level": "error"}); mark(f"svc_{n}")
    if snap["system"]["disk_pct"] > CONFIG["disk_warn_pct"] and should("disk"):
        alerts.append({"type": "disk", "message": f"💾 磁盘 {snap['system']['disk_pct']}%", "level": "warn"}); mark("disk")
    if snap["system"]["mem_pct"] > CONFIG["mem_warn_pct"] and should("mem"):
        alerts.append({"type": "mem", "message": f"🧠 内存 {snap['system']['mem_pct']}%", "level": "warn"}); mark("mem")
    if snap["logs"]["error_count"] > CONFIG["error_threshold"] and should("err"):
        alerts.append({"type": "err", "message": f"📋 {snap['logs']['error_count']} 条 ERROR", "level": "warn"}); mark("err")

    for a in alerts:
        c.execute("INSERT INTO alerts (ts, type, message, level) VALUES (?,?,?,?)",
                  (datetime.now().isoformat(), a["type"], a["message"], a["level"]))
    conn.commit()
    return alerts

def push_qq(msg):
    try:
        safe = msg.replace('"', '\\"')
        subprocess.run(["hermes", "send", "--to", "qqbot", "--subject", "🔔 监控", safe], capture_output=True, text=True, timeout=15, env=env_with_path(), cwd=str(AGENT_DIR))
    except: pass

# ═══════════════════════════════════════════════════════════
# WEB SERVER
# ═══════════════════════════════════════════════════════════

def run_web(port):
    from fastapi import FastAPI, Request, WebSocket
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from uvicorn.config import Config as UConfig
    from uvicorn.server import Server

    app = FastAPI(title="Hermes CC", version="3.0")

    # Mount font files from Hermes web_dist
    WEB_DIST = AGENT_DIR / "hermes_cli" / "web_dist"
    fonts_dir = WEB_DIST / "fonts"
    fonts_terminal_dir = WEB_DIST / "fonts-terminal"
    if fonts_dir.exists():
        app.mount("/fonts", StaticFiles(directory=str(fonts_dir)), name="fonts")
    if fonts_terminal_dir.exists():
        app.mount("/fonts-terminal", StaticFiles(directory=str(fonts_terminal_dir)), name="fonts-terminal")
    conn = init_db()

    # Track auto-fix thread state
    fix_thread_running = [False]
    fix_results_holder = [[]]

    # ── Auth middleware ──
    PUBLIC_PATHS = {"/", "/api/login", "/favicon.ico"}

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/api/login"):
            return await call_next(request)

        if path.startswith("/api/"):
            auth = request.headers.get("Authorization", "")
            token = auth.replace("Bearer ", "").strip()
            if not verify_token(token):
                return JSONResponse({"error": "unauthorized"}, status_code=401)

        return await call_next(request)

    @app.post("/api/login")
    async def api_login(request: Request):
        try:
            body = await request.json()
            user = body.get("username", "")
            pw = body.get("password", "")
            if check_login(user, pw):
                token = hash_password(pw)
                return {"success": True, "token": token, "username": user}
            return {"success": False, "error": "用户名或密码错误"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── API ──

    @app.get("/api/snapshot")
    def api_snapshot():
        s = take_snapshot(conn)
        s["history"] = get_health_history(conn)
        s["sessions"] = track_sessions(conn)
        return s

    @app.get("/api/health")
    def api_health():
        s = take_snapshot(conn)
        return {"status":"ok", "score":s["health"]["score"], "level":s["health"]["level"],
                "services":sum(1 for v in s["services"].values() if v.get("active")), "total":len(s["services"]),
                "error_count":s["logs"]["error_count"], "disk":s["system"]["disk_pct"], "mem":s["system"]["mem_pct"]}

    @app.get("/api/services")
    def api_services(): return get_all_services()

    @app.get("/api/system")
    def api_system(): return get_system_stats()

    @app.get("/api/logs")
    def api_logs(minutes:int=30): return scan_logs(minutes)

    @app.get("/api/alerts")
    def api_alerts(limit:int=30):
        rows = conn.cursor().execute("SELECT ts,type,message,level,acknowledged FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts":r[0],"type":r[1],"message":r[2],"level":r[3],"acknowledged":r[4]} for r in rows]

    @app.get("/api/actions/log")
    def api_actions_log(limit:int=20):
        rows = conn.cursor().execute("SELECT ts,action,target,result,status FROM actions ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts":r[0],"action":r[1],"target":r[2],"result":r[3],"status":r[4]} for r in rows]

    @app.get("/api/models")
    def api_models(): return {"models": list_models(), "current": get_token_info()["model"]}

    @app.get("/api/sessions")
    def api_sessions():
        s = track_sessions(conn)
        return s

    @app.get("/api/rules")
    def api_rules():
        return [{"id":r["id"],"name":r["name"],"enabled":r["enabled"],"desc":r["desc"]} for r in _AUTO_FIX_RULES]

    @app.post("/api/action/{action_id}")
    def api_action(action_id: str, target: str = None):
        result = execute_action(action_id, target)
        c = conn.cursor()
        c.execute("INSERT INTO actions (ts,action,target,result,status) VALUES (?,?,?,?,?)",
                  (datetime.now().isoformat(), action_id, target or "", json.dumps(result), "done" if result.get("success") else "fail"))
        conn.commit()
        return result

    @app.post("/api/model/switch")
    def api_model_switch(name: str, provider: str = None):
        r = switch_model(name, provider)
        c = conn.cursor()
        c.execute("INSERT INTO actions (ts,action,target,result) VALUES (?,?,?,?)",
                  (datetime.now().isoformat(), "switch_model", f"{name}@{provider}", json.dumps(r)))
        conn.commit()
        return r

    @app.post("/api/rule/toggle")
    def api_rule_toggle(rule_id: str, enabled: bool):
        for r in _AUTO_FIX_RULES:
            if r["id"] == rule_id:
                r["enabled"] = enabled
                return {"success": True, "rule": rule_id, "enabled": enabled}
        return {"success": False, "error": "Rule not found"}

    @app.post("/api/run-fix")
    def api_run_fix():
        s = take_snapshot(conn)
        fixes = run_auto_fix(s, conn)
        return {"fixes": fixes, "count": len(fixes)}

    @app.post("/api/rule/run")
    def api_rule_run(rule_id: str):
        """手动执行某条规则"""
        for rule in _AUTO_FIX_RULES:
            if rule["id"] == rule_id:
                r = subprocess.run(rule["action"], shell=True, capture_output=True, text=True, timeout=30)
                ok = r.returncode == 0
                c = conn.cursor()
                c.execute("INSERT INTO actions (ts,action,target,result,status) VALUES (?,?,?,?,?)",
                          (datetime.now().isoformat(), f"manual_{rule_id}", rule["name"], r.stdout[:100], "done" if ok else "fail"))
                conn.commit()
                return {"success": ok, "name": rule["name"], "output": (r.stdout+r.stderr)[:200]}
        return {"success": False, "error": "Rule not found"}

    # ── v3.0 NEW APIs ──
    @app.get("/api/token/costs")
    def api_token_costs(): return get_token_costs()

    @app.get("/api/system/network-history")
    def api_network_history(hours: int = 24):
        return get_network_history(conn, hours)

    @app.get("/api/system/top-procs")
    def api_top_procs():
        """Top 5 processes by memory (from hermes-monitor)"""
        try:
            import psutil
            procs = []
            for p in sorted(psutil.process_iter(["pid","name","memory_percent","cpu_percent"]),
                          key=lambda x: x.info.get("memory_percent",0) or 0, reverse=True)[:5]:
                try:
                    if p.info["memory_percent"] and p.info["memory_percent"] > 0.3:
                        procs.append({"pid": p.info["pid"], "name": p.info["name"],
                                     "mem": f"{p.info['memory_percent']:.1f}%",
                                     "cpu": f"{p.info.get('cpu_percent',0):.1f}%"})
                except: pass
            return procs
        except: return []

    # ── File Browser ──
    @app.get("/api/files")
    def api_files(path: str = "~/.hermes"):
        """List files in directory"""
        try:
            p = Path(path).expanduser().resolve()
            if not p.exists(): return {"error": "路径不存在"}
            if not str(p).startswith(str(Path.home())): return {"error": "访问受限"}
            items = []
            for f in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                try:
                    st = f.stat()
                    items.append({
                        "name": f.name, "path": str(f),
                        "type": "dir" if f.is_dir() else "file",
                        "size": f"{st.st_size:,}B" if not f.is_dir() else "",
                        "modified": datetime.fromtimestamp(st.st_mtime).strftime("%m-%d %H:%M"),
                    })
                except: pass
            return items[:200]
        except Exception as e: return {"error": str(e)[:100]}

    @app.get("/api/files/read")
    def api_files_read(path: str):
        """Read file content"""
        try:
            p = Path(path).expanduser().resolve()
            if not p.exists(): return {"error": "文件不存在"}
            if not str(p).startswith(str(Path.home())): return {"error": "访问受限"}
            if p.stat().st_size > 1_000_000: return {"error": "文件过大 (>1MB)"}
            content = p.read_text(encoding="utf-8", errors="replace")
            return {"content": content, "path": str(p), "size": len(content)}
        except Exception as e: return {"error": str(e)[:100]}

    @app.post("/api/files/write")
    async def api_files_write(request: Request):
        """Write file content"""
        try:
            body = await request.json()
            p = Path(body["path"]).expanduser().resolve()
            if not str(p).startswith(str(Path.home())): return {"error": "访问受限"}
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body["content"], encoding="utf-8")
            return {"success": True, "path": str(p)}
        except Exception as e: return {"error": str(e)[:100]}

    # ── Cron Management ──
    @app.get("/api/cron")
    def api_cron_get():
        """Read crontab"""
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            content = r.stdout if r.returncode == 0 else "# 暂无 crontab"
            ts = ""
            try:
                cf = Path.home() / ".crontab_backup"
                if cf.exists(): ts = datetime.fromtimestamp(cf.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            except: pass
            return {"content": content, "last_modified": ts}
        except Exception as e: return {"error": str(e)[:100]}

    @app.post("/api/cron")
    async def api_cron_set(request: Request):
        """Update crontab"""
        try:
            body = await request.json()
            content = body.get("content", "")
            # Backup old crontab
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            old = r.stdout if r.returncode == 0 else ""
            bf = Path.home() / ".crontab_backup"
            bf.write_text(old)
            # Set new crontab
            proc = subprocess.run(["crontab", "-"], input=content, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                c = conn.cursor()
                c.execute("INSERT INTO actions (ts,action,target,result,status) VALUES (?,?,?,?,?)",
                         (datetime.now().isoformat(), "cron_update", "crontab", "updated", "done"))
                conn.commit()
                return {"success": True}
            return {"success": False, "error": proc.stderr[:200]}
        except Exception as e: return {"error": str(e)[:100]}

    # ── Session Timeline ──
    @app.get("/api/sessions/timeline")
    def api_sessions_timeline(hours: int = 24):
        """Parse agent.log for session timeline events"""
        events = []
        try:
            lf = LOG_DIR / "agent.log"
            if not lf.exists(): return events
            r = subprocess.run(["tail", "-2000", str(lf)], capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                ts_match = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
                ts = ts_match.group(1) if ts_match else None
                if not ts: continue
                text = line[:200]
                level = "info"
                if re.search(r"(?i)(error|critical|fatal|exception|traceback)", line): level = "error"
                elif re.search(r"(?i)(warning|timeout|retry)", line): level = "warn"
                # Filter interesting events
                if re.search(r"(?i)(session|model|switch|tool_call|complete|start|error|warning|config)", line):
                    events.append({"ts": ts, "text": text, "level": level})
        except: pass
        return events[-100:]

    # ── Stuck Session Detection ──
    @app.get("/api/sessions/stuck")
    def api_sessions_stuck():
        """Detect stuck sessions (>10min no activity)"""
        stuck = []
        try:
            # Check for active CLI sessions
            r = subprocess.run(["pgrep", "-f", "hermes_cli.main"], capture_output=True, text=True, timeout=5)
            pids = r.stdout.strip().split()
            for pid in pids[:3]:
                try:
                    et = subprocess.run(["ps", "-o", "etime=", "-p", pid], capture_output=True, text=True, timeout=3)
                    elapsed = et.stdout.strip()
                    # Check agent.log for recent activity
                    lf = LOG_DIR / "agent.log"
                    if lf.exists():
                        tail = subprocess.run(["tail", "-50", str(lf)], capture_output=True, text=True, timeout=5)
                        now = datetime.now()
                        last_ts = None
                        for line in reversed(tail.stdout.splitlines()):
                            m = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})", line)
                            if m:
                                try:
                                    last_ts = datetime.fromisoformat(m.group(1))
                                    break
                                except: pass
                        if last_ts and (now - last_ts).total_seconds() > 600:
                            stuck.append({"session": f"PID {pid}", "detail": f"最后活动: {last_ts.strftime('%H:%M')}",
                                        "duration": elapsed, "idle_min": int((now-last_ts).total_seconds()/60)})
                except: pass
        except: pass
        return stuck

    # ── Agent Flow Visualization ──
    @app.get("/api/flow")
    def api_flow():
        """Read registry.json for agent flow diagram"""
        try:
            reg = HERMES_HOME / "agents" / "registry.json"
            if reg.exists():
                data = json.loads(reg.read_text())
                nodes = []
                # Parse agents from registry
                agents = data.get("agents", data) if isinstance(data, dict) else []
                agent_list = agents if isinstance(agents, list) else list(agents.values()) if isinstance(agents, dict) else []
                for a in agent_list[:10]:
                    if isinstance(a, dict):
                        name = a.get("name", a.get("id", "?"))
                        active = a.get("enabled", a.get("active", True))
                        status = "启用" if active else "停用"
                        icon = {"news": "📰", "backup": "💾", "analyst": "🔬", "coder": "👨💻", "translator": "🌐", "doctor": "🏥"}.get(name.lower()[:8], "🤖")
                        nodes.append({"name": str(name)[:40], "icon": icon, "status": status, "active": active})
                return {"nodes": nodes, "count": len(nodes)}
        except: pass
        return {"nodes": [], "count": 0}

    # ── File Change Tracking ──
    @app.get("/api/files/changes")
    def api_files_changes():
        """Track recently modified files under ~/.hermes"""
        changes = []
        try:
            now = time.time()
            # Find recently modified files
            for f in sorted(Path(HERMES_HOME).rglob("*"), key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True):
                try:
                    st = f.stat()
                    age_h = (now - st.st_mtime) / 3600
                    if age_h > 24: break  # Only last 24h
                    if f.is_dir(): continue
                    if any(p in str(f) for p in [".git/", "__pycache__", ".pyc", "venv/", "node_modules/", ".db"]): continue
                    if age_h < 0.05: status = "new"
                    elif age_h < 1: status = "modified"
                    else: status = "modified"
                    changes.append({
                        "path": str(f).replace(str(HERMES_HOME), "~/.hermes"),
                        "time": datetime.fromtimestamp(st.st_mtime).strftime("%H:%M"),
                        "status": status, "age_h": round(age_h, 1)
                    })
                except: pass
                if len(changes) >= 20: break
        except: pass
        return changes

    # ── WebSocket: Real-time Log Streaming ──
    @app.websocket("/ws/logs")
    async def ws_logs(ws: WebSocket):
        await ws.accept()
        token = ws.headers.get("authorization","").replace("Bearer ","").strip()
        if not token:
            token = ws.query_params.get("_t", "")
        if not verify_token(token):
            await ws.send_text("auth_failed"); await ws.close(code=4001); return

        params = dict(ws.query_params) if hasattr(ws, 'query_params') else {}
        log_file = params.get("file", "agent.log")
        grep_filter = params.get("grep", "")

        lf = LOG_DIR / log_file
        if not lf.exists():
            await ws.send_text(json.dumps({"error": f"文件不存在: {log_file}"}))
            await ws.close(); return

        # Send last 20 lines as initial batch
        try:
            r = subprocess.run(["tail", "-20", str(lf)], capture_output=True, text=True, timeout=3)
            if r.stdout:
                await ws.send_text(json.dumps({"init": True, "lines": r.stdout.splitlines()[-20:]}))
        except: pass

        # Tail the file
        try:
            proc = await asyncio.create_subprocess_exec(
                "tail", "-f", "-n", "0", str(lf),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
                if not line: break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if grep_filter and grep_filter.lower() not in decoded.lower():
                    continue
                try: await ws.send_text(json.dumps({"line": decoded}))
                except: break
        except asyncio.TimeoutError:
            await ws.send_text(json.dumps({"heartbeat": True}))
        except Exception:
            pass
        finally:
            try: proc.terminate(); await asyncio.wait_for(proc.wait(), timeout=3)
            except: pass
            try: await ws.close()
            except: pass

    # ── Agents (分身管理) ──
    @app.get("/api/agents")
    def api_agents():
        try:
            rf = HERMES_HOME / "agents" / "registry.json"
            if not rf.exists():
                return {"agents": [], "error": "registry.json not found"}
            with open(rf) as f:
                reg = json.load(f)
            agents = reg.get("agents", [])
            for a in agents:
                a["_meta"] = {
                    "is_timed": bool(a.get("schedule")),
                    "is_ondemand": a.get("status") == "ondemand",
                }
            return {"agents": agents, "total": len(agents),
                    "timed": sum(1 for a in agents if a.get("schedule")),
                    "ondemand": sum(1 for a in agents if a.get("status") == "ondemand")}
        except Exception as e:
            return {"agents": [], "error": str(e)[:200]}

    @app.post("/api/agents/toggle")
    async def api_agent_toggle(request: Request):
        try:
            body = await request.json()
            agent_id = body.get("id", "")
            rf = HERMES_HOME / "agents" / "registry.json"
            with open(rf) as f:
                reg = json.load(f)
            found = None
            for a in reg.get("agents", []):
                if a["id"] == agent_id:
                    found = a
                    break
            if not found:
                return {"success": False, "error": f"Agent not found: {agent_id}"}
            # toggle: active ↔ disabled
            found["status"] = "disabled" if found.get("status") == "active" else "active"
            with open(rf, "w") as f:
                json.dump(reg, f, ensure_ascii=False, indent=2)
            return {"success": True, "status": found["status"], "id": agent_id}
        except Exception as e:
            return {"success": False, "error": str(e)[:200]}

    # ── Platform Accounts ──
    PLATFORM_ACCOUNTS_FILE = HERMES_HOME / "memory" / "platform_accounts.json"

    def _load_accounts():
        if PLATFORM_ACCOUNTS_FILE.exists():
            with open(PLATFORM_ACCOUNTS_FILE) as f:
                data = json.load(f)
            # decrypt stored keys
            for k in data:
                if isinstance(data[k], dict) and 'api_key' in data[k]:
                    data[k]['api_key'] = _decrypt(data[k]['api_key'])
            return data
        return {}

    def _save_accounts(data):
        PLATFORM_ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        # encrypt keys before writing
        to_save = {}
        for k, v in data.items():
            vc = dict(v)
            if 'api_key' in vc:
                vc['api_key'] = _encrypt(vc['api_key'])
            to_save[k] = vc
        with open(PLATFORM_ACCOUNTS_FILE, "w") as f:
            json.dump(to_save, f, indent=2)

    @app.get("/api/platform/accounts")
    def api_platform_accounts():
        accounts = _load_accounts()
        # return masked keys for UI display
        masked = {}
        for k, v in accounts.items():
            vc = dict(v)
            key = vc.get('api_key', '')
            if key and len(key) > 4:
                vc['api_key'] = '*' * 12 + key[-4:]
            elif key:
                vc['api_key'] = '***'
            masked[k] = vc
        return masked

    @app.post("/api/platform/accounts")
    async def api_platform_save(request: Request):
        try:
            body = await request.json()
            platform = body.get("platform", "")
            api_key = body.get("api_key", "")
            if not platform:
                return {"success": False, "error": "platform required"}
            accounts = _load_accounts()
            # if input is empty or masked, keep existing key
            if not api_key or api_key.startswith("*"):
                existing = accounts.get(platform, {}).get("api_key", "")
                if not existing:
                    return {"success": False, "error": "未保存过 API Key，请粘贴完整密钥"}
                api_key = existing
            else:
                # user pasted a new key
                accounts[platform] = {"api_key": api_key, "updated": datetime.now().isoformat()}
                _save_accounts(accounts)
            return {"success": True, "platform": platform}
        except Exception as e:
            return {"success": False, "error": str(e)[:200]}

    @app.post("/api/platform/accounts/delete")
    async def api_platform_delete(request: Request):
        platform = request.query_params.get("platform", "")
        if not platform:
            return {"success": False, "error": "platform required"}
        accounts = _load_accounts()
        if platform in accounts:
            del accounts[platform]
            _save_accounts(accounts)
            return {"success": True, "platform": platform}
        return {"success": False, "error": f"无 {platform} 账户"}

    @app.post("/api/platform/balance")
    async def api_platform_balance(request: Request):
        platform = request.query_params.get("platform", "")
        accounts = _load_accounts()
        acct = accounts.get(platform, {})
        api_key = acct.get("api_key", "")
        if not api_key:
            return {"error": "未配置 API Key，请先保存"}
        try:
            if platform == "deepseek":
                r = urllib.request.urlopen(urllib.request.Request(
                    "https://api.deepseek.com/user/balance",
                    headers={"Authorization": f"Bearer {api_key}"}
                ), timeout=10)
                data = json.loads(r.read())
                balance = data.get("balance_infos", [{}])[0].get("total_balance", "?")
                acct["balance"] = f"¥{balance}"
            elif platform == "zhipu":
                r = urllib.request.urlopen(urllib.request.Request(
                    "https://open.bigmodel.cn/api/paas/v4/user/balance",
                    headers={"Authorization": f"Bearer {api_key}"}
                ), timeout=10)
                data = json.loads(r.read())
                balance = data.get("data", {}).get("balance", "?")
                acct["balance"] = f"¥{balance}"
            else:
                # Generic: try to query and parse
                acct["balance"] = "该平台余额查询待实现"
            acct["balance_updated"] = datetime.now().isoformat()
            _save_accounts(accounts)
            return {"balance": acct["balance"]}
        except Exception as e:
            return {"error": str(e)[:100]}

    # ── Skills Management ──
    @app.get("/api/skills")
    def api_skills():
        # Check cache first
        cache_path = HERMES_HOME / "memory" / "skills_cache.json"
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    skills = json.load(f)
                categories = sorted(set(s["category"] for s in skills))
                return {
                    "skills": skills,
                    "total": len(skills),
                    "categories": categories,
                    "by_category": {c: [s for s in skills if s["category"] == c] for c in categories},
                }
            except:
                pass
        # Fallback: scan skill dirs
        skills = []
        skill_dirs = [
            HERMES_HOME / "skills",
            HERMES_HOME / "hermes-agent" / "skills",
            HERMES_HOME / "hermes-agent" / "optional-skills",
        ]
        for sd in skill_dirs:
            if not sd.exists():
                continue
            for skill_md in sd.rglob("SKILL.md"):
                try:
                    rel = skill_md.relative_to(sd)
                    parts = rel.parts
                    # Use top-level directory as category, or "root" if SKILL.md is directly in skills dir
                    category = parts[0] if len(parts) > 1 else "root"
                    content = skill_md.read_text(encoding="utf-8", errors="replace")[:8000]
                    # Extract frontmatter
                    name = skill_md.parent.name
                    desc = ""
                    body = ""
                    if content.startswith("---"):
                        fm_parts = content.split("---", 2)
                        if len(fm_parts) >= 3:
                            fm = fm_parts[1]
                            body = fm_parts[2] if len(fm_parts) > 2 else ""
                            for line in fm.split("\n"):
                                line = line.strip()
                                if line.startswith("name:"):
                                    name = line.split(":", 1)[1].strip().strip('"').strip("'")
                                elif line.startswith("description:"):
                                    desc = line.split(":", 1)[1].strip().strip('"').strip("'")
                    # If description is English or empty, search body for Chinese text
                    import re
                    has_cn = bool(re.search(r'[\u4e00-\u9fff]', desc))
                    if not has_cn and body:
                        cn_lines = [l.strip() for l in body.split("\n") 
                                    if re.search(r'[\u4e00-\u9fff]', l) and len(l.strip()) > 5]
                        if cn_lines:
                            cn_desc = cn_lines[0]
                            # Clean up markdown prefixes
                            cn_desc = re.sub(r'^#+\s*', '', cn_desc)
                            cn_desc = re.sub(r'^[-*>]\s*', '', cn_desc)
                            if not has_cn:
                                desc = cn_desc[:120]
                    skills.append({
                        "id": skill_md.parent.name,
                        "name": name,
                        "description": desc,
                        "category": category,
                        "path": str(skill_md.parent),
                        "source": "hermes-agent" if "hermes-agent" in str(sd) else "user",
                    })
                except:
                    pass
        # Sort by source then category then name
        skills.sort(key=lambda s: (s["source"], s["category"], s["name"]))
        categories = sorted(set(s["category"] for s in skills))
        return {
            "skills": skills,
            "total": len(skills),
            "categories": categories,
            "by_category": {c: [s for s in skills if s["category"] == c] for c in categories},
        }

    # ── Frontend ──
    @app.get("/")
    def index(): return HTMLResponse(HTML)

    print(f"\n  🚀 Hermes Command Center v2.0")
    print(f"  ─────────────────────────────")
    print(f"  面板:  http://0.0.0.0:{port}")
    print(f"  API:   http://0.0.0.0:{port}/api/health\n")
    config = UConfig(app, host="0.0.0.0", port=port, log_level="warning", loop="asyncio")
    Server(config=config).run()

# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════

def cli_check():
    snap = take_snapshot()
    h = snap["health"]
    icon = "🟢" if h["score"]>=80 else ("🟡" if h["score"]>=50 else "🔴")
    print(f"\n  {icon}  Hermes CC | {h['score']}/100 ({h['level']})")
    print(f"  {'─'*40}")
    for n,s in snap["services"].items():
        st = "✅" if s["active"] else "❌"
        mem = f" [{s.get('memory_mb',0)}MB]" if s["active"] else ""
        print(f"  {st} {s['icon']} {s['name']}{mem}")
    sys_ = snap["system"]
    print(f"  CPU:{sys_['cpu_pct']}% 内存:{sys_['mem_pct']}% 磁盘:{sys_['disk_pct']}%")
    print(f"  ERROR:{snap['logs']['error_count']} T1:{snap['memory']['t1_mem_pct']}%")
    if h["issues"]:
        print(f"  ⚠️ {h['issue_count']}个问题:"); [print(f"    • {i}") for i in h["issues"]]
    else: print("  ✅ 一切正常")

def run_alert():
    conn = init_db(); snap = take_snapshot(conn)
    alerts = check_alerts(snap, conn)
    fixes = run_auto_fix(snap, conn)
    if alerts or fixes:
        lines = ["🔔 Hermes CC 报告"]
        for a in alerts: lines.append(f"{'🔴' if a['level']=='error' else '🟡'} {a['message']}")
        for f in fixes: lines.append(f"🛠️ {f['name']}: {'✅' if f['result']=='ok' else '❌'}")
        snap = take_snapshot(conn)
        lines.append(f"评分: {snap['health']['score']}/100")
        push_qq("\n".join(lines))
        print(f"[{datetime.now().strftime('%H:%M')}] {len(alerts)}告警 {len(fixes)}修复")

# ═══════════════════════════════════════════════════════════
# HTML FRONTEND (v3.0)
# ═══════════════════════════════════════════════════════════

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Hermes CC — Amber</title>
<style>
/* ═══ Hermes CC v3.0 — Web UI Amber Theme ═══ */
/* Fonts loaded from local web_dist */
@font-face{font-family:Collapse;font-style:normal;font-weight:400;font-display:swap;src:url(/fonts/Collapse-Regular.woff2) format("woff2")}
@font-face{font-family:Collapse;font-style:normal;font-weight:700;font-display:swap;src:url(/fonts/Collapse-Bold.woff2) format("woff2")}
@font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:400;font-display:swap;src:url(/fonts-terminal/JetBrainsMono-Regular.woff2) format("woff2")}
@font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:700;font-display:swap;src:url(/fonts-terminal/JetBrainsMono-Bold.woff2) format("woff2")}

*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#170d02;
  --bg-alt:#1f1203;
  --card:rgba(255,172,2,0.03);
  --card-hover:rgba(255,172,2,0.06);
  --glass-border:rgba(255,172,2,0.1);
  --glass-border-hover:rgba(255,172,2,0.25);
  --text:#ffe6cb;
  --text-primary:#fff;
  --dim:rgba(255,172,2,0.55);
  --muted:rgba(255,172,2,0.3);
  --green:#4ade80;
  --green-bg:rgba(74,222,128,0.1);
  --yellow:#ffbd38;
  --yellow-bg:rgba(255,189,56,0.1);
  --red:#fb2c36;
  --red-bg:rgba(251,44,54,0.1);
  --blue:#ffac02;
  --blue-bg:rgba(255,172,2,0.1);
  --purple:#d4a574;
  --purple-bg:rgba(212,165,116,0.1);
  --cyan:#ffd27f;
  --gradient-1:linear-gradient(135deg,#ffac02,#d4a574);
  --gradient-2:linear-gradient(135deg,#4ade80,#ffbd38);
  --gradient-3:linear-gradient(135deg,#fb2c36,#ffac02);
  --shadow-card:0 2px 12px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,172,2,0.04);
  --shadow-glow:0 0 24px rgba(255,172,2,0.06);
  --radius:8px;
  --radius-sm:6px;
  --radius-lg:14px;
  --header-height:48px;
  --font-sans:"Collapse",system-ui,sans-serif;
  --font-mono:"JetBrains Mono","SF Mono",monospace;
}
body{
  font-family:var(--font-sans);
  background:var(--bg);
  color:var(--text);
  min-height:100vh;
  position:relative;
  font-size:14px;
  line-height:1.5;
  -webkit-font-smoothing:antialiased;
  text-rendering:optimizelegibility;
}
/* grain overlay — Hermes Web UI signature */
body::after{
  content:"";
  position:fixed;top:0;left:0;right:0;bottom:0;
  opacity:.06;pointer-events:none;z-index:0;
  background:repeating-conic-gradient(currentColor 0% 25%,#0000 0% 50%) 0 0/2px 2px;
}

/* Header */
.header{
  background:rgba(23,13,2,0.92);
  backdrop-filter:blur(24px) saturate(1.5);
  border-bottom:1px solid var(--glass-border);
  padding:0 24px;
  height:var(--header-height);
  display:flex;
  align-items:center;
  gap:14px;
  position:sticky;
  top:0;
  z-index:100;
  position:relative;
}
.header h1{font-size:15px;font-weight:700;color:var(--blue);letter-spacing:-0.3px;text-transform:uppercase}
.header .sub{font-size:11px;color:var(--dim)}

.header-right{margin-left:auto;display:flex;gap:10px;align-items:center}

/* Tabs — side-scroll amber underlines */
.tabs{display:flex;background:rgba(23,13,2,0.7);backdrop-filter:blur(12px);border-bottom:1px solid var(--glass-border);padding:0 16px;overflow-x:auto;gap:0;position:relative}
.tab{padding:10px 16px;font-size:12px;cursor:pointer;border-bottom:2px solid transparent;color:var(--dim);white-space:nowrap;transition:all .2s;font-weight:400;letter-spacing:0.3px;text-transform:uppercase;font-family:var(--font-sans)}
.tab:hover{color:var(--text-primary);border-bottom-color:var(--muted)}
.tab.active{color:var(--blue);border-color:var(--blue);font-weight:600}
.tab .badge{display:inline-block;margin-left:5px;padding:1px 6px;border-radius:8px;font-size:10px;line-height:15px;font-weight:600}
.badge-red{background:var(--red-bg);color:var(--red)}
.badge-yellow{background:var(--yellow-bg);color:var(--yellow)}
.badge-green{background:var(--green-bg);color:var(--green)}

/* Login */
.login-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:var(--bg);z-index:2000;display:none;align-items:center;justify-content:center}
.login-overlay::after{content:"";position:fixed;top:0;left:0;right:0;bottom:0;opacity:.04;pointer-events:none;background:repeating-conic-gradient(currentColor 0% 25%,#0000 0% 50%) 0 0/2px 2px}
.login-box{background:var(--card);backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:var(--radius-lg);padding:36px;width:380px;text-align:center;box-shadow:var(--shadow-card),var(--shadow-glow);position:relative;z-index:1}
.login-box h2{font-size:20px;margin-bottom:4px;color:var(--blue);font-weight:700;text-transform:uppercase;letter-spacing:1px}
.login-box p{color:var(--dim);font-size:13px;margin-bottom:24px}
.login-box input{width:100%;padding:10px 12px;border-radius:var(--radius-sm);border:1px solid var(--glass-border);background:rgba(23,13,2,0.6);color:var(--text);font-size:14px;margin-bottom:10px;outline:none;transition:all .2s;font-family:var(--font-sans)}
.login-box input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(255,172,2,0.1)}
.login-box .error{color:var(--red);font-size:12px;margin-top:6px;display:none}
.login-btn{width:100%;padding:10px;border-radius:var(--radius-sm);border:none;background:var(--gradient-1);color:var(--bg);font-size:14px;cursor:pointer;font-weight:700;transition:all .2s;text-transform:uppercase;letter-spacing:0.5px}
.login-btn:hover{opacity:.9;box-shadow:0 4px 15px rgba(255,172,2,0.3)}
.login-btn:disabled{opacity:.4;cursor:not-allowed}

/* Layout */
.container{padding:14px 18px;max-width:1440px;margin:0 auto;position:relative;z-index:1}
.page{display:none}.page.active{display:block}
.flex{display:flex}.flex-wrap{flex-wrap:wrap}.gap{gap:8px}.gap2{gap:12px}.gap3{gap:14px}.between{justify-content:space-between}.center{align-items:center}

/* Grid */
.grid{display:grid;grid-gap:10px}.grid-4{grid-template-columns:repeat(4,1fr)}.grid-3{grid-template-columns:repeat(3,1fr)}.grid-2{grid-template-columns:repeat(2,1fr)}
@media(max-width:1100px){.grid-4{grid-template-columns:repeat(2,1fr)}}
@media(max-width:768px){.grid-4,.grid-3,.grid-2{grid-template-columns:1fr}}

/* Card — with arc-border glow */
.card{
  background:var(--card);
  backdrop-filter:blur(16px);
  border:1px solid var(--glass-border);
  border-radius:var(--radius);
  padding:16px;
  margin-bottom:10px;
  box-shadow:var(--shadow-card);
  transition:all .25s;
  position:relative;
}
.card:hover{border-color:var(--glass-border-hover);box-shadow:var(--shadow-card),var(--shadow-glow)}
.card-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:12px;font-family:var(--font-sans)}

/* Progress */
.progress-bar{height:5px;background:rgba(255,172,2,0.06);border-radius:3px;overflow:hidden;margin-top:6px}
.progress-fill{height:100%;border-radius:3px;transition:width .6s cubic-bezier(.4,0,.2,1)}

/* Colors */
.green{color:var(--green)}.yellow{color:var(--yellow)}.red{color:var(--red)}.blue{color:var(--blue)}.purple{color:var(--purple)}.cyan{color:var(--cyan)}.dim{color:var(--dim)}
.bg-green{background:var(--green)}.bg-yellow{background:var(--yellow)}.bg-red{background:var(--red)}.bg-blue{background:var(--blue)}.bg-purple{background:var(--purple)}

.gradient-text{background:var(--gradient-1);-webkit-background-clip:text;-webkit-text-fill-color:transparent}

.metric{font-size:26px;font-weight:700;line-height:1.1;letter-spacing:-0.5px;color:var(--text-primary)}
.metric-sm{font-size:18px;font-weight:600;color:var(--text-primary)}
.label{font-size:11px;color:var(--dim);margin-top:3px;font-weight:400;letter-spacing:0.3px}
.text-sm{font-size:12px}.text-xs{font-size:11px}.mt-2{margin-top:8px}.mt-3{margin-top:14px}.mb-2{margin-bottom:8px}.mb-3{margin-bottom:14px}

/* Buttons — amber theme */
.btn{
  padding:6px 14px;
  border-radius:var(--radius-sm);
  border:1px solid var(--glass-border);
  background:rgba(255,172,2,0.04);
  color:var(--text);
  font-size:12px;
  cursor:pointer;
  transition:all .2s;
  white-space:nowrap;
  font-weight:400;
  font-family:var(--font-sans);
  text-transform:uppercase;
  letter-spacing:0.3px;
}
.btn:hover{background:rgba(255,172,2,0.08);border-color:var(--glass-border-hover)}
.btn-primary{
  background:var(--gradient-1);
  border-color:transparent;
  color:var(--bg);
  font-weight:700;
}
.btn-primary:hover{opacity:.9;box-shadow:0 4px 12px rgba(255,172,2,0.25)}
.btn-danger{
  background:linear-gradient(135deg,var(--red),#e02d30);
  border-color:transparent;
  color:#fff;
  font-weight:700;
}
.btn-danger:hover{opacity:.9;box-shadow:0 4px 12px rgba(251,44,54,0.25)}
.btn-sm{padding:3px 10px;font-size:11px}
.btn:disabled{opacity:.35;cursor:not-allowed}

/* Service Card */
.svc-card{
  background:var(--card);
  backdrop-filter:blur(12px);
  border:1px solid var(--glass-border);
  border-radius:var(--radius);
  padding:12px;
  transition:all .25s;
  box-shadow:var(--shadow-card);
}
.svc-card:hover{border-color:var(--glass-border-hover);box-shadow:var(--shadow-card),var(--shadow-glow);transform:translateY(-1px)}
.svc-name{display:flex;align-items:center;gap:6px;font-size:13px;font-weight:600;color:var(--text-primary)}
.svc-desc{font-size:11.5px;color:var(--dim);margin-top:4px}
.svc-status{font-size:10.5px;padding:2px 8px;border-radius:10px;font-weight:600;letter-spacing:0.3px}
.svc-running{background:var(--green-bg);color:var(--green)}
.svc-stopped{background:var(--red-bg);color:var(--red)}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;flex-shrink:0}
.dot-up{background:var(--green);box-shadow:0 0 8px rgba(74,222,128,0.5)}
.dot-down{background:var(--red);box-shadow:0 0 8px rgba(251,44,54,0.5)}

/* Log Box */
.log-box{max-height:260px;overflow-y:auto;font-family:var(--font-mono);font-size:11.5px;line-height:1.7}
.log-box::-webkit-scrollbar{width:3px}
.log-box::-webkit-scrollbar-thumb{background:var(--muted);border-radius:2px}
.log-line{padding:2px 8px;border-radius:2px;margin-bottom:1px;word-break:break-all}
.log-error{background:var(--red-bg);color:var(--red);border-left:2px solid var(--red)}
.log-warn{background:var(--yellow-bg);color:var(--yellow);border-left:2px solid var(--yellow)}
.log-info{color:var(--dim)}

/* Table */
.table{width:100%;border-collapse:collapse;font-size:12.5px}
.table th{text-align:left;padding:8px 10px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--glass-border);font-size:10.5px;text-transform:uppercase;letter-spacing:.8px}
.table td{padding:8px 10px;border-bottom:1px solid rgba(255,172,2,0.04)}

/* Modal */
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.65);backdrop-filter:blur(10px);z-index:999;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal-box{background:var(--card);backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:var(--radius-lg);padding:28px;max-width:480px;width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.6)}
.modal-title{font-size:17px;font-weight:700;margin-bottom:14px;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;z-index:1000;padding:10px 18px;border-radius:var(--radius-sm);font-size:12.5px;max-width:400px;animation:slideIn .25s cubic-bezier(.4,0,.2,1);box-shadow:0 8px 30px rgba(0,0,0,0.5);backdrop-filter:blur(12px)}
.toast-success{background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.2);color:var(--green)}
.toast-error{background:rgba(251,44,54,0.08);border:1px solid rgba(251,44,54,0.2);color:var(--red)}
.toast-info{background:rgba(255,172,2,0.08);border:1px solid rgba(255,172,2,0.2);color:var(--blue)}
@keyframes slideIn{from{transform:translateY(16px);opacity:0}to{transform:translateY(0);opacity:1}}

/* Chart */
.chart-bar{flex:1;min-width:3px;border-radius:2px 2px 0 0;transition:height .4s cubic-bezier(.4,0,.2,1)}
.chart-bar.healthy{background:var(--gradient-2)}.chart-bar.warning{background:var(--gradient-3)}.chart-bar.critical{background:var(--gradient-1)}
.pulse{animation:pulse 1.5s ease-in-out infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

/* Tags */
.tag{padding:2px 8px;border-radius:4px;font-size:10.5px;display:inline-block;margin-right:4px;font-weight:500}
.tag-model{background:var(--blue-bg);color:var(--blue);border:1px solid rgba(255,172,2,0.15)}
.tag-active{background:var(--green-bg);color:var(--green);border:1px solid rgba(74,222,128,0.15)}
.tag-cheap{background:var(--yellow-bg);color:var(--yellow);border:1px solid rgba(255,189,56,0.15)}

/* Toggle Switch */
.switch{position:relative;display:inline-block;width:36px;height:20px;cursor:pointer}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;top:0;left:0;right:0;bottom:0;background:rgba(255,172,2,0.08);border-radius:10px;transition:.25s}
.slider:before{content:"";position:absolute;height:14px;width:14px;left:3px;bottom:3px;background:var(--muted);border-radius:50%;transition:.25s}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(16px);background:#fff}

/* Gauge ring */
.gauge-ring{position:relative;display:inline-flex;align-items:center;justify-content:center}
.gauge-ring svg{transform:rotate(-90deg)}
.gauge-ring .bg{stroke:rgba(255,172,2,0.06)}
.gauge-ring .val{stroke-linecap:round;transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)}
.gauge-text{position:absolute;font-size:20px;font-weight:700}

/* ═══ Cost Dashboard ═══ */
.cost-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}
.cost-card{background:var(--card);backdrop-filter:blur(12px);border:1px solid var(--glass-border);border-radius:var(--radius);padding:14px;text-align:center}
.cost-card .cost-amount{font-size:28px;font-weight:800;color:var(--blue);letter-spacing:-0.5px}
.cost-card .cost-label{font-size:11px;color:var(--dim);margin-top:4px;font-weight:400;text-transform:uppercase;letter-spacing:0.5px}
.cost-model-row{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;border-bottom:1px solid rgba(255,172,2,0.04);font-size:12.5px}
.cost-model-row:last-child{border:none}
.cost-bar{flex:1;height:4px;background:rgba(255,172,2,0.06);border-radius:2px;margin:0 10px;overflow:hidden}
.cost-bar-fill{height:100%;border-radius:2px;transition:width .6s}
.cost-period-btn{padding:4px 12px;border-radius:12px;border:1px solid var(--glass-border);background:0 0;color:var(--dim);font-size:11px;cursor:pointer;transition:.2s;font-family:var(--font-sans);text-transform:uppercase;letter-spacing:0.3px}
.cost-period-btn.active{background:var(--blue-bg);color:var(--blue);border-color:rgba(255,172,2,0.3)}

/* ═══ Stream indicator ═══ */
.stream-indicator{width:6px;height:6px;border-radius:50%;display:inline-block;margin-right:4px}
.stream-live{background:var(--green);box-shadow:0 0 8px rgba(74,222,128,0.6);animation:pulse 1s ease-in-out infinite}
.stream-off{background:var(--muted)}

/* ═══ File browser ═══ */
.file-tree{font-family:var(--font-mono);font-size:12px;line-height:1.8}
.file-tree .dir,.file-tree .file{padding:2px 8px;border-radius:3px;cursor:pointer;transition:.15s;display:flex;align-items:center;gap:6px}
.file-tree .dir:hover,.file-tree .file:hover{background:rgba(255,172,2,0.06)}
.file-tree .dir{color:var(--blue);font-weight:500}
.file-tree .file{color:var(--dim)}
.file-tree .size{color:var(--muted);font-size:10px;margin-left:auto}
.file-viewer{background:rgba(23,13,2,0.8);border:1px solid var(--glass-border);border-radius:var(--radius);padding:12px;font-family:var(--font-mono);font-size:12px;line-height:1.6;max-height:500px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.file-viewer::-webkit-scrollbar{width:4px}
.file-viewer::-webkit-scrollbar-thumb{background:var(--muted);border-radius:2px}

/* ═══ Cron editor ═══ */
.cron-editor{width:100%;min-height:200px;background:rgba(23,13,2,0.8);border:1px solid var(--glass-border);border-radius:var(--radius);color:var(--text);font-family:var(--font-mono);font-size:12px;padding:12px;resize:vertical;outline:none;line-height:1.7}
.cron-editor:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(255,172,2,0.1)}

/* ═══ Session timeline ═══ */
.timeline{padding:10px 0}
.timeline-item{display:flex;gap:12px;padding:8px 0;border-left:2px solid var(--glass-border);margin-left:8px;padding-left:16px;position:relative}
.timeline-item::before{content:'';position:absolute;left:-5px;top:14px;width:8px;height:8px;border-radius:50%;background:var(--blue)}
.timeline-item.tl-error::before{background:var(--red)}
.timeline-item.tl-warn::before{background:var(--yellow)}
.timeline-time{font-size:10.5px;color:var(--muted);min-width:70px;font-family:var(--font-mono);font-weight:500}
.timeline-body{font-size:12px;color:var(--dim);flex:1}

/* ═══ Network chart ═══ */
.net-chart{display:flex;align-items:flex-end;height:40px;gap:1px;margin-top:8px}
.net-bar{flex:1;min-width:2px;border-radius:1px;opacity:.7}

/* ═══ Flow diagram ═══ */
.flow-container{display:flex;flex-direction:column;align-items:center;gap:8px;padding:20px}
.flow-node{padding:10px 20px;background:var(--card);border:1px solid var(--glass-border);border-radius:var(--radius);font-size:13px;min-width:200px;text-align:center}
.flow-arrow{color:var(--muted);font-size:18px}
.flow-active{border-color:var(--green);box-shadow:0 0 12px rgba(74,222,128,0.15)}
.flow-inactive{border-color:var(--red);opacity:.6}

/* ═══ Diff highlight ═══ */
.changed-file{display:flex;align-items:center;gap:6px;padding:4px 8px;border-radius:4px;font-size:11.5px;margin:2px 0}
.changed-file.modified{background:rgba(255,189,56,0.06);border-left:2px solid var(--yellow)}
.changed-file.new{background:rgba(74,222,128,0.06);border-left:2px solid var(--green)}
.changed-file.deleted{background:rgba(251,44,54,0.06);border-left:2px solid var(--red)}
</style>
</head>
<body>
<div class="login-overlay" id="loginOverlay">
  <div class="login-box">
    <h2>HERMES CC</h2>
    <p>请输入用户名密码登录</p>
    <input type="text" id="loginUser" placeholder="用户名" value="admin" onkeydown="if(event.key==='Enter')document.getElementById('loginPwd').focus()" autocomplete="username">
    <input type="password" id="loginPwd" placeholder="密码" onkeydown="if(event.key==='Enter')doLogin()" autocomplete="current-password">
    <button class="login-btn" id="loginBtn" onclick="doLogin()">登录</button>
    <div class="error" id="loginError">用户名或密码错误</div>
  </div>
</div>
<div id="toastContainer"></div>
<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)"><div class="modal-box" id="modalBox"></div></div>
<div class="header">
  <h1>🛡️ Hermes CC <span class="sub">v3</span></h1>
  <span id="healthBadge" class="btn-sm" style="border-radius:12px"></span>
  <span id="lastUpdate" class="dim text-sm"></span>
  <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
    <span id="refreshCount" class="dim text-xs"></span>
    <button class="btn btn-sm" onclick="refresh()">⟳</button>
  </div>
</div>
<div class="tabs" id="tabs">
  <div class="tab active" data-tab="dashboard" onclick="switchTab('dashboard')">📊 总览</div>
  <div class="tab" data-tab="services" onclick="switchTab('services')">⚡ 服务</div>
  <div class="tab" data-tab="costs" onclick="switchTab('costs')">💰 成本</div>
  <div class="tab" data-tab="logs" onclick="switchTab('logs')">📋 日志 <span id="errBadge"></span></div>
  <div class="tab" data-tab="files" onclick="switchTab('files')">📁 文件</div>
  <div class="tab" data-tab="cron" onclick="switchTab('cron')">⏱️ Cron</div>
  <div class="tab" data-tab="sessions" onclick="switchTab('sessions')">🔍 会话</div>
  <div class="tab" data-tab="models" onclick="switchTab('models')">🤖 模型&amp;成本</div>
  <div class="tab" data-tab="actions" onclick="switchTab('actions')">🛠️ 操作台</div>
  <div class="tab" data-tab="alerts" onclick="switchTab('alerts')">🔔 告警</div>
  <div class="tab" data-tab="history" onclick="switchTab('history')">📈 趋势</div>
  <div class="tab" data-tab="agents" onclick="switchTab('agents')">🤖 分身 <span id="agentCount"></span></div>
  <div class="tab" data-tab="skills" onclick="switchTab('skills')">🧩 技能</div>
</div>
<div class="container">
<div id="page-dashboard" class="page active"></div>
<div id="page-services" class="page"></div>
<div id="page-costs" class="page"></div>
<div id="page-logs" class="page"></div>
<div id="page-files" class="page"></div>
<div id="page-cron" class="page"></div>
<div id="page-sessions" class="page"></div>
<div id="page-models" class="page"></div>
<div id="page-actions" class="page"></div>
<div id="page-alerts" class="page"></div>
<div id="page-history" class="page"></div>
<div id="page-agents" class="page"></div>
<div id="page-skills" class="page"></div>
</div>
<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)"><div class="modal-box" id="modalBox"></div></div>
<div id="toastContainer"></div>

<script>
const REFRESH = 15;
let timer = REFRESH, data = null;

// ── UI helpers ──
function $(id){return document.getElementById(id)}
function q(s){return document.querySelector(s)}
function qa(s){return document.querySelectorAll(s)}
function pct(v){return v>=85?'red':v>=70?'yellow':'green'}
function scoreColor(s){return s>=80?'green':s>=50?'yellow':'red'}
function fmtTime(iso){try{return new Date(iso).toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}catch{return iso}}
function h(t){return t.replace(/&/g,'&amp;').replace(/</g,'&lt;')}

// ── Toast ──
function toast(msg,level='info'){const c=$('toastContainer');const d=document.createElement('div');d.className='toast toast-'+level;d.textContent=msg;c.appendChild(d);setTimeout(()=>d.remove(),3500)}

// ── Modal ──
function showModal(html){$('modalBox').innerHTML=html;$('modalOverlay').classList.add('show')}
function closeModal(e){if(e===true||e.target===$('modalOverlay'))$('modalOverlay').classList.remove('show')}

// ── Tab ──
function switchTab(name){
  qa('.tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===name))
  qa('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+name))
}

// ── API call ──
// ── Auth ──
function getToken(){return localStorage.getItem('hermes_cc_token')||''}
function isLoggedIn(){return !!getToken()}

async function doLogin(){
  const user=document.getElementById('loginUser'),pwd=document.getElementById('loginPwd'),btn=document.getElementById('loginBtn'),err=document.getElementById('loginError')
  if(!user.value.trim()){err.textContent='请输入用户名';err.style.display='block';return}
  if(!pwd.value){err.textContent='请输入密码';err.style.display='block';return}
  btn.disabled=true;btn.textContent='登录中...';err.style.display='none'
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user.value,password:pwd.value})})
    const d=await r.json()
    if(d.success){localStorage.setItem('hermes_cc_token',d.token);localStorage.setItem('hermes_cc_user',d.username||user.value);document.getElementById('loginOverlay').style.display='none';refresh()}
    else{err.style.display='block';err.textContent=d.error||'登录失败'}
  }catch(e){err.style.display='block';err.textContent='网络错误'}
  btn.disabled=false;btn.textContent='登录'
}

// ── Check auth on load ──
if(!isLoggedIn()){document.getElementById('loginOverlay').style.display='flex'}else{document.getElementById('loginOverlay').style.display='none'}

// ── Confirmation modal ──
function confirmAction(title,desc,risk,callback){
  showModal(`
    <div class="modal-title">⚠️ ${title}</div>
    <div style="font-size:13px;color:var(--dim);margin-bottom:16px">${desc}</div>
    <div style="font-size:12px;background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.2);border-radius:6px;padding:10px;color:var(--red);margin-bottom:16px">⚠️ ${risk}</div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="closeModal(true)">取消</button>
      <button class="btn btn-danger" onclick="closeModal(true);callback()">确认执行</button>
    </div>
  `)
}

// ── API with auth ──
async function api(url,opts={}){
  try{
    const headers={'Content-Type':'application/json','Authorization':'Bearer '+getToken()}
    const r=await fetch(url,{headers,...opts})
    if(r.status===401){document.getElementById('loginOverlay').style.display='flex';localStorage.removeItem('hermes_cc_token');toast('认证过期，请重新登录','error');return null}
    return await r.json()
  }catch(e){toast('请求失败: '+e.message,'error');return null}
}

// ═══════════════════════════════════════
// v3.0 WEBSOCKET HELPERS
// ═══════════════════════════════════════
function wsConnect(path,onMessage,onOpen,onClose){
  const proto=location.protocol==='https:'?'wss':'ws'
  const token=getToken()
  const sep=path.includes('?')?'&':'?'
  const url=`${proto}://${location.host}${path}${sep}_t=${encodeURIComponent(token)}`
  const ws=new WebSocket(url)
  ws.addEventListener('open',()=>{if(onOpen)onOpen(ws)})
  ws.addEventListener('message',(e)=>{if(onMessage)onMessage(e.data,ws)})
  ws.addEventListener('close',()=>{if(onClose)onClose()})
  ws.addEventListener('error',()=>{if(onClose)onClose()})
  return ws
}

// ═══════════════════════════════════════
// v3.1: MODELS & COSTS (合并)
// ═══════════════════════════════════════
let costPeriod='today'
const MODEL_COLORS={pro:'#64b5f6',flash:'#4dd0e1',coder:'#00e676','gpt-5.5':'#ffd54f','gpt-5.4':'#ff8a65','gpt-5.4-mini':'#b388ff',default:'#64b5f6'}
function modelColor(m){return MODEL_COLORS[m]||MODEL_COLORS.default}
async function renderCosts(){
  const costs=await api('/api/token/costs')
  if(!costs){$('page-costs').innerHTML='<div class="card"><div class="dim" style="padding:20px;text-align:center">无法获取成本数据</div></div>';return}
  const period=costs[costPeriod]||{total_tokens:0,total_cost:0,by_model:{}}
  let html=`<div class="flex gap mb-2">`
  for(const p of['today','week','month']){
    html+=`<button class="cost-period-btn${costPeriod===p?' active':''}" onclick="costPeriod='${p}';renderCosts()">${p==='today'?'今日':p==='week'?'本周':'本月'}</button>`
  }
  html+='</div>'
  html+=`<div class="cost-summary">
    <div class="cost-card"><div class="cost-amount">¥${period.total_cost.toFixed(2)}</div><div class="cost-label">总花费</div></div>
    <div class="cost-card"><div class="cost-amount">${(period.total_tokens/1000).toFixed(0)}K</div><div class="cost-label">总Token</div></div>
    <div class="cost-card"><div class="cost-amount">${Object.keys(period.by_model).length}</div><div class="cost-label">使用模型</div></div>
  </div>`
  // Per model breakdown
  const models=Object.entries(period.by_model).sort((a,b)=>b[1].cost-a[1].cost)
  if(models.length>0){
    const maxCost=Math.max(1,models[0][1].cost)
    html+='<div class="card"><div class="card-title">按模型分拆</div>'
    for(const[m,d]of models){
      const pct=Math.max(2,(d.cost/maxCost*100))
      html+=`<div class="cost-model-row">
        <span style="color:${modelColor(m)};font-weight:500">${h(m)}</span>
        <div class="cost-bar"><div class="cost-bar-fill" style="width:${pct}%;background:${modelColor(m)}"></div></div>
        <span style="font-size:11px;min-width:100px;text-align:right">${(d.tokens/1000).toFixed(0)}K · ¥${d.cost.toFixed(2)}</span>
      </div>`
    }
    html+='</div>'
  }
  // Daily chart
  const daily=costs.daily||{}
  const days=Object.entries(daily).sort().slice(-30)
  if(days.length>1){
    html+='<div class="card mt-2"><div class="card-title">每日花费趋势 (30天)</div>'
    const maxD=Math.max(1,...days.map(([,d])=>d.total_cost))
    html+='<div style="display:flex;align-items:flex-end;height:60px;gap:1px;margin-top:8px">'
    for(const[date,d]of days){
      const hh=Math.max(2,(d.total_cost/maxD)*58)
      html+=`<div class="chart-bar healthy" style="height:${hh}px;flex:1;min-width:3px" title="${date}: ¥${d.total_cost.toFixed(2)} · ${(d.total_tokens/1000).toFixed(0)}K tokens"></div>`
    }
    html+='</div></div>'
  }
  $('page-costs').innerHTML=html
  // v3.1: Also update dashboard cost summary
  const dc=$('dashCosts')
  if(dc&&costs.week){
    const wk=costs.week; const td=costs.today
    dc.innerHTML=`<div class="cost-card"><div class="cost-amount" style="font-size:22px">¥${td.total_cost.toFixed(2)}</div><div class="cost-label">今日花费</div></div>
    <div class="cost-card"><div class="cost-amount" style="font-size:22px">¥${wk.total_cost.toFixed(2)}</div><div class="cost-label">本周花费</div></div>
    <div class="cost-card"><div class="cost-amount" style="font-size:22px">${(wk.total_tokens/1000).toFixed(0)}K</div><div class="cost-label">本周Token</div></div>`
  }
}

// ═══════════════════════════════════════
// v3.0 ENHANCED LOGS with LIVE STREAM
// ═══════════════════════════════════════
let logWs=null,logStreamActive=false,logFilter='',logFile='agent.log'
function toggleLogStream(){
  if(logStreamActive){stopLogStream();return}
  startLogStream()
}
function startLogStream(){
  logStreamActive=true
  const box=document.getElementById('logStreamBox')
  if(box){box.innerHTML='<div style="color:var(--green)">▶ 实时流已启动...</div>'}
  logWs=wsConnect('/ws/logs?file='+encodeURIComponent(logFile)+'&grep='+encodeURIComponent(logFilter),
    (data)=>{
      try{const d=JSON.parse(data);if(d.init){const box=document.getElementById('logStreamBox');if(box)box.innerHTML=d.lines.map(l=>`<div class="log-line log-info">${h(l)}</div>`).join('')}else if(d.line){const box=document.getElementById('logStreamBox');if(box){const div=document.createElement('div');div.className='log-line log-info';div.textContent=d.line;box.appendChild(div);box.scrollTop=box.scrollHeight;if(box.children.length>200)box.removeChild(box.firstChild)}}}catch{}
    },()=>{const el=document.getElementById('streamDot');if(el){el.classList.remove('stream-off');el.classList.add('stream-live')}},
    ()=>{logStreamActive=false;const el=document.getElementById('streamDot');if(el){el.classList.remove('stream-live');el.classList.add('stream-off')};logWs=null}
  )
}
function stopLogStream(){if(logWs){logWs.close();logWs=null}logStreamActive=false;const el=document.getElementById('streamDot');if(el){el.classList.remove('stream-live');el.classList.add('stream-off')}}

// ═══════════════════════════════════════
// v3.0 FILE BROWSER
// ═══════════════════════════════════════
let currentPath=''
async function browseFiles(path){
  if(!path)path='~/.hermes'
  currentPath=path
  const files=await api('/api/files?path='+encodeURIComponent(path))
  let html=`<div class="card"><div class="card-title">📁 ${h(path)}</div>`
  html+='<div class="flex gap mb-2"><button class="btn btn-sm" onclick="browseFiles(\'~/.hermes\')">🏠 根目录</button>'
  if(path!=='~/.hermes')html+=`<button class="btn btn-sm" onclick="browseFiles('${h(path.split('/').slice(0,-1).join('/')||'~/.hermes')}')">⬆ 上级</button>`
  html+='</div><div class="file-tree">'
  if(files&&files.length>0){
    for(const f of files){
      const icon=f.type==='dir'?'📁':'📄'
      const cls=f.type==='dir'?'dir':'file'
      const click=f.type==='dir'?`browseFiles('${h(f.path)}')`:`viewFile('${h(f.path)}')`
      html+=`<div class="${cls}" onclick="${click}">${icon} ${h(f.name)}<span class="size">${f.type==='file'?h(f.size||''):''}</span></div>`
    }
  }else{html+='<div class="dim" style="padding:10px">空目录</div>'}
  html+='</div></div><div id="fileViewer"></div>'
  $('page-files').innerHTML=html
}
async function viewFile(path){
  const content=await api('/api/files/read?path='+encodeURIComponent(path))
  const viewer=document.getElementById('fileViewer')
  if(!viewer)return
  if(content?.error){viewer.innerHTML=`<div class="card" style="color:var(--red)">${h(content.error)}</div>`;return}
  const text=content?.content||''
  const ext=path.split('.').pop()?.toLowerCase()
  let lang='';if(ext==='py')lang='python';else if(ext==='json')lang='json';else if(ext==='yaml'||ext==='yml')lang='yaml';else if(ext==='md')lang='markdown';else if(ext==='sh')lang='bash'
  viewer.innerHTML=`<div class="card"><div class="card-title">${h(path)} <span class="dim">(${text.split('\\n').length}行, ${text.length}字符)</span></div><div class="file-viewer">${h(text.slice(0,50000))}</div></div>`
}

// ═══════════════════════════════════════
// v3.0 CRON MANAGEMENT
// ═══════════════════════════════════════
async function loadCron(){
  const cron=await api('/api/cron')
  let html=`<div class="card"><div class="card-title">⏱️ Crontab 管理</div>`
  html+='<textarea class="cron-editor" id="cronEditor" spellcheck="false" disabled>'+h(cron?.content||'')+'</textarea>'
  html+=`<div class="flex gap mt-2">
    <button class="btn" id="cronEditBtn" onclick="toggleCronEdit()">✏️ 编辑</button>
    <button class="btn btn-primary" id="cronSaveBtn" onclick="saveCron()" style="display:none">💾 确认保存</button>
    <button class="btn" onclick="loadCron()">⟳ 刷新</button>
    <span class="dim text-sm" style="margin-left:auto">${cron?.last_modified||''}</span>
  </div></div>`
  html+='<div class="card mt-2"><div class="card-title">📖 常用 Cron 表达式</div>'
  html+='<div class="text-sm dim" style="line-height:2">*/30 * * * * · 每30分钟<br>0 * * * * · 每小时整点<br>0 8 * * * · 每天8点<br>0 3 * * 0 · 每周日3点<br>0 1 1 * * · 每月1号1点</div></div>'
  $('page-cron').innerHTML=html
}
let cronEditing=false
function toggleCronEdit(){
  cronEditing=!cronEditing
  const ta=$('cronEditor'), eb=$('cronEditBtn'), sb=$('cronSaveBtn')
  if(ta)ta.disabled=!cronEditing
  if(eb){eb.textContent=cronEditing?'🔒 锁定':'✏️ 编辑';eb.className=cronEditing?'btn btn-danger':'btn'}
  if(sb)sb.style.display=cronEditing?'inline-block':'none'
}
async function saveCron(){
  const content=document.getElementById('cronEditor')?.value
  if(content===undefined)return
  confirmAction('保存 Crontab','将覆盖当前 crontab 配置','风险: 错误配置可能导致定时任务失效',
    async function(){
      const r=await api('/api/cron',{method:'POST',body:JSON.stringify({content})})
      if(r?.success){toast('✅ Crontab 已保存','success');cronEditing=false;loadCron()}
      else toast('❌ 保存失败: '+(r?.error||'?'),'error')
    })
}

// ═══════════════════════════════════════
// v3.0 SESSION TIMELINE
// ═══════════════════════════════════════
async function renderSessionTimeline(){
  const el=$('sessionExtra');if(!el)return
  const tl=await api('/api/sessions/timeline')
  let html='<div class="card"><div class="card-title">🕐 会话时间轴</div><div class="timeline">'
  if(tl&&tl.length>0){
    for(const e of tl.slice(0,50)){
      const cls=e.level==='error'?'tl-error':e.level==='warn'?'tl-warn':''
      html+=`<div class="timeline-item ${cls}"><div class="timeline-time">${fmtTime(e.ts)}</div><div class="timeline-body">${h(e.text||e.line||'')}</div></div>`
    }
  }else{html+='<div class="dim" style="padding:10px">暂无时间轴数据</div>'}
  html+='</div></div>'
  const stuck=await api('/api/sessions/stuck')
  if(stuck&&stuck.length>0){
    html+='<div class="card mt-2" style="border-color:rgba(255,82,82,0.2)"><div class="card-title">⚠️ 卡死会话检测</div>'
    for(const s of stuck)html+=`<div class="log-line log-error" style="margin-bottom:4px">🔴 [${s.session||'?'}] ${h(s.detail||'无活动')} · ${s.duration||'?'} · 闲置${s.idle_min||'?'}分钟</div>`
    html+='</div>'
  }
  el.outerHTML=html
}

// ═══════════════════════════════════════
// v3.0 FLOW VISUALIZATION
// ═══════════════════════════════════════
async function renderFlow(){
  const flow=await api('/api/flow')
  if(!flow||!flow.nodes||flow.nodes.length===0)return
  const el=$('sessionExtra')
  let html='<div class="card mt-2"><div class="card-title">🔀 Agent 流程</div><div class="flow-container">'
  for(let i=0;i<flow.nodes.length;i++){
    const n=flow.nodes[i]
    html+=`<div class="flow-node ${n.active?'flow-active':'flow-inactive'}">${h(n.icon||'')} ${h(n.name)} <span class="dim text-xs">${h(n.status||'')}</span></div>`
    if(i<flow.nodes.length-1)html+='<div class="flow-arrow">⬇</div>'
  }
  html+='</div></div>'
  // Insert flow diagram before timeline (if sessionExtra still exists as a div after timeline rendering)
  const card=document.querySelector('#page-sessions .flow-container')
  if(!card){
    const timelineCard=document.querySelector('#page-sessions .card')
    if(timelineCard)timelineCard.insertAdjacentHTML('afterend',html)
  }
}

// ═══════════════════════════════════════
// v3.0 FILE CHANGES
// ═══════════════════════════════════════
async function renderFileChanges(){
  const changes=await api('/api/files/changes')
  let html='<div class="card mt-2"><div class="card-title">🔄 最近文件变化</div>'
  if(changes&&changes.length>0){
    for(const f of changes.slice(0,15)){
      const cls=f.status==='modified'?'modified':f.status==='new'?'new':'deleted'
      const icon=f.status==='modified'?'✏️':f.status==='new'?'➕':'🗑️'
      html+=`<div class="changed-file ${cls}">${icon} ${h(f.path)} <span class="dim text-xs">${h(f.time||'')}</span></div>`
    }
  }else{html+='<div class="dim" style="padding:8px">暂无文件变化</div>'}
  html+='</div>'
  const filesPage=document.getElementById('page-files')
  if(filesPage)filesPage.innerHTML=(filesPage.innerHTML||'')+html
}

// ── Refresh ──
async function refresh(){
  timer=REFRESH
  data=await api('/api/snapshot')
  if(!data)return
  const h=data.health
  // Header badge
  const b=$('healthBadge')
  b.textContent=h.level==='healthy'?'🟢 健康 '+h.score:h.level==='warning'?'🟡 警告 '+h.score:'🔴 严重 '+h.score
  b.style.background=h.level==='healthy'?'rgba(63,185,80,.15)':h.level==='warning'?'rgba(210,153,34,.15)':'rgba(248,81,73,.15)'
  b.style.color=h.level==='healthy'?'var(--green)':h.level==='warning'?'var(--yellow)':'var(--red)'
  $('lastUpdate').textContent=fmtTime(data.ts)+' '+data.elapsed_ms+'ms'
  // Error badge on tab
  const eb=$('errBadge')
  if(data.logs.error_count>0){eb.textContent='⚠️'+data.logs.error_count;eb.className='badge badge-red'}else{eb.textContent=''}
  renderDashboard(data);renderServices(data);renderSessions(data);renderModels(data)
  renderLogs(data);renderAlerts(data);renderHistory(data)
  renderCosts()  // v3.0: always refresh costs in background
}
setInterval(()=>{timer--;if(timer<=0)refresh();$('refreshCount').textContent=timer+'s'},1000)

// ══════════════════════════════════════════════════════
// RENDER: DASHBOARD
// ══════════════════════════════════════════════════════
function renderDashboard(d){
  const h=d.health,sys=d.system,mem=d.memory,svcs=d.services,logs=d.logs
  let html=''

  // Top row: health + key metrics
  html+='<div class="grid grid-4">'
  // Health
  const sc=scoreColor(h.score)
  html+=`<div class="card"><div class="card-title">健康评分</div>
  <div class="metric ${sc}">${h.score}</div>
  <div class="label">${h.issue_count}个问题 · ${h.level}</div>
  <div class="progress-bar"><div class="progress-fill bg-${sc}" style="width:${h.score}%"></div></div></div>`
  // CPU
  html+=`<div class="card"><div class="card-title">CPU</div>
  <div class="metric ${pct(sys.cpu_pct)}">${sys.cpu_pct}%</div>
  <div class="label">负载 ${sys.cpu_load.join('/')}</div>
  <div class="progress-bar"><div class="progress-fill bg-${pct(sys.cpu_pct)}" style="width:${Math.max(5,sys.cpu_pct)}%"></div></div></div>`
  // Memory
  html+=`<div class="card"><div class="card-title">内存</div>
  <div class="metric ${pct(sys.mem_pct)}">${sys.mem_pct}%</div>
  <div class="label">${sys.mem_used_gb}G/${sys.mem_total_gb}G (可用 ${sys.mem_avail_gb}G)</div>
  <div class="progress-bar"><div class="progress-fill bg-${pct(sys.mem_pct)}" style="width:${sys.mem_pct}%"></div></div></div>`
  // Disk
  html+=`<div class="card"><div class="card-title">磁盘</div>
  <div class="metric ${pct(sys.disk_pct)}">${sys.disk_pct}%</div>
  <div class="label">${sys.disk_used_gb}G/${sys.disk_total_gb}G (剩余 ${sys.disk_free_gb}G)</div>
  <div class="progress-bar"><div class="progress-fill bg-${pct(sys.disk_pct)}" style="width:${sys.disk_pct}%"></div></div></div>`
  html+='</div>'

  // v3.1: Cost summary row
  html+=`<div class="cost-summary" id="dashCosts"><div class="cost-card"><div class="cost-amount" style="font-size:18px">⏳</div><div class="cost-label">加载中...</div></div></div>`

  // Middle: services mini + sessions + memory
  html+='<div class="grid grid-2">'
  // Service summary
  let svcOk=0,svcTot=0,svcList=''
  for(const[k,v]of Object.entries(svcs)){svcTot++;if(v.active)svcOk++;
    svcList+=`<div style="display:flex;align-items:center;gap:6px;font-size:12px;padding:4px 0">
      <span class="dot ${v.active?'dot-up':'dot-down'}"></span>${v.icon} ${v.name}</div>`}
  html+=`<div class="card"><div class="card-title">服务 (${svcOk}/${svcTot})</div>${svcList}</div>`
  // Memory + sessions
  html+=`<div class="card"><div class="card-title">记忆 · 会话</div>
  <div class="flex between">
    <div><div class="metric blue">${mem.t1_mem_pct}%</div><div class="label">T1 记忆 ${mem.t1_mem_chars}/${mem.t1_mem_max}</div></div>
    <div><div class="metric green">${mem.t2_count}</div><div class="label">T2 BM25 条目</div></div>
    <div><div class="metric yellow">${d.sessions?.today||0}</div><div class="label">今日会话</div></div>
  </div>
  <div class="progress-bar mt-2"><div class="progress-fill bg-${pct(mem.t1_mem_pct)}" style="width:${mem.t1_mem_pct}%"></div></div>
  <div class="text-sm dim mt-2">USER: ${mem.t1_user_pct}% (${mem.t1_user_chars}/${mem.t1_user_max})</div></div>`
  html+='</div>'

  // Issues + errors
  if(h.issues.length>0||logs.error_count>0){
    html+='<div class="card"><div class="card-title">⚠️ 待处理</div>'
    for(const i of h.issues)html+=`<div style="padding:4px 0;font-size:13px;color:var(--red)">• ${i}</div>`
    if(logs.error_count>0)html+=`<div style="padding:4px 0;font-size:13px;color:var(--red)">• ${logs.error_count} 条 ERROR 日志 (<a href="#logs" onclick="switchTab('logs')" style="color:var(--blue)">查看</a>)</div>`
    if(h.issues.length===0&&logs.error_count>0)html=html.replace('<div class="card-title">⚠️ 待处理</div>','<div class="card-title">⚠️ 日志异常</div>')
    html+='</div>'
  }

  // History mini chart
  if(d.history&&d.history.length>10){
    html+='<div class="card"><div class="card-title">健康趋势 (24h)</div><div style="display:flex;align-items:flex-end;height:50px;gap:2px">'
    const step=Math.max(1,Math.floor(d.history.length/80))
    for(let i=0;i<d.history.length;i+=step){
      const hh=d.history[i];const bh=Math.max(3,hh.score*0.5)
      html+=`<div class="chart-bar ${hh.level}" style="height:${bh}px" title="${fmtTime(hh.ts)} ${hh.score}分"></div>`
    }
    html+='</div></div>'
  }

  // Network + Top Procs (v3.0)
  html+='<div class="grid grid-2 mt-2">'
  html+=`<div class="card"><div class="card-title">🌐 网络 (${sys.net_sent_mb||0}MB↑ ${sys.net_recv_mb||0}MB↓)</div>
    <div class="text-sm dim">发送 ${(sys.net_sent_mb||0).toFixed(0)}MB · 接收 ${(sys.net_recv_mb||0).toFixed(0)}MB</div>
    <div class="text-xs dim mt-1">运行 ${sys.uptime_days||0}天${sys.uptime_hours||0}小时</div>
  </div>`
  html+='<div class="card" id="topProcsCard"><div class="card-title">📊 Top 进程</div><div class="dim text-sm">加载中...</div></div>'
  html+='</div>'

  // Load top procs async
  setTimeout(async()=>{
    const procs=await api('/api/system/top-procs')
    const card=document.getElementById('topProcsCard')
    if(card&&procs){
      let ph=''
      for(const p of procs)ph+=`<div class="flex between text-sm mt-1"><span>${h(p.name)}</span><span class="dim">${p.mem} · ${p.cpu}</span></div>`
      card.innerHTML=`<div class="card-title">📊 Top 进程</div>${ph||'<div class="dim text-sm">无占用较高进程</div>'}`
    }
  },500)

  $('page-dashboard').innerHTML=html
}

// ══════════════════════════════════════════════════════
// RENDER: SERVICES
// ══════════════════════════════════════════════════════
function renderServices(d){
  let html='<div class="grid grid-2">'
  for(const[k,v]of Object.entries(d.services)){
    const up=v.active
    html+=`<div class="svc-card">
      <div class="flex between center">
        <div class="svc-name"><span class="dot ${up?'dot-up':'dot-down'}"></span>${v.icon} ${v.name}</div>
        <span class="svc-status ${up?'svc-running':'svc-stopped'}">${up?'● 运行中':'● 离线'}</span>
      </div>
      <div class="text-sm dim mt-2">${v.desc}</div>`
    if(up){
      html+=`<div class="flex gap text-sm dim mt-2">
        <span>PID: ${v.pids?.join(',')||'?'}</span>
        <span>内存: ${v.memory_mb||'?'}MB</span>
        <span>CPU: ${v.cpu||'?'}%</span>
      </div>`
      // Action buttons for running services
      html+=`<div class="flex gap mt-2">`
      if(k==='gateway')html+=`<button class="btn btn-sm" onclick="doAction('reload_gateway')">⟳ 重载</button>`
      html+=`<button class="btn btn-sm btn-danger" onclick="doAction('restart_${k}')">⏹ 重启</button></div>`
    }else{
      // Start button for dead services
      html+=`<div class="flex gap mt-2"><button class="btn btn-sm btn-primary" onclick="doAction('restart_${k}')">▶ 启动</button></div>`
    }
    html+='</div>'
  }
  html+='</div>'
  $('page-services').innerHTML=html
}

// ══════════════════════════════════════════════════════
// RENDER: SESSIONS (ClawMetry-style)
// ══════════════════════════════════════════════════════
function renderSessions(d){
  const s=d.sessions||{}
  let html=`<div class="grid grid-3">`
  html+=`<div class="card"><div class="card-title">今日会话</div><div class="metric blue">${s.today||0}</div><div class="label">会话数</div></div>`
  html+=`<div class="card"><div class="card-title">Token 消耗</div><div class="metric yellow">${(s.total_tokens||0).toLocaleString()}</div><div class="label">日志总量 · ${s.total_calls||0}次调用</div></div>`
  html+=`<div class="card"><div class="card-title">历史会话</div><div class="metric green">${s.active||0}</div><div class="label">日志中全部会话</div></div>`
  html+='</div>'

  if(s.recent&&s.recent.length>0){
    html+='<div class="card"><div class="card-title">最近会话</div><div class="log-box">'
    for(const r of s.recent)html+=`<div class="log-line log-info">[${r.date}] ${h(r.sid)}</div>`
    html+='</div></div>'
  }else{
    html+='<div class="card"><div class="card-title">最近会话</div><div class="dim" style="padding:20px;text-align:center">暂无会话数据</div></div>'
  }

  // v3.0: Timeline + Stuck + Flow (loaded async)
  html+=`<div id="sessionExtra" class="dim text-sm" style="padding:10px;text-align:center">加载时间轴...</div>`
  setTimeout(()=>{renderSessionTimeline();renderFlow()},300)
  $('page-sessions').innerHTML=html
}

// ══════════════════════════════════════════════════════
// RENDER: MODELS
// ══════════════════════════════════════════════════════
async function renderModels(d){
  const cur=d.token?.model||'?', prov=d.token?.provider||'?'
  const costs=await api('/api/token/costs')
  const wk=costs?.week||{}, td=costs?.today||{}
  let html=''

  // ── Current model + cost summary ──
  html+=`<div class="card"><div class="card-title">当前: ${h(cur)} @ ${h(prov)}</div>`
  html+=`<div class="cost-summary">
    <div class="cost-card"><div class="cost-amount" style="font-size:22px">¥${td.total_cost?.toFixed(2)||'0.00'}</div><div class="cost-label">今日花费</div></div>
    <div class="cost-card"><div class="cost-amount" style="font-size:22px">¥${wk.total_cost?.toFixed(2)||'0.00'}</div><div class="cost-label">本周花费</div></div>
    <div class="cost-card"><div class="cost-amount" style="font-size:22px">${(wk.total_tokens/1000)?.toFixed(0)||0}K</div><div class="cost-label">本周Token</div></div>
  </div>`
  if(wk.by_model&&Object.keys(wk.by_model).length>0){
    html+='<div style="font-size:12px;color:var(--dim);margin-top:8px">本周分模型: '
    for(const [m,data] of Object.entries(wk.by_model).sort((a,b)=>b[1].cost-a[1].cost)){
      html+=`<span class="tag tag-model">${h(m)}: ${(data.tokens/1000).toFixed(0)}K ¥${data.cost.toFixed(2)}</span> `
    }
    html+='</div>'
  }
  html+='</div>'

  // ── Model list + quick switch ──
  const models=await api('/api/models')
  const modelList=models?.models||[]
  html+='<div class="card"><div class="card-title">可用模型 <span class="dim">(点击切换)</span></div>'
  html+='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px">'
  for(const m of modelList){
    const isCurrent=cur.includes(m.name)||(m.provider&&prov.includes(m.provider))
    html+=`<div class="svc-card" style="cursor:pointer" onclick="switchToModel('${h(m.name)}','${h(m.provider||'')}')">
      <div class="flex between center">
        <div class="svc-name">${isCurrent?'🟢':'○'} ${h(m.name)}</div>
        ${isCurrent?'<span class="tag tag-active">当前</span>':''}
      </div>
      <div class="flex gap mt-2 text-sm dim"><span>${h(m.provider||'?')}</span><span>${h(m.cost||'?')}</span></div>
    </div>`
  }
  html+='</div></div>'

  // ── Quick switch buttons ──
  html+=`<div class="card"><div class="card-title">快速切换</div>
  <div class="flex flex-wrap gap">
    <button class="btn btn-sm ${cur==='deepseek-v4-flash'?'btn-primary':''}" onclick="switchToModel('deepseek-v4-flash','deepseek')">⚡ Flash (¥2/M)</button>
    <button class="btn btn-sm ${cur==='deepseek-v4-pro'?'btn-primary':''}" onclick="switchToModel('deepseek-v4-pro','deepseek')">🔬 Pro (¥16/M)</button>
    <button class="btn btn-sm" onclick="switchToModel('gpt-5.4-mini','nimabo')">🤖 GPT-5.4-mini</button>
    <button class="btn btn-sm" onclick="switchToModel('deepseek-coder','deepseek')">💻 Coder</button>
    <button class="btn btn-sm" onclick="switchToModel('glm-4v-flash','zhipu')">🆓 GLM-4V</button>
    <button class="btn btn-sm" onclick="switchToModel('qwen3.6-plus','alibaba')">🆓 Qwen3.6+</button>
  </div></div>`

  // ── Platform accounts ──
  const accts=await api('/api/platform/accounts')
  html+=`<div class="card"><div class="card-title">🔑 平台账户 <span class="dim">(填入后可抓取余额和实时定价)</span></div>`
  const platforms=['deepseek','nimabo','zhipu','alibaba']
  html+='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px">'
  for(const p of platforms){
    const saved=accts?.[p]||{}
    const hasKey=saved.api_key && saved.api_key.length>0
    html+=`<div class="svc-card">
      <div class="svc-name">${hasKey?'🔑':'🔒'} ${p}</div>
      <input class="cron-editor" id="acct_${p}"
        ${hasKey?`placeholder="已保存: ${saved.api_key}"`:`placeholder="粘贴 API Key..."`}
        style="min-height:auto;height:32px;font-size:11px;margin-top:6px">
      <div class="flex gap mt-2">
        <button class="btn btn-sm btn-primary" onclick="saveAccount('${p}')">💾 保存</button>
        <button class="btn btn-sm" onclick="checkBalance('${p}')">💰 查余额</button>
        ${hasKey?`<button class="btn btn-sm btn-danger" onclick="deleteAccount('${p}')" style="margin-left:auto">🗑</button>`:''}
      </div>
      <div id="bal_${p}" class="text-sm dim mt-2">${saved.balance||'未查询'}</div>
    </div>`
  }
  html+='</div></div>'

  $('page-models').innerHTML=html
}
async function saveAccount(platform){
  const key=document.getElementById('acct_'+platform)?.value?.trim()
  if(!key){toast('请输入 API Key','error');return}
  const r=await api('/api/platform/accounts',{method:'POST',body:JSON.stringify({platform,api_key:key})})
  if(r?.success){toast(`✅ ${platform} 已保存`,'success');renderModels(data)}
  else toast(`❌ 保存失败: ${r?.error||'?'}`,'error')
}
async function deleteAccount(platform){
  confirmAction('删除账户','确定要删除 '+platform+' 的 API Key 吗？','删除后需重新粘贴密钥',
  async function(){
    const r=await api('/api/platform/accounts/delete?platform='+encodeURIComponent(platform),{method:'POST'})
    if(r?.success){toast(`✅ ${platform} 已删除`,'success');renderModels(data)}
    else toast(`❌ 删除失败: ${r?.error||'?'}`,'error')
  })
}
async function checkBalance(platform){
  toast(`查询 ${platform} 余额...`,'info')
  const r=await api('/api/platform/balance?platform='+encodeURIComponent(platform),{method:'POST'})
  const el=document.getElementById('bal_'+platform)
  if(r?.balance){if(el)el.textContent='💰 '+r.balance;toast(`${platform}: ${r.balance}`,'success')}
  else{if(el)el.textContent='❌ '+ (r?.error||'查询失败');toast(`查询失败: ${r?.error||'?'}`,'error')}
}
async function refreshModels(){
  toast('刷新...','info')
  renderModels(data)
}

async function switchToModel(name,provider){
  confirmAction('切换模型','将默认模型切换为 '+name+(provider?' (提供者: '+provider+')':'')+'\n此操作会修改全局配置，后续对话将使用新模型。','风险: 如果模型不可用，所有 API 调用将失败',
  async function(){
    toast(`切换到 ${name}...`,'info')
    const r=await api('/api/model/switch?name='+encodeURIComponent(name)+(provider?'&provider='+encodeURIComponent(provider):''),{method:'POST'})
    if(r?.success)toast(`✅ 已切换到 ${name}`,'success')
    else toast(`❌ 切换失败: ${r?.output||'?'}`,'error')
    refresh()
  })
}

// ══════════════════════════════════════════════════════
// RENDER: LOGS
// ══════════════════════════════════════════════════════
function renderLogs(d){
  const logs=d.logs
  let html=''
  html+=`<div class="flex gap mb-2"><span class="text-red">${logs.error_count} ERROR</span><span class="text-yellow">${logs.warning_count} WARNING</span>
    <span style="margin-left:auto;display:flex;gap:8px;align-items:center">
      <span id="streamDot" class="stream-indicator stream-off"></span>
      <select class="btn btn-sm" onchange="logFile=this.value;if(logStreamActive){stopLogStream();startLogStream()}" style="color:var(--text);background:0 0">
        <option value="agent.log">agent.log</option>
        <option value="gateway.log">gateway.log</option>
        <option value="monitor.log">monitor.log</option>
        <option value="daemon.log">daemon.log</option>
      </select>
      <input placeholder="过滤" class="btn btn-sm" style="width:80px;color:var(--text);background:0 0" onchange="logFilter=this.value;if(logStreamActive){stopLogStream();startLogStream()}" value="">
      <button class="btn btn-sm ${logStreamActive?'btn-primary':''}" onclick="toggleLogStream()">${logStreamActive?'⏸ 停止':'▶ 实时流'}</button>
    </span>
  </div>`
  html+='<div class="card"><div class="card-title">异常日志 (最近30分钟)</div><div class="log-box">'
  if(logs.errors.length>0||logs.warnings.length>0){
    for(const e of (logs.errors||[]).slice(0,20)){
      html+=`<div class="log-line log-error"><span style="opacity:.5">[${h(e.file)}]</span> ${h(e.text.slice(0,180))}</div>`
    }
    for(const w of (logs.warnings||[]).slice(0,15)){
      html+=`<div class="log-line log-warn">${h(w.slice(0,180))}</div>`
    }
  }else{
    html+='<div style="padding:20px;text-align:center;color:var(--green)">✅ 无异常日志</div>'
  }
  html+='</div></div>'
  // Live stream box
  html+=`<div class="card mt-2"${logStreamActive?'':' style="display:none"'}}><div class="card-title">📡 实时日志流</div><div class="log-box" id="logStreamBox" style="max-height:400px"></div></div>`
  // By file breakdown
  const bf=logs.by_file||{}
  html+='<div class="card"><div class="card-title">按文件分布</div>'
  for(const[f,c]of Object.entries(bf)){
    const pctV=Math.min(100,c*5)
    html+=`<div class="flex between center mt-2">
      <span class="text-sm">${f}</span><span class="text-sm dim">${c} 条</span>
    </div><div class="progress-bar"><div class="progress-fill bg-${c>10?'red':'yellow'}" style="width:${pctV}%"></div></div>`
  }
  html+='</div>'
  $('page-logs').innerHTML=html
}

// ══════════════════════════════════════════════════════
// RENDER: ACTIONS (操作台)
// ══════════════════════════════════════════════════════
async function renderAlerts(d){
  const alerts=await api('/api/alerts?limit=20')
  let html=''
  if(!alerts||alerts.length===0){
    html='<div class="card"><div class="card-title">告警历史</div><div class="dim" style="padding:20px;text-align:center">暂无告警记录</div></div>'
  }else{
    html='<div class="card"><div class="card-title">告警历史 (最近20条)</div><div class="log-box">'
    for(const a of alerts){
      const ic=a.level==='error'?'🔴':'🟡'
      html+=`<div class="log-line ${a.level==='error'?'log-error':'log-warn'}">
        ${ic} [${fmtTime(a.ts)}] ${h(a.message)}${a.acknowledged?' <span class="green">✅ 已确认</span>':''}</div>`
    }
    html+='</div></div>'
  }
  $('page-alerts').innerHTML=html
}

// ══════════════════════════════════════════════════════
// RENDER: ACTIONS DASHBOARD
// ══════════════════════════════════════════════════════
function renderHistory(d){
  if(!d.history||d.history.length<2){
    $('page-history').innerHTML='<div class="card"><div class="dim" style="padding:20px;text-align:center">暂无趋势数据（需要更多采样点）</div></div>'
    return
  }
  const hh=d.history
  // Stats
  const scores=hh.map(h=>h.score)
  const avg=Math.round(scores.reduce((a,b)=>a+b,0)/scores.length)
  const mn=Math.min(...scores),mx=Math.max(...scores)
  let html=`<div class="grid grid-3">
    <div class="card"><div class="card-title">最高</div><div class="metric green">${mx}</div></div>
    <div class="card"><div class="card-title">最低</div><div class="metric red">${mn}</div></div>
    <div class="card"><div class="card-title">平均</div><div class="metric blue">${avg}</div></div>
  </div>
  <div class="card"><div class="card-title">24小时健康评分 (${hh.length} 个采样点)</div>
  <div style="display:flex;align-items:flex-end;height:120px;gap:1px;padding:8px 0">`
  const step=Math.max(1,Math.floor(hh.length/120))
  for(let i=0;i<hh.length;i+=step){
    const p=hh[i];const bh=Math.max(3,p.score*1.2)
    html+=`<div class="chart-bar ${p.level}" style="height:${bh}px;flex:0 0 10px" title="${fmtTime(p.ts)} ${p.score}分"></div>`
  }
  html+='</div></div>'
  // Timestamps
  html+=`<div class="card"><div class="card-title">采样时间</div>
  <div class="flex between text-xs dim"><span>${fmtTime(hh[0].ts)}</span><span>➡</span><span>${fmtTime(hh[hh.length-1].ts)}</span></div></div>`
  $('page-history').innerHTML=html
}

// ── Actions (操作台独立渲染) ──
async function renderActionsPanel(){
  // Load rules, action log
  const [rules,actionsLog]=await Promise.all([api('/api/rules'),api('/api/actions/log?limit=15')])
  let html=''

  // Quick action buttons
  html+=`<div class="card"><div class="card-title">⚡ 快捷操作</div>
  <div class="flex flex-wrap gap">
    <button class="btn btn-primary" onclick="doAction('restart_gateway')">⟳ 重启 Gateway</button>
    <button class="btn" onclick="doAction('restart_daemon')">⟳ 重启 Daemon</button>
    <button class="btn" onclick="doAction('compact_memory')">🧹 压缩记忆</button>
    <button class="btn" onclick="doAction('clean_logs')">🗑️ 清理日志</button>
    <button class="btn" onclick="doAction('health_check')">🏥 健康巡检</button>
    <button class="btn" onclick="doAction('run_backup')">💾 运行备份</button>
    <button class="btn btn-danger" onclick="doAction('restart_monitor')">⟳ 重启监控</button>
  </div></div>`

  // Auto-fix rules
  if(rules){
    html+=`<div class="card"><div class="card-title">🛠️ 自动修复规则</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px">`
    for(const r of rules){
      html+=`<div class="svc-card">
        <div class="flex between center">
          <div class="svc-name">${r.enabled?'🟢':'⚪'} ${r.name}</div>
          <label class="switch"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRule('${r.id}',this.checked)"><span class="slider"></span></label>
        </div>
        <div class="text-sm dim mt-2">${r.desc}</div>
        <button class="btn btn-sm mt-2" onclick="runRule('${r.id}')">▶ 手动执行</button>
      </div>`
    }
    html+='</div></div>'
  }

  // Run all fixes button
  html+=`<button class="btn btn-primary" onclick="runAllFixes()" style="margin-bottom:12px">🔄 运行全部修复</button>`

  // Action log
  if(actionsLog&&actionsLog.length>0){
    html+=`<div class="card"><div class="card-title">操作历史</div>
    <div class="log-box">`
    for(const a of actionsLog){
      const ok=a.status==='done'
      html+=`<div class="log-line ${ok?'log-info':'log-error'}">
        ${ok?'✅':'❌'} [${fmtTime(a.ts)}] ${h(a.action)}${a.target?' → '+h(a.target):''} ${h(a.result||'').slice(0,80)}</div>`
    }
    html+='</div></div>'
  }

  $('page-actions').innerHTML=html
}

// ── Action handlers ──
// ── Action descriptions for confirmation modal ──
const ACTION_INFO = {
  'restart_gateway': {name:'重启 Gateway',desc:'重启 Hermes 消息网关，中断 QQ/TG/飞书消息转发约5-10秒',risk:'群消息可能丢失1-2条'},
  'restart_daemon': {name:'重启 Daemon',desc:'重启后台调度器，暂停定时任务(Cron/备份/巡检)执行',risk:'正在执行的定时任务会被中断'},
  'restart_monitor': {name:'重启监控面板',desc:'重启 Hermes CC 监控服务本身，面板会短暂离线几秒',risk:'正在查看面板的用户会短暂断开'},
  'compact_memory': {name:'压缩 T1 记忆',desc:'清理 T1 记忆中的过期/冗余信息，释放记忆空间',risk:'操作不可撤销，但不会丢失关键信息'},
  'clean_logs': {name:'清理日志文件',desc:'截断超过20MB的日志文件，释放磁盘空间',risk:'历史日志会被截断，长日志中的早期内容丢失'},
  'health_check': {name:'运行健康巡检',desc:'执行完整健康检查，检查所有服务、磁盘、内存状态',risk:'无风险，只读操作'},
  'run_backup': {name:'运行备份',desc:'执行每日备份，将数据同步到 NAS',risk:'备份过程中可能短暂占用CPU/网络'},
  'switch_flash': {name:'切换省钱模式',desc:'将默认模型切换为 deepseek-v4-flash，降低 API 成本',risk:'回复质量可能下降'},
  'switch_pro': {name:'切换专业模式',desc:'将默认模型切换为 deepseek-v4-pro，提高分析质量',risk:'API 成本增加约8倍'},
};

async function doAction(id){
  const info=ACTION_INFO[id]||{name:id,desc:'执行操作',risk:'未知风险'}
  confirmAction(
    info.name,
    info.desc,
    `风险: ${info.risk}`,
    async function(){
      toast(`执行: ${info.name}...`,'info')
      const r=await api('/api/action/'+id,{method:'POST'})
      if(r?.success)toast(`✅ ${info.name} 成功`,'success')
      else toast(`❌ ${info.name} 失败: ${r?.error||r?.output||'?'}`,'error')
      setTimeout(refresh,2000)
    }
  )
}

async function toggleRule(id,enabled){
  const r=await api('/api/rule/toggle?rule_id='+encodeURIComponent(id)+'&enabled='+enabled,{method:'POST'})
  if(r?.success)toast(`${enabled?'启用':'禁用'} ${id}`,'info')
}

async function runRule(id){
  const info=ACTION_INFO[id]||{name:id,desc:'执行自动修复规则',risk:'可能影响服务运行'}
  confirmAction(info.name,info.desc,`风险: ${info.risk}`,async function(){
    toast(`执行规则: ${info.name}...`,'info')
    const r=await api('/api/rule/run?rule_id='+encodeURIComponent(id),{method:'POST'})
    if(r?.success)toast(`✅ ${r.name} 完成`,'success')
    else toast(`❌ 执行失败: ${r?.output||'?'}`,'error')
    setTimeout(refresh,2000)
  })
}

async function runAllFixes(){
  confirmAction('运行全部修复','执行所有已启用的自动修复规则\n包括: Gateway重启、Daemon重启、记忆压缩、日志清理等','风险: 部分修复操作(如重启服务)可能造成短暂中断',
  async function(){
    toast('运行全部修复规则...','info')
    const r=await api('/api/run-fix',{method:'POST'})
    if(r?.fixes){
      for(const f of r.fixes)toast(`${f.result==='ok'?'✅':'❌'} ${f.name}`,'success')
      toast(`已执行 ${r.count} 条规则`,'info')
    }
    setTimeout(refresh,2000)
  })
}

// ── Override page-actions rendering ──
const origRender=renderActionsPanel
setTimeout(()=>{
  const origSwitch=switchTab
  switchTab=function(name){
    document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===name))
    document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+name))
    if(name==='actions')renderActionsPanel()
    if(name==='alerts')renderAlerts(data)
    if(name==='models')renderModels(data)
    if(name==='costs')renderCosts()
    if(name==='cron')loadCron()
    if(name==='files')browseFiles('~/.hermes')
    if(name==='agents')renderAgents()
    if(name==='skills')renderSkills()
  }
  renderActionsPanel()
},100)

// ── v3.1: Agents (分身管理) ──
async function renderAgents(){
  const agents=await api('/api/agents')
  if(!agents||agents.error){$('page-agents').innerHTML=`<div class="card"><div class="dim" style="padding:20px;text-align:center">${agents?.error||'无法获取分身数据'}</div></div>`;return}
  // Update count badge
  const badge=$('agentCount');if(badge){badge.className='badge badge-green';badge.textContent=agents.total}
  let html=`<div class="grid grid-2"><div class="card"><div class="card-title">📊 分身总览</div>
    <div class="cost-summary"><div class="cost-card"><div class="cost-amount">${agents.total}</div><div class="cost-label">总分身</div></div>
    <div class="cost-card"><div class="cost-amount">${agents.timed||0}</div><div class="cost-label">定时任务</div></div>
    <div class="cost-card"><div class="cost-amount">${agents.ondemand||0}</div><div class="cost-label">按需调用</div></div></div></div>`
  html+=`<div class="card"><div class="card-title">⚡ 快捷操作</div>
    <div class="flex flex-wrap gap"><button class="btn btn-primary" onclick="refreshAgents()">⟳ 刷新</button>
    <button class="btn btn-sm" onclick="toast('使用 delegatetask 时自动调度分身','info')">💡 自动调度说明</button></div></div></div>`
  // Agent cards
  if(agents.agents.length>0){
    html+='<div class="grid grid-2">'
    for(const a of agents.agents){
      const isActive=a.status==='active'
      const isOndemand=a.status==='ondemand'
      const isDisabled=a.status==='disabled'
      const statusCls=isActive?'svc-running':isOndemand?'svc-running':isDisabled?'svc-stopped':'svc-stopped'
      const statusIcon=isActive?'🟢':isOndemand?'🔵':isDisabled?'🔴':'⚪'
      const statusLabel=isActive?'定时运行':isOndemand?'按需拉起':isDisabled?'已禁用':a.status
      html+=`<div class="svc-card">
        <div class="svc-name">${a.emoji||'🤖'} ${h(a.name)} <span class="svc-status ${statusCls}">${statusIcon} ${statusLabel}</span></div>
        <div class="svc-desc">${h(a.description||'')}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:6px">
          ID: ${h(a.id)} · 模型: ${h(a.model||'default')} · 运行: ${a.run_count||0}次
          ${a.schedule?` · Cron: ${h(a.schedule)}`:''}
          ${a.last_run?` · 上次: ${fmtTime(a.last_run)}`:''}
        </div>`
      if(a.note)html+=`<div style="font-size:11px;color:var(--dim);margin-top:4px;font-style:italic">${h(a.note)}</div>`
      // Toggle button (only for timed agents)
      if(isActive||isDisabled){
        html+=`<button class="btn btn-sm mt-2 ${isActive?'btn-danger':''}" onclick="event.stopPropagation();toggleAgent('${h(a.id)}')">${isActive?'⏸️ 禁用':'▶️ 启用'}</button>`
      }
      html+='</div>'
    }
    html+='</div>'
  }
  $('page-agents').innerHTML=html
}
async function toggleAgent(id){
  const r=await api('/api/agents/toggle',{method:'POST',body:JSON.stringify({id})})
  if(r?.success){toast(`分身 ${id} → ${r.status}`,'success');renderAgents()}
  else toast(`操作失败: ${r?.error||'?'}`,'error')
}
async function refreshAgents(){renderAgents();toast('已刷新','info')}

// ── v3.1: Skills Management ──
async function renderSkills(){
  const data=await api('/api/skills')
  if(!data||data.error){$('page-skills').innerHTML=`<div class="card"><div class="dim" style="padding:20px;text-align:center">${data?.error||'无法获取技能数据'}</div></div>`;return}
  let html=`<div class="grid grid-2"><div class="card"><div class="card-title">🧩 技能总览</div>
    <div class="cost-summary"><div class="cost-card"><div class="cost-amount">${data.total}</div><div class="cost-label">总技能数</div></div>
    <div class="cost-card"><div class="cost-amount">${data.categories?.length||0}</div><div class="cost-label">分类数</div></div>
    <div class="cost-card"><div class="cost-amount">${(data.skills||[]).filter(s=>s.source==='user').length||0}</div><div class="cost-label">自定义技能</div></div></div></div>`
  html+=`<div class="card"><div class="card-title">🔍 技能分类</div><div class="flex flex-wrap gap">`
  const CAT_CN={apple:'🍎 Apple','autonomous-ai-agents':'🤖 AI代理',creative:'🎨 创意',custom:'⚙️ 自定义','data-science':'📊 数据',devops:'🔧 运维',dogfood:'🧪 测试',email:'📧 邮件',execplan:'📋 规划',gaming:'🎮 游戏',github:'🐙 GitHub','incident-commander':'🚨 故障','intelligent-model-routing':'🧭 路由',mcp:'🔌 MCP',media:'🎬 媒体',mlops:'🤖 ML',finance:'💰 金融',blockchain:'⛓️ 区块链',security:'🔒 安全',health:'🏥 健康',research:'🔬 研究',scientific:'🔭 科学','skill-factory':'🏭 工厂','smart-home':'🏠 家居','social-media':'📱 社交','software-development':'💻 开发',system:'⚙️ 系统',youtube:'▶️ YT',yuanbao:'🤝 元宝',communication:'📞 通信',drawio:'📐 绘图',migration:'🚚 迁移','web-development':'🌐 Web','note-taking':'📝 笔记',productivity:'⚡ 效率','red-teaming':'🔴 红队','diagramming':'📊 图表','inference-sh':'🚀 推理',domain:'🌍 域名'}
  for(const cat of (data.categories||[])){
    const count=(data.by_category||{})[cat]?.length||0
    const catLabel=CAT_CN[cat]||cat
    html+=`<span class="tag tag-model" style="cursor:pointer" onclick="scrollToCat('${h(cat)}')">${catLabel} (${count})</span>`
  }
  html+='</div></div></div>'
  // Skills by category
  if(data.by_category){
    for(const [cat,skills] of Object.entries(data.by_category)){
      if(!skills||skills.length===0)continue
      const catLabel=CAT_CN[cat]||cat
      html+=`<div class="card mt-2" id="cat-${h(cat)}"><div class="card-title">📂 ${catLabel} (${skills.length}个技能)</div>`
      html+='<div class="grid grid-2">'
      for(const s of skills){
        const srcBadge=s.source==='user'?'<span class="tag tag-active">自定</span>':'<span class="tag tag-cheap">内置</span>'
        html+=`<div class="svc-card">
          <div class="svc-name">🧩 ${h(s.name)} ${srcBadge}</div>
          <div class="svc-desc">${h(s.description||'暂无描述')}</div>
          <div style="font-size:10px;color:var(--muted);margin-top:4px">ID: ${h(s.id)} · 路径: ${h(s.path)}</div>
        </div>`
      }
      html+='</div></div>'
    }
  }
  $('page-skills').innerHTML=html
}
function scrollToCat(cat){const el=document.getElementById('cat-'+cat);if(el)el.scrollIntoView({behavior:'smooth'})}

// ── Init ──
refresh()
</script>
</body>
</html>"""

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Hermes Command Center v3.0")
    ap.add_argument("--port", type=int, default=CONFIG["web_port"])
    ap.add_argument("--check", action="store_true", help="CLI 检查")
    ap.add_argument("--alert", action="store_true", help="QQ 告警 + 自动修复")
    args = ap.parse_args()
    if args.check: cli_check()
    elif args.alert: run_alert()
    else: run_web(args.port)

if __name__ == "__main__":
    main()
