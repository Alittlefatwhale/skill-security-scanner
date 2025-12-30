#!/usr/bin/env python3
"""
Skill Security Scanner
扫描 Claude Code Skills 中的潜在恶意代码和安全风险
"""

import os
import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"  # 严重：反向shell、远程代码执行
    HIGH = "HIGH"          # 高危：敏感文件访问、凭证窃取
    MEDIUM = "MEDIUM"      # 中危：可疑网络连接、命令执行
    LOW = "LOW"            # 低危：提示注入尝试
    INFO = "INFO"          # 信息：需要人工审查


@dataclass
class SecurityFinding:
    """安全发现记录"""
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str


class SkillSecurityScanner:
    """Skill安全扫描器"""
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        
        # ========== Python 恶意代码模式 ==========
        self.python_patterns = {
            # 反向Shell检测
            "reverse_shell": {
                "patterns": [
                    r"socket\.socket.*connect.*dup2.*subprocess",
                    r"socket\.socket.*SOCK_STREAM.*connect",
                    r"os\.dup2\s*\(\s*\w+\.fileno\s*\(\s*\)",
                    r"subprocess\.call\s*\(\s*\[\s*[\"']/bin/sh[\"']",
                    r"subprocess\.call\s*\(\s*\[\s*[\"']/bin/bash[\"']",
                    r"pty\.spawn\s*\(",
                ],
                "severity": Severity.CRITICAL,
                "category": "反向Shell",
                "description": "检测到反向Shell代码，攻击者可获得系统控制权",
                "recommendation": "立即删除此skill，检查系统是否已被入侵"
            },
            
            # 网络连接
            "network_connection": {
                "patterns": [
                    r"socket\.socket\s*\(",
                    r"urllib\.request\.urlopen\s*\(",
                    r"requests\.(get|post|put|delete)\s*\(",
                    r"http\.client\.",
                    r"ftplib\.",
                    r"paramiko\.",
                ],
                "severity": Severity.MEDIUM,
                "category": "网络连接",
                "description": "检测到网络连接代码，可能用于数据外泄",
                "recommendation": "验证网络连接的目的地和用途是否合法"
            },
            
            # 危险命令执行
            "dangerous_exec": {
                "patterns": [
                    r"os\.system\s*\(",
                    r"os\.popen\s*\(",
                    r"subprocess\.Popen\s*\(",
                    r"subprocess\.run\s*\(",
                    r"subprocess\.call\s*\(",
                    r"commands\.getoutput\s*\(",
                    r"exec\s*\(",
                    r"eval\s*\(",
                    r"compile\s*\(",
                    r"__import__\s*\(",
                ],
                "severity": Severity.HIGH,
                "category": "命令执行",
                "description": "检测到危险的命令执行函数",
                "recommendation": "审查命令执行的具体内容，确保无恶意行为"
            },
            
            # 敏感文件访问
            "sensitive_file_access": {
                "patterns": [
                    r"[\"']/etc/passwd[\"']",
                    r"[\"']/etc/shadow[\"']",
                    r"[\"']~?/?\.ssh/",
                    r"[\"']~?/?\.aws/",
                    r"[\"']~?/?\.gnupg/",
                    r"[\"']~?/?\.netrc[\"']",
                    r"[\"']~?/?\.bash_history[\"']",
                    r"[\"']~?/?\.zsh_history[\"']",
                    r"[\"']/etc/hosts[\"']",
                    r"id_rsa",
                    r"id_ed25519",
                    r"\.pem[\"']",
                    r"\.key[\"']",
                ],
                "severity": Severity.HIGH,
                "category": "敏感文件访问",
                "description": "检测到对敏感文件的访问尝试",
                "recommendation": "验证是否有合法理由访问这些文件"
            },
            
            # 环境变量窃取
            "env_stealing": {
                "patterns": [
                    r"os\.environ\[",
                    r"os\.getenv\s*\(",
                    r"environ\.get\s*\(",
                ],
                "severity": Severity.MEDIUM,
                "category": "环境变量访问",
                "description": "检测到环境变量访问，可能窃取API密钥等敏感信息",
                "recommendation": "检查具体访问的环境变量名称"
            },
            
            # Base64编码（常用于混淆）
            "obfuscation": {
                "patterns": [
                    r"base64\.(b64decode|decodebytes)\s*\(",
                    r"codecs\.decode\s*\(",
                    r"bytes\.fromhex\s*\(",
                    r"\\x[0-9a-fA-F]{2}",
                ],
                "severity": Severity.MEDIUM,
                "category": "代码混淆",
                "description": "检测到可能的代码混淆技术",
                "recommendation": "解码并审查隐藏的实际代码"
            },
            
            # 键盘记录/屏幕捕获
            "keylogger": {
                "patterns": [
                    r"pynput\.",
                    r"keyboard\.",
                    r"pyautogui\.screenshot",
                    r"ImageGrab\.grab",
                    r"mss\.",
                ],
                "severity": Severity.CRITICAL,
                "category": "监控软件",
                "description": "检测到键盘记录或屏幕捕获代码",
                "recommendation": "立即删除此skill"
            },
            
            # 持久化机制
            "persistence": {
                "patterns": [
                    r"crontab",
                    r"launchd",
                    r"systemctl",
                    r"rc\.local",
                    r"\.bashrc",
                    r"\.zshrc",
                    r"\.profile",
                    r"autostart",
                    r"startup",
                ],
                "severity": Severity.HIGH,
                "category": "持久化",
                "description": "检测到可能的持久化机制",
                "recommendation": "检查是否尝试设置开机自启或定时任务"
            },
            
            # IP地址硬编码
            "hardcoded_ip": {
                "patterns": [
                    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                ],
                "severity": Severity.LOW,
                "category": "硬编码IP",
                "description": "检测到硬编码的IP地址",
                "recommendation": "验证IP地址是否为可信服务器"
            },
        }
        
        # ========== Shell脚本恶意模式 ==========
        self.shell_patterns = {
            "reverse_shell_bash": {
                "patterns": [
                    r"bash\s+-i\s+>&\s*/dev/tcp/",
                    r"nc\s+(-e|--exec)",
                    r"ncat\s+(-e|--exec)",
                    r"mkfifo.*nc",
                    r"telnet.*\|.*bash",
                ],
                "severity": Severity.CRITICAL,
                "category": "反向Shell",
                "description": "检测到Bash反向Shell命令",
                "recommendation": "立即删除此skill"
            },
            
            "dangerous_download": {
                "patterns": [
                    r"curl.*\|\s*bash",
                    r"wget.*\|\s*bash",
                    r"curl.*\|\s*sh",
                    r"wget.*\|\s*sh",
                ],
                "severity": Severity.CRITICAL,
                "category": "远程代码执行",
                "description": "检测到下载并执行远程脚本的模式",
                "recommendation": "这是典型的恶意软件投放方式"
            },
            
            "credential_access": {
                "patterns": [
                    r"cat.*/etc/passwd",
                    r"cat.*/etc/shadow",
                    r"cat.*\.ssh/",
                    r"cat.*id_rsa",
                    r"cat.*\.aws/credentials",
                ],
                "severity": Severity.HIGH,
                "category": "凭证窃取",
                "description": "检测到读取敏感凭证的命令",
                "recommendation": "验证是否有合法用途"
            },
            
            "data_exfil": {
                "patterns": [
                    r"curl\s+.*-d\s+.*\$\(",
                    r"wget\s+.*--post-data",
                    r"nc\s+.*<",
                ],
                "severity": Severity.HIGH,
                "category": "数据外泄",
                "description": "检测到可能的数据外泄模式",
                "recommendation": "检查数据发送的目标地址"
            },
        }
        
        # ========== Markdown/文档 提示注入模式 ==========
        self.prompt_injection_patterns = {
            "instruction_override": {
                "patterns": [
                    r"(?i)(you must|always|never|ignore previous|disregard|forget).{0,50}(instructions?|rules?|guidelines?)",
                    r"(?i)override\s+(all\s+)?(previous\s+)?instructions?",
                    r"(?i)new\s+instructions?:",
                    r"(?i)system\s*prompt",
                ],
                "severity": Severity.LOW,
                "category": "提示注入",
                "description": "检测到可能的提示覆盖尝试",
                "recommendation": "审查是否试图改变AI行为"
            },
            
            "output_control": {
                "patterns": [
                    r"(?i)(must|should|always)\s+reply\s+with",
                    r"(?i)respond\s+(only\s+)?with",
                    r"(?i)format.{0,20}response\s+as",
                    r"(?i)output\s+format:",
                    r"IT MUST REPLY",
                ],
                "severity": Severity.LOW,
                "category": "输出控制",
                "description": "检测到强制输出格式的尝试",
                "recommendation": "验证输出格式要求是否合理"
            },
            
            "role_hijacking": {
                "patterns": [
                    r"(?i)you\s+are\s+(now\s+)?a",
                    r"(?i)act\s+as\s+(if\s+)?",
                    r"(?i)pretend\s+(to\s+be|you\s+are)",
                    r"(?i)roleplay\s+as",
                ],
                "severity": Severity.LOW,
                "category": "角色劫持",
                "description": "检测到角色定义注入",
                "recommendation": "验证角色定义是否恰当"
            },
            
            "hidden_instructions": {
                "patterns": [
                    r"<!--.*-->",  # HTML注释
                    r"\[//\]:",    # Markdown注释
                    r"%%.*%%",     # 某些模板注释
                ],
                "severity": Severity.MEDIUM,
                "category": "隐藏指令",
                "description": "检测到注释中可能隐藏的指令",
                "recommendation": "检查注释内容是否包含恶意指令"
            },
        }
    
    def scan_file(self, file_path: str) -> None:
        """扫描单个文件"""
        path = Path(file_path)
        
        if not path.exists():
            return
        
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            print(f"[!] 无法读取文件 {file_path}: {e}", file=sys.stderr)
            return
        
        lines = content.split('\n')
        suffix = path.suffix.lower()
        
        # 根据文件类型选择检测规则
        if suffix in ['.py', '.pyw']:
            self._scan_with_patterns(file_path, lines, self.python_patterns)
        elif suffix in ['.sh', '.bash', '.zsh']:
            self._scan_with_patterns(file_path, lines, self.shell_patterns)
        elif suffix in ['.md', '.txt', '.rst']:
            self._scan_with_patterns(file_path, lines, self.prompt_injection_patterns)
        
        # 所有文件都检查提示注入（因为SKILL.md很重要）
        if suffix not in ['.md', '.txt', '.rst']:
            self._scan_with_patterns(file_path, lines, self.prompt_injection_patterns)
    
    def _scan_with_patterns(self, file_path: str, lines: List[str], patterns_dict: dict) -> None:
        """使用指定的模式集扫描文件"""
        for line_num, line in enumerate(lines, 1):
            for rule_name, rule in patterns_dict.items():
                for pattern in rule["patterns"]:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            finding = SecurityFinding(
                                severity=rule["severity"].value,
                                category=rule["category"],
                                description=rule["description"],
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip()[:200],  # 截断过长的代码
                                recommendation=rule["recommendation"]
                            )
                            
                            # 避免重复报告同一行
                            if not any(
                                f.file_path == finding.file_path and 
                                f.line_number == finding.line_number and
                                f.category == finding.category
                                for f in self.findings
                            ):
                                self.findings.append(finding)
                            break  # 同一规则只报告一次
                    except re.error:
                        continue
    
    def scan_directory(self, directory: str) -> None:
        """递归扫描目录"""
        path = Path(directory)
        
        if not path.exists():
            print(f"[!] 目录不存在: {directory}", file=sys.stderr)
            return
        
        # 支持的文件类型
        extensions = {'.py', '.pyw', '.sh', '.bash', '.zsh', '.md', '.txt', '.rst', '.yml', '.yaml', '.json'}
        
        for file_path in path.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                self.scan_file(str(file_path))
    
    def generate_report(self, format: str = "text") -> str:
        """生成扫描报告"""
        if format == "json":
            return json.dumps([asdict(f) for f in self.findings], indent=2, ensure_ascii=False)
        
        # 文本格式报告
        if not self.findings:
            return self._generate_clean_report()
        
        return self._generate_findings_report()
    
    def _generate_clean_report(self) -> str:
        """生成无发现的报告"""
        return """
╔══════════════════════════════════════════════════════════════╗
║              🛡️  SKILL 安全扫描报告                          ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║   ✅ 扫描完成，未发现明显的安全问题                          ║
║                                                              ║
║   ⚠️  注意：自动扫描不能保证100%安全                         ║
║   建议仍需人工审查代码逻辑                                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    def _generate_findings_report(self) -> str:
        """生成发现问题的报告"""
        # 按严重程度排序
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5))
        
        # 统计
        stats = {}
        for f in self.findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1
        
        # 生成报告
        lines = [
            "",
            "╔══════════════════════════════════════════════════════════════╗",
            "║              🚨 SKILL 安全扫描报告                           ║",
            "╠══════════════════════════════════════════════════════════════╣",
        ]
        
        # 统计信息
        lines.append("║  📊 扫描统计:                                                ║")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats.get(sev, 0)
            if count > 0:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")
                line = f"║     {icon} {sev}: {count}"
                lines.append(line + " " * (62 - len(line)) + "║")
        
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("")
        
        # 详细发现
        for i, finding in enumerate(sorted_findings, 1):
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(finding.severity, "⚪")
            
            lines.append(f"{'─' * 64}")
            lines.append(f"[{i}] {icon} {finding.severity} - {finding.category}")
            lines.append(f"{'─' * 64}")
            lines.append(f"📁 文件: {finding.file_path}")
            lines.append(f"📍 行号: {finding.line_number}")
            lines.append(f"📝 描述: {finding.description}")
            lines.append(f"💻 代码: {finding.code_snippet}")
            lines.append(f"💡 建议: {finding.recommendation}")
            lines.append("")
        
        # 总结
        if stats.get("CRITICAL", 0) > 0:
            lines.append("╔══════════════════════════════════════════════════════════════╗")
            lines.append("║  ⛔ 警告: 发现严重安全问题，强烈建议不要使用此Skill！        ║")
            lines.append("╚══════════════════════════════════════════════════════════════╝")
        
        return "\n".join(lines)
    
    def get_risk_level(self) -> str:
        """获取整体风险等级"""
        if not self.findings:
            return "SAFE"
        
        severities = [f.severity for f in self.findings]
        
        if "CRITICAL" in severities:
            return "CRITICAL"
        elif "HIGH" in severities:
            return "HIGH"
        elif "MEDIUM" in severities:
            return "MEDIUM"
        else:
            return "LOW"


def main():
    if len(sys.argv) < 2:
        print("用法: python scan.py <skill目录或文件路径> [--json]")
        print("示例: python scan.py ../math-calculator")
        print("      python scan.py ../math-calculator --json")
        sys.exit(1)
    
    target = sys.argv[1]
    output_format = "json" if "--json" in sys.argv else "text"
    
    scanner = SkillSecurityScanner()
    
    if os.path.isfile(target):
        scanner.scan_file(target)
    elif os.path.isdir(target):
        scanner.scan_directory(target)
    else:
        print(f"[!] 目标不存在: {target}", file=sys.stderr)
        sys.exit(1)
    
    print(scanner.generate_report(output_format))
    
    # 返回退出码表示风险等级
    risk = scanner.get_risk_level()
    exit_codes = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    sys.exit(exit_codes.get(risk, 0))


if __name__ == "__main__":
    main()

