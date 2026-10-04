#!/usr/bin/env python3
"""Signature-Based Threat Detection Engine"""
import re
from datetime import datetime
from typing import Dict, List, Any, Pattern

class PatternMatcher:
    """Matches collected data against known threat signatures"""
    
    SIGNATURES = {
        "reconnaissance": [
            {
                "name": "PORT_SCAN_INDICATOR",
                "regex": r"(nmap|masscan|zmap|scanport)",
                "severity": "HIGH",
                "description": "Known port scanning tool detected",
            },
            {
                "name": "NETWORK_ENUMERATION",
                "regex": r"(netstat\s+-a|ip\s+addr|ifconfig|arp\s+-a)",
                "severity": "MEDIUM",
                "description": "Network enumeration command detected",
            },
        ],
        "credential_theft": [
            {
                "name": "PASSWD_ACCESS",
                "regex": r"(/etc/passwd|/etc/shadow|\.gnupg|\.ssh/id_) ",
                "severity": "CRITICAL",
                "description": "Sensitive credential file accessed",
            },
            {
                "name": "CREDENTIAL_DUMP_TOOL",
                "regex": r"(mimikatz|procdump|sekurlsa)",
                "severity": "CRITICAL",
                "description": "Credential dumping tool signature",
            },
        ],
        "persistence": [
            {
                "name": "SUDOERS_MODIFICATION",
                "regex": r"(visudo|/etc/sudoers|/etc/sudoers\.d/)",
                "severity": "CRITICAL",
                "description": "Sudoers configuration touched",
            },
            {
                "name": "CRON_PERSISTENCE",
                "regex": r"(crontab\s+-e|/etc/cron\.(d|daily|weekly)/)",
                "severity": "HIGH",
                "description": "Cron job modification detected",
            },
            {
                "name": "SYSTEMD_PERSISTENCE",
                "regex": r"(systemctl.*enable|/etc/systemd/system/)",
                "severity": "HIGH",
                "description": "Systemd persistence mechanism",
            },
        ],
        "command_control": [
            {
                "name": "REVERSE_SHELL_PATTERN",
                "regex": r"(bash\s+-i|nc\s+-e|/dev/tcp/)",
                "severity": "CRITICAL",
                "description": "Reverse shell attempt detected",
            },
            {
                "name": "C2_COMMUNICATION",
                "regex": r"(beacon|callback|exfil|c2server)",
                "severity": "CRITICAL",
                "description": "Command & control communication",
            },
        ],
        "crypto_mining": [
            {
                "name": "XMIGER_MINER",
                "regex": r"(xmrig|minerd|stratum\+tcp://)",
                "severity": "CRITICAL",
                "description": "Cryptocurrency mining activity",
            },
            {
                "name": "POOL_CONNECTION",
                "regex": r"(pool\.mining|stratum\+ssl://)",
                "severity": "HIGH",
                "description": "Mining pool connection attempt",
            },
        ],
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled_categories = config.get('analyzers', {}).get('enabled_categories', 
                                                                list(self.SIGNATURES.keys()))
        self.compiled_patterns = self._compile_signatures()
        
    def _compile_signatures(self) -> Dict[str, List[Dict[str, Any]]]:
        """Pre-compile regex patterns for performance"""
        compiled = {}
        
        for category, signatures in self.SIGNATURES.items():
            if category not in self.enabled_categories:
                continue
                
            compiled[category] = []
            for sig in signatures:
                try:
                    sig['compiled'] = re.compile(sig['regex'], re.I)
                    compiled[category].append(sig)
                except re.error:
                    print(f"Warning: Invalid regex for {sig['name']}")
        
        return compiled
    
    def analyze(self, network_data: Dict[str, Any],
                process_data: Dict[str, Any],
                log_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan all data against threat signatures"""
        findings = []
        
        # Aggregate text content to scan
        text_contents = self._extract_text_content(network_data, process_data, log_data)
        
        # Match against signatures
        for category, signatures in self.compiled_patterns.items():
            for sig in signatures:
                for content in text_contents:
                    if sig['compiled'].search(content):
                        findings.append({
                            "type": sig['name'],
                            "category": category,
                            "severity": sig['severity'],
                            "description": sig['description'],
                            "matched_pattern": sig['regex'][:50] + "...",
                            "timestamp": datetime.now().isoformat(),
                        })
                        break  # One hit per signature enough
        
        return findings
    
    def _extract_text_content(self, *data_sources: Dict[str, Any]) -> List[str]:
        """Extract all text fields from data sources for pattern matching"""
        contents = []
        
        for source in data_sources:
            contents.extend(self._flatten_dict_values(source))
        
        return contents
    
    def _flatten_dict_values(self, obj, max_depth: int = 3) -> List[str]:
        """Recursively extract string values from nested structures"""
        values = []
        
        if isinstance(obj, dict):
            for val in obj.values():
                if isinstance(val, (dict, list)) and max_depth > 0:
                    values.extend(self._flatten_dict_values(val, max_depth - 1))
                elif isinstance(val, str):
                    values.append(val[:1000])  # Limit length
                elif isinstance(val, (int, float)):
                    values.append(str(val))
        elif isinstance(obj, list):
            for item in obj:
                values.extend(self._flatten_dict_values(item, max_depth))
        
        return values
    
    def update_signature(self, category: str, name: str, regex: str, 
                         severity: str, description: str):
        """Add custom signature dynamically"""
        if category not in self.compiled_patterns:
            self.compiled_patterns[category] = []
        
        try:
            compiled = re.compile(regex, re.I)
            self.compiled_patterns[category].append({
                'name': name,
                'regex': regex,
                'compiled': compiled,
                'severity': severity,
                'description': description,
            })
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
