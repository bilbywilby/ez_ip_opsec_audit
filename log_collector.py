#!/usr/bin/env python3
"""System Log Collector Module"""
import os
import glob
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
import hashlib

class LogCollector:
    """Collects and indexes relevant security events from system logs"""
    
    LOG_PATHS = {
        "linux": [
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/kern.log",
            "/var/log/dmesg",
            "/var/log/boot.log",
        ],
        "macos": [
            "/var/log/system.log",
            "/var/log/asl.log",
            "/private/var/log/auth.log",
        ],
        "windows": [
            "C:/Windows/System32/winevt/Logs/Security.evtx",
            "C:/Windows/System32/winevt/Logs/System.evtx",
        ]
    }
    
    PATTERNS = {
        "authentication": r"(failed|invalid|wrong|denied|unauthorized)",
        "connection": r"(connect|disconnect|session|login|logout|accepted)",
        "security": r"(security|violation|intrusion|attack|breach|exploit)",
        "sudo": r"(sudo|su:|permission|privilege|escalat)",
        "vpn": r"(vpn|tunnel|wireguard|openvpn|mullvad|nord|express)",
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log_dirs = config.get('paths', {}).get('logs', '.')
        self.lookback_hours = config.get('logging', {}).get('lookback_hours', 24)
        
    def collect(self, quick_mode: bool = False) -> Dict[str, Any]:
        """Collect and analyze relevant log entries"""
        timestamp = datetime.now().isoformat()
        
        result = {
            "timestamp": timestamp,
            "files_scanned": 0,
            "total_entries": 0,
            "matches_by_pattern": {},
            "recent_alerts": [],
            "log_integrity_hashes": {},
        }
        
        # Determine system type
        system = os.name
        if system == 'posix':
            import platform
            if platform.system() == "Darwin":
                system = "macos"
            else:
                system = "linux"
        
        log_files = self.LOG_PATHS.get(system, [])
        
        if quick_mode:
            # Only check last 100 lines of primary log
            result.update(self._quick_scan(log_files[:1]))
        else:
            # Full log analysis
            result.update(self._full_scan(log_files))
        
        return result
    
    def _quick_scan(self, log_files: List[str]) -> Dict[str, Any]:
        """Lightweight scan for critical issues"""
        result = {
            "files_scanned": 0,
            "total_entries": 0,
            "matches_by_pattern": {},
            "recent_alerts": [],
        }
        
        for log_path in log_files:
            if os.path.exists(log_path):
                result["files_scanned"] += 1
                try:
                    with open(log_path, 'r', errors='ignore') as f:
                        lines = f.readlines()[-100:]
                        result["total_entries"] += len(lines)
                        
                        for pattern_name, pattern in self.PATTERNS.items():
                            import re
                            matches = [l.strip() for l in lines if re.search(pattern, l, re.I)]
                            if matches:
                                result["matches_by_pattern"][pattern_name] = len(matches)
                                
                                # Capture first few matches as alerts
                                for match in matches[:3]:
                                    result["recent_alerts"].append({
                                        "source": log_path,
                                        "pattern": pattern_name,
                                        "entry": match[:200],
                                        "timestamp": datetime.now().isoformat(),
                                    })
                except (IOError, PermissionError):
                    pass
        
        return result
    
    def _full_scan(self, log_files: List[str]) -> Dict[str, Any]:
        """Comprehensive log analysis"""
        result = {
            "files_scanned": 0,
            "total_entries": 0,
            "matches_by_pattern": {},
            "recent_alerts": [],
            "log_integrity_hashes": {},
        }
        
        cutoff_time = datetime.now() - timedelta(hours=self.lookback_hours)
        
        for log_path in log_files:
            if os.path.exists(log_path):
                result["files_scanned"] += 1
                
                # Calculate integrity hash
                result["log_integrity_hashes"][log_path] = self._hash_file(log_path)
                
                try:
                    lines = self._read_compressed_if_needed(log_path)
                    result["total_entries"] += len(lines)
                    
                    for line in lines:
                        if self._is_within_lookback(line, cutoff_time):
                            for pattern_name, pattern in self.PATTERNS.items():
                                import re
                                if re.search(pattern, line, re.I):
                                    if pattern_name not in result["matches_by_pattern"]:
                                        result["matches_by_pattern"][pattern_name] = 0
                                    result["matches_by_pattern"][pattern_name] += 1
                    
                except (IOError, PermissionError):
                    pass
        
        return result
    
    def _read_compressed_if_needed(self, path: str) -> List[str]:
        """Read regular or compressed (.gz) log file"""
        if path.endswith('.gz'):
            with gzip.open(path, 'rt', errors='ignore') as f:
                return f.readlines()
        else:
            with open(path, 'r', errors='ignore') as f:
                return f.readlines()
    
    def _hash_file(self, path: str) -> str:
        """Calculate SHA256 hash of log file for integrity tracking"""
        sha256 = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError):
            return "unreadable"
    
    def _is_within_lookback(self, line: str, cutoff: datetime) -> bool:
        """Check if log entry is within lookback window"""
        # Extract timestamp from common log formats
        import re
        patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # syslog
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # ISO
            r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})',  # Windows
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    ts_str = match.group(1)
                    # Parse based on format (simplified)
                    if 'T' in ts_str:
                        ts = datetime.fromisoformat(ts_str.replace('T', ' '))
                        return ts >= cutoff
                except ValueError:
                    pass
        
        # Default: assume recent
        return True
