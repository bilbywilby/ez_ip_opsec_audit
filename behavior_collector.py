#!/usr/bin/env python3
"""User Behavior Anomaly Detection Module"""
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

class BehaviorCollector:
    """Tracks baseline behavior and detects deviations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.baseline_file = config.get('paths', {}).get('baseline', '/tmp/behavior_baseline.json')
        self.session_data_dir = Path(config.get('paths', {}).get('logs', '.')) / 'sessions'
        
    def collect(self, quick_mode: bool = False) -> Dict[str, Any]:
        """Collect behavioral metrics and compare to baseline"""
        timestamp = datetime.now().isoformat()
        
        result = {
            "timestamp": timestamp,
            "baseline_loaded": False,
            "metrics": self._gather_metrics(),
            "anomalies": [],
            "session_id": self._generate_session_id(),
        }
        
        # Load and compare to baseline
        baseline = self._load_baseline()
        if baseline:
            result["baseline_loaded"] = True
            result["anomalies"] = self._compare_to_baseline(result["metrics"], baseline)
        
        # Save current session for trend analysis
        self._save_session(result)
        
        return result
    
    def _gather_metrics(self) -> Dict[str, Any]:
        """Gather behavioral metrics from system"""
        metrics = {
            "current_hour": datetime.now().hour,
            "day_of_week": datetime.now().weekday(),
            "active_users": len(os.popen('users').read().split()),
            "uptime_seconds": self._get_uptime(),
            "recent_login_attempts": self._count_recent_logins(),
            "file_access_count_last_hour": self._count_recent_file_access(),
            "network_connection_count": self._count_active_connections(),
            "new_processes_last_10min": self._count_new_processes(),
            "disk_io_reads_mb": self._get_disk_read_megabytes(),
            "disk_io_writes_mb": self._get_disk_write_megabytes(),
            "bytes_in_network_last_5min": self._get_network_bytes_in(),
            "bytes_out_network_last_5min": self._get_network_bytes_out(),
        }
        return metrics
    
    def _get_uptime(self) -> int:
        """Get system uptime in seconds"""
        try:
            with open('/proc/uptime') as f:
                return int(float(f.read().split()[0]))
        except (IOError, OSError):
            return 0
    
    def _count_recent_logins(self) -> int:
        """Count login attempts in last hour"""
        try:
            with open('/var/log/auth.log' if os.path.exists('/var/log/auth.log') 
                      else '/var/log/secure', 'r', errors='ignore') as f:
                lines = f.readlines()[-1000:]
                return sum(1 for l in lines if 'session opened' in l or 'Accepted' in l)
        except (IOError, PermissionError):
            return 0
    
    def _count_recent_file_access(self) -> int:
        """Estimate file access rate"""
        try:
            # Use /proc/stat for disk activity
            with open('/proc/diskstats') as f:
                lines = f.readlines()
                total_reads = sum(int(l.split()[6]) for l in lines if len(l.split()) > 6)
                return total_reads // 1000  # Rough estimate in KB
        except (IOError, OSError):
            return 0
    
    def _count_active_connections(self) -> int:
        """Count network connections"""
        try:
            import psutil
            return len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
        except (ImportError, psutil.AccessDenied):
            return 0
    
    def _count_new_processes(self) -> int:
        """Count processes started in last 10 minutes"""
        cutoff = datetime.now() - timedelta(minutes=10)
        try:
            import psutil
            count = 0
            for proc in psutil.process_iter(['create_time']):
                try:
                    ct = datetime.fromtimestamp(proc.info['create_time'])
                    if ct >= cutoff:
                        count += 1
                except (psutil.NoSuchProcess, OSError):
                    continue
            return count
        except (ImportError, psutil.AccessDenied):
            return 0
    
    def _get_disk_read_megabytes(self) -> float:
        """Get approximate disk reads since boot"""
        try:
            with open('/proc/diskstats') as f:
                lines = f.readlines()
                sectors = sum(int(l.split()[5]) for l in lines if len(l.split()) > 5)
                return (sectors * 512) / (1024 * 1024)  # Convert to MB
        except (IOError, OSError):
            return 0.0
    
    def _get_disk_write_megabytes(self) -> float:
        """Get approximate disk writes since boot"""
        try:
            with open('/proc/diskstats') as f:
                lines = f.readlines()
                sectors = sum(int(l.split()[9]) for l in lines if len(l.split()) > 9)
                return (sectors * 512) / (1024 * 1024)
        except (IOError, OSError):
            return 0.0
    
    def _get_network_bytes_in(self) -> int:
        """Get network bytes received in last 5 minutes"""
        try:
            with open('/proc/net/dev') as f:
                lines = f.readlines()[2:]  # Skip headers
                total = 0
                for line in lines:
                    parts = line.split()
                    if len(parts) > 9:
                        total += int(parts[1])  # Rx bytes
                return total // 1024  # Convert to KB
        except (IOError, OSError):
            return 0
    
    def _get_network_bytes_out(self) -> int:
        """Get network bytes sent in last 5 minutes"""
        try:
            with open('/proc/net/dev') as f:
                lines = f.readlines()[2:]
                total = 0
                for line in lines:
                    parts = line.split()
                    if len(parts) > 9:
                        total += int(parts[9])  # Tx bytes
                return total // 1024
        except (IOError, OSError):
            return 0
    
    def _load_baseline(self) -> Dict[str, Any]:
        """Load previously established baseline"""
        try:
            path = Path(self.baseline_file)
            if path.exists():
                with open(path) as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
        return None
    
    def _compare_to_baseline(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compare current metrics to baseline and flag anomalies"""
        anomalies = []
        thresholds = {
            "active_users": 3,
            "uptime_seconds": 86400,  # 24hr variance allowed
            "recent_login_attempts": 5,
            "network_connection_count": 10,
            "new_processes_last_10min": 50,
            "bytes_in_network_last_5min": 102400,  # 100MB
            "bytes_out_network_last_5min": 102400,
        }
        
        baseline_metrics = baseline.get("metrics", {})
        
        for metric, threshold in thresholds.items():
            current_val = current.get(metric, 0)
            baseline_val = baseline_metrics.get(metric, 0)
            
            if baseline_val > 0:
                variance = abs(current_val - baseline_val) / max(baseline_val, 1)
                if variance > 2.0:  # 200% deviation
                    anomalies.append({
                        "metric": metric,
                        "current": current_val,
                        "baseline": baseline_val,
                        "variance_percent": round(variance * 100, 1),
                        "severity": "WARNING" if variance < 5.0 else "CRITICAL",
                    })
        
        return anomalies
    
    def _save_session(self, result: Dict[str, Any]):
        """Save session data for trend analysis"""
        self.session_data_dir.mkdir(parents=True, exist_ok=True)
        session_file = self.session_data_dir / f"session-{result['session_id']}.json"
        
        with open(session_file, 'w') as f:
            json.dump(result, f, indent=2)
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        import uuid
        return datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + str(uuid.uuid4())[:8]
    
    def establish_baseline(self):
        """Create new baseline from current metrics"""
        metrics = self._gather_metrics()
        
        baseline = {
            "created": datetime.now().isoformat(),
            "metrics": metrics,
            "sample_count": 1,
        }
        
        path = Path(self.baseline_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        print(f"Baseline established: {path}")
