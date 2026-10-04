#!/usr/bin/env python3
"""Process Monitoring Collector Module"""
import psutil
from datetime import datetime
from typing import Dict, List, Any
import platform

class ProcessCollector:
    """Collects and analyzes process-level data"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.suspicious_patterns = config.get('process_monitoring', {}).get('suspicious_process_names', [])
        self.hidden_process_detection = config.get('process_monitoring', {}).get('detect_hidden', False)
        
    def collect(self, quick_mode: bool = False) -> Dict[str, Any]:
        """Collect process information"""
        timestamp = datetime.now().isoformat()
        
        result = {
            "timestamp": timestamp,
            "total_processes": 0,
            "top_cpu_consumers": [],
            "top_memory_consumers": [],
            "suspicious_processes": [],
            "network_bound_processes": [],
            "process_tree_overview": {},
        }
        
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                                 'username', 'status', 'create_time']))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            # Fallback for restricted environments
            processes = []
        
        result["total_processes"] = len(processes)
        
        if not quick_mode:
            # Update CPU/memory percentages (requires iteration)
            for proc in processes:
                try:
                    proc.cpu_percent(interval=0.1)
                    proc.memory_percent()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            
            # Sort and capture top consumers
            cpu_sorted = sorted([p.info for p in processes 
                               if p.info['cpu_percent'] and p.info['cpu_percent'] > 1],
                              key=lambda x: x['cpu_percent'] or 0, reverse=True)[:10]
            mem_sorted = sorted([p.info for p in processes 
                               if p.info['memory_percent'] and p.info['memory_percent'] > 0.1],
                              key=lambda x: x['memory_percent'] or 0, reverse=True)[:10]
            
            result["top_cpu_consumers"] = cpu_sorted
            result["top_memory_consumers"] = mem_sorted
            
            # Detect suspicious processes
            result["suspicious_processes"] = self._scan_suspicious(processes)
            
            # Detect processes with network connections
            result["network_bound_processes"] = self._find_network_processes(processes)
            
            # Process tree snapshot (first 50 processes)
            result["process_tree_overview"] = self._snapshot_process_tree(processes[:50])
            
        return result
    
    def _scan_suspicious(self, processes) -> List[Dict[str, Any]]:
        """Identify potentially malicious processes"""
        suspicious = []
        
        for proc in processes:
            try:
                info = proc.info
                name_lower = info['name'].lower() if info['name'] else ''
                
                # Check against known suspicious patterns
                for pattern in self.suspicious_patterns:
                    if pattern.lower() in name_lower:
                        suspicious.append({
                            "pid": info['pid'],
                            "name": info['name'],
                            "user": info['username'],
                            "pattern_matched": pattern,
                            "cpu": info.get('cpu_percent', 0),
                            "memory": info.get('memory_percent', 0),
                            "create_time": datetime.fromtimestamp(info['create_time']).isoformat() if info['create_time'] else None,
                        })
                        break
                
                # Additional heuristics
                if self._is_hidden_process(proc):
                    suspicious.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "user": info['username'],
                        "type": "hidden_process",
                        "cpu": info.get('cpu_percent', 0),
                        "memory": info.get('memory_percent', 0),
                    })
                    
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        
        return suspicious
    
    def _is_hidden_process(self, proc) -> bool:
        """Detect hidden/invisible processes"""
        if not self.hidden_process_detection:
            return False
            
        try:
            # Cross-check: process exists in psutil but not in /proc (Linux)
            if platform.system() == "Linux":
                import os
                proc_path = f"/proc/{proc.pid}"
                if not os.path.exists(proc_path):
                    return True
                    
                # Check for anomalous parent PID relationships
                ppid = proc.ppid()
                if ppid == 0 or ppid == proc.pid:
                    return True
                    
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
            
        return False
    
    def _find_network_processes(self, processes) -> List[Dict[str, Any]]:
        """Find processes with active network connections"""
        network_procs = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            conn_pids = set(c.pid for c in connections if c.pid)
            
            for proc in processes:
                info = proc.info
                if info['pid'] in conn_pids:
                    network_procs.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "connections": sum(1 for c in connections if c.pid == info['pid']),
                    })
        except psutil.AccessDenied:
            pass
            
        return network_procs
    
    def _snapshot_process_tree(self, processes) -> Dict[str, Any]:
        """Create simplified process tree view"""
        tree = {"children": [], "stats": {"total": len(processes)}}
        
        # Count by parent process
        parent_counts = {}
        for proc in processes:
            try:
                ppid = proc.ppid()
                parent_counts[ppid] = parent_counts.get(ppid, 0) + 1
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
        tree["by_parent"] = dict(sorted(parent_counts.items(), key=lambda x: -x[1])[:20])
        return tree
