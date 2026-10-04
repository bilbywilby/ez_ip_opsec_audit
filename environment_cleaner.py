#!/usr/bin/env python3
"""Environment Configuration Collector"""
import os
import platform
import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Any

class EnvironmentCollector:
    """Collects system environment and configuration baseline"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
    def collect(self, quick_mode: bool = False) -> Dict[str, Any]:
        """Collect environment and configuration data"""
        timestamp = datetime.now().isoformat()
        
        result = {
            "timestamp": timestamp,
            "system_info": self._get_system_info(),
            "environment_variables": self._get_environment_vars(),
            "network_config": self._get_network_config(),
            "installed_packages": [],
            "services": [],
            "mounted_filesystems": [],
            "firewall_status": None,
            "selinux_apparmor": None,
        }
        
        if not quick_mode:
            result["installed_packages"] = self._get_installed_packages()
            result["services"] = self._get_running_services()
            result["mounted_filesystems"] = self._get_mounted_fs()
            result["firewall_status"] = self._check_firewall()
            result["selinux_apparmor"] = self._check_mac()
        
        return result
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        return {
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "uname": tuple(platform.uname()),
            "python_version": platform.python_version(),
        }
    
    def _get_environment_vars(self) -> Dict[str, str]:
        """Get environment variables (excluding secrets)"""
        sensitive_prefixes = ['PASSWORD', 'SECRET', 'TOKEN', 'API_KEY', 'PRIVATE', 'KEY']
        
        env = {}
        for key, val in os.environ.items():
            if not any(prefix in key.upper() for prefix in sensitive_prefixes):
                env[key] = val if len(val) < 100 else val[:100] + '...'
            else:
                env[key] = '<redacted>'
        
        return env
    
    def _get_network_config(self) -> Dict[str, Any]:
        """Get network interface configuration"""
        config = {
            "hostname": socket.gethostname(),
            "ip_addresses": [],
            "dns_servers": [],
            "routes": [],
        }
        
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for iface, addresses in addrs.items():
                for addr in addresses:
                    if addr.family.name == 'AF_INET':
                        config["ip_addresses"].append({
                            "interface": iface,
                            "ip": addr.address,
                            "netmask": addr.netmask,
                        })
        except (ImportError, AttributeError):
            pass
        
        # DNS servers
        try:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        config["dns_servers"].append(line.split()[1])
        except (IOError, OSError):
            pass
        
        # Routes
        try:
            routes = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
            config["routes"] = routes.stdout.strip().split('\n')[:10]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return config
    
    def _get_installed_packages(self) -> List[Dict[str, Any]]:
        """Get installed package list"""
        packages = []
        
        try:
            if os.path.exists('/etc/debian_version'):
                # Debian/Ubuntu
                proc = subprocess.run(['dpkg-query', '-W', '-f=${Package} ${Version}\n'],
                                      capture_output=True, text=True, timeout=10)
                for line in proc.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        packages.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "unknown"})
            elif os.path.exists('/etc/redhat-release'):
                # RHEL/CentOS
                proc = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}\n'],
                                      capture_output=True, text=True, timeout=10)
                for line in proc.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        packages.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "unknown"})
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        return packages[:100]  # Limit size
    
    def _get_running_services(self) -> List[Dict[str, Any]]:
        """Get running services"""
        services = []
        
        try:
            proc = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running',
                                   '--no-pager', '--no-legend'], capture_output=True, text=True, timeout=10)
            for line in proc.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        services.append({"name": parts[0], "status": parts[1]})
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return services[:50]
    
    def _get_mounted_fs(self) -> List[Dict[str, Any]]:
        """Get mounted filesystems"""
        mounts = []
        
        try:
            with open('/proc/mounts') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        mounts.append({
                            "device": parts[0],
                            "mount_point": parts[1],
                            "fstype": parts[2],
                            "options": parts[3],
                        })
        except (IOError, OSError):
            pass
        
        return mounts
    
    def _check_firewall(self) -> Dict[str, Any]:
        """Check firewall status"""
        status = {"iptables": None, "ufw": None, "firewalld": None}
        
        try:
            proc = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                status["iptables"] = "running" if 'Chain' in proc.stdout else "empty"
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        try:
            proc = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                status["ufw"] = "active" if 'active' in proc.stdout else "inactive"
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        try:
            proc = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=5)
            status["firewalld"] = proc.stdout.strip() if proc.returncode == 0 else None
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return status
    
    def _check_mac(self) -> Dict[str, Any]:
        """Check SELinux/AppArmor status"""
        status = {"selinux": None, "apparmor": None}
        
        try:
            with open('/etc/selinux/config') as f:
                for line in f:
                    if line.startswith('SELINUX='):
                        status["selinux"] = line.split('=')[1].strip()
        except (IOError, OSError):
            pass
        
        try:
            proc = subprocess.run(['aa-status'], capture_output=True, text=True, timeout=5)
            status["apparmor"] = "loaded" if 'loaded' in proc.stdout else None
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return status
