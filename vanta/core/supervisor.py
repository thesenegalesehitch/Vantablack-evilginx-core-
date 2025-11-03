import psutil
import time
import os
import signal
from threading import Thread

class VantaSupervisor:
    """
    CLASS: VantaSupervisor
    ROLE: Monitors resources (CPU/RAM) and manages the lifecycle of processes.
    WHY: Ensure the infrastructure stays online even in case of memory leaks or freezing.
    """
    def __init__(self, orchestrator, cpu_limit=80, mem_limit_mb=500):
        self.orchestrator = orchestrator
        self.cpu_limit = cpu_limit
        self.mem_limit_mb = mem_limit_mb
        self.running = True

    def monitor(self):
        """MONITORS process resource usage."""
        while self.running:
            for name, proc in list(self.orchestrator.processes.items()):
                try:
                    p = psutil.Process(proc.pid)
                    cpu_usage = p.cpu_percent(interval=0.1)
                    mem_usage_mb = p.memory_info().rss / (1024 * 1024)

                    if cpu_usage > self.cpu_limit or mem_usage_mb > self.mem_limit_mb:
                        self.orchestrator.log(f"Supervisor: {name} exceeds limits ({cpu_usage}% CPU, {mem_usage_mb}MB RAM). Restarting...", "warning")
                        self.restart_process(name, proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process already dead
                    pass
            time.sleep(10)

    def restart_process(self, name, proc):
        """KILLS a process so it can be restarted by the orchestrator."""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except:
            pass

    def start(self):
        """STARTS the monitoring thread."""
        Thread(target=self.monitor, daemon=True).start()

    def stop(self):
        """STOPS the supervisor."""
        self.running = False
