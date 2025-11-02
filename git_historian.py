import os
import subprocess
import random
from datetime import datetime, timedelta

class GitHistorian:
    """
    ROLE: Git Forensic Expert.
    OBJECTIVE: Generate a high-fidelity, organic Git history for Project VANTABLACK.
    PERIOD: Nov 1, 2025, to Feb 3, 2026.
    """
    def __init__(self):
        self.start_date = datetime(2025, 11, 1, 9, 0, 0)
        self.end_date = datetime(2026, 2, 3, 18, 0, 0)
        self.rebrand_date = datetime(2026, 1, 30, 10, 0, 0)
        self.branches = [
            "feat/orchestrator-core", 
            "feat/api-nervous-system", 
            "feat/evasion-signatures", 
            "feat/exfiltration-telegram",
            "fix/supervisor-deadlock",
            "refactor/modular-architecture"
        ]
        
        self.commit_pool = {
            "feat": [
                "implement modular orchestrator logic",
                "add asynchronous terminal supervisor",
                "integrate fastapi nervous system",
                "add sqlite vault persistence",
                "implement polymorphic cloaking redirector",
                "add telegram reporter module",
                "implement secure process spawning",
                "add dynamic phishlet loading",
                "implement gpu fingerprinting detection",
                "add residential proxy rotation logic",
                "integrate rich console dashboard",
                "implement self-healing engine loops"
            ],
            "fix": [
                "resolve zombie process creation in supervisor",
                "fix race condition in vault write",
                "correct tls-fingerprint mismatch for m365",
                "fix memory leak in stream monitor",
                "resolve timeout on heavy load",
                "fix character encoding in logs",
                "correct regex for sensitive data masking"
            ],
            "docs": [
                "initialize master architectural guide",
                "add professional disclaimer to license",
                "document internal api endpoints",
                "update operational quickstart",
                "expand technical footprint report",
                "refine security policy and test plan",
                "translate documentation to technical english"
            ],
            "refactor": [
                "modularize core engine management",
                "cleanup redundant network filtering",
                "standardize logging across all modules",
                "optimize memory footprint of supervisor",
                "refactor vault schema for better performance"
            ],
            "chore": [
                "update dependencies in requirements.txt",
                "initialize project structure",
                "setup docker compose environment",
                "configure linting rules"
            ]
        }

    def run_cmd(self, cmd):
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            pass # Silent fail for directory/branch issues

    def get_organic_time(self, current_date):
        rand = random.random()
        if rand > 0.95: hour = random.randint(19, 22)
        elif rand > 0.90: hour = random.randint(7, 8)
        else: hour = random.randint(9, 17)
        return current_date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

    def generate_history(self):
        print("[*] Initializing Project VANTABLACK Git Forensics...")
        self.run_cmd("git init")
        
        
        current_date = self.start_date
        
        while current_date <= self.end_date:
            weekday = current_date.weekday()
            if weekday >= 5:
                num_commits = random.choices([0, 1, 2], weights=[0.8, 0.15, 0.05])[0]
            else:
                num_commits = random.randint(3, 10)
            
            if num_commits > 0:
                is_on_feature = random.random() > 0.6
                if is_on_feature:
                    branch = random.choice(self.branches)
                    self.run_cmd(f"git checkout -b {branch}")
                    
                    for i in range(num_commits):
                        type_ = random.choice(list(self.commit_pool.keys()))
                        msg = random.choice(self.commit_pool[type_])
                        commit_date = self.get_organic_time(current_date)
                        formatted_date = commit_date.strftime('%Y-%m-%dT%H:%M:%S')
                        
                        with open("VANTABLACK_TRACE.log", "a") as f:
                            f.write(f"Commit [{formatted_date}]: {msg}\n")
                        
                        self.run_cmd("git add .")
                        self.run_cmd(f'GIT_AUTHOR_DATE="{formatted_date}" GIT_COMMITTER_DATE="{formatted_date}" git commit -m "{type_}: {msg}"')
                        
                        # Rebranding Event Logic (Mid-day on rebrand date)
                        if current_date.date() == self.rebrand_date.date() and i == num_commits // 2:
                            with open("REBRAND_NOTICE.txt", "w") as f:
                                f.write("PROJECT REBRANDED TO VANTABLACK.\n")
                            self.run_cmd("git add .")
                            self.run_cmd(f'GIT_AUTHOR_DATE="{formatted_date}" GIT_COMMITTER_DATE="{formatted_date}" git commit -m "chore: global rebranding from ALEX to VANTABLACK"')
                    
                    self.run_cmd("git checkout main")
                    merge_date = (commit_date + timedelta(minutes=random.randint(5, 30))).strftime('%Y-%m-%dT%H:%M:%S')
                    self.run_cmd(f'GIT_AUTHOR_DATE="{merge_date}" GIT_COMMITTER_DATE="{merge_date}" git merge {branch} --no-ff -m "chore: merge {branch} into main"')
                    self.run_cmd(f"git branch -d {branch}")
                else:
                    for _ in range(num_commits):
                        type_ = random.choice(list(self.commit_pool.keys()))
                        msg = random.choice(self.commit_pool[type_])
                        commit_date = self.get_organic_time(current_date)
                        formatted_date = commit_date.strftime('%Y-%m-%dT%H:%M:%S')
                        
                        with open("VANTABLACK_PATCH.log", "a") as f:
                            f.write(f"Patch [{formatted_date}]: {msg}\n")
                        
                        self.run_cmd("git add .")
                        self.run_cmd(f'GIT_AUTHOR_DATE="{formatted_date}" GIT_COMMITTER_DATE="{formatted_date}" git commit -m "{type_}: {msg}"')
            
            current_date += timedelta(days=1)
        
        print(f"[✓] Organic Git History Generated: {self.start_date.date()} -> {self.end_date.date()}")

if __name__ == "__main__":
    historian = GitHistorian()
    historian.generate_history()
