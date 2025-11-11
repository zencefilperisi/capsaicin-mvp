# capsaicin_engine.py
import time
from collections import defaultdict

class CapsaicinEngine:
    def __init__(self):
        self.threat_log = defaultdict(list)  # IP → [zamanlar]
        self.shu_levels = {
            "normal": 0,
            "suspicious": 5000,
            "brute_force": 100000,
            "scanner": 500000,
            "aggressive": 1000000
        }

    def calculate_shu(self, ip, path, user_agent, login_attempts=0):
        now = time.time()
        attempts = self.threat_log[ip]

        # Son 10 saniyede 5+ istek → scanner
        recent = [t for t in attempts if now - t < 10]
        if len(recent) > 5:
            return self.shu_levels["scanner"]

        # Login sayfasında 3+ başarısız → brute force
        if "/login" in path and login_attempts > 2:
            return self.shu_levels["brute_force"]

        # Bot izi
        if "bot" in user_agent.lower() or "spider" in user_agent.lower():
            return self.shu_levels["suspicious"]

        # Temiz
        self.threat_log[ip] = [t for t in attempts if now - t < 60]  # 1 dk sakla
        self.threat_log[ip].append(now)
        return self.shu_levels["normal"]