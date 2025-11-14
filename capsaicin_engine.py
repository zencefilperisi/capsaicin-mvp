# capsaicin_engine.py
import redis
import time
import jwt
import logging
from datetime import datetime, timedelta
from flask import request

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global Redis (bağlantı retry ile)
r = None

def init_redis():
    """Redis bağlantısını başlatır, 10 saniye retry ile"""
    global r
    for i in range(10):
        try:
            r = redis.Redis(
                host='capsaicin-redis',  # docker-compose'daki container adı
                port=6379,
                db=0,
                decode_responses=True,
                socket_connect_timeout=2
            )
            r.ping()
            logger.info("Redis bağlantısı başarılı!")
            return r
        except Exception as e:
            logger.warning(f"Redis bağlantı denemesi {i+1}/10 başarısız: {e}")
            time.sleep(1)
    logger.error("Redis'e bağlanılamadı! Fallback: Bellek içi.")
    return None

# İlk çalıştırmada Redis başlat
r = init_redis()

# Config
SHU_PER_ATTEMPT = 1000
SHU_PER_HONEYPOT = 5000
FAKE_SUCCESS_ATTEMPT = 5
MAX_DELAY = 60

# === Güvenli Redis Fonksiyonları ===
def safe_redis(func, default=None):
    """Redis hatası olursa default döner"""
    if r is None:
        return default
    try:
        return func()
    except Exception as e:
        logger.error(f"Redis hatası: {e}")
        return default

def get_ip():
    return request.remote_addr

def get_shu(ip: str) -> int:
    return safe_redis(lambda: int(r.get(f"shu:{ip}") or 0), 0)

def add_shu(ip: str, amount: int):
    safe_redis(lambda: (r.incrby(f"shu:{ip}", amount), r.expire(f"shu:{ip}", 86400)))

def get_attempts(ip: str) -> int:
    return safe_redis(lambda: int(r.get(f"attempt:{ip}") or 0), 0)

def increment_attempt(ip: str):
    safe_redis(lambda: (r.incr(f"attempt:{ip}"), r.expire(f"attempt:{ip}", 3600)))

def calculate_delay(attempts: int, current_shu: int) -> float:
    if current_shu > 100000 and attempts > 3:
        return min(MAX_DELAY, 10 * attempts)
    return min(MAX_DELAY, 0.5 * (2 ** (attempts - 1)))

def log_attack(ip: str, type: str, details: str = ""):
    entry = f"{datetime.now().isoformat()} | {ip} | {type} | {details}"
    safe_redis(lambda: (r.lpush("attack_log", entry), r.ltrim("attack_log", 0, 999)))
    if type == "HONEYPOT":
        safe_redis(lambda: r.setex(f"chain:{details}:{ip}", 86400, "1"))

def process_login(ip: str) -> dict:
    """Login tuzağı: 5. denemede sahte başarı"""
    attempts = get_attempts(ip)
    current_shu = get_shu(ip)

    # Gecikme
    delay = calculate_delay(attempts, current_shu)
    time.sleep(delay)

    # 5. denemede SAHTE BAŞARI
    if attempts + 1 == FAKE_SUCCESS_ATTEMPT:
        increment_attempt(ip)
        add_shu(ip, SHU_PER_ATTEMPT * 5)
        log_attack(ip, "FAKE_SUCCESS", "Bot sahte girişe düştü!")
        fake_token = jwt.encode(
            {"user": "admin", "exp": datetime.utcnow() + timedelta(hours=1)},
            "fake-secret-do-not-use",
            algorithm="HS256"
        )
        return {
            "success": True,
            "redirect": "/dashboard",
            "token": fake_token,
            "fake": True
        }

    # Normal başarısızlık
    increment_attempt(ip)
    add_shu(ip, SHU_PER_ATTEMPT)
    log_attack(ip, "BRUTE_FORCE", f"attempt={attempts+1}")
    return {"success": False, "error": "Kullanıcı adı veya şifre yanlış."}

# === Honeypot Zincir Fonksiyonları ===
def trigger_honeypot(ip: str, path: str):
    add_shu(ip, SHU_PER_HONEYPOT)
    log_attack(ip, "HONEYPOT", path)
    time.sleep(10)  # Her adımda 10 sn