from flask import Flask, request, render_template, jsonify, session, redirect, url_for
from capsaicin_engine import (
    init_redis, r, get_ip, process_login, trigger_honeypot,
    get_shu, add_shu, log_attack
)
import logging
import time

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'capsaicin_secret_2025'

# Redis başlat (uygulama ilk yüklendiğinde)
init_redis()

# --- Ana Sayfalar ---
@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    ip = get_ip()
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Gerçek admin girişi (korundu)
    if username == "admin" and password == "123":
        session['logged_in'] = True
        # IP'yi temizle
        if r:
            r.delete(f"attempt:{ip}")
            r.delete(f"shu:{ip}")
        return jsonify({"success": True, "redirect": "/dashboard"})

    # Tuzağa düşür (5. denemede sahte başarı)
    result = process_login(ip)
    return jsonify(result), 200 if result.get("success") else 401

# --- Honeypot Zinciri ---
HONEYPOT_CHAIN = [
    ("/superadmin", "Sahte Admin Paneli", "Config dosyası: <a href='/config.json'>/config.json</a>"),
    ("/config.json", "Sahte Config Dosyası", "Backup: <a href='/backup.zip'>/backup.zip</a>"),
    ("/backup.zip", "Sahte Backup ZIP", "Final: <a href='/final-trap'>/final-trap</a>"),
    ("/final-trap", "Sonsuz Yükleme", "Yükleniyor... (sonsuza dek)"),
]

def make_honeypot(path, title, next_link):
    def honeypot():
        ip = get_ip()
        trigger_honeypot(ip, path)

        if path == "/final-trap":
            return f"""
            <div class="loading-screen">
                <div class="spinner"></div>
                <div class="loading-text">{next_link}</div>
            </div>
            <script>
                setTimeout(() => {{
                    const gotcha = document.createElement('div');
                    gotcha.className = 'gotcha';
                    gotcha.innerText = 'GOTCHA! BOT TUZAĞA DÜŞTÜ!';
                    document.body.appendChild(gotcha);
                }}, 3000);
            </script>
            """, 200

        return f"""
        <div style="text-align:center; padding:100px; font-family:sans-serif; color:#fff; background:#000;">
            <h1>{title}</h1>
            <p>{next_link}</p>
            <br><a href="/dashboard" style="color:#ff6666;">Dashboard'a dön</a>
        </div>
        """, 200
    # Flask'ı dinamik route ekleme konusunda kandırıyoruz
    honeypot.__name__ = f"honeypot_{path.replace('/', '')}"
    app.route(path)(honeypot)

for path, title, next_link in HONEYPOT_CHAIN:
    make_honeypot(path, title, next_link)

# --- Dashboard ---
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    ip = get_ip()

    # Veriler (Redis'ten)
    total_attacks = 0 if r is None else r.llen("attack_log")
    max_shu_val = 0
    blocked_ips = []

    if r:
        all_shu_keys = r.keys("shu:*")
        shu_values = [get_shu(ip.split(":", 1)[1]) for ip in all_shu_keys] if all_shu_keys else []
        max_shu_val = max(shu_values) if shu_values else 0
        blocked_ips = [ip.split(":", 1)[1] for ip in all_shu_keys if get_shu(ip.split(":", 1)[1]) > 500000]

    # Zincir durumu
    chain_steps = [step[0] for step in HONEYPOT_CHAIN]
    chain_status = {}
    if r:
        for step in chain_steps:
            chain_status[step] = bool(r.get(f"chain:{step}:{ip}"))

    # Son loglar
    logs = []
    if r:
        logs = r.lrange("attack_log", 0, 49)

    return render_template('dashboard.html',
                         total_attacks=total_attacks,
                         max_shu=max_shu_val,
                         blocked_ips=blocked_ips,
                         chain_steps=chain_steps,
                         chain_status=chain_status,
                         logs=logs)

# --- Saldırı Logları ---
@app.route('/attacks')
def attacks():
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    logs = []
    if r:
        logs = r.lrange("attack_log", 0, 99)

    highlight = request.args.get('filter')
    if highlight == 'total':
        highlight = "Tüm saldırılar listeleniyor."
    elif highlight == 'max_shu':
        highlight = "En yüksek SHU'lu saldırılar."
    else:
        highlight = None

    return render_template('attacks.html', logs=logs, highlight=highlight)

# --- Diğer ---
@app.route('/settings')
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('settings.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

# --- Hata Sayfası (Redis yoksa) ---
@app.errorhandler(500)
def internal_error(error):
    return "<h1>Redis başlatılıyor... Lütfen 10 saniye bekleyin.</h1>", 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)