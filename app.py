from flask import Flask, request, render_template, jsonify, session, redirect, url_for
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'capsaicin_secret_2025'  # Oturum için

# --- Kapsaisin Motoru ---
class CapsaicinEngine:
    def __init__(self):
        self.threat_log = defaultdict(list)
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

        recent = [t for t in attempts if now - t < 10]
        if len(recent) > 5:
            return self.shu_levels["scanner"]

        if "/login" in path and login_attempts > 2:
            return self.shu_levels["brute_force"]

        if "bot" in user_agent.lower():
            return self.shu_levels["suspicious"]

        self.threat_log[ip] = [t for t in attempts if now - t < 60]
        self.threat_log[ip].append(now)
        return self.shu_levels["normal"]

capsaicin = CapsaicinEngine()

# --- Ana Sayfalar ---
@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    login_attempts = request.cookies.get(f'attempts_{ip}', '0')
    attempts = int(login_attempts) + 1 if username else 0

    shu = capsaicin.calculate_shu(ip, request.path, user_agent, attempts)

    # ACILI YANIT
    if shu > 50000:
        delay = min(shu / 200000, 5)
        time.sleep(delay)
        resp = jsonify({"error": "Sunucu meşgul. Lütfen daha sonra deneyin."})
        resp.status_code = 429
        resp.set_cookie(f'attempts_{ip}', str(attempts), max_age=300)
        return resp

    # BAŞARILI GİRİŞ
    if username == "admin" and password == "123":
        session['logged_in'] = True
        resp = jsonify({"success": True, "redirect": "/dashboard"})
        resp.set_cookie(f'attempts_{ip}', '0', max_age=300)
        return resp

    # Yanlış giriş
    resp = jsonify({"error": "Kullanıcı adı veya şifre yanlış."})
    resp.set_cookie(f'attempts_{ip}', str(attempts), max_age=300)
    return resp, 401

# --- Dashboard ve Diğer Sayfalar ---
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    # Gerçek veri (örnek)
    total_attacks = 127
    max_shu = 1500000
    blocked_ips = ['192.168.1.100', '203.0.113.45', '10.0.0.5']
    
    return render_template('dashboard.html', 
                         total_attacks=total_attacks,
                         max_shu=max_shu,
                         blocked_ips=blocked_ips,
                         username=session.get('username'))

@app.route('/attacks')
def attacks():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    filter_type = request.args.get('filter')
    
    if filter_type == 'total':
        highlight = "Tüm saldırılar listeleniyor."
    elif filter_type == 'max_shu':
        highlight = "En yüksek SHU'lu saldırılar."
    else:
        highlight = None

    return render_template('attacks.html', highlight=highlight)

@app.route('/settings')
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('settings.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)