#!/bin/bash
# ================================================================
#   GUARD VPN PANEL - Professional Installer v1.1
#   Built by LOCALVPS
#   Telegram : t.me/localvps
#   GitHub   : github.com/localvps
# ================================================================

set -euo pipefail

# ── Color Palette ───────────────────────────────────────────────
R='\e[0;31m';  BR='\e[1;31m'
G='\e[0;32m';  BG='\e[1;32m'
Y='\e[0;33m';  BY='\e[1;33m'
B='\e[0;34m';  BB='\e[1;34m'
M='\e[0;35m';  BM='\e[1;35m'
C='\e[0;36m';  BC='\e[1;36m'
W='\e[0;37m';  BW='\e[1;37m'
DIM='\e[2m';   NC='\e[0m'

sep()  { echo -e "${DIM}${B}  ────────────────────────────────────────────────────${NC}"; }
step() { echo ""; echo -e "${BC}  ❯ ${BW}$1${NC}"; }
ok()   { echo -e "  ${BG}✔${NC}  $1"; }
info() { echo -e "  ${BB}•${NC}  ${W}$1${NC}"; }

spin() {
  local pid=$1 msg=$2
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${BC}${frames[$i]}${NC}  ${W}%s${NC}   " "$msg"
    i=$(( (i+1) % 10 ))
    sleep 0.1
  done
  printf "\r  ${BG}✔${NC}  ${W}%s${NC}   \n" "$msg"
}

progress() {
  local cur=$1 total=$2 msg=$3
  local w=38 pct=$(( cur * 100 / total ))
  local filled=$(( w * cur / total )) empty=$(( w - filled ))
  local bar=""
  for _ in $(seq 1 $filled); do bar="${bar}▓"; done
  for _ in $(seq 1 $empty);  do bar="${bar}░"; done
  printf "\r  ${M}[${C}%s${M}]${NC} ${BW}%3d%%${NC}  ${DIM}%s${NC}   " "$bar" "$pct" "$msg"
  [ "$cur" -ge "$total" ] && echo ""
}

if [ "$(id -u)" -ne 0 ]; then
  echo -e "\n${BR}  ✖  This script must be run as root.${NC}\n"
  exit 1
fi

clear

# ================================================================
#   BANNER
# ================================================================
echo ""
echo -e "${BM}  ╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}  ${BC}  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗       ${BM}║${NC}"
echo -e "${BM}  ║${NC}  ${BC} ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗      ${BM}║${NC}"
echo -e "${BM}  ║${NC}  ${BC} ██║  ███╗██║   ██║███████║██████╔╝██║  ██║      ${BM}║${NC}"
echo -e "${BM}  ║${NC}  ${BC} ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║      ${BM}║${NC}"
echo -e "${BM}  ║${NC}  ${BC} ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝      ${BM}║${NC}"
echo -e "${BM}  ║${NC}  ${BC}  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝       ${BM}║${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BW}VPN Panel Installer${NC}  ${DIM}v1.1${NC}  ${DIM}│${NC}  ${M}Built by LOCALVPS${NC}    ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${DIM}github.com/localvps${NC}  ${DIM}│${NC}  ${DIM}t.me/localvps${NC}           ${BM}║${NC}"
echo -e "${BM}  ╚══════════════════════════════════════════════════════╝${NC}"
echo ""
sep

# ================================================================
#   PRE-FLIGHT
# ================================================================
step "System Requirements"
info "Ubuntu 20.04 / 22.04 / 24.04  (root access required)"
info "Ports: custom (you will be asked below)"
info "Dependencies: python3, pip3, gunicorn, iptables"
sep

# ================================================================
#   USER PROMPTS
# ================================================================
step "Panel Configuration"
echo ""

echo -e "  ${BY}[1]${NC} Panel Port"
echo -e "      ${DIM}1) Default — 6565${NC}"
echo -e "      ${DIM}2) Custom${NC}"
printf "  ${BW}Choice [1/2]: ${NC}"; read -r port_choice
if [ "$port_choice" = "2" ]; then
  printf "  ${BW}Enter port: ${NC}"; read -r PORT
else
  PORT=6565
fi
ok "Port set to ${BC}${PORT}${NC}"
echo ""

echo -e "  ${BY}[2]${NC} Admin Username"
echo -e "      ${DIM}1) Default — admin${NC}"
echo -e "      ${DIM}2) Custom${NC}"
printf "  ${BW}Choice [1/2]: ${NC}"; read -r user_choice
if [ "$user_choice" = "2" ]; then
  printf "  ${BW}Enter username: ${NC}"; read -r ADMIN_USER
else
  ADMIN_USER="admin"
fi
ok "Username set to ${BC}${ADMIN_USER}${NC}"
echo ""

echo -e "  ${BY}[3]${NC} Admin Password"
echo -e "      ${DIM}1) Default — admin123${NC}"
echo -e "      ${DIM}2) Custom${NC}"
printf "  ${BW}Choice [1/2]: ${NC}"; read -r pass_choice
if [ "$pass_choice" = "2" ]; then
  printf "  ${BW}Enter password: ${NC}"; read -r ADMIN_PASS
else
  ADMIN_PASS="admin123"
fi
ok "Password configured"
sep

# ================================================================
#   DETECT SERVER IP
# ================================================================
step "Detecting Public IPv4"
apt-get install -y curl > /dev/null 2>&1 || true
IP=$(curl -4 -s --max-time 5 icanhazip.com 2>/dev/null || true)
[ -z "$IP" ] || echo "$IP" | grep -q '<' && IP=$(curl -4 -s --max-time 5 ipinfo.io/ip 2>/dev/null || true)
[ -z "$IP" ] || echo "$IP" | grep -q '<' && IP=$(hostname -I | awk '{print $1}')
ok "Server IP: ${BC}${IP}${NC}"
sep

# ================================================================
#   INSTALL DEPENDENCIES
# ================================================================
step "Installing System Packages"
echo ""
for i in $(seq 1 10); do progress $i 10 "apt update..."; sleep 0.05; done
apt-get update -y > /dev/null 2>&1

for i in $(seq 1 10); do progress $i 10 "Installing packages..."; sleep 0.05; done
apt-get install -y python3 python3-pip iptables-persistent net-tools lsof curl psmisc > /dev/null 2>&1
ok "System packages installed"

for i in $(seq 1 10); do progress $i 10 "pip install..."; sleep 0.05; done
pip3 install flask flask-login psutil gunicorn > /dev/null 2>&1
ok "Python packages installed (flask, flask-login, psutil, gunicorn)"
sep

# ================================================================
#   KILL EXISTING PROCESS ON PORT
# ================================================================
step "Freeing Port ${PORT}"
kill -9 $(lsof -t -i:"$PORT") 2>/dev/null || true
ok "Port ${PORT} is free"
sep

# ================================================================
#   CREATE DIRECTORY STRUCTURE
# ================================================================
step "Creating Application Directory"
mkdir -p /opt/traffic_panel/templates
mkdir -p /opt/traffic_panel/static
cd /opt/traffic_panel
ok "Created /opt/traffic_panel/"
sep

# ================================================================
#   WRITE app.py  (exact copy of current source)
# ================================================================
step "Writing Flask Application (app.py)"
for i in $(seq 1 20); do progress $i 20 "Generating app.py..."; sleep 0.02; done

cat > /opt/traffic_panel/app.py <<'GUARD_PYEOF'
import os
import json
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, stream_with_context
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import sqlite3
import subprocess
from datetime import datetime, timedelta
import re
import psutil

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_change_me')

ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin123')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DB_PATH = os.path.join(os.path.dirname(__file__), 'traffic.db')

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

conn = get_db()
conn.execute('CREATE TABLE IF NOT EXISTS users (uid INTEGER PRIMARY KEY, username TEXT, limit_bytes INTEGER DEFAULT 0, expiration_date TEXT, active INTEGER DEFAULT 1, connection_limit INTEGER DEFAULT 1)')
conn.execute('CREATE TABLE IF NOT EXISTS usage (date TEXT, uid INTEGER, bytes_out INTEGER, PRIMARY KEY (date, uid))')
try:
    conn.execute('ALTER TABLE usage ADD COLUMN bytes_in INTEGER')
except sqlite3.OperationalError:
    pass
try:
    conn.execute('ALTER TABLE users ADD COLUMN limit_bytes INTEGER DEFAULT 0')
except sqlite3.OperationalError:
    pass
try:
    conn.execute('ALTER TABLE users ADD COLUMN expiration_date TEXT')
except sqlite3.OperationalError:
    pass
try:
    conn.execute('ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1')
except sqlite3.OperationalError:
    pass
try:
    conn.execute('ALTER TABLE users ADD COLUMN connection_limit INTEGER DEFAULT 1')
except sqlite3.OperationalError:
    pass
conn.commit()
conn.close()

def update_users():
    try:
        conn = get_db()
        output = subprocess.check_output("getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $3\" \"$1}'", shell=True).decode().strip()
        users = output.split('\n') if output else []
        for line in users:
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    uid, username = parts[0], parts[1]
                    uid = int(uid)
                    conn.execute('INSERT OR IGNORE INTO users (uid, username) VALUES (?, ?)', (uid, username))
        conn.commit()
        conn.close()
    except Exception:
        pass

def ensure_chains():
    try:
        conn = get_db()
        cursor = conn.execute('SELECT uid FROM users')
        for row in cursor:
            uid = row['uid']
            out_chain = f"USER_OUT_{uid}"
            in_chain = f"USER_IN_{uid}"
            try:
                subprocess.check_output(f"iptables -n -L {out_chain} 2>/dev/null", shell=True)
            except subprocess.CalledProcessError:
                subprocess.call(f"iptables -N {out_chain}", shell=True)
                subprocess.call(f"iptables -A {out_chain} -j RETURN", shell=True)
                subprocess.call(f"iptables -A OUTPUT -m owner --uid-owner {uid} -j {out_chain}", shell=True)
            try:
                subprocess.check_output(f"iptables -n -L {in_chain} 2>/dev/null", shell=True)
            except subprocess.CalledProcessError:
                subprocess.call(f"iptables -N {in_chain}", shell=True)
                subprocess.call(f"iptables -A {in_chain} -j RETURN", shell=True)
                subprocess.call(f"iptables -A INPUT -m owner --uid-owner {uid} -j {in_chain}", shell=True)
        conn.close()
    except Exception:
        pass

update_users()
ensure_chains()

def get_online_users():
    try:
        output = subprocess.check_output("ps -eo user | tail -n +2 | sort | uniq", shell=True).decode().strip()
        return output.split('\n') if output else []
    except Exception:
        return []

def get_current_traffic():
    traffic = {}
    try:
        conn = get_db()
        cursor = conn.execute('SELECT uid FROM users')
        for row in cursor:
            uid = row['uid']
            out_chain = f"USER_OUT_{uid}"
            in_chain = f"USER_IN_{uid}"
            bytes_out = 0
            bytes_in = 0
            try:
                output = subprocess.check_output(f"iptables -L {out_chain} -v -n -x 2>/dev/null", shell=True).decode()
                lines = output.split('\n')
                if len(lines) > 2 and lines[2].strip():
                    bytes_out = int(lines[2].split()[1])
            except Exception:
                pass
            try:
                output = subprocess.check_output(f"iptables -L {in_chain} -v -n -x 2>/dev/null", shell=True).decode()
                lines = output.split('\n')
                if len(lines) > 2 and lines[2].strip():
                    bytes_in = int(lines[2].split()[1])
            except Exception:
                pass
            traffic[uid] = {'out': bytes_out, 'in': bytes_in}
        conn.close()
    except Exception:
        pass
    return traffic

def get_historical(uid, days, direction='total'):
    conn = get_db()
    date_limit = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    if direction == 'out':
        cursor = conn.execute('SELECT SUM(bytes_out) FROM usage WHERE uid = ? AND date >= ?', (uid, date_limit))
    elif direction == 'in':
        cursor = conn.execute('SELECT SUM(COALESCE(bytes_in, 0)) FROM usage WHERE uid = ? AND date >= ?', (uid, date_limit))
    else:
        cursor = conn.execute('SELECT SUM(bytes_out + COALESCE(bytes_in, 0)) FROM usage WHERE uid = ? AND date >= ?', (uid, date_limit))
    total = cursor.fetchone()[0] or 0
    conn.close()
    return total

def get_total_bytes(uid):
    conn = get_db()
    cursor = conn.execute('SELECT SUM(bytes_out + COALESCE(bytes_in, 0)) FROM usage WHERE uid = ?', (uid,))
    total = cursor.fetchone()[0] or 0
    conn.close()
    return total

def get_chart_data(uid):
    conn = get_db()
    date_limit = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    cursor = conn.execute('SELECT date, (bytes_out + COALESCE(bytes_in, 0)) AS total FROM usage WHERE uid = ? AND date >= ? ORDER BY date', (uid, date_limit))
    data = cursor.fetchall()
    labels = [row['date'] for row in data]
    values = [row['total'] for row in data]
    conn.close()
    return labels, values

def format_bytes(bytes_val):
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 ** 2:
        return f"{round(bytes_val / 1024, 2)} KB"
    elif bytes_val < 1024 ** 3:
        return f"{round(bytes_val / (1024 ** 2), 2)} MB"
    else:
        return f"{round(bytes_val / (1024 ** 3), 2)} GB"

def days_remaining(expiration_date):
    if not expiration_date:
        return None
    try:
        exp = datetime.strptime(expiration_date, '%Y-%m-%d')
        delta = (exp - datetime.now()).days
        return delta
    except Exception:
        return None

def check_user_limits():
    try:
        conn = get_db()
        cursor = conn.execute('SELECT uid, username, limit_bytes, expiration_date, active FROM users')
        for row in cursor:
            uid = row['uid']
            username = row['username']
            limit_bytes = row['limit_bytes']
            expiration_date = row['expiration_date']
            active = row['active']
            if active == 0:
                continue
            total_traffic = get_total_bytes(uid)
            if limit_bytes > 0 and total_traffic >= limit_bytes:
                deactivate_user(username)
                conn.execute('UPDATE users SET active = 0 WHERE uid = ?', (uid,))
            if expiration_date:
                exp_date = datetime.strptime(expiration_date, '%Y-%m-%d')
                if datetime.now() > exp_date:
                    deactivate_user(username)
                    conn.execute('UPDATE users SET active = 0 WHERE uid = ?', (uid,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def deactivate_user(username):
    try:
        subprocess.call(f"usermod -L {username}", shell=True)
        subprocess.call(f"pkill -u {username}", shell=True)
    except Exception:
        pass

def activate_user(username):
    try:
        subprocess.call(f"usermod -U {username}", shell=True)
    except Exception:
        pass

def build_user_row(user, online_users, current_traffic):
    uid = user['uid']
    username = user['username']
    active = user['active']
    limit_bytes = user['limit_bytes'] or 0
    expiration_date = user['expiration_date']

    online = username in online_users and active == 1
    curr = current_traffic.get(uid, {'out': 0, 'in': 0})
    total_used = get_total_bytes(uid)
    week_bytes = get_historical(uid, 7)
    month_bytes = get_historical(uid, 30)
    labels, values = get_chart_data(uid)

    usage_pct = 0
    if limit_bytes > 0:
        usage_pct = min(100, round(total_used / limit_bytes * 100, 1))

    dr = days_remaining(expiration_date)

    return {
        'uid': uid,
        'username': username,
        'active': active,
        'online': online,
        'current': format_bytes(curr['out'] + curr['in']),
        'current_bytes': curr['out'] + curr['in'],
        'week': format_bytes(week_bytes),
        'month': format_bytes(month_bytes),
        'total': format_bytes(total_used),
        'total_bytes': total_used,
        'limit_bytes': limit_bytes,
        'limit': format_bytes(limit_bytes) if limit_bytes > 0 else 'نامحدود',
        'usage_pct': usage_pct,
        'expiration_date': expiration_date,
        'days_remaining': dr,
        'labels': labels,
        'values': values,
    }

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USER and password == ADMIN_PASS:
            user = User(1)
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('نام کاربری یا رمز عبور اشتباه است.')
    return render_template('login.html')

@app.route('/toggle_theme')
@login_required
def toggle_theme():
    session['theme'] = 'light' if session.get('theme') == 'dark' else 'dark'
    return redirect(url_for('dashboard'))

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        limit_mb = int(request.form.get('limit_mb', 0)) * 1024 * 1024
        expiration_days = int(request.form.get('expiration_days', 0))
        connection_limit = 1
        expiration_date = None
        if expiration_days > 0:
            expiration_date = (datetime.now() + timedelta(days=expiration_days)).strftime('%Y-%m-%d')
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('نام کاربری نامعتبر است. فقط حروف، اعداد و زیرخط مجاز است.')
            return render_template('add_user.html')
        try:
            subprocess.check_call(f"useradd -M -s /bin/false {username}", shell=True)
            subprocess.check_call(f"echo '{username}:{password}' | chpasswd", shell=True)
            conn = get_db()
            uid = int(subprocess.check_output(f"id -u {username}", shell=True).decode().strip())
            conn.execute('INSERT INTO users (uid, username, limit_bytes, expiration_date, connection_limit) VALUES (?, ?, ?, ?, ?)', (uid, username, limit_mb, expiration_date, connection_limit))
            conn.commit()
            conn.execute('DELETE FROM usage WHERE uid = ?', (uid,))
            conn.commit()
            conn.close()
            out_chain = f"USER_OUT_{uid}"
            in_chain = f"USER_IN_{uid}"
            subprocess.call(f"iptables -F {out_chain} 2>/dev/null", shell=True)
            subprocess.call(f"iptables -Z {out_chain} 2>/dev/null", shell=True)
            subprocess.call(f"iptables -F {in_chain} 2>/dev/null", shell=True)
            subprocess.call(f"iptables -Z {in_chain} 2>/dev/null", shell=True)
            flash('یوزر جدید با موفقیت اضافه شد.')
            update_users()
            ensure_chains()
        except Exception:
            flash('خطا در اضافه کردن یوزر.')
        return redirect(url_for('dashboard'))
    return render_template('add_user.html')

@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
def edit_user(username):
    conn = get_db()
    cursor = conn.execute('SELECT limit_bytes, expiration_date, connection_limit FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        current_limit_mb = row['limit_bytes'] // (1024 * 1024) if row['limit_bytes'] else 0
        current_expiration = row['expiration_date']
        current_connection_limit = row['connection_limit']
    else:
        current_limit_mb = 0
        current_expiration = None
        current_connection_limit = 1
    if request.method == 'POST':
        limit_mb = int(request.form.get('limit_mb', 0)) * 1024 * 1024
        expiration_days = int(request.form.get('expiration_days', 0))
        connection_limit = int(request.form.get('connection_limit', 1))
        expiration_date = None
        if expiration_days > 0:
            expiration_date = (datetime.now() + timedelta(days=expiration_days)).strftime('%Y-%m-%d')
        conn = get_db()
        conn.execute('UPDATE users SET limit_bytes = ?, expiration_date = ?, connection_limit = ? WHERE username = ?', (limit_mb, expiration_date, connection_limit, username))
        conn.commit()
        conn.close()
        flash('یوزر با موفقیت ویرایش شد.')
        return redirect(url_for('dashboard'))
    return render_template('edit_user.html', username=username, current_limit_mb=current_limit_mb, current_expiration=current_expiration, current_connection_limit=current_connection_limit)

@app.route('/delete_user/<username>', methods=['GET'])
@login_required
def delete_user(username):
    try:
        subprocess.check_call(f"userdel {username}", shell=True)
        conn = get_db()
        conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.execute('DELETE FROM usage WHERE uid = (SELECT uid FROM users WHERE username = ?)', (username,))
        conn.commit()
        conn.close()
        flash('یوزر با موفقیت حذف شد.')
    except Exception:
        flash('خطا در حذف یوزر.')
    return redirect(url_for('dashboard'))

@app.route('/toggle_active/<username>', methods=['GET'])
@login_required
def toggle_active(username):
    conn = get_db()
    cursor = conn.execute('SELECT active FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    if row:
        active = row['active']
        new_active = 1 if active == 0 else 0
        conn.execute('UPDATE users SET active = ? WHERE username = ?', (new_active, username))
        conn.commit()
        if new_active == 1:
            activate_user(username)
        else:
            deactivate_user(username)
        flash('وضعیت یوزر تغییر کرد.')
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/reset_traffic/<username>', methods=['GET'])
@login_required
def reset_traffic(username):
    try:
        conn = get_db()
        cursor = conn.execute('SELECT uid FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            uid = row['uid']
            conn.execute('DELETE FROM usage WHERE uid = ?', (uid,))
            conn.commit()
            out_chain = f"USER_OUT_{uid}"
            in_chain = f"USER_IN_{uid}"
            subprocess.call(f"iptables -Z {out_chain} 2>/dev/null", shell=True)
            subprocess.call(f"iptables -Z {in_chain} 2>/dev/null", shell=True)
            flash(f'ترافیک کاربر {username} با موفقیت ریست شد.')
        conn.close()
    except Exception:
        flash('خطا در ریست ترافیک.')
    return redirect(url_for('dashboard'))

def get_system_stats():
    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    conn = get_db()
    cursor = conn.execute('SELECT SUM(bytes_out + COALESCE(bytes_in, 0)) FROM usage')
    total_traffic_bytes = cursor.fetchone()[0] or 0
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] or 0
    active_users = conn.execute('SELECT COUNT(*) FROM users WHERE active=1').fetchone()[0] or 0
    conn.close()
    traffic_limit = 100 * 1024 * 1024 * 1024
    traffic = (total_traffic_bytes / traffic_limit) * 100 if traffic_limit > 0 else 0
    return {
        'cpu': round(cpu, 1),
        'memory': round(memory, 1),
        'disk': round(disk, 1),
        'traffic': round(min(traffic, 100), 1),
        'total_users': total_users,
        'active_users': active_users,
    }

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_system_stats())

@app.route('/api/users')
@login_required
def api_users():
    check_user_limits()
    update_users()
    conn = get_db()
    cursor = conn.execute('SELECT uid, username, active, limit_bytes, expiration_date FROM users')
    users = cursor.fetchall()
    conn.close()
    online_users = get_online_users()
    current_traffic = get_current_traffic()
    search_query = request.args.get('search', '')
    result = []
    for user in users:
        if search_query and search_query.lower() not in user['username'].lower():
            continue
        row = build_user_row(user, online_users, current_traffic)
        result.append({
            'uid': row['uid'],
            'username': row['username'],
            'active': row['active'],
            'online': row['online'],
            'current': row['current'],
            'week': row['week'],
            'month': row['month'],
            'total': row['total'],
            'limit': row['limit'],
            'usage_pct': row['usage_pct'],
            'expiration_date': row['expiration_date'],
            'days_remaining': row['days_remaining'],
        })
    return jsonify(result)

@app.route('/system_stats')
@login_required
def system_stats():
    return jsonify(get_system_stats())

@app.route('/api/stream')
@login_required
def api_stream():
    def generate():
        while True:
            try:
                data = get_system_stats()
                yield f"data: {json.dumps(data)}\n\n"
                time.sleep(0.5)
            except GeneratorExit:
                break
            except Exception:
                time.sleep(1)
    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/dashboard')
@login_required
def dashboard():
    check_user_limits()
    update_users()
    ensure_chains()
    conn = get_db()
    cursor = conn.execute('SELECT uid, username, active, limit_bytes, expiration_date FROM users')
    users = cursor.fetchall()
    conn.close()
    online_users = get_online_users()
    current_traffic = get_current_traffic()
    search_query = request.args.get('search', '')
    filtered_data = []
    for user in users:
        if search_query and search_query.lower() not in user['username'].lower():
            continue
        filtered_data.append(build_user_row(user, online_users, current_traffic))
    stats = get_system_stats()
    return render_template('dashboard.html', data=filtered_data, stats=stats, search_query=search_query)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 6565))
    app.run(host='0.0.0.0', port=port, debug=False)
GUARD_PYEOF

ok "app.py written"
sep

# ================================================================
#   WRITE TEMPLATES  (exact copies of current design)
# ================================================================
step "Writing HTML Templates"

# ── login.html ──────────────────────────────────────────────────
for i in $(seq 1 5); do progress $i 5 "login.html..."; sleep 0.03; done
cat > /opt/traffic_panel/templates/login.html <<'GUARD_LOGINHTML'
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>GUARD VPN — ورود</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --purple-deep: #0d0018;
            --purple-dark: #130026;
            --purple-mid: #1e0040;
            --purple-accent: #7c3aed;
            --purple-light: #a855f7;
            --purple-glow: #c084fc;
            --pink-accent: #ec4899;
            --text-primary: #f3e8ff;
            --text-secondary: #c4b5fd;
            --border-glow: rgba(124, 58, 237, 0.4);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Vazir', sans-serif;
            background: var(--purple-deep);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }

        /* Animated background blobs */
        .bg-blob {
            position: fixed;
            border-radius: 50%;
            filter: blur(80px);
            opacity: 0.25;
            animation: floatBlob 8s ease-in-out infinite;
            pointer-events: none;
        }
        .blob-1 {
            width: 400px; height: 400px;
            background: #7c3aed;
            top: -100px; right: -100px;
            animation-delay: 0s;
        }
        .blob-2 {
            width: 350px; height: 350px;
            background: #a855f7;
            bottom: -80px; left: -80px;
            animation-delay: 3s;
        }
        .blob-3 {
            width: 200px; height: 200px;
            background: #ec4899;
            top: 50%; left: 50%;
            animation-delay: 5s;
        }
        @keyframes floatBlob {
            0%, 100% { transform: translate(0, 0) scale(1); }
            33% { transform: translate(20px, -20px) scale(1.05); }
            66% { transform: translate(-15px, 15px) scale(0.95); }
        }

        /* Grid lines background */
        .bg-grid {
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(124,58,237,0.06) 1px, transparent 1px),
                linear-gradient(90deg, rgba(124,58,237,0.06) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
        }

        .login-wrapper {
            position: relative;
            z-index: 10;
            width: 100%;
            max-width: 420px;
            padding: 16px;
        }

        /* Logo / brand */
        .brand-area {
            text-align: center;
            margin-bottom: 32px;
        }
        .brand-icon {
            width: 72px; height: 72px;
            background: linear-gradient(135deg, #7c3aed, #ec4899);
            border-radius: 20px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            color: #fff;
            margin-bottom: 14px;
            box-shadow: 0 0 30px rgba(124,58,237,0.5), 0 0 60px rgba(124,58,237,0.2);
            animation: pulseIcon 3s ease-in-out infinite;
        }
        @keyframes pulseIcon {
            0%, 100% { box-shadow: 0 0 30px rgba(124,58,237,0.5), 0 0 60px rgba(124,58,237,0.2); }
            50% { box-shadow: 0 0 50px rgba(168,85,247,0.7), 0 0 80px rgba(168,85,247,0.3); }
        }
        .brand-title {
            font-size: 26px;
            font-weight: 900;
            background: linear-gradient(135deg, #c084fc, #f0abfc, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: 2px;
        }
        .brand-subtitle {
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 4px;
            letter-spacing: 1px;
        }

        /* Card */
        .login-card {
            background: rgba(19, 0, 38, 0.85);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(124, 58, 237, 0.3);
            border-radius: 24px;
            padding: 36px 32px;
            box-shadow:
                0 0 0 1px rgba(124,58,237,0.1),
                0 20px 60px rgba(0,0,0,0.6),
                inset 0 1px 0 rgba(255,255,255,0.05);
        }

        /* Alert */
        .alert-custom {
            background: rgba(236, 72, 153, 0.15);
            border: 1px solid rgba(236, 72, 153, 0.3);
            border-radius: 12px;
            color: #f9a8d4;
            padding: 12px 16px;
            font-size: 13px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Form fields */
        .form-group { margin-bottom: 20px; }
        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }
        .input-wrapper {
            position: relative;
        }
        .input-icon {
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--purple-accent);
            font-size: 15px;
            pointer-events: none;
        }
        .form-input {
            width: 100%;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(124,58,237,0.25);
            border-radius: 12px;
            padding: 13px 42px 13px 16px;
            color: var(--text-primary);
            font-family: 'Vazir', sans-serif;
            font-size: 15px;
            transition: all 0.3s ease;
            outline: none;
        }
        .form-input::placeholder { color: rgba(196,181,253,0.4); }
        .form-input:focus {
            border-color: var(--purple-accent);
            background: rgba(124,58,237,0.08);
            box-shadow: 0 0 0 3px rgba(124,58,237,0.15), 0 0 20px rgba(124,58,237,0.1);
        }

        /* Submit button */
        .btn-login {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 12px;
            font-family: 'Vazir', sans-serif;
            font-size: 16px;
            font-weight: 700;
            color: #fff;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            background: linear-gradient(135deg, #7c3aed, #a855f7);
            box-shadow: 0 4px 20px rgba(124,58,237,0.4);
            transition: all 0.3s ease;
            letter-spacing: 0.5px;
            margin-top: 8px;
        }
        .btn-login::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, #a855f7, #ec4899);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        .btn-login:hover::before { opacity: 1; }
        .btn-login:hover {
            transform: translateY(-1px);
            box-shadow: 0 8px 30px rgba(124,58,237,0.6);
        }
        .btn-login:active { transform: translateY(0); }
        .btn-login span { position: relative; z-index: 1; }

        /* Version tag */
        .version-tag {
            text-align: center;
            margin-top: 22px;
            font-size: 12px;
            color: rgba(196,181,253,0.4);
            letter-spacing: 1px;
        }

        @media (max-width: 480px) {
            .login-card { padding: 28px 20px; border-radius: 20px; }
            .brand-icon { width: 60px; height: 60px; font-size: 26px; }
            .brand-title { font-size: 22px; }
        }
    </style>
</head>
<body>
    <div class="bg-blob blob-1"></div>
    <div class="bg-blob blob-2"></div>
    <div class="bg-blob blob-3"></div>
    <div class="bg-grid"></div>

    <div class="login-wrapper">
        <div class="brand-area">
            <div class="brand-icon">
                <i class="fas fa-shield-halved"></i>
            </div>
            <div class="brand-title">GUARD VPN</div>

        </div>

        <div class="login-card">
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert-custom">
                    <i class="fas fa-circle-exclamation"></i>
                    {{ messages[0] }}
                </div>
              {% endif %}
            {% endwith %}

            <form method="POST">
                <div class="form-group">
                    <label class="form-label" for="username">نام کاربری</label>
                    <div class="input-wrapper">
                        <i class="fas fa-user input-icon"></i>
                        <input type="text" class="form-input" id="username" name="username" placeholder="نام کاربری ادمین" required autocomplete="username">
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label" for="password">رمز عبور</label>
                    <div class="input-wrapper">
                        <i class="fas fa-lock input-icon"></i>
                        <input type="password" class="form-input" id="password" name="password" placeholder="••••••••" required autocomplete="current-password">
                    </div>
                </div>
                <button type="submit" class="btn-login">
                    <span><i class="fas fa-right-to-bracket" style="margin-left: 8px;"></i>ورود به پنل</span>
                </button>
            </form>
        </div>

        <div class="version-tag">GUARDNET VPN v1.1 &nbsp;•&nbsp; LOCALVPS</div>
    </div>
</body>
</html>
GUARD_LOGINHTML

ok "login.html written"

# ── add_user.html ────────────────────────────────────────────────
for i in $(seq 1 5); do progress $i 5 "add_user.html..."; sleep 0.03; done
cat > /opt/traffic_panel/templates/add_user.html <<'GUARD_ADDUSERHTML'
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>GUARD VPN — کاربر جدید</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --purple-accent: #7c3aed;
            --purple-light: #a855f7;
            --purple-glow: #c084fc;
            --text-primary: #f3e8ff;
            --text-secondary: #c4b5fd;
            --text-muted: rgba(196,181,253,0.5);
            --border: rgba(124,58,237,0.25);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Vazir', sans-serif;
            background: #0a0015;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px 16px;
            position: relative;
            overflow-x: hidden;
        }
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(124,58,237,0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(124,58,237,0.04) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
        }
        .blob { position: fixed; border-radius: 50%; filter: blur(80px); opacity: 0.2; pointer-events: none; }
        .blob-1 { width: 400px; height: 400px; background: #7c3aed; top: -150px; right: -150px; }
        .blob-2 { width: 300px; height: 300px; background: #ec4899; bottom: -100px; left: -100px; }

        .page-wrap {
            position: relative; z-index: 1;
            width: 100%; max-width: 460px;
        }
        .back-link {
            display: inline-flex; align-items: center; gap: 8px;
            color: var(--text-muted); font-size: 13px; text-decoration: none;
            margin-bottom: 20px; transition: color 0.2s;
        }
        .back-link:hover { color: var(--purple-glow); }

        .page-card {
            background: rgba(19, 0, 38, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 36px 32px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.04);
        }
        .page-header {
            display: flex; align-items: center; gap: 12px;
            margin-bottom: 28px;
        }
        .page-header-icon {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, #7c3aed, #a855f7);
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 18px; color: #fff;
            box-shadow: 0 0 20px rgba(124,58,237,0.4);
            flex-shrink: 0;
        }
        .page-header-title { font-size: 20px; font-weight: 800; color: var(--text-primary); }
        .page-header-sub { font-size: 12px; color: var(--text-muted); margin-top: 2px; }

        .alert-msg {
            background: rgba(236,72,153,0.12);
            border: 1px solid rgba(236,72,153,0.25);
            border-radius: 12px;
            padding: 12px 16px;
            color: #f9a8d4;
            font-size: 13px;
            margin-bottom: 20px;
            display: flex; align-items: center; gap: 8px;
        }
        .form-group { margin-bottom: 18px; }
        .form-label {
            display: block; font-size: 12px; font-weight: 700;
            color: var(--text-secondary); margin-bottom: 8px;
            letter-spacing: 0.5px; text-transform: uppercase;
        }
        .input-wrap { position: relative; }
        .input-icon {
            position: absolute; right: 13px; top: 50%;
            transform: translateY(-50%);
            color: var(--purple-accent); font-size: 14px; pointer-events: none;
        }
        .form-input {
            width: 100%;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px 40px 12px 14px;
            color: var(--text-primary);
            font-family: 'Vazir', sans-serif;
            font-size: 14px;
            outline: none;
            transition: all 0.3s;
        }
        .form-input::placeholder { color: var(--text-muted); }
        .form-input:focus {
            border-color: var(--purple-accent);
            background: rgba(124,58,237,0.07);
            box-shadow: 0 0 0 3px rgba(124,58,237,0.14);
        }
        .hint { font-size: 11px; color: var(--text-muted); margin-top: 5px; }
        .divider { border: none; border-top: 1px solid var(--border); margin: 22px 0; }
        .btn-submit {
            width: 100%; padding: 14px; border: none; border-radius: 12px;
            font-family: 'Vazir', sans-serif; font-size: 15px; font-weight: 700;
            color: #fff; cursor: pointer;
            background: linear-gradient(135deg, #7c3aed, #a855f7);
            box-shadow: 0 4px 20px rgba(124,58,237,0.4);
            transition: all 0.3s; letter-spacing: 0.5px; margin-top: 4px;
        }
        .btn-submit:hover {
            background: linear-gradient(135deg, #6d28d9, #9333ea);
            transform: translateY(-1px);
            box-shadow: 0 8px 30px rgba(124,58,237,0.55);
        }

        @media (max-width: 480px) {
            .page-card { padding: 24px 18px; border-radius: 18px; }
            .page-header-title { font-size: 17px; }
        }
    </style>
</head>
<body>
    <div class="blob blob-1"></div>
    <div class="blob blob-2"></div>
    <div class="page-wrap">
        <a href="{{ url_for('dashboard') }}" class="back-link">
            <i class="fas fa-arrow-right"></i> بازگشت به داشبورد
        </a>
        <div class="page-card">
            <div class="page-header">
                <div class="page-header-icon"><i class="fas fa-user-plus"></i></div>
                <div>
                    <div class="page-header-title">کاربر جدید</div>
                    <div class="page-header-sub">اضافه کردن کاربر VPN</div>
                </div>
            </div>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert-msg"><i class="fas fa-circle-exclamation"></i> {{ messages[0] }}</div>
              {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="form-group">
                    <label class="form-label">نام کاربری</label>
                    <div class="input-wrap">
                        <i class="fas fa-user input-icon"></i>
                        <input type="text" class="form-input" name="username" placeholder="username" required autocomplete="off">
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">رمز عبور</label>
                    <div class="input-wrap">
                        <i class="fas fa-key input-icon"></i>
                        <input type="password" class="form-input" name="password" placeholder="••••••••" required>
                    </div>
                </div>
                <hr class="divider">
                <div class="form-group">
                    <label class="form-label">محدودیت ترافیک (مگابایت)</label>
                    <div class="input-wrap">
                        <i class="fas fa-gauge-high input-icon"></i>
                        <input type="number" class="form-input" name="limit_mb" value="0" min="0" required>
                    </div>
                    <div class="hint">عدد ۰ یعنی بدون محدودیت</div>
                </div>
                <div class="form-group">
                    <label class="form-label">مدت انقضا (روز)</label>
                    <div class="input-wrap">
                        <i class="fas fa-calendar-days input-icon"></i>
                        <input type="number" class="form-input" name="expiration_days" value="0" min="0" required>
                    </div>
                    <div class="hint">عدد ۰ یعنی بدون انقضا</div>
                </div>
                <button type="submit" class="btn-submit">
                    <i class="fas fa-plus" style="margin-left:8px;"></i>ایجاد کاربر
                </button>
            </form>
        </div>
    </div>
</body>
</html>
GUARD_ADDUSERHTML

ok "add_user.html written"

# ── edit_user.html ───────────────────────────────────────────────
for i in $(seq 1 5); do progress $i 5 "edit_user.html..."; sleep 0.03; done
cat > /opt/traffic_panel/templates/edit_user.html <<'GUARD_EDITUSERHTML'
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>GUARD VPN — ویرایش کاربر</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --purple-accent: #7c3aed;
            --purple-light: #a855f7;
            --purple-glow: #c084fc;
            --text-primary: #f3e8ff;
            --text-secondary: #c4b5fd;
            --text-muted: rgba(196,181,253,0.5);
            --border: rgba(124,58,237,0.25);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Vazir', sans-serif;
            background: #0a0015;
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
            padding: 24px 16px; position: relative; overflow-x: hidden;
        }
        body::before {
            content: '';
            position: fixed; inset: 0;
            background-image:
                linear-gradient(rgba(124,58,237,0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(124,58,237,0.04) 1px, transparent 1px);
            background-size: 50px 50px; pointer-events: none;
        }
        .blob { position: fixed; border-radius: 50%; filter: blur(80px); opacity: 0.2; pointer-events: none; }
        .blob-1 { width: 400px; height: 400px; background: #7c3aed; top: -150px; left: -150px; }
        .blob-2 { width: 300px; height: 300px; background: #ec4899; bottom: -100px; right: -100px; }

        .page-wrap { position: relative; z-index: 1; width: 100%; max-width: 460px; }
        .back-link {
            display: inline-flex; align-items: center; gap: 8px;
            color: var(--text-muted); font-size: 13px; text-decoration: none;
            margin-bottom: 20px; transition: color 0.2s;
        }
        .back-link:hover { color: var(--purple-glow); }

        .page-card {
            background: rgba(19, 0, 38, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 36px 32px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.04);
        }
        .page-header { display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }
        .page-header-icon {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, #3b82f6, #6366f1);
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 18px; color: #fff;
            box-shadow: 0 0 20px rgba(59,130,246,0.4);
            flex-shrink: 0;
        }
        .page-header-title { font-size: 20px; font-weight: 800; color: var(--text-primary); }
        .page-header-sub { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
        .username-highlight {
            color: var(--purple-glow); font-family: monospace;
            background: rgba(124,58,237,0.1); padding: 2px 8px; border-radius: 6px;
            font-size: 13px;
        }

        .form-group { margin-bottom: 18px; }
        .form-label {
            display: block; font-size: 12px; font-weight: 700;
            color: var(--text-secondary); margin-bottom: 8px;
            letter-spacing: 0.5px; text-transform: uppercase;
        }
        .input-wrap { position: relative; }
        .input-icon {
            position: absolute; right: 13px; top: 50%;
            transform: translateY(-50%);
            color: var(--purple-accent); font-size: 14px; pointer-events: none;
        }
        .form-input {
            width: 100%;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px 40px 12px 14px;
            color: var(--text-primary);
            font-family: 'Vazir', sans-serif;
            font-size: 14px; outline: none; transition: all 0.3s;
        }
        .form-input::placeholder { color: var(--text-muted); }
        .form-input:focus {
            border-color: var(--purple-accent);
            background: rgba(124,58,237,0.07);
            box-shadow: 0 0 0 3px rgba(124,58,237,0.14);
        }
        .hint { font-size: 11px; color: var(--text-muted); margin-top: 5px; }
        .divider { border: none; border-top: 1px solid var(--border); margin: 22px 0; }
        .btn-submit {
            width: 100%; padding: 14px; border: none; border-radius: 12px;
            font-family: 'Vazir', sans-serif; font-size: 15px; font-weight: 700;
            color: #fff; cursor: pointer;
            background: linear-gradient(135deg, #3b82f6, #6366f1);
            box-shadow: 0 4px 20px rgba(59,130,246,0.35);
            transition: all 0.3s; margin-top: 4px;
        }
        .btn-submit:hover {
            background: linear-gradient(135deg, #2563eb, #4f46e5);
            transform: translateY(-1px);
            box-shadow: 0 8px 30px rgba(59,130,246,0.5);
        }

        @media (max-width: 480px) {
            .page-card { padding: 24px 18px; border-radius: 18px; }
            .page-header-title { font-size: 17px; }
        }
    </style>
</head>
<body>
    <div class="blob blob-1"></div>
    <div class="blob blob-2"></div>
    <div class="page-wrap">
        <a href="{{ url_for('dashboard') }}" class="back-link">
            <i class="fas fa-arrow-right"></i> بازگشت به داشبورد
        </a>
        <div class="page-card">
            <div class="page-header">
                <div class="page-header-icon"><i class="fas fa-pen-to-square"></i></div>
                <div>
                    <div class="page-header-title">ویرایش کاربر</div>
                    <div class="page-header-sub"><span class="username-highlight">{{ username }}</span></div>
                </div>
            </div>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div style="background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.25);border-radius:12px;padding:12px 16px;color:#6ee7b7;font-size:13px;margin-bottom:20px;display:flex;align-items:center;gap:8px;">
                    <i class="fas fa-circle-check"></i> {{ messages[0] }}
                </div>
              {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="form-group">
                    <label class="form-label">محدودیت ترافیک (مگابایت)</label>
                    <div class="input-wrap">
                        <i class="fas fa-gauge-high input-icon"></i>
                        <input type="number" class="form-input" name="limit_mb" value="{{ current_limit_mb }}" min="0" required>
                    </div>
                    <div class="hint">عدد ۰ یعنی بدون محدودیت</div>
                </div>
                <div class="form-group">
                    <label class="form-label">مدت انقضا جدید (روز از امروز)</label>
                    <div class="input-wrap">
                        <i class="fas fa-calendar-days input-icon"></i>
                        <input type="number" class="form-input" name="expiration_days" value="0" min="0" required>
                    </div>
                    <div class="hint">عدد ۰ یعنی بدون تغییر / بدون انقضا</div>
                </div>
                <div class="form-group">
                    <label class="form-label">محدودیت اتصال همزمان</label>
                    <div class="input-wrap">
                        <i class="fas fa-network-wired input-icon"></i>
                        <input type="number" class="form-input" name="connection_limit" value="{{ current_connection_limit }}" min="1" required>
                    </div>
                </div>
                <button type="submit" class="btn-submit">
                    <i class="fas fa-floppy-disk" style="margin-left:8px;"></i>ذخیره تغییرات
                </button>
            </form>
        </div>
    </div>
</body>
</html>
GUARD_EDITUSERHTML

ok "edit_user.html written"

# ── dashboard.html ───────────────────────────────────────────────
for i in $(seq 1 10); do progress $i 10 "dashboard.html..."; sleep 0.03; done
cat > /opt/traffic_panel/templates/dashboard.html <<'GUARD_DASHHTML'
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>GUARD VPN — داشبورد</title>
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg:       #080013;
            --bg2:      #0f001f;
            --card:     rgba(18, 0, 38, 0.88);
            --card2:    rgba(26, 4, 52, 0.9);
            --p:        #7c3aed;
            --p2:       #a855f7;
            --p3:       #c084fc;
            --pink:     #ec4899;
            --green:    #10b981;
            --red:      #ef4444;
            --yellow:   #f59e0b;
            --blue:     #3b82f6;
            --t1:       #f3e8ff;
            --t2:       #c4b5fd;
            --t3:       rgba(196,181,253,.45);
            --border:   rgba(124,58,237,.18);
            --border2:  rgba(124,58,237,.38);
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Vazir', sans-serif;
            background: var(--bg);
            color: var(--t1);
            min-height: 100vh;
        }
        body::before {
            content: '';
            position: fixed; inset: 0;
            background-image:
                linear-gradient(rgba(124,58,237,.035) 1px, transparent 1px),
                linear-gradient(90deg, rgba(124,58,237,.035) 1px, transparent 1px);
            background-size: 52px 52px;
            pointer-events: none; z-index: 0;
        }

        /* ── NAVBAR ── */
        .navbar {
            position: sticky; top: 0; z-index: 200;
            background: rgba(8,0,19,.96);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            border-bottom: 1px solid var(--border2);
            box-shadow: 0 2px 30px rgba(0,0,0,.5);
        }
        .navbar-row {
            display: flex; align-items: center; justify-content: space-between;
            max-width: 1440px; margin: 0 auto;
            padding: 0 20px; height: 62px; gap: 12px;
        }
        /* brand */
        .brand { display: flex; align-items: center; gap: 10px; text-decoration: none; flex-shrink: 0; }
        .brand-icon {
            width: 38px; height: 38px; border-radius: 11px; flex-shrink: 0;
            background: linear-gradient(135deg, var(--p), var(--pink));
            display: flex; align-items: center; justify-content: center;
            font-size: 17px; color: #fff;
            box-shadow: 0 0 18px rgba(124,58,237,.55);
        }
        .brand-name {
            font-size: 17px; font-weight: 900; letter-spacing: 1.5px;
            background: linear-gradient(135deg, var(--p3), var(--pink));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }
        .brand-ver { font-size: 10px; color: var(--t3); display: block; -webkit-text-fill-color: var(--t3); }

        /* live bar inside navbar */
        .navbar-live {
            display: flex; align-items: center; gap: 16px;
            flex: 1; justify-content: center;
        }
        .live-pill {
            display: flex; align-items: center; gap: 7px;
            background: rgba(255,255,255,.04); border: 1px solid var(--border);
            border-radius: 20px; padding: 5px 13px; font-size: 12px; color: var(--t2);
            white-space: nowrap;
        }
        .live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); animation: blink 1.5s ease-in-out infinite; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }
        .live-pill .val { font-weight: 700; color: var(--t1); font-size: 13px; }

        /* nav buttons */
        .nav-btns { display: flex; align-items: center; gap: 7px; flex-shrink: 0; }
        .nbtn {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 7px 13px; border-radius: 9px; font-size: 12px; font-weight: 700;
            font-family: 'Vazir', sans-serif; text-decoration: none; cursor: pointer;
            border: 1px solid transparent; transition: all .22s; white-space: nowrap;
        }
        .nbtn-green { background: rgba(16,185,129,.13); color: #34d399; border-color: rgba(16,185,129,.28); }
        .nbtn-green:hover { background: rgba(16,185,129,.28); color: #fff; }
        .nbtn-purple { background: rgba(124,58,237,.14); color: var(--p3); border-color: rgba(124,58,237,.28); }
        .nbtn-purple:hover { background: rgba(124,58,237,.3); color: #fff; }
        .nbtn-red { background: rgba(239,68,68,.11); color: #fca5a5; border-color: rgba(239,68,68,.22); }
        .nbtn-red:hover { background: rgba(239,68,68,.25); color: #fff; }

        /* hamburger */
        .ham { display:none; background:transparent; border:1px solid var(--border); color:var(--t2); border-radius:8px; padding:6px 10px; cursor:pointer; font-size:17px; transition:.2s; }
        .ham:hover { background:rgba(124,58,237,.2); }
        .mob-menu { display:none; background:rgba(8,0,19,.98); border-bottom:1px solid var(--border); padding:12px 16px; gap:8px; flex-direction:column; }
        .mob-menu.open { display:flex; }
        .mob-menu .nbtn { justify-content:center; }

        /* ── CONTENT ── */
        .wrap { position:relative; z-index:1; max-width:1440px; margin:0 auto; padding:20px 16px 40px; }

        /* ── STAT CARDS (gauges) ── */
        .gauges { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:22px; }
        .gcard {
            background: var(--card); border:1px solid var(--border); border-radius:18px;
            padding:18px 14px; display:flex; flex-direction:column; align-items:center; gap:10px;
            transition: all .3s; position:relative; overflow:hidden;
        }
        .gcard::after { content:''; position:absolute; top:0;left:0;right:0; height:2px; background:var(--gcolor,var(--p)); opacity:.7; }
        .gcard:hover { border-color:var(--border2); transform:translateY(-2px); box-shadow:0 8px 30px rgba(0,0,0,.35),0 0 20px rgba(124,58,237,.08); }
        .glabel { font-size:11px; font-weight:700; color:var(--t3); letter-spacing:1.2px; text-transform:uppercase; }
        .gring { position:relative; width:86px; height:86px; }
        .gring canvas { width:86px!important; height:86px!important; }
        .gval { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
        .gval-num { font-size:16px; font-weight:900; color:var(--t1); line-height:1; }
        .gval-pct { font-size:9px; color:var(--t3); margin-top:2px; }
        .gicon { font-size:11px; color:var(--t3); }

        /* ── SUMMARY STRIP ── */
        .summary { display:flex; gap:10px; margin-bottom:22px; flex-wrap:wrap; }
        .scard {
            background:var(--card); border:1px solid var(--border); border-radius:14px;
            padding:14px 18px; display:flex; align-items:center; gap:12px; flex:1; min-width:150px;
        }
        .scard-icon { width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0; }
        .scard-body { display:flex; flex-direction:column; }
        .scard-val { font-size:20px; font-weight:900; color:var(--t1); }
        .scard-lab { font-size:11px; color:var(--t3); margin-top:1px; }

        /* ── TOOLBAR ── */
        .toolbar { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:16px; flex-wrap:wrap; }
        .toolbar-left { display:flex; align-items:center; gap:10px; }
        .page-title { font-size:17px; font-weight:800; color:var(--t1); display:flex; align-items:center; gap:8px; }
        .page-title i { color:var(--p2); }
        .user-count { font-size:12px; color:var(--t3); background:rgba(124,58,237,.1); border:1px solid var(--border); border-radius:20px; padding:3px 10px; }
        .rt-badge { display:inline-flex; align-items:center; gap:5px; font-size:11px; color:var(--green); }

        /* search */
        .search-wrap { display:flex; gap:8px; }
        .sinput-wrap { position:relative; }
        .sicon { position:absolute; right:13px; top:50%; transform:translateY(-50%); color:var(--p); font-size:13px; pointer-events:none; }
        .sinput {
            background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:11px;
            padding:9px 38px 9px 14px; color:var(--t1); font-family:'Vazir',sans-serif;
            font-size:13px; outline:none; transition:all .3s; width:200px;
        }
        .sinput::placeholder { color:var(--t3); }
        .sinput:focus { border-color:var(--p); background:rgba(124,58,237,.07); box-shadow:0 0 0 3px rgba(124,58,237,.12); }
        .sbtn {
            background:linear-gradient(135deg,var(--p),var(--p2)); border:none; border-radius:11px;
            padding:9px 16px; color:#fff; font-family:'Vazir',sans-serif; font-size:13px; font-weight:700;
            cursor:pointer; transition:all .25s;
        }
        .sbtn:hover { background:linear-gradient(135deg,#6d28d9,#9333ea); box-shadow:0 4px 16px rgba(124,58,237,.4); }

        /* ── TABLE CARD ── */
        .tcard { background:var(--card); border:1px solid var(--border); border-radius:20px; overflow:hidden; box-shadow:0 10px 40px rgba(0,0,0,.35); }
        .tscroll { overflow-x:auto; -webkit-overflow-scrolling:touch; }
        table { width:100%; border-collapse:collapse; min-width:820px; }
        thead tr { background:rgba(124,58,237,.13); border-bottom:1px solid var(--border2); }
        thead th { padding:13px 12px; font-size:11px; font-weight:700; color:var(--t2); text-align:center; letter-spacing:.9px; text-transform:uppercase; white-space:nowrap; }
        tbody tr { border-bottom:1px solid rgba(124,58,237,.07); transition:background .18s; }
        tbody tr:last-child { border-bottom:none; }
        tbody tr:hover { background:rgba(124,58,237,.07); }
        tbody td { padding:12px 12px; font-size:13px; color:var(--t1); text-align:center; vertical-align:middle; }

        .uname { font-weight:800; color:var(--p3); font-size:14px; display:flex; align-items:center; gap:6px; justify-content:center; }
        .uname i { opacity:.5; font-size:13px; }

        /* badges */
        .badge { display:inline-flex; align-items:center; gap:4px; padding:4px 9px; border-radius:20px; font-size:10px; font-weight:800; letter-spacing:.3px; }
        .badge-on  { background:rgba(16,185,129,.12); color:#34d399; border:1px solid rgba(16,185,129,.28); }
        .badge-off { background:rgba(239,68,68,.1);   color:#f87171;  border:1px solid rgba(239,68,68,.2); }
        .badge-act { background:rgba(16,185,129,.1);  color:#6ee7b7;  border:1px solid rgba(16,185,129,.22); }
        .badge-dis { background:rgba(239,68,68,.09);  color:#fca5a5;  border:1px solid rgba(239,68,68,.2); }
        .badge i   { font-size:7px; }

        /* progress bar for usage */
        .usage-bar-wrap { min-width:90px; }
        .usage-label { font-size:11px; color:var(--t2); margin-bottom:4px; }
        .usage-bar { background:rgba(255,255,255,.06); border-radius:20px; height:5px; overflow:hidden; }
        .usage-fill { height:100%; border-radius:20px; transition:width .5s; background:linear-gradient(90deg,var(--p),var(--p2)); }
        .usage-fill.warn { background:linear-gradient(90deg,var(--yellow),#ef4444); }

        /* expiry */
        .expiry-ok   { color:#6ee7b7; font-weight:700; }
        .expiry-warn { color:#fcd34d; font-weight:700; }
        .expiry-exp  { color:#f87171; font-weight:700; }
        .expiry-none { color:var(--t3); }

        /* traffic values */
        .tval { font-weight:600; }
        .tval-total { color:var(--p3); font-weight:700; }

        /* mini chart */
        .mchart { width:100px; height:44px; margin:0 auto; }

        /* action buttons */
        .acts { display:flex; flex-direction:column; gap:4px; min-width:88px; }
        .abtn {
            display:inline-flex; align-items:center; justify-content:center; gap:5px;
            padding:5px 8px; border-radius:8px; font-family:'Vazir',sans-serif;
            font-size:11px; font-weight:700; text-decoration:none;
            border:1px solid transparent; cursor:pointer; transition:all .2s; white-space:nowrap;
        }
        .abtn-toggle { background:rgba(245,158,11,.11); color:#fcd34d; border-color:rgba(245,158,11,.24); }
        .abtn-toggle:hover { background:rgba(245,158,11,.25); color:#fff; }
        .abtn-edit   { background:rgba(59,130,246,.11);  color:#93c5fd; border-color:rgba(59,130,246,.24); }
        .abtn-edit:hover { background:rgba(59,130,246,.25); color:#fff; }
        .abtn-reset  { background:rgba(16,185,129,.1);   color:#6ee7b7; border-color:rgba(16,185,129,.22); }
        .abtn-reset:hover { background:rgba(16,185,129,.25); color:#fff; }
        .abtn-del    { background:rgba(239,68,68,.1);    color:#fca5a5; border-color:rgba(239,68,68,.2); }
        .abtn-del:hover { background:rgba(239,68,68,.25); color:#fff; }

        /* empty */
        .empty { text-align:center; padding:60px 20px; color:var(--t3); }
        .empty i { font-size:44px; margin-bottom:14px; color:rgba(124,58,237,.25); }
        .empty p { font-size:14px; }

        /* flash */
        .flash {
            background:rgba(124,58,237,.1); border:1px solid rgba(124,58,237,.28);
            border-radius:12px; padding:12px 16px; margin-bottom:18px;
            color:var(--p3); display:flex; align-items:center; gap:10px; font-size:13px;
        }

        /* ── RESPONSIVE ── */
        @media(max-width:1100px) { .navbar-live { display:none; } }
        @media(max-width:900px)  { .gauges { grid-template-columns:repeat(2,1fr); } }
        @media(max-width:680px) {
            .nav-btns { display:none; }
            .ham { display:block; }
            .gauges { gap:8px; }
            .gring { width:72px; height:72px; }
            .gring canvas { width:72px!important; height:72px!important; }
            .gval-num { font-size:14px; }
            .wrap { padding:14px 10px 30px; }
            .toolbar { gap:8px; }
            .search-wrap { width:100%; }
            .sinput { width:100%; flex:1; }
            .summary { gap:8px; }
            .scard { padding:12px 14px; flex:1; min-width:130px; }
            .scard-val { font-size:17px; }
        }
        @media(max-width:400px) { .gauges { grid-template-columns:repeat(2,1fr); gap:6px; } }
    </style>
</head>
<body>

<!-- ── NAVBAR ── -->
<nav class="navbar">
    <div class="navbar-row">
        <a href="#" class="brand">
            <div class="brand-icon"><i class="fas fa-shield-halved"></i></div>
            <div>
                <span class="brand-name">GUARD VPN</span>
                <span class="brand-ver">v1.1 &nbsp;•&nbsp; پنل مدیریت</span>
            </div>
        </a>

        <!-- live pills -->
        <div class="navbar-live">
            <div class="live-pill">
                <div class="live-dot"></div>
                لایو
                &nbsp;<span class="val" id="hdr-cpu">{{ stats.cpu }}%</span>
                CPU
            </div>
            <div class="live-pill">
                <i class="fas fa-memory" style="color:var(--p2);font-size:11px;"></i>
                RAM &nbsp;<span class="val" id="hdr-ram">{{ stats.memory }}%</span>
            </div>
            <div class="live-pill">
                <i class="fas fa-users" style="color:var(--p2);font-size:11px;"></i>
                <span class="val" id="hdr-users">{{ stats.active_users }}</span> / {{ stats.total_users }} فعال
            </div>
            <div class="live-pill" id="hdr-clock" style="font-variant-numeric:tabular-nums;">--:--:--</div>
        </div>

        <div class="nav-btns">
            <a href="{{ url_for('add_user') }}" class="nbtn nbtn-green">
                <i class="fas fa-user-plus"></i> کاربر جدید
            </a>
            <a href="{{ url_for('logout') }}" class="nbtn nbtn-red">
                <i class="fas fa-right-from-bracket"></i> خروج
            </a>
        </div>
        <button class="ham" id="ham-btn" onclick="toggleHam()"><i class="fas fa-bars"></i></button>
    </div>
</nav>
<div class="mob-menu" id="mob-menu">
    <a href="{{ url_for('add_user') }}" class="nbtn nbtn-green"><i class="fas fa-user-plus"></i> کاربر جدید</a>
    <a href="{{ url_for('logout') }}" class="nbtn nbtn-red"><i class="fas fa-right-from-bracket"></i> خروج</a>
</div>

<!-- ── MAIN ── -->
<div class="wrap">

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="flash"><i class="fas fa-circle-check"></i> {{ messages[0] }}</div>
      {% endif %}
    {% endwith %}

    <!-- ── GAUGES ── -->
    <div class="gauges">
        <div class="gcard" style="--gcolor:#7c3aed;">
            <div class="glabel">CPU</div>
            <div class="gring"><canvas id="gCpu"></canvas>
                <div class="gval"><div class="gval-num" id="gcv-cpu">{{ stats.cpu }}%</div></div>
            </div>
            <div class="gicon"><i class="fas fa-microchip"></i> پردازنده</div>
        </div>
        <div class="gcard" style="--gcolor:#a855f7;">
            <div class="glabel">RAM</div>
            <div class="gring"><canvas id="gRam"></canvas>
                <div class="gval"><div class="gval-num" id="gcv-ram">{{ stats.memory }}%</div></div>
            </div>
            <div class="gicon"><i class="fas fa-memory"></i> حافظه</div>
        </div>
        <div class="gcard" style="--gcolor:#ec4899;">
            <div class="glabel">DISK</div>
            <div class="gring"><canvas id="gDisk"></canvas>
                <div class="gval"><div class="gval-num" id="gcv-disk">{{ stats.disk }}%</div></div>
            </div>
            <div class="gicon"><i class="fas fa-hard-drive"></i> هارد دیسک</div>
        </div>
        <div class="gcard" style="--gcolor:#c084fc;">
            <div class="glabel">TRAFFIC</div>
            <div class="gring"><canvas id="gTraf"></canvas>
                <div class="gval"><div class="gval-num" id="gcv-traf">{{ stats.traffic }}%</div></div>
            </div>
            <div class="gicon"><i class="fas fa-chart-line"></i> ترافیک سرور</div>
        </div>
    </div>

    <!-- ── SUMMARY ── -->
    <div class="summary">
        <div class="scard">
            <div class="scard-icon" style="background:rgba(124,58,237,.15);color:var(--p3);"><i class="fas fa-users"></i></div>
            <div class="scard-body">
                <span class="scard-val" id="sum-total">{{ stats.total_users }}</span>
                <span class="scard-lab">کل کاربران</span>
            </div>
        </div>
        <div class="scard">
            <div class="scard-icon" style="background:rgba(16,185,129,.13);color:#34d399;"><i class="fas fa-user-check"></i></div>
            <div class="scard-body">
                <span class="scard-val" id="sum-active">{{ stats.active_users }}</span>
                <span class="scard-lab">کاربران فعال</span>
            </div>
        </div>
        <div class="scard">
            <div class="scard-icon" style="background:rgba(239,68,68,.11);color:#f87171;"><i class="fas fa-user-xmark"></i></div>
            <div class="scard-body">
                <span class="scard-val" id="sum-inactive">{{ stats.total_users - stats.active_users }}</span>
                <span class="scard-lab">کاربران غیرفعال</span>
            </div>
        </div>
        <div class="scard">
            <div class="scard-icon" style="background:rgba(245,158,11,.12);color:#fcd34d;"><i class="fas fa-circle-dot"></i></div>
            <div class="scard-body">
                <span class="scard-val" id="sum-online">{{ data | selectattr('online') | list | length }}</span>
                <span class="scard-lab">کاربران آنلاین</span>
            </div>
        </div>
    </div>

    <!-- ── TOOLBAR ── -->
    <div class="toolbar">
        <div class="toolbar-left">
            <div class="page-title"><i class="fas fa-table-list"></i> مدیریت کاربران</div>
            <span class="user-count" id="tbl-count">{{ data | length }} کاربر</span>
        </div>
        <form method="GET" action="{{ url_for('dashboard') }}">
            <div class="search-wrap">
                <div class="sinput-wrap">
                    <i class="fas fa-magnifying-glass sicon"></i>
                    <input type="text" name="search" class="sinput" placeholder="جستجو..." value="{{ search_query }}" id="search-inp">
                </div>
                <button type="submit" class="sbtn">جستجو</button>
            </div>
        </form>
    </div>

    <!-- ── TABLE ── -->
    <div class="tcard" id="tcard">
        <div class="tscroll">
            <table id="users-table">
                <thead>
                    <tr>
                        <th>کاربر</th>
                        <th>آنلاین</th>
                        <th>وضعیت</th>
                        <th>حجم / محدودیت</th>
                        <th>انقضا</th>
                        <th>جلسه</th>
                        <th>۷ روز</th>
                        <th>۳۰ روز</th>
                        <th>کل</th>
                        <th>نمودار</th>
                        <th>عملیات</th>
                    </tr>
                </thead>
                <tbody id="users-tbody">
                    {% for u in data %}
                    <tr data-uid="{{ u.uid }}">
                        <td><div class="uname"><i class="fas fa-circle-user"></i>{{ u.username }}</div></td>
                        <td>
                            {% if u.online %}<span class="badge badge-on"><i class="fas fa-circle"></i> آنلاین</span>
                            {% else %}<span class="badge badge-off"><i class="fas fa-circle"></i> آفلاین</span>{% endif %}
                        </td>
                        <td>
                            {% if u.active %}<span class="badge badge-act"><i class="fas fa-check"></i> فعال</span>
                            {% else %}<span class="badge badge-dis"><i class="fas fa-xmark"></i> غیرفعال</span>{% endif %}
                        </td>
                        <td>
                            <div class="usage-bar-wrap">
                                <div class="usage-label">{{ u.total }} / {{ u.limit }}</div>
                                {% if u.limit_bytes > 0 %}
                                <div class="usage-bar">
                                    <div class="usage-fill {% if u.usage_pct >= 80 %}warn{% endif %}" style="width:{{ u.usage_pct }}%"></div>
                                </div>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            {% if u.expiration_date %}
                                {% if u.days_remaining is not none %}
                                    {% if u.days_remaining < 0 %}
                                        <span class="expiry-exp"><i class="fas fa-clock"></i> منقضی شده</span>
                                    {% elif u.days_remaining <= 3 %}
                                        <span class="expiry-warn"><i class="fas fa-triangle-exclamation"></i> {{ u.days_remaining }} روز</span>
                                    {% else %}
                                        <span class="expiry-ok"><i class="fas fa-calendar-check"></i> {{ u.days_remaining }} روز</span>
                                    {% endif %}
                                {% endif %}
                                <div style="font-size:10px;color:var(--t3);margin-top:3px;">{{ u.expiration_date }}</div>
                            {% else %}
                                <span class="expiry-none">نامحدود</span>
                            {% endif %}
                        </td>
                        <td class="tval">{{ u.current }}</td>
                        <td class="tval">{{ u.week }}</td>
                        <td class="tval">{{ u.month }}</td>
                        <td class="tval tval-total">{{ u.total }}</td>
                        <td>
                            <div class="mchart"><canvas id="c{{ u.uid }}"></canvas></div>
                        </td>
                        <td>
                            <div class="acts">
                                <a href="{{ url_for('toggle_active', username=u.username) }}" class="abtn abtn-toggle">
                                    <i class="fas fa-toggle-on"></i> وضعیت
                                </a>
                                <a href="{{ url_for('edit_user', username=u.username) }}" class="abtn abtn-edit">
                                    <i class="fas fa-pen"></i> ویرایش
                                </a>
                                <a href="{{ url_for('reset_traffic', username=u.username) }}" class="abtn abtn-reset"
                                   onclick="return confirm('ریست ترافیک {{ u.username }}؟')">
                                    <i class="fas fa-rotate"></i> ریست ترافیک
                                </a>
                                <a href="{{ url_for('delete_user', username=u.username) }}" class="abtn abtn-del"
                                   onclick="return confirm('حذف کاربر {{ u.username }}؟')">
                                    <i class="fas fa-trash"></i> حذف
                                </a>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                    {% if data | length == 0 %}
                    <tr><td colspan="11">
                        <div class="empty"><i class="fas fa-users-slash"></i><p>هیچ کاربری یافت نشد</p></div>
                    </td></tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
    </div>
</div><!-- /wrap -->

<script>
/* ── hamburger ── */
function toggleHam() {
    const m = document.getElementById('mob-menu');
    const b = document.getElementById('ham-btn');
    m.classList.toggle('open');
    b.innerHTML = m.classList.contains('open') ? '<i class="fas fa-xmark"></i>' : '<i class="fas fa-bars"></i>';
}

/* ── live clock ── */
function tickClock() {
    const now = new Date();
    document.getElementById('hdr-clock').textContent =
        now.toLocaleTimeString('fa-IR', {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}
tickClock();
setInterval(tickClock, 1000);

/* ── gauge factory ── */
const gaugeCharts = {};
function makeGauge(id, val, color) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const ch = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{ data: [val, 100 - val],
                backgroundColor: [color, 'rgba(255,255,255,.05)'],
                borderWidth: 0, borderRadius: 4 }]
        },
        options: {
            cutout: '76%', responsive: false,
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            animation: { animateRotate: true, duration: 900, easing: 'easeOutQuart' }
        }
    });
    gaugeCharts[id] = ch;
    return ch;
}
function updateGauge(id, val) {
    const ch = gaugeCharts[id];
    if (!ch) return;
    ch.data.datasets[0].data = [val, Math.max(0, 100 - val)];
    ch.update('none');
}

makeGauge('gCpu',  {{ stats.cpu }},    '#7c3aed');
makeGauge('gRam',  {{ stats.memory }}, '#a855f7');
makeGauge('gDisk', {{ stats.disk }},   '#ec4899');
makeGauge('gTraf', {{ stats.traffic }},'#c084fc');

/* ── mini user charts ── */
{% for u in data %}
(function() {
    const ctx = document.getElementById('c{{ u.uid }}');
    if (!ctx) return;
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: {{ u['labels'] | tojson }},
            datasets: [{ data: {{ u['values'] | tojson }},
                borderColor: 'rgba(168,85,247,.85)',
                backgroundColor: 'rgba(124,58,237,.1)',
                borderWidth: 1.5, pointRadius: 0, fill: true, tension: 0.4 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
            animation: false
        }
    });
})();
{% endfor %}

/* ── SSE: real-time instant stats ── */
function applyStats(d) {
    const keys  = ['cpu','memory','disk','traffic'];
    const gids  = ['gCpu','gRam','gDisk','gTraf'];
    const cvids = ['gcv-cpu','gcv-ram','gcv-disk','gcv-traf'];

    keys.forEach((k, i) => {
        const val = d[k];
        updateGauge(gids[i], val);
        document.getElementById(cvids[i]).textContent = val + '%';
    });

    document.getElementById('hdr-cpu').textContent   = d.cpu + '%';
    document.getElementById('hdr-ram').textContent   = d.memory + '%';
    document.getElementById('hdr-users').textContent = d.active_users;

    document.getElementById('sum-total').textContent    = d.total_users;
    document.getElementById('sum-active').textContent   = d.active_users;
    document.getElementById('sum-inactive').textContent = d.total_users - d.active_users;
}

(function startSSE() {
    let es = new EventSource('/api/stream');

    es.onmessage = function(e) {
        try { applyStats(JSON.parse(e.data)); } catch(_) {}
    };

    es.onerror = function() {
        es.close();
        setTimeout(startSSE, 2000);
    };
})();
</script>
</body>
</html>
GUARD_DASHHTML

ok "dashboard.html written"
sep

# ================================================================
#   WRITE save_traffic.py + CRON
# ================================================================
step "Setting Up Traffic Cron Job"
for i in $(seq 1 5); do progress $i 5 "save_traffic.py..."; sleep 0.03; done

cat > /opt/traffic_panel/save_traffic.py <<'GUARD_SAVETRAFFIC'
import sqlite3
import subprocess
from datetime import date

DB_PATH = '/opt/traffic_panel/traffic.db'
conn = sqlite3.connect(DB_PATH)
today = date.today().strftime('%Y-%m-%d')

for row in conn.execute('SELECT uid FROM users'):
    uid = row[0]
    b_out = b_in = 0
    for chain, key in [(f"USER_OUT_{uid}", 'out'), (f"USER_IN_{uid}", 'in')]:
        try:
            out = subprocess.check_output(f"iptables -L {chain} -v -n -x 2>/dev/null", shell=True).decode()
            lines = out.split('\n')
            if len(lines) > 2 and lines[2].strip():
                val = int(lines[2].split()[1])
                if key == 'out': b_out = val
                else: b_in = val
            subprocess.call(f"iptables -Z {chain} 2>/dev/null", shell=True)
        except Exception:
            pass
    if b_out > 0 or b_in > 0:
        conn.execute('INSERT OR REPLACE INTO usage (date, uid, bytes_out, bytes_in) VALUES (?, ?, ?, ?)', (today, uid, b_out, b_in))

conn.commit()
conn.close()
GUARD_SAVETRAFFIC

cat > /etc/cron.daily/save_traffic <<'GUARD_CRON'
#!/bin/sh
/usr/bin/python3 /opt/traffic_panel/save_traffic.py
GUARD_CRON
chmod +x /etc/cron.daily/save_traffic
ok "Traffic cron job installed"
sep

# ================================================================
#   IPTABLES SETUP
# ================================================================
step "Configuring iptables Chains"
for i in $(seq 1 10); do progress $i 10 "iptables..."; sleep 0.04; done

cat > /opt/traffic_panel/setup_iptables.sh <<'GUARD_IPTS'
#!/bin/sh
users=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $3}')
for uid in $users; do
  for chain in "USER_OUT_${uid}" "USER_IN_${uid}"; do
    iptables -D OUTPUT -m owner --uid-owner "$uid" -j "$chain" 2>/dev/null || true
    iptables -D INPUT  -m owner --uid-owner "$uid" -j "$chain" 2>/dev/null || true
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
  done
  iptables -N "USER_OUT_${uid}" 2>/dev/null || true
  iptables -A "USER_OUT_${uid}" -j RETURN
  iptables -A OUTPUT -m owner --uid-owner "$uid" -j "USER_OUT_${uid}"
  iptables -N "USER_IN_${uid}" 2>/dev/null || true
  iptables -A "USER_IN_${uid}" -j RETURN
  iptables -A INPUT -m owner --uid-owner "$uid" -j "USER_IN_${uid}"
done
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
GUARD_IPTS
chmod +x /opt/traffic_panel/setup_iptables.sh
/opt/traffic_panel/setup_iptables.sh 2>/dev/null || true
ok "iptables chains configured"
sep

# ================================================================
#   SYSTEMD SERVICE
# ================================================================
step "Creating Systemd Service"
for i in $(seq 1 5); do progress $i 5 "systemd..."; sleep 0.04; done

cat > /etc/systemd/system/traffic_panel.service <<GUARD_SYSTEMD
[Unit]
Description=GUARD VPN Panel
After=network.target

[Service]
User=root
WorkingDirectory=/opt/traffic_panel
Environment="PORT=${PORT}"
Environment="ADMIN_USER=${ADMIN_USER}"
Environment="ADMIN_PASS=${ADMIN_PASS}"
Environment="SECRET_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
ExecStart=/usr/local/bin/gunicorn --bind=0.0.0.0:${PORT} --workers=2 --timeout=120 --chdir /opt/traffic_panel app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
GUARD_SYSTEMD

systemctl daemon-reload
systemctl stop traffic_panel 2>/dev/null || true
systemctl start traffic_panel
systemctl enable traffic_panel
ok "Service started and enabled"
sep

# ================================================================
#   MANAGEMENT COMMAND: guardvpn
# ================================================================
step "Installing Management Command (guardvpn)"
for i in $(seq 1 5); do progress $i 5 "guardvpn cmd..."; sleep 0.03; done

cat > /usr/local/bin/guardvpn <<GUARD_CMD
#!/bin/bash
R='\e[0;31m';BR='\e[1;31m';G='\e[0;32m';BG='\e[1;32m'
Y='\e[0;33m';BY='\e[1;33m';B='\e[0;34m';BB='\e[1;34m'
M='\e[0;35m';BM='\e[1;35m';C='\e[0;36m';BC='\e[1;36m'
BW='\e[1;37m';DIM='\e[2m';NC='\e[0m'
PANEL_IP="${IP}"
PANEL_PORT="${PORT}"
ADMIN_USER_DISPLAY="${ADMIN_USER}"

banner(){
echo ""
echo -e "\${BM}  ╔══════════════════════════════════════╗\${NC}"
echo -e "\${BM}  ║\${NC}  \${BC}GUARD VPN Panel\${NC}  \${DIM}v1.1\${NC}               \${BM}║\${NC}"
echo -e "\${BM}  ║\${NC}  \${DIM}Built by LOCALVPS  |  t.me/localvps\${NC}  \${BM}║\${NC}"
echo -e "\${BM}  ╚══════════════════════════════════════╝\${NC}"
echo ""
}

case "\$1" in
  start)
    banner
    echo -e "  \${BG}▶\${NC}  Starting GUARD VPN Panel..."
    systemctl start traffic_panel
    echo -e "  \${BG}✔\${NC}  Panel started successfully"
    echo -e "  \${BB}•\${NC}  URL: \${BC}http://\${PANEL_IP}:\${PANEL_PORT}\${NC}"
    ;;
  stop)
    banner
    echo -e "  \${BY}■\${NC}  Stopping GUARD VPN Panel..."
    systemctl stop traffic_panel
    echo -e "  \${BG}✔\${NC}  Panel stopped"
    ;;
  restart)
    banner
    echo -e "  \${BC}↺\${NC}  Restarting GUARD VPN Panel..."
    systemctl restart traffic_panel
    echo -e "  \${BG}✔\${NC}  Panel restarted"
    echo -e "  \${BB}•\${NC}  URL: \${BC}http://\${PANEL_IP}:\${PANEL_PORT}\${NC}"
    ;;
  status)
    banner
    echo -e "  \${BC}◎\${NC}  Service Status:\n"
    systemctl status traffic_panel --no-pager -l
    ;;
  logs)
    banner
    echo -e "  \${BC}◎\${NC}  Live Logs (Ctrl+C to exit):\n"
    journalctl -u traffic_panel -f --no-pager
    ;;
  remove)
    banner
    echo -e "  \${BR}⚠\${NC}  \${BW}This will completely remove GUARD VPN Panel.\${NC}"
    printf "  \${BY}Are you sure? [y/N]: \${NC}"; read -r confirm
    if [ "\$confirm" = "y" ] || [ "\$confirm" = "Y" ]; then
      systemctl stop traffic_panel 2>/dev/null || true
      systemctl disable traffic_panel 2>/dev/null || true
      rm -f /etc/systemd/system/traffic_panel.service
      rm -rf /opt/traffic_panel
      rm -f /etc/cron.daily/save_traffic
      rm -f /usr/local/bin/guardvpn
      systemctl daemon-reload
      echo -e "  \${BG}✔\${NC}  GUARD VPN Panel has been removed."
    else
      echo -e "  \${DIM}Cancelled.\${NC}"
    fi
    ;;
  info)
    banner
    echo -e "  \${BB}•\${NC}  Panel URL  : \${BC}http://\${PANEL_IP}:\${PANEL_PORT}\${NC}"
    echo -e "  \${BB}•\${NC}  Admin User : \${BC}\${ADMIN_USER_DISPLAY}\${NC}"
    echo -e "  \${BB}•\${NC}  Install Dir: \${DIM}/opt/traffic_panel\${NC}"
    echo -e "  \${BB}•\${NC}  Service    : \${DIM}traffic_panel\${NC}"
    echo ""
    echo -e "  \${BM}Built by LOCALVPS\${NC}"
    echo -e "  \${DIM}GitHub  : github.com/localvps\${NC}"
    echo -e "  \${DIM}Telegram: t.me/localvps\${NC}"
    echo ""
    ;;
  *)
    banner
    echo -e "  \${BW}Usage:\${NC}  guardvpn <command>"
    echo ""
    echo -e "  \${BG}start\${NC}      Start the panel"
    echo -e "  \${BY}stop\${NC}       Stop the panel"
    echo -e "  \${BC}restart\${NC}    Restart the panel"
    echo -e "  \${BB}status\${NC}     Show service status"
    echo -e "  \${BB}logs\${NC}       Follow live logs"
    echo -e "  \${BM}info\${NC}       Show panel info & URLs"
    echo -e "  \${BR}remove\${NC}     Completely uninstall panel"
    echo ""
    ;;
esac
GUARD_CMD

chmod +x /usr/local/bin/guardvpn
ok "Management command installed: guardvpn"
sep

# ================================================================
#   VERIFY
# ================================================================
step "Verifying Installation"
sleep 2
if systemctl is-active --quiet traffic_panel; then
  ok "Service is running"
else
  echo -e "  ${BR}✖${NC}  Service failed — check: ${C}journalctl -u traffic_panel -n 30${NC}"
fi
sep

# ================================================================
#   FINAL SUMMARY
# ================================================================
echo ""
echo -e "${BM}  ╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}  INSTALLATION COMPLETE!${NC}                          ${BM}║${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BB}Panel URL   ${NC}  ${BC}http://${IP}:${PORT}${NC}                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BB}Username    ${NC}  ${BW}${ADMIN_USER}${NC}                               ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BB}Password    ${NC}  ${BW}${ADMIN_PASS}${NC}                            ${BM}║${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BY}Management Commands:${NC}                              ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}guardvpn start${NC}    — Start panel                   ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BY}guardvpn stop${NC}     — Stop panel                    ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BC}guardvpn restart${NC}  — Restart panel                 ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BB}guardvpn status${NC}   — Show status                   ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BB}guardvpn logs${NC}     — Follow live logs              ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BM}guardvpn info${NC}     — Show URLs & info              ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BR}guardvpn remove${NC}   — Uninstall panel               ${BM}║${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}✔${NC}  دیزاین Glassmorphism + Animated Blobs           ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}✔${NC}  Real-time CPU/RAM/Disk/Traffic via SSE           ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}✔${NC}  محدودیت ترافیک و تاریخ انقضا per-user            ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}✔${NC}  دکمه ریست ترافیک و نمودار mini chart             ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}✔${NC}  موبایل-فرندلی با hamburger menu                  ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${BG}✔${NC}  gunicorn + systemd — Auto-start on boot          ${BM}║${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${M}Built by LOCALVPS${NC}                                  ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${DIM}GitHub   : github.com/localvps${NC}                   ${BM}║${NC}"
echo -e "${BM}  ║${NC}   ${DIM}Telegram : t.me/localvps${NC}                         ${BM}║${NC}"
echo -e "${BM}  ║${NC}                                                      ${BM}║${NC}"
echo -e "${BM}  ╚══════════════════════════════════════════════════════╝${NC}"
echo ""
