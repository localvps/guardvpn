#!/bin/sh

# This script installs a web panel for monitoring per-user traffic (incoming and outgoing) on Ubuntu.
# Run as root: sudo bash this_script.sh

if [ "$(id -u)" -ne 0 ]; then
  echo -e "\e[1;31mThis script must be run as root.\e[0m"
  exit 1
fi

# Colors
RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
CYAN='\e[1;36m'
NC='\e[0m' # No Color

# Install figlet for big text
apt install -y figlet > /dev/null 2>&1

echo -e "${GREEN}"
figlet "GUARDNET VPN"
echo "POWER BY LOCALVPS"
echo -e "${NC}"

echo -e "${GREEN}Starting installation...${NC}"

# Function to simulate progress
simulate_progress() {
  start=$1
  end=$2
  for p in $(seq $((start + 1)) $end); do
    bar=$(printf '%*s' "$p" | tr ' ' '|')
    echo -e "\r${CYAN}${bar} ${p}%${NC}"
    sleep 0.05  # Adjust speed as needed
  done
}

simulate_progress 0 0

# Ask for port
echo -e "${YELLOW}Select port for the panel:${NC}"
echo "1) Default (6565)"
echo "2) Custom"
read -p "Enter choice (1 or 2): " port_choice
if [ "$port_choice" = "2" ]; then
  read -p "Enter custom port: " PORT
else
  PORT=6565
fi

# Ask for username
echo -e "${YELLOW}Select username for admin:${NC}"
echo "1) Default (admin)"
echo "2) Custom"
read -p "Enter choice (1 or 2): " user_choice
if [ "$user_choice" = "2" ]; then
  read -p "Enter custom username: " ADMIN_USER
else
  ADMIN_USER="admin"
fi

# Ask for password
echo -e "${YELLOW}Select password for admin:${NC}"
echo "1) Default (admin123)"
echo "2) Custom"
read -p "Enter choice (1 or 2): " pass_choice
if [ "$pass_choice" = "2" ]; then
  read -p "Enter custom password: " ADMIN_PASS
else
  ADMIN_PASS="admin123"
fi

# Get public IP with better services
echo -e "${YELLOW}Detecting server IP...${NC}"
apt install -y curl > /dev/null 2>&1
IP=$(curl -s icanhazip.com)
if [ -z "$IP" ] || echo "$IP" | grep -q '<'; then
  IP=$(curl -s ipinfo.io/ip)
fi
if [ -z "$IP" ] || echo "$IP" | grep -q '<'; then
  IP=$(curl -s ifconfig.co)
fi
if [ -z "$IP" ] || echo "$IP" | grep -q '<'; then
  IP=$(hostname -I | awk '{print $1}')
  echo -e "${RED}Could not detect public IP, using local IP: $IP${NC}"
else
  echo -e "${GREEN}Public IP detected: $IP${NC}"
fi

simulate_progress 0 10

echo -e "${YELLOW}Updating system and installing dependencies...${NC}"
apt update -y > /dev/null 2>&1
simulate_progress 10 30
apt install -y python3 python3-pip iptables-persistent net-tools lsof curl figlet psmisc > /dev/null 2>&1
pip3 install flask flask-login psutil > /dev/null 2>&1
simulate_progress 30 50

echo -e "${YELLOW}Killing any existing process on port $PORT...${NC}"
kill -9 $(lsof -t -i:$PORT) 2>/dev/null || true
simulate_progress 50 55

echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p /opt/traffic_panel/templates
mkdir -p /opt/traffic_panel/static
cd /opt/traffic_panel
simulate_progress 55 60

echo -e "${YELLOW}Creating the Flask application file...${NC}"
cat > app.py <<EOF
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import sqlite3
import subprocess
from datetime import datetime, timedelta
import re
import psutil

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_me'  # Change this in production

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def get_db():
    conn = sqlite3.connect('traffic.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB and migrate
conn = get_db()
conn.execute('CREATE TABLE IF NOT EXISTS users (uid INTEGER PRIMARY KEY, username TEXT, limit_bytes INTEGER DEFAULT 0, expiration_date TEXT, active INTEGER DEFAULT 1)')
conn.execute('CREATE TABLE IF NOT EXISTS usage (date TEXT, uid INTEGER, bytes_out INTEGER, PRIMARY KEY (date, uid))')
try:
    conn.execute('ALTER TABLE usage ADD COLUMN bytes_in INTEGER')
except sqlite3.OperationalError:
    pass  # column already exists
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
conn.commit()
conn.close()

def update_users():
    conn = get_db()
    output = subprocess.check_output("getent passwd | awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$3\" \"\$1}'", shell=True).decode().strip()
    users = output.split('\n') if output else []
    for line in users:
        if line:
            uid, username = line.split()
            uid = int(uid)
            conn.execute('INSERT OR IGNORE INTO users (uid, username) VALUES (?, ?)', (uid, username))
    conn.commit()
    conn.close()

def ensure_chains():
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
    # Save rules
    subprocess.call("iptables-save > /etc/iptables/rules.v4", shell=True)

update_users()  # Initial update
ensure_chains()  # Initial ensure

def get_online_users():
    # Check if user has any running processes
    output = subprocess.check_output("ps -eo user | tail -n +2 | sort | uniq", shell=True).decode().strip()
    return output.split('\n') if output else []

def get_current_traffic():
    traffic = {}
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
                bytes_out = int(lines[2].split()[1])  # bytes column
        except:
            pass
        try:
            output = subprocess.check_output(f"iptables -L {in_chain} -v -n -x 2>/dev/null", shell=True).decode()
            lines = output.split('\n')
            if len(lines) > 2 and lines[2].strip():
                bytes_in = int(lines[2].split()[1])  # bytes column
        except:
            pass
        traffic[uid] = {'out': bytes_out, 'in': bytes_in}
    conn.close()
    return traffic

def get_historical(uid, days, direction='total'):
    conn = get_db()
    date_limit = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    if direction == 'out':
        cursor = conn.execute('SELECT SUM(bytes_out) FROM usage WHERE uid = ? AND date >= ?', (uid, date_limit))
    elif direction == 'in':
        cursor = conn.execute('SELECT SUM(COALESCE(bytes_in, 0)) FROM usage WHERE uid = ? AND date >= ?', (uid, date_limit))
    else:  # total
        cursor = conn.execute('SELECT SUM(bytes_out + COALESCE(bytes_in, 0)) FROM usage WHERE uid = ? AND date >= ?', (uid, date_limit))
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

def check_user_limits():
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
        total_traffic = get_historical(uid, 365 * 10)  # Total lifetime
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

def deactivate_user(username):
    subprocess.call(f"usermod -L {username}", shell=True)
    subprocess.call(f"pkill -u {username}", shell=True)

def activate_user(username):
    subprocess.call(f"usermod -U {username}", shell=True)

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == '$ADMIN_USER' and password == '$ADMIN_PASS':
            user = User(1)
            login_user(user)
            return redirect(url_for('dashboard'))
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
        limit_mb = int(request.form.get('limit_mb', 0)) * 1024 * 1024  # Convert MB to bytes
        expiration_days = int(request.form.get('expiration_days', 0))
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
            conn.execute('INSERT INTO users (uid, username, limit_bytes, expiration_date) VALUES (?, ?, ?, ?)', (uid, username, limit_mb, expiration_date))
            conn.commit()
            conn.close()
            flash('یوزر جدید با موفقیت اضافه شد.')
            update_users()  # Update DB
            ensure_chains()  # Ensure iptables chains
        except:
            flash('خطا در اضافه کردن یوزر.')
        return redirect(url_for('dashboard'))
    return render_template('add_user.html')

@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
def edit_user(username):
    conn = get_db()
    cursor = conn.execute('SELECT limit_bytes, expiration_date FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        current_limit_mb = row['limit_bytes'] // (1024 * 1024) if row['limit_bytes'] else 0
        current_expiration = row['expiration_date']
    else:
        current_limit_mb = 0
        current_expiration = None
    if request.method == 'POST':
        limit_mb = int(request.form.get('limit_mb', 0)) * 1024 * 1024
        expiration_days = int(request.form.get('expiration_days', 0))
        expiration_date = None
        if expiration_days > 0:
            expiration_date = (datetime.now() + timedelta(days=expiration_days)).strftime('%Y-%m-%d')
        conn = get_db()
        conn.execute('UPDATE users SET limit_bytes = ?, expiration_date = ? WHERE username = ?', (limit_mb, expiration_date, username))
        conn.commit()
        conn.close()
        flash('یوزر با موفقیت ویرایش شد.')
        return redirect(url_for('dashboard'))
    return render_template('edit_user.html', username=username, current_limit_mb=current_limit_mb, current_expiration=current_expiration)

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
    except:
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

@app.route('/system_stats')
@login_required
def system_stats():
    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    # For total traffic, sum all historical
    conn = get_db()
    cursor = conn.execute('SELECT SUM(bytes_out + COALESCE(bytes_in, 0)) FROM usage')
    total_traffic_bytes = cursor.fetchone()[0] or 0
    conn.close()
    # Assume server has 100GB traffic limit for percentage, adjust as needed
    traffic_limit = 100 * 1024 * 1024 * 1024  # 100 GB in bytes
    traffic = (total_traffic_bytes / traffic_limit) * 100 if traffic_limit > 0 else 0
    return {'cpu': cpu, 'memory': memory, 'disk': disk, 'traffic': traffic}

@app.route('/dashboard')
@login_required
def dashboard():
    check_user_limits()
    theme = session.get('theme', 'dark')
    update_users()
    ensure_chains()
    conn = get_db()
    cursor = conn.execute('SELECT uid, username, active FROM users')
    users = cursor.fetchall()
    conn.close()
    online_users = get_online_users()
    current_traffic = get_current_traffic()
    
    # Search functionality
    search_query = request.args.get('search', '')
    filtered_data = []
    
    for user in users:
        uid = user['uid']
        username = user['username']
        active = user['active']
        
        # Apply search filter
        if search_query and search_query.lower() not in username.lower():
            continue
            
        online = username in online_users and active == 1
        curr = current_traffic.get(uid, {'out': 0, 'in': 0})
        current = format_bytes(curr['out'] + curr['in'])
        week = format_bytes(get_historical(uid, 7))
        month = format_bytes(get_historical(uid, 30))
        total = format_bytes(get_historical(uid, 365 * 10))
        labels, values = get_chart_data(uid)
        filtered_data.append({
            'uid': uid,
            'username': username,
            'active': active,
            'online': online,
            'current': current,
            'week': week,
            'month': month,
            'total': total,
            'labels': labels,
            'values': values  # numerical bytes for chart
        })
    
    stats = system_stats()
    return render_template('dashboard.html', data=filtered_data, theme=theme, stats=stats, search_query=search_query)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=$PORT, debug=True)  # Set debug=True to see errors in browser
EOF
simulate_progress 60 70

echo -e "${YELLOW}Creating login template...${NC}"
cat > templates/login.html <<EOF
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>ورود</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet" type="text/css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { font-family: 'Vazir', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-card { background: rgba(255, 255, 255, 0.1); border-radius: 20px; box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.18); padding: 30px; }
        .card-header { background: transparent; border-bottom: none; text-align: center; font-size: 24px; margin-bottom: 20px; }
        .form-control { background: rgba(255, 255, 255, 0.2); border: none; color: #fff; }
        .form-control::placeholder { color: #ddd; }
        .btn-primary { background: #6f42c1; border: none; border-radius: 50px; padding: 10px; }
        .btn-primary:hover { background: #5a32a3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-5 login-card">
                <div class="card-header">ورود به پنل GUARD VPN <i class="fas fa-shield-alt"></i></div>
                <form method="POST">
                    <div class="form-group">
                        <label for="username">نام کاربری</label>
                        <input type="text" class="form-control" id="username" name="username" placeholder="نام کاربری" required>
                    </div>
                    <div class="form-group">
                        <label for="password">رمز عبور</label>
                        <input type="password" class="form-control" id="password" name="password" placeholder="رمز عبور" required>
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">ورود <i class="fas fa-sign-in-alt"></i></button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
EOF
simulate_progress 70 75

echo -e "${YELLOW}Creating add_user template...${NC}"
cat > templates/add_user.html <<EOF
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>اضافه کردن یوزر جدید</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet" type="text/css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { font-family: 'Vazir', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; height: 100vh; display: flex; align-items: center; justify-content: center; }
        .add-user-card { background: rgba(255, 255, 255, 0.1); border-radius: 20px; box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.18); padding: 30px; }
        .card-header { background: transparent; border-bottom: none; text-align: center; font-size: 24px; margin-bottom: 20px; }
        .form-control { background: rgba(255, 255, 255, 0.2); border: none; color: #fff; }
        .form-control::placeholder { color: #ddd; }
        .btn-primary { background: #6f42c1; border: none; border-radius: 50px; padding: 10px; }
        .btn-primary:hover { background: #5a32a3; }
        .alert { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-5 add-user-card">
                <div class="card-header">اضافه کردن یوزر جدید <i class="fas fa-user-plus"></i></div>
                {% with messages = get_flashed_messages() %}
                  {% if messages %}
                    <div class="alert alert-info">
                      {{ messages[0] }}
                    </div>
                  {% endif %}
                {% endwith %}
                <form method="POST">
                    <div class="form-group">
                        <label for="username">نام کاربری</label>
                        <input type="text" class="form-control" id="username" name="username" placeholder="نام کاربری" required>
                    </div>
                    <div class="form-group">
                        <label for="password">رمز عبور</label>
                        <input type="password" class="form-control" id="password" name="password" placeholder="رمز عبور" required>
                    </div>
                    <div class="form-group">
                        <label for="limit_mb">محدودیت ترافیک (مگابایت، 0 برای نامحدود)</label>
                        <input type="number" class="form-control" id="limit_mb" name="limit_mb" placeholder="0" value="0" min="0" required>
                    </div>
                    <div class="form-group">
                        <label for="expiration_days">انقضا (روز، 0 برای نامحدود)</label>
                        <input type="number" class="form-control" id="expiration_days" name="expiration_days" placeholder="0" value="0" min="0" required>
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">اضافه کردن <i class="fas fa-plus"></i></button>
                </form>
                <a href="{{ url_for('dashboard') }}" class="btn btn-secondary btn-block mt-3">بازگشت به داشبورد</a>
            </div>
        </div>
    </div>
</body>
</html>
EOF
simulate_progress 75 77

echo -e "${YELLOW}Creating edit_user template...${NC}"
cat > templates/edit_user.html <<EOF
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>ویرایش یوزر</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet" type="text/css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { font-family: 'Vazir', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; height: 100vh; display: flex; align-items: center; justify-content: center; }
        .edit-user-card { background: rgba(255, 255, 255, 0.1); border-radius: 20px; box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.18); padding: 30px; }
        .card-header { background: transparent; border-bottom: none; text-align: center; font-size: 24px; margin-bottom: 20px; }
        .form-control { background: rgba(255, 255, 255, 0.2); border: none; color: #fff; }
        .form-control::placeholder { color: #ddd; }
        .btn-primary { background: #6f42c1; border: none; border-radius: 50px; padding: 10px; }
        .btn-primary:hover { background: #5a32a3; }
        .alert { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-5 edit-user-card">
                <div class="card-header">ویرایش یوزر {{ username }} <i class="fas fa-edit"></i></div>
                {% with messages = get_flashed_messages() %}
                  {% if messages %}
                    <div class="alert alert-info">
                      {{ messages[0] }}
                    </div>
                  {% endif %}
                {% endwith %}
                <form method="POST">
                    <div class="form-group">
                        <label for="limit_mb">محدودیت ترافیک (مگابایت، 0 برای نامحدود)</label>
                        <input type="number" class="form-control" id="limit_mb" name="limit_mb" value="{{ current_limit_mb }}" min="0" required>
                    </div>
                    <div class="form-group">
                        <label for="expiration_days">انقضا (روز از امروز، 0 برای نامحدود)</label>
                        <input type="number" class="form-control" id="expiration_days" name="expiration_days" value="0" min="0" required>
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">به‌روزرسانی <i class="fas fa-sync"></i></button>
                </form>
                <a href="{{ url_for('dashboard') }}" class="btn btn-secondary btn-block mt-3">بازگشت به داشبورد</a>
            </div>
        </div>
    </div>
</body>
</html>
EOF
simulate_progress 77 78

echo -e "${YELLOW}Creating dashboard template with search and fixed light theme...${NC}"
cat > templates/dashboard.html <<EOF
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>GUARD VPN</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/vazir-font@27.2.2/dist/font-face.css" rel="stylesheet" type="text/css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: 'Vazir', sans-serif; 
            transition: background 0.3s, color 0.3s;
            padding: 0;
            margin: 0;
        }
        .dark { 
            background: linear-gradient(135deg, #1e0033 0%, #330066 100%); 
            color: #ffffff;
            min-height: 100vh;
        }
        .dark .container {
            padding: 10px;
        }
        .dark .card { 
            background: linear-gradient(135deg, #4b0082 0%, #6a1b9a 100%); 
            border: none; 
            border-radius: 15px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.3); 
            padding: 15px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .dark .table { 
            background: transparent; 
            color: #ffffff !important; 
            border: none;
            margin: 0;
            width: 100%;
        }
        .dark .table th, 
        .dark .table td { 
            color: #ffffff !important; 
            border: 1px solid rgba(255,255,255,0.1);
            padding: 10px 8px;
            font-size: 13px;
            text-align: center;
            vertical-align: middle;
        }
        .dark .thead-dark { 
            background: linear-gradient(135deg, #8a2be2 0%, #6a1b9a 100%) !important; 
            border-radius: 10px;
        }
        .dark .thead-dark th {
            border: none;
            padding: 12px 8px;
            font-weight: bold;
        }
        .dark .btn { 
            border-radius: 8px !important; 
            padding: 6px 12px;
            margin: 2px;
            font-size: 12px;
            border: none;
        }
        .dark .btn-warning { 
            background: #ffc107; 
            color: #000;
        }
        .dark .btn-info { 
            background: #17a2b8; 
            color: #fff;
        }
        .dark .btn-danger { 
            background: #dc3545; 
            color: #fff;
        }
        .dark .badge { 
            border-radius: 10px; 
            padding: 6px 10px;
            font-size: 12px;
        }
        .dark .badge-success { 
            background: #28a745; 
        }
        .dark .badge-danger { 
            background: #dc3545; 
        }
        
        /* Light Theme Styles */
        .light { 
            background: linear-gradient(135deg, #f0f4ff 0%, #d9e2ff 100%); 
            color: #000000; 
            min-height: 100vh;
        }
        .light .card { 
            background: #ffffff; 
            border: none; 
            border-radius: 15px; 
            box-shadow: 0 4px 16px rgba(0,0,0,0.1); 
            padding: 15px;
            margin-bottom: 20px;
        }
        .light .table { 
            background: #fff; 
            color: #000; 
            border: none;
        }
        .light .thead-dark { 
            background: #343a40; 
            border-radius: 10px;
        }
        .light .gauge-label { 
            color: #000000 !important; 
        }
        .light .gauge-label span { 
            color: #000000 !important; 
        }
        .light .search-box {
            background: #ffffff;
            border: 1px solid #ddd;
            color: #000000;
        }
        .light .search-box::placeholder {
            color: #666;
        }
        
        .navbar { 
            background: linear-gradient(135deg, #4b0082 0%, #8a2be2 100%); 
            box-shadow: 0 4px 12px rgba(0,0,0,0.2); 
            padding: 12px 0;
        }
        .nav-link { 
            color: white !important; 
            font-weight: bold;
            border-radius: 8px;
            margin: 0 5px;
            padding: 8px 15px !important;
        }
        
        .table-responsive {
            border-radius: 10px;
            overflow: hidden;
        }
        
        .btn-toggle { 
            background: #6f42c1; 
            border-radius: 8px; 
            padding: 8px 15px; 
        }
        .add-user-btn { 
            background: #28a745; 
            border-radius: 8px; 
            padding: 8px 15px; 
        }
        
        .gauge { 
            height: 120px; 
            position: relative; 
        }
        .row-gauges { 
            margin-bottom: 20px; 
        }
        .gauge-label { 
            position: absolute; 
            top: 50%; 
            left: 50%; 
            transform: translate(-50%, -50%); 
            text-align: center; 
            font-size: 12px; 
        }
        .gauge-label span { 
            display: block; 
            font-size: 20px; 
            font-weight: bold; 
        }
        
        .chart-container {
            height: 80px;
            width: 100%;
        }
        
        .action-buttons {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        
        .action-buttons .btn {
            width: 100%;
        }
        
        .search-container {
            margin-bottom: 20px;
        }
        .search-box {
            border-radius: 25px;
            padding: 10px 20px;
            border: 1px solid rgba(255,255,255,0.3);
            background: rgba(255,255,255,0.1);
            color: white;
            width: 100%;
        }
        .dark .search-box {
            background: rgba(255,255,255,0.1);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
        }
        .dark .search-box::placeholder {
            color: rgba(255,255,255,0.7);
        }
        .search-btn {
            border-radius: 25px;
            padding: 10px 25px;
        }
        
        /* Fix for table responsiveness */
        @media (max-width: 768px) {
            .table-responsive {
                font-size: 12px;
            }
            .dark .table th, 
            .dark .table td {
                padding: 6px 4px;
                font-size: 11px;
            }
            .action-buttons {
                flex-direction: row;
                flex-wrap: wrap;
            }
            .action-buttons .btn {
                flex: 1;
                min-width: 60px;
            }
        }
    </style>
</head>
<body class="{{ theme }}">
    <nav class="navbar navbar-expand-lg navbar-dark">
        <a class="navbar-brand" href="#"><i class="fas fa-shield-virus"></i> GUARD VPN</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link add-user-btn" href="{{ url_for('add_user') }}"><i class="fas fa-user-plus"></i> اضافه کردن یوزر جدید</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link btn-toggle" href="{{ url_for('toggle_theme') }}"><i class="fas fa-moon"></i> تغییر تم</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link btn-danger" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> خروج</a>
                </li>
            </ul>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="card">
            <div class="card-body">
                <h2 class="text-center mb-4"><i class="fas fa-users-cog"></i> نظارت بر کاربران</h2>
                
                <!-- Search Box -->
                <div class="search-container">
                    <form method="GET" action="{{ url_for('dashboard') }}" class="form-inline justify-content-center">
                        <div class="input-group" style="width: 100%; max-width: 400px;">
                            <input type="text" name="search" class="form-control search-box" placeholder="جستجوی کاربر..." value="{{ search_query }}">
                            <div class="input-group-append">
                                <button class="btn btn-primary search-btn" type="submit">
                                    <i class="fas fa-search"></i> جستجو
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
                
                <div class="row row-gauges">
                    <div class="col-md-3 col-6 mb-3">
                        <div class="position-relative">
                            <canvas id="cpuGauge" class="gauge"></canvas>
                            <div class="gauge-label">
                                <span>{{ stats.cpu | round(1) }}%</span>
                                CPU
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6 mb-3">
                        <div class="position-relative">
                            <canvas id="memoryGauge" class="gauge"></canvas>
                            <div class="gauge-label">
                                <span>{{ stats.memory | round(1) }}%</span>
                                RAM
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6 mb-3">
                        <div class="position-relative">
                            <canvas id="diskGauge" class="gauge"></canvas>
                            <div class="gauge-label">
                                <span>{{ stats.disk | round(1) }}%</span>
                                هارد
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6 mb-3">
                        <div class="position-relative">
                            <canvas id="trafficGauge" class="gauge"></canvas>
                            <div class="gauge-label">
                                <span>{{ stats.traffic | round(1) }}%</span>
                                ترافیک
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="table-responsive">
                    <table class="table table-striped table-bordered">
                        <thead class="thead-dark">
                            <tr>
                                <th>نام کاربری</th>
                                <th>آنلاین</th>
                                <th>وضعیت</th>
                                <th>جلسه فعلی</th>
                                <th>7 روز گذشته</th>
                                <th>30 روز گذشته</th>
                                <th>کل</th>
                                <th>نمودار 30 روزه</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for user in data %}
                            <tr>
                                <td><strong>{{ user.username }}</strong></td>
                                <td>
                                    {% if user.online %}
                                        <span class="badge badge-success"><i class="fas fa-check-circle"></i> بله</span>
                                    {% else %}
                                        <span class="badge badge-danger"><i class="fas fa-times-circle"></i> خیر</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if user.active %}
                                        <span class="badge badge-success">فعال</span>
                                    {% else %}
                                        <span class="badge badge-danger">غیرفعال</span>
                                    {% endif %}
                                </td>
                                <td>{{ user.current }}</td>
                                <td>{{ user.week }}</td>
                                <td>{{ user.month }}</td>
                                <td>{{ user.total }}</td>
                                <td>
                                    <div class="chart-container">
                                        <canvas id="chart_{{ user.uid }}"></canvas>
                                    </div>
                                </td>
                                <td>
                                    <div class="action-buttons">
                                        <a href="{{ url_for('toggle_active', username=user.username) }}" class="btn btn-warning btn-sm">
                                            <i class="fas fa-toggle-on"></i> وضعیت
                                        </a>
                                        <a href="{{ url_for('edit_user', username=user.username) }}" class="btn btn-info btn-sm">
                                            <i class="fas fa-edit"></i> ویرایش
                                        </a>
                                        <a href="{{ url_for('delete_user', username=user.username) }}" class="btn btn-danger btn-sm" onclick="return confirm('آیا مطمئن هستید؟');">
                                            <i class="fas fa-trash"></i> حذف
                                        </a>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    
    <script>
        // Create gauge charts
        function createGauge(id, value) {
            var data = {
                datasets: [{
                    data: [value, 100 - value],
                    backgroundColor: ['#28a745', 'rgba(255,255,255,0.2)'],
                    borderWidth: 0
                }]
            };
            var config = {
                type: 'doughnut',
                data: data,
                options: {
                    cutout: '70%',
                    responsive: true,
                    plugins: {
                        legend: { display: false },
                        tooltip: { enabled: false }
                    }
                }
            };
            new Chart(document.getElementById(id), config);
        }

        createGauge('cpuGauge', {{ stats.cpu }});
        createGauge('memoryGauge', {{ stats.memory }});
        createGauge('diskGauge', {{ stats.disk }});
        createGauge('trafficGauge', {{ stats.traffic }});

        // Create user charts
        {% for user in data %}
        var ctx{{ user.uid }} = document.getElementById('chart_{{ user.uid }}').getContext('2d');
        new Chart(ctx{{ user.uid }}, {
            type: 'line',
            data: {
                labels: {{ user['labels'] | tojson }},
                datasets: [{
                    label: 'ترافیک',
                    data: {{ user['values'] | tojson }},
                    borderColor: 'rgba(138, 43, 226, 1)',
                    backgroundColor: 'rgba(138, 43, 226, 0.1)',
                    borderWidth: 2,
                    pointRadius: 1,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { display: false },
                    y: { 
                        display: false,
                        beginAtZero: true
                    }
                }
            }
        });
        {% endfor %}
    </script>
</body>
</html>
EOF
simulate_progress 78 80

echo -e "${YELLOW}Setting up iptables chains...${NC}"
cat > setup_iptables.sh <<EOF
#!/bin/sh
# Flush existing user chains (careful, this may affect other rules)
users=\$(getent passwd | awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$3}')
for uid in \$users; do
  out_chain="USER_OUT_\$uid"
  in_chain="USER_IN_\$uid"
  iptables -D OUTPUT -m owner --uid-owner \$uid -j \$out_chain 2>/dev/null
  iptables -F \$out_chain 2>/dev/null
  iptables -X \$out_chain 2>/dev/null
  iptables -N \$out_chain
  iptables -A \$out_chain -j RETURN
  iptables -A OUTPUT -m owner --uid-owner \$uid -j \$out_chain
  iptables -D INPUT -m owner --uid-owner \$uid -j \$in_chain 2>/dev/null
  iptables -F \$in_chain 2>/dev/null
  iptables -X \$in_chain 2>/dev/null
  iptables -N \$in_chain
  iptables -A \$in_chain -j RETURN
  iptables -A INPUT -m owner --uid-owner \$uid -j \$in_chain
done
EOF
chmod +x setup_iptables.sh
./setup_iptables.sh
simulate_progress 80 85

echo -e "${YELLOW}Saving iptables rules...${NC}"
iptables-save > /etc/iptables/rules.v4
simulate_progress 85 90

echo -e "${YELLOW}Setting up daily cron job to save traffic data...${NC}"
cat > /etc/cron.daily/save_traffic <<EOF
#!/bin/sh
cd /opt/traffic_panel
python3 - <<PYEOF
import sqlite3
import subprocess
from datetime import date
conn = sqlite3.connect('traffic.db')
cursor = conn.execute('SELECT uid FROM users')
today = date.today().strftime('%Y-%m-%d')
for row in cursor:
    uid = row[0]
    out_chain = f"USER_OUT_{uid}"
    in_chain = f"USER_IN_{uid}"
    bytes_out = 0
    bytes_in = 0
    try:
        output = subprocess.check_output(f"iptables -L {out_chain} -v -n -x 2>/dev/null", shell=True).decode()
        lines = output.split('\n')
        if len(lines) > 2 and lines[2].strip():
            bytes_out = int(lines[2].split()[1])
        subprocess.call(f"iptables -Z {out_chain} 2>/dev/null", shell=True)
    except:
        pass
    try:
        output = subprocess.check_output(f"iptables -L {in_chain} -v -n -x 2>/dev/null", shell=True).decode()
        lines = output.split('\n')
        if len(lines) > 2 and lines[2].strip():
            bytes_in = int(lines[2].split()[1])
        subprocess.call(f"iptables -Z {in_chain} 2>/dev/null", shell=True)
    except:
        pass
    if bytes_out > 0 or bytes_in > 0:
        conn.execute('INSERT OR REPLACE INTO usage (date, uid, bytes_out, bytes_in) VALUES (?, ?, ?, ?)', (today, uid, bytes_out, bytes_in))
conn.commit()
conn.close()
PYEOF
EOF
chmod +x /etc/cron.daily/save_traffic
simulate_progress 90 95

echo -e "${YELLOW}Creating systemd service for the panel...${NC}"
cat > /etc/systemd/system/traffic_panel.service <<EOF
[Unit]
Description=Traffic Monitoring Panel
After=network.target

[Service]
User=root
WorkingDirectory=/opt/traffic_panel
ExecStart=/usr/bin/python3 /opt/traffic_panel/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl stop traffic_panel 2>/dev/null || true
systemctl start traffic_panel
systemctl enable traffic_panel
simulate_progress 95 100

echo -e "${BLUE}==========================================${NC}"
echo -e "${GREEN}Installation complete!${NC}"
echo -e "${BLUE}=======================================${NC}"
echo ""
echo -e "${YELLOW}Access it via:${NC} ${GREEN}http://${IP}:$PORT/${NC}"
echo -e "${YELLOW}Username:${NC} ${GREEN}${ADMIN_USER}${NC}"
echo -e "${YELLOW}Password:${NC} ${GREEN}${ADMIN_PASS}${NC}"
echo ""
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}✓ Search box added for filtering users${NC}"
echo -e "${GREEN}✓ Fixed light theme text colors (CPU, RAM, Disk, Traffic now black in light mode)${NC}"
echo -e "${GREEN}✓ Now monitors both incoming and outgoing traffic per user${NC}"
echo -e "${GREEN}✓ Online status based on running processes${NC}"
echo -e "${GREEN}✓ Professional design with dark/light themes${NC}"
echo -e "${GREEN}✓ System monitoring gauges${NC}"
echo -e "${GREEN}✓ User management with limits and expiration${NC}"

echo -e "${GREEN}"
figlet "GUARDNET VPN"
echo "POWER BY LOCALVPS"
echo -e "${NC}"