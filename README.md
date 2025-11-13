# 🛡️ GUARDNET VPN Panel

## Advanced VPN User Management & Monitoring System

![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Ubuntu-lightgrey.svg)

Professional web panel for VPN user management, traffic monitoring, and system administration

## ✨ Features

### 👥 User Management
- ✅ Create new VPN users with traffic limits and expiration
- ✅ Edit and delete existing users
- ✅ Activate/deactivate users
- ✅ Advanced user search functionality

### 📊 Traffic Monitoring
- ✅ Real-time incoming/outgoing traffic monitoring per user
- ✅ Interactive 30-day traffic charts
- ✅ Session, weekly, monthly, and total usage statistics
- ✅ Online user detection

### 🖥️ System Monitoring
- ✅ Real-time CPU, RAM, and Disk usage monitoring
- ✅ Total server traffic consumption percentage
- ✅ Beautiful gauge charts

### 🎨 Professional Design
- ✅ Fully responsive (mobile & desktop)
- ✅ Dark/Light theme toggle
- ✅ Persian/English interface
- ✅ Interactive Chart.js graphs

### 🔒 Security & Automation
- ✅ Admin authentication
- ✅ Automatic traffic limit enforcement
- ✅ Automatic user expiration
- ✅ Detailed traffic logging

## 🚀 Quick Installation

### Prerequisites
- Ubuntu Server (18.04 or higher)
- Root access
- Internet connection

### One-Command Installation

```bash
# Download and run the installation script
wget -O install_panel.sh https://raw.githubusercontent.com/localvps/guardvpn/main/install_panel.sh
sudo bash install_panel.sh
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/localvps/guardvpn.git
cd guardvpn

# Run the installation script
chmod +x install_panel.sh
sudo ./install_panel.sh
```

### Configuration

During installation, you'll be prompted for:

- **Panel Port** (default: 6565)
- **Admin Username** (default: admin)
- **Admin Password** (default: admin123)

## 📖 Usage Guide

### Accessing the Panel

1. Open your web browser
2. Navigate to:
   ```
   http://YOUR_SERVER_IP:PORT
   ```
3. Login with your admin credentials

### Creating VPN Users

1. Click **"Add New User"** button
2. Fill in user information:
   - Username
   - Password
   - Traffic limit (MB)
   - Expiration days
3. Click **"Add"** to create user

### Managing Users

- **Edit**: Click edit button next to user
- **Delete**: Click delete button (with confirmation)
- **Toggle Status**: Activate/deactivate users

### Searching Users

- Use the search box at the top of the panel
- Type username to filter
- Real-time filtering as you type

### Monitoring Traffic

- **Current Session**: Traffic used in current session
- **7 Days**: Total traffic in last 7 days
- **30 Days**: Total traffic in last 30 days
- **Total**: All-time traffic consumption

## 🛠️ Advanced Configuration

### Changing Port

```bash
# Edit service file
sudo nano /etc/systemd/system/traffic_panel.service

# Change port in ExecStart line
ExecStart=/usr/bin/python3 /opt/traffic_panel/app.py --port 8080

# Reload and restart service
sudo systemctl daemon-reload
sudo systemctl restart traffic_panel
```

### Database Backup

```bash
# Backup database
sudo cp /opt/traffic_panel/traffic.db /backup/traffic_backup.db

# Restore database
sudo cp /backup/traffic_backup.db /opt/traffic_panel/traffic.db
sudo chown root:root /opt/traffic_panel/traffic.db
sudo systemctl restart traffic_panel
```

### Service Management

```bash
# Check service status
sudo systemctl status traffic_panel

# View service logs
sudo journalctl -u traffic_panel -f

# Restart service
sudo systemctl restart traffic_panel
```

### iptables Management

```bash
# View user rules
sudo iptables -L -v -n | grep USER_

# Reset user traffic counters
sudo iptables -Z USER_OUT_1001
sudo iptables -Z USER_IN_1001
```

## 📊 Database Structure

### users table
```sql
CREATE TABLE users (
    uid INTEGER PRIMARY KEY,
    username TEXT,
    limit_bytes INTEGER DEFAULT 0,
    expiration_date TEXT,
    active INTEGER DEFAULT 1
);
```

### usage table
```sql
CREATE TABLE usage (
    date TEXT,
    uid INTEGER,
    bytes_out INTEGER,
    bytes_in INTEGER,
    PRIMARY KEY (date, uid)
);
```

## 🔧 Troubleshooting

### Common Issues

**Panel not accessible**
```bash
# Check service status
sudo systemctl status traffic_panel

# Check port availability
sudo netstat -tlnp | grep PORT
```

**Traffic not showing**
```bash
# Check iptables rules
sudo iptables -L -v -n

# Restart service
sudo systemctl restart traffic_panel
```

**New users not appearing**
```bash
# Manual user update
cd /opt/traffic_panel
python3 -c "from app import update_users; update_users()"
```

### Logging

```bash
# View application logs
sudo tail -f /opt/traffic_panel/app.log

# View system logs
sudo journalctl -u traffic_panel -f
```

## 🤝 Contributing

We welcome contributions! To contribute:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


### Bug Reports

Please report bugs and issues via [GitHub Issues](https://github.com/localvps/guardvpn/issues).

## 🙏 Acknowledgments

Thanks to the open-source community and all developers who contributed to improving this project.

**Main Developer**: LOCALVPS Team

---

<div align="center">

**Made with ❤️ by LOCALVPS **

![GUARDNET VPN](https://via.placeholder.com/150x50/8a2be2/ffffff?text=GUARDNET+VPN)

[**Install Now**](https://github.com/localvps/guardvpn/blob/main/install_panel.sh) | [**View on GitHub**](https://github.com/localvps/guardvpn)

</div>

## 🔗 Quick Install Command

```bash
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/localvps/guardvpn/main/install_panel.sh)"
```

This README provides comprehensive documentation for the GUARDNET VPN panel with:
- Complete feature overview
- Step-by-step installation guide
- Usage instructions
- Advanced configuration options
- Troubleshooting guide
- Professional structure suitable for GitHub

The installation script is available at: https://github.com/localvps/guardvpn/blob/main/install_panel.sh
