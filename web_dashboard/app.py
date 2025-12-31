import os
import json
import subprocess
import time
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash

app = Flask(__name__)
app.secret_key = 'fsociety_dat_nids_key'

# ================= PATH CONFIGURATION =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "Basic_data")

FILES = {
    'alerts':   os.path.join(DATA_DIR, "logs/alerts.json"),
    'users':    os.path.join(DATA_DIR, "JSON/users.json"),
    'router':   os.path.join(DATA_DIR, "JSON/Router_details.json"),
    'restrict': os.path.join(DATA_DIR, "JSON/Restrict_web.json"),
    'trusted':  os.path.join(DATA_DIR, "JSON/Trusted_Users.json"),
    'pcap':     os.path.join(DATA_DIR, "logs/web_session.pcap"),
    'email':    os.path.join(DATA_DIR, "JSON/email.json"),
    'creds':    os.path.join(DATA_DIR, "JSON/admin_creds.json")
}

capture_process = None

# ================= HELPER FUNCTIONS =================
def load_json(key):
    """Reads JSON files safely with strict default types"""
    path = FILES[key]
    
    # 1. Define Strict Defaults
    # 'users' and 'router' MUST be dictionaries {}. Others are lists [].
    defaults = {
        'router': {},
        'users': {},      # <--- FIX: This was defaulting to [] before
        'email': {"email": ""},
        'creds': {"username": "admin", "password": "nids2025"},
        'alerts': [],
        'restrict': [],
        'trusted': []
    }
    
    default_val = defaults.get(key, [])

    # 2. Check if file exists
    if not os.path.exists(path):
        return default_val

    # 3. Try to read
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            # If file is empty/null, return default
            if data is None: 
                return default_val
            return data
    except:
        # On any error (permission, race condition, corrupt file), return default
        return default_val

def save_json(key, data):
    try:
        with open(FILES[key], 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving {key}: {e}")

# ================= ROUTES =================

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        creds = load_json('creds')
        if request.form['username'] == creds.get('username') and request.form['password'] == creds.get('password'):
            session['logged_in'] = True
            session['user'] = creds.get('username')
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'): return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not session.get('logged_in'): return redirect(url_for('login'))
    
    creds = load_json('creds')
    email_data = load_json('email')
    msg = ""
    msg_type = ""

    if request.method == 'POST':
        current_pass = request.form.get('current_password')
        new_user = request.form.get('username')
        new_pass = request.form.get('new_password')
        new_email = request.form.get('email')

        if current_pass != creds.get('password'):
            msg = "Error: Current password incorrect!"
            msg_type = "red"
        else:
            changes_made = False
            if new_user and new_user != creds['username']:
                creds['username'] = new_user
                changes_made = True
            if new_pass and new_pass.strip() != "":
                creds['password'] = new_pass
                changes_made = True
            
            if changes_made:
                save_json('creds', creds)
                session['user'] = creds['username']

            if new_email and new_email != email_data.get('email'):
                email_data['email'] = new_email
                save_json('email', email_data)

            msg = "Success: Profile updated successfully!"
            msg_type = "#00ff41"

    return render_template('settings.html', 
                           user=creds.get('username'), 
                           email=email_data.get('email'),
                           msg=msg, 
                           msg_type=msg_type)

@app.route('/alerts')
def alerts():
    if not session.get('logged_in'): return redirect(url_for('login'))
    alerts_data = load_json('alerts')
    if isinstance(alerts_data, list):
        alerts_data = alerts_data[::-1]
    return render_template('alerts.html', alerts=alerts_data)

@app.route('/iam', methods=['GET', 'POST'])
def iam():
    if not session.get('logged_in'): return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_router':
            data = {"ssid": request.form['ssid'], "mac": request.form['mac'], "channel": request.form['channel']}
            save_json('router', data)

        elif action == 'add_restrict':
            site = request.form['site']
            current = load_json('restrict')
            if site and site not in current:
                current.append(site)
                save_json('restrict', current)

        elif action == 'add_trusted':
            mac = request.form['mac']
            current = load_json('trusted')
            exists = False
            for u in current:
                u_mac = u.get('mac') if isinstance(u, dict) else u
                if u_mac == mac: exists = True
            if not exists:
                current.append({"mac": mac, "added": time.ctime()})
                save_json('trusted', current)

        elif action == 'remove_trusted':
            mac_to_remove = request.form.get('mac_to_remove')
            current = load_json('trusted')
            new_list = [u for u in current if (u.get('mac') if isinstance(u, dict) else u) != mac_to_remove]
            save_json('trusted', new_list)

    return render_template('iam.html', 
                           users=load_json('users'),
                           router=load_json('router'),
                           restricted=load_json('restrict'),
                           trusted=load_json('trusted'))

@app.route('/instructions')
def instructions():
    if not session.get('logged_in'): return redirect(url_for('login'))
    return render_template('instructions.html')

@app.route('/data', methods=['GET', 'POST'])
def data():
    if not session.get('logged_in'): return redirect(url_for('login'))
    global capture_process
    
    status = "STOPPED"
    if capture_process and capture_process.poll() is None: status = "RUNNING"

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'start' and status == "STOPPED":
            capture_process = subprocess.Popen(["sudo", "tcpdump", "-i", "eth0", "-w", FILES['pcap']])
            status = "RUNNING"
        elif action == 'stop' and status == "RUNNING":
            subprocess.run(["sudo", "pkill", "-f", f"tcpdump.*{FILES['pcap']}"])
            if capture_process: capture_process.terminate()
            status = "STOPPED"
        elif action == 'download':
            if os.path.exists(FILES['pcap']): return send_file(FILES['pcap'], as_attachment=True)
        elif action == 'delete':
            if os.path.exists(FILES['pcap']): os.remove(FILES['pcap'])

    return render_template('capture.html', status=status, file_exists=os.path.exists(FILES['pcap']))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
