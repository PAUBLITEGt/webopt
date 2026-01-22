from gevent import monkey
monkey.patch_all()

from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix
import imaplib
import email
from email.header import decode_header
import re
import html
import threading
import time
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
# Soporte para Proxy Inverso (Nginx)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Configuración de base de datos - Priorizar variables de entorno, caer a otp_user
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://otp_user:admin123@localhost:5432/otp_db')

socketio = SocketIO(
    app,
    async_mode="gevent",
    cors_allowed_origins="*"
)

def get_db_connection():
    """Manejo de re-intentos para la conexión a la base de datos."""
    for i in range(3):
        try:
            conn = psycopg2.connect(DATABASE_URL)
            return conn
        except Exception as e:
            print(f"Error conectando a la DB (intento {i+1}/3): {e}")
            time.sleep(2)
    return None

def get_accounts():
    conn = get_db_connection()
    if not conn: return []
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT email, app_password FROM accounts")
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows
    except: 
        if conn: conn.close()
        return []

def init_db():
    print("🛠️ INICIALIZANDO BASE DE DATOS AUTOMÁTICA...")
    conn = get_db_connection()
    if not conn:
        print("❌ No se pudo conectar a la DB para inicializar.")
        return
    
    try:
        conn.autocommit = True
        cur = conn.cursor()
        
        # 1. Asegurar esquema y permisos
        try:
            cur.execute("GRANT ALL ON SCHEMA public TO public")
        except: pass
        
        # 2. Creación automática de tablas (Unificado y Estandarizado)
        cur.execute('CREATE TABLE IF NOT EXISTS otps (id SERIAL PRIMARY KEY, sender TEXT, account TEXT, subject TEXT, code TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        cur.execute('CREATE TABLE IF NOT EXISTS accounts (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, app_password TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        cur.execute('CREATE TABLE IF NOT EXISTS admin_users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)')
        cur.execute('CREATE TABLE IF NOT EXISTS user_credentials (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, expires_at TIMESTAMP)')
        cur.execute('CREATE TABLE IF NOT EXISTS settings (id SERIAL PRIMARY KEY, key TEXT UNIQUE, value TEXT)')
        
        # 3. Crear administrador por defecto (Unificado)
        cur.execute("SELECT * FROM admin_users WHERE username = 'paudronixGt20p'")
        if not cur.fetchone():
            cur.execute("INSERT INTO admin_users (username, password) VALUES ('paudronixGt20p', 'paudronixADM20a')")
        
        # 4. Cargar cuentas por defecto si está vacío
        cur.execute("SELECT COUNT(*) FROM accounts")
        res = cur.fetchone()
        if res and res[0] == 0:
            default_accounts = [
                ("propaublite@gmail.com", "zczzcnpyhrzqbpgl"),
                ("paublutegt@gmail.com", "nvkvbiymuouxjmkf"),
                ("popupa083@gmail.com", "pcvyhpdrbrsyghok"),
                ("pakistepa254@gmail.com", "zzzhexfwvilikwwf")
            ]
            for e, p in default_accounts:
                cur.execute("INSERT INTO accounts (email, app_password) VALUES (%s, %s) ON CONFLICT DO NOTHING", (e, p))
        
        cur.close()
        conn.close()
        print("✅ SISTEMA AUTOMÁTICO LISTO")
    except Exception as e:
        if conn: conn.close()
        print(f"❌ Error crítico en DB: {e}")

def save_otp(sender, account, subject, code):
    conn = get_db_connection()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO otps (sender, account, subject, code) VALUES (%s, %s, %s, %s)", (sender, account, subject, code))
        conn.commit(); cur.close(); conn.close()
    except: 
        if conn: conn.close()

def get_history():
    conn = get_db_connection()
    if not conn: return []
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT sender, account, subject, code, timestamp FROM otps WHERE timestamp > NOW() - INTERVAL '1 hour' ORDER BY timestamp DESC LIMIT 50")
        rows = cur.fetchall(); cur.close(); conn.close()
        for row in rows:
            if row['timestamp']:
                local_time = row['timestamp'] + timedelta(hours=6)
                row['time'] = local_time.strftime("%I:%M %p")
            if 'timestamp' in row:
                del row['timestamp']
        return rows
    except: 
        if conn: conn.close()
        return []

def decode_mime_words(s):
    if not s: return ""
    parts = decode_header(s)
    decoded = ""
    for part, encoding in parts:
        if isinstance(part, bytes):
            try: decoded += part.decode(encoding or "utf-8", errors="ignore")
            except: decoded += part.decode("utf-8", errors="ignore")
        else: decoded += part
    return decoded

def strip_html_tags(text: str) -> str:
    if not text: return ""
    text = re.sub(r'(?is)<(script|style).*?>.*?(</\1>)', ' ', text)
    text = re.sub(r'(?s)<.*?>', ' ', text)
    text = html.unescape(text)
    return re.sub(r'\s+', ' ', text).strip()

def extract_otp_code(text: str, subject: str = ""):
    if not text: return None
    full_text = (text + " " + (subject or "")).replace("\n", " ").replace("-", " ")
    match = re.search(r"(?<!\d)(\d{4,8})(?!\d)", full_text)
    return match.group(1) if match else None

def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try: return strip_html_tags(part.get_payload(decode=True).decode(errors='ignore'))
                except: pass
    else:
        try: return strip_html_tags(msg.get_payload(decode=True).decode(errors='ignore'))
        except: pass
    return ""

def check_single_account(account, processed_otps, semaphore):
    with semaphore:
        email_addr, app_pass = account["email"], account["app_password"]
        mail = None
        # Sistema de re-intento IMAP
        for attempt in range(3):
            try:
                mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=15)
                mail.login(email_addr, app_pass)
                mail.select("INBOX", readonly=True)
                _, email_ids = mail.search(None, "ALL")
                ids = email_ids[0].split()
                if not ids: return
                
                for uid in reversed(ids[-5:]):
                    try:
                        res, msg_data = mail.fetch(uid, "(RFC822)")
                        if not msg_data or not msg_data[0] or not isinstance(msg_data[0][1], bytes): continue
                        import email as email_pkg
                        msg = email_pkg.message_from_bytes(msg_data[0][1])
                        import email.utils
                        email_date = msg.get("Date")
                        if not email_date: continue
                        parsed_date = email.utils.parsedate_to_datetime(email_date)
                        now_aware = datetime.now(parsed_date.tzinfo)
                        if (now_aware - parsed_date).total_seconds() > 600: continue 
                        real_email_time = (parsed_date + timedelta(hours=6)).strftime("%I:%M %p")
                        subject = decode_mime_words(msg.get("subject"))
                        sender = decode_mime_words(msg.get("from"))
                        body = get_email_body(msg)
                        otp = extract_otp_code(body, subject)
                        if otp:
                            otp_id = f"{sender}_{email_addr}_{otp}"
                            if otp_id not in processed_otps:
                                socketio.emit('new_otp', {'sender': sender, 'account': email_addr, 'subject': subject, 'code': otp, 'time': real_email_time})
                                save_otp(sender, email_addr, subject, otp)
                                processed_otps.add(otp_id)
                    except: pass
                break # Éxito, salir de re-intentos
            except Exception as e:
                print(f"Error en IMAP para {email_addr} (intento {attempt+1}/3): {e}")
                time.sleep(5)
            finally:
                if mail:
                    try: mail.logout()
                    except: pass
                    mail = None

def check_emails():
    print("🛰️ ESCANEANDO CORREOS...")
    processed_otps = set()
    conn = get_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("SELECT sender, account, code FROM otps ORDER BY timestamp DESC LIMIT 100")
            for r, a, c in cur.fetchall(): processed_otps.add(f"{r}_{a}_{c}")
            cur.close(); conn.close()
        except: 
            if conn: conn.close()
    
    semaphore = threading.Semaphore(10)
    while True:
        try:
            accounts = get_accounts()
            for account in accounts:
                t = threading.Thread(target=check_single_account, args=(account, processed_otps, semaphore))
                t.daemon = True
                t.start()
            time.sleep(10) # Pausa entre escaneos para estabilidad
        except Exception as e:
            print(f"Error en el loop principal de correos: {e}")
            time.sleep(10)

@app.route('/')
def index():
    if not session.get('user_logged_in') and not session.get('logged_in'):
        return render_template('login_choice.html')
    return render_template('index.html')

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        conn = get_db_connection()
        if not conn: return render_template('login_choice.html', error="Error de DB")
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM user_credentials WHERE username = %s AND password = %s", (u, p))
            user = cur.fetchone(); cur.close(); conn.close()
            if user:
                if user['expires_at'] and user['expires_at'] < datetime.now():
                    return render_template('login_choice.html', error="Su cuenta ha expirado.")
                session['user_logged_in'] = True
                return redirect(url_for('index'))
        except:
            if conn: conn.close()
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        conn = get_db_connection()
        if not conn: return redirect(url_for('index'))
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM admin_users WHERE username = %s AND password = %s", (u, p))
            user = cur.fetchone(); cur.close(); conn.close()
            if user: session['logged_in'] = True; return redirect(url_for('admin'))
        except:
            if conn: conn.close()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if not session.get('logged_in'): return redirect(url_for('login'))
    conn = get_db_connection()
    if not conn: return "Error de base de datos"
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM user_credentials")
        users = cur.fetchall(); cur.close(); conn.close()
        return render_template('admin.html', accounts=get_accounts(), users=users)
    except:
        if conn: conn.close()
        return "Error al cargar datos"

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if not session.get('logged_in'): return redirect(url_for('login'))
    u, p, days = request.form.get('username'), request.form.get('password'), request.form.get('days')
    if u and p:
        conn = get_db_connection()
        if not conn: return redirect(url_for('admin'))
        try:
            cur = conn.cursor()
            expires_at = datetime.now() + timedelta(days=int(days)) if days else datetime.now() + timedelta(days=30)
            cur.execute("INSERT INTO user_credentials (username, password, expires_at) VALUES (%s, %s, %s) ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, expires_at = EXCLUDED.expires_at", (u, p, expires_at))
            conn.commit(); cur.close(); conn.close()
        except:
            if conn: conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    if not session.get('logged_in'): return redirect(url_for('login'))
    u = request.form.get('username')
    if u:
        conn = get_db_connection()
        if not conn: return redirect(url_for('admin'))
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM user_credentials WHERE username = %s", (u,))
            conn.commit(); cur.close(); conn.close()
        except:
            if conn: conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/add', methods=['POST'])
def add_account():
    if not session.get('logged_in'): return redirect(url_for('login'))
    e, p = request.form.get('email'), request.form.get('app_password')
    if e and p:
        conn = get_db_connection()
        if not conn: return redirect(url_for('admin'))
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO accounts (email, app_password) VALUES (%s, %s) ON CONFLICT (email) DO UPDATE SET app_password = EXCLUDED.app_password", (e, p))
            conn.commit(); cur.close(); conn.close()
        except:
            if conn: conn.close()
    return redirect(url_for('admin'))

@socketio.on('ping_test')
def handle_ping(data): socketio.emit('pong_response', {'message': 'Conexión OK'})

@socketio.on('get_history')
def handle_history(): socketio.emit('history_data', get_history())

if __name__ == '__main__':
    init_db()
    threading.Thread(target=check_emails, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5000, log_output=True, use_reloader=False)
