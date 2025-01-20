import logging
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import bcrypt

# Flask uygulamasını oluştur
app = Flask(__name__)
app.secret_key = '645118'  # Flash mesajları için

# Loglama yapılandırması
logging.basicConfig(level=logging.DEBUG,  # Log seviyesini ayarlayın
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(), logging.FileHandler("app.log")])  # Konsol ve dosya logları


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:  # Kullanıcı giriş yapmamışsa
            return redirect(url_for('login'))  # Giriş sayfasına yönlendir
        return f(*args, **kwargs)

    return decorated_function


# Veritabanı bağlantısı
def connect_db():
    return sqlite3.connect("database_and_menangement/user.db")


# Kullanıcı giriş işlemi
def check_user(username, password):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        stored_password, role = user
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            app.logger.info(f"Başarıyla giriş yapan kullanıcı: {username}, Rol: {role}")  # Başarı logu
            return role
        else:
            app.logger.warning(f"Hatalı şifre girişimi: {username}")  # Hatalı şifre logu
    else:
        app.logger.warning(f"Kullanıcı bulunamadı: {username}")  # Kullanıcı bulunamadı logu
    return None  # Kullanıcı yok ya da şifre yanlış


@app.route('/')
def home():
    app.logger.info("Ana sayfa yüklendi.")  # Ana sayfa yüklendi logu
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    app.logger.debug(f"Giriş denemesi: {username}")  # Giriş denemesi logu

    role = check_user(username, password)

    if role:
        session['username'] = username  # Giriş yapan kullanıcı adı
        session['role'] = role  # Giriş yapan kullanıcı rolü
        app.logger.info(f"{username} başarılı bir şekilde giriş yaptı.")  # Başarı logu
        return redirect(url_for('dashboard', role=role))  # Giriş başarılı
    else:
        flash('Kullanıcı adı veya şifre yanlış!', 'danger')  # Hata mesajı
        app.logger.error(f"{username} giriş hatası: Kullanıcı adı veya şifre yanlış.")  # Hata logu
        return redirect(url_for('home'))  # Hata durumunda tekrar giriş sayfasına yönlendir


@app.route('/dashboard/<role>')
@login_required
def dashboard(role):
    # Kullanıcı giriş yapmamışsa yönlendirilecek
    if session.get('role') != role:  # Kullanıcı rolü eşleşmiyorsa
        flash('Bu sayfaya erişiminiz yok!', 'danger')
        return redirect(url_for('home'))

    app.logger.info(f"Dashboard sayfası yüklendi. Rol: {role}")  # Dashboard yüklendi logu
    return f"Hoş geldiniz, {role}!"


@app.route('/logout')
def logout():
    session.pop('username', None)  # Kullanıcıyı oturumdan çıkar
    session.pop('role', None)  # Rol bilgisi de sıfırlanır
    flash('Çıkış yapıldı.', 'info')  # Çıkış mesajı
    return redirect(url_for('home'))  # Giriş sayfasına yönlendir


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
