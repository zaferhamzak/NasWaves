import sqlite3
import bcrypt
import getpass


# Veritabanı bağlantısı
def connect_db():
    return sqlite3.connect("user.db")


# Giriş yapma fonksiyonu
def login():
    conn = connect_db()
    cursor = conn.cursor()

    username = input("Kullanıcı adı: ").strip()
    password = getpass.getpass("Şifre: ")

    # Kullanıcıyı veritabanında kontrol et
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        stored_password, role = user
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            print(f"Giriş başarılı! Rolünüz: {role}")
            conn.close()
            return role  # Kullanıcının rolünü döndür
        else:
            print("Hatalı şifre!")
    else:
        print("Kullanıcı bulunamadı!")

    conn.close()
    return None  # Giriş başarısız


# Kullanıcı silme fonksiyonu (admin yetkisiyle)
def delete_user(role):
    if role != "admin":
        print("Sadece adminler kullanıcı silebilir!")
        return

    conn = connect_db()
    cursor = conn.cursor()

    # Silinecek kullanıcı adını al
    username_to_delete = input("Silmek istediğiniz kullanıcının adı: ").strip()

    # Kullanıcıyı veritabanında kontrol et
    cursor.execute("SELECT role FROM users WHERE username = ?", (username_to_delete,))
    user = cursor.fetchone()
    if not user:
        print("Bu isimde bir kullanıcı bulunamadı!")
    else:
        # Admin kullanıcılar da silinebilecek
        cursor.execute("DELETE FROM users WHERE username = ?", (username_to_delete,))
        conn.commit()
        print(f"{username_to_delete} adlı kullanıcı başarıyla silindi.")

    conn.close()

# Kullanıcı oluşturma fonksiyonu (admin yetkisiyle)
def create_user(role):
    if role != "admin":
        print("Sadece adminler yeni kullanıcı oluşturabilir!")
        return

    conn = connect_db()
    cursor = conn.cursor()

    # Yeni kullanıcı bilgilerini al
    username = input("Yeni kullanıcı adı: ").strip()
    password = getpass.getpass("Yeni kullanıcı şifresi: ")
    role = input("Yeni kullanıcı rolü (admin/user/visitor): ").strip()

    if role not in ["admin", "user", "visitor"]:
        print("Geçersiz rol seçimi!")
        conn.close()
        return

    # Şifreyi hash'le
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        # Kullanıcıyı ekle
        cursor.execute("""
        INSERT INTO users (username, password, role)
        VALUES (?, ?, ?)
        """, (username, hashed_password, role))
        conn.commit()
        print("Yeni kullanıcı başarıyla oluşturuldu.")
    except sqlite3.IntegrityError:
        print("Bu kullanıcı adı zaten mevcut!")
    finally:
        conn.close()


# Kullanıcıları listeleme fonksiyonu (admin yetkisiyle)
def list_users(role):
    if role != "admin":
        print("Sadece adminler kullanıcıları listeleyebilir!")
        return

    conn = connect_db()
    cursor = conn.cursor()

    # Tüm kullanıcıları listele
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()

    print("\nKullanıcı Listesi:")
    print("-" * 40)
    for user in users:
        print(f"ID: {user[0]}, Kullanıcı Adı: {user[1]}, Rol: {user[2]}")
    print("-" * 40)

    conn.close()


# Ana işlev
def main():
    print("Sisteme giriş yapın:")
    role = login()  # Kullanıcı giriş yapar

    if not role:
        print("Giriş başarısız. Program sonlandırılıyor.")
        return

    while True:
        print("\nSeçenekler:")
        print("1. Yeni kullanıcı oluştur")
        print("2. Kullanıcıları listele")
        print("3. Kullanıcı sil")
        print("4. Çıkış yap")
        choice = input("Seçiminizi yapın: ").strip()

        if choice == "1":
            create_user(role)  # Yeni kullanıcı oluşturma
        elif choice == "2":
            list_users(role)  # Kullanıcıları listeleme
        elif choice == "3":
            delete_user(role)  # Kullanıcı silme
        elif choice == "4":
            print("Çıkış Yapılıyor...")
            break
        else:
            print("Geçersiz seçim!")


# Programı başlat
if __name__ == "__main__":
    main()
