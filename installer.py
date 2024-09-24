import os
import subprocess
import getpass
import re

def install_packages():
    print("Installing required packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def setup_database():
    from app import db, User, Config
    from werkzeug.security import generate_password_hash

    print("Setting up the database...")
    db.create_all()

    # Admin kullanıcı oluştur
    admin_username = input("Enter admin username: ")
    admin_password = getpass.getpass("Enter admin password: ")
    admin_user = User(
        username=admin_username,
        password=generate_password_hash(admin_password, method='pbkdf2:sha256'),
        is_admin=True
    )
    db.session.add(admin_user)

    # Başlangıç kredi miktarını ayarla
    initial_credits = Config(key='initial_credits', value='5')
    db.session.add(initial_credits)

    db.session.commit()
    print("Database setup complete.")

def update_config():
    site_name = input("Enter site name: ")

    # app.py dosyasını güncelle
    with open("app.py", "r") as file:
        content = file.read()

    content = re.sub(r"app.config\['SECRET_KEY'\] = '.*'", f"app.config['SECRET_KEY'] = '{os.urandom(24).hex()}'", content)
    content = re.sub(r"app.config\['SQLALCHEMY_DATABASE_URI'\] = 'sqlite:///.*'", f"app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'", content)

    with open("app.py", "w") as file:
        file.write(content)

    # base.html dosyasını güncelle
    with open("templates/base.html", "r") as file:
        content = file.read()

    content = re.sub(r"<title>.*</title>", f"<title>{site_name}</title>", content)
    content = re.sub(r"<a href=\"{{ url_for\('index'\) }}\" class=\"text-white text-xl font-bold\">.*</a>", f"<a href=\"{{ url_for('index') }}\" class=\"text-white text-xl font-bold\">{site_name}</a>", content)

    with open("templates/base.html", "w") as file:
        file.write(content)

    print("Configuration updated.")

if __name__ == "__main__":
    import sys

    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt not found.")
        sys.exit(1)

    install_packages()
    setup_database()
    update_config()

    print("Installation complete. You can now run the application with 'python app.py'.")