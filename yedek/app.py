import os
import sys
import string
import random
print("Current working directory:", os.getcwd())
print("Python path:", sys.path)

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, RegistrationForm, GenerateForm, AdminLoginForm, PaymentNotificationForm
import pandas as pd
import numpy as np
from geopy.distance import geodesic
import io
import zipfile
import re
from flask import jsonify
from flask import send_file, abort
import logging
from celery import Celery
from flask_caching import Cache
from datetime import datetime, timedelta
from sqlalchemy import func
from flask import send_from_directory
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gizli_anahtar'

# Uygulama klasörünün yolunu alın
basedir = os.path.abspath(os.path.dirname(__file__))

# Veritabanı yolunu ayarlayın
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SQLAlchemy nesnesini oluşturun
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# User modelini tanımlayın
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    credits = db.Column(db.Integer, default=5)
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

# User modelinden sonra, diğer modelleri tanımlamadan önce ekleyin:

class Coordinate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    center_lat = db.Column(db.Float, nullable=False)
    center_long = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, nullable=False)
    num_points = db.Column(db.Integer, nullable=False)
    strategy = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('coordinates', lazy=True))

class PaymentNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    credits = db.Column(db.Integer, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    transaction_code = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('payment_notifications', lazy=True))

    @staticmethod
    def generate_transaction_code():
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

# Yeni model ekleyin
class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Başlangıç kredi miktarını Config tablosundan al
            initial_credits_config = Config.query.filter_by(key='initial_credits').first()
            initial_credits = int(initial_credits_config.value) if initial_credits_config else 5

            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            new_user = User(
                username=form.username.data, 
                password=hashed_password,
                credits=initial_credits  # Başlangıç kredi miktarını burada kullan
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('This username is already taken. Please choose a different one.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {str(e)}', 'danger')
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def generate_random_coordinates(center_lat, center_long, radius, num_points):
    points = []
    for _ in range(num_points):
        angle = random.uniform(0, 360)
        distance_from_center = random.uniform(0, radius)
        destination = geodesic(kilometers=distance_from_center).destination((center_lat, center_long), angle)
        points.append((destination.latitude, destination.longitude))
    return points

@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    form = GenerateForm()
    if form.validate_on_submit():
        num_points = form.num_points.data
        required_credits = (num_points - 1) // 20000 + 1  # Her 20.000 koordinat için 1 kredi

        if current_user.credits >= required_credits:
            center_lat = form.center_lat.data
            center_long = form.center_long.data
            radius = form.radius.data
            name = form.name.data
            description = form.description.data
            keywords = form.keywords.data.split(',')
            website = form.website.data
            phone_number = form.phone_number.data
            strategy = form.strategy.data

            if strategy == 'circle':
                coordinates = generate_concentric_circles(center_lat, center_long, radius, num_points)
            else:  # Fill strategy
                coordinates = generate_random_coordinates(center_lat, center_long, radius, num_points)
            
            # Anahtar kelimeleri eşit şekilde tekrarla
            keywords_repeated = (keywords * (num_points // len(keywords) + 1))[:num_points]

            # Excel için veriyi hazırla
            data = {
                "Name": [name] * num_points,
                "Description": [description] * num_points,
                "Keyword": keywords_repeated,
                "Website": [website] * num_points,
                "Phone Number": [phone_number] * num_points,
                "Latitude": [coord[0] for coord in coordinates],
                "Longitude": [coord[1] for coord in coordinates]
            }
            df = pd.DataFrame(data)

            # Excel dosyalarını oluştur ve zip dosyasına ekle
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
                for i in range(0, num_points, 2000):
                    chunk = df.iloc[i:i+2000]
                    excel_buffer = io.BytesIO()
                    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
                        chunk.to_excel(writer, index=False, sheet_name='Coordinates')
                    excel_buffer.seek(0)
                    zip_file.writestr(f'coordinates_{name}_{i//2000+1}.xlsx', excel_buffer.getvalue())

            zip_buffer.seek(0)

            # Kredi düşürme
            current_user.credits -= required_credits
            db.session.commit()

            # Koordinat bilgilerini kaydet
            new_coordinate = Coordinate(
                user_id=current_user.id,
                name=name,
                description=description,
                center_lat=center_lat,
                center_long=center_long,
                radius=radius,
                num_points=num_points,
                strategy=strategy
            )
            db.session.add(new_coordinate)
            db.session.commit()

            flash(f'{required_credits} credits used. {num_points} coordinates generated.', 'success')

            # Zip dosyasını indir
            return send_file(
                zip_buffer,
                download_name=f'coordinates_{name}.zip',
                as_attachment=True,
                mimetype='application/zip'
            )

        else:
            flash(f'You do not have enough credits! {required_credits} credits required.', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')
    return render_template('generate.html', form=form)

def generate_concentric_circles(center_lat, center_long, max_radius, total_points):
    points = []
    num_circles = (total_points - 1) // 2000 + 1
    points_per_circle = min(total_points, 2000)
    radius_step = max_radius / num_circles

    for i in range(num_circles):
        current_radius = (i + 1) * radius_step
        circle_points = generate_circle_coordinates(center_lat, center_long, current_radius, points_per_circle)
        points.extend(circle_points)

    return points[:total_points]  # Tam olarak istenen sayıda nokta döndür

def generate_circle_coordinates(center_lat, center_long, radius, num_points):
    points = []
    angle_step = 360 / num_points
    for i in range(num_points):
        angle = angle_step * i
        destination = geodesic(kilometers=radius).destination((center_lat, center_long), angle)
        points.append((destination.latitude, destination.longitude))
    return points

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        if form.username.data == 'admin' and form.password.data == '187400Baran*':
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                admin_user = User(
                    username='admin',
                    password=generate_password_hash('187400Baran*', method='pbkdf2:sha256'),
                    is_admin=True
                )
                db.session.add(admin_user)
                db.session.commit()
            login_user(admin_user)
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/admin/panel', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    notifications = PaymentNotification.query.filter_by(status='pending').order_by(PaymentNotification.created_at.desc()).all()
    
    initial_credits = Config.query.filter_by(key='initial_credits').first()
    if not initial_credits:
        initial_credits = Config(key='initial_credits', value='5')
        db.session.add(initial_credits)
        db.session.commit()

    if request.method == 'POST':
        new_initial_credits = request.form.get('initial_credits')
        initial_credits.value = new_initial_credits
        db.session.commit()
        flash('Initial credit amount updated.', 'success')

    return render_template('admin_panel.html', users=users, notifications=notifications, initial_credits=initial_credits.value)

@app.route('/admin/update_credits/<int:user_id>', methods=['POST'])
@login_required
def update_credits(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    new_credits = int(request.form['credits'])
    user.credits = new_credits
    db.session.commit()
    flash(f"{user.username}'s credits updated.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/approve_payment/<int:notification_id>', methods=['POST'])
@login_required
def admin_approve_payment(notification_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))
    
    notification = PaymentNotification.query.get_or_404(notification_id)
    user = User.query.get(notification.user_id)
    
    user.credits += notification.credits
    notification.status = 'approved'
    
    db.session.commit()
    
    flash(f'{notification.credits} credits added to {user.username} account.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Admin session ended.', 'success')
    return redirect(url_for('index'))

@app.route('/admin/backup_database')
@login_required
def backup_database():
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))
    
    try:
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if not os.path.exists(db_path):
            flash('Database file not found.', 'error')
            return redirect(url_for('admin_panel'))
        
        return send_file(db_path, as_attachment=True, download_name='users.db')
    except Exception as e:
        flash(f'Database backup error: {str(e)}', 'error')
        return redirect(url_for('admin_panel'))

@app.route('/admin/restore_database', methods=['POST'])
@login_required
def restore_database():
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))
    
    if 'database_file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('admin_panel'))
    
    file = request.files['database_file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('admin_panel'))
    
    if file:
        filename = secure_filename(file.filename)
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        file.save(db_path)
        flash('Database restored successfully', 'success')
        return redirect(url_for('admin_panel'))

@app.route('/user_panel')
@login_required
def user_panel():
    user_coordinates = Coordinate.query.filter_by(user_id=current_user.id).order_by(Coordinate.created_at.desc()).all()
    credit_packages = [
        {'credits': 1, 'price': 35},
        {'credits': 5, 'price': 150},
        {'credits': 10, 'price': 250}
    ]
    payment_notifications = PaymentNotification.query.filter_by(user_id=current_user.id).order_by(PaymentNotification.created_at.desc()).limit(5).all()
    return render_template('user_panel.html', coordinates=user_coordinates, user=current_user, credit_packages=credit_packages, payment_notifications=payment_notifications)

@app.route('/download_coordinate/<int:coordinate_id>')
@login_required
def download_coordinate(coordinate_id):
    coordinate = Coordinate.query.get_or_404(coordinate_id)
    if coordinate.user_id != current_user.id:
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('user_panel'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'coordinates_{coordinate.id}.xlsx')
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=f'coordinates_{coordinate.name}.xlsx')
    else:
        flash('File not found.', 'danger')
        return redirect(url_for('user_panel'))

@app.route('/parse_google_maps_link', methods=['POST'])
def parse_google_maps_link():
    link = request.json['link']
    pattern = r'@([-\d.]+),([-\d.]+)'
    name_pattern = r'/place/([^/]+)/'
    
    coords_match = re.search(pattern, link)
    name_match = re.search(name_pattern, link)
    
    if coords_match and name_match:
        lat, lng = coords_match.groups()
        name = name_match.group(1).replace('+', ' ')
        return jsonify({
            'success': True,
            'lat': float(lat),
            'lng': float(lng),
            'name': name
        })
    else:
        return jsonify({'success': False})

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
    total_users = User.query.count()
    total_coordinates = Coordinate.query.count()
    
    # Son 30 günün tarihlerini oluştur
    today = datetime.now().date()
    last_30_days = [today - timedelta(days=i) for i in range(30)][::-1]
    
    # Günlük kredi kullanımı ve kazanç
    daily_stats = db.session.query(
        func.date(Coordinate.created_at).label('date'),
        func.sum(Coordinate.num_points / 20000).label('credits_used'),
        func.count(Coordinate.id).label('coordinate_count')
    ).filter(Coordinate.created_at >= last_30_days[0]).group_by(func.date(Coordinate.created_at)).all()
    
    credit_usage_data = {date: {'credits': 0, 'coordinates': 0, 'revenue': 0} for date in last_30_days}
    for stat in daily_stats:
        credit_usage_data[stat.date]['credits'] = int(stat.credits_used)
        credit_usage_data[stat.date]['coordinates'] = stat.coordinate_count
        credit_usage_data[stat.date]['revenue'] = int(stat.credits_used) * 2  # Her kredi 2 TL olarak varsayalım

    # Strateji kullanımı
    strategy_usage = db.session.query(
        Coordinate.strategy,
        func.count(Coordinate.id).label('count')
    ).group_by(Coordinate.strategy).all()
    
    # En çok koordinat oluşturan kullanıcılar
    top_users = db.session.query(
        User.username,
        func.count(Coordinate.id).label('coordinate_count')
    ).join(Coordinate).group_by(User.id).order_by(func.count(Coordinate.id).desc()).limit(10).all()
    
    # Kullanıcı kayıt istatistikleri
    user_registrations = db.session.query(
        func.date(User.date_joined).label('date'),
        func.count(User.id).label('count')
    ).filter(User.date_joined >= last_30_days[0]).group_by(func.date(User.date_joined)).all()

    registration_data = {date: 0 for date in last_30_days}
    for reg in user_registrations:
        registration_data[reg.date] = reg.count

    # Hata ayıklama için print ifadeleri
    print("Registration data:", registration_data)
    for date, count in registration_data.items():
        print(f"Date: {date}, Type: {type(date)}, Count: {count}")

    analytics_data = {
        'total_users': total_users,
        'total_coordinates': total_coordinates,
        'credit_usage': [{'date': date.strftime('%Y-%m-%d'), 'credits': data['credits'], 'coordinates': data['coordinates'], 'revenue': data['revenue']} for date, data in credit_usage_data.items()],
        'strategy_usage': [{'strategy': usage.strategy, 'count': usage.count} for usage in strategy_usage],
        'top_users': [{'username': user.username, 'count': user.coordinate_count} for user in top_users],
        'user_registrations': [{'date': date.strftime('%Y-%m-%d') if isinstance(date, datetime) else date, 'count': count} for date, count in registration_data.items()]
    }
    
    return render_template('admin_analytics.html', data=analytics_data)

@app.route('/add_credits', methods=['GET', 'POST'])
@login_required
def add_credits():
    form = PaymentNotificationForm()
    if form.validate_on_submit():
        credit_amount = int(form.credit_package.data)
        payment_amount = {1: 35, 5: 150, 10: 250}[credit_amount]
        
        transaction_code = PaymentNotification.generate_transaction_code()
        
        notification = PaymentNotification(
            user_id=current_user.id,
            amount=payment_amount,
            credits=credit_amount,
            payment_method=form.payment_method.data,
            status='pending',
            transaction_code=transaction_code
        )
        db.session.add(notification)
        db.session.commit()
        
        return render_template('payment_instructions.html', 
                               transaction_code=transaction_code, 
                               amount=payment_amount, 
                               payment_method=form.payment_method.data)
    
    return render_template('add_credits.html', form=form)

@app.route('/admin/payment_notifications')
@login_required
def admin_payment_notifications():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
    notifications = PaymentNotification.query.filter_by(status='pending').order_by(PaymentNotification.created_at.desc()).all()
    return render_template('admin/payment_notifications.html', notifications=notifications)

@app.route('/admin/approve_payment/<int:notification_id>', methods=['POST'])
@login_required
def approve_payment(notification_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))
    
    notification = PaymentNotification.query.get_or_404(notification_id)
    user = User.query.get(notification.user_id)
    
    user.credits += notification.credits
    notification.status = 'approved'
    
    db.session.commit()
    
    flash(f'{notification.credits} credits added to {user.username} account.', 'success')
    return redirect(url_for('admin_payment_notifications'))

@app.route('/submit_payment', methods=['POST'])
def submit_payment():
    if request.method == 'POST':
        amount = request.form['amount']
        payment_method = request.form['payment_method']
        transaction_id = request.form['transaction_id']
        
        flash('Your payment notification has been received. It will be reflected in your account after review.', 'success')
        return redirect(url_for('add_credits'))

@app.route('/loaderio-fa42b311f22e364778c0de981b740803.txt')
def loaderio():
    return send_from_directory(app.static_folder, 'loaderio-fa42b311f22e364778c0de981b740803.txt')

@app.route('/how_to_use')
def how_to_use():
    return render_template('how_to_use.html')

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Mevcut tabloları sil
        db.create_all()  # Tabloları yeniden oluştur
    app.run(debug=True, host="0.0.0.0", port=5000)