from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, IntegerField, SelectField, URLField
from wtforms.validators import DataRequired, Length, EqualTo, URL, Optional

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class GenerateForm(FlaskForm):
    google_maps_link = URLField('Google Maps Link', validators=[Optional(), URL()])
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    center_lat = FloatField('Center Latitude', validators=[DataRequired()])
    center_long = FloatField('Center Longitude', validators=[DataRequired()])
    radius = FloatField('Radius (km)', validators=[DataRequired()])
    num_points = IntegerField('Number of Coordinates', validators=[DataRequired()])
    keywords = StringField('Keywords (comma separated)', validators=[DataRequired()])
    website = StringField('Website')
    phone_number = StringField('Phone Number')
    strategy = SelectField('Strategy', choices=[('circle', 'Circle'), ('fill', 'Fill')], validators=[DataRequired()])
    submit = SubmitField('Generate Coordinates')

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PaymentNotificationForm(FlaskForm):
    credit_package = SelectField('Credit Package', choices=[
        ('1', '1 Credit - 35TL'),
        ('5', '5 Credits - 150TL'),
        ('10', '10 Credits - 250TL')
    ], validators=[DataRequired()])
    payment_method = SelectField('Payment Method', choices=[
        ('eft', 'EFT'),
        ('papara', 'Papara')
    ], validators=[DataRequired()])
    submit = SubmitField('Send Payment Notification')