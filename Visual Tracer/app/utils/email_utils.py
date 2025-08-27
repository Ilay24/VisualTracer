from flask_mail import Message
from flask import current_app, url_for
from itsdangerous import URLSafeTimedSerializer
from app import mail


def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='reset-password-salt')


def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='reset-password-salt', max_age=expiration)
    except Exception:
        return None
    return email


def send_reset_email(user):
    print("MAIL_SERVER:", current_app.config.get('MAIL_SERVER'))
    print("MAIL_USERNAME:", current_app.config.get('MAIL_USERNAME'))
    print("MAIL_PASSWORD:", current_app.config.get('MAIL_PASSWORD'))
    print("MAIL_DEFAULT_SENDER:", current_app.config.get('MAIL_DEFAULT_SENDER'))
    token = generate_reset_token(user.email)
    reset_url = url_for('auth.reset_password', token=token, _external=True)

    msg = Message(
        'Reset Your Password',
        sender='ilay2017ilay@gmail.com',
        recipients=[user.email]
    )
    msg.body = f"""
    Hi {user.username},

    To reset your password, click the following link:
    {reset_url}

    If you did not request this, please ignore this email.
    """
    mail.send(msg)

