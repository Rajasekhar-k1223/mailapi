from flask import Flask, request, jsonify
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from werkzeug.security import check_password_hash  # For password verification
import jwt  # PyJWT library for JWT generation
import datetime
from sqlalchemy.exc import IntegrityError
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import hashlib
import base64

app = Flask(__name__)

# MariaDB configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Admin!123@localhost/vmail'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure your SMTP server settings
app.config['SMTP_SERVER'] = 'smtp.imailler.com'
app.config['MAIL_PORT'] = 587  # Change to 465 if SSL is required
app.config['USE_SSL'] = False  # Set to True if SSL is required, False for TLS
app.config['JWT_SECRET_KEY'] = 'slgnskjgnsfjgn654sdg654fs'  # Set your JWT secret key

### SQLAlchemy Models ###
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Mailbox(db.Model):
    __tablename__ = 'mailbox'  # Table name in MySQL
    username = db.Column(db.String(120), primary_key=True)  # Primary key on username
    password = db.Column(db.String(255), nullable=False)


### Helper Functions ###
def generate_jwt(mail_username):
    """
    Generate a JWT token for SMTP authentication.
    """
    payload = {
        'email': mail_username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # Token expires in 30 minutes
    }
    jwt_token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return jwt_token

def check_ssha512_password(hashed_password, plain_password):
    """
    Verify if the given plain_password matches the SSHA512 hashed_password.
    """
    # Remove the "{SSHA512}" prefix
    if hashed_password.startswith("{SSHA512}"):
        hashed_password = hashed_password[len("{SSHA512}"):]

    # Decode the base64-encoded hash and extract the hash and salt
    decoded = base64.b64decode(hashed_password)
    password_hash = decoded[:64]  # SHA-512 produces 64 bytes
    salt = decoded[64:]  # The rest is the salt

    # Hash the plain password with the extracted salt
    hash_with_salt = hashlib.sha512(plain_password.encode() + salt).digest()

    # Compare the computed hash with the stored hash
    return password_hash == hash_with_salt
### Routes ###
@app.route('/send_email', methods=['POST'])
def send_email():
    mail_username = request.form.get('mail_username')
    plain_password = request.form.get('secret_key')  # The plain password input by the user
    to_email = request.form.get('to_email')
    cc_email = request.form.get('cc_email')
    subject = request.form.get('subject')
    body = request.form.get('body')
    body_format = request.form.get('body_format', 'plain')

    if not mail_username or not plain_password or not to_email or not subject or not body:
        return jsonify({'error': 'Missing required parameters'}), 400

    # Validate the password
    user_data = Mailbox.query.filter_by(username=mail_username).first()
    if not user_data or not check_ssha512_password(user_data.password, plain_password):
        return jsonify({'error': 'Authentication failed: Invalid username or password'}), 401

    # Generate JWT for authentication
    jwt_token = generate_jwt(mail_username)

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = mail_username
    msg['To'] = to_email
    if cc_email:
        msg['Cc'] = cc_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, body_format))

    # Attach files
    attachments = request.files.getlist('attachments')
    for attachment in attachments:
        if attachment:
            try:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={attachment.filename}')
                msg.attach(part)
            except Exception as e:
                return jsonify({'error': f'Failed to attach file {attachment.filename}: {str(e)}'}), 500

    try:
        # Establish a connection to the SMTP server
        if app.config['USE_SSL']:
            server = smtplib.SMTP_SSL(app.config['SMTP_SERVER'], app.config['MAIL_PORT'])
        else:
            server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['MAIL_PORT'])
            server.starttls()  # Upgrade the connection to TLS if not using SSL

        # Login using the plain_password in the password field
        server.login(mail_username, plain_password)

        # Combine to_email and cc_email into one list
        recipients = [to_email]
        if cc_email:
            recipients.append(cc_email)

        # Send the email
        server.sendmail(mail_username, recipients, msg.as_string())
        server.quit()

        return jsonify({'message': 'Email sent successfully!'})

    except smtplib.SMTPAuthenticationError as auth_error:
        return jsonify({'error': f'Authentication failed: {auth_error}'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
