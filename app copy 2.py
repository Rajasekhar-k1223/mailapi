from email.message import EmailMessage
import smtplib
from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from flask_login import LoginManager, login_user, UserMixin, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import imaplib
import email
from email.header import decode_header
import os
import dns.resolver
import logging
import jwt
from datetime import datetime, timedelta
from flask_cors import CORS
from sqlalchemy import text 
from sqlalchemy.exc import IntegrityError
import subprocess
from pymongo import MongoClient  # New import for MongoDB
import base64
import re
import asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from flask_restx import Api, Resource
from datetime import datetime
from flask_cors import CORS, cross_origin

app = Flask(__name__)

# Configuration
app.secret_key = os.getenv('SECRET_KEY', '65465kljnkjbjkb')
# app.secret_key = os.getenv('SECRET_KEY', 'default_fallback_key')  # Use a fallback key only for development
# jwt = JWTManager(app)
api = Api(app)
CORS(app, resources={r"/*": {"origins": ["https://domreg.imailler.com", "http://localhost:3000"], "supports_credentials": True}})
# app.secret_key = 'random_secret_key'
# SECRET_KEY = app.secret_key


# MariaDB configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Admin!123@localhost/vmail'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager()
login_manager.init_app(app)
# Blacklist storage for JWT tokens
BLACKLIST = set()
# MongoDB configuration
mongo_client = MongoClient("mongodb://157.173.199.49:25312/")
mongo_db = mongo_client['vmail']  # Specify your MongoDB database name
# mongo_collection = mongo_db['users']  # Example collection

# Configure logging
#logging.basicConfig(level=logging.DEBUG)

# Flask-Login setup
# Create tables
with app.app_context():
    db.create_all()

# JWT Blacklist Check
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in BLACKLIST

# Login Manager loader
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# MariaDB User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class EmailLog(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(120), nullable=False)
    recipient = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())


### Helper Functions for SSHA512 Encryption ###
def generate_ssha512_password(password):
    salt = base64.b64encode(hashlib.sha512().digest()).decode()[:16]  # Generate a 16-byte salt
    password_hash = hashlib.sha512(password.encode() + salt.encode()).digest()
    return '{SSHA512}' + base64.b64encode(password_hash + salt.encode()).decode()


import hashlib
import base64
import hmac

def check_ssha512_password(stored_password, input_password):
    # Remove the {SSHA512} prefix
    stored_password = stored_password.replace("{SSHA512}", "")
    
    # Decode the stored password from Base64
    decoded = base64.b64decode(stored_password)
    
    # Split the decoded value into the hash part and the salt (last 16 bytes)
    hash_part = decoded[:-16]
    salt = decoded[-16:]
    
    # Hash the input password with the same salt
    input_hash = hashlib.sha512(input_password.encode() + salt).digest()
    
    # Use hmac.compare_digest for secure comparison
    return hmac.compare_digest(hash_part, input_hash)



### Helper Function to Log Email to MongoDB ###
def log_email_to_mongo(sender, recipient, subject, body):
    email_log = {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "timestamp": db.func.now()
    }
    mongo.db.email_logs.insert_one(email_log)


### API Endpoints ###
# API Endpoint for user login
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            token = create_access_token(identity=str(user.id), expires_delta=timedelta(hours=1))
            return jsonify({'message': 'Login successful', 'token': token,'userId':user.id}), 200

        return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# API Endpoint for user logout
@app.route('/api/logout', methods=['POST'])
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

# Helper function to connect to the IMAP server (iRedMail)
def connect_to_imap(username, password, imap_server):
    # try:
    #     mail = imaplib.IMAP4_SSL(imap_server)
    #     mail.login(username, password)
    #     return mail
    # except Exception as e:
    #     return None
    try:
        # Connect to the IMAP server over SSL
        mail = imaplib.IMAP4_SSL(imap_server, port=993)
        return mail
        # Login with provided credentials
        mail.login(username, password)
        print("Connected successfully!")
        return mail
    except imaplib.IMAP4.error as e:
        print(f"IMAP error: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


# Helper function to list received emails (Inbox or Spam)
def list_inbox_emails(mail, folder="INBOX", limit=10):
    try:
        mail.select(folder)
        status, email_ids = mail.search(None, "ALL")
        email_ids = email_ids[0].split()
        emails = []
        for email_id in email_ids[-limit:]:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # Decode the subject
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding if encoding else "utf-8")
                    
                    # Get other headers
                    from_ = msg.get("From")
                    date_ = msg.get("Date")
                    to_ = msg.get("To")
                    
                    # Parse email content
                    content = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            
                            # Extract the email body
                            if content_type == "text/plain" and "attachment" not in content_disposition:
                                content = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
                                break
                    else:
                        content = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8")
                    
                    # Append the email details to the list
                    emails.append({
                        "subject": subject,
                        "from": from_,
                        "to": to_,
                        "date": date_,
                        "content": content
                    })

        return emails
    except Exception as e:
        print(f"Error: {e}")
        return []


# API to send emails (JWT-protected)
@app.route('/api/send-mail', methods=['POST'])
@jwt_required()
def send_mail():
    try:
        data = request.json
        domain = data.get('domain')
        username = data.get('username')
        password = data.get('password')
        recipient = data.get('recipient')
        subject = data.get('subject')
        body = data.get('body')

        if not all([domain, username, password, recipient, subject, body]):
            return jsonify({"error": "Missing required fields"}), 400

        # Construct sender email address
        sender = f"{username}@{domain}"
        # sender = "rsekhar042@gmail.com"
        smtp_server = "smtp.imailler.com"
        smtp_port=587
        # Send the email via SMTP
        success, error_message = send_email(sender, recipient, subject, body, smtp_server,smtp_port, sender, str(password))

        if success:
            # Log email to SQL and MongoDB
            email_log = EmailLog(sender=sender, recipient=recipient, subject=subject, body=body)
            db.session.add(email_log)
            db.session.commit()
            
            log_email_to_mongo(sender, recipient, subject, body)

            return jsonify({"message": "Email sent successfully!"}), 200
        else:
            return jsonify({"error": error_message}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# API to fetch inbox or spam emails (JWT-protected)
@app.route('/api/get-mails', methods=['POST'])
@jwt_required()
def get_mails():
    try:
        data = request.json
        domain = data.get('domain')
        username = data.get('username')
        password = data.get('password')
        folder = data.get('folder', 'INBOX')  # Default to INBOX, can be 'SPAM' or others

        if not all([domain, username, password]):
            return jsonify({"error": "Missing domain, username, or password"}), 400

        email_address = f"{username}@{domain}"
        imap_server = "0.0.0.0"
        # Connect to IMAP (iRedMail server)
        mail = connect_to_imap('rsekhar042@gmail.com', 'Raja@1223', imap_server)
        if not mail:
            return jsonify({"error": "Failed to connect to the email server"}), 500

        # Fetch emails from the specified folder
        emails = list_inbox_emails(mail, folder=folder)
        # # Log fetched emails to MongoDB
        for email_item in emails:
            log_email_to_mongo(email_item['from'], email_address, email_item['subject'], "")

        mail.logout()

        return jsonify({"emails": emails}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


### Helper function to send an email using SMTP ###
def send_email(sender, recipient, subject, body, smtp_server, smtp_port, smtp_username, smtp_password):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Use TLS for security
            server.login(smtp_username,smtp_password)
            server.send_message(msg)

        return True, None
    except Exception as e:
        return False, str(e)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
