import email
from flask import Flask, request, jsonify
import smtplib
import imaplib
from flask_login import LoginManager, login_user, UserMixin, logout_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.message import EmailMessage
from email.header import decode_header
from email import encoders
from werkzeug.security import check_password_hash  # For password verification
import jwt  # PyJWT library for JWT generation
# import datetime
from sqlalchemy.exc import IntegrityError
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import hashlib
import base64
from pymongo import MongoClient  # New import for MongoDB
from sqlalchemy.exc import SQLAlchemyError  # For handling database errors
import os
app = Flask(__name__)
jwt = JWTManager(app)  # Initialize JWTManager after app config
# MariaDB configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Admin!123@localhost/vmail'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# MongoDB configuration
mongo_client = MongoClient("mongodb://157.173.199.49:25312/")
mongo_db = mongo_client['vmail']  # Specify your MongoDB database name

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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), primary_key=True)  # Primary key on username
    password = db.Column(db.String(255), nullable=False)
    pwdbcrypt = db.Column(db.String(255), nullable=False)

class EmailLog(db.Model):
    __tablename__ = 'emaillog'  # Table name in MySQL
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    to_email = db.Column(db.Text, nullable=False)
    cc_email = db.Column(db.Text, nullable=True)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    body_format = db.Column(db.String(50), default='plain')
    attachments = db.Column(db.Text, nullable=True)  # Comma-separated filenames
    sent_at = db.Column(db.DateTime, default=datetime)


BASE_MAILDIR = "/var/vmail/vmail1"


### Helper Functions ###
def generate_jwt(mail_username):
    """
    Generate a JWT token for SMTP authentication.
    """
    payload = {
        'email': mail_username,
        'exp': datetime.utcnow() + timedelta(minutes=30)  # Token expires in 30 minutes
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


# Helper function to list received emails (Inbox or Spam)
def list_inbox_emails(mail, folder="INBOX", limit=10):
    try:
        # Select the folder (default is INBOX)
        mail.select(folder)
        status, email_ids = mail.search(None, "ALL")
        email_ids = email_ids[0].split()
        emails = []

        # Fetch the latest 'limit' emails
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
                        "content": content,
                        "retrieved_at": datetime.utcnow()  # Use datetime.utcnow() instead of func.now()
                    })

        return emails
    except Exception as e:
        print(f"Error: {e}")
        return []


# Helper function to connect to the IMAP server (iRedMail)
def connect_to_imap(username, password, imap_server):
    try:
        mail = imaplib.IMAP4_SSL(imap_server, 993)
        mail.login(username, password)
        return mail
    except Exception as e:
        print(f"IMAP connection error: {e}")
        return None


### Helper Function to Log Email to MongoDB ###
def log_email_to_mongo(sender, recipient, subject, body):
    email_log = {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "timestamp": db.func.now()
    }
    mongo_collection = mongo_db['email_logs']
    mongo_collection.insert_one(email_log)

# API Endpoint for user login
# Login route
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Find the user in the database
        user = Mailbox.query.filter_by(username=username).first()
        
        if user and check_ssha512_password(user.password, password):
            # Generate a JWT token
            token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))
            return jsonify({'message': 'Login successful', 'token': token, 'userId': user.id,'bcrypt':user.pwdbcrypt}), 200
        
        return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 400




# API to fetch inbox or spam emails (JWT-protected)
@app.route('/api/get-mails', methods=['POST'])
# @jwt_required()
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
        imap_server = "127.0.0.1"

        # Connect to IMAP (iRedMail server)
        mail = connect_to_imap(email_address, password, imap_server)
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


### Routes ###
@app.route('/send_email', methods=['POST'])
def send_email():
    mail_username = request.form.get('mail_username')
    plain_password = request.form.get('secret_key')
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

    # Parse multiple recipients
    to_emails = [email.strip() for email in to_email.split(',') if email.strip()]
    cc_emails = [email.strip() for email in cc_email.split(',')] if cc_email else []
    recipients = to_emails + cc_emails

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = mail_username
    msg['To'] = ', '.join(to_emails)
    if cc_emails:
        msg['Cc'] = ', '.join(cc_emails)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, body_format))

    # Attach files
    attachments = request.files.getlist('attachments')
    attachment_filenames = []
    for attachment in attachments:
        if attachment:
            try:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={attachment.filename}')
                msg.attach(part)
                attachment_filenames.append(attachment.filename)
            except Exception as e:
                return jsonify({'error': f'Failed to attach file {attachment.filename}: {str(e)}'}), 500

    try:
        # Establish a connection to the SMTP server
        if app.config['USE_SSL']:
            server = smtplib.SMTP_SSL(app.config['SMTP_SERVER'], app.config['MAIL_PORT'])
        else:
            server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['MAIL_PORT'])
            server.starttls()

        # Login using the plain_password in the password field
        server.login(mail_username, plain_password)

        # Send the email
        server.sendmail(mail_username, recipients, msg.as_string())
        server.quit()

        # Log the email details in MySQL/MariaDB
        email_entry = EmailLog(
            username=mail_username,
            to_email=', '.join(to_emails),
            cc_email=', '.join(cc_emails) if cc_email else None,
            subject=subject,
            body=body,
            body_format=body_format,
            attachments=', '.join(attachment_filenames) if attachment_filenames else None,
            sent_at=datetime.utcnow()
        )
        db.session.add(email_entry)
        db.session.commit()

        # Log the email details in MongoDB
        email_data = {
            "username": mail_username,
            "to_email": to_emails,
            "cc_email": cc_emails,
            "subject": subject,
            "body": body,
            "body_format": body_format,
            "attachments": attachment_filenames,
            "sent_at": datetime.utcnow()
        }
        mongo_collection = mongo_db['send_mails']
        mongo_collection.insert_one(email_data)

        return jsonify({'message': 'Email sent successfully!','status':200}),200

    except smtplib.SMTPAuthenticationError as auth_error:
        return jsonify({'error': f'Authentication failed: {auth_error}'}), 401
    except SQLAlchemyError as sql_error:
        return jsonify({'error': f'Database error: {sql_error}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# def get_folder_name(email_address):
#     """
#     Generate the folder path based on the email address.
#     Example: rajasekhark@imailler.com -> /var/vmail/vmail1/imailler.com/r/a/j/rajasekhark-2024.11.21.06.27.17/Maildir
#     """
#     try:
#         user_part, domain = email_address.split("@")
#         initials = "/".join(user_part[:3])
#         folder_name = f"{user_part}-{domain.replace('.', '-')}"
#         maildir_path = os.path.join(BASE_MAILDIR, domain, initials, folder_name, "Maildir")
#         return maildir_path
#     except Exception as e:
#         return {"error": f"Invalid email address: {email_address}. Error: {str(e)}"}


def list_all_folders(maildir_path):
    """
    List all folders in the user's Maildir.
    """
    data = maildir_path
       # If maildir_path is a dictionary containing an error, return it directly
    if isinstance(maildir_path, dict) and "error" in maildir_path:
        return maildir_path

    # Proceed only if maildir_path is valid (string)
    if not isinstance(data["maildir_path"], str):
        return {"error": "Maildir path is invalid."}
    
    try:
        # Check if the directory exists before listing its contents
        if not os.path.exists(data["maildir_path"]):
            return {"error": f"Maildir path not found: {maildir_path}"}
        
        # List directories inside the Maildir path
        folders = [
            folder for folder in os.listdir(data["maildir_path"])
            if os.path.isdir(os.path.join(data["maildir_path"], folder))
        ]
        return folders
    
    except Exception as e:
        return {"error": f"Error listing folders: {str(e)}"}


def fetch_emails(maildir_path, folder="new"):
    """
    Fetch emails from the specified folder.
    """
    data = maildir_path
    folder_path = os.path.join(data["maildir_path"], folder)
    if not os.path.exists(folder_path):
        return {"error": f"Folder not found: {folder}"}
    emails = []
    try:
        for filename in os.listdir(folder_path):
            filepath = os.path.join(folder_path, filename)
            with open(filepath, "r") as f:
                msg = email.message_from_file(f)
                email_data = {
                    "from": msg.get("From"),
                    "to": msg.get("To"),
                    "subject": msg.get("Subject"),
                    "date": msg.get("Date"),
                }
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            email_data["body"] = part.get_payload(decode=True).decode("utf-8")
                            break
                else:
                    email_data["body"] = msg.get_payload(decode=True).decode("utf-8")
                emails.append(email_data)
    except Exception as e:
        return {"error": f"Error reading emails: {str(e)}"}
    
    return emails


@app.route("/api/email", methods=["GET"])
def email_api():
    """
    Unified API to:
    1. List folders: Action = 'list_folders'
    2. Fetch emails: Action = 'fetch_emails'
    """
    email_address = request.args.get("email")
    action = request.args.get("action", "list_folders")  # Default to list folders
    folder = request.args.get("folder", "new")  # Default to 'new'
    
    if not email_address:
        return jsonify({"error": "Email address is required."}), 400
    
    # Get the Maildir path
    maildir_path = get_folder_name(email_address)

    # if isinstance(maildir_path, dict) and "error" in maildir_path:
    #     return jsonify(maildir_path), 400
    
    # Perform the requested action
    if action == "list_folders":
        folders = list_all_folders(maildir_path)
        if "error" in folders:
            return jsonify({"error": folders["error"]}), 404
        return jsonify({"email": email_address, "folders": folders})
    
    elif action == "fetch_emails":
        emails = fetch_emails(maildir_path, folder)
        if "error" in emails:
            return jsonify({"error": emails["error"]}), 404
        return jsonify({"email": email_address, "folder": folder, "emails": emails})
    
    else:
        return jsonify({"error": f"Invalid action: {action}"}), 400


def get_folder_name(email_address):
    """
    Generate the folder path based on the email address.
    Example: rajasekhark@imailler.com -> /var/vmail/vmail1/imailler.com/r/a/j/rajasekhark-2024.11.21.06.27.17/Maildir
    """
    try:
        # Split email into user and domain parts
        user_part, domain = email_address.split("@")
        
        # Generate initials based on the first three characters of the user part
        initials = "/".join(user_part[:3])
        
        # Look for the folder in the actual directory
        domain_path = os.path.join(BASE_MAILDIR, domain)
        user_path = os.path.join(domain_path, initials)
        
        # Find the exact folder matching the user and timestamp format
        possible_folders = [
            folder for folder in os.listdir(user_path)
            # if folder.startswith(user_part) and "Maildir" in folder
        ]
        
        if not possible_folders:
            return {"error": "Folder not found for the given email address."}
        
        # Assuming there's only one match
        folder_name = possible_folders[0]
        maildir_path = os.path.join(user_path, folder_name, "Maildir")
        
        return {"maildir_path": maildir_path}
    
    except Exception as e:
        return {"error": f"Error processing email address '{email_address}': {str(e)}"}

@app.route("/api/get-folder-name", methods=["GET"])
def folder_name_api():
    """
    API to get the folder name based on the email address.
    """
    email_address = request.args.get("email")
    if not email_address:
        return jsonify({"error": "Email address is required."}), 400
    
    result = get_folder_name(email_address)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
