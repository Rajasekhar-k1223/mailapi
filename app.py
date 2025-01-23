import email
from email.mime import text
from quopri import encodestring
import uuid
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
import smtplib
import imaplib
import web
from flask_login import LoginManager, login_user, UserMixin, logout_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required,get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.message import EmailMessage
from email.header import decode_header
from email import encoders
from email.utils import parseaddr
from werkzeug.security import check_password_hash  # For password verification
import jwt  # PyJWT library for JWT generation
# import datetime
from sqlalchemy.exc import IntegrityError
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import hashlib
import base64
import json
from bson import json_util
from pymongo import MongoClient  # New import for MongoDB
from sqlalchemy.exc import SQLAlchemyError  # For handling database errors
import os
from flask_cors import CORS, cross_origin
from email.policy import default
from email import message_from_file
import re
from email.parser import BytesParser
from urllib.parse import quote
import stat
import shutil
from bson import ObjectId

from libs import iredutils, iredpwd,form_utils
import settings
from libs.l10n import TIMEZONES
from libs.logger import logger, log_activity
from libs.sqllib import SQLWrap, decorators, sqlutils
from libs.sqllib import general as sql_lib_general
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import domain as sql_lib_domain


app = Flask(__name__)
jwt = JWTManager(app)  # Initialize JWTManager after app config
login_manager = LoginManager()
login_manager.init_app(app)
# MariaDB configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Admin!123@localhost/vmail'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
CORS(app, resources={r"/*": {"origins": ["https://mail.imailler.com","http://157.173.199.49:3000/*", "http://localhost:3000", "http://127.0.0.1:3000","http://localhost","http://127.0.0.1"], "supports_credentials": True}})
# MongoDB configuration
mongo_client = MongoClient("mongodb://157.173.199.49:25312/")
MONGO_URI= "mongodb://157.173.199.49:25312/"
mongo_db = mongo_client['vmail']  # Specify your MongoDB database name

with open("fernet_key.txt", "rb") as file:
    key = file.read()
cipher = Fernet(key)

# Configure your SMTP server settings
app.config['SMTP_SERVER'] = 'smtp.imailler.com'
app.config['MAIL_PORT'] = 587  # Change to 465 if SSL is required
app.config['USE_SSL'] = False  # Set to True if SSL is required, False for TLS
app.config['JWT_SECRET_KEY'] = 'slgnskjgnsfjgn654sdg654fs'  # Set your JWT secret key

# Blocklist for invalidated tokens
BLOCKLIST = set()

### SQLAlchemy Models ###
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Mailbox(UserMixin, db.Model):
    __tablename__ = 'mailbox'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    pwdbcrypt = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(255))
    language = db.Column(db.String(50))
    mailboxformat = db.Column(db.String(50))
    mailboxfolder = db.Column(db.String(255))
    storagebasedirectory = db.Column(db.String(255))
    storagenode = db.Column(db.String(255))
    maildir = db.Column(db.String(255))
    quota = db.Column(db.Integer)
    domain = db.Column(db.String(255))
    transport = db.Column(db.String(255))
    department = db.Column(db.String(255))
    rank = db.Column(db.String(255))
    employeeid = db.Column(db.String(50))
    isadmin = db.Column(db.Boolean, default=False)
    isglobaladmin = db.Column(db.Boolean, default=False)
    enablesmtp = db.Column(db.Boolean, default=False)
    enablesmtpsecured = db.Column(db.Boolean, default=False)
    enablepop3 = db.Column(db.Boolean, default=False)
    enablepop3secured = db.Column(db.Boolean, default=False)
    enablepop3tls = db.Column(db.Boolean, default=False)
    enableimap = db.Column(db.Boolean, default=False)
    enableimapsecured = db.Column(db.Boolean, default=False)
    enableimaptls = db.Column(db.Boolean, default=False)
    enabledeliver = db.Column(db.Boolean, default=False)
    enablelda = db.Column(db.Boolean, default=False)
    enablemanagesieve = db.Column(db.Boolean, default=False)
    enablemanagesievesecured = db.Column(db.Boolean, default=False)
    enablesieve = db.Column(db.Boolean, default=False)
    enablesievesecured = db.Column(db.Boolean, default=False)
    enablesievetls = db.Column(db.Boolean, default=False)
    enableinternal = db.Column(db.Boolean, default=False)
    enabledoveadm = db.Column(db.Boolean, default=False)
   # Use `key` to map database column names with hyphens to valid Python attributes
    enablelib_storage = db.Column('enablelib-storage', db.Boolean, default=False)
    enablequota_status = db.Column('enablequota-status', db.Boolean, default=False)
    enableindexer_worker = db.Column('enableindexer-worker', db.Boolean, default=False)
    enablelmtp = db.Column(db.Boolean, default=False)
    enabledsync = db.Column(db.Boolean, default=False)
    enablesogo = db.Column(db.Boolean, default=False)
    enablesogowebmail = db.Column(db.String(10))
    enablesogocalendar = db.Column(db.String(10))
    enablesogoactivesync = db.Column(db.String(10))
    allow_nets = db.Column('allow_nets', db.String(255))
    disclaimer = db.Column(db.Text)
    settings = db.Column(db.Text)
    passwordlastchange = db.Column(db.DateTime)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    modified = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expired = db.Column(db.DateTime)
    active = db.Column(db.Boolean, default=True)


class Forwarding(db.Model):
    __tablename__ = 'forwardings'

    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(255), nullable=False)
    forwarding = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    dest_domain = db.Column(db.String(255), nullable=False)
    is_maillist = db.Column(db.Boolean, default=False)
    is_list = db.Column(db.Boolean, default=False)
    is_forwarding = db.Column(db.Boolean, default=False)
    is_alias = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)

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

class Email(db.Model):
    __tablename__ = 'received_emails'

    id = db.Column(db.Integer, primary_key=True)
    msg_queue_id = db.Column(db.Integer, nullable=False)
    sender = db.Column(db.String(255), nullable=False)
    recipient = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=True)
    body_type_html = db.Column(db.Text, nullable=True)
    body_type_plain = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    attachments = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return (
            f"<Email(id={self.id}, sender='{self.sender}', recipient='{self.recipient}', "
            f"subject='{self.subject}', date='{self.date}')>"
        )


BASE_MAILDIR_MAIN = "/var/vmail/vmail1"
# Define the public directory for attachments
ATTACHMENTS_FOLDER = "/var/www/html/attachments"
NEW_PATH = "cur"  # New path for processed emails

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
# def convert_plaintext_to_html(plain_text):
#     """
#     Converts plain text email content into an HTML structure.
#     """
#     import html
#     # Escape HTML special characters
#     escaped_text = html.escape(plain_text)
    
#     # Replace line breaks with HTML <br> tags
#     html_content = escaped_text.replace("\n", "<br>")
    
#     # Construct the final HTML
#     final_html = f"""
#     <!DOCTYPE html>
#     <html lang="en">
#     <head>
#         <meta charset="UTF-8">
#         <meta name="viewport" content="width=device-width, initial-scale=1.0">
#         <title>Email</title>
#         <style>
#             body {{
#                 font-family: Arial, sans-serif;
#                 line-height: 1.6;
#                 color: #333;
#                 margin: 20px;
#             }}
#             a {{
#                 color: #007BFF;
#                 text-decoration: none;
#             }}
#             a:hover {{
#                 text-decoration: underline;
#             }}
#         </style>
#     </head>
#     <body>
#         {html_content}
#     </body>
#     </html>
#     """
#     return final_html
def generate_html(input_text):
    """
    Convert plain text with embedded links and attachments to HTML format.

    Args:
    input_text (str): The input text containing content, links, and attachments.

    Returns:
    str: HTML string representing the content.
    """
    # Extract links and CID mappings
    links = re.findall(r"&lt;(https?://[^\s&gt;]+)&gt;", input_text)
    cids = re.findall(r"\[cid:([^\]]+)\]", input_text)

    # Create a mapping of CIDs to links
    cid_link_mapping = dict(zip(cids, links))

    # Replace placeholders in the input text
    for cid, link in cid_link_mapping.items():
        input_text = input_text.replace(f"[cid:{cid}]", f'<a href="{link}" target="_blank"><img src="{cid}.png" alt="Image"></a>')

    # Convert plain text line breaks to HTML line breaks
    html_content = input_text.replace("\n", "<br>").replace("&lt;", "<").replace("&gt;", ">")

    # Wrap the content in HTML structure
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Content</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
            }}
            a img {{
                height: 20px;
                margin: 0 5px;
            }}
        </style>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    return html_template

def convert_plaintext_to_html(plain_text):
    """
    Converts plain text into basic HTML format.
    """
    import html
    escaped_text = html.escape(plain_text)
    return escaped_text.replace("\n", "<br>")

# def save_attachment(part, attachments_folder):
#     """
#     Save email attachment to the specified folder.
#     """
#     filename = part.get_filename()
#     if not filename:
#         return None

#     # Ensure the attachments folder exists
#     if not os.path.exists(attachments_folder):
#         os.makedirs(attachments_folder)

#     # Save the attachment
#     file_path = os.path.join(attachments_folder, filename)
#     with open(file_path, "wb") as attachment_file:
#         attachment_file.write(part.get_payload(decode=True))
    
#     return file_path

def decode_decrypt(encoded_string):
    decoded_bytes = base64.b64decode(encoded_string)
    decoded_string = decoded_bytes.decode('utf-8')
    return decoded_string

def encrypt_pwd(data):
    encoded_data = base64.b64encode(data.encode("utf-8"))

# Convert bytes to string for easier readability
    encoded_string = encoded_data.decode("utf-8")
    return encoded_string
def generate_ssha512(password, salt=None):
    """
    Generate an SSHA512 hash for a given password.

    :param password: The original password to hash
    :param salt: Optional salt (randomly generated if not provided)
    :return: SSHA512 hashed password
    """
    if not salt:
        salt = os.urandom(16)  # Generate 16 bytes of random salt

    password_bytes = password.encode('utf-8')
    ssha512_hasher = hashlib.sha512()
    ssha512_hasher.update(password_bytes + salt)
    ssha512_digest = ssha512_hasher.digest()

    # Combine the digest and salt, then encode in Base64
    ssha512_encoded = base64.b64encode(ssha512_digest + salt).decode('utf-8')

    # Wrap the result in {SSHA512}
    ssha512_result = f"{{SSHA512}}{ssha512_encoded}"
    return ssha512_result


# Create Mailbox Directory
def create_mailbox_directory(base_dir, domain, username):
    timestamp = datetime.now().strftime("%Y.%m.%d.%H.%M.%S")
    full_username = f"{username}-{timestamp}"
    mailbox_path = os.path.join(base_dir,domain, full_username[0], full_username[1], full_username[2], full_username, "Maildir")
    subdirs = ["cur", "new", "tmp"]
    dovecot_files = [
        "dovecot.index.cache",
        "dovecot.index.log",
        "dovecot-uidlist",
        "dovecot-uidvalidity",
    ]

    try:
        # Create directories and files
        for subdir in subdirs:
            os.makedirs(os.path.join(mailbox_path, subdir), exist_ok=True)
        for file in dovecot_files:
            open(os.path.join(mailbox_path, file), 'a').close()
        print(mailbox_path)
        set_directory_permissions(mailbox_path)
        return mailbox_path
    except Exception as e:
        raise RuntimeError(f"Error creating mailbox directory: {e}")
    
def set_directory_permissions(path_new):
    # """
    # Sets ownership and permissions for a mailbox directory.
    
    # Args:
    #     path (str): The path to set permissions for.
    # """
    # vmail_uid = 2000  # UID of the 'vmail' user
    # vmail_gid = 2000  # GID of the 'vmail' group

    # try:
    #     # Ensure the top-level directory ownership and permissions are correct
    #     os.chown(path, vmail_uid, vmail_gid)
    #     os.chmod(path, stat.S_IRWXU | stat.S_IRWXG)  # rwx for owner and group, no access for others

    #     # Recursively set ownership and permissions for subdirectories and files
    #     for root, dirs, files in os.walk(path):
    #         for directory in dirs:
    #             dir_path = os.path.join(root, directory)
    #             os.chown(dir_path, vmail_uid, vmail_gid)
    #             os.chmod(dir_path, stat.S_IRWXU | stat.S_IRWXG)  # rwx for owner and group

    #         for file in files:
    #             file_path = os.path.join(root, file)
    #             os.chown(file_path, vmail_uid, vmail_gid)
    #             os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)  # rw for owner and group

    #     print(f"Successfully set permissions for: {path}")

    # except PermissionError as e:
    #     raise RuntimeError(f"Permission error: {e}")
    # except Exception as e:
    #     raise RuntimeError(f"Unexpected error: {e}")
    """
    Sets ownership and permissions for a mailbox directory.
    Grants write permission to the user and group.
    
    Args:
        path (str): The path to set permissions for.
    """
    path, last_component = os.path.split(path_new)
    vmail_uid = 2000  # UID of the 'vmail' user
    vmail_gid = 2000  # GID of the 'vmail' group

    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")

    try:
        print(f"Before chown: {os.stat(path)}")
        # Set ownership and permissions for the top-level directory
        os.chown(path, vmail_uid, vmail_gid)
        os.chmod(path, 0o755)  # rwxr-xr-x for user, rx for group and others
        print(f"After chown: {os.stat(path)}")

        # Recursively set ownership and permissions for subdirectories and files
        for root, dirs, files in os.walk(path):
            for directory in dirs:
                dir_path = os.path.join(root, directory)
                try:
                    print(f"Setting permissions for directory: {dir_path}")
                    os.chown(dir_path, vmail_uid, vmail_gid)
                    os.chmod(dir_path, 0o755)  # rwxr-xr-x for user, rx for group and others
                    print(f"Permissions set for directory: {dir_path}")
                except Exception as e:
                    print(f"Failed to set permissions for directory: {dir_path}. Error: {e}")

            for file in files:
                file_path = os.path.join(root, file)
                try:
                    print(f"Setting permissions for file: {file_path}")
                    os.chown(file_path, vmail_uid, vmail_gid)
                    os.chmod(file_path, 0o644)  # rw-r--r-- for user, r for group and others
                    print(f"Permissions set for file: {file_path}")
                except Exception as e:
                    print(f"Failed to set permissions for file: {file_path}. Error: {e}")

    except PermissionError as e:
        raise RuntimeError(f"Permission error: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {e}")

@app.route('/api/add_user', methods=['POST'])
def add_user_from_form():
    try:
        # Parse form data from request
        form = request.json
        domain = form.get('domainName')
        conn = None
        print(form)
        # Get domain name and username
        mail_domain = form_utils.get_domain_name(form)
        print(mail_domain)
        print(domain)
        mail_username = form.get('username')
        if mail_username:
            mail_username = mail_username.strip().lower()
        else:
            return jsonify(success=False, message='INVALID_ACCOUNT')

        mail = f"{mail_username}@{mail_domain}"

        if mail_domain != domain:
            return jsonify(success=False, message='PERMISSION_DENIED')

        if not iredutils.is_auth_email(mail):
            return jsonify(success=False, message='INVALID_MAIL')

        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        # Check if the email already exists
        if sql_lib_general.is_email_exists(mail=mail, conn=conn):
            return jsonify(success=False, message='ALREADY_EXISTS')
        print(conn)
        print(domain)
        # Get domain profile
        qr_profile = sql_lib_domain.profile(conn=conn, domain=domain)
        print(qr_profile)
        if qr_profile[0]:
            domain_profile = qr_profile[1]
            domain_settings = sqlutils.account_settings_string_to_dict(domain_profile['settings'])
        else:
            return jsonify(success=False, message=qr_profile[1])

        # Check account limit
        num_exist_accounts = sql_lib_admin.num_managed_users(conn=conn, domains=[domain])

        if domain_profile.mailboxes == -1:
            return jsonify(success=False, message='NOT_ALLOWED')
        elif domain_profile.mailboxes > 0 and domain_profile.mailboxes <= num_exist_accounts:
            return jsonify(success=False, message='EXCEEDED_DOMAIN_ACCOUNT_LIMIT')

        # Get quota from form
        quota = str(form.get('mailQuota', 0)).strip()
        try:
            quota = int(quota)
        except ValueError:
            quota = 0

        # Get password from form
        pw_hash = form.get('password_hash', '')
        newpw = form.get('newpw', '')
        confirmpw = form.get('confirmpw', '')
        pwdbcrypt = encrypt_pwd(newpw)
        if pw_hash:
            if not iredpwd.is_supported_password_scheme(pw_hash):
                return jsonify(success=False, message='INVALID_PASSWORD_SCHEME')
            passwd = pw_hash
        else:
            min_passwd_length = domain_settings.get('min_passwd_length', 0)
            max_passwd_length = domain_settings.get('max_passwd_length', 0)

            qr_pw = iredpwd.verify_new_password(newpw, confirmpw, min_passwd_length, max_passwd_length)
            if qr_pw[0]:
                pwscheme = None
                if settings.STORE_PASSWORD_IN_PLAIN_TEXT:
                    pwscheme = 'PLAIN'
                passwd = iredpwd.generate_password_hash(qr_pw[1], pwscheme=pwscheme)
            else:
                return jsonify(success=False, message=qr_pw[1])

        # Get display name from form
        cn = form_utils.get_single_value(form, input_name='cn', default_value='')

        # Get preferred language
        preferred_language = form_utils.get_language(form)
        if preferred_language not in iredutils.get_language_maps():
            preferred_language = ''

        # Get storage base directory and maildir
        _storage_base_directory = settings.storage_base_directory
        splited_sbd = _storage_base_directory.rstrip('/').split('/')
        storage_node = splited_sbd.pop()
        storage_base_directory = '/'.join(splited_sbd)
        maildir = iredutils.generate_maildir_path(mail)

        mailbox_maildir = form.get('maildir', '').lower().rstrip('/')
        if mailbox_maildir and os.path.isabs(mailbox_maildir):
            _splited = mailbox_maildir.rstrip('/').split('/')
            storage_base_directory = '/' + _splited[0]
            storage_node = _splited[1]
            maildir = '/'.join(_splited[2:])

        record = {
            'domain': domain,
            'username': mail,
            'password': passwd,
            "pwdbcrypt":pwdbcrypt,
            'name': cn,
            'quota': quota,
            'storagebasedirectory': storage_base_directory,
            'storagenode': storage_node,
            'maildir': maildir,
            'language': preferred_language,
            'passwordlastchange': iredutils.get_gmttime(),
            'created': iredutils.get_gmttime(),
            'active': 1
        }

        # Always store plain password in another attribute
        if settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR:
            record[settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR] = newpw

        # Store the new user in the SQL database
        conn.insert('mailbox', **record)

        # Create an entry in `vmail.forwardings`
        conn.insert('forwardings',
                    address=mail,
                    forwarding=mail,
                    domain=domain,
                    dest_domain=domain,
                    is_forwarding=1,
                    active=1)

        log_activity(msg=f"Create user: {mail}.", domain=domain, event='create')
        return jsonify(success=True, message="User created successfully.")

    except Exception as e:
        return jsonify(success=False, message=str(e))



@app.route('/api/register', methods=['POST'])
def register():
    try:
        # Collect data from the request JSON
        data = request.json
        username = data.get('username')
        password = data.get('password')
        confirmpw = data.get('confirmpassword')
        pwdbcrypt = encrypt_pwd(password)
        name = data.get('name')
        language = data.get('language')
        mailbox_format = data.get('mailboxformat')
        mailbox_folder = data.get('mailboxfolder')
        storage_base_directory = data.get('storagebasedirectory')
        storage_node = data.get('storagenode')
        maildir = data.get('maildir')
        quota = data.get('quota')
        domain = data.get('domain')
        transport = data.get('transport')
        department = data.get('department')
        rank = data.get('rank')
        employee_id = data.get('employeeid')
        is_admin = data.get('isadmin', True)
        is_global_admin = data.get('isglobaladmin', False)
        pw_hash = data.get('password_hash', '')
        store_password_in_plain_text = True

        # Hash password
        salt = os.urandom(16)
        hashed_password = generate_ssha512(password, salt)

        maildir = create_mailbox_directory(BASE_MAILDIR_MAIN, domain, username)
        maildir_new = maildir.removeprefix(BASE_MAILDIR_MAIN).lstrip("/")
        # data = {
        #     'username': 'rajasekhar.k1223@mibook.com',
        #     'password': 'pbkdf2:sha256:1000000$4JL57pUI2cOUidOP$61b076e40d6beab30232e31793d9e241e16294d00fec2a1db36348a36c453a0d',
        #     'name': 'rajasekhar kanamaluri',
        #     'language': '',
        #     'mailbox_format': 'maildir',
        #     'mailbox_folder': 'Maildir',
        #     'storage_base_directory': '/var/vmail',
        #     'storage_node': 'vmail1',
        #     'maildir': '',
        #     'quota': 0,
        #     'domain': 'mibook.com',
        #     'transport': '',
        #     'department': '',
        #     'rank': 'normal',
        #     'employee_id': '',
        #     'is_admin': False,
        #     'is_global_admin': False,
        #     'enable_smtp': True,
        #     'enable_smtp_secured': True,
        #     'enable_pop3': True,
        #     'enable_pop3_secured': True,
        #     'enable_pop3_tls': True,
        #     'enable_imap': True,
        #     'enable_imap_secured': True,
        #     'enable_imap_tls': True,
        #     'enable_deliver': True,
        #     'enable_lda': True,
        #     'enable_managesieve': True,
        #     'enable_managesieve_secured': True,
        #     'enable_sieve': True,
        #     'enable_sieve_secured': True,
        #     'enable_sieve_tls': True,
        #     'enable_internal': True,
        #     'enable_doveadm': True,
        #     'enable_lib_storage': True,
        #     'enable_quota_status': True,
        #     'enable_indexer_worker': True,
        #     'enable_lmtp': True,
        #     'enable_dsync': True,
        #     'enable_sogo': True,
        #     'enable_sogo_webmail': True,
        #     'enable_sogo_calendar': True,
        #     'enable_sogo_activesync': True,
        #     'allow_nets': 'y',
        #     'disclaimer': 'y',
        #     'settings': 'y',
        #     'password_last_change': datetime(1970, 1, 1, 1, 1, 1),
        #     'created': datetime(2024, 11, 11, 2, 38, 30),
        #     'modified': datetime(1970, 1, 1, 1, 1, 1),
        #     'expired': datetime(9999, 12, 31, 0, 0, 0),
        #     'active': True
        # }
        
        # # Extract the data from the input (defaulting to existing values if not provided)
        # user.username = data.get('username', user.username)
        # user.password = generate_password_hash(data.get('password', user.password), method='pbkdf2:sha256')  # hash the password if provided
        # user.name = data.get('name', user.name)
        # user.language = data.get('language', user.language)
        # user.mailboxformat = data.get('mailboxformat', user.mailboxformat)
        # user.mailboxfolder = data.get('mailboxfolder', user.mailboxfolder)
        # user.storagebasedirectory = data.get('storagebasedirectory', user.storagebasedirectory)
        # user.storagenode = data.get('storagenode', user.storagenode)
        # user.maildir = data.get('maildir', user.maildir)
        # user.quota = data.get('quota', user.quota)
        # user.domain = data.get('domain', user.domain)
        # user.transport = data.get('transport', user.transport)
        # user.department = data.get('department', user.department)
        # user.rank = data.get('rank', user.rank)
        # user.employeeid = data.get('employeeid', user.employeeid)
        # user.isadmin = data.get('isadmin', user.isadmin)
        # user.isglobaladmin = data.get('isglobaladmin', user.isglobaladmin)

        # # Optionally set boolean fields
        # user.enablesmtp = data.get('enablesmtp', user.enablesmtp)
        # user.enablesmtpsecured = data.get('enablesmtpsecured', user.enablesmtpsecured)
        # user.enablepop3 = data.get('enablepop3', user.enablepop3)
        # user.enablepop3secured = data.get('enablepop3secured', user.enablepop3secured)
        # user.enablepop3tls = data.get('enablepop3tls', user.enablepop3tls)
        # user.enableimap = data.get('enableimap', user.enableimap)
        # user.enableimapsecured = data.get('enableimapsecured', user.enableimapsecured)
        # user.enableimaptls = data.get('enableimaptls', user.enableimaptls)
        # user.enabledeliver = data.get('enabledeliver', user.enabledeliver)
        # user.enablelda = data.get('enablelda', user.enablelda)
        # user.enablemanagesieve = data.get('enablemanagesieve', user.enablemanagesieve)
        # user.enablemanagesievesecured = data.get('enablemanagesievesecured', user.enablemanagesievesecured)
        # user.enablesieve = data.get('enablesieve', user.enablesieve)
        # user.enablesievesecured = data.get('enablesievesecured', user.enablesievesecured)
        # user.enablesievetls = data.get('enablesievetls', user.enablesievetls)
        # user.enableinternal = data.get('enableinternal', user.enableinternal)
        # user.enabledoveadm = data.get('enabledoveadm', user.enabledoveadm)
        # user.enablelib_storage = data.get('enablelib_storage', user.enablelib_storage)
        # user.enablequota_status = data.get('enablequota_status', user.enablequota_status)
        # user.enableindexer_worker = data.get('enableindexer_worker', user.enableindexer_worker)
        # user.enablelmtp = data.get('enablelmtp', user.enablelmtp)
        # user.enabledsync = data.get('enabledsync', user.enabledsync)
        # user.enablesogo = data.get('enablesogo', user.enablesogo)
        # user.enablesogowebmail = data.get('enablesogowebmail', user.enablesogowebmail)
        # user.enablesogocalendar = data.get('enablesogocalendar', user.enablesogocalendar)
        # user.enablesogoactivesync = data.get('enablesogoactivesync', user.enablesogoactivesync)
        # user.allow_nets = data.get('allow_nets', user.allow_nets)
        # user.disclaimer = data.get('disclaimer', user.disclaimer)
        # user.settings = data.get('settings', user.settings)

        # # Optional: Update password last change and modification time
        # if 'password' in data:
        #     user.passwordlastchange = datetime.utcnow()
        
        # # Update the 'modified' timestamp on every update
        # user.modified = datetime.utcnow()
        # if qr_pw[0] is True:
        #     pwscheme = None
            # if 'store_password_in_plain_text' in form and settings.STORE_PASSWORD_IN_PLAIN_TEXT:
        # pwscheme = 'PLAIN'
        # passwd = iredpwd.generate_password_hash(password, pwscheme=pwscheme)
        # else:
        #     return qr_pw
        
        if pw_hash:
            if not iredpwd.is_supported_password_scheme(pw_hash):
                return (False, 'INVALID_PASSWORD_SCHEME')

            passwd = pw_hash
        else:
            # Get password length limit from domain profile or global setting.
            # min_passwd_length = domain_settings.get('min_passwd_length', 0)
            # max_passwd_length = domain_settings.get('max_passwd_length', 0)
            min_passwd_length = 0
            max_passwd_length = 0

            qr_pw = iredpwd.verify_new_password(password,
                                                confirmpw,
                                                min_passwd_length=min_passwd_length,
                                                max_passwd_length=max_passwd_length)

            if qr_pw[0] is True:
                pwscheme = None
                if store_password_in_plain_text and settings.STORE_PASSWORD_IN_PLAIN_TEXT:
                    pwscheme = 'PLAIN'
                passwd = iredpwd.generate_password_hash(qr_pw[1], pwscheme=pwscheme)
            else:
                return qr_pw
            
        # Prepare additional attributes dynamically
        # additional_attributes = {}
        # if settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR:
        #     additional_attributes[settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR] = newpw

        # Fetch settings from the database
        # db_settings = iredutils.get_settings_from_db()

        # # Retrieve mailbox format and folder, with fallback to database settings
        # _mailbox_format = data.get('mailboxFormat', db_settings['mailbox_format']).lower()
        # _mailbox_folder = data.get('mailboxFolder', db_settings['mailbox_folder'])

        # # Validate mailbox format and folder
        # mailbox_format = _mailbox_format if iredutils.is_valid_mailbox_format(_mailbox_format) else None
        # mailbox_folder = _mailbox_folder if iredutils.is_valid_mailbox_folder(_mailbox_folder) else None

        # # Prepare the record object with plain password, if required
        # record = {}
        # if settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR:
        #     record[settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR] = newpw

        # # Prepare service enable/disable flags
        # disabled_mail_services = domain_settings.get('disabled_mail_services', [])
        # enabled_services = {f"enable{srv}": 0 for srv in disabled_mail_services}

        # # Globally disabled services
        # for srv in settings.ADDITIONAL_DISABLED_USER_SERVICES:
        #     enabled_services[f"enable{srv}"] = 0

        # # Globally enabled services
        # for srv in settings.ADDITIONAL_ENABLED_USER_SERVICES:
        #     enabled_services[f"enable{srv}"] = 1

        # Create a new Mailbox instance
        new_mailbox = Mailbox(
            username=username+'@'+domain,
            password=passwd,
            pwdbcrypt=pwdbcrypt,
            name=name,
            language=language,
            mailboxformat=mailbox_format,
            mailboxfolder=mailbox_folder,
            storagebasedirectory=storage_base_directory,
            storagenode=storage_node,
            maildir=maildir_new,
            quota=quota,
            domain=domain,
            transport=transport,
            department=department,
            rank=rank,
            employeeid=employee_id,
            isadmin=is_admin,
            isglobaladmin=is_global_admin,
            enablesmtp=True,
            enablesmtpsecured= True,
            enablepop3= True,
            enablepop3secured= True,
            enablepop3tls= True,
            enableimap= True,
            enableimapsecured= True,
            enableimaptls= True,
            enabledeliver= True,
            enablelda= True,
            enablemanagesieve= True,
            enablemanagesievesecured= True,
            enablesieve=True,
            enablesievesecured= True,
            enablesievetls= True,
            enableinternal= True,
            enabledoveadm= True,
            enablelib_storage=True,  # Use the Python-friendly attribute name
            enablequota_status=True,
            enableindexer_worker=True,
            enablelmtp= True,
            enabledsync= True,
            enablesogo= True,
            enablesogowebmail= 'y',
            enablesogocalendar= 'y',
            enablesogoactivesync= 'y',
            allow_nets= '',
            disclaimer= '',
            settings= '',
            passwordlastchange= datetime(1970, 1, 1, 1, 1, 1),
            created= datetime(2024, 11, 11, 2, 38, 30),
            modified= datetime(1970, 1, 1, 1, 1, 1),
            expired=datetime(9999, 12, 31, 0, 0, 0),
            # **additional_attributes  # Include additional attributes dynamically
            # Enable fields can be added here similarly, or default values can be used
        )
        
        new_forwarding = Forwarding(
        address=username+'@'+domain,
        forwarding=username+'@'+domain,
        domain=domain,
        dest_domain=domain,
        is_maillist=0,
        is_list=0,
        is_forwarding=1,
        is_alias=0,
        active=1
    )
        # Save to MariaDB
        db.session.add(new_mailbox)
        db.session.add(new_forwarding)
        db.session.commit()

        # Optionally save to MongoDB
        mongo_collection = mongo_db['mailboxes']
        mongo_collection.insert_one({
            'username': username,
            'password': passwd,
            'pwdbycrypt':pwdbcrypt,
            'name': name,
            'language': language,
            'mailbox_format': mailbox_format,
            # Add other fields here if necessary
        })

        return jsonify({'message': 'Mailbox registered successfully'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400

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
            return jsonify({'message': 'Login successful', 'token': token, 'userId': user.id,'username':user.username,'bcrypt':user.pwdbcrypt}), 200
        
        return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 400




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
@app.route('/api/send_email', methods=['POST'])
@jwt_required()
def send_email():
    userId = request.form.get('userId')
    user_data = Mailbox.query.filter_by(id=userId).first()
    mail_username = user_data.username
    plain_password = decode_decrypt(user_data.pwdbcrypt)
    to_email = request.form.get('to_email')
    cc_email = request.form.get('cc_email')
    subject = request.form.get('subject')
    body = request.form.get('body')
    body_format = request.form.get('body_format', 'plain')
    print(to_email)
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
    print(msg)
    print(app.config['MAIL_PORT'])
    print(app.config['SMTP_SERVER'])
    print(app.config['USE_SSL'])
    #print(server = smtplib.SMTP_SSL(app.config['SMTP_SERVER'], app.config['MAIL_PORT']))
    try:
        # Establish a connection to the SMTP server
        if app.config['USE_SSL']:
            server = smtplib.SMTP_SSL(app.config['SMTP_SERVER'], app.config['MAIL_PORT'])
        else:
            server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['MAIL_PORT'])
            server.starttls()
        print(mail_username)
        print(plain_password)
        server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['MAIL_PORT'])
        print(server.starttls())
        # Login using the plain_password in the password field
        server.login(mail_username, str(plain_password))
        print(server)
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

def save_attachment(part, username, msg_queue_id, timestamp, attachments_folder=ATTACHMENTS_FOLDER):
    """
    Save the attachment from the email part to the specified public folder and return the URL.
    Skip saving if a file with the same name is already available via the link.
    """
    filename = part.get_filename()
    if filename:
        # Replace spaces in the filename with underscores
        filename = filename.replace(" ", "_")
        
        # Ensure the filename is URL-safe
        filename = quote(filename)

        # Replace spaces in the username with underscores
        username = username.replace(" ", "_")

        # Define the URL and file path
        attachment_url = f"http://imailler.com/attachments/{username}/{msg_queue_id}/{timestamp}/{filename}"
        filepath = os.path.join(attachments_folder, f"{username}_{msg_queue_id}_{timestamp}_{filename}")

        # Check if the file exists based on the filepath
        if os.path.exists(filepath):
            print(f"File {filename} already exists at {attachment_url}. Skipping save.")
            return attachment_url

        # Save the attachment
        with open(filepath, "wb") as f:
            f.write(part.get_payload(decode=True))

        print(f"File {filename} saved at {attachment_url}.")
        return attachment_url
    return None

# def fetch_emails(maildir_path, folder="new", attachments_folder=ATTACHMENTS_FOLDER):
#     """
#     Fetch emails from the specified folder and process attachments.
#     """
#     data = maildir_path
#     folder_path = os.path.join(data["maildir_path"], folder)

#     if not os.path.exists(folder_path):
#         return {"error": f"Folder not found: {folder}"}

#     emails = []

#     try:
#         for filename in os.listdir(folder_path):
#             filepath = os.path.join(folder_path, filename)

#             # Open the file in binary mode ("rb") instead of text mode ("r")
#             with open(filepath, "rb") as f:
#                 msg = BytesParser(policy=default).parse(f)

#             # Extracting email data
#             email_data = {
#                 "from": msg.get("From"),
#                 "to": msg.get("To"),
#                 "subject": msg.get("Subject"),
#                 "date": msg.get("Date"),
#                 "timestamp": None,  # To store Unix timestamp for sorting
#                 "body": "",
#                 "attachments": [],
#                 "username": msg.get("From").split('<')[0].strip(),  # Extracting username
#                 "msg_queue_id": str(uuid.uuid4()),  # Generating a unique queue ID for the message
#             }

#             # Convert date to timestamp
#             try:
#                 if email_data["date"]:
#                     parsed_date = datetime.strptime(email_data["date"], "%a, %d %b %Y %H:%M:%S %z")
#                     email_data["timestamp"] = parsed_date.timestamp()
#                 else:
#                     email_data["timestamp"] = 0  # Default to 0 if no date
#             except ValueError:
#                 email_data["timestamp"] = 0  # Handle invalid date format gracefully

#             # Process email body
#             if msg.is_multipart():
#                 for part in msg.walk():
#                     content_type = part.get_content_type()
#                     disposition = part.get("Content-Disposition")

#                     if content_type == "text/html" and not disposition:
#                         email_data["body"] = part.get_payload(decode=True).decode("utf-8", errors="ignore")
#                     elif content_type.startswith("application/") or part.get_filename():  # Handle attachments
#                         attachment_url = save_attachment(part, email_data["username"], email_data["msg_queue_id"], email_data["timestamp"], attachments_folder)
#                         if attachment_url:
#                             email_data["attachments"].append(attachment_url)
#             else:
#                 email_data["body"] = msg.get_payload(decode=True).decode("utf-8", errors="ignore")

#             # Add email data to the list
#             emails.append(email_data)

#         # Sort emails by timestamp in descending order
#         emails = sorted(emails, key=lambda x: x["timestamp"], reverse=True)

#     except Exception as e:
#         return {"error": f"Error reading emails: {str(e)}"}

#     return emails

# def save_attachment(part, username, msg_queue_id, timestamp, attachments_folder):
#     filename = part.get_filename()
#     if filename:
#         safe_filename = f"{msg_queue_id}_{timestamp}_{filename}"
#         file_path = os.path.join(attachments_folder, safe_filename)
#         with open(file_path, "wb") as f:
#             f.write(part.get_payload(decode=True))
#         return file_path
#     return None

# def store_in_mongodb(email_data):
#     client = MongoClient(MONGO_URI)
#     db = client[MONGO_DB_NAME]
#     collection = db[MONGO_COLLECTION_NAME]
#     collection.insert_one(email_data)
#     client.close()

def store_in_mysql(email_data):
    try:
        # Validate and parse the date
        if "date" in email_data and email_data["date"]:
            try:
                email_date = datetime.strptime(email_data["date"], "%a, %d %b %Y %H:%M:%S %z").date()
            except ValueError:
                print(f"Invalid date format: {email_data['date']}. Using today's date instead.")
                email_date = datetime.now().date()
        else:
            print("Date not provided. Using today's date instead.")
            email_date = datetime.now().date()

        # Convert timestamp to current datetime if not provided
        email_timestamp = email_data.get("timestamp", datetime.now())

        # Convert attachments list to a JSON string
        attachments = json.dumps(email_data.get("attachments", []))

        # SQLAlchemy Query with Parameterized Values
        query = text("""
            INSERT INTO received_emails (
                msg_queue_id,
                sender,
                recipient,
                subject,
                body_type_html,
                body_type_plain,
                date,
                timestamp,
                attachments
            ) VALUES (
                :msg_queue_id,
                :sender,
                :recipient,
                :subject,
                :body_type_html,
                :body_type_plain,
                :date,
                :timestamp,
                :attachments
            )
        """)

        # Execute query with parameter binding
        db.session.execute(query, {
            "msg_queue_id": email_data["msg_queue_id"],
            "sender": email_data["from"],
            "recipient": email_data["to"],
            "subject": email_data.get("subject", ""),
            "body_type_html": email_data.get("body_type_html", ""),
            "body_type_plain": email_data.get("body_type_plain", ""),
            "date": email_date,
            "timestamp": email_timestamp,
            "attachments": attachments
        })
        db.session.commit()
        print("Email data successfully inserted.")
    except Exception as e:
        print(f"An error occurred: {e}")

def move_email_to_new_path(filepath, new_base_path):
    # filename = os.path.basename(filepath)
    # # new_folder = os.path.join(os.path.dirname(filepath), new_base_path)
    # new_folder = os.path.join(filepath, new_base_path)
    # os.makedirs(new_folder, exist_ok=True)
    # new_path = os.path.join(filepath, new_base_path)
    # file_path_f = os.path.join(filepath, 'new/')
    # return file_path_f
    # shutil.move(file_path_f, new_path)
    # return new_path
    base_path = filepath
    new_folder = os.path.join(base_path, "new")
    cur_folder = os.path.join(base_path, "cur")

    # Ensure the 'cur' folder exists
    os.makedirs(cur_folder, exist_ok=True)

    moved_files = []

    # Move all files from 'new' to 'cur'
    for filename in os.listdir(new_folder):
        src_path = os.path.join(new_folder, filename)
        dest_path = os.path.join(cur_folder, filename)

        # Check if it's a file before moving
        if os.path.isfile(src_path):
            shutil.move(src_path, dest_path)
            moved_files.append(dest_path)
            print(f"Moved: {src_path} -> {dest_path}")
        else:
            print(f"Skipped: {src_path} (not a file)")

    return moved_files

def fetch_emails(maildir_path, folder="new", attachments_folder=ATTACHMENTS_FOLDER):
    
    folder_path = os.path.join(maildir_path, folder)
    if not os.path.exists(folder_path):
        return {"error": f"Folder not found: {folder}"}

    emails = []

    try:
        for filename in os.listdir(folder_path):
            filepath = os.path.join(folder_path, filename)

            with open(filepath, "rb") as f:
                msg = BytesParser(policy=default).parse(f)

            email_data = {
                "from": msg.get("From"),
                "to": msg.get("To"),
                "subject": msg.get("Subject"),
                "date": msg.get("Date"),
                "timestamp": None,
                "body_type_html": "",
                "body_type_plain": "",
                "attachments": [],
                "username": msg.get("From").split('<')[0].strip(),
                "msg_queue_id": str(uuid.uuid4()),
            }

            try:
                if email_data["date"]:
                    parsed_date = datetime.strptime(email_data["date"], "%a, %d %b %Y %H:%M:%S %z")
                    email_data["timestamp"] = parsed_date.timestamp()
                else:
                    email_data["timestamp"] = 0
            except ValueError:
                email_data["timestamp"] = 0

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disposition = part.get("Content-Disposition")

                    if content_type == "text/plain" and not disposition:
                        email_data["body_type_plain"] += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    elif content_type == "text/html" and not disposition:
                        email_data["body_type_html"] += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    elif content_type.startswith("application/") or part.get_filename():
                        attachment_url = save_attachment(part, email_data["username"], email_data["msg_queue_id"], email_data["timestamp"], attachments_folder)
                        if attachment_url:
                            email_data["attachments"].append(attachment_url)
            else:
                email_data["body_type_plain"] = msg.get_payload(decode=True).decode("utf-8", errors="ignore")

            mongo_collection = mongo_db['received_email']
            mongo_collection.insert_one(email_data)
            store_in_mysql(email_data)

            new_path = move_email_to_new_path(maildir_path, NEW_PATH)
            email_data["new_path"] = new_path

            emails.append(email_data)

        emails = sorted(emails, key=lambda x: x["timestamp"], reverse=True)

    except Exception as e:
        return {"error": f"Error reading emails: {str(e)}"}

    return emails
# Function to serialize emails with ObjectId
def serialize_emails(emails):
    """Converts ObjectId fields to strings for JSON serialization."""
    for email in emails:
        if "_id" in email and isinstance(email["_id"], ObjectId):
            email["_id"] = str(email["_id"])
    return emails

@app.route("/api/email", methods=["GET"])
@jwt_required()
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
        emails = fetch_emails(maildir_path['maildir_path'], folder)
        if "error" in emails:
            return jsonify({"error": emails["error"]}), 404
         # Serialize emails to ensure JSON compatibility
        serialized_emails = serialize_emails(emails)
        return jsonify({"email": email_address, "folder": folder, "emails": serialized_emails})
    
    else:
        return jsonify({"error": f"Invalid action: {action}"}), 400


def get_folder_name(email_address):
    """
    Generate the folder path based on the email address.
    Example: rajasekhark@imailler.com -> /var/vmail/vmail1/imailler.com/r/a/j/rajasekhark-2024.11.21.06.27.17/Maildir
    """
    try:
        # Split email into user and domain parts
        # user_part, domain = email_address.split("@")
        
        
        # # Generate initials based on the first three characters of the user part
        # initials = "/".join(user_part[:3])
        
        # # Look for the folder in the actual directory
        # domain_path = os.path.join(BASE_MAILDIR_MAIN, domain)
        # user_path = os.path.join(domain_path, initials)
        
        mailbox = Mailbox.query.filter_by(username=email_address).first()
        domain_path = os.path.join(BASE_MAILDIR_MAIN, mailbox.maildir)
        # user_path = os.path.join(domain_path, initials)
        # return domain_path
        # Find the exact folder matching the user and timestamp format
        # possible_folders = [
        #     folder for folder in os.listdir(user_path)
        #     # if folder.startswith(user_part) and "Maildir" in folder
        # ]
        
        # if not possible_folders:
        #     return {"error": "Folder not found for the given email address."}
        
        # # Assuming there's only one match
        # folder_name = possible_folders[0]
        # maildir_path = os.path.join(user_path, folder_name, "Maildir")
        
        return {"maildir_path": domain_path}
    
    except Exception as e:
        return {"error": f"Error processing email address '{email_address}': {str(e)}"}

@app.route("/api/get-folder-name", methods=["GET"])
@jwt_required()
def folder_name_api():
    """
    API to get the folder name based on the email address.
    """
    email_address = request.args.get("email")
    if not email_address:
        return jsonify({"error": "Email address is required."}), 400
    
    result = get_folder_name(email_address)
    return jsonify(result)

@app.route("/api/get-emails", methods=["GET"])
@jwt_required()
def get_emails_by_user():
    """
    API to get emails based on the email address with decryption for specific fields.
    """
    email_address = request.args.get("email")
    if not email_address:
        return jsonify({"error": "Email address is required."}), 400
    
    mongo_db = mongo_client['mail_database']
    mongo_collection = mongo_db['emails']
    fields_to_encrypt = ["html_body"]  # Fields that need decryption

    # Define a helper function to convert MongoDB documents to JSON-serializable format
    def serialize_document(document):
        if isinstance(document, list):
            return [serialize_document(doc) for doc in document]
        elif isinstance(document, dict):
            return {
                key: str(value) if isinstance(value, ObjectId) else value
                for key, value in document.items()
            }
        return document

    # Decrypt specified fields if they exist
    def decrypt_fields(document):
        decrypted_document = {}
        for key, value in document.items():
            if key in fields_to_encrypt and isinstance(value, str):
                try:
                    decrypted_document[key] = cipher.decrypt(value.encode()).decode()
                except Exception as e:
                    print(f"Failed to decrypt field '{key}': {e}")
                    decrypted_document[key] = value  # Return encrypted data if decryption fails
            else:
                decrypted_document[key] = value
        return decrypted_document

    results = mongo_collection.find({"to": email_address}).sort("date", -1)
    
    documents = []
    for result in results:
        serialized_doc = serialize_document(result)
        decrypted_doc = decrypt_fields(serialized_doc)
        documents.append(decrypted_doc)

    # print("Decrypted Data:")
    # print(json.dumps(documents, indent=2, default=json_util.default))
     # Process and rename fields
    formatted_result = [
        {
            "subject": doc["subject"],
            "from": doc["from"],
            "to": doc["to"],
            "date": doc["date"],
            "msgId": doc["msgId"]
            
        }
        for doc in documents
    ]
    # print("Decrypted Data:")
    # print(json.dumps(documents, indent=2, default=json_util.default))
    
    return jsonify(formatted_result)


@app.route("/api/email-details", methods=["GET"])
@jwt_required()
def get_emails_by_msgId():
    """
    API to get emails based on the email address with decryption for specific fields.
    """
    msgId = request.args.get("msgId")
    if not msgId:
        return jsonify({"error": "Email address is required."}), 400
    
    mongo_db = mongo_client['mail_database']
    mongo_collection = mongo_db['emails']
    fields_to_encrypt = ["html_body"]  # Fields that need decryption

    # Define a helper function to convert MongoDB documents to JSON-serializable format
    def serialize_document(document):
        if isinstance(document, list):
            return [serialize_document(doc) for doc in document]
        elif isinstance(document, dict):
            return {
                key: str(value) if isinstance(value, ObjectId) else value
                for key, value in document.items()
            }
        return document

    # Decrypt specified fields if they exist
    def decrypt_fields(document):
        decrypted_document = {}
        for key, value in document.items():
            if key in fields_to_encrypt and isinstance(value, str):
                try:
                    decrypted_document[key] = cipher.decrypt(value.encode()).decode()
                except Exception as e:
                    print(f"Failed to decrypt field '{key}': {e}")
                    decrypted_document[key] = value  # Return encrypted data if decryption fails
            else:
                decrypted_document[key] = value
        return decrypted_document

    results = mongo_collection.find({"msgId": msgId},{"subject": 1, "from": 1,"date": 1,"to": 1,"msgId": 1,"html_body": 1, "_id": 0})
    
    documents = []
    for result in results:
        serialized_doc = serialize_document(result)
        decrypted_doc = decrypt_fields(serialized_doc)
        documents.append(decrypted_doc)

    # Process and rename fields
    formatted_result = [
        {
            "subject": doc["subject"],
            "from": doc["from"],
            "to": doc["to"],
            "date": doc["date"],
            "msgId": doc["msgId"],
            "htmlBody": doc["html_body"]
            
        }
        for doc in documents
    ]
    # print("Decrypted Data:")
    # print(json.dumps(documents, indent=2, default=json_util.default))
    
    return jsonify(formatted_result)



@app.route("/api/get-sent-emails", methods=["GET"])
@jwt_required()
def get_sent_emails_by_user():
    """
    API to get sent emails based on the sender's email address with decryption for specific fields.
    """
    email_address = request.args.get("email")
    if not email_address:
        return jsonify({"error": "Email address is required."}), 400
    
    mongo_db = mongo_client['mail_database']
    sent_collection = mongo_db['sent_emails']
    fields_to_encrypt = ["html_body"]  # Fields that need decryption

    # Define a helper function to convert MongoDB documents to JSON-serializable format
    def serialize_document(document):
        if isinstance(document, list):
            return [serialize_document(doc) for doc in document]
        elif isinstance(document, dict):
            return {
                key: str(value) if isinstance(value, ObjectId) else value
                for key, value in document.items()
            }
        return document

    # Decrypt specified fields if they exist
    def decrypt_fields(document):
        decrypted_document = {}
        for key, value in document.items():
            if key in fields_to_encrypt and isinstance(value, str):
                try:
                    decrypted_document[key] = cipher.decrypt(value.encode()).decode()
                except Exception as e:
                    print(f"Failed to decrypt field '{key}': {e}")
                    decrypted_document[key] = value  # Return encrypted data if decryption fails
            else:
                decrypted_document[key] = value
        return decrypted_document

    # Fetch sent emails
    try:
        results = sent_collection.find({"from": email_address}).sort("date", -1)
        
        documents = []
        for result in results:
            serialized_doc = serialize_document(result)
            decrypted_doc = decrypt_fields(serialized_doc)
            documents.append(decrypted_doc)
        
        return jsonify(documents), 200

    except Exception as e:
        print(f"Error retrieving sent emails: {e}")
        return jsonify({"error": "Failed to retrieve sent emails."}), 500

@app.route("/api/delete-email", methods=["DELETE"])
@jwt_required()
def delete_email_by_message_id():
    """
    API to delete an email based on the message-id.
    Before deletion, the email is moved to the 'trash' collection.
    """
    message_id = request.args.get("msgId")
    if not message_id:
        return jsonify({"error": "Message-ID is required."}), 400

    mongo_db = mongo_client['mail_database']
    emails_collection = mongo_db['emails']
    trash_collection = mongo_db['trash']

    try:
        # Find the email with the given message-id
        email_document = emails_collection.find_one({"msgId": message_id})
        
        if not email_document:
            return jsonify({"error": "Email with the given Message-ID not found."}), 404
        
        # Move the email document to the 'trash' collection
        trash_collection.insert_one(email_document)
        
        # Delete the email from the 'emails' collection
        emails_collection.delete_one({"msgId": message_id})
        
        return jsonify({"message": "Email moved to trash and deleted successfully."}), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({"error": "An error occurred while deleting the email."}), 500
    
@app.route("/api/get-trash-emails", methods=["GET"])
@jwt_required()
def get_trash_emails():
    """
    API to get emails from the trash folder.
    Supports optional filtering by email, date, or message-id.
    """
    email_address = request.args.get("email")
    message_id = request.args.get("message-id")
    date = request.args.get("date")  # Expected in 'YYYY-MM-DD' format
    
    mongo_db = mongo_client['mail_database']
    trash_collection = mongo_db['trash']

    query = {}

    if email_address:
        query["to"] = email_address
    if message_id:
        query["message-id"] = message_id
    if date:
        try:
            # Filter by date (assuming the date field is stored as ISODate in MongoDB)
            query["date"] = {
                "$gte": datetime.strptime(date, "%Y-%m-%d"),
                "$lt": datetime.strptime(date, "%Y-%m-%d") + timedelta(days=1)
            }
        except ValueError:
            return jsonify({"error": "Invalid date format. Use 'YYYY-MM-DD'."}), 400

    # Serialize MongoDB documents
    def serialize_document(document):
        if isinstance(document, list):
            return [serialize_document(doc) for doc in document]
        elif isinstance(document, dict):
            return {
                key: str(value) if isinstance(value, ObjectId) else value
                for key, value in document.items()
            }
        return document

    try:
        results = trash_collection.find(query).sort("date", -1)
        
        documents = []
        for result in results:
            documents.append(serialize_document(result))
        
        return jsonify(documents), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({"error": "Failed to retrieve emails from trash."}), 500

# API Endpoint for user logout
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    # Add the current token's JTI to the blocklist
    token = get_jwt()
    jti = token["jti"]  # JWT ID, a unique identifier for the token
    BLOCKLIST.add(jti)

    return jsonify({'message': 'Logged out successfully'}), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5001, debug=True)
