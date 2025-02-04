# -*- coding: utf-8 -*-
#
###############################################################
# DO NOT MODIFY THIS LINE, IT'S USED TO IMPORT DEFAULT SETTINGS.
from default_settings import *
###############################################################
# General settings.
#
# Site webmaster's mail address.
webmaster = "postmaster@imailler.com"

# Default language.
default_language = 'en_US'

# Database backend: mysql.
backend = 'mysql'

# Directory used to store mailboxes. Defaults to /var/vmail/vmail1.
# Note: This directory must be owned by 'vmail:vmail' with permission 0700.
storage_base_directory = "/var/vmail/vmail1"

# Default mta transport.
# There're 3 transports available in iRedMail:
#
#   1. dovecot: default LDA transport. Supported by all iRedMail releases.
#   2. lmtp:unix:private/dovecot-lmtp: LMTP (socket listener). Supported by
#                                      iRedMail-0.8.6 and later releases.
#   3. lmtp:inet:127.0.0.1:24: LMTP (TCP listener). Supported by iRedMail-0.8.6
#                              and later releases.
#
# Note: You can set per-domain or per-user transport in account profile page.
default_mta_transport = "dovecot"

# Min/Max admin password length. 0 means unlimited.
#   - min_passwd_length: at least 1 character is required.
# Normal admin can not set shorter/longer password lengths than global settings
# defined here.
min_passwd_length = 8
max_passwd_length = 0

#####################################################################
# Database used to store iRedAdmin data. e.g. sessions, log.
#
iredadmin_db_host = "127.0.0.1"
iredadmin_db_port = "3306"
iredadmin_db_name = "iredadmin"
iredadmin_db_user = "iredadmin"
iredadmin_db_password = "Dq3ycnUB0ynoLjucuuDTSyU0vwlpjUqo"

############################################
# Database used to store mail accounts.
#
vmail_db_host = "127.0.0.1"
vmail_db_port = "3306"
vmail_db_name = "vmail"
vmail_db_user = "vmailadmin"
vmail_db_password = "wjIN2rknEmYVqkR5T5rD1Jrx2KOEO51M"

##############################################################################
# Settings used for Amavisd-new integration. Provides spam/virus quaranting,
# releasing, etc.
#
# Log basic info of in/out emails into SQL (@storage_sql_dsn): True, False.
# It's @storage_sql_dsn setting in amavisd. You can find this setting
# in amavisd-new config files:
#   - On RHEL/CentOS:   /etc/amavisd.conf or /etc/amavisd/amavisd.conf
#   - On Debian/Ubuntu: /etc/amavis/conf.d/50-user.conf
#   - On FreeBSD:       /usr/local/etc/amavisd.conf
amavisd_enable_logging = True

amavisd_db_host = "127.0.0.1"
amavisd_db_port = "3306"
amavisd_db_name = "amavisd"
amavisd_db_user = "amavisd"
amavisd_db_password = "4T7xiX6GBkrHrg24luVu6RaMqQ4Svjpa"

# #### Quarantining ####
# Release quarantined SPAM/Virus mails: True, False.
# iRedAdmin-Pro will connect to @amavisd_db_host to release quarantined mails.
# How to enable quarantining in Amavisd-new:
# http://www.iredmail.org/docs/quarantining.html
amavisd_enable_quarantine = True

# Port of Amavisd protocol 'AM.PDP-INET'. Default is 9998.
# If Amavisd is not running on database server specified in amavisd_db_host,
# please set the server address in parameter `AMAVISD_QUARANTINE_HOST`.
# Default is '127.0.0.1'. Sample setting:
#AMAVISD_QUARANTINE_HOST = '192.168.1.1'
amavisd_quarantine_port = "9998"

# Enable per-recipient spam policy, white/blacklist.
amavisd_enable_policy_lookup = True

##############################################################################
# Settings used for iRedAPD integration. Provides throttling and more.
#
iredapd_enabled = True
iredapd_db_host = "127.0.0.1"
iredapd_db_port = "3306"
iredapd_db_name = "iredapd"
iredapd_db_user = "iredapd"
iredapd_db_password = "oTapzfqt9Jokn0XUBN9zLhzUIVJ2EoLl"

##############################################################################
# Settings used for mlmmj (mailing list manager) and mlmmjadmin integration.
#
# The API auth token required to access mlmmjadmin API.
mlmmjadmin_api_auth_token = ''

##############################################################################
# Place your custom settings below, you can override all settings in this file
# and libs/default_settings.py here.
#
DEFAULT_PASSWORD_SCHEME = 'SSHA512'
mlmmjadmin_api_auth_token = '8eH1mdCQeyweYSrJ3L4UdpYWH0VTwthi'
fail2ban_enabled = True
fail2ban_db_host = '127.0.0.1'
fail2ban_db_port = '3306'
fail2ban_db_name = 'fail2ban'
fail2ban_db_user = 'fail2ban'
fail2ban_db_password = 'jcVWnIcuoPdZ5jeSKUOiJRrnl5OE2Jbd'
