#!/usr/bin/env bash
# Lab installer: bypass Joomla web installer entirely. Load install SQL
# straight into MySQL, INSERT an admin user with a known bcrypt hash,
# write configuration.php from values, blow away installation/.
#
# Lab-only. Real Joomla installs go through the web installer.

set -uo pipefail

ADMIN_USER="admin"
ADMIN_PASS="admin1234"
ADMIN_NAME="Administrator"
ADMIN_EMAIL="admin@joombrute.local"

gen_hash() {
    local web="$1"
    rtk docker exec "$web" php -r "echo password_hash('$ADMIN_PASS', PASSWORD_BCRYPT);"
}

install_one() {
    local web="$1" db="$2" dbpass="$3" branch="$4" port="$5"
    echo "===[ $branch / $web ]==="

    local hash
    hash=$(gen_hash "$web")
    echo "[$branch] admin hash generated"

    echo "[$branch] drop+create schema"
    rtk docker exec -i "$db" mysql -uroot -prootpass <<SQL 2>&1 | grep -v "Using a password" || true
DROP DATABASE IF EXISTS joomla;
CREATE DATABASE joomla DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL ON joomla.* TO 'joomla'@'%';
FLUSH PRIVILEGES;
SQL

    echo "[$branch] load install SQL"
    for s in joomla.sql base.sql extensions.sql supports.sql; do
        if rtk docker exec "$web" test -f "/var/www/html/installation/sql/mysql/$s"; then
            echo "[$branch]   loading $s"
            rtk docker exec "$web" sh -c "sed 's/#__/jos_/g' /var/www/html/installation/sql/mysql/$s" \
                | rtk docker exec -i "$db" mysql -uroot -prootpass joomla 2>&1 | grep -v "Using a password" || true
        fi
    done

    echo "[$branch] insert admin user"
    rtk docker exec -i "$db" mysql -uroot -prootpass joomla <<SQL 2>&1 | grep -v "Using a password" || true
DELETE FROM jos_users WHERE username = '$ADMIN_USER';
INSERT INTO jos_users
    (id, name, username, email, password, block, sendEmail,
     registerDate, lastvisitDate, activation, params,
     lastResetTime, resetCount, otpKey, otep, requireReset)
VALUES
    (700, '$ADMIN_NAME', '$ADMIN_USER', '$ADMIN_EMAIL', '$hash', 0, 1,
     NOW(), NOW(), '0', '',
     NULL, 0, '', '', 0);
DELETE FROM jos_user_usergroup_map WHERE user_id = 700;
INSERT INTO jos_user_usergroup_map (user_id, group_id) VALUES (700, 8);
SQL

    echo "[$branch] write configuration.php"
    local secret
    secret=$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 32)
    rtk docker exec -i "$web" sh -c "cat > /var/www/html/configuration.php" <<PHP
<?php
class JConfig
{
    public \$offline = false;
    public \$offline_message = '';
    public \$display_offline_message = 1;
    public \$offline_image = '';
    public \$sitename = '${branch}Lab';
    public \$editor = 'tinymce';
    public \$captcha = 0;
    public \$list_limit = 20;
    public \$access = 1;
    public \$frontediting = 1;
    public \$dbtype = 'mysqli';
    public \$host = '$db';
    public \$user = 'joomla';
    public \$password = '$dbpass';
    public \$db = 'joomla';
    public \$dbprefix = 'jos_';
    public \$dbencryption = 0;
    public \$dbsslverifyservercert = false;
    public \$dbsslkey = '';
    public \$dbsslcert = '';
    public \$dbsslca = '';
    public \$dbsslcipher = '';
    public \$secret = '$secret';
    public \$gzip = false;
    public \$error_reporting = 'default';
    public \$helpurl = '';
    public \$tmp_path = '/tmp';
    public \$log_path = '/var/www/html/administrator/logs';
    public \$live_site = '';
    public \$force_ssl = 0;
    public \$session_handler = 'database';
    public \$shared_session = false;
    public \$session_metadata = true;
    public \$lifetime = 15;
    public \$mailonline = true;
    public \$mailer = 'mail';
    public \$mailfrom = '$ADMIN_EMAIL';
    public \$fromname = '${branch}Lab';
    public \$sendmail = '/usr/sbin/sendmail';
    public \$smtpauth = false;
    public \$smtpuser = '';
    public \$smtppass = '';
    public \$smtphost = 'localhost';
    public \$smtpsecure = 'none';
    public \$smtpport = 25;
    public \$caching = 0;
    public \$cache_handler = 'file';
    public \$cachetime = 15;
    public \$debug = false;
    public \$debug_lang = false;
    public \$debug_lang_const = true;
    public \$language = 'en-GB';
    public \$MetaDesc = '';
    public \$MetaKeys = '';
    public \$MetaTitle = 1;
    public \$MetaAuthor = 1;
    public \$MetaVersion = 0;
    public \$robots = '';
    public \$sef = 1;
    public \$sef_rewrite = 0;
    public \$sef_suffix = 0;
    public \$unicodeslugs = 0;
    public \$feed_limit = 10;
    public \$feed_email = 'author';
    public \$log_everything = 0;
    public \$cookie_domain = '';
    public \$cookie_path = '';
    public \$asset_id = 1;
}
PHP

    echo "[$branch] remove installation/"
    rtk docker exec "$web" rm -rf /var/www/html/installation 2>&1 || true
    rtk docker exec "$web" chown -R www-data:www-data /var/www/html/configuration.php 2>&1 || true

    echo "[$branch] verify /administrator/ (port $port)"
    sleep 2
    local code
    code=$(rtk curl -s -o /dev/null -w '%{http_code}' "http://localhost:$port/administrator/")
    echo "[$branch] /administrator/ -> HTTP $code"
}

install_one joombrute-j3 joombrute-j3-db 'joomlapass'    j3 8310
install_one joombrute-j4 joombrute-j4-db 'joomlapass_j4' j4 8420
install_one joombrute-j5 joombrute-j5-db 'joomlapass_j5' j5 8500

echo "all installs done"
