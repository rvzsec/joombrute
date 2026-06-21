<?php
/**
 * Seed a known TOTP secret on the admin user (user_id=700) so we can
 * exercise mfa-brute and mfa-bypass end-to-end inside the J4 container.
 *
 * Runs INSIDE the joombrute-j4 container only.
 *
 * Strategy: skip the broken Joomla web-app bootstrap and use the
 * com_users Encrypt service the way MfaTable::store() does - load the
 * AES key from configuration.php $secret, AES-128-CBC encrypt
 * json_encode(['key' => SECRET]), prefix with '###AES128###', INSERT
 * the row directly with PDO.
 *
 * The encryption format MUST match what the captive screen will decrypt
 * at validation time. We verified that format by reading:
 *   administrator/components/com_users/src/Service/Encrypt.php
 *   administrator/components/com_users/src/Table/MfaTable.php
 *
 * Default secret: JBSWY3DPEHPK3PXP  (the canonical RFC 6238 test vector,
 * matches lab/totp.py for current-code generation).
 */

const ADMIN_USER_ID = 700;
const TOTP_SECRET   = 'JBSWY3DPEHPK3PXP'; // base32, RFC 6238 test vector

// 1. Pull $secret from configuration.php - that's the AES key Joomla uses.
require '/var/www/html/configuration.php';
$cfg = new JConfig();
if (empty($cfg->secret)) {
    fwrite(STDERR, "configuration.php has no \$secret - cannot encrypt MFA options\n");
    exit(1);
}

// 2. Load Joomla's Aes implementation. It doesn't require the web app - 
//    only Joomla\CMS\Encrypt\AES\{OpenSSL,AbstractAES,AesInterface}.
define('_JEXEC', 1);
define('JPATH_PLATFORM', 1);

require '/var/www/html/libraries/src/Encrypt/AES/AesInterface.php';
require '/var/www/html/libraries/src/Encrypt/AES/AbstractAES.php';
require '/var/www/html/libraries/src/Encrypt/AES/OpenSSL.php';
require '/var/www/html/libraries/src/Encrypt/Aes.php';
require '/var/www/html/libraries/src/Encrypt/RandValInterface.php';
require '/var/www/html/libraries/src/Encrypt/Randval.php';

use Joomla\CMS\Encrypt\Aes;

// 3. Encrypt {"key":"JBSWY3DPEHPK3PXP"} the way the Encrypt service does.
//    Encrypt service: new Aes('cbc'); setPassword(secret); encryptString(data, true)
$aes = new Aes('cbc');
$aes->setPassword($cfg->secret);
$plaintext  = json_encode(['key' => TOTP_SECRET]);
$ciphertext = '###AES128###' . $aes->encryptString($plaintext, true);

// 4. INSERT via PDO so we don't need any Joomla DB layer.
$dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $cfg->host, $cfg->db);
$pdo = new PDO($dsn, $cfg->user, $cfg->password, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);

$pdo->exec("DELETE FROM jos_user_mfa WHERE user_id = " . ADMIN_USER_ID);

$stmt = $pdo->prepare(
    "INSERT INTO jos_user_mfa
        (user_id, title, method, `default`, options, created_on, last_used)
     VALUES
        (:uid, :title, :method, 1, :options, NOW(), NULL)"
);
$stmt->execute([
    ':uid'     => ADMIN_USER_ID,
    ':title'   => 'lab-totp',
    ':method'  => 'totp',
    ':options' => $ciphertext,
]);

$id = (int) $pdo->lastInsertId();

// Sanity: round-trip the value we just stored, confirm decrypt matches.
$check = $pdo->query("SELECT options FROM jos_user_mfa WHERE id = $id")->fetchColumn();
$payload = substr($check, strlen('###AES128###'));
$aes2 = new Aes('cbc');
$aes2->setPassword($cfg->secret);
$decoded = rtrim($aes2->decryptString($payload, true), "\0");
$opts = json_decode($decoded, true);

if (!is_array($opts) || ($opts['key'] ?? null) !== TOTP_SECRET) {
    fwrite(STDERR, "ROUND-TRIP FAILED: stored secret did not decrypt back\n");
    fwrite(STDERR, "  decoded payload: " . var_export($decoded, true) . "\n");
    exit(2);
}

echo "OK  mfa_id=$id  user_id=" . ADMIN_USER_ID . "  method=totp  secret=" . TOTP_SECRET . "\n";
echo "OK  round-trip verified - captive endpoint will read secret correctly\n";
