<?php
/**
 * ITN Sicherung - Vollständiger Restore-Installer (überarbeitet)
 * Ziel: stabiler WP-Restore (DB + Files) inkl. sauberer URL-/Pfad-Migration,
 *       korrekter wp-config.php, robustem SQL-Import und Plugin-/Rewrite-Fixes.
 *
 * Voraussetzungen:
 * - PHP 8.1+ (getestet für 8.3)
 * - mysqli + zip
 *
 * Sicherheitshinweis:
 * - Diese Datei sollte nur temporär auf einem leeren Zielsystem liegen.
 * - Nach erfolgreichem Restore wird sie (wie gehabt) gelöscht.
 */

declare(strict_types=1);

// ------------------------------------------------------------
// Strikte Fehlerbehandlung / Logging
// ------------------------------------------------------------
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/installer_error.log');

// ------------------------------------------------------------
// Konfiguration
// ------------------------------------------------------------
$DEFAULT_ZIP = ''; // optional: "backup.zip"
$RESTORE_DIR = __DIR__;
$TEMP_DIR = $RESTORE_DIR . '/itn_restore_temp_' . time();
$LOCK_FILE = $RESTORE_DIR . '/.itn_installer.lock';

// Session starten
if (PHP_SESSION_NONE === session_status()) {
    session_start();
}

// ------------------------------------------------------------
// Hilfsfunktionen
// ------------------------------------------------------------
function h($s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function log_message(string $msg): void {
    error_log('[ITN Installer] ' . $msg);
    if (!isset($_SESSION['itn_log']) || !is_array($_SESSION['itn_log'])) {
        $_SESSION['itn_log'] = [];
    }
    $_SESSION['itn_log'][] = date('H:i:s') . ' - ' . $msg;
}

function fail_html(string $title, string $message): void {
    log_message("FEHLER: $title - $message");
    http_response_code(500);
    echo '<h1>' . h($title) . '</h1><p>' . h($message) . '</p><p><a href="' . h($_SERVER['PHP_SELF']) . '">Zurück</a></p>';
    exit;
}

function safe_password(int $length = 64): string {
    // WordPress Salts dürfen Sonderzeichen enthalten, aber keine Zeilenumbrüche
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}:;,.?';
    $password = '';
    $max = strlen($chars) - 1;
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, $max)];
    }
    return $password;
}

function rrmdir(string $dir): void {
    if (!is_dir($dir)) return;
    $items = scandir($dir);
    if ($items === false) return;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            rrmdir($path);
        } else {
            @unlink($path);
        }
    }
    @rmdir($dir);
}

function ensure_dir(string $dir, int $mode = 0755): void {
    if (!is_dir($dir)) {
        if (!@mkdir($dir, $mode, true) && !is_dir($dir)) {
            throw new Exception('Kann Verzeichnis nicht erstellen: ' . $dir);
        }
    }
}

function normalize_path(string $p): string {
    $p = str_replace('\\', '/', $p);
    return rtrim($p, '/');
}

// ------------------------------------------------------------
// Encryption Helper Functions (for container decryption)
// ------------------------------------------------------------
const ITN_ENC_MAGIC = 'ITNENC01';
const ITN_ENC_VERSION = 1;
const ITN_ENC_SALT_LENGTH = 16;
const ITN_ENC_IV_LENGTH = 12;
const ITN_ENC_TAG_LENGTH = 16;
const ITN_ENC_PBKDF2_ITERATIONS = 100000;

/**
 * Check if a file is an encrypted container
 */
function is_encrypted_container(string $file_path): bool {
    if (!file_exists($file_path) || !is_readable($file_path)) {
        return false;
    }
    
    $handle = @fopen($file_path, 'rb');
    if (!$handle) {
        return false;
    }
    
    $magic = fread($handle, 8);
    fclose($handle);
    
    return $magic === ITN_ENC_MAGIC;
}

/**
 * Decrypt a container-encrypted file
 * Returns the path to the decrypted file or throws an exception
 */
function decrypt_container(string $enc_path, string $password): string {
    if (!function_exists('openssl_decrypt') || !function_exists('openssl_pbkdf2')) {
        throw new Exception('OpenSSL-Funktionen nicht verfügbar');
    }
    
    if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
        throw new Exception('AES-256-GCM nicht verfügbar');
    }
    
    // Read container
    $container = @file_get_contents($enc_path);
    if ($container === false) {
        throw new Exception('Konnte verschlüsselte Datei nicht lesen');
    }
    
    // Verify minimum size
    $header_size = 8 + 1 + 16 + 4 + 12 + 16; // MAGIC + VERSION + SALT + ITERATIONS + IV + TAG
    if (strlen($container) < $header_size) {
        throw new Exception('Ungültige Container-Datei (zu klein)');
    }
    
    // Parse header
    $pos = 0;
    
    // Check magic
    $magic = substr($container, $pos, 8);
    $pos += 8;
    if ($magic !== ITN_ENC_MAGIC) {
        throw new Exception('Ungültiger Container-Header');
    }
    
    // Read version
    $version = unpack('C', substr($container, $pos, 1))[1];
    $pos += 1;
    if ($version !== ITN_ENC_VERSION) {
        throw new Exception('Nicht unterstützte Container-Version: ' . $version);
    }
    
    // Read salt
    $salt = substr($container, $pos, ITN_ENC_SALT_LENGTH);
    $pos += ITN_ENC_SALT_LENGTH;
    
    // Read iterations
    $iterations = unpack('N', substr($container, $pos, 4))[1];
    $pos += 4;
    
    // Read IV
    $iv = substr($container, $pos, ITN_ENC_IV_LENGTH);
    $pos += ITN_ENC_IV_LENGTH;
    
    // Read tag
    $tag = substr($container, $pos, ITN_ENC_TAG_LENGTH);
    $pos += ITN_ENC_TAG_LENGTH;
    
    // Read ciphertext
    $ciphertext = substr($container, $pos);
    
    // Derive decryption key
    $key = openssl_pbkdf2($password, $salt, 32, $iterations, 'sha256');
    if ($key === false) {
        throw new Exception('Schlüsselableitung fehlgeschlagen');
    }
    
    // Decrypt data
    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );
    
    if ($plaintext === false) {
        throw new Exception('Entschlüsselung fehlgeschlagen (falsches Passwort oder beschädigte Datei)');
    }
    
    // Write decrypted data to temporary file
    $dec_path = dirname($enc_path) . '/' . basename($enc_path, '.enc');
    if (@file_put_contents($dec_path, $plaintext) === false) {
        throw new Exception('Konnte entschlüsselte Datei nicht schreiben');
    }
    
    return $dec_path;
}

/**
 * Kopiert rekursiv Inhalte von $src nach $dst.
 * - Excludes sind relative Namen (Datei/Ordner) auf erster Ebene UND in Unterordnern (basename-Vergleich).
 * - WICHTIG: WordPress braucht u.a. ".htaccess" ggf. auch, wird kopiert (nicht ausgeschlossen).
 */
function copy_recursive(string $src, string $dst, array $exclude = []): void {
    if (!is_dir($src)) return;

    ensure_dir($dst);

    $dir = opendir($src);
    if ($dir === false) return;

    while (($file = readdir($dir)) !== false) {
        if ($file === '.' || $file === '..') continue;
        if (in_array($file, $exclude, true)) continue;

        $src_path = $src . DIRECTORY_SEPARATOR . $file;
        $dst_path = $dst . DIRECTORY_SEPARATOR . $file;

        if (is_dir($src_path)) {
            copy_recursive($src_path, $dst_path, $exclude);
        } else {
            // Copy mit Fallback via stream
            if (!@copy($src_path, $dst_path)) {
                $in = @fopen($src_path, 'rb');
                $out = @fopen($dst_path, 'wb');
                if ($in && $out) {
                    stream_copy_to_stream($in, $out);
                }
                if ($in) fclose($in);
                if ($out) fclose($out);
            }
        }
    }
    closedir($dir);
}

// ------------------------------------------------------------
// Serialisierung: robust & sicher
// ------------------------------------------------------------
function is_serialized_string($data): bool {
    if (!is_string($data)) return false;
    $data = trim($data);
    if ($data === 'N;') return true;
    if (strlen($data) < 4) return false;
    if ($data[1] !== ':') return false;

    $last = substr($data, -1);
    if ($last !== ';' && $last !== '}') return false;

    $token = $data[0];
    // Minimalprüfung (WordPress-typisch)
    return (bool)preg_match('/^(s|a|O|b|i|d):/', $data);
}

/**
 * Unserialize OHNE Objekt-Instantierung (Sicherheit).
 * Gibt bei Fehlern originalen String zurück.
 */
function safe_unserialize(string $data) {
    if (!is_serialized_string($data)) return $data;
    try {
        $v = @unserialize($data, ['allowed_classes' => false]);
        return ($v === false && $data !== 'b:0;') ? $data : $v;
    } catch (Throwable $e) {
        return $data;
    }
}

function recursive_replace($search, $replace, $subject) {
    if (is_array($subject)) {
        foreach ($subject as $k => $v) {
            $subject[$k] = recursive_replace($search, $replace, $v);
        }
        return $subject;
    }
    if (is_object($subject)) {
        // Objekt wird nicht erwartet (allowed_classes=false), aber falls doch:
        foreach (get_object_vars($subject) as $k => $v) {
            $subject->$k = recursive_replace($search, $replace, $v);
        }
        return $subject;
    }
    if (is_string($subject)) {
        return str_replace((string)$search, (string)$replace, $subject);
    }
    return $subject;
}

/**
 * WordPress Search/Replace DB
 * - Nur Tabellen des Präfix (falls vorhanden) oder alle (Fallback)
 * - Behandelt serialisierte Werte korrekt (serialize nach Änderung)
 * - Nutzt Prepared Statements, wo möglich
 */
function wp_search_replace_db(mysqli $mysqli, string $prefix, string $old_url, string $new_url): int {
    $updated = 0;
    $old_url = rtrim($old_url, '/');
    $new_url = rtrim($new_url, '/');

    $tables_res = $mysqli->query("SHOW TABLES");
    if (!$tables_res) return 0;

    while ($table_row = $tables_res->fetch_array()) {
        $table = (string)$table_row[0];

        // Optional: auf Präfix einschränken, wenn sinnvoll
        if ($prefix !== '' && str_starts_with($table, $prefix) === false) {
            // Manche Backups haben andere Präfixe oder keine, daher NICHT strikt skippen.
            // Wenn du strikt nur Prefix willst: hier continue.
            // continue;
        }

        // Primary Key ermitteln
        $pk = null;
        $pk_query = $mysqli->query("SHOW KEYS FROM `{$table}` WHERE Key_name = 'PRIMARY'");
        if ($pk_query && ($pk_row = $pk_query->fetch_assoc())) {
            $pk = $pk_row['Column_name'] ?? null;
        }
        if (!$pk) {
            // Ohne PK wird es schnell teuer/unsicher -> überspringen
            continue;
        }

        $cols_res = $mysqli->query("SHOW COLUMNS FROM `{$table}`");
        if (!$cols_res) continue;

        while ($col = $cols_res->fetch_assoc()) {
            $column = (string)($col['Field'] ?? '');
            $type = strtolower((string)($col['Type'] ?? ''));

            if (
                strpos($type, 'char') === false &&
                strpos($type, 'text') === false &&
                strpos($type, 'blob') === false &&
                strpos($type, 'json') === false
            ) {
                continue;
            }

            $old_like = '%' . $mysqli->real_escape_string($old_url) . '%';
            $sql = "SELECT `{$pk}`, `{$column}` FROM `{$table}` WHERE `{$column}` LIKE '{$old_like}'";
            $rows = $mysqli->query($sql);
            if (!$rows) continue;

            while ($row = $rows->fetch_assoc()) {
                $pk_val = (string)($row[$pk] ?? '');
                $old_value = $row[$column] ?? null;

                if ($old_value === null || $old_value === '') continue;

                $new_value = $old_value;

                if (is_string($old_value) && is_serialized_string($old_value)) {
                    $un = safe_unserialize($old_value);

                    // Falls unser safe_unserialize den String zurückgibt, war es kaputt -> dann fallback str_replace
                    if (is_string($un) && $un === $old_value) {
                        $new_value = str_replace($old_url, $new_url, $old_value);
                    } else {
                        $new_un = recursive_replace($old_url, $new_url, $un);
                        $new_value = serialize($new_un);
                    }
                } elseif (is_string($old_value)) {
                    $new_value = str_replace($old_url, $new_url, $old_value);
                }

                if ($new_value !== $old_value) {
                    $stmt = $mysqli->prepare("UPDATE `{$table}` SET `{$column}` = ? WHERE `{$pk}` = ?");
                    if ($stmt) {
                        $stmt->bind_param('ss', $new_value, $pk_val);
                        if ($stmt->execute()) $updated++;
                        $stmt->close();
                    }
                }
            }
        }
    }

    return $updated;
}

// ------------------------------------------------------------
// SQL Import: robust (multi_query ist bei großen Dumps fehleranfällig)
// ------------------------------------------------------------
/**
 * Sehr einfacher SQL-Splitter (funktioniert für typische WP-Backups).
 * - Entfernt Kommentare (/* * / und -- und #)
 * - Splittet auf ';' außerhalb von Strings
 */
function sql_import_file(mysqli $mysqli, string $file): void {
    $fh = fopen($file, 'rb');
    if (!$fh) {
        throw new Exception('Kann SQL-Datei nicht öffnen: ' . $file);
    }

    $buffer = '';
    $in_string = false;
    $string_char = '';
    $line_num = 0;

    $mysqli->query("SET FOREIGN_KEY_CHECKS=0");

    while (($line = fgets($fh)) !== false) {
        $line_num++;

        // BOM entfernen
        if ($line_num === 1) {
            $line = preg_replace('/^\xEF\xBB\xBF/', '', $line);
        }

        // Skip line comments
        $trim = ltrim($line);
        if (!$in_string) {
            if ($trim === '' || $trim === "\n" || $trim === "\r\n") continue;
            if (str_starts_with($trim, '-- ') || str_starts_with($trim, '#')) continue;
        }

        // Block comments grob entfernen (nicht perfekt, aber ok für WP dumps)
        if (!$in_string) {
            // Entferne /* ... */ innerhalb der Zeile (greedy vermeiden)
            $line = preg_replace('#/\*.*?\*/#s', '', $line);
        }

        $len = strlen($line);
        for ($i = 0; $i < $len; $i++) {
            $ch = $line[$i];

            if ($in_string) {
                if ($ch === $string_char) {
                    // Escapes beachten
                    $bs = 0;
                    $j = $i - 1;
                    while ($j >= 0 && $line[$j] === '\\') { $bs++; $j--; }
                    if ($bs % 2 === 0) {
                        $in_string = false;
                        $string_char = '';
                    }
                }
                $buffer .= $ch;
                continue;
            }

            if ($ch === '\'' || $ch === '"') {
                $in_string = true;
                $string_char = $ch;
                $buffer .= $ch;
                continue;
            }

            if ($ch === ';') {
                $buffer .= ';';
                $query = trim($buffer);
                $buffer = '';

                if ($query !== '' && $query !== ';') {
                    if (!$mysqli->query($query)) {
                        $err = $mysqli->error;
                        throw new Exception("SQL-Fehler (Zeile ~{$line_num}): {$err}");
                    }
                }
                continue;
            }

            $buffer .= $ch;
        }
    }

    $tail = trim($buffer);
    if ($tail !== '') {
        if (!$mysqli->query($tail)) {
            throw new Exception('SQL-Fehler (Ende der Datei): ' . $mysqli->error);
        }
    }

    $mysqli->query("SET FOREIGN_KEY_CHECKS=1");
    fclose($fh);
}

// ------------------------------------------------------------
// WordPress-config Generator (safer, inkl. FS_METHOD, WP_HOME/SITEURL optional)
// ------------------------------------------------------------
function build_wp_config(array $db, string $absolutePath, ?string $homeUrl = null, ?string $siteUrl = null): string {
    $abs = rtrim(str_replace('\\', '/', $absolutePath), '/') . '/';

    // Optional URL-Defines helfen, wenn optionen inkonsistent sind / Migration hakt
    $urlDefines = '';
    if ($homeUrl) {
        $urlDefines .= "define('WP_HOME', '" . addslashes(rtrim($homeUrl, '/')) . "');\n";
    }
    if ($siteUrl) {
        $urlDefines .= "define('WP_SITEURL', '" . addslashes(rtrim($siteUrl, '/')) . "');\n";
    }

    // Häufige Ursache für "kritische Fehler": falsche FS Rechte -> setze direct, wenn möglich
    // (kann man später entfernen)
    $fsMethod = "define('FS_METHOD', 'direct');\n";

    return "<?php
/**
 * Auto-generated by ITN Restore Installer
 * @date " . date('c') . "
 */

define('DB_NAME', '" . addslashes((string)$db['name']) . "');
define('DB_USER', '" . addslashes((string)$db['user']) . "');
define('DB_PASSWORD', '" . addslashes((string)$db['pass']) . "');
define('DB_HOST', '" . addslashes((string)$db['host']) . "');

define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

" . $urlDefines . "
" . $fsMethod . "

define('AUTH_KEY',         '" . safe_password() . "');
define('SECURE_AUTH_KEY',  '" . safe_password() . "');
define('LOGGED_IN_KEY',    '" . safe_password() . "');
define('NONCE_KEY',        '" . safe_password() . "');
define('AUTH_SALT',        '" . safe_password() . "');
define('SECURE_AUTH_SALT', '" . safe_password() . "');
define('LOGGED_IN_SALT',   '" . safe_password() . "');
define('NONCE_SALT',       '" . safe_password() . "');

\$table_prefix = '" . addslashes((string)$db['prefix']) . "';

// Debug (bei Bedarf aktivieren)
// define('WP_DEBUG', true);
// define('WP_DEBUG_LOG', true);
// define('WP_DEBUG_DISPLAY', false);

if (!defined('ABSPATH')) {
    define('ABSPATH', '" . addslashes($abs) . "');
}

require_once ABSPATH . 'wp-settings.php';
";
}

// ------------------------------------------------------------
// Step-Init / Locking (verhindert Doppel-Ausführung)
// ------------------------------------------------------------
if (!isset($_SESSION['step'])) {
    $_SESSION['step'] = 'select_zip';
    $_SESSION['itn_log'] = [];
}

// Basic lock (optional)
if (!file_exists($LOCK_FILE)) {
    @file_put_contents($LOCK_FILE, (string)time());
}

// ------------------------------------------------------------
// POST: ZIP extrahieren
// ------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'extract_zip') {
    try {
        $_SESSION['step'] = 'extract';

        $zip_password = trim((string)($_POST['zip_password'] ?? ''));

        $zip_file_path = '';
        $zip_display_name = '';

        if (isset($_FILES['zip_upload']) && ($_FILES['zip_upload']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK) {
            $zip_file_path = (string)$_FILES['zip_upload']['tmp_name'];
            $zip_display_name = (string)$_FILES['zip_upload']['name'];
            log_message('ZIP Upload: ' . $zip_display_name);
        } elseif (!empty($_POST['zip_file'])) {
            $zip_display_name = basename((string)$_POST['zip_file']);
            $zip_file_path = $RESTORE_DIR . '/' . $zip_display_name;
            if (!file_exists($zip_file_path)) {
                throw new Exception('ZIP nicht gefunden: ' . $zip_display_name);
            }
            log_message('ZIP gewählt: ' . $zip_display_name);
        } else {
            throw new Exception('Keine ZIP-Datei angegeben');
        }

        // Check if file is an encrypted container (.enc)
        $is_container = is_encrypted_container($zip_file_path);
        if ($is_container) {
            log_message('Verschlüsselter Container erkannt');
            
            if ($zip_password === '') {
                throw new Exception('Passwort erforderlich für verschlüsseltes Backup');
            }
            
            log_message('Entschlüssele Container...');
            $zip_file_path = decrypt_container($zip_file_path, $zip_password);
            log_message('Container erfolgreich entschlüsselt');
        }

        if (!class_exists('ZipArchive')) {
            throw new Exception('ZipArchive fehlt (PHP Extension "zip" nicht aktiv)');
        }

        ensure_dir($TEMP_DIR);

        $zip = new ZipArchive();
        $openRes = $zip->open($zip_file_path);
        if ($openRes !== true) {
            throw new Exception('ZIP öffnen fehlgeschlagen (Code ' . $openRes . ')');
        }

        // If not a container but password provided, assume ZipArchive encryption
        if (!$is_container && $zip_password !== '') {
            $zip->setPassword($zip_password);
        }

        log_message('Entpacke ' . $zip->numFiles . ' Dateien nach ' . $TEMP_DIR);

        // Teste Passwort/Lesbarkeit: versuche eine Datei zu lesen, falls verschlüsselt
        if ($zip->numFiles > 0 && $zip_password !== '' && !$is_container) {
            $stat = $zip->statIndex(0);
            if ($stat && isset($stat['name'])) {
                $test = $zip->getFromName($stat['name']);
                if ($test === false) {
                    $zip->close();
                    throw new Exception('ZIP-Passwort falsch oder Datei kann nicht gelesen werden');
                }
            }
        }

        if (!$zip->extractTo($TEMP_DIR)) {
            $zip->close();
            throw new Exception('Entpacken fehlgeschlagen');
        }

        $zip->close();
        log_message('Entpacken erfolgreich');

        // Meta
        $meta = [];
        $meta_file = $TEMP_DIR . '/backup_meta.json';
        if (file_exists($meta_file)) {
            $meta_raw = file_get_contents($meta_file);
            $meta = json_decode((string)$meta_raw, true) ?: [];
        }

        // Erwartete Dateien prüfen
        if (!file_exists($TEMP_DIR . '/database.sql')) {
            log_message('WARN: database.sql nicht gefunden. (Backup evtl. anders strukturiert?)');
        }

        $_SESSION['temp_dir'] = $TEMP_DIR;
        $_SESSION['meta'] = $meta;
        $_SESSION['zip_display_name'] = $zip_display_name;
        $_SESSION['step'] = 'db_config';

        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } catch (Throwable $e) {
        fail_html('Fehler', $e->getMessage());
    }
}

// ------------------------------------------------------------
// AJAX: DB Test
// ------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'test_db') {
    header('Content-Type: application/json');

    try {
        $db_host = trim((string)($_POST['db_host'] ?? 'localhost'));
        $db_name = trim((string)($_POST['db_name'] ?? ''));
        $db_user = trim((string)($_POST['db_user'] ?? ''));
        $db_pass = (string)($_POST['db_pass'] ?? '');

        if ($db_name === '' || $db_user === '') {
            throw new Exception('Datenbank-Name und Benutzer erforderlich');
        }

        mysqli_report(MYSQLI_REPORT_OFF);
        $mysqli = @new mysqli($db_host, $db_user, $db_pass, $db_name);

        if ($mysqli->connect_error) {
            throw new Exception('Verbindung fehlgeschlagen: ' . $mysqli->connect_error);
        }

        $mysqli->set_charset('utf8mb4');
        $mysqli->close();

        echo json_encode(['success' => true, 'message' => 'Verbindung OK']);
        exit;
    } catch (Throwable $e) {
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        exit;
    }
}

// ------------------------------------------------------------
// POST: DB Import (robust)
// ------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'import_db') {
    try {
        $db_host = trim((string)($_POST['db_host'] ?? 'localhost'));
        $db_name = trim((string)($_POST['db_name'] ?? ''));
        $db_user = trim((string)($_POST['db_user'] ?? ''));
        $db_pass = (string)($_POST['db_pass'] ?? '');
        $db_prefix = trim((string)($_POST['db_prefix'] ?? 'wp_'));

        if (!isset($_SESSION['temp_dir']) || !is_dir((string)$_SESSION['temp_dir'])) {
            throw new Exception('Temp-Verzeichnis fehlt. Bitte Schritt 1 erneut ausführen.');
        }

        $sql_file = (string)$_SESSION['temp_dir'] . '/database.sql';
        if (!file_exists($sql_file)) {
            throw new Exception('database.sql nicht gefunden im Backup');
        }

        log_message('Verbinde zu DB: ' . $db_host . ' / ' . $db_name);
        mysqli_report(MYSQLI_REPORT_OFF);
        $mysqli = @new mysqli($db_host, $db_user, $db_pass, $db_name);
        if ($mysqli->connect_error) {
            throw new Exception('DB-Verbindung fehlgeschlagen: ' . $mysqli->connect_error);
        }
        $mysqli->set_charset('utf8mb4');

        // Vor Import: optional alle Tabellen droppen (sonst Konflikte/Logins kaputt)
        // -> WordPress Dumps enthalten i.d.R. DROP TABLE / CREATE TABLE.
        // Falls nicht: alte Tabellen bleiben und verursachen Chaos.
        // Daher: drop alle Tabellen im Ziel-DB.
        log_message('Leere Ziel-Datenbank (DROP TABLES)');
        $tables = $mysqli->query("SHOW TABLES");
        if ($tables) {
            $mysqli->query("SET FOREIGN_KEY_CHECKS=0");
            while ($tr = $tables->fetch_array()) {
                $t = (string)$tr[0];
                $mysqli->query("DROP TABLE IF EXISTS `{$t}`");
            }
            $mysqli->query("SET FOREIGN_KEY_CHECKS=1");
        }

        log_message('Importiere SQL (streaming)');
        sql_import_file($mysqli, $sql_file);
        log_message('SQL importiert');

        $mysqli->close();

        $_SESSION['db_config'] = [
            'host' => $db_host,
            'name' => $db_name,
            'user' => $db_user,
            'pass' => $db_pass,
            'prefix' => $db_prefix,
        ];

        $_SESSION['step'] = 'restore_files';
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } catch (Throwable $e) {
        fail_html('Fehler', $e->getMessage());
    }
}

// ------------------------------------------------------------
// POST: Dateien wiederherstellen + Migration + Fixes
// ------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'restore_files') {
    try {
        if (!isset($_SESSION['temp_dir']) || !is_dir((string)$_SESSION['temp_dir'])) {
            throw new Exception('Temp-Verzeichnis fehlt. Bitte Schritt 1 erneut ausführen.');
        }
        if (!isset($_SESSION['db_config']) || !is_array($_SESSION['db_config'])) {
            throw new Exception('DB-Konfiguration fehlt. Bitte Schritt 2 erneut ausführen.');
        }

        $new_url = rtrim(trim((string)($_POST['new_url'] ?? '')), '/');
        if ($new_url === '') {
            $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
            $new_url = $protocol . '://' . $host;
        }

        log_message('Neue URL: ' . $new_url);

        $tempDir = (string)$_SESSION['temp_dir'];

        // 1) Dateien kopieren
        // wp-config.php NICHT aus Backup kopieren; wir erzeugen es neu
        // database.sql/meta bleiben im Temp
        $exclude = ['database.sql', 'backup_meta.json', 'wp-config.php', basename(__FILE__), '.DS_Store'];
        copy_recursive($tempDir, $RESTORE_DIR, $exclude);
        log_message('Dateien kopiert');

        // 2) wp-config.php neu erstellen (mit optionalen URL-Defines)
        $db = $_SESSION['db_config'];
        $absPath = realpath($RESTORE_DIR) ?: $RESTORE_DIR;

        // Optional: für Stabilität direkt definieren (kann später entfernt werden)
        $config = build_wp_config($db, $absPath, $new_url, $new_url);
        if (@file_put_contents($RESTORE_DIR . '/wp-config.php', $config) === false) {
            throw new Exception('Kann wp-config.php nicht schreiben (Rechte?)');
        }
        log_message('wp-config.php erstellt');

        // 3) DB-Migration
        $meta = $_SESSION['meta'] ?? [];
        $old_url = rtrim((string)($meta['site_url'] ?? ''), '/');

        $old_path = normalize_path((string)($meta['abs_path'] ?? ''));
        $new_path = normalize_path((string)$absPath);

        mysqli_report(MYSQLI_REPORT_OFF);
        $mysqli = @new mysqli((string)$db['host'], (string)$db['user'], (string)$db['pass'], (string)$db['name']);
        if ($mysqli->connect_error) {
            throw new Exception('DB-Verbindung fehlgeschlagen: ' . $mysqli->connect_error);
        }
        $mysqli->set_charset('utf8mb4');

        $prefix = (string)$db['prefix'];

        // 3a) siteurl/home zuerst (wichtig für Login/Redirect)
        if ($old_url !== '' && $old_url !== $new_url) {
            log_message("Update {$prefix}options: siteurl/home");
        }

        // Tabelle existiert?
        $optTable = $prefix . 'options';
        $hasOptions = $mysqli->query("SHOW TABLES LIKE '" . $mysqli->real_escape_string($optTable) . "'")->num_rows > 0;

        if ($hasOptions) {
            $stmt = $mysqli->prepare("UPDATE `{$optTable}` SET option_value=? WHERE option_name='siteurl'");
            if ($stmt) { $stmt->bind_param('s', $new_url); $stmt->execute(); $stmt->close(); }

            $stmt = $mysqli->prepare("UPDATE `{$optTable}` SET option_value=? WHERE option_name='home'");
            if ($stmt) { $stmt->bind_param('s', $new_url); $stmt->execute(); $stmt->close(); }
        } else {
            log_message("WARN: Options-Tabelle {$optTable} nicht gefunden. Prefix korrekt?");
        }

        // 3b) URL Search/Replace (serialisiert korrekt)
        if ($old_url !== '' && $old_url !== $new_url) {
            log_message('Starte URL-Migration: ' . $old_url . ' -> ' . $new_url);
            $updated = wp_search_replace_db($mysqli, $prefix, $old_url, $new_url);
            log_message("URLs ersetzt: {$updated} Updates");
        } else {
            log_message('URL-Migration übersprungen (keine alte URL in Meta oder identisch)');
        }

        // 3c) Pfad ersetzen (inkl. wp-content uploads, etc.)
        if ($old_path !== '' && $old_path !== $new_path) {
            log_message('Ersetze Pfade: ' . $old_path . ' -> ' . $new_path);

            $tables = $mysqli->query("SHOW TABLES");
            if ($tables) {
                $old_esc = $mysqli->real_escape_string($old_path);
                $new_esc = $mysqli->real_escape_string($new_path);

                while ($row = $tables->fetch_array()) {
                    $table = (string)$row[0];

                    $columns = $mysqli->query("SHOW COLUMNS FROM `{$table}`");
                    if (!$columns) continue;

                    while ($col = $columns->fetch_assoc()) {
                        $column = (string)$col['Field'];
                        $type = strtolower((string)$col['Type']);

                        if (strpos($type, 'char') !== false || strpos($type, 'text') !== false) {
                            $mysqli->query("UPDATE `{$table}` SET `{$column}` = REPLACE(`{$column}`, '{$old_esc}', '{$new_esc}') WHERE `{$column}` LIKE '%{$old_esc}%'");
                        }
                    }
                }
            }

            log_message('Pfade ersetzt');
        }

        // 4) Plugin Aktivierung: NICHT aggressiv überschreiben.
        //    Problem: "Plugins nicht aktiviert" entsteht oft durch kaputte Serialisierung, falsche SiteURL oder DB Import.
        //    Wir reparieren nur, wenn active_plugins nicht sauber unserialisierbar ist.
        if ($hasOptions) {
            $res = $mysqli->query("SELECT option_value FROM `{$optTable}` WHERE option_name='active_plugins' LIMIT 1");
            $active_raw = '';
            if ($res && ($r = $res->fetch_row())) {
                $active_raw = (string)($r[0] ?? '');
            }

            $active = null;
            if ($active_raw !== '') {
                $tmp = safe_unserialize($active_raw);
                if (is_array($tmp)) $active = $tmp;
            }

            if ($active_raw !== '' && !is_array($active)) {
                log_message('active_plugins ist nicht lesbar -> setze auf leeres Array (WordPress Standard)');
                $empty = serialize([]);
                $stmt = $mysqli->prepare("UPDATE `{$optTable}` SET option_value=? WHERE option_name='active_plugins'");
                if ($stmt) { $stmt->bind_param('s', $empty); $stmt->execute(); $stmt->close(); }
            } else {
                log_message('active_plugins OK (wird nicht überschrieben)');
            }

            // Optional: template/stylesheet prüfen (Theme)
            // Ein häufiger "kritischer Fehler" ist ein fehlendes Theme (template/stylesheet zeigt auf nicht vorhandenes Verzeichnis).
            // Wir prüfen nur grob: Wenn gesetzt, aber Ordner fehlt, setzen wir auf "twentytwentyfour" falls vorhanden.
            $themeTemplate = '';
            $themeStylesheet = '';
            $r1 = $mysqli->query("SELECT option_value FROM `{$optTable}` WHERE option_name='template' LIMIT 1");
            if ($r1 && ($row = $r1->fetch_row())) $themeTemplate = (string)$row[0];
            $r2 = $mysqli->query("SELECT option_value FROM `{$optTable}` WHERE option_name='stylesheet' LIMIT 1");
            if ($r2 && ($row = $r2->fetch_row())) $themeStylesheet = (string)$row[0];

            $themeDir = $RESTORE_DIR . '/wp-content/themes/';
            $tplOk = ($themeTemplate !== '' && is_dir($themeDir . $themeTemplate));
            $styOk = ($themeStylesheet !== '' && is_dir($themeDir . $themeStylesheet));

            if (!$tplOk || !$styOk) {
                $fallbacks = ['twentytwentyfour', 'twentytwentythree', 'twentytwentytwo', 'twentytwentyone'];
                $chosen = null;
                foreach ($fallbacks as $fb) {
                    if (is_dir($themeDir . $fb)) { $chosen = $fb; break; }
                }
                if ($chosen) {
                    log_message("Theme scheint zu fehlen -> setze template/stylesheet auf {$chosen}");
                    $stmt = $mysqli->prepare("UPDATE `{$optTable}` SET option_value=? WHERE option_name IN ('template','stylesheet')");
                    // MySQLi kann kein IN mit single bind so einfach; daher 2 Updates:
                    if ($stmt) { $stmt->close(); }
                    $st = $mysqli->prepare("UPDATE `{$optTable}` SET option_value=? WHERE option_name='template'");
                    if ($st) { $st->bind_param('s', $chosen); $st->execute(); $st->close(); }
                    $st = $mysqli->prepare("UPDATE `{$optTable}` SET option_value=? WHERE option_name='stylesheet'");
                    if ($st) { $st->bind_param('s', $chosen); $st->execute(); $st->close(); }
                } else {
                    log_message('WARN: Theme fehlt, aber kein Standard-Theme gefunden. Bitte Theme hochladen.');
                }
            }
        }

        // 5) Cleanup in DB: transients + rewrite_rules leeren
        if ($hasOptions) {
            $mysqli->query("DELETE FROM `{$optTable}` WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'");
            $mysqli->query("UPDATE `{$optTable}` SET option_value='' WHERE option_name='rewrite_rules'");
            log_message('Transients gelöscht, rewrite_rules zurückgesetzt');
        }

        $mysqli->close();
        log_message('DB-Migration abgeschlossen');

        // 6) Temp löschen
        rrmdir($tempDir);
        log_message('Temp gelöscht');

        $_SESSION['step'] = 'complete';
        $_SESSION['new_url'] = $new_url;

        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } catch (Throwable $e) {
        fail_html('Fehler', $e->getMessage() . ' (Details in installer_error.log)');
    }
}

// ------------------------------------------------------------
// HTML Output
// ------------------------------------------------------------
$current_step = $_SESSION['step'] ?? 'select_zip';
$steps = ['select_zip' => 1, 'db_config' => 2, 'restore_files' => 3, 'complete' => 4];
$step_num = $steps[$current_step] ?? 1;

$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$auto_url = $protocol . '://' . $host;
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ITN Sicherung - Installer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 650px;
            width: 100%;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .content { padding: 40px; }
        .form-group { margin-bottom: 20px; }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        input[type="text"],
        input[type="password"],
        input[type="url"],
        input[type="file"],
        select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            border: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s;
        }
        .btn:hover { transform: translateY(-2px); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-test { background: #2196f3; margin-bottom: 15px; }
        .help-text {
            font-size: 13px;
            color: #666;
            margin-top: 6px;
        }
        .success-message {
            background: #d7f2dc;
            border-left: 4px solid #00a32a;
            padding: 20px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .test-result {
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
            display: none;
        }
        .test-result.success {
            background: #d7f2dc;
            color: #00a32a;
            display: block;
        }
        .test-result.error {
            background: #fcecee;
            color: #d63638;
            display: block;
        }
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196f3;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .warning-box {
            background: #fff4e5;
            border-left: 4px solid #ff9800;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .log-box {
            background: #f6f7f7;
            border: 1px solid #ddd;
            padding: 15px;
            margin-top: 10px;
            max-height: 220px;
            overflow-y: auto;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
            font-size: 12px;
        }
        .log-box div { margin-bottom: 4px; }
        .small { color:#666; font-size: 13px; margin-top: 10px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>ITN Sicherung</h1>
        <p>Wiederherstellung (Schritt <?php echo (int)$step_num; ?>/4)</p>
    </div>

    <div class="content">
        <?php if ($current_step === 'select_zip'): ?>
            <h2>Schritt 1: Backup wählen</h2>
            <p class="small">Hinweis: Zielverzeichnis sollte idealerweise leer sein (außer diesem Installer und der ZIP).</p>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="action" value="extract_zip">

                <?php
                $zip_files = glob($RESTORE_DIR . '/*.zip') ?: [];
                if (!empty($zip_files) || $DEFAULT_ZIP):
                ?>
                    <div class="form-group">
                        <label>Vorhandene ZIP:</label>
                        <select name="zip_file">
                            <?php if ($DEFAULT_ZIP): ?>
                                <option value="<?php echo h($DEFAULT_ZIP); ?>"><?php echo h($DEFAULT_ZIP); ?></option>
                            <?php endif; ?>
                            <?php foreach ($zip_files as $zf): ?>
                                <option value="<?php echo h(basename($zf)); ?>">
                                    <?php echo h(basename($zf)); ?> (<?php echo round(filesize($zf)/1024/1024, 2); ?> MB)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <p style="text-align: center; margin: 20px 0; color: #999;">— ODER —</p>
                <?php endif; ?>

                <div class="form-group">
                    <label>ZIP hochladen:</label>
                    <input type="file" name="zip_upload" accept=".zip">
                    <div class="help-text">Maximale Größe: <?php echo h((string)ini_get('upload_max_filesize')); ?></div>
                </div>

                <div class="form-group">
                    <label>Passwort (falls verschlüsselt):</label>
                    <input type="password" name="zip_password" placeholder="Optional">
                </div>

                <button type="submit" class="btn">Weiter →</button>
            </form>

        <?php elseif ($current_step === 'db_config'): ?>
            <h2>Schritt 2: Datenbank</h2>

            <?php $meta = $_SESSION['meta'] ?? []; ?>
            <?php if (!empty($meta) && is_array($meta)): ?>
                <div class="info-box">
                    <strong>Backup-Info:</strong><br>
                    Erstellt: <?php echo h($meta['created_at'] ?? 'unbekannt'); ?><br>
                    Domain: <?php echo h($meta['site_url'] ?? 'unbekannt'); ?><br>
                    WordPress: <?php echo h($meta['wp_version'] ?? 'unbekannt'); ?><br>
                    PHP: <?php echo h($meta['php_version'] ?? 'unbekannt'); ?>
                </div>
            <?php endif; ?>

            <div class="warning-box">
                <strong>Achtung:</strong> Die Ziel-Datenbank wird geleert und neu importiert.
            </div>

            <div id="test-result" class="test-result"></div>

            <form method="post" id="db-form">
                <input type="hidden" name="action" value="import_db">

                <div class="form-group">
                    <label>Datenbank-Host:</label>
                    <input type="text" name="db_host" id="db_host" value="localhost" required>
                </div>

                <div class="form-group">
                    <label>Datenbank-Name:</label>
                    <input type="text" name="db_name" id="db_name" required>
                </div>

                <div class="form-group">
                    <label>Benutzer:</label>
                    <input type="text" name="db_user" id="db_user" required>
                </div>

                <div class="form-group">
                    <label>Passwort:</label>
                    <input type="password" name="db_pass" id="db_pass">
                </div>

                <div class="form-group">
                    <label>Tabellen-Präfix:</label>
                    <input type="text" name="db_prefix" value="<?php echo h($meta['table_prefix'] ?? 'wp_'); ?>">
                    <div class="help-text">Wichtig: muss zum Backup passen (häufig wp_)</div>
                </div>

                <button type="button" class="btn btn-test" id="test-btn">Verbindung testen</button>
                <button type="submit" class="btn" id="import-btn" disabled>Datenbank importieren →</button>
            </form>

            <script>
            document.getElementById('test-btn').onclick = function() {
                var btn = this;
                var result = document.getElementById('test-result');
                var importBtn = document.getElementById('import-btn');

                btn.disabled = true;
                btn.textContent = 'Teste Verbindung...';
                result.style.display = 'none';

                var fd = new FormData();
                fd.append('action', 'test_db');
                fd.append('db_host', document.getElementById('db_host').value);
                fd.append('db_name', document.getElementById('db_name').value);
                fd.append('db_user', document.getElementById('db_user').value);
                fd.append('db_pass', document.getElementById('db_pass').value);

                fetch(window.location.href, { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    btn.disabled = false;
                    btn.textContent = 'Verbindung testen';

                    if (data.success) {
                        result.className = 'test-result success';
                        result.textContent = 'OK: ' + data.message;
                        importBtn.disabled = false;
                    } else {
                        result.className = 'test-result error';
                        result.textContent = 'Fehler: ' + data.message;
                        importBtn.disabled = true;
                    }
                })
                .catch(err => {
                    btn.disabled = false;
                    btn.textContent = 'Verbindung testen';
                    result.className = 'test-result error';
                    result.textContent = 'Netzwerkfehler: ' + err;
                    importBtn.disabled = true;
                });
            };
            </script>

        <?php elseif ($current_step === 'restore_files'): ?>
            <h2>Schritt 3: Wiederherstellung starten</h2>

            <div class="info-box">
                <strong>Automatisch erkannte URL:</strong><br>
                <?php echo h($auto_url); ?>
            </div>

            <div class="warning-box">
                <strong>Was wird gemacht:</strong>
                <ul style="margin: 10px 0 0 20px;">
                    <li>Dateien werden aus dem Backup kopiert</li>
                    <li>wp-config.php wird neu erstellt</li>
                    <li>siteurl/home + DB-URLs werden migriert (inkl. serialisierter Daten)</li>
                    <li>Pfade werden ersetzt</li>
                    <li>Transients/Rewrite Rules werden zurückgesetzt</li>
                    <li>Theme wird bei Bedarf auf Standard-Theme gefixt</li>
                </ul>
            </div>

            <form method="post">
                <input type="hidden" name="action" value="restore_files">

                <div class="form-group">
                    <label>Website-URL:</label>
                    <input type="url" name="new_url" value="<?php echo h($auto_url); ?>" required>
                    <div class="help-text">Ohne abschließenden Slash</div>
                </div>

                <button type="submit" class="btn">Wiederherstellung starten →</button>
            </form>

        <?php elseif ($current_step === 'complete'): ?>
            <div class="success-message">
                <h3>Wiederherstellung erfolgreich</h3>
                <p>WordPress wurde wiederhergestellt. Falls du noch einen „kritischen Fehler“ siehst, prüfe zuerst das Theme und Plugin-Ordner (und installer_error.log).</p>
            </div>

            <div class="info-box">
                <strong>Neue URL:</strong><br>
                <a href="<?php echo h((string)($_SESSION['new_url'] ?? $auto_url)); ?>" style="color:#2196f3; font-weight:bold; text-decoration:none;">
                    <?php echo h((string)($_SESSION['new_url'] ?? $auto_url)); ?>
                </a>
            </div>

            <div class="warning-box">
                <strong>Wichtige Hinweise:</strong>
                <ul style="margin: 10px 0 0 20px;">
                    <li>Gehe zu <strong>Einstellungen → Permalinks</strong> und klicke „Speichern“</li>
                    <li>Wenn Login nicht geht: Cookies löschen und prüfen ob URL/HTTPS korrekt ist</li>
                    <li>Wenn „kritischer Fehler“: prüfe <code>wp-content/themes</code> und <code>wp-content/plugins</code> sowie <code>installer_error.log</code></li>
                </ul>
            </div>

            <?php if (!empty($_SESSION['itn_log']) && is_array($_SESSION['itn_log'])): ?>
                <details style="margin: 20px 0;">
                    <summary style="cursor:pointer; font-weight:bold; padding:10px; background:#f6f7f7; border-radius:4px;">
                        Installation-Log anzeigen (<?php echo count($_SESSION['itn_log']); ?> Einträge)
                    </summary>
                    <div class="log-box">
                        <?php foreach ($_SESSION['itn_log'] as $log): ?>
                            <div><?php echo h($log); ?></div>
                        <?php endforeach; ?>
                    </div>
                </details>
            <?php endif; ?>

            <a href="<?php echo h((string)($_SESSION['new_url'] ?? $auto_url)); ?>/wp-admin/" class="btn" style="text-decoration:none; display:block; text-align:center; margin-top:20px;">
                Zum WordPress-Admin →
            </a>

            <p style="text-align:center; margin-top:20px; color:#999; font-size:13px;">
                Installer und ZIP werden jetzt gelöscht…
            </p>

            <?php
            // Cleanup
            @unlink($LOCK_FILE);

            // Versuch: Installer löschen
            @unlink(__FILE__);

            // Session bereinigen (ZIP Upload tmp existiert nicht mehr; lokale ZIPs NICHT automatisch löschen,
            // weil das oft zu "wo ist mein Backup hin?" führt. Wenn du das willst, kann man es wieder aktivieren.)
            session_destroy();
            ?>
        <?php endif; ?>
    </div>
</div>
</body>
</html>