<?php
if (!defined('ABSPATH')) { exit; }

class ITN_Helpers {
    public static function path_is_excluded($path, $excludes) {
        foreach ($excludes as $pattern) {
            $pattern = trim($pattern);
            if ($pattern === '') continue;
            $pathNorm = str_replace('\\', '/', $path);
            $patternNorm = str_replace('\\', '/', $pattern);
            if (strpos($patternNorm, '*') !== false) {
                $quoted = preg_quote($patternNorm, '/');
                $regex = '/^' . str_replace('\*', '.*', $quoted) . '$/i';
                if (preg_match($regex, $pathNorm)) return true;
            } else {
                if (stripos($pathNorm, $patternNorm) !== false) return true;
            }
        }
        return false;
    }

    public static function ensure_dir($dir) {
        if (!file_exists($dir)) return wp_mkdir_p($dir);
        return is_dir($dir);
    }

    public static function esc_filename($name) {
        return preg_replace('/[^A-Za-z0-9._-]/', '_', $name);
    }

    public static function unserialize_safe($value) {
        if (!is_string($value)) return $value;
        $trim = trim($value);
        $un = @unserialize($trim, ['allowed_classes' => false]);
        if ($un !== false || $trim === 'b:0;') return $un;
        return $value;
    }

    public static function deep_replace_safe($data, $search, $replace) {
        if (is_string($data)) return str_replace($search, $replace, $data);
        if (is_array($data)) { foreach ($data as $k => $v) $data[$k] = self::deep_replace_safe($v, $search, $replace); return $data; }
        return $data;
    }

    public static function format_bytes($bytes, $precision = 1) {
        $bytes = max(0, (int)$bytes);
        $units = ['B','KB','MB','GB','TB'];
        $power = $bytes > 0 ? floor(log($bytes, 1024)) : 0;
        $power = min($power, count($units) - 1);
        $value = $bytes / pow(1024, $power);
        return number_format($value, $precision, ',', '.') . ' ' . $units[$power];
    }

    public static function format_datetime($ts) {
        return date('Y-m-d H:i', (int)$ts);
    }

    public static function progress_set($run_id, $percent, $message, $extra = []) {
        $data = array_merge(['percent' => (int)$percent, 'message' => (string)$message, 'time' => time()], $extra);
        set_transient('itn_progress_' . $run_id, $data, HOUR_IN_SECONDS);
    }
    
    public static function progress_get($run_id) {
        return get_transient('itn_progress_' . $run_id);
    }

    public static function build_excludes($opts) {
        $manual = $opts['exclude_paths'] ?? [];
        $patterns = array_filter(array_map('trim', (array)$manual));
        return array_values(array_unique($patterns));
    }

    public static function send_domain_mail($to, $subject, $body, $from_local = 'itn-sicherung', $from_name = 'ITN - Sicherung') {
        $site_url = home_url();
        $server_name = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '';
        $host = parse_url($site_url, PHP_URL_HOST);
        if (!$host && $server_name) $host = $server_name;
        $host = preg_replace('/^www\./i', '', (string)$host);
        $from_email = $from_local . '@' . ($host ?: 'localhost');

        $headers = [
            'Content-Type: text/plain; charset=UTF-8',
            'From: ' . $from_name . ' <' . $from_email . '>',
        ];
        return wp_mail($to, $subject, $body, $headers);
    }

    public static function rrmdir($dir) {
        if (!is_dir($dir)) return true;
        $items = @scandir($dir);
        if (!$items) return false;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $path = $dir . '/' . $item;
            if (is_dir($path)) {
                if (!self::rrmdir($path)) return false;
            } else {
                if (!@unlink($path)) return false;
            }
        }
        return @rmdir($dir);
    }

    public static function db_serialized_search_replace($old, $new) {
        global $wpdb;
        $old = (string)$old; $new = (string)$new;
        if ($old === '' || $old === $new) return;

        @set_time_limit(0);
        $tables = $wpdb->get_col('SHOW TABLES');
        if (empty($tables)) return;

        foreach ($tables as $table) {
            $columns = $wpdb->get_results("SHOW COLUMNS FROM `$table`", ARRAY_A);
            if (!$columns) continue;

            $pk = null;
            foreach ($columns as $col) {
                if (!empty($col['Key']) && $col['Key'] === 'PRI') { $pk = $col['Field']; break; }
            }
            if (!$pk) {
                $fields = array_column($columns, 'Field');
                foreach (['ID','id',$table . '_id'] as $c) { if (in_array($c, $fields, true)) { $pk = $c; break; } }
                if (!$pk) $pk = $fields[0] ?? null;
            }
            if (!$pk) continue;

            $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM `$table`");
            $limit = 500;
            for ($offset = 0; $offset < $total; $offset += $limit) {
                $rows = $wpdb->get_results("SELECT * FROM `$table` LIMIT $offset, $limit", ARRAY_A);
                if (!$rows) break;

                foreach ($rows as $row) {
                    $changed = false;
                    $update = [];

                    foreach ($row as $col => $val) {
                        if ($val === null || !is_string($val)) continue;

                        $maybe = self::unserialize_safe($val);
                        if (is_array($maybe)) {
                            $newval = serialize(self::deep_replace_safe($maybe, $old, $new));
                            if ($newval !== $val) { $changed = true; $update[$col] = $newval; }
                        } elseif (is_string($maybe)) {
                            $newval = str_replace($old, $new, $maybe);
                            if ($newval !== $maybe) { $changed = true; $update[$col] = $newval; }
                        }
                    }

                    if ($changed && isset($row[$pk])) {
                        $wpdb->update($table, $update, [$pk => $row[$pk]]);
                    }
                }
            }
        }
    }

    public static function db_serialized_path_replace($old_path, $new_path) {
        $old_path = trim((string)$old_path, '/');
        $new_path = trim((string)$new_path, '/');

        $from = $old_path === '' ? '' : '/' . $old_path . '/';
        $to   = $new_path === '' ? '/' : '/' . $new_path . '/';

        if ($from === $to) return;
        self::db_serialized_search_replace($from, $to);
    }

    public static function db_serialized_abs_path_replace($old_abs, $new_abs) {
        $old_abs = rtrim(str_replace('\\','/', (string)$old_abs), '/');
        $new_abs = rtrim(str_replace('\\','/', (string)$new_abs), '/');
        if (!$old_abs || !$new_abs || $old_abs === $new_abs) return;
        self::db_serialized_search_replace($old_abs, $new_abs);
    }

    public static function db_enforce_scheme_all($host, $scheme) {
        $host = trim((string)$host);
        $scheme = trim((string)$scheme);
        if (!$host || !$scheme) return;

        $from = ($scheme === 'https') ? ('http://' . $host) : ('https://' . $host);
        $to   = ($scheme === 'https') ? ('https://' . $host) : ('http://' . $host);

        self::db_serialized_search_replace($from, $to);
    }

    public static function rewrite_wp_config_urls($new_url, $force_ssl_admin = null) {
        $config = ABSPATH . 'wp-config.php';
        if (!file_exists($config) || !is_writable($config)) return false;

        $content = @file_get_contents($config);
        if ($content === false) return false;

        $new_url = rtrim((string)$new_url, '/');
        $scheme  = parse_url($new_url, PHP_URL_SCHEME) ?: 'https';
        $host    = parse_url($new_url, PHP_URL_HOST) ?: '';
        $path    = parse_url($new_url, PHP_URL_PATH);
        $path    = ($path === '/') ? '' : ($path ?: '');

        $replacements = [
            "/define\\(\\s*'WP_HOME'\\s*,\\s*'[^']*'\\s*\\);/"    => "define('WP_HOME', '" . addslashes($new_url) . "');",
            "/define\\(\\s*'WP_SITEURL'\\s*,\\s*'[^']*'\\s*\\);/" => "define('WP_SITEURL', '" . addslashes($new_url) . "');",
        ];
        foreach ($replacements as $rx => $rep) {
            $content = preg_replace($rx, $rep, $content, 1);
        }
        if (!preg_match("/define\\(\\s*'WP_HOME'\\s*,/", $content)) {
            $content .= "\ndefine('WP_HOME', '" . addslashes($new_url) . "');";
        }
        if (!preg_match("/define\\(\\s*'WP_SITEURL'\\s*,/", $content)) {
            $content .= "\ndefine('WP_SITEURL', '" . addslashes($new_url) . "');";
        }

        $want_ssl = $force_ssl_admin !== null ? (bool)$force_ssl_admin : ($scheme === 'https');
        $ssl_line = "define('FORCE_SSL_ADMIN', " . ($want_ssl ? 'true' : 'false') . ");";
        if (preg_match("/define\\(\\s*'FORCE_SSL_ADMIN'\\s*,\\s*(true|false)\\s*\\);/", $content)) {
            $content = preg_replace("/define\\(\\s*'FORCE_SSL_ADMIN'\\s*,\\s*(true|false)\\s*\\);/", $ssl_line, $content, 1);
        } else {
            $content .= "\n" . $ssl_line;
        }

        if (preg_match("/define\\(\\s*'MULTISITE'\\s*,\\s*true\\s*\\);/", $content)) {
            $dom_line  = "define('DOMAIN_CURRENT_SITE', '" . addslashes($host) . "');";
            $path_line = "define('PATH_CURRENT_SITE', '" . addslashes(($path ? $path : '/')) . "');";
            if (preg_match("/define\\(\\s*'DOMAIN_CURRENT_SITE'\\s*,\\s*'[^']*'\\s*\\);/", $content)) {
                $content = preg_replace("/define\\(\\s*'DOMAIN_CURRENT_SITE'\\s*,\\s*'[^']*'\\s*\\);/", $dom_line, $content, 1);
            } else {
                $content .= "\n" . $dom_line;
            }
            if (preg_match("/define\\(\\s*'PATH_CURRENT_SITE'\\s*,\\s*'[^']*'\\s*\\);/", $content)) {
                $content = preg_replace("/define\\(\\s*'PATH_CURRENT_SITE'\\s*,\\s*'[^']*'\\s*\\);/", $path_line, $content, 1);
            } else {
                $content .= "\n" . $path_line;
            }
        }

        return @file_put_contents($config, $content) !== false;
    }

    /* Secret-Encryption / Masking für OneDrive Client-ID */
    protected static function crypto_key() {
        $sources = [
            defined('AUTH_KEY') ? AUTH_KEY : '',
            defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : '',
            defined('LOGGED_IN_KEY') ? LOGGED_IN_KEY : '',
            defined('NONCE_KEY') ? NONCE_KEY : '',
            get_site_url(),
        ];
        return hash('sha256', implode('|', $sources), true);
    }
    
    public static function encrypt_secret($plain) {
        $plain = (string)$plain;
        if ($plain === '') return '';
        if (function_exists('openssl_encrypt')) {
            $key = self::crypto_key();
            $iv = random_bytes(16);
            $cipher = openssl_encrypt($plain, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
            return 'enc:' . base64_encode($iv . $cipher);
        }
        return 'b64:' . base64_encode($plain);
    }
    
    public static function decrypt_secret($enc) {
        $enc = (string)$enc;
        if ($enc === '') return '';
        if (strpos($enc, 'enc:') === 0 && function_exists('openssl_decrypt')) {
            $data = base64_decode(substr($enc, 4), true);
            if ($data === false || strlen($data) < 17) return '';
            $iv = substr($data, 0, 16);
            $cipher = substr($data, 16);
            $key = self::crypto_key();
            $plain = openssl_decrypt($cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
            return $plain === false ? '' : $plain;
        }
        if (strpos($enc, 'b64:') === 0) {
            $data = base64_decode(substr($enc, 4), true);
            return $data === false ? '' : $data;
        }
        return '';
    }
    
    public static function mask_secret($plain, $visible = 4) {
        $plain = (string)$plain;
        if ($plain === '') return '';
        $len = strlen($plain);
        if ($len <= $visible) return str_repeat('•', $len);
        return str_repeat('•', max(0, $len - $visible)) . substr($plain, -$visible);
    }
    
    public static function get_onedrive_client_id($opts) {
        if (!empty($opts['onedrive_client_id_enc'])) {
            return self::decrypt_secret($opts['onedrive_client_id_enc']);
        }
        if (!empty($opts['onedrive_client_id'])) {
            return (string)$opts['onedrive_client_id'];
        }
        return '';
    }

    /* HTTP + Cloud Helpers (S3, Azure, OneDrive) */
    public static function has_curl() { return function_exists('curl_init') && function_exists('curl_exec'); }

    public static function http_put_file($url, $filePath, $headers = [], $timeout = 600) {
        $size = @filesize($filePath);
        if (self::has_curl()) {
            $ch = curl_init($url);
            $fh = fopen($filePath, 'rb');
            $hdrs = [];
            foreach ($headers as $k => $v) $hdrs[] = $k . ': ' . $v;
            curl_setopt($ch, CURLOPT_PUT, true);
            curl_setopt($ch, CURLOPT_INFILE, $fh);
            if ($size !== false) curl_setopt($ch, CURLOPT_INFILESIZE, $size);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $hdrs);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            $body = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $err  = curl_error($ch);
            curl_close($ch);
            fclose($fh);
            if ($err) return ['success' => false, 'code' => $code, 'error' => $err];
            return ['success' => ($code >= 200 && $code < 300), 'code' => $code, 'body' => $body];
        } else {
            $data = @file_get_contents($filePath);
            if ($data === false) return ['success' => false, 'code' => 0, 'error' => 'read_failed'];
            $resp = wp_remote_request($url, [
                'method'  => 'PUT',
                'headers' => $headers,
                'body'    => $data,
                'timeout' => $timeout,
            ]);
            if (is_wp_error($resp)) return ['success' => false, 'code' => 0, 'error' => $resp->get_error_message()];
            $code = wp_remote_retrieve_response_code($resp);
            $body = wp_remote_retrieve_body($resp);
            return ['success' => ($code >= 200 && $code < 300), 'code' => $code, 'body' => $body];
        }
    }

    public static function s3_presign_put($region, $accessKey, $secretKey, $bucket, $key, $expires = 3600) {
        $service   = 's3';
        $host      = 's3.' . $region . '.amazonaws.com';
        $algorithm = 'AWS4-HMAC-SHA256';
        $amzDate   = gmdate('Ymd\THis\Z');
        $dateStamp = gmdate('Ymd');

        $canonical_uri = '/' . rawurlencode($bucket) . '/' . str_replace('%2F', '/', rawurlencode($key));
        $credential_scope = $dateStamp . '/' . $region . '/' . $service . '/aws4_request';

        $canonical_query = 'X-Amz-Algorithm=' . rawurlencode($algorithm)
            . '&X-Amz-Credential=' . rawurlencode($accessKey . '/' . $credential_scope)
            . '&X-Amz-Date=' . rawurlencode($amzDate)
            . '&X-Amz-Expires=' . rawurlencode((string)$expires)
            . '&X-Amz-SignedHeaders=' . rawurlencode('host');

        $canonical_headers = 'host:' . $host . "\n";
        $signed_headers    = 'host';
        $payload_hash      = 'UNSIGNED-PAYLOAD';

        $canonical_request = "PUT\n{$canonical_uri}\n{$canonical_query}\n{$canonical_headers}\n{$signed_headers}\n{$payload_hash}";
        $string_to_sign    = $algorithm . "\n" . $amzDate . "\n" . $credential_scope . "\n" . hash('sha256', $canonical_request);

        $kSecret  = 'AWS4' . $secretKey;
        $kDate    = hash_hmac('sha256', $dateStamp, $kSecret, true);
        $kRegion  = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        $signature = hash_hmac('sha256', $string_to_sign, $kSigning);
        $url = 'https://' . $host . $canonical_uri . '?' . $canonical_query . '&X-Amz-Signature=' . $signature;
        return $url;
    }

    public static function azure_blob_sas_url($account, $accountKeyBase64, $container, $blob, $permissions = 'w', $expirySeconds = 3600, $protocol = 'https', $version = '2020-10-02') {
        $start  = gmdate('Y-m-d\TH:i:s\Z', time() - 300);
        $expiry = gmdate('Y-m-d\TH:i:s\Z', time() + $expirySeconds);
        $canonicalizedResource = '/blob/' . $account . '/' . $container . '/' . $blob;

        $stringToSign = $permissions . "\n"
            . $start . "\n"
            . $expiry . "\n"
            . $canonicalizedResource . "\n"
            . "\n"
            . "\n"
            . $protocol . "\n"
            . $version . "\n"
            . "b\n"
            . "\n"
            . "\n"
            . "\n"
            . "\n"
            . "\n";

        $key = base64_decode($accountKeyBase64);
        $sig = base64_encode(hash_hmac('sha256', $stringToSign, $key, true));

        $query = [
            'sv'  => $version,
            'spr' => $protocol,
            'st'  => $start,
            'se'  => $expiry,
            'sr'  => 'b',
            'sp'  => $permissions,
            'sig' => $sig,
        ];
        $sas = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        $url = 'https://' . $account . '.blob.core.windows.net/' . rawurlencode($container) . '/' . str_replace('%2F', '/', rawurlencode($blob)) . '?' . $sas;
        return $url;
    }

    public static function od_device_code_start($tenant, $client_id, $scope = 'offline_access files.readwrite') {
        $tenant = trim($tenant ?: 'consumers');
        $url = 'https://login.microsoftonline.com/' . rawurlencode($tenant) . '/oauth2/v2.0/devicecode';
        $resp = wp_remote_post($url, [
            'body' => ['client_id' => $client_id, 'scope' => $scope],
            'timeout' => 30,
        ]);
        if (is_wp_error($resp)) return ['success' => false, 'message' => $resp->get_error_message()];
        $code = wp_remote_retrieve_response_code($resp);
        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if ($code !== 200 || !is_array($body)) return ['success' => false, 'message' => 'Device-Code Fehler'];
        return ['success' => true] + $body;
    }
    
    public static function od_device_code_poll($tenant, $client_id, $device_code) {
        $tenant = trim($tenant ?: 'consumers');
        $url = 'https://login.microsoftonline.com/' . rawurlencode($tenant) . '/oauth2/v2.0/token';
        $resp = wp_remote_post($url, [
            'body' => [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
                'client_id'  => $client_id,
                'device_code'=> $device_code,
            ],
            'timeout' => 30,
        ]);
        if (is_wp_error($resp)) return ['success' => false, 'message' => $resp->get_error_message()];
        $code = wp_remote_retrieve_response_code($resp);
        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if ($code !== 200 || empty($body['access_token'])) {
            $err = $body['error'] ?? 'poll_failed';
            return ['success' => false, 'message' => $err];
        }
        return ['success' => true] + $body;
    }
    
    public static function od_refresh_token($tenant, $client_id, $refresh_token) {
        $tenant = trim($tenant ?: 'consumers');
        $url = 'https://login.microsoftonline.com/' . rawurlencode($tenant) . '/oauth2/v2.0/token';
        $resp = wp_remote_post($url, [
            'body' => [
                'grant_type'    => 'refresh_token',
                'client_id'     => $client_id,
                'refresh_token' => $refresh_token,
                'scope'         => 'offline_access files.readwrite',
            ],
            'timeout' => 30,
        ]);
        if (is_wp_error($resp)) return ['success' => false, 'message' => $resp->get_error_message()];
        $code = wp_remote_retrieve_response_code($resp);
        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if ($code !== 200 || empty($body['access_token'])) {
            return ['success' => false, 'message' => $body['error'] ?? 'refresh_failed'];
        }
        return ['success' => true] + $body;
    }
    
    public static function od_upload_file($access_token, $file, $drivePath = 'backups') {
        $size = @filesize($file);
        if ($size === false) return ['success' => false, 'message' => 'Datei nicht lesbar'];
        $drivePath = trim($drivePath, '/');
        $basename = basename($file);
        $target   = ($drivePath !== '' ? ($drivePath . '/' . $basename) : $basename);

        $url = 'https://graph.microsoft.com/v1.0/me/drive/root:/' . rawurlencode($target) . ':/createUploadSession';
        $resp = wp_remote_post($url, [
            'headers' => ['Authorization' => 'Bearer ' . $access_token, 'Content-Type' => 'application/json'],
            'body' => wp_json_encode(['item' => ['@microsoft.graph.conflictBehavior' => 'replace']]),
            'timeout' => 30,
        ]);
        if (is_wp_error($resp)) return ['success' => false, 'message' => $resp->get_error_message()];
        $code = wp_remote_retrieve_response_code($resp);
        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if ($code >= 300 || empty($body['uploadUrl'])) return ['success' => false, 'message' => 'UploadSession fehlgeschlagen'];
        $uploadUrl = $body['uploadUrl'];

        $chunkSize = 5 * 1024 * 1024;
        $fp = fopen($file, 'rb');
        if (!$fp) return ['success' => false, 'message' => 'Datei konnte nicht geöffnet werden'];
        $pos = 0; $maxRetry = 3;
        while ($pos < $size) {
            $len = min($chunkSize, $size - $pos);
            $data = fread($fp, $len);
            if ($data === false) { fclose($fp); return ['success' => false, 'message' => 'Lesefehler bei Chunk']; }
            if (!self::has_curl()) { fclose($fp); return ['success' => false, 'message' => 'cURL benötigt für OneDrive-Upload']; }
            $ch = curl_init($uploadUrl);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Length: ' . strlen($data),
                'Content-Range: bytes ' . $pos . '-' . ($pos + strlen($data) - 1) . '/' . $size,
            ]);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 300);
            $respBody = curl_exec($ch);
            $respCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $err = curl_error($ch);
            curl_close($ch);

            if ($err) { fclose($fp); return ['success' => false, 'message' => $err]; }
            if ($respCode === 429 || ($respCode >= 500 && $respCode < 600)) {
                $retry = 0;
                while ($retry < $maxRetry && $respCode !== 201 && $respCode !== 200 && $respCode !== 202) {
                    usleep(500000);
                    $ch = curl_init($uploadUrl);
                    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
                    curl_setopt($ch, CURLOPT_HTTPHEADER, [
                        'Content-Length: ' . strlen($data),
                        'Content-Range: bytes ' . $pos . '-' . ($pos + strlen($data) - 1) . '/' . $size,
                    ]);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 300);
                    $respBody = curl_exec($ch);
                    $respCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                    curl_close($ch);
                    $retry++;
                }
            }
            if ($respCode >= 300 && $respCode !== 202) { fclose($fp); return ['success' => false, 'code' => $respCode, 'message' => 'Fehler beim Chunk']; }
            $pos += $len;
        }
        fclose($fp);
        return ['success' => true];
    }
}