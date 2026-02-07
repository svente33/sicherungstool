<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ITN Encryption Helper
 * Handles container encryption using OpenSSL AES-256-GCM as fallback when ZipArchive AES is not available
 */
class ITN_Encryption {
    
    const MAGIC = 'ITNENC01'; // 8 bytes magic header
    const VERSION = 1;
    const SALT_LENGTH = 16;
    const IV_LENGTH = 12; // GCM recommended IV length
    const TAG_LENGTH = 16;
    const PBKDF2_ITERATIONS = 100000; // OWASP recommended minimum
    const MIN_PASSWORD_LENGTH = 12;
    
    /**
     * Check if encryption capabilities are available
     * Returns array with capability information
     */
    public static function check_capabilities() {
        $caps = [
            'ziparchive_aes' => false,
            'openssl_gcm' => false,
            'has_encryption' => false,
        ];
        
        // Check ZipArchive AES-256
        if (class_exists('ZipArchive') && 
            method_exists('ZipArchive', 'setEncryptionName') && 
            defined('ZipArchive::EM_AES_256')) {
            $caps['ziparchive_aes'] = true;
            $caps['has_encryption'] = true;
        }
        
        // Check OpenSSL AES-256-GCM
        if (function_exists('openssl_encrypt') && 
            function_exists('openssl_decrypt') && 
            function_exists('openssl_pbkdf2') && 
            in_array('aes-256-gcm', openssl_get_cipher_methods())) {
            $caps['openssl_gcm'] = true;
            $caps['has_encryption'] = true;
        }
        
        return $caps;
    }
    
    /**
     * Validate password meets minimum requirements
     */
    public static function validate_password($password) {
        if (!is_string($password)) {
            return ['valid' => false, 'message' => 'Passwort muss ein String sein'];
        }
        
        if (strlen($password) < self::MIN_PASSWORD_LENGTH) {
            return ['valid' => false, 'message' => 'Passwort muss mindestens ' . self::MIN_PASSWORD_LENGTH . ' Zeichen lang sein'];
        }
        
        return ['valid' => true];
    }
    
    /**
     * Encrypt a file using OpenSSL AES-256-GCM container format
     * 
     * @param string $source_path Path to source file (e.g., backup.zip)
     * @param string $target_path Path to encrypted output file (e.g., backup.zip.enc)
     * @param string $password Encryption password
     * @return array ['success' => bool, 'message' => string]
     */
    public static function encrypt_file($source_path, $target_path, $password) {
        try {
            // Validate password
            $pw_check = self::validate_password($password);
            if (!$pw_check['valid']) {
                return ['success' => false, 'message' => $pw_check['message']];
            }
            
            // Check OpenSSL availability
            if (!function_exists('openssl_encrypt') || !function_exists('openssl_pbkdf2')) {
                return ['success' => false, 'message' => 'OpenSSL-Funktionen nicht verfügbar'];
            }
            
            if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
                return ['success' => false, 'message' => 'AES-256-GCM nicht verfügbar'];
            }
            
            // Check source file
            if (!file_exists($source_path) || !is_readable($source_path)) {
                return ['success' => false, 'message' => 'Quelldatei nicht lesbar: ' . $source_path];
            }
            
            // Read source data
            $plaintext = file_get_contents($source_path);
            if ($plaintext === false) {
                return ['success' => false, 'message' => 'Konnte Quelldatei nicht lesen'];
            }
            
            // Generate random salt and IV
            $salt = random_bytes(self::SALT_LENGTH);
            $iv = random_bytes(self::IV_LENGTH);
            
            // Derive encryption key using PBKDF2
            $key = openssl_pbkdf2($password, $salt, 32, self::PBKDF2_ITERATIONS, 'sha256');
            if ($key === false) {
                return ['success' => false, 'message' => 'Schlüsselableitung fehlgeschlagen'];
            }
            
            // Encrypt data
            $tag = '';
            $ciphertext = openssl_encrypt(
                $plaintext,
                'aes-256-gcm',
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                '',
                self::TAG_LENGTH
            );
            
            if ($ciphertext === false || strlen($tag) !== self::TAG_LENGTH) {
                return ['success' => false, 'message' => 'Verschlüsselung fehlgeschlagen'];
            }
            
            // Build container format:
            // MAGIC (8) | VERSION (1) | SALT (16) | ITERATIONS (4) | IV (12) | TAG (16) | CIPHERTEXT
            $container = self::MAGIC;                                    // 8 bytes
            $container .= pack('C', self::VERSION);                      // 1 byte
            $container .= $salt;                                         // 16 bytes
            $container .= pack('N', self::PBKDF2_ITERATIONS);           // 4 bytes (unsigned long, big-endian)
            $container .= $iv;                                           // 12 bytes
            $container .= $tag;                                          // 16 bytes
            $container .= $ciphertext;                                   // variable length
            
            // Write to target file
            if (file_put_contents($target_path, $container) === false) {
                return ['success' => false, 'message' => 'Konnte verschlüsselte Datei nicht schreiben'];
            }
            
            // Clear sensitive data from memory
            $plaintext = null;
            $key = null;
            $ciphertext = null;
            
            return [
                'success' => true,
                'message' => 'Datei erfolgreich verschlüsselt',
                'method' => 'php-openssl-aes-256-gcm',
                'format_version' => self::VERSION,
            ];
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Verschlüsselungsfehler: ' . $e->getMessage()];
        }
    }
    
    /**
     * Decrypt a container-encrypted file
     * 
     * @param string $source_path Path to encrypted file (e.g., backup.zip.enc)
     * @param string $target_path Path to decrypted output file (e.g., backup.zip)
     * @param string $password Decryption password
     * @return array ['success' => bool, 'message' => string]
     */
    public static function decrypt_file($source_path, $target_path, $password) {
        try {
            // Check OpenSSL availability
            if (!function_exists('openssl_decrypt') || !function_exists('openssl_pbkdf2')) {
                return ['success' => false, 'message' => 'OpenSSL-Funktionen nicht verfügbar'];
            }
            
            if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
                return ['success' => false, 'message' => 'AES-256-GCM nicht verfügbar'];
            }
            
            // Check source file
            if (!file_exists($source_path) || !is_readable($source_path)) {
                return ['success' => false, 'message' => 'Verschlüsselte Datei nicht lesbar: ' . $source_path];
            }
            
            // Read container
            $container = file_get_contents($source_path);
            if ($container === false) {
                return ['success' => false, 'message' => 'Konnte verschlüsselte Datei nicht lesen'];
            }
            
            // Verify minimum size
            $header_size = 8 + 1 + 16 + 4 + 12 + 16; // MAGIC + VERSION + SALT + ITERATIONS + IV + TAG
            if (strlen($container) < $header_size) {
                return ['success' => false, 'message' => 'Ungültige Container-Datei (zu klein)'];
            }
            
            // Parse header
            $pos = 0;
            
            // Check magic
            $magic = substr($container, $pos, 8);
            $pos += 8;
            if ($magic !== self::MAGIC) {
                return ['success' => false, 'message' => 'Ungültiger Container-Header (falscher MAGIC)'];
            }
            
            // Read version
            $version = unpack('C', substr($container, $pos, 1))[1];
            $pos += 1;
            if ($version !== self::VERSION) {
                return ['success' => false, 'message' => 'Nicht unterstützte Container-Version: ' . $version];
            }
            
            // Read salt
            $salt = substr($container, $pos, self::SALT_LENGTH);
            $pos += self::SALT_LENGTH;
            
            // Read iterations
            $iterations = unpack('N', substr($container, $pos, 4))[1];
            $pos += 4;
            
            // Read IV
            $iv = substr($container, $pos, self::IV_LENGTH);
            $pos += self::IV_LENGTH;
            
            // Read tag
            $tag = substr($container, $pos, self::TAG_LENGTH);
            $pos += self::TAG_LENGTH;
            
            // Read ciphertext
            $ciphertext = substr($container, $pos);
            
            // Derive decryption key
            $key = openssl_pbkdf2($password, $salt, 32, $iterations, 'sha256');
            if ($key === false) {
                return ['success' => false, 'message' => 'Schlüsselableitung fehlgeschlagen'];
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
                // Clear sensitive data
                $key = null;
                return ['success' => false, 'message' => 'Entschlüsselung fehlgeschlagen (falsches Passwort oder beschädigte Datei)'];
            }
            
            // Write decrypted data
            if (file_put_contents($target_path, $plaintext) === false) {
                return ['success' => false, 'message' => 'Konnte entschlüsselte Datei nicht schreiben'];
            }
            
            // Clear sensitive data from memory
            $plaintext = null;
            $key = null;
            
            return [
                'success' => true,
                'message' => 'Datei erfolgreich entschlüsselt',
            ];
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Entschlüsselungsfehler: ' . $e->getMessage()];
        }
    }
    
    /**
     * Check if a file is an encrypted container
     */
    public static function is_encrypted_container($file_path) {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }
        
        $handle = fopen($file_path, 'rb');
        if (!$handle) {
            return false;
        }
        
        $magic = fread($handle, 8);
        fclose($handle);
        
        return $magic === self::MAGIC;
    }
}
