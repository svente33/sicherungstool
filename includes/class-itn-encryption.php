<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ITN Encryption Class
 * 
 * Provides pure-PHP encryption without external CLI tools.
 * Uses Sodium (preferred) or OpenSSL as fallback.
 * 
 * Container format: HEADER(8) + SALT(32) + NONCE(24/16) + CIPHERTEXT + TAG(16)
 */
class ITN_Encryption {
    
    const FORMAT_VERSION = 1;
    const HEADER = 'ITNENC01'; // 8 bytes
    const SALT_LENGTH = 32;
    const SODIUM_NONCE_LENGTH = 24; // NONCE_BYTES for secretbox
    const OPENSSL_IV_LENGTH = 16;   // For AES-256-GCM
    const TAG_LENGTH = 16;          // Auth tag for GCM
    
    /**
     * Check if encryption is available
     * 
     * @return array ['available' => bool, 'method' => string|null]
     */
    public static function check_availability() {
        if (function_exists('sodium_crypto_secretbox') && function_exists('sodium_crypto_pwhash')) {
            return ['available' => true, 'method' => 'sodium-secretbox'];
        }
        
        if (function_exists('openssl_encrypt') && in_array('aes-256-gcm', openssl_get_cipher_methods())) {
            return ['available' => true, 'method' => 'openssl-aes-256-gcm'];
        }
        
        return ['available' => false, 'method' => null];
    }
    
    /**
     * Derive key from password using Argon2id or PBKDF2
     * 
     * @param string $password
     * @param string $salt
     * @param string $method 'sodium-secretbox' or 'openssl-aes-256-gcm'
     * @return string Binary key
     */
    protected static function derive_key($password, $salt, $method) {
        if ($method === 'sodium-secretbox' && function_exists('sodium_crypto_pwhash')) {
            // Argon2id - highly recommended
            $key_length = SODIUM_CRYPTO_SECRETBOX_KEYBYTES; // 32 bytes
            $key = sodium_crypto_pwhash(
                $key_length,
                $password,
                $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
            return $key;
        } else {
            // PBKDF2 fallback for OpenSSL
            return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
        }
    }
    
    /**
     * Encrypt a file and save as container
     * 
     * @param string $input_path Path to plaintext file
     * @param string $output_path Path to save encrypted container
     * @param string $password Password for encryption
     * @return array ['success' => bool, 'message' => string, 'method' => string|null]
     */
    public static function encrypt_file($input_path, $output_path, $password) {
        if (!file_exists($input_path)) {
            return ['success' => false, 'message' => 'Input file does not exist', 'method' => null];
        }
        
        if (empty($password)) {
            return ['success' => false, 'message' => 'Password is required', 'method' => null];
        }
        
        $avail = self::check_availability();
        if (!$avail['available']) {
            return ['success' => false, 'message' => 'No encryption method available', 'method' => null];
        }
        
        $method = $avail['method'];
        
        // Read plaintext
        $plaintext = file_get_contents($input_path);
        if ($plaintext === false) {
            return ['success' => false, 'message' => 'Failed to read input file', 'method' => null];
        }
        
        // Generate salt
        if (function_exists('random_bytes')) {
            $salt = random_bytes(self::SALT_LENGTH);
        } else {
            $salt = openssl_random_pseudo_bytes(self::SALT_LENGTH);
        }
        
        // Derive key
        $key = self::derive_key($password, $salt, $method);
        
        // Encrypt based on method
        if ($method === 'sodium-secretbox') {
            // Sodium secretbox (XSalsa20-Poly1305)
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
            
            // Container: HEADER + SALT + NONCE + CIPHERTEXT_WITH_TAG
            $container = self::HEADER . $salt . $nonce . $ciphertext;
            
            // Clean up
            sodium_memzero($key);
            sodium_memzero($plaintext);
            
        } else {
            // OpenSSL AES-256-GCM
            $iv = openssl_random_pseudo_bytes(self::OPENSSL_IV_LENGTH);
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
            
            if ($ciphertext === false) {
                return ['success' => false, 'message' => 'OpenSSL encryption failed', 'method' => null];
            }
            
            // Container: HEADER + SALT + IV + CIPHERTEXT + TAG
            $container = self::HEADER . $salt . $iv . $ciphertext . $tag;
        }
        
        // Write container
        if (file_put_contents($output_path, $container) === false) {
            return ['success' => false, 'message' => 'Failed to write output file', 'method' => null];
        }
        
        return [
            'success' => true,
            'message' => 'File encrypted successfully',
            'method' => $method,
            'size' => strlen($container)
        ];
    }
    
    /**
     * Decrypt a container file
     * 
     * @param string $input_path Path to encrypted container
     * @param string $output_path Path to save decrypted file
     * @param string $password Password for decryption
     * @return array ['success' => bool, 'message' => string]
     */
    public static function decrypt_file($input_path, $output_path, $password) {
        if (!file_exists($input_path)) {
            return ['success' => false, 'message' => 'Input file does not exist'];
        }
        
        if (empty($password)) {
            return ['success' => false, 'message' => 'Password is required'];
        }
        
        // Read container
        $container = file_get_contents($input_path);
        if ($container === false) {
            return ['success' => false, 'message' => 'Failed to read input file'];
        }
        
        $container_len = strlen($container);
        $header_len = strlen(self::HEADER);
        
        // Validate header
        if ($container_len < $header_len) {
            return ['success' => false, 'message' => 'Invalid container: too short'];
        }
        
        $header = substr($container, 0, $header_len);
        if ($header !== self::HEADER) {
            return ['success' => false, 'message' => 'Invalid container: wrong header'];
        }
        
        // Extract salt
        $pos = $header_len;
        if ($container_len < $pos + self::SALT_LENGTH) {
            return ['success' => false, 'message' => 'Invalid container: missing salt'];
        }
        $salt = substr($container, $pos, self::SALT_LENGTH);
        $pos += self::SALT_LENGTH;
        
        // Try Sodium first
        if (function_exists('sodium_crypto_secretbox_open') && function_exists('sodium_crypto_pwhash')) {
            $nonce_len = self::SODIUM_NONCE_LENGTH;
            if ($container_len >= $pos + $nonce_len) {
                $nonce = substr($container, $pos, $nonce_len);
                $ciphertext = substr($container, $pos + $nonce_len);
                
                // Derive key
                $key = self::derive_key($password, $salt, 'sodium-secretbox');
                
                // Decrypt
                $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
                sodium_memzero($key);
                
                if ($plaintext !== false) {
                    // Success
                    if (file_put_contents($output_path, $plaintext) === false) {
                        sodium_memzero($plaintext);
                        return ['success' => false, 'message' => 'Failed to write output file'];
                    }
                    sodium_memzero($plaintext);
                    return ['success' => true, 'message' => 'File decrypted successfully (Sodium)'];
                }
            }
        }
        
        // Try OpenSSL
        if (function_exists('openssl_decrypt')) {
            $iv_len = self::OPENSSL_IV_LENGTH;
            $tag_len = self::TAG_LENGTH;
            
            if ($container_len >= $pos + $iv_len + $tag_len) {
                $iv = substr($container, $pos, $iv_len);
                $ciphertext_and_tag = substr($container, $pos + $iv_len);
                
                // Extract tag from end
                $ciphertext = substr($ciphertext_and_tag, 0, -$tag_len);
                $tag = substr($ciphertext_and_tag, -$tag_len);
                
                // Derive key
                $key = self::derive_key($password, $salt, 'openssl-aes-256-gcm');
                
                // Decrypt
                $plaintext = openssl_decrypt(
                    $ciphertext,
                    'aes-256-gcm',
                    $key,
                    OPENSSL_RAW_DATA,
                    $iv,
                    $tag
                );
                
                if ($plaintext !== false) {
                    // Success
                    if (file_put_contents($output_path, $plaintext) === false) {
                        return ['success' => false, 'message' => 'Failed to write output file'];
                    }
                    return ['success' => true, 'message' => 'File decrypted successfully (OpenSSL)'];
                }
            }
        }
        
        return ['success' => false, 'message' => 'Decryption failed: wrong password or corrupted file'];
    }
    
    /**
     * Check if ZipArchive supports AES encryption
     * 
     * @return bool
     */
    public static function ziparchive_has_aes() {
        if (!class_exists('ZipArchive')) {
            return false;
        }
        
        // Check if encryption methods are available
        if (!method_exists('ZipArchive', 'setEncryptionName')) {
            return false;
        }
        
        if (!defined('ZipArchive::EM_AES_256')) {
            return false;
        }
        
        return true;
    }
}
