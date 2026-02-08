<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ITN_Encryption - Streaming encryption/decryption for large backup files
 * 
 * Supports two container formats:
 * - v1: AES-256-GCM (legacy, for backward compatibility)
 * - v2: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) with streaming support
 * 
 * Format v2 Container Structure:
 * - Magic: "ITN\x02" (4 bytes)
 * - Version: 2 (1 byte)
 * - Salt: 16 bytes
 * - Iterations: 4 bytes (big-endian, default 100000)
 * - IV: 16 bytes
 * - Ciphertext: variable length (chunked)
 * - HMAC: 32 bytes (SHA-256)
 */
class ITN_Encryption {
    
    const MAGIC_V1 = "ITN\x01";
    const MAGIC_V2 = "ITN\x02";
    const VERSION_V1 = 1;
    const VERSION_V2 = 2;
    
    const SALT_LENGTH = 16;
    const IV_LENGTH = 16;
    const HMAC_LENGTH = 32;
    const ITERATIONS_DEFAULT = 100000;
    const CHUNK_SIZE = 2097152; // 2MB chunks for streaming
    
    /**
     * Detect if file is an encrypted container and which version
     * 
     * @param string $file_path Path to file
     * @return array ['is_encrypted' => bool, 'version' => int|null]
     */
    public static function detect_container_version($file_path) {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return ['is_encrypted' => false, 'version' => null];
        }
        
        $fp = fopen($file_path, 'rb');
        if (!$fp) {
            return ['is_encrypted' => false, 'version' => null];
        }
        
        $magic = fread($fp, 4);
        fclose($fp);
        
        if ($magic === self::MAGIC_V1) {
            return ['is_encrypted' => true, 'version' => self::VERSION_V1];
        } elseif ($magic === self::MAGIC_V2) {
            return ['is_encrypted' => true, 'version' => self::VERSION_V2];
        }
        
        return ['is_encrypted' => false, 'version' => null];
    }
    
    /**
     * Check if file is an encrypted container (any version)
     * 
     * @param string $file_path Path to file
     * @return bool
     */
    public static function is_encrypted_container($file_path) {
        $info = self::detect_container_version($file_path);
        return $info['is_encrypted'];
    }
    
    /**
     * Derive encryption and HMAC keys from password using PBKDF2
     * 
     * @param string $password User password
     * @param string $salt Salt (16 bytes)
     * @param int $iterations PBKDF2 iterations
     * @return array ['enc_key' => string(32), 'hmac_key' => string(32)]
     */
    protected static function derive_keys($password, $salt, $iterations = self::ITERATIONS_DEFAULT) {
        // Derive 64 bytes total: 32 for encryption, 32 for HMAC
        $key_material = openssl_pbkdf2($password, $salt, 64, $iterations, 'sha256');
        
        return [
            'enc_key' => substr($key_material, 0, 32),
            'hmac_key' => substr($key_material, 32, 32)
        ];
    }
    
    /**
     * Encrypt a file using streaming with format v2
     * 
     * @param string $source_path Path to source file
     * @param string $dest_path Path to output encrypted container
     * @param string $password Encryption password
     * @param int $iterations PBKDF2 iterations (default: 100000)
     * @param callable|null $progress_callback Optional progress callback(percent, message)
     * @return array ['success' => bool, 'message' => string, 'size' => int]
     */
    public static function encrypt_file_streaming_v2($source_path, $dest_path, $password, $iterations = self::ITERATIONS_DEFAULT, $progress_callback = null) {
        if (!file_exists($source_path) || !is_readable($source_path)) {
            return ['success' => false, 'message' => 'Source file not readable'];
        }
        
        if (empty($password)) {
            return ['success' => false, 'message' => 'Password is required'];
        }
        
        if (!function_exists('openssl_encrypt') || !function_exists('openssl_pbkdf2')) {
            return ['success' => false, 'message' => 'OpenSSL functions not available'];
        }
        
        try {
            // Generate salt and IV
            $salt = openssl_random_pseudo_bytes(self::SALT_LENGTH);
            $iv = openssl_random_pseudo_bytes(self::IV_LENGTH);
            
            // Derive keys
            $keys = self::derive_keys($password, $salt, $iterations);
            $enc_key = $keys['enc_key'];
            $hmac_key = $keys['hmac_key'];
            
            // Open files
            $fp_in = fopen($source_path, 'rb');
            if (!$fp_in) {
                return ['success' => false, 'message' => 'Cannot open source file'];
            }
            
            $fp_out = fopen($dest_path, 'wb');
            if (!$fp_out) {
                fclose($fp_in);
                return ['success' => false, 'message' => 'Cannot create output file'];
            }
            
            // Write header
            fwrite($fp_out, self::MAGIC_V2);
            fwrite($fp_out, chr(self::VERSION_V2));
            fwrite($fp_out, $salt);
            fwrite($fp_out, pack('N', $iterations)); // 4 bytes big-endian
            fwrite($fp_out, $iv);
            
            // Initialize HMAC context
            $hmac_ctx = hash_init('sha256', HASH_HMAC, $hmac_key);
            hash_update($hmac_ctx, self::MAGIC_V2);
            hash_update($hmac_ctx, chr(self::VERSION_V2));
            hash_update($hmac_ctx, $salt);
            hash_update($hmac_ctx, pack('N', $iterations));
            hash_update($hmac_ctx, $iv);
            
            // Encrypt in chunks
            $file_size = filesize($source_path);
            $processed = 0;
            $chunk_num = 0;
            
            while (!feof($fp_in)) {
                $plaintext = fread($fp_in, self::CHUNK_SIZE);
                if ($plaintext === false || $plaintext === '') {
                    break;
                }
                
                // For CBC mode, we need to handle IV properly for chaining
                // Each chunk uses the last ciphertext block as IV for next chunk
                $ciphertext = openssl_encrypt(
                    $plaintext,
                    'aes-256-cbc',
                    $enc_key,
                    OPENSSL_RAW_DATA,
                    $iv
                );
                
                if ($ciphertext === false) {
                    fclose($fp_in);
                    fclose($fp_out);
                    @unlink($dest_path);
                    return ['success' => false, 'message' => 'Encryption failed'];
                }
                
                // Write ciphertext
                fwrite($fp_out, $ciphertext);
                
                // Update HMAC
                hash_update($hmac_ctx, $ciphertext);
                
                // Update IV for next chunk (CBC chaining)
                if (strlen($ciphertext) >= 16) {
                    $iv = substr($ciphertext, -16);
                }
                
                $processed += strlen($plaintext);
                $chunk_num++;
                
                // Progress callback
                if ($progress_callback && $file_size > 0) {
                    $percent = min(95, (int)(($processed / $file_size) * 95));
                    call_user_func($progress_callback, $percent, 'Encrypting chunk ' . $chunk_num);
                }
            }
            
            // Finalize HMAC
            $hmac = hash_final($hmac_ctx, true);
            fwrite($fp_out, $hmac);
            
            fclose($fp_in);
            fclose($fp_out);
            
            $output_size = filesize($dest_path);
            
            if ($progress_callback) {
                call_user_func($progress_callback, 100, 'Encryption complete');
            }
            
            return [
                'success' => true,
                'message' => 'File encrypted successfully',
                'size' => $output_size,
                'version' => self::VERSION_V2
            ];
            
        } catch (Exception $e) {
            if (isset($fp_in) && is_resource($fp_in)) fclose($fp_in);
            if (isset($fp_out) && is_resource($fp_out)) fclose($fp_out);
            @unlink($dest_path);
            return ['success' => false, 'message' => 'Exception: ' . $e->getMessage()];
        }
    }
    
    /**
     * Decrypt a v2 container file using streaming
     * 
     * @param string $source_path Path to encrypted container
     * @param string $dest_path Path to output decrypted file
     * @param string $password Decryption password
     * @param callable|null $progress_callback Optional progress callback(percent, message)
     * @return array ['success' => bool, 'message' => string, 'size' => int]
     */
    public static function decrypt_file_streaming_v2($source_path, $dest_path, $password, $progress_callback = null) {
        if (!file_exists($source_path) || !is_readable($source_path)) {
            return ['success' => false, 'message' => 'Source file not readable'];
        }
        
        if (empty($password)) {
            return ['success' => false, 'message' => 'Password is required'];
        }
        
        try {
            $fp_in = fopen($source_path, 'rb');
            if (!$fp_in) {
                return ['success' => false, 'message' => 'Cannot open encrypted file'];
            }
            
            // Read and verify header
            $magic = fread($fp_in, 4);
            if ($magic !== self::MAGIC_V2) {
                fclose($fp_in);
                return ['success' => false, 'message' => 'Invalid container magic or version'];
            }
            
            $version = ord(fread($fp_in, 1));
            if ($version !== self::VERSION_V2) {
                fclose($fp_in);
                return ['success' => false, 'message' => 'Unsupported container version'];
            }
            
            $salt = fread($fp_in, self::SALT_LENGTH);
            $iterations_packed = fread($fp_in, 4);
            $iterations = unpack('N', $iterations_packed)[1];
            $iv = fread($fp_in, self::IV_LENGTH);
            
            // Derive keys
            $keys = self::derive_keys($password, $salt, $iterations);
            $enc_key = $keys['enc_key'];
            $hmac_key = $keys['hmac_key'];
            
            // Read HMAC from end of file
            $file_size = filesize($source_path);
            $ciphertext_size = $file_size - 4 - 1 - self::SALT_LENGTH - 4 - self::IV_LENGTH - self::HMAC_LENGTH;
            
            fseek($fp_in, -self::HMAC_LENGTH, SEEK_END);
            $stored_hmac = fread($fp_in, self::HMAC_LENGTH);
            
            // Verify HMAC
            fseek($fp_in, 0, SEEK_SET);
            $hmac_ctx = hash_init('sha256', HASH_HMAC, $hmac_key);
            
            // Hash header
            $header_data = fread($fp_in, 4 + 1 + self::SALT_LENGTH + 4 + self::IV_LENGTH);
            hash_update($hmac_ctx, $header_data);
            
            // Hash ciphertext
            $remaining = $ciphertext_size;
            while ($remaining > 0) {
                $to_read = min($remaining, self::CHUNK_SIZE);
                $data = fread($fp_in, $to_read);
                hash_update($hmac_ctx, $data);
                $remaining -= strlen($data);
            }
            
            $computed_hmac = hash_final($hmac_ctx, true);
            
            if (!hash_equals($computed_hmac, $stored_hmac)) {
                fclose($fp_in);
                return ['success' => false, 'message' => 'HMAC verification failed - file may be corrupted or tampered'];
            }
            
            if ($progress_callback) {
                call_user_func($progress_callback, 10, 'HMAC verified');
            }
            
            // Now decrypt
            fseek($fp_in, 4 + 1 + self::SALT_LENGTH + 4 + self::IV_LENGTH, SEEK_SET);
            
            $fp_out = fopen($dest_path, 'wb');
            if (!$fp_out) {
                fclose($fp_in);
                return ['success' => false, 'message' => 'Cannot create output file'];
            }
            
            $processed = 0;
            $chunk_num = 0;
            
            while ($processed < $ciphertext_size) {
                $to_read = min(self::CHUNK_SIZE + 16, $ciphertext_size - $processed); // +16 for CBC padding
                $ciphertext = fread($fp_in, $to_read);
                
                if ($ciphertext === false || $ciphertext === '') {
                    break;
                }
                
                $plaintext = openssl_decrypt(
                    $ciphertext,
                    'aes-256-cbc',
                    $enc_key,
                    OPENSSL_RAW_DATA,
                    $iv
                );
                
                if ($plaintext === false) {
                    fclose($fp_in);
                    fclose($fp_out);
                    @unlink($dest_path);
                    return ['success' => false, 'message' => 'Decryption failed'];
                }
                
                fwrite($fp_out, $plaintext);
                
                // Update IV for next chunk
                if (strlen($ciphertext) >= 16) {
                    $iv = substr($ciphertext, -16);
                }
                
                $processed += strlen($ciphertext);
                $chunk_num++;
                
                if ($progress_callback && $ciphertext_size > 0) {
                    $percent = 10 + min(85, (int)(($processed / $ciphertext_size) * 85));
                    call_user_func($progress_callback, $percent, 'Decrypting chunk ' . $chunk_num);
                }
            }
            
            fclose($fp_in);
            fclose($fp_out);
            
            $output_size = filesize($dest_path);
            
            if ($progress_callback) {
                call_user_func($progress_callback, 100, 'Decryption complete');
            }
            
            return [
                'success' => true,
                'message' => 'File decrypted successfully',
                'size' => $output_size
            ];
            
        } catch (Exception $e) {
            if (isset($fp_in) && is_resource($fp_in)) fclose($fp_in);
            if (isset($fp_out) && is_resource($fp_out)) fclose($fp_out);
            @unlink($dest_path);
            return ['success' => false, 'message' => 'Exception: ' . $e->getMessage()];
        }
    }
    
    /**
     * Decrypt v1 GCM container (legacy support)
     * 
     * @param string $source_path Path to encrypted container
     * @param string $dest_path Path to output decrypted file
     * @param string $password Decryption password
     * @return array ['success' => bool, 'message' => string]
     */
    public static function decrypt_file_v1($source_path, $dest_path, $password) {
        if (!file_exists($source_path)) {
            return ['success' => false, 'message' => 'Source file not found'];
        }
        
        $data = file_get_contents($source_path);
        if ($data === false) {
            return ['success' => false, 'message' => 'Cannot read source file'];
        }
        
        // V1 format: MAGIC(4) + VERSION(1) + SALT(16) + IV(12) + TAG(16) + CIPHERTEXT
        $header_size = 4 + 1 + 16 + 12 + 16;
        if (strlen($data) < $header_size) {
            return ['success' => false, 'message' => 'File too small to be valid v1 container'];
        }
        
        $pos = 0;
        $magic = substr($data, $pos, 4); $pos += 4;
        if ($magic !== self::MAGIC_V1) {
            return ['success' => false, 'message' => 'Invalid v1 magic'];
        }
        
        $version = ord(substr($data, $pos, 1)); $pos += 1;
        $salt = substr($data, $pos, 16); $pos += 16;
        $iv = substr($data, $pos, 12); $pos += 12;
        $tag = substr($data, $pos, 16); $pos += 16;
        $ciphertext = substr($data, $pos);
        
        // Derive key
        $key = openssl_pbkdf2($password, $salt, 32, 100000, 'sha256');
        
        // Decrypt
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($plaintext === false) {
            return ['success' => false, 'message' => 'Decryption failed - wrong password or corrupted file'];
        }
        
        if (file_put_contents($dest_path, $plaintext) === false) {
            return ['success' => false, 'message' => 'Cannot write decrypted file'];
        }
        
        return [
            'success' => true,
            'message' => 'File decrypted successfully (v1)',
            'size' => strlen($plaintext)
        ];
    }
}
