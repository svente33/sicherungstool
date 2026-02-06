<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Chunked Backup - Backup in kleinen Schritten über mehrere AJAX-Requests
 * Wie Duplicator - umgeht alle Timeout-Probleme
 */
class ITN_Chunked_Backup {
    const CHUNK_SIZE = 500; // Dateien pro Chunk
    const CHUNK_TIME_LIMIT = 15; // Sekunden pro Chunk
    
    protected $opts;
    protected $run_id;
    protected $backup_dir;
    protected $state_file;
    
    public function __construct($opts, $run_id) {
        $this->opts = $opts;
        $this->run_id = $run_id;
        $this->backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;
        $this->state_file = $this->backup_dir . '/.backup_state_' . $run_id . '.json';
    }
    
    /**
     * Initialisiert neues Backup
     */
    public function init() {
        error_log('ITN Chunked Backup: init() gestartet');
        
        try {
            @set_time_limit(30);
            
            $timestamp = current_time('timestamp');
            $siteHost = ITN_Helpers::esc_filename(parse_url(home_url(), PHP_URL_HOST));
            $name = 'backup_' . date('Ymd_His', $timestamp) . '_' . $siteHost;
            
            error_log('ITN Chunked Backup: Name = ' . $name);
            
            $work_dir = $this->backup_dir . '/' . $name;
            ITN_Helpers::ensure_dir($work_dir);
            
            // Erstelle DB-Dump
            ITN_Helpers::progress_set($this->run_id, 5, 'Erstelle Datenbank-Dump...');
            error_log('ITN Chunked Backup: Starte DB-Dump');
            
            $sql_path = $work_dir . '/' . $name . '.sql';
            $db_result = $this->dump_database($sql_path);
            
            if (!$db_result['success']) {
                error_log('ITN Chunked Backup: DB-Dump fehlgeschlagen - ' . ($db_result['message'] ?? 'Unbekannter Fehler'));
                return ['success' => false, 'message' => 'DB-Dump fehlgeschlagen: ' . ($db_result['message'] ?? '')];
            }
            
            error_log('ITN Chunked Backup: DB-Dump erfolgreich');
            
            // Erstelle Meta-Datei
            $meta = $this->create_meta($timestamp);
            $meta_path = $work_dir . '/backup_meta.json';
            file_put_contents($meta_path, wp_json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            
            // Sammle alle Dateien
            ITN_Helpers::progress_set($this->run_id, 15, 'Sammle Dateien...');
            error_log('ITN Chunked Backup: Sammle Dateien...');
            
            $excludes = ITN_Helpers::build_excludes($this->opts);
            $excludes = array_unique(array_merge($excludes, ['itn-sicherung-backups']));
            
            $files = $this->collect_files(ABSPATH, '', $excludes);
            
            error_log('ITN Chunked Backup: ' . count($files) . ' Dateien gefunden');
            
            // Speichere Status
            $state = [
                'step' => 'collect',
                'name' => $name,
                'work_dir' => $work_dir,
                'sql_path' => $sql_path,
                'meta_path' => $meta_path,
                'zip_path' => $this->backup_dir . '/' . $name . '.zip',
                'files' => $files,
                'total_files' => count($files),
                'processed_files' => 0,
                'current_chunk' => 0,
                'timestamp' => $timestamp,
            ];
            
            $this->save_state($state);
            
            ITN_Helpers::progress_set($this->run_id, 20, 'Gefunden: ' . count($files) . ' Dateien');
            
            error_log('ITN Chunked Backup: init() erfolgreich abgeschlossen');
            
            return ['success' => true, 'total_files' => count($files), 'state' => $state];
            
        } catch (Exception $e) {
            error_log('ITN Chunked Backup EXCEPTION in init(): ' . $e->getMessage());
            return ['success' => false, 'message' => 'Exception: ' . $e->getMessage()];
        }
    }
    
    /**
     * Verarbeitet einen Chunk von Dateien
     */
    public function process_chunk() {
        @set_time_limit(self::CHUNK_TIME_LIMIT + 5);
        $start_time = microtime(true);
        
        $state = $this->load_state();
        if (!$state) {
            return ['success' => false, 'message' => 'Kein Status gefunden'];
        }
        
        // Verschlüsselung
        $zip_encrypt_enabled = !empty($this->opts['zip_encrypt_enabled']);
        $zip_password = isset($this->opts['zip_encrypt_password']) ? (string)$this->opts['zip_encrypt_password'] : '';
        
        // Öffne ZIP
        $z = new ZipArchive();
        $result = $z->open($state['zip_path'], ZipArchive::CREATE);
        
        if ($result !== true) {
            return ['success' => false, 'message' => 'ZIP konnte nicht geöffnet werden (Code: ' . $result . ')'];
        }
        
        // Verarbeite Dateien
        $chunk_start = $state['processed_files'];
        $chunk_end = min($chunk_start + self::CHUNK_SIZE, $state['total_files']);
        $files_processed = 0;
        
        for ($i = $chunk_start; $i < $chunk_end; $i++) {
            // Prüfe Zeitlimit
            if ((microtime(true) - $start_time) > self::CHUNK_TIME_LIMIT) {
                break;
            }
            
            $file_info = $state['files'][$i];
            
            if ($file_info['type'] === 'dir') {
                @$z->addEmptyDir($file_info['rel']);
            } else {
                // Füge Datei hinzu
                if (@$z->addFile($file_info['full'], $file_info['rel'])) {
                    // Verschlüssele SOFORT nach dem Hinzufügen
                    if ($zip_encrypt_enabled && $zip_password !== '') {
                        $this->encrypt_zip_entry($z, $file_info['rel'], $zip_password);
                    }
                }
            }
            
            $files_processed++;
            $state['processed_files']++;
        }
        
        // Schließe ZIP
        $z->close();
        
        // Update Progress
        $percent = 25 + (int)floor(($state['processed_files'] / $state['total_files']) * 65);
        ITN_Helpers::progress_set(
            $this->run_id, 
            $percent, 
            'Dateien gepackt: ' . $state['processed_files'] . ' / ' . $state['total_files']
        );
        
        // Speichere Status
        $state['current_chunk']++;
        $this->save_state($state);
        
        $is_complete = ($state['processed_files'] >= $state['total_files']);
        
        return [
            'success' => true,
            'processed' => $files_processed,
            'total_processed' => $state['processed_files'],
            'total_files' => $state['total_files'],
            'is_complete' => $is_complete,
            'percent' => $percent,
        ];
    }
    
    /**
     * Verschlüsselt einen einzelnen ZIP-Eintrag
     */
    protected function encrypt_zip_entry($zip, $filename, $password) {
        if (!method_exists($zip, 'setPassword') || !method_exists($zip, 'setEncryptionName')) {
            return false;
        }
        
        // Setze Passwort für das gesamte ZIP
        $zip->setPassword($password);
        
        // Verschlüssele diese spezifische Datei
        $encryption_method = ZipArchive::EM_AES_256;
        if (!defined('ZipArchive::EM_AES_256')) {
            $encryption_method = 257; // Fallback für ältere PHP-Versionen
        }
        
        return @$zip->setEncryptionName($filename, $encryption_method);
    }
    
    /**
     * Finalisiert das Backup
     */
    public function finalize() {
        @set_time_limit(60);
        
        $state = $this->load_state();
        if (!$state) {
            return ['success' => false, 'message' => 'Kein Status gefunden'];
        }
        
        ITN_Helpers::progress_set($this->run_id, 92, 'Füge Meta-Dateien hinzu...');
        
        $zip_encrypt_enabled = !empty($this->opts['zip_encrypt_enabled']);
        $zip_password = isset($this->opts['zip_encrypt_password']) ? (string)$this->opts['zip_encrypt_password'] : '';
        
        // Öffne ZIP ein letztes Mal
        $z = new ZipArchive();
        if ($z->open($state['zip_path']) !== true) {
            return ['success' => false, 'message' => 'ZIP konnte nicht geöffnet werden'];
        }
        
        // Füge DB und Meta hinzu
        $z->addFile($state['sql_path'], 'database.sql');
        if ($zip_encrypt_enabled && $zip_password !== '') {
            $this->encrypt_zip_entry($z, 'database.sql', $zip_password);
        }
        
        $z->addFile($state['meta_path'], 'backup_meta.json');
        if ($zip_encrypt_enabled && $zip_password !== '') {
            $this->encrypt_zip_entry($z, 'backup_meta.json', $zip_password);
        }
        
        $z->close();
        
        ITN_Helpers::progress_set($this->run_id, 94, 'Prüfe ZIP...');
        
        // Prüfe ZIP
        clearstatcache(true, $state['zip_path']);
        if (!file_exists($state['zip_path'])) {
            return ['success' => false, 'message' => 'ZIP wurde nicht erstellt'];
        }
        
        $zip_size = @filesize($state['zip_path']);
        if ($zip_size < 100) {
            return ['success' => false, 'message' => 'ZIP ist zu klein'];
        }
        
        // Teste Verschlüsselung
        if ($zip_encrypt_enabled && $zip_password !== '') {
            $test_zip = new ZipArchive();
            if ($test_zip->open($state['zip_path']) === true) {
                // Prüfe ersten Eintrag
                if ($test_zip->numFiles > 0) {
                    $stat = $test_zip->statIndex(0);
                    $is_encrypted = isset($stat['encryption_method']) && $stat['encryption_method'] > 0;
                    
                    if ($is_encrypted) {
                        error_log('ITN SUCCESS: ZIP ist verschlüsselt (Methode: ' . $stat['encryption_method'] . ')');
                    } else {
                        error_log('ITN WARNING: ZIP-Verschlüsselung fehlgeschlagen - PHP ' . PHP_VERSION . ' unterstützt möglicherweise keine AES-256');
                        error_log('ITN WARNING: Bitte PHP 7.2+ mit libzip 1.2.0+ verwenden für ZIP-Verschlüsselung');
                    }
                }
                $test_zip->close();
            }
        }
        
        ITN_Helpers::progress_set($this->run_id, 95, 'Erstelle Installer...');
        
        // Erstelle Installer
        $installer_target = $this->backup_dir . '/installer-' . $state['name'] . '.php';
        ITN_Installer_Generator::write_installer_for_backup($state['zip_path'], $installer_target);
        
        ITN_Helpers::progress_set($this->run_id, 97, 'Cloud-Upload...');
        
        // Cloud-Upload
        $cloud_status = $this->handle_cloud_uploads($state['zip_path'], $installer_target);
        
        // Retention
        $this->enforce_retention();
        
        // E-Mail senden
        $msg_suffix = $zip_encrypt_enabled ? ' (verschlüsselt)' : '';
        $this->send_notification(true, 'Backup erfolgreich erstellt' . $msg_suffix, $zip_size, $cloud_status);
        
        // Aufräumen
        $this->cleanup($state);
        
        $msg = 'Backup erstellt (' . ITN_Helpers::format_bytes($zip_size) . ')' . $msg_suffix;
        update_option('itn_last_backup_result', [
            'success' => true,
            'message' => $msg,
            'zip' => $state['zip_path'],
            'time' => time(),
        ], false);
        
        $report = [
            'success'    => true,
            'message'    => $msg,
            'zip'        => $state['zip_path'],
            'zip_size'   => $zip_size,
            'encrypted'  => $zip_encrypt_enabled,
            'cloud'      => $cloud_status,
            'created_at' => time(),
        ];
        update_option('itn_last_backup_report', $report, false);
        
        ITN_Helpers::progress_set($this->run_id, 100, $msg, ['done' => true, 'zip' => $state['zip_path']]);
        
        return ['success' => true, 'message' => $msg, 'zip' => $state['zip_path'], 'size' => $zip_size];
    }
    
    protected function collect_files($base_path, $relative, $excludes) {
        $files = [];
        $dir = rtrim($base_path . $relative, '/');
        $items = @scandir($dir);
        
        if (!$items) return $files;
        
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            
            $full = $dir . '/' . $item;
            $rel = ltrim($relative . '/' . $item, '/');
            
            if (ITN_Helpers::path_is_excluded($rel, $excludes)) continue;
            if (strpos($full, ITN_BACKUP_DIR) === 0) continue;
            if (strpos($full, ITN_PLUGIN_DIR) === 0) continue;
            
            if (is_dir($full)) {
                $files[] = ['type' => 'dir', 'full' => $full, 'rel' => $rel];
                $files = array_merge($files, $this->collect_files($base_path, $relative . '/' . $item, $excludes));
            } elseif (is_file($full)) {
                $files[] = ['type' => 'file', 'full' => $full, 'rel' => $rel];
            }
        }
        
        return $files;
    }
    
    protected function dump_database($sql_path) {
        global $wpdb;
        
        try {
            $tables = $wpdb->get_col('SHOW TABLES');
            $sql = "-- ITN Sicherung SQL Dump\n-- Date: " . date('c') . "\n\nSET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n";
            
            foreach ($tables as $table) {
                $create = $wpdb->get_row("SHOW CREATE TABLE `$table`", ARRAY_N);
                $sql .= "DROP TABLE IF EXISTS `$table`;\n" . $create[1] . ";\n\n";
                
                $rows = $wpdb->get_results("SELECT * FROM `$table`", ARRAY_A);
                if ($rows) {
                    $columns = array_keys($rows[0]);
                    $sql .= "INSERT INTO `$table` (`" . implode('`,`', $columns) . "`) VALUES\n";
                    $vals = [];
                    foreach ($rows as $row) {
                        $v = [];
                        foreach ($columns as $col) {
                            $val = $row[$col] ?? null;
                            $v[] = ($val === null) ? 'NULL' : "'" . esc_sql(addslashes($val)) . "'";
                        }
                        $vals[] = '(' . implode(',', $v) . ')';
                    }
                    $sql .= implode(",\n", $vals) . ";\n\n";
                }
            }
            
            $sql .= "SET FOREIGN_KEY_CHECKS=1;\n";
            file_put_contents($sql_path, $sql);
            
            return ['success' => true];
        } catch (Exception $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
    
    protected function create_meta($timestamp) {
        $uploads = wp_get_upload_dir();
        global $wpdb;
        
        return [
            'created_at' => date('c', $timestamp),
            'site_url' => home_url(),
            'home' => get_option('home'),
            'table_prefix' => $GLOBALS['table_prefix'],
            'base_prefix' => isset($wpdb) ? $wpdb->base_prefix : $GLOBALS['table_prefix'],
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'run_id' => $this->run_id,
            'abs_path' => rtrim(ABSPATH, "/\\"),
            'uploads' => [
                'basedir' => $uploads['basedir'] ?? '',
                'baseurl' => $uploads['baseurl'] ?? '',
            ],
            'is_multisite' => function_exists('is_multisite') ? (bool) is_multisite() : false,
        ];
    }
    
    protected function handle_cloud_uploads($zip_path, $installer_path) {
        // Cloud-Uploads über bestehende ITN_Backup Instanz
        if (!class_exists('ITN_Backup')) {
            return ['s3' => null, 'azure' => null, 'onedrive' => null];
        }
        
        $backup = new ITN_Backup($this->opts);
        $cloud_status = ['s3' => null, 'azure' => null, 'onedrive' => null];
        
        // S3 Upload
        if (!empty($this->opts['s3_enabled'])) {
            $s3_zip = $backup->upload_to_s3($zip_path);
            $s3_inst = file_exists($installer_path) ? $backup->upload_to_s3($installer_path) : ['success' => false];
            $cloud_status['s3'] = ['zip' => $s3_zip, 'installer' => $s3_inst];
        }
        
        // Azure Upload
        if (!empty($this->opts['azure_enabled'])) {
            $az_zip = $backup->upload_to_azure($zip_path);
            $az_inst = file_exists($installer_path) ? $backup->upload_to_azure($installer_path) : ['success' => false];
            $cloud_status['azure'] = ['zip' => $az_zip, 'installer' => $az_inst];
        }
        
        // OneDrive Upload
        if (!empty($this->opts['onedrive_enabled'])) {
            $od_zip = $backup->upload_to_onedrive($zip_path);
            $od_inst = file_exists($installer_path) ? $backup->upload_to_onedrive($installer_path) : ['success' => false];
            $cloud_status['onedrive'] = ['zip' => $od_zip, 'installer' => $od_inst];
        }
        
        return $cloud_status;
    }
    
    protected function enforce_retention() {
        $keep = max(1, intval($this->opts['retention'] ?? 5));
        $files = glob($this->backup_dir . '/*.zip') ?: [];
        rsort($files);
        
        if (count($files) > $keep) {
            $remove = array_slice($files, $keep);
            foreach ($remove as $f) {
                $baseNoExt = basename($f, '.zip');
                $installer = $this->backup_dir . '/installer-' . $baseNoExt . '.php';
                @unlink($f);
                if (file_exists($installer)) @unlink($installer);
            }
        }
    }
    
    protected function send_notification($success, $message, $size = 0, $cloud_status = []) {
        if (empty($this->opts['notify_enabled'])) return;
        
        $to = $this->opts['notify_email'] ?? get_option('admin_email');
        if (!$to || !is_email($to)) return;
        
        $site_name = get_bloginfo('name');
        $subject = $success 
            ? '[ITN Sicherung] ✅ Backup erfolgreich - ' . $site_name
            : '[ITN Sicherung] ❌ Backup fehlgeschlagen - ' . $site_name;
        
        $body = $success
            ? "Backup erfolgreich erstellt!\n\nGröße: " . ITN_Helpers::format_bytes($size) . "\nZeit: " . date('d.m.Y H:i:s')
            : "Backup fehlgeschlagen!\n\nFehler: " . $message;
        
        ITN_Helpers::send_domain_mail($to, $subject, $body, 'itn-sicherung', 'ITN - Sicherung');
    }
    
    protected function cleanup($state) {
        // Lösche Arbeitsverzeichnis
        if (isset($state['work_dir']) && is_dir($state['work_dir'])) {
            ITN_Helpers::rrmdir($state['work_dir']);
        }
        
        // Lösche Status-Datei
        if (file_exists($this->state_file)) {
            @unlink($this->state_file);
        }
        
        delete_option('itn_backup_running');
    }
    
    protected function save_state($state) {
        file_put_contents($this->state_file, wp_json_encode($state));
    }
    
    protected function load_state() {
        if (!file_exists($this->state_file)) return null;
        $json = file_get_contents($this->state_file);
        return json_decode($json, true);
    }
}