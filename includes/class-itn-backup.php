<?php
if (!defined('ABSPATH')) { exit; }

class ITN_Backup {
    protected $opts;
    protected $zip;
    protected $backup_dir;
    protected $timestamp;
    protected $work_dir;
    protected $zip_path;
    protected $sql_path;
    protected $meta_path;
    protected $run_id;
    protected $total_files = 0;
    protected $processed_files = 0;

    protected $zip_encrypt_enabled = false;
    protected $zip_password = '';

    public function __construct($opts = []) {
        $this->opts = $opts;
        $this->backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;
        ITN_Helpers::ensure_dir($this->backup_dir);
        if (function_exists('itn_protect_backup_dir')) itn_protect_backup_dir($this->backup_dir);

        $this->zip_encrypt_enabled = !empty($opts['zip_encrypt_enabled']);
        $this->zip_password = isset($opts['zip_encrypt_password']) ? (string)$opts['zip_encrypt_password'] : '';
        if ($this->zip_encrypt_enabled && $this->zip_password === '') {
            $this->zip_encrypt_enabled = false;
        }
    }

    protected function progress($percent, $message, $extra = []) {
        if (!$this->run_id) return;
        ITN_Helpers::progress_set($this->run_id, $percent, $message, $extra);
    }

    protected static function can_exec() {
        $disabled = ini_get('disable_functions');
        if ($disabled) {
            $list = array_map('trim', explode(',', $disabled));
            if (in_array('exec', $list, true)) return false;
            if (in_array('shell_exec', $list, true)) return false;
        }
        return function_exists('exec') || function_exists('shell_exec');
    }
    
    protected static function find_bin($candidates) {
        if (!self::can_exec()) return null;
        foreach ($candidates as $bin) {
            $cmd = 'command -v ' . escapeshellcmd($bin) . ' 2>/dev/null';
            $out = @shell_exec($cmd);
            if ($out) {
                $path = trim($out);
                if ($path && @is_executable($path)) return $path;
            }
        }
        return null;
    }

    protected function repack_zip_with_encryption($zip_path, $password) {
        if (!self::can_exec()) {
            $this->progress(95, 'Verschlüsselung nicht möglich: exec deaktiviert');
            return ['success' => false, 'message' => 'exec disabled'];
        }
        $bin7z  = self::find_bin(['7z','7za','7zz']);
        $binzip = self::find_bin(['zip']);

        $tmp = $this->backup_dir . '/repack_' . basename($zip_path, '.zip') . '_' . time();
        @mkdir($tmp, 0755, true);

        $z = new ZipArchive();
        if ($z->open($zip_path) !== true) { return ['success'=>false,'message'=>'ZIP konnte zum Repack nicht geöffnet werden']; }
        if (!$z->extractTo($tmp)) { $z->close(); return ['success'=>false,'message'=>'ZIP konnte zum Repack nicht entpackt werden']; }
        $z->close();

        $enc_path = $zip_path . '.enc';
        $ok = false; $method = '';

        if ($bin7z) {
            $cmd = 'cd ' . escapeshellarg($tmp) . ' && ' .
                   escapeshellcmd($bin7z) . ' a -tzip -mem=AES256 -p' . escapeshellarg($password) . ' ' .
                   escapeshellarg($enc_path) . ' ' . escapeshellarg('*');
            @exec($cmd, $out, $ret);
            $ok = ($ret === 0 && file_exists($enc_path) && filesize($enc_path) > 0);
            $method = 'AES-256 (7z)';
        } elseif ($binzip) {
            $cmd = 'cd ' . escapeshellarg($tmp) . ' && ' .
                   escapeshellcmd($binzip) . ' -rq -P ' . escapeshellarg($password) . ' ' .
                   escapeshellarg($enc_path) . ' ' . escapeshellarg('.');
            @exec($cmd, $out, $ret);
            $ok = ($ret === 0 && file_exists($enc_path) && filesize($enc_path) > 0);
            $method = 'PKWARE/ZipCrypto (zip)';
        } else {
            $this->progress(95, 'Keine CLI für Verschlüsselung gefunden (7z/zip)');
        }

        ITN_Helpers::rrmdir($tmp);

        if ($ok) {
            @unlink($zip_path);
            @rename($enc_path, $zip_path);
            $this->progress(96, 'ZIP neu verpackt mit Passwort — ' . $method);
            return ['success'=>true,'method'=>$method];
        } else {
            @unlink($enc_path);
            return ['success'=>false,'message'=>'CLI-Repack fehlgeschlagen'];
        }
    }

    public function run($run_id = null) {
        try {
            @ignore_user_abort(true);
            @set_time_limit(0);
            @ini_set('max_execution_time', '0');
            $mem = ini_get('memory_limit');
            if (!$mem || (int)$mem < 512) @ini_set('memory_limit', '512M');

            $this->timestamp = current_time('timestamp');
            $siteHost = ITN_Helpers::esc_filename(parse_url(home_url(), PHP_URL_HOST));
            $name = 'backup_' . date('Ymd_His', $this->timestamp) . '_' . $siteHost;
            $this->run_id = $run_id ?: $name;

            $this->work_dir = $this->backup_dir . '/' . $name;
            ITN_Helpers::ensure_dir($this->work_dir);
            $this->progress(1, 'Initialisierung');
            
            error_log('ITN Backup Start - Run ID: ' . $this->run_id);

            $this->sql_path = $this->work_dir . '/' . $name . '.sql';
            $this->progress(5, 'Datenbank-Dump');
            $db = $this->dump_database($this->sql_path);
            if (!$db['success']) {
                error_log('ITN DB-Dump fehlgeschlagen: ' . ($db['message'] ?? 'unbekannt'));
                $res = ['success' => false, 'message' => $db['message'] ?? 'DB-Dump fehlgeschlagen'];
                update_option('itn_last_backup_result', $res + ['time' => time()], false);
                $this->progress(100, 'Fehlgeschlagen', ['done' => true]);
                return $res;
            }
            error_log('ITN DB-Dump OK: ' . filesize($this->sql_path) . ' bytes');
            $this->progress(20, 'Datenbank-Dump abgeschlossen');

            $uploads = wp_get_upload_dir();
            global $wpdb;
            $meta = [
                'created_at'   => date('c', $this->timestamp),
                'site_url'     => home_url(),
                'home'         => get_option('home'),
                'table_prefix' => $GLOBALS['table_prefix'],
                'base_prefix'  => isset($wpdb) ? $wpdb->base_prefix : $GLOBALS['table_prefix'],
                'wp_version'   => get_bloginfo('version'),
                'php_version'  => PHP_VERSION,
                'run_id'       => $this->run_id,
                'abs_path'     => rtrim(ABSPATH, "/\\"),
                'uploads'      => [
                    'basedir' => $uploads['basedir'] ?? '',
                    'baseurl' => $uploads['baseurl'] ?? '',
                ],
                'upload_path_option'     => get_option('upload_path', ''),
                'upload_url_path_option' => get_option('upload_url_path', ''),
                'is_multisite' => function_exists('is_multisite') ? (bool) is_multisite() : false,
                'network' => [],
                'zip_encrypted' => (bool)$this->zip_encrypt_enabled,
            ];
            if (!empty($meta['is_multisite']) && isset($wpdb)) {
                $site_table = $wpdb->base_prefix . 'site';
                $blogs_table = $wpdb->base_prefix . 'blogs';
                $net = $wpdb->get_row("SELECT domain, path FROM `{$site_table}` LIMIT 1", ARRAY_A);
                if ($net) $meta['network']['domain'] = $net['domain'] ?? '';
                if ($net) $meta['network']['path']   = $net['path'] ?? '';
                $first_blog = $wpdb->get_row("SELECT domain, path FROM `{$blogs_table}` ORDER BY blog_id ASC LIMIT 1", ARRAY_A);
                if ($first_blog) {
                    $meta['network']['type'] = (strpos($first_blog['domain'], '.') !== false && $first_blog['path'] === '/') ? 'subdomain' : 'subdirectory';
                }
            }
            $this->meta_path = $this->work_dir . '/backup_meta.json';
            file_put_contents($this->meta_path, wp_json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            $this->zip_path = $this->backup_dir . '/' . $name . '.zip';
            
            error_log('ITN ZIP wird erstellt: ' . $this->zip_path);
            
            if (!is_writable($this->backup_dir)) {
                error_log('ITN ERROR: Backup-Dir nicht beschreibbar');
                throw new Exception('Backup-Verzeichnis ist nicht beschreibbar: ' . $this->backup_dir);
            }
            
            if (file_exists($this->zip_path)) {
                @unlink($this->zip_path);
            }
            
            if (!class_exists('ZipArchive')) {
                error_log('ITN ERROR: ZipArchive nicht verfügbar');
                throw new Exception('ZipArchive PHP-Erweiterung fehlt');
            }
            
            $z = new ZipArchive();
            $open_result = $z->open($this->zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE);
            
            if ($open_result !== true) {
                error_log('ITN ERROR: ZIP->open() failed with code ' . $open_result);
                throw new Exception('ZipArchive konnte nicht geöffnet werden (Code: ' . $open_result . ')');
            }
            
            error_log('ITN ZIP erfolgreich geöffnet');
            $this->zip = $z;

            if ($this->zip_encrypt_enabled && $this->zip_password !== '' && method_exists($this->zip, 'setPassword')) {
                @$this->zip->setPassword($this->zip_password);
            }

            $excludes = ITN_Helpers::build_excludes($this->opts);
            $excludes = array_unique(array_merge($excludes, ['itn-sicherung-backups']));

            $root = ABSPATH;
            error_log('ITN Zähle Dateien...');
            $this->total_files = $this->count_files($root, '', $excludes);
            if ($this->total_files <= 0) $this->total_files = 1;
            error_log('ITN Dateien gezählt: ' . $this->total_files);

            $this->progress(25, 'Dateien werden gezählt: ' . $this->total_files . ' Dateien gefunden');
            $this->progress(26, 'Dateien werden gepackt: 0 / ' . $this->total_files);
            
            try {
                error_log('ITN Beginne Dateien zu packen...');
                $this->add_dir_to_zip($root, '', $excludes);
                error_log('ITN Dateien gepackt: ' . $this->processed_files);
            } catch (Exception $e) {
                error_log('ITN ERROR beim Packen: ' . $e->getMessage());
                throw new Exception('Fehler beim Hinzufügen der Dateien: ' . $e->getMessage());
            }

            $this->progress(90, 'Alle Dateien gepackt: ' . $this->processed_files . ' / ' . $this->total_files);

            $this->progress(91, 'Füge Metadaten hinzu...');
            
            if (!$z->addFile($this->sql_path, 'database.sql')) {
                error_log('ITN ERROR: Konnte database.sql nicht hinzufügen');
                throw new Exception('Konnte database.sql nicht zum ZIP hinzufügen');
            }
            $this->encryptEntryIfNeeded('database.sql');
            
            if (!$z->addFile($this->meta_path, 'backup_meta.json')) {
                error_log('ITN ERROR: Konnte backup_meta.json nicht hinzufügen');
                throw new Exception('Konnte backup_meta.json nicht zum ZIP hinzufügen');
            }
            $this->encryptEntryIfNeeded('backup_meta.json');

            // KRITISCH: ZIP schließen mit FLUSH-Strategie
            $this->progress(93, 'Schließe ZIP-Archiv (kann einige Minuten dauern)...');
            error_log('ITN Schließe ZIP... (dies kann bei vielen Dateien lange dauern)');
            
            // Speicher leeren vor close()
            if (function_exists('gc_collect_cycles')) {
                gc_collect_cycles();
            }
            
            // Setze noch längeres Timeout speziell für close()
            @set_time_limit(600); // 10 Minuten nur für close()
            
            $close_start = microtime(true);
            $close_result = $z->close();
            $close_duration = microtime(true) - $close_start;
            
            error_log('ITN ZIP->close() dauerte ' . round($close_duration, 2) . ' Sekunden, Result: ' . ($close_result ? 'TRUE' : 'FALSE'));
            
            $this->zip = null;
            
            if (!$close_result) {
                error_log('ITN ERROR: ZIP->close() returned FALSE');
                throw new Exception('ZIP konnte nicht geschlossen werden');
            }

            // Warte und prüfe
            sleep(1);
            clearstatcache(true, $this->zip_path);

            error_log('ITN Prüfe ob ZIP existiert...');
            
            if (!file_exists($this->zip_path)) {
                error_log('ITN ERROR: ZIP existiert nicht nach close()!');
                throw new Exception('ZIP-Datei wurde nicht erstellt trotz erfolgreichem close()');
            }
            
            $zip_size = @filesize($this->zip_path);
            error_log('ITN SUCCESS! ZIP erstellt: ' . $zip_size . ' bytes');
            
            if ($zip_size === false || $zip_size < 100) {
                throw new Exception('ZIP-Datei ist zu klein oder beschädigt');
            }

            $this->progress(94, 'ZIP erfolgreich erstellt (' . ITN_Helpers::format_bytes($zip_size) . ')');

            // Rest bleibt gleich...
            if ($this->zip_encrypt_enabled) {
                $supports = method_exists($z, 'setEncryptionName') || method_exists($z, 'setEncryptionIndex');
                if (!$supports) {
                    $this->progress(94, 'Verschlüsselung via ZipArchive nicht verfügbar – versuche CLI');
                    $re = $this->repack_zip_with_encryption($this->zip_path, $this->zip_password);
                    if (!$re['success']) {
                        $this->progress(95, 'Hinweis: ZIP unverschlüsselt (' . ($re['message'] ?? 'CLI nicht verfügbar') . ')');
                    } else {
                        $this->progress(96, 'ZIP verschlüsselt (CLI) — ' . ($re['method'] ?? ''));
                    }
                } else {
                    $this->progress(95, 'ZIP mit Passwort erstellt (ZipArchive)');
                }
            }

            $this->progress(95, 'Erstelle Installer-Datei');
            $installer_target = $this->backup_dir . '/installer-' . basename($this->zip_path, '.zip') . '.php';
            $gen = ITN_Installer_Generator::write_installer_for_backup($this->zip_path, $installer_target);
            $installer_exists = !empty($gen['success']) && file_exists($installer_target);
            if (!$gen['success']) {
                $this->progress(96, 'Installer konnte nicht erzeugt werden: ' . ($gen['message'] ?? 'Unbekannt'));
            }

            $this->progress(97, 'Aufräumen (Retention)');
            $this->enforce_retention();

            $cloud_msgs = [];
            $cloud_status = ['s3'=>null,'azure'=>null,'onedrive'=>null];

            if (!empty($this->opts['s3_enabled'])) {
                $this->progress(98, 'Upload: AWS S3 (ZIP)');
                $s3_zip = $this->upload_to_s3($this->zip_path);
                $msg = $s3_zip['success'] ? 'S3 ZIP OK' : ('S3 ZIP Fehler');
                if ($installer_exists) {
                    $s3_inst = $this->upload_to_s3($installer_target);
                    $msg .= $s3_inst['success'] ? ', Installer OK' : ', Installer Fehler';
                    $cloud_status['s3'] = ['zip'=>$s3_zip, 'installer'=>$s3_inst];
                } else {
                    $cloud_status['s3'] = $s3_zip;
                }
                $cloud_msgs[] = $msg;
            }
            if (!empty($this->opts['azure_enabled'])) {
                $this->progress(98, 'Upload: Azure Blob (ZIP)');
                $az_zip = $this->upload_to_azure($this->zip_path);
                $msg = $az_zip['success'] ? 'Azure ZIP OK' : 'Azure ZIP Fehler';
                if ($installer_exists) {
                    $az_inst = $this->upload_to_azure($installer_target);
                    $msg .= $az_inst['success'] ? ', Installer OK' : ', Installer Fehler';
                    $cloud_status['azure'] = ['zip'=>$az_zip, 'installer'=>$az_inst];
                } else {
                    $cloud_status['azure'] = $az_zip;
                }
                $cloud_msgs[] = $msg;
            }
            if (!empty($this->opts['onedrive_enabled'])) {
                $this->progress(98, 'Upload: OneDrive (ZIP)');
                $od_zip = $this->upload_to_onedrive($this->zip_path);
                $msg = $od_zip['success'] ? 'OneDrive ZIP OK' : 'OneDrive ZIP Fehler';
                if ($installer_exists) {
                    $od_inst = $this->upload_to_onedrive($installer_target);
                    $msg .= $od_inst['success'] ? ', Installer OK' : ', Installer Fehler';
                    $cloud_status['onedrive'] = ['zip'=>$od_zip, 'installer'=>$od_inst];
                } else {
                    $cloud_status['onedrive'] = $od_zip;
                }
                $cloud_msgs[] = $msg;
            }

            $msg = 'Backup erstellt' . ($this->zip_encrypt_enabled ? ' (ZIP verschlüsselt)' : '');
            if (!empty($cloud_msgs)) $msg .= ' — ' . implode(' | ', $cloud_msgs);

            $res = ['success' => true, 'message' => $msg, 'zip' => $this->zip_path];
            update_option('itn_last_backup_result', $res + ['time' => time()], false);

            $report = [
                'success'    => true,
                'message'    => $msg,
                'zip'        => $this->zip_path,
                'zip_size'   => $zip_size,
                'encrypted'  => (bool)$this->zip_encrypt_enabled,
                'cloud'      => $cloud_status,
                'created_at' => time(),
            ];
            update_option('itn_last_backup_report', $report, false);

            // E-MAIL BENACHRICHTIGUNG bei Erfolg
            $this->send_notification_email(true, $msg, $report);

            $this->progress(100, 'Abgeschlossen', ['done' => true, 'zip' => $this->zip_path]);
            error_log('ITN Backup komplett fertig!');
            
            // Markiere als fertig
            delete_option('itn_backup_running');
            
            return $res;
        } catch (Exception $e) {
            if ($this->zip) {
                @$this->zip->close();
                $this->zip = null;
            }
            
            error_log('ITN BACKUP FEHLER: ' . $e->getMessage());
            
            $res = ['success' => false, 'message' => $e->getMessage()];
            update_option('itn_last_backup_result', $res + ['time' => time()], false);

            $report = [
                'success'    => false,
                'message'    => $e->getMessage(),
                'zip'        => $this->zip_path ?? '',
                'zip_size'   => ($this->zip_path && file_exists($this->zip_path)) ? @filesize($this->zip_path) : 0,
                'encrypted'  => (bool)$this->zip_encrypt_enabled,
                'cloud'      => ['s3'=>null,'azure'=>null,'onedrive'=>null],
                'created_at' => time(),
            ];
            update_option('itn_last_backup_report', $report, false);

            // E-MAIL BENACHRICHTIGUNG bei Fehler
            $this->send_notification_email(false, $e->getMessage(), $report);

            $this->progress(100, 'Fehlgeschlagen: ' . $e->getMessage(), ['done' => true]);
            
            // Markiere als fertig
            delete_option('itn_backup_running');
            
            return $res;
        }
    }
    
    // NEUE Methode für E-Mail-Benachrichtigungen
    protected function send_notification_email($success, $message, $report = []) {
        // Prüfe ob Benachrichtigungen aktiviert sind
        if (empty($this->opts['notify_enabled'])) {
            return;
        }
        
        $to = $this->opts['notify_email'] ?? get_option('admin_email');
        if (!$to || !is_email($to)) {
            return;
        }
        
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        
        if ($success) {
            $subject = '[ITN Sicherung] ✅ Backup erfolgreich - ' . $site_name;
            
            $body = "Gute Nachrichten!\n\n";
            $body .= "Das Backup wurde erfolgreich erstellt.\n\n";
            $body .= "═══════════════════════════════════════\n";
            $body .= "BACKUP-DETAILS\n";
            $body .= "═══════════════════════════════════════\n\n";
            $body .= "Website: {$site_name}\n";
            $body .= "URL: {$site_url}\n";
            $body .= "Zeitpunkt: " . date('d.m.Y H:i:s', time()) . "\n\n";
            
            if (!empty($report['zip'])) {
                $body .= "ZIP-Datei: " . basename($report['zip']) . "\n";
                $body .= "Größe: " . ITN_Helpers::format_bytes($report['zip_size'] ?? 0) . "\n";
            }
            
            if (!empty($report['encrypted'])) {
                $body .= "Verschlüsselung: ✅ AES-256\n";
            }
            
            $body .= "\n";
            
            // Cloud-Status
            if (!empty($report['cloud'])) {
                $body .= "───────────────────────────────────────\n";
                $body .= "CLOUD-UPLOADS\n";
                $body .= "───────────────────────────────────────\n\n";
                
                if (isset($report['cloud']['s3'])) {
                    $s3 = $report['cloud']['s3'];
                    if (is_array($s3) && isset($s3['zip'])) {
                        $status = ($s3['zip']['success'] ?? false) ? '✅' : '❌';
                        $body .= "AWS S3: {$status}\n";
                    }
                }
                
                if (isset($report['cloud']['azure'])) {
                    $az = $report['cloud']['azure'];
                    if (is_array($az) && isset($az['zip'])) {
                        $status = ($az['zip']['success'] ?? false) ? '✅' : '❌';
                        $body .= "Azure Blob: {$status}\n";
                    }
                }
                
                if (isset($report['cloud']['onedrive'])) {
                    $od = $report['cloud']['onedrive'];
                    if (is_array($od) && isset($od['zip'])) {
                        $status = ($od['zip']['success'] ?? false) ? '✅' : '❌';
                        $body .= "OneDrive: {$status}\n";
                    }
                }
                
                $body .= "\n";
            }
            
            $body .= "═══════════════════════════════════════\n\n";
            $body .= "Diese E-Mail wurde automatisch vom ITN Sicherung Plugin gesendet.\n";
            
        } else {
            $subject = '[ITN Sicherung] ❌ Backup fehlgeschlagen - ' . $site_name;
            
            $body = "ACHTUNG: Backup fehlgeschlagen!\n\n";
            $body .= "═══════════════════════════════════════\n";
            $body .= "FEHLER-DETAILS\n";
            $body .= "═══════════════════════════════════════\n\n";
            $body .= "Website: {$site_name}\n";
            $body .= "URL: {$site_url}\n";
            $body .= "Zeitpunkt: " . date('d.m.Y H:i:s', time()) . "\n\n";
            $body .= "Fehlermeldung:\n";
            $body .= $message . "\n\n";
            $body .= "═══════════════════════════════════════\n\n";
            $body .= "Bitte überprüfen Sie die Einstellungen und den Server.\n";
            $body .= "Debug-Log: wp-content/debug.log\n\n";
            $body .= "Diese E-Mail wurde automatisch vom ITN Sicherung Plugin gesendet.\n";
        }
        
        // Sende E-Mail
        $result = ITN_Helpers::send_domain_mail(
            $to,
            $subject,
            $body,
            'itn-sicherung',
            'ITN - Sicherung'
        );
        
        if ($result) {
            error_log('ITN E-Mail-Benachrichtigung gesendet an: ' . $to);
        } else {
            error_log('ITN E-Mail-Benachrichtigung FEHLER an: ' . $to);
        }
    }

        // Restore-Funktion
        public function restore($backup_file, $run_id = null, $force_drop = false) {
            try {
                @ignore_user_abort(true);
                @set_time_limit(0);
                $this->run_id = $run_id ?: ('restore_' . wp_generate_password(10, false, false) . '_' . time());
                $this->progress(1, 'Initialisierung (Restore)');
    
                $opts = $this->opts ?: [];
                $backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;
                $real_dir = realpath($backup_dir);
                $real_file = realpath($backup_file);
                if (!$real_dir || !$real_file || strpos($real_file, $real_dir) !== 0 || !is_file($real_file) || strtolower(pathinfo($real_file, PATHINFO_EXTENSION)) !== 'zip') {
                    $msg = 'Ungültige Backup-Datei (erwarte ZIP im Sicherungsordner).';
                    $this->progress(100, $msg, ['done' => true]);
                    return ['success' => false, 'message' => $msg];
                }
    
                $base = basename($real_file, '.zip');
                $this->work_dir = $backup_dir . '/' . $base;
                if (is_dir($this->work_dir)) ITN_Helpers::rrmdir($this->work_dir);
                ITN_Helpers::ensure_dir($this->work_dir);
    
                $this->progress(5, 'Entpacke ZIP...');
                $z = new ZipArchive();
                if ($z->open($real_file) !== true) {
                    $msg = 'ZIP konnte nicht geöffnet werden.';
                    $this->progress(100, $msg, ['done' => true]);
                    return ['success' => false, 'message' => $msg];
                }
                if (!$z->extractTo($this->work_dir)) {
                    $z->close();
                    $msg = 'ZIP konnte nicht entpackt werden.';
                    $this->progress(100, $msg, ['done' => true]);
                    return ['success' => false, 'message' => $msg];
                }
                $z->close();
                $this->progress(15, 'ZIP entpackt');
    
                $meta = [];
                $meta_path = $this->work_dir . '/backup_meta.json';
                if (file_exists($meta_path)) {
                    $meta = json_decode(@file_get_contents($meta_path), true) ?: [];
                }
    
                $sql_path = $this->work_dir . '/database.sql';
                if (!file_exists($sql_path)) {
                    $candidates = glob($this->work_dir . '/*.sql') ?: [];
                    $sql_path = $candidates ? $candidates[0] : '';
                }
    
                if ($force_drop || !empty($opts['restore_drop_db'])) {
                    $this->progress(20, 'Leere Datenbank (DROP ALL TABLES)');
                    $this->drop_all_tables();
                }
    
                if ($sql_path && file_exists($sql_path)) {
                    $this->progress(35, 'Importiere Datenbank...');
                    $ok = $this->import_sql_file($sql_path);
                    if (!$ok['success']) {
                        $msg = 'DB-Import fehlgeschlagen: ' . ($ok['message'] ?? 'Unbekannter Fehler');
                        $this->progress(100, $msg, ['done' => true]);
                        return ['success' => false, 'message' => $msg];
                    }
                    $this->progress(55, 'Datenbank importiert');
                } else {
                    $this->progress(35, 'Keine database.sql gefunden – überspringe DB-Import');
                }
    
                $this->progress(60, 'Dateien werden wiederhergestellt...');
                $exclude_files = ['database.sql', 'backup_meta.json', 'wp-config.php'];
                $this->copy_dir($this->work_dir, rtrim(ABSPATH, "/\\"), $exclude_files);
                $this->progress(80, 'Dateien wiederhergestellt');
    
                $new_url = home_url();
                if (!empty($meta['site_url']) && is_string($meta['site_url']) && $meta['site_url'] !== $new_url) {
                    $this->progress(85, 'URL-Anpassungen...');
                    ITN_Helpers::db_serialized_search_replace((string)$meta['site_url'], (string)$new_url);
                    ITN_Helpers::rewrite_wp_config_urls($new_url);
                    $host = parse_url($new_url, PHP_URL_HOST);
                    $scheme = parse_url($new_url, PHP_URL_SCHEME) ?: 'https';
                    if ($host) ITN_Helpers::db_enforce_scheme_all($host, $scheme);
                }
                if (!empty($meta['abs_path'])) {
                    $this->progress(90, 'Pfad-Anpassungen...');
                    $old_abs = rtrim(str_replace('\\','/', (string)$meta['abs_path']), '/');
                    $new_abs = rtrim(str_replace('\\','/', ABSPATH), '/');
                    if ($old_abs && $new_abs && $old_abs !== $new_abs) {
                        ITN_Helpers::db_serialized_abs_path_replace($old_abs, $new_abs);
                    }
                }
                $this->progress(95, 'Anpassungen abgeschlossen');
    
                $msg = 'Wiederherstellung abgeschlossen.';
                $this->progress(100, $msg, ['done' => true]);
    
                return ['success' => true, 'message' => $msg];
            } catch (Exception $e) {
                $msg = 'Restore-Fehler: ' . $e->getMessage();
                $this->progress(100, $msg, ['done' => true]);
                return ['success' => false, 'message' => $msg];
            }
        }
    
        protected function encryptEntryIfNeeded($entryName) {
            if (!$this->zip_encrypt_enabled || !$this->zip) return;
            if (!method_exists($this->zip, 'setEncryptionName')) return;
    
            $method = defined('ZipArchive::EM_AES_256') ? ZipArchive::EM_AES_256
                     : (defined('ZipArchive::EM_TRAD_PKWARE') ? ZipArchive::EM_TRAD_PKWARE : 0);
            if ($method) {
                if (PHP_VERSION_ID >= 70200) {
                    @$this->zip->setEncryptionName($entryName, $method, $this->zip_password);
                } else {
                    @$this->zip->setEncryptionName($entryName, $method);
                }
            }
        }
    
        protected function count_files($base_path, $relative, $excludes) {
            $dir = rtrim($base_path . $relative, '/');
            $items = @scandir($dir);
            if (!$items) return 0;
            $count = 0;
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $full = $dir . '/' . $item;
                $rel = ltrim($relative . '/' . $item, '/');
    
                if (ITN_Helpers::path_is_excluded($rel, $excludes)) continue;
                if (strpos($full, ITN_BACKUP_DIR) === 0) continue;
                if (strpos($full, ITN_PLUGIN_DIR) === 0) continue;
    
                if (is_dir($full)) {
                    $count += $this->count_files($base_path, $relative . '/' . $item, $excludes);
                } elseif (is_file($full)) {
                    $count += 1;
                }
            }
            return $count;
        }
    
        protected function add_dir_to_zip($base_path, $relative, $excludes) {
            $dir = rtrim($base_path . $relative, '/');
            $items = @scandir($dir);
            if (!$items) return;
            $batch = 0;
            $flush_counter = 0;
            
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $full = $dir . '/' . $item;
                $rel = ltrim($relative . '/' . $item, '/');
    
                if (ITN_Helpers::path_is_excluded($rel, $excludes)) continue;
                if (strpos($full, ITN_BACKUP_DIR) === 0) continue;
                if (strpos($full, ITN_PLUGIN_DIR) === 0) continue;
    
                if (is_dir($full)) {
                    @$this->zip->addEmptyDir($rel);
                    $this->add_dir_to_zip($base_path, $relative . '/' . $item, $excludes);
                } elseif (is_file($full)) {
                    @$this->zip->addFile($full, $rel);
                    $this->encryptEntryIfNeeded($rel);
                    $this->processed_files++;
                    $batch++;
                    $flush_counter++;
                    
                    // Progress alle 100 Dateien
                    if ($batch >= 100) {
                        $pct = 26 + (int)floor(($this->processed_files / $this->total_files) * 64);
                        $this->progress(min(90, $pct), 'Dateien gepackt: ' . $this->processed_files . ' / ' . $this->total_files);
                        $batch = 0;
                    }
                    
                    // WICHTIG: Speicher freigeben alle 1000 Dateien
                    if ($flush_counter >= 1000) {
                        if (function_exists('gc_collect_cycles')) {
                            gc_collect_cycles();
                        }
                        // Bei sehr vielen Dateien: Zwischenspeichern
                        if ($this->processed_files % 5000 === 0) {
                            error_log('ITN Zwischenstand: ' . $this->processed_files . ' Dateien gepackt');
                        }
                        $flush_counter = 0;
                    }
                }
            }
        }
    
        protected static function find_mysqldump() {
            if (!function_exists('exec')) return null;
            $disabled = ini_get('disable_functions');
            if ($disabled) {
                $list = array_map('trim', explode(',', $disabled));
                if (in_array('exec', $list, true)) return null;
            }
            $candidates = ['mysqldump', '/usr/bin/mysqldump', '/usr/local/bin/mysqldump'];
            foreach ($candidates as $bin) {
                $path = @trim(shell_exec('command -v ' . escapeshellcmd($bin)));
                if ($path) return $path;
            }
            return null;
        }
    
        protected function dump_database($sql_path) {
            global $wpdb;
            $db_name = DB_NAME;
            $db_user = DB_USER;
            $db_pass = DB_PASSWORD;
            $db_host = DB_HOST;
    
            $mysqldump = self::find_mysqldump();
            if ($mysqldump) {
                $cmd = escapeshellcmd($mysqldump) . ' --host=' . escapeshellarg($db_host) .
                       ' --user=' . escapeshellarg($db_user) . ' --password=' . escapeshellarg($db_pass) .
                       ' --default-character-set=utf8mb4 ' . escapeshellarg($db_name) . ' > ' . escapeshellarg($sql_path);
                $ret = null;
                @exec($cmd, $out, $ret);
                if ($ret === 0 && file_exists($sql_path) && filesize($sql_path) > 0) {
                    return ['success' => true];
                }
            }
    
            try {
                $tables = $wpdb->get_col('SHOW TABLES');
                $sql = "-- ITN Sicherung SQL Dump\n-- Host: " . $db_host . "\n-- DB: " . $db_name . "\n-- Date: " . date('c') . "\n\nSET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n";
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
                                $v[] = ($val === null) ? 'NULL' : "'" . esc_sql($this->sql_escape($val)) . "'";
                            }
                            $vals[] = '(' . implode(',', $v) . ')';
                        }
                        $sql .= implode(",\n", $vals) . ";\n\n";
                    }
                }
                $sql .= "SET FOREIGN_KEY_CHECKS=1;\n";
                file_put_contents($this->sql_path, $sql);
                return ['success' => true];
            } catch (Exception $e) {
                return ['success' => false, 'message' => 'DB-Dump fehlgeschlagen: ' . $e->getMessage()];
            }
        }
    
        protected function sql_escape($val) {
            return str_replace(["\\", "\0", "\n", "\r", "'", '"', "\x1a"], ["\\\\", "\\0", "\\n", "\\r", "\\'", '\\"', "\\Z"], $val);
        }
    
        protected function drop_all_tables() {
            global $wpdb;
            $tables = $wpdb->get_col('SHOW TABLES');
            foreach ($tables as $t) {
                $wpdb->query("DROP TABLE IF EXISTS `$t`");
            }
        }
    
        protected function import_sql_file($sql_path) {
            global $wpdb;
            $sql = @file_get_contents($sql_path);
            if ($sql === false) return ['success' => false, 'message' => 'SQL-Datei nicht lesbar'];
            $wpdb->query("SET NAMES utf8mb4");
            $wpdb->query("SET FOREIGN_KEY_CHECKS=0");
    
            $stmts = preg_split('/;[\r\n]+/', $sql);
            foreach ($stmts as $stmt) {
                $stmt = trim($stmt);
                if ($stmt === '' || strpos($stmt, '--') === 0) continue;
                $res = $wpdb->query($stmt);
                if ($res === false) {
                    return ['success' => false, 'message' => 'Fehler bei SQL: ' . substr($stmt, 0, 120)];
                }
            }
            $wpdb->query("SET FOREIGN_KEY_CHECKS=1");
            return ['success' => true];
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
    
        protected function upload_to_s3($file) {
            $region = $this->opts['s3_region'] ?? '';
            $access = $this->opts['s3_access_key'] ?? '';
            $secret = $this->opts['s3_secret_key'] ?? '';
            $bucket = $this->opts['s3_bucket'] ?? '';
            $prefix = trim($this->opts['s3_prefix'] ?? '', '/');
            if (!$region || !$access || !$secret || !$bucket) return ['success'=>false,'message'=>'S3 unvollständig konfiguriert'];
            $key = ($prefix !== '' ? ($prefix . '/') : '') . basename($file);
    
            $url = ITN_Helpers::s3_presign_put($region, $access, $secret, $bucket, $key, 3600);
            $mime = (strtolower(pathinfo($file, PATHINFO_EXTENSION))==='php' ? 'text/plain' : 'application/zip');
            $put = ITN_Helpers::http_put_file($url, $file, ['Content-Type' => $mime]);
            if (!empty($put['success'])) return ['success'=>true];
            return ['success'=>false,'code'=>$put['code'] ?? 0, 'message'=>$put['error'] ?? 's3_put_failed'];
        }
    
        protected function upload_to_azure($file) {
            $account = $this->opts['azure_account'] ?? '';
            $keyB64  = $this->opts['azure_key'] ?? '';
            $container = $this->opts['azure_container'] ?? '';
            $prefix = trim($this->opts['azure_prefix'] ?? '', '/');
            if (!$account || !$keyB64 || !$container) return ['success'=>false,'message'=>'Azure unvollständig konfiguriert'];
            $blob = ($prefix !== '' ? ($prefix . '/') : '') . basename($file);
            $url = ITN_Helpers::azure_blob_sas_url($account, $keyB64, $container, $blob, 'cw', 3600, 'https');
            $mime = (strtolower(pathinfo($file, PATHINFO_EXTENSION))==='php' ? 'text/plain' : 'application/zip');
            $put = ITN_Helpers::http_put_file($url, $file, ['x-ms-blob-type' => 'BlockBlob', 'Content-Type' => $mime]);
            if (!empty($put['success'])) return ['success'=>true];
            return ['success'=>false,'code'=>$put['code'] ?? 0,'message'=>$put['error'] ?? 'azure_put_failed'];
        }
    
        protected function upload_to_onedrive($file) {
            $folder = $this->opts['onedrive_folder'] ?? 'backups';
            $tokens = get_option('itn_onedrive_tokens', []);
            $access = $tokens['access_token'] ?? '';
            $refresh= $tokens['refresh_token'] ?? '';
            $expires= intval($tokens['expires'] ?? 0);
            $tenant = $this->opts['onedrive_tenant'] ?? 'consumers';
            $client = ITN_Helpers::get_onedrive_client_id($this->opts);
    
            if (!$client) return ['success'=>false,'message'=>'OneDrive Client-ID fehlt'];
            if (!$access && !$refresh) return ['success'=>false,'message'=>'OneDrive nicht verbunden'];
    
            if ($expires && time() >= $expires - 60 && $refresh) {
                $po = ITN_Helpers::od_refresh_token($tenant, $client, $refresh);
                if (!empty($po['success'])) {
                    $access = $po['access_token'];
                    $refresh= $po['refresh_token'] ?? $refresh;
                    $exp = time() + intval($po['expires_in'] ?? 3600);
                    update_option('itn_onedrive_tokens', [
                        'access_token'  => $access,
                        'refresh_token' => $refresh,
                        'expires'       => $exp,
                    ], false);
                }
            }
    
            if (!$access) return ['success'=>false,'message'=>'Kein gültiger OneDrive Access Token'];
            $up = ITN_Helpers::od_upload_file($access, $file, $folder);
            return $up;
        }
    
        protected function copy_dir($from, $to, $exclude_files = []) {
            $items = @scandir($from);
            if (!$items) return;
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $src = $from . '/' . $item;
                $dst = $to . '/' . $item;
                if (in_array($item, $exclude_files, true)) continue;
    
                if (is_dir($src)) {
                    if (!file_exists($dst)) @mkdir($dst, 0755, true);
                    $this->copy_dir($src, $dst, $exclude_files);
                } else {
                    @copy($src, $dst);
                }
            }
        }
    }