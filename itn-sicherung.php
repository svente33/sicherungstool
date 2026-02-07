<?php
/**
 * Plugin Name: ITN - Sicherung
 * Description: Backups von Dateien und Datenbank als ZIP mit optionaler AES-256-Verschlüsselung, Zeitplan, Wiederherstellung (In-Place mit Fortschritt). Sicherer Sicherungsordner, Live-Status. E-Mail-Benachrichtigungen, FTP-Upload. Cloud-Uploads: AWS S3, Azure Blob, OneDrive. Backupbericht nach Abschluss.
 * Version: 2.0.0
 * Author: ITN Online
 * Text Domain: itn-sicherung
 */

if (!defined('ABSPATH')) exit;

define('ITN_PLUGIN_VERSION', '2.0.0');
define('ITN_PLUGIN_FILE', __FILE__);
define('ITN_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ITN_PLUGIN_URL', plugin_dir_url(__FILE__));
define('ITN_BACKUP_DIR', WP_CONTENT_DIR . '/itn-sicherung-backups');

function itn_safe_require($path, $label) {
    if (!file_exists($path)) {
        $GLOBALS['itn_activation_errors'][] = sprintf('Datei fehlt: %s (%s)', $path, $label);
        return false;
    }
    @require_once $path;
    return true;
}

function itn_protect_backup_dir($dir) {
    if (!$dir) return;
    if (!file_exists($dir)) @wp_mkdir_p($dir);
    if (!is_dir($dir) || !is_writable($dir)) return;
    $htaccess = $dir . '/.htaccess';
    $ht_content = "Options -Indexes\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Deny from all\n</IfModule>\n";
    @file_put_contents($htaccess, $ht_content);
    $webconfig = $dir . '/web.config';
    $web_content = '<?xml version="1.0" encoding="UTF-8"?>
<configuration><system.webServer><security><authorization><remove users="*" roles="" verbs="" /><add accessType="Deny" users="*" /></authorization></security><directoryBrowse enabled="false" /></system.webServer></configuration>';
    @file_put_contents($webconfig, $web_content);
    $index = $dir . '/index.php';
    if (!file_exists($index)) { @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit;\n"); }
}

function itn_collect_environment_issues() {
    $errors = []; $warnings = [];
    if (version_compare(PHP_VERSION, '7.4', '<')) $errors[] = sprintf('Erforderliche PHP-Version >= 7.4, gefunden: %s', PHP_VERSION);
    if (!file_exists(ITN_BACKUP_DIR)) {
        if (!wp_mkdir_p(ITN_BACKUP_DIR)) $errors[] = sprintf('Backup-Verzeichnis konnte nicht angelegt werden: %s', ITN_BACKUP_DIR);
        else itn_protect_backup_dir(ITN_BACKUP_DIR);
    } else {
        itn_protect_backup_dir(ITN_BACKUP_DIR);
        if (!is_writable(ITN_BACKUP_DIR)) $errors[] = sprintf('Backup-Verzeichnis ist nicht beschreibbar: %s', ITN_BACKUP_DIR);
    }
    if (!class_exists('ZipArchive')) $warnings[] = 'PHP-Erweiterung ZipArchive fehlt. ZIP-Backups/Installer funktionieren nicht.';
    $required = [
        ITN_PLUGIN_DIR . 'includes/helpers.php' => 'Hilfsfunktionen',
        ITN_PLUGIN_DIR . 'includes/class-itn-encryption.php' => 'Verschlüsselung',
        ITN_PLUGIN_DIR . 'includes/class-itn-backup.php' => 'Backup',
        ITN_PLUGIN_DIR . 'includes/class-itn-chunked-backup.php' => 'Chunked Backup',
        ITN_PLUGIN_DIR . 'includes/class-itn-installer-generator.php' => 'Installer-Generator',
        ITN_PLUGIN_DIR . 'includes/class-itn-schedule.php' => 'Zeitplan',
        ITN_PLUGIN_DIR . 'includes/templates/installer.php' => 'Installer-Vorlage',
    ];
    foreach ($required as $file => $label) { if (!file_exists($file)) $errors[] = sprintf('Pflichtdatei fehlt: %s (%s)', $file, $label); }
    return ['errors' => $errors, 'warnings' => $warnings];
}

function itn_send_activation_email() {
    $site_url   = home_url();
    $site_name  = get_bloginfo('name');
    $admin_email= get_option('admin_email');
    $wp_version = get_bloginfo('version');
    $php_version= PHP_VERSION;
    $server_name= $_SERVER['SERVER_NAME'] ?? '';
    $host       = parse_url($site_url, PHP_URL_HOST) ?: ($server_name ?: 'localhost');
    $host       = preg_replace('/^www\./i', '', (string)$host);
    $from_email = 'itn-sicherung@' . $host;

    $to      = 'plugin@itn-ol.de';
    $subject = '[ITN - Sicherung] Plugin aktiviert auf ' . $site_name;
    $body    = "Das Plugin 'ITN - Sicherung' wurde aktiviert.\n\nSeite: {$site_name}\nURL: {$site_url}\nAdmin-E-Mail: {$admin_email}\nPlugin-Version: " . ITN_PLUGIN_VERSION . "\nWordPress-Version: {$wp_version}\nPHP-Version: {$php_version}\nServer: {$server_name}\nZeit: " . date('Y-m-d H:i:s') . "\n";
    $headers = ['Content-Type: text/plain; charset=UTF-8','From: ITN - Sicherung <' . $from_email . '>'];
    @wp_mail($to, $subject, $body, $headers);
}

register_activation_hook(ITN_PLUGIN_FILE, function () {
    $issues = itn_collect_environment_issues();
    update_option('itn_last_activation_issues', $issues, false);
    itn_send_activation_email();
});

register_deactivation_hook(ITN_PLUGIN_FILE, function () {
    if (file_exists(ITN_PLUGIN_DIR . 'includes/class-itn-schedule.php')) {
        @require_once ITN_PLUGIN_DIR . 'includes/class-itn-schedule.php';
        if (class_exists('ITN_Schedule')) ITN_Schedule::clear_cron();
    }
});

/* ITN_PLUGIN_READY definieren */
$GLOBALS['itn_activation_errors'] = [];
$GLOBALS['itn_activation_warnings'] = [];

$itn_ready = true;
$itn_ready = itn_safe_require(ITN_PLUGIN_DIR . 'includes/helpers.php', 'Hilfsfunktionen') && $itn_ready;
$itn_ready = itn_safe_require(ITN_PLUGIN_DIR . 'includes/class-itn-encryption.php', 'Verschlüsselung') && $itn_ready;
$itn_ready = itn_safe_require(ITN_PLUGIN_DIR . 'includes/class-itn-backup.php', 'Backup') && $itn_ready;
$itn_ready = itn_safe_require(ITN_PLUGIN_DIR . 'includes/class-itn-chunked-backup.php', 'Chunked Backup') && $itn_ready;
$itn_ready = itn_safe_require(ITN_PLUGIN_DIR . 'includes/class-itn-installer-generator.php', 'Installer-Generator') && $itn_ready;
$itn_ready = itn_safe_require(ITN_PLUGIN_DIR . 'includes/class-itn-schedule.php', 'Zeitplan') && $itn_ready;
define('ITN_PLUGIN_READY', $itn_ready);

/* Settings-Defaults */
function itn_settings_defaults() {
    return [
        'exclude_paths' => [],
        'ftp_enabled' => false,
        'ftp_host' => '',
        'ftp_port' => 21,
        'ftp_user' => '',
        'ftp_pass' => '',
        'ftp_path' => '',
        'ftp_passive' => false,
        'schedule_frequency' => 'daily',
        'schedule_time' => '02:00',
        'schedule_dow' => 1,
        'schedule_dom' => 1,
        'custom_interval_minutes' => 60,
        'retention' => 5,
        'backup_dir' => ITN_BACKUP_DIR,
        'notify_enabled' => false,
        'notify_email' => '',
        'zip_encrypt_enabled' => false,
        'zip_encrypt_password' => '',
        'restore_drop_db' => false,
        's3_enabled' => false,
        's3_access_key' => '',
        's3_secret_key' => '',
        's3_region' => '',
        's3_bucket' => '',
        's3_prefix' => '',
        'azure_enabled' => false,
        'azure_account' => '',
        'azure_key' => '',
        'azure_container' => '',
        'azure_prefix' => '',
        'onedrive_enabled' => false,
        'onedrive_tenant' => 'consumers',
        'onedrive_client_id_enc' => '',
        'onedrive_folder' => 'backups',
    ];
}

/* Admin-Hinweise */
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) return;

    // Zeige Verschlüsselungsfehler, falls vorhanden
    $enc_error = get_transient('itn_encryption_error');
    if ($enc_error) {
        echo '<div class="notice notice-error is-dismissible">';
        echo '<p><strong>ITN Sicherung - Verschlüsselungsfehler:</strong> ' . esc_html($enc_error) . '</p>';
        echo '<p>Bitte prüfen Sie die Verschlüsselungseinstellungen oder deaktivieren Sie die Verschlüsselung.</p>';
        echo '</div>';
        delete_transient('itn_encryption_error');
    }

    $current = itn_collect_environment_issues();
    $last = get_option('itn_last_activation_issues');
    if (empty($current['errors']) && !empty($last)) { delete_option('itn_last_activation_issues'); $last = null; }

    $errors = $current['errors']; $warnings = $current['warnings'];
    if ($last) {
        foreach (($last['errors'] ?? []) as $e) if (!in_array($e, $errors, true)) $errors[] = $e;
        foreach (($last['warnings'] ?? []) as $w) if (!in_array($w, $warnings, true)) $warnings[] = $w;
    }

    if (!empty($errors)) {
        echo '<div class="notice notice-error"><p><strong>ITN - Sicherung:</strong> Probleme erkannt:</p><ul>';
        foreach ($errors as $e) echo '<li>' . esc_html($e) . '</li>';
        echo '</ul></div>';
    }
    if (!empty($warnings)) {
        echo '<div class="notice notice-warning"><p><strong>ITN - Sicherung:</strong> Hinweise:</p><ul>';
        foreach ($warnings as $w) echo '<li>' . esc_html($w) . '</li>';
        echo '</ul></div>';
    }

    $od_notice = isset($_GET['itn_od_notice']) ? sanitize_text_field($_GET['itn_od_notice']) : '';
    $od_msg    = isset($_GET['itn_od_msg']) ? sanitize_text_field($_GET['itn_od_msg']) : '';
    if ($od_notice) {
        $cls = (strpos($od_notice,'error')!==false?'notice-error':(strpos($od_notice,'info')!==false?'notice-info':'notice-success'));
        echo '<div class="notice ' . esc_attr($cls) . '"><p>' . esc_html($od_msg) . '</p></div>';
    }

    $cloud_notice = isset($_GET['itn_cloud_notice']) ? sanitize_text_field($_GET['itn_cloud_notice']) : '';
    $cloud_msg    = isset($_GET['itn_cloud_msg']) ? sanitize_text_field($_GET['itn_cloud_msg']) : '';
    if ($cloud_notice) {
        $cls = (strpos($cloud_notice,'error')!==false?'notice-error':'notice-success');
        echo '<div class="notice ' . esc_attr($cls) . '"><p>' . esc_html($cloud_msg) . '</p></div>';
    }
});

class ITNSicherungPlugin {
    public function __construct() {
        add_action('admin_menu', [$this, 'register_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);

        add_action('admin_post_itn_download_file', [$this, 'handle_download_file']);
        add_action('admin_post_itn_delete_backup', [$this, 'handle_delete_backup']);

        // CHUNKED BACKUP AJAX-HANDLER
        add_action('wp_ajax_itn_chunked_init', [$this, 'ajax_chunked_init']);
        add_action('wp_ajax_itn_chunked_process', [$this, 'ajax_chunked_process']);
        add_action('wp_ajax_itn_chunked_finalize', [$this, 'ajax_chunked_finalize']);
        add_action('wp_ajax_itn_test_cron', [$this, 'ajax_test_cron']);
        
        add_action('wp_ajax_itn_start_backup', [$this, 'ajax_start_backup']);
        add_action('wp_ajax_itn_get_progress', [$this, 'ajax_get_progress']);
        add_action('wp_ajax_itn_start_restore', [$this, 'ajax_start_restore']);
        add_action('wp_ajax_itn_background_backup', [$this, 'handle_background_backup']);

        add_action('admin_post_itn_onedrive_start', [$this, 'handle_onedrive_start']);
        add_action('admin_post_itn_onedrive_poll',  [$this, 'handle_onedrive_poll']);
        add_action('admin_post_itn_cloud_disconnect', [$this, 'handle_cloud_disconnect']);

        add_action('itn/run_backup_cron', [$this, 'cron_run_backup'], 10, 0);
        add_action('itn/run_backup_now', [$this, 'cron_run_backup_with_id'], 10, 1);
        add_action('itn/run_restore_now', [$this, 'cron_run_restore_with_id'], 10, 3);

        if (ITN_PLUGIN_READY) {
            add_action('admin_post_itn_restore_backup', [$this, 'handle_restore_backup']);
            add_action('admin_post_itn_save_settings', [$this, 'handle_save_settings']);
        }
    }

    public function register_admin_menu() {
        add_menu_page(
            __('ITN - Sicherung', 'itn-sicherung'),
            __('ITN - Sicherung', 'itn-sicherung'),
            'manage_options',
            'itn-sicherung',
            [$this, 'render_admin_page'],
            'dashicons-shield',
            80
        );
    }
    
    public function register_settings() { 
        register_setting('itn_settings_group', 'itn_settings'); 
    }

    public function enqueue_admin_assets($hook) {
        if (strpos($hook, 'itn-sicherung') !== false) {
            wp_enqueue_style('itn-admin', ITN_PLUGIN_URL . 'assets/admin.css', [], ITN_PLUGIN_VERSION);
            wp_enqueue_script('itn-admin', ITN_PLUGIN_URL . 'assets/admin.js', ['jquery'], ITN_PLUGIN_VERSION, true);
            wp_localize_script('itn-admin', 'ITNSicherungAjax', [
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonces'  => [
                    'start'    => wp_create_nonce('itn_start_backup'),
                    'progress' => wp_create_nonce('itn_get_progress'),
                    'restore'  => wp_create_nonce('itn_start_restore'),
                    'chunked'  => wp_create_nonce('itn_chunked_backup'),
                ],
                'i18n' => [
                    'starting'  => __('Backup wird gestartet...', 'itn-sicherung'),
                    'running'   => __('Sicherung läuft...', 'itn-sicherung'),
                    'done'      => __('Backup abgeschlossen.', 'itn-sicherung'),
                    'error'     => __('Fehler beim Backup.', 'itn-sicherung'),
                    'restoring' => __('Wiederherstellung läuft...', 'itn-sicherung'),
                    'restored'  => __('Wiederherstellung abgeschlossen.', 'itn-sicherung'),
                ]
            ]);
        }
    }

    public function cron_run_backup() {
        error_log('ITN Cron: Starte geplantes Backup');
        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup = new ITN_Backup($opts);
        $result = $backup->run(null);
        error_log('ITN Cron: Backup abgeschlossen - ' . ($result['success'] ? 'SUCCESS' : 'FAILED'));
        if (class_exists('ITN_Schedule')) ITN_Schedule::maybe_schedule_next_monthly();
    }
    
    public function cron_run_backup_with_id($run_id = null) {
        error_log('ITN Cron Backup gestartet mit Run-ID: ' . $run_id);
        
        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup = new ITN_Backup($opts);
        
        error_log('ITN Starte Backup->run()...');
        $result = $backup->run($run_id);
        
        error_log('ITN Backup->run() fertig: ' . ($result['success'] ? 'SUCCESS' : 'FAILED'));
        
        if (class_exists('ITN_Schedule')) ITN_Schedule::maybe_schedule_next_monthly();
    }
    
    public function cron_run_restore_with_id($run_id, $backup_file, $force_drop = false) {
        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup = new ITN_Backup($opts);
        $backup->restore($backup_file, $run_id, (bool)$force_drop);
    }

    public function ajax_start_backup() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __('Keine Berechtigung', 'itn-sicherung')], 403);
        check_ajax_referer('itn_start_backup');

        $issues = itn_collect_environment_issues();
        if (!empty($issues['errors'])) {
            wp_send_json_error(['message' => implode(' | ', $issues['errors'])], 400);
        }

        $run_id = 'run_' . wp_generate_password(12, false, false) . '_' . time();
        ITN_Helpers::progress_set($run_id, 1, 'Backup wird im Hintergrund gestartet...');

        update_option('itn_backup_running', ['run_id' => $run_id, 'started' => time()], false);
        
        $ts = time() + 2;
        wp_schedule_single_event($ts, 'itn/run_backup_now', [$run_id]);
        spawn_cron();
        
        wp_send_json_success(['run_id' => $run_id, 'method' => 'cron', 'message' => 'Backup läuft via WP-Cron']);
    }

       // CHUNKED BACKUP: Initialisierung
       public function ajax_chunked_init() {
        // Error Handling aktivieren
        @ini_set('display_errors', '0');
        @error_reporting(E_ALL);
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Keine Berechtigung', 'itn-sicherung')], 403);
        }
        
        // Nonce prüfen
        if (!isset($_POST['_ajax_nonce']) || !wp_verify_nonce($_POST['_ajax_nonce'], 'itn_chunked_backup')) {
            wp_send_json_error(['message' => 'Ungültige Nonce'], 403);
        }

        $run_id = isset($_POST['run_id']) ? sanitize_text_field($_POST['run_id']) : '';
        if (!$run_id) {
            wp_send_json_error(['message' => 'Keine Run-ID'], 400);
        }

        try {
            // Prüfe ob Klasse existiert
            if (!class_exists('ITN_Chunked_Backup')) {
                throw new Exception('ITN_Chunked_Backup Klasse nicht gefunden');
            }

            $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
            $chunked = new ITN_Chunked_Backup($opts, $run_id);

            $result = $chunked->init();

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result);
            }
        } catch (Exception $e) {
            error_log('ITN Chunked Init Error: ' . $e->getMessage());
            wp_send_json_error(['message' => 'Fehler: ' . $e->getMessage()]);
        }
    }

    // CHUNKED BACKUP: Chunk verarbeiten
    public function ajax_chunked_process() {
        @ini_set('display_errors', '0');
        @error_reporting(E_ALL);
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Keine Berechtigung', 'itn-sicherung')], 403);
        }
        
        if (!isset($_POST['_ajax_nonce']) || !wp_verify_nonce($_POST['_ajax_nonce'], 'itn_chunked_backup')) {
            wp_send_json_error(['message' => 'Ungültige Nonce'], 403);
        }

        $run_id = isset($_POST['run_id']) ? sanitize_text_field($_POST['run_id']) : '';
        if (!$run_id) {
            wp_send_json_error(['message' => 'Keine Run-ID'], 400);
        }

        try {
            if (!class_exists('ITN_Chunked_Backup')) {
                throw new Exception('ITN_Chunked_Backup Klasse nicht gefunden');
            }

            $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
            $chunked = new ITN_Chunked_Backup($opts, $run_id);

            $result = $chunked->process_chunk();

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result);
            }
        } catch (Exception $e) {
            error_log('ITN Chunked Process Error: ' . $e->getMessage());
            wp_send_json_error(['message' => 'Fehler: ' . $e->getMessage()]);
        }
    }

    // CHUNKED BACKUP: Finalisierung
    public function ajax_chunked_finalize() {
        @ini_set('display_errors', '0');
        @error_reporting(E_ALL);
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Keine Berechtigung', 'itn-sicherung')], 403);
        }
        
        if (!isset($_POST['_ajax_nonce']) || !wp_verify_nonce($_POST['_ajax_nonce'], 'itn_chunked_backup')) {
            wp_send_json_error(['message' => 'Ungültige Nonce'], 403);
        }

        $run_id = isset($_POST['run_id']) ? sanitize_text_field($_POST['run_id']) : '';
        if (!$run_id) {
            wp_send_json_error(['message' => 'Keine Run-ID'], 400);
        }

        try {
            if (!class_exists('ITN_Chunked_Backup')) {
                throw new Exception('ITN_Chunked_Backup Klasse nicht gefunden');
            }

            $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
            $chunked = new ITN_Chunked_Backup($opts, $run_id);

            $result = $chunked->finalize();

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result);
            }
        } catch (Exception $e) {
            error_log('ITN Chunked Finalize Error: ' . $e->getMessage());
            wp_send_json_error(['message' => 'Fehler: ' . $e->getMessage()]);
        }
    }

    // CRON TEST
    public function ajax_test_cron() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Keine Berechtigung'], 403);
        }
        
        check_ajax_referer('itn_test_cron');
        
        // Triggere WP-Cron manuell
        spawn_cron();
        
        // Warte kurz
        sleep(1);
        
        // Prüfe ob unser Cron geplant ist
        $next = wp_next_scheduled('itn/run_backup_cron');
        
        if ($next) {
            wp_send_json_success([
                'message' => 'WP-Cron ausgeführt! Nächstes Backup: ' . date('d.m.Y H:i:s', $next) . ' (' . human_time_diff(time(), $next) . ')',
                'next' => $next,
            ]);
        } else {
            wp_send_json_error([
                'message' => 'WP-Cron ausgeführt, aber kein Backup geplant. Bitte Einstellungen speichern.',
            ]);
        }
    }

    public function ajax_get_progress() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Keine Berechtigung', 'itn-sicherung')], 403);
        }
        check_ajax_referer('itn_get_progress');

        $run_id = isset($_POST['run_id']) ? sanitize_text_field($_POST['run_id']) : '';
        if (!$run_id) wp_send_json_error(['message' => __('Run-ID fehlt', 'itn-sicherung')], 400);

        $p = ITN_Helpers::progress_get($run_id);
        if (!$p) {
            $last = get_option('itn_last_backup_result');
            if ($last && !empty($last['time']) && (time() - intval($last['time'])) < DAY_IN_SECONDS) {
                wp_send_json_success([
                    'percent' => 100,
                    'message' => $last['message'] ?? 'Fertig',
                    'done'    => true,
                    'zip'     => $last['zip'] ?? '',
                ]);
            }
            wp_send_json_success(['percent' => 0, 'message' => 'Warte auf Start...', 'done' => false]);
        }

        wp_send_json_success([
            'percent' => max(0, min(100, intval($p['percent']))),
            'message' => $p['message'] ?? '',
            'done'    => !empty($p['done']),
            'zip'     => $p['zip'] ?? '',
        ]);
    }

    public function ajax_start_restore() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Keine Berechtigung', 'itn-sicherung')], 403);
        }
        check_ajax_referer('itn_start_restore');

        $issues = itn_collect_environment_issues();
        if (!empty($issues['errors'])) {
            wp_send_json_error(['message' => implode(' | ', $issues['errors'])], 400);
        }

        $file = isset($_POST['backup_file']) ? sanitize_text_field($_POST['backup_file']) : '';
        if (!$file) {
            wp_send_json_error(['message' => __('Kein Backup gewählt.', 'itn-sicherung')], 400);
        }

        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;
        $real_dir = realpath($backup_dir);
        $real_file = realpath($file);

        $ext = strtolower(pathinfo($real_file, PATHINFO_EXTENSION));
        if (!$real_dir || !$real_file || strpos($real_file, $real_dir) !== 0 || !is_file($real_file) || $ext !== 'zip') {
            wp_send_json_error(['message' => __('Ungültige Backup-Datei (erwarte ZIP).', 'itn-sicherung')], 400);
        }

        $run_id = 'restore_' . wp_generate_password(10, false, false) . '_' . time();
        ITN_Helpers::progress_set($run_id, 1, __('Initialisierung', 'itn-sicherung'));

        $ts = time() + 2;
        wp_schedule_single_event($ts, 'itn/run_restore_now', [$run_id, $real_file, true]);
        spawn_cron();

        wp_send_json_success(['run_id' => $run_id]);
    }

    public function handle_background_backup() {
        @ignore_user_abort(true);
        @set_time_limit(0);
        @ini_set('max_execution_time', '0');
        
        $run_id = isset($_REQUEST['run_id']) ? sanitize_text_field($_REQUEST['run_id']) : '';
        $nonce = isset($_REQUEST['nonce']) ? sanitize_text_field($_REQUEST['nonce']) : '';
        
        if (!$run_id || !wp_verify_nonce($nonce, 'itn_bg_backup_' . $run_id)) {
            error_log('ITN Background Backup: Ungültige Nonce');
            exit;
        }
        
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } else {
            @ob_end_clean();
            header("Connection: close");
            header("Content-Length: 0");
            @flush();
        }
        
        $this->cron_run_backup_with_id($run_id);
        exit;
    }

    public function handle_download_file() {
        if (!current_user_can('manage_options')) {
            wp_die(__('Keine Berechtigung.', 'itn-sicherung'));
        }
        if (!isset($_REQUEST['_wpnonce']) || !wp_verify_nonce($_REQUEST['_wpnonce'], 'itn_download_file')) {
            wp_die(__('Ungültige Anfrage (Nonce).', 'itn-sicherung'));
        }

        $file = isset($_REQUEST['file']) ? sanitize_text_field($_REQUEST['file']) : '';
        if (!$file) wp_die(__('Keine Datei angegeben.', 'itn-sicherung'));

        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;

        $real_dir = realpath($backup_dir);
        $real_file = realpath($file);

        $ext = strtolower(pathinfo($real_file, PATHINFO_EXTENSION));
        $allowed = in_array($ext, ['zip','php','sql','json','txt','log'], true);

        if (!$real_dir || !$real_file || strpos($real_file, $real_dir) !== 0 || !is_file($real_file) || !$allowed) {
            wp_die(__('Ungültige Datei oder Pfad.', 'itn-sicherung'));
        }

        if (function_exists('nocache_headers')) nocache_headers();
        @set_time_limit(0);
        while (ob_get_level()) { @ob_end_clean(); }

        $mime = 'application/octet-stream';
        if ($ext === 'zip') $mime = 'application/zip';
        elseif ($ext === 'php' || $ext === 'sql' || $ext === 'log' || $ext === 'txt') $mime = 'text/plain';
        elseif ($ext === 'json') $mime = 'application/json';

        header('Content-Type: ' . $mime);
        header('Content-Disposition: attachment; filename="' . basename($real_file) . '"');
        header('Content-Length: ' . filesize($real_file));

        $fp = fopen($real_file, 'rb');
        if ($fp) {
            while (!feof($fp)) {
                echo fread($fp, 8192);
                flush();
            }
            fclose($fp);
            exit;
        }

        wp_die(__('Datei konnte nicht gelesen werden.', 'itn-sicherung'));
    }

    public function handle_delete_backup() {
        if (!current_user_can('manage_options')) wp_die(__('Keine Berechtigung.', 'itn-sicherung'));
        if (!isset($_REQUEST['_wpnonce']) || !wp_verify_nonce($_REQUEST['_wpnonce'], 'itn_delete_backup')) {
            wp_die(__('Ungültige Anfrage (Nonce).', 'itn-sicherung'));
        }

        $file = isset($_REQUEST['file']) ? sanitize_text_field($_REQUEST['file']) : '';
        if (!$file) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'backup','itn_notice'=>'delete_error','itn_msg'=>urlencode('Keine Datei angegeben.')], admin_url('admin.php')));
            exit;
        }

        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;

        $real_dir = realpath($backup_dir);
        $real_file = realpath($file);
        $ext = strtolower(pathinfo($real_file, PATHINFO_EXTENSION));
        $is_enc = (substr($real_file, -8) === '.zip.enc'); // Check for .zip.enc specifically
        
        // Accept both .zip and .zip.enc files
        if (!$real_dir || !$real_file || strpos($real_file, $real_dir) !== 0 || !is_file($real_file)) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'backup','itn_notice'=>'delete_error','itn_msg'=>urlencode('Ungültige Backup-Datei.')], admin_url('admin.php')));
            exit;
        }
        
        // Validate file extension: must be .zip or .zip.enc
        if (!$is_enc && $ext !== 'zip') {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'backup','itn_notice'=>'delete_error','itn_msg'=>urlencode('Ungültige Backup-Datei (erwarte ZIP oder ZIP.ENC).')], admin_url('admin.php')));
            exit;
        }

        $basename_no_ext = $is_enc ? basename($real_file, '.zip.enc') : basename($real_file, '.zip');
        $installer_candidate = $backup_dir . '/installer-' . $basename_no_ext . '.php';
        $work_dir_candidate  = $backup_dir . '/' . $basename_no_ext;
        $report_candidate    = $is_enc ? str_replace('.zip.enc', '.report.json', $real_file) : '';

        $ok_zip = @unlink($real_file);
        $ok_inst = true;
        $ok_dir = true;
        $ok_report = true;

        if (file_exists($installer_candidate)) {
            $ok_inst = @unlink($installer_candidate);
        }
        if (is_dir($work_dir_candidate)) {
            $ok_dir = ITN_Helpers::rrmdir($work_dir_candidate);
        }
        if ($report_candidate && file_exists($report_candidate)) {
            $ok_report = @unlink($report_candidate);
        }

        if ($ok_zip && $ok_inst && $ok_dir && $ok_report) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'backup','itn_notice'=>'delete_ok','itn_msg'=>urlencode('Backup vollständig gelöscht: '.basename($real_file))], admin_url('admin.php')));
        } else {
            $parts = [];
            if (!$ok_zip) $parts[] = 'ZIP';
            if (file_exists($installer_candidate) && !$ok_inst) $parts[] = 'Installer';
            if (is_dir($work_dir_candidate) && !$ok_dir) $parts[] = 'Arbeitsordner';
            $msg = 'Teilweise fehlgeschlagen ('.implode(', ', $parts).'). Bitte Dateirechte prüfen.';
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'backup','itn_notice'=>'delete_error','itn_msg'=>urlencode($msg)], admin_url('admin.php')));
        }
        exit;
    }

    public function handle_restore_backup() {
        if (!current_user_can('manage_options')) wp_die(__('Keine Berechtigung.', 'itn-sicherung'));
        check_admin_referer('itn_restore_backup');

        $issues = itn_collect_environment_issues();
        if (!empty($issues['errors'])) {
            $msg = 'Plugin nicht bereit. ' . implode(' | ', $issues['errors']);
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'restore','itn_notice'=>'restore_error','itn_msg'=>urlencode($msg)], admin_url('admin.php')));
            exit;
        }

        $backup_file = isset($_POST['backup_file']) ? sanitize_text_field($_POST['backup_file']) : '';
        if (!$backup_file) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'restore','itn_notice'=>'restore_error','itn_msg'=>urlencode('Kein Backup gewählt.')], admin_url('admin.php')));
            exit;
        }

        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup = new ITN_Backup($opts);
        $result = $backup->restore($backup_file, null, true);

        if (!empty($result['success'])) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'restore','itn_notice'=>'restore_success'], admin_url('admin.php')));
        } else {
            $msg = isset($result['message']) ? $result['message'] : __('Wiederherstellung fehlgeschlagen.', 'itn-sicherung');
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'restore','itn_notice'=>'restore_error','itn_msg'=>urlencode($msg)], admin_url('admin.php')));
        }
        exit;
    }

    public function handle_save_settings() {
        if (!current_user_can('manage_options')) wp_die(__('Keine Berechtigung.', 'itn-sicherung'));
        check_admin_referer('itn_save_settings');

        $old = get_option('itn_settings', []);
        $defaults = itn_settings_defaults();
        $new = [];

        $new['exclude_paths'] = array_values(array_filter(array_map('trim', explode("\n", (string)($_POST['exclude_paths'] ?? '')))));
        $new['ftp_enabled'] = isset($_POST['ftp_enabled']);
        $new['ftp_host'] = trim((string)($_POST['ftp_host'] ?? ''));
        $new['ftp_port'] = intval($_POST['ftp_port'] ?? 21);
        $new['ftp_user'] = trim((string)($_POST['ftp_user'] ?? ''));
        $new['ftp_pass'] = trim((string)($_POST['ftp_pass'] ?? ''));
        $new['ftp_path'] = trim((string)($_POST['ftp_path'] ?? ''));
        $new['ftp_passive'] = isset($_POST['ftp_passive']);
        $new['schedule_frequency'] = trim((string)($_POST['schedule_frequency'] ?? 'daily'));
        $new['schedule_time'] = trim((string)($_POST['schedule_time'] ?? '02:00'));
        $new['schedule_dow'] = intval($_POST['schedule_dow'] ?? 1);
        $new['schedule_dom'] = max(1, min(31, intval($_POST['schedule_dom'] ?? 1)));
        $new['custom_interval_minutes'] = max(5, intval($_POST['custom_interval_minutes'] ?? 60));
        $new['retention'] = max(1, intval($_POST['retention'] ?? 5));
        $new['backup_dir'] = trim((string)($_POST['backup_dir'] ?? ITN_BACKUP_DIR));
        $new['notify_enabled'] = isset($_POST['notify_enabled']);
        $new['notify_email'] = sanitize_email($_POST['notify_email'] ?? '');
        $new['zip_encrypt_enabled']  = isset($_POST['zip_encrypt_enabled']);
        $posted_zip_pw = isset($_POST['zip_encrypt_password']) ? trim((string)$_POST['zip_encrypt_password']) : '';
        
        // Validate password if encryption is enabled
        if ($new['zip_encrypt_enabled'] && $posted_zip_pw !== '') {
            $pw_check = ITN_Encryption::validate_password($posted_zip_pw);
            if (!$pw_check['valid']) {
                // Password validation failed - redirect with error
                $notice = ['itn_notice'=>'error','itn_msg'=>urlencode('Verschlüsselungspasswort ungültig: ' . $pw_check['message'])];
                wp_redirect(add_query_arg(array_merge(['page' => 'itn-sicherung', 'tab' => 'settings'], $notice), admin_url('admin.php')));
                exit;
            }
            $new['zip_encrypt_password'] = $posted_zip_pw;
        } elseif ($posted_zip_pw !== '') {
            $new['zip_encrypt_password'] = $posted_zip_pw;
        }
        $new['restore_drop_db'] = isset($_POST['restore_drop_db']);
        $new['s3_enabled']    = isset($_POST['s3_enabled']);
        $new['s3_access_key'] = trim((string)($_POST['s3_access_key'] ?? ''));
        $new['s3_secret_key'] = trim((string)($_POST['s3_secret_key'] ?? ''));
        $new['s3_region']     = trim((string)($_POST['s3_region'] ?? ''));
        $new['s3_bucket']     = trim((string)($_POST['s3_bucket'] ?? ''));
        $new['s3_prefix']     = trim((string)($_POST['s3_prefix'] ?? ''));
        $new['azure_enabled']   = isset($_POST['azure_enabled']);
        $new['azure_account']   = trim((string)($_POST['azure_account'] ?? ''));
        $new['azure_key']       = trim((string)($_POST['azure_key'] ?? ''));
        $new['azure_container'] = trim((string)($_POST['azure_container'] ?? ''));
        $new['azure_prefix']    = trim((string)($_POST['azure_prefix'] ?? ''));
        $new['onedrive_enabled']   = isset($_POST['onedrive_enabled']);
        $new['onedrive_tenant']    = trim((string)($_POST['onedrive_tenant'] ?? 'consumers'));
        $posted_client_id = trim((string)($_POST['onedrive_client_id'] ?? ''));
        if ($posted_client_id !== '') {
            $new['onedrive_client_id_enc'] = ITN_Helpers::encrypt_secret($posted_client_id);
        }
        $new['onedrive_folder']    = trim((string)($_POST['onedrive_folder'] ?? 'backups'));

        $merged = array_merge($defaults, (array)$old, $new);

        $saved = update_option('itn_settings', $merged);
        if (!$saved && get_option('itn_settings', null) === null) {
            add_option('itn_settings', $merged);
            $saved = true;
        }

        itn_protect_backup_dir($merged['backup_dir']);
        if (class_exists('ITN_Schedule')) ITN_Schedule::ensure_cron();

        $notice = $saved ? ['itn_notice'=>'settings_saved'] : ['itn_notice'=>'error','itn_msg'=>urlencode('Einstellungen konnten nicht gespeichert werden.')];
        wp_redirect(add_query_arg(array_merge(['page' => 'itn-sicherung', 'tab' => 'settings'], $notice), admin_url('admin.php')));
        exit;
    }

    public function handle_cloud_disconnect() {
        if (!current_user_can('manage_options')) wp_die(__('Keine Berechtigung.', 'itn-sicherung'));
        check_admin_referer('itn_cloud_disconnect');

        $provider = isset($_GET['provider']) ? sanitize_text_field($_GET['provider']) : '';
        $opts = get_option('itn_settings', []);
        $defaults = itn_settings_defaults();
        $changed = false;

        switch ($provider) {
            case 'onedrive':
                delete_option('itn_onedrive_tokens');
                delete_option('itn_onedrive_device');
                $opts['onedrive_enabled'] = false;
                $changed = true;
                $msg = __('OneDrive wurde getrennt (Tokens gelöscht).', 'itn-sicherung');
                break;
            case 's3':
                $opts['s3_enabled'] = false;
                $opts['s3_access_key'] = '';
                $opts['s3_secret_key'] = '';
                $opts['s3_region'] = '';
                $opts['s3_bucket'] = '';
                $opts['s3_prefix'] = '';
                $changed = true;
                $msg = __('AWS S3 wurde getrennt (Zugangsdaten entfernt).', 'itn-sicherung');
                break;
            case 'azure':
                $opts['azure_enabled'] = false;
                $opts['azure_account'] = '';
                $opts['azure_key'] = '';
                $opts['azure_container'] = '';
                $opts['azure_prefix'] = '';
                $changed = true;
                $msg = __('Azure Blob Storage wurde getrennt (Zugangsdaten entfernt).', 'itn-sicherung');
                break;
            default:
                $msg = __('Unbekannter Cloud-Provider.', 'itn-sicherung');
                wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_cloud_notice'=>'error','itn_cloud_msg'=>urlencode($msg)], admin_url('admin.php')));
                exit;
        }

        if ($changed) {
            $merged = array_merge($defaults, (array)$opts);
            update_option('itn_settings', $merged);
        }

        wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_cloud_notice'=>'ok','itn_cloud_msg'=>urlencode($msg)], admin_url('admin.php')));
        exit;
    }

    public function handle_onedrive_start() {
        if (!current_user_can('manage_options')) wp_die(__('Keine Berechtigung.', 'itn-sicherung'));
        check_admin_referer('itn_onedrive_start');

        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $tenant    = $opts['onedrive_tenant'] ?? 'consumers';
        $client_id = ITN_Helpers::get_onedrive_client_id($opts);
        if (!$client_id) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_od_notice'=>'error','itn_od_msg'=>urlencode('OneDrive Client-ID fehlt. Bitte zuerst Einstellungen speichern.')], admin_url('admin.php')));
            exit;
        }
        $dc = ITN_Helpers::od_device_code_start($tenant, $client_id, 'offline_access files.readwrite');
        if (empty($dc['success'])) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_od_notice'=>'error','itn_od_msg'=>urlencode('Device-Code Fehler: '.$dc['message'])], admin_url('admin.php')));
            exit;
        }
        update_option('itn_onedrive_device', [
            'device_code' => $dc['device_code'],
            'user_code'   => $dc['user_code'],
            'verification_uri' => $dc['verification_uri'] ?? ($dc['verification_uri_complete'] ?? 'https://microsoft.com/devicelogin'),
            'expires_in'  => $dc['expires_in'],
            'interval'    => $dc['interval'],
            'time'        => time(),
        ], false);
        $validMin = intval(($dc['expires_in'] ?? 1800) / 60);
        $msg = 'Code: ' . $dc['user_code'] . ' — URL: ' . ($dc['verification_uri'] ?? 'https://microsoft.com/devicelogin') . ' (Gültig ~' . $validMin . ' Min). Nach Bestätigung bitte „Token abrufen" klicken.';
        wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_od_notice'=>'info','itn_od_msg'=>urlencode($msg)], admin_url('admin.php')));
        exit;
    }

    public function handle_onedrive_poll() {
        if (!current_user_can('manage_options')) wp_die(__('Keine Berechtigung.', 'itn-sicherung'));
        check_admin_referer('itn_onedrive_poll');

        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $tenant    = $opts['onedrive_tenant'] ?? 'consumers';
        $client_id = ITN_Helpers::get_onedrive_client_id($opts);
        $dev = get_option('itn_onedrive_device', []);
        if (!$client_id || empty($dev['device_code'])) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_od_notice'=>'error','itn_od_msg'=>urlencode('Kein Gerätecode vorhanden. Bitte zuerst „OneDrive verbinden" klicken.')], admin_url('admin.php')));
            exit;
        }
        $po = ITN_Helpers::od_device_code_poll($tenant, $client_id, $dev['device_code']);
        if (empty($po['success'])) {
            wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_od_notice'=>'error','itn_od_msg'=>urlencode('Token-Abruf fehlgeschlagen: '.$po['message'])], admin_url('admin.php')));
            exit;
        }
        $exp = time() + intval($po['expires_in'] ?? 3600);
        update_option('itn_onedrive_tokens', [
            'access_token'  => $po['access_token'],
            'refresh_token' => $po['refresh_token'] ?? '',
            'expires'       => $exp,
        ], false);
        wp_redirect(add_query_arg(['page'=>'itn-sicherung','tab'=>'settings','itn_od_notice'=>'info','itn_od_msg'=>urlencode('OneDrive verbunden. Token gespeichert.')], admin_url('admin.php')));
        exit;
    }

    public function render_admin_page() {
        if (!current_user_can('manage_options')) return;

        $opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
        $backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;
        $backups_zip = glob($backup_dir . '/*.zip') ?: [];
        $backups_enc = glob($backup_dir . '/*.zip.enc') ?: [];
        $backups = array_merge($backups_zip, $backups_enc);
        rsort($backups);

        $active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'dashboard';

        $notice = isset($_GET['itn_notice']) ? sanitize_text_field($_GET['itn_notice']) : '';
        $msg = isset($_GET['itn_msg']) ? sanitize_text_field($_GET['itn_msg']) : '';

        ?>
        <div class="wrap itn-wrap">
            <h1 class="itn-title"><span class="dashicons dashicons-shield"></span> <?php _e('ITN - Sicherung', 'itn-sicherung'); ?></h1>

            <?php if ($notice): ?>
                <div class="notice <?php echo strpos($notice, 'error') !== false ? 'notice-error' : (strpos($notice, 'ok') !== false || $notice==='settings_saved' || $notice==='restore_success' ? 'notice-success' : 'notice-info'); ?>">
                    <p><?php echo esc_html($msg ?: ($notice === 'settings_saved' ? __('Einstellungen gespeichert.', 'itn-sicherung') : ($notice === 'restore_success' ? __('Wiederherstellung erfolgreich.', 'itn-sicherung') : ''))); ?></p>
                </div>
            <?php endif; ?>

            <nav class="nav-tab-wrapper itn-nav-tabs">
                <a href="<?php echo esc_url(admin_url('admin.php?page=itn-sicherung&tab=dashboard')); ?>" class="nav-tab <?php echo $active_tab === 'dashboard' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-dashboard"></span> <?php _e('Dashboard', 'itn-sicherung'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=itn-sicherung&tab=backup')); ?>" class="nav-tab <?php echo $active_tab === 'backup' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-download"></span> <?php _e('Backup', 'itn-sicherung'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=itn-sicherung&tab=restore')); ?>" class="nav-tab <?php echo $active_tab === 'restore' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-upload"></span> <?php _e('Wiederherstellung', 'itn-sicherung'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=itn-sicherung&tab=settings')); ?>" class="nav-tab <?php echo $active_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-admin-settings"></span> <?php _e('Einstellungen', 'itn-sicherung'); ?>
                </a>
            </nav>

            <div class="itn-tab-content">
                <?php
                $tab_file = '';
                switch ($active_tab) {
                    case 'backup':
                        $tab_file = ITN_PLUGIN_DIR . 'includes/admin/tab-backup.php';
                        break;
                    case 'restore':
                        $tab_file = ITN_PLUGIN_DIR . 'includes/admin/tab-restore.php';
                        break;
                    case 'settings':
                        $tab_file = ITN_PLUGIN_DIR . 'includes/admin/tab-settings.php';
                        break;
                    case 'dashboard':
                    default:
                        $tab_file = ITN_PLUGIN_DIR . 'includes/admin/tab-dashboard.php';
                        break;
                }
                
                if (file_exists($tab_file)) {
                    require $tab_file;
                } else {
                    echo '<p class="notice notice-error">Tab-Datei nicht gefunden: ' . esc_html(basename($tab_file)) . '</p>';
                }
                ?>
            </div>
        </div>
        <?php
    }
}

new ITNSicherungPlugin();