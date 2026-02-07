<?php
/**
 * ITN Sicherung CLI Backup Runner
 * Wird direkt über PHP-CLI aufgerufen, umgeht alle Webserver-Timeouts
 * 
 * Usage:
 *   php cli-backup-runner.php <run-id>           - Run with specific Run-ID
 *   php cli-backup-runner.php --cron             - Cron mode (generates Run-ID)
 */

// Parse command line arguments
$cron_mode = false;
$run_id = null;

if (isset($argv[1])) {
    if ($argv[1] === '--cron') {
        $cron_mode = true;
    } else {
        $run_id = $argv[1];
    }
}

// Finde WordPress
$wp_load = dirname(__FILE__) . '/../../wp-load.php';
if (!file_exists($wp_load)) {
    // Versuche alternative Pfade
    $alternatives = [
        dirname(__FILE__) . '/../../../wp-load.php',
        dirname(__FILE__) . '/../../../../wp-load.php',
    ];
    foreach ($alternatives as $alt) {
        if (file_exists($alt)) {
            $wp_load = $alt;
            break;
        }
    }
}

if (!file_exists($wp_load)) {
    error_log('ITN CLI Runner: wp-load.php nicht gefunden!');
    exit(1);
}

// Lade WordPress
define('DOING_CRON', true);
require_once($wp_load);

// Lade Plugin-Klassen
require_once(dirname(__FILE__) . '/includes/helpers.php');
require_once(dirname(__FILE__) . '/includes/class-itn-encryption.php');
require_once(dirname(__FILE__) . '/includes/class-itn-backup.php');
require_once(dirname(__FILE__) . '/includes/class-itn-schedule.php');
require_once(dirname(__FILE__) . '/includes/class-itn-installer-generator.php');

// Lade Einstellungen (shared with WordPress)
// Note: This function must match itn_settings_defaults() in the main plugin file
// to ensure consistent default values between web and CLI modes
function itn_cli_settings_defaults() {
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
        'backup_dir' => WP_CONTENT_DIR . '/itn-sicherung-backups',
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

// Handle cron mode - generate Run-ID
if ($cron_mode) {
    $timestamp = current_time('timestamp');
    $siteHost = preg_replace('/[^a-z0-9_-]/i', '_', parse_url(home_url(), PHP_URL_HOST));
    $run_id = 'backup_' . date('Ymd_His', $timestamp) . '_' . $siteHost;
    error_log('ITN CLI Runner: Cron-Modus - generierte Run-ID: ' . $run_id);
}

if (!$run_id) {
    error_log('ITN CLI Runner: Keine Run-ID übergeben und kein --cron Modus');
    exit(1);
}

error_log('ITN CLI Runner gestartet mit Run-ID: ' . $run_id);

// Starte Backup
$opts = array_merge(itn_cli_settings_defaults(), get_option('itn_settings', []));

try {
    $backup = new ITN_Backup($opts);
    error_log('ITN CLI Runner: Starte Backup->run()...');
    $result = $backup->run($run_id);
    
    error_log('ITN CLI Runner: Backup fertig - ' . ($result['success'] ? 'SUCCESS' : 'FAILED'));
    error_log('ITN CLI Runner: Message: ' . ($result['message'] ?? 'keine Nachricht'));
    
    // Aufräumen
    delete_option('itn_backup_running');
    
    exit($result['success'] ? 0 : 1);
} catch (Exception $e) {
    error_log('ITN CLI Runner: EXCEPTION - ' . $e->getMessage());
    delete_option('itn_backup_running');
    exit(1);
}