<?php
/**
 * ITN Sicherung CLI Backup Runner
 * Wird direkt über PHP-CLI aufgerufen, umgeht alle Webserver-Timeouts
 */

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

// Hole Run-ID aus Command-Line-Argumenten
$run_id = isset($argv[1]) ? $argv[1] : null;

if (!$run_id) {
    error_log('ITN CLI Runner: Keine Run-ID übergeben');
    exit(1);
}

error_log('ITN CLI Runner gestartet mit Run-ID: ' . $run_id);

// Lade Plugin-Klassen
require_once(dirname(__FILE__) . '/includes/helpers.php');
require_once(dirname(__FILE__) . '/includes/class-itn-encryption.php');
require_once(dirname(__FILE__) . '/includes/class-itn-backup.php');
require_once(dirname(__FILE__) . '/includes/class-itn-schedule.php');
require_once(dirname(__FILE__) . '/includes/class-itn-installer-generator.php');

// Lade Einstellungen
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

// Starte Backup
$opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
$backup = new ITN_Backup($opts);

error_log('ITN CLI Runner: Starte Backup->run()...');
$result = $backup->run($run_id);

error_log('ITN CLI Runner: Backup fertig - ' . ($result['success'] ? 'SUCCESS' : 'FAILED'));
error_log('ITN CLI Runner: Message: ' . ($result['message'] ?? 'keine Nachricht'));

// Aufräumen
delete_option('itn_backup_running');

exit($result['success'] ? 0 : 1);