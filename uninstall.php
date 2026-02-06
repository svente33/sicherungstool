<?php
/**
 * Wird automatisch ausgeführt, wenn das Plugin über WP-Admin gelöscht wird.
 * Entfernt alle Plugin-Optionen, Cron-Jobs, Transients und das Backup-Verzeichnis.
 */
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Optionen/Settings laden (für Pfad)
$opts = get_option('itn_settings', []);
$backup_dir = '';
if (is_array($opts)) {
    $backup_dir = isset($opts['backup_dir']) ? (string)$opts['backup_dir'] : '';
}
if (!$backup_dir) {
    if (defined('WP_CONTENT_DIR')) {
        $backup_dir = WP_CONTENT_DIR . '/itn-sicherung-backups';
    }
}

// Cron aufräumen
$hook = 'itn/run_backup_cron';
if (function_exists('wp_next_scheduled')) {
    $next = wp_next_scheduled($hook);
    while ($next) {
        wp_unschedule_event($next, $hook);
        $next = wp_next_scheduled($hook);
    }
}
delete_option('itn_monthly_next_ts');

// Transients löschen (itn_progress_*)
if (isset($wpdb) && $wpdb instanceof wpdb) {
    $like1 = $wpdb->esc_like('_transient_itn_progress_') . '%';
    $like2 = $wpdb->esc_like('_transient_timeout_itn_progress_') . '%';
    $table = $wpdb->options;
    $wpdb->query($wpdb->prepare("DELETE FROM `$table` WHERE option_name LIKE %s OR option_name LIKE %s", $like1, $like2));
}

// Plugin-Optionen löschen
$opt_keys = [
    'itn_settings',
    'itn_last_activation_issues',
    'itn_last_backup_result',
    'itn_last_backup_report',
    'itn_onedrive_device',
    'itn_onedrive_tokens',
];
foreach ($opt_keys as $k) {
    delete_option($k);
}

// Backup-Verzeichnis löschen (nur wenn innerhalb WP_CONTENT_DIR)
function itn_uninstall_rrmdir($dir) {
    if (!is_dir($dir)) return true;
    $items = @scandir($dir);
    if (!$items) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            if (!itn_uninstall_rrmdir($path)) return false;
        } else {
            @unlink($path);
        }
    }
    return @rmdir($dir);
}

if ($backup_dir) {
    $real_backup = realpath($backup_dir);
    $real_content= realpath(defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content');
    if ($real_backup && $real_content && strpos($real_backup, $real_content) === 0) {
        itn_uninstall_rrmdir($backup_dir);
    }
}