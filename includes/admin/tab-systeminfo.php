<?php
if (!defined('ABSPATH')) exit;

// Get system information
$wp_version = get_bloginfo('version');
$site_url = get_option('siteurl');
$home_url = get_option('home');
$is_multisite = is_multisite();

$php_version = PHP_VERSION;
$memory_limit = ini_get('memory_limit');
$max_execution_time = ini_get('max_execution_time');
$max_upload_size = ini_get('upload_max_filesize');
$post_max_size = ini_get('post_max_size');

// OpenSSL
$openssl_available = function_exists('openssl_encrypt');
$openssl_version = $openssl_available ? OPENSSL_VERSION_TEXT : 'N/A';
$aes_256_cbc_available = $openssl_available && in_array('aes-256-cbc', openssl_get_cipher_methods());
$aes_256_gcm_available = $openssl_available && in_array('aes-256-gcm', openssl_get_cipher_methods());

// ZipArchive
$ziparchive_available = class_exists('ZipArchive');
$zip_aes_support = false;
if ($ziparchive_available) {
    $zip = new ZipArchive();
    $zip_aes_support = method_exists($zip, 'setEncryptionName') || method_exists($zip, 'setEncryptionIndex');
}

// Backup directory
$opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
$backup_dir = $opts['backup_dir'] ?? ITN_BACKUP_DIR;
$backup_dir_exists = is_dir($backup_dir);
$backup_dir_writable = $backup_dir_exists && is_writable($backup_dir);
$backup_dir_size = 0;
$free_space = 0;

if ($backup_dir_exists) {
    $free_space = @disk_free_space($backup_dir);
    
    // Calculate backup directory size
    $files = glob($backup_dir . '/*');
    if ($files) {
        foreach ($files as $file) {
            if (is_file($file)) {
                $backup_dir_size += filesize($file);
            }
        }
    }
}

// Cron information
$next_scheduled = wp_next_scheduled('itn/run_backup_cron');
$disable_wp_cron = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
$last_cron_run = get_option('itn_last_cron_run', 0);
$last_cron_status = get_option('itn_last_cron_status', 'never');
$last_cron_message = get_option('itn_last_cron_message', 'Noch kein Cron ausgeführt');
$last_cron_error = get_option('itn_last_cron_error', '');

// Check if backup is currently running
$running_locks = glob($backup_dir . '/.itn_backup_lock_*');
$is_running = !empty($running_locks);

function format_bytes($bytes, $precision = 2) {
    if ($bytes <= 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $base = log($bytes, 1024);
    return round(pow(1024, $base - floor($base)), $precision) . ' ' . $units[floor($base)];
}

?>
<div class="itn-systeminfo-tab">
    <div class="itn-section">
        <h2><?php _e('Systeminfos', 'itn-sicherung'); ?></h2>
        
        <!-- WordPress Information -->
        <h3><?php _e('WordPress', 'itn-sicherung'); ?></h3>
        <table class="widefat">
            <tbody>
                <tr>
                    <td style="width: 30%;"><strong><?php _e('Version', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($wp_version); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('Site URL', 'itn-sicherung'); ?></strong></td>
                    <td><code><?php echo esc_html($site_url); ?></code></td>
                </tr>
                <tr>
                    <td><strong><?php _e('Home URL', 'itn-sicherung'); ?></strong></td>
                    <td><code><?php echo esc_html($home_url); ?></code></td>
                </tr>
                <tr>
                    <td><strong><?php _e('Multisite', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($is_multisite): ?>
                            <span style="color: #46b450;">✓ <?php _e('Ja', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #999;">✗ <?php _e('Nein', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>
        
        <!-- PHP Information -->
        <h3><?php _e('PHP', 'itn-sicherung'); ?></h3>
        <table class="widefat">
            <tbody>
                <tr>
                    <td style="width: 30%;"><strong><?php _e('Version', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($php_version); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('memory_limit', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($memory_limit); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('max_execution_time', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($max_execution_time); ?> <?php _e('Sekunden', 'itn-sicherung'); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('upload_max_filesize', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($max_upload_size); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('post_max_size', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($post_max_size); ?></td>
                </tr>
            </tbody>
        </table>
        
        <!-- OpenSSL Information -->
        <h3><?php _e('OpenSSL / Verschlüsselung', 'itn-sicherung'); ?></h3>
        <table class="widefat">
            <tbody>
                <tr>
                    <td style="width: 30%;"><strong><?php _e('OpenSSL verfügbar', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($openssl_available): ?>
                            <span style="color: #46b450;">✓ <?php _e('Ja', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #dc3232;">✗ <?php _e('Nein', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('OpenSSL Version', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($openssl_version); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('AES-256-CBC', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($aes_256_cbc_available): ?>
                            <span style="color: #46b450;">✓ <?php _e('Unterstützt', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #dc3232;">✗ <?php _e('Nicht verfügbar', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('AES-256-GCM', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($aes_256_gcm_available): ?>
                            <span style="color: #46b450;">✓ <?php _e('Unterstützt', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #dc3232;">✗ <?php _e('Nicht verfügbar', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>
        
        <!-- ZipArchive Information -->
        <h3><?php _e('ZipArchive', 'itn-sicherung'); ?></h3>
        <table class="widefat">
            <tbody>
                <tr>
                    <td style="width: 30%;"><strong><?php _e('ZipArchive verfügbar', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($ziparchive_available): ?>
                            <span style="color: #46b450;">✓ <?php _e('Ja', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #dc3232;">✗ <?php _e('Nein', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('AES Encryption Support', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($zip_aes_support): ?>
                            <span style="color: #46b450;">✓ <?php _e('Ja', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #999;">✗ <?php _e('Nein', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>
        
        <!-- Backup Directory Information -->
        <h3><?php _e('Backup-Verzeichnis', 'itn-sicherung'); ?></h3>
        <table class="widefat">
            <tbody>
                <tr>
                    <td style="width: 30%;"><strong><?php _e('Pfad', 'itn-sicherung'); ?></strong></td>
                    <td><code><?php echo esc_html($backup_dir); ?></code></td>
                </tr>
                <tr>
                    <td><strong><?php _e('Existiert', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($backup_dir_exists): ?>
                            <span style="color: #46b450;">✓ <?php _e('Ja', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #dc3232;">✗ <?php _e('Nein', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('Beschreibbar', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($backup_dir_writable): ?>
                            <span style="color: #46b450;">✓ <?php _e('Ja', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #dc3232;">✗ <?php _e('Nein', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('Verwendeter Speicherplatz', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo format_bytes($backup_dir_size); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('Freier Speicherplatz', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($free_space !== false && $free_space > 0): ?>
                            <?php echo format_bytes($free_space); ?>
                            <?php if ($free_space < 1073741824): // < 1GB ?>
                                <span style="color: #dc3232;">(<?php _e('Niedrig', 'itn-sicherung'); ?>)</span>
                            <?php endif; ?>
                        <?php else: ?>
                            <span style="color: #999;">N/A</span>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>
        
        <!-- Cron Diagnosis -->
        <h3><?php _e('Cron / Zeitgesteuerte Backups', 'itn-sicherung'); ?></h3>
        
        <?php if ($disable_wp_cron): ?>
            <div class="notice notice-warning inline">
                <p><strong>DISABLE_WP_CRON ist aktiviert.</strong> WordPress-Cron ist deaktiviert. Stellen Sie sicher, dass ein System-Cron für wp-cron.php konfiguriert ist.</p>
            </div>
        <?php endif; ?>
        
        <table class="widefat">
            <tbody>
                <tr>
                    <td style="width: 30%;"><strong><?php _e('DISABLE_WP_CRON', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($disable_wp_cron): ?>
                            <span style="color: #dc3232;"><?php _e('Ja (deaktiviert)', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #46b450;"><?php _e('Nein (aktiv)', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('Nächster geplanter Backup-Cron', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($next_scheduled): ?>
                            <span style="color: #46b450;">
                                <?php echo date_i18n('Y-m-d H:i:s', $next_scheduled); ?>
                                (<?php echo human_time_diff($next_scheduled, current_time('timestamp')); ?> <?php echo $next_scheduled > current_time('timestamp') ? __('verbleibend', 'itn-sicherung') : __('überfällig', 'itn-sicherung'); ?>)
                            </span>
                        <?php else: ?>
                            <span style="color: #dc3232;"><?php _e('Nicht geplant', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('Letzter Cron-Lauf', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($last_cron_run > 0): ?>
                            <?php echo date_i18n('Y-m-d H:i:s', $last_cron_run); ?>
                            (<?php echo human_time_diff($last_cron_run, current_time('timestamp')); ?> <?php _e('her', 'itn-sicherung'); ?>)
                        <?php else: ?>
                            <span style="color: #999;"><?php _e('Noch nicht ausgeführt', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('Status letzter Cron', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php
                        $status_color = '#999';
                        if ($last_cron_status === 'success') $status_color = '#46b450';
                        elseif ($last_cron_status === 'failed') $status_color = '#dc3232';
                        elseif ($last_cron_status === 'running') $status_color = '#ffb900';
                        ?>
                        <span style="color: <?php echo $status_color; ?>;">
                            <?php echo esc_html(ucfirst($last_cron_status)); ?>
                        </span>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('Meldung', 'itn-sicherung'); ?></strong></td>
                    <td><?php echo esc_html($last_cron_message); ?></td>
                </tr>
                <?php if ($last_cron_error): ?>
                <tr>
                    <td><strong style="color: #dc3232;"><?php _e('Fehler-Details', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <pre style="background: #f8f8f8; padding: 10px; border: 1px solid #ddd; overflow-x: auto; max-height: 200px;"><?php echo esc_html($last_cron_error); ?></pre>
                    </td>
                </tr>
                <?php endif; ?>
                <tr>
                    <td><strong><?php _e('Backup läuft gerade', 'itn-sicherung'); ?></strong></td>
                    <td>
                        <?php if ($is_running): ?>
                            <span style="color: #ffb900;">⚠ <?php _e('Ja', 'itn-sicherung'); ?></span>
                        <?php else: ?>
                            <span style="color: #46b450;">✓ <?php _e('Nein', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>
        
        <!-- Test Cron Button -->
        <p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display: inline;">
                <?php wp_nonce_field('itn_test_cron'); ?>
                <input type="hidden" name="action" value="itn_test_cron">
                <button type="submit" class="button button-primary">
                    <span class="dashicons dashicons-update"></span> <?php _e('Cron-Test jetzt ausführen', 'itn-sicherung'); ?>
                </button>
            </form>
            <span class="description"><?php _e('Führt den Cron-Callback einmal manuell aus und speichert das Ergebnis.', 'itn-sicherung'); ?></span>
        </p>
    </div>
</div>
