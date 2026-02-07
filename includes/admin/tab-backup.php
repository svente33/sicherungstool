<?php
if (!defined('ABSPATH')) exit;

$issues = itn_collect_environment_issues();
?>
<div class="itn-backup-tab">
    <div class="itn-section">
        <h2><?php _e('Neues Backup erstellen', 'itn-sicherung'); ?></h2>
        <p class="description"><?php _e('Erstellt ein ZIP mit Dateien und Datenbank. Optional wird in die konfigurierten Cloud-Ziele hochgeladen (inkl. Installer-Datei).', 'itn-sicherung'); ?></p>

        <div id="itn-progress-wrap" class="itn-progress" style="display:none;">
            <div class="itn-progress-bar"><span class="itn-progress-fill" style="width:0%"></span></div>
            <div class="itn-progress-text"><?php _e('Warte auf Start...', 'itn-sicherung'); ?></div>
        </div>

        <p>
            <button id="itn-start-backup" class="button button-primary button-hero" <?php disabled(!empty($issues['errors'])); ?>>
                <span class="dashicons dashicons-download"></span> <?php _e('Backup starten', 'itn-sicherung'); ?>
            </button>
        </p>
    </div>

    <?php if (!empty($backups)) : ?>
        <div class="itn-section">
            <h2><?php _e('Vorhandene Backups', 'itn-sicherung'); ?></h2>
            <table class="widefat striped itn-backup-table">
                <thead>
                    <tr>
                        <th><?php _e('Dateiname', 'itn-sicherung'); ?></th>
                        <th><?php _e('Größe', 'itn-sicherung'); ?></th>
                        <th><?php _e('Verschlüsselung', 'itn-sicherung'); ?></th>
                        <th><?php _e('Datum', 'itn-sicherung'); ?></th>
                        <th><?php _e('Aktionen', 'itn-sicherung'); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($backups as $file):
                    $size = ITN_Helpers::format_bytes(filesize($file));
                    $date = ITN_Helpers::format_datetime(filemtime($file));
                    $zip_basename = basename($file);
                    $is_enc = str_ends_with($file, '.enc');
                    
                    // For .enc files, try to read encryption info from .report.json
                    $encryption_info = '';
                    if ($is_enc) {
                        $report_file = str_replace('.zip.enc', '.report.json', $file);
                        if (file_exists($report_file)) {
                            $report_data = json_decode(file_get_contents($report_file), true);
                            if ($report_data && isset($report_data['encryption_method'])) {
                                if ($report_data['encryption_method'] === 'php-openssl-aes-256-gcm') {
                                    $encryption_info = '🔒 AES-256-GCM Container';
                                } else {
                                    $encryption_info = '🔒 Verschlüsselt';
                                }
                            } else {
                                $encryption_info = '🔒 Verschlüsselt (.enc)';
                            }
                        } else {
                            $encryption_info = '🔒 Verschlüsselt (.enc)';
                        }
                    } else {
                        // For .zip files, check if they have ZipArchive encryption
                        // This is harder to detect, so we assume unencrypted unless we have metadata
                        $encryption_info = '—';
                    }
                    
                    $installer_name = 'installer-' . basename($file, '.zip') . '.php';
                    if ($is_enc) {
                        $installer_name = 'installer-' . basename($file, '.zip.enc') . '.php';
                    }
                    $installer_path = $backup_dir . '/' . $installer_name;
                    if (!file_exists($installer_path) && class_exists('ITN_Installer_Generator')) {
                        @ITN_Installer_Generator::write_installer_for_backup($file, $installer_path);
                    }
                    $installer_exists = file_exists($installer_path);
                    $dl_zip = wp_nonce_url(admin_url('admin-post.php?action=itn_download_file&file=' . rawurlencode($file)), 'itn_download_file');
                    $dl_installer = $installer_exists ? wp_nonce_url(admin_url('admin-post.php?action=itn_download_file&file=' . rawurlencode($installer_path)), 'itn_download_file') : '';
                    $del_backup = wp_nonce_url(admin_url('admin-post.php?action=itn_delete_backup&file=' . rawurlencode($file)), 'itn_delete_backup');
                ?>
                    <tr>
                        <td><strong><?php echo esc_html($zip_basename); ?></strong></td>
                        <td><?php echo esc_html($size); ?></td>
                        <td><?php echo esc_html($encryption_info); ?></td>
                        <td><?php echo esc_html($date); ?></td>
                        <td class="itn-actions">
                            <a class="button button-small" href="<?php echo esc_url($dl_zip); ?>">
                                <span class="dashicons dashicons-download"></span> <?php _e('ZIP', 'itn-sicherung'); ?>
                            </a>
                            <?php if ($installer_exists): ?>
                                <a class="button button-small" href="<?php echo esc_url($dl_installer); ?>">
                                    <span class="dashicons dashicons-media-code"></span> <?php _e('Installer', 'itn-sicherung'); ?>
                                </a>
                            <?php endif; ?>
                            <a class="button button-small button-link-delete" href="<?php echo esc_url($del_backup); ?>" onclick="return confirm('<?php echo esc_js(__('Gesamtes Backup löschen? ZIP, Installer und temporäre Dateien werden entfernt.', 'itn-sicherung')); ?>');">
                                <span class="dashicons dashicons-trash"></span> <?php _e('Löschen', 'itn-sicherung'); ?>
                            </a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <div class="itn-section">
            <p class="description"><?php _e('Noch keine Backups vorhanden.', 'itn-sicherung'); ?></p>
        </div>
    <?php endif; ?>
</div>