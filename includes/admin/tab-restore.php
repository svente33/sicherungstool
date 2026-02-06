<?php
if (!defined('ABSPATH')) exit;

$issues = itn_collect_environment_issues();
?>
<div class="itn-restore-tab">
    <div class="itn-section">
        <h2><?php _e('Backup wiederherstellen', 'itn-sicherung'); ?></h2>

        <?php if (empty($backups)): ?>
            <p class="description"><?php _e('Keine Backups zum Wiederherstellen vorhanden.', 'itn-sicherung'); ?></p>
        <?php else: ?>
            <div class="notice notice-warning inline">
                <p><strong><?php _e('Achtung:', 'itn-sicherung'); ?></strong> <?php _e('Die Wiederherstellung überschreibt Dateien und importiert die Datenbank aus dem Backup. Danach werden Domain-/Pfadangaben automatisch angepasst und WP-Admin-URL-Konstanten aktualisiert.', 'itn-sicherung'); ?></p>
            </div>

            <div id="itn-restore-progress-wrap" class="itn-progress" style="display:none;">
                <div class="itn-progress-bar"><span class="itn-progress-fill" style="width:0%"></span></div>
                <div class="itn-progress-text"><?php _e('Warte auf Start...', 'itn-sicherung'); ?></div>
            </div>

            <form id="itn-restore-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <?php wp_nonce_field('itn_restore_backup'); ?>
                <input type="hidden" name="action" value="itn_restore_backup">
                <table class="form-table">
                    <tr>
                        <th><label for="backup_file"><?php _e('Backup-Datei:', 'itn-sicherung'); ?></label></th>
                        <td>
                            <select id="backup_file" name="backup_file" class="regular-text">
                                <?php foreach ($backups as $file): ?>
                                    <option value="<?php echo esc_attr($file); ?>"><?php echo esc_html(basename($file)); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <p>
                    <button id="itn-start-restore" class="button button-primary button-hero" type="button" <?php disabled(!empty($issues['errors'])); ?>>
                        <span class="dashicons dashicons-upload"></span> <?php _e('Wiederherstellung starten (mit Fortschritt)', 'itn-sicherung'); ?>
                    </button>
                    <button class="button button-secondary" type="submit" <?php disabled(!empty($issues['errors'])); ?>>
                        <?php _e('Wiederherstellen (klassisch)', 'itn-sicherung'); ?>
                    </button>
                </p>
            </form>
        <?php endif; ?>
    </div>
</div>