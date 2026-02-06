<?php
if (!defined('ABSPATH')) exit;

$last = get_option('itn_last_backup_result');
$report = get_option('itn_last_backup_report');
$issues = itn_collect_environment_issues();
?>
<div class="itn-dashboard">
    <div class="itn-card-grid">
        <div class="itn-card itn-card-primary">
            <div class="itn-card-icon"><span class="dashicons dashicons-backup"></span></div>
            <div class="itn-card-content">
                <h3><?php _e('Backups', 'itn-sicherung'); ?></h3>
                <p class="itn-card-stat"><?php echo count($backups); ?></p>
                <p class="itn-card-desc"><?php _e('Gespeicherte Sicherungen', 'itn-sicherung'); ?></p>
            </div>
        </div>

        <div class="itn-card itn-card-success">
            <div class="itn-card-icon"><span class="dashicons dashicons-clock"></span></div>
            <div class="itn-card-content">
                <h3><?php _e('Letztes Backup', 'itn-sicherung'); ?></h3>
                <p class="itn-card-stat"><?php echo !empty($last['time']) ? ITN_Helpers::format_datetime($last['time']) : '—'; ?></p>
                <p class="itn-card-desc"><?php echo !empty($last['success']) ? __('Erfolgreich', 'itn-sicherung') : __('Fehlgeschlagen', 'itn-sicherung'); ?></p>
            </div>
        </div>

        <div class="itn-card itn-card-info">
            <div class="itn-card-icon"><span class="dashicons dashicons-database"></span></div>
            <div class="itn-card-content">
                <h3><?php _e('Speicher', 'itn-sicherung'); ?></h3>
                <p class="itn-card-stat"><?php
                    $total = 0;
                    foreach ($backups as $b) $total += @filesize($b);
                    echo ITN_Helpers::format_bytes($total);
                ?></p>
                <p class="itn-card-desc"><?php _e('Belegter Speicherplatz', 'itn-sicherung'); ?></p>
            </div>
        </div>

        <div class="itn-card itn-card-warning">
            <div class="itn-card-icon"><span class="dashicons dashicons-admin-generic"></span></div>
            <div class="itn-card-content">
                <h3><?php _e('Status', 'itn-sicherung'); ?></h3>
                <p class="itn-card-stat"><?php echo empty($issues['errors']) ? __('OK', 'itn-sicherung') : count($issues['errors']); ?></p>
                <p class="itn-card-desc"><?php echo empty($issues['errors']) ? __('Keine Fehler', 'itn-sicherung') : __('Fehler erkannt', 'itn-sicherung'); ?></p>
            </div>
        </div>
    </div>

    <?php
    // Zeige geplante Backups
    if (class_exists('ITN_Schedule')) {
        $schedule_info = ITN_Schedule::get_scheduled_info();
    ?>
        <div class="itn-section">
            <h2><?php _e('Geplante Backups', 'itn-sicherung'); ?></h2>
            <div class="itn-report-box">
                <table class="widefat">
                    <tbody>
                        <tr>
                            <th style="width: 200px;"><?php _e('Status', 'itn-sicherung'); ?></th>
                            <td>
                                <?php if ($schedule_info['scheduled']): ?>
                                    <span style="color: #00a32a; font-weight: bold;">✅ Aktiv</span>
                                <?php else: ?>
                                    <span style="color: #d63638; font-weight: bold;">❌ Nicht geplant</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php if ($schedule_info['scheduled']): ?>
                            <tr>
                                <th><?php _e('Nächster Lauf', 'itn-sicherung'); ?></th>
                                <td><strong><?php echo esc_html($schedule_info['next_run']); ?></strong></td>
                            </tr>
                            <tr>
                                <th><?php _e('Zeit bis zum Backup', 'itn-sicherung'); ?></th>
                                <td><?php echo esc_html($schedule_info['time_until']); ?></td>
                            </tr>
                            <tr>
                                <th><?php _e('Frequenz', 'itn-sicherung'); ?></th>
                                <td><?php echo esc_html(ucfirst($schedule_info['frequency'])); ?></td>
                            </tr>
                        <?php else: ?>
                            <tr>
                                <th><?php _e('Hinweis', 'itn-sicherung'); ?></th>
                                <td>
                                    <?php echo esc_html($schedule_info['message']); ?>
                                    <br><br>
                                    <a href="<?php echo esc_url(admin_url('admin.php?page=itn-sicherung&tab=settings')); ?>" class="button button-primary">
                                        <span class="dashicons dashicons-admin-settings"></span> <?php _e('Zeitplan konfigurieren', 'itn-sicherung'); ?>
                                    </a>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php } ?>

    <?php if (!empty($last)): ?>
        <div class="itn-section">
            <h2><?php _e('Letzter Backup-Status', 'itn-sicherung'); ?></h2>
            <div class="notice <?php echo !empty($last['success']) ? 'notice-success' : 'notice-error'; ?> inline">
                <p><strong><?php echo esc_html($last['message'] ?? ''); ?></strong></p>
                <?php if (!empty($last['zip'])): ?>
                    <p><?php _e('Datei:', 'itn-sicherung'); ?> <code><?php echo esc_html(basename($last['zip'])); ?></code></p>
                <?php endif; ?>
                <p class="description"><?php echo esc_html(!empty($last['time']) ? ('Zeit: ' . date('Y-m-d H:i:s', intval($last['time']))) : ''); ?></p>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($report)): ?>
        <div class="itn-section">
            <h2><?php _e('Detaillierter Backupbericht', 'itn-sicherung'); ?></h2>
            <div class="itn-report-box">
                <table class="widefat striped">
                    <tbody>
                        <tr>
                            <th><?php _e('Status', 'itn-sicherung'); ?></th>
                            <td><span class="itn-badge itn-badge-<?php echo !empty($report['success']) ? 'success' : 'error'; ?>"><?php echo !empty($report['success']) ? __('Erfolgreich', 'itn-sicherung') : __('Fehlgeschlagen', 'itn-sicherung'); ?></span></td>
                        </tr>
                        <?php if (!empty($report['zip'])): ?>
                        <tr>
                            <th><?php _e('ZIP-Datei', 'itn-sicherung'); ?></th>
                            <td><code><?php echo esc_html(basename($report['zip'])); ?></code> (<?php echo esc_html(ITN_Helpers::format_bytes($report['zip_size'] ?? 0)); ?>)</td>
                        </tr>
                        <?php endif; ?>
                        <tr>
                            <th><?php _e('Verschlüsselung', 'itn-sicherung'); ?></th>
                            <td><?php echo !empty($report['encrypted']) ? '<span class="dashicons dashicons-lock"></span> ' . __('Ja (AES-256)', 'itn-sicherung') : '<span class="dashicons dashicons-unlock"></span> ' . __('Nein', 'itn-sicherung'); ?></td>
                        </tr>
                        <?php if (is_array(($report['cloud'] ?? null))): ?>
                        <tr>
                            <th><?php _e('Cloud-Uploads', 'itn-sicherung'); ?></th>
                            <td>
                                <ul class="itn-cloud-status">
                                    <li><strong>S3:</strong> <?php
                                        if (!isset($report['cloud']['s3'])) {
                                            echo '—';
                                        } else {
                                            $s3 = $report['cloud']['s3'];
                                            if (is_array($s3) && isset($s3['zip'])) {
                                                echo ($s3['zip']['success'] ?? false) ? '<span class="dashicons dashicons-yes-alt"></span> ZIP OK' : '<span class="dashicons dashicons-dismiss"></span> ZIP Fehler';
                                                if (isset($s3['installer'])) {
                                                    echo ($s3['installer']['success'] ?? false) ? ', <span class="dashicons dashicons-yes-alt"></span> Installer OK' : ', <span class="dashicons dashicons-dismiss"></span> Installer Fehler';
                                                }
                                            } else {
                                                echo ($s3['success'] ?? false) ? '<span class="dashicons dashicons-yes-alt"></span> OK' : '<span class="dashicons dashicons-dismiss"></span> Fehler';
                                            }
                                        }
                                    ?></li>
                                    <li><strong>Azure:</strong> <?php
                                        if (!isset($report['cloud']['azure'])) {
                                            echo '—';
                                        } else {
                                            $az = $report['cloud']['azure'];
                                            if (is_array($az) && isset($az['zip'])) {
                                                echo ($az['zip']['success'] ?? false) ? '<span class="dashicons dashicons-yes-alt"></span> ZIP OK' : '<span class="dashicons dashicons-dismiss"></span> ZIP Fehler';
                                                if (isset($az['installer'])) {
                                                    echo ($az['installer']['success'] ?? false) ? ', <span class="dashicons dashicons-yes-alt"></span> Installer OK' : ', <span class="dashicons dashicons-dismiss"></span> Installer Fehler';
                                                }
                                            } else {
                                                echo ($az['success'] ?? false) ? '<span class="dashicons dashicons-yes-alt"></span> OK' : '<span class="dashicons dashicons-dismiss"></span> Fehler';
                                            }
                                        }
                                    ?></li>
                                    <li><strong>OneDrive:</strong> <?php
                                        if (!isset($report['cloud']['onedrive'])) {
                                            echo '—';
                                        } else {
                                            $od = $report['cloud']['onedrive'];
                                            if (is_array($od) && isset($od['zip'])) {
                                                echo ($od['zip']['success'] ?? false) ? '<span class="dashicons dashicons-yes-alt"></span> ZIP OK' : '<span class="dashicons dashicons-dismiss"></span> ZIP Fehler';
                                                if (isset($od['installer'])) {
                                                    echo ($od['installer']['success'] ?? false) ? ', <span class="dashicons dashicons-yes-alt"></span> Installer OK' : ', <span class="dashicons dashicons-dismiss"></span> Installer Fehler';
                                                }
                                            } else {
                                                echo ($od['success'] ?? false) ? '<span class="dashicons dashicons-yes-alt"></span> OK' : '<span class="dashicons dashicons-dismiss"></span> Fehler';
                                            }
                                        }
                                    ?></li>
                                </ul>
                            </td>
                        </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>

    <div class="itn-section">
        <h2><?php _e('Schnellaktionen', 'itn-sicherung'); ?></h2>
        <p>
            <a href="<?php echo esc_url(admin_url('admin.php?page=itn-sicherung&tab=backup')); ?>" class="button button-primary button-hero">
                <span class="dashicons dashicons-download"></span> <?php _e('Backup erstellen', 'itn-sicherung'); ?>
            </a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=itn-sicherung&tab=restore')); ?>" class="button button-secondary button-hero">
                <span class="dashicons dashicons-upload"></span> <?php _e('Backup wiederherstellen', 'itn-sicherung'); ?>
            </a>
        </p>
    </div>
</div>