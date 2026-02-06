<?php
if (!defined('ABSPATH')) exit;

$opts = array_merge(itn_settings_defaults(), get_option('itn_settings', []));
?>

<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
    <?php wp_nonce_field('itn_save_settings'); ?>
    <input type="hidden" name="action" value="itn_save_settings">

    <div class="itn-settings-container">
        
        <!-- Allgemeine Einstellungen -->
        <div class="itn-section">
            <h2><?php _e('Allgemeine Einstellungen', 'itn-sicherung'); ?></h2>
            <table class="form-table">
                <tr>
                    <th><label><?php _e('Backup-Verzeichnis', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="backup_dir" value="<?php echo esc_attr($opts['backup_dir']); ?>" class="regular-text" />
                        <p class="description"><?php _e('Absoluter Pfad zum Backup-Verzeichnis', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Retention (Aufbewahrung)', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="number" name="retention" value="<?php echo esc_attr($opts['retention']); ?>" min="1" max="100" />
                        <p class="description"><?php _e('Anzahl der aufzubewahrenden Backups (ältere werden automatisch gelöscht)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Ausschlüsse', 'itn-sicherung'); ?></label></th>
                    <td>
                        <textarea name="exclude_paths" rows="6" class="large-text"><?php
                            if (!empty($opts['exclude_paths'])) {
                                echo esc_textarea(implode("\n", $opts['exclude_paths']));
                            }
                        ?></textarea>
                        <p class="description">
                            <?php _e('Pfade die vom Backup ausgeschlossen werden sollen (ein Pfad pro Zeile, relativ zu WordPress-Root)', 'itn-sicherung'); ?><br>
                            <?php _e('Beispiel: wp-content/cache', 'itn-sicherung'); ?>
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Automatische Backups (Zeitplan) -->
        <div class="itn-section">
            <h2><?php _e('Automatische Backups (Zeitplan)', 'itn-sicherung'); ?></h2>
            
            <?php
            // Prüfe ob WP-Cron deaktiviert ist
            $disable_wp_cron = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
            $cli_runner_path = WP_CONTENT_DIR . '/plugins/' . basename(dirname(ITN_PLUGIN_FILE)) . '/cli-backup-runner.php';
            $cli_runner_exists = file_exists($cli_runner_path);
            
            if ($disable_wp_cron) {
                echo '<div class="notice notice-warning inline"><p><strong>⚠️ WP-Cron ist deaktiviert (DISABLE_WP_CRON)!</strong><br>';
                echo 'Für automatische Backups muss ein Server-Cron eingerichtet werden.<br><br>';
                
                if ($cli_runner_exists) {
                    echo '<strong>Empfohlen: CLI-Runner (umgeht Webserver-Timeouts)</strong><br>';
                    echo 'Füge in crontab hinzu:<br>';
                    echo '<code>0 2 * * * cd ' . esc_html(ABSPATH) . ' && /usr/bin/php ' . esc_html($cli_runner_path) . ' backup_' . date('Ymd_His') . ' >> /var/log/itn-backup.log 2>&1</code><br><br>';
                    echo 'Alternative: WordPress-Cron über Web triggern:<br>';
                } else {
                    echo 'Alternative: WordPress-Cron über Web triggern:<br>';
                }
                
                echo '<code>*/15 * * * * wget -q -O - ' . esc_url(site_url('/wp-cron.php?doing_wp_cron')) . ' >/dev/null 2>&1</code>';
                echo '</p></div>';
            } else {
                if ($cli_runner_exists) {
                    echo '<div class="notice notice-info inline"><p><strong>💡 Tipp: CLI-Runner verfügbar</strong><br>';
                    echo 'Für große Websites empfohlen (umgeht Webserver-Timeouts):<br>';
                    echo '<code>0 2 * * * cd ' . esc_html(ABSPATH) . ' && /usr/bin/php ' . esc_html($cli_runner_path) . ' backup_' . date('Ymd_His') . ' >> /var/log/itn-backup.log 2>&1</code>';
                    echo '</p></div>';
                }
            }
            
            // Zeige nächsten geplanten Cron
            $next_cron = wp_next_scheduled('itn/run_backup_cron');
            if ($next_cron) {
                echo '<div class="notice notice-info inline"><p><strong>✅ Nächstes Backup geplant:</strong> ' . date('d.m.Y H:i:s', $next_cron) . ' (' . human_time_diff(time(), $next_cron) . ')</p></div>';
            } else {
                echo '<div class="notice notice-error inline"><p><strong>❌ Kein Backup geplant!</strong> Bitte Einstellungen speichern um Zeitplan zu aktivieren.</p></div>';
            }
            ?>
            
            <table class="form-table">
                <tr>
                    <th><label><?php _e('Frequenz', 'itn-sicherung'); ?></label></th>
                    <td>
                        <select name="schedule_frequency" id="schedule_frequency">
                            <option value="hourly" <?php selected($opts['schedule_frequency'], 'hourly'); ?>><?php _e('Stündlich', 'itn-sicherung'); ?></option>
                            <option value="twicedaily" <?php selected($opts['schedule_frequency'], 'twicedaily'); ?>><?php _e('Zweimal täglich', 'itn-sicherung'); ?></option>
                            <option value="daily" <?php selected($opts['schedule_frequency'], 'daily'); ?>><?php _e('Täglich', 'itn-sicherung'); ?></option>
                            <option value="weekly" <?php selected($opts['schedule_frequency'], 'weekly'); ?>><?php _e('Wöchentlich', 'itn-sicherung'); ?></option>
                            <option value="monthly" <?php selected($opts['schedule_frequency'], 'monthly'); ?>><?php _e('Monatlich', 'itn-sicherung'); ?></option>
                            <option value="custom" <?php selected($opts['schedule_frequency'], 'custom'); ?>><?php _e('Benutzerdefiniert (Intervall)', 'itn-sicherung'); ?></option>
                        </select>
                    </td>
                </tr>
                <tr class="itn-schedule-time">
                    <th><label><?php _e('Uhrzeit', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="time" name="schedule_time" value="<?php echo esc_attr($opts['schedule_time']); ?>" />
                        <p class="description"><?php _e('Uhrzeit für tägliche/wöchentliche/monatliche Backups (Format: HH:MM)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr class="itn-schedule-dow" style="display: none;">
                    <th><label><?php _e('Wochentag', 'itn-sicherung'); ?></label></th>
                    <td>
                        <select name="schedule_dow">
                            <option value="0" <?php selected($opts['schedule_dow'], 0); ?>><?php _e('Sonntag', 'itn-sicherung'); ?></option>
                            <option value="1" <?php selected($opts['schedule_dow'], 1); ?>><?php _e('Montag', 'itn-sicherung'); ?></option>
                            <option value="2" <?php selected($opts['schedule_dow'], 2); ?>><?php _e('Dienstag', 'itn-sicherung'); ?></option>
                            <option value="3" <?php selected($opts['schedule_dow'], 3); ?>><?php _e('Mittwoch', 'itn-sicherung'); ?></option>
                            <option value="4" <?php selected($opts['schedule_dow'], 4); ?>><?php _e('Donnerstag', 'itn-sicherung'); ?></option>
                            <option value="5" <?php selected($opts['schedule_dow'], 5); ?>><?php _e('Freitag', 'itn-sicherung'); ?></option>
                            <option value="6" <?php selected($opts['schedule_dow'], 6); ?>><?php _e('Samstag', 'itn-sicherung'); ?></option>
                        </select>
                        <p class="description"><?php _e('Wochentag für wöchentliche Backups', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr class="itn-schedule-dom" style="display: none;">
                    <th><label><?php _e('Tag des Monats', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="number" name="schedule_dom" value="<?php echo esc_attr($opts['schedule_dom']); ?>" min="1" max="31" />
                        <p class="description"><?php _e('Tag des Monats für monatliche Backups (1-31)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr class="itn-schedule-custom" style="display: none;">
                    <th><label><?php _e('Intervall (Minuten)', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="number" name="custom_interval_minutes" value="<?php echo esc_attr($opts['custom_interval_minutes']); ?>" min="5" max="1440" />
                        <p class="description"><?php _e('Intervall in Minuten (min. 5, max. 1440 = 24 Stunden)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
            </table>
            
            <script>
            jQuery(document).ready(function($){
                function updateScheduleFields() {
                    var freq = $('#schedule_frequency').val();
                    $('.itn-schedule-time').hide();
                    $('.itn-schedule-dow').hide();
                    $('.itn-schedule-dom').hide();
                    $('.itn-schedule-custom').hide();
                    
                    if (freq === 'daily' || freq === 'weekly' || freq === 'monthly') {
                        $('.itn-schedule-time').show();
                    }
                    if (freq === 'weekly') {
                        $('.itn-schedule-dow').show();
                    }
                    if (freq === 'monthly') {
                        $('.itn-schedule-dom').show();
                    }
                    if (freq === 'custom') {
                        $('.itn-schedule-custom').show();
                    }
                }
                
                $('#schedule_frequency').on('change', updateScheduleFields);
                updateScheduleFields();
            });
            </script>
        </div>

        <!-- E-Mail-Benachrichtigungen -->
        <div class="itn-section">
            <h2><?php _e('E-Mail-Benachrichtigungen', 'itn-sicherung'); ?></h2>
            <table class="form-table">
                <tr>
                    <th><label><?php _e('Benachrichtigungen', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="notify_enabled" <?php checked(!empty($opts['notify_enabled'])); ?>>
                            <?php _e('E-Mail-Benachrichtigungen aktivieren', 'itn-sicherung'); ?>
                        </label>
                        <p class="description"><?php _e('Erhalte E-Mails bei erfolgreichen und fehlgeschlagenen Backups', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('E-Mail-Adresse', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="email" name="notify_email" value="<?php echo esc_attr($opts['notify_email'] ?? get_option('admin_email')); ?>" class="regular-text">
                        <p class="description"><?php _e('E-Mail-Adresse für Backup-Benachrichtigungen (Erfolg und Fehler)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- ZIP-Verschlüsselung -->
        <div class="itn-section">
            <h2><?php _e('ZIP-Verschlüsselung', 'itn-sicherung'); ?></h2>
            
            <?php
            // Check encryption capabilities
            $has_ziparchive_encryption = class_exists('ZipArchive') && method_exists(new ZipArchive(), 'setEncryptionName');
            $has_exec = !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))), true) && function_exists('exec');
            $has_shell_exec = !in_array('shell_exec', array_map('trim', explode(',', ini_get('disable_functions'))), true) && function_exists('shell_exec');
            $can_exec = $has_exec || $has_shell_exec;
            
            if (!$has_ziparchive_encryption && !$can_exec) {
                echo '<div class="notice notice-error inline"><p><strong>⚠️ Verschlüsselung nicht verfügbar!</strong><br>';
                echo 'ZipArchive unterstützt keine Verschlüsselung und exec/shell_exec sind deaktiviert.<br>';
                echo 'Verschlüsselung kann nicht funktionieren.</p></div>';
            } elseif (!$has_ziparchive_encryption) {
                echo '<div class="notice notice-warning inline"><p><strong>⚠️ ZipArchive-Verschlüsselung nicht verfügbar</strong><br>';
                echo 'Fallback zu CLI-Tools (7z/zip) wird verwendet. Stelle sicher, dass 7z oder zip installiert ist.</p></div>';
            } else {
                echo '<div class="notice notice-success inline"><p><strong>✅ ZipArchive AES-256 Verschlüsselung verfügbar</strong></p></div>';
            }
            ?>
            
            <table class="form-table">
                <tr>
                    <th><label><?php _e('Verschlüsselung', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="zip_encrypt_enabled" id="zip_encrypt_enabled" <?php checked(!empty($opts['zip_encrypt_enabled'])); ?>>
                            <?php _e('ZIP-Dateien mit AES-256 verschlüsseln', 'itn-sicherung'); ?>
                        </label>
                        <p class="description"><?php _e('Schützt Backups mit einem Passwort (empfohlen für Cloud-Storage)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr class="itn-zip-password-row">
                    <th><label><?php _e('Passwort', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="password" name="zip_encrypt_password" id="zip_encrypt_password" value="<?php echo esc_attr($opts['zip_encrypt_password'] ?? ''); ?>" class="regular-text" placeholder="<?php _e('Passwort für ZIP-Verschlüsselung', 'itn-sicherung'); ?>" minlength="12" />
                        <p class="description">
                            <strong><?php _e('Mindestlänge: 12 Zeichen', 'itn-sicherung'); ?></strong><br>
                            <?php _e('Starkes Passwort empfohlen (Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen)', 'itn-sicherung'); ?><br>
                            <strong><?php _e('WICHTIG: Passwort gut aufbewahren! Ohne Passwort kann das Backup nicht wiederhergestellt werden.', 'itn-sicherung'); ?></strong>
                        </p>
                    </td>
                </tr>
            </table>
            
            <script>
            jQuery(document).ready(function($){
                function toggleZipPassword() {
                    if ($('#zip_encrypt_enabled').is(':checked')) {
                        $('.itn-zip-password-row').show();
                        $('#zip_encrypt_password').prop('required', true);
                    } else {
                        $('.itn-zip-password-row').hide();
                        $('#zip_encrypt_password').prop('required', false);
                    }
                }
                
                $('#zip_encrypt_enabled').on('change', toggleZipPassword);
                toggleZipPassword();
            });
            </script>
        </div>

        <!-- Wiederherstellung -->
        <div class="itn-section">
            <h2><?php _e('Wiederherstellung', 'itn-sicherung'); ?></h2>
            <table class="form-table">
                <tr>
                    <th><label><?php _e('Datenbank', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="restore_drop_db" <?php checked(!empty($opts['restore_drop_db'])); ?>>
                            <?php _e('Datenbank vor Wiederherstellung leeren (DROP ALL TABLES)', 'itn-sicherung'); ?>
                        </label>
                        <p class="description"><?php _e('Empfohlen für saubere Wiederherstellung. Achtung: Alle aktuellen Daten gehen verloren!', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Cloud-Storage: AWS S3 -->
        <div class="itn-section">
            <h2><?php _e('Cloud-Storage: AWS S3', 'itn-sicherung'); ?></h2>
            
            <?php
            $s3_connected = !empty($opts['s3_enabled']) && !empty($opts['s3_access_key']) && !empty($opts['s3_bucket']);
            if ($s3_connected) {
                echo '<div class="notice notice-success inline"><p><strong>✅ AWS S3 verbunden</strong><br>';
                echo 'Region: ' . esc_html($opts['s3_region']) . '<br>';
                echo 'Bucket: ' . esc_html($opts['s3_bucket']) . '<br>';
                echo '<a href="' . esc_url(wp_nonce_url(admin_url('admin-post.php?action=itn_cloud_disconnect&provider=s3'), 'itn_cloud_disconnect')) . '" class="button button-small">Trennen</a>';
                echo '</p></div>';
            }
            ?>
            
            <table class="form-table">
                <tr>
                    <th><label><?php _e('S3-Upload aktivieren', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="s3_enabled" <?php checked(!empty($opts['s3_enabled'])); ?>>
                            <?php _e('Backups automatisch zu AWS S3 hochladen', 'itn-sicherung'); ?>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Access Key ID', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="s3_access_key" value="<?php echo esc_attr($opts['s3_access_key']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Secret Access Key', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="password" name="s3_secret_key" value="<?php echo esc_attr($opts['s3_secret_key']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Region', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="s3_region" value="<?php echo esc_attr($opts['s3_region']); ?>" placeholder="us-east-1" class="regular-text" />
                        <p class="description"><?php _e('z.B. us-east-1, eu-central-1, ap-southeast-1', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Bucket-Name', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="s3_bucket" value="<?php echo esc_attr($opts['s3_bucket']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Pfad-Präfix (optional)', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="s3_prefix" value="<?php echo esc_attr($opts['s3_prefix']); ?>" placeholder="backups/mysite" class="regular-text" />
                        <p class="description"><?php _e('Unterordner im Bucket (ohne führenden/abschließenden Slash)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Cloud-Storage: Azure Blob -->
        <div class="itn-section">
            <h2><?php _e('Cloud-Storage: Azure Blob Storage', 'itn-sicherung'); ?></h2>
            
            <?php
            $azure_connected = !empty($opts['azure_enabled']) && !empty($opts['azure_account']) && !empty($opts['azure_container']);
            if ($azure_connected) {
                echo '<div class="notice notice-success inline"><p><strong>✅ Azure Blob verbunden</strong><br>';
                echo 'Account: ' . esc_html($opts['azure_account']) . '<br>';
                echo 'Container: ' . esc_html($opts['azure_container']) . '<br>';
                echo '<a href="' . esc_url(wp_nonce_url(admin_url('admin-post.php?action=itn_cloud_disconnect&provider=azure'), 'itn_cloud_disconnect')) . '" class="button button-small">Trennen</a>';
                echo '</p></div>';
            }
            ?>
            
            <table class="form-table">
                <tr>
                    <th><label><?php _e('Azure-Upload aktivieren', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="azure_enabled" <?php checked(!empty($opts['azure_enabled'])); ?>>
                            <?php _e('Backups automatisch zu Azure Blob hochladen', 'itn-sicherung'); ?>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Storage Account Name', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="azure_account" value="<?php echo esc_attr($opts['azure_account']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Access Key (Base64)', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="password" name="azure_key" value="<?php echo esc_attr($opts['azure_key']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Container-Name', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="azure_container" value="<?php echo esc_attr($opts['azure_container']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Pfad-Präfix (optional)', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="azure_prefix" value="<?php echo esc_attr($opts['azure_prefix']); ?>" placeholder="backups/mysite" class="regular-text" />
                        <p class="description"><?php _e('Unterordner im Container (ohne führenden/abschließenden Slash)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Cloud-Storage: OneDrive -->
        <div class="itn-section">
            <h2><?php _e('Cloud-Storage: Microsoft OneDrive', 'itn-sicherung'); ?></h2>
            
            <?php
            $od_tokens = get_option('itn_onedrive_tokens', []);
            $od_connected = !empty($od_tokens['access_token']);
            $od_device = get_option('itn_onedrive_device', []);
            
            if ($od_connected) {
                $expires = intval($od_tokens['expires'] ?? 0);
                $expires_in = $expires ? human_time_diff(time(), $expires) : 'unbekannt';
                echo '<div class="notice notice-success inline"><p><strong>✅ OneDrive verbunden</strong><br>';
                echo 'Token läuft ab in: ' . esc_html($expires_in) . '<br>';
                echo 'Ordner: ' . esc_html($opts['onedrive_folder'] ?? 'backups') . '<br>';
                echo '<a href="' . esc_url(wp_nonce_url(admin_url('admin-post.php?action=itn_cloud_disconnect&provider=onedrive'), 'itn_cloud_disconnect')) . '" class="button button-small">Trennen</a>';
                echo '</p></div>';
            } elseif (!empty($od_device['user_code'])) {
                echo '<div class="notice notice-info inline"><p><strong>⏳ OneDrive-Autorisierung läuft...</strong><br>';
                echo 'Code: <strong>' . esc_html($od_device['user_code']) . '</strong><br>';
                echo 'URL: <a href="' . esc_url($od_device['verification_uri'] ?? 'https://microsoft.com/devicelogin') . '" target="_blank">' . esc_html($od_device['verification_uri'] ?? 'https://microsoft.com/devicelogin') . '</a><br>';
                echo 'Nach Eingabe des Codes bitte "Token abrufen" klicken.';
                echo '</p></div>';
            }
            ?>
            
            <table class="form-table">
                <tr>
                    <th><label><?php _e('OneDrive-Upload aktivieren', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="onedrive_enabled" <?php checked(!empty($opts['onedrive_enabled'])); ?>>
                            <?php _e('Backups automatisch zu OneDrive hochladen', 'itn-sicherung'); ?>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Tenant', 'itn-sicherung'); ?></label></th>
                    <td>
                        <select name="onedrive_tenant">
                            <option value="consumers" <?php selected($opts['onedrive_tenant'], 'consumers'); ?>><?php _e('Persönlich (consumers)', 'itn-sicherung'); ?></option>
                            <option value="common" <?php selected($opts['onedrive_tenant'], 'common'); ?>><?php _e('Geschäftlich (common)', 'itn-sicherung'); ?></option>
                        </select>
                        <p class="description"><?php _e('Wähle "Persönlich" für private OneDrive-Konten', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Client-ID (Azure App)', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="onedrive_client_id" value="<?php echo esc_attr(ITN_Helpers::get_onedrive_client_id($opts)); ?>" class="regular-text" />
                        <p class="description">
                            <?php _e('Azure App Registration Client-ID', 'itn-sicherung'); ?><br>
                            <a href="https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" target="_blank"><?php _e('App erstellen im Azure Portal', 'itn-sicherung'); ?></a>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Ordner', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="onedrive_folder" value="<?php echo esc_attr($opts['onedrive_folder']); ?>" placeholder="backups" class="regular-text" />
                        <p class="description"><?php _e('Ordner in OneDrive (wird automatisch erstellt)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Verbindung', 'itn-sicherung'); ?></label></th>
                    <td>
                        <?php if (!$od_connected): ?>
                            <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=itn_onedrive_start'), 'itn_onedrive_start')); ?>" class="button button-primary">
                                <?php _e('Mit OneDrive verbinden', 'itn-sicherung'); ?>
                            </a>
                            <?php if (!empty($od_device['user_code'])): ?>
                                <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=itn_onedrive_poll'), 'itn_onedrive_poll')); ?>" class="button">
                                    <?php _e('Token abrufen', 'itn-sicherung'); ?>
                                </a>
                            <?php endif; ?>
                        <?php else: ?>
                            <span style="color: #00a32a; font-weight: bold;">✅ <?php _e('Verbunden', 'itn-sicherung'); ?></span>
                        <?php endif; ?>
                        <p class="description">
                            <?php _e('Speichere zuerst die Einstellungen mit Client-ID, dann "Mit OneDrive verbinden" klicken', 'itn-sicherung'); ?>
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- FTP-Upload (optional) -->
        <div class="itn-section">
            <h2><?php _e('FTP-Upload (optional)', 'itn-sicherung'); ?></h2>
            <table class="form-table">
                <tr>
                    <th><label><?php _e('FTP aktivieren', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="ftp_enabled" <?php checked(!empty($opts['ftp_enabled'])); ?>>
                            <?php _e('Backups via FTP hochladen', 'itn-sicherung'); ?>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('FTP-Host', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="ftp_host" value="<?php echo esc_attr($opts['ftp_host']); ?>" class="regular-text" placeholder="ftp.example.com" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('FTP-Port', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="number" name="ftp_port" value="<?php echo esc_attr($opts['ftp_port']); ?>" min="1" max="65535" />
                        <p class="description"><?php _e('Standard: 21', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('FTP-Benutzer', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="ftp_user" value="<?php echo esc_attr($opts['ftp_user']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('FTP-Passwort', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="password" name="ftp_pass" value="<?php echo esc_attr($opts['ftp_pass']); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('FTP-Pfad', 'itn-sicherung'); ?></label></th>
                    <td>
                        <input type="text" name="ftp_path" value="<?php echo esc_attr($opts['ftp_path']); ?>" class="regular-text" placeholder="/backups" />
                        <p class="description"><?php _e('Zielverzeichnis auf dem FTP-Server (optional)', 'itn-sicherung'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label><?php _e('Passiver Modus', 'itn-sicherung'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="ftp_passive" <?php checked(!empty($opts['ftp_passive'])); ?>>
                            <?php _e('Passiven FTP-Modus verwenden', 'itn-sicherung'); ?>
                        </label>
                    </td>
                </tr>
            </table>
        </div>

        <p class="submit">
            <button type="submit" class="button button-primary button-hero">
                <span class="dashicons dashicons-yes"></span> <?php _e('Einstellungen speichern', 'itn-sicherung'); ?>
            </button>
        </p>
    </div>
    <div class="itn-section">
            <h2><?php _e('Cron-Diagnose', 'itn-sicherung'); ?></h2>
            <table class="form-table">
                <tr>
                    <th><?php _e('WP-Cron Status', 'itn-sicherung'); ?></th>
                    <td>
                        <?php
                        $cron_disabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
                        if ($cron_disabled) {
                            echo '<span style="color: #d63638; font-weight: bold;">❌ Deaktiviert</span><br>';
                            echo '<p class="description">WP-Cron ist deaktiviert. Richte einen System-Cron ein:<br>';
                            echo '<code>*/15 * * * * wget -q -O - ' . esc_url(site_url('/wp-cron.php?doing_wp_cron')) . ' >/dev/null 2>&1</code></p>';
                        } else {
                            echo '<span style="color: #00a32a; font-weight: bold;">✅ Aktiv</span>';
                        }
                        ?>
                    </td>
                </tr>
                <tr>
                    <th><?php _e('Geplante Backups', 'itn-sicherung'); ?></th>
                    <td>
                        <?php
                        $all_crons = _get_cron_array();
                        $itn_crons = [];
                        
                        foreach ($all_crons as $timestamp => $cron) {
                            if (isset($cron['itn/run_backup_cron'])) {
                                $itn_crons[] = [
                                    'time' => $timestamp,
                                    'date' => date('Y-m-d H:i:s', $timestamp),
                                    'in' => human_time_diff(time(), $timestamp),
                                ];
                            }
                        }
                        
                        if (empty($itn_crons)) {
                            echo '<span style="color: #d63638;">❌ Keine Backups geplant</span>';
                        } else {
                            echo '<strong style="color: #00a32a;">✅ ' . count($itn_crons) . ' Backup(s) geplant:</strong><br>';
                            foreach ($itn_crons as $cron) {
                                echo '📅 ' . esc_html($cron['date']) . ' (' . esc_html($cron['in']) . ')<br>';
                            }
                        }
                        ?>
                    </td>
                </tr>
                <tr>
                    <th><?php _e('Cron manuell auslösen', 'itn-sicherung'); ?></th>
                    <td>
                        <button type="button" class="button" id="itn-trigger-cron">🔄 WP-Cron jetzt ausführen</button>
                        <p class="description">Führt alle fälligen Cron-Jobs sofort aus (inkl. Backup wenn geplant)</p>
                        <div id="itn-cron-result" style="margin-top: 10px;"></div>
                        
                        <script>
                        jQuery(document).ready(function($) {
                            $('#itn-trigger-cron').on('click', function() {
                                var $btn = $(this);
                                var $result = $('#itn-cron-result');
                                
                                $btn.prop('disabled', true).text('⏳ Führe Cron aus...');
                                $result.html('');
                                
                                $.post(ajaxurl, {
                                    action: 'itn_test_cron',
                                    _ajax_nonce: '<?php echo wp_create_nonce('itn_test_cron'); ?>'
                                })
                                .done(function(res) {
                                    if (res.success) {
                                        $result.html('<div class="notice notice-success inline"><p>✅ ' + res.data.message + '</p></div>');
                                    } else {
                                        $result.html('<div class="notice notice-error inline"><p>❌ ' + res.data.message + '</p></div>');
                                    }
                                })
                                .fail(function() {
                                    $result.html('<div class="notice notice-error inline"><p>❌ Netzwerkfehler</p></div>');
                                })
                                .always(function() {
                                    $btn.prop('disabled', false).text('🔄 WP-Cron jetzt ausführen');
                                    setTimeout(function() { location.reload(); }, 2000);
                                });
                            });
                        });
                        </script>
                    </td>
                </tr>
            </table>
        </div>
</form>

<style>
.itn-settings-container {
    max-width: 1200px;
}
.itn-section {
    background: #fff;
    border: 1px solid #ccd0d4;
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 1px 1px rgba(0,0,0,.04);
}
.itn-section h2 {
    margin-top: 0;
    padding-bottom: 10px;
    border-bottom: 1px solid #e5e5e5;
}
.form-table th {
    width: 220px;
    font-weight: 600;
}
.button-hero {
    font-size: 16px !important;
    height: auto !important;
    padding: 12px 24px !important;
}
.notice.inline {
    margin: 5px 0 15px 0;
    padding: 10px 15px;
}
</style>