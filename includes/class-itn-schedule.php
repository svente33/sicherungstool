<?php
if (!defined('ABSPATH')) { exit; }

class ITN_Schedule {
    public static function register_schedules($schedules) {
        $opts = get_option('itn_settings', []);
        $custom_minutes = max(5, intval($opts['custom_interval_minutes'] ?? 60));
        
        // Custom interval
        $schedules['itn_custom'] = [
            'interval' => $custom_minutes * 60,
            'display'  => 'ITN Sicherung benutzerdefiniert (' . $custom_minutes . ' Min)',
        ];
        
        // Weekly interval
        $schedules['itn_weekly'] = [
            'interval' => 7 * DAY_IN_SECONDS,
            'display'  => 'ITN Sicherung wöchentlich',
        ];
        
        // Twice daily interval (if not already defined by WordPress)
        if (!isset($schedules['itn_twicedaily'])) {
            $schedules['itn_twicedaily'] = [
                'interval' => 12 * HOUR_IN_SECONDS,
                'display'  => 'ITN Sicherung zweimal täglich',
            ];
        }
        
        return $schedules;
    }

    public static function ensure_cron() {
        // Registriere Custom Schedules - WICHTIG: muss vor wp_schedule_event aufgerufen werden
        add_filter('cron_schedules', [__CLASS__, 'register_schedules']);

        $opts = get_option('itn_settings', []);
        $freq = $opts['schedule_frequency'] ?? 'daily';
        $time = $opts['schedule_time'] ?? '02:00';

        $parts = explode(':', $time);
        $hour = intval($parts[0] ?? 2);
        $min = intval($parts[1] ?? 0);

        // Lösche alle bestehenden Crons (inkl. Duplikate)
        self::clear_cron();

        $now = current_time('timestamp');

        error_log('ITN Schedule: Plane Cron mit Frequenz: ' . $freq . ' um ' . $time);

        if ($freq === 'daily') {
            $next = mktime($hour, $min, 0, date('n', $now), date('j', $now), date('Y', $now));
            if ($next <= $now) $next = strtotime('+1 day', $next);
            
            $scheduled = wp_schedule_event($next, 'daily', 'itn/run_backup_cron');
            error_log('ITN Schedule: Daily Cron geplant für ' . date('Y-m-d H:i:s', $next) . ' - Result: ' . ($scheduled ? 'OK' : 'FAILED'));
            
        } elseif ($freq === 'hourly') {
            $next = $now + 3600; // Nächste volle Stunde
            $scheduled = wp_schedule_event($next, 'hourly', 'itn/run_backup_cron');
            error_log('ITN Schedule: Hourly Cron geplant für ' . date('Y-m-d H:i:s', $next) . ' - Result: ' . ($scheduled ? 'OK' : 'FAILED'));
            
        } elseif ($freq === 'twicedaily') {
            $next = $now + 60; // Start in 1 minute
            // Use our custom interval to ensure it's registered
            $scheduled = wp_schedule_event($next, 'twicedaily', 'itn/run_backup_cron');
            error_log('ITN Schedule: Twice Daily Cron geplant für ' . date('Y-m-d H:i:s', $next) . ' - Result: ' . ($scheduled ? 'OK' : 'FAILED'));
            
        } elseif ($freq === 'weekly') {
            $dow = intval($opts['schedule_dow'] ?? 1);
            $cur_dow = intval(date('w', $now));
            $days_ahead = ($dow - $cur_dow + 7) % 7;
            if ($days_ahead === 0) $days_ahead = 7; // Nächste Woche
            
            $target_base = mktime($hour, $min, 0, date('n', $now), date('j', $now), date('Y', $now));
            $target = strtotime('+' . $days_ahead . ' days', $target_base);
            
            $scheduled = wp_schedule_event($target, 'itn_weekly', 'itn/run_backup_cron');
            error_log('ITN Schedule: Weekly Cron geplant für ' . date('Y-m-d H:i:s', $target) . ' (Wochentag: ' . $dow . ') - Result: ' . ($scheduled ? 'OK' : 'FAILED'));
            
        } elseif ($freq === 'monthly') {
            $dom = max(1, min(31, intval($opts['schedule_dom'] ?? 1)));
            $year = intval(date('Y', $now));
            $month = intval(date('n', $now));
            $cur_day = intval(date('j', $now));

            // Wenn aktueller Tag >= gewünschter Tag, nächsten Monat nehmen
            if ($cur_day >= $dom) {
                $month++;
                if ($month > 12) { 
                    $month = 1; 
                    $year++; 
                }
            }
            
            $last_day = intval(date('t', mktime(0, 0, 0, $month, 1, $year)));
            $day = min($dom, $last_day);
            $target = mktime($hour, $min, 0, $month, $day, $year);

            $scheduled = wp_schedule_single_event($target, 'itn/run_backup_cron');
            update_option('itn_monthly_next_ts', $target, false);
            
            error_log('ITN Schedule: Monthly Cron geplant für ' . date('Y-m-d H:i:s', $target) . ' (Tag: ' . $dom . ') - Result: ' . ($scheduled ? 'OK' : 'FAILED'));
            
        } elseif ($freq === 'custom') {
            $custom_minutes = max(5, intval($opts['custom_interval_minutes'] ?? 60));
            $next = $now + 60; // Start in 1 Minute
            $scheduled = wp_schedule_event($next, 'itn_custom', 'itn/run_backup_cron');
            error_log('ITN Schedule: Custom Cron geplant für ' . date('Y-m-d H:i:s', $next) . ' (Intervall: ' . $custom_minutes . ' Min) - Result: ' . ($scheduled ? 'OK' : 'FAILED'));
            
        } else {
            // Fallback auf täglich
            $next = mktime($hour, $min, 0, date('n', $now), date('j', $now), date('Y', $now));
            if ($next <= $now) $next = strtotime('+1 day', $next);
            
            $scheduled = wp_schedule_event($next, 'daily', 'itn/run_backup_cron');
            error_log('ITN Schedule: Default Daily Cron geplant für ' . date('Y-m-d H:i:s', $next) . ' - Result: ' . ($scheduled ? 'OK' : 'FAILED'));
        }
        
        // Prüfe ob Cron wirklich existiert
        $next_run = wp_next_scheduled('itn/run_backup_cron');
        if ($next_run) {
            error_log('ITN Schedule: Nächster Cron-Lauf bestätigt: ' . date('Y-m-d H:i:s', $next_run));
        } else {
            error_log('ITN Schedule ERROR: Kein Cron gefunden nach Planung!');
        }
    }

    public static function maybe_schedule_next_monthly() {
        $opts = get_option('itn_settings', []);
        if (($opts['schedule_frequency'] ?? '') !== 'monthly') return;

        $last_target = intval(get_option('itn_monthly_next_ts', 0));
        $now = current_time('timestamp');
        
        // Nur neu planen wenn letzter Termin vorbei ist
        if ($last_target && $now < $last_target) return;

        $time = $opts['schedule_time'] ?? '02:00';
        $parts = explode(':', $time);
        $hour = intval($parts[0] ?? 2);
        $min = intval($parts[1] ?? 0);

        $dom = max(1, min(31, intval($opts['schedule_dom'] ?? 1)));

        $year = intval(date('Y', $now));
        $month = intval(date('n', $now));
        $month++; // Nächster Monat
        
        if ($month > 12) { 
            $month = 1; 
            $year++; 
        }
        
        $last_day = intval(date('t', mktime(0, 0, 0, $month, 1, $year)));
        $day = min($dom, $last_day);
        $target = mktime($hour, $min, 0, $month, $day, $year);

        wp_schedule_single_event($target, 'itn/run_backup_cron');
        update_option('itn_monthly_next_ts', $target, false);
        
        error_log('ITN Schedule: Nächster monatlicher Cron geplant für ' . date('Y-m-d H:i:s', $target));
    }

    public static function clear_cron() {
        $cleared_count = 0;
        $max_iterations = 50; // Prevent infinite loops
        $iterations = 0;
        
        // Clear all scheduled events for our hook (including duplicates)
        while ($iterations < $max_iterations) {
            $next = wp_next_scheduled('itn/run_backup_cron');
            if (!$next) {
                break; // No more events found
            }
            
            wp_unschedule_event($next, 'itn/run_backup_cron');
            $cleared_count++;
            $iterations++;
        }
        
        if ($cleared_count > 0) {
            error_log('ITN Schedule: ' . $cleared_count . ' alte Cron-Events gelöscht');
        }
        
        if ($iterations >= $max_iterations) {
            error_log('ITN Schedule WARNING: Max iterations erreicht beim Löschen von Crons');
        }
        
        delete_option('itn_monthly_next_ts');
    }
    
    /**
     * Debugging-Funktion: Zeigt geplante Crons
     */
    public static function get_scheduled_info() {
        $next = wp_next_scheduled('itn/run_backup_cron');
        
        if (!$next) {
            return ['scheduled' => false, 'message' => 'Kein Backup geplant'];
        }
        
        $opts = get_option('itn_settings', []);
        $freq = $opts['schedule_frequency'] ?? 'daily';
        
        return [
            'scheduled' => true,
            'next_run' => date('Y-m-d H:i:s', $next),
            'next_run_timestamp' => $next,
            'frequency' => $freq,
            'time_until' => human_time_diff(time(), $next),
        ];
    }
}