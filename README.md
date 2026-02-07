# sicherungstool

WordPress Backup Plugin mit automatischer Verschlüsselung und Zeitsteuerung.

## Features

- **Vollständige Backups**: Dateien und Datenbank in einem ZIP-Archiv
- **Verschlüsselung**: AES-256 Verschlüsselung (ZipArchive, Sodium oder OpenSSL)
- **Automatische Backups**: WordPress-Cron oder System-Cron
- **Wiederherstellung**: Installer-Generator für einfache Restores
- **Cloud-Upload**: AWS S3, Azure Blob, OneDrive
- **E-Mail-Benachrichtigungen**: Bei Erfolg oder Fehler

## Installation

1. Plugin in `/wp-content/plugins/sicherungstool/` hochladen
2. Plugin in WordPress aktivieren
3. Einstellungen unter "ITN - Sicherung" konfigurieren

## Verschlüsselung

Das Plugin unterstützt mehrere Verschlüsselungsmethoden:

1. **ZipArchive AES-256**: Wenn verfügbar (empfohlen für beste Kompatibilität)
2. **Sodium (XSalsa20-Poly1305)**: Pure-PHP Verschlüsselung mit Argon2id Key-Derivation
3. **OpenSSL AES-256-GCM**: Fallback wenn Sodium nicht verfügbar

Bei aktivierter Verschlüsselung wird das Backup automatisch mit der besten verfügbaren Methode verschlüsselt. Wenn keine Methode verfügbar ist, wird der Backup-Vorgang mit einer Fehlermeldung abgebrochen.

## System-Cron Einrichtung (Empfohlen)

Für zuverlässige automatische Backups ohne Zeitbeschränkungen wird die Verwendung eines System-Crons empfohlen:

### Einrichtung

1. Öffnen Sie die crontab:
   ```bash
   crontab -e
   ```

2. Fügen Sie eine Zeile für automatische Backups hinzu:
   ```bash
   # Tägliches Backup um 02:00 Uhr
   0 2 * * * /usr/bin/php /pfad/zu/wordpress/wp-content/plugins/sicherungstool/cli-backup-runner.php --cron >> /var/log/itn-backup.log 2>&1
   ```

3. Passen Sie den Pfad und die Zeit nach Bedarf an:
   - `/usr/bin/php` - Pfad zur PHP-CLI (mit `which php` ermitteln)
   - `/pfad/zu/wordpress/` - Ihr WordPress-Installations-Pfad
   - `0 2 * * *` - Cron-Zeitausdruck (täglich um 02:00)

### Cron-Zeitausdrücke

Beispiele für häufige Backup-Intervalle:

```bash
# Täglich um 02:00 Uhr
0 2 * * * ...

# Jeden Sonntag um 03:00 Uhr
0 3 * * 0 ...

# Zweimal täglich (02:00 und 14:00)
0 2,14 * * * ...

# Stündlich
0 * * * * ...

# Jeden ersten des Monats um 04:00
0 4 1 * * ...
```

### CLI Modi

Der `cli-backup-runner.php` unterstützt zwei Modi:

1. **Mit Run-ID** (für manuelle Aufrufe):
   ```bash
   php cli-backup-runner.php backup_20240207_120000_example_com
   ```

2. **Cron-Modus** (für automatische Aufrufe):
   ```bash
   php cli-backup-runner.php --cron
   ```
   Im Cron-Modus wird automatisch eine Run-ID generiert.

### Vorteile von System-Cron

- ✅ Keine PHP Zeitbeschränkungen (max_execution_time)
- ✅ Zuverlässige Ausführung auch bei viel Traffic
- ✅ Unabhängig von WordPress-Cron
- ✅ Bessere Kontrolle über Ausführungszeiten
- ✅ Einfaches Logging und Monitoring

## Wiederherstellung

Verschlüsselte Backups werden automatisch vom Installer erkannt und können mit dem gleichen Passwort wiederhergestellt werden.

1. ZIP-Backup und Installer-Datei auf neuen Server hochladen
2. Installer im Browser aufrufen (`installer-backup_*.php`)
3. Bei verschlüsselten Backups: Passwort eingeben
4. Datenbank-Zugangsdaten eingeben
5. Restore durchführen

## Lizenz

Proprietär - ITN Online