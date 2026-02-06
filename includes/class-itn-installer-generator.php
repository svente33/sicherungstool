<?php
if (!defined('ABSPATH')) { exit; }

class ITN_Installer_Generator {
    public static function write_installer_for_backup($zip_path, $target_path) {
        $src = ITN_PLUGIN_DIR . 'includes/templates/installer.php';
        if (!file_exists($src)) return ['success' => false, 'message' => 'Installer-Vorlage fehlt: ' . $src];

        $tpl = file_get_contents($src);
        if ($tpl === false) return ['success' => false, 'message' => 'Installer-Vorlage konnte nicht gelesen werden'];

        $zip_base = basename($zip_path);
        $cfg = '$DEFAULT_ZIP = ' . var_export($zip_base, true) . ';';

        $out = preg_replace('/\\$DEFAULT_ZIP\\s*=\\s*\'[^\']*\'\\s*;/', $cfg, $tpl, 1);
        if ($out === null) {
            $out = "<?php\n" . $cfg . "\n?>\n" . $tpl;
        }

        if (@file_put_contents($target_path, $out) === false) {
            return ['success' => false, 'message' => 'Installer konnte nicht geschrieben werden: ' . $target_path];
        }
        return ['success' => true, 'path' => $target_path];
    }
}