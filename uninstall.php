<?php
/**
 * Uninstall: removes every table, option, transient, cron event and user meta key the
 * plugin creates (plan 6.6). Deactivation removes nothing.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

require_once __DIR__ . '/src/Settings/Options.php';
require_once __DIR__ . '/src/Install/Schema.php';
require_once __DIR__ . '/src/Install/Uninstaller.php';

\MaxtDesign\Mfa\Install\Uninstaller::run();
