<?php
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/sdk/php/Sentinel.php';

use Sentinel\Plugin;

$plugin = new Plugin();

$plugin->command('greet', static function (array $ctx): array {
    $name = (string) ($ctx['args']['name'] ?? $ctx['actor']);
    $name = substr(preg_replace('/[^a-zA-Z0-9 _-]/', '', $name) ?? '', 0, 50);
    return [
        'view' => 'greeting',
        'values' => [
            'name' => $name,
            'timestamp' => gmdate('Y-m-d H:i:s') . ' UTC',
        ],
    ];
});

$plugin->run();
