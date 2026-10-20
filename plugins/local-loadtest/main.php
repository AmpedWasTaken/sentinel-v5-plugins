<?php
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/sdk/php/Sentinel.php';

use Sentinel\Plugin;

/**
 * Trusted LOCAL diagnostics example, not a remote attack API.
 * Fixed loopback destination: user arguments cannot change URL, host or port.
 * Requires a service listening at 127.0.0.1:8080 on the Sentinel host.
 */
const BASE_URL = 'http://127.0.0.1:8080';
const PROFILES = [
    'health' => '/health',
    'status' => '/api/status',
];

$plugin = new Plugin();

$plugin->command('loadtestinfo', static function (array $ctx): array {
    return [
        'view' => 'loadtest-info',
        'values' => [
            'destination' => BASE_URL,
            'profiles' => 'health, status',
            'limits' => '1-3 sequential GET requests, 2s per request, no redirects',
        ],
    ];
});

$plugin->command('loadtest', static function (array $ctx): array {
    if (!function_exists('curl_init')) {
        throw new RuntimeException('PHP cURL extension is required');
    }

    $args = $ctx['args'];
    $profile = (string) ($args['profile'] ?? 'health');
    if (!array_key_exists($profile, PROFILES)) {
        throw new InvalidArgumentException('Profile must be health or status');
    }

    $rawCount = (string) ($args['count'] ?? '1');
    if (!preg_match('/^[1-3]$/', $rawCount)) {
        throw new InvalidArgumentException('Count must be 1, 2 or 3');
    }
    $count = (int) $rawCount;
    $case = (string) ($args['case'] ?? 'smoke');
    if (!preg_match('/^[a-zA-Z0-9_-]{1,24}$/', $case)) {
        throw new InvalidArgumentException('Case must be 1-24 safe characters');
    }

    $url = BASE_URL . PROFILES[$profile] . '?' . http_build_query(
        ['case' => $case], '', '&', PHP_QUERY_RFC3986
    );
    $ok = 0;
    $errors = 0;
    $durationMs = 0.0;
    $lastStatus = 0;

    for ($i = 0; $i < $count; $i++) {
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Unable to initialize HTTP client');
        }
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => 500,
            CURLOPT_TIMEOUT_MS => 2000,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_PROXY => '',
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'User-Agent: Sentinel-LocalDiagnostics/1'],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $response = curl_exec($handle);
        $code = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $durationMs += (float) curl_getinfo($handle, CURLINFO_TOTAL_TIME) * 1000;
        $lastStatus = $code;
        if ($response !== false && $code >= 200 && $code < 400) {
            $ok++;
        } else {
            $errors++;
        }
        curl_close($handle);
        if ($i + 1 < $count) {
            usleep(500000); // strictly sequential; at most two requests/second
        }
    }

    return [
        'view' => 'loadtest-report',
        'values' => [
            'profile' => $profile,
            'destination' => BASE_URL,
            'case' => $case,
            'count' => (string) $count,
            'success' => (string) $ok,
            'errors' => (string) $errors,
            'last_status' => (string) $lastStatus,
            'average_ms' => number_format($durationMs / $count, 1, '.', ''),
        ],
    ];
});

$plugin->run();
