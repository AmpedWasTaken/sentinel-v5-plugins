<?php
declare(strict_types=1);

namespace Sentinel;

/**
 * Minimal WordPress-style plugin registration API.
 * Handlers receive authenticated request context and return an associative
 * result array with text OR a plugin-owned SML view + scalar values.
 *
 * This SDK uses PHP CLI. It does not supply filesystem/network permissions:
 * installed PHP plugins are trusted host code, never untrusted marketplace code.
 */
final class Plugin
{
    /** @var array<string, callable> */
    private array $commands = [];

    public function command(string $name, callable $handler): self
    {
        if (!preg_match('/^[a-z][a-z0-9_-]{0,23}$/', $name)) {
            throw new \InvalidArgumentException('Invalid plugin command name');
        }
        if (isset($this->commands[$name])) {
            throw new \InvalidArgumentException('Duplicate plugin command');
        }
        $this->commands[$name] = $handler;
        return $this;
    }

    public function run(): void
    {
        $raw = stream_get_contents(STDIN, 16385);
        $response = ['version' => 1, 'result' => new \stdClass()];
        try {
            if ($raw === false || strlen($raw) > 16384) {
                throw new \RuntimeException('Invalid plugin request size');
            }
            $request = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($request) || ($request['version'] ?? null) !== 1) {
                throw new \RuntimeException('Unsupported plugin protocol');
            }
            $command = $request['command'] ?? null;
            if (!is_string($command) || !isset($this->commands[$command])) {
                throw new \RuntimeException('Unknown plugin command');
            }
            $result = ($this->commands[$command])([
                'actor' => (string) ($request['actor'] ?? ''),
                'role' => (string) ($request['role'] ?? ''),
                'args' => is_array($request['args'] ?? null) ? $request['args'] : [],
            ]);
            if (!is_array($result)) {
                throw new \RuntimeException('Plugin handler must return an array');
            }
            $response['result'] = $result;
        } catch (\Throwable $e) {
            $response['error'] = substr($e->getMessage(), 0, 180);
        }
        echo json_encode($response, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        echo "\n";
    }
}
