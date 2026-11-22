<?php

namespace Acciv\KeyGate;

class KeyGateClient
{
    private string $baseUrl;
    private string $masterKey;
    private string $clientId;

    public function __construct(
        string $baseUrl = 'http://127.0.0.1:8080',
        string $masterKey = 'kg_master_local',
        string $clientId = 'php-sdk'
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->masterKey = $masterKey;
        $this->clientId = $clientId;
    }

    public function request(string $method, string $path, ?array $body = null): array
    {
        $ch = curl_init($this->baseUrl . $path);
        $payload = $body === null ? null : json_encode($body, JSON_UNESCAPED_SLASHES);

        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => [
                'X-KeyGate-Key: ' . $this->masterKey,
                'X-Client-ID: ' . $this->clientId,
                'Content-Type: application/json',
            ],
        ]);
        if ($payload !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        }

        $raw = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new \RuntimeException('keygate request failed: ' . $error);
        }
        $decoded = json_decode($raw, true) ?? [];
        if ($status >= 400) {
            throw new \RuntimeException('keygate HTTP ' . $status . ': ' . $raw);
        }
        return $decoded;
    }

    public function health(): array { return $this->request('GET', '/healthz'); }
    public function resolve(string $provider, string $scope = 'read', int $ttl = 60): array
    {
        return $this->request('POST', '/v1/keys/resolve', [
            'provider' => $provider, 'scope' => $scope, 'ttl' => $ttl,
        ]);
    }
    public function rotate(string $provider): array
    {
        return $this->request('POST', '/v1/keys/rotate', ['provider' => $provider]);
    }
    public function audit(): array { return $this->request('GET', '/v1/audit'); }
    public function providers(): array { return $this->request('GET', '/v1/providers'); }
}
