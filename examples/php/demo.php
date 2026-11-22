<?php

require __DIR__ . '/../../sdk/php/src/KeyGateClient.php';

use Acciv\KeyGate\KeyGateClient;

$client = new KeyGateClient('http://127.0.0.1:8080', 'kg_master_local', 'demo-php');

print_r($client->health());
print_r($client->resolve('aws', 'read', 30));
print_r($client->providers());
