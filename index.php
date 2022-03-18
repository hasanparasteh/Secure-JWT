<?php

use Hasanparasteh\JwtExperiments\SecureJWT;

require "vendor/autoload.php";

//$jwt = new SecureJWT();
//$keypair = $jwt->createKeyPair("/tmp");
//if (is_bool($keypair) && $keypair === false) {
//    echo "ERROR: Failed to generate keypair" . PHP_EOL;
//    exit;
//}
//
//$publicKey = $keypair['public_key'];
//$privateKey = $keypair['private_key'];
//
//echo "public key is: " . $publicKey . PHP_EOL;
//echo "private key is: " . $privateKey . PHP_EOL;
//
//echo PHP_EOL . PHP_EOL;


$payload = [
    "userId" => 6
];

$encodeInfo = [
    $payload,
    'Hasan Parasteh', // iss
    'test', // sub
    'github', // aud
    'secret', // key
    '2 hour' // exp
];
$token = SecureJWT::encodeJWT(...$encodeInfo);
echo "Token is: " . $token . PHP_EOL;


$decodeInfo = [
    $token,
    'Hasan Parasteh', // iss
    'test', // sub
    'github', // aud
    'secret', // key
];
$payload = SecureJWT::decodeJWT(...$decodeInfo);
echo json_encode($payload, 128);

