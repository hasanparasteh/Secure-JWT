<?php

namespace Hasanparasteh\JwtExperiments;

use phpseclib3\Crypt\RSA;

class Cipher
{
    protected mixed $privateKey;
    protected mixed $publicKey;

    public function getPrivateKey(): ?string
    {
        return $this->privateKey;
    }

    public function getPublicKey(): ?string
    {
        return $this->publicKey;
    }

    public function setPublicKey(string $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function setPrivateKey(string $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    public function readKeyPairFromPath(string $path)
    {
        $this->privateKey = file_get_contents(Helpers::joinPath($path, 'private.key'));
        $this->publicKey = file_get_contents(Helpers::joinPath($path, 'public.key'));
    }

    public static function createKeyPair(?string $path = null): bool|array
    {
        if (!Helpers::isPathValid($path))
            return false;

        $publicKeyPath = Helpers::joinPath($path, "private.key");
        $privateKeyPath = Helpers::joinPath($path, "public.key");

        $privateKey = RSA::createKey();
        $publicKey = $privateKey->getPublicKey();

        $pair = [
            'public_key' => $publicKey,
            'private_key' => $privateKey
        ];

        if (is_null($path))
            return $pair;

        if (!self::insertKeyPairIntoFile($publicKeyPath, $privateKeyPath, $publicKey, $privateKey))
            return false;

        return $pair;
    }

    private static function insertKeyPairIntoFile(
        $publicKeyPath,
        $privateKeyPath,
        $publicKey,
        $privateKey
    ): bool
    {
        $privateKeyFileHandle = file_put_contents($privateKeyPath, $privateKey);
        $publicKeyFileHandle = file_put_contents($publicKeyPath, $publicKey);

        chmod($publicKeyPath, 644);
        chmod($privateKeyPath, 644);

        if ($publicKeyFileHandle === FALSE || $privateKeyFileHandle === FALSE)
            return false;
        return true;
    }
}