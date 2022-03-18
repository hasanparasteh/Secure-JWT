<?php

namespace hasanparasteh;

use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWE\EncryptionAlgorithm\A256CBCHS512Algorithm;
use Sop\JWX\JWE\KeyAlgorithm\RSAESOAEPAlgorithm;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWK\RSA\RSAPublicKeyJWK;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWT\Claim\AudienceClaim;
use Sop\JWX\JWT\Claim\ExpirationTimeClaim;
use Sop\JWX\JWT\Claim\IssuedAtClaim;
use Sop\JWX\JWT\Claim\IssuerClaim;
use Sop\JWX\JWT\Claim\NotBeforeClaim;
use Sop\JWX\JWT\Claim\SubjectClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\JWT;
use Sop\JWX\JWT\ValidationContext;

class SecureJWT extends Cipher
{
    public static function encodeJWT(
        array  $payload,
        string $iss,
        string $sub,
        string $aud,
        string $key,
        string $exp = "6 hour"
    ): string
    {
        $payloadClaims = Helpers::makeClaims($payload);
        $claims = new Claims(
            IssuedAtClaim::now(),
            NotBeforeClaim::now(),
            ExpirationTimeClaim::fromString("now + $exp"),
            IssuerClaim::fromNameAndValue('iss', $iss),
            SubjectClaim::fromNameAndValue('sub', $sub),
            AudienceClaim::fromNameAndValue('aud', $aud),
            ...$payloadClaims
        );
        return JWT::signedFromClaims($claims, new HS256Algorithm($key))->token();
    }

    public static function decodeJWT(
        string $token,
        string $iss,
        string $sub,
        string $aud,
        string $key
    ): array
    {
        $jwt = new JWT($token);
        $jwk = SymmetricKeyJWK::fromKey($key);
        $ctx = ValidationContext::fromJWK($jwk)
            ->withIssuer($iss)
            ->withSubject($sub)
            ->withAudience($aud);
        $claims = $jwt->claims($ctx);

        $payload = [];
        foreach ($claims as $claim) {
            $payload[] = [$claim->name() => $claim->value()];
        }
        return $payload;
    }

    public static function encodeSecureJWT(
        array  $payload,
        string $iss, string $sub,
        string $aud, string $publicKey,
        string $exp = "6 hour"
    ): string
    {
        $payloadClaims = Helpers::makeClaims($payload);
        $claims = new Claims(
            IssuedAtClaim::now(),
            NotBeforeClaim::now(),
            ExpirationTimeClaim::fromString("now + $exp"),
            IssuerClaim::fromNameAndValue('iss', $iss),
            SubjectClaim::fromNameAndValue('sub', $sub),
            AudienceClaim::fromNameAndValue('aud', $aud),
            ...$payloadClaims,
        );

        $jwk = RSAPublicKeyJWK::fromPEM(
            PEM::fromString($publicKey)
        );
        $key_algo = RSAESOAEPAlgorithm::fromPublicKey($jwk);
        $enc_algo = new A256CBCHS512Algorithm();

        $jwt = JWT::encryptedFromClaims($claims, $key_algo, $enc_algo);
        return $jwt->token();
    }

    public static function decodeSecureJWT(
        string $token,
        string $iss,
        string $sub,
        string $aud,
        string $privateKey
    ): array
    {
        $jwt = new JWT($token);
        $jwk = RSAPrivateKeyJWK::fromPEM(PEM::fromString($privateKey));
        $ctx = ValidationContext::fromJWK($jwk)
            ->withIssuer($iss)
            ->withSubject($sub)
            ->withAudience($aud);

        $claims = $jwt->claims($ctx);

        $payload = [];
        foreach ($claims as $claim) {
            $payload[] = [$claim->name() => $claim->value()];
        }
        return $payload;
    }
}