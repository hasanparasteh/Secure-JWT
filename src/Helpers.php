<?php

namespace hasanparasteh;

use Sop\JWX\JWT\Claim\Claim;

class Helpers
{
    public static function joinPath(string $base, string $file): string
    {
        if (str_ends_with($base, '/'))
            return $base . $file;
        return $base . DIRECTORY_SEPARATOR . $file;
    }

    public static function isPathValid(string $path): bool
    {
        return file_exists($path) && is_dir($path) && is_writable($path);
    }

    public static function makeClaims(array $payload): array
    {
        $claims = [];
        foreach ($payload as $claimKey => $claimValue) {
            $claims[] = new Claim($claimKey, $claimValue);
        }
        return $claims;
    }
}