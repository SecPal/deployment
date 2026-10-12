<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

// Qualification-only front controller for the immutable pinned API image.
// Mounted explicitly on disposable private hosts, never a product route.
// Preserve the complete real HTTP kernel, proxy, CORS, cookie and CSRF stack.
require '/app/vendor/autoload.php';
$application = require '/app/bootstrap/app.php';
$application->booted(static function (): void {
    $identity = static function (Illuminate\Http\Request $request) {
        $count = null;
        if ($request->hasSession()) {
            $count = (int) $request->session()->get('direct-qualification-count', 0) + 1;
            $request->session()->put('direct-qualification-count', $count);
        }

        return response()->json([
            'client' => $request->ip(),
            'peer' => $request->server('REMOTE_ADDR'),
            'scheme' => $request->getScheme(),
            'host' => $request->getHost(),
            'port' => $request->getPort(),
            'session_count' => $count,
        ]);
    };
    Illuminate\Support\Facades\Route::middleware('api')->group(static function () use ($identity): void {
        Illuminate\Support\Facades\Route::get('/v1/_secpal/direct-qualification', $identity);
        Illuminate\Support\Facades\Route::post('/v1/_secpal/direct-qualification', $identity);
    });
});
$application->handleRequest(Illuminate\Http\Request::capture());
