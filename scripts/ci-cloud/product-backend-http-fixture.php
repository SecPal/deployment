<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

// Disposable HTTP transport only; native PostgreSQL owns product readiness.
if (($_SERVER['REQUEST_URI'] ?? '') !== '/health/ready') {
    http_response_code(404);
    exit;
}
header('Content-Type: application/json');
echo '{"status":"transport-ready"}';
