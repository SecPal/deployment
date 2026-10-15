<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

// Disposable HTTP transport only; native PostgreSQL owns product readiness.
if (!in_array($_SERVER['REQUEST_URI'] ?? '', ['/health/live', '/health/ready'], true)) {
    http_response_code(404);
    exit;
}
header('Content-Type: application/json');
echo '{"status":"transport-ready"}';
