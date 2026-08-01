// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

const { defineConfig } = require("@playwright/test");

const appOrigin = process.env.APP_ORIGIN;
const apiOrigin = process.env.API_ORIGIN;

if (!appOrigin || !apiOrigin) {
  throw new Error("APP_ORIGIN and API_ORIGIN are required.");
}

const appHost = new URL(appOrigin).hostname;
const apiHost = new URL(apiOrigin).hostname;

module.exports = defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 45_000,
  expect: {
    timeout: 10_000,
  },
  reporter: "line",
  use: {
    baseURL: appOrigin,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    launchOptions: {
      args: [
        "--ignore-certificate-errors",
        `--host-resolver-rules=MAP ${appHost} 127.0.0.1,MAP ${apiHost} 127.0.0.1`,
      ],
    },
  },
});
