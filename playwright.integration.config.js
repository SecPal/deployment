// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

const { defineConfig } = require("@playwright/test");
const path = require("node:path");

const appOrigin = process.env.APP_ORIGIN;
const apiOrigin = process.env.API_ORIGIN;
const integrationInstance =
  process.env.SECPAL_INTEGRATION_INSTANCE ?? "phasebcompose";

if (
  !appOrigin ||
  !apiOrigin ||
  !/^[a-z0-9]{8,24}$/.test(integrationInstance ?? "")
) {
  throw new Error(
    "APP_ORIGIN, API_ORIGIN, and a valid integration instance are required.",
  );
}

const appHost = new URL(appOrigin).hostname;
const apiHost = new URL(apiOrigin).hostname;
const outputDir = path.join(
  __dirname,
  "test-results",
  `secpal-int-${integrationInstance}`,
);

module.exports = defineConfig({
  testDir: "./tests/e2e",
  outputDir,
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
