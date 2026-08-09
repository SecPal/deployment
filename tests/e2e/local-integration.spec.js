// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

const { expect, test } = require("@playwright/test");

const appOrigin = process.env.APP_ORIGIN;
const apiOrigin = process.env.API_ORIGIN;

test("the cross-origin SPA contract works through the real integration gateway", async ({
  page,
  context,
}) => {
  const pageErrors = [];
  const coreFailures = [];
  const apiRequests = [];
  const allRequests = [];
  let runtimeConfigCacheControl = "";

  await page.addInitScript(() => {
    window.__phaseBSecurityPolicyViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      window.__phaseBSecurityPolicyViolations.push(event.violatedDirective);
    });
  });

  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("request", (request) => {
    allRequests.push(request.url());
    if (["fetch", "xhr"].includes(request.resourceType())) {
      apiRequests.push(request.url());
    }
  });
  page.on("response", (response) => {
    const request = response.request();
    if (
      ["document", "script", "stylesheet"].includes(request.resourceType()) &&
      !response.ok()
    ) {
      coreFailures.push(request.url());
    }
    if (new URL(response.url()).pathname === "/runtime-config.js") {
      runtimeConfigCacheControl = response.headers()["cache-control"] ?? "";
    }
  });
  page.on("requestfailed", (request) => {
    if (["document", "script", "stylesheet"].includes(request.resourceType())) {
      coreFailures.push(request.url());
    }
  });

  const response = await page.goto(`${appOrigin}/login`, {
    waitUntil: "networkidle",
  });
  expect(response?.ok()).toBe(true);
  await expect(page.locator("#root")).not.toBeEmpty();

  const runtimeApiOrigin = await page.evaluate(
    () => window.__SECPAL_RUNTIME_CONFIG__?.apiBaseUrl,
  );
  expect(runtimeApiOrigin).toBe(apiOrigin);
  expect(
    await page.locator('script[src$=".js"], script[type="module"]').count(),
  ).toBeGreaterThan(0);
  expect(await page.locator('link[rel="stylesheet"]').count()).toBeGreaterThan(
    0,
  );
  expect(await page.locator("script:not([src])").count()).toBe(0);
  expect(await page.locator("style").count()).toBe(0);

  const registration = await page.evaluate(async () => {
    const ready = await navigator.serviceWorker.ready;
    return Boolean(ready.active);
  });
  expect(registration).toBe(true);

  const runtimeConfigCached = await page.evaluate(async () => {
    for (const cacheName of await caches.keys()) {
      const cache = await caches.open(cacheName);
      for (const request of await cache.keys()) {
        if (new URL(request.url).pathname === "/runtime-config.js") return true;
      }
    }
    return false;
  });
  expect(runtimeConfigCached).toBe(false);
  expect(runtimeConfigCacheControl).toContain("no-store");

  const handshake = await page.evaluate(async (origin) => {
    const csrfResponse = await fetch(`${origin}/sanctum/csrf-cookie`, {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    const cookie = document.cookie
      .split(";")
      .map((value) => value.trim())
      .find((value) => value.startsWith("XSRF-TOKEN="));
    if (!cookie) return { csrfStatus: csrfResponse.status, loginStatus: 0 };

    const token = decodeURIComponent(cookie.slice("XSRF-TOKEN=".length));
    const loginResponse = await fetch(`${origin}/v1/auth/login`, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-XSRF-TOKEN": token,
      },
      body: JSON.stringify({
        email: "phase-b@example.invalid",
        password: "CHANGEME",
      }),
    });
    return {
      csrfStatus: csrfResponse.status,
      loginStatus: loginResponse.status,
    };
  }, apiOrigin);

  expect(handshake.csrfStatus).toBe(204);
  expect(handshake.loginStatus).toBe(422);
  expect(handshake.loginStatus).not.toBe(419);

  const cookies = await context.cookies([appOrigin, apiOrigin]);
  const xsrfCookie = cookies.find((cookie) => cookie.name === "XSRF-TOKEN");
  const sessionCookie = cookies.find(
    (cookie) => cookie.name === "secpal-session",
  );
  expect(xsrfCookie).toMatchObject({
    domain: ".secpal.example.invalid",
    secure: true,
  });
  expect(sessionCookie).toMatchObject({
    domain: ".secpal.example.invalid",
    httpOnly: true,
    sameSite: "Lax",
    secure: true,
  });
  expect(
    cookies.every((cookie) =>
      cookie.domain.endsWith(".secpal.example.invalid"),
    ),
  ).toBe(true);

  expect(apiRequests.length).toBeGreaterThan(0);
  for (const requestUrl of apiRequests) {
    const requestOrigin = new URL(requestUrl).origin;
    expect(requestOrigin).toBe(apiOrigin);
  }
  for (const requestUrl of allRequests) {
    const requestHost = new URL(requestUrl).hostname;
    expect(requestHost).not.toBe("localhost");
    expect(requestHost).not.toBe("127.0.0.1");
    expect(requestHost).not.toBe("api.secpal.dev");
  }

  expect(pageErrors).toEqual([]);
  expect(coreFailures).toEqual([]);
  expect(
    await page.evaluate(() => window.__phaseBSecurityPolicyViolations),
  ).toEqual([]);
});
