import { expect, test } from '@playwright/test';

test('production dashboard mounts and switches views without browser errors', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  // Test rendering with deterministic local data; backend contracts have Go tests.
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const fixtures: Record<string, unknown> = {
      '/api/auth/providers': { providers: [] },
      '/api/status': { generated_at: '2026-09-14T00:00:00Z', danger: { signals: [] }, receipts: [] },
      '/api/saas/config': { enabled: false, mode: 'local' },
      '/api/saas/economics': null,
      '/api/saas/stripe-price': null
    };
    expect(path in fixtures, `unexpected API request: ${path}`).toBe(true);
    return route.fulfill({ json: fixtures[path] });
  });

  await page.goto('/');
  await expect(page).toHaveTitle('zt-gateway dashboard');
  await expect(page.getByRole('heading', { name: 'Scan Workspace Safety', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Findings Evidence Export', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Export JSON', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await page.getByRole('button', { name: 'Scan', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Scan Workspace Safety', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(page.locator('vite-error-overlay')).toHaveCount(0);
  expect(errors).toEqual([]);
});
