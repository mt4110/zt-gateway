<script lang="ts">
  import { fade, fly } from 'svelte/transition';
  import { onDestroy, onMount } from 'svelte';

  type Provider = {
    id: string;
    label: string;
    issuer: string;
    enabled: boolean;
    disabled_why?: string;
  };

  type SSOSession = {
    provider: string;
    tokenType: string;
    accessToken: string;
    idToken: string;
    claims: Record<string, unknown>;
    expiresIn: number;
    loggedInAt: string;
  };

  const SSO_SESSION_KEY = 'zt_dashboard_sso_session_v1';

  let activeView: 'scan' | 'findings' = 'scan';
  let snapshot: Record<string, any> | null = null;
  let providers: Provider[] = [];
  let ssoSession: SSOSession | null = null;

  let loading = true;
  let refreshing = false;
  let secondaryOpen = false;
  let toast = '';
  let baselineMessage = '';
  let errorMessage = '';

  let toastTimer = 0;
  let pollTimer = 0;

  $: dangerLevel = String(snapshot?.danger?.level ?? 'low').toLowerCase();
  $: primaryLabel = activeView === 'scan' ? 'Start Scan' : 'Export Evidence';
  $: primaryDescription =
    activeView === 'scan'
      ? '現在のポリシー・監査・鍵状態を再取得して、危険信号を即時更新します。'
      : '監査提出向けに JSON evidence を1クリックで出力します。';

  $: ssoIdentity = (() => {
    const claims = ssoSession?.claims ?? {};
    return (
      String(claims.email ?? '') ||
      String(claims.preferred_username ?? '') ||
      String(claims.name ?? '') ||
      String(claims.sub ?? '') ||
      'authenticated'
    );
  })();

  function showToast(message: string): void {
    toast = message;
    if (toastTimer) {
      window.clearTimeout(toastTimer);
    }
    toastTimer = window.setTimeout(() => {
      toast = '';
    }, 2200);
  }

  function parseStoredSession(raw: string | null): SSOSession | null {
    if (!raw) {
      return null;
    }
    try {
      const parsed = JSON.parse(raw) as SSOSession;
      if (!parsed || !parsed.provider) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }

  function persistSession(session: SSOSession | null): void {
    if (!session) {
      localStorage.removeItem(SSO_SESSION_KEY);
      return;
    }
    localStorage.setItem(SSO_SESSION_KEY, JSON.stringify(session));
  }

  async function fetchProviders(): Promise<void> {
    try {
      const res = await fetch('/api/auth/providers', { cache: 'no-store' });
      if (!res.ok) {
        return;
      }
      const body = (await res.json()) as { providers?: Provider[] };
      providers = body.providers ?? [];
    } catch {
      providers = [];
    }
  }

  async function refreshSnapshot(silent = false): Promise<void> {
    if (refreshing) {
      return;
    }
    refreshing = true;
    if (!silent) {
      errorMessage = '';
    }
    try {
      const res = await fetch('/api/status', { cache: 'no-store' });
      if (!res.ok) {
        errorMessage = `status fetch failed: HTTP ${res.status}`;
        return;
      }
      snapshot = await res.json();
      if (!silent) {
        showToast('Dashboard updated');
      }
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : 'status fetch failed';
    } finally {
      refreshing = false;
      loading = false;
    }
  }

  function downloadBlob(name: string, body: string, type: string): void {
    const blob = new Blob([body], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function exportEvidenceJSON(): void {
    if (!snapshot) {
      showToast('Export target is empty');
      return;
    }
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    downloadBlob(`zt-evidence-${ts}.json`, JSON.stringify(snapshot, null, 2), 'application/json');
    showToast('Evidence JSON exported');
  }

  function exportEvidenceHTML(): void {
    if (!snapshot) {
      showToast('Export target is empty');
      return;
    }
    const title = 'zt-gateway Findings Report';
    const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>${title}</title><style>body{font-family:-apple-system,system-ui;padding:24px;background:#f5f6f8;color:#0f172a}h1{margin:0 0 8px}pre{white-space:pre-wrap;background:#fff;border:1px solid #dbe0e7;padding:16px;border-radius:12px}</style></head><body><h1>${title}</h1><p>generated_at=${String(snapshot.generated_at ?? '')}</p><pre>${JSON.stringify(snapshot, null, 2).replace(/</g, '&lt;')}</pre></body></html>`;
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    downloadBlob(`zt-findings-${ts}.html`, html, 'text/html; charset=utf-8');
    showToast('Findings HTML exported');
  }

  function createBaseline(): void {
    const ok = window.confirm('Create Baseline は危険操作です。実行前に必ず commit してください。続行しますか？');
    if (!ok) {
      return;
    }
    baselineMessage = 'Baseline creation queued. 先に commit された状態で実行してください。';
    showToast('Baseline flow prepared');
  }

  async function runPrimaryAction(): Promise<void> {
    if (activeView === 'scan') {
      await refreshSnapshot();
      return;
    }
    exportEvidenceJSON();
  }

  function startSSO(providerId: string): void {
    secondaryOpen = false;
    const popup = window.open(
      `/api/auth/login?provider=${encodeURIComponent(providerId)}`,
      'zt-sso-login',
      'popup=yes,width=540,height=760'
    );
    if (!popup) {
      showToast('Popup blocked. Please allow popups for localhost.');
    }
  }

  function clearSession(): void {
    ssoSession = null;
    persistSession(null);
    showToast('Signed out');
  }

  function onSSOResult(event: MessageEvent): void {
    if (event.origin !== window.location.origin) {
      return;
    }
    const data = event.data as { type?: string; payload?: Record<string, any> };
    if (!data || data.type !== 'zt-sso-result') {
      return;
    }
    const payload = data.payload ?? {};
    if (!payload.ok) {
      showToast(`SSO failed: ${String(payload.error ?? 'unknown_error')}`);
      return;
    }
    const session: SSOSession = {
      provider: String(payload.provider ?? 'unknown'),
      tokenType: String(payload.token_type ?? 'Bearer'),
      accessToken: String(payload.access_token ?? ''),
      idToken: String(payload.id_token ?? ''),
      claims: (payload.claims as Record<string, unknown>) ?? {},
      expiresIn: Number(payload.expires_in ?? 0),
      loggedInAt: new Date().toISOString()
    };
    ssoSession = session;
    persistSession(session);
    showToast(`${session.provider} SSO connected`);
  }

  onMount(async () => {
    ssoSession = parseStoredSession(localStorage.getItem(SSO_SESSION_KEY));
    window.addEventListener('message', onSSOResult);

    await Promise.all([fetchProviders(), refreshSnapshot(true)]);
    loading = false;

    pollTimer = window.setInterval(() => {
      void refreshSnapshot(true);
    }, 10000);
  });

  onDestroy(() => {
    window.removeEventListener('message', onSSOResult);
    if (toastTimer) {
      window.clearTimeout(toastTimer);
    }
    if (pollTimer) {
      window.clearInterval(pollTimer);
    }
  });
</script>

<div class="canvas"></div>
<main class="shell" in:fade={{ duration: 180 }}>
  <header class="top glass" in:fly={{ y: -8, duration: 180 }}>
    <div>
      <p class="kicker">ZT Gateway</p>
      <h1>Operations Dashboard</h1>
      <p class="muted">{snapshot?.generated_at ? `Last update ${snapshot.generated_at}` : 'Live snapshot'}</p>
    </div>

    <div class="top-right">
      <div class="view-toggle" role="tablist" aria-label="Screen">
        <button class:active={activeView === 'scan'} on:click={() => (activeView = 'scan')}>Scan</button>
        <button class:active={activeView === 'findings'} on:click={() => (activeView = 'findings')}>Findings</button>
      </div>

      <div class="identity">
        {#if ssoSession}
          <p class="identity-main">{ssoIdentity}</p>
          <p class="identity-sub">{ssoSession.provider.toUpperCase()} SSO</p>
        {:else}
          <p class="identity-main">Not signed in</p>
          <p class="identity-sub">Google / Apple / iCloud</p>
        {/if}
      </div>

      <div class="menu-wrap">
        <button class="menu-btn" on:click={() => (secondaryOpen = !secondaryOpen)}>More</button>
        {#if secondaryOpen}
          <div class="menu" transition:fade={{ duration: 150 }}>
            <button on:click={exportEvidenceJSON}>Export JSON</button>
            <button on:click={exportEvidenceHTML}>Export HTML</button>
            <button class="danger" on:click={createBaseline}>Create Baseline (commit first)</button>
          </div>
        {/if}
      </div>
    </div>
  </header>

  {#if !ssoSession}
    <section class="login glass" in:fly={{ y: 8, duration: 180 }}>
      <div>
        <h2>SSO Login</h2>
        <p class="muted">Control Plane連携を前提に OAuth SSO でログインします。</p>
      </div>
      <div class="provider-list">
        {#each providers as provider}
          <button
            class="provider-btn"
            disabled={!provider.enabled}
            on:click={() => startSSO(provider.id)}
            title={provider.enabled ? provider.issuer : provider.disabled_why ?? 'disabled'}
          >
            Continue with {provider.label}
          </button>
        {/each}
      </div>
      {#if providers.length === 0}
        <p class="muted">SSO provider config is missing (`ZT_DASHBOARD_SSO_*`).</p>
      {/if}
    </section>
  {:else}
    <section class="login glass" in:fly={{ y: 8, duration: 180 }}>
      <div>
        <h2>SSO Session</h2>
        <p class="muted">Bearer token is active in this browser session.</p>
      </div>
      <div class="session-row">
        <code>{ssoSession.tokenType} {ssoSession.accessToken ? `${ssoSession.accessToken.slice(0, 16)}...` : '(id_token only)'}</code>
        <button class="menu-btn" on:click={clearSession}>Sign out</button>
      </div>
    </section>
  {/if}

  <section class="hero glass" in:fly={{ y: 10, duration: 200 }}>
    <div>
      <p class="kicker">Primary Action</p>
      <h2>{activeView === 'scan' ? 'Scan Workspace Safety' : 'Findings Evidence Export'}</h2>
      <p class="muted">{primaryDescription}</p>
    </div>
    <button class="primary" on:click={runPrimaryAction} disabled={refreshing}>
      {refreshing ? 'Processing…' : primaryLabel}
    </button>
  </section>

  {#if baselineMessage}
    <p class="baseline" transition:fade={{ duration: 180 }}>{baselineMessage}</p>
  {/if}

  {#if errorMessage}
    <p class="error" transition:fade={{ duration: 180 }}>{errorMessage}</p>
  {/if}

  {#if loading}
    <section class="loading glass" in:fade={{ duration: 150 }}>Loading dashboard…</section>
  {:else if snapshot}
    <section class="grid" in:fade={{ duration: 180 }}>
      <article class="panel glass">
        <h3>Danger</h3>
        <p class="metric {dangerLevel}">{String(snapshot.danger?.level ?? 'low').toUpperCase()}</p>
        <p class="muted">signals: {Number(snapshot.danger?.count ?? 0)}</p>
      </article>

      <article class="panel glass">
        <h3>Local Lock</h3>
        <p class="metric">{snapshot.lock?.locked ? 'LOCKED' : 'UNLOCKED'}</p>
        <p class="muted">{String(snapshot.lock?.reason ?? 'No lock reason')}</p>
      </article>

      <article class="panel glass">
        <h3>KPI Verify Pass</h3>
        <p class="metric">{Number(snapshot.kpi?.verify_pass_ratio ?? 0).toFixed(3)}</p>
        <p class="muted">audit invalid: {Number(snapshot.kpi?.audit_invalid ?? 0)}</p>
      </article>

      <article class="panel glass">
        <h3>Alerts</h3>
        <p class="metric">{String(snapshot.alerts?.level ?? 'low').toUpperCase()}</p>
        <p class="muted">items: {Number(snapshot.alerts?.count ?? 0)}</p>
      </article>
    </section>

    <section class="detail glass" in:fly={{ y: 12, duration: 220 }}>
      <h3>{activeView === 'scan' ? 'Scan Signals' : 'Findings Evidence'}</h3>
      {#if activeView === 'scan'}
        <ul>
          {#each snapshot.danger?.signals ?? [] as signal}
            <li>
              <strong>{signal.code}</strong>
              <span>{signal.message}</span>
            </li>
          {/each}
        </ul>
      {:else}
        <ul>
          {#each snapshot.receipts ?? [] as rec}
            <li>
              <strong>{rec.client}</strong>
              <span>{rec.path}</span>
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  {/if}

  {#if toast}
    <aside class="toast" transition:fade={{ duration: 180 }}>{toast}</aside>
  {/if}
</main>
