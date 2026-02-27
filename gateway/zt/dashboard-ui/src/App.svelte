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

  type FileHolderRow = {
    content_sha256: string;
    filename_sample: string;
    holder_client_count: number;
    holder_clients: string[];
    signature_count: number;
    exchange_count: number;
    last_seen_at: string;
  };

  type FileTimelinePoint = {
    bucket_start: string;
    holder_count: number;
    delta: number;
    added: number;
    removed: number;
    exchange_count: number;
  };

  type SaaSConfig = {
    mode: string;
    enabled: boolean;
    contract_title: string;
    currency: string;
    included_files: number;
    price_per_file_floor_usd: number;
    target_gross_margin: number;
    platform_fee_rate: number;
    trial_enabled: boolean;
    trial_files_per_user_per_month: number;
    trial_data_gb_per_user_per_month: number;
    trial_ad_revenue_per_user_usd: number;
    personal_free_max_file_mb: number;
    org_trial_min_files: number;
    org_trial_max_files: number;
    org_trial_max_file_mb: number;
    org_trial_duration_days: number;
    growth_max_file_mb: number;
    enterprise_max_file_mb: number;
  };

  type SaaSEconomics = {
    monthly_data_gb: number;
    monthly_signed_data_gb: number;
    variable_cost_usd: number;
    fixed_cost_usd: number;
    total_cost_usd: number;
    required_revenue_usd: number;
    recommended_revenue_usd: number;
    recommended_unit_price_usd: number;
    recommended_monthly_minimum_usd: number;
    break_even_files_at_floor: number;
    safe_file_size_threshold_mb: number;
    safe_files_per_month: number;
    tier: string;
    trial_applied: boolean;
    trial_subsidy_usd: number;
    trial_ad_revenue_usd: number;
    billable_files: number;
    required_paid_users_per_trial_user: number;
    monthly_reset: boolean;
  };

  type StripePrice = {
    currency: string;
    net_recommended_revenue_usd: number;
    gross_charge_usd: number;
    gross_unit_price_usd: number;
    stripe_fee_usd: number;
    stripe_fee_rate: number;
    stripe_fixed_fee_usd: number;
    billable_files: number;
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

  let tenantID = '';
  let dashboardToken = '';
  let lockReason = '';

  let keyID = '';
  let keyStatus = 'compromised';
  let keyReason = '';

  let repairKeyID = '';
  let repairSummary = '';
  let repairJobID = '';
  let repairState = 'contained';

  let incidentReason = '';
  let incidentAction = 'break_glass_start';

  let lastMutationResult = '';

  let fileFilter = '';
  let fileRows: FileHolderRow[] = [];
  let selectedContentSHA = '';
  let timelineWindowDays = 30;
  let fileTimeline: FileTimelinePoint[] = [];

  let saasConfig: SaaSConfig | null = null;
  let saasEconomics: SaaSEconomics | null = null;
  let stripePrice: StripePrice | null = null;
  let ecoFilesPerMonth = 10000;
  let ecoActiveUsers = 20;
  let ecoTrialUsers = 1;
  let ecoAvgFileMB = 8;
  let ecoRetentionDays = 30;

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
  $: freeTierMessage =
    saasEconomics?.trial_applied
      ? `Personal trial active (monthly reset=${saasEconomics.monthly_reset ? 'on' : 'off'})`
      : 'Paid user billing applies';

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

  async function fetchSaaSConfig(): Promise<void> {
    try {
      const res = await fetch('/api/saas/config', { cache: 'no-store' });
      if (!res.ok) {
        return;
      }
      saasConfig = (await res.json()) as SaaSConfig;
    } catch {
      saasConfig = null;
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
      if (!tenantID) {
        tenantID = String(
          snapshot?.clients?.tenant_id ??
            snapshot?.keys?.tenant_id ??
            snapshot?.signature_holders?.tenant_id ??
            ''
        );
      }
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

  function mutationHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (dashboardToken.trim()) {
      headers['X-ZT-Dashboard-Token'] = dashboardToken.trim();
    }
    return headers;
  }

  async function runMutation(path: string, body: Record<string, unknown>): Promise<void> {
    if (!tenantID.trim()) {
      showToast('tenant_id is required');
      return;
    }
    const url = path.includes('?') ? `${path}&tenant_id=${encodeURIComponent(tenantID)}` : `${path}?tenant_id=${encodeURIComponent(tenantID)}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: mutationHeaders(),
      body: JSON.stringify(body)
    });
    const text = await res.text();
    lastMutationResult = text;
    if (!res.ok) {
      showToast(`Mutation failed (${res.status})`);
      return;
    }
    showToast('Mutation applied');
    await refreshSnapshot(true);
    await fetchFileHolderMap();
  }

  async function submitLock(action: 'lock' | 'unlock'): Promise<void> {
    await runMutation('/api/lock', { action, reason: lockReason.trim() });
  }

  async function submitIncident(): Promise<void> {
    await runMutation('/api/incident', { action: incidentAction, reason: incidentReason.trim() });
  }

  async function submitKeyStatus(): Promise<void> {
    if (!keyID.trim()) {
      showToast('key_id is required');
      return;
    }
    await runMutation(`/api/keys/${encodeURIComponent(keyID.trim())}/status`, {
      status: keyStatus,
      reason: keyReason.trim(),
      actor: 'dashboard-ui'
    });
  }

  async function submitKeyRepairCreate(): Promise<void> {
    if (!repairKeyID.trim()) {
      showToast('key_id is required');
      return;
    }
    await runMutation('/api/key-repair/jobs', {
      key_id: repairKeyID.trim(),
      trigger: 'manual',
      operator: 'dashboard-ui',
      summary: repairSummary.trim(),
      runbook_id: 'docs/OPERATIONS.md#key-repair'
    });
  }

  async function submitKeyRepairTransition(): Promise<void> {
    if (!repairJobID.trim()) {
      showToast('job_id is required');
      return;
    }
    await runMutation(`/api/key-repair/jobs/${encodeURIComponent(repairJobID.trim())}/transition`, {
      state: repairState,
      operator: 'dashboard-ui',
      summary: repairSummary.trim(),
      runbook_id: 'docs/OPERATIONS.md#key-repair'
    });
  }

  async function fetchFileHolderMap(): Promise<void> {
    if (!tenantID.trim()) {
      return;
    }
    const q = fileFilter.trim();
    const res = await fetch(
      `/api/files/holders?tenant_id=${encodeURIComponent(tenantID)}&q=${encodeURIComponent(q)}&sort=holder_desc&page=1&page_size=30`,
      { cache: 'no-store' }
    );
    if (!res.ok) {
      return;
    }
    const body = (await res.json()) as { items?: FileHolderRow[] };
    fileRows = body.items ?? [];
    if (selectedContentSHA && !fileRows.some((row) => row.content_sha256 === selectedContentSHA)) {
      selectedContentSHA = '';
      fileTimeline = [];
    }
  }

  async function fetchFileHolderTimeline(contentSHA: string): Promise<void> {
    if (!tenantID.trim() || !contentSHA.trim()) {
      return;
    }
    const res = await fetch(
      `/api/files/holders/timeseries?tenant_id=${encodeURIComponent(tenantID)}&content_sha256=${encodeURIComponent(contentSHA)}&window_days=${timelineWindowDays}`,
      { cache: 'no-store' }
    );
    if (!res.ok) {
      return;
    }
    const body = (await res.json()) as { points?: FileTimelinePoint[] };
    selectedContentSHA = contentSHA;
    fileTimeline = body.points ?? [];
  }

  async function fetchSaaSEconomics(): Promise<void> {
    const query = new URLSearchParams({
      files_per_month: String(ecoFilesPerMonth),
      active_users: String(ecoActiveUsers),
      trial_users: String(ecoTrialUsers),
      avg_file_mb: String(ecoAvgFileMB),
      retention_days: String(ecoRetentionDays)
    });
    const res = await fetch(`/api/saas/economics?${query.toString()}`, { cache: 'no-store' });
    if (!res.ok) {
      return;
    }
    saasEconomics = (await res.json()) as SaaSEconomics;
    await fetchStripePrice();
  }

  async function fetchStripePrice(): Promise<void> {
    const query = new URLSearchParams({
      files_per_month: String(ecoFilesPerMonth),
      active_users: String(ecoActiveUsers),
      trial_users: String(ecoTrialUsers),
      avg_file_mb: String(ecoAvgFileMB),
      retention_days: String(ecoRetentionDays)
    });
    const res = await fetch(`/api/saas/stripe-price?${query.toString()}`, { cache: 'no-store' });
    if (!res.ok) {
      return;
    }
    stripePrice = (await res.json()) as StripePrice;
  }

  function downloadQuotePDF(): void {
    const query = new URLSearchParams({
      files_per_month: String(ecoFilesPerMonth),
      active_users: String(ecoActiveUsers),
      trial_users: String(ecoTrialUsers),
      avg_file_mb: String(ecoAvgFileMB),
      retention_days: String(ecoRetentionDays)
    });
    const anchor = document.createElement('a');
    anchor.href = `/api/saas/economics/quote.pdf?${query.toString()}`;
    anchor.download = `zt-saas-quote-${new Date().toISOString().slice(0, 10)}.pdf`;
    anchor.click();
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

    await Promise.all([fetchProviders(), refreshSnapshot(true), fetchSaaSConfig(), fetchSaaSEconomics()]);
    await fetchFileHolderMap();
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

  <section class="ops glass" in:fade={{ duration: 180 }}>
    <div class="ops-head">
      <h2>Abnormal Recovery Panel</h2>
      <p class="muted">tenant_id / mutation token を指定して、異常時オペレーションを実行</p>
    </div>
    <div class="form-row">
      <label>
        Tenant ID
        <input bind:value={tenantID} placeholder="tenant-a" />
      </label>
      <label>
        Dashboard Token (optional)
        <input bind:value={dashboardToken} placeholder="X-ZT-Dashboard-Token" />
      </label>
    </div>

    <div class="ops-grid">
      <article>
        <h3>Local Lock</h3>
        <input bind:value={lockReason} placeholder="incident reason" />
        <div class="btns">
          <button on:click={() => submitLock('lock')}>Lock</button>
          <button on:click={() => submitLock('unlock')}>Unlock</button>
        </div>
      </article>

      <article>
        <h3>Incident</h3>
        <select bind:value={incidentAction}>
          <option value="break_glass_start">break_glass_start</option>
          <option value="break_glass_end">break_glass_end</option>
          <option value="lock">lock</option>
          <option value="unlock">unlock</option>
        </select>
        <input bind:value={incidentReason} placeholder="incident reason" />
        <button on:click={submitIncident}>Record Incident</button>
      </article>

      <article>
        <h3>Key Status</h3>
        <input bind:value={keyID} placeholder="key_id" />
        <select bind:value={keyStatus}>
          <option value="active">active</option>
          <option value="rotating">rotating</option>
          <option value="revoked">revoked</option>
          <option value="compromised">compromised</option>
        </select>
        <input bind:value={keyReason} placeholder="reason" />
        <button on:click={submitKeyStatus}>Update Key Status</button>
      </article>

      <article>
        <h3>Key Repair</h3>
        <input bind:value={repairKeyID} placeholder="key_id (create)" />
        <input bind:value={repairSummary} placeholder="summary" />
        <button on:click={submitKeyRepairCreate}>Create Job</button>
        <input bind:value={repairJobID} placeholder="job_id (transition)" />
        <select bind:value={repairState}>
          <option value="detected">detected</option>
          <option value="contained">contained</option>
          <option value="rekeyed">rekeyed</option>
          <option value="rewrapped">rewrapped</option>
          <option value="completed">completed</option>
          <option value="failed">failed</option>
        </select>
        <button on:click={submitKeyRepairTransition}>Transition Job</button>
      </article>
    </div>
    <pre>{lastMutationResult}</pre>
  </section>

  <section class="grid" in:fade={{ duration: 180 }}>
    <article class="panel glass">
      <h3>Danger</h3>
      <p class="metric {dangerLevel}">{String(snapshot?.danger?.level ?? 'low').toUpperCase()}</p>
      <p class="muted">signals: {Number(snapshot?.danger?.count ?? 0)}</p>
    </article>

    <article class="panel glass">
      <h3>Local Lock</h3>
      <p class="metric">{snapshot?.lock?.locked ? 'LOCKED' : 'UNLOCKED'}</p>
      <p class="muted">{String(snapshot?.lock?.reason ?? 'No lock reason')}</p>
    </article>

    <article class="panel glass">
      <h3>KPI Verify Pass</h3>
      <p class="metric">{Number(snapshot?.kpi?.verify_pass_ratio ?? 0).toFixed(3)}</p>
      <p class="muted">audit invalid: {Number(snapshot?.kpi?.audit_invalid ?? 0)}</p>
    </article>

    <article class="panel glass">
      <h3>Alerts</h3>
      <p class="metric">{String(snapshot?.alerts?.level ?? 'low').toUpperCase()}</p>
      <p class="muted">items: {Number(snapshot?.alerts?.count ?? 0)}</p>
    </article>
  </section>

  <section class="holder-map glass" in:fly={{ y: 10, duration: 190 }}>
    <div class="ops-head">
      <h2>File -> Holder Map</h2>
      <p class="muted">同一コンテンツハッシュ単位で、どの client が保有しているかを可視化</p>
    </div>
    <div class="form-row">
      <label>
        Filter
        <input bind:value={fileFilter} placeholder="filename or sha256" />
      </label>
      <label>
        Timeline Days
        <input type="number" bind:value={timelineWindowDays} min="7" max="180" step="1" />
      </label>
      <button class="menu-btn" on:click={fetchFileHolderMap}>Refresh Map</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>sha256</th>
            <th>file</th>
            <th>holders</th>
            <th>signers</th>
            <th>exchanges</th>
            <th>last_seen</th>
            <th>timeline</th>
          </tr>
        </thead>
        <tbody>
          {#each fileRows as row}
            <tr>
              <td class="mono">{row.content_sha256}</td>
              <td>{row.filename_sample}</td>
              <td>{row.holder_client_count} ({row.holder_clients.join(', ')})</td>
              <td>{row.signature_count}</td>
              <td>{row.exchange_count}</td>
              <td>{row.last_seen_at}</td>
              <td>
                <button on:click={() => fetchFileHolderTimeline(row.content_sha256)}>
                  View
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if selectedContentSHA}
      <div class="timeline">
        <h3>Holder Timeline: {selectedContentSHA}</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>bucket</th>
                <th>holders</th>
                <th>delta</th>
                <th>added</th>
                <th>removed</th>
                <th>exchanges</th>
              </tr>
            </thead>
            <tbody>
              {#each fileTimeline as point}
                <tr>
                  <td>{point.bucket_start}</td>
                  <td>{point.holder_count}</td>
                  <td>{point.delta}</td>
                  <td>{point.added}</td>
                  <td>{point.removed}</td>
                  <td>{point.exchange_count}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {/if}
  </section>

  <section class="pricing glass" in:fly={{ y: 10, duration: 200 }}>
    <div class="ops-head">
      <h2>Contract & SaaS Economics</h2>
      <p class="muted">定数1つ（`ZT_DASHBOARD_SAAS_MODE=1`）で SaaS モード。企業無料枠は持たず、個人 trial 枠のみ数理試算。</p>
    </div>

    <div class="form-row">
      <label>
        Files / Month
        <input type="number" bind:value={ecoFilesPerMonth} min="1" step="100" />
      </label>
      <label>
        Active Users
        <input type="number" bind:value={ecoActiveUsers} min="1" step="1" />
      </label>
      <label>
        Trial Users (personal)
        <input type="number" bind:value={ecoTrialUsers} min="0" step="1" />
      </label>
      <label>
        Avg File Size MB
        <input type="number" bind:value={ecoAvgFileMB} min="0.1" step="0.5" />
      </label>
      <label>
        Retention Days
        <input type="number" bind:value={ecoRetentionDays} min="1" step="1" />
      </label>
      <button class="menu-btn" on:click={fetchSaaSEconomics}>Recalculate</button>
      <button class="menu-btn" on:click={downloadQuotePDF}>Estimate PDF</button>
    </div>

    <div class="contract-card">
      <p class="kicker">Contract Screen</p>
      <h3>{saasConfig?.contract_title ?? 'ZT Gateway SaaS Agreement'}</h3>
      <p class="muted">Mode: {saasConfig?.mode ?? 'local'} | Currency: {saasConfig?.currency ?? 'USD'}</p>
      <p class="muted">Included files: {saasConfig?.included_files ?? 0} / month</p>
      <p class="muted">Personal Free: {saasConfig?.trial_files_per_user_per_month ?? 0} files, {saasConfig?.personal_free_max_file_mb ?? 0}MB/file, {saasConfig?.trial_data_gb_per_user_per_month ?? 0}GB/user</p>
      <p class="muted">Org Trial: {saasConfig?.org_trial_min_files ?? 0}-{saasConfig?.org_trial_max_files ?? 0} files, {saasConfig?.org_trial_max_file_mb ?? 0}MB/file, {saasConfig?.org_trial_duration_days ?? 0} days</p>
      <p class="muted">Paid tiers: Growth {saasConfig?.growth_max_file_mb ?? 0}MB/file, Enterprise {saasConfig?.enterprise_max_file_mb ?? 0}MB/file</p>
      <p class="muted">{freeTierMessage}</p>
      {#if saasEconomics}
        <div class="contract-metrics">
          <p>Recommended monthly minimum: ${saasEconomics.recommended_monthly_minimum_usd}</p>
          <p>Recommended unit price: ${saasEconomics.recommended_unit_price_usd} / file</p>
          <p>Billable files: {saasEconomics.billable_files}</p>
          <p>Break-even files at floor: {saasEconomics.break_even_files_at_floor}</p>
          <p>Personal trial subsidy: ${saasEconomics.trial_subsidy_usd}</p>
          <p>Ad revenue from trial users: ${saasEconomics.trial_ad_revenue_usd}</p>
          <p>Required paid users per trial user: {saasEconomics.required_paid_users_per_trial_user}</p>
          <p>Safe threshold: {saasEconomics.safe_file_size_threshold_mb}MB x {saasEconomics.safe_files_per_month}/month ({saasEconomics.tier})</p>
        </div>
      {/if}
      {#if stripePrice}
        <div class="contract-metrics">
          <p>Stripe gross charge: ${stripePrice.gross_charge_usd}</p>
          <p>Stripe gross unit price: ${stripePrice.gross_unit_price_usd} / file</p>
          <p>Stripe fee: ${stripePrice.stripe_fee_usd} ({Math.round(stripePrice.stripe_fee_rate * 1000) / 10}%)</p>
        </div>
      {/if}
      <p class="muted">※ 無料運用は前提にせず、固定費 + 変動費 + 目標粗利 + プラットフォーム手数料で価格を算定。</p>
    </div>
  </section>

  <section class="detail glass" in:fly={{ y: 12, duration: 220 }}>
    <h3>{activeView === 'scan' ? 'Scan Signals' : 'Findings Evidence'}</h3>
    {#if activeView === 'scan'}
      <ul>
        {#each snapshot?.danger?.signals ?? [] as signal}
          <li>
            <strong>{signal.code}</strong>
            <span>{signal.message}</span>
          </li>
        {/each}
      </ul>
    {:else}
      <ul>
        {#each snapshot?.receipts ?? [] as rec}
          <li>
            <strong>{rec.client}</strong>
            <span>{rec.path}</span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  {#if baselineMessage}
    <p class="baseline" transition:fade={{ duration: 180 }}>{baselineMessage}</p>
  {/if}

  {#if errorMessage}
    <p class="error" transition:fade={{ duration: 180 }}>{errorMessage}</p>
  {/if}

  {#if loading}
    <section class="loading glass" in:fade={{ duration: 150 }}>Loading dashboard…</section>
  {/if}

  {#if toast}
    <aside class="toast" transition:fade={{ duration: 180 }}>{toast}</aside>
  {/if}
</main>
