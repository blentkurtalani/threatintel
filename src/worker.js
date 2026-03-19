// ============================================================
// Straybit Threat Intel — Cloudflare Worker
// Handles: OAuth, API proxy, rate limiting, D1 storage
// Static frontend served via [assets] in wrangler.toml
// ============================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Only handle /api/* routes — static assets handled by CF automatically
    if (!path.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    const corsHeaders = {
      'Access-Control-Allow-Origin': url.origin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // ── Public Auth Routes ──
      if (path === '/api/auth/google') return handleGoogleAuth(url, env);
      if (path === '/api/auth/google/callback') return handleGoogleCallback(url, env);
      if (path === '/api/auth/github') return handleGithubAuth(url, env);
      if (path === '/api/auth/github/callback') return handleGithubCallback(url, env);
      if (path === '/api/auth/logout') return handleLogout(request, env, corsHeaders);

      // ── Authenticated Routes ──
      const user = await authenticate(request, env);
      if (!user) {
        return json({ error: 'Unauthorized', message: 'Please sign in' }, 401, corsHeaders);
      }

      if (path === '/api/user/profile' && request.method === 'GET') {
        return json({ user }, 200, corsHeaders);
      }
      if (path === '/api/user/profile' && request.method === 'PUT') {
        return handleProfileUpdate(request, user, env, corsHeaders);
      }
      if (path === '/api/user/usage') {
        return handleUsageCheck(user, env, corsHeaders);
      }

      // ── Rate-limited Search Routes ──
      const withinLimit = await checkRateLimit(user, env);
      if (!withinLimit && path.startsWith('/api/search/')) {
        return json({
          error: 'Rate limit exceeded',
          message: `You've used all ${user.daily_limit} searches today. Resets at midnight UTC.`,
        }, 429, corsHeaders);
      }

      if (path === '/api/search/ip') return handleIPSearch(url, user, env, corsHeaders);
      if (path === '/api/search/domain') return handleDomainSearch(url, user, env, corsHeaders);
      if (path === '/api/search/cve') return handleCVESearch(url, user, env, corsHeaders);
      if (path === '/api/search/phishing') return handlePhishingCheck(url, user, env, corsHeaders);
      if (path === '/api/search/feeds') return handleFeedSearch(url, user, env, corsHeaders);

      return json({ error: 'Not found' }, 404, corsHeaders);
    } catch (err) {
      console.error('Worker error:', err);
      return json({ error: 'Internal server error', detail: err.message }, 500, corsHeaders);
    }
  }
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function json(data, status = 200, corsHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

function generateId() {
  return crypto.randomUUID();
}

function getOrigin(url) {
  return `${url.protocol}//${url.host}`;
}

// ── Auth ─────────────────────────────────────────────────────────────────────

async function authenticate(request, env) {
  // Check cookie first, then Authorization header
  const cookieToken = getCookie(request, 'sb_session');
  const headerToken = request.headers.get('Authorization')?.replace('Bearer ', '');
  const token = cookieToken || headerToken;
  if (!token) return null;

  const session = await env.DB.prepare(
    `SELECT s.user_id, u.id, u.email, u.name, u.avatar_url, u.tier, u.daily_limit,
            u.profile_completed, u.company_name, u.job_title, u.industry
     FROM sessions s JOIN users u ON s.user_id = u.id
     WHERE s.id = ? AND s.expires_at > datetime("now")`
  ).bind(token).first();

  return session || null;
}

function getCookie(request, name) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

function sessionCookie(token, origin) {
  const secure = origin.startsWith('https') ? '; Secure' : '';
  return `sb_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure}`;
}

// ── Google OAuth ─────────────────────────────────────────────────────────────

function handleGoogleAuth(url, env) {
  const origin = getOrigin(url);
  const redirectUri = `${origin}/api/auth/google/callback`;
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('access_type', 'offline');
  return Response.redirect(authUrl.toString(), 302);
}

async function handleGoogleCallback(url, env) {
  const code = url.searchParams.get('code');
  const origin = getOrigin(url);
  if (!code) return Response.redirect(`${origin}/?error=missing_code`, 302);

  const redirectUri = `${origin}/api/auth/google/callback`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });
  const tokens = await tokenRes.json();
  if (!tokens.access_token) return Response.redirect(`${origin}/?error=google_auth_failed`, 302);

  const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const gUser = await userRes.json();

  const sessionToken = await upsertUserAndCreateSession(env, {
    email: gUser.email,
    name: gUser.name,
    avatar_url: gUser.picture,
    oauth_provider: 'google',
    oauth_id: String(gUser.id),
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${origin}/?login=success`,
      'Set-Cookie': sessionCookie(sessionToken, origin),
    },
  });
}

// ── GitHub OAuth ─────────────────────────────────────────────────────────────

function handleGithubAuth(url, env) {
  const origin = getOrigin(url);
  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', `${origin}/api/auth/github/callback`);
  authUrl.searchParams.set('scope', 'read:user user:email');
  return Response.redirect(authUrl.toString(), 302);
}

async function handleGithubCallback(url, env) {
  const code = url.searchParams.get('code');
  const origin = getOrigin(url);
  if (!code) return Response.redirect(`${origin}/?error=missing_code`, 302);

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });
  const tokens = await tokenRes.json();
  if (!tokens.access_token) return Response.redirect(`${origin}/?error=github_auth_failed`, 302);

  const userRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${tokens.access_token}`, 'User-Agent': 'Straybit-TI' },
  });
  const ghUser = await userRes.json();

  let email = ghUser.email;
  if (!email) {
    const emailRes = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${tokens.access_token}`, 'User-Agent': 'Straybit-TI' },
    });
    const emails = await emailRes.json();
    email = emails.find(e => e.primary)?.email || emails[0]?.email;
  }

  const sessionToken = await upsertUserAndCreateSession(env, {
    email,
    name: ghUser.name || ghUser.login,
    avatar_url: ghUser.avatar_url,
    oauth_provider: 'github',
    oauth_id: String(ghUser.id),
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${origin}/?login=success`,
      'Set-Cookie': sessionCookie(sessionToken, origin),
    },
  });
}

// ── Shared Auth ──────────────────────────────────────────────────────────────

async function upsertUserAndCreateSession(env, profile) {
  const existing = await env.DB.prepare(
    'SELECT id FROM users WHERE oauth_provider = ? AND oauth_id = ?'
  ).bind(profile.oauth_provider, profile.oauth_id).first();

  let userId;
  if (existing) {
    userId = existing.id;
    await env.DB.prepare(
      'UPDATE users SET name = ?, avatar_url = ?, last_login_at = datetime("now"), updated_at = datetime("now") WHERE id = ?'
    ).bind(profile.name, profile.avatar_url, userId).run();
  } else {
    userId = generateId();
    await env.DB.prepare(
      'INSERT INTO users (id, email, name, avatar_url, oauth_provider, oauth_id) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(userId, profile.email, profile.name, profile.avatar_url, profile.oauth_provider, profile.oauth_id).run();
  }

  const sessionId = generateId();
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, datetime("now", "+7 days"))'
  ).bind(sessionId, userId).run();

  // Cleanup expired sessions
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < datetime("now")').run();

  return sessionId;
}

async function handleLogout(request, env, corsHeaders) {
  const token = getCookie(request, 'sb_session');
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'sb_session=; Path=/; HttpOnly; Max-Age=0',
      ...corsHeaders,
    },
  });
}

// ── Profile ──────────────────────────────────────────────────────────────────

async function handleProfileUpdate(request, user, env, corsHeaders) {
  const body = await request.json();
  const { company_name, company_size, job_title, phone, industry, use_case } = body;
  await env.DB.prepare(`
    UPDATE users SET company_name=?, company_size=?, job_title=?, phone=?, industry=?, use_case=?,
    profile_completed=1, updated_at=datetime("now") WHERE id=?
  `).bind(company_name||null, company_size||null, job_title||null, phone||null, industry||null, use_case||null, user.id).run();
  return json({ success: true }, 200, corsHeaders);
}

// ── Rate Limiting ────────────────────────────────────────────────────────────

async function checkRateLimit(user, env) {
  const today = new Date().toISOString().split('T')[0];
  const usage = await env.DB.prepare(
    'SELECT search_count FROM usage_tracking WHERE user_id = ? AND date = ?'
  ).bind(user.id, today).first();
  return !usage || usage.search_count < user.daily_limit;
}

async function incrementUsage(userId, env) {
  const today = new Date().toISOString().split('T')[0];
  await env.DB.prepare(`
    INSERT INTO usage_tracking (user_id, date, search_count) VALUES (?, ?, 1)
    ON CONFLICT(user_id, date) DO UPDATE SET search_count = search_count + 1
  `).bind(userId, today).run();
}

async function handleUsageCheck(user, env, corsHeaders) {
  const today = new Date().toISOString().split('T')[0];
  const usage = await env.DB.prepare(
    'SELECT search_count FROM usage_tracking WHERE user_id = ? AND date = ?'
  ).bind(user.id, today).first();
  return json({
    used: usage?.search_count || 0,
    limit: user.daily_limit,
    remaining: user.daily_limit - (usage?.search_count || 0),
    tier: user.tier,
  }, 200, corsHeaders);
}

// ── Search Logging ───────────────────────────────────────────────────────────

async function logSearch(env, userId, query, queryType, resultSummary, sources, elapsed) {
  await env.DB.prepare(
    'INSERT INTO search_logs (user_id, query, query_type, result_summary, sources_queried, response_time_ms) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(userId, query, queryType, resultSummary, JSON.stringify(sources), elapsed).run();
}

// ── IP Search ────────────────────────────────────────────────────────────────

async function handleIPSearch(url, user, env, corsHeaders) {
  const ip = url.searchParams.get('q');
  if (!ip) return json({ error: 'Missing ?q= parameter' }, 400, corsHeaders);

  const start = Date.now();
  const results = {};
  const sources = [];

  // AbuseIPDB
  if (env.ABUSEIPDB_KEY) {
    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`, {
        headers: { Key: env.ABUSEIPDB_KEY, Accept: 'application/json' },
      });
      results.abuseipdb = await res.json();
      sources.push('abuseipdb');
    } catch (e) { results.abuseipdb = { error: e.message }; }
  }

  // VirusTotal
  if (env.VIRUSTOTAL_KEY) {
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
        headers: { 'x-apikey': env.VIRUSTOTAL_KEY },
      });
      results.virustotal = await res.json();
      sources.push('virustotal');
    } catch (e) { results.virustotal = { error: e.message }; }
  }

  // Shodan
  if (env.SHODAN_KEY) {
    try {
      const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${env.SHODAN_KEY}`);
      results.shodan = await res.json();
      sources.push('shodan');
    } catch (e) { results.shodan = { error: e.message }; }
  }

  // IPinfo (free, no key)
  try {
    const res = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`);
    results.ipinfo = await res.json();
    sources.push('ipinfo');
  } catch (e) { results.ipinfo = { error: e.message }; }

  const elapsed = Date.now() - start;
  const summary = results.abuseipdb?.data
    ? `score:${results.abuseipdb.data.abuseConfidenceScore},reports:${results.abuseipdb.data.totalReports}`
    : 'completed';

  await logSearch(env, user.id, ip, 'ip', summary, sources, elapsed);
  await incrementUsage(user.id, env);

  return json({ query: ip, type: 'ip', results, sources, response_time_ms: elapsed }, 200, corsHeaders);
}

// ── Domain Search ────────────────────────────────────────────────────────────

async function handleDomainSearch(url, user, env, corsHeaders) {
  const domain = url.searchParams.get('q');
  if (!domain) return json({ error: 'Missing ?q= parameter' }, 400, corsHeaders);

  const start = Date.now();
  const results = {};
  const sources = [];

  if (env.VIRUSTOTAL_KEY) {
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
        headers: { 'x-apikey': env.VIRUSTOTAL_KEY },
      });
      results.virustotal = await res.json();
      sources.push('virustotal');
    } catch (e) { results.virustotal = { error: e.message }; }
  }

  if (env.OTX_KEY) {
    try {
      const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`, {
        headers: { 'X-OTX-API-KEY': env.OTX_KEY },
      });
      results.otx = await res.json();
      sources.push('otx');
    } catch (e) { results.otx = { error: e.message }; }
  }

  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `host=${encodeURIComponent(domain)}`,
    });
    results.urlhaus = await res.json();
    sources.push('urlhaus');
  } catch (e) { results.urlhaus = { error: e.message }; }

  const elapsed = Date.now() - start;
  await logSearch(env, user.id, domain, 'domain', 'completed', sources, elapsed);
  await incrementUsage(user.id, env);

  return json({ query: domain, type: 'domain', results, sources, response_time_ms: elapsed }, 200, corsHeaders);
}

// ── CVE Search ───────────────────────────────────────────────────────────────

async function handleCVESearch(url, user, env, corsHeaders) {
  const query = url.searchParams.get('q');
  if (!query) return json({ error: 'Missing ?q= parameter' }, 400, corsHeaders);

  const start = Date.now();
  const results = {};
  const sources = [];

  // NVD (free, no key needed)
  try {
    const isCve = /^CVE-\d{4}-\d+$/i.test(query);
    const nvdUrl = isCve
      ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(query)}`
      : `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=20`;
    const res = await fetch(nvdUrl);
    results.nvd = await res.json();
    sources.push('nvd');
  } catch (e) { results.nvd = { error: e.message }; }

  // CISA KEV
  try {
    const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    const kev = await res.json();
    const id = query.toUpperCase();
    results.cisa_kev = {
      in_kev: kev.vulnerabilities?.some(v => v.cveID === id),
      kev_entry: kev.vulnerabilities?.find(v => v.cveID === id) || null,
      catalog_count: kev.vulnerabilities?.length || 0,
    };
    sources.push('cisa_kev');
  } catch (e) { results.cisa_kev = { error: e.message }; }

  const elapsed = Date.now() - start;
  await logSearch(env, user.id, query, 'cve', 'completed', sources, elapsed);
  await incrementUsage(user.id, env);

  return json({ query, type: 'cve', results, sources, response_time_ms: elapsed }, 200, corsHeaders);
}

// ── Phishing Check ───────────────────────────────────────────────────────────

async function handlePhishingCheck(url, user, env, corsHeaders) {
  const target = url.searchParams.get('q');
  if (!target) return json({ error: 'Missing ?q= parameter' }, 400, corsHeaders);

  const start = Date.now();
  const results = {};
  const sources = [];

  // Google Safe Browsing
  if (env.GOOGLE_SAFEBROWSING_KEY) {
    try {
      const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${env.GOOGLE_SAFEBROWSING_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'straybit-ti', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: target }],
          },
        }),
      });
      results.google_safe_browsing = await res.json();
      sources.push('google_safe_browsing');
    } catch (e) { results.google_safe_browsing = { error: e.message }; }
  }

  // URLhaus
  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(target)}`,
    });
    results.urlhaus = await res.json();
    sources.push('urlhaus');
  } catch (e) { results.urlhaus = { error: e.message }; }

  // VirusTotal
  if (env.VIRUSTOTAL_KEY) {
    try {
      const vtUrlId = btoa(target).replace(/=/g, '');
      const res = await fetch(`https://www.virustotal.com/api/v3/urls/${vtUrlId}`, {
        headers: { 'x-apikey': env.VIRUSTOTAL_KEY },
      });
      results.virustotal = await res.json();
      sources.push('virustotal');
    } catch (e) { results.virustotal = { error: e.message }; }
  }

  const elapsed = Date.now() - start;
  await logSearch(env, user.id, target, 'phishing', 'completed', sources, elapsed);
  await incrementUsage(user.id, env);

  return json({ query: target, type: 'phishing', results, sources, response_time_ms: elapsed }, 200, corsHeaders);
}

// ── Feed Search ──────────────────────────────────────────────────────────────

async function handleFeedSearch(url, user, env, corsHeaders) {
  const feed = url.searchParams.get('feed') || 'urlhaus';
  const start = Date.now();
  const results = {};

  if (feed === 'urlhaus' || feed === 'all') {
    try {
      const res = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/25/', { method: 'POST' });
      results.urlhaus = await res.json();
    } catch (e) { results.urlhaus = { error: e.message }; }
  }

  if (feed === 'feodo' || feed === 'all') {
    try {
      const res = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json');
      results.feodo = await res.json();
    } catch (e) { results.feodo = { error: e.message }; }
  }

  if (feed === 'cisa_kev' || feed === 'all') {
    try {
      const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      const data = await res.json();
      results.cisa_kev = { count: data.vulnerabilities?.length, latest: data.vulnerabilities?.slice(-10) };
    } catch (e) { results.cisa_kev = { error: e.message }; }
  }

  const elapsed = Date.now() - start;
  await logSearch(env, user.id, feed, 'feed', 'completed', [feed], elapsed);

  return json({ feed, results, response_time_ms: elapsed }, 200, corsHeaders);
}
