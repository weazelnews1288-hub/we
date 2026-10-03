// Cloudflare Pages Function. Нужны: KV-привязка SITE, секреты ADMINS и SECRET.
// ADMINS = "anna:пароль1,ivan:пароль2"   SECRET = любая длинная случайная строка
const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
async function hmac(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const admins = (env) => Object.fromEntries((env.ADMINS || '').split(',').map((x) => x.trim()).filter(Boolean).map((x) => { const i = x.indexOf(':'); return [x.slice(0, i), x.slice(i + 1)]; }));
const json = (o, code = 200, h = {}) => new Response(JSON.stringify(o), { status: code, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...h } });

async function userOf(req, env) {
  const m = /(?:^|; )sid=([^;]+)/.exec(req.headers.get('Cookie') || ''); if (!m) return null;
  const [p, s] = m[1].split('.'); if (!p || !s || !same(await hmac(env.SECRET, p), s)) return null;
  try { const o = JSON.parse(new TextDecoder().decode(unb64u(p))); return o.e > Date.now() && admins(env)[o.u] !== undefined ? o.u : null; } catch { return null; }
}

export async function onRequest({ request, env }) {
  if (!env.SITE || !env.SECRET) return json({ error: 'Не настроены KV-привязка SITE или секрет SECRET' }, 500);
  const path = new URL(request.url).pathname.replace(/\/$/, ''), m = request.method;
  try {
    if (path === '/api/config' && m === 'GET') { const v = await env.SITE.get('config'); return new Response(v || 'null', { headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } }); }
    if (path === '/api/config' && m === 'PUT') {
      const user = await userOf(request, env); if (!user) return json({ error: 'auth' }, 401);
      const raw = await request.text(); if (raw.length > 24e6) return json({ error: 'Слишком большой (макс. ~24 МБ)' }, 413);
      JSON.parse(raw);
      const prev = await env.SITE.get('config'); if (prev) await env.SITE.put('config_backup', prev); // 2 записи на сохранение
      await env.SITE.put('config', raw);
      return json({ ok: true, by: user });
    }
    if (path === '/api/me') return json({ user: await userOf(request, env) });
    if (path === '/api/login' && m === 'POST') {
      const { login, password } = await request.json(), pw = admins(env)[String(login)];
      if (pw === undefined || !same(await hmac(env.SECRET, String(password)), await hmac(env.SECRET, pw))) return json({ error: 'Неверный логин или пароль' }, 401);
      const p = b64u(enc.encode(JSON.stringify({ u: login, e: Date.now() + 30 * 864e5 })));
      return json({ user: login }, 200, { 'Set-Cookie': `sid=${p}.${await hmac(env.SECRET, p)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000` });
    }
    if (path === '/api/logout') return json({ ok: true }, 200, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
    return json({ error: 'not found' }, 404);
  } catch (e) { return json({ error: String(e.message) }, 400); }
}
