// KEY SCANNER v1.1 · github.com/faheemsaleem/supabase-leak-check · MIT
// What it does: reads the JavaScript YOUR live site has sent to this browser tab,
// and looks for secret keys that should never be there. It sends nothing anywhere.
//
// How to use:
//   1. Open your LIVE app (not the editor preview) and log in.
//   2. Click through every page and feature once, especially AI features, payments and admin pages.
//      Modern apps load code page by page; the scanner only sees code this tab has loaded.
//   3. Press F12 (Mac: Cmd+Option+I), click "Console", paste this whole file, press Enter.
//      If Chrome refuses the paste, type "allow pasting", press Enter, and paste again.
(async () => {
  // A key must not be glued to other letters/digits/dashes on the left, so ordinary
  // words like "task-list-item-container" don't count. Most specific patterns first.
  const L = '(?<![A-Za-z0-9_\\-])';
  const P = (s) => new RegExp(L + s, 'g');
  const PATTERNS = [
    // [name, regex, severity, where to go]
    ['Supabase SECRET key', P('sb_secret_[A-Za-z0-9_\\-]{20,}'), 'CRITICAL', 'Hole #3'],
    ['Anthropic key', P('sk-ant-[A-Za-z0-9_\\-]{30,}'), 'CRITICAL', 'Hole #2 (roll it at console.anthropic.com)'],
    ['OpenRouter key', P('sk-or-v1-[a-f0-9]{40,}'), 'CRITICAL', 'Hole #2 (roll it at openrouter.ai)'],
    ['OpenAI key', P('sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\\-]{40,}'), 'CRITICAL', 'Hole #2 (roll it at platform.openai.com)'],
    ['OpenAI key (old format)', P('sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'), 'CRITICAL', 'Hole #2 (roll it at platform.openai.com)'],
    ['sk- key (DeepSeek or other OpenAI-compatible)', P('sk-[a-f0-9]{32}(?![A-Za-z0-9])'), 'CRITICAL', 'Hole #2 (roll it at the AI provider you use)'],
    ['Stripe or Clerk SECRET key', P('(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}'), 'CRITICAL', 'Hole #2 (check which service: Stripe dashboard or Clerk dashboard)'],
    ['Groq key', P('gsk_[A-Za-z0-9]{40,}'), 'CRITICAL', 'Hole #2'],
    ['xAI key', P('xai-[A-Za-z0-9]{40,}'), 'CRITICAL', 'Hole #2'],
    ['Hugging Face token', P('hf_[A-Za-z0-9]{30,}'), 'CRITICAL', 'Hole #2'],
    ['Replicate token', P('r8_[A-Za-z0-9]{30,}'), 'CRITICAL', 'Hole #2'],
    ['Resend key', P('re_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}'), 'CRITICAL', 'Hole #2'],
    ['SendGrid key', P('SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}'), 'CRITICAL', 'Hole #2'],
    ['GitHub token', P('(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})'), 'CRITICAL', 'Hole #2'],
    ['AWS access key', P('(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])'), 'CRITICAL', 'Hole #2'],
    ['Google API key', P('AIza[0-9A-Za-z_\\-]{35}'), 'CHECK', 'Fine for Firebase/Maps if restricted in Google Cloud; NOT fine for Gemini. Hole #2'],
  ];
  const JWT = new RegExp(L + 'eyJ[A-Za-z0-9_\\-]{10,}\\.eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}', 'g');
  const mask = s => s.slice(0, 10) + '…' + s.slice(-4) + ` (${s.length} chars)`;
  const decode = part => { try { return JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/'))); } catch { return null; } };
  const short = u => (u.split('/').pop() || u).split('?')[0];

  const urls = new Set();
  document.querySelectorAll('script[src]').forEach(s => urls.add(s.src));
  const entries = performance.getEntriesByType('resource');
  entries.forEach(r => { if (/\.m?js(\?|$)/.test(r.name)) urls.add(r.name); });
  const listFull = entries.length >= 240;
  const sources = [{ where: 'inline <script> tags', text: [...document.querySelectorAll('script:not([src])')].map(s => s.textContent).join('\n') }];
  for (const u of urls) {
    try { sources.push({ where: u, text: await (await fetch(u)).text() }); }
    catch { console.warn('Could not read', u); }
  }

  const found = [];
  const seen = new Set();
  for (const { where, text } of sources) {
    for (const [name, re, severity, todo] of PATTERNS) {
      for (const m of text.matchAll(re)) {
        if (seen.has(m[0])) continue; seen.add(m[0]);
        found.push({ severity, key: name, value: mask(m[0]), file: short(where), fix: todo });
      }
    }
    for (const m of text.matchAll(JWT)) {
      if (seen.has(m[0])) continue; seen.add(m[0]);
      const p = decode(m[0].split('.')[1]);
      if (!p) continue;
      if (p.role === 'service_role') found.push({ severity: 'CRITICAL', key: 'Supabase service_role key (legacy)', value: mask(m[0]), file: short(where), fix: 'Hole #3' });
      else if (p.role === 'anon') found.push({ severity: 'OK', key: 'Supabase anon key (public by design)', value: mask(m[0]), file: short(where), fix: 'Nothing. Safe only if Hole #1 is fixed.' });
    }
  }

  console.log(`%cTight Ship key scanner: read ${sources.length} script source(s) loaded in this tab.`, 'font-weight:bold');
  if (listFull) console.warn('This tab has loaded a lot of files, so the browser may have stopped listing some. Reload the page, visit only your AI, payment and admin pages, then run the scanner again. Also use the DevTools search (see the guide).');
  if (!found.length) {
    console.log('%cNo secret keys found in the code this tab has loaded.', 'color:green;font-weight:bold');
    console.log('Only pages you visited before running this are covered. Visit every page and feature, then run it again to be sure.');
    return;
  }
  console.table(found);
  const bad = found.filter(f => f.severity === 'CRITICAL').length;
  console.log(bad ? `%c${bad} CRITICAL key(s) found. Anyone can copy them. Follow the "fix" column.` : '%cNothing critical. Review any CHECK rows.', `color:${bad ? 'red' : 'green'};font-weight:bold`);
  if (!bad) console.log('Only pages you visited before running this are covered. Visit every page and feature, then run it again to be sure.');
})();
