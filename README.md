# supabase-leak-check

Two free, read-only checks for apps built with Lovable, Bolt, Cursor, v0 or Replit on Supabase. Each takes about two minutes and needs no install.

1. **`key-scanner.js`** finds secret keys your live site ships to the browser: OpenAI, Anthropic, Stripe, Supabase `service_role` / `sb_secret_`, and more.
2. **`find-rls-holes.sql`** lists the tables and views in your Supabase database that strangers or any signed-in user can read.

Both only read. Neither changes anything or sends data anywhere.

## Why

In March 2025 a researcher scanned 1,645 apps from Lovable's public showcase and found 170 exposing user data through misconfigured database rules ([source](https://mattpalmer.io/posts/2025/05/statement-on-CVE-2025-48757/)). Escape's research team analyzed 5,600+ publicly available vibe-coded apps and found 2,000+ vulnerabilities and 400+ exposed secrets ([source](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/)).

AI app builders ship fast. These two checks catch the most common ways that speed leaks data.

## 1. Key scanner (browser console)

1. Open your **live** app (not the editor preview) and log in.
2. Click through every page and feature once, especially AI features, payments and admin pages. Modern apps load code page by page, and the scanner only sees code this tab has loaded.
3. Press F12 (Mac: Cmd+Option+I), open **Console**, paste the whole of [`key-scanner.js`](key-scanner.js), press Enter. If Chrome blocks the paste, type `allow pasting`, press Enter, and paste again.

| Result | Meaning |
|---|---|
| **CRITICAL** | A secret key is in your public code. Anyone can copy it. Roll (replace) the key at the provider today, then move the call to a server. |
| **CHECK** (Google `AIza…` key) | Fine for Firebase or Maps if restricted in Google Cloud. Not fine for Gemini. |
| **OK** (Supabase anon key) | Public by design. Safe only if your RLS is right. Run check 2. |
| No secret keys found | Good, for the pages you visited. |

The scanner masks every value it prints, so you can share a screenshot of the results.

## 2. RLS hole finder (Supabase SQL Editor)

Open your project at supabase.com/dashboard → **SQL Editor**, paste [`find-rls-holes.sql`](find-rls-holes.sql), click **Run**. Every row it returns is a hole:

| Row | What's wrong |
|---|---|
| **A** | A table with Row Level Security turned off. Anyone with your public key can read it. |
| **B** | A policy that lets *everyone* in (`true`). |
| **C** | A policy that lets *any signed-in user* in, such as `auth.role() = 'authenticated'` or `auth.uid() is not null`. Anyone who signs up can see every row. |
| **D** | A view that ignores RLS. It reads data with the owner's rights. |
| **E** | A materialized view in `public`. RLS never applies to these. |

**No rows means these holes are closed.** One exception: a **B** row that says "lets everyone select" is fine on a table meant to be public, like published blog posts.

Tables owned by extensions (for example PostGIS's `spatial_ref_sys`) are skipped, because you can't change them anyway.

## Found something?

Turning RLS on is the easy part. Doing it without breaking your app is the hard part. Turn it on with no rules and your own users see an empty app. Use a common AI-written rule and every signed-in user can read every row.

- **Free:** the full Hole #1 fix pack: the 2-minute test, 4 SQL files (find, lock, add the right rules, prove it), prompts for Lovable and Bolt, an agent skill for Claude Code and Cursor, and the mistakes to avoid. [Get it on Whop](https://whop.com/whop-7a9a/free-hole-1-supabase-rls-fix-pack/).
- **$19.99:** the Launch-Ready Kit covers 4 holes: database rules, API keys in the browser, the Supabase master key, and users making themselves admin. You get the test, the fix and the proof for each, with copy-paste SQL, prompts and agent skills. [See the kit](https://whop.com/whop-7a9a/products/launch-ready-kit-the-4-holes/).

The `Hole #2` / `Hole #3` labels in the scanner's output refer to chapters of that kit. You don't need the kit to act on a result: roll the key, then move it server-side.

## How these were tested

In November 2026 we ran both checks against a deliberately leaky app on a real Supabase project.

- **SQL query:** it flagged a table with RLS off, `using (true)` policies, `auth.role() = 'authenticated'` and `(select auth.uid()) is not null` policies, a view and a materialized view. It skipped PostGIS's own table, and it did not flag correct per-user policies.
- **Scanner:** on a Vite build with fake OpenAI, Stripe and Supabase keys in `VITE_` variables, it flagged all of them and raised no false alarms on a clean build.

## Limits

- The scanner only sees code the current tab has loaded. Search DevTools (Ctrl+Shift+F) for `sk-`, `sk_live`, `sb_secret` and `service_role` to double-check.
- The SQL checks the `public` schema and Row Level Security only. Storage buckets have their own policies.
- This is not a security audit. It catches common holes. It doesn't certify your app.

## License

MIT. Made by [Faheem Saleem](https://github.com/faheemsaleem).
