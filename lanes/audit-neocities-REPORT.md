# Static security audit: neocities (Ruby/Sinatra) — dynamic regex usage vs CVE-2026-110264 / Onigmo CVE class

Date: 2026-10-23
Repo: https://github.com/neocities/neocities @ 74ff27ac8df6c29fbd616244a01d682ef621e1f3 (shallow clone)
Scope: pure static source audit of app/, app.rb, app_helpers.rb, models/, workers/, ext/, environment.rb. No HTTP requests to neocities or hosted sites, no crafted regexes sent anywhere, app not executed.

Context: CVE-2026-110264 (CVSS 10.0, unauth RCE) and siblings are integer-overflow bugs in Ruby's Onigmo regex compiler, fixed in Ruby 3.3.13 / 3.4.12 / 4.0.9 (2026-10-23). The dangerous server-side pattern is compiling a regex from attacker-supplied pattern text (native `Regexp.new` / interpolated `#{...}` inside `/.../` literals) with the vulnerable constructs (case-fold expansion sizes, bracket-range integers, repetition nesting, `(?() )` conditional numbering, lookbehind distance int-casts). We previously audited GitLab's tree the same way.

## 1. Dynamic regex compilation sites (complete enumeration)

Grep strategy: `Regexp.new|Regexp.compile`, interpolated `#{` inside regex literals (`match /...#{...}/`, `=~`, `split`, `gsub`, `sub`), and `.match/.scan/.split(...)` with non-literal first args, across all non-test Ruby files. Findings:

| # | file:line | Pattern source | Attacker-controlled? | Escaped? | Note |
|---|-----------|----------------|----------------------|----------|------|
| 1 | models/site.rb:766 | `/@#{Regexp.quote(whitelisted_disposable_email_domain)}$/i` — domain from server-side `files/disposable_email_whitelist.conf` | no (operator-controlled config file; not in repo) | yes (`Regexp.quote`) | Interpolated but static server data, double-protected |
| 2 | models/site.rb:770 | `/@#{Regexp.quote(disposable_email_domain)}$/i` — domain from `files/disposable_email_blacklist.conf` | no (server-side file, absent from repo) | yes | Same |
| 3 | models/site.rb:783 | `/@*#{Regexp.quote(banned_email_domain)}$/i` — domain from `files/banned_email_blacklist.conf` | no (server-side file) | yes | Same; `@*` prefix is the only unescaped quantifier, applied to literal `@` |
| 4 | app/site.rb:303 | `request.referer.match /\/site\/#{Regexp.quote(username)}/i` — `username` is a Sinatra route param `:username` | yes (partial: route param is attacker-supplied text) | yes | `Regexp.quote` (alias of `Regexp.escape`) applied. Per range findings escape kills most constructs but survives brackets/hyphen/counts; input is also matched, not compiled via Regexp.new — the compiled pattern includes escaped attacker text. Low residual risk (see §4) |
| 5 | models/site_file.rb:29 | `.where(path: /^#{Regexp.quote path}\//)` — `path` is a SiteFile path (from DB; originates as user-uploaded filename) | yes (partial: user-controlled filename at upload time, round-tripped through DB) | yes | Escaped. DB round-trip and Sequel regex/like handling; residual bracket/hyphen/count reachability as above |
| 6 | ext/string.rb:12 | `gsub /^#{Regexp.quote(scan(/^\s*/).min_by{|l|l.length})}/, ""` (`String#unindent`) — interpolated whitespace prefix computed from the string itself | no (self-derived data; callers pass internal heredoc/boilerplate strings) | yes | Not user-pattern input |
| 7 | models/site.rb:119 | `EDITABLE_FILE_EXT = /#{VALID_EDITABLE_EXTENSIONS.join('|')}/i` — join of a static `%w` array | no (compile-time constant) | n/a (static word list) | Constructed dynamically at boot but entirely static content; used against user-controlled *subjects* (app.rb:17, models/site.rb:1381), never as a carrier of user text |
| 8 | app/create.rb:9 | `params[:new_tags_string].match(Regexp.quote(t))` — pattern is `Regexp.quote(t)` over an operator-config whitelist | no (pattern is whitelist entry; user input is the *subject*) | yes | Only a Boolean whitelist membership test |
| 9 | tests/acceptance/email_recovery_tests.rb:57,85 | `Regexp.new(Regexp.escape(@new_email))` | no (test code, escaped) | yes | Test-only; not production code path |

**Regexp.new / Regexp.compile**: zero occurrences in production code; the only two `Regexp.new` calls in the entire tree are the escaped test assertions above.

**`=~` / `.match` with variable patterns**: none found — every `.match(...)`, `=~ /.../`, `.scan`, `.split`, `.gsub` in app/, models/, workers/, ext/ uses a static literal or a constant (`HTML_REGEX`, `IMAGE_REGEX`, `VALID_HOSTNAME`, `Tag::INVALID_TAG_REGEX`, `CLAMAV_THREAT_MATCHES`, `EMAIL_SANITY_REGEX`, `CREATE_MATCH_REGEX`) applied to user-controlled *subjects*. User input is never the pattern in any `=~`.

## 2. Data-flow verdict summary

- **No site compiles a regex from attacker-controlled pattern text without escaping.** The only sites where attacker-influenced data reaches a compiled pattern are #4 (route param `username`) and #5 (DB file path), and both wrap it in `Regexp.quote` — the same defensive posture we observed as "good practice" in the GitLab tree audit.
- The search feature (app/search.rb) does NOT build regexes from the query — it URL-escapes the query (`Rack::Utils.escape`) and sends it to an external Google-CSE-style search endpoint. The query is never compiled as a regex.
- Tag filtering (app.rb:119, app/activity.rb:12) validates tags against static `Tag::INVALID_TAG_REGEX`; user input is subject-only.
- HTML/DOM processing of user-uploaded pages uses the `sanitize` gem (SiteFile requires `sanitize`) and ClamAV scanning — no regexes compiled from page content.

## 3. Ruby/Onigmo lineage

- No `.ruby-version` file in the repo.
- `vagrant/ruby.sh` (the project's documented provisioning script) downloads and builds **Ruby 3.3.0 from the pristine ruby-lang.org tarball** (`https://cache.ruby-lang.org/pub/ruby/3.3/ruby-3.3.0.tar.gz`) — the exact pristine-tarball build class that, per the GitLab firing-range intel, carries **no distro backports**. Any host built from this script at version < 3.3.13 is **unpatched** against CVE-2026-110264 and the sibling Onigmo CVEs (89078, 93577, 97229).
- `.github/workflows/ci.yml` pins `ruby-version: '3.3'` (floating minor — CI on 3.3.13+ would be patched; production is what matters).
- Gemfile mentions Ruby 4 compat shims (`ostruct` comment: "Ruby 4 no longer loads this default gem"), suggesting the project tracks modern Ruby, but no deploy Dockerfile or production Ruby pin exists in the tree — production Ruby version is not determinable statically. **Verdict: repo metadata shows a pristine-tarball Ruby 3.3.x build path, presumed UNPATCHED (< 3.3.13) unless the operator has upgraded after 2026-10-23.**

## 4. Risk assessment

**No exploitable path for CVE-2026-110264-class bugs was found.** The vulnerability requires attacker-controlled pattern text to reach the Onigmo compiler; in neocities, every interpolated pattern site uses `Regexp.quote` on values that are either server-static (blacklist domains) or attacker-influenced (username, file path), and there is no `Regexp.new` on user input at all. The pattern is not GitLab's `UntrustedRegexp` (RE2-backed) wrapper — neocities relies on `Regexp.quote`, which per range research "kills most constructs but survives brackets/hyphen/counts". A crafted username or filename like `[a-z]{...}` or `a-b` would survive quoting as literal-ish text in the compiled pattern (it does not inject metacharacters — quote escapes `-` only outside char-class context but escapes `[`/`]`, so no injection of Onigmo *constructs*), so the 110264-style integer-overflow constructs (case-fold expansion, repetition nesting depth, lookbehind distance) **cannot be reached** through these sites. Even if the host Ruby is an unpatched pristine 3.3.x build, there is no attacker-reachable compile of attacker-shaped pattern text.

Residual/defense-in-depth notes:
1. models/site_file.rb:29 and app/site.rb:303 could harden by replacing regex prefix-match with a plain string prefix comparison (`path` LIKE or `start_with?`-style SQL), eliminating the last attacker-influenced pattern interpolations entirely.
2. Ruby lineage: production should be upgraded to 3.3.13/3.4.12/4.0.9 regardless of app code (host-side Ruby is unpatched per §3), since any future code change introducing an unescaped interpolation would become 10.0-severity on the current build.
3. `Regexp.quote` on blacklist-domain files (#1–3) means an operator editing those config files could inject constructs — operator-trust only, not a vuln.

## 5. ReDoS (lesser finding) review

Checked every literal regex applied to user-controlled subjects for catastrophic-backtracking shapes (nested quantifiers, `(.*)*`, overlapping alternations with quantifiers):
- models/site.rb:834 `/^.+: (.+) FOUND$/` — applied to ClamAV scan output (`output.strip`), not directly attacker-authored; linear, safe.
- app/settings.rb:278 `/^did:plc:([a-z|0-9)]+)$/` — note the typo: `|` inside the character class is a literal pipe, and `)` is a literal `)` in the class; harmless backtracking-wise (single quantifier), but the class is likely not what the author intended.
- models/site.rb:713 `/^[a-z0-9]([a-z0-9_\-]{0,}[a-z0-9])?$/`, EMAIL_SANITY_REGEX (character-class-only quantifiers, linear), app/signin.rb:78 `/\A\d{6}\z/`, workers/screenshot_worker.rb:58 — all linear/anchored, no exponential backtracking.
- No nested-quantifier or overlapping-alternation patterns were found anywhere in app/, models/, workers/, ext/.

**No ReDoS findings of note.** All user-input regexes are anchored, linear, and character-class based.

## Conclusion

Neocities exhibits the same "good-practice" profile we found in GitLab's tree: user input is never compiled as a regex pattern without `Regexp.escape`/`Regexp.quote`, and there are zero `Regexp.new`-on-input sites. Against the CVE-2026-110264 class, the app code is not an attack surface. The actionable item is infrastructure: the repo's own provisioning builds pristine-tarball Ruby 3.3.0, which is unpatched against the four Onigmo CVEs — the operator should move to Ruby 3.3.13/3.4.12/4.0.9 (or a distro image with backports, verified behaviorally, e.g. `ruby:3.3-bookworm`).
