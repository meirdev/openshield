# crs2os — OWASP CRS → openshield converter

Converts [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
seclang (`SecRule`) files into an openshield ruleset YAML, using only wirefilter
features the current engine supports. Rules that need features we don't have yet
are skipped and tallied — never emitted in a broken state.

## Usage

```bash
pip install msc_pyparser pyyaml
python tools/crs2os/convert.py path/to/coreruleset -o rules/owasp-crs.yaml
```

Prints a report of how many CRS rules converted and, for the rest, why they were
skipped (grouped by reason).

## How rules map

- **One openshield rule per target variable.** `SecRule REQUEST_COOKIES|ARGS ...`
  becomes several rules with ids `<crs-id>#<field>`, e.g.
  `921200#http.request.cookies.values`. Each carries a single, readable
  `regex_match(...)` (or `detect_sqli`, `==`, `contains`, …). A payload hitting
  two variables therefore fires two rules and scores twice (accepted for now).
- `@rx` → `regex_match(field[*], r#"..."#)` (byte-mode `\x{HH}` rewritten to
  `\xHH`); `@detectSQLi/@detectXSS` → `detect_*`; `@streq/@contains/@beginsWith/
  @endsWith` → `== / contains / starts_with / ends_with`; numeric `@eq/@gt/...`
  and `&VAR` counts → `len(field) op N`; `@ipMatch` → `ip.src in {...}`.
- Transforms map to the matching functions (`t:lowercase` → `lower`, etc.).
- `@pmFromFile file.data` becomes a `phrases` list (`kind: phrases`, emitted at
  the top level of the output) matched via `x in $crs_pm_<file>`; short inline
  `@pm "a b c"` becomes a case-insensitive `regex_match` alternation.
- Negated operators (`!@rx ...`) become `len(field) > 0 and not(any(...))` so
  they match only when the field is present and non-conforming — mirroring
  ModSecurity, which skips the rule when the variable is absent.
- `tag` → `categories` (incl. `severity/<sev>`), `msg` → `description`,
  `ver` → `version`, `ref` deep-links to the source line.
- `setvar:tx.<name>=+%{tx.<sev>_anomaly_score}` → `action: score`. Paranoia
  level ≥ 2 rules are emitted `enabled: false` (CRS default); enable them with a
  `paranoia-level/N` category override.
- A seclang string match on `RESPONSE_STATUS` is rendered as the idiomatic
  numeric comparison on `http.response.code` (e.g. `@rx ^5\d{2}$` -> `>= 500 and
  <= 599`, `!@rx ^404$` -> `!= 404`).
- A **chained rule** becomes a single rule (id = the chain head) whose
  expression is the `and` of each link's per-target disjunction. Metadata comes
  from the head; anomaly scores are collected across all links (CRS often puts
  the `setvar` on the last link). A chain converts only when every link does.

## Not converted (skipped, no code changes)

`@within`, `@validate*`, `!VAR`/regex selectors,
`XML`/`MATCHED_VARS`/`FILES`/`REQBODY_PROCESSOR`, capture-based `setvar`,
macros in operator args, and the two transforms the engine still lacks (`length`, `removeCommentsChar`).
Most skipped chains are blocked by one of these appearing in a link, not by the
chain mechanism itself.

## Using the output

`rules/owasp-crs.yaml` is a `rulesets:` block. To run it, reference the ruleset
from an `execute` rule and declare the score names at the top level of your
config (ruleset-scoped `scores:` and file includes are not wired yet):

```yaml
scores: [ inbound_anomaly_score_pl1, sql_injection_score, ... ]   # from the ruleset's scores:
rulesets:
  - <paste the ruleset here, or its rules>
rules:
  - id: run-crs
    action: execute
    expression: "true"
    action_parameters: { id: owasp-crs }
  - id: block-on-score           # CRS 949110 uses TX vars (skipped) — add your own threshold
    phase: response_headers
    action: block
    expression: "score.inbound_anomaly_score_pl1 >= 5"
```
