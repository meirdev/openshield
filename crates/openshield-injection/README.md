# openshield-injection

Injection detection over raw request bytes, with no dependencies. Both
detectors return a finding that says why the input matched, so the reason
can be logged.

## XSS

`detect_xss` answers one question: would these bytes become active content if
a page reflected them into HTML? It tokenizes the input as HTML in each
context a page might reflect it into (text, and attribute values with each
kind of quoting) and checks the tokens against blocklists of tags, attributes,
URL schemes and style constructs that execute.

```rust
if let Some(finding) = openshield_injection::detect_xss(b"<img src=x onerror=alert(1)>") {
    println!("{finding}"); // onerror attribute in text context
}
```

There is no JavaScript parsing and no scoring: inline styles, unknown tags
and plain text are never flagged, and payloads that only work in a
JavaScript string context are out of scope.

## SQLi

`detect_sqli` answers: would these bytes change the meaning of an SQL query
they were spliced into? It follows libinjection's method. The input is
tokenized as SQL, accepting the string, number and comment syntaxes of
MySQL, PostgreSQL, SQL Server and Oracle at once; the tokens are folded down
to the few that carry structure; and the sequence of their kinds, the
fingerprint, is looked up in a database of 8367 sequences seen in attacks.
The input is scanned as is, as if it started inside a single-quoted string,
and as if it started inside a double-quoted string, and inputs with `#` or
`--x` comments are scanned again under MySQL's comment rules.

```rust
if let Some(finding) = openshield_injection::detect_sqli(b"1' OR '1'='1") {
    println!("{finding}"); // s&sos fingerprint in single-quoted context
}
```

The fingerprint notation is libinjection's: `s` string, `1` number, `n`
bare word, `o` operator, `&` logic operator, `c` comment, `U` union, `E`
`SELECT`-like expression, `T` statement keyword such as `DROP`, and so on.

## Differences from libinjection

### XSS

The detector keeps libinjection's model, an HTML tokenizer run in five
reflection contexts over blocklists, but departs from it where measurements
on the corpora under `testdata/` showed a better trade-off. Each change below
was checked against both the positive corpora and the benign corpora.

### Fewer false positives

- **Inline styles are not XSS by themselves.** libinjection flags any
  `style` attribute. We flag a style only when it contains a construct that
  executed in some browser: `expression(`, `behavior:`, `behaviour:`,
  `binding:`, `@import`, `javascript:` or `vbscript:`, matched after HTML
  references, CSS escapes, comments and whitespace are undone. CSS-only
  injections that just restyle the page are listed as accepted misses.
- **URL schemes need their colon.** libinjection flags any URL attribute
  whose value starts with `java`, `vbscript`, `data` or `view-source`, so
  `href="data-sheet.pdf"` and `href="javascript-tutorial.html"` match. We
  decode the value, drop control characters, strip leading whitespace and
  require the whole scheme followed by `:`.
- **Event handlers must be real.** The attribute must be `on` plus a name
  from the event list, matched exactly. libinjection matched by prefix, so
  `onloadx` counted.
- **Processing-instruction keywords need a word boundary.** `<!important>`
  no longer matches the `<?import` check.
- **An end tag stays an end tag.** libinjection reports `</foo  >` as an
  opening tag and flags `</script >`; we never flag closing tags.

### More attacks caught

- **Current event list.** All handlers libinjection collected from WebKit,
  Blink and Gecko in 2025, plus IE's `onbounce` and `onfilterchange` and the
  Firefox OS device events from the PortSwigger cheat sheet. The
  libinjectionrs port we replaced had an older list.
- **Named character references.** `java&Tab;script&colon;` decodes like a
  browser does; libinjection only decoded numeric references.
- **Nulls and control characters inside schemes.** `javas\x01cript:` and
  `javascript&\0colon;` are recognized.
- **Dangling markup.** A `form action` or `formaction` pointing at another
  origin, and an unclosed URL attribute ending in `?`, `&` or `=` that points
  at another origin (`<img src="//evil?`), are flagged. libinjection had no
  notion of exfiltration without script.
- **`srcdoc` and `data`** are treated as dangerous attributes.

### Behaviour kept on purpose

- Five contexts: text, unquoted, single-, double- and backtick-quoted
  attribute values.
- The tag blocklist, `svg*` and `xsl*` prefixes, `xmlns*`/`xlink*`
  attributes, SVG `attributeName` indirection, doctype declarations, and the
  IE comment quirks (backtick, `[if`, `<?xml`, `<?import`, `<!ENTITY`).
- Lenient tokenization: nulls inside names, IE whitespace, `<% %>` comments,
  `--!>` comment ends. The upstream HTML5 conformance suite passes with the
  single end-tag deviation noted above.

### Out of scope

Payloads that only work inside a JavaScript string, a comment or an existing
event handler are not HTML injection and are not in the corpora. Inputs that
need a decoding transform first (percent-encoding, UTF-7, overlong UTF-8)
are the rule's job: apply `url_decode_uni` and friends before `detect_xss`.

### SQLi

The SQLi detector is a faithful reimplementation rather than a redesign:
the fingerprint database was learned against libinjection's exact
tokenizer and folding rules, so both are kept, and libinjection's own
tokenizer, folding and verdict suites (419 cases) pass unchanged. The
keyword table and fingerprint database are libinjection 4.0.1's; the
libinjectionrs crate this replaced shipped older data, which is why this
detector catches payloads it misses from the same corpora (`1.e`
obfuscation, `INTO OUTFILE`, `IN BOOLEAN MODE` and the like): about 100 of
the 19,900 vendored samples, and about 1,800 before the two sqlmap corpora
were sampled down.

Two whitelist rules were tightened, each checked against the positive
corpora:

- **Identifiers ending in `--`.** libinjection treats a number followed by
  a trailing comment as an attack whenever folding removed something in
  between, to catch `1*1--`. `1611-IioXXIG--` and `1,1--` are IDs and lists:
  when the number is followed by `-`, `/` or `,` and then a letter, it is not
  SQL.
- **`NOT` quoted between two strings.** `"a" + "b"`, `"a" LIKE "b"` and even
  `"a" IS \N` change a WHERE clause through MySQL's implicit conversions, so
  an operator between two strings stays an attack. `NOT` is the one operator
  that can never sit between two values, so `STOCKING "NOT" STUFFER` is prose.

Everything else, including the 17 inputs in libinjection's own
false-positive list that are still flagged (runnable SQL such as
`select x from y where`, and quoted operators MySQL would evaluate), is
listed in `testdata/sqli/exceptions/` with the reason.

## Testing

- `cargo test -p openshield-injection` runs the unit tests, libinjection's
  conformance suites (HTML5 tokenizer, SQL tokenizer, folding and verdicts)
  and the corpus tests under `testdata/`. Every positive sample must be
  detected unless it is listed in that detector's
  `exceptions/positive-exceptions.txt`, and every negative must be clean
  unless listed in `exceptions/negative-exceptions.txt`; stale entries fail
  the test, so the lists only shrink.
- `cargo run -p openshield-injection --example eval -- [xss|sqli] --diff`
  compares a detector with libinjectionrs over the corpora and lists every
  disagreement.
- `cargo bench -p openshield-injection --bench detect` measures throughput
  against libinjectionrs.

## License

The SQL keyword table, the fingerprint database, the event handler list and
the test corpora under `testdata/` are derived from
[libinjection](https://github.com/libinjection/libinjection), BSD 3-clause;
see `LICENSE-libinjection`.
