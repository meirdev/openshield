# Test corpora

Lines are read the way libinjection's `reader` reads them: blank lines and
lines starting with `#` are skipped, trailing whitespace is trimmed, and the
rest is URL-decoded.

- `xss/positive/libinjection-*.txt` and `xss/negative/libinjection-false-positives.txt`
  come from the `data/` directory of <https://github.com/libinjection/libinjection>
  (BSD 3-clause, see `LICENSE-libinjection`). `libinjection-shazzer-sample.txt`
  is a 1-in-80 sample of the 80k-line browser fuzzing corpus there.
- `xss/positive/portswigger-cheat-sheet.txt` holds the payloads from
  <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>.
- `xss/negative/benign-*.txt` are inputs written for this crate that a
  detector must leave alone.
- `xss/exceptions/positive-exceptions.txt` lists positives the detector is
  allowed to miss.
- `sqli/positive/libinjection-*.txt` and `sqli/negative/libinjection-false-positives.txt`
  come from the same `data/` directory. The two `sqlmap` files are 1-in-25
  samples of 7-8 MB originals whose lines differ only in digits; `sqli/negative/benign-*.txt` and the
  `sqli/exceptions/` lists are this crate's.
- `html5/` is libinjection's HTML tokenizer conformance suite and
  `sqli-suite/` its SQL tokenizer, folding and verdict suites.
