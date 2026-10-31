# openshield-transforms

ModSecurity-compatible input transformations over raw bytes, with three
small dependencies (`base64`, `hex`, `html-escape`) plus `md-5` and `sha1`
behind the default `hash` feature.

Every function has the shape `fn(&[u8]) -> Cow<[u8]>`. The result is
borrowed when the input needed no change and owned otherwise, so a chain of
transforms over ordinary input allocates nothing:

```rust
use openshield_transforms::{lower, url_decode_uni};

let decoded = url_decode_uni(b"1%27%20OR%201");   // owned: "1' OR 1"
let same = lower(b"already lower");               // borrowed
```

## Functions

| Function | ModSecurity | Notes |
| --- | --- | --- |
| `url_decode_uni` | `t:urlDecodeUni` | `%XX`, `%uXXXX`, `+`; full-width ASCII folded |
| `html_entity_decode` | `t:htmlEntityDecode` | non-UTF-8 passes through |
| `js_decode` | `t:jsDecode` | `\uHHHH` keeps the low byte, as ModSecurity does |
| `css_decode` | `t:cssDecode` | last two hex digits, trailing space consumed |
| `escape_seq_decode` | `t:escapeSeqDecode` | ANSI C escapes |
| `base64_decode` | `t:base64Decode` | standard or URL-safe alphabet; invalid passes through |
| `hex_decode` | `t:hexDecode` | invalid passes through |
| `lower`, `upper` | `t:lowercase`, `t:uppercase` | ASCII only |
| `trim`, `trim_start`, `trim_end` | `t:trim`, `t:trimLeft`, `t:trimRight` | always borrowed |
| `remove_nulls`, `replace_nulls` | `t:removeNulls`, `t:replaceNulls` | |
| `remove_whitespace`, `compress_whitespace` | `t:removeWhitespace`, `t:compressWhitespace` | C `isspace` set |
| `replace_comments`, `remove_comments` | `t:replaceComments`, `t:removeComments` | ModSecurity's quirks kept |
| `cmd_line` | `t:cmdLine` | |
| `normalize_path`, `normalize_path_win` | `t:normalizePath`, `t:normalizePathWin` | |
| `base64_encode`, `hex_encode` | `t:base64Encode`, `t:hexEncode` | |
| `md5`, `sha1` | `t:md5`, `t:sha1` + `t:hexEncode` | lowercase hex digest; `hash` feature |
| `utf8_to_unicode` | `t:utf8toUnicode` | |

Where ModSecurity's behaviour is surprising, for instance the byte copied
through after a closing `*/` in `remove_comments`, the function reproduces it
and its documentation says so, because rules written against ModSecurity
depend on it.
