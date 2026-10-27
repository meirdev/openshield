---
title: As a library
description: "Embed the WAF engine, openshield-core, in another Rust server."
sidebar:
  order: 3
---

The proxy and the nginx module are two hosts of the same engine, the `openshield-core` crate. A host builds a `Waf` from the configuration, starts a `Transaction` per request, feeds it the request phase by phase, and acts on the verdicts.

This is a lifecycle sketch; `request_data`, chunks, and response metadata come from your host:

```rust
use openshield_core::{config::WafConfig, Waf, Verdict, BodyVerdict, ResponseOutcome};

let config = WafConfig::from_yaml(&std::fs::read_to_string("waf.yaml")?)?;
let waf = std::sync::Arc::new(Waf::from_config(&config)?);

// Per request:
let mut tx = waf.transaction();
match tx.request_headers(request_data) {
    Verdict::Pass | Verdict::Allow => { /* continue to body processing */ }
    Verdict::Block(response) => { /* send response.status_code, content_type, content */ }
    Verdict::Challenge => { /* serve waf.challenge().challenge_page() */ }
}
// With request_body rules, as chunks arrive:
match tx.request_body_chunk(chunk, end_of_stream) {
    BodyVerdict::Passthrough => {}
    BodyVerdict::Hold => { /* withhold output; the core retains the bytes */ }
    BodyVerdict::Forward(bytes) => { /* forward these instead of the chunk */ }
    BodyVerdict::Block(response) => { /* send it */ }
}
// Response phases mirror these; finally:
let summary = tx.finish(ResponseOutcome { status, headers: Some(&headers), error: None });
// summary feeds the host's access log; the audit record was written by the core.
```

Complete body processing by sending a final chunk with `end_of_stream: true`, even when the body is empty. When the core returns `Forward(bytes)`, those bytes replace the held output, so forwarding the original chunks as well would duplicate them. Act on block and challenge verdicts immediately, then call `finish` once when the transaction ends, including when it ends early.

The core handles policy evaluation, while the host translates its verdicts into network behavior:

| The core | The host |
| --- | --- |
| Parsing and validating the configuration, compiling rules | Listening, TLS, connecting to the upstream |
| Populating fields from plain request data | Turning its own request type into `RequestData` |
| Evaluating phases, scores, rate limits, verdicts | Sending block and challenge responses, holding or releasing bodies |
| JWT and schema validation | The HTTP call that verifies a Turnstile token (`ChallengeManager::turnstile_request` builds it) |
| Writing the audit log | Writing the access log from `TransactionSummary` |
| Counting rate limits in memory | A shared store, by implementing `RateLimitStore`, where workers are processes |

The core has no dependency on an async runtime or on networking, which is what lets it run inside nginx workers. The OpenAPI validator is a further crate, `openshield-openapi`, usable on its own.
