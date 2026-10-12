# Test vectors

- `paid-tcp-relay-844e834-auth.json` is `fixtures/wire/auth.json` from
  `github.com/douglaz/paid-tcp-relay` at commit `844e834066f42fd2c962b9724b457db50a32f6ac`,
  copied byte for byte. It is a complete signed AUTH (`WIR-5` of paid-tcp-relay at `844e834`): a known answer for the
  NIP-01 event id and the BIP-340 signature, read by `src/relay_auth.rs`'s tests.
- `paid-tcp-relay-844e834-timing.toml` is `bundle/timing.toml` from the same repository at the
  same commit, copied byte for byte. Its `[relay]` limits (`auth_skew`, `min_spacing`, `window`,
  `window_cap`; that repository's `OPR-7`) are the ones the relay fixture applies, read from this
  file by `tracer/src/fixtures.rs`.
