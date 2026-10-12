# Test vectors

- `paid-tcp-relay-844e834-auth.json` is `fixtures/wire/auth.json` from
  `github.com/douglaz/paid-tcp-relay` at commit `844e834066f42fd2c962b9724b457db50a32f6ac`,
  copied byte for byte. It is a complete signed AUTH (`WIR-5` of paid-tcp-relay at `844e834`): a known answer for the
  NIP-01 event id and the BIP-340 signature, read by `src/relay_auth.rs`'s tests.
