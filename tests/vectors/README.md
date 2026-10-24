# Test vectors

- `paid-tcp-relay-844e834-auth.json` is `fixtures/wire/auth.json` from
  `github.com/douglaz/paid-tcp-relay` at commit `844e834066f42fd2c962b9724b457db50a32f6ac`,
  copied byte for byte. It is a complete signed AUTH (`WIR-5` of paid-tcp-relay at `844e834`): a known answer for the
  NIP-01 event id and the BIP-340 signature, read by `src/relay_auth.rs`'s tests.
- `paid-tcp-relay-844e834-timing.toml` is `bundle/timing.toml` from the same repository at the
  same commit, copied byte for byte. Its `[relay]` limits (`auth_skew`, `min_spacing`, `window`,
  `window_cap`; that repository's `OPR-7`) are the ones the relay fixture applies, read from this
  file by `tracer/src/fixtures.rs`.
- `bips-927b6de-bip-0032.mediawiki` is `bip-0032.mediawiki` from `github.com/bitcoin/bips` at
  commit `927b6de9915c9262615a6399de51b200f81e5aa4`, copied byte for byte (SHA-256
  `e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f`). `src/seed.rs`'s tests read
  its test vectors (lines 218–310): vector 1's `m` and `m/0H`, and vectors 3 and 4 complete, on
  key and chain code at every step; vector 5's two key-range entries ("private key 0 not in
  1..n-1", "private key n not in 1..n-1"), refused; vector 5's other 14 entries are listed as not
  applicable, and vector 2, which starts with a non-hardened step, is not used.
- `bips-927b6de-bip-0340-test-vectors.csv` is `bip-0340/test-vectors.csv` from the same
  repository at the same commit, copied byte for byte (SHA-256
  `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d`). The rows carrying a
  secret key (indices 0–3 and 15–18) are checked on their x-only public key; the signing columns
  are not run.
- `rfc8032-section-7.1.txt` is section 7.1, "Test Vectors for Ed25519", of RFC 8032, from
  `https://www.rfc-editor.org/rfc/rfc8032.txt` (SHA-256
  `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3`): lines 1295–1498, copied
  byte for byte with `sed -n 1295,1498p`, page breaks included (SHA-256
  `c36090c85ac05e19c2b34a7b02a2225acd2e07631dcd66e74d02e88e0f79062c`). All five tests are run:
  TEST 1, TEST 2, TEST 3, TEST 1024 and TEST SHA(abc), on the public key and the signature.
- `python-mnemonic-b57a5ad-vectors.json` is `vectors.json` from
  `github.com/trezor/python-mnemonic` at commit `b57a5ad77a981e743f4167ab2f7927a55c1e82a8`,
  copied byte for byte (SHA-256
  `fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8`). Its eight 12-word
  `english` entries are checked on entropy to mnemonic and on import; their seeds, under the
  passphrase `TREZOR`, are not run. Its 24-word `english` entry and the 12-word entries of
  `spanish`, `french`, `italian` and `czech` are import refusals.
- `src/bip39-english.txt`, compiled in, is `bip-0039/english.txt` from `github.com/bitcoin/bips`
  at commit `927b6de9915c9262615a6399de51b200f81e5aa4`, copied byte for byte: 2048 lines,
  SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`, which
  `the_word_list_is_bip39s` checks.

The specification's own v1 known answers, `spec/docs/design/credential-vectors-v1.json`, are
not copied here: the tests read them from `spec/` at the pin.

`seed-backup-collisions.txt` contains four public seed-backup test mnemonics. Each fixes its
first eleven listed words (121 bits), appends seven zero bits to form 128-bit entropy, and
uses the first four SHA-256 checksum bits to select its twelfth word. The host imports each
with `Seed::import` and checks the required words against the vendored list. These fixtures
exercise fixed text such as `icon`, `state`, `call` and `machine`, and the adjacent phrases
`all twelve`, `match this`, `this seed` and `try again`, without relying on random word draws.
The fourth also holds `approve never` and `improve never`: concatenated list-item text carries
`proven` across those word boundaries. The language check omits only the displayed word list
and still reports a planted hidden reserved claim elsewhere in the page.

- `pacman-c8ccc368.conf` is Arch Linux's `pacman.conf` from its pacman packaging project,
  copied byte for byte from
  `https://gitlab.archlinux.org/archlinux/packaging/packages/pacman/-/raw/c8ccc3684e28c419ebd709e666eef15e1479acdf/pacman.conf`,
  commit `c8ccc3684e28c419ebd709e666eef15e1479acdf` (`c8ccc368`). The upstream project is
  pacman, https://www.archlinux.org/pacman/, licensed GPL-2.0-or-later (the packaging
  project's `PKGBUILD` at that same commit declares the licence). The signature-lowering
  tests admit this stock configuration, including its commented TrustAll example; they
  execute no package manager and claim no observed unsigned-package refusal.
