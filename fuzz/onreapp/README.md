# onreapp fuzz harness

Stateful invariant fuzzing for `programs/onreapp`, run on FuzzCorp by
`.github/workflows/fuzzcorp-submit.yml`. The workflow builds the program from source on every
push and fuzzes that build — nothing here ships a prebuilt `.so`.

## Layout

    src/main.rs        actions (one per instruction) + invariants
    build-bundle.sh    assembles the FuzzCorp bundle
    idls/              IDL the action bindings were generated from
    programs/          program artifacts, staged by CI (gitignored)

## Local run

```bash
cargo build-sbf --tools-version v1.51 --manifest-path ../../programs/onreapp/Cargo.toml
mkdir -p programs && cp ../../target/deploy/onreapp.so programs/
cargo test --release          # deterministic regression tests
./build-bundle.sh             # bundle for FuzzCorp
```

`--tools-version v1.51` is deliberate. v1.52 emits larger stack frames and pushes
`MakeOffer::try_accounts` past the SBF 4096-byte frame limit; the build still exits 0 and the
instruction then fails at runtime with an access violation that looks like a missing account.
CI pins the same version and fails the build if the frame warning appears.

## Invariants

| id | property |
|----|----------|
| P-0002 | the redemption vault holds at least the sum of amounts locked by open requests |
| P-0003 | `requested_redemptions` equals the sum of `amount` over that offer's open requests |
| P-0004 | while `max_supply` is non-zero, ONyc supply never exceeds it |
| P-0005 | no offer has `token_in_mint == token_out_mint` |
| P-0006 | every live `Offer.fee_basis_points` is at most `MAX_ALLOWED_FEE_BPS` |
| P-0008 | the redemption vault for a transfer-fee `token_in` still covers its open requests |

All are armed. Those already reported to the maintainers are silenced by id via
`SCOUT_CHECK_MUTE` in the bundle manifest, so campaigns surface only new signal; muting is
announced on stderr as `[SCOUT_CHECK_MUTED]`. Drop an id from that list once its bug is fixed and
the property becomes a regression guard.

## CI secrets

`FUZZ_API_KEY` (the only secret; crucible is public, so no token is needed to fetch it). Org
and project are repo variables `FUZZ_ORG` / `FUZZ_PROJECT`.
