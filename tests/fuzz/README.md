# Fuzz harness (P5)

Reserved for the WebAuthn verifier's fuzzing (plan section 12, `docs/webauthn-library-eval.md`
section 3.6): the restricted CBOR decoder and COSE-to-SPKI conversion get a seeded
random-mutation harness in CI, with the iteration count recorded in `docs/STATE.md`.

Differential tests run the same ceremony fixtures through the in-house verifier and two
**require-dev only** oracles, `web-auth/webauthn-lib` and `lbuchs/webauthn`, added to
`composer.json` in P5. Neither can ship: `/vendor` and `/tests` are in `.distignore`, the plugin
loads its own classes without Composer, and the release gate proves it by extracting the zip.
