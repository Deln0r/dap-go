# Authorship and tooling

This file documents what this project is and is not, with respect to AI tooling. The IETF crypto community has good reasons to ask. The honest answer follows.

## What I write by hand

- The DAP wire codec (`pkg/dap/wire`).
- The DAP protocol state machine (`pkg/dap`).
- All cryptographic glue, including HPKE wrappers, Prio3 wrappers, key derivation, and serialization that goes anywhere near a key, ciphertext, or aggregate.
- All commit messages.
- All code review responses, issue replies, and mailing-list posts.

If a fix or feature touches the protocol or any cryptographic surface, I write the code, the tests, and the prose. No LLM completion, no Cursor "compose", no auto-commit tools.

## What I use tooling for

- Editor autocomplete at the symbol level (gopls, language server suggestions, single-line completions).
- Reading specs, RFCs, and reference implementations.
- Drafting non-cryptographic plumbing and project documentation, which I then rewrite by hand before committing.
- Background research and search.

I do not paste protocol drafts or our own code into a third-party assistant and commit the output.

## Commit and PR conventions

- No `Co-Authored-By:` trailers naming any AI system.
- No emoji-and-attribution lines such as "Generated with [Tool]" or "Co-authored by [Bot]".
- No `noreply` emails routing through AI vendor domains.
- Commits are signed off under the Developer Certificate of Origin (`git commit -s`).
- The author byline is the human committing the change.

## Why this file exists

Two reasons. First, IETF crypto reviewers are pattern-matching AI-style prose and code in 2026 (see [caddyserver/caddy#5190](https://github.com/caddyserver/caddy/issues/5190) for one explicit policy). Second, the security properties of DAP and Prio3 depend on every byte being put there on purpose. A protocol implementation generated without that intention is a bug-farm.

If you find a section of this repo that contradicts the rules above, open an issue. It will be treated as a bug.
