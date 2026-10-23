# How this project uses AI

Most of the code, tests, documentation and commit messages in this repository are written by an AI coding assistant: Anthropic's Claude models, run through Claude Code. OpenAI Codex is used as a second reviewer. This includes the protocol and cryptographic code: the DAP wire codec, the Helper, the HPKE wrapper, and the Prio3 implementation with its field, XOF and FLP layers.

I decide what gets built, in what order, and what the project claims. Changes go to main once the tests pass. Commits carry my name and no AI trailers, so this file is the disclosure for the whole history.

## What the correctness claims rest on

Who typed a line says nothing about whether it is right, so the claims in the README rest on checks anyone can rerun:

- byte-exact agreement with the CFRG VDAF test vectors;
- live runs against Janus, with dates and commits recorded in [docs/interop.md](docs/interop.md);
- negative and truncation tests for the wire types, and fuzzing of the decoders;
- CI on two Go versions, on 32-bit, and against a live Dendrite homeserver.

If you find a bug that one of these checks should have caught, please open an issue.

## Text posted elsewhere

Replies in other projects' issue trackers and posts to mailing lists may be drafted with the same assistant. I read them and send them myself.
