# Trill Wire Protocol Specification Assets

This directory contains shared assets, schemas, golden messages, and test vectors for the Trill wire protocol (v1).

## Contents

- `schema/messages.schema.json`: JSON Schema describing wire message structures.
- `golden/`: Canonical valid and invalid JSON messages for cross-implementation testing.
- `testvectors/`:
  - `spake2_rfc9382_p256.json`: Test vectors from RFC 9382 Appendix B.
  - `pair_v1.json`: trill SPAKE2 binding with fixed identity channel bindings and ephemeral keys.
- `tools/gen_pair_vectors.py`: Independent Python implementation that verifies the RFC vectors and outputs test vectors.
- `recipes.md`: Quick `roc-send` and `roc-recv` command recipes.
