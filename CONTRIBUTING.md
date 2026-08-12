# Contributing

1. Add or change a detector with the smallest useful rule surface.
2. Add a vulnerable fixture proving the true positive.
3. Add a safe near-miss proving that the rule does not over-fire.
4. Keep raw credentials synthetic and ensure serialized reports redact them.
5. Run `npm test` and `npm run benchmark`.
6. For adapter or compatibility changes, prepare the Trivy database and run
   `npm run test:engines` with every version newly added to the verified matrix.

Detection changes should explain their evidence level, expected false-positive
mode, affected framework versions, CWE mapping and remediation. A rule based on
file or route naming alone must be `inferred`; it cannot become blocking without
additional deterministic evidence.

Do not add install scripts, curl-to-shell flows, automatic project builds, or
network access to the default scan path.
