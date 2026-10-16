# secretmask 1.0.0 certification report

Progress:
- [x] Branch `release/1.0.0` created from `main` (0.2.0, 0668d02; PyPI has 0.2.0)
- [x] Baseline gates run on 0.2.0
- [x] API review and 1.0.0 API changes (item 1)
- [x] Ground truth: vendor documentation, RFCs and reference rule sets fetched, detect-secrets run live (item 7)
- [x] Errors, typing, docstrings and doctests (items 2 to 5)
- [x] Contract, fuzz and author mutation round (items 6, 9, 18)
- [x] Docs: README, GUIDE, CHANGELOG (items 11, 12)
- [ ] Packaging, e2e and upgrade from PyPI 0.2.0 (items 8, 13, 14)
- [ ] Every interpreter on this PC (item 10)
- [ ] Five QA lenses report PASS (item 19)
- [ ] Independent reviewer (item 16)
- [ ] Gates (item 15)
- [ ] PR open and trace guard CLEAN (item 17); merge and publish left to the maintainer

## Baseline on 0.2.0 (before any change)

Fresh clone of `main` (0668d02) on Elena's PC, CPython 3.14: `ruff format --check .`,
`ruff check .` and `mypy --strict src tests` exit 0; `pytest` 94 passed. PyPI has 0.2.0.

Defects of 0.2.0 found by the API review, the ground truth and fuzzing (each one now has
a contract):

- Tokens matched inside words: `risk-assessment-for-the-project` became `ri***` (an
  `sk-` key), `disk_test_...` a Stripe key, `XAKIA...` an AWS key.
- Common leaks: `AWS_SECRET_ACCESS_KEY=...`, `client_secret=...`, `dbPassword=...`,
  `"password": "..."` inside text, `$config['api_key'] = '...'`, `redis://:pw@host`,
  `Authorization: Basic ...`, OpenPGP private keys, private key blocks without an
  `END` line, unsecured JWTs (empty signature) were all left in clear.
- A card followed by an expiry date or another number (`4111 1111 1111 1111 12/26`)
  was missed, because the extra digits were counted into the card.
- Masking was not idempotent: with `placeholder="[hidden]"`, `password=hunter2`
  became `password=[hidden]]`, and each detector rescanned the previous one's output.
- `MaskConfig(allowlist="a@b.io")` allowed every single character; an invalid custom
  regex raised `re.error` and crashed the CLI with a traceback; wrong types failed
  late or not at all.
- `mask()` recursed: deep data raised `RecursionError`, a cycle recursed forever until
  `RecursionError`; `mask_json` on deeply nested JSON raised `RecursionError`.
- Sensitive keys matched as substrings: `author`, `authenticated`, `tokenizer` and
  `passwordless` were masked.
- A PEM body of many `BEGIN` lines without `END` took quadratic time (2.5 s for 80 kB).
- CLI: an extra newline was appended to file and standard-input text, non-UTF-8 bytes
  failed the whole run, a closed pipe gave a traceback.

## Author mutation round (item 18)

42 mutants over every module, each applied alone to a fresh clone at 09cf3e0,
`pytest -x` without bytecode and with a 240 second limit, baseline green before and
after (928 passed, 4 skipped). 37 killed, 5 survived. Contracts for three survivors
landed in 1a88501 and were confirmed to kill them; two are equivalent.

| Id | File | Mutation | Result | Caught by |
| --- | --- | --- | --- | --- |
| A01 | `_patterns.py` | AWS drops `ASIA` | killed | `test_detectors.py::test_every_shape_is_hidden_and_labelled_by_its_detector` |
| A02 | `_patterns.py` | AWS id one character short | killed | same |
| A03 | `_patterns.py` | tokens may start inside words | killed | `test_detectors.py::test_lookalikes_are_left_alone` |
| A04 | `_patterns.py` | GitHub `ghr_` missed | killed | `test_every_shape_is_hidden_and_labelled_by_its_detector` |
| A05 | `_patterns.py` | Google key one short | killed | same |
| A06 | `_patterns.py` | Stripe `rk_` missed | killed | same |
| A07 | `_patterns.py` | PEM body runs to the end of the text | killed | same |
| A08 | `_patterns.py` | JWT with a single dot | survived, then killed | `test_lookalikes_are_left_alone[...only-two-segments]` (1a88501) |
| A09 | `_patterns.py` | bearer of any length | killed | `test_lookalikes_are_left_alone[the bearer of bad news]` |
| A10 | `_patterns.py` | URL password needs a user | killed | `test_partial_detectors_hide_only_the_secret[redis://...]` |
| A11 | `_patterns.py` | bare value runs over `&` | killed | `test_ground_truth.py::test_rfc7617_basic_and_rfc6750_bearer_examples` |
| A12 | `_patterns.py` | `tokenizer=` read as a key | killed | `test_lookalikes_are_left_alone[tokenizer=bert ...]` |
| A13 | `_patterns.py` | connection string quotes not read | equivalent | the `assignment` detector reads the same quoted value and the rescan joins the rest; `Password="a;b";Db=x` still gives `Password=***;Db=x` (pinned in 1a88501) |
| A14 | `_patterns.py` | Slack `xoxe.` tokens missed | killed | `test_ground_truth.py::test_slack_documented_prefixes_and_examples` |
| A15 | `_cards.py` | 12-digit cards | killed | `test_cards.py::test_lengths_outside_thirteen_to_nineteen_are_not_cards` |
| A16 | `_cards.py` | 20-digit cards | killed | same |
| A17 | `_cards.py` | Luhn table wrong | killed | `test_cards.py::test_luhn_matches_a_plain_reference_implementation` |
| A18 | `_cards.py` | shortest card taken | survived, then killed | `test_cards.py::test_the_longest_card_from_the_first_group_is_taken` (1a88501) |
| A19 | `_cards.py` | single-digit groups | survived, then killed | `test_cards.py::test_single_digit_groups_never_form_a_card` (1a88501) |
| A20 | `_scan.py` | joined span named after the later detector | killed | `test_every_shape_is_hidden_and_labelled_by_its_detector` |
| A21 | `_scan.py` | allowlist ignored in text | killed | `test_cli.py::test_options_reach_the_config` |
| A22 | `_scan.py` | touching redactions not joined | killed | `test_detectors.py::test_a_private_key_with_its_end_line_cut_off_is_still_hidden` |
| A23 | `_scan.py` | zero-length matches not skipped | equivalent | a zero-length span counts as already masked and renders as nothing |
| A24 | `_strategy.py` | partial reveals a secret of exactly `keep_last` | killed | `test_strategy.py::test_partial_keeps_the_tail_and_hides_short_secrets_whole` |
| A25 | `_strategy.py` | `hash_key` ignored | killed | `test_strategy.py::test_hash_length_and_hash_key` |
| A26 | `_strategy.py` | digests not recognised | killed | `test_fuzz.py::test_random_text_never_crashes_and_masking_is_idempotent` |
| A27 | `_keys.py` | plural keys missed | killed | `test_keys.py::test_secret_key_names_are_recognised[user-passwords]` |
| A28 | `_keys.py` | any substring is a key | killed | `test_keys.py::test_lookalike_key_names_are_not[author]` |
| A29 | `_walk.py` | tuples become lists | killed | `test_contract.py::test_mask_never_mutates_and_returns_new_containers` |
| A30 | `_walk.py` | shared objects read as cycles | killed | `test_mask.py::test_a_shared_object_that_is_not_a_cycle_is_masked_twice` |
| A31 | `_walk.py` | sensitive values kept | killed | `test_cli.py::test_options_reach_the_config` |
| A32 | `_config.py` | `bool` accepted as an int | killed | `test_config.py::test_wrong_types_raise_type_error` |
| A33 | `_config.py` | `hash_length=65` accepted | killed | `test_config.py::test_bad_values_raise_value_error` |
| A34 | `_config.py` | bare string allowlist accepted | killed | `test_config.py::test_wrong_types_raise_type_error` |
| A35 | `_config.py` | long values echoed in errors | killed | `test_config.py::test_error_messages_never_echo_long_input` |
| A36 | `_mask.py` | allowlist ignored for key values | killed | `test_strategy.py::test_allowlisted_values_are_kept_under_every_strategy` |
| A37 | `_mask.py` | a single pass | killed | `test_fuzz.py::test_random_text_never_crashes_and_masking_is_idempotent` |
| A38 | `_mask.py` | deep JSON leaks `RecursionError` | killed | `test_contract.py::test_mask_json_is_compact_keeps_unicode_and_rejects_bad_json` |
| A39 | `_cli.py` | no newline after an argument | killed | `test_cli.py::test_masks_a_positional_argument` |
| A40 | `_cli.py` | undecodable bytes replaced | killed | `test_cli.py::test_a_file_is_masked_byte_for_byte` |
| A41 | `_cli.py` | closed pipe on Windows is an error | killed | `test_cli.py::test_a_closed_reader_is_not_an_error` |
| A42 | `_patterns.py` | `basic_auth` renamed | killed | `test_docs.py::test_the_guide_lists_every_builtin_detector` |
