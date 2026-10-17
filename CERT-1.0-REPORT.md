# secretmask 1.0.0 certification report

Progress:
- [x] Branch `release/1.0.0` created from `main` (0.2.0, 0668d02; PyPI has 0.2.0)
- [x] Baseline gates run on 0.2.0
- [x] API review and 1.0.0 API changes (item 1)
- [x] Ground truth: vendor documentation, RFCs and reference rule sets fetched, detect-secrets run live (item 7)
- [x] Errors, typing, docstrings and doctests (items 2 to 5)
- [x] Contract, fuzz and author mutation round (items 6, 9, 18)
- [x] Docs: README, GUIDE, CHANGELOG (items 11, 12)
- [x] Packaging, e2e and upgrade from PyPI 0.2.0 (items 8, 13, 14)
- [x] Every interpreter on this PC (item 10)
- [x] Five QA lenses report PASS (item 19)
- [x] Independent reviewer (item 16)
- [x] Gates (item 15)
- [x] PR #3 open and trace guard CLEAN (item 17); merge and publish left to the maintainer

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

## API review (items 1 to 5)

Kept from 0.2.0: the six public names (`mask`, `mask_text`, `mask_json`, `SecretMask`,
`MaskConfig`, `Strategy`), every signature, every `MaskConfig` field and default, the
`Strategy` values, the detector names used by the label strategy, and the
`secretmask` command with its options. Added: `MaskConfig.hash_key` (last field,
keyword-friendly), `SecretMask.config`, `SecretMask.__repr__`, `--file -`. Changed:
typed argument checks with documented `TypeError`/`ValueError` (GUIDE "Errors"),
bounded messages, public names reporting `secretmask` as their module, `mask` without
recursion (cycles raise `ValueError`). `__all__` lists the six names and nothing else
public shows in `dir(secretmask)`; `tests/test_contract.py` freezes the signatures and
the config fields. Every public name and the three masker methods carry examples that
`tests/test_docs.py` runs, along with every README and GUIDE example (output compared
line by line). `mypy --strict src tests scripts` is clean; `mask` returns `Any` because
it returns the shape it is given (documented in GUIDE).

## Behaviour changes against PyPI 0.2.0

The CHANGELOG "Changed (upgrading from 0.2.0)" list is the reference; lens a checked it
line by line against the real 0.2.0 from PyPI (58 side-by-side probes) and lens d ran
0.2.0-style code before and after an in-place upgrade with identical output. In short:
more secrets found (vendor formats as documented, `AWS_SECRET_ACCESS_KEY=`,
`client_secret=`, JSON-like text, quoted values with spaces and escapes, Basic
credentials, OpenPGP keys, truncated key blocks, unsecured JWTs, cards followed by a
date); fewer false hits (tokens inside words, AWS unique ids that are not credentials,
`author`/`tokenizer` keys, digit lists); stable output when masked again; typed config
errors (`ValueError` instead of `re.error` for a bad regex); no recursion limit; CLI
writes input back byte for byte, exits 2 on usage errors, masks its own messages.

## Supported Pythons (item 10)

`requires-python = ">=3.10"`. The suite from the extracted sdist, with `src` removed so
it imports the installed wheel, on every interpreter of this PC from 3.10 up, at
e7ad5f6: CPython 3.10.19, 3.11.5, 3.12.12, 3.13.2, 3.14.2 and 3.14.2 free-threaded,
1015 passed and 50 skipped on each (the fetched-source tests, which the sdist does not
carry, the live detect-secrets test and the opt-in wheel end-to-end tests). 3.8 and 3.9
are installed but below `requires-python`. Lens d ran the same at 99eccef (1003 passed
each), and CPython 3.14.6 on the laptop.

## Ground truth (item 7)

Nothing here is the library's own output. Three kinds of truth:

- **Each vendor's own documentation and the RFCs, fetched live.**
  `scripts/fetch_sources.py` (2026-10-16) fetches the AWS IAM identifiers page, GitHub's
  token formats, Stripe's API keys, testing and webhook pages, Slack's token types,
  Google Cloud's API keys page and RFC 3986, 4880, 6750, 7468, 7519 and 7617;
  `tests/sources/MANIFEST.json` records URL, date, size, SHA-256 and licence, and the
  copies stay git-ignored. `tests/test_ground_truth.py` reads facts from the copies at
  run time: the twelve AWS id prefixes and which four are credentials (the others, and
  the page's `AIDA...`/`AROA...` examples, stay visible), GitHub's six token prefixes
  and the 2026 stateless `ghs_APPID_JWT` note, Stripe's `sk_`/`rk_`/`pk_`/`sk_org_`/`whsec_`
  prefixes (publishable keys stay), every Luhn-valid number in Stripe's testing page
  (at least 30 test cards), Slack's documented prefixes and example tokens, Google's
  example key, both complete JWTs of RFC 7519 (signed and unsecured), every
  `BEGIN`/`END` block of RFC 7468 (private ones hidden, certificates and public keys
  kept), the OpenPGP armor labels of RFC 4880, the Basic examples of RFC 7617 and the
  Bearer examples of RFC 6750.
- **Other scanners' rule sets.** gitleaks (`config/gitleaks.toml` at b58d3f1, MIT) and
  trufflehog (seven detector files at 31d7303, AGPL-3.0) are fetched at pinned commits,
  never committed, and compiled in `tests/test_reference_rules.py`: over a seeded
  corpus of synthetic tokens and `key = value` lines, everything any of their rules
  matches must be gone after masking (25 seeds), and every generated vendor token must
  be recognised by at least one gitleaks rule, so the corpus uses real formats. The
  test of the corpus first found `session_key=` missed (gitleaks generic rule): fixed.
- **detect-secrets 1.5.0, run live.** `scripts/capture_oracles.py` ran its vendor and
  keyword plugins over seeds 0 to 19 of the corpus (CPython 3.13.2): 2,262 findings,
  stored as seed, line, plugin, span and SHA-256 only (no secret text) in
  `tests/fixtures/detect_secrets.json`; the test regenerates each line, checks the hash
  and that the finding is hidden. With detect-secrets installed, ten fresh seeds are
  scanned live. Before the fix of `$config['key'] = 'v'` and `key => 'v'`, 720 of its
  keyword findings leaked; after, none.

All synthetic secrets are generated at run time from a seed and carry a marker no real
credential has (AWS's own `EXAMPLE` suffix, `FAKE`, broken GitHub checksums, unsigned
JWTs); no token appears literally in the repository. Stripe's published test card
numbers are cited with their URL in `tests/test_cards.py`.

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

## QA lenses (item 19)

Five independent reviews, one at a time, each reading the certification rules, running
the code and reporting only to the maintainer. Later rounds confirm the earlier findings
and sweep at most 40 new mutations on the code changed since.

| Lens | Round | Head | Verdict | Findings and outcome |
| --- | --- | --- | --- | --- |
| a. API and docs | 1 | 1a88501 | FAIL | `extra_patterns` as a list of lists refused (worked in 0.2.0); `password => x` garbled by the connection-string detector; GUIDE claimed every error message is bounded (CLI and `JSONDecodeError.doc` were not); `--key` only affects mappings, undocumented; GUIDE key-rule wording; CLI usage errors exited 1. Fixed in a94408b and eb4a3a3 |
| a | 2 | eb4a3a3 | FAIL | all seven confirmed fixed; examples and doctests rerun; 35 mutants on the changed code: 20 killed, 3 equivalent, 12 needing contracts (pattern option parsing, malformed pairs, quoted password values). Contracts in d76e796 |
| a | 3 | d76e796 | PASS | all 12 survivors killed by the full suite; new tests check hard-coded expectations |
| b. Correctness and ground truth | 1 | d76e796 | FAIL | own corpus of 231 cases from docs fetched live, gitleaks 8.30.1 (91 hits), trufflehog 3.99.2 (49) and detect-secrets 1.5.0 (40) on it: 0 leaks after masking except: quoted values holding the other quote or an escaped quote leaked their tail; a number before a card was read into it and the card's last digits shown; `pw@db.example.com` read as an email, swallowing the URL host; ADO.NET unquoted passwords with spaces; tokens after `-` missed; 40 own mutants, 30 killed, 10 needing contracts. Fixed in 635cfce, 2c40084 and a406a4a (card layouts and overlapping readings joined, emails never inside a URL authority, escape-aware quoted values) |
| b | 2 | a406a4a | FAIL | all leak reproducers fixed; 70,000 card-adjacency cases, 0 digits shown; scanners on the corpus: 0 leaks. Partial: a URL password with sub-delims or `~` still let the email detector swallow the host; JWTs after `-`/`_` undocumented. 11 round-1 survivors killed; 40 new mutants: 20 killed, 2 equivalent, 18 needing contracts (escapes under partial and hash, spaced values, single-quote escapes, card layouts and joins). Fixed in f76c378 (email never read inside a URL authority, quoted fragments kept together) |
| b | 3 | f76c378 | FAIL | round-2 fixes confirmed and the corpus clean, but the URL-authority guess hid no email glued to a URL by `,` `;` `\|` `)` or quotes (a regression); 7 of 18 round-2 survivors and 27 of 35 new mutants survived. Fixed in 196e46b: the guess was removed, an address that overlaps a hidden URL password yields to it, the URL user part stops at quotes and `<>` |
| b | 4 | 196e46b | FAIL | emails glued to URLs all hidden and hosts kept; single-quoted values with doubled quotes (`'it''s'`) showed their tail; a URL password ran over `,` into the next value; addresses with more than 64 characters before `@` missed; 46 mutants: survivors in quoted escapes, card runs of 16 or more, URL bounds and the yield rule. Fixed in 8964f58 |
| b | 5 | e8fd83d | FAIL | round-4 findings confirmed fixed and the corpus clean; 8 of 10 round-4 survivors killed, N12 argued equivalent (the `assignment` detector reads the same doubled quote), U8 over-masking only; new sweep: URL separators `;` `\|` `(` `)` `'` and single-quote doubled escapes unpinned, and addresses with 129 to 256 characters before `@` still missed under a mutant. Contracts and an unbounded address name in fb44b87 |
| b | 6 | fb44b87 | FAIL | round-5 survivors killed (N12 equivalent again); corpus unchanged, no leak, names of 1 to 100,000 characters hidden; 10 mutants on the address name: 7 killed, 1 equivalent (lazy match before a literal `@`), 2 test gaps: a lookbehind without `+` turns quadratic on long `+` runs, and no name over 300 characters was tested. Hostile runs of `+`, `%` and `_` and a 5,000-character name added in 91c03ac |
| b | 7 | 91c03ac | PASS | both round-6 survivors killed by the full suite (the 5,000-character name and the `+` run timing test); suite green before and after |
| c. Adversarial and robustness | 1 | 6004e12 | FAIL | fuzz clean (14,000 planted-secret seeds, 291,000 noise runs, idempotent), every hostile shape linear, a 200 MB file masked with no leak, closed pipes exit 0. Findings: the CLI echoed a secret typed as an option or as a bad `--strategy`/`--keep-last` value to standard error; `--json` with an escaped lone surrogate exited 1; data sharing objects (`y = [y, y]` twenty times) took exponential time; 40 mutants, 29 killed, 1 equivalent, 10 needing contracts. Fixed in c2b24ab and 571d5d9 (masked CLI messages, escaped surrogates in JSON output, shared copies reused, `tests/test_robust.py`) |
| c | 2 | ff5ba17 | FAIL | round-1 fixes confirmed (CLI messages, JSON surrogates, shared objects in 0.0002 s); 10 survivors killed, M10 equivalent; fuzz (64,424 noise runs) and timing clean. New: the shared-object cache keyed by `id()` could hand a later value an earlier copy when a mapping builds values on access; argparse still echoed `--ke=<value>` and `--json=<value>`; 35 new mutants, 19 killed, 16 needing contracts. Fixed in e2c7ffd |
| c | 3 | 3cc5b40 | FAIL | id-reuse fix and plain-value redaction confirmed; argparse still echoed values holding whitespace (`--ke=a SECRET`), a single quote (`--json=it'sSECRET`, `--strategy`, `--keep-last`) or a second `=`; 13 of 16 round-2 survivors killed, N23 equivalent, N04 and N09 needing a masked message of ours; 13 new mutants, 9 killed, 2 equivalent (cache identity, root entry), 2 needing contracts. Fixed in 30e1c20: usage errors rebuilt from the parser's option names only |
| c | 4 | 224f169 | PASS | 322 CLI probes (whitespace, quotes, `=`, `: `, non-ASCII in values; unknown, ambiguous, invalid and ignored-argument options): no four-character piece of a typed value on standard error; N04, M04 and M05 killed; N09 equivalent in practice (no argparse message reaching the parser's error keeps typed text); 12 new mutants: 7 killed, 4 wording-only, D07 (`rpartition`) leaked a value holding `": "`: contract added in bf724bf and confirmed to kill it |
| d. Packaging and real e2e | 1 | 99eccef | PASS (1 minor) | build and `twine check --strict`; wheel and sdist contents and metadata; outsider venv with a strict mypy consumer of all six names; console script and `python -m` by subprocess (44 cases, closed pipe, non-UTF-8 bytes, no secret on stderr); in-place upgrade from PyPI 0.2.0 with identical output; opt-in e2e 3 passed; suite from the sdist against the installed wheel on CPython 3.10.19, 3.11.5, 3.12.12, 3.13.2, 3.14.2 and 3.14.2t, 1003 passed each. Minor: `scripts/release.ps1` named a PowerShell 7-only exception type and stopped under 5.1 (failing safe); fixed with a generic catch, guard checked under 5.1 for 0.2.0 (refused) and 1.0.0 (free) |
| e. Contract strength (blind) | 1 | cbe2fc3 | FAIL | 80 own mutants over all 11 modules with the ground-truth tests active: 64 killed, 1 equivalent (touching spans grouped early), 15 needing contracts: escapes in quoted values, the `,` stop, allowlisted touching spans, optional `s` groups, repeated and empty key names, full-length digests, empty labels, an empty placeholder (a hang under the mutant), surrogates and non-ASCII keys in hashing, built-ins before extra patterns, the bytes message, the missing option value message. Contracts in 68c1f31 (`tests/test_edges.py`), all 15 confirmed killed |
| e | 2 | 7b869c5 | PASS | all 15 round-1 survivors killed by the full suite (T03 by the 300 s limit: the empty-placeholder test hangs under that mutant); the new tests assert fixed literals or digests computed apart with `hashlib`/`hmac`; suite green before and after |

## Independent reviewer (item 16)

| Round | Head | Verdict | Findings and outcome |
| --- | --- | --- | --- |
| 1 | 04c096f | FAIL (item 5) | 18 items passed from fresh clones (gates each alone, build and `twine check --strict`, archives, metadata, 27 README and CHANGELOG claims rerun from the wheel, doctests, opt-in e2e with the 0.2.0 upgrade, report hashes and test names, hygiene, trace guard CLEAN); 25 own mutants on `_scan.py`, `_patterns.py`, `_output.py`: 23 killed, 2 equivalent (touching spans that no detector can produce). Fail: a custom regex too large (`a{4294967296}`) or too nested raised `OverflowError`/`RecursionError` instead of `ValueError`, and the CLI showed a traceback. Minor: two test files over 200 lines. Fixed in 148babd |
| 2 | 89dfbd5 | PASS | the regex fix confirmed (`ValueError`, one-line CLI message); every file under `src/` and `tests/` at most 200 lines; the four gates each alone on a fresh clone with the sources fetched (1063 passed, 4 skipped); 5 mutants on the change: 4 killed, the message wording pinned after it (exact message match in `tests/test_edges.py`); trace guard CLEAN |

## Gates (item 15)

From fresh clones at 89dfbd5, each command alone with the sources fetched first:
`ruff format --check .`, `ruff check .`, `mypy --strict src tests scripts` exit 0;
`pytest` 1063 passed, 4 skipped (three opt-in wheel tests and the live detect-secrets
test). `SECRETMASK_E2E=1 pytest tests/test_e2e_wheel.py` 3 passed (wheel in a fresh
venv, console script, in-place upgrade from PyPI 0.2.0). `python -m build` and
`twine check --strict` pass for the wheel and the sdist.

## Scorecard

| # | Item | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | API reviewed for stability | PASS | every 0.2.0 name, signature and default kept; additions and changes in CHANGELOG 1.0.0, checked against PyPI 0.2.0 by lenses a and d |
| 2 | `__all__` exact | PASS | six names, nothing else public (`tests/test_contract.py`) |
| 3 | Docstrings with runnable examples | PASS | every public name and the three masker methods; doctests and every README and GUIDE example run in `tests/test_docs.py` |
| 4 | Typed end to end | PASS | `mypy --strict src tests scripts` clean; `py.typed` shipped; strict outsider consumer clean (lens d) |
| 5 | Typed, documented, safe errors | PASS | GUIDE "Errors"; long values described by length; CLI messages masked and rebuilt from option names (lens c, reviewer) |
| 6 | Contract asserts the full promise | PASS | 1063 tests: frozen signatures, every detector, vendor and RFC ground truth, reference rules, fuzz, hostile input, CLI |
| 7 | Real ground truth | PASS | vendor pages and RFCs fetched live with manifest; gitleaks and trufflehog rules at pinned commits; detect-secrets 1.5.0 run live (2,262 findings recorded); re-derived independently by lens b over six rounds |
| 8 | Real e2e incl. PyPI upgrade | PASS | opt-in wheel tests; outsider venv; in-place upgrade from PyPI 0.2.0 with identical output (author, lens d, reviewer) |
| 9 | Seeded fuzz, no crash, hang or blow-up | PASS | seeded fuzz in the suite; lens c: 14,000 planted-secret seeds, 291,000 noise runs, linear timing on every hostile shape, a 200 MB file |
| 10 | Every interpreter on this PC | PASS | 3.10.19, 3.11.5, 3.12.12, 3.13.2, 3.14.2, 3.14.2t from the installed wheel, 1015 passed each |
| 11 | README | PASS | `twine check --strict`; absolute links; problem, verified why, install, quick start, guide and changelog links |
| 12 | CHANGELOG dated 1.0.0 | PASS | `## [1.0.0] - 2026-10-16` with the stable surface and every change since 0.2.0 |
| 13 | pyproject | PASS | 1.0.0 from one source, Production/Stable, 3.10 to 3.14, MIT, Homepage/Source/Issues/Changelog, keywords, no dependencies |
| 14 | sdist and wheel contents | PASS | wheel: package, `py.typed`, LICENSE; sdist: source, tests, hash-only oracle fixture, manifest, scripts, docs; no fetched copy or notes |
| 15 | Gates exit 0 alone | PASS | fresh clones, each command alone (author and reviewer) |
| 16 | Independent reviewer | PASS | round 1 FAIL at 04c096f, round 2 PASS at 89dfbd5 |
| 17 | PR, trace guard | ready | PR #3 from `release/1.0.0`, trace guard CLEAN; merge and PyPI publish left to the maintainer |
| 18 | Mutation rounds | PASS | author 42; lens a 35 + 12; lens b 40 + 40 + 46 + 16 + 10 + 2; lens c 40 + 46 + 29 + 16; blind lens e 80 + 15; reviewer 25 + 5; every survivor killed by a contract or argued equivalent |
| 19 | Five QA lenses | PASS | a (round 3), b (round 7), c (round 4), d (round 1), e (round 2) |
