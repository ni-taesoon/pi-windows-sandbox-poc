# Manual Windows build and safe basic checks

`.github/workflows/windows-basic.yml` is a `workflow_dispatch`-only workflow.
It uses a standard GitHub-hosted `windows-2022` runner (not a larger or self-hosted
runner), with a 30-minute job limit and read-only repository permission. There
are no push/PR/scheduled triggers, repository writes, deployment steps, secrets,
security-setting changes, or public activation changes.

## Run selection and bootstrap

GitHub requires a manually dispatched workflow to exist on the default branch.
If it is new on a PR branch, first obtain authorization for a **workflow-only**
bootstrap commit to the default branch. Do not merge the implementation PR to
make the button appear. Copy only `.github/workflows/windows-basic.yml` for that
bootstrap. The default-branch workflow checks out an explicitly selected source
commit, which must already contain the driver and allowlist below.

In Actions, choose **Windows build and safe basic tests**, then **Run workflow**.
Supply the reviewed implementation commit's full lowercase 40-character SHA as
`source_sha`. The workflow validates its syntax before checkout, uses it only as
an action input/environment value, and verifies `git rev-parse HEAD` afterward.
The run logs identify both the runner OS build and actual source SHA. A source
fix needs a new dispatch with its new SHA; rerunning an old run tests the old SHA.
No automatic trigger or PR merge is a substitute for manual dispatch.

Official dispatch documentation:
https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch

## Executed checks

The driver is `scripts/run_windows_basic_ci.py`. It refuses non-Windows hosts
and verifies that the Rust public activation gate remains false.

- Node 22.19.0 syntax checks and six explicit JavaScript test files: currently
  **66 tests, zero skips required**. The real Pi SDK smoke test imports
  `@earendil-works/pi-coding-agent@1.0.2`, initializes in memory without model
  network or credentials, checks registration, and disposes without executing
  a broker command. npm lifecycle scripts are disabled during installation.
- Python 3.12: 16 probe unit tests, 18 collector/schema unit tests, and the
  probe's `--self-test`. `jsonschema==4.25.1` makes schema coverage available.
  These use mocks and ordinary disposable filesystem fixtures. Socket calls in
  network-classification tests are mocked. Link fixtures may skip if Windows
  does not permit creating them; no privilege is enabled to make them work.
- Official rustup stable toolchain, target `x86_64-pc-windows-msvc`;
  toolchain version/host are logged. Cargo uses the committed lockfile.
  `cargo build --locked --target x86_64-pc-windows-msvc --release --bins`
  performs a real Windows executable link. `cargo test --lib --no-run` compiles
  and links the complete library test harness without executing tests.
- The harness is listed with `--list`; exactly the **33 named Rust tests** in
  `scripts/windows-basic-rust-tests.json` are then executed individually with
  `--exact`. Missing names, duplicates, zero executed tests, or unexpected test
  counts fail the run. Newly added tests are not automatically allowed.
- The linked release executable runs **only `status`**, which must report
  `platformSupported: true` and `nativeValidated: false`. Neither `run` nor
  `internal-experimental-helper` is invoked.

### Rust allowlist audit

The complete Rust test modules were inspected before defining the allowlist.
The included tests are value-only validators/formatters:

| Module | Count | Scope |
| --- | ---: | --- |
| `protocol::tests` | 4 | Request validation, serialization, closed activation gate |
| `policy_masks::tests` | 1 | Constant bit-mask arithmetic |
| `firewall_scope::tests` | 23 | Pure in-memory expected/readback comparisons; no COM or firewall changes |
| `network::firewall::tests` | 1 | Pure HRESULT/policy-state validation, no COM call |
| `network::wfp::tests` | 2 | Static filter key/name uniqueness, no WFP call |
| `winutil::tests` | 2 | Argument quoting strings, no process creation |

The exact names are the authority, not broad module filters. All other tests
are printed as excluded in the run log and are compiled but **not executed**:

- `acl::tests`: excluded wholesale, including temporary file/directory ACL
  mutation (`existing_deny_ace_is_visible_without_write_dac`,
  `revoking_absent_sid_preserves_child_null_dacl`). Even the pure error/root
  classification tests in that module are not selected.
- `broker::tests`: excluded wholesale. In particular,
  `denied_pid_open_still_allows_existing_handle_attenuation` creates a suspended
  child with a custom DACL; this is not an approved basic test. The other handle
  tests are also excluded.
- Token restriction/default-DACL tests: excluded; do not create restricted
  tokens, alter token defaults, impersonate, or adjust privileges.
- Token-user and token-group decoding/query tests: excluded conservatively,
  despite several being memory-only or read-only.
- `setup::no_reparse_dir::tests`: excluded wholesale, including junction and
  native directory-handle fixtures and pure path checks.
- No account creation/enabling, credential storage, desktop setup, ACL changes,
  firewall rules, WFP installation, native sandbox execution, live Python
  sandbox probe, connectivity test, or descendant-cleanup experiment runs.

JavaScript file-worker regression tests intentionally execute Node against
ordinary disposable test files. That is test-fixture code, not a production
host fallback or evidence that the Windows sandbox enforced anything.

## Pins and reproducibility limits

Official action release commits were verified against the vendors' release
pages and commit URLs:

- checkout v4.2.2: https://github.com/actions/checkout/commit/11bd71901bbe5b1630ceea73d27597364c9af683
- setup-node v4.4.0: https://github.com/actions/setup-node/commit/49933ea5288caeca8642d1e84afbd3f7d6820020
- setup-python v5.6.0: https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065

Node and direct optional package versions are fixed. The Rust stable toolchain,
Python patch release, GitHub runner image, and npm/pip transitive resolutions
can change; exact toolchain/source/run logs must accompany any result. This is
basic CI, not a fully reproducible release build. Dependency download requires
normal registry network access; no application/model endpoint is exercised.

## Interpretation

A green run establishes Windows compilation/linking and the listed basic
regressions only. It does **not** establish effective account isolation, file
or network denial, native Python behavior, process-tree cleanup, recovery, or
safe production activation. `NATIVE_VALIDATED` remains false. Those require a
separately reviewed and explicitly authorized disposable Windows lab phase.

Before the first hosted run, Linux preparation passed 66 JavaScript tests
(including the real Pi SDK), 16 Python probe tests, 18 collector/schema tests,
JavaScript syntax, Python driver syntax, and YAML parsing. Windows runtime and
MSVC linking were not claimed from those Linux checks.
