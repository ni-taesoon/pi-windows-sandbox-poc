# Firewall readback refusal: diagnostic-only follow-up

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37193517290.
Source: `29418b93813dd1213bca49eab25a88545cbea8aa`.

The parent verified that Windows build, selector mocks and staging passed. Fresh
account creation and local-SAM identity capture succeeded. Setup then rejected the
first compiled loopback-TCP firewall rule because its readback did not exactly
match the expected scope. The existing error did not identify the mismatched field.
Rollback and the final explicit disable each produced disabled-state readback.
Python execution was skipped. No raw runner/account evidence is reproduced here.

This patch adds diagnostic field names and safe scalar/byte-length metadata only.
All 22 fields are covered. No returned rule string, account/owner SID, runner path,
credential or link target is formatted into the added diagnostic. The original
exact comparator and rejection behavior remain unchanged. No field normalization,
rule broadening, firewall-profile change or privilege expansion is attempted.
The next approved fresh-VM run must identify the actual differing field before
any behavioral correction is proposed.

Local validation: 25 portable firewall-scope tests passed, including all-field
name coverage, raw-string non-disclosure, safe scalar/length output and unchanged
rejection. Windows-GNU example check passed. These are local static/unit checks,
not another Windows firewall or Python execution.
