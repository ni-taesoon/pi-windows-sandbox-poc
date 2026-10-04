# Local account identity failure and SID-based correction

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37191352982.
Source: `9ad76bd6072cc45d92207a76e824ef404f7876d1`.

Actual Windows logs show staging and expanded PowerShell selector mocks passed. Setup failed with `LAB_FAILED: LookupAccountNameW failed:
1332`. The always-disable step then failed with an NtCreateFile OS error 2 because
no credential record existed. The Python execution step was skipped.

Source-order analysis places that specific error in setup/accounts.rs after a
successful fresh NetUserAdd request with UF_ACCOUNTDISABLE, but before the
credential-record write. That is an inference from the observed error and source
order, not independent proof of the account's final state. This run did not verify
successful disable recovery, and it did not execute sandbox Python.

## Correction and bounded recovery

The fixed local username is now queried with NetUserGetInfo(NULL, name, 23).
The API result's allocation is freed with NetApiBufferFree; bounded string/SID
fields are copied before releasing it. The account name, SID shape and disabled
flag are inspected without ambiguous `.\name` LookupAccountName resolution.
Helper identity checks use the same local-SAM SID. WFP descriptors are built from
a SID trustee directly, so WFP installation/readback no longer resolves a name.

Fresh NetUserAdd remains mandatory and never adopts/resets an existing account.
A random creation-comment marker identifies this transaction, then an in-memory
guard requires that marker and the captured SID before rollback. The marker is an
accidental-collision/transaction check, not security against a malicious local
administrator. SAM name-based mutation is checked before and after against the
expected SID; the checks are not an atomic compare-and-set and do not solve an
administrator replacement race.

A protected ready:false credential record is flushed before network installation,
readback and activation. Every subsequent failure, including a failed store write,
is covered by the in-memory guard. Already-disabled state is reported only after
readback; otherwise a same-SID-checked disable is followed by another state query.
If the initial SID or marker cannot be established, there is no name-only mutation
or invented recovery. Missing-store Disable still refuses to guess an identity.
Phase-tagged diagnostics contain only fixed account name, SID, flags and observed
state; neither password, DPAPI blob nor creation marker is logged.

## Official API basis

- [NetUserGetInfo](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo)
  documents NULL server selection of the local computer and level 23.
- [USER_INFO_23](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_23)
  supplies name, comment, flags and user SID.
- [TRUSTEE_W](https://learn.microsoft.com/en-us/windows/win32/api/accctrl/ns-accctrl-trustee_w)
  supports TRUSTEE_IS_SID, avoiding a trustee-name lookup.
- [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
  explicitly documents the separate domain argument `.` as local-account-database
  selection. That domain argument is retained; it is different from `.\name`
  passed to LookupAccountName.
- The official [CreateProcessWithLogonW example](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)
  likewise identifies `.` for local-account-database selection.

The patch's local checks are cross-compilation and source contracts, not Windows
account/firewall execution. The next approved fresh-VM run must establish the
actual state transitions. Production activation and enforcement-validation claims
remain disabled; no firewall-profile enablement or privilege expansion is added.

## Publication scope

Only this technical result summary and local regression results are committed.
Raw runner logs, owner SIDs, host identifiers, authentication metadata and the
full staging-environment record are intentionally not republished in the repository.
The linked Actions run is the source for the observed failure. No credential
material is part of this change.
