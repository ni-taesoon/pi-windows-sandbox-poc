# Guarded directory identity query correction

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37195977256.
Source: `27fdffeed328d7337b3ef6e07b84aea6239dad63`.

The query-only helper-token opening passed. Admission then failed at the guarded
directory identity query. Setup and disabled-state recovery passed. The old error
did not preserve the native error code; no raw account/path evidence is reproduced.

Source inspection found an access-mask asymmetry: the initial target handle
requests FILE_READ_ATTRIBUTES, while the post-guard reopened directory handle
requested FILE_TRAVERSE alone before the same GetFileInformationByHandle query.
Microsoft documents read-attribute access for underlying basic-file metadata
queries. This supports missing metadata-read access as the explanation, but the
precise native failure cause remains an inference until the next Windows attempt.

The narrow correction requests FILE_TRAVERSE | FILE_READ_ATTRIBUTES on that one
broker-owned reopen. It grants no account/file ACL permission and enables no
privilege. No-reparse opening, the live directory guard, no-delete sharing,
retained handles and exact volume/file-index comparison remain unchanged.
Unavailable or unequal identities still reject admission. Both identity-query
errors now identify the API/phase and numeric Win32 error without printing paths
or file identifiers. No pathname-based identity substitution or fallback exists.

The existing handle identity mechanism is not newly claimed to provide universal
filesystem guarantees. Its original filesystem assumptions remain; this patch
does not relax identity checks for unsupported filesystems.

References:
- [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
  documents comparing volume serial and file-index members for target identity.
- [NtQueryInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile)
  documents FILE_READ_ATTRIBUTES for basic, network-open and attribute-tag queries.

Local checks: two new source-contract tests and Windows-GNU example compilation
passed. These are not native directory-query tests. The next approved fresh-VM
run must establish actual readback and continue toward restricted Python execution.
