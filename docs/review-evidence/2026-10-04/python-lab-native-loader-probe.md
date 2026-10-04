# Fixed CRT-free loader differential

Preceding diagnostic trace: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37202088202.
The trace showed loaded core/runtime images, a handled startup breakpoint and final
DLL initialization failure. It did not identify a failed DllMain. No USER32/GDI
image was observed; this neither proves nor excludes a lower-level station check.
CPython's [3.12.10 DllMain source](https://raw.githubusercontent.com/python/cpython/v3.12.10/PC/dl_nt.c)
only stores the module handle on attach and returns TRUE. CRT/dependency and earlier
Windows initialization therefore remain relevant; Python-level code did not start.

## Bounded differential

The default-off `lab-loader-probe` feature first runs the original Python command
without debugger flags. Its original run evidence is written unchanged to its own
file. Only an exited 0xC0000142 outcome with verified complete cleanup permits the
next fixed diagnostic child. A live dedicated-account process blocks that step.
The account stays inside the same fresh-VM transaction and is disabled afterward.

The probe has a CRT-free entry point and uses only Kernel32 imports. Installed
MSVC builds the reviewed C source with /NODEFAULTLIB, explicit entry, /GS retained,
ASLR/NX flags and reproducible-build options. A bounded PE verifier rejects every
non-Kernel32 import, delay import or non-x64 image before staging. The exact probe
file/ancestors are checked, its build hash is checked before and after copy, and
its immutable staged image is pinned/baselined through both child runs.

This child uses the same sandbox construction, account, policy, environment,
stdio, atomic jobs and 15-second deadline, with a newly created helper token,
capability and private desktop. It is not literally the same token object. A direct
WriteFile entry marker distinguishes executable entry from pre-entry failure;
invalid stdout/write failures have distinct customer exit sentinels. There is no
CRT buffering. A bounded 100 ms pause permits observation, then fixed absolute
loads test system ucrtbase, staged vcruntime140 and staged python312 in order.
Per-call search flags restrict dependencies to that DLL's directory and System32.
No PATH/cwd search, arguments, exports, Py_Main, process spawning or policy edits
are used. Loading stops at the first failure, preserving GetLastError in the
stage marker and using a separate fixed load-failure exit sentinel.

## Interpretation

- No entry marker plus a Windows initialization status suggests failure below the
  Python dependency loads. A custom stdout sentinel instead identifies output failure.
- A failing named load identifies the failing loading stage and numeric error,
  potentially including that DLL's dependencies; it does not prove its own DllMain
  was the function that failed.
- Successful loads distinguish this dynamic-loading path from original static
  startup. Order, timing and process image differ, so this is not proof of a fix.

The original Python evidence is never overwritten. Probe results/observations have
a separate artifact. Probe-feature builds refuse LAB_SMOKE_PASS regardless of the
probe result. Debugger mode is removed for this experiment and combining the two
modes is refused. Final completion still requires a fresh normal python.exe run.

Local verification: 65 portable Rust tests, 10 Python tests and Windows-GNU
probe-feature compilation passed. The native C build, import check on the actual
produced PE and PowerShell mock additions await the approved Windows run; no local
Windows probe was executed. No shared-station ACL or privilege grant is added.

## Native build correction

[Run 37203822828](https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37203822828)
passed the Rust build but MSVC 19.44 could not link the probe: compiler-generated
`__report_rangecheckfailure` was unresolved (LNK2019/LNK1120). The import verifier,
staging and account setup were not reached. This run gives no probe runtime result.

The standalone helper now terminates with the
[Microsoft `__fastfail` intrinsic](https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail?view=msvc-170)
and `FAST_FAIL_RANGE_CHECK_FAILURE`. It has the C calling convention, no return
path and no dependency on CRT. Range checks and /GS remain enabled; the existing
Kernel32-only import verifier must still pass on the native output. A source
regression checks the exact fatal helper body. Native relinking remains pending.
