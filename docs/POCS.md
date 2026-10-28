# PoC correspondence

This table maps the 33 PoCs in the paper's "Per-sample detection results on 33 PoC samples" table to their implementations and sources.

## Sources

- Self: [groundtruth.cpp](../poc/groundtruth.cpp) implements the six self-implemented entries listed below as menu cases 1–6.
- S23: Starink et al., SecureComm 2023, [code-injection-malware](https://github.com/utwente-scs/code-injection-malware). The twelve traditional PoCs are in [data/ground-truth-samples.zip](https://github.com/utwente-scs/code-injection-malware/blob/a648c7f56d3dfa866d1d3b837426eda6d034abc6/data/ground-truth-samples.zip).
- PP: [SafeBreach-Labs/PoolParty](https://github.com/SafeBreach-Labs/PoolParty), `PoolParty.exe`.

## All 33 paper entries

| Row | Paper category / variant | Source entry |
|---|---|---|
| 1 | Remote thread / CreateRemoteThread | Self: case 1, `Test_RemoteThread_Win32` |
| 2 | Remote thread / NtCreateThreadEx | Self: case 2, `Test_RemoteThread_Native` |
| 3 | Remote thread / RtlCreateUserThread | Self: case 3, `Test_RtlCreateUserThread` |
| 4 | Remote thread / Variant A | S23 ZIP: `binaries/Shell/shell_Process_Injection_Techniques_shell.exe` |
| 5 | Remote thread / Variant B | S23 ZIP: `binaries/Shell/shell_shellinject.exe` |
| 6 | APC / EarlyBird APC | Self: case 5, `Test_EarlyBird` |
| 7 | APC / Generic APC | Self: case 4, `Test_APC_Runtime` |
| 8 | APC / Variant A | S23 ZIP: `binaries/APCSHell/acpshell_apcshellinject.exe` |
| 9 | APC / Variant B | S23 ZIP: `binaries/APCSHell/apcshell_Process_Injection_Techniques.exe` |
| 10 | Reflective DLL / Variant A | S23 ZIP: `binaries/Shell/shell_Process_Injection_Techniques_reflective.exe` |
| 11 | Reflective DLL / Variant B | S23 ZIP: `binaries/Shell/shell_reflectivedllinject.exe` |
| 12 | Process hollowing / Variant A | S23 ZIP: `binaries/ProcessHollowing/hollow_Process_Injection_Techniques.exe` |
| 13 | Process hollowing / Variant B | S23 ZIP: `binaries/ProcessHollowing/hollow_processhollow.exe` |
| 14 | Process hollowing / Variant C | S23 ZIP: `binaries/ProcessHollowing/hollow_ProcessHollowing2_x64.exe` |
| 15 | Thread hijacking / Variant A | Self: case 6, `Test_Context_Hijack` |
| 16 | Thread hijacking / Variant B | S23 ZIP: `binaries/ThreadHijack/threadhijack_injectAllTheThings.exe` |
| 17 | Thread hijacking / Variant C | S23 ZIP: `binaries/ThreadHijack/threadhijack_Process_Injection_Techniques.exe` |
| 18 | Thread hijacking / Variant D | S23 ZIP: `binaries/ThreadHijack/threadhijack_threadhijack.exe` |
| 19 | PoolParty / ALPC | PP: TP_ALPC, ID 5 |
| 20 | PoolParty / Direct | PP: TP_DIRECT, ID 7 |
| 21 | PoolParty / Job Object | PP: TP_JOB, ID 6 |
| 22 | PoolParty / Start Routine | PP: worker-factory start routine, ID 1 |
| 23 | PoolParty / TP I/O | PP: TP_IO, ID 4 |
| 24 | PoolParty / Timer | PP: TP_TIMER, ID 8 |
| 25 | PoolParty / Wait | PP: TP_WAIT, ID 3 |
| 26 | PoolParty / Work | PP: TP_WORK, ID 2 |
| 27 | Emerging / Dirty Vanity | [deepinstinct/Dirty-Vanity](https://github.com/deepinstinct/Dirty-Vanity/tree/30c2ba7c1caa35378403b75b8caee3e5eb18614c) |
| 28 | Emerging / DLL notify | [Dec0ne/DllNotificationInjection](https://github.com/Dec0ne/DllNotificationInjection/tree/6b067ca4834c331c38dccdb72ce89fa193de5700) |
| 29 | Emerging / Early Cascade | [Cracked5pider/earlycascade-injection](https://github.com/Cracked5pider/earlycascade-injection/tree/8a9c010b275b413ef0318b7fd4973e4a4e69d779) |
| 30 | Emerging / FrostLock | [zero2504/FrostLock-Injection](https://github.com/zero2504/FrostLock-Injection/tree/82d9f38c39299147265abde2d81a8009364be7af) |
| 31 | Emerging / PoisonFiber | [JanielDary/ImmoralFiber](https://github.com/JanielDary/ImmoralFiber/tree/b2d93d23e2f8f0d4a4ce4af423470762ef43469a) |
| 32 | Emerging / Thread Name-Calling | [hasherezade/thread_namecalling](https://github.com/hasherezade/thread_namecalling/tree/441386b7aed9b7207dac5b3801f575877acdf518) |
| 33 | Emerging / Waiting-thread hijack | [hasherezade/waiting_thread_hijacking](https://github.com/hasherezade/waiting_thread_hijacking/tree/724cf6e540823f326d4e476bf0dcd274c0d1273b) |

## Build the self-implemented PoCs

Run in an x64 Native Tools Command Prompt:

```cmd
cl /EHsc /std:c++17 /utf-8 poc\groundtruth.cpp /link advapi32.lib
```
