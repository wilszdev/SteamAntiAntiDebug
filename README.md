# SteamAntiAntiDebug

Should always build in the x86 config if targeting steam

Prevents steam from setting `ThreadHideFromDebugger` by hooking `NtSetInformationThread`. Also hooks `CreateProcessA` and `CreateProcessW` (where it injects itself) so that child processes (i.e. games) can't set `ThreadHideFromDebugger` either.

Need to use a DLL injector to inject this into steam. After use, make sure to (completely) restart steam before launching games with anticheat as this is pretty easy to detect so you could get banned.
