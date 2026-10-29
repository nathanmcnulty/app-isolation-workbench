# Retired VM106 administration clients

These PowerShell and Python entry points fail immediately without opening a connection. Their default remoting and Python `run_ps` execution paths do not satisfy the stable PowerShell Core 7.6 runtime contract. They are intentionally unsupported rather than falling back to a legacy endpoint.

Historical code and evidence remain at source checkpoint `7bb40d6a9f3d2ea54774631826cedeadd623e644`. Do not use old installation commands or replay old worker requests. Use the runtime-bound VM107 production flow after separately approved setup and fresh native acceptance. This migration changes no VM106 credentials, services, firewall, endpoint or files.
