#pragma once

NTSTATUS InitProcessList();
BOOLEAN ProcAllowed(ULONG ProcID);
VOID FreeAllowedProcs();