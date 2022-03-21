#pragma once
#include <ntddk.h>

NTSTATUS InitProcessList();
BOOLEAN ProcAllowed(ULONG ProcID);
VOID FreeAllowedProcs();