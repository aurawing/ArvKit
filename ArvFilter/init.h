#pragma once
#include <fltKernel.h>

//NTSTATUS InitProcessList();
BOOLEAN ProcAllowed(ULONG ProcID);
//VOID FreeAllowedProcs();

VOID ArvCleanLog();
NTSTATUS ArvInitLog(PFLT_FILTER pFilter);
NTSTATUS ArvWriteLog(PCWSTR type, PUNICODE_STRING path, UINT procID, PSTR processName, BOOLEAN pass);