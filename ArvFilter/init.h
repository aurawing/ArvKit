#pragma once
#include <fltKernel.h>

//NTSTATUS InitProcessList();
//BOOLEAN ProcAllowed(ULONG ProcID);
//VOID FreeAllowedProcs();
NTSTATUS CleanFilterConfig();
NTSTATUS InitFilterConfig();
//BOOLEAN ProcAllowedPaths(ULONG ProcID, PSTR ProcessName, PUNICODE_STRING FullPath);
PUNICODE_STRING ArvGetSystemRoot();
ArvGetLogFlag();
VOID ArvCleanLog();
VOID ArvDeleteLogResource();
NTSTATUS ArvInitLog(PFLT_FILTER pFilter);
NTSTATUS ArvWriteLog(PCWSTR type, PUNICODE_STRING path, UINT procID, PSTR processName, BOOLEAN read, BOOLEAN isFile, BOOLEAN pass);