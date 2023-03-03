#pragma once
#include <fltKernel.h>

typedef enum _LogType {  //²Ù×÷ÃüÁî
	UNKNOWN,
	LEARN,
	VERIFY,
	ENABLE,
	ABNORMAL,
} LogType;

//NTSTATUS InitProcessList();
//BOOLEAN ProcAllowed(ULONG ProcID);
//VOID FreeAllowedProcs();
NTSTATUS CleanFilterConfig();
NTSTATUS InitFilterConfig();
//BOOLEAN ProcAllowedPaths(ULONG ProcID, PSTR ProcessName, PUNICODE_STRING FullPath);
PUNICODE_STRING ArvGetSystemRoot();
PUNICODE_STRING ArvGetLogPath();
DWORD ArvGetLogFlag();
DWORD ArvGetLogOnly();
VOID ArvCleanLog();
VOID ArvDeleteLogResource();
NTSTATUS ArvInitLog(PFLT_FILTER pFilter);
NTSTATUS ArvWriteLog(PCWSTR type, PUNICODE_STRING path, UINT procID, PSTR processName, BOOLEAN read, BOOLEAN isFile, BOOLEAN pass);
NTSTATUS ArvWriteLogEx(PCWSTR type, PUNICODE_STRING path, PLIST_ENTRY pProcHead, BOOLEAN read, BOOLEAN isFolder, BOOLEAN pass, BOOLEAN abnormal);
NTSTATUS ArvClearFileEx(LogType type);