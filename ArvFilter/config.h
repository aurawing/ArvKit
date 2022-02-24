#pragma once

#include <windef.h>
#include <ntstrsafe.h>

typedef struct _PathStat {
	volatile long passCounter;
	volatile long blockCounter;

} PathStat, *PPathStat;

typedef struct _PathEntry {
	LIST_ENTRY entry;
	UNICODE_STRING Path;
	PathStat stat;

} PathEntry, *PPathEntry;

typedef struct _ProcEntry {
	LIST_ENTRY entry;
	ULONG ProcID;
} ProcEntry, *PProcEntry;

//过滤规则项，包括密钥编号、公钥、过滤目录列表
typedef struct _RuleEntry {
	LIST_ENTRY entry;
	UINT ID;
	UNICODE_STRING PubKey;
	LIST_ENTRY Dirs;
	LIST_ENTRY Procs;
} RuleEntry, *PRuleEntry;

//过滤规则
typedef struct _FilterConfig {
	LIST_ENTRY Rules;
} FilterConfig, *PFilterConfig;

VOID ArvInitializeFilterConfig(PFilterConfig pFilterConfig);
VOID ArvAddRule(PFilterConfig pFilterConfig, UINT id, PWSTR pubKey, PZPWSTR paths, UINT pathsLen);
BOOL ArvMapRule(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID);
BOOL ArvRemoveProc(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID);
VOID ArvFreeRules(PFilterConfig pFilterConfig);
VOID ArvAddProc(PLIST_ENTRY pHead, ULONG procID);
VOID ArvFreeProcs(PLIST_ENTRY pHead);
VOID ArvFreeUnicodeString(PUNICODE_STRING str, ULONG tag);
