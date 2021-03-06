#pragma once

#include <windef.h>

typedef struct _PathStat {
	volatile ULONGLONG passCounter;
	volatile ULONGLONG blockCounter;
	volatile ULONGLONG passCounterDB;
	volatile ULONGLONG blockCounterDB;
} PathStat, *PPathStat;

typedef struct _PathEntry {
	LIST_ENTRY entry;
	UNICODE_STRING Path;
	BOOL isDB;
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

typedef struct _RegProcEntry {
	LIST_ENTRY entry;
	PSTR ProcName;
	UINT RuleID;
} RegProcEntry, *PRegProcEntry;

//过滤规则
typedef struct _FilterConfig {
	LIST_ENTRY Rules;
	LIST_ENTRY RegProcs;
	volatile ULONGLONG readCount;
	volatile ULONGLONG writeCount;
	volatile ULONGLONG readCountDB;
	volatile ULONGLONG writeCountDB;
} FilterConfig, *PFilterConfig;

VOID ArvInitializeFilterConfig(PFilterConfig pFilterConfig);
PRuleEntry ArvAddRule(PFilterConfig pFilterConfig, UINT id, PWSTR pubKey, PZPWSTR paths, BOOL *isDBs, UINT pathsLen);
BOOL ArvMapRule(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID);
BOOL ArvRemoveProc(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID);
VOID ArvRemoveProcEx(PFilterConfig pFilterConfig, ULONG procID);
VOID ArvFreeRules(PFilterConfig pFilterConfig);
VOID ArvFreeRule(PRuleEntry pRuleEntry);
PUNICODE_STRING ArvGetPubKeyByRuleID(PFilterConfig pFilterConfig, UINT ruleID);
BOOL ArvSetDBConf(PFilterConfig pFilterConfig, UINT ruleID, PWSTR path);
VOID ArvAddProc(PLIST_ENTRY pHead, ULONG procID);
VOID ArvFreeProcs(PLIST_ENTRY pHead);
UINT ArvGetRuleIDByRegProcName(PFilterConfig pFilterConfig, PSTR procName);
VOID ArvAddRegProc(PFilterConfig pFilterConfig, PSTR procName, UINT ruleID);
BOOL ArvFreeRegProc(PFilterConfig pFilterConfig, PSTR procName);
VOID ArvFreeRegProcs(PFilterConfig pFilterConfig);
VOID ArvFreeUnicodeString(PUNICODE_STRING str, ULONG tag);
VOID Sha256UnicodeString(PUNICODE_STRING pUniStr, BYTE result[32]);
int ArvGetTime();
ULONG ArvGetUnixTimestamp();