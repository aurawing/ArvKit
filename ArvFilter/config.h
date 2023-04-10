#pragma once

#include <windef.h>
#include "uthash.h"
#include "sha256.h"

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
	BOOL Inherit;
} ProcEntry, *PProcEntry;

//过滤规则项，包括密钥编号、公钥、过滤目录列表
typedef struct _RuleEntry {
	LIST_ENTRY entry;
	UINT ID;
	UNICODE_STRING PubKey;
	LIST_ENTRY Dirs;
	//LIST_ENTRY Procs;
} RuleEntry, *PRuleEntry;

typedef struct _RuleEntry2 {
	LIST_ENTRY entry;
	PRuleEntry pRuleEntry;
	BOOL underDBPath;
} RuleEntry2, *PRuleEntry2;

typedef struct _RegProcEntry {
	LIST_ENTRY entry;
	PSTR ProcName;
	BOOL Inherit;
	UINT RuleID;
	BOOL Once;
} RegProcEntry, *PRegProcEntry;

//过滤规则
typedef struct _FilterConfig {
	LIST_ENTRY Rules;
	LIST_ENTRY RegProcs;
	LIST_ENTRY ExeAllowedPath;
	volatile ULONGLONG readCount;
	volatile ULONGLONG writeCount;
	volatile ULONGLONG readCountDB;
	volatile ULONGLONG writeCountDB;
	volatile ULONGLONG illegalCount;
	volatile ULONGLONG sillegalCount;
	volatile ULONGLONG abnormalCount;
} FilterConfig, *PFilterConfig;

typedef struct _ProcessFlag {
	UINT Pid;
	BOOL Inherit;
	UINT RuleID;
	BOOL IsDaemon;
	UT_hash_handle hh;
} ProcessFlag, *PProcessFlag;

typedef struct _ProcessFlags {
	PProcessFlag Flags;
	ERESOURCE Res;
} ProcessFlags, *PProcessFlags;

typedef struct _ParamData {
	HANDLE ParentID;
	HANDLE ChildID;
	BOOLEAN Create;
} ParamData, *PParamData;

typedef struct _AbnormalCounter {
	UINT Pid;
	//UNICODE_STRING Path;
	ULONG Timestamp;
	ULONGLONG Counter;
	BOOL Forbid;
	UT_hash_handle hh;
} AbnormalCounter, *PAbnormalCounter;

typedef struct _AbnormalCounters {
	PAbnormalCounter counters;
	UINT Threshold;
	ULONG Interval;
	ERESOURCE Res;
} AbnormalCounters, *PAbnormalCounters;

VOID ArvInitializeFilterConfig(PFilterConfig pFilterConfig);
PRuleEntry ArvAddRule(PFilterConfig pFilterConfig, UINT id, PWSTR pubKey, PZPWSTR paths, BOOL *isDBs, UINT pathsLen);
//BOOL ArvMapRule(PFilterConfig pFilterConfig, ULONG procID, BOOL inherit, UINT ruleID);
//BOOL ArvRemoveProc(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID);
//VOID ArvRemoveProcEx(PFilterConfig pFilterConfig, ULONG procID);
VOID ArvFreeRules(PFilterConfig pFilterConfig);
VOID ArvFreeRule(PRuleEntry pRuleEntry);
PRuleEntry ArvGetRuleEntryByRuleID(PFilterConfig pFilterConfig, UINT ruleID);
PUNICODE_STRING ArvGetPubKeyByRuleID(PFilterConfig pFilterConfig, UINT ruleID);
BOOL ArvSetDBConf(PFilterConfig pFilterConfig, UINT ruleID, PWSTR path);
VOID ArvAddProc(PLIST_ENTRY pHead, ULONG procID, BOOL inherit);
VOID ArvFreeProcs(PLIST_ENTRY pHead);
VOID ArvAddRuleEntry2(PLIST_ENTRY pHead, PRuleEntry entry, BOOL underDBPath);
VOID ArvFreeRuleEntry2(PLIST_ENTRY pHead);
UINT ArvGetRuleIDByRegProcName(PFilterConfig pFilterConfig, PSTR procName);
PRegProcEntry ArvGetRegProcEntryByRegProcName(PFilterConfig pFilterConfig, PSTR procName);
VOID ArvAddRegProc(PFilterConfig pFilterConfig, PSTR procName, BOOL inherit, BOOL once, UINT ruleID);
BOOL ArvFreeRegProc(PFilterConfig pFilterConfig, PSTR procName);
VOID ArvFreeRegProcs(PFilterConfig pFilterConfig);
BOOL ArvIfExeAllowedPath(PFilterConfig pFilterConfig, PUNICODE_STRING path);
VOID ArvAddExeAllowedPaths(PFilterConfig pFilterConfig, PZPWSTR paths, UINT pathsLen);
VOID ArvFreeExeAllowedPaths(PFilterConfig pFilterConfig);
VOID ArvFreeUnicodeString(PUNICODE_STRING str, ULONG tag);

VOID ArvProcessFlagInit(PProcessFlags pFlags);
VOID ArvProcessFlagRelease(PProcessFlags pFlags);
VOID ArvProcessFlagAdd(PProcessFlags pFlags, UINT pid, BOOL inherit, UINT ruleID, BOOL isDaemon);
PProcessFlag ArvProcessFlagFind(PProcessFlags pFlags, UINT pid);
VOID ArvProcessFlagDelete(PProcessFlags pFlags, UINT pid);

VOID Sha256UnicodeString(PUNICODE_STRING pUniStr, BYTE result[32]);
int ArvGetTime();
ULONG ArvGetUnixTimestamp();

PPathEntry ArvFindPathByPrefix(PFilterConfig pFilterConfig, PUNICODE_STRING path);

VOID ArvAbnormalCounterInit(PAbnormalCounters counters);
VOID ArvAbnormalCounterRelease(PAbnormalCounters counters);
VOID ArvAbnormalCounterAdd(PAbnormalCounters counters, UINT pid);
VOID ArvAbnormalCounterDelete(PAbnormalCounters counters, UINT pid);
VOID ArvAbnormalCounterCheck(PAbnormalCounters counters, UINT pid, PUNICODE_STRING path, PLIST_ENTRY pProcHead, BOOLEAN read, BOOLEAN isFolder, BOOLEAN pass);
BOOL ArvAbnormalCounterIfForbid(PAbnormalCounters counters, UINT pid);
VOID ArvAbnormalCounterSetThreshold(PAbnormalCounters counters, UINT threshold, ULONG interval);