#pragma once
#include <fltKernel.h>
#include <windef.h>
#include "uthash.h"

#define ARVISFILE 0x01
#define ARVISDIRECTORY 0x02
#define ARVFILEORDIRECTORY 0x03

#define ARVREADFILE 0x01
#define ARVWRITEFILE 0x02
#define ARVREADWRITE 0x03

#define ARVINITRULES(pRules, procname, ruleLen)															\
do {																									\
	pRules = ExAllocatePoolWithTag(NonPagedPool, sizeof(RuleItems) + sizeof(RuleItem)*ruleLen, 'frit');	\
	RtlZeroMemory(pRules, sizeof(RuleItems) + sizeof(RuleItem)*ruleLen);								\
	strcpy_s(pRules->ProcessName, strlen(procname) + 1, procname);											\
	pRules->Len = ruleLen;																				\
} while(0)

#define ARVDEFRULE(rule, path, ford, row)		\
do {											\
	wcscpy_s(rule.Path, wcslen(path) + 1, path);	\
	rule.FileType = ford;						\
	rule.RWType = row;							\
} while (0)

//system filter path rules related structs
typedef struct _RuleItem {
	WCHAR Path[260];
	CHAR FileType;
	CHAR RWType;
} RuleItem, *PRuleItem;

typedef struct _RuleItems {
	UT_hash_handle hh;
	CHAR ProcessName[260];
	UINT Len;
	RuleItem Items[0];
} RuleItems, *PRuleItems;

//system enviroment related structs
typedef struct _EnvItem {
	UT_hash_handle hh;
	WCHAR EnvName[260];
	WCHAR EnvVal[320];
} EnvItem, *PEnvItem;

typedef struct _PathFilterRules {
	PRuleItems FilterRules;
	PEnvItem EnvsMap;
	ERESOURCE Res;
} PathFilterRules, *PPathFilterRules;

NTSTATUS ArvSysPathFilterRulesInit(PPathFilterRules pRules);
VOID ArvSysPathFilterRulesRelease(PPathFilterRules pRules);
BOOLEAN ArvSysPathFilterRulesIfMatch(PPathFilterRules pRules, ULONG ProcID, PSTR ProcessName, BYTE ForD, BYTE RorW, PUNICODE_STRING FullPath);