#include <ntifs.h>
#include <wdm.h>

#include "config.h"
#include "sha256.h"

VOID ArvInitializeFilterConfig(PFilterConfig pFilterConfig)
{
	InitializeListHead(&pFilterConfig->Rules);
}

PRuleEntry ArvAddRule(PFilterConfig pFilterConfig, UINT id, PWSTR pubKey, PZPWSTR paths, UINT pathsLen)
{
	PRuleEntry pRuleEntry = (PRuleEntry)ExAllocatePoolWithTag(PagedPool, sizeof(RuleEntry), 'RLE');
	RtlZeroMemory(pRuleEntry, sizeof(RuleEntry));
	pRuleEntry->ID = id;
	size_t pubKeyLen = wcslen(pubKey);
	pRuleEntry->PubKey.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, pubKeyLen * sizeof(wchar_t), 'RLE');
	for (UINT i = 0; i < pubKeyLen; i++)
	{
		pRuleEntry->PubKey.Buffer[i] = pubKey[i];
	}
	pRuleEntry->PubKey.Length = pRuleEntry->PubKey.MaximumLength = (USHORT)pubKeyLen * sizeof(wchar_t);
	InitializeListHead(&pRuleEntry->Dirs);
	for (UINT j = 0; j < pathsLen; j++)
	{
		PWSTR path = paths[j];
		size_t pathLen = wcslen(path);
		PPathEntry pPathEntry = (PPathEntry)ExAllocatePoolWithTag(PagedPool, sizeof(PathEntry), 'PTE');
		RtlZeroMemory(pPathEntry, sizeof(PathEntry));
		pPathEntry->Path.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, pathLen * sizeof(wchar_t), 'PTE');
		for (UINT k = 0; k < pathLen; k++)
		{
			pPathEntry->Path.Buffer[k] = path[k];
		}
		pPathEntry->Path.Length = pPathEntry->Path.MaximumLength = (USHORT)pathLen * sizeof(wchar_t);
		InsertTailList(&pRuleEntry->Dirs, &pPathEntry->entry);
	}
	InsertTailList(&pFilterConfig->Rules, &pRuleEntry->entry);
	InitializeListHead(&pRuleEntry->Procs);
	return pRuleEntry;
}

PUNICODE_STRING ArvGetPubKeyByRuleID(PFilterConfig pFilterConfig, UINT ruleID)
{
	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
	while (pListEntry != &pFilterConfig->Rules)
	{
		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		if (pRuleEntry->ID == ruleID)
		{
			return &pRuleEntry->PubKey;
		}
		pListEntry = pListEntry->Flink;
	}
	return NULL;
}

BOOL ArvMapRule(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID)
{
	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
	while (pListEntry != &pFilterConfig->Rules)
	{
		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		if (pRuleEntry->ID == ruleID)
		{
			PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
			while (pListEntry2 != &pRuleEntry->Procs)
			{
				PProcEntry ppe = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
				if (ppe->ProcID == procID)
				{
					DbgPrint("[FsFilter:addRule]existed %d - %d\n", procID, ruleID);
					return TRUE;
				}
				pListEntry2 = pListEntry2->Flink;
			}
			PProcEntry pProcEntry = (PProcEntry)ExAllocatePoolWithTag(PagedPool, sizeof(ProcEntry), 'FME');
			RtlZeroMemory(pProcEntry, sizeof(ProcEntry));
			pProcEntry->ProcID = procID;
			InsertTailList(&pRuleEntry->Procs, &pProcEntry->entry);
			DbgPrint("[FsFilter:addRule]new %d - %d\n", procID, ruleID);
			return TRUE;
		}
		pListEntry = pListEntry->Flink;
	}
	return FALSE;
}

BOOL ArvRemoveProc(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID)
{
	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
	while (pListEntry != &pFilterConfig->Rules)
	{
		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		if (pRuleEntry->ID == ruleID)
		{
			PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
			while (pListEntry2 != &pRuleEntry->Procs)
			{
				PProcEntry ppe = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
				if (ppe->ProcID == procID)
				{
					DbgPrint("[FsFilter:addRule]del proc %d - %d\n", procID, ruleID);
					RemoveEntryList(pListEntry2);
					ExFreePoolWithTag(ppe, 'FME');
					return TRUE;
				}
				pListEntry2 = pListEntry2->Flink;
			}
		}
		pListEntry = pListEntry->Flink;
	}
	return FALSE;
}

VOID ArvFreeRules(PFilterConfig pFilterConfig)
{
	while (pFilterConfig->Rules.Flink != &pFilterConfig->Rules)
	{
		PLIST_ENTRY pDelRuleEntry = RemoveTailList(&pFilterConfig->Rules);
		PRuleEntry pRuleEntry = CONTAINING_RECORD(pDelRuleEntry, RuleEntry, entry);
		ArvFreeRule(pRuleEntry);
		/*pRuleEntry->ID = 0;
		ArvFreeUnicodeString(&pRuleEntry->PubKey, 'RLE');
		while (pRuleEntry->Dirs.Flink != &pRuleEntry->Dirs)
		{
			PLIST_ENTRY pDelPathEntry = RemoveTailList(&pRuleEntry->Dirs);
			PPathEntry pPathEntry = CONTAINING_RECORD(pDelPathEntry, PathEntry, entry);
			ArvFreeUnicodeString(&pPathEntry->Path, 'PTE');
			ExFreePoolWithTag(pPathEntry, 'PTE');
		}
		while (pRuleEntry->Procs.Flink != &pRuleEntry->Procs)
		{
			PLIST_ENTRY pDelProcEntry = RemoveTailList(&pRuleEntry->Procs);
			PProcEntry pProcEntry = CONTAINING_RECORD(pDelProcEntry, ProcEntry, entry);
			pProcEntry->ProcID = 0;
			ExFreePoolWithTag(pProcEntry, 'FME');
		}
		ExFreePoolWithTag(pRuleEntry, 'RLE');*/
	}
	InitializeListHead(&pFilterConfig->Rules);
}

VOID ArvFreeRule(PRuleEntry pRuleEntry)
{
	pRuleEntry->ID = 0;
	ArvFreeUnicodeString(&pRuleEntry->PubKey, 'RLE');
	while (pRuleEntry->Dirs.Flink != &pRuleEntry->Dirs)
	{
		PLIST_ENTRY pDelPathEntry = RemoveTailList(&pRuleEntry->Dirs);
		PPathEntry pPathEntry = CONTAINING_RECORD(pDelPathEntry, PathEntry, entry);
		ArvFreeUnicodeString(&pPathEntry->Path, 'PTE');
		ExFreePoolWithTag(pPathEntry, 'PTE');
	}
	while (pRuleEntry->Procs.Flink != &pRuleEntry->Procs)
	{
		PLIST_ENTRY pDelProcEntry = RemoveTailList(&pRuleEntry->Procs);
		PProcEntry pProcEntry = CONTAINING_RECORD(pDelProcEntry, ProcEntry, entry);
		pProcEntry->ProcID = 0;
		ExFreePoolWithTag(pProcEntry, 'FME');
	}
	ExFreePoolWithTag(pRuleEntry, 'RLE');
}

VOID ArvAddProc(PLIST_ENTRY pHead, ULONG procID)
{
	PProcEntry pProcEntry = (PProcEntry)ExAllocatePoolWithTag(PagedPool, sizeof(ProcEntry), 'RLE');
	RtlZeroMemory(pProcEntry, sizeof(ProcEntry));
	pProcEntry->ProcID = procID;
	InsertTailList(pHead, &pProcEntry->entry);
}

VOID ArvFreeProcs(PLIST_ENTRY pHead)
{
	while (pHead->Flink != pHead)
	{
		PLIST_ENTRY pDelProcEntry = RemoveTailList(pHead);
		PProcEntry pProcEntry = CONTAINING_RECORD(pDelProcEntry, ProcEntry, entry);
		pProcEntry->ProcID = 0;
		ExFreePoolWithTag(pProcEntry, 'POC');
	}
}

VOID ArvFreeUnicodeString(PUNICODE_STRING str, ULONG tag)
{
	if (str) {
		if (str->Buffer)
		{
			ExFreePoolWithTag(str->Buffer, tag);
			str->Buffer = NULL;
			str->Length = str->MaximumLength = 0;
		}
	}
}

VOID Sha256UnicodeString(PUNICODE_STRING pUniStr, BYTE result[32])
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, pUniStr->Buffer, pUniStr->Length);
	sha256_final(&ctx, result);
}

int ArvGetTime()
{
	LARGE_INTEGER GelinTime = { 0 };
	LARGE_INTEGER LocalTime = { 0 };
	TIME_FIELDS NowFields;
	KeQuerySystemTime(&GelinTime);
	ExSystemTimeToLocalTime(&GelinTime, &LocalTime);
	RtlTimeToTimeFields(&LocalTime, &NowFields);
	return NowFields.Hour * 3600 + NowFields.Minute * 60 + NowFields.Second;
}

ULONG ArvGetUnixTimestamp()
{
	LARGE_INTEGER GelinTime = { 0 };
	ULONG ts = 0;
	KeQuerySystemTime(&GelinTime);
	BOOLEAN ret = RtlTimeToSecondsSince1970(&GelinTime, &ts);
	if (ret)
	{
		return ts;
	}
	else
	{
		return 0;
	}
}