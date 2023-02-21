#include "pch.h"
#include "sha256.h"

VOID ArvInitializeFilterConfig(PFilterConfig pFilterConfig)
{
	InitializeListHead(&pFilterConfig->Rules);
	InitializeListHead(&pFilterConfig->RegProcs);
	InitializeListHead(&pFilterConfig->ExeAllowedPath);
}

PRuleEntry ArvAddRule(PFilterConfig pFilterConfig, UINT id, PWSTR pubKey, PZPWSTR paths, BOOL *isDBs, UINT pathsLen)
{
	PRuleEntry pRuleEntry = (PRuleEntry)ExAllocatePoolWithTag(NonPagedPool, sizeof(RuleEntry), 'RLE');
	RtlZeroMemory(pRuleEntry, sizeof(RuleEntry));
	pRuleEntry->ID = id;
	size_t pubKeyLen = wcslen(pubKey);
	pRuleEntry->PubKey.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, pubKeyLen * sizeof(wchar_t), 'RLE');
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
		PPathEntry pPathEntry = (PPathEntry)ExAllocatePoolWithTag(NonPagedPool, sizeof(PathEntry), 'PTE');
		RtlZeroMemory(pPathEntry, sizeof(PathEntry));
		pPathEntry->Path.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, pathLen * sizeof(wchar_t), 'PTE');
		for (UINT k = 0; k < pathLen; k++)
		{
			pPathEntry->Path.Buffer[k] = path[k];
		}
		pPathEntry->Path.Length = pPathEntry->Path.MaximumLength = (USHORT)pathLen * sizeof(wchar_t);
		pPathEntry->isDB = isDBs[j];
		InsertTailList(&pRuleEntry->Dirs, &pPathEntry->entry);
	}
	InsertTailList(&pFilterConfig->Rules, &pRuleEntry->entry);
	//InitializeListHead(&pRuleEntry->Procs);
	return pRuleEntry;
}

PRuleEntry ArvGetRuleEntryByRuleID(PFilterConfig pFilterConfig, UINT ruleID)
{
	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
	while (pListEntry != &pFilterConfig->Rules)
	{
		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		if (pRuleEntry->ID == ruleID)
		{
			return pRuleEntry;
		}
		pListEntry = pListEntry->Flink;
	}
	return NULL;
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

//BOOL ArvMapRule(PFilterConfig pFilterConfig, ULONG procID, BOOL inherit, UINT ruleID)
//{
//	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
//	while (pListEntry != &pFilterConfig->Rules)
//	{
//		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
//		if (pRuleEntry->ID == ruleID)
//		{
//			PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
//			while (pListEntry2 != &pRuleEntry->Procs)
//			{
//				PProcEntry ppe = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
//				if (ppe->ProcID == procID)
//				{
//					DbgPrint("[FsFilter:addRule]existed %d - %d\n", procID, ruleID);
//					return TRUE;
//				}
//				pListEntry2 = pListEntry2->Flink;
//			}
//			PProcEntry pProcEntry = (PProcEntry)ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcEntry), 'FME');
//			RtlZeroMemory(pProcEntry, sizeof(ProcEntry));
//			pProcEntry->ProcID = procID;
//			pProcEntry->Inherit = inherit;
//			InsertTailList(&pRuleEntry->Procs, &pProcEntry->entry);
//			DbgPrint("[FsFilter:addRule]new %d - %d\n", procID, ruleID);
//			return TRUE;
//		}
//		pListEntry = pListEntry->Flink;
//	}
//	return FALSE;
//}

//BOOL ArvRemoveProc(PFilterConfig pFilterConfig, ULONG procID, UINT ruleID)
//{
//	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
//	while (pListEntry != &pFilterConfig->Rules)
//	{
//		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
//		if (pRuleEntry->ID == ruleID)
//		{
//			PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
//			while (pListEntry2 != &pRuleEntry->Procs)
//			{
//				PProcEntry ppe = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
//				if (ppe->ProcID == procID)
//				{
//					DbgPrint("[FsFilter:addRule]del proc %d - %d\n", procID, ruleID);
//					RemoveEntryList(pListEntry2);
//					ExFreePoolWithTag(ppe, 'FME');
//					return TRUE;
//				}
//				pListEntry2 = pListEntry2->Flink;
//			}
//		}
//		pListEntry = pListEntry->Flink;
//	}
//	return FALSE;
//}

//VOID ArvRemoveProcEx(PFilterConfig pFilterConfig, ULONG procID)
//{
//	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
//	while (pListEntry != &pFilterConfig->Rules)
//	{
//		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
//		PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
//		while (pListEntry2 != &pRuleEntry->Procs)
//		{
//			PProcEntry ppe = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
//			if (ppe->ProcID == procID)
//			{
//				DbgPrint("[FsFilter:ArvRemoveProcEx]del proc %d - %d\n", procID, pRuleEntry->ID);
//				PLIST_ENTRY pListEntry3 = pListEntry2->Flink;
//				RemoveEntryList(pListEntry2);
//				ExFreePoolWithTag(ppe, 'FME');
//				pListEntry2 = pListEntry3;
//				continue;
//			}
//			pListEntry2 = pListEntry2->Flink;
//		}
//		pListEntry = pListEntry->Flink;
//	}
//}

VOID ArvFreeRules(PFilterConfig pFilterConfig)
{
	while (pFilterConfig->Rules.Flink != &pFilterConfig->Rules)
	{
		PLIST_ENTRY pDelRuleEntry = RemoveTailList(&pFilterConfig->Rules);
		PRuleEntry pRuleEntry = CONTAINING_RECORD(pDelRuleEntry, RuleEntry, entry);
		ArvFreeRule(pRuleEntry);
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
		pPathEntry->isDB = FALSE;
		ExFreePoolWithTag(pPathEntry, 'PTE');
		pPathEntry = NULL;
	}
	/*while (pRuleEntry->Procs.Flink != &pRuleEntry->Procs)
	{
		PLIST_ENTRY pDelProcEntry = RemoveTailList(&pRuleEntry->Procs);
		PProcEntry pProcEntry = CONTAINING_RECORD(pDelProcEntry, ProcEntry, entry);
		pProcEntry->ProcID = 0;
		ExFreePoolWithTag(pProcEntry, 'FME');
	}*/
	ExFreePoolWithTag(pRuleEntry, 'RLE');
	pRuleEntry = NULL;
}

BOOL ArvSetDBConf(PFilterConfig pFilterConfig, UINT ruleID, PWSTR path)
{
	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
	while (pListEntry != &pFilterConfig->Rules)
	{
		PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		if (pRuleEntry->ID == ruleID)
		{
			PLIST_ENTRY pListEntry2 = pRuleEntry->Dirs.Flink;
			while (pListEntry2 != &pRuleEntry->Dirs)
			{
				PPathEntry ppe = CONTAINING_RECORD(pListEntry2, PathEntry, entry);
				if (memcmp(ppe->Path.Buffer, path, ppe->Path.Length * sizeof(wchar_t)) == 0)
				{
					DbgPrint("[FsFilter:setDBPath]existed %wZ\n", ppe->Path);
					ppe->isDB = TRUE;
					return TRUE;
				}
				pListEntry2 = pListEntry2->Flink;
			}
		}
		pListEntry = pListEntry->Flink;
	}
	return FALSE;
}

VOID ArvAddProc(PLIST_ENTRY pHead, ULONG procID, BOOL inherit)
{
	PProcEntry pProcEntry = (PProcEntry)ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcEntry), 'RLE');
	RtlZeroMemory(pProcEntry, sizeof(ProcEntry));
	pProcEntry->ProcID = procID;
	pProcEntry->Inherit = inherit;
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
		pProcEntry = NULL;
	}
}

VOID ArvAddRuleEntry2(PLIST_ENTRY pHead, PRuleEntry entry, BOOL underDBPath)
{
	PRuleEntry2 pRuleEntry2 = (PRuleEntry2)ExAllocatePoolWithTag(NonPagedPool, sizeof(RuleEntry2), 'RLE');
	RtlZeroMemory(pRuleEntry2, sizeof(RuleEntry2));
	pRuleEntry2->pRuleEntry = entry;
	pRuleEntry2->underDBPath = underDBPath;
	InsertTailList(pHead, &pRuleEntry2->entry);
}

VOID ArvFreeRuleEntry2(PLIST_ENTRY pHead)
{
	while (pHead->Flink != pHead)
	{
		PLIST_ENTRY pDelProcEntry = RemoveTailList(pHead);
		PRuleEntry2 pRuleEntry2 = CONTAINING_RECORD(pDelProcEntry, RuleEntry2, entry);
		pRuleEntry2->pRuleEntry = NULL;
		pRuleEntry2->underDBPath = FALSE;
		ExFreePoolWithTag(pRuleEntry2, 'POC');
		pRuleEntry2 = NULL;
	}
}

UINT ArvGetRuleIDByRegProcName(PFilterConfig pFilterConfig, PSTR procName)
{
	PLIST_ENTRY pListEntry = pFilterConfig->RegProcs.Flink;
	while (pListEntry != &pFilterConfig->RegProcs)
	{
		PRegProcEntry pRegProcEntry = CONTAINING_RECORD(pListEntry, RegProcEntry, entry);
		if (strcmp(pRegProcEntry->ProcName, procName) == 0)
		{
			return pRegProcEntry->RuleID;
		}
		pListEntry = pListEntry->Flink;
	}
	return 0;
}

PRegProcEntry ArvGetRegProcEntryByRegProcName(PFilterConfig pFilterConfig, PSTR procName)
{
	PLIST_ENTRY pListEntry = pFilterConfig->RegProcs.Flink;
	while (pListEntry != &pFilterConfig->RegProcs)
	{
		PRegProcEntry pRegProcEntry = CONTAINING_RECORD(pListEntry, RegProcEntry, entry);
		if (strcmp(pRegProcEntry->ProcName, procName) == 0)
		{
			return pRegProcEntry;
		}
		pListEntry = pListEntry->Flink;
	}
	return NULL;
}

VOID ArvAddRegProc(PFilterConfig pFilterConfig, PSTR procName, BOOL inherit, UINT ruleID)
{
	PLIST_ENTRY pListEntry = pFilterConfig->RegProcs.Flink;
	while (pListEntry != &pFilterConfig->RegProcs)
	{
		PRegProcEntry pRegProcEntry = CONTAINING_RECORD(pListEntry, RegProcEntry, entry);
		if (strcmp(pRegProcEntry->ProcName, procName) == 0)
		{
			pRegProcEntry->RuleID = ruleID;
			pRegProcEntry->Inherit = inherit;
			return;
		}
		pListEntry = pListEntry->Flink;
	}

	PRegProcEntry pRegProcEntry = (PRegProcEntry)ExAllocatePoolWithTag(NonPagedPool, sizeof(RegProcEntry), 'RLE');
	RtlZeroMemory(pRegProcEntry, sizeof(RegProcEntry));
	PSTR regProcName = (PSTR)ExAllocatePoolWithTag(NonPagedPool, strlen(procName)+1, 'RLE');
	RtlCopyMemory(regProcName, procName, strlen(procName)+1);
	pRegProcEntry->ProcName = regProcName;
	pRegProcEntry->RuleID = ruleID;
	pRegProcEntry->Inherit = inherit;
	InsertTailList(&pFilterConfig->RegProcs, &pRegProcEntry->entry);
}

BOOL ArvFreeRegProc(PFilterConfig pFilterConfig, PSTR procName)
{
	PLIST_ENTRY pListEntry = pFilterConfig->RegProcs.Flink;
	while (pListEntry != &pFilterConfig->RegProcs)
	{
		PRegProcEntry pRegProcEntry = CONTAINING_RECORD(pListEntry, RegProcEntry, entry);
		if (strcmp(pRegProcEntry->ProcName, procName) == 0)
		{
			DbgPrint("[FsFilter:ArvFreeRegProc]del reg proc %s - %d\n", procName, pRegProcEntry->RuleID);
			RemoveEntryList(pListEntry);
			ExFreePoolWithTag(pRegProcEntry->ProcName, 'POC');
			pRegProcEntry->ProcName = NULL;
			pRegProcEntry->RuleID = 0;
			pRegProcEntry->Inherit = FALSE;
			ExFreePoolWithTag(pRegProcEntry, 'FME');
			pRegProcEntry = NULL;
			return TRUE;
		}
		pListEntry = pListEntry->Flink;
	}
	return FALSE;
}

VOID ArvFreeRegProcs(PFilterConfig pFilterConfig)
{
	while (pFilterConfig->RegProcs.Flink != &pFilterConfig->RegProcs)
	{
		PLIST_ENTRY pDelRegProcEntry = RemoveTailList(&pFilterConfig->RegProcs);
		PRegProcEntry pRegProcEntry = CONTAINING_RECORD(pDelRegProcEntry, RegProcEntry, entry);
		ExFreePoolWithTag(pRegProcEntry->ProcName, 'POC');
		pRegProcEntry->ProcName = NULL;
		pRegProcEntry->RuleID = 0;
		ExFreePoolWithTag(pRegProcEntry, 'POC');
		pRegProcEntry = NULL;
	}
}

BOOL ArvIfExeAllowedPath(PFilterConfig pFilterConfig, PUNICODE_STRING path)
{
	BOOL ret = FALSE;
	PLIST_ENTRY pListEntry = pFilterConfig->ExeAllowedPath.Flink;
	while (pListEntry != &pFilterConfig->ExeAllowedPath)
	{
		PPathEntry pPathEntry = CONTAINING_RECORD(pListEntry, PathEntry, entry);
		USHORT fpLen = path->Length;
		path->Length = pPathEntry->Path.Length;
		if (RtlCompareUnicodeString(path, &pPathEntry->Path, TRUE) == 0)
		{
			path->Length = fpLen;
			if (path->Length >= sizeof(WCHAR) * 4)
			{
				UNICODE_STRING usExeBuffer = RTL_CONSTANT_STRING(L".exe");
				UNICODE_STRING usDllBuffer = RTL_CONSTANT_STRING(L".dll");
				UNICODE_STRING usJarBuffer = RTL_CONSTANT_STRING(L".jar");
				UNICODE_STRING usImageExtBuffer = { 0 };
				WCHAR szBuffer[4] = { 0 };
				PUCHAR pBuffer = (PUCHAR)path->Buffer + path->Length - sizeof(WCHAR) * 4;
				RtlCopyMemory(szBuffer, pBuffer, sizeof(WCHAR) * 4);
				RtlInitUnicodeString(&usImageExtBuffer, szBuffer);
				usImageExtBuffer.Length = usImageExtBuffer.MaximumLength = sizeof(WCHAR) * 4;
				if (RtlEqualUnicodeString(&usExeBuffer, &usImageExtBuffer, true) || RtlEqualUnicodeString(&usDllBuffer, &usImageExtBuffer, true) || RtlEqualUnicodeString(&usJarBuffer, &usImageExtBuffer, true))
				{
					ret = TRUE;
					break;
				}
			}
		}
		path->Length = fpLen;
		pListEntry = pListEntry->Flink;
		ret = FALSE;
	}
	return ret;
}

VOID ArvAddExeAllowedPaths(PFilterConfig pFilterConfig, PZPWSTR paths, UINT pathsLen)
{
	for (UINT j = 0; j < pathsLen; j++)
	{
		PWSTR path = paths[j];
		size_t pathLen = wcslen(path);
		PPathEntry pPathEntry = (PPathEntry)ExAllocatePoolWithTag(NonPagedPool, sizeof(PathEntry), 'PTE');
		RtlZeroMemory(pPathEntry, sizeof(PathEntry));
		pPathEntry->Path.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, pathLen * sizeof(wchar_t), 'PTE');
		for (UINT k = 0; k < pathLen; k++)
		{
			pPathEntry->Path.Buffer[k] = path[k];
		}
		pPathEntry->Path.Length = pPathEntry->Path.MaximumLength = (USHORT)pathLen * sizeof(wchar_t);
		InsertTailList(&pFilterConfig->ExeAllowedPath, &pPathEntry->entry);
	}
}

VOID ArvFreeExeAllowedPaths(PFilterConfig pFilterConfig)
{
	while (pFilterConfig->ExeAllowedPath.Flink != &pFilterConfig->ExeAllowedPath)
	{
		PLIST_ENTRY pDelExeAllowedPathEntry = RemoveTailList(&pFilterConfig->ExeAllowedPath);
		PPathEntry pDelExeAllowedPath = CONTAINING_RECORD(pDelExeAllowedPathEntry, PathEntry, entry);
		RtlFreeUnicodeString(&pDelExeAllowedPath->Path);
		ExFreePoolWithTag(pDelExeAllowedPath, 'POC');
		pDelExeAllowedPath = NULL;
	}
}

VOID ArvProcessFlagInit(PProcessFlags pFlags)
{
	ExInitializeResourceLite(&pFlags->Res);
}

VOID ArvProcessFlagRelease(PProcessFlags pFlags)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&pFlags->Res);
	PProcessFlag currentFlag, tmp;
	HASH_ITER(hh, pFlags->Flags, currentFlag, tmp) {
		HASH_DEL(pFlags->Flags, currentFlag);
		ExFreePoolWithTag(currentFlag, 'pcfg');
		currentFlag = NULL;
	}
	ExReleaseResourceAndLeaveCriticalRegion(&pFlags->Res);
	ExDeleteResourceLite(&pFlags->Res);
}

VOID ArvProcessFlagAdd(PProcessFlags pFlags, UINT pid, BOOL inherit, UINT ruleID)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&pFlags->Res);
	PProcessFlag pflag = (PProcessFlag)ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcessFlag), 'pcfg');
	pflag->Pid = pid;
	pflag->Inherit = inherit;
	pflag->RuleID = ruleID;
	HASH_ADD_INT(pFlags->Flags, Pid, pflag);
	ExReleaseResourceAndLeaveCriticalRegion(&pFlags->Res);
}

PProcessFlag ArvProcessFlagFind(PProcessFlags pFlags, UINT pid)
{
	PProcessFlag pFlag = { 0 };
	ExEnterCriticalRegionAndAcquireResourceShared(&pFlags->Res);
	PProcessFlag tmp;
	HASH_FIND_INT(pFlags->Flags, &pid, tmp);
	if (tmp)
	{
		pFlag = ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcessFlag), 'pcft');
		pFlag->Pid = tmp->Pid;
		pFlag->Inherit = tmp->Inherit;
		pFlag->RuleID = tmp->RuleID;
	}
	ExReleaseResourceAndLeaveCriticalRegion(&pFlags->Res);
	return pFlag;
}

VOID ArvProcessFlagDelete(PProcessFlags pFlags, UINT pid)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&pFlags->Res);
	PProcessFlag pflag;
	HASH_FIND_INT(pFlags->Flags, &pid, pflag);
	if (pflag)
	{
		HASH_DEL(pFlags->Flags, pflag);
		ExFreePoolWithTag(pflag, 'pcfg');
		pflag = NULL;
	}
	ExReleaseResourceAndLeaveCriticalRegion(&pFlags->Res);
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

PPathEntry ArvFindPathByPrefix(PFilterConfig pFilterConfig, PUNICODE_STRING path)
{
	PLIST_ENTRY pListEntry = pFilterConfig->Rules.Flink;
	PRuleEntry pRuleEntry = NULL;
	PLIST_ENTRY pListEntry2 = NULL;
	PPathEntry ppe = NULL;
	while (pListEntry != &pFilterConfig->Rules)
	{
		pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		pListEntry2 = pRuleEntry->Dirs.Flink;
		while (pListEntry2 != &pRuleEntry->Dirs)
		{
			ppe = CONTAINING_RECORD(pListEntry2, PathEntry, entry);
			UNICODE_STRING ppes = ppe->Path;
			if (RtlPrefixUnicodeString(&ppe->Path, path, TRUE))
			{
				return ppe;
			}
			pListEntry2 = pListEntry2->Flink;
		}
		pListEntry = pListEntry->Flink;
	}
	return NULL;
}

VOID ArvAbnormalCounterInit(PAbnormalCounters counters)
{
	ExInitializeResourceLite(&counters->Res);
}

VOID ArvAbnormalCounterRelease(PAbnormalCounters counters)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&counters->Res);
	PAbnormalCounter currentCounter, tmp;
	HASH_ITER(hh, counters->counters, currentCounter, tmp) {
		HASH_DEL(counters->counters, currentCounter);
		if (currentCounter->Path.Buffer)
		{
			ExFreePoolWithTag(currentCounter->Path.Buffer, 'pcfg');
		}
		ExFreePoolWithTag(currentCounter, 'pcfg');
		currentCounter = NULL;
	}
	ExReleaseResourceAndLeaveCriticalRegion(&counters->Res);
	ExDeleteResourceLite(&counters->Res);
}

VOID ArvAbnormalCounterAdd(PAbnormalCounters counters, UINT pid)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&counters->Res);
	PAbnormalCounter counter = (PAbnormalCounter)ExAllocatePoolWithTag(NonPagedPool, sizeof(AbnormalCounter), 'pcfg');
	RtlZeroMemory(counter, sizeof(AbnormalCounter));
	counter->Pid = pid;
	HASH_ADD_INT(counters->counters, Pid, counter);
	ExReleaseResourceAndLeaveCriticalRegion(&counters->Res);
}

VOID ArvAbnormalCounterDelete(PAbnormalCounters counters, UINT pid)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&counters->Res);
	PAbnormalCounter counter = NULL;
	HASH_FIND_INT(counters->counters, &pid, counter);
	if (counter)
	{
		HASH_DEL(counters->counters, counter);
		if (counter->Path.Buffer)
		{
			ExFreePoolWithTag(counter->Path.Buffer, 'pcfg');
		}
		ExFreePoolWithTag(counter, 'pcfg');
		counter = NULL;
	}
	ExReleaseResourceAndLeaveCriticalRegion(&counters->Res);
}

VOID ArvAbnormalCounterCheck(PAbnormalCounters counters, UINT pid, PUNICODE_STRING path, PLIST_ENTRY pProcHead, BOOLEAN read, BOOLEAN isFolder, BOOLEAN pass)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&counters->Res);
	PAbnormalCounter counter = NULL;
	HASH_FIND_INT(counters->counters, &pid, counter);
	if (counter)
	{
		if (counter->Path.Buffer && RtlEqualUnicodeString(&counter->Path, path, TRUE))
		{
			counter->Counter++;
			if (counter->Counter == counters->Threshold)
			{
				counter->Forbid = TRUE;
				PWSTR optype = NULL;
				if (read)
				{
					optype = L"read";
				}
				else
				{
					optype = L"write";
				}
				ArvWriteLogEx(optype, path, pProcHead, read, isFolder, pass, TRUE);
				InterlockedIncrement64(&filterConfig.abnormalCount);
			}
		}
		else
		{
			if (counter->Path.Buffer)
			{
				ExFreePoolWithTag(counter->Path.Buffer, 'pcfg');
			}
			counter->Path.Buffer = ExAllocatePoolWithTag(NonPagedPool, path->MaximumLength, 'pcfg');
			counter->Path.Length = 0;
			counter->Path.MaximumLength = path->MaximumLength;
			RtlAppendUnicodeStringToString(&counter->Path, path);
			counter->Counter = 1;
			counter->Forbid = FALSE;
		}
	}
	ExReleaseResourceAndLeaveCriticalRegion(&counters->Res);
}

BOOL ArvAbnormalCounterIfForbid(PAbnormalCounters counters, UINT pid)
{
	BOOL ret = FALSE;
	ExEnterCriticalRegionAndAcquireResourceShared(&counters->Res);
	PAbnormalCounter counter = NULL;
	HASH_FIND_INT(counters->counters, &pid, counter);
	if (counter && counter->Forbid)
	{
		ret = TRUE;
	}
	else
	{
		ret = FALSE;
	}
	ExReleaseResourceAndLeaveCriticalRegion(&counters->Res);
	return ret;
}

VOID ArvAbnormalCounterSetThreshold(PAbnormalCounters counters, UINT threshold)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&counters->Res);
	counters->Threshold = threshold;
	ExReleaseResourceAndLeaveCriticalRegion(&counters->Res);
}