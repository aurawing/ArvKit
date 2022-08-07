#include "comm.h"

PFLT_PORT     gServerPort;//服务端口
PFLT_PORT     gClientPort;//客户端口

//用户态和内核态建立连接
NTSTATUS
MiniConnect(
	__in PFLT_PORT ClientPort,
	__in PVOID ServerPortCookie,
	__in_bcount(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
)
{
	DbgPrint("[FsFilter:MiniConnect]connected");
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	ASSERT(gClientPort == NULL);
	gClientPort = ClientPort;
	return STATUS_SUCCESS;
}

//用户态和内核断开连接
VOID
MiniDisconnect(
	__in_opt PVOID ConnectionCookie
)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ConnectionCookie);
	DbgPrint("[FsFilter:MiniDisconnect]disconnected");

	//  Close our handle
	FltCloseClientPort(g_minifilterHandle, &gClientPort);
}

//用户态和内核态传送数据
NTSTATUS
MiniMessage(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
)
{

	NTSTATUS status = STATUS_SUCCESS;
	wchar_t buffer[] = L"had received";
	// LIST_ENTRY tmpHeader = { 0 };
	// PLIST_ENTRY firstEntry = NULL;
	// PLIST_ENTRY lastEntry = NULL;
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ConnectionCookie);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	if ((InputBuffer != NULL) &&
		(InputBufferSize >= (FIELD_OFFSET(OpGetStat, command) +
			sizeof(OpCommand)))) {
		//int level = KeGetCurrentIrql();
		DbgPrint("[FsFilter:MiniMessage]received message\n");
		OpSetProc *pOpSetProc = NULL;
		OpSetRules *pOpSetRules = NULL;
		OpSetDBConf *pOpSetDBConf = NULL;
		OpSetAllowUnload *pOpSetAllowUnload = NULL;
		OpSetControlProc *pOpSetControlProc = NULL;
		OpCommand command;
		try {
			command = ((POpGetStat)InputBuffer)->command;
			switch (command)
			{
			case SET_PROC:
				pOpSetProc = (OpSetProc*)InputBuffer;
				ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
				BOOL ret = ArvMapRule(&filterConfig, pOpSetProc->procID, FALSE, pOpSetProc->ruleID);
				ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
				DbgPrint("[FsFilter:MiniMessage]add procID %d: %d - %d\n", ret, pOpSetProc->procID, pOpSetProc->ruleID);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			case SET_RULES:
				ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
				FilterConfig tmpConfig = { 0 };
				ArvInitializeFilterConfig(&tmpConfig);
				tmpConfig.readCount = filterConfig.readCount;
				tmpConfig.writeCount = filterConfig.writeCount;
				pOpSetRules = (OpSetRules*)InputBuffer;
				controlProcID = pOpSetRules->controlProcID;
				for (UINT i = 0; i < pOpSetRules->ruleLen; i++)
				{
					PRuleEntry newRuleEntry = ArvAddRule(&tmpConfig, pOpSetRules->rules[i]->id, pOpSetRules->rules[i]->pubKey, pOpSetRules->rules[i]->paths, pOpSetRules->rules[i]->isDB, pOpSetRules->rules[i]->pathsLen);

					PLIST_ENTRY pListEntry = filterConfig.Rules.Flink;
					while (pListEntry != &filterConfig.Rules)
					{
						PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
						if (pRuleEntry->ID == newRuleEntry->ID)
						{
							PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
							while (pListEntry2 != &pRuleEntry->Procs)
							{
								PProcEntry ppe = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
								ArvAddProc(&newRuleEntry->Procs, ppe->ProcID, ppe->Inherit);
								pListEntry2 = pListEntry2->Flink;
							}

							PLIST_ENTRY pListEntry3 = pRuleEntry->Dirs.Flink;
							while (pListEntry3 != &pRuleEntry->Dirs)
							{
								PPathEntry pae = CONTAINING_RECORD(pListEntry3, PathEntry, entry);

								PLIST_ENTRY pListEntry4 = newRuleEntry->Dirs.Flink;
								while (pListEntry4 != &newRuleEntry->Dirs)
								{
									PPathEntry pae2 = CONTAINING_RECORD(pListEntry4, PathEntry, entry);
									if (RtlEqualUnicodeString(&pae->Path, &pae2->Path, FALSE))
									{
										pae2->stat = pae->stat;
										break;
									}
									pListEntry4 = pListEntry4->Flink;
								}
								pListEntry3 = pListEntry3->Flink;
							}
							RemoveEntryList(pListEntry);
							ArvFreeRule(pRuleEntry);
							break;
						}
						pListEntry = pListEntry->Flink;
					}

					DbgPrint("[FsFilter:MiniMessage]add rule %d: %d - %ws - %d\n", i + 1, pOpSetRules->rules[i]->id, pOpSetRules->rules[i]->pubKey, pOpSetRules->rules[i]->pathsLen);
				}
				ArvFreeRules(&filterConfig);
				tmpConfig.RegProcs = filterConfig.RegProcs;
				filterConfig = tmpConfig;
				if (pOpSetRules->ruleLen > 0)
				{
					tmpConfig.Rules.Blink->Flink = &filterConfig.Rules;
					tmpConfig.Rules.Flink->Blink = &filterConfig.Rules;
				}
				else
				{
					filterConfig.Rules.Flink = &filterConfig.Rules;
					filterConfig.Rules.Blink = &filterConfig.Rules;
				}
				ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			case SET_DB_CONF:
				pOpSetDBConf = (OpSetDBConf*)InputBuffer;
				ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
				BOOL ret2 = ArvSetDBConf(&filterConfig, pOpSetDBConf->id, pOpSetDBConf->path);
				ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
				DbgPrint("[FsFilter:MiniMessage]set DB conf %d: %d - %ws\n", ret2, pOpSetDBConf->id, pOpSetDBConf->path);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			case SET_ALLOW_UNLOAD:
				pOpSetAllowUnload = (OpSetAllowUnload*)InputBuffer;
				ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
				AllowUnload = pOpSetAllowUnload->allow;
				ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
				DbgPrint("[FsFilter:MiniMessage]set allow unload: %d\n", pOpSetAllowUnload->allow);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			case GET_STAT:
				ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
				PRepStat pStats = (PRepStat)OutputBuffer;
				PRuleEntry pRuleEntry = NULL;
				PPathEntry pPathEntry = NULL;
				PLIST_ENTRY pListEntry = filterConfig.Rules.Flink;
				UINT i = 0;
				ULONGLONG keyCount = 0;
				ULONGLONG passTotal = 0;
				ULONGLONG blockTotal = 0;
				ULONGLONG passTotalDB = 0;
				ULONGLONG blockTotalDB = 0;
				while (pListEntry != &filterConfig.Rules)
				{
					keyCount++;
					pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
					PLIST_ENTRY pListEntry2 = pRuleEntry->Dirs.Flink;
					while (pListEntry2 != &pRuleEntry->Dirs)
					{
						pPathEntry = CONTAINING_RECORD(pListEntry2, PathEntry, entry);
						//Sha256UnicodeString(&pPathEntry->Path, pStats[i].SHA256);
						passTotal += pPathEntry->stat.passCounter;
						blockTotal += pPathEntry->stat.blockCounter;
						passTotalDB += pPathEntry->stat.passCounterDB;
						blockTotalDB += pPathEntry->stat.blockCounterDB;
						i++;
						pListEntry2 = pListEntry2->Flink;
					}
					pListEntry = pListEntry->Flink;
				}
				pStats->KeyCount = keyCount;
				pStats->Block = blockTotal;
				pStats->Pass = passTotal;
				pStats->BlockDB = blockTotalDB;
				pStats->PassDB = passTotalDB;
				pStats->Read = filterConfig.readCount;
				pStats->Write = filterConfig.writeCount;
				pStats->ReadDB = filterConfig.readCountDB;
				pStats->WriteDB = filterConfig.writeCountDB;
				ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
				*ReturnOutputBufferLength = (ULONG)sizeof(RepStat);
				break;
			case SET_CONTROL_PROC:
				ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
				pOpSetControlProc = (OpSetControlProc*)InputBuffer;
				controlProcID = pOpSetControlProc->controlProcID;
				ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
				DbgPrint("[FsFilter:MiniMessage]set procID %d\n", pOpSetControlProc->controlProcID);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			}
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}
	else {
		status = STATUS_INVALID_PARAMETER;
	}
	return status;
}
