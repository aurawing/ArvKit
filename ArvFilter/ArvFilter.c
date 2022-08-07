/*++

Module Name:

    ArvFilter.c

Abstract:

    This is the main module of the ArvFilter miniFilter driver.

Environment:

    Kernel mode

--*/
#include "pch.h"

#define BUFFER_SWAP_TAG     'bdBS'
#define NAME_TAG            'mnBS'
#define PRE_2_POST_TAG      'ppBS'

NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);


FilterConfig filterConfig = { 0 };
ERESOURCE HashResource = { 0 };
ULONG controlProcID = 0;
PFLT_FILTER g_minifilterHandle = NULL;
PDEVICE_OBJECT gDeviceObject = NULL;
BOOL AllowUnload = FALSE;

// 获取全部父进程ID
VOID FindAncestorProcessID(ULONG processID, PLIST_ENTRY pProcHead)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	while (TRUE)
	{
		PLIST_ENTRY pListEntry = pProcHead->Flink;
		while (pListEntry != pProcHead)
		{
			PProcEntry pProcEntry = CONTAINING_RECORD(pListEntry, ProcEntry, entry);
			if (pProcEntry->ProcID == processID)
			{
				return;
			}
			pListEntry = pListEntry->Flink;
		}

		ArvAddProc(pProcHead, processID, FALSE);
		status = PsLookupProcessByProcessId((HANDLE)processID, &pProcess);
		if (!NT_SUCCESS(status))
		{
			return;
		}
		processID = (ULONG)PsGetProcessInheritedFromUniqueProcessId(pProcess);
		ObDereferenceObject(pProcess);
		pProcess = NULL;
	}
}

//判断是否为读写进程
BOOLEAN MatchReadWriteProcess(char *pStrProcessName)
{
	/*PEPROCESS pProcess;
	NTSTATUS ntStatus = PsLookupProcessByProcessId((HANDLE)ProcID, &pProcess);
	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}
	CHAR*  pStrProcessName = PsGetProcessImageFileName(pProcess);
	ObDereferenceObject(pProcess);*/
	return strcmp(pStrProcessName, "System") == 0; // strcmp(pStrProcessName, "smartscreen.exe") == 0 || strcmp(pStrProcessName, "smartscreen.ex") == 0;
}

//判断是否为只读进程
BOOLEAN MatchReadonlyProcess(char *pStrProcessName)
{
	/*PEPROCESS pProcess;
	NTSTATUS ntStatus = PsLookupProcessByProcessId((HANDLE)ProcID, &pProcess);
	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}
	CHAR*  pStrProcessName = PsGetProcessImageFileName(pProcess);
	ObDereferenceObject(pProcess);*/
	return 
		strcmp(pStrProcessName, "System") == 0 ||
		strcmp(pStrProcessName, "csrss.exe") == 0 ||
		strcmp(pStrProcessName, "lsass.exe") == 0 ||
		strcmp(pStrProcessName, "smss.exe") == 0 ||
		strcmp(pStrProcessName, "sc.exe") == 0 ||
		strcmp(pStrProcessName, "services.exe") == 0 ||
		strcmp(pStrProcessName, "MsMpEng.exe") == 0 ||
		strcmp(pStrProcessName, "dllhost.exe") == 0 || 
		strcmp(pStrProcessName, "svchost.exe") == 0 || 
		strcmp(pStrProcessName, "conhost.exe") == 0 || 
		//strcmp(pStrProcessName, "fodhelper.exe") == 0 || 
		//strcmp(pStrProcessName, "RuntimeBroker.exe") == 0 || 
		//strcmp(pStrProcessName, "SearchUI.exe") == 0 || 
		//strcmp(pStrProcessName, "ShellExperienceHost.exe") == 0 || 
		strcmp(pStrProcessName, "sihost.exe") == 0 || 
		strcmp(pStrProcessName, "smartscreen.ex") == 0 || 
		strcmp(pStrProcessName, "taskhostw.exe") == 0 || 
		strcmp(pStrProcessName, "Taskmgr.exe") == 0 ||
		//strcmp(pStrProcessName, "vm3dservice.exe") == 0 || 
		strcmp(pStrProcessName, "dwm.exe") == 0 || 
		strcmp(pStrProcessName, "fontdrvhost.ex") == 0 || 
		strcmp(pStrProcessName, "ChsIME.exe") == 0 || 
		strcmp(pStrProcessName, "ctfmon.exe") == 0 || 
		//strcmp(pStrProcessName, "WindowsInternal.ComposableShell.Experiences,TextInput.InputApp.exe") == 0 || 
		strcmp(pStrProcessName, "explorer.exe") == 0 || 
		strcmp(pStrProcessName, "cmd.exe") == 0 || 
		strcmp(pStrProcessName, "powershell.exe") == 0 || 
		//strcmp(pStrProcessName, "secretmanager.exe") == 0 ||
		strcmp(pStrProcessName, "secretmanager.") == 0;
}


FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	/*if (Data->Iopb->TargetFileObject->FileName.Length > 14 &&
		Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / 2 - 1] == L't' &&
		Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / 2 - 2] == L'x' &&
		Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / 2 - 3] == L't' &&
		Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / 2 - 4] == L'.' &&
		Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / 2 - 5] == L'3' &&
		Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / 2 - 6] == L'2' &&
		Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / 2 - 7] == L'1')
	{
		DbgPrint("hit");
	}*/
	PARV_STREAM_CONTEXT streamContext = NULL;
	NTSTATUS status;
	BOOLEAN streamContextCreated;

	if (!NT_SUCCESS(Data->IoStatus.Status)) {
		status = FLT_PREOP_SUCCESS_NO_CALLBACK;
		goto CtxPreReadCleanup;
	}

	if (FltObjects->FileObject == NULL) {
		status = FLT_PREOP_SUCCESS_NO_CALLBACK;
		goto CtxPreReadCleanup;
	}

	status = CtxFindOrCreateStreamContext(Data,
		FALSE,     // do not create if one does not exist
		&streamContext,
		&streamContextCreated);
	if (!NT_SUCCESS(status)) {

		//
		//  This failure will most likely be because stream contexts are not supported
		//  on the object we are trying to assign a context to or the object is being 
		//  deleted
		//  

		DbgPrint("[Ctx]: CtxPostRead -> Failed to find stream context (Cbd = %p, FileObject = %p)\n",
				Data,
				FltObjects->FileObject);

		goto CtxPreReadCleanup;
	}

	CtxAcquireResourceShared(streamContext->Resource);
	if (streamContext->UnderDBPath)
	{
		InterlockedIncrement64(&filterConfig.readCountDB);
	}
	CtxReleaseResource(streamContext->Resource);

	ExAcquireResourceSharedLite(&HashResource, TRUE);
	InterlockedIncrement64(&filterConfig.readCount);
	ExReleaseResourceLite(&HashResource);

CtxPreReadCleanup:
	if (streamContext != NULL) {
		FltReleaseContext(streamContext);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	PARV_STREAM_CONTEXT streamContext = NULL;
	NTSTATUS status;
	BOOLEAN streamContextCreated;

	if (!NT_SUCCESS(Data->IoStatus.Status)) {
		status = FLT_PREOP_SUCCESS_NO_CALLBACK;
		goto CtxPreWriteCleanup;
	}

	if (FltObjects->FileObject == NULL) {
		status = FLT_PREOP_SUCCESS_NO_CALLBACK;
		goto CtxPreWriteCleanup;
	}

	status = CtxFindOrCreateStreamContext(Data,
		FALSE,     // do not create if one does not exist
		&streamContext,
		&streamContextCreated);
	if (!NT_SUCCESS(status)) {

		//
		//  This failure will most likely be because stream contexts are not supported
		//  on the object we are trying to assign a context to or the object is being 
		//  deleted
		//  

		DbgPrint("[Ctx]: CtxPreWrite -> Failed to find stream context (Cbd = %p, FileObject = %p)\n",
			Data,
			FltObjects->FileObject);

		goto CtxPreWriteCleanup;
	}

	CtxAcquireResourceShared(streamContext->Resource);
	if (streamContext->UnderDBPath)
	{
		InterlockedIncrement64(&filterConfig.writeCountDB);
	}
	CtxReleaseResource(streamContext->Resource);

	ExAcquireResourceSharedLite(&HashResource, TRUE);
	InterlockedIncrement64(&filterConfig.writeCount);
	ExReleaseResourceLite(&HashResource);

CtxPreWriteCleanup:
	if (streamContext != NULL) {
		FltReleaseContext(streamContext);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	//
	// Pre-create callback to get file info during creation or opening
	//
	NTSTATUS status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	NTSTATUS status2 = STATUS_SUCCESS;
	PCreateContext cbdContext = (PCreateContext)ExAllocatePoolWithTag(PagedPool, sizeof(CreateContext), 'POC');
	if (controlProcID == 0) {
		*CompletionContext = cbdContext;
		return status;
	}
	if (FltObjects->FileObject == NULL) {
		*CompletionContext = cbdContext;
		return status;
	}
	
	UNICODE_STRING fullPath = { 0 };
	UNICODE_STRING dosName = { 0 };
	PARV_VOLUME_CONTEXT volCtx = NULL;
	//BOOL underDBPath = FALSE;
	LIST_ENTRY ruleEntry2Head = { 0 };
	InitializeListHead(&ruleEntry2Head);

	//UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	if (Data->Iopb->TargetFileObject->FileName.Length == 0)
	{
		*CompletionContext = cbdContext;
		return status;
	}

	ULONG procID = FltGetRequestorProcessId(Data);
	if (procID == controlProcID) // || ProcAllowed(procID))
	{
		*CompletionContext = cbdContext;
		return status;
	}
	//check processname
	PEPROCESS pCallerProcess = NULL;
	char *callerProcessName = "";

	WCHAR SystemRoot[] = { 'C', ':', '\\' };
	WCHAR LoginPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'i', 'n', '?', '\\' };
	WCHAR LogoutPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'o', 't', '?', '\\' };
	WCHAR ReginPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'R', 'e', 'g', 'i', 'n', '?', '\\' };
	WCHAR RegoutPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'R', 'e', 'g', 'o', 't', '?', '\\' };

	if ((Data->Iopb->TargetFileObject->FileName.Length > 15 * sizeof(wchar_t)) &&
		(memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LoginPath, 15 * sizeof(wchar_t)) == 0 || memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LogoutPath, 15 * sizeof(wchar_t)) == 0) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / sizeof(wchar_t) - 1] == L'\\' &&
		ArvCalculateCharCountWithinUnicodeString(&Data->Iopb->TargetFileObject->FileName, L'\\')==6)
		)
	{
		PSTR logintag = (PSTR)ExAllocatePoolWithTag(PagedPool, Data->Iopb->TargetFileObject->FileName.Length, 'LGI');
		RtlZeroMemory(logintag, Data->Iopb->TargetFileObject->FileName.Length);
		int b = 0;
		PSTR keyidstr = NULL;
		PSTR timestr = NULL;
		PSTR sigstr = NULL;
		PSTR inheritStr = NULL;
		bool isWChar = false;
		int bPoint[4];
		for (UINT a = 0; a < Data->Iopb->TargetFileObject->FileName.Length / sizeof(wchar_t); a++)
		{
			if (Data->Iopb->TargetFileObject->FileName.Buffer[a] != L'\\')
			{
				if (Data->Iopb->TargetFileObject->FileName.Buffer[a] < 256)
				{
					logintag[a] = Data->Iopb->TargetFileObject->FileName.Buffer[a];
				}
				else
				{
					isWChar = true; //路径不应包含多字节字符
					break;
				}
			}
			else
			{
				logintag[a] = '\0';
				if (b == 0)
				{
					bPoint[0] = a;
				}
				else if (b == 1)
				{
					bPoint[1] = a;
					keyidstr = &logintag[a + 1];
				}
				else if (b == 2)
				{
					bPoint[2] = a;
					timestr = &logintag[a + 1];
				}
				else if (b == 3)
				{
					bPoint[3] = a;
					inheritStr = &logintag[a + 1];
				}
				else if (b == 4)
				{
					sigstr = &logintag[a + 1];
				}
				
				b++;
			}
		}
		if (isWChar || keyidstr == NULL || timestr == NULL || inheritStr == NULL || sigstr == NULL )
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}
		int keyid = atoi(keyidstr);
		if (keyid == 0)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}

		LONG timeBaseLine = (LONG)ArvGetUnixTimestamp();
		LONG timeparam = atol(timestr);
		if (timeBaseLine == 0 || timeparam == 0 || (timeBaseLine - timeparam) > 10 || (timeBaseLine - timeparam) < -10)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}
		int inherit = atoi(inheritStr);
		if (inherit > 0)
		{
			inherit = 1;
		}
		else
		{
			inherit = 0;
		}
		ExAcquireResourceSharedLite(&HashResource, TRUE);
		PUNICODE_STRING wPubKey = ArvGetPubKeyByRuleID(&filterConfig, keyid);
		if (wPubKey == NULL)
		{
			ExReleaseResourceLite(&HashResource);
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}
		PSTR pubKey = (PSTR)ExAllocatePoolWithTag(PagedPool, wPubKey->Length / sizeof(wchar_t) + 1, 'LGI');
		RtlZeroMemory(pubKey, wPubKey->Length / sizeof(wchar_t) + 1);
		for (UINT c = 0; c < wPubKey->Length / sizeof(wchar_t); c++)
		{
			if (wPubKey->Buffer[c] < 256)
			{
				pubKey[c] = wPubKey->Buffer[c];
			}
			else
			{
				isWChar = true; //路径不应包含多字节字符
				break;
			}
		}
		if (isWChar)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(pubKey, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			ExReleaseResourceLite(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		for (UINT d = 0; d < 4; d++)
		{
			logintag[bPoint[d]] = '\\';
		}
		bool verified = ArvVerifySig(logintag, sigstr, pubKey);
		if (!verified)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(pubKey, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			ExReleaseResourceLite(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		ExReleaseResourceLite(&HashResource);

		ExAcquireResourceExclusiveLite(&HashResource, TRUE);
		if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LoginPath, 15 * sizeof(wchar_t)) == 0)
		{
			ArvMapRule(&filterConfig, procID, inherit, keyid);
		}
		else if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LogoutPath, 15 * sizeof(wchar_t)) == 0)
		{
			ArvRemoveProc(&filterConfig, procID, keyid);
		}
		ExReleaseResourceLite(&HashResource);
		ExFreePoolWithTag(logintag, 'LGI');
		ExFreePoolWithTag(pubKey, 'LGI');
		ExFreePoolWithTag(cbdContext, 'POC');
		return FLT_PREOP_COMPLETE;
	}
	else if ((Data->Iopb->TargetFileObject->FileName.Length > 15 * sizeof(wchar_t)) &&
		(memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, ReginPath, 15 * sizeof(wchar_t)) == 0 || memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, RegoutPath, 15 * sizeof(wchar_t)) == 0) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / sizeof(wchar_t) - 1] == L'\\' &&
		ArvCalculateCharCountWithinUnicodeString(&Data->Iopb->TargetFileObject->FileName, L'\\') == 7)
		)
	{
		PSTR logintag = (PSTR)ExAllocatePoolWithTag(PagedPool, Data->Iopb->TargetFileObject->FileName.Length, 'LGI');
		RtlZeroMemory(logintag, Data->Iopb->TargetFileObject->FileName.Length);
		int b = 0;
		PSTR keyidstr = NULL;
		PSTR procstr = NULL;
		PSTR timestr = NULL;
		PSTR sigstr = NULL;
		PSTR inheritstr = NULL;
		bool isWChar = false;
		int bPoint[5];
		for (UINT a = 0; a < Data->Iopb->TargetFileObject->FileName.Length / sizeof(wchar_t); a++)
		{
			if (Data->Iopb->TargetFileObject->FileName.Buffer[a] != L'\\')
			{
				if (Data->Iopb->TargetFileObject->FileName.Buffer[a] < 256)
				{
					logintag[a] = Data->Iopb->TargetFileObject->FileName.Buffer[a];
				}
				else
				{
					isWChar = true; //路径不应包含多字节字符
					break;
				}
			}
			else
			{
				logintag[a] = '\0';
				if (b == 0)
				{
					bPoint[0] = a;
				}
				else if (b == 1)
				{
					bPoint[1] = a;
					keyidstr = &logintag[a + 1];
				}
				else if (b == 2)
				{
					bPoint[2] = a;
					procstr = &logintag[a + 1];
				}
				else if (b == 3)
				{
					bPoint[3] = a;
					timestr = &logintag[a + 1];
				}
				else if (b == 4)
				{
					bPoint[4] = a;
					inheritstr = &logintag[a + 1];
				}
				else if (b == 5)
				{
					sigstr = &logintag[a + 1];
				}
				b++;
			}
		}
		if (isWChar || keyidstr == NULL || procstr == NULL || timestr == NULL || inheritstr == NULL || sigstr == NULL)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}
		int keyid = atoi(keyidstr);
		if (keyid == 0)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}
		LONG timeBaseLine = (LONG)ArvGetUnixTimestamp();
		LONG timeparam = atol(timestr);
		if (timeBaseLine == 0 || timeparam == 0 || (timeBaseLine - timeparam) > 10 || (timeBaseLine - timeparam) < -10)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}
		int inherit = atoi(inheritstr);
		if (inherit > 0)
		{
			inherit = 1;
		}
		else
		{
			inherit = 0;
		}
		ExAcquireResourceSharedLite(&HashResource, TRUE);
		PUNICODE_STRING wPubKey = ArvGetPubKeyByRuleID(&filterConfig, keyid);
		if (wPubKey == NULL)
		{
			ExReleaseResourceLite(&HashResource);
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			return FLT_PREOP_COMPLETE;
		}
		PSTR pubKey = (PSTR)ExAllocatePoolWithTag(PagedPool, wPubKey->Length / sizeof(wchar_t) + 1, 'LGI');
		RtlZeroMemory(pubKey, wPubKey->Length / sizeof(wchar_t) + 1);
		for (UINT c = 0; c < wPubKey->Length / sizeof(wchar_t); c++)
		{
			if (wPubKey->Buffer[c] < 256)
			{
				pubKey[c] = wPubKey->Buffer[c];
			}
			else
			{
				isWChar = true; //路径不应包含多字节字符
				break;
			}
		}
		if (isWChar)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(pubKey, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			ExReleaseResourceLite(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		for (UINT d = 0; d < 5; d++)
		{
			logintag[bPoint[d]] = '\\';
		}
		bool verified = ArvVerifySig(logintag, sigstr, pubKey);
		if (!verified)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(pubKey, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			ExReleaseResourceLite(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		for (UINT d = 0; d < 5; d++)
		{
			logintag[bPoint[d]] = '\0';
		}
		ExReleaseResourceLite(&HashResource);

		ExAcquireResourceExclusiveLite(&HashResource, TRUE);
		if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, ReginPath, 15 * sizeof(wchar_t)) == 0)
		{
			ArvAddRegProc(&filterConfig, procstr, inherit, keyid);
		}
		else if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, RegoutPath, 15 * sizeof(wchar_t)) == 0)
		{
			if (ArvGetRuleIDByRegProcName(&filterConfig, procstr) != keyid)
			{
				Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
				Data->IoStatus.Information = 0;
			}
			else
			{
				ArvFreeRegProc(&filterConfig, procstr);
			}
		}
		ExReleaseResourceLite(&HashResource);
		ExFreePoolWithTag(logintag, 'LGI');
		ExFreePoolWithTag(pubKey, 'LGI');
		ExFreePoolWithTag(cbdContext, 'POC');
		return FLT_PREOP_COMPLETE;
	}

	try
	{
		ExAcquireResourceSharedLite(&HashResource, TRUE);
		if (filterConfig.Rules.Flink == &filterConfig.Rules)
		{
			if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION && status != FLT_PREOP_COMPLETE)
			{
				status = FLT_PREOP_SYNCHRONIZE;
			}
			leave;
		}

		status = FltGetVolumeContext(FltObjects->Filter,
			FltObjects->Volume,
			&volCtx);

		if (!NT_SUCCESS(status)) {
			DbgPrint("[FsFilter:create]Error getting volume context, status=%x\n", status);
			leave;
		}

		status2 = PsLookupProcessByProcessId((HANDLE)procID, &pCallerProcess);
		if (status2 == STATUS_SUCCESS)
		{
			callerProcessName = PsGetProcessImageFileName(pCallerProcess);
		}

		UNICODE_STRING netVolName;
		RtlInitUnicodeString(&netVolName, L"\\Device\\Mup");
		dosName.Buffer = ExAllocatePoolWithTag(PagedPool, volCtx->VolumeName.Length, 'SOD');
		if (!dosName.Buffer)
		{
			//ExReleaseResourceLite(&HashResource);
			//ObDereferenceObject(pCallerProcess);
			//return STATUS_INSUFFICIENT_RESOURCES;
			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}
		dosName.Length = dosName.MaximumLength = volCtx->VolumeName.Length;
		RtlCopyUnicodeString(&dosName, &volCtx->VolumeName);
		//size_t fullLen = 0;
		if (dosName.Length && RtlCompareUnicodeString(&dosName, &netVolName, TRUE) == 0)
		{
			dosName.Length = dosName.MaximumLength = 2;
		}


		PFLT_FILE_NAME_INFORMATION nameInfo;
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
		if (!NT_SUCCESS(status))
		{
			leave;
		}
		status = FltParseFileNameInformation(nameInfo);
		if (!NT_SUCCESS(status))
		{
			if (nameInfo!=NULL)
			{
				FltReleaseFileNameInformation(nameInfo);
			}
			leave;
		}

		size_t fullLen = dosName.Length + nameInfo->Name.Length - nameInfo->Volume.Length;
		fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, fullLen, 'POC');
		fullPath.Length = fullPath.MaximumLength = (USHORT)fullLen;
		UINT i = 0, j = 0, k = nameInfo->Volume.Length / sizeof(wchar_t);
		for (i = 0; i < fullLen / sizeof(wchar_t); i++)
		{
			if (i < dosName.Length / sizeof(wchar_t))
			{
				fullPath.Buffer[i] = dosName.Buffer[j];
				j++;
			}
			else
			{
				fullPath.Buffer[i] = nameInfo->Name.Buffer[k];
				k++;
			}
		}
		/*}
		else
		{
			size_t fullLen = dosName.Length + Data->Iopb->TargetFileObject->FileName.Length;
			fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, fullLen, 'POC');
			fullPath.Length = 0;
			fullPath.MaximumLength = (USHORT)fullLen;
			RtlAppendUnicodeStringToString(&fullPath, &dosName);
			RtlAppendUnicodeStringToString(&fullPath, &Data->Iopb->TargetFileObject->FileName);
		}*/
		
		BOOL flag = FALSE;
		PRuleEntry pRuleEntry = { 0 };
		PPathEntry pPathEntry = { 0 };
		PLIST_ENTRY pListEntry = filterConfig.Rules.Flink;
		while (pListEntry != &filterConfig.Rules)
		{
			pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
			PLIST_ENTRY pListEntry2 = pRuleEntry->Dirs.Flink;
			while (pListEntry2 != &pRuleEntry->Dirs)
			{
				pPathEntry = CONTAINING_RECORD(pListEntry2, PathEntry, entry);
				if (pPathEntry->Path.Length <= fullPath.Length)
				{
					USHORT fpLen = fullPath.Length;
					fullPath.Length = pPathEntry->Path.Length;
					if (RtlCompareUnicodeString(&fullPath, &pPathEntry->Path, TRUE) == 0)
					{
						fullPath.Length = fpLen;
						flag = TRUE;
						ArvAddRuleEntry2(&ruleEntry2Head, pRuleEntry, pPathEntry->isDB);
						break;
						/*if (pPathEntry->isDB)
						{
							underDBPath = TRUE;
						}
						goto out1;*/
					}
					fullPath.Length = fpLen;
				}
				pListEntry2 = pListEntry2->Flink;
			}
			pListEntry = pListEntry->Flink;
		}
		if (flag) 
		{
			BOOL flag2 = FALSE;
			LIST_ENTRY procHead = { 0 };
			InitializeListHead(&procHead);
			FindAncestorProcessID(procID, &procHead);
			PLIST_ENTRY pListEntry1 = procHead.Flink;
			while (pListEntry1 != &procHead)
			{
				PProcEntry pProcEntry1 = CONTAINING_RECORD(pListEntry1, ProcEntry, entry);
				PLIST_ENTRY pRule2 = ruleEntry2Head.Flink;
				while (pRule2 != &ruleEntry2Head)
				{
					PRuleEntry2 pRuleEntry2 = CONTAINING_RECORD(pRule2, RuleEntry2, entry);
					PLIST_ENTRY pListEntry2 = pRuleEntry2->pRuleEntry->Procs.Flink;
					while (pListEntry2 != &pRuleEntry2->pRuleEntry->Procs)
					{
						PProcEntry pProcEntry2 = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
						if (pProcEntry1->ProcID == pProcEntry2->ProcID)
						{
							flag2 = TRUE;
							if (pRuleEntry2->underDBPath)
							{
								cbdContext->UnderDBPath = TRUE;
							}
							goto out2;
						}
						pListEntry2 = pListEntry2->Flink;
					}
					pRule2 = pRule2->Flink;
				}
				pListEntry1 = pListEntry1->Flink;
			}
		out2:
			if (!flag2)
			{

				if (Data && Data->Iopb && (Data->Iopb->MajorFunction == IRP_MJ_CREATE))
				{
					ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
					if (fullPath.Length >= 3 * sizeof(wchar_t) && memcmp(fullPath.Buffer, SystemRoot, 3 * sizeof(wchar_t)) == 0)
					{
						//if (ProcAllowed(procID) || (MatchReadonlyProcess(procID) && FILE_OPEN == createDisposition))
						if (ProcAllowed(procID) || FILE_OPEN == createDisposition)
						{
							DbgPrint("[FsFilter:create]allowed system process under system device: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							InterlockedIncrement64(&pPathEntry->stat.passCounter);
							if (cbdContext->UnderDBPath)
							{
								InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
							}
						}
						else
						{
							DbgPrint("[FsFilter:create]unallowed process under system device: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							if (cbdContext->UnderDBPath)
							{
								InterlockedIncrement64(&pPathEntry->stat.blockCounterDB);
							}
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
						}
					}
					else
					{
						if (MatchReadWriteProcess(callerProcessName) || (MatchReadonlyProcess(callerProcessName) && FILE_OPEN == createDisposition))
						{
							DbgPrint("[FsFilter:create]allowed system process(readonly): %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							InterlockedIncrement64(&pPathEntry->stat.passCounter);
							if (cbdContext->UnderDBPath)
							{
								InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
							}
						}
						else
						{
							DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							if (cbdContext->UnderDBPath)
							{
								InterlockedIncrement64(&pPathEntry->stat.blockCounterDB);
							}
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
						}
					}
				}
				else if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
				{
					if (fullPath.Length >= 3 * sizeof(wchar_t) && memcmp(fullPath.Buffer, SystemRoot, 3 * sizeof(wchar_t)) == 0)
					{
						if (ProcAllowed(procID))
						{
							InterlockedIncrement64(&pPathEntry->stat.passCounter);
							if (cbdContext->UnderDBPath)
							{
								InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
							}
						}
						else
						{
							InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							if (cbdContext->UnderDBPath)
							{
								InterlockedIncrement64(&pPathEntry->stat.blockCounterDB);
							}
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
						}
					}
					else
					{
						if (MatchReadWriteProcess(callerProcessName))
						{
							InterlockedIncrement64(&pPathEntry->stat.passCounter);
							if (cbdContext->UnderDBPath)
							{
								InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
							}
						}
						else
						{
							switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
							case FileDispositionInformation:
							case 64:
								// deleting a file we need to action
								if (((FILE_DISPOSITION_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile) {
									InterlockedIncrement64(&pPathEntry->stat.blockCounter);
									if (cbdContext->UnderDBPath)
									{
										InterlockedIncrement64(&pPathEntry->stat.blockCounterDB);
									}
									Data->IoStatus.Status = STATUS_ACCESS_DENIED;
									Data->IoStatus.Information = 0;
									status = FLT_PREOP_COMPLETE;
								}
								break;
							case FileRenameInformation:
							case 65:
								// Process the request according to our needs e.g copy the file
								InterlockedIncrement64(&pPathEntry->stat.blockCounter);
								if (cbdContext->UnderDBPath)
								{
									InterlockedIncrement64(&pPathEntry->stat.blockCounterDB);
								}
								Data->IoStatus.Status = STATUS_ACCESS_DENIED;
								Data->IoStatus.Information = 0;
								status = FLT_PREOP_COMPLETE;
								break;
							}
						}
					}
				}
			}
			else
			{
				InterlockedIncrement64(&pPathEntry->stat.passCounter);
				if (cbdContext->UnderDBPath)
				{
					InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
				}
				//DbgPrint("[FsFilter:create]unauthorized process: %d - %wZ\n", procID, fullPath);
			}
			ArvFreeProcs(&procHead);
		}
		else
		{
			//DbgPrint("[FsFilter:create]unfiltered path: %d - %wZ\n", procID, fullPath);
			//TODO: 未命中目录，可读
			BOOL flag3 = FALSE;
			PRuleEntry pRuleEntry3 = { 0 };
			PLIST_ENTRY pListEntry3 = filterConfig.Rules.Flink;
			while (pListEntry3 != &filterConfig.Rules)
			{
				pRuleEntry3 = CONTAINING_RECORD(pListEntry3, RuleEntry, entry);
				PLIST_ENTRY pListEntry4 = pRuleEntry3->Procs.Flink;
				while (pListEntry4 != &pRuleEntry3->Procs)
				{
					PProcEntry pProcEntry4 = CONTAINING_RECORD(pListEntry4, ProcEntry, entry);
					if (pProcEntry4->ProcID == procID && ArvGetRuleIDByRegProcName(&filterConfig, callerProcessName)==0)
					{

						flag3 = TRUE;
						goto out3;
					}
					pListEntry4 = pListEntry4->Flink;
				}
				pListEntry3 = pListEntry3->Flink;
			}
		out3:
			if (!flag3)
			{
				if (Data && Data->Iopb && (Data->Iopb->MajorFunction == IRP_MJ_CREATE))
				{
					ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
					if (fullPath.Length >= 3 * sizeof(wchar_t) && memcmp(fullPath.Buffer, SystemRoot, 3 * sizeof(wchar_t)) == 0)
					{
						//if (ProcAllowed(procID) || (MatchReadonlyProcess(procID) && FILE_OPEN == createDisposition))
						if (ProcAllowed(procID) || FILE_OPEN == createDisposition)
						{
							DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							//InterlockedIncrement64(&pPathEntry->stat.passCounter);
						}
						else
						{
							DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
						}
					}
					else
					{
						if (MatchReadWriteProcess(callerProcessName) || (MatchReadonlyProcess(callerProcessName) && FILE_OPEN == createDisposition))
						{
							DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							//InterlockedIncrement64(&pPathEntry->stat.passCounter);
						}
						else
						{
							DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
						}
					}
				}
				else if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
				{
					ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
					if (fullPath.Length >= 3 * sizeof(wchar_t) && memcmp(fullPath.Buffer, SystemRoot, 3 * sizeof(wchar_t)) == 0)
					{
						if (ProcAllowed(procID))
						{
							DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							//InterlockedIncrement64(&pPathEntry->stat.passCounter);
						}
						else
						{
							DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
							//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
						}
					}
					else 
					{
						if (MatchReadWriteProcess(callerProcessName))
						{
							DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
						}
						else
						{
							switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
							case FileDispositionInformation:
							case 64:
								// deleting a file we need to action
								if (((FILE_DISPOSITION_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile) {
									//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
									Data->IoStatus.Status = STATUS_ACCESS_DENIED;
									Data->IoStatus.Information = 0;
									status = FLT_PREOP_COMPLETE;
								}
								break;
							case FileRenameInformation:
							case 65:
								// Process the request according to our needs e.g copy the file
								//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
								Data->IoStatus.Status = STATUS_ACCESS_DENIED;
								Data->IoStatus.Information = 0;
								status = FLT_PREOP_COMPLETE;
								break;
							}
						}
					}
				}
			}
			else
			{
				ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
				if (MatchReadWriteProcess(callerProcessName) || FILE_OPEN == createDisposition)
				{
					DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					//InterlockedIncrement64(&pPathEntry->stat.passCounter);
				}
				else
				{
					DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					Data->IoStatus.Information = 0;
					status = FLT_PREOP_COMPLETE;
				}
			}
		}
	}
	finally
	{
		ExReleaseResourceLite(&HashResource);
		ArvFreeRuleEntry2(&ruleEntry2Head);
		if (dosName.Buffer)
		{
			ArvFreeUnicodeString(&dosName, 'SOD');
		}
		if (fullPath.Buffer)
		{
			ArvFreeUnicodeString(&fullPath, 'POC');
		}
		if (pCallerProcess != NULL)
		{
			ObDereferenceObject(pCallerProcess);
		}
		if (volCtx != NULL) {

			FltReleaseContext(volCtx);
		}
		/*if (status != FLT_PREOP_COMPLETE)
		{
			status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}*/
		if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
		{
			if (status != FLT_PREOP_COMPLETE)
			{
				status = FLT_PREOP_SYNCHRONIZE;
				//PCreateContext cbdContext = (PCreateContext)ExAllocatePoolWithTag(PagedPool, sizeof(CreateContext), 'POC');
				//cbdContext->UnderDBPath = underDBPath;
				*CompletionContext = cbdContext;
			}
		}
		else
		{
			if (status != FLT_PREOP_COMPLETE)
			{
				status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
				//PCreateContext cbdContext = (PCreateContext)ExAllocatePoolWithTag(PagedPool, sizeof(CreateContext), 'POC');
				//cbdContext->UnderDBPath = underDBPath;
				*CompletionContext = cbdContext;
			}
		}
		
	}
	if (status == FLT_PREOP_COMPLETE)
	{
		ExFreePoolWithTag(cbdContext, 'POC');
	}
	if (status == FLT_PREOP_SUCCESS_WITH_CALLBACK && !FLT_IS_IRP_OPERATION(Data))
	{
		ExFreePoolWithTag(cbdContext, 'POC');
		status = FLT_PREOP_DISALLOW_FASTIO;
	}
	return status;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostOperationCreate(
	_Inout_ PFLT_CALLBACK_DATA Cbd,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Inout_opt_ PVOID CbdContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CbdContext);

	FLT_POSTOP_CALLBACK_STATUS opStatus = FLT_POSTOP_FINISHED_PROCESSING;
	

	PCreateContext createContext = CbdContext;
	PARV_STREAM_CONTEXT streamContext = NULL;
	//PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	//UNICODE_STRING fullPath = { 0 };
	//UNICODE_STRING dosName = { 0 };
	//size_t fullLen = 0;

	NTSTATUS status;
	BOOLEAN streamContextCreated;
	WCHAR FileName[ARV_MAX_NAME_LENGTH] = { 0 };

	if (STATUS_SUCCESS != Cbd->IoStatus.Status)
	{
		opStatus = FLT_POSTOP_FINISHED_PROCESSING;
		goto CtxPostCreateCleanup;
	}


	/*if (Cbd->Iopb->TargetFileObject->FileName.Length > 14 &&
		Cbd->Iopb->TargetFileObject->FileName.Buffer[Cbd->Iopb->TargetFileObject->FileName.Length / 2 - 1] == L't' &&
		Cbd->Iopb->TargetFileObject->FileName.Buffer[Cbd->Iopb->TargetFileObject->FileName.Length / 2 - 2] == L'x' &&
		Cbd->Iopb->TargetFileObject->FileName.Buffer[Cbd->Iopb->TargetFileObject->FileName.Length / 2 - 3] == L't' &&
		Cbd->Iopb->TargetFileObject->FileName.Buffer[Cbd->Iopb->TargetFileObject->FileName.Length / 2 - 4] == L'.' &&
		Cbd->Iopb->TargetFileObject->FileName.Buffer[Cbd->Iopb->TargetFileObject->FileName.Length / 2 - 5] == L'6' &&
		Cbd->Iopb->TargetFileObject->FileName.Buffer[Cbd->Iopb->TargetFileObject->FileName.Length / 2 - 6] == L'5' &&
		Cbd->Iopb->TargetFileObject->FileName.Buffer[Cbd->Iopb->TargetFileObject->FileName.Length / 2 - 7] == L'4')
	{
		LONGLONG FileSize = ArvQueryEndOfFileInfo(FltObjects->Instance, FltObjects->FileObject);
	}*/

	//PAGED_CODE();

	DbgPrint("[Ctx]: CtxPostCreate -> Enter (Cbd = %p, FileObject = %p)\n",
		Cbd,
		FltObjects->FileObject);

	//
	// Initialize defaults
	//

	status = STATUS_SUCCESS;

	//
	//  If the Create has failed, do nothing
	//

	//if (!NT_SUCCESS(Cbd->IoStatus.Status)) {
	//	goto CtxPostCreateCleanup;
	//}

	//
	// Find or create a stream context
	//

	status = CtxFindOrCreateStreamContext(Cbd,
		TRUE,
		&streamContext,
		&streamContextCreated);
	if (!NT_SUCCESS(status)) {

		//
		//  This failure will most likely be because stream contexts are not supported
		//  on the object we are trying to assign a context to or the object is being 
		//  deleted
		//  

		DbgPrint("[Ctx]: CtxPostCreate -> Failed to find or create stream context (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);
		opStatus = FLT_POSTOP_FINISHED_PROCESSING;
		goto CtxPostCreateCleanup;
	}

	/*DbgPrint("[Ctx]: CtxPostCreate -> Getting/Creating stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p. StreamContextCreated = %x)\n",
		&nameInfo->Name,
		Cbd,
		FltObjects->FileObject,
		streamContext,
		streamContextCreated);*/

	//
	//  Acquire write acccess to the context
	//

	CtxAcquireResourceExclusive(streamContext->Resource);

	//
	//  Increment the create count
	//

	streamContext->UnderDBPath = createContext->UnderDBPath;


	/*DbgPrint("[Ctx]: CtxPostCreate -> Stream context info for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p)\n",
		&nameInfo->Name,
		Cbd,
		FltObjects->FileObject,
		streamContext);*/

	//
	//  Relinquish write acccess to the context
	//

	CtxReleaseResource(streamContext->Resource);

	//
	//  Quit on failure after we have given up
	//  the resource
	//

	//if (!NT_SUCCESS(status)) {

	//	/*DbgPrint("[Ctx]: CtxPostCreate -> Failed to update name in stream context for file %wZ (Cbd = %p, FileObject = %p)\n",
	//		&nameInfo->Name,
	//		Cbd,
	//		FltObjects->FileObject);*/

	//	goto CtxPostCreateCleanup;
	//}

	if (streamContextCreated || 0 == wcslen(streamContext->FileName))
	{
		status = ArvGetFileNameOrExtension(Cbd, NULL, FileName);

		if (STATUS_SUCCESS != status)
		{
			ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->ArvGetFileNameOrExtension failed. Status = 0x%x.\n", __FUNCTION__, status));
			goto CtxPostCreateCleanup;
		}

		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->ContextCreated Fcb = %p FileName = %ws.\n", __FUNCTION__,
			FltObjects->FileObject->FsContext,
			FileName));


		ExEnterCriticalRegionAndAcquireResourceExclusive(streamContext->Resource);

		RtlZeroMemory(streamContext->FileName, ARV_MAX_NAME_LENGTH);

		if (wcslen(FileName) < ARV_MAX_NAME_LENGTH)
			RtlMoveMemory(streamContext->FileName, FileName, wcslen(FileName) * sizeof(WCHAR));

		ExReleaseResourceAndLeaveCriticalRegion(streamContext->Resource);

	}

	/*if (FlagOn(Cbd->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_READ_DATA))
	{
		status = ArvFlushOriginalCache(
			FltObjects->Instance,
			streamContext->FileName);

		if (STATUS_SUCCESS != status)
		{
			DbgPrint("flush file success");
		}
		else
		{
			DbgPrint("flush file failed");
		}
	}*/


CtxPostCreateCleanup:


	//
	// Release the references we have acquired
	//    

	/*if (nameInfo != NULL) {

		FltReleaseFileNameInformation(nameInfo);
	}*/

	if (streamContext != NULL) {

		FltReleaseContext(streamContext);
	}

	//ArvFreeUnicodeString(&dosName, 'SOD');
	//ArvFreeUnicodeString(&fullPath, 'POC');

	if (createContext)
	{
		ExFreePoolWithTag(createContext, 'POC');
	}

	DbgPrint("[Ctx]: CtxPostCreate -> Exit (Cbd = %p, FileObject = %p, Status = 0x%x)\n",
		Cbd,
		FltObjects->FileObject,
		Cbd->IoStatus.Status);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostOperationSetInfo(
	_Inout_ PFLT_CALLBACK_DATA Cbd,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Inout_opt_ PVOID CbdContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	PCreateContext createContext = CbdContext;
	PARV_STREAM_CONTEXT streamContext = NULL;
	//PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	//UNICODE_STRING fullPath = { 0 };
	//UNICODE_STRING dosName = { 0 };
	//size_t fullLen = 0;

	NTSTATUS status;
	BOOLEAN streamContextCreated;

	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CbdContext);

	//
	//  The pre-operation callback will return FLT_PREOP_SYNCHRONIZE if it needs a 
	//  post operation callback. In this case, the Filter Manager will call the 
	//  minifilter's post-operation callback in the context of the pre-operation 
	//  thread, at IRQL <= APC_LEVEL. This allows the post-operation code to be
	//  pagable and also allows it to access paged data
	//  

	PAGED_CODE();

	DbgPrint("[Ctx]: CtxPostSetInfo -> Enter (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);


	//
	// Initialize defaults
	//

	status = STATUS_SUCCESS;

	//
	//  If the SetInfo has failed, do nothing
	//

	if (!NT_SUCCESS(Cbd->IoStatus.Status)) {

		goto CtxPostSetInfoCleanup;
	}


	//
	//  Get the instance context for the target instance
	//

	DbgPrint("[Ctx]: CtxPostSetInfo -> Trying to get instance context (TargetInstance = %p, Cbd = %p, FileObject = %p)\n",
			Cbd->Iopb->TargetInstance,
			Cbd,
			FltObjects->FileObject);


	//
	// Get the directory name
	//

	/*status = FltGetFileNameInformation(Cbd,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo);

	if (!NT_SUCCESS(status)) {

		DbgPrint("[Ctx]: CtxPostSetInfo -> Failed to get file name information (Cbd = %p, FileObject = %p)\n",
				Cbd,
				FltObjects->FileObject);

		goto CtxPostSetInfoCleanup;
	}

	status = FltParseFileNameInformation(nameInfo);

	if (!NT_SUCCESS(status))
	{

		DbgPrint("[Ctx]: CtxPostCreate -> Failed to parse file name (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

		goto CtxPostSetInfoCleanup;
	}

	if (!(nameInfo->Volume).Buffer)
	{
		DbgPrint("[Ctx]: CtxPostCreate -> No volume parsed (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

		goto CtxPostSetInfoCleanup;
	}

	status = MyRtlVolumeDeviceToDosName(&(nameInfo->Volume), &dosName);

	if (!NT_SUCCESS(status))
	{

		DbgPrint("[Ctx]: CtxPostCreate -> Failed to parse volume name (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

		goto CtxPostSetInfoCleanup;
	}

	fullLen = dosName.Length + Cbd->Iopb->TargetFileObject->FileName.Length;
	fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, fullLen, 'POC');
	fullPath.Length = fullPath.MaximumLength = (USHORT)fullLen;
	UINT i = 0, j = 0, k = 0;
	for (i = 0; i < fullLen / sizeof(wchar_t); i++)
	{
		if (i < dosName.Length / sizeof(wchar_t))
		{
			fullPath.Buffer[i] = dosName.Buffer[j];
			j++;
		}
		else
		{
			fullPath.Buffer[i] = Cbd->Iopb->TargetFileObject->FileName.Buffer[k];
			k++;
		}
	}

	BOOL flag = FALSE;
	PRuleEntry pRuleEntry = { 0 };
	PPathEntry pPathEntry = { 0 };
	ExAcquireResourceSharedLite(&HashResource, TRUE);
	PLIST_ENTRY pListEntry = filterConfig.Rules.Flink;
	while (pListEntry != &filterConfig.Rules)
	{
		pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		PLIST_ENTRY pListEntry2 = pRuleEntry->Dirs.Flink;
		while (pListEntry2 != &pRuleEntry->Dirs)
		{
			pPathEntry = CONTAINING_RECORD(pListEntry2, PathEntry, entry);
			if (pPathEntry->Path.Length <= fullPath.Length)
			{
				USHORT fpLen = fullPath.Length;
				fullPath.Length = pPathEntry->Path.Length;
				if (RtlCompareUnicodeString(&fullPath, &pPathEntry->Path, TRUE) == 0 && pPathEntry->isDB)
				{
					fullPath.Length = fpLen;
					flag = TRUE;
					goto out1;
				}
				fullPath.Length = fpLen;
			}
			pListEntry2 = pListEntry2->Flink;
		}
		pListEntry = pListEntry->Flink;
	}
out1:
	ExReleaseResourceLite(&HashResource);*/


	//
	// Get the stream context
	//

	status = CtxFindOrCreateStreamContext(Cbd,
		FALSE,     // do not create if one does not exist
		&streamContext,
		&streamContextCreated);
	if (!NT_SUCCESS(status)) {

		//
		//  This failure will most likely be because stream contexts are not supported
		//  on the object we are trying to assign a context to or the object is being 
		//  deleted
		//  

		DbgPrint("[Ctx]: CtxPostSetInfo -> Failed to find stream context (Cbd = %p, FileObject = %p)\n",
				Cbd,
				FltObjects->FileObject);

		goto CtxPostSetInfoCleanup;
	}

	/*DbgPrint("[Ctx]: CtxPostSetInfo -> Getting stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p. StreamContextCreated = %x)\n",
			&nameInfo->Name,
			Cbd,
			FltObjects->FileObject,
			streamContext,
			streamContextCreated);*/

	//
	//  Acquire write acccess to the context
	//

	CtxAcquireResourceExclusive(streamContext->Resource);

	streamContext->UnderDBPath = createContext->UnderDBPath;

	/*DbgPrint("[Ctx]: CtxPostSetInfo -> Old info in stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p)\n",
			&nameInfo->Name,
			Cbd,
			FltObjects->FileObject,
			streamContext);*/


	//
	//  Relinquish write acccess to the context
	//

	CtxReleaseResource(streamContext->Resource);


CtxPostSetInfoCleanup:


	//
	// Release the references we have acquired
	//    


	if (streamContext != NULL) {

		FltReleaseContext(streamContext);
	}

	/*if (nameInfo != NULL) {

		FltReleaseFileNameInformation(nameInfo);
	}

	ArvFreeUnicodeString(&dosName, 'SOD');
	ArvFreeUnicodeString(&fullPath, 'POC');*/

	if (createContext)
	{
		ExFreePoolWithTag(createContext, 'POC');
	}

	DbgPrint("[Ctx]: CtxPostSetInfo -> Exit (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

// 监控进程创建回调函数
VOID CreateProcessNotify(IN HANDLE  ParentId, IN HANDLE  ChildId, IN BOOLEAN  Create)
{
	PEPROCESS ChildEprocess = NULL;
	NTSTATUS status;
	if (Create)
	{
		status = PsLookupProcessByProcessId(ChildId, &ChildEprocess);
		if (!NT_SUCCESS(status))
		{
			DbgPrint(("Get Eprocess Failed\n"));
			return;
		}
		PSTR cProcName = PsGetProcessImageFileName(ChildEprocess);
		ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
		PRegProcEntry entry = ArvGetRegProcEntryByRegProcName(&filterConfig, cProcName);
		if (entry != NULL)
		{
			ArvMapRule(&filterConfig, ChildId, entry->Inherit, entry->RuleID);
		}
		else
		{
			LIST_ENTRY procHead = { 0 };
			InitializeListHead(&procHead);
			FindAncestorProcessID(ChildId, &procHead);
			PLIST_ENTRY pListEntry1 = procHead.Flink;
			while (pListEntry1 != &procHead)
			{
				PProcEntry pProcEntry1 = CONTAINING_RECORD(pListEntry1, ProcEntry, entry);
				PLIST_ENTRY pListEntry2 = filterConfig.Rules.Flink;
				while (pListEntry2 != &filterConfig.Rules)
				{
					PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry2, RuleEntry, entry);
					PLIST_ENTRY pListEntry3 = pRuleEntry->Procs.Flink;
					while (pListEntry3 != &pRuleEntry->Procs)
					{
						PProcEntry pProcEntry2 = CONTAINING_RECORD(pListEntry3, ProcEntry, entry);
						if (pProcEntry1->ProcID == pProcEntry2->ProcID && pProcEntry2->Inherit)
						{
							ArvMapRule(&filterConfig, ChildId, FALSE, pRuleEntry->ID);
							goto out;
						}
						pListEntry3 = pListEntry3->Flink;
					}
					pListEntry2 = pListEntry2->Flink;
				}
				pListEntry1 = pListEntry1->Flink;
			}
		out:
			ArvFreeProcs(&procHead);
			/*if (ParentId > 0)
			{
				PRuleEntry pRuleEntry = { 0 };
				PLIST_ENTRY pListEntry = filterConfig.Rules.Flink;
				while (pListEntry != &filterConfig.Rules)
				{
					pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
					PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
					while (pListEntry2 != &pRuleEntry->Procs)
					{
						PProcEntry pProcEntry2 = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
						if (pProcEntry2->ProcID == ParentId && pProcEntry2->Inherit)
						{
							ArvMapRule(&filterConfig, ChildId, FALSE, pRuleEntry->ID);
							goto out;
						}
						pListEntry2 = pListEntry2->Flink;
					}
					pListEntry = pListEntry->Flink;
				}
			}*/
		}
		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
		ObDereferenceObject(ChildEprocess);
	}
	else
	{
		ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
		ArvRemoveProcEx(&filterConfig, ChildId);
		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
	}
}

NTSTATUS FLTAPI InstanceFilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	//
	// This is called before a filter is unloaded.
	// If NULL is specified for this routine, then the filter can never be unloaded.
	//
	UNREFERENCED_PARAMETER(Flags);
	if (!AllowUnload)
	{
		return STATUS_FLT_DO_NOT_DETACH;
	}
	if (NULL != gServerPort) {
		FltCloseCommunicationPort(gServerPort);
	}
	if (NULL != g_minifilterHandle) {
		FltUnregisterFilter(g_minifilterHandle);
	}
	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
	ExAcquireResourceExclusiveLite(&HashResource, TRUE);
	ArvFreeRegProcs(&filterConfig);
	ArvFreeRules(&filterConfig);
	ExReleaseResourceLite(&HashResource);
	ExDeleteResourceLite(&HashResource);
	FreeAllowedProcs();
	if (NULL != gDeviceObject)
	{
		if (NULL != gDeviceObject->DeviceExtension)
			KeCancelTimer(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer);

		if (NULL != gDeviceObject->DeviceExtension)
			IoFreeWorkItem(((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem);

		IoDeleteDevice(gDeviceObject);
	}
	return STATUS_SUCCESS;
}

VOID ArvInstanceSetupWhenSafe(
	IN PDEVICE_OBJECT DeviceObject,
	IN PVOID Context)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Context);


	ASSERT(NULL != Context);
	PFLT_VOLUME Volume = Context;
	PDEVICE_OBJECT devObj = NULL;
	PARV_VOLUME_CONTEXT ctx = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG retLen;
	PUNICODE_STRING workingName;
	USHORT size;
	UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
	PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;

	try {

		//
		//  Allocate a volume context structure.
		//

		status = FltAllocateContext(g_minifilterHandle,
			FLT_VOLUME_CONTEXT,
			ARV_VOLUME_CONTEXT_SIZE,
			NonPagedPool,
			&ctx);

		if (!NT_SUCCESS(status)) {

			//
			//  We could not allocate a context, quit now
			//

			leave;
		}

		//
		//  Always get the volume properties, so I can get a sector size
		//

		status = FltGetVolumeProperties(Volume,
			volProp,
			sizeof(volPropBuffer),
			&retLen);

		if (!NT_SUCCESS(status)) {

			leave;
		}

		//
		//  Save the sector size in the context for later use.  Note that
		//  we will pick a minimum sector size if a sector size is not
		//  specified.
		//

		FLT_ASSERT((volProp->SectorSize == 0) || (volProp->SectorSize >= MIN_SECTOR_SIZE));

		ctx->SectorSize = max(volProp->SectorSize, MIN_SECTOR_SIZE);

		//
		//  Init the buffer field (which may be allocated later).
		//

		ctx->VolumeName.Buffer = NULL;

		//
		//  Get the storage device object we want a name for.
		//

		status = FltGetDiskDeviceObject(Volume, &devObj);

		if (NT_SUCCESS(status)) {

			//
			//  Try and get the DOS name.  If it succeeds we will have
			//  an allocated name buffer.  If not, it will be NULL
			//

			status = IoVolumeDeviceToDosName(devObj, &ctx->VolumeName);
		}

		//
		//  If we could not get a DOS name, get the NT name.
		//

		if (!NT_SUCCESS(status)) {

			FLT_ASSERT(ctx->VolumeName.Buffer == NULL);

			//
			//  Figure out which name to use from the properties
			//

			if (volProp->RealDeviceName.Length > 0) {

				workingName = &volProp->RealDeviceName;

			}
			else if (volProp->FileSystemDeviceName.Length > 0) {

				workingName = &volProp->FileSystemDeviceName;

			}
			else {

				//
				//  No name, don't save the context
				//

				status = STATUS_FLT_DO_NOT_ATTACH;
				leave;
			}

			//
			//  Get size of buffer to allocate.  This is the length of the
			//  string plus room for a trailing colon.
			//

			size = workingName->Length; //+sizeof(WCHAR);

			//
			//  Now allocate a buffer to hold this name
			//

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "ctx->VolumeName.Buffer will not be leaked because it is freed in CleanupVolumeContext")
			ctx->VolumeName.Buffer = ExAllocatePoolWithTag(NonPagedPool,
				size,
				NAME_TAG);
			if (ctx->VolumeName.Buffer == NULL) {

				status = STATUS_INSUFFICIENT_RESOURCES;
				leave;
			}

			//
			//  Init the rest of the fields
			//

			ctx->VolumeName.Length = 0;
			ctx->VolumeName.MaximumLength = size;

			//
			//  Copy the name in
			//

			RtlCopyUnicodeString(&ctx->VolumeName,
				workingName);

			//
			//  Put a trailing colon to make the display look good
			//

			//RtlAppendUnicodeToString(&ctx->Name, L":");
		}

		//
		//  Set the context
		//

		status = FltSetVolumeContext(Volume,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			ctx,
			NULL);

		//
		//  Log debug info
		//

		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, 
			("%s->Real SectSize=0x%04x, Used SectSize=0x%04x, Name=\"%wZ\"\n",
			__FUNCTION__,
			volProp->SectorSize,
			ctx->SectorSize,
			&ctx->VolumeName));

		//
		//  It is OK for the context to already be defined.
		//

		/*if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

			status = STATUS_SUCCESS;
		}*/

	}
	finally{

		//
		//  Always release the context.  If the set failed, it will free the
		//  context.  If not, it will remove the reference added by the set.
		//  Note that the name buffer in the ctx will get freed by the context
		//  cleanup routine.
		//

		if (ctx) {

			FltReleaseContext(ctx);
		}

		//
		//  Remove the reference added to the device object by
		//  FltGetDiskDeviceObject.
		//

		if (devObj) {

			ObDereferenceObject(devObj);
		}
	}

	return;
}

NTSTATUS FLTAPI InstanceSetupCallback(
	_In_ PCFLT_RELATED_OBJECTS  FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
	_In_ DEVICE_TYPE  VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	NTSTATUS Status = 0;

	Status = ArvDoCompletionProcessingWhenSafe(
		(PVOID)ArvInstanceSetupWhenSafe,
		FltObjects->Volume,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES,
			("%s->ArvDoCompletionProcessingWhenSafe failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

EXIT:

	return Status;
}

NTSTATUS FLTAPI InstanceQueryTeardownCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
	//
	// This is called to see if the filter wants to detach from the given volume.
	//
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	return STATUS_SUCCESS;
}

//
	// Constant FLT_REGISTRATION structure for our filter.
	// This initializes the callback routines our filter wants to register for.
	//
FLT_OPERATION_REGISTRATION g_callbacks[] =
{
	{
		IRP_MJ_CREATE,
		0,
		PreOperationCreate,
		PostOperationCreate
	},
	{
		IRP_MJ_READ,
		0,
		PreOperationRead,
		0
	},
	{
		IRP_MJ_WRITE,
		0,
		PreOperationWrite,
		0
	},
	{ 
		IRP_MJ_SET_INFORMATION,
		0,
		PreOperationCreate,
		PostOperationSetInfo
	},
	{ IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_VOLUME_CONTEXT,
	   0,
	   CtxVolumeContextCleanup,
	   ARV_VOLUME_CONTEXT_SIZE,
	   ARV_VOLUME_CONTEXT_TAG },

	{ FLT_STREAM_CONTEXT,
	  0,
	  CtxStreamContextCleanup,
	  ARV_STREAM_CONTEXT_SIZE,
	  ARV_STREAM_CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};


//
// The FLT_REGISTRATION structure provides information about a file system minifilter to the filter manager.
//
CONST FLT_REGISTRATION g_filterRegistration =
{
	sizeof(FLT_REGISTRATION),						//  Size
	FLT_REGISTRATION_VERSION,						//  Version
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,	//  Flags
	ContextRegistration,							//  Context registration
	g_callbacks,									//  Operation callbacks
	InstanceFilterUnloadCallback,					//  FilterUnload
	InstanceSetupCallback,							//  InstanceSetup
	InstanceQueryTeardownCallback,					//  InstanceQueryTeardown
	NULL,											//  InstanceTeardownStart
	NULL,											//  InstanceTeardownComplete
	NULL,											//  GenerateFileName
	NULL,											//  GenerateDestinationFileName
	NULL											//  NormalizeNameComponent
};


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	NTSTATUS status = STATUS_SUCCESS;
	PSECURITY_DESCRIPTOR sd = NULL;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING uniString;
	DbgPrint("[FsFilter:register]registry path: %wZ\n", *RegistryPath);
	__try {
		//int ret = testSecp256k1();
		//bool ret = ArvVerifySig("test123", "SIG_K1_KmAZfXPHxnnPr4TC6PZs547hruSKRCd583kug9HTYPN76YQfJayeBVdkDSEg1PWwCurnqDhbsr3BiwSjCYLggkYHUVdmgq", "6ZDdiLbKdXP4W7F3gqXccQCHYARnMnbunRNNo8WjHHBvB5EN17");
		status = IoCreateDevice(
			DriverObject,
			sizeof(ARV_DEVICE_EXTENSION),
			NULL,
			FILE_DEVICE_UNKNOWN,
			0,
			FALSE,
			&gDeviceObject);

		if (!NT_SUCCESS(status))
		{
			ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->IoCreateDevice failed. Status = 0x%x.\n", __FUNCTION__, status));
			leave;
		}
		RtlZeroMemory(gDeviceObject->DeviceExtension, sizeof(ARV_DEVICE_EXTENSION));
		ArvInitDpcRoutine();

		status = InitProcessList();
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:register]find all existed processes: %d\n", status);
			__leave;
		}

		ArvInitializeFilterConfig(&filterConfig);
		ExInitializeResourceLite(&HashResource);
		status = FltRegisterFilter(DriverObject, &g_filterRegistration, &g_minifilterHandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:register]register filter handle failed: %d\n", status);
			__leave;
		}
		DbgPrint("[FsFilter:register]register filter handle success\n");
		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:register]build security descriptor failed: %d\n", status);
			__leave;
		}
		DbgPrint("[FsFilter:register]build security descriptor success\n");
		RtlInitUnicodeString(&uniString, MINI_PORT_NAME);

		//初始化对象属性
		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			sd);

		//内核建立通信端口
		status = FltCreateCommunicationPort(g_minifilterHandle, &gServerPort, &oa, NULL, MiniConnect, MiniDisconnect, MiniMessage, 1);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:register]create communication port failed: %d\n", status);
			__leave;
		}
		DbgPrint("[FsFilter:register]create communication port success\n");
		
		//开启进程过滤
		PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);

		//
		// start minifilter driver
		//
		status = FltStartFiltering(g_minifilterHandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:start]start filter handle failed: %d\n", status);
			__leave;
		}
		DbgPrint("[FsFilter:start]start filter handle success\n");
	}
	__finally {
		if (sd != NULL)
		{
			FltFreeSecurityDescriptor(sd);
		}
		if (!NT_SUCCESS(status))
		{
			if (NULL != gServerPort) {
				FltCloseCommunicationPort(gServerPort);
			}

			if (NULL != g_minifilterHandle) {
				FltUnregisterFilter(g_minifilterHandle);
			}
			if (NULL != gDeviceObject)
			{
				if (NULL != gDeviceObject->DeviceExtension)
					KeCancelTimer(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer);

				if (NULL != gDeviceObject->DeviceExtension)
					IoFreeWorkItem(((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem);

				IoDeleteDevice(gDeviceObject);
			}
			ExDeleteResourceLite(&HashResource);
		}
	}
	return status;
}
