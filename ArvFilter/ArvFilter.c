/*++

Module Name:

	ArvFilter.c

Abstract:

	This is the main module of the ArvFilter miniFilter driver.

Environment:

	Kernel mode

--*/

#include "pch.h"

//#include "Trace.h"
//#define WPP_GLOBALLOGGER
//#include "ArvFilter.tmh"

#define BUFFER_SWAP_TAG     'bdBS'
#define NAME_TAG            'mnBS'
#define PRE_2_POST_TAG      'ppBS'

NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);

//PDRIVER_OBJECT pDriverObject = { 0 };
ProcessFlags processFlags = { 0 };
FilterConfig filterConfig = { 0 };
ERESOURCE HashResource = { 0 };
ULONG controlProcID = 0;
PFLT_FILTER g_minifilterHandle = NULL;
PDEVICE_OBJECT gDeviceObject = NULL;
BOOL AllowUnload = TRUE;
PathFilterRules SystemFilterRules = { 0 };

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
	BOOLEAN ret = _stricmp(pStrProcessName, "System") == 0 ||
		_stricmp(pStrProcessName, "Cortana.exe") == 0 ||
		_stricmp(pStrProcessName, "StartMenuExper") == 0 ||
		_stricmp(pStrProcessName, "SearchUI.exe") == 0 ||
		_stricmp(pStrProcessName, "SearchApp.exe") == 0 ||
		_stricmp(pStrProcessName, "ShellExperienc") == 0 ||
		_stricmp(pStrProcessName, "ChsIME.exe") == 0 ||
		_stricmp(pStrProcessName, "ServerManagerL") == 0 ||
		_stricmp(pStrProcessName, "ServerManager.") == 0 ||
		_stricmp(pStrProcessName, "RuntimeBroker.") == 0 ||
		//_stricmp(pStrProcessName, "DllHost.exe") == 0 ||
		_stricmp(pStrProcessName, "SystemSettings") == 0 ||
		_stricmp(pStrProcessName, "WmiPrvSE.exe") == 0 ||
		_stricmp(pStrProcessName, "mmc.exe") == 0 ||
		_stricmp(pStrProcessName, "taskhostw.exe") == 0 ||
		_stricmp(pStrProcessName, "w3wp.exe") == 0 || 
		//_stricmp(pStrProcessName, "InstallAgent.e") == 0 || 
		_stricmp(pStrProcessName, "rdpclip.exe") == 0 || 
		_stricmp(pStrProcessName, "fltMC.exe") == 0 ||
		_stricmp(pStrProcessName, "cleanmgr.exe") == 0 ||
		_stricmp(pStrProcessName, "MusNotificatio") == 0 ||
		_stricmp(pStrProcessName, "Dllhost.exe") == 0;// strcmp(pStrProcessName, "smartscreen.exe") == 0 || strcmp(pStrProcessName, "smartscreen.ex") == 0;
	return ret;
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
	BOOLEAN ret = //_stricmp(pStrProcessName, "System") == 0 ||
		//_stricmp(pStrProcessName, "csrss.exe") == 0 ||
		//_stricmp(pStrProcessName, "lsass.exe") == 0 ||
		//_stricmp(pStrProcessName, "smss.exe") == 0 ||
		_stricmp(pStrProcessName, "sc.exe") == 0 ||
		//_stricmp(pStrProcessName, "services.exe") == 0 ||
		//_stricmp(pStrProcessName, "MsMpEng.exe") == 0 ||
		_stricmp(pStrProcessName, "DllHost.exe") == 0 ||
		_stricmp(pStrProcessName, "svchost.exe") == 0 ||
		_stricmp(pStrProcessName, "conhost.exe") == 0 ||
		//strcmp(pStrProcessName, "fodhelper.exe") == 0 || 
		_stricmp(pStrProcessName, "RuntimeBroker.") == 0 ||
		//strcmp(pStrProcessName, "SearchUI.exe") == 0 || 
		//_stricmp(pStrProcessName, "ShellExperienc") == 0 ||
		_stricmp(pStrProcessName, "sihost.exe") == 0 ||
		_stricmp(pStrProcessName, "smartscreen.ex") == 0 ||
		_stricmp(pStrProcessName, "taskhostw.exe") == 0 ||
		_stricmp(pStrProcessName, "Taskmgr.exe") == 0 ||
		//strcmp(pStrProcessName, "vm3dservice.exe") == 0 || 
		_stricmp(pStrProcessName, "dwm.exe") == 0 ||
		_stricmp(pStrProcessName, "fontdrvhost.ex") == 0 ||
		//_stricmp(pStrProcessName, "ChsIME.exe") == 0 ||
		_stricmp(pStrProcessName, "ctfmon.exe") == 0 ||
		//strcmp(pStrProcessName, "WindowsInternal.ComposableShell.Experiences,TextInput.InputApp.exe") == 0 || 
		_stricmp(pStrProcessName, "Explorer.EXE") == 0 ||
		_stricmp(pStrProcessName, "cmd.exe") == 0 ||
		_stricmp(pStrProcessName, "powershell.exe") == 0 ||
		//_stricmp(pStrProcessName, "arvdaemon.exe") == 0 ||
		_stricmp(pStrProcessName, "secretmanager.") == 0;
	/*strcmp(pStrProcessName, "Cortana.exe") == 0 ||
	strcmp(pStrProcessName, "StartMenuExper") == 0 ||
	strcmp(pStrProcessName, "SearchUI.exe") == 0 ||
	strcmp(pStrProcessName, "SearchApp.exe") == 0;*/
	return ret;
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

	ExEnterCriticalRegionAndAcquireResourceShared(streamContext->Resource);
	if (streamContext->UnderDBPath)
	{
		InterlockedIncrement64(&filterConfig.readCountDB);
	}
	ExReleaseResourceAndLeaveCriticalRegion(streamContext->Resource);

	ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
	InterlockedIncrement64(&filterConfig.readCount);
	ExReleaseResourceAndLeaveCriticalRegion(&HashResource);

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

	ExEnterCriticalRegionAndAcquireResourceShared(streamContext->Resource);
	if (streamContext->UnderDBPath)
	{
		InterlockedIncrement64(&filterConfig.writeCountDB);
	}
	ExReleaseResourceAndLeaveCriticalRegion(streamContext->Resource);

	ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
	InterlockedIncrement64(&filterConfig.writeCount);
	ExReleaseResourceAndLeaveCriticalRegion(&HashResource);

CtxPreWriteCleanup:
	if (streamContext != NULL) {
		FltReleaseContext(streamContext);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOL ArvIfMatchUnicodeString(PCUNICODE_STRING strs, PCUNICODE_STRING str, UINT len)
{
	for (UINT i = 0; i < len; i++)
	{
		if (RtlEqualUnicodeString(&strs[i], str, TRUE))
		{
			return TRUE;
		}
	}
	return FALSE;
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
	PCreateContext cbdContext = (PCreateContext)ExAllocatePoolWithTag(NonPagedPool, sizeof(CreateContext), 'POC');
	if (controlProcID == 0) {
		*CompletionContext = cbdContext;
		return status;
	}
	if (FltObjects->FileObject == NULL) {
		*CompletionContext = cbdContext;
		return status;
	}

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

	/*WCHAR MicroCachePath[] = { '\\','U','s','e','r','s','\\','A','d','m','i','n','i','s','t','r','a','t','o','r' };
	if ((Data->Iopb->TargetFileObject->FileName.Length >= 20 * sizeof(wchar_t)) &&
		(memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, MicroCachePath, 20 * sizeof(wchar_t)) == 0))
	{
		DbgPrint("hit");
	}*/

	PFLT_FILE_NAME_INFORMATION nameInfo = { 0 };
	UNICODE_STRING fullPath = { 0 };
	UNICODE_STRING dosName = { 0 };
	PARV_VOLUME_CONTEXT volCtx = NULL;
	//BOOL underDBPath = FALSE;
	//LIST_ENTRY ruleEntry2Head = { 0 };
	//InitializeListHead(&ruleEntry2Head);

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

	//WCHAR SystemRoot[] = { 'C', ':', '\\' };
	WCHAR LoginPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'i', 'n', '?', '\\' };
	WCHAR LogoutPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'o', 't', '?', '\\' };
	WCHAR ReginPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'R', 'e', 'g', 'i', 'n', '?', '\\' };
	WCHAR RegoutPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'R', 'e', 'g', 'o', 't', '?', '\\' };

	if ((Data->Iopb->TargetFileObject->FileName.Length > 15 * sizeof(wchar_t)) &&
		(memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LoginPath, 15 * sizeof(wchar_t)) == 0 || memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LogoutPath, 15 * sizeof(wchar_t)) == 0) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / sizeof(wchar_t) - 1] == L'\\' &&
			ArvCalculateCharCountWithinUnicodeString(&Data->Iopb->TargetFileObject->FileName, L'\\') == 6))
	{
		PSTR logintag = (PSTR)ExAllocatePoolWithTag(NonPagedPool, Data->Iopb->TargetFileObject->FileName.Length, 'LGI');
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
		if (isWChar || keyidstr == NULL || timestr == NULL || inheritStr == NULL || sigstr == NULL)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			logintag = NULL;
			cbdContext = NULL;
			return FLT_PREOP_COMPLETE;
		}
		int keyid = atoi(keyidstr);
		if (keyid == 0)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			logintag = NULL;
			cbdContext = NULL;
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
			logintag = NULL;
			cbdContext = NULL;
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
		ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
		PUNICODE_STRING wPubKey = ArvGetPubKeyByRuleID(&filterConfig, keyid);
		if (wPubKey == NULL)
		{
			ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			logintag = NULL;
			cbdContext = NULL;
			return FLT_PREOP_COMPLETE;
		}
		PSTR pubKey = (PSTR)ExAllocatePoolWithTag(NonPagedPool, wPubKey->Length / sizeof(wchar_t) + 1, 'LGI');
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
			logintag = NULL;
			pubKey = NULL;
			cbdContext = NULL;
			ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
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
			logintag = NULL;
			pubKey = NULL;
			cbdContext = NULL;
			ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);

		//ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
		if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LoginPath, 15 * sizeof(wchar_t)) == 0)
		{
			//ArvMapRule(&filterConfig, procID, inherit, keyid);
			ArvProcessFlagAdd(&processFlags, procID, inherit, keyid);
		}
		else if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LogoutPath, 15 * sizeof(wchar_t)) == 0)
		{
			//ArvRemoveProc(&filterConfig, procID, keyid);
			ArvProcessFlagDelete(&processFlags, procID);
		}
		//ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
		ExFreePoolWithTag(logintag, 'LGI');
		ExFreePoolWithTag(pubKey, 'LGI');
		ExFreePoolWithTag(cbdContext, 'POC');
		logintag = NULL;
		pubKey = NULL;
		cbdContext = NULL;
		return FLT_PREOP_COMPLETE;
	}
	else if ((Data->Iopb->TargetFileObject->FileName.Length > 15 * sizeof(wchar_t)) &&
		(memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, ReginPath, 15 * sizeof(wchar_t)) == 0 || memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, RegoutPath, 15 * sizeof(wchar_t)) == 0) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[Data->Iopb->TargetFileObject->FileName.Length / sizeof(wchar_t) - 1] == L'\\' &&
			ArvCalculateCharCountWithinUnicodeString(&Data->Iopb->TargetFileObject->FileName, L'\\') == 7))
	{
		PSTR logintag = (PSTR)ExAllocatePoolWithTag(NonPagedPool, Data->Iopb->TargetFileObject->FileName.Length, 'LGI');
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
			logintag = NULL;
			cbdContext = NULL;
			return FLT_PREOP_COMPLETE;
		}
		int keyid = atoi(keyidstr);
		if (keyid == 0)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			logintag = NULL;
			cbdContext = NULL;
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
			logintag = NULL;
			cbdContext = NULL;
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
		ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
		PUNICODE_STRING wPubKey = ArvGetPubKeyByRuleID(&filterConfig, keyid);
		if (wPubKey == NULL)
		{
			ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			ExFreePoolWithTag(cbdContext, 'POC');
			logintag = NULL;
			cbdContext = NULL;
			return FLT_PREOP_COMPLETE;
		}
		PSTR pubKey = (PSTR)ExAllocatePoolWithTag(NonPagedPool, wPubKey->Length / sizeof(wchar_t) + 1, 'LGI');
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
			logintag = NULL;
			pubKey = NULL;
			cbdContext = NULL;
			ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
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
			logintag = NULL;
			pubKey = NULL;
			cbdContext = NULL;
			ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		for (UINT d = 0; d < 5; d++)
		{
			logintag[bPoint[d]] = '\0';
		}
		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);

		ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
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
		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
		ExFreePoolWithTag(logintag, 'LGI');
		ExFreePoolWithTag(pubKey, 'LGI');
		ExFreePoolWithTag(cbdContext, 'POC');
		logintag = NULL;
		pubKey = NULL;
		cbdContext = NULL;
		return FLT_PREOP_COMPLETE;
	}

	/*if (KeGetCurrentIrql() >= APC_LEVEL)
	{
		KeBugCheck(NO_EXCEPTION_HANDLING_SUPPORT);
	}*/
	/*UNICODE_STRING ExpAllow1 = RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows");
	UNICODE_STRING ExpAllow2 = RTL_CONSTANT_STRING(L"\\AppData\\Roaming\\Microsoft\\Windows");
	UNICODE_STRING ExpAllow3 = RTL_CONSTANT_STRING(L"\\AppData\\Local\\Temp");
	UNICODE_STRING ExpAllow4 = RTL_CONSTANT_STRING(L"\\AppData\\Local\\ConnectedDevicesPlatform");
	UNICODE_STRING ExpAllow5 = RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft");
	UNICODE_STRING ExpAllow6 = RTL_CONSTANT_STRING(L"C:\\Windows\\rescache\\_merged");
	UNICODE_STRING ExpAllow7 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator");

	UNICODE_STRING ExpAllows[24] = {
		RTL_CONSTANT_STRING(L"C:\\Users"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\ConnectedDevicesPlatform"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Temp"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Roaming"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\Desktop"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Public"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Public\\Desktop"),
		RTL_CONSTANT_STRING(L"C:\\Windows\\rescache\\_merged"),
		RTL_CONSTANT_STRING(L"C:\\Windows\\system32\\catroot"),
		RTL_CONSTANT_STRING(L"C:\\Windows\\system32\\catroot2"),
		RTL_CONSTANT_STRING(L"C:\\ProgramData"),
		RTL_CONSTANT_STRING(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu"),
		RTL_CONSTANT_STRING(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs"),
		RTL_CONSTANT_STRING(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu Places"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\IconCache.db"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache_idx.db"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch"),
		RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned")
	};

	UNICODE_STRING ExpAllow20 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\WebCache");
	UNICODE_STRING ExpAllow21 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\ConnectedDevicesPlatform");
	UNICODE_STRING ExpAllow22 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Packages");
	UNICODE_STRING ExpAllow23 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\WebCacheLock.dat");
	UNICODE_STRING ExpAllow24 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches");
	UNICODE_STRING ExpAllow25 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\INetCache");*/

	ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
	UINT ForD = 0;
	UINT RorW = 0;
	PProcessFlag pFlag = { 0 };
	LIST_ENTRY procHead = { 0 };
	InitializeListHead(&procHead);
	FindAncestorProcessID(procID, &procHead);
	try
	{
		ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
		if (filterConfig.Rules.Flink == &filterConfig.Rules)
		{
			/*if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION && status != FLT_PREOP_COMPLETE)
			{
				status = FLT_PREOP_SYNCHRONIZE;
			}*/
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
		dosName.Buffer = ExAllocatePoolWithTag(NonPagedPool, volCtx->VolumeName.Length, 'SOD');
		if (!dosName.Buffer)
		{
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

		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
		if (!NT_SUCCESS(status))
		{
			leave;
		}
		status = FltParseFileNameInformation(nameInfo);
		if (!NT_SUCCESS(status))
		{
			leave;
		}

		size_t fullLen = dosName.Length + nameInfo->Name.Length - nameInfo->Volume.Length;
		fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, fullLen, 'POC');
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


		/*UNICODE_STRING tests = { 0 };
		RtlInitUnicodeString(&tests, L"C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Themes");
		if (strcmp(callerProcessName, "explorer.exe") && RtlEqualUnicodeString(&fullPath, &tests, TRUE))
		{
			DbgPrint("hit");
		}*/

		PRuleEntry pRuleEntry = { 0 };
		PPathEntry pPathEntry = { 0 };
		PLIST_ENTRY pListEntry1 = procHead.Flink;
		while (pListEntry1 != &procHead)
		{
			PProcEntry pProcEntry1 = CONTAINING_RECORD(pListEntry1, ProcEntry, entry);
			pFlag = ArvProcessFlagFind(&processFlags, pProcEntry1->ProcID);
			if (pFlag)
			{
				break;
			}
			pListEntry1 = pListEntry1->Flink;
		}

		BOOL flag = FALSE;
		if (!pFlag)
		{
			goto out1;
		}
		pRuleEntry = ArvGetRuleEntryByRuleID(&filterConfig, pFlag->RuleID);
		if (!pRuleEntry)
		{
			goto out1;
		}
		
		//PLIST_ENTRY pListEntry = filterConfig.Rules.Flink;
		//while (pListEntry != &filterConfig.Rules)
		//{
			//pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
		PLIST_ENTRY pListEntry = pRuleEntry->Dirs.Flink;
		while (pListEntry != &pRuleEntry->Dirs)
		{
			pPathEntry = CONTAINING_RECORD(pListEntry, PathEntry, entry);
			if (pPathEntry->Path.Length <= fullPath.Length)
			{
				USHORT fpLen = fullPath.Length;
				fullPath.Length = pPathEntry->Path.Length;
				if (RtlCompareUnicodeString(&fullPath, &pPathEntry->Path, TRUE) == 0)
				{
					fullPath.Length = fpLen;
					flag = TRUE;
					//ArvAddRuleEntry2(&ruleEntry2Head, pRuleEntry, pPathEntry->isDB);
					break;
					/*if (pPathEntry->isDB)
					{
						underDBPath = TRUE;
					}
					goto out1;*/
				}
				fullPath.Length = fpLen;
			}
			pListEntry = pListEntry->Flink;
		}

		//TODO: 限制可执行文件读取

			//pListEntry = pListEntry->Flink;
		//}
		if (ArvGetLogOnly() == 2)
		{
			flag = FALSE;
		}
	out1:
		if (flag)
		{
			cbdContext->UnderDBPath = pPathEntry->isDB;
			InterlockedIncrement64(&pPathEntry->stat.passCounter);
			if (cbdContext->UnderDBPath)
			{
				InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
			}
			DbgPrint("[FsFilter:create]unauthorized process: %d - %wZ\n", procID, fullPath);
		}
		else
		{
			//ArvWriteLog(L"create", &fullPath, procID, callerProcessName, TRUE);
			//ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
			if (pFlag && pFlag->Pid == procID && ArvGetRuleIDByRegProcName(&filterConfig, callerProcessName) == 0 && (FILE_OPEN == createDisposition && !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)))
			{
				DbgPrint("[FsFilter:create]unauthorized process: %d - %wZ\n", procID, fullPath);
				//if (MatchReadWriteProcess(callerProcessName) || (FILE_OPEN == createDisposition && !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)))
				//{
				//	DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
				//	//InterlockedIncrement64(&pPathEntry->stat.passCounter);
				//}
				//else if (_stricmp(callerProcessName, "Explorer.EXE") == 0 && (ArvFindSubString(&fullPath, &ExpAllow1) || ArvFindSubString(&fullPath, &ExpAllow2) || ArvFindSubString(&fullPath, &ExpAllow3) || ArvFindSubString(&fullPath, &ExpAllow4) || RtlPrefixUnicodeString(&ExpAllow5, &fullPath, TRUE) == TRUE))
				//{
				//	DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
				//}
				//else
				//{
				//	DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
				//	//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
				//	Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				//	Data->IoStatus.Information = 0;
				//	status = FLT_PREOP_COMPLETE;
				//}
			}
			else
			{
				PPathEntry pathEntry2 = NULL;
				//UINT ForD = FALSE;
				FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &ForD);
				ForD++;

				RorW = FILE_OPEN != createDisposition;
				RorW++;

				if (ArvSysPathFilterRulesIfMatch(&SystemFilterRules, procID, callerProcessName, ForD, RorW, &fullPath))
				{
					DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
				}
				else if (fullPath.Length >= 3 * sizeof(wchar_t) && memcmp(fullPath.Buffer, ArvGetSystemRoot()->Buffer, 3 * sizeof(wchar_t)) == 0 && (FILE_OPEN == createDisposition && !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)))
				{
					DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
				}
				else
				{
					DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					pathEntry2 = ArvFindPathByPrefix(&filterConfig, &fullPath);
					if (pathEntry2)
					{
						InterlockedIncrement64(&pathEntry2->stat.blockCounter);
						if (pathEntry2->isDB)
						{
							InterlockedIncrement64(&pathEntry2->stat.blockCounterDB);
						}
					}
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					Data->IoStatus.Information = 0;
					status = FLT_PREOP_COMPLETE;
				}

//				/*if (Data && Data->Iopb && (Data->Iopb->MajorFunction == IRP_MJ_CREATE))
//				{*/
//				//ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
//				if (fullPath.Length >= 3 * sizeof(wchar_t) && memcmp(fullPath.Buffer, SystemRoot, 3 * sizeof(wchar_t)) == 0)
//				{
//					//if (ProcAllowed(procID) || (MatchReadonlyProcess(procID) && FILE_OPEN == createDisposition))
//					if (ProcAllowed(procID) || MatchReadWriteProcess(callerProcessName) || (FILE_OPEN == createDisposition && !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)))
//					{
//						DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
////InterlockedIncrement64(&pPathEntry->stat.passCounter);
//					}
//					else if (ProcAllowedPaths(procID, callerProcessName, &fullPath))
//					{
//						DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
//					}
//					/*else if (_stricmp(callerProcessName, "Explorer.EXE") == 0 && (ArvFindSubString(&fullPath, &ExpAllow1) || ArvFindSubString(&fullPath, &ExpAllow2) || ArvFindSubString(&fullPath, &ExpAllow3) || ArvFindSubString(&fullPath, &ExpAllow4) || ArvFindSubString(&fullPath, &ExpAllow5) || RtlPrefixUnicodeString(&ExpAllow6, &fullPath, TRUE) == TRUE ) || RtlEqualUnicodeString(&fullPath, &ExpAllow7, TRUE) || ArvIfMatchUnicodeString(ExpAllows, &fullPath, sizeof(ExpAllows)/sizeof(ExpAllows[0])))
//					{
//						DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
//					}
//					else if (RtlPrefixUnicodeString(&ExpAllow21, &fullPath, TRUE) || RtlPrefixUnicodeString(&ExpAllow22, &fullPath, TRUE) ||  RtlEqualUnicodeString(&fullPath, &ExpAllow23, TRUE) || RtlEqualUnicodeString(&fullPath, &ExpAllow24, TRUE) || RtlEqualUnicodeString(&fullPath, &ExpAllow25, TRUE))
//					{
//						DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
//					}*/
//					else
//					{
//						DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
//						pathEntry2 = ArvFindPathByPrefix(&filterConfig, &fullPath);
//						if (pathEntry2)
//						{
//							InterlockedIncrement64(&pathEntry2->stat.blockCounter);
//							if (pathEntry2->isDB)
//							{
//								InterlockedIncrement64(&pathEntry2->stat.blockCounterDB);
//							}
//						}
//						Data->IoStatus.Status = STATUS_ACCESS_DENIED;
//						Data->IoStatus.Information = 0;
//						status = FLT_PREOP_COMPLETE;
//					}
//				}
//				else
//				{
//					if (ProcAllowed(procID) || MatchReadWriteProcess(callerProcessName) || (MatchReadonlyProcess(callerProcessName) && FILE_OPEN == createDisposition && !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)))
//					{
//						DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
//						//InterlockedIncrement64(&pPathEntry->stat.passCounter);
//					}
//					else
//					{
//						DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
//						pathEntry2 = ArvFindPathByPrefix(&filterConfig, &fullPath);
//						if (pathEntry2)
//						{
//							InterlockedIncrement64(&pathEntry2->stat.blockCounter);
//							if (pathEntry2->isDB)
//							{
//								InterlockedIncrement64(&pathEntry2->stat.blockCounterDB);
//							}
//						}
//						Data->IoStatus.Status = STATUS_ACCESS_DENIED;
//						Data->IoStatus.Information = 0;
//						status = FLT_PREOP_COMPLETE;
//					}
//				}
			}
		}
	}
	finally
	{
		if (status != FLT_PREOP_COMPLETE)
		{
			status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			//PCreateContext cbdContext = (PCreateContext)ExAllocatePoolWithTag(NonPagedPool, sizeof(CreateContext), 'POC');
			//cbdContext->UnderDBPath = underDBPath;
			*CompletionContext = cbdContext;
		}
		if ((ArvGetLogFlag() & 1) && status == FLT_PREOP_COMPLETE && fullPath.Length)
		{
			/*if (ArvGetLogOnly())
			{*/
				ArvWriteLogEx(L"create", &fullPath, &procHead, FILE_OPEN == createDisposition, ForD - 1, FALSE);
			/*}
			else
			{
				ArvWriteLog(L"create", &fullPath, procID, callerProcessName, FILE_OPEN == createDisposition, ForD - 1, FALSE);
			}*/
			
			//status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
		else if ((ArvGetLogFlag() & 2) && status == FLT_PREOP_SUCCESS_WITH_CALLBACK && FLT_IS_IRP_OPERATION(Data) && fullPath.Length)
		{
			/*if (ArvGetLogOnly())
			{*/
				ArvWriteLogEx(L"create", &fullPath, &procHead, FILE_OPEN == createDisposition, ForD - 1, TRUE);
			/*}
			else
			{
				ArvWriteLog(L"create", &fullPath, procID, callerProcessName, FILE_OPEN == createDisposition, ForD - 1, TRUE);
			}*/
		}

		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
		//ArvFreeRuleEntry2(&ruleEntry2Head);
		if (dosName.Buffer)
		{
			ArvFreeUnicodeString(&dosName, 'SOD');
		}
		if (fullPath.Buffer)
		{
			ArvFreeUnicodeString(&fullPath, 'POC');
		}
		if (nameInfo != NULL)
		{
			FltReleaseFileNameInformation(nameInfo);
		}
		if (pCallerProcess != NULL)
		{
			ObDereferenceObject(pCallerProcess);
		}
		if (volCtx != NULL) {

			FltReleaseContext(volCtx);
		}
		if (pFlag != NULL)
		{
			ExFreePoolWithTag(pFlag, 'pcft');
			pFlag = NULL;
		}
		ArvFreeProcs(&procHead);
		/*if (status != FLT_PREOP_COMPLETE)
		{
			status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}*/
		//if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
		//{
		//	if (status != FLT_PREOP_COMPLETE)
		//	{
		//		//status = FLT_PREOP_SYNCHRONIZE;
		//		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		//		//PCreateContext cbdContext = (PCreateContext)ExAllocatePoolWithTag(NonPagedPool, sizeof(CreateContext), 'POC');
		//		//cbdContext->UnderDBPath = underDBPath;
		//		*CompletionContext = cbdContext;
		//	}
		//}
		//else
		//{
		
		//}

	}
	if (status == FLT_PREOP_COMPLETE)
	{
		if (ArvGetLogOnly())
		{
			status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
		else
		{
			ExFreePoolWithTag(cbdContext, 'POC');
			cbdContext = NULL;
		}
	}
	if (status == FLT_PREOP_SUCCESS_WITH_CALLBACK && !FLT_IS_IRP_OPERATION(Data))
	{
		ExFreePoolWithTag(cbdContext, 'POC');
		cbdContext = NULL;
		status = FLT_PREOP_DISALLOW_FASTIO;
	}

	//if (status == FLT_PREOP_COMPLETE && fullPath.Length)
	//{
	//	/*UNICODE_STRING AdminPath = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator");
	//	UNICODE_STRING AdminCachePath = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches");
	//	if (RtlCompareUnicodeString(&fullPath, &AdminPath, TRUE) == 0 || RtlCompareUnicodeString(&fullPath, &AdminCachePath, TRUE) == 0)
	//	{
	//		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	//	}*/
	//	ArvWriteLog(L"create", &fullPath, procID, callerProcessName, FILE_OPEN == createDisposition, FALSE);
	//	//TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Path: %wZ, Proc: %s, result: %d", &Data->Iopb->TargetFileObject->FileName, callerProcessName, 0);
	//}
	//else if (status == FLT_PREOP_SUCCESS_WITH_CALLBACK && !FLT_IS_IRP_OPERATION(Data) && fullPath.Length)
	//{
	//	ArvWriteLog(L"create", &fullPath, procID, callerProcessName, FILE_OPEN == createDisposition, TRUE);
	//	//TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Path: %wZ, Proc: %s, result: %d", &Data->Iopb->TargetFileObject->FileName, callerProcessName, 1);
	//}
	/*BOOL isFile = FALSE;
	if (STATUS_SUCCESS == FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isFile) && isFile)
	{
		DbgPrint("hit");
	}*/
	/*WCHAR MicroCachePath[] = { '\\','U','s','e','r','s','\\','A','d','m','i','n','i','s','t','r','a','t','o','r' };
	if (status == FLT_PREOP_COMPLETE && _stricmp(callerProcessName, "SearchUI.exe") == 0 && (Data->Iopb->TargetFileObject->FileName.Length >= 20 * sizeof(wchar_t)) &&
		(memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, MicroCachePath, 20 * sizeof(wchar_t)) == 0))
	{
		KeBugCheck(NO_EXCEPTION_HANDLING_SUPPORT);
	}*/
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

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
	{
		goto CtxPostCreateCleanup;
	}

	if (STATUS_SUCCESS != Cbd->IoStatus.Status)
	{
		opStatus = FLT_POSTOP_FINISHED_PROCESSING;
		goto CtxPostCreateCleanup;
	}

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

	ExEnterCriticalRegionAndAcquireResourceExclusive(streamContext->Resource);

	//
	//  Increment the create count
	//
	if (createContext)
	{
		streamContext->UnderDBPath = createContext->UnderDBPath;
	}


	/*DbgPrint("[Ctx]: CtxPostCreate -> Stream context info for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p)\n",
		&nameInfo->Name,
		Cbd,
		FltObjects->FileObject,
		streamContext);*/

		//
		//  Relinquish write acccess to the context
		//

	ExReleaseResourceAndLeaveCriticalRegion(streamContext->Resource);

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
		createContext = NULL;
	}

	DbgPrint("[Ctx]: CtxPostCreate -> Exit (Cbd = %p, FileObject = %p, Status = 0x%x)\n",
		Cbd,
		FltObjects->FileObject,
		Cbd->IoStatus.Status);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationSetInfo(
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
	PCreateContext cbdContext = (PCreateContext)ExAllocatePoolWithTag(NonPagedPool, sizeof(CreateContext), 'POC');
	if (controlProcID == 0) {
		*CompletionContext = cbdContext;
		return status;
	}
	if (FltObjects->FileObject == NULL) {
		*CompletionContext = cbdContext;
		return status;
	}

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

	PFLT_FILE_NAME_INFORMATION nameInfo = { 0 };
	UNICODE_STRING fullPath = { 0 };
	UNICODE_STRING dosName = { 0 };
	PARV_VOLUME_CONTEXT volCtx = NULL;
	//BOOL underDBPath = FALSE;
	//LIST_ENTRY ruleEntry2Head = { 0 };
	//InitializeListHead(&ruleEntry2Head);

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

	PProcessFlag pFlag = { 0 };
	LIST_ENTRY procHead = { 0 };
	InitializeListHead(&procHead);
	FindAncestorProcessID(procID, &procHead);
	UINT ForD = 0;

	/*UNICODE_STRING ExpAllow10 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches");

	UNICODE_STRING ExpAllow20 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\WebCache");
	UNICODE_STRING ExpAllow21 = RTL_CONSTANT_STRING(L"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Explorer");*/

	try
	{
		ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
		if (filterConfig.Rules.Flink == &filterConfig.Rules)
		{
			leave;
		}

		status = FltGetVolumeContext(FltObjects->Filter,
			FltObjects->Volume,
			&volCtx);

		if (!NT_SUCCESS(status)) {
			DbgPrint("[FsFilter:setinfo]Error getting volume context, status=%x\n", status);
			leave;
		}

		status2 = PsLookupProcessByProcessId((HANDLE)procID, &pCallerProcess);
		if (status2 == STATUS_SUCCESS)
		{
			callerProcessName = PsGetProcessImageFileName(pCallerProcess);
		}

		UNICODE_STRING netVolName;
		RtlInitUnicodeString(&netVolName, L"\\Device\\Mup");
		dosName.Buffer = ExAllocatePoolWithTag(NonPagedPool, volCtx->VolumeName.Length, 'SOD');
		if (!dosName.Buffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}
		dosName.Length = dosName.MaximumLength = volCtx->VolumeName.Length;
		RtlCopyUnicodeString(&dosName, &volCtx->VolumeName);

		if (dosName.Length && RtlCompareUnicodeString(&dosName, &netVolName, TRUE) == 0)
		{
			dosName.Length = dosName.MaximumLength = 2;
		}

		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
		if (!NT_SUCCESS(status))
		{
			leave;
		}
		status = FltParseFileNameInformation(nameInfo);
		if (!NT_SUCCESS(status))
		{
			leave;
		}

		size_t fullLen = dosName.Length + nameInfo->Name.Length - nameInfo->Volume.Length;
		fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, fullLen, 'POC');
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

		PRuleEntry pRuleEntry = { 0 };
		PPathEntry pPathEntry = { 0 };
		PLIST_ENTRY pListEntry1 = procHead.Flink;
		while (pListEntry1 != &procHead)
		{
			PProcEntry pProcEntry1 = CONTAINING_RECORD(pListEntry1, ProcEntry, entry);
			pFlag = ArvProcessFlagFind(&processFlags, pProcEntry1->ProcID);
			if (pFlag)
			{
				break;
			}
			pListEntry1 = pListEntry1->Flink;
		}

		BOOL flag = FALSE;
		if (!pFlag)
		{
			goto out1;
		}
		pRuleEntry = ArvGetRuleEntryByRuleID(&filterConfig, pFlag->RuleID);
		if (!pRuleEntry)
		{
			goto out1;
		}

		//PLIST_ENTRY pListEntry = filterConfig.Rules.Flink;
		//while (pListEntry != &filterConfig.Rules)
		//{
			//pRuleEntry = CONTAINING_RECORD(pListEntry, RuleEntry, entry);
			PLIST_ENTRY pListEntry = pRuleEntry->Dirs.Flink;
			while (pListEntry != &pRuleEntry->Dirs)
			{
				pPathEntry = CONTAINING_RECORD(pListEntry, PathEntry, entry);
				if (pPathEntry->Path.Length <= fullPath.Length)
				{
					USHORT fpLen = fullPath.Length;
					fullPath.Length = pPathEntry->Path.Length;
					if (RtlCompareUnicodeString(&fullPath, &pPathEntry->Path, TRUE) == 0)
					{
						fullPath.Length = fpLen;
						flag = TRUE;
						//ArvAddRuleEntry2(&ruleEntry2Head, pRuleEntry, pPathEntry->isDB);
						break;
					}
					fullPath.Length = fpLen;
				}
				pListEntry = pListEntry->Flink;
			}
			//pListEntry = pListEntry->Flink;
		//}
	out1:
		if (flag)
		{
			cbdContext->UnderDBPath = pPathEntry->isDB;
			InterlockedIncrement64(&pPathEntry->stat.passCounter);
			if (cbdContext->UnderDBPath)
			{
				InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
			}
			DbgPrint("[FsFilter:setinfo]unauthorized process: %d - %wZ\n", procID, fullPath);

		}
		else
		{
			//DbgPrint("[FsFilter:create]unfiltered path: %d - %wZ\n", procID, fullPath);
			//TODO: 未命中目录，可读
			//if (pFlag && pFlag->Pid == procID && ArvGetRuleIDByRegProcName(&filterConfig, callerProcessName) == 0)
			//{
			//	if (MatchReadWriteProcess(callerProcessName))
			//	{
			//		DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
			//		//InterlockedIncrement64(&pPathEntry->stat.passCounter);
			//	}
			//	else
			//	{
			//		DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
			//		//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
			//		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			//		Data->IoStatus.Information = 0;
			//		status = FLT_PREOP_COMPLETE;
			//	}
			//}
			//else
			//{
			//	if (fullPath.Length >= 3 * sizeof(wchar_t) && memcmp(fullPath.Buffer, SystemRoot, 3 * sizeof(wchar_t)) == 0)
			//	{
					//if (ProcAllowed(procID) || MatchReadWriteProcess(callerProcessName))
					//{
					//	DbgPrint("[FsFilter:setinfo]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					//	//InterlockedIncrement64(&pPathEntry->stat.passCounter);
					//}
					//else if (ProcAllowedPaths(procID, callerProcessName, &fullPath))
					//{
					//	DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					//}
					/*else if (_stricmp(callerProcessName, "Explorer.EXE") == 0 && (RtlPrefixUnicodeString(&ExpAllow10, &fullPath, TRUE) || RtlPrefixUnicodeString(&ExpAllow21, &fullPath, TRUE)))
					{
						DbgPrint("[FsFilter:setinfo]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					}
					else if (RtlPrefixUnicodeString(&ExpAllow20, &fullPath, TRUE) || RtlPrefixUnicodeString(&ExpAllow21, &fullPath, TRUE))
					{
						DbgPrint("[FsFilter:setinfo]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					}*/

					PPathEntry pathEntry2 = NULL;
					//UINT ForD = FALSE;
					FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &ForD);
					ForD++;

					UINT RorW = 2;

					if (ArvSysPathFilterRulesIfMatch(&SystemFilterRules, procID, callerProcessName, ForD, RorW, &fullPath))
					{
						DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
					}
					else
					{
						//DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
						////InterlockedIncrement64(&pPathEntry->stat.blockCounter);
						//Data->IoStatus.Status = STATUS_ACCESS_DENIED;
						//Data->IoStatus.Information = 0;
						//status = FLT_PREOP_COMPLETE;
						BOOLEAN blocked = FALSE;
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
							blocked = TRUE;
							break;
						case FileRenameInformation:
						case 65:
							// Process the request according to our needs e.g copy the file
							//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
							blocked = TRUE;
							break;
						}
						if (blocked)
						{
							PPathEntry pathEntry2 = ArvFindPathByPrefix(&filterConfig, &fullPath);
							if (pathEntry2)
							{
								InterlockedIncrement64(&pathEntry2->stat.blockCounter);
								if (pathEntry2->isDB)
								{
									InterlockedIncrement64(&pathEntry2->stat.blockCounterDB);
								}
							}
						}
					}
				//}
				//else
				//{
				//	if (MatchReadWriteProcess(callerProcessName))
				//	{
				//		DbgPrint("[FsFilter:create]allowed system process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
				//	}
				//	else
				//	{
				//		switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
				//		case FileDispositionInformation:
				//		case 64:
				//			// deleting a file we need to action
				//			if (((FILE_DISPOSITION_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile) {
				//				//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
				//				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				//				Data->IoStatus.Information = 0;
				//				status = FLT_PREOP_COMPLETE;
				//			}
				//			break;
				//		case FileRenameInformation:
				//		case 65:
				//			// Process the request according to our needs e.g copy the file
				//			//InterlockedIncrement64(&pPathEntry->stat.blockCounter);
				//			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				//			Data->IoStatus.Information = 0;
				//			status = FLT_PREOP_COMPLETE;
				//			break;
				//		}
				//	}
				//}
			//}
		}
	}
	finally
	{
		if ((ArvGetLogFlag() & 1) && status == FLT_PREOP_COMPLETE && fullPath.Length)
		{
			/*if (ArvGetLogOnly())
			{*/
				ArvWriteLogEx(L"setinfo", &fullPath, &procHead, FALSE, ForD - 1, FALSE);
			/*}
			else
			{
				ArvWriteLog(L"setinfo", &fullPath, procID, callerProcessName, FALSE, ForD - 1, FALSE);
			}*/
		}
		else if ((ArvGetLogFlag() & 2) && status == FLT_PREOP_SUCCESS_WITH_CALLBACK && FLT_IS_IRP_OPERATION(Data) && fullPath.Length)
		{
			/*if (ArvGetLogOnly())
			{*/
				ArvWriteLogEx(L"setinfo", &fullPath, &procHead, FALSE, ForD - 1, TRUE);
			/*}
			else
			{
				ArvWriteLog(L"setinfo", &fullPath, procID, callerProcessName, FALSE, ForD - 1, TRUE);
			}*/
		}
		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
		//ArvFreeRuleEntry2(&ruleEntry2Head);
		if (dosName.Buffer)
		{
			ArvFreeUnicodeString(&dosName, 'SOD');
		}
		if (fullPath.Buffer)
		{
			ArvFreeUnicodeString(&fullPath, 'POC');
		}
		if (nameInfo != NULL)
		{
			FltReleaseFileNameInformation(nameInfo);
		}
		if (pCallerProcess != NULL)
		{
			ObDereferenceObject(pCallerProcess);
		}
		if (volCtx != NULL) {

			FltReleaseContext(volCtx);
		}
		if (pFlag != NULL)
		{
			ExFreePoolWithTag(pFlag, 'pcft');
			pFlag = NULL;
		}
		ArvFreeProcs(&procHead);
		if (status != FLT_PREOP_COMPLETE)
		{
			status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			*CompletionContext = cbdContext;
		}
	}
	if (status == FLT_PREOP_COMPLETE)
	{
		ExFreePoolWithTag(cbdContext, 'POC');
		cbdContext = NULL;
		if (ArvGetLogOnly())
		{
			status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
	}
	/*if (status == FLT_PREOP_COMPLETE && fullPath.Length)
	{
		ArvWriteLog(L"setinfo", &fullPath, procID, callerProcessName, FALSE, FALSE);
	}
	else if (status == FLT_PREOP_SUCCESS_WITH_CALLBACK && fullPath.Length)
	{
		ArvWriteLog(L"setinfo", &fullPath, procID, callerProcessName, FALSE, TRUE);
	}*/
	if (status == FLT_PREOP_SUCCESS_WITH_CALLBACK && !FLT_IS_IRP_OPERATION(Data))
	{
		ExFreePoolWithTag(cbdContext, 'POC');
		cbdContext = NULL;
		status = FLT_PREOP_DISALLOW_FASTIO;
	}
	return status;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostOperationSetInfoWhenSafe(
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
	fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, fullLen, 'POC');
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

	ExEnterCriticalRegionAndAcquireResourceExclusive(streamContext->Resource);

	if (createContext)
	{
		streamContext->UnderDBPath = createContext->UnderDBPath;
	}

	/*DbgPrint("[Ctx]: CtxPostSetInfo -> Old info in stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p)\n",
			&nameInfo->Name,
			Cbd,
			FltObjects->FileObject,
			streamContext);*/


			//
			//  Relinquish write acccess to the context
			//

	ExReleaseResourceAndLeaveCriticalRegion(streamContext->Resource);


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
		createContext = NULL;
	}

	DbgPrint("[Ctx]: CtxPostSetInfo -> Exit (Cbd = %p, FileObject = %p)\n",
		Cbd,
		FltObjects->FileObject);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS PostOperationSetInfo(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	FLT_POSTOP_CALLBACK_STATUS Status = FLT_POSTOP_FINISHED_PROCESSING;

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
	{
		if (CompletionContext)
		{
			ExFreePoolWithTag(CompletionContext, 'POC');
		}
		goto EXIT;
	}

	/*
	* 如果FO创建失败，不进入PocFindOrCreateStreamContext
	*/
	if (STATUS_SUCCESS != Data->IoStatus.Status)
	{
		Status = FLT_POSTOP_FINISHED_PROCESSING;
		goto EXIT;
	}


	if (!FltDoCompletionProcessingWhenSafe(Data,
		FltObjects,
		CompletionContext,
		Flags,
		PostOperationSetInfoWhenSafe,
		&Status))
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES,
			("%s->FltDoCompletionProcessingWhenSafe failed. Status = 0x%x.\n",
				__FUNCTION__,
				Status));
	}

EXIT:

	return Status;
}


//VOID CreateProcessNotifyWhenSafe(
//	IN PDEVICE_OBJECT DeviceObject,
//	IN PVOID Context)
//{
//	PParamData data = (PParamData)Context;
//	//KEVENT Event = *((PKEVENT)(data->Event));
//	HANDLE ChildId = data->ChildID;
//	BOOLEAN Create = data->Create;
//	PEPROCESS ChildEprocess = NULL;
//	NTSTATUS status;
//	if (Create)
//	{
//		status = PsLookupProcessByProcessId(ChildId, &ChildEprocess);
//		if (!NT_SUCCESS(status))
//		{
//			DbgPrint(("Get Eprocess Failed\n"));
//			//KeSetEvent(
//			//	&Event,               //被激活的事件
//			//	IO_NO_INCREMENT,      //被唤醒线程临时提升线程优先级的增量,传0
//			//	FALSE);
//			//PsTerminateSystemThread(STATUS_SUCCESS);
//			return;
//		}
//		PSTR cProcName = PsGetProcessImageFileName(ChildEprocess);
//		ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
//		PRegProcEntry entry = ArvGetRegProcEntryByRegProcName(&filterConfig, cProcName);
//		if (entry != NULL)
//		{
//			ArvMapRule(&filterConfig, ChildId, entry->Inherit, entry->RuleID);
//		}
//		/*else
//		{
//			LIST_ENTRY procHead = { 0 };
//			InitializeListHead(&procHead);
//			FindAncestorProcessID(ChildId, &procHead);
//			PLIST_ENTRY pListEntry1 = procHead.Flink;
//			while (pListEntry1 != &procHead)
//			{
//				PProcEntry pProcEntry1 = CONTAINING_RECORD(pListEntry1, ProcEntry, entry);
//				PLIST_ENTRY pListEntry2 = filterConfig.Rules.Flink;
//				while (pListEntry2 != &filterConfig.Rules)
//				{
//					PRuleEntry pRuleEntry = CONTAINING_RECORD(pListEntry2, RuleEntry, entry);
//					PLIST_ENTRY pListEntry3 = pRuleEntry->Procs.Flink;
//					while (pListEntry3 != &pRuleEntry->Procs)
//					{
//						PProcEntry pProcEntry2 = CONTAINING_RECORD(pListEntry3, ProcEntry, entry);
//						if (pProcEntry1->ProcID == pProcEntry2->ProcID && pProcEntry2->Inherit)
//						{
//							ArvMapRule(&filterConfig, ChildId, FALSE, pRuleEntry->ID);
//							goto out;
//						}
//						pListEntry3 = pListEntry3->Flink;
//					}
//					pListEntry2 = pListEntry2->Flink;
//				}
//				pListEntry1 = pListEntry1->Flink;
//			}
//		out:
//			ArvFreeProcs(&procHead);
//		}*/
//		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
//		ObDereferenceObject(ChildEprocess);
//	}
//	else
//	{
//		ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
//		ArvRemoveProcEx(&filterConfig, ChildId);
//		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
//	}
//	//KeSetEvent(
//	//	&Event,               //被激活的事件
//	//	IO_NO_INCREMENT,      //被唤醒线程临时提升线程优先级的增量,传0
//	//	TRUE);
//	//PsTerminateSystemThread(STATUS_SUCCESS);
//}

// 监控进程创建回调函数
VOID CreateProcessNotify(IN HANDLE  ParentId, IN HANDLE  ChildId, IN BOOLEAN  Create)
{
	PEPROCESS ParentEprocess = NULL;
	PEPROCESS ChildEprocess = NULL;
	PProcessFlag pPFlag = NULL;
	PProcessFlag pGFlag = NULL;
	NTSTATUS status;
	if (Create)
	{
		status = PsLookupProcessByProcessId(ChildId, &ChildEprocess);
		if (!NT_SUCCESS(status))
		{
			DbgPrint(("Get Eprocess Failed\n"));
			goto EXIT;
		}
		PSTR cProcName = PsGetProcessImageFileName(ChildEprocess);
		BOOL inherit = FALSE;
		UINT ruleID = 0;
		ExEnterCriticalRegionAndAcquireResourceShared(&HashResource);
		PRegProcEntry entry = ArvGetRegProcEntryByRegProcName(&filterConfig, cProcName);
		if (entry != NULL)
		{
			inherit = entry->Inherit;
			ruleID = entry->RuleID;
		}
		ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
		if (entry != NULL)
		{
			ArvProcessFlagAdd(&processFlags, ChildId, inherit, ruleID);
		}
		else
		{
			HANDLE GrandID = 0;
			BOOL flag = FALSE;
			status = PsLookupProcessByProcessId(ParentId, &ParentEprocess);
			if (!NT_SUCCESS(status))
			{
				DbgPrint(("Get parent process Failed\n"));
			}
			else
			{
				GrandID = (HANDLE)PsGetProcessInheritedFromUniqueProcessId(ParentEprocess);
			}
			if (ParentId != 0)
			{
				pPFlag = ArvProcessFlagFind(&processFlags, (UINT)ParentId);
				if (pPFlag)
				{
					if (pPFlag->Inherit)
					{
						ArvProcessFlagAdd(&processFlags, ChildId, FALSE, pPFlag->RuleID);
					}
				}
			}
			if (GrandID != 0)
			{
				pGFlag = ArvProcessFlagFind(&processFlags, (UINT)GrandID);
				if (pGFlag)
				{
					if (pGFlag->Inherit)
					{
						ArvProcessFlagAdd(&processFlags, ChildId, FALSE, pGFlag->RuleID);
					}
				}
			}
		}
	}
	else
	{
		ArvProcessFlagDelete(&processFlags, ChildId);
	}
EXIT:
	if (ParentEprocess)
	{
		ObDereferenceObject(ParentEprocess);
	}
	if (ChildEprocess)
	{
		ObDereferenceObject(ChildEprocess);
	}
	if (pPFlag)
	{
		ExFreePoolWithTag(pPFlag, 'pcft');
		pPFlag = NULL;
	}
	if (pGFlag)
	{
		ExFreePoolWithTag(pGFlag, 'pcft');
		pGFlag = NULL;
	}
	

	//NTSTATUS Status = 0;
	//ParamData data;
	//data.ParentID = ParentId;
	//data.ChildID = ChildId;
	//data.Create = Create;

	//KEVENT Event;

	//KeInitializeEvent(&Event, NotificationEvent, FALSE);

	//Status = ArvDoCompletionProcessingWhenSafe(
	//	(PVOID)CreateProcessNotifyWhenSafe,
	//	&data,
	//	&Event);

	//if (!NT_SUCCESS(Status))
	//{
	//	ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES,
	//		("%s->ArvDoCompletionProcessingWhenSafe failed. Status = 0x%x.\n", __FUNCTION__, Status));
	//}
	//else
	//{
	//	KeWaitForSingleObject(
	//		&Event,      //同步对象的指针，
	//		Executive,   //等待的原因，一般为Executive
	//		KernelMode,  //等待模式，一般为KernelMode
	//		FALSE,       //指明等待是否为“警惕”的，一般为FALSE
	//		NULL);
	//}
}

NTSTATUS FLTAPI InstanceFilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	//
	// This is called before a filter is unloaded.
	// If NULL is specified for this routine, then the filter can never be unloaded.
	//
	UNREFERENCED_PARAMETER(Flags);
	//ArvCleanLog();
	if (!AllowUnload)
	{
		return STATUS_FLT_DO_NOT_DETACH;
	}
	if (NULL != gServerPort) {
		FltCloseCommunicationPort(gServerPort);
	}
	ArvCleanLog();
	if (NULL != g_minifilterHandle) {
		FltUnregisterFilter(g_minifilterHandle);
	}
	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
	ExEnterCriticalRegionAndAcquireResourceExclusive(&HashResource);
	ArvFreeRegProcs(&filterConfig);
	ArvFreeRules(&filterConfig);
	ExReleaseResourceAndLeaveCriticalRegion(&HashResource);
	ExDeleteResourceLite(&HashResource);
	//FreeAllowedProcs();
	if (NULL != gDeviceObject)
	{
		if (NULL != gDeviceObject->DeviceExtension)
			KeCancelTimer(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer);

		if (NULL != gDeviceObject->DeviceExtension)
			IoFreeWorkItem(((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem);

		IoDeleteDevice(gDeviceObject);
	}
	ArvProcessFlagRelease(&processFlags);
	//WPP_CLEANUP(pDriverObject);
	//CleanFilterPaths();
	ArvSysPathFilterRulesRelease(&SystemFilterRules);
	CleanFilterConfig();
	ArvDeleteLogResource();
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
		PreOperationSetInfo,
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
	/*pDriverObject = DriverObject;
	WPP_INIT_TRACING(DriverObject, RegistryPath);
	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry,RegPath: %wZ", RegistryPath);*/
	ArvInitLog(NULL);
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

		/*status = InitProcessList();
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:register]find all existed processes: %d\n", status);
			__leave;
		}*/
		ArvProcessFlagInit(&processFlags);
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

		/*status = InitFilterPaths();
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:register]read by-pass paths from registry failed: %d\n", status);
			__leave;
		}*/
		status = ArvSysPathFilterRulesInit(&SystemFilterRules);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:register]read by-pass paths from registry failed: %d\n", status);
			__leave;
		}
		InitFilterConfig();

		////Test
		//UNICODE_STRING FullPath = { 0 };
		//RtlInitUnicodeString(&FullPath, L"C:\\Users\\Public\\123.txt");
		//BOOLEAN bTest = ArvSysPathFilterRulesIfMatch(&SystemFilterRules, 4, "explorer.exe", 1, 2, &FullPath);
		////Test

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

		/*status = ArvInitLog(g_minifilterHandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[FsFilter:start]start log writer failed: %d\n", status);
			__leave;
		}*/
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
			ArvProcessFlagRelease(&processFlags);
		}
	}



	/*PProcessFlag pflag = (PProcessFlag)ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcessFlag), 'pcfg');
	pflag->Pid = 2;
	pflag->Inherit = TRUE;
	HASH_ADD_INT(processFlags, Pid, pflag);
	PProcessFlag pflag2;
	INT id2 = 2;
	HASH_FIND_INT(processFlags, &id2, pflag2);
	if (pflag2)
	{
		HASH_DEL(processFlags, pflag2);
		ExFreePoolWithTag(pflag2, 'pcfg');
	}
	PProcessFlag pflag3;
	INT id3 = 3;
	HASH_FIND_INT(processFlags, &id3, pflag3);
	if (pflag3)
	{
		HASH_DEL(processFlags, pflag3);
		ExFreePoolWithTag(pflag3, 'pcfg');
	}*/

	return status;
}
