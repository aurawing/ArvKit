/*++

Module Name:

    ArvFilter.c

Abstract:

    This is the main module of the ArvFilter miniFilter driver.

Environment:

    Kernel mode

--*/
#include "pch.h"

#define MINI_PORT_NAME L"\\ArvCommPort"

NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);

typedef enum _OP_COMMAND {  //操作命令
	SET_PROC,
	SET_RULES,
	GET_STAT,
	SET_DB_CONF,
} OpCommand;

typedef struct _OpGetStat { //获取统计信息
	OpCommand command;
} OpGetStat, *POpGetStat;

typedef struct _OpSetProc { //操作数据
	OpCommand command;
	ULONG procID;
	UINT ruleID;
	//wchar_t **pathnames;
	//UINT pathlen;
} OpSetProc, *POpSetProc;

typedef struct _OpRule {
	UINT id;
	PWSTR pubKey;
	PZPWSTR paths;
	BOOL *isDB;
	UINT pathsLen;
} OpRule, *POpRule;

typedef struct _OpSetRules { //操作数据
	OpCommand command;
	ULONG controlProcID;
	POpRule *rules;
	UINT		ruleLen;
} OpSetRules, *POpSetRules;

typedef struct _OpSetDBConf { //设置DB路径
	OpCommand command;
	UINT id;
	PWSTR path;
} OpSetDBConf, *POpSetDBConf;

typedef struct _RepStat { //返回统计信息
	//BYTE SHA256[SHA256_BLOCK_SIZE];
	ULONGLONG KeyCount;
	ULONGLONG Pass;
	ULONGLONG Block;
	ULONGLONG PassDB;
	ULONGLONG BlockDB;
	ULONGLONG Read;
	ULONGLONG Write;
	ULONGLONG ReadDB;
	ULONGLONG WriteDB;
} RepStat, *PRepStat;

PFLT_PORT     gServerPort;//服务端口
PFLT_PORT     gClientPort;//客户端口
//unsigned long procID; //过滤进程ID
//LIST_ENTRY pathListHeader = { 0 }; //过滤数据盘路径
FilterConfig filterConfig = { 0 };
ERESOURCE HashResource = { 0 };
ULONG controlProcID = 0;


PFLT_FILTER g_minifilterHandle = NULL;
//PDEVICE_OBJECT g_cdo = NULL;
//static const GUID SLBKGUID_CLASS_MYCDO = { 0x06A16B65, 0x7DA0, 0x4A3F, { 0x9D, 0x9A, 0x26, 0x79, 0x39, 0x5D, 0x0D, 0x93 } };

//输入\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Buffer注意要释放
/*把符号链接转换成设备名 可以通过API直接转换*/
NTSTATUS QuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
)
{
	OBJECT_ATTRIBUTES	oa = { 0 };
	NTSTATUS			status = 0;
	HANDLE				handle = NULL;

	InitializeObjectAttributes(
		&oa,
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE,
		0,
		0);

	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	LinkTarget->MaximumLength = MAX_PATH * sizeof(WCHAR);
	LinkTarget->Length = 0;

	//分配的内存需要释放
	LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, 'SOD');
	if (!LinkTarget->Buffer)
	{
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(LinkTarget->Buffer);
	}

	return status;
}

//输入\\Device\\harddiskvolume1
//输出C:
//DosName.Buffer的内存记得释放
/*设备名转换成符号链接 不能直接转换  思路是吧a-z盘的符号链接名转换成设备名 与提供的设备名相比较 如果一样 那就找到了对应的盘符*/
NTSTATUS
MyRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
)

/*++

Routine Description:

This routine returns a valid DOS path for the given device object.
This caller of this routine must call ExFreePool on DosName->Buffer
when it is no longer needed.

Arguments:

VolumeDeviceObject - Supplies the volume device object.
DosName - Returns the DOS name for the volume
Return Value:

NTSTATUS

--*/

{
	NTSTATUS				status = 0;
	UNICODE_STRING			driveLetterName = { 0 };
	WCHAR					driveLetterNameBuf[128] = { 0 };
	WCHAR					c = L'\0';
	WCHAR					DriLetter[3] = { 0 };
	UNICODE_STRING			linkTarget = { 0 };

	for (c = L'A'; c <= L'Z'; c++)
	{
		RtlInitEmptyUnicodeString(&driveLetterName, driveLetterNameBuf, sizeof(driveLetterNameBuf));
		RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
		DriLetter[0] = c;
		DriLetter[1] = L':';
		DriLetter[2] = 0;
		RtlAppendUnicodeToString(&driveLetterName, DriLetter);

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE))
		{
			ExFreePool(linkTarget.Buffer);
			break;
		}

		ExFreePool(linkTarget.Buffer);
	}

	if (c <= L'Z')
	{
		DosName->Buffer = ExAllocatePoolWithTag(PagedPool, 3 * sizeof(WCHAR), 'SOD');
		if (!DosName->Buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DosName->MaximumLength = 6;
		DosName->Length = 4;
		*DosName->Buffer = c;
		*(DosName->Buffer + 1) = ':';
		*(DosName->Buffer + 2) = 0;

		return STATUS_SUCCESS;
	}

	return status;
}

//c:\\windows\\hi.txt<--\\device\\harddiskvolume1\\windows\\hi.txt
/*完整的路径转换为设备名*/
BOOL NTAPI GetNTLinkName(IN WCHAR * wszNTName, OUT WCHAR * wszFileName)
{
	UNICODE_STRING		ustrFileName = { 0 };
	UNICODE_STRING		ustrDosName = { 0 };
	UNICODE_STRING		ustrDeviceName = { 0 };

	WCHAR				*pPath = NULL;
	ULONG				i = 0;
	ULONG				ulSepNum = 0;


	if (wszFileName == NULL ||
		wszNTName == NULL ||
		_wcsnicmp(wszNTName, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume")) != 0)
	{
		return FALSE;
	}

	ustrFileName.Buffer = wszFileName;
	ustrFileName.Length = 0;
	ustrFileName.MaximumLength = sizeof(WCHAR)*MAX_PATH;

	while (wszNTName[i] != L'\0')
	{

		if (wszNTName[i] == L'\0')
		{
			break;
		}
		if (wszNTName[i] == L'\\')
		{
			ulSepNum++;
		}
		if (ulSepNum == 3)
		{
			wszNTName[i] = UNICODE_NULL;
			pPath = &wszNTName[i + 1];
			break;
		}
		i++;
	}

	if (pPath == NULL)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&ustrDeviceName, wszNTName);

	if (!NT_SUCCESS(MyRtlVolumeDeviceToDosName(&ustrDeviceName, &ustrDosName)))
	{
		return FALSE;
	}

	RtlCopyUnicodeString(&ustrFileName, &ustrDosName);
	RtlAppendUnicodeToString(&ustrFileName, L"\\");
	RtlAppendUnicodeToString(&ustrFileName, pPath);

	ExFreePool(ustrDosName.Buffer);

	return TRUE;
}

BOOL QueryVolumeName(WCHAR ch, WCHAR * name, USHORT size)
{
	WCHAR szVolume[7] = L"\\??\\C:";
	UNICODE_STRING LinkName;
	UNICODE_STRING VolName;
	UNICODE_STRING ustrTarget;
	NTSTATUS ntStatus = 0;

	RtlInitUnicodeString(&LinkName, szVolume);

	szVolume[4] = ch;

	ustrTarget.Buffer = name;
	ustrTarget.Length = 0;
	ustrTarget.MaximumLength = size;

	ntStatus = QuerySymbolicLink(&LinkName, &VolName);
	if (NT_SUCCESS(ntStatus))
	{
		RtlCopyUnicodeString(&ustrTarget, &VolName);
		ExFreePool(VolName.Buffer);
	}
	return NT_SUCCESS(ntStatus);

}

//\\??\\c:\\windows\\hi.txt-->\\device\\harddiskvolume1\\windows\\hi.txt
/*符号链接全路径转换成设备链接全路径*/
BOOL NTAPI GetNtDeviceName(IN WCHAR * filename, OUT WCHAR * ntname)
{
	UNICODE_STRING uVolName = { 0,0,0 };
	WCHAR volName[MAX_PATH] = L"";
	WCHAR tmpName[MAX_PATH] = L"";
	WCHAR chVol = L'\0';
	WCHAR * pPath = NULL;
	int i = 0;


	RtlStringCbCopyW(tmpName, MAX_PATH * sizeof(WCHAR), filename);

	for (i = 1; i < MAX_PATH - 1; i++)
	{
		if (tmpName[i] == L':')
		{
			pPath = &tmpName[(i + 1) % MAX_PATH];
			chVol = tmpName[i - 1];
			break;
		}
	}

	if (pPath == NULL)
	{
		return FALSE;
	}

	if (chVol == L'?')
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, L"\\Device\\HarddiskVolume?");
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}
	else if (QueryVolumeName(chVol, volName, MAX_PATH * sizeof(WCHAR)))
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, volName);
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}

	return FALSE;
}

/* 输入\\Device\\harddiskvolume1\\1.TXT
   输出C:\\1.TXT
   DosName.Buffer的内存记得释放
   设备名转换成符号链接 不能直接转换  思路是吧a-z盘的符号链接名转换成设备名 与提供的设备名相比较 如果一样 那就找到了对应的盘符
*/
NTSTATUS
MyFullRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
)

/*++

Routine Description:

This routine returns a valid DOS path for the given device object.
This caller of this routine must call ExFreePool on DosName->Buffer
when it is no longer needed.

Arguments:

VolumeDeviceObject - Supplies the volume device object.
DosName - Returns the DOS name for the volume
Return Value:

NTSTATUS

--*/

{
	NTSTATUS				status = 0;
	UNICODE_STRING			driveLetterName = { 0 };
	WCHAR					driveLetterNameBuf[128] = { 0 };
	WCHAR					c = L'\0';
	WCHAR					DriLetter[3] = { 0 };
	UNICODE_STRING			linkTarget = { 0 };

	for (c = L'A'; c <= L'Z'; c++)
	{
		RtlInitEmptyUnicodeString(&driveLetterName, driveLetterNameBuf, sizeof(driveLetterNameBuf));
		RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
		DriLetter[0] = c;
		DriLetter[1] = L':';
		DriLetter[2] = 0;
		RtlAppendUnicodeToString(&driveLetterName, DriLetter);

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		if (wcsstr(DeviceName->Buffer, linkTarget.Buffer))
		{
			ExFreePool(linkTarget.Buffer);
			break;
		}

		ExFreePool(linkTarget.Buffer);
	}


	if (c <= L'Z')
	{
		DosName->Buffer = ExAllocatePoolWithTag(PagedPool, DeviceName->Length * sizeof(WCHAR), 'SOD');

		if (!DosName->Buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(DosName->Buffer, DeviceName->Length * sizeof(WCHAR));

		DosName->MaximumLength = DeviceName->Length * sizeof(WCHAR);
		DosName->Length = DeviceName->Length * sizeof(WCHAR) - 2;
		*DosName->Buffer = c;
		*(DosName->Buffer + 1) = ':';
		*(DosName->Buffer + 2) = 0;

		//+23
		RtlCopyMemory(DosName->Buffer + 2, DeviceName->Buffer + 23, DeviceName->Length - 23);
		return STATUS_SUCCESS;
	}

	return status;
}

// 获取全部父进程ID
VOID FindAncestorProcessID(ULONG processID, PLIST_ENTRY pProcHead)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	while (TRUE)
	{
		ArvAddProc(pProcHead, processID);
		status = PsLookupProcessByProcessId((HANDLE)processID, &pProcess);
		if (!NT_SUCCESS(status))
		{
			break;
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
	return FALSE; // strcmp(pStrProcessName, "smartscreen.exe") == 0 || strcmp(pStrProcessName, "smartscreen.ex") == 0;
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

NTSTATUS
CtxCreateStreamContext(
	_Outptr_ PCTX_STREAM_CONTEXT *StreamContext
)
/*++

Routine Description:

	This routine creates a new stream context

Arguments:

	StreamContext         - Returns the stream context

Return Value:

	Status

--*/
{
	NTSTATUS status;
	PCTX_STREAM_CONTEXT streamContext;

	PAGED_CODE();

	//
	//  Allocate a stream context
	//

	DbgPrint("[Ctx]: Allocating stream context \n");

	status = FltAllocateContext(g_minifilterHandle,
		FLT_STREAM_CONTEXT,
		CTX_STREAM_CONTEXT_SIZE,
		PagedPool,
		&streamContext);

	if (!NT_SUCCESS(status)) {

		DbgPrint("[Ctx]: Failed to allocate stream context with status 0x%x \n",
			status);
		return status;
	}

	//
	//  Initialize the newly created context
	//

	RtlZeroMemory(streamContext, CTX_STREAM_CONTEXT_SIZE);

	streamContext->Resource = CtxAllocateResource();
	if (streamContext->Resource == NULL) {

		FltReleaseContext(streamContext);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	ExInitializeResourceLite(streamContext->Resource);

	*StreamContext = streamContext;

	return STATUS_SUCCESS;
}

NTSTATUS
CtxFindOrCreateStreamContext(
	_In_ PFLT_CALLBACK_DATA Cbd,
	_In_ BOOLEAN CreateIfNotFound,
	_Outptr_ PCTX_STREAM_CONTEXT *StreamContext,
	_Out_opt_ PBOOLEAN ContextCreated
)
/*++

Routine Description:

	This routine finds the stream context for the target stream.
	Optionally, if the context does not exist this routing creates
	a new one and attaches the context to the stream.

Arguments:

	Cbd                   - Supplies a pointer to the callbackData which
							declares the requested operation.
	CreateIfNotFound      - Supplies if the stream must be created if missing
	StreamContext         - Returns the stream context
	ContextCreated        - Returns if a new context was created

Return Value:

	Status

--*/
{
	NTSTATUS status;
	PCTX_STREAM_CONTEXT streamContext;
	PCTX_STREAM_CONTEXT oldStreamContext;

	PAGED_CODE();

	*StreamContext = NULL;
	if (ContextCreated != NULL) *ContextCreated = FALSE;

	//
	//  First try to get the stream context.
	//

	DbgPrint("[Ctx]: Trying to get stream context (FileObject = %p, Instance = %p)\n",
		Cbd->Iopb->TargetFileObject,
		Cbd->Iopb->TargetInstance);

	status = FltGetStreamContext(Cbd->Iopb->TargetInstance,
		Cbd->Iopb->TargetFileObject,
		&streamContext);

	//
	//  If the call failed because the context does not exist
	//  and the user wants to creat a new one, the create a
	//  new context
	//

	if (!NT_SUCCESS(status) &&
		(status == STATUS_NOT_FOUND) &&
		CreateIfNotFound) {


		//
		//  Create a stream context
		//

		DbgPrint("[Ctx]: Creating stream context (FileObject = %p, Instance = %p)\n",
			Cbd->Iopb->TargetFileObject,
			Cbd->Iopb->TargetInstance);

		status = CtxCreateStreamContext(&streamContext);

		if (!NT_SUCCESS(status)) {

			DbgPrint("[Ctx]: Failed to create stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
				status,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);

			return status;
		}


		//
		//  Set the new context we just allocated on the file object
		//

		DbgPrint("[Ctx]: Setting stream context %p (FileObject = %p, Instance = %p)\n",
			streamContext,
			Cbd->Iopb->TargetFileObject,
			Cbd->Iopb->TargetInstance);

		status = FltSetStreamContext(Cbd->Iopb->TargetInstance,
			Cbd->Iopb->TargetFileObject,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			streamContext,
			&oldStreamContext);

		if (!NT_SUCCESS(status)) {

			DbgPrint("[Ctx]: Failed to set stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
				status,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);
			//
			//  We release the context here because FltSetStreamContext failed
			//
			//  If FltSetStreamContext succeeded then the context will be returned
			//  to the caller. The caller will use the context and then release it
			//  when he is done with the context.
			//

			DbgPrint("[Ctx]: Releasing stream context %p (FileObject = %p, Instance = %p)\n",
				streamContext,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);

			FltReleaseContext(streamContext);

			if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

				//
				//  FltSetStreamContext failed for a reason other than the context already
				//  existing on the stream. So the object now does not have any context set
				//  on it. So we return failure to the caller.
				//

				DbgPrint("[Ctx]: Failed to set stream context with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED. (FileObject = %p, Instance = %p)\n",
					status,
					Cbd->Iopb->TargetFileObject,
					Cbd->Iopb->TargetInstance);

				return status;
			}

			//
			//  Race condition. Someone has set a context after we queried it.
			//  Use the already set context instead
			//

			DbgPrint("[Ctx]: Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
				oldStreamContext,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);

			//
			//  Return the existing context. Note that the new context that we allocated has already been
			//  realeased above.
			//

			streamContext = oldStreamContext;
			status = STATUS_SUCCESS;

		}
		else {

			if (ContextCreated != NULL) *ContextCreated = TRUE;
		}
	}

	*StreamContext = streamContext;

	return status;
}

//
//  Support Routines
//

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _In_)
_At_(String->Buffer, _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(String->MaximumLength))
NTSTATUS
CtxAllocateUnicodeString(
	_Out_ PUNICODE_STRING String
)
/*++

Routine Description:

	This routine allocates a unicode string

Arguments:

	String - supplies the size of the string to be allocated in the MaximumLength field
			 return the unicode string

Return Value:

	STATUS_SUCCESS                  - success
	STATUS_INSUFFICIENT_RESOURCES   - failure

--*/
{
	PAGED_CODE();

	String->Buffer = ExAllocatePoolWithTag(PagedPool,
		String->MaximumLength,
		CTX_STRING_TAG);

	if (String->Buffer == NULL) {

		DbgPrint("[Ctx]: Failed to allocate unicode string of size 0x%x\n",
			String->MaximumLength);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	String->Length = 0;

	return STATUS_SUCCESS;
}

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _Out_range_(== , 0))
_At_(String->Buffer, _Pre_notnull_ _Post_null_)
VOID
CtxFreeUnicodeString(
	_Pre_notnull_ PUNICODE_STRING String
)
/*++

Routine Description:

	This routine frees a unicode string

Arguments:

	String - supplies the string to be freed

Return Value:

	None

--*/
{
	PAGED_CODE();

	ExFreePoolWithTag(String->Buffer,
		CTX_STRING_TAG);

	String->Length = String->MaximumLength = 0;
	String->Buffer = NULL;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	PCTX_STREAM_CONTEXT streamContext = NULL;
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
	PCTX_STREAM_CONTEXT streamContext = NULL;
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
	if (controlProcID == 0) {
		return status;
	}
	if (FltObjects->FileObject == NULL) {
		return status;
	}
	PFLT_FILE_NAME_INFORMATION nameInfo;
	UNICODE_STRING fullPath = { 0 };
	UNICODE_STRING dosName = { 0 };
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return status;
	}
	USHORT fileNameLen = Data->Iopb->TargetFileObject->FileName.Length;
	if (fileNameLen == 0)
	{
		return status;
	}
	ULONG procID = FltGetRequestorProcessId(Data);
	if (procID == controlProcID) // || ProcAllowed(procID))
	{
		return status;
	}
	//check processname
	PEPROCESS pCallerProcess = NULL;
	char *callerProcessName = "";
	//NTSTATUS ntStatus3 = PsLookupProcessByProcessId((HANDLE)procID, &pCallerProcess);
	//if (NT_SUCCESS(ntStatus3))
	//{
	//	callerProcessName = PsGetProcessImageFileName(pCallerProcess);
	//	ObDereferenceObject(pCallerProcess);
	//}

	WCHAR SystemRoot[] = { 'C', ':', '\\' };
	WCHAR LoginPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'i', 'n', '?', '\\' };
	WCHAR LogoutPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'o', 't', '?', '\\' };
	//PEPROCESS pProcess = NULL;
	//NTSTATUS status2 = STATUS_SUCCESS;

	//PEPROCESS pProcess = NULL;
	//status = PsLookupProcessByProcessId((HANDLE)procID, &pProcess);
	//if (status == STATUS_SUCCESS)
	//{
	//	//char *processName = (char*)pProcess + 0x174;
	//	char *processName = PsGetProcessImageFileName(pProcess);
	//	DbgPrint("[FsFilter:create]%s - %wZ\n", processName, &Data->Iopb->TargetFileObject->FileName);
	//	if (procID == 4 ||
	//		strcmp(processName, "Registry") == 0 ||
	//		strcmp(processName, "smss.exe") == 0 ||
	//		strcmp(processName, "csrss.exe") == 0 ||
	//		strcmp(processName, "smss.exe") == 0)
	//	{

	//	}
	//	ObDereferenceObject(pProcess);
	//}
	//else
	//{
	//	DbgPrint("[FsFilter:create]%d - %wZ\n", procID, &Data->Iopb->TargetFileObject->FileName);
	//}
	if ((Data->Iopb->TargetFileObject->FileName.Length > 15 * sizeof(wchar_t)) &&
		(memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LoginPath, 15 * sizeof(wchar_t)) == 0 || memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LogoutPath, 15 * sizeof(wchar_t)) == 0) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[fileNameLen / sizeof(wchar_t) - 1] == L'\\')
		)
	{
		PSTR logintag = (PSTR)ExAllocatePoolWithTag(PagedPool, fileNameLen, 'LGI');
		RtlZeroMemory(logintag, fileNameLen);
		int b = 0;
		PSTR keyidstr = NULL;
		PSTR timestr = NULL;
		PSTR sigstr = NULL;
		bool isWChar = false;
		int bPoint[3];
		for (UINT a = 0; a < fileNameLen / sizeof(wchar_t); a++)
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
					sigstr = &logintag[a + 1];
				}
				b++;
			}
		}
		if (isWChar || keyidstr == NULL || timestr == NULL || sigstr == NULL)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			return FLT_PREOP_COMPLETE;
		}
		int keyid = atoi(keyidstr);
		if (keyid == 0)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			return FLT_PREOP_COMPLETE;
		}

		LONG timeBaseLine = (LONG)ArvGetUnixTimestamp();
		LONG timeparam = atol(timestr);
		if (timeBaseLine == 0 || timeparam == 0 || (timeBaseLine - timeparam) > 10 || (timeBaseLine - timeparam) < -10)
		{
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
			return FLT_PREOP_COMPLETE;
		}

		ExAcquireResourceSharedLite(&HashResource, TRUE);
		PUNICODE_STRING wPubKey = ArvGetPubKeyByRuleID(&filterConfig, keyid);
		if (wPubKey == NULL)
		{
			ExReleaseResourceLite(&HashResource);
			Data->IoStatus.Status = STATUS_ILLEGAL_INSTRUCTION;
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(logintag, 'LGI');
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
			ExReleaseResourceLite(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		for (UINT d = 0; d < 3; d++)
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
			ExReleaseResourceLite(&HashResource);
			return FLT_PREOP_COMPLETE;
		}
		ExReleaseResourceLite(&HashResource);

		ExAcquireResourceExclusiveLite(&HashResource, TRUE);
		if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LoginPath, 15 * sizeof(wchar_t)) == 0)
		{
			ArvMapRule(&filterConfig, procID, keyid);
		}
		else if (memcmp(Data->Iopb->TargetFileObject->FileName.Buffer, LogoutPath, 15 * sizeof(wchar_t)) == 0)
		{
			ArvRemoveProc(&filterConfig, procID, keyid);
		}
		ExReleaseResourceLite(&HashResource);
		ExFreePoolWithTag(logintag, 'LGI');
		ExFreePoolWithTag(pubKey, 'LGI');
		return FLT_PREOP_COMPLETE;
	}

	//FILE_BASIC_INFORMATION basicInfo;

	//status = FltQueryInformationFile(FltObjects->Instance,
	//	FltObjects->FileObject,
	//	&basicInfo,
	//	sizeof(FILE_BASIC_INFORMATION),
	//	FileBasicInformation,
	//	NULL);

	//if (NT_SUCCESS(status)) {
	//	if ((basicInfo.FileAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM)
	//	{
	//		DbgPrint("[FsFilter:create]filtering system file: %d - %wZ\n", procID, &Data->Iopb->TargetFileObject->FileName);
	//		if (procID != 4)
	//		{
	//			return FLT_PREOP_COMPLETE;
	//		}
	//	}
	//}
	//else
	//{
	//	DbgPrint("[FsFilter:create]filtering system file failed: %d - %wZ\n", procID, &Data->Iopb->TargetFileObject->FileName);
	//	//return FLT_PREOP_COMPLETE;;
	//}

	ExAcquireResourceSharedLite(&HashResource, TRUE);
	if (filterConfig.Rules.Flink == &filterConfig.Rules)
	{
		ExReleaseResourceLite(&HashResource);
		if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION && status != FLT_PREOP_COMPLETE)
		{
			status = FLT_PREOP_SYNCHRONIZE;
		}
		return status;
	}
	__try
	{
		status2 = PsLookupProcessByProcessId((HANDLE)procID, &pCallerProcess);
		if (status2 == STATUS_SUCCESS)
		{
			callerProcessName = PsGetProcessImageFileName(pCallerProcess);
		}

		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
		if (NT_SUCCESS(status))
		{
			status = FltParseFileNameInformation(nameInfo);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[FsFilter:create]Parse file name failed\n");
			}
			else
			{
				/*UNICODE_STRING vol;
				RtlInitUnicodeString(&vol, L"123.txt");
				if (RtlCompareUnicodeString(&nameInfo->FinalComponent, &vol, TRUE) == 0)
				{
					DbgPrint("[FsFilter:create]process network volume\n");
				}*/
				UNICODE_STRING netVolName;
				RtlInitUnicodeString(&netVolName, L"\\Device\\Mup");
				if ((nameInfo->Volume).Buffer)
				{
					MyRtlVolumeDeviceToDosName(&(nameInfo->Volume), &dosName);
					if (!dosName.Length && RtlCompareUnicodeString(&nameInfo->Volume, &netVolName, TRUE) == 0)
					{
						dosName.Buffer = ExAllocatePoolWithTag(PagedPool, sizeof(WCHAR), 'SOD');
						if (!dosName.Buffer)
						{
							ExReleaseResourceLite(&HashResource);
							ObDereferenceObject(pCallerProcess);
							return STATUS_INSUFFICIENT_RESOURCES;
						}
						dosName.MaximumLength = 2;
						dosName.Length = 2;
						dosName.Buffer[0] = '\\';
					}
					//size_t fullLen = dosName.Length + Data->Iopb->TargetFileObject->FileName.Length;
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
					BOOL underDBPath = FALSE;
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
									if (pPathEntry->isDB)
									{
										underDBPath = TRUE;
									}
									goto out1;
								}
								fullPath.Length = fpLen;
							}
							pListEntry2 = pListEntry2->Flink;
						}
						pListEntry = pListEntry->Flink;
					}

				out1:
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
							PLIST_ENTRY pListEntry2 = pRuleEntry->Procs.Flink;
							while (pListEntry2 != &pRuleEntry->Procs)
							{
								PProcEntry pProcEntry2 = CONTAINING_RECORD(pListEntry2, ProcEntry, entry);
								if (pProcEntry1->ProcID == pProcEntry2->ProcID)
								{
									flag2 = TRUE;
									goto out2;
								}
								pListEntry2 = pListEntry2->Flink;
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
										if (underDBPath)
										{
											InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
										}
									}
									else
									{
										DbgPrint("[FsFilter:create]unallowed process under system device: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
										InterlockedIncrement64(&pPathEntry->stat.blockCounter);
										if (underDBPath)
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
									if (ProcAllowed(procID) || (MatchReadonlyProcess(callerProcessName) && FILE_OPEN == createDisposition))
									{
										DbgPrint("[FsFilter:create]allowed system process(readonly): %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
										InterlockedIncrement64(&pPathEntry->stat.passCounter);
										if (underDBPath)
										{
											InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
										}
									}
									else
									{
										DbgPrint("[FsFilter:create]unallowed process: %d(%s) - %wZ\n", procID, callerProcessName, fullPath);
										InterlockedIncrement64(&pPathEntry->stat.blockCounter);
										if (underDBPath)
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
										if (underDBPath)
										{
											InterlockedIncrement64(&pPathEntry->stat.passCounterDB);
										}
									}
									else
									{
										InterlockedIncrement64(&pPathEntry->stat.blockCounter);
										if (underDBPath)
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
									switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
									case FileDispositionInformation:
									case 64:
										// deleting a file we need to action
										if (((FILE_DISPOSITION_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile) {
											InterlockedIncrement64(&pPathEntry->stat.blockCounter);
											if (underDBPath)
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
										if (underDBPath)
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

							/*ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
							if (FILE_OPEN != createDisposition || !ProcAllowed(procID))
							{
								InterlockedIncrement64(&pPathEntry->stat.blockCounter);
								Data->IoStatus.Status = STATUS_ACCESS_DENIED;
								Data->IoStatus.Information = 0;
								status = FLT_PREOP_COMPLETE;
							}*/
						}
						else
						{
							InterlockedIncrement64(&pPathEntry->stat.passCounter);
							if (underDBPath)
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
								if (pProcEntry4->ProcID == procID)
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
									if (ProcAllowed(procID) || (MatchReadonlyProcess(callerProcessName) && FILE_OPEN == createDisposition))
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
						else
						{
							ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
							if (FILE_OPEN == createDisposition)
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
				else
				{
					DbgPrint("[FsFilter:create]no volume name: %d(%s) - %wZ\n", procID, callerProcessName, nameInfo->Name);
				}
			}
			FltReleaseFileNameInformation(nameInfo);

			//check secretmanager.exe
			/*PEPROCESS pProcess1;
			NTSTATUS ntStatus3 = PsLookupProcessByProcessId((HANDLE)procID, &pProcess1);
			if (NT_SUCCESS(ntStatus3))
			{
				CHAR* pStrProcessName = PsGetProcessImageFileName(pProcess1);
				ObDereferenceObject(pProcess1);
				if (strcmp(pStrProcessName, "secretmanager.exe") == 0)
				{
					ULONG createDisposition3 = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
					DbgPrint("##### secretmanager: %d - %wZ - %d\n", procID, Data->Iopb->TargetFileObject->FileName, createDisposition3);
				}
			}*/
			
		}
		else
		{
			DbgPrint("[FsFilter:create]parse name failed: %d(%s) - %wZ\n", procID, callerProcessName, Data->Iopb->TargetFileObject->FileName);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[FsFilter:create]PreOperationWrite EXCEPTION_EXECUTE_HANDLER: %d(%s) - %wZ - %d\n", procID, callerProcessName, Data->Iopb->TargetFileObject->FileName, GetExceptionCode());
	}
	ExReleaseResourceLite(&HashResource);
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
	/*if (status != FLT_PREOP_COMPLETE)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}*/
	if (Data && Data->Iopb && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION && status != FLT_PREOP_COMPLETE)
	{
		status = FLT_PREOP_SYNCHRONIZE;
	}
	if (status != FLT_PREOP_COMPLETE)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
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
	PCTX_STREAM_CONTEXT streamContext = NULL;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	UNICODE_STRING fullPath = { 0 };
	UNICODE_STRING dosName = { 0 };
	size_t fullLen = 0;

	NTSTATUS status;
	BOOLEAN streamContextCreated;


	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CbdContext);

	PAGED_CODE();

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

	if (!NT_SUCCESS(Cbd->IoStatus.Status)) {

		goto CtxPostCreateCleanup;
	}


	//
	// Get the file name
	//

	status = FltGetFileNameInformation(Cbd,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo);

	if (!NT_SUCCESS(status)) {

		DbgPrint("[Ctx]: CtxPostCreate -> Failed to get name information (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

		goto CtxPostCreateCleanup;
	}

	status = FltParseFileNameInformation(nameInfo);

	if (!NT_SUCCESS(status))
	{

		DbgPrint("[Ctx]: CtxPostCreate -> Failed to parse file name (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

		goto CtxPostCreateCleanup;
	}

	if (!(nameInfo->Volume).Buffer)
	{
		DbgPrint("[Ctx]: CtxPostCreate -> No volume parsed (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

		goto CtxPostCreateCleanup;
	}

	status = MyRtlVolumeDeviceToDosName(&(nameInfo->Volume), &dosName);

	if (!NT_SUCCESS(status))
	{

		DbgPrint("[Ctx]: CtxPostCreate -> Failed to parse volume name (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

		goto CtxPostCreateCleanup;
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
	ExReleaseResourceLite(&HashResource);

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

		goto CtxPostCreateCleanup;
	}

	DbgPrint("[Ctx]: CtxPostCreate -> Getting/Creating stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p. StreamContextCreated = %x)\n",
		&nameInfo->Name,
		Cbd,
		FltObjects->FileObject,
		streamContext,
		streamContextCreated);

	//
	//  Acquire write acccess to the context
	//

	CtxAcquireResourceExclusive(streamContext->Resource);

	//
	//  Increment the create count
	//

	streamContext->UnderDBPath = flag;


	DbgPrint("[Ctx]: CtxPostCreate -> Stream context info for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p)\n",
		&nameInfo->Name,
		Cbd,
		FltObjects->FileObject,
		streamContext);

	//
	//  Relinquish write acccess to the context
	//

	CtxReleaseResource(streamContext->Resource);

	//
	//  Quit on failure after we have given up
	//  the resource
	//

	if (!NT_SUCCESS(status)) {

		DbgPrint("[Ctx]: CtxPostCreate -> Failed to update name in stream context for file %wZ (Cbd = %p, FileObject = %p)\n",
			&nameInfo->Name,
			Cbd,
			FltObjects->FileObject);

		goto CtxPostCreateCleanup;
	}


CtxPostCreateCleanup:


	//
	// Release the references we have acquired
	//    

	if (nameInfo != NULL) {

		FltReleaseFileNameInformation(nameInfo);
	}

	if (streamContext != NULL) {

		FltReleaseContext(streamContext);
	}

	ArvFreeUnicodeString(&dosName, 'SOD');
	ArvFreeUnicodeString(&fullPath, 'POC');

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
	PCTX_STREAM_CONTEXT streamContext = NULL;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	UNICODE_STRING fullPath = { 0 };
	UNICODE_STRING dosName = { 0 };
	size_t fullLen = 0;

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

	status = FltGetFileNameInformation(Cbd,
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
	ExReleaseResourceLite(&HashResource);


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

	DbgPrint("[Ctx]: CtxPostSetInfo -> Getting stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p. StreamContextCreated = %x)\n",
			&nameInfo->Name,
			Cbd,
			FltObjects->FileObject,
			streamContext,
			streamContextCreated);

	//
	//  Acquire write acccess to the context
	//

	CtxAcquireResourceExclusive(streamContext->Resource);

	streamContext->UnderDBPath = flag;

	DbgPrint("[Ctx]: CtxPostSetInfo -> Old info in stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p)\n",
			&nameInfo->Name,
			Cbd,
			FltObjects->FileObject,
			streamContext);


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

	if (nameInfo != NULL) {

		FltReleaseFileNameInformation(nameInfo);
	}

	ArvFreeUnicodeString(&dosName, 'SOD');
	ArvFreeUnicodeString(&fullPath, 'POC');

	DbgPrint("[Ctx]: CtxPostSetInfo -> Exit (Cbd = %p, FileObject = %p)\n",
			Cbd,
			FltObjects->FileObject);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS FLTAPI InstanceFilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	//
	// This is called before a filter is unloaded.
	// If NULL is specified for this routine, then the filter can never be unloaded.
	//
	UNREFERENCED_PARAMETER(Flags);
	if (NULL != gServerPort) {
		FltCloseCommunicationPort(gServerPort);
	}
	if (NULL != g_minifilterHandle) {
		FltUnregisterFilter(g_minifilterHandle);
	}
	ExAcquireResourceExclusiveLite(&HashResource, TRUE);
	ArvFreeRules(&filterConfig);
	ExReleaseResourceLite(&HashResource);
	ExDeleteResourceLite(&HashResource);
	FreeAllowedProcs();
	return STATUS_SUCCESS;
}

NTSTATUS FLTAPI InstanceSetupCallback(
	_In_ PCFLT_RELATED_OBJECTS  FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
	_In_ DEVICE_TYPE  VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{
	//
	// This is called to see if a filter would like to attach an instance to the given volume.
	//
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);
	return STATUS_SUCCESS;
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

VOID
CtxContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	PCTX_STREAM_CONTEXT streamContext;

	PAGED_CODE();

	switch (ContextType) {

	case FLT_STREAM_CONTEXT:

		streamContext = (PCTX_STREAM_CONTEXT)Context;

		DbgPrint("[Ctx]: Cleaning up stream context %p: %d\n",
				streamContext, 
				&streamContext->UnderDBPath);

		//
		//  Delete the resource and memory the memory allocated for the resource
		//

		if (streamContext->Resource != NULL) {

			ExDeleteResourceLite(streamContext->Resource);
			CtxFreeResource(streamContext->Resource);
		}

		if (streamContext->UnderDBPath ) {

			streamContext->UnderDBPath = FALSE;
		}

		DbgPrint("[Ctx]: Stream context cleanup complete.\n");

		break;

	}

}

//
	// Constant FLT_REGISTRATION structure for our filter.
	// This initializes the callback routines our filter wants to register for.
	//
FLT_OPERATION_REGISTRATION g_callbacks[] =
{
	{
		IRP_MJ_CREATE,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreOperationCreate,
		PostOperationCreate
	},
	{
		IRP_MJ_READ,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreOperationRead,
		0
	},
	{
		IRP_MJ_WRITE,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreOperationWrite,
		0
	},
	{ 
		IRP_MJ_SET_INFORMATION,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreOperationCreate,
		PostOperationSetInfo
	},
	{ IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAM_CONTEXT,
	  0,
	  CtxContextCleanup,
	  CTX_STREAM_CONTEXT_SIZE,
	  CTX_STREAM_CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};


//
// The FLT_REGISTRATION structure provides information about a file system minifilter to the filter manager.
//
CONST FLT_REGISTRATION g_filterRegistration =
{
	sizeof(FLT_REGISTRATION),      //  Size
	FLT_REGISTRATION_VERSION,      //  Version
	0,                             //  Flags
	ContextRegistration,           //  Context registration
	g_callbacks,                   //  Operation callbacks
	InstanceFilterUnloadCallback,  //  FilterUnload
	InstanceSetupCallback,         //  InstanceSetup
	InstanceQueryTeardownCallback, //  InstanceQueryTeardown
	NULL,                          //  InstanceTeardownStart
	NULL,                          //  InstanceTeardownComplete
	NULL,                          //  GenerateFileName
	NULL,                          //  GenerateDestinationFileName
	NULL                           //  NormalizeNameComponent
};

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
		OpCommand command;
		try {
			command = ((POpGetStat)InputBuffer)->command;
			switch (command)
			{
			case SET_PROC:
				pOpSetProc = (OpSetProc*)InputBuffer;
				ExAcquireResourceExclusiveLite(&HashResource, TRUE);
				BOOL ret = ArvMapRule(&filterConfig, pOpSetProc->procID, pOpSetProc->ruleID);
				ExReleaseResourceLite(&HashResource);
				DbgPrint("[FsFilter:MiniMessage]add procID %d: %d - %d\n", ret, pOpSetProc->procID, pOpSetProc->ruleID);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			case SET_RULES:
				ExAcquireResourceExclusiveLite(&HashResource, TRUE);
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
								ArvAddProc(&newRuleEntry->Procs, ppe->ProcID);
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
				filterConfig = tmpConfig;
				tmpConfig.Rules.Blink->Flink = &filterConfig.Rules;
				tmpConfig.Rules.Flink->Blink = &filterConfig.Rules;
				ExReleaseResourceLite(&HashResource);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			case SET_DB_CONF:
				pOpSetDBConf = (OpSetDBConf*)InputBuffer;
				ExAcquireResourceExclusiveLite(&HashResource, TRUE);
				BOOL ret2 = ArvSetDBConf(&filterConfig, pOpSetDBConf->id, pOpSetDBConf->path);
				ExReleaseResourceLite(&HashResource);
				DbgPrint("[FsFilter:MiniMessage]set DB conf %d: %d - %ws\n", ret2, pOpSetDBConf->id, pOpSetDBConf->path);
				*ReturnOutputBufferLength = (ULONG)sizeof(buffer);
				RtlCopyMemory(OutputBuffer, buffer, *ReturnOutputBufferLength);
				break;
			case GET_STAT:
				ExAcquireResourceSharedLite(&HashResource, TRUE);
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
				ExReleaseResourceLite(&HashResource);
				*ReturnOutputBufferLength = (ULONG)sizeof(RepStat);
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
			ExDeleteResourceLite(&HashResource);
		}
	}
	return status;
}
