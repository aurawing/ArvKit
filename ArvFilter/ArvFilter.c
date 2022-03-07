/*++

Module Name:

    ArvFilter.c

Abstract:

    This is the main module of the ArvFilter miniFilter driver.

Environment:

    Kernel mode

--*/
#include <fltKernel.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntifs.h>
#include <Wdmsec.h>
#include <stdlib.h>

#include "config.h"
#include "crypto.h"

#define MINI_PORT_NAME L"\\ArvCommPort"

NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);

typedef enum _OP_COMMAND {  //操作命令
	SET_PROC,
	SET_RULES,
	GET_STAT,
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
	UINT pathsLen;
} OpRule, *POpRule;

typedef struct _OpSetRules { //操作数据
	OpCommand command;
	POpRule *rules;
	UINT		ruleLen;
} OpSetRules, *POpSetRules;

//typedef struct _RepStat { //返回统计信息
//	BYTE SHA256[SHA256_BLOCK_SIZE];
//	LONG Pass;
//	LONG Block;
//} RepStat, *PRepStat;

typedef struct _RepStat { //返回统计信息
	//BYTE SHA256[SHA256_BLOCK_SIZE];
	ULONGLONG KeyCount;
	ULONGLONG Pass;
	ULONGLONG Block;
	ULONGLONG Read;
	ULONGLONG Write;
} RepStat, *PRepStat;

PFLT_PORT     gServerPort;//服务端口
PFLT_PORT     gClientPort;//客户端口
//unsigned long procID; //过滤进程ID
//LIST_ENTRY pathListHeader = { 0 }; //过滤数据盘路径
FilterConfig filterConfig = { 0 };
ERESOURCE HashResource = { 0 };


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
		if (status != STATUS_SUCCESS)
		{
			break;
		}
		processID = (ULONG)PsGetProcessInheritedFromUniqueProcessId(pProcess);
		ObDereferenceObject(pProcess);
		pProcess = NULL;
	}
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	if (FltObjects->FileObject == NULL) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	ExAcquireResourceSharedLite(&HashResource, TRUE);
	InterlockedIncrement64(&filterConfig.readCount);
	ExReleaseResourceLite(&HashResource);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	if (FltObjects->FileObject == NULL) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	ExAcquireResourceSharedLite(&HashResource, TRUE);
	InterlockedIncrement64(&filterConfig.writeCount);
	ExReleaseResourceLite(&HashResource);
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
	NTSTATUS status = FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (FltObjects->FileObject == NULL) {
		return status;
	}
	PFLT_FILE_NAME_INFORMATION nameInfo;
	UNICODE_STRING fullPath = { 0 };
	UNICODE_STRING dosName = { 0 };
	//HANDLE cProcessId = NULL;
	//PEPROCESS cProcess = NULL;
	//UNREFERENCED_PARAMETER(FltObjects);
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
	WCHAR LoginPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'i', 'n', '?', '\\' };
	WCHAR LogoutPath[] = { '\\','?','S','u','r','s', 'e', 'n', 'L', 'o', 'g', 'o', 'u', 't', '?', '\\' };
	ULONG procID = FltGetRequestorProcessId(Data);
	DbgPrint("[FsFilter:create]%d - %wZ\n", procID, &Data->Iopb->TargetFileObject->FileName);
	if ((Data->Iopb->TargetFileObject->FileName.Length > 15 * sizeof(wchar_t)) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[0] == LoginPath[0]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[1] == LoginPath[1]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[2] == LoginPath[2]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[3] == LoginPath[3]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[4] == LoginPath[4]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[5] == LoginPath[5]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[6] == LoginPath[6]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[7] == LoginPath[7]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[8] == LoginPath[8]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[9] == LoginPath[9]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[10] == LoginPath[10]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[11] == LoginPath[11]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[12] == LoginPath[12]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[13] == LoginPath[13]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[14] == LoginPath[14]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[fileNameLen / sizeof(wchar_t) - 1] == L'\\')
		)
	{
		PWSTR logintag = (PWSTR)ExAllocatePoolWithTag(PagedPool, fileNameLen, 'LGI');
		RtlZeroMemory(logintag, fileNameLen);
		int b = 0;
		PWSTR keyidstr = NULL;
		PWSTR timestr = NULL;
		for (UINT a = 0; a < fileNameLen / sizeof(wchar_t); a++)
		{
			if (Data->Iopb->TargetFileObject->FileName.Buffer[a] != L'\\')
			{
				logintag[a] = Data->Iopb->TargetFileObject->FileName.Buffer[a];
			}
			else
			{
				logintag[a] = L'\0';
				if (b == 1)
				{
					keyidstr = &logintag[a + 1];
				}
				else if (b == 2)
				{
					timestr = &logintag[a + 1];
				}
				b++;
			}
		}
		int keyid = _wtoi(keyidstr);
		//TODO: process timestamp
		ExAcquireResourceExclusiveLite(&HashResource, TRUE);
		ArvMapRule(&filterConfig, procID, keyid);
		ExReleaseResourceLite(&HashResource);
		ExFreePoolWithTag(logintag, 'LGI');
		return FLT_PREOP_COMPLETE;
	}
	else if ((Data->Iopb->TargetFileObject->FileName.Length > 16 * sizeof(wchar_t)) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[0] == LogoutPath[0]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[1] == LogoutPath[1]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[2] == LogoutPath[2]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[3] == LogoutPath[3]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[4] == LogoutPath[4]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[5] == LogoutPath[5]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[6] == LogoutPath[6]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[7] == LogoutPath[7]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[8] == LogoutPath[8]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[9] == LogoutPath[9]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[10] == LogoutPath[10]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[11] == LogoutPath[11]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[12] == LogoutPath[12]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[13] == LogoutPath[13]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[14] == LogoutPath[14]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[15] == LogoutPath[15]) &&
		(Data->Iopb->TargetFileObject->FileName.Buffer[fileNameLen / sizeof(wchar_t) - 1] == L'\\')
		)
	{
		PWSTR logouttag = (PWSTR)ExAllocatePoolWithTag(PagedPool, fileNameLen, 'LGO');
		RtlZeroMemory(logouttag, fileNameLen);
		int b = 0;
		PWSTR keyidstr = NULL;
		PWSTR timestr = NULL;
		for (UINT a = 0; a < fileNameLen / sizeof(wchar_t); a++)
		{
			if (Data->Iopb->TargetFileObject->FileName.Buffer[a] != L'\\')
			{
				logouttag[a] = Data->Iopb->TargetFileObject->FileName.Buffer[a];
			}
			else
			{
				logouttag[a] = L'\0';
				if (b == 1)
				{
					keyidstr = &logouttag[a + 1];
				}
				else if (b == 2)
				{
					timestr = &logouttag[a + 1];
				}
				b++;
			}
		}
		int keyid = _wtoi(keyidstr);
		//TODO: process timestamp
		ExAcquireResourceExclusiveLite(&HashResource, TRUE);
		ArvRemoveProc(&filterConfig, procID, keyid);
		ExReleaseResourceLite(&HashResource);
		ExFreePoolWithTag(logouttag, 'LGO');
		return FLT_PREOP_COMPLETE;
	}
	ExAcquireResourceSharedLite(&HashResource, TRUE);
	if (filterConfig.Rules.Flink == &filterConfig.Rules)
	{
		ExReleaseResourceLite(&HashResource);
		return status;
	}
	//ExReleaseResourceLite(&HashResource);
	//ExAcquireResourceSharedLite(&HashResource, TRUE);
	__try
	{
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
				if ((nameInfo->Volume).Buffer)
				{
					MyRtlVolumeDeviceToDosName(&(nameInfo->Volume), &dosName);
					size_t fullLen = dosName.Length + Data->Iopb->TargetFileObject->FileName.Length;
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
							fullPath.Buffer[i] = Data->Iopb->TargetFileObject->FileName.Buffer[k];
							k++;
						}
					}
					BOOL flag = FALSE;
					PRuleEntry pRuleEntry = { 0 };
					PPathEntry pPathEntry = { 0 };
					//ExAcquireResourceSharedLite(&HashResource, TRUE);
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
								UINT m = 0;
								for (m = 0; m < pPathEntry->Path.Length / sizeof(wchar_t); m++)
								{
									if (pPathEntry->Path.Buffer[m] != fullPath.Buffer[m])
									{
										break;
									}
								}
								if (m == pPathEntry->Path.Length / sizeof(wchar_t))
								{
									flag = TRUE;
									goto out1;
								}
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
							InterlockedIncrement64(&pPathEntry->stat.blockCounter);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							status = FLT_PREOP_COMPLETE;
						}
						else
						{
							InterlockedIncrement64(&pPathEntry->stat.passCounter);
						}
						ArvFreeProcs(&procHead);
					}
					else
					{
						DbgPrint("[FsFilter:create]no filter: %d - %wZ\n", FltGetRequestorProcessId(Data), fullPath);
					}
					//ExReleaseResourceLite(&HashResource);
				}
				else
				{
					DbgPrint("[FsFilter:create]no volume: %d - %wZ\n", FltGetRequestorProcessId(Data), nameInfo->Name);
				}
			}
			FltReleaseFileNameInformation(nameInfo);
		}
		else
		{
			DbgPrint("[FsFilter:create]parse name failed: %d - %wZ\n", FltGetRequestorProcessId(Data), Data->Iopb->TargetFileObject->FileName);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[FsFilter:create]PreOperationWrite EXCEPTION_EXECUTE_HANDLER: %wZ - %d\n", Data->Iopb->TargetFileObject->FileName, GetExceptionCode());
	}
	ExReleaseResourceLite(&HashResource);
	ArvFreeUnicodeString(&dosName, 'SOD');
	ArvFreeUnicodeString(&fullPath, 'POC');
	if (status != FLT_PREOP_COMPLETE)
	{
		status = FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	return status;
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

//
	// Constant FLT_REGISTRATION structure for our filter.
	// This initializes the callback routines our filter wants to register for.
	//
CONST FLT_OPERATION_REGISTRATION g_callbacks[] =
{
	{
		IRP_MJ_CREATE,
		0,
		PreOperationCreate,
		0
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
	{ IRP_MJ_OPERATION_END }
};

//
// The FLT_REGISTRATION structure provides information about a file system minifilter to the filter manager.
//
CONST FLT_REGISTRATION g_filterRegistration =
{
	sizeof(FLT_REGISTRATION),      //  Size
	FLT_REGISTRATION_VERSION,      //  Version
	0,                             //  Flags
	NULL,                          //  Context registration
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
				for (UINT i = 0; i < pOpSetRules->ruleLen; i++)
				{
					PRuleEntry newRuleEntry = ArvAddRule(&tmpConfig, pOpSetRules->rules[i]->id, pOpSetRules->rules[i]->pubKey, pOpSetRules->rules[i]->paths, pOpSetRules->rules[i]->pathsLen);
					
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
						i++;
						pListEntry2 = pListEntry2->Flink;
					}
					pListEntry = pListEntry->Flink;
				}
				pStats->KeyCount = keyCount;
				pStats->Block = blockTotal;
				pStats->Pass = passTotal;
				pStats->Read = filterConfig.readCount;
				pStats->Write = filterConfig.writeCount;
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
	NTSTATUS status = STATUS_SUCCESS;
	PSECURITY_DESCRIPTOR sd = NULL;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING uniString;
	DbgPrint("[FsFilter:register]registry path: %wZ\n", *RegistryPath);
	__try {
		int ret = testSecp256k1();
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
