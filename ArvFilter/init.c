#include "pch.h"

#define SYSTEMPROCESSINFORMATION 5

NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);

//处理进程信息，需要用到这两个结构体
typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientIs;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   ThreadState;
	KWAIT_REASON            WaitReason;
}SYSTEM_THREADS, *PSYSTEM_THREADS;

//进程信息结构体  
typedef struct _SYSTEM_PROCESSES
{
	ULONG                           NextEntryDelta;    //链表下一个结构和上一个结构的偏移
	ULONG                           ThreadCount;
	ULONG                           Reserved[6];
	LARGE_INTEGER                   CreateTime;
	LARGE_INTEGER                   UserTime;
	LARGE_INTEGER                   KernelTime;
	UNICODE_STRING                  ProcessName;     //进程名字
	KPRIORITY                       BasePriority;
	SIZE_T                           ProcessId;      //进程的pid号
	SIZE_T                           InheritedFromProcessId;
	ULONG                           HandleCount;
	ULONG                           Reserved2[2];
	VM_COUNTERS                     VmCounters;
	IO_COUNTERS                     IoCounters; //windows 2000 only  
	struct _SYSTEM_THREADS          Threads[1];
}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

//声明ZqQueryAyatemInformation
NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,  //处理进程信息,只需要处理类别为5的即可
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);

LIST_ENTRY AllowedProcs;

NTSTATUS InitProcessList()
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	ULONG retLength;  //缓冲区长度
	PVOID pProcInfo;
	PSYSTEM_PROCESSES pProcIndex;
	PEPROCESS pProcess;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	InitializeListHead(&AllowedProcs);
	//调用函数，获取进程信息
	nStatus = ZwQuerySystemInformation(
		SYSTEMPROCESSINFORMATION,   //获取进程信息,宏定义为5
		NULL,
		0,
		&retLength  //返回的长度，即为我们需要申请的缓冲区的长度
	);
	if (!retLength)
	{
		DbgPrint("ZwQuerySystemInformation error!\n");
		return nStatus;
	}
	DbgPrint("retLength =  %u\n", retLength);
	//申请空间
	pProcInfo = ExAllocatePool(NonPagedPool, retLength);
	if (!pProcInfo)
	{
		DbgPrint("ExAllocatePool error!\n");
		return STATUS_UNSUCCESSFUL;
	}
	nStatus = ZwQuerySystemInformation(
		SYSTEMPROCESSINFORMATION,   //获取进程信息,宏定义为5
		pProcInfo,
		retLength,
		&retLength
	);
	if (NT_SUCCESS(nStatus)/*STATUS_INFO_LENGTH_MISMATCH == nStatus*/)
	{
		pProcIndex = (PSYSTEM_PROCESSES)pProcInfo;
		//第一个进程应该是 pid 为 0 的进程
		if (pProcIndex->ProcessId == 0)
			DbgPrint("PID 0 System Idle Process\n");
		//循环打印所有进程信息,因为最后一天进程的NextEntryDelta值为0，所以先打印后判断
		do
		{
			pProcIndex = (PSYSTEM_PROCESSES)((char*)pProcIndex + pProcIndex->NextEntryDelta);
			//进程名字字符串处理，防止打印时，出错
			if (pProcIndex->ProcessName.Buffer == NULL)
				pProcIndex->ProcessName.Buffer = L"NULL";
			ntStatus = PsLookupProcessByProcessId((HANDLE)pProcIndex->ProcessId, &pProcess);
			if (NT_SUCCESS(ntStatus))
			{
				char *pStrProcessName = PsGetProcessImageFileName(pProcess);
				ObDereferenceObject(pProcess);
				if (strcmp(pStrProcessName, "explorer.exe") == 0)
				{
					continue;
				}
			}
			DbgPrint("ProcName:  %-20ws     pid:  %u\n", pProcIndex->ProcessName.Buffer, pProcIndex->ProcessId);
			ArvAddProc(&AllowedProcs, pProcIndex->ProcessId, FALSE);
		} while (pProcIndex->NextEntryDelta != 0);
	}
	else
	{
		DbgPrint("error code : %u!!!\n", nStatus);
	}
	ExFreePool(pProcInfo);
	return nStatus;
}

BOOLEAN ProcAllowed1(ULONG ProcID)
{
	PLIST_ENTRY pListEntry = AllowedProcs.Flink;
	while (pListEntry != &AllowedProcs)
	{
		PProcEntry pProcEntry = CONTAINING_RECORD(pListEntry, ProcEntry, entry);
		if (pProcEntry->ProcID == ProcID)
		{
			return TRUE;
		}
		pListEntry = pListEntry->Flink;
	}
	return FALSE;
}

BOOLEAN ProcAllowed(ULONG ProcID)
	//__in const UINT32               pid,
	//__in PROCESS_BASIC_INFORMATION *procBasicInfo,
	//__in UNICODE_STRING            *sid)
{
	/*if (ProcAllowed1(ProcID))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}*/

	WCHAR sidSystem[] = { 'S','-','1','-','5','-','1','8' };
	WCHAR sidLocalService[] = { 'S','-','1','-','5','-','1','9' };
	WCHAR sidNetworkService[] = { 'S','-','1','-','5','-','2','0' };

	NTSTATUS    status;
	HANDLE      processToken = NULL;
	TOKEN_USER *processUser = NULL;
	ULONG       processUserBytes = 0;
	UNICODE_STRING sid = { 0 };
	HANDLE handle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID clientid;
	InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
	clientid.UniqueProcess = (HANDLE)ProcID;
	clientid.UniqueThread = 0;
	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientid);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot open token for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	// Open process token
	status = ZwOpenProcessTokenEx(handle, GENERIC_READ,
		OBJ_KERNEL_HANDLE, &processToken);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot open token for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	// Get size of buffer to hold the user information, which contains the SID
	status = ZwQueryInformationToken(processToken, TokenUser,
		NULL, 0, &processUserBytes);
	if (status != STATUS_BUFFER_TOO_SMALL) {
		DbgPrint("Cannot get token information size for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	// Allocate the buffer to hold the user information
	processUser = (TOKEN_USER*)ExAllocatePoolWithTag(
		NonPagedPool, processUserBytes, 'TOK');
	if (processUser == NULL) {
		DbgPrint("Cannot allocate %u token information bytes for process %u", processUserBytes, ProcID);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	// Get user information for the process token
	status = ZwQueryInformationToken(processToken, TokenUser, processUser, processUserBytes, &processUserBytes);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot get token information for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	// Convert the SID to a string, but don't free it until after enqueing the
	// PCAP-NG process block
	status = RtlConvertSidToUnicodeString(&sid, processUser->User.Sid, TRUE);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot convert SID to string for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	if (memcmp(sidSystem, sid.Buffer, 8 * sizeof(wchar_t)) == 0 || memcmp(sidLocalService, sid.Buffer, 8 * sizeof(wchar_t)) == 0 || memcmp(sidNetworkService, sid.Buffer, 8 * sizeof(wchar_t)) == 0)
	{
		status = STATUS_SUCCESS;
	}
	else
	{
		status = STATUS_ACCESS_DENIED;
	}

Cleanup:
	if (processToken) {
		ZwClose(processToken);
	}
	if (processUser) {
		ExFreePoolWithTag(processUser, 'TOK');
	}
	if (sid.Buffer)
	{
		ExFreePool(sid.Buffer);
	}
	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN ProcAllowed2(ULONG ProcID)
{
	WCHAR sidSystem[] = { 'S','-','1','-','5','-', '18' };
	WCHAR sidLocalService[] = { 'S','-','1','-','5','-', '19' };
	WCHAR sidNetworkService[] = { 'S','-','1','-','5','-', '20' };
	NTSTATUS ntStatus;
	PVOID Token;
	HANDLE tokenHandle;
	PTOKEN_USER tokenInfoBuffer;
	ULONG requiredLength;
	// PCHAR sidStringBuffer[512];
	PWCHAR sidStringBuffer;
	UNICODE_STRING sidString;
	PEPROCESS pProcess;

	ntStatus = PsLookupProcessByProcessId((HANDLE)ProcID, &pProcess);
	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}
	
	//ObDereferenceObject(pProcess);

	sidStringBuffer = ExAllocatePool(NonPagedPool, 512);
	RtlInitEmptyUnicodeString(&sidString, sidStringBuffer, 512);


	Token = PsReferencePrimaryToken(pProcess);
	ObDereferenceObject(pProcess);
	ntStatus = ObOpenObjectByPointer(Token, 0, NULL, TOKEN_QUERY,
		NULL, KernelMode, &tokenHandle);
	ObDereferenceObject(Token);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint(("GetSID: Could not open process token: %x\n",
			ntStatus));
		return FALSE;
	}

	//
	// Pull out the SID
	//
	ntStatus = NtQueryInformationToken(tokenHandle, TokenUser, NULL, 0,
		&requiredLength);
	if (ntStatus != STATUS_BUFFER_TOO_SMALL) {

		DbgPrint(("GetSID: Error getting token information: %x\n",
			ntStatus));
		ZwClose(tokenHandle);
		return FALSE;
	}
	tokenInfoBuffer = (PTOKEN_USER)ExAllocatePool(NonPagedPool,
		requiredLength);
	if (tokenInfoBuffer) {
		ntStatus = NtQueryInformationToken(tokenHandle, TokenUser,
			tokenInfoBuffer, requiredLength, &requiredLength);
	}
	if (!NT_SUCCESS(ntStatus) || !tokenInfoBuffer) {
		DbgPrint(("GetSID: Error getting token information: %x\n",
			ntStatus));
		if (tokenInfoBuffer)
			ExFreePool(tokenInfoBuffer);
		ZwClose(tokenHandle);
		return FALSE;
	}
	ZwClose(tokenHandle);

	//
	// Got it, now convert to text representation
	//
	//memset( sidStringBuffer, 0, sizeof(sidStringBuffer ));
	//sidStringBuffer= ExAllocatePool(NonPagedPool, 512 );
	//sidString->Buffer = (PWCHAR) sidStringBuffer;
	//sidString->MaximumLength = sizeof(sidStringBuffer);
	//RtlInitEmptyUnicodeString(sidString,sidStringBuffer,512);
	ntStatus = RtlConvertSidToUnicodeString(&sidString, tokenInfoBuffer->
		User.Sid, FALSE);
	sidString.Buffer[sidString.Length + 1] = '\0';
	DbgPrint(("GetSID: sidString = %ws\n", sidString.Buffer));
	ExFreePool(tokenInfoBuffer);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint(("GetSID: Unable to convert SID to text: %x\n",
			ntStatus));
		return FALSE;
	}
	if (memcmp(sidSystem, sidString.Buffer, 8 * sizeof(wchar_t)) == 0 || memcmp(sidLocalService, sidString.Buffer, 8 * sizeof(wchar_t)) == 0 || memcmp(sidNetworkService, sidString.Buffer, 8 * sizeof(wchar_t)) == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

VOID FreeAllowedProcs()
{
	ArvFreeProcs(&AllowedProcs);
}