#include "pch.h"

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

//HANDLE LogFileHandle = { 0 };
//PFILE_OBJECT LogFileObject = { 0 };
//PFLT_INSTANCE LogInstance = { 0 };
//PFLT_VOLUME LogVolume = { 0 };
LARGE_INTEGER Offset = { 0 };
ERESOURCE LogResource = { 0 };
BOOLEAN bReady = TRUE;

//#define SYSTEMPROCESSINFORMATION 5
//
//NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
//
////处理进程信息，需要用到这两个结构体
//typedef struct _SYSTEM_THREADS
//{
//	LARGE_INTEGER           KernelTime;
//	LARGE_INTEGER           UserTime;
//	LARGE_INTEGER           CreateTime;
//	ULONG                   WaitTime;
//	PVOID                   StartAddress;
//	CLIENT_ID               ClientIs;
//	KPRIORITY               Priority;
//	KPRIORITY               BasePriority;
//	ULONG                   ContextSwitchCount;
//	ULONG                   ThreadState;
//	KWAIT_REASON            WaitReason;
//}SYSTEM_THREADS, *PSYSTEM_THREADS;
//
////进程信息结构体  
//typedef struct _SYSTEM_PROCESSES
//{
//	ULONG                           NextEntryDelta;    //链表下一个结构和上一个结构的偏移
//	ULONG                           ThreadCount;
//	ULONG                           Reserved[6];
//	LARGE_INTEGER                   CreateTime;
//	LARGE_INTEGER                   UserTime;
//	LARGE_INTEGER                   KernelTime;
//	UNICODE_STRING                  ProcessName;     //进程名字
//	KPRIORITY                       BasePriority;
//	SIZE_T                           ProcessId;      //进程的pid号
//	SIZE_T                           InheritedFromProcessId;
//	ULONG                           HandleCount;
//	ULONG                           Reserved2[2];
//	VM_COUNTERS                     VmCounters;
//	IO_COUNTERS                     IoCounters; //windows 2000 only  
//	struct _SYSTEM_THREADS          Threads[1];
//}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;
//
////声明ZqQueryAyatemInformation
//NTSTATUS ZwQuerySystemInformation(
//	IN ULONG SystemInformationClass,  //处理进程信息,只需要处理类别为5的即可
//	OUT PVOID SystemInformation,
//	IN ULONG SystemInformationLength,
//	OUT PULONG ReturnLength
//);
//
//LIST_ENTRY AllowedProcs;
//
//NTSTATUS InitProcessList()
//{
//	NTSTATUS nStatus = STATUS_SUCCESS;
//	ULONG retLength;  //缓冲区长度
//	PVOID pProcInfo;
//	PSYSTEM_PROCESSES pProcIndex;
//	PEPROCESS pProcess;
//	NTSTATUS ntStatus = STATUS_SUCCESS;
//	InitializeListHead(&AllowedProcs);
//	//调用函数，获取进程信息
//	nStatus = ZwQuerySystemInformation(
//		SYSTEMPROCESSINFORMATION,   //获取进程信息,宏定义为5
//		NULL,
//		0,
//		&retLength  //返回的长度，即为我们需要申请的缓冲区的长度
//	);
//	if (!retLength)
//	{
//		DbgPrint("ZwQuerySystemInformation error!\n");
//		return nStatus;
//	}
//	DbgPrint("retLength =  %u\n", retLength);
//	//申请空间
//	pProcInfo = ExAllocatePoolWithTag(NonPagedPool, retLength, 'PPIF');
//	if (!pProcInfo)
//	{
//		DbgPrint("ExAllocatePool error!\n");
//		return STATUS_UNSUCCESSFUL;
//	}
//	nStatus = ZwQuerySystemInformation(
//		SYSTEMPROCESSINFORMATION,   //获取进程信息,宏定义为5
//		pProcInfo,
//		retLength,
//		&retLength
//	);
//	if (NT_SUCCESS(nStatus)/*STATUS_INFO_LENGTH_MISMATCH == nStatus*/)
//	{
//		pProcIndex = (PSYSTEM_PROCESSES)pProcInfo;
//		//第一个进程应该是 pid 为 0 的进程
//		if (pProcIndex->ProcessId == 0)
//			DbgPrint("PID 0 System Idle Process\n");
//		//循环打印所有进程信息,因为最后一天进程的NextEntryDelta值为0，所以先打印后判断
//		do
//		{
//			pProcIndex = (PSYSTEM_PROCESSES)((char*)pProcIndex + pProcIndex->NextEntryDelta);
//			//进程名字字符串处理，防止打印时，出错
//			if (pProcIndex->ProcessName.Buffer == NULL)
//				pProcIndex->ProcessName.Buffer = L"NULL";
//			ntStatus = PsLookupProcessByProcessId((HANDLE)pProcIndex->ProcessId, &pProcess);
//			if (NT_SUCCESS(ntStatus))
//			{
//				char *pStrProcessName = PsGetProcessImageFileName(pProcess);
//				ObDereferenceObject(pProcess);
//				if (strcmp(pStrProcessName, "explorer.exe") == 0)
//				{
//					continue;
//				}
//			}
//			DbgPrint("ProcName:  %-20ws     pid:  %u\n", pProcIndex->ProcessName.Buffer, pProcIndex->ProcessId);
//			ArvAddProc(&AllowedProcs, pProcIndex->ProcessId, FALSE);
//		} while (pProcIndex->NextEntryDelta != 0);
//	}
//	else
//	{
//		DbgPrint("error code : %u!!!\n", nStatus);
//	}
//	ExFreePoolWithTag(pProcInfo, 'PPIF');
//	return nStatus;
//}
//
//BOOLEAN ProcAllowed1(ULONG ProcID)
//{
//	PLIST_ENTRY pListEntry = AllowedProcs.Flink;
//	while (pListEntry != &AllowedProcs)
//	{
//		PProcEntry pProcEntry = CONTAINING_RECORD(pListEntry, ProcEntry, entry);
//		if (pProcEntry->ProcID == ProcID)
//		{
//			return TRUE;
//		}
//		pListEntry = pListEntry->Flink;
//	}
//	return FALSE;
//}

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
		processUser = NULL;
	}
	if (handle) {
		ZwClose(handle);
	}
	if (sid.Buffer)
	{
		RtlFreeUnicodeString(&sid);
		//ExFreePool(sid.Buffer);
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

	sidStringBuffer = ExAllocatePoolWithTag(NonPagedPool, 512, 'SSBF');
	RtlInitEmptyUnicodeString(&sidString, sidStringBuffer, 512);


	Token = PsReferencePrimaryToken(pProcess);
	ObDereferenceObject(pProcess);
	ntStatus = ObOpenObjectByPointer(Token, 0, NULL, TOKEN_QUERY,
		NULL, KernelMode, &tokenHandle);
	ObDereferenceObject(Token);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint(("GetSID: Could not open process token: %x\n",
			ntStatus));
		//ExFreePool(sidStringBuffer);
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
	tokenInfoBuffer = (PTOKEN_USER)ExAllocatePoolWithTag(NonPagedPool,
		requiredLength, 'TKUR');
	if (tokenInfoBuffer) {
		ntStatus = NtQueryInformationToken(tokenHandle, TokenUser,
			tokenInfoBuffer, requiredLength, &requiredLength);
	}
	if (!NT_SUCCESS(ntStatus) || !tokenInfoBuffer) {
		DbgPrint(("GetSID: Error getting token information: %x\n",
			ntStatus));
		if (tokenInfoBuffer)
		{
			ExFreePoolWithTag(tokenInfoBuffer, 'TKUR');
			tokenInfoBuffer = NULL;
		}
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
	ExFreePoolWithTag(tokenInfoBuffer, 'TKUR');
	tokenInfoBuffer = NULL;
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

//VOID FreeAllowedProcs()
//{
//	ArvFreeProcs(&AllowedProcs);
//}

PFLT_INSTANCE
XBFltGetVolumeInstance(
	IN PFLT_FILTER		pFilter,
	IN PUNICODE_STRING	pVolumeName
)
{
	NTSTATUS		status;
	PFLT_INSTANCE	pInstance = NULL;
	PFLT_VOLUME		pVolumeList[256];
	BOOLEAN			bDone = FALSE;
	ULONG			uRet;
	UNICODE_STRING	uniName = { 0 };
	ULONG 			index = 0;
	WCHAR			wszNameBuffer[MAX_PATH] = { 0 };

	status = FltEnumerateVolumes(pFilter,
		NULL,
		0,
		&uRet);
	if (status != STATUS_BUFFER_TOO_SMALL)
	{
		return NULL;
	}

	status = FltEnumerateVolumes(pFilter,
		pVolumeList,
		uRet,
		&uRet);

	if (!NT_SUCCESS(status))
	{

		return NULL;
	}
	uniName.Buffer = wszNameBuffer;

	if (uniName.Buffer == NULL)
	{
		for (index = 0; index < uRet; index++)
			FltObjectDereference(pVolumeList[index]);

		return NULL;
	}

	uniName.MaximumLength = MAX_PATH * sizeof(WCHAR);

	for (index = 0; index < uRet; index++)
	{
		uniName.Length = 0;

		status = FltGetVolumeName(pVolumeList[index],
			&uniName,
			NULL);

		if (!NT_SUCCESS(status))
			continue;

		if (RtlCompareUnicodeString(&uniName,
			pVolumeName,
			TRUE) != 0)
			continue;

		status = FltGetVolumeInstanceFromName(pFilter,
			pVolumeList[index],
			NULL,
			&pInstance);

		if (NT_SUCCESS(status))
		{
			//FltObjectDereference(pInstance);
			break;
		}
	}

	for (index = 0; index < uRet; index++)
		FltObjectDereference(pVolumeList[index]);
	return pInstance;
}

//UNICODE_STRING ProfilesDirectoryPath = { 0 };
//UNICODE_STRING ProgramDataPath = { 0 };
//UNICODE_STRING PublicPath = { 0 };
UNICODE_STRING SystemRoot = { 0 };
DWORD LogFlag = 0;
//DWORD LogAutoClose = 0;
DWORD LogOnly = 0;
UNICODE_STRING LogPath = { 0 };
UNICODE_STRING IllegalLogPath = { 0 };
UNICODE_STRING SillegalLogPath = { 0 };
UNICODE_STRING AbnormalLogPath = { 0 };


NTSTATUS CleanFilterConfig()
{
	if (SystemRoot.Buffer)
	{
		RtlFreeUnicodeString(&SystemRoot);
	}
	if (LogPath.Buffer)
	{
		RtlFreeUnicodeString(&LogPath);
	}
	if (IllegalLogPath.Buffer)
	{
		RtlFreeUnicodeString(&IllegalLogPath);
	}
	if (SillegalLogPath.Buffer)
	{
		RtlFreeUnicodeString(&SillegalLogPath);
	}
	if (AbnormalLogPath.Buffer)
	{
		RtlFreeUnicodeString(&AbnormalLogPath);
	}
}

NTSTATUS InitFilterConfig()
{
	NTSTATUS status = STATUS_SUCCESS;

	RTL_QUERY_REGISTRY_TABLE arrayTable0[2];
	RtlZeroMemory(arrayTable0, sizeof(arrayTable0));
	arrayTable0[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable0[0].Name = L"SystemRoot";
	arrayTable0[0].EntryContext = &SystemRoot;
	arrayTable0[0].DefaultType = REG_SZ;
	arrayTable0[0].DefaultData = REG_NONE;
	arrayTable0[0].DefaultLength = REG_NONE;
	status = RtlQueryRegistryValues(RTL_REGISTRY_WINDOWS_NT, L"", arrayTable0, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	DWORD logFlag = -1;
	RTL_QUERY_REGISTRY_TABLE arrayTable1[2];
	RtlZeroMemory(arrayTable1, sizeof(arrayTable1));
	arrayTable1[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable1[0].Name = L"LogFlag";
	arrayTable1[0].EntryContext = &logFlag;
	arrayTable1[0].DefaultType = REG_DWORD;
	arrayTable1[0].DefaultData = REG_NONE;
	arrayTable1[0].DefaultLength = REG_NONE;
	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable1, NULL, NULL);
	if (!NT_SUCCESS(status) || logFlag == -1)
	{
		logFlag = 0;
	}
	LogFlag = logFlag;


	/*arrayTable[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable[1].Name = L"LogAutoClose";
	arrayTable[1].EntryContext = &LogAutoClose;
	arrayTable[1].DefaultType = REG_DWORD;
	arrayTable[1].DefaultData = REG_NONE;
	arrayTable[1].DefaultLength = REG_NONE;*/

	DWORD logOnly = -1;
	RTL_QUERY_REGISTRY_TABLE arrayTable2[2];
	RtlZeroMemory(arrayTable2, sizeof(arrayTable2));
	arrayTable2[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable2[0].Name = L"LogOnly";
	arrayTable2[0].EntryContext = &logOnly;
	arrayTable2[0].DefaultType = REG_DWORD;
	arrayTable2[0].DefaultData = REG_NONE;
	arrayTable2[0].DefaultLength = REG_NONE;
	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable2, NULL, NULL);
	if (!NT_SUCCESS(status) || logOnly == -1)
	{
		logOnly = 2;
	}
	LogOnly = logOnly;

	RTL_QUERY_REGISTRY_TABLE arrayTable3[2];
	RtlZeroMemory(arrayTable3, sizeof(arrayTable3));
	arrayTable3[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable3[0].Name = L"LogPath";
	arrayTable3[0].EntryContext = &LogPath;
	arrayTable3[0].DefaultType = REG_SZ;
	arrayTable3[0].DefaultData = REG_NONE;
	arrayTable3[0].DefaultLength = REG_NONE;

	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable3, NULL, NULL);
	if (!NT_SUCCESS(status) || !LogPath.Buffer)
	{
		PWSTR Buffer = (PWSTR)ExAllocatePool(NonPagedPool, 34);
		RtlInitEmptyUnicodeString(&LogPath, Buffer, 17 * sizeof(WCHAR));
		//拷贝字符串
		RtlAppendUnicodeToString(&LogPath, L"\\??\\C:\\filter.log");
	}

	RTL_QUERY_REGISTRY_TABLE arrayTable4[2];
	RtlZeroMemory(arrayTable4, sizeof(arrayTable4));
	arrayTable4[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable4[0].Name = L"IllegalLogPath";
	arrayTable4[0].EntryContext = &IllegalLogPath;
	arrayTable4[0].DefaultType = REG_SZ;
	arrayTable4[0].DefaultData = REG_NONE;
	arrayTable4[0].DefaultLength = REG_NONE;

	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable4, NULL, NULL);
	if (!NT_SUCCESS(status) || !IllegalLogPath.Buffer)
	{
		PWSTR Buffer = (PWSTR)ExAllocatePool(NonPagedPool, 36);
		RtlInitEmptyUnicodeString(&IllegalLogPath, Buffer, 18 * sizeof(WCHAR));
		//拷贝字符串
		RtlAppendUnicodeToString(&IllegalLogPath, L"\\??\\C:\\illegal.log");
	}

	RTL_QUERY_REGISTRY_TABLE arrayTable5[2];
	RtlZeroMemory(arrayTable5, sizeof(arrayTable5));
	arrayTable5[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable5[0].Name = L"SillegalLogPath";
	arrayTable5[0].EntryContext = &SillegalLogPath;
	arrayTable5[0].DefaultType = REG_SZ;
	arrayTable5[0].DefaultData = REG_NONE;
	arrayTable5[0].DefaultLength = REG_NONE;

	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable5, NULL, NULL);
	if (!NT_SUCCESS(status) || !SillegalLogPath.Buffer)
	{
		PWSTR Buffer = (PWSTR)ExAllocatePool(NonPagedPool, 38);
		RtlInitEmptyUnicodeString(&SillegalLogPath, Buffer, 19 * sizeof(WCHAR));
		//拷贝字符串
		RtlAppendUnicodeToString(&SillegalLogPath, L"\\??\\C:\\sillegal.log");
	}

	RTL_QUERY_REGISTRY_TABLE arrayTable6[2];
	RtlZeroMemory(arrayTable6, sizeof(arrayTable6));
	arrayTable6[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable6[0].Name = L"AbnormalLogPath";
	arrayTable6[0].EntryContext = &AbnormalLogPath;
	arrayTable6[0].DefaultType = REG_SZ;
	arrayTable6[0].DefaultData = REG_NONE;
	arrayTable6[0].DefaultLength = REG_NONE;

	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable6, NULL, NULL);
	if (!NT_SUCCESS(status) || !AbnormalLogPath.Buffer)
	{
		PWSTR Buffer = (PWSTR)ExAllocatePool(NonPagedPool, 38);
		RtlInitEmptyUnicodeString(&AbnormalLogPath, Buffer, 19 * sizeof(WCHAR));
		//拷贝字符串
		RtlAppendUnicodeToString(&AbnormalLogPath, L"\\??\\C:\\abnormal.log");
	}

	DWORD abnormalThreshold = -1;
	RTL_QUERY_REGISTRY_TABLE arrayTable7[2];
	RtlZeroMemory(arrayTable7, sizeof(arrayTable7));
	arrayTable7[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable7[0].Name = L"AbnormalThreshold";
	arrayTable7[0].EntryContext = &abnormalThreshold;
	arrayTable7[0].DefaultType = REG_DWORD;
	arrayTable7[0].DefaultData = REG_NONE;
	arrayTable7[0].DefaultLength = REG_NONE;
	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable7, NULL, NULL);
	if (!NT_SUCCESS(status) || abnormalThreshold == -1)
	{
		abnormalThreshold = 0;
	}

	DWORD abnormalInterval = -1;
	RTL_QUERY_REGISTRY_TABLE arrayTable8[2];
	RtlZeroMemory(arrayTable8, sizeof(arrayTable8));
	arrayTable8[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	arrayTable8[0].Name = L"AbnormalInterval";
	arrayTable8[0].EntryContext = &abnormalInterval;
	arrayTable8[0].DefaultType = REG_DWORD;
	arrayTable8[0].DefaultData = REG_NONE;
	arrayTable8[0].DefaultLength = REG_NONE;
	status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"ArvCtl", arrayTable8, NULL, NULL);
	if (!NT_SUCCESS(status) || abnormalInterval == -1)
	{
		abnormalInterval = 0;
	}

	ArvAbnormalCounterSetThreshold(&abnormalCounters, abnormalThreshold, abnormalInterval);

	/*if (LogAutoClose == 1)
	{
		status = RtlDeleteRegistryValue(RTL_REGISTRY_SERVICES, L"ArvCtl", L"LogFlag");
	}*/
	return STATUS_SUCCESS;
}

PUNICODE_STRING ArvGetSystemRoot()
{
	return &SystemRoot;
}

PUNICODE_STRING ArvGetLogPath()
{
	return &LogPath;
}

DWORD ArvGetLogFlag()
{
	return LogFlag;
}

DWORD ArvGetLogOnly()
{
	return LogOnly;
}

//UNICODE_STRING ExpAllowedPartialPaths[25] = {
//		RTL_CONSTANT_STRING(L""),
//		RTL_CONSTANT_STRING(L""),
//		RTL_CONSTANT_STRING(L"\\AppData"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Local"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Local\\ConnectedDevicesPlatform*"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft*"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows*"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Local\\Temp*"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Roaming"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Roaming\\Microsoft\\Windows*"),
//		RTL_CONSTANT_STRING(L"\\Desktop"),
//		RTL_CONSTANT_STRING(L""),
//		RTL_CONSTANT_STRING(L"\\Desktop"),
//		RTL_CONSTANT_STRING(L"\\rescache\\_merged*"),
//		RTL_CONSTANT_STRING(L"\\system32\\catroot"),
//		RTL_CONSTANT_STRING(L"\\system32\\catroot2"),
//		RTL_CONSTANT_STRING(L""),
//		RTL_CONSTANT_STRING(L"\\Microsoft\\Windows\\Start Menu"),
//		RTL_CONSTANT_STRING(L"\\Microsoft\\Windows\\Start Menu\\Programs"),
//		RTL_CONSTANT_STRING(L"\\Microsoft\\Windows\\Start Menu Places"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Local\\IconCache.db"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache_idx.db"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch"),
//		RTL_CONSTANT_STRING(L"\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned"),
//		RTL_CONSTANT_STRING(L"\\Microsoft\\Windows\\Caches")
//};
//
//UNICODE_STRING OthAllowedPartialPaths[8] = {
//	RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows\\WebCache*"),
//	RTL_CONSTANT_STRING(L"\\AppData\\Local\\ConnectedDevicesPlatform*"),
//	RTL_CONSTANT_STRING(L"\\AppData\\Local\\Packages*"),
//	RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows\\WebCacheLock.dat"),
//	RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows\\Caches"),
//	RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows\\INetCache"),
//	RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows\\Explorer*"),
//	RTL_CONSTANT_STRING(L"")
//};


//BOOLEAN ProcAllowedPaths(ULONG ProcID, PSTR ProcessName, PUNICODE_STRING FullPath)
//{
//	//BYTE PathBuffers[24][520] = ExAllocatePoolWithTag(NonPagedPool, 24*520, 'ftr1');
//	BYTE (*PathBuffers)[520] = ExAllocatePoolWithTag(NonPagedPool, 25 * 520, 'ftr1');
//	RtlZeroMemory(PathBuffers, 25*520);
//	UNICODE_STRING ExpAllowedPaths[25] = { 0 };
//
//	//BYTE OthPathBuffers[6][520] = ExAllocatePoolWithTag(NonPagedPool, 6 * 520, 'ftr2');
//	BYTE (*OthPathBuffers)[520] = ExAllocatePoolWithTag(NonPagedPool, 8 * 520, 'ftr2');
//	RtlZeroMemory(OthPathBuffers, 8 * 520);
//	UNICODE_STRING OthAllowedPaths[8] = { 0 };
//	 
//	NTSTATUS    status;
//	HANDLE      processToken = NULL;
//	TOKEN_USER *processUser = NULL;
//	ULONG       processUserBytes = 0;
//	UNICODE_STRING sid = { 0 };
//	HANDLE handle;
//	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
//	CLIENT_ID clientid = { 0 };
//
//	UNICODE_STRING owner = { 0 };
//	BYTE ownerBuffer[256] = { 0 };
//	//UNICODE_STRING domain;
//	ULONG ownerSize = 1;// , domainSize = 1;
//	SID_NAME_USE eUse = SidTypeUnknown;
//	RtlInitEmptyUnicodeString(&owner, ownerBuffer, 256);
//
//	InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
//	clientid.UniqueProcess = (HANDLE)ProcID;
//	clientid.UniqueThread = 0;
//	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientid);
//	if (!NT_SUCCESS(status)) {
//		DbgPrint("Cannot open token for process %u: %08X", ProcID, status);
//		goto Cleanup;
//	}
//
//	// Open process token
//	status = ZwOpenProcessTokenEx(handle, GENERIC_READ,
//		OBJ_KERNEL_HANDLE, &processToken);
//	if (!NT_SUCCESS(status)) {
//		DbgPrint("Cannot open token for process %u: %08X", ProcID, status);
//		goto Cleanup;
//	}
//
//	// Get size of buffer to hold the user information, which contains the SID
//	status = ZwQueryInformationToken(processToken, TokenUser,
//		NULL, 0, &processUserBytes);
//	if (status != STATUS_BUFFER_TOO_SMALL) {
//		DbgPrint("Cannot get token information size for process %u: %08X", ProcID, status);
//		goto Cleanup;
//	}
//
//	// Allocate the buffer to hold the user information
//	processUser = (TOKEN_USER*)ExAllocatePoolWithTag(
//		NonPagedPool, processUserBytes, 'TOK');
//	if (processUser == NULL) {
//		DbgPrint("Cannot allocate %u token information bytes for process %u", processUserBytes, ProcID);
//		status = STATUS_INSUFFICIENT_RESOURCES;
//		goto Cleanup;
//	}
//
//	// Get user information for the process token
//	status = ZwQueryInformationToken(processToken, TokenUser, processUser, processUserBytes, &processUserBytes);
//	if (!NT_SUCCESS(status)) {
//		DbgPrint("Cannot get token information for process %u: %08X", ProcID, status);
//		goto Cleanup;
//	}
//
//	status = SecLookupAccountSid(processUser->User.Sid, &ownerSize, &owner, NULL, NULL, &eUse);
//	if (!NT_SUCCESS(status))
//	{
//		DbgPrint("Cannot convert SID to name for process %u: %08X", ProcID, status);
//		goto Cleanup;
//	}
//
//	for (UINT i = 0; i < sizeof(ExpAllowedPaths) / sizeof(UNICODE_STRING); i++)
//	{
//		RtlInitEmptyUnicodeString(&ExpAllowedPaths[i], PathBuffers[i], 520);
//	}
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[0], &ProfilesDirectoryPath);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[1], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[1], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[1], &owner);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[2], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[2], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[2], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[2], &ExpAllowedPartialPaths[2]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[3], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[3], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[3], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[3], &ExpAllowedPartialPaths[3]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[4], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[4], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[4], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[4], &ExpAllowedPartialPaths[4]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[5], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[5], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[5], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[5], &ExpAllowedPartialPaths[5]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[6], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[6], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[6], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[6], &ExpAllowedPartialPaths[6]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[7], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[7], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[7], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[7], &ExpAllowedPartialPaths[7]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[8], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[8], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[8], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[8], &ExpAllowedPartialPaths[8]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[9], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[9], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[9], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[9], &ExpAllowedPartialPaths[9]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[10], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[10], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[10], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[10], &ExpAllowedPartialPaths[10]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[11], &PublicPath);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[12], &PublicPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[12], &ExpAllowedPartialPaths[12]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[13], &WinRootPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[13], &ExpAllowedPartialPaths[13]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[14], &WinRootPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[14], &ExpAllowedPartialPaths[14]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[15], &WinRootPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[15], &ExpAllowedPartialPaths[15]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[16], &ProgramDataPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[16], &ExpAllowedPartialPaths[16]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[17], &ProgramDataPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[17], &ExpAllowedPartialPaths[17]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[18], &ProgramDataPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[18], &ExpAllowedPartialPaths[18]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[19], &ProgramDataPath); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[19], &ExpAllowedPartialPaths[19]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[20], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[20], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[20], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[20], &ExpAllowedPartialPaths[20]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[21], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[21], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[21], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[21], &ExpAllowedPartialPaths[21]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[22], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[22], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[22], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[22], &ExpAllowedPartialPaths[22]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[23], &ProfilesDirectoryPath); 
//	RtlAppendUnicodeToString(&ExpAllowedPaths[23], L"\\");  
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[23], &owner); 
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[23], &ExpAllowedPartialPaths[23]);
//
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[24], &ProgramDataPath);
//	RtlAppendUnicodeStringToString(&ExpAllowedPaths[24], &ExpAllowedPartialPaths[24]);
//
//	for (UINT i = 0; i < sizeof(OthAllowedPaths) / sizeof(UNICODE_STRING); i++)
//	{
//		RtlInitEmptyUnicodeString(&OthAllowedPaths[i], OthPathBuffers[i], 520);
//		/*RtlAppendUnicodeStringToString(&OthAllowedPaths[i], &ProfilesDirectoryPath);
//		RtlAppendUnicodeToString(&OthAllowedPaths[i], L"\\"); 
//		RtlAppendUnicodeStringToString(&OthAllowedPaths[i], &owner);
//		RtlAppendUnicodeStringToString(&OthAllowedPaths[i], &OthAllowedPartialPaths[i]);*/
//	}
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[0], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[0], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[0], &owner);
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[0], &OthAllowedPartialPaths[0]);
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[1], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[1], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[1], &owner);
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[1], &OthAllowedPartialPaths[1]);
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[2], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[2], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[2], &owner);
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[2], &OthAllowedPartialPaths[2]);
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[3], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[3], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[3], &owner);
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[3], &OthAllowedPartialPaths[3]);
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[4], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[4], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[4], &owner);
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[4], &OthAllowedPartialPaths[4]);
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[5], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[5], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[5], &owner);
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[5], &OthAllowedPartialPaths[5]);
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[6], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[6], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[6], &owner);
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[6], &OthAllowedPartialPaths[6]);
//
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[7], &ProfilesDirectoryPath);
//	RtlAppendUnicodeToString(&OthAllowedPaths[7], L"\\");
//	RtlAppendUnicodeStringToString(&OthAllowedPaths[7], &owner);
//
//
//	for (UINT i = 0; i < sizeof(ExpAllowedPaths) / sizeof(UNICODE_STRING); i++)
//	{
//		RtlUpcaseUnicodeString(&ExpAllowedPaths[i], &ExpAllowedPaths[i], FALSE);
//	}
//
//	for (UINT i = 0; i < sizeof(OthAllowedPaths) / sizeof(UNICODE_STRING); i++)
//	{
//		RtlUpcaseUnicodeString(&OthAllowedPaths[i], &OthAllowedPaths[i], FALSE);
//	}
//
//	status = STATUS_ACCESS_DENIED;
//	if (_stricmp(ProcessName, "explorer.exe") == 0)
//	{
//		for (UINT i = 0; i < sizeof(ExpAllowedPaths) / sizeof(UNICODE_STRING); i++)
//		{
//			if (FsRtlIsNameInExpression(&ExpAllowedPaths[i], FullPath, TRUE, NULL))
//			{
//				status = STATUS_SUCCESS;
//				goto Cleanup;
//			}
//		}
//	}
//	else
//	{
//		for (UINT i = 0; i < sizeof(OthAllowedPaths) / sizeof(UNICODE_STRING); i++)
//		{
//			if (FsRtlIsNameInExpression(&OthAllowedPaths[i], FullPath, TRUE, NULL))
//			{
//				status = STATUS_SUCCESS;
//				goto Cleanup;
//			}
//		}
//	}
//Cleanup:
//	if (processToken) {
//		ZwClose(processToken);
//	}
//	if (processUser) {
//		ExFreePoolWithTag(processUser, 'TOK');
//		processUser = NULL;
//	}
//	if (handle) {
//		ZwClose(handle);
//	}
//	if (sid.Buffer)
//	{
//		RtlFreeUnicodeString(&sid);
//	}
//	/*if (owner.Buffer)
//	{
//		RtlFreeUnicodeString(&owner);
//	}*/
//	if (PathBuffers)
//	{
//		ExFreePoolWithTag(PathBuffers, 'ftr1');
//	}
//	if (OthPathBuffers)
//	{
//		ExFreePoolWithTag(OthPathBuffers, 'ftr1');
//	}
//	if (NT_SUCCESS(status))
//	{
//		return TRUE;
//	}
//	else
//	{
//		return FALSE;
//	}
//}

VOID ArvCleanLog()
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&LogResource);
	bReady = FALSE;
	ExReleaseResourceAndLeaveCriticalRegion(&LogResource);
}

VOID ArvDeleteLogResource()
{
	ExDeleteResourceLite(&LogResource);
}

NTSTATUS ArvInitLog(PFLT_FILTER pFilter)
{
	ExInitializeResourceLite(&LogResource);
	return STATUS_SUCCESS;
}

NTSTATUS GetOwnerNameByProcID2(__in ULONG ProcID, __in UINT bufLen, __inout PWSTR name, __out PUINT len)
{
	NTSTATUS    status;
	HANDLE      processToken = NULL;
	TOKEN_USER *processUser = NULL;
	ULONG       processUserBytes = 0;
	UNICODE_STRING sid = { 0 };
	HANDLE handle;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	CLIENT_ID clientid = { 0 };

	UNICODE_STRING owner = { 0 };
	//BYTE ownerBuffer[256] = { 0 };
	//ULONG ownerSize = 1;
	SID_NAME_USE eUse = SidTypeUnknown;
	RtlInitEmptyUnicodeString(&owner, name, bufLen);
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

	status = SecLookupAccountSid(processUser->User.Sid, len, &owner, NULL, NULL, &eUse);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Cannot convert SID to name for process %u: %08X", ProcID, status);
		goto Cleanup;
	}
Cleanup:
	if (processToken) {
		ZwClose(processToken);
	}
	if (processUser) {
		ExFreePoolWithTag(processUser, 'TOK');
		processUser = NULL;
	}
	if (handle) {
		ZwClose(handle);
	}
	if (sid.Buffer)
	{
		RtlFreeUnicodeString(&sid);
	}
	return status;
}

NTSTATUS ArvQuerySymbolicLink(
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
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
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
	LinkTarget->Buffer = ExAllocatePoolWithTag(NonPagedPool, LinkTarget->MaximumLength, 'SOD');
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

NTSTATUS ArvWriteLog(PCWSTR type, PUNICODE_STRING path, UINT procID, PSTR processName, BOOLEAN read, BOOLEAN isFolder, BOOLEAN pass)
{
	HANDLE LogFileHandle = { 0 };
	PFILE_OBJECT LogFileObject = { 0 };
	PFLT_INSTANCE LogFileInstance = { 0 };
	PFLT_VOLUME LogVolume = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjectAttributes;  //OBJECT_ATTRIBUTES结构
	//UNICODE_STRING LogFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\filter.log"); //源文件
	//UNICODE_STRING  LogVolumeName = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume2");
	UNICODE_STRING  LogVolumeName = { 0 };
	PVOID Buffer = NULL;
	UNICODE_STRING String = { 0 };
	IO_STATUS_BLOCK IoStatusBlock;
	//ExInitializeResourceLite(&LogResource);
	//初始化OBJECT_ATTRIBUTES结构体

	ExEnterCriticalRegionAndAcquireResourceExclusive(&LogResource);
	if (!bReady)
	{
		goto CLEAN;
	}
	PUNICODE_STRING pLog = NULL;
	if (LogFlag == 1 && LogOnly == 2)
	{
		pLog = &LogPath;
	}
	else if (LogFlag == 1 && LogOnly == 1)
	{
		pLog = &SillegalLogPath;
	}
	else if (LogFlag == 1 && LogOnly == 0)
	{
		pLog = &IllegalLogPath;
	}
	else
	{
		goto CLEAN;
	}
	USHORT pathLen = pLog->Length;
	pLog->Length = 12;
	Status = ArvQuerySymbolicLink(pLog, &LogVolumeName);
	pLog->Length = pathLen;
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}
	InitializeObjectAttributes(
		&ObjectAttributes,
		pLog,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	
	LogFileInstance = XBFltGetVolumeInstance(g_minifilterHandle, &LogVolumeName);
	if (!LogFileInstance)
	{
		goto CLEAN;
	}
	//以FILE_OVERWRITE_IF方式打开
	Status = FltCreateFile(
		g_minifilterHandle,
		LogFileInstance,
		&LogFileHandle,
		FILE_APPEND_DATA | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Open source file fault !! - %#x\n", Status);
		goto CLEAN;
	}
	/*if (LogFileObject)
	{
		Status = FltGetVolumeFromFileObject(g_minifilterHandle, LogFileObject, &LogVolume);
		if (NT_SUCCESS(Status))
		{
			Status = FltGetVolumeInstanceFromName(g_minifilterHandle, LogVolume, NULL, &LogInstance);
		}
	}
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}*/
	
	Status = ObReferenceObjectByHandle(LogFileHandle, 0, NULL, KernelMode, &LogFileObject, NULL);

	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}



	//UNICODE_STRING LogFilePath = RTL_CONSTANT_STRING(L"\\??\\D:\\arv\\filter.log");
	
	
	Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 1024, 'LogT');
	if (NULL == Buffer)
	{
		goto CLEAN;
	}
	//初始化字符串指针
	RtlInitEmptyUnicodeString(&String, Buffer, 512 * sizeof(WCHAR));
	//拷贝字符串
	RtlAppendUnicodeToString(&String, type);
	RtlAppendUnicodeToString(&String, L" - ");
	RtlAppendUnicodeStringToString(&String, path);
	RtlAppendUnicodeToString(&String, L" - ");
	char intbuf[16];
	UNICODE_STRING procIDStr;
	RtlInitEmptyUnicodeString(&procIDStr, intbuf, 16);
	RtlIntegerToUnicodeString(procID, 10, &procIDStr);
	RtlAppendUnicodeStringToString(&String, &procIDStr);
	RtlAppendUnicodeToString(&String, L" - ");
	//追加Unicode变量
	UNICODE_STRING uniProcess = { 0 };

	ANSI_STRING AnsiString;
	RtlInitAnsiString(&AnsiString, processName);

	char buf[128];
	RtlInitEmptyUnicodeString(&uniProcess, buf, 128);
	RtlAnsiStringToUnicodeString(&uniProcess, &AnsiString, FALSE);
	RtlAppendUnicodeStringToString(&String, &uniProcess);

	WCHAR ownerName[128];
	UINT ownerNameLen = 0;
	Status = GetOwnerNameByProcID2(procID, 128, ownerName, &ownerNameLen);
	UNICODE_STRING uOwnerName = { 0 };
	RtlInitUnicodeString(&uOwnerName, ownerName);
	uOwnerName.Length = uOwnerName.MaximumLength = ownerNameLen;
	RtlAppendUnicodeToString(&String, L" - ");
	RtlAppendUnicodeStringToString(&String, &uOwnerName);

	if (read)
	{
		RtlAppendUnicodeToString(&String, L" - read");
	}
	else
	{
		RtlAppendUnicodeToString(&String, L" - write");
	}

	if (isFolder)
	{
		RtlAppendUnicodeToString(&String, L" - folder");
	}
	else
	{
		RtlAppendUnicodeToString(&String, L" - file");
	}

	if (pass)
	{
		RtlAppendUnicodeToString(&String, L" - yes\n");
	}
	else
	{
		RtlAppendUnicodeToString(&String, L" - no\n");
	}
	/*if (!LogFileInstance)
	{
		goto CLEAN;
	}*/
	FILE_STANDARD_INFORMATION fileInfo = { 0 };
	Status = FltQueryInformationFile(LogFileInstance, LogFileObject, &fileInfo, sizeof(fileInfo), FileStandardInformation, NULL);
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}
	
	//写入文件
	USHORT Length = String.Length;
	Status = FltWriteFile(
		LogFileInstance,
		LogFileObject,
		&fileInfo.EndOfFile,
		Length,
		Buffer,
		NULL,
		NULL,
		NULL,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("写入源文件失败!!\n - %#X", Status);
	}
	else
	{
		Offset.QuadPart += Length;
	}
CLEAN:
	if (LogVolumeName.Buffer)
	{
		ExFreePool(LogVolumeName.Buffer);
		LogVolumeName.Buffer = NULL;
	}
	if (LogVolume)
	{
		FltObjectDereference(LogVolume);
	}
	if (LogFileInstance)
	{
		FltObjectDereference(LogFileInstance);
	}
	if (LogFileObject)
	{
		FltClose(LogFileHandle);
		ObDereferenceObject(LogFileObject);
	}
	if (Buffer)
	{
		ExFreePool(Buffer);
	}
	ExReleaseResourceAndLeaveCriticalRegion(&LogResource);
	return Status;
}

NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING *PProcessImageName)
{
	NTSTATUS status;
	ULONG returnedLength;
	ULONG bufferLength;
	PVOID buffer;
	PUNICODE_STRING imageName;
	HANDLE handle = NULL;;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID clientid;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (NULL == ZwQueryInformationProcess) {
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (NULL == ZwQueryInformationProcess) {
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			status = STATUS_UNSUCCESSFUL;
			goto Cleanup;
		}
	}
	//
	// Get process handle
	//
	InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
	clientid.UniqueProcess = (HANDLE)processId;
	clientid.UniqueThread = 0;
	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientid);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot open token for process %u: %08X", processId, status);
		goto Cleanup;
	}
	//
	// Step one - get the size we need
	//
	status = ZwQueryInformationProcess(handle,
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		goto Cleanup;
	}

	//
	// Is the passed-in buffer going to be big enough for us? 
	// This function returns a single contguous buffer model...
	//
	// bufferLength = returnedLength - sizeof(UNICODE_STRING);
	//
	// if (ProcessImageName->MaximumLength < bufferLength) {
	// 	ProcessImageName->Length = (USHORT)bufferLength;
	// 	status = STATUS_BUFFER_OVERFLOW;
	// 	goto Cleanup;
	// }

	//
	// If we get here, the buffer IS going to be big enough for us, so
	// let's allocate some storage.
	//
	buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'ipgD');
	if (NULL == buffer) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	//
	// Now lets go get the data
	//
	status = ZwQueryInformationProcess(handle,
		ProcessImageFileName,
		buffer,
		returnedLength,
		&returnedLength);

	if (NT_SUCCESS(status)) {
		//
		// Ah, we got what we needed
		//
		*PProcessImageName = (PUNICODE_STRING)buffer;
	}
Cleanup:
	//
	// free process handle
	//
	//if (buffer)
	//	ExFreePool(buffer);
	if (handle) {
		ZwClose(handle);
	}
	//
	// And tell the caller what happened.
	//   
	return status;

}

NTSTATUS ArvClearFileEx(LogType type)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE LogFileHandle = { 0 };
	PFILE_OBJECT LogFileObject = { 0 };
	PFLT_INSTANCE LogFileInstance = { 0 };
	UNICODE_STRING  LogVolumeName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	PUNICODE_STRING pLog = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	PFILE_RENAME_INFORMATION pFileRenameInformation = NULL;
	ExEnterCriticalRegionAndAcquireResourceExclusive(&LogResource);
	switch (type)
	{
	case LEARN:
		pLog = &LogPath;
		break;
	case VERIFY:
		pLog = &SillegalLogPath;
		break;
	case ENABLE:
		pLog = &IllegalLogPath;
		break;
	case ABNORMAL:
		pLog = &AbnormalLogPath;
		break;
	}
	if (pLog == NULL)
	{
		goto CLEAN;
	}
	USHORT pathLen = pLog->Length;
	pLog->Length = 12;
	Status = ArvQuerySymbolicLink(pLog, &LogVolumeName);
	pLog->Length = pathLen;
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}
	InitializeObjectAttributes(
		&ObjectAttributes,
		pLog,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	LogFileInstance = XBFltGetVolumeInstance(g_minifilterHandle, &LogVolumeName);
	if (!LogFileInstance)
	{
		goto CLEAN;
	}
	Status = FltCreateFile(
		g_minifilterHandle,
		LogFileInstance,
		&LogFileHandle,
		DELETE | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}
	Status = ObReferenceObjectByHandle(LogFileHandle, 0, NULL, KernelMode, &LogFileObject, NULL);
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}
	pFileRenameInformation = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_RENAME_INFORMATION) + pLog->Length + 4 * sizeof(WCHAR), 'frni');
	RtlZeroMemory(pFileRenameInformation, sizeof(FILE_RENAME_INFORMATION) + pLog->Length + 4 * sizeof(WCHAR));
	pFileRenameInformation->ReplaceIfExists = FALSE;
	pFileRenameInformation->RootDirectory = NULL;
	pFileRenameInformation->FileNameLength = pLog->Length + 4 * sizeof(WCHAR);
	UNICODE_STRING tmpStr = { 0 };
	tmpStr.Buffer = pFileRenameInformation->FileName;
	tmpStr.MaximumLength = pLog->Length + 4 * sizeof(WCHAR) + 1;
	RtlAppendUnicodeStringToString(&tmpStr, pLog);
	RtlAppendUnicodeToString(&tmpStr, L".bak");
	/*wcscpy_s(pFileRenameInformation->FileName, pLog->Length / sizeof(wchar_t) + 1, pLog->Buffer);
	wcscpy_s(&pFileRenameInformation->FileName[pLog->Length / sizeof(wchar_t)], 5, L".bak");*/
	Status = FltSetInformationFile(LogFileInstance, LogFileObject, pFileRenameInformation, sizeof(FILE_RENAME_INFORMATION), FileRenameInformation);
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}

	/*FILE_ALLOCATION_INFORMATION fileInformation;
	fileInformation.AllocationSize.QuadPart = 0;
	Status = FltSetInformationFile(LogFileInstance, LogFileObject, &fileInformation, sizeof(FILE_ALLOCATION_INFORMATION), FileAllocationInformation);
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}*/
CLEAN:
	if (pFileRenameInformation)
	{
		ExFreePoolWithTag(pFileRenameInformation, 'frni');
	}
	if (LogVolumeName.Buffer)
	{
		ExFreePool(LogVolumeName.Buffer);
		LogVolumeName.Buffer = NULL;
	}
	if (LogFileObject)
	{
		ObDereferenceObject(LogFileObject);
	}
	if (LogFileHandle)
	{
		FltClose(LogFileHandle);
	}
	if (LogFileInstance)
	{
		FltObjectDereference(LogFileInstance);
	}
	ExReleaseResourceAndLeaveCriticalRegion(&LogResource);
	return Status;
}

NTSTATUS ArvWriteLogEx(PCWSTR type, PUNICODE_STRING path, PLIST_ENTRY pProcHead, BOOLEAN read, BOOLEAN isFolder, BOOLEAN pass, BOOLEAN abnormal) {
	HANDLE LogFileHandle = { 0 };
	PFILE_OBJECT LogFileObject = { 0 };
	PFLT_INSTANCE LogFileInstance = { 0 };
	PFLT_VOLUME LogVolume = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjectAttributes;  //OBJECT_ATTRIBUTES结构
	//UNICODE_STRING LogFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\filter.log"); //源文件
	//UNICODE_STRING  LogVolumeName = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume2");
	UNICODE_STRING  LogVolumeName = { 0 };
	PVOID Buffer = NULL;
	UNICODE_STRING String = { 0 };
	UNICODE_STRING logType = { 0 };
	WCHAR logTypeBuf[10];
	UNICODE_STRING timestamp = { 0 };
	WCHAR timestampBuf[20];
	IO_STATUS_BLOCK IoStatusBlock;

	RtlInitEmptyUnicodeString(&logType, logTypeBuf, 10 * sizeof(WCHAR));
	RtlInitEmptyUnicodeString(&timestamp, timestampBuf, 20 * sizeof(WCHAR));

	//ExInitializeResourceLite(&LogResource);
	//初始化OBJECT_ATTRIBUTES结构体

	ExEnterCriticalRegionAndAcquireResourceExclusive(&LogResource);
	if (!bReady)
	{
		goto CLEAN;
	}
	PUNICODE_STRING pLog = NULL;
	if (abnormal)
	{
		pLog = &AbnormalLogPath;
		RtlAppendUnicodeToString(&logType, L"abnormal");
		if (!pass)
		{
			InterlockedIncrement64(&filterConfig.abnormalCount);
		}
	}
	else
	{
		if (LogFlag == 1 && LogOnly == 2)
		{
			pLog = &LogPath;
			RtlAppendUnicodeToString(&logType, L"learn");
		}
		else if (LogFlag == 1 && LogOnly == 1)
		{
			pLog = &SillegalLogPath;
			RtlAppendUnicodeToString(&logType, L"verify");
			if (!pass)
			{
				InterlockedIncrement64(&filterConfig.sillegalCount);
			}
		}
		else if (LogFlag == 1 && LogOnly == 0)
		{
			pLog = &IllegalLogPath;
			RtlAppendUnicodeToString(&logType, L"enable");
			if (!pass)
			{
				InterlockedIncrement64(&filterConfig.illegalCount);
			}
		}
		else
		{
			goto CLEAN;
		}
	}
	
	USHORT pathLen = pLog->Length;
	pLog->Length = 12;
	Status = ArvQuerySymbolicLink(pLog, &LogVolumeName);
	pLog->Length = pathLen;
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}

	InitializeObjectAttributes(
		&ObjectAttributes,
		pLog,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	LogFileInstance = XBFltGetVolumeInstance(g_minifilterHandle, &LogVolumeName);
	if (!LogFileInstance)
	{
		goto CLEAN;
	}
	//以FILE_OVERWRITE_IF方式打开
	Status = FltCreateFile(
		g_minifilterHandle,
		LogFileInstance,
		&LogFileHandle,
		//&LogFileObject,
		FILE_APPEND_DATA | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Open source file fault !! - %#x\n", Status);
		goto CLEAN;
	}
	/*if (LogFileObject)
	{
		Status = FltGetVolumeFromFileObject(g_minifilterHandle, LogFileObject, &LogVolume);
		if (NT_SUCCESS(Status))
		{
			Status = FltGetVolumeInstanceFromName(g_minifilterHandle, LogVolume, NULL, &LogInstance);
		}
	}
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}*/

	Status = ObReferenceObjectByHandle(LogFileHandle, 0, NULL, KernelMode, &LogFileObject, NULL);

	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}

	//UNICODE_STRING LogFilePath = RTL_CONSTANT_STRING(L"\\??\\D:\\arv\\filter.log");
	ULONG bufsize = 18 + path->Length + 49 + 56 + 80; //{"path":"xxx","type":"r","procs":["aaa","bbb","ccc"],"folder":"y","pass":"n","time":1673578456,"logtype":"abnormal"}\n
	for (UINT i = 0; i < path->Length / sizeof(wchar_t); i++) {
		if (path->Buffer[i] == L'\\')
		{
			bufsize += sizeof(wchar_t);
		}
	}
	if (pProcHead)
	{
		PLIST_ENTRY pListEntry = pProcHead->Flink;
		while (pListEntry != pProcHead)
		{
			PProcEntry pProcEntry = CONTAINING_RECORD(pListEntry, ProcEntry, entry);
			PUNICODE_STRING pTempStr = NULL;
			UNICODE_STRING procStr = { 0 };
			Status = GetProcessImageName(pProcEntry->ProcID, &pTempStr);
			if (!NT_SUCCESS(Status))
			{
				if (pTempStr)
				{
					ExFreePoolWithTag(pTempStr, 'ipgD');
				}
				//goto CLEAN;
			}
			else
			{
				UINT procNameLen = 0;
				INT i = pTempStr->Length / sizeof(wchar_t) - 1;
				for (; i >= 0; i--) {
					if (pTempStr->Buffer[i] == L'\\')
					{
						break;
					}
					procNameLen += sizeof(wchar_t);
				}
				procStr.Buffer = &pTempStr->Buffer[(pTempStr->Length - procNameLen)/sizeof(wchar_t)];
				if (procNameLen > 28)
				{
					procNameLen = 28;
				}
				procStr.Length = procStr.MaximumLength = procNameLen;
				bufsize += procNameLen;
				bufsize += 6;
				if (pTempStr)
				{
					ExFreePoolWithTag(pTempStr, 'ipgD');
					pTempStr = NULL;
				}

				/*bufsize += pTempStr->Length;
				bufsize += 6;
				for (UINT i = 0; i < pTempStr->Length / sizeof(wchar_t); i++) {
					if (pTempStr->Buffer[i] == L'\\')
					{
						bufsize += sizeof(wchar_t);
					}
				}
				ExFreePoolWithTag(pTempStr, 'ipgD');
				pTempStr = NULL;*/
			}
			pListEntry = pListEntry->Flink;
		}
	}
	Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, bufsize, 'LogT');
	if (NULL == Buffer)
	{
		goto CLEAN;
	}
	//初始化字符串指针
	RtlInitEmptyUnicodeString(&String, Buffer, bufsize);
	//拷贝字符串
	RtlAppendUnicodeToString(&String, L"{\"E\":\"");
	//RtlAppendUnicodeStringToString(&String, path);
	for (UINT i = 0; i < path->Length / sizeof(wchar_t); i++)
	{
		String.Buffer[String.Length / sizeof(wchar_t)] = path->Buffer[i];
		String.Length += sizeof(wchar_t);
		//String.MaximumLength = String.Length;
		if (path->Buffer[i] == L'\\')
		{
			String.Buffer[String.Length / sizeof(wchar_t)] = path->Buffer[i];
			String.Length += sizeof(wchar_t);
			//String.MaximumLength = String.Length;
		}
	}
	RtlAppendUnicodeToString(&String, L"\",\"B\":\"");
	/*if (read)
	{
		RtlAppendUnicodeToString(&String, L"r");
	}
	else
	{
		RtlAppendUnicodeToString(&String, L"w");
	}*/
	RtlAppendUnicodeToString(&String, type);
	RtlAppendUnicodeToString(&String, L"\",\"D\":[");
	if (pProcHead)
	{
		PLIST_ENTRY pListEntry = pProcHead->Flink;
		while (pListEntry != pProcHead)
		{
			PProcEntry pProcEntry = CONTAINING_RECORD(pListEntry, ProcEntry, entry);
			PUNICODE_STRING pTempStr = NULL;
			UNICODE_STRING procStr = { 0 };
			Status = GetProcessImageName(pProcEntry->ProcID, &pTempStr);
			if (!NT_SUCCESS(Status))
			{
				if (pTempStr)
				{
					ExFreePoolWithTag(pTempStr, 'ipgD');
				}
				//goto CLEAN;
			}
			else
			{
				RtlAppendUnicodeToString(&String, L"\"");
				UINT procNameLen = 0;
				INT i = pTempStr->Length / sizeof(wchar_t) - 1;
				for (; i >= 0; i--) {
					if (pTempStr->Buffer[i] == L'\\')
					{
						break;
					}
					procNameLen += sizeof(wchar_t);
				}
				procStr.Buffer = &pTempStr->Buffer[(pTempStr->Length - procNameLen)/sizeof(wchar_t)];
				if (procNameLen > 28)
				{
					procNameLen = 28;
				}
				procStr.Length = procStr.MaximumLength = procNameLen;
				for (UINT i = 0; i < procStr.Length / sizeof(wchar_t); i++)
				{
					String.Buffer[String.Length / sizeof(wchar_t)] = procStr.Buffer[i];
					String.Length += sizeof(wchar_t);
					if (procStr.Buffer[i] == L'\\')
					{
						String.Buffer[String.Length / sizeof(wchar_t)] = procStr.Buffer[i];
						String.Length += sizeof(wchar_t);
					}
				}
				RtlAppendUnicodeToString(&String, L"\",");
				if (pTempStr)
				{
					ExFreePoolWithTag(pTempStr, 'ipgD');
					pTempStr = NULL;
				}

				//RtlAppendUnicodeToString(&String, L"\"");
				////RtlAppendUnicodeStringToString(&String, pTempStr);
				//for (UINT i = 0; i < pTempStr->Length / sizeof(wchar_t); i++)
				//{
				//	String.Buffer[String.Length / sizeof(wchar_t)] = pTempStr->Buffer[i];
				//	String.Length += sizeof(wchar_t);
				//	//String.MaximumLength = String.Length;
				//	if (pTempStr->Buffer[i] == L'\\')
				//	{
				//		String.Buffer[String.Length / sizeof(wchar_t)] = pTempStr->Buffer[i];
				//		String.Length += sizeof(wchar_t);
				//		//String.MaximumLength = String.Length;
				//	}
				//}
				//RtlAppendUnicodeToString(&String, L"\",");
				//ExFreePoolWithTag(pTempStr, 'ipgD');
				//pTempStr = NULL;
			}
			pListEntry = pListEntry->Flink;
		}
		String.Length -= sizeof(wchar_t);
	}
	RtlAppendUnicodeToString(&String, L"],\"folder\":\"");
	if (isFolder)
	{
		RtlAppendUnicodeToString(&String, L"y");
	}
	else
	{
		RtlAppendUnicodeToString(&String, L"n");
	}
	RtlAppendUnicodeToString(&String, L"\",\"pass\":\"");
	if (pass)
	{
		RtlAppendUnicodeToString(&String, L"y");
	}
	else
	{
		RtlAppendUnicodeToString(&String, L"n");
	}
	RtlAppendUnicodeToString(&String, L"\",\"A\":");
	ULONG now = ArvGetUnixTimestamp();
	Status = RtlIntegerToUnicodeString(now, 10, &timestamp);
	RtlAppendUnicodeStringToString(&String, &timestamp);
	RtlAppendUnicodeToString(&String, L",\"C\":\"");
	RtlAppendUnicodeStringToString(&String, &logType);
	RtlAppendUnicodeToString(&String, L"\"}\r\n");

	/*if (!LogFileInstance)
	{
		goto CLEAN;
	}*/
	FILE_STANDARD_INFORMATION fileInfo = { 0 };
	Status = FltQueryInformationFile(LogFileInstance, LogFileObject, &fileInfo, sizeof(fileInfo), FileStandardInformation, NULL);
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}

	//写入文件
	USHORT Length = String.Length;
	Status = FltWriteFile(
		LogFileInstance,
		LogFileObject,
		&fileInfo.EndOfFile,
		Length,
		Buffer,
		NULL,
		NULL,
		NULL,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("写入源文件失败!!\n - %#X", Status);
	}
	else
	{
		Offset.QuadPart += Length;
	}
CLEAN:
	if (LogVolumeName.Buffer)
	{
		ExFreePool(LogVolumeName.Buffer);
		LogVolumeName.Buffer = NULL;
	}
	if (Buffer)
	{
		ExFreePool(Buffer);
	}
	if (LogFileObject)
	{
		ObDereferenceObject(LogFileObject);
		//FltClose(LogFileHandle);
	}
	if (LogFileHandle)
	{
		FltClose(LogFileHandle);
	}
	if (LogFileInstance)
	{
		FltObjectDereference(LogFileInstance);
	}
	if (LogVolume)
	{
		FltObjectDereference(LogVolume);
	}
	ExReleaseResourceAndLeaveCriticalRegion(&LogResource);
	return Status;
}