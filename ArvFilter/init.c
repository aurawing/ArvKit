#include "pch.h"

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
////���������Ϣ����Ҫ�õ��������ṹ��
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
////������Ϣ�ṹ��  
//typedef struct _SYSTEM_PROCESSES
//{
//	ULONG                           NextEntryDelta;    //������һ���ṹ����һ���ṹ��ƫ��
//	ULONG                           ThreadCount;
//	ULONG                           Reserved[6];
//	LARGE_INTEGER                   CreateTime;
//	LARGE_INTEGER                   UserTime;
//	LARGE_INTEGER                   KernelTime;
//	UNICODE_STRING                  ProcessName;     //��������
//	KPRIORITY                       BasePriority;
//	SIZE_T                           ProcessId;      //���̵�pid��
//	SIZE_T                           InheritedFromProcessId;
//	ULONG                           HandleCount;
//	ULONG                           Reserved2[2];
//	VM_COUNTERS                     VmCounters;
//	IO_COUNTERS                     IoCounters; //windows 2000 only  
//	struct _SYSTEM_THREADS          Threads[1];
//}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;
//
////����ZqQueryAyatemInformation
//NTSTATUS ZwQuerySystemInformation(
//	IN ULONG SystemInformationClass,  //���������Ϣ,ֻ��Ҫ�������Ϊ5�ļ���
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
//	ULONG retLength;  //����������
//	PVOID pProcInfo;
//	PSYSTEM_PROCESSES pProcIndex;
//	PEPROCESS pProcess;
//	NTSTATUS ntStatus = STATUS_SUCCESS;
//	InitializeListHead(&AllowedProcs);
//	//���ú�������ȡ������Ϣ
//	nStatus = ZwQuerySystemInformation(
//		SYSTEMPROCESSINFORMATION,   //��ȡ������Ϣ,�궨��Ϊ5
//		NULL,
//		0,
//		&retLength  //���صĳ��ȣ���Ϊ������Ҫ����Ļ������ĳ���
//	);
//	if (!retLength)
//	{
//		DbgPrint("ZwQuerySystemInformation error!\n");
//		return nStatus;
//	}
//	DbgPrint("retLength =  %u\n", retLength);
//	//����ռ�
//	pProcInfo = ExAllocatePoolWithTag(NonPagedPool, retLength, 'PPIF');
//	if (!pProcInfo)
//	{
//		DbgPrint("ExAllocatePool error!\n");
//		return STATUS_UNSUCCESSFUL;
//	}
//	nStatus = ZwQuerySystemInformation(
//		SYSTEMPROCESSINFORMATION,   //��ȡ������Ϣ,�궨��Ϊ5
//		pProcInfo,
//		retLength,
//		&retLength
//	);
//	if (NT_SUCCESS(nStatus)/*STATUS_INFO_LENGTH_MISMATCH == nStatus*/)
//	{
//		pProcIndex = (PSYSTEM_PROCESSES)pProcInfo;
//		//��һ������Ӧ���� pid Ϊ 0 �Ľ���
//		if (pProcIndex->ProcessId == 0)
//			DbgPrint("PID 0 System Idle Process\n");
//		//ѭ����ӡ���н�����Ϣ,��Ϊ���һ����̵�NextEntryDeltaֵΪ0�������ȴ�ӡ���ж�
//		do
//		{
//			pProcIndex = (PSYSTEM_PROCESSES)((char*)pProcIndex + pProcIndex->NextEntryDelta);
//			//���������ַ���������ֹ��ӡʱ������
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
			FltObjectDereference(pInstance);
			break;
		}
	}

	for (index = 0; index < uRet; index++)
		FltObjectDereference(pVolumeList[index]);
	return pInstance;
}

VOID ArvCleanLog()
{
	/*if (LogVolume)
	{
		FltObjectDereference(LogVolume);
	}
	if (LogInstance)
	{
		FltObjectDereference(LogInstance);
	}
	if (LogFileObject)
	{
		FltClose(LogFileHandle);
		ObDereferenceObject(LogFileObject);
	}*/
	ExEnterCriticalRegionAndAcquireResourceExclusive(&LogResource);
	bReady = FALSE;
	ExReleaseResourceAndLeaveCriticalRegion(&LogResource);
	ExDeleteResourceLite(&LogResource);
}

NTSTATUS ArvInitLog(PFLT_FILTER pFilter)
{
	ExInitializeResourceLite(&LogResource);



	////HANDLE SourceFileHandle = NULL;      //Դ�ļ����
	////HANDLE TargetFileHandle = NULL;      //Ŀ���ļ����
	//NTSTATUS Status = STATUS_SUCCESS;    //����״̬
	//OBJECT_ATTRIBUTES ObjectAttributes;  //OBJECT_ATTRIBUTES�ṹ
	//UNICODE_STRING LogFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\filter.log"); //Դ�ļ�
	////UNICODE_STRING TargetFilePath = RTL_CONSTANT_STRING(L"\\??\\c:\\target.txt"); //Ŀ���ļ�
	////UNICODE_STRING String = { 0 };           //ָ��Buffer
	//IO_STATUS_BLOCK IoStatusBlock;         //���ؽ��״̬�ṹ��
	////PVOID Buffer = NULL;                   //bufferָ��
	////USHORT Length = 0;                     //Ҫ��д�ĳ���
	////LARGE_INTEGER Offset = { 0 };            //Ҫ��д��ƫ��

	//ExInitializeResourceLite(&LogResource);
	////��ʼ��OBJECT_ATTRIBUTES�ṹ��
	//InitializeObjectAttributes(
	//	&ObjectAttributes,
	//	&LogFilePath,
	//	OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
	//	NULL,
	//	NULL);

	////��FILE_OVERWRITE_IF��ʽ��
	//Status = FltCreateFile(
	//	pFilter,
	//	NULL,
	//	&LogFileHandle,
	//	&LogFileObject,
	//	GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
	//	&ObjectAttributes,
	//	&IoStatusBlock,
	//	NULL,
	//	FILE_ATTRIBUTE_NORMAL,
	//	FILE_SHARE_READ,
	//	FILE_OVERWRITE_IF,
	//	FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,
	//	NULL,
	//	0,
	//	0);
	//if (!NT_SUCCESS(Status))
	//{
	//	DbgPrint("Open source file fault !! - %#x\n", Status);
	//	return Status;
	//}
	//if (LogFileObject)
	//{
	//	Status = FltGetVolumeFromFileObject(pFilter, LogFileObject, &LogVolume);
	//	if (NT_SUCCESS(Status))
	//	{
	//		Status = FltGetVolumeInstanceFromName(pFilter, LogVolume, NULL, &LogInstance);
	//	}
	//}
	//if (!NT_SUCCESS(Status))
	//{
	//	ArvCleanLog();
	//}
	return STATUS_SUCCESS;
}

NTSTATUS ArvWriteLog(PCWSTR type, PUNICODE_STRING path, UINT procID, PSTR processName, BOOLEAN pass)
{
	HANDLE LogFileHandle = { 0 };
	PFILE_OBJECT LogFileObject = { 0 };
	PFLT_INSTANCE LogFileInstance = { 0 };
	PFLT_VOLUME LogVolume = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjectAttributes;  //OBJECT_ATTRIBUTES�ṹ
	UNICODE_STRING LogFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\filter.log"); //Դ�ļ�
	UNICODE_STRING  LogVolumeName = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume2");
	PVOID Buffer = NULL;
	UNICODE_STRING String = { 0 };
	IO_STATUS_BLOCK IoStatusBlock;
	//ExInitializeResourceLite(&LogResource);
	//��ʼ��OBJECT_ATTRIBUTES�ṹ��

	ExEnterCriticalRegionAndAcquireResourceExclusive(&LogResource);
	if (!bReady)
	{
		goto CLEAN;
	}
	InitializeObjectAttributes(
		&ObjectAttributes,
		&LogFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	
	LogFileInstance = XBFltGetVolumeInstance(g_minifilterHandle, &LogVolumeName);
	//��FILE_OVERWRITE_IF��ʽ��
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
	//��ʼ���ַ���ָ��
	RtlInitEmptyUnicodeString(&String, Buffer, 512 * sizeof(WCHAR));
	//�����ַ���
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
	//׷��Unicode����
	UNICODE_STRING uniProcess = { 0 };

	ANSI_STRING AnsiString;
	RtlInitAnsiString(&AnsiString, processName);

	char buf[128];
	RtlInitEmptyUnicodeString(&uniProcess, buf, 128);
	RtlAnsiStringToUnicodeString(&uniProcess, &AnsiString, FALSE);
	RtlAppendUnicodeStringToString(&String, &uniProcess);
	if (pass)
	{
		RtlAppendUnicodeToString(&String, L" - yes\n");
	}
	else
	{
		RtlAppendUnicodeToString(&String, L" - no\n");
	}

	FILE_STANDARD_INFORMATION fileInfo = { 0 };
	Status = FltQueryInformationFile(LogFileInstance, LogFileObject, &fileInfo, sizeof(fileInfo), FileStandardInformation, NULL);
	if (!NT_SUCCESS(Status))
	{
		goto CLEAN;
	}
	
	//д���ļ�
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
		DbgPrint("д��Դ�ļ�ʧ��!!\n - %#X", Status);
	}
	else
	{
		Offset.QuadPart += Length;
	}
CLEAN:
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