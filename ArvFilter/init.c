#include "init.h"
#include "config.h"

#define SYSTEMPROCESSINFORMATION 5
//���������Ϣ����Ҫ�õ��������ṹ��
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

//������Ϣ�ṹ��  
typedef struct _SYSTEM_PROCESSES
{
	ULONG                           NextEntryDelta;    //������һ���ṹ����һ���ṹ��ƫ��
	ULONG                           ThreadCount;
	ULONG                           Reserved[6];
	LARGE_INTEGER                   CreateTime;
	LARGE_INTEGER                   UserTime;
	LARGE_INTEGER                   KernelTime;
	UNICODE_STRING                  ProcessName;     //��������
	KPRIORITY                       BasePriority;
	SIZE_T                           ProcessId;      //���̵�pid��
	SIZE_T                           InheritedFromProcessId;
	ULONG                           HandleCount;
	ULONG                           Reserved2[2];
	VM_COUNTERS                     VmCounters;
	IO_COUNTERS                     IoCounters; //windows 2000 only  
	struct _SYSTEM_THREADS          Threads[1];
}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

//����ZqQueryAyatemInformation
NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,  //���������Ϣ,ֻ��Ҫ�������Ϊ5�ļ���
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);

LIST_ENTRY AllowedProcs;

NTSTATUS InitProcessList()
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	ULONG retLength;  //����������
	PVOID pProcInfo;
	PSYSTEM_PROCESSES pProcIndex;
	InitializeListHead(&AllowedProcs);
	//���ú�������ȡ������Ϣ
	nStatus = ZwQuerySystemInformation(
		SYSTEMPROCESSINFORMATION,   //��ȡ������Ϣ,�궨��Ϊ5
		NULL,
		0,
		&retLength  //���صĳ��ȣ���Ϊ������Ҫ����Ļ������ĳ���
	);
	if (!retLength)
	{
		DbgPrint("ZwQuerySystemInformation error!\n");
		return nStatus;
	}
	DbgPrint("retLength =  %u\n", retLength);
	//����ռ�
	pProcInfo = ExAllocatePool(NonPagedPool, retLength);
	if (!pProcInfo)
	{
		DbgPrint("ExAllocatePool error!\n");
		return STATUS_UNSUCCESSFUL;
	}
	nStatus = ZwQuerySystemInformation(
		SYSTEMPROCESSINFORMATION,   //��ȡ������Ϣ,�궨��Ϊ5
		pProcInfo,
		retLength,
		&retLength
	);
	if (NT_SUCCESS(nStatus)/*STATUS_INFO_LENGTH_MISMATCH == nStatus*/)
	{
		pProcIndex = (PSYSTEM_PROCESSES)pProcInfo;
		//��һ������Ӧ���� pid Ϊ 0 �Ľ���
		if (pProcIndex->ProcessId == 0)
			DbgPrint("PID 0 System Idle Process\n");
		//ѭ����ӡ���н�����Ϣ,��Ϊ���һ����̵�NextEntryDeltaֵΪ0�������ȴ�ӡ���ж�
		do
		{
			pProcIndex = (PSYSTEM_PROCESSES)((char*)pProcIndex + pProcIndex->NextEntryDelta);
			//���������ַ���������ֹ��ӡʱ������
			if (pProcIndex->ProcessName.Buffer == NULL)
				pProcIndex->ProcessName.Buffer = L"NULL";
			DbgPrint("ProcName:  %-20ws     pid:  %u\n", pProcIndex->ProcessName.Buffer, pProcIndex->ProcessId);
			ArvAddProc(&AllowedProcs, pProcIndex->ProcessId);
		} while (pProcIndex->NextEntryDelta != 0);
	}
	else
	{
		DbgPrint("error code : %u!!!\n", nStatus);
	}
	ExFreePool(pProcInfo);
	return nStatus;
}

BOOLEAN ProcAllowed(ULONG ProcID)
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

VOID FreeAllowedProcs()
{
	ArvFreeProcs(&AllowedProcs);
}