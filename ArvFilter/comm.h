#pragma once

#include <fltKernel.h>
#include <ntdef.h>
#include <windef.h>

#include "global.h"

#define MINI_PORT_NAME L"\\ArvCommPort"

#define SYSTEMPROCESSINFORMATION 5

NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);

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

typedef enum _OP_COMMAND {  //��������
	SET_PROC,
	SET_RULES,
	GET_STAT,
	SET_DB_CONF,
	SET_ALLOW_UNLOAD,
	SET_CONTROL_PROC,
	SET_REG_PROC,
} OpCommand;

typedef struct _OpGetStat { //��ȡͳ����Ϣ
	OpCommand command;
} OpGetStat, *POpGetStat;

typedef struct _OpSetProc { //��������
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

typedef struct _OpSetRules { //��������
	OpCommand command;
	ULONG controlProcID;
	POpRule *rules;
	UINT		ruleLen;
} OpSetRules, *POpSetRules;

typedef struct _OpSetDBConf { //����DB·��
	OpCommand command;
	UINT id;
	PWSTR path;
} OpSetDBConf, *POpSetDBConf;

typedef struct _OpSetAllowUnload { //��������ж������
	OpCommand command;
	BOOL allow;
} OpSetAllowUnload, *POpSetAllowUnload;

typedef struct _RepStat { //����ͳ����Ϣ
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

typedef struct _OpSetControlProc { //�޸Ŀ��ƽ���ID
	OpCommand command;
	ULONG controlProcID;
} OpSetControlProc, *POpSetControlProc;

typedef struct _OpRegProc {
	PSTR procName;
	BOOL inherit;
	UINT ruleID;
} OpRegProc, *POpRegProc;

typedef struct _OpSetRegProcs {
	OpCommand command;
	POpRegProc *regProcs;
	UINT		regProcLen;
} OpSetRegProcs, *POpSetRegProcs;

//�û�̬���ں�̬��������
NTSTATUS
MiniConnect(
	__in PFLT_PORT ClientPort,
	__in PVOID ServerPortCookie,
	__in_bcount(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
);

//�û�̬���ں˶Ͽ�����
VOID
MiniDisconnect(
	__in_opt PVOID ConnectionCookie
);

//�û�̬���ں�̬��������
NTSTATUS
MiniMessage(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
);