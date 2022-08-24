#pragma once

#include <fltKernel.h>
#include <ntdef.h>
#include <windef.h>

#include "global.h"

#define MINI_PORT_NAME L"\\ArvCommPort"

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

typedef enum _OP_COMMAND {  //操作命令
	SET_PROC,
	SET_RULES,
	GET_STAT,
	SET_DB_CONF,
	SET_ALLOW_UNLOAD,
	SET_CONTROL_PROC,
	SET_REG_PROC,
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

typedef struct _OpSetAllowUnload { //设置允许卸载驱动
	OpCommand command;
	BOOL allow;
} OpSetAllowUnload, *POpSetAllowUnload;

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

typedef struct _OpSetControlProc { //修改控制进程ID
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

//用户态和内核态建立连接
NTSTATUS
MiniConnect(
	__in PFLT_PORT ClientPort,
	__in PVOID ServerPortCookie,
	__in_bcount(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
);

//用户态和内核断开连接
VOID
MiniDisconnect(
	__in_opt PVOID ConnectionCookie
);

//用户态和内核态传送数据
NTSTATUS
MiniMessage(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
);