#pragma once

#include <fltKernel.h>
#include <ntdef.h>
#include <windef.h>

#include "global.h"

#define MINI_PORT_NAME L"\\ArvCommPort"

typedef enum _OP_COMMAND {  //��������
	SET_PROC,
	SET_RULES,
	GET_STAT,
	SET_DB_CONF,
	SET_ALLOW_UNLOAD,
	SET_CONTROL_PROC,
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