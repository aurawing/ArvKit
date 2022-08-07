#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <fltUser.h>

#define MINI_PORT_NAME L"\\ArvCommPort"

typedef enum _OpCommand {  //��������
	SET_PROC = 0,
	SET_RULES = 1,
	GET_STAT = 2,
	SET_DB_CONF = 3,
	SET_ALLOW_UNLOAD = 4,
	SET_CONTROL_PROC = 5,
} OpCommand;

typedef struct _OpGetStat { //��ȡͳ����Ϣ
	OpCommand command;
} OpGetStat, *POpGetStat;

typedef struct _OpSetProc { //��������
	OpCommand command;
	ULONG procID;
	UINT ruleID;
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

typedef struct _OpSetControlProc { //�޸Ŀ��ƽ���ID
	OpCommand command;
	ULONG controlProcID;
} OpSetControlProc, *POpSetControlProc;

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

typedef struct _ArvDiskInfo {
	ULONGLONG totalBytes;
	ULONGLONG totalFreeBytes;
} ArvDiskInfo, *PArvDiskInfo;

//HRESULT InitCommunicationPort(HANDLE *hPort);
//VOID CloseCommunicationPort(HANDLE port);
HRESULT SendSetControlProcMessage(BOOL disable);
HRESULT GetStatistics(__inout LPVOID OutBuffer, __in DWORD dwInBufferSize, __out DWORD *bytesReturned);
HRESULT SendSetProcMessage(ULONG procID, UINT ruleID);
HRESULT SendSetRulesMessage(POpRule *rules, UINT len);
HRESULT SendSetDBConfMessage(UINT ruleID, PWSTR path);
HRESULT SendAllowUnloadMessage(BOOL allow);
BOOL UTF8ToUnicode(const char* UTF8, PZPWSTR strUnicode);
VOID FreeRuleList(POpRule *pzpRules, int ruleSize);
//VOID Sha256UnicodeString(PWSTR pWStr, BYTE result[SHA256_BLOCK_SIZE]);
void GetDiskInfo(PArvDiskInfo diskInfo);
bool VerifyPublicKey(PSTR pubkey58);
int CopyByBlock(const TCHAR *dest_file_name, const TCHAR *src_file_name);