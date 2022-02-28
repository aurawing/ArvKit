#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <fltUser.h>
#include "sha256.h"

#define MINI_PORT_NAME L"\\ArvCommPort"

typedef enum _OpCommand {  //��������
	SET_PROC = 0,
	SET_RULES = 1,
	GET_STAT = 2,
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
	UINT pathsLen;
} OpRule, *POpRule;

typedef struct _OpSetRules { //��������
	OpCommand command;
	POpRule *rules;
	UINT		ruleLen;
} OpSetRules, *POpSetRules;

typedef struct _RepStat { //����ͳ����Ϣ
	BYTE SHA256[SHA256_BLOCK_SIZE];
	LONG Pass;
	LONG Block;
} RepStat, *PRepStat;

//HRESULT InitCommunicationPort(HANDLE *hPort);
//VOID CloseCommunicationPort(HANDLE port);
HRESULT GetStatistics(__inout LPVOID OutBuffer, __in DWORD dwInBufferSize, __out DWORD *bytesReturned);
HRESULT SendSetProcMessage(ULONG procID, UINT ruleID);
HRESULT SendSetRulesMessage(POpRule *rules, UINT len);
BOOL UTF8ToUnicode(const char* UTF8, PZPWSTR strUnicode);
VOID Sha256UnicodeString(PWSTR pWStr, BYTE result[SHA256_BLOCK_SIZE]);
