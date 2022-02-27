#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <fltUser.h>

#define MINI_PORT_NAME L"\\ArvCommPort"

typedef enum _OpCommand {  //操作命令
	SET_PROC = 0,
	SET_RULES = 1,
} OpCommand;

typedef struct _OpSetProc { //操作数据
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

typedef struct _OpSetRules { //操作数据
	OpCommand command;
	POpRule *rules;
	UINT		ruleLen;
} OpSetRules, *POpSetRules;

int SendSetProcMessage(ULONG procID, UINT ruleID);
int SendSetRulesMessage(POpRule *rules, UINT len);
BOOL UTF8ToUnicode(const char* UTF8, PZPWSTR strUnicode);
