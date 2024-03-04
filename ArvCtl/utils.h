#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <fltUser.h>

#define MINI_PORT_NAME L"\\ArvCommPort"

typedef enum _OpCommand {  //操作命令
	SET_PROC = 0,
	SET_RULES = 1,
	GET_STAT = 2,
	SET_DB_CONF = 3,
	SET_ALLOW_UNLOAD = 4,
	SET_CONTROL_PROC = 5,
	SET_REG_PROC = 6,
	SET_FILTER_STATUS = 7,
	SET_EXE_ALLOWED_PATHS = 8,
	SET_REG_PROC_TMP = 9,
	SET_ABNORMAL_THRESHOLD = 10,
	SET_CLEAR_LOG = 11,
} OpCommand;

typedef enum _LogType {  //操作命令
	UNKNOWN,
	LEARN,
	VERIFY,
	ENABLE,
	ABNORMAL,
} LogType;

typedef struct _OpGetStat { //获取统计信息
	OpCommand command;
} OpGetStat, *POpGetStat;

typedef struct _OpSetProc { //操作数据
	OpCommand command;
	ULONG procID;
	UINT ruleID;
} OpSetProc, *POpSetProc;

typedef struct _OpRule {
	UINT id;
	PWSTR pubKey;
	PZPWSTR paths;
	BOOL *isDB;
	BOOL *blockExe;
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

typedef struct _OpSetControlProc { //修改控制进程ID
	OpCommand command;
	ULONG controlProcID;
} OpSetControlProc, *POpSetControlProc;

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
	ULONGLONG Sillegal;
	ULONGLONG Abnormal;
} RepStat, *PRepStat;

typedef struct _ArvDiskInfo {
	ULONGLONG totalBytes;
	ULONGLONG totalFreeBytes;
} ArvDiskInfo, *PArvDiskInfo;

typedef struct _OpRegProc {
	PSTR procName;
	BOOL inherit;
	UINT ruleID;
	BOOL once;
} OpRegProc, *POpRegProc;

typedef struct _OpSetRegProcs {
	OpCommand command;
	POpRegProc *regProcs;
	UINT		regProcLen;
} OpSetRegProcs, *POpSetRegProcs;

typedef struct _OpSetFilterStatus {
	OpCommand command;
	DWORD logFlag;
	DWORD logOnly;
} OpSetFilterStatus, *POpSetFilterStatus;

typedef struct _OpSetExeAllowedPaths {
	OpCommand command;
	PZPWSTR paths;
	UINT	len;
} OpSetExeAllowedPaths, *POpSetExeAllowedPaths;

typedef struct _OpSetAbnormalThreshold {
	OpCommand command;
	UINT threshold;
	ULONG interval;
} OpSetAbnormalThreshold, *POpSetAbnormalThreshold;

typedef struct _OpSetClearLog {
	OpCommand command;
	LogType type;
} OpSetClearLog, *POpSetClearLog;

//HRESULT InitCommunicationPort(HANDLE *hPort);
//VOID CloseCommunicationPort(HANDLE port);
HRESULT SendSetControlProcMessage(BOOL disable);
HRESULT GetStatistics(__inout LPVOID OutBuffer, __in DWORD dwInBufferSize, __out DWORD *bytesReturned);
HRESULT SendSetProcMessage(ULONG procID, UINT ruleID);
HRESULT SendSetRegProcsMessage(POpRegProc *regProcs, UINT len);
HRESULT SendSetAuthProcMessage(POpRegProc *regProcs, UINT len);
HRESULT SendSetRulesMessage(POpRule *rules, UINT len);
HRESULT SendSetDBConfMessage(UINT ruleID, PWSTR path);
HRESULT SendAllowUnloadMessage(BOOL allow);
HRESULT SendSetFilterStatusMessage(DWORD logFlag, DWORD logOnly);
HRESULT SendSetExeAllowedPathMessage(PZPWSTR paths, UINT len);
HRESULT SendSetAbnormalThresholdMessage(UINT threshold, ULONG interval);
HRESULT SendSetClearLogMessage(LogType type);
BOOL UTF8ToUnicode(const char* UTF8, PZPWSTR strUnicode);
VOID FreeRegProcList(POpRegProc *pzpRegProcs, int regProcSize);
VOID FreeRuleList(POpRule *pzpRules, int ruleSize);
//VOID Sha256UnicodeString(PWSTR pWStr, BYTE result[SHA256_BLOCK_SIZE]);
void GetDiskInfo(PArvDiskInfo diskInfo);
bool VerifyPublicKey(PSTR pubkey58);
int CopyByBlock(const TCHAR *dest_file_name, const TCHAR *src_file_name);
bool InitRegistry();