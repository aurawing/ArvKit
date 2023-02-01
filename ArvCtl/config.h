#pragma once
#include"io.h"
#include "utils.h"
#include "cJSON.h"

#define SVC_NAME	TEXT("ArvCtl")
#define FLT_SVC_NAME L"ArvFilter"

extern UINT listenPort;
extern char *keyManageAddr;

typedef struct _SaveRulesParam {
	UINT id;
	PSTR pubkey;
	PZPSTR paths;
	BOOL *isDBs;
	UINT pathLen;
} SaveRulesParam, *PSaveRulesParam;

typedef struct _SaveRegProcParam {
	PSTR procName;
	BOOL inherit;
	UINT ruleID;
} SaveRegProcParam, *PSaveRegProcParam;

BOOL InitSysConfig();
BOOL UpdateSysConfig(UINT listenPort, PSTR keyManageAddr);
BOOL InitConfig();
PSTR PrintJsonConfig();
void ClearConfig();
BOOL ConfigRegProcs();
BOOL ConfigExeAllowedPath();
BOOL ConfigArvFilter();
BOOL UpdateConfigs(PSaveRulesParam params, UINT dataLen);
BOOL UpdateConfig(UINT id, PSTR pubkey, PSTR url, PZPSTR paths, BOOL *isDBs, UINT pathLen);
BOOL UpdateDBPath(UINT id, PSTR path, BOOL isDB);
PSTR LoadDBConf();

BOOL InitRegProcConfig();
BOOL UpdateRegProcsConfig(PSaveRegProcParam params, UINT dataLen);
BOOL UpdateAuthProcsConfig(PSaveRegProcParam params, UINT regProcSize);
BOOL UpdateRegProcConfig(PSTR procName, BOOL inherit, INT keyID, BOOL add);
void ClearRegProcConfig();

BOOL InitDaemonConfig();
BOOL UpdateDaemonConfig(PSTR daemonPath, PSTR exePath, INT keyID, PSTR url);
PSTR PrintDaemonConfig(PSTR daemonName);
void ClearDaemonConfig();

BOOL InitExeAllowedPathConfig();
BOOL UpdateExeAllowedPathConfig(PZPSTR paths, UINT len);
void ClearExeAllowedPathConfig();