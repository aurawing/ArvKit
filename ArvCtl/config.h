#pragma once
#include"io.h"
#include "utils.h"
#include "cJSON.h"

#define SVC_NAME	TEXT("ArvCtl")
#define FLT_SVC_NAME L"ArvFilter"

extern UINT listenPort;
extern char *keyManageAddr;

BOOL InitSysConfig();
BOOL UpdateSysConfig(UINT listenPort, PSTR keyManageAddr);
BOOL InitConfig();
PSTR PrintJsonConfig();
void ClearConfig();
BOOL ConfigArvFilter();
BOOL UpdateConfig(UINT id, PSTR pubkey, PSTR url, PZPSTR paths, BOOL *isDBs, UINT pathLen);
BOOL UpdateDBPath(UINT id, PSTR path, BOOL isDB);
PSTR LoadDBConf();

BOOL InitDaemonConfig();
BOOL UpdateDaemonConfig(PSTR daemonPath, PSTR exePath, INT keyID, PSTR url);
PSTR PrintDaemonConfig(PSTR daemonName);
void ClearDaemonConfig();