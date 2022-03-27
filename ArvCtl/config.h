#pragma once
#include"io.h"
#include "utils.h"
#include "cJSON.h"

#define SVC_NAME	TEXT("ArvCtl")
#define FLT_SVC_NAME L"ArvFilter"

BOOL InitConfig();
PSTR PrintJsonConfig();
void ClearConfig();
BOOL ConfigArvFilter();
BOOL UpdateConfig(UINT id, PSTR pubkey, PZPSTR paths, BOOL *isDBs, UINT pathLen);
BOOL UpdateDBPath(UINT id, PSTR path, BOOL isDB);
PSTR LoadDBConf();