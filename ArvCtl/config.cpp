#include <windows.h>
#include "config.h"

cJSON *jsonConfig = NULL;
TCHAR configPath[MAX_PATH];
SRWLOCK configLock;

cJSON *regProcConfig = NULL;
TCHAR regProcPath[MAX_PATH];
SRWLOCK regProcLock;

cJSON *daemonConfig = NULL;
TCHAR daemonPath[MAX_PATH];
SRWLOCK daemonLock;

cJSON *exeAllowedPathConfig = NULL;
TCHAR exeAllowedPathPath[MAX_PATH];
SRWLOCK exeAllowedPathLock;

TCHAR serConfigPath[MAX_PATH];
UINT listenPort;
char *keyManageAddr;

BOOL InitSysConfig()
{
	GetModuleFileName(NULL, serConfigPath, MAX_PATH);
	WCHAR *ch = wcsrchr(serConfigPath, '\\');
	ch[1] = L's';
	ch[2] = L'e';
	ch[3] = L'r';
	ch[4] = L'v';
	ch[5] = L'i';
	ch[6] = L'c';
	ch[7] = L'e';
	ch[8] = L'.';
	ch[9] = L'j';
	ch[10] = L's';
	ch[11] = L'o';
	ch[12] = L'n';
	ch[13] = L'\0';
	errno_t err;
	FILE *fp;
	int file_size;
	if (_waccess(serConfigPath, 0))
	{
		listenPort = 8888;
		keyManageAddr = (char*)"http://127.0.0.1:8080";
		return TRUE;
	}
	err = _wfopen_s(&fp, serConfigPath, L"rb");
	if (err != 0)
	{
		return FALSE;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	char *tmp;
	fseek(fp, 0, SEEK_SET);
	size_t allocSize = file_size * sizeof(char) + sizeof(char);
	tmp = (char *)malloc(allocSize);
	memset(tmp, 0, allocSize);
	fread(tmp, sizeof(char), file_size, fp);
	fclose(fp);
	cJSON *serConfig = cJSON_Parse(tmp);
	free(tmp);
	cJSON *pJsonPort = cJSON_GetObjectItem(serConfig, "listenPort");
	cJSON *pJsonKMA = cJSON_GetObjectItem(serConfig, "keyManageAddr");
	if (pJsonPort == NULL)
	{
		listenPort = 8888;
	}
	else
	{
		listenPort = pJsonPort->valueint;
	}
	if (pJsonKMA == NULL)
	{
		keyManageAddr = (char*)"http://127.0.0.1:8080";
	}
	else
	{
		size_t s = strlen(pJsonKMA->valuestring);
		keyManageAddr = (char*)malloc(sizeof(char)*(s + 1));
		strcpy_s(keyManageAddr, s+1, pJsonKMA->valuestring);
	}
	return TRUE;
}

BOOL UpdateSysConfig(UINT port, PSTR keyManageAddr)
{
	if (port == 0)
	{
		port = listenPort;
	}
	AcquireSRWLockExclusive(&configLock);
	cJSON *item = cJSON_CreateObject();
	cJSON_AddItemToObject(item, "listenPort", cJSON_CreateNumber(port));
	cJSON_AddItemToObject(item, "keyManageAddr", cJSON_CreateString(keyManageAddr));

	errno_t err;
	FILE *fp;
	err = _wfopen_s(&fp, serConfigPath, L"wb");
	if (err != 0)
	{
		ReleaseSRWLockExclusive(&configLock);
		return FALSE;
	}
	PSTR jsonstr = cJSON_Print(item);
	fprintf(fp, jsonstr);
	fclose(fp);
	cJSON_Delete(item);
	ReleaseSRWLockExclusive(&configLock);
	return TRUE;
}

BOOL InitConfig()
{
	if (!InitSysConfig())
	{
		return FALSE;
	}
	InitializeSRWLock(&configLock);
	GetModuleFileName(NULL, configPath, MAX_PATH);
	WCHAR *ch = wcsrchr(configPath, '\\');
	ch[1] = L'c';
	ch[2] = L'o';
	ch[3] = L'n';
	ch[4] = L'f';
	ch[5] = L'i';
	ch[6] = L'g';
	ch[7] = L'.';
	ch[8] = L'j';
	ch[9] = L's';
	ch[10] = L'o';
	ch[11] = L'n';
	ch[12] = L'\0';
	errno_t err;
	FILE *fp;
	int file_size;
	if (_waccess(configPath, 0))
	{
		jsonConfig = cJSON_Parse("[]");
		return TRUE;
	}
	err = _wfopen_s(&fp, configPath, L"rb");
	if (err != 0)
	{
		jsonConfig = cJSON_Parse("[]");
		return FALSE;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	char *tmp;
	fseek(fp, 0, SEEK_SET);
	size_t allocSize = file_size * sizeof(char) + sizeof(char);
	tmp = (char *)malloc(allocSize);
	memset(tmp, 0, allocSize);
	fread(tmp, sizeof(char), file_size, fp);
	fclose(fp);
	AcquireSRWLockExclusive(&configLock);
	jsonConfig = cJSON_Parse(tmp);
	free(tmp);
	ReleaseSRWLockExclusive(&configLock);
	if (jsonConfig == NULL)
	{
		jsonConfig = cJSON_Parse("[]");
		return FALSE;
	}
	return TRUE;
}

void UpdateAllowUnload(BOOL allow)
{
	AcquireSRWLockExclusive(&configLock);
	SendAllowUnloadMessage(allow);
	ReleaseSRWLockExclusive(&configLock);
}

PSTR PrintJsonConfig()
{
	PSTR str = NULL;
	AcquireSRWLockShared(&configLock);
	if (jsonConfig != NULL) {
		str = cJSON_Print(jsonConfig);
	}
	ReleaseSRWLockShared(&configLock);
	return str;
}

void ClearConfig()
{
	AcquireSRWLockExclusive(&configLock);
	if (jsonConfig != NULL)
	{
		cJSON_Delete(jsonConfig);
		jsonConfig = NULL;
	}
	ReleaseSRWLockExclusive(&configLock);
}

BOOL ConfigRegProcs()
{
	if (regProcConfig == NULL)
	{
		return TRUE;
	}
	AcquireSRWLockShared(&regProcLock);
	int regProcSize = cJSON_GetArraySize(regProcConfig);
	cJSON *pJsonRegProc;
	cJSON *pJsonRegProcItem;
	POpRegProc pRegProc;
	POpRegProc *pzpRegProcs;
	HRESULT result = S_OK;
	if (regProcSize > 0)
	{
		pzpRegProcs = (POpRegProc*)malloc(regProcSize * sizeof(POpRegProc));
		for (int i = 0; i < regProcSize; i++)
		{
			pRegProc = (POpRegProc)malloc(sizeof(OpRegProc));
			pJsonRegProc = cJSON_GetArrayItem(regProcConfig, i);

			pJsonRegProcItem = cJSON_GetObjectItem(pJsonRegProc, "procName");
			pRegProc->procName = (PSTR)malloc(sizeof(char)*(strlen(pJsonRegProcItem->valuestring) + 1));
			strcpy_s(pRegProc->procName, sizeof(char)*(strlen(pJsonRegProcItem->valuestring) + 1), pJsonRegProcItem->valuestring);

			pJsonRegProcItem = cJSON_GetObjectItem(pJsonRegProc, "keyID");
			pRegProc->ruleID = pJsonRegProcItem->valueint;

			pJsonRegProcItem = cJSON_GetObjectItem(pJsonRegProc, "inherit");
			if (cJSON_IsTrue(pJsonRegProcItem))
				pRegProc->inherit = TRUE;
			else if (cJSON_IsFalse(pJsonRegProcItem))
				pRegProc->inherit = FALSE;

			pzpRegProcs[i] = pRegProc;
		}
		result = SendSetRegProcsMessage(pzpRegProcs, regProcSize);
		FreeRegProcList(pzpRegProcs, regProcSize);
		free(pzpRegProcs);
		pzpRegProcs = NULL;
	}

	ReleaseSRWLockShared(&regProcLock);
	if (result != S_OK)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL ConfigExeAllowedPath()
{
	if (exeAllowedPathConfig == NULL)
	{
		return TRUE;
	}
	AcquireSRWLockShared(&exeAllowedPathLock);
	int exeAllowedPathSize = cJSON_GetArraySize(exeAllowedPathConfig);
	/*cJSON *pJsonRegProc;
	cJSON *pJsonRegProcItem;
	POpRegProc pRegProc;
	POpRegProc *pzpRegProcs;*/
	HRESULT result = S_OK;
	if (exeAllowedPathSize > 0)
	{
		PZPWSTR paths = (PZPWSTR)malloc(exeAllowedPathSize * sizeof(PWSTR));

		for (int i = 0; i < exeAllowedPathSize; i++)
		{
			cJSON *pJsonPathItem = cJSON_GetArrayItem(exeAllowedPathConfig, i);
			UTF8ToUnicode(pJsonPathItem->valuestring, &paths[i]);
		}
		result = SendSetExeAllowedPathMessage(paths, exeAllowedPathSize);
		for (int j = 0; j < exeAllowedPathSize; j++)
		{
			free(paths[j]);
		}
		free(paths);
		paths = NULL;
	}

	ReleaseSRWLockShared(&exeAllowedPathLock);
	if (result != S_OK)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL ConfigArvFilter()
{
	if (jsonConfig == NULL)
	{
		return TRUE;
	}
	AcquireSRWLockShared(&configLock);
	int ruleSize = cJSON_GetArraySize(jsonConfig); 
	cJSON *pJsonRule;
	cJSON *pJsonRuleItem;
	cJSON *pJsonPathItem;
	cJSON *pJsonPath;
	cJSON *pJsonIsDB;
	POpRule pRule;
	POpRule *pzpRules;
	HRESULT result = S_OK;
	if (ruleSize > 0)
	{
		pzpRules = (POpRule*)malloc(ruleSize * sizeof(POpRule));
		for (int i = 0; i < ruleSize; i++)
		{
			pRule = (POpRule)malloc(sizeof(OpRule));
			pJsonRule = cJSON_GetArrayItem(jsonConfig, i);
			pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "id");
			pRule->id = pJsonRuleItem->valueint;
			pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "pubkey");
			UTF8ToUnicode(pJsonRuleItem->valuestring, &pRule->pubKey);
			pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "path");
			int pathLen = cJSON_GetArraySize(pJsonRuleItem);
			pRule->pathsLen = pathLen;
			pRule->paths = (PZPWSTR)malloc(pathLen * sizeof(PWSTR));
			pRule->isDB = (BOOL*)malloc(pathLen * sizeof(BOOL));
			for (int j = 0; j < pathLen; j++)
			{
				pJsonPathItem = cJSON_GetArrayItem(pJsonRuleItem, j);
				pJsonPath = cJSON_GetObjectItem(pJsonPathItem, "path");
				pJsonIsDB = cJSON_GetObjectItem(pJsonPathItem, "crypt");
				UTF8ToUnicode(pJsonPath->valuestring, &pRule->paths[j]);
				if (cJSON_IsTrue(pJsonIsDB))
					pRule->isDB[j] = TRUE;
				else if (cJSON_IsFalse(pJsonIsDB))
					pRule->isDB[j] = FALSE;
			}
			pzpRules[i] = pRule;
		}
		result = SendSetRulesMessage(pzpRules, ruleSize);
		FreeRuleList(pzpRules, ruleSize);
		free(pzpRules);
		pzpRules = NULL;
	}
	else
	{
		result = SendSetRulesMessage(NULL, 0);
		ReleaseSRWLockShared(&configLock);
		return TRUE;
	}

	errno_t err;
	FILE *fp;
	err = _wfopen_s(&fp, configPath, L"wb");
	if (err != 0)
	{
		ReleaseSRWLockShared(&configLock);
		return FALSE;
	}
	PSTR jsonstr = cJSON_Print(jsonConfig);
	fprintf(fp, jsonstr);
	fclose(fp);

	ReleaseSRWLockShared(&configLock);
	if (result != S_OK)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL UpdateConfigs(PSaveRulesParam params, UINT dataLen)
{
	AcquireSRWLockExclusive(&configLock);
	if (jsonConfig != NULL)
	{
		cJSON_Delete(jsonConfig);
		jsonConfig = NULL;
	}
	jsonConfig = cJSON_CreateArray();
	for (int i = 0; i < dataLen; i++)
	{
		cJSON *item = cJSON_CreateObject();
		cJSON *pathItem = cJSON_CreateArray();
		for (int j = 0; j < params[i].pathLen; j++)
		{
			cJSON *innerItem = cJSON_CreateObject();
			cJSON_AddItemToObject(innerItem, "path", cJSON_CreateString(params[i].paths[j]));
			cJSON_AddItemToObject(innerItem, "crypt", cJSON_CreateBool(params[i].isDBs[j]));
			cJSON_AddItemToArray(pathItem, innerItem);
		}

		//cJSON *pathItem = cJSON_CreateStringArray(paths, pathLen);
		cJSON_AddItemToObject(item, "id", cJSON_CreateNumber(params[i].id));
		cJSON_AddItemToObject(item, "pubkey", cJSON_CreateString(params[i].pubkey));
		//cJSON_AddItemToObject(item, "url", cJSON_CreateString(url));
		cJSON_AddItemToObject(item, "path", pathItem);
		cJSON_AddItemToArray(jsonConfig, item);
	}

	ReleaseSRWLockExclusive(&configLock);
	return ConfigArvFilter();
}

BOOL UpdateConfig(UINT id, PSTR pubkey, PSTR url, PZPSTR paths, BOOL *isDBs, UINT pathLen)
{
	AcquireSRWLockExclusive(&configLock);
	if (jsonConfig == NULL)
	{
		jsonConfig = cJSON_CreateArray();
	}
	int ruleSize = cJSON_GetArraySize(jsonConfig);
	cJSON *pJsonRule;
	cJSON *pJsonRuleItem;
	cJSON *pJsonPath;
	int selindex = -1;
	for (int i = 0; i < ruleSize; i++)
	{
		pJsonRule = cJSON_GetArrayItem(jsonConfig, i);
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "id");
		if (pJsonRuleItem->valueint == id)
		{
			selindex = i;
			break;
		}
	}
	cJSON *item = cJSON_CreateObject();
	cJSON *pathItem = cJSON_CreateArray();
	for (int j = 0; j < pathLen; j++)
	{
		cJSON *innerItem = cJSON_CreateObject();
		cJSON_AddItemToObject(innerItem, "path", cJSON_CreateString(paths[j]));
		cJSON_AddItemToObject(innerItem, "crypt", cJSON_CreateBool(isDBs[j]));
		cJSON_AddItemToArray(pathItem, innerItem);
	}

	//cJSON *pathItem = cJSON_CreateStringArray(paths, pathLen);
	cJSON_AddItemToObject(item, "id", cJSON_CreateNumber(id));
	cJSON_AddItemToObject(item, "pubkey", cJSON_CreateString(pubkey));
	cJSON_AddItemToObject(item, "url", cJSON_CreateString(url));
	cJSON_AddItemToObject(item, "path", pathItem);
	if (selindex >= 0)
	{
		cJSON_ReplaceItemInArray(jsonConfig, selindex, item);
	}
	else
	{
		cJSON_AddItemToArray(jsonConfig, item);
	}
	ReleaseSRWLockExclusive(&configLock);
	return ConfigArvFilter();
}

BOOL UpdateDBPath(UINT id, PSTR path, BOOL isDB)
{
	AcquireSRWLockExclusive(&configLock);
	if (jsonConfig == NULL)
	{
		return FALSE;
	}
	int ruleSize = cJSON_GetArraySize(jsonConfig);
	cJSON *pJsonRule = NULL;
	cJSON *pJsonRuleItem = NULL;
	cJSON *pJsonPath = NULL;
	int selindex = -1;
	for (int i = 0; i < ruleSize; i++)
	{
		pJsonRule = cJSON_GetArrayItem(jsonConfig, i);
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "id");
		if (pJsonRuleItem->valueint == id)
		{
			selindex = i;
			break;
		}
	}
	if (selindex == -1)
	{
		ReleaseSRWLockExclusive(&configLock);
		return FALSE;
	}
	pJsonPath = cJSON_GetObjectItem(pJsonRule, "path");
	int pathLen = cJSON_GetArraySize(pJsonPath);
	for (int j = 0; j < pathLen; j++)
	{
		cJSON *pJsonPathItem = cJSON_GetArrayItem(pJsonPath, j);
		cJSON *pJsonPathInner = cJSON_GetObjectItem(pJsonPathItem, "path");
		cJSON *pJsonIsDB = cJSON_GetObjectItem(pJsonPathItem, "crypt");
		if (strcmp(pJsonPathInner->valuestring, path)==0)
		{
			cJSON_ReplaceItemInObject(pJsonPathItem, "crypt", cJSON_CreateBool(isDB));
			break;
		}
	}
	ReleaseSRWLockExclusive(&configLock);
	return ConfigArvFilter();
}

PSTR LoadDBConf()
{
	PSTR str = NULL;
	AcquireSRWLockShared(&configLock);
	cJSON *jsonDBConf = cJSON_CreateArray();
	if (jsonConfig != NULL) {
		int ruleSize = cJSON_GetArraySize(jsonConfig);
		cJSON *pJsonRule;
		cJSON *pJsonID;
		cJSON *pJsonPath;
		cJSON *pJsonPathItem;
		cJSON *pJsonPath2;
		cJSON *pJsonIsDB;
		for (int i = 0; i < ruleSize; i++)
		{
			pJsonRule = cJSON_GetArrayItem(jsonConfig, i);
			pJsonID = cJSON_GetObjectItem(pJsonRule, "id");
			pJsonPath = cJSON_GetObjectItem(pJsonRule, "path");
			int pathLen = cJSON_GetArraySize(pJsonPath);
			for (int j = 0; j < pathLen; j++)
			{
				pJsonPathItem = cJSON_GetArrayItem(pJsonPath, j);
				pJsonPath2 = cJSON_GetObjectItem(pJsonPathItem, "path");
				pJsonIsDB = cJSON_GetObjectItem(pJsonPathItem, "crypt");
				if (cJSON_IsTrue(pJsonIsDB))
				{
					cJSON *innerItem = cJSON_CreateObject();
					cJSON_AddItemToObject(innerItem, "id", cJSON_CreateNumber(pJsonID->valueint));
					cJSON_AddItemToObject(innerItem, "path", cJSON_CreateString(pJsonPath2->valuestring));
					cJSON_AddItemToArray(jsonDBConf, innerItem);
				}
			}
		}

	}
	ReleaseSRWLockShared(&configLock);
	str = cJSON_Print(jsonDBConf);
	return str;
}

BOOL InitRegProcConfig()
{
	InitializeSRWLock(&regProcLock);
	GetModuleFileName(NULL, regProcPath, MAX_PATH);
	WCHAR *ch = wcsrchr(regProcPath, '\\');
	ch[1] = L'r';
	ch[2] = L'e';
	ch[3] = L'g';
	ch[4] = L'p';
	ch[5] = L'r';
	ch[6] = L'o';
	ch[7] = L'c';
	ch[8] = L'.';
	ch[9] = L'j';
	ch[10] = L's';
	ch[11] = L'o';
	ch[12] = L'n';
	ch[13] = L'\0';
	errno_t err;
	FILE *fp;
	int file_size;
	if (_waccess(regProcPath, 0))
	{
		regProcConfig = cJSON_Parse("[]");
		return TRUE;
	}
	err = _wfopen_s(&fp, regProcPath, L"rb");
	if (err != 0)
	{
		regProcConfig = cJSON_Parse("[]");
		return FALSE;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	char *tmp;
	fseek(fp, 0, SEEK_SET);
	size_t allocSize = file_size * sizeof(char) + sizeof(char);
	tmp = (char *)malloc(allocSize);
	memset(tmp, 0, allocSize);
	fread(tmp, sizeof(char), file_size, fp);
	fclose(fp);
	AcquireSRWLockExclusive(&regProcLock);
	regProcConfig = cJSON_Parse(tmp);
	free(tmp);
	ReleaseSRWLockExclusive(&regProcLock);
	if (regProcConfig == NULL)
	{
		regProcConfig = cJSON_Parse("[]");
		return FALSE;
	}
	return TRUE;
}

BOOL UpdateAuthProcsConfig(PSaveRegProcParam params, UINT regProcSize)
{
	/*cJSON *authProcConfig = cJSON_CreateArray();
	for (int i = 0; i < regProcSize; i++)
	{
		cJSON *item = cJSON_CreateObject();
		cJSON_AddItemToObject(item, "procName", cJSON_CreateString(params[i].procName));
		cJSON_AddItemToObject(item, "inherit", cJSON_CreateBool(params[i].inherit));
		cJSON_AddItemToObject(item, "keyID", cJSON_CreateNumber(params[i].ruleID));
		cJSON_AddItemToArray(authProcConfig, item);
	}*/
	AcquireSRWLockShared(&regProcLock);
	//cJSON *pJsonRegProc;
	//cJSON *pJsonRegProcItem;
	POpRegProc pRegProc;
	POpRegProc *pzpRegProcs;
	HRESULT result = S_OK;
	if (regProcSize > 0)
	{
		pzpRegProcs = (POpRegProc*)malloc(regProcSize * sizeof(POpRegProc));
		for (int i = 0; i < regProcSize; i++)
		{
			pRegProc = (POpRegProc)malloc(sizeof(OpRegProc));
			//pJsonRegProc = cJSON_GetArrayItem(regProcConfig, i);

			//pJsonRegProcItem = cJSON_GetObjectItem(pJsonRegProc, "procName");
			pRegProc->procName = (PSTR)malloc(sizeof(char)*(strlen(params[i].procName) + 1));
			strcpy_s(pRegProc->procName, sizeof(char)*(strlen(params[i].procName) + 1), params[i].procName);

			//pJsonRegProcItem = cJSON_GetObjectItem(pJsonRegProc, "keyID");
			pRegProc->ruleID = params[i].ruleID;

			//pJsonRegProcItem = cJSON_GetObjectItem(pJsonRegProc, "inherit");
			/*pRegProc->inherit = params[i].inherit;
			if (cJSON_IsTrue(TRUE))
				pRegProc->inherit = params[i].inherit;
			else if (cJSON_IsFalse(pJsonRegProcItem))
				pRegProc->inherit = FALSE;*/

			pzpRegProcs[i] = pRegProc;
		}
		result = SendSetAuthProcMessage(pzpRegProcs, regProcSize);
		for (int i = 0; i < regProcSize; i++)
		{
			POpRegProc pOpRegProc = pzpRegProcs[i];
			free(pOpRegProc);
			pOpRegProc = NULL;
		}
		free(pzpRegProcs);
		pzpRegProcs = NULL;
	}

	ReleaseSRWLockShared(&regProcLock);
	if (result != S_OK)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL UpdateRegProcsConfig(PSaveRegProcParam params, UINT dataLen)
{
	AcquireSRWLockExclusive(&regProcLock);
	if (regProcConfig != NULL)
	{
		cJSON_Delete(regProcConfig);
		regProcConfig = NULL;
	}
	regProcConfig = cJSON_CreateArray();
	for (int i = 0; i < dataLen; i++)
	{
		cJSON *item = cJSON_CreateObject();
		cJSON_AddItemToObject(item, "procName", cJSON_CreateString(params[i].procName));
		cJSON_AddItemToObject(item, "inherit", cJSON_CreateBool(params[i].inherit));
		cJSON_AddItemToObject(item, "keyID", cJSON_CreateNumber(params[i].ruleID));
		cJSON_AddItemToArray(regProcConfig, item);
	}
	errno_t err;
	FILE *fp;
	err = _wfopen_s(&fp, regProcPath, L"wb");
	if (err != 0)
	{
		ReleaseSRWLockExclusive(&regProcLock);
		return FALSE;
	}
	PSTR jsonstr = cJSON_Print(regProcConfig);
	fprintf(fp, jsonstr);
	fclose(fp);
	ReleaseSRWLockExclusive(&regProcLock);
	return ConfigRegProcs();
}

BOOL UpdateRegProcConfig(PSTR procName, BOOL inherit, INT keyID, BOOL add)
{
	AcquireSRWLockExclusive(&regProcLock);
	if (regProcConfig == NULL)
	{
		regProcConfig = cJSON_CreateArray();
	}
	int entrySize = cJSON_GetArraySize(regProcConfig);
	cJSON *pJsonReg;
	cJSON *pJsonRegItem;
	int selindex = -1;
	for (int i = 0; i < entrySize; i++)
	{
		pJsonReg = cJSON_GetArrayItem(regProcConfig, i);
		pJsonRegItem = cJSON_GetObjectItem(pJsonReg, "procName");
		if (strcmp(pJsonRegItem->valuestring, procName) == 0)
		{
			selindex = i;
			break;
		}
	}
	if (add)
	{
		cJSON *item = cJSON_CreateObject();
		cJSON_AddItemToObject(item, "procName", cJSON_CreateString(procName));
		cJSON_AddItemToObject(item, "inherit", cJSON_CreateBool(inherit));
		cJSON_AddItemToObject(item, "keyID", cJSON_CreateNumber(keyID));
		if (selindex >= 0)
		{
			cJSON_ReplaceItemInArray(regProcConfig, selindex, item);
		}
		else
		{
			cJSON_AddItemToArray(regProcConfig, item);
		}
	}
	else
	{
		if (selindex >= 0)
		{
			cJSON_DeleteItemFromArray(regProcConfig, selindex);
		}
	}

	errno_t err;
	FILE *fp;
	err = _wfopen_s(&fp, regProcPath, L"wb");
	if (err != 0)
	{
		ReleaseSRWLockExclusive(&regProcLock);
		return FALSE;
	}
	PSTR jsonstr = cJSON_Print(regProcConfig);
	fprintf(fp, jsonstr);
	fclose(fp);
	ReleaseSRWLockExclusive(&regProcLock);
	return TRUE;
}

void ClearRegProcConfig()
{
	AcquireSRWLockExclusive(&regProcLock);
	if (regProcConfig != NULL)
	{
		cJSON_Delete(regProcConfig);
		regProcConfig = NULL;
	}
	ReleaseSRWLockExclusive(&regProcLock);
}

BOOL InitExeAllowedPathConfig()
{
	InitializeSRWLock(&exeAllowedPathLock);
	GetModuleFileName(NULL, exeAllowedPathPath, MAX_PATH);
	WCHAR *ch = wcsrchr(exeAllowedPathPath, '\\');
	ch[1] = L'e';
	ch[2] = L'x';
	ch[3] = L'e';
	ch[4] = L'A';
	ch[5] = L'l';
	ch[6] = L'l';
	ch[7] = L'o';
	ch[8] = L'w';
	ch[9] = L'e';
	ch[10] = L'd';
	ch[11] = L'.';
	ch[12] = L'j';
	ch[13] = L's';
	ch[14] = L'o';
	ch[15] = L'n';
	ch[16] = L'\0';
	errno_t err;
	FILE *fp;
	int file_size;
	if (_waccess(exeAllowedPathPath, 0))
	{
		exeAllowedPathConfig = cJSON_Parse("[]");
		return TRUE;
	}
	err = _wfopen_s(&fp, exeAllowedPathPath, L"rb");
	if (err != 0)
	{
		exeAllowedPathConfig = cJSON_Parse("[]");
		return FALSE;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	char *tmp;
	fseek(fp, 0, SEEK_SET);
	size_t allocSize = file_size * sizeof(char) + sizeof(char);
	tmp = (char *)malloc(allocSize);
	memset(tmp, 0, allocSize);
	fread(tmp, sizeof(char), file_size, fp);
	fclose(fp);
	AcquireSRWLockExclusive(&exeAllowedPathLock);
	exeAllowedPathConfig = cJSON_Parse(tmp);
	free(tmp);
	ReleaseSRWLockExclusive(&exeAllowedPathLock);
	if (exeAllowedPathConfig == NULL)
	{
		exeAllowedPathConfig = cJSON_Parse("[]");
		return FALSE;
	}
	return ConfigExeAllowedPath();
}

BOOL UpdateExeAllowedPathConfig(PZPSTR paths, UINT len)
{
	AcquireSRWLockExclusive(&exeAllowedPathLock);
	if (exeAllowedPathConfig != NULL)
	{
		cJSON_Delete(exeAllowedPathConfig);
		exeAllowedPathConfig = NULL;
	}
	exeAllowedPathConfig = cJSON_CreateArray();
	for (int i = 0; i < len; i++)
	{
		cJSON_AddItemToArray(exeAllowedPathConfig, cJSON_CreateString(paths[i]));
	}
	errno_t err;
	FILE *fp;
	err = _wfopen_s(&fp, exeAllowedPathPath, L"wb");
	if (err != 0)
	{
		ReleaseSRWLockExclusive(&exeAllowedPathLock);
		return FALSE;
	}
	PSTR jsonstr = cJSON_Print(exeAllowedPathConfig);
	fprintf(fp, jsonstr);
	fclose(fp);
	ReleaseSRWLockExclusive(&exeAllowedPathLock);
	return ConfigExeAllowedPath();
}

void ClearExeAllowedPathConfig()
{
	AcquireSRWLockExclusive(&exeAllowedPathLock);
	if (exeAllowedPathConfig != NULL)
	{
		cJSON_Delete(exeAllowedPathConfig);
		exeAllowedPathConfig = NULL;
	}
	ReleaseSRWLockExclusive(&exeAllowedPathLock);
}


BOOL InitDaemonConfig()
{
	InitializeSRWLock(&daemonLock);
	GetModuleFileName(NULL, daemonPath, MAX_PATH);
	WCHAR *ch = wcsrchr(daemonPath, '\\');
	ch[1] = L'd';
	ch[2] = L'a';
	ch[3] = L'e';
	ch[4] = L'm';
	ch[5] = L'o';
	ch[6] = L'n';
	ch[7] = L'.';
	ch[8] = L'j';
	ch[9] = L's';
	ch[10] = L'o';
	ch[11] = L'n';
	ch[12] = L'\0';
	errno_t err;
	FILE *fp;
	int file_size;
	if (_waccess(daemonPath, 0))
	{
		return TRUE;
	}
	err = _wfopen_s(&fp, daemonPath, L"rb");
	if (err != 0)
	{
		return FALSE;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	char *tmp;
	fseek(fp, 0, SEEK_SET);
	size_t allocSize = file_size * sizeof(char) + sizeof(char);
	tmp = (char *)malloc(allocSize);
	memset(tmp, 0, allocSize);
	fread(tmp, sizeof(char), file_size, fp);
	fclose(fp);
	AcquireSRWLockExclusive(&daemonLock);
	daemonConfig = cJSON_Parse(tmp);
	free(tmp);
	ReleaseSRWLockExclusive(&daemonLock);
	if (daemonConfig == NULL)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL UpdateDaemonConfig(PSTR daemonName, PSTR exeName, INT keyID, PSTR url)
{
	AcquireSRWLockExclusive(&daemonLock);
	if (daemonConfig == NULL)
	{
		daemonConfig = cJSON_CreateArray();
	}
	int ruleSize = cJSON_GetArraySize(daemonConfig);
	cJSON *pJsonRule;
	cJSON *pJsonRuleItem;
	cJSON *pJsonPath;
	int selindex = -1;
	for (int i = 0; i < ruleSize; i++)
	{
		pJsonRule = cJSON_GetArrayItem(daemonConfig, i);
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "daemonName");
		if (strcmp(pJsonRuleItem->valuestring, daemonName)==0)
		{
			selindex = i;
			break;
		}
	}
	cJSON *item = cJSON_CreateObject();
	//cJSON *pathItem = cJSON_CreateArray();
	/*for (int j = 0; j < pathLen; j++)
	{
		cJSON *innerItem = cJSON_CreateObject();
		cJSON_AddItemToObject(innerItem, "path", cJSON_CreateString(paths[j]));
		cJSON_AddItemToObject(innerItem, "crypt", cJSON_CreateBool(isDBs[j]));
		cJSON_AddItemToArray(pathItem, innerItem);
	}*/

	//cJSON *pathItem = cJSON_CreateStringArray(paths, pathLen);
	cJSON_AddItemToObject(item, "daemonName", cJSON_CreateString(daemonName));
	cJSON_AddItemToObject(item, "exeName", cJSON_CreateString(exeName));
	cJSON_AddItemToObject(item, "keyID", cJSON_CreateNumber(keyID));
	cJSON_AddItemToObject(item, "url", cJSON_CreateString(url));
	if (selindex >= 0)
	{
		cJSON_ReplaceItemInArray(daemonConfig, selindex, item);
	}
	else
	{
		cJSON_AddItemToArray(daemonConfig, item);
	}
	//ReleaseSRWLockExclusive(&daemonLock);

	PWSTR dpath = NULL;
	PWSTR epath = NULL;
	UTF8ToUnicode(daemonName, &dpath);
	UTF8ToUnicode(exeName, &epath);
	errno_t err;
	FILE *fp;
	err = _wfopen_s(&fp, daemonPath, L"wb");
	if (err != 0)
	{
		if (dpath != NULL)
		{
			free(dpath);
		}
		if (epath != NULL)
		{
			free(epath);
		}
		ReleaseSRWLockExclusive(&daemonLock);
		return FALSE;
	}
	PSTR jsonstr = cJSON_Print(daemonConfig);
	fprintf(fp, jsonstr);
	fclose(fp);
	if (dpath != NULL)
	{
		free(dpath);
	}
	if (epath != NULL)
	{
		free(epath);
	}
	ReleaseSRWLockExclusive(&daemonLock);
	return TRUE;
}

PSTR PrintDaemonConfig(PSTR daemonName)
{
	PSTR str = NULL;
	AcquireSRWLockShared(&daemonLock);
	if (daemonConfig != NULL) {
		if (daemonName == NULL)
		{
			str = cJSON_Print(daemonConfig);
		}
		else
		{
			int ruleSize = cJSON_GetArraySize(daemonConfig);
			cJSON *pJsonRule;
			cJSON *pJsonRuleItem;
			//cJSON *pJsonPath;
			int selindex = -1;
			for (int i = 0; i < ruleSize; i++)
			{
				pJsonRule = cJSON_GetArrayItem(daemonConfig, i);
				pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "daemonName");
				if (_stricmp(pJsonRuleItem->valuestring, daemonName) == 0)
				{
					//cJSON_AddItemToObject(pJsonRule, "keyManageAddr", cJSON_CreateString(keyManageAddr));
					str = cJSON_Print(pJsonRule);
					//cJSON_DeleteItemFromObject(pJsonRule, "keyManageAddr");
					break;
				}
			}
		}
	}
	ReleaseSRWLockShared(&daemonLock);
	return str;
}

void ClearDaemonConfig()
{
	AcquireSRWLockExclusive(&daemonLock);
	if (daemonConfig != NULL)
	{
		cJSON_Delete(daemonConfig);
		daemonConfig = NULL;
	}
	ReleaseSRWLockExclusive(&daemonLock);
}