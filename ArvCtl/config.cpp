#include <windows.h>
#include "config.h"

cJSON *jsonConfig = NULL;
TCHAR configPath[MAX_PATH];
SRWLOCK configLock;

BOOL InitConfig()
{
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
		return TRUE;
	}
	err = _wfopen_s(&fp, configPath, L"rb");
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
	AcquireSRWLockExclusive(&configLock);
	jsonConfig = cJSON_Parse(tmp);
	free(tmp);
	ReleaseSRWLockExclusive(&configLock);
	if (jsonConfig == NULL)
	{
		return FALSE;
	}
	return TRUE;
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
	cJSON *pJsonPath;
	POpRule pRule;
	POpRule *pzpRules = (POpRule*)malloc(ruleSize * sizeof(POpRule));
	HRESULT result = S_OK;
	for (int i = 0; i < ruleSize; i++)
	{
		pRule = (POpRule)malloc(sizeof(OpRule));
		pJsonRule = cJSON_GetArrayItem(jsonConfig, i);
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "ID");
		pRule->id = pJsonRuleItem->valueint;
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "PublicKey");
		UTF8ToUnicode(pJsonRuleItem->valuestring, &pRule->pubKey);
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "Paths");
		int pathLen = cJSON_GetArraySize(pJsonRuleItem);
		pRule->pathsLen = pathLen;
		pRule->paths = (PZPWSTR)malloc(pathLen * sizeof(PWSTR));
		for (int j = 0; j < pathLen; j++)
		{
			pJsonPath = cJSON_GetArrayItem(pJsonRuleItem, j);
			UTF8ToUnicode(pJsonPath->valuestring, &pRule->paths[j]);
		}
		pzpRules[i] = pRule;
	}
	if (ruleSize == 0)
	{
		ReleaseSRWLockShared(&configLock);
		return TRUE;
	}
	result = SendSetRulesMessage(pzpRules, ruleSize);
	FreeRuleList(pzpRules, ruleSize);
	pzpRules = NULL;

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

BOOL UpdateConfig(UINT id, PSTR pubkey, PZPSTR paths, UINT pathLen)
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
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "ID");
		if (pJsonRuleItem->valueint == id)
		{
			selindex = i;
			break;
		}
	}
	cJSON *item = cJSON_CreateObject();
	cJSON *pathItem = cJSON_CreateStringArray(paths, pathLen);
	cJSON_AddItemToObject(item, "ID", cJSON_CreateNumber(id));
	cJSON_AddItemToObject(item, "PublicKey", cJSON_CreateString(pubkey));
	cJSON_AddItemToObject(item, "Paths", pathItem);
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