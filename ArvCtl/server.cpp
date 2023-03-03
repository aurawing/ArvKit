/*
  Copyright (c) 2019 Sogou, Inc.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
	  http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/
#include <sys/types.h>
#include <winsock2.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <string>
#include <tlhelp32.h>
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/WFServer.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFFacilities.h"
#include "server.h"


void process(WFHttpTask *server_task)
{
	//user_req->get_request_uri()调用得到请求的完整URL，通过这个URL构建发往mysql的insert任务。
	protocol::HttpRequest *user_req = server_task->get_req();
	protocol::HttpResponse *user_resp = server_task->get_resp();
	user_resp->set_header_pair("Content-Type", "application/json");
	//调用 decode_chunked_body 方法解析 req 注意解析的是 body
	std::string http_body = protocol::HttpUtil::decode_chunked_body(user_req);
	std::string method;
	user_req->get_method(method);
	if (method != "POST")
	{
		user_resp->set_status_code("405");
		user_resp->append_output_body("{\"code\": -1, \"msg\": \"only post method is allowed\", \"data\": {}}");
		return;
	}
	if (http_body.empty()) {
		user_resp->set_status_code("404");
		user_resp->append_output_body("{\"code\": -1, \"msg\": \"no request data\", \"data\": {}}");
		return;
	}
	const char* jsonstr = http_body.c_str();
	cJSON *jsonHead = cJSON_Parse(jsonstr);
	if (jsonHead == NULL)
	{
		user_resp->set_status_code("500");
		user_resp->append_output_body("{\"code\": -1, \"msg\": \"parse json failed\", \"data\": {}}");
		return;
	}
	cJSON *ifname = cJSON_GetObjectItem(jsonHead, "name");
	if (ifname != NULL && ifname->type == cJSON_String)
	{
		std::string ifnamestr(ifname->valuestring);
		if (ifnamestr == "statinfo")
		{
			cJSON *iftime = cJSON_GetObjectItem(jsonHead, "time");
			//ARV过滤器统计信息
			RepStat kernelStat;
			DWORD bytesReturn = 0;
			HRESULT result = GetStatistics((PVOID)&kernelStat, sizeof(RepStat), &bytesReturn);
			if (result != S_OK)
			{
				user_resp->append_output_body("{\"code\": -10, \"msg\": \"get statistics from kernel failed\", \"data\": {}}");
				user_resp->set_status_code("500");
			}
			else
			{
				//磁盘统计信息查询
				ArvDiskInfo diskInfo;
				GetDiskInfo(&diskInfo);
				cJSON *root = cJSON_CreateObject();
				cJSON *item = cJSON_CreateObject();
				cJSON_AddItemToObject(root, "code", cJSON_CreateNumber(0));
				cJSON_AddItemToObject(root, "message", cJSON_CreateString("success"));
				cJSON_AddItemToObject(root, "data", item);
				cJSON_AddItemToObject(item, "secretnumber", cJSON_CreateNumber(kernelStat.KeyCount));
				cJSON_AddItemToObject(item, "filesize", cJSON_CreateNumber(diskInfo.totalBytes - diskInfo.totalFreeBytes));
				cJSON_AddItemToObject(item, "filenumber", cJSON_CreateNumber(0));
				cJSON_AddItemToObject(item, "writenumber", cJSON_CreateNumber(kernelStat.Write));
				cJSON_AddItemToObject(item, "readnumber", cJSON_CreateNumber(kernelStat.Read));
				cJSON_AddItemToObject(item, "illegalaccess", cJSON_CreateNumber(kernelStat.Block));
				cJSON_AddItemToObject(item, "dbwritenumber", cJSON_CreateNumber(kernelStat.WriteDB));
				cJSON_AddItemToObject(item, "dbreadnumber", cJSON_CreateNumber(kernelStat.ReadDB));
				cJSON_AddItemToObject(item, "dbillegalaccess", cJSON_CreateNumber(kernelStat.BlockDB));
				cJSON_AddItemToObject(item, "sillegalaccess", cJSON_CreateNumber(kernelStat.Sillegal));
				cJSON_AddItemToObject(item, "abnormalnum", cJSON_CreateNumber(kernelStat.Abnormal));
				char* jsonstr = cJSON_Print(root);
				user_resp->append_output_body(jsonstr);
				user_resp->set_status_code("200");
				cJSON_Delete(root);
			}
		}
		else if (ifnamestr == "saverules")
		{
			cJSON *dataEntry = cJSON_GetObjectItem(jsonHead, "data");
			if (dataEntry == NULL || dataEntry->type != cJSON_Array)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -80, \"msg\": \"data must exist\", \"data\": {}}");
			}
			else
			{
				int dataLen = cJSON_GetArraySize(dataEntry);
				if (dataLen > 0)
				{
					PSaveRulesParam params = (PSaveRulesParam)malloc(dataLen * sizeof(SaveRulesParam));
					memset(params, 0, dataLen * sizeof(SaveRulesParam));
					bool succ = true;
					for (int i = 0; i < dataLen; i++)
					{
						cJSON *pJsonDataItem = cJSON_GetArrayItem(dataEntry, i);
						cJSON *idEntry = cJSON_GetObjectItem(pJsonDataItem, "id");
						cJSON *pkEntry = cJSON_GetObjectItem(pJsonDataItem, "pubkey");
						cJSON *pathEntry = cJSON_GetObjectItem(pJsonDataItem, "path");
						if (idEntry == NULL || pkEntry == NULL || pathEntry == NULL || idEntry->type != cJSON_Number || pkEntry->type != cJSON_String || pathEntry->type != cJSON_Array)
						{
							succ = false;
							break;
						}
						params[i].id = idEntry->valueint;
						PSTR pubkey = pkEntry->valuestring;
						if (!VerifyPublicKey(pubkey))
						{
							succ = false;
							break;
						}
						params[i].pubkey = pubkey;
						int pathLen = cJSON_GetArraySize(pathEntry);
						if (pathLen <= 0)
						{
							succ = false;
							break;
						}
						PZPSTR paths = (PZPSTR)malloc(pathLen * sizeof(PSTR));
						memset(paths, 0, pathLen * sizeof(PSTR));
						BOOL *isDBs = (BOOL*)malloc(pathLen * sizeof(BOOL));
						memset(isDBs, 0, pathLen * sizeof(BOOL));
						for (int j = 0; j < pathLen; j++)
						{
							cJSON *pJsonPathItem = cJSON_GetArrayItem(pathEntry, j);
							cJSON *pJsonPath = cJSON_GetObjectItem(pJsonPathItem, "path");
							cJSON *pJsonIsDB = cJSON_GetObjectItem(pJsonPathItem, "crypt");
							if (pJsonPath == NULL || pJsonIsDB == NULL || pJsonPath->type != cJSON_String || (pJsonIsDB->type != cJSON_True && pJsonIsDB->type != cJSON_False))
							{
								succ = false;
								goto OUTLOOP;
							}
							if (pJsonPath->valuestring[strlen(pJsonPath->valuestring) - 1] != '\\')
							{
								succ = false;
								goto OUTLOOP;
							}
							paths[j] = pJsonPath->valuestring;
							if (cJSON_IsTrue(pJsonIsDB))
								isDBs[j] = TRUE;
							else if (cJSON_IsFalse(pJsonIsDB))
								isDBs[j] = FALSE;
						}
						params[i].paths = paths;
						params[i].isDBs = isDBs;
						params[i].pathLen = pathLen;
					}
				OUTLOOP:
					if (!succ)
					{
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -81, \"msg\": \"id/pubkey/path incorrect\", \"data\": {}}");
					}
					else
					{
						UpdateConfigs(params, dataLen);
						user_resp->set_status_code("200");
						user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
					}
					for (int k = 0; k < dataLen; k++)
					{
						if (params[k].paths)
						{
							free(params[k].paths);
						}
						if (params[k].isDBs)
						{
							free(params[k].isDBs);
						}
					}
					free(params);
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -82, \"msg\": \"no elements in data\", \"data\": {}}");
				}
			}
		}
		else if (ifnamestr == "saveconf2")
		{
			cJSON *idEntry = cJSON_GetObjectItem(jsonHead, "id");
			cJSON *urlEntry = cJSON_GetObjectItem(jsonHead, "url");
			cJSON *pkEntry = cJSON_GetObjectItem(jsonHead, "pubkey");
			cJSON *pathEntry = cJSON_GetObjectItem(jsonHead, "path");
			if (idEntry == NULL || pkEntry == NULL || pathEntry == NULL || idEntry->type != cJSON_Number || pkEntry->type != cJSON_String || pathEntry->type != cJSON_Array)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -23, \"msg\": \"id/pubkey/path must exist\", \"data\": {}}");
			}
			else
			{
				int id = idEntry->valueint;
				PSTR urlStr = (PSTR)"";
				if (urlEntry != NULL)
				{
					urlStr = urlEntry->valuestring;
				}
				PSTR pubkey = pkEntry->valuestring;
				if (!VerifyPublicKey(pubkey))
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -22, \"msg\": \"wrong format of public key\", \"data\": {}}");
				}
				else
				{
					int pathLen = cJSON_GetArraySize(pathEntry);
					if (id > 0 && pathLen > 0)
					{
						BOOL flag = TRUE;
						PZPSTR paths = (PZPSTR)malloc(pathLen * sizeof(PSTR));
						BOOL *isDBs = (BOOL*)malloc(pathLen * sizeof(BOOL));
						for (int i = 0; i < pathLen; i++)
						{
							cJSON *pJsonPathItem = cJSON_GetArrayItem(pathEntry, i);
							cJSON *pJsonPath = cJSON_GetObjectItem(pJsonPathItem, "path");
							cJSON *pJsonIsDB = cJSON_GetObjectItem(pJsonPathItem, "crypt");
							if (pJsonPath == NULL || pJsonIsDB == NULL || pJsonPath->type != cJSON_String || (pJsonIsDB->type != cJSON_True && pJsonIsDB->type != cJSON_False))
							{
								flag = false;
								break;
							}
							if (pJsonPath->valuestring[strlen(pJsonPath->valuestring) - 1] != '\\')
							{
								flag = false;
								break;
							}
							paths[i] = pJsonPath->valuestring;
							if (cJSON_IsTrue(pJsonIsDB))
								isDBs[i] = TRUE;
							else if (cJSON_IsFalse(pJsonIsDB))
								isDBs[i] = FALSE;
						}
						if (flag)
						{
							UpdateConfig(id, pubkey, urlStr, paths, isDBs, pathLen);
							free(paths);
							free(isDBs);
							user_resp->set_status_code("200");
							char* jsonstr = PrintJsonConfig();
							if (jsonstr != NULL)
							{
								user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": ");
								user_resp->append_output_body(jsonstr);
								user_resp->append_output_body("}");
								free(jsonstr);
							}
							else
							{
								user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
							}
						}
						else
						{
							free(paths);
							free(isDBs);
							user_resp->set_status_code("500");
							user_resp->append_output_body("{\"code\": -21, \"msg\": \"path format error\", \"data\": {}}");
						}
					}
					else
					{
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -20, \"msg\": \"parse parameter failed\", \"data\": {}}");
					}
				}
			}
		}
		else if (ifnamestr == "saveauths")
		{
			cJSON *dataEntry = cJSON_GetObjectItem(jsonHead, "data");
			if (dataEntry == NULL || dataEntry->type != cJSON_Array)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -90, \"msg\": \"data must exist\", \"data\": {}}");
			}
			else
			{
				int dataLen = cJSON_GetArraySize(dataEntry);
				if (dataLen > 0)
				{
					PSaveRegProcParam params = (PSaveRegProcParam)malloc(dataLen * sizeof(SaveRegProcParam));
					memset(params, 0, dataLen * sizeof(SaveRegProcParam));
					bool succ = true;
					for (int i = 0; i < dataLen; i++)
					{
						cJSON *pJsonDataItem = cJSON_GetArrayItem(dataEntry, i);
						cJSON *procNameEntry = cJSON_GetObjectItem(pJsonDataItem, "procName");
						cJSON *inheritEntry = cJSON_GetObjectItem(pJsonDataItem, "inherit");
						cJSON *keyIDEntry = cJSON_GetObjectItem(pJsonDataItem, "keyID");
						if (procNameEntry == NULL || inheritEntry == NULL || keyIDEntry == NULL || procNameEntry->type != cJSON_String || keyIDEntry->type != cJSON_Number || (inheritEntry->type != cJSON_True && inheritEntry->type != cJSON_False))
						{
							succ = false;
							break;
						}
						params[i].procName = procNameEntry->valuestring;
						if (cJSON_IsTrue(inheritEntry))
							params[i].inherit = true;
						else
							params[i].inherit = false;
						params[i].ruleID = keyIDEntry->valueint;
					}
					if (!succ)
					{
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -91, \"msg\": \"procName/inherit/keyID is NULL\", \"data\": {}}");
					}
					else
					{
						UpdateRegProcsConfig(params, dataLen);
						user_resp->set_status_code("200");
						user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
					}
					free(params);
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -92, \"msg\": \"no elements in data\", \"data\": {}}");
				}
			}
		}
		else if (ifnamestr == "authproc")
		{
			cJSON *dataEntry = cJSON_GetObjectItem(jsonHead, "data");
			if (dataEntry == NULL || dataEntry->type != cJSON_Array)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -170, \"msg\": \"data must exist\", \"data\": {}}");
			}
			else
			{
				int dataLen = cJSON_GetArraySize(dataEntry);
				if (dataLen > 0)
				{
					PSaveRegProcParam params = (PSaveRegProcParam)malloc(dataLen * sizeof(SaveRegProcParam));
					memset(params, 0, dataLen * sizeof(SaveRegProcParam));
					bool succ = true;
					for (int i = 0; i < dataLen; i++)
					{
						cJSON *pJsonDataItem = cJSON_GetArrayItem(dataEntry, i);
						cJSON *procNameEntry = cJSON_GetObjectItem(pJsonDataItem, "procName");
						cJSON *inheritEntry = cJSON_GetObjectItem(pJsonDataItem, "inherit");
						cJSON *keyIDEntry = cJSON_GetObjectItem(pJsonDataItem, "keyID");
						if (procNameEntry == NULL || inheritEntry == NULL || procNameEntry->type != cJSON_String || (inheritEntry->type != cJSON_True && inheritEntry->type != cJSON_False))
						{
							succ = false;
							break;
						}
						params[i].procName = procNameEntry->valuestring;
						if (cJSON_IsTrue(inheritEntry))
							params[i].inherit = true;
						else
							params[i].inherit = false;
						if (keyIDEntry == NULL)
						{
							params[i].ruleID = 2;
						}
						else
						{
							if (keyIDEntry->type != cJSON_Number)
							{
								succ = false;
								break;
							}
							params[i].ruleID = keyIDEntry->valueint;
						}
					}
					if (!succ)
					{
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -171, \"msg\": \"procName/inherit/keyID is NULL\", \"data\": {}}");
					}
					else
					{
						UpdateAuthProcsConfig(params, dataLen);
						user_resp->set_status_code("200");
						user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
					}
					free(params);
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -172, \"msg\": \"no elements in data\", \"data\": {}}");
				}
			}
		}
		else if (ifnamestr == "savedbconf")
		{
			cJSON *idEntry = cJSON_GetObjectItem(jsonHead, "id");
			cJSON *pathEntry = cJSON_GetObjectItem(jsonHead, "path");
			if (idEntry == NULL || pathEntry == NULL || idEntry->type != cJSON_Number || pathEntry->type != cJSON_String)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -31, \"msg\": \"id/path must exist\", \"data\": {}}");
			}
			else
			{
				int id = idEntry->valueint;
				BOOL ret = UpdateDBPath(id, pathEntry->valuestring, TRUE);
				if (ret)
				{
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -30, \"msg\": \"parse parameter failed\", \"data\": {}}");
				}
			}
		}
		else if (ifnamestr == "loadconf2")
		{
			char* jsonstr = PrintJsonConfig();
			if (jsonstr != NULL)
			{
				user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": ");
				user_resp->append_output_body(jsonstr);
				user_resp->append_output_body("}");
				free(jsonstr);
			}
			else
			{
				user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
			}
			user_resp->set_status_code("200");
		}
		else if (ifnamestr == "loaddbconf")
		{
			PSTR conf = LoadDBConf();
			user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": ");
			user_resp->append_output_body(conf);
			user_resp->append_output_body("}");
			free(conf);
		}
		else if (ifnamestr == "savedaemonconf")
		{
			TCHAR daemonExePath[MAX_PATH];
			GetModuleFileName(NULL, daemonExePath, MAX_PATH);
			WCHAR *ch = wcsrchr(daemonExePath, '\\');
			ch[1] = L'a';
			ch[2] = L'r';
			ch[3] = L'v';
			ch[4] = L'd';
			ch[5] = L'a';
			ch[6] = L'e';
			ch[7] = L'm';
			ch[8] = L'o';
			ch[9] = L'n';
			ch[10] = L'.';
			ch[11] = L'e';
			ch[12] = L'x';
			ch[13] = L'e';
			ch[14] = L'\0';

			cJSON *daemonNameEntry = cJSON_GetObjectItem(jsonHead, "daemonName");
			cJSON *exeNameEntry = cJSON_GetObjectItem(jsonHead, "exeName");
			cJSON *keyIDEntry = cJSON_GetObjectItem(jsonHead, "keyID");
			cJSON *urlEntry = cJSON_GetObjectItem(jsonHead, "url");
			if (daemonNameEntry == NULL || exeNameEntry == NULL || keyIDEntry == NULL || urlEntry == NULL ||
				daemonNameEntry->type != cJSON_String || exeNameEntry->type != cJSON_String || keyIDEntry->type != cJSON_Number || urlEntry->type != cJSON_String)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -44, \"msg\": \"daemonName/exeName/keyID/url must exist\", \"data\": {}}");
			}
			else
			{
				PWSTR dpath = NULL;
				PWSTR epath = NULL;
				UTF8ToUnicode(daemonNameEntry->valuestring, &dpath);
				UTF8ToUnicode(exeNameEntry->valuestring, &epath);
				FILE *fp;
				errno_t err = _wfopen_s(&fp, epath, L"rb");
				if (err > 0) {
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -43, \"msg\": \"source file not exist\", \"data\": {}}");
				}
				else
				{
					int len = CopyByBlock(dpath, daemonExePath);
					if (len < 0)
					{
						if (len == -2)
						{
							user_resp->set_status_code("500");
							user_resp->append_output_body("{\"code\": -42, \"msg\": \"arvdaemon file not exist\", \"data\": {}}");
						}
						else
						{
							user_resp->set_status_code("500");
							user_resp->append_output_body("{\"code\": -40, \"msg\": \"copy daemon failed\", \"data\": {}}");
						}
					}
					else
					{
						BOOL ret = UpdateDaemonConfig(daemonNameEntry->valuestring, exeNameEntry->valuestring, keyIDEntry->valueint, urlEntry->valuestring);
						if (ret) {
							//char *jsonstr = PrintDaemonConfig(NULL);
							user_resp->set_status_code("200");
							user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
							//user_resp->append_output_body(jsonstr);
							//user_resp->append_output_body("}");
							//free(jsonstr);
						}
						else
						{
							user_resp->set_status_code("500");
							user_resp->append_output_body("{\"code\": -41, \"msg\": \"parse parameter failed\", \"data\": {}}");
						}
					}
				}
				if (fp != NULL)
				{
					fclose(fp);
				}
				if (dpath != NULL)
				{
					free(dpath);
				}
				if (epath != NULL)
				{
					free(epath);
				}
			}
		}
		else if (ifnamestr == "loaddaemonconf")
		{
			cJSON *daemonEntry = cJSON_GetObjectItem(jsonHead, "daemonName");
			char *jsonstr = NULL;
			if (daemonEntry == NULL)
			{
				jsonstr = PrintDaemonConfig(NULL);
			}
			else
			{
				if (daemonEntry->type != cJSON_String)
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -51, \"msg\": \"invalid daemon name\", \"data\": {}}");
				}
				else
				{
					jsonstr = PrintDaemonConfig(daemonEntry->valuestring);
				}
			}
			if (jsonstr==NULL)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -50, \"msg\": \"no daemon configuration found\", \"data\": {}}");
			}
			else
			{
				user_resp->set_status_code("200");
				user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": ");
				user_resp->append_output_body(jsonstr);
				user_resp->append_output_body("}");
				free(jsonstr);
			}
		}
		else if (ifnamestr == "kms")
		{
			cJSON *portEntry = cJSON_GetObjectItem(jsonHead, "port");
			int port = 0;
			if (portEntry != NULL && portEntry->type == cJSON_Number)
			{
				port = portEntry->valueint;
			}
			cJSON *urlEntry = cJSON_GetObjectItem(jsonHead, "url");
			PSTR urlStr = (PSTR)"";
			if (urlEntry != NULL && urlEntry->type == cJSON_String)
			{
				urlStr = urlEntry->valuestring;
			}
			BOOL ret = UpdateSysConfig(port, urlStr);
			if (ret)
			{
				HKEY hKey = NULL;
				TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
				LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
				if (lRet == ERROR_SUCCESS) {
					RegDeleteValue(hKey, _T("keyManageAddr"));
					PWSTR kma;
					UTF8ToUnicode(urlEntry->valuestring, &kma);
					DWORD len = sizeof(TCHAR)*(wcslen(kma) + 1);
					if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("keyManageAddr"), 0, REG_SZ, (const BYTE*)kma, len))
					{
						RegCloseKey(hKey);
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -62, \"msg\": \"save registry of system config failed\", \"data\": {}}");
					}
					else
					{
						RegCloseKey(hKey);
						user_resp->set_status_code("200");
						user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
					}
				}
				else {
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -61, \"msg\": \"open registry of system config failed\", \"data\": {}}");
				}
			}
			else
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -60, \"msg\": \"save system config failed\", \"data\": {}}");
			}
		}
		else if (ifnamestr == "allowunload")
		{
			cJSON *allowUnloadEntry = cJSON_GetObjectItem(jsonHead, "allow");
			if (cJSON_IsTrue(allowUnloadEntry))
			{
				SendAllowUnloadMessage(TRUE);
			}
			else
			{
				SendAllowUnloadMessage(FALSE);
			}
			user_resp->set_status_code("200");
			user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
		}
		else if (ifnamestr == "disablefilter")
		{
			cJSON *disableEntry = cJSON_GetObjectItem(jsonHead, "disable");
			if (cJSON_IsTrue(disableEntry))
			{
				SendSetControlProcMessage(TRUE);
			}
			else
			{
				SendSetControlProcMessage(FALSE);
			}
			user_resp->set_status_code("200");
			user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
		}
		else if (ifnamestr == "saveregproc")
		{
			cJSON *procNameEntry = cJSON_GetObjectItem(jsonHead, "procName");
			cJSON *inheritEntry = cJSON_GetObjectItem(jsonHead, "inherit");
			cJSON *keyIDEntry = cJSON_GetObjectItem(jsonHead, "keyID");
			cJSON *addEntry = cJSON_GetObjectItem(jsonHead, "add");

			if (procNameEntry == NULL || inheritEntry == NULL || keyIDEntry == NULL || addEntry == NULL ||
				procNameEntry->type != cJSON_String || keyIDEntry->type != cJSON_Number || (inheritEntry->type != cJSON_True && inheritEntry->type != cJSON_False) || (addEntry->type != cJSON_True && addEntry->type != cJSON_False))
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -72, \"msg\": \"procName/inherit/keyID/add must exist\", \"data\": {}}");
			}
			else
			{
				BOOL ret = UpdateRegProcConfig(procNameEntry->valuestring, cJSON_IsTrue(inheritEntry), keyIDEntry->valueint, cJSON_IsTrue(addEntry));
				if (ret) {
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -71, \"msg\": \"parse parameter failed\", \"data\": {}}");
				}
			}
		}
		else if (ifnamestr == "setstate")
		{
			cJSON *learnEntry = cJSON_GetObjectItem(jsonHead, "state");
			if (learnEntry == NULL || learnEntry->type != cJSON_String)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -100, \"msg\": \"state parameter must exist\", \"data\": {}}");
			}
			else
			{
				std::string learnstr(learnEntry->valuestring);
				bool flag = true;
				DWORD logFlag;
				DWORD logOnly;
				if (learnstr == "learn")
				{
					logFlag = 1;
					logOnly = 2;
				}
				else if (learnstr == "verify")
				{
					logFlag = 1;
					logOnly = 1;
				}
				else if (learnstr == "enable")
				{
					logFlag = 1;
					logOnly = 0;
				}
				else if (learnstr == "disable")
				{
					logFlag = 0;
					logOnly = 2;
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -101, \"msg\": \"learn parameter must exist\", \"data\": {}}");
					flag = false;
				}
				if (flag)
				{
					HKEY hKey = NULL;
					TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
					LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
					if (lRet == ERROR_SUCCESS) {
						RegDeleteValue(hKey, _T("LogFlag"));
						if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("LogFlag"), 0, REG_DWORD, (CONST BYTE*)&logFlag, sizeof(DWORD)))
						{
							//RegCloseKey(hKey);
							user_resp->set_status_code("500");
							user_resp->append_output_body("{\"code\": -102, \"msg\": \"save registry of system config failed\", \"data\": {}}");
						}
						else
						{
							//RegCloseKey(hKey);
							//user_resp->set_status_code("200");
							//user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
							RegDeleteValue(hKey, _T("LogOnly"));
							if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("LogOnly"), 0, REG_DWORD, (CONST BYTE*)&logOnly, sizeof(DWORD)))
							{
								user_resp->set_status_code("500");
								user_resp->append_output_body("{\"code\": -103, \"msg\": \"save registry of system config failed\", \"data\": {}}");
							}
							else
							{
								SendSetFilterStatusMessage(logFlag, logOnly);
								user_resp->set_status_code("200");
								user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
							}
						}
						RegCloseKey(hKey);
						
					}
					else {
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -102, \"msg\": \"open registry of ArvCtl config failed\", \"data\": {}}");
					}
				}
			}
		}
		else if (ifnamestr == "getstate")
		{
			DWORD logFlag = -1;
			DWORD logOnly = -1;
			HKEY hKey = NULL;
			TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
			DWORD dwSize = sizeof(DWORD);
			LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
			if (lRet == ERROR_SUCCESS) {
				if (ERROR_SUCCESS != ::RegQueryValueEx(hKey, _T("LogFlag"), NULL, NULL, (LPBYTE)&logFlag, &dwSize))
				{
					logFlag = 0;
				}
				if (ERROR_SUCCESS != ::RegQueryValueEx(hKey, _T("LogOnly"), NULL, NULL, (LPBYTE)&logOnly, &dwSize))
				{
					logOnly = 2;
				}
				RegCloseKey(hKey);
				if (logFlag == 1 && logOnly == 2)
				{
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"state\": \"learn\", \"data\": {}}");
				}
				else if (logFlag == 1 && logOnly == 1)
				{
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"state\": \"verify\", \"data\": {}}");
				}
				else if (logFlag == 1 && logOnly == 0)
				{
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"state\": \"enable\", \"data\": {}}");
				}
				else if (logFlag == 0 && logOnly == 2)
				{
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"state\": \"disable\", \"data\": {}}");
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -111, \"msg\": \"invalid state\", \"data\": {}}");
				}
			}
			else {
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -110, \"msg\": \"open registry of ArvCtl config failed\", \"data\": {}}");
			}
		}
		else if (ifnamestr == "loadlog")
		{
			bool del = false;
			cJSON *deleteEntry = cJSON_GetObjectItem(jsonHead, "delete");
			if (deleteEntry != NULL && (deleteEntry->type == cJSON_True || deleteEntry->type == cJSON_False))
			{
				del = cJSON_IsTrue(deleteEntry);
				if (del)
				{
					SendSetClearLogMessage(LEARN);
				}
			}
			HKEY hKey = NULL;
			TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
			TCHAR logPath[512];
			DWORD logPathSize = 512;
			DWORD dwType = REG_SZ;
			LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
			if (lRet == ERROR_SUCCESS) {
				if (ERROR_SUCCESS != ::RegQueryValueEx(hKey, _T("LogPath"), NULL, &dwType, (LPBYTE)logPath, &logPathSize))
				{
					logPath[0] = L'\\';
					logPath[1] = L'?';
					logPath[2] = L'?';
					logPath[3] = L'\\';
					logPath[4] = L'C';
					logPath[5] = L':';
					logPath[6] = L'\\';
					logPath[7] = L'f';
					logPath[8] = L'i';
					logPath[9] = L'l';
					logPath[10] = L't';
					logPath[11] = L'e';
					logPath[12] = L'r';
					logPath[13] = L'.';
					logPath[14] = L'l';
					logPath[15] = L'o';
					logPath[16] = L'g';
					logPath[17] = L'\0';
					if (del)
					{
						logPath[17] = L'.';
						logPath[18] = L'b';
						logPath[19] = L'a';
						logPath[20] = L'k';
						logPath[21] = L'\0';
					}
				}
				else if (del)
				{
					logPath[logPathSize] = L'.';
					logPath[logPathSize+1] = L'b';
					logPath[logPathSize+2] = L'a';
					logPath[logPathSize+3] = L'k';
					logPath[logPathSize+4] = L'\0';
				}
				RegCloseKey(hKey);
				TCHAR *logPathFull = &logPath[4];
				//TODO: loop read file
				if (_waccess(logPathFull, 0) == 0)
				{
					FILE *fp1;
					errno_t err = _wfopen_s(&fp1, logPathFull, L"r");
					if (fp1 == NULL) {
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -121, \"msg\": \"open log file failed\", \"data\": {}}");
					}
					else
					{
						user_resp->set_status_code("200");
						user_resp->add_header_pair("Content-Type", "application/octet-stream");
						void *buffer = (void *)malloc(8192);
						while (1) {
							int op = fread(buffer, 1, 8192, fp1);
							if (op <= 0) break;
							user_resp->append_output_body(buffer, op);
						}
						free(buffer);
						fclose(fp1);
						if (del)
						{
							_wremove(logPathFull);
						}
					}
				}
			}
			else {
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -120, \"msg\": \"open registry of ArvCtl config failed\", \"data\": {}}");
			}
		}
		else if (ifnamestr == "illegalaccess")
		{
			bool del = false;
			cJSON *deleteEntry = cJSON_GetObjectItem(jsonHead, "delete");
			if (deleteEntry != NULL && (deleteEntry->type == cJSON_True || deleteEntry->type == cJSON_False))
			{
				del = cJSON_IsTrue(deleteEntry);
				if (del)
				{
					SendSetClearLogMessage(ENABLE);
				}
			}
			HKEY hKey = NULL;
			TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
			TCHAR logPath[512];
			DWORD logPathSize = 512;
			DWORD dwType = REG_SZ;
			LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
			if (lRet == ERROR_SUCCESS) {
				if (ERROR_SUCCESS != ::RegQueryValueEx(hKey, _T("IllegalLogPath"), NULL, &dwType, (LPBYTE)logPath, &logPathSize))
				{
					logPath[0] = L'\\';
					logPath[1] = L'?';
					logPath[2] = L'?';
					logPath[3] = L'\\';
					logPath[4] = L'C';
					logPath[5] = L':';
					logPath[6] = L'\\';
					logPath[7] = L'i';
					logPath[8] = L'l';
					logPath[9] = L'l';
					logPath[10] = L'e';
					logPath[11] = L'g';
					logPath[12] = L'a';
					logPath[13] = L'l';
					logPath[14] = L'.';
					logPath[15] = L'l';
					logPath[16] = L'o';
					logPath[17] = L'g';
					logPath[18] = L'\0';
					if (del)
					{
						logPath[18] = L'.';
						logPath[19] = L'b';
						logPath[20] = L'a';
						logPath[21] = L'k';
						logPath[22] = L'\0';
					}
				}
				else if (del)
				{
					logPath[logPathSize] = L'.';
					logPath[logPathSize + 1] = L'b';
					logPath[logPathSize + 2] = L'a';
					logPath[logPathSize + 3] = L'k';
					logPath[logPathSize + 4] = L'\0';
				}
				RegCloseKey(hKey);
				TCHAR *logPathFull = &logPath[4];
				//TODO: loop read file
				if (_waccess(logPathFull, 0) == 0)
				{
					FILE *fp1;
					errno_t err = _wfopen_s(&fp1, logPathFull, L"r");
					if (fp1 == NULL) {
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -131, \"msg\": \"open log file failed\", \"data\": {}}");
					}
					else
					{
						user_resp->set_status_code("200");
						user_resp->add_header_pair("Content-Type", "application/octet-stream");
						void *buffer = (void *)malloc(8192);
						while (1) {
							int op = fread(buffer, 1, 8192, fp1);
							if (op <= 0) break;
							user_resp->append_output_body(buffer, op);
						}
						free(buffer);
						fclose(fp1);
						if (del)
						{
							_wremove(logPathFull);
						}
					}
				}
			}
			else {
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -130, \"msg\": \"open registry of ArvCtl config failed\", \"data\": {}}");
			}
		}
		else if (ifnamestr == "sillegalaccess")
		{
			bool del = false;
			cJSON *deleteEntry = cJSON_GetObjectItem(jsonHead, "delete");
			if (deleteEntry != NULL && (deleteEntry->type == cJSON_True || deleteEntry->type == cJSON_False))
			{
				del = cJSON_IsTrue(deleteEntry);
				if (del)
				{
					SendSetClearLogMessage(VERIFY);
				}
			}
			HKEY hKey = NULL;
			TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
			TCHAR logPath[512];
			DWORD logPathSize = 512;
			DWORD dwType = REG_SZ;
			LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
			if (lRet == ERROR_SUCCESS) {
				if (ERROR_SUCCESS != ::RegQueryValueEx(hKey, _T("SillegalLogPath"), NULL, &dwType, (LPBYTE)logPath, &logPathSize))
				{
					logPath[0] = L'\\';
					logPath[1] = L'?';
					logPath[2] = L'?';
					logPath[3] = L'\\';
					logPath[4] = L'C';
					logPath[5] = L':';
					logPath[6] = L'\\';
					logPath[7] = L's';
					logPath[8] = L'i';
					logPath[9] = L'l';
					logPath[10] = L'l';
					logPath[11] = L'e';
					logPath[12] = L'g';
					logPath[13] = L'a';
					logPath[14] = L'l';
					logPath[15] = L'.';
					logPath[16] = L'l';
					logPath[17] = L'o';
					logPath[18] = L'g';
					logPath[19] = L'\0';
					if (del)
					{
						logPath[19] = L'.';
						logPath[20] = L'b';
						logPath[21] = L'a';
						logPath[22] = L'k';
						logPath[23] = L'\0';
					}
				}
				else if (del)
				{
					logPath[logPathSize] = L'.';
					logPath[logPathSize + 1] = L'b';
					logPath[logPathSize + 2] = L'a';
					logPath[logPathSize + 3] = L'k';
					logPath[logPathSize + 4] = L'\0';
				}
				RegCloseKey(hKey);
				TCHAR *logPathFull = &logPath[4];
				//TODO: loop read file
				if (_waccess(logPathFull, 0) == 0)
				{
					FILE *fp1;
					errno_t err = _wfopen_s(&fp1, logPathFull, L"r");
					if (fp1 == NULL) {
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -141, \"msg\": \"open log file failed\", \"data\": {}}");
					}
					else
					{
						user_resp->set_status_code("200");
						user_resp->add_header_pair("Content-Type", "application/octet-stream");
						void *buffer = (void *)malloc(8192);
						while (1) {
							int op = fread(buffer, 1, 8192, fp1);
							if (op <= 0) break;
							user_resp->append_output_body(buffer, op);
						}
						free(buffer);
						fclose(fp1);
						if (del)
						{
							_wremove(logPathFull);
						}
					}
				}
			}
			else {
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -140, \"msg\": \"open registry of ArvCtl config failed\", \"data\": {}}");
			}
		}
		else if (ifnamestr == "abnormal")
		{
			bool del = false;
			cJSON *deleteEntry = cJSON_GetObjectItem(jsonHead, "delete");
			if (deleteEntry != NULL && (deleteEntry->type == cJSON_True || deleteEntry->type == cJSON_False))
			{
				del = cJSON_IsTrue(deleteEntry);
				if (del)
				{
					SendSetClearLogMessage(ABNORMAL);
				}
			}
			HKEY hKey = NULL;
			TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
			TCHAR logPath[512];
			DWORD logPathSize = 512;
			DWORD dwType = REG_SZ;
			LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
			if (lRet == ERROR_SUCCESS) {
				if (ERROR_SUCCESS != ::RegQueryValueEx(hKey, _T("AbnormalLogPath"), NULL, &dwType, (LPBYTE)logPath, &logPathSize))
				{
					logPath[0] = L'\\';
					logPath[1] = L'?';
					logPath[2] = L'?';
					logPath[3] = L'\\';
					logPath[4] = L'C';
					logPath[5] = L':';
					logPath[6] = L'\\';
					logPath[7] = L'a';
					logPath[8] = L'b';
					logPath[9] = L'n';
					logPath[10] = L'o';
					logPath[11] = L'r';
					logPath[12] = L'm';
					logPath[13] = L'a';
					logPath[14] = L'l';
					logPath[15] = L'.';
					logPath[16] = L'l';
					logPath[17] = L'o';
					logPath[18] = L'g';
					logPath[19] = L'\0';
					if (del)
					{
						logPath[19] = L'.';
						logPath[20] = L'b';
						logPath[21] = L'a';
						logPath[22] = L'k';
						logPath[23] = L'\0';
					}
				}
				else if (del)
				{
					logPath[logPathSize] = L'.';
					logPath[logPathSize + 1] = L'b';
					logPath[logPathSize + 2] = L'a';
					logPath[logPathSize + 3] = L'k';
					logPath[logPathSize + 4] = L'\0';
				}
				RegCloseKey(hKey);
				TCHAR *logPathFull = &logPath[4];
				//TODO: loop read file
				if (_waccess(logPathFull, 0) == 0)
				{
					FILE *fp1;
					errno_t err = _wfopen_s(&fp1, logPathFull, L"r");
					if (fp1 == NULL) {
						user_resp->set_status_code("500");
						user_resp->append_output_body("{\"code\": -151, \"msg\": \"open log file failed\", \"data\": {}}");
					}
					else
					{
						user_resp->set_status_code("200");
						user_resp->add_header_pair("Content-Type", "application/octet-stream");
						void *buffer = (void *)malloc(8192);
						while (1) {
							int op = fread(buffer, 1, 8192, fp1);
							if (op <= 0) break;
							user_resp->append_output_body(buffer, op);
						}
						free(buffer);
						fclose(fp1);
						if (del)
						{
							_wremove(logPathFull);
						}
					}
				}
			}
			else {
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -150, \"msg\": \"open registry of ArvCtl config failed\", \"data\": {}}");
			}
		}
		else if (ifnamestr == "saveexeallowedpaths")
		{
			cJSON *dataEntry = cJSON_GetObjectItem(jsonHead, "data");
			if (dataEntry == NULL || dataEntry->type != cJSON_Array)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -160, \"msg\": \"data must exist\", \"data\": {}}");
			}
			else
			{
				int dataLen = cJSON_GetArraySize(dataEntry);
				if (dataLen > 0)
				{
					PZPSTR paths = (PZPSTR)malloc(sizeof(PSTR)*dataLen);
					for (int i = 0; i < dataLen; i++)
					{
						cJSON *pJsonDataItem = cJSON_GetArrayItem(dataEntry, i);
						if (pJsonDataItem != NULL && pJsonDataItem->type == cJSON_String)
							paths[i] = pJsonDataItem->valuestring;
					}
					UpdateExeAllowedPathConfig(paths, dataLen);
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
					free(paths);
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -161, \"msg\": \"no elements in data\", \"data\": {}}");
				}
			}
		}
		else if (ifnamestr == "setabnormalthreshold")
		{
			cJSON *thresholdEntry = cJSON_GetObjectItem(jsonHead, "threshold");
			cJSON *intervalEntry = cJSON_GetObjectItem(jsonHead, "interval");
			if (thresholdEntry == NULL || thresholdEntry->type != cJSON_Number || intervalEntry == NULL || intervalEntry->type != cJSON_Number)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -170, \"msg\": \"threshold and interval parameters must be exist\", \"data\": {}}");
			}
			else
			{
				UINT threshold = thresholdEntry->valueint;
				ULONG interval = intervalEntry->valueint;
				SendSetAbnormalThresholdMessage(threshold, interval);
				user_resp->set_status_code("200");
				user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
			}
		}
		else if (ifnamestr == "killproc")
		{
			cJSON *procEntry = cJSON_GetObjectItem(jsonHead, "procname");
			if (procEntry == NULL || procEntry->type != cJSON_String)
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -180, \"msg\": \"procname parameter must exist\", \"data\": {}}");
			}
			else
			{
				bool flag = false;
				PWSTR procname = NULL;
				UTF8ToUnicode(procEntry->valuestring, &procname);
				HANDLE hSnapShot =(HANDLE)CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
				PROCESSENTRY32 pEntry;
				pEntry.dwSize = sizeof(pEntry);
				BOOL hRes = Process32First(hSnapShot, &pEntry);
				while (hRes)
				{
					if (_wcsicmp(pEntry.szExeFile, procname) == 0 && pEntry.th32ProcessID != GetCurrentProcessId())
					{
						HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
							(DWORD)pEntry.th32ProcessID);
						if (hProcess != NULL)
						{
							TerminateProcess(hProcess, 9);
							CloseHandle(hProcess);
							flag = true;
						}
					}
					hRes = Process32Next(hSnapShot, &pEntry);
				}
				CloseHandle(hSnapShot);
				free(procname);
				if (flag)
				{
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
				}
				else
				{
					user_resp->set_status_code("500");
					user_resp->append_output_body("{\"code\": -181, \"msg\": \"no process killed\", \"data\": {}}");
				}
			}
		}
		else
		{
			user_resp->set_status_code("450");
			user_resp->append_output_body("{\"code\": -999, \"msg\": \"no matched action\", \"data\": {}}");
		}
	}
	else
	{
		user_resp->set_status_code("450");
		user_resp->append_output_body("{\"code\": -1, \"msg\": \"request type not match\", \"data\": {}}");
	}
	cJSON_Delete(jsonHead);
	return;
}

static WFHttpServer server(process);

bool StartArvCtlServer()
{
	//WFHttpServer server(process);
	if (server.start(listenPort) == 0)
	{
		HKEY hKey = NULL;
		TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
		LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
		if (lRet == ERROR_SUCCESS) {
			RegDeleteValue(hKey, _T("listenPort"));
			RegDeleteValue(hKey, _T("keyManageAddr"));
			DWORD dwValuePort = (DWORD)listenPort;
			if (ERROR_SUCCESS != RegSetValueEx(hKey, _T("listenPort"), 0, REG_DWORD, (CONST BYTE*)&dwValuePort, sizeof(DWORD)))
			{
				RegCloseKey(hKey);
				return false;
			}
			
			PWSTR kma;
			UTF8ToUnicode(keyManageAddr, &kma);
			DWORD len = sizeof(TCHAR)*(wcslen(kma) + 1);
			if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("keyManageAddr"), 0, REG_SZ, (const BYTE*)kma, len))
			{
				RegCloseKey(hKey);
				return false;
			}
			RegCloseKey(hKey);
		}
		else
		{
			return false;
		}
		return true;
	}
	else
	{
		return false;
	}
}

void StopArvCtlServer()
{
	server.stop();
	HKEY hKey = NULL;
	TCHAR *lpszSubKey = (TCHAR*)_T("SYSTEM\\CurrentControlSet\\Services\\ArvCtl");
	LONG lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_ALL_ACCESS, &hKey);
	if (lRet == ERROR_SUCCESS) {
		RegDeleteValue(hKey, _T("listenPort"));
		RegDeleteValue(hKey, _T("keyManageAddr"));
		RegCloseKey(hKey);
	}
}

