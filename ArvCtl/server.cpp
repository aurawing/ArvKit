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
	if (ifname != NULL)
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
				char* jsonstr = cJSON_Print(root);
				user_resp->append_output_body(jsonstr);
				user_resp->set_status_code("200");
				cJSON_Delete(root);
			}
		}
		else if (ifnamestr == "saveconf2")
		{
			cJSON *idEntry = cJSON_GetObjectItem(jsonHead, "id");
			int id = idEntry->valueint;
			cJSON *urlEntry = cJSON_GetObjectItem(jsonHead, "url");
			PSTR url = urlEntry->valuestring;
			cJSON *pkEntry = cJSON_GetObjectItem(jsonHead, "pubkey");
			PSTR pubkey = pkEntry->valuestring;
			if (!VerifyPublicKey(pubkey))
			{
				user_resp->set_status_code("500");
				user_resp->append_output_body("{\"code\": -22, \"msg\": \"wrong format of public key\", \"data\": {}}");
			}
			else
			{
				cJSON *pathEntry = cJSON_GetObjectItem(jsonHead, "path");
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
						UpdateConfig(id, pubkey, url, paths, isDBs, pathLen);
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
		else if (ifnamestr == "savedbconf")
		{
			cJSON *idEntry = cJSON_GetObjectItem(jsonHead, "id");
			int id = idEntry->valueint;
			cJSON *pathEntry = cJSON_GetObjectItem(jsonHead, "path");
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
				jsonstr = PrintDaemonConfig(daemonEntry->valuestring);
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
			if (portEntry != NULL)
			{
				port = portEntry->valueint;
			}
			cJSON *urlEntry = cJSON_GetObjectItem(jsonHead, "url");
			BOOL ret = UpdateSysConfig(port, urlEntry->valuestring);
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
					RegCloseKey(hKey);
					user_resp->set_status_code("200");
					user_resp->append_output_body("{\"code\": 0, \"msg\": \"success\", \"data\": {}}");
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
		else
		{
			user_resp->set_status_code("450");
			user_resp->append_output_body("{\"code\": -99, \"msg\": \"no matched action\", \"data\": {}}");
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

