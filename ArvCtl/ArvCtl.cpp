// ArvCtl.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <locale.h>
#include <strsafe.h>
#include <tchar.h>
#include "server.h"
#include "utils.h"
#include"cJSON.h"


#pragma comment(lib, "advapi32.lib")

#define SVC_NAME	TEXT("ArvCtl")
#define SVC_ERROR	((DWORD)0xC0020001L)
#define FLT_SVC_NAME L"ArvFilter"
#define LOGFILE "D:\\arv\\arvlog.txt"

typedef struct _PathShaMap {
	BYTE sha256[SHA256_BLOCK_SIZE];
	PSTR path;
} PathShaMap, *PPathShaMap;

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;
//HANDLE					port = INVALID_HANDLE_VALUE;
FILE* logfile;

POpRule *pzpRules = NULL;
PPathShaMap pathMap = NULL;
int ruleSize = 0;
int pathSize = 0;


VOID SvcInstall(void);
VOID WINAPI SvcCtrlHandler(DWORD);
VOID WINAPI SvcMain(DWORD, LPTSTR *);

VOID ReportSvcStatus(DWORD, DWORD, DWORD);
VOID SvcInit(DWORD, LPTSTR *);
VOID SvcReportEvent(LPTSTR);
BOOL RestartArvFilter();
BOOL ConfigArvFilter();
int WriteToLog(char*);

//
// Purpose: 
//   Entry point for the process
//
// Note:
//   The main function of a service program calls the StartServiceCtrlDispatcher function to connect to the 
//      service control manager (SCM) and start the control dispatcher thread. The dispatcher thread loops, 
//      waiting for incoming control requests for the services specified in the dispatch table. This thread 
//      returns when there is an error or when all of the services in the process have terminated. When all 
//      services in the process have terminated, the SCM sends a control request to the dispatcher thread 
//      telling it to exit. This thread then returns from the StartServiceCtrlDispatcher call and the process
//      can terminate.
//
// Parameters:
//   None
// 
// Return value:
//   None
//
int __cdecl _tmain(int argc, TCHAR *argv[])
{
	// If command-line parameter is "install", install the service. 
	// Otherwise, the service is probably being started by the SCM.
	setlocale(LC_ALL, "");
	if (lstrcmpi(argv[1], TEXT("install")) == 0)
	{
		SvcInstall();
		return 0;
	}
	// TO_DO: Add any additional services for the process to this table.
	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ (LPWSTR)SVC_NAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
		{ NULL, NULL }
	};

	DWORD dw_RetCode = -1;

	// This call returns when the service has stopped. 
	// The process should simply terminate when the call returns.

	if (!StartServiceCtrlDispatcher(DispatchTable))
	{
		dw_RetCode = GetLastError();
		MessageBoxEx(NULL, _T("start ArvCtl service fail!"), NULL, 0, 0);
		SvcReportEvent((LPTSTR)TEXT("StartServiceCtrlDispatcher"));
	}
}

//
// Purpose: 
//   Installs a service in the SCM database
//
// Parameters:
//   None
// 
// Return value:
//   None
//
VOID SvcInstall()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	TCHAR szPath[MAX_PATH];

	if (!GetModuleFileName(NULL, szPath, MAX_PATH))
	{
		printf("Cannot install service (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Create the service

	schService = CreateService(
		schSCManager,              // SCM database 
		SVC_NAME,                   // name of service 
		SVC_NAME,                   // service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_WIN32_OWN_PROCESS, // service type 
		SERVICE_DEMAND_START,      // start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		szPath,                    // path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // LocalSystem account 
		NULL);                     // no password 

	if (schService == NULL)
	{
		printf("CreateService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}
	else printf("Service installed successfully\n");

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

//
// Purpose: 
//   Entry point for the service
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None.
//
VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	// Register the handler function for the service
	fopen_s(&logfile, LOGFILE, "a+");
	if (logfile == NULL)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	gSvcStatusHandle = RegisterServiceCtrlHandler(
		SVC_NAME,
		SvcCtrlHandler);

	if (!gSvcStatusHandle)
	{
		SvcReportEvent((LPTSTR)TEXT("RegisterServiceCtrlHandler"));
		return;
	}

	// These SERVICE_STATUS members remain as set here

	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwServiceSpecificExitCode = 0;
	gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_PAUSE_CONTINUE;


	WriteToLog((char*)"in SvrMain(), start Service success!");

	// Report initial status to the SCM

	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	// Perform service-specific initialization and work.

	SvcInit(dwArgc, lpszArgv);
}

//
// Purpose: 
//   The service code
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None
//
VOID SvcInit(DWORD dwArgc, LPTSTR *lpszArgv)
{
	// TO_DO: Declare and set any required variables.
	//   Be sure to periodically call ReportSvcStatus() with 
	//   SERVICE_START_PENDING. If initialization fails, call
	//   ReportSvcStatus with SERVICE_STOPPED.

	// Create an event. The control handler function, SvcCtrlHandler,
	// signals this event when it receives the stop control code.

	ghSvcStopEvent = CreateEvent(
		NULL,    // default security attributes
		TRUE,    // manual reset event
		FALSE,   // not signaled
		NULL);   // no name

	if (ghSvcStopEvent == NULL)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	BOOL bSucc = RestartArvFilter();
	if (!bSucc)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	/*HRESULT result = InitCommunicationPort(&port);
	if (result != S_OK)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}*/
	bSucc = ConfigArvFilter();
	if (!bSucc)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	LPVOID buffer = (LPVOID)malloc(sizeof(RepStat)*pathSize);
	DWORD bytesReturn = 0;
	HRESULT result = GetStatistics(buffer, sizeof(RepStat)*pathSize, &bytesReturn);
	if (result != S_OK)
	{
		free(buffer);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	int lenRet = bytesReturn / sizeof(RepStat);
	PRepStat retVal = (PRepStat)buffer;
	for (int i = 0; i < lenRet; i++)
	{
		for (int j = 0; j < pathSize; j++) {
			if (memcmp(pathMap[j].sha256, retVal[i].SHA256, SHA256_BLOCK_SIZE) == 0)
			{
				char logStr[100] = { 0 };
				sprintf_s(logStr, 100, "find path %s: %d/%d", pathMap[j].path, retVal[i].Pass, retVal[i].Block);
				WriteToLog(logStr);
				break;
			}
		}
	}
	// Report running status when initialization is complete.

	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	// TO_DO: Perform work until service stops.
	if (!StartArvCtlServer())
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	while (1)
	{
		// Check whether to stop the service.
		WaitForSingleObject(ghSvcStopEvent, INFINITE);

		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
}

//
// Purpose: 
//   Sets the current service status and reports it to the SCM.
//
// Parameters:
//   dwCurrentState - The current state (see SERVICE_STATUS)
//   dwWin32ExitCode - The system error code
//   dwWaitHint - Estimated time for pending operation, 
//     in milliseconds
// 
// Return value:
//   None
//
// NOTE:
//      SCM中对服务进行的可控操作是由SERVICE_STATUS.dwControlsAccepted决定的，所以当服务程序状态发生变化后需要下
//      需要及时向SCM汇报服务当前可接受的操作
//
//
VOID ReportSvcStatus(DWORD dwCurrentState,
	DWORD dwWin32ExitCode,
	DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// Fill in the SERVICE_STATUS structure.

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
	{
		gSvcStatus.dwControlsAccepted = 0;
	}
	else
	{
		gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	}

	if ((dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED))
	{
		gSvcStatus.dwCheckPoint = 0;
	}
	else
	{
		gSvcStatus.dwCheckPoint = dwCheckPoint++;
	}

	// Report the status of the service to the SCM.
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

//
// Purpose: 
//   Called by SCM whenever a control code is sent to the service
//   using the ControlService function.
//
// Parameters:
//   dwCtrl - control code
// 
// Return value:
//   None
//
VOID WINAPI SvcCtrlHandler(DWORD dwCtrl)
{
	// Handle the requested control code. 

	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		StopArvCtlServer();
		//CloseCommunicationPort(port);
		// Signal the service to stop.

		SetEvent(ghSvcStopEvent);
		ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
		fclose(logfile);
		return;
	case SERVICE_CONTROL_PAUSE:
		break;
	case SERVICE_CONTROL_CONTINUE:
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;

	default:
		break;
	}
}

//
// Purpose: 
//   Logs messages to the event log
//
// Parameters:
//   szFunction - name of function that failed
// 
// Return value:
//   None
//
// Remarks:
//   The service must have an entry in the Application event log.

VOID SvcReportEvent(LPTSTR szFunction)
{
	HANDLE hEventSource;
	LPCTSTR lpszStrings[2];
	TCHAR Buffer[80];

	hEventSource = RegisterEventSource(NULL, SVC_NAME);

	if (NULL != hEventSource)
	{
		StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());

		lpszStrings[0] = SVC_NAME;
		lpszStrings[1] = Buffer;

		ReportEvent(hEventSource,        // event log handle
			EVENTLOG_ERROR_TYPE, // event type
			0,                   // event category
			SVC_ERROR,           // event identifier
			NULL,                // no security identifier
			2,                   // size of lpszStrings array
			0,                   // no binary data
			lpszStrings,         // array of strings
			NULL);               // no binary data

		DeregisterEventSource(hEventSource);
	}
}

/**
*   功能：
*       重启ArvFilter服务
*/
BOOL RestartArvFilter()
{

	SC_HANDLE hSCM = NULL;
	SC_HANDLE hSer = NULL;
	SERVICE_STATUS serStatus = { 0 };
	BOOL bSucc = FALSE;
	hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
	{
		WriteToLog((char*)"OpenSCManager failed!");
		goto clean;
	}
	hSer = OpenService(hSCM, FLT_SVC_NAME, SERVICE_ALL_ACCESS);
	if (hSer == NULL)
	{
		WriteToLog((char*)"OpenService failed!");
		goto clean;
	}
	bSucc = ControlService(hSer, SERVICE_CONTROL_STOP, &serStatus);
	if (bSucc)
	{
		WriteToLog((char*)"Stop ArvFilter success!");
	}
	else {
		WriteToLog((char*)"Stop ArvFilter failed!");
	}
	bSucc = StartService(hSer, NULL, NULL);
	if (bSucc)
	{
		WriteToLog((char*)"Start ArvFilter success!");
	}
	else
	{
		WriteToLog((char*)"Start ArvFilter failed!");
		goto clean;
	}
clean:
	if (hSer != NULL)
	{
		CloseServiceHandle(hSer);
	}
	if (hSCM != NULL)
	{
		CloseServiceHandle(hSCM);
	}
	if (hSer == NULL || hSCM == NULL)
	{
		WriteToLog((char*)"Failed to restart ArvFilter!");
		return FALSE;
	}
	hSCM = NULL;
	hSer = NULL;
	return TRUE;
}

BOOL ConfigArvFilter()
{
	errno_t err;
	FILE *fp;
	int file_size;
	TCHAR drvFilePath[MAX_PATH];
	GetModuleFileName(NULL, drvFilePath, MAX_PATH);
	WCHAR *ch = wcsrchr(drvFilePath, '\\');
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
	err = _wfopen_s(&fp, drvFilePath, L"rb");
	if (err != 0)
	{
		WriteToLog((char*)"failed to open config.json!");
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

	cJSON *jsonHead = cJSON_Parse(tmp);
	if (jsonHead == NULL)
	{
		WriteToLog((char*)"failed to parse config.json!");
		return FALSE;
	}
	ruleSize = cJSON_GetArraySize(jsonHead);
	cJSON *pJsonRule;
	cJSON *pJsonRuleItem;
	cJSON *pJsonPath;
	POpRule pRule;
	for (int i = 0; i < ruleSize; i++)
	{
		pJsonRule = cJSON_GetArrayItem(jsonHead, i);
		pJsonRuleItem = cJSON_GetObjectItem(pJsonRule, "Paths");
		int pathLen = cJSON_GetArraySize(pJsonRuleItem);
		pathSize += pathLen;
	}

	//printf("配置文件中共有%d条规则\n", ruleSize);
	pzpRules = (POpRule*)malloc(ruleSize * sizeof(POpRule));
	pathMap = (PPathShaMap)malloc(pathSize * sizeof(PathShaMap));
	int k = 0;
	for (int i = 0; i < ruleSize; i++)
	{
		pRule = (POpRule)malloc(sizeof(OpRule));
		pJsonRule = cJSON_GetArrayItem(jsonHead, i);
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
			Sha256UnicodeString(pRule->paths[j], pathMap[k].sha256);
			pathMap[k].path = pJsonPath->valuestring;
			k++;
		}
		pzpRules[i] = pRule;
		/*printf("Rule %d:\n", i + 1);
		printf("  id: %d\n", pRule->id);
		printf("  public key: %ls\n", pRule->pubKey);
		for (UINT j = 0; j < pRule->pathsLen; j++)
		{
			printf("  path %d: %ls\n", j + 1, pRule->paths[j]);
		}
		printf("\n");*/
	}
	if (SendSetRulesMessage(pzpRules, ruleSize) != S_OK)
	{
		WriteToLog((char*)"failed to config ArvFilter!");
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

/**
*   功能：
*       将日志写入日志文件
*/
int WriteToLog(char* str)
{
	//获取系统时间
	SYSTEMTIME sysTime;
	GetLocalTime(&sysTime);

	char logStr[200] = { 0 };
	sprintf_s(logStr, 200, "%04d-%02d-%02d %02d:%02d:%02d : %s", sysTime.wYear, sysTime.wMonth, sysTime.wDay,
		sysTime.wHour, sysTime.wMinute, sysTime.wSecond, str);

	/*FILE* logfile;
	fopen_s(&logfile, LOGFILE, "a+");

	if (logfile == NULL)
	{
		return -1;
	}*/

	fprintf(logfile, "%s\n", logStr);
	//fclose(logfile);
	return 0;
}