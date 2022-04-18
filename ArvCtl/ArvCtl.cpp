// ArvCtl.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <locale.h>
#include <strsafe.h>
#include <tchar.h>
#include "io.h"
#include "server.h"
#include "utils.h"
#include"cJSON.h"


#pragma comment(lib, "advapi32.lib")

#define SVC_NAME	TEXT("ArvCtl")
#define SVC_ERROR	((DWORD)0xC0020001L)
#define FLT_SVC_NAME L"ArvFilter"

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;
FILE* logfile;
TCHAR logPath[MAX_PATH];

VOID SvcInstall(void);
VOID WINAPI SvcCtrlHandler(DWORD);
VOID WINAPI SvcMain(DWORD, LPTSTR *);

VOID ReportSvcStatus(DWORD, DWORD, DWORD);
VOID SvcInit(DWORD, LPTSTR *);
VOID SvcReportEvent(LPTSTR);
BOOL StopArvFilter();
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
	GetModuleFileName(NULL, logPath, MAX_PATH);
	WCHAR *ch = wcsrchr(logPath, '\\');
	ch[1] = L'a';
	ch[2] = L'r';
	ch[3] = L'v';
	ch[4] = L'c';
	ch[5] = L't';
	ch[6] = L'l';
	ch[7] = L'.';
	ch[8] = L'l';
	ch[9] = L'o';
	ch[10] = L'g';
	ch[11] = L'\0';

	_wfopen_s(&logfile, logPath, L"a+");
	if (logfile == NULL)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	if (InitConfig())
	{
		WriteToLog((char*)"in InitConfig(), parse config.json success!");
	}
	else
	{
		WriteToLog((char*)"in InitConfig(), parse config.json failed!");
	}
	if (InitDaemonConfig())
	{
		WriteToLog((char*)"in InitDaemonConfig(), parse daemon.json success!");
	}
	else
	{
		WriteToLog((char*)"in InitDaemonConfig(), parse daemon.json failed!");
	}

	gSvcStatusHandle = RegisterServiceCtrlHandler(
		SVC_NAME,
		SvcCtrlHandler);

	if (!gSvcStatusHandle)
	{
		fclose(logfile);
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
		WriteToLog((char*)"in SvcInit(), creat event failed!");
		fclose(logfile);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	if (!RestartArvFilter())
	{
		WriteToLog((char*)"in SvcInit(), restart ArvFilter failed!");
		fclose(logfile);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	if (!ConfigArvFilter())
	{
		WriteToLog((char*)"in SvcInit(), config ArvFilter failed!");
		fclose(logfile);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	// Report running status when initialization is complete.

	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	// Perform work until service stops.
	if (!StartArvCtlServer())
	{
		WriteToLog((char*)"in SvcInit(), start http server failed!");
		fclose(logfile);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	while (1)
	{
		// Check whether to stop the service.
		WaitForSingleObject(ghSvcStopEvent, INFINITE);
		StopArvCtlServer();
		StopArvFilter();
		ClearConfig();
		fclose(logfile);
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
		// Signal the service to stop.

		SetEvent(ghSvcStopEvent);
		ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
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
*       关闭ArvFilter服务
*/
BOOL StopArvFilter()
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
clean:
	if (hSer != NULL)
	{
		CloseServiceHandle(hSer);
	}
	if (hSCM != NULL)
	{
		CloseServiceHandle(hSCM);
	}
	hSer = NULL;
	hSCM = NULL;
	return bSucc;
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