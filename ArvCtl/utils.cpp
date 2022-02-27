#include "utils.h"

HRESULT SendToDriver(LPVOID lpInBuffer, DWORD dwInBufferSize)
{
	//通讯端口
	HANDLE port = INVALID_HANDLE_VALUE;
	HRESULT hResult = S_OK;
	wchar_t OutBuffer[MAX_PATH] = { 0 };
	DWORD bytesReturned = 0;
	//打开端口通讯
	hResult = FilterConnectCommunicationPort(MINI_PORT_NAME, 0, NULL, 0, NULL, &port);
	if (IS_ERROR(hResult)) {
		OutputDebugString(L"FilterConnectCommunicationPort fail!\n");
		return hResult;
	}

	hResult = FilterSendMessage(port, lpInBuffer, dwInBufferSize, OutBuffer, sizeof(OutBuffer), &bytesReturned);
	if (IS_ERROR(hResult)) {
		CloseHandle(port);
		return hResult;
	}
	OutputDebugString(L"从内核发来的信息是:");
	OutputDebugString(OutBuffer);
	OutputDebugString(L"\n");
	CloseHandle(port);
	return hResult;
}

int SendSetProcMessage(ULONG procID, UINT ruleID)
{
	HRESULT hResult = S_OK;
	OpSetProc msg;
	memset(&msg, 0, sizeof(OpSetRules));
	msg.command = SET_PROC;
	msg.procID = procID;
	msg.ruleID = ruleID;
	hResult = SendToDriver(&msg.command, sizeof(msg));
	if (hResult != S_OK)
	{
		return hResult;
	}
	return 0;
}

int SendSetRulesMessage(POpRule *rules, UINT len)
{
	HRESULT hResult = S_OK;
	OpSetRules msg;
	memset(&msg, 0, sizeof(OpSetRules));
	msg.command = SET_RULES;
	msg.rules = rules;
	msg.ruleLen = len;
	hResult = SendToDriver(&msg.command, sizeof(msg));
	if (hResult != S_OK)
	{
		return hResult;
	}
	return 0;
}

BOOL UTF8ToUnicode(const char* UTF8, PZPWSTR strUnicode)
{
	DWORD dwUnicodeLen;    //转换后Unicode的长度
	WCHAR *pwText;      //保存Unicode的指针
	//获得转换后的长度，并分配内存
	dwUnicodeLen = MultiByteToWideChar(CP_UTF8, 0, UTF8, -1, NULL, 0);
	pwText = (WCHAR*)malloc(dwUnicodeLen * sizeof(WCHAR));
	if (!pwText)
	{
		return FALSE;
	}
	//转为Unicode
	MultiByteToWideChar(CP_UTF8, 0, UTF8, -1, pwText, dwUnicodeLen);
	*strUnicode = pwText;
	return TRUE;
}