#include "utils.h"

HRESULT SendToDriver(LPVOID lpInBuffer, DWORD dwInBufferSize)
{
	//ͨѶ�˿�
	HANDLE port = INVALID_HANDLE_VALUE;
	HRESULT hResult = S_OK;
	wchar_t OutBuffer[MAX_PATH] = { 0 };
	DWORD bytesReturned = 0;
	//�򿪶˿�ͨѶ
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
	OutputDebugString(L"���ں˷�������Ϣ��:");
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
	DWORD dwUnicodeLen;    //ת����Unicode�ĳ���
	WCHAR *pwText;      //����Unicode��ָ��
	//���ת����ĳ��ȣ��������ڴ�
	dwUnicodeLen = MultiByteToWideChar(CP_UTF8, 0, UTF8, -1, NULL, 0);
	pwText = (WCHAR*)malloc(dwUnicodeLen * sizeof(WCHAR));
	if (!pwText)
	{
		return FALSE;
	}
	//תΪUnicode
	MultiByteToWideChar(CP_UTF8, 0, UTF8, -1, pwText, dwUnicodeLen);
	*strUnicode = pwText;
	return TRUE;
}