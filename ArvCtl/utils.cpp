#include "utils.h"
#include "base58.h"
#include "ripemd160.h"

//HRESULT InitCommunicationPort(HANDLE *hPort)
//{
//	HRESULT hResult = FilterConnectCommunicationPort(MINI_PORT_NAME, 0, NULL, 0, NULL, hPort);
//	if (IS_ERROR(hResult)) {
//		OutputDebugString(L"FilterConnectCommunicationPort fail!\n");
//		return hResult;
//	}
//	return S_OK;
//}
//
//VOID CloseCommunicationPort(HANDLE port)
//{
//	if (port)
//	{
//		CloseHandle(port);
//	}
//}

HRESULT GetStatistics(__inout LPVOID OutBuffer, __in DWORD dwInBufferSize, __out DWORD *bytesReturned)
{
	HANDLE port = INVALID_HANDLE_VALUE;
	HRESULT hResult = S_OK;
	hResult = FilterConnectCommunicationPort(MINI_PORT_NAME, 0, NULL, 0, NULL, &port);
	if (IS_ERROR(hResult)) {
		OutputDebugString(L"FilterConnectCommunicationPort fail!\n");
		return hResult;
	}
	OpGetStat command;
	command.command = GET_STAT;
	hResult = FilterSendMessage(port, &command, sizeof(command), OutBuffer, dwInBufferSize, bytesReturned);
	if (IS_ERROR(hResult)) {
		CloseHandle(port);
		return hResult;
	}
	CloseHandle(port);
	return hResult;
}

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

HRESULT SendSetProcMessage(ULONG procID, UINT ruleID)
{
	HRESULT hResult = S_OK;
	OpSetProc msg;
	memset(&msg, 0, sizeof(OpSetRules));
	msg.command = SET_PROC;
	msg.procID = procID;
	msg.ruleID = ruleID;
	hResult = SendToDriver(&msg.command, sizeof(msg));
	return hResult;
}

HRESULT SendSetRulesMessage(POpRule *rules, UINT len)
{
	HRESULT hResult = S_OK;
	OpSetRules msg;
	memset(&msg, 0, sizeof(OpSetRules));
	msg.command = SET_RULES;
	msg.controlProcID = GetCurrentProcessId();
	msg.rules = rules;
	msg.ruleLen = len;
	hResult = SendToDriver(&msg.command, sizeof(msg));
	return hResult;
}

HRESULT SendSetDBConfMessage(UINT ruleID, PWSTR path)
{
	HRESULT hResult = S_OK;
	OpSetDBConf msg;
	memset(&msg, 0, sizeof(OpSetDBConf));
	msg.command = SET_DB_CONF;
	msg.id = ruleID;
	msg.path = path;
	hResult = SendToDriver(&msg.command, sizeof(msg));
	return hResult;
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

VOID FreeRuleList(POpRule *pzpRules, int ruleSize)
{
	for (int i = 0; i < ruleSize; i++)
	{
		POpRule pOpRule = pzpRules[i];
		pOpRule->id = 0;
		free(pOpRule->pubKey);
		for (int j = 0; j < pOpRule->pathsLen; j++)
		{
			free(pOpRule->paths[j]);
			pOpRule->paths[j] = NULL;
		}
		free(pOpRule->paths);
		pOpRule->paths = NULL;
		free(pOpRule->isDB);
		pOpRule->isDB = NULL;
		pOpRule->pathsLen = 0;
		free(pOpRule);
		pOpRule = NULL;
	}
}

//VOID Sha256UnicodeString(PWSTR pWStr, BYTE result[SHA256_BLOCK_SIZE])
//{
//	SHA256_CTX ctx;
//	size_t len = wcslen(pWStr);
//	sha256_init(&ctx);
//	sha256_update(&ctx, (BYTE*)pWStr, len*sizeof(wchar_t));
//	sha256_final(&ctx, result);
//}

void GetDiskInfo(PArvDiskInfo diskInfo)
{
	ULONGLONG totalBytes = 0, totalFreeBytes = 0;
	ULARGE_INTEGER nFreeBytesAvailable, nTotalNumberOfBytes, nTotalNumberOfFreeBytes;
	TCHAR buf[MAX_PATH] = { 0 };
	GetLogicalDriveStrings(MAX_PATH, buf);
	TCHAR*  pDrives = buf;
	while (*pDrives != 0) {
		if (GetDiskFreeSpaceEx(pDrives, &nFreeBytesAvailable, &nTotalNumberOfBytes, &nTotalNumberOfFreeBytes))
		{
			totalBytes += nTotalNumberOfBytes.QuadPart;
			totalFreeBytes += nTotalNumberOfFreeBytes.QuadPart;
		}
		pDrives += wcslen(pDrives) + 1;
	}
	diskInfo->totalBytes = totalBytes;
	diskInfo->totalFreeBytes = totalFreeBytes;
}

bool VerifyPublicKey(PSTR pubkey58)
{
	size_t pubkey58len = strlen(pubkey58);
	if (pubkey58len > 51)
	{
		return false;
	}
	size_t pubkeylen = 40; //公钥长度
	unsigned char pubkeybytes[40];
	bool ret = b58tobin(pubkeybytes, &pubkeylen, pubkey58, pubkey58len);
	if (!ret)
	{
		return false; //base58解码失败
	}
	if (pubkeylen != 37)
	{
		return false; //公钥长度不对
	}
	unsigned char *rawpubkey = (unsigned char*)pubkeybytes + 40 - pubkeylen; //公钥
	uint8_t pubkeyhash[20];
	ripemd160(rawpubkey, 33, pubkeyhash);
	if (memcmp(&rawpubkey[33], pubkeyhash, 4) != 0)
	{
		return false; //checksum不对
	}
	return true;
}
int CopyByBlock(const TCHAR *dest_file_name, const TCHAR *src_file_name)
{
	FILE *fp1, *fp2;
	_wfopen_s(&fp1, dest_file_name, L"wb");
	errno_t err = _wfopen_s(&fp2, src_file_name, L"rb");
	if (fp1 == NULL) {
		perror("fp1:");
		return -1;
	}
	if (fp2 == NULL) {
		perror("fp2:");
		return -1;
	}
	void *buffer = (void *)malloc(1024);
	int cnt = 0;
	while (1) {
		int op = fread(buffer, 1, 1024, fp2);
		if (op <= 0) break;
		fwrite(buffer, 1, 1024, fp1);
		cnt++;
	}
	free(buffer);
	fclose(fp1);
	fclose(fp2);
	return cnt;
}