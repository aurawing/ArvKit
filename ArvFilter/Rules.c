#include "Rules.h"

NTSTATUS ReleaseFilterRules(PRuleItems pFilterRules)
{
	if (pFilterRules)
	{
		PRuleItems current, tmp;
		HASH_ITER(hh, pFilterRules, current, tmp) {
			HASH_DEL(pFilterRules, current);
			ExFreePoolWithTag(current, 'frit');
			current = NULL;
		}
	}
}

NTSTATUS InitFilterRulesFromReg(PRuleItems *ppFilterRules)
{
	PRuleItems pFilterRules = *ppFilterRules;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING RegUnicodeString = { 0 };
	HANDLE hRegister = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	PKEY_FULL_INFORMATION pfi = NULL;
	PKEY_VALUE_FULL_INFORMATION pvbi = NULL;
	ULONG ulSize = 0;
	//初始化 UNICODE_STRING 字符串
	RtlInitUnicodeString(&RegUnicodeString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ArvCtl\\SystemFilterRules");
	//初始化 objectAttributes
	InitializeObjectAttributes(&objectAttributes, &RegUnicodeString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	//打开注册表
	status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	//查询 VALUE 的大小
	status = ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
	pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulSize, 'freg');
	if (!pfi)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto CLEAN;
	}
	status = ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);
	if (!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	for (ULONG i = 0; i < pfi->Values; i++)
	{
		//查询单个 VALUE 的大小
		status = ZwEnumerateValueKey(hRegister, i, KeyValueFullInformation, NULL, 0, &ulSize);
		pvbi = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulSize, 'freg');
		if (!pvbi)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto CLEAN;
		}
		//查询单个 VALUE 的详情
		status = ZwEnumerateValueKey(hRegister, i, KeyValueFullInformation, pvbi, ulSize, &ulSize);
		if (!NT_SUCCESS(status))
		{
			goto CLEAN;
		}
		if (pvbi->Type == REG_MULTI_SZ)
		{
			// show value name
			UNICODE_STRING uValueKey = { 0 };
			UNICODE_STRING uValueData = { 0 };
			// value key
			uValueKey.Length = uValueKey.MaximumLength = (USHORT)pvbi->NameLength;
			uValueKey.Buffer = pvbi->Name;
			// value data
			uValueData.Length = uValueData.MaximumLength = (USHORT)pvbi->DataLength;
			uValueData.Buffer = (PWCH)((PCH)pvbi + pvbi->DataOffset);

			CHAR procName[256] = { 0 };
			ULONG procNameLen = 0;
			status = RtlUnicodeToUTF8N(procName, 256, &procNameLen, uValueKey.Buffer, uValueKey.Length);
			if (!NT_SUCCESS(status))
			{
				goto CLEAN;
			}
			UINT ruleSize = 0;
			for (UINT j = 0; j < uValueData.Length / sizeof(WCHAR)-1; j++)
			{
				if (!uValueData.Buffer[j])
				{
					ruleSize++;
					if (!uValueData.Buffer[j + 1])
					{
						break;
					}
				}
			}
			PRuleItems pRule = NULL;
			ARVINITRULES(pRule, procName, ruleSize);
			UINT startIndex = 0;
			UINT endIndex = 0;
			ruleSize = 0;
			for (UINT j = 0; j < uValueData.Length / sizeof(WCHAR) - 1; j++)
			{
				if (!uValueData.Buffer[j])
				{
					endIndex = j;
					WCHAR temp[260] = { 0 };
					UNICODE_STRING dorfStr = { 0 };
					UNICODE_STRING rorwStr = { 0 };
					ULONG dorf = 0;
					ULONG rorw = 0;
					ULONG index = 0;
					UINT startIndex2 = 0;
					for (UINT k = startIndex; k <= endIndex; k++)
					{
						temp[k - startIndex] = uValueData.Buffer[k];
						if (temp[k - startIndex] == L'>' || temp[k - startIndex] ==  0)
						{
							temp[k - startIndex] = 0;
							if (index == 1)
							{
								dorfStr.Buffer = &temp[startIndex2];
								dorfStr.Length = (k - startIndex - startIndex2) * sizeof(WCHAR);
								dorfStr.MaximumLength = (k - startIndex - startIndex2+1) * sizeof(WCHAR);
								RtlUnicodeStringToInteger(&dorfStr, 10, &dorf);
							}
							else if (index == 2)
							{
								rorwStr.Buffer = &temp[startIndex2];
								rorwStr.Length = (k - startIndex - startIndex2) * sizeof(WCHAR);
								rorwStr.MaximumLength = (k - startIndex - startIndex2 + 1) * sizeof(WCHAR);
								RtlUnicodeStringToInteger(&rorwStr, 10, &rorw);
								ARVDEFRULE(pRule->Items[ruleSize], temp, dorf, rorw);
								break;
							}
							index++;
							startIndex2 = k - startIndex + 1;
						}
					}
					ruleSize++;
					if (!uValueData.Buffer[j + 1])
					{
						break;
					}
					startIndex = j + 1;

				}
			}

			HASH_ADD_STR(pFilterRules, ProcessName, pRule);
			//if (FsRtlIsNameInExpression(&uPrefix, &uValueKey, TRUE, NULL))
			//{
			//	PEnvItem item = (PEnvItem)ExAllocatePoolWithTag(NonPagedPool, sizeof(EnvItem), 'freg');
			//	if (!item)
			//	{
			//		status = STATUS_INSUFFICIENT_RESOURCES;
			//		goto CLEAN;
			//	}
			//	RtlZeroMemory(item, sizeof(EnvItem));
			//	//wcsncpy_s(item->EnvName, uValueKey.Length/sizeof(WCHAR) + 1, uValueKey.Buffer, 260);
			//	//wcsncpy_s(item->EnvVal, uValueData.Length / sizeof(WCHAR) + 1, uValueData.Buffer, 320);
			//	RtlCopyMemory(item->EnvName, uValueKey.Buffer, uValueKey.Length);
			//	RtlCopyMemory(item->EnvVal, uValueData.Buffer, uValueData.Length);
			//	//HASH_ADD_STR(pEnvsMap, EnvName, item);
			//	HASH_ADD(hh, pEnvsMap, EnvName, 260 * sizeof(WCHAR), item);
			//}
		}
		ExFreePool(pvbi);
		pvbi = NULL;
	}
CLEAN:
	if (pvbi)
	{
		ExFreePool(pvbi);
	}
	if (pfi)
	{
		ExFreePool(pfi);
	}
	if (hRegister)
	{
		ZwClose(hRegister);
	}
	if (NT_SUCCESS(status))
	{
		*ppFilterRules = pFilterRules;
	}
	return status;
}

NTSTATUS InitFilterRules(PRuleItems *ppFilterRules)
{
	PRuleItems pFilterRules = *ppFilterRules;

	//Rules for System
	UINT sysRuleLen = 1;
	PRuleItems pSystemRule = NULL;
	ARVINITRULES(pSystemRule, "System", sysRuleLen);
	ARVDEFRULE(pSystemRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSystemRule);

	//Rules for smss.exe
	UINT smssRuleLen = 1;
	PRuleItems pSmssRule = NULL;
	ARVINITRULES(pSmssRule, "smss.exe", smssRuleLen);
	ARVDEFRULE(pSmssRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSmssRule);

	//Rules for csrss.exe
	UINT csrssRuleLen = 2;
	PRuleItems pCsrssRule = NULL;
	ARVINITRULES(pCsrssRule, "csrss.exe", csrssRuleLen);
	ARVDEFRULE(pCsrssRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pCsrssRule->Items[1], L"|ArvWinRoot|\\appcompat\\Programs\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pCsrssRule);

	//Rules for wininit.exe
	UINT wininitRuleLen = 1;
	PRuleItems pWininitRule = NULL;
	ARVINITRULES(pWininitRule, "wininit.exe", wininitRuleLen);
	ARVDEFRULE(pWininitRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWininitRule);

	//Rules for services.exe
	UINT servicesRuleLen = 1;
	PRuleItems pServicesRule = NULL;
	ARVINITRULES(pServicesRule, "services.exe", servicesRuleLen);
	ARVDEFRULE(pServicesRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pServicesRule);

	//Rules for svchost.exe
	UINT svchostRuleLen = 67;
	PRuleItems pSvchostRule = NULL;
	ARVINITRULES(pSvchostRule, "svchost.exe", svchostRuleLen);
	ARVDEFRULE(pSvchostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSvchostRule->Items[1], L"|ArvProgramData|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[2], L"|ArvProgramData|\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[3], L"|ArvProgramData|\\Microsoft\\Crypto", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[4], L"|ArvProgramData|\\Microsoft\\Crypto\\RSA", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[5], L"|ArvProgramData|\\Microsoft\\Crypto\\RSA\\MachineKeys", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[6], L"|ArvProgramData|\\Microsoft\\Diagnosis\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[7], L"|ArvProgramData|\\Microsoft\\Diagnosis\\DownloadedSettings\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[8], L"|ArvProgramData|\\Microsoft\\Network\\Downloader\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[9], L"|ArvProgramData|\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[10], L"|ArvProgramData|\\Microsoft\\Windows\\AppRepository\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[11], L"|ArvProgramData|\\Microsoft\\Windows\\DeviceMetadataCache\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[12], L"|ArvProgramData|\\Microsoft\\Windows\\LfSvc", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[13], L"|ArvProgramData|\\Microsoft\\Windows\\LfSvc\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[14], L"|ArvProgramData|\\Microsoft\\Windows\\WER\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[15], L"|ArvProgramData|\\USOPrivate\\UpdateStore\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[16], L"|ArvProgramData|\\USOShared\\Logs\\System\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[17], L"|ArvProfilesDirectory|\\*\\AppData\\LocalLow", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[18], L"|ArvProfilesDirectory|\\*\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[19], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\ConnectedDevicesPlatform\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[20], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[21], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Microsoft\\Windows\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[22], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Packages\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[23], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Temp", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[24], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Temp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[25], L"|ArvProfilesDirectory|\\*\\ntuser.*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[26], L"|ArvWinRoot|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[27], L"|ArvWinRoot|\\appcompat\\Programs\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[28], L"|ArvWinRoot|\\AppReadiness", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[29], L"|ArvWinRoot|\\AppReadiness\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[30], L"|ArvWinRoot|\\INF\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[31], L"|ArvWinRoot|\\Logs\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[32], L"|ArvWinRoot|\\Panther\\UnattendGC\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[33], L"|ArvWinRoot|\\Program Files\\WindowsApps\\Deleted", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[34], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[35], L"|ArvWinRoot|\\ServiceProfiles\\NetworkService\\AppData\\Local\\AutoTrace", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[36], L"|ArvWinRoot|\\ServiceProfiles\\NetworkService\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[37], L"|ArvWinRoot|\\System32", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[38], L"|ArvWinRoot|\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[39], L"|ArvWinRoot|\\System32\\Tasks\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[40], L"|ArvWinRoot|\\SoftwareDistribution", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[41], L"|ArvWinRoot|\\SoftwareDistribution\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[42], L"|ArvWinRoot|\\SoftwareDistribution\\Download", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[43], L"|ArvWinRoot|\\SoftwareDistribution\\Download\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[44], L"|ArvWinRoot|\\System32\\config", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[45], L"|ArvWinRoot|\\System32\\config\\systemprofile", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[46], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[47], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[48], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\DataSharing", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[49], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\DataSharing\\Storage", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[50], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\ConnectedDevicesPlatform\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[51], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[52], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[53], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[54], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Notifications", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[55], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Notifications\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[56], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[57], L"|ArvWinRoot|\\System32\\Tasks\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[58], L"|ArvWinRoot|\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[59], L"|ArvWinRoot|\\System32\\Tasks\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[60], L"|ArvWinRoot|\\System32\\LogFiles\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[61], L"|ArvWinRoot|\\System32\\WMI\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[62], L"|ArvWinRoot|\\System32\\wbem\\repository", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[63], L"|ArvWinRoot|\\System32\\wbem\\repository\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[64], L"|ArvWinRoot|\\SystemApps\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[65], L"|ArvWinRoot|\\Temp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSvchostRule->Items[66], L"|ArvWinRoot|\\WindowsUpdate.log", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSvchostRule);

	//Rules for WmiPrvSE.exe
	UINT wmiprvseRuleLen = 3;
	PRuleItems pWmiPrvSeRule = NULL;
	ARVINITRULES(pWmiPrvSeRule, "WmiPrvSE.exe", wmiprvseRuleLen);
	ARVDEFRULE(pWmiPrvSeRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWmiPrvSeRule->Items[1], L"|ArvWinRoot|\\Logs\\DISM\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pWmiPrvSeRule->Items[2], L"|ArvWinRoot|\\System32\\wbem\\Logs\\wmiprov.log", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWmiPrvSeRule);

	//Rules for RuntimeBroker.exe
	UINT runtimebrokerRuleLen = 7;
	PRuleItems pRuntimebrokerRule = NULL;
	ARVINITRULES(pRuntimebrokerRule, "RuntimeBroker.", runtimebrokerRuleLen);
	ARVDEFRULE(pRuntimebrokerRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pRuntimebrokerRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRuntimebrokerRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRuntimebrokerRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRuntimebrokerRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRuntimebrokerRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Explorer", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRuntimebrokerRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pRuntimebrokerRule);

	//Rules for ChsIME.exe
	UINT chsimeRuleLen = 12;
	PRuleItems pChsimeRule = NULL;
	ARVINITRULES(pChsimeRule, "ChsIME.exe", chsimeRuleLen);
	ARVDEFRULE(pChsimeRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pChsimeRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\History", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\INetCache", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\INetCookies", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[7], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[8], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\microsoft\\InputMethod\\Chs", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[9], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\microsoft\\InputMethod\\Chs\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[10], L"|ArvWinRoot|\\InputMethod\\Chs", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pChsimeRule->Items[11], L"|ArvWinRoot|\\System32\\ChsPinyinUDL.dat", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pChsimeRule);

	//Rules for ShellExperienceHost.exe
	UINT shellExperienceHostRuleLen = 2;
	PRuleItems pShellExperienceHostRule = NULL;
	ARVINITRULES(pShellExperienceHostRule, "ShellExperienc", shellExperienceHostRuleLen);
	ARVDEFRULE(pShellExperienceHostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pShellExperienceHostRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Packages\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pShellExperienceHostRule);

	//Rules for SearchUI.exe
	UINT searchUIRuleLen = 7;
	PRuleItems pSearchUIRule = NULL;
	ARVINITRULES(pSearchUIRule, "SearchUI.exe", searchUIRuleLen);
	ARVDEFRULE(pSearchUIRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSearchUIRule->Items[1], L"|ArvProgramData|\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchUIRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchUIRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchUIRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchUIRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\INetCache", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchUIRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Packages\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSearchUIRule);

	//Rules for WUDFHost.exe
	UINT wudfHostRuleLen = 1;
	PRuleItems pWUDFHostRule = NULL;
	ARVINITRULES(pWUDFHostRule, "WUDFHost.exe", wudfHostRuleLen);
	ARVDEFRULE(pWUDFHostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWUDFHostRule);

	//Rules for sihost.exe
	UINT sihostRuleLen = 1;
	PRuleItems pSihostRule = NULL;
	ARVINITRULES(pSihostRule, "sihost.exe", sihostRuleLen);
	ARVDEFRULE(pSihostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSihostRule);

	//Rules for taskhostw.exe
	UINT taskhostwRuleLen = 7;
	PRuleItems pTaskhostwRule = NULL;
	ARVINITRULES(pTaskhostwRule, "taskhostw.exe", taskhostwRuleLen);
	ARVDEFRULE(pTaskhostwRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pTaskhostwRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTaskhostwRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTaskhostwRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\History\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTaskhostwRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\INetCache", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTaskhostwRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\WebCacheLock.dat", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pTaskhostwRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Packages\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pTaskhostwRule);

	//Rules for spoolsv.exe
	UINT spoolsvRuleLen = 8;
	PRuleItems pSpoolsvRule = NULL;
	ARVINITRULES(pSpoolsvRule, "spoolsv.exe", spoolsvRuleLen);
	ARVDEFRULE(pSpoolsvRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSpoolsvRule->Items[1], L"|ArvWinRoot|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSpoolsvRule->Items[2], L"|ArvWinRoot|\\system32", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSpoolsvRule->Items[3], L"|ArvWinRoot|\\system32\\spool", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSpoolsvRule->Items[4], L"|ArvWinRoot|\\system32\\spool\\DRIVERS", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSpoolsvRule->Items[5], L"|ArvWinRoot|\\system32\\spool\\DRIVERS\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSpoolsvRule->Items[6], L"|ArvWinRoot|\\system32\\spool\\PRINTERS", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSpoolsvRule->Items[7], L"|ArvWinRoot|\\system32\\spool\\SERVERS", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSpoolsvRule);

	//Rules for MsMpEng.exe
	UINT msmpengRuleLen = 11;
	PRuleItems pMsMpEngRule = NULL;
	ARVINITRULES(pMsMpEngRule, "MsMpEng.exe", msmpengRuleLen);
	ARVDEFRULE(pMsMpEngRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMsMpEngRule->Items[1], L"|ArvProgramData|\\Microsoft\\Windows Defender\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[2], L"|ArvWinRoot|\\system32\\catroot", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[3], L"|ArvWinRoot|\\system32\\catroot2", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[4], L"|ArvWinRoot|\\system32\\catroot\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[5], L"|ArvWinRoot|\\system32\\catroot2\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[6], L"|ArvWinRoot|\\system32\\drivers\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[7], L"|ArvWinRoot|\\system32\\MpEngineStore", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[8], L"|ArvWinRoot|\\system32\\MpEngineStore\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[9], L"|ArvWinRoot|\\Logs\\DISM\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMsMpEngRule->Items[10], L"|ArvWinRoot|\\Temp\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMsMpEngRule);

	//Rules for wlms.exe
	UINT wlmsRuleLen = 2;
	PRuleItems pWlmsRule = NULL;
	ARVINITRULES(pWlmsRule, "wlms.exe", wlmsRuleLen);
	ARVDEFRULE(pWlmsRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWlmsRule->Items[1], L"|ArvWinRoot|\\Debug\\wlms.log", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWlmsRule);

	//Rules for dllhost.exe
	UINT dllhostRuleLen = 6;
	PRuleItems pDllhostRule = NULL;
	ARVINITRULES(pDllhostRule, "dllhost.exe", dllhostRuleLen);
	ARVDEFRULE(pDllhostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pDllhostRule->Items[1], L"|ArvProgramData|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pDllhostRule->Items[2], L"|ArvProgramData|\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pDllhostRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pDllhostRule->Items[4], L"|ArvWinRoot|\\Registration\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pDllhostRule->Items[5], L"|ArvWinRoot|\\Temp\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pDllhostRule);

	//Rules for NisSrv.exe
	UINT nissrvRuleLen = 12;
	PRuleItems pNissrvRule = NULL;
	ARVINITRULES(pNissrvRule, "NisSrv.exe", nissrvRuleLen);
	ARVDEFRULE(pNissrvRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pNissrvRule->Items[1], L"|ArvWinRoot|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[2], L"|ArvWinRoot|\\ServiceProfiles", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[3], L"|ArvWinRoot|\\ServiceProfiles\\LocalService", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[4], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[5], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[6], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[7], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[8], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows\\Safety", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[9], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows\\Safety\\network", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[10], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows\\Safety\\network\\local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pNissrvRule->Items[11], L"|ArvWinRoot|\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows\\Safety\\network\\local\\sinkholeCache", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pNissrvRule);

	//Rules for SearchIndexer.exe
	UINT searchindexerRuleLen = 20;
	PRuleItems pSearchindexerRule = NULL;
	ARVINITRULES(pSearchindexerRule, "SearchIndexer.", searchindexerRuleLen);
	ARVDEFRULE(pSearchindexerRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSearchindexerRule->Items[1], L"|ArvProgramData|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[2], L"|ArvProgramData|\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[3], L"|ArvProgramData|\\Microsoft\\Search", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[4], L"|ArvProgramData|\\Microsoft\\Search\\Data", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[5], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[6], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[7], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[8], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[9], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[10], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[11], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\PropMap", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[12], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\PropMap\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[13], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\SecStore", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[14], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\SecStore\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[15], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Temp", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[16], L"|ArvProgramData|\\Microsoft\\Search\\Data\\Temp\\usgthrsvc", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[17], L"?:\\System Volume Information", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[18], L"|ArvWinRoot|\\system32\\config\\systemprofile", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSearchindexerRule->Items[19], L"|ArvWinRoot|\\system32\\config\\systemprofile\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSearchindexerRule);

	//Rules for fontdrvhost.exe
	UINT fontdrvhostRuleLen = 1;
	PRuleItems pFontdrvhostRule = NULL;
	ARVINITRULES(pFontdrvhostRule, "fontdrvhost.ex", fontdrvhostRuleLen);
	ARVDEFRULE(pFontdrvhostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pFontdrvhostRule);

	//Rules for lsass.exe
	UINT lsassRuleLen = 14;
	PRuleItems pLsassRule = NULL;
	ARVINITRULES(pLsassRule, "lsass.exe", lsassRuleLen);
	ARVDEFRULE(pLsassRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	//ARVDEFRULE(pLsassRule->Items[1], L"|ArvProfilesDirectory|\\", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[1], L"|ArvProgramData|\\Microsoft\\Vault", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[2], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[3], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Microsoft\\Credentials", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[4], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Microsoft\\Vault", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[5], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Microsoft\\Vault\\UserProfileRoaming", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[6], L"|ArvProfilesDirectory|\\*\\AppData\\Local\\Microsoft\\Vault\\UserProfileRoaming\\Latest.dat", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[7], L"|ArvProfilesDirectory|\\*\\AppData\\Roaming\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[8], L"|ArvProfilesDirectory|\\*\\AppData\\Roaming\\Microsoft\\Credentials", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[9], L"|ArvProfilesDirectory|\\*\\AppData\\Roaming\\Microsoft\\Protect\\CREDHIST", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[10], L"|ArvProfilesDirectory|\\*\\AppData\\Roaming\\Microsoft\\Vault", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[11], L"|ArvWinRoot|\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[12], L"|ArvWinRoot|\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLsassRule->Items[13], L"|ArvWinRoot|\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pLsassRule);

	//Rules for winlogon.exe
	UINT winlogonRuleLen = 1;
	PRuleItems pWinlogonRule = NULL;
	ARVINITRULES(pWinlogonRule, "winlogon.exe", winlogonRuleLen);
	ARVDEFRULE(pWinlogonRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWinlogonRule);

	//Rules for dwm.exe
	UINT dwmRuleLen = 1;
	PRuleItems pDwmRule = NULL;
	ARVINITRULES(pDwmRule, "dwm.exe", dwmRuleLen);
	ARVDEFRULE(pDwmRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pDwmRule);

	//Rules for explorer.exe
	UINT expRuleLen = 43;
	PRuleItems pExplorerRule = NULL;
	ARVINITRULES(pExplorerRule, "explorer.exe", expRuleLen);
	//Windows Server 2016
	ARVDEFRULE(pExplorerRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pExplorerRule->Items[1], L"|ArvProgramData|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[2], L"|ArvProgramData|\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[3], L"|ArvProgramData|\\Microsoft\\Windows\\Start Menu Places", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[4], L"|ArvProgramData|\\Microsoft\\Windows\\Start Menu", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[5], L"|ArvProgramData|\\Microsoft\\Windows\\Start Menu\\Programs", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[6], L"|ArvProfilesDirectory|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[7], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[8], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[9], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[10], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\ConnectedDevicesPlatform\\CDPGlobalSettings.cdp", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[11], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\IconCache.db", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[12], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[13], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\PenWorkspace\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[14], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[15], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[16], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Packages", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[17], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Packages\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[18], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Temp", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[19], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Temp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[20], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[21], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[22], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[23], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Vault", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[24], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Recent", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[25], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[26], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[27], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[28], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[29], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[30], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Themes", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[31], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[32], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\CachedFiles", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[33], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\CachedFiles\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[34], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\TranscodedWallpaper", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[35], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\Desktop", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[36], L"|ArvPublic|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[37], L"|ArvPublic|\\Desktop", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[38], L"|ArvWinRoot|\\rescache\\_merged", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[39], L"|ArvWinRoot|\\rescache\\_merged\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[40], L"|ArvWinRoot|\\Resources", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[41], L"|ArvWinRoot|\\system32\\catroot", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pExplorerRule->Items[42], L"|ArvWinRoot|\\system32\\catroot2", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pExplorerRule);

	//Rules for cmd.exe
	UINT cmdRuleLen = 3;
	PRuleItems pCmdRule = NULL;
	ARVINITRULES(pCmdRule, "cmd.exe", cmdRuleLen);
	ARVDEFRULE(pCmdRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pCmdRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pCmdRule->Items[2], L"|ArvWinRoot|\\Temp\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pCmdRule);

	//Rules for sc.exe
	UINT scRuleLen = 1;
	PRuleItems pScRule = NULL;
	ARVINITRULES(pScRule, "sc.exe", scRuleLen);
	ARVDEFRULE(pScRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pScRule);

	//Rules for LogonUI.exe
	UINT logonuiRuleLen = 4;
	PRuleItems pLogonUIRule = NULL;
	ARVINITRULES(pLogonUIRule, "LogonUI.exe", logonuiRuleLen);
	ARVDEFRULE(pLogonUIRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pLogonUIRule->Items[1], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLogonUIRule->Items[2], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pLogonUIRule->Items[3], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pLogonUIRule);

	//Rules for WMIADAP.exe
	UINT wmiadapRuleLen = 3;
	PRuleItems pWmiadapRule = NULL;
	ARVINITRULES(pWmiadapRule, "WMIADAP.exe", wmiadapRuleLen);
	ARVDEFRULE(pWmiadapRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWmiadapRule->Items[1], L"|ArvWinRoot|\\System32\\wbem\\Performance", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWmiadapRule->Items[2], L"|ArvWinRoot|\\System32\\wbem\\Performance\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWmiadapRule);

	//Rules for WdkCommSvc.exe
	UINT wdkcommRuleLen = 1;
	PRuleItems pWdkCommRule = NULL;
	ARVINITRULES(pWdkCommRule, "WdkCommSvc.exe", wdkcommRuleLen);
	ARVDEFRULE(pWdkCommRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWdkCommRule);

	//Rules for conhost.exe
	UINT conhostRuleLen = 1;
	PRuleItems pConHostRule = NULL;
	ARVINITRULES(pConHostRule, "conhost.exe", conhostRuleLen);
	ARVDEFRULE(pConHostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pConHostRule);

	//Rules for msdtc.exe
	UINT msdtcRuleLen = 3;
	PRuleItems pMsdtcRule = NULL;
	ARVINITRULES(pMsdtcRule, "msdtc.exe", msdtcRuleLen);
	ARVDEFRULE(pMsdtcRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMsdtcRule->Items[1], L"|ArvWinRoot|\\DtcInstall.log", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMsdtcRule->Items[2], L"|ArvWinRoot|\\System32\\MsDtc\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMsdtcRule);

	//Rules for netsh.exe
	UINT netshRuleLen = 2;
	PRuleItems pNetshRule = NULL;
	ARVINITRULES(pNetshRule, "netsh.exe", netshRuleLen);
	ARVDEFRULE(pNetshRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pNetshRule->Items[1], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\PeerDistRepub", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pNetshRule);

	//Rules for sppsvc.exe
	UINT sppsvcRuleLen = 2;
	PRuleItems pSppsvcRule = NULL;
	ARVINITRULES(pSppsvcRule, "sppsvc.exe", sppsvcRuleLen);
	ARVDEFRULE(pSppsvcRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSppsvcRule->Items[1], L"|ArvWinRoot|\\System32\\spp\\store\\2.0\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSppsvcRule);

	//Rules for WerFault.exe
	UINT werFaultRuleLen = 2;
	PRuleItems pWerFaultRule = NULL;
	ARVINITRULES(pWerFaultRule, "WerFault.exe", werFaultRuleLen);
	ARVDEFRULE(pWerFaultRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWerFaultRule->Items[1], L"|ArvProgramData|\\Microsoft\\Windows\\WER\\Temp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWerFaultRule);

	//Rules for wermgr.exe
	UINT wermgrRuleLen = 4;
	PRuleItems pWermgrRule = NULL;
	ARVINITRULES(pWermgrRule, "wermgr.exe", wermgrRuleLen);
	ARVDEFRULE(pWermgrRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWermgrRule->Items[1], L"|ArvProgramData|\\Microsoft\\Windows\\WER\\ReportArchive\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWermgrRule->Items[2], L"|ArvProgramData|\\Microsoft\\Windows\\WER\\ReportQueue\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWermgrRule->Items[3], L"|ArvProgramData|\\Microsoft\\Windows\\WER\\Temp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWermgrRule);

	//Rules for wevtutil.exe
	UINT wevtutilRuleLen = 1;
	PRuleItems pWevtutilRule = NULL;
	ARVINITRULES(pWevtutilRule, "wevtutil.exe", wevtutilRuleLen);
	ARVDEFRULE(pWevtutilRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWevtutilRule);

	//Rules for CompatTelRunner.exe
	UINT compatTelRunnerRuleLen = 8;
	PRuleItems pCompatTelRunnerRule = NULL;
	ARVINITRULES(pCompatTelRunnerRule, "CompatTelRunne", compatTelRunnerRuleLen);
	ARVDEFRULE(pCompatTelRunnerRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pCompatTelRunnerRule->Items[1], L"|ArvWinRoot|\\appcompat\\appraiser\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pCompatTelRunnerRule->Items[2], L"|ArvWinRoot|\\appcompat\\Programs\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pCompatTelRunnerRule->Items[3], L"|ArvWinRoot|\\appcompat\\UA\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pCompatTelRunnerRule->Items[4], L"|ArvWinRoot|\\System32\\CatRoot", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pCompatTelRunnerRule->Items[5], L"|ArvWinRoot|\\System32\\catroot2", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pCompatTelRunnerRule->Items[6], L"|ArvWinRoot|\\System32\\catroot2\\dberr.txt", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pCompatTelRunnerRule->Items[7], L"|ArvWinRoot|\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pCompatTelRunnerRule);

	//Rules for ServerManagerLancher.exe
	UINT serverManagerLRuleLen = 2;
	PRuleItems pServerManagerLRule = NULL;
	ARVINITRULES(pServerManagerLRule, "ServerManagerL", serverManagerLRuleLen);
	ARVDEFRULE(pServerManagerLRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pServerManagerLRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pServerManagerLRule);

	//Rules for ServerManager.exe
	UINT serverManagerRuleLen = 7;
	PRuleItems pServerManagerRule = NULL;
	ARVINITRULES(pServerManagerRule, "ServerManager.", serverManagerRuleLen);
	ARVDEFRULE(pServerManagerRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pServerManagerRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pServerManagerRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft_Corporation\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pServerManagerRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pServerManagerRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Temp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pServerManagerRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pServerManagerRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\ServerManager\\ServerList.xml", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pServerManagerRule);

	//Rules for WMIC.exe
	UINT wmicRuleLen = 1;
	PRuleItems pWmicRule = NULL;
	ARVINITRULES(pWmicRule, "WMIC.exe", wmicRuleLen);
	ARVDEFRULE(pWmicRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWmicRule);

	//Rules for reg.exe
	UINT regRuleLen = 1;
	PRuleItems pRegRule = NULL;
	ARVINITRULES(pRegRule, "reg.exe", regRuleLen);
	ARVDEFRULE(pRegRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pRegRule);

	//Rules for userinit.exe
	UINT userinitRuleLen = 1;
	PRuleItems pUserinitRule = NULL;
	ARVINITRULES(pUserinitRule, "userinit.exe", userinitRuleLen);
	ARVDEFRULE(pUserinitRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pUserinitRule);

	//Rules for mobsync.exe
	UINT mobsyncRuleLen = 1;
	PRuleItems pMobsyncRule = NULL;
	ARVINITRULES(pMobsyncRule, "mobsync.exe", mobsyncRuleLen);
	ARVDEFRULE(pMobsyncRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMobsyncRule);

	//Rules for SearchProtocolHost.exe
	UINT searchProtocolRuleLen = 2;
	PRuleItems pSearchProtocolRule = NULL;
	ARVINITRULES(pSearchProtocolRule, "SearchProtocol", searchProtocolRuleLen);
	ARVDEFRULE(pSearchProtocolRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSearchProtocolRule->Items[1], L"|ArvWinRoot|\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSearchProtocolRule);

	//Rules for VSSVC.exe
	UINT vssvcRuleLen = 1;
	PRuleItems pVSSVCRule = NULL;
	ARVINITRULES(pVSSVCRule, "VSSVC.exe", vssvcRuleLen);
	ARVDEFRULE(pVSSVCRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pVSSVCRule);

	//Rules for WmiApSrv.exe
	UINT wmiApSrvRuleLen = 6;
	PRuleItems pWmiApSrvRule = NULL;
	ARVINITRULES(pWmiApSrvRule, "WmiApSrv.exe", wmiApSrvRuleLen);
	ARVDEFRULE(pWmiApSrvRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWmiApSrvRule->Items[1], L"|ArvWinRoot|\\INF\\WmiApRpl", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWmiApSrvRule->Items[2], L"|ArvWinRoot|\\INF\\WmiApRpl\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWmiApSrvRule->Items[3], L"|ArvWinRoot|\\System32\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWmiApSrvRule->Items[4], L"|ArvWinRoot|\\System32\\wbem\\Performance", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWmiApSrvRule->Items[5], L"|ArvWinRoot|\\System32\\wbem\\Performance\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWmiApSrvRule);

	//Rules for ApplicationFrameHost.exe
	UINT appFrmHostRuleLen = 1;
	PRuleItems pAppFrmHostRule = NULL;
	ARVINITRULES(pAppFrmHostRule, "ApplicationFra", appFrmHostRuleLen);
	ARVDEFRULE(pAppFrmHostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pAppFrmHostRule);

	//Rules for SearchFilterHost.exe
	UINT searchFltHostRuleLen = 1;
	PRuleItems pSearchFltHostRule = NULL;
	ARVINITRULES(pSearchFltHostRule, "SearchFilterHo", searchFltHostRuleLen);
	ARVDEFRULE(pSearchFltHostRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSearchFltHostRule);

	//Rules for SystemSettings.exe
	UINT systemSettingsRuleLen = 10;
	PRuleItems pSystemSettingsRule = NULL;
	ARVINITRULES(pSystemSettingsRule, "SystemSettings", systemSettingsRuleLen);
	ARVDEFRULE(pSystemSettingsRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSystemSettingsRule->Items[1], L"|ArvProgramData|\\USOShared\\Logs\\User\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[7], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[8], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSystemSettingsRule->Items[9], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSystemSettingsRule);

	//Rules for rundll32.exe
	UINT rundll32RuleLen = 7;
	PRuleItems pRundll32Rule = NULL;
	ARVINITRULES(pRundll32Rule, "rundll32.exe", rundll32RuleLen);
	ARVDEFRULE(pRundll32Rule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pRundll32Rule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRundll32Rule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRundll32Rule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Themes", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pRundll32Rule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Temp\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pRundll32Rule->Items[5], L"|ArvWinRoot|\\*.tmp", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pRundll32Rule->Items[6], L"|ArvWinRoot|\\Resources", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pRundll32Rule);

	//Rules for VGAuthService.exe
	UINT vgAuthRuleLen = 2;
	PRuleItems pVgAuthRule = NULL;
	ARVINITRULES(pVgAuthRule, "VGAuthService.", vgAuthRuleLen);
	ARVDEFRULE(pVgAuthRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pVgAuthRule->Items[1], L"|ArvProgramData|", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pVgAuthRule);

	//Rules for UsoClient.exe
	UINT usoClientRuleLen = 1;
	PRuleItems pUsoClientRule = NULL;
	ARVINITRULES(pUsoClientRule, "UsoClient.exe", usoClientRuleLen);
	ARVDEFRULE(pUsoClientRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pUsoClientRule);

	//Rules for fltMC.exe
	UINT fltmcRuleLen = 1;
	PRuleItems pFltmcRule = NULL;
	ARVINITRULES(pFltmcRule, "fltMC.exe", fltmcRuleLen);
	ARVDEFRULE(pFltmcRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pFltmcRule);

	//Rules for MpCmdRun.exe
	UINT mpCmdRunRuleLen = 3;
	PRuleItems pMpCmdRunRule = NULL;
	ARVINITRULES(pMpCmdRunRule, "MpCmdRun.exe", mpCmdRunRuleLen);
	ARVDEFRULE(pMpCmdRunRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMpCmdRunRule->Items[1], L"|ArvWinRoot|\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMpCmdRunRule->Items[2], L"|ArvWinRoot|\\Temp\\MpCmdRun.log", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMpCmdRunRule);

	//Rules for OpenWith.exe
	UINT openWithRuleLen = 3;
	PRuleItems pOpenWithRule = NULL;
	ARVINITRULES(pOpenWithRule, "OpenWith.exe", openWithRuleLen);
	ARVDEFRULE(pOpenWithRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pOpenWithRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pOpenWithRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pOpenWithRule);

	//Rules for control.exe
	UINT controlRuleLen = 2;
	PRuleItems pControlRule = NULL;
	ARVINITRULES(pControlRule, "control.exe", controlRuleLen);
	ARVDEFRULE(pControlRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pControlRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pControlRule);

	//Rules for msconfig.exe
	UINT msconfigRuleLen = 1;
	PRuleItems pMsconfigRule = NULL;
	ARVINITRULES(pMsconfigRule, "msconfig.exe", msconfigRuleLen);
	ARVDEFRULE(pMsconfigRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMsconfigRule);

	//Rules for MusNotification.exe
	UINT musNotifyRuleLen = 3;
	PRuleItems pMusNotifyRule = NULL;
	ARVINITRULES(pMusNotifyRule, "MusNotificatio", musNotifyRuleLen);
	ARVDEFRULE(pMusNotifyRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMusNotifyRule->Items[1], L"|ArvProgramData|\\USOShared\\Logs\\System\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMusNotifyRule->Items[2], L"|ArvProgramData|\\USOShared\\Logs\\User\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMusNotifyRule);

	//Rules for TiWorker.exe
	UINT tiWorkerRuleLen = 10;
	PRuleItems pTiWorkerRule = NULL;
	ARVINITRULES(pTiWorkerRule, "TiWorker.exe", tiWorkerRuleLen);
	ARVDEFRULE(pTiWorkerRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pTiWorkerRule->Items[1], L"|ArvWinRoot|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[2], L"|ArvWinRoot|\\CbsTemp", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[3], L"|ArvWinRoot|\\CbsTemp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[4], L"|ArvWinRoot|\\Logs", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[5], L"|ArvWinRoot|\\Logs\\CBS", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[6], L"|ArvWinRoot|\\Logs\\CBS\\CBS.log", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[7], L"|ArvWinRoot|\\SoftwareDistribution\\Download\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[8], L"|ArvWinRoot|\\System32", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTiWorkerRule->Items[9], L"|ArvWinRoot|\\servicing\\Sessions", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pTiWorkerRule);

	//Rules for TrustedInstall.exe
	UINT trustedInstallRuleLen = 6;
	PRuleItems pTrustedInstallRule = NULL;
	ARVINITRULES(pTrustedInstallRule, "TrustedInstall", trustedInstallRuleLen);
	ARVDEFRULE(pTrustedInstallRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pTrustedInstallRule->Items[1], L"|ArvWinRoot|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTrustedInstallRule->Items[2], L"|ArvWinRoot|\\Logs", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTrustedInstallRule->Items[3], L"|ArvWinRoot|\\Logs\\CBS", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTrustedInstallRule->Items[4], L"|ArvWinRoot|\\Logs\\CBS\\CBS.log", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pTrustedInstallRule->Items[5], L"|ArvWinRoot|\\System32", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pTrustedInstallRule);

	//Rules for InstallAgent.exe
	UINT installAgentRuleLen = 2;
	PRuleItems pInstallAgentRule = NULL;
	ARVINITRULES(pInstallAgentRule, "InstallAgent.e", installAgentRuleLen);
	ARVDEFRULE(pInstallAgentRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pInstallAgentRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\InstallAgent\\Checkpoints", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pInstallAgentRule);

	//Rules for taskmgr.exe
	UINT taskmgrRuleLen = 4;
	PRuleItems pTaskmgrRule = NULL;
	ARVINITRULES(pTaskmgrRule, "taskmgr.exe", taskmgrRuleLen);
	ARVDEFRULE(pTaskmgrRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pTaskmgrRule->Items[1], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTaskmgrRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pTaskmgrRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pTaskmgrRule);

	//Rules for mmc.exe
	UINT mmcRuleLen = 10;
	PRuleItems pMmcRule = NULL;
	ARVINITRULES(pMmcRule, "mmc.exe", mmcRuleLen);
	ARVDEFRULE(pMmcRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMmcRule->Items[1], L"|ArvProgramData|\\Microsoft\\Event Viewer\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Event Viewer\\*", ARVISFILE, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Caches", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Roaming", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[7], L"|ArvWinRoot|\\System32\\Catroot", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[8], L"|ArvWinRoot|\\System32\\catroot2", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMmcRule->Items[9], L"|ArvWinRoot|\\System32\\catroot2\\*", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMmcRule);

	//Rules for smartscreen.exe
	UINT smartScreenRuleLen = 9;
	PRuleItems pSmartScreenRule = NULL;
	ARVINITRULES(pSmartScreenRule, "smartscreen.ex", smartScreenRuleLen);
	ARVDEFRULE(pSmartScreenRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSmartScreenRule->Items[1], L"|ArvProfilesDirectory|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSmartScreenRule->Items[2], L"|ArvProfilesDirectory|\\|ArvOwnerName|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSmartScreenRule->Items[3], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSmartScreenRule->Items[4], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSmartScreenRule->Items[5], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSmartScreenRule->Items[6], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSmartScreenRule->Items[7], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Safety", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pSmartScreenRule->Items[8], L"|ArvProfilesDirectory|\\|ArvOwnerName|\\AppData\\Local\\Microsoft\\Windows\\Safety\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSmartScreenRule);

	//Rules for wuauclt.exe
	UINT wuaucltRuleLen = 2;
	PRuleItems pWuaucltRule = NULL;
	ARVINITRULES(pWuaucltRule, "wuauclt.exe", wuaucltRuleLen);
	ARVDEFRULE(pWuaucltRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWuaucltRule->Items[1], L"|ArvWinRoot|\\SoftwareDistribution", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWuaucltRule);

	//Rules for MSASCui.exe
	UINT msascuiRuleLen = 4;
	PRuleItems pMsascuiRule = NULL;
	ARVINITRULES(pMsascuiRule, "MSASCui.exe", msascuiRuleLen);
	ARVDEFRULE(pMsascuiRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMsascuiRule->Items[1], L"|ArvWinRoot|\\System32\\CatRoot", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMsascuiRule->Items[2], L"|ArvWinRoot|\\System32\\catroot2", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMsascuiRule->Items[3], L"|ArvWinRoot|\\System32\\catroot2\\dberr.txt", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMsascuiRule);

	//Rules for MSASCuiL.exe
	UINT msascuilRuleLen = 4;
	PRuleItems pMsascuilRule = NULL;
	ARVINITRULES(pMsascuilRule, "MSASCuiL.exe", msascuilRuleLen);
	ARVDEFRULE(pMsascuilRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMsascuilRule->Items[1], L"|ArvWinRoot|\\System32\\CatRoot", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMsascuilRule->Items[2], L"|ArvWinRoot|\\System32\\catroot2", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pMsascuilRule->Items[3], L"|ArvWinRoot|\\System32\\catroot2\\dberr.txt", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMsascuilRule);

	//Rules for SIHClient.exe
	UINT sihclientRuleLen = 2;
	PRuleItems pSihclientRule = NULL;
	ARVINITRULES(pSihclientRule, "SIHClient.exe", sihclientRuleLen);
	ARVDEFRULE(pSihclientRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pSihclientRule->Items[1], L"|ArvWinRoot|\\SoftwareDistribution", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pSihclientRule);

	//Rules for wsqmcons.exe
	UINT wsqmconsRuleLen = 11;
	PRuleItems pWsqmconsRule = NULL;
	ARVINITRULES(pWsqmconsRule, "wsqmcons.exe", wsqmconsRuleLen);
	ARVDEFRULE(pWsqmconsRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pWsqmconsRule->Items[1], L"|ArvProgramData|", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[2], L"|ArvProgramData|\\Microsoft", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[3], L"|ArvProgramData|\\Microsoft\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[4], L"|ArvProgramData|\\Microsoft\\Windows\\Sqm", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[5], L"|ArvProgramData|\\Microsoft\\Windows\\Sqm\\Manifest", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[6], L"|ArvProgramData|\\Microsoft\\Windows\\Sqm\\Sessions", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[7], L"|ArvWinRoot|\\Windows", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[8], L"|ArvWinRoot|\\System32", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[9], L"|ArvWinRoot|\\System32\\LogFiles", ARVFILEORDIRECTORY, ARVREADWRITE);
	ARVDEFRULE(pWsqmconsRule->Items[10], L"|ArvWinRoot|\\System32\\LogFiles\\SQM", ARVISFILE, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pWsqmconsRule);

	//Rules for makecab.exe
	UINT makecabRuleLen = 2;
	PRuleItems pMakecabRule = NULL;
	ARVINITRULES(pMakecabRule, "makecab.exe", makecabRuleLen);
	ARVDEFRULE(pMakecabRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pMakecabRule->Items[1], L"|ArvWinRoot|\\Temp\\*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pMakecabRule);

	//Rules for ngentask.exe
	UINT ngentaskRuleLen = 2;
	PRuleItems pNgentaskRule = NULL;
	ARVINITRULES(pNgentaskRule, "ngentask.exe", ngentaskRuleLen);
	ARVDEFRULE(pNgentaskRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADFILE);
	ARVDEFRULE(pNgentaskRule->Items[1], L"|ArvWinRoot|\\Microsoft.NET\\Framework*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pNgentaskRule);

	//虚拟机辅助进程，测试用
	//Rules for vmtoolsd.exe
	UINT vmtoolssdRuleLen = 1;
	PRuleItems pVmtoolssdRule = NULL;
	ARVINITRULES(pVmtoolssdRule, "vmtoolsd.exe", vmtoolssdRuleLen);
	ARVDEFRULE(pVmtoolssdRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pVmtoolssdRule);

	//Rules for vm3dservice.exe
	UINT vm3dRuleLen = 1;
	PRuleItems pVm3dRule = NULL;
	ARVINITRULES(pVm3dRule, "vm3dservice.ex", vm3dRuleLen);
	ARVDEFRULE(pVm3dRule->Items[0], L"*", ARVFILEORDIRECTORY, ARVREADWRITE);
	HASH_ADD_STR(pFilterRules, ProcessName, pVm3dRule);

	*ppFilterRules = pFilterRules;
}

NTSTATUS ReleaseEnv(PEnvItem EnvsMap)
{
	if (EnvsMap)
	{
		PEnvItem current, tmp;
		HASH_ITER(hh, EnvsMap, current, tmp) {
			HASH_DEL(EnvsMap, current);
			ExFreePoolWithTag(current, 'freg');
			current = NULL;
		}
	}
}

NTSTATUS InitEnv(PEnvItem *ppEnvsMap)
{
	PEnvItem pEnvsMap = *ppEnvsMap;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING RegUnicodeString = { 0 };
	HANDLE hRegister = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	PKEY_FULL_INFORMATION pfi = NULL;
	PKEY_VALUE_FULL_INFORMATION pvbi = NULL;
	ULONG ulSize = 0;
	//初始化 UNICODE_STRING 字符串
	RtlInitUnicodeString(&RegUnicodeString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ArvCtl");
	//初始化 objectAttributes
	InitializeObjectAttributes(&objectAttributes, &RegUnicodeString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	//打开注册表
	status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	//查询 VALUE 的大小
	status = ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
	/*if (!NT_SUCCESS(status))
	{
		goto CLEAN;
	}*/
	pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulSize, 'freg');
	if (!pfi)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto CLEAN;
	}
	status = ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);
	if (!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	for (ULONG i = 0; i < pfi->Values; i++)
	{
		//查询单个 VALUE 的大小
		status = ZwEnumerateValueKey(hRegister, i, KeyValueFullInformation, NULL, 0, &ulSize);
		/*if (!NT_SUCCESS(status))
		{
			goto CLEAN;
		}*/
		pvbi = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulSize, 'freg');
		if (!pvbi)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto CLEAN;
		}
		//查询单个 VALUE 的详情
		status = ZwEnumerateValueKey(hRegister, i, KeyValueFullInformation, pvbi, ulSize, &ulSize);
		if (!NT_SUCCESS(status))
		{
			goto CLEAN;
		}
		if (pvbi->Type == REG_SZ)
		{
			UNICODE_STRING uPrefix = { 0 };
			RtlInitUnicodeString(&uPrefix, L"ARV*");
			// show value name
			UNICODE_STRING uValueKey = { 0 };
			UNICODE_STRING uValueData = { 0 };
			// value key
			uValueKey.Length = uValueKey.MaximumLength = (USHORT)pvbi->NameLength;
			uValueKey.Buffer = pvbi->Name;
			// value data
			uValueData.Length = uValueData.MaximumLength = (USHORT)pvbi->DataLength;
			uValueData.Buffer = (PWCH)((PCH)pvbi + pvbi->DataOffset);
			//if (RtlPrefixUnicodeString(&uPrefix, &uValueKey, TRUE))
			if(FsRtlIsNameInExpression(&uPrefix, &uValueKey, TRUE, NULL))
			{
				PEnvItem item = (PEnvItem)ExAllocatePoolWithTag(NonPagedPool, sizeof(EnvItem), 'freg');
				if (!item)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					goto CLEAN;
				}
				RtlZeroMemory(item, sizeof(EnvItem));
				//wcsncpy_s(item->EnvName, uValueKey.Length/sizeof(WCHAR) + 1, uValueKey.Buffer, 260);
				//wcsncpy_s(item->EnvVal, uValueData.Length / sizeof(WCHAR) + 1, uValueData.Buffer, 320);
				RtlCopyMemory(item->EnvName, uValueKey.Buffer, uValueKey.Length);
				RtlCopyMemory(item->EnvVal, uValueData.Buffer, uValueData.Length);
				//HASH_ADD_STR(pEnvsMap, EnvName, item);
				HASH_ADD(hh, pEnvsMap, EnvName, 260*sizeof(WCHAR), item);
			}
		}
		/*else if (pvbi->Type == REG_MULTI_SZ)
		{
			KdPrint(("The sub value type:REG_MULTI_SZ\n"));
		}
		else if (pvbi->Type == REG_DWORD)
		{
			KdPrint(("The sub value type:REG_DWORD\n"));
		}
		else if (pvbi->Type == REG_BINARY)
		{
			KdPrint(("The sub value type:REG_BINARY\n"));
		}*/
		ExFreePool(pvbi);
		pvbi = NULL;
	}
CLEAN:
	if (pvbi)
	{
		ExFreePool(pvbi);
	}
	if (pfi)
	{
		ExFreePool(pfi);
	}
	if (hRegister)
	{
		ZwClose(hRegister);
	}
	if (NT_SUCCESS(status))
	{
		*ppEnvsMap = pEnvsMap;
	}
	return status;
}

NTSTATUS ArvSysPathFilterRulesInit(PPathFilterRules pRules)
{
	NTSTATUS Status = STATUS_SUCCESS;
	if (!NT_SUCCESS(InitFilterRulesFromReg(&pRules->FilterRules)))
	{
		Status = InitFilterRules(&pRules->FilterRules);
	}
	Status = InitEnv(&pRules->EnvsMap);
	ExInitializeResourceLite(&pRules->Res);
	return Status;
}

VOID ArvSysPathFilterRulesRelease(PPathFilterRules pRules)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&pRules->Res);
	ReleaseFilterRules(pRules->FilterRules);
	ReleaseEnv(pRules->EnvsMap);
	ExReleaseResourceAndLeaveCriticalRegion(&pRules->Res);
	ExDeleteResourceLite(&pRules->Res);
}

NTSTATUS GetOwnerNameByProcID(__in ULONG ProcID, __in UINT bufLen, __inout PWSTR name, __out PUINT len)
{
	NTSTATUS    status;
	HANDLE      processToken = NULL;
	TOKEN_USER *processUser = NULL;
	ULONG       processUserBytes = 0;
	UNICODE_STRING sid = { 0 };
	HANDLE handle;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	CLIENT_ID clientid = { 0 };

	UNICODE_STRING owner = { 0 };
	//BYTE ownerBuffer[256] = { 0 };
	//ULONG ownerSize = 1;
	SID_NAME_USE eUse = SidTypeUnknown;
	RtlInitEmptyUnicodeString(&owner, name, bufLen);
	InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
	clientid.UniqueProcess = (HANDLE)ProcID;
	clientid.UniqueThread = 0;
	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientid);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot open token for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	// Open process token
	status = ZwOpenProcessTokenEx(handle, GENERIC_READ,
		OBJ_KERNEL_HANDLE, &processToken);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot open token for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	// Get size of buffer to hold the user information, which contains the SID
	status = ZwQueryInformationToken(processToken, TokenUser,
		NULL, 0, &processUserBytes);
	if (status != STATUS_BUFFER_TOO_SMALL) {
		DbgPrint("Cannot get token information size for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	// Allocate the buffer to hold the user information
	processUser = (TOKEN_USER*)ExAllocatePoolWithTag(
		NonPagedPool, processUserBytes, 'TOK');
	if (processUser == NULL) {
		DbgPrint("Cannot allocate %u token information bytes for process %u", processUserBytes, ProcID);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	// Get user information for the process token
	status = ZwQueryInformationToken(processToken, TokenUser, processUser, processUserBytes, &processUserBytes);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot get token information for process %u: %08X", ProcID, status);
		goto Cleanup;
	}

	status = SecLookupAccountSid(processUser->User.Sid, len, &owner, NULL, NULL, &eUse);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Cannot convert SID to name for process %u: %08X", ProcID, status);
		goto Cleanup;
	}
Cleanup:
	if (processToken) {
		ZwClose(processToken);
	}
	if (processUser) {
		ExFreePoolWithTag(processUser, 'TOK');
		processUser = NULL;
	}
	if (handle) {
		ZwClose(handle);
	}
	if (sid.Buffer)
	{
		RtlFreeUnicodeString(&sid);
	}
	return status;
}

NTSTATUS ExpandFilterRuleWithEnv(__inout PWSTR pwRule, __in UINT PathLen, __in UINT BufLen, __out PUINT pExpandLen, __in ULONG ProcID, __in PEnvItem pEnvs)
{
	NTSTATUS Status = STATUS_SUCCESS;
	INT start = -1;
	INT end = -1;
	//UINT NewPathLen = PathLen;
	for (INT i = PathLen-1; i >= 0; i--)
	{
		//发现环境变量参数后标志，记录索引
		if (pwRule[i] == L'|' && end == -1)
		{
			end = i;
			if (end - 1 < 0)
			{
				Status = STATUS_ARRAY_BOUNDS_EXCEEDED;
				goto EXIT;
			}
		}
		else if (pwRule[i] == L'|' && end != -1) //发现环境变量参数前标志，记录索引
		{
			start = i;
			if (start + 1 >= end)
			{
				Status = STATUS_INVALID_PARAMETER;
				goto EXIT;
			}
			//提取变量名
			UNICODE_STRING uVarName = { 0 };
			RtlInitUnicodeString(&uVarName, &pwRule[start+1]);
			uVarName.Length = uVarName.MaximumLength = (end - start - 1)*sizeof(WCHAR);

			UNICODE_STRING uOwnerParamName;
			RtlInitUnicodeString(&uOwnerParamName, L"ArvOwnerName");

			WCHAR envValue[320];
			UINT envValueLen = 0;
			if (RtlEqualUnicodeString(&uVarName, &uOwnerParamName, TRUE))
			{
				//如果变量名是ArvOwnerName，需要从进程信息中提取所属用户名
				Status = GetOwnerNameByProcID(ProcID, 320, envValue, &envValueLen);
				if (!NT_SUCCESS(Status))
				{
					goto EXIT;
				}
				envValueLen = envValueLen / sizeof(WCHAR);
			}
			else
			{
				//如果变量名是其他，从EnvsMap中查找
				WCHAR tempEnvName[260] = { 0 };
				RtlCopyMemory(tempEnvName, uVarName.Buffer, uVarName.Length);
				PEnvItem pEnvItem = NULL;
				//HASH_FIND_STR(pEnvs, tempEnvName, pEnvItem);
				HASH_FIND(hh, pEnvs, tempEnvName, 260*sizeof(WCHAR), pEnvItem);
				if (!pEnvItem)
				{
					Status = STATUS_INVALID_PARAMETER;
					goto EXIT;
				}
				envValueLen = wcslen(pEnvItem->EnvVal);
				RtlCopyMemory(envValue, pEnvItem->EnvVal, envValueLen *sizeof(WCHAR));
			}
			if (end - start + 1 > envValueLen)
			{
				for (INT j = end + 1; j < PathLen; j++)
				{
					pwRule[j - (end - start + 1 - envValueLen)] = pwRule[j];
				}
				PathLen = PathLen - (end - start + 1 - envValueLen);
			}
			else if (end - start + 1 < envValueLen)
			{
				INT skip = 0;
				for (INT j = PathLen - 1; j > end; j--)
				{
					if (j + envValueLen - (end - start + 1) >= BufLen)
					{
						skip++;
					}
					else
					{
						pwRule[j + envValueLen - (end - start + 1)] = pwRule[j];
					}
				}
				PathLen = PathLen + envValueLen - (end - start + 1) - skip;
			}
			for (INT j = 0; j < envValueLen; j++)
			{
				pwRule[start + j] = envValue[j];
			}
			for (INT k = PathLen; k <= 260; k++)
			{
				pwRule[k] = 0;
			}
			start = end = -1;
		}
	}
	*pExpandLen = PathLen;
EXIT:
	return Status;
}

BOOLEAN ArvSysPathFilterRulesIfMatch(PPathFilterRules pRules, ULONG ProcID, PSTR ProcessName, BYTE ForD, BYTE RorW, PUNICODE_STRING pFullPath)
{
	ExEnterCriticalRegionAndAcquireResourceShared(&pRules->Res);
	BOOLEAN bRet = FALSE;
	PRuleItems pRule = NULL;
	WCHAR tempPath[260] = { 0 };
	HASH_FIND_STR(pRules->FilterRules, ProcessName, pRule); //根据进程名查找规则列表
	if (!pRule)
	{
		goto EXIT;	//规则不存在返回FALSE
	}
	//遍历规则列表中每一项，根据当前路径和路径类型、读写方式判断是否放行操作
	for (UINT i = 0; i < pRule->Len; i++)
	{
		RtlZeroMemory(tempPath, 260*sizeof(WCHAR));
		wcscpy_s(tempPath, 260, pRule->Items[i].Path);
		UINT expLen = 0;
		ExpandFilterRuleWithEnv(tempPath, wcslen(tempPath), 260, &expLen, ProcID, pRules->EnvsMap); //替换路径规则中的占位符
		UNICODE_STRING uTempPath = { 0 };
		RtlInitUnicodeString(&uTempPath, tempPath);
		uTempPath.Length = uTempPath.MaximumLength = expLen * sizeof(WCHAR);
		RtlUpcaseUnicodeString(&uTempPath, &uTempPath, FALSE);
		if (FsRtlIsNameInExpression(&uTempPath, pFullPath, TRUE, NULL) && (ForD & pRule->Items[i].FileType) && (RorW & pRule->Items[i].RWType))
		{
			bRet = TRUE;
			goto EXIT;
		}
	}
EXIT:
	/*bRet = TRUE;
	ExFreePool(pRule);*/

	ExReleaseResourceAndLeaveCriticalRegion(&pRules->Res);
	return bRet;
}
