#include "utils.h"

//
//  Resource support
//

LONGLONG ArvQueryEndOfFileInfo(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject)
{

	FILE_STANDARD_INFORMATION StandardInfo = { 0 };
	ULONG LengthReturned = 0;
	NTSTATUS Status;

	Status = FltQueryInformationFile(Instance, FileObject, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("ArvQueryEndOfFileInfo->FltQueryInformationFile failed. Status = 0x%x.\n", Status));
		return 0;
	}

	return StandardInfo.EndOfFile.QuadPart;
}

USHORT ArvQueryVolumeSectorSize(IN PFLT_VOLUME Volume)
{
	// Therefore, a minifilter driver commonly calls this routine from a post-mount callback function
	// or an InstanceSetupCallback (PFLT_INSTANCE_SETUP_CALLBACK) routine to determine whether to attach to a given volume.

	UCHAR VolPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512] = { 0 };
	PFLT_VOLUME_PROPERTIES VolProp = (PFLT_VOLUME_PROPERTIES)VolPropBuffer;
	ULONG LengthReturned = 0;
	NTSTATUS Status;

	Status = FltGetVolumeProperties(Volume, VolProp, sizeof(VolPropBuffer), &LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("ArvQueryVolumeSectorSize->FltGetVolumeProperties failed. Status = 0x%x.\n", Status));
		return 0;
	}

	return max(VolProp->SectorSize, MIN_SECTOR_SIZE);
}

UINT ArvCalculateCharCountWithinUnicodeString(PUNICODE_STRING str, WCHAR c)
{
	UINT count = 0;
	for (UINT i = 0; i < str->Length / sizeof(wchar_t); i++)
	{
		if (str->Buffer[i] == c)
		{
			count++;
		}
	}
	return count;
}

BOOLEAN
ArvFindSubString(
	IN PUNICODE_STRING String,
	IN PUNICODE_STRING SubString
)
/*++

Routine Description:
This routine looks to see if SubString is a substring of String.

Arguments:
String - the string to search in
SubString - the substring to find in String

Return Value:
Returns TRUE if the substring is found in string and FALSE
otherwise.

--*/
{
	ULONG index;

	//
	// First, check to see if the strings are equal.
	//

	if (RtlEqualUnicodeString(String, SubString, TRUE)) {

		return TRUE;
	}

	//
	// String and SubString aren't equal, so now see if SubString
	// is in String any where.
	//

	for (index = 0;
		index + SubString->Length <= String->Length;
		index++) {

		if (_wcsnicmp(&String->Buffer[index],
			SubString->Buffer,
			(SubString->Length / sizeof(WCHAR))) == 0) {

			//
			// SubString is found in String, so return TRUE.
			//
			return TRUE;
		}
	}

	return FALSE;
}