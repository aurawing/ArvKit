#include "filefuncs.h"

NTSTATUS ArvGetFileNameOrExtension(
	IN PFLT_CALLBACK_DATA Data,
	IN OUT PWCHAR FileExtension,
	IN OUT PWCHAR FileName)
{

	NTSTATUS Status;
	PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;

	Status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		&FileNameInfo);

	if (!NT_SUCCESS(Status))
	{
		if (STATUS_FLT_NAME_CACHE_MISS == Status)
		{
			ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->FltGetFileNameInformation failed. Status = STATUS_FLT_NAME_CACHE_MISS\n", __FUNCTION__));
		}
		else
		{
			ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->FltGetFileNameInformation failed. Status = 0x%x\n", __FUNCTION__, Status));
		}
		return Status;
	}

	Status = FltParseFileNameInformation(FileNameInfo);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}

	if (NULL != FileExtension &&
		NULL != FileNameInfo->Extension.Buffer &&
		wcslen(FileNameInfo->Extension.Buffer) < ARV_MAX_NAME_LENGTH)
	{
		RtlMoveMemory(FileExtension, FileNameInfo->Extension.Buffer, wcslen(FileNameInfo->Extension.Buffer) * sizeof(WCHAR));
	}

	if (NULL != FileName &&
		NULL != FileNameInfo->Name.Buffer &&
		wcslen(FileNameInfo->Name.Buffer) < ARV_MAX_NAME_LENGTH)
	{
		RtlMoveMemory(FileName, FileNameInfo->Name.Buffer, wcslen(FileNameInfo->Name.Buffer) * sizeof(WCHAR));
	}

	// PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocGetFileExtension->FileName is %ws.\n", FileNameInfo->Name.Buffer);

EXIT:
	if (NULL != FileNameInfo)
	{
		FltReleaseFileNameInformation(FileNameInfo);
		FileNameInfo = NULL;
	}

	return Status;
}

NTSTATUS ArvFlushOriginalCache(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName)
{
	if (NULL == Instance)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == FileName)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UNICODE_STRING uFileName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	HANDLE hFile = NULL;
	PFILE_OBJECT FileObject = NULL;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	RtlInitUnicodeString(&uFileName, FileName);

	InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = FltCreateFileEx(
		g_minifilterHandle,
		Instance,
		&hFile,
		&FileObject,
		0,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		0,
		IO_IGNORE_SHARE_ACCESS_CHECK);

	if (STATUS_SUCCESS != Status)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
		goto EXIT;
	}

	if (CcIsFileCached(FileObject))
	{
		Status = FltFlushBuffers(Instance, FileObject);

		if (STATUS_SUCCESS != Status)
		{
			ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->FltFlushBuffers failed. Status = 0x%x\n", __FUNCTION__, Status));
			goto EXIT;
		}
	}


EXIT:

	if (NULL != hFile)
	{
		FltClose(hFile);
		hFile = NULL;
	}

	if (NULL != FileObject)
	{
		ObDereferenceObject(FileObject);
		FileObject = NULL;
	}

	return Status;
}

NTSTATUS ArvNtfsFlushAndPurgeCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject)
{
	if (NULL == Instance)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == FileObject)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->FileObject is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PFLT_CALLBACK_DATA Data = NULL;

	Status = FltAllocateCallbackData(Instance, FileObject, &Data);

	if (STATUS_SUCCESS != Status)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("ArvNtfsFlushAndPurgeCache->FltAllocateCallbackData failed. Status = 0x%x\n", Status));
		return Status;
	}

	Data->Iopb->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
	Data->Iopb->MinorFunction = IRP_MN_FLUSH_AND_PURGE;
	Data->Iopb->IrpFlags = IRP_SYNCHRONOUS_API;
	FltPerformSynchronousIo(Data);

	FltFreeCallbackData(Data);

	return Data->IoStatus.Status;
}