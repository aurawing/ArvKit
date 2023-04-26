#include "context.h"

//NTSTATUS
//CtxCreateStreamContext2(
//	_Outptr_ PARV_STREAM_CONTEXT *StreamContext
//)
///*++
//
//Routine Description:
//
//	This routine creates a new stream context
//
//Arguments:
//
//	StreamContext         - Returns the stream context
//
//Return Value:
//
//	Status
//
//--*/
//{
//	NTSTATUS status;
//	PARV_STREAM_CONTEXT streamContext;
//
//	PAGED_CODE();
//
//	//
//	//  Allocate a stream context
//	//
//
//	DbgPrint("[Ctx]: Allocating stream context \n");
//
//	/*if (g_minifilterHandle == filter)
//	{
//		DbgPrint("============= same filter instance ================\n");
//	}
//	else
//	{
//		DbgPrint("============= diff filter instance ================\n");
//	}*/
//
//	status = FltAllocateContext(g_minifilterHandle,
//		FLT_STREAM_CONTEXT,
//		ARV_STREAM_CONTEXT_SIZE,
//		NonPagedPool,
//		&streamContext);
//
//	if (!NT_SUCCESS(status)) {
//
//		DbgPrint("[Ctx]: Failed to allocate stream context with status 0x%x \n",
//			status);
//		return status;
//	}
//
//	//
//	//  Initialize the newly created context
//	//
//
//	RtlZeroMemory(streamContext, ARV_STREAM_CONTEXT_SIZE);
//
//	streamContext->FileName = ExAllocatePoolWithTag(NonPagedPool, ARV_MAX_NAME_LENGTH * sizeof(WCHAR), CTX_STRING_TAG);
//
//	if (streamContext->FileName == NULL)
//	{
//		FltReleaseContext(streamContext);
//		return STATUS_INSUFFICIENT_RESOURCES;
//	}
//
//	RtlZeroMemory(streamContext->FileName, ARV_MAX_NAME_LENGTH * sizeof(WCHAR));
//
//	streamContext->Resource = CtxAllocateResource();
//	if (streamContext->Resource == NULL) {
//		ExFreePoolWithTag(streamContext->FileName, CTX_STRING_TAG);
//		FltReleaseContext(streamContext);
//		return STATUS_INSUFFICIENT_RESOURCES;
//	}
//	ExInitializeResourceLite(streamContext->Resource);
//
//	*StreamContext = streamContext;
//
//	return STATUS_SUCCESS;
//}
//
//NTSTATUS
//CtxFindOrCreateStreamContext2(
//	_In_ PFLT_CALLBACK_DATA Cbd,
//	_In_ BOOLEAN CreateIfNotFound,
//	_Outptr_ PARV_STREAM_CONTEXT *StreamContext,
//	_Out_opt_ PBOOLEAN ContextCreated
//)
///*++
//
//Routine Description:
//
//	This routine finds the stream context for the target stream.
//	Optionally, if the context does not exist this routing creates
//	a new one and attaches the context to the stream.
//
//Arguments:
//
//	Cbd                   - Supplies a pointer to the callbackData which
//							declares the requested operation.
//	CreateIfNotFound      - Supplies if the stream must be created if missing
//	StreamContext         - Returns the stream context
//	ContextCreated        - Returns if a new context was created
//
//Return Value:
//
//	Status
//
//--*/
//{
//	NTSTATUS status;
//	PARV_STREAM_CONTEXT streamContext;
//	PARV_STREAM_CONTEXT oldStreamContext;
//
//	PAGED_CODE();
//
//	*StreamContext = NULL;
//	if (ContextCreated != NULL) *ContextCreated = FALSE;
//
//	//
//	//  First try to get the stream context.
//	//
//
//	DbgPrint("------------- [Ctx]: Trying to get stream context (FileObject = %p, Instance = %p)\n",
//		Cbd->Iopb->TargetFileObject,
//		Cbd->Iopb->TargetInstance);
//	//ArvWriteDebug(Cbd->Iopb->TargetFileObject, Cbd->Iopb->TargetInstance);
//	status = FltGetStreamContext(Cbd->Iopb->TargetInstance,
//		Cbd->Iopb->TargetFileObject,
//		&streamContext);
//
//	//
//	//  If the call failed because the context does not exist
//	//  and the user wants to creat a new one, the create a
//	//  new context
//	//
//
//	if (!NT_SUCCESS(status) &&
//		(status == STATUS_NOT_FOUND) &&
//		CreateIfNotFound) {
//
//
//		//
//		//  Create a stream context
//		//
//
//		DbgPrint("------------- [Ctx]: Creating stream context (FileObject = %p, Instance = %p)\n",
//			Cbd->Iopb->TargetFileObject,
//			Cbd->Iopb->TargetInstance);
//
//		status = CtxCreateStreamContext2(&streamContext);
//
//		if (!NT_SUCCESS(status)) {
//
//			DbgPrint("[Ctx]: Failed to create stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
//				status,
//				Cbd->Iopb->TargetFileObject,
//				Cbd->Iopb->TargetInstance);
//
//			return status;
//		}
//
//
//		//
//		//  Set the new context we just allocated on the file object
//		//
//
//		DbgPrint("------------- [Ctx]: Setting stream context %p (FileObject = %p, Instance = %p)\n",
//			streamContext,
//			Cbd->Iopb->TargetFileObject,
//			Cbd->Iopb->TargetInstance);
//
//		status = FltSetStreamContext(Cbd->Iopb->TargetInstance,
//			Cbd->Iopb->TargetFileObject,
//			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
//			streamContext,
//			&oldStreamContext);
//
//		if (!NT_SUCCESS(status)) {
//
//			DbgPrint("[Ctx]: Failed to set stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
//				status,
//				Cbd->Iopb->TargetFileObject,
//				Cbd->Iopb->TargetInstance);
//			//
//			//  We release the context here because FltSetStreamContext failed
//			//
//			//  If FltSetStreamContext succeeded then the context will be returned
//			//  to the caller. The caller will use the context and then release it
//			//  when he is done with the context.
//			//
//
//			DbgPrint("[Ctx]: Releasing stream context %p (FileObject = %p, Instance = %p)\n",
//				streamContext,
//				Cbd->Iopb->TargetFileObject,
//				Cbd->Iopb->TargetInstance);
//
//			FltReleaseContext(streamContext);
//
//			if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
//
//				//
//				//  FltSetStreamContext failed for a reason other than the context already
//				//  existing on the stream. So the object now does not have any context set
//				//  on it. So we return failure to the caller.
//				//
//
//				DbgPrint("[Ctx]: Failed to set stream context with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED. (FileObject = %p, Instance = %p)\n",
//					status,
//					Cbd->Iopb->TargetFileObject,
//					Cbd->Iopb->TargetInstance);
//
//				return status;
//			}
//
//			//
//			//  Race condition. Someone has set a context after we queried it.
//			//  Use the already set context instead
//			//
//
//			DbgPrint("[Ctx]: Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
//				oldStreamContext,
//				Cbd->Iopb->TargetFileObject,
//				Cbd->Iopb->TargetInstance);
//
//			//
//			//  Return the existing context. Note that the new context that we allocated has already been
//			//  realeased above.
//			//
//
//			streamContext = oldStreamContext;
//			status = STATUS_SUCCESS;
//
//		}
//		else {
//
//			if (ContextCreated != NULL) *ContextCreated = TRUE;
//		}
//	}
//
//	*StreamContext = streamContext;
//
//	return status;
//}

NTSTATUS
CtxCreateStreamContext(
	_Outptr_ PARV_STREAM_CONTEXT *StreamContext
)
/*++

Routine Description:

	This routine creates a new stream context

Arguments:

	StreamContext         - Returns the stream context

Return Value:

	Status

--*/
{
	NTSTATUS status;
	PARV_STREAM_CONTEXT streamContext;

	PAGED_CODE();

	//
	//  Allocate a stream context
	//

	DbgPrint("[Ctx]: Allocating stream context \n");

	/*if (g_minifilterHandle == filter)
	{
		DbgPrint("============= same filter instance ================\n");
	}
	else
	{
		DbgPrint("============= diff filter instance ================\n");
	}*/

	status = FltAllocateContext(g_minifilterHandle,
		FLT_STREAM_CONTEXT,
		ARV_STREAM_CONTEXT_SIZE,
		NonPagedPool,
		&streamContext);

	if (!NT_SUCCESS(status)) {

		DbgPrint("[Ctx]: Failed to allocate stream context with status 0x%x \n",
			status);
		return status;
	}

	//
	//  Initialize the newly created context
	//

	RtlZeroMemory(streamContext, ARV_STREAM_CONTEXT_SIZE);

	streamContext->FileName = ExAllocatePoolWithTag(NonPagedPool, ARV_MAX_NAME_LENGTH * sizeof(WCHAR), CTX_STRING_TAG);

	if (streamContext->FileName == NULL)
	{
		FltReleaseContext(streamContext);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(streamContext->FileName, ARV_MAX_NAME_LENGTH * sizeof(WCHAR));

	streamContext->Resource = CtxAllocateResource();
	if (streamContext->Resource == NULL) {
		ExFreePoolWithTag(streamContext->FileName, CTX_STRING_TAG);
		FltReleaseContext(streamContext);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	ExInitializeResourceLite(streamContext->Resource);

	*StreamContext = streamContext;

	return STATUS_SUCCESS;
}

NTSTATUS
CtxFindOrCreateStreamContext(
	_In_ PFLT_CALLBACK_DATA Cbd,
	_In_ BOOLEAN CreateIfNotFound,
	_Outptr_ PARV_STREAM_CONTEXT *StreamContext,
	_Out_opt_ PBOOLEAN ContextCreated
)
/*++

Routine Description:

	This routine finds the stream context for the target stream.
	Optionally, if the context does not exist this routing creates
	a new one and attaches the context to the stream.

Arguments:

	Cbd                   - Supplies a pointer to the callbackData which
							declares the requested operation.
	CreateIfNotFound      - Supplies if the stream must be created if missing
	StreamContext         - Returns the stream context
	ContextCreated        - Returns if a new context was created

Return Value:

	Status

--*/
{
	NTSTATUS status;
	PARV_STREAM_CONTEXT streamContext;
	PARV_STREAM_CONTEXT oldStreamContext;

	PAGED_CODE();

	*StreamContext = NULL;
	if (ContextCreated != NULL) *ContextCreated = FALSE;

	//
	//  First try to get the stream context.
	//

	DbgPrint("------------- [Ctx]: Trying to get stream context (FileObject = %p, Instance = %p)\n",
		Cbd->Iopb->TargetFileObject,
		Cbd->Iopb->TargetInstance);

	status = FltGetStreamContext(Cbd->Iopb->TargetInstance,
		Cbd->Iopb->TargetFileObject,
		&streamContext);

	//
	//  If the call failed because the context does not exist
	//  and the user wants to creat a new one, the create a
	//  new context
	//

	if (!NT_SUCCESS(status) &&
		(status == STATUS_NOT_FOUND) &&
		CreateIfNotFound) {


		//
		//  Create a stream context
		//

		DbgPrint("------------- [Ctx]: Creating stream context (FileObject = %p, Instance = %p)\n",
			Cbd->Iopb->TargetFileObject,
			Cbd->Iopb->TargetInstance);

		status = CtxCreateStreamContext(&streamContext);

		if (!NT_SUCCESS(status)) {

			DbgPrint("[Ctx]: Failed to create stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
				status,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);

			return status;
		}


		//
		//  Set the new context we just allocated on the file object
		//

		DbgPrint("------------- [Ctx]: Setting stream context %p (FileObject = %p, Instance = %p)\n",
			streamContext,
			Cbd->Iopb->TargetFileObject,
			Cbd->Iopb->TargetInstance);

		status = FltSetStreamContext(Cbd->Iopb->TargetInstance,
			Cbd->Iopb->TargetFileObject,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			streamContext,
			&oldStreamContext);

		if (!NT_SUCCESS(status)) {

			DbgPrint("[Ctx]: Failed to set stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
				status,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);
			//
			//  We release the context here because FltSetStreamContext failed
			//
			//  If FltSetStreamContext succeeded then the context will be returned
			//  to the caller. The caller will use the context and then release it
			//  when he is done with the context.
			//

			DbgPrint("[Ctx]: Releasing stream context %p (FileObject = %p, Instance = %p)\n",
				streamContext,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);

			FltReleaseContext(streamContext);

			if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

				//
				//  FltSetStreamContext failed for a reason other than the context already
				//  existing on the stream. So the object now does not have any context set
				//  on it. So we return failure to the caller.
				//

				DbgPrint("[Ctx]: Failed to set stream context with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED. (FileObject = %p, Instance = %p)\n",
					status,
					Cbd->Iopb->TargetFileObject,
					Cbd->Iopb->TargetInstance);

				return status;
			}

			//
			//  Race condition. Someone has set a context after we queried it.
			//  Use the already set context instead
			//

			DbgPrint("[Ctx]: Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
				oldStreamContext,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance);

			//
			//  Return the existing context. Note that the new context that we allocated has already been
			//  realeased above.
			//

			streamContext = oldStreamContext;
			status = STATUS_SUCCESS;

		}
		else {

			if (ContextCreated != NULL) *ContextCreated = TRUE;
		}
	}

	*StreamContext = streamContext;

	return status;
}

VOID
CtxVolumeContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	PARV_VOLUME_CONTEXT ctx = Context;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ContextType);

	FLT_ASSERT(ContextType == FLT_VOLUME_CONTEXT);

	if (ctx->VolumeName.Buffer != NULL) {

		ExFreePool(ctx->VolumeName.Buffer);
		ctx->VolumeName.Buffer = NULL;
	}
}

VOID
CtxStreamContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	PARV_STREAM_CONTEXT streamContext;

	PAGED_CODE();

	switch (ContextType) {

	case FLT_STREAM_CONTEXT:

		streamContext = (PARV_STREAM_CONTEXT)Context;

		DbgPrint("[Ctx]: Cleaning up stream context %p: %d\n",
			streamContext,
			&streamContext->UnderDBPath);

		//
		//  Delete the resource and memory the memory allocated for the resource
		//

		if (streamContext->FileName != NULL)
		{
			ExFreePool(streamContext->FileName);
			streamContext->FileName = NULL;
		}

		if (streamContext->Resource != NULL) {

			ExDeleteResourceLite(streamContext->Resource);
			CtxFreeResource(streamContext->Resource);
			streamContext->Resource = NULL;
		}

		if (streamContext->UnderDBPath) {

			streamContext->UnderDBPath = FALSE;
		}

		DbgPrint("[Ctx]: Stream context cleanup complete.\n");

		break;

	}

}