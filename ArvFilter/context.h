#pragma once

#include <fltKernel.h>

#include "global.h"
#include "utils.h"



typedef struct _CreateContext {

	BOOLEAN UnderDBPath;

} CreateContext, *PCreateContext;

typedef struct _ARV_VOLUME_CONTEXT {

	//
	//  Holds the name to display
	//

	UNICODE_STRING VolumeName;

	//
	//  Holds the sector size for this volume.
	//

	ULONG SectorSize;

} ARV_VOLUME_CONTEXT, *PARV_VOLUME_CONTEXT;

typedef struct _ARV_STREAM_CONTEXT {

	PWCHAR FileName;

	//
	//  Name of the file associated with this context.
	//
	BOOLEAN UnderDBPath;

	//
	//  Lock used to protect this context.
	//
	PERESOURCE Resource;

} ARV_STREAM_CONTEXT, *PARV_STREAM_CONTEXT;

#define ARV_VOLUME_CONTEXT_SIZE         sizeof( ARV_VOLUME_CONTEXT )
#define ARV_STREAM_CONTEXT_SIZE         sizeof( ARV_STREAM_CONTEXT )

#define ARV_VOLUME_CONTEXT_TAG				  'xcBS'
#define ARV_STREAM_CONTEXT_TAG                'cSxC'

NTSTATUS
CtxFindOrCreateStreamContext(
	_In_ PFLT_CALLBACK_DATA Cbd,
	_In_ BOOLEAN CreateIfNotFound,
	_Outptr_ PARV_STREAM_CONTEXT *StreamContext,
	_Out_opt_ PBOOLEAN ContextCreated
);

VOID
CtxVolumeContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);

VOID
CtxStreamContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);