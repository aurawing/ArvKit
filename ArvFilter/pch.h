/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

	pch.h

Abstract:

	This module includes all  the headers which need to be
	precompiled & are included by all the source files in this
	project


Environment:

	Kernel mode


--*/

#ifndef __ARV_PCH_H__
#define __ARV_PCH_H__

//
//  Enabled warnings
//

//#pragma warning(error:4100)     //  Enable-Unreferenced formal parameter
//#pragma warning(error:4101)     //  Enable-Unreferenced local variable
//#pragma warning(error:4061)     //  Eenable-missing enumeration in switch statement
//#pragma warning(error:4505)     //  Enable-identify dead functions

//
//  Includes
//

#include <fltKernel.h>
#include <windef.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntifs.h>
#include <Wdmsec.h>
#include <stdlib.h>
#include <stdbool.h>

#include "config.h"
#include "crypto.h"
#include "init.h"

//
//  Memory Pool Tags
//

typedef struct _CTX_STREAM_CONTEXT {

	//
	//  Name of the file associated with this context.
	//
	BOOLEAN UnderDBPath;

	//
	//  Lock used to protect this context.
	//
	PERESOURCE Resource;

} CTX_STREAM_CONTEXT, *PCTX_STREAM_CONTEXT;

#define CTX_STREAM_CONTEXT_SIZE         sizeof( CTX_STREAM_CONTEXT )

#define CTX_STRING_TAG                        'tSxC'
#define CTX_RESOURCE_TAG                      'cRxC'
#define CTX_STREAM_CONTEXT_TAG                'cSxC'

extern PFLT_FILTER g_minifilterHandle;
extern FilterConfig filterConfig;
extern ERESOURCE HashResource;

//
//  Functions implemented in support.c
//

NTSTATUS
MyRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
);

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _In_)
_At_(String->Buffer, _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(String->MaximumLength))
NTSTATUS
CtxAllocateUnicodeString(
	_Out_ PUNICODE_STRING String
);

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _Out_range_(== , 0))
_At_(String->Buffer, _Pre_notnull_ _Post_null_)
VOID
CtxFreeUnicodeString(
	_Pre_notnull_ PUNICODE_STRING String
);


//
//  Resource support
//

FORCEINLINE
PERESOURCE
CtxAllocateResource(
	VOID
)
{

	return ExAllocatePoolWithTag(NonPagedPool,
		sizeof(ERESOURCE),
		CTX_RESOURCE_TAG);
}

FORCEINLINE
VOID
CtxFreeResource(
	_In_ PERESOURCE Resource
)
{

	ExFreePoolWithTag(Resource,
		CTX_RESOURCE_TAG);
}

FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
CtxAcquireResourceExclusive(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_exclusive_lock_(*_Curr_)
	PERESOURCE Resource
)
{
	FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
	FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
		!ExIsResourceAcquiredSharedLite(Resource));

	KeEnterCriticalRegion();
	(VOID)ExAcquireResourceExclusiveLite(Resource, TRUE);
}

FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
CtxAcquireResourceShared(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_shared_lock_(*_Curr_)
	PERESOURCE Resource
)
{
	FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	KeEnterCriticalRegion();
	(VOID)ExAcquireResourceSharedLite(Resource, TRUE);
}

FORCEINLINE
VOID
_Releases_lock_(_Global_critical_region_)
_Requires_lock_held_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
CtxReleaseResource(
	_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
	PERESOURCE Resource
)
{
	FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
	FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
		ExIsResourceAcquiredSharedLite(Resource));

	ExReleaseResourceLite(Resource);
	KeLeaveCriticalRegion();
}

#endif __ARV_PCH_H__