#pragma once

#include <fltKernel.h>

#include "global.h"

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

LONGLONG ArvQueryEndOfFileInfo(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject);

USHORT ArvQueryVolumeSectorSize(IN PFLT_VOLUME Volume);