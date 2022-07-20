#pragma once
#pragma once

#include "global.h"

typedef struct _ARV_WORKITEM_PARAMETER
{
	PVOID WorkerRoutine;
	PVOID Context;

	PKEVENT Event;

}ARV_WORKITEM_PARAMETER, *PARV_WORKITEM_PARAMETER;


typedef struct _ARV_WORKITEM_LIST
{
	LIST_ENTRY ListEntry;
	PARV_WORKITEM_PARAMETER WorkItemParam;

}ARV_WORKITEM_LIST, *PARV_WORKITEM_LIST;


typedef struct _ARV_DEVICE_EXTENSION
{
	KTIMER Timer;
	KDPC Dpc;

	PIO_WORKITEM IoWorkItem;

	LIST_ENTRY WorkItemListHead;
	KSPIN_LOCK WorkItemSpinLock;

}ARV_DEVICE_EXTENSION, *PARV_DEVICE_EXTENSION;


typedef VOID(*ArvSafePostCallback) (
	IN PDEVICE_OBJECT,
	IN PVOID
	);

VOID ArvInitDpcRoutine();

VOID ArvWorkItemListCleanup();

NTSTATUS ArvDoCompletionProcessingWhenSafe(
	IN PVOID SafePostCallback,
	IN PVOID Context,
	IN PKEVENT Event);
