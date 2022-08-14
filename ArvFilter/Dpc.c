
#include "dpc.h"

KDEFERRED_ROUTINE ArvKdeferredRoutine;

VOID ArvSafePostCallbackShell(
	IN PDEVICE_OBJECT DeviceObject,
	IN PVOID Context);


VOID ArvInitDpcRoutine()
{

	InitializeListHead(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead);
	KeInitializeSpinLock(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);

	KeInitializeTimer(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer);

	KeInitializeDpc(
		&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Dpc,
		ArvKdeferredRoutine,
		NULL);


	((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem = IoAllocateWorkItem(gDeviceObject);

	if (NULL == ((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->IoAllocateWorkItem IoWorkItem failed.\n", __FUNCTION__));
		return;
	}
}


VOID ArvKdeferredRoutine(
	IN KDPC* Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	/*
	* Do not call IoQueueWorkItem or IoQueueWorkItemEx to queue a work item that is already in the queue.
	* Doing so can cause corruption of system data structures.
	* If your driver queues the same work item each time a particular driver routine runs,
	* you can use the following technique to avoid queuing the work item a second time if it is already in the queue:

	* The driver maintains a list of tasks for the worker routine.
	* This task list is available in the context that is supplied to the worker routine.
	* The worker routine and any driver routines that modify the task list synchronize their access to the list.
	* Each time the worker routine runs, it performs all the tasks in the list,
	* and removes each task from the list as the task is completed.
	* When a new task arrives, the driver adds this task to the list.
	* The driver queues the work item only if the task list was previously empty.
	*
	* The system worker thread removes the work item from the queue before it calls the worker thread.
	* Thus, a driver thread can safely queue the work item again as soon as the worker thread starts to run.
	*
	* �����ǰ�IoQueueWorkItem������Dpc�У���Dpc��Timer����KeSetTimer����ʱ�������ʱ����Timerû��ʱ��
	* ������ȡ��֮ǰ��Timer����������Timer��������IoQueueWorkItemҲ�Ͳ����г�ͻ�ˡ�
	*/

	IoQueueWorkItem(
		((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem,
		ArvSafePostCallbackShell,
		DelayedWorkQueue,
		NULL);

	//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->IoQueueWorkItem PocSafePostCallbackShell.\n", __FUNCTION__));

}


VOID ArvSafePostCallbackShell(
	IN PDEVICE_OBJECT DeviceObject,
	IN PVOID Context)
{

	UNREFERENCED_PARAMETER(Context);

	PARV_WORKITEM_LIST WorkItem = NULL;

	PLIST_ENTRY pListEntry = ((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead.Flink;
	KIRQL OldIrql = 0;

	while (pListEntry != &((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead)
	{

		WorkItem = CONTAINING_RECORD(pListEntry, ARV_WORKITEM_LIST, ListEntry);



		if (NULL != WorkItem->WorkItemParam)
		{
			((ArvSafePostCallback)(WorkItem->WorkItemParam->WorkerRoutine))(
				DeviceObject,
				WorkItem->WorkItemParam->Context);

			if (NULL != WorkItem->WorkItemParam->Event)
				KeSetEvent(WorkItem->WorkItemParam->Event, IO_NO_INCREMENT, TRUE);
		}



		OldIrql = KeAcquireSpinLockRaiseToDpc(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);

		RemoveEntryList(&WorkItem->ListEntry);

		KeReleaseSpinLock(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock, OldIrql);

		if (NULL != WorkItem && NULL != WorkItem->WorkItemParam)
		{
			ExFreePoolWithTag(WorkItem->WorkItemParam, ARV_DPC_BUFFER_TAG);
			WorkItem->WorkItemParam = NULL;
		}

		if (NULL != WorkItem)
		{
			ExFreePoolWithTag(WorkItem, ARV_DPC_BUFFER_TAG);
			WorkItem = NULL;
		}

		pListEntry = pListEntry->Flink;
	}

}


NTSTATUS ArvDoCompletionProcessingWhenSafe(
	IN PVOID SafePostCallback,
	IN PVOID Context,
	IN PKEVENT Event)
	/*---------------------------------------------------------
	��������:	PocDoCompletionProcessingWhenSafe
	��������:	�����ڸ�IRQLʱ��ȫ����SafePostCallback�������APC_LEVEL��һ�£�SafePostCallback������ֱ�ӱ�����
	����:		SafePostCallback����Ҫִ�еĺ�����
				Context��SafePostCallback�Ĳ���������Ǿֲ���������������EventΪ���źţ�Ȼ��KeWaitForSingleObject�ȴ���
				Event��ͬ���¼�����ѡ����Event��Ҫ�Ƿ�����NonPagedPool���ڴ�
				�����Ҫͬ���Ļ���ʹ��KeInitializeEvent����ΪNotificationEvent����ʼ״̬���źţ�
				SafePostCallback����ִ�����Event�����źš�
	����:		hkx3upper
	ʱ�䣺		2022.06.05
	����ά��:
	---------------------------------------------------------*/
{

	if (NULL == SafePostCallback)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->SafePostCallback is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_SUCCESS;

	PARV_WORKITEM_LIST WorkItem = NULL;
	BOOLEAN ListEmpty = FALSE;

	LARGE_INTEGER DueTime = { 0 };


	if (KeGetCurrentIrql() <= APC_LEVEL)
	{
		((ArvSafePostCallback)SafePostCallback)(gDeviceObject, Context);
		if (Event != NULL)
		{
			KeSetEvent(Event, IO_NO_INCREMENT, TRUE);
		}
		goto EXIT;

	}
	else if (KeGetCurrentIrql() == DISPATCH_LEVEL)
	{

	}
	else
	{
		KeBugCheck(IRQL_NOT_LESS_OR_EQUAL);
	}



	WorkItem = ExAllocatePoolWithTag(NonPagedPool, sizeof(ARV_WORKITEM_LIST), ARV_DPC_BUFFER_TAG);

	if (NULL == WorkItem)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag WorkItem failed.\n", __FUNCTION__));
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(WorkItem, sizeof(ARV_WORKITEM_LIST));


	WorkItem->WorkItemParam = ExAllocatePoolWithTag(NonPagedPool, sizeof(ARV_WORKITEM_PARAMETER), ARV_DPC_BUFFER_TAG);

	if (NULL == WorkItem->WorkItemParam)
	{
		ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag WorkItem->WorkItemParam failed.\n", __FUNCTION__));
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(WorkItem->WorkItemParam, sizeof(ARV_WORKITEM_PARAMETER));


	WorkItem->WorkItemParam->WorkerRoutine = SafePostCallback;
	WorkItem->WorkItemParam->Context = Context;

	if (NULL != Event)
		WorkItem->WorkItemParam->Event = Event;

	if (IsListEmpty(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead))
	{
		ListEmpty = TRUE;
	}


	ExInterlockedInsertTailList(
		&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead,
		&WorkItem->ListEntry,
		&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);


	/*
	* If the timer object was already in the timer queue,
	* it is implicitly canceled before being set to the new expiration time.
	* A call to KeSetTimer before the previously specified DueTime has expired cancels both the timerand the call to the Dpc,
	* if any, associated with the previous call.
	*/

	if (ListEmpty)
	{

#pragma warning(push)
#pragma warning(disable:4996)
		DueTime = RtlConvertLongToLargeInteger(-1);
#pragma warning(pop)

		if (KeSetTimer(
			&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer,
			DueTime,
			&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Dpc))
		{
			ARV_DBG_PRINT(ARVDBG_TRACE_ROUTINES, ("%s->The timer object was already in the system timer queue.\n", __FUNCTION__));
			Status = STATUS_SUCCESS;
			goto EXIT;
		}

		KeWaitForSingleObject(
			&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer,
			Executive,
			KernelMode,
			FALSE,
			NULL);

		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Timer expire.\n", __FUNCTION__));
	}


EXIT:

	return Status;
}


VOID ArvWorkItemListCleanup()
{
	PARV_WORKITEM_LIST WorkItem = NULL;
	PLIST_ENTRY pListEntry = { 0 };

	while (!IsListEmpty(&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead))
	{

		pListEntry = ExInterlockedRemoveHeadList(
			&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead,
			&((PARV_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);


		WorkItem = CONTAINING_RECORD(pListEntry, ARV_WORKITEM_LIST, ListEntry);


		if (NULL != WorkItem && NULL != WorkItem->WorkItemParam)
		{
			ExFreePoolWithTag(WorkItem->WorkItemParam, ARV_DPC_BUFFER_TAG);
			WorkItem->WorkItemParam = NULL;
		}

		if (NULL != WorkItem)
		{
			ExFreePoolWithTag(WorkItem, ARV_DPC_BUFFER_TAG);
			WorkItem = NULL;
		}
	}
}
