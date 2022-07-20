#pragma once

#include <fltKernel.h>
#include "global.h"

NTSTATUS ArvGetFileNameOrExtension(
	IN PFLT_CALLBACK_DATA Data,
	IN OUT PWCHAR FileExtension,
	IN OUT PWCHAR FileName);

NTSTATUS ArvFlushOriginalCache(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName);

NTSTATUS ArvNtfsFlushAndPurgeCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject);