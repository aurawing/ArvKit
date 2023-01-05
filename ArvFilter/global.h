#pragma once

#include <fltKernel.h>

#include "config.h"
#include "Rules.h"

#define MIN_SECTOR_SIZE 0x200

#define CTX_RESOURCE_TAG	'cRxC'
#define CTX_STRING_TAG		'tSxC'
#define ARV_DPC_BUFFER_TAG              'dPBt'

#define ARV_MAX_NAME_LENGTH				512

#define ARVDBG_TRACE_ROUTINES            0x00000001
#define ARVDBG_TRACE_OPERATION_STATUS    0x00000002


const static ULONG gTraceFlags = 0x00000001;

#define ARV_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

extern PFLT_FILTER g_minifilterHandle;
extern PDEVICE_OBJECT gDeviceObject;
extern FilterConfig filterConfig;
extern ProcessFlags processFlags;
extern ERESOURCE HashResource;
extern ULONG controlProcID;
extern BOOL AllowUnload;

extern PFLT_PORT     gServerPort;//服务端口
extern PFLT_PORT     gClientPort;//客户端口

extern PathFilterRules SystemFilterRules;

extern DWORD LogFlag;
extern DWORD LogOnly;