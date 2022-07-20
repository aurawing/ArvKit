#pragma once
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
#include "filefuncs.h"
#include "comm.h"
#include "context.h"
#include "dpc.h"
#include "global.h"
