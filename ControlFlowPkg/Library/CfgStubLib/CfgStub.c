/**

Copyright (c) 2012, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>

#include "PeLoadConfiguration.h"

//
// Below data structure is from guard_support.c (Microsoft Visual Studio)
//

void
__fastcall
_my_guard_check_icall (
    IN UINTN Target
    )
{
  DEBUG ((DEBUG_INFO, "_my_guard_check_icall - 0x%08x\n", Target));
}

#pragma section(".00cfg", read)

__declspec(allocate(".00cfg"))
__declspec(selectany)
volatile void * __guard_check_icall_fptr = (void *)_my_guard_check_icall;
