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

//#pragma section(".00cfg", read)

//__declspec(allocate(".00cfg"))
//__declspec(selectany)
//volatile void * __guard_check_icall_fptr = (void *)_my_guard_check_icall;

extern void * __guard_check_icall_fptr;

extern UINT32 *gGuardCFFunctionTable;
extern UINTN  gGuardCFFunctionCount;
extern UINTN  gImageBase;

void
__fastcall
_my_guard_check_icall (
    IN UINTN Target
    )
{
  UINTN  Index;

  DEBUG ((DEBUG_INFO, "_my_guard_check_icall - 0x%016lx\n", (UINT64)Target));
  for (Index = 0; Index < gGuardCFFunctionCount; Index++) {
    DEBUG ((DEBUG_INFO, "Checking ... 0x%016lx\n", gGuardCFFunctionTable[Index] + gImageBase));
    if ((gGuardCFFunctionTable[Index] + gImageBase) == Target) {
      DEBUG ((DEBUG_INFO, "\n!!! guard check pass !!!\n"));
      return;
    }
  }
  DEBUG ((DEBUG_ERROR, "\n!!! guard check fail !!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
}

RETURN_STATUS
EFIAPI
UefiCfgLibConstructor(
  VOID
  );

VOID
EFIAPI
EnableReadOnlyProtection (
  IN VOID  *Buffer,
  IN UINTN Size
  );

VOID
EFIAPI
DisableReadOnlyProtection (
  IN VOID  *Buffer,
  IN UINTN Size
  );

RETURN_STATUS
EFIAPI
CfgLibConstructor(
  VOID
  )
{
  UefiCfgLibConstructor ();

#ifdef WINNT
  DisableReadOnlyProtection (&__guard_check_icall_fptr, sizeof(__guard_check_icall_fptr));
#endif
  __guard_check_icall_fptr = (void *)_my_guard_check_icall;
#ifdef WINNT
  EnableReadOnlyProtection (&__guard_check_icall_fptr, sizeof(__guard_check_icall_fptr));
#endif

  return RETURN_SUCCESS;
}