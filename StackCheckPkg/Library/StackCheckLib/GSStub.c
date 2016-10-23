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

//
// Below data structure is from vcruntime.h and gs_report.c (Microsoft Visual Studio)
//

UINTN __security_cookie = 0;

void __security_init_cookie(void)
{
  UINT64  Cookie;
  GetRandomNumber64(&Cookie);
  __security_cookie = (UINTN)Cookie;
}

static void __cdecl __report_gsfailure(UINTN StackCookie)
{
  DEBUG ((EFI_D_ERROR, "\n!!! stack overflow check failed in cookie checker!!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

__declspec(noreturn) void __cdecl __report_rangecheckfailure()
{
  DEBUG((EFI_D_ERROR, "\n!!! range check check failed in cookie checker!!!\n"));
  ASSERT(FALSE);

  CpuDeadLoop();
}

void __fastcall __security_check_cookie(UINTN cookie)
{
  if (cookie == __security_cookie) {
    return;
  }

  __report_gsfailure(cookie);
  return ;
}

void __GSHandlerCheck(void)
{
  // dummy
  CpuDeadLoop ();
  return ;
}

RETURN_STATUS
EFIAPI
StackCheckLibConstructor(
  VOID
  )
{
  __security_init_cookie();
  return RETURN_SUCCESS;
}