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

//
// Below data structure is from rtcapi.h (Microsoft Visual Studio)
//

void   __cdecl     _RTC_UninitUse(const char *VarName)
{
  DEBUG ((EFI_D_ERROR, "\n!!! uninitialized var \"%a\" is used!!!\n", VarName));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}
