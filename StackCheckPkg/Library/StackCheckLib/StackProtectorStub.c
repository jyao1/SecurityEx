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
// Implementation
//

UINTN __stack_chk_guard = 0;

void __init_stack_check_guard(void)
{
  UINT64  Guard;
  GetRandomNumber64(&Guard);
  __stack_chk_guard = (UINTN)Guard;
}

void __stack_chk_fail()
{
  DEBUG ((EFI_D_ERROR, "\n!!! stack overflow check failed in stack protector!!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

RETURN_STATUS
EFIAPI
StackCheckLibConstructor(
  VOID
  )
{
  __init_stack_check_guard();
  return RETURN_SUCCESS;
}