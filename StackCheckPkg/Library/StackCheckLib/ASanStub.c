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
#include <Library/MemoryAllocationLib.h>

//
// https://github.com/OP-TEE/optee_os/blob/master/core/kernel/asan.c
//

VOID __asan_init ()
{
  return ;
}

VOID __asan_version_mismatch_check_v8 ()
{
  return ;
}

UINTN __asan_stack_malloc_1 (UINTN Size)
{
  return 0;
}

VOID __asan_report_store1 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_store1 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

VOID __asan_report_store2 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_store2 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

VOID __asan_report_store4 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_store4 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

VOID __asan_report_store8 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_store8 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
}

VOID __asan_report_load1 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_load1 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
}

VOID __asan_report_load2 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_load2 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
}

VOID __asan_report_load4 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_load4 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
}

VOID __asan_report_load8 (UINTN Address)
{
  DEBUG ((EFI_D_ERROR, "\n!!! __asan_report_load8 - 0x%x!!!\n", Address));
  ASSERT (FALSE);

  CpuDeadLoop();
}

UINTN __asan_shadow_memory_dynamic_address = 0x0;
INT32 __asan_option_detect_stack_use_after_return = 0x0;

#define SHADOW_MEM_SIZE  SIZE_1MB

VOID
EFIAPI
ASanLibConstructor(
  VOID
  )
{
  UINTN ShadowAddr;
  ShadowAddr = (UINTN)AllocatePool (SHADOW_MEM_SIZE);

  //
  // We need to make sure:
  // (Address >> 3) + __asan_shadow_memory_dynamic_address is in [ShadowAddr, ShadowAddr + SHADOW_MEM_SIZE)
  // Here Address is in Stack
  //
  __asan_shadow_memory_dynamic_address = ShadowAddr + (SHADOW_MEM_SIZE / 2) - ((UINTN)&ShadowAddr>> 3);
  DEBUG ((DEBUG_INFO, "ShadowAddr - %p\n", ShadowAddr));
  DEBUG ((DEBUG_INFO, "Stack - %p\n", &ShadowAddr));
  DEBUG ((DEBUG_INFO, "__asan_shadow_memory_dynamic_address - %p\n", __asan_shadow_memory_dynamic_address));
}
