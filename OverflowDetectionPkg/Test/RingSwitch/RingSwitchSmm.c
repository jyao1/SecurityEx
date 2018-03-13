/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiSmm.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include "Communication.h"

VOID
EFIAPI
RingSwitch (
  VOID
  );

EFI_GUID  mSmmTestGuid = SMM_TEST_GUID;

#define COUNT 1000

EFI_STATUS
EFIAPI
InitializeSmiPerf (
  OUT UINT64  *StartTsc,
  OUT UINT64  *EndTsc
  )
{
  UINTN                     Index;

  *StartTsc = AsmReadTsc ();
  for (Index = 0; Index < COUNT; Index++) {
    RingSwitch();
  }
  *EndTsc = AsmReadTsc ();
  
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SmmTestHandler (
  IN     EFI_HANDLE                                DispatchHandle,
  IN     CONST VOID                                *RegisterContext,
  IN OUT VOID                                      *CommBuffer,
  IN OUT UINTN                                     *CommBufferSize
  )
{
  SMM_TEST_COMMUNICATE_FUNCTION_HEADER  *SmmTestFunctionHeader;
  SMM_TEST_PERF                         *SmmTestPerf;

  SmmTestFunctionHeader = (SMM_TEST_COMMUNICATE_FUNCTION_HEADER *)CommBuffer;
  SmmTestPerf = (SMM_TEST_PERF *) SmmTestFunctionHeader->Data;

  InitializeSmiPerf (&SmmTestPerf->StartTsc, &SmmTestPerf->EndTsc);

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RingSwitchEntrypoint(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_HANDLE  SmmHandle;
  EFI_STATUS  Status;

  SmmHandle = NULL;
  Status = gSmst->SmiHandlerRegister (SmmTestHandler, &mSmmTestGuid, &SmmHandle);
  ASSERT_EFI_ERROR (Status);
  
  return EFI_SUCCESS;
}
