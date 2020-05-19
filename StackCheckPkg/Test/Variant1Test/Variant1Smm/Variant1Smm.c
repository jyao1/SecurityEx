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
#include <Library/DebugLib.h>
#include <Library/SmmServicesTableLib.h>
#include "Variant1SmmCommBuffer.h"

EFI_GUID mSmmCommGuid = VARIANT1_SMM_COMM_GUID;

CHAR8 * secret = "SMM. The Magic Words are ...";

UINT8 temp = 0; /* Used so compiler won't optimize out victim_function() */

__declspec(noinline)
VOID
victim_function (
  IN UINT64                   x,
  IN VARIANT1_SMM_COMM_BUFFER *arrays_ptr
  )
{
    if (x < arrays_ptr->array1_size) {
        temp &= arrays_ptr->array2[arrays_ptr->array1[x] * 512];
    } else {
        DEBUG ((DEBUG_INFO, "Attack!!!\n"));
    }
}

/**
  Variant1

  @param[in] DispatchHandle       - The handle of this callback, obtained when registering
  @param[in] DispatchContext      - Pointer to the EFI_SMM_SW_DISPATCH_CONTEXT
  @param[in] CommBuffer           - A pointer to a collection of data in memory that will
                                    be conveyed from a non-SMM environment into an SMM environment.
  @param[in] CommBufferSize       - The size of the CommBuffer.
**/
EFI_STATUS
EFIAPI
Variant1SmmCallback (
  IN  EFI_HANDLE                    DispatchHandle,
  IN  CONST VOID                    *DispatchContext,
  IN  OUT VOID                      *CommBuffer  OPTIONAL,
  IN  OUT UINTN                     *CommBufferSize  OPTIONAL
  )
{
  SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER  *SmmVariant1FunctionHeader;

  SmmVariant1FunctionHeader = (SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER *)CommBuffer;
  switch (SmmVariant1FunctionHeader->Function) {
  case FUNCTION_GET_SECRET_ADDRESS:
    SmmVariant1FunctionHeader->Address = (UINT64)(UINTN)secret;
    SmmVariant1FunctionHeader->Offset = 0;
    SmmVariant1FunctionHeader->ReturnStatus = EFI_SUCCESS;
    break;
  case FUNCTION_COMMUNICATION:
    victim_function (
      SmmVariant1FunctionHeader->Offset,
      (VARIANT1_SMM_COMM_BUFFER *)(UINTN)SmmVariant1FunctionHeader->Address
      );
    break;
  default:
    SmmVariant1FunctionHeader->Address = 0;
    SmmVariant1FunctionHeader->Offset = 0;
    SmmVariant1FunctionHeader->ReturnStatus = EFI_UNSUPPORTED;
    break;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Variant1SmmEntrypoint (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_HANDLE  SmmHandle;
  EFI_STATUS  Status;

  SmmHandle = NULL;
  Status = gSmst->SmiHandlerRegister (Variant1SmmCallback, &mSmmCommGuid, &SmmHandle);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
