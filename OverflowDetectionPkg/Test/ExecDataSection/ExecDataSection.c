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

typedef
VOID
(*TEST_FUNC) (
  VOID
  );

UINT8  mTestCode[] = {
  0xEB, 0xFE,
};

EFI_STATUS
EFIAPI
SmmReadyToBootCallback (
  IN CONST EFI_GUID                       *Protocol,
  IN VOID                                 *Interface,
  IN EFI_HANDLE                           Handle
  )
{
  TEST_FUNC  TestFunc;

  TestFunc = (TEST_FUNC)(UINTN)mTestCode;
  TestFunc();
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ExecDataSectionEntrypoint(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS  Status;
  VOID        *SmmReadyToBootRegistration;

  Status = gSmst->SmmRegisterProtocolNotify (
                    &gEdkiiSmmReadyToBootProtocolGuid,
                    SmmReadyToBootCallback,
                    &SmmReadyToBootRegistration
                    );
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
