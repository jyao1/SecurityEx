/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/DebugLib.h>

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
ExecDataSectionEntrypoint(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  TEST_FUNC  TestFunc;

  TestFunc = (TEST_FUNC)(UINTN)mTestCode;
  TestFunc();
  return EFI_SUCCESS;
}
