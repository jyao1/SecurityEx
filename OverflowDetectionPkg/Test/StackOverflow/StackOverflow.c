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

VOID
DumpArchStatus(
  VOID
  );

typedef
VOID
(*TEST_FUNC) (
  VOID
  );

UINT8  mTestCode[] = {
  0x50,       // push  rax
  0xEB, 0xFD, // jmp   $ - 1
};

EFI_STATUS
EFIAPI
StackOverflowEntrypoint(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  TEST_FUNC  TestFunc;

  DumpArchStatus();

  TestFunc = (TEST_FUNC)(UINTN)mTestCode;
  TestFunc();
  return EFI_SUCCESS;
}
