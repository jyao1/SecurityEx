/**

Copyright (c) 2007, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php        

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiDxe.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

UINTN
TestA (
  UINTN Index
  )
{
  UINTN  Data;

  // NOTE: Some simple unitialization can be caught by C4700
  //       e.g. without conditional check

  if (Index > 10) {
    Data = 0;
  }

  Data ++;

  return Data;
}

EFI_STATUS
EFIAPI
UninitializedVariableTestInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  TestA (0);

  return EFI_SUCCESS;
}