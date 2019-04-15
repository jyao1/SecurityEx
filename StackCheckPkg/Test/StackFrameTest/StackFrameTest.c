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

VOID
TestA (
  UINTN Index
  )
{
  CHAR16   Buffer[10];

  // NOTE: Some simple buffer overflow may be caught by C4789.
  //       E.g if Index is an immediate value

  Buffer[Index] = 1;
}

EFI_STATUS
EFIAPI
StackFrameTestInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  TestA (10);

  return EFI_SUCCESS;
}