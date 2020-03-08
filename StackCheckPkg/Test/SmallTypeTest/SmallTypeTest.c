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

UINT8
TestA (
  VOID
  )
{
  UINTN   Data = 0xFFFFFFFF;
  UINT8   Data8 = 0;

  //
  // NOTE: warning C4244: '=': conversion from 'UINTN' to 'UINT8', possible loss of data
  //       It can only catch data without cast - Data8 = (Data >> 8);
  // Data8 = (Data >> 8);

  Data8 = (CHAR8)(Data >> 8);
  //
  // NOTE: Using type case cannot resolve the error.
  //       Need use explicit data truncate - (CHAR8)((Data >> 8) & 0xFF);
  //
  // Data8 = (CHAR8)((Data >> 8) & 0xFF);
  return Data8;
}

INT32
TestB (
  INT32  Test
  )
{
  INT32 Data = 0x7fffffff;
  Data += Test;
  return Data;
}

EFI_STATUS
EFIAPI
SmallTypeTestInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  TestA ();

  TestB (3);

  return EFI_SUCCESS;
}