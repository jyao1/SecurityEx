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


#define ARRAY1_NUM  256
#define ARRAY2_NUM  256

UINT8 Array1[ARRAY1_NUM];
UINT8 Array2[ARRAY1_NUM];

UINT8
TestA (
  IN UINTN  UntrustedIndex
  )
{
  UINT8  Value;
  UINT8  Value2 = 0;

  if (UntrustedIndex < ARRAY1_NUM) {
    Value = Array1[UntrustedIndex];
    Value2 = Array2[Value * 64];
  }
  return Value2;
}

EFI_STATUS
EFIAPI
SideChannelTestInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  CopyMem (Array1, SystemTable, sizeof(Array1));
  CopyMem (Array2, SystemTable, sizeof(Array2));
  return (UINTN)TestA ((UINTN)ImageHandle);
}