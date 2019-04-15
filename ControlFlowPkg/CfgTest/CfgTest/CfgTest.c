/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
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

typedef
VOID
(EFIAPI *EXTERNAL_FUNC) (
  VOID
  );

VOID
EFIAPI
ExternFunc (
  VOID
  )
{
}


VOID
EFIAPI
CfgTest (
  VOID
  )
{
  EXTERNAL_FUNC Func;

  Func = ExternFunc;

  Func ();
}

EFI_STATUS
EFIAPI
CfgTestInitialize(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  CfgTest ();

  return EFI_SUCCESS;
}
