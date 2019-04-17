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
#include <Library/UefiBootServicesTableLib.h>
#include "CfgTest.h"

EFI_GUID gCfgTestProtocolGuid = CFG_TEST_PROTOCOL_GUID;

CFG_TEST_PROTOCOL  *mCfgTestProtocol;

VOID
EFIAPI
CfgTest (
  VOID
  )
{
  EXTERNAL_FUNC Func;

  Func = (EXTERNAL_FUNC)((UINTN)mCfgTestProtocol->ExternFunc);
  Func ();

  Func = (EXTERNAL_FUNC)((UINTN)mCfgTestProtocol->ExternFunc + 1);
  Func ();
}

EFI_STATUS
EFIAPI
CfgTestAgentInitialize(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS   Status;

  Status = gBS->LocateProtocol (
                  &gCfgTestProtocolGuid,
                  NULL,
                  &mCfgTestProtocol
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  CfgTest ();

  return EFI_SUCCESS;
}
