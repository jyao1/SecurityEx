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

VOID
EFIAPI
ExternFunc (
  VOID
  );

VOID
EFIAPI
ExternFunc2 (
  VOID
  );

EFI_GUID gCfgTestProtocolGuid = CFG_TEST_PROTOCOL_GUID;

CFG_TEST_PROTOCOL  mCfgTestProtocol = {
  ExternFunc,
  ExternFunc2
};

VOID
EFIAPI
CfgTest (
  VOID
  )
{
  EXTERNAL_FUNC Func;

  Func = (EXTERNAL_FUNC)((UINTN)ExternFunc);
  Func ();

  //Func = (EXTERNAL_FUNC)((UINTN)ExternFunc + 1);
  //Func ();
}

EFI_STATUS
EFIAPI
CfgTestInitialize(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;

  CfgTest ();

  Handle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &Handle,
                  &gCfgTestProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mCfgTestProtocol
                  );

  return EFI_SUCCESS;
}
