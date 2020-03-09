/** @file
  Entry point library instance to a UEFI application.

Copyright (c) 2007 - 2010, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffLib.h>
#include <Protocol/LoadedImage.h>
#include "PeLoadConfiguration.h"
#include "CfgProtocol.h"

#if defined(__GNUC__) || defined(__clang__)
  #define GLOBAL_USED __attribute__((used))
#else
  #define GLOBAL_USED
#endif

GLOBAL_USED
VOID
EFIAPI
MyTrap (
  VOID
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! cfi check fail !!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
}

RETURN_STATUS
EFIAPI
CfgLibConstructor(
  VOID
  )
{
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
CfgLibDestructor(
  VOID
  )
{
  return RETURN_SUCCESS;
}
