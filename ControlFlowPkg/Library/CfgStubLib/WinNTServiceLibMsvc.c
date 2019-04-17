/**@file

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <stdio.h>
#include <Uefi.h>
#include <WinNtInclude.h>
#include <WinNtThunk.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>

EFI_WIN_NT_THUNK_PROTOCOL  *gWinNt;

EFI_GUID gEfiWinNtThunkProtocolGuid = EFI_WIN_NT_THUNK_PROTOCOL_GUID;

VOID
EFIAPI
EnableReadOnlyProtection (
  IN VOID  *Buffer,
  IN UINTN Size
  )
{
  BOOL  Result;
  DWORD OldProtect;
  if (gWinNt == NULL) {
    gBS->LocateProtocol (&gEfiWinNtThunkProtocolGuid, NULL, &gWinNt);
  }
  Result = gWinNt->VirtualProtect (Buffer, Size, PAGE_READONLY, &OldProtect);
  DEBUG ((DEBUG_INFO, "EnableReadOnlyProtection - %x\n", Result));
}

VOID
EFIAPI
DisableReadOnlyProtection (
  IN VOID  *Buffer,
  IN UINTN Size
  )
{
  BOOL  Result;
  DWORD OldProtect;
  if (gWinNt == NULL) {
    gBS->LocateProtocol (&gEfiWinNtThunkProtocolGuid, NULL, &gWinNt);
  }
  Result = gWinNt->VirtualProtect (Buffer, Size, PAGE_READWRITE, &OldProtect);
  DEBUG ((DEBUG_INFO, "DisableReadOnlyProtection - %x\n", Result));
}
