/**

Copyright (c) 2012, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "PeLoadConfiguration.h"
#include "CfgProtocol.h"

//
// Below data structure is from guard_support.c (Microsoft Visual Studio)
//

//#pragma section(".00cfg", read)

//__declspec(allocate(".00cfg"))
//__declspec(selectany)
//volatile void * __guard_check_icall_fptr = (void *)_guard_check_icall_nop;

extern void * __guard_check_icall_fptr;

extern CFG_PROTOCOL *mCfgProtocol;

CFG_NODE *
GetCfgNode (
  IN UINTN Target
  )
{
  CFG_NODE    *CfgNode;
  LIST_ENTRY  *CfgNodeList;
  LIST_ENTRY  *Link;

  CfgNodeList = &mCfgProtocol->CfgNode;
  for (Link = CfgNodeList->ForwardLink;
       Link != CfgNodeList;
       Link = Link->ForwardLink) {
    CfgNode = BASE_CR (
                Link,
                CFG_NODE,
                Link
                );
    if ((Target >= CfgNode->ImageBase) && 
        (Target < (CfgNode->ImageBase + CfgNode->ImageSize))) {
      return CfgNode;
    }
  }

  return NULL;
}

void
__fastcall
_my_guard_check_icall (
    IN UINTN Target
    )
{
  UINTN       Index;
  UINTN       *Ptr;
  CFG_NODE    *CfgNode;

  DEBUG ((DEBUG_INFO, "_my_guard_check_icall - 0x%016lx\n", (UINT64)Target));
  CfgNode = GetCfgNode (Target);
  if (CfgNode != NULL) {
    for (Index = 0; Index < CfgNode->GuardCFFunctionCount; Index++) {
      DEBUG ((DEBUG_INFO, "Checking ... 0x%016lx\n", (UINT64)(CfgNode->GuardCFFunctionTable[Index] + CfgNode->ImageBase)));
      if ((CfgNode->GuardCFFunctionTable[Index] + CfgNode->ImageBase) == Target) {
        DEBUG ((DEBUG_INFO, "\n!!! guard check pass !!!\n"));
        return;
      }
    }
  } else {
    //
    // Check default table - gBS
    //
    DEBUG ((DEBUG_INFO, "check gBS - 0x%016lx\n", (UINT64)gBS));
    Ptr = (UINTN *)((UINTN)gBS + OFFSET_OF(EFI_BOOT_SERVICES, RaiseTPL));
    for (Index = 0; Index < (sizeof(EFI_BOOT_SERVICES) - sizeof(EFI_TABLE_HEADER))/sizeof(UINTN); Index++) {
      DEBUG ((DEBUG_INFO, "Checking ... 0x%016lx\n", (UINT64)Ptr[Index]));
      if (Ptr[Index] == Target) {
        DEBUG ((DEBUG_INFO, "\n!!! guard check pass !!!\n"));
        return;
      }
    }
  }

  DEBUG ((DEBUG_ERROR, "\n!!! guard check fail !!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
}

RETURN_STATUS
EFIAPI
UefiCfgLibConstructor(
  VOID
  );

VOID
EFIAPI
EnableReadOnlyProtection (
  IN VOID  *Buffer,
  IN UINTN Size
  );

VOID
EFIAPI
DisableReadOnlyProtection (
  IN VOID  *Buffer,
  IN UINTN Size
  );

RETURN_STATUS
EFIAPI
CfgLibConstructor(
  VOID
  )
{
  UefiCfgLibConstructor ();

#ifdef WINNT
  DisableReadOnlyProtection (&__guard_check_icall_fptr, sizeof(__guard_check_icall_fptr));
#endif
  __guard_check_icall_fptr = (void *)_my_guard_check_icall;
#ifdef WINNT
  EnableReadOnlyProtection (&__guard_check_icall_fptr, sizeof(__guard_check_icall_fptr));
#endif

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
CfgLibDestructor(
  VOID
  )
{
  CFG_NODE    *CfgNode;

  CfgNode = GetCfgNode ((UINTN)CfgLibDestructor);
  ASSERT (CfgNode != NULL);
  RemoveEntryList (&CfgNode->Link);
  return RETURN_SUCCESS;
}