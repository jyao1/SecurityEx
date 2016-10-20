/** @file

  Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include <PiDxe.h>

#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/CpuLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiCpuLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/PageTableLib.h>

#include <Library/HobLib.h>
#include <Guid/HobList.h>
#include <Guid/MemoryAllocationHob.h>

/**
  Initialize NULL address protection.
**/
EFI_STATUS
InitNullPointerProtection (
  VOID
  )
{
  EFI_STATUS  Status;
  DEBUG((EFI_D_INFO, "InitNullPointerProtection ...\n"));
  Status = SetMemoryPageAttributes(
             NULL,
             0,
             EFI_PAGES_TO_SIZE(1),
             EFI_MEMORY_RP,
             AllocatePages
             );
  DEBUG((EFI_D_INFO, "SetMemoryPageAttributes - %r\n", Status));
  DEBUG((EFI_D_INFO, "InitNullPointerProtection Done\n"));
  return Status;
}

#if defined (MDE_CPU_IA32)

///
/// Page Table Entry
///
#define IA32_PG_P                   BIT0
#define IA32_PG_RW                  BIT1
#define IA32_PG_U                   BIT2
#define IA32_PG_WT                  BIT3
#define IA32_PG_CD                  BIT4
#define IA32_PG_A                   BIT5
#define IA32_PG_D                   BIT6
#define IA32_PG_PS                  BIT7
#define IA32_PG_PAT_2M              BIT12
#define IA32_PG_PAT_4K              IA32_PG_PS
#define IA32_PG_PMNT                BIT62
#define IA32_PG_NX                  BIT63

#define PAGE_ATTRIBUTE_BITS         (IA32_PG_RW | IA32_PG_P)
//
// Bits 1, 2, 5, 6 are reserved in the IA32 PAE PDPTE
// X64 PAE PDPTE does not have such restriction
//
#define IA32_PAE_PDPTE_ATTRIBUTE_BITS    (IA32_PG_P)

VOID
CreateIa32Paging(
  VOID
  )
{
  VOID    *PageTable;
  UINT64  *Pte;
  UINTN   Index;

  PageTable = AllocatePages(5);
  ASSERT(PageTable != NULL);

  Pte = (UINT64*)PageTable;

  //
  // Zero out all page table entries first
  //
  ZeroMem(Pte, EFI_PAGES_TO_SIZE(1));

  //
  // Set Page Directory Pointers
  //
  for (Index = 0; Index < 4; Index++) {
    Pte[Index] = (UINTN)PageTable + EFI_PAGE_SIZE * (Index + 1) + (IA32_PAE_PDPTE_ATTRIBUTE_BITS);
  }
  Pte += EFI_PAGE_SIZE / sizeof(*Pte);

  //
  // Fill in Page Directory Entries
  //
  for (Index = 0; Index < EFI_PAGE_SIZE * 4 / sizeof(*Pte); Index++) {
    Pte[Index] = (Index << 21) | IA32_PG_PS | PAGE_ATTRIBUTE_BITS;
  }
  AsmWriteCr3((UINTN)PageTable);
  AsmWriteCr4(AsmReadCr4() | BIT5);
  AsmWriteCr0(AsmReadCr0() | BIT31);
}
#endif

/**
  Initialize null pointer protection.

  @param ImageHandle     Image handle this driver.
  @param SystemTable     Pointer to the System Table.

  @retval EFI_SUCCESS           Thread can be successfully created
  @retval EFI_OUT_OF_RESOURCES  Cannot allocate protocol data structure
  @retval EFI_DEVICE_ERROR      Cannot create the thread

**/
EFI_STATUS
EFIAPI
NullPointerProtectionEntrypoint(
  IN EFI_HANDLE                            ImageHandle,
  IN EFI_SYSTEM_TABLE                      *SystemTable
  )
{
#if defined (MDE_CPU_IA32)
  if (AsmReadCr3() == 0) {
    CreateIa32Paging();
  }
#endif

  if (FeaturePcdGet(PcdNullPointerProtection)) {
    //
    // NULL address protection
    //
    InitNullPointerProtection();
  }
  return EFI_SUCCESS;
}
