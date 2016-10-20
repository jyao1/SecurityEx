/** @file

Copyright (c) 2012, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/CpuLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PageTableLib.h>
#include <Library/DebugLib.h>

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

#define PAGE_ATTRIBUTE_BITS         (IA32_PG_D | IA32_PG_A | IA32_PG_U | IA32_PG_RW | IA32_PG_P)
//
// Bits 1, 2, 5, 6 are reserved in the IA32 PAE PDPTE
// X64 PAE PDPTE does not have such restriction
//
#define IA32_PAE_PDPTE_ATTRIBUTE_BITS    (IA32_PG_P)

#define PAGE_PROGATE_BITS           (IA32_PG_NX | PAGE_ATTRIBUTE_BITS)

#define PAGING_4K_MASK  0xFFF
#define PAGING_2M_MASK  0x1FFFFF
#define PAGING_1G_MASK  0x3FFFFFFF

#define PAGING_PAE_INDEX_MASK  0x1FF

#define PAGING_4K_ADDRESS_MASK_64 0x000FFFFFFFFFF000ull
#define PAGING_2M_ADDRESS_MASK_64 0x000FFFFFFFE00000ull
#define PAGING_1G_ADDRESS_MASK_64 0x000FFFFFC0000000ull

typedef enum {
  PageNone,
  Page4K,
  Page2M,
  Page1G,
} PAGE_ATTRIBUTE;

typedef struct {
  PAGE_ATTRIBUTE   Attribute;
  UINT64           Length;
  UINT64           AddressMask;
} PAGE_ATTRIBUTE_TABLE;

PAGE_ATTRIBUTE_TABLE mPageAttributeTable[] = {
  {Page4K,  SIZE_4KB, PAGING_4K_ADDRESS_MASK_64},
  {Page2M,  SIZE_2MB, PAGING_2M_ADDRESS_MASK_64},
  {Page1G,  SIZE_1GB, PAGING_1G_ADDRESS_MASK_64},
};

/**
  Return current paging context.

  @param  PagingContext     The paging context.
**/
VOID
GetCurrentPagingContext (
  IN OUT PAGE_TABLE_LIB_PAGING_CONTEXT     *PagingContext
  )
{
  UINT32                         RegEax;
  UINT32                         RegEdx;

  ZeroMem(PagingContext, sizeof(*PagingContext));
  if (sizeof(UINTN) == sizeof(UINT64)) {
    PagingContext->MachineType = IMAGE_FILE_MACHINE_X64;
  } else {
    PagingContext->MachineType = IMAGE_FILE_MACHINE_I386;
  }
  if ((AsmReadCr0 () & BIT31) != 0) {
    PagingContext->ContextData.X64.PageTableBase = (AsmReadCr3 () & PAGING_4K_ADDRESS_MASK_64);
  } else {
    PagingContext->ContextData.X64.PageTableBase = 0;
  }

  if ((AsmReadCr4 () & BIT4) != 0) {
    PagingContext->ContextData.Ia32.Attributes |= PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_PSE;
  }
  if ((AsmReadCr4 () & BIT5) != 0) {
    PagingContext->ContextData.Ia32.Attributes |= PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_PAE;
  }
  if ((AsmReadCr0 () & BIT16) != 0) {
    PagingContext->ContextData.Ia32.Attributes |= PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_WP_ENABLE;
  }

  AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
  if (RegEax > 0x80000000) {
    AsmCpuid (0x80000001, NULL, NULL, NULL, &RegEdx);
    if ((RegEdx & BIT20) != 0) {
      // XD supported
      if ((AsmReadMsr64 (0x000001A0) & BIT34) != 0) {
        // XD enabled
        if ((AsmReadMsr64 (0xC0000080) & BIT11) != 0) {
          // XD activated
          PagingContext->ContextData.Ia32.Attributes |= PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_XD_ACTIVATED;
        }
      }
    }
    if ((RegEdx & BIT26) != 0) {
      PagingContext->ContextData.Ia32.Attributes |= PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_PAGE_1G_SUPPORT;
    }
  }
}

/**
  Return length according to page attributes.

  @param  PageAttributes   The page attribute of the page entry.

  @return The length of page entry. 
**/
UINTN
PageAttributeToLength (
  IN PAGE_ATTRIBUTE  PageAttribute
  )
{
  UINTN  Index;
  for (Index = 0; Index < sizeof(mPageAttributeTable)/sizeof(mPageAttributeTable[0]); Index++) {
    if (PageAttribute == mPageAttributeTable[Index].Attribute) {
      return (UINTN)mPageAttributeTable[Index].Length;
    }
  }
  return 0;
}

/**
  Return address mask according to page attributes.

  @param  PageAttributes   The page attribute of the page entry.

  @return The address mask of page entry. 
**/
UINTN
PageAttributeToMask (
  IN PAGE_ATTRIBUTE  PageAttribute
  )
{
  UINTN  Index;
  for (Index = 0; Index < sizeof(mPageAttributeTable)/sizeof(mPageAttributeTable[0]); Index++) {
    if (PageAttribute == mPageAttributeTable[Index].Attribute) {
      return (UINTN)mPageAttributeTable[Index].AddressMask;
    }
  }
  return 0;
}

/**
  Return page table entry to match the address.

  @param  PagingContext     The paging context.
  @param  Address           The address to be checked.
  @param  PageAttributes    The page attribute of the page entry.

  @return The page entry. 
**/
VOID *
GetPageTableEntry (
  IN  PAGE_TABLE_LIB_PAGING_CONTEXT     *PagingContext,
  IN  PHYSICAL_ADDRESS                  Address,
  OUT PAGE_ATTRIBUTE                    *PageAttribute
  )
{
  UINTN                 Index1;
  UINTN                 Index2;
  UINTN                 Index3;
  UINTN                 Index4;
  UINT64                *L1PageTable;
  UINT64                *L2PageTable;
  UINT64                *L3PageTable;
  UINT64                *L4PageTable;

  ASSERT (PagingContext != NULL);

  Index4 = ((UINTN)RShiftU64 (Address, 39)) & PAGING_PAE_INDEX_MASK;
  Index3 = ((UINTN)Address >> 30) & PAGING_PAE_INDEX_MASK;
  Index2 = ((UINTN)Address >> 21) & PAGING_PAE_INDEX_MASK;
  Index1 = ((UINTN)Address >> 12) & PAGING_PAE_INDEX_MASK;

  if (PagingContext->MachineType == IMAGE_FILE_MACHINE_X64) {
    L4PageTable = (UINT64 *)(UINTN)PagingContext->ContextData.X64.PageTableBase;
    if (L4PageTable[Index4] == 0) {
      *PageAttribute = PageNone;
      return NULL;
    }

    L3PageTable = (UINT64 *)(UINTN)(L4PageTable[Index4] & PAGING_4K_ADDRESS_MASK_64);
  } else {
    ASSERT((PagingContext->ContextData.Ia32.Attributes & PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_PAE) != 0);
    L3PageTable = (UINT64 *)(UINTN)PagingContext->ContextData.Ia32.PageTableBase;
  }
  if (L3PageTable[Index3] == 0) {
    *PageAttribute = PageNone;
    return NULL;
  }
  if ((L3PageTable[Index3] & IA32_PG_PS) != 0) {
    // 1G 
    *PageAttribute = Page1G;
    return &L3PageTable[Index3];
  }

  L2PageTable = (UINT64 *)(UINTN)(L3PageTable[Index3] & PAGING_4K_ADDRESS_MASK_64);
  if (L2PageTable[Index2] == 0) {
    *PageAttribute = PageNone;
    return NULL;
  }
  if ((L2PageTable[Index2] & IA32_PG_PS) != 0) {
    // 2M 
    *PageAttribute = Page2M;
    return &L2PageTable[Index2];
  }

  // 4k
  L1PageTable = (UINT64 *)(UINTN)(L2PageTable[Index2] & PAGING_4K_ADDRESS_MASK_64);
  if ((L1PageTable[Index1] == 0) && (Address != 0)) {
    *PageAttribute = PageNone;
    return NULL;
  }
  *PageAttribute = Page4K;
  return &L1PageTable[Index1];
}

/**
  Return memory attributes of page entry.

  @param  PageEntry        The page entry.

  @return Memory attributes of page entry. 
**/
UINT64
GetAttributesFromPageEntry (
  IN  UINT64                            *PageEntry
  )
{
  UINT64  Attributes;
  Attributes = 0;
  if ((*PageEntry & IA32_PG_P) == 0) {
    Attributes |= EFI_MEMORY_RP;
  }
  if ((*PageEntry & IA32_PG_RW) == 0) {
    Attributes |= EFI_MEMORY_RO;
  }
  if ((*PageEntry & IA32_PG_NX) != 0) {
    Attributes |= EFI_MEMORY_XP;
  }
  return Attributes;
}

/**
  Modify memory attributes of page entry.

  @param  PageEntry        The page entry.
  @param  Attributes       The bit mask of attributes to modify for the memory region.
  @param  IsSet            TRUE means to set attributes. FALSE means to clear attributes.
  @param  IsModified       TRUE means page table modified. FALSE means page table not modified.
**/
VOID
ConvertPageEntryAttribute (
  IN  UINT64                            *PageEntry,
  IN  UINT64                            Attributes,
  IN  BOOLEAN                           IsSet,
  OUT BOOLEAN                           *IsModified
  )
{
  UINT64  CurrentPageEntry;
  UINT64  NewPageEntry;

  CurrentPageEntry = *PageEntry;
  NewPageEntry = CurrentPageEntry;
  if ((Attributes & EFI_MEMORY_RP) != 0) {
    if (IsSet) {
      NewPageEntry &= ~(UINT64)IA32_PG_P;
    } else {
      NewPageEntry |= IA32_PG_P;
    }
  }
  if ((Attributes & EFI_MEMORY_RO) != 0) {
    if (IsSet) {
      NewPageEntry &= ~(UINT64)IA32_PG_RW;
    } else {
      NewPageEntry |= IA32_PG_RW;
    }
  }
  if ((Attributes & EFI_MEMORY_XP) != 0) {
    if (IsSet) {
      NewPageEntry |= IA32_PG_NX;
    } else {
      NewPageEntry &= ~IA32_PG_NX;
    }
  }
  *PageEntry = NewPageEntry;
  if (CurrentPageEntry != NewPageEntry) {
    *IsModified = TRUE;
    DEBUG ((EFI_D_INFO, "ConvertPageEntryAttribute 0x%lx", CurrentPageEntry));
    DEBUG ((EFI_D_INFO, "->0x%lx\n", NewPageEntry));
  } else {
    *IsModified = FALSE;
  }
}

/**
  This function returns if there is need to split page entry.
  
  @param  BaseAddress      The base address to be checked.
  @param  Length           The length to be checked.
  @param  PageEntry        The page entry to be checked.
  @param  PageAttribute    The page attribute of the page entry.
  
  @retval SplitAttributes on if there is need to split page entry.
**/
PAGE_ATTRIBUTE
NeedSplitPage (
  IN  PHYSICAL_ADDRESS                  BaseAddress,
  IN  UINT64                            Length,
  IN  UINT64                            *PageEntry,
  IN  PAGE_ATTRIBUTE                    PageAttribute
  )
{
  UINT64                PageEntryLength;

  PageEntryLength = PageAttributeToLength (PageAttribute);

  if (((BaseAddress & (PageEntryLength - 1)) == 0) && (Length >= PageEntryLength)) {
    return PageNone;
  }

  if (((BaseAddress & PAGING_2M_MASK) != 0) || (Length < SIZE_2MB)) {
    return Page4K;
  }

  return Page2M;
}

/**
  This function splits one page entry to small page entries.
  
  @param  PageEntry         The page entry to be splitted.
  @param  PageAttribute     The page attribute of the page entry.
  @param  SplitAttribute    How to split the page entry.
  @param  AllocatePagesFunc If page split is needed, this function is used to allocate more pages.

  @retval RETURN_SUCCESS            The page entry is splitted.
  @retval RETURN_UNSUPPORTED        The page entry does not support to be splitted.
  @retval RETURN_OUT_OF_RESOURCES   No resource to split page entry.
**/
RETURN_STATUS
SplitPage (
  IN  UINT64                            *PageEntry,
  IN  PAGE_ATTRIBUTE                    PageAttribute,
  IN  PAGE_ATTRIBUTE                    SplitAttribute,
  IN  PAGE_TABLE_LIB_ALLOCATE_PAGES     AllocatePagesFunc
  )
{
  UINT64   BaseAddress;
  UINT64   *NewPageEntry;
  UINTN    Index;

  ASSERT (PageAttribute == Page2M || PageAttribute == Page1G);

  ASSERT (AllocatePagesFunc != NULL);

  if (PageAttribute == Page2M) {
    //
    // Split 2M to 4K
    //
    ASSERT (SplitAttribute == Page4K);
    if (SplitAttribute == Page4K) {
      NewPageEntry = AllocatePagesFunc (1);
      DEBUG ((EFI_D_INFO, "Split - 0x%x\n", NewPageEntry));
      if (NewPageEntry == NULL) {
        return RETURN_OUT_OF_RESOURCES;
      }
      BaseAddress = *PageEntry & PAGING_2M_ADDRESS_MASK_64;
      for (Index = 0; Index < SIZE_4KB / sizeof(UINT64); Index++) {
        NewPageEntry[Index] = BaseAddress + SIZE_4KB * Index + ((*PageEntry) & PAGE_PROGATE_BITS);
      }
      (*PageEntry) = (UINT64)(UINTN)NewPageEntry + ((*PageEntry) & PAGE_PROGATE_BITS);
      return RETURN_SUCCESS;
    } else {
      return RETURN_UNSUPPORTED;
    }
  } else if (PageAttribute == Page1G) {
    //
    // Split 1G to 2M
    // No need support 1G->4K directly, we should use 1G->2M, then 2M->4K to get more compact page table.
    //
    ASSERT (SplitAttribute == Page2M || SplitAttribute == Page4K);
    if ((SplitAttribute == Page2M || SplitAttribute == Page4K)) {
      NewPageEntry = AllocatePagesFunc (1);
      DEBUG ((EFI_D_INFO, "Split - 0x%x\n", NewPageEntry));
      if (NewPageEntry == NULL) {
        return RETURN_OUT_OF_RESOURCES;
      }
      BaseAddress = *PageEntry & PAGING_1G_ADDRESS_MASK_64;
      for (Index = 0; Index < SIZE_4KB / sizeof(UINT64); Index++) {
        NewPageEntry[Index] = BaseAddress + SIZE_2MB * Index + IA32_PG_PS + ((*PageEntry) & PAGE_PROGATE_BITS);
      }
      (*PageEntry) = (UINT64)(UINTN)NewPageEntry + ((*PageEntry) & PAGE_PROGATE_BITS);
      return RETURN_SUCCESS;
    } else {
      return RETURN_UNSUPPORTED;
    }
  } else {
    return RETURN_UNSUPPORTED;
  }
}

/**
  This function modifies the page attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  Caller should make sure BaseAddress and Length is at page boundary.

  @param  PagingContext     The paging context. NULL means get page table from current CPU context.
  @param  BaseAddress       The physical address that is the start address of a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        The bit mask of attributes to modify for the memory region.
  @param  IsSet             TRUE means to set attributes. FALSE means to clear attributes.
  @param  AllocatePagesFunc If page split is needed, this function is used to allocate more pages.
                            NULL mean page split is unsupported.
  @param  IsSplitted        TRUE means page table splitted. FALSE means page table not splitted.
  @param  IsModified        TRUE means page table modified. FALSE means page table not modified.

  @retval RETURN_SUCCESS           The attributes were modified for the memory region.
  @retval RETURN_ACCESS_DENIED     The attributes for the memory resource range specified by
                                   BaseAddress and Length cannot be modified.
  @retval RETURN_INVALID_PARAMETER Length is zero.
                                   Attributes specified an illegal combination of attributes that
                                   cannot be set together.
  @retval RETURN_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                   the memory resource range.
  @retval RETURN_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                   resource range specified by BaseAddress and Length.
                                   The bit mask of attributes is not support for the memory resource
                                   range specified by BaseAddress and Length.
**/
RETURN_STATUS
ConvertMemoryPageAttributes (
  IN  PAGE_TABLE_LIB_PAGING_CONTEXT     *PagingContext OPTIONAL,
  IN  PHYSICAL_ADDRESS                  BaseAddress,
  IN  UINT64                            Length,
  IN  UINT64                            Attributes,
  IN  BOOLEAN                           IsSet,
  IN  PAGE_TABLE_LIB_ALLOCATE_PAGES     AllocatePagesFunc OPTIONAL,
  OUT BOOLEAN                           *IsSplitted,  OPTIONAL
  OUT BOOLEAN                           *IsModified   OPTIONAL
  )
{
  PAGE_TABLE_LIB_PAGING_CONTEXT     CurrentPagingContext;
  UINT64                            *PageEntry;
  PAGE_ATTRIBUTE                    PageAttribute;
  UINTN                             PageEntryLength;
  PAGE_ATTRIBUTE                    SplitAttribute;
  RETURN_STATUS                     Status;
  BOOLEAN                           IsEntryModified;

  if (PagingContext == NULL) {
    GetCurrentPagingContext (&CurrentPagingContext);
  } else {
    CopyMem (&CurrentPagingContext, PagingContext, sizeof(CurrentPagingContext));
  }
  switch(CurrentPagingContext.MachineType) {
  case IMAGE_FILE_MACHINE_I386:
    ASSERT (CurrentPagingContext.ContextData.Ia32.PageTableBase != 0);
    break;
  case IMAGE_FILE_MACHINE_X64:
    ASSERT (CurrentPagingContext.ContextData.X64.PageTableBase != 0);
    break;
  default:
    ASSERT(FALSE);
    break;
  }

  ASSERT (Attributes != 0);
  ASSERT ((Attributes & ~(EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_XP)) == 0);

  ASSERT ((BaseAddress & (SIZE_4KB - 1)) == 0);
  ASSERT ((Length & (SIZE_4KB - 1)) == 0);
  
  if (Length == 0) {
    return RETURN_INVALID_PARAMETER;
  }

//  DEBUG ((EFI_D_ERROR, "ConvertMemoryPageAttributes(%x) - %016lx, %016lx, %02lx\n", IsSet, BaseAddress, Length, Attributes));

  if (IsSplitted != NULL) {
    *IsSplitted = FALSE;
  }
  if (IsModified != NULL) {
    *IsModified = FALSE;
  }
  
  //
  // Below logic is to check 2M/4K page to make sure we donot waist memory.
  //
  while (Length != 0) {
    PageEntry = GetPageTableEntry (&CurrentPagingContext, BaseAddress, &PageAttribute);
    if (PageEntry == NULL) {
      return RETURN_UNSUPPORTED;
    }
    PageEntryLength = PageAttributeToLength (PageAttribute);
    SplitAttribute = NeedSplitPage (BaseAddress, Length, PageEntry, PageAttribute);
    if (SplitAttribute == PageNone) {
      ConvertPageEntryAttribute (PageEntry, Attributes, IsSet, &IsEntryModified);
      if (IsEntryModified) {
        if (IsModified != NULL) {
          *IsModified = TRUE;
        }
      }
      //
      // Convert success, move to next
      //
      BaseAddress += PageEntryLength;
      Length -= PageEntryLength;
    } else {
      if (AllocatePagesFunc == NULL) {
        return RETURN_UNSUPPORTED;
      }
      Status = SplitPage (PageEntry, PageAttribute, SplitAttribute, AllocatePagesFunc);
      if (RETURN_ERROR (Status)) {
        return RETURN_UNSUPPORTED;
      }
      if (IsSplitted != NULL) {
        *IsSplitted = TRUE;
      }
      if (IsModified != NULL) {
        *IsModified = TRUE;
      }
      //
      // Just split current page
      // Convert success in next around
      //
    }
  }

  return RETURN_SUCCESS;
}

/**
  This function sets the page attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  Caller should make sure BaseAddress and Length is at page boundary.

  Caller need guarentee the TPL <= TPL_NOTIFY, if there is split page request.

  @param  PagingContext     The paging context. NULL means get page table from current CPU context.
  @param  BaseAddress       The physical address that is the start address of a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        The bit mask of attributes to set for the memory region.
  @param  AllocatePagesFunc If page split is needed, this function is used to allocate more pages.
                            NULL mean page split is unsupported.

  @retval RETURN_SUCCESS           The attributes were set for the memory region.
  @retval RETURN_ACCESS_DENIED     The attributes for the memory resource range specified by
                                   BaseAddress and Length cannot be modified.
  @retval RETURN_INVALID_PARAMETER Length is zero.
                                   Attributes specified an illegal combination of attributes that
                                   cannot be set together.
  @retval RETURN_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                   the memory resource range.
  @retval RETURN_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                   resource range specified by BaseAddress and Length.
                                   The bit mask of attributes is not support for the memory resource
                                   range specified by BaseAddress and Length.
**/
RETURN_STATUS
EFIAPI
SetMemoryPageAttributes (
  IN  PAGE_TABLE_LIB_PAGING_CONTEXT     *PagingContext OPTIONAL,
  IN  PHYSICAL_ADDRESS                  BaseAddress,
  IN  UINT64                            Length,
  IN  UINT64                            Attributes,
  IN  PAGE_TABLE_LIB_ALLOCATE_PAGES     AllocatePagesFunc OPTIONAL
  )
{
  RETURN_STATUS  Status;
  BOOLEAN        IsModified;
  BOOLEAN        IsSplitted;

//  DEBUG((EFI_D_INFO, "SetMemoryPageAttributes: 0x%lx - 0x%lx (0x%lx)\n", BaseAddress, Length, Attributes));
  Status = ConvertMemoryPageAttributes (PagingContext, BaseAddress, Length, Attributes, TRUE, AllocatePagesFunc, &IsSplitted, &IsModified);
  if (!EFI_ERROR(Status)) {
    if ((PagingContext == NULL) && IsModified) {
      //
      // Flush TLB as last step
      //
      CpuFlushTlb();
    }
  }
  
  return Status;
}

/**
  This function clears the page attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  Caller should make sure BaseAddress and Length is at page boundary.

  Caller need guarentee the TPL <= TPL_NOTIFY, if there is split page request.

  @param  PagingContext     The paging context. NULL means get page table from current CPU context.
  @param  BaseAddress       The physical address that is the start address of a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        The bit mask of attributes to set for the memory region.
  @param  AllocatePagesFunc If page split is needed, this function is used to allocate more pages.
                            NULL mean page split is unsupported.

  @retval RETURN_SUCCESS           The attributes were cleared for the memory region.
  @retval RETURN_ACCESS_DENIED     The attributes for the memory resource range specified by
                                   BaseAddress and Length cannot be modified.
  @retval RETURN_INVALID_PARAMETER Length is zero.
                                   Attributes specified an illegal combination of attributes that
                                   cannot be set together.
  @retval RETURN_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                   the memory resource range.
  @retval RETURN_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                   resource range specified by BaseAddress and Length.
                                   The bit mask of attributes is not support for the memory resource
                                   range specified by BaseAddress and Length.
**/
RETURN_STATUS
EFIAPI
ClearMemoryPageAttributes (
  IN  PAGE_TABLE_LIB_PAGING_CONTEXT     *PagingContext OPTIONAL,
  IN  PHYSICAL_ADDRESS                  BaseAddress,
  IN  UINT64                            Length,
  IN  UINT64                            Attributes,
  IN  PAGE_TABLE_LIB_ALLOCATE_PAGES     AllocatePagesFunc OPTIONAL
  )
{
  RETURN_STATUS  Status;
  BOOLEAN        IsModified;
  BOOLEAN        IsSplitted;

//  DEBUG((EFI_D_INFO, "ClearMemoryPageAttributes: 0x%lx - 0x%lx (0x%lx)\n", BaseAddress, Length, Attributes));
  Status = ConvertMemoryPageAttributes (PagingContext, BaseAddress, Length, Attributes, FALSE, AllocatePagesFunc, &IsSplitted, &IsModified);
  if (!EFI_ERROR(Status)) {
    if ((PagingContext == NULL) && IsModified) {
      //
      // Flush TLB as last step
      //
      CpuFlushTlb();
    }
  }
  
  return Status;
}

/**
  This function return the page attributes for the memory region specified by BaseAddress.

  Caller should make sure BaseAddress is at page boundary.

  @param  PagingContext     The paging context. NULL means get page table from current CPU context.
  @param  BaseAddress       The physical address that is the start address of a memory region.
  @param  Attributes        The bit mask of attributes of the memory region.
  @param  PageSize          The size of the pages which contains the BaseAddress.

  @retval RETURN_SUCCESS           The Attributes and PageSize is returned.
  @retval RETURN_INVALID_PARAMETER Both Attributes and PageSize are zero.
  @retval RETURN_NOT_FOUND         The processor does not setup paging for BaseAddress.
**/
RETURN_STATUS
EFIAPI
GetMemoryPageAttributes (
  IN  PAGE_TABLE_LIB_PAGING_CONTEXT     *PagingContext OPTIONAL,
  IN  PHYSICAL_ADDRESS                  BaseAddress,
  OUT UINT64                            *Attributes,
  OUT UINT64                            *PageSize
  )
{
  PAGE_TABLE_LIB_PAGING_CONTEXT     CurrentPagingContext;
  PAGE_ATTRIBUTE                    PageAttribute;
  UINT64                            *PageEntry;

//  DEBUG((EFI_D_INFO, "GetMemoryPageAttributes: 0x%lx\n", BaseAddress));
  if (PagingContext == NULL) {
    GetCurrentPagingContext (&CurrentPagingContext);
  } else {
    CopyMem (&CurrentPagingContext, PagingContext, sizeof(CurrentPagingContext));
  }
  switch(CurrentPagingContext.MachineType) {
  case IMAGE_FILE_MACHINE_I386:
    ASSERT (CurrentPagingContext.ContextData.Ia32.PageTableBase != 0);
    break;
  case IMAGE_FILE_MACHINE_X64:
    ASSERT (CurrentPagingContext.ContextData.X64.PageTableBase != 0);
    break;
  default:
    ASSERT(FALSE);
    break;
  }

  if (Attributes == NULL && PageSize == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  ASSERT((BaseAddress & (SIZE_4KB - 1)) == 0);

  PageEntry = GetPageTableEntry(&CurrentPagingContext, BaseAddress, &PageAttribute);
  if (PageEntry == NULL) {
    return RETURN_NOT_FOUND;
  }

  if (Attributes != NULL) {
    *Attributes = 0;
    if ((*PageEntry & IA32_PG_NX) != 0) {
      *Attributes |= EFI_MEMORY_XP;
    }
    if ((*PageEntry & IA32_PG_RW) == 0) {
      *Attributes |= EFI_MEMORY_RO;
    }
    if ((*PageEntry & IA32_PG_P) == 0) {
      *Attributes |= EFI_MEMORY_RP;
    }
  }

  if (PageSize != NULL) {
    *PageSize = PageAttributeToLength(PageAttribute);
  }

  return RETURN_SUCCESS;
}
