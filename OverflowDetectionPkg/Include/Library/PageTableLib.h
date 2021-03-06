/** @file

Copyright (c) 2012, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _PAGE_TABLE_LIB_H_
#define _PAGE_TABLE_LIB_H_

#include <IndustryStandard/PeImage.h>

#define PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_PSE              BIT0
#define PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_PAE              BIT1
#define PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_PAGE_1G_SUPPORT  BIT2
#define PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_WP_ENABLE        BIT30
#define PAGE_TABLE_LIB_PAGING_CONTEXT_IA32_X64_ATTRIBUTES_XD_ACTIVATED     BIT31
// Other bits are reserved for future use
typedef struct {
  UINT32  PageTableBase;
  UINT32  Reserved;
  UINT32  Attributes;
} PAGE_TABLE_LIB_PAGING_CONTEXT_IA32;

typedef struct {
  UINT64  PageTableBase;
  UINT32  Attributes;
} PAGE_TABLE_LIB_PAGING_CONTEXT_X64;

typedef union {
  PAGE_TABLE_LIB_PAGING_CONTEXT_IA32  Ia32;
  PAGE_TABLE_LIB_PAGING_CONTEXT_X64   X64;
} PAGE_TABLE_LIB_PAGING_CONTEXT_DATA;

typedef struct {
  //
  // PE32+ Machine type for EFI images
  //
  // #define IMAGE_FILE_MACHINE_I386            0x014c
  // #define IMAGE_FILE_MACHINE_X64             0x8664
  //
  UINT16                                 MachineType;
  PAGE_TABLE_LIB_PAGING_CONTEXT_DATA     ContextData;
} PAGE_TABLE_LIB_PAGING_CONTEXT;

/**
  Allocates one or more 4KB pages for page table.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
typedef
VOID *
(EFIAPI *PAGE_TABLE_LIB_ALLOCATE_PAGES) (
  IN UINTN  Pages
  );

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
  );

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
  );

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
  );

#endif
