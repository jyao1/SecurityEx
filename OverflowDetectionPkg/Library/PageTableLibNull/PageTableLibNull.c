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
#include <Library/PageTableLib.h>
#include <Library/DebugLib.h>

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
//  DEBUG((EFI_D_INFO, "SetMemoryPageAttributes: 0x%lx - 0x%lx (0x%lx)\n", BaseAddress, Length, Attributes));
  return RETURN_UNSUPPORTED;
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
//  DEBUG((EFI_D_INFO, "ClearMemoryPageAttributes: 0x%lx - 0x%lx (0x%lx)\n", BaseAddress, Length, Attributes));
  return RETURN_UNSUPPORTED;
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
//  DEBUG((EFI_D_INFO, "GetMemoryPageAttributes: 0x%lx\n", BaseAddress));
  if (Attributes != NULL) {
    *Attributes = 0;
  }
  if (PageSize != NULL) {
    *PageSize = SIZE_4GB;
  }
  return RETURN_SUCCESS;
}
