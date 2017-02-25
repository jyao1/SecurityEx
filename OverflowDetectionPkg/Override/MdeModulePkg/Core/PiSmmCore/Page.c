/** @file
  SMM Memory page management functions.

  Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the BSD License which accompanies this
  distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "PiSmmCore.h"
#include <Library/SmmServicesTableLib.h>
#include <Library/PageTableLib.h>


#define TRUNCATE_TO_PAGES(a)  ((a) >> EFI_PAGE_SHIFT)

LIST_ENTRY  mSmmMemoryMap = INITIALIZE_LIST_HEAD_VARIABLE (mSmmMemoryMap);

//
// For GetMemoryMap()
//

#define MEMORY_MAP_SIGNATURE   SIGNATURE_32('m','m','a','p')
typedef struct {
  UINTN           Signature;
  LIST_ENTRY      Link;

  BOOLEAN         FromStack;
  EFI_MEMORY_TYPE Type;
  UINT64          Start;
  UINT64          End;

} MEMORY_MAP;

LIST_ENTRY        gMemoryMap  = INITIALIZE_LIST_HEAD_VARIABLE (gMemoryMap);


#define MAX_MAP_DEPTH 6

///
/// mMapDepth - depth of new descriptor stack
///
UINTN         mMapDepth = 0;
///
/// mMapStack - space to use as temp storage to build new map descriptors
///
MEMORY_MAP    mMapStack[MAX_MAP_DEPTH];
UINTN         mFreeMapStack = 0;
///
/// This list maintain the free memory map list
///
LIST_ENTRY   mFreeMemoryMapEntryList = INITIALIZE_LIST_HEAD_VARIABLE (mFreeMemoryMapEntryList);

/**
  Update SMM memory map entry.

  @param[in]  Type                   The type of allocation to perform.
  @param[in]  Memory                 The base of memory address.
  @param[in]  NumberOfPages          The number of pages to allocate.
  @param[in]  AddRegion              If this memory is new added region.
**/
VOID
ConvertSmmMemoryMapEntry (
  IN EFI_MEMORY_TYPE       Type,
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages,
  IN BOOLEAN               AddRegion
  );

/**
  Internal function.  Moves any memory descriptors that are on the
  temporary descriptor stack to heap.

**/
VOID
CoreFreeMemoryMapStack (
  VOID
  );

BOOLEAN
IsMemoryTypeForHeapPageGuard (
  IN EFI_MEMORY_TYPE        MemoryType
  )
{
  UINT64 TestBit;
  
  if ((MemoryType != EfiRuntimeServicesData) && (MemoryType != EfiRuntimeServicesCode)) {
    return FALSE;
  }

  TestBit = LShiftU64 (1, MemoryType);

  if ((PcdGet64 (PcdHeapPageGuardTypeMask) & TestBit) != 0) {
    return TRUE;
  } else {
    return FALSE;
  }
}

BOOLEAN
IsAllocateTypeForHeapGuard (
  IN EFI_ALLOCATE_TYPE      Type
  )
{
  if ((Type == AllocateMaxAddress || Type == AllocateAnyPages)) {
    return TRUE;
  }
  return FALSE;
}

typedef enum {
  GuardPageTypeUnallocated,
  GuardPageTypeAllocatedUnguarded,
  GuardPageTypeGuarded,
} GUARD_PAGE_TYPE;

#define GUARD_PAGE_HEAD_SIGNATURE   SIGNATURE_32('g','h','d','0')

typedef struct {
  UINT32            Signature;
  UINT32            Reserved;
  PHYSICAL_ADDRESS  Address;
  LIST_ENTRY        Link;
} GUARD_PAGE_HEAD;

#define GUARD_PAGE_TAIL_SIGNATURE   SIGNATURE_32('g','t','a','l')

typedef GUARD_PAGE_HEAD GUARD_PAGE_TAIL;

#define GUARD_HEAD_TO_TAIL(a)   \
  ((GUARD_PAGE_TAIL *) (((CHAR8 *) (a)) + EFI_PAGES_TO_SIZE(1) - sizeof(GUARD_PAGE_TAIL)));

#define GUARD_TAIL_TO_HEAD(a)   \
  ((GUARD_PAGE_HEAD *) (((CHAR8 *) (a)) + sizeof(GUARD_PAGE_TAIL) - EFI_PAGES_TO_SIZE(1)));

GLOBAL_REMOVE_IF_UNREFERENCED LIST_ENTRY  mGuardPageList = INITIALIZE_LIST_HEAD_VARIABLE (mGuardPageList);

BOOLEAN
IsTheGuardPageGuarded(
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
  EFI_STATUS  Status;
  UINT64      Attributes;

  ASSERT((Address & (SIZE_4KB - 1)) == 0);
  if (Address == ((UINTN)&mGuardPageList & ~(SIZE_4KB - 1))) {
    // Skip the list head node.
    return FALSE;
  }

  Status = GetMemoryPageAttributes(
             NULL,
             Address,
             &Attributes,
             NULL
             );
  ASSERT_EFI_ERROR(Status);
  if ((Attributes & EFI_MEMORY_RP) == 0) {
    return FALSE;
  } else {
    return TRUE;
  }
}

VOID
UnguardTheGuardPage (
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
  ASSERT((Address & (SIZE_4KB - 1)) == 0);
  if (Address == ((UINTN)&mGuardPageList & ~(SIZE_4KB - 1))) {
    // Skip the list head node.
    return;
  }

  ClearMemoryPageAttributes (
    NULL,
    Address,
    EFI_PAGES_TO_SIZE(1),
    EFI_MEMORY_RP,
    NULL
    );
}

VOID
GuardTheGuardPage (
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
  ASSERT((Address & (SIZE_4KB - 1)) == 0);
  if (Address == ((UINTN)&mGuardPageList & ~(SIZE_4KB - 1))) {
    // Skip the list head node.
    return;
  }

  SetMemoryPageAttributes (
    NULL,
    Address,
    EFI_PAGES_TO_SIZE(1),
    EFI_MEMORY_RP,
    NULL
    );
}

VOID
DumpGuardPages (
  VOID
  )
{
  LIST_ENTRY      *Link;
  GUARD_PAGE_HEAD *GuardPageHead;
  GUARD_PAGE_TAIL *GuardPageTail;

  DEBUG((EFI_D_INFO, "DumpGuardPages - head: 0x%08x (0x%08x, 0x%08x)\n", &mGuardPageList, mGuardPageList.BackLink, mGuardPageList.ForwardLink));

  for (Link = mGuardPageList.ForwardLink; Link != &mGuardPageList; Link = Link->ForwardLink) {
    GuardPageHead = BASE_CR(Link, GUARD_PAGE_HEAD, Link);

    if (IsTheGuardPageGuarded((UINTN)GuardPageHead & ~(SIZE_4KB - 1))) {
      // Do not go through link list, the are not present.
      return;
    }

    ASSERT ((GuardPageHead->Signature == GUARD_PAGE_HEAD_SIGNATURE) || (GuardPageHead->Signature == GUARD_PAGE_TAIL_SIGNATURE));
    if (GuardPageHead->Signature == GUARD_PAGE_HEAD_SIGNATURE) {
      GuardPageTail = GUARD_HEAD_TO_TAIL(GuardPageHead);
      ASSERT(GuardPageHead->Address == (UINTN)GuardPageHead);
      ASSERT(GuardPageHead->Address == GuardPageTail->Address);
      DEBUG((EFI_D_INFO, "GUARD_HEAD: 0x%08x, 0x%08x (0x%08x, 0x%08x)\n", GuardPageHead, &GuardPageHead->Link, GuardPageHead->Link.BackLink, GuardPageHead->Link.ForwardLink));
    }
    if (GuardPageHead->Signature == GUARD_PAGE_TAIL_SIGNATURE) {
      GuardPageTail = GuardPageHead;
      GuardPageHead = GUARD_TAIL_TO_HEAD(GuardPageTail);
      ASSERT(GuardPageHead->Address == (UINTN)GuardPageHead);
      ASSERT(GuardPageHead->Address == GuardPageTail->Address);
      DEBUG((EFI_D_INFO, "GUARD_TAIL: 0x%08x, 0x%08x (0x%08x, 0x%08x)\n", GuardPageTail, &GuardPageTail->Link, GuardPageTail->Link.BackLink, GuardPageTail->Link.ForwardLink));
    }
  }
  DEBUG((EFI_D_INFO, "DumpGuardPages Done\n"));
}

VOID
CheckGuardPages(
  VOID
  )
{
  LIST_ENTRY      *Link;
  GUARD_PAGE_HEAD *GuardPageHead;
  GUARD_PAGE_TAIL *GuardPageTail;

  for (Link = mGuardPageList.ForwardLink; Link != &mGuardPageList; Link = Link->ForwardLink) {
    GuardPageHead = BASE_CR(Link, GUARD_PAGE_HEAD, Link);
      
    if (IsTheGuardPageGuarded((UINTN)GuardPageHead & ~(SIZE_4KB - 1))) {
      // No need to check, they are already page protected.
      return;
    }

    ASSERT((GuardPageHead->Signature == GUARD_PAGE_HEAD_SIGNATURE) || (GuardPageHead->Signature == GUARD_PAGE_TAIL_SIGNATURE));
    if (GuardPageHead->Signature == GUARD_PAGE_HEAD_SIGNATURE) {
      GuardPageTail = GUARD_HEAD_TO_TAIL(GuardPageHead);
      ASSERT(GuardPageHead->Address == (UINTN)GuardPageHead);
      ASSERT(GuardPageHead->Address == GuardPageTail->Address);
    }
    if (GuardPageHead->Signature == GUARD_PAGE_TAIL_SIGNATURE) {
      GuardPageTail = GuardPageHead;
      GuardPageHead = GUARD_TAIL_TO_HEAD(GuardPageTail);
      ASSERT(GuardPageHead->Address == (UINTN)GuardPageHead);
      ASSERT(GuardPageHead->Address == GuardPageTail->Address);
    }
  }
}

GUARD_PAGE_TYPE
GetGuardPageType (
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
  LIST_ENTRY      *Link;
  MEMORY_MAP      *Entry;
  GUARD_PAGE_HEAD *GuardPageHead;

  //
  // Find the entry that the covers the range
  //
  Entry = NULL;
  for (Link = gMemoryMap.ForwardLink; Link != &gMemoryMap; Link = Link->ForwardLink) {
    Entry = CR(Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    if (Entry->Start <= Address && Entry->End > Address) {
        break;
    }
  }
  if (Link == &gMemoryMap) {
    return GuardPageTypeUnallocated;
  }

  ASSERT (Entry != NULL);

  if (Entry->Type == EfiConventionalMemory) {
    return GuardPageTypeUnallocated;
  }

  //
  // Now we know it is allocated
  //

  for (Link = mGuardPageList.ForwardLink; Link != &mGuardPageList; Link = Link->ForwardLink) {
    GuardPageHead = BASE_CR(Link, GUARD_PAGE_HEAD, Link);

    if (IsTheGuardPageGuarded((UINTN)GuardPageHead & ~(SIZE_4KB - 1))) {
      // Do not go through link list, check presence directly.
      if (IsTheGuardPageGuarded(Address)) {
        return GuardPageTypeGuarded;
      } else {
        return GuardPageTypeAllocatedUnguarded;
      }
    }

    ASSERT((GuardPageHead->Signature == GUARD_PAGE_HEAD_SIGNATURE) || (GuardPageHead->Signature == GUARD_PAGE_TAIL_SIGNATURE));
    if (GuardPageHead->Address == Address) {
      return GuardPageTypeGuarded;
    }
  }
  return GuardPageTypeAllocatedUnguarded;
}

VOID
AllocateGuardPage(
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
//  DEBUG ((EFI_D_INFO, "AllocateGuardPage - 0x%x\n", Address));
  ConvertSmmMemoryMapEntry (Address, 1, EfiRuntimeServicesData, FALSE);
  CoreFreeMemoryMapStack();
}

VOID
FreeGuardPage(
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
//  DEBUG ((EFI_D_INFO, "FreeGuardPage - 0x%x\n", Address));
  ConvertSmmMemoryMapEntry (Address, 1, EfiConventionalMemory, FALSE);
  CoreFreeMemoryMapStack();
}


/**
  Adds a node to the beginning of a doubly-linked list, and returns the pointer
  to the head node of the doubly-linked list.

  Adds the node Entry at the beginning of the doubly-linked list denoted by
  ListHead, and returns ListHead.

  If ListHead is NULL, then ASSERT().
  If Entry is NULL, then ASSERT().
  If ListHead was not initialized with INTIALIZE_LIST_HEAD_VARIABLE() or
  InitializeListHead(), then ASSERT().
  If PcdMaximumLinkedListLength is not zero, and prior to insertion the number
  of nodes in ListHead, including the ListHead node, is greater than or
  equal to PcdMaximumLinkedListLength, then ASSERT().

  @param  ListHead  A pointer to the head node of a doubly-linked list.
  @param  Entry     A pointer to a node that is to be inserted at the beginning
                    of a doubly-linked list.

  @return ListHead

**/
LIST_ENTRY *
EFIAPI
InsertHeadListGuarded (
  IN OUT  LIST_ENTRY                *ListHead,
  IN OUT  LIST_ENTRY                *Entry
  )
{
  BOOLEAN   IsEntryForwardLinkGuarded;

  IsEntryForwardLinkGuarded = IsTheGuardPageGuarded((UINTN)ListHead->ForwardLink & ~(SIZE_4KB - 1));
  if (IsEntryForwardLinkGuarded) {
    UnguardTheGuardPage((UINTN)ListHead->ForwardLink & ~(SIZE_4KB - 1));
  }

//  DEBUG((EFI_D_INFO, "InsertHeadListGuarded - Entry (0x%x)\n", Entry));
//  DEBUG((EFI_D_INFO, "InsertHeadListGuarded - ListHead (0x%x)\n", ListHead));
  Entry->ForwardLink = ListHead->ForwardLink;
  Entry->BackLink = ListHead;
//  DEBUG((EFI_D_INFO, "InsertHeadListGuarded - Entry->ForwardLink (0x%x)\n", Entry->ForwardLink));
  Entry->ForwardLink->BackLink = Entry;
  ListHead->ForwardLink = Entry;

  if (IsEntryForwardLinkGuarded) {
    UnguardTheGuardPage((UINTN)Entry->ForwardLink & ~(SIZE_4KB - 1));
  }
  return ListHead;
}

/**
  Adds a node to the end of a doubly-linked list, and returns the pointer to
  the head node of the doubly-linked list.

  Adds the node Entry to the end of the doubly-linked list denoted by ListHead,
  and returns ListHead.

  If ListHead is NULL, then ASSERT().
  If Entry is NULL, then ASSERT().
  If ListHead was not initialized with INTIALIZE_LIST_HEAD_VARIABLE() or 
  InitializeListHead(), then ASSERT().
  If PcdMaximumLinkedListLength is not zero, and prior to insertion the number
  of nodes in ListHead, including the ListHead node, is greater than or
  equal to PcdMaximumLinkedListLength, then ASSERT().

  @param  ListHead  A pointer to the head node of a doubly-linked list.
  @param  Entry     A pointer to a node that is to be added at the end of the
                    doubly-linked list.

  @return ListHead

**/
LIST_ENTRY *
EFIAPI
InsertTailListGuarded (
  IN OUT  LIST_ENTRY                *ListHead,
  IN OUT  LIST_ENTRY                *Entry
  )
{
  BOOLEAN   IsEntryBackLinkGuarded;

  IsEntryBackLinkGuarded = IsTheGuardPageGuarded((UINTN)ListHead->BackLink & ~(SIZE_4KB - 1));
  if (IsEntryBackLinkGuarded) {
    UnguardTheGuardPage((UINTN)ListHead->BackLink & ~(SIZE_4KB - 1));
  }

//  DEBUG((EFI_D_INFO, "InsertTailListGuarded - Entry (0x%x)\n", Entry));
  Entry->ForwardLink = ListHead;
//  DEBUG((EFI_D_INFO, "InsertTailListGuarded - ListHead (0x%x)\n", ListHead));
  Entry->BackLink = ListHead->BackLink;
//  DEBUG((EFI_D_INFO, "InsertTailListGuarded - Entry->BackLink (0x%x)\n", Entry->BackLink));
  Entry->BackLink->ForwardLink = Entry;
  ListHead->BackLink = Entry;

  if (IsEntryBackLinkGuarded) {
    UnguardTheGuardPage((UINTN)Entry->BackLink & ~(SIZE_4KB - 1));
  }
  return ListHead;
}

/**
  Removes a node from a doubly-linked list, and returns the node that follows
  the removed node.

  Removes the node Entry from a doubly-linked list. It is up to the caller of
  this function to release the memory used by this node if that is required. On
  exit, the node following Entry in the doubly-linked list is returned. If
  Entry is the only node in the linked list, then the head node of the linked
  list is returned.

  If Entry is NULL, then ASSERT().
  If Entry is the head node of an empty list, then ASSERT().
  If PcdMaximumLinkedListLength is not zero, and the number of nodes in the
  linked list containing Entry, including the Entry node, is greater than
  or equal to PcdMaximumLinkedListLength, then ASSERT().

  @param  Entry A pointer to a node in a linked list.

  @return Entry.

**/
LIST_ENTRY *
EFIAPI
RemoveEntryListGuarded (
  IN      CONST LIST_ENTRY          *Entry
  )
{
  BOOLEAN   IsEntryForwardLinkGuarded;
  BOOLEAN   IsEntryBackLinkGuarded;

  IsEntryForwardLinkGuarded = IsTheGuardPageGuarded((UINTN)Entry->ForwardLink & ~(SIZE_4KB - 1));
  if (IsEntryForwardLinkGuarded) {
    UnguardTheGuardPage((UINTN)Entry->ForwardLink & ~(SIZE_4KB - 1));
  }
  IsEntryBackLinkGuarded = IsTheGuardPageGuarded((UINTN)Entry->BackLink & ~(SIZE_4KB - 1));
  if (IsEntryBackLinkGuarded) {
    UnguardTheGuardPage((UINTN)Entry->BackLink & ~(SIZE_4KB - 1));
  }

//  DEBUG((EFI_D_INFO, "RemoveEntryListGuarded - Entry (0x%x)\n", Entry));
//  DEBUG((EFI_D_INFO, "RemoveEntryListGuarded - Entry->ForwardLink (0x%x)\n", Entry->ForwardLink));
//  DEBUG((EFI_D_INFO, "RemoveEntryListGuarded - Entry->BackLink (0x%x)\n", Entry->BackLink));
  Entry->ForwardLink->BackLink = Entry->BackLink;
  Entry->BackLink->ForwardLink = Entry->ForwardLink;

  if (IsEntryForwardLinkGuarded) {
    UnguardTheGuardPage((UINTN)Entry->ForwardLink & ~(SIZE_4KB - 1));
  }
  if (IsEntryBackLinkGuarded) {
    UnguardTheGuardPage((UINTN)Entry->BackLink & ~(SIZE_4KB - 1));
  }
  return Entry->ForwardLink;
}


VOID
SetGuardPage (
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
  GUARD_PAGE_HEAD  *GuardPageHead;
  GUARD_PAGE_TAIL  *GuardPageTail;

//  DEBUG ((EFI_D_INFO, "SetGuardPage - 0x%x\n", Address));

  GuardPageHead = (VOID *)(UINTN)Address;
  GuardPageHead->Signature = GUARD_PAGE_HEAD_SIGNATURE;
  GuardPageHead->Address = Address;
  InsertTailListGuarded (&mGuardPageList, &GuardPageHead->Link);

  GuardPageTail = GUARD_HEAD_TO_TAIL(GuardPageHead);
  GuardPageTail->Signature = GUARD_PAGE_TAIL_SIGNATURE;
  GuardPageTail->Address = Address;
  InsertTailListGuarded (&mGuardPageList, &GuardPageTail->Link);
}

VOID
ClearGuardPage (
  IN EFI_PHYSICAL_ADDRESS   Address
  )
{
  GUARD_PAGE_HEAD  *GuardPageHead;
  GUARD_PAGE_TAIL  *GuardPageTail;

//  DEBUG ((EFI_D_INFO, "ClearGuardPage - 0x%x\n", Address));

  GuardPageHead = (VOID *)(UINTN)Address;
  UnguardTheGuardPage(Address);

  ASSERT (GuardPageHead->Signature == GUARD_PAGE_HEAD_SIGNATURE);
  ASSERT (GuardPageHead->Address == Address);
  RemoveEntryListGuarded (&GuardPageHead->Link);

  GuardPageTail = GUARD_HEAD_TO_TAIL(GuardPageHead);
  ASSERT (GuardPageTail->Signature == GUARD_PAGE_TAIL_SIGNATURE);
  ASSERT (GuardPageTail->Address == Address);
  RemoveEntryListGuarded (&GuardPageTail->Link);
}

/**
  +---------+--------------+---------+
  |GuardPage|Allocated Page|GuardPage|
  +---------+--------------+---------+
**/
VOID
SetGuardPageOnAllocatePages (
  IN EFI_PHYSICAL_ADDRESS   Memory,
  IN UINTN                  NumberOfPages
  )
{
  DEBUG ((EFI_D_INFO, "SetGuardPageOnAllocatePages - 0x%lx (0x%x)\n", Memory, NumberOfPages));

  SetGuardPage (Memory - EFI_PAGES_TO_SIZE(1));
  SetGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages));

//  DumpGuardPages ();
}

/**
We need consider below situations.
                 +-------+-----------+------------+---------+-------+
                 | GUARD | Mem_Start | Mem_Middle | Mem_End | GUARD |
                 +-------+-----------+------------+---------+-------+

==> (Free All)

                         +-----------+------------+---------+-------+
==> (Free Start)         |   GUARD   | Mem_Middle | Mem_End | GUARD |
                         +-----------+------------+---------+-------+
                 +-------+-----------+------------+---------+-------+
==> (Free Middle)| GUARD | Mem_Start |   GUARD    | Mem_End | GUARD |
                 +-------+-----------+------------+---------+-------+
                 +-------+-----------+------------+---------+
==> (Free End)   | GUARD | Mem_Start | Mem_Middle |  GUARD  |
                 +-------+-----------+------------+---------+
}

Operation is an array to carry 4 entries.
  0: Operation for Memory - EFI_PAGES_TO_SIZE(1)                   // GuardOperationNoAction or GuardOperationClearGuard
  1: Operation for Memory                                          // GuardOperationNoAction or GuardOperationSetGuard
  2: Operation for Memory + EFI_PAGES_TO_SIZE(NumberOfPages - 1)   // GuardOperationNoAction or GuardOperationSetGuard
  3: Operation for Memory + EFI_PAGES_TO_SIZE(NumberOfPages)       // GuardOperationNoAction or GuardOperationClearGuard

**/
VOID
ClearGuardPageOnFreePages (
  IN EFI_PHYSICAL_ADDRESS   Memory,
  IN UINTN                  NumberOfPages,
  OUT GUARD_OPERATION       *Operation
  )
{
  GUARD_PAGE_TYPE   PreviousPageType;
  GUARD_PAGE_TYPE   Previous2PageType;
  GUARD_PAGE_TYPE   NextPageType;
  GUARD_PAGE_TYPE   Next2PageType;

  DEBUG ((EFI_D_INFO, "ClearGuardPageOnFreePages - 0x%lx (0x%x)\n", Memory, NumberOfPages));

  ZeroMem (Operation, sizeof(GUARD_OPERATION) * 4);

  PreviousPageType = GetGuardPageType (Memory - EFI_PAGES_TO_SIZE(1));
  Previous2PageType = GetGuardPageType (Memory - EFI_PAGES_TO_SIZE(2));
  if (PreviousPageType == GuardPageTypeGuarded) {
    if (Previous2PageType != GuardPageTypeAllocatedUnguarded) {
      ClearGuardPage (Memory - EFI_PAGES_TO_SIZE(1));
      FreeGuardPage (Memory - EFI_PAGES_TO_SIZE(1));
      if (Operation != NULL) {
        Operation[0] = GuardOperationNoAction;
      }
    }
  } else if (PreviousPageType == GuardPageTypeAllocatedUnguarded) {
    AllocateGuardPage (Memory);
    SetGuardPage (Memory);
    if (Operation != NULL) {
      Operation[1] = GuardOperationSetGuard;
    }
  } else {
    ASSERT(FALSE);
  }

  NextPageType = GetGuardPageType (Memory + EFI_PAGES_TO_SIZE(NumberOfPages));
  Next2PageType = GetGuardPageType (Memory + EFI_PAGES_TO_SIZE(NumberOfPages + 1));
  if (NextPageType == GuardPageTypeGuarded) {
    if (Next2PageType != GuardPageTypeAllocatedUnguarded) {
      ClearGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages));
      FreeGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages));
      if (Operation != NULL) {
        Operation[3] = GuardOperationNoAction;
      }
    }
  } else if (NextPageType == GuardPageTypeAllocatedUnguarded) {
    AllocateGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages - 1));
    SetGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages - 1));
    if (Operation != NULL) {
      Operation[2] = GuardOperationSetGuard;
    }
  } else {
    ASSERT(FALSE);
  }

//  DumpGuardPages ();
}

VOID
SetGuardPageOnAllocatePoolPages (
  IN EFI_PHYSICAL_ADDRESS   Memory,
  IN UINTN                  NumberOfPages
  )
{
  DEBUG ((EFI_D_INFO, "SetGuardPageOnAllocatePoolPages - 0x%lx (0x%x)\n", Memory, NumberOfPages));

  SetGuardPage (Memory - EFI_PAGES_TO_SIZE(1));
  SetGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages));

//  DumpGuardPages ();
}

VOID
ClearGuardPageOnFreePoolPages (
  IN EFI_PHYSICAL_ADDRESS   Memory,
  IN UINTN                  NumberOfPages
  )
{
  DEBUG ((EFI_D_INFO, "ClearGuardPageOnFreePoolPages - 0x%lx (0x%x)\n", Memory, NumberOfPages));

  ClearGuardPage (Memory - EFI_PAGES_TO_SIZE(1));
  FreeGuardPage (Memory - EFI_PAGES_TO_SIZE(1));

  ClearGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages));
  FreeGuardPage (Memory + EFI_PAGES_TO_SIZE(NumberOfPages));

//  DumpGuardPages();
}


/**
  Allocates pages from the memory map.

  @param[in]   Type                   The type of allocation to perform.
  @param[in]   MemoryType             The type of memory to turn the allocated pages
                                      into.
  @param[in]   NumberOfPages          The number of pages to allocate.
  @param[out]  Memory                 A pointer to receive the base allocated memory
                                      address.
  @param[in]   AddRegion              If this memory is new added region.

  @retval EFI_INVALID_PARAMETER  Parameters violate checking rules defined in spec.
  @retval EFI_NOT_FOUND          Could not allocate pages match the requirement.
  @retval EFI_OUT_OF_RESOURCES   No enough pages to allocate.
  @retval EFI_SUCCESS            Pages successfully allocated.

**/
EFI_STATUS
SmmInternalAllocatePagesEx (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory,
  IN  BOOLEAN               PoolPage,
  IN  BOOLEAN               AddRegion,
  IN BOOLEAN                NeedGuard
  );

/**
  Internal function.  Deque a descriptor entry from the mFreeMemoryMapEntryList.
  If the list is emtry, then allocate a new page to refuel the list.
  Please Note this algorithm to allocate the memory map descriptor has a property
  that the memory allocated for memory entries always grows, and will never really be freed.

  @return The Memory map descriptor dequed from the mFreeMemoryMapEntryList

**/
MEMORY_MAP *
AllocateMemoryMapEntry (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS   Mem;
  EFI_STATUS             Status;
  MEMORY_MAP*            FreeDescriptorEntries;
  MEMORY_MAP*            Entry;
  UINTN                  Index;

  //DEBUG((DEBUG_INFO, "AllocateMemoryMapEntry\n"));

  if (IsListEmpty (&mFreeMemoryMapEntryList)) {
    //DEBUG((DEBUG_INFO, "mFreeMemoryMapEntryList is empty\n"));
    //
    // The list is empty, to allocate one page to refuel the list
    //
    Status = SmmInternalAllocatePagesEx (
               AllocateAnyPages,
               EfiRuntimeServicesData,
               EFI_SIZE_TO_PAGES(DEFAULT_PAGE_ALLOCATION),
               &Mem,
               FALSE,
               TRUE,
               FALSE
               );
    ASSERT_EFI_ERROR (Status);
    if(!EFI_ERROR (Status)) {
      FreeDescriptorEntries = (MEMORY_MAP *)(UINTN)Mem;
      //DEBUG((DEBUG_INFO, "New FreeDescriptorEntries - 0x%x\n", FreeDescriptorEntries));
      //
      // Enque the free memmory map entries into the list
      //
      for (Index = 0; Index< DEFAULT_PAGE_ALLOCATION / sizeof(MEMORY_MAP); Index++) {
        FreeDescriptorEntries[Index].Signature = MEMORY_MAP_SIGNATURE;
        InsertTailList (&mFreeMemoryMapEntryList, &FreeDescriptorEntries[Index].Link);
      }
    } else {
      return NULL;
    }
  }
  //
  // dequeue the first descriptor from the list
  //
  Entry = CR (mFreeMemoryMapEntryList.ForwardLink, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
  RemoveEntryList (&Entry->Link);

  return Entry;
}


/**
  Internal function.  Moves any memory descriptors that are on the
  temporary descriptor stack to heap.

**/
VOID
CoreFreeMemoryMapStack (
  VOID
  )
{
  MEMORY_MAP      *Entry;

  //
  // If already freeing the map stack, then return
  //
  if (mFreeMapStack != 0) {
    ASSERT (FALSE);
    return ;
  }

  //
  // Move the temporary memory descriptor stack into pool
  //
  mFreeMapStack += 1;

  while (mMapDepth != 0) {
    //
    // Deque an memory map entry from mFreeMemoryMapEntryList
    //
    Entry = AllocateMemoryMapEntry ();
    ASSERT (Entry);

    //
    // Update to proper entry
    //
    mMapDepth -= 1;

    if (mMapStack[mMapDepth].Link.ForwardLink != NULL) {

      CopyMem (Entry , &mMapStack[mMapDepth], sizeof (MEMORY_MAP));
      Entry->FromStack = FALSE;

      //
      // Move this entry to general memory
      //
      InsertTailList (&mMapStack[mMapDepth].Link, &Entry->Link);
      RemoveEntryList (&mMapStack[mMapDepth].Link);
      mMapStack[mMapDepth].Link.ForwardLink = NULL;
    }
  }

  mFreeMapStack -= 1;
}

/**
  Insert new entry from memory map.

  @param[in]  Link       The old memory map entry to be linked.
  @param[in]  Start      The start address of new memory map entry.
  @param[in]  End        The end address of new memory map entry.
  @param[in]  Type       The type of new memory map entry.
  @param[in]  Next       If new entry is inserted to the next of old entry.
  @param[in]  AddRegion  If this memory is new added region.
**/
VOID
InsertNewEntry (
  IN LIST_ENTRY      *Link,
  IN UINT64          Start,
  IN UINT64          End,
  IN EFI_MEMORY_TYPE Type,
  IN BOOLEAN         Next,
  IN BOOLEAN         AddRegion
  )
{
  MEMORY_MAP  *Entry;

  Entry = &mMapStack[mMapDepth];
  mMapDepth += 1;
  ASSERT (mMapDepth < MAX_MAP_DEPTH);
  Entry->FromStack = TRUE;

  Entry->Signature = MEMORY_MAP_SIGNATURE;
  Entry->Type = Type;
  Entry->Start = Start;
  Entry->End = End;
  if (Next) {
    InsertHeadList (Link, &Entry->Link);
  } else {
    InsertTailList (Link, &Entry->Link);
  }
}

/**
  Remove old entry from memory map.

  @param[in] Entry Memory map entry to be removed.
**/
VOID
RemoveOldEntry (
  IN MEMORY_MAP  *Entry
  )
{
  RemoveEntryList (&Entry->Link);
  if (!Entry->FromStack) {
    InsertTailList (&mFreeMemoryMapEntryList, &Entry->Link);
  }
}

/**
  Update SMM memory map entry.

  @param[in]  Type                   The type of allocation to perform.
  @param[in]  Memory                 The base of memory address.
  @param[in]  NumberOfPages          The number of pages to allocate.
  @param[in]  AddRegion              If this memory is new added region.
**/
VOID
ConvertSmmMemoryMapEntry (
  IN EFI_MEMORY_TYPE       Type,
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages,
  IN BOOLEAN               AddRegion
  )
{
  LIST_ENTRY               *Link;
  MEMORY_MAP               *Entry;
  MEMORY_MAP               *NextEntry;
  LIST_ENTRY               *NextLink;
  MEMORY_MAP               *PreviousEntry;
  LIST_ENTRY               *PreviousLink;
  EFI_PHYSICAL_ADDRESS     Start;
  EFI_PHYSICAL_ADDRESS     End;

  Start = Memory;
  End = Memory + EFI_PAGES_TO_SIZE(NumberOfPages) - 1;

  //
  // Exclude memory region
  //
  Link = gMemoryMap.ForwardLink;
  while (Link != &gMemoryMap) {
    Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    Link  = Link->ForwardLink;

    //
    // ---------------------------------------------------
    // |  +----------+   +------+   +------+   +------+  |
    // ---|gMemoryMep|---|Entry1|---|Entry2|---|Entry3|---
    //    +----------+ ^ +------+   +------+   +------+
    //                 |
    //              +------+
    //              |EntryX|
    //              +------+
    //
    if (Entry->Start > End) {
      if ((Entry->Start == End + 1) && (Entry->Type == Type)) {
        Entry->Start = Start;
        return ;
      }
      InsertNewEntry (
        &Entry->Link,
        Start,
        End,
        Type,
        FALSE,
        AddRegion
        );
      return ;
    }

    if ((Entry->Start <= Start) && (Entry->End >= End)) {
      if (Entry->Type != Type) {
        if (Entry->Start < Start) {
          //
          // ---------------------------------------------------
          // |  +----------+   +------+   +------+   +------+  |
          // ---|gMemoryMep|---|Entry1|---|EntryX|---|Entry3|---
          //    +----------+   +------+ ^ +------+   +------+
          //                            |
          //                         +------+
          //                         |EntryA|
          //                         +------+
          //
          InsertNewEntry (
            &Entry->Link,
            Entry->Start,
            Start - 1,
            Entry->Type,
            FALSE,
            AddRegion
            );
        }
        if (Entry->End > End) {
          //
          // ---------------------------------------------------
          // |  +----------+   +------+   +------+   +------+  |
          // ---|gMemoryMep|---|Entry1|---|EntryX|---|Entry3|---
          //    +----------+   +------+   +------+ ^ +------+
          //                                       |
          //                                    +------+
          //                                    |EntryZ|
          //                                    +------+
          //
          InsertNewEntry (
            &Entry->Link,
            End + 1,
            Entry->End,
            Entry->Type,
            TRUE,
            AddRegion
            );
        }
        //
        // Update this node
        //
        Entry->Start = Start;
        Entry->End = End;
        Entry->Type = Type;

        //
        // Check adjacent
        //
        NextLink = Entry->Link.ForwardLink;
        if (NextLink != &gMemoryMap) {
          NextEntry = CR (NextLink, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
          //
          // ---------------------------------------------------
          // |  +----------+   +------+   +-----------------+  |
          // ---|gMemoryMep|---|Entry1|---|EntryX     Entry3|---
          //    +----------+   +------+   +-----------------+
          //
          if ((Entry->Type == NextEntry->Type) && (Entry->End + 1 == NextEntry->Start)) {
            Entry->End = NextEntry->End;
            RemoveOldEntry (NextEntry);
          }
        }
        PreviousLink = Entry->Link.BackLink;
        if (PreviousLink != &gMemoryMap) {
          PreviousEntry = CR (PreviousLink, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
          //
          // ---------------------------------------------------
          // |  +----------+   +-----------------+   +------+  |
          // ---|gMemoryMep|---|Entry1     EntryX|---|Entry3|---
          //    +----------+   +-----------------+   +------+
          //
          if ((PreviousEntry->Type == Entry->Type) && (PreviousEntry->End + 1 == Entry->Start)) {
            PreviousEntry->End = Entry->End;
            RemoveOldEntry (Entry);
          }
        }
      }
      return ;
    }
  }

  //
  // ---------------------------------------------------
  // |  +----------+   +------+   +------+   +------+  |
  // ---|gMemoryMep|---|Entry1|---|Entry2|---|Entry3|---
  //    +----------+   +------+   +------+   +------+ ^
  //                                                  |
  //                                               +------+
  //                                               |EntryX|
  //                                               +------+
  //
  Link = gMemoryMap.BackLink;
  if (Link != &gMemoryMap) {
    Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    if ((Entry->End + 1 == Start) && (Entry->Type == Type)) {
      Entry->End = End;
      return ;
    }
  }
  InsertNewEntry (
    &gMemoryMap,
    Start,
    End,
    Type,
    FALSE,
    AddRegion
    );
  return ;
}

/**
  Return the count of Smm memory map entry.

  @return The count of Smm memory map entry.
**/
UINTN
GetSmmMemoryMapEntryCount (
  VOID
  )
{
  LIST_ENTRY               *Link;
  UINTN                    Count;

  Count = 0;
  Link = gMemoryMap.ForwardLink;
  while (Link != &gMemoryMap) {
    Link  = Link->ForwardLink;
    Count++;
  }
  return Count;
}

/**
  Dump Smm memory map entry.
**/
VOID
DumpSmmMemoryMapEntry (
  VOID
  )
{
  LIST_ENTRY               *Link;
  MEMORY_MAP               *Entry;
  EFI_PHYSICAL_ADDRESS     Last;

  Last = 0;
  DEBUG ((DEBUG_INFO, "DumpSmmMemoryMapEntry:\n"));
  Link = gMemoryMap.ForwardLink;
  while (Link != &gMemoryMap) {
    Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    Link  = Link->ForwardLink;

    if ((Last != 0) && (Last != (UINT64)-1)) {
      if (Last + 1 != Entry->Start) {
        Last = (UINT64)-1;
      } else {
        Last = Entry->End;
      }
    } else if (Last == 0) {
      Last = Entry->End;
    }

    DEBUG ((DEBUG_INFO, "Entry (Link - 0x%x)\n", &Entry->Link));
    DEBUG ((DEBUG_INFO, "  Signature         - 0x%x\n", Entry->Signature));
    DEBUG ((DEBUG_INFO, "  Link.ForwardLink  - 0x%x\n", Entry->Link.ForwardLink));
    DEBUG ((DEBUG_INFO, "  Link.BackLink     - 0x%x\n", Entry->Link.BackLink));
    DEBUG ((DEBUG_INFO, "  Type              - 0x%x\n", Entry->Type));
    DEBUG ((DEBUG_INFO, "  Start             - 0x%016lx\n", Entry->Start));
    DEBUG ((DEBUG_INFO, "  End               - 0x%016lx\n", Entry->End));
  }

  ASSERT (Last != (UINT64)-1);
}

/**
  Dump Smm memory map.
**/
VOID
DumpSmmMemoryMap (
  VOID
  )
{
  LIST_ENTRY      *Node;
  FREE_PAGE_LIST  *Pages;

  DEBUG ((DEBUG_INFO, "DumpSmmMemoryMap\n"));

  Pages = NULL;
  Node = mSmmMemoryMap.ForwardLink;
  while (Node != &mSmmMemoryMap) {
    Pages = BASE_CR (Node, FREE_PAGE_LIST, Link);
    DEBUG ((DEBUG_INFO, "Pages - 0x%x\n", Pages));
    DEBUG ((DEBUG_INFO, "Pages->NumberOfPages - 0x%x\n", Pages->NumberOfPages));
    Node = Node->ForwardLink;
  }
}

/**
  Check if a Smm base~length is in Smm memory map.

  @param[in] Base   The base address of Smm memory to be checked.
  @param[in] Length THe length of Smm memory to be checked.

  @retval TRUE  Smm base~length is in smm memory map.
  @retval FALSE Smm base~length is in smm memory map.
**/
BOOLEAN
SmmMemoryMapConsistencyCheckRange (
  IN EFI_PHYSICAL_ADDRESS Base,
  IN UINTN                Length
  )
{
  LIST_ENTRY               *Link;
  MEMORY_MAP               *Entry;
  BOOLEAN                  Result;

  Result = FALSE;
  Link = gMemoryMap.ForwardLink;
  while (Link != &gMemoryMap) {
    Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    Link  = Link->ForwardLink;

    if (Entry->Type != EfiConventionalMemory) {
      continue;
    }
    if (Entry->Start == Base && Entry->End == Base + Length - 1) {
      Result = TRUE;
      break;
    }
  }

  return Result;
}

/**
  Check the consistency of Smm memory map.
**/
VOID
SmmMemoryMapConsistencyCheck (
  VOID
  )
{
  LIST_ENTRY      *Node;
  FREE_PAGE_LIST  *Pages;
  BOOLEAN         Result;

  Pages = NULL;
  Node = mSmmMemoryMap.ForwardLink;
  while (Node != &mSmmMemoryMap) {
    Pages = BASE_CR (Node, FREE_PAGE_LIST, Link);
    Result = SmmMemoryMapConsistencyCheckRange ((EFI_PHYSICAL_ADDRESS)(UINTN)Pages, (UINTN)EFI_PAGES_TO_SIZE(Pages->NumberOfPages));
    ASSERT (Result);
    Node = Node->ForwardLink;
  }
}

/**
  Internal Function. Allocate n pages from given free page node.

  @param  Pages                  The free page node.
  @param  NumberOfPages          Number of pages to be allocated.
  @param  MaxAddress             Request to allocate memory below this address.

  @return Memory address of allocated pages.

**/
UINTN
InternalAllocPagesOnOneNode (
  IN OUT FREE_PAGE_LIST  *Pages,
  IN     UINTN           NumberOfPages,
  IN     UINTN           MaxAddress
  )
{
  UINTN           Top;
  UINTN           Bottom;
  FREE_PAGE_LIST  *Node;

  Top = TRUNCATE_TO_PAGES (MaxAddress + 1 - (UINTN)Pages);
  if (Top > Pages->NumberOfPages) {
    Top = Pages->NumberOfPages;
  }
  Bottom = Top - NumberOfPages;

  if (Top < Pages->NumberOfPages) {
    Node = (FREE_PAGE_LIST*)((UINTN)Pages + EFI_PAGES_TO_SIZE (Top));
    Node->NumberOfPages = Pages->NumberOfPages - Top;
    InsertHeadList (&Pages->Link, &Node->Link);
  }

  if (Bottom > 0) {
    Pages->NumberOfPages = Bottom;
  } else {
    RemoveEntryList (&Pages->Link);
  }

  return (UINTN)Pages + EFI_PAGES_TO_SIZE (Bottom);
}

/**
  Internal Function. Allocate n pages from free page list below MaxAddress.

  @param  FreePageList           The free page node.
  @param  NumberOfPages          Number of pages to be allocated.
  @param  MaxAddress             Request to allocate memory below this address.

  @return Memory address of allocated pages.

**/
UINTN
InternalAllocMaxAddress (
  IN OUT LIST_ENTRY  *FreePageList,
  IN     UINTN       NumberOfPages,
  IN     UINTN       MaxAddress
  )
{
  LIST_ENTRY      *Node;
  FREE_PAGE_LIST  *Pages;

  for (Node = FreePageList->BackLink; Node != FreePageList; Node = Node->BackLink) {
    Pages = BASE_CR (Node, FREE_PAGE_LIST, Link);
    if (Pages->NumberOfPages >= NumberOfPages &&
        (UINTN)Pages + EFI_PAGES_TO_SIZE (NumberOfPages) - 1 <= MaxAddress) {
      return InternalAllocPagesOnOneNode (Pages, NumberOfPages, MaxAddress);
    }
  }
  return (UINTN)(-1);
}

/**
  Internal Function. Allocate n pages from free page list at given address.

  @param  FreePageList           The free page node.
  @param  NumberOfPages          Number of pages to be allocated.
  @param  MaxAddress             Request to allocate memory below this address.

  @return Memory address of allocated pages.

**/
UINTN
InternalAllocAddress (
  IN OUT LIST_ENTRY  *FreePageList,
  IN     UINTN       NumberOfPages,
  IN     UINTN       Address
  )
{
  UINTN           EndAddress;
  LIST_ENTRY      *Node;
  FREE_PAGE_LIST  *Pages;

  if ((Address & EFI_PAGE_MASK) != 0) {
    return ~Address;
  }

  EndAddress = Address + EFI_PAGES_TO_SIZE (NumberOfPages);
  for (Node = FreePageList->BackLink; Node!= FreePageList; Node = Node->BackLink) {
    Pages = BASE_CR (Node, FREE_PAGE_LIST, Link);
    if ((UINTN)Pages <= Address) {
      if ((UINTN)Pages + EFI_PAGES_TO_SIZE (Pages->NumberOfPages) < EndAddress) {
        break;
      }
      return InternalAllocPagesOnOneNode (Pages, NumberOfPages, EndAddress);
    }
  }
  return ~Address;
}

/**
  Allocates pages from the memory map.

  @param[in]   Type                   The type of allocation to perform.
  @param[in]   MemoryType             The type of memory to turn the allocated pages
                                      into.
  @param[in]   NumberOfPages          The number of pages to allocate.
  @param[out]  Memory                 A pointer to receive the base allocated memory
                                      address.
  @param[in]   AddRegion              If this memory is new added region.

  @retval EFI_INVALID_PARAMETER  Parameters violate checking rules defined in spec.
  @retval EFI_NOT_FOUND          Could not allocate pages match the requirement.
  @retval EFI_OUT_OF_RESOURCES   No enough pages to allocate.
  @retval EFI_SUCCESS            Pages successfully allocated.

**/
EFI_STATUS
SmmInternalAllocatePagesEx (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory,
  IN  BOOLEAN               PoolPage,
  IN  BOOLEAN               AddRegion,
  IN BOOLEAN                NeedGuard
  )
{
  UINTN  RequestedAddress;

  if (MemoryType != EfiRuntimeServicesCode &&
      MemoryType != EfiRuntimeServicesData) {
    return EFI_INVALID_PARAMETER;
  }

  if (FeaturePcdGet(PcdHeapPageGuard) && NeedGuard && !AddRegion) {
    NumberOfPages += 2;
  }

  if (NumberOfPages > TRUNCATE_TO_PAGES ((UINTN)-1) + 1) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // We don't track memory type in SMM
  //
  RequestedAddress = (UINTN)*Memory;
  switch (Type) {
    case AllocateAnyPages:
      RequestedAddress = (UINTN)(-1);
    case AllocateMaxAddress:
      *Memory = InternalAllocMaxAddress (
                  &mSmmMemoryMap,
                  NumberOfPages,
                  RequestedAddress
                  );
      if (*Memory == (UINTN)-1) {
        return EFI_OUT_OF_RESOURCES;
      }
      break;
    case AllocateAddress:
      *Memory = InternalAllocAddress (
                  &mSmmMemoryMap,
                  NumberOfPages,
                  RequestedAddress
                  );
      if (*Memory != RequestedAddress) {
        return EFI_NOT_FOUND;
      }
      break;
    default:
      return EFI_INVALID_PARAMETER;
  }

  //
  // Update SmmMemoryMap here.
  //
  ConvertSmmMemoryMapEntry (MemoryType, *Memory, NumberOfPages, AddRegion);
  if (!AddRegion) {
    CoreFreeMemoryMapStack();
  }

  if (FeaturePcdGet(PcdHeapPageGuard) && NeedGuard && !AddRegion) {
    *Memory += EFI_PAGES_TO_SIZE(1);
    if (PoolPage) {
      SetGuardPageOnAllocatePoolPages (*Memory, NumberOfPages - 2);
    } else {
      SetGuardPageOnAllocatePages (*Memory, NumberOfPages - 2);
    }
  }

  return EFI_SUCCESS;
}

/**
  Allocates pages from the memory map.

  @param[in]   Type                   The type of allocation to perform.
  @param[in]   MemoryType             The type of memory to turn the allocated pages
                                      into.
  @param[in]   NumberOfPages          The number of pages to allocate.
  @param[out]  Memory                 A pointer to receive the base allocated memory
                                      address.

  @retval EFI_INVALID_PARAMETER  Parameters violate checking rules defined in spec.
  @retval EFI_NOT_FOUND          Could not allocate pages match the requirement.
  @retval EFI_OUT_OF_RESOURCES   No enough pages to allocate.
  @retval EFI_SUCCESS            Pages successfully allocated.

**/
EFI_STATUS
EFIAPI
SmmInternalAllocatePages (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory,
  IN BOOLEAN                PoolPage,
  IN BOOLEAN                NeedGuard
  )
{
  return SmmInternalAllocatePagesEx (Type, MemoryType, NumberOfPages, Memory, PoolPage, FALSE, NeedGuard);
}

VOID *
EFIAPI
AllocatePagesForGuard (
  IN UINTN  Pages
  )
{
  EFI_PHYSICAL_ADDRESS Memory;
  EFI_STATUS           Status;

  Status = SmmInternalAllocatePages (AllocateAnyPages, EfiRuntimeServicesData, Pages, &Memory, FALSE, FALSE);
  if (!EFI_ERROR (Status)) {
    return (VOID *)(UINTN)Memory;
  }
  return NULL;
}

/**
  Allocates pages from the memory map.

  @param  Type                   The type of allocation to perform.
  @param  MemoryType             The type of memory to turn the allocated pages
                                 into.
  @param  NumberOfPages          The number of pages to allocate.
  @param  Memory                 A pointer to receive the base allocated memory
                                 address.

  @retval EFI_INVALID_PARAMETER  Parameters violate checking rules defined in spec.
  @retval EFI_NOT_FOUND          Could not allocate pages match the requirement.
  @retval EFI_OUT_OF_RESOURCES   No enough pages to allocate.
  @retval EFI_SUCCESS            Pages successfully allocated.

**/
EFI_STATUS
EFIAPI
SmmAllocatePages (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory
  )
{
  EFI_STATUS  Status;
  BOOLEAN               NeedGuard;
  EFI_PHYSICAL_ADDRESS  BasePage;

  NeedGuard = FALSE;
  if (FeaturePcdGet(PcdHeapPageGuard)) {
    CheckGuardPages();
    if (IsAllocateTypeForHeapGuard(Type) && IsMemoryTypeForHeapPageGuard(MemoryType)) {
      NeedGuard = TRUE;
    }
  }

  Status = SmmInternalAllocatePages (Type, MemoryType, NumberOfPages, Memory, FALSE, NeedGuard);
  if (!EFI_ERROR (Status)) {
    SmmCoreUpdateProfile (
      (EFI_PHYSICAL_ADDRESS) (UINTN) RETURN_ADDRESS (0),
      MemoryProfileActionAllocatePages,
      MemoryType,
      EFI_PAGES_TO_SIZE (NumberOfPages),
      (VOID *) (UINTN) *Memory,
      NULL
      );
    if (FeaturePcdGet(PcdHeapPageGuard) && NeedGuard) {
      // we must defer heap guard here to avoid allocation re-entry issue.
      BasePage = *Memory - EFI_PAGES_TO_SIZE(1);
      SetMemoryPageAttributes (
        NULL,
        BasePage,
        EFI_PAGES_TO_SIZE(1),
        EFI_MEMORY_RP,
        AllocatePagesForGuard
        );
      BasePage = *Memory + EFI_PAGES_TO_SIZE(NumberOfPages);
      SetMemoryPageAttributes (
        NULL,
        BasePage,
        EFI_PAGES_TO_SIZE(1),
        EFI_MEMORY_RP,
        AllocatePagesForGuard
        );
    }
  }
  return Status;
}

/**
  Internal Function. Merge two adjacent nodes.

  @param  First             The first of two nodes to merge.

  @return Pointer to node after merge (if success) or pointer to next node (if fail).

**/
FREE_PAGE_LIST *
InternalMergeNodes (
  IN FREE_PAGE_LIST  *First
  )
{
  FREE_PAGE_LIST  *Next;

  Next = BASE_CR (First->Link.ForwardLink, FREE_PAGE_LIST, Link);
  ASSERT (
    TRUNCATE_TO_PAGES ((UINTN)Next - (UINTN)First) >= First->NumberOfPages);

  if (TRUNCATE_TO_PAGES ((UINTN)Next - (UINTN)First) == First->NumberOfPages) {
    First->NumberOfPages += Next->NumberOfPages;
    RemoveEntryList (&Next->Link);
    Next = First;
  }
  return Next;
}

EFI_MEMORY_TYPE
GetMemoryTypeFromAddress (
  IN EFI_PHYSICAL_ADDRESS  Address
  )
{
  LIST_ENTRY               *Link;
  MEMORY_MAP               *Entry;
  
  Link = gMemoryMap.ForwardLink;
  while (Link != &gMemoryMap) {
    Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    Link  = Link->ForwardLink;
    if (Entry->Start <= Address && Entry->End > Address) {
      return Entry->Type;
    }
  }
  ASSERT (FALSE);
  return EfiConventionalMemory;
}

/**
  Frees previous allocated pages.

  @param[in]  Memory                 Base address of memory being freed.
  @param[in]  NumberOfPages          The number of pages to free.
  @param[in]  AddRegion              If this memory is new added region.

  @retval EFI_NOT_FOUND          Could not find the entry that covers the range.
  @retval EFI_INVALID_PARAMETER  Address not aligned, Address is zero or NumberOfPages is zero.
  @return EFI_SUCCESS            Pages successfully freed.

**/
EFI_STATUS
SmmInternalFreePagesEx (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages,
  IN BOOLEAN               PoolPage,
  IN BOOLEAN               AddRegion,
  OUT EFI_MEMORY_TYPE      *MemoryType,
  OUT GUARD_OPERATION      *GuardOperation OPTIONAL
  )
{
  LIST_ENTRY      *Node;
  FREE_PAGE_LIST  *Pages;
  BOOLEAN         IsGuarded;
  EFI_MEMORY_TYPE Type;

  IsGuarded = FALSE;

  if (((Memory & EFI_PAGE_MASK) != 0) || (Memory == 0) || (NumberOfPages == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Pages = NULL;
  Node = mSmmMemoryMap.ForwardLink;
  while (Node != &mSmmMemoryMap) {
    Pages = BASE_CR (Node, FREE_PAGE_LIST, Link);
    if (Memory < (UINTN)Pages) {
      break;
    }
    Node = Node->ForwardLink;
  }

  if (Node != &mSmmMemoryMap &&
      Memory + EFI_PAGES_TO_SIZE (NumberOfPages) > (UINTN)Pages) {
    return EFI_INVALID_PARAMETER;
  }

  if (Node->BackLink != &mSmmMemoryMap) {
    Pages = BASE_CR (Node->BackLink, FREE_PAGE_LIST, Link);
    if ((UINTN)Pages + EFI_PAGES_TO_SIZE (Pages->NumberOfPages) > Memory) {
      return EFI_INVALID_PARAMETER;
    }
  }

  Pages = (FREE_PAGE_LIST*)(UINTN)Memory;
  Pages->NumberOfPages = NumberOfPages;
  InsertTailList (Node, &Pages->Link);

  if (Pages->Link.BackLink != &mSmmMemoryMap) {
    Pages = InternalMergeNodes (
              BASE_CR (Pages->Link.BackLink, FREE_PAGE_LIST, Link)
              );
  }

  if (Node != &mSmmMemoryMap) {
    InternalMergeNodes (Pages);
  }

  //
  // Update SmmMemoryMap here.
  //
  ConvertSmmMemoryMapEntry (EfiConventionalMemory, Memory, NumberOfPages, AddRegion);
  if (!AddRegion) {
    CoreFreeMemoryMapStack();
  }
  
  if (!AddRegion) {
    Type = GetMemoryTypeFromAddress (Memory);
    if (MemoryType != NULL) {
      *MemoryType = Type;
    }
    if (FeaturePcdGet(PcdHeapPageGuard)) {
      if (IsMemoryTypeForHeapPageGuard(Type)) {
        if (PoolPage) {
          ClearGuardPageOnFreePoolPages (Memory, NumberOfPages);
        } else {
          ClearGuardPageOnFreePages (Memory, NumberOfPages, GuardOperation);
        }
      }
    }
  }
  return EFI_SUCCESS;
}

/**
  Frees previous allocated pages.

  @param[in]  Memory                 Base address of memory being freed.
  @param[in]  NumberOfPages          The number of pages to free.

  @retval EFI_NOT_FOUND          Could not find the entry that covers the range.
  @retval EFI_INVALID_PARAMETER  Address not aligned, Address is zero or NumberOfPages is zero.
  @return EFI_SUCCESS            Pages successfully freed.

**/
EFI_STATUS
EFIAPI
SmmInternalFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages,
  IN BOOLEAN               PoolPage,
  OUT EFI_MEMORY_TYPE      *MemoryType,
  OUT GUARD_OPERATION      *GuardOperation OPTIONAL
  )
{
  return SmmInternalFreePagesEx (Memory, NumberOfPages, PoolPage, FALSE, MemoryType, GuardOperation);
}

/**
  Frees previous allocated pages.

  @param  Memory                 Base address of memory being freed.
  @param  NumberOfPages          The number of pages to free.

  @retval EFI_NOT_FOUND          Could not find the entry that covers the range.
  @retval EFI_INVALID_PARAMETER  Address not aligned, Address is zero or NumberOfPages is zero.
  @return EFI_SUCCESS            Pages successfully freed.

**/
EFI_STATUS
EFIAPI
SmmFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages
  )
{
  EFI_STATUS  Status;
  EFI_MEMORY_TYPE       MemoryType;
  GUARD_OPERATION       GuardOperation[4];
  UINTN                 Index;
  EFI_PHYSICAL_ADDRESS  BasePage;

  if (FeaturePcdGet(PcdHeapPageGuard)) {
    CheckGuardPages();
  }

  Status = SmmInternalFreePages (Memory, NumberOfPages, FALSE, &MemoryType, GuardOperation);
  if (!EFI_ERROR (Status)) {
    SmmCoreUpdateProfile (
      (EFI_PHYSICAL_ADDRESS) (UINTN) RETURN_ADDRESS (0),
      MemoryProfileActionFreePages,
      EfiMaxMemoryType,
      EFI_PAGES_TO_SIZE (NumberOfPages),
      (VOID *) (UINTN) Memory,
      NULL
      );
    if (FeaturePcdGet(PcdHeapPageGuard)) {
      // we must defer heap guard here to avoid allocation re-entry issue.
      if (IsMemoryTypeForHeapPageGuard(MemoryType)) {
        for (Index = 0; Index < 4; Index++) {
          switch(Index) {
          case 0:
            BasePage = Memory - EFI_PAGES_TO_SIZE(1);
            break;
          case 1:
            BasePage = Memory;
            break;
          case 2:
            BasePage = Memory + EFI_PAGES_TO_SIZE(NumberOfPages - 1);
            break;
          case 3:
            BasePage = Memory + EFI_PAGES_TO_SIZE(NumberOfPages);
            break;
          }
          switch(GuardOperation[Index]) {
          case GuardOperationSetGuard:
            SetMemoryPageAttributes (
              NULL,
              BasePage,
              EFI_PAGES_TO_SIZE(1),
              EFI_MEMORY_RP,
              AllocatePagesForGuard
              );
            break;
          case GuardOperationClearGuard:
            ClearMemoryPageAttributes (
              NULL,
              BasePage,
              EFI_PAGES_TO_SIZE(1),
              EFI_MEMORY_RP,
              AllocatePagesForGuard
              );
            break;
          case GuardOperationNoAction:
            break;
          default:
            ASSERT(FALSE);
            break;
          }
        }
      }
    }
  }
  return Status;
}

/**
  Add free SMRAM region for use by memory service.

  @param  MemBase                Base address of memory region.
  @param  MemLength              Length of the memory region.
  @param  Type                   Memory type.
  @param  Attributes             Memory region state.

**/
VOID
SmmAddMemoryRegion (
  IN  EFI_PHYSICAL_ADDRESS  MemBase,
  IN  UINT64                MemLength,
  IN  EFI_MEMORY_TYPE       Type,
  IN  UINT64                Attributes
  )
{
  UINTN  AlignedMemBase;

  //
  // Add EfiRuntimeServicesData for memory regions that is already allocated, needs testing, or needs ECC initialization
  //
  if ((Attributes & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
    Type = EfiRuntimeServicesData;
  } else {
    Type = EfiConventionalMemory;
  }

  DEBUG ((DEBUG_INFO, "SmmAddMemoryRegion\n"));
  DEBUG ((DEBUG_INFO, "  MemBase    - 0x%lx\n", MemBase));
  DEBUG ((DEBUG_INFO, "  MemLength  - 0x%lx\n", MemLength));
  DEBUG ((DEBUG_INFO, "  Type       - 0x%x\n", Type));
  DEBUG ((DEBUG_INFO, "  Attributes - 0x%lx\n", Attributes));

  //
  // Align range on an EFI_PAGE_SIZE boundary
  //
  AlignedMemBase = (UINTN)(MemBase + EFI_PAGE_MASK) & ~EFI_PAGE_MASK;
  MemLength -= AlignedMemBase - MemBase;
  if (Type == EfiConventionalMemory) {
    SmmInternalFreePagesEx (AlignedMemBase, TRUNCATE_TO_PAGES ((UINTN)MemLength), FALSE, TRUE, NULL, NULL);
  } else {
    ConvertSmmMemoryMapEntry (EfiRuntimeServicesData, AlignedMemBase, TRUNCATE_TO_PAGES ((UINTN)MemLength), TRUE);
  }

  CoreFreeMemoryMapStack ();
}

/**
  This function returns a copy of the current memory map. The map is an array of
  memory descriptors, each of which describes a contiguous block of memory.

  @param[in, out]  MemoryMapSize          A pointer to the size, in bytes, of the
                                          MemoryMap buffer. On input, this is the size of
                                          the buffer allocated by the caller.  On output,
                                          it is the size of the buffer returned by the
                                          firmware  if the buffer was large enough, or the
                                          size of the buffer needed  to contain the map if
                                          the buffer was too small.
  @param[in, out]  MemoryMap              A pointer to the buffer in which firmware places
                                          the current memory map.
  @param[out]      MapKey                 A pointer to the location in which firmware
                                          returns the key for the current memory map.
  @param[out]      DescriptorSize         A pointer to the location in which firmware
                                          returns the size, in bytes, of an individual
                                          EFI_MEMORY_DESCRIPTOR.
  @param[out]      DescriptorVersion      A pointer to the location in which firmware
                                          returns the version number associated with the
                                          EFI_MEMORY_DESCRIPTOR.

  @retval EFI_SUCCESS            The memory map was returned in the MemoryMap
                                 buffer.
  @retval EFI_BUFFER_TOO_SMALL   The MemoryMap buffer was too small. The current
                                 buffer size needed to hold the memory map is
                                 returned in MemoryMapSize.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.

**/
EFI_STATUS
EFIAPI
SmmCoreGetMemoryMap (
  IN OUT UINTN                  *MemoryMapSize,
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  OUT UINTN                     *MapKey,
  OUT UINTN                     *DescriptorSize,
  OUT UINT32                    *DescriptorVersion
  )
{
  UINTN                    Count;
  LIST_ENTRY               *Link;
  MEMORY_MAP               *Entry;
  UINTN                    Size;
  UINTN                    BufferSize;

  Size = sizeof (EFI_MEMORY_DESCRIPTOR);

  //
  // Make sure Size != sizeof(EFI_MEMORY_DESCRIPTOR). This will
  // prevent people from having pointer math bugs in their code.
  // now you have to use *DescriptorSize to make things work.
  //
  Size += sizeof(UINT64) - (Size % sizeof (UINT64));

  if (DescriptorSize != NULL) {
    *DescriptorSize = Size;
  }

  if (DescriptorVersion != NULL) {
    *DescriptorVersion = EFI_MEMORY_DESCRIPTOR_VERSION;
  }

  Count = GetSmmMemoryMapEntryCount ();
  BufferSize = Size * Count;
  if (*MemoryMapSize < BufferSize) {
    *MemoryMapSize = BufferSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  *MemoryMapSize = BufferSize;
  if (MemoryMap == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (MemoryMap, BufferSize);
  Link = gMemoryMap.ForwardLink;
  while (Link != &gMemoryMap) {
    Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    Link  = Link->ForwardLink;

    MemoryMap->Type           = Entry->Type;
    MemoryMap->PhysicalStart  = Entry->Start;
    MemoryMap->NumberOfPages  = RShiftU64 (Entry->End - Entry->Start + 1, EFI_PAGE_SHIFT);

    MemoryMap = NEXT_MEMORY_DESCRIPTOR (MemoryMap, Size);
  }

  return EFI_SUCCESS;
}
