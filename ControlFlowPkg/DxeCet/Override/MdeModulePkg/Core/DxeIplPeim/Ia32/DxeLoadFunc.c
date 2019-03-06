/** @file
  Ia32-specific functionality for DxeLoad.

Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "DxeIpl.h"
#include "VirtualMemory.h"


VOID
EFIAPI
DxeCoreEntryPointTrampline (
  IN VOID  *HobList,
  IN UINTN DxeCoreEntryPoint
  );

//
// CET definition
//
#define CPUID_CET_SS   BIT7
#define CPUID_CET_IBT  BIT20

#define CPUID_CET_XSS_U  BIT11
#define CPUID_CET_XSS_S  BIT12

#define CR4_CET_ENABLE  BIT23

#define MSR_IA32_XSS                       0xDA0

#define MSR_IA32_S_CET                     0x6A2
#define MSR_IA32_PL0_SSP                   0x6A4
#define MSR_IA32_INTERRUPT_SSP_TABLE_ADDR  0x6A8

typedef union {
  struct {
    // enable shadow stacks
    UINT32  SH_STK_ENP:1;
    // enable the WRSS{D,Q}W instructions.
    UINT32  WR_SHSTK_EN:1;
    // enable tracking of indirect call/jmp targets to be ENDBRANCH instruction.
    UINT32  ENDBR_EN:1;
    // enable legacy compatibility treatment for indirect call/jmp tracking.
    UINT32  LEG_IW_EN:1;
    // enable use of no-track prefix on indirect call/jmp.
    UINT32  NO_TRACK_EN:1;
    // disable suppression of CET indirect branch tracking on legacy compatibility.
    UINT32  SUPPRESS_DIS:1;
    UINT32  RSVD:4;
    // indirect branch tracking is suppressed.
    // This bit can be written to 1 only if TRACKER is written as IDLE.
    UINT32  SUPPRESS:1;
    // Value of the endbranch state machine
    // Values: IDLE (0), WAIT_FOR_ENDBRANCH(1).
    UINT32  TRACKER:1;
    // linear address of a bitmap in memory indicating valid
    // pages as target of CALL/JMP_indirect that do not land on ENDBRANCH when CET is enabled
    // and not suppressed. Valid when ENDBR_EN is 1. Must be machine canonical when written on
    // parts that support 64 bit mode. On parts that do not support 64 bit mode, the bits 63:32 are
    // reserved and must be 0. This value is extended by 12 bits at the low end to form the base address
    // (this automatically aligns the address on a 4-Kbyte boundary).
    UINT32  EB_LEG_BITMAP_BASE_low:12;
    UINT32  EB_LEG_BITMAP_BASE_high:32;
  } Bits;
  UINT64   Uint64;
} MSR_IA32_CET;

#define PAGING_PAE_INDEX_MASK  0x1FF
#define PAGING_4K_ADDRESS_MASK_64 0x000FFFFFFFFFF000ull

#define IA32_PG_U                   (1u << 2)
#define IA32_PG_WT                  (1u << 3)
#define IA32_PG_CD                  (1u << 4)
#define IA32_PG_A                   (1u << 5)
#define IA32_PG_D                   (1u << 6)
#define IA32_PG_G                   (1u << 8)
#define IA32_PG_PAT_2M              (1u << 12)
#define IA32_PG_PAT_4K              IA32_PG_PS
#define IA32_PG_NX                  (1ull << 63)

BOOLEAN  PcdCpuStackGuard = TRUE;
UINTN    PcdCpuShadowStackSize = SIZE_16KB;
BOOLEAN  PcdCpuCetXssEnable = TRUE;

BOOLEAN  mCetSupported = FALSE;
BOOLEAN  mCetXssSupported = FALSE;
UINTN    mShadowStacks;
UINTN    mShadowStackSize;

UINTN  mInterruptSspTables;

BOOLEAN
ToSplitPageTableForCet (
  IN EFI_PHYSICAL_ADDRESS               Address,
  IN UINTN                              Size
  )
{
  UINTN  ShadowStackGuardSize;

  if (((PcdGet32(PcdControlFlowEnforcementPropertyMask) & 0x2) != 0) && mCetSupported) {
    if (PcdCpuStackGuard) {
      ShadowStackGuardSize = EFI_PAGES_TO_SIZE (2);
    } else {
      ShadowStackGuardSize = 0;
    }
#if 0
    if ((Address == (mShadowStacks & ~(SIZE_2MB - 1))) ||
        (Address == ((mShadowStacks + mShadowStackSize + ShadowStackGuardSize) & ~(SIZE_2MB - 1)))) {
      DEBUG ((DEBUG_INFO, "SplitCet: Address - 0x%lx, Size - 0x%x\n", Address, Size));
      return TRUE;
    }
#endif
    if (((Address >= mShadowStacks) && (Address < mShadowStacks + mShadowStackSize + ShadowStackGuardSize)) ||
        ((mShadowStacks >= Address) && (mShadowStacks < Address + Size))) {
      DEBUG ((DEBUG_INFO, "SplitCet: Address - 0x%lx, Size - 0x%x\n", Address, Size));
      return TRUE;
    }
  }

  return FALSE;
}

VOID
InitShadowStack (
  VOID
  )
{
  UINT64  *InterruptSspTable;

  if (((PcdGet32(PcdControlFlowEnforcementPropertyMask) & 0x2) != 0) && PcdCpuStackGuard && mCetSupported) {
    mInterruptSspTables = (UINTN)AllocatePool(sizeof(UINT64) * 8);
    ASSERT (mInterruptSspTables != 0);
    DEBUG ((DEBUG_INFO, "mInterruptSspTables - 0x%x\n", mInterruptSspTables));

    InterruptSspTable = (UINT64 *)(UINTN)(mInterruptSspTables);
    InterruptSspTable[1] = (mShadowStacks + EFI_PAGES_TO_SIZE(1) - sizeof(UINT64));
    *(UINT64 *)(UINTN)InterruptSspTable[1] = InterruptSspTable[1]; // Create Token
  }
}

VOID
SetMemoryAttribute (
  IN UINTN                 PageTable,
  IN EFI_PHYSICAL_ADDRESS  Address,
  IN UINT64                AndMask,
  IN UINT64                OrMask
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

  DEBUG ((DEBUG_INFO, "SetMemoryAttribute - 0x%x\n", Address));

  Index4 = ((UINTN)RShiftU64 (Address, 39)) & PAGING_PAE_INDEX_MASK;
  Index3 = ((UINTN)Address >> 30) & PAGING_PAE_INDEX_MASK;
  Index2 = ((UINTN)Address >> 21) & PAGING_PAE_INDEX_MASK;
  Index1 = ((UINTN)Address >> 12) & PAGING_PAE_INDEX_MASK;

  L4PageTable = (UINT64 *)(UINTN)PageTable;
  ASSERT (L4PageTable[Index4] != 0);
  L3PageTable = (UINT64 *)(UINTN)(L4PageTable[Index4] & PAGING_4K_ADDRESS_MASK_64);
  ASSERT (L3PageTable[Index3] != 0);
  ASSERT ((L3PageTable[Index3] & IA32_PG_PS) == 0);
  L2PageTable = (UINT64 *)(UINTN)(L3PageTable[Index3] & PAGING_4K_ADDRESS_MASK_64);
  ASSERT (L2PageTable[Index2] != 0);
  ASSERT ((L2PageTable[Index2] & IA32_PG_PS) == 0);
  L1PageTable = (UINT64 *)(UINTN)(L2PageTable[Index2] & PAGING_4K_ADDRESS_MASK_64);
  ASSERT (L1PageTable[Index1] != 0);

  DEBUG ((DEBUG_INFO, "  L1PageTable[Index1] - 0x%x", L1PageTable[Index1]));
  L1PageTable[Index1] = (L1PageTable[Index1] & AndMask) | OrMask;
  DEBUG ((DEBUG_INFO, " <== 0x%x\n", L1PageTable[Index1]));
}

VOID
SetShadowStack (
  IN UINTN                 PageTable,
  IN EFI_PHYSICAL_ADDRESS  Address,
  IN UINT64                Size
  )
{
  UINTN  Index;
  for (Index = 0; Index < Size; Index += SIZE_4KB) {
    SetMemoryAttribute (PageTable, Address + Index, ~(UINT64)(IA32_PG_RW | IA32_PG_U), IA32_PG_D);
  }
}

VOID
SetNotPresentPage (
  IN UINTN                 PageTable,
  IN EFI_PHYSICAL_ADDRESS  Address,
  IN UINT64                Size
  )
{
  UINTN  Index;
  for (Index = 0; Index < Size; Index += SIZE_4KB) {
    SetMemoryAttribute (PageTable, Address + Index, ~(UINT64)IA32_PG_P, 0);
  }
}


VOID
EnableShadowStack (
  VOID
  )
{
  UINTN  InterruptSspTable;

  InterruptSspTable = (UINTN)(mInterruptSspTables);
  AsmWriteMsr64 (MSR_IA32_INTERRUPT_SSP_TABLE_ADDR, InterruptSspTable);
  DEBUG ((DEBUG_INFO, "MSR_IA32_INTERRUPT_SSP_TABLE_ADDR - 0x%x\n", InterruptSspTable));
}

VOID
InitCet (
  VOID
  )
{
  UINT32                     RegEax;
  UINT32                     RegEbx;
  UINT32                     RegEcx;
  UINTN                      ShadowStackGuardSize;
  UINTN                      Pl0Ssp;

  if (((PcdGet32(PcdControlFlowEnforcementPropertyMask) & 0x2) != 0)) {
    AsmCpuidEx(7, 0, NULL, NULL, &RegEcx, NULL);
    DEBUG ((EFI_D_INFO, "CPUID[7/0] ECX - 0x%08x\n", RegEcx));
    DEBUG ((EFI_D_INFO, "  CET_SS  - 0x%08x\n", RegEcx & CPUID_CET_SS));
    DEBUG ((EFI_D_INFO, "  CET_IBT - 0x%08x\n", RegEcx & CPUID_CET_IBT));
    if ((RegEcx & CPUID_CET_SS) != 0) {
      mCetSupported = TRUE;
    }
    AsmCpuidEx(0xD, 1, NULL, &RegEbx, &RegEcx, NULL);
    DEBUG ((EFI_D_INFO, "CPUID[D/1] EBX - 0x%08x, ECX - 0x%08x\n", RegEbx, RegEcx));
    if ((RegEcx & CPUID_CET_XSS_S) != 0) {
      mCetXssSupported = TRUE;
    }
    AsmCpuidEx(0xD, 11, &RegEax, NULL, &RegEcx, NULL);
    DEBUG ((EFI_D_INFO, "CPUID[D/11] EAX - 0x%08x, ECX - 0x%08x\n", RegEax, RegEcx));
    AsmCpuidEx(0xD, 12, &RegEax, NULL, &RegEcx, NULL);
    DEBUG ((EFI_D_INFO, "CPUID[D/12] EAX - 0x%08x, ECX - 0x%08x\n", RegEax, RegEcx));
  }

  if (((PcdGet32(PcdControlFlowEnforcementPropertyMask) & 0x2) != 0) && mCetSupported) {
    mShadowStackSize = EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (PcdCpuShadowStackSize));
    if (PcdCpuStackGuard) {
      ShadowStackGuardSize = EFI_PAGES_TO_SIZE (2);
    } else {
      ShadowStackGuardSize = 0;
    }

    mShadowStacks = (UINTN)AllocatePages(EFI_SIZE_TO_PAGES(mShadowStackSize + ShadowStackGuardSize));
    ASSERT (mShadowStacks != 0);
    DEBUG ((DEBUG_INFO, "mShadowStacks - 0x%x\n", mShadowStacks));
    DEBUG ((DEBUG_INFO, "mShadowStackSize - 0x%x\n", mShadowStackSize));

    Pl0Ssp = (UINTN)(mShadowStacks + mShadowStackSize + ShadowStackGuardSize - sizeof(UINT64));
    *(UINT64 *)(UINTN)Pl0Ssp = Pl0Ssp; // Create Token

    InitShadowStack ();
  }
}

VOID
EnableCet (
  IN UINTN                           PageTables
  )
{
  UINTN   Pl0Ssp;
  UINTN   ShadowStackGuardSize;

  DEBUG ((DEBUG_INFO, "EnableCet\n"));

    if (PcdCpuStackGuard) {
      ShadowStackGuardSize = EFI_PAGES_TO_SIZE (2);
    } else {
      ShadowStackGuardSize = 0;
    }

  if (((PcdGet32(PcdControlFlowEnforcementPropertyMask) & 0x2) != 0) && mCetSupported) {
    SetShadowStack (
      PageTables,
      (EFI_PHYSICAL_ADDRESS)(UINTN)mShadowStacks,
      mShadowStackSize + ShadowStackGuardSize
      );
    if (PcdCpuStackGuard) {
      SetNotPresentPage (
        PageTables,
        (EFI_PHYSICAL_ADDRESS)(UINTN)mShadowStacks + EFI_PAGES_TO_SIZE(1),
        EFI_PAGES_TO_SIZE(1)
        );
    }
  }

  AsmWriteMsr64 (MSR_IA32_S_CET, 1);
  DEBUG ((DEBUG_INFO, "MSR_IA32_S_CET - 1\n"));

  Pl0Ssp = (UINTN)(mShadowStacks + mShadowStackSize + ShadowStackGuardSize - sizeof(UINT64));
  AsmWriteMsr64 (MSR_IA32_PL0_SSP, Pl0Ssp);
  DEBUG ((DEBUG_INFO, "MSR_IA32_PL0_SSP - 0x%x\n", Pl0Ssp));

  if (PcdCpuCetXssEnable && mCetXssSupported) {
    AsmWriteMsr64 (MSR_IA32_XSS, AsmReadMsr64 (MSR_IA32_XSS) | BIT12);
  }

  EnableShadowStack ();
}


#define IDT_ENTRY_COUNT       32

typedef struct _X64_IDT_TABLE {
  //
  // Reserved 4 bytes preceding PeiService and IdtTable,
  // since IDT base address should be 8-byte alignment.
  //
  UINT32                   Reserved;
  CONST EFI_PEI_SERVICES   **PeiService;
  X64_IDT_GATE_DESCRIPTOR  IdtTable[IDT_ENTRY_COUNT];
} X64_IDT_TABLE;

//
// Global Descriptor Table (GDT)
//
GLOBAL_REMOVE_IF_UNREFERENCED IA32_GDT gGdtEntries[] = {
/* selector { Global Segment Descriptor                              } */
/* 0x00 */  {{0,      0,  0,  0,    0,  0,  0,  0,    0,  0, 0,  0,  0}}, //null descriptor
/* 0x08 */  {{0xffff, 0,  0,  0x2,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //linear data segment descriptor
/* 0x10 */  {{0xffff, 0,  0,  0xf,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //linear code segment descriptor
/* 0x18 */  {{0xffff, 0,  0,  0x3,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //system data segment descriptor
/* 0x20 */  {{0xffff, 0,  0,  0xa,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //system code segment descriptor
/* 0x28 */  {{0,      0,  0,  0,    0,  0,  0,  0,    0,  0, 0,  0,  0}}, //spare segment descriptor
/* 0x30 */  {{0xffff, 0,  0,  0x2,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //system data segment descriptor
/* 0x38 */  {{0xffff, 0,  0,  0xa,  1,  0,  1,  0xf,  0,  1, 0,  1,  0}}, //system code segment descriptor
/* 0x40 */  {{0,      0,  0,  0,    0,  0,  0,  0,    0,  0, 0,  0,  0}}, //spare segment descriptor
};

//
// IA32 Gdt register
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST IA32_DESCRIPTOR gGdt = {
  sizeof (gGdtEntries) - 1,
  (UINTN) gGdtEntries
  };

GLOBAL_REMOVE_IF_UNREFERENCED  IA32_DESCRIPTOR gLidtDescriptor = {
  sizeof (X64_IDT_GATE_DESCRIPTOR) * IDT_ENTRY_COUNT - 1,
  0
};

/**
  Allocates and fills in the Page Directory and Page Table Entries to
  establish a 4G page table.

  @param[in] StackBase  Stack base address.
  @param[in] StackSize  Stack size.

  @return The address of page table.

**/
UINTN
Create4GPageTablesIa32Pae (
  IN EFI_PHYSICAL_ADDRESS   StackBase,
  IN UINTN                  StackSize
  )
{
  UINT8                                         PhysicalAddressBits;
  EFI_PHYSICAL_ADDRESS                          PhysicalAddress;
  UINTN                                         IndexOfPdpEntries;
  UINTN                                         IndexOfPageDirectoryEntries;
  UINT32                                        NumberOfPdpEntriesNeeded;
  PAGE_MAP_AND_DIRECTORY_POINTER                *PageMap;
  PAGE_MAP_AND_DIRECTORY_POINTER                *PageDirectoryPointerEntry;
  PAGE_TABLE_ENTRY                              *PageDirectoryEntry;
  UINTN                                         TotalPagesNum;
  UINTN                                         PageAddress;
  UINT64                                        AddressEncMask;

  //
  // Make sure AddressEncMask is contained to smallest supported address field
  //
  AddressEncMask = PcdGet64 (PcdPteMemoryEncryptionAddressOrMask) & PAGING_1G_ADDRESS_MASK_64;

  PhysicalAddressBits = 32;

  //
  // Calculate the table entries needed.
  //
  NumberOfPdpEntriesNeeded = (UINT32) LShiftU64 (1, (PhysicalAddressBits - 30));

  TotalPagesNum = NumberOfPdpEntriesNeeded + 1;
  PageAddress = (UINTN) AllocatePageTableMemory (TotalPagesNum);
  ASSERT (PageAddress != 0);

  PageMap = (VOID *) PageAddress;
  PageAddress += SIZE_4KB;

  PageDirectoryPointerEntry = PageMap;
  PhysicalAddress = 0;

  for (IndexOfPdpEntries = 0; IndexOfPdpEntries < NumberOfPdpEntriesNeeded; IndexOfPdpEntries++, PageDirectoryPointerEntry++) {
    //
    // Each Directory Pointer entries points to a page of Page Directory entires.
    // So allocate space for them and fill them in in the IndexOfPageDirectoryEntries loop.
    //
    PageDirectoryEntry = (VOID *) PageAddress;
    PageAddress += SIZE_4KB;

    //
    // Fill in a Page Directory Pointer Entries
    //
    PageDirectoryPointerEntry->Uint64 = (UINT64) (UINTN) PageDirectoryEntry | AddressEncMask;
    PageDirectoryPointerEntry->Bits.Present = 1;

    for (IndexOfPageDirectoryEntries = 0; IndexOfPageDirectoryEntries < 512; IndexOfPageDirectoryEntries++, PageDirectoryEntry++, PhysicalAddress += SIZE_2MB) {
      if ((IsNullDetectionEnabled () && PhysicalAddress == 0)
          || ((PhysicalAddress < StackBase + StackSize)
              && ((PhysicalAddress + SIZE_2MB) > StackBase))) {
        //
        // Need to split this 2M page that covers stack range.
        //
        Split2MPageTo4K (PhysicalAddress, (UINT64 *) PageDirectoryEntry, StackBase, StackSize);
      } else {
        //
        // Fill in the Page Directory entries
        //
        PageDirectoryEntry->Uint64 = (UINT64) PhysicalAddress | AddressEncMask;
        PageDirectoryEntry->Bits.ReadWrite = 1;
        PageDirectoryEntry->Bits.Present = 1;
        PageDirectoryEntry->Bits.MustBe1 = 1;
      }
    }
  }

  for (; IndexOfPdpEntries < 512; IndexOfPdpEntries++, PageDirectoryPointerEntry++) {
    ZeroMem (
      PageDirectoryPointerEntry,
      sizeof (PAGE_MAP_AND_DIRECTORY_POINTER)
      );
  }

  //
  // Protect the page table by marking the memory used for page table to be
  // read-only.
  //
  EnablePageTableProtection ((UINTN)PageMap, FALSE);

  return (UINTN) PageMap;
}

/**
  The function will check if IA32 PAE is supported.

  @retval TRUE      IA32 PAE is supported.
  @retval FALSE     IA32 PAE is not supported.

**/
BOOLEAN
IsIa32PaeSupport (
  VOID
  )
{
  UINT32            RegEax;
  UINT32            RegEdx;
  BOOLEAN           Ia32PaeSupport;

  Ia32PaeSupport = FALSE;
  AsmCpuid (0x0, &RegEax, NULL, NULL, NULL);
  if (RegEax >= 0x1) {
    AsmCpuid (0x1, NULL, NULL, NULL, &RegEdx);
    if ((RegEdx & BIT6) != 0) {
      Ia32PaeSupport = TRUE;
    }
  }

  return Ia32PaeSupport;
}

/**
  The function will check if page table should be setup or not.

  @retval TRUE      Page table should be created.
  @retval FALSE     Page table should not be created.

**/
BOOLEAN
ToBuildPageTable (
  VOID
  )
{
  if (!IsIa32PaeSupport ()) {
    return FALSE;
  }

  if (IsNullDetectionEnabled ()) {
    return TRUE;
  }

  if (PcdGet8 (PcdHeapGuardPropertyMask) != 0) {
    return TRUE;
  }

  if (PcdGetBool (PcdCpuStackGuard)) {
    return TRUE;
  }

  if (IsEnableNonExecNeeded ()) {
    return TRUE;
  }

  return FALSE;
}

/**
   Transfers control to DxeCore.

   This function performs a CPU architecture specific operations to execute
   the entry point of DxeCore with the parameters of HobList.
   It also installs EFI_END_OF_PEI_PPI to signal the end of PEI phase.

   @param DxeCoreEntryPoint         The entry point of DxeCore.
   @param HobList                   The start of HobList passed to DxeCore.

**/
VOID
HandOffToDxeCore (
  IN EFI_PHYSICAL_ADDRESS   DxeCoreEntryPoint,
  IN EFI_PEI_HOB_POINTERS   HobList
  )
{
  EFI_STATUS                Status;
  EFI_PHYSICAL_ADDRESS      BaseOfStack;
  EFI_PHYSICAL_ADDRESS      TopOfStack;
  UINTN                     PageTables;
  X64_IDT_GATE_DESCRIPTOR   *IdtTable;
  UINTN                     SizeOfTemplate;
  VOID                      *TemplateBase;
  EFI_PHYSICAL_ADDRESS      VectorAddress;
  UINT32                    Index;
  X64_IDT_TABLE             *IdtTableForX64;
  EFI_VECTOR_HANDOFF_INFO   *VectorInfo;
  EFI_PEI_VECTOR_HANDOFF_INFO_PPI *VectorHandoffInfoPpi;
  BOOLEAN                   BuildPageTablesIa32Pae;

  if (IsNullDetectionEnabled ()) {
    ClearFirst4KPage (HobList.Raw);
  }

  Status = PeiServicesAllocatePages (EfiBootServicesData, EFI_SIZE_TO_PAGES (STACK_SIZE), &BaseOfStack);
  ASSERT_EFI_ERROR (Status);

  if (FeaturePcdGet(PcdDxeIplSwitchToLongMode)) {
    //
    // Compute the top of the stack we were allocated, which is used to load X64 dxe core.
    // Pre-allocate a 32 bytes which confroms to x64 calling convention.
    //
    // The first four parameters to a function are passed in rcx, rdx, r8 and r9.
    // Any further parameters are pushed on the stack. Furthermore, space (4 * 8bytes) for the
    // register parameters is reserved on the stack, in case the called function
    // wants to spill them; this is important if the function is variadic.
    //
    TopOfStack = BaseOfStack + EFI_SIZE_TO_PAGES (STACK_SIZE) * EFI_PAGE_SIZE - 32;

    //
    //  x64 Calling Conventions requires that the stack must be aligned to 16 bytes
    //
    TopOfStack = (EFI_PHYSICAL_ADDRESS) (UINTN) ALIGN_POINTER (TopOfStack, 16);

    DEBUG ((DEBUG_INFO, "Stack: 0x%lx ~ 0x%lx\n", BaseOfStack, TopOfStack));

    InitCet ();

    //
    // Load the GDT of Go64. Since the GDT of 32-bit Tiano locates in the BS_DATA
    // memory, it may be corrupted when copying FV to high-end memory
    //
    AsmWriteGdtr (&gGdt);
    //
    // Create page table and save PageMapLevel4 to CR3
    //
    PageTables = CreateIdentityMappingPageTables (BaseOfStack, STACK_SIZE);

    //
    // End of PEI phase signal
    //
    PERF_EVENT_SIGNAL_BEGIN (gEndOfPeiSignalPpi.Guid);
    Status = PeiServicesInstallPpi (&gEndOfPeiSignalPpi);
    PERF_EVENT_SIGNAL_END (gEndOfPeiSignalPpi.Guid);
    ASSERT_EFI_ERROR (Status);

    //
    // Paging might be already enabled. To avoid conflict configuration,
    // disable paging first anyway.
    //
    AsmWriteCr0 (AsmReadCr0 () & (~BIT31));
    AsmWriteCr3 (PageTables);

    DEBUG ((DEBUG_INFO, "PageTables - 0x%x\n", PageTables));

    EnableCet (PageTables);

    //
    // Update the contents of BSP stack HOB to reflect the real stack info passed to DxeCore.
    //
    UpdateStackHob (BaseOfStack, STACK_SIZE);

    SizeOfTemplate = AsmGetVectorTemplatInfo (&TemplateBase);

    Status = PeiServicesAllocatePages (
               EfiBootServicesData,
               EFI_SIZE_TO_PAGES(sizeof (X64_IDT_TABLE) + SizeOfTemplate * IDT_ENTRY_COUNT),
               &VectorAddress
               );
    ASSERT_EFI_ERROR (Status);

    //
    // Store EFI_PEI_SERVICES** in the 4 bytes immediately preceding IDT to avoid that
    // it may not be gotten correctly after IDT register is re-written.
    //
    IdtTableForX64 = (X64_IDT_TABLE *) (UINTN) VectorAddress;
    IdtTableForX64->PeiService = GetPeiServicesTablePointer ();

    VectorAddress = (EFI_PHYSICAL_ADDRESS) (UINTN) (IdtTableForX64 + 1);
    IdtTable      = IdtTableForX64->IdtTable;
    for (Index = 0; Index < IDT_ENTRY_COUNT; Index++) {
      IdtTable[Index].Ia32IdtEntry.Bits.GateType    =  0x8e;
      IdtTable[Index].Ia32IdtEntry.Bits.Reserved_0  =  0;
      IdtTable[Index].Ia32IdtEntry.Bits.Selector    =  SYS_CODE64_SEL;

      IdtTable[Index].Ia32IdtEntry.Bits.OffsetLow   = (UINT16) VectorAddress;
      IdtTable[Index].Ia32IdtEntry.Bits.OffsetHigh  = (UINT16) (RShiftU64 (VectorAddress, 16));
      IdtTable[Index].Offset32To63                  = (UINT32) (RShiftU64 (VectorAddress, 32));
      IdtTable[Index].Reserved                      = 0;

      CopyMem ((VOID *) (UINTN) VectorAddress, TemplateBase, SizeOfTemplate);
      AsmVectorFixup ((VOID *) (UINTN) VectorAddress, (UINT8) Index);

      VectorAddress += SizeOfTemplate;
    }

    gLidtDescriptor.Base = (UINTN) IdtTable;

    //
    // Disable interrupt of Debug timer, since new IDT table cannot handle it.
    //
    SaveAndSetDebugTimerInterrupt (FALSE);

    AsmWriteIdtr (&gLidtDescriptor);

    DEBUG ((
      DEBUG_INFO,
      "%a() Stack Base: 0x%lx, Stack Size: 0x%x\n",
      __FUNCTION__,
      BaseOfStack,
      STACK_SIZE
      ));

    //
    // Go to Long Mode and transfer control to DxeCore.
    // Interrupts will not get turned on until the CPU AP is loaded.
    // Call x64 drivers passing in single argument, a pointer to the HOBs.
    //
    if (((PcdGet32(PcdControlFlowEnforcementPropertyMask) & 0x2) != 0) && mCetSupported) {
      AsmEnablePaging64 (
        SYS_CODE64_SEL,
        (EFI_PHYSICAL_ADDRESS)(UINTN)DxeCoreEntryPointTrampline,
        (EFI_PHYSICAL_ADDRESS)(UINTN)(HobList.Raw),
        DxeCoreEntryPoint,
        TopOfStack
        );
    } else {
      AsmEnablePaging64 (
        SYS_CODE64_SEL,
        DxeCoreEntryPoint,
        (EFI_PHYSICAL_ADDRESS)(UINTN)(HobList.Raw),
        0,
        TopOfStack
        );
    }
  } else {
    //
    // Get Vector Hand-off Info PPI and build Guided HOB
    //
    Status = PeiServicesLocatePpi (
               &gEfiVectorHandoffInfoPpiGuid,
               0,
               NULL,
               (VOID **)&VectorHandoffInfoPpi
               );
    if (Status == EFI_SUCCESS) {
      DEBUG ((EFI_D_INFO, "Vector Hand-off Info PPI is gotten, GUIDed HOB is created!\n"));
      VectorInfo = VectorHandoffInfoPpi->Info;
      Index = 1;
      while (VectorInfo->Attribute != EFI_VECTOR_HANDOFF_LAST_ENTRY) {
        VectorInfo ++;
        Index ++;
      }
      BuildGuidDataHob (
        &gEfiVectorHandoffInfoPpiGuid,
        VectorHandoffInfoPpi->Info,
        sizeof (EFI_VECTOR_HANDOFF_INFO) * Index
        );
    }

    //
    // Compute the top of the stack we were allocated. Pre-allocate a UINTN
    // for safety.
    //
    TopOfStack = BaseOfStack + EFI_SIZE_TO_PAGES (STACK_SIZE) * EFI_PAGE_SIZE - CPU_STACK_ALIGNMENT;
    TopOfStack = (EFI_PHYSICAL_ADDRESS) (UINTN) ALIGN_POINTER (TopOfStack, CPU_STACK_ALIGNMENT);

    PageTables = 0;
    BuildPageTablesIa32Pae = ToBuildPageTable ();
    if (BuildPageTablesIa32Pae) {
      PageTables = Create4GPageTablesIa32Pae (BaseOfStack, STACK_SIZE);
      if (IsEnableNonExecNeeded ()) {
        EnableExecuteDisableBit();
      }
    }

    //
    // End of PEI phase signal
    //
    PERF_EVENT_SIGNAL_BEGIN (gEndOfPeiSignalPpi.Guid);
    Status = PeiServicesInstallPpi (&gEndOfPeiSignalPpi);
    PERF_EVENT_SIGNAL_END (gEndOfPeiSignalPpi.Guid);
    ASSERT_EFI_ERROR (Status);

    if (BuildPageTablesIa32Pae) {
      //
      // Paging might be already enabled. To avoid conflict configuration,
      // disable paging first anyway.
      //
      AsmWriteCr0 (AsmReadCr0 () & (~BIT31));
      AsmWriteCr3 (PageTables);
      //
      // Set Physical Address Extension (bit 5 of CR4).
      //
      AsmWriteCr4 (AsmReadCr4 () | BIT5);
    }

    //
    // Update the contents of BSP stack HOB to reflect the real stack info passed to DxeCore.
    //
    UpdateStackHob (BaseOfStack, STACK_SIZE);

    DEBUG ((
      DEBUG_INFO,
      "%a() Stack Base: 0x%lx, Stack Size: 0x%x\n",
      __FUNCTION__,
      BaseOfStack,
      STACK_SIZE
      ));

    //
    // Transfer the control to the entry point of DxeCore.
    //
    if (BuildPageTablesIa32Pae) {
      AsmEnablePaging32 (
        (SWITCH_STACK_ENTRY_POINT)(UINTN)DxeCoreEntryPoint,
        HobList.Raw,
        NULL,
        (VOID *) (UINTN) TopOfStack
        );
    } else {
      SwitchStack (
        (SWITCH_STACK_ENTRY_POINT)(UINTN)DxeCoreEntryPoint,
        HobList.Raw,
        NULL,
        (VOID *) (UINTN) TopOfStack
        );
    }
  }
}

