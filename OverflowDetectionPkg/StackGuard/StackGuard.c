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

#pragma pack (1)

#define IA32_GDT_TYPE_TSS          0x89

#if defined (MDE_CPU_IA32)
typedef struct {
  UINT16    PreviousTaskLink;
  UINT16    Reserved_2;
  UINT32    ESP0;
  UINT16    SS0;
  UINT16    Reserved_10;
  UINT32    ESP1;
  UINT16    SS1;
  UINT16    Reserved_18;
  UINT32    ESP2;
  UINT16    SS2;
  UINT16    Reserved_26;
  UINT32    CR3;
  UINT32    EIP;
  UINT32    EFLAGS;
  UINT32    EAX;
  UINT32    ECX;
  UINT32    EDX;
  UINT32    EBX;
  UINT32    ESP;
  UINT32    EBP;
  UINT32    ESI;
  UINT32    EDI;
  UINT16    ES;
  UINT16    Reserved_74;
  UINT16    CS;
  UINT16    Reserved_78;
  UINT16    SS;
  UINT16    Reserved_82;
  UINT16    DS;
  UINT16    Reserved_86;
  UINT16    FS;
  UINT16    Reserved_90;
  UINT16    GS;
  UINT16    Reserved_94;
  UINT16    LDTSegmentSelector;
  UINT16    Reserved_98;
  UINT16    T;
  UINT16    IOMapBaseAddress;
} IA32_TASK_STATE_SEGMENT;
#endif

#if defined (MDE_CPU_X64)
typedef struct {
  UINT32    Reserved_0;
  UINT64    RSP0;
  UINT64    RSP1;
  UINT64    RSP2;
  UINT64    Reserved_28;
  UINT64    IST1;
  UINT64    IST2;
  UINT64    IST3;
  UINT64    IST4;
  UINT64    IST5;
  UINT64    IST6;
  UINT64    IST7;
  UINT64    Reserved_92;
  UINT16    Reserved_100;
  UINT16    IOMapBaseAddress;
} IA32_TASK_STATE_SEGMENT;
#endif

#if defined (MDE_CPU_IA32)
typedef struct {
  UINT16 Limit15_0;
  UINT16 Base15_0;
  UINT8  Base23_16;
  UINT8  Type;
  UINT8  Limit19_16_and_flags;
  UINT8  Base31_24;
} IA32_TSS_DESCRIPTOR;
#endif

#if defined (MDE_CPU_X64)
typedef struct {
  UINT16 Limit15_0;
  UINT16 Base15_0;
  UINT8  Base23_16;
  UINT8  Type;
  UINT8  Limit19_16_and_flags;
  UINT8  Base31_24;
  UINT32 Base63_32;
  UINT32 Reserved;
} IA32_TSS_DESCRIPTOR;
#endif

//
// Global Descriptor Entry structures
//

typedef struct _GDT_ENTRY {
  UINT16 Limit15_0;
  UINT16 Base15_0;
  UINT8  Base23_16;
  UINT8  Type;
  UINT8  Limit19_16_and_flags;
  UINT8  Base31_24;
} GDT_ENTRY;

typedef

struct {
#if defined (MDE_CPU_IA32)
  IA32_TSS_DESCRIPTOR           TssSeg;
  IA32_TSS_DESCRIPTOR           ExceptionTssSeg;
  IA32_TASK_STATE_SEGMENT       Tss;
  IA32_TASK_STATE_SEGMENT       ExceptionTss;
#elif defined (MDE_CPU_X64)
  IA32_TSS_DESCRIPTOR           TssSeg;
  IA32_TASK_STATE_SEGMENT       Tss;
#endif
} TSS_ENTRIES;

#pragma pack ()

#define TSS_SEL           OFFSET_OF (TSS_ENTRIES, TssSeg)
#if defined (MDE_CPU_IA32)
#define EXCEPTION_TSS_SEL OFFSET_OF (TSS_ENTRIES, ExceptionTssSeg)
#endif
#define TSS_OFFSET        OFFSET_OF (TSS_ENTRIES, Tss)

#define ADD_GDT_SIZE     TSS_OFFSET

UINTN  mOrgGdtSize;

/**
  Load the task register.

  @param  Selector  Value of task register.

**/
VOID
EFIAPI
LoadTask (
  UINT16 Selector
  );

/**
  Initialize Global Descriptor Table.
**/
VOID
InitGlobalDescriptorTable(
  VOID
  )
{
  VOID            *Gdt;
  IA32_DESCRIPTOR GdtPtr;

  AsmReadGdtr(&GdtPtr);
  Gdt = (VOID *)GdtPtr.Base;
  mOrgGdtSize = GdtPtr.Limit + 1;

  //
  // Allocate Runtime Data for the GDT
  //
  Gdt = AllocateRuntimeZeroPool(mOrgGdtSize + sizeof(TSS_ENTRIES) + 8);
  ASSERT(Gdt != NULL);
  Gdt = ALIGN_POINTER(Gdt, 8);

  //
  // Initialize all GDT entries
  //
  CopyMem(Gdt, (VOID *)GdtPtr.Base, mOrgGdtSize);

  //
  // Write GDT register
  //
  GdtPtr.Base = (UINTN)(VOID*)Gdt;
  GdtPtr.Limit = (UINT16)(mOrgGdtSize + ADD_GDT_SIZE - 1);
  AsmWriteGdtr(&GdtPtr);
}

UINTN
EnableStackGuard (
  OUT UINTN  *KnownGoodStackTop
  )
{
  EFI_STATUS                  Status;
  VOID                        *HobList;
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_MEMORY_ALLOCATION   *MemoryHob;
  UINTN                       StackBase;
  UINTN                       StackSize;

  Status = EfiGetSystemConfigurationTable(&gEfiHobListGuid, &HobList);
  ASSERT_EFI_ERROR(Status);

  StackBase = 0;
  StackSize = 0;
  for (Hob.Raw = HobList; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
    if (GET_HOB_TYPE(Hob) == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      MemoryHob = Hob.MemoryAllocation;
      if (CompareGuid(&gEfiHobMemoryAllocStackGuid, &MemoryHob->AllocDescriptor.Name)) {
        StackBase = (UINTN)MemoryHob->AllocDescriptor.MemoryBaseAddress;
        StackSize = (UINTN)MemoryHob->AllocDescriptor.MemoryLength;
        DEBUG((EFI_D_INFO, "Stack - 0x%x\n", StackBase, StackSize));
      }
    }
  }
  ASSERT(StackBase != 0);

  //
  // Reserve last 2 pages.
  // one is guard page and the other is known good stack.
  //
  // +--------------------------------------------+
  // | Known Good Stack | Guard Page | UEFI Stack |
  // +--------------------------------------------+
  //
  *KnownGoodStackTop = StackBase + EFI_PAGES_TO_SIZE(1);

  Status = SetMemoryPageAttributes(
             NULL,
             StackBase + EFI_PAGES_TO_SIZE(1),
             EFI_PAGES_TO_SIZE(1),
             EFI_MEMORY_RP,
             AllocatePages
             );
  DEBUG((EFI_D_INFO, "SetMemoryPageAttributes - %r\n", Status));

  return Status;
}

/**
  Initialize stack guard.
**/
EFI_STATUS
InitStackGuard(
  VOID
  )
{
  EFI_STATUS                Status;
  UINTN                     KnownGoodStackTop;
  IA32_DESCRIPTOR           Idtr;
  IA32_IDT_GATE_DESCRIPTOR  *IdtDesc;
  TSS_ENTRIES               *TssEntry;
  IA32_DESCRIPTOR           GdtPtr;
#if defined (MDE_CPU_IA32)
  UINT32                    PageFaultHandler;
#endif
  UINTN                     TssBase;

  DEBUG((EFI_D_INFO, "InitStackGuard ...\n"));

  Status = EnableStackGuard(&KnownGoodStackTop);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  DEBUG((EFI_D_INFO, "KnownGoodStackTop - 0x%x\n", KnownGoodStackTop));
  
  //
  // Patch IDT
  //
  AsmReadIdtr(&Idtr);
#if defined (MDE_CPU_IA32)
  IdtDesc = (VOID *)Idtr.Base;
  PageFaultHandler = (IdtDesc[14].Bits.OffsetHigh << 16) | IdtDesc[14].Bits.OffsetLow;
  IdtDesc[14].Bits.OffsetLow = 0;
  IdtDesc[14].Bits.Selector = mOrgGdtSize + EXCEPTION_TSS_SEL; // TSS Segment selector
  IdtDesc[14].Bits.Reserved_0 = 0;
  IdtDesc[14].Bits.GateType = IA32_IDT_GATE_TYPE_TASK;
  IdtDesc[14].Bits.OffsetHigh = 0;
#elif defined (MDE_CPU_X64)
  IdtDesc = (VOID *)Idtr.Base;
  IdtDesc[14].Bits.Reserved_0 = 1; // set the IST field to 1
#endif
  AsmWriteIdtr(&Idtr);

  //
  // Fixup TSS descriptors
  //
  AsmReadGdtr (&GdtPtr);
  TssEntry = (VOID *)(GdtPtr.Base + mOrgGdtSize);
#if defined (MDE_CPU_IA32)
  TssBase = (UINTN)(VOID *)&TssEntry->Tss;
  TssEntry->TssSeg.Limit15_0            = sizeof(IA32_TASK_STATE_SEGMENT) - 1;
  TssEntry->TssSeg.Base15_0             = (UINT16)TssBase;
  TssEntry->TssSeg.Base23_16            = (UINT8)(TssBase >> 16);
  TssEntry->TssSeg.Type                 = IA32_GDT_TYPE_TSS;
  TssEntry->TssSeg.Limit19_16_and_flags = 0;
  TssEntry->TssSeg.Base31_24            = (UINT8)(TssBase >> 24);
  TssBase = (UINTN)(VOID *)&TssEntry->ExceptionTss;
  TssEntry->ExceptionTssSeg.Limit15_0            = sizeof(IA32_TASK_STATE_SEGMENT) - 1;
  TssEntry->ExceptionTssSeg.Base15_0             = (UINT16)TssBase;
  TssEntry->ExceptionTssSeg.Base23_16            = (UINT8)(TssBase >> 16);
  TssEntry->ExceptionTssSeg.Type                 = 0x89;
  TssEntry->ExceptionTssSeg.Limit19_16_and_flags = 0;
  TssEntry->ExceptionTssSeg.Base31_24            = (UINT8)(TssBase >> 24);
#elif defined (MDE_CPU_X64)
  TssBase = (UINTN)(VOID *)&TssEntry->Tss;
  TssEntry->TssSeg.Limit15_0            = sizeof(IA32_TASK_STATE_SEGMENT) - 1;
  TssEntry->TssSeg.Base15_0             = (UINT16)TssBase;
  TssEntry->TssSeg.Base23_16            = (UINT8)(TssBase >> 16);
  TssEntry->TssSeg.Type                 = IA32_GDT_TYPE_TSS;
  TssEntry->TssSeg.Limit19_16_and_flags = 0;
  TssEntry->TssSeg.Base31_24            = (UINT8)(TssBase >> 24);
  TssEntry->TssSeg.Base63_32            = (UINT32)(TssBase >> 32);
  TssEntry->TssSeg.Reserved             = 0;
#endif

  //
  // Fixup TSS segments
  //
#if defined (MDE_CPU_IA32)
  DEBUG((EFI_D_INFO, "CR3 - 0x%x\n", AsmReadCr3()));
  TssEntry->ExceptionTss.CR3    = AsmReadCr3();
  TssEntry->ExceptionTss.EIP    = PageFaultHandler;
  TssEntry->ExceptionTss.EFLAGS = 0x2;
  TssEntry->ExceptionTss.ESP    = KnownGoodStackTop;
  TssEntry->ExceptionTss.ES     = AsmReadDs();
  TssEntry->ExceptionTss.CS     = AsmReadCs();
  TssEntry->ExceptionTss.SS     = AsmReadSs();
  TssEntry->ExceptionTss.DS     = AsmReadDs();
  TssEntry->ExceptionTss.FS     = AsmReadFs();
  TssEntry->ExceptionTss.GS     = AsmReadGs();
#elif defined (MDE_CPU_X64)
  TssEntry->Tss.IST1 = KnownGoodStackTop;
#endif
  AsmWriteGdtr (&GdtPtr);

  //
  // Load task register
  //
  LoadTask((UINT16)(mOrgGdtSize + TSS_SEL));

  DEBUG((EFI_D_INFO, "InitStackGuard Done\n"));

  return EFI_SUCCESS;
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
  Initialize stack guard.

  @param ImageHandle     Image handle this driver.
  @param SystemTable     Pointer to the System Table.

  @retval EFI_SUCCESS           Thread can be successfully created
  @retval EFI_OUT_OF_RESOURCES  Cannot allocate protocol data structure
  @retval EFI_DEVICE_ERROR      Cannot create the thread

**/
EFI_STATUS
EFIAPI
StackGuardEntrypoint(
  IN EFI_HANDLE                            ImageHandle,
  IN EFI_SYSTEM_TABLE                      *SystemTable
  )
{
#if defined (MDE_CPU_IA32)
  if (AsmReadCr3() == 0) {
    CreateIa32Paging();
  }
#endif
  
  InitGlobalDescriptorTable();
  if (FeaturePcdGet(PcdCpuStackGuard)) {
    //
    // Set stack guard
    //
    InitStackGuard();
  }
  return EFI_SUCCESS;
}
