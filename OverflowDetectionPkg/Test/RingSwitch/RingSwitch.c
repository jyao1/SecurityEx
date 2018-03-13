/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Guid/Performance.h>

#pragma pack (1)

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

//
// Org: GDT:
//   00: 0000000000000000
//   08: 00CF92000000FFFF - data
//   10: 00CF9F000000FFFF - code32
//   18: 00CF93000000FFFF - data
//   20: 00CF9A000000FFFF - code32
//   28: 0000000000000000
//   30: 00CF93000000FFFF - data64
//   38: 00AF9B000000FFFF - code64
//   40: 0000000000000000
//
//
// New: GDT:
//   00: 0000000000000000
//   08: 00CF92000000FFFF - data32
//   10: 00CF9F000000FFFF - code32
//   18: 00CF93000000FFFF - data32
//   20: 00CF9A000000FFFF - code32
//   28: 0000000000000000
//   30: 00CF93000000FFFF - data64
//   38: 00AF9B000000FFFF - code64 <--
//   40: 00CF93000000FFFF - data64
//   48: 00CFFA000000FFFF - code32 - R3
//   50: 00CFF3000000FFFF - data32 - R3
//   58: 00AFFB000000FFFF - code64 - R3
//   60: 00CFF3000000FFFF - data64 - R3
//   68: 0000000000000000
//   70: 0000890000000068 - tss
//

typedef struct {
  GDT_ENTRY                     Null_0;
  GDT_ENTRY                     Data32_8;
  GDT_ENTRY                     Code32_10;
  GDT_ENTRY                     Data32_18;
  GDT_ENTRY                     Code32_20;
  GDT_ENTRY                     Null_28;
  GDT_ENTRY                     Data64_30;
  GDT_ENTRY                     Code64_38;
  GDT_ENTRY                     Data64_40;
  GDT_ENTRY                     R3Code32_48;
  GDT_ENTRY                     R3Data32_50;
  GDT_ENTRY                     R3Code64_58;
  GDT_ENTRY                     R3Data64_60;
  GDT_ENTRY                     Null_68;
  GDT_ENTRY                     TssSeg_70;
  IA32_TASK_STATE_SEGMENT       Tss;
} NEW_GDT;

NEW_GDT mNewGdt = {
  {0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00},
  {0xFFFF, 0x0000, 0x00, 0x92, 0xCF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0x9F, 0xCF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0x93, 0xCF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0x9A, 0xCF, 0x00},
  {0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00},
  {0xFFFF, 0x0000, 0x00, 0x93, 0xCF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0x9B, 0xAF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0x93, 0xCF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0xFA, 0xCF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0xF3, 0xCF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0xFB, 0xAF, 0x00},
  {0xFFFF, 0x0000, 0x00, 0xF3, 0xCF, 0x00},
  {0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00},
  {0x0068, 0x0000, 0x00, 0x89, 0x00, 0x00},
};

#pragma pack ()

#define TSS_SEL           OFFSET_OF (TSS_ENTRIES, TssSeg)
#define TSS_OFFSET        OFFSET_OF (TSS_ENTRIES, Tss)

#define ADD_GDT_SIZE     TSS_OFFSET

UINTN  mOrgGdtSize;

VOID
EFIAPI
RingSwitch (
  VOID
  );

VOID
DumpArchStatus(
  VOID
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
  Gdt = AllocatePages(EFI_SIZE_TO_PAGES(sizeof(mNewGdt)));
  ASSERT(Gdt != NULL);
  Gdt = ALIGN_POINTER(Gdt, 8);

  //
  // Initialize all GDT entries
  //
  CopyMem(Gdt, (VOID *)&mNewGdt, sizeof(mNewGdt));

  //
  // Write GDT register
  //
  GdtPtr.Base = (UINTN)(VOID*)Gdt;
  GdtPtr.Limit = (UINT16)(OFFSET_OF(NEW_GDT, Tss) - 1);
  AsmWriteGdtr(&GdtPtr);
}

VOID
PatchPaging (
  VOID
  )
{
  UINTN                             PageTable;
  UINT64                            *Pml4;
  UINT64                            *Pdpte;
  UINT64                            *Pde;
  UINT64                            *Pte;
  UINTN                             Pml4Index;
  UINTN                             PdpteIndex;
  UINTN                             PdeIndex;
  UINTN                             PteIndex;

  AsmWriteCr0 (AsmReadCr0() & ~BIT16);

  PageTable = AsmReadCr3 ();
  Pml4 = (UINT64 *)PageTable;
  for (Pml4Index = 0; Pml4Index < 512; Pml4Index++) {
    if (Pml4[Pml4Index] == 0) {
      continue;
    }
    Pml4[Pml4Index] = Pml4[Pml4Index] | BIT2;
    Pdpte = (UINT64 *)(UINTN)(Pml4[Pml4Index] & 0xFFFFFFFFFFFFF000);
    for (PdpteIndex = 0; PdpteIndex < 512; PdpteIndex++) {
      if (Pdpte[PdpteIndex] == 0) {
        continue;
      }
      Pdpte[PdpteIndex] = Pdpte[PdpteIndex] | BIT2;
      if ((Pdpte[PdpteIndex] & BIT7) != 0) {
        continue;
      }
      Pde = (UINT64 *)(UINTN)(Pdpte[PdpteIndex] & 0xFFFFFFFFFFFFF000);
      for (PdeIndex = 0; PdeIndex < 512; PdeIndex++) {
        if (Pde[PdeIndex] == 0) {
          continue;
        }
        Pde[PdeIndex] = Pde[PdeIndex] | BIT2;
        if ((Pde[PdeIndex] & BIT7) != 0) {
          continue;
        }
        Pte = (UINT64 *)(UINTN)(Pde[PdeIndex] & 0xFFFFFFFFFFFFF000);
        for (PteIndex = 0; PteIndex < 512; PteIndex++) {
          if (Pte[PteIndex] == 0) {
            continue;
          }
          Pte[PteIndex] = Pte[PteIndex] | BIT2;
        }
      }
    }    
  }
}

#define COUNT 1000

EFI_STATUS
EFIAPI
InitializeSmiPerf (
  VOID
  )
{
  UINT64                    StartTsc;
  UINT64                    EndTsc;
  UINTN                     Index;
  PERFORMANCE_PROPERTY      *PerformanceProperty;
  EFI_STATUS                Status;
  EFI_TPL                   OldTpl;

  OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);
  StartTsc = AsmReadTsc ();
  for (Index = 0; Index < COUNT; Index++) {
    RingSwitch();
  }
  EndTsc = AsmReadTsc ();
  gBS->RestoreTPL (OldTpl);
  
  Status = EfiGetSystemConfigurationTable (&gPerformanceProtocolGuid, (VOID *)&PerformanceProperty);
  if (EFI_ERROR (Status)) {
    Print (L"PERFORMANCE_PROPERTY not found!\n");
    return EFI_NOT_FOUND;
  } else {
    Print (L"PERFORMANCE_PROPERTY\n");
    Print (L"  Revision        - 0x%x\n", PerformanceProperty->Revision);
    Print (L"  TimerStartValue - %ld\n", PerformanceProperty->TimerStartValue);
    Print (L"  TimerEndValue   - %ld\n", PerformanceProperty->TimerEndValue);
    Print (L"  Frequency       - %ld\n", PerformanceProperty->Frequency);
  }

  Print (L"%d RingSwitch - %ld tick\n", COUNT, EndTsc - StartTsc);
  //
  // 1 SMI = (EndTsc - StartTsc)/COUNT * 1000 * 1000 / Frequency uS
  //       = 341115 * 1000 * 1000 / 1616844000
  //
  Print (L"RingSwitch - %ld us\n", DivU64x64Remainder (MultU64x64 (DivU64x32(EndTsc - StartTsc, COUNT), 1000 * 1000), PerformanceProperty->Frequency, NULL));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RingSwitchEntrypoint(
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  DumpArchStatus ();
  InitGlobalDescriptorTable();
  PatchPaging ();

  InitializeSmiPerf ();
  return EFI_SUCCESS;
}
