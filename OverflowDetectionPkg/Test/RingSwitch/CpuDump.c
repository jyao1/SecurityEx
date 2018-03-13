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
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

#pragma pack (1)

VOID
DumpTss(
  IN IA32_TSS_DESCRIPTOR       *TssDesc
  )
{
  IA32_TASK_STATE_SEGMENT   *Tss;
  UINTN                     TssLimit;
  UINT32                    *BufferPtr;
  UINTN                     Index;
  UINTN                     Count;

#if defined (MDE_CPU_IA32)
  Tss = (VOID *)(UINTN)((TssDesc->Bits.BaseHigh << 24) | (TssDesc->Bits.BaseMid << 16) | TssDesc->Bits.BaseLow);
#elif defined (MDE_CPU_X64)
  Tss = (VOID *)(UINTN)(((UINTN)TssDesc->Bits.BaseHigh << 32) | (TssDesc->Bits.BaseMidh << 24) | (TssDesc->Bits.BaseMidl << 16) | TssDesc->Bits.BaseLow);
#endif
  TssLimit = (UINTN)((TssDesc->Bits.LimitHigh << 16) | TssDesc->Bits.LimitLow);
  if (TssDesc->Bits.G != 0) {
    TssLimit = (TssLimit << 12);
  }

#if defined (MDE_CPU_IA32)
  DEBUG((EFI_D_INFO, "    TSS: Base - 0x%08x, Limit - 0x%08x\n", Tss, TssLimit));
#elif defined (MDE_CPU_X64)
  DEBUG((EFI_D_INFO, "    TSS: Base - 0x%016lx, Limit - 0x%08x\n", Tss, TssLimit));
#endif

  if (Tss == NULL) {
    return;
  }

  BufferPtr = (VOID *)Tss;
  Count = (TssLimit + 1) / sizeof(*BufferPtr);
  for (Index = 0; Index < Count; Index++) {
    DEBUG((EFI_D_INFO, "    %3d: 0x%08x\n", Index * sizeof(*BufferPtr), BufferPtr[Index]));
  }
}

VOID
DumpGdt(
  VOID
  )
{
  UINTN                     Count;
  UINTN                     Index;
  IA32_DESCRIPTOR           GdtPtr;
  IA32_SEGMENT_DESCRIPTOR   *SegDesc;

  AsmReadGdtr(&GdtPtr);
#if defined (MDE_CPU_IA32)
  DEBUG((EFI_D_INFO, "GDTR: Base - 0x%08x, Limit - 0x%04x\n", GdtPtr.Base, GdtPtr.Limit));
#elif defined (MDE_CPU_X64)
  DEBUG((EFI_D_INFO, "GDTR: Base - 0x%016lx, Limit - 0x%04x\n", GdtPtr.Base, GdtPtr.Limit));
#endif
  SegDesc = (VOID *)GdtPtr.Base;
  Count = (GdtPtr.Limit + 1) / sizeof(IA32_SEGMENT_DESCRIPTOR);
  for (Index = 0; Index < Count; Index++) {
    DEBUG((EFI_D_INFO, "%02x: 0x%016lx (Type: 0x%x)\n", Index * sizeof(IA32_SEGMENT_DESCRIPTOR), SegDesc[Index].Uint64, SegDesc[Index].Bits.Type));
    if ((SegDesc[Index].Bits.P == 1) && (SegDesc[Index].Bits.S == 0) && ((SegDesc[Index].Bits.Type == 0x9) || (SegDesc[Index].Bits.Type == 0xB))  && (SegDesc[Index].Bits.DB == 0) && (SegDesc[Index].Bits.L == 0)) {
#if defined (MDE_CPU_X64)
      // TSS is expanded
      DEBUG((EFI_D_INFO, "    0x%016lx\n", SegDesc[Index + 1].Uint64));
#endif
      DumpTss((VOID *)&SegDesc[Index]);
#if defined (MDE_CPU_X64)
      // TSS is expanded
      Index++;
#endif
    }
  }
}

VOID
DumpIdt(
  VOID
  )
{
  UINTN                     Count;
  UINTN                     Index;
  IA32_DESCRIPTOR           Idtr;
  IA32_IDT_GATE_DESCRIPTOR  *IdtDesc;
  UINTN                     Handler;

  AsmReadIdtr(&Idtr);
#if defined (MDE_CPU_IA32)
  DEBUG((EFI_D_INFO, "IDTR: Base - 0x%08x, Limit - 0x%04x\n", Idtr.Base, Idtr.Limit));
#elif defined (MDE_CPU_X64)
  DEBUG((EFI_D_INFO, "IDTR: Base - 0x%016lx, Limit - 0x%04x\n", Idtr.Base, Idtr.Limit));
#endif
  IdtDesc = (VOID *)Idtr.Base;
  Count = (Idtr.Limit + 1) / sizeof(IA32_IDT_GATE_DESCRIPTOR);
  for (Index = 0; Index < Count; Index++) {
#if defined (MDE_CPU_IA32)
    DEBUG((EFI_D_INFO, "%02x: 0x%016lx (Type: 0x%x)\n", Index, IdtDesc[Index].Uint64, IdtDesc[Index].Bits.GateType));
#elif defined (MDE_CPU_X64)
    DEBUG((EFI_D_INFO, "%02x: 0x%016lx%016lx (Type: 0x%x)\n", Index, IdtDesc[Index].Uint128.Uint64_1, IdtDesc[Index].Uint128.Uint64, IdtDesc[Index].Bits.GateType));
#endif
    if (IdtDesc[Index].Bits.GateType == IA32_IDT_GATE_TYPE_TASK) {
      DEBUG((EFI_D_INFO, "    TSS: 0x%04x\n", IdtDesc[Index].Bits.Selector));
    } else {
#if defined (MDE_CPU_IA32)
      Handler = (IdtDesc[Index].Bits.OffsetHigh << 16) | IdtDesc[Index].Bits.OffsetLow;
      DEBUG((EFI_D_INFO, "    Handler: 0x%04x:0x%08x\n", IdtDesc[Index].Bits.Selector, Handler));
#elif defined (MDE_CPU_X64)
      Handler = ((UINTN)IdtDesc[Index].Bits.OffsetUpper << 32) | (IdtDesc[Index].Bits.OffsetHigh << 16) | IdtDesc[Index].Bits.OffsetLow;
      DEBUG((EFI_D_INFO, "    Handler: 0x%04x:0x%016lx (IST: 0x%x)\n", IdtDesc[Index].Bits.Selector, Handler, IdtDesc[Index].Bits.Reserved_0 & 0x7));
#endif
    }
  }
}

VOID
DumpCr(
  VOID
  )
{
#if defined (MDE_CPU_IA32)
  DEBUG((EFI_D_INFO, "CR0: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n", AsmReadCr0(), AsmReadCr3(), AsmReadCr4()));
#elif defined (MDE_CPU_X64)
  DEBUG((EFI_D_INFO, "CR0: 0x%016lx, CR3: 0x%016lx, CR4: 0x%016lx\n", AsmReadCr0(), AsmReadCr3(), AsmReadCr4()));
#endif
}

VOID
DumpArchStatus(
  VOID
  )
{
  DumpGdt();
  DumpIdt();
  DumpCr();
}
