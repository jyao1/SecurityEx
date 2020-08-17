/** @file

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>

#include <Register/Msr.h>

#include <Protocol/Cpu.h>
#include <Protocol/UserModeThunk.h>

#define PAGING_4K_ADDRESS_MASK_64 0x000FFFFFFFFFF000ull
#define IA32_PG_U                   BIT2
#define IA32_PG_PS                  BIT7

#define IA32_DPL(x)  ((x) << 5)

typedef struct {
  IA32_SEGMENT_DESCRIPTOR   SystemCodeSegment;
  IA32_SEGMENT_DESCRIPTOR   SystemDataSegment;
  IA32_SEGMENT_DESCRIPTOR   Dummy1;
  IA32_SEGMENT_DESCRIPTOR   Dummy2;
  IA32_SEGMENT_DESCRIPTOR   UserCodeSegment;
  IA32_SEGMENT_DESCRIPTOR   UserDataSegment;
} ADDITIONAL_GDT_ENTRY;

#if defined (MDE_CPU_IA32)
ADDITIONAL_GDT_ENTRY mAddGdtEntry = {
//LimitLow, BaseLow, BaseMid, Type, S, DPL, P, LimitHigh, AVL, L, DB, G, BaseHigh,
  {{0xFFFF,     0x0,     0x0,  0xA, 1,   0, 1,       0xF, 0,   0,  1, 1,      0x0}}, // SystemCodeSegment
  {{0xFFFF,     0x0,     0x0,  0x2, 1,   0, 1,       0xF, 0,   0,  1, 1,      0x0}}, // SystemDataSegment
  {{0x0000,     0x0,     0x0,  0x0, 0,   0, 0,       0x0, 0,   0,  0, 0,      0x0}}, // Dummy1
  {{0x0000,     0x0,     0x0,  0x0, 0,   0, 0,       0x0, 0,   0,  0, 0,      0x0}}, // Dummy2
  {{0xFFFF,     0x0,     0x0,  0xA, 1,   3, 1,       0xF, 0,   0,  1, 1,      0x0}}, // UserCodeSegment
  {{0xFFFF,     0x0,     0x0,  0x2, 1,   3, 1,       0xF, 0,   0,  1, 1,      0x0}}, // UserDataSegment
};
#endif

#if defined (MDE_CPU_X64)
ADDITIONAL_GDT_ENTRY mAddGdtEntry = {
//LimitLow, BaseLow, BaseMid, Type, S, DPL, P, LimitHigh, AVL, L, DB, G, BaseHigh,
  {{0xFFFF,     0x0,     0x0,  0xA, 1,   0, 1,       0xF, 0,   1,  0, 1,      0x0}}, // SystemCodeSegment
  {{0xFFFF,     0x0,     0x0,  0x2, 1,   0, 1,       0xF, 0,   0,  1, 1,      0x0}}, // SystemDataSegment
  {{0x0000,     0x0,     0x0,  0x0, 0,   0, 0,       0x0, 0,   0,  0, 0,      0x0}}, // Dummy1
  {{0x0000,     0x0,     0x0,  0x0, 0,   0, 0,       0x0, 0,   0,  0, 0,      0x0}}, // Dummy2
  {{0xFFFF,     0x0,     0x0,  0xA, 1,   3, 1,       0xF, 0,   1,  0, 1,      0x0}}, // UserCodeSegment
  {{0xFFFF,     0x0,     0x0,  0x2, 1,   3, 1,       0xF, 0,   0,  1, 1,      0x0}}, // UserDataSegment
};
#endif

UINTN  mOrgGdtSize;
extern UINT32  AsmUserDs;
extern UINT32  AsmSystemDs;

#define  ADDITIONAL_GDT_ENTRY_SIZE  (sizeof(ADDITIONAL_GDT_ENTRY))
#define  SYSTEM_CODE_SEGMENT        (mOrgGdtSize + OFFSET_OF(ADDITIONAL_GDT_ENTRY, SystemCodeSegment))
#define  SYSTEM_DATA_SEGMENT        (mOrgGdtSize + OFFSET_OF(ADDITIONAL_GDT_ENTRY, SystemDataSegment))
#define  USER_CODE_SEGMENT          (mOrgGdtSize + OFFSET_OF(ADDITIONAL_GDT_ENTRY, UserCodeSegment))
#define  USER_DATA_SEGMENT          (mOrgGdtSize + OFFSET_OF(ADDITIONAL_GDT_ENTRY, UserDataSegment))

VOID
EFIAPI
AsmUserModeEnter (
  VOID
  );

VOID
EFIAPI
AsmUserModeExit (
  VOID
  );

VOID
EFIAPI
AsmSystemModeEnter (
  VOID
  );

EFI_CPU_ARCH_PROTOCOL  *mCpu;

EFI_STATUS
EFIAPI
UserModeEnter (
  IN USER_MODE_THUNK_PROTOCOL  *This
  )
{
  mCpu->DisableInterrupt (mCpu);
  AsmUserModeEnter ();
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UserModeExit (
  IN USER_MODE_THUNK_PROTOCOL  *This
  )
{
  AsmUserModeExit ();
  mCpu->EnableInterrupt (mCpu);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UserModeCall (
  IN USER_MODE_THUNK_PROTOCOL  *This,
  IN USER_MODE_THUNK_FUNCTION  EntryPoint,
  IN UINTN                     Param1,
  IN UINTN                     Param2,
  OUT EFI_STATUS               *RetStatus
  )
{
  UserModeEnter (This);
  *RetStatus = EntryPoint (Param1, Param2);
  UserModeExit (This);
  return EFI_SUCCESS;
}

VOID
InitUserModeGdt (
  VOID
  )
{
  ADDITIONAL_GDT_ENTRY     *AddGdtEntry;
  VOID                     *Gdt;
  IA32_DESCRIPTOR          GdtPtr;

  AsmReadGdtr(&GdtPtr);
  Gdt = (VOID *)GdtPtr.Base;
  mOrgGdtSize = GdtPtr.Limit + 1;

  //
  // Allocate Runtime Data for the GDT
  //
  Gdt = AllocateRuntimeZeroPool(mOrgGdtSize + ADDITIONAL_GDT_ENTRY_SIZE + 8);
  ASSERT(Gdt != NULL);
  Gdt = ALIGN_POINTER(Gdt, 8);

  //
  // Initialize all GDT entries
  //
  CopyMem(Gdt, (VOID *)GdtPtr.Base, mOrgGdtSize);
  AddGdtEntry = (ADDITIONAL_GDT_ENTRY *)((UINTN)GdtPtr.Base + mOrgGdtSize);
  CopyMem((VOID *)((UINTN)Gdt + mOrgGdtSize), &mAddGdtEntry, ADDITIONAL_GDT_ENTRY_SIZE);

  //
  // Write GDT register
  //
  GdtPtr.Base = (UINTN)(VOID*)Gdt;
  GdtPtr.Limit = (UINT16)(mOrgGdtSize + ADDITIONAL_GDT_ENTRY_SIZE - 1);
  AsmWriteGdtr(&GdtPtr);

  AsmSystemDs = (UINT32)SYSTEM_DATA_SEGMENT;
  AsmUserDs = (UINT32)(USER_DATA_SEGMENT + 3);
}

VOID
InitUserModeIdt (
  VOID
  )
{
  IA32_IDT_GATE_DESCRIPTOR *IdtEntry;
  IA32_DESCRIPTOR          IdtPtr;
  UINTN                    Index;

  AsmReadIdtr(&IdtPtr);
  IdtEntry = (IA32_IDT_GATE_DESCRIPTOR *)IdtPtr.Base;
  for (Index = 0; Index < (IdtPtr.Limit + 1) / sizeof(IA32_IDT_GATE_DESCRIPTOR); Index++) {
    IdtEntry[Index].Bits.GateType |= IA32_DPL(3);
//    IdtEntry[Index].Bits.Selector |= 0;
  }
  AsmWriteIdtr(&IdtPtr);
}

VOID
InitUserModePaging (
  VOID
  )
{
  UINTN                 PageTable;
  UINTN                 Index1;
  UINTN                 Index2;
  UINTN                 Index3;
#if defined (MDE_CPU_X64)
  UINTN                 Index4;
#endif
  UINT64                *L1PageTable;
  UINT64                *L2PageTable;
  UINT64                *L3PageTable;
#if defined (MDE_CPU_X64)
  UINT64                *L4PageTable;
#endif
  UINTN                 Index3Max;

  DEBUG ((EFI_D_INFO, "InitUserModePaging...\n"));

  PageTable = AsmReadCr3 () & PAGING_4K_ADDRESS_MASK_64;
#if defined (MDE_CPU_X64)
  L4PageTable = (UINT64 *)PageTable;
  for (Index4 = 0; Index4 < 512; Index4++) {
    if (L4PageTable[Index4] == 0) {
      continue;
    }
    L4PageTable[Index4] |= IA32_PG_U;
    L3PageTable = (UINT64 *)(UINTN)(L4PageTable[Index4] & PAGING_4K_ADDRESS_MASK_64);
    Index3Max = 512;
#endif
#if defined (MDE_CPU_IA32)
    L3PageTable = (UINT64 *)PageTable;
    Index3Max = 4;
#endif
    for (Index3 = 0; Index3 < Index3Max; Index3++) {
      if (L3PageTable[Index3] == 0) {
        continue;
      }
      L3PageTable[Index3] |= IA32_PG_U;
      if ((L3PageTable[Index3] & IA32_PG_PS) != 0) {
        continue;
      }
      L2PageTable = (UINT64 *)(UINTN)(L3PageTable[Index3] & PAGING_4K_ADDRESS_MASK_64);
      for (Index2 = 0; Index2 < 512; Index2++) {
        if (L2PageTable[Index2] == 0) {
          continue;
        }
        L2PageTable[Index2] |= IA32_PG_U;
        if ((L2PageTable[Index2] & IA32_PG_PS) != 0) {
          continue;
        }
        L1PageTable = (UINT64 *)(UINTN)(L2PageTable[Index2] & PAGING_4K_ADDRESS_MASK_64);
        for (Index1 = 0; Index1 < 512; Index1++) {
          if (L1PageTable[Index1] == 0) {
            continue;
          }
          L1PageTable[Index1] |= IA32_PG_U;
        }
      }
    }
#if defined (MDE_CPU_X64)
  }
#endif

  DEBUG ((EFI_D_INFO, "InitUserModePaging Done\n"));
}

typedef struct {
  UINTN ExceptionStart;
  UINTN ExceptionStubHeaderSize;
  UINTN HookAfterStubHeaderStart;
} EXCEPTION_HANDLER_TEMPLATE_MAP;

VOID
EFIAPI
AsmGetTemplateAddressMap (
  OUT EXCEPTION_HANDLER_TEMPLATE_MAP *AddressMap
  );

VOID
EFIAPI
AsmVectorNumFixup (
  IN VOID    *NewVectorAddr,
  IN UINT8   VectorNum,
  IN VOID    *OldVectorAddr
  );

#define  HOOKAFTER_STUB_SIZE        16
CONST UINT32 mErrorCodeFlag   = 0x00027d00;
CONST UINTN  mDoFarReturnFlag = 0;

VOID
InitInterruptGate (
  VOID
  )
{
  IA32_IDT_GATE_DESCRIPTOR           *IdtTable;
  IA32_DESCRIPTOR                    IdtDescriptor;
  EXCEPTION_HANDLER_TEMPLATE_MAP     TemplateMap;
  UINTN                              Index;
  UINT8                              *InterruptEntryCode;
  UINTN                              InterruptEntry;
  UINTN                              InterruptHandler;

  AsmReadIdtr (&IdtDescriptor);

  IdtTable = AllocateZeroPool (sizeof (IA32_IDT_GATE_DESCRIPTOR) * 256);
  ASSERT (IdtTable != NULL);
  CopyMem (IdtTable, (VOID *)IdtDescriptor.Base, IdtDescriptor.Limit + 1);

  AsmGetTemplateAddressMap (&TemplateMap);
  ASSERT (TemplateMap.ExceptionStubHeaderSize <= HOOKAFTER_STUB_SIZE);
  InterruptEntryCode = AllocatePool (TemplateMap.ExceptionStubHeaderSize * 0x20);
  ASSERT (InterruptEntryCode != NULL);

  InterruptEntry = (UINTN) InterruptEntryCode;
  for (Index = 0; Index < 0x20; Index ++) {
    CopyMem (
      (VOID *) InterruptEntry,
      (VOID *) TemplateMap.ExceptionStart,
      TemplateMap.ExceptionStubHeaderSize
      );
    AsmVectorNumFixup ((VOID *) InterruptEntry,  (UINT8) Index, (VOID *) TemplateMap.ExceptionStart);
    InterruptEntry += TemplateMap.ExceptionStubHeaderSize;
  }

  for (Index = 0; Index < 0x20; Index ++) {
    IdtTable[Index].Bits.Selector = (UINT32)(USER_CODE_SEGMENT | 3);
    InterruptHandler = TemplateMap.ExceptionStart + Index * TemplateMap.ExceptionStubHeaderSize;
    IdtTable[Index].Bits.OffsetLow   = (UINT16)(UINTN)InterruptHandler;
    IdtTable[Index].Bits.OffsetHigh  = (UINT16)((UINTN)InterruptHandler >> 16);
#if defined (MDE_CPU_X64)
    IdtTable[Index].Bits.OffsetUpper = (UINT32)((UINTN)InterruptHandler >> 32);	
#endif
    IdtTable[Index].Bits.GateType    = IA32_IDT_GATE_TYPE_INTERRUPT_32 | IA32_DPL(3);
  }

  IdtDescriptor.Base  = (UINTN) IdtTable;
  AsmWriteIdtr ((IA32_DESCRIPTOR *) &IdtDescriptor);
}

VOID
EFIAPI
CommonExceptionHandler (
  IN EFI_EXCEPTION_TYPE          ExceptionType, 
  IN EFI_SYSTEM_CONTEXT          SystemContext
  );

VOID
UserModeInit (
  VOID
  )
{
  InitUserModeGdt ();
  InitUserModeIdt ();
  InitUserModePaging ();

  InitInterruptGate ();

  //
  // For SYSENTER, target fields are generated using the following sources:
  //   Target code segment — Reads this from IA32_SYSENTER_CS.
  //   Target instruction — Reads this from IA32_SYSENTER_EIP.
  //   Stack segment — Computed by adding 8 to the value in IA32_SYSENTER_CS.
  //   Stack pointer — Reads this from the IA32_SYSENTER_ESP.
  // For SYSEXIT, target fields are generated using the following sources:
  //   Target code segment — Computed by adding 16 to the value in the IA32_SYSENTER_CS.
  //   Target instruction — Reads this from EDX.
  //   Stack segment — Computed by adding 24 to the value in IA32_SYSENTER_CS.
  //   Stack pointer — Reads this from ECX.
  //
  AsmWriteMsr64 (MSR_IA32_SYSENTER_CS, (UINT64)SYSTEM_CODE_SEGMENT);
  AsmWriteMsr64 (MSR_IA32_SYSENTER_EIP, (UINT64)(UINTN)AsmSystemModeEnter);
}

USER_MODE_THUNK_PROTOCOL  mUserModeThunk = {
  UserModeEnter,
  UserModeExit,
  UserModeCall,
};

EFI_STATUS
EFIAPI
UserModeThunkEntryPoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  EFI_STATUS   Status;
  EFI_HANDLE   Handle;

  Status = gBS->LocateProtocol (
                  &gEfiCpuArchProtocolGuid,
                  NULL,
                  (VOID **)&mCpu
                  );
  ASSERT_EFI_ERROR(Status);

  UserModeInit ();

  Handle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &Handle,
                  &gUserModeThunkProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mUserModeThunk
                  );
  ASSERT_EFI_ERROR(Status);

  return EFI_SUCCESS;
}