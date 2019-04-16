/** @file
  Entry point library instance to a UEFI application.

Copyright (c) 2007 - 2010, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffLib.h>
#include <Protocol/LoadedImage.h>
#include "PeLoadConfiguration.h"

RETURN_STATUS
EFIAPI
CfgLibConstructor(
  VOID
  )
{
  EFI_LOADED_IMAGE_PROTOCOL            *LoadedImage;
  EFI_STATUS                           Status;
  VOID                                 *ImageAddress;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  EFI_IMAGE_SECTION_HEADER             *Section;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINT16                               Magic;
  UINT8                                *Name;
  UINTN                                Index;
  UINTN                                AddressOfEntryPoint;
  UINT64                               ImageBase;
  EFI_IMAGE_DATA_DIRECTORY             *DataDirectory;
  UINTN                                Offset;
  EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_PTR_UNION  LoadConfig;
  UINT32                               Size;
  UINT32                               *FuncTable32;
  UINT64                               *FuncTable64;

  Status = gBS->HandleProtocol (
                  gImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage
                  );
  ASSERT_EFI_ERROR (Status);

  ImageAddress = LoadedImage->ImageBase;

  //
  // Check PE/COFF image
  //
  DosHdr = (EFI_IMAGE_DOS_HEADER *) (UINTN) ImageAddress;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *) (UINTN) ImageAddress + PeCoffHeaderOffset);
  if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    goto Finish;
  }
  
  DEBUG ((EFI_D_INFO, "ImageAddress - 0x%08x\n", ImageAddress));
  DEBUG ((EFI_D_INFO, "_ModuleEntryPoint - 0x%08x\n", _ModuleEntryPoint));
  AddressOfEntryPoint = Hdr.Pe32->OptionalHeader.AddressOfEntryPoint;
  DEBUG ((DEBUG_INFO, "AddressOfEntryPoint - 0x%08x\n", AddressOfEntryPoint));
  
  Offset = (UINTN)_ModuleEntryPoint - (AddressOfEntryPoint + (UINTN)ImageAddress);
  
  //
  // Get the magic value from the PE/COFF Optional Header
  //
  Magic = Hdr.Pe32->OptionalHeader.Magic;
  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    DataDirectory = &Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    ImageBase = Hdr.Pe32->OptionalHeader.ImageBase;
  } else {
    DataDirectory = &Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    ImageBase = Hdr.Pe32Plus->OptionalHeader.ImageBase;
  }
  DEBUG ((DEBUG_INFO, "ImageBase - 0x%016lx\n", ImageBase));
  DEBUG ((DEBUG_INFO, "DataDirectory.VirtualAddress - 0x%08x\n", DataDirectory->VirtualAddress));
  DEBUG ((DEBUG_INFO, "DataDirectory.Size           - 0x%08x\n", DataDirectory->Size));

  LoadConfig.Entry32 = (VOID *)(UINTN)(ImageBase + DataDirectory->VirtualAddress);
  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    Size = LoadConfig.Entry32->Characteristics;
    DEBUG ((DEBUG_INFO, "  Characteristics                 - 0x%08x\n", LoadConfig.Entry32->Characteristics));
    DEBUG ((DEBUG_INFO, "  TimeDateStamp                   - 0x%08x\n", LoadConfig.Entry32->TimeDateStamp));
    DEBUG ((DEBUG_INFO, "  MajorVersion                    - 0x%04x\n", LoadConfig.Entry32->MajorVersion));
    DEBUG ((DEBUG_INFO, "  MinorVersion                    - 0x%04x\n", LoadConfig.Entry32->MinorVersion));
    DEBUG ((DEBUG_INFO, "  GlobalFlagsClear                - 0x%08x\n", LoadConfig.Entry32->GlobalFlagsClear));
    DEBUG ((DEBUG_INFO, "  GlobalFlagsSet                  - 0x%08x\n", LoadConfig.Entry32->GlobalFlagsSet));
    DEBUG ((DEBUG_INFO, "  CriticalSectionDefaultTimeout   - 0x%08x\n", LoadConfig.Entry32->CriticalSectionDefaultTimeout));
    DEBUG ((DEBUG_INFO, "  DeCommitFreeBlockThreshold      - 0x%08x\n", LoadConfig.Entry32->DeCommitFreeBlockThreshold));
    DEBUG ((DEBUG_INFO, "  DeCommitTotalFreeThreshold      - 0x%08x\n", LoadConfig.Entry32->DeCommitTotalFreeThreshold));
    DEBUG ((DEBUG_INFO, "  LockPrefixTable                 - 0x%08x\n", LoadConfig.Entry32->LockPrefixTable));
    DEBUG ((DEBUG_INFO, "  MaximumAllocationSize           - 0x%08x\n", LoadConfig.Entry32->MaximumAllocationSize));
    DEBUG ((DEBUG_INFO, "  VirtualMemoryThreshold          - 0x%08x\n", LoadConfig.Entry32->VirtualMemoryThreshold));
    DEBUG ((DEBUG_INFO, "  ProcessAffinityMask             - 0x%08x\n", LoadConfig.Entry32->ProcessAffinityMask));
    DEBUG ((DEBUG_INFO, "  ProcessHeapFlags                - 0x%08x\n", LoadConfig.Entry32->ProcessHeapFlags));
    DEBUG ((DEBUG_INFO, "  CSDVersion                      - 0x%04x\n", LoadConfig.Entry32->CSDVersion));
    DEBUG ((DEBUG_INFO, "  EditList                        - 0x%08x\n", LoadConfig.Entry32->EditList));
    DEBUG ((DEBUG_INFO, "  SecurityCookie                  - 0x%08x\n", LoadConfig.Entry32->SecurityCookie));
    DEBUG ((DEBUG_INFO, "  SEHandlerTable                  - 0x%08x\n", LoadConfig.Entry32->SEHandlerTable));
    DEBUG ((DEBUG_INFO, "  SEHandlerCount                  - 0x%08x\n", LoadConfig.Entry32->SEHandlerCount));
    DEBUG ((DEBUG_INFO, "  GuardCFCheckFunctionPointer     - 0x%08x\n", LoadConfig.Entry32->GuardCFCheckFunctionPointer));
    DEBUG ((DEBUG_INFO, "  GuardCFDispatchFunctionPointer  - 0x%08x\n", LoadConfig.Entry32->GuardCFDispatchFunctionPointer));
    DEBUG ((DEBUG_INFO, "  GuardCFFunctionTable            - 0x%08x\n", LoadConfig.Entry32->GuardCFFunctionTable));
    DEBUG ((DEBUG_INFO, "  GuardCFFunctionCount            - 0x%08x\n", LoadConfig.Entry32->GuardCFFunctionCount));
    DEBUG ((DEBUG_INFO, "  GuardFlags                      - 0x%08x\n", LoadConfig.Entry32->GuardFlags));
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_INSTRUMENTED\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_CFW_INSTRUMENTED) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CFW_INSTRUMENTED\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_SECURITY_COOKIE_UNUSED) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_SECURITY_COOKIE_UNUSED\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_PROTECT_DELAYLOAD_IAT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION\n"));
    }
    if ((LoadConfig.Entry32->GuardFlags & IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT\n"));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32, CodeIntegrity)) {
      DEBUG ((DEBUG_INFO, "  CodeIntegrity                   - %g\n", LoadConfig.Entry32->CodeIntegrity));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32, GuardAddressTakenIatEntryTable)) {
      DEBUG ((DEBUG_INFO, "  GuardAddressTakenIatEntryTable  - 0x%08x\n", LoadConfig.Entry32->GuardAddressTakenIatEntryTable));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32, GuardAddressTakenIatEntryCount)) {
      DEBUG ((DEBUG_INFO, "  GuardAddressTakenIatEntryCount  - 0x%08x\n", LoadConfig.Entry32->GuardAddressTakenIatEntryCount));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32, GuardLongJumpTargetTable)) {
      DEBUG ((DEBUG_INFO, "  GuardLongJumpTargetTable        - 0x%08x\n", LoadConfig.Entry32->GuardLongJumpTargetTable));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32, GuardLongJumpTargetCount)) {
      DEBUG ((DEBUG_INFO, "  GuardLongJumpTargetCount        - 0x%08x\n", LoadConfig.Entry32->GuardLongJumpTargetCount));
    }
    DEBUG ((DEBUG_INFO, "\n  Guard CF Function Table\n"));
    DEBUG ((DEBUG_INFO, "    Address\n"));
    DEBUG ((DEBUG_INFO, "    =======\n"));
    FuncTable32 = (VOID *)(UINTN)LoadConfig.Entry32->GuardCFFunctionTable;
    for (Index = 0; Index < LoadConfig.Entry32->GuardCFFunctionCount; Index++) {
      DEBUG ((DEBUG_INFO, "    0x%08x | 0x%08x\n", FuncTable32[Index], FuncTable32[Index] + ImageBase));
    }
  } else {
    Size = LoadConfig.Entry64->Characteristics;
    DEBUG ((DEBUG_INFO, "  Characteristics                 - 0x%08x\n", LoadConfig.Entry64->Characteristics));
    DEBUG ((DEBUG_INFO, "  TimeDateStamp                   - 0x%08x\n", LoadConfig.Entry64->TimeDateStamp));
    DEBUG ((DEBUG_INFO, "  MajorVersion                    - 0x%04x\n", LoadConfig.Entry64->MajorVersion));
    DEBUG ((DEBUG_INFO, "  MinorVersion                    - 0x%04x\n", LoadConfig.Entry64->MinorVersion));
    DEBUG ((DEBUG_INFO, "  GlobalFlagsClear                - 0x%08x\n", LoadConfig.Entry64->GlobalFlagsClear));
    DEBUG ((DEBUG_INFO, "  GlobalFlagsSet                  - 0x%08x\n", LoadConfig.Entry64->GlobalFlagsSet));
    DEBUG ((DEBUG_INFO, "  CriticalSectionDefaultTimeout   - 0x%08x\n", LoadConfig.Entry64->CriticalSectionDefaultTimeout));
    DEBUG ((DEBUG_INFO, "  DeCommitFreeBlockThreshold      - 0x%016lx\n", LoadConfig.Entry64->DeCommitFreeBlockThreshold));
    DEBUG ((DEBUG_INFO, "  DeCommitTotalFreeThreshold      - 0x%016lx\n", LoadConfig.Entry64->DeCommitTotalFreeThreshold));
    DEBUG ((DEBUG_INFO, "  LockPrefixTable                 - 0x%016lx\n", LoadConfig.Entry64->LockPrefixTable));
    DEBUG ((DEBUG_INFO, "  MaximumAllocationSize           - 0x%016lx\n", LoadConfig.Entry64->MaximumAllocationSize));
    DEBUG ((DEBUG_INFO, "  VirtualMemoryThreshold          - 0x%016lx\n", LoadConfig.Entry64->VirtualMemoryThreshold));
    DEBUG ((DEBUG_INFO, "  ProcessAffinityMask             - 0x%016lx\n", LoadConfig.Entry64->ProcessAffinityMask));
    DEBUG ((DEBUG_INFO, "  ProcessHeapFlags                - 0x%08x\n", LoadConfig.Entry64->ProcessHeapFlags));
    DEBUG ((DEBUG_INFO, "  CSDVersion                      - 0x%04x\n", LoadConfig.Entry64->CSDVersion));
    DEBUG ((DEBUG_INFO, "  EditList                        - 0x%016lx\n", LoadConfig.Entry64->EditList));
    DEBUG ((DEBUG_INFO, "  SecurityCookie                  - 0x%016lx\n", LoadConfig.Entry64->SecurityCookie));
    DEBUG ((DEBUG_INFO, "  SEHandlerTable                  - 0x%016lx\n", LoadConfig.Entry64->SEHandlerTable));
    DEBUG ((DEBUG_INFO, "  SEHandlerCount                  - 0x%016lx\n", LoadConfig.Entry64->SEHandlerCount));
    DEBUG ((DEBUG_INFO, "  GuardCFCheckFunctionPointer     - 0x%016lx\n", LoadConfig.Entry64->GuardCFCheckFunctionPointer));
    DEBUG ((DEBUG_INFO, "  GuardCFDispatchFunctionPointer  - 0x%016lx\n", LoadConfig.Entry64->GuardCFDispatchFunctionPointer));
    DEBUG ((DEBUG_INFO, "  GuardCFFunctionTable            - 0x%016lx\n", LoadConfig.Entry64->GuardCFFunctionTable));
    DEBUG ((DEBUG_INFO, "  GuardCFFunctionCount            - 0x%016lx\n", LoadConfig.Entry64->GuardCFFunctionCount));
    DEBUG ((DEBUG_INFO, "  GuardFlags                      - 0x%08x\n", LoadConfig.Entry64->GuardFlags));
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_INSTRUMENTED\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_CFW_INSTRUMENTED) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CFW_INSTRUMENTED\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_SECURITY_COOKIE_UNUSED) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_SECURITY_COOKIE_UNUSED\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_PROTECT_DELAYLOAD_IAT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION\n"));
    }
    if ((LoadConfig.Entry64->GuardFlags & IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT) != 0) {
      DEBUG ((DEBUG_INFO, "    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT\n"));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64, CodeIntegrity)) {
      DEBUG ((DEBUG_INFO, "  CodeIntegrity                   - %g\n", LoadConfig.Entry64->CodeIntegrity));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64, GuardAddressTakenIatEntryTable)) {
      DEBUG ((DEBUG_INFO, "  GuardAddressTakenIatEntryTable  - 0x%016lx\n", LoadConfig.Entry64->GuardAddressTakenIatEntryTable));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64, GuardAddressTakenIatEntryCount)) {
      DEBUG ((DEBUG_INFO, "  GuardAddressTakenIatEntryCount  - 0x%016lx\n", LoadConfig.Entry64->GuardAddressTakenIatEntryCount));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64, GuardLongJumpTargetTable)) {
      DEBUG ((DEBUG_INFO, "  GuardLongJumpTargetTable        - 0x%016lx\n", LoadConfig.Entry64->GuardLongJumpTargetTable));
    }
    if (Size > OFFSET_OF(EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64, GuardLongJumpTargetCount)) {
      DEBUG ((DEBUG_INFO, "  GuardLongJumpTargetCount        - 0x%016lx\n", LoadConfig.Entry64->GuardLongJumpTargetCount));
    }
    DEBUG ((DEBUG_INFO, "\n  Guard CF Function Table\n"));
    DEBUG ((DEBUG_INFO, "    Address\n"));
    DEBUG ((DEBUG_INFO, "    =======\n"));
    FuncTable64 = (VOID *)(UINTN)LoadConfig.Entry64->GuardCFFunctionTable;
    for (Index = 0; Index < LoadConfig.Entry64->GuardCFFunctionCount; Index++) {
      DEBUG ((DEBUG_INFO, "    0x%016lx | 0x%016lx\n", FuncTable64[Index], FuncTable64[Index] + ImageBase));
    }
  }

  Section = (EFI_IMAGE_SECTION_HEADER *) (
               (UINT8 *) (UINTN) ImageAddress +
               PeCoffHeaderOffset +
               sizeof(UINT32) +
               sizeof(EFI_IMAGE_FILE_HEADER) +
               Hdr.Pe32->FileHeader.SizeOfOptionalHeader
               );
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Name = Section[Index].Name;
    DEBUG ((
      DEBUG_INFO,
      "Section - '%c%c%c%c%c%c%c%c'\n",
      Name[0],
      Name[1],
      Name[2],
      Name[3],
      Name[4],
      Name[5],
      Name[6],
      Name[7]
      ));
  }

Finish:
  return RETURN_SUCCESS;
}
