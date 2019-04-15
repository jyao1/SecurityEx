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

VOID
CrtInternalDumpHex (
  IN VOID  *Data,
  IN UINTN Length
  )
{
  UINTN  Index;
  UINT8  *Data8;

  Data8 = (UINT8 *)Data;
  for (Index = 0; Index < Length; Index++) {
    DEBUG ((EFI_D_INFO, "0x%02x, ", Data8[Index]));
    if (((Index + 1) % 16) == 0) {
      DEBUG ((EFI_D_INFO, "\n"));
    }
  }
  if (((Index + 1) % 16) != 0) {
    DEBUG ((EFI_D_INFO, "\n"));
  }
}

UINTN
CrtInternalGetRunningImageOffset (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_LOADED_IMAGE_PROTOCOL            *LoadedImage;
  EFI_STATUS                           Status;
  VOID                                 *ImageAddress;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINT16                               Magic;
  UINTN                                AddressOfEntryPoint;

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
    return 0;
  }
  
  //
  // Measuring PE/COFF Image Header;
  // But CheckSum field and SECURITY data directory (certificate) are excluded
  //
  if (Hdr.Pe32->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 && Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // NOTE: Some versions of Linux ELILO for Itanium have an incorrect magic value 
    //       in the PE/COFF Header. If the MachineType is Itanium(IA64) and the 
    //       Magic value in the OptionalHeader is EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC
    //       then override the magic value to EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC
    //
    Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  } else {
    //
    // Get the magic value from the PE/COFF Optional Header
    //
    Magic = Hdr.Pe32->OptionalHeader.Magic;
  }
  
  AddressOfEntryPoint = Hdr.Pe32->OptionalHeader.AddressOfEntryPoint;

  DEBUG ((EFI_D_INFO, "_ModuleEntryPoint - 0x%08x\n", _ModuleEntryPoint));
  DEBUG ((EFI_D_INFO, "AddressOfEntryPoint - 0x%08x\n", AddressOfEntryPoint));
  DEBUG ((EFI_D_INFO, "ImageAddress - 0x%08x\n", ImageAddress));

  return (UINTN)_ModuleEntryPoint - (AddressOfEntryPoint + (UINTN)ImageAddress);
}
