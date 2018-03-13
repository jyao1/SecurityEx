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
#include <Protocol/SmmCommunication.h>
#include <Guid/PiSmmCommunicationRegionTable.h>

#include "Communication.h"

EFI_SMM_COMMUNICATION_PROTOCOL     *mSmmCommunication        = NULL;

UINT8                              *mCommBuffer;

EFI_GUID  mSmmTestGuid = SMM_TEST_GUID;

/**
  Initialize the communicate buffer using DataSize and Function number.

  @param[out]      CommunicateBuffer The communicate buffer. Caller should free it after use.
  @param[out]      DataPtr           Points to the data in the communicate buffer. Caller should not free it.
  @param[in]       DataSize          The payload size.
  @param[in]       Function          The function number used to initialize the communicate header.

**/
VOID
InitCommunicateBuffer (
  OUT     VOID                              **CommunicateBuffer,
  OUT     VOID                              **DataPtr,
  IN      UINTN                             DataSize,
  IN      UINTN                             Function
  )
{
  EFI_SMM_COMMUNICATE_HEADER                *SmmCommunicateHeader;  
  SMM_TEST_COMMUNICATE_FUNCTION_HEADER      *SmmTestFunctionHeader; 

  //
  // The whole buffer size: SMM_COMMUNICATE_HEADER_SIZE + SMM_SPI_COMMUNICATE_HEADER_SIZE + DataSize.
  //
  SmmCommunicateHeader = (VOID *)mCommBuffer;
  ASSERT (SmmCommunicateHeader != NULL);
   
  //
  // Prepare data buffer.
  //
  CopyGuid (&SmmCommunicateHeader->HeaderGuid, &mSmmTestGuid);
  SmmCommunicateHeader->MessageLength = DataSize + SMM_TEST_COMMUNICATE_HEADER_SIZE;
 
  SmmTestFunctionHeader = (SMM_TEST_COMMUNICATE_FUNCTION_HEADER *) SmmCommunicateHeader->Data;
  SmmTestFunctionHeader->Function = Function;
  SmmTestFunctionHeader->ReturnStatus = EFI_NOT_READY;

  *CommunicateBuffer = SmmCommunicateHeader;
  if (DataPtr != NULL) {
    *DataPtr = SmmTestFunctionHeader->Data;
  }  
}


/**
  Send the data in communicate buffer to SMI handler and get response.

  @param[in, out]  SmmCommunicateHeader    The communicate buffer.
  @param[in]       DataSize                The payload size.
                      
**/
EFI_STATUS
SendCommunicateBuffer (
  IN OUT  EFI_SMM_COMMUNICATE_HEADER        *SmmCommunicateHeader,
  IN      UINTN                             DataSize
  )
{
  EFI_STATUS                                Status;
  UINTN                                     CommSize;
  SMM_TEST_COMMUNICATE_FUNCTION_HEADER      *SmmTestFunctionHeader; 
 
  CommSize = DataSize + SMM_COMMUNICATE_HEADER_SIZE + SMM_TEST_COMMUNICATE_HEADER_SIZE;
  Status = mSmmCommunication->Communicate (mSmmCommunication, SmmCommunicateHeader, &CommSize);
  ASSERT_EFI_ERROR (Status);

  SmmTestFunctionHeader = (SMM_TEST_COMMUNICATE_FUNCTION_HEADER *) SmmCommunicateHeader->Data;
  return  SmmTestFunctionHeader->ReturnStatus;
}




VOID
DumpArchStatus(
  VOID
  );

#define COUNT 1000

EFI_STATUS
EFIAPI
InitializeSmiPerf (
  VOID
  )
{
  UINT64                    StartTsc;
  UINT64                    EndTsc;
  PERFORMANCE_PROPERTY      *PerformanceProperty;
  EFI_STATUS                Status;
  UINTN                                     PayloadSize;
  EFI_SMM_COMMUNICATE_HEADER                *SmmCommunicateHeader;
  SMM_TEST_PERF                             *SmmTestPerf;

  PayloadSize = sizeof(SMM_TEST_PERF);
  InitCommunicateBuffer ((VOID **)&SmmCommunicateHeader, (VOID **)&SmmTestPerf, PayloadSize, FUNCTION_TEST_PERF);
  SmmTestPerf->StartTsc = 0;
  SmmTestPerf->EndTsc = 0;

  Status = SendCommunicateBuffer (SmmCommunicateHeader, PayloadSize);
  StartTsc = SmmTestPerf->StartTsc;
  EndTsc = SmmTestPerf->EndTsc;
  
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
  EFI_STATUS                                          Status;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE             *PiSmmCommunicationRegionTable;
  UINT32                                              Index;
  EFI_MEMORY_DESCRIPTOR                               *Entry;
  UINTN                                               Size;

  Status = gBS->LocateProtocol(&gEfiSmmCommunicationProtocolGuid, NULL, (VOID **)&mSmmCommunication);
  if (EFI_ERROR(Status)) {
    Print(L"SmiHandlerProfile: Locate SmmCommunication protocol - %r\n", Status);
    return EFI_SUCCESS;
  }

  Status = EfiGetSystemConfigurationTable(
             &gEdkiiPiSmmCommunicationRegionTableGuid,
             (VOID **)&PiSmmCommunicationRegionTable
             );
  if (EFI_ERROR(Status)) {
    Print(L"Get PiSmmCommunicationRegionTable - %r\n", Status);
    return EFI_SUCCESS;
  }
  Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
  Size = 0;
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (Entry->Type == EfiConventionalMemory) {
      Size = EFI_PAGES_TO_SIZE((UINTN)Entry->NumberOfPages);
      if (Size >= EFI_PAGE_SIZE) {
        break;
      }
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
  }
  ASSERT(Index < PiSmmCommunicationRegionTable->NumberOfEntries);

  mCommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

  InitializeSmiPerf ();
  return EFI_SUCCESS;
}
