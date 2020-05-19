/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _VARIANT1_SMM_COMM_BUFFER_H_
#define _VARIANT1_SMM_COMM_BUFFER_H_

///
/// Size of SMM communicate header, without including the payload.
///
#define SMM_COMMUNICATE_HEADER_SIZE  (OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data))

#define FUNCTION_GET_SECRET_ADDRESS   1
#define FUNCTION_COMMUNICATION        2

typedef struct {
  UINTN       Function;
  EFI_STATUS  ReturnStatus;
  UINT64      Address;
  UINT64      Offset;
} SMM_VARIANT1_COMMUNICATE_FUNCTION_HEADER;

#pragma pack(1)
typedef struct arrays {
    UINT64 array1_size;
    UINT8  unused1[64];
    UINT8  array1[160];
    UINT8  unused2[64];
    UINT8  array2[256 * 512];
} VARIANT1_SMM_COMM_BUFFER;
#pragma pack()

#define VARIANT1_SMM_COMM_GUID \
  {0x19d505a3, 0xe2c, 0x4efb, {0xb1, 0x4f, 0x89, 0x50, 0xc2, 0x9b, 0xa2, 0x96}}

#endif