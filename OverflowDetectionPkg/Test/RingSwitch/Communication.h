/** @file

  The common header file for SMM SPI module and SMM SPI DXE Module. 

Copyright (c) 2011, Intel Corporation. All rights reserved. <BR>
This program and the accompanying materials                          
are licensed and made available under the terms and conditions of the BSD License         
which accompanies this distribution.  The full text of the license may be found at        
http://opensource.org/licenses/bsd-license.php                                            
                                                                                          
THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED. 

**/

#ifndef __COMMUNICATION_H__
#define __COMMUNICATION_H__

#include <Uefi.h>

#pragma pack(1)

#define FUNCTION_TEST_PERF                 1

typedef struct {
  UINTN       Function;
  EFI_STATUS  ReturnStatus;
  UINT8       Data[1];
} SMM_TEST_COMMUNICATE_FUNCTION_HEADER;

///
/// Size of SMM communicate header, without including the payload.
///
#define SMM_COMMUNICATE_HEADER_SIZE  (OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data))

///
/// Size of SMM test communicate function header, without including the payload.
///
#define SMM_TEST_COMMUNICATE_HEADER_SIZE  (OFFSET_OF (SMM_TEST_COMMUNICATE_FUNCTION_HEADER, Data))

typedef struct {
  UINT64  StartTsc;
  UINT64  EndTsc;
} SMM_TEST_PERF;

#pragma pack()


#define SMM_TEST_GUID \
  {0x9df336f9, 0x450a, 0x4867, {0xa2, 0x40, 0x40, 0xdd, 0x4d, 0x6a, 0x1a, 0x76}}

#endif
