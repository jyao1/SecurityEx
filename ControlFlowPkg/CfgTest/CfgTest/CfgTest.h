/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _CFG_TEST_H_
#define _CFG_TEST_H_

#define CFG_TEST_PROTOCOL_GUID \
  { 0xe34ccd0, 0x820f, 0x4c76, { 0xbc, 0x73, 0xbb, 0x38, 0x57, 0x6c, 0xab, 0x12 } }

typedef
VOID
(EFIAPI *EXTERNAL_FUNC) (
  VOID
  );

typedef struct {
  EXTERNAL_FUNC   ExternFunc;
  EXTERNAL_FUNC   ExternFunc2;
} CFG_TEST_PROTOCOL;

extern EFI_GUID gCfgTestProtocolGuid;

#endif