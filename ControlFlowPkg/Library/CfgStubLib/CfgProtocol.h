/** @file

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __CFG_PROTOCOL_H__
#define __CFG_PROTOCOL_H__

#define CFG_PROTOCOL_GUID \
  { 0xa984b418, 0x8a15, 0x49c4, { 0xa0, 0x90, 0x67, 0x83, 0x99, 0xf8, 0xa6, 0x5d } }

typedef struct {
  LIST_ENTRY      Link;
  UINT32          *GuardCFFunctionTable;
  UINTN           GuardCFFunctionCount;
  UINTN           ImageBase;
  UINTN           ImageSize;
} CFG_NODE;

typedef struct {
  LIST_ENTRY   CfgNode;
} CFG_PROTOCOL;

extern EFI_GUID gCfgProtocolGuid;

#endif