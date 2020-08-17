/** @file

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _USER_MODE_THUNK_H_
#define _USER_MODE_THUNK_H_

#define USER_MODE_THUNK_PROTOCOL_GUID \
  { \
    0x44109850, 0xc259, 0x4e95, { 0x87, 0x59, 0xcc, 0xd4, 0xf3, 0xd5, 0x24, 0xed } \
  }

typedef struct _USER_MODE_THUNK_PROTOCOL USER_MODE_THUNK_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *USER_MODE_THUNK_ENTER) (
  IN USER_MODE_THUNK_PROTOCOL  *This
  );

typedef
EFI_STATUS
(EFIAPI *USER_MODE_THUNK_EXIT) (
  IN USER_MODE_THUNK_PROTOCOL  *This
  );

typedef
EFI_STATUS
(EFIAPI *USER_MODE_THUNK_FUNCTION) (
  IN UINTN                     Param1,
  IN UINTN                     Param2
  );

typedef
EFI_STATUS
(EFIAPI *USER_MODE_THUNK_CALL)(
  IN USER_MODE_THUNK_PROTOCOL  *This,
  IN USER_MODE_THUNK_FUNCTION  EntryPoint,
  IN UINTN                     Param1,
  IN UINTN                     Param2,
  OUT EFI_STATUS               *RetStatus
  );

struct _USER_MODE_THUNK_PROTOCOL {
  USER_MODE_THUNK_ENTER                       UserModeEnter;
  USER_MODE_THUNK_EXIT                        UserModeExit;
  USER_MODE_THUNK_CALL                        UserModeCall;
};

extern EFI_GUID gUserModeThunkProtocolGuid;

#endif
