/** @file
  Entry point library instance to a UEFI application.

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifdef __cplusplus
extern "C" {
#endif

#include <Uefi.h>

typedef void (__attribute__((cdecl)) *INIT_FUNC) (void);

INIT_FUNC crtbegin[1] __attribute__ ((section(".ctors"))) = {(INIT_FUNC)(UINTN)-1};

#ifdef __cplusplus
}
#endif
