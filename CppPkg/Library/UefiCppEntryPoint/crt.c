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

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

typedef void (__cdecl * _PVFV)();  

#define MAX_EXITFUNC_NUM  256
_PVFV __mExitFunc[MAX_EXITFUNC_NUM];
UINTN     __mCurrentExitFunc;

#pragma section(".CRT$XCA", long, read)
#pragma section(".CRT$XCZ", long, read)

__declspec(allocate(".CRT$XCA")) __declspec(selectany) _PVFV __xc_a[1] = {NULL};
// When the compiler sees a global initializer, it generates a dynamic initializer in the .CRT$XCU section.
// (where CRT is the section name and XCU is the group name)
__declspec(allocate(".CRT$XCZ")) __declspec(selectany) _PVFV __xc_z[1] = {NULL};

#pragma comment(linker, "/merge:.CRT=.data")

EFI_STATUS
EFIAPI
EfiCRTInit (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  _PVFV  InitFunc;
  _PVFV  *InitFuncPtr;
  
  DEBUG ((EFI_D_INFO, "__xc_a - 0x%08x\n", __xc_a));
  DEBUG ((EFI_D_INFO, "__xc_z - 0x%08x\n", __xc_z));

  InitFuncPtr = __xc_a;
  for (InitFuncPtr = __xc_a; InitFuncPtr < __xc_z; InitFuncPtr++) {
    DEBUG ((EFI_D_INFO, "FuncPtr - 0x%08x\n", *InitFuncPtr));
    InitFunc = *InitFuncPtr;
    DEBUG ((EFI_D_INFO, "InitFunc - 0x%08x\n", InitFunc));
    if (InitFunc == NULL) {
      continue;
    }
    InitFunc ();
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiCRTDeinit (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  UINTN      Index;

  for (Index = 0; Index < __mCurrentExitFunc; Index++) {
    if (__mExitFunc[Index] != NULL) {
      __mExitFunc[Index] ();
    }
  }
  return EFI_SUCCESS;
}

int __cdecl atexit(_PVFV func)
{
  DEBUG ((EFI_D_INFO, "atexit - 0x%x\n", func));
  __mExitFunc[__mCurrentExitFunc] = func;
  __mCurrentExitFunc ++;
  return 0;
}
