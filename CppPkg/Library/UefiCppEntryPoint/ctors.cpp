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
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

typedef void (__attribute__((cdecl)) *INIT_FUNC) (void);

typedef void (__attribute__((cdecl)) *EXIT_FUNC) (void *);

#define MAX_EXITFUNC_NUM  256
EXIT_FUNC __mExitFunc[MAX_EXITFUNC_NUM];
VOID      *__mExitArg[MAX_EXITFUNC_NUM];
UINTN     __mCurrentExitFunc;

extern INIT_FUNC crtbegin[1];
extern INIT_FUNC crtend[1];

EFI_STATUS
EFIAPI
EfiCRTInit (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  INIT_FUNC  InitFunc;
  INIT_FUNC  *InitFuncPtr;
  
  DEBUG ((EFI_D_INFO, "crtbegin - 0x%08x\n", crtbegin));
  DEBUG ((EFI_D_INFO, "crtend   - 0x%08x\n", crtend));

  InitFuncPtr = crtbegin;
  for (InitFuncPtr = crtbegin + 1; InitFuncPtr < crtend; InitFuncPtr++) {
    DEBUG ((EFI_D_INFO, "FuncPtr - 0x%08x\n", *InitFuncPtr));
    InitFunc = *InitFuncPtr;
    DEBUG ((EFI_D_INFO, "InitFunc - 0x%08x\n", InitFunc));
    if (InitFunc == NULL) {
      continue;
    }
    if ((UINTN)InitFunc == (UINTN)-1) {
      break;
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
      __mExitFunc[Index] (__mExitArg[Index]);
    }
  }
  return EFI_SUCCESS;
}

int __attribute__((cdecl)) __cxa_atexit (EXIT_FUNC func, void *arg, void *dso_handle)
{
  DEBUG ((EFI_D_INFO, "__cxa_atexit - 0x%x, 0x%x, 0x%x\n", func, arg, dso_handle));
  __mExitFunc[__mCurrentExitFunc] = func;
  __mExitArg[__mCurrentExitFunc] = arg;
  __mCurrentExitFunc ++;
  return 0;
}

// DSO (Dynamic Shared Object) is not needed.
void *__dso_handle;

#ifdef __cplusplus
}
#endif
