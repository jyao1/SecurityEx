/**

Copyright (c) 2012, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

//
// Below data structure is from rtcapi.h (Microsoft Visual Studio)
//

typedef struct _RTC_vardesc {
  int addr;
  int size;
  char *name;
} _RTC_vardesc;

typedef struct _RTC_framedesc {
  int varCount;
  _RTC_vardesc *variables;
} _RTC_framedesc;

#define RTC_STACK_CHECK_COOKIE  0xCCCCCCCC

#ifdef MDE_CPU_IA32

static void _RTC_Failure ()
{
  DEBUG ((EFI_D_ERROR, "\n!!! stack pointer check failed in StackChecker!!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

void  __declspec(naked) __cdecl _RTC_CheckEsp()
{
  __asm {
    jne         CheckEspFail
    ret
CheckEspFail:
    call        _RTC_Failure
    ret
  }
}
#endif

static void _RTC_StackFailure (char *name)
{
  DEBUG ((EFI_D_ERROR, "\n!!! stack variable check failed in StackChecker!!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

void __fastcall _RTC_CheckStackVars (void *_Esp, _RTC_framedesc *_Fd)
{
  int   Index;
  UINT8 *Addr;

  for (Index = 0; Index < _Fd->varCount; Index++) {
    Addr = (UINT8 *)_Esp + _Fd->variables[Index].addr - sizeof(UINT32);
    if (*(int *)Addr != RTC_STACK_CHECK_COOKIE) {
      _RTC_StackFailure (_Fd->variables[Index].name);
    }

    Addr = (UINT8 *)_Esp + _Fd->variables[Index].addr + _Fd->variables[Index].size;
    if (*(int *)Addr != RTC_STACK_CHECK_COOKIE) {
      _RTC_StackFailure (_Fd->variables[Index].name);
    }
  }
}

void __cdecl _RTC_Shutdown(void)
{
  // dummy
  return ;
}

void __cdecl _RTC_InitBase(void)
{
  // dummy
  return ;
}
