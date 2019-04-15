/** @file

Copyright (c) 2014, Intel Corporation. All rights reserved.<BR>
This software and associated documentation (if any) is furnished
under a license and may only be used or copied in accordance
with the terms of the license. Except as permitted by such
license, no part of this software or documentation may be
reproduced, stored in a retrieval system, or transmitted in any
form or by any means without the express written consent of
Intel Corporation.

**/


#ifdef __cplusplus
extern "C" {
#endif

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>

#ifdef __cplusplus
}
#endif

class TestClass {
private:
  UINTN  Member1;
  UINTN  *Addr;
public:
  TestClass()
  {
    DEBUG ((EFI_D_INFO, "TestClass - 0x%x\n", Member1));
    Member1 = 1;
    Addr = new UINTN;
  }
  ~TestClass()
  {
    Member1 = 0;
    delete Addr;
    DEBUG ((EFI_D_INFO, "TestClass(D) - 0x%x\n", Member1));
  }
  VOID
  SetNumber (
    IN UINTN Number
    )
  {
    DEBUG ((EFI_D_INFO, "SetNumber - 0x%x\n", Number));
    Member1 = Number;
  }
  UINTN
  GetNumber (
    VOID
    )
  {
    DEBUG ((EFI_D_INFO, "GetNumber - 0x%x\n", Member1));
    return Member1;
  }
};

typedef class TestClass TestClass;

TestClass testClass;
TestClass testClass2;

UINTN  DummySymbol;

EFI_STATUS
EFIAPI
MainEntryPoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
#if 1
  UINTN *Ptr;
  UINTN *Array;

  Ptr = new UINTN;
  Array = new UINTN[100];

  *Ptr = 5;

  delete Ptr;
  delete[] Array;

  Print ((CHAR16 *)L"Number - 0x%x\n", testClass.GetNumber ());
  testClass.SetNumber (2);
  Print ((CHAR16 *)L"Number - 0x%x\n", testClass.GetNumber ());

  Print ((CHAR16 *)L"Number - 0x%x\n", testClass2.GetNumber ());
  testClass2.SetNumber (3);
  Print ((CHAR16 *)L"Number - 0x%x\n", testClass2.GetNumber ());
#endif
  return EFI_SUCCESS;
}
