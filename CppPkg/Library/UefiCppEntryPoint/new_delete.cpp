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
#include <Library/MemoryAllocationLib.h>

#ifdef __cplusplus
}
#endif

void operator delete(void *Ptr)
{
  return FreePool (Ptr);
}

void operator delete[](void *Ptr)
{
  return FreePool (Ptr);
}

void operator delete(void *Ptr, size_t Size)
{
  return FreePool (Ptr);
}

void * operator new(size_t Size)
{
  return AllocatePool (Size);
}

void * operator new[](size_t Size)
{
  return AllocatePool (Size);
}