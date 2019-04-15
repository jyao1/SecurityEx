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

void _RTCc_Failure () {
  DEBUG ((EFI_D_ERROR, "\n!!! small type check failed!!!\n"));
  ASSERT (FALSE);

  CpuDeadLoop();
  return ;
}

char   __fastcall _RTC_Check_2_to_1(short _Src)
{
  if ((_Src & 0xFF00) != 0) {
    _RTCc_Failure ();
  }
  return (char)(_Src & 0xFF);
}

char   __fastcall _RTC_Check_4_to_1(int _Src)
{
  if ((_Src & 0xFFFFFF00) != 0) {
    _RTCc_Failure ();
  }
  return (char)(_Src & 0xFF);
}

char   __fastcall _RTC_Check_8_to_1(__int64 _Src)
{
  if ((_Src & 0xFFFFFFFFFFFFFF00) != 0) {
    _RTCc_Failure ();
  }
  return (char)(_Src & 0xFF);
}

short  __fastcall _RTC_Check_4_to_2(int _Src)
{
  if ((_Src & 0xFFFF0000) != 0) {
    _RTCc_Failure ();
  }
  return (short)(_Src & 0xFFFF);
}

short  __fastcall _RTC_Check_8_to_2(__int64 _Src)
{
  if ((_Src & 0xFFFFFFFFFFFF0000) != 0) {
    _RTCc_Failure ();
  }
  return (short)(_Src & 0xFFFF);
}

int    __fastcall _RTC_Check_8_to_4(__int64 _Src)
{
  if ((_Src & 0xFFFFFFFF00000000) != 0) {
    _RTCc_Failure ();
  }
  return (int)(_Src & 0xFFFFFFFF);
}
