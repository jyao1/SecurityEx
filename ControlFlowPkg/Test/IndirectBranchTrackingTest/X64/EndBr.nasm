;------------------------------------------------------------------------------ ;
; Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
; This program and the accompanying materials
; are licensed and made available under the terms and conditions of the BSD License
; which accompanies this distribution.  The full text of the license may be found at
; http://opensource.org/licenses/bsd-license.php.
;
; THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
; WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;
;-------------------------------------------------------------------------------

DEFAULT REL
SECTION .text

ASM_PFX(TargetFunc):
  DB      0xF3, 0x0F, 0x1E, 0xFA    ;    endbr64
  ret

global ASM_PFX(EndBrTest)
ASM_PFX(EndBrTest):
  mov  rax, ASM_PFX(TargetFunc)
  add  rax, 4
  call rax
  ret
