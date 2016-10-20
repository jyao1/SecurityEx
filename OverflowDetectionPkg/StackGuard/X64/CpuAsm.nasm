;------------------------------------------------------------------------------
;*
;*   Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
;*   This program and the accompanying materials
;*   are licensed and made available under the terms and conditions of the BSD License
;*   which accompanies this distribution.  The full text of the license may be found at
;*   http://opensource.org/licenses/bsd-license.php
;*
;*   THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
;*   WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;*
;*    CpuAsm.nasm
;*
;*   Abstract:
;*
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
; VOID
; LoadTask (
;   UINT16 Selector
;   );
;------------------------------------------------------------------------------
global ASM_PFX(LoadTask)
ASM_PFX(LoadTask):
    mov     eax, ecx
    ltr     ax
    ret

