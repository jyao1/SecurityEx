;------------------------------------------------------------------------------
;
; Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
; This program and the accompanying materials
; are licensed and made available under the terms and conditions of the BSD License
; which accompanies this distribution.  The full text of the license may be found at
; http://opensource.org/licenses/bsd-license.php.
;
; THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
; WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;
; Module Name:
; 
;    UserMode.asm
;
;------------------------------------------------------------------------------

.686P
.MMX
.MODEL FLAT,C

MSR_IA32_SYSENTER_ESP EQU 175h

EXTERNDEF   AsmUserDs:DWORD
EXTERNDEF   AsmSystemDs:DWORD

.CODE

AsmUserModeEnter PROC PUBLIC
    ; update IOPL
    pushfd
    pop     eax
    or      eax, 0x3000                 ; set IOPL [BIT12~BIT13] to ring 3 
    push    eax
    popfd

    ; update RSP
    mov     ecx, MSR_IA32_SYSENTER_ESP
    mov     eax, esp
    xor     edx, edx
    wrmsr

    ; prepare enter ring 3
    ; jmp $
    mov     edx, Ring3                  ; RIP for Ring3
    mov     ecx, esp                    ; RSP for Ring3
    DB 0fh,35h ; SYSEXIT
Ring3:
    ; we are in ring 3 now
    ; jmp $
    DB     0b8h      ; mov    eax, USER_DATA_SEGMENT + 3
AsmUserDs   DD     00000000h
    mov    ds, eax
    mov    es, eax
    mov    fs, eax
    mov    gs, eax

    ret
AsmUserModeEnter  ENDP

AsmUserModeExit  PROC PUBLIC
    ; prepare enter ring 0
    ; jmp $
    DB 0fh, 34h ; SYSENTER
    jmp $
AsmUserModeExit  ENDP

AsmSystemModeEnter PROC PUBLIC
    DB     0b8h      ; mov    eax, SYSTEM_DATA_SEGMENT
AsmSystemDs DD     00000000h
    mov    ds, eax
    mov    es, eax
    mov    ss, eax

    ret
AsmSystemModeEnter ENDP

END
