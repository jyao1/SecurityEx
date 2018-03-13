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

%define MSR_IA32_SYSENTER_CS   0x174
%define MSR_IA32_SYSENTER_ESP  0x175
%define MSR_IA32_SYSENTER_EIP  0x176

    SECTION .text

global ASM_PFX(RingSwitch)
ASM_PFX(RingSwitch):
    cli
    mov      ecx, MSR_IA32_SYSENTER_CS
    mov      eax, cs
    xor      edx, edx
    wrmsr
    mov      ecx, MSR_IA32_SYSENTER_EIP
    mov      eax, ASM_PFX(SmiRing0ExitProc)
    xor      edx, edx
    wrmsr
    mov      ecx, MSR_IA32_SYSENTER_ESP
    mov      eax, esp
    xor      edx, edx
    wrmsr

    ; prepare enter ring 3
    mov     edx, Ring3                  ; RIP for Ring3
    mov     ecx, esp                    ; RSP for Ring3
    SYSEXIT
Ring3:
    ; we are in ring 3 now
    mov    eax, ss
    mov    ds, eax
    mov    es, eax
    mov    fs, eax
    mov    gs, eax

    ; prepare enter ring 0
    SYSENTER

ASM_PFX(SmiRing0ExitProc):
    ; we are in ring 0 now
    mov    eax, ss
    mov    ds, eax
    mov    es, eax
    mov    fs, eax
    mov    gs, eax

    ret