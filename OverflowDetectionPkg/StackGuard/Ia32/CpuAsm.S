#------------------------------------------------------------------------------
#*
#*   Copyright (c) 2006 - 2013, Intel Corporation. All rights reserved.<BR>
#*   This program and the accompanying materials
#*   are licensed and made available under the terms and conditions of the BSD License
#*   which accompanies this distribution.  The full text of the license may be found at
#*   http://opensource.org/licenses/bsd-license.php
#*
#*   THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
#*   WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#*
#*    CpuAsm.S
#*
#*   Abstract:
#*
#------------------------------------------------------------------------------


#.MMX
#.XMM

#------------------------------------------------------------------------------
# VOID
# LoadTask (
#   UINT16 Selector
#   );
#------------------------------------------------------------------------------
ASM_GLOBAL ASM_PFX(LoadTask)
ASM_PFX(LoadTask):
    movl    4(%esp), %eax
    ltrw    %ax
    ret

#END

