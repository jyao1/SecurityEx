# Security Enhancement summary

## Data Execution Protection

### Image Protection

Technology: Set PE image code region to readonly, data region to be non-executable.

Status: _Production_

DXE controlled by: gEfiMdeModulePkgTokenSpaceGuid.PcdImageProtectionPolicy in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec), 
SMM enabled by default.

### Non-Executable Memory protection

Technology: Set data region to be non-executable

Status: _Production_

DXE controlled by: gEfiMdeModulePkgTokenSpaceGuid.PcdDxeNxMemoryProtectionPolicy in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec), 
SMM enabled by default.

## NULL pointer detection

Technology: mark the first 4K page to be not present to detect NULL pointer dereference

Status: _Production_

Controlled by: gEfiMdeModulePkgTokenSpaceGuid.PcdNullPointerDetectionPropertyMask in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec).

## Address Space Layout Randomization

### Image Shuffle

Technology: Shuffle the loaded image

Status: _Prototype_

ImageShuffle is configured by [PcdImageShuffleEnable](https://github.com/jyao1/SecurityEx/blob/master/AslrPkg/AslrPkg.dec). 
DXE prototype is at [DxeCore](https://github.com/jyao1/SecurityEx/tree/master/AslrPkg/Override/MdeModulePkg/Core/Dxe), 
SMM prototype is at [PiSmmCore](https://github.com/jyao1/SecurityEx/tree/master/AslrPkg/Override/MdeModulePkg/Core/PiSmmCore).

### Data Buffer Shift

Technology: Shift the data buffer - heap and stack

Status: _Prototype_

Randomization is configured by [PcdASLRMinimumEntropyBits](https://github.com/jyao1/SecurityEx/blob/master/AslrPkg/AslrPkg.dec),
DXE prototype is at [DxeCore](https://github.com/jyao1/SecurityEx/tree/master/AslrPkg/Override/MdeModulePkg/Core/Dxe) and [DxeIpl](https://github.com/jyao1/SecurityEx/tree/master/AslrPkg/Override/MdeModulePkg/Core/DxeIplPeim), 
SMM prototype is at [PiSmmCore](https://github.com/jyao1/SecurityEx/tree/master/AslrPkg/Override/MdeModulePkg/Core/PiSmmCore).

## Buffer Overflow Detection

### Stack Guard

Technology: Use guard page to detect global stack overflow.

Status: _Production_

DXE controlled by: gEfiMdeModulePkgTokenSpaceGuid.PcdCpuStackGuard in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec), 
SMM controlled by: gUefiCpuPkgTokenSpaceGuid.PcdCpuSmmStackGuard in [UefiCpuPkg.dec](https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/UefiCpuPkg.dec).

### Heap Guard

Technology: Use guard page to detect heap overflow.

Status: _Debug_

Controlled by: gEfiMdeModulePkgTokenSpaceGuid.PcdHeapGuardPropertyMask in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec), 
gEfiMdeModulePkgTokenSpaceGuid.PcdHeapGuardPageType in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec), 
gEfiMdeModulePkgTokenSpaceGuid.PcdHeapGuardPoolType in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec).

### Stack Canary

Technology: Use compiler to insert cookie to detect local stack overflow (need compiler support)

Status: _Prototype_

MSVC compiler stub (/GS) prototype is at [GSStub.c](https://github.com/jyao1/SecurityEx/blob/master/StackCheckPkg/Library/StackCheckLib/GSStub.c), 
GCC/LLVM compiler stub (-fstack-protector-strong) prototype is at [StackProtectorStub.c](https://github.com/jyao1/SecurityEx/blob/master/StackCheckPkg/Library/StackCheckLib/StackProtectorStub.c).

### Address Sanitizer

Technology: Use compiler to insert redzone to detect buffer overflow (need compiler support)

Status: _Prototype_, _Debug_

MSVC compiler stub (/RTCs) prototype is at [RTCsStub.c](https://github.com/jyao1/SecurityEx/blob/master/StackCheckPkg/Library/StackCheckLib/RTCsStub.c), 
LLVM compiler stub (-fsanitize=address) prototype is at [ASanStub.c](https://github.com/jyao1/SecurityEx/blob/master/StackCheckPkg/Library/StackCheckLib/ASanStub.c).

## Misc Runtime Check

### Undefined Behavior Sanitizer (Type Cast)

Technology: Use compiler to insert runtime check for undefined behavior such as type cast. (need compiler support)

Status: _Prototype_, _Debug_

MSVC compiler stub (/RTCc) prototype is at [RTCcStub.c](https://github.com/jyao1/SecurityEx/blob/master/StackCheckPkg/Library/StackCheckLib/RTCcStub.c), 
LLVM compiler stub (-fsanitize=undefined) protype is at [UBSanStub.c](https://github.com/jyao1/SecurityEx/blob/master/StackCheckPkg/Library/StackCheckLib/UBSanStub.c).

### Memory Sanitizer (Uninitialized Access)

Technology: Use compiler to insert check to detect uninitialized data read. (need compiler support)

Status: _Prototype_, _Debug_

MSVC compiler stub (/RTCu) prototype is at [RTCuStub.c](https://github.com/jyao1/SecurityEx/blob/master/StackCheckPkg/Library/StackCheckLib/RTCuStub.c), 
LLVM (-fsanitize=memory) cannot be enabled because it does not support windows platform yet.

## Control Flow

### Shadow Stack (Intel CET-SS)

Technology : return address protection to defend against Return Oriented Programming

Status: SMM _production_, DXE _prototype_

SMM shadow stack is controlled by gEfiMdePkgTokenSpaceGuid.PcdControlFlowEnforcementPropertyMask in [MdePkg.c](https://github.com/tianocore/edk2/blob/master/MdePkg/MdePkg.dec), 
DXE shadow stack prototype is at [DxeCet](https://github.com/jyao1/SecurityEx/tree/master/ControlFlowPkg/DxeCet/Override).

### Indirect Branch Tracking (Intel CET-IBT)

Technology : free branch protection to defend against Jump/Call Oriented Programming (need compiler support)

Status: _Prototype_

Prototype is at [Ibt](https://github.com/jyao1/SecurityEx/tree/master/ControlFlowPkg/Ibt/Override/UefiCpuPkg). The IBT cannot be enabled in MSVC, because the compiler does NOT support it yet.

### Software Control Flow Integrity/Guard

Technology : Use compiler to insert control flow check to detect control flow attack (need compiler support)

Status: _Prototype_

MSVC compiler stub (/guard:cf) prototype is at [CfgStub.c](https://github.com/jyao1/SecurityEx/blob/master/ControlFlowPkg/Library/CfgStubLib/CfgStub.c), 
LLVM compiler stub (-fsanitize=cfi) prototype is at [CfiStub.c](https://github.com/jyao1/SecurityEx/blob/master/ControlFlowPkg/Library/CfgStubLib/CfiStub.c).

## Reference

1) [A Tour Beyond BIOS - Security Enhancement to Mitigate Buffer Overflow in UEFI](https://edk2-docs.gitbook.io/a-tour-beyond-bios-mitigate-buffer-overflow-in-ue/)

2) [A Tour Beyond BIOS - Memory Map And Practices in UEFI BIOS](https://edk2-docs.gitbook.io/a-tour-beyond-bios-memory-protection-in-uefi-bios/)

3) [SMM protection in EDKII](http://www.uefi.org/sites/default/files/resources/Jiewen%20Yao%20-%20SMM%20Protection%20in%20%20EDKII_Intel.pdf)

4) [CET-in-SMM](https://github.com/tianocore/tianocore.github.io/wiki/CET-in-SMM)


