# UEFI/EDKII Security Enhancement summary

## Code Integrity Guard (CIG)

### UEFI Secure Boot

Technology: UEFI image signature verification

Status: _Production_

The platform variable region need use [EFI_AUTHENTICATED_VARIABLE_GUID](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/VariableFormat.h) format.

The variable driver need link [AuthVariableLib](https://github.com/tianocore/edk2/tree/master/SecurityPkg/Library/AuthVariableLib) instance.

UEFI secure boot enable/disable is controlled by variable [EFI_SECURE_BOOT_ENABLE_NAME](https://github.com/tianocore/edk2/blob/master/SecurityPkg/Include/Guid/AuthenticatedVariableFormat.h):[gEfiSecureBootEnableDisableGuid](https://github.com/tianocore/edk2/blob/master/SecurityPkg/SecurityPkg.dec).

### PI FV verified boot

Technology: PI firmware volume verification

Status: _Production_

The platform PEI (initial boot block) need verify the OEM boot block (OBB) by using [FvReportPei](https://github.com/tianocore/edk2/tree/master/SecurityPkg/FvReportPei), after memory is discovered.

The platform need install [EDKII_PEI_FIRMWARE_VOLUME_INFO_STORED_HASH_FV_PPI](https://github.com/tianocore/edk2/blob/master/SecurityPkg/Include/Ppi/FirmwareVolumeInfoStoredHashFv.h) to convey FVs and hash information of a specific platform.

## Data Execution Protection (DEP) & Arbitrary Code Guard (ACG)

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

### SMM Code Access Check

Technology: Only the SMM code covered by SMRAM Range Register (SMRR) can be executable.

Status: _Production_

SMM controlled by: gUefiCpuPkgTokenSpaceGuid.PcdCpuSmmCodeAccessCheckEnable in [UefiCpuPkg.dec](https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/UefiCpuPkg.dec).

## NULL pointer detection

Technology: mark the first 4K page to be not present to detect NULL pointer dereference

Status: _Production_

Controlled by: gEfiMdeModulePkgTokenSpaceGuid.PcdNullPointerDetectionPropertyMask in [MdeModulePkg.dec](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec).

## Address Space Layout Randomization (ASLR)

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

### Software Control Flow Integrity/Guard (CFI/CFG)

Technology : Use compiler to insert control flow check to detect control flow attack (need compiler support)

Status: _Prototype_

MSVC compiler stub (/guard:cf) prototype is at [CfgStub.c](https://github.com/jyao1/SecurityEx/blob/master/ControlFlowPkg/Library/CfgStubLib/CfgStub.c), 
LLVM compiler stub (-fsanitize=cfi) prototype is at [CfiStub.c](https://github.com/jyao1/SecurityEx/blob/master/ControlFlowPkg/Library/CfgStubLib/CfiStub.c).

## PreBoot DMA Prevention

### IOMMU Engine Based Protection (Intel VTd)

Technology : Enable IOMMU in BIOS to prevent DMA attack from device.

Status: _Production_

DXE enabled by: [IntelVTdDxe](https://github.com/tianocore/edk2-platforms/tree/master/Silicon/Intel/IntelSiliconPkg/Feature/VTd/IntelVTdDxe), 
PEI enabled by: [IntelVTdDmarPei](https://github.com/tianocore/edk2-platforms/tree/master/Silicon/Intel/IntelSiliconPkg/Feature/VTd/IntelVTdDmarPei).

### Silicon specific DMA Protection (Intel VTd PMR)

Technology : Enable Protected Memory Region (PMR) in PEI phase as a lightweight solution.

Status: _Production_

PEI enabled by: [IntelVTdPmrPei](https://github.com/tianocore/edk2-platforms/tree/master/Silicon/Intel/IntelSiliconPkg/Feature/VTd/IntelVTdPmrPei).

## Reference

A list of security whitepaper can be found at [EDK II Security White Papers](https://github.com/tianocore/tianocore.github.io/wiki/EDK-II-Security-White-Papers).

1) [A Tour Beyond BIOS - Security Enhancement to Mitigate Buffer Overflow in UEFI](https://edk2-docs.gitbook.io/a-tour-beyond-bios-mitigate-buffer-overflow-in-ue/)

2) [A Tour Beyond BIOS - Memory Map And Practices in UEFI BIOS](https://edk2-docs.gitbook.io/a-tour-beyond-bios-memory-protection-in-uefi-bios/)

3) [SMM protection in EDKII](http://www.uefi.org/sites/default/files/resources/Jiewen%20Yao%20-%20SMM%20Protection%20in%20%20EDKII_Intel.pdf)

4) [CET-in-SMM](https://github.com/tianocore/tianocore.github.io/wiki/CET-in-SMM)

6) [A Tour Beyond BIOS - Using IOMMU for DMA Protection in UEFI firmware](https://www.intel.com/content/dam/develop/external/us/en/documents/intel-whitepaper-using-iommu-for-dma-protection-in-uefi.pdf)

7) [Windows DMA Protection](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection)

8) [Intel 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)