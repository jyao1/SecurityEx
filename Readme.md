# These packages are to demonstrate how we enable security enhancement to prevent or detect buffer overflow in UEFI firmware.

## Feature:
1) AslrPkg

This package is to demonstrate Address Space Layout Randomization (ASLR).

1.1) UEFI randomization support stack/heap randomization and image shuffle.
  AslrPkg\Override\MdeModulePkg\Core\Dxe.
  AslrPkg\Override\MdeModulePkg\Core\DxeIplPeim.

1.2) SMM randomization support stack/heap randomization and image shuffle.
  AslrPkg\Override\MdeModulePkg\Core\PiSmmCore.

2) OverflowDetectionPkg

This package is to demonstrate how to detect stack overflow, heap overflow, NULL pointer reference.

2.1) Stack overflow detection.
  OverflowDetectionPkg\StackGuard.

2.2) Heap overflow detection.
  OverflowDetectionPkg\Override\MdeModulePkg\Core\Dxe.
  OverflowDetectionPkg\Override\MdeModulePkg\Core\PiSmmCore.

2.3) NULL pointer reference.
  OverflowDetectionPkg\NullPointerProtection.

2.4) Unit Test.
  OverflowDetectionPkg\Test\HeapOverflow.
  OverflowDetectionPkg\Test\StackOverflow.

3) StackCheckPkg

This package is to demonstrate how to use compiler option to check stack.

3.1) Using Microsoft Visual Studio: /GS /RTcs, and GCC: -fstack-protector-strong.
  StackCheckPkg\Library\StackCheckLib.

3.2) Unit Test.
  StackCheckPkg\Test\StackCookieTest.

For more detail, please refer to https://github.com/tianocore-docs/Docs/raw/master/White_Papers/A_Tour_Beyond_BIOS_Securiy_Enhancement_to_Mitigate_Buffer_Overflow_in_UEFI.pdf

## Known limitation:
This package is only the sample code to show the concept.
It does not have a full validation and does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.


