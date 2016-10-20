# These packages are to demonstrate how we enable security enhancement to prevent or detect buffer overflow in UEFI firmware.

## Feature:
1) AslrPkg

This package is to demonstrate Address Space Layout Randomization (ASLR).

UEFI randomization support stack/heap randomization and image shuffle.
  1.1) AslrPkg\Override\MdeModulePkg\Core\Dxe.
  1.2) AslrPkg\Override\MdeModulePkg\Core\DxeIplPeim.

SMM randomization support stack/heap randomization and image shuffle.
  1.3) AslrPkg\Override\MdeModulePkg\Core\PiSmmCore.

2) OverflowDetectionPkg

This package is to demonstrate how to detect stack overflow, heap overflow, NULL pointer reference.

Stack overflow detection.
  2.1) OverflowDetectionPkg\StackGuard.

Heap overflow detection.
  2.2) OverflowDetectionPkg\Override\MdeModulePkg\Core\Dxe.
  2.3) OverflowDetectionPkg\Override\MdeModulePkg\Core\PiSmmCore.

NULL pointer reference.
  2.4) OverflowDetectionPkg\NullPointerProtection.

Unit Test.
  2.5) OverflowDetectionPkg\Test\HeapOverflow.
  2.6) OverflowDetectionPkg\Test\StackOverflow.

3) StackCheckPkg

This package is to demonstrate how to use compiler option to check stack.

Using Microsoft Visual Studio: /GS /RTcs, and GCC: -fstack-protector-strong.
  3.1) StackCheckPkg\Library\StackCheckLib.

Unit Test.
  3.2) StackCheckPkg\Test\StackCookieTest.

## Known limitation:
This package is only the sample code to show the concept.
It does not have a full validation and does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.


