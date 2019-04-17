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
  This is merged into EDKII.

2.2) Heap overflow detection.
  This is merged into EDKII.

2.3) NULL pointer reference.
  This is merged into EDKII.

2.4) Unit Test.
  OverflowDetectionPkg\Test\HeapOverflow.
  OverflowDetectionPkg\Test\StackOverflow.

3) StackCheckPkg

This package is to demonstrate how to use compiler option for runtime stack.

3.1) Using Microsoft Visual Studio: /GS /RTCs /RTCc /RTCu, and GCC: -fstack-protector-strong.
  StackCheckPkg\Library\StackCheckLib.

3.2) Unit Test.
  StackCheckPkg\Test\SmallTypeTest             - Test /RTCc and -fstack-protector-strong
  StackCheckPkg\Test\StackCookieTest           - Test /GS
  StackCheckPkg\Test\StackFrameTest            - Test /RTCs
  StackCheckPkg\Test\UninitializedVariableTest - Test /RTCu

For more detail, please refer to https://www.gitbook.com/book/edk2-docs/a-tour-beyond-bios-mitigate-buffer-overflow-in-ue/details

4) ControlFlowPkg

This package is to demonstrate Control Flow Enforcement.

4.1) Using Intel CET-ShadowStack in SMM
  This is merged into EDKII.

4.2) Using Intel CET-ShadowStack in DXE
  ControlFlowPkg\DxeCet

4.3) Using Intel CET-IBT
  ControlFlowPkg\Ibt

4.4) Using Microsoft Visual Studio: /guard:cf
  ControlFlowPkg\Library\CfgStubLib

4.5) Unit Test
  ControlFlowPkg\Test\ShadowStackTest
  ControlFlowPkg\Test\IndirectBranchTrackingTest
  ControlFlowPkg\CfgTest\CfgTest

For CET in SMM, please refer to https://github.com/tianocore/tianocore.github.io/wiki/CET-in-SMM 

## Known limitation:
This package is only the sample code to show the concept.
It does not have a full validation and does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.


