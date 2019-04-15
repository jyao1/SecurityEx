/** @file

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PE_LOAD_CONFIGURATION_H__
#define __PE_LOAD_CONFIGURATION_H__

///
/// Load Configuration Layout
/// the data structure for EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
///
typedef struct {
  UINT32  Characteristics;
  UINT32  TimeDateStamp;
  UINT16  MajorVersion;
  UINT16  MinorVersion;
  UINT32  GlobalFlagsClear;
  UINT32  GlobalFlagsSet;
  UINT32  CriticalSectionDefaultTimeout;
  UINT32  DeCommitFreeBlockThreshold;
  UINT32  DeCommitTotalFreeThreshold;
  UINT32  LockPrefixTable;
  UINT32  MaximumAllocationSize;
  UINT32  VirtualMemoryThreshold;
  UINT32  ProcessAffinityMask;
  UINT32  ProcessHeapFlags;
  UINT16  CSDVersion;
  UINT16  Reserved;
  UINT32  EditList;
  UINT32  SecurityCookie;
  UINT32  SEHandlerTable;
  UINT32  SEHandlerCount;
  UINT32  GuardCFCheckFunctionPointer;    /// The VA where Control Flow Guard check-function pointer is stored.
  UINT32  GuardCFDispatchFunctionPointer; /// The VA where Control Flow Guard dispatch-function pointer is stored.
  UINT32  GuardCFFunctionTable;           /// The VA of the sorted table of RVAs of each Control Flow Guard function in the image.
  UINT32  GuardCFFunctionCount;           /// The count of unique RVAs in the above table.
  UINT32  GuardFlags;                     /// Control Flow Guard related flags.
  UINT8   CodeIntegrity[12];              /// Code integrity information.
  UINT32  GuardAddressTakenIatEntryTable; /// The VA where Control Flow Guard address taken IAT table is stored.
  UINT32  GuardAddressTakenIatEntryCount; /// The count of unique RVAs in the above table.
  UINT32  GuardLongJumpTargetTable;       /// The VA where Control Flow Guard long jump target table is stored.
  UINT32  GuardLongJumpTargetCount;       /// The count of unique RVAs in the above table.
} EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32;

typedef struct {
  UINT32  Characteristics;
  UINT32  TimeDateStamp;
  UINT16  MajorVersion;
  UINT16  MinorVersion;
  UINT32  GlobalFlagsClear;
  UINT32  GlobalFlagsSet;
  UINT32  CriticalSectionDefaultTimeout;
  UINT64  DeCommitFreeBlockThreshold;
  UINT64  DeCommitTotalFreeThreshold;
  UINT64  LockPrefixTable;
  UINT64  MaximumAllocationSize;
  UINT64  VirtualMemoryThreshold;
  UINT64  ProcessAffinityMask;
  UINT32  ProcessHeapFlags;
  UINT16  CSDVersion;
  UINT16  Reserved;
  UINT64  EditList;
  UINT64  SecurityCookie;
  UINT64  SEHandlerTable;
  UINT64  SEHandlerCount;
  UINT64  GuardCFCheckFunctionPointer;    /// The VA where Control Flow Guard check-function pointer is stored.
  UINT64  GuardCFDispatchFunctionPointer; /// The VA where Control Flow Guard dispatch-function pointer is stored.
  UINT64  GuardCFFunctionTable;           /// The VA of the sorted table of RVAs of each Control Flow Guard function in the image.
  UINT64  GuardCFFunctionCount;           /// The count of unique RVAs in the above table.
  UINT32  GuardFlags;                     /// Control Flow Guard related flags.
  UINT8   CodeIntegrity[12];              /// Code integrity information.
  UINT64  GuardAddressTakenIatEntryTable; /// The VA where Control Flow Guard address taken IAT table is stored.
  UINT64  GuardAddressTakenIatEntryCount; /// The count of unique RVAs in the above table.
  UINT64  GuardLongJumpTargetTable;       /// The VA where Control Flow Guard long jump target table is stored.
  UINT64  GuardLongJumpTargetCount;       /// The count of unique RVAs in the above table.
} EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64;

typedef union {
  EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32  Entry32;
  EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64  Entry64;
} EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_UNION;

typedef union {
  EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_32  *Entry32;
  EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_64  *Entry64;
} EFI_IMAGE_LOAD_CONFIGURATION_ENTRY_PTR_UNION;

/// Module performs control flow integrity checks using system-supplied support.
#define IMAGE_GUARD_CF_INSTRUMENTED 0x00000100

/// Module performs control flow and write integrity checks.
#define IMAGE_GUARD_CFW_INSTRUMENTED 0x00000200

/// Module contains valid control flow target metadata.
#define IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT 0x00000400

/// Module does not make use of the /GS security cookie.
#define IMAGE_GUARD_SECURITY_COOKIE_UNUSED 0x00000800

/// Module supports read only delay load IAT.
#define IMAGE_GUARD_PROTECT_DELAYLOAD_IAT 0x00001000

/// Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected.
#define IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION 0x00002000

/// Module contains suppressed export information.
/// This also infers that the address taken IAT table is also present in the load config.
#define IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000

/// Module enables suppression of exports.
#define IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION 0x00008000

/// Module contains longjmp target information.
#define IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT 0x00010000

/// Mask for the subfield that contains the stride of Control Flow Guard function table entries
/// (that is, the additional count of bytes per table entry).
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK 0xF0000000

/// Additionally, the Windows SDK winnt.h header defines this macro
/// for the amount of bits to right-shift the GuardFlags value to
/// right-justify the Control Flow Guard function table stride:
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT 28

#endif