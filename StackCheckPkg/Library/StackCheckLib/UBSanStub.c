/**

Copyright (c) 2012, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>

//
// https://github.com/OP-TEE/optee_os/blob/master/core/kernel/ubsan.c
//

struct source_location {
	CHAR8  *file_name;
	UINT32 line;
	UINT32 column;
};

struct type_descriptor {
	UINT16 type_kind;
	UINT16 type_info;
	CHAR8  type_name[1];
};

struct type_mismatch_data {
	struct source_location loc;
	struct type_descriptor *type;
	UINTN                   alignment;
	UINT8                   type_check_kind;
};

struct overflow_data {
	struct source_location loc;
	struct type_descriptor *type;
};

struct shift_out_of_bounds_data {
	struct source_location loc;
	struct type_descriptor *lhs_type;
	struct type_descriptor *rhs_type;
};

struct out_of_bounds_data {
	struct source_location loc;
	struct type_descriptor *array_type;
	struct type_descriptor *index_type;
};

struct unreachable_data {
	struct source_location loc;
};

struct vla_bound_data {
	struct source_location loc;
	struct type_descriptor *type;
};

struct invalid_value_data {
	struct source_location loc;
	struct type_descriptor *type;
};

struct nonnull_arg_data {
	struct source_location loc;
};

STATIC VOID print_loc(struct source_location *loc)
{
  DEBUG ((DEBUG_ERROR, "  at %a:%d col %d\n", loc->file_name, loc->line, loc->column));
}

STATIC VOID panic(VOID)
{
  ASSERT (FALSE);
  CpuDeadLoop();
}

//STATIC BOOLEAN ubsan_panic = TRUE;

VOID
__ubsan_handle_type_mismatch(
  struct type_mismatch_data *data,
  UINTN                     ptr
  );

VOID
__ubsan_handle_add_overflow(
  struct overflow_data *data,
  UINTN lhs,
  UINTN rhs
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_add_overflow - 0x%x, 0x%x!!!\n", lhs, rhs));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_sub_overflow(
  struct overflow_data *data,
  UINTN lhs,
  UINTN rhs
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_sub_overflow - 0x%x, 0x%x!!!\n", lhs, rhs));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_mul_overflow(
  struct overflow_data *data,
  UINTN lhs,
  UINTN rhs
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_mul_overflow - 0x%x, 0x%x!!!\n", lhs, rhs));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_negate_overflow(
  struct overflow_data *data,
  UINTN old_val
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_negate_overflow - 0x%x!!!\n", old_val));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_divrem_overflow(
  struct overflow_data *data,
  UINTN lhs,
  UINTN rhs
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_divrem_overflow - 0x%x, 0x%x!!!\n", lhs, rhs));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_shift_out_of_bounds(
  struct shift_out_of_bounds_data *data,
  UINTN lhs,
  UINTN rhs
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_shift_out_of_bounds - 0x%x, 0x%x!!!\n", lhs, rhs));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_out_of_bounds(
  struct out_of_bounds_data *data,
  UINTN idx
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_out_of_bounds - 0x%x!!!\n", idx));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_unreachable(
  struct unreachable_data *data
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_unreachable!!!\n"));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_missing_return(
  struct unreachable_data *data
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_missing_return!!!\n"));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_vla_bound_not_positive(
  struct vla_bound_data *data,
  UINTN bound
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_vla_bound_not_positive - 0x%x!!!\n", bound));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_load_invalid_value(
  struct invalid_value_data *data,
  UINTN val
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_load_invalid_value - 0x%x!!!\n", val));
  print_loc (&data->loc);
  panic();
}

VOID
__ubsan_handle_nonnull_arg (
  struct nonnull_arg_data *data
  )
{
  DEBUG ((DEBUG_ERROR, "\n!!! __ubsan_handle_nonnull_arg!!!\n"));
  print_loc (&data->loc);
  panic();
}

