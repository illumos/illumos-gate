/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2012, Richard Lowe.
 */

#include <stdio.h>
#include <sys/types.h>
#include <saveargs.h>

#define	DEF_TEST(name)		\
    extern uint8_t name[];	\
    extern int name##_end

#define	SIZE_OF(name) ((caddr_t)&name##_end - (caddr_t)&name)

#define	TEST_GOOD(name, argc)					\
	if (saveargs_has_args(name, SIZE_OF(name), argc, 0) ==	\
	    SAVEARGS_TRAD_ARGS)					\
		printf("Pass: %s\n", #name);			\
	else							\
		printf("FAIL: %s\n", #name);

#define	TEST_GOOD_STRUCT(name, argc)				\
	if (saveargs_has_args(name, SIZE_OF(name), argc, 1) ==	\
	    SAVEARGS_STRUCT_ARGS)				\
		printf("Pass: %s\n", #name);			\
	else							\
		printf("FAIL: %s\n", #name);

/*
 * GCC deals with structures differently, so TRAD args is actually correct for
 * this
 */
#define	TEST_GOOD_GSTRUCT(name, argc)				\
	if (saveargs_has_args(name, SIZE_OF(name), argc, 1) ==	\
	    SAVEARGS_TRAD_ARGS)					\
		printf("Pass: %s\n", #name);			\
	else							\
		printf("FAIL: %s\n", #name);

#define	TEST_BAD(name, argc)					\
	if (saveargs_has_args(name, SIZE_OF(name), argc, 0) == 	\
		SAVEARGS_NO_ARGS)				\
		printf("Pass: %s\n", #name);			\
	else							\
		printf("FAIL: %s\n", #name);

#define	TEST_BAD_STRUCT(name, argc)				\
	if (saveargs_has_args(name, SIZE_OF(name), argc, 1) == 	\
		SAVEARGS_NO_ARGS)				\
		printf("Pass: %s\n", #name);			\
	else							\
		printf("FAIL: %s\n", #name);

#define	TEST_BAD_GSTRUCT(name, argc)				\
	if (saveargs_has_args(name, SIZE_OF(name), argc, 1) == 	\
		SAVEARGS_NO_ARGS)				\
		printf("Pass: %s\n", #name);			\
	else							\
		printf("FAIL: %s\n", #name);

DEF_TEST(gcc_mov_align);
DEF_TEST(gcc_mov_basic);
DEF_TEST(gcc_mov_noorder);
DEF_TEST(gcc_mov_struct_noorder);
DEF_TEST(gcc_mov_big_struct_ret);
DEF_TEST(gcc_mov_big_struct_ret_and_spill);
DEF_TEST(gcc_mov_small_struct_ret);
DEF_TEST(gcc_mov_small_struct_ret_and_spill);
DEF_TEST(gcc_mov_stack_spill);

DEF_TEST(gcc_push_align);
DEF_TEST(gcc_push_basic);
DEF_TEST(gcc_push_noorder);
DEF_TEST(gcc_push_struct_noorder);
DEF_TEST(gcc_push_big_struct_ret);
DEF_TEST(gcc_push_big_struct_ret_and_spill);
DEF_TEST(gcc_push_small_struct_ret);
DEF_TEST(gcc_push_small_struct_ret_and_spill);
DEF_TEST(gcc_push_stack_spill);

DEF_TEST(ss_mov_align);
DEF_TEST(ss_mov_basic);
DEF_TEST(ss_mov_big_struct_ret);
DEF_TEST(ss_mov_big_struct_ret_and_spill);
DEF_TEST(ss_mov_small_struct_ret);
DEF_TEST(ss_mov_small_struct_ret_and_spill);
DEF_TEST(ss_mov_stack_spill);

DEF_TEST(dtrace_instrumented);
DEF_TEST(kmem_alloc);
DEF_TEST(uts_kill);
DEF_TEST(av1394_ic_bitreverse);

DEF_TEST(small_struct_ret_w_float);
DEF_TEST(big_struct_ret_w_float);

DEF_TEST(interleaved_argument_saves);
DEF_TEST(jmp_table);

/*
 * Functions which should not match
 *
 * no_fp			-- valid save-args sequence with no saved FP
 * big_struct_arg_by_value	-- function with big struct passed by value
 * small_struct_arg_by_value	-- function with small struct passed by value
 */
DEF_TEST(no_fp);
DEF_TEST(big_struct_arg_by_value);
DEF_TEST(small_struct_arg_by_value);

int
main(int argc, char **argv)
{
	TEST_GOOD(kmem_alloc, 2);
	TEST_GOOD(uts_kill, 2);
	TEST_GOOD(av1394_ic_bitreverse, 1);
	TEST_GOOD(dtrace_instrumented, 4);
	TEST_GOOD_GSTRUCT(big_struct_ret_w_float, 1);
	TEST_BAD(no_fp, 5);

	TEST_GOOD(gcc_mov_align, 5);
	TEST_GOOD(gcc_push_align, 5);
	TEST_GOOD(ss_mov_align, 5);

	TEST_GOOD(gcc_mov_basic, 4);
	TEST_GOOD(gcc_push_basic, 4);
	TEST_GOOD(ss_mov_basic, 4);

	TEST_GOOD(gcc_mov_noorder, 4);
	TEST_GOOD(gcc_push_noorder, 4);

	TEST_GOOD_GSTRUCT(gcc_mov_big_struct_ret, 4);
	TEST_GOOD_GSTRUCT(gcc_push_big_struct_ret, 4);
	TEST_GOOD_STRUCT(ss_mov_big_struct_ret, 4);

	TEST_GOOD_GSTRUCT(gcc_mov_struct_noorder, 4);
	TEST_GOOD_GSTRUCT(gcc_push_struct_noorder, 4);

	TEST_GOOD_GSTRUCT(gcc_mov_big_struct_ret_and_spill, 8);
	TEST_GOOD_GSTRUCT(gcc_push_big_struct_ret_and_spill, 8);
	TEST_GOOD_STRUCT(ss_mov_big_struct_ret_and_spill, 8);

	TEST_GOOD(gcc_mov_small_struct_ret, 4);
	TEST_GOOD(gcc_push_small_struct_ret, 4);
	TEST_GOOD(ss_mov_small_struct_ret, 4);

	TEST_GOOD(gcc_mov_small_struct_ret_and_spill, 8);
	TEST_GOOD(gcc_push_small_struct_ret_and_spill, 8);
	TEST_GOOD(ss_mov_small_struct_ret_and_spill, 8);

	TEST_GOOD(gcc_mov_stack_spill, 8);
	TEST_GOOD(gcc_push_stack_spill, 8);
	TEST_GOOD(ss_mov_stack_spill, 8);

	TEST_BAD(big_struct_arg_by_value, 2);
	TEST_BAD(small_struct_arg_by_value, 2);

	TEST_BAD(small_struct_ret_w_float, 1);

	TEST_GOOD(interleaved_argument_saves, 4);
	TEST_BAD(jmp_table, 1);

	return (0);
}
