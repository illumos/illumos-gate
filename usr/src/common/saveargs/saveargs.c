/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * The Sun Studio and GCC (patched for opensolaris/illumos) compilers
 * implement a argument saving scheme on amd64 via the -Wu,save-args or
 * options.  When the option is specified, INTEGER type function arguments
 * passed via registers will be saved on the stack immediately after %rbp, and
 * will not be modified through out the life of the routine.
 *
 *				+--------+
 *		%rbp	-->     |  %rbp  |
 *				+--------+
 *		-0x8(%rbp)	|  %rdi  |
 *				+--------+
 *		-0x10(%rbp)	|  %rsi  |
 *				+--------+
 *		-0x18(%rbp)	|  %rdx  |
 *				+--------+
 *		-0x20(%rbp)	|  %rcx  |
 *				+--------+
 *		-0x28(%rbp)	|  %r8   |
 *				+--------+
 *		-0x30(%rbp)	|  %r9   |
 *				+--------+
 *
 *
 * For example, for the following function,
 *
 * void
 * foo(int a1, int a2, int a3, int a4, int a5, int a6, int a7)
 * {
 * ...
 * }
 *
 * Disassembled code will look something like the following:
 *
 *     pushq	%rbp
 *     movq	%rsp, %rbp
 *     subq	$imm8, %rsp			**
 *     movq	%rdi, -0x8(%rbp)
 *     movq	%rsi, -0x10(%rbp)
 *     movq	%rdx, -0x18(%rbp)
 *     movq	%rcx, -0x20(%rbp)
 *     movq	%r8, -0x28(%rbp)
 *     movq	%r9, -0x30(%rbp)
 *     ...
 * or
 *     pushq	%rbp
 *     movq	%rsp, %rbp
 *     subq	$imm8, %rsp			**
 *     movq	%r9, -0x30(%rbp)
 *     movq	%r8, -0x28(%rbp)
 *     movq	%rcx, -0x20(%rbp)
 *     movq	%rdx, -0x18(%rbp)
 *     movq	%rsi, -0x10(%rbp)
 *     movq	%rdi, -0x8(%rbp)
 *     ...
 * or
 *     pushq	%rbp
 *     movq	%rsp, %rbp
 *     pushq	%rdi
 *     pushq	%rsi
 *     pushq	%rdx
 *     pushq	%rcx
 *     pushq	%r8
 *     pushq	%r9
 *
 * **: The space being reserved is in addition to what the current
 *     function prolog already reserves.
 *
 * We loop through the first SAVEARGS_INSN_SEQ_LEN bytes of the function
 * looking for each argument saving instruction we would expect to see.  We
 * loop byte-by-byte, rather than doing anything smart about insn lengths,
 * only deviating from this when we know we have our insn, and can skip the
 * rest of it.
 *
 * If there are odd number of arguments to a function, additional space is
 * reserved on the stack to maintain 16-byte alignment.  For example,
 *
 *     argc == 0: no argument saving.
 *     argc == 3: save 3, but space for 4 is reserved
 *     argc == 7: save 6.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <saveargs.h>

/*
 * Size of the instruction sequence arrays.  It should correspond to
 * the maximum number of arguments passed via registers.
 */
#define	INSTR_ARRAY_SIZE	6

#define	INSTR1(ins, off) (ins[(off)])
#define	INSTR2(ins, off) (ins[(off)] + (ins[(off) + 1] << 8))
#define	INSTR3(ins, off)	\
	(ins[(off)] + (ins[(off) + 1] << 8) + (ins[(off + 2)] << 16))
#define	INSTR4(ins, off)	\
	(ins[(off)] + (ins[(off) + 1] << 8) + (ins[(off + 2)] << 16) + \
	(ins[(off) + 3] << 24))

/*
 * Sun Studio 10 patch implementation saves %rdi first;
 * GCC 3.4.3 Sun branch implementation saves them in reverse order.
 */
static const uint32_t save_instr[INSTR_ARRAY_SIZE] = {
	0xf87d8948,	/* movq %rdi, -0x8(%rbp) */
	0xf0758948,	/* movq %rsi, -0x10(%rbp) */
	0xe8558948,	/* movq %rdx, -0x18(%rbp) */
	0xe04d8948,	/* movq %rcx, -0x20(%rbp) */
	0xd845894c,	/* movq %r8, -0x28(%rbp) */
	0xd04d894c	/* movq %r9, -0x30(%rbp) */
};

static const uint16_t save_instr_push[] = {
	0x57,	/* pushq %rdi */
	0x56,	/* pushq %rsi */
	0x52,	/* pushq %rdx */
	0x51,	/* pushq %rcx */
	0x5041,	/* pushq %r8 */
	0x5141	/* pushq %r9 */
};

/*
 * If the return type of a function is a structure greater than 16 bytes in
 * size, %rdi will contain the address to which it should be stored, and
 * arguments will begin at %rsi.  Studio will push all of the normal argument
 * registers anyway, GCC will start pushing at %rsi, so we need a separate
 * pattern.
 */
static const uint32_t save_instr_sr[INSTR_ARRAY_SIZE-1] = {
	0xf8758948,	/* movq %rsi,-0x8(%rbp) */
	0xf0558948,	/* movq %rdx,-0x10(%rbp) */
	0xe84d8948,	/* movq %rcx,-0x18(%rbp) */
	0xe045894c,	/* movq %r8,-0x20(%rbp) */
	0xd84d894c	/* movq %r9,-0x28(%rbp) */
};

static const uint8_t save_fp_pushes[] = {
    0x55,	/* pushq %rbp */
    0xcc	/* int $0x3 */
};
#define	NUM_FP_PUSHES (sizeof (save_fp_pushes) / sizeof (save_fp_pushes[0]))

static const uint32_t save_fp_movs[] = {
	0x00e58948,	/* movq %rsp,%rbp, encoding 1 */
	0x00ec8b48,	/* movq %rsp,%rbp, encoding 2 */
};
#define	NUM_FP_MOVS (sizeof (save_fp_movs) / sizeof (save_fp_movs[0]))

static int
has_saved_fp(uint8_t *ins, int size)
{
	int i, j;
	uint32_t n;
	int found_push = 0;

	for (i = 0; i < size; i++) {
		if (found_push == 0) {
			n = INSTR1(ins, i);
			for (j = 0; j <= NUM_FP_PUSHES; j++)
				if (save_fp_pushes[j] == n) {
					found_push = 1;
					break;
				}
		} else {
			n = INSTR3(ins, i);
			for (j = 0; j <= NUM_FP_MOVS; j++)
				if (save_fp_movs[j] == n)
					return (1);
		}
	}

	return (0);
}

int
saveargs_has_args(uint8_t *ins, size_t size, uint_t argc, int start_index)
{
	int		i, j;
	uint32_t	n;

	argc = MIN((start_index + argc), INSTR_ARRAY_SIZE);

	if (!has_saved_fp(ins, size))
		return (SAVEARGS_NO_ARGS);

	/*
	 * Compare against Sun Studio implementation
	 */
	for (i = 4, j = 0; i <= size - 4; i++) {
		n = INSTR4(ins, i);

		if (n == save_instr[j]) {
			i += 3;
			if (++j >= argc)
				return (start_index ? SAVEARGS_STRUCT_ARGS :
				    SAVEARGS_TRAD_ARGS);
		}
	}

	/*
	 * Compare against GCC implementation
	 */
	for (i = 4, j = argc - 1; i <= size - 4; i++) {
		n = INSTR4(ins, i);

		if (n == save_instr[j]) {
			i += 3;
			if (--j < start_index)
				return (SAVEARGS_TRAD_ARGS);
		}
	}

	/*
	 * Compare against GCC push-based implementation
	 */
	for (i = 4, j = start_index; i <= size - 2; i += 1) {
		n = (i >= (8 - start_index)) ? INSTR2(ins, i) : INSTR1(ins, i);

		if (n == save_instr_push[j]) {
			if (i >= (8 - start_index))
				i += 1;
			if (++j >= argc)
				return (SAVEARGS_TRAD_ARGS);
		}
	}

	/* Look for a GCC-style returned structure */
	if (start_index != 0) {
		for (i = 4, j = argc - 2; i <= size - 4; i++) {
			n = INSTR4(ins, i);

			if (n == save_instr_sr[j]) {
				i += 3;
				if (--j >= (argc - 1))
					return (SAVEARGS_TRAD_ARGS);
			}
		}
	}

	return (SAVEARGS_NO_ARGS);
}
