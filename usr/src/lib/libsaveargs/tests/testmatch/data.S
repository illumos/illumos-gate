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

#define	FUNC(x) \
	.text; \
	.align	16; \
	.globl	x; \
	.type	x, @function; \
x:

#define	SET_SIZE(x, x_size) \
	.size	x, [.-x]; \
        .globl x_size; \
        .type  x_size, @object; \
x_size:

/*
 * Extracted versions of the functional tests
 *
 * Named of the form <compiler>-<prologue style>-<nature of test>
 * basic			-- A regular function
 * align			-- odd number of arguments needing save-area
 * 				   alignment
 * big-struct-ret		-- returns a > 16byte structure by value
 * big-struct-ret-and-spill	-- returns a > 16byte structure by value and
 * 				   spills args to the stack
 * small-struct-ret		-- returns a < 16byte structure by value
 * small-struct-ret-and-spill	-- returns a < 16byte structure by value and
 * 				   spills args to the stack
 * stack-spill			-- spills arguments to the stack
 */
FUNC(gcc_mov_align)
pushq	%rbp
movq	%rsp, %rbp
movq	%rbx, -0x38(%rbp)
movq	%r8, -0x28(%rbp)
movq	%rcx, -0x20(%rbp)
movq	%rdx, -0x18(%rbp)
movq	%rsi, -0x10(%rbp)
movq	%rdi, -0x8(%rbp)
subq	$0x70, %rsp
SET_SIZE(gcc_mov_align, gcc_mov_align_end)

FUNC(gcc_mov_basic)
pushq	%rbp
movq	%rsp, %rbp
movq	%rbx,-0x28(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
subq    $0x50,%rsp
SET_SIZE(gcc_mov_basic, gcc_mov_basic_end)

FUNC(gcc_mov_noorder)
pushq	%rbp
movq	%rsp, %rbp
movq    %rcx,-0x20(%rbp)
movq	%rbx,-0x28(%rbp)
movq    %rdi,-0x8(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
subq    $0x50,%rsp
SET_SIZE(gcc_mov_noorder, gcc_mov_noorder_end)
        
FUNC(gcc_mov_big_struct_ret)
pushq   %rbp
movq    %rsp,%rbp
movq    %rbx,-0x28(%rbp)
movq    %r8,-0x20(%rbp)
movq    %rcx,-0x18(%rbp)
movq    %rdx,-0x10(%rbp)
movq    %rsi,-0x8(%rbp)
subq    $0x50,%rsp
SET_SIZE(gcc_mov_big_struct_ret, gcc_mov_big_struct_ret_end)

FUNC(gcc_mov_struct_noorder)
pushq   %rbp
movq    %rsp,%rbp
movq    %rcx,-0x18(%rbp)
movq    %r8,-0x20(%rbp)
movq    %rsi,-0x8(%rbp)
movq    %rdx,-0x10(%rbp)
movq    %rbx,-0x28(%rbp)
subq    $0x50,%rsp
SET_SIZE(gcc_mov_struct_noorder, gcc_mov_struct_noorder_end)

FUNC(gcc_mov_big_struct_ret_and_spill)
pushq   %rbp
movq    %rsp,%rbp
movq    %rbx,-0x38(%rbp)
movq    %r9,-0x28(%rbp)
movq    %r8,-0x20(%rbp)
movq    %rcx,-0x18(%rbp)
movq    %rdx,-0x10(%rbp)
movq    %rsi,-0x8(%rbp)
subq    $0x90,%rsp
SET_SIZE(gcc_mov_big_struct_ret_and_spill, gcc_mov_big_struct_ret_and_spill_end)

FUNC(gcc_mov_small_struct_ret)
pushq   %rbp
movq    %rsp,%rbp
movq    %rbx,-0x28(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
subq    $0x50,%rsp
SET_SIZE(gcc_mov_small_struct_ret, gcc_mov_small_struct_ret_end)

FUNC(gcc_mov_small_struct_ret_and_spill)
pushq   %rbp
movq    %rsp,%rbp
movq    %rbx,-0x38(%rbp)
movq    %r9,-0x30(%rbp)
movq    %r8,-0x28(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
subq    $0x90,%rsp
SET_SIZE(gcc_mov_small_struct_ret_and_spill, gcc_mov_small_struct_ret_and_spill_end)

FUNC(gcc_mov_stack_spill)
pushq   %rbp
movq    %rsp,%rbp
movq    %rbx,-0x38(%rbp)
movq    %r9,-0x30(%rbp)
movq    %r8,-0x28(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
subq    $0x90,%rsp
SET_SIZE(gcc_mov_stack_spill, gcc_mov_stack_spill_end)

FUNC(gcc_push_align)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rdi
pushq   %rsi
pushq   %rdx
pushq   %rcx
pushq   %r8
subq    $0x8,%rsp
subq    $0x30,%rsp
SET_SIZE(gcc_push_align, gcc_push_align_end)

FUNC(gcc_push_basic)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rdi
pushq   %rsi
pushq   %rdx
pushq   %rcx
subq    $0x20,%rsp
SET_SIZE(gcc_push_basic, gcc_push_basic_end)

FUNC(gcc_push_noorder)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rsi
pushq   %rdi
pushq   %rcx
pushq   %rdx
subq    $0x20,%rsp
SET_SIZE(gcc_push_noorder, gcc_push_noorder_end)

FUNC(gcc_push_big_struct_ret)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rsi
pushq   %rdx
pushq   %rcx
pushq   %r8
subq    $0x30,%rsp
SET_SIZE(gcc_push_big_struct_ret, gcc_push_big_struct_ret_end)

FUNC(gcc_push_struct_noorder)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rdx
pushq   %rsi
pushq   %r8
pushq   %rcx
subq    $0x30,%rsp
SET_SIZE(gcc_push_struct_noorder, gcc_push_struct_noorder_end)
        
FUNC(gcc_push_big_struct_ret_and_spill)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rsi
pushq   %rdx
pushq   %rcx
pushq   %r8
pushq   %r9
subq    $0x8,%rsp
subq    $0x50,%rsp
SET_SIZE(gcc_push_big_struct_ret_and_spill, gcc_push_big_struct_ret_and_spill_end)

FUNC(gcc_push_small_struct_ret)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rdi
pushq   %rsi
pushq   %rdx
pushq   %rcx
subq    $0x20,%rsp
SET_SIZE(gcc_push_small_struct_ret, gcc_push_small_struct_ret_end)

FUNC(gcc_push_small_struct_ret_and_spill)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rdi
pushq   %rsi
pushq   %rdx
pushq   %rcx
pushq   %r8
pushq   %r9
subq    $0x50,%rsp
SET_SIZE(gcc_push_small_struct_ret_and_spill, gcc_push_small_struct_ret_and_spill_end)

FUNC(gcc_push_stack_spill)
pushq   %rbp
movq    %rsp,%rbp
pushq   %rdi
pushq   %rsi
pushq   %rdx
pushq   %rcx
pushq   %r8
pushq   %r9
subq    $0x50,%rsp
SET_SIZE(gcc_push_stack_spill, gcc_push_stack_spill_end)

FUNC(ss_mov_align)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x30,%rsp
movq    %rdi,-0x8(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %r8,-0x28(%rbp)
SET_SIZE(ss_mov_align, ss_mov_align_end)

FUNC(ss_mov_basic)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x20,%rsp
movq    %rdi,-0x8(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rcx,-0x20(%rbp)
SET_SIZE(ss_mov_basic, ss_mov_basic_end)

FUNC(ss_mov_big_struct_ret)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x30,%rsp
movq    %rdi,-0x8(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %r8,-0x28(%rbp)
SET_SIZE(ss_mov_big_struct_ret, ss_mov_big_struct_ret_end)

FUNC(ss_mov_big_struct_ret_and_spill)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x50,%rsp
movq    %rdi,-0x8(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %r8,-0x28(%rbp)
movq    %r9,-0x30(%rbp)
SET_SIZE(ss_mov_big_struct_ret_and_spill, ss_mov_big_struct_ret_and_spill_end)

FUNC(ss_mov_small_struct_ret)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x20,%rsp
movq    %rdi,-0x8(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rcx,-0x20(%rbp)
SET_SIZE(ss_mov_small_struct_ret, ss_mov_small_struct_ret_end)

FUNC(ss_mov_small_struct_ret_and_spill)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x50,%rsp
movq    %rdi,-0x8(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %r8,-0x28(%rbp)
movq    %r9,-0x30(%rbp)
SET_SIZE(ss_mov_small_struct_ret_and_spill, ss_mov_small_struct_ret_and_spill_end)

FUNC(ss_mov_stack_spill)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x50,%rsp
movq    %rdi,-0x8(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %r8,-0x28(%rbp)
movq    %r9,-0x30(%rbp)
SET_SIZE(ss_mov_stack_spill, ss_mov_stack_spill_end)

/* DTrace instrumentation */
FUNC(dtrace_instrumented)
int	$0x3
movq	%rsp, %rbp
movq	%rbx,-0x28(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
subq    $0x50,%rsp
SET_SIZE(dtrace_instrumented, dtrace_instrumented_end)

/*
 * System functions with special characteristics, be they non-initial FP save,
 * gaps between FP save and argument saving, or gaps between saved arguments.
 */
FUNC(kmem_alloc)
leaq    -0x1(%rdi),%rax
pushq   %rbp
movq    %rax,%rdx
movq    %rsp,%rbp
subq    $0x30,%rsp
shrq    $0x3,%rdx
movq    %r12,-0x28(%rbp)
movq    %rbx,-0x30(%rbp)
cmpq    $0x1ff,%rdx
movq    %r13,-0x20(%rbp)
movq    %r14,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
movq    %rdi,%r12
SET_SIZE(kmem_alloc, kmem_alloc_end)

FUNC(uts_kill)
pushq   %rbp
movq    %rsp,%rbp
subq    $0x50,%rsp
movq    %rbx,-0x28(%rbp)
leaq    -0x50(%rbp),%rbx
movq    %r12,-0x20(%rbp)
movq    %r13,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movl    %edi,%r12d
movq    %rdi,-0x8(%rbp)
SET_SIZE(uts_kill, uts_kill_end)

FUNC(av1394_ic_bitreverse)
movq    %rdi,%rdx
movq    $0x5555555555555555,%rax
movq    $0x3333333333333333,%rcx
shrq    $0x1,%rdx
pushq   %rbp
andq    %rax,%rdx
andq    %rdi,%rax
addq    %rax,%rax
movq    %rsp,%rbp
subq    $0x10,%rsp
orq     %rdx,%rax
movq    %rdi,-0x8(%rbp)
SET_SIZE(av1394_ic_bitreverse, av1394_ic_bitreverse_end)

/* Problematic functions which should not match */

FUNC(no_fp) /* No frame pointer */
movq	%rdi, %rsi
movq	%rsi, %rdi
movq	%rbx,-0x28(%rbp)
movq    %rcx,-0x20(%rbp)
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
subq    $0x50,%rsp
SET_SIZE(no_fp, no_fp_end)

/* Small structure return, but with an SSE type (thus forcing it to the stack) */
FUNC(small_struct_ret_w_float)
pushq   %rbp
movq    %rsp,%rbp
movq    %rdi,-0x8(%rbp)
subq    $0x30,%rsp
SET_SIZE(small_struct_ret_w_float, small_struct_ret_w_float_end)

/* Big structure return, but with an SSE type */
FUNC(big_struct_ret_w_float)
pushq  %rbp
movq   %rsp,%rbp
movq   %rsi,-0x8(%rbp)
subq   $0x50,%rsp
movq   %rsi,-0x48(%rbp)
movq   -0x48(%rbp),%rax
movq   %rax,%rsi
movl   $0x400f60,%edi
movl   $0x0,%eax
movl   $0x1770,%edi
movl   $0x0,%eax
leave
ret
SET_SIZE(big_struct_ret_w_float, big_struct_ret_w_float_end)

FUNC(big_struct_arg_by_value)
pushq   %rbp
movq    %rsp,%rbp
movq    %rdi,-0x8(%rbp)
subq    $0x40,%rsp
SET_SIZE(big_struct_arg_by_value, big_struct_arg_by_value_end)

FUNC(small_struct_arg_by_value)
pushq   %rbp
movq    %rsp,%rbp
movq    %rdx,-0x18(%rbp)
movq    %rsi,-0x10(%rbp)
movq    %rdi,-0x8(%rbp)
subq    $0x50,%rsp
SET_SIZE(small_struct_arg_by_value, small_struct_arg_by_value_end)

FUNC(interleaved_argument_saves)
pushq	%rbp
movq	%rdi,%rax
shlq	$0x21,%rax
movq	%rsp,%rbp
shrq	$0x29,%rax
subq	$0x30,%rsp
movq	%rdi,-0x8(%rbp)
movq	%rbx,-0x28(%rbp)
movzbl	%dil,%edi
movq	%rcx,-0x20(%rbp)
movq	%rdx,-0x18(%rbp)
movq	%rsi,-0x10(%rbp)
movq	0x0(,%rax,8),%rax
SET_SIZE(interleaved_argument_saves, interleaved_argument_saves_end)

FUNC(jmp_table)
pushq	%rbp
movq	%rsp,%rbp
.word	0x9afe
.word	0xffff
.word	0xffff
.word	0xa8ff
.word	0xffff
.word	0xffff
.word	0x7cff
.word	0xffff
.word	0xffff
SET_SIZE(jmp_table, jmp_table_end)        
