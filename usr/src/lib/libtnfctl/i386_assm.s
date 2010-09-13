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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The following c routine has appropriate interface semantics
 * for the chaining combination template.  On the sparc architecture
 * the assembly routine is further tuned to make it tail recursive.
 *
 * void
 * prb_chain_entry(void *a, void *b, void *c)
 * {
 * 	prb_chain_down(a, b, c);
 * 	prb_chain_next(a, b, c);
 * }
 */

	.file	"i386_assm.s"
	.data
	.align	4
	.globl	prb_callinfo
prb_callinfo:
	.4byte	1		/* offset */
	.4byte	0		/* shift right */
	.4byte	0xffffffff	/* mask */

	.text
	.align	4
	.globl	prb_chain_entry
	.globl	prb_chain_down
	.local	chain_down
	.globl	prb_chain_next
	.local	chain_next
	.globl	prb_chain_end
prb_chain_entry:
#if defined(__amd64)
	/* XX64 -- fix me */
#else
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	movl	16(%ebp), %ebx
	pushl	%ebx
	movl	12(%ebp), %edi
	pushl	%edi
	movl	8(%ebp), %esi
	pushl	%esi
#endif
prb_chain_down:
chain_down:
#if defined(__amd64)
	/* XX64 -- fix me */
#else
	call	chain_down
	addl	$12, %esp
	pushl	%ebx
	pushl	%edi
	pushl	%esi
#endif
prb_chain_next:
chain_next:
#if defined(__amd64)
	/* XX64 -- fix me */
#else
	call	chain_next
	addl	$12, %esp
	popl	%ebx
	popl	%esi
	popl	%edi
	leave
#endif
	ret
prb_chain_end:
	nop
