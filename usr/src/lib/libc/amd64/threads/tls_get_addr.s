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

	.file	"tls_get_addr.s"

/*
 * To make thread-local storage accesses as fast as possible, we
 * hand-craft the __tls_get_addr() function below, from this C code:
 * void *
 * __tls_get_addr(TLS_index *tls_index)
 * {
 *	ulwp_t *self = curthread;
 *	tls_t *tlsent = self->ul_tlsent;
 *	ulong_t moduleid;
 *	caddr_t	base;
 *
 *	if ((moduleid = tls_index->ti_moduleid) < self->ul_ntlsent &&
 *	    (base = tlsent[moduleid].tls_data) != NULL)
 *		return (base + tls_index->ti_tlsoffset);
 *
 *	return (slow_tls_get_addr(tls_index));
 * }
 *
 * ___tls_get_addr() is identical to __tls_get_addr() except that it
 * assumes its argument is passed in %eax rather than on the stack.
 */

#include "SYS.h"
#include <../assym.h>

	ENTRY_NP(__tls_get_addr)
	ALTENTRY(___tls_get_addr)
	movq	%fs:UL_TLSENT, %rax
	movq	TI_MODULEID (%rdi), %rdx
	cmpq	%fs:UL_NTLSENT, %rdx
	jae	slow_tls_get_addr	/* tail call */
	/* movq	TLS_DATA (%rax,%rdx,SIZEOF_TLS_T), %rax */
	shlq	$4, %rdx	/* SIZEOF_TLS_T == 16 */
	movq	TLS_DATA (%rax,%rdx), %rax
	testq	%rax, %rax
	je	slow_tls_get_addr	/* tail call */
	addq	TI_TLSOFFSET (%rdi), %rax
	ret
	SET_SIZE(___tls_get_addr)
	SET_SIZE(__tls_get_addr)
