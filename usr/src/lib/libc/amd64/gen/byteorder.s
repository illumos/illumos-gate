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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"byteorder.s"

#include <sys/asm_linkage.h>

	/*
	 * NOTE: htonll/ntohll, htonl/ntohl, and htons/ntohs are identical
	 * routines. As such, they could be implemented as a single routine,
	 * using multiple ALTENTRY/SET_SIZE definitions. We don't do this so
	 * that they will have unique addresses, allowing DTrace and
	 * other debuggers to tell them apart.
	 */

/*
 *	unsigned long long htonll( hll )
 *	unsigned long long ntohll( hll )
 *	unsigned long long hll;
 *	reverses the byte order of 'uint64_t hll' on little endian machines
 */
	ENTRY(htonll)
	movq	%rdi, %rax	/* %rax = hll */
	bswapq	%rax		/* reverses the byte order of %rax */
	ret			/* return (%rax) */
	SET_SIZE(htonll)

	ENTRY(ntohll)
	movq	%rdi, %rax	/* %rax = hll */
	bswapq	%rax		/* reverses the byte order of %rax */
	ret			/* return (%rax) */
	SET_SIZE(ntohll)


/*
 *	unsigned long htonl( hl )
 *	unsigned long ntohl( hl )
 *	unsigned long hl;
 *	reverses the byte order of 'uint32_t hl' on little endian machines
 */
	ENTRY(htonl)
	movl	%edi, %eax	/* %eax = hl */
	bswap	%eax		/* reverses the byte order of %eax */
	ret			/* return (%eax) */
	SET_SIZE(htonl)

	ENTRY(ntohl)
	movl	%edi, %eax	/* %eax = hl */
	bswap	%eax		/* reverses the byte order of %eax */
	ret			/* return (%eax) */
	SET_SIZE(ntohl)

/*
 *	unsigned short htons( hs )
 *	unsigned short hs;
 *	reverses the byte order of 'uint16_t hs' on little endian machines.
 */
	ENTRY(htons)
	movl	%edi, %eax	/* %eax = hs */
	bswap	%eax		/* reverses the byte order of %eax */
	shrl	$16, %eax	/* moves high 16-bit to low 16-bit */
	ret			/* return (%eax) */
	SET_SIZE(htons)

	ENTRY(ntohs)
	movl	%edi, %eax	/* %eax = hs */
	bswap	%eax		/* reverses the byte order of %eax */
	shrl	$16, %eax	/* moves high 16-bit to low 16-bit */
	ret			/* return (%eax) */
	SET_SIZE(ntohs)
