/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

#if defined(lint)

void *
getfp(void)
{
	return (NULL);
}

void
flush_windows(void)
{

}

#ifndef UMEM_STANDALONE
void
_breakpoint(void)
{
	return;
}
#endif

#else	/* lint */

	ENTRY(getfp)
	retl
	mov	%fp, %o0
	SET_SIZE(getfp)

#ifdef UMEM_STANDALONE
#ifdef __sparcv9

	/*
	 * The caller doesn't need the top window to be flushed, so this
	 * is sufficient.
	 */
	ENTRY(flush_windows)
	retl
	flushw
	SET_SIZE(flush_windows)

#else	/* !__sparcv9 */
#error	"This file does not provide a pre-v9 standalone flush_windows"
#endif	/* __sparcv9 */

#else	/* !UMEM_STANDALONE */

	ENTRY(flush_windows)
	retl
	ta	0x3
	SET_SIZE(flush_windows)

#endif	/* UMEM_STANDALONE */

#ifndef UMEM_STANDALONE
	ENTRY(_breakpoint)
	retl
	ta	0x1
	SET_SIZE(_breakpoint)
#endif

#endif	/* lint */
