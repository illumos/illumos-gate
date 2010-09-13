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

#if defined(__lint)
#include <sys/types.h>
#include <kmdb/kmdb_asmutil.h>
#endif

#include <sys/asm_linkage.h>

#if defined(__lint)
/*ARGSUSED*/
uintptr_t
cas(uintptr_t *rs1, uintptr_t rs2, uintptr_t rd)
{
	return (0);
}
#else

	ENTRY(cas)
	casx	[%o0], %o1, %o2
	retl
	mov	%o2, %o0
	SET_SIZE(cas)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
flush_windows(void)
{
}
#else

	ENTRY(flush_windows)
	save
	flushw
	restore
	retl
	nop
	SET_SIZE(flush_windows)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
membar_producer(void)
{
}
#else

	/*
	 * US I has a problem with membars in the delay slot.  We don't care 
	 * about performance here, so for safety's sake, we'll assume that all 
	 * the world's an US I.
	 */
	ENTRY(membar_producer)
	membar	#StoreStore
	retl
	nop
	SET_SIZE(membar_producer)

#endif

#if defined(__lint)
/*ARGSUSED*/
uint64_t
rdasi(uint32_t asi, uintptr_t va)
{
	return (0);
}
#else

	ENTRY_NP(rdasi)
	rd	%asi, %o3
	wr	%o0, %asi
	ldxa	[%o1]%asi, %o0
	retl
	wr	%o3, %asi
	SET_SIZE(rdasi)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
wrasi(uint32_t asi, uintptr_t va, uint64_t val)
{
}
#else

	ENTRY_NP(wrasi)
	rd	%asi, %o3
	wr	%o0, %asi
	stxa	%o2, [%o1]%asi
	retl
	wr	%o3, %asi
	SET_SIZE(wrasi)

#endif
