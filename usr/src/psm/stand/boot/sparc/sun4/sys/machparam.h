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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#define	ADDRESS_C(c)    c ## ul
#else   /* _ASM */
#define	ADDRESS_C(c)    (c)
#endif	/* _ASM */

/*
 * Common subset of sun4 machine dependent parameters and limits
 */

/*
 * MMU_PAGES* describes the physical page size used by the mapping hardware.
 * PAGES* describes the logical page size used by the system.
 */
#define	MMU_PAGE_SIZES		6	/* max mmu-supported page sizes */
#define	DEFAULT_MMU_PAGE_SIZES	4	/* default supported page sizes */

/*
 * XXX make sure the MMU_PAGESHIFT definition here is
 * consistent with the one in param.h
 */
#define	MMU_PAGESHIFT		13
#define	MMU_PAGESIZE		(1<<MMU_PAGESHIFT)
#define	MMU_PAGEOFFSET		(MMU_PAGESIZE - 1)
#define	MMU_PAGEMASK		(~MMU_PAGEOFFSET)

#define	MMU_PAGESHIFT64K	16
#define	MMU_PAGESIZE64K		(1 << MMU_PAGESHIFT64K)
#define	MMU_PAGEOFFSET64K	(MMU_PAGESIZE64K - 1)
#define	MMU_PAGEMASK64K		(~MMU_PAGEOFFSET64K)

#define	MMU_PAGESHIFT512K	19
#define	MMU_PAGESIZE512K	(1 << MMU_PAGESHIFT512K)
#define	MMU_PAGEOFFSET512K	(MMU_PAGESIZE512K - 1)
#define	MMU_PAGEMASK512K	(~MMU_PAGEOFFSET512K)

#define	MMU_PAGESHIFT4M		22
#define	MMU_PAGESIZE4M		(1 << MMU_PAGESHIFT4M)
#define	MMU_PAGEOFFSET4M	(MMU_PAGESIZE4M - 1)
#define	MMU_PAGEMASK4M		(~MMU_PAGEOFFSET4M)

#define	MMU_PAGESHIFT32M	25
#define	MMU_PAGESIZE32M		(1 << MMU_PAGESHIFT32M)
#define	MMU_PAGEOFFSET32M	(MMU_PAGESIZE32M - 1)
#define	MMU_PAGEMASK32M		(~MMU_PAGEOFFSET32M)

#define	MMU_PAGESHIFT256M	28
#define	MMU_PAGESIZE256M	(1 << MMU_PAGESHIFT256M)
#define	MMU_PAGEOFFSET256M	(MMU_PAGESIZE256M - 1)
#define	MMU_PAGEMASK256M	(~MMU_PAGEOFFSET256M)

#define	PAGESHIFT	13
#define	PAGESIZE	(1<<PAGESHIFT)
#define	PAGEOFFSET	(PAGESIZE - 1)
#define	PAGEMASK	(~PAGEOFFSET)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHPARAM_H */
