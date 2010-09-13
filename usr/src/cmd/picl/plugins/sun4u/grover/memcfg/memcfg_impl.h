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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MEMCFG_IMPL_H
#define	_MEMCFG_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Log message texts
 */
#define	EM_INIT_FAILED		gettext("SUNW_piclmemcfg init failed!\n")
#define	EM_PHYSIC_MEM_TREE_FAILED	\
	gettext("SUNW_piclmemcfg physic memory tree failed!\n")
#define	EM_LOGIC_MEM_TREE_FAILED		\
	gettext("SUNW_piclmemcfg logic memory tree failed!\n")

/*
 * Constants for some PICL properties
 */
#define	INTERLEAVEFACTOR	1	/* Only one interleave way */

/*
 * OBP property names
 */
#define	OBP_PROP_SIZE_CELLS		"#size-cells"

#define	SUPPORTED_NUM_CELL_SIZE		2	/* #size-cells */

#define	TOTAL_MEM_SLOTS		4	/* Total memory module slots */

typedef struct memmod_info {
	picl_nodehdl_t	memmodh;	/* memory-module node handle */
	uint64_t	base;		/* base address at the slot */
	uint64_t	size;		/* in bytes */
} mmodinfo_t;

/*
 * The expected values of the IEEE 1275 reg property of a memory node
 * in PLATFORM
 */
typedef struct regspec {
	uint64_t	physaddr;
	uint64_t	size;
} regspec_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _MEMCFG_IMPL_H */
