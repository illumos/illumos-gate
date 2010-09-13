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
#ifndef _MEM_CACHE_IOCTL_H
#define	_MEM_CACHE_IOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PN_ECSTATE_MASK		0x7	/* three bit field */
#define	PN_ECSTATE_INV		0x0	/* invalid */
#define	PN_ECSTATE_SHR		0x1	/* shared */
#define	PN_ECSTATE_EXL		0x2	/* exclusive */
#define	PN_ECSTATE_OWN		0x3	/* owner */
#define	PN_ECSTATE_MOD		0x4	/* modified */
#define	PN_ECSTATE_NA		0x5	/* Not Available */
#define	PN_ECSTATE_OWN_SHR	0x6	/* owner/shared */
#define	PN_ECSTATE_RES		0x7	/* reserved */

typedef	void retire_func_t(uint64_t, uint64_t);
typedef struct cache_info32 {
		int		cpu_id;
		cache_id_t	cache;
		uint32_t	index;
		uint32_t	way;
		uint16_t		bit;
		caddr32_t	datap;
} cache_info32_t;

#ifdef	__cplusplus
}
#endif

#endif /* _MEM_CACHE_IOCTL_H */
