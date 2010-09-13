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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_PHYSMEM_H
#define	_PHYSMEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* ioctl values */
#define	PHYSMEM_SETUP 1
#define	PHYSMEM_MAP 2
#define	PHYSMEM_DESTROY 3

/* flags values */
#define	PHYSMEM_CAGE	(1 << 0)
#define	PHYSMEM_RETIRED	(1 << 1)

struct physmem_setup_param {
	uint64_t req_paddr;	/* requested physical address */
	uint64_t len;		/* length of memory to be allocated */
	uint64_t user_va;	/* VA to associate with req_paddr */
	uint64_t cookie;	/* cookie returned for destroy function */
};

struct physmem_map_param {
	uint64_t req_paddr;	/* requested physical address */
	uint64_t ret_va;	/* VA which mapped req_paddr */
	uint32_t flags;		/* flags for cage or retired pages */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _PHYSMEM_H */
