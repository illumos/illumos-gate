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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AMD64_BOOTOPS64_H
#define	_AMD64_BOOTOPS64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/inttypes.h>

#include <amd64/types.h>

struct bsys_mem64 {
	caddr64_t	physinstalled;	/* struct memlist64 pointer */
	caddr64_t	physavail;	/* struct memlist64 pointer */
	caddr64_t	pcimem;		/* struct memlist64 pointer */
};

/*
 * We need bootops-extensions >= 1 to make S10 work.
 * bsys_version is BO_VERSION == 5.
 */
struct bootops64 {
	uint32_t	bsys_version;
	uint32_t	__bsys_pad0;
	caddr64_t	boot_mem;	/* struct bsys_mem64 pointer */
	fnaddr64_t	bsys_alloc;
	fnaddr64_t	bsys_free;
	fnaddr64_t	bsys_getproplen;
	fnaddr64_t	bsys_getprop;
	fnaddr64_t	bsys_nextprop;
	fnaddr64_t	bsys_printf;
	fnaddr64_t	bsys_doint;
	fnaddr64_t	bsys_ealloc;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_BOOTOPS64_H */
