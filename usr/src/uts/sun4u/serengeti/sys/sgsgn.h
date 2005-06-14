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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SGSGN_H
#define	_SGSGN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/inttypes.h>
#include <sys/sysmacros.h>

/*
 * Type definitions for layout in I/O SRAM of CPU signatures.
 *
 * The cpusig array bound is a white lie.  The SC will allocate
 * enough space for this array so that it can be indexed by any
 * valid cpu id.  Generally, this means that there will be about
 * NCPU entries in the array.  However, NCPU is a kernel defined
 * value that may be larger than the actual maximum; the SC
 * allocates based strictly on the hardware's capabilities, not on
 * the kernel's definition of NCPU.
 */

typedef struct {
	uint32_t	magic;
	uint32_t	version;
	uint32_t	domainsig;
	uint32_t	pad;
	uint32_t	cpusig[1];
} sg_sgnblk_t;


/*
 * Access to the signature block in I/O SRAM is done by calls to
 * iosram_write(), which believes in offsets, not pointers.
 * Below are the relevant offsets.
 */
#define	SG_SGNBLK_MAGIC_OFFSET				\
	    (offsetof(sg_sgnblk_t, magic))
#define	SG_SGNBLK_VERSION_OFFSET			\
	    (offsetof(sg_sgnblk_t, version))
#define	SG_SGNBLK_DOMAINSIG_OFFSET			\
	    (offsetof(sg_sgnblk_t, domainsig))
#define	SG_SGNBLK_CPUSIG_OFFSET(cpuid)			\
	    (offsetof(sg_sgnblk_t, cpusig) + (cpuid)*sizeof (uint32_t))


#ifdef __cplusplus
}
#endif

#endif	/* _SGSGN_H */
