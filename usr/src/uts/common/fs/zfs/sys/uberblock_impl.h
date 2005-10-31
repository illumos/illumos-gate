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

#ifndef _SYS_UBERBLOCK_IMPL_H
#define	_SYS_UBERBLOCK_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/uberblock.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The uberblock version is incremented whenever an incompatible on-disk
 * format change is made to the SPA, DMU, or ZAP.
 *
 * Note: the first two fields should never be moved.  When a storage pool
 * is opened, the uberblock must be read off the disk before the version
 * can be checked.  If the ub_version field is moved, we may not detect
 * version mismatch.  If the ub_magic field is moved, applications that
 * expect the magic number in the first word won't work.
 */

#define	UBERBLOCK_SHIFT		(10)
#define	UBERBLOCK_SIZE		(1ULL << UBERBLOCK_SHIFT)

#define	UBERBLOCK_MAGIC		0x00bab10c		/* oo-ba-bloc!	*/

#define	UBERBLOCK_VERSION	1ULL

struct uberblock {
	uint64_t	ub_magic;	/* UBERBLOCK_MAGIC		*/
	uint64_t	ub_version;	/* UBERBLOCK_VERSION		*/
	uint64_t	ub_txg;		/* txg of last sync		*/
	uint64_t	ub_guid_sum;	/* sum of all vdev guids	*/
	uint64_t	ub_timestamp;	/* UTC time of last sync	*/
	blkptr_t	ub_rootbp;	/* MOS objset_phys_t		*/
};

typedef struct uberblock_phys {
	uberblock_t	ubp_uberblock;
	char		ubp_pad[UBERBLOCK_SIZE - sizeof (uberblock_t) -
	    sizeof (zio_block_tail_t)];
	zio_block_tail_t ubp_zbt;
} uberblock_phys_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_UBERBLOCK_IMPL_H */
