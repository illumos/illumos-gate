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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FM_CPU_GENAMD_H
#define	_SYS_FM_CPU_GENAMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Ereport class subcategory - same as in GMCA.h */
#define	FM_EREPORT_CPU_GENAMD	"generic-x86"

/* Ereport leaf classes */
#define	FM_EREPORT_CPU_GENAMD_MEM_CE		"mem_ce"
#define	FM_EREPORT_CPU_GENAMD_MEM_UE		"mem_ue"
#define	FM_EREPORT_CPU_GENAMD_CKMEM_CE		"mem_ce"
#define	FM_EREPORT_CPU_GENAMD_CKMEM_UE		"mem_ue"
#define	FM_EREPORT_CPU_GENADM_GARTTBLWLK	"gart_tbl_walk"

#define	_FM_EREPORT_FLAG(n) (1ULL << (n))

#define	FM_EREPORT_GENAMD_PAYLOAD_NAME_SYND		"syndrome"
#define	FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYND		_FM_EREPORT_FLAG(1)

#define	FM_EREPORT_GENAMD_PAYLOAD_NAME_CKSYND		"syndrome"
#define	FM_EREPORT_GENAMD_PAYLOAD_FLAG_CKSYND		_FM_EREPORT_FLAG(2)

#define	FM_EREPORT_GENAMD_PAYLOAD_NAME_SYNDTYPE		"syndrome-type"
#define	FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYNDTYPE		_FM_EREPORT_FLAG(3)

#define	FM_EREPORT_GENAMD_PAYLOAD_NAME_RESOURCE		"resource"
#define	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCE		_FM_EREPORT_FLAG(4)

#define	FM_EREPORT_GENAMD_PAYLOAD_NAME_RESOURCECNT	"resource_counts"
#define	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCECNT	_FM_EREPORT_FLAG(5)

#define	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_MEM_CE \
	(FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYND | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYNDTYPE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCECNT)

#define	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_MEM_UE \
	(FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYND | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYNDTYPE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCECNT)

#define	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_CKMEM_CE \
	(FM_EREPORT_GENAMD_PAYLOAD_FLAG_CKSYND | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYNDTYPE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCECNT)

#define	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_CKMEM_UE \
	(FM_EREPORT_GENAMD_PAYLOAD_FLAG_CKSYND | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYNDTYPE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCE | \
	FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCECNT)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FM_CPU_GENAMD_H */
