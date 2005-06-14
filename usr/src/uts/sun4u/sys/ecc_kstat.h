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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_ECC_KSTAT_H
#define	_SYS_ECC_KSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	KSTAT_CE_UNUM_NAMLEN 60

/*
 * Using these stats are not reset to zero during system operation.
 * To determine the number of errors between times "A" and "B" a program
 * would have to snapshot the kstats and subtract the counts at time "A"
 * from the counts at time "B".
 */

/*
 * Legacy raw kstat: unix:0:ecc-mm-info
 */
struct kstat_ecc_mm_info_1 {
	struct kstat_ecc_mm {
		char name[KSTAT_CE_UNUM_NAMLEN];
		uint64_t intermittent_total;
		uint64_t persistent_total;
		uint64_t sticky_total;
	} ecc_mm[1];    /* variable-length array */
};

/*
 * Named kstat: mm:(instance):ecc-info
 */
struct kstat_ecc_mm_info_2 {
	struct kstat_named name;
	struct kstat_named intermittent_total;
	struct kstat_named persistent_total;
	struct kstat_named sticky_total;
};

#define	kstat_ecc_mm_info	kstat_ecc_mm_info_2
#define	KSTAT_CE_INFO_VER_1	1
#define	KSTAT_CE_INFO_VER_2	2
#define	KSTAT_CE_INFO_VER	KSTAT_CE_INFO_VER_2

/*
 * Clients of this kstat will have to check the version and maintain
 * compatibility code to handle the previous versions.
 *
 * named kstat: unix:0:ecc-info:version
 *	- the version of the kstats implemented by the running kernel
 *
 * named kstat: unix:0:ecc-info:count
 *	- the current count of valid mm:ecc-info kstats
 *
 * named kstat: unix:0:ecc-info:maxcount
 *	- the maximum number of mm:ecc-info kstats
 */
struct ecc_error_info {
	struct kstat_named version;
	struct kstat_named maxcount;
	struct kstat_named count;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ECC_KSTAT_H */
