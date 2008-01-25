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

#ifndef _HB_RCID_H
#define	_HB_RCID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Physical information of a root complex (pciexrc)
 */
typedef struct prc {
	int id;				/* physical id of a rc */
	uint64_t ba;			/* bus address */
} prc_t;

/*
 * A list of rc per platform
 */
typedef struct pprc {
	const char *platform;		/* platform on which the names apply */
	int nrcs;			/* number of pciexrc */
	struct prc *rcs;		/* array of pciexrc */
} pprc_t;

/*
 * A list of platforms
 */
typedef struct pprcs {
	int nplats;			/* Number of platforms */
	struct pprc *plats;		/* Array of platforms */
} pprcs_t;

extern int hb_find_rc_pid(char *platform, uint64_t ba);

#ifdef __cplusplus
}
#endif

#endif /* _HB_RCID_H */
