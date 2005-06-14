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

#ifndef _MACH_DESCRIP_H
#define	_MACH_DESCRIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common structure between kernel and mdesc driver
 * enabling the current machine description to be retrieved
 * or updated.
 */
struct machine_descrip_s {
	void		*va;
	uint64_t	pa;
	uint64_t	size;
	uint64_t	space;
	kstat_t		*ksp;
};

typedef struct machine_descrip_s machine_descrip_t;

extern machine_descrip_t machine_descrip;

#ifdef __cplusplus
}
#endif

#endif	/* _MACH_DESCRIP_H */
