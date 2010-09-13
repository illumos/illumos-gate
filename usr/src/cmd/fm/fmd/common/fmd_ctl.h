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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_CTL_H
#define	_FMD_CTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef void fmd_ctl_f(nvlist_t *);

typedef struct fmd_ctl_desc {
	const char *cde_class;		/* protocol event class */
	uint_t cde_vers;		/* protocol event version */
	fmd_ctl_f *cde_func;		/* callback function */
} fmd_ctl_desc_t;

typedef struct fmd_ctl {
	pthread_mutex_t ctl_lock;	/* lock for ctl_exec and ctl_cv */
	pthread_cond_t ctl_cv;		/* condition variable for ctl_exec */
	fmd_ctl_f *ctl_func;		/* type-specific callback function */
	nvlist_t *ctl_nvl;		/* name-value pair list from event */
	uint_t ctl_refs;		/* reference count for barrier */
} fmd_ctl_t;

extern fmd_ctl_t *fmd_ctl_init(nvlist_t *);
extern void fmd_ctl_fini(fmd_ctl_t *);
extern void fmd_ctl_hold(fmd_ctl_t *);
extern void fmd_ctl_rele(fmd_ctl_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_CTL_H */
