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

#ifndef	_LDOM_H
#define	_LDOM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <libnvpair.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ldom_hdl ldom_hdl_t;

extern ldom_hdl_t *ldom_init(void *(*allocp)(size_t size),
			    void (*freep)(void *addr, size_t size));
extern void ldom_fini(ldom_hdl_t *lhp);

extern int ldom_fmri_status(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_retire(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_unretire(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_blacklist(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_unblacklist(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);

extern ssize_t ldom_get_core_md(ldom_hdl_t *lhp, uint64_t **buf);

extern int ldom_major_version(ldom_hdl_t *lhp);
extern int ldom_on_service(ldom_hdl_t *lhp);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDOM_H */
