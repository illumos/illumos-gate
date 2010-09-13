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
 * Copyright (c) 1993, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_METAD_LOCAL_H
#define	_METAD_LOCAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <meta.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* metad_svc.c */
extern	struct timeval	gc;

/* metad_svc_subr.c */
extern	md_setkey_t	*svc_get_setkey(set_t setno);
extern	void		svc_set_setkey(md_setkey_t *svc_sl);

/* metad_init.c */
extern	int		svc_init(struct svc_req *rqstp, int amode,
			    md_error_t *ep);
extern	void		sigalarmhandler(int sig);
extern	int		svc_fini(md_error_t *ep);
extern	int		check_set_lock(int amode, md_setkey_t *cl_sk,
			    md_error_t *ep);

#ifdef	__cplusplus
}
#endif

#endif	/* _METAD_LOCAL_H */
