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

#ifndef _SYS_DR_UTIL_H_
#define	_SYS_DR_UTIL_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/sbd_ioctl.h>
#include <sys/varargs.h>
#include <sys/kmem.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	GETSTRUCT(t, n) \
		((t *)kmem_zalloc((size_t)(n) * sizeof (t), KM_SLEEP))
#define	FREESTRUCT(p, t, n) \
		(kmem_free((caddr_t)(p), sizeof (t) * (size_t)(n)))

#define	DRERR_SET_C(epps, eppn)		\
	if (*(epps) == NULL)		\
		*(epps) = *(eppn);	\
	else				\
		sbd_err_clear(eppn)

#ifdef DEBUG
#define	MEMLIST_DUMP(ml) memlist_dump(ml)
#else
#define	MEMLIST_DUMP(ml)
#endif

extern sbd_error_t	*sbd_err_new(int e_code, char *fmt, va_list args);
extern void		sbd_err_log(sbd_error_t *ep, int ce);
extern void		sbd_err_clear(sbd_error_t **ep);
extern void		sbd_err_set_c(sbd_error_t **ep, int ce,
				int e_code, char *fmt, ...);
extern void		sbd_err_set(sbd_error_t **ep, int ce,
				int e_code, char *fmt, ...);

extern sbd_error_t	*drerr_new(int log, int e_code, char *fmt, ...);
extern sbd_error_t	*drerr_new_v(int e_code, char *fmt, va_list args);
extern void		drerr_set_c(int log, sbd_error_t **ep,
				int e_code, char *fmt, ...);

extern void		memlist_delete(struct memlist *mlist);
extern void		memlist_dump(struct memlist *mlist);
extern int		memlist_intersect(struct memlist *al,
				struct memlist *bl);
extern void		memlist_coalesce(struct memlist *mlist);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_DR_UTIL_H_ */
