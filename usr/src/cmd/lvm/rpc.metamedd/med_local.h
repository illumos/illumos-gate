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

#ifndef	_MED_LOCAL_H
#define	_MED_LOCAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#include <sys/time.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>

#include <metamed.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_REENTRANT
/*
 * millisecond time
 */
typedef	u_longlong_t	med_msec_t;
#endif	/* _REENTRANT */

/*
 * extern functions
 */
/* med_error.c */
extern	int		med_error(med_err_t *medep, int errnum, char *name);
/*PRINTFLIKE2*/
extern	void		medde_perror(med_err_t *medep, const char *fmt, ...);
/*PRINTFLIKE1*/
extern	void		med_perror(const char *fmt, ...);
/*PRINTFLIKE1*/
extern	void		med_eprintf(const char *fmt, ...);

/* med_init.c */
extern	void		med_exit(int eval);
extern	int		med_init(struct svc_req *rqstp, int amode,
			    med_err_t *medep);
extern	char		*mynode(void);

/* med_mem.c */
extern	void		*Malloc(size_t s);
extern	void		*Zalloc(size_t s);
extern	void		*Realloc(void *p, size_t s);
extern	void		*Calloc(size_t n, size_t s);
extern	char		*Strdup(char *p);
extern	void		Free(void *p);

/* meta_metad.c */
#ifdef	_REENTRANT
/* med_synch.c */
extern	void		med_cv_init(cond_t *cvp);
extern	void		med_cv_destroy(cond_t *cvp);
extern	void		med_cv_wait(cond_t *cvp, mutex_t *mp);
extern	void		med_cv_timedwait(cond_t *cvp, mutex_t *mp,
			    med_msec_t to);
extern	void		med_cv_broadcast(cond_t *cvp);
extern	void		med_mx_init(mutex_t *mp);
extern	void		med_mx_destroy(mutex_t *mp);
extern	void		med_mx_lock(mutex_t *mp);
extern	void		med_mx_unlock(mutex_t *mp);
extern	void		med_rw_rdlock(rwlock_t *rwlp);
extern	void		med_rw_wrlock(rwlock_t *rwlp);
extern	void		med_rw_unlock(rwlock_t *rwlp);
#endif	/* _REENTRANT */

/* med_db.c */
extern int		med_db_init(med_err_t *medep);
extern med_rec_t	*med_db_get_rec(med_med_t *medp, med_err_t *medep);
extern med_data_t	*med_db_get_data(med_med_t *medp, med_err_t *medep);
extern int		med_db_put_rec(med_med_t *medp, med_rec_t *nmedrp,
			    med_err_t *medep);
extern int		med_db_put_data(med_med_t *medp, med_data_t *meddp,
			    med_err_t *medep);
extern int		med_db_finit(med_err_t *medep);

#ifdef	__cplusplus
}
#endif

#endif	/* _MED_LOCAL_H */
