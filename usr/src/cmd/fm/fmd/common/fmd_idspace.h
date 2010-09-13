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

#ifndef	_FMD_IDSPACE_H
#define	_FMD_IDSPACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <pthread.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct fmd_idelem {
	struct fmd_idelem *ide_next;	/* next element in hash bucket chain */
	void *ide_data;			/* data associated with this element */
	id_t ide_id;			/* identifier associated w/ element */
} fmd_idelem_t;

typedef struct fmd_idspace {
	char ids_name[32];		/* string name of idspace for debug */
	pthread_mutex_t ids_lock;	/* lock protecting idspace contents */
	pthread_cond_t ids_cv;		/* condition variable for waiters */
	fmd_idelem_t **ids_hash;	/* hash bucket array of fmd_idelems */
	uint_t ids_hashlen;		/* size of hash bucket array */
	uint_t ids_refs;		/* reference count for idspace_hold */
	id_t ids_nextid;		/* next identifier guess for alloc */
	id_t ids_minid;			/* minimum identifier value */
	id_t ids_maxid;			/* maximum identifier value */
	id_t ids_count;			/* number of allocated ids */
} fmd_idspace_t;

extern fmd_idspace_t *fmd_idspace_create(const char *, id_t, id_t);
extern void fmd_idspace_destroy(fmd_idspace_t *);
extern void fmd_idspace_apply(fmd_idspace_t *,
    void (*)(fmd_idspace_t *, id_t, void *), void *);

extern void *fmd_idspace_getspecific(fmd_idspace_t *, id_t);
extern void fmd_idspace_setspecific(fmd_idspace_t *, id_t, void *);
extern int fmd_idspace_contains(fmd_idspace_t *, id_t);
extern int fmd_idspace_valid(fmd_idspace_t *, id_t);

extern id_t fmd_idspace_xalloc(fmd_idspace_t *, id_t, void *);
extern id_t fmd_idspace_alloc(fmd_idspace_t *, void *);
extern id_t fmd_idspace_alloc_min(fmd_idspace_t *, void *);
extern void *fmd_idspace_free(fmd_idspace_t *, id_t);

extern void *fmd_idspace_hold(fmd_idspace_t *, id_t);
extern void fmd_idspace_rele(fmd_idspace_t *, id_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_IDSPACE_H */
