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

#ifndef	_FMD_SCHEME_H
#define	_FMD_SCHEME_H

#include <libnvpair.h>
#include <pthread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Scheme operations.  These function pointers are filled in when the scheme
 * is loaded.  New operations must be added here as well as to the default
 * operations declaration and initialization table in fmd_scheme.c.
 */
typedef struct fmd_scheme_ops {
	int (*sop_init)(void);
	void (*sop_fini)(void);
	ssize_t (*sop_nvl2str)(nvlist_t *, char *, size_t);
	int (*sop_expand)(nvlist_t *);
	int (*sop_present)(nvlist_t *);
	int (*sop_replaced)(nvlist_t *);
	int (*sop_service_state)(nvlist_t *);
	int (*sop_unusable)(nvlist_t *);
	int (*sop_contains)(nvlist_t *, nvlist_t *);
	nvlist_t *(*sop_translate)(nvlist_t *, nvlist_t *);
} fmd_scheme_ops_t;

typedef struct fmd_scheme_opd {
	const char *opd_name;		/* symbol name of scheme function */
	size_t opd_off;			/* offset within fmd_scheme_ops_t */
} fmd_scheme_opd_t;

typedef struct fmd_scheme {
	struct fmd_scheme *sch_next;	/* next scheme on hash bucket chain */
	char *sch_name;			/* name of this scheme (fmri prefix) */
	void *sch_dlp;			/* libdl shared library handle */
	pthread_mutex_t sch_lock;	/* lock protecting cv, refs, loaded */
	pthread_cond_t sch_cv;		/* condition variable for sch_loaded */
	uint_t sch_refs;		/* scheme reference count */
	uint_t sch_loaded;		/* scheme has been loaded */
	pthread_mutex_t sch_opslock;	/* lock protecting non-init/fini ops */
	fmd_scheme_ops_t sch_ops;	/* scheme function pointers */
} fmd_scheme_t;

typedef struct fmd_scheme_hash {
	pthread_rwlock_t sch_rwlock;	/* rwlock protecting scheme hash */
	fmd_scheme_t **sch_hash;	/* hash bucket array of schemes */
	uint_t sch_hashlen;		/* length of hash bucket array */
	char *sch_dirpath;		/* directory path for schemes */
} fmd_scheme_hash_t;

extern fmd_scheme_hash_t *fmd_scheme_hash_create(const char *, const char *);
extern void fmd_scheme_hash_destroy(fmd_scheme_hash_t *);
extern void fmd_scheme_hash_trygc(fmd_scheme_hash_t *);

extern fmd_scheme_t *fmd_scheme_hash_lookup(fmd_scheme_hash_t *, const char *);
extern void fmd_scheme_hash_release(fmd_scheme_hash_t *, fmd_scheme_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_SCHEME_H */
