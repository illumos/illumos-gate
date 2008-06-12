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

#ifndef	_FMD_ASRU_H
#define	_FMD_ASRU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <pthread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_api.h>
#include <fmd_log.h>
#include <fmd_list.h>
#include <fmd_topo.h>

/*
 * The resource is represented by an fmd_asru_t structure and one or more
 * fmd_asru_link_t structures. Each of the latter represents a separate
 * unrepaired case (problem) involving the resource. There are separate
 * reference counts for both the fmd_asru_t and fmd_asru_link_t structures,
 * but only one lock is used (asru_lock) which protects both the parent
 * fmd_asru_t and its associated fmd_asru_link_t structures. The FMD_ASRU_FAULTY
 * flags in the fmd_asru_t represents the cumulative value of the associated
 * FMD_ASRU_FAULTY flags in the fmd_asru_link_t structures (and therefore of
 * all independant unrepaired problems that are affecting that resource).
 */
typedef struct fmd_asru {
	struct fmd_asru *asru_next;	/* next asru on hash chain */
	char *asru_name;		/* string form of resource fmri (ro) */
	nvlist_t *asru_fmri;		/* nvlist form of resource fmri (ro) */
	char *asru_root;		/* directory for cache entry (ro) */
	char *asru_uuid;		/* uuid for asru cache entry (ro) */
	uint_t asru_uuidlen;		/* length of asru_uuid (not incl. \0) */
	pthread_mutex_t asru_lock;	/* lock protecting remaining members */
	pthread_cond_t asru_cv;		/* condition variable for asru_flags */
	uint_t asru_refs;		/* reference count */
	uint_t asru_flags;		/* flags (see below) */
	fmd_case_t *asru_case;		/* case associated with last change */
	nvlist_t *asru_event;		/* event associated with last change */
	fmd_list_t asru_list;		/* linked list next/prev pointers */
} fmd_asru_t;

typedef struct fmd_asru_link {
	fmd_list_t al_list;		/* linked list next/prev pointers */
	struct fmd_asru *al_asru;		/* pointer back to parent */
	struct fmd_asru_link *al_asru_next;	/* next link on hash chain */
	struct fmd_asru_link *al_case_next;	/* next link on hash chain */
	struct fmd_asru_link *al_fru_next;	/* next link on hash chain */
	struct fmd_asru_link *al_label_next;	/* next link on hash chain */
	struct fmd_asru_link *al_rsrc_next;	/* next link on hash chain */
	char *al_uuid;			/* uuid for asru cache entry (ro) */
	uint_t al_uuidlen;		/* length of al_uuid (not incl. \0) */
	fmd_log_t *al_log;		/* persistent event log */
	char *al_asru_name;		/* string form of asru fmri (ro) */
	char *al_fru_name;		/* string form of fru fmri (ro) */
	char *al_rsrc_name;		/* string form of resource fmri (ro) */
	char *al_label;			/* label */
	char *al_case_uuid;		/* case uuid */
	nvlist_t *al_asru_fmri;		/* nvlist form of resource fmri (ro) */
	fmd_case_t *al_case;		/* case associated with last change */
	nvlist_t *al_event;		/* event associated with last change */
	uint_t al_refs;			/* reference count */
	uint_t al_flags;		/* flags (see below) */
} fmd_asru_link_t;

#define	FMD_ASRU_FAULTY		0x01	/* asru has been diagnosed as faulty */
#define	FMD_ASRU_UNUSABLE	0x02	/* asru can not be used at present */
#define	FMD_ASRU_VALID		0x04	/* asru is initialized and valid */
#define	FMD_ASRU_INTERNAL	0x08	/* asru is managed by fmd itself */
#define	FMD_ASRU_INVISIBLE	0x10	/* asru is not visibly administered */
#define	FMD_ASRU_RECREATED	0x20	/* asru recreated by cache replay */
#define	FMD_ASRU_PRESENT	0x40	/* asru present at last R$ update */

#define	FMD_ASRU_STATE	(FMD_ASRU_FAULTY | FMD_ASRU_UNUSABLE)

#define	FMD_ASRU_AL_HASH_NAME(a, off) \
	*(char **)((uint8_t *)a + off)
#define	FMD_ASRU_AL_HASH_NEXT(a, off) \
	*(fmd_asru_link_t **)((uint8_t *)a + off)
#define	FMD_ASRU_AL_HASH_NEXTP(a, off) \
	(fmd_asru_link_t **)((uint8_t *)a + off)

typedef struct fmd_asru_hash {
	pthread_rwlock_t ah_lock;	/* r/w lock protecting hash contents */
	fmd_asru_t **ah_hash;		/* hash bucket array for asrus */
	fmd_asru_link_t **ah_asru_hash;	/* hash bucket array for asrus */
	fmd_asru_link_t **ah_case_hash;	/* hash bucket array for frus */
	fmd_asru_link_t **ah_fru_hash;	/* hash bucket array for cases */
	fmd_asru_link_t **ah_label_hash;	/* label hash bucket array */
	fmd_asru_link_t **ah_rsrc_hash;	/* hash bucket array for rsrcs */
	uint_t ah_hashlen;		/* length of hash bucket array */
	char *ah_dirpath;		/* path of hash's log file directory */
	uint64_t ah_lifetime;		/* max lifetime of log if not present */
	uint_t ah_al_count;		/* count of number of entries in hash */
	uint_t ah_count;		/* count of separate rsrcs in hash */
	int ah_error;			/* error from opening asru log */
	fmd_topo_t *ah_topo;		/* topo handle */
} fmd_asru_hash_t;

extern fmd_asru_hash_t *fmd_asru_hash_create(const char *, const char *);
extern void fmd_asru_hash_destroy(fmd_asru_hash_t *);
extern void fmd_asru_hash_refresh(fmd_asru_hash_t *);
extern void fmd_asru_hash_replay(fmd_asru_hash_t *);

extern void fmd_asru_hash_apply(fmd_asru_hash_t *,
    void (*)(fmd_asru_t *, void *), void *);
extern void fmd_asru_al_hash_apply(fmd_asru_hash_t *,
    void (*)(fmd_asru_link_t *, void *), void *);
extern void fmd_asru_hash_apply_by_asru(fmd_asru_hash_t *, char *,
    void (*)(fmd_asru_link_t *, void *), void *);
extern void fmd_asru_hash_apply_by_label(fmd_asru_hash_t *, char *,
    void (*)(fmd_asru_link_t *, void *), void *);
extern void fmd_asru_hash_apply_by_fru(fmd_asru_hash_t *, char *,
    void (*)(fmd_asru_link_t *, void *), void *);
extern void fmd_asru_hash_apply_by_rsrc(fmd_asru_hash_t *, char *,
    void (*)(fmd_asru_link_t *, void *), void *);
extern void fmd_asru_hash_apply_by_case(fmd_asru_hash_t *, fmd_case_t *,
    void (*)(fmd_asru_link_t *, void *), void *);

extern fmd_asru_t *fmd_asru_hash_lookup_name(fmd_asru_hash_t *, const char *);
extern fmd_asru_t *fmd_asru_hash_lookup_nvl(fmd_asru_hash_t *, nvlist_t *);
extern fmd_asru_link_t *fmd_asru_hash_create_entry(fmd_asru_hash_t *,
    fmd_case_t *, nvlist_t *);
extern void fmd_asru_hash_release(fmd_asru_hash_t *, fmd_asru_t *);
extern void fmd_asru_hash_delete_case(fmd_asru_hash_t *, fmd_case_t *);

extern void fmd_asru_clear_aged_rsrcs();
extern void fmd_asru_repair(fmd_asru_link_t *, void *);
extern int fmd_asru_setflags(fmd_asru_link_t *, uint_t);
extern int fmd_asru_clrflags(fmd_asru_link_t *, uint_t);
extern int fmd_asru_al_getstate(fmd_asru_link_t *);
extern int fmd_asru_getstate(fmd_asru_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_ASRU_H */
