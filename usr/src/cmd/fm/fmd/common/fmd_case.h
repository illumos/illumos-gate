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

#ifndef	_FMD_CASE_H
#define	_FMD_CASE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_list.h>
#include <fmd_api.h>
#include <fmd_buf.h>

struct fmd_module;			/* see <fmd_module.h> */

typedef struct fmd_case_item {
	struct fmd_case_item *cit_next;	/* pointer to next element in list */
	fmd_event_t *cit_event;		/* pointer to held event */
} fmd_case_item_t;

typedef struct fmd_case_susp {
	struct fmd_case_susp *cis_next;	/* pointer to next element in list */
	nvlist_t *cis_nvl;		/* nvpair representing fault event */
} fmd_case_susp_t;

typedef struct fmd_case_impl {
	fmd_list_t ci_list;		/* linked list next/prev pointers */
	struct fmd_case_impl *ci_next;	/* next pointer for hash bucket chain */
	char *ci_uuid;			/* uuid string for this case */
	uint_t ci_uuidlen;		/* length of ci_uuid (not incl. \0) */
	char *ci_code;			/* code associated with this case */
	size_t ci_codelen;		/* size of ci_code buffer in bytes */
	struct fmd_module *ci_mod;	/* module that owns this case */
	fmd_xprt_t *ci_xprt;		/* transport for this case (or NULL) */
	void *ci_data;			/* data from fmd_case_setspecific() */
	pthread_mutex_t ci_lock;	/* lock for remainder of contents */
	uint_t ci_refs;			/* reference count */
	ushort_t ci_state;		/* case state (see below) */
	ushort_t ci_flags;		/* case flags (see below) */
	fmd_case_item_t *ci_items;	/* list of items in this case */
	uint_t ci_nitems;		/* number of ci_items */
	fmd_event_t *ci_principal;	/* principal event (if any) */
	fmd_case_susp_t *ci_suspects;	/* list of suspects in this case */
	uint_t ci_nsuspects;		/* number of ci_suspects */
	size_t ci_nvsz;			/* packed suspect nvlist array size */
	fmd_buf_hash_t ci_bufs;		/* hash of bufs associated with case */
	struct timeval ci_tv;		/* time of original diagnosis */
	int ci_tv_valid;		/* time of original diagnosis valid */
} fmd_case_impl_t;

#define	FMD_CASE_CURRENT	-1u	/* flag for current state */

#define	FMD_CASE_UNSOLVED	0	/* case is not yet solved (waiting) */
#define	FMD_CASE_SOLVED		1	/* case is solved (suspects added) */
#define	FMD_CASE_CLOSE_WAIT	2	/* case is executing fmdo_close() */
#define	FMD_CASE_CLOSED		3	/* case is closed (reconfig done) */
#define	FMD_CASE_REPAIRED	4	/* case is repaired (can be freed) */

#define	FMD_CF_DIRTY		0x01	/* case is in need of checkpoint */
#define	FMD_CF_SOLVED		0x02	/* case has been solved */
#define	FMD_CF_ISOLATED		0x04	/* case has been isolated */
#define	FMD_CF_REPAIRED		0x08	/* case has been repaired */
#define	FMD_CF_REPAIRING	0x10	/* case repair in progress */
#define	FMD_CF_INVISIBLE	0x20	/* case should be invisible */
#define	FMD_CF_DELETING		0x40	/* case is about to be deleted */

typedef struct fmd_case_hash {
	pthread_rwlock_t ch_lock;	/* lock protecting case hash */
	fmd_case_impl_t **ch_hash;	/* hash bucket array for cases */
	uint_t ch_hashlen;		/* size of hash bucket array */
	uint_t ch_count;		/* number of cases in hash */
} fmd_case_hash_t;

extern fmd_case_hash_t *fmd_case_hash_create(void);
extern void fmd_case_hash_destroy(fmd_case_hash_t *);
extern fmd_case_t *fmd_case_hash_lookup(fmd_case_hash_t *, const char *);
extern void fmd_case_hash_apply(fmd_case_hash_t *,
    void (*)(fmd_case_t *, void *), void *);

extern fmd_case_t *fmd_case_create(struct fmd_module *, void *);
extern fmd_case_t *fmd_case_recreate(struct fmd_module *,
    struct fmd_xprt *, uint_t, const char *, const char *);
extern void fmd_case_destroy(fmd_case_t *, int);
extern void fmd_case_hold(fmd_case_t *);
extern void fmd_case_hold_locked(fmd_case_t *);
extern void fmd_case_rele(fmd_case_t *);

extern int fmd_case_insert_principal(fmd_case_t *, fmd_event_t *);
extern int fmd_case_insert_event(fmd_case_t *, fmd_event_t *);

extern void fmd_case_insert_suspect(fmd_case_t *, nvlist_t *);
extern void fmd_case_recreate_suspect(fmd_case_t *, nvlist_t *);
extern void fmd_case_reset_suspects(fmd_case_t *);

extern nvlist_t *fmd_case_mkevent(fmd_case_t *, const char *);
extern void fmd_case_publish(fmd_case_t *, uint_t);
extern void fmd_case_transition(fmd_case_t *, uint_t, uint_t);
extern void fmd_case_transition_update(fmd_case_t *, uint_t, uint_t);
extern void fmd_case_setdirty(fmd_case_t *);
extern void fmd_case_clrdirty(fmd_case_t *);
extern void fmd_case_commit(fmd_case_t *);
extern void fmd_case_update(fmd_case_t *);
extern void fmd_case_delete(fmd_case_t *);
extern void fmd_case_discard(fmd_case_t *);
extern void fmd_case_settime(fmd_case_t *, time_t, suseconds_t);

extern int fmd_case_repair(fmd_case_t *);
extern int fmd_case_contains(fmd_case_t *, fmd_event_t *);
extern int fmd_case_orphaned(fmd_case_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_CASE_H */
