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
/*
 * Copyright (c) 2013 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */

#ifndef	_MDB_NV_H
#define	_MDB_NV_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

/*
 * There used to be a cap (MDB_NV_NAMELEN bytes including null) on the
 * length of variable names stored in-line.  This cap is no longer there,
 * however parts of mdb use the constant to sanitize input.
 */
#define	MDB_NV_NAMELEN	31	/* Max variable name length including null */

/*
 * These flags are stored inside each variable in v_flags:
 */
#define	MDB_NV_PERSIST	0x01	/* Variable is persistent (cannot be unset) */
#define	MDB_NV_RDONLY	0x02	/* Variable is read-only (cannot insert over) */
#define	MDB_NV_EXTNAME	0x04	/* Variable name is stored externally */
#define	MDB_NV_TAGGED	0x08	/* Variable is tagged (user-defined) */
#define	MDB_NV_OVERLOAD	0x10	/* Variable can be overloaded (multiple defs) */

/*
 * These flags may be passed to mdb_nv_insert() but are not stored
 * inside the variable (and thus use bits outside of 0x00 - 0xff):
 */
#define	MDB_NV_SILENT	0x100	/* Silence warnings about existing defs */
#define	MDB_NV_INTERPOS	0x200	/* Interpose definition over previous defs */

struct mdb_var;			/* Forward declaration */
struct mdb_walk_state;		/* Forward declaration */

/*
 * Each variable's behavior with respect to the get-value and set-value
 * operations can be changed using a discipline: a pointer to an ops
 * vector which can re-define these operations:
 */
typedef struct mdb_nv_disc {
	void (*disc_set)(struct mdb_var *, uintmax_t);
	uintmax_t (*disc_get)(const struct mdb_var *);
} mdb_nv_disc_t;

/*
 * Each variable is defined by the following variable-length structure.
 * The debugger uses name/value collections to hash almost everything, so
 * we make a few simple space optimizations:
 *
 * A variable's name can be a pointer to external storage (v_ename and
 * MDB_NV_EXTNAME set), or it can be stored locally (bytes of storage are
 * allocated immediately after v_lname[0]).
 *
 * A variable may have multiple definitions (v_ndef chain), but this feature
 * is mutually exclusive with MDB_NV_EXTNAME in order to save space.
 */
typedef struct mdb_var {
	uintmax_t v_uvalue;		/* Value as unsigned integral type */
	union {
		const char *v_ename;	/* Variable name if stored externally */
		struct mdb_var *v_ndef;	/* Variable's next definition */
	} v_du;
	const mdb_nv_disc_t *v_disc;	/* Link to variable discipline */
	struct mdb_var *v_next;		/* Link to next var in hash chain */
	uchar_t v_flags;		/* Variable flags (see above) */
	char v_lname[1];		/* Variable name if stored locally */
} mdb_var_t;

#define	MDB_NV_VALUE(v)		((v)->v_uvalue)
#define	MDB_NV_COOKIE(v)	((void *)(uintptr_t)((v)->v_uvalue))

#define	v_ename		v_du.v_ename
#define	v_ndef		v_du.v_ndef

/*
 * The name/value collection itself is a simple array of hash buckets,
 * as well as a persistent bucket index and pointer for iteration:
 */
typedef struct mdb_nv {
	mdb_var_t **nv_hash;		/* Hash bucket array */
	size_t nv_hashsz;		/* Size of hash bucket array */
	size_t nv_nelems;		/* Total number of hashed elements */
	mdb_var_t *nv_iter_elt;		/* Iterator element pointer */
	size_t nv_iter_bucket;		/* Iterator bucket index */
	uint_t nv_um_flags;		/* Flags for the memory allocator */
} mdb_nv_t;

extern mdb_nv_t *mdb_nv_create(mdb_nv_t *, uint_t);
extern void mdb_nv_destroy(mdb_nv_t *);

extern mdb_var_t *mdb_nv_insert(mdb_nv_t *, const char *,
    const mdb_nv_disc_t *, uintmax_t, uint_t);

extern mdb_var_t *mdb_nv_lookup(mdb_nv_t *, const char *);
extern void mdb_nv_remove(mdb_nv_t *, mdb_var_t *);

extern void mdb_nv_rewind(mdb_nv_t *);
extern mdb_var_t *mdb_nv_advance(mdb_nv_t *);
extern mdb_var_t *mdb_nv_peek(mdb_nv_t *);
extern size_t mdb_nv_size(mdb_nv_t *);

extern void mdb_nv_sort_iter(mdb_nv_t *,
    int (*)(mdb_var_t *, void *), void *, uint_t);

extern void mdb_nv_defn_iter(mdb_var_t *,
    int (*)(mdb_var_t *, void *), void *);

extern uintmax_t mdb_nv_get_value(const mdb_var_t *);
extern void mdb_nv_set_value(mdb_var_t *, uintmax_t);

extern void *mdb_nv_get_cookie(const mdb_var_t *);
extern void mdb_nv_set_cookie(mdb_var_t *, void *);

extern const char *mdb_nv_get_name(const mdb_var_t *);
extern mdb_var_t *mdb_nv_get_ndef(const mdb_var_t *);

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_NV_H */
