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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 */

#ifndef	_MDB_CTF_H
#define	_MDB_CTF_H

#include <mdb/mdb_target.h>
#include <libctf.h>

#ifdef _MDB
#include <sys/machelf.h>
#endif

/*
 * The following directive tells the mapfile generator that prototypes and
 * declarations ending with an "Internal" comment should be excluded from the
 * mapfile.
 *
 * MAPFILE: exclude "Internal"
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mdb_ctf_id {
	void *_opaque[2];
} mdb_ctf_id_t;

typedef struct mdb_ctf_funcinfo {
	mdb_ctf_id_t mtf_return;	/* function return type */
	uint_t mtf_argc;		/* number of arguments */
	uint_t mtf_flags;		/* function attributes (see libctf.h) */
	uint_t mtf_symidx;		/* for ctf_func_args */
} mdb_ctf_funcinfo_t;

typedef struct mdb_ctf_arinfo {
	mdb_ctf_id_t mta_contents;	/* type of array conents */
	mdb_ctf_id_t mta_index;		/* type of array index */
	uint_t mta_nelems;		/* number of elements */
} mdb_ctf_arinfo_t;

typedef int mdb_ctf_visit_f(const char *, mdb_ctf_id_t, mdb_ctf_id_t, ulong_t,
    int, void *);
typedef int mdb_ctf_member_f(const char *, mdb_ctf_id_t, ulong_t, void *);
typedef int mdb_ctf_enum_f(const char *, int, void *);
typedef int mdb_ctf_type_f(mdb_ctf_id_t, void *);

extern int mdb_ctf_enabled_by_object(const char *);

extern int mdb_ctf_lookup_by_name(const char *, mdb_ctf_id_t *);
extern int mdb_ctf_lookup_by_addr(uintptr_t, mdb_ctf_id_t *);

extern int mdb_ctf_module_lookup(const char *, mdb_ctf_id_t *);

extern int mdb_ctf_func_info(const GElf_Sym *, const mdb_syminfo_t *,
    mdb_ctf_funcinfo_t *);
extern int mdb_ctf_func_args(const mdb_ctf_funcinfo_t *, uint_t,
    mdb_ctf_id_t *);

extern void mdb_ctf_type_invalidate(mdb_ctf_id_t *);
extern int mdb_ctf_type_valid(mdb_ctf_id_t);
extern int mdb_ctf_type_cmp(mdb_ctf_id_t, mdb_ctf_id_t);

extern int mdb_ctf_type_resolve(mdb_ctf_id_t, mdb_ctf_id_t *);
extern char *mdb_ctf_type_name(mdb_ctf_id_t, char *, size_t);
extern ssize_t mdb_ctf_type_size(mdb_ctf_id_t);
extern int mdb_ctf_type_kind(mdb_ctf_id_t);
extern int mdb_ctf_type_reference(const mdb_ctf_id_t, mdb_ctf_id_t *);
extern int mdb_ctf_type_encoding(mdb_ctf_id_t, ctf_encoding_t *);
extern int mdb_ctf_type_visit(mdb_ctf_id_t, mdb_ctf_visit_f *, void *);

extern int mdb_ctf_array_info(mdb_ctf_id_t, mdb_ctf_arinfo_t *);
extern const char *mdb_ctf_enum_name(mdb_ctf_id_t, int);

extern int mdb_ctf_member_iter(mdb_ctf_id_t, mdb_ctf_member_f *, void *);
extern int mdb_ctf_enum_iter(mdb_ctf_id_t, mdb_ctf_enum_f *, void *);
extern int mdb_ctf_type_iter(const char *, mdb_ctf_type_f *, void *);
extern int mdb_ctf_type_delete(const mdb_ctf_id_t *);

/*
 * Special values for mdb_ctf_type_iter.
 */
#define	MDB_CTF_SYNTHETIC_ITER	(const char *)(-1L)

#define	SYNTHETIC_ILP32	1
#define	SYNTHETIC_LP64	2
extern int mdb_ctf_synthetics_create_base(int);
extern int mdb_ctf_synthetics_reset(void);

/*
 * Synthetic creation routines
 */
extern int mdb_ctf_add_typedef(const char *, const mdb_ctf_id_t *,
    mdb_ctf_id_t *);
extern int mdb_ctf_add_struct(const char *, mdb_ctf_id_t *);
extern int mdb_ctf_add_union(const char *, mdb_ctf_id_t *);
extern int mdb_ctf_add_member(const mdb_ctf_id_t *, const char *,
    const mdb_ctf_id_t *, mdb_ctf_id_t *);
extern int mdb_ctf_add_array(const mdb_ctf_arinfo_t *, mdb_ctf_id_t *);
extern int mdb_ctf_add_pointer(const mdb_ctf_id_t *, mdb_ctf_id_t *);

/* utility stuff */
extern ctf_id_t mdb_ctf_type_id(mdb_ctf_id_t);
extern ctf_file_t *mdb_ctf_type_file(mdb_ctf_id_t);


extern int mdb_ctf_member_info(mdb_ctf_id_t, const char *,
    ulong_t *, mdb_ctf_id_t *);
extern int mdb_ctf_offsetof(mdb_ctf_id_t, const char *, ulong_t *);
extern int mdb_ctf_num_members(mdb_ctf_id_t);
extern int mdb_ctf_offsetof_by_name(const char *, const char *);

extern ssize_t mdb_ctf_offset_to_name(mdb_ctf_id_t, ulong_t, char *, size_t,
    int, mdb_ctf_id_t *, ulong_t *);

#define	MDB_CTF_VREAD_QUIET		0x100

extern int mdb_ctf_vread(void *, const char *, const char *,
    uintptr_t, uint_t);
extern int mdb_ctf_readsym(void *, const char *, const char *, uint_t);

#ifdef _MDB

extern ctf_file_t *mdb_ctf_open(const char *, int *);		/* Internal */
extern ctf_file_t *mdb_ctf_bufopen(const void *, size_t,	/* Internal */
    const void *, Shdr *, const void *, Shdr *, int *);
extern int mdb_ctf_write(const char *, ctf_file_t *fp);		/* Internal */
extern void mdb_ctf_close(ctf_file_t *fp);			/* Internal */
extern int mdb_ctf_synthetics_init(void);			/* Internal */
extern void mdb_ctf_synthetics_fini(void);			/* Internal */
extern int mdb_ctf_synthetics_from_file(const char *);		/* Internal */
extern int mdb_ctf_synthetics_to_file(const char *);		/* Internal */

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_CTF_H */
