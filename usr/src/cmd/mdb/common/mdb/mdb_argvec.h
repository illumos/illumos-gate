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

#ifndef	_MDB_ARGVEC_H
#define	_MDB_ARGVEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct mdb_arg;

typedef struct mdb_argvec {
	struct mdb_arg *a_data;		/* Array of arguments */
	size_t a_nelems;		/* Number of valid elements */
	size_t a_size;			/* Array size */
} mdb_argvec_t;

/* see mdb_modapi.h for 1-6 */
#define	MDB_OPT_SUBOPTS	7		/* Option requires a mdb_subopt_t */
					/* list and a value argument */

typedef struct mdb_subopt {
	uint_t sop_flag;		/* Option flag */
	const char *sop_str;		/* Sub-option name */
	int sop_index;			/* Index of subopt in argument */
} mdb_subopt_t;

typedef struct mdb_opt {
	char opt_char;			/* Option name */
	void *opt_valp;			/* Value storage pointer */
	uint_t opt_bits;		/* Bits to set or clear for booleans */
	boolean_t *opt_flag;		/* pointer to flag (uintptr_set) */
	mdb_subopt_t *opt_subopts;	/* List of mdb_subopt_t */
	uint_t opt_type;		/* Option type (see above) */
} mdb_opt_t;

#ifdef _MDB

#ifdef	_BIG_ENDIAN
#ifdef	_LP64
#define	MDB_INIT_CHAR(x)	((const char *)((uintptr_t)(uchar_t)(x) << 56))
#else	/* _LP64 */
#define	MDB_INIT_CHAR(x)	((const char *)((uintptr_t)(uchar_t)(x) << 24))
#endif	/* _LP64 */
#else	/* _BIG_ENDIAN */
#define	MDB_INIT_CHAR(x)	((const char *)(uchar_t)(x))
#endif	/* _BIG_ENDIAN */
#define	MDB_INIT_STRING(x)	((const char *)(x))

extern void mdb_argvec_create(mdb_argvec_t *);
extern void mdb_argvec_destroy(mdb_argvec_t *);
extern void mdb_argvec_append(mdb_argvec_t *, const struct mdb_arg *);
extern void mdb_argvec_reset(mdb_argvec_t *);
extern void mdb_argvec_zero(mdb_argvec_t *);
extern void mdb_argvec_copy(mdb_argvec_t *, const mdb_argvec_t *);

extern char *mdb_argv_to_str(int, const struct mdb_arg *);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_ARGVEC_H */
