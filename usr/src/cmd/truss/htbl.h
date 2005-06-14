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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_HTBL_H
#define	_HTBL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdlib.h>

typedef struct hentry {
	struct hentry *next;		/* next entry in hash chain */
	struct hentry *prev;		/* previous entry in hash chain */
	char *lib;			/* library name */
	char *key;			/* hash key (function name) */
	unsigned long count;		/* number of occurances of fn */
} hentry_t;

typedef struct hashb {
	hentry_t *first;		/* first entry in bucket */
	mutex_t block;			/* bucket lock */
} hashb_t;

typedef struct htbl {
	unsigned int size;		/* size of tbl in buckets */
	hashb_t *tbl;			/* ptr to buckets */
} htbl_t;

typedef struct hiter {
	int bucket;			/* bucket in current iteration */
	hentry_t *next;			/* next entry in iteration */
	htbl_t *table;			/* ptr to table */
} hiter_t;

/*
 * HD_hashntry specifies that the entry written to disk contains information
 * about function calls and is stored in the hash table.  When read back from
 * disk this is merged into the parent's hash table
 *
 * HD_cts_syscts specifies that the entry written to disk is a struct counts
 * struct syscount pair.  This contains information about system calls,
 * signals, and faults.  When read back from disk, the information is added
 * to the struct count / struct syscount information kept by the parent.
 */

typedef enum hdtype { HD_hashntry, HD_cts_syscts } hdtype_t;

typedef struct hdntry {
	hdtype_t type;		/* type of entry we've written to disk */
	size_t sz_lib;		/* size of library string on disk */
	size_t sz_key;		/* size of key string on disk */
	unsigned long count;	/* count of occurrances of key */
} hdntry_t;


extern htbl_t *init_hash(unsigned int);
extern void destroy_hash(htbl_t *);
extern hiter_t *iterate_hash(htbl_t *);
extern hentry_t *iter_next(hiter_t *);
extern void iter_free(hiter_t *);
extern void add_fcall(htbl_t *, char *, char *, unsigned long);
extern size_t elements_in_table(htbl_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _HTBL_H */
