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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_BUF_H
#define	_FMD_BUF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct fmd_buf {
	char *buf_name;			/* name of this buffer */
	struct fmd_buf *buf_next;	/* next buffer in hash chain */
	void *buf_data;			/* buffer data storage */
	size_t buf_size;		/* buffer size */
	uint_t buf_flags;		/* buffer flags (see below) */
} fmd_buf_t;

#define	FMD_BUF_DIRTY	0x1		/* buffer is dirty (needs checkpoint) */

typedef void fmd_buf_f(fmd_buf_t *, void *);

typedef struct fmd_buf_hash {
	fmd_buf_t **bh_hash;		/* hash bucket array for buffers */
	uint_t bh_hashlen;		/* length of hash bucket array */
	uint_t bh_count;		/* number of buffers in hash */
} fmd_buf_hash_t;

extern void fmd_buf_hash_create(fmd_buf_hash_t *);
extern size_t fmd_buf_hash_destroy(fmd_buf_hash_t *);
extern void fmd_buf_hash_apply(fmd_buf_hash_t *, fmd_buf_f *, void *);
extern void fmd_buf_hash_commit(fmd_buf_hash_t *);
extern uint_t fmd_buf_hash_count(fmd_buf_hash_t *);

extern fmd_buf_t *fmd_buf_insert(fmd_buf_hash_t *, const char *, size_t);
extern fmd_buf_t *fmd_buf_lookup(fmd_buf_hash_t *, const char *);
extern void fmd_buf_delete(fmd_buf_hash_t *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_BUF_H */
