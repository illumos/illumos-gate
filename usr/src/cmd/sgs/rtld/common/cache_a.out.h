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
 *	Copyright (c) 1998 by Sun Microsystems, Inc.
 */
#ifndef	_CACHE_DOT_H
#define	_CACHE_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ld.so directory caching
 */
#include	<sys/types.h>

/*
 * Shared object lookup performance in the run-time link editor is
 * enhanced through the use of caches for directories that the editor
 * searches.  A given "cache" describes the contents of a single directory,
 * and each cache entry contains the canonical name for a shared object
 * as well as its absolute pathname.
 *
 * Within a cache, "pointers" are really relative addresses to some absolute
 * address (often the base address of the containing database).
 */

/*
 * Relative pointer macros.
 */
#define	RELPTR(base, absptr) ((long)(absptr) - (long)(base))
#define	AP(base) ((caddr_t)base)

/*
 * Definitions for cache structures.
 */
#define	DB_HASH		11		/* number of hash buckets in caches */
#define	LD_CACHE_MAGIC 	0x041155	/* cookie to identify data structure */
#define	LD_CACHE_VERSION 0		/* version number of cache structure */

struct	dbe	{			/* element of a directory cache */
	long	dbe_next;		/* (rp) next element on this list */
	long	dbe_lop;		/* (rp) canonical name for object */
	long	dbe_name;		/* (rp) absolute name */
};

struct	db	{			/* directory cache database */
	long	db_name;		/* (rp) directory contained here */
	struct	dbe db_hash[DB_HASH];	/* hash buckets */
	caddr_t	db_chain;		/* private to database mapping */
};

struct dbf 	{			/* cache file image */
	long dbf_magic;			/* identifying cookie */
	long dbf_version;		/* version no. of these dbs */
	long dbf_machtype;		/* machine type */
	long dbf_db;		/* directory cache dbs */
};

/*
 * Structures used to describe and access a database.
 */
struct	dbd	{			/* data base descriptor */
	struct	dbd *dbd_next;		/* next one on this list */
	struct	db *dbd_db;		/* data base described by this */
};

struct	dd	{			/* directory descriptor */
	struct	dd *dd_next;		/* next one on this list */
	struct	db *dd_db;		/* data base described by this */
};

/*
 * Interfaces imported/exported by the lookup code.
 */

char	*ask_db();			/* ask db for highest minor number */
struct	db *lo_cache();			/* obtain cache for directory name */

#endif
