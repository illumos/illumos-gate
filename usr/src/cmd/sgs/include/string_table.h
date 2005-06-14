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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_STRING_TABLE_DOT_H
#define	_STRING_TABLE_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/avl.h>
#include <sgs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef	struct str_hash		Str_hash;
typedef	struct str_tbl		Str_tbl;
typedef	struct str_master	Str_master;


/*
 * The Stringlist is the list of 'input strings'
 * associatied with the AVL nodes Stringelem.
 */
typedef struct stringlist {
	const char		*sl_string;
	struct stringlist	*sl_next;
} Stringlist;

/*
 * Nodes for the initial AVL tree which contains all of
 * the input strings.  The AVL tree is indexed off of
 * the length of the strings.  This permits later traversal
 * of all of the strings based off of their string length.
 */
typedef struct {
	avl_node_t	se_avlnode;
	Stringlist	*se_strlist;
	uint_t		se_stlen;
} Stringelem;


/*
 * Pointer to the Master string, other strings may be suffixes
 * of this string.
 */
struct str_master {
	const char	*sm_str;	/* pointer to master string */
	Str_master	*sm_next;	/* used for tracking master strings */
	uint_t		sm_stlen;	/* length of master string */
	uint_t		sm_hashval;	/* hashval of master string */
	uint_t		sm_stoff;	/* offset into destination strtab */
};


/*
 * Represents a individual string that was input into
 * the String hash table.  The string may either be a
 * suffix of another string or a master string.
 */
struct str_hash {
	uint_t		hi_stlen;	/* string length */
	uint_t		hi_refcnt;	/* # of references to str */
	uint_t		hi_hashval;	/* hash for string */
	Str_master	*hi_mstr;	/* pointer to master string */
	Str_hash	*hi_next;	/* next entry in hash bckt */
};

/*
 * Controlling data structure for a String Table
 */
struct str_tbl {
	avl_tree_t	*st_strtree;		/* avl tree of initial strs */
	char		*st_strbuf;		/* string buffer */
	Str_hash	**st_hashbcks;		/* hash buckets */
	Str_master	*st_mstrlist;		/* list of all master strings */
	uint_t		st_fullstringsize;	/* uncompressed table size */
	uint_t		st_nextoff;		/* next available string */
	uint_t		st_stringsize;		/* compressed size */
	uint_t		st_stringcnt;		/* # of strings */
	uint_t		st_hbckcnt;		/* # of buckets in hashlist */
	uint_t		st_flags;
};

#define	FLG_STTAB_COOKED	0x00000001	/* offset has been assigned */
#define	FLG_STTAB_COMPRESS	0x00000002	/* build compressed str tab */

/*
 * starting value for use with string hashing functions
 * inside of string_table.c
 */
#define	HASHSEED		5381

/*
 * Flags for st_new
 */
#define	FLG_STNEW_COMPRESS	0x00000001	/* build compressed str tab */

/*
 * exported string_table.c functions
 */
extern int		st_delstring(Str_tbl *, const char *);
extern void		st_destroy(Str_tbl *);
extern uint_t		st_getstrtab_sz(Str_tbl *);
extern const char	*st_getstrbuf(Str_tbl *);
extern int		st_insert(Str_tbl *, const char *);
extern int		st_setstrbuf(Str_tbl *, char *, uint_t);
extern int		st_setstring(Str_tbl *, const char *, uint_t *);
extern Str_tbl		*st_new(uint_t);

#ifdef __cplusplus
}
#endif

#endif /* _STRING_TABLE_DOT_H */
