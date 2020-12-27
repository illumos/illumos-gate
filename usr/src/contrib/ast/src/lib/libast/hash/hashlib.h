/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * hash table library private definitions
 */

#ifndef _HASHLIB_H
#define _HASHLIB_H

#include <ast.h>

#define hash_info	_hash_info_

typedef void*		(*Hash_alloc_f)(size_t);
typedef int		(*Hash_compare_f)(const char*, const char*, ...);
typedef unsigned int	(*Hash_hash_f)(const char*, ...);
typedef void		(*Hash_free_f)(void*);
typedef void*		(*Hash_region_f)(void*, void*, size_t, int);

typedef struct				/* root local pointers		*/
{
	Hash_hash_f	hash;		/* name hash routine		*/
	Hash_compare_f	compare;	/* name comparision routine	*/
	Hash_alloc_f	alloc;		/* value allocation routine	*/
	Hash_free_f	free;		/* value free routine		*/
	Hash_region_f	region;		/* region alloc/free routine	*/
	void*		handle;		/* region handle arg		*/
} Hash_local_t;

#define _HASH_POSITION_PRIVATE_ \
	Hash_table_t*	tab;		/* table pointer		*/ \
	int		flags;		/* scan flags			*/ \
	Hash_bucket_t**	slot;		/* table slot			*/ \
	Hash_bucket_t**	limit;		/* slot limit			*/

#define _HASH_LAST_PRIVATE_ \
	const char*	name;		/* last lookup name		*/ \
	unsigned int	hash;		/* last lookup hash		*/

#define _HASH_ROOT_PRIVATE_ \
	int		namesize;	/* fixed name size: 0 => string	*/ \
	int		meanchain;	/* resize mean chain length	*/ \
	Hash_local_t*	local;		/* root local pointers		*/ \
	Hash_root_t*	next;		/* next in list	of all roots	*/ \
	Hash_table_t*	references;	/* referencing table list	*/

#define _HASH_TABLE_PRIVATE_ \
	unsigned char	frozen;		/* table freeze nesting		*/ \
	unsigned char	bucketsize;	/* min bucket size in char*'s	*/ \
	Hash_bucket_t**	table;		/* hash slot table		*/ \
	Hash_table_t*	next;		/* root reference list link	*/

#include <hash.h>

#define HASHMINSIZE	(1<<4)		/* min table slots (power of 2)	*/
#define HASHMEANCHAIN	2		/* def resize mean chain len	*/

#define HASHMOD(t,h)	(h &= (t->size - 1))
#define HASHVAL(x)	((x)&~HASH_FLAGS)

#define HASH(r,n,h)	if (r->local->hash) h = r->namesize ? (*r->local->hash)(n, r->namesize) : (*r->local->hash)(n);\
			else\
			{\
				register const char*	_hash_s1 = n;\
				h = 0;\
				if (r->namesize)\
				{\
					register const char*	_hash_s2 = _hash_s1 + r->namesize;\
					while (_hash_s1 < _hash_s2) HASHPART(h, *_hash_s1++);\
				}\
				else while (*_hash_s1) HASHPART(h, *_hash_s1++);\
			}

typedef struct				/* library private info		*/
{
	Hash_root_t*	list;		/* root table list		*/
} Hash_info_t;

extern Hash_info_t	hash_info;

#endif
