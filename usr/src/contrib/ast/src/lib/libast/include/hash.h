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
 * hash table library interface definitions
 *
 * NOTE: new code should use the more general <cdt.h>
 */

#ifndef _HASH_H
#define _HASH_H

#define HASH_ALLOCATE	(1L<<0)		/* allocate new key names	*/
#define HASH_FIXED	(1L<<1)		/* fixed table size		*/
#define HASH_HASHED	(1L<<6)		/* key names already hashed	*/
#define HASH_RESIZE	(1L<<2)		/* table has been resized	*/
#define HASH_SCANNING	(1L<<3)		/* currently scanning scope	*/
#define HASH_SCOPE	(1L<<4)		/* push scope / create in bot	*/
#define HASH_STATIC	(1L<<5)		/* static table allocation	*/

#define HASH_CREATE	(1L<<8)		/* create bucket if not found	*/
#define HASH_DELETE	(1L<<9)		/* delete bucket if found	*/
#define HASH_LOOKUP	0		/* default op			*/
#define HASH_RENAME	(1L<<7)		/* rename bucket if found	*/

#define HASH_BUCKET	(1L<<11)	/* name is installed bucket	*/
#define HASH_INSTALL	(1L<<12)	/* install allocated bucket	*/
#define HASH_NOSCOPE	(1L<<13)	/* top scope only		*/
#define HASH_OPAQUE	(1L<<14)	/* opaque bucket		*/
#define HASH_VALUE	(1L<<15)	/* value bucket field used	*/

#define HASH_SIZE(n)	(((long)(n))<<16)  /* fixed bucket size		*/
#define HASH_SIZEOF(f)	((((long)(f))>>16)&0xffff) /* extract size	*/

#define HASH_DELETED	((unsigned long)1<<(8*sizeof(int)-1)) /* deleted placeholder	*/
#define HASH_KEEP	(1L<<(8*sizeof(int)-2))	/* no free on bucket	*/
#define HASH_HIDDEN	(1L<<(8*sizeof(int)-3))	/* hidden by scope	*/
#define HASH_HIDES	(1L<<(8*sizeof(int)-4))	/* hides lower scope	*/
#define HASH_OPAQUED	(1L<<(8*sizeof(int)-5))	/* opaqued placeholder	*/
#define HASH_FREENAME	(1L<<(8*sizeof(int)-6))	/* free bucket name	*/

#define HASH_RESET	(HASH_RESIZE|HASH_SCOPE|HASH_STATIC|HASH_VALUE)
#define HASH_INTERNAL	(HASH_BUCKET|HASH_RESIZE|HASH_SCANNING|HASH_STATIC)
#define HASH_FLAGS	(HASH_DELETED|HASH_FREENAME|HASH_HIDDEN|HASH_HIDES|HASH_KEEP|HASH_OPAQUED)

#define HASH_alloc		1
#define HASH_clear		2
#define HASH_compare		3
#define HASH_free		4
#define HASH_hash		5
#define HASH_meanchain		6
#define HASH_name		7
#define HASH_namesize		8
#define HASH_set		9
#define HASH_size		10
#define HASH_table		11
#define HASH_va_list		12

#define HASH_bucketsize		13

#define HASH_region		14

#include <hashpart.h>

#define hashclear(t,f)		((t)->flags &= ~((f) & ~HASH_INTERNAL))
#define hashcover(b)		(((b)->hash&HASH_HIDES)?(Hash_bucket_t*)((b)->name):(Hash_bucket_t*)0)
#define hashdel(t,n)		hashlook(t, (char*)(n), HASH_DELETE, (char*)0)
#define hashget(t,n)		hashlook(t, (char*)(n), HASH_LOOKUP|HASH_VALUE, (char*)0)
#define hashgetbucket(s)	((Hash_bucket_t*)((s)-((sizeof(Hash_bucket_t)+sizeof(char*)-1)/sizeof(char*))*sizeof(char*)))
#define hashkeep(b)		((b)->hash|=HASH_KEEP)
#define hashname(b)		((((b)->hash&HASH_HIDES)?((Hash_bucket_t*)((b)->name)):(b))->name)
#define hashput(t,n,v)		hashlook(t, (char*)(n), HASH_CREATE|HASH_VALUE, (char*)(v))
#define hashref(t,n)		hashlook(t, (char*)(n), HASH_LOOKUP|HASH_INTERNAL|HASH_VALUE, (char*)0)
#define hashscope(t)		((t)->scope)
#define hashset(t,f)		((t)->flags |= ((f) & ~HASH_INTERNAL))

/*
 * DEPRECATED renames for compatibility
 */

#define Hashbin_t		Hash_bucket_t
#define HASHBUCKET		Hash_bucket_t
#define Hashhdr_t 		Hash_header_t
#define HASHHEADER 		Hash_header_t
#define Hashpos_t 		Hash_position_t
#define HASHPOSITION 		Hash_position_t
#define Hashtab_t		Hash_table_t
#define HASHTABLE		Hash_table_t

#define vhashalloc		hashvalloc
#define hashvalloc(t,a)		hashalloc(t,HASH_va_list,a,0)

/*
 * the #define's avoid union tags
 */

typedef struct Hash_bucket Hash_bucket_t;
typedef struct Hash_root Hash_root_t;
typedef struct Hash_table Hash_table_t;

#define HASH_HEADER			/* common bucket header		*/ \
	Hash_bucket_t*	next;		/* next in collision chain	*/ \
	unsigned int	hash;		/* hash flags and value		*/ \
	char*		name		/* key name			*/

#define HASH_DEFAULT			/* HASH_VALUE bucket elements	*/ \
	char*		value		/* key value			*/

typedef struct				/* bucket header		*/
{
	HASH_HEADER;
} Hash_header_t;

struct Hash_bucket			/* prototype bucket		*/
{
	HASH_HEADER;
	HASH_DEFAULT;
};

typedef struct				/* hash scan bucket position	*/
{
	Hash_bucket_t*	bucket;		/* bucket			*/
#ifdef _HASH_POSITION_PRIVATE_
	_HASH_POSITION_PRIVATE_
#endif
} Hash_position_t;

typedef struct				/* last lookup cache		*/
{
	Hash_table_t*	table;		/* last lookup table		*/
	Hash_bucket_t*	bucket;		/* last lookup bucket		*/
#ifdef _HASH_LAST_PRIVATE_
	_HASH_LAST_PRIVATE_
#endif
} Hash_last_t;

struct Hash_root			/* root hash table information	*/
{
	int		accesses;	/* number of accesses		*/
	int		collisions;	/* number of collisions		*/
	int		flags;		/* flags: see HASH_[A-Z]*	*/
	Hash_last_t	last;		/* last lookup cache		*/
	void*		context;	/* user defined context		*/
#ifdef _HASH_ROOT_PRIVATE_
	_HASH_ROOT_PRIVATE_
#endif
};

struct Hash_table			/* hash table information	*/
{
	Hash_root_t*	root;		/* root hash table information	*/
	int		size;		/* table size			*/
	int		buckets;	/* active bucket count		*/
	char*		name;		/* table name			*/
	Hash_table_t*	scope;		/* scope covered table		*/
	short		flags;		/* flags: see HASH_[A-Z]*	*/
#ifdef _HASH_TABLE_PRIVATE_
	_HASH_TABLE_PRIVATE_
#endif
};

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern Hash_table_t*	hashalloc(Hash_table_t*, ...);
extern void		hashdone(Hash_position_t*);
extern void		hashdump(Hash_table_t*, int);
extern Hash_table_t*	hashfree(Hash_table_t*);
extern Hash_bucket_t*	hashlast(Hash_table_t*);
extern char*		hashlook(Hash_table_t*, const char*, long, const char*);
extern Hash_bucket_t*	hashnext(Hash_position_t*);
extern Hash_position_t*	hashscan(Hash_table_t*, int);
extern void		hashsize(Hash_table_t*, int);
extern Hash_table_t*	hashview(Hash_table_t*, Hash_table_t*);
extern int		hashwalk(Hash_table_t*, int, int (*)(const char*, char*, void*), void*);

#undef	extern

#endif
