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
 * AT&T Bell Laboratories
 *
 * hash table library
 */

#include "hashlib.h"

/*
 * dump HASH_* flags
 */

static void
dumpflags(register int flags)
{
	if (flags & HASH_ALLOCATE) sfprintf(sfstderr, "allocate ");
	if (flags & HASH_BUCKET) sfprintf(sfstderr, "bucket ");
	if (flags & HASH_FIXED) sfprintf(sfstderr, "fixed ");
	if (flags & HASH_HASHED) sfprintf(sfstderr, "hashed ");
	if (flags & HASH_RESIZE) sfprintf(sfstderr, "resize ");
	if (flags & HASH_STATIC) sfprintf(sfstderr, "static ");
	if (flags & HASH_VALUE) sfprintf(sfstderr, "value ");
}

/*
 * dump hash table bucket info
 */

static void
dumpbucket(register Hash_table_t* tab, int flags)
{
	register Hash_bucket_t**	sp;
	register Hash_bucket_t*		b;
	Hash_bucket_t**			sx;
	int				n;
	unsigned char*			s;

	NoP(flags);
	sx = tab->table + tab->size;
	for (sp = tab->table; sp < sx; sp++)
	{
		n = 0;
		for (b = *sp; b; b = b->next)
			if (!(b->hash & HASH_DELETED) && (!(tab->flags & HASH_VALUE) || b->value))
				n++;
		if (n)
		{
			sfprintf(sfstderr, "%5d %2d :", sp - tab->table, n);
			for (b = *sp; b; b = b->next)
				if (!(b->hash & HASH_DELETED) && (!(tab->flags & HASH_VALUE) || b->value))
				{
					if (n = tab->root->namesize)
					{
						sfprintf(sfstderr, " 0x");
						s = (unsigned char*)hashname(b);
						while (n-- > 0)
							sfprintf(sfstderr, "%02x", *s++);
					}
					else sfprintf(sfstderr, " %s", hashname(b));
					if (b->hash & HASH_FLAGS)
					{
						sfprintf(sfstderr, "|");
						if (b->hash & HASH_HIDES) sfprintf(sfstderr, "hides|");
						if (b->hash & HASH_HIDDEN) sfprintf(sfstderr, "hidden|");
						if (b->hash & HASH_KEEP) sfprintf(sfstderr, "keep|");
						if (b->hash & HASH_OPAQUED) sfprintf(sfstderr, "opaque|");
					}
					if (tab->flags & HASH_VALUE) sfprintf(sfstderr, "=0x%08lx", (long)b->value);
				}
			sfprintf(sfstderr, "\n");
		}
	}
	sfprintf(sfstderr, "\n");
}

/*
 * dump info on a single table
 */

static void
dumptable(register Hash_table_t* tab, register int flags)
{
	Hash_table_t*	scope;
	int		level;

	sfprintf(sfstderr, "        name:        %s", tab->name ? tab->name : "*no name*");
	if (scope = tab->scope)
	{
		level = 1;
		while (scope = scope->scope) level++;
		sfprintf(sfstderr, " level %d scope on 0x%08lx", level, (unsigned long)tab->scope);
	}
	sfprintf(sfstderr, "\n");
	sfprintf(sfstderr, "        address:     0x%08lx\n", (unsigned long)tab);
	sfprintf(sfstderr, "        flags:       ");
	if (tab->frozen) sfprintf(sfstderr, "frozen=%d ", tab->frozen);
	dumpflags(tab->flags);
	sfprintf(sfstderr, "\n");
	sfprintf(sfstderr, "        size:        %d\n", tab->size);
	sfprintf(sfstderr, "        buckets:     %d\n", tab->buckets);
	sfprintf(sfstderr, "        bucketsize:  %d\n", tab->bucketsize * sizeof(char*));
	sfprintf(sfstderr, "\n");
	if ((flags | tab->flags) & HASH_BUCKET) dumpbucket(tab, flags);
}

/*
 * dump hash table root info
 */

static void
dumproot(register Hash_root_t* root, register int flags)
{
	register Hash_table_t*	tab;

	sfprintf(sfstderr, "    root\n");
	sfprintf(sfstderr, "        address:     0x%08lx\n", (unsigned long)root);
	sfprintf(sfstderr, "        flags:       ");
	dumpflags(root->flags);
	if (root->namesize) sfprintf(sfstderr, "namesize=%d ", root->namesize);
	if (root->local->alloc) sfprintf(sfstderr, "alloc=0x%08lx ", (unsigned long)root->local->alloc);
	if (root->local->compare) sfprintf(sfstderr, "compare=0x%08lx ", (unsigned long)root->local->compare);
	if (root->local->free) sfprintf(sfstderr, "free=0x%08lx ", (unsigned long)root->local->free);
	if (root->local->hash) sfprintf(sfstderr, "hash=0x%08lx ", (unsigned long)root->local->hash);
	if (root->local->region) sfprintf(sfstderr, "region=0x%08lx handle=0x%08lx ", (unsigned long)root->local->region, (unsigned long)root->local->handle);
	sfprintf(sfstderr, "\n");
	sfprintf(sfstderr, "        meanchain:   %d\n", root->meanchain);
	sfprintf(sfstderr, "        accesses:    %d\n", root->accesses);
	sfprintf(sfstderr, "        collisions:  %d\n", root->collisions);
	sfprintf(sfstderr, "\n");
	for (tab = root->references; tab; tab = tab->next)
		dumptable(tab, flags);
}

/*
 * dump hash table accounting info
 * if tab is 0 then dump all tables in hash_info.list
 * flags are HASH_* flags that specifiy optional dump info
 */

void
hashdump(register Hash_table_t* tab, int flags)
{
	register Hash_root_t*	root;

	sfprintf(sfstderr, "\nhash table information:\n\n");
	if (tab) dumproot(tab->root, flags);
	else for (root = hash_info.list; root; root = root->next)
		dumproot(root, flags);
	sfsync(sfstderr);
}
