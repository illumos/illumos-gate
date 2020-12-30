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
 * hash table library
 */

static const char id_hash[] = "\n@(#)$Id: hash (AT&T Research) 1996-08-11 $\0\n";

#include "hashlib.h"

Hash_info_t	hash_info = { 0 };

/*
 * create a new hash table
 */

Hash_table_t*
hashalloc(Hash_table_t* ref, ...)
{
	register Hash_table_t*	tab;
	register Hash_table_t*	ret = 0;
	register int		internal;
	int			n;
	va_list			ap;
	va_list			va[4];
	va_list*		vp = va;
	Hash_region_f		region = 0;
	void*			handle;

	va_start(ap, ref);

	/*
	 * check for HASH_region which must be first
	 */

	n = va_arg(ap, int);
	if (!ref && n == HASH_region)
	{
		region = va_arg(ap, Hash_region_f);
		handle = va_arg(ap, void*);
		n = va_arg(ap, int);
		if (!(tab = (Hash_table_t*)(*region)(handle, NiL, sizeof(Hash_table_t), 0)))
			goto out;
		memset(tab, 0, sizeof(Hash_table_t));
	}
	else if (!(tab = newof(0, Hash_table_t, 1, 0)))
		goto out;
	tab->bucketsize = (sizeof(Hash_header_t) + sizeof(char*) - 1) / sizeof(char*);
	if (ref)
	{
		tab->flags = ref->flags & ~HASH_RESET;
		tab->root = ref->root;
		internal = HASH_INTERNAL;
	}
	else
	{
		if (region)
		{
			if (!(tab->root = (Hash_root_t*)(*region)(handle, NiL, sizeof(Hash_root_t), 0)))
				goto out;
			memset(tab->root, 0, sizeof(Hash_root_t));
		}
		else if (!(tab->root = newof(0, Hash_root_t, 1, 0)))
			goto out;
		if (!(tab->root->local = newof(0, Hash_local_t, 1, 0)))
			goto out;
		if (tab->root->local->region = region)
			tab->root->local->handle = handle;
		tab->root->meanchain = HASHMEANCHAIN;
		internal = 0;
	}
	tab->size = HASHMINSIZE;
	for (;;)
	{
		switch (n) 
		{
		case HASH_alloc:
			if (ref) goto out;
			tab->root->local->alloc = va_arg(ap, Hash_alloc_f);
			break;
		case HASH_bucketsize:
			n = (va_arg(ap, int) + sizeof(char*) - 1) / sizeof(char*);
			if (n > UCHAR_MAX) goto out;
			if (n > tab->bucketsize) tab->bucketsize = n;
			break;
		case HASH_clear:
			tab->flags &= ~(va_arg(ap, int) & ~internal);
			break;
		case HASH_compare:
			if (ref) goto out;
			tab->root->local->compare = va_arg(ap, Hash_compare_f);
			break;
		case HASH_free:
			if (ref) goto out;
			tab->root->local->free = va_arg(ap, Hash_free_f);
			break;
		case HASH_hash:
			if (ref) goto out;
			tab->root->local->hash = va_arg(ap, Hash_hash_f);
			break;
		case HASH_meanchain:
			if (ref) goto out;
			tab->root->meanchain = va_arg(ap, int);
			break;
		case HASH_name:
			tab->name = va_arg(ap, char*);
			break;
		case HASH_namesize:
			if (ref) goto out;
			tab->root->namesize = va_arg(ap, int);
			break;
		case HASH_region:
			goto out;
		case HASH_set:
			tab->flags |= (va_arg(ap, int) & ~internal);
			break;
		case HASH_size:
			tab->size = va_arg(ap, int);
			if (tab->size & (tab->size - 1)) tab->flags |= HASH_FIXED;
			break;
		case HASH_table:
			tab->table = va_arg(ap, Hash_bucket_t**);
			tab->flags |= HASH_STATIC;
			break;
		case HASH_va_list:
			if (vp < &va[elementsof(va)])
			{
				va_copy(*vp, ap);
				vp++;
			}
			va_copy(ap, va_listval(va_arg(ap, va_listarg)));
			break;
		case 0:
			if (vp > va)
			{
				vp--;
				va_copy(ap, *vp);
				break;
			}
			if (tab->flags & HASH_SCOPE)
			{
				if (!(tab->scope = ref)) goto out;
				ref->frozen++;
			}
			if (!tab->table)
			{
				if (region)
				{
					if (!(tab->table = (Hash_bucket_t**)(*region)(handle, NiL, sizeof(Hash_bucket_t*) * tab->size, 0)))
						goto out;
					memset(tab->table, 0, sizeof(Hash_bucket_t*) * tab->size);
				}
				else if (!(tab->table = newof(0, Hash_bucket_t*, tab->size, 0))) goto out;
			}
			if (!ref)
			{
				tab->root->flags = tab->flags & HASH_INTERNAL;
				tab->root->next = hash_info.list;
				hash_info.list = tab->root;
			}
			if (!region)
			{
				tab->next = tab->root->references;
				tab->root->references = tab;
			}
			ret = tab;
			goto out;
		default:
			goto out;
		}
		n = va_arg(ap, int);
	}
 out:
	va_end(ap);
	if (!ret) hashfree(tab);
	return(ret);
}
