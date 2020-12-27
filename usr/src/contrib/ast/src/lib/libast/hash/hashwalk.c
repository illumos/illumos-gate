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

#include "hashlib.h"

/*
 * apply walker to each active bucket in the table
 */

int
hashwalk(Hash_table_t* tab, int flags, register int (*walker)(const char*, char*, void*), void* handle)
{
	register Hash_bucket_t*	b;
	register int		v;
	Hash_position_t*	pos;

	if (!(pos = hashscan(tab, flags)))
		return(-1);
	v = 0;
	while (b = hashnext(pos))
		if ((v = (*walker)(hashname(b), (tab->flags & HASH_VALUE) ? b->value : (char*)b, handle)) < 0)
			break;
	hashdone(pos);
	return(v);
}
