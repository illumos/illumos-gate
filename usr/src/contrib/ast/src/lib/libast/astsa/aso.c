/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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

#include <aso.h>

int
asolock(unsigned int volatile* lock, unsigned int key, int type)
{
	unsigned int	k;

	if (key)
		switch (type)
		{
		case ASO_UNLOCK:
			if (*lock != 0)
			{
				if (*lock != key)
					return -1;
				*lock = 0;
			}
			return 0;
		case ASO_TRYLOCK:
			if (*lock != key)
			{
				if (*lock != 0)
					return -1;
				*lock = key;
			}
			return 0;
		case ASO_LOCK:
		case ASO_SPINLOCK:
			*lock = key;
			return 0;
		}
	return -1;
}
