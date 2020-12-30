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
 * in-place path name canonicalization -- preserves the logical view
 * pointer to trailing 0 in path returned
 *
 *	remove redundant .'s and /'s
 *	move ..'s to the front
 *	/.. preserved (for pdu and newcastle hacks)
 *	FS_3D handles ...
 *	if (flags&PATH_PHYSICAL) then symlinks resolved at each component
 *	if (flags&PATH_DOTDOT) then each .. checked for access
 *	if (flags&PATH_EXISTS) then path must exist at each component
 *	if (flags&PATH_VERIFIED(n)) then first n chars of path exist
 * 
 * longer pathname possible if (flags&PATH_PHYSICAL) or FS_3D ... involved
 * 0 returned on error and if (flags&(PATH_DOTDOT|PATH_EXISTS)) then path
 * will contain the components following the failure point
 */

#define _AST_API_H	1

#include <ast.h>
#include <ls.h>
#include <fs3d.h>
#include <error.h>

char*
pathcanon(char* path, int flags)
{
	return pathcanon_20100601(path, PATH_MAX, flags);
}

#undef	_AST_API_H

#include <ast_api.h>

char*
pathcanon_20100601(char* path, size_t size, int flags)
{
	register char*	p;
	register char*	r;
	register char*	s;
	register char*	t;
	register int	dots;
	char*		phys;
	char*		v;
	int		loop;
	int		oerrno;
#if defined(FS_3D)
	long		visits = 0;
#endif

	oerrno = errno;
	dots = loop = 0;
	phys = path;
	v = path + ((flags >> 5) & 01777);
	if (!size)
		size = strlen(path) + 1;
	if (*path == '/')
	{
		if (*(path + 1) == '/' && *astconf("PATH_LEADING_SLASHES", NiL, NiL) == '1')
			do path++; while (*path == '/' && *(path + 1) == '/');
		if (!*(path + 1))
			return path + 1;
	}
	p = r = s = t = path;
	for (;;)
		switch (*t++ = *s++)
		{
		case '.':
			dots++;
			break;
		case 0:
			s--;
			/*FALLTHROUGH*/
		case '/':
			while (*s == '/') s++;
			switch (dots)
			{
			case 1:
				t -= 2;
				break;
			case 2:
				if ((flags & (PATH_DOTDOT|PATH_EXISTS)) == PATH_DOTDOT && (t - 2) >= v)
				{
					struct stat	st;

					*(t - 2) = 0;
					if (stat(phys, &st))
					{
						strcpy(path, s);
						return 0;
					}
					*(t - 2) = '.';
				}
#if PRESERVE_TRAILING_SLASH
				if (t - 5 < r) r = t;
#else
				if (t - 5 < r)
				{
					if (t - 4 == r) t = r + 1;
					else r = t;
				}
#endif
				else for (t -= 5; t > r && *(t - 1) != '/'; t--);
				break;
			case 3:
#if defined(FS_3D)
				{
					char*		x;
					char*		o;
					int		c;

					o = t;
					if ((t -= 5) <= path) t = path + 1;
					c = *t;
					*t = 0;
					if (x = pathnext(phys, s - (*s != 0), &visits))
					{
						r = path;
						if (t == r + 1) x = r;
						v = s = t = x;
					}
					else
					{
						*t = c;
						t = o;
					}
				}
#else
				r = t;
#endif
				break;
			default:
				if ((flags & PATH_PHYSICAL) && loop < 32 && (t - 1) > path)
				{
					int	c;
					char	buf[PATH_MAX];

					c = *(t - 1);
					*(t - 1) = 0;
					dots = pathgetlink(phys, buf, sizeof(buf));
					*(t - 1) = c;
					if (dots > 0)
					{
						loop++;
						strcpy(buf + dots, s - (*s != 0));
						if (*buf == '/') p = r = path;
						v = s = t = p;
						strcpy(p, buf);
					}
					else if (dots < 0 && errno == ENOENT)
					{
						if (flags & PATH_EXISTS)
						{
							strcpy(path, s);
							return 0;
						}
						flags &= ~(PATH_PHYSICAL|PATH_DOTDOT);
					}
					dots = 4;
				}
				break;
			}
			if (dots >= 4 && (flags & PATH_EXISTS) && (t - 1) >= v && (t > path + 1 || t > path && *(t - 1) && *(t - 1) != '/'))
			{
				struct stat	st;

				*(t - 1) = 0;
				if (stat(phys, &st))
				{
					strcpy(path, s);
					return 0;
				}
				v = t;
				if (*s) *(t - 1) = '/';
			}
			if (!*s)
			{
				if (t > path && !*(t - 1)) t--;
				if (t == path) *t++ = '.';
#if DONT_PRESERVE_TRAILING_SLASH
				else if (t > path + 1 && *(t - 1) == '/') t--;
#else
				else if ((s <= path || *(s - 1) != '/') && t > path + 1 && *(t - 1) == '/') t--;
#endif
				*t = 0;
				errno = oerrno;
				return t;
			}
			dots = 0;
			p = t;
			break;
		default:
			dots = 4;
			break;
		}
}
