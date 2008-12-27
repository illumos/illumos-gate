/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
 * AT&T Research
 *
 * generate a temp file / name
 *
 *	[<dir>/][<pfx>]<bas>.<suf>
 *
 * length(<pfx>)<=5
 * length(<bas>)==3
 * length(<suf>)==3
 *
 *	pathtmp(a,b,c,d)	pathtemp(a,L_tmpnam,b,c,0)
 *	tmpfile()		char*p=pathtemp(0,0,0,"tf",&sp);
 *				remove(p);
 *				free(p)
 *	tmpnam(0)		static char p[L_tmpnam];
 *				pathtemp(p,sizeof(p),0,"tn",0)
 *	tmpnam(p)		pathtemp(p,L_tmpnam,0,"tn",0)
 *	tempnam(d,p)		pathtemp(0,d,p,0)
 *
 * if buf==0 then space is malloc'd
 * buf size is size
 * dir and pfx may be 0
 * only first 5 chars of pfx are used
 * if fdp!=0 then the path is opened O_EXCL and *fdp is the open fd
 * malloc'd space returned by successful pathtemp() calls
 * must be freed by the caller
 *
 * generated names are pseudo-randomized to avoid both
 * collisions and predictions (same alg in sfio/sftmp.c)
 *
 * / as first pfx char provides tmp file generation control
 * 0 returned for unknown ops
 *
 *	/cycle		dir specifies TMPPATH cycle control
 *		automatic	(default) cycled with each tmp file
 *		manual		cycled by application with dir=(nil)
 *		(nil)		cycle TMPPATH
 *	/prefix		dir specifies the default prefix (default ast)
 *	/TMPPATH	dir overrides the env value
 *	/TMPDIR		dir overrides the env value
 */

#include <ast.h>
#include <ls.h>
#include <tm.h>

#define ATTEMPT		10

#define TMP_ENV		"TMPDIR"
#define TMP_PATH_ENV	"TMPPATH"
#define TMP1		"/tmp"
#define TMP2		"/usr/tmp"

#define VALID(d)	(*(d)&&!eaccess(d,W_OK|X_OK))

static struct
{
	mode_t		mode;
	char**		vec;
	char**		dir;
	unsigned long	key;
	unsigned long	rng;
	pid_t		pid;
	int		manual;
	char*		pfx;
	char*		tmpdir;
	char*		tmppath;
} tmp = { S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH };

char*
pathtemp(char* buf, size_t len, const char* dir, const char* pfx, int* fdp)
{
	register char*		d;
	register char*		b;
	register char*		s;
	register char*		x;
	char*			fmt;
	int			m;
	int			n;
	int			z;
	int			attempt;

	if (pfx && *pfx == '/')
	{
		pfx++;
		if (streq(pfx, "cycle"))
		{
			if (!dir)
			{
				tmp.manual = 1;
				if (tmp.dir && !*tmp.dir++)
					tmp.dir = tmp.vec;
			}
			else
				tmp.manual = streq(dir, "manual");
			return (char*)pfx;
		}
		else if (streq(pfx, "prefix"))
		{
			if (tmp.pfx)
				free(tmp.pfx);
			tmp.pfx = dir ? strdup(dir) : (char*)0;
			return (char*)pfx;
		}
		else if (streq(pfx, "private"))
			tmp.mode = S_IRUSR|S_IWUSR;
		else if (streq(pfx, "public"))
			tmp.mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
		else if (streq(pfx, TMP_ENV))
		{
			if (tmp.vec)
			{
				free(tmp.vec);
				tmp.vec = 0;
			}
			if (tmp.tmpdir)
				free(tmp.tmpdir);
			tmp.tmpdir = dir ? strdup(dir) : (char*)0;
			return (char*)pfx;
		}
		else if (streq(pfx, TMP_PATH_ENV))
		{
			if (tmp.vec)
			{
				free(tmp.vec);
				tmp.vec = 0;
			}
			if (tmp.tmppath)
				free(tmp.tmppath);
			tmp.tmppath = dir ? strdup(dir) : (char*)0;
			return (char*)pfx;
		}
		return 0;
	}
	if (!(d = (char*)dir) || *d && eaccess(d, W_OK|X_OK))
	{
		if (!tmp.vec)
		{
			if ((x = tmp.tmppath) || (x = getenv(TMP_PATH_ENV)))
			{
				n = 2;
				s = x;
				while (s = strchr(s, ':'))
				{
					s++;
					n++;
				}
				if (!(tmp.vec = newof(0, char*, n, strlen(x) + 1)))
					return 0;
				tmp.dir = tmp.vec;
				x = strcpy((char*)(tmp.dir + n), x);
				*tmp.dir++ = x;
				while (x = strchr(x, ':'))
				{
					*x++ = 0;
					if (!VALID(*(tmp.dir - 1)))
						tmp.dir--;
					*tmp.dir++ = x;
				}
				if (!VALID(*(tmp.dir - 1)))
					tmp.dir--;
				*tmp.dir = 0;
			}
			else
			{
				if (((d = tmp.tmpdir) || (d = getenv(TMP_ENV))) && !VALID(d))
					d = 0;
				if (!(tmp.vec = newof(0, char*, 2, d ? (strlen(d) + 1) : 0)))
					return 0;
				if (d)
					*tmp.vec = strcpy((char*)(tmp.vec + 2), d);
			}
			tmp.dir = tmp.vec;
		}
		if (!(d = *tmp.dir++))
		{
			tmp.dir = tmp.vec;
			d = *tmp.dir++;
		}
		if (!d && (!*(d = astconf("TMP", NiL, NiL)) || eaccess(d, W_OK|X_OK)) && eaccess(d = TMP1, W_OK|X_OK) && eaccess(d = TMP2, W_OK|X_OK))
			return 0;
	}
	if (!len)
		len = PATH_MAX;
	len--;
	if (!(b = buf) && !(b = newof(0, char, len, 1)))
		return 0;
	if (buf && dir && pfx && (buf == (char*)dir && (buf + strlen(buf) + 1) == (char*)pfx || buf == (char*)pfx && !*dir) && !strcmp((char*)pfx + strlen(pfx) + 1, "XXXXX"))
	{
		z = 0;
		d = (char*)dir;
		len = m = strlen(d) + strlen(pfx) + 8;
		fmt = "%03.3.32lu%03.3.32lu";
	}
	else
	{
		z = '.';
		m = 5;
		fmt = "%02.2.32lu.%03.3.32lu";
	}
	x = b + len;
	s = b;
	if (d)
	{
		while (s < x && (n = *d++))
			*s++ = n;
		if (s < x && s > b && *(s - 1) != '/')
			*s++ = '/';
	}
	if (!pfx && !(pfx = tmp.pfx))
		pfx = "ast";
	if ((x - s) > m)
		x = s + m;
	while (s < x && (n = *pfx++))
	{
		if (n == '/' || n == '\\' || n == z)
			n = '_';
		*s++ = n;
	}
	*s = 0;
	len -= (s - b);
	for (attempt = 0; attempt < ATTEMPT; attempt++)
	{
		if (!tmp.rng || attempt || tmp.pid != getpid())
		{	
			register int	r;

			/*
			 * get a quasi-random coefficient
			 */

			tmp.pid = getpid();
			tmp.rng = (unsigned long)tmp.pid * ((unsigned long)time(NiL) ^ (((unsigned long)(&attempt)) >> 3) ^ (((unsigned long)tmp.dir) >> 3));
			if (!tmp.key)
				tmp.key = (tmp.rng >> 16) | ((tmp.rng & 0xffff) << 16);
			tmp.rng ^= tmp.key;

			/*
			 * Knuth vol.2, page.16, Thm.A
			 */

			if ((r = (tmp.rng - 1) & 03))
				tmp.rng += 4 - r;
		}

		/*
		 * generate a pseudo-random name
		 */

		tmp.key = tmp.rng * tmp.key + 987654321L;
		sfsprintf(s, len, fmt, (tmp.key >> 15) & 0x7fff, tmp.key & 0x7fff);
		if (fdp)
		{
			if ((n = open(b, O_CREAT|O_RDWR|O_EXCL|O_TEMPORARY, tmp.mode)) >= 0)
			{
				*fdp = n;
				return b;
			}
		}
		else if (access(b, F_OK))
			return b;
	}
	if (!buf)
		free(b);
	return 0;
}
