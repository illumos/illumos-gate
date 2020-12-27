/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1997-2012 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 */

#define _DLLINFO_PRIVATE_ \
	char*	sib[3]; \
	char	sibbuf[64]; \
	char	envbuf[64];

#define _DLLSCAN_PRIVATE_ \
	Dllent_t	entry; \
	Uniq_t*		uniq; \
	int		flags; \
	Vmalloc_t*	vm; \
	Dt_t*		dict; \
	Dtdisc_t	disc; \
	FTS*		fts; \
	FTSENT*		ent; \
	Sfio_t*		tmp; \
	char**		sb; \
	char**		sp; \
	char*		pb; \
	char*		pp; \
	char*		pe; \
	int		off; \
	int		prelen; \
	int		suflen; \
	char**		lib; \
	char		nam[64]; \
	char		pat[64]; \
	char		buf[64];

#define DLL_MATCH_DONE		0x8000
#define DLL_MATCH_NAME		0x4000
#define DLL_MATCH_VERSION	0x2000

#include <ast.h>
#include <cdt.h>
#include <ctype.h>
#include <error.h>
#include <fts.h>
#include <vmalloc.h>

typedef struct Uniq_s
{
	Dtlink_t	link;
	char		name[1];
} Uniq_t;

#include <dlldefs.h>

static char		bin[] = "bin";
static char		lib[] = "lib";

/*
 * we need a sibling dir in PATH to search for dlls
 * the confstr LIBPATH provides the local info
 *
 *	<sibling-dir>[:<env-var>[:<host-pattern>]][,...]
 *
 * if <host-pattern> is present then it must match confstr HOSTTYPE
 */

Dllinfo_t*
dllinfo(void)
{
	register char*		s;
	register char*		h;
	char*			d;
	char*			v;
	char*			p;
	int			dn;
	int			vn;
	int			pn;
	char			pat[256];

	static Dllinfo_t	info;

	if (!info.sibling)
	{
		info.sibling = info.sib;
		if (*(s = astconf("LIBPATH", NiL, NiL)))
		{
			while (*s == ':' || *s == ',')
				s++;
			if (*s)
			{
				h = 0;
				for (;;)
				{
					for (d = s; *s && *s != ':' && *s != ','; s++);
					if (!(dn = s - d))
						d = 0;
					if (*s == ':')
					{
						for (v = ++s; *s && *s != ':' && *s != ','; s++);
						if (!(vn = s - v))
							v = 0;
						if (*s == ':')
						{
							for (p = ++s; *s && *s != ':' && *s != ','; s++);
							if (!(pn = s - p))
								p = 0;
						}
						else
							p = 0;
					}
					else
					{
						v = 0;
						p = 0;
					}
					while (*s && *s++ != ',');
					if (!*s || !p || !h && !*(h = astconf("HOSTTYPE", NiL, NiL)))
						break;
					if (pn >= sizeof(pat))
						pn = sizeof(pat) - 1;
					memcpy(pat, p, pn);
					pat[pn] = 0;
					if (strmatch(h, pat))
						break;
				}
				if (d && dn < sizeof(info.sibbuf))
				{
					memcpy(info.sibbuf, d, dn);
					info.sibling[0] = info.sibbuf;
				}
				if (v && vn < sizeof(info.envbuf))
				{
					memcpy(info.envbuf, v, vn);
					info.env = info.envbuf;
				}
			}
		}
		if (!info.sibling[0] || streq(info.sibling[0], bin))
			info.sibling[0] = bin;
		if (!streq(info.sibling[0], lib))
			info.sibling[1] = lib;
		if (!info.env)
			info.env = "LD_LIBRARY_PATH";
		info.prefix = astconf("LIBPREFIX", NiL, NiL);
		info.suffix = astconf("LIBSUFFIX", NiL, NiL);
		if (streq(info.suffix, ".dll"))
			info.flags |= DLL_INFO_PREVER;
		else
			info.flags |= DLL_INFO_DOTVER;
	}
	return &info;
}

/*
 * fts version sort order
 * higher versions appear first
 */

static int
vercmp(FTSENT* const* ap, FTSENT* const* bp)
{
	register unsigned char*	a = (unsigned char*)(*ap)->fts_name;
	register unsigned char*	b = (unsigned char*)(*bp)->fts_name;
	register int		n;
	register int		m;
	char*			e;

	for (;;)
	{
		if (isdigit(*a) && isdigit(*b))
		{
			m = strtol((char*)a, &e, 10);
			a = (unsigned char*)e;
			n = strtol((char*)b, &e, 10);
			b = (unsigned char*)e;
			if (n -= m)
				return n;
		}
		if (n = *a - *b)
			return n;
		if (!*a++)
			return *b ? 0 : -1;
		if (!*b++)
			return 1;
	}
	/*NOTREACHED*/
}

/*
 * open a scan stream
 */

Dllscan_t*
dllsopen(const char* lib, const char* name, const char* version)
{
	register char*	s;
	register char*	t;
	Dllscan_t*	scan;
	Dllinfo_t*	info;
	Vmalloc_t*	vm;
	int		i;
	int		j;
	int		k;
	char		buf[32];

	if (!(vm = vmopen(Vmdcheap, Vmlast, 0)))
		return 0;
	if (lib && *lib && (*lib != '-' || *(lib + 1)))
	{
		/*
		 * grab the local part of the library id
		 */

		if (s = strrchr(lib, ':'))
			lib = (const char*)(s + 1);
		i = 2 * sizeof(char**) + strlen(lib) + 5;
	}
	else
	{
		lib = 0;
		i = 0;
	}
	if (version && (!*version || *version == '-' && !*(version + 1)))
		version = 0;
	if (!(scan = vmnewof(vm, 0, Dllscan_t, 1, i)) || !(scan->tmp = sfstropen()))
	{
		vmclose(vm);
		return 0;
	}
	scan->vm = vm;
	info = dllinfo();
	scan->flags = info->flags;
	if (lib)
	{
		scan->lib = (char**)(scan + 1);
		s = *scan->lib = (char*)(scan->lib + 2);
		sfsprintf(s, i, "lib/%s", lib);
		if (!version && streq(info->suffix, ".dylib"))
			version = "0.0";
	}
	if (!name || !*name || *name == '-' && !*(name + 1))
	{
		name = (const char*)"?*";
		scan->flags |= DLL_MATCH_NAME;
	}
	else if (t = strrchr(name, '/'))
	{
		if (!(scan->pb = vmnewof(vm, 0, char, t - (char*)name, 2)))
			goto bad;
		memcpy(scan->pb, name, t - (char*)name);
		name = (const char*)(t + 1);
	}
	if (name)
	{
		i = strlen(name);
		j = strlen(info->prefix);
		if (!j || i > j && strneq(name, info->prefix, j))
		{
			k = strlen(info->suffix);
			if (i > k && streq(name + i - k, info->suffix))
			{
				i -= j + k;
				if (!(t = vmnewof(vm, 0, char, i, 1)))
					goto bad;
				memcpy(t, name + j, i);
				t[i] = 0;
				name = (const char*)t;
			}
		}
		if (!version)
			for (t = (char*)name; *t; t++)
				if ((*t == '-' || *t == '.' || *t == '?') && isdigit(*(t + 1)))
				{
					if (*t != '-')
						scan->flags |= DLL_MATCH_VERSION;
					version = t + 1;
					if (!(s = vmnewof(vm, 0, char, t - (char*)name, 1)))
						goto bad;
					memcpy(s, name, t - (char*)name);
					name = (const char*)s;
					break;
				}
	}
	if (!version)
	{
		scan->flags |= DLL_MATCH_VERSION;
		sfsprintf(scan->nam, sizeof(scan->nam), "%s%s%s", info->prefix, name, info->suffix);
	}
	else if (scan->flags & DLL_INFO_PREVER)
	{
		sfprintf(scan->tmp, "%s%s", info->prefix, name);
		for (s = (char*)version; *s; s++)
			if (isdigit(*s))
				sfputc(scan->tmp, *s);
		sfprintf(scan->tmp, "%s", info->suffix);
		if (!(s = sfstruse(scan->tmp)))
			goto bad;
		sfsprintf(scan->nam, sizeof(scan->nam), "%s", s);
	}
	else
		sfsprintf(scan->nam, sizeof(scan->nam), "%s%s%s.%s", info->prefix, name, info->suffix, version);
	if (scan->flags & (DLL_MATCH_NAME|DLL_MATCH_VERSION))
	{
		if (scan->flags & DLL_INFO_PREVER)
		{
			if (!version)
				version = "*([0-9_])";
			else
			{
				t = buf;
				for (s = (char*)version; *s; s++)
					if (isdigit(*s) && t < &buf[sizeof(buf)-1])
						*t++ = *s;
				*t = 0;
				version = (const char*)buf;
			}
			sfsprintf(scan->pat, sizeof(scan->pat), "%s%s%s%s", info->prefix, name, version, info->suffix);
		}
		else if (version)
			sfsprintf(scan->pat, sizeof(scan->pat), "%s%s@(%s([-.])%s%s|%s.%s)", info->prefix, name, strchr(version, '.') ? "@" : "?", version, info->suffix, info->suffix, version);
		else
		{
			version = "*([0-9.])";
			sfsprintf(scan->pat, sizeof(scan->pat), "%s%s@(?([-.])%s%s|%s%s)", info->prefix, name, version, info->suffix, info->suffix, version);
		}
	}
	scan->sp = scan->sb = (scan->lib ? scan->lib : info->sibling);
	scan->prelen = strlen(info->prefix);
	scan->suflen = strlen(info->suffix);
	return scan;
 bad:
	dllsclose(scan);
	return 0;
}

/*
 * close a scan stream
 */

int
dllsclose(Dllscan_t* scan)
{
	if (!scan)
		return -1;
	if (scan->fts)
		fts_close(scan->fts);
	if (scan->dict)
		dtclose(scan->dict);
	if (scan->tmp)
		sfclose(scan->tmp);
	if (scan->vm)
		vmclose(scan->vm);
	return 0;
}

/*
 * return the next scan stream entry
 */

Dllent_t*
dllsread(register Dllscan_t* scan)
{
	register char*		p;
	register char*		b;
	register char*		t;
	register Uniq_t*	u;
	register int		n;
	register int		m;

	if (scan->flags & DLL_MATCH_DONE)
		return 0;
 again:
	do
	{
		while (!scan->ent || !(scan->ent = scan->ent->fts_link))
		{
			if (scan->fts)
			{
				fts_close(scan->fts);
				scan->fts = 0;
			}
			if (!scan->pb)
				scan->pb = pathbin();
			else if (!*scan->sp)
			{
				scan->sp = scan->sb;
				if (!*scan->pe++)
					return 0;
				scan->pb = scan->pe;
			}
			for (p = scan->pp = scan->pb; *p && *p != ':'; p++)
				if (*p == '/')
					scan->pp = p;
			scan->pe = p;
			if (*scan->sp == bin)
				scan->off = sfprintf(scan->tmp, "%-.*s", scan->pe - scan->pb, scan->pb);
			else
				scan->off = sfprintf(scan->tmp, "%-.*s/%s", scan->pp - scan->pb, scan->pb, *scan->sp);
			scan->sp++;
			if (!(scan->flags & DLL_MATCH_NAME))
			{
				sfprintf(scan->tmp, "/%s", scan->nam);
				if (!(p = sfstruse(scan->tmp)))
					return 0;
				if (!eaccess(p, R_OK))
				{
					b = scan->nam;
					goto found;
				}
				if (errno != ENOENT)
					continue;
			}
			if (scan->flags & (DLL_MATCH_NAME|DLL_MATCH_VERSION))
			{
				sfstrseek(scan->tmp, scan->off, SEEK_SET);
				if (!(t = sfstruse(scan->tmp)))
					return 0;
				if ((scan->fts = fts_open((char**)t, FTS_LOGICAL|FTS_NOPOSTORDER|FTS_ONEPATH, vercmp)) && (scan->ent = fts_read(scan->fts)) && (scan->ent = fts_children(scan->fts, FTS_NOSTAT)))
					break;
			}
		}
	} while (!strmatch(scan->ent->fts_name, scan->pat));
	b = scan->ent->fts_name;
	sfstrseek(scan->tmp, scan->off, SEEK_SET);
	sfprintf(scan->tmp, "/%s", b);
	if (!(p = sfstruse(scan->tmp)))
		return 0;
 found:
	b = scan->buf + sfsprintf(scan->buf, sizeof(scan->buf), "%s", b + scan->prelen);
	if (!(scan->flags & DLL_INFO_PREVER))
		while (b > scan->buf)
		{
			if (!isdigit(*(b - 1)) && *(b - 1) != '.')
				break;
			b--;
		}
	b -= scan->suflen;
	if (b > (scan->buf + 2) && (*(b - 1) == 'g' || *(b - 1) == 'O') && *(b - 2) == '-')
		b -= 2;
	n = m = 0;
	for (t = b; t > scan->buf; t--)
		if (isdigit(*(t - 1)))
			n = 1;
		else if (*(t - 1) != m)
		{
			if (*(t - 1) == '.' || *(t - 1) == '-' || *(t - 1) == '_')
			{
				n = 1;
				if (m)
				{
					m = -1;
					t--;
					break;
				}
				m = *(t - 1);
			}
			else
				break;
		}
	if (n)
	{
		if (isdigit(t[0]) && isdigit(t[1]) && !isdigit(t[2]))
			n = (t[0] - '0') * 10 + (t[1] - '0');
		else if (isdigit(t[1]) && isdigit(t[2]) && !isdigit(t[3]))
			n = (t[1] - '0') * 10 + (t[2] - '0');
		else
			n = 0;
		if (n && !(n & (n - 1)))
		{
			if (!isdigit(t[0]))
				t++;
			m = *(t += 2);
		}
		if (m || (scan->flags & DLL_INFO_PREVER))
			b = t;
	}
	*b = 0;
	if (!*(b = scan->buf))
		goto again;
	if (scan->uniq)
	{
		if (!scan->dict)
		{
			scan->disc.key = offsetof(Uniq_t, name);
			scan->disc.size = 0;
			scan->disc.link = offsetof(Uniq_t, link);
			if (!(scan->dict = dtopen(&scan->disc, Dtset)))
				return 0;
			dtinsert(scan->dict, scan->uniq);
		}
		if (dtmatch(scan->dict, b))
			goto again;
		if (!(u = vmnewof(scan->vm, 0, Uniq_t, 1, strlen(b))))
			return 0;
		strcpy(u->name, b);
		dtinsert(scan->dict, u);
	}
	else if (!(scan->flags & DLL_MATCH_NAME))
		scan->flags |= DLL_MATCH_DONE;
	else if (!(scan->uniq = vmnewof(scan->vm, 0, Uniq_t, 1, strlen(b))))
		return 0;
	else
		strcpy(scan->uniq->name, b);
	scan->entry.name = b;
	scan->entry.path = p;
	errorf("dll", NiL, -1, "dllsread: %s bound to %s", b, p);
	return &scan->entry;
}
