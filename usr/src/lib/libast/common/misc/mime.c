/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
 * Glenn Fowler
 * AT&T Research
 *
 * mime/mailcap support library
 */

static const char id[] = "\n@(#)$Id: mime library (AT&T Research) 2002-10-29 $\0\n";

static const char lib[] = "libast:mime";

#include "mimelib.h"

typedef struct Att_s
{
	struct Att_s*	next;
	char*		name;
	char*		value;
} Att_t;

typedef struct Cap_s
{
	struct Cap_s*	next;
	unsigned long	flags;
	Att_t		att;
	char*		test;
	char		data[1];
} Cap_t;

typedef struct
{
	Dtlink_t	link;
	Cap_t*		cap;
	Cap_t*		pac;
	char		name[1];
} Ent_t;

typedef struct
{
	char*		data;
	int		size;
} String_t;

typedef struct
{
	char*		next;
	String_t	name;
	String_t	value;
} Parse_t;

typedef struct
{
	const char*	pattern;
	int		prefix;
	Sfio_t*		fp;
	int		hit;
} Walk_t;

/*
 * convert c to lower case
 */

static int
lower(register int c)
{
	return isupper(c) ? tolower(c) : c;
}

/*
 * Ent_t case insensitive comparf
 */

static int
order(Dt_t* dt, void* a, void* b, Dtdisc_t* disc)
{
	return strcasecmp(a, b);
}

/*
 * Cap_t free
 */

static void
dropcap(register Cap_t* cap)
{
	register Att_t*	att;

	while (att = cap->att.next)
	{
		cap->att.next = att->next;
		free(att);
	}
	free(cap);
}

/*
 * Ent_t freef
 */

static void
drop(Dt_t* dt, void* object, Dtdisc_t* disc)
{
	register Ent_t*	ent = (Ent_t*)object;
	register Cap_t*	cap;

	while (cap = ent->cap)
	{
		ent->cap = cap->next;
		dropcap(cap);
	}
	free(ent);
}

/*
 * add mime type entry in s to mp
 */

int
mimeset(Mime_t* mp, register char* s, unsigned long flags)
{
	register Ent_t*	ent;
	register Cap_t*	cap;
	register Att_t*	att;
	register char*	t;
	register char*	v;
	register char*	k;
	char*		x;
	Att_t*		tta;
	int		q;

	for (; isspace(*s); s++);
	if (*s && *s != '#')
	{
		cap = 0;
		for (v = s; *v && *v != ';'; v++)
			if (isspace(*v) || *v == '/' && *(v + 1) == '*')
				*v = 0;
		if (*v)
		{
			*v++ = 0;
			do
			{
				for (; isspace(*v); v++);
				if (cap)
				{
					for (t = v; *t && !isspace(*t) && *t != '='; t++);
					for (k = t; isspace(*t); t++);
					if (!*t || *t == '=' || *t == ';')
					{
						if (*t)
							while (isspace(*++t));
						*k = 0;
						k = v;
						v = t;
					}
					else
						k = 0;
				}
				if (*v == '"')
					q = *v++;
				else
					q = 0;
				for (t = v; *t; t++)
					if (*t == '\\')
					{
						switch (*(t + 1))
						{
						case 0:
						case '\\':
						case '%':
							*t = *(t + 1);
							break;
						default:
							*t = ' ';
							break;
						}
						if (!*++t)
							break;
					}
					else if (*t == q)
					{
						*t = ' ';
						q = 0;
					}
					else if (*t == ';' && !q)
					{
						*t = ' ';
						break;
					}
				for (; t > v && isspace(*(t - 1)); t--);
				if (t <= v && (!cap || !k))
					break;
				if (!cap)
				{
					if (!(cap = newof(0, Cap_t, 1, strlen(v) + 1)))
						return -1;
					if (*t)
						*t++ = 0;
					tta = &cap->att;
					tta->name = "default";
					x = strcopy(tta->value = cap->data, v) + 1;
				}
				else if (k)
				{
					if (*t)
						*t++ = 0;
					if (!(att = newof(0, Att_t, 1, 0)))
						return -1;
					x = strcopy(att->name = x, k) + 1;
					x = strcopy(att->value = x, v) + 1;
					tta = tta->next = att;
					if (!strcasecmp(k, "test"))
						cap->test = att->value;
				}
			} while (*(v = t));
		}
		ent = (Ent_t*)dtmatch(mp->cap, s);
		if (cap)
		{
			if (ent)
			{
				register Cap_t*	dup;
				register Cap_t*	pud;

				for (pud = 0, dup = ent->cap; dup; pud = dup, dup = dup->next)
					if (!cap->test && !dup->test || cap->test && dup->test && streq(cap->test, dup->test))
					{
						if (flags & MIME_REPLACE)
						{
							if (pud)
								pud->next = cap;
							else
								ent->cap = cap;
							if (!(cap->next = dup->next))
								ent->pac = cap;
							cap = dup;
						}
						dropcap(cap);
						return 0;
					}
				ent->pac = ent->pac->next = cap;
			}
			else if (!(ent = newof(0, Ent_t, 1, strlen(s) + 1)))
				return -1;
			else
			{
				strcpy(ent->name, s);
				ent->cap = ent->pac = cap;
				dtinsert(mp->cap, ent);
			}
		}
		else if (ent && (flags & MIME_REPLACE))
			dtdelete(mp->cap, ent);
	}
	return 0;
}

/*
 * load mime type files into mp
 */

int
mimeload(Mime_t* mp, const char* file, unsigned long flags)
{
	register char*	s;
	register char*	t;
	register char*	e;
	register int	n;
	Sfio_t*		fp;

	if (!(s = (char*)file))
	{
		flags |= MIME_LIST;
		if (!(s = getenv(MIME_FILES_ENV)))
			s = MIME_FILES;
	}
	for (;;)
	{
		if (!(flags & MIME_LIST))
			e = 0;
		else if (e = strchr(s, ':'))
		{
			/*
			 * ok, so ~ won't work for the last list element
			 * we do it for MIME_FILES_ENV anyway
			 */

			if ((strneq(s, "~/", n = 2) || strneq(s, "$HOME/", n = 6) || strneq(s, "${HOME}/", n = 8)) && (t = getenv("HOME")))
			{
				sfputr(mp->buf, t, -1);
				s += n - 1;
			}
			sfwrite(mp->buf, s, e - s);
			if (!(s = sfstruse(mp->buf)))
				return -1;
		}
		if (fp = tokline(s, SF_READ, NiL))
		{
			while (t = sfgetr(fp, '\n', 1))
				if (mimeset(mp, t, flags))
					break;
			sfclose(fp);
		}
		else if (!(flags & MIME_LIST))
			return -1;
		if (!e)
			break;
		s = e + 1;
	}
	return 0;
}

/*
 * mimelist walker
 */

static int
list(Dt_t* dt, void* object, void* context)
{
	register Walk_t*	wp = (Walk_t*)context;
	register Ent_t*		ent = (Ent_t*)object;
	register Cap_t*		cap;
	register Att_t*		att;

	if (!wp->pattern || !strncasecmp(ent->name, wp->pattern, wp->prefix) && (!ent->name[wp->prefix] || ent->name[wp->prefix] == '/'))
	{
		wp->hit++;
		for (cap = ent->cap; cap; cap = cap->next)
		{
			sfprintf(wp->fp, "%s", ent->name);
			for (att = &cap->att; att; att = att->next)
			{
				sfprintf(wp->fp, "\n\t");
				if (att != &cap->att)
				{
					sfprintf(wp->fp, "%s", att->name);
					if (*att->value)
						sfprintf(wp->fp, " = ");
				}
				sfputr(wp->fp, att->value, -1);
			}
			sfprintf(wp->fp, "\n");
		}
	}
	return 0;
}

/*
 * find entry matching type
 * if exact match fails then left and right x- and right version number
 * permutations are attempted
 */

static Ent_t*
find(Mime_t* mp, const char* type)
{
	register char*	lp;
	register char*	rp;
	register char*	rb;
	register char*	rv;
	register int	rc;
	register int	i;
	char*		s;
	Ent_t*		ent;
	char		buf[256];

	static const char*	prefix[] = { "", "", "x-", "x-", "" };

	if ((ent = (Ent_t*)dtmatch(mp->cap, type)) ||
	    !(rp = strchr(lp = (char*)type, '/')) ||
	    strlen(lp) >= sizeof(buf))
		return ent;
	strcpy(buf, type);
	rp = buf + (rp - lp);
	*rp++ = 0;
	if (*rp == 'x' && *(rp + 1) == '-')
		rp += 2;
	lp = buf;
	if (*lp == 'x' && *(lp + 1) == '-')
		lp += 2;
	rb = rp;
	for (rv = rp + strlen(rp); rv > rp && (isdigit(*(rv - 1)) || *(rv - 1) == '.'); rv--);
	rc = *rv;
	do
	{
		rp = rb;
		do
		{
			for (i = 0; i < elementsof(prefix) - 1; i++)
			{
				sfprintf(mp->buf, "%s%s/%s%s", prefix[i], lp, prefix[i + 1], rp);
				if (!(s = sfstruse(mp->buf)))
					return 0;
				if (ent = (Ent_t*)dtmatch(mp->cap, s))
					return ent;
				if (rc)
				{
					*rv = 0;
					sfprintf(mp->buf, "%s%s/%s%s", prefix[i], lp, prefix[i + 1], rp);
					if (!(s = sfstruse(mp->buf)))
						return 0;
					if (ent = (Ent_t*)dtmatch(mp->cap, s))
						return ent;
					*rv = rc;
				}
			}
			while (*rp && *rp++ != '-');
		} while (*rp);
		while (*lp && *lp++ != '-');
	} while (*lp);
	return (Ent_t*)dtmatch(mp->cap, buf);
}

/*
 * list mime <type,data> for pat on fp
 */

int
mimelist(Mime_t* mp, Sfio_t* fp, register const char* pattern)
{
	Ent_t*	ent;
	Walk_t	ws;

	ws.fp = fp;
	ws.hit = 0;
	ws.prefix = 0;
	if (ws.pattern = pattern)
	{
		while (*pattern && *pattern++ != '/');
		if (!*pattern || *pattern == '*' && !*(pattern + 1))
			ws.prefix = pattern - ws.pattern;
		else if (ent = find(mp, ws.pattern))
		{
			ws.pattern = 0;
			list(mp->cap, ent, &ws);
			return ws.hit;
		}
	}
	dtwalk(mp->cap, list, &ws);
	return ws.hit;
}

/*
 * get next arg in pp
 * 0 returned if no more args
 */

static int
arg(register Parse_t* pp, int first)
{
	register char*	s;
	register int	c;
	register int	q;
	int		x;

	for (s = pp->next; isspace(*s) && *s != '\n'; s++);
	if (!*s || *s == '\n')
	{
		pp->next = s;
		return 0;
	}
	pp->name.data = s;
	pp->value.data = 0;
	q = 0;
	x = 0;
	while ((c = *s++) && c != ';' && c != '\n')
	{
		if (c == '"')
		{
			q = 1;
			if (pp->value.data)
			{
				pp->value.data = s;
				if (x)
					x = -1;
				else
					x = 1;
			}
			else if (!x && pp->name.data == (s - 1))
			{
				x = 1;
				pp->name.data = s;
			}
			do
			{
				if (!(c = *s++) || c == '\n')
				{
					s--;
					break;
				}
			} while (c != '"');
			if (first < 0 || x > 0)
			{
				c = ';';
				break;
			}
 		}
		else if (c == '=' && !first)
		{
			first = 1;
			pp->name.size = s - pp->name.data - 1;
			pp->value.data = s;
		}
		else if (first >= 0 && isspace(c))
			break;
	}
	pp->next = s - (c != ';');
	if (first >= 0 || !q)
		for (s--; s > pp->name.data && isspace(*(s - 1)); s--);
	if (pp->value.data)
		pp->value.size = s - pp->value.data - (q && first < 0);
	else
	{
		pp->value.size = 0;
		pp->name.size = s - pp->name.data - (q && first < 0);
	}
	if (first >= 0 && pp->name.size > 0 && pp->name.data[pp->name.size - 1] == ':')
		return 0;
	return pp->name.size > 0;
}

/*
 * low level for mimeview()
 */

static char*
expand(Mime_t* mp, register char* s, const char* name, const char* type, const char* opts)
{
	register char*	t;
	register int	c;
	Parse_t		pp;

	mp->disc->flags |= MIME_PIPE;
	for (;;)
	{
		switch (c = *s++)
		{
		case 0:
		case '\n':
			break;
		case '%':
			switch (c = *s++)
			{
			case 's':
				sfputr(mp->buf, (char*)name, -1);
				mp->disc->flags &= ~MIME_PIPE;
				continue;
			case 't':
				sfputr(mp->buf, (char*)type, -1);
				continue;
			case '{':
				for (t = s; *s && *s != '}'; s++);
				if (*s && (c = s++ - t) && (pp.next = (char*)opts))
					while (arg(&pp, 0))
						if (pp.name.size == c && !strncasecmp(pp.name.data, t, c))
						{
							if (pp.value.size)
								sfwrite(mp->buf, pp.value.data, pp.value.size);
							break;
						}
				continue;
			}
			/*FALLTHROUGH*/
		default:
			sfputc(mp->buf, c);
			continue;
		}
		break;
	}
	return sfstruse(mp->buf);
}

/*
 * return expanded command/path/value for <view,name,type,opts>
 * return value valid until next mime*() call
 */

char*
mimeview(Mime_t* mp, const char* view, const char* name, const char* type, const char* opts)
{
	register Ent_t*	ent;
	register Cap_t*	cap;
	register Att_t*	att;
	register char*	s;
	int		c;

	if (ent = find(mp, type))
	{
		cap = ent->cap;
		if (!view || strcasecmp(view, "test"))
			while (s = cap->test)
			{
				if (s = expand(mp, s, name, type, opts))
				{
					Parse_t	a1;
					Parse_t	a2;
					Parse_t	a3;
					Parse_t	a4;

					/*
					 * try to do a few common cases here
					 * mailcap consistency is a winning
					 * strategy
					 */

					a1.next = s;
					if (arg(&a1, -1))
					{
						if ((c = *a1.name.data == '!') && --a1.name.size <= 0 && !arg(&a1, -1))
							goto lose;
						if (a1.name.size == 6 && strneq(a1.name.data, "strcmp", 6) || a1.name.size == 10 && strneq(a1.name.data, "strcasecmp", 10))
						{
							a2.next = a1.next;
							if (!arg(&a2, -1))
								goto lose;
							a3.next = a2.next;
							if (!arg(&a3, -1))
								goto lose;
							if (a2.name.size != a3.name.size)
								c ^= 0;
							else c ^= (a1.name.size == 6 ? strncmp : strncasecmp)(a2.name.data, a3.name.data, a2.name.size) == 0;
							if (c)
								break;
							goto skip;
						}
						else if (a1.name.size == 4 && strneq(a1.name.data, "test", 4))
						{
							if (!arg(&a1, -1))
								goto lose;
							a2.next = a1.next;
							if (!arg(&a2, -1) || a2.name.size > 2 || a2.name.size == 1 && *a2.name.data != '=' || a2.name.size == 2 && (!strneq(a1.name.data, "!=", 2) || !strneq(a2.name.data, "==", 2)))
								goto lose;
							a3.next = a2.next;
							if (!arg(&a3, -1))
								goto lose;
							if (*a3.name.data == '`' && *(a3.name.data + a3.name.size - 1) == '`')
							{
								a4 = a3;
								a3 = a1;
								a1 = a4;
							}
							if (*a1.name.data == '`' && *(a1.name.data + a1.name.size - 1) == '`')
							{
								a1.next = a1.name.data + 1;
								if (!arg(&a1, -1) || a1.name.size != 4 || !strneq(a1.name.data, "echo", 4) || !arg(&a1, -1))
									goto lose;
								a4.next = a1.next;
								if (!arg(&a4, 1) || a4.name.size < 21 || !strneq(a4.name.data, "| tr '[A-Z]' '[a-z]'`", 21))
									goto lose;
							}
							else
								a4.name.size = 0;
							c = *a2.name.data == '!';
							if (a1.name.size != a3.name.size)
								c ^= 0;
							else c ^= (a4.name.size ? strncasecmp : strncmp)(a1.name.data, a3.name.data, a1.name.size) == 0;
							if (c)
								break;
							goto skip;
						}
					}
				lose:
					if (!system(s))
						break;
				}
			skip:
				if (!(cap = cap->next))
					return 0;
			}
		att = &cap->att;
		if (view && *view && !streq(view, "-"))
			while (strcasecmp(view, att->name))
				if (!(att = att->next))
					return 0;
		return expand(mp, att->value, name, type, opts);
	}
	return 0;
}

/*
 * lower case identifier prefix strcmp
 * if e!=0 then it will point to the next char after the match
 */

int
mimecmp(register const char* s, register const char* v, char** e)
{
	register int	n;

	while (isalnum(*v) || *v == *s && (*v == '_' || *v == '-' || *v == '/'))
		if (n = lower(*s++) - lower(*v++))
			return n;
	if (!isalnum(*s) && *s != '_' && *s != '-')
	{
		if (e)
			*e = (char*)s;
		return 0;
	}
	return lower(*s) - lower(*v);
}

/*
 * parse mime headers in strsearch(tab,num,siz) from s
 * return >0 if mime header consumed
 */

int
mimehead(Mime_t* mp, void* tab, size_t num, size_t siz, register char* s)
{
	register void*	p;
	char*		e;
	Parse_t		pp;
	Mimevalue_f	set;

	set = mp->disc->valuef;
	if (!strncasecmp(s, "original-", 9))
		s += 9;
	if (!strncasecmp(s, "content-", 8))
	{
		s += 8;
		if ((p = strsearch(tab, num, siz, (Strcmp_f)mimecmp, s, &e)) && *e == ':')
		{
			pp.next = e + 1;
			if (arg(&pp, 1))
			{
				if ((*set)(mp, p, pp.name.data, pp.name.size, mp->disc))
					return 0;
				while (arg(&pp, 0))
					if (pp.value.size &&
					    (p = strsearch(tab, num, siz, (Strcmp_f)mimecmp, pp.name.data, &e)) &&
					    (*set)(mp, p, pp.value.data, pp.value.size, mp->disc))
						return 0;
				return 1;
			}
		}
		else if (strchr(s, ':'))
			return 1;
	}
	return !strncasecmp(s, "x-", 2);
}

/*
 * open a mime library handle
 */

Mime_t*
mimeopen(Mimedisc_t* disc)
{
	register Mime_t*	mp;

	if (!(mp = newof(0, Mime_t, 1, 0)))
		return 0;
	mp->id = lib;
	mp->disc = disc;
	mp->dict.key = offsetof(Ent_t, name);
	mp->dict.comparf = order;
	mp->dict.freef = drop;
	if (!(mp->buf = sfstropen()) || !(mp->cap = dtopen(&mp->dict, Dtorder)))
	{
		mimeclose(mp);
		return 0;
	}
	return mp;
}

/*
 * close a mimeopen() handle
 */

int
mimeclose(Mime_t* mp)
{
	if (mp)
	{
		if (mp->buf)
			sfclose(mp->buf);
		if (mp->cap)
			dtclose(mp->cap);
		if (mp->freef)
			(*mp->freef)(mp);
		free(mp);
	}
	return 0;
}
