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

/*
 * Glenn Fowler
 * AT&T Research
 *
 * keyword printf support
 */

#include <ast.h>
#include <ccode.h>
#include <ctype.h>
#include <sfdisc.h>
#include <regex.h>

#define FMT_case	1
#define FMT_edit	2

typedef struct
{
	Sffmt_t			fmt;
	void*			handle;
	Sf_key_lookup_t		lookup;
	Sf_key_convert_t	convert;
	Sfio_t*			tmp[2];
	regex_t			red[2];
	regex_t*		re[2];
	int			invisible;
	int			level;
	int			version;
} Fmt_t;

typedef struct
{
	char*			next;
	int			delimiter;
	int			first;
} Field_t;

typedef union
{
	char**			p;
	char*			s;
	Sflong_t		q;
	long			l;
	int			i;
	short			h;
	char			c;
} Value_t;

#define initfield(f,s)	((f)->first = (f)->delimiter = *((f)->next = (s)))

static char*
getfield(register Field_t* f, int restore)
{
	register char*	s;
	register int	n;
	register int	c;
	register int	lp;
	register int	rp;
	char*		b;

	if (!f->delimiter)
		return 0;
	s = f->next;
	if (f->first)
		f->first = 0;
	else if (restore)
		*s = f->delimiter;
	b = ++s;
	lp = rp = n = 0;
	for (;;)
	{
		if (!(c = *s++))
		{
			f->delimiter = 0;
			break;
		}
		else if (c == CC_esc || c == '\\')
		{
			if (*s)
				s++;
		}
		else if (c == lp)
			n++;
		else if (c == rp)
			n--;
		else if (n <= 0)
		{
			if (c == '(' && restore)
			{
				lp = '(';
				rp = ')';
				n = 1;
			}
			else if (c == '[' && restore)
			{
				lp = '[';
				rp = ']';
				n = 1;
			}
			else if (c == f->delimiter)
			{
				*(f->next = --s) = 0;
				break;
			}
		}
	}
	return b;
}

/*
 * sfio %! extension function
 */

static int
getfmt(Sfio_t* sp, void* vp, Sffmt_t* dp)
{
	register Fmt_t*	fp = (Fmt_t*)dp;
	Value_t*	value = (Value_t*)vp;
	register char*	v;
	char*		t;
	char*		b;
	char*		a = 0;
	char*		s = 0;
	Sflong_t	n = 0;
	int		h = 0;
	int		i = 0;
	int		x = 0;
	int		d;
	Field_t		f;
	regmatch_t	match[10];

	fp->level++;
	if (fp->fmt.t_str && fp->fmt.n_str > 0 && (v = fmtbuf(fp->fmt.n_str + 1)))
	{
		memcpy(v, fp->fmt.t_str, fp->fmt.n_str);
		v[fp->fmt.n_str] = 0;
		b = v;
		for (;;)
		{
			switch (*v++)
			{
			case 0:
				break;
			case '(':
				h++;
				continue;
			case ')':
				h--;
				continue;
			case '=':
			case ':':
			case ',':
				if (h <= 0)
				{
					a = v;
					break;
				}
				continue;
			default:
				continue;
			}
			if (i = *--v)
			{
				*v = 0;
				if (i == ':' && fp->fmt.fmt == 's' && strlen(a) > 4 && !isalnum(*(a + 4)))
				{
					d = *(a + 4);
					*(a + 4) = 0;
					if (streq(a, "case"))
						x = FMT_case;
					else if (streq(a, "edit"))
						x = FMT_edit;
					*(a + 4) = d;
					if (x)
						a = 0;
				}
			}
			break;
		}
		n = i;
		t = fp->fmt.t_str;
		fp->fmt.t_str = b;
		h = (*fp->lookup)(fp->handle, &fp->fmt, a, &s, &n);
		fp->fmt.t_str = t;
		if (i)
			*v++ = i;
	}
	else
	{
		h = (*fp->lookup)(fp->handle, &fp->fmt, a, &s, &n);
		v = 0;
	}
	fp->fmt.flags |= SFFMT_VALUE;
	switch (fp->fmt.fmt)
	{
	case 'c':
		value->c = s ? *s : n;
		break;
	case 'd':
	case 'i':
		fp->fmt.size = sizeof(Sflong_t);
		value->q = (Sflong_t)(s ? strtoll(s, NiL, 0) : n);
		break;
	case 'o':
	case 'u':
	case 'x':
		fp->fmt.size = sizeof(Sflong_t);
		value->q = s ? (Sflong_t)strtoull(s, NiL, 0) : n;
		break;
	case 'p':
		if (s)
			n = strtoll(s, NiL, 0);
		value->p = pointerof(n);
		break;
	case 'q':
		if (s)
		{
			fp->fmt.fmt = 's';
			value->s = fmtquote(s, "$'", "'", strlen(s), 0);
		}
		else
		{
			fp->fmt.fmt = 'd';
			value->q = n;
		}
		break;
	case 's':
		if (!s && (!h || !fp->tmp[1] && !(fp->tmp[1] = sfstropen()) || sfprintf(fp->tmp[1], "%I*d", sizeof(n), n) <= 0 || !(s = sfstruse(fp->tmp[1]))))
			s = "";
		if (x)
		{
			h = 0;
			d = initfield(&f, v + 4);
			switch (x)
			{
			case FMT_case:
				while ((a = getfield(&f, 1)) && (v = getfield(&f, 0)))
				{
					if (strmatch(s, a))
					{
						Fmt_t	fmt;

						fmt = *fp;
						fmt.fmt.form = v;
						for (h = 0; h < elementsof(fmt.tmp); h++)
							fmt.tmp[h] = 0;
						if (!fp->tmp[0] && !(fp->tmp[0] = sfstropen()) || sfprintf(fp->tmp[0], "%!", &fmt) <= 0 || !(s = sfstruse(fp->tmp[0])))
							s = "";
						*(v - 1) = d;
						if (f.delimiter)
							*f.next = d;
						for (h = 0; h < elementsof(fmt.tmp); h++)
							if (fmt.tmp[h])
								sfclose(fmt.tmp[h]);
						h = 1;
						break;
					}
					*(v - 1) = d;
				}
				break;
			case FMT_edit:
				for (x = 0; *f.next; x ^= 1)
				{
					if (fp->re[x])
						regfree(fp->re[x]);
					else
						fp->re[x] = &fp->red[x];
					if (regcomp(fp->re[x], f.next, REG_DELIMITED|REG_NULL))
						break;
					f.next += fp->re[x]->re_npat;
					if (regsubcomp(fp->re[x], f.next, NiL, 0, 0))
						break;
					f.next += fp->re[x]->re_npat;
					if (!regexec(fp->re[x], s, elementsof(match), match, 0) && !regsubexec(fp->re[x], s, elementsof(match), match))
					{
						s = fp->re[x]->re_sub->re_buf;
						if (fp->re[x]->re_sub->re_flags & REG_SUB_STOP)
							break;
					}
				}
				h = 1;
				break;
			}
			if (!h)
				s = "";
		}
		value->s = s;
		if (fp->level == 1)
			while ((s = strchr(s, CC_esc)) && *(s + 1) == '[')
				do fp->invisible++; while (*s && !islower(*s++));
		break;
	case 'Z':
		fp->fmt.fmt = 'c';
		value->c = 0;
		break;
	case '\n':
		value->s = "\n";
		break;
	case '.':
		value->i = n;
		break;
	default:
		if ((!fp->convert || !(value->s = (*fp->convert)(fp->handle, &fp->fmt, a, s, n))) && (!fp->tmp[0] && !(fp->tmp[0] = sfstropen()) || sfprintf(fp->tmp[0], "%%%c", fp->fmt.fmt) <= 0 || !(value->s = sfstruse(fp->tmp[0]))))
			value->s = "";
		break;
	}
	fp->level--;
	return 0;
}

/*
 * this is the original interface
 */

#undef	sfkeyprintf

int
sfkeyprintf(Sfio_t* sp, void* handle, const char* format, Sf_key_lookup_t lookup, Sf_key_convert_t convert)
{
	register int	i;
	int		r;
	Fmt_t		fmt;

	memset(&fmt, 0, sizeof(fmt));
	fmt.fmt.version = SFIO_VERSION;
	fmt.fmt.form = (char*)format;
	fmt.fmt.extf = getfmt;
	fmt.handle = handle;
	fmt.lookup = lookup;
	fmt.convert = convert;
	r = sfprintf(sp, "%!", &fmt) - fmt.invisible;
	for (i = 0; i < elementsof(fmt.tmp); i++)
		if (fmt.tmp[i])
			sfclose(fmt.tmp[i]);
	for (i = 0; i < elementsof(fmt.re); i++)
		if (fmt.re[i])
			regfree(fmt.re[i]);
	return r;
}

#undef	_AST_API_H

#include <ast_api.h>

/*
 * Sffmt_t* callback args
 */

int
sfkeyprintf_20000308(Sfio_t* sp, void* handle, const char* format, Sf_key_lookup_t lookup, Sf_key_convert_t convert)
{
	register int	i;
	int		r;
	Fmt_t		fmt;

	memset(&fmt, 0, sizeof(fmt));
	fmt.version = 20030909;
	fmt.fmt.version = SFIO_VERSION;
	fmt.fmt.form = (char*)format;
	fmt.fmt.extf = getfmt;
	fmt.handle = handle;
	fmt.lookup = lookup;
	fmt.convert = convert;
	r = sfprintf(sp, "%!", &fmt) - fmt.invisible;
	for (i = 0; i < elementsof(fmt.tmp); i++)
		if (fmt.tmp[i])
			sfclose(fmt.tmp[i]);
	return r;
}
