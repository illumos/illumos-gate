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
#include <ast.h>
#include <stdarg.h>

#define STR		(8*1024)

#define VALID(p,f)	((p=(Sfstr_t*)f)>=&strs[0]&&p<&strs[elementsof(strs)])

static Sfstr_t		strs[64];

static int
extend(Sfstr_t* p, int n)
{
	int	o;

	if (n < STR)
		n = STR;
	n += p->end - p->beg;
	o = p->nxt - p->beg;
	if (!(p->beg = realloc(p->beg, n)))
		return -1;
	p->nxt = p->beg + o;
	p->end = p->beg + n;
	return 0;
}

int
sfclose(Sfio_t* f)
{
	Sfstr_t*	p;
	int		r;

	if (VALID(p, f))
	{
		p->nxt = 0;
		r = 0;
	}
	else
		r = fclose(f);
	return r;
}

int
sfprintf(Sfio_t* f, const char* fmt, ...)
{
	Sfstr_t*	p;
	char*		s;
	va_list		ap;
	int		r;

	static char	buf[STR];

	va_start(ap, fmt);
	if (!VALID(p, f))
		r = vfprintf(f, fmt, ap);
	else if ((r = vsnprintf(buf, sizeof(buf), fmt, ap)) > 0)
		r = sfwrite(f, buf, r);
	va_end(ap);
	return r;
}

char*
sfprints(const char* fmt, ...)
{
	va_list		ap;
	int		r;

	static char	buf[STR];

	va_start(ap, fmt);
	r = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return r > 0 ? buf : (char*)0;
}

int
sfputc(Sfio_t* f, int c)
{
	Sfstr_t*	p;
	int		r;

	if (VALID(p, f))
	{
		if (p->nxt >= p->end && extend(p, 1))
			return -1;
		*p->nxt++ = c;
		r = 1;
	}
	else
		r = fputc(c, f);
	return r;
}

int
sfputr(Sfio_t* f, const char* buf, int sep)
{
	Sfstr_t*	p;
	int		r;
	int		n;

	n = strlen(buf);
	if (VALID(p, f))
	{
		r = n + (sep >= 0);
		if (r > (p->end - p->nxt) && extend(p, r))
			return -1;
		memcpy(p->nxt, buf, n);
		p->nxt += n;
		if (sep >= 0)
			*p->nxt++ = sep;
	}
	else
	{
		r = fwrite(buf, 1, n, f);
		if (sep >= 0 && fputc(sep, f) != EOF)
			r++;
	}
	return r;
}

char*
sfstrbase(Sfio_t* f)
{
	Sfstr_t*	p;

	if (VALID(p, f))
		return p->beg;
	return 0;
}

Sfio_t*
sfstropen(void)
{
	Sfstr_t*	p;

	for (p = &strs[0]; p < &strs[elementsof(strs)]; p++)
		if (!p->nxt)
		{
			if (!p->beg)
			{
				if (!(p->beg = malloc(STR)))
					break;
				p->end = p->beg + STR;
			}
			p->nxt = p->beg;
			return (Sfio_t*)p;
		}
	return 0;
}

#define _sf_strseek(f,p,m) \
	( (m) == SEEK_SET ? \
	 	(((p) < 0 || (p) > ((f)->end - (f)->beg)) ? (char*)0 : \
		 (char*)((f)->nxt = (f)->beg+(p)) ) \
	: (m) == SEEK_CUR ? \
		((f)->nxt += (p), \
		 (((f)->nxt < (f)->beg || (f)->nxt > (f)->end) ? \
			((f)->nxt -= (p), (char*)0) : (char*)(f)->nxt ) ) \
	: (m) == SEEK_END ? \
		( ((p) > 0 || (((f)->end - (f)->beg) + (p)) < 0) ? (char*)0 : \
			(char*)((f)->nxt = (f)->end+(p)) ) \
	: (char*)0 \
	)

char*
sfstrseek(Sfio_t* f, int n, int w)
{
	Sfstr_t*	p;

	if (VALID(p, f))
		return _sf_strseek(p, n, w);
	return 0;
}

char*
sfstrset(Sfio_t* f, int n)
{
	Sfstr_t*	p;

	if (VALID(p, f) && n >= 0 && n < (p->nxt - p->beg))
		return p->nxt = p->beg + n;
	return 0;
}

int
sfstrtell(Sfio_t* f)
{
	Sfstr_t*	p;
	int		r;

	if (VALID(p, f) && p->nxt)
		r = p->nxt - p->beg;
	else
		r = -1;
	return r;
}

char*
sfstruse(Sfio_t* f)
{
	Sfstr_t*	p;

	if (VALID(p, f) && (p->nxt < p->end || !extend(p, 1)))
	{
		*p->nxt = 0;
		return p->nxt = p->beg;
	}
	return 0;
}

int
sfwrite(Sfio_t* f, void* buf, int n)
{
	Sfstr_t*	p;

	if (VALID(p, f))
	{
		if (n > (p->end - p->nxt) && extend(p, n))
			return -1;
		memcpy(p->nxt, buf, n);
		p->nxt += n;
	}
	else
		n = fwrite(buf, 1, n, f);
	return n;
}
