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
 * catopen intercept
 * the ast catalogs are checked first
 * the ast mc* and native cat* routines do all the work
 * catalogs found by mcfind() are converted from utf to ucs
 *
 * nl_catd is cast to void*
 * this is either an Mc_t* (Mc_t.set != 0)
 * or a Cc_t* where Cc_t.cat is the native nl_catd
 */

#include <ast.h>
#include <mc.h>
#include <nl_types.h>
#include <iconv.h>

#ifndef DEBUG_trace
#define DEBUG_trace		0
#endif
#if DEBUG_trace
#undef setlocale
#endif

#if _lib_catopen

#undef	nl_catd
#undef	catopen
#undef	catgets
#undef	catclose

typedef struct
{
	Mcset_t*	set;
	nl_catd		cat;
	iconv_t		cvt;
	Sfio_t*		tmp;
} Cc_t;

#else

#define _ast_nl_catd	nl_catd
#define _ast_catopen	catopen
#define _ast_catgets	catgets
#define _ast_catclose	catclose

#endif

_ast_nl_catd
_ast_catopen(const char* name, int flag)
{
	Mc_t*		mc;
	char*		s;
	Sfio_t*		ip;
	char		path[PATH_MAX];

	/*
	 * first try the ast catalogs
	 */

#if DEBUG_trace
sfprintf(sfstderr, "AHA#%d:%s %s LC_MESSAGES=%s:%s\n", __LINE__, __FILE__, name, _ast_setlocale(LC_MESSAGES, 0), setlocale(LC_MESSAGES, 0));
#endif
	if ((s = mcfind(NiL, name, LC_MESSAGES, flag, path, sizeof(path))) && (ip = sfopen(NiL, s, "r")))
	{
#if DEBUG_trace
sfprintf(sfstderr, "AHA#%d:%s %s\n", __LINE__, __FILE__, s);
#endif
		mc = mcopen(ip);
		sfclose(ip);
		if (mc)
			return (_ast_nl_catd)mc;
	}
#if _lib_catopen
	if (strcmp(setlocale(LC_MESSAGES, NiL), "debug"))
	{
		Cc_t*		cc;
		nl_catd		d;

		/*
		 * now the native catalogs
		 */

		if (s && (d = catopen(s, flag)) != (nl_catd)(-1) || !(s = 0) && (d = catopen(name, flag)) != (nl_catd)(-1))
		{
			if (!(cc = newof(0, Cc_t, 1, 0)))
			{
				catclose(d);
				return (_ast_nl_catd)(-1);
			}
			cc->cat = d;
			if ((s || *name == '/') && (ast.locale.set & (1<<AST_LC_MESSAGES)))
			{
				if ((cc->cvt = iconv_open("", "utf")) == (iconv_t)(-1) || !(cc->tmp = sfstropen()))
				{
					catclose(d);
					free(cc);
					return (_ast_nl_catd)(-1);
				}
			}
			else
				cc->cvt = (iconv_t)(-1);
#if DEBUG_trace
sfprintf(sfstderr, "AHA#%d:%s %s %s native %p\n", __LINE__, __FILE__, s, name, cc->cat);
#endif
			return (_ast_nl_catd)cc;
		}
	}
#endif

	/*
	 * loser
	 */

	return (_ast_nl_catd)(-1);
}

char*
_ast_catgets(_ast_nl_catd cat, int set, int num, const char* msg)
{
	if (cat == (_ast_nl_catd)(-1))
		return (char*)msg;
#if _lib_catopen
	if (!((Cc_t*)cat)->set)
	{
		char*	s;
		size_t	n;

		msg = (char*)catgets(((Cc_t*)cat)->cat, set, num, msg);
		if (((Cc_t*)cat)->cvt != (iconv_t)(-1))
		{
			s = (char*)msg;
			n = strlen(s);
			iconv_write(((Cc_t*)cat)->cvt, ((Cc_t*)cat)->tmp, &s, &n, NiL);
			if (s = sfstruse(((Cc_t*)cat)->tmp))
				return s;
		}
		return (char*)msg;
	}
#endif
	return mcget((Mc_t*)cat, set, num, msg);
}

int
_ast_catclose(_ast_nl_catd cat)
{
	if (cat == (_ast_nl_catd)(-1))
		return -1;
#if _lib_catopen
	if (!((Cc_t*)cat)->set)
	{
		if (((Cc_t*)cat)->cvt != (iconv_t)(-1))
			iconv_close(((Cc_t*)cat)->cvt);
		if (((Cc_t*)cat)->tmp)
			sfclose(((Cc_t*)cat)->tmp);
		return catclose(((Cc_t*)cat)->cat);
	}
#endif
	return mcclose((Mc_t*)cat);
}
