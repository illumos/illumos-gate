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

#include <ast.h>

#undef	_lib_getopt	/* we can satisfy the api */

#if _lib_getopt

NoN(getopt)

#else

#undef	_BLD_ast	/* enable ast imports since we're user static */

#include <error.h>
#include <option.h>

int		opterr = 1;
int		optind = 1;
int		optopt = 0;
char*		optarg = 0;

static int	lastoptind;

extern int
getopt(int argc, char* const* argv, const char* optstring)
{
	int	n;

	NoP(argc);
	opt_info.index = (optind > 1 || optind == lastoptind) ? optind : 0;
	if (opt_info.index >= argc)
		return -1;
	switch (n = optget((char**)argv, optstring))
	{
	case ':':
		n = '?';
		/*FALLTHROUGH*/
	case '?':
		if (opterr && (!optstring || *optstring != ':'))
		{
			if (!error_info.id)
				error_info.id = argv[0];
			errormsg(NiL, 2, opt_info.arg);
		}
		optopt = opt_info.option[1];
		break;
	case 0:
		n = -1;
		break;
	}
	optarg = opt_info.arg;
	lastoptind = optind = opt_info.index;
	return n;
}

#endif
