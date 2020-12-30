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
 * <regexp.h> library support
 */

#define _REGEXP_DECLARE

#include <ast.h>
#include <regexp.h>
#include <regex.h>
#include <align.h>

typedef struct
{
	regex_t		re;
	char*		buf;
	char*		cur;
	unsigned int	size;
} Env_t;

static void*
block(void* handle, void* data, size_t size)
{
	register Env_t*	env = (Env_t*)handle;

	if (data || (size = roundof(size, ALIGN_BOUND2)) > (env->buf + env->size - env->cur))
		return 0;
	data = (void*)env->cur;
	env->cur += size;
	return data;
}

int
_re_comp(regexp_t* re, const char* pattern, char* handle, unsigned int size)
{
	register Env_t*	env = (Env_t*)handle;
	register int	n;

	if (size <= sizeof(Env_t))
		return 50;
	env->buf = env->cur = (char*)env + sizeof(Env_t);
	env->size = size - sizeof(Env_t);
	regalloc(env, block, REG_NOFREE);
	n = regcomp(&env->re, pattern, REG_LENIENT|REG_NULL);
	switch (n)
	{
	case 0:
		break;
	case REG_ERANGE:
		n = 11;
		break;
	case REG_BADBR:
		n = 16;
		break;
	case REG_ESUBREG:
		n = 25;
		break;
	case REG_EPAREN:
		n = 42;
		break;
	case REG_EBRACK:
		n = 49;
		break;
	default:
		n = 50;
		break;
	}
	re->re_nbra = env->re.re_nsub;
	return n;
}

int
_re_exec(regexp_t* re, const char* subject, const char* handle, int anchor)
{
	register Env_t*	env = (Env_t*)handle;
	register int	n;
	regmatch_t	match[elementsof(re->re_braslist)+1];

	if (regexec(&env->re, subject, elementsof(match), match, 0) || anchor && match[0].rm_so)
		return 0;
	re->re_loc1 = (char*)subject + match[0].rm_so;
	re->re_loc2 = (char*)subject + match[0].rm_eo;
	for (n = 1; n <= env->re.re_nsub; n++)
	{
		re->re_braslist[n-1] = (char*)subject + match[n].rm_so;
		re->re_braelist[n-1] = (char*)subject + match[n].rm_eo;
	}
	return 1;
}

char*
_re_putc(int c)
{
	static Sfio_t*	sp;

	if (!sp && !(sp = sfstropen()))
		return 0;
	if (!c)
		return sfstruse(sp);
	sfputc(sp, c);
	return 0;
}
