/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2011 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
#ifndef  _ENV_H
#define	_ENV_H	1

#ifdef _BLD_env
#    ifdef __EXPORT__
#	define export	__EXPORT__
#    endif
#else
     typedef void *Env_t;
#endif

/* for use with env_open */
#define ENV_STABLE	(-1)

/* for third agument to env_add */
#define ENV_MALLOCED	1
#define ENV_STRDUP	2

extern void	env_close(Env_t*);
extern int	env_add(Env_t*, const char*, int);
extern int	env_delete(Env_t*, const char*);
extern char	**env_get(Env_t*);
extern Env_t	*env_open(char**,int);
extern Env_t	*env_scope(Env_t*,int);

#undef extern

#endif


