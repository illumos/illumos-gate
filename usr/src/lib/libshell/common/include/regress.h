/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * AT&T Labs
 *
 * Shell interface private definitions
 *
 */

#ifndef _REGRESS_H
#define _REGRESS_H		1

#if SHOPT_REGRESS

typedef struct Regress_s
{
	Shopt_t	options;
} Regress_t;

#define sh_isregress(r)		is_option(&sh.regress->options,r)
#define sh_onregress(r)		on_option(&sh.regress->options,r)
#define sh_offregress(r)	off_option(&sh.regress->options,r)

#define REGRESS(r,i,f)		do { if (sh_isregress(REGRESS_##r)) sh_regress(REGRESS_##r, i, sfprints f, __LINE__, __FILE__); } while (0)

#define REGRESS_egid		1
#define REGRESS_euid		2
#define REGRESS_p_suid		3
#define REGRESS_source		4
#define REGRESS_etc		5

#undef	SHOPT_P_SUID
#define SHOPT_P_SUID		sh_regress_p_suid(__LINE__, __FILE__)

extern int			b___regress__(int, char**, void*);
extern void			sh_regress_init(Shell_t*);
extern void			sh_regress(unsigned int, const char*, const char*, unsigned int, const char*);
extern uid_t			sh_regress_p_suid(unsigned int, const char*);
extern char*			sh_regress_etc(const char*, unsigned int, const char*);

#else

#define REGRESS(r,i,f)

#endif /* SHOPT_REGRESS */

#endif /* _REGRESS_H */
