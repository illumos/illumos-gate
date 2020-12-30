/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2012 AT&T Intellectual Property          *
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
#ifndef _SHTABLE_H

/*
 * David Korn
 * AT&T Labs
 *
 * Interface definitions read-only data tables for shell
 *
 */

#define _SHTABLE_H	1

typedef struct shtable1
{
	const char	*sh_name;
	const unsigned	sh_number;
} Shtable_t;

struct shtable2
{
	const char	*sh_name;
	const unsigned	sh_number;
	const char	*sh_value;
};

struct shtable3
{
	const char	*sh_name;
	const unsigned	sh_number;
	int		(*sh_value)(int, char*[], Shbltin_t*);
};

#define sh_lookup(name,value)	(sh_locate(name,(Shtable_t*)(value),sizeof(*(value)))->sh_number)
extern const Shtable_t		shtab_testops[];
extern const Shtable_t		shtab_options[];
extern const Shtable_t		shtab_attributes[];
extern const struct shtable2	shtab_variables[];
extern const struct shtable2	shtab_aliases[];
extern const struct shtable2	shtab_signals[];
extern const struct shtable3	shtab_builtins[];
extern const Shtable_t		shtab_reserved[];
extern const Shtable_t		*sh_locate(const char*, const Shtable_t*, int);
extern int			sh_lookopt(const char*, int*);

#endif /* SH_TABLE_H */
