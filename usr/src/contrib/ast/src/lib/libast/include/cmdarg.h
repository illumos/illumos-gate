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
 * xargs/tw command arg list interface definitions
 */

#ifndef _CMDARG_H
#define _CMDARG_H	1

#include <error.h>

#define CMD_VERSION	20120411L

#define CMD_CHECKED	(1<<9)		/* cmdopen() argv[0] ok		*/
#define CMD_EMPTY	(1<<0)		/* run once, even if no args	*/
#define CMD_EXACT	(1<<1)		/* last command must have argmax*/
#define CMD_EXIT	(1<<11)		/* fatal error_info.exit()	*/
#define CMD_IGNORE	(1<<2)		/* ignore EXIT_QUIT exit	*/
#define CMD_INSERT	(1<<3)		/* argpat for insertion		*/
#define CMD_MINIMUM	(1<<4)		/* argmax is a minimum		*/
#define CMD_NEWLINE	(1<<5)		/* echo separator is newline	*/
#define CMD_POST	(1<<6)		/* argpat is post arg position	*/
#define CMD_QUERY	(1<<7)		/* trace and query each command	*/
#define CMD_SILENT	(1<<10)		/* no error messages		*/
#define CMD_TRACE	(1<<8)		/* trace each command		*/

#define CMD_USER	(1<<12)

#define CMDDISC(d,f,e)	(memset(d,0,sizeof(*(d))),(d)->version=CMD_VERSION,(d)->flags=(f),(d)->errorf=(e))

struct Cmddisc_s;
typedef struct Cmddisc_s Cmddisc_t;

typedef int (*Cmdrun_f)(int, char**, Cmddisc_t*);

struct Cmddisc_s
{
	uint32_t	version;	/* CMD_VERSION			*/
	uint32_t	flags;		/* CMD_* flags			*/
	Error_f		errorf;		/* optional error function	*/
	Cmdrun_f	runf;		/* optional exec function	*/
};

typedef struct Cmdarg_s			/* cmdopen() handle		*/
{
	const char*	id;		/* library id string		*/

#ifdef _CMDARG_PRIVATE_
	_CMDARG_PRIVATE_
#endif

} Cmdarg_t;

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#ifndef cmdopen
extern Cmdarg_t*	cmdopen(char**, int, int, const char*, int);
#endif
extern Cmdarg_t*	cmdopen_20110505(char**, int, int, const char*, int, Error_f);
extern Cmdarg_t*	cmdopen_20120411(char**, int, int, const char*, Cmddisc_t*);
extern int		cmdflush(Cmdarg_t*);
extern int		cmdarg(Cmdarg_t*, const char*, int);
extern int		cmdclose(Cmdarg_t*);

#undef	extern

#endif
