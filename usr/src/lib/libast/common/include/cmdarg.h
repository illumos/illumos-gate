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
 * xargs/tw command arg list interface definitions
 */

#ifndef _CMDARG_H
#define _CMDARG_H

#define CMD_CHECKED	(1<<9)		/* cmdopen() argv[0] ok		*/
#define CMD_EMPTY	(1<<0)		/* run once, even if no args	*/
#define CMD_EXACT	(1<<1)		/* last command must have argmax*/
#define CMD_IGNORE	(1<<2)		/* ignore EXIT_QUIT exit	*/
#define CMD_INSERT	(1<<3)		/* argpat for insertion		*/
#define CMD_MINIMUM	(1<<4)		/* argmax is a minimum		*/
#define CMD_NEWLINE	(1<<5)		/* echo separator is newline	*/
#define CMD_POST	(1<<6)		/* argpat is post arg position	*/
#define CMD_QUERY	(1<<7)		/* trace and query each command	*/
#define CMD_SILENT	(1<<10)		/* no error messages		*/
#define CMD_TRACE	(1<<8)		/* trace each command		*/

#define CMD_USER	(1<<12)

typedef struct				/* cmd + args info		*/
{
	struct
	{
	size_t		args;		/* total args			*/
	size_t		commands;	/* total commands		*/
	}		total;

	int		argcount;	/* current arg count		*/
	int		argmax;		/* max # args			*/
	int		echo;		/* just an echo			*/
	int		flags;		/* CMD_* flags			*/
	int		insertlen;	/* strlen(insert)		*/
	int		offset;		/* post arg offset		*/

	char**		argv;		/* exec argv			*/
	char**		firstarg;	/* first argv file arg		*/
	char**		insertarg;	/* argv before insert		*/
	char**		postarg;	/* start of post arg list	*/
	char**		nextarg;	/* next argv file arg		*/
	char*		nextstr;	/* next string ends before here	*/
	char*		laststr;	/* last string ends before here	*/
	char*		insert;		/* replace with current arg	*/
	char		buf[1];		/* argv and arg buffer		*/
} Cmdarg_t;

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern Cmdarg_t*	cmdopen(char**, int, int, const char*, int);
extern int		cmdflush(Cmdarg_t*);
extern int		cmdarg(Cmdarg_t*, const char*, int);
extern int		cmdclose(Cmdarg_t*);

#undef	extern

#endif
