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
#include	<ast.h>
#include	<signal.h>
#include	"FEATURE/options"
#include	"FEATURE/dynamic"
#include	"shtable.h"
#include	"name.h"

/*
 * This is the table of built-in aliases.  These should be exported.
 */

const struct shtable2 shtab_aliases[] =
{
#if SHOPT_FS_3D
	"2d",		NV_NOFREE,	"set -f;_2d",
#endif /* SHOPT_FS_3D */
	"autoload",	NV_NOFREE,	"typeset -fu",
	"command",	NV_NOFREE,	"command ",
	"compound",	NV_NOFREE,	"typeset -C",
	"fc",		NV_NOFREE,	"hist",
	"float",	NV_NOFREE,	"typeset -lE",
	"functions",	NV_NOFREE,	"typeset -f",
	"hash",		NV_NOFREE,	"alias -t --",
	"history",	NV_NOFREE,	"hist -l",
	"integer",	NV_NOFREE,	"typeset -li",
	"nameref",	NV_NOFREE,	"typeset -n",
	"nohup",	NV_NOFREE,	"nohup ",
	"r",		NV_NOFREE,	"hist -s",
	"redirect",	NV_NOFREE,	"command exec",
	"source",	NV_NOFREE,	"command .",
#ifdef SIGTSTP
	"stop",		NV_NOFREE,	"kill -s STOP",
	"suspend", 	NV_NOFREE,	"kill -s STOP $$",
#endif /*SIGTSTP */
	"times",	NV_NOFREE,	"{ { time;} 2>&1;}",
	"type",		NV_NOFREE,	"whence -v",
	"",		0,		(char*)0
};

