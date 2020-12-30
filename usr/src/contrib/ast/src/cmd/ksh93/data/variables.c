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

#include	<ast.h>
#include	"FEATURE/options"
#include	"FEATURE/dynamic"
#include	<shell.h>
#include	"shtable.h"
#include	"name.h"
#include	"defs.h"
#include	"variables.h"
#include	"builtins.h"

/*
 * This is the list of built-in shell variables and default values
 * and default attributes.
 */

const struct shtable2 shtab_variables[] =
{
	"PATH",		0,				(char*)0,
	"PS1",		0,				(char*)0,
	"PS2",		NV_NOFREE, 			"> ",
	"IFS",		NV_NOFREE, 			" \t\n",
	"PWD",		0,				(char*)0,
	"HOME",		0,				(char*)0,
	"MAIL",		0,				(char*)0,
	"REPLY",	0,				(char*)0,
	"SHELL",	NV_NOFREE,			"/bin/" SH_STD,
	"EDITOR",	0,				(char*)0,
	"MAILCHECK",	NV_NOFREE|NV_INTEGER,		(char*)0,
	"RANDOM",	NV_NOFREE|NV_INTEGER,		(char*)0,
	"ENV",		NV_NOFREE,			(char*)0,
	"HISTFILE",	0,				(char*)0,
	"HISTSIZE",	0,				(char*)0,
	"HISTEDIT",	NV_NOFREE,			(char*)0,
	"HISTCMD",	NV_NOFREE|NV_INTEGER,		(char*)0,
	"FCEDIT",	NV_NOFREE,			&e_defedit[0],
	"CDPATH",	0,				(char*)0,
	"MAILPATH",	0,				(char*)0,
	"PS3",		NV_NOFREE, 			"#? ",
	"OLDPWD",	0,				(char*)0,
	"VISUAL",	0,				(char*)0,
	"COLUMNS",	0,				(char*)0,
	"LINES",	0,				(char*)0,
	"PPID",		NV_NOFREE|NV_INTEGER,		(char*)0,
	"_",		NV_EXPORT,			(char*)0,
	"TMOUT",	NV_NOFREE|NV_INTEGER,		(char*)0,
	"SECONDS",	NV_NOFREE|NV_INTEGER|NV_DOUBLE,	(char*)0,
	"LINENO",	NV_NOFREE|NV_INTEGER,		(char*)0,
	"OPTARG",	0,				(char*)0,
	"OPTIND",	NV_NOFREE|NV_INTEGER,		(char*)0,
	"PS4",		0,				(char*)0,
	"FPATH",	0,				(char*)0,
	"LANG",		0,				(char*)0,
	"LC_ALL",	0,				(char*)0,
	"LC_COLLATE",	0,				(char*)0,
	"LC_CTYPE",	0,				(char*)0,
	"LC_MESSAGES",	0,				(char*)0,
	"LC_NUMERIC",	0,				(char*)0,
	"FIGNORE",	0,				(char*)0,
	"KSH_VERSION",	0,				(char*)0,
	"JOBMAX",	NV_NOFREE|NV_INTEGER,		(char*)0,
	".sh",		NV_TABLE|NV_NOFREE|NV_NOPRINT,	(char*)0,
	".sh.edchar",	0,				(char*)0,
	".sh.edcol",	0,				(char*)0,
	".sh.edtext",	0,				(char*)0,
	".sh.edmode",	0,				(char*)0,
	".sh.name",	0,				(char*)0,
	".sh.subscript",0,				(char*)0,
	".sh.value",	0,				(char*)0,
	".sh.version",	NV_NOFREE,			(char*)(&e_version[10]),
	".sh.dollar",	0,				(char*)0,
	".sh.match",	0,				(char*)0,
	".sh.command",	0,				(char*)0,
	".sh.file",	0,				(char*)0,
	".sh.fun",	0,				(char*)0,
	".sh.subshell",	NV_INTEGER|NV_SHORT|NV_NOFREE,	(char*)0,
	".sh.level",	0,				(char*)0,
	".sh.lineno",	NV_INTEGER,			(char*)0,
	".sh.stats",	0,				(char*)0,
	".sh.math",	0,				(char*)0,
	".sh.pool",	0,				(char*)0,
	"SHLVL",	NV_INTEGER|NV_NOFREE|NV_EXPORT,	(char*)0,
#if SHOPT_FS_3D
	"VPATH",	0,				(char*)0,
#endif /* SHOPT_FS_3D */
#if SHOPT_MULTIBYTE
	"CSWIDTH",	0,				(char*)0,
#endif /* SHOPT_MULTIBYTE */
#ifdef apollo
	"SYSTYPE",	0,				(char*)0,
#endif /* apollo */
	"",	0,					(char*)0
};

const char *nv_discnames[] = { "get", "set", "append", "unset", "getn", 0 };

#ifdef SHOPT_STATS
const Shtable_t shtab_stats[] =
{
	"arg_cachehits",	STAT_ARGHITS,
	"arg_expands",		STAT_ARGEXPAND,
	"comsubs",		STAT_COMSUB,
	"forks",		STAT_FORKS,
	"funcalls",		STAT_FUNCT,
	"globs",		STAT_GLOBS,
	"linesread",		STAT_READS,
	"nv_cachehit",		STAT_NVHITS,
	"nv_opens",		STAT_NVOPEN,
	"pathsearch",		STAT_PATHS,
	"posixfuncall",		STAT_SVFUNCT,
	"simplecmds",		STAT_SCMDS,
	"spawns",		STAT_SPAWN,
	"subshell",		STAT_SUBSHELL
};
#endif /* SHOPT_STATS */

