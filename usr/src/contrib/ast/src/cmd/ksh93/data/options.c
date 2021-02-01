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

#include	"defs.h"
#include	"name.h"
#include	"shtable.h"

#if SHOPT_BASH
#   define bashopt(a,b)		a,	b|SH_BASHOPT,
#   define bashextra(a,b)	a,	b|SH_BASHEXTRA,
#else
#   define bashopt(a,b)
#   define bashextra(a,b)
#endif

/*
 * This is the list of invocation and set options
 * This list must be in in ascii sorted order
 */

const Shtable_t shtab_options[] =
{
	"allexport",			SH_ALLEXPORT,
#if SHOPT_BASH
	"bash",				(SH_BASH|SH_COMMANDLINE),
#endif
	"bgnice",			SH_BGNICE,
	"braceexpand",			SH_BRACEEXPAND,
	bashopt("cdable_vars",		SH_CDABLE_VARS)
	bashopt("cdspell",		SH_CDSPELL)
	bashopt("checkhash",		SH_CHECKHASH)
	bashopt("checkwinsize",		SH_CHECKWINSIZE)
	"noclobber",			SH_NOCLOBBER,
	bashopt("dotglob",		SH_DOTGLOB)
	"emacs",			SH_EMACS,
	"errexit",			SH_ERREXIT,
	"noexec",			SH_NOEXEC,
	bashopt("execfail",		SH_EXECFAIL)
	bashopt("expand_aliases",	SH_EXPAND_ALIASES)
	bashopt("extglob",		SH_EXTGLOB)
	"noglob",			SH_NOGLOB,
	"globstar",			SH_GLOBSTARS,
	"gmacs",			SH_GMACS,
	bashextra("hashall",		SH_TRACKALL)
	bashopt("histappend",		SH_HISTAPPEND)
#if SHOPT_HISTEXPAND
	"histexpand",			SH_HISTEXPAND,
#else
	bashextra("histexpand",		SH_HISTEXPAND)
#endif
	bashextra("history",		SH_HISTORY2)
	bashopt("histreedit",		SH_HISTREEDIT)
	bashopt("histverify",		SH_HISTVERIFY)
	bashopt("hostcomplete",		SH_HOSTCOMPLETE)
	bashopt("huponexit",		SH_HUPONEXIT)
	"ignoreeof",			SH_IGNOREEOF,
	"interactive",			SH_INTERACTIVE|SH_COMMANDLINE,
	bashextra("interactive_comments",	SH_INTERACTIVE_COMM)
	"keyword",			SH_KEYWORD,
	"letoctal",			SH_LETOCTAL,
	bashopt("lithist",		SH_LITHIST)
	"nolog",			SH_NOLOG,
	"login_shell",			SH_LOGIN_SHELL|SH_COMMANDLINE,
	bashopt("mailwarn",		SH_MAILWARN)
	"markdirs",			SH_MARKDIRS,
	"monitor",			SH_MONITOR,
	"multiline",			SH_MULTILINE,
	bashopt("no_empty_cmd_completion", SH_NOEMPTYCMDCOMPL)
	bashopt("nocaseglob",		SH_NOCASEGLOB)
	"notify",			SH_NOTIFY,
	bashopt("nullglob",		SH_NULLGLOB)
	bashextra("onecmd",		SH_TFLAG)
	"pipefail",			SH_PIPEFAIL,
	bashextra("physical",		SH_PHYSICAL)
	bashextra("posix",		SH_POSIX)
	"privileged",			SH_PRIVILEGED,
#if SHOPT_BASH
	"profile",			SH_LOGIN_SHELL|SH_COMMANDLINE,
#   if SHOPT_PFSH
	"pfsh",				SH_PFSH|SH_COMMANDLINE,
#   endif
#else
#   if SHOPT_PFSH
	"profile",			SH_PFSH|SH_COMMANDLINE,
#   endif
#endif
	bashopt("progcomp",		SH_PROGCOMP)
	bashopt("promptvars",		SH_PROMPTVARS)
	"rc",				SH_RC|SH_COMMANDLINE,
	"restricted",			SH_RESTRICTED,
	bashopt("restricted_shell",	SH_RESTRICTED2|SH_COMMANDLINE)
	bashopt("shift_verbose",	SH_SHIFT_VERBOSE)
	"showme",			SH_SHOWME,
	bashopt("sourcepath",		SH_SOURCEPATH)
	"trackall",			SH_TRACKALL,
	"nounset",			SH_NOUNSET,
	"verbose",			SH_VERBOSE,
	"vi",				SH_VI,
	"viraw",			SH_VIRAW,
	bashopt("xpg_echo",		SH_XPG_ECHO)
	"xtrace",			SH_XTRACE,
	"",				0
};

const Shtable_t shtab_attributes[] =
{
	{"-Sshared",	NV_REF|NV_TAGGED},
	{"-nnameref",	NV_REF},
	{"-xexport",	NV_EXPORT},
	{"-rreadonly",	NV_RDONLY},
	{"-ttagged",	NV_TAGGED},
	{"-Aassociative array",	NV_ARRAY},
	{"-aindexed array",	NV_ARRAY},
	{"-llong",	(NV_DOUBLE|NV_LONG)},
	{"-Eexponential",(NV_DOUBLE|NV_EXPNOTE)},
	{"-Xhexfloat",	(NV_DOUBLE|NV_HEXFLOAT)},
	{"-Ffloat",	NV_DOUBLE},
	{"-llong",	(NV_INTEGER|NV_LONG)},
	{"-sshort",	(NV_INTEGER|NV_SHORT)},
	{"-uunsigned",	(NV_INTEGER|NV_UNSIGN)},
	{"-iinteger",	NV_INTEGER},
	{"-Hfilename",	NV_HOST},
	{"-bbinary",    NV_BINARY},
	{"-ltolower",	NV_UTOL},
	{"-utoupper",	NV_LTOU},
	{"-Zzerofill",	NV_ZFILL},
	{"-Lleftjust",	NV_LJUST},
	{"-Rrightjust",	NV_RJUST},
	{"++namespace",	NV_TABLE},
	{"",		0}
};
