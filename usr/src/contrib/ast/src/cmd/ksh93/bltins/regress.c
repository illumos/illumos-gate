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
/*
 * regression test intercept control
 * enable with SHOPT_REGRESS==1 in Makefile
 * not for production use
 * see --man for details
 * all string constants inline here instead of in data/...
 *
 *   David Korn
 *   at&t research
 */

#include	"defs.h"

#if SHOPT_REGRESS

#include	<error.h>
#include	<ls.h>
#include	"io.h"
#include	"builtins.h"
#include	<tmx.h>

#define REGRESS_HEADER	"ksh:REGRESS:"

#define TRACE(r,i,f)		sh_regress(REGRESS_##r, i, sfprints f, __LINE__, __FILE__)

static const char	usage[] =
"[-1p0?\n@(#)$Id: __regress__ (AT&T Research) 2009-03-29 $\n]"
USAGE_LICENSE
"[+NAME?__regress__ - shell regression test intercept control]"
"[+DESCRIPTION?\b__regress__\b controls the regression test intercepts "
    "for shells compiled with SHOPT_REGRESS==1. Shells compiled this way are "
    "for testing only. In addition to \b__regress__\b and the \b--regress\b "
    "command line option, these shells may contain system library function "
    "intercepts that behave different from the native counterparts.]"
"[+?Each option controls a different test and possibly a different set "
    "of intercepts. The options are interpreted \bdd\b(1) style -- '-' or "
    "'--' prefix not required. This simplifies the specification of the "
    "command line \b--regress\b=\avalue\a option, where \avalue\a is passed "
    "as an option to the \b__regress__\b builtin. Typically regression test "
    "intercepts are enabled with one or more command line \b--regress\b "
    "options, with optional specific calls to \b__regress__\b in test "
    "scripts to enable/disable intercepts as the test progresses.]"
"[+?Each enabled intercept may result in trace lines of the form \b" REGRESS_HEADER
    "\aoption\a:\aintercept\a:\ainfo\a on the standard error, where "
    "\aoption\a is one of the options below, \aintercept\a is the name of "
    "the specific intercept for \aoption\a, and \ainfo\a is \aoption\a "
    "specific information. Unless noted otherwise, one regression test trace "
    "line is produced each time an enabled intercept is called.]"
"[101:egid?The intercept effective gid is set to \aoriginal-egid\a. The "
    "effective gid of the underlying system process is not affected. The "
    "trace line info is either \begid==rgid\b or \begid!=rgid\b. The "
    "intercepts are:]#?[original-egid:=1]"
    "{"
        "[+getegid()?The intercept effecive gid is returned. The "
            "\bsetgid\b() intercept may change this between the real gid and "
            "\aoriginal-egid\a.]"
        "[+setgid(gid)?Sets the intercept effective gid to \agid\a. "
            "Fails if \agid\a is neither the real gid nor "
            "\aoriginal-egid\a.]"
    "}"
"[102:euid?The intercept effective uid is set to \aoriginal-euid\a. The "
    "effective uid of the underlying system process is not affected. The "
    "trace line info is either \beuid==ruid\b or \beuid!=ruid\b. The "
    "intercepts are:]#?[original-euid:=1]"
    "{"
        "[+geteuid()?The intercept effecive uid is returned. The "
            "\bsetuid\b() intercept may change this between the real uid and "
            "\aoriginal-euid\a.]"
        "[+setuid(uid)?Sets the intercept effective uid to \auid\a. "
            "Fails if \auid\a is neither the real uid nor "
            "\aoriginal-euid\a.]"
    "}"
"[103:p_suid?Specifies a value for SHOPT_P_SUID. Effective uids greater "
    "than the non-privileged-uid disable the priveleged mode. The intercepts "
    "are:]#?[non-privileged-uid:=1]"
    "{"
        "[+SHOPT_P_SUID?The SHOPT_P_SUID macro value is overridden by "
            "\bp_suid\b. A trace line is output for each SHOPT_P_SUID "
            "access.]"
    "}"
"[104:source?The intercepts are:]"
    "{"
        "[+sh_source()?The trace line info is the path of the script "
            "being sourced. Used to trace shell startup scripts.]"
    "}"
"[105:etc?Map file paths matching \b/etc/\b* to \aetc-dir\a/*. The "
    "intercepts are:]:[etc-dir:=/etc]"
    "{"
        "[+sh_open()?Paths matching \b/etc/\b* are changed to "
            "\aetc-dir\a/*.]"
    "}"
"[+SEE ALSO?\bksh\b(1), \bregress\b(1), \brt\b(1)]"
;

static const char*	regress_options[] =
{
	"ERROR",
	"egid",
	"euid",
	"p_suid",
	"source",
	"etc",
};

void sh_regress_init(Shell_t* shp)
{
	static Regress_t	state;

	shp->regress = &state;
}

/*
 * regress info trace output
 */

void sh_regress(unsigned int index, const char* intercept, const char* info, unsigned int line, const char* file)
{
	char*	name;
	char	buf[16];

	if (index >= 1 && index <= elementsof(regress_options))
		name = (char*)regress_options[index];
	else
		sfsprintf(name = buf, sizeof(buf), "%u", index);
	sfprintf(sfstderr, REGRESS_HEADER "%s:%s:%s\n", name, intercept, fmtesc(info));
}

/*
 * egid intercepts
 */

static gid_t	intercept_sgid = 0;
static gid_t	intercept_egid = -1;
static gid_t	intercept_rgid = -1;

gid_t getegid(void)
{
	if (intercept_rgid == -1)
		intercept_rgid = getgid();
	if (sh_isregress(REGRESS_egid))
	{
		TRACE(egid, "getegid", ("%s", intercept_egid == intercept_rgid ? "egid==rgid" : "egid!=rgid"));
		return intercept_egid;
	}
	return intercept_rgid;
}

int setgid(gid_t gid)
{
	if (intercept_rgid == -1)
		intercept_rgid = getgid();
	if (sh_isregress(REGRESS_egid))
	{
		if (gid != intercept_rgid && gid != intercept_sgid)
		{
			TRACE(egid, "setgid", ("%s", "EPERM"));
			errno = EPERM;
			return -1;
		}
		intercept_egid = gid;
		TRACE(egid, "setgid", ("%s", intercept_egid == intercept_rgid ? "egid==rgid" : "egid!=rgid"));
	}
	else if (gid != intercept_rgid)
	{
		errno = EPERM;
		return -1;
	}
	return 0;
}

/*
 * euid intercepts
 */

static uid_t	intercept_suid = 0;
static uid_t	intercept_euid = -1;
static uid_t	intercept_ruid = -1;

uid_t geteuid(void)
{
	if (intercept_ruid == -1)
		intercept_ruid = getuid();
	if (sh_isregress(REGRESS_euid))
	{
		TRACE(euid, "geteuid", ("%s", intercept_euid == intercept_ruid ? "euid==ruid" : "euid!=ruid"));
		return intercept_euid;
	}
	return intercept_ruid;
}

int setuid(uid_t uid)
{
	if (intercept_ruid == -1)
		intercept_ruid = getuid();
	if (sh_isregress(REGRESS_euid))
	{
		if (uid != intercept_ruid && uid != intercept_suid)
		{
			TRACE(euid, "setuid", ("%s", "EPERM"));
			errno = EPERM;
			return -1;
		}
		intercept_euid = uid;
		TRACE(euid, "setuid", ("%s", intercept_euid == intercept_ruid ? "euid==ruid" : "euid!=ruid"));
	}
	else if (uid != intercept_ruid)
	{
		errno = EPERM;
		return -1;
	}
	return 0;
}

/*
 * p_suid intercept
 */

static uid_t	intercept_p_suid = 0x7fffffff;

uid_t sh_regress_p_suid(unsigned int line, const char* file)
{
	REGRESS(p_suid, "SHOPT_P_SUID", ("%d", intercept_p_suid));
	return intercept_p_suid;
}

/*
 * p_suid intercept
 */

static char*	intercept_etc = 0;

char* sh_regress_etc(const char* path, unsigned int line, const char* file)
{
	REGRESS(etc, "sh_open", ("%s => %s%s", path, intercept_etc, path+4));
	return intercept_etc;
}

/*
 * __regress__ builtin
 */

int b___regress__(int argc, char** argv, Shbltin_t *context)
{
	register Shell_t*	shp = context->shp;
	int			n;

	for (;;)
	{
		switch (n = optget(argv, usage))
		{
		case '?':
			errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
			break;
		case ':':
			errormsg(SH_DICT, 2, "%s", opt_info.arg);
			break;
		case 0:
			break;
		default:
			if (n < -100)
			{
				n = -(n + 100);
				if (opt_info.arg || opt_info.number)
					sh_onregress(n);
				else
					sh_offregress(n);
				switch (n)
				{
				case REGRESS_egid:
					if (sh_isregress(n))
					{
						intercept_egid = intercept_sgid = (gid_t)opt_info.number;
						TRACE(egid, argv[0], ("%d", intercept_egid));
					}
					else
						TRACE(egid, argv[0], ("%s", "off"));
					break;
				case REGRESS_euid:
					if (sh_isregress(n))
					{
						intercept_euid = intercept_suid = (uid_t)opt_info.number;
						TRACE(euid, argv[0], ("%d", intercept_euid));
					}
					else
						TRACE(euid, argv[0], ("%s", "off"));
					break;
				case REGRESS_p_suid:
					if (sh_isregress(n))
					{
						intercept_p_suid = (uid_t)opt_info.number;
						TRACE(p_suid, argv[0], ("%d", intercept_p_suid));
					}
					else
						TRACE(p_suid, argv[0], ("%s", "off"));
					break;
				case REGRESS_source:
					TRACE(source, argv[0], ("%s", sh_isregress(n) ? "on" : "off"));
					break;
				case REGRESS_etc:
					if (sh_isregress(n))
					{
						intercept_etc = opt_info.arg;
						TRACE(etc, argv[0], ("%s", intercept_etc));
					}
					else
						TRACE(etc, argv[0], ("%s", "off"));
					break;
				}
			}
			continue;
		}
		break;
	}
	if (error_info.errors || *(argv + opt_info.index))
		errormsg(SH_DICT, ERROR_usage(2), "%s", optusage(NiL));
	return 0;
}

#else

NoN(regress)

#endif
