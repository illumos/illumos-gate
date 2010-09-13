/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2010 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * AT&T Bell Laboratories
 *
 * mkdir
 */

static const char usage[] =
"[-?\n@(#)$Id: mkdir (AT&T Research) 2009-12-03 $\n]"
USAGE_LICENSE
"[+NAME?mkdir - make directories]"
"[+DESCRIPTION?\bmkdir\b creates one or more directories.  By "
	"default, the mode of created directories is \ba=rwx\b minus the "
	"bits set in the \bumask\b(1).]"
"[m:mode]:[mode?Set the mode of created directories to \amode\a.  "
	"\amode\a is symbolic or octal mode as in \bchmod\b(1).  Relative "
	"modes assume an initial mode of \ba=rwx\b.]"
"[p:parents?Create any missing intermediate pathname components. For "
    "each dir operand that does not name an existing directory, effects "
    "equivalent to those caused by the following command shall occur: "
    "\vmkdir -p -m $(umask -S),u+wx $(dirname dir) && mkdir [-m mode]] "
    "dir\v where the \b-m\b mode option represents that option supplied to "
    "the original invocation of \bmkdir\b, if any. Each dir operand that "
    "names an existing directory shall be ignored without error.]"
"[v:verbose?Print a message on the standard error for each created "
    "directory.]"
"\n"
"\ndirectory ...\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?All directories created successfully, or the \b-p\b option "
	"was specified and all the specified directories now exist.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bchmod\b(1), \brmdir\b(1), \bumask\b(1)]"
;

#include <cmd.h>
#include <ls.h>

#define DIRMODE	(S_IRWXU|S_IRWXG|S_IRWXO)

int
b_mkdir(int argc, char** argv, void* context)
{
	register char*	arg;
	register int	n;
	register mode_t	mode = DIRMODE;
	register mode_t	mask = 0;
	register int	mflag = 0;
	register int	pflag = 0;
	register int	vflag = 0;
	char*		name;
	mode_t		dmode;
	struct stat	st;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 0:
			break;
		case 'm':
			mflag = 1;
			mode = strperm(arg = opt_info.arg, &opt_info.arg, mode);
			if (*opt_info.arg)
				error(ERROR_exit(0), "%s: invalid mode", arg);
			continue;
		case 'p':
			pflag = 1;
			continue;
		case 'v':
			vflag = 1;
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || !*argv)
		error(ERROR_usage(2), "%s", optusage(NiL));
	mask = umask(0);
	if (mflag || pflag)
	{
		dmode = DIRMODE & ~mask;
		if (!mflag)
			mode = dmode;
		dmode |= S_IWUSR | S_IXUSR;
	}
	else
	{
		mode &= ~mask;
		umask(mask);
		mask = 0;
	}
	while (arg = *argv++)
	{
		if (mkdir(arg, mode) < 0)
		{
			if (!pflag || !(errno == ENOENT || errno == EEXIST || errno == ENOTDIR))
			{
				error(ERROR_system(0), "%s:", arg);
				continue;
			}
			if (errno == EEXIST)
				continue;

			/*
			 * -p option, preserve intermediates
			 * first eliminate trailing /'s
			 */

			n = strlen(arg);
			while (n > 0 && arg[--n] == '/');
			arg[n + 1] = 0;
			for (name = arg, n = *arg; n;)
			{
				/* skip over slashes */
				while (*arg == '/')
					arg++;
				/* skip to next component */
				while ((n = *arg) && n != '/')
					arg++;
				*arg = 0;
				if (mkdir(name, n ? dmode : mode) < 0 && errno != EEXIST && access(name, F_OK) < 0)
				{
					*arg = n;
					error(ERROR_system(0), "%s:", name);
					break;
				}
				if (vflag)
					error(0, "%s: directory created", name);
				if (!(*arg = n) && (mode & (S_ISVTX|S_ISUID|S_ISGID)))
				{
					if (stat(name, &st))
					{
						error(ERROR_system(0), "%s: cannot stat", name);
						break;
					}
					if ((st.st_mode & (S_ISVTX|S_ISUID|S_ISGID)) != (mode & (S_ISVTX|S_ISUID|S_ISGID)) && chmod(name, mode))
					{
						error(ERROR_system(0), "%s: cannot change mode from %s to %s", name, fmtperm(st.st_mode & (S_ISVTX|S_ISUID|S_ISGID)), fmtperm(mode));
						break;
					}
				}
			}
		}
		else if (vflag)
			error(0, "%s: directory created", arg);
	}
	if (mask)
		umask(mask);
	return error_info.errors != 0;
}
