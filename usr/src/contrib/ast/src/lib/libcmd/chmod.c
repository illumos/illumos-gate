/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * Glenn Fowler
 * AT&T Research
 *
 * chmod
 */

static const char usage[] =
"[-?\n@(#)$Id: chmod (AT&T Research) 2012-04-20 $\n]"
USAGE_LICENSE
"[+NAME?chmod - change the access permissions of files]"
"[+DESCRIPTION?\bchmod\b changes the permission of each file "
	"according to mode, which can be either a symbolic representation "
	"of changes to make, or an octal number representing the bit "
	"pattern for the new permissions.]"
"[+?Symbolic mode strings consist of one or more comma separated list "
	"of operations that can be perfomed on the mode. Each operation is of "
	"the form \auser\a \aop\a \aperm\a where \auser\a is zero or more of "
	"the following letters:]{"
	"[+u?User permission bits.]"
	"[+g?Group permission bits.]"
	"[+o?Other permission bits.]"
	"[+a?All permission bits. This is the default if none are specified.]"
	"}"
"[+?The \aperm\a portion consists of zero or more of the following letters:]{"
	"[+r?Read permission.]"
	"[+s?Setuid when \bu\b is selected for \awho\a and setgid when \bg\b "
		"is selected for \awho\a.]"
	"[+w?Write permission.]"
	"[+x?Execute permission for files, search permission for directories.]"
	"[+X?Same as \bx\b except that it is ignored for files that do not "
		"already have at least one \bx\b bit set.]"
	"[+l?Exclusive lock bit on systems that support it. Group execute "
		"must be off.]"
	"[+t?Sticky bit on systems that support it.]"
	"}"
"[+?The \aop\a portion consists of one or more of the following characters:]{"
	"[++?Cause the permission selected to be added to the existing "
		"permissions. | is equivalent to +.]"
	"[+-?Cause the permission selected to be removed to the existing "
		"permissions.]"
	"[+=?Cause the permission to be set to the given permissions.]"
	"[+&?Cause the permission selected to be \aand\aed with the existing "
		"permissions.]"
	"[+^?Cause the permission selected to be propagated to more "
		"restrictive groups.]"
	"}"
"[+?Symbolic modes with the \auser\a portion omitted are subject to "
	"\bumask\b(2) settings unless the \b=\b \aop\a or the "
	"\b--ignore-umask\b option is specified.]"
"[+?A numeric mode is from one to four octal digits (0-7), "
	"derived by adding up the bits with values 4, 2, and 1. "
	"Any omitted digits are assumed to be leading zeros. The "
	"first digit selects the set user ID (4) and set group ID "
	"(2) and save text image (1) attributes. The second digit "
	"selects permissions for the user who owns the file: read "
	"(4), write (2), and execute (1); the third selects permissions"
	"for other users in the file's group, with the same values; "
	"and the fourth for other users not in the file's group, with "
	"the same values.]"

"[+?For symbolic links, by default, \bchmod\b changes the mode on the file "
	"referenced by the symbolic link, not on the symbolic link itself. "
	"The \b-h\b options can be specified to change the mode of the link. "
	"When traversing directories with \b-R\b, \bchmod\b either follows "
	"symbolic links or does not follow symbolic links, based on the "
	"options \b-H\b, \b-L\b, and \b-P\b. The configuration parameter "
	"\bPATH_RESOLVE\b determines the default behavior if none of these "
	"options is specified.]"

"[+?When the \b-c\b or \b-v\b options are specified, change notifications "
	"are written to standard output using the format, "
	"\b%s: mode changed to %0.4o (%s)\b, with arguments of the "
	"pathname, the numeric mode, and the resulting permission bits as "
	"would be displayed by the \bls\b command.]"

"[+?For backwards compatibility, if an invalid option is given that is a valid "
	"symbolic mode specification, \bchmod\b treats this as a mode "
	"specification rather than as an option specification.]"

"[H:metaphysical?Follow symbolic links for command arguments; otherwise don't "
	"follow symbolic links when traversing directories.]"
"[L:logical|follow?Follow symbolic links when traversing directories.]"
"[P:physical|nofollow?Don't follow symbolic links when traversing directories.]"
"[R:recursive?Change the mode for files in subdirectories recursively.]"
"[c:changes?Describe only files whose permission actually change.]"
"[f:quiet|silent?Do not report files whose permissioins fail to change.]"
"[h|l:symlink?Change the mode of symbolic links on systems that "
    "support \blchmod\b(2). Implies \b--physical\b.]"
"[i:ignore-umask?Ignore the \bumask\b(2) value in symbolic mode "
	"expressions. This is probably how you expect \bchmod\b to work.]"
"[n:show?Show actions but do not change any file modes.]"
"[F:reference?Omit the \amode\a operand and use the mode of \afile\a "
	"instead.]:[file]"
"[v:verbose?Describe changed permissions of all files.]"
"\n"
"\nmode file ...\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?All files changed successfully.]"
	"[+>0?Unable to change mode of one or more files.]"
"}"
"[+SEE ALSO?\bchgrp\b(1), \bchown\b(1), \blchmod\b(1), \btw\b(1), \bgetconf\b(1), "
	"\bls\b(1), \bumask\b(2)]"
;


#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide lchmod
#else
#define lchmod		______lchmod
#endif

#include <cmd.h>
#include <ls.h>
#include <fts_fix.h>

#ifndef ENOSYS
#define ENOSYS	EINVAL
#endif

#include "FEATURE/symlink"

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide lchmod
#else
#undef	lchmod
#endif

extern int	lchmod(const char*, mode_t);

/*
 * NOTE: we only use the native lchmod() on symlinks just in case
 *	 the implementation is a feckless stub
 */

int
b_chmod(int argc, char** argv, Shbltin_t* context)
{
	register int	mode;
	register int	force = 0;
	register int	flags;
	register char*	amode = 0;
	register FTS*	fts;
	register FTSENT*ent;
	char*		last;
	int		(*chmodf)(const char*, mode_t);
	int		logical = 1;
	int		notify = 0;
	int		ignore = 0;
	int		show = 0;
	int		chlink = 0;
	struct stat	st;

	cmdinit(argc, argv, context, ERROR_CATALOG, ERROR_NOTIFY);
	flags = fts_flags() | FTS_META | FTS_TOP | FTS_NOPOSTORDER | FTS_NOSEEDOTDIR;

	/*
	 * NOTE: we diverge from the normal optget boilerplate
	 *	 to allow `chmod -x etc' to fall through
	 */

	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'c':
			notify = 1;
			continue;
		case 'f':
			force = 1;
			continue;
		case 'h':
			chlink = 1;
			continue;
		case 'i':
			ignore = 1;
			continue;
		case 'n':
			show = 1;
			continue;
		case 'v':
			notify = 2;
			continue;
		case 'F':
			if (stat(opt_info.arg, &st))
				error(ERROR_exit(1), "%s: cannot stat", opt_info.arg);
			mode = st.st_mode;
			amode = "";
			continue;
		case 'H':
			flags |= FTS_META|FTS_PHYSICAL;
			logical = 0;
			continue;
		case 'L':
			flags &= ~(FTS_META|FTS_PHYSICAL);
			logical = 0;
			continue;
		case 'P':
			flags &= ~FTS_META;
			flags |= FTS_PHYSICAL;
			logical = 0;
			continue;
		case 'R':
			flags &= ~FTS_TOP;
			logical = 0;
			continue;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || !*argv || !amode && !*(argv + 1))
		error(ERROR_usage(2), "%s", optusage(NiL));
	if (chlink)
	{
		flags &= ~FTS_META;
		flags |= FTS_PHYSICAL;
		logical = 0;
	}
	if (logical)
		flags &= ~(FTS_META|FTS_PHYSICAL);
	if (ignore)
		ignore = umask(0);
	if (amode)
		amode = 0;
	else
	{
		amode = *argv++;
		mode = strperm(amode, &last, 0);
		if (*last)
		{
			if (ignore)
				umask(ignore);
			error(ERROR_exit(1), "%s: invalid mode", amode);
		}
	}
	if (!(fts = fts_open(argv, flags, NiL)))
	{
		if (ignore)
			umask(ignore);
		error(ERROR_system(1), "%s: not found", *argv);
	}
	while (!sh_checksig(context) && (ent = fts_read(fts)))
		switch (ent->fts_info)
		{
		case FTS_SL:
		case FTS_SLNONE:
			if (chlink)
			{
#if _lib_lchmod
				chmodf = lchmod;
				goto commit;
#else
				if (!force)
				{
					errno = ENOSYS;
					error(ERROR_system(0), "%s: cannot change symlink mode", ent->fts_path);
				}
#endif
			}
			break;
		case FTS_F:
		case FTS_D:
		anyway:
			chmodf = chmod;
#if _lib_lchmod
		commit:
#endif
			if (amode)
				mode = strperm(amode, &last, ent->fts_statp->st_mode);
			if (show || (*chmodf)(ent->fts_accpath, mode) >= 0)
			{
				if (notify == 2 || notify == 1 && (mode&S_IPERM) != (ent->fts_statp->st_mode&S_IPERM))
					sfprintf(sfstdout, "%s: mode changed to %0.4o (%s)\n", ent->fts_path, mode, fmtmode(mode, 1)+1);
			}
			else if (!force)
				error(ERROR_system(0), "%s: cannot change mode", ent->fts_path);
			break;
		case FTS_DC:
			if (!force)
				error(ERROR_warn(0), "%s: directory causes cycle", ent->fts_path);
			break;
		case FTS_DNR:
			if (!force)
				error(ERROR_system(0), "%s: cannot read directory", ent->fts_path);
			goto anyway;
		case FTS_DNX:
			if (!force)
				error(ERROR_system(0), "%s: cannot search directory", ent->fts_path);
			goto anyway;
		case FTS_NS:
			if (!force)
				error(ERROR_system(0), "%s: not found", ent->fts_path);
			break;
		}
	fts_close(fts);
	if (ignore)
		umask(ignore);
	return error_info.errors != 0;
}
