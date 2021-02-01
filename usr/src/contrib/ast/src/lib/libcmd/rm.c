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
 * Glenn Fowler
 * AT&T Research
 *
 * rm [-fir] [file ...]
 */

static const char usage[] =
"[-?\n@(#)$Id: rm (AT&T Research) 2012-02-14 $\n]"
USAGE_LICENSE
"[+NAME?rm - remove files]"
"[+DESCRIPTION?\brm\b removes the named \afile\a arguments. By default it"
"	does not remove directories. If a file is unwritable, the"
"	standard input is a terminal, and the \b--force\b option is not"
"	given, \brm\b prompts the user for whether to remove the file."
"	An affirmative response (\by\b or \bY\b) removes the file, a quit"
"	response (\bq\b or \bQ\b) causes \brm\b to exit immediately, and"
"	all other responses skip the current file.]"

"[c|F:clear|clobber?Clear the contents of each file before removing by"
"	writing a 0 filled buffer the same size as the file, executing"
"	\bfsync\b(2) and closing before attempting to remove. Implemented"
"	only on systems that support \bfsync\b(2).]"
"[d:directory?\bremove\b(3) (or \bunlink\b(2)) directories rather than"
"	\brmdir\b(2), and don't require that they be empty before removal."
"	The caller requires sufficient privilege, not to mention a strong"
"	constitution, to use this option. Even though the directory must"
"	not be empty, \brm\b still attempts to empty it before removal.]"
"[f:force?Ignore nonexistent files, ignore no file operands specified,"
"	and never prompt the user.]"
"[i:interactive|prompt?Prompt whether to remove each file."
"	An affirmative response (\by\b or \bY\b) removes the file, a quit"
"	response (\bq\b or \bQ\b) causes \brm\b to exit immediately, and"
"	all other responses skip the current file.]"
"[r|R:recursive?Remove the contents of directories recursively.]"
"[u:unconditional?If \b--recursive\b and \b--force\b are also enabled then"
"	the owner read, write and execute modes are enabled (if not already"
"	enabled) for each directory before attempting to remove directory"
"	contents.]"
"[v:verbose?Print the name of each file before removing it.]"

"\n"
"\nfile ...\n"
"\n"

"[+SEE ALSO?\bmv\b(1), \brmdir\b(2), \bunlink\b(2), \bremove\b(3)]"
;

#include <cmd.h>
#include <ls.h>
#include <fts_fix.h>
#include <fs3d.h>

#define RM_ENTRY	1

#define beenhere(f)	(((f)->fts_number>>1)==(f)->fts_statp->st_nlink)
#define isempty(f)	(!((f)->fts_number&RM_ENTRY))
#define nonempty(f)	((f)->fts_parent->fts_number|=RM_ENTRY)
#define pathchunk(n)	roundof(n,1024)
#define retry(f)	((f)->fts_number=((f)->fts_statp->st_nlink<<1))

typedef struct State_s			/* program state		*/
{
	Shbltin_t*	context;	/* builtin context		*/
	int		clobber;	/* clear out file data first	*/
	int		directory;	/* remove(dir) not rmdir(dir)	*/
	int		force;		/* force actions		*/
	int		fs3d;		/* 3d enabled			*/
	int		interactive;	/* prompt for approval		*/
	int		recursive;	/* remove subtrees too		*/
	int		terminal;	/* attached to terminal		*/
	int		uid;		/* caller uid			*/
	int		unconditional;	/* enable dir rwx on preorder	*/
	int		verbose;	/* display each file		*/
#if _lib_fsync
	char		buf[SF_BUFSIZE];/* clobber buffer		*/
#endif
} State_t;

/*
 * remove a single file
 */

static int
rm(State_t* state, register FTSENT* ent)
{
	register char*	path;
	register int	n;
	int		v;
	struct stat	st;

	if (ent->fts_info == FTS_NS || ent->fts_info == FTS_ERR || ent->fts_info == FTS_SLNONE)
	{
		if (!state->force)
			error(2, "%s: not found", ent->fts_path);
	}
	else if (state->fs3d && iview(ent->fts_statp))
		fts_set(NiL, ent, FTS_SKIP);
	else switch (ent->fts_info)
	{
	case FTS_DNR:
	case FTS_DNX:
		if (state->unconditional)
		{
			if (!beenhere(ent))
				break;
			if (!chmod(ent->fts_name, (ent->fts_statp->st_mode & S_IPERM)|S_IRWXU))
			{
				fts_set(NiL, ent, FTS_AGAIN);
				break;
			}
			error_info.errors++;
		}
		else if (!state->force)
			error(2, "%s: cannot %s directory", ent->fts_path, (ent->fts_info & FTS_NR) ? "read" : "search");
		else
			error_info.errors++;
		fts_set(NiL, ent, FTS_SKIP);
		nonempty(ent);
		break;
	case FTS_D:
	case FTS_DC:
		path = ent->fts_name;
		if (path[0] == '.' && (!path[1] || path[1] == '.' && !path[2]) && (ent->fts_level > 0 || path[1]))
		{
			fts_set(NiL, ent, FTS_SKIP);
			if (!state->force)
				error(2, "%s: cannot remove", ent->fts_path);
			else
				error_info.errors++;
			break;
		}
		if (!state->recursive)
		{
			fts_set(NiL, ent, FTS_SKIP);
			error(2, "%s: directory", ent->fts_path);
			break;
		}
		if (!beenhere(ent))
		{
			if (state->unconditional && (ent->fts_statp->st_mode & S_IRWXU) != S_IRWXU)
				chmod(path, (ent->fts_statp->st_mode & S_IPERM)|S_IRWXU);
			if (ent->fts_level > 0)
			{
				char*	s;

				if (ent->fts_accpath == ent->fts_name || !(s = strrchr(ent->fts_accpath, '/')))
					v = !stat(".", &st);
				else
				{
					path = ent->fts_accpath;
					*s = 0;
					v = !stat(path, &st);
					*s = '/';
				}
				if (v)
					v = st.st_nlink <= 2 || st.st_ino == ent->fts_parent->fts_statp->st_ino && st.st_dev == ent->fts_parent->fts_statp->st_dev || strchr(astconf("PATH_ATTRIBUTES", path, NiL), 'l');
			}
			else
				v = 1;
			if (v)
			{
				if (state->interactive)
				{
					if ((v = astquery(-1, "remove directory %s? ", ent->fts_path)) < 0 || sh_checksig(state->context))
						return -1;
					if (v > 0)
					{
						fts_set(NiL, ent, FTS_SKIP);
						nonempty(ent);
					}
				}
				if (ent->fts_info == FTS_D)
					break;
			}
			else
			{
				ent->fts_info = FTS_DC;
				error(1, "%s: hard link to directory", ent->fts_path);
			}
		}
		else if (ent->fts_info == FTS_D)
			break;
		/*FALLTHROUGH*/
	case FTS_DP:
		if (isempty(ent) || state->directory)
		{
			path = ent->fts_name;
			if (path[0] != '.' || path[1])
			{
				path = ent->fts_accpath;
				if (state->verbose)
					sfputr(sfstdout, ent->fts_path, '\n');
				if ((ent->fts_info == FTS_DC || state->directory) ? remove(path) : rmdir(path))
					switch (errno)
					{
					case ENOENT:
						break;
					case EEXIST:
#if defined(ENOTEMPTY) && (ENOTEMPTY) != (EEXIST)
					case ENOTEMPTY:
#endif
						if (ent->fts_info == FTS_DP && !beenhere(ent))
						{
							retry(ent);
							fts_set(NiL, ent, FTS_AGAIN);
							break;
						}
						/*FALLTHROUGH*/
					default:
						nonempty(ent);
						if (!state->force)
							error(ERROR_SYSTEM|2, "%s: directory not removed", ent->fts_path);
						else
							error_info.errors++;
						break;
					}
			}
			else if (!state->force)
				error(2, "%s: cannot remove", ent->fts_path);
			else
				error_info.errors++;
		}
		else
		{
			nonempty(ent);
			if (!state->force)
				error(2, "%s: directory not removed", ent->fts_path);
			else
				error_info.errors++;
		}
		break;
	default:
		path = ent->fts_accpath;
		if (state->verbose)
			sfputr(sfstdout, ent->fts_path, '\n');
		if (state->interactive)
		{
			if ((v = astquery(-1, "remove %s? ", ent->fts_path)) < 0 || sh_checksig(state->context))
				return -1;
			if (v > 0)
			{
				nonempty(ent);
				break;
			}
		}
		else if (!(ent->fts_info & FTS_SL) && !state->force && state->terminal && eaccess(path, W_OK))
		{
			if ((v = astquery(-1, "override protection %s for %s? ",
#ifdef ETXTBSY
				errno == ETXTBSY ? "``running program''" : 
#endif
				ent->fts_statp->st_uid != state->uid ? "``not owner''" :
				fmtmode(ent->fts_statp->st_mode & S_IPERM, 0) + 1, ent->fts_path)) < 0 ||
			    sh_checksig(state->context))
				return -1;
			if (v > 0)
			{
				nonempty(ent);
				break;
			}
		}
#if _lib_fsync
		if (state->clobber && S_ISREG(ent->fts_statp->st_mode) && ent->fts_statp->st_size > 0)
		{
			if ((n = open(path, O_WRONLY|O_cloexec)) < 0)
				error(ERROR_SYSTEM|2, "%s: cannot clear data", ent->fts_path);
			else
			{
				off_t		c = ent->fts_statp->st_size;

				for (;;)
				{
					if (write(n, state->buf, sizeof(state->buf)) != sizeof(state->buf))
					{
						error(ERROR_SYSTEM|2, "%s: data clear error", ent->fts_path);
						break;
					}
					if (c <= sizeof(state->buf))
						break;
					c -= sizeof(state->buf);
				}
				fsync(n);
				close(n);
			}
		}
#endif
		if (remove(path))
		{
			nonempty(ent);
			switch (errno)
			{
			case ENOENT:
				break;
			default:
				if (!state->force || state->interactive)
					error(ERROR_SYSTEM|2, "%s: not removed", ent->fts_path);
				else
					error_info.errors++;
				break;
			}
		}
		break;
	}
	return 0;
}

int
b_rm(int argc, register char** argv, Shbltin_t* context)
{
	State_t		state;
	FTS*		fts;
	FTSENT*		ent;
	int		set3d;

	cmdinit(argc, argv, context, ERROR_CATALOG, ERROR_NOTIFY);
	memset(&state, 0, sizeof(state));
	state.context = context;
	state.fs3d = fs3d(FS3D_TEST);
	state.terminal = isatty(0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'd':
			state.directory = 1;
			continue;
		case 'f':
			state.force = 1;
			state.interactive = 0;
			continue;
		case 'i':
			state.interactive = 1;
			state.force = 0;
			continue;
		case 'r':
		case 'R':
			state.recursive = 1;
			continue;
		case 'F':
#if _lib_fsync
			state.clobber = 1;
#else
			error(1, "%s not implemented on this system", opt_info.name);
#endif
			continue;
		case 'u':
			state.unconditional = 1;
			continue;
		case 'v':
			state.verbose = 1;
			continue;
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			break;
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (*argv && streq(*argv, "-") && !streq(*(argv - 1), "--"))
		argv++;
	if (error_info.errors || !*argv && !state.force)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	if (!*argv)
		return 0;

	/*
	 * do it
	 */

	if (state.interactive)
		state.verbose = 0;
	state.uid = geteuid();
	state.unconditional = state.unconditional && state.recursive && state.force;
	if (state.recursive && state.fs3d)
	{
		set3d = state.fs3d;
		state.fs3d = 0;
		fs3d(0);
	}
	else
		set3d = 0;
	if (fts = fts_open(argv, FTS_PHYSICAL, NiL))
	{
		while (!sh_checksig(context) && (ent = fts_read(fts)) && !rm(&state, ent));
		fts_close(fts);
	}
	else if (!state.force)
		error(ERROR_SYSTEM|2, "%s: cannot remove", argv[0]);
	if (set3d)
		fs3d(set3d);
	return error_info.errors != 0;
}
