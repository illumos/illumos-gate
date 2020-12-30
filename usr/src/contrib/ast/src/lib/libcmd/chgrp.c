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
 * chgrp+chown
 */

static const char usage_1[] =
"[-?@(#)$Id: chgrp (AT&T Research) 2012-04-20 $\n]"
USAGE_LICENSE
;

static const char usage_grp_1[] =
"[+NAME?chgrp - change the group ownership of files]"
"[+DESCRIPTION?\bchgrp\b changes the group ownership of each file"
"	to \agroup\a, which can be either a group name or a numeric"
"	group id. The user ownership of each file may also be changed to"
"	\auser\a by prepending \auser\a\b:\b to the group name.]"
;

static const char usage_own_1[] =
"[+NAME?chown - change the ownership of files]"
"[+DESCRIPTION?\bchown\b changes the ownership of each file"
"	to \auser\a, which can be either a user name or a numeric"
"	user id. The group ownership of each file may also be changed to"
"	\auser\a by appending \b:\b\agroup\a to the user name.]"
;

static const char usage_2[] =
"[b:before?Only change files with \bctime\b before (less than) the "
    "\bmtime\b of \afile\a.]:[file]"
"[c:changes?Describe only files whose ownership actually changes.]"
"[f:quiet|silent?Do not report files whose ownership fails to change.]"
"[h|l:symlink?Change the ownership of symbolic links on systems that "
    "support \blchown\b(2). Implies \b--physical\b.]"
"[m:map?The first operand is interpreted as a file that contains a map "
    "of space separated \afrom_uid:from_gid to_uid:to_gid\a pairs. The "
    "\auid\a or \agid\a part of each pair may be omitted to mean any \auid\a "
    "or \agid\a. Ownership of files matching the \afrom\a part of any pair "
    "is changed to the corresponding \ato\a part of the pair. The matching "
    "for each file operand is in the order \auid\a:\agid\a, \auid\a:, "
    ":\agid\a. For a given file, once a \auid\a or \agid\a mapping is "
    "determined it is not overridden by any subsequent match. Unmatched "
    "files are silently ignored.]"
"[n:show?Show actions but don't execute.]"
"[N:numeric?By default numeric user and group id operands are first "
    "interpreted as names; if no name exists then they are interpreted as "
    "explicit numeric ids. \b--numeric\b interprets numeric id operands as "
    "numeric ids.]"
"[r:reference?Omit the explicit ownership operand and use the ownership "
    "of \afile\a instead.]:[file]"
"[u:unmapped?Print a diagnostic for each file for which either the "
    "\auid\a or \agid\a or both were not mapped.]"
"[v:verbose?Describe changed permissions of all files.]"
"[H:metaphysical?Follow symbolic links for command arguments; otherwise "
    "don't follow symbolic links when traversing directories.]"
"[L:logical|follow?Follow symbolic links when traversing directories.]"
"[P:physical|nofollow?Don't follow symbolic links when traversing "
    "directories.]"
"[R:recursive?Recursively change ownership of directories and their "
    "contents.]"
"[X:test?Canonicalize output for testing.]"

"\n"
"\n"
;

static const char usage_3[] =
" file ...\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?All files changed successfully.]"
	"[+>0?Unable to change ownership of one or more files.]"
"}"
"[+SEE ALSO?\bchmod\b(1), \bchown\b(2), \btw\b(1), \bgetconf\b(1), \bls\b(1)]"
;

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide lchown
#else
#define lchown		______lchown
#endif

#include <cmd.h>
#include <cdt.h>
#include <ls.h>
#include <ctype.h>
#include <fts_fix.h>

#ifndef ENOSYS
#define ENOSYS	EINVAL
#endif

#include "FEATURE/symlink"

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide lchown
#else
#undef	lchown
#endif

typedef struct Key_s			/* uid/gid key			*/
{
	int		uid;		/* uid				*/
	int		gid;		/* gid				*/
} Key_t;

typedef struct Map_s			/* uid/gid map			*/
{
	Dtlink_t	link;		/* dictionary link		*/
	Key_t		key;		/* key				*/
	Key_t		to;		/* map to these			*/
} Map_t;

#define NOID		(-1)

#define OPT_CHOWN	0x0001		/* chown			*/
#define OPT_FORCE	0x0002		/* ignore errors		*/
#define OPT_GID		0x0004		/* have gid			*/
#define OPT_LCHOWN	0x0008		/* lchown			*/
#define OPT_NUMERIC	0x0010		/* favor numeric ids		*/
#define OPT_SHOW	0x0020		/* show but don't do		*/
#define OPT_TEST	0x0040		/* canonicalize output		*/
#define OPT_UID		0x0080		/* have uid			*/
#define OPT_UNMAPPED	0x0100		/* unmapped file diagnostic	*/
#define OPT_VERBOSE	0x0200		/* have uid			*/

extern int	lchown(const char*, uid_t, gid_t);

/*
 * parse uid and gid from s
 */

static void
getids(register char* s, char** e, Key_t* key, int options)
{
	register char*	t;
	register int	n;
	register int	m;
	char*		z;
	char		buf[64];

	key->uid = key->gid = NOID;
	while (isspace(*s))
		s++;
	for (t = s; (n = *t) && n != ':' && n != '.' && !isspace(n); t++);
	if (n)
	{
		options |= OPT_CHOWN;
		if ((n = t++ - s) >= sizeof(buf))
			n = sizeof(buf) - 1;
		*((s = (char*)memcpy(buf, s, n)) + n) = 0;
	}
	if (options & OPT_CHOWN)
	{
		if (*s)
		{
			n = (int)strtol(s, &z, 0);
			if (*z || !(options & OPT_NUMERIC))
			{
				if ((m = struid(s)) != NOID)
					n = m;
				else if (*z)
					error(ERROR_exit(1), "%s: unknown user", s);
			}
			key->uid = n;
		}
		for (s = t; (n = *t) && !isspace(n); t++);
		if (n)
		{
			if ((n = t++ - s) >= sizeof(buf))
				n = sizeof(buf) - 1;
			*((s = (char*)memcpy(buf, s, n)) + n) = 0;
		}
	}
	if (*s)
	{
		n = (int)strtol(s, &z, 0);
		if (*z || !(options & OPT_NUMERIC))
		{
			if ((m = strgid(s)) != NOID)
				n = m;
			else if (*z)
				error(ERROR_exit(1), "%s: unknown group", s);
		}
		key->gid = n;
	}
	if (e)
		*e = t;
}

/*
 * NOTE: we only use the native lchown() on symlinks just in case
 *	 the implementation is a feckless stub
 */

int
b_chgrp(int argc, char** argv, Shbltin_t* context)
{
	register int	options = 0;
	register char*	s;
	register Map_t*	m;
	register FTS*	fts;
	register FTSENT*ent;
	register int	i;
	Dt_t*		map = 0;
	int		logical = 1;
	int		flags;
	int		uid;
	int		gid;
	char*		op;
	char*		usage;
	char*		t;
	Sfio_t*		sp;
	unsigned long	before;
	Dtdisc_t	mapdisc;
	Key_t		keys[3];
	Key_t		key;
	struct stat	st;
	int		(*chownf)(const char*, uid_t, gid_t);

	cmdinit(argc, argv, context, ERROR_CATALOG, ERROR_NOTIFY);
	flags = fts_flags() | FTS_META | FTS_TOP | FTS_NOPOSTORDER | FTS_NOSEEDOTDIR;
	before = ~0;
	if (!(sp = sfstropen()))
		error(ERROR_SYSTEM|3, "out of space");
	sfputr(sp, usage_1, -1);
	if (error_info.id[2] == 'g')
		sfputr(sp, usage_grp_1, -1);
	else
	{
		sfputr(sp, usage_own_1, -1);
		options |= OPT_CHOWN;
	}
	sfputr(sp, usage_2, -1);
	if (options & OPT_CHOWN)
		sfputr(sp, ERROR_translate(0, 0, 0, "[owner[:group]]"), -1);
	else
		sfputr(sp, ERROR_translate(0, 0, 0, "[[owner:]group]"), -1);
	sfputr(sp, usage_3, -1);
	if (!(usage = sfstruse(sp)))
		error(ERROR_SYSTEM|3, "out of space");
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'b':
			if (stat(opt_info.arg, &st))
				error(ERROR_exit(1), "%s: cannot stat", opt_info.arg);
			before = st.st_mtime;
			continue;
		case 'c':
		case 'v':
			options |= OPT_VERBOSE;
			continue;
		case 'f':
			options |= OPT_FORCE;
			continue;
		case 'h':
			options |= OPT_LCHOWN;
			continue;
		case 'm':
			memset(&mapdisc, 0, sizeof(mapdisc));
			mapdisc.key = offsetof(Map_t, key);
			mapdisc.size = sizeof(Key_t);
			if (!(map = dtopen(&mapdisc, Dtset)))
				error(ERROR_exit(1), "out of space [id map]");
			continue;
		case 'n':
			options |= OPT_SHOW;
			continue;
		case 'N':
			options |= OPT_NUMERIC;
			continue;
		case 'r':
			if (stat(opt_info.arg, &st))
				error(ERROR_exit(1), "%s: cannot stat", opt_info.arg);
			uid = st.st_uid;
			gid = st.st_gid;
			options |= OPT_UID|OPT_GID;
			continue;
		case 'u':
			options |= OPT_UNMAPPED;
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
		case 'X':
			options |= OPT_TEST;
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if (error_info.errors || argc < 2)
		error(ERROR_usage(2), "%s", optusage(NiL));
	s = *argv;
	if (options & OPT_LCHOWN)
	{
		flags &= ~FTS_META;
		flags |= FTS_PHYSICAL;
		logical = 0;
	}
	if (logical)
		flags &= ~(FTS_META|FTS_PHYSICAL);
	if (map)
	{
		if (streq(s, "-"))
			sp = sfstdin;
		else if (!(sp = sfopen(NiL, s, "r")))
			error(ERROR_exit(1), "%s: cannot read", s);
		while (s = sfgetr(sp, '\n', 1))
		{
			getids(s, &t, &key, options);
			if (!(m = (Map_t*)dtmatch(map, &key)))
			{
				if (!(m = (Map_t*)stakalloc(sizeof(Map_t))))
					error(ERROR_exit(1), "out of space [id dictionary]");
				m->key = key;
				m->to.uid = m->to.gid = NOID;
				dtinsert(map, m);
			}
			getids(t, NiL, &m->to, options);
		}
		if (sp != sfstdin)
			sfclose(sp);
		keys[1].gid = keys[2].uid = NOID;
	}
	else if (!(options & (OPT_UID|OPT_GID)))
	{
		getids(s, NiL, &key, options);
		if ((uid = key.uid) != NOID)
			options |= OPT_UID;
		if ((gid = key.gid) != NOID)
			options |= OPT_GID;
	}
	switch (options & (OPT_UID|OPT_GID))
	{
	case OPT_UID:
		s = ERROR_translate(0, 0, 0, " owner");
		break;
	case OPT_GID:
		s = ERROR_translate(0, 0, 0, " group");
		break;
	case OPT_UID|OPT_GID:
		s = ERROR_translate(0, 0, 0, " owner and group");
		break;
	default:
		s = "";
		break;
	}
	if (!(fts = fts_open(argv + 1, flags, NiL)))
		error(ERROR_system(1), "%s: not found", argv[1]);
	while (!sh_checksig(context) && (ent = fts_read(fts)))
		switch (ent->fts_info)
		{
		case FTS_SL:
		case FTS_SLNONE:
			if (options & OPT_LCHOWN)
			{
#if _lib_lchown
				chownf = lchown;
				op = "lchown";
				goto commit;
#else
				if (!(options & OPT_FORCE))
				{
					errno = ENOSYS;
					error(ERROR_system(0), "%s: cannot change symlink owner/group", ent->fts_path);
				}
#endif
			}
			break;
		case FTS_F:
		case FTS_D:
		anyway:
			chownf = chown;
			op = "chown";
		commit:
			if ((unsigned long)ent->fts_statp->st_ctime >= before)
				break;
			if (map)
			{
				options &= ~(OPT_UID|OPT_GID);
				uid = gid = NOID;
				keys[0].uid = keys[1].uid = ent->fts_statp->st_uid;
				keys[0].gid = keys[2].gid = ent->fts_statp->st_gid;
				i = 0;
				do
				{
					if (m = (Map_t*)dtmatch(map, &keys[i]))
					{
						if (uid == NOID && m->to.uid != NOID)
						{
							uid = m->to.uid;
							options |= OPT_UID;
						}
						if (gid == NOID && m->to.gid != NOID)
						{
							gid = m->to.gid;
							options |= OPT_GID;
						}
					}
				} while (++i < elementsof(keys) && (uid == NOID || gid == NOID));
			}
			else
			{
				if (!(options & OPT_UID))
					uid = ent->fts_statp->st_uid;
				if (!(options & OPT_GID))
					gid = ent->fts_statp->st_gid;
			}
			if ((options & OPT_UNMAPPED) && (uid == NOID || gid == NOID))
			{
				if (uid == NOID && gid == NOID)
					error(ERROR_warn(0), "%s: uid and gid not mapped", ent->fts_path);
				else if (uid == NOID)
					error(ERROR_warn(0), "%s: uid not mapped", ent->fts_path);
				else
					error(ERROR_warn(0), "%s: gid not mapped", ent->fts_path);
			}
			if (uid != ent->fts_statp->st_uid && uid != NOID || gid != ent->fts_statp->st_gid && gid != NOID)
			{
				if (options & (OPT_SHOW|OPT_VERBOSE))
				{
					if (options & OPT_TEST)
					{
						ent->fts_statp->st_uid = 0;
						ent->fts_statp->st_gid = 0;
					}
					sfprintf(sfstdout, "%s uid:%05d->%05d gid:%05d->%05d %s\n", op, ent->fts_statp->st_uid, uid, ent->fts_statp->st_gid, gid, ent->fts_path);
				}
				if (!(options & OPT_SHOW) && (*chownf)(ent->fts_accpath, uid, gid) && !(options & OPT_FORCE))
					error(ERROR_system(0), "%s: cannot change%s", ent->fts_path, s);
			}
			break;
		case FTS_DC:
			if (!(options & OPT_FORCE))
				error(ERROR_warn(0), "%s: directory causes cycle", ent->fts_path);
			break;
		case FTS_DNR:
			if (!(options & OPT_FORCE))
				error(ERROR_system(0), "%s: cannot read directory", ent->fts_path);
			goto anyway;
		case FTS_DNX:
			if (!(options & OPT_FORCE))
				error(ERROR_system(0), "%s: cannot search directory", ent->fts_path);
			goto anyway;
		case FTS_NS:
			if (!(options & OPT_FORCE))
				error(ERROR_system(0), "%s: not found", ent->fts_path);
			break;
		}
	fts_close(fts);
	if (map)
		dtclose(map);
	return error_info.errors != 0;
}
