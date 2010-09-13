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
 * Glenn Fowler
 * AT&T Research
 *
 * chgrp+chown
 */

static const char usage_1[] =
"[-?@(#)$Id: chgrp (AT&T Research) 2009-07-02 $\n]"
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
"[l|h:symlink?Change the ownership of the symbolic links on systems that "
    "support this.]"
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
"[+SEE ALSO?\bchmod\b(1), \btw\b(1), \bgetconf\b(1), \bls\b(1)]"
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

#define OPT_CHOWN	(1<<0)		/* chown			*/
#define OPT_FORCE	(1<<1)		/* ignore errors		*/
#define OPT_GID		(1<<2)		/* have gid			*/
#define OPT_LCHOWN	(1<<3)		/* lchown			*/
#define OPT_SHOW	(1<<4)		/* show but don't do		*/
#define OPT_TEST	(1<<5)		/* canonicalize output		*/
#define OPT_UID		(1<<6)		/* have uid			*/
#define OPT_UNMAPPED	(1<<7)		/* unmapped file diagnostic	*/
#define OPT_VERBOSE	(1<<8)		/* have uid			*/

extern int	lchown(const char*, uid_t, gid_t);

#if !_lib_lchown

#ifndef ENOSYS
#define ENOSYS	EINVAL
#endif

int
lchown(const char* path, uid_t uid, gid_t gid)
{
	return ENOSYS;
}

#endif /* _lib_chown */

/*
 * parse uid and gid from s
 */

static void
getids(register char* s, char** e, Key_t* key, int options)
{
	register char*	t;
	register int	n;
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
			if ((n = struid(s)) == NOID)
			{
				n = (int)strtol(s, &z, 0);
				if (*z)
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
		if ((n = strgid(s)) == NOID)
		{
			n = (int)strtol(s, &z, 0);
			if (*z)
				error(ERROR_exit(1), "%s: unknown group", s);
		}
		key->gid = n;
	}
	if (e)
		*e = t;
}

int
b_chgrp(int argc, char** argv, void* context)
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
	flags = fts_flags() | FTS_TOP | FTS_NOPOSTORDER | FTS_NOSEEDOTDIR;
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
		case 'l':
			options |= OPT_LCHOWN;
			continue;
		case 'm':
			memset(&mapdisc, 0, sizeof(mapdisc));
			mapdisc.key = offsetof(Map_t, key);
			mapdisc.size = sizeof(Key_t);
			if (!(map = dtopen(&mapdisc, Dthash)))
				error(ERROR_exit(1), "out of space [id map]");
			continue;
		case 'n':
			options |= OPT_SHOW;
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
		case FTS_F:
		case FTS_D:
		case FTS_SL:
		case FTS_SLNONE:
		anyway:
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
				if ((ent->fts_info & FTS_SL) && (flags & FTS_PHYSICAL) && (options & OPT_LCHOWN))
				{
					op = "lchown";
					chownf = lchown;
				}
				else
				{
					op = "chown";
					chownf = chown;
				}
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
					error(ERROR_system(0), "%s: cannot change%s", ent->fts_accpath, s);
			}
			break;
		case FTS_DC:
			if (!(options & OPT_FORCE))
				error(ERROR_warn(0), "%s: directory causes cycle", ent->fts_accpath);
			break;
		case FTS_DNR:
			if (!(options & OPT_FORCE))
				error(ERROR_system(0), "%s: cannot read directory", ent->fts_accpath);
			goto anyway;
		case FTS_DNX:
			if (!(options & OPT_FORCE))
				error(ERROR_system(0), "%s: cannot search directory", ent->fts_accpath);
			goto anyway;
		case FTS_NS:
			if (!(options & OPT_FORCE))
				error(ERROR_system(0), "%s: not found", ent->fts_accpath);
			break;
		}
	fts_close(fts);
	if (map)
		dtclose(map);
	return error_info.errors != 0;
}
