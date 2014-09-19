/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_statfs.h>
#include <sys/lx_syscall.h>

/*
 * these defines must exist before we include regexp.h, see regexp(5)
 */
#define	RE_SIZE		1024
#define	INIT		char *sp = instring;
#define	GETC()		(*sp++)
#define	PEEKC()		(*sp)
#define	UNGETC(c)	(--sp)
#define	RETURN(c)	return (NULL);
#define	ERROR(c)	return ((char *)c);

/*
 * for regular expressions we're using regexp(5).
 *
 * we'd really prefer to use some other nicer regular expressions
 * interfaces (like regcmp(3c), regcomp(3c), or re_comp(3c)) but we
 * can't because all these other interfaces rely on the ability
 * to allocate memory via libc malloc()/calloc() calls, which
 * we can't really do here.
 *
 * we could optionally use regexpr(3gen) but we don't since the
 * interfaces there are incredibly similar to the regexp(5)
 * interfaces we're already using and we'd have the added
 * requirement of linking against libgen.
 *
 * another option that was considered is fnmatch(3c) but the
 * limited pattern expansion capability of this interface would
 * force us to include more patterns to check against.
 */
#include <regexp.h>

static struct lx_ftype_path {
	char		*lfp_path;
	char		lfp_re[RE_SIZE];
	int		lfp_magic;
	char		*lfp_magic_str;
} ftype_path_list[] = {
	{ "^/dev/pts$",		"",
		LX_DEVPTS_SUPER_MAGIC,	"LX_DEVPTS_SUPER_MAGIC"	},
	{ "^/dev/pts/$",	"",
		LX_DEVPTS_SUPER_MAGIC,	"LX_DEVPTS_SUPER_MAGIC"	},
	{ "^/dev/pts/[0-9][0-9]*$",	"",
		LX_DEVPTS_SUPER_MAGIC,	"LX_DEVPTS_SUPER_MAGIC"	},
	{ NULL,			"",
		0,			NULL			}
};

/*
 * For lack of linux equivalents, we present lofs and zfs as being ufs.
 */
static struct lx_ftype_name {
	const char	*lfn_name;
	int		lfn_magic;
	char		*lfn_magic_str;
} ftype_name_list[] = {
	{ "hsfs",	LX_ISOFS_SUPER_MAGIC,	"LX_ISOFS_SUPER_MAGIC"	},
	{ "nfs",	LX_NFS_SUPER_MAGIC,	"LX_NFS_SUPER_MAGIC"	},
	{ "pcfs",	LX_MSDOS_SUPER_MAGIC,	"LX_MSDOS_SUPER_MAGIC"	},
	{ "lx_proc",	LX_PROC_SUPER_MAGIC,	"LX_PROC_SUPER_MAGIC"	},
	{ "tmpfs",	LX_TMPFS_SUPER_MAGIC,	"LX_TMPFS_SUPER_MAGIC"	},
	{ "ufs",	LX_UFS_MAGIC,		"LX_UFS_MAGIC"		},
	{ "lofs",	LX_UFS_MAGIC,		"LX_UFS_MAGIC"		},
	{ "zfs",	LX_UFS_MAGIC,		"LX_UFS_MAGIC"		},
	{ NULL,		0,			NULL	}
};

int
lx_statfs_init()
{
	int	i;
	char	*rv;

	for (i = 0; ftype_path_list[i].lfp_path != NULL; i++) {
		rv = compile(
		    ftype_path_list[i].lfp_path,
		    ftype_path_list[i].lfp_re,
		    ftype_path_list[i].lfp_re + RE_SIZE, '\0');
		if (rv == NULL)
			continue;

		lx_debug("lx_statfs_init compile(\"%s\") failed",
		    ftype_path_list[i].lfp_path);
		return (1);
	}
	return (0);
}

static int
stol_type(const char *path, const char *name)
{
	int	i;
	lx_debug("\tstol_type(\"%s\", \"%s\")\n", path == NULL ? "NULL" : path,
	    name == NULL ? "NULL" : name);

	if (path != NULL) {
		char userpath[MAXPATHLEN];

		if (uucopystr(path, userpath, MAXPATHLEN) == -1)
			return (-errno);

		for (i = 0; ftype_path_list[i].lfp_path != NULL; i++) {
			if (step(userpath, ftype_path_list[i].lfp_re) == 0)
				continue;

			/* got a match on the fs path */
			lx_debug("\ttranslated f_type to 0x%x - %s",
			    ftype_path_list[i].lfp_magic,
			    ftype_path_list[i].lfp_magic_str);
			return (ftype_path_list[i].lfp_magic);
		}
	}

	assert(name != NULL);
	for (i = 0; ftype_name_list[i].lfn_name != NULL; i++) {
		if (strcmp(name, ftype_name_list[i].lfn_name) == 0) {

			/* got a match on the fs name */
			lx_debug("\ttranslated f_type to 0x%x - %s",
			    ftype_name_list[i].lfn_magic,
			    ftype_name_list[i].lfn_magic_str);
			return (ftype_name_list[i].lfn_magic);
		}
	}

	/* we don't know what the fs type is so just set it to 0 */
	return (0);
}

/*
 * The Linux statfs() is similar to the Solaris statvfs() call, the main
 * difference being the use of a numeric 'f_type' identifier instead of the
 * 'f_basetype' string.
 */
static int
stol_statfs(const char *path, struct lx_statfs *l, struct statvfs *s)
{
	int type;

	if ((type = stol_type(path, s->f_basetype)) < 0)
		return (type);

	l->f_type = type;
	l->f_bsize = s->f_frsize;	/* other fields depend on frsize */
	l->f_blocks = s->f_blocks;
	l->f_bfree = s->f_bfree;
	l->f_bavail = s->f_bavail;
	l->f_files = s->f_files;
	l->f_ffree = s->f_ffree;
	l->f_fsid = s->f_fsid;
	l->f_namelen = s->f_namemax;
	l->f_frsize = s->f_frsize;
	bzero(&(l->f_spare), sizeof (l->f_spare));

	return (0);
}

static int
stol_statfs64(const char *path, struct lx_statfs64 *l, struct statvfs64 *s)
{
	int type;

	if ((type = stol_type(path, s->f_basetype)) < 0)
		return (type);

	l->f_type = type;
	l->f_bsize = s->f_frsize;	/* other fields depend on frsize */
	l->f_blocks = s->f_blocks;
	l->f_bfree = s->f_bfree;
	l->f_bavail = s->f_bavail;
	l->f_files = s->f_files;
	l->f_ffree = s->f_ffree;
	l->f_fsid = s->f_fsid;
	l->f_namelen = s->f_namemax;
	l->f_frsize = s->f_frsize;
	bzero(&(l->f_spare), sizeof (l->f_spare));

	return (0);
}

long
lx_statfs(uintptr_t p1, uintptr_t p2)
{
	const char *path = (const char *)p1;
	struct lx_statfs lxfs, *fs = (struct lx_statfs *)p2;
	struct statvfs vfs;
	int err;

	lx_debug("\tfstatvfs(%s, 0x%p)", path, fs);
	if (statvfs(path, &vfs) != 0)
		return (-errno);

	if ((err = stol_statfs(path, &lxfs, &vfs)) != 0)
		return (err);

	if (uucopy(&lxfs, fs, sizeof (struct lx_statfs)) != 0)
		return (-errno);

	return (0);
}

long
lx_fstatfs(uintptr_t p1, uintptr_t p2)
{
	struct lx_statfs lxfs, *fs = (struct lx_statfs *)p2;
	struct stat64 sb;
	struct statvfs vfs;
	char *path, path_buf[MAXPATHLEN];
	int fd = (int)p1;
	int err;

	lx_debug("\tfstatvfs(%d, 0x%p)", fd, fs);

	/*
	 * fstatfs emulation for a pipe.
	 */
	if (fstat64(fd, &sb) == 0 && S_ISFIFO(sb.st_mode)) {
		lxfs.f_type = LX_PIPEFS_MAGIC;
		lxfs.f_bsize = 4096;
		lxfs.f_blocks = 0;
		lxfs.f_bfree = 0;
		lxfs.f_bavail = 0;
		lxfs.f_files = 0;
		lxfs.f_ffree = 0;
		lxfs.f_fsid = 0;
		lxfs.f_namelen = 255;
		lxfs.f_frsize = 4096;
	} else {
		if (fstatvfs(fd, &vfs) != 0)
			return (-errno);

		path = lx_fd_to_path(fd, path_buf, sizeof (path_buf));

		if ((err = stol_statfs(path, &lxfs, &vfs)) != 0)
			return (err);
	}

	if (uucopy(&lxfs, fs, sizeof (struct lx_statfs)) != 0)
		return (-errno);

	return (0);
}

/* ARGSUSED */
long
lx_statfs64(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	const char *path = (const char *)p1;
	struct lx_statfs64 lxfs, *fs = (struct lx_statfs64 *)p3;
	struct statvfs64 vfs;
	int err;

	lx_debug("\tstatvfs64(%s, %d, 0x%p)", path, p2, fs);
	if (statvfs64(path, &vfs) != 0)
		return (-errno);

	if ((err = stol_statfs64(path, &lxfs, &vfs)) != 0)
		return (err);

	if (uucopy(&lxfs, fs, sizeof (struct lx_statfs64)) != 0)
		return (-errno);

	return (0);
}

/* ARGSUSED */
long
lx_fstatfs64(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	struct lx_statfs64 lxfs, *fs = (struct lx_statfs64 *)p3;
	struct stat64 sb;
	struct statvfs64 vfs;
	char *path, path_buf[MAXPATHLEN];
	int fd = (int)p1;
	int err;

	lx_debug("\tfstatvfs64(%d, %d, 0x%p)", fd, p2, fs);
	if (fstat64(fd, &sb) == 0 && S_ISFIFO(sb.st_mode)) {
		lxfs.f_type = LX_PIPEFS_MAGIC;
		lxfs.f_bsize = 4096;
		lxfs.f_blocks = 0;
		lxfs.f_bfree = 0;
		lxfs.f_bavail = 0;
		lxfs.f_files = 0;
		lxfs.f_ffree = 0;
		lxfs.f_fsid = 0;
		lxfs.f_namelen = 255;
		lxfs.f_frsize = 4096;
	} else {
		if (fstatvfs64(fd, &vfs) != 0)
			return (-errno);

		path = lx_fd_to_path(fd, path_buf, sizeof (path_buf));

		if ((err = stol_statfs64(path, &lxfs, &vfs)) != 0)
			return (err);
	}

	if (uucopy(&lxfs, fs, sizeof (struct lx_statfs64)) != 0)
		return (-errno);

	return (0);
}
