/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include <ast.h>
#include <ls.h>

#if _lib_statvfs

NoN(statvfs)

#else

#include <error.h>

#define HUH	(-1)

#if _lib_statfs && _mem_f_files_statfs && ( _sys_statfs || _sys_vfs || _sys_mount )

#if _sys_statfs
#include <sys/statfs.h>
#else
#if _sys_vfs
#include <sys/vfs.h>
#else
#if _sys_mount
#if _lib_getmntinfo
#include <sys/param.h>		/* expect some macro redefinitions here */
#endif
#include <sys/mount.h>
#endif
#endif
#endif

#if _lib_statfs4
#define FSTATFS(a,b)	fstatfs(a,b,sizeof(struct statfs),0)
#define STATFS(a,b)	statfs(a,b,sizeof(struct statfs),0)
#else
#define FSTATFS(a,b)	fstatfs(a,b)
#define STATFS(a,b)	statfs(a,b)
#endif

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

static void
us2v(register struct statfs* ufs, register struct stat* st, register struct statvfs* vfs)
{
	memset(vfs, 0, sizeof(*vfs));
	vfs->f_bsize = vfs->f_frsize = ufs->f_bsize;
	vfs->f_blocks = ufs->f_blocks;
	vfs->f_bfree = ufs->f_bfree;
	vfs->f_bavail =
#if _mem_f_bavail_statfs
		ufs->f_bavail;
#else
		ufs->f_bfree;
#endif
	vfs->f_files = ufs->f_files;
	vfs->f_ffree = ufs->f_ffree;
	vfs->f_favail = (ufs->f_ffree > 10) ? (ufs->f_ffree - 10) : 0;
	vfs->f_fsid = st->st_dev;
	strlcpy(vfs->f_basetype, FS_default, sizeof(vfs->f_basetype) - 1);
	vfs->f_namemax = 14;
	strlcpy(vfs->f_fstr, vfs->f_basetype, sizeof(vfs->f_fstr) - 1);
}

extern int
fstatvfs(int fd, struct statvfs* vfs)
{
	struct statfs	ufs;
	struct stat	st;

	if (FSTATFS(fd, &ufs) || fstat(fd, &st))
		return(-1);
	us2v(&ufs, &st, vfs);
	return(0);
}

extern int
statvfs(const char* path, struct statvfs* vfs)
{
	struct statfs	ufs;
	struct stat	st;

	if (STATFS(path, &ufs) || stat(path, &st))
		return(-1);
	us2v(&ufs, &st, vfs);
	return(0);
}

#else

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

static void
s2v(register struct stat* st, register struct statvfs* vfs)
{
	memset(vfs, 0, sizeof(*vfs));
	vfs->f_bsize = vfs->f_frsize =
#if _mem_st_blksize_stat
		st->st_blksize;
#else
		512;
#endif
	vfs->f_blocks = HUH;
	vfs->f_bfree = HUH;
	vfs->f_files = HUH;
	vfs->f_ffree = HUH;
	vfs->f_favail = HUH;
	vfs->f_fsid = st->st_dev;
	strlcpy(vfs->f_basetype, FS_default, sizeof(vfs->f_basetype));
	vfs->f_namemax = 14;
	strlcpy(vfs->f_fstr, vfs->f_basetype, sizeof(vfs->f_fstr));
}

extern int
fstatvfs(int fd, struct statvfs* vfs)
{
	struct stat	st;

	if (fstat(fd, &st))
		return(-1);
	s2v(&st, vfs);
	return(0);
}

extern int
statvfs(const char* path, struct statvfs* vfs)
{
	struct stat	st;

	if (stat(path, &st))
		return(-1);
	s2v(&st, vfs);
	return(0);
}

#endif

#endif
