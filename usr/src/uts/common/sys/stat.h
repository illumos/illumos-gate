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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	All Rights Reserved	*/

#ifndef _SYS_STAT_H
#define	_SYS_STAT_H

#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The implementation specific header <sys/time_impl.h> includes a
 * definition for timestruc_t needed by the stat structure.  However,
 * including either <time.h>, which includes <sys/time_impl.h>, or
 * including <sys/time_impl.h> directly will break both X/Open and
 * POSIX namespace. Preceeding tag, structure, and structure member
 * names with underscores eliminates the namespace breakage and at the
 * same time, with unique type names, eliminates the possibility of
 * timespec_t or timestruct_t naming conflicts that could otherwise
 * result based on the order of inclusion of <sys/stat.h> and
 * <sys/time.h>.  The header <sys/time_std_impl.h> contains the
 * standards namespace safe versions of these definitions.
 */
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#include <sys/time_impl.h>
#else
#include <sys/time_std_impl.h>
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#define	_ST_FSTYPSZ 16		/* array size for file system type name */

/*
 * stat structure, used by stat(2) and fstat(2)
 */

#if defined(_KERNEL)

	/* Expanded stat structure */

#if defined(_LP64)

struct stat {
	dev_t		st_dev;
	ino_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	off_t		st_size;
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
};

struct stat64 {
	dev_t		st_dev;
	ino_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	off_t		st_size;
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
};

#else	/* _LP64 */

struct	stat {
	dev_t		st_dev;
	long		st_pad1[3];	/* reserve for dev expansion, */
					/* sysid definition */
	ino_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	long		st_pad2[2];
	off_t		st_size;
	long		st_pad3;	/* pad for future off_t expansion */
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
	long		st_pad4[8];	/* expansion area */
};

struct  stat64 {
	dev_t		st_dev;
	long		st_pad1[3];	/* reserve for dev expansion, */
				/* sysid definition */
	ino64_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	long		st_pad2[2];
	off64_t		st_size;	/* large file support */
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
	blksize_t	st_blksize;
	blkcnt64_t	st_blocks;	/* large file support */
	char		st_fstype[_ST_FSTYPSZ];
	long		st_pad4[8];	/* expansion area */
};

#endif	/* _LP64 */

#else /* !defined(_KERNEL) */

/*
 * large file compilation environment setup
 */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	fstat	fstat64
#pragma redefine_extname	stat	stat64
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) || \
	defined(_ATFILE_SOURCE)
#pragma	redefine_extname	fstatat	fstatat64
#endif /* defined (_ATFILE_SOURCE) */

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG_2) || defined(__EXTENSIONS__)
#pragma	redefine_extname	lstat	lstat64
#endif
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	fstat	fstat64
#define	stat	stat64
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) || \
	defined(_ATFILE_SOURCE)
#define	fstatat	fstatat64
#endif /* defined (_ATFILE_SOURCE) */
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG_2) || defined(__EXTENSIONS__)
#define	lstat	lstat64
#endif
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif	/* !_LP64 && _FILE_OFFSET_BITS == 64 */

/*
 * In the LP64 compilation environment, map large file interfaces
 * back to native versions where possible.
 */
#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	fstat64	fstat
#pragma	redefine_extname	stat64	stat
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) || \
	defined(_ATFILE_SOURCE)
#pragma	redefine_extname	fstatat64 fstatat
#endif /* defined (_ATFILE_SOURCE) */
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG_2) || defined(__EXTENSIONS__)
#pragma	redefine_extname	lstat64	lstat
#endif
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	fstat64	fstat
#define	stat64	stat
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) || \
	defined(_ATFILE_SOURCE)
#define	fstatat64	fstatat
#endif /* defined (_ATFILE_SOURCE) */
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG_2) || defined(__EXTENSIONS__)
#define	lstat64	lstat
#endif
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

/*
 * User level stat structure definitions.
 */

#if defined(_LP64)

struct stat {
	dev_t		st_dev;
	ino_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	off_t		st_size;
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
#else
	_timestruc_t	st_atim;
	_timestruc_t	st_mtim;
	_timestruc_t	st_ctim;
#endif
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
};

#else	/* _LP64 */

struct	stat {
	dev_t		st_dev;
	long		st_pad1[3];	/* reserved for network id */
	ino_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	long		st_pad2[2];
	off_t		st_size;
#if _FILE_OFFSET_BITS != 64
	long		st_pad3;	/* future off_t expansion */
#endif
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
#else
	_timestruc_t	st_atim;
	_timestruc_t	st_mtim;
	_timestruc_t	st_ctim;
#endif
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
	long		st_pad4[8];	/* expansion area */
};

#endif	/* _LP64 */

/* transitional large file interface version */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
#if defined(_LP64)

struct stat64 {
	dev_t		st_dev;
	ino_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	off_t		st_size;
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
#else
	_timestruc_t	st_atim;
	_timestruc_t	st_mtim;
	_timestruc_t	st_ctim;
#endif
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
};

#else	/* _LP64 */

struct	stat64 {
	dev_t		st_dev;
	long		st_pad1[3];	/* reserved for network id */
	ino64_t		st_ino;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	long		st_pad2[2];
	off64_t		st_size;
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
#else
	_timestruc_t    st_atim;
	_timestruc_t    st_mtim;
	_timestruc_t    st_ctim;
#endif
	blksize_t	st_blksize;
	blkcnt64_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
	long		st_pad4[8];	/* expansion area */
};

#endif	/* _LP64 */
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#define	st_atime	st_atim.tv_sec
#define	st_mtime	st_mtim.tv_sec
#define	st_ctime	st_ctim.tv_sec
#else
#define	st_atime	st_atim.__tv_sec
#define	st_mtime	st_mtim.__tv_sec
#define	st_ctime	st_ctim.__tv_sec
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#endif /* end defined(_KERNEL) */

#if defined(_SYSCALL32)

/*
 * Kernel's view of user ILP32 stat and stat64 structures
 */

struct stat32 {
	dev32_t		st_dev;
	int32_t		st_pad1[3];
	ino32_t		st_ino;
	mode32_t	st_mode;
	nlink32_t	st_nlink;
	uid32_t		st_uid;
	gid32_t		st_gid;
	dev32_t		st_rdev;
	int32_t		st_pad2[2];
	off32_t		st_size;
	int32_t		st_pad3;
	timestruc32_t	st_atim;
	timestruc32_t	st_mtim;
	timestruc32_t	st_ctim;
	int32_t		st_blksize;
	blkcnt32_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
	int32_t		st_pad4[8];
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct stat64_32 {
	dev32_t		st_dev;
	int32_t		st_pad1[3];
	ino64_t		st_ino;
	mode32_t	st_mode;
	nlink32_t	st_nlink;
	uid32_t		st_uid;
	gid32_t		st_gid;
	dev32_t		st_rdev;
	int32_t		st_pad2[2];
	off64_t		st_size;
	timestruc32_t	st_atim;
	timestruc32_t	st_mtim;
	timestruc32_t	st_ctim;
	int32_t		st_blksize;
	blkcnt64_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
	int32_t		st_pad4[8];
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif	/* _SYSCALL32 */

/* MODE MASKS */

/* de facto standard definitions */

#define	S_IFMT		0xF000	/* type of file */
#define	S_IAMB		0x1FF	/* access mode bits */
#define	S_IFIFO		0x1000	/* fifo */
#define	S_IFCHR		0x2000	/* character special */
#define	S_IFDIR		0x4000	/* directory */
/* XENIX definitions are not relevant to Solaris */
#define	S_IFNAM		0x5000  /* XENIX special named file */
#define	S_INSEM		0x1	/* XENIX semaphore subtype of IFNAM */
#define	S_INSHD		0x2	/* XENIX shared data subtype of IFNAM */
#define	S_IFBLK		0x6000	/* block special */
#define	S_IFREG		0x8000	/* regular */
#define	S_IFLNK		0xA000	/* symbolic link */
#define	S_IFSOCK	0xC000	/* socket */
#define	S_IFDOOR	0xD000	/* door */
#define	S_IFPORT	0xE000	/* event port */
#define	S_ISUID		0x800	/* set user id on execution */
#define	S_ISGID		0x400	/* set group id on execution */
#define	S_ISVTX		0x200	/* save swapped text even after use */
#define	S_IREAD		00400	/* read permission, owner */
#define	S_IWRITE	00200	/* write permission, owner */
#define	S_IEXEC		00100	/* execute/search permission, owner */
#define	S_ENFMT		S_ISGID	/* record locking enforcement flag */

/* the following macros are for POSIX conformance */

#define	S_IRWXU		00700	/* read, write, execute: owner */
#define	S_IRUSR		00400	/* read permission: owner */
#define	S_IWUSR		00200	/* write permission: owner */
#define	S_IXUSR		00100	/* execute permission: owner */
#define	S_IRWXG		00070	/* read, write, execute: group */
#define	S_IRGRP		00040	/* read permission: group */
#define	S_IWGRP		00020	/* write permission: group */
#define	S_IXGRP		00010	/* execute permission: group */
#define	S_IRWXO		00007	/* read, write, execute: other */
#define	S_IROTH		00004	/* read permission: other */
#define	S_IWOTH		00002	/* write permission: other */
#define	S_IXOTH		00001	/* execute permission: other */


#define	S_ISFIFO(mode)	(((mode)&0xF000) == 0x1000)
#define	S_ISCHR(mode)	(((mode)&0xF000) == 0x2000)
#define	S_ISDIR(mode)	(((mode)&0xF000) == 0x4000)
#define	S_ISBLK(mode)	(((mode)&0xF000) == 0x6000)
#define	S_ISREG(mode)	(((mode)&0xF000) == 0x8000)
#define	S_ISLNK(mode)	(((mode)&0xF000) == 0xa000)
#define	S_ISSOCK(mode)	(((mode)&0xF000) == 0xc000)
#define	S_ISDOOR(mode)	(((mode)&0xF000) == 0xd000)
#define	S_ISPORT(mode)	(((mode)&0xF000) == 0xe000)

/* POSIX.4 macros */
#define	S_TYPEISMQ(_buf)	(0)
#define	S_TYPEISSEM(_buf)	(0)
#define	S_TYPEISSHM(_buf)	(0)

#if defined(__i386) || (defined(__i386_COMPAT) && defined(_KERNEL))

/*
 * A version number is included in the x86 SVR4 stat and mknod interfaces
 * so that SVR4 binaries can be supported.  An LP64 kernel that supports
 * the i386 ABI need to be aware of this too.
 */

#define	_R3_MKNOD_VER	1	/* SVR3.0 mknod */
#define	_MKNOD_VER	2	/* current version of mknod */
#define	_R3_STAT_VER	1	/* SVR3.0 stat */
#define	_STAT_VER	2	/* current version of stat */

#endif	/* __i386 || (__i386_COMPAT && _KERNEL) */

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))
	/* || defined(_XPG7) */
/* for use with futimens() and utimensat() */
#define	UTIME_NOW	-1L
#define	UTIME_OMIT	-2L
#endif	/* defined(__EXTENSIONS__) ... */

#if !defined(_KERNEL) || defined(_BOOT)

#if !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE > 2) || \
	defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int fchmod(int, mode_t);
#endif /* !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE > 2)... */

extern int chmod(const char *, mode_t);
extern int mkdir(const char *, mode_t);
extern int mkfifo(const char *, mode_t);
extern mode_t umask(mode_t);

/* transitional large file interfaces */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern int fstat64(int, struct stat64 *);
extern int stat64(const char *_RESTRICT_KYWD, struct stat64 *_RESTRICT_KYWD);
extern int lstat64(const char *_RESTRICT_KYWD, struct stat64 *_RESTRICT_KYWD);
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) || \
	defined(_ATFILE_SOURCE)
extern int fstatat64(int, const char *, struct stat64 *, int);
#endif /* defined (_ATFILE_SOURCE) */
#endif

#if defined(__EXTENSIONS__) || defined(_ATFILE_SOURCE) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))
	/* || defined(_XPG7) */
extern int mkdirat(int, const char *, mode_t);
extern int mkfifoat(int, const char *, mode_t);
extern int mknodat(int, const char *, mode_t, dev_t);
extern int fchmodat(int, const char *, mode_t, int);
extern int futimens(int, const struct timespec[2]);
extern int utimensat(int, const char *, const struct timespec[2], int);
#endif	/* defined(__EXTENSIONS__) ... */

#include <sys/stat_impl.h>

#endif /* !defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STAT_H */
