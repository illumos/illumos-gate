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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#ifndef	_SYS_FCNTL_H
#define	_SYS_FCNTL_H

#include <sys/feature_tests.h>

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Flag values accessible to open(2) and fcntl(2)
 * The first five can only be set (exclusively) by open(2).
 */
#define	O_RDONLY	0
#define	O_WRONLY	1
#define	O_RDWR		2
#define	O_SEARCH	0x200000
#define	O_EXEC		0x400000
#if defined(__EXTENSIONS__) || !defined(_POSIX_C_SOURCE)
#define	O_NDELAY	0x04	/* non-blocking I/O */
#endif /* defined(__EXTENSIONS__) || !defined(_POSIX_C_SOURCE) */
#define	O_APPEND	0x08	/* append (writes guaranteed at the end) */
#if defined(__EXTENSIONS__) || !defined(_POSIX_C_SOURCE) || \
	(_POSIX_C_SOURCE > 2) || defined(_XOPEN_SOURCE)
#define	O_SYNC		0x10	/* synchronized file update option */
#define	O_DSYNC		0x40	/* synchronized data update option */
#define	O_RSYNC		0x8000	/* synchronized file update option */
				/* defines read/write file integrity */
#endif /* defined(__EXTENSIONS__) || !defined(_POSIX_C_SOURCE) ... */
#define	O_NONBLOCK	0x80	/* non-blocking I/O (POSIX) */
#ifdef	_LARGEFILE_SOURCE
#define	O_LARGEFILE	0x2000
#endif

/*
 * Flag values accessible only to open(2).
 */
#define	O_CREAT		0x100	/* open with file create (uses third arg) */
#define	O_TRUNC		0x200	/* open with truncation */
#define	O_EXCL		0x400	/* exclusive open */
#define	O_NOCTTY	0x800	/* don't allocate controlling tty (POSIX) */
#define	O_XATTR		0x4000	/* extended attribute */
#define	O_NOFOLLOW	0x20000	/* don't follow symlinks */
#define	O_NOLINKS	0x40000	/* don't allow multiple hard links */
#define	O_CLOEXEC	0x800000	/* set the close-on-exec flag */

/*
 * fcntl(2) requests
 *
 * N.B.: values are not necessarily assigned sequentially below.
 */
#define	F_DUPFD		0	/* Duplicate fildes */
#define	F_GETFD		1	/* Get fildes flags */
#define	F_SETFD		2	/* Set fildes flags */
#define	F_GETFL		3	/* Get file flags */
#define	F_GETXFL	45	/* Get file flags including open-only flags */
#define	F_SETFL		4	/* Set file flags */

/*
 * Applications that read /dev/mem must be built like the kernel.  A
 * new symbol "_KMEMUSER" is defined for this purpose.
 */
#if defined(_KERNEL) || defined(_KMEMUSER)
#define	F_O_GETLK	5	/* SVR3 Get file lock (need for rfs, across */
				/* the wire compatibility */
/* clustering: lock id contains both per-node sysid and node id */
#define	SYSIDMASK		0x0000ffff
#define	GETSYSID(id)		(id & SYSIDMASK)
#define	NODEIDMASK		0xffff0000
#define	BITS_IN_SYSID		16
#define	GETNLMID(sysid)		((int)(((uint_t)(sysid) & NODEIDMASK) >> \
				    BITS_IN_SYSID))

/* Clustering: Macro used for PXFS locks */
#define	GETPXFSID(sysid)	((int)(((uint_t)(sysid) & NODEIDMASK) >> \
				    BITS_IN_SYSID))
#endif	/* defined(_KERNEL) */

#define	F_CHKFL		8	/* Unused */
#define	F_DUP2FD	9	/* Duplicate fildes at third arg */
#define	F_DUP2FD_CLOEXEC	36	/* Like F_DUP2FD with O_CLOEXEC set */
					/* EINVAL is fildes matches arg1 */
#define	F_DUPFD_CLOEXEC	37	/* Like F_DUPFD with O_CLOEXEC set */

#define	F_ISSTREAM	13	/* Is the file desc. a stream ? */
#define	F_PRIV		15	/* Turn on private access to file */
#define	F_NPRIV		16	/* Turn off private access to file */
#define	F_QUOTACTL	17	/* UFS quota call */
#define	F_BLOCKS	18	/* Get number of BLKSIZE blocks allocated */
#define	F_BLKSIZE	19	/* Get optimal I/O block size */
/*
 * Numbers 20-22 have been removed and should not be reused.
 */
#define	F_GETOWN	23	/* Get owner (socket emulation) */
#define	F_SETOWN	24	/* Set owner (socket emulation) */
#define	F_REVOKE	25	/* Object reuse revoke access to file desc. */

#define	F_HASREMOTELOCKS 26	/* Does vp have NFS locks; private to lock */
				/* manager */

/*
 * Commands that refer to flock structures.  The argument types differ between
 * the large and small file environments; therefore, the #defined values must
 * as well.
 * The NBMAND forms are private and should not be used.
 */

#if defined(_LP64) || _FILE_OFFSET_BITS == 32
/* "Native" application compilation environment */
#define	F_SETLK		6	/* Set file lock */
#define	F_SETLKW	7	/* Set file lock and wait */
#define	F_ALLOCSP	10	/* Allocate file space */
#define	F_FREESP	11	/* Free file space */
#define	F_GETLK		14	/* Get file lock */
#define	F_SETLK_NBMAND	42	/* private */
#else
/* ILP32 large file application compilation environment version */
#define	F_SETLK		34	/* Set file lock */
#define	F_SETLKW	35	/* Set file lock and wait */
#define	F_ALLOCSP	28	/* Alllocate file space */
#define	F_FREESP	27	/* Free file space */
#define	F_GETLK		33	/* Get file lock */
#define	F_SETLK_NBMAND	44	/* private */
#endif /* _LP64 || _FILE_OFFSET_BITS == 32 */

#if 	defined(_LARGEFILE64_SOURCE)

#if !defined(_LP64) || defined(_KERNEL)
/*
 * transitional large file interface version
 * These are only valid in a 32 bit application compiled with large files
 * option, for source compatibility, the 64-bit versions are mapped back
 * to the native versions.
 */
#define	F_SETLK64	34	/* Set file lock */
#define	F_SETLKW64	35	/* Set file lock and wait */
#define	F_ALLOCSP64	28	/* Allocate file space */
#define	F_FREESP64	27	/* Free file space */
#define	F_GETLK64	33	/* Get file lock */
#define	F_SETLK64_NBMAND	44	/* private */
#else
#define	F_SETLK64	6	/* Set file lock */
#define	F_SETLKW64	7	/* Set file lock and wait */
#define	F_ALLOCSP64	10	/* Allocate file space */
#define	F_FREESP64	11	/* Free file space */
#define	F_GETLK64	14	/* Get file lock */
#define	F_SETLK64_NBMAND	42	/* private */
#endif /* !_LP64 || _KERNEL */

#endif /* _LARGEFILE64_SOURCE */

#define	F_SHARE		40	/* Set a file share reservation */
#define	F_UNSHARE	41	/* Remove a file share reservation */
#define	F_SHARE_NBMAND	43	/* private */

#define	F_BADFD		46	/* Create Poison FD */

/*
 * File segment locking set data type - information passed to system by user.
 */

/* regular version, for both small and large file compilation environment */
typedef struct flock {
	short	l_type;
	short	l_whence;
	off_t	l_start;
	off_t	l_len;		/* len == 0 means until end of file */
	int	l_sysid;
	pid_t	l_pid;
	long	l_pad[4];		/* reserve area */
} flock_t;

#if defined(_SYSCALL32)

/* Kernel's view of ILP32 flock structure */

typedef struct flock32 {
	int16_t	l_type;
	int16_t	l_whence;
	off32_t	l_start;
	off32_t	l_len;		/* len == 0 means until end of file */
	int32_t	l_sysid;
	pid32_t	l_pid;
	int32_t	l_pad[4];		/* reserve area */
} flock32_t;

#endif /* _SYSCALL32 */

/* transitional large file interface version */

#if 	defined(_LARGEFILE64_SOURCE)

typedef struct flock64 {
	short	l_type;
	short	l_whence;
	off64_t	l_start;
	off64_t	l_len;		/* len == 0 means until end of file */
	int	l_sysid;
	pid_t	l_pid;
	long	l_pad[4];		/* reserve area */
} flock64_t;

#if defined(_SYSCALL32)

/* Kernel's view of ILP32 flock64 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma	pack(4)
#endif

typedef struct flock64_32 {
	int16_t	l_type;
	int16_t	l_whence;
	off64_t	l_start;
	off64_t	l_len;		/* len == 0 means until end of file */
	int32_t	l_sysid;
	pid32_t	l_pid;
	int32_t	l_pad[4];		/* reserve area */
} flock64_32_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/* Kernel's view of LP64 flock64 */

typedef struct flock64_64 {
	int16_t	l_type;
	int16_t	l_whence;
	off64_t	l_start;
	off64_t	l_len;		/* len == 0 means until end of file */
	int32_t	l_sysid;
	pid32_t	l_pid;
	int64_t	l_pad[4];		/* reserve area */
} flock64_64_t;

#endif	/* _SYSCALL32 */

#endif /* _LARGEFILE64_SOURCE */

#if defined(_KERNEL) || defined(_KMEMUSER)
/* SVr3 flock type; needed for rfs across the wire compatibility */
typedef struct o_flock {
	int16_t	l_type;
	int16_t	l_whence;
	int32_t	l_start;
	int32_t	l_len;		/* len == 0 means until end of file */
	int16_t	l_sysid;
	int16_t	l_pid;
} o_flock_t;
#endif	/* defined(_KERNEL) */

/*
 * File segment locking types.
 */
#define	F_RDLCK		01	/* Read lock */
#define	F_WRLCK		02	/* Write lock */
#define	F_UNLCK		03	/* Remove lock(s) */
#define	F_UNLKSYS	04	/* remove remote locks for a given system */

/*
 * POSIX constants
 */

/* Mask for file access modes */
#define	O_ACCMODE	(O_SEARCH | O_EXEC | 0x3)
#define	FD_CLOEXEC	1	/* close on exec flag */

/*
 * DIRECTIO
 */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
#define	DIRECTIO_OFF	(0)
#define	DIRECTIO_ON	(1)

/*
 * File share reservation type
 */
typedef struct fshare {
	short	f_access;
	short	f_deny;
	int	f_id;
} fshare_t;

/*
 * f_access values
 */
#define	F_RDACC		0x1	/* Read-only share access */
#define	F_WRACC		0x2	/* Write-only share access */
#define	F_RWACC		0x3	/* Read-Write share access */
#define	F_RMACC		0x4	/* private flag: Delete share access */
#define	F_MDACC		0x20	/* private flag: Metadata share access */

/*
 * f_deny values
 */
#define	F_NODNY		0x0	/* Don't deny others access */
#define	F_RDDNY		0x1	/* Deny others read share access */
#define	F_WRDNY		0x2	/* Deny others write share access */
#define	F_RWDNY		0x3	/* Deny others read or write share access */
#define	F_RMDNY		0x4	/* private flag: Deny delete share access */
#define	F_COMPAT	0x8	/* Set share to old DOS compatibility mode */
#define	F_MANDDNY	0x10	/* private flag: mandatory enforcement */
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) */

/*
 * Special flags for functions such as openat(), fstatat()....
 */
#if !defined(__XOPEN_OR_POSIX) || defined(_ATFILE_SOURCE) || \
	defined(__EXTENSIONS__)
	/* || defined(_XPG7) */
#define	AT_FDCWD			0xffd19553
#define	AT_SYMLINK_NOFOLLOW		0x1000
#define	AT_SYMLINK_FOLLOW		0x2000	/* only for linkat() */
#define	AT_REMOVEDIR			0x1
#define	_AT_TRIGGER			0x2
#define	AT_EACCESS			0x4	/* use EUID/EGID for access */
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
/* advice for posix_fadvise */
#define	POSIX_FADV_NORMAL	0
#define	POSIX_FADV_RANDOM	1
#define	POSIX_FADV_SEQUENTIAL	2
#define	POSIX_FADV_WILLNEED	3
#define	POSIX_FADV_DONTNEED	4
#define	POSIX_FADV_NOREUSE	5
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FCNTL_H */
