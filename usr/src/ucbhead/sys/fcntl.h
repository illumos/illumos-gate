/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
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

#ifndef _SYS_FCNTL_H
#define	_SYS_FCNTL_H

#ifndef _SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Flag values accessible to open(2) and fcntl(2) */
/*  (The first three can only be set by open) */
#define	O_RDONLY 0
#define	O_WRONLY 1
#define	O_RDWR	 2
#define	O_NDELAY 04	/* Non-blocking I/O */
#define	O_APPEND 010	/* append (writes guaranteed at the end) */
#define	O_SYNC	 020	/* synchronous write option */
#define	O_NONBLOCK 0200 /* Non-blocking I/O (POSIX) */
#define	O_PRIV 010000   /* Private access to file */

#ifdef	_LARGEFILE_SOURCE
#define	O_LARGEFILE	0x2000
#endif

/* Flag values accessible only to open(2) */
#define	O_CREAT	00400	/* open with file create (uses third open arg) */
#define	O_TRUNC	01000	/* open with truncation */
#define	O_EXCL	02000	/* exclusive open */
#define	O_NOCTTY 04000	/* don't allocate controlling tty (POSIX) */

/* fcntl(2) requests */
#define	F_DUPFD		0	/* Duplicate fildes */
#define	F_GETFD		1	/* Get fildes flags */
#define	F_SETFD		2	/* Set fildes flags */
#define	F_GETFL		3	/* Get file flags */
#define	F_SETFL		4	/* Set file flags */
#define	F_SETLK		6	/* Set file lock */
#define	F_SETLKW	7	/* Set file lock and wait */
#define	F_FLOCK		53	/* private - flock */
#define	F_FLOCKW	54	/* private - flock wait */

/*
 * Applications that read /dev/mem must be built like the kernel. A new
 * symbol "_KMEMUSER" is defined for this purpose.
 * Applications that read /dev/mem will migrate with the kernel
 * to an "_LTYPES" definition.
 */

#if defined(_KERNEL) || defined(_KMEMUSER)
#define	F_GETLK		14	/* Get file lock */
#define	F_O_GETLK	5	/* SVR3 Get file lock */

#else	/* user definition */

#if defined(_LTYPES)	/* EFT definition */
#define	F_GETLK		14	/* Get file lock */
#else
#define	F_GETLK		5	/* Get file lock */
#endif	/* defined(_LTYPES) */

#endif	/* defined(_KERNEL) */

#define	F_SETLK		6	/* Set file lock */
#define	F_SETLKW	7	/* Set file lock and wait */


#define	F_CHKFL		8	/* Reserved */
#define	F_ALLOCSP	10	/* Reserved */
#define	F_FREESP	11	/* Free file space */
#define	F_ISSTREAM	13	/* Is the file desc. a stream ? */
#define	F_PRIV		15	/* Turn on private access to file */
#define	F_NPRIV		16	/* Turn off private access to file */
#define	F_QUOTACTL	17	/* UFS quota call */
#define	F_BLOCKS	18	/* Get number of BLKSIZE blocks allocated */
#define	F_BLKSIZE	19	/* Get optimal I/O block size */

#define	F_GETOWN	23	/* Get owner */
#define	F_SETOWN	24	/* Set owner */

/* flags for F_GETFL, F_SETFL-- copied from <sys/file.h> */
#ifndef FOPEN
#define	FOPEN		0xFFFFFFFF
#define	FREAD		0x01
#define	FWRITE		0x02
#define	FNDELAY		0x04
#define	FAPPEND		0x08
#define	FSYNC		0x10
#define	FNONBLOCK	0x80

#define	FMASK		0xFF    /* should be disjoint from FASYNC */

/* open-only modes */

#define	FCREAT		0x0100
#define	FTRUNC		0x0200
#define	FEXCL		0x0400
#define	FNOCTTY		0x0800
#define	FASYNC		0x1000

/* file descriptor flags */
#define	FCLOSEXEC	001	/* close on exec */
#endif

/*
 * File segment locking set data type - information passed to system by user.
 */
#if defined(_KERNEL) || defined(_KMEMUSER)
	/* EFT definition */
typedef struct flock {
	short	l_type;
	short	l_whence;
	off_t	l_start;
	off_t	l_len;		/* len == 0 means until end of file */
	int	l_sysid;
	pid_t	l_pid;
	long	pad[4];		/* reserve area */
} flock_t;

typedef struct o_flock {
	short	l_type;
	short	l_whence;
	int	l_start;
	int	l_len;		/* len == 0 means until end of file */
	short   l_sysid;
	o_pid_t l_pid;
} o_flock_t;

#else		/* user level definition */

#if defined(_STYPES)
	/* SVR3 definition */
typedef struct flock {
	short	l_type;
	short	l_whence;
	off_t	l_start;
	off_t	l_len;		/* len == 0 means until end of file */
	short	l_sysid;
	o-pid_t	l_pid;
} flock_t;

#else

typedef struct flock {
	short	l_type;
	short	l_whence;
	off_t	l_start;
	off_t	l_len;		/* len == 0 means until end of file */
	int	l_sysid;
	pid_t	l_pid;
	long 	pad[4];		/* reserve area */
} flock_t;

#endif	/* define(_STYPES) */

#endif	/* defined(_KERNEL) */

/*
 * File segment locking types.
 */
#define	F_RDLCK	01	/* Read lock */
#define	F_WRLCK	02	/* Write lock */
#define	F_UNLCK	03	/* Remove lock(s) */

/*
 * POSIX constants
 */

#define	O_ACCMODE	3	/* Mask for file access modes */
#define	FD_CLOEXEC	1	/* close on exec flag */

/* large file compilation environment setup */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	open	open64
#pragma	redefine_extname	creat	creat64
#else
#define	open			open64
#define	creat			creat64
#endif
#endif  /* !_LP64 && _FILE_OFFSET_BITS == 64 */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	open64	open
#pragma	redefine_extname	creat64	creat
#else
#define	open64			open
#define	creat64			creat
#endif
#endif  /* _LP64 && _LARGEFILE64_SOURCE */

#if defined(__STDC__)
extern int fcntl(int, int, ...);
extern int open(const char *, int, ...);
extern int creat(const char *, mode_t);
#if defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	!defined(__PRAGMA_REDEFINE_EXTNAME))
extern int open64(const char *, int, ...);
extern int creat64(const char *, mode_t);
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FCNTL_H */
