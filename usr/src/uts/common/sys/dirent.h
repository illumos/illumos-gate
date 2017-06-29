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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DIRENT_H
#define	_SYS_DIRENT_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * File-system independent directory entry.
 */
typedef struct dirent {
	ino_t		d_ino;		/* "inode number" of entry */
	off_t		d_off;		/* offset of disk directory entry */
	unsigned short	d_reclen;	/* length of this record */
	char		d_name[1];	/* name of file */
} dirent_t;

#if defined(_SYSCALL32)

/* kernel's view of user ILP32 dirent */

typedef	struct dirent32 {
	ino32_t		d_ino;		/* "inode number" of entry */
	off32_t		d_off;		/* offset of disk directory entry */
	uint16_t	d_reclen;	/* length of this record */
	char		d_name[1];	/* name of file */
} dirent32_t;

#endif	/* _SYSCALL32 */

#ifdef	_LARGEFILE64_SOURCE

/*
 * transitional large file interface version AND kernel internal version
 */
typedef struct dirent64 {
	ino64_t		d_ino;		/* "inode number" of entry */
	off64_t		d_off;		/* offset of disk directory entry */
	unsigned short	d_reclen;	/* length of this record */
	char		d_name[1];	/* name of file */
} dirent64_t;

#endif	/* _LARGEFILE64_SOURCE */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#if defined(_KERNEL)
#define	DIRENT64_RECLEN(namelen)	\
	((offsetof(dirent64_t, d_name[0]) + 1 + (namelen) + 7) & ~ 7)
#define	DIRENT64_NAMELEN(reclen)	\
	((reclen) - (offsetof(dirent64_t, d_name[0])))
#define	DIRENT32_RECLEN(namelen)	\
	((offsetof(dirent32_t, d_name[0]) + 1 + (namelen) + 3) & ~ 3)
#define	DIRENT32_NAMELEN(reclen)	\
	((reclen) - (offsetof(dirent32_t, d_name[0])))
#endif

/*
 * This is the maximum number of bytes that getdents(2) will store in
 * user-supplied dirent buffers.
 */
#define	MAXGETDENTS_SIZE	(64 * 1024)

#if !defined(_KERNEL)

/*
 * large file compilation environment setup
 *
 * In the LP64 compilation environment, map large file interfaces
 * back to native versions where possible. (This only works because
 * a 'struct dirent' == 'struct dirent64').
 */

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	getdents	getdents64
#else
#define	getdents		getdents64
#endif
#endif	/* !_LP64 && _FILE_OFFSET_BITS == 64 */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	getdents64	getdents
#else
#define	getdents64		getdents
#define	dirent64		dirent
#define	dirent64_t		dirent_t
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

extern int getdents(int, struct dirent *, size_t);

/* N.B.: transitional large file interface version deliberately not provided */

#endif /* !defined(_KERNEL) */
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DIRENT_H */
