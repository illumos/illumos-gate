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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LX_FCNTL_H
#define	_SYS_LX_FCNTL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Lx open/fcntl flags
 */
#define	LX_O_RDONLY		00
#define	LX_O_WRONLY		01
#define	LX_O_RDWR		02
#define	LX_O_CREAT		0100
#define	LX_O_EXCL		0200
#define	LX_O_NOCTTY		0400
#define	LX_O_TRUNC		01000
#define	LX_O_APPEND		02000
#define	LX_O_NONBLOCK		04000
#define	LX_O_NDELAY		LX_O_NONBLOCK
#define	LX_O_SYNC		010000
#define	LX_O_FSYNC		LX_O_SYNC
#define	LX_O_ASYNC		020000
#define	LX_O_DIRECT		040000
#define	LX_O_LARGEFILE		0100000
#define	LX_O_DIRECTORY		0200000
#define	LX_O_NOFOLLOW		0400000
/* lx flag for pipe2 */
#define	LX_O_CLOEXEC		02000000

#define	LX_F_DUPFD		0
#define	LX_F_GETFD		1
#define	LX_F_SETFD		2
#define	LX_F_GETFL		3
#define	LX_F_SETFL		4
#define	LX_F_GETLK		5
#define	LX_F_SETLK		6
#define	LX_F_SETLKW		7
#define	LX_F_SETOWN		8
#define	LX_F_GETOWN		9
#define	LX_F_SETSIG		10
#define	LX_F_GETSIG		11

#define	LX_F_GETLK64		12
#define	LX_F_SETLK64		13
#define	LX_F_SETLKW64		14

#define	LX_F_SETLEASE		1024
#define	LX_F_GETLEASE		1025
#define	LX_F_NOTIFY		1026

#define	LX_F_RDLCK		0
#define	LX_F_WRLCK		1
#define	LX_F_UNLCK		2

/*
 * Lx flock codes.
 */
#define	LX_NAME_MAX		255
#define	LX_LOCK_SH		1	/* shared */
#define	LX_LOCK_EX		2	/* exclusive */
#define	LX_LOCK_NB		4	/* non-blocking */
#define	LX_LOCK_UN		8	/* unlock */

#define	LX_AT_FDCWD		-100
#define	LX_AT_SYMLINK_NOFOLLOW	0x100
#define	LX_AT_EACCESS		0x200
#define	LX_AT_REMOVEDIR		0x200
#define	LX_AT_SYMLINK_FOLLOW	0x400

struct lx_flock {
	short		l_type;
	short		l_whence;
	long		l_start;
	long		l_len;
	int		l_pid;
};

struct lx_flock64 {
	short		l_type;
	short		l_whence;
	long long	l_start;
	long long	l_len;
	int		l_pid;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_FCNTL_H */
