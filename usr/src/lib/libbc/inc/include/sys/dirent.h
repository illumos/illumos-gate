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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Filesystem-independent directory information.
 * Directory entry structures are of variable length.
 * Each directory entry is a struct dirent containing its file number, the
 * offset of the next entry (a cookie interpretable only the filesystem
 * type that generated it), the length of the entry, and the length of the
 * name contained in the entry.  These are followed by the name. The
 * entire entry is padded with null bytes to a 4 byte boundary. All names
 * are guaranteed null terminated. The maximum length of a name in a
 * directory is MAXNAMLEN, plus a null byte.
 */

#ifndef	__sys_dirent_h
#define	__sys_dirent_h

struct	dirent {
	off_t		d_off;		/* offset of next disk dir entry */
	unsigned long	d_fileno;	/* file number of entry */
	unsigned short	d_reclen;	/* length of this record */
	unsigned short	d_namlen;	/* length of string in d_name */
	char		d_name[255+1];	/* name (up to MAXNAMLEN + 1) */
};

#ifndef	_POSIX_SOURCE
/*
 * It's unlikely to change, but make sure that sizeof d_name above is
 * at least MAXNAMLEN + 1 (more may be added for padding).
 */
#define	MAXNAMLEN	255
/*
 * The macro DIRSIZ(dp) gives the minimum amount of space required to represent
 * a directory entry.  For any directory entry dp->d_reclen >= DIRSIZ(dp).
 * Specific filesystem types may use this macro to construct the value
 * for d_reclen.
 */
#undef	DIRSIZ
#define	DIRSIZ(dp) \
	(((sizeof(struct dirent) - (MAXNAMLEN+1) + ((dp)->d_namlen+1)) +3) & ~3)

#endif	/* !_POSIX_SOURCE */
#endif	/* !__sys_dirent_h */
