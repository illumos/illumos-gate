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
 * Copyright (c) 1990-1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI" /* from SunOS 4.1 */

/*
 * This stuff keeps track of an open file in the standalone I/O system.
 *
 * The definitions herein are *private* to ufs.c
 *
 * It includes an IOB for device addess, an inode, a buffer for reading
 * indirect blocks and inodes, and a buffer for the superblock of the
 * file system (if any).
 *
 * To make the boot block smaller, we're using a 'bnode' (for boot node)
 * struct instead of an inode struct. This contains just the common
 * data from the on-disk inode.
 */

struct saioreq {
	off_t	si_offset;
	char	*si_ma;			/* memory address to r/w */
	int	si_cc;			/* character count to r/w */
};

struct bnode 
{
	dev_t i_dev;			/* from inode struct */
	struct icommon i_ic;		/* disk inode struct */
};


struct iob {
	void		*i_si;		/* I/O handle for this file */
	struct {
		off_t	si_offset;
		char	*si_ma;		/* memory address to r/w */
		int	si_cc;		/* character count to r/w */
	} i_saio;			/* I/O request block */
	struct bnode	i_ino;		/* Inode for this file */
	char		i_buf[MAXBSIZE]; /* Buffer for reading inodes & dirs */
	union {
		struct fs ui_fs;	/* Superblock for file system */
		char dummy[SBSIZE];
	} i_un;
};

/*
 * XXX: i_fs conflicts with a definition in ufs_inode.h...
 */
#define	iob_fs		i_un.ui_fs
