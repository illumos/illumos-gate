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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/syscall.h>

#define FSTYPSZ	16	/* array size for file system type name */

struct statvfs {
        u_long  f_bsize;        /* fundamental file system block size */
        u_long  f_frsize;       /* fragment size */
        u_long  f_blocks;       /* total # of blocks of f_frsize on fs */
        u_long  f_bfree;        /* total # of free blocks of f_frsize */
        u_long  f_bavail;       /* # of free blocks avail to non-superuser */
        u_long  f_files;        /* total # of file nodes (inodes) */
        u_long  f_ffree;        /* total # of free file nodes */
        u_long  f_favail;       /* # of free nodes avail to non-superuser */
        u_long  f_fsid;         /* file system id (dev for now) */
        char    f_basetype[FSTYPSZ]; /* target fs type name, null-terminated */
        u_long  f_flag;         /* bit-mask of flags */
        u_long  f_namemax;      /* maximum file name length */
        char    f_fstr[32];     /* filesystem-specific string */
        u_long  f_filler[16];   /* reserved for future expansion */
};

void	cpstatvfs(struct statfs *, struct statvfs *);

int
statfs_com(char *s, struct statfs *b)
{
	int    ret;
	struct statvfs vfsb;

	if ((ret = _syscall(SYS_statvfs, s, &vfsb)) == 0) {
		cpstatvfs(b, &vfsb);
	}
	return(ret);		
}

int
fstatfs(int fd, struct statfs *b)
{
	int    ret;
	struct statvfs vfsb;

	if ((ret = _syscall(SYS_fstatvfs,fd, &vfsb)) == 0) {
		cpstatvfs(b, &vfsb);
	}
	return(ret);		
}

/* 
 * Common code to copy vfs buf to BSD style buf 
 */
void
cpstatvfs(struct statfs *bsdbuf, struct statvfs *vbuf)
{
	bsdbuf->f_type = (long) 0;  		/* type of info, zero for now */
	bsdbuf->f_bsize = (vbuf->f_frsize != 0) ?
	    (long) vbuf->f_frsize: (long) vbuf->f_bsize;
	bsdbuf->f_blocks = (long) vbuf->f_blocks;
	bsdbuf->f_bfree = (long) vbuf->f_bfree;
	bsdbuf->f_bavail = (long) vbuf->f_bavail;
	bsdbuf->f_files = (long) vbuf->f_files;
	bsdbuf->f_ffree = (long) vbuf->f_ffree;
	bsdbuf->f_fsid.val[0] = vbuf->f_fsid;
	bsdbuf->f_fsid.val[1] = 0;
}
