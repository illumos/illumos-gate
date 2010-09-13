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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* SunOS-4.1 1.16	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/vfs.h>
#include <sys/t_lock.h>

extern int swapinit(int fstype, char *name);

/*
 * WARNING: THE POSITIONS OF FILESYSTEM TYPES IN THIS TABLE SHOULD NOT
 * BE CHANGED. These positions are used in generating fsids and
 * fhandles.  Thus, changing positions will cause a server to change
 * the fhandle it gives out for a file.  It is okay to reuse formerly
 * used slots, just be sure that we're not going to start supporting
 * the former owner of the slot again.
 *
 * Since there's been some question about whether the above comment is
 * true, let's provide more detail.  Most filesystems call
 * vfs_make_fsid with two arguments that go into making the fsid: the
 * dev number, and the fs type number - which is the offset of the
 * filesystem's entry in the below table.  If you would like to check
 * if the position of the filesystem in this table still affects the
 * fsid, just check what arguments filesystems are calling
 * vfs_make_fsid with.
 *
 * The scenario we're trying to prevent here is:
 *
 * NFS server gets upgraded to new kernel version with different vfssw
 * Clients are -not- rebooted, still retain filehandles
 * NFS server boots up and now the fsid of an exported fs is different
 *  --> Clients get stale file handle errors
 */

struct vfssw vfssw[] = {
	{ "BADVFS" },				/* invalid */
	{ "specfs" },				/* SPECFS */
	{ "ufs" },				/* UFS */
	{ "fifofs" },				/* FIFOFS */
	{ "namefs" },				/* NAMEFS */
	{ "proc" },				/* PROCFS */
	{ "samfs" },				/* QFS */
	{ "nfs" },				/* NFS Version 2 */
	{ "zfs" },				/* ZFS */
	{ "hsfs" },				/* HSFS */
	{ "lofs" },				/* LOFS */
	{ "tmpfs" },				/* TMPFS */
	{ "fd" },				/* FDFS */
	{ "pcfs" },				/* PCFS */
	{ "swapfs", swapinit },			/* SWAPFS */
	{ "mntfs" },				/* MNTFS */
	{ "devfs" },				/* DEVFS */
	{ "dev" },				/* DEV */
	{ "ctfs" },				/* CONTRACTFS */
	{ "objfs" },				/* OBJFS */
	{ "sharefs" },				/* SHAREFS */
	{ "dcfs" },				/* DCFS */
	{ "smbfs" },				/* SMBFS */
	{ "" },					/* reserved for loadable fs */
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
	{ "" },
};

const int nfstype = (sizeof (vfssw) / sizeof (vfssw[0]));
