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
 * Copyright 1994-1996, 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/filep.h>
#include <sys/salib.h>

static	char	prom_dev_type = 0;

/*
 * unix root slice offset for PROMS that do
 * not know about fdisk partitions or Solaris
 * slices.
 * the default is 0 for machines with proms that
 * do know how to interpret solaris slices.
 */
unsigned long unix_startblk = 0;

/*
 *	The various flavors of PROM make this grotesque.
 */
int
diskread(fileid_t *filep)
{
	int err;
	devid_t	*devp;
	uint_t blocknum;

	/* add in offset of root slice */
	blocknum = filep->fi_blocknum + unix_startblk;

	devp = filep->fi_devp;

	err = prom_seek(devp->di_dcookie,
	    (unsigned long long)blocknum * (unsigned long long)DEV_BSIZE);
	if (err == -1) {
		printf("Seek error at block %x\n", blocknum);
		return (-1);
	}

	if ((err = prom_read(devp->di_dcookie, filep->fi_memp, filep->fi_count,
	    blocknum, prom_dev_type)) != filep->fi_count) {
		printf("Short read.  0x%x chars read\n", err);
		return (-1);
	}

	return (0);
}
