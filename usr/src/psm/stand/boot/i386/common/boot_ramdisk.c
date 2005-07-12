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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/bootconf.h>
#include <sys/bootvfs.h>
#include <sys/filep.h>
#include "util.h"
#include "debug.h"

extern struct boot_fs_ops bufs_ops, bhsfs_ops;

extern uint64_t ramdisk_start, ramdisk_end;
struct boot_fs_ops *bfs_ops;
struct boot_fs_ops *bfs_tab[] = {&bufs_ops, &bhsfs_ops, NULL};

/*
 * This one reads the ramdisk. If fi_memp is set, we copy the
 * ramdisk content to the designated buffer. Otherwise, we
 * do a "cached" read (set fi_memp to the actual ramdisk buffer).
 */
int
diskread(fileid_t *filep)
{
	uint_t blocknum;
	caddr_t diskloc;

	/* add in offset of root slice */
	blocknum = filep->fi_blocknum;

	diskloc = (caddr_t)(ramdisk_start + blocknum * DEV_BSIZE);
	if (diskloc + filep->fi_count > (caddr_t)ramdisk_end) {
		printf("diskread: reading beyond end of ramdisk\n");
		printf("\tstart = 0x%p, size = 0x%x\n",
		    (void *)diskloc, filep->fi_count);
		return (-1);
	}

	if (filep->fi_memp) {
		bcopy(diskloc, filep->fi_memp, filep->fi_count);
	} else {
		/* "cached" read */
		filep->fi_memp = diskloc;
	}

	return (0);
}

int
mountroot(char *name)
{
	int i;

	if (verbosemode)
		printf("mountroot on ramdisk: 0x%llx-%llx\n",
		    ramdisk_start, ramdisk_end);
	/* try ops in bfs_tab and return the first successful one */
	for (i = 0; bfs_tab[i] != NULL; i++) {
		bfs_ops = bfs_tab[i];
		if (BRD_MOUNTROOT(bfs_ops, name) == 0)
			return (0);
	}
	return (-1);
}

int
unmountroot()
{
	return (BRD_UNMOUNTROOT(bfs_ops));
}

int
open(const char *filename, int flags)
{
	return (BRD_OPEN(bfs_ops, (char *)filename, flags));
}

int
close(int fd)
{
	return (BRD_CLOSE(bfs_ops, fd));
}

ssize_t
read(int fd, void *buf, size_t size)
{
	return (BRD_READ(bfs_ops, fd, buf, size));
}

off_t
lseek(int fd, off_t addr, int whence)
{
	return (BRD_SEEK(bfs_ops, fd, addr, whence));
}
