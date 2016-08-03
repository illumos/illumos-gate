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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/bootvfs.h>
#include <sys/filep.h>

#include <libintl.h>
#include <locale.h>
#include "message.h"

/*
 * This file is glue layer to pcfs module in usr/src/common/fs/pcfs.c.
 * It's main functionality is to get the stage file blocklist. It's
 * used for installing grub on a Solaris boot partition.
 */
extern struct boot_fs_ops bpcfs_ops;
struct boot_fs_ops *bfs_ops;
struct boot_fs_ops *bfs_tab[] = {&bpcfs_ops, NULL};
static int dev_fd;
int bootrd_debug = 0;

#define	DEV_BSIZE	512
#define	MAX_CHUNK	64

static unsigned int *blocklist;

/* diskread_callback is set in filesytem module (pcfs.c) */
int (*diskread_callback)(int, int);
int (*fileread_callback)(int, int);

static int
add_stage2_block(int blocknum, int nblk)
{
	static int i = -2;

	if (i >= 0 && (blocklist[i] + blocklist[i + 1] == blocknum)) {
		blocklist[i + 1] += nblk;
		return (0);
	}

	i += 2;
	if (i >= DEV_BSIZE / 8) {
		fprintf(stderr, PCFS_FRAGMENTED);
		exit(-1);
	}
	blocklist[i] = blocknum;
	blocklist[i + 1] = nblk;
	return (0);
}

/*
 * This one reads the ramdisk. If fi_memp is set, we copy the
 * ramdisk content to the designated buffer. Otherwise, we
 * do a "cached" read (set fi_memp to the actual ramdisk buffer).
 */
int
diskread(fileid_t *filep)
{
	int ret;
	uint_t blocknum, diskloc;

	blocknum = filep->fi_blocknum;

	if (diskread_callback) {
		diskread_callback(blocknum, filep->fi_count / DEV_BSIZE);
		return (0);
	}

	diskloc = blocknum * DEV_BSIZE;
	if (filep->fi_memp == NULL) {
		filep->fi_memp = malloc(filep->fi_count);
	}
	if (filep->fi_memp == NULL) {
		fprintf(stderr, OUT_OF_MEMORY);
		return (-1);
	}

	ret = pread(dev_fd, filep->fi_memp, filep->fi_count, diskloc);
	if (ret < 0)
		perror("diskread: pread");
	return (ret >= 0 ? 0 : -1);
}

void *
bkmem_alloc(size_t s)
{
	return (malloc(s));
}

/*ARGSUSED*/
void
bkmem_free(void *p, size_t s)
{
	free(p);
}

static int
mountroot(char *name)
{
	int i;

	/* try ops in bfs_tab and return the first successful one */
	for (i = 0; bfs_tab[i] != NULL; i++) {
		bfs_ops = bfs_tab[i];
		if (BRD_MOUNTROOT(bfs_ops, name) == 0)
			return (0);
	}
	return (-1);
}

static int
unmountroot()
{
	return (BRD_UNMOUNTROOT(bfs_ops));
}

static int
pcfs_glue_open(const char *filename, int flags)
{
	return (BRD_OPEN(bfs_ops, (char *)filename, flags));
}

static int
pcfs_glue_close(int fd)
{
	return (BRD_CLOSE(bfs_ops, fd));
}

static ssize_t
pcfs_glue_read(int fd, void *buf, size_t size)
{
	return (BRD_READ(bfs_ops, fd, buf, size));
}

/*
 * Get the blocklist for stage2
 */
int
read_stage2_blocklist(int device_fd, unsigned int *blkbuf)
{
	int i, fd, stage2_block;
	char buf[DEV_BSIZE];
	ssize_t size;

	dev_fd = device_fd;
	if (mountroot("dummy") != 0) {
		fprintf(stderr, MOUNT_FAIL_PCFS);
		return (-1);
	}

	if ((fd = pcfs_glue_open("/boot/grub/stage2", 0)) == -1) {
		fprintf(stderr, OPEN_FAIL_PCFS);
		return (-1);
	}

	if (bootrd_debug)
		(void) printf("start reading stage2:\n");
	stage2_block = 0;
	blocklist = blkbuf;
	fileread_callback = add_stage2_block;
	for (;;) {
		size = pcfs_glue_read(fd, buf, DEV_BSIZE);
		if (size != DEV_BSIZE)
			break;
		stage2_block++;
	}
	fileread_callback = NULL;
	(void) pcfs_glue_close(fd);

	if (bootrd_debug) {
		(void) printf("last block size = %d\n", size);
		for (i = 0; blocklist[i] != 0; i += 2) {
			(void) printf("sectors: %d-%d\n",
			    blocklist[i],
			    blocklist[i] + blocklist[i + 1] - 1);
		}
		(void) printf("total blocks in stage 2: %d\n", stage2_block);
	}

	(void) unmountroot();
	return (0);
}
