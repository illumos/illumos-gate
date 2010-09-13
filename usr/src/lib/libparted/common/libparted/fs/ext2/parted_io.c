/*
    parted_io.c -- parted I/O code interface for libext2resize
    Copyright (C) 1998-2000, 2007 Free Software Foundation, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>

#ifndef DISCOVER_ONLY

#include <parted/parted.h>
#include <stdio.h>
#include <stdlib.h>
#include "ext2.h"

/* pseudo-header.... */

loff_t llseek(unsigned int fd, loff_t offset, unsigned int whence);

struct my_cookie
{
	int logsize;
	PedGeometry* geom;
};

/* ...then this must be pseudo-code  :-) */

static int   do_close        (void *cookie);
static int   do_sync         (void *cookie);
static blk_t do_get_size     (void *cookie);
static int   do_read         (void *cookie, void *ptr, blk_t block, blk_t numblocks);
static int   do_set_blocksize(void *cookie, int logsize);
static int   do_write        (void *cookie, void *ptr, blk_t block, blk_t numblocks);

struct ext2_dev_ops ops =
{
	.close =		do_close,
	.get_size =	do_get_size,
	.read =		do_read,
	.set_blocksize =	do_set_blocksize,
	.sync =		do_sync,
	.write =		do_write
};



static int do_close(void *cookie)
{
	struct my_cookie *monster = cookie;

	return ped_geometry_sync(monster->geom);
}

static int do_sync(void *cookie)
{
	struct my_cookie *monster = cookie;

	return ped_geometry_sync(monster->geom);
}

static blk_t do_get_size(void *cookie)
{
	struct my_cookie *monster = cookie;

	return monster->geom->length >> (monster->logsize - 9);
}

static int do_read(void *cookie, void *ptr, blk_t block, blk_t num)
{
	struct my_cookie *monster = cookie;

	return ped_geometry_read(monster->geom, ptr, block << (monster->logsize - 9), num << (monster->logsize - 9));
}

static int do_set_blocksize(void *cookie, int logsize)
{
	struct my_cookie *monster = cookie;

	monster->logsize = logsize;
	return 1;
} 

static int do_write(void *cookie, void *ptr, blk_t block, blk_t num)
{
	struct my_cookie *monster = cookie;

	return ped_geometry_write(monster->geom, ptr,
				  block << (monster->logsize - 9),
				  num << (monster->logsize - 9));
}


struct ext2_dev_handle *ext2_make_dev_handle_from_parted_geometry(PedGeometry* geom)
{
	struct ext2_dev_handle *dh;
	struct my_cookie *monster;

	if ((dh = ped_malloc(sizeof(struct ext2_dev_handle))) == NULL)
		goto error;

	if ((monster = ped_malloc(sizeof(struct my_cookie))) == NULL)
		goto error_free_dh;

	dh->ops = &ops;
	dh->cookie = monster;
	monster->logsize = 9;
	monster->geom = geom;

	return dh;

error_free_dh:
	ped_free(dh);
error:
	return NULL;
}

void ext2_destroy_dev_handle(struct ext2_dev_handle *handle)
{
	ped_geometry_destroy(((struct my_cookie *)handle->cookie)->geom);
	ped_free(handle->cookie);
	ped_free(handle);
}
#endif /* !DISCOVER_ONLY */
