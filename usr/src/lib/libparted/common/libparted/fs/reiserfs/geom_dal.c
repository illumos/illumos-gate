/*
    geom_dal.c -- parted device abstraction layer
    Copyright (C) 2001, 2002, 2007  Free Software Foundation, Inc.

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

#if (DYNAMIC_LOADING || HAVE_LIBREISERFS) && !DISCOVER_ONLY

#include "geom_dal.h"

#include <parted/parted.h>
#include <parted/debug.h>

static blk_t __len(dal_t *dal) {
    PED_ASSERT(dal != NULL, return 0);
    
    return ((PedGeometry *)dal->dev)->length / 
	(dal->block_size / PED_SECTOR_SIZE_DEFAULT);
}

static int __read(dal_t *dal, void *buff, blk_t block, blk_t count) {
    blk_t k;
    PedSector block_pos;
    PedSector block_count;
    
    PED_ASSERT(dal != NULL, return 0);
    
    k = dal->block_size / PED_SECTOR_SIZE_DEFAULT;
    block_pos = (PedSector)(block * k);
    block_count = (PedSector)(count * k);
    
    return ped_geometry_read((PedGeometry *)dal->dev, buff, block_pos, block_count);
}

static int __write(dal_t *dal, void *buff, blk_t block, blk_t count) {
    blk_t k;
    PedSector block_pos;
    PedSector block_count;
    
    PED_ASSERT(dal != NULL, return 0);
    
    k = dal->block_size / PED_SECTOR_SIZE_DEFAULT;
    block_pos = (PedSector)(block * k);
    block_count = (PedSector)(count * k);
    
    return ped_geometry_write((PedGeometry *)dal->dev, buff, block_pos, 
	block_count);
}

static int __sync(dal_t *dal) {
    PED_ASSERT(dal != NULL, return 0);
    return ped_geometry_sync((PedGeometry *)dal->dev);
}

static int __flags(dal_t *dal) {
    PED_ASSERT(dal != NULL, return 0);
    return dal->flags;
}

static int __equals(dal_t *dal1, dal_t *dal2) {
    PED_ASSERT(dal1 != NULL, return 0);
    PED_ASSERT(dal2 != NULL, return 0);

    return ped_geometry_test_equal((PedGeometry *)dal1->dev, 
	(PedGeometry *)dal2->dev);
}

static int __stat(dal_t *dal, struct stat *st) {
    
    PED_ASSERT(dal != NULL, return 0);
    PED_ASSERT(st != NULL, return 0);
    
    if (stat(((PedGeometry *)dal->dev)->dev->path, st))
	return 0;

    return 1;
}

static dev_t __dev(dal_t *dal) {
    struct stat st;
    
    if (!__stat(dal, &st))
	return (dev_t)0;
	
    return st.st_dev;
}

static struct dal_ops ops = {
    __len, __read, __write, __sync, 
    __flags, __equals, __stat, __dev
};

dal_t *geom_dal_create(PedGeometry *geom, size_t block_size, int flags) {
    dal_t *dal;

    if (!geom) 
	return NULL;
    
    if (!(dal = ped_malloc(sizeof(dal_t))))
	return NULL;
    
    dal->ops = &ops;
    dal->dev = geom;
    dal->block_size = block_size;
    dal->flags = flags;
    dal->len = 0;

    return dal;
}

int geom_dal_reopen(dal_t *dal, int flags) {

    if (!dal) return 0;
    dal->flags = flags;
    
    return 1;
}

void geom_dal_free(dal_t *dal) {
    PED_ASSERT(dal != NULL, return);
    ped_free(dal);
}

#endif
