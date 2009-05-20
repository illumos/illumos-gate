/*
    geom_dal.h -- parted device abstraction layer
    Copyright (C) 2001, 2002, 2007 Free Software Foundation, Inc.

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

#ifndef GEOM_DAL_H
#define GEOM_DAL_H

#include <parted/parted.h>

#if DYNAMIC_LOADING || !DISCOVER_ONLY

#include <sys/stat.h>

typedef unsigned long blk_t;

struct dal_ops;

struct _dal {
    struct dal_ops *ops;
    const void *dev;
    size_t block_size;
    int flags;
    void *data;
    blk_t len;
};

typedef struct _dal dal_t;

struct dal_ops {
    blk_t (*len)(dal_t *);
    int (*read)(dal_t *, void *, blk_t, blk_t);
    int (*write)(dal_t *, void *, blk_t, blk_t);
    int (*sync)(dal_t *);
    int (*flags)(dal_t *);
    int (*equals)(dal_t *, dal_t *);
    int (*stat)(dal_t *, struct stat *);
    dev_t (*dev)(dal_t *);
};

extern dal_t *geom_dal_create(PedGeometry *geom, size_t block_size, int flags);
extern int geom_dal_reopen(dal_t *dal, int flags);
extern void geom_dal_free(dal_t *dal);

#endif

#endif
