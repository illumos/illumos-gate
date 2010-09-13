/*
    interface.c -- parted binding glue to libext2resize
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

/* VERSION: libext2resize 1.1.6 (by Lennert)
 * merged 1.1.11 changes (by Andrew)
 */

#include <config.h>

#include <parted/parted.h>
#include "ext2.h"
#include "parted_io.h"

static PedFileSystemType _ext2_type;
static PedFileSystemType _ext3_type;

struct ext2_dev_handle* ext2_make_dev_handle_from_parted_geometry(PedGeometry* geom);

static PedGeometry*
_ext2_generic_probe (PedGeometry* geom, int expect_ext3)
{
	struct ext2_super_block sb;

	if (!ped_geometry_read(geom, &sb, 2, 2))
		return NULL;

	if (EXT2_SUPER_MAGIC(sb) == EXT2_SUPER_MAGIC_CONST) {
		PedSector block_size = 1 << (EXT2_SUPER_LOG_BLOCK_SIZE(sb) + 1);
		PedSector block_count = EXT2_SUPER_BLOCKS_COUNT(sb);
		PedSector group_blocks = EXT2_SUPER_BLOCKS_PER_GROUP(sb);
		PedSector group_nr = EXT2_SUPER_BLOCK_GROUP_NR(sb);
		PedSector first_data_block = EXT2_SUPER_FIRST_DATA_BLOCK(sb);
		int version = EXT2_SUPER_REV_LEVEL(sb);
		int is_ext3 = (EXT2_SUPER_FEATURE_COMPAT(sb) 
				& EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0;

		if (expect_ext3 != is_ext3)
			return NULL;

		if (version > 0 && group_nr > 0) {
			PedSector start;
			PedGeometry probe_geom;

			start = geom->start
					- group_blocks * group_nr
					- first_data_block;

			if (start < 0)
				return NULL;
			ped_geometry_init (&probe_geom, geom->dev,
					   start, block_count * block_size);
			return _ext2_generic_probe (&probe_geom, expect_ext3);
		} else {
			return ped_geometry_new (geom->dev, geom->start,
						 block_count * block_size);
		}
	}
	return NULL;
}

static PedGeometry*
_ext2_probe (PedGeometry* geom)
{
	return _ext2_generic_probe (geom, 0);
}

static PedGeometry*
_ext3_probe (PedGeometry* geom)
{
	return _ext2_generic_probe (geom, 1);
}

#ifndef DISCOVER_ONLY
static int
_ext2_clobber (PedGeometry* geom)
{
	struct ext2_super_block sb;

	if (!ped_geometry_read(geom, &sb, 2, 2))
		return 0;
	if (EXT2_SUPER_MAGIC(sb) != EXT2_SUPER_MAGIC_CONST)
		return 1;

	sb.s_magic = 0;
	return ped_geometry_write(geom, &sb, 2, 2);
}

static PedFileSystem*
_ext2_open (PedGeometry* geom)
{
	PedFileSystem*		fs;
	struct ext2_fs*		fs_info;
	struct ext2_dev_handle*	handle;

	fs = (PedFileSystem*) ped_malloc (sizeof (PedFileSystem));
	if (!fs) goto error;

	fs->type = &_ext2_type;
	fs->geom = ped_geometry_duplicate (geom);
	fs->checked = 1;

	handle = ext2_make_dev_handle_from_parted_geometry(fs->geom);
	if (!handle) goto error_free_fs;

	fs_info = (struct ext2_fs*) ext2_open(handle, 0);
	if (!fs_info) goto error_free_handle;

	fs->type_specific = (void*) fs_info;
	fs_info->opt_verbose = 0;

	return fs;

error_free_handle:
	ext2_destroy_dev_handle(handle);
error_free_fs:
	ped_free(fs);
error:
	return NULL;
}

static PedFileSystem*
_ext2_create (PedGeometry* geom, PedTimer* timer)
{
	PedFileSystem*		fs;
	struct ext2_fs*		fs_info;
	struct ext2_dev_handle*	handle;

	fs = (PedFileSystem*) ped_malloc (sizeof (PedFileSystem));
	if (!fs) goto error;

	fs->type = &_ext2_type;
	fs->geom = ped_geometry_duplicate (geom);

	handle = ext2_make_dev_handle_from_parted_geometry(fs->geom);
	if (!handle) goto error_free_fs;

	fs_info = ext2_mkfs (handle, 0, 0, 0, 0, -1, -1, timer);
	if (!fs_info) goto error_free_handle;

	fs->type_specific = (void*) fs_info;
	fs_info->opt_verbose = 0;

	return fs;

error_free_handle:
	ext2_destroy_dev_handle(handle);
error_free_fs:
	ped_free(fs);
error:
	return NULL;
}

static int
_ext2_close (PedFileSystem *fs)
{
	struct ext2_dev_handle* handle;

	handle = ((struct ext2_fs*)fs->type_specific)->devhandle;
	ext2_close(fs->type_specific);
	ext2_destroy_dev_handle(handle);

	ped_free(fs);
	return 1;
}

static int
_ext2_check (PedFileSystem *fs, PedTimer* timer)
{
	ped_exception_throw (PED_EXCEPTION_INFORMATION, PED_EXCEPTION_OK,
		_("The ext2 file system passed a basic check.  For a more "
		  "comprehensive check, use the e2fsck program."));
	return 1;
}

static int
_ext2_resize (PedFileSystem* fs, PedGeometry* geom, PedTimer* timer)
{
	struct ext2_fs* f;
	PedSector	old_length = fs->geom->length;

	PED_ASSERT (fs->geom->dev == geom->dev, return 0);

	if (fs->geom->start != geom->start)
	{
		ped_exception_throw (PED_EXCEPTION_NO_FEATURE,
		      PED_EXCEPTION_CANCEL,
		      _("Sorry, can't move the start of ext2 partitions yet!"));
		return 0;
	}

	geom->dev->boot_dirty = 1;

	f = (struct ext2_fs *) fs->type_specific;

/* ensure that the geometry contains the new and old geometry */
	if (old_length > geom->length) {
		if (!ext2_resize_fs(f, geom->length >> (f->logsize - 9),
				    timer))
			goto error;

		fs->geom->length = geom->length;
		fs->geom->end = fs->geom->start + geom->length - 1;
	} else {
		fs->geom->length = geom->length;
		fs->geom->end = fs->geom->start + geom->length - 1;

		if (!ext2_resize_fs(f, geom->length >> (f->logsize - 9),
				    timer))
			goto error;
	}
	return 1;

error:
	return 0;
}

static PedConstraint*
_ext2_get_create_constraint (const PedDevice* dev)
{
	PedGeometry	full_dev;

	if (!ped_geometry_init (&full_dev, dev, 0, dev->length - 1))
		return NULL;

	return ped_constraint_new (
			ped_alignment_any, ped_alignment_any,
			&full_dev, &full_dev,
			64, dev->length);
}

static PedConstraint*
_ext2_get_resize_constraint (const PedFileSystem* fs)
{
	struct ext2_fs* f = (struct ext2_fs *) fs->type_specific;
	PedDevice*	dev = fs->geom->dev;
	PedAlignment	start_align;
	PedGeometry	start_sector;
	PedGeometry	full_dev;
	PedSector	min_size;

	if (!ped_alignment_init (&start_align, fs->geom->start, 0))
		return NULL;
	if (!ped_geometry_init (&full_dev, dev, 0, dev->length - 1))
		return NULL;
	if (!ped_geometry_init (&start_sector, dev, fs->geom->start, 1))
		return NULL;
	min_size = (EXT2_SUPER_BLOCKS_COUNT(f->sb)
		   	- EXT2_SUPER_FREE_BLOCKS_COUNT(f->sb))
		   * (f->blocksize / dev->sector_size);

	return ped_constraint_new (&start_align, ped_alignment_any,
				   &start_sector, &full_dev, min_size,
				   dev->length);
}
#endif /* !DISCOVER_ONLY */

static PedFileSystemOps _ext2_ops = {
	.probe =		_ext2_probe,
#ifndef DISCOVER_ONLY
	.clobber =	_ext2_clobber,
	.open =		_ext2_open,
	.create =         _ext2_create,
	.close =		_ext2_close,
	.check =          _ext2_check,
	.resize =		_ext2_resize,
	.copy =           NULL,
	.get_create_constraint =	_ext2_get_create_constraint,
	.get_copy_constraint =	NULL,
	.get_resize_constraint =	_ext2_get_resize_constraint
#else /* !DISCOVER_ONLY */
	.clobber =	NULL,
	.open =		NULL,
	.create =         NULL,
	.close =		NULL,
	.check =          NULL,
	.resize =		NULL,
	.copy =           NULL,
	.get_create_constraint =	NULL,
	.get_copy_constraint =	NULL,
	.get_resize_constraint =	NULL
#endif /* !DISCOVER_ONLY */
};

static PedFileSystemOps _ext3_ops = {
	.probe =		_ext3_probe,
#ifndef DISCOVER_ONLY
	.clobber =	_ext2_clobber,
	.open =		_ext2_open,
	.create =         NULL,
	.close =		_ext2_close,
	.check =          _ext2_check,
	.resize =		_ext2_resize,
	.copy =           NULL,
	.get_create_constraint =	_ext2_get_create_constraint,
	.get_copy_constraint =	NULL,
	.get_resize_constraint =	_ext2_get_resize_constraint
#else /* !DISCOVER_ONLY */
	.clobber =	NULL,
	.open =		NULL,
	.create =         NULL,
	.close =		NULL,
	.check =          NULL,
	.resize =		NULL,
	.copy =           NULL,
	.get_create_constraint =	NULL,
	.get_copy_constraint =	NULL,
	.get_resize_constraint =	NULL
#endif /* !DISCOVER_ONLY */
};

#define EXT23_BLOCK_SIZES ((int[6]){512, 1024, 2048, 4096, 8192, 0})

static PedFileSystemType _ext2_type = {
       .next =		 NULL,
       .ops =		 &_ext2_ops,
       .name =		 "ext2",
       .block_sizes =      EXT23_BLOCK_SIZES
};

static PedFileSystemType _ext3_type = {
       .next =		 NULL,
       .ops =		 &_ext3_ops,
       .name =		 "ext3",
       .block_sizes =      EXT23_BLOCK_SIZES
};

void ped_file_system_ext2_init ()
{
	ped_file_system_type_register (&_ext2_type);
	ped_file_system_type_register (&_ext3_type);
}

void ped_file_system_ext2_done ()
{
	ped_file_system_type_unregister (&_ext2_type);
	ped_file_system_type_unregister (&_ext3_type);
}
