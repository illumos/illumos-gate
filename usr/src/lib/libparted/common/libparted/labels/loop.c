/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 1999, 2000, 2007 Free Software Foundation, Inc.

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

#include <parted/parted.h>
#include <parted/debug.h>
#include <parted/endian.h>

#if ENABLE_NLS
#  include <libintl.h>
#  define _(String) dgettext (PACKAGE, String)
#else
#  define _(String) (String)
#endif /* ENABLE_NLS */

#define	LOOP_SIGNATURE		"GNU Parted Loopback 0"

static PedDiskType loop_disk_type;

static PedDisk* loop_alloc (const PedDevice* dev);
static void loop_free (PedDisk* disk);

static int
loop_probe (const PedDevice* dev)
{
	PedDisk*	disk;
	char		buf [512];
	int		result;

        if (dev->sector_size != 512)
                return 0;

	disk = loop_alloc (dev);
	if (!disk)
		goto error;

	if (!ped_device_read (dev, buf, 0, 1))
		goto error_destroy_disk;
	if (strncmp (buf, LOOP_SIGNATURE, strlen (LOOP_SIGNATURE)) == 0) {
		result = 1;
	} else {
		PedGeometry*	geom;

		geom = ped_geometry_new (dev, 0, disk->dev->length);
		if (!geom)
			goto error_destroy_disk;
		result = ped_file_system_probe (geom) != NULL;
		ped_geometry_destroy (geom);
	}
	loop_free (disk);
	return result;

error_destroy_disk:
	loop_free (disk);
error:
	return 0;
}

#ifndef DISCOVER_ONLY
static int
loop_clobber (PedDevice* dev)
{
	char		buf [512];
	PedSector	i = 0;

	PED_ASSERT (dev != NULL, return 0);

	memset (buf, 0, 512);

	while (loop_probe (dev)) {
		if (!ped_device_write (dev, buf, i++, 1))
			return 0;
	}
	return 1;
}
#endif /* !DISCOVER_ONLY */

static PedDisk*
loop_alloc (const PedDevice* dev)
{
	PED_ASSERT (dev != NULL, return 0);

	if (dev->length < 256)
		return NULL;
	return _ped_disk_alloc ((PedDevice*)dev, &loop_disk_type);
}

static PedDisk*
loop_duplicate (const PedDisk* disk)
{
	return ped_disk_new_fresh (disk->dev, &loop_disk_type);
}

static void
loop_free (PedDisk* disk)
{
	PED_ASSERT (disk != NULL, return);

	_ped_disk_free (disk);
}

static int
loop_read (PedDisk* disk)
{
	PedDevice*		dev = NULL;
	char			buf [512];
	PedGeometry*		geom;
	PedFileSystemType*	fs_type;
	PedPartition*		part;
	PedConstraint*		constraint_any;

	PED_ASSERT (disk != NULL, return 0);
	dev = disk->dev;
	constraint_any = ped_constraint_any (dev);

	ped_disk_delete_all (disk);

	if (!ped_device_read (dev, buf, 0, 1))
		goto error;
	if (!strncmp (buf, LOOP_SIGNATURE, strlen (LOOP_SIGNATURE)))
		return 1;

	geom = ped_geometry_new (dev, 0, dev->length);
	if (!geom)
		goto error;

	fs_type = ped_file_system_probe (geom);
	if (!fs_type)
		goto error_free_geom;

	part = ped_partition_new (disk, 0, fs_type, geom->start, geom->end);
	ped_geometry_destroy (geom);
	if (!part)
		goto error;
	part->fs_type = fs_type;

	if (!ped_disk_add_partition (disk, part, constraint_any))
		goto error;
	ped_constraint_destroy (constraint_any);
	return 1;

error_free_geom:
	ped_geometry_destroy (geom);
error:
	ped_constraint_destroy (constraint_any);
	return 0;
}

#ifndef DISCOVER_ONLY
static int
loop_write (const PedDisk* disk)
{
	char		buf [512];

	if (ped_disk_get_partition (disk, 1)) {
		if (!ped_device_read (disk->dev, buf, 0, 1))
			return 0;
		if (strncmp (buf, LOOP_SIGNATURE, strlen (LOOP_SIGNATURE)) != 0)
	       		return 1;
		memset (buf, 0, strlen (LOOP_SIGNATURE));
		return ped_device_write (disk->dev, buf, 0, 1);
	}

	memset (buf, 0, 512);
	strcpy (buf, LOOP_SIGNATURE);

	return ped_device_write (disk->dev, buf, 0, 1);
}
#endif /* !DISCOVER_ONLY */

static PedPartition*
loop_partition_new (const PedDisk* disk, PedPartitionType part_type,
		    const PedFileSystemType* fs_type,
		    PedSector start, PedSector end)
{
	PedPartition*	part;
	
	part = _ped_partition_alloc (disk, part_type, fs_type, start, end);
	if (!part)
		return NULL;
	part->disk_specific = NULL;
	return part;
}

static PedPartition*
loop_partition_duplicate (const PedPartition* part)
{
	PedPartition* result;
	
	result = ped_partition_new (part->disk, part->type, part->fs_type,
				    part->geom.start, part->geom.end);
	result->num = part->num;
	return result;
}

static void
loop_partition_destroy (PedPartition* part)
{
	ped_free (part);
}

static int
loop_partition_set_system (PedPartition* part, const PedFileSystemType* fs_type)
{
	part->fs_type = fs_type;
	return 1;
}

static int
loop_partition_set_flag (PedPartition* part, PedPartitionFlag flag, int state)
{
	return 0;
}

static int
loop_partition_get_flag (const PedPartition* part, PedPartitionFlag flag)
{
	return 0;
}

static int
loop_partition_align (PedPartition* part, const PedConstraint* constraint)
{
	PedGeometry*	new_geom;

	new_geom = ped_constraint_solve_nearest (constraint, &part->geom);
	if (!new_geom) {
		ped_exception_throw (
			PED_EXCEPTION_ERROR,
			PED_EXCEPTION_CANCEL,
			_("Unable to satisfy all constraints on the "
			  "partition."));
		return 0;
	}
	ped_geometry_set (&part->geom, new_geom->start, new_geom->length);
	ped_geometry_destroy (new_geom);
	return 1;
}

static int
loop_partition_is_flag_available (const PedPartition* part,
	       			  PedPartitionFlag flag)
{
	return 0;
}

static int
loop_partition_enumerate (PedPartition* part)
{
	part->num = 1;
	return 1;
}

static int
loop_alloc_metadata (PedDisk* disk)
{
	return 1;
}

static int
loop_get_max_primary_partition_count (const PedDisk* disk)
{
	return 1;
}

static PedDiskOps loop_disk_ops = {
	.probe =		loop_probe,
#ifndef DISCOVER_ONLY
	.clobber =		loop_clobber,
#else
	.clobber =		NULL,
#endif
	.alloc =		loop_alloc,
	.duplicate =		loop_duplicate,
	.free =			loop_free,
	.read =			loop_read,
#ifndef DISCOVER_ONLY
	.write =		loop_write,
#else
	.write =		NULL,
#endif

	.partition_new =	loop_partition_new,
	.partition_duplicate =	loop_partition_duplicate,
	.partition_destroy =	loop_partition_destroy,
	.partition_set_system =	loop_partition_set_system,
	.partition_set_flag =	loop_partition_set_flag,
	.partition_get_flag =	loop_partition_get_flag,
	.partition_is_flag_available =	loop_partition_is_flag_available,
	.partition_set_name =	NULL,
	.partition_get_name =	NULL,
	.partition_align =	loop_partition_align,
	.partition_enumerate =	loop_partition_enumerate,

	.alloc_metadata =	loop_alloc_metadata,
	.get_max_primary_partition_count =
				loop_get_max_primary_partition_count
};

static PedDiskType loop_disk_type = {
	.next =		NULL,
	.name =		"loop",
	.ops =		&loop_disk_ops,
	.features =	0
};

void
ped_disk_loop_init ()
{
	ped_disk_type_register (&loop_disk_type);
}

void
ped_disk_loop_done ()
{
	ped_disk_type_unregister (&loop_disk_type);
}
