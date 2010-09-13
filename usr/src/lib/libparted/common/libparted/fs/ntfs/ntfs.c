/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 2000, 2007 Free Software Foundation, Inc.

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
#include <parted/endian.h>
#include <parted/debug.h>

#if ENABLE_NLS
#  include <libintl.h>
#  define _(String) dgettext (PACKAGE, String)
#else
#  define _(String) (String)
#endif /* ENABLE_NLS */

#include <unistd.h>
#include <string.h>
#include <limits.h> /* for PATH_MAX */

#define NTFS_BLOCK_SIZES	((int[2]){512, 0})

#define NTFS_SIGNATURE		"NTFS"

#define NTFSRESIZE_CMD_PATH	"ntfsresize"
#define NTFSCREATE_CMD_PATH	"mkntfs"
#define NTFSFIX_CMD_PATH	"ntfsfix"
#define NTFSCLONE_CMD_PATH	"ntfsclone"

static PedFileSystemType ntfs_type;

static char bigbuf[128*1024];	/* for command output storage */

static PedGeometry*
ntfs_probe (PedGeometry* geom)
{
	char	buf[512];

	PED_ASSERT(geom != NULL, return 0);

	if (!ped_geometry_read (geom, buf, 0, 1))
		return 0;

	if (strncmp (NTFS_SIGNATURE, buf + 3, strlen (NTFS_SIGNATURE)) == 0)
		return ped_geometry_new (geom->dev, geom->start,
					 PED_LE64_TO_CPU (*(uint64_t*)
						 	  (buf + 0x28)));
	else
		return NULL;
}

#ifndef DISCOVER_ONLY
static int
ntfs_clobber (PedGeometry* geom)
{
	char	buf[512];

	PED_ASSERT(geom != NULL, return 0);

	memset (buf, 0, sizeof(buf));
	return ped_geometry_write (geom, buf, 0, 1);
}

static PedFileSystem*
ntfs_open (PedGeometry* geom)
{
	PedFileSystem*		fs;

	PED_ASSERT(geom != NULL, return 0);

	fs = (PedFileSystem*) ped_malloc (sizeof (PedFileSystem));
	if (!fs)
		return NULL;

	fs->type = &ntfs_type;
	fs->geom = ped_geometry_duplicate (geom);
	fs->checked = 1; /* XXX */
	fs->type_specific = NULL;

	return fs;
}

/*
 * Returns partition number (1..4) that contains geom, 0 otherwise.
 */
static int
_get_partition_num_by_geom(const PedGeometry* geom)
{
        PedDisk *disk;
	PedPartition *part;
	int partnum = 0;

	PED_ASSERT(geom != NULL, return 0);

        disk = ped_disk_new (geom->dev);
        if (!disk) {
		printf("_get_partition_num_by_geom: ped_disk_new failed!\n");
	}
	else {
		part = ped_disk_get_partition_by_sector (disk, geom->start);
		if (part == NULL) {
			printf("_get_partition_num_by_geom: "
				"ped_disk_get_partition_by_sector failed!\n");
		}
		else {
			if (part->num > 0)
				partnum = part->num;
		}
		ped_disk_destroy (disk);
	}
	return partnum;
}

/*
 * return the partition device name for geom in partpath.
 * return 1 on success, 0 on failure.
 */
static int
_get_part_device_path(const PedGeometry* geom, char *partpath, const int len)
{
	int partnum;

	PED_ASSERT(geom != NULL, return 0);
	PED_ASSERT(partpath != NULL, return 0);

	partnum = _get_partition_num_by_geom(geom);
	if (!partnum)
		return 0;

	strncpy(partpath, geom->dev->path, len);
	/*
	 * XXX Solaris specific
	 * Create the path name to the *pn device, where n is the partition #
	 * geom->dev->path looks like this: "/devices/.../cmdk@0,0:q"
	 * or like this: "/dev/dsk/...p0"
	 * ":q" is the "/dev/dsk/...p0" device
	 * :r is p1, :s is p2, :t is p3, :u is p4
	 * 'q' + 1 == 'r'
	 * '0' + 1 == '1'
	 */
	partpath[strlen(partpath) -1] += partnum;

	return 1;
}

/*
 * Executes cmd in a pipe.
 * Returns -1 on popen failure or the return value from pclose.
 * Saves the output from cmd in bigbuf for later display.
 */
static int
_execute(const char *cmd)
{
	FILE *fp;
	char buf[512];
	int szbigbuf;

	PED_ASSERT(cmd != NULL, return 0);

	fp = popen(cmd, "r");
	if (fp == NULL)
		return -1;

	strcpy(bigbuf, "");
	szbigbuf = sizeof(bigbuf) -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (szbigbuf > 0) {
			strncat(bigbuf, buf, szbigbuf);
			szbigbuf -= strlen(buf);
		}
	}

	return pclose(fp);
}

/*
 * ./mkntfs -f -s 512 -S 63 -H 255 -p 0 /dev/dsk/c0d0p1
 * Returns new fs on success, NULL on failure.
 */
PedFileSystem*
ntfs_create (PedGeometry* geom, PedTimer* timer)
{
	int x;
	PedFileSystem* fs = NULL;
	char partpath[PATH_MAX];
	char cmd[PATH_MAX];

	PED_ASSERT(geom != NULL, return 0);
	PED_ASSERT(timer != NULL, return 0);

	ped_timer_reset (timer);
	ped_timer_update (timer, 0.0);
	ped_timer_set_state_name(timer, _("creating"));

	if (_get_part_device_path(geom, partpath, sizeof(partpath)) == 0)
		goto error;

	snprintf(cmd, sizeof(cmd), "%s -f -s %lld -S %d -H %d -p %lld %s",
		NTFSCREATE_CMD_PATH,
		geom->dev->sector_size,
		geom->dev->hw_geom.sectors,
		geom->dev->hw_geom.heads,
		(PedSector) 0,		/* partition start sector */
		partpath);
	printf("%s\n", cmd);

	/*
	 * Use system() so the output that shows progress is displayed.
	 */
	ped_device_begin_external_access(geom->dev);
	x = system(cmd);
	ped_device_end_external_access(geom->dev);

	if (x != 0) {
		goto error;
	}

	fs = (PedFileSystem*) ped_malloc (sizeof (PedFileSystem));
	if (!fs)
		goto error;
	fs->type = &ntfs_type;
	fs->geom = ped_geometry_duplicate (geom);
	fs->checked = 1; /* XXX */
	fs->type_specific = NULL;

error:
	ped_timer_update (timer, 1.0);
	return fs;
}

/*
 * Returns 1 on success, 0 on failure.
 */
static int
ntfs_close (PedFileSystem *fs)
{
	PED_ASSERT(fs != NULL, return 0);

	ped_geometry_destroy (fs->geom);
	ped_free (fs);

	return 1;
}

/*
 * ntfsfix /dev/dsk/c0d0p1
 * Returns 1 on success, 0 on failure.
 */
static int
ntfs_check(PedFileSystem *fs, PedTimer *timer)
{
	int x;
	int ret = 0;
	char partpath[PATH_MAX];
	char cmd[PATH_MAX];

	PED_ASSERT(fs != NULL, return 0);
	PED_ASSERT(timer != NULL, return 0);

	ped_timer_reset(timer);
	ped_timer_set_state_name(timer, _("checking"));
	ped_timer_update(timer, 0.0);
	
	if (_get_part_device_path(fs->geom, partpath, sizeof(partpath)) == 0)
		goto error;

	snprintf(cmd, sizeof(cmd), "%s %s",
		NTFSFIX_CMD_PATH, partpath);
	printf("%s\n", cmd);

	/*
	 * Use system() so the output that shows progress is displayed.
	 */
	ped_device_begin_external_access(fs->geom->dev);
	x = system(cmd);
	ped_device_end_external_access(fs->geom->dev);

	if (x == 0) {
		ret = 1; /* return success to the upper layer */
	}
	else {
		goto error;
	}

error:
	ped_timer_update(timer, 1.0);
	return ret;
}

/*
 * Copy from source fs to destination geom.
 * The destination partition must alreay exist.
 * ntfsclone --overwrite destination-device source-device
 * Returns new fs on success, NULL on failure.
 */
static PedFileSystem*
ntfs_copy(const PedFileSystem *fs, PedGeometry *geom, PedTimer *timer)
{
	int x;
	char spartpath[PATH_MAX];
	char dpartpath[PATH_MAX];
	char cmd[PATH_MAX];
	PedFileSystem *new_fs = NULL;

	PED_ASSERT(fs != NULL, return 0);
	PED_ASSERT(geom != NULL, return 0);
	PED_ASSERT(timer != NULL, return 0);

	ped_timer_reset(timer);
	ped_timer_set_state_name(timer, _("copying"));
	ped_timer_update(timer, 0.0);

	if (_get_part_device_path(fs->geom, spartpath, sizeof(spartpath)) == 0)
		goto error;

	if (_get_part_device_path(geom, dpartpath, sizeof(dpartpath)) == 0)
		goto error;

	snprintf(cmd, sizeof(cmd), "%s --overwrite %s %s",
		NTFSCLONE_CMD_PATH, dpartpath, spartpath);
	printf("%s\n", cmd);

	/*
	 * Use system() so the output that shows progress is displayed.
	 */
	ped_device_begin_external_access(geom->dev);
	x = system(cmd);
	ped_device_end_external_access(geom->dev);

	if (x != 0) {
		goto error;
	}

	if (!(new_fs = (PedFileSystem *) ped_malloc(sizeof(PedFileSystem))))
		goto error;

	new_fs->type = &ntfs_type;
	new_fs->geom = ped_geometry_duplicate(geom);
	new_fs->checked = 0;
	new_fs->type_specific = NULL;

error:
	ped_timer_update(timer, 1.0);
	return new_fs;
}

/*
 * fs->geom has the current filesystem size in sectors.
 * geom has the new, requested filesystem size in sectors.
 *
 * fs->geom->dev is the same object as geom->dev.
 * geom->dev->path looks like this:
 *   /dev/dsk/...p0
 * or this:
 *   /devices/.../cmdk@0,0:q
 *
 * The ntfsresize cmd wants the block disk device, not the raw one.
 * It also wants the partition device, not the whole disk.
 *
 * Returns 1 on success, 0 on failure.
 */
static int
ntfs_resize (PedFileSystem* fs, PedGeometry* geom, PedTimer* timer)
{
	int x;
	int ret = 0; /* this tells the upper layer NOT to resize partition */
	char partpath[PATH_MAX];
	char cmd[PATH_MAX];

	PED_ASSERT(fs != NULL, return 0);
	PED_ASSERT(geom != NULL, return 0);
	PED_ASSERT(timer != NULL, return 0);

	if (fs->geom->start != geom->start) {
		ped_exception_throw(PED_EXCEPTION_ERROR,
		                    PED_EXCEPTION_CANCEL,
		                    _("Sorry, can't move the start of "
		                      "ntfs partitions yet."));
		return 0;
	}

	ped_timer_reset (timer);
	ped_timer_update (timer, 0.0);

	if (fs->geom->length > geom->length) {
		ped_timer_set_state_name(timer, _("shrinking"));
	}
	else if (fs->geom->length < geom->length) {
		ped_timer_set_state_name(timer, _("enlarging"));
	}
	else {
		ped_timer_set_state_name(timer, _("no change"));
	}

	if (_get_part_device_path(fs->geom, partpath, sizeof(partpath)) == 0)
		goto error1;

	ped_device_begin_external_access(geom->dev);

	/*
	 * ntfsresize -f says don't worry about consistency flag
	 */
	snprintf(cmd, sizeof(cmd), "%s -f -i %s",
		NTFSRESIZE_CMD_PATH, partpath);
	printf("%s\n", cmd);
	x = _execute(cmd);
	if (x != 0) {
		printf("ntfsresize had this message:\n%s\n", bigbuf);
		goto error2;
	}

	snprintf(cmd, sizeof(cmd), "%s -f -n -s %lld %s",
	    NTFSRESIZE_CMD_PATH,
	    geom->length * geom->dev->sector_size, partpath);
	printf("%s\n", cmd);
	x = _execute(cmd);
	if (x != 0) {
		printf("ntfsresize had this message:\n%s\n", bigbuf);
		goto error2;
	}

	/*
	 * ntfsresize -f -f means don't ask "Are you sure?"
	 * Use system() so the output that shows progress is displayed.
	 */
	snprintf(cmd, sizeof(cmd), "%s -f -f -s %lld %s",
	    NTFSRESIZE_CMD_PATH,
	    geom->length * geom->dev->sector_size, partpath);
	printf("%s\n", cmd);
	x = system(cmd);
	if (x == 0) {
		ret = 1; /* this tells upper layer to resize the partition */
	}
	else {
		goto error2;
	}

error2:
	ped_device_end_external_access(geom->dev);
error1:
	ped_timer_update (timer, 1.0);
	return ret;
}

/*
 * return the minimum resize size from the ntfsresize external cmd
 * in blocks, 0 on error.
 * Saves the output from cmd in bigbuf for later display.
 */
static PedSector
_get_min_from_ntfsresize(const char *cmd)
{
	FILE *fp;
	char buf[512];
	PedSector size = 0;
	int x;
	int szbigbuf;

	PED_ASSERT(cmd != NULL, return 0);

	fp = popen(cmd, "r");
	if (fp == NULL)
		return 0;

	strcpy(bigbuf, "");
	szbigbuf = sizeof(bigbuf) -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (szbigbuf > 0) {
			strncat(bigbuf, buf, szbigbuf);
			szbigbuf -= strlen(buf);
		}
		x = sscanf(buf, "You might resize at %lld", &size);
		if (x > 0)
			break;
	}

	pclose(fp);
	return size;
}

/*
 * return the minimum resize size in blocks, fs->geom->length on error.
 */
static PedSector
_get_min_resize_size (const PedFileSystem* fs)
{
	PedSector	max_length = fs->geom->length;
	PedSector	length;
	char partpath[PATH_MAX];
	char cmd[PATH_MAX];

	PED_ASSERT(fs != NULL, return 0);

	if (_get_part_device_path(fs->geom, partpath, sizeof(partpath)) == 0)
		return max_length;

	snprintf(cmd, sizeof(cmd), "%s -f -i %s",
		NTFSRESIZE_CMD_PATH, partpath);

	length = _get_min_from_ntfsresize(cmd);
	if (length == 0) {
		printf("ntfsresize had this message:\n%s\n", bigbuf);
		return max_length;
	}

	return (length / fs->geom->dev->sector_size);
}

PedConstraint*
ntfs_get_copy_constraint (const PedFileSystem* fs, const PedDevice* dev)
{
	PedGeometry	full_dev;

	PED_ASSERT(fs != NULL, return 0);
	PED_ASSERT(dev != NULL, return 0);

	if (!ped_geometry_init (&full_dev, dev, 0, dev->length - 1))
		return NULL;

	return ped_constraint_new (ped_alignment_any, ped_alignment_any,
				   &full_dev, &full_dev,
				   _get_min_resize_size (fs),
				   dev->length);
}

PedConstraint*
ntfs_get_resize_constraint (const PedFileSystem* fs)
{
	PED_ASSERT(fs != NULL, return 0);

	return ntfs_get_copy_constraint (fs, fs->geom->dev);
}

#endif /* !DISCOVER_ONLY */

static PedFileSystemOps ntfs_ops = {
	.probe =		ntfs_probe,
#ifndef DISCOVER_ONLY
	.clobber =	ntfs_clobber,
	.open =		ntfs_open,
	.create =		ntfs_create,
	.close =		ntfs_close,
	.check =		ntfs_check,
	.copy =		ntfs_copy,
	.resize =		ntfs_resize,
	.get_create_constraint =	NULL,
	.get_resize_constraint =	ntfs_get_resize_constraint,
	.get_copy_constraint =	ntfs_get_copy_constraint
#else
	.clobber =	NULL,
	.open =		NULL,
	.create =		NULL,
	.close =		NULL,
	.check =		NULL,
	.copy =		NULL,
	.resize =		NULL,
	.get_create_constraint =	NULL,
	.get_resize_constraint =	NULL,
	.get_copy_constraint =	NULL
#endif 
};

static PedFileSystemType ntfs_type = {
	.next =	NULL,
	.ops =	&ntfs_ops,
	.name =	"ntfs",
	.block_sizes = NTFS_BLOCK_SIZES
};

void
ped_file_system_ntfs_init ()
{
	ped_file_system_type_register (&ntfs_type);
}

void
ped_file_system_ntfs_done ()
{
	ped_file_system_type_unregister (&ntfs_type);
}


