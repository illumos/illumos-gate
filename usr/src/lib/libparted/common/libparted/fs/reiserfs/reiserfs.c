/*
    reiserfs.c -- libparted / libreiserfs glue
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

    This is all rather complicated.  There are a few combinations:
	* shared libraries full support
	* dynamic libraries present full support (via dlopen)
	* dynamic libraries absent (full support disabled) (via dlopen)
	* discover only

    We'd love to hear comments...

    So far, we've opted for maximum flexibility for the user.  Is it
    all worth it?
*/

#include <config.h>

#if (HAVE_LIBREISERFS || DYNAMIC_LOADING) && !DISCOVER_ONLY
#	define REISER_FULL_SUPPORT
#endif

#include <uuid/uuid.h>
#include <fcntl.h>
#include <errno.h>

#ifdef DYNAMIC_LOADING
#	include <dlfcn.h>
#endif

#include <parted/parted.h>
#include <parted/debug.h>
#include <parted/endian.h>

#if ENABLE_NLS
#	include <libintl.h>
#	define _(String) dgettext (PACKAGE, String)
#else
#	define _(String) (String)
#endif

#include "reiserfs.h"
#include "geom_dal.h"

#define REISERFS_BLOCK_SIZES       ((int[2]){512, 0})

static PedSector reiserfs_super_offset[] = { 128, 16, -1 };
static PedFileSystemType* reiserfs_type;

#ifdef DYNAMIC_LOADING
#	define FPTR *
#	define FCLASS static
#else
#	define FPTR
#	define FCLASS extern
#endif

#ifdef DYNAMIC_LOADING

static int libreiserfs_present;

static void *libdal_handle;
static void *libreiserfs_handle;

#endif /* DYNAMIC_LOADING */

#ifdef REISER_FULL_SUPPORT

FCLASS blk_t (FPTR reiserfs_fs_probe) (dal_t *);

FCLASS int (FPTR libreiserfs_exception_type) (reiserfs_exception_t *);
FCLASS int (FPTR libreiserfs_exception_option) (reiserfs_exception_t *);
FCLASS char *(FPTR libreiserfs_exception_message) (reiserfs_exception_t *);
FCLASS void (FPTR libreiserfs_exception_set_handler)
		(int(FPTR)(reiserfs_exception_t *));

FCLASS void (FPTR dal_realize) (dal_t *);
FCLASS size_t (FPTR dal_block_size) (dal_t *);
FCLASS blk_t (FPTR dal_len) (dal_t *);
FCLASS int (FPTR dal_flags) (dal_t *);

FCLASS reiserfs_fs_t* (FPTR reiserfs_fs_open) (dal_t *, dal_t *);
FCLASS reiserfs_fs_t* (FPTR reiserfs_fs_create) (dal_t *, dal_t *,
					  blk_t, blk_t, blk_t, size_t,
					  int, int, const char *,
					  const char *, blk_t,
				          reiserfs_gauge_t *);

FCLASS int (FPTR reiserfs_fs_resize) (reiserfs_fs_t *, blk_t, reiserfs_gauge_t *);
#ifdef HAVE_REISERFS_FS_CHECK
FCLASS int (FPTR reiserfs_fs_check) (reiserfs_fs_t *, reiserfs_gauge_t *);
#endif

FCLASS reiserfs_fs_t *(FPTR reiserfs_fs_copy) (reiserfs_fs_t *, dal_t *,
					reiserfs_gauge_t *);

FCLASS int (FPTR reiserfs_fs_clobber) (dal_t *);
FCLASS void (FPTR reiserfs_fs_close) (reiserfs_fs_t *);

FCLASS int (FPTR reiserfs_fs_is_resizeable) (reiserfs_fs_t *);
FCLASS int (FPTR reiserfs_fs_is_consistent) (reiserfs_fs_t *);

FCLASS blk_t (FPTR reiserfs_fs_min_size) (reiserfs_fs_t *);
FCLASS blk_t (FPTR reiserfs_fs_block_size) (reiserfs_fs_t *);
FCLASS dal_t* (FPTR reiserfs_fs_host_dal) (reiserfs_fs_t *);

FCLASS blk_t (FPTR reiserfs_fs_bitmap_used) (reiserfs_fs_t *);
FCLASS int (FPTR reiserfs_fs_bitmap_check) (reiserfs_fs_t *);

FCLASS reiserfs_gauge_t *(FPTR libreiserfs_gauge_create) (
	char *, reiserfs_gauge_handler_t, void *);

FCLASS void (FPTR libreiserfs_gauge_free) (reiserfs_gauge_t *);

static void gauge_handler(const char *name, unsigned int value, void *data,
			  int determined, int update_header,
			  int update_footer)
{
	PedTimer *timer = (PedTimer *) data;
	ped_timer_set_state_name(timer, name);
	ped_timer_update(timer, 1.0 * value / 100);
}

static PedExceptionOption
exopt_libreiserfs_to_parted(reiserfs_exception_option_t option)
{
	switch (option) {
	case EXCEPTION_UNHANDLED:
		return PED_EXCEPTION_UNHANDLED;
	case EXCEPTION_FIX:
		return PED_EXCEPTION_FIX;
	case EXCEPTION_YES:
		return PED_EXCEPTION_YES;
	case EXCEPTION_NO:
		return PED_EXCEPTION_NO;
	case EXCEPTION_OK:
		return PED_EXCEPTION_OK;
	case EXCEPTION_RETRY:
		return PED_EXCEPTION_RETRY;
	case EXCEPTION_IGNORE:
		return PED_EXCEPTION_IGNORE;
	case EXCEPTION_CANCEL:
		return PED_EXCEPTION_CANCEL;

	default:
		return PED_EXCEPTION_UNHANDLED;
	}
}

static PedExceptionType
extype_libreiserfs_to_parted(reiserfs_exception_type_t type)
{
	switch (type) {
	case EXCEPTION_INFORMATION:
		return PED_EXCEPTION_INFORMATION;
	case EXCEPTION_WARNING:
		return PED_EXCEPTION_WARNING;
	case EXCEPTION_ERROR:
		return PED_EXCEPTION_ERROR;
	case EXCEPTION_FATAL:
		return PED_EXCEPTION_FATAL;
	case EXCEPTION_BUG:
		return PED_EXCEPTION_BUG;
	case EXCEPTION_NO_FEATURE:
		return PED_EXCEPTION_NO_FEATURE;

	default:
		return PED_EXCEPTION_NO_FEATURE;
	}
}

static int exception_handler(reiserfs_exception_t *exception)
{
	int ex_type = libreiserfs_exception_type(exception);
	int ex_option = libreiserfs_exception_option(exception);
	char *ex_message = libreiserfs_exception_message(exception);

	return ped_exception_throw (extype_libreiserfs_to_parted (ex_type),
				    exopt_libreiserfs_to_parted (ex_option),
				    ex_message);
}
#endif /* REISER_FULL_SUPPORT */

static PedGeometry *reiserfs_probe(PedGeometry *geom)
{
	int i;
	reiserfs_super_block_t sb;

	PED_ASSERT(geom != NULL, return NULL);

	for (i = 0; reiserfs_super_offset[i] != -1; i++) {
		if (reiserfs_super_offset[i] >= geom->length)
			continue;
		if (!ped_geometry_read (geom, &sb, reiserfs_super_offset[i], 1))
			continue;

		if (strncmp(REISERFS_SIGNATURE, sb.s_magic,
		            strlen(REISERFS_SIGNATURE)) == 0
		    || strncmp(REISER2FS_SIGNATURE, sb.s_magic,
			       strlen(REISER2FS_SIGNATURE)) == 0
		    || strncmp(REISER3FS_SIGNATURE, sb.s_magic,
			       strlen(REISER3FS_SIGNATURE)) == 0) {
			PedSector block_size;
			PedSector block_count;

			block_size = PED_LE16_TO_CPU(sb.s_blocksize)
					/ PED_SECTOR_SIZE_DEFAULT;
			block_count = PED_LE32_TO_CPU(sb.s_block_count);

			return ped_geometry_new(geom->dev, geom->start,
						block_size * block_count);
		}
	}
	return NULL;
}

#ifndef DISCOVER_ONLY
static int reiserfs_clobber(PedGeometry *geom)
{
	int i;
	char buf[512];

	PED_ASSERT(geom != NULL, return 0);

	memset(buf, 0, 512);
	for (i = 0; reiserfs_super_offset[i] != -1; i++) {
		if (reiserfs_super_offset[i] >= geom->length)
			continue;
		if (!ped_geometry_write
		    (geom, buf, reiserfs_super_offset[i], 1))
			return 0;
	}
	return 1;
}
#endif /* !DISCOVER_ONLY */

#ifdef REISER_FULL_SUPPORT

static PedFileSystem *reiserfs_open(PedGeometry *geom)
{
	PedFileSystem *fs;
	PedGeometry *fs_geom;
	dal_t *dal;
	reiserfs_fs_t *fs_info;

	PED_ASSERT(geom != NULL, return NULL);

	if (!(fs_geom = ped_geometry_duplicate(geom)))
		goto error;

	if (! (dal = geom_dal_create(fs_geom, DEFAULT_BLOCK_SIZE, O_RDONLY)))
		goto error_fs_geom_free;

	/*
	   We are passing NULL as DAL for journal. Therefore we let libreiserfs know, 
	   that journal not available and parted will be working fine for reiserfs 
	   with relocated journal too.
	 */
	if (!(fs = (PedFileSystem *) ped_malloc(sizeof(PedFileSystem))))
		goto error_free_dal;

	if (!(fs_info = reiserfs_fs_open(dal, NULL)))
		goto error_free_fs;

	fs->type = reiserfs_type;
	fs->geom = fs_geom;
	fs->type_specific = (void *) fs_info;

	return fs;

error_free_fs:
	ped_free(fs);
error_free_dal:
	geom_dal_free(dal);
error_fs_geom_free:
	ped_geometry_destroy(fs_geom);
error:
	return NULL;
}

static PedFileSystem *reiserfs_create(PedGeometry *geom, PedTimer *timer)
{
	dal_t *dal;
	uuid_t uuid;
	PedFileSystem *fs;
	PedGeometry *fs_geom;
	reiserfs_fs_t *fs_info;
	reiserfs_gauge_t *gauge = NULL;

	PED_ASSERT(geom != NULL, return NULL);

	fs_geom = ped_geometry_duplicate(geom);

	if (!(dal = geom_dal_create(fs_geom, DEFAULT_BLOCK_SIZE, O_RDWR)))
		goto error_fs_geom_free;

	memset(uuid, 0, sizeof(uuid));
	uuid_generate(uuid);

	ped_timer_reset(timer);
	ped_timer_set_state_name(timer, _("creating"));

	if (libreiserfs_gauge_create && libreiserfs_gauge_free) {
		if (! (gauge =
		     libreiserfs_gauge_create(NULL, gauge_handler, timer)))
			goto error_free_dal;
	}

	if (!(fs_info = reiserfs_fs_create(dal, dal, 0, JOURNAL_MAX_TRANS,
					   DEFAULT_JOURNAL_SIZE,
					   DEFAULT_BLOCK_SIZE,
					   FS_FORMAT_3_6, R5_HASH, NULL,
					   (char *) uuid, dal_len(dal),
					   gauge)))
		goto error_free_gauge;

	ped_timer_update(timer, 1.0);

	if (gauge)
		libreiserfs_gauge_free(gauge);

	if (!(fs = (PedFileSystem *) ped_malloc(sizeof(PedFileSystem))))
		goto error_free_fs_info;

	fs->type = reiserfs_type;
	fs->geom = fs_geom;
	fs->type_specific = (void *) fs_info;

	return fs;

error_free_fs_info:
	ped_free(fs_info);
error_free_gauge:
	if (gauge)
		libreiserfs_gauge_free(gauge);
error_free_dal:
	geom_dal_free(dal);
error_fs_geom_free:
	ped_geometry_destroy(fs_geom);
	return NULL;
}

static int reiserfs_close(PedFileSystem *fs)
{
	dal_t *dal;

	PED_ASSERT(fs != NULL, return 0);

	dal = reiserfs_fs_host_dal(fs->type_specific);
	reiserfs_fs_close(fs->type_specific);

	geom_dal_free(dal);
	ped_geometry_sync(fs->geom);

	ped_free(fs);
	return 1;
}

static PedConstraint *reiserfs_get_create_constraint(const PedDevice *dev)
{
	PedGeometry full_dev;
	PedSector min_blks = (SUPER_OFFSET_IN_BYTES / DEFAULT_BLOCK_SIZE)
			     + 2 + DEFAULT_JOURNAL_SIZE + 1 + 100 + 1;

	if (!ped_geometry_init(&full_dev, dev, 0, dev->length - 1))
		return NULL;

	return ped_constraint_new(ped_alignment_any, ped_alignment_any,
				  &full_dev, &full_dev,
				  min_blks * (DEFAULT_BLOCK_SIZE / 512),
				  dev->length);
}

static int reiserfs_check(PedFileSystem *fs, PedTimer *timer)
{
	reiserfs_fs_t *fs_info;
#ifdef HAVE_REISERFS_FS_CHECK
	reiserfs_gauge_t *gauge = NULL;
#endif

	PED_ASSERT(fs != NULL, return 0);

	fs_info = fs->type_specific;

	if (!reiserfs_fs_is_consistent(fs_info)) {
		ped_exception_throw(PED_EXCEPTION_ERROR,
				    PED_EXCEPTION_CANCEL,
				    _("The file system is in an invalid "
				      "state.  Perhaps it is mounted?"));
		return 0;
	}

	if (!reiserfs_fs_is_resizeable(fs_info))
		ped_exception_throw(PED_EXCEPTION_WARNING,
				    PED_EXCEPTION_IGNORE,
				    _("The file system is in old "
				      "(unresizeable) format."));

	if (!reiserfs_fs_bitmap_check(fs_info)) {
		ped_exception_throw(PED_EXCEPTION_ERROR,
				    PED_EXCEPTION_CANCEL,
				    _("Invalid free blocks count.  Run "
				      "reiserfsck --check first."));
		return 0;
	}

#ifdef HAVE_REISERFS_FS_CHECK
	ped_timer_reset(timer);
	
	if (libreiserfs_gauge_create && libreiserfs_gauge_free) {
		if (!
		    (gauge =
		     libreiserfs_gauge_create(NULL, gauge_handler, timer)))
			return 0;
	}
		
	ped_timer_set_state_name(timer, _("checking"));
	ped_timer_update(timer, 0.0);

	if (!reiserfs_fs_check(fs_info, gauge)) {
		ped_exception_throw(PED_EXCEPTION_ERROR,
				    PED_EXCEPTION_CANCEL,
				    _("Reiserfs tree seems to be corrupted.  "
				      "Run reiserfsck --check first."));
		return 0;
	}
	
	ped_timer_update(timer, 1.0);

	if (gauge)
		libreiserfs_gauge_free(gauge);
#endif
	
	ped_exception_throw(PED_EXCEPTION_INFORMATION, PED_EXCEPTION_OK,
			    _("The reiserfs file system passed a basic check.  "
			      "For a more comprehensive check, run "
			      "reiserfsck --check."));

	return 1;
}

static int reiserfs_resize(PedFileSystem *fs, PedGeometry *geom,
			   PedTimer *timer)
{
	dal_t *dal;
	blk_t fs_len;
	PedSector old_length;
	reiserfs_fs_t *fs_info;
	reiserfs_gauge_t *gauge = NULL;

	PED_ASSERT(fs != NULL, return 0);

	old_length = fs->geom->length;

	PED_ASSERT (fs->geom->dev == geom->dev, return 0);

	if (fs->geom->start != geom->start) {
		ped_exception_throw(PED_EXCEPTION_ERROR,
				    PED_EXCEPTION_CANCEL,
				    _("Sorry, can't move the start of "
				      "reiserfs partitions yet."));
		return 0;
	}

	fs_info = fs->type_specific;

	fs_len = (blk_t) (geom->length / (reiserfs_fs_block_size(fs_info) /
					  PED_SECTOR_SIZE_DEFAULT));

	dal = reiserfs_fs_host_dal(fs_info);

	if (dal_flags(dal) && O_RDONLY) {
		if (!geom_dal_reopen(dal, O_RDWR)) {
			ped_exception_throw(PED_EXCEPTION_ERROR,
					    PED_EXCEPTION_CANCEL,
					    _("Couldn't reopen device "
					      "abstraction layer for "
					      "read/write."));
			return 0;
		}
	}

	ped_timer_reset(timer);

	if (libreiserfs_gauge_create && libreiserfs_gauge_free) {
		if (!
		    (gauge =
		     libreiserfs_gauge_create(NULL, gauge_handler, timer)))
			return 0;
	}

	if (old_length > geom->length) {

		ped_timer_set_state_name(timer, _("shrinking"));
		ped_timer_update(timer, 0.0);

		if (!reiserfs_fs_resize(fs_info, fs_len, gauge))
			goto error_free_gauge;

		ped_geometry_set_end (fs->geom, geom->end);
		dal_realize(dal);
	} else {
		ped_geometry_set_end (fs->geom, geom->end);
		dal_realize(dal);

		ped_timer_set_state_name(timer, _("expanding"));
		ped_timer_update(timer, 0.0);

		if (!reiserfs_fs_resize(fs_info, fs_len, gauge))
			goto error_free_gauge;
	}

	ped_timer_update(timer, 1.0);

	if (gauge)
		libreiserfs_gauge_free(gauge);

	return 1;

error_free_gauge:
	if (gauge)
		libreiserfs_gauge_free(gauge);
	ped_geometry_set_end (fs->geom, fs->geom->start + old_length - 1);
	return 0;
}

static PedConstraint *reiserfs_get_resize_constraint(const PedFileSystem *
						     fs)
{
	PedDevice *dev;
	PedSector min_size;
	PedGeometry full_disk;
	reiserfs_fs_t *fs_info;
	PedAlignment start_align;
	PedGeometry start_sector;

	PED_ASSERT(fs != NULL, return NULL);

	fs_info = fs->type_specific;
	dev = fs->geom->dev;

	if (!ped_alignment_init(&start_align, fs->geom->start, 0))
		return NULL;
	if (!ped_geometry_init(&full_disk, dev, 0, dev->length - 1))
		return NULL;
	if (!ped_geometry_init(&start_sector, dev, fs->geom->start, 1))
		return NULL;

	/* 
	   Minsize for reiserfs is area occupied by data blocks and 
	   metadata blocks minus free space blocks and minus bitmap 
	   blocks which describes free space blocks.
	 */
	min_size = reiserfs_fs_min_size(fs_info) *
	    (reiserfs_fs_block_size(fs_info) / PED_SECTOR_SIZE_DEFAULT);

	return ped_constraint_new(&start_align, ped_alignment_any,
				  &start_sector, &full_disk, min_size,
				  dev->length);
}

static PedFileSystem *reiserfs_copy(const PedFileSystem *fs,
				    PedGeometry *geom, PedTimer *timer)
{
	dal_t *dal;
	PedGeometry *fs_geom;
	PedFileSystem *new_fs;
	blk_t fs_len, min_needed_blk;

	reiserfs_fs_t *dest_fs, *src_fs;
	reiserfs_gauge_t *gauge = NULL;

	fs_geom = ped_geometry_duplicate(geom);

	if (!(dal = geom_dal_create(fs_geom, DEFAULT_BLOCK_SIZE, O_RDWR))) {
		ped_exception_throw(PED_EXCEPTION_ERROR,
				    PED_EXCEPTION_CANCEL,
				    _("Couldn't create reiserfs device "
				      "abstraction handler."));
		goto error_free_fs_geom;
	}

	src_fs = fs->type_specific;

	fs_len =
	    (geom->length / (reiserfs_fs_block_size(src_fs) / PED_SECTOR_SIZE_DEFAULT));
	min_needed_blk = reiserfs_fs_bitmap_used(src_fs);

	if (fs_len <= min_needed_blk) {
		ped_exception_throw(PED_EXCEPTION_ERROR,
				    PED_EXCEPTION_CANCEL,
				    _("Device is too small for %lu blocks."),
				    min_needed_blk);
		goto error_free_dal;
	}

	if (! (new_fs = (PedFileSystem *) ped_malloc(sizeof(PedFileSystem))))
		goto error_free_dal;

	ped_timer_reset(timer);
	ped_timer_set_state_name(timer, _("copying"));
	ped_timer_update(timer, 0.0);

	if (libreiserfs_gauge_create && libreiserfs_gauge_free) {
		if (! (gauge =
		     libreiserfs_gauge_create(NULL, gauge_handler, timer)))
			goto error_free_new_fs;
	}

	if (!(dest_fs = reiserfs_fs_copy(src_fs, dal, gauge)))
		goto error_free_gauge;

	ped_timer_update(timer, 1.0);

	if (gauge)
		libreiserfs_gauge_free(gauge);

	new_fs->type = reiserfs_type;
	new_fs->geom = fs_geom;
	new_fs->type_specific = (void *) dest_fs;

	return new_fs;

error_free_gauge:
	if (gauge)
		libreiserfs_gauge_free(gauge);
error_free_new_fs:
	ped_free(new_fs);
error_free_dal:
	geom_dal_free(dal);
error_free_fs_geom:
	ped_geometry_destroy(fs_geom);
	return NULL;
}

static PedConstraint *reiserfs_get_copy_constraint(const PedFileSystem *fs,
						   const PedDevice *dev)
{
	PedGeometry full_dev;

	PED_ASSERT(fs != NULL, return NULL);
	PED_ASSERT(dev != NULL, return NULL);

	if (!ped_geometry_init(&full_dev, dev, 0, dev->length - 1))
		return NULL;

	return ped_constraint_new(ped_alignment_any, ped_alignment_any,
				  &full_dev, &full_dev,
				  reiserfs_fs_bitmap_used(fs->type_specific),
				  dev->length);
}

#endif /* !REISER_FULL_SUPPORT */

#ifdef DYNAMIC_LOADING

#define INIT_SYM(SYM)	SYM = getsym (libreiserfs_handle, #SYM)

static void *getsym(void *handle, const char *symbol)
{
	void *entry;
	char *error;

	entry = dlsym(handle, symbol);
	if ((error = dlerror()) != NULL) {
		ped_exception_throw(PED_EXCEPTION_WARNING,
				    PED_EXCEPTION_IGNORE,
				    _("Couldn't resolve symbol %s.  "
				      "Error: %s."),
				    symbol, error);
		return NULL;
	}

	return entry;
}

static int reiserfs_ops_interface_version_check(void)
{
	int min_interface_version, max_interface_version;
	int (*libreiserfs_get_max_interface_version) (void);
	int (*libreiserfs_get_min_interface_version) (void);

	INIT_SYM(libreiserfs_get_max_interface_version);
	INIT_SYM(libreiserfs_get_min_interface_version);

	if (!libreiserfs_get_min_interface_version ||
	    !libreiserfs_get_max_interface_version) {
		ped_exception_throw(
			PED_EXCEPTION_WARNING, PED_EXCEPTION_CANCEL,
			_("GNU Parted found an invalid libreiserfs library."));
		return 0;
	}

	min_interface_version = libreiserfs_get_min_interface_version();
	max_interface_version = libreiserfs_get_max_interface_version();

	if (REISERFS_API_VERSION < min_interface_version ||
	    REISERFS_API_VERSION > max_interface_version) {
		ped_exception_throw(
			PED_EXCEPTION_WARNING, PED_EXCEPTION_CANCEL,
			_("GNU Parted has detected libreiserfs interface "
			  "version mismatch.  Found %d-%d, required %d. "
			  "ReiserFS support will be disabled."),
			min_interface_version,
			max_interface_version,
			REISERFS_API_VERSION);
		return 0;
	}

	return 1;
}

static int reiserfs_ops_init(void)
{
	if (!(libreiserfs_handle = dlopen("libreiserfs.so", RTLD_NOW)))
		goto error;

	if (!reiserfs_ops_interface_version_check())
		goto error_free_libreiserfs_handle;

	if (!(libdal_handle = dlopen("libdal.so", RTLD_NOW)))
		goto error_free_libreiserfs_handle;

	INIT_SYM(reiserfs_fs_probe);
	INIT_SYM(libreiserfs_exception_type);

	INIT_SYM(libreiserfs_exception_option);
	INIT_SYM(libreiserfs_exception_message);
	INIT_SYM(libreiserfs_exception_set_handler);

	INIT_SYM(reiserfs_fs_clobber);
	INIT_SYM(reiserfs_fs_open);
	INIT_SYM(reiserfs_fs_create);
	INIT_SYM(reiserfs_fs_resize);
	INIT_SYM(reiserfs_fs_copy);

	INIT_SYM(reiserfs_fs_is_resizeable);
	INIT_SYM(reiserfs_fs_is_consistent);

	INIT_SYM(reiserfs_fs_bitmap_check);
	INIT_SYM(reiserfs_fs_bitmap_used);

	INIT_SYM(reiserfs_fs_min_size);
	INIT_SYM(reiserfs_fs_block_size);

	INIT_SYM(reiserfs_fs_host_dal);
	INIT_SYM(reiserfs_fs_close);

	INIT_SYM(libreiserfs_gauge_create);
	INIT_SYM(libreiserfs_gauge_free);

	INIT_SYM(dal_realize);
	INIT_SYM(dal_flags);

	INIT_SYM(dal_block_size);
	INIT_SYM(dal_len);

	return 1;

error_free_libreiserfs_handle:
	dlclose(libreiserfs_handle);
	libreiserfs_handle = NULL;
error:
	return 0;
}

static void reiserfs_ops_done()
{
	if (libdal_handle)
		dlclose(libdal_handle);
	if (libreiserfs_handle)
		dlclose(libreiserfs_handle);
}
#endif /* DYNAMIC_LOADING */

#define REISER_BLOCK_SIZES ((int[]){512, 1024, 2048, 4096, 8192, 0})

#ifdef REISER_FULL_SUPPORT
static PedFileSystemOps reiserfs_full_ops = {
	.probe =		reiserfs_probe,
	.clobber =	reiserfs_clobber,
	.open =		reiserfs_open,
	.create =		reiserfs_create,
	.close =		reiserfs_close,
	.check =		reiserfs_check,
	.copy =		reiserfs_copy,
	.resize =		reiserfs_resize,
	.get_create_constraint =	reiserfs_get_create_constraint,
	.get_resize_constraint =	reiserfs_get_resize_constraint,
	.get_copy_constraint =	reiserfs_get_copy_constraint
};

static PedFileSystemType reiserfs_full_type = {
	.next =	NULL,
	.ops =	&reiserfs_full_ops,
	.name =	"reiserfs",
        .block_sizes =    REISER_BLOCK_SIZES
};
#endif /* REISER_FULL_SUPPORT */

static PedFileSystemOps reiserfs_simple_ops = {
	.probe =		reiserfs_probe,
#ifdef DISCOVER_ONLY
	.clobber =	NULL,
#else
	.clobber =	reiserfs_clobber,
#endif
	.open =		NULL,
	.create =		NULL,
	.close =		NULL,
	.check =		NULL,
	.copy =		NULL,
	.resize =		NULL,
	.get_create_constraint =	NULL,
	.get_resize_constraint =	NULL,
	.get_copy_constraint =	NULL
};

static PedFileSystemType reiserfs_simple_type = {
	.next =	        NULL,
	.ops =	        &reiserfs_simple_ops,
	.name =	        "reiserfs",
        .block_sizes =    REISER_BLOCK_SIZES
};

void ped_file_system_reiserfs_init()
{
#ifdef DYNAMIC_LOADING
	libreiserfs_present = reiserfs_ops_init();
	if (libreiserfs_present) {
		reiserfs_type = &reiserfs_full_type;
		libreiserfs_exception_set_handler(exception_handler);
	} else {
		reiserfs_type = &reiserfs_simple_type;
	}
#else	/* !DYNAMIC_LOADING */
#ifdef REISER_FULL_SUPPORT
	libreiserfs_exception_set_handler(exception_handler);
	reiserfs_type = &reiserfs_full_type;
#else
	reiserfs_type = &reiserfs_simple_type;
#endif
#endif	/* !DYNAMIC_LOADING */
	ped_file_system_type_register(reiserfs_type);
}

void ped_file_system_reiserfs_done()
{
	ped_file_system_type_unregister(reiserfs_type);
#ifdef DYNAMIC_LOADING
	reiserfs_ops_done();
#endif /* DYNAMIC_LOADING */
}
