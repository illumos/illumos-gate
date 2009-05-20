/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 1999, 2000, 2001, 2007 Free Software Foundation, Inc.

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

/** \file filesys.c */

/**
 * \addtogroup PedFileSystem
 *
 * \note File systems exist on a PedGeometry - NOT a PedPartition.
 *
 * @{
 */

#include <config.h>

#include <parted/parted.h>
#include <parted/debug.h>

#if ENABLE_NLS
#  include <libintl.h>
#  define _(String) dgettext (PACKAGE, String)
#else
#  define _(String) (String)
#endif /* ENABLE_NLS */

#define BUFFER_SIZE	4096		/* in sectors */

static PedFileSystemType*	fs_types = NULL;

void
ped_file_system_type_register (PedFileSystemType* fs_type)
{
	PED_ASSERT (fs_type != NULL, return);
	PED_ASSERT (fs_type->ops != NULL, return);
	PED_ASSERT (fs_type->name != NULL, return);
	
	/* pretend that "next" isn't part of the struct :-) */
	((struct _PedFileSystemType*) fs_type)->next = fs_types;
	fs_types = (struct _PedFileSystemType*) fs_type;
}

void
ped_file_system_type_unregister (PedFileSystemType* fs_type)
{
	PedFileSystemType*	walk;
	PedFileSystemType*	last = NULL;

	PED_ASSERT (fs_types != NULL, return);
	PED_ASSERT (fs_type != NULL, return);

	for (walk = fs_types; walk && walk != fs_type;
                last = walk, walk = walk->next);

	PED_ASSERT (walk != NULL, return);
	if (last)
		((struct _PedFileSystemType*) last)->next = fs_type->next;
	else
		fs_types = fs_type->next;	
}

/**
 * Get a PedFileSystemType by its @p name.
 *
 * @return @c NULL if none found.
 */
PedFileSystemType*
ped_file_system_type_get (const char* name)
{
	PedFileSystemType*	walk;

	PED_ASSERT (name != NULL, return NULL);

	for (walk = fs_types; walk != NULL; walk = walk->next) {
		if (!strcasecmp (walk->name, name))
			break;
	}
	return walk;
}

/**
 * Get the next PedFileSystemType after @p fs_type.
 *
 * @return @c NULL if @p fs_type is the last item in the list.
 */
PedFileSystemType*
ped_file_system_type_get_next (const PedFileSystemType* fs_type)
{
	if (fs_type)
		return fs_type->next;
	else
		return fs_types;
}

/**
 * Attempt to find a file system and return the region it occupies.
 *
 * @param fs_type The file system type to probe for.
 * @param geom The region to be searched.
 *
 * @return @p NULL if @p fs_type file system wasn't detected
 */
PedGeometry*
ped_file_system_probe_specific (
		const PedFileSystemType* fs_type, PedGeometry* geom)
{
	PedGeometry*	result;

	PED_ASSERT (fs_type != NULL, return NULL);
	PED_ASSERT (fs_type->ops->probe != NULL, return NULL);
	PED_ASSERT (geom != NULL, return NULL);

	if (!ped_device_open (geom->dev))
		return 0;
	result = fs_type->ops->probe (geom);
	ped_device_close (geom->dev);
	return result;
}

static int
_test_open (PedFileSystemType* fs_type, PedGeometry* geom)
{
	PedFileSystem*		fs;

	ped_exception_fetch_all ();
	fs = fs_type->ops->open (geom);
	if (fs)
		fs_type->ops->close (fs);
	else
		ped_exception_catch ();
	ped_exception_leave_all ();
	return fs != NULL;
}

static PedFileSystemType*
_probe_with_open (PedGeometry* geom, int detected_count,
		  PedFileSystemType* detected[])
{
	int			i;
	PedFileSystemType*	open_detected = NULL;

	ped_device_open (geom->dev);

	/* If one and only one file system that Parted is able to open
	 * can be successfully opened on this geometry, return it.
	 * If more than one can be, return NULL.
	 */
	for (i=0; i<detected_count; i++) {
		if (!detected[i]->ops->open || !_test_open (detected [i], geom))
			continue;

		if (open_detected) {
			ped_device_close (geom->dev);
			return NULL;
		} else {
			open_detected = detected [i];
		}
	}

	/* If no file system has been successfully opened, and
	 * if Parted has detected at most one unopenable file system,
	 * return it.
	 */
	if (!open_detected)
	for (i=0; i<detected_count; i++) {
		if (detected[i]->ops->open)
			continue;
		if (open_detected) {
			ped_device_close (geom->dev);
			return NULL;
		} else {
			open_detected = detected [i];
		}
	}	

	ped_device_close (geom->dev);
	return open_detected;
}

static int
_geometry_error (const PedGeometry* a, const PedGeometry* b)
{
	PedSector	start_delta = a->start - b->start;
	PedSector	end_delta = a->end - b->end;

	return abs (start_delta) + abs (end_delta);
}

static PedFileSystemType*
_best_match (const PedGeometry* geom, PedFileSystemType* detected [],
	     const int detected_error [], int detected_count)
{
	int		best_match = 0;
	int		i;
	PedSector	min_error;

	min_error = PED_MAX (4096, geom->length / 100);

	for (i = 1; i < detected_count; i++) {
		if (detected_error [i] < detected_error [best_match])
			best_match = i;
	}

	/* make sure the best match is significantly better than all the
	 * other matches
	 */
	for (i = 0; i < detected_count; i++) {
		if (i == best_match)
			continue;

		if (abs (detected_error [best_match] - detected_error [i])
				< min_error)
			return NULL;
	}

	return detected [best_match];
}


/**
 * Attempt to detect a file system in region \p geom. 
 * This function tries to be clever at dealing with ambiguous
 * situations, such as when one file system was not completely erased before a
 * new file system was created on top of it.
 *
 * \return a new PedFileSystem on success, \c NULL on failure
 */
PedFileSystemType*
ped_file_system_probe (PedGeometry* geom)
{
	PedFileSystemType*	detected[32];
	int			detected_error[32];
	int			detected_count = 0;
	PedFileSystemType*	walk = NULL;

	PED_ASSERT (geom != NULL, return NULL);

	if (!ped_device_open (geom->dev))
		return NULL;

	ped_exception_fetch_all ();
	while ( (walk = ped_file_system_type_get_next (walk)) ) {
		PedGeometry*	probed;

		probed = ped_file_system_probe_specific (walk, geom);
		if (probed) {
			detected [detected_count] = walk;
			detected_error [detected_count]
				= _geometry_error (geom, probed);
			detected_count++;
			ped_geometry_destroy (probed);
		} else {
			ped_exception_catch ();
		}
	}
	ped_exception_leave_all ();

	ped_device_close (geom->dev);

	if (!detected_count)
		return NULL;
	walk = _best_match (geom, detected, detected_error, detected_count);
	if (walk)
		return walk;
	return _probe_with_open (geom, detected_count, detected);
}

/**
 * This function erases all file system signatures that indicate that a
 * file system occupies a given region described by \p geom.
 * After this operation ped_file_system_probe() won't detect any file system.
 *
 * \note ped_file_system_create() calls this before creating a new file system.
 * 
 * \return \c 1 on success, \c 0 on failure
 */
int
ped_file_system_clobber (PedGeometry* geom)
{
	PedFileSystemType*	fs_type = NULL;

	PED_ASSERT (geom != NULL, return 0);

	if (!ped_device_open (geom->dev))
		goto error;

	ped_exception_fetch_all ();
	while ((fs_type = ped_file_system_type_get_next (fs_type))) {
		PedGeometry*	probed;

		if (!fs_type->ops->clobber)
			continue;

		probed = ped_file_system_probe_specific (fs_type, geom);
		if (!probed) {
			ped_exception_catch ();
			continue;
		}
		ped_geometry_destroy (probed);

		if (fs_type->ops->clobber && !fs_type->ops->clobber (geom)) {
			ped_exception_leave_all ();
			goto error_close_dev;
		}
	}
	ped_device_close (geom->dev);
	ped_exception_leave_all ();
	return 1;

error_close_dev:
	ped_device_close (geom->dev);
error:
	return 0;
}

/* This function erases all signatures that indicate the presence of
 * a file system in a particular region, without erasing any data
 * contained inside the "exclude" region.
 */
static int
ped_file_system_clobber_exclude (PedGeometry* geom,
				 const PedGeometry* exclude)
{
	PedGeometry*    clobber_geom;
	int             status;

	if (ped_geometry_test_sector_inside (exclude, geom->start))
		return 1;

	clobber_geom = ped_geometry_duplicate (geom);
	if (ped_geometry_test_overlap (clobber_geom, exclude))
		ped_geometry_set_end (clobber_geom, exclude->start - 1);

	status = ped_file_system_clobber (clobber_geom);
	ped_geometry_destroy (clobber_geom);
	return status;
}

/**
 * This function opens the file system stored on \p geom, if it
 * can find one.
 * It is often called in the following manner:
 * \code
 * 	fs = ped_file_system_open (&part.geom)
 * \endcode
 *
 * \throws PED_EXCEPTION_ERROR if file system could not be detected
 * \throws PED_EXCEPTION_ERROR if the file system is bigger than its volume
 * \throws PED_EXCEPTION_NO_FEATURE if opening of a file system stored on 
 * 	\p geom is not implemented
 *
 * \return a PedFileSystem on success, \c NULL on failure.
 */
PedFileSystem*
ped_file_system_open (PedGeometry* geom)
{
	PedFileSystemType*	type;
	PedFileSystem*		fs;
	PedGeometry*		probed_geom;

	PED_ASSERT (geom != NULL, return NULL);

	if (!ped_device_open (geom->dev))
		goto error;

	type = ped_file_system_probe (geom);
	if (!type) {
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
				     _("Could not detect file system."));
		goto error_close_dev;
	}

	probed_geom = ped_file_system_probe_specific (type, geom);
	if (!probed_geom)
		goto error_close_dev;
	if (!ped_geometry_test_inside (geom, probed_geom)) {
		if (ped_exception_throw (
			PED_EXCEPTION_ERROR,
			PED_EXCEPTION_IGNORE_CANCEL,
			_("The file system is bigger than its volume!"))
				!= PED_EXCEPTION_IGNORE)
			goto error_destroy_probed_geom;
	}

	if (!type->ops->open) {
		ped_exception_throw (PED_EXCEPTION_NO_FEATURE,
				     PED_EXCEPTION_CANCEL,
				     _("Support for opening %s file systems "
				       "is not implemented yet."),
				     type->name);
		goto error_destroy_probed_geom;
	}

	fs = type->ops->open (probed_geom);
	if (!fs)
		goto error_destroy_probed_geom;
	ped_geometry_destroy (probed_geom);
	return fs;

error_destroy_probed_geom:
	ped_geometry_destroy (probed_geom);
error_close_dev:
	ped_device_close (geom->dev);
error:
	return 0;
}

/**
 * This function initializes a new file system of type \p type on 
 * a region described by \p geom, writing out appropriate metadata and 
 * signatures.  If \p timer is non-NULL, it is used as the progress meter.
 *
 * \throws PED_EXCEPTION_NO_FEATURE if creating file system type \p type 
 * 	is not implemented yet
 *
 * \return a PedFileSystem on success, \c NULL on failure
 */
PedFileSystem*
ped_file_system_create (PedGeometry* geom, const PedFileSystemType* type,
			PedTimer* timer)
{
	PedFileSystem*	fs;

	PED_ASSERT (geom != NULL, return NULL);
	PED_ASSERT (type != NULL, return NULL);

	if (!type->ops->create) {
		ped_exception_throw (PED_EXCEPTION_NO_FEATURE,
				     PED_EXCEPTION_CANCEL,
				     _("Support for creating %s file systems "
				       "is not implemented yet."),
				     type->name);
		goto error;
	}

	if (!ped_device_open (geom->dev))
		goto error;

	if (!ped_file_system_clobber (geom))
		goto error_close_dev;
	fs = type->ops->create (geom, timer);
	if (!fs)
		goto error_close_dev;
	return fs;

error_close_dev:
	ped_device_close (geom->dev);
error:
	return 0;
}

/**
 * Close file system \p fs.
 *
 * \return \c 1 on success, \c 0 on failure
 */
int
ped_file_system_close (PedFileSystem* fs)
{
	PedDevice*	dev = fs->geom->dev;

	PED_ASSERT (fs != NULL, goto error_close_dev);

	if (!fs->type->ops->close (fs))
		goto error_close_dev;
	ped_device_close (dev);
	return 1;

error_close_dev:
	ped_device_close (dev);
	return 0;
}

/**
 * Check \p fs file system for errors.
 *
 * \throws PED_EXCEPTION_NO_FEATURE if checking file system \p fs is 
 * 	not implemented yet
 *
 * \return \c 0 on failure (i.e. unfixed errors)
 */
int
ped_file_system_check (PedFileSystem* fs, PedTimer* timer)
{
	PED_ASSERT (fs != NULL, return 0);

	if (!fs->type->ops->check) {
		ped_exception_throw (PED_EXCEPTION_NO_FEATURE,
				     PED_EXCEPTION_CANCEL,
				     _("Support for checking %s file systems "
				       "is not implemented yet."),
				     fs->type->name);
		return 0;
	}
	return fs->type->ops->check (fs, timer);
}

static int
_raw_copy (const PedGeometry* src, PedGeometry* dest, PedTimer* timer)
{
	char*		buf;
	PedSector	pos;

	PED_ASSERT (src != NULL, goto error);
	PED_ASSERT (dest != NULL, goto error);
	PED_ASSERT (src->length <= dest->length, goto error);

	buf = ped_malloc (BUFFER_SIZE * 512);		/* FIXME */
	if (!buf)
		goto error;

	if (!ped_device_open (src->dev))
		goto error_free_buf;
	if (!ped_device_open (dest->dev))
		goto error_close_src;

	for (pos = 0; pos + BUFFER_SIZE < src->length; pos += BUFFER_SIZE) {
		ped_timer_update (timer, 1.0 * pos / src->length);
		if (!ped_geometry_read (src, buf, pos, BUFFER_SIZE))
			goto error_close_dest;
		if (!ped_geometry_write (dest, buf, pos, BUFFER_SIZE))
			goto error_close_dest;
	}
	if (pos < src->length) {
		ped_timer_update (timer, 1.0 * pos / src->length);
		if (!ped_geometry_read (src, buf, pos, src->length - pos))
			goto error_close_dest;
		if (!ped_geometry_write (dest, buf, pos, src->length - pos))
			goto error_close_dest;
	}
	ped_timer_update (timer, 1.0);

	ped_device_close (src->dev);
	ped_device_close (dest->dev);
	ped_free (buf);
	return 1;

error_close_dest:
	ped_device_close (dest->dev);
error_close_src:
	ped_device_close (src->dev);
error_free_buf:
	ped_free (buf);
error:
	return 0;
}

static PedFileSystem*
_raw_copy_and_resize (const PedFileSystem* fs, PedGeometry* geom,
		      PedTimer* timer)
{
	PedFileSystem*	new_fs;
	PedTimer*	sub_timer = NULL;

	ped_timer_reset (timer);
	ped_timer_set_state_name (timer, _("raw block copying"));

	sub_timer = ped_timer_new_nested (timer, 0.95);
	if (!_raw_copy (fs->geom, geom, sub_timer))
		goto error;
	ped_timer_destroy_nested (sub_timer);

	new_fs = ped_file_system_open (geom);
	if (!new_fs)
		goto error;

	ped_timer_set_state_name (timer, _("growing file system"));

	sub_timer = ped_timer_new_nested (timer, 0.05);
	if (!ped_file_system_resize (new_fs, geom, sub_timer))
		goto error_close_new_fs;
	ped_timer_destroy_nested (sub_timer);
	return new_fs;

error_close_new_fs:
	ped_file_system_close (new_fs);
error:
	ped_timer_destroy_nested (sub_timer);
	return NULL;
}

/**
 * Create a new file system (of the same type) on \p geom, and
 * copy the contents of \p fs into the new filesystem.  
 * If \p timer is non-NULL, it is used as the progress meter.
 *
 * \throws PED_EXCEPTION_ERROR when trying to copy onto an overlapping partition
 * \throws PED_EXCEPTION_NO_FEATURE if copying of file system \p fs 
 * 	is not implemented yet
 *
 * \return a new PedFileSystem on success, \c NULL on failure
 */
PedFileSystem*
ped_file_system_copy (PedFileSystem* fs, PedGeometry* geom, PedTimer* timer)
{
	PedFileSystem* new_fs;

	PED_ASSERT (fs != NULL, return 0);
	PED_ASSERT (geom != NULL, return 0);

	if (!ped_device_open (geom->dev))
		goto error;

	if (ped_geometry_test_overlap (fs->geom, geom)) {
		ped_exception_throw (
			PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("Can't copy onto an overlapping partition."));
		goto error_close_dev;
	}

	if (!fs->checked && fs->type->ops->check) {
		if (!ped_file_system_check (fs, timer))
			goto error_close_dev;
	}

	if (!ped_file_system_clobber_exclude (geom, fs->geom))
		goto error_close_dev;

	if (!fs->type->ops->copy) {
		if (fs->type->ops->resize) {
			if (fs->geom->length <= geom->length)
				return _raw_copy_and_resize (
						fs, (PedGeometry*) geom,
						timer);
				
			ped_exception_throw (
				PED_EXCEPTION_NO_FEATURE,
				PED_EXCEPTION_CANCEL,
				_("Direct support for copying file systems is "
				  "not yet implemented for %s.  However, "
				  "support for resizing is implemented.  "
				  "Therefore, the file system can be copied if "
				  "the new partition is at least as big as the "
				  "old one.  So, either shrink the partition "
				  "you are trying to copy, or copy to a bigger "
				  "partition."),
				fs->type->name);
			goto error_close_dev;
		} else {
			ped_exception_throw (
				PED_EXCEPTION_NO_FEATURE,
				PED_EXCEPTION_CANCEL,
				_("Support for copying %s file systems is not "
				  "implemented yet."),
				fs->type->name);
			goto error_close_dev;
		}
	}
	new_fs = fs->type->ops->copy (fs, geom, timer);
	if (!new_fs)
		goto error_close_dev;
	return new_fs;

error_close_dev:
	ped_device_close (geom->dev);
error:
	return NULL;;
}

/**
 * Resize \p fs to new geometry \p geom.
 *
 * \p geom should satisfy the ped_file_system_get_resize_constraint().
 * (This isn't asserted, so it's not a bug not to... just it's likely
 * to fail ;)  If \p timer is non-NULL, it is used as the progress meter.
 *
 * \throws PED_EXCEPTION_NO_FEATURE if resizing of file system \p fs 
 * 	is not implemented yet
 * 
 * \return \c 0 on failure 
 */
int
ped_file_system_resize (PedFileSystem* fs, PedGeometry* geom, PedTimer* timer)
{
	PED_ASSERT (fs != NULL, return 0);
	PED_ASSERT (geom != NULL, return 0);

	if (!fs->type->ops->resize) {
		ped_exception_throw (PED_EXCEPTION_NO_FEATURE,
				     PED_EXCEPTION_CANCEL,
				     _("Support for resizing %s file systems "
				       "is not implemented yet."),
				     fs->type->name);
		return 0;
	}
	if (!fs->checked && fs->type->ops->check) {
		if (!ped_file_system_check (fs, timer))
			return 0;
	}
	if (!ped_file_system_clobber_exclude (geom, fs->geom))
		return 0;

	return fs->type->ops->resize (fs, geom, timer);
}

/**
 * This function returns a constraint on the region that all file systems
 * of a particular type \p fs_type created on device \p dev with 
 * ped_file_system_create() must satisfy. For example, FAT16 file systems must
 * be at least 32 megabytes.
 *
 * \return \c NULL on failure
 */
PedConstraint*
ped_file_system_get_create_constraint (const PedFileSystemType* fs_type,
				       const PedDevice* dev)
{
	PED_ASSERT (fs_type != NULL, return NULL);
	PED_ASSERT (dev != NULL, return NULL);

	if (!fs_type->ops->get_create_constraint)
		return NULL;
	return fs_type->ops->get_create_constraint (dev);
}
/**
 * Return a constraint, that represents all of the possible ways the
 * file system \p fs can be resized with ped_file_system_resize().  
 * This takes into account the amount of used space on
 * the filesystem \p fs and the capabilities of the resize algorithm.
 * Hints:
 * -# if constraint->start_align->grain_size == 0, or
 *    constraint->start_geom->length == 1, then the start can not be moved
 * -# constraint->min_size is the minimum size you can resize the partition
 *    to.  You might want to tell the user this ;-).
 *    
 * \return a PedConstraint on success, \c NULL on failure
 */
PedConstraint*
ped_file_system_get_resize_constraint (const PedFileSystem* fs)
{
	PED_ASSERT (fs != NULL, return 0);

	if (!fs->type->ops->get_resize_constraint)
		return NULL;
	return fs->type->ops->get_resize_constraint (fs);
}

/**
 * Get the constraint on copying \p fs with ped_file_system_copy()
 * to somewhere on \p dev.
 *
 * \return a PedConstraint on success, \c NULL on failure
 */ 
PedConstraint*
ped_file_system_get_copy_constraint (const PedFileSystem* fs,
				     const PedDevice* dev)
{
	PedGeometry	full_dev;

	PED_ASSERT (fs != NULL, return NULL);
	PED_ASSERT (dev != NULL, return NULL);

	if (fs->type->ops->get_copy_constraint)
		return fs->type->ops->get_copy_constraint (fs, dev);

	if (fs->type->ops->resize) {
		if (!ped_geometry_init (&full_dev, dev, 0, dev->length - 1))
			return NULL;
		return ped_constraint_new (
				ped_alignment_any, ped_alignment_any,
				&full_dev, &full_dev,
				fs->geom->length, dev->length);
	}

	return NULL;
}

/** @} */
