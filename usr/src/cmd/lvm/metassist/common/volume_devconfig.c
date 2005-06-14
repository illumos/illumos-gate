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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "volume_devconfig.h"

#include <string.h>
#include <ctype.h>
#include <meta.h>
#include "volume_nvpair.h"
#include "volume_error.h"
#include "volume_output.h"
#include "volume_string.h"

/*
 * Methods which manipulate a devconfig_t struct
 */

/*
 * Constructor: Create a devconfig_t struct.  This devconfig_t must be
 * freed with free_devconfig().
 *
 * @param       devconfig
 *              RETURN: a new devconfig_t
 *
 * @param       type
 *              the type of devconfig_t to create
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
new_devconfig(
	devconfig_t **devconfig,
	component_type_t type)
{
	int error;

	*devconfig = (devconfig_t *)calloc(1, sizeof (devconfig_t));
	if (*devconfig == NULL) {
	    volume_set_error(gettext("new_devconfig() calloc() failed\n"));
	    return (-1);
	}

	/* Create attribute list */
	if ((error = nvlist_alloc(&((*devconfig)->attributes),
	    NV_UNIQUE_NAME_TYPE, 0)) != 0) {
	    volume_set_error(gettext("devconfig_t nvlist_alloc() failed\n"));
	    free_devconfig(*devconfig);
	    return (error);
	}

	if ((error = devconfig_set_type(*devconfig, type)) != 0) {
	    free_devconfig(*devconfig);
	    return (error);
	}

	return (0);
}

/*
 * Free memory (recursively) allocated to a devconfig_t struct
 *
 * @param       arg
 *              pointer to the devconfig_t to be freed
 */
void
free_devconfig(
	void *arg)
{
	devconfig_t *devconfig = (devconfig_t *)arg;

	if (devconfig == NULL) {
	    return;
	}

	/* Free the attributes nvlist */
	if (devconfig->attributes != NULL) {
	    nvlist_free(devconfig->attributes);
	}

	/* Free available devices */
	if (devconfig->available != NULL) {
	    free_string_array(devconfig->available);
	}

	/* Free unavailable devices */
	if (devconfig->unavailable != NULL) {
	    free_string_array(devconfig->unavailable);
	}

	/* Free the components */
	if (devconfig->components != NULL) {
	    dlist_free_items(devconfig->components, free_devconfig);
	}

	/* Free the devconfig itself */
	free(devconfig);
}

/*
 * Check the type of the given device.
 *
 * @param       device
 *              the device whose type to check
 *
 * @param       type
 *              the type of the device against which to compare
 *
 * @return      B_TRUE if the device is of the given type, B_FALSE
 *              otherwise
 */
boolean_t
devconfig_isA(
	devconfig_t *device,
	component_type_t type)
{
	component_type_t curtype;

	if (device == NULL) {
	    return (B_FALSE);
	}

	if (devconfig_get_type(device, &curtype) != 0) {
	    return (B_FALSE);
	}

	if (curtype != type) {
	    return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Get the first component of the given type from the given
 * devconfig_t.  Create the component if create is B_TRUE.
 *
 * @return      ENOENT
 *              if the requested component does not exist and its
 *              creation was not requested
 *
 * @return      0
 *              if the requested component exists or was created
 *
 * @return      non-zero
 *              if the requested component did not exist and could not
 *              be created
 */
int
devconfig_get_component(
	devconfig_t *device,
	component_type_t type,
	devconfig_t **component,
	boolean_t create)
{
	dlist_t *list;
	int error = 0;
	char *typestr = devconfig_type_to_str(type);

	oprintf(OUTPUT_DEBUG, gettext("Searching for singleton %s\n"), typestr);

	/* For each component of this device... */
	for (list = devconfig_get_components(device);
	    list != NULL; list = list->next) {

	    *component = (devconfig_t *)list->obj;

	    /* Is this subcomponent an instance of the given type? */
	    if (*component != NULL && devconfig_isA(*component, type)) {
		oprintf(OUTPUT_DEBUG, gettext("Found %s\n"), typestr);
		return (0);
	    }
	}

	/* No component found */
	error = ENOENT;
	*component = NULL;

	oprintf(OUTPUT_DEBUG, gettext("%s not found\n"), typestr);

	if (create == B_TRUE) {
	    oprintf(OUTPUT_DEBUG, gettext("Creating %s\n"), typestr);

		/*
		 * An existing singleton component of the given type was
		 * not found under the given disk set.  So, create one.
		 */
	    if ((error = new_devconfig(component, type)) == 0) {
		/* Attach new component to given device */
		devconfig_set_components(
		    device, dlist_append(dlist_new_item(*component),
		    devconfig_get_components(device), AT_TAIL));
	    }
	}

	return (error);
}

/*
 * Set the available devices for use in creating this device
 *
 * @param       device
 *              a devconfig_t representing the device to modify
 *
 * @param       available
 *              A NULL-terminated array of device names
 */
void
devconfig_set_available(
	devconfig_t *device,
	char **available)
{
	device->available = available;
}

/*
 * Get the available devices for use in creating this device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @return      available
 *              A NULL-terminated array of device names
 */
char **
devconfig_get_available(
	devconfig_t *device)
{
	return (device->available);
}

/*
 * Set the unavailable devices which may not be used in creating this
 * device
 *
 * @param       device
 *              a devconfig_t representing the device to modify
 *
 * @param       available
 *              A NULL-terminated array of device names
 */
void
devconfig_set_unavailable(
	devconfig_t *device,
	char **unavailable)
{
	device->unavailable = unavailable;
}

/*
 * Get the unavailable devices for use in creating this device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @return      unavailable
 *              A NULL-terminated array of device names
 */
char **
devconfig_get_unavailable(
	devconfig_t *device)
{
	return (device->unavailable);
}

/*
 * Set the subcomponent devices of a given device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       components
 *              A dlist_t containing devconfig_t devices
 */
void
devconfig_set_components(
	devconfig_t *device,
	dlist_t *components)
{
	device->components = components;
}

/*
 * Get the subcomponent devices of a given device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @return      A dlist_t containing devconfig_t devices
 */
dlist_t *
devconfig_get_components(
	devconfig_t *device)
{
	return (device->components);
}

/*
 * Set the device name
 *
 * @param       device
 *              a devconfig_t representing the device to modify
 *
 * @param       name
 *              the value to set as the device name
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_name(
	devconfig_t *device,
	char *name)
{
	return (set_string(device->attributes, ATTR_NAME, name));
}

/*
 * Set the disk set name
 *
 * @param       diskset
 *              a devconfig_t representing the diskset to modify
 *
 * @param       name
 *              the value to set as the device name
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_diskset_name(
	devconfig_t *diskset,
	char *name)
{
	md_error_t error = mdnullerror;

	/* Verify syntax of disk set name */
	if (meta_set_checkname(name, &error)) {
	    volume_set_error(gettext("invalid disk set name: %s"), name);
	    return (-1);
	}

	return (devconfig_set_name(diskset, name));
}

/*
 * Set the device name
 *
 * @param       hsp
 *              a devconfig_t representing the hsp to modify
 *
 * @param       name
 *              the value to set as the device name
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_hsp_name(
	devconfig_t *hsp,
	char *name)
{
	/* Validate name */
	if (!is_hspname(name)) {
	    volume_set_error(gettext("invalid hot spare pool name: %s"), name);
	    return (-1);
	}

	return (devconfig_set_name(hsp, name));
}

/*
 * Set the device name
 *
 * @param       volume
 *              a devconfig_t representing the volume to modify
 *
 * @param       name
 *              the value to set as the device name
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_volume_name(
	devconfig_t *volume,
	char *name)
{
	/* Validate name */
	if (!is_metaname(name)) {
	    volume_set_error(gettext("invalid volume name: %s"), name);
	    return (-1);
	}

	return (devconfig_set_name(volume, name));
}

/*
 * Get the device name
 *
 * @param       volume
 *              a devconfig_t representing the volume to examine
 *
 * @param       name
 *              RETURN: the device name
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_name(
	devconfig_t *device,
	char **name)
{
	int error = get_string(device->attributes, ATTR_NAME, name);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("device name not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the device type
 *
 * @param       device
 *              a devconfig_t representing the device to modify
 *
 * @param       type
 *              the value to set as the device type
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_type(
	devconfig_t *device,
	component_type_t type)
{
	return (set_uint16(device->attributes, ATTR_TYPE, (uint16_t)type));
}

/*
 * Get the device type
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       type
 *              RETURN: the device type
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_type(
	devconfig_t *device,
	component_type_t *type)
{
	uint16_t val;
	int error = get_uint16(device->attributes, ATTR_TYPE, &val);

	switch (error) {
	    /* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	    case ENOENT:
		volume_set_error(gettext("device type not set"));
		error = ERR_ATTR_UNSET;
	    break;

	    /* Success */
	    case 0:
		*type = (component_type_t)val;
	}

	return (error);
}

/*
 * Set the device size (for volume, mirror, stripe, concat) in bytes
 *
 * Note that size in bytes in a 64-bit field cannot hold the size that
 * can be accessed in a 16 byte CDB.  Since CDBs operate on blocks,
 * the max capacity is 2^73 bytes with 512 byte blocks.
 *
 * @param       device
 *              a devconfig_t representing the device to modify
 *
 * @param       size_in_bytes
 *              the value to set as the device size in bytes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_size(
	devconfig_t *device,
	uint64_t size_in_bytes)
{

	/* Validate against limits */
	/* LINTED -- MIN_SIZE may be 0 */
	if (size_in_bytes < MIN_SIZE) {
	    volume_set_error(gettext("size (in bytes) too small: %llu"),
		(unsigned long long)size_in_bytes);
	    return (-1);
	}

	return (set_uint64(device->attributes,
	    ATTR_SIZEINBYTES, size_in_bytes));
}

/*
 * Get the device size (for volume, mirror, stripe, concat) in bytes
 *
 * Note that size in bytes in a 64-bit field cannot hold the size that
 * can be accessed in a 16 byte CDB.  Since CDBs operate on blocks,
 * the max capacity is 2^73 bytes with 512 byte blocks.
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       size_in_bytes
 *              RETURN: the device size in bytes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_size(
	devconfig_t *device,
	uint64_t *size_in_bytes)
{
	int error = get_uint64(
	    device->attributes, ATTR_SIZEINBYTES, size_in_bytes);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("size (in bytes) not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the device size in blocks
 *
 * @param       device
 *              a devconfig_t representing the device to modify
 *
 * @param       type
 *              the value to set as the device size in blocks
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_size_in_blocks(
	devconfig_t *device,
	uint64_t size_in_blocks)
{
	/* Validate against limits */
	/* LINTED -- MIN_SIZE_IN_BLOCKS may be 0 */
	if (size_in_blocks < MIN_SIZE_IN_BLOCKS) {
	    volume_set_error(gettext("size (in blocks) too small: %llu"),
		(unsigned long long)size_in_blocks);
	    return (-1);
	}

	return (set_uint64(device->attributes,
	    ATTR_SIZEINBLOCKS, size_in_blocks));
}

/*
 * Get the device size in blocks
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       size_in_blocks
 *              RETURN: the device size in blocks
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_size_in_blocks(
	devconfig_t *device,
	uint64_t *size_in_blocks)
{
	int error = get_uint64(
	    device->attributes, ATTR_SIZEINBLOCKS, size_in_blocks);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("size (in blocks) not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the the slice index
 *
 * @param       slice
 *              a devconfig_t representing the slice to modify
 *
 * @param       index
 *              the value to set as the the slice index
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_slice_index(
	devconfig_t *slice,
	uint16_t index)
{
	return (set_uint16(slice->attributes, ATTR_SLICE_INDEX, index));
}

/*
 * Get the slice index
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       index
 *              RETURN: the slice index
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_slice_index(
	devconfig_t *slice,
	uint16_t *index)
{
	int error = get_uint16(slice->attributes, ATTR_SLICE_INDEX, index);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("slice index not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the the slice start block
 *
 * @param       slice
 *              a devconfig_t representing the slice to modify
 *
 * @param       start_block
 *              the value to set as the the slice start block
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_slice_start_block(
	devconfig_t *slice,
	uint64_t start_block)
{
	return (set_uint64(slice->attributes,
	    ATTR_SLICE_STARTSECTOR, start_block));
}

/*
 * Get the slice start block
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       start_block
 *              RETURN: the slice start block
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_slice_start_block(
	devconfig_t *slice,
	uint64_t *start_block)
{
	int error = get_uint64(
	    slice->attributes, ATTR_SLICE_STARTSECTOR, start_block);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("slice start block not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the number of subcomponents in mirror
 *
 * @param       mirror
 *              a devconfig_t representing the mirror to modify
 *
 * @param       nsubs
 *              the value to set as the number of subcomponents in
 *              mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_mirror_nsubs(
	devconfig_t *mirror,
	uint16_t nsubs)
{
	/* Validate against limits */
	if (nsubs < 1 || nsubs > NMIRROR) {
	    volume_set_error(
		gettext("number of submirrors (%d) out of valid range (%d-%d)"),
		nsubs, 1, NMIRROR);
	    return (-1);
	}

	return (set_uint16(mirror->attributes, ATTR_MIRROR_NSUBMIRRORS, nsubs));
}

/*
 * Get number of subcomponents in mirror
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       nsubs
 *              RETURN: number of subcomponents in mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_mirror_nsubs(
	devconfig_t *mirror,
	uint16_t *nsubs)
{
	int error = get_uint16(
	    mirror->attributes, ATTR_MIRROR_NSUBMIRRORS, nsubs);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("number or submirrors not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the read strategy for mirror
 *
 * @param       mirror
 *              a devconfig_t representing the mirror to modify
 *
 * @param       read
 *              the value to set as the read strategy for mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_mirror_read(
	devconfig_t *mirror,
	mirror_read_strategy_t read)
{
	return (set_uint16(mirror->attributes,
	    ATTR_MIRROR_READ, (uint16_t)read));
}

/*
 * Get read strategy for mirror
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       read
 *              RETURN: read strategy for mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_mirror_read(
	devconfig_t *mirror,
	mirror_read_strategy_t *read)
{
	uint16_t val;
	int error = get_uint16(mirror->attributes, ATTR_MIRROR_READ, &val);

	switch (error) {
	    /* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	    case ENOENT:
		volume_set_error(gettext("mirror read strategy not set"));
		error = ERR_ATTR_UNSET;
	    break;

	    /* Success */
	    case 0:
		*read = (mirror_read_strategy_t)val;
	}

	return (error);
}

/*
 * Set the write strategy for mirror
 *
 * @param       mirror
 *              a devconfig_t representing the mirror to modify
 *
 * @param       write
 *              the value to set as the write strategy for mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_mirror_write(
	devconfig_t *mirror,
	mirror_write_strategy_t write)
{
	return (set_uint16(mirror->attributes,
	    ATTR_MIRROR_WRITE, (uint16_t)write));
}

/*
 * Get write strategy for mirror
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       write
 *              RETURN: write strategy for mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_mirror_write(
	devconfig_t *mirror,
	mirror_write_strategy_t *write)
{
	uint16_t val;
	int error = get_uint16(mirror->attributes, ATTR_MIRROR_WRITE, &val);

	switch (error) {
	    /* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	    case ENOENT:
		volume_set_error(gettext("mirror write strategy not set"));
		error = ERR_ATTR_UNSET;
	    break;

	    /* Success */
	    case 0:
		*write = (mirror_write_strategy_t)val;
	}

	return (error);
}

/*
 * Set the resync pass for mirror
 *
 * @param       mirror
 *              a devconfig_t representing the mirror to modify
 *
 * @param       pass
 *              the value to set as the resync pass for mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_mirror_pass(
	devconfig_t *mirror,
	uint16_t pass)
{
	/* Validate against max value */
	if (pass > MD_PASS_MAX) {
	    volume_set_error(
		gettext("mirror pass number (%d) out of valid range (0-%d)"),
		pass, MD_PASS_MAX);
	    return (-1);
	}

	return (set_uint16(mirror->attributes, ATTR_MIRROR_PASSNUM, pass));
}

/*
 * Get resync pass for mirror
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       pass
 *              RETURN: resync pass for mirror
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_mirror_pass(
	devconfig_t *mirror,
	uint16_t *pass)
{
	int error = get_uint16(mirror->attributes, ATTR_MIRROR_PASSNUM, pass);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("mirror pass number not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the minimum number of components in stripe
 *
 * @param       stripe
 *              a devconfig_t representing the stripe to modify
 *
 * @param       mincomp
 *              the value to set as the minimum number of components
 *              in stripe
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_stripe_mincomp(
	devconfig_t *stripe,
	uint16_t mincomp)
{
	/* Validate against minimum value */
	if (mincomp < MIN_NSTRIPE_COMP) {
	    volume_set_error(gettext(
		"minimum stripe components (%d) below minimum allowable (%d)"),
		mincomp, MIN_NSTRIPE_COMP);
	    return (-1);
	}

	return (set_uint16(stripe->attributes, ATTR_STRIPE_MINCOMP, mincomp));
}

/*
 * Get minimum number of components in stripe
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       mincomp
 *              RETURN: minimum number of components in stripe
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_stripe_mincomp(
	devconfig_t *stripe,
	uint16_t *mincomp)
{
	int error = get_uint16(
	    stripe->attributes, ATTR_STRIPE_MINCOMP, mincomp);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(
		gettext("minimum number of stripe components not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the maximum number of components in stripe
 *
 * @param       stripe
 *              a devconfig_t representing the stripe to modify
 *
 * @param       maxcomp
 *              the value to set as the maximum number of components
 *              in stripe
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_stripe_maxcomp(
	devconfig_t *stripe,
	uint16_t maxcomp)
{
	/* Validate against minimum value */
	if (maxcomp < MIN_NSTRIPE_COMP) {
	    volume_set_error(gettext(
		"maximum stripe components (%d) below minimum allowable (%d)"),
		maxcomp, MIN_NSTRIPE_COMP);
	    return (-1);
	}

	return (set_uint16(stripe->attributes, ATTR_STRIPE_MAXCOMP, maxcomp));
}

/*
 * Get maximum number of components in stripe
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       maxcomp
 *              RETURN: maximum number of components in stripe
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_stripe_maxcomp(
	devconfig_t *stripe,
	uint16_t *maxcomp)
{
	int error = get_uint16(
	    stripe->attributes, ATTR_STRIPE_MAXCOMP, maxcomp);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(
		gettext("maximum number of stripe components not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the stripe interlace
 *
 * @param       stripe
 *              a devconfig_t representing the stripe to modify
 *
 * @param       interlace
 *              the value to set as the stripe interlace
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_stripe_interlace(
	devconfig_t *stripe,
	uint64_t interlace)
{
	if (interlace < MININTERLACE || interlace > MAXINTERLACE) {
	    char *intstr = NULL;
	    char *minstr = NULL;
	    char *maxstr = NULL;

	    /* Get string representations of interlaces */
	    bytes_to_sizestr(interlace, &intstr, universal_units, B_FALSE);
	    bytes_to_sizestr(MININTERLACE, &minstr, universal_units, B_FALSE);
	    bytes_to_sizestr(MAXINTERLACE, &maxstr, universal_units, B_FALSE);

	    volume_set_error(
		gettext("interlace (%s) out of valid range (%s - %s)"),
		intstr, minstr, maxstr);

	    free(intstr);
	    free(minstr);
	    free(maxstr);

	    return (-1);
	}

	return (set_uint64(stripe->attributes,
	    ATTR_STRIPE_INTERLACE, interlace));
}

/*
 * Get stripe interlace
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       interlace
 *              RETURN: stripe interlace
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_stripe_interlace(
	devconfig_t *stripe,
	uint64_t *interlace)
{
	int error = get_uint64(
	    stripe->attributes, ATTR_STRIPE_INTERLACE, interlace);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("stripe interlace not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the redundancy level for a volume.
 *
 * @param       volume
 *              a devconfig_t representing the volume to modify
 *
 * @param       rlevel
 *              If 0, a stripe will be created.  If > 0, a mirror with
 *              this number of submirrors will be created.
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_volume_redundancy_level(
	devconfig_t *volume,
	uint16_t rlevel)
{
	/* Validate against limits */
	if (rlevel > NMIRROR) {
	    volume_set_error(gettext(
		"volume redundancy level (%d) out of valid range (%d-%d)"),
		rlevel, 0, NMIRROR);
	    return (-1);
	}

	return (set_uint16(volume->attributes, ATTR_VOLUME_REDUNDANCY, rlevel));
}

/*
 * Get the redundancy level for a volume.
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       rlevel
 *              RETURN: the redundancy level for a volume
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_volume_redundancy_level(
	devconfig_t *volume,
	uint16_t *rlevel)
{
	int error = get_uint16(
	    volume->attributes, ATTR_VOLUME_REDUNDANCY, rlevel);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("volume redundancy level not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the number of paths in volume
 *
 * @param       volume
 *              a devconfig_t representing the volume to modify
 *
 * @param       npaths
 *              the value to set as the number of paths in volume
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_volume_npaths(
	devconfig_t *volume,
	uint16_t npaths)
{
	/* Validate against limits */
	if (npaths < MIN_NDATAPATHS || npaths > MAX_NDATAPATHS) {
	    volume_set_error(
		gettext("number of data paths (%d) out of valid range (%d-%d)"),
		npaths, MIN_NDATAPATHS, MAX_NDATAPATHS);
	    return (-1);
	}

	return (set_uint16(volume->attributes, ATTR_VOLUME_DATAPATHS, npaths));
}

/*
 * Get number of paths in volume
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       npaths
 *              RETURN: number of paths in volume
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_volume_npaths(
	devconfig_t *volume,
	uint16_t *npaths)
{
	int error = get_uint16(
	    volume->attributes, ATTR_VOLUME_DATAPATHS, npaths);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("number of data paths not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Set the HSP creation option (for volume, stripe, concat, mirror)
 *
 * @param       volume
 *              a devconfig_t representing the volume to modify
 *
 * @param       usehsp
 *              the value to set as the HSP creation option
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_set_volume_usehsp(
	devconfig_t *volume,
	boolean_t usehsp)
{
	return (set_boolean(volume->attributes, ATTR_VOLUME_USEHSP, usehsp));
}

/*
 * Get HSP creation option (for volume, stripe, concat, mirror)
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       usehsp
 *              RETURN: HSP creation option (for volume, stripe,
 *              concat, mirror)
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
devconfig_get_volume_usehsp(
	devconfig_t *volume,
	boolean_t *usehsp)
{
	int error = get_boolean(
	    volume->attributes, ATTR_VOLUME_USEHSP, usehsp);

	/* Convert ENOENT to ERR_ATTR_UNSET for a custom error message */
	if (error == ENOENT) {
	    volume_set_error(gettext("volume usehsp not set"));
	    error = ERR_ATTR_UNSET;
	}

	return (error);
}

/*
 * Get the string representation of the volume's type
 *
 * @param       type
 *              a valid component_type_t
 *
 * @return      an internationalized string representing the given
 *              type
 */
char *
devconfig_type_to_str(
	component_type_t type)
{
	char *str;

	switch (type) {
	    case TYPE_CONCAT:	    str = gettext("Concat");	    break;
	    case TYPE_CONTROLLER:   str = gettext("Controller");    break;
	    case TYPE_DISKSET:	    str = gettext("Diskset");	    break;
	    case TYPE_DRIVE:	    str = gettext("Disk");	    break;
	    case TYPE_EXTENT:	    str = gettext("Extent");	    break;
	    case TYPE_HOST:	    str = gettext("Host");	    break;
	    case TYPE_HSP:	    str = gettext("Hot Spare Pool"); break;
	    case TYPE_MIRROR:	    str = gettext("Mirror");	    break;
	    case TYPE_RAID5:	    str = gettext("Raid5");	    break;
	    case TYPE_SLICE:	    str = gettext("Slice");	    break;
	    case TYPE_SOFTPART:	    str = gettext("Soft Partition"); break;
	    case TYPE_STRIPE:	    str = gettext("Stripe");	    break;
	    case TYPE_TRANS:	    str = gettext("Trans");	    break;
	    case TYPE_VOLUME:	    str = gettext("Volume");	    break;
	    default:
	    case TYPE_UNKNOWN:	    str = gettext("Unknown");	    break;
	}

	return (str);
}

/*
 * Get the string representation of the mirror's read strategy
 *
 * @param       read
 *              a valid mirror_read_strategy_t
 *
 * @return      an internationalized string representing the given
 *              read strategy
 */
char *
devconfig_read_strategy_to_str(
	mirror_read_strategy_t read)
{
	char *str;

	switch (read) {
	    case MIRROR_READ_ROUNDROBIN: str = gettext("ROUNDROBIN");	break;
	    case MIRROR_READ_GEOMETRIC:	 str = gettext("GEOMETRIC");	break;
	    case MIRROR_READ_FIRST:	 str = gettext("FIRST");	break;
	    default:			 str = "";
	}

	return (str);
}

/*
 * Get the string representation of the mirror's write strategy
 *
 * @param       write
 *              a valid mirror_write_strategy_t
 *
 * @return      an internationalized string representing the given
 *              write strategy
 */
char *
devconfig_write_strategy_to_str(
	mirror_write_strategy_t write)
{
	char *str;

	switch (write) {
	    case MIRROR_WRITE_PARALLEL:	str = gettext("PARALLEL");	break;
	    case MIRROR_WRITE_SERIAL:	str = gettext("SERIAL");	break;
	    default:			str = "";
	}

	return (str);
}

#ifdef DEBUG
/*
 * Dump the contents of a devconfig_t struct to stdout.
 *
 * @param       device
 *              the devconfig_t to examine
 *
 * @param       prefix
 *              a prefix string to print before each line
 */
void
devconfig_dump(
	devconfig_t *device,
	char *prefix)
{
	dlist_t *comps = NULL;
	char **array = NULL;
	char *str = NULL;
	int i = 0;

	component_type_t type = TYPE_UNKNOWN;
	boolean_t bool = B_FALSE;
	uint16_t val16 = 0;
	uint64_t val64 = 0;
	mirror_read_strategy_t read;
	mirror_write_strategy_t write;

	if (device == NULL) {
	    return;
	}

	/* Type */
	if (devconfig_get_type(device, &type) == 0) {
	    printf("%s%s\n", prefix, devconfig_type_to_str(type));
	}

	/* Name */
	if (devconfig_get_name(device, &str) == 0) {
	    printf("%s  name: %s\n", prefix, str);
	}

	/* Size in bytes */
	if (devconfig_get_size(device, &val64) == 0) {
	    printf("%s  size in bytes: %llu\n", prefix, val64);
	}

	/* Size in blocks */
	if (devconfig_get_size_in_blocks(device, &val64) == 0) {
	    printf("%s  size in blocks: %llu\n", prefix, val64);
	}

	/* Use HSP */
	if (devconfig_get_volume_usehsp(device, &bool) == 0) {
	    printf("%s  usehsp: %s\n", prefix, bool? "TRUE" : "FALSE");
	}

	switch (type) {
	    case TYPE_VOLUME:
		/* Volume rlevel */
		if (devconfig_get_volume_redundancy_level(
		    device, &val16) == 0) {
		    printf("%s  volume redundancy level: %d\n", prefix, val16);
		}

		/* Volume npaths */
		if (devconfig_get_volume_npaths(device, &val16) == 0) {
		    printf("%s  volume npaths: %d\n", prefix, val16);
		}
	    break;

	    case TYPE_MIRROR:

		/* Mirror nsubs */
		if (devconfig_get_mirror_nsubs(device, &val16) == 0) {
		    printf("%s  mirror nsubs: %d\n", prefix, val16);
		}

		/* Mirror read */
		if (devconfig_get_mirror_read(device, &read) == 0) {
		    printf("%s  mirror read: %s\n", prefix,
			devconfig_read_strategy_to_str(read));
		}

		/* Mirror write */
		if (devconfig_get_mirror_write(device, &write) == 0) {
		    printf("%s  mirror write: %s\n", prefix,
			devconfig_write_strategy_to_str(write));
		}

		/* Mirror pass */
		if (devconfig_get_mirror_pass(device, &val16) == 0) {
		    printf("%s  mirror pass: %d\n", prefix, val16);
		}
	    break;

	    case TYPE_STRIPE:
		/* Stripe mincomp */
		if (devconfig_get_stripe_mincomp(device, &val16) == 0) {
		    printf("%s  stripe mincomp: %d\n", prefix, val16);
		}

		/* Stripe maxcomp */
		if (devconfig_get_stripe_maxcomp(device, &val16) == 0) {
		    printf("%s  stripe maxcomp: %d\n", prefix, val16);
		}

		/* Stripe interlace */
		if (devconfig_get_stripe_interlace(device, &val64) == 0) {
		    printf("%s  stripe interlace: %lld\n", prefix, val64);
		}
	    break;

	    case TYPE_SLICE:
		/* Slice index */
		if (devconfig_get_slice_index(device, &val16) == 0) {
		    printf("%s  slice index: %d\n", prefix, val16);
		}

		/* Slice start block */
		if (devconfig_get_slice_start_block(device, &val64) == 0) {
		    printf("%s  slice start block: %llu\n", prefix, val64);
		}
	    break;
	}

	array = devconfig_get_available(device);
	if (array != NULL) {
	    printf("%s  available:\n", prefix);
	    for (i = 0; array[i] != NULL; i++) {
		printf("%s    %s\n", prefix, array[i]);
	    }
	}

	array = devconfig_get_unavailable(device);
	if (array != NULL) {
	    printf("%s  unavailable:\n", prefix);
	    for (i = 0; array[i] != NULL; i++) {
		printf("%s    %s\n", prefix, array[i]);
	    }
	}

	printf("\n");

	comps = devconfig_get_components(device);
	if (comps != NULL) {
	    char buf[128];
	    snprintf(buf, 128, "%s%s", prefix, "    ");
	    for (; comps != NULL; comps = comps->next) {
		devconfig_dump((devconfig_t *)comps->obj, buf);
	    }
	}
}
#endif /* DEBUG */
