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

#ifndef	_VOLUME_DEVCONFIG_H
#define	_VOLUME_DEVCONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <libnvpair.h>
#include "volume_dlist.h"
#include <sys/lvm/md_mdiox.h>

/*
 * String constants for XML element/attribute names.
 */
#define	ELEMENT_AVAILABLE		"available"
#define	ELEMENT_COMMENT			"comment"
#define	ELEMENT_CONCAT			"concat"
#define	ELEMENT_DISK			"disk"
#define	ELEMENT_DISKSET			"diskset"
#define	ELEMENT_HSP			"hsp"
#define	ELEMENT_L10N			"localization"
#define	ELEMENT_MESSAGE			"message"
#define	ELEMENT_MIRROR			"mirror"
#define	ELEMENT_PARAM			"param"
#define	ELEMENT_SLICE			"slice"
#define	ELEMENT_STRIPE			"stripe"
#define	ELEMENT_TEXT			"text"
#define	ELEMENT_UNAVAILABLE		"unavailable"
#define	ELEMENT_VARIABLE		"variable"
#define	ELEMENT_VOLUME			"volume"
#define	ELEMENT_VOLUMECONFIG		"volume-config"
#define	ELEMENT_VOLUMEDEFAULTS		"volume-defaults"
#define	ELEMENT_VOLUMEREQUEST		"volume-request"

#define	ATTR_LANG			"xml:lang"
#define	ATTR_MESSAGEID			"msgid"
#define	ATTR_MIRROR_NSUBMIRRORS		"nsubmirrors"
#define	ATTR_MIRROR_PASSNUM		"passnum"
#define	ATTR_MIRROR_READ		"read"
#define	ATTR_MIRROR_WRITE		"write"
#define	ATTR_NAME			"name"
#define	ATTR_SELECT			"select"
#define	ATTR_SIZEINBLOCKS		"sizeinblocks"
#define	ATTR_SIZEINBYTES		"size"
#define	ATTR_SLICE_INDEX		"index"
#define	ATTR_SLICE_STARTSECTOR		"startsector"
#define	ATTR_STRIPE_INTERLACE		"interlace"
#define	ATTR_STRIPE_MAXCOMP		"maxcomp"
#define	ATTR_STRIPE_MINCOMP		"mincomp"
#define	ATTR_TYPE			"type"
#define	ATTR_VOLUME_CREATE		"create"
#define	ATTR_VOLUME_DATAPATHS		"datapaths"
#define	ATTR_VOLUME_FAULTRECOVERY	"faultrecovery"
#define	ATTR_VOLUME_REDUNDANCY		"redundancy"
#define	ATTR_VOLUME_USEHSP		"usehsp"

#define	NAME_L10N_MESSAGE_FILE		"msgfile"
#define	NAME_LANG			"lang"

/*
 * Limits for attributes
 */
#define	MIN_NSTRIPE_COMP	1
#define	MIN_SIZE		0
#define	MIN_SIZE_IN_BLOCKS	0
#define	MIN_NDATAPATHS		1
#define	MAX_NDATAPATHS		4

/* Attribute requested but not set */
#define	ERR_ATTR_UNSET	-10001

/*
 * Enumeration defining physical or logical device types
 */
typedef enum {
	TYPE_UNKNOWN = 0,
	TYPE_CONCAT = 1,
	TYPE_CONTROLLER,
	TYPE_DISKSET,
	TYPE_DRIVE,
	TYPE_EXTENT,
	TYPE_HOST,
	TYPE_HSP,
	TYPE_MIRROR,
	TYPE_RAID5,
	TYPE_SLICE,
	TYPE_SOFTPART,
	TYPE_STRIPE,
	TYPE_TRANS,
	TYPE_VOLUME
} component_type_t;

/*
 * enumerated constants for SVM Mirror read strategies
 */
typedef enum {
	MIRROR_READ_ROUNDROBIN = 0,
	MIRROR_READ_GEOMETRIC,
	MIRROR_READ_FIRST
} mirror_read_strategy_t;

/*
 * enumerated constants for SVM Mirror write strategies
 */
typedef enum {
	MIRROR_WRITE_PARALLEL = 0,
	MIRROR_WRITE_SERIAL
} mirror_write_strategy_t;

/*
 * devconfig_t - struct to hold a device configuration hierarchy
 */
typedef struct devconfig {

	/* Attributes of this device */
	nvlist_t *attributes;

	/*
	 * Available devices for use in construction of this device
	 * and its subcomponents
	 */
	char **available;

	/*
	 * Unavailable devices for use in construction of this device
	 * and its subcomponents
	 */
	char **unavailable;

	/*
	 * Subcomponents (devconfig_t) of this device
	 */
	dlist_t *components;
} devconfig_t;

/*
 * Function prototypes
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
extern int new_devconfig(devconfig_t **devconfig, component_type_t type);

/*
 * Free memory (recursively) allocated to a devconfig_t struct
 *
 * @param       arg
 *              pointer to the devconfig_t to be freed
 */
extern void free_devconfig(void *arg);

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
extern boolean_t devconfig_isA(devconfig_t *device, component_type_t type);

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
extern int devconfig_get_component(devconfig_t *device,
	component_type_t type, devconfig_t **component, boolean_t create);

/*
 * Set the available devices for use in creating this device
 *
 * @param       device
 *              a devconfig_t representing the device to modify
 *
 * @param       available
 *              A NULL-terminated array of device names
 */
extern void devconfig_set_available(devconfig_t *device, char **available);

/*
 * Get the available devices for use in creating this device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @return      available
 *              A NULL-terminated array of device names
 */
extern char ** devconfig_get_available(devconfig_t *device);

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
extern void devconfig_set_unavailable(devconfig_t *device, char **unavailable);

/*
 * Get the unavailable devices for use in creating this device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @return      unavailable
 *              A NULL-terminated array of device names
 */
extern char ** devconfig_get_unavailable(devconfig_t *device);

/*
 * Set the subcomponent devices of a given device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @param       components
 *              A dlist_t containing devconfig_t devices
 */
extern void devconfig_set_components(devconfig_t *device, dlist_t *components);

/*
 * Get the subcomponent devices of a given device
 *
 * @param       device
 *              a devconfig_t representing the device to examine
 *
 * @return      A dlist_t containing devconfig_t devices
 */
extern dlist_t *devconfig_get_components(devconfig_t *device);

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
extern int devconfig_set_name(devconfig_t *device, char *name);

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
extern int devconfig_set_diskset_name(devconfig_t *diskset, char *name);

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
extern int devconfig_set_hsp_name(devconfig_t *hsp, char *name);

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
extern int devconfig_set_volume_name(devconfig_t *volume, char *name);

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
extern int devconfig_get_name(devconfig_t *device, char **name);

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
extern int devconfig_set_type(devconfig_t *device, component_type_t type);

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
extern int devconfig_get_type(devconfig_t *device, component_type_t *type);

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
extern int devconfig_set_size(devconfig_t *device, uint64_t size_in_bytes);

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
extern int devconfig_get_size(devconfig_t *device, uint64_t *size_in_bytes);

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
extern int devconfig_set_size_in_blocks(
	devconfig_t *device, uint64_t size_in_blocks);

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
extern int devconfig_get_size_in_blocks(
	devconfig_t *device, uint64_t *size_in_blocks);

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
extern int devconfig_set_slice_index(devconfig_t *slice, uint16_t index);

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
extern int devconfig_get_slice_index(devconfig_t *slice, uint16_t *index);

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
extern int devconfig_set_slice_start_block(
	devconfig_t *slice, uint64_t start_block);

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
extern int devconfig_get_slice_start_block(
	devconfig_t *slice, uint64_t *start_block);

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
extern int devconfig_set_mirror_nsubs(devconfig_t *mirror, uint16_t nsubs);

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
extern int devconfig_get_mirror_nsubs(devconfig_t *mirror, uint16_t *nsubs);

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
extern int devconfig_set_mirror_read(
	devconfig_t *mirror, mirror_read_strategy_t read);

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
extern int devconfig_get_mirror_read(
	devconfig_t *mirror, mirror_read_strategy_t *read);

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
extern int devconfig_set_mirror_write(
	devconfig_t *mirror, mirror_write_strategy_t write);

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
extern int devconfig_get_mirror_write(
	devconfig_t *mirror, mirror_write_strategy_t *write);

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
extern int devconfig_set_mirror_pass(devconfig_t *mirror, uint16_t pass);

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
extern int devconfig_get_mirror_pass(devconfig_t *mirror, uint16_t *pass);

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
extern int devconfig_set_stripe_mincomp(devconfig_t *stripe, uint16_t mincomp);

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
extern int devconfig_get_stripe_mincomp(devconfig_t *stripe, uint16_t *mincomp);

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
extern int devconfig_set_stripe_maxcomp(devconfig_t *stripe, uint16_t maxcomp);

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
extern int devconfig_get_stripe_maxcomp(devconfig_t *stripe, uint16_t *maxcomp);

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
extern int devconfig_set_stripe_interlace(
	devconfig_t *stripe, uint64_t interlace);

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
extern int devconfig_get_stripe_interlace(
	devconfig_t *stripe, uint64_t *interlace);

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
extern int devconfig_set_volume_redundancy_level(
	devconfig_t *volume, uint16_t rlevel);

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
extern int devconfig_get_volume_redundancy_level(
	devconfig_t *volume, uint16_t *rlevel);

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
extern int devconfig_set_volume_npaths(devconfig_t *volume, uint16_t npaths);

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
extern int devconfig_get_volume_npaths(devconfig_t *volume, uint16_t *npaths);

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
extern int devconfig_set_volume_usehsp(devconfig_t *volume, boolean_t usehsp);

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
extern int devconfig_get_volume_usehsp(devconfig_t *volume, boolean_t *usehsp);

/*
 * Get the string representation of the volume's type
 *
 * @param       type
 *              a valid component_type_t
 *
 * @return      an internationalized string representing the given
 *              type
 */
extern char *devconfig_type_to_str(component_type_t type);

/*
 * Get the string representation of the mirror's read strategy
 *
 * @param       read
 *              a valid mirror_read_strategy_t
 *
 * @return      an internationalized string representing the given
 *              read strategy
 */
extern char *devconfig_read_strategy_to_str(mirror_read_strategy_t read);

/*
 * Get the string representation of the mirror's write strategy
 *
 * @param       write
 *              a valid mirror_write_strategy_t
 *
 * @return      an internationalized string representing the given
 *              write strategy
 */
extern char *devconfig_write_strategy_to_str(mirror_write_strategy_t write);

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
extern void devconfig_dump(devconfig_t *device, char *prefix);
#endif /* DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_DEVCONFIG_H */
