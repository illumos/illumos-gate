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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Medium class implementation file.
 */

/*
 * System include files
 */

#include <stdlib.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>

/*
 * Local include files
 */

#include "medium.h"
#include "partition.h"

/*
 * Definitions of private attributes and methods shared
 * with friend classes like the partition class.
 */

#include "medium_private.h"

extern bool_t	support_nomedia;

/*
 * IMPORTANT NOTE:
 *
 * The strings in the medium_result_strings[] string array below
 * MUST match the result types in typedef enum medium_result_t in
 * medium.h.  When you add or remove result types, keep the
 * result types and the matching strings in alphabetical order
 * to make it easier to maintain the match.
 */

static const char *medium_result_strings[] = {
	"bad device",
	"bad file descriptor",
	"bad input parameter",
	"can't create partitions",
	"can't create pathnames",
	"can't create vnodes",
	"can't get access_mode",
	"can't mount partitions",
	"can't remount partitions",
	"can't remove medium from the database",
	"can't unmount partitions",
	"out of memory",
	"success"
};

/*
 * Declarations of private methods
 */

static medium_result_t
create_block_pathname(char *raw_pathnamep,
			char **block_pathnamepp);
/*
 * Converts a raw pathname into a block pathname.
 */

static medium_result_t
create_pathnames(medium_private_t *medium_privatep);
/*
 * Creates the "/vol" block and raw pathnames of the
 * medium and writes pointers to them to the medium's
 * block_pathnamep and raw_pathnamep attributes.
 */

static medium_result_t
create_symlink_directory(medium_private_t *medium_privatep);
/*
 * When the medium contains more than one file system,
 * creates a directory that will contain a symbolic link
 * to each of the file systems.  Creates a symbolic link
 * to that directory, and stores a pointer to the symbolic
 * link in the dp_symvn attribute of the device object
 * that models the device in which the medium is inserted.
 */

static medium_result_t
get_permissions(medium_private_t *medium_privatep);
/*
 * Gets the access mode of the medium addressed by
 * file_descriptor.  Writes the encoded access mode to
 * *permissionsp.  If it can't get the access mode it
 * returns an error code and writes READ_WRITE to
 * *permissionsp.
 */

static medium_result_t
remove_medium_from_db(medium_handle_t	mediump);
/*
 * Removes all database entries for the medium object.
 */

/*
 * Definitions of public functions
 */

static medium_result_t
create_new_medium(dev_t  in_device,
		medium_handle_t *mediumpp)
{
	struct devs 		*devicep;
	int			(*device_get_fd)(dev_t) = NULL;
	medium_result_t		medium_result;
	partition_result_t	partition_result;
	medium_private_t 	*privatep;

	debug(2, "entering create_new_medium()\n");

	medium_result = MEDIUM_SUCCESS;
	if ((mediumpp == NULL) || (in_device == NODEV)) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	}
	if (medium_result == MEDIUM_SUCCESS) {
		privatep = (medium_private_t *)calloc((size_t)1,
			(size_t)sizeof (medium_private_t));
		if (privatep == NULL) {
			medium_result = MEDIUM_OUT_OF_MEMORY;
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		devicep = dev_getdp(in_device);
		if ((devicep != NULL) && (devicep->dp_dsw != NULL)) {
			privatep->in_device = in_device;
		} else {
			medium_result = MEDIUM_BAD_DEVICE;
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		medium_result = create_pathnames(privatep);
	}
	if (medium_result == MEDIUM_SUCCESS) {
		privatep->block_vvnodep = devicep->dp_bvn;
		device_get_fd = devicep->dp_dsw->d_getfd;
		if (device_get_fd == NULL) {
			medium_result = MEDIUM_BAD_DEVICE;
		} else {
			privatep->file_descriptor = NO_FILE_DESCRIPTOR;
			privatep->file_descriptor = (*device_get_fd)(in_device);
			if (privatep->file_descriptor == NO_FILE_DESCRIPTOR) {
				medium_result = MEDIUM_BAD_FILE_DESCRIPTOR;
			}
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		privatep->number_of_filesystems = 0;
		privatep->number_of_partition_types =
			number_of_partition_types();
		privatep->partition_counts = (int *)
			calloc((size_t)privatep->number_of_partition_types,
				(size_t)sizeof (int));
		if (privatep->partition_counts == NULL) {
			medium_result = MEDIUM_OUT_OF_MEMORY;
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		privatep->gid = devicep->dp_dsw->d_gid;
		privatep->medium_typep = strdup(devicep->dp_dsw->d_mtype);
		if (privatep->medium_typep == NULL) {
			medium_result = MEDIUM_OUT_OF_MEMORY;
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		privatep->mode = devicep->dp_dsw->d_mode;
		medium_result = get_permissions(privatep);
	}
	if (medium_result == MEDIUM_SUCCESS) {
		struct dk_minfo dkinfo;

		privatep->medium_capacity = 0;
		if (ioctl(privatep->file_descriptor, DKIOCGMEDIAINFO,
		    &dkinfo) == 0) {
			privatep->medium_capacity =
			    (uint64_t)dkinfo.dki_capacity * dkinfo.dki_lbsize;
		}
		if (privatep->medium_capacity == 0) {
			privatep->medium_capacity = ULLONG_MAX;
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		privatep->raw_vvnodep = devicep->dp_rvn;
		privatep->uid = devicep->dp_dsw->d_uid;
		partition_result =
			create_top_partition((medium_handle_t)privatep,
			(partition_handle_t *)
						&(privatep->top_partitionp));
		if (partition_result != PARTITION_SUCCESS) {
			medium_result = MEDIUM_CANT_CREATE_PARTITIONS;
		}
	}
	/*
	 * we will start creating nodes which may be accessed from
	 * the main thread. vold_main_mutex needs to be acquired
	 * to avoid race condition between main and other threads
	 * which are reading mediums.
	 */
	(void) mutex_lock(&vold_main_mutex);

	if (medium_result == MEDIUM_SUCCESS) {
		if (privatep->number_of_filesystems > 1) {
			medium_result = create_symlink_directory(privatep);
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		partition_result =
			partition_create_vnodes(privatep->top_partitionp);
		if (partition_result != PARTITION_SUCCESS) {
			medium_result = MEDIUM_CANT_CREATE_VNODES;
		}
	}


	if (medium_result != MEDIUM_SUCCESS) {
		destroy_medium((medium_handle_t *)&privatep);
	}

	*mediumpp = (medium_handle_t)privatep;
	/*
	 * In later versions of the volume management software
	 * device objects will create medium objects on insertion
	 * of media into the devices that the device objects model.
	 * They will therefore know which medium objects model the
	 * media they contain without having to be told.  The
	 * current architecture of the volume manager software forces
	 * medium objects to tell device objects that they model
	 * media inserted in the devices that the device objects
	 * model.
	 */
	if (devicep != NULL) {
		devicep->dp_mediump = (medium_handle_t)privatep;
	}

	(void) mutex_unlock(&vold_main_mutex);

	debug(2, "leaving create_new_medium(), result code = %s\n",
		medium_result_strings[medium_result]);

	return (medium_result);
}

void
destroy_medium(medium_handle_t *mediumpp)
{
	medium_result_t		medium_result;
	medium_private_t 	*privatep;

	debug(2, "entering destroy_medium()\n");

	medium_result = MEDIUM_SUCCESS;
	if (mediumpp == NULL) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	}
	if (medium_result == MEDIUM_SUCCESS) {
		privatep = (medium_private_t *)*mediumpp;
		if (privatep == NULL) {
			medium_result = MEDIUM_BAD_INPUT_PARAMETER;
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		destroy_partition(&(privatep->top_partitionp));
		if (privatep->block_pathnamep != NULL) {
			free(privatep->block_pathnamep);
		}
		if (privatep->medium_typep != NULL) {
			free(privatep->medium_typep);
		}
		if (privatep->partition_counts != NULL) {
			free(privatep->partition_counts);
		}
		if (privatep->raw_pathnamep != NULL) {
			free(privatep->raw_pathnamep);
		}
		if (privatep->symlink_dir_namep != NULL) {
			free(privatep->symlink_dir_namep);
		}
		free(privatep);
		*mediumpp = NULL;
	}

	debug(2, "leaving destroy_medium(), result code = %s\n",
		medium_result_strings[medium_result]);

}

medium_result_t
medium_mount_partitions(medium_handle_t  mediump)
{
	medium_result_t		medium_result;
	partition_result_t	partition_result;
	medium_private_t 	*privatep;

	debug(2, "entering medium_mount_partitions()\n");

	medium_result = MEDIUM_SUCCESS;
	privatep = (medium_private_t *)mediump;
	if (privatep == NULL) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	} else if (privatep->top_partitionp == NULL) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	}
	if (medium_result == MEDIUM_SUCCESS) {
		partition_result = mount_partition(privatep->top_partitionp);
	}
	if (partition_result != PARTITION_SUCCESS) {
		medium_result = MEDIUM_CANT_MOUNT_PARTITIONS;
	}

	debug(2, "leaving medium_mount_partitions(), result code = %s\n",
		medium_result_strings[medium_result]);

	return (medium_result);
}

medium_result_t
medium_remount_partitions(medium_handle_t  mediump)
{
	medium_result_t		medium_result;
	partition_result_t	partition_result;
	medium_private_t 	*privatep;

	debug(2, "entering medium_remount_partitions()\n");

	medium_result = MEDIUM_SUCCESS;
	privatep = (medium_private_t *)mediump;
	if (privatep == NULL) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	} else if (privatep->top_partitionp == NULL) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	}
	if (medium_result == MEDIUM_SUCCESS) {
		partition_result = remount_partition(privatep->top_partitionp);
	}
	if (partition_result != PARTITION_SUCCESS) {
		medium_result = MEDIUM_CANT_REMOUNT_PARTITIONS;
	}

	debug(2, "leaving medium_remount_partitions(), result code = %s\n",
		medium_result_strings[medium_result]);

	return (medium_result);
}

medium_result_t
medium_unmount_partitions(medium_handle_t  mediump)
{
	medium_result_t		medium_result;
	partition_result_t	partition_result;
	medium_private_t 	*privatep;

	debug(2, "entering medium_unmount_partitions()\n");

	medium_result = MEDIUM_SUCCESS;
	privatep = (medium_private_t *)mediump;
	if (privatep == NULL) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	} else if (privatep->top_partitionp == NULL) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	}
	if (medium_result == MEDIUM_SUCCESS) {
		partition_result = unmount_partition(privatep->top_partitionp);
		if (partition_result != PARTITION_SUCCESS) {
			medium_result = MEDIUM_CANT_UNMOUNT_PARTITIONS;
		}
	}

	debug(2, "leaving medium_unmount_partitions(), result code = %s\n",
		medium_result_strings[medium_result]);

	return (medium_result);
}

static medium_result_t
remove_medium_from_db(medium_handle_t	mediump)
{
	uint_t			error;
	medium_private_t 	*medium_privatep;
	medium_result_t		medium_result;
	vol_t 			*volumep;

	error = 0;
	medium_privatep = (medium_private_t *)mediump;
	medium_result = MEDIUM_SUCCESS;
	volumep = medium_privatep->volumep;

	if (volumep != NULL && (volumep->v_flags & V_UNLAB) == 0) {
		volumep->v_confirmed = FALSE;
		node_remove((obj_t *)volumep, TRUE, &error);
		if (error != 0) {
			medium_result = MEDIUM_CANT_REMOVE_FROM_DB;
		}
	}
	return (medium_result);
}

medium_result_t
create_medium(dev_t in_device, medium_handle_t *mediumpp)
{
	struct devs 		*devicep;
	medium_result_t		medium_result;

	debug(2, "Entering create_medium()\n");

	medium_result = MEDIUM_SUCCESS;
	if (mediumpp == NULL || in_device == NODEV) {
		medium_result = MEDIUM_BAD_INPUT_PARAMETER;
	}
	if (medium_result == MEDIUM_SUCCESS) {
		devicep = dev_getdp(in_device);
		if (devicep == NULL || devicep->dp_dsw == NULL) {
			medium_result = MEDIUM_BAD_DEVICE;
		}
	}
	if (medium_result == MEDIUM_SUCCESS) {
		/*
		 * do the real work.
		 */
		medium_result = create_new_medium(in_device, mediumpp);
	}
	if (medium_result != MEDIUM_SUCCESS) {
		/*
		 * We'd better to eject the medium here. Otherwise user
		 * cannot do anything against the inserted medium since
		 * vold does not create a device node for it.
		 */
		if (devicep != NULL) {
			dev_hard_eject(devicep);
			/*
			 * Create "nomedia" device node.
			 */
			if (support_nomedia) {
				(void) mutex_lock(&vold_main_mutex);
				dev_create_ctldev(devicep);
				(void) mutex_unlock(&vold_main_mutex);
			}
		}
	}

	debug(2, "leaving create_medium(), result code = %s\n",
		medium_result_strings[medium_result]);

	return (medium_result);
}

void
clean_medium_and_volume(medium_handle_t mediump)
{
	medium_private_t *privatep;
	vol_t	*v;

	/*
	 * called only from main thread. No need to acquire
	 * lock.
	 */
	privatep = (medium_private_t *)mediump;
	v = privatep->volumep;
	(void) remove_medium_from_db(mediump);
	destroy_medium(&mediump);
	destroy_volume(v);
}

/*
 * Definitions of private methods
 */

static medium_result_t
create_block_pathname(char *raw_pathnamep,
		    char **block_pathnamepp)
{
	medium_result_t		medium_result;
	char 			*block_pathnamep;
	size_t			block_pathname_length;
	char 			*device_namep;
	char 			*device_numberp;
	char 			*rdiskette_startp;
	char 			*rdsk_startp;

	debug(8, "entering create_block_pathname()\n");

	medium_result = MEDIUM_SUCCESS;
	/*
	 * malloc one less char than the number used in raw_pathnamep
	 * because "/dsk/" has one less character than "/rdsk/", and
	 * "diskette" has one less character than "rdiskette"
	 */
	block_pathname_length = strlen(raw_pathnamep) - 1;
	block_pathnamep = (char *)malloc((size_t)(block_pathname_length + 1));
	if (block_pathnamep == NULL) {
		medium_result = MEDIUM_OUT_OF_MEMORY;
	}
	if (medium_result == MEDIUM_SUCCESS) {
		rdsk_startp = strstr(raw_pathnamep, "/rdsk/");
		if (rdsk_startp != NULL) {
			device_namep = rdsk_startp + 6;
			(void) strncpy(block_pathnamep, raw_pathnamep,
				(rdsk_startp - raw_pathnamep));
			block_pathnamep[rdsk_startp - raw_pathnamep] = NULLC;
			(void) strcat(block_pathnamep, "/dsk/");
			(void) strcat(block_pathnamep, device_namep);
		} else {
			rdiskette_startp = strstr(raw_pathnamep, "rdiskette");
			if (rdiskette_startp != NULL) {
				device_numberp = rdiskette_startp + 9;
				(void) strncpy(block_pathnamep, raw_pathnamep,
					(rdiskette_startp - raw_pathnamep));
				block_pathnamep[rdiskette_startp -
					raw_pathnamep] = NULLC;
				(void) strcat(block_pathnamep, "diskette");
				(void) strcat(block_pathnamep, device_numberp);
			}
		}
	}
	*block_pathnamepp = block_pathnamep;

	debug(8, "leaving create_block_pathname(), result code = %s\n",
		medium_result_strings[medium_result]);

	return (medium_result);
}

static medium_result_t
create_pathnames(medium_private_t *medium_privatep)
{
	struct devs 		*devicep;
	medium_result_t		medium_result;
	char 			*pathname_bufferp;
	char 			*raw_devicep;
	int			raw_slice_path_length;

	debug(8, "entering create_pathnames()\n");

	medium_result = MEDIUM_SUCCESS;
	pathname_bufferp = malloc(MAXPATHLEN);
	if (pathname_bufferp == NULL) {
		medium_result = MEDIUM_OUT_OF_MEMORY;
	}
	devicep = dev_getdp(medium_privatep->in_device);
	(void) snprintf(pathname_bufferp, MAXPATHLEN, "%s%s",
		vold_root, devicep->dp_path);
	raw_devicep = strstr(pathname_bufferp, "rdsk");
	if (raw_devicep != NULL) {
		raw_slice_path_length = strlen(pathname_bufferp);
		pathname_bufferp[raw_slice_path_length - 2] = NULLC;
		medium_privatep->raw_pathnamep = strdup(pathname_bufferp);
		if (medium_privatep->raw_pathnamep == NULL) {
			medium_result = MEDIUM_OUT_OF_MEMORY;
		} else {
			medium_result =
				create_block_pathname(
					medium_privatep->raw_pathnamep,
					&(medium_privatep->block_pathnamep));
		}
	} else {
		raw_devicep = strstr(pathname_bufferp, "rdiskette");
		if (raw_devicep != NULL) {
			medium_privatep->raw_pathnamep =
				strdup(pathname_bufferp);
			if (medium_privatep->raw_pathnamep == NULL) {
				medium_result = MEDIUM_OUT_OF_MEMORY;
			} else {
				medium_result =
					create_block_pathname(
						medium_privatep->raw_pathnamep,
						&(medium_privatep->
							block_pathnamep));
			}
		} else {
			/*
			 * The pathname is a test pathname of the
			 * form /vol/dev/voltestdrv/<number>, where
			 * <number> ranges from 1 through about 150.
			 */
			medium_privatep->raw_pathnamep =
				strdup(pathname_bufferp);
			medium_privatep->block_pathnamep =
				strdup(pathname_bufferp);
			if ((medium_privatep->raw_pathnamep == NULL) ||
				(medium_privatep->block_pathnamep == NULL)) {
				medium_result = MEDIUM_OUT_OF_MEMORY;
			}
		}
	}
	if (pathname_bufferp != NULL) {
		free(pathname_bufferp);
	}

	debug(8, "leaving create_pathnames(), result code = %s\n",
		medium_result_strings[medium_result]);

	return (medium_result);
}

static medium_result_t
create_symlink_directory(medium_private_t *medium_privatep)
{
	/*
	 * When the medium contains more than one file system,
	 * create a subdirectory of /vol/dev/aliases that will
	 * contain a symbolic link to each of the file systems.
	 * Store a pointer to the subdirectory in the dp_symvn
	 * attribute of the device object that models the device
	 * in which the medium is inserted.
	 */

	struct devs 		*devicep;
	char 			*device_symbolic_namep;
	medium_result_t		medium_result;

	medium_result = MEDIUM_SUCCESS;

	devicep = dev_getdp(medium_privatep->in_device);
	device_symbolic_namep = devicep->dp_symname;
	medium_privatep->symlink_dir_namep =
		malloc((size_t)
			(strlen(ALIAS_DIRECTORY_NAME) +
			    strlen("/") +
			    strlen(device_symbolic_namep) + 1));
	if (medium_privatep->symlink_dir_namep == NULL) {
		medium_result = MEDIUM_OUT_OF_MEMORY;
	} else {
		(void) strcpy(medium_privatep->symlink_dir_namep,
			ALIAS_DIRECTORY_NAME);
		(void) strcat(medium_privatep->symlink_dir_namep, "/");
		(void) strcat(medium_privatep->symlink_dir_namep,
			device_symbolic_namep);
		medium_privatep->symlink_dir_vvnodep =
			dev_dirpath(medium_privatep->symlink_dir_namep);
		devicep->dp_symvn = medium_privatep->symlink_dir_vvnodep;
	}
	return (medium_result);
}

static medium_result_t
get_permissions(medium_private_t *medium_privatep)
{
	permissions_t		permissions;
	medium_result_t		medium_result;
	smwp_state_t		wstate;
	smedia_handle_t		handle;

	debug(2, "entering get_permissions()\n");
	medium_result = MEDIUM_SUCCESS;
	handle = smedia_get_handle(medium_privatep->file_descriptor);
	if (handle == NULL) {
		debug(2, "rpc.smserverd is not responding\n");
		medium_result = MEDIUM_CANT_GET_ACCESS_MODE;
		return (medium_result);
	}

	if (smedia_get_protection_status(handle, &wstate) == -1) {
		debug(5, "Could not get protection status\n");
		permissions = READ_WRITE;
	} else {
		switch (wstate.sm_new_state) {
		case SM_UNPROTECTED:
			permissions = READ_WRITE;
			break;
		case SM_WRITE_PROTECTED:
			permissions = READ_ONLY;
			break;
		case SM_WRITE_PROTECTED_WP:
			permissions = PASSWORD_WRITE_PROTECTED;
			break;
		case SM_READ_WRITE_PROTECTED:
			permissions = PASSWORD_PROTECTED;
			break;
		case SM_STATUS_UNKNOWN:
			permissions = READ_WRITE;
			break;
		default:
			/* the device returned an unknown protection state */
			debug(5, "Invalid protection status returned\n");
			permissions = READ_WRITE;
		}
	}
	smedia_release_handle(handle);
	medium_privatep->permissions = permissions;

	debug(2, "leaving get_permissions(), result code = 0x%x\n",
	    permissions);
	return (medium_result);
}
