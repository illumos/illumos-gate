/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _MGMT_MMS_LIBRARY_H
#define	_MGMT_MMS_LIBRARY_H


/*
 * mgmt_library.h
 *
 * This header contains the definitions of a library and drives that are
 * controlled by the Solaris Media Management System
 *
 * This header includes functions such as
 * 1.	get library(s)
 * 2.	get drive(s) (by library)
 * 3.	add library
 * 4.	add drive to library
 * 5.	remove library
 * 6.	remove drive(s) from library
 * 7.	change library/drive state
 * 8.	get supported libraries and drives - To bo provided by MMS team
 *
 * mms_get_library(), mms_get drive(), mms_get_dm(), mms_get_lm()
 * mms_add_library(), mms_add_drive()
 * mms_del_library(), mms_del_drive(),
 * online/offline drive, online/offline DM
 */

#include <stdio.h>
#include <sys/nvpair.h>

#include "mms.h"
#include "mgmt_util.h"
#include "mgmt_acsls.h"

/*
 * The MMS implementation currently supports the StorageTek ACSLS network
 * attached libraries namely L180, L700 and L500, and the 9840, LTO1, LTO2,
 * LTO3 and DISK (disk archiving) drives.
 *
 * All definitions for a library are specific to the ACSLS library, for a
 * direct attached library, it is not clear as to what connection parameters
 * i.e. SCSI ID, device paths etc are required.
 *
 * TBD: The list of supported drive and library types should be maintained
 * in the MM.
 */

/* Structure to define an ACSLS-connected library in MMS */
typedef struct mms_acslib {
	mms_list_node_t	lib_link;
	char		name[MAXNAMELEN];	/* Type_SerialNumber */
	char		serialnum[MAXSERIALNUMLEN];
	char		type[32];
	char		acshost[MAXHOSTNAMELEN];
	uint32_t	acsport;
	uint32_t	flags;			/* state and status */
	uint32_t	acs;
	uint32_t	lsm;
	mms_list_t	drive_list;
	mms_list_t	lm_list;
} mms_acslib_t;

/*
 * The MMS defines a Library Manager(LM) to manage each Library object. While
 * the MMS spec supports a library to be managed by multiple LMs (without any
 * upper limit), multiple LMs are only required for switchover or failover
 * purposes. As such, for the first release of the MMS api, the hostname of
 * the LM is defaulted to the MM host.
 */

/* Structure to define the LMs in MMS */
typedef struct mms_lm {
	mms_list_node_t	lm_link;
	char		name[MAXNAMELEN];
	char		hostname[MAXHOSTNAMELEN];
	uint32_t	flags;
} mms_lm_t;

/* Structure to define the drive in MMS */
typedef struct mms_drive {
	mms_list_node_t	drive_link;
	char		name[MAXNAMELEN];	/* DRV_SerialNumber */
	char		serialnum[MAXSERIALNUMLEN];
	char		type[32];
	uint32_t	flags;			/* status, state */
	char		libname[MAXNAMELEN];
	int32_t		blocksize;
	int32_t		priority;
	mms_list_t	dm_list;
	mms_list_t	app_list;		/* application names */
	char		devpath[256];		/* drive /dev path */
	char		volid[64];		/* vol name in drive, if any */
	uint32_t	acs;
	uint32_t	lsm;
	uint32_t	panel;
	uint32_t	drive;
} mms_drive_t;

/* Flags (status/state) for a Drive */

/* drive is not supported by MMS */
#define	MMS_ST_DRIVE_UNSUPPORTED	0x00000001
/* drive is not configured in MM */
#define	MMS_ST_DRIVE_UNCONFIGURED	0x00000002
/* use of drive is suspended although it is configured and running */
#define	MMS_ST_DRIVE_DISABLED		0x00000004
#define	MMS_ST_DRIVE_BROKEN		0x00000008
#define	MMS_ST_DRIVE_INUSE		0x00000010
#define	MMS_ST_DRIVE_READY		0x00000020
#define	MMS_ST_DRIVE_LOADED		0x00000040
#define	MMS_ST_DRIVE_LOADING		0x00000080
#define	MMS_ST_DRIVE_UNLOADING		0x00000100
#define	MMS_ST_DRIVE_UNLOADED		0x00000200
/* LM cannot mount/unmount cartridges */
#define	MMS_ST_DRIVE_INACCESSIBLE	0x00000400
/* cartridge in drive */
#define	MMS_ST_DRIVE_OCCUPIED		0x00000800
/* Drive needs cleaning */
#define	MMS_ST_DRIVE_RCLEANING		0x00001000
/* Drive needs cleaning, but may still allow mounting of cartridges */
#define	MMS_ST_DRIVE_ACLEANING		0x00002000
/* Drive will not accept mounts until it is cleaned */
#define	MMS_ST_DRIVE_MCLEANING		0x00004000
#define	MMS_ST_DRIVE_OFFLINE		0x00008000

/* Structure to define the drive manager (DMs) in MMS */
typedef struct mms_dm {
	mms_list_node_t	dm_link;
	char		name[MAXNAMELEN];
	char		drivename[MAXNAMELEN];
	char		hostname[MAXHOSTNAMELEN];
	/* drivepath[MAXPATHLEN] not required, MM/DM will map serial number */
} mms_dm_t;

/*
 * The MM hostname, port number, application name, instance name, tag name and
 * the application password are not taken as input parameters for the library
 * related functions. Since there can be only one MM in a setup, it is better
 * to store these parameters in a config file or SMF and let the calling
 * function create the session first and pass the session as an input param
 *
 * All comunication with the MM requires an unique identifier to determine the
 * associated task. This tid is provided optinally as an input param
 *
 */

/*
 * The mms_get_library() function returns information about a library from
 * MM configuration.
 *
 * PARAM
 * session	- IN -
 * getdrives	- IN
 * lib_list	- OUT - A list of mms_acslib_t controlled by MMS
 *
 * RETURN
 * upon successful completion, a value of 0 is returned to indicate success and
 * lib_list is filled with a list of libraries
 * If the request cannot be completed, an appropriate error number is returned
 * to signify the error
 *
 * ERROR
 * internal processing errors from MM/LM/DM/API (!MMS_API_OK)
 * 		-- media manager is not found
 *		-- media manager is not running
 * 		-- unable to connect to the media manager
 * MMS_RESPONSE_ECANCELLED
 * MMS_RESPONSE_EUNKNOWN
 *
 */
int mms_get_library(void *session, boolean_t get_drives, mms_list_t *lib_list);


/*
 * The mms_get_lm() function returns information about the LM(s) for a
 * particular library
 *
 * PARAM
 * session	- IN -
 * libname	- IN - library name
 * lm_list	- OUT - A list of mms_lm_t controlled by MMS
 *
 * RETURN
 * upon successful completion, a value of 0 is returned to indicate success and
 * lm_list is filled with a list of LM
 * If the request cannot be completed, an appropriate error number is returned
 * to signify the error
 *
 * ERROR
 *
 */
int mms_get_lm(void *session, char *libname, mms_list_t *lm_list);


/*
 * The mms_get_drives_for_lib() function returns information about the
 * drives for a specific library in the MM configuration.
 *
 * PARAM
 * session	- IN -
 * libname	- IN - name of library
 * drive_list	- OUT - A list of sm_drive_t in the specified library.
 *
 * RETURN
 * upon successful completion, a value of 0 is returned to indicate success and
 * drive_list is filled with a list of drives
 * If the request cannot be completed, an appropriate error number is returned
 * to signify the error
 *
 * ERROR
 *
 */
int mms_get_drives_for_lib(void *session, char *libname,
    mms_list_t *drive_list);


/*
 * The mms_get_dm()  function returns information about the DM(s) for a
 * particular drive.
 *
 * PARAM
 * session	- IN -
 * drivename	- IN - name of a drive
 * dm_list	- OUT - A list of sm_dm_t for the given drive
 *
 * RETURN
 * upon successful completion, a value of 0 is returned to indicate success and
 * dm_list is filled with a list of DM
 * If the request cannot be completed, an appropriate error number is returned
 * to signify the error
 *
 * ERROR
 *
 */
int mms_get_dm(void *session, char *drivename, mms_list_t *dm_list);


/*
 * The mms_add_library() function is used to add a library to the MM
 * configuration. The following steps are taken:
 *
 * 1. A Library object is created and associated with its network IP (ACSLS)
 * 2. the Library object is associated with a Library Manager
 * 3. Default DriveGroups (if any) are created.
 * 4. Drive objects and their respective DMs are created
 * 5. Supported SLOTTYPE entries are created
 * 6. Supported CARTRIDGETYPE entries are created
 * 7. Default CartridgeGroups (if any) are created.
 * 8. Library and drives are brought online, unless otherwise requested
 *
 * PARAM
 * session	- IN -
 * lib		- IN - library attributes in an nvlist
 * errs		- IN - Processing errors in an nvlist
 * RETURN
 *
 * ERROR
 *
 * A library without drives is useless and so it is considered to be an
 * error to add a library without adding some/any of its drives.
 *
 * IMPLEMENTATION NOTES
 * 1. library name is derived from library type and serial number.
 * 2. If the library to be added already exists in the MMS configuration,
 * then a check is made to see if additional drives are to be added via this
 * operation. This request is not treated as an error condition.
 *
 * QUESTIONS
 * 1. How are partial failures to be handled? i.e. if there are 4 drives to be
 * added to MMS configuration and only 2 of them could be added?
 *
 *
 */
int mms_add_library(void *session, nvlist_t *lib, nvlist_t *errs);
int mms_create_library(void *session, nvlist_t *lib, nvlist_t *errs);


/*
 * This function is used to add drives to an existing library configuration
 *
 * PARAM
 *
 * RETURN
 */
int mms_add_drive(void *session, nvlist_t *nvl, nvlist_t *errs);

/*
 * The mms_remove_library() function is used to remove a library from the MM
 * configuration. The following steps are taken:
 *
 * 1. The volume(s) in that library are deleted
 * 2. Should the association between the CARTRIDGEGROUP and APPLICATION/INSTANCE
 * be deleted? (if there are no other libraries)
 * 3. If there are no more entries in the CARTRIDGEGROUP, should it be deleted?
 * 4. Should the corresponding SLOTTYPE and CARTRIDGETYPE entries be deleted?
 * 5. The drive(s) and their corresponding DM(s) are deleted
 * 6. Should the association between the DRIVEGROUP and APPLICATION/INSTANCE
 * be deleted?
 * 7. If there are no more entries in the DRIVEGROUP, should it be deleted?
 * 8. The LM associated with this library is deleted
 * 9. The library object is deleted
 *
 * PARAM
 * session	- IN -
 * libname	- IN - library name
 * RETURN
 */
int
mms_remove_library(void *session, nvlist_t *lib, nvlist_t *errs);

int
mms_remove_drive(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_modify_library(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_modify_drive(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mgmt_find_local_drives(nvlist_t **drv_list);

#endif /* _MGMT_MMS_LIBRARY_H */
