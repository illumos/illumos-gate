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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <libpq-fe.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_commands.h"
#include "mm_sql.h"
#include "mm_sql_impl.h"
#include "mm_task.h"
#include "mm_path.h"

static char *_SrcFile = __FILE__;

#define	SELECT_GETALL "select \"DriveName\" from "	\
	"getall('%s', '%s', '%s');"

#define	SELECT_LIB "select \"LibraryName\" from "	\
	"gettypename('%s', '%s');"

/* Unmount command states */
#define	UM_CANDIDATE_SELECTION 0
#define	UM_DM_DETACH 1
#define	UM_SCHEDULE_UNLOAD 2
#define	UM_DM_UNLOAD 3
#define	UM_DM_RELEASE 4
#define	UM_LM_UNMOUNT 5
#define	UM_FINAL 100

extern int mm_get_dest(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_get_source(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_get_const(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_add_match_list(char *str, mms_list_t *list);
extern void tm_be_cancel_all(mm_command_t *cmd);

void
mm_print_unmount_state(int state) {
	switch (state) {
	case UM_CANDIDATE_SELECTION:
		mms_trace(MMS_DEBUG,
		    "unmount candidate selection");
		return;
	case UM_DM_DETACH:
		mms_trace(MMS_DEBUG,
		    "add dm detach command");
		return;
	case UM_SCHEDULE_UNLOAD:
		mms_trace(MMS_DEBUG,
		    "schedule dm unload command");
		return;
	case UM_DM_UNLOAD:
		mms_trace(MMS_DEBUG,
		    "add dm unload command");
		return;
	case UM_DM_RELEASE:
		mms_trace(MMS_DEBUG,
		    "add dm release command");
		return;

	case UM_LM_UNMOUNT:
		mms_trace(MMS_DEBUG,
		    "add lm unmount command");
		return;

	case UM_FINAL:
		mms_trace(MMS_DEBUG,
		    "umount final commmand state");
		return;

	}
}

void
mm_print_mount_candidates(mm_command_t *cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	mms_trace(MMS_INFO, "Candidate Cartridges are :");
	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		if (cart->cmi_cart_not_ready) {
			mms_trace(MMS_INFO, "    Cartridge, %s, (not ready)",
			    cart->cmi_cart_id);
		} else {
			mms_trace(MMS_INFO, "    Cartridge, %s",
			    cart->cmi_cart_id);
		}
		if (cart->cmi_cart_pcl != NULL) {
			mms_trace(MMS_INFO, "      %s",
			    cart->cmi_cart_pcl);
		}
		mms_trace(MMS_INFO, "     Library, %s",
		    cart->cmi_library);
		mms_trace(MMS_INFO,
		    "     Drive Candidates:");
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			if (drive->cmi_mode_valid == 0) {
				mms_trace(MMS_INFO, "        %s"
				    "  * no DM configured *",
				    drive->cmi_drive_name);
			} else {
				if (drive->cmi_drive_not_ready) {
					mms_trace(MMS_INFO,
					    "        %s, (not ready)",
					    drive->cmi_drive_name);
				} else {
					mms_trace(MMS_INFO, "        %s",
					    drive->cmi_drive_name);
				}
			}
		}
	}
}
void
mm_print_accessmodes(mm_command_t *cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	cmi_mode_list_t		*mode = NULL;
	int			i;

	mms_trace(MMS_INFO, "Number of First Mount Tokens's is %d",
	    mount_info->cmi_num_firstmount);

	for (i = 0; i < mount_info->cmi_num_firstmount; i ++) {
		mms_trace(MMS_INFO, "  First Mount Token %d is %s", i,
		    mount_info->cmi_firstmount[i]);
	}
	mms_trace(MMS_INFO, "Total Number of Access Modes is %d",
	    mount_info->cmi_total_modes);
	mms_list_foreach(&mount_info->cmi_mode_list, mode) {
		for (i = 0;
		    i < mode->cmi_num_accessmode;
		    i ++) {
			mms_trace(MMS_INFO, "  Mode Token %d is %s", i,
			    mode->cmi_accessmode[i]);
		}
	}
}
void
mm_print_mount_summary(mm_wka_t *mm_wka, mm_command_t *cmd) {

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	cci_t			*conn = &mm_wka->wka_conn;

	/* Print mount information */
	if (mount_info->cmi_operation == MM_MOUNT) {
		mms_trace(MMS_INFO, "*** Mount Summary ***");
	} else {
		mms_trace(MMS_INFO, "*** UnMount Summary ***");
	}
	mms_trace(MMS_INFO, "Application is %s",
	    conn->cci_client);
	mms_trace(MMS_INFO, "Instance is %s",
	    conn->cci_instance);
	if (cmd->wka_ptr->wka_privilege == MM_PRIV_STANDARD) {
		mms_trace(MMS_INFO,
		    "Standard Privilege");
	} else {
		mms_trace(MMS_INFO,
		    "Privileged Client");
	}
	switch (mount_info->cmi_type) {
	case MM_SIDE:
		mms_trace(MMS_INFO, "    Type is SIDE");
		break;
	case MM_PARTITION:
		mms_trace(MMS_INFO, "    Type is PARTITION");
		break;
	case MM_VOLUME:
		mms_trace(MMS_INFO, "    Type is VOLUME");
		break;
	}
	switch (mount_info->cmi_when) {
	case MM_BLOCKING:
		mms_trace(MMS_INFO, "    When is 'blocking'");
		break;
	case MM_IMMEDIATE:
		mms_trace(MMS_INFO, "    When is 'immediate'");
		break;
	}

	if (mount_info->cmi_where)
		mms_trace(MMS_INFO,
		    "    Where is %s", mount_info->cmi_where);


	/* Print access modes */
	if (mount_info->cmi_operation == MM_MOUNT)
		mm_print_accessmodes(cmd);

	/* Print all the cartridge/library/drive information */
	mm_print_mount_candidates(cmd);
}

int
mm_check_drive(mm_wka_t *mm_wka, mm_command_t *cmd,
    cmi_drive_list_t *drive_struct,
    char *cart_id, char *dm_name, mm_db_t *db)
{
	/* Need to set cmd error buf for every return (0) */
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	cmi_mode_list_t		*mode;

	char			*cap_tokens = NULL;
	int			a_mode = 0;
	char			*drive = drive_struct->cmi_drive_name;

	/* Check if a DM is configured for this drive */
	if (mm_db_exec(HERE, db, "select * from \"DMCAPABILITYGROUP\" "
	    "where \"DriveName\" = '%s';", drive) != MM_DB_DATA) {
		mms_trace(MMS_ERR, "Error getting DMCAPABILITYGROUP");
		mm_sql_db_err_rsp_new(cmd, db);
		return (0);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		/* DM is not configured for this drive */
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    "EDRVNODMCONFIGURED",
		    MM_5035_MSG,
		    "dm",
		    dm_name,
		    "drive",
		    drive,
		    NULL);
		mm_clear_db(&db->mm_db_results);
		return (0);
	}
	mm_clear_db(&db->mm_db_results);

	/* Check the cartridge shape */
	if (mm_db_exec(HERE, db,
	    "select distinct * from drive_cart('%s', '%s');",
	    drive, cart_id) != MM_DB_DATA) {
		mms_trace(MMS_ERR, "Error checking drive shape");
		mm_sql_db_err_rsp_new(cmd, db);
		return (0);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		/* Drive does not support this cartridge shape */
		mms_trace(MMS_DEVP, "Drive does not support "\
		    "this cartridge shape, %s %s", drive, cart_id);
		mm_response_error(cmd,
		    ECLASS_COMPAT,
		    "ECARTDRVNOTCOMPATIBLE",
		    MM_5096_MSG,
		    "drive",
		    drive,
		    "cart",
		    cart_id,
		    NULL);
		mm_clear_db(&db->mm_db_results);
		return (0);
	}
	mm_clear_db(&db->mm_db_results);

	/* For each Access Mode, check if the drive supports it */
	mms_list_foreach(&mount_info->cmi_mode_list, mode) {
		mms_trace(MMS_DEVP,
		    "checking a mode");
		a_mode = 1;
		cap_tokens = (char *)mm_check_mode(mm_wka,
		    cmd, drive, mode,
		    cart_id, db);
		if (cap_tokens != NULL) {
			/* There is at least one supported mode */
			mms_trace(MMS_DEVP, "Good mode is %s",
			    cap_tokens);
			/* mode is ok */
			free(cap_tokens);
			return (1);
		}
	}
	if (a_mode) {
		/* there was at least 1 mode passed, */
		/* and none were not good, return error */
		if (cap_tokens != NULL) {
			free(cap_tokens);
		}
		mm_response_error(cmd,
		    ECLASS_COMPAT,
		    "ECARTDRVNOTCOMPATIBLE",
		    MM_5036_MSG,
		    "dm",
		    dm_name,
		    "drive",
		    drive,
		    NULL);
		return (0);
	}
	/* No modes exist, access is default */
	if (cap_tokens != NULL) {
		free(cap_tokens);
	}
	return (1);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}

#ifdef	MM_LIBRARY_DRIVE_HAS_PCL
static int
mm_library_drive_has_pcl(mm_command_t *cmd, char *library, char *drive,
    char *cart_pcl)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	int		 loaded;

	if (mm_db_exec(HERE, db, "select \"DriveName\" from \"DRIVE\" "
	    "where \"LibraryName\" = '%s' "
	    "and \"DriveName\" = '%s' "
	    "and \"CartridgePCL\" = '%s' "
	    "and \"DriveLibraryAccessible\" = 'true' "
	    "and \"DriveLibraryOccupied\" = 'true' "
	    "and \"DriveBroken\" = 'false' "
	    "and \"DriveDisabled\" = 'false';",
	    library, drive, cart_pcl) != MM_DB_DATA) {
		return (0);
	}
	loaded = (PQntuples(db->mm_db_results) != 1 ? 0 : 1);
	mm_clear_db(&db->mm_db_results);
	return (loaded);
}
#endif
int
mm_candidate_drive_ok(mm_wka_t *mm_wka,
    mm_command_t *cmd, mm_db_t *db,
    char *candidate_cartid,
    cmi_drive_list_t *drive) {

	/* Determines if the candidate drive */
	/* is available as a candidate */
	char			*candidate_drive = drive->cmi_drive_name;
	char			*candidate_dm = drive->cmi_dm_name;

	cci_t			*conn = &mm_wka->wka_conn;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	mm_dm_stat_t		*dm_stat = NULL;
	mm_drive_stat_t		*drive_stat = NULL;

	int			rc;
	mms_trace(MMS_DEVP, "mm_candidate_drive_ok");
	if ((drive_stat = mm_get_drive_status(candidate_drive, db)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error getting drive information, "
		    "drive %s",
		    candidate_drive);
		mm_system_error(cmd,
		    "failed to get drive information");
		rc = 0; goto end;
	}

	/* For mounts we know drive and host, for umounts we know dm */
	/* Use the approperate call to getdmstatus */
	if (mount_info->cmi_operation == MM_MOUNT) {
		if ((dm_stat = mm_get_dm_status(NULL, candidate_drive,
		    mount_info->cmi_where, db)) == NULL) {
			mms_trace(MMS_ERR,
			    "Error getting dm information, "
			    "drive %s",
			    candidate_drive);
			mm_system_error(cmd,
			    "failed to get dm information");
			rc = 0; goto end;
		}
	} else {
		mms_trace(MMS_DEVP,
		    "cmi_dm_name/candidate_dm == %s",
		    candidate_dm);
		if ((dm_stat = mm_get_dm_status(candidate_dm, NULL,
		    NULL, db)) == NULL) {
			mms_trace(MMS_ERR,
			    "Error getting dm information, "
			    "drive %s",
			    candidate_drive);
			mm_system_error(cmd,
			    "failed to get dm information");
			rc = 0; goto end;
		}
	}

	mm_print_drive_status(drive_stat);


	mm_print_dm_status(dm_stat);

	/* The order of check is the order errors get returned */
	/* check higher level problems before lower level */
	/* ie. online, diabled first */

	/* Exclusive access check */
	if (strcmp(drive_stat->drive_stat_excl_app, "none") != 0) {
		if (strcmp(conn->cci_client,
		    drive_stat->drive_stat_excl_app) != 0) {
			mms_trace(MMS_DEVP,
			    "%s exclusive app is not clients app,"
			    " ExclusiveAppName != %s or none",
			    candidate_drive,
			    conn->cci_client);
			mm_response_error(cmd,
			    ECLASS_EXPLICIT,
			    "EAPPDRVNOACC",
			    MM_5027_MSG,
			    "app", conn->cci_client,
			    "drive", candidate_drive,
			    NULL);
			rc = 0; goto end;
		}
	}

	/* DRIVEGROUPAPPLICATION check */
	if (cmd->wka_ptr->wka_privilege == MM_PRIV_STANDARD) {
		mms_trace(MMS_DEVP,
		    "Non-privileged client, "
		    "checking Drive Access");
		/* standard priv, check drive group access */
		if (mm_db_exec(HERE, db,
		    "select \"DRIVEGROUPAPPLICATION\".\"ApplicationName\" "
		    "from \"DRIVEGROUPAPPLICATION\" "
		    "where \"DriveGroupName\" = '%s' and "
		    "\"ApplicationName\" = '%s';",
		    drive_stat->drive_stat_group,
		    conn->cci_client) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "Error getting drive group information, "
			    "drive %s, db trans failed",
			    candidate_drive);
			mm_sql_db_err_rsp_new(cmd, db);
			rc = 0; goto end;
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "%s does not have "
			    "access to drive group %s",
			    conn->cci_client,
			    drive_stat->drive_stat_group);
			mm_response_error(cmd,
			    ECLASS_EXPLICIT,
			    "EAPPDRVNOACC",
			    MM_5030_MSG,
			    "app", conn->cci_client,
			    "drive", candidate_drive,
			    NULL);
			mm_clear_db(&db->mm_db_results);
			rc = 0; goto end;
		}
		mm_clear_db(&db->mm_db_results);
	} else {
		mms_trace(MMS_DEVP,
		    "Privileged Client, "
		    "skip Drive Access check");
	}


	/* Online check */
	if ((strcmp(drive_stat->drive_stat_online, "false") == 0) ||
	    (strcmp(drive_stat->drive_stat_online, "f") == 0)) {
		mms_trace(MMS_DEVP,
		    "%s is not online",
		    candidate_drive);
		mm_response_error(cmd,
		    ECLASS_PERMPRIV,
		    "EDRIVEOFFLINE",
		    MM_5029_MSG,
		    "drive", candidate_drive,
		    NULL);
		rc = 0; goto end;
	}

	/* Drive In use */
	if ((mount_info->cmi_operation == MM_MOUNT) &&
	    (strcmp(drive_stat->drive_stat_soft, "ready") != 0)) {
		mms_trace(MMS_DEVP,
		    "%s is not ready,"
		    " DriveStateSoft != ready ",
		    candidate_drive);
		drive->cmi_drive_not_ready = 1;
		mm_response_error(cmd,
		    ECLASS_RETRY,
		    "EDRVINUSE",
		    MM_5025_MSG,
		    "drive", candidate_drive,
		    NULL);
		mm_set_retry_drive(cmd,
		    candidate_drive);
		if (mount_info->cmi_when == MM_IMMEDIATE) {
			rc = 0; goto end;
		} else {
			mms_trace(MMS_DEVP,
			    "drive in use, keep as"
			    " candidate for blocking mounts");
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "EDRVINUSE",
			    MM_5025_MSG,
			    "drive", candidate_drive,
			    NULL);
			mm_set_retry_drive(cmd,
			    candidate_drive);
		}
		/* Keep this drive as a candidate for blocking mounts */

	}

	if ((mount_info->cmi_operation == MM_MOUNT) &&
	    ((strcmp(drive_stat->drive_stat_hard, "loaded") == 0) ||
	    (strcmp(drive_stat->drive_stat_drvlib_occ, "true") == 0) ||
	    (strcmp(drive_stat->drive_stat_drvlib_occ, "t") == 0))) {
		/* Find this drive's delayed unload and set to dispatch */
		mms_trace(MMS_DEVP,
		    "drive is loaded with %s, need to unload",
		    drive_stat->drive_stat_pcl);

		if ((strcmp(drive_stat->drive_stat_hard, "unloading") == 0) ||
		    (strcmp(drive_stat->drive_stat_hard, "loading") == 0)) {
			/* This drive is in the process of unloading */
			mms_trace(MMS_DEVP,
			    "This drive is in the process of "
			    "unloading/loading");
			drive->cmi_drive_not_ready = 1;
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "EDRVUNLOADING",
			    MM_5102_MSG,
			    "drive", candidate_drive,
			    NULL);
			mm_set_retry_drive(cmd,
			    candidate_drive);
			if (mount_info->cmi_when == MM_IMMEDIATE) {
				rc = 0; goto end;
			}
		} else {
			drive->cmi_drive_loaded = 1;
			drive->cmi_loaded_pcl = NULL;
			drive->cmi_loaded_pcl = mms_strapp(drive->
			    cmi_loaded_pcl,
			    drive_stat->drive_stat_pcl);
			if (strcmp(MM_NON_MMS_CART,
			    drive_stat->drive_stat_pcl) == 0) {
				drive->cmi_drive_not_ready = 1;
				mms_trace(MMS_DEVP,
				    "drive is loaded with a non-mms tape");
				mm_response_error(cmd,
				    ECLASS_RETRY,
				    "EDRVINUSE",
				    MM_5028_MSG,
				    "drive", candidate_drive,
				    NULL);
				mm_set_retry_drive(cmd,
				    candidate_drive);
				if (mount_info->cmi_when == MM_IMMEDIATE) {
					rc = 0; goto end;
				}
			}
		}
	}

	if (mount_info->cmi_operation == MM_UNMOUNT) {
		if ((strcmp(drive_stat->drive_stat_hard, "loaded") != 0) ||
		    (strcmp(drive_stat->drive_stat_drvlib_occ, "t") != 0)) {
			mms_trace(MMS_DEVP,
			    "%s not loaded/occupied with tape, "
			    "but has MOUNTPHYSICAL",
			    candidate_drive);
			mm_system_error(cmd,
			    "drive with MOUNTPHYSICAL not "
			    "loaded/occupied with tape");
			rc = 0; goto end;
		}
	}


	/* Drive disabled */
	if ((strcmp(drive_stat->drive_stat_disabled, "true") == 0) ||
	    (strcmp(drive_stat->drive_stat_disabled, "t") == 0)) {
		mms_trace(MMS_DEVP,
		    "%s is disabled",
		    candidate_drive);
		if (strcmp(drive_stat->drive_stat_disabled,
		    "temporary") == 0) {
			mm_response_error(cmd,
			    ECLASS_PERMPRIV,
			    "EDRVDISABLEDTEMP",
			    MM_5022_MSG,
			    "drive", candidate_drive,
			    NULL);

		} else {
			mm_response_error(cmd,
			    ECLASS_PERMPRIV,
			    "EDRVDISABLEDPERM",
			    MM_5023_MSG,
			    "drive", candidate_drive,
			    NULL);
		}
		rc = 0; goto end;
	}
	/* Drive Broken */
	if ((strcmp(drive_stat->drive_stat_broken, "true") == 0) ||
	    (strcmp(drive_stat->drive_stat_broken, "t") == 0)) {
		mms_trace(MMS_DEVP,
		    "%s is broken",
		    candidate_drive);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    "EDRVBROKEN",
		    MM_5024_MSG,
		    "drive", candidate_drive,
		    NULL);
		rc = 0; goto end;
	}

	/* Drive is library accessible */
	if ((strcmp(drive_stat->drive_stat_lib_acc, "false") == 0) ||
	    (strcmp(drive_stat->drive_stat_lib_acc, "f") == 0)) {
		mms_trace(MMS_DEVP,
		    "%s is not accessible",
		    candidate_drive);
		mm_response_error(cmd,
		    ECLASS_INTERNAL,
		    "ELMDRVNOTACCESS",
		    MM_5026_MSG,
		    "drive", candidate_drive,
		    NULL);
		rc = 0; goto end;
	}

	/* DM Status Checks */
	if (strcmp(dm_stat->dm_stat_soft, "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "DM for %s is not ready,"
		    " DMStateSoft != ready ",
		    candidate_drive);

		if (strcmp(dm_stat->dm_stat_soft,
		    "absent") == 0) {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "EDMNOTCONNECTED",
			    MM_5032_MSG,
			    "dm",
			    dm_stat->dm_stat_name,
			    "drive",
			    candidate_drive,
			    NULL);
			rc = 0; goto end;
		} else if (strcmp(dm_stat->dm_stat_soft,
		    "disconnected") == 0) {
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    "EDRVBROKEN",
			    MM_5033_MSG,
			    "dm",
			    dm_stat->dm_stat_name,
			    "drive",
			    candidate_drive,
			    NULL);
			mm_set_retry_drive(cmd,
			    candidate_drive);
			rc = 0; goto end;
		} else if (strcmp(dm_stat->dm_stat_soft,
		    "not ready") == 0) {
			/* drive is not ready for blocked */
			drive->cmi_drive_not_ready = 1;
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "EDMSTILLBOOTING",
			    MM_5034_MSG,
			    "dm",
			    dm_stat->dm_stat_name,
			    "drive",
			    candidate_drive,
			    NULL);
			if (mount_info->cmi_when == MM_IMMEDIATE) {
				rc = 0; goto end;
			}
		} else if (strcmp(dm_stat->dm_stat_soft,
		    "present") == 0) {
			/* drive is not ready for blocked */
			drive->cmi_drive_not_ready = 1;
				mm_response_error(cmd,
				    ECLASS_CONFIG,
				    "EDRVNODMCONFIGURED",
				    MM_5034_MSG,
				    "dm",
				    dm_stat->dm_stat_name,
				    "drive",
				    candidate_drive,
				    NULL);
				mm_set_retry_drive(cmd,
				    candidate_drive);
			if (mount_info->cmi_when == MM_IMMEDIATE) {
				rc = 0; goto end;
			}
		} else if ((mount_info->cmi_operation == MM_MOUNT) &&
		    (strcmp(dm_stat->dm_stat_soft,
		    "reserved") == 0)) {
			/* drive is not ready for blocked */
			drive->cmi_drive_not_ready = 1;
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "EDRVINUSE",
			    MM_5098_MSG,
			    "dm",
			    dm_stat->dm_stat_name,
			    NULL);
			mm_set_retry_drive(cmd,
			    candidate_drive);
			if (mount_info->cmi_when == MM_IMMEDIATE) {
				rc = 0; goto end;
			}
		}
	} else if (mount_info->cmi_operation == MM_UNMOUNT) {
		/* Unmount, and DM is ready */
		mms_trace(MMS_DEVP,
		    "%s is in incorrect state for unmount",
		    dm_stat->dm_stat_name);
		mm_system_error(cmd,
		    "DM is in incorrect state for unmount");
		rc = 0; goto end;
	}

	if (strcmp(dm_stat->dm_stat_hard, "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "DM for %s is not ready,"
		    " DMStateHard != ready ",
		    candidate_drive);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    "EDRVBROKEN",
		    MM_5031_MSG,
		    "drive",
		    candidate_drive,
		    "dm",
		    dm_stat->dm_stat_name,
		    NULL);
		rc = 0; goto end;
	}
	if (mount_info->cmi_operation == MM_UNMOUNT) {
		mms_trace(MMS_DEVP,
		    "Drive/DM Status ok for unmounts");
		rc = 1; goto end;
	}


	mms_trace(MMS_DEVP,
	    "DM Status ok, check DM accessmodes DM, %s",
	    dm_stat->dm_stat_name);

	if (mm_check_drive(mm_wka, cmd,
	    drive,
	    candidate_cartid,
	    dm_stat->dm_stat_name,
	    db) == 1) {
		/* DM supports the access modes */
		mms_trace(MMS_DEVP,
		    "DM configured for at least 1 access mode");
	} else {
		mms_trace(MMS_DEVP,
		    "DM not configured to support the access mode");
		/* Error buf should be set by check drive */
		rc = 0; goto end;
	}


	rc = 1; goto end;

end:
	mm_free_drive_status(drive_stat);
	mm_free_dm_status(dm_stat);
	return (rc);
}

int
mm_candidate_cartridge_ok(mm_wka_t *mm_wka,
    mm_command_t *cmd, mm_db_t *db,
    cmi_cart_list_t *cart_struct) {

	uuid_text_t		*candidate_cartid = &cart_struct->cmi_cart_id;

	cci_t			*conn = &mm_wka->wka_conn;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	PGresult		*cart = NULL;
	PGresult		*volume = NULL;
	PGresult		*slot = NULL;

	int			rc;
	mms_trace(MMS_DEVP, "mm_candidate_cartridge_ok");
	if (mm_db_exec(HERE, db,
	    "select "
	    "\"CARTRIDGE\".\"CartridgeState\", "
	    "\"CARTRIDGE\".\"CartridgeStatus\", "
	    "\"CARTRIDGE\".\"CartridgeGroupName\", "
	    "\"CARTRIDGE\".\"CartridgeDriveOccupied\" "
	    "from \"CARTRIDGE\" "
	    "where \"CartridgeID\" = '%s';",
	    candidate_cartid) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "Error getting cartridge information, "
		    "cartridge, %s, db trans failed",
		    candidate_cartid);
		mm_sql_db_err_rsp_new(cmd, db);
		rc = 0; goto end;
	}
	cart = db->mm_db_results;
	if (PQntuples(cart) != 1) {
		mms_trace(MMS_ERR,
		    "Error getting cartridge information, "
		    "cartridge, %s, db results != 1",
		    candidate_cartid);
		mm_system_error(cmd,
		    "row number mismatch getting "
		    "cartridge information");
		rc = 0; goto end;
	}
	mms_trace(MMS_DEVP,
	    "Cartridge Status for Cartridge, %s",
	    candidate_cartid);
	mms_trace(MMS_DEVP,
	    "    CartridgeState = %s",
	    PQgetvalue(cart, 0, 0));
	mms_trace(MMS_DEVP,
	    "    CartridgeStatus = %s",
	    PQgetvalue(cart, 0, 1));
	mms_trace(MMS_DEVP,
	    "    CartridgeGroup = %s",
	    PQgetvalue(cart, 0, 2));
	mms_trace(MMS_DEVP,
	    "    CartridgeDriveOccupied = %s",
	    PQgetvalue(cart, 0, 3));

	/* Ignore this attribute for now */
	/*
	 * if (strcmp(PQgetvalue(cart, 0, 0), "defined") != 0) {
	 *
	 * }
	 */

	if ((mount_info->cmi_operation == MM_MOUNT) &&
	    (strcmp(PQgetvalue(cart, 0, 1), "available") != 0)) {
		mms_trace(MMS_DEVP,
		    "%s is in use,"
		    " CartridgeStatus != available ",
		    candidate_cartid);
		if (strcmp(PQgetvalue(cart, 0, 1),
		    "unavailable") == 0) {
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    "ECARTNOTLOCATED",
			    MM_5037_MSG,
			    "cart",
			    candidate_cartid,
			    NULL);
			rc = 0; goto end;
		}
		/* mark this cartridge not ready */
		/* for blocked mounts */
		cart_struct->cmi_cart_not_ready = 1;
		/* State is 'in use' */
		mm_response_error(cmd,
		    ECLASS_RETRY,
		    "ECARTINUSE",
		    MM_5038_MSG,
		    "cart",
		    candidate_cartid,
		    NULL);
		mm_set_retry_cart(cmd,
		    (char *)candidate_cartid);
		if (mount_info->cmi_when == MM_IMMEDIATE) {
			rc = 0; goto end;
		}
	}
	if ((mount_info->cmi_operation == MM_UNMOUNT) &&
	    (strcmp(PQgetvalue(cart, 0, 1), "in use") != 0)) {
		mms_trace(MMS_DEVP,
		    "%s is not in use,"
		    " CartridgeStatus != in use ",
		    candidate_cartid);
		mm_system_error(cmd,
		    "cartridge status is not in use");
		rc = 0; goto end;
	}

	/* Check if this CARTRIDGE has a SLOT created for it */
	if (mm_db_exec(HERE, db,
	    "select \"SlotName\" "
	    "from \"SLOT\" "
	    "where \"CartridgeID\" = '%s';",
	    candidate_cartid) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "Error getting slot info, "
		    "cartridge, %s, db trans failed",
		    candidate_cartid);
		mm_sql_db_err_rsp_new(cmd, db);
		rc = 0; goto end;
	}
	slot = db->mm_db_results;
	if (PQntuples(slot) == 0) {
		mms_trace(MMS_DEVP,
		    "no slot found for cartridge, %s",
		    candidate_cartid);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    "ENOSLOT",
		    MM_5095_MSG,
		    "cart",
		    candidate_cartid,
		    NULL);
		rc = 0; goto end;
	}


	if (mount_info->cmi_operation == MM_UNMOUNT) {
		/* skip volume check */
		/* This cart already has mapped to mount physical */
		mms_trace(MMS_DEVP,
		    "skip vol check for unmount");
		rc = 1; goto end;
	}


	/* Get VOLUME information */
	mms_trace(MMS_DEVP,
	    "Checking for Volumes");
	if (mm_db_exec(HERE, db,
	    "select \"ApplicationName\" "
	    "from \"VOLUME\" where "
	    "\"CartridgeID\" = '%s' and "
	    "\"ApplicationName\" = '%s';",
	    candidate_cartid,
	    conn->cci_client) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "Error getting volume information, "
		    "cartridge, %s, db trans failed",
		    candidate_cartid);
		mm_sql_db_err_rsp_new(cmd, db);
		rc = 0; goto end;
	}
	volume = db->mm_db_results;
	if (PQntuples(volume) == 0) {
		mms_trace(MMS_DEVP,
		    "%s doesn't have a volume "
		    "on cartridge, %s",
		    conn->cci_client,
		    candidate_cartid);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    "EAPPHASNOVOLS",
		    MM_5040_MSG,
		    "app",
		    conn->cci_client,
		    "cart",
		    candidate_cartid,
		    NULL);
		rc = 0; goto end;
	}


	rc = 1; goto end;

end:
	if (cart != NULL) {
		mm_clear_db(&cart);
	}
	if (volume != NULL) {
		mm_clear_db(&volume);
	}
	if (slot != NULL) {
		mm_clear_db(&slot);
	}
	return (rc);

}


int
mm_candidate_library_ok(mm_command_t *cmd, mm_db_t *db,
    char *candidate_library) {

	/* Determines if the candidate library */
	/* is available as a candidate */

	mm_lm_stat_t		*lm_stat = NULL;
	mm_lib_stat_t		*lib_stat = NULL;

	int			rc;
	mms_trace(MMS_DEVP, "mm_candidate_library_ok");
	if ((lib_stat = mm_get_library_status(candidate_library, db)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error getting library information, "
		    "library %s",
		    candidate_library);
		mm_system_error(cmd,
		    "failed to get library "
		    "information from database");
		rc = 0; goto end;
	}

	mm_print_library_status(lib_stat);

	if ((strcmp(lib_stat->lib_stat_online, "false") == 0) ||
	    (strcmp(lib_stat->lib_stat_online, "f") == 0)) {
		mms_trace(MMS_DEVP,
		    "%s is not online",
		    candidate_library);
		mm_response_error(cmd,
		    ECLASS_PERMPRIV,
		    "ELIBRARYOFFLINE",
		    MM_5041_MSG,
		    "lib",
		    candidate_library,
		    NULL);
		rc = 0; goto end;
	}
	if ((strcmp(lib_stat->lib_stat_disabled, "true") == 0) ||
	    (strcmp(lib_stat->lib_stat_disabled, "t") == 0)) {
		mms_trace(MMS_DEVP,
		    "%s is disabled",
		    candidate_library);
		if (strcmp(lib_stat->lib_stat_disabled,
		    "temporary") == 0) {
			mm_response_error(cmd,
			    ECLASS_PERMPRIV,
			    "ELIBDISABLEDTEMP",
			    MM_5042_MSG,
			    "lib",
			    candidate_library,
			    NULL);
		} else {
			mm_response_error(cmd,
			    ECLASS_PERMPRIV,
			    "ELIBDISABLEDPERM",
			    MM_5043_MSG,
			    "lib",
			    candidate_library,
			    NULL);
		}
		rc = 0; goto end;
	}
	if ((strcmp(lib_stat->lib_stat_broken, "true") == 0) ||
	    (strcmp(lib_stat->lib_stat_broken, "t") == 0)) {
		mms_trace(MMS_DEVP,
		    "%s is broken",
		    candidate_library);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    "ELIBBROKEN",
		    MM_5044_MSG,
		    "lib",
		    candidate_library,
		    NULL);
		rc = 0; goto end;
	}
	mms_trace(MMS_DEVP,
	    "Library status ok, check LM");

	/* Library is online and ready, get LM status */

	if ((lm_stat = mm_get_lm_status(lib_stat->lib_stat_lm,
	    db)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error getting lm information, "
		    "library %s",
		    candidate_library);
		mm_system_error(cmd,
		    "failed to get lm information");
		rc = 0; goto end;
	}

	mm_print_lm_status(lm_stat);

	if (strcmp(lm_stat->lm_stat_hard, "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "%s is not ready,"
		    " LMStateHard != ready ",
		    lib_stat->lib_stat_lm);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    "ELIBBROKEN",
		    MM_5045_MSG,
		    "lm",
		    lib_stat->lib_stat_lm,
		    NULL);
		rc = 0; goto end;
	}
	if (strcmp(lm_stat->lm_stat_soft, "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "%s is not ready,"
		    " LMStateSoft != ready ",
		    lib_stat->lib_stat_lm);
		if (strcmp(lm_stat->lm_stat_soft,
		    "absent") == 0) {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "ELMNOTCONNECTED",
			    MM_5046_MSG,
			    "lm",
			    lib_stat->lib_stat_lm,
			    "lib",
			    lib_stat->lib_stat_name,
			    NULL);
			mm_set_retry_lib(cmd,
			    candidate_library);
		}
		if (strcmp(lm_stat->lm_stat_soft,
		    "present") == 0) {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "ELMNOTREADY",
			    MM_5047_MSG,
			    "lm",
			    lib_stat->lib_stat_lm,
			    "lib",
			    lib_stat->lib_stat_name,
			    NULL);
			mm_set_retry_lib(cmd,
			    candidate_library);
		}
		if (strcmp(lm_stat->lm_stat_soft,
		    "disconnected") == 0) {
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    "ELIBBROKEN",
			    MM_5048_MSG,
			    "lm",
			    lib_stat->lib_stat_lm,
			    "lib",
			    lib_stat->lib_stat_name,
			    NULL);

		}
		if (strcmp(lm_stat->lm_stat_soft,
		    "not ready") == 0) {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    "ELMSTILLBOOTING",
			    MM_5049_MSG,
			    "lm",
			    lib_stat->lib_stat_lm,
			    "lib",
			    lib_stat->lib_stat_name,
			    NULL);
			mm_set_retry_lib(cmd,
			    candidate_library);
		}
		rc = 0; goto end;
	}
	mms_trace(MMS_DEVP,
	    "LM status ok");

	rc = 1; goto end;

end:
	mm_free_library_status(lib_stat);
	mm_free_lm_status(lm_stat);
	return (rc);

}


int
mm_insert_next_drive(mms_list_t *drive_list, cmi_drive_list_t  *drive_struct) {

	/*
	 * This will insert the drive_struct into its
	 * proper place in drive_list
	 *
	 * the drives are inserted in order of drive_priority
	 * check the dm shape and dm density priority to
	 * arrange the drives within each drive priority group
	 */

	cmi_drive_list_t		*drive;
	cmi_drive_list_t		*next_drive;

	int				drv_priority;
	int				dm_shape_priority;
	int				dm_density_priority;

	int				cur_drv_priority;
	int				cur_shape_priority;
	int				cur_density_priority;

	int				next_drv_priority;

	int				a_drive = 0;

	drv_priority = drive_struct->cmi_drv_priority;
	dm_shape_priority = drive_struct->cmi_dm_shape_priority;
	dm_density_priority = drive_struct->cmi_dm_density_priority;

	for (drive = mms_list_head(drive_list);
	    drive != NULL;
	    drive = next_drive) {
		a_drive = 1;
		next_drive =
		    mms_list_next(drive_list,
		    drive);
		cur_drv_priority = drive->cmi_drv_priority;
		cur_shape_priority = drive->cmi_dm_shape_priority;
		cur_density_priority = drive->cmi_dm_density_priority;

		if (cur_drv_priority != drv_priority) {
			/* go to the next drive */
			continue;
		}
		if (cur_shape_priority > dm_shape_priority) {
			/* Insert before cur */
			mms_list_insert_before(drive_list, drive, drive_struct);
			return (0);
		}
		if ((cur_shape_priority == dm_shape_priority) &&
		    (cur_density_priority > dm_density_priority)) {
			/* Insert before cur */
			mms_list_insert_before(drive_list, drive, drive_struct);
			return (0);
		}
		if (next_drive == NULL) {
			mms_list_insert_after(drive_list, drive, drive_struct);
			return (0);
		}
		next_drv_priority = next_drive->cmi_drv_priority;
		if (next_drv_priority != drv_priority) {
			mms_list_insert_after(drive_list, drive, drive_struct);
			return (0);
		}
	}
	mms_list_insert_tail(drive_list,
	    drive_struct);
	return (a_drive);
}

cmi_drive_list_t *
mm_setup_drive_unmount(mm_command_t *cmd,
    mm_db_t *db,
    cmi_cart_list_t *cart,
    PGresult *drive_results,
    int drive_row) {

	cmi_drive_list_t	*drive = NULL;

	PGresult		*dm;
	char			*dm_name = NULL;

	char *candidate_drive = PQgetvalue(drive_results, drive_row, 0);

	mms_trace(MMS_DEVP, "mm_setup_drive_unmount");

	if (mm_db_exec(HERE, db,
	    "select \"DMName\""
	    " from \"DRIVE\" where "
	    "\"DriveName\" = '%s';",
	    candidate_drive) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "Error getting dm information");
		mm_sql_db_err_rsp_new(cmd, db);
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		mms_trace(MMS_ERR,
		    "Coudn't find DRIVE for "
		    "this drive, %s",
		    candidate_drive);
		mm_system_error(cmd,
		    "missing DRIVE obj during unmount");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	dm = db->mm_db_results;
	dm_name = PQgetvalue(dm, 0, 0);

	drive = NULL;
	drive = (cmi_drive_list_t *)
	    calloc(1,
	    sizeof (cmi_drive_list_t));
	if (drive == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc"\
		    " cmi_drive_list: %s",
		    strerror(errno));
		mm_system_error(cmd,
		    "unable to allocate mem for drive stat");
		mm_clear_db(&dm);
		return (NULL);
	}
	drive->cmi_drive_name =
	    strdup(candidate_drive);
	drive->cmi_mode_valid = 1;
	drive->cmi_drive_not_ready = 0;
	drive->cmi_drive_used = 0;

	drive->cmi_dm_name = mms_strapp(drive->cmi_dm_name, dm_name);
	drive->cmi_dm_shape_priority = 0;
	drive->cmi_dm_density_priority = 0;
	/* Column references must match what is in mm_mount_init_candidates */
	drive->cmi_drv_priority = atoi(PQgetvalue(drive_results,
	    drive_row, 2));
	drive->cmi_drv_num_mounts = atoi(PQgetvalue(drive_results,
	    drive_row, 3));
	mms_list_insert_tail(&cart->cmi_drive_list,
	    drive);
	mm_clear_db(&dm);
	return (drive);


}

cmi_drive_list_t *
mm_setup_drive(mm_command_t *cmd,
    mm_db_t *db,
    cmi_cart_list_t *cart,
    PGresult *drive_results,
    int drive_row) {

	/* drive_results is created in mm_init_candidates */

	cmi_drive_list_t	*drive = NULL;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	PGresult		*dm_shape;
	int			dm_shape_priority;
	int			dm_density_priority;
	PGresult		*dm;
	char			*dm_name = NULL;
	char			*cart_type = cart->cmi_cart_type;
	char			*bit_format = cart->cmi_bit_format;
	int			drive_not_ready;
	int			i;

	char			*candidate_drive = PQgetvalue(drive_results,
	    drive_row, 0);

	char			*cur_dm_shape;
	char			*cur_dm_shape_priority;
	char			*cur_dm_density;
	char			*cur_dm_density_priority;

	/* get the dm name */
	/* get name by host */
	if (mm_db_exec(HERE, db,
	    "select \"DMName\""
	    " from \"DM\" where "
	    "\"DriveName\" = '%s' "
	    "and pg_host_ident("
	    "\"DMTargetHost\") "
	    "= pg_host_ident('%s');",
	    candidate_drive,
	    mount_info->cmi_where) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "Error getting dm information");
		mm_sql_db_err_rsp_new(cmd, db);
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		mms_trace(MMS_ERR,
		    "No dm configured for "
		    "this drive, on host %s",
		    mount_info->cmi_where);
		mm_response_error(cmd,
		    ECLASS_COMPAT,
		    "EAPPDMDIFFHOSTS",
		    MM_5050_MSG,
		    "host",
		    mount_info->cmi_where,
		    NULL);
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	dm = db->mm_db_results;
	dm_name = PQgetvalue(dm, 0, 0);
	/* Check the cartridge shape */
	if (mm_db_exec(HERE, db,
	    "select \"DMSHAPEPRIORITY\".\"DMName\", "
	    "\"DMSHAPEPRIORITY\".\"DMShapeName\","
	    "\"DMSHAPEPRIORITY\".\"DMShapePriority\","
	    "\"DMDENSITYPRIORITY\".\"DMDensityName\","
	    "\"DMDENSITYPRIORITY\".\"DMDensityPriority\" from "
	    "\"DMSHAPEPRIORITY\",\"DMDENSITYPRIORITY\""
	    "where "
	    "\"DMSHAPEPRIORITY\".\"DMName\" = '%s' and "
	    "\"DMDENSITYPRIORITY\".\"DMName\" = '%s';",
	    dm_name,
	    dm_name) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "Error checking cartridge shape");
		mm_sql_db_err_rsp_new(cmd, db);
		mm_clear_db(&dm);
		return (NULL);
	}
	drive_not_ready = 0;
	if (PQntuples(db->mm_db_results) == 0) {
		/* This will be an error for immediate mounts */
		/* for blocking keep drive, and set drive_not_ready */
		mms_trace(MMS_ERR,
		    "dm has not been configured for this drive");
		drive_not_ready = 1;

	}
	dm_shape = db->mm_db_results;
	dm_shape_priority = -1;
	/* Default density is 1 */
	dm_density_priority = 1;

	for (i = 0; i < PQntuples(dm_shape); i++) {
		cur_dm_shape = PQgetvalue(dm_shape, i, 1);
		cur_dm_shape_priority = PQgetvalue(dm_shape, i, 2);
		cur_dm_density = PQgetvalue(dm_shape, i, 3);
		cur_dm_density_priority = PQgetvalue(dm_shape, i, 4);
		if (strcmp(cart_type, cur_dm_shape) == 0) {
			dm_shape_priority = atoi(cur_dm_shape_priority);
		}
		if (strcmp(bit_format, cur_dm_density) == 0) {
			dm_density_priority = atoi(cur_dm_density_priority);
		}
	}
	if ((dm_shape_priority == -1) &&
	    (drive_not_ready != 1)) {
		/* Drive has configed dm, but slot does not match */
		/* Didn't find this dm_shape */
		mms_trace(MMS_ERR,
		    "dm is not configured for this slot type");
		mm_response_error(cmd,
		    ECLASS_COMPAT,
		    "ECARTDRVSLOTMISMATCH",
		    MM_5097_MSG,
		    NULL);
		mm_clear_db(&dm);
		mm_clear_db(&dm_shape);
		return (NULL);
	}

	mm_clear_db(&dm_shape);

	drive = NULL;
	drive = (cmi_drive_list_t *)
	    calloc(1,
	    sizeof (cmi_drive_list_t));
	if (drive == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc"\
		    " cmi_drive_list: %s",
		    strerror(errno));
		mm_system_error(cmd,
		    "unable to allocate mem for drive stat");
		mm_clear_db(&dm);
		return (NULL);
	}
	drive->cmi_drive_name =
	    strdup(candidate_drive);
	drive->cmi_mode_valid = 1;
	drive->cmi_drive_not_ready = drive_not_ready;
	drive->cmi_drive_used = 0;

	drive->cmi_dm_name =
	    strdup(PQgetvalue(dm,
	    0, 0));
	drive->cmi_dm_shape_priority = dm_shape_priority;
	drive->cmi_dm_density_priority = dm_density_priority;
	/* Column references must match what is in mm_mount_init_candidates */
	drive->cmi_drv_priority = atoi(PQgetvalue(drive_results,
	    drive_row, 2));
	drive->cmi_drv_num_mounts = atoi(PQgetvalue(drive_results,
	    drive_row, 3));


	/* Insert Drives into the correct place in the list here */
	/* Drives are already orderd by priority and number mounts */
	/* Enforce shape and density priority here */
	/* Go down the drive list and find where this */
	/* drive's pritoriy group starts */
	/* Then insert the current drive according to dm_shape_priority */
	/* Maintain the original ordering within like prioritys */
	if (mm_insert_next_drive(&cart->cmi_drive_list,
	    drive)) {
		mms_trace(MMS_ERR,
		    "error inserting drive into list");
		mm_free_cmi_drive(drive);
		drive = NULL;
	}
	mm_clear_db(&dm);
	return (drive);
}

cmi_cart_list_t *
mm_setup_cart(mm_command_t *cmd,
    mm_db_t *db,
    PGresult *cart_results,
    int row_number) {

	cmi_cart_list_t		*cart = NULL;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	/* Column references must match what is in mm_mount_cart_results */
	char *candidate_cartid = PQgetvalue(cart_results, row_number, 0);
	char *candidate_library = PQgetvalue(cart_results, row_number, 1);
	char *candidate_priority = PQgetvalue(cart_results, row_number, 2);
	char *candidate_num_mounts = PQgetvalue(cart_results, row_number, 3);
	char *cart_type = PQgetvalue(cart_results, row_number, 4);
	char *cart_pcl = PQgetvalue(cart_results, row_number, 5);
	char *cart_loaded = PQgetvalue(cart_results, row_number, 6);

	PGresult *partition_results;
	char *bit_format = NULL;

	/* Get PARTITION."PartitionBitFormat" */
	if (mm_db_exec(HERE, db,
	    "select \"PARTITION\".\"PartitionBitFormat\" "
	    "from \"PARTITION\" where \"CartridgeID\" = '%s';",
	    candidate_cartid) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mms_trace(MMS_ERR,
		    "db error getting PartitionBitFormat");
		return (NULL);
	}
	partition_results = db->mm_db_results;
	if (PQntuples(partition_results) == 0) {
		mms_trace(MMS_ERR,
		    "couldn't find PARTITION for %s",
		    candidate_cartid);
		mm_system_error(cmd,
		    "couldn't find PARTITION");
		mm_clear_db(&partition_results);
		return (NULL);
	}
	bit_format = PQgetvalue(db->mm_db_results, 0, 0);


	cart = (cmi_cart_list_t *)
	    calloc(1, sizeof (cmi_cart_list_t));
	if (cart == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc cmi_cart_list: %s",
		    strerror(errno));
		mm_system_error(cmd,
		    "unable to allocate mem for drive list");
		mm_clear_db(&partition_results);
		return (NULL);
	}
	mms_list_create(&cart->cmi_drive_list,
	    sizeof (cmi_drive_list_t),
	    offsetof(cmi_drive_list_t,
	    cmi_drive_next));

	strcpy(cart->cmi_cart_id, candidate_cartid);
	cart->cmi_library = NULL;
	cart->cmi_library = mms_strapp(cart->cmi_library,
	    candidate_library);
	cart->cmi_cart_pcl = mms_strapp(cart->cmi_cart_pcl,
	    cart_pcl);
	cart->cmi_cart_type = mms_strapp(cart->cmi_cart_type,
	    cart_type);
	cart->cmi_bit_format = mms_strapp(cart->cmi_bit_format,
	    bit_format);

	cart->cmi_cart_not_ready = 0;
	cart->cmi_cart_used = 0;

	cart->cmi_cart_priority = atoi(candidate_priority);
	cart->cmi_cart_num_mounts = atoi(candidate_num_mounts);
	if ((strcmp(cart_loaded, "true") == 0) ||
	    (strcmp(cart_loaded, "t") == 0)) {
		cart->cmi_cart_loaded = 1;
	} else {
		cart->cmi_cart_loaded = 0;
	}

	mms_list_insert_tail(&mount_info->cmi_cart_list,
	    cart);

	mm_clear_db(&partition_results);
	return (cart);
}

int
mm_mount_candidate_loaded(mm_command_t *cmd) {

	/*
	 * this function needs to determine if a candidate
	 * cartridge is already loaded into a candidate drive.
	 * If there is, it must set the mount_info
	 * for the cart/lib/drive/dm
	 */

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*cur_pcl = NULL;
	char			*cur_cartid = NULL;
	char			*cur_library = NULL;
	char			*cur_dm = NULL;
	char			*cur_drive = NULL;

	char			*drive_pcl = NULL;

	mms_trace(MMS_DEVP,
	    "mm_mount_candidate_loaded: ");

	mount_info->cmi_mount_cart_loaded = 0;

	/* The list should already be ordered */
	/* select the 1st available */
	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		cur_pcl = cart->cmi_cart_pcl;
		cur_library = cart->cmi_library;
		cur_cartid = cart->cmi_cart_id;
		/* The list should already be ordered */
		/* select the 1st available */
		if (cart->cmi_cart_not_ready ||
		    cart->cmi_cart_used) {
			continue;
		}
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			if (drive->cmi_drive_not_ready ||
			    drive->cmi_drive_used) {
				continue;
			}
			if (drive->cmi_drive_loaded) {
				drive_pcl = drive->cmi_loaded_pcl;
				cur_drive = drive->cmi_drive_name;
				cur_dm = drive->cmi_dm_name;
				if (strcmp(cur_pcl, drive_pcl) == 0) {
					/* set this mount info and return */
					mm_set_mount_info_cart(cur_cartid,
					    mount_info);
					mm_set_mount_info_drive(cur_drive,
					    mount_info);
					mm_set_mount_info_dm(cur_dm,
					    mount_info);
					mm_set_mount_info_library(cur_library,
					    mount_info);
					mount_info->cmi_mount_cart_loaded = 1;
					return (1);
				}
			}
		}
	}
	return (0);

}
int
mm_mount_open_drive(mm_command_t *cmd) {
	/*
	 * this function needs to determine if there is an
	 * open drive for a candidate cartridge
	 * If there is, it must set the mount_info
	 * for the cart/lib/drive/dm
	 */
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*cur_cartid = NULL;
	char			*cur_library = NULL;
	char			*cur_dm = NULL;
	char			*cur_drive = NULL;

	mms_trace(MMS_DEVP,
	    "mm_mount_open_drive: ");

	/* The list should already be ordered */
	/* select the 1st available */
	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		if (cart->cmi_cart_not_ready ||
		    cart->cmi_cart_used) {
			continue;
		}
		cur_library = cart->cmi_library;
		cur_cartid = cart->cmi_cart_id;
		/* only look at non loaded carts */
		if (cart->cmi_cart_loaded) {
			continue;
		}
		/* The list should already be ordered */
		/* select the 1st available */
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			if (drive->cmi_drive_not_ready ||
			    drive->cmi_drive_used) {
				continue;
			}
			/* only look at non-loaded drives */
			if (drive->cmi_drive_loaded) {
				continue;
			}
			cur_drive = drive->cmi_drive_name;
			cur_dm = drive->cmi_dm_name;
			/* set this mount info and return */
			mm_set_mount_info_cart(cur_cartid,
			    mount_info);
			mm_set_mount_info_drive(cur_drive,
			    mount_info);
			mm_set_mount_info_dm(cur_dm,
			    mount_info);
			mm_set_mount_info_library(cur_library,
			    mount_info);
			return (1);
		}
	}
	return (0);

}

int
mm_unmount_2_drive(mm_command_t *cmd, mm_db_t *db) {
	/* check if a loaded candidate cartridge */
	/* must be mounted in a drive loaded with a non-candidate */
	/* need unmount candidate drive and candidate cart */
	/* then mount */

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*cur_cartid = NULL;
	char			*cur_pcl = NULL;
	char			*cur_library = NULL;
	char			*cur_dm = NULL;
	char			*cur_drive = NULL;

	mms_trace(MMS_DEVP,
	    "mm_unmount_2_drive: ");

	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		if (cart->cmi_cart_not_ready ||
		    cart->cmi_cart_used) {
			continue;
		}
		cur_library = cart->cmi_library;
		cur_cartid = cart->cmi_cart_id;
		cur_pcl = cart->cmi_cart_pcl;
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			if (drive->cmi_drive_not_ready ||
			    drive->cmi_drive_used) {
				continue;
			}
			cur_drive = drive->cmi_drive_name;
			cur_dm = drive->cmi_dm_name;
			if (cart->cmi_cart_loaded &&
			    drive->cmi_drive_loaded) {
				if (mm_db_exec(HERE, db,
				    "select \"LibraryName\",\"DriveName\" "
				    "from \"DRIVE\" where \"DRIVE\"."
				    "\"CartridgePCL\" = '%s' and "
				    "\"DRIVE\".\"DriveName\" = '%s';",
				    cur_pcl, cur_drive) != MM_DB_DATA) {
					mms_trace(MMS_ERR,
					    "mm_unmount_2_drive:"
					    " db error reading data");
					mm_clear_db(&db->mm_db_results);
					continue;
				}

				if (PQntuples(db->mm_db_results) == 0) {
					/* Cur cart is not loaded */
					mms_trace(MMS_ERR,
					    "%s not found in drive %s",
					    cur_pcl, cur_drive);
					mm_clear_db(&db->mm_db_results);
					continue;
				}

				mm_set_mount_info_cart(cur_cartid,
				    mount_info);
				mm_set_mount_info_drive(cur_drive,
				    mount_info);
				mm_set_mount_info_dm(cur_dm,
				    mount_info);
				mm_set_mount_info_library(cur_library,
				    mount_info);
				mms_trace(MMS_DEVP,
				    "** 2 Unmount Summary **");
				mms_trace(MMS_DEVP,
				    "1st unmount %s %s",
				    cur_library,
				    cur_drive);
				mms_trace(MMS_DEVP,
				    "2nd unmount %s %s",
				    PQgetvalue(db->mm_db_results, 0, 0),
				    PQgetvalue(db->mm_db_results, 0, 1));

				mount_info->cmi_first_lib =
				    strdup(cur_library);
				mount_info->cmi_first_drive =
				    strdup(cur_drive);
				mount_info->cmi_second_lib =
				    strdup(PQgetvalue(db->mm_db_results, 0, 0));
				mount_info->cmi_second_drive =
				    strdup(PQgetvalue(db->mm_db_results, 0, 1));


				mm_clear_db(&db->mm_db_results);
				return (1);
			}
		}
	}
	return (0);

}

int
mm_mount_loaded_drive(mm_command_t *cmd, mm_db_t *db,
    char **drive_to_unload, char **lib_to_unload) {
	/*
	 * this function needs to determine if a candidate
	 * cartridge must be mounted on a drive already loaded
	 * with a non-candidate cartridge that needs to be unmounted
	 * OR
	 * If a candidate cartridge is loaded in a non-candidate drive
	 * that 1st must be unmounted
	 * If there is, it must set the mount_info
	 * for the cart/lib/drive/dm
	 */
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*cur_cartid = NULL;
	char			*cur_pcl = NULL;
	char			*cur_library = NULL;
	char			*cur_dm = NULL;
	char			*cur_drive = NULL;

	mms_trace(MMS_DEVP,
	    "mm_mount_loaded_drive: ");

	/* The list should already be ordered */
	/* select the 1st available */
	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		if (cart->cmi_cart_not_ready ||
		    cart->cmi_cart_used) {
			continue;
		}
		cur_library = cart->cmi_library;
		cur_cartid = cart->cmi_cart_id;
		cur_pcl = cart->cmi_cart_pcl;

		/* If the cartridge is not mounted */

		/* The list should already be ordered */
		/* select the 1st available */

		mms_list_foreach(&cart->cmi_drive_list, drive) {
			if (drive->cmi_drive_not_ready ||
			    drive->cmi_drive_used) {
				continue;
			}
			cur_drive = drive->cmi_drive_name;
			cur_dm = drive->cmi_dm_name;

			if (cart->cmi_cart_loaded &&
			    (drive->cmi_drive_loaded == 0)) {
				/* Candidate is loaded and drive is empty */

				/* this candidate cart is loaded in a drive */
				/* Get the lib/drive name where */
				/* this cartridge is mounted */
				if (mm_db_exec(HERE, db,
				    "select \"LibraryName\",\"DriveName\" "
				    "from \"DRIVE\" where \"DRIVE\"."
				    "\"CartridgePCL\" = '%s';",
				    cur_pcl) != MM_DB_DATA) {
					mms_trace(MMS_ERR,
					    "mm_mount_loaded_drive: "
					    "db error getting data");
					continue;
				}

				if (PQntuples(db->mm_db_results) == 0) {
					/* Cur cart is not loaded */
					mms_trace(MMS_ERR,
					    "%s not found in a drive",
					    cur_pcl);
					mm_clear_db(&db->mm_db_results);
					continue;
				} else {
					/* cur cart is loaded */
					*(drive_to_unload) =
					    mms_strapp(*(drive_to_unload),
					    PQgetvalue(db->mm_db_results,
					    0, 1));
					*(lib_to_unload) =
					    mms_strapp(*(lib_to_unload),
					    PQgetvalue(db->mm_db_results,
					    0, 0));
					mms_trace(MMS_DEVP,
					    "%s loaded in %s %s",
					    cur_pcl,
					    PQgetvalue(db->mm_db_results,
					    0, 0),
					    PQgetvalue(db->mm_db_results,
					    0, 1));
				}
				mm_clear_db(&db->mm_db_results);

				mm_set_mount_info_cart(cur_cartid,
				    mount_info);
				mm_set_mount_info_drive(cur_drive,
				    mount_info);
				mm_set_mount_info_dm(cur_dm,
				    mount_info);
				mm_set_mount_info_library(cur_library,
				    mount_info);
				return (1);

			} else if ((cart->cmi_cart_loaded == 0) &&
			    (drive->cmi_drive_loaded == 1)) {

				/* set this mount info and return */
				*(drive_to_unload) = NULL;
				*(lib_to_unload) = NULL;
				mm_set_mount_info_cart(cur_cartid,
				    mount_info);
				mm_set_mount_info_drive(cur_drive,
				    mount_info);
				mm_set_mount_info_dm(cur_dm,
				    mount_info);
				mm_set_mount_info_library(cur_library,
				    mount_info);
				return (1);
			}
		}
	}
	return (0);
}

int
mm_set_immediate_unmount(mm_command_t *cmd, mm_db_t *db) {

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*cur_cartid = NULL;
	char			*cur_library = NULL;
	char			*cur_dm = NULL;
	char			*cur_drive = NULL;


	int			rc = MM_CMD_DONE;


	/* The list should already be ordered */
	/* select the 1st available */

	cart = mms_list_head(&mount_info->cmi_cart_list);
	if (cart == NULL) {
		mms_trace(MMS_ERR,
		    "internal error setting cmi info, "
		    "cannot find candidate carts structfound");
		mm_system_error(cmd,
		    "internal error setting cmi info, "
		    "no candidate carts found");
		return (MM_CMD_ERROR);
	}
	cur_library = cart->cmi_library;
	cur_cartid = cart->cmi_cart_id;

	drive = mms_list_head(&cart->cmi_drive_list);
	if (drive == NULL) {
		mms_trace(MMS_ERR,
		    "internal error setting cmi info, "
		    "no candidate drives found");
		mm_system_error(cmd,
		    "internal error setting cmi info, "
		    "no candidate drives found");
		return (MM_CMD_ERROR);
	}

	cur_drive = drive->cmi_drive_name;
	cur_dm = drive->cmi_dm_name;


	mm_set_mount_info_cart(cur_cartid,
	    mount_info);
	mm_set_mount_info_drive(cur_drive,
	    mount_info);
	mm_set_mount_info_dm(cur_dm,
	    mount_info);
	mm_set_mount_info_library(cur_library,
	    mount_info);
	if (mount_info->cmi_pcl == NULL) {
		mount_info->cmi_pcl =
		    mm_get_cart_pcl(cmd, mount_info->cmi_cartridge, db);
	}
	/* Select Is done - print the results */
	mms_trace(MMS_DEVP, "Cart/Lib/Drive selection "
	    "complete for task %s",
	    cmd->cmd_uuid);
	mms_trace(MMS_DEVP, "Cartridge ID is %s",
	    mount_info->cmi_cartridge);
	mms_trace(MMS_DEVP, "Cartridge PCL is %s",
	    mount_info->cmi_pcl);
	mms_trace(MMS_DEVP, "Library is %s",
	    mount_info->cmi_library);
	mms_trace(MMS_DEVP, "Drive is %s",
	    mount_info->cmi_drive);
	mms_trace(MMS_DEVP, "DM is %s",
	    mount_info->cmi_dm);

	if (mm_db_exec(HERE, db, "delete from \"TASK\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error removing TASK");
	}

	if (mm_new_tm_task(db, cmd, "dispatched") != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error creating TASK");
	}

	/* Delete all old TASK objects and create them anew */
	if (mm_db_exec(HERE, db, "delete from \"TASKDRIVE\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error removing TASKDRIVE");
	}
	if (mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error removing TASKLIBRARY");
	}
	if (mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error removing TASKCARTRIDGE");
	}


	if (mm_set_tm_drive(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error setting TASKDRIVE");
	}
	if (mm_set_tm_library(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_library) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error setting TASKLIBRARY");
	}

	if (mm_set_tm_cartridge(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_cartridge) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error setting TASKCARTRIDGE");
	}

	if (mm_db_exec(HERE, db, "update \"DRIVE\""
	    "set \"DriveStateSoft\" = 'in use'"
	    "where \"DriveName\" = '%s';",
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error setting DriveStateSoft");
	}
	if (mm_db_exec(HERE, db, "update \"DRIVE\""
	    "set \"DMName\" = '%s' "
	    "where \"DriveName\" = '%s';",
	    mount_info->cmi_dm,
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error setting DMName");
	}

	if (mm_db_exec(HERE, db,
	    "update \"CARTRIDGE\" set "
	    "\"CartridgeStatus\" = 'in use' "
	    "where \"CartridgeID\" = '%s';",
	    mount_info->cmi_cartridge) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_unmount: "
		    "db error setting CartridgeStatus");
	}


	return (rc);

}
void
mm_set_mount_objs(mm_command_t *cmd, mm_db_t *db) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;



	if (mm_db_exec(HERE, db, "delete from \"TASK\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error deleting TASK");
	}

	/* Delete all old TASK objects and create them anew */
	if (mm_db_exec(HERE, db, "delete from \"TASKDRIVE\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error deleting TASKDRIVE");
	}
	if (mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error deleting TASKLIBRARY");
	}
	if (mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error deleting TASKCARTRIDGE");
	}

	if ((mount_info->cmi_drive == NULL) ||
	    (mount_info->cmi_library == NULL) ||
	    (mount_info->cmi_cartridge == NULL) ||
	    (mount_info->cmi_dm == NULL)) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "mount info incomplete");
		mm_system_error(cmd,
		    "internal error setting task info, "
		    "mount info incomplete");
		return;
	}

	if (mm_new_tm_task(db, cmd, "dispatched") != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error inserting TASK");
	}

	if (mm_set_tm_drive(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error inserting TASKDRIVE");
	}
	if (mm_set_tm_library(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_library) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error inserting TASKLIBRARY");
	}
	if (mm_set_tm_cartridge(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_cartridge) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error inserting TASKCARTRIDGE");
	}

	if (mm_db_exec(HERE, db, "update \"DRIVE\""
	    "set \"DriveStateSoft\" = 'in use'"
	    "where \"DriveName\" = '%s';",
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error updating DriveStateSoft");
	}
	if (mm_db_exec(HERE, db, "update \"DRIVE\""
	    "set \"DMName\" = '%s' "
	    "where \"DriveName\" = '%s';",
	    mount_info->cmi_dm,
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error updating DMName");
	}

	if (mm_db_exec(HERE, db,
	    "update \"CARTRIDGE\" set "
	    "\"CartridgeStatus\" = 'in use' "
	    "where \"CartridgeID\" = '%s';",
	    mount_info->cmi_cartridge) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_mount_objs: "
		    "db error updating CartridgeStatus");
	}

}

int
mm_dispatch_now(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	mm_command_t		*unmnt_cmd_1 = NULL;
	mm_command_t		*unmnt_cmd_2 = NULL;

	/* This function is used to setup the command */
	/* flags and depend pointers for the mount */

	/* Need to set error message in this function */
	if (mount_info->cmi_mount_type ==
	    MM_CANDIDATE_LOADED) {
		mms_trace(MMS_DEVP,
		    "MM_CANDIDATE_LOADED");
		/* Remove the delay unload command */
		(void) mm_remove_unload(mount_info->cmi_library,
		    mount_info->cmi_drive,
		    mm_wka->mm_data);
		return (0);
	}
	if (mount_info->cmi_mount_type ==
	    MM_OPEN_DRIVE) {
		mms_trace(MMS_DEVP,
		    "MM_OPEN_DRIVE");
		return (0);
	}
	if (mount_info->cmi_mount_type ==
	    MM_UNMOUNT_DRIVE) {
		mms_trace(MMS_DEVP,
		    "MM_UNMOUNT_DRIVE");
		/* Set the delay unload for immdiate dispatch */
		if (mm_dispatch_unload(mount_info->cmi_library,
		    mount_info->cmi_drive,
		    cmd,
		    mm_wka->mm_data) == NULL) {
			/* Instead of return error */
			/* attempt to fix by adding a clear_drive */
			/* for this drive, set this */
			/* command as parent of */
			/* the clear drive */
			mms_trace(MMS_ERR,
			    "could not find delay unload, "
			    "attempt to clear and continue");
			if (mm_add_clear_drive(mount_info->cmi_drive,
			    mm_wka->mm_data,
			    db, cmd, NULL, 1, 0) == NULL) {
				mm_system_error(cmd,
				    "error adding clear drive cmd");
				return (1);
			}
		}
		MM_UNSET_FLAG(cmd->cmd_flags, MM_CMD_DISPATCHABLE);
		return (0);
	}
	if (mount_info->cmi_mount_type ==
	    MM_UNMOUNT_CART) {
		mms_trace(MMS_DEVP,
		    "MM_UNMOUNT_CART");
		/* Set the delay unload for immdiate dispatch */
		if (mm_dispatch_unload(mount_info->
		    cmi_first_lib,
		    mount_info->cmi_first_drive,
		    cmd,
		    mm_wka->mm_data) == NULL) {
			/* Instead of return error */
			/* attempt to fix by adding a clear_drive */
			/* for this drive, set this */
			/* command as parent of */
			/* the clear drive */
			mms_trace(MMS_ERR,
			    "could not find delay unload, "
			    "attempt to clear and continue");
			if (mm_add_clear_drive(mount_info->
			    cmi_first_drive,
			    mm_wka->mm_data,
			    db, cmd, NULL, 1, 0) == NULL) {
				mm_system_error(cmd,
				    "error adding clear drive cmd");
				return (1);
			}
		}
		MM_UNSET_FLAG(cmd->cmd_flags, MM_CMD_DISPATCHABLE);
		return (0);
	}
	if (mount_info->cmi_mount_type ==
	    MM_UNMOUNT_2) {
		mms_trace(MMS_DEVP,
		    "MM_UNMOUNT_2");
		if ((unmnt_cmd_1 =
		    mm_dispatch_unload(mount_info->cmi_first_lib,
		    mount_info->cmi_first_drive,
		    NULL,
		    mm_wka->mm_data)) == NULL) {
			mms_trace(MMS_ERR,
			    "error finding unmount command");

			if ((unmnt_cmd_1 =
			    mm_add_clear_drive(mount_info->cmi_first_drive,
			    mm_wka->mm_data,
			    db, cmd, NULL, 1, 0)) == NULL) {
				mm_system_error(cmd,
				    "error adding clear drive cmd");
				return (1);
			}
		}

		if ((unmnt_cmd_2 =
		    mm_return_unload(mount_info->cmi_second_lib,
		    mount_info->cmi_second_drive,
		    mm_wka->mm_data)) == NULL) {
			mms_trace(MMS_ERR,
			    "error finding unmount command");
			if ((unmnt_cmd_2 =
			    mm_add_clear_drive(mount_info->cmi_second_drive,
			    mm_wka->mm_data,
			    db, cmd, NULL, 1, 0)) == NULL) {
				mm_system_error(cmd,
				    "error adding clear drive cmd");
				return (1);
			}
		}
		mm_add_depend(unmnt_cmd_1, unmnt_cmd_2);
		mm_add_depend(unmnt_cmd_2, cmd);
		MM_SET_FLAG(unmnt_cmd_1->cmd_flags,
		    MM_CMD_DISPATCHABLE);
		MM_UNSET_FLAG(unmnt_cmd_2->cmd_flags,
		    MM_CMD_DISPATCHABLE);
		MM_UNSET_FLAG(cmd->cmd_flags,
		    MM_CMD_DISPATCHABLE);
		return (0);
	}
	mm_system_error(cmd,
	    "encountered unknown mount type");
	return (1);

}

int
mm_set_immediate_mount(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	int			rc = MM_CMD_DONE;

	char			*drive_to_unload = NULL;
	char			*lib_to_unload = NULL;

	mms_trace(MMS_DEVP, "mm_set_immediate_mount");

	/* select the exact cart/drive/dm/lib combination */

	/* Every candidate is currently in a ready state */
	/* Drives may be loaded with a cartridge */
	/* Cartridge could be: */
	/* a. a non-candidate cartridge */
	/* b. a candidate cartridge */

	/* If a candidate drive has a candidate loaded, use that now */
	/* If their are no candidate cartridge's loaded, */
	/* try to find an open drive */
	/* If there are no open drives, use a drive loaded */
	/* with a non-candidate cartridge */

	if (mm_mount_candidate_loaded(cmd)) {
		/* 0 mount time */
		mms_trace(MMS_DEVP,
		    "a candidate cartridge is loaded");
		mount_info->cmi_mount_type =
		    MM_CANDIDATE_LOADED;
	} else if (mm_mount_open_drive(cmd)) {
		/* 1 mount time */
		mms_trace(MMS_DEVP,
		    "open drive found");
		mount_info->cmi_mount_type =
		    MM_OPEN_DRIVE;
	} else if (mm_mount_loaded_drive(cmd, db, &drive_to_unload,
	    &lib_to_unload)) {
		/* 2 mount time */
		/* these mounts need an unmount, then mount */
		if (drive_to_unload == NULL &&
		    lib_to_unload == NULL) {
			mount_info->cmi_mount_type =
			    MM_UNMOUNT_DRIVE;
			mms_trace(MMS_DEVP,
			    "drive loaded with non-candidate "
			    "must unload 1st");
			/* Need to set up parent command */
			/* return as dispatch depend */
			mms_trace(MMS_DEVP,
			    "%s needs unload to complete first",
			    mount_info->cmi_drive);
			MM_UNSET_FLAG(cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
			rc = MM_DISPATCH_DEPEND;
		} else {
			mms_trace(MMS_DEVP,
			    "candidate loaded in non-candidate drive "
			    "must unload 1st");
			mount_info->cmi_mount_type =
			    MM_UNMOUNT_CART;
			mount_info->cmi_first_drive =
			    strdup(drive_to_unload);
			mount_info->cmi_first_lib =
			    strdup(lib_to_unload);

			/* Need to set up parent command */
			/* return as dispatch depend */
			mms_trace(MMS_DEVP,
			    "%s needs unload to complete first",
			    drive_to_unload);
			MM_UNSET_FLAG(cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
			rc = MM_DISPATCH_DEPEND;
			free(drive_to_unload);
			free(lib_to_unload);
		}

	} else if (mm_unmount_2_drive(cmd, db)) {
		mount_info->cmi_mount_type =
		    MM_UNMOUNT_2;
		/* 3 mount time  */
		/* Candidate cart is mounted, */
		/* the only candidate drive is loaded with non-candidate */
		/* need to unmount candidate cart, unmount candidate drive */
		/* then mount candidate cart/drive */
		MM_UNSET_FLAG(cmd->cmd_flags, MM_CMD_DISPATCHABLE);
		rc = MM_DISPATCH_DEPEND;
	} else {

		/* should never reach herer */
		mms_trace(MMS_ERR,
		    "MMS_ERROR - no drives found");
		mm_system_error(cmd,
		    "internal error, "
		    "could not find ready drive, "
		    "submitt a bug if you hit this!,"
		    "MM internal states out of sync");
		mms_trace(MMS_INFO, "mm_set_immediate_mount: "
		    "returning MM_RESYNC");
		return (MM_RESYNC);

	}

	if (mount_info->cmi_pcl == NULL) {
		mount_info->cmi_pcl =
		    mm_get_cart_pcl(cmd, mount_info->cmi_cartridge, db);
	}

	/*  call function to kick off delay unmounts */

	if (mm_dispatch_now(mm_wka, cmd, db)) {
		/* error should be set */
		mms_trace(MMS_ERR,
		    "error setting up mount for dispatch");
		return (MM_CMD_ERROR);
	}

	/* Select Is done - print the results */
	mms_trace(MMS_DEVP, "Cart/Lib/Drive selection "
	    "complete for task %s",
	    cmd->cmd_uuid);
	mms_trace(MMS_DEVP, "Cartridge ID is %s",
	    mount_info->cmi_cartridge);
	mms_trace(MMS_DEVP, "Cartridge PCL is %s",
	    mount_info->cmi_pcl);
	mms_trace(MMS_DEVP, "Library is %s",
	    mount_info->cmi_library);
	mms_trace(MMS_DEVP, "Drive is %s",
	    mount_info->cmi_drive);
	mms_trace(MMS_DEVP, "DM is %s",
	    mount_info->cmi_dm);

	if (mm_db_exec(HERE, db, "delete from \"TASK\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error removing TASK");
	}

	if (mm_new_tm_task(db, cmd, "dispatched") != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error creating TASK");
	}

	/* Delete all old TASK objects and create them anew */
	if (mm_db_exec(HERE, db, "delete from \"TASKDRIVE\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error removing TASKDRIVE");
	}
	if (mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error removing TASKLIBRARY");
	}
	if (mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\" "
	    "where \"TaskID\" = '%s';",
	    cmd->cmd_uuid) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error removing TASKCARTRIDGE");
	}


	if (mm_set_tm_drive(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error creating TASKDRIVE");
	}
	if (mm_set_tm_library(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_library) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error creating TASKLIBRARY");
	}
	if (mm_set_tm_cartridge(db,
	    cmd->cmd_uuid,
	    mount_info->cmi_cartridge) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error creating TASKCARTRIDGE");
	}

	if (mm_db_exec(HERE, db, "update \"DRIVE\""	\
	    "set \"DriveStateSoft\" = 'in use'"	\
	    "where \"DriveName\" = '%s';",
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error updating DriveStateSoft");
	}
	if (mm_db_exec(HERE, db, "update \"DRIVE\""\
	    "set \"DMName\" = '%s' "\
	    "where \"DriveName\" = '%s';",
	    mount_info->cmi_dm,
	    mount_info->cmi_drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error updating DMName");
	}
	if (mm_db_exec(HERE, db,
	    "update \"CARTRIDGE\" set "
	    "\"CartridgeStatus\" = 'in use' "
	    "where \"CartridgeID\" = '%s';",
	    mount_info->cmi_cartridge) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_set_immediate_mount: "
		    "db error updating CartridgeStatus");
	}


	return (rc);


}


int
mm_parse_mount_cmd(mm_wka_t *mm_wka, mm_command_t *cmd) {

	cci_t			*conn = &mm_wka->wka_conn;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	mms_par_node_t		*arg;
	mms_par_node_t		*value;
	mms_par_node_t		*work = NULL;
	mms_par_node_t		*item = NULL;
	int			go;
	int			count;

	char			*dm_host;

	cmi_mode_list_t		*mode = NULL;

	mms_trace(MMS_DEVP, "mm_parse_mount_cmd");
	mount_info->cmi_operation = MM_MOUNT;


	/* Get the type */
	mms_trace(MMS_DEVP, "type");
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "type",
	    MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_KEYWORD, NULL);
	if (strcmp(value->pn_string, "SIDE") == 0) {
		mount_info->cmi_type = MM_SIDE;
	} else if (strcmp(value->pn_string, "PARTITION") == 0) {
		mount_info->cmi_type = MM_PARTITION;
	} else if (strcmp(value->pn_string, "VOLUME") == 0) {
		mount_info->cmi_type = MM_VOLUME;
	} else {
		mms_trace(MMS_ERR, "Invalid mount type specified");
		mm_response_error(cmd,
		    EINVALIDTYPE,
		    ESYNTAX,
		    MM_5051_MSG,
		    NULL);
		return (MM_CMD_ERROR);
	}

	/* Get when */
	mms_trace(MMS_DEVP, "when");
	arg = mms_pn_lookup(cmd->cmd_root, "when",
	    MMS_PN_CLAUSE, NULL);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value,
		    arg, NULL, MMS_PN_KEYWORD, NULL);
		if (strcmp(value->pn_string, "blocking") == 0) {
			mount_info->cmi_when = MM_BLOCKING;
		} else {
			mount_info->cmi_when = MM_IMMEDIATE;
		}
	} else {
		/* when is optional and defaults to immediate */
		mount_info->cmi_when = MM_IMMEDIATE;
	}

	/* Get where */
	mms_trace(MMS_DEVP, "where");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "where",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value, arg, NULL,
		    MMS_PN_STRING, NULL);
		if (value->pn_string != NULL) {
			dm_host = value->pn_string;
		} else {
			dm_host = mm_cci_host_ident(conn);
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a where clause...");
		dm_host = mm_cci_host_ident(conn);
	}
	mount_info->cmi_where = mm_host_ident(dm_host);
	mms_trace(MMS_DEVP, "where %s", mount_info->cmi_where);

	/* Get File Name - Optional */
	mms_trace(MMS_DEVP, "filename");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "filename",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value, arg, NULL,
		    MMS_PN_STRING, NULL);
		if (value->pn_string != NULL) {
			mount_info->cmi_filename =
			    strdup(value->pn_string);
		} else {
			mount_info->cmi_filename = NULL;
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a filename clause...");
		mount_info->cmi_filename = NULL;
	}
	/* Get BlockSize - Optional */
	mms_trace(MMS_DEVP, "blocksize");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "blocksize",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value, arg, NULL,
		    MMS_PN_STRING, NULL);
		if (value->pn_string != NULL) {
			mount_info->cmi_blocksize =
			    strdup(value->pn_string);
		} else {
			mount_info->cmi_blocksize = NULL;
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a blocksize clause...");
		mount_info->cmi_blocksize = NULL;
	}
	/* Get volumeid - Optional */
	mms_trace(MMS_DEVP, "volumeid");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "volumeid",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value, arg, NULL,
		    MMS_PN_STRING, NULL);
		if (value->pn_string != NULL) {
			mount_info->cmi_volumeid =
			    strdup(value->pn_string);
		} else {
			mount_info->cmi_volumeid = NULL;
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a volumeid clause...");
		mount_info->cmi_volumeid = NULL;
	}
	/* Get filesequence - Optional */
	mms_trace(MMS_DEVP, "filesequence");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "filesequence",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value, arg, NULL,
		    MMS_PN_STRING, NULL);
		if (value->pn_string != NULL) {
			mount_info->cmi_filesequence =
			    strdup(value->pn_string);
		} else {
			mount_info->cmi_filesequence = NULL;
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a filesequence clause...");
		mount_info->cmi_filesequence = NULL;
	}
	/* Get user - Optional */
	mms_trace(MMS_DEVP, "user");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "user",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value, arg, NULL,
		    MMS_PN_STRING, NULL);
		if (value->pn_string != NULL) {
			mount_info->cmi_user =
			    strdup(value->pn_string);
		} else {
			mount_info->cmi_user = NULL;
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a user clause...");
		mount_info->cmi_user = NULL;
	}

	/* Get First Mount Clause */
	mms_trace(MMS_DEVP, "firstmount");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "firstmount",
	    MMS_PN_CLAUSE, &work);
	item = NULL;
	if (arg != NULL) {
		count = 0;
		go = 1;
		while (go) {

			if ((value =
			    mms_pn_lookup(arg, NULL,
			    MMS_PN_STRING,
			    &item)) == NULL) {
				go = 0;
			} else {
				mount_info->cmi_firstmount[count] =
				    value->pn_string;
				count ++;
			}

		}
		mount_info->cmi_num_firstmount = count;
	} else {
		mms_trace(MMS_DEVP, "Didin't find a first mount clause");
	}

	/* Get Access Mode Clause */
	mms_trace(MMS_DEVP, "accessmode");

	work = NULL;
	for (arg = mms_pn_lookup(cmd->cmd_root, "accessmode",
	    MMS_PN_CLAUSE, &work);
	    arg != NULL;
	    arg = mms_pn_lookup(cmd->cmd_root, "accessmode",
	    MMS_PN_CLAUSE, &work)) {
		/* Malloc a new mode object */
		mode = (cmi_mode_list_t *)
		    calloc(1, sizeof (cmi_mode_list_t));
		if (mode == NULL) {
			mms_trace(MMS_ERR,
			    "Unable to malloc cmi_mode_list: %s",
			    strerror(errno));
			mm_system_error(cmd,
			    "unable to allocate "
			    "memory for mode list");
			return (MM_CMD_ERROR);
		}
		/* Get all of the access Mode tokens */
		item = NULL;
		count = 0;
		go = 1;
		while (go) {
			if ((value =
			    mms_pn_lookup(arg, NULL,
			    MMS_PN_STRING,
			    &item)) == NULL) {
				go = 0;
			} else {
				mode->cmi_accessmode[count] =
				    value->pn_string;
				count ++;
			}
		}
		/* Put this access mode into the Accessmode list */
		mount_info->cmi_total_modes ++;
		mode->cmi_num_accessmode = count;
		mms_list_insert_tail(&mount_info->cmi_mode_list, mode);
	}

	/* Get retention clause */
	/* Get user - Optional */
	mms_trace(MMS_DEVP, "retention");
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "retention",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		MMS_PN_LOOKUP(value, arg, NULL,
		    MMS_PN_STRING, NULL);
		if (value->pn_string != NULL) {
			mount_info->cmi_retention =
			    strdup(value->pn_string);
		} else {
			mount_info->cmi_retention = NULL;
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a retention clause");
		mount_info->cmi_retention = NULL;
	}
	return (MM_CMD_DONE);


not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}


void
mm_mount_clean_candidates(mm_command_t *cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	int			has_drive = 0;


	cmi_cart_list_t *next_cart;

	cmi_drive_list_t *next_drive;


	mms_trace(MMS_DEVP, "mm_mount_clean_candidates");


	/* Cannot use mms_list_foreach when removing list elements */
	/* For each cart */
	for (cart = mms_list_head(&mount_info->
	    cmi_cart_list);
	    cart != NULL;
	    cart = next_cart) {
		next_cart =
		    mms_list_next(&mount_info->
		    cmi_cart_list,
		    cart);

		mms_trace(MMS_DEVP, "  check cart %s",
		    cart->cmi_cart_pcl);
		has_drive = 0;

		/* For each drive */
		for (drive = mms_list_head(&cart->
		    cmi_drive_list);
		    drive != NULL;
		    drive = next_drive) {
			next_drive =
			    mms_list_next(&cart->
			    cmi_drive_list,
			    drive);

			mms_trace(MMS_DEVP, "    check drive %s",
			    drive->cmi_drive_name);
			if (drive->cmi_remove_drive) {
				mms_list_remove(&cart->
				    cmi_drive_list,
				    drive);
				mms_trace(MMS_DEVP,
				    "      free drive %s",
				    drive->cmi_drive_name);
				mm_free_cmi_drive(drive);
			} else {
				mms_trace(MMS_DEVP,
				    "      drive good, %s",
				    drive->cmi_drive_name);
				has_drive = 1;
			}
		}
		if (has_drive == 0)
			cart->cmi_remove_cart = 1;
		if (cart->cmi_remove_cart) {
			mms_list_remove(&mount_info->cmi_cart_list, cart);
			mms_trace(MMS_DEVP,
			    "  free cart, %s",
			    cart->cmi_cart_pcl);
			mm_free_cmi_cart(cart);
		} else {
			mms_trace(MMS_DEVP,
			    "  cart good, %s",
			    cart->cmi_cart_pcl);
		}
	}

}

int
mm_mount_check_candidates(mm_wka_t *mm_wka, mm_command_t *cmd,
    mm_db_t *db) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*candidate_cartid = NULL;
	char			*candidate_drive = NULL;

	mms_list_foreach(&mount_info->cmi_cart_list, cart) {

		candidate_cartid = cart->cmi_cart_id;

		mms_trace(MMS_INFO, "Check Cartridge, %s",
		    candidate_cartid);

		if (mm_candidate_cartridge_ok(mm_wka,
		    cmd, db,
		    cart)) {
			/* Cartridge is ok */
			if (cart->cmi_cart_not_ready) {
				mms_trace(MMS_DEVP,
				    "cartridge %s is not "
				    "ready/in use",
				    candidate_cartid);
			} else {
				mms_trace(MMS_DEVP,
				    "Cartridge, %s, is available",
				    candidate_cartid);
			}
		} else {
			/* Cartridge not available */
			mms_trace(MMS_DEVP,
			    "Cartridge, %s, is not "
			    "available for mount",
			    candidate_cartid);
			cart->cmi_remove_cart = 1;
			/* Go on to next cartridge */
			continue;
		}


		mms_list_foreach(&cart->cmi_drive_list, drive) {

			candidate_drive = drive->cmi_drive_name;
			if (cart->cmi_cart_not_ready) {
				drive->cmi_drive_not_ready = 1;
				continue;
			}

			mms_trace(MMS_INFO,
			    "Check Drive, %s", candidate_drive);
			if (mm_candidate_drive_ok(mm_wka,
			    cmd, db,
			    candidate_cartid,
			    drive)) {
				if (drive->cmi_drive_not_ready) {
					mms_trace(MMS_DEVP,
					    "Drive, %s, is not ready/in use",
					    candidate_drive);
				} else {
					mms_trace(MMS_DEVP,
					    "Drive, %s, is available",
					    candidate_drive);
				}
			} else {
				mms_trace(MMS_DEVP,
				    "Drive, %s, not available"
				    " for mounts",
				    candidate_drive);
				drive->cmi_remove_drive = 1;
			}
		}
	}

	mm_mount_clean_candidates(cmd);
	return (0);
}

int
mm_mount_init_candidates(mm_command_t *cmd,
    PGresult *cart_results, mm_db_t *db) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;


	cmi_cart_list_t		*cur_cart;


	int			cart_rows;
	int			cart_row;
	int			drive_rows;
	int			drive_row;

	char			*candidate_library = NULL;
	char			*candidate_drive = NULL;
	char			*candidate_cartid = NULL;



	PGresult		*drive_results;

	cart_rows = PQntuples(cart_results);
	mm_free_cmi_cart_list(&mount_info->cmi_cart_list);

	for (cart_row = 0; cart_row < cart_rows; cart_row ++) {
		candidate_cartid = PQgetvalue(cart_results, cart_row, 0);
		candidate_library = PQgetvalue(cart_results, cart_row, 1);
		mms_trace(MMS_DEVP,
		    "mm_mount_init_candidates: cartid = %s, library = %s",
		    candidate_cartid, candidate_library);

		/* Allocate this cartridge */
		cur_cart = NULL;
		cur_cart = mm_setup_cart(cmd,
		    db,
		    cart_results,
		    cart_row);
		if (cur_cart == NULL) {
			mms_trace(MMS_ERR, "error allocing candidate cart");
			mm_system_error(cmd,
			    "error allocing candidate cart");
			return (1);
		}
		mms_trace(MMS_INFO, "Check Library, %s",
		    candidate_library);
		if (mm_candidate_library_ok(cmd, db,
		    candidate_library)) {
			mms_trace(MMS_DEVP,
			    "Library, %s, is available",
			    candidate_library);
		} else {
			mms_trace(MMS_DEVP,
			    "Library, %s, not available",
			    candidate_library);
			cur_cart->cmi_remove_cart = 1;
			/* Go on to next cartridge */
			continue;
		}


		/* Get the drives in this library */
		/* Do some ordering of drives here */
		/* mm_mount_order_candidates will do the ordering */
		if (cmd->cmd_func == mm_mount_cmd_func) {
			if (mm_db_exec(HERE, db,
			    "select distinct \"DriveName\","
			    "\"LibraryName\",\"DrivePriority\","
			    "\"DriveNumberMounts\" from ("
			    "select \"DriveName\",\"LibraryName\","
			    "\"DrivePriority\",\"DriveNumberMounts\""
			    "from \"DRIVE\""
			    "where (\"DRIVE\".\"LibraryName\" = '%s')"
			    "order by \"DRIVE\".\"DriveNumberMounts\""
			    ") as foo order by \"DrivePriority\";",
			    candidate_library) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "db error, init candidate cart");
				mm_sql_db_err_rsp_new(cmd, db);
				return (1);
			}
		} else {
			if (mm_db_exec(HERE, db,
			    "select distinct \"DriveName\","
			    "\"LibraryName\",\"DrivePriority\","
			    "\"DriveNumberMounts\" from ("
			    "select \"DriveName\",\"LibraryName\","
			    "\"DrivePriority\",\"DriveNumberMounts\""
			    "from \"DRIVE\""
			    "where (\"DRIVE\".\"LibraryName\" = '%s' "
			    "and \"DRIVE\".\"CartridgePCL\" = '%s')"
			    "order by \"DRIVE\".\"DriveNumberMounts\""
			    ") as foo order by \"DrivePriority\";",
			    candidate_library,
			    cur_cart->cmi_cart_pcl) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "db error, init candidate cart");
				mm_sql_db_err_rsp_new(cmd, db);
				return (1);
			}
		}
		drive_results = db->mm_db_results;
		drive_rows = PQntuples(drive_results);
		if (drive_rows == 0) {
			mms_trace(MMS_ERR,
			    "couldn't match any drives for library %s",
			    candidate_library);
			mm_response_error(cmd,
			    ECLASS_EXPLICIT, ENOMATCH,
			    MM_5094_MSG,
			    "lib",
			    candidate_library,
			    NULL);
			mm_clear_db(&drive_results);
			return (1);
		}

		for (drive_row = 0; drive_row < drive_rows; drive_row ++) {

			candidate_drive = PQgetvalue(drive_results,
			    drive_row, 0);

			mms_trace(MMS_DEVP,
			    "mm_mount_init_candidates: drive = %s",
			    candidate_drive);

			/* mm_set_dirve_unmount and */
			/* mm_setup_drive return a pointer */
			/* to the set up drive struct */
			if (mount_info->cmi_operation == MM_UNMOUNT) {
				(void) mm_setup_drive_unmount(cmd,
				    db,
				    cur_cart,
				    drive_results,
				    drive_row);
			} else {
				(void) mm_setup_drive(cmd,
				    db,
				    cur_cart,
				    drive_results,
				    drive_row);
			}

		}
		mm_clear_db(&drive_results);
	}

	mm_mount_clean_candidates(cmd);
	return (0);

}


PGresult* mm_mount_cart_results(mm_wka_t *mm_wka,
    mm_command_t *cmd, mm_db_t *db) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	char			*path_buf = NULL;
	char			*tmp_buf = NULL;

	cci_t			*conn = &mm_wka->wka_conn;
	char			*app_name = conn->cci_client;
	int			i;


	mm_clear_source(cmd);
	mm_clear_dest(cmd);
	mm_clear_const(cmd);

	if (mm_get_dest(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our dest info */
		mms_trace(MMS_DEVP, "Dest count is %d", cmd->cmd_dest_num);
		mm_print_char_list(&cmd->cmd_dest_list);
	}

	if (mm_get_const(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our const info */
		mms_trace(MMS_DEVP, "Const count is %d", cmd->cmd_const_num);
		mm_print_char_list(&cmd->cmd_const_list);
	}

	if (cmd->wka_ptr->wka_privilege == MM_PRIV_STANDARD) {
		/* add CARTRIDGEGROUPAPPLICATION constraint */
		(void) mm_add_to_dest(cmd,
		    "CARTRIDGEGROUPAPPLICATION");
		if (tmp_buf)
			free(tmp_buf);
		tmp_buf = NULL;
		tmp_buf = mms_strapp(tmp_buf,
		    "\"CARTRIDGEGROUPAPPLICATION\"."
		    "\"ApplicationName\" = '%s'",
		    app_name);
		(void) mm_add_to_const(cmd, tmp_buf);
		if (tmp_buf)
			free(tmp_buf);
		tmp_buf = NULL;
	}

	/* Clear cmd_buf */
	if (cmd->cmd_buf)
		SQL_CHK_LEN(&cmd->cmd_buf, NULL,
		    &cmd->cmd_bufsize, 0);


	/* Make path_buf and set source */
	path_buf = mms_strapp(path_buf,
	    "select distinct");
	if (mount_info->cmi_type == MM_VOLUME) {

		if (mm_add_char("VOLUME",
		    &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_mount_cart_results: "
			    "Error adding char to source list");
			mm_system_error(cmd,
			    "out of mem adding to source list");
			return (NULL);
		}
		path_buf = mms_strapp(path_buf,
		    "\"VOLUME\"");

	}
	if (mount_info->cmi_type == MM_PARTITION) {
		if (mm_add_char("PARTITION",
		    &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_mount_cart_results: "
			    "Error adding char to source list");
			mm_system_error(cmd,
			    "out of mem adding to source list");
			return (NULL);
		}
		path_buf = mms_strapp(path_buf,
		    "\"PARTITION\"");
	}
	if (mount_info->cmi_type == MM_SIDE) {
		if (mm_add_char("SIDE",
		    &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_mount_cart_results: "
			    "Error adding char to source list");
			mm_system_error(cmd,
			    "out of mem adding to source list");
			return (NULL);
		}
		path_buf = mms_strapp(path_buf,
		    "\"SIDE\"");
	}
	if (tmp_buf != NULL) {
		free(tmp_buf);
		tmp_buf = NULL;
	}


	/* Put path_buf into cmd_buf */
	path_buf = mms_strapp(path_buf,
	    ".\"CartridgeID\" from\n");
	SQL_CHK_LEN(&cmd->cmd_buf, NULL,
	    &cmd->cmd_bufsize, strlen(path_buf) + 1);
	strcpy(cmd->cmd_buf, path_buf);
	free(path_buf);
	path_buf = NULL;
	cmd->cmd_source_num = 1;
	/* Make report funcs */

	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_mount_cart_results: "
		    "db error creating helper functions");
		return (NULL);
	}

	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mms_trace(MMS_ERR,
		    "db error getting candidate cartridges");
		return (NULL);
	}

	if (PQntuples(db->mm_db_results) == 0) {
		/* no cartridge matches */
		mms_trace(MMS_INFO,
		    "match statment in mount "
		    "didn't match any cartridge/volumes");
		mm_response_error(cmd,
		    ECLASS_EXPLICIT, ENOMATCH,
		    MM_5052_MSG,
		    NULL);
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}


	/* Order cartridges based on priority and last time mounted */
	/* Additional Cartridge Ordering */
	/* done in mm_mount_order_candidates */
	tmp_buf = mms_strapp(tmp_buf,
	    "select distinct \"CartridgeID\","
	    "\"LibraryName\",\"CartridgeGroupPriority\","
	    "\"CartridgeNumberMounts\", "
	    "\"CartridgeShapeName\",\"CartridgePCL\", "
	    "\"CartridgeDriveOccupied\" "
	    "from ( "
	    "select \"CartridgeID\",\"LibraryName\", "
	    "\"CartridgeGroupPriority\","
	    "\"CartridgeNumberMounts\", "
	    "\"CartridgeShapeName\",\"CartridgePCL\", "
	    "\"CartridgeDriveOccupied\" "
	    "from \"CARTRIDGE\","
	    "\"CARTRIDGEGROUP\",\"CARTRIDGETYPE\" ");
	for (i = 0; i < PQntuples(db->mm_db_results); i++) {
		if (i == 0) {
			tmp_buf = mms_strapp(tmp_buf, "where (");
		} else {
			tmp_buf = mms_strapp(tmp_buf, "or ");
		}
		tmp_buf = mms_strapp(tmp_buf, " (\"CartridgeID\" = '%s')",
		    PQgetvalue(db->mm_db_results, i, 0));
	}
	tmp_buf = mms_strapp(tmp_buf,
	    ") and"
	    "(\"CARTRIDGEGROUP\".\"CartridgeGroupName\" "
	    "= \"CARTRIDGE\".\"CartridgeGroupName\")"
	    "and"
	    "(\"CARTRIDGE\".\"CartridgeTypeName\" "
	    "= \"CARTRIDGETYPE\".\"CartridgeTypeName\")"
	    "order by \"CARTRIDGE\".\"CartridgeTimeMountedLast\""
	    ") as foo order by \"CartridgeGroupPriority\";");
	mm_clear_db(&db->mm_db_results);
	if (mm_db_exec(HERE, db, tmp_buf) != MM_DB_DATA) {
		free(tmp_buf);
		mm_sql_db_err_rsp_new(cmd, db);
		return (NULL);
	}
	free(tmp_buf);
	return (db->mm_db_results);
no_mem:
	MM_ABORT_NO_MEM();
	return (NULL);

}

int
mm_mount_ready(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db, int is_retry) {

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;


	PGresult		*cart_results;
	int			cart_rows;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;


	int			found_cart_drive = 0;
	int			found_ready_cart_drive = 0;

	int			rc;

	int			resync_tries = 5;
	int			i = 0;

	/* Do drive/cart/lib selection using path matching */
	if ((cart_results = mm_mount_cart_results(mm_wka,
	    cmd, db)) == NULL) {
		/* No carts or error */
		return (MM_MOUNT_ERROR);
	}

	cart_rows = PQntuples(cart_results);
	mms_trace(MMS_DEVP, "Number of Cartridges is %d", cart_rows);

	if (cart_rows == 0) {
		/* No Cartridge Matches Error */
		mms_trace(MMS_INFO,
		    "match statment in mount "
		    "didn't match any cartridge/volumes");
		mm_response_error(cmd,
		    ECLASS_EXPLICIT, ENOMATCH,
		    MM_5052_MSG,
		    NULL);
		mm_clear_db(&cart_results);
		return (MM_MOUNT_ERROR);
	}
	/* Create the list objects for */
	/* every cartridge/drive candidate */
	if (mm_mount_init_candidates(cmd, cart_results,
	    db)) {
		mms_trace(MMS_ERR,
		    "error initializing candidate lists");
		/* err buf should be set by mm_mount_init */
		/* so return and remove */
		mm_clear_db(&cart_results);
		return (MM_MOUNT_ERROR);
	}
	mms_trace(MMS_DEVP, "candidate list created, check availability ");
	mm_clear_db(&cart_results);
	/* Check the availability of the candidates */
	if (mm_mount_check_candidates(mm_wka, cmd,
	    db)) {
		mms_trace(MMS_ERR,
		    "error checking candidate lists");
		mm_system_error(cmd,
		    "error checking candidate lists");
		return (MM_MOUNT_ERROR);
	}
	mms_trace(MMS_DEVP, "done checking list");



	/* Print mount information */
	mm_print_mount_summary(mm_wka, cmd);


	/*
	 * For blocking mounts,
	 * check that at least some cart/drive combo exists
	 * if that cart/drive exists, but is not ready, return not ready
	 *
	 * for immediate mounts, check that at least one combination exists
	 */

	found_cart_drive = 0;
	found_ready_cart_drive = 0;

	/* if cart/drive is not reay, set for remove */
	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		if (cart->cmi_cart_not_ready)
			cart->cmi_remove_cart = 1;
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			found_cart_drive = 1;
			if ((cart->cmi_cart_not_ready == 0) &&
			    (drive->cmi_drive_not_ready == 0)) {
				found_ready_cart_drive = 1;
			}
			if (drive->cmi_drive_not_ready)
				drive->cmi_remove_drive = 1;
		}
	}


	/* If there is a library or drive error */
	/* the error buff has already been set */
	if (found_cart_drive == 0) {
		mms_trace(MMS_INFO,
		    "No candidate "
		    "cartridge/library/drive "
		    "combination found");
		/* set least severe error */
		mm_set_least_severe(cmd);
		return (MM_MOUNT_ERROR);
	}
	if (found_ready_cart_drive == 0) {
		mms_trace(MMS_INFO,
		    "candidate "
		    "cartridge/library/drive "
		    "combination found, but is not ready");
		return (MM_MOUNT_NOT_READY);
	}
	/* There is a ready cart/drive */
	/* we may have set some non ready for remove */
	/* so call the clean func before contine */
	mm_mount_clean_candidates(cmd);
	cmd->cmd_state = 1;
	rc = mm_set_immediate_mount(mm_wka, cmd, db);

	if (rc == MM_RESYNC) {
		if (is_retry) {
			return (rc);
		}
		/* Destroy all cart lists */
		mms_trace(MMS_INFO,
		    "mm_mount_ready: "
		    "states out of sync, attempt to resync this mount");
		for (i = 0; i < resync_tries; i++) {
			mm_free_cmi_cart_list(&mount_info->cmi_cart_list);
			rc = mm_mount_ready(mm_wka, cmd, db, 1);
			if (rc != MM_RESYNC) {
				mms_trace(MMS_INFO,
				    "mm_mount_ready: "
				    "resync successful");
				return (rc);
			}
		}
		mms_trace(MMS_INFO,
		    "mm_mount_ready: "
		    "states out of sync, resync failed");
		return (MM_MOUNT_ERROR);
	}
	if (rc == MM_CMD_ERROR) {
		mms_trace(MMS_ERR,
		    "error setting up immediate mount");
		/* set least severe error */
		mm_set_least_severe(cmd);
		return (MM_MOUNT_ERROR);
	} else if (rc == MM_DISPATCH_DEPEND) {
		/* this immediate mount needs to */
		/* wait for an unload */
		mms_trace(MMS_DEVP,
		    " mount waiting "
		    "for unload to complete");
		return (MM_MOUNT_NEED_UNLOAD);
	}
	mms_trace(MMS_DEVP,
	    "mount ready for dispatch");

	return (MM_MOUNT_READY);

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	return (MM_MOUNT_ERROR);

}


int
mm_mount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	cci_t			*conn = &mm_wka->wka_conn;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	int			rows;
	int			rc;
	char			*response_message = NULL;
	mm_command_t		*dmp_release = NULL;

	mms_trace(MMS_DEVP, "mm mount cmd state %d", cmd->cmd_state);

	if (cmd->cmd_state == 0) {

		mms_trace(MMS_INFO, "Processing Mount Request...");
		/*
		 * Generate Candidate Cartridge and Drive lists
		 * First parse and save the mount info
		 * then use SQL queries to gereate the lists
		 */

		mount_info->cmi_mount_cart_loaded = 0;
		mount_info->cmi_fail_type = NONE;
		if (mm_parse_mount_cmd(mm_wka, cmd) == MM_CMD_ERROR) {
			mms_trace(MMS_ERR,
			    "error parsing mount command");
			/* Error buf should already be set */
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mms_trace(MMS_DEVP, "done parsing");



		/* ***DONE PARSING MOUNT COMMAND*** */

		if (mount_info->cmi_when == MM_BLOCKING) {
			if (mm_set_tm_task(db, cmd) != MM_DB_OK) {
				goto db_error;
			}
			mms_trace(MMS_DEVP,
			    "blocking mount will be passed to task manager");
			return (MM_WORK_TODO);
		}
		/* This is an immediate mount */
		rc = mm_mount_ready(mm_wka, cmd, db, 0);
		switch (rc) {

		case MM_MOUNT_ERROR:
			/* Error code should be set */
			mms_trace(MMS_ERR,
			    "internal error, mm_mount_ready");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);

		case MM_MOUNT_READY:
			/* The mount is ready, mount_info should be set */
			/* continue to state 1 */
			cmd->cmd_state = 1;
			mms_trace(MMS_DEVP,
			    "mount is ready to go, "
			    "continue to state 1");
			break;

		case MM_MOUNT_NEED_UNLOAD:
			/* this immediate mount needs to */
			/* wait for an unload */
			cmd->cmd_state = 1;
			mms_trace(MMS_DEVP,
			    "mount waiting "
			    "for unload to complete");
			return (MM_DISPATCH_DEPEND);

		case MM_MOUNT_NOT_READY:
			/* Error code should be set */
			mms_trace(MMS_ERR,
			    "immediate mount not ready, "
			    "send error to client");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);

		default:
			mms_trace(MMS_ERR,
			    "bad rc mm_mount_ready");
			mm_system_error(cmd,
			    "bad rc mm_mount_ready");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);

		}
	}

start:
	if (cmd->cmd_state == 1) {
		mms_trace(MMS_INFO, "Mounting tape...");

		/* Reserve the DM */
		/*
		 * mm_sql_update_state(mm_wka->mm_data, "DM",
		 *   "DMStateSoft",
		 *   "reserved", "DMName",
		 *   mount_info->cmi_dm);
		 */
		mm_sql_update_state(mm_wka->mm_data, "DRIVE",
		    "DMName",
		    mount_info->cmi_dm, "DriveName",
		    mount_info->cmi_drive);

		/*  Add activate command */
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_RESERVE) == NULL) {
			mms_trace(MMS_ERR,
			    "error adding dmp reserve");
			mm_system_error(cmd,
			    "error adding dmp reserve");
			goto reset_states;
		}
		cmd->cmd_state = 3;
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 3) {

		/*
		 * Mount cartridge in the library drive
		 */

		mm_command_t		*lmp_mnt_cmd;
		mm_wka_t		*lm_wka;
		uuid_text_t		 new_task;
		char			*cart_pcl;
		char			*side_name;

		/*
		 * DM Activate failed
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "DM reserve failed");
			/* Reset drive and cartridge */
			/* return error to client */
			mount_info->cmi_reset_states = 1;
			goto lm_dm_error;
		}

		if (mount_info->cmi_mount_cart_loaded) {
			/* Skip lmp mount */
			cmd->cmd_state = 4;
			goto start;
		}
		/*
		 * Cartridge pcl and side name
		 */
		if ((cart_pcl = mm_get_cart_pcl(cmd,
		    cmd->cmd_mount_info.cmi_cartridge, db)) == NULL) {
			/* Error buf should be set in mm_get_cart_pcl */
			goto reset_states;
		}

		/* TODO side name needs to be generated in candidate query */
		if ((side_name = cmd->cmd_mount_info.cmi_side_name) == NULL) {
			side_name = "side 1";
		}

		/*
		 * LMP mount command
		 */
		lm_wka = mm_library_lm_wka(cmd->wka_ptr->mm_data,
		    cmd->cmd_mount_info.cmi_library, NULL);
		if ((lmp_mnt_cmd = mm_alloc_cmd(lm_wka)) == NULL) {
			mms_trace(MMS_ERR,
			    "Unable to malloc mm_command_t: %s",
			    strerror(errno));
			mm_system_error(cmd,
			    "Unable to malloc lmp mount cmd");
			goto reset_states;
		}

		lmp_mnt_cmd->cmd_func = mm_lmp_mount_cmd_func;
		mm_get_uuid(new_task);
		lmp_mnt_cmd->cmd_textcmd = mms_strnew(LMP_MOUNT, new_task,
		    cart_pcl, cart_pcl, side_name,
		    cmd->cmd_mount_info.cmi_drive);
		lmp_mnt_cmd->cmd_root =
		    mm_text_to_par_node(lmp_mnt_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		lmp_mnt_cmd->cmd_task = mm_get_task(lmp_mnt_cmd->cmd_root);
		mm_add_depend(lmp_mnt_cmd, cmd);
		lmp_mnt_cmd->cmd_name = strdup("lmp mount");
		lmp_mnt_cmd->cmd_mount_info.cmi_drive =
		    strdup(cmd->cmd_mount_info.cmi_drive);
		lmp_mnt_cmd->cmd_mount_info.cmi_cartridge =
		    strdup(cmd->cmd_mount_info.cmi_cartridge);
		cmd->cmd_state = 4;

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue,
		    lmp_mnt_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		free(cart_pcl);

		return (MM_DISPATCH_DEPEND);

	} else if (cmd->cmd_state == 4) {

		/*
		 * LMP Mount command failed
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "lm mount failed");
			/* Reset drive and cartridge */
			/* return error to client */
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;
			/* DM is reserved, release the DM */
			if (dmp_release = mm_dmp_add_cmd(mm_wka,
			    cmd, mount_info->cmi_dm,
			    MM_DMP_RELEASE)) {
				/* run withtout parent */
				mm_remove_all_depend(dmp_release);
			}
			/* Generate error message */
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    "subop", "ELMPMOUNT", MM_5018_MSG,
			    "cartridge", mount_info->cmi_cartridge,
			    "drive", mount_info->cmi_drive,
			    "msg_rsp", response_message,
			    NULL);
			free(response_message);
			/* Set cmd for remove, send message to client */
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_PRIV) == NULL) {
			mms_trace(MMS_ERR,
			    "error adding dmp private");
			mm_system_error(cmd,
			    "error adding dmp private");
			goto reset_states;
		}
		cmd->cmd_state = 5;
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 5) {

		/* DM_load state */
		/*
		 * Private has finished, add a load command to the
		 * queue
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "mmp_mount-> DMP private error");
			/* Reset drive and cartridge */
			/* return error to client */
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;
			/* DM is reserved, release the DM */
			if (dmp_release = mm_dmp_add_cmd(mm_wka,
			    cmd, mount_info->cmi_dm,
			    MM_DMP_RELEASE)) {
				/* run withtout parent */
				mm_remove_all_depend(dmp_release);
			}
			goto lm_dm_error;
		}

		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_LOAD) == NULL) {
			mms_trace(MMS_ERR,
			    "error adding dmp load");
			mm_system_error(cmd,
			    "error adding dmp load");
			goto reset_states;
		}
		cmd->cmd_state = 6;
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 6) {
		/* load command has finished, add an attach */
		/* Update Drive Table */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "mmp_mount-> DMP load error");
			/* Reset drive and cartridge */
			/* return error to client */
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;
			/* DM is reserved, release the DM */
			if (dmp_release = mm_dmp_add_cmd(mm_wka,
			    NULL, mount_info->cmi_dm,
			    MM_DMP_RELEASE)) {
				/* run withtout parent */
				mm_remove_all_depend(dmp_release);
			}
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    "EDMPLOAD",
			    MM_5053_MSG,
			    "cartridge",
			    mount_info->cmi_cartridge,
			    "drive",
			    mount_info->cmi_drive,
			    "msg_rsp",
			    response_message,
			    NULL);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}

		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_ATTACH) == NULL) {
			mms_trace(MMS_ERR,
			    "error adding dmp attach");
			mm_system_error(cmd,
			    "error adding dmp attach");
			goto reset_states;
		}
		cmd->cmd_state = 7;
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 7) {

		PGresult		*side;
		PGresult		*slot;
		PGresult		*mount_log;
		PGresult		*results;
		int			priv_no_vol = 0;
		char			*side_name = NULL;
		char			*slot_name = NULL;
		char			*slot_pcl = NULL;

		/* DM_identify tester state */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "mmp_mount-> DMP attach error");
			/* Reset drive and cartridge */
			/* return error to client */
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;
			/* DM is reserved, release the DM */
			if (dmp_release = mm_dmp_add_cmd(mm_wka,
			    cmd, mount_info->cmi_dm,
			    MM_DMP_RELEASE)) {
				/* run withtout parent */
				mm_remove_all_depend(dmp_release);
			}
			/* write error message */
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    "EDMPATTACH",
			    MM_5054_MSG,
			    "cartridge",
			    mount_info->cmi_cartridge,
			    "drive",
			    mount_info->cmi_drive,
			    "msg_rsp",
			    response_message,
			    NULL);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}

		rc = mm_db_exec(HERE, db,
		    "select * from \"MOUNTPHYSICAL\" "\
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge);
		if (rc != MM_DB_DATA) {
			mms_trace(MMS_ERR, "Exec returned with no Data");
			mm_sql_db_err_rsp_new(cmd, db);
			goto reset_states;
		}
		mount_log = db->mm_db_results;
		rows = PQntuples(mount_log);
		mm_clear_db(&mount_log);
		/* attach command has finished, add an indentify */
		/* insert row into MOUNTLOGICAL */

		rc = mm_db_exec(HERE, db,
		    "select \"VolumeName\", "
		    "\"PartitionName\", \"SideName\" "
		    "from \"VOLUME\" where \"CartridgeID\" = '%s'"
		    "and \"ApplicationName\" = '%s';",
		    mount_info->cmi_cartridge,
		    conn->cci_client);

		if (rc != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			goto reset_states;
		}
		results = db->mm_db_results;
		if ((PQntuples(results) == 0) &&
		    (cmd->wka_ptr->wka_privilege != MM_PRIV_STANDARD)) {
			/* Priv app doesn't have a volume */
			rc = mm_db_exec(HERE, db,
			    "select \"VolumeName\", "
			    "\"PartitionName\", \"SideName\", "
			    "\"ApplicationName\" "
			    "from \"VOLUME\" where \"CartridgeID\" = '%s';",
			    mount_info->cmi_cartridge);
			priv_no_vol = 1;
			mm_clear_db(&results);
			results = db->mm_db_results;
		}

		rc = mm_db_exec(HERE, db,
		    "select \"SideName\" from "	\
		    "\"SIDE\" where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge);
		if (rc != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			goto reset_states;
		}
		side = db->mm_db_results;


		if (PQntuples(side) == 0) {
			mms_trace(MMS_DEVP,
			    "missing SIDE obj for %s",
			    mount_info->cmi_cartridge);
			mm_system_error(cmd,
			    "cartridge missing SIDE obj");
			mm_clear_db(&results);
			mm_clear_db(&side);
			goto reset_states;
		}
		side_name = PQgetvalue(side, 0, 0);

		rc = mm_db_exec(HERE, db,
		    "select \"SlotName\", "\
		    "\"CartridgePCL\" from \"SLOT\" "\
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge);
		if (rc != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			mm_clear_db(&side);
			goto reset_states;
		}
		slot = db->mm_db_results;
		if (PQntuples(slot) == 0) {
			mms_trace(MMS_DEVP,
			    "missing SLOT obj for %s",
			    mount_info->cmi_cartridge);
			mm_system_error(cmd,
			    "cartridge missing SLOT obj");
			mm_clear_db(&results);
			mm_clear_db(&side);
			mm_clear_db(&slot);
			goto reset_states;
		}
		slot_name = PQgetvalue(slot, 0, 0);
		slot_pcl = PQgetvalue(slot, 0, 1);

		if (rows == 0) {
			if (priv_no_vol) {
				rc = mm_db_exec(HERE, db,
				    "insert into \"MOUNTLOGICAL\" "\
				    "(\"ApplicationName\", \"VolumeName\", "\
				    "\"PartitionName\", \"SideName\", "\
				    "\"CartridgeID\", \"DriveName\", "\
				    "\"DMName\", \"DMCapabilityName\", "\
				    "\"MountLogicalHandle\", "\
				    "\"MountLogicalTimeWhenMounted\") "\
				    "values ('%s', '%s', '%s', '%s', "\
				    "'%s', '%s', '%s', '%s', '%s', now());",
				    PQgetvalue(results, 0, 3),
				    PQgetvalue(results, 0, 0),
				    PQgetvalue(results, 0, 1),
				    PQgetvalue(results, 0, 2),
				    mount_info->cmi_cartridge,
				    mount_info->cmi_drive,
				    mount_info->cmi_dm,
				    mount_info->cmi_capability,
				    mount_info->cmi_handle);
			} else {
				rc = mm_db_exec(HERE, db,
				    "insert into \"MOUNTLOGICAL\" "
				    "(\"ApplicationName\", \"VolumeName\", "
				    "\"PartitionName\", \"SideName\", "
				    "\"CartridgeID\", \"DriveName\", "
				    "\"DMName\", \"DMCapabilityName\", "
				    "\"MountLogicalHandle\", "
				    "\"MountLogicalTimeWhenMounted\") "
				    "values ('%s', '%s', '%s', '%s', "
				    "'%s', '%s', '%s', '%s', '%s', now());",
				    conn->cci_client,
				    PQgetvalue(results, 0, 0),
				    PQgetvalue(results, 0, 1),
				    PQgetvalue(results, 0, 2),
				    mount_info->cmi_cartridge,
				    mount_info->cmi_drive,
				    mount_info->cmi_dm,
				    mount_info->cmi_capability,
				    mount_info->cmi_handle);
			}
			if (rc != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_mount_cmd_func: "
				    "error inserting MOUNTLOGICAL");
			}

			if (mm_db_exec(HERE, db,
			    "insert into \"MOUNTPHYSICAL\" "
			    "(\"ApplicationName\",\"DriveName\", "
			    "\"LibraryName\", "
			    "\"CartridgeID\", \"CartridgePCL\", "
			    "\"SideName\", "
			    "\"SlotName\", "
			    "\"MountPhysicalTimeWhenMounted\", "
			    "\"SessionID\") "
			    "values('%s', '%s', '%s', '%s', "
			    "'%s', '%s', '%s', now(), '%s');",
			    conn->cci_client,
			    mount_info->cmi_drive,
			    mount_info->cmi_library,
			    mount_info->cmi_cartridge,
			    slot_pcl,
			    side_name,
			    slot_name,
			    mm_wka->session_uuid) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_mount_cmd_func: "
				    "error inserting MOUNTPHYSICAL");
			}
		} else {
			if (mm_db_exec(HERE, db,
			    "delete from \"MOUNTLOGICAL\" "\
			    "where \"CartridgeID\" = '%s';",
			    mount_info->cmi_cartridge) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_mount_cmd_func: "
				    "error deleting MOUNTLOGICAL");
			}
			rc = mm_db_exec(HERE, db,
			    "insert into \"MOUNTLOGICAL\" "\
			    "(\"ApplicationName\", \"VolumeName\", "\
			    "\"PartitionName\", \"SideName\", "\
			    "\"CartridgeID\", \"DriveName\", "\
			    "\"DMName\", \"DMCapabilityName\", "\
			    "\"MountLogicalHandle\", "\
			    "\"MountLogicalTimeWhenMounted\") "\
			    "values ('%s', '%s', '%s', '%s', "\
			    "'%s', '%s', '%s', '%s', '%s', now());",
			    conn->cci_client,
			    PQgetvalue(results, 0, 0),
			    PQgetvalue(results, 0, 1),
			    PQgetvalue(results, 0, 2),
			    mount_info->cmi_cartridge,
			    mount_info->cmi_drive,
			    mount_info->cmi_dm,
			    mount_info->cmi_capability,
			    mount_info->cmi_handle);
			if (rc != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_mount_cmd_func: "
				    "error inserting MOUNTLOGICAL");
			}

		}
		mm_clear_db(&results);
		mm_clear_db(&side);
		mm_clear_db(&slot);
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_IDENTIFY) == NULL) {
			mms_trace(MMS_ERR,
			    "error adding dmp identify");
			mm_system_error(cmd,
			    "error adding dmp identify");
			goto reset_states;
		}
		cmd->cmd_state = 8;
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 8) {
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "mmp_mount-> DMP identify error");
			/* Reset drive and cartridge */
			/* return error to client */
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;
			/* DM is reserved, release the DM */
			if (dmp_release = mm_dmp_add_cmd(mm_wka,
			    cmd, mount_info->cmi_dm,
			    MM_DMP_RELEASE)) {
				/* run withtout parent */
				mm_remove_all_depend(dmp_release);
			}
			goto lm_dm_error;
		}
		/* The command is finished so generate a report */

		/* Remove the TASK objs */
		if (mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\""
		    "where \"TaskID\" = '%s';",
		    cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_mount_cmd_func: "
			    "db error deleting TASKCARTRIDGE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKDRIVE\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_mount_cmd_func: "
			    "db error deleting TASKDRIVE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_mount_cmd_func: "
			    "db error deleting TASKLIBRARY");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASK\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_mount_cmd_func: "
			    "db error deleting TASK");
		}
		/*
		 * Report clause.
		 */
		cmd->cmd_remove = 1;
		mm_path_match_report(cmd, db);
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		mms_trace(MMS_INFO, "Tape Successfully Mounted");
		rc = MM_CMD_DONE;
		goto end;

	}

	cmd->cmd_remove = 1;
	rc = MM_CMD_ERROR;
	goto end;

reset_states:
	mount_info->cmi_reset_states = 1;
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
no_mem:
	MM_ABORT_NO_MEM();
	rc = MM_CMD_ERROR;
	goto end;

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;
lm_dm_error:
	response_message =
	    mm_ret_response_msg(cmd);
	mm_response_error(cmd,
	    ECLASS_SUBOP,
	    ELMDMCOMMUNICATION,
	    MM_5055_MSG,
	    "msg_rsp", response_message,
	    NULL);
	free(response_message);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	/* Clear the Drive */
	if (mount_info->cmi_drive != NULL) {
		mount_info->cmi_need_clear = 1;

	}
	rc = MM_CMD_ERROR;
	goto end;

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn,
	    cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;

end:

	return (rc);

}


int
mm_delay_unmount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	time_t			tm;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	char			*response_message = NULL;

	mms_trace(MMS_DEVP, "mm_delay_unmount_cmd_func %s",
	    cmd->cmd_mount_info.cmi_drive);

	if (cmd->cmd_state == 0) {
		(void) time(&tm);

		if (tm < mount_info->unload_tm) {
			mms_trace(MMS_DEVP,
			    "wait longer for this unload");
			return (MM_DISPATCH_DEPEND);
		}

		if (mount_info->cui_skip_unload) {
			mms_trace(MMS_DEVP,
			    "procced with unload, "
			    "but skip the DM unload command");
			return (MM_CMD_DONE);
		}
		cmd->cmd_state = 1;
		mms_trace(MMS_DEVP,
		    "proceed with DM unload command");

	}

	if (cmd->cmd_state == 1) {
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_UNLOAD) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_delay_unmount_cmd_func: "
			    "error adding dmp unload");
			return (MM_CMD_ERROR);
		}
		cmd->cmd_state = 2;
		return (MM_DISPATCH_DEPEND);
	}

	if (cmd->cmd_state == 2) {
		mm_command_t		*lmp_umnt_cmd;
		mm_wka_t		*lm_wka;
		uuid_text_t		 new_task;
		char			*cart_pcl;
		char			*side_name;
		/*
		 * Unload has returned
		 * check error, update states
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "delay unmount-> DMP unload error");
			response_message = mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    MM_5055_MSG,
			    "msg_rsp", response_message,
			    NULL);
			free(response_message);
			response_message = NULL;

		}

		/*
		 * Cartridge pcl and side name
		 */
		if ((cart_pcl = mm_get_cart_pcl(cmd,
		    cmd->cmd_mount_info.cmi_cartridge, db)) == NULL) {
			cmd->cmd_remove = 1;
			mms_trace(MMS_ERR,
			    "mm_get_cart_pcl error");
			return (MM_CMD_ERROR);
		}

		mm_set_mount_info_pcl(cart_pcl,
		    mount_info);

		/* TODO side name needs to be generated in candidate query */
		if ((side_name = cmd->cmd_mount_info.cmi_side_name) == NULL) {
			side_name = "side 1";
		}

		/*
		 * LMP unmount command
		 */
		lm_wka = mm_library_lm_wka(cmd->wka_ptr->mm_data,
		    cmd->cmd_mount_info.cmi_library, NULL);
		if ((lmp_umnt_cmd = mm_alloc_cmd(lm_wka)) == NULL) {
			mms_trace(MMS_ERR,
			    "Unable to malloc mm_command_t: %s",
			    strerror(errno));
			return (MM_CMD_ERROR);
		}
		lmp_umnt_cmd->cmd_func = mm_lmp_unmount_cmd_func;
		mm_get_uuid(new_task);
		lmp_umnt_cmd->cmd_textcmd = mms_strnew(LMP_UNMOUNT, new_task,
		    cart_pcl, cart_pcl, side_name,
		    cmd->cmd_mount_info.cmi_drive,
		    cart_pcl, cart_pcl, side_name);
		mm_set_mount_info_drive(cmd->cmd_mount_info.cmi_drive,
		    &lmp_umnt_cmd->cmd_mount_info);
		lmp_umnt_cmd->cmd_root =
		    mm_text_to_par_node(lmp_umnt_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		lmp_umnt_cmd->cmd_task = mm_get_task(lmp_umnt_cmd->cmd_root);
		mm_add_depend(lmp_umnt_cmd, cmd);
		lmp_umnt_cmd->cmd_name = strdup("lmp unmount");


		cmd->cmd_state = 3;

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue,
		    lmp_umnt_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		free(cart_pcl);

		return (MM_DISPATCH_DEPEND);

	}
	if (cmd->cmd_state == 3) {
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_ERR, "LMP unmount error, "
			    "scan both drive and slot");
			/* Clear depend error flags */
			MM_UNSET_FLAG(cmd->cmd_flags,
			    MM_CMD_DEPEND_ERROR);

			/* Add LMP scan command for this drive */
			if (mm_add_lmp_scan(mm_wka->mm_data, cmd,
			    mount_info->cmi_drive,
			    NULL, mount_info->cmi_library)) {
				mms_trace(MMS_ERR,
				    "Error adding LMP scan");
				return (MM_CMD_ERROR);
			} else {
				mms_trace(MMS_DEBUG,
				    "Added LMP scan");
			}
			cmd->cmd_state = 4;
			return (MM_DISPATCH_DEPEND);
		}


		mms_trace(MMS_INFO, "Tape Unmounted Successfully");
		/*
		 * Don't reset the soft state
		 * "\"DriveStateSoft\" = 'ready',"
		 */

		if (mm_db_exec(HERE, db, "update \"DRIVE\" set "
		    "\"DMName\" = '',"
		    "\"DriveStateHard\" = 'unloaded' where "
		    "\"DriveName\" = '%s';",
		    cmd->cmd_mount_info.cmi_drive) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_delay_unmount_cmd_func: "
			    "db error updating DriveStateHard");
		}

		/* Don't update the cartridge soft state */
		/* The unload may be part of a mount sequence */

		if (mm_has_depend(cmd)) {
			mm_command_t *cur_depend = NULL;
			mms_list_foreach(&cmd->cmd_depend_list, cur_depend) {
				if (cur_depend->cmd_func ==
				    mm_delay_unmount_cmd_func) {
					mms_trace(MMS_DEVP,
					    "this delay unmount has "
					    "delay unmount as parent,"
					    " set parent ready for dispatch");
					mm_set_unload_dispatch(cur_depend,
					    NULL);
				}
			}
			return (MM_DEPEND_DONE);
		}

		return (MM_CMD_DONE);
	}
	if (cmd->cmd_state == 4) {
		/* This is state after lmp scan of drive */
		/* send a scan of the cartridge now */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_ERR, "error in LMP drive scan, try"
			    "slot scan anyways");
			/* Clear depend error flags */
			MM_UNSET_FLAG(cmd->cmd_flags,
			    MM_CMD_DEPEND_ERROR);
		}
		mms_trace(MMS_DEVP, "drive scan done, scan slot");

		/* Add LMP scan command for this drive */
		if (mm_add_lmp_scan(mm_wka->mm_data, cmd,
		    NULL,
		    mount_info->cmi_pcl,
		    mount_info->cmi_library)) {
			mms_trace(MMS_ERR,
			    "Error adding LMP scan");
			return (MM_CMD_ERROR);
		} else {
			mms_trace(MMS_DEBUG,
			    "Added LMP scan");
		}
		cmd->cmd_state = 5;
		return (MM_DISPATCH_DEPEND);

	}
	if (cmd->cmd_state == 5) {
		/* cartridge scan returned , return cmd done */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_ERR, "error in LMP slot scan");
		}
		mms_trace(MMS_DEVP, "slot scan done");

		/* Don't update the cartridge soft state */
		/* The unload may be part of a mount sequence */

		if (mm_has_depend(cmd)) {
			mm_command_t *cur_depend = NULL;
			mms_list_foreach(&cmd->cmd_depend_list, cur_depend) {
				if (cur_depend->cmd_func ==
				    mm_delay_unmount_cmd_func) {
					mms_trace(MMS_DEVP,
					    "this delay unmount has "
					    "delay unmount as parent,"
					    " set parent ready for dispatch");
					mm_set_unload_dispatch(cur_depend,
					    NULL);
				}
			}
			return (MM_DEPEND_DONE);
		}

		return (MM_CMD_DONE);
	}

	mms_trace(MMS_ERR,
	    "mm_delay_unmount_cmd_func: unknown command state");
	return (MM_CMD_ERROR);

}


int
mm_schedule_unload(mm_wka_t *mm_wka, mm_command_t *cmd) {

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	mm_data_t		*mm_data = mm_wka->mm_data;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;

	mm_command_t		*unmount_cmd;
	mm_wka_t		*lm_wka;
	uuid_text_t		uuid;

	/* Time releated */
	char		cur_date[100];
	char		unload_date[100];
	time_t		tm;
	struct tm	cur_time;
	struct tm	unload_time;

	/* allocate the unmount command */
	lm_wka = NULL;
	lm_wka = mm_library_lm_wka(cmd->wka_ptr->mm_data,
	    cmd->cmd_mount_info.cmi_library, NULL);
	if ((unmount_cmd = mm_alloc_cmd(lm_wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		return (1);
	}
	mm_get_uuid(uuid);
	unmount_cmd->cmd_root = NULL;
	unmount_cmd->cmd_task = NULL;
	unmount_cmd->cmd_task = strdup(uuid);
	unmount_cmd->cmd_func = mm_delay_unmount_cmd_func;
	unmount_cmd->cmd_name = strdup("delay unmount");

	/* Copy over the mount info to the new command */
	if (mount_info->cmi_cartridge != NULL)
		unmount_cmd->cmd_mount_info.cmi_cartridge =
		    strdup(mount_info->cmi_cartridge);
	if (mount_info->cmi_drive != NULL)
		unmount_cmd->cmd_mount_info.cmi_drive =
		    strdup(mount_info->cmi_drive);
	if (mount_info->cmi_side_name != NULL)
		unmount_cmd->cmd_mount_info.cmi_side_name =
		    strdup(mount_info->cmi_side_name);
	if (mount_info->cmi_library != NULL)
		unmount_cmd->cmd_mount_info.cmi_library =
		    strdup(mount_info->cmi_library);
	if (mount_info->cmi_dm != NULL)
		unmount_cmd->cmd_mount_info.cmi_dm =
		    strdup(mount_info->cmi_dm);

	unmount_cmd->cmd_mount_info.cui_skip_unload =
	    mount_info->cui_skip_unload;

	/* Set up timer */

	if (mm_db_exec(HERE, db,
	    "select \"DriveGroupUnloadTime\" from "
	    "\"DRIVEGROUP\",\"DRIVE\" where "
	    "\"DRIVE\".\"DriveGroupName\" = "
	    "\"DRIVEGROUP\".\"DriveGroupName\" and "
	    "\"DRIVE\".\"DriveName\" = '%s';",
	    mount_info->cmi_drive) != MM_DB_DATA) {
		mms_trace(MMS_ERR, "Exec returned with no Data");
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR, "Exec rows != 1");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	/* set the time to unload */
	/* Get the delay time, get the current time */
	(void) time(&tm);
	mms_trace(MMS_DEVP, "Current tm is %d", tm);
	(void) localtime_r(&tm, &cur_time);
	(void) strftime(cur_date, 100, "%Y/%m/%d %H:%M:%S", &cur_time);

	/* unload time is in min, so mult by 60 for sec */
	tm = tm + 60*atoi(PQgetvalue(db->mm_db_results, 0, 0));
	unmount_cmd->cmd_mount_info.unload_tm = tm;

	mms_trace(MMS_DEVP, "Unload tm is %d", tm);
	(void) localtime_r(&tm, &unload_time);
	(void) strftime(unload_date, 100, "%Y/%m/%d %H:%M:%S", &unload_time);
	mms_trace(MMS_DEVP,
	    "Current time is %s, delay time is %s mins, unload at %s",
	    cur_date, PQgetvalue(db->mm_db_results, 0, 0), unload_date);


	pthread_mutex_lock(&mm_data->
	    mm_queue_mutex);
	mms_list_insert_tail(&mm_data->mm_cmd_queue, unmount_cmd);
	pthread_mutex_unlock(&mm_data->
	    mm_queue_mutex);

	mm_clear_db(&db->mm_db_results);
	return (0);


}

int
mm_parse_unmount_cmd(mm_wka_t *mm_wka, mm_command_t *cmd) {


	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;


	mms_par_node_t		*arg;
	mms_par_node_t		*value;

	mms_par_node_t		*work = NULL;


	mms_trace(MMS_DEVP, "mm_parse_unmount_cmd");
	mount_info->cmi_operation = MM_UNMOUNT;

	/* Get the type */
	mms_trace(MMS_DEVP, "type");
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "type",
	    MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_KEYWORD, NULL);
	if (strcmp(value->pn_string, "SIDE") == 0) {
		mount_info->cmi_type = MM_SIDE;
	} else if (strcmp(value->pn_string, "PARTITION") == 0) {
		mount_info->cmi_type = MM_PARTITION;
	} else if (strcmp(value->pn_string, "VOLUME") == 0) {
		mount_info->cmi_type = MM_VOLUME;
	}
	mms_trace(MMS_DEVP, "type %s", value->pn_string);

	if (mms_pn_lookup(cmd->cmd_root, "physicalunmount",
	    MMS_PN_KEYWORD, NULL)) {
		mount_info->cui_physical = 1;
	}
	mms_trace(MMS_DEVP, "physicalunmount %d",
	    mount_info->cui_physical);

	/* signature optional */
	if (arg = mms_pn_lookup(cmd->cmd_root, "signature",
	    MMS_PN_CLAUSE, NULL)) {
		value = mms_pn_lookup(arg, NULL, MMS_PN_KEYWORD,
		    NULL);
		if (value &&
		    strcmp(value->pn_string, "CLEAN") == 0) {
			mount_info->cui_signature_clean = 1;
			mms_trace(MMS_DEVP, "signature clean");
		} else {
			work = NULL;
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, &work);
			mount_info->cui_signature_type =
			    strdup(value->pn_string);
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, &work);
			mount_info->cui_signature =
			    strdup(value->pn_string);
			mms_trace(MMS_DEVP, "signature %s %s",
			    mount_info->cui_signature_type,
			    mount_info->cui_signature);
		}
	} else {
		/* default signature */
		mount_info->cui_signature_clean = 1;
		mms_trace(MMS_DEVP, "signature defaults to clean");
	}

	return (MM_CMD_DONE);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}


PGresult*
mm_unmount_cart_results(mm_wka_t *mm_wka,
    mm_command_t *cmd, mm_db_t *db) {

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	char			*tmp_buf = NULL;

	cci_t			*conn = &mm_wka->wka_conn;
	char			*app_name = conn->cci_client;
	char			*type = NULL;
	int			i;



	mm_clear_source(cmd);
	mm_clear_dest(cmd);
	mm_clear_const(cmd);

	switch (mount_info->cmi_type) {
	case MM_SIDE:
		type = mms_strapp(type, MM_SIDE_STRING);
		break;
	case MM_PARTITION:
		type = mms_strapp(type, MM_PARTITION_STRING);
		break;
	case MM_VOLUME:
		type = mms_strapp(type, MM_VOLUME_STRING);
		break;
	}

	/* Do drive/cart/lib selection using path matching */

	if (mm_get_dest(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our dest info */
		mms_trace(MMS_DEVP, "Dest count is %d", cmd->cmd_dest_num);
		mm_print_char_list(&cmd->cmd_dest_list);
	}

	if (mm_get_const(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our const info */
		mms_trace(MMS_DEVP, "Const count is %d", cmd->cmd_const_num);
		mm_print_char_list(&cmd->cmd_const_list);
	}

	if (cmd->wka_ptr->wka_privilege == MM_PRIV_STANDARD) {
		/* add CARTRIDGEGROUPAPPLICATION constraint */
		(void) mm_add_to_dest(cmd,
		    "CARTRIDGEGROUPAPPLICATION");
		if (tmp_buf)
			free(tmp_buf);
		tmp_buf = NULL;
		tmp_buf = mms_strapp(tmp_buf,
		    "\"CARTRIDGEGROUPAPPLICATION\"."
		    "\"ApplicationName\" = '%s'",
		    app_name);
		(void) mm_add_to_const(cmd, tmp_buf);
		if (tmp_buf)
			free(tmp_buf);
		tmp_buf = NULL;
	}
	/* Constrain to only cartridges mounted by this session */
	/* Maybe a forced unmount will not use this constraint */
	(void) mm_add_to_dest(cmd,
	    "SESSION");
	if (tmp_buf)
		free(tmp_buf);
	tmp_buf = NULL;
	tmp_buf = mms_strapp(tmp_buf,
	    "\"SESSION\"."
	    "\"ConnectionID\" = '%s'",
	    conn->cci_uuid);
	(void) mm_add_to_const(cmd, tmp_buf);
	if (tmp_buf)
		free(tmp_buf);
	tmp_buf = NULL;

	/* Add MOUNTPHYSICAL constraint */
	/* Maybe a forced unmount will not use this constraint */
	(void) mm_add_to_dest(cmd,
	    "MOUNTPHYSICAL");
	if (tmp_buf)
		free(tmp_buf);
	tmp_buf = NULL;
	tmp_buf = mms_strapp(tmp_buf,
	    "(\"MOUNTPHYSICAL\".\"CartridgeID\" "
	    "= \"%s\".\"CartridgeID\")", type);
	(void) mm_add_to_const(cmd, tmp_buf);
	if (tmp_buf)
		free(tmp_buf);
	tmp_buf = NULL;
	/* Make tmp_buf and set source */
	(void) mm_add_to_source(cmd, type);
	tmp_buf = mms_strapp(tmp_buf,
	    "select \"%s\"."
	    "\"CartridgeID\" from\n ", type);
	if (type)
		free(type);
	type = NULL;

	SQL_CHK_LEN(&cmd->cmd_buf, NULL,
	    &cmd->cmd_bufsize, strlen(tmp_buf) + 1);
	strcpy(cmd->cmd_buf, tmp_buf);

	if (tmp_buf)
		free(tmp_buf);
	tmp_buf = NULL;

	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_unmount_cart_results: "
		    "db error creating helper functions");
		return (NULL);
	}


	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		/* no cartridge matches */
		mms_trace(MMS_INFO,
		    "match statment in mount "
		    "didn't match any cartridge/volumes");
		mm_response_error(cmd,
		    ECLASS_EXPLICIT, ENOMATCH,
		    MM_5052_MSG,
		    NULL);
		return (NULL);
	}
	tmp_buf = mms_strapp(tmp_buf,
	    "select distinct \"CartridgeID\","
	    "\"LibraryName\",\"CartridgeGroupPriority\","
	    "\"CartridgeNumberMounts\", "
	    "\"CartridgeTypeName\",\"CartridgePCL\", "
	    "\"CartridgeDriveOccupied\" "
	    "from ( "
	    "select \"CartridgeID\",\"LibraryName\", "
	    "\"CartridgeGroupPriority\","
	    "\"CartridgeNumberMounts\", "
	    "\"CartridgeTypeName\",\"CartridgePCL\", "
	    "\"CartridgeDriveOccupied\" "
	    "from \"CARTRIDGE\",\"CARTRIDGEGROUP\"");
	for (i = 0; i < PQntuples(db->mm_db_results); i++) {
		if (i == 0) {
			tmp_buf = mms_strapp(tmp_buf, "where (");
		} else {
			tmp_buf = mms_strapp(tmp_buf, "or ");
		}
		tmp_buf = mms_strapp(tmp_buf, " (\"CartridgeID\" = '%s')",
		    PQgetvalue(db->mm_db_results, i, 0));
	}
	tmp_buf = mms_strapp(tmp_buf,
	    ") and"
	    "(\"CARTRIDGEGROUP\".\"CartridgeGroupName\" "
	    "= \"CARTRIDGE\".\"CartridgeGroupName\")"
	    "order by \"CARTRIDGE\".\"CartridgeTimeMountedLast\""
	    ") as foo order by \"CartridgeGroupPriority\";");
	mm_clear_db(&db->mm_db_results);
	if (mm_db_exec(HERE, db, tmp_buf) != MM_DB_DATA) {
		if (tmp_buf)
			free(tmp_buf);
		tmp_buf = NULL;
		mm_sql_db_err_rsp_new(cmd, db);
		return (NULL);
	}
	if (tmp_buf)
		free(tmp_buf);
	tmp_buf = NULL;
	return (db->mm_db_results);
no_mem:
	MM_ABORT_NO_MEM();
	return (NULL);
}

int
mm_unmount_ready(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db) {

	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	PGresult		*cart_results;
	int			cart_rows;

	int			found_cart_drive = 0;
	int			found_ready_cart_drive = 0;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	int			rc;

	/* Do drive/cart/lib selection using path matching */
	if ((cart_results = mm_unmount_cart_results(mm_wka,
	    cmd, db)) == NULL) {
		/* No carts or error */
		return (MM_UNMOUNT_ERROR);
	}

	cart_rows = PQntuples(cart_results);
	mms_trace(MMS_DEVP, "Number of Cartridges is %d", cart_rows);
	if (cart_rows == 0) {
		/* No Cartridge Matches Error */
		mms_trace(MMS_INFO,
		    "match statment in mount "
		    "didn't match any cartridge/volumes");
		mm_response_error(cmd,
		    ECLASS_EXPLICIT, ENOMATCH,
		    MM_5052_MSG,
		    NULL);
		mm_clear_db(&cart_results);
		return (MM_UNMOUNT_ERROR);
	}

	/* Create the list objects for */
	/* every cartridge/drive candidate */
	if (mm_mount_init_candidates(cmd, cart_results,
	    db)) {
		mms_trace(MMS_ERR,
		    "error initializing candidate lists");
		/* err buf should be set by mm_mount_init */
		/* so return and remove */
		mm_clear_db(&cart_results);
		return (MM_UNMOUNT_ERROR);
	}
	mms_trace(MMS_DEVP, "candidate list created, check availability ");
	mm_clear_db(&cart_results);
	/* Check the availability of the candidates */
	if (mm_mount_check_candidates(mm_wka, cmd,
	    db)) {
		mms_trace(MMS_ERR,
		    "error checking candidate lists");
		mm_system_error(cmd,
		    "error checking candidate lists");
		return (MM_UNMOUNT_ERROR);
	}
	mms_trace(MMS_DEVP, "done checking list");


	/* Print mount information */
	mm_print_mount_summary(mm_wka, cmd);
	found_cart_drive = 0;
	found_ready_cart_drive = 0;

	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		if (cart->cmi_cart_not_ready)
			cart->cmi_remove_cart = 1;
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			found_cart_drive = 1;
			if ((cart->cmi_cart_not_ready == 0) &&
			    (drive->cmi_drive_not_ready == 0)) {
				found_ready_cart_drive = 1;
			}
			if (drive->cmi_drive_not_ready)
				drive->cmi_remove_drive = 1;
		}
	}


	/* If there is a library or drive error */
	/* the error buff has already been set */
	if (found_cart_drive == 0) {
		mms_trace(MMS_INFO,
		    "No candidate "
		    "cartridge/library/drive "
		    "combination found");
		return (MM_UNMOUNT_ERROR);
	}
	if (found_ready_cart_drive == 0) {
		mms_trace(MMS_INFO,
		    "candidate "
		    "cartridge/library/drive "
		    "combination found, but is not ready");
		return (MM_UNMOUNT_NOT_READY);
	}
	/* There is a ready cart/drive */
	/* we may have set some non ready for remove */
	/* so call the clean func before contine */
	mm_mount_clean_candidates(cmd);
	cmd->cmd_state = 1;
	rc = mm_set_immediate_unmount(cmd, db);

	if (rc == MM_CMD_ERROR) {
		mms_trace(MMS_ERR,
		    "error setting up immediate mount");
		return (MM_UNMOUNT_ERROR);
	}
	mms_trace(MMS_DEVP,
	    "mount ready for dispatch");

	return (MM_UNMOUNT_READY);

}

int
mm_unmount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	int			rc;
	char			*response_message = NULL;

	mms_trace(MMS_DEVP, "mm unmount state %d", cmd->cmd_state);
	mm_print_unmount_state(cmd->cmd_state);

	/* UM_CANDIDATE_SELECTION == 0 */
	if (cmd->cmd_state == UM_CANDIDATE_SELECTION)	{

		mms_trace(MMS_INFO, "Processing Unmount Request...");
		/*
		 * Generate Candidate Cartridge and Drive lists
		 * First parse and save the mount info
		 * then use SQL queries to gereate the lists
		 */

		if (mm_parse_unmount_cmd(mm_wka, cmd) == MM_CMD_ERROR) {
			mms_trace(MMS_ERR,
			    "error parsing unmount command");
			/* Error buf should already be set */
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mms_trace(MMS_DEVP, "done parsing unmount");

		if (mm_set_tm_task(db, cmd) != MM_DB_OK) {
			goto db_error;
		}
		mms_trace(MMS_DEVP,
		    "unmount will be passed to task manager");
		return (MM_WORK_TODO);

	} else if (cmd->cmd_state == UM_DM_DETACH) {
		mms_trace(MMS_INFO, "Unmounting Tape...");
		/*
		 * Add Detach command
		 */
		if (mm_dmp_add_cmd(mm_wka, cmd,
		    mount_info->cmi_dm,
		    MM_DMP_DETACH) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "error adding dmp unload");
			mm_system_error(cmd,
			    "error adding dmp unload");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_state = UM_DM_RELEASE;
		return (MM_DISPATCH_DEPEND);

	}
	if (cmd->cmd_state == UM_DM_RELEASE) {
		/*
		 * Detach has returned
		 * check error, update states
		 * Add release command
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "mmp_unmount-> DMP detach error");

			if ((cmd->cmd_response != NULL) &&
			    mm_errorcode_eq(cmd->cmd_response,
			    "DM_E_NOEXISTHANDLE")) {

				/* DM doesn't know about the handle */
				/* Continue with unmount regardless */
				/* skip unload */
				mms_trace(MMS_DEVP,
				    "DM doesn't know the handle, "
				    "skip DMP unload, "
				    "send LMP unmount");
				mount_info->cui_skip_unload = 1;
				/* Clear depend error flags */
				MM_UNSET_FLAG(cmd->cmd_flags,
				    MM_CMD_DEPEND_ERROR);
			} else {
				mount_info->cmi_reset_states = 1;
				mount_info->cmi_need_clear = 1;
				response_message =
				    mm_ret_response_msg(cmd);
				mm_response_error(cmd,
				    ECLASS_SUBOP,
				    ELMDMCOMMUNICATION,
				    MM_5055_MSG,
				    "msg_rsp", response_message,
				    NULL);
				free(response_message);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;
			}
		}

		if (mm_db_exec(HERE, db, "delete from \"MOUNTLOGICAL\" " \
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleteing MOUNTLOGICAL");
		}
		if (mm_db_exec(HERE, db, "delete from \"STALEHANDLE\" "\
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleteing STALEHANDLE");
		}

		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_RELEASE) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "error adding dmp release");
			mm_system_error(cmd,
			    "error adding dmp release");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_state = UM_SCHEDULE_UNLOAD;
		return (MM_DISPATCH_DEPEND);
	}
	if (cmd->cmd_state == UM_SCHEDULE_UNLOAD) {
		/*
		 * release command has returned
		 * check for errors, update states
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "mmp_unmount-> DMP release error");
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    MM_5055_MSG,
			    "msg_rsp", mm_ret_response_msg(cmd),
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}

		if (mount_info->cui_physical) {
			/* This is a physical unmount */
			cmd->cmd_state = UM_LM_UNMOUNT;

			if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
			    MM_DMP_UNLOAD) == NULL) {
				mms_trace(MMS_ERR,
				    "mm_unmount_cmd_func: "
				    "error adding dmp unload");
				mm_system_error(cmd,
				    "error adding dmp unload");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			rc = MM_DISPATCH_DEPEND;
			goto end;

		}
		/* Delayed unmount */

		mms_trace(MMS_DEVP,
		    "DELAY UNLOAD NOW!!!!");

		/* update drive and cartridge states */
		if (mm_db_exec(HERE, db, "update \"DRIVE\" set "
		    "\"DriveStateSoft\" = 'ready',"
		    "\"DMName\" = ''"
		    " where "
		    "\"DriveName\" = '%s';",
		    cmd->cmd_mount_info.cmi_drive) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error updating DriveStateSoft");
		}

		if (mm_db_exec(HERE, db,
		    "update \"CARTRIDGE\" set \"CartridgeStatus\" "
		    "= 'available' where "
		    "\"CartridgeID\" = '%s';",
		    cmd->cmd_mount_info.cmi_cartridge) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error updating CartridgeStatus");
		}

		if (mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\""
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASKCARTRIDGE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKDRIVE\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASKDRIVE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASKLIBRARY");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASK\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASK");
		}
		if (mm_db_exec(HERE, db, "delete from \"MOUNTPHYSICAL\" "
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting MOUNTPHYSICAL");
		}


		if (mm_schedule_unload(mm_wka, cmd)) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "error scheduling unload");
		}
		/* Send success for the unmount */
		mm_path_match_report(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		rc = MM_DISPATCH_AGAIN;
		goto end;

	}

	if (cmd->cmd_state == UM_LM_UNMOUNT) {
		mm_command_t		*lmp_umnt_cmd;
		mm_wka_t		*lm_wka;
		uuid_text_t		 new_task;
		char			*cart_pcl;
		char			*side_name;

		/*
		 * Unload has returned
		 * check error, update states
		 * Add release command
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;

			mms_trace(MMS_DEVP, "mmp_unmount-> DMP unload error");
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    MM_5055_MSG,
			    "msg_rsp", response_message,
			    NULL);
			free(response_message);
			cmd->cmd_remove = 1;

			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);

			rc = MM_CMD_ERROR;
			goto end;
		}

		/*
		 * Cartridge pcl and side name
		 */
		if ((cart_pcl = mm_get_cart_pcl(cmd,
		    cmd->cmd_mount_info.cmi_cartridge, db)) == NULL) {
			cmd->cmd_remove = 1;
			mms_trace(MMS_ERR,
			    "mm_get_cart_pcl error");
			return (MM_CMD_ERROR);
		}


		/* TODO side name needs to be generated in candidate query */
		if ((side_name = cmd->cmd_mount_info.cmi_side_name) == NULL) {
			side_name = "side 1";
		}

		/*
		 * LMP unmount command
		 */
		lm_wka = mm_library_lm_wka(cmd->wka_ptr->mm_data,
		    cmd->cmd_mount_info.cmi_library, NULL);
		if ((lmp_umnt_cmd = mm_alloc_cmd(lm_wka)) == NULL) {
			mms_trace(MMS_ERR,
			    "Unable to malloc mm_command_t: %s",
			    strerror(errno));
			return (MM_CMD_ERROR);
		}
		lmp_umnt_cmd->cmd_func = mm_lmp_unmount_cmd_func;
		mm_get_uuid(new_task);
		lmp_umnt_cmd->cmd_textcmd = mms_strnew(LMP_UNMOUNT, new_task,
		    cart_pcl, cart_pcl, side_name,
		    cmd->cmd_mount_info.cmi_drive,
		    cart_pcl, cart_pcl, side_name);
		mm_set_mount_info_drive(cmd->cmd_mount_info.cmi_drive,
		    &lmp_umnt_cmd->cmd_mount_info);
		mm_set_mount_info_pcl(cart_pcl,
		    &lmp_umnt_cmd->cmd_mount_info);
		lmp_umnt_cmd->cmd_root =
		    mm_text_to_par_node(lmp_umnt_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		lmp_umnt_cmd->cmd_task = mm_get_task(lmp_umnt_cmd->cmd_root);
		mm_add_depend(lmp_umnt_cmd, cmd);
		lmp_umnt_cmd->cmd_name = strdup("lmp unmount");

		cmd->cmd_state = UM_FINAL;

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->
		    mm_cmd_queue, lmp_umnt_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		free(cart_pcl);

		return (MM_DISPATCH_DEPEND);

	} else if (cmd->cmd_state == UM_FINAL) {

		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "lm unmount failed");
			mount_info->cmi_reset_states = 1;
			mount_info->cmi_need_clear = 1;
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    MM_5055_MSG,
			    "msg_rsp", response_message,
			    NULL);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}

		/*
		 * TEMPORARY update drive states remove TASK objs
		 */

		/* If cmd_depend is set this is part of a begin-end group */
		/* so do not reset the drive state */
		if (mm_has_depend(cmd) == 0) {
			if (mm_db_exec(HERE, db, "update \"DRIVE\" set "
			    "\"DriveStateSoft\" = 'ready',"
			    "\"DMName\" = '',"
			    "\"DriveStateHard\" = 'unloaded' where "
			    "\"DriveName\" = '%s';",
			    cmd->cmd_mount_info.cmi_drive) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_unmount_cmd_func: "
				    "db error updating DRIVE");
			}

		} else {
			if (mm_db_exec(HERE, db, "update \"DRIVE\" set "
			    "\"DMName\" = '',"
			    "\"DriveStateHard\" = 'unloaded' where "
			    "\"DriveName\" = '%s';",
			    cmd->cmd_mount_info.cmi_drive) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_unmount_cmd_func: "
				    "db error updating DRIVE");
			}
		}
		if (mm_db_exec(HERE, db,
		    "update \"CARTRIDGE\" set \"CartridgeStatus\" "
		    "= 'available' where "
		    "\"CartridgeID\" = '%s';",
		    cmd->cmd_mount_info.cmi_cartridge) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error updating CartridgeStatus");
		}


		if (mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\""
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASKCARTRIDGE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKDRIVE\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASKDRIVE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASKLIBRARY");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASK\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting TASK");
		}
		if (mm_db_exec(HERE, db, "delete from \"MOUNTPHYSICAL\" "
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_unmount_cmd_func: "
			    "db error deleting MOUNTPHYSICAL");
		}

		/*
		 * Report clause.
		 */

		mm_path_match_report(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		mms_trace(MMS_INFO, "Tape Unmounted Successfully");

		if (mm_has_depend(cmd)) {
			mm_command_t *cur_depend = NULL;
			mms_list_foreach(&cmd->cmd_depend_list, cur_depend) {
				if (cur_depend->cmd_func ==
				    mm_delay_unmount_cmd_func) {
					mms_trace(MMS_DEVP,
					    "this delay unmount has "
					    "delay unmount as parent,"
					    " set parent ready for dispatch");
					mm_set_unload_dispatch(cur_depend,
					    NULL);
				}
			}
			rc = MM_DEPEND_DONE;
			goto end;
		}
		rc = MM_CMD_DONE;
		goto end;
	}
	mms_trace(MMS_ERR, "Unknown state");
	cmd->cmd_remove = 1;
	rc = MM_CMD_ERROR;
	goto end;

no_mem:
	MM_ABORT_NO_MEM();
	rc = MM_CMD_ERROR;
	goto end;

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;
db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn,
	    cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;

end:
	return (rc);

}



int
mm_begin_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t		*arg;
	mms_par_node_t		*value;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;

	mms_trace(MMS_DEVP, "sql trans begin cmd");
	if (cmd->cmd_state == 0) {
		mms_trace(MMS_DEVP, "when");
		arg = mms_pn_lookup(cmd->cmd_root, "when",
		    MMS_PN_CLAUSE, NULL);
		if (arg != NULL) {
			MMS_PN_LOOKUP(value,
			    arg, NULL, MMS_PN_KEYWORD, NULL);
			if (strcmp(value->pn_string, "blocking") == 0) {
				mm_wka->wka_begin_end.be_mode =
				    ACCESS_MODE_BLOCKING;
			} else {
				mm_wka->wka_begin_end.be_mode =
				    ACCESS_MODE_IMMEDIATE;
			}
		} else {
			/* when is optional and defaults to immediate */
			mm_wka->wka_begin_end.be_mode = ACCESS_MODE_IMMEDIATE;
		}
		mms_trace(MMS_DEVP, "ready for mount unmount command group");
		/* return MM_DISPATCH_DEPEND??? */
		cmd->cmd_state = 1;
		return (MM_DISPATCH_DEPEND);
	}
	if (cmd->cmd_state == 1) {
		/* when End has been accepted, send success for begin */
		/* Send success */
		mm_path_match_report(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		return (MM_DEPEND_DONE);
	}

	mms_trace(MMS_ERR,
	    "bad command state- begin command");
	mm_system_error(cmd,
	    "bad command state- begin command");
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	mm_wka->wka_begin_end.be_active = B_FALSE;
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
}


void
mm_mv_beginend(mm_command_t *begin, mm_command_t *end) {
	/* begin end command list */
	mm_command_t *cur_cmd;
	mm_command_t *next_cmd;

	/* Move beginend commands from begin to end */
	for (cur_cmd = mms_list_head(&begin->cmd_beginend_list);
	    cur_cmd != NULL;
	    cur_cmd = next_cmd) {
		next_cmd =
		    mms_list_next(&begin->cmd_beginend_list,
		    cur_cmd);
		mms_list_remove(&begin->cmd_beginend_list,
		    cur_cmd);
		mms_list_insert_tail(&end->cmd_beginend_list,
		    cur_cmd);
	}
}

int
mm_be_parse_cmds(mm_command_t *cmd) {

	mm_command_t	*cur_cmd;
	int		cmd_count = 0;
	mm_wka_t	*mm_wka = cmd->wka_ptr;

	cmd_count = 0;
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		cmd_count ++;
		mms_trace(MMS_DEVP,
		    "Begin-end cmd %d, %s",
		    cmd_count, cur_cmd->cmd_name);

		if (cur_cmd->cmd_func == mm_mount_cmd_func) {
			if (mm_parse_mount_cmd(cur_cmd->wka_ptr,
			    cur_cmd) == MM_CMD_ERROR) {
				mms_trace(MMS_ERR,
				    "error parsing unmount command");
				/* Error buf should already be set */
				return (-1);
			}
		} else {
			if (mm_parse_unmount_cmd(cur_cmd->wka_ptr,
			    cur_cmd) == MM_CMD_ERROR) {
				mms_trace(MMS_ERR,
				    "error parsing unmount command");
				/* Error buf should already be set */
				return (-1);
			}
		}
		if (mm_wka->wka_begin_end.be_mode == ACCESS_MODE_IMMEDIATE) {
			cur_cmd->cmd_mount_info.cmi_when = MM_IMMEDIATE;
		} else {
			cur_cmd->cmd_mount_info.cmi_when = MM_BLOCKING;
		}
	}
	return (cmd_count);
}

int
mm_end_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_command_t		*be_command = NULL;
	int			cmd_count;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;

	mms_trace(MMS_DEVP, "mm_end_cmd_func");
	if (cmd->cmd_state == 0) {
		be_command = cmd->cmd_begin_cmd;
		if (be_command == NULL) {
			mms_trace(MMS_ERR,
			    "couldn't find begin for this end");
			mm_system_error(cmd,
			    "couldn't find begin for this end");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		/* Copy begin cmd list ptr */
		/* set begin for dispatch */
		/* as depend */
		mm_add_depend(be_command, cmd);
		mm_mv_beginend(be_command, cmd);
		MM_SET_FLAG(be_command->cmd_flags,
		    MM_CMD_DISPATCHABLE);
		cmd->cmd_state = 1;
		return (MM_DISPATCH_DEPEND);
	}
	if (cmd->cmd_state == 1) {
		/* Begin has returned success */

		/* abort command group */
		if (mms_pn_lookup(cmd->cmd_root, "abort",
		    MMS_PN_KEYWORD, NULL)) {
			/* Cancel all the commands */
			/* and return success for the abort */
			mms_trace(MMS_DEVP, "begin-end abort");
			mm_path_match_report(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			tm_be_cancel_all(cmd);
			return (MM_CMD_DONE);
		}

		if ((cmd_count = mm_be_parse_cmds(cmd)) == -1) {
			/* Error parsing a command */
			mm_system_error(cmd,
			    "error parsing mount/unmount "
			    "inside begin-end group");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);

		} else if (cmd_count == 0) {
			/* No commands in this command group */
			/* Send success ??? */
			mm_path_match_report(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_response(mm_wka->mm_wka_conn, cmd);
			return (MM_CMD_DONE);
		}

		mms_trace(MMS_DEVP,
		    "done parsing %d commands for begin-end group",
		    cmd_count);
		if (mm_set_tm_task(db, cmd) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_state = 2;
		mms_trace(MMS_DEVP,
		    "begin-end group will be passed to task manager");

		return (MM_WORK_TODO);
	}
	if (cmd->cmd_state == 2) {
		/* Task manager has dispatched this command */
		/* Send success for end */
		mms_trace(MMS_DEVP, "end command state 2");

		cmd->cmd_remove = 1;
		return (MM_CMD_DONE);
	}
	mms_trace(MMS_ERR,
	    "bad command state- end command");
	mm_system_error(cmd,
	    "bad command state- end command");
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}
