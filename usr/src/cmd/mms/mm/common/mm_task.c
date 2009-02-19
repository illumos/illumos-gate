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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <libpq-fe.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_sql.h"
#include "mm_commands.h"
#include "mm_sql.h"
#include "mm_sql_impl.h"
#include "mm_task.h"

static char *_SrcFile = __FILE__;

#define	MM_BE_ERROR 0
#define	MM_BE_DISPATCH 1
#define	MM_BE_BLOCKING 2
#define	MM_BE_OK 3

cmi_drive_list_t *
tm_return_drive_ptr(char *drive, cmi_cart_list_t *cart) {
	/* if drive is NULL return the 1st drive in the list */
	cmi_drive_list_t	*cur_drive = NULL;

	if (drive == NULL) {
		cur_drive = mms_list_head(&cart->cmi_drive_list);
		if (cur_drive == NULL) {
			mms_trace(MMS_ERR,
			    "1st drive was NULL");
		}
		return (cur_drive);

	}

	mms_list_foreach(&cart->cmi_drive_list, cur_drive) {
		if (strcmp(cur_drive->cmi_drive_name,
			drive) == 0) {
			return (cur_drive);
		}
	}
	return (NULL);
}

cmi_cart_list_t *
tm_return_cart_ptr(char *cart_id, cmd_mount_info_t *mount_info) {
	cmi_cart_list_t	*cur_cart;
	mms_list_foreach(&mount_info->cmi_cart_list, cur_cart) {
		if (strcmp(cur_cart->cmi_cart_id,
			cart_id) == 0) {
			return (cur_cart);
		}
	}
	return (NULL);
}


char *
tm_return_dm_name(char *drive_name, char *host, mm_data_t *mm_data) {
	/* Return the dm name for drive_name on host */
	mm_db_t			*db = &mm_data->mm_db_tm;
	char			*dm_name = NULL;
	if (mm_db_exec(HERE, db,
		    "select \"DMName\" from \"DM\" "
		    "where \"DM\".\"DriveName\" = '%s' and "
		    " pg_host_ident(\"DMTargetHost\") "
		    "= pg_host_ident('%s');",
		    drive_name, host) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error, tm_return_dm_name");
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR,
		    "row num mismatch , tm_return_dm_name");
		return (NULL);
	}
	dm_name = mms_strapp(dm_name, PQgetvalue(db->mm_db_results, 0, 0));
	mm_clear_db(&db->mm_db_results);
	return (dm_name);
}

int
tm_can_dispatch_mount(mm_command_t *cmd, mm_data_t *mm_data)
{

	/* Use this function for both unmout and mounts */
	mm_db_t			*db = &mm_data->mm_db_tm;

	mm_wka_t		*mm_wka = cmd->wka_ptr;


	int			rc;

	mms_trace(MMS_DEVP,
	    "tm_can_dispatch_mount");

	rc = mm_mount_ready(mm_wka, cmd, db, 0);
	switch (rc) {

	case MM_MOUNT_ERROR:
		/* Error code should be set */
		mms_trace(MMS_ERR,
		    "internal error, mm_mount_ready");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (0);

	case MM_MOUNT_READY:
		/* The mount is ready, mount_info should be set */
		/* continue to state 1 */
		cmd->cmd_state = 1;
		mms_trace(MMS_DEVP,
		    "mount is ready to go, "
		    "continue to state 1");
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_DISPATCHABLE);
		return (1);

	case MM_MOUNT_NEED_UNLOAD:
		/* this immediate mount needs to */
		/* wait for an unload */
		cmd->cmd_state = 1;
		mms_trace(MMS_DEVP,
		    "mount waiting "
		    "for unload to complete");
		return (1);

	case MM_MOUNT_NOT_READY:
		/* Error code should be set */
		mms_trace(MMS_ERR,
		    "blocking mount not ready, "
		    "wait longer and try later");
		return (0);

	default:
		mms_trace(MMS_ERR,
		    "bad rc mm_mount_ready");
		mm_system_error(cmd,
		    "bad rc mm_mount_ready");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (0);
	}

}



PGresult* tm_get_inuse_carts(mm_command_t *cmd,  mm_data_t *mm_data) {
	/* returns ordered list of inuse candidate cartridges */
	/* for task_id */

	mm_db_t			*db = &mm_data->mm_db_tm;
	char			*task_id = cmd->cmd_uuid;

	if (mm_db_exec(HERE, db, "select \"CartridgeID\" "
			"from \"CARTRIDGE\" "
			"where \"CartridgeStatus\" = 'in use' "
			"and \"CartridgeID\" "
			"in (select distinct \"CartridgeID\" "
			"from \"TASKCARTRIDGE\" "
			"where \"TaskID\" = '%s') "
			"order by \"CartridgeNumberMounts\";",
			task_id) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db_error, tm_get_inuse_carts");
		return (NULL);
	}
	return (db->mm_db_results);
}

int
tm_can_dispatch_unmount(mm_command_t *cmd, mm_data_t *mm_data)
{
	mm_db_t			*db = &mm_data->mm_db_tm;
	mm_wka_t		*mm_wka = cmd->wka_ptr;

	int			rc;

	mms_trace(MMS_DEVP,
	    "tm_can_dispatch_unmount");

	rc = mm_unmount_ready(mm_wka, cmd, db);
	switch (rc) {

	case MM_UNMOUNT_ERROR:
		/* Error code should be set */
		mms_trace(MMS_ERR,
		    "internal error, mm_unmount_ready");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (0);

	case MM_UNMOUNT_READY:
		/* The unmount is ready, unmount_info should be set */
		/* continue to state 1 */
		cmd->cmd_state = 1;
		mms_trace(MMS_DEVP,
		    "unmount is ready to go, "
		    "continue to state 1");
		return (1);

	case MM_UNMOUNT_NOT_READY:
		/* Error code should be set */
		mms_trace(MMS_ERR,
		    "blocking unmount not ready, "
		    "wait longer and try later");
		return (0);
	default:
		mms_trace(MMS_ERR,
		    "bad rc mm_unmount_ready");
		mm_system_error(cmd,
		    "bad rc mm_unmount_ready");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (0);
	}

}

int
mm_be_remove_non_ready(mm_command_t *cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;
	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		if (cart->cmi_cart_not_ready) {
			cart->cmi_remove_cart = 1;
		}
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			if (drive->cmi_drive_not_ready) {
				drive->cmi_remove_drive = 1;
			}
		}
	}
	mm_mount_clean_candidates(cmd);
	return (0);
}

int
tm_be_unmount_ready(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db,
		mm_command_t *end_cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	PGresult		*cart_results;
	int			cart_rows;

	int			found_cart_drive = 0;
	int			found_ready_cart_drive = 0;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	/* Do drive/cart/lib selection using path matching */
	if ((cart_results = mm_unmount_cart_results(mm_wka,
		cmd, db)) == NULL) {
		mm_system_error(end_cmd,
			"error getting candidate "
			"cartridge");
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
		mm_response_error(end_cmd,
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
		mm_system_error(end_cmd,
				"error init candidate lists");
		return (MM_UNMOUNT_ERROR);
	}
	mms_trace(MMS_DEVP, "candidate list created, check availability ");

	/* Check the availability of the candidates */
	if (mm_mount_check_candidates(mm_wka, cmd,
				    db)) {
		mms_trace(MMS_ERR,
		    "error checking candidate lists");
		mm_system_error(end_cmd,
				"error checking candidate lists");
		return (MM_UNMOUNT_ERROR);
	}
	mms_trace(MMS_DEVP, "done checking list");

	/* Print mount information */
	mm_print_mount_summary(mm_wka, cmd);
	found_cart_drive = 0;
	found_ready_cart_drive = 0;

	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			found_cart_drive = 1;
			if ((cart->cmi_cart_not_ready == 0) &&
			    (drive->cmi_drive_not_ready == 0)) {
				found_ready_cart_drive = 1;
			}
		}
	}


	/* If there is a library or drive error */
	/* the error buff has already been set */
	if (found_cart_drive == 0) {
		mms_trace(MMS_ERR,
		    "No candidate "
		    "cartridge/library/drive "
		    "combination found");
		mm_response_error(end_cmd,
		    ECLASS_EXPLICIT,
		    "ENOSOLUTIONS",
		    MM_5105_MSG,
		    NULL);
		return (MM_UNMOUNT_ERROR);
	}
	if (found_ready_cart_drive == 0) {
		mms_trace(MMS_ERR,
		    "candidate "
		    "cartridge/library/drive "
		    "combination found, but is not ready");
		mm_response_error(end_cmd,
		    ECLASS_RETRY,
		    "ETMPUNAVAIL",
		    MM_5104_MSG,
		    NULL);
		return (MM_UNMOUNT_NOT_READY);
	}

	return (MM_UNMOUNT_READY);

}

int
tm_be_mount_ready(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db,
		mm_command_t *end_cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	PGresult		*cart_results;
	int			cart_rows;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;


	int			found_cart_drive = 0;
	int			found_ready_cart_drive = 0;

	char			*err_text = NULL;


	/* Need to set end_cmd buf correctly for any MM_MOUNT_ERROR return */


	/* Do drive/cart/lib selection using path matching */
	if ((cart_results = mm_mount_cart_results(mm_wka,
		cmd, db)) == NULL) {
		mm_system_error(end_cmd,
			"error getting candidate "
			"cartridge");
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
		mm_response_error(end_cmd,
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
		mm_system_error(end_cmd,
				"error init candidate lists");
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
		mm_system_error(end_cmd,
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

	mms_list_foreach(&mount_info->cmi_cart_list, cart) {
		mms_list_foreach(&cart->cmi_drive_list, drive) {
			found_cart_drive = 1;
			if ((cart->cmi_cart_not_ready == 0) &&
			    (drive->cmi_drive_not_ready == 0)) {
				found_ready_cart_drive = 1;
			}
		}
	}


	/* If there is a library or drive error */
	/* the error buff has already been set */
	if (found_cart_drive == 0) {
		mms_trace(MMS_ERR,
		    "No candidate "
		    "cartridge/library/drive "
		    "combination found");

		/* If this cmd has a retry error class */
		/* Send a retry error */
		if (strcmp(cmd->cmd_eclass, ECLASS_RETRY) == 0) {
			/* This is a retry error */
			mms_trace(MMS_ERR,
			    "Error is from a retry error");

			mm_response_error(end_cmd,
			    ECLASS_RETRY,
			    "ETMPUNAVAIL",
			    MM_5104_MSG,
			    NULL);
			return (MM_MOUNT_ERROR);
		}
		err_text = mm_return_err_text(cmd->cmd_err_ptr);
		mm_response_error(end_cmd,
		    ECLASS_EXPLICIT,
		    "ENOSOLUTIONS",
		    MM_5110_MSG,
		    "err_text", err_text,
		    NULL);
		free(err_text);
		return (MM_MOUNT_ERROR);
	}
	if (found_ready_cart_drive == 0) {
		mms_trace(MMS_ERR,
		    "candidate "
		    "cartridge/library/drive "
		    "combination found, but is not ready");

		mm_response_error(end_cmd,
		    ECLASS_RETRY,
		    "ETMPUNAVAIL",
		    MM_5104_MSG,
		    NULL);

		return (MM_MOUNT_NOT_READY);
	}

	return (MM_MOUNT_READY);
}

#define	TM_CANCEL_RESPONSE "response task[\"%s\"] cancelled;"

void
mm_cancel_cmd_buf(mm_command_t *cmd) {
	char			*buf = NULL;
	buf = mms_strnew(TM_CANCEL_RESPONSE, cmd->cmd_task);
	SQL_CHK_LEN(&cmd->cmd_buf, 0,
	    &cmd->cmd_bufsize, strlen(buf) + 1);
	strcpy(cmd->cmd_buf, buf);
	free(buf);
	buf = NULL;
	return;
no_mem:
	MM_ABORT_NO_MEM();
}

void
tm_be_cancel_all(mm_command_t *cmd) {
	mm_command_t		*cur_cmd;

	/* Send cancel for all commands in this group */
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		mm_cancel_cmd_buf(cur_cmd);

		mm_send_text(cur_cmd->wka_ptr->mm_wka_conn,
			cur_cmd->cmd_buf);
	}

}

int
tm_be_set_mount(mm_command_t *cmd, mm_db_t *db,
		mm_command_t *end_cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	char			*drive_to_unload = NULL;
	char			*lib_to_unload = NULL;



	/* cmd is the mount command */
	MM_SET_FLAG(cmd->cmd_flags,
		    MM_CMD_DISPATCHABLE);
	cmd->cmd_state = 1;

	/* This code is the same code as is in mm_set_immediate_mount */
	/* make a common function?? */
	if (mm_mount_candidate_loaded(cmd)) {
		mms_trace(MMS_DEVP,
		    "a candidate cartridge is loaded");
		mount_info->cmi_mount_type =
		    MM_CANDIDATE_LOADED;
	} else if (mm_mount_open_drive(cmd)) {
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
		} else {
			mms_trace(MMS_DEVP,
			    "candidate loaded in non-candidate drive "
			    "must unload 1st");
			/* Need to set up parent command */
			/* return as dispatch depend */
			mms_trace(MMS_DEVP,
			    "%s needs unload to complete first",
			    drive_to_unload);
			mount_info->cmi_mount_type =
			    MM_UNMOUNT_CART;
			mount_info->cmi_first_drive =
			    strdup(drive_to_unload);
			mount_info->cmi_first_lib =
			    strdup(lib_to_unload);
			MM_UNSET_FLAG(cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
			free(drive_to_unload);
			free(lib_to_unload);
		}
	} else if (mm_unmount_2_drive(cmd, db)) {
		/* 3 mount time  */
		/* Candidate cart is mounted, */
		/* the only candidate drive is loaded with non-candidate */
		/* need to unmount candidate cart, unmount candidate drive */
		/* then mount candidate cart/drive */
		MM_UNSET_FLAG(cmd->cmd_flags, MM_CMD_DISPATCHABLE);

	} else {
		mms_trace(MMS_ERR,
		    "no drives found due to other candidates");
		mm_set_least_severe(cmd);
		if (cmd->cmd_err_ptr == NULL) {
			mms_trace(MMS_ERR,
			    "cmd has no errors, set ENOMATCH");
			mm_response_error(end_cmd,
			    ECLASS_EXPLICIT, ENOMATCH,
			    MM_5052_MSG,
			    NULL);
		}
		return (MM_BE_ERROR);
	}

	/* Select Is done - print the results */
	mms_trace(MMS_DEVP, "Cart/Lib/Drive selection "
		"complete for task %s",
		cmd->cmd_uuid);
	mms_trace(MMS_DEVP, "Cartridge ID is %s",
		mount_info->cmi_cartridge);
	mms_trace(MMS_DEVP, "Library is %s",
		mount_info->cmi_library);
	mms_trace(MMS_DEVP, "Drive is %s",
		mount_info->cmi_drive);
	mms_trace(MMS_DEVP, "DM is %s",
		mount_info->cmi_dm);

	/* since this mount will work, clear the error flags for it */
	if (cmd->cmd_eclass != NULL) {
		free(cmd->cmd_eclass);
		cmd->cmd_eclass = NULL;
	}
	if (cmd->cmd_ecode != NULL) {
		free(cmd->cmd_ecode);
		cmd->cmd_ecode = NULL;
	}
	cmd->cmd_mount_info.cmi_mount_ok = 1;

	return (MM_BE_DISPATCH);
}

int
tm_be_set_unmount(mm_wka_t *mm_wka, mm_command_t *cmd,
	mm_command_t *end_cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*cur_cartid = NULL;
	char			*cur_library = NULL;
	char			*cur_dm = NULL;
	char			*cur_drive = NULL;

	/* cmd is the unmount command */

	cart = mms_list_head(&mount_info->cmi_cart_list);
	if (cart == NULL) {
		mm_response_error(end_cmd,
		    ECLASS_RETRY,
		    "ETMPUNAVAIL",
		    MM_5104_MSG,
		    NULL);
		if (mm_wka->wka_begin_end.be_mode ==
		    ACCESS_MODE_BLOCKING) {
			return (MM_BE_BLOCKING);
		}
		mms_trace(MMS_ERR,
		    "unmount has no candidates"
		    " due to other unmount");
		return (MM_BE_ERROR);
	}
	cur_library = cart->cmi_library;
	cur_cartid = cart->cmi_cart_id;

	drive = mms_list_head(&cart->cmi_drive_list);
	if (drive == NULL) {
		mm_response_error(end_cmd,
		    ECLASS_RETRY,
		    "ETMPUNAVAIL",
		    MM_5104_MSG,
		    NULL);
		if (mm_wka->wka_begin_end.be_mode ==
		    ACCESS_MODE_BLOCKING) {
			return (MM_BE_BLOCKING);
		}
		mms_trace(MMS_ERR,
		    "unmount has no candidates"
		    " due to other unmount");
		return (MM_BE_ERROR);
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

	/* Select Is done - print the results */
	mms_trace(MMS_DEVP, "Cart/Lib/Drive selection "
	    "complete for task %s",
	    cmd->cmd_uuid);
	mms_trace(MMS_DEVP, "Cartridge ID is %s",
	    mount_info->cmi_cartridge);
	mms_trace(MMS_DEVP, "Library is %s",
	    mount_info->cmi_library);
	mms_trace(MMS_DEVP, "Drive is %s",
	    mount_info->cmi_drive);
	mms_trace(MMS_DEVP, "DM is %s",
	    mount_info->cmi_dm);

	return (MM_BE_DISPATCH);
}

void
tm_be_rm_error_candidates(mm_command_t *cmd, mm_command_t *err_cmd) {
	/* remove candidates set in err_cmd */
	/* from the beginend candidatea list in cmd */

	mm_cmd_err_t	*err = err_cmd->cmd_err_ptr;
	mm_command_t		*cur_cmd;
	cmd_mount_info_t	*cur_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	mms_list_t			*cart_list;

	int			seen_same = 0;
	mm_cmd_err_t		*cur_err = NULL;

	mms_trace(MMS_DEVP,
	    "tm_be_rm_error_candidates: ");
	if (err == NULL) {
		mms_trace(MMS_ERR,
		    "tm_be_rm_error_candidates: "
		    "error ptr set to NULL");
		return;
	}

	mms_trace(MMS_DEVP,
	    "  Error to remove:");
	mm_print_err(err);

	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		/* same command */
		if (cur_cmd == err_cmd) {
			seen_same = 1;
			continue;
		}
		if (seen_same == 0) {
			continue;
		}

		/* check cur_cmd's error */
		mms_list_foreach(&cur_cmd->cmd_err_list, cur_err) {
			if (mm_same_err(err, cur_err)) {
			cur_err->err_already_used = 1;
			mms_trace(MMS_DEVP,
			    "  matched an err");
			}
		}
		cur_cmd->cmd_err_ptr = NULL;
		mm_set_least_severe(cur_cmd);

		cur_mount_info = &cur_cmd->cmd_mount_info;
		cart_list = &cur_mount_info->cmi_cart_list;
		mms_list_foreach(cart_list, cart) {
			/* Check this cart */
			if ((err->retry_cart != NULL) &&
			    (cart->cmi_cart_id != NULL) &&
			    (strcmp(err->retry_cart,
			    cart->cmi_cart_id) == 0)) {
				cart->cmi_cart_used = 1;
				mms_trace(MMS_DEVP,
				    "tm_be_rm_error_candidates: "
				    "set a cart as used");
			}
			mms_list_foreach(&cart->cmi_drive_list, drive) {
				/* check this drive */
				if ((err->retry_drive != NULL) &&
				    (drive->cmi_drive_name != NULL) &&
				    (strcmp(err->retry_drive,
				    drive->cmi_drive_name) == 0)) {
					drive->cmi_drive_used = 1;
					mms_trace(MMS_DEVP,
					    "tm_be_rm_error_candidates: "
					    "set a drive as used");
				}
			}
		}
	}
}

void
tm_be_rm_mount_candidates(mm_command_t *cmd, mm_command_t *set_cmd) {
	/* remove candidates set in set_cmd */
	/* from the beginend candidatea list in cmd */
	mm_command_t		*cur_cmd;
	cmd_mount_info_t	*set_mount_info = &set_cmd->cmd_mount_info;
	cmd_mount_info_t	*cur_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	mms_list_t			*cart_list;

	int			seen_same = 0;

	mms_trace(MMS_DEVP,
	    "set %s and %s as used candidates",
	    set_mount_info->cmi_cartridge,
	    set_mount_info->cmi_drive);
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		/* same command */
		if (cur_cmd == set_cmd) {
			seen_same = 1;
			continue;
		}
		if (seen_same == 0) {
			continue;
		}
		cur_mount_info = &cur_cmd->cmd_mount_info;
		cart_list = &cur_mount_info->cmi_cart_list;
		mms_list_foreach(cart_list, cart) {
			if (strcmp(set_mount_info->cmi_cartridge,
				cart->cmi_cart_id) == 0) {
				cart->cmi_cart_used = 1;
			}
			mms_list_foreach(&cart->cmi_drive_list, drive) {
				if (strcmp(set_mount_info->cmi_drive,
					drive->cmi_drive_name) == 0) {
					drive->cmi_drive_used = 1;
				}
			}
		}
	}
}

void
tm_be_rm_unmount_candidates(mm_command_t *cmd, mm_command_t *set_cmd) {
	/* remove candidates set in set_cmd */
	/* from the beginend candidatea list in cmd */
	mm_command_t		*cur_cmd;
	cmd_mount_info_t	*set_mount_info = &set_cmd->cmd_mount_info;
	cmd_mount_info_t	*cur_mount_info;
	cmi_cart_list_t		*cart = NULL;

	cmi_drive_list_t	*drive = NULL;


	mms_list_t			*cart_list;

	int			seen_same = 0;

	mms_trace(MMS_DEVP,
	    "remove %s and %s from candidate lists",
	    set_mount_info->cmi_cartridge,
	    set_mount_info->cmi_drive);
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_mount_cmd_func) {
			/* not an unmount */
			continue;
		}
		/* same command */
		if (cur_cmd == set_cmd) {
			seen_same = 1;
			continue;
		}
		if (seen_same == 0) {
			continue;
		}
		cur_mount_info = &cur_cmd->cmd_mount_info;
		cart_list = &cur_mount_info->cmi_cart_list;
		mms_list_foreach(cart_list, cart) {
			if (strcmp(set_mount_info->cmi_cartridge,
				cart->cmi_cart_id) == 0) {
				cart->cmi_remove_cart = 1;
			}
			mms_list_foreach(&cart->cmi_drive_list, drive) {
				if (strcmp(set_mount_info->cmi_drive,
					drive->cmi_drive_name) == 0) {
					drive->cmi_remove_drive = 1;
				}
			}
		}
		mm_mount_clean_candidates(cur_cmd);
	}
}

int
tm_be_is_in_unmount(char *drive_name, mm_command_t *end_cmd) {
	mm_command_t		*cur_cmd;

	mms_list_foreach(&end_cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_mount_cmd_func) {
			/* not an unmount */
			continue;
		}
		if (strcmp(cur_cmd->cmd_mount_info.cmi_drive,
			drive_name) == 0) {
			return (1);
		}
	}
	return (0);
}

int
tm_be_init_mount(mm_command_t *end_cmd, mm_db_t *db) {
	/* this function needs to initialize the mount cmd's */
	/* Candidate lists using the selected carts/drives */
	/* in the unmount commands */
	/* tm_be_match_mount will match mounts to unmounts */

	PGresult		*cart_results;
	int			cart_rows;

	mm_wka_t		*mm_wka = end_cmd->wka_ptr;

	mm_command_t		*cur_cmd;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;
	mms_list_t			*cart_list;

	mms_list_foreach(&end_cmd->cmd_beginend_list, cur_cmd) {
		/* Do drive/cart/lib selection using path matching */
		if ((cart_results = mm_mount_cart_results(mm_wka,
					cur_cmd, db)) == NULL) {
			mm_system_error(end_cmd,
				"error getting candidate "
				"cartridge");
			/* No carts or error */
			return (MM_BE_ERROR);
		}
		cart_rows = PQntuples(cart_results);
		mms_trace(MMS_DEVP, "Number of Cartridges is %d", cart_rows);

		if (cart_rows == 0) {
			/* No Cartridge Matches Error */
			mms_trace(MMS_INFO,
			    "match statment in mount "
			    "didn't match any cartridge/volumes");
			mm_response_error(end_cmd,
				ECLASS_EXPLICIT, ENOMATCH,
				MM_5052_MSG,
				NULL);
			mm_clear_db(&cart_results);
			return (MM_BE_ERROR);
		}

		/* Create the list objects for */
		/* every cartridge/drive candidate */
		if (mm_mount_init_candidates(cur_cmd, cart_results,
				db)) {
			mms_trace(MMS_ERR,
			    "error initializing candidate lists");
			/* err buf should be set by mm_mount_init */
			/* so return and remove */
			mm_system_error(end_cmd,
				"error init candidate lists");
			mm_clear_db(&cart_results);
			return (MM_BE_ERROR);
		}
		mm_clear_db(&cart_results);
	}

	mms_trace(MMS_DEVP,
	    "keep only drive candidates selected in unmount cmd");
	/* Keep only the drive candidates selected in a unmount command */
	mms_list_foreach(&end_cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_unmount_cmd_func) {
			/* not an mount */
			continue;
		}
		cart_list = &cur_cmd->cmd_mount_info.cmi_cart_list;
		mms_list_foreach(cart_list, cart) {
			mms_list_foreach(&cart->cmi_drive_list, drive) {
				mms_trace(MMS_DEVP,
				    "  check if %s is selected in an unmount",
				    drive->cmi_drive_name);
				if (tm_be_is_in_unmount(drive->cmi_drive_name,
							end_cmd) == 0) {
					mms_trace(MMS_DEVP,
					    "    remove this drive");
					drive->cmi_remove_drive = 1;
				} else {
					mms_trace(MMS_DEVP,
					    "    keep this drive");
					drive->cmi_remove_drive = 0;
				}
			}
		}
		mm_mount_clean_candidates(cur_cmd);
	}
	return (MM_BE_OK);

}
int
tm_be_match_mount(mm_command_t *mnt_cmd, mm_command_t *end_cmd, mm_db_t *db) {
	/* select the cart drive for this mnt */
	mm_wka_t		*mm_wka = end_cmd->wka_ptr;
	cmd_mount_info_t	*mount_info = &mnt_cmd->cmd_mount_info;

	cmi_cart_list_t		*cart = NULL;
	cmi_drive_list_t	*drive = NULL;

	char			*cur_cartid = NULL;
	char			*cur_library = NULL;
	char			*cur_dm = NULL;
	char			*cur_drive = NULL;

	mm_command_t		*unmnt_cmd1 = NULL;
	mm_command_t		*unmnt_cmd2 = NULL;

	mm_command_t		*cur_cmd;
	int			found_unmount = 0;

	mms_trace(MMS_DEVP,
	    "tm_be_match_mount");
	MM_UNSET_FLAG(mnt_cmd->cmd_flags,
		    MM_CMD_DISPATCHABLE);
	mnt_cmd->cmd_state = 1;


	cart = mms_list_head(&mount_info->cmi_cart_list);
	if (cart == NULL) {
		mm_response_error(end_cmd,
		    ECLASS_RETRY,
		    "ETMPUNAVAIL",
		    MM_5104_MSG,
		    NULL);
		if (mm_wka->wka_begin_end.be_mode ==
		    ACCESS_MODE_BLOCKING) {
			return (MM_BE_BLOCKING);
		}
		mms_trace(MMS_ERR,
		    "mount has no candidates");
		return (MM_BE_ERROR);
	}
	cur_library = cart->cmi_library;
	cur_cartid = cart->cmi_cart_id;

	drive = mms_list_head(&cart->cmi_drive_list);
	if (drive == NULL) {
		mm_response_error(end_cmd,
		    ECLASS_RETRY,
		    "ETMPUNAVAIL",
		    MM_5104_MSG,
		    NULL);
		if (mm_wka->wka_begin_end.be_mode ==
		    ACCESS_MODE_BLOCKING) {
			return (MM_BE_BLOCKING);
		}
		mms_trace(MMS_ERR,
		    "mount has no candidates");
		return (MM_BE_ERROR);
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

	/* Select Is done - print the results */
	mms_trace(MMS_DEVP, "Cart/Lib/Drive selection "
	    "complete for task %s",
	    mnt_cmd->cmd_uuid);
	mms_trace(MMS_DEVP, "Cartridge ID is %s",
	    mount_info->cmi_cartridge);
	mms_trace(MMS_DEVP, "Library is %s",
	    mount_info->cmi_library);
	mms_trace(MMS_DEVP, "Drive is %s",
	    mount_info->cmi_drive);
	mms_trace(MMS_DEVP, "DM is %s",
	    mount_info->cmi_dm);


	mm_remove_all_depend(mnt_cmd);
	mms_list_foreach(&end_cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_mount_cmd_func) {
			/* not an unmount */
			continue;
		}
		if (strcmp(mount_info->cmi_drive,
			    cur_cmd->cmd_mount_info.cmi_drive) == 0) {
			/* same drive */
			mm_add_depend(mnt_cmd, cur_cmd);
			found_unmount = 1;
			unmnt_cmd1 = cur_cmd;
		}
	}
	if (found_unmount == 0) {
		mm_system_error(end_cmd,
			"couldn't find unmount for this mount");
		mms_trace(MMS_ERR,
		    "couldn't find unmount for this mount");
		return (MM_BE_ERROR);
	}


	/* Is this cart currently loaded */
	if (mm_db_exec(HERE, db,
		"select \"LibraryName\",\"DriveName\" "
		"from \"DRIVE\" where \"DRIVE\"."
		"\"CartridgePCL\" = (select \"CartridgePCL\" "
		"from \"CARTRIDGE\" where \"CartridgeID\" = '%s');",
	    mount_info->cmi_cartridge) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "tm_be_match_mount: "
		    "db error getting drive info");
		mm_sql_db_err_rsp_new(end_cmd, db);
		return (MM_BE_ERROR);
	}

	if (PQntuples(db->mm_db_results) == 0) {
		/* Cur cart is not loaded */
		mms_trace(MMS_DEVP,
		    "cartid %s not found in a drive",
		    mount_info->cmi_cartridge);
	} else {
		mms_trace(MMS_DEVP,
		    "need to unmount %s, %s "
		    "before mount ",
		    PQgetvalue(db->mm_db_results, 0, 0),
		    PQgetvalue(db->mm_db_results, 0, 1));

		unmnt_cmd2 = mm_return_unload(
			PQgetvalue(db->mm_db_results, 0, 0),
			PQgetvalue(db->mm_db_results, 0, 1),
			mm_wka->mm_data);
		if (unmnt_cmd2 == NULL) {
			mm_system_error(end_cmd,
				"couldn't find unmount for this mount");
			mms_trace(MMS_ERR,
			    "couldn't find unmount for this mount");
			return (MM_BE_ERROR);
		}
		MM_SET_FLAG(unmnt_cmd1->cmd_flags,
			MM_CMD_DISPATCHABLE);
		MM_UNSET_FLAG(mnt_cmd->cmd_flags, MM_CMD_DISPATCHABLE);
		MM_UNSET_FLAG(unmnt_cmd2->cmd_flags, MM_CMD_DISPATCHABLE);
		mms_trace(MMS_DEVP,
		    "unmnt_cmd1->cmd_name == %s (%p)",
		    unmnt_cmd1->cmd_name,
		    unmnt_cmd1);
		mms_trace(MMS_DEVP,
		    "unmnt_cmd2->cmd_name == %s (%p)",
		    unmnt_cmd2->cmd_name, unmnt_cmd2);
		mms_trace(MMS_DEVP,
		    "mnt_cmd->cmd_name == %s (%p)",
		    mnt_cmd->cmd_name, mnt_cmd);
		mm_remove_all_depend(mnt_cmd);
		mm_add_depend(unmnt_cmd1, unmnt_cmd2);
		mm_add_depend(unmnt_cmd2, mnt_cmd);
	}
	mm_clear_db(&db->mm_db_results);
	mms_trace(MMS_DEVP,
	    "mount finished setting up");
	return (MM_BE_OK);
}

int
tm_be_pairs(mm_command_t *cmd, mm_data_t *mm_data) {
	/* This is what the function may return */
	/* MM_BE_ERROR */
	/* MM_BE_BLOCKING */
	/* MM_BE_DISPATCH */
	/* For BLOCKING and MMS_ERROR, end cmd error buf */
	/* Should be set */

	mm_db_t			*db = &mm_data->mm_db_tm;
	mm_wka_t		*mm_wka = cmd->wka_ptr;
	mm_command_t		*cur_cmd;
	int			rc;
	mms_trace(MMS_DEVP,
	    "tm_be_pairs");

	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_mount_cmd_func) {
			/* not an unmount */
			continue;
		}

		rc = tm_be_unmount_ready(cur_cmd->wka_ptr, cur_cmd, db, cmd);
		switch (rc) {

		case MM_UNMOUNT_ERROR:
			/* Error code should be set */
			mms_trace(MMS_ERR,
			    "internal error, mm_unmount_ready");
			return (MM_BE_ERROR);

		case MM_UNMOUNT_READY:
			mms_trace(MMS_DEVP,
			    "unmount is ready to go, ");
			break;

		case MM_UNMOUNT_NOT_READY:
			if (mm_wka->wka_begin_end.be_mode ==
				ACCESS_MODE_IMMEDIATE) {
				/* Error code should be set */
				mms_trace(MMS_ERR,
				    "immediate begin-end group "
				    "is not ready");
				return (MM_BE_ERROR);
			}
			/* Error code should be set */
			mms_trace(MMS_ERR,
			    "blocking unmount not ready, "
			    "wait longer and try later");
			return (MM_BE_BLOCKING);
		default:
			mms_trace(MMS_ERR,
			    "bad rc mm_unmount_ready");
			mm_system_error(cmd,
				"bad rc mm_unmount_ready");
			return (MM_BE_ERROR);
		}
	}
	mms_trace(MMS_DEVP,
	    "unmounts prepared");
	/* Unmounts prepared/partially ready */
	/* now determine exactly which tapes to unmount */
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_mount_cmd_func) {
			/* not an unmount */
			continue;
		}
		mms_trace(MMS_DEVP, "set up a unmount for dispatch");
		rc = tm_be_set_unmount(cur_cmd->wka_ptr,
				cur_cmd, cmd);
		if (rc == MM_BE_ERROR) {
			mms_trace(MMS_ERR, "error setting up unmount");
			/* error set for end command already */
			return (MM_BE_ERROR);
		} else if (rc == MM_BE_BLOCKING) {
			mms_trace(MMS_ERR,
			    "blocking mount not ready, "
			    "wait longer and try later");
			return (MM_BE_BLOCKING);
		}
		/* remove cmi_cart and cmi_drive from */
		/* above from the remaining */
		/* unmount candidates */
		tm_be_rm_unmount_candidates(cmd, cur_cmd);
		MM_SET_FLAG(cur_cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
		cur_cmd->cmd_state = 1;
		cur_cmd->cmd_mount_info.cui_physical = 1;
	}
	mms_trace(MMS_DEVP,
	    "unmounts cart/drive selected and set");
	/* All unmount cmds have been set up */
	/* set up each mount using the candidates in unmounts */
	if (tm_be_init_mount(cmd, db) == MM_BE_ERROR) {
		mms_trace(MMS_ERR, "error init mounts for unmounts");
		/* error set for end command already */
		return (MM_BE_ERROR);
	}
	mms_trace(MMS_DEVP,
	    "mounts initialized");
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_unmount_cmd_func) {
			/* not an mount */
			continue;
		}
		/* tm_be_match_mount will match this */
		/* mount with an unmount */
		MM_UNSET_FLAG(cur_cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
		cur_cmd->cmd_state = 1;
		rc = tm_be_match_mount(cur_cmd, cmd, db);
		if (rc == MM_BE_ERROR) {
			mms_trace(MMS_ERR, "error setting up unmount");
			/* error set for end command already */
			return (MM_BE_ERROR);
		}

	}

	/* All mounts have been setup, */
	/* create the TASK objects */
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		mm_set_mount_objs(cur_cmd, db);
	}
	/* Put these mounts on the command queue */
	tm_be_add_mounts(cmd);

	/* All mounts are set and ready to go */
	return (MM_BE_DISPATCH);

}


void tm_be_add_mounts(mm_command_t *cmd) {
	mm_command_t	*next;
	mm_command_t	*cur;

	for (cur = mms_list_head(&cmd->cmd_beginend_list);
	    cur != NULL;
	    cur = next) {
		next = mms_list_next(&cmd->cmd_beginend_list, cur);

		mms_list_remove(&cmd->cmd_beginend_list,
			    cur);
		pthread_mutex_lock(&cmd->wka_ptr->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&cmd->wka_ptr->mm_data->mm_cmd_queue, cur);
		pthread_mutex_unlock(&cmd->wka_ptr->mm_data->mm_queue_mutex);
	}
}

void
mm_be_order_mount_cmds(mm_command_t *cmd)
{
	mm_command_t		*be_cmd;
	mm_command_t		*next_cmd;

	/* Put mount commands with already loaded cartridges on */
	/* front of begin end mount list. */

	for (be_cmd = mms_list_head(&cmd->cmd_beginend_list);
	    be_cmd != NULL;
	    be_cmd = next_cmd) {
		next_cmd = mms_list_next(&cmd->cmd_beginend_list, be_cmd);
		if (mm_mount_candidate_loaded(be_cmd)) {
			mms_list_remove(&cmd->cmd_beginend_list, be_cmd);
			mms_list_insert_head(&cmd->cmd_beginend_list, be_cmd);
		}
	}
}

int
tm_be_mounts(mm_command_t *cmd, mm_data_t *mm_data) {
	mm_db_t			*db = &mm_data->mm_db_tm;
	mm_wka_t		*mm_wka = cmd->wka_ptr;
	mm_command_t		*cur_cmd;
	int			rc;

	/* Errors */
	int			mount_has_error = 0;

	char			*err_text = NULL;

	/* This is the function can return */
	/* MM_BE_ERROR */
	/* MM_BE_BLOCKING */
	/* MM_BE_DISPATCH */
	/* For BLOCKING and MMS_ERROR, end cmd error buf */
	/* Should be set */

	mms_trace(MMS_DEVP,
	    "tm_be_mounts");


	/* Instead of returning set mount_has_error or mount_would_block */
	/* After calling for ever mount generate the correct error code */
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		cur_cmd->cmd_mount_info.cmi_mount_ok = 0;
		rc = tm_be_mount_ready(cur_cmd->wka_ptr, cur_cmd, db, cmd);
		switch (rc) {

		case MM_MOUNT_ERROR:
			/* Error code should be set */
			mms_trace(MMS_ERR,
			    "tm_be_mounts: "
			    "internal error, tm_be_mount_ready");
			mount_has_error = 1;
			break;

		case MM_MOUNT_READY:
			/* The mount is ready, mount_info should be set */
			/* continue to state 1 */
			mms_trace(MMS_DEVP,
			    "tm_be_mounts: "
			    "mount is ready to go ");
			cur_cmd->cmd_mount_info.cmi_mount_ok = 1;
			break;

		case MM_MOUNT_NEED_UNLOAD:
			/* this immediate mount needs to */
			/* wait for an unload */
			mms_trace(MMS_DEVP,
			    "tm_be_mounts: "
			    "mount needs to wait "
			    "for unload to complete");
			cur_cmd->cmd_mount_info.cmi_mount_ok = 1;
			break;

		case MM_MOUNT_NOT_READY:
			mount_has_error = 1;
			mms_trace(MMS_ERR,
			    "tm_be_mounts: "
			    "mount not ready, "
			    "wait longer and try later");
				break;
		default:
			mms_trace(MMS_ERR,
			    "tm_be_mounts: "
			    "bad rc mm_mount_ready");
			mm_system_error(cmd,
				"bad rc mm_mount_ready");
			return (MM_BE_ERROR);
		}
	}


	/* Determine the correct error code to use for the end command */
	/* Each mount in the group with an error will have ecode and eclass */
	if (mount_has_error) {
		mms_trace(MMS_ERR,
		    "at least one mount had "
		    "an error for this begin-end");

		/* at least one mount had an error */
		/* for each mount set the least sever errror */
		/* if any mount has a error more severe than retry */
		/* return error for the end command */
		/* since this mount will not work for immediate or blocking */
		mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
			if (cur_cmd->cmd_mount_info.cmi_mount_ok) {
				mms_trace(MMS_ERR,
				    "tm_be_mounts: "
				    "this mount is ok, no errors");
			} else {
				mms_trace(MMS_ERR,
				    "tm_be_mounts: "
				    "this mount has errors, set least severe");

				mm_set_least_severe(cur_cmd);
				if (strcmp(cur_cmd->cmd_eclass,
				    ECLASS_RETRY) != 0) {
					/* this is not a retry error class */
					/* return error for this end command */
					mms_trace(MMS_ERR,
					    "at least one mount's "
					    "least severe error is"
					    " more severe than retry, "
					    "this begin-end group "
					    "will not work");
					/* One or more mount has errors */
					/* that are non retry */
					err_text =
					    mm_return_err_text(cur_cmd->
					    cmd_err_ptr);
					mm_response_error(cmd,
					    ECLASS_EXPLICIT,
					    "ENOSOLUTIONS",
					    MM_5110_MSG,
					    "err_text", err_text,
					    NULL);
					free(err_text);
					return (MM_BE_ERROR);
				}
			}
		}



	}


	mm_be_order_mount_cmds(cmd);

	/* All mounts are either ok or retry */
	/* Determine which error to return/block */
	/* for immediate, return retry or nosolutions */
	/* for blocking, block or return nosolutions */


	/* Mount candidate lists have been set up, */
	/* divide the resources and set up the exact */
	/* Drive/cartridge combination */

	mount_has_error = 0;
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {

		mms_trace(MMS_DEVP, "set up a mount for dispatch");

		/* tm_be_set_mount returns MM_BE_ERROR or MM_BE_DISPATCH */

		if (cur_cmd->cmd_mount_info.cmi_mount_ok) {
			rc = tm_be_set_mount(cur_cmd,
			    db, cmd);
		} else {
			rc = MM_BE_ERROR;
		}

		if (rc == MM_BE_ERROR) {
			mount_has_error = 1;
			/* If the cur err ptr is null or */
			/* pointing to a non-retry error class */
			/* This begin-end group cannot succeede */
			if ((cur_cmd->cmd_err_ptr == NULL) ||
			    (strcmp(cur_cmd->cmd_err_ptr->eclass,
			    ECLASS_RETRY) != 0)) {
				mms_trace(MMS_ERR,
				    "tm_be_mounts: "
				    "There are no valid "
				    "solutions to this mount ");

				err_text =
				    mm_return_err_text(cur_cmd->
				    cmd_err_ptr);
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    "ENOSOLUTIONS",
				    MM_5110_MSG,
				    "err_text", err_text,
				    NULL);
				free(err_text);
				return (MM_BE_ERROR);
			}
			tm_be_rm_error_candidates(cmd, cur_cmd);
		} else {
			tm_be_rm_mount_candidates(cmd, cur_cmd);
		}
	}

	if (mount_has_error) {
		/* If this is immediate, return retry error class for the end */
		/* if this is blocking, then block for the whole group */
		/* Set error for retry */
		mm_response_error(cmd,
		    ECLASS_RETRY,
		    "ETMPUNAVAIL",
		    MM_5104_MSG,
		    NULL);
		return (MM_BE_BLOCKING);
	}
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		if (mm_dispatch_now(mm_wka, cur_cmd, db)) {
			/* error should be set */
			mms_trace(MMS_ERR,
			    "error setting up mount for dispatch");
		}
	}
	/* All mounts have been setup, */
	/* create the TASK objects */
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		mm_set_mount_objs(cur_cmd, db);
	}
	/* Put these mounts on the command queue */
	tm_be_add_mounts(cmd);

	/* All mounts are set and ready to go */
	return (MM_BE_DISPATCH);
}

int
tm_be_cmd_has_unmounts(mm_command_t *cmd) {
	mm_command_t		*cur_cmd;
	int			unmount_count = 0;
	int			mount_count = 0;

	int			print_message = 1;
	/* Returns 1 if this has unmounts */
	/* Also makes sure unmounts are paird with mounts */
	if (print_message)
		mms_trace(MMS_DEVP,
		    "tm_be_cmd_has_unmounts");
	mms_list_foreach(&cmd->cmd_beginend_list, cur_cmd) {
		if (cur_cmd->cmd_func == mm_mount_cmd_func) {
			if (print_message)
				mms_trace(MMS_DEVP,
				    "saw a mount");
			mount_count ++;
		} else if (cur_cmd->cmd_func == mm_unmount_cmd_func) {
			if (print_message)
				mms_trace(MMS_DEVP,
				    "saw an unmount");
			unmount_count ++;
		}
	}
	if (unmount_count == 0)
		return (0);
	if (unmount_count == mount_count)
		return (1);
	mm_system_error(cmd,
		"num mounts does not match num unmounts");
	return (-1);
}

int
tm_can_dispatch_end(mm_command_t *cmd, mm_data_t *mm_data)
{
	mm_db_t			*db = &mm_data->mm_db_tm;
	mm_wka_t		*mm_wka = cmd->wka_ptr;

	int			rc;
	int			immediate = 0;
	int			unmount = 0;

	if (mm_wka->wka_begin_end.be_mode ==
	    ACCESS_MODE_IMMEDIATE)
		immediate = 1;

	/* Determine the begin-end type */
	/* Currently there are 2 types */
	/* 1. A group of all mounts */
	/* 2. A group of unmounts paired 1to1 w/mounts */
	if ((unmount = tm_be_cmd_has_unmounts(cmd)) == -1) {
		/* Error buf is set */
		goto cmd_error;
	}
	if (unmount == 1) {
		rc = tm_be_pairs(cmd, mm_data);
	} else {
		rc = tm_be_mounts(cmd, mm_data);
	}
	switch (rc) {
	case MM_BE_BLOCKING:
		if (immediate)
			goto cmd_error;
		return (0);
	case MM_BE_DISPATCH:
		/* Send success for end */
		mm_path_match_report(cmd, db);
		(void) mm_del_tm_cmd(db, cmd->cmd_uuid);
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		return (1);
	case MM_BE_ERROR:
		/* Error buf is set */
		goto cmd_error;
	}


cmd_error:
	/* Error buf must be set */
	(void) mm_del_tm_cmd(db, cmd->cmd_uuid);
	cmd->cmd_remove = 1;
	mm_send_text(cmd->wka_ptr->mm_wka_conn,
	    cmd->cmd_buf);
	tm_be_cancel_all(cmd);
	return (0);
}

int
tm_can_dispatch(char *task_id, mm_data_t *mm_data)
{

	mms_list_t			*cmd_queue = &mm_data->mm_cmd_queue;

	mm_command_t		*cur_cmd;


	mms_trace(MMS_DEVP, "tm_can_dispatch");

	/* Find the command associated with this task */
	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(cmd_queue, cur_cmd) {
		if ((strcmp(task_id,
		    cur_cmd->cmd_uuid) == 0)) {
			/* task id matches */
			break;
		}

	}
	pthread_mutex_unlock(&mm_data->mm_queue_mutex);
	if (cur_cmd == NULL) {
		mms_trace(MMS_INFO, "Could not match task %s with a command",
		    task_id);
		return (0);
	}

	mms_trace(MMS_DEVP, "Matched Task with command - cmd is %s",
	    cur_cmd->cmd_uuid);
	if (cur_cmd->cmd_remove) {
		/* This command has already been marked for removal */
		/* skip and let main thread clean it up */
		mms_trace(MMS_DEVP,
		    "skip %s, marked for remove",
		    cur_cmd->cmd_uuid);
		return (0);
	}

	if (cur_cmd->cmd_func == mm_mount_cmd_func) {
		pthread_mutex_lock(&cur_cmd->wka_ptr->
		    wka_local_lock);
		/* Set cmd_dispatchable inside this func */
		if (tm_can_dispatch_mount(cur_cmd, mm_data)) {
			pthread_mutex_unlock(&cur_cmd->wka_ptr->
			    wka_local_lock);
			return (1);
		}
		pthread_mutex_unlock(&cur_cmd->wka_ptr->
		    wka_local_lock);
		return (0);
	} else if (cur_cmd->cmd_func == mm_unmount_cmd_func) {
		pthread_mutex_lock(&cur_cmd->wka_ptr->
		    wka_local_lock);
		if (tm_can_dispatch_unmount(cur_cmd, mm_data)) {
			/* set command as dispatchable */
			MM_SET_FLAG(cur_cmd->cmd_flags, MM_CMD_DISPATCHABLE);
			pthread_mutex_unlock(&cur_cmd->wka_ptr->
			    wka_local_lock);
			return (1);
		}
		pthread_mutex_unlock(&cur_cmd->wka_ptr->
		    wka_local_lock);

		return (0);
	} else if (cur_cmd->cmd_func == mm_end_cmd_func) {
		pthread_mutex_lock(&cur_cmd->wka_ptr->
		    wka_local_lock);
		if (tm_can_dispatch_end(cur_cmd, mm_data)) {
			/* set command as dispatchable */
			MM_SET_FLAG(cur_cmd->cmd_flags, MM_CMD_DISPATCHABLE);
			pthread_mutex_unlock(&cur_cmd->wka_ptr->
			    wka_local_lock);
			return (1);
		}
		pthread_mutex_unlock(&cur_cmd->wka_ptr->
		    wka_local_lock);
	} else {
		mms_trace(MMS_ERR,
		    "command is not a mount/unmount or end");
		return (0);
	}
	return (0);
}


int
mm_get_tm_cmd(mm_data_t *mm_data)
{
	mm_db_t			*db = &mm_data->mm_db_tm;
	PGresult	 *tasks;
	int		num_tasks;
	int		num_dispatched = 0;
	int		i;

	/* used when a mount needs a drive unloaded 1st */


	mms_trace(MMS_DEVP, "mm_get_tm_cmd");

	mms_trace(MMS_DEVP, "Getting list of tasks...");

	/* Get ordered list of blocked tasks */
	if (mm_db_exec(HERE, db,
	    "select * from "
	    "(select \"TaskID\","
	    "\"TaskPriority\" from \"TASK\" "
	    "where \"TaskState\" = 'blocked' "
	    "order by \"TaskArrivalTime\") "
	    "as foo order by \"TaskPriority\" "
	    "desc;") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "mm_get_tm_cmd: "
		    "db error getting task info");
		return (1);
	}

	tasks = db->mm_db_results;
	num_tasks = PQntuples(tasks);
	if (num_tasks == 0) {
		mms_trace(MMS_DEVP, "%d tasks found",
		    num_tasks);
		mm_clear_db(&tasks);
		mms_trace(MMS_DEVP, "TaskManager is Done");
		return (0);
	}
	mms_trace(MMS_DEVP, "%d tasks found, trying dispatch",
	    num_tasks);
	for (i = 0; i < num_tasks; i++) {
		/* Try to dispatch each task */
		mms_trace(MMS_DEVP, "    task %s, priority %s",
		    PQgetvalue(tasks, i, 0),
		    PQgetvalue(tasks, i, 1));

		if (tm_can_dispatch(PQgetvalue(tasks, i, 0),
		    mm_data) == 1) {
			/* Task ok for dispatch */
			mms_trace(MMS_INFO, "task %s ready for dispatch",
			    PQgetvalue(tasks, i, 0));
			num_dispatched ++;
		} else {
			/* Resources not available */
			mms_trace(MMS_DEVP, "task %s not ready",
			    PQgetvalue(tasks, i, 0));
		}
	}

	mms_trace(MMS_DEVP, "%d tasks dispatched",
	    num_dispatched);

	if (num_dispatched == 0) {
		mms_trace(MMS_DEVP, "TaskManager is Done");
		mm_clear_db(&tasks);
		return (0);
	}
	/* wakeup worker thread to do work */

	pthread_mutex_lock(&mm_data->mm_worker_mutex);
	mm_data->mm_work_todo = 1;
	pthread_cond_signal(&mm_data->mm_work_cv);
	pthread_mutex_unlock(&mm_data->mm_worker_mutex);


	mms_trace(MMS_DEVP, "TaskManager is Done");
	mm_clear_db(&tasks);
	return (0);

}

mm_db_rval_t
mm_set_tm_task(mm_db_t *db, mm_command_t *command)
{
	return (mm_new_tm_task(db, command, "blocked"));
}

mm_db_rval_t
mm_new_tm_task(mm_db_t *db, mm_command_t *command, char *state)
{
	mm_db_rval_t	 rc;
	char		*cmd_text;

	if ((cmd_text = mms_pn_build_cmd_text(command->cmd_root)) == NULL) {
		return (MM_DB_ERROR); /* out of memory */
	}
	rc = mm_db_exec(HERE, db, "INSERT INTO \"TASK\" "
	    "(\"TaskID\", \"TaskType\", \"ApplicationName\", "
	    "\"AIName\", \"TaskStatement\", \"ClientTaskID\", "
	    "\"TaskState\") VALUES "
	    "('%s', '%s', '%s', '%s', $$%s$$, '%s', '%s')",
	    command->cmd_uuid,
	    command->cmd_root->pn_string,
	    command->wka_ptr->wka_conn.cci_client,
	    command->wka_ptr->wka_conn.cci_instance,
	    cmd_text, command->cmd_task, state);
	free(cmd_text);
	return (rc);
}

mm_db_rval_t
mm_set_tm_cartridge(mm_db_t *db, char *taskid, char *cartridge_id)
{
	mm_db_rval_t	rc;
	PGresult	*task_results;

	rc = mm_db_exec(HERE, db,
	    "select * from \"TASKCARTRIDGE\" where "
	    "\"TaskID\" = '%s' and \"CartridgeID\" = '%s'",
	    taskid, cartridge_id);
	if (rc != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "mm_set_tm_cartridge: "
		    "db error getting info for"
		    " TASKCARTRIDGE");
		mm_clear_db(&db->mm_db_results);
		return (rc);
	}
	task_results = db->mm_db_results;
	if (PQntuples(task_results) == 0) {
		rc = mm_db_exec(HERE, db, "INSERT INTO \"TASKCARTRIDGE\" "
		    "(\"TaskID\", \"CartridgeID\") VALUES ('%s', '%s')",
		    taskid, cartridge_id);
		if (rc != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_set_tm_cartridge: "
			    "db error inserting TASKCARTRIDGE");
			mm_clear_db(&db->mm_db_results);
		}
	} else {
		if (rc == MM_DB_DATA) {
			rc = MM_DB_OK;
		}
	}
	mm_clear_db(&task_results);
	return (rc);
}

mm_db_rval_t
mm_set_tm_drive(mm_db_t *db, char *taskid, char *drive)
{
	mm_db_rval_t	rc;
	PGresult	*task_results;

	rc = mm_db_exec(HERE, db,
	    "select * from \"TASKDRIVE\" where "
	    "\"TaskID\" = '%s' and \"DriveName\" = '%s'",
	    taskid, drive);
	if (rc != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "mm_set_tm_drive: "
		    "db error getting info for"
		    " TASKDRIVE");
		mm_clear_db(&db->mm_db_results);
		return (rc);
	}
	task_results = db->mm_db_results;
	if (PQntuples(task_results) == 0) {
		rc = mm_db_exec(HERE, db, "INSERT INTO \"TASKDRIVE\" "
		    "(\"TaskID\", \"DriveName\") VALUES ('%s', '%s')",
		    taskid, drive);
		if (rc != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_set_tm_drive: "
			    "db error inserting TASKDRIVE");
			mm_clear_db(&db->mm_db_results);
		}
	} else {
		if (rc == MM_DB_DATA) {
			rc = MM_DB_OK;
		}
	}
	mm_clear_db(&task_results);
	return (rc);
}

mm_db_rval_t
mm_set_tm_library(mm_db_t *db, char *taskid, char *library)
{
	mm_db_rval_t	rc;
	PGresult	*task_results;

	rc = mm_db_exec(HERE, db,
	    "select * from \"TASKLIBRARY\" where "
	    "\"TaskID\" = '%s' and \"LibraryName\" = '%s'",
	    taskid, library);
	if (rc != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "mm_set_tm_library: "
		    "db error getting info for"
		    " TASKLIBRARY");
		mm_clear_db(&db->mm_db_results);
		return (rc);
	}
	task_results = db->mm_db_results;
	if (PQntuples(task_results) == 0) {
		rc = mm_db_exec(HERE, db, "INSERT INTO \"TASKLIBRARY\" "
		    "(\"TaskID\", \"LibraryName\") VALUES ('%s', '%s')",
		    taskid, library);
		if (rc != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_set_tm_library: "
			    "db error inserting TASKLIBRARY");
			mm_clear_db(&db->mm_db_results);
		}
	} else {
		if (rc == MM_DB_DATA) {
			rc = MM_DB_OK;
		}
	}
	mm_clear_db(&task_results);
	return (rc);
}

mm_db_rval_t
mm_set_tm_cmd_dispatched(mm_db_t *db, char *taskid)
{
	mm_db_rval_t	rc;

	rc = mm_db_exec(HERE, db, "UPDATE \"TASK\" "
	    "SET \"TaskState\" = 'dispatched' "
	    "WHERE \"TaskID\" = '%s'", taskid);

	return (rc);
}

mm_db_rval_t
mm_del_tm_cmd(mm_db_t *db, char *taskid)
{
	mm_db_rval_t	rc;

	rc = mm_db_exec(HERE, db, "DELETE FROM \"TASK\" "
	    "WHERE \"TaskID\" = '%s'", taskid);
	if (rc != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_del_tm_cmd: "
		    "db error deleteing from TASK");
	}

	rc = mm_db_exec(HERE, db, "delete from \"REQUEST\" where "
	    "\"RequestingTaskID\" = '%s' and "
	    "\"RequestState\" != 'responded';", taskid);

	if (rc != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "mm_del_tm_cmd: "
		    "db error deleteing from REQUEST");
	}

	return (rc);
}

mm_db_rval_t
mm_chg_tm_cmd_priority(mm_db_t *db, char *taskid, int priority)
{
	mm_db_rval_t	rc;

	rc = mm_db_exec(HERE, db, "UPDATE \"TASK\" "
	    "SET \"TaskPriority\" = '%s' "
	    "WHERE \"TaskID\" = '%s'", priority, taskid);

	return (rc);
}
