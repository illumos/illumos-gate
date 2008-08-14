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


#include "lm_acs.h"

acs_rsp_t	acs_rsp;

static char	*_SrcFile = __FILE__;

int
lm_acs_init()
{
	mms_list_create(&acs_rsp.acs_queue, sizeof (acs_rsp_ele_t),
	    offsetof(acs_rsp_ele_t, acs_rsp_next));

	if (pthread_mutex_init(&acs_rsp.acs_mutex, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_acs_init: acs_mutex init failed, errno - "
		    "%s", strerror(errno));
		return (LM_ERROR);
	}

	if (pthread_cond_init(&acs_rsp.acs_cv, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_acs_init: acs_cv init failed, errno - %s",
		    strerror(errno));
		(void) pthread_mutex_destroy(&acs_rsp.acs_mutex);
		return (LM_ERROR);
	}
	return (LM_OK);
}

/*
 * lm_handle_acs_cmd_error()
 *
 * Parameters:
 *	- status	The status that was returned from ACSLS for the
 *			the acsls command.
 *	- cmd		The LMPM command that is being processed.
 *	- tid		The task id of the LMPM command that is responsible for
 *			the acsls command being executed.
 *	- msg		Contains the error response that is generated.
 *
 * Description:
 *	This function is called when a ACSLS command returns something
 *	other than STATUS_SUCCESS. The possible return status for
 *	ACSLS commands are the following:
 *	  - STATUS_IPC_FAILURE
 *		There was a fatal communications failure in the IPC layer.
 *		Most likely two internal components were unable to
 *		communicate. Another possible cause could be that SSI
 *		has failed.
 *	  - STATUS_PROCESS_FAILURE
 *		The ACSLM was not able to spawn the request or the ACSLM
 *		received a process failure from a spawned task.
 *	If a status other than those above is returned, this function
 *	returns the error code of MMS_LM_E_INTERNAL to indicate that
 *	there is an internal processing error.
 *
 *	For a STATUS_IPC_FAILURE, this routine will send a "alert" message
 *	to the operator interface to notify the operator that the LM has
 *	encountered a communication problem with ACSLS. It also will send
 *	a "ready disconnected" to MM, as well as set the internal state of
 *	the LM to "disconnected".
 *
 * Return Values:
 *	None
 *
 */
void
lm_handle_acs_cmd_error(STATUS status, char *cmd, char *tid, char *msg)
{
	int	class = MMS_INTERNAL;
	int	code;
	char	msg_str[1024];

	class = MMS_INTERNAL;

	if (status == STATUS_IPC_FAILURE) {
			/* Change state of LM to "disconnected" */
		if (lm_common_ready(LM_DISCONN, tid, msg) != LM_OK)
			mms_trace(MMS_ERR, "lm_handle_acs_cmd_error: Failure "
			    "encountered while issueing ready disconnect "
			    "command to MM.");
		lm_state = LM_DISCONNECTED;
			/* Send message to operator indicating issue */
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7203_MSG, acs_status(status),
		    acs_status(status));
				/* No need to check return status */
		lm_message("operator", "alert", msg_str);
			/* Create error message for LMPM command */
		code = MMS_LM_E_DEVCOMMERR;
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7225_MSG, cmd, acs_status(status),
		    cmd, acs_status(status));
	} else if (status == STATUS_PROCESS_FAILURE) {
		code = MMS_LM_E_DEVCMD;
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7227_MSG, cmd, acs_status(status),
		    cmd, acs_status(status));
	} else {
		code = MMS_LM_E_INTERNAL;
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7229_MSG, cmd, acs_status(status),
		    cmd, acs_status(status));
	}

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(class),
	    mms_sym_code_to_str(code), msg_str);
}

/*
 * lm_handle_acsls_rsp_error()
 *
 * Parameters:
 *	- status	The status that was returned from acs_response().
 *	- acsls		The acsls command the response was for.
 *	- cmd		The LMPM command that is being processed.
 *	- tid		The task id of the LMPM command that is responsible for
 *			the acsls command being executed.
 *	- msg		Contains the error response that is generated.
 *
 *
 * Description:
 *	This function is called when acs_response() returns something
 *	other than STATUS_SUCCESS. The possible return status for
 *	acs_response are the following:
 *	  - STATUS_IPC_FAILURE
 *		There was a fatal communications failure in the IPC layer.
 *		Most likely two internal components were unable to
 *		communicate.
 *	  - STATUS_PENDING
 *		The ACS response will return this status when there is no
 *		input from the SSI.
 *	  - STATUS_PROCESS_FAILURE
 *		The ACSLM was not able to spawn the request or the ACSLM
 *		received a process failure from a spawned task.
 *	If a status other than those above is returned, this function
 *	returns the error code of MMS_LM_E_INTERNAL to indicate that
 *	there is an internal processing error.
 *
 *	For STATUS_IPC_FAILURE and STATUS_PENDING, this routine will send
 *	a "alert" message to the operator interface to notify the operator
 *	that the LM has encountered a communication problem with ACSLS. It
 *	also will send a "ready disconnected" to MM, as well as set the
 *	internal state of the LM to "disconnected".
 *
 * Return Values:
 *	None
 */
void
lm_handle_acsls_rsp_error(STATUS status, char *acsls, char *cmd, char *tid,
char *msg)
{
	int	class = MMS_INTERNAL;
	int	code;
	char	msg_str[1024];

	if (status == STATUS_IPC_FAILURE || status == STATUS_PENDING) {
			/* Change state of LM to "disconnected" */
		if (lm_common_ready(LM_DISCONN, tid, msg) != LM_OK)
			mms_trace(MMS_ERR, "lm_handle_acsls_rsp_error: Failure "
			    "encountered while issueing ready disconnect "
			    "command to MM.");
		lm_state = LM_DISCONNECTED;
			/* Send message to operator indicating issue */
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7203_MSG, acs_status(status),
		    acs_status(status));
				/* No need to check return status */
		lm_message("operator", "alert", msg_str);
			/* Create error message for LMPM command */
		code = MMS_LM_E_DEVCOMMERR;
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7226_MSG, cmd, acsls, acs_status(status),
		    cmd, acsls, acs_status(status));
	} else if (status == STATUS_PROCESS_FAILURE) {
		code = MMS_LM_E_DEVCMD;
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7228_MSG, cmd, acsls, acs_status(status),
		    cmd, acsls, acs_status(status));
	} else {
		code = MMS_LM_E_INTERNAL;
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7230_MSG, cmd, acsls, acs_status(status),
		    cmd, acsls, acs_status(status));
	}

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(class),
	    mms_sym_code_to_str(code), msg_str);
}

/*
 * lm_handle_acsls_status_error()
 *
 * Parameters:
 *	- class		The class of error used in error response.
 *	- code		The code of error used in error response.
 *	- status	The ACSLS error status being handled.
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is one of the status that are not usually seen. This set of error
 *	status should not be seen and if seen, possible changes to this
 *	code may be needed in order to handle the error status in a
 *	more approiate manner. This function purpose is to log these
 *	response and generate an error response for the LMPM command.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_acsls_status_error(int class, int code, STATUS status, char *acsls,
char *cmd, char *tid, char *msg)
{

	char msg_str[1024];

	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7208_MSG, cmd, acsls, acs_status(status), cmd,
	    acsls, acs_status(status));
	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(class),
	    mms_sym_code_to_str(code), msg_str);

}

/*
 * lm_handle_drive_offline_error()
 *
 * Parameters:
 *	- drive		The name of the drive in the LMPM command
 *	- geometry	The geometry of the drive in the ACSLS library
 *	- cart		If the LMPM command is a unmount, it contains the
 *			cartridge barcode. If the LMPM command is mount, it
 *			contains an empty string.
 *	- panel		The ACSLS panel number of the drive.
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is STATUS_DRIVE_OFFLINE.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_drive_offline_error(char *drive, char *serialnum, char *geometry,
char *cart, int panel, char *acsls, char *cmd, char *tid, char *msg)
{
	int	rc;
	int	lmpl_tid;

	char	msg_str[1024];
	char	drive_spec[1024];

	lmpl_rsp_ele_t	*ele;

			/* Send alert message to operator indicating */
			/* that a drive was found to be offline in */
			/* ACSLS library */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7210_MSG, drive, serialnum, drive, serialnum);
	lm_message("operator", "alert", msg_str);

			/* Generate LMPL config drive command to update */
			/* state of drive to not accessible in MM's database */
	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_handle_drive_offline_error: "
		    "lm_obtain_task_id failed trying to generate LMPL config "
		    "drive command");
	} else {
		if (strcmp(acsls, "acs_mount") == 0)
			(void) snprintf(drive_spec, sizeof (drive_spec),
			    "config task[\"%d\"] scope[partial]"
			    " drive [\"%s\" \"%s\" \"panel %d\" \"none\" false "
			    "false];", lmpl_tid, serialnum, geometry, panel);
		else
			(void) snprintf(drive_spec, sizeof (drive_spec),
			    "config task[\"%d\"] scope[partial]"
			    " drive [\"%s\" \"%s\" \"panel %d\" \"%s\" true "
			    "false];",
			    lmpl_tid, serialnum, geometry, panel, cart);

		mms_trace(MMS_DEBUG, "lm_handle_drive_offline_error: "
		    "DRIVE_SPEC:\n%s", drive_spec);

		if ((rc = lm_gen_lmpl_cmd(drive_spec, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_handle_drive_offline_error: "
			    "Internal processing error encountered while "
			    "processing LMPL config drive command");
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_ERR, "lm_handle_drive_offline_error: Did "
			    "not receive a success response for LMPL config "
			    "drive command");
		} else {
			mms_trace(MMS_DEBUG, "lm_handle_drive_offline_error: "
			    "Got successful response for LMPL config drive "
			    "command");
		}
		lm_remove_lmpl_cmd(lmpl_tid, ele);
	}

			/* Generate error response for LMPM command */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7208_MSG, cmd, acsls, "STATUS_DRIVE_OFFLINE", cmd,
	    acsls, "STATUS_DRIVE_OFFLINE");

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_STATE),
	    mms_sym_code_to_str(MMS_LM_E_READY), msg_str);
}

/*
 * lm_handle_drive_not_in_lib_error()
 *
 * Parameters:
 *	- drive		The name of the drive in the LMPM command
 *	- geometry	The geometry of the drive in the ACSLS library
 *	- cart		If the LMPM command is a unmount, it contains the
 *			cartridge barcode. If the LMPM command is mount, it
 *			contains an empty string.
 *	- panel		The ACSLS panel number of the drive.
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is STATUS_DRIVE_NOT_IN_LIBRARY.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_drive_not_in_lib_error(char *drive, char *serialnum, char *geometry,
char *cart, int panel, char *acsls, char *cmd, char *tid, char *msg)
{
	int	rc;
	int	lmpl_tid;

	char	msg_str[1024];
	char	drive_spec[1024];

	lmpl_rsp_ele_t	*ele;

			/* Send alert message to operator indicating */
			/* that a drive was not found in ACSLS library */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7219_MSG, drive, serialnum, drive, serialnum);
	lm_message("operator", "alert", msg_str);

			/* Generate LMPL config drive command to update */
			/* state of drive to not accessible in MM's database */
	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_handle_drive_not_in_lib_error: "
		    "lm_obtain_task_id failed trying to generate LMPL config "
		    "drive command");
	} else {

		if (strcmp(acsls, "acs_mount") == 0)
			(void) snprintf(drive_spec, sizeof (drive_spec),
			    "config task[\"%d\"] scope[partial]"
			    " drive [\"%s\" \"%s\" \"panel %d\" \"none\" false "
			    "false];", lmpl_tid, serialnum, geometry, panel);
		else
			(void) snprintf(drive_spec, sizeof (drive_spec),
			    "config task[\"%d\"] scope[partial]"
			    " drive [\"%s\" \"%s\" \"panel %d\" \"%s\" true "
			    "false];",
			    lmpl_tid, serialnum, geometry, panel, cart);

		mms_trace(MMS_DEBUG, "lm_handle_drive_not_in_lib_error: "
		    "DRIVE_SPEC:\n%s", drive_spec);

		if ((rc = lm_gen_lmpl_cmd(drive_spec, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_handle_drive_not_in_lib_error: "
			    "Internal processing error encountered while "
			    "processing LMPL config drive command");
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_ERR, "lm_handle_drive_not_in_lib_error: "
			    "Did not receive a success response for LMPL "
			    "config drive command");
		} else {
			mms_trace(MMS_DEBUG,
			    "lm_handle_drive_not_in_lib_error: "
			    "Got successful response for LMPL config drive "
			    "command");
		}
		lm_remove_lmpl_cmd(lmpl_tid, ele);
	}

			/* Generate error response for LMPM command */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7208_MSG, cmd, acsls, "STATUS_DRIVE_NOT_IN_LIBRARY",
	    cmd, acsls, "STATUS_DRIVE_NOT_IN_LIBRARY");

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_STATE),
	    mms_sym_code_to_str(MMS_LM_E_READY), msg_str);
}

/*
 * lm_handle_drive_available_error()
 *
 * Parameters:
 *	- drive		The name of the drive in the LMPM command
 *	- geometry	The geometry of the drive in the ACSLS library
 *	- cart		The cartridge name that was suppose to be in drive.
 *	- panel		The ACSLS panel number of the drive.
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is STATUS_DRIVE_AVAILABLE.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_drive_available_error(char *drive, char *serialnum, char *geometry,
/* LINTED argument unused in function: acsls */
char *cart, int panel, char *acsls, char *cmd, char *tid, char *msg)
{
	int	rc;
	int	lmpl_tid;

	char	msg_str[1024];
	char	drive_spec[1024];

	lmpl_rsp_ele_t	*ele;

			/* Send alert message to operator indicating */
			/* that a drive was found to be empty in the */
			/* ACSLS library */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7220_MSG, cart, drive, serialnum,
	    cart, drive, serialnum);
	lm_message("operator", "alert", msg_str);

			/* Generate LMPL config drive command to update */
			/* state of drive to accessible in MM's database */
			/* as well as delete the SLOT for the cartridge */
			/* that was suppose to be in drive */
	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_handle_drive_available_error: "
		    "lm_obtain_task_id failed trying to generate LMPL config "
		    "drive and delslot command");
	} else {

		(void) snprintf(drive_spec, sizeof (drive_spec),
		    "config task[\"%d\"] scope[partial] drive "
		    "[\"%s\" \"%s\" \"panel %d\" \"none\" false true] delslots "
		    "[\"%s\"];", lmpl_tid, serialnum, geometry, panel, cart);

		mms_trace(MMS_DEBUG, "lm_handle_drive_available_error: "
		    "DRIVE_SPEC:\n%s", drive_spec);

		if ((rc = lm_gen_lmpl_cmd(drive_spec, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_handle_drive_available_error: "
			    "Internal processing error encountered while "
			    "processing LMPL config drive and delslot "
			    "command");
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_ERR, "lm_handle_drive_available_error: "
			    "Did not receive a success response for LMPL "
			    "config drive and delslot command");
		} else {
			mms_trace(MMS_DEBUG,
			    "lm_handle_drive_available_error: Got "
			    "successful response for LMPL config drive "
			    "and delslot command");
		}
		lm_remove_lmpl_cmd(lmpl_tid, ele);
	}

	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7215_MSG, cmd, drive, cart, cmd, drive, cart);

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_STATE),
	    mms_sym_code_to_str(MMS_LM_E_SCREMPTY), msg_str);
}

/*
 * lm_handle_lsm_offline()
 *
 * Parameters:
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is STATUS_LSM_OFFLINE.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_lsm_offline(int lsm, char *acsls, char *cmd, char *tid, char *msg)
{
	char	msg_str[1024];

			/* If only one lsm in library set state of */
			/* library to broken */
	if (lm.lm_lsms == 1) {
		if (lm_common_ready(LM_BROKE, tid, msg) != LM_OK) {
			mms_trace(MMS_ERR, "lm_handle_lsm_offline_error: "
			    "Failure while issueing ready command to MM. "
			    "Unable to set state of LM to broken in MM's "
			    "database.");
		}
		lm_state = LM_BROKEN;
	}

			/* Send alert message to operator indicating */
			/* that the lsm is set to offline on the */
			/* ACSLS server */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7211_MSG, lm.lm_acs, lsm, lm.lm_acs, lsm);
	lm_message("operator", "alert", msg_str);

	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7208_MSG, cmd, acsls, "STATUS_LSM_OFFLINE",
	    cmd, acsls, "STATUS_LSM_OFFLINE");

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_STATE),
	    mms_sym_code_to_str(MMS_LM_E_READY), msg_str);
}

/*
 * lm_handle_database_error()
 *
 * Parameters:
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is STATUS_DATABASE_ERROR.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_database_error(char *acsls, char *cmd, char *tid, char *msg)
{
	char	msg_str[1024];

			/* Switch state of library to broken */
	if (lm_common_ready(LM_BROKE, tid, msg) != LM_OK) {
		mms_trace(MMS_ERR, "lm_handle_database_error: Failure while "
		    "issueing ready command to MM. Unable to set "
		    "state of LM to broken in MM's database.");
	}
	lm_state = LM_BROKEN;

			/* Send alert message to operator indicating */
			/* that the ACSLS database is generating an error */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7207_MSG, "STATUS_DATABASE_ERROR", acsls,
	    "STATUS_DATABASE_ERROR", acsls);
	lm_message("operator", "alert", msg_str);

			/* Create error response for LMPM command */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7208_MSG, cmd, acsls, "STATUS_DATABASE_ERROR",
	    cmd, acsls, "STATUS_DATABASE_ERROR");

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_LIBRARY), msg_str);
}

/*
 * lm_handle_configuration_error()
 *
 * Parameters:
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is STATUS_CONFIGURATION_ERROR.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_configuration_error(char *acsls, char *cmd, char *tid, char *msg)
{
	char	msg_str[1024];

			/* Switch state of library to broken */
	if (lm_common_ready(LM_BROKE, tid, msg) != LM_OK) {
		mms_trace(MMS_ERR,
		    "lm_handle_configuration_error: Failure while "
		    "issueing ready command to MM. Unable to set "
		    "state of LM to broken in MM's database.");
	}
	lm_state = LM_BROKEN;

			/* Send alert message to operator indicating */
			/* that the ACSLS server has a configuration */
			/* issue */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7207_MSG, "STATUS_CONFIGURATION_ERROR", acsls,
	    "STATUS_CONFIGURATION_ERROR", acsls);
	lm_message("operator", "alert", msg_str);

			/* Create error response for LMPM command */
	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7208_MSG, cmd, acsls, "STATUS_CONFIGURATION_ERROR",
	    cmd, acsls, "STATUS_CONFIGURATION_ERROR");

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_LIBRARY), msg_str);
}

/*
 * lm_handle_library_not_available()
 *
 * Parameters:
 *	- acsls		The ACSLS command that returned this error.
 *	- cmd		The LMPM command being processed.
 *	- tid		The task id of the LMPM command.
 *	- msg		Will contain the error response for the LMPM command.
 *
 * Description:
 *	This function is invoked when the response status to an ACSLS command
 *	is STATUS_LIBRARY_NOT_AVAILABLE.
 *
 * Return Value:
 *	None
 *
 */
static void
lm_handle_library_not_available(char *acsls, char *cmd, char *tid, char *msg)
{
	char	msg_str[1024];

	acs_rsp_ele_t		*acs_rsp;
	ACS_QUERY_SRV_RESPONSE	*srv_qp;
	QU_SRV_STATUS		*srv_sp;

	if (lm_common_ready(LM_BROKE, tid, msg) != LM_OK) {
		mms_trace(MMS_ERR, "lm_handle_library_not_available: Failure "
		    "while issueing ready command to MM. Unable to set "
		    "state of LM to broken in MM's database.");
	}
	lm_state = LM_BROKEN;

			/* Obtain the state of the ACSLS server */
	if (lm_acs_query_server(&acs_rsp, cmd, tid, msg) != LM_ERROR) {
		srv_qp = (ACS_QUERY_SRV_RESPONSE *)acs_rsp->acs_rbuf;
		if (srv_qp->query_srv_status == STATUS_SUCCESS) {
			srv_sp = &srv_qp->srv_status[0];
				/* Send alert message to operator with */
				/* state of server */
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7202_MSG, acs_state(srv_sp->state),
			    acs_state(srv_sp->state));
			lm_message("operator", "alert", msg_str);

				/* Create error response with state of server */
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7200_MSG, cmd, acsls,
			    acs_state(srv_sp->state), cmd,
			    acsls, acs_state(srv_sp->state));
		} else {
				/* Send alert message to operator without */
				/* state of server */
			(void) snprintf(msg_str, sizeof (msg_str), LM_7206_MSG);
			lm_message("operator", "alert", msg_str);

				/* Create error response without the state */
				/* of the server */
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7201_MSG, cmd, acsls, cmd, acsls);
		}
	} else {
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7201_MSG, cmd, acsls, cmd, acsls);
	}

	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_STATE),
	    mms_sym_code_to_str(MMS_LM_E_READY), msg_str);
}

void
lm_handle_acsls_error(STATUS status, char *acsls, char *cmd, char *tid,
char *msg)
{

	char msg_str[1024];

	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7232_MSG, cmd, acsls, acs_status(status), cmd,
	    acsls, acs_status(status));
	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

}

void
lm_handle_query_vol_error(STATUS status, char *cmd, char *tid, char *msg)
{
	int	class;
	int	code;

	char	msg_str[512];

	switch (status) {
		case STATUS_AUDIT_IN_PROGRESS:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7204_MSG, cmd, cmd);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_RETRY),
			    mms_sym_code_to_str(MMS_LM_E_AGAIN), msg_str);
			return;

		case STATUS_COMMAND_ACCESS_DENIED:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7222_MSG, "acs_query_volume",
			    "acs_query_volume");
			lm_message("operator", "alert", msg_str);
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7205_MSG, cmd, "acs_query_volume",
			    cmd, "acs_query_volume");
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_DEVPREM), msg_str);
			return;

		case STATUS_DATABASE_ERROR:
			lm_handle_database_error("acs_query_volume", cmd, tid,
			    msg);
			return;

		case STATUS_LIBRARY_NOT_AVAILABLE:
			lm_handle_library_not_available("acs_query_volume",
			    cmd, tid, msg);
			return;

		case STATUS_PROCESS_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7221_MSG, "acs_query_volume",
			    acs_status(status), "acs_query_volume",
			    acs_status(status));
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_DEVCOMMERR;
			break;

			/* Non of the following status should be returned */
			/* as a response for a query_volume */
		case STATUS_CANCELLED:
		case STATUS_COUNT_TOO_LARGE:
		case STATUS_COUNT_TOO_SMALL:
		case STATUS_INVALID_OPTION:
		case STATUS_INVALID_TYPE:
		case STATUS_INVALID_VERSION:
		case STATUS_LOCKID_NOT_FOUND:
		case STATUS_MESSAGE_TOO_LARGE:
		case STATUS_MESSAGE_TOO_SMALL:
		case STATUS_MISSING_OPTION:
		case STATUS_UNSUPPORTED_OPTION:
		case STATUS_UNSUPPORTED_TYPE:
		default:
			class = MMS_INTERNAL;
			code = MMS_LM_E_INTERNAL;
			break;
	}

	lm_handle_acsls_status_error(class, code, status, "acs_query_volume",
	    cmd, tid, msg);
}

void
lm_handle_query_mount_error(STATUS status, char *cmd, char *tid, char *msg)
{
	int	class;
	int	code;

	char	msg_str[512];

	switch (status) {
		case STATUS_AUDIT_IN_PROGRESS:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7204_MSG, cmd, cmd);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_RETRY),
			    mms_sym_code_to_str(MMS_LM_E_AGAIN), msg_str);
			return;

		case STATUS_COMMAND_ACCESS_DENIED:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7222_MSG, "acs_query_mount",
			    "acs_query_mount");
			lm_message("operator", "alert", msg_str);
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7205_MSG, cmd, "acs_query_mount",
			    cmd, "acs_query_mount");
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_DEVPREM), msg_str);
			return;

		case STATUS_DATABASE_ERROR:
			lm_handle_database_error("acs_query_mount", cmd, tid,
			    msg);
			return;

		case STATUS_LIBRARY_NOT_AVAILABLE:
			lm_handle_library_not_available("acs_query_mount",
			    cmd, tid, msg);
			return;

		case STATUS_PROCESS_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7221_MSG, "acs_query_mount",
			    acs_status(status), "acs_query_mount",
			    acs_status(status));
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_DEVCOMMERR;
			break;

			/* Non of the following status should be returned */
			/* as a response for a query_volume */
		case STATUS_CANCELLED:
		case STATUS_COUNT_TOO_LARGE:
		case STATUS_COUNT_TOO_SMALL:
		case STATUS_INVALID_OPTION:
		case STATUS_INVALID_TYPE:
		case STATUS_INVALID_VERSION:
		case STATUS_LOCKID_NOT_FOUND:
		case STATUS_MESSAGE_TOO_LARGE:
		case STATUS_MESSAGE_TOO_SMALL:
		case STATUS_MISSING_OPTION:
		case STATUS_UNSUPPORTED_OPTION:
		case STATUS_UNSUPPORTED_TYPE:
		default:
			class = MMS_INTERNAL;
			code = MMS_LM_E_INTERNAL;
			break;
	}

	lm_handle_acsls_status_error(class, code, status, "acs_query_mount",
	    cmd, tid, msg);
}

void
lm_handle_mount_error(STATUS status, char *drive, char *serialnum,
char *geometry, int lsm, int panel, char *cmd, char *tid, char *msg)
{
	int	class;
	int	code;

	char	msg_str[512];

	switch (status) {
		case STATUS_AUDIT_IN_PROGRESS:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7204_MSG, cmd, cmd);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_RETRY),
			    mms_sym_code_to_str(MMS_LM_E_AGAIN), msg_str);
			return;

		case STATUS_COMMAND_ACCESS_DENIED:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7222_MSG, "acs_mount", "acs_mount");
			lm_message("operator", "alert", msg_str);
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7205_MSG, cmd, "acs_mount",
			    cmd, "acs_mount");
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_DEVPREM), msg_str);
			return;

		case STATUS_DATABASE_ERROR:
			lm_handle_database_error("acs_mount", cmd, tid,
			    msg);
			return;

		case STATUS_LIBRARY_NOT_AVAILABLE:
			lm_handle_library_not_available("acs_mount",
			    cmd, tid, msg);
			return;

		case STATUS_LIBRARY_BUSY:
		case STATUS_PROCESS_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7221_MSG, "acs_mount",
			    acs_status(status), "acs_mount",
			    acs_status(status));
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_DEVCOMMERR;
			break;

		case STATUS_ACS_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7217_MSG, lm.lm_acs, lm.lm_acs);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LSM_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7218_MSG, lm.lm_acs, 0,
			    lm.lm_acs, 0);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LSM_OFFLINE:
			lm_handle_lsm_offline(lsm, "acs_mount", cmd, tid, msg);
			return;

		case STATUS_DRIVE_OFFLINE:
			lm_handle_drive_offline_error(drive, serialnum,
			    geometry, "", panel, "acs_mount", cmd, tid, msg);
			return;

		case STATUS_DRIVE_IN_USE:
			class = MMS_STATE;
			code = MMS_LM_E_DESTFULL;
			break;

		case STATUS_DRIVE_NOT_IN_LIBRARY:
			lm_handle_drive_not_in_lib_error(drive, serialnum,
			    geometry, "", panel, "acs_mount", cmd, tid, msg);
			return;

		case STATUS_INCOMPATIBLE_MEDIA_TYPE:
			class = MMS_INVALID;
			code = MMS_LM_E_SHAPE;
			break;

		case STATUS_LIBRARY_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7209_MSG, "acs_mount", "acs_mount");
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_LIBRARY;
			break;

		case STATUS_VOLUME_IN_DRIVE:
			class = MMS_STATE;
			code = MMS_LM_E_ACCESS;
			break;

		case STATUS_VOLUME_NOT_IN_LIBRARY:
		case STATUS_VOLUME_MISSING:
		case STATUS_VOLUME_ABSENT:
			class = MMS_EXIST;
			code = MMS_LM_E_NOPCL;
			break;

			/* Non of the following status should be returned */
			/* as a response for a mount */
		case STATUS_CANCELLED:
		case STATUS_COUNT_TOO_LARGE:
		case STATUS_COUNT_TOO_SMALL:
		case STATUS_INVALID_ACS:
		case STATUS_INVALID_DRIVE:
		case STATUS_INVALID_DRIVE_TYPE:
		case STATUS_INVALID_LSM:
		case STATUS_INVALID_MEDIA_TYPE:
		case STATUS_INVALID_OPTION:
		case STATUS_INVALID_TYPE:
		case STATUS_INVALID_VERSION:
		case STATUS_LOCKID_NOT_FOUND:
		case STATUS_MESSAGE_TOO_LARGE:
		case STATUS_MESSAGE_TOO_SMALL:
		case STATUS_MISPLACED_TAPE:
		case STATUS_MISSING_OPTION:
		case STATUS_NOT_IN_SAME_ACS:
		case STATUS_UNSUPPORTED_OPTION:
		case STATUS_UNSUPPORTED_TYPE:
		default:
			class = MMS_INTERNAL;
			code = MMS_LM_E_INTERNAL;
			break;
	}

	lm_handle_acsls_status_error(class, code, status, "acs_mount", cmd,
	    tid, msg);
}

void
lm_handle_dismount_error(STATUS status, char *drive, char *serialnum,
char *geometry, char *cart, int lsm, int panel, char *cmd, char *tid, char *msg)
{
	int	class;
	int	code;

	char	msg_str[512];

	switch (status) {
		case STATUS_AUDIT_IN_PROGRESS:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7204_MSG, cmd, cmd);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_RETRY),
			    mms_sym_code_to_str(MMS_LM_E_AGAIN), msg_str);
			return;

		case STATUS_COMMAND_ACCESS_DENIED:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7222_MSG, "acs_dismount", "acs_dismount");
			lm_message("operator", "alert", msg_str);
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7205_MSG, cmd, "acs_dismount",
			    cmd, "acs_dismount");
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_DEVPREM), msg_str);
			return;

		case STATUS_ACS_FULL:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7216_MSG, cmd, lm.lm_acs, cmd, lm.lm_acs);
			lm_message("operator", "alert", msg_str);

			class = MMS_STATE;
			code = MMS_LM_E_DEVPREM;
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(class),
			    mms_sym_code_to_str(code), msg_str);
			return;

		case STATUS_DRIVE_AVAILABLE:
			lm_handle_drive_available_error(drive, serialnum,
			    geometry, cart,
			    panel, "acs_dismount", cmd, tid, msg);
			return;

		case STATUS_DATABASE_ERROR:
			lm_handle_database_error("acs_dismount", cmd, tid,
			    msg);
			return;

		case STATUS_LIBRARY_NOT_AVAILABLE:
			lm_handle_library_not_available("acs_dismount",
			    cmd, tid, msg);
			return;

		case STATUS_LIBRARY_BUSY:
		case STATUS_PROCESS_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7221_MSG, "acs_dismount",
			    acs_status(status), "acs_dismount",
			    acs_status(status));
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_DEVCOMMERR;
			break;

		case STATUS_ACS_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7217_MSG, lm.lm_acs, lm.lm_acs);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LSM_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7218_MSG, lm.lm_acs, 0, lm.lm_acs, 0);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LSM_OFFLINE:
			lm_handle_lsm_offline(lsm, "acs_dismount", cmd, tid,
			    msg);
			return;

		case STATUS_DRIVE_OFFLINE:
			lm_handle_drive_offline_error(drive, serialnum,
			    geometry, cart,
			    panel, "acs_dismount", cmd, tid, msg);
			return;

		case STATUS_DRIVE_IN_USE:
			class = MMS_STATE;
			code = MMS_LM_E_DESTFULL;
			break;

		case STATUS_DRIVE_NOT_IN_LIBRARY:
			lm_handle_drive_not_in_lib_error(drive, serialnum,
			    geometry, cart,
			    panel, "acs_dismount", cmd, tid, msg);
			return;

		case STATUS_LIBRARY_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7209_MSG, "acs_dismount", "acs_dismount");
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_LIBRARY;
			break;

		case STATUS_VOLUME_NOT_IN_DRIVE:
			class = MMS_INVALID;
			code = MMS_LM_E_PCL;
			break;

		case STATUS_VOLUME_NOT_IN_LIBRARY:
			class = MMS_EXIST;
			code = MMS_LM_E_NOPCL;
			break;

		case STATUS_VOLUME_ACCESS_DENIED:
			class = MMS_PERMPRIV;
			code = MMS_LM_E_DEVPREM;
			break;

		case STATUS_UNREADABLE_LABEL:
			class = MMS_INVALID;
			code = MMS_LM_E_NOPCL;
			break;

			/* Non of the following status should be returned */
			/* as a response for a dismount */
		case STATUS_CANCELLED:
		case STATUS_COUNT_TOO_LARGE:
		case STATUS_COUNT_TOO_SMALL:
		case STATUS_INVALID_ACS:
		case STATUS_INVALID_DRIVE:
		case STATUS_INVALID_LSM:
		case STATUS_INVALID_OPTION:
		case STATUS_INVALID_VERSION:
		case STATUS_INVALID_VOLUME:
		case STATUS_LOCKID_NOT_FOUND:
		case STATUS_MESSAGE_TOO_LARGE:
		case STATUS_MESSAGE_TOO_SMALL:
		case STATUS_MISPLACED_TAPE:
		case STATUS_UNSUPPORTED_OPTION:
		default:
			class = MMS_INTERNAL;
			code = MMS_LM_E_INTERNAL;
			break;
	}

	lm_handle_acsls_status_error(class, code, status, "acs_mount", cmd,
	    tid, msg);
}

void
lm_handle_enter_error(STATUS status, char *cap, int lsm, char *cmd, char *tid,
char *msg)
{
	int	class;
	int	code;

	char	msg_str[512];

	switch (status) {

		case STATUS_CAP_IN_USE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7212_MSG, cap, cap);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_RETRY),
			    mms_sym_code_to_str(MMS_LM_E_AGAIN), msg_str);
			return;

		case STATUS_CAP_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7117_MSG, cap, cap);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INVALID),
			    mms_sym_code_to_str(MMS_LM_E_PORT), msg_str);
			return;

		case STATUS_CAP_OFFLINE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7214_MSG, cap, "enter", cap, "enter");
			lm_message("operator", "alert", msg_str);

			class = MMS_STATE;
			code = MMS_LM_E_READY;
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_READY), msg_str);
			return;

		case STATUS_INCORRECT_CAP_MODE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7213_MSG, cap, cap);
			lm_message("operator", "alert", msg_str);

			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_DEVPREV), msg_str);
			return;

		case STATUS_COMMAND_ACCESS_DENIED:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7222_MSG, "acs_enter", "acs_enter");
			lm_message("operator", "alert", msg_str);
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7205_MSG, cmd, "acs_enter",
			    cmd, "acs_enter");
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_DEVPREM), msg_str);
			return;

		case STATUS_DATABASE_ERROR:
			lm_handle_database_error("acs_enter", cmd, tid,
			    msg);
			return;

		case STATUS_CONFIGURATION_ERROR:
			lm_handle_configuration_error("acs_enter", cmd,
			    tid, msg);
			return;

		case STATUS_LIBRARY_NOT_AVAILABLE:
			lm_handle_library_not_available("acs_enter",
			    cmd, tid, msg);
			return;

		case STATUS_LIBRARY_BUSY:
		case STATUS_PROCESS_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7221_MSG, "acs_enter",
			    acs_status(status), "acs_enter",
			    acs_status(status));
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_DEVCOMMERR;
			break;

		case STATUS_ACS_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7217_MSG, lm.lm_acs, lm.lm_acs);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LSM_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7218_MSG, lm.lm_acs, 0, lm.lm_acs, 0);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LIBRARY_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7209_MSG, "acs_enter", "acs_enter");
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_LIBRARY;
			break;

		case STATUS_LSM_OFFLINE:
			lm_handle_lsm_offline(lsm, "acs_enter", cmd, tid, msg);
			return;

			/* Non of the following status should be returned */
			/* as a response for a enter */
		case STATUS_CANCELLED:
		case STATUS_COUNT_TOO_LARGE:
		case STATUS_COUNT_TOO_SMALL:
		case STATUS_INVALID_ACS:
		case STATUS_INVALID_CAP:
		case STATUS_INVALID_LSM:
		case STATUS_INVALID_MEDIA_TYPE:
		case STATUS_INVALID_OPTION:
		case STATUS_INVALID_VERSION:
		case STATUS_LOCKID_NOT_FOUND:
		case STATUS_MESSAGE_TOO_LARGE:
		case STATUS_MESSAGE_TOO_SMALL:
		case STATUS_UNSUPPORTED_OPTION:
		default:
			class = MMS_INTERNAL;
			code = MMS_LM_E_INTERNAL;
			break;
	}

	lm_handle_acsls_status_error(class, code, status, "acs_enter", cmd,
	    tid, msg);
}

void
lm_handle_eject_error(STATUS status, char *cap, int lsm, char *cmd, char *tid,
char *msg)
{
	int	class;
	int	code;

	char	msg_str[512];

	switch (status) {

		case STATUS_CAP_IN_USE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7212_MSG, cap, cap);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_RETRY),
			    mms_sym_code_to_str(MMS_LM_E_AGAIN), msg_str);
			return;

		case STATUS_CAP_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7117_MSG, cap, cap);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INVALID),
			    mms_sym_code_to_str(MMS_LM_E_PORT), msg_str);
			return;

		case STATUS_CAP_OFFLINE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7214_MSG, cap, "eject", cap, "eject");
			lm_message("operator", "alert", msg_str);

			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_READY), msg_str);
			return;

		case STATUS_COMMAND_ACCESS_DENIED:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7222_MSG, "acs_eject", "acs_eject");
			lm_message("operator", "alert", msg_str);
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7205_MSG, cmd, "acs_eject", cmd, "acs_eject");
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_DEVPREM), msg_str);
			return;

		case STATUS_DATABASE_ERROR:
			lm_handle_database_error("acs_eject", cmd, tid,
			    msg);
			return;

		case STATUS_CONFIGURATION_ERROR:
			lm_handle_configuration_error("acs_eject", cmd,
			    tid, msg);
			return;

		case STATUS_LIBRARY_NOT_AVAILABLE:
			lm_handle_library_not_available("acs_eject",
			    cmd, tid, msg);
			return;

		case STATUS_LIBRARY_BUSY:
		case STATUS_PROCESS_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7221_MSG, "acs_eject", acs_status(status),
			    "acs_eject", acs_status(status));
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_DEVCOMMERR;
			break;

		case STATUS_ACS_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7217_MSG, lm.lm_acs, lm.lm_acs);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LSM_NOT_IN_LIBRARY:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7218_MSG, lm.lm_acs, 0,
			    lm.lm_acs, 0);
			(void) snprintf(msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
			return;

		case STATUS_LIBRARY_FAILURE:
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7209_MSG, "acs_eject", "acs_eject");
			lm_message("operator", "alert", msg_str);
			class = MMS_INTERNAL;
			code = MMS_LM_E_LIBRARY;
			break;

		case STATUS_LSM_OFFLINE:
			lm_handle_lsm_offline(lsm, "acs_eject", cmd, tid, msg);
			return;

			/* Non of the following status should be returned */
			/* as a response for a eject */
		case STATUS_CANCELLED:
		case STATUS_COUNT_TOO_LARGE:
		case STATUS_COUNT_TOO_SMALL:
		case STATUS_INVALID_ACS:
		case STATUS_INVALID_CAP:
		case STATUS_INVALID_LSM:
		case STATUS_INVALID_OPTION:
		case STATUS_INVALID_RANGE:
		case STATUS_INVALID_VERSION:
		case STATUS_LOCKID_NOT_FOUND:
		case STATUS_MESSAGE_TOO_LARGE:
		case STATUS_MESSAGE_TOO_SMALL:
		case STATUS_UNSUPPORTED_OPTION:
		case STATUS_VOLUME_ACCESS_DENIED:
		default:
			class = MMS_INTERNAL;
			code = MMS_LM_E_INTERNAL;
			break;
	}

	lm_handle_acsls_status_error(class, code, status, "acs_eject", cmd,
	    tid, msg);
}

void
lm_handle_acsls_state(STATE state, char *acsls, char *cmd, char *tid, char *msg)
{

	int class;
	int code;
	char msg_str[1024];

	class = MMS_INTERNAL;
	code = MMS_LM_E_DEVCMD;

	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7234_MSG, cmd, acsls, acs_state(state),
	    cmd, acsls, acs_state(state));
	(void) snprintf(msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid, mms_sym_code_to_str(class),
	    mms_sym_code_to_str(code), msg_str);

}

acs_rsp_ele_t *
lm_obtain_acs_response(SEQ_NO seq, char *cmd, char *tid, char *msg)
{

	int		rc;
	int		not_timeout;
	int		acs_bad_pkt = 0;

	char		msg_str[1024];

	struct timespec	timeout;

	acs_rsp_ele_t	*ele;
	acs_rsp_ele_t	*next;
	acs_rsp_ele_t	*new_rsp;

			/* Lock acs response queue */
	if ((rc = pthread_mutex_lock(&acs_rsp.acs_mutex)) != 0) {
		lm_serr(MMS_CRIT, "lm_obtain_acs_response: Lock of acs "
		    "response queue's mutex failed with errno "
		    "- %s", strerror(errno));
		return (NULL);
	}
	while (!lm_internal_error) {

			/* Go through queue to see if a response for seq */
			/* already exists */
		mms_list_foreach_safe(&acs_rsp.acs_queue, ele, next) {
			if (ele->acs_seq_nmbr == seq) {
				mms_trace(MMS_DEBUG,
				    "ele->acs_seq_nmbr: Thread "
				    "found a acs response for itself, seq "
				    "number - %d", seq);
					/* Found a reponse, remove from list */
				mms_list_remove(&acs_rsp.acs_queue, ele);
					/* Unlock response queue */
				if ((rc = pthread_mutex_unlock(
				    &acs_rsp.acs_mutex)) != 0) {
					lm_serr(MMS_CRIT,
					    "lm_obtain_acs_response: "
					    "Unlock of acs response "
					    "queue's mutex failed with "
					    "errno - %s",
					    strerror(errno));
					return (NULL);
				}
					/* Return response */
				return (ele);
			}
		}

		/* Did not find a response for thread */
		mms_trace(MMS_DEBUG,
		    "lm_obtain_acs_response: acs_rsp.acs_reading - "
		    "%d", acs_rsp.acs_reading);
		if (acs_rsp.acs_reading) {
			mms_trace(MMS_DEBUG,
			    "lm_obtain_acs_response: Reader thread "
			    "already exists, going into wait, seq number "
			    "- %d", seq);

			not_timeout = 1;
			while (not_timeout) {
				timeout.tv_sec = time(NULL) + LM_THREAD_WAIT;
				timeout.tv_nsec = 0;
				rc = pthread_cond_timedwait(&acs_rsp.acs_cv,
				    &acs_rsp.acs_mutex, &timeout);
				if (rc == ETIMEDOUT)
					if (!lm_internal_error)
						continue;
					else
						break;
				else if (rc != 0) {
					lm_serr(MMS_CRIT,
					    "lm_obtain_acs_response: "
					    "Unable to wait on acs response "
					    "queue's condition variable, "
					    "errno - %s", strerror(errno));
					(void) pthread_mutex_unlock(
					    &acs_rsp.acs_mutex);
					return (NULL);
				}
				not_timeout = 0;
			}
			mms_trace(MMS_DEBUG,
			    "lm_obtain_acs_response: Thread woke up "
			    "by broadcast from reader thread, seq number - "
			    "%d", seq);
		} else {
				/* No acs reader, become reader */
			break;
		}
	}

	if (lm_internal_error)
		return (NULL);

	mms_trace(MMS_DEBUG,
	    "lm_obtain_acs_response: Thread becoming acs_response "
	    "reader, seq number - %d", seq);
	acs_rsp.acs_reading = 1;
	while (!lm_internal_error) {
			/* Unlock acs's response mutex so other threads */
			/* can look at response queue, Need to relock it */
			/* when a acs response is obtained */
		if ((rc = pthread_mutex_unlock(&acs_rsp.acs_mutex)) != 0) {
			lm_serr(MMS_CRIT,
			    "lm_obtain_acs_response: Unlock of acs "
			    "response queue's mutex failed with errno "
			    "- %s", strerror(errno));
			return (NULL);
		}

			/* Obtain next response from acsls ssi */
		if ((new_rsp = (acs_rsp_ele_t *)malloc(sizeof (acs_rsp_ele_t)))
		    == NULL) {
			lm_serr(MMS_CRIT, "lm_obtain_acs_response: Unable to "
			    "malloc space for new acs response, seq num "
			    "- %d, errno - %s", seq, strerror(errno));
			return (NULL);
		}
		(void) memset(new_rsp, 0, sizeof (acs_rsp_ele_t));
			/* XXX NEED TO CHANGE THIS TO DO A TIMEOUT */
			/* CURRENTLY BLOCK FOR EVER, MAKE SURE CHECK */
			/* STATUS FOR PENDING */
		mms_trace(MMS_DEBUG,
		    "lm_obtain_acs_response: Read next response from "
		    "acsls server, seq number - %d", seq);

			/* This is done so that if type is not set */
			/* by acsls code below is insured to work */
/*
 *		new_rsp->acs_type = RT_NONE;
 */

		do {
			new_rsp->acs_status = acs_response(-1,
			    &new_rsp->acs_seq_nmbr, &new_rsp->acs_req_id,
			    &new_rsp->acs_type, new_rsp->acs_rbuf);
			if (new_rsp->acs_type == RT_NONE) {
				mms_trace(MMS_WARN, "lm_obtain_acs_response: "
				    "acs_response() returned a RT_NONE "
				    "response, status - %s",
				    acs_status(new_rsp->acs_status));
				if (new_rsp->acs_status == STATUS_NI_FAILURE) {
					mms_trace(MMS_CRIT,
					    "lm_obtain_acs_response: "
					    "lost connection to the CSI "
					    "on the ACSLS server");
					if ((rc = lm_common_ready(LM_DISCONN,
					    tid, msg)) != LM_OK)
						mms_trace(MMS_ERR,
						    "lm_obtain_acs_response: "
						    "Failure encountered while "
						    "issueing ready disconnect "
						    "command to MM.");
					lm_state = LM_DISCONNECTED;
						/* Send message to operator */
						/* indicating issue */
					(void) snprintf(msg_str,
					    sizeof (msg_str),
					    LM_7203_MSG,
					    acs_status(new_rsp->acs_status),
					    acs_status(new_rsp->acs_status));
						/* No need to check return */
						/* status */
					lm_message("operator", "alert",
					    msg_str);
						/* Create error message for */
						/* LMPM command */
					(void) snprintf(msg_str,
					    sizeof (msg_str),
					    LM_7225_MSG, cmd,
					    acs_status(new_rsp->acs_status),
					    cmd,
					    acs_status(new_rsp->acs_status));
					(void) snprintf(msg, RMBUFSIZE,
					    LM_ERR_FINAL, tid,
					    mms_sym_code_to_str(MMS_INTERNAL),
					    mms_sym_code_to_str(
					    MMS_LM_E_DEVCOMMERR), msg_str);
					return (NULL);
				}
				if (++acs_bad_pkt > MAX_BAD_ACS_PKT) {
					/* XXX ADDITIONAL CHECKS CAN */
					/* BE DONE TO VERIFY THAT THE */
					/* LIBRARY IS STILL ACTIVE */
					lm_serr(MMS_CRIT,
					    "lm_obtain_acs_response: "
					    "acsls returned multiple "
					    "RT_NONE response packets that "
					    "exceed threshold");
/*
 *	LEAVING FOR WHEN RECOVERY IS ADDED TO
 *	CHECK FOR LIBRARY. WHEN DONE LM WILL
 *	SWITCH LIBRARY TO BROKEN STATE
 *					*class = MMS_INTERNAL;
 *					*code = MMS_LM_E_LIBRARY;
 *					sprintf(msg_str, LM_7231_MSG);
 *					free(new_rsp);
 */
					return (NULL);
				}
			}
		} while (new_rsp->acs_type == RT_NONE);

		acs_bad_pkt = 0;

			/* Lock acs's response mutex */
		if ((rc = pthread_mutex_lock(&acs_rsp.acs_mutex)) != 0) {
			lm_serr(MMS_CRIT, "lm_obtain_acs_response: Lock of acs "
			    "response queue's mutex failed with errno "
			    "- %s", strerror(errno));
			return (NULL);
		}

			/* See if response is for this thread or another */
		if (new_rsp->acs_seq_nmbr == seq) {
			mms_trace(MMS_DEBUG,
			    "lm_obtain_acs_response: Reader thread "
			    "found a response for itself, seq number - %d"
			    ", %d", seq, acs_rsp.acs_reading);
			acs_rsp.acs_reading = 0;
				/* Wake up any other threads waiting for a */
				/* acs_response so one of them can take over */
				/* as the reader */
			if ((rc = pthread_cond_broadcast(&acs_rsp.acs_cv))
			    != 0) {
				lm_serr(MMS_CRIT, "lm_obtain_acs_response: "
				    "broadcast to wake up threads waiting "
				    "for a acs_response failed with errno "
				    "- %s", strerror(errno));
				return (NULL);
			}
			if ((rc = pthread_mutex_unlock(&acs_rsp.acs_mutex))
			    != 0) {
				lm_serr(MMS_CRIT,
				    "lm_obtain_acs_response: Unlock "
				    "of acs response queue's mutex failed "
				    "with errno - %s", strerror(errno));
				return (NULL);
			}
			return (new_rsp);
		}

		mms_trace(MMS_DEBUG,
		    "lm_obtain_acs_response: Reader thread received "
		    "a acs response that does not belong to it, seq "
		    "number for response - %d", new_rsp->acs_seq_nmbr);
			/* Add new response to acs response queue */
		mms_list_insert_tail(&acs_rsp.acs_queue, new_rsp);

			/* Broadcast to other threads waiting on responses */
		if ((rc = pthread_cond_broadcast(&acs_rsp.acs_cv)) != 0) {
			lm_serr(MMS_CRIT,
			    "lm_obtain_acs_response: broadcast to "
			    "wake up threads waiting for a acs_response "
			    "failed with errno - %s", strerror(errno));
			(void) pthread_mutex_unlock(&acs_rsp.acs_mutex);
			return (NULL);
		}
	}

	/* If we get here then LM has detected an internal processing */
	/* error and all threads should exit as quickly as possible */
	return (NULL);
}

int
lm_acs_enter(acs_rsp_ele_t **ret_rsp, CAPID cap_id, char *cmd, char *tid,
							char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	SEQ_NO		s;
	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_ENTER_SEQ + pthread_self());

	if ((status = acs_enter(s, cap_id, 0)) != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_acs_enter() failed while processing "
		    "inject command, status - %s", acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "acs_response() for acs_inject() "
			    "failed, status - %s", acs_status(status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_enter", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG,
			    "Received acknowledge response for "
			    "acs_enter while processing inject commad");
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_enter() while processing %s cmd, "
			    "type - %s", cmd,
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "enter",
			    acs_type_response(acs_rsp->acs_type), cmd, "enter",
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_eject(acs_rsp_ele_t **ret_rsp, CAPID cap_id, VOLID vols[MAX_ID],
				int cnt, char *cmd, char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	LOCKID		lock_id = NO_LOCK_ID;
	SEQ_NO		s;
	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_EJECT_SEQ + pthread_self());

	if ((status = acs_eject(s, lock_id, cap_id, cnt, vols))
	    != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_acs_eject() failed while processing "
		    "eject command, status - %s", acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
			/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "acs_response() for acs_eject() "
			    "failed, status - %s", acs_status(status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_eject", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG,
			    "Received acknowledge response for "
			    "acs_eject while processing eject command");
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_eject() while processing %s cmd, "
			    "type - %s", cmd,
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "eject",
			    acs_type_response(acs_rsp->acs_type), cmd, "eject",
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_mount(acs_rsp_ele_t **ret_rsp, VOLID vol_id, DRIVEID drive_id,
					char *cmd, char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	LOCKID		lock_id = NO_LOCK_ID;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_MOUNT_SEQ + pthread_self());

	if ((status = acs_mount(s, lock_id, vol_id, drive_id, FALSE, FALSE))
	    != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_acs_mount() failed while processing "
		    "%s command, status - %s", cmd, acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "acs_response() for acs_mount() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(acs_rsp->acs_status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_mount", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG,
			    "Received acknowledge response for "
			    "acs_mount while processing %s command", cmd);
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_mount() while processing %s cmd, type "
			    "- %s", cmd, acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "mount",
			    acs_type_response(acs_rsp->acs_type), cmd,
			    "mount", acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_dismount(acs_rsp_ele_t **ret_rsp, VOLID vol_id, DRIVEID drive_id,
					char *cmd, char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	LOCKID		lock_id = NO_LOCK_ID;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_DISMOUNT_SEQ + pthread_self());

	if ((status = acs_dismount(s, lock_id, vol_id, drive_id, TRUE))
	    != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_acs_dismount() failed while processing "
		    "%s command, status - %s", cmd, acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "acs_response() for acs_dismount() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_dismount", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG,
			    "Received acknowledge response for "
			    "acs_dismount while processing %s command", cmd);
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_dismount() while processing %s cmd, type "
			    "- %s", cmd, acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "unmount",
			    acs_type_response(acs_rsp->acs_type), cmd,
			    "unmount", acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_query_drive(acs_rsp_ele_t **ret_rsp, DRIVEID drive_id[MAX_ID],
				int count, char *cmd, char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_Q_DRIVE_SEQ + pthread_self());

	if ((status = acs_query_drive(s, drive_id, count))
	    != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_acs_query_drive() failed while processing "
		    "%s command, status - %s", cmd, acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}
	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
			/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT,
			    "acs_response() for acs_query_drive() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(acs_rsp->acs_status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_query_drive", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}
			/* Query drives < MAX_ID should never get an */
			/* intermidate response */
		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG, "Received acknowledge response for"
			    "acs_query_drive while processing %s "
			    "command", cmd);
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_query_drive() while processing %s "
			    "command, type - %s", cmd,
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "query_drive",
			    acs_type_response(acs_rsp->acs_type), cmd,
			    "query_drive",
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_query_mount(acs_rsp_ele_t **ret_rsp, VOLID vol_id_list[MAX_ID],
				int count, char *cmd, char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_Q_MOUNT_SEQ + pthread_self());

	if ((status = acs_query_mount(s, vol_id_list, count))
	    != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_acs_query_mount() failed while processing "
		    "%s command, status - %s", cmd, acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	acs_rsp = NULL;
	do {
		if (acs_rsp != NULL)
			free(acs_rsp);
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT,
			    "acs_response() for acs_query_mount() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(acs_rsp->acs_status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_query_mount", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG, "Received acknowledge response for"
			    "acs_query_mount while processing %s "
			    "command", cmd);
			continue;
		} else if (acs_rsp->acs_type == RT_FINAL) {
			mms_trace(MMS_DEBUG, "Received final response for "
			    "acs_query_mount while processing %s command",
			    cmd);
		} else {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_query_mount() while processing %s "
			    "command, type - %s", cmd,
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "query_volume",
			    acs_type_response(acs_rsp->acs_type), cmd,
			    "query_mount",
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);
	free(acs_rsp);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_query_volume(acs_rsp_ele_t **ret_rsp, VOLID vol_id_list[MAX_ID],
				int count, char *cmd, char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_Q_VOL_SEQ + pthread_self());

	if ((status = acs_query_volume(s, vol_id_list, count))
	    != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_acs_query_volume() failed while processing "
		    "%s command, status - %s", cmd, acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT,
			    "acs_response() for acs_query_volume() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(acs_rsp->acs_status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_query_volume", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

			/* Query volumes < MAX_ID should never get an */
			/* intermidate response */
		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG, "Received acknowledge response for"
			    "acs_query_volume while processing %s "
			    "command", cmd);
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_query_volume() while processing %s "
			    "command, type - %s", cmd,
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "query_volume",
			    acs_type_response(acs_rsp->acs_type), cmd,
			    "query_volume",
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_query_cap(acs_rsp_ele_t **ret_rsp, CAPID capid[MAX_ID], char *cmd,
						char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	SEQ_NO		s;
	unsigned short	count = 0;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_Q_CAP_SEQ + pthread_self());

	if ((status = acs_query_cap(s, capid, count)) != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_acs_query_cap() failed while processing "
		    "%s command, status - %s", cmd, acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT,
			    "acs_response() for acs_query_cap() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_query_cap", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

			/* Query cap should never get an */
			/* intermidate response */
		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG,
			    "Received acknowledge response for"
			    "acs_query_cap while processing %s "
			    "command", cmd);
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_query_cap() while processing %s "
			    "command, type - %s", cmd,
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "query_cap",
			    acs_type_response(acs_rsp->acs_type), cmd,
			    "query_cap", acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_query_server(acs_rsp_ele_t **ret_rsp, char *cmd, char *tid,
char *ret_msg)
{
	STATUS		status;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_Q_SERVER_SEQ + pthread_self());

	if ((status = acs_query_server(s)) != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_acs_query_server() failed while "
		    "processing %s command, status - %s",
		    cmd, acs_status(status));
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "acs_response() "
			    "for acs_query_server() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(status));
			free(acs_rsp);
			return (LM_ERROR);
		}

			/* Query server should never get an */
			/* intermidate response */
		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG, "Received acknowledge response "
			    "for acs_query_server while processing %s "
			    "command", cmd);
			free(acs_rsp);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_query_server() while processing %s "
			    "command, type - %d", cmd, acs_rsp->acs_type);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}

int
lm_acs_display(acs_rsp_ele_t **ret_rsp, DISPLAY_XML_DATA display_xml_data,
    char *cmd, char *tid, char *ret_msg)
{
	char		msg_str[256];

	STATUS		status;
	TYPE		display_type;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;

	s = (SEQ_NO)(ACS_DISPLAY_SEQ + pthread_self());
	display_type = TYPE_DISPLAY;

	if ((status = acs_display(s, display_type, display_xml_data))
	    != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_acs_display_drive() failed while "
		    "processing %s command, status - %s", cmd,
		    acs_status(status));
		lm_handle_acs_cmd_error(status, cmd, tid, ret_msg);
		return (LM_ERROR);
	}

	do {
		if ((acs_rsp = lm_obtain_acs_response(s, cmd, tid, ret_msg))
		    == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "acs_response() for acs_display() "
			    "failed while processing %s cmd, status - %s",
			    cmd, acs_status(status));
			lm_handle_acsls_rsp_error(acs_rsp->acs_status,
			    "acs_display_drive", cmd, tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

			/* Query one volume should never get an */
			/* intermidate response */
		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG, "Received acknowledge response for"
			    "acs_display while processing %s "
			    "command", cmd);
			free(acs_rsp);
		} else if (acs_rsp->acs_type == RT_INTERMEDIATE) {
			mms_trace(MMS_DEBUG, "Received intermediate response "
			    "for acs_dispaly while processing %s commmand",
			    cmd);
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_ERR, "Received unexpected response type "
			    "for acs_display() while processing %s "
			    "command, type - %s", cmd,
			    acs_type_response(acs_rsp->acs_type));
			(void) snprintf(msg_str, sizeof (msg_str),
			    LM_7233_MSG, cmd, "display",
			    acs_type_response(acs_rsp->acs_type), cmd,
			    "display", acs_type_response(acs_rsp->acs_type));
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCOMMERR),
			    msg_str);
			free(acs_rsp);
			return (LM_ERROR);
		}
	} while (acs_rsp->acs_type != RT_FINAL);

	*ret_rsp = acs_rsp;
	return (LM_OK);
}
