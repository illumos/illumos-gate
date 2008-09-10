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


#include "lm.h"
#include <lm_proto.h>

static char *_SrcFile = __FILE__;

static char *lm_c_priv_set[] =  {
	"LMMessageLevel",
	"TraceLevel",
	"TraceFileSize",
	"SystemDiskMountTimeout",
	NULL };

static char *lm_c_priv_unset[] = {
	"LMMessageLevel",
	"Tracelevel",
	"TraceFileSize",
	"SystemDiskMountTimeout",
	NULL };

static char *lm_c_priv_get[] = {
	NULL };

/*
 * lm_common_ready
 *
 * Parameters:
 *	level	The level that the LMPL command is to issue to MM
 *	tid	The task id of the LMPM command that is responsible for
 *		the ready command to be issued.
 *	ret_msg	If an error is detected while processing the ready command
 *		the error response is create here.
 *
 * This function sends the different forms of the LMPL ready command to MM
 * based on the level sent to it.
 *
 * Return Values:
 *    LM_OK	If LM was able to successfully complete the ready command.
 *
 *    LM_ERROR	If LM encountered an error while processing the ready
 *		command. This could mean either an internal processing error
 *		or just a command processing error. In either case an
 *		final error response is created in ret_msg with the error.
 *		This message would be used in the case where the ready is
 *		part of a LMPM command sequence. Currently only the LMPM
 *		activate command calls this function.
 *		NOTE: May not return a ret_msg here when more levels are
 *		called from other parts of the code. The caller would be
 *		responsible to generate a error message if required for a
 *		final response to a LMPM command.
 *
 */
int
lm_common_ready(int level, char *tid, char *ret_msg)
{

	int		rc;
	int		lmpl_tid;

	char		cmd_str[512];
	const char	*cfg_str;
	char		msg_str[256];

	lmpl_rsp_ele_t	*ele;

	mms_trace(MMS_DEVP, "Entering lm_common_ready, set level to %d", level);

	switch (level) {
		case LM_READY:
			cfg_str = LM_READY_R;
			break;
		case LM_NOT:
			cfg_str = LM_READY_N;
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7013_MSG, "state", "Not Ready", NULL);
			break;
		case LM_DISCONN:
			cfg_str = LM_READY_D;
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7013_MSG, "state", "Disconnected", NULL);
			break;
		case LM_BROKE:
			cfg_str = LM_READY_B;
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7013_MSG, "state", "Broke", NULL);
			break;
		case LM_PRESENT:
			cfg_str = LM_READY_P;
			break;
		default:
			mms_trace(MMS_ERR, "lm_c_ready: Invalid level sent "
			    "- %d", level);
			return (LM_ERROR);
	}

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_ERR, "lm_c_ready: lm_obtain_task_id was unable "
		    "to get a taskid for LMPL ready command");
		return (LM_ERROR);
	}

	if (level == LM_PRESENT || level == LM_READY) {
		(void) snprintf(cmd_str, sizeof (cmd_str),
		    cfg_str, lmpl_tid);
	} else {
		(void) snprintf(cmd_str, sizeof (cmd_str),
		    cfg_str, lmpl_tid, msg_str);
	}

	mms_trace(MMS_DEVP, "lm_c_ready: Send ready command:\n%s", cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_CRIT, "lm_c_ready: Internal processing error "
		    "encountered while processing LMPL ready command:\n%s",
		    cmd_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR, "lm_c_ready: Non success response "
		    "received from MM for LMPL ready command:\n%s, cmd_str");
		handle_lmpl_cmd_error(rc, "activate", "ready", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_OPER,
	    "lm_c_ready: LMPL ready command was successfull:\n%s",
	    cmd_str);

	lm_remove_lmpl_cmd(lmpl_tid, ele);
	mms_trace(MMS_DEVP, "Exiting lm_common_ready");
	return (LM_OK);
}

/*
 * lm_common_activate
 *
 * Parameters:
 *	cmd	Pointer to the parse tree of the activate command.
 *	tid	The task id of the activate command.
 *	ret_msg	The final response message that is to be sent back to MM.
 *		This could be either a success or error final response.
 *
 * This function executes the necessary steps that are common between
 * all libraries when the LM receives an activate command. This routine
 * is responsible for dynamically loading and unloading the library specific
 * command modules when the LM is activated and deactivated.
 *
 * Return Values:
 *    LM_OK	If LM was able to successfully complete the activate command.
 *		A final success response is created in ret_msg that will be
 *		sent to MM.
 *    LM_ERROR	If LM encountered an error while processing the activate
 *		command. This could mean either an internal processing error
 *		or just a command processing error. In either case an
 *		final error response is created in ret_msg with the
 *		error information that will be sent to MM.
 *
 */
int
lm_common_activate(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int		rc;
	int		lmpl_tid;
	int		connection = LM_GENERIC;

	char		cmd_str[512];
	char		msg_str[1024];

	mms_par_node_t	*cmd_spec;
	mms_par_node_t	*attribute;
	mms_par_node_t	*clause;
	mms_par_node_t	*loc = NULL;
	lmpl_rsp_ele_t	*ele;
	lmpl_rsp_node_t	*node;

	mms_trace(MMS_DEVP, "Entering lm_common_activate()");

		/* Create default final error response for MM */
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "activate", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	if ((cmd_spec = mms_pn_lookup(cmd, "enable", MMS_PN_KEYWORD, NULL))
	    != NULL) {
		mms_trace(MMS_DEBUG,
		    "lm_c_activate: Processing activate enable");

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_ERR, "lm_c_activate: lm_obtain_task_id "
			    "was unable to get a taskid for LMPL private "
			    "command to obtain library type and connection "
			    "information");
			return (LM_ERROR);
		}

		(void) snprintf(cmd_str, sizeof (cmd_str),
		    PRIVATE_CMD, lmpl_tid, PRI_GET_LIB);

		mms_trace(MMS_DEVP, "lm_c_activate: Obtain library info:\n%s",
		    cmd_str);

		if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_CRIT,
			    "lm_c_activate: Internal processing "
			    "error encountered while processing private "
			    "command to obtain library type:\n%s", cmd_str);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_ERR,
			    "lm_c_activate: Non success response "
			    "received from MM for LMPL private command to "
			    "obtain library and connection type:\n%s", cmd_str);
			handle_lmpl_cmd_error(rc, "activate", "private",
			    tid, ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		node = mms_list_head(&ele->lmpl_rsp_list);
		cmd_spec = node->lmpl_rsp_tree;
		mms_trace(MMS_DEVP, "lm_c_activate: Private command to obtain "
		    "LibraryType and LibraryConnection received a success "
		    "response");

		if ((clause = mms_pn_lookup(cmd_spec, "text",
		    MMS_PN_CLAUSE, NULL)) == NULL) {
			mms_trace(MMS_ERR,
			    "lm_c_activate: No text clause found "
			    "in final success response of private command to "
			    "obtain library type, response:\n%s",
			    mms_pn_build_cmd_text(cmd_spec));
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		if ((attribute = mms_pn_lookup(clause, "LibraryName",
		    MMS_PN_STRING, &loc)) == NULL) {
			mms_trace(MMS_ERR, "lm_c_activate: No LibraryName "
			    "attribute found in final success response of "
			    "private command to obtain library name, "
			    "response:\n%s", mms_pn_build_cmd_text(cmd_spec));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7018_MSG, "object", "LibraryName", NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED),
			    msg_str);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}
		if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc)) == NULL) {
			mms_trace(MMS_ERR, "lm_c_activate: No value associated "
			    "with LibraryName attribute found in final success "
			    "response of private command to obtain library "
			    "name, response:\n%s",
			    mms_pn_build_cmd_text(cmd_spec));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7018_MSG, "object", "LibraryName", NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED),
			    msg_str);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_c_activate: Library Name - %s",
		    mms_pn_token(attribute));

		lm.lm_name = strdup(mms_pn_token(attribute));

		loc = NULL;
		if ((attribute = mms_pn_lookup(clause, "LibraryType",
		    MMS_PN_STRING, &loc)) == NULL) {
			mms_trace(MMS_ERR, "lm_c_activate: No LibraryType "
			    "attribute found in final success response of "
			    "private command to obtain library type, "
			    "response:\n%s", mms_pn_build_cmd_text(cmd_spec));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7018_MSG, "object", "LibraryType", NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED),
			    msg_str);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}
		if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc)) == NULL) {
			mms_trace(MMS_ERR, "lm_c_activate: No value associated "
			    "with LibraryType attribute found in final success "
			    "response of private command to obtain library "
			    "type, response:\n%s",
			    mms_pn_build_cmd_text(cmd_spec));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7018_MSG, "object", "LibraryType", NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED),
			    msg_str);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_c_activate: Library Type - %s",
		    mms_pn_token(attribute));

		lm.lm_type = strdup(mms_pn_token(attribute));

		loc = NULL;
		if ((attribute = mms_pn_lookup(clause, "LibraryConnection",
		    MMS_PN_STRING, &loc)) == NULL) {
			mms_trace(MMS_ERR,
			    "lm_c_activate: No LibraryConnection "
			    "attribute found in finial success response of "
			    "private command to obtain library connection "
			    "type, response:\n%s",
			    mms_pn_build_cmd_text(cmd_spec));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7018_MSG, "object", "LibraryConnection", NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED),
			    msg_str);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc)) == NULL) {
			mms_trace(MMS_ERR, "lm_c_activate: No value associated "
			    "with LibraryConnection  attribute found in final "
			    "success response of private command to obtain "
			    "library connection type, response:\n%s",
			    mms_pn_build_cmd_text(cmd_spec));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7018_MSG, "object", "LibraryConnection", NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED),
			    msg_str);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_c_activate: Library Connection - %s",
		    mms_pn_token(attribute));

		if (strcmp("network", mms_pn_token(attribute)) == 0) {
			connection = LM_NETWORK_ATTACHED;
		} else if (strcmp("direct", mms_pn_token(attribute)) == 0) {
			connection = LM_DIRECT_ATTACHED;
		}
		lm.lm_conn = strdup(mms_pn_token(attribute));

			/* Private command to obtain library type completed */
			/* Free up element components and response array */
		lm_remove_lmpl_cmd(lmpl_tid, ele);

		mms_trace(MMS_DEBUG,
		    "lm_c_activate: Load correct command handling "
		    "routines for library type %s, %s", lm.lm_type, lm.lm_conn);

		/* Import in the correct cmd handling routines */
		if ((lm.lm_cmdHandle = lm_load_cmds(lm.lm_type, connection,
		    lm_cmdData)) == NULL) {
			mms_trace(MMS_ERR, "lm_c_activate: unable to load "
			    "command handling routines for library type - "
			    "%s, %s", lm.lm_type, lm.lm_conn);
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7020_MSG, "type", lm.lm_type,
			    "conn", lm.lm_conn, NULL);
			lm_message("operator", "alert", msg_str);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_STATE),
			    mms_sym_code_to_str(MMS_LM_E_CONFIG), msg_str);
			return (LM_ERROR);
		}
				/* Call library specific activate to finish */
				/* the activation of the library */
		if ((rc = (*lm_cmdData[LM_ACTIVATE].cd_cmdptr)(cmd, tid,
		    ret_msg)) != LM_OK) {
			mms_trace(MMS_ERR, "lm_c_activate: library specific "
			    "activate command failed, unable to activate LM");
			lm_unload_cmds(lm.lm_cmdHandle);
			return (LM_ERROR);
		}

/*
 *		LM does not need to register for any events at this time
 *		This code is being left in in case it is required in the
 *		future
 *
 *		if ((rc = lm_register_events(tid, ret_msg)) != LM_OK) {
 *		  mms_trace(MMS_DEBUG, "c_activate: Failure while issueing "
 *			    "event register command to MM. Unable to "
 *			    "activate LM - %s", lm.lm_net_cfg.cli_inst);
 *			return (LM_ERROR);
 *		}
 *
 *		LM is not going to send the LMPL ready command on the
 *		activate. MM will set LM state to ready when it receives
 *		the final success response to the activate command
 *
 *		if ((rc = lm_common_ready(LM_READY, tid, ret_msg)) != LM_OK) {
 *		   mms_trace(MMS_DEBUG, "lm_c_activate: Failure while issueing "
 *			   "ready command to MM. Unable to enable LM");
 *			lm_unload_cmds(lm.lm_cmdHandle);
 *			return (LM_ERROR);
 *		}
 */
		lm_state = LM_ACTIVE;

		mms_trace(MMS_DEBUG, "lm_c_activate: LM is active");

		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7014_MSG, NULL);
		(void) snprintf(ret_msg, RMBUFSIZE,
		    LM_SUC_FINAL, tid, msg_str, "");

	} else if ((cmd_spec = mms_pn_lookup(cmd, "disable", MMS_PN_KEYWORD,
	    NULL)) != NULL) {
		mms_trace(MMS_DEBUG,
		    "lm_c_activate: Processing activate disable");

		lm_state = LM_NOT_ACTIVE;

			/* Abort any abortable LMPM cmds on work queue */
		lm_queue_clean();

			/* Wait for all non abortable LMPM cmds to complete */
		while (lm_cmdq.lmq_first != NULL || lm_cmdq.lmq_counter != 1) {
			mms_trace(MMS_DEBUG, "lm_c_activate: Waiting for all "
			    "outstanding LMPM commands to complete "
			    "before disable is complete");
			(void) sleep(5);
		}

		mms_trace(MMS_DEBUG, "lm_c_activate: all LMPM commands have "
		    "completed, ready to disable LM");

		if ((rc = lm_common_ready(LM_PRESENT, tid, ret_msg)) != LM_OK) {
			mms_trace(MMS_ERR,
			    "lm_c_activate: Failure while issueing "
			    "ready command to MM. Unable to disable LM");
				/* Reset state to ACTIVE */
			lm_state = LM_ACTIVE;
			return (LM_ERROR);
		}

		free(lm.lm_name);
		free(lm.lm_type);
		free(lm.lm_conn);
		lm_unload_cmds(lm.lm_cmdHandle);

		mms_trace(MMS_DEBUG, "lm_c_activate: LM is inactive");

		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7015_MSG, NULL);
		(void) snprintf(ret_msg, RMBUFSIZE,
		    LM_SUC_FINAL, tid, msg_str, "");

	} else {
		mms_trace(MMS_ERR, "lm_c_activate: Invalid activate command");
		return (LM_ERROR);
	}
	mms_trace(MMS_DEVP, "Exiting lm_common_activate with LM_OK");
	return (LM_OK);
}

/*
 * lm_c_validate_private()
 *
 * Parameters:
 *	- cmd		LMPM private command being processed.
 *	- tid		Task id of private command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the private command because of
 *			a failure, the response is copied here.
 *
 * Globals:
 *	- lm_c_priv_set   The set-name values allowed in a LMPM private cmd.
 *	- lm_c_priv_get   The get-name values allowed in a LMPM private cmd.
 *	- lm_c_priv_unset The unset-name values allowed in a LMPM private cmd.
 *
 * This function validates that all the set-name, get-name, and unset-name
 * are valid. If the private command contains a name that is not known by
 * LM, a error final response is sent in response the the LMPM private cmd.
 * This function does not validate that the set-value is valid, while the
 * set-name is being processed, the value needs to be validated. This function
 * is only invoked if the LM has not yet activated. In the case of an
 * activated LM where a library specific private command is available, the
 * validation needs to be done by the library specific private command.
 *
 * Return Values:
 *	- LM_OK		If all names are valid LM_OK is returned.
 *	- LM_ERROR	If a name is encountered that is not know, LM_ERROR
 *			is returned and ret_msg is updated to reflect the
 *			error final response for the LMPM private cmd.
 */
static int
lm_c_validate_private(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int		i;

	char		*kw;
	char		msg_str[256];

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*loc1;
	mms_par_node_t	*clause;
	mms_par_node_t	*name;
	mms_par_node_t	*value;

	for (clause = mms_pn_lookup(cmd, kw = "get", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "get",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG,
		    "lm_c_v_private:, Validating a get clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			for (i = 0; lm_c_priv_get[i] != NULL; i++) {
				if (strcmp(mms_pn_token(name),
				    lm_c_priv_get[i]) == 0) {
					mms_trace(MMS_DEBUG, "lm_c_v_private: "
					    "private get contains %s get-name",
					    mms_pn_token(name));
					break;
				}
			}

			if (lm_c_priv_get[i] == NULL) {
				mms_trace(MMS_ERR, "lm_c_v_private: private "
				    "command contains a unsupport get-name - "
				    "%s", mms_pn_token(name));
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7010_MSG, "type", "get",
				    "name", mms_pn_token(name), NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_EXIST),
				    mms_sym_code_to_str(MMS_LM_E_NOELT),
				    msg_str);
				return (LM_ERROR);
			}

		}
	}

	loc = NULL;
	for (clause = mms_pn_lookup(cmd, kw = "set", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "set",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG,
		    "lm_c_v_private:, Validating a set clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			for (i = 0; lm_c_priv_set[i] != NULL; i++) {
				if (strcmp(mms_pn_token(name),
				    lm_c_priv_set[i]) == 0) {
					mms_trace(MMS_DEBUG, "lm_c_v_private: "
					    "private set contains %s set-name",
					    mms_pn_token(name));
					break;
				}
			}

			if (lm_c_priv_set[i] == NULL) {
				mms_trace(MMS_ERR, "lm_c_v_private: private "
				    "command contains a unsupport set-name - "
				    "%s", mms_pn_token(name));
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7010_MSG, "type", "set",
				    "name", mms_pn_token(name), NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_EXIST),
				    mms_sym_code_to_str(MMS_LM_E_NOELT),
				    msg_str);
				return (LM_ERROR);
			}

				/* For set clauses, the values asssociated */
				/* with the set-name are validated when */
				/* the set is acutally being processed, */
				/* here just skip them to get next set-name */
			MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING,
			    &loc1);
		}
	}

	loc = NULL;
	for (clause = mms_pn_lookup(cmd, kw = "unset", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "unset",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG,
		    "lm_c_v_private:, Validating a unset clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			for (i = 0; lm_c_priv_unset[i] != NULL; i++) {
				if (strcmp(mms_pn_token(name),
				    lm_c_priv_unset[i]) == 0) {
					mms_trace(MMS_DEBUG, "lm_c_v_private: "
					    "private unset contains %s "
					    "unset-name", mms_pn_token(name));
					break;
				}
			}

			if (lm_c_priv_unset[i] == NULL) {
				mms_trace(MMS_ERR, "lm_c_v_private: private "
				    "command contains a unsupport unset-name - "
				    "%s", mms_pn_token(name));
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7010_MSG, "type", "unset",
				    "name", mms_pn_token(name), NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_EXIST),
				    mms_sym_code_to_str(MMS_LM_E_NOELT),
				    msg_str);
				return (LM_ERROR);
			}

		}
	}

	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "lm_c_v_private: LMPM private command has a "
	    "missing value for a %s set-name", mms_pn_token(name));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "private", "part", kw, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}

/*
 * lm_common_private
 *
 * Parameters:
 *	cmd	Pointer to the parse tree of the private command.
 *	tid	The task id of the private command.
 *	ret_msg	The final response message that is to be sent back to MM.
 *		This could be either a success or error final response.
 *
 * This function executes the necessary steps that are common between
 * all libraries when the LM receives an private command. This routine
 * is responsible for parsing through the parse tree to determine what
 * attributes are to be updated based on the private command. This
 * routine only handles what is common to all types of LMs. Once it has
 * gone through the parse tree, it call the library specific private command
 * handler.
 *
 * Return Values:
 *    LM_OK	If LM was able to successfully complete the private command.
 *		A final success response is created in ret_msg that will be
 *		sent to MM.
 *    LM_ERROR	If LM encountered an error while processing the private
 *		command. This could mean either an internal processing error
 *		or just a command processing error. In either case a
 *		final error response is created in ret_msg with the
 *		error information that will be sent to MM.
 */
int
lm_common_private(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char		*kw;
	char		msg_str[256];
	char		get_str[256];	/* This may need to be changed */
					/* to accommodate larger get */
					/* return text clauses, currently */
					/* LM does not have any get-name */
					/* that it supports */

	mms_msg_sev_t	m_level;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*loc1;
	mms_par_node_t	*clause;
	mms_par_node_t	*name;
	mms_par_node_t	*value;

	mms_trace(MMS_DEVP, "Entering lm_common_private");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "private", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

		/* Call library specific private to handle parts that */
		/* are specific for library only */
	if (lm_cmdData[LM_PRIVATE].cd_cmdptr != NULL) {
		if ((*lm_cmdData[LM_PRIVATE].cd_cmdptr)(cmd, tid,
		    ret_msg) != LM_OK) {
			mms_trace(MMS_DEBUG, "lm_c_private: library specific "
			    "private command failed, unable to complete "
			    "private command");
			return (LM_ERROR);
		}

		/* If the library specific private command processes */
		/* cleanly any get library specific operations will */
		/* return their text clauses in the ret_msg, copy them */
		/* to the get_str to retain their values and add any */
		/* common library get operations to them */
		(void) strcpy(get_str, ret_msg);
	} else {
		if (lm_c_validate_private(cmd, tid, ret_msg) == LM_ERROR) {
			mms_trace(MMS_DEBUG,
			    "lm_c_private: lm_c_validate_private() "
			    "failed");
			return (LM_ERROR);
		}

		(void) strcpy(get_str, "");
	}

	for (clause = mms_pn_lookup(cmd, kw = "get", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "get",
	    MMS_PN_CLAUSE, &loc)) {

			/* Currently LM does not support any common get */
			/* operations, just a place holder for when it */
			/* does */
		mms_trace(MMS_DEBUG, "lm_c_private: Skipping get clause");

	}

	loc = NULL;
	for (clause = mms_pn_lookup(cmd, kw = "set", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "set",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG, "lm_c_private: Handle set clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING,
			    &loc1);
			if (strcmp(mms_pn_token(name), "TraceLevel") == 0) {
				if (mms_trace_str_filter(mms_pn_token(value))) {
					mms_trace(MMS_DEBUG, "lm_c_private: "
					    "mms_trace_str_filter failed");
					(void) mms_buf_msgcl(msg_str,
					    sizeof (msg_str),
					    LM_7011_MSG,
					    "name", mms_pn_token(name),
					    "value", mms_pn_token(value),
					    NULL);
					(void) snprintf(ret_msg, RMBUFSIZE,
					    LM_ERR_FINAL,
					    tid,
					    mms_sym_code_to_str(
					    MMS_INTERNAL),
					    mms_sym_code_to_str(
					    MMS_LM_E_BADVAL),
					    msg_str);
					return (LM_ERROR);
				}
				mms_trace(MMS_OPER,
				    "lm_c_private: changing mms_trace "
				    "level to %s", mms_pn_token(value));
			}
			if (strcmp(mms_pn_token(name), "TraceFileSize")
			    == 0) {
				if (mms_trace_set_fsize(mms_pn_token(value))) {
					mms_trace(MMS_DEBUG, "lm_c_private: "
					    "mms_trace_set_fsize failed");
					(void) mms_buf_msgcl(msg_str,
					    sizeof (msg_str),
					    LM_7011_MSG,
					    "name", mms_pn_token(name),
					    "value", mms_pn_token(value),
					    NULL);
					(void) snprintf(ret_msg, RMBUFSIZE,
					    LM_ERR_FINAL,
					    tid,
					    mms_sym_code_to_str(
					    MMS_INTERNAL),
					    mms_sym_code_to_str(
					    MMS_LM_E_BADVAL),
					    msg_str);
					return (LM_ERROR);
				}
				mms_trace(MMS_OPER,
				    "lm_c_private: changing mms_trace "
				    "file rotation size to %s",
				    mms_pn_token(value));
			}
			if (strcmp(mms_pn_token(name), "LMMessageLevel")
			    == 0) {
				m_level =
				    mms_msg_get_severity(mms_pn_token(value));
				if (m_level < MMS_MSG_SEV_EMERG || m_level >
				    MMS_MSG_SEV_DEVP) {
					mms_trace(MMS_ERR, "lm_c_private "
					    "invalid message level - %s",
					    mms_pn_token(value));
					(void) mms_buf_msgcl(msg_str,
					    sizeof (msg_str),
					    LM_7011_MSG,
					    "name", mms_pn_token(name),
					    "value", mms_pn_token(value),
					    NULL);
					(void) snprintf(ret_msg, RMBUFSIZE,
					    LM_ERR_FINAL,
					    tid,
					    mms_sym_code_to_str(
					    MMS_INTERNAL),
					    mms_sym_code_to_str(
					    MMS_LM_E_BADVAL),
					    msg_str);
					return (LM_ERROR);
				}
				lm_message_level = m_level;
				mms_trace(MMS_OPER, "lm_c_private: changing "
				    "message level to %s",
				    mms_pn_token(value));
			}
			if (strcmp(mms_pn_token(name),
			    "SystemDiskMountTimeout") == 0) {
				lm.lm_disk_timeout =
				    atoi(mms_pn_token(value));
				mms_trace(MMS_OPER, "lm_c_private: changing "
				    "disk stat timeout to %s",
				    mms_pn_token(value));
			}
		}
	}

	loc = NULL;
	for (clause = mms_pn_lookup(cmd, kw = "unset", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "unset",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG, "lm_c_private: Handle unset clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			if (strcmp(mms_pn_token(name), "TraceLevel") == 0) {
				mms_trace(MMS_OPER,
				    "lm_c_private: changing mms_trace "
				    "level to default of error");
				(void) mms_trace_filter(MMS_SEV_ERROR);
			}
			if (strcmp(mms_pn_token(name), "TraceFileSize")
			    == 0) {
				mms_trace(MMS_OPER,
				    "lm_c_private: changing mms_trace "
				    "file rotation size to 10M");
				(void) mms_trace_set_fsize("10M");
			}

			if (strcmp(mms_pn_token(name), "LMMessageLevel")
			    == 0) {
				mms_trace(MMS_OPER, "lm_c_private: changing "
				    "message level to warning");
				lm_message_level = MMS_MSG_SEV_WARN;
			}
			if (strcmp(mms_pn_token(name),
			    "SystemDiskMountTimeout") == 0) {
				lm.lm_disk_timeout = LM_DISK_TIMEOUT;
				mms_trace(MMS_OPER, "lm_c_private: changing "
				    "disk stat timeout to %d",
				    LM_DISK_TIMEOUT);
			}
		}
	}

	mms_trace(MMS_DEBUG,
	    "lm_c_private: completed private command successfully");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7101_MSG, "cmd", "private", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE,
	    LM_SUC_FINAL, tid, get_str, msg_str);
	mms_trace(MMS_DEVP, "Exiting lm_common_private");
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "lm_c_private: LMPM private command has a "
	    "missing value for a %s set-name", mms_pn_token(name));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "private", "part", kw, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}

/*
 * lm_common_event
 *
 * Parameters:
 *	cmd	Pointer to the parse tree of the event command.
 *	tid	The task id of the event command.
 *	ret_msg	Just a place holder, events do not get a response. The
 *		lm_cmd_handler() routine that calls this routine will
 *		skip the sending of the response.
 *
 * This function executes the necessary steps that are common between
 * all libraries when the LM receives an event. The routine will first
 * call the library specific lm_event() routine.
 *
 * Currently there are no events that LM registers for, so LM should
 * never receive an event. If one is received, it is just ignored at this
 * time. In the future if LM can receive events, this code will need to
 * be updated to handle those events.
 *
 * Return Values:
 *    LM_OK	If LM was able to successfully complete the event.
 *    LM_ERROR	If LM encountered an error while processing the event
 *		This could mean either an internal processing error
 *		or just a command processing error.
 */
int
lm_common_event(mms_par_node_t *cmd, char *tid, char *ret_msg)
{

	mms_trace(MMS_DEVP, "Entering lm_common_event");

	mms_trace(MMS_OPER,
	    "Processing event:\n%s", mms_pn_build_cmd_text(cmd));

	if (lm_cmdData[LM_EVENT].cd_cmdptr == NULL) {
		mms_trace(MMS_DEBUG,
		    "lm_c_event: no library specific lm_event() "
		    "defined");
	} else if ((*lm_cmdData[LM_EVENT].cd_cmdptr)(cmd, tid, ret_msg)
	    != LM_OK) {
		mms_trace(MMS_ERR, "lm_c_event: Library specific event command "
		    "failed");
		return (LM_ERROR);
	}

	mms_trace(MMS_DEVP, "Exiting lm_common_event");
	return (LM_OK);
}

/*
 * lm_common_internal
 *
 * Parameters:
 *	cmd	Pointer to the parse tree of the internal command.
 *	tid	The task id of the internal command.
 *	ret_msg	Just a place holder, internal commands do not get a
 *		response. The lm_cmd_handler() routine that calls this
 *		routine will skip the sending of the response.
 *
 * This function is used by the LM to be able to process another command
 * on behalf of a different LMPM command.
 *
 * Currently, when lm_gen_lmpl_cmd() sends a LMPL command as part of
 * processing a LMPM command, the routine processing the LMPM command
 * can specifiy a timeout for how long it will wait for a response to
 * the LMPL command. If the timeout is hit, the LM will need to send a
 * cancel command for the LMPL command. This is done by adding an
 * internal cancel command to the work queue, which will cause this
 * routine to be invoked by the lm_cmd_handler().
 *
 * Note: No commands currently send a LMPL command with a timeout, thus
 * nothing within LM currently will generate the internal command.
 *
 * Return Values:
 *    LM_OK	If LM was able to successfully complete the internal command.
 *    LM_ERROR	If LM encountered an error while processing the internal
 *		command. This could mean either an internal processing error
 *		or just a command processing error.
 */
int
lm_common_internal(mms_par_node_t *cmd, char *tid, char *ret_msg)
{

	int	rc;
	int	lmpl_tid;

	char	cmd_str[256];

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*icmd;
	mms_par_node_t	*taskid;
	lmpl_rsp_ele_t	*ele;

	mms_trace(MMS_DEVP, "Entering lm_common_internal");

	if ((icmd = mms_pn_lookup(cmd, NULL, MMS_PN_STRING, &loc))
	    == NULL) {
		mms_trace(MMS_ERR, "lm_c_internal: No internal command found "
		    "in command:\n%s", mms_pn_build_cmd_text(cmd));
		return (LM_ERROR);
	}

	if (strcmp("cancel", mms_pn_token(icmd)) == 0) {
		mms_trace(MMS_DEBUG, "lm_c_internal: Processing an internal "
		    "cancel command");

		if ((taskid = mms_pn_lookup(cmd, NULL, MMS_PN_STRING, &loc))
		    == NULL) {
			mms_trace(MMS_ERR, "lm_c_internal: No taskid found in "
			    "the internal cancel command:\n%s",
			    mms_pn_build_cmd_text(cmd));
			return (LM_ERROR);
		}

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_ERR, "lm_obtain_task_id failed trying to "
			    "generate cancel command for LMPL command "
			    "with taskid - %s", mms_pn_token(taskid));
			return (LM_ERROR);
		}

		(void) snprintf(cmd_str, sizeof (cmd_str),
		    LM_CANCEL_CMD, lmpl_tid,
		    mms_pn_token(taskid));

		mms_trace(MMS_DEBUG, "lm_c_internal: Cancel cmd:\n%s", cmd_str);

		if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_CRIT, "lm_common_internal: Internal "
			    "processing error encountered while processing "
			    "internal cancel command to cancel LMPL "
			    "command with taskid - %s", mms_pn_token(taskid));
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		} else if (rc == LMPL_FINAL_ERROR) {
			mms_trace(MMS_ERR,
			    "lm_common_internal: Internal cancel "
			    "command received error response, unable to "
			    "cancel LMPL commmand with task id - %s",
			    mms_pn_token(taskid));
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_CRIT,
			    "lm_common_internal: Internal cancel "
			    "command received a non success response, unable "
			    "to cancel LMPL command with taskid - %s",
			    mms_pn_token(taskid));
			handle_lmpl_cmd_error(rc, "internal", "cancel", tid,
			    ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		} else {
			mms_trace(MMS_DEBUG,
			    "lm_common_internal: Internal cancel "
			    "command received a success final response");
		}
		lm_remove_lmpl_cmd(lmpl_tid, ele);

	} else {
		mms_trace(MMS_ERR,
		    "lm_c_internal: Unsupported internal command "
		    "received:\n", mms_pn_build_cmd_text(cmd));
		return (LM_ERROR);
	}

	return (LM_OK);
}

/*
 * lm_message
 *
 * Parameters:
 *	who		Specifies the who in the LMPL message
 *	severity	Specifies the severity of the LMPL message
 *	msg		The message to be sent out
 *
 * This function is used to send a message of some severity level to
 * the destination defined by the argument "who".
 *
 * Return Values:
 *    None	Since this is just a message going out, if it fails to
 *		be sent, it should not affect the running of the LM.
 *
 *		Currently the messages are being sent out only to tell
 *		the operator of some other type of error that has
 *		occurred on a LMPM command; therefore, the error will be
 *		returned to the client in the error response.
 */
void
lm_message(char *who, char *severity, char *msg)
{
	int	rc;
	int	lmpl_tid;

	char	cmd_str[1024];

	lmpl_rsp_ele_t	*ele;

	mms_trace(MMS_DEVP, "Entering lm_message");

	if (mms_msg_get_severity(severity) > lm_message_level) {
		mms_trace(MMS_INFO, "lm_message: Unable to send message, the "
		    "severity of the message is less than what is currently "
		    "allowed. message ignored:\n%s", msg);
		return;
	}

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_ERR, "lm_message: lm_obtain_task_id was unable "
		    "to get a taskid for LMPL message command");
		return;
	}

	(void) snprintf(cmd_str, sizeof (cmd_str),
	    LM_MSG_CMD, lmpl_tid, who, severity, msg);

	mms_trace(MMS_DEVP, "lm_message: message command:\n%s", cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_CRIT, "lm_message: Internal processing error "
		    "encountered while processing LMPL message command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return;
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR, "lm_message: Non success response "
		    "received from MM for LMPL message command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return;
	}

	lm_remove_lmpl_cmd(lmpl_tid, ele);
	mms_trace(MMS_DEVP, "Message sent successfully, exiting lm_message");
}

/*
 * lm_common_exit
 *
 * Parameters:
 *	cmd	Pointer to the parse tree of the exit command.
 *	tid	The task id of the exit command.
 *	ret_msg	The final response message that is to be sent back to MM.
 *		This could be either a success or error final response.
 *
 * This function executes the necessary steps that are common between
 * all libraries when the LM receives a exit command. This routine
 * is responsible for shutting down the LM gracefully and then exiting.
 * Even if something does not shutdown cleanly, the LM will still exit.
 *
 * Return Values:
 *    LM_OK	If LM was able to successfully complete the exit command.
 *		A final success response is created in ret_msg that will be
 *		sent to MM.
 *    LM_ERROR	If LM encountered an error while processing the exit
 *		command. This could mean either an internal processing error
 *		or just a command processing error. In either case a
 *		final error response is created in ret_msg with the
 *		error information that will be sent to MM.
 */
int
lm_common_exit(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	rc;

	char	msg_str[1024];

	mms_trace(MMS_DEVP, "Entering CommonExit");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "exit", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE,
	    LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

		/* Set state of lm to stop to abort any new commands */
	lm_state = LM_STOP;
		/* Set LM state in MM to not ready */
	if ((rc = lm_common_ready(LM_NOT, tid, ret_msg)) != LM_OK) {
		mms_trace(MMS_ERR, "lm_c_exit: Failure of ready command to MM. "
		    "Unable to set LM's state to not ready");
	}

		/* Abort any abortable LMPM cmds on work queue */
	lm_queue_clean();

		/* Wait for all non abortable LMPM cmds to complete */
	while (lm_cmdq.lmq_first != NULL || lm_cmdq.lmq_counter != 1) {
		mms_trace(MMS_DEBUG,
		    "lm_c_exit: Waiting for all outstanding LMPM "
		    "commands to complete before exit is complete");
		(void) sleep(5);
	}
		/* Call library specific lm_exit() to handle any parts */
		/* are specific for the library only */
	if (lm_cmdData[LM_EXIT].cd_cmdptr != NULL) {
		if ((*lm_cmdData[LM_EXIT].cd_cmdptr)(cmd, tid,
		    ret_msg) != LM_OK) {
			mms_trace(MMS_ERR, "lm_c_exit: library specific "
			    "exit command failed to do pre exit cleanly");
		} else {
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7016_MSG, NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_SUC_FINAL, tid, msg_str, "");
		}
	} else {
		if (rc == LM_OK) {
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7016_MSG, NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_SUC_FINAL, tid, msg_str, "");
		}
	}

	mms_trace(MMS_DEVP, "lm_c_exit: exit command's final response:\n%s",
	    ret_msg);
	mms_trace(MMS_OPER, "lm_c_exit: All outstanding LMPM commands have "
	    "completed, ready to exit LM");

	exit_code = LM_NON_RESTART;

	return (LM_OK);
}

/*
 * lm_common_reset
 *
 * Parameters:
 *	cmd	Pointer to the parse tree of the reset command.
 *	tid	The task id of the reset command.
 *	ret_msg	The final response message that is to be sent back to MM.
 *		This could be either a success or error final response.
 *
 * This function executes the necessary steps that are common between
 * all libraries when the LM receives a reset command. This routine
 * is responsible for shutting down the LM gracefully and then restarting.
 *
 * Return Values:
 *    LM_OK	If LM was able to successfully complete the reset command.
 *		A final success response is created in ret_msg that will be
 *		sent to MM.
 *    LM_ERROR	If LM encountered an error while processing the reset
 *		command. This could mean either an internal processing error
 *		or just a command processing error. In either case a
 *		final error response is created in ret_msg with the
 *		error information that will be sent to MM.
 */

int
lm_common_reset(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	rc;
	int	partial = LM_NO;

	char	msg_str[1024];
	char	lret_msg[2048];

	mms_trace(MMS_DEVP, "Entering CommonReset");

	lret_msg[0] = '\0';

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "reset", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE,
	    LM_ERR_FINAL,
	    tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL),
	    msg_str);

	if (mms_pn_lookup(cmd, "partial", MMS_PN_KEYWORD, NULL)
	    != NULL) {
		partial = LM_YES;

			/* Set LM state in MM to not ready */
		if ((rc = lm_common_ready(LM_NOT, tid, ret_msg)) != LM_OK) {
			mms_trace(MMS_ERR, "lm_c_reset: LMPL ready not failed, "
			    "unable to set LM's state to ready not prior to "
			    "reset");
			return (LM_ERROR);
		}
	} else {
			/* Set LM state in MM to not ready, ignore return */
			/* value since the LM will reset itself */
		if ((rc = lm_common_ready(LM_NOT, tid, lret_msg)) != LM_OK) {
			mms_trace(MMS_ERR, "lm_c_reset: LMPL ready not failed, "
			    "unable to set LM's state to ready not prior to "
			    "reset");
		}
			/* Set state of lm to stop to abort any new commands */
		lm_state = LM_STOP;

			/* Abort any abortable LMPM cmds on work queue */
		lm_queue_clean();

			/* Wait for all non abortable LMPM cmds to complete */
		while (lm_cmdq.lmq_first != NULL || lm_cmdq.lmq_counter != 1) {
			mms_trace(MMS_DEBUG, "lm_c_reset: Waiting for all "
			    "outstanding LMPM commands to complete before "
			    "reset is complete");
			(void) sleep(5);
		}
	}

		/* Call library specific lm_reset() to handle any parts */
		/* are specific for the library only */
	if (lm_cmdData[LM_RESET].cd_cmdptr != NULL) {
		if ((*lm_cmdData[LM_RESET].cd_cmdptr)(cmd, tid,
		    ret_msg) != LM_OK) {
				/* Use retmsg for resturn message */
			mms_trace(MMS_DEVP, "lm_c_reset: library specific "
			    "reset command failed to do reset cleanly");
			if (partial) {
				if (lm_common_ready(LM_READY, tid, lret_msg)
				    != LM_OK) {
					lm_serr(MMS_CRIT, "lm_c_reset: During "
					    "a partial reset, LMPL ready "
					    "command failed to set LM's state "
					    "back to ready");
				}
				return (LM_ERROR);
			} else {
				mms_trace(MMS_ERR,
				    "lm_c_reset: library specific "
				    "full reset failed");
			}
		} else {
			if (partial) {
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7022_MSG, NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_SUC_FINAL,
				    tid, msg_str, "");
			} else {
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7017_MSG, NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_SUC_FINAL,
				    tid, msg_str, "");
			}
		}
	} else {
		mms_trace(MMS_DEBUG, "No library specific reset function "
		    "exists");
		if (partial) {
			if (lm_common_ready(LM_READY, tid, ret_msg) != LM_OK) {
				lm_serr(MMS_CRIT,
				    "lm_c_reset: During a partial "
				    "reset, LMPL ready command failed to set "
				    "LM's state back to ready");
				return (LM_ERROR);
			}
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7022_MSG, NULL);
			(void) snprintf(ret_msg, RMBUFSIZE,
			    LM_SUC_FINAL, tid, msg_str, "");
			return (LM_OK);
		} else {
			if (rc == LM_OK) {
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7017_MSG, NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_SUC_FINAL,
				    tid, msg_str, "");
			}
		}
	}
	if (partial) {
		if (lm_common_ready(LM_READY, tid, ret_msg) != LM_OK) {
			lm_serr(MMS_CRIT, "lm_c_reset: During a partial "
			    "reset, LMPL ready command failed to set "
			    "LM's state back to ready");
			return (LM_ERROR);
		}
	} else {
		mms_trace(MMS_OPER,
		    "lm_c_reset: All outstanding LMPM commands have "
		    "completed, ready to reset LM");

		exit_code = LM_RESTART;
	}
	mms_trace(MMS_DEVP, "lm_c_reset: reset command's final response:\n%s",
	    ret_msg);

	return (LM_OK);
}
/*
 * lm_set_drive_disabled
 *
 * Parameters:
 *	- drive_name :	ptr to string of drive name
 *	- drive_state :	ptr to string of DriveDisabled state to set to
 *
 * Sends an attribute command to MM to set the DriveDisabled state to
 * the drive_state string for a drive who's name is drive_name
 *
 * Return Values:
 *	None
 *
 */
void
lm_set_drive_disabled(char *drive_name, char *drive_state)
{
	int	rc;
	int	lmpl_tid;

	char	*cmd_str = NULL;

	lmpl_rsp_ele_t	*ele;

	mms_trace(MMS_DEVP, "Entering lm_set_drive_disabled");

	if (drive_name == NULL) {
		mms_trace(MMS_ERR,
		    "lm_set_drive_disabled: "
		    "passed null drive_name");
		return;
	}
	if (drive_state == NULL) {
		mms_trace(MMS_ERR,
		    "lm_set_drive_disabled: "
		    "passed null drive_state");
		return;
	}
	mms_trace(MMS_DEBUG,
	    "lm_set_drive_disabled: "
	    "set DriveDisabled = %s for %s",
	    drive_state, drive_name);

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_ERR,
		    "lm_set_drive_disabled: "
		    "lm_obtain_task_id was unable "
		    "to get a taskid for LMPL attribute command");
		return;
	}

	cmd_str = mms_strapp(cmd_str,
	    LM_DRIVEDISABLED_CMD, lmpl_tid,
	    drive_name, drive_state);

	mms_trace(MMS_DEVP,
	    "lm_set_drive_disabled: "
	    "attribute command:\n%s", cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_CRIT,
		    "lm_set_drive_disabled: "
		    "Internal processing error "
		    "encountered while processing LMPL attribute command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(cmd_str);
		return;
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR,
		    "lm_set_drive_disabled: "
		    "Non success response "
		    "received from MM for LMPL attribute command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(cmd_str);
		return;
	}

	lm_remove_lmpl_cmd(lmpl_tid, ele);
	mms_trace(MMS_DEBUG,
	    "lm_set_drive_disabled: "
	    "Attribute sent successfully");
	free(cmd_str);

}
