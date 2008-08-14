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


#include "lm_disk.h"
#include <lm.h>

static	char	*_SrcFile = __FILE__;

/*
 * lm_activate()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM activate command being processed.
 *	- tid		Task id of LMPM activate command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the activate command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the activate command. This routine is responsible
 * for establishing that the LM can access each file system and cartridge
 * defined within that file system.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to become active. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot become active.
 */
int
/* LINTED argument unused in function */
lm_activate(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	rc;

	mms_trace(MMS_DEVP, "Entering Disk lm_activate");

	if ((rc = lm_library_config("activate", tid, ret_msg)) != LM_OK) {
		mms_trace(MMS_ERR,
		    "lm_activate: lm_library_config failed, rc %d", rc);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEVP, "Disk lm_activate succeeded");

	return (LM_OK);
}

/*
 * lm_mount()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM mount command being processed.
 *	- tid		Task id of LMPM mount command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the mount command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the mount command. This routine is responsible
 * for performing the mounting operations necessary to reflect a cartridge
 * mounted in a drive within a disk archiving library.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to mount a cartridge. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot mount a cartridge.
 */
int
lm_mount(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	rc;
	int	lmpl_tid;

	char	*kw;
	char	msg_str[256];
	char	text_str[256];
	char	cfg_str[1024];

	lmpl_rsp_ele_t	*ele;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*drive;
	mms_par_node_t	*slot;
	mms_par_node_t	*value;
	mms_par_node_t	*slot_name;
	mms_par_node_t	*cartridge;
	mms_par_node_t	*side;

	mms_trace(MMS_DEVP, "Entering lm_mount");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7004_MSG, "mount",
	    "mount");
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	MMS_PN_LOOKUP(drive, cmd, kw = "drive", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, NULL);

	mms_trace(MMS_DEBUG, "lm_mount: Drive for mount cmd - %s",
	    mms_pn_token(value));

	MMS_PN_LOOKUP(slot, cmd, kw = "slot", MMS_PN_CLAUSE, NULL);
	loc = NULL;
	MMS_PN_LOOKUP(slot_name, slot, NULL, MMS_PN_STRING, &loc);
	MMS_PN_LOOKUP(cartridge, slot, NULL, MMS_PN_STRING, &loc);
	MMS_PN_LOOKUP(side, slot, NULL, MMS_PN_STRING, &loc);

	mms_trace(MMS_DEBUG, "lm_mount: Mount cartridge %s, side %s, from "
	    "slot %s", mms_pn_token(slot_name), mms_pn_token(cartridge),
	    mms_pn_token(side));

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_mount: lm_obtain_task_id failed trying "
		    "to generate config command for mount");
		return (LM_ERROR);
	}

	(void) snprintf(cfg_str, sizeof (cfg_str), CONFIG_MOUNT, lmpl_tid,
	    mms_pn_token(cartridge), mms_pn_token(value),
	    mms_pn_token(cartridge));

	mms_trace(MMS_DEBUG, "lm_mount: config for mount:\n%s", cfg_str);

	if ((rc = lm_gen_lmpl_cmd(cfg_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_mount: Internal processing error "
		    "encountered while processing lmpl config command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR, "lm_mount: config command did not receive "
		    "a successful response");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_mount: Got successful response for mount "
	    "config command");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7102_MSG,
	    mms_pn_token(cartridge), mms_pn_token(value),
	    mms_pn_token(cartridge), mms_pn_token(value));
	(void) snprintf(text_str, sizeof (text_str), LM_TEXT_MNT,
	    mms_pn_token(value), mms_pn_token(slot_name),
	    mms_pn_token(cartridge), mms_pn_token(side));
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, text_str,
	    msg_str);

	lm_remove_lmpl_cmd(lmpl_tid, ele);

	mms_trace(MMS_DEVP, "Exiting lm_mount");
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "LMPM command %s encounterd an invalid or missing "
	    "%s clause:\n%s", "mount", kw, mms_pn_build_cmd_text(cmd));
	(void) snprintf(msg_str, sizeof (msg_str), LM_7009_MSG, "mount", kw,
	    "mount", kw);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);

	mms_trace(MMS_DEVP, "Exiting lm_mount");
	return (LM_ERROR);
}

/*
 * lm_unmount()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM unmount command being processed.
 *	- tid		Task id of LMPM unmount command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the unmount command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the unmount command. This routine is responsible
 * for performing the unmount operations necessary to reflect a cartridge
 * unmounted from a drive within a disk archiving library.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to unmount a cartridge. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot unmount a cartridge.
 */
int
lm_unmount(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	rc;
	int	lmpl_tid;

	char	*kw;
	char	msg_str[256];
	char	text_str[256];
	char	cfg_str[1024];

	lmpl_rsp_ele_t	*ele;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*drive;
	mms_par_node_t	*slot;
	mms_par_node_t	*value;
	mms_par_node_t	*slot_name;
	mms_par_node_t	*cartridge;
	mms_par_node_t	*side;

	mms_trace(MMS_DEVP, "Entering lm_unmount");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7004_MSG, "unmount",
	    "unmount");
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	MMS_PN_LOOKUP(drive, cmd, kw = "drive", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, NULL);

	mms_trace(MMS_DEBUG, "lm_unmount: Drive for unmount cmd - %s",
	    mms_pn_token(value));

	MMS_PN_LOOKUP(slot, cmd, kw = "fromslot", MMS_PN_CLAUSE, NULL);
	loc = NULL;
	MMS_PN_LOOKUP(slot_name, slot, NULL, MMS_PN_STRING, &loc);
	MMS_PN_LOOKUP(cartridge, slot, NULL, MMS_PN_STRING, &loc);
	MMS_PN_LOOKUP(side, slot, NULL, MMS_PN_STRING, &loc);

	mms_trace(MMS_DEBUG, "lm_mount: fromslot cartridge %s, side %s, slot "
	    "%s", mms_pn_token(slot_name), mms_pn_token(side),
	    mms_pn_token(cartridge));

	MMS_PN_LOOKUP(slot, cmd, kw = "toslot", MMS_PN_CLAUSE, NULL);
	loc = NULL;
	MMS_PN_LOOKUP(slot_name, slot, NULL, MMS_PN_STRING, &loc);
	MMS_PN_LOOKUP(cartridge, slot, NULL, MMS_PN_STRING, &loc);
	MMS_PN_LOOKUP(side, slot, NULL, MMS_PN_STRING, &loc);

	mms_trace(MMS_DEBUG, "lm_mount: toslot cartridge %s, side %s, slot "
	    "%s", mms_pn_token(slot_name), mms_pn_token(side),
	    mms_pn_token(cartridge));

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT,
		    "lm_unmount: lm_obtain_task_id failed trying "
		    "to generate config command for unmount");
		return (LM_ERROR);
	}

	(void) snprintf(cfg_str, sizeof (cfg_str), CONFIG_UNMOUNT, lmpl_tid,
	    mms_pn_token(cartridge), mms_pn_token(cartridge),
	    mms_pn_token(value));

	mms_trace(MMS_DEBUG, "lm_unmount: config for unmount:\n%s", cfg_str);

	if ((rc = lm_gen_lmpl_cmd(cfg_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_unmount: Internal processing error "
		    "encountered while processing lmpl config command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR, "lm_unmount: config command did not receive "
		    "a successful response");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_unmount: Got successful response for unmount "
	    "config command");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7103_MSG,
	    mms_pn_token(cartridge), mms_pn_token(value),
	    mms_pn_token(cartridge), mms_pn_token(value));
	(void) snprintf(text_str, sizeof (text_str), LM_TEXT_MNT,
	    mms_pn_token(value), mms_pn_token(slot_name),
	    mms_pn_token(cartridge), mms_pn_token(side));
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, text_str,
	    msg_str);

	lm_remove_lmpl_cmd(lmpl_tid, ele);

	mms_trace(MMS_DEVP, "Exiting lm_unmount");
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "LMPM command %s encounterd an invalid or missing "
	    "%s clause:\n%s", "unmount", kw, mms_pn_build_cmd_text(cmd));
	(void) snprintf(msg_str, sizeof (msg_str), LM_7009_MSG, "unmount", kw,
	    "unmount", kw);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);

	mms_trace(MMS_DEVP, "Exiting lm_unmount");
	return (LM_ERROR);
}

/*
 * lm_move()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM move command being processed.
 *	- tid		Task id of LMPM move command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the move command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the move command. This routine does not currently
 * perform any real move type operations within the disk archiving
 * environment.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to move a cartridge . In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot move a cartridge
 */
int
/* LINTED argument unused in function */
lm_move(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char	msg_str[256];

	mms_trace(MMS_DEVP, "Entering lm_move");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7105_MSG, "move",
	    lm.lm_type, "move", lm.lm_type);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");

	mms_trace(MMS_DEVP, "Exiting lm_move");

	return (LM_OK);
}
/*
 * lm_inject()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM ctivate command being processed.
 *	- tid		Task id of LMPM ctivate command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the ctivate command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the ctivate command. This routine is responsible
 * for performing the inject operations necessary to reflect a cartridge
 * injected into a disk archiving library.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to inject a cartridge . In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot inject a cartridge.
 */
int
/* LINTED argument unused in function */
lm_inject(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char	msg_str[256];

	mms_trace(MMS_DEVP, "Entering lm_inject");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7105_MSG, "inject",
	    lm.lm_type, "inject", lm.lm_type);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");

	mms_trace(MMS_DEVP, "Exiting lm_inject");

	return (LM_OK);
}

/*
 * lm_scan()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM scan command being processed.
 *	- tid		Task id of LMPM scan command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the scan command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the scan command. This routine is responsible
 * for performaing a scan operation on a cartridge, drive, or library within
 * a disk archiving library.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to scan. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot scan.
 */
int
lm_scan(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	i;
	int	rc;
	int	lmpl_tid;
	char	*kw;
	char	*spec_str = NULL;
	char	*dev_list = NULL;
	char	*config_buf = NULL;
	char	msg_str[512];
	char	cfg_str[512];
	char	cmd_str[1024];

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*loc1 = NULL;
	mms_par_node_t	*resp_loc = NULL;
	mms_par_node_t	*clause;
	mms_par_node_t	*resp_clause;
	mms_par_node_t	*pcl;
	mms_par_node_t	*occ;
	mms_par_node_t	*fslot;
	mms_par_node_t	*tslot;
	mms_par_node_t	*dname;
	mms_par_node_t	*rsp;


	lmpl_rsp_ele_t	*show_ele;
	lmpl_rsp_ele_t	*config_ele;
	lmpl_rsp_node_t	*node;

	mms_trace(MMS_DEVP, "Entering lm_scan");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7004_MSG, "scan", "scan");
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	loc = NULL;
			/* See if scan is for cartridge(s) */
	if ((clause = mms_pn_lookup(cmd, kw = "slot", MMS_PN_CLAUSE, &loc))
	    != NULL) {

		if (dev_list != NULL) {
			free(dev_list);
		}
		if (spec_str != NULL) {
			free(spec_str);
		}
		dev_list = NULL;
		spec_str = NULL;
		spec_str = mms_strapp(spec_str, " ");
		dev_list = mms_strapp(dev_list, " ");

			/* Generate list of cartridges to scan for */
		for (i = 0; clause != NULL; clause = mms_pn_lookup(cmd,
		    "slot", MMS_PN_CLAUSE, &loc)) {
				/* Obtain slot-name */
			if ((pcl = mms_pn_lookup(clause, NULL,
			    MMS_PN_STRING, NULL)) == NULL) {
				mms_trace(MMS_ERR,
				    "lm_scan: No pcl string found "
				    "in text clause of cartridge scan");
				free(spec_str);
				free(dev_list);
				return (LM_ERROR);
			}
			if (i == MAX_CONFIG_CARTS) {
				mms_trace(MMS_OPER, "lm_scan: Number of slots "
				    "to scan exceeded the max allowed of "
				    "%d, skipping cartridge %s",
				    MAX_CONFIG_CARTS, mms_pn_token(pcl));
			} else {
				if (i != 0)
					(void) strcat(dev_list, " ");

				mms_trace(MMS_DEBUG,
				    "lm_scan: scan for cartridge "
				    "%s", mms_pn_token(pcl));

				if (lm_obtain_task_id(&lmpl_tid, &show_ele)
				    != LM_OK) {
					mms_trace(MMS_CRIT,
					    "lm_scan: Unable to "
					    "get a task id for show slot "
					    "occupied command");
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				}
				(void) snprintf(cmd_str, sizeof (cmd_str),
				    LM_SHOW_OCC, lmpl_tid, lm.lm_name,
				    mms_pn_token(pcl));

				if ((rc = lm_gen_lmpl_cmd(cmd_str,
				    show_ele, 0)) == LM_ERROR) {
					mms_trace(MMS_ERR, "lm_scan: Internal "
					    "processing error encountered "
					    "while processing LMPL show "
					    "slot occupied command");
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				} else if (rc != LMPL_FINAL_OK) {
					mms_trace(MMS_ERR, "lm_scan: show cmd "
					    "did not receive a successful "
					    "response, unable to get pcl "
					    "%s's occupied state",
					    mms_pn_token(pcl));
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				}

				node = mms_list_head(&show_ele->lmpl_rsp_list);
				rsp = node->lmpl_rsp_tree;
				resp_loc = NULL;
				resp_clause = NULL;

				if ((resp_clause = mms_pn_lookup(rsp, "text",
				    MMS_PN_CLAUSE, &resp_loc)) == NULL) {
					mms_trace(MMS_ERR, "lm_scan: No text "
					    "clause found in show occupied for "
					    "pcl %s", mms_pn_token(pcl));
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				}

				if ((occ = mms_pn_lookup(resp_clause, NULL,
				    MMS_PN_STRING, &resp_loc)) == NULL) {
					mms_trace(MMS_ERR,
					    "lm_scan: No occupied "
					    "string found in show occupied for "
					    "pcl %s", mms_pn_token(pcl));
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				}
				mms_trace(MMS_DEBUG,
				    "lm_scan: pcl %s occupied is "
				    "%s", mms_pn_token(pcl),
				    mms_pn_token(occ));
				if (strcmp("true", mms_pn_token(occ)) == 0)
					(void) snprintf(cfg_str,
					    sizeof (cfg_str), CFG_SLOT,
					    mms_pn_token(pcl),
					    mms_pn_token(pcl), lm.lm_type,
					    "false");
				else
					(void) snprintf(cfg_str,
					    sizeof (cfg_str), CFG_SLOT,
					    mms_pn_token(pcl),
					    mms_pn_token(pcl), lm.lm_type,
					    "true");
				mms_trace(MMS_DEBUG, "lm_scan: Slot spec - %s",
				    cfg_str);
				spec_str = mms_strapp(spec_str, cfg_str);
				dev_list = mms_strapp(dev_list,
				    mms_pn_token(pcl));
				lm_remove_lmpl_cmd(lmpl_tid, show_ele);
			}
		}
		spec_str = mms_strapp(spec_str, ";");

		if (lm_obtain_task_id(&lmpl_tid, &config_ele) != LM_OK) {
			mms_trace(MMS_CRIT, "lm_scan: Unable to get a task "
			    "id for config slot command");
			free(spec_str);
			free(dev_list);
			return (LM_ERROR);
		}

		if (config_buf != NULL)
			free(config_buf);
		config_buf = NULL;
		config_buf = mms_strapp(config_buf,
		    "config task[\"%d\"] scope[partial] %s",
		    lmpl_tid, spec_str);

		if ((rc = lm_gen_lmpl_cmd(config_buf,
		    config_ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_scan: Internal processing "
			    "error encountered while processing lmpl "
			    "config slot command");
			lm_remove_lmpl_cmd(lmpl_tid, config_ele);
			free(config_buf);
			free(spec_str);
			free(dev_list);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_ERR, "lm_scan: Did not receive a "
			    "success response for lmpl config slot "
			    "command");
			handle_lmpl_cmd_error(rc, "scan", "config", tid,
			    ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, config_ele);
			free(config_buf);
			free(spec_str);
			free(dev_list);
			return (LM_ERROR);
		}
		mms_trace(MMS_DEBUG, "lm_scan: Got successful response "
		    "for scan config slot command");

		lm_remove_lmpl_cmd(lmpl_tid, config_ele);
		free(spec_str);
		free(config_buf);
		(void) snprintf(msg_str, sizeof (msg_str), LM_7118_MSG,
		    dev_list, dev_list);
		free(dev_list);
	} else if ((clause = mms_pn_lookup(cmd, kw = "fromslot",
	    MMS_PN_CLAUSE, NULL)) != NULL) {
		loc = NULL;
		MMS_PN_LOOKUP(fslot, clause, NULL, MMS_PN_STRING, &loc);

		MMS_PN_LOOKUP(clause, cmd, kw = "toslot", MMS_PN_CLAUSE,
		    NULL);
		loc = NULL;
		MMS_PN_LOOKUP(tslot, clause, NULL, MMS_PN_STRING, &loc);
		mms_trace(MMS_DEBUG,
		    "lm_scan: scan for cartridges from %s to %s",
		    mms_pn_token(fslot), mms_pn_token(tslot));
		mms_trace(MMS_OPER, "lm_scan: scan for a range of slots is not "
		    "supported on a DiskArchiving library, sending error "
		    "response for scan command");

		(void) snprintf(msg_str, sizeof (msg_str), LM_7116_MSG,
		    lm.lm_type, lm.lm_type);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);
		return (LM_ERROR);

	} else  if ((clause = mms_pn_lookup(cmd, kw = "drive",
	    MMS_PN_CLAUSE, &loc1)) != NULL) {

		if (dev_list != NULL) {
			free(dev_list);
		}
		if (spec_str != NULL) {
			free(spec_str);
		}
		dev_list = NULL;
		spec_str = NULL;
		spec_str = mms_strapp(spec_str, " ");
		dev_list = mms_strapp(dev_list, " ");

		/* Setup to send partial config for drives */
		for (i = 0; clause != NULL; clause = mms_pn_lookup(cmd,
		    "drive", MMS_PN_CLAUSE, &loc1)) {

			if ((dname = mms_pn_lookup(clause, NULL,
			    MMS_PN_STRING, NULL)) == NULL) {
				mms_trace(MMS_ERR,
				    "lm_scan: No drive name string "
				    "found in text clause of drive scan");
				free(spec_str);
				free(dev_list);
				return (LM_ERROR);
			}
			if (i == MAX_CONFIG_DRIVES) {
				mms_trace(MMS_OPER, "lm_scan: Number of drives "
				    "to scan exceeded the max allowed of "
				    "%d, skipping drive %s",
				    MAX_CONFIG_DRIVES, mms_pn_token(dname));
			} else {
				if (i != 0)
					dev_list = mms_strapp(dev_list, " ");

				mms_trace(MMS_DEBUG, "lm_scan: scan for drive "
				    "%s", mms_pn_token(dname));

				if (lm_obtain_task_id(&lmpl_tid,
				    &show_ele) != LM_OK) {
					mms_trace(MMS_CRIT,
					    "lm_scan: Unable to get a task id "
					    "for config drive command");
					return (LM_ERROR);
				}

				(void) snprintf(cmd_str, sizeof (cmd_str),
				    LM_SHOW_DRIVE, lmpl_tid, lm.lm_name,
				    mms_pn_token(dname));
				if ((rc = lm_gen_lmpl_cmd(cmd_str,
				    show_ele, 0)) == LM_ERROR) {
					mms_trace(MMS_ERR, "lm_scan: Internal "
					    "processing error encountered "
					    "while processing LMPL show cmd");
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					lm_remove_lmpl_cmd(lmpl_tid,
					    config_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				} else if (rc != LMPL_FINAL_OK) {
					mms_trace(MMS_ERR, "lm_scan: show cmd "
					    "did not receive a successful "
					    "response, unable to get drive "
					    "%s's drive name",
					    mms_pn_token(dname));
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					lm_remove_lmpl_cmd(lmpl_tid,
					    config_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				}

				node = mms_list_head(&show_ele->lmpl_rsp_list);
				rsp = node->lmpl_rsp_tree;
				resp_loc = NULL;
				resp_clause = NULL;

				if ((resp_clause = mms_pn_lookup(rsp, "text",
				    MMS_PN_CLAUSE, &resp_loc)) == NULL) {
					mms_trace(MMS_ERR, "lm_scan: No text "
					    "clause found in show pcl for "
					    "drive %s", mms_pn_token(dname));
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					lm_remove_lmpl_cmd(lmpl_tid,
					    config_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				}
				if ((pcl = mms_pn_lookup(resp_clause, NULL,
				    MMS_PN_STRING, &resp_loc)) == NULL) {
					mms_trace(MMS_ERR, "lm_scan: No pcl "
					    "string found in show pcl for "
					    "drive %s", mms_pn_token(dname));
					lm_remove_lmpl_cmd(lmpl_tid, show_ele);
					lm_remove_lmpl_cmd(lmpl_tid,
					    config_ele);
					free(spec_str);
					free(dev_list);
					return (LM_ERROR);
				}
				mms_trace(MMS_DEBUG,
				    "lm_scan: drive %s pcl is %s",
				    mms_pn_token(dname), mms_pn_token(pcl));
				if (strlen(mms_pn_token(pcl)) == 0) {
					(void) snprintf(cfg_str,
					    sizeof (cfg_str), CFG_DRIVE,
					    mms_pn_token(dname), "none",
					    "false", "true");
				} else {
					(void) snprintf(cfg_str,
					    sizeof (cfg_str), CFG_DRIVE,
					    mms_pn_token(dname),
					    mms_pn_token(pcl), "true",
					    "true");
				}
				mms_trace(MMS_DEVP, "lm_scan: Drive spec: %s",
				    cfg_str);
				spec_str = mms_strapp(spec_str, cfg_str);
				dev_list = mms_strapp(dev_list,
				    mms_pn_token(dname));
				lm_remove_lmpl_cmd(lmpl_tid, show_ele);
			}
		}
		spec_str = mms_strapp(spec_str, ";");

		if (lm_obtain_task_id(&lmpl_tid, &config_ele) != LM_OK) {
			mms_trace(MMS_CRIT, "lm_scan: Unable to get a task id "
			    "for config drive command");
			return (LM_ERROR);
		}

		if (config_buf != NULL)
			free(config_buf);
		config_buf = NULL;
		config_buf = mms_strapp(config_buf,
		    "config task[\"%d\"] scope[partial] %s",
		    lmpl_tid, spec_str);

		if ((rc = lm_gen_lmpl_cmd(config_buf, config_ele, 0))
		    == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_scan: Internal processing "
			    "error encountered while processing lmpl "
			    "config drive command");
			lm_remove_lmpl_cmd(lmpl_tid, config_ele);
			free(config_buf);
			free(spec_str);
			free(dev_list);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_ERR, "lm_scan: Did not receive a "
			    "success response for lmpl config drive "
			    "command");
			handle_lmpl_cmd_error(rc, "scan", "config", tid,
			    ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, config_ele);
			free(spec_str);
			free(config_buf);
			free(dev_list);
			return (LM_ERROR);
		}
		mms_trace(MMS_DEBUG, "lm_scan: Got successful response "
		    "for scan config drive command");
		free(spec_str);
		free(config_buf);

		lm_remove_lmpl_cmd(lmpl_tid, config_ele);
		(void) snprintf(msg_str, sizeof (msg_str), LM_7125_MSG,
		    dev_list, dev_list);
		free(dev_list);

	} else {
		mms_trace(MMS_DEBUG, "lm_scan: rescan entire library");

		if ((rc = lm_common_ready(LM_NOT, tid, ret_msg)) != LM_OK) {
			mms_trace(MMS_ERR, "lm_scan: Failure of ready command "
			    "to MM. Unable to set state to not ready");
		}
		lm_state = LM_NOT_READY;

		mms_trace(MMS_OPER, "lm_scan: library state set to NOT_READY");

		if ((rc = lm_library_config("scan", tid, ret_msg)) != LM_OK) {
			mms_trace(MMS_ERR, "lm_scan: lm_library_config failed");
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG,
		    "lm_scan: rescan of entire library completed");

		if ((rc = lm_common_ready(LM_READY, tid, ret_msg)) != LM_OK) {
			mms_trace(MMS_ERR, "lm_scan: Failure of ready command "
			    "to MM. Unable to set state to ready");
			return (LM_ERROR);
		}
		lm_state = LM_ACTIVE;

		mms_trace(MMS_OPER, "lm_scan: library sate set to READY");
		(void) snprintf(msg_str, sizeof (msg_str), LM_7124_MSG);
	}

	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");

	mms_trace(MMS_DEVP, "Exiting lm_scan");
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "lm_scan: Encountered an invalid or missing "
	    "%s clause:\n%s", kw, mms_pn_build_cmd_text(cmd));
	(void) snprintf(msg_str, sizeof (msg_str), LM_7009_MSG, "scan", kw,
	    "scan", kw);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}

/*
 * lm_reset()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM ctivate command being processed.
 *	- tid		Task id of LMPM ctivate command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the ctivate command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the ctivate command. This routine is responsible
 * for performing either a partial or full reset on a disk archving library.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to reset. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot reset the library.
 */
int
/* LINTED argument unused in function */
lm_reset(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	mms_trace(MMS_DEVP, "Entering DISK reset process");

	if (mms_pn_lookup(cmd, "partial", MMS_PN_KEYWORD, NULL) == NULL) {
		mms_trace(MMS_DEBUG, "lm_reset: Nothing defined to do for a "
		    "full reset of an DISK library");
	}

	mms_trace(MMS_DEBUG,
	    "lm_reset: Nothing defined to do for a partial reset "
	    "of a DISK library");

	return (LM_OK);
}

/*
 * lm_eject()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM eject command being processed.
 *	- tid		Task id of LMPM eject command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the eject command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the eject command. This routine is responsible
 * for performing the eject operations necessary to reflect a cartridge
 * being ejected from a disk archiving library.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to eject a cartridge. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot eject a cartridge.
 */
int
/* LINTED argument unused in function */
lm_eject(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char	msg_str[256];

	mms_trace(MMS_DEVP, "Entering lm_eject");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7105_MSG, "eject",
	    lm.lm_type, "eject", lm.lm_type);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");

	mms_trace(MMS_DEVP, "Exiting lm_eject");

	return (LM_OK);
}

/*
 * lm_barrier()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM barrier command being processed.
 *	- tid		Task id of LMPM barrier command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the barrier command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the barrier command. This routine does not currently
 * perform any real barrier type operations within the disk archiving
 * environment.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to set a barrier. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot set a barrier.
 */
int
/* LINTED argument unused in function */
lm_barrier(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char	msg_str[256];

	mms_trace(MMS_DEVP, "Entering lm_barrier");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7105_MSG, "barrier",
	    lm.lm_type, "barrier", lm.lm_type);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");

	mms_trace(MMS_DEVP, "Exiting lm_barrier");

	return (LM_OK);
}

/*
 * lm_private()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM private command being processed.
 *	- tid		Task id of LMPM private command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the private command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the private command. This routine is responsible
 * for handling the get, set, unset of any specific disk library
 * variables.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to handle a private command. In some
 *			cases depending on the error, ret_msg may be updated
 *			to reflect the error that was encountered as to why
 *			the LM cannot handle a private command.
 */

int
/* LINTED argument unused in function */
lm_private(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char    msg_str[256];

	mms_trace(MMS_DEVP, "Entering lm_private");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7015_MSG, "private",
	    lm.lm_type, "private", lm.lm_type);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");

	mms_trace(MMS_DEVP, "Exiting lm_private");
	return (LM_OK);
}

/*
 * lm_cancel()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM activate command being processed.
 *	- tid		Task id of LMPM activate command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the activate command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the cancel command. This routine does not do
 * anything. The cancel of a LMPM command is only available in the
 * common library code. The commad can only be cancelled if processing of
 * it has not yet started.
 *
 * Return Values:
 *	- LM_OK		Always
 */
int
/* LINTED argument unused in function */
lm_cancel(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char msg_str[512];

	mms_trace(MMS_DEVP, "Entering DISK lm_cancel");

	(void) snprintf(msg_str, sizeof (msg_str), LM_7105_MSG, "barrier",
	    lm.lm_type, "barrier", lm.lm_type);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");

	mms_trace(MMS_DEVP, "Exiting DISK lm_cancel");
	return (LM_OK);
}

/*
 * lm_exit()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM exit command being processed.
 *	- tid		Task id of LMPM exit command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the exit command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the exit command. This routine does nothing. The
 * LM exit is handled in the common exit library code only.
 *
 * Return Values:
 *	- LM_OK		Always
 */
int
/* LINTED argument unused in function */
lm_exit(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	mms_trace(MMS_DEVP, "Entering DISK lm_exit");

	mms_trace(MMS_DEVP, "Exiting DISK lm_exit");
	return (LM_OK);
}
/*
 * lm_event()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM event command being processed.
 *	- tid		Task id of LMPM event command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the event command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are disk archiving specific
 * for the LM to process the event command. There are currently no events
 * that a disk archiving library will register for. This routine does
 * nothing.
 *
 * Return Values:
 *	- LM_OK		Always
 */
int
/* LINTED argument unused in function */
lm_event(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	mms_trace(MMS_DEVP, "Entering DISK lm_event");
	mms_trace(MMS_DEVP, "Exiting DISK lm_event");
	return (LM_OK);
}

/*
 * lm_library_config()()
 *
 * Parameters:
 *	- cmd		The command that needs a full config (activate or
 *			full library scan)
 *	- tid		Task id of LMPM activate command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the activate command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are required to do a
 * full config on a disk specific library. It creates the bay-spec,
 * slotgrp-spec, slot-spec, and drive-spec as defined in the LMPL
 * config command.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to complete the full config command.
 *			In some cases depending on the error, ret_msg may
 *			be updated to reflect the error that was encountered.
 */
int
lm_library_config(char *cmd, char *tid, char *ret_msg)
{
	int		rc;
	int		lmpl_tid;
	int		cfg_tid;
	int		num_carts;
	int		num_drives;
	int		cell_size;
	int		rsp_cnt;

	char		*kw;
	char		cmd_str[1024];
	char		cfg_str[512];
	char		*slot_spec;
	char		*drive_spec;
	char		*fmt;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*loc1 = NULL;
	mms_par_node_t	*rsp;
	mms_par_node_t	*clause;
	mms_par_node_t	*num;
	mms_par_node_t	*dname;
	mms_par_node_t	*pcl;
	mms_par_node_t	*occ;

	lmpl_rsp_ele_t	*ele;
	lmpl_rsp_ele_t	*cfg_ele;
	lmpl_rsp_node_t	*node;

	mms_trace(MMS_DEVP, "Entering lm_library_config");

		/* Configure bays and slot groups */
	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_library_config: Unable to get a task "
		    "id for full config command to set bays and groups");
		return (LM_ERROR);
	}

		/* There are no real bays, caps, free slots for a disk */
		/* archive library, create a generic set to conform to */
		/* IEEE spec */
	(void) snprintf(cmd_str, sizeof (cmd_str), DISK_CONFIG, lmpl_tid);
	mms_trace(MMS_DEVP, "lm_library_config: bay and slot group config:\n%s",
	    cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_library_config: Internal "
		    "processing error encountered while processing "
		    "full config command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Error encountered while "
		    "sending full config command");
		handle_lmpl_cmd_error(rc, cmd, "config", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_library_config: Got successful response for "
	    "full creation config command");
	lm_remove_lmpl_cmd(lmpl_tid, ele);

		/* Obtain the number of cartridges in library */
	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Unable to get a task id "
		    "for show command to obtain number of cartridges in "
		    "disk library");
		return (LM_ERROR);
	}

	(void) snprintf(cmd_str, sizeof (cmd_str), LM_SHOW_CART_NUM, lmpl_tid,
	    lm.lm_name);
	mms_trace(MMS_DEVP, "lm_library_config: Obtain number of cartridges in "
	    "libary:\n%s", cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_library_config: Internal "
		    "processing error encountered while processing "
		    "show command to get number of cartridges in library");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Error encountered while "
		    "sending show command to get number of cartridges in "
		    "disk library");
		handle_lmpl_cmd_error(rc, cmd, "show", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	node = mms_list_head(&ele->lmpl_rsp_list);
	rsp = node->lmpl_rsp_tree;

	MMS_PN_LOOKUP(clause, rsp, kw = "text", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(num, clause, NULL, MMS_PN_STRING, NULL);
	num_carts = atoi(mms_pn_token(num));

	mms_trace(MMS_DEBUG, "lm_library_config: %d cartridges in disk library "
	    "%s", num_carts, lm.lm_name);

	lm_remove_lmpl_cmd(lmpl_tid, ele);

	if (num_carts == 0)
		goto skip_carts;

	if (num_carts > MAX_CONFIG_CARTS)
		cell_size = MAX_CONFIG_CARTS * SLOT_CFG_SIZE + SLOT_MIN;
	else
		cell_size = num_carts * SLOT_CFG_SIZE + SLOT_MIN;

	if ((slot_spec = (char *)malloc(cell_size)) == NULL) {
		lm_serr(MMS_CRIT, "lm_library_config: Unable to malloc space "
		    "for slot spec definitions, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

		/* Create slot configs for each cartridge */
	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Unable to get a task id "
		    "for show command to obtain list of cartridges");
		free(slot_spec);
		return (LM_ERROR);
	}

	(void) snprintf(cmd_str, sizeof (cmd_str), LM_SHOW_CARTS, lmpl_tid,
	    lm.lm_name);

	mms_trace(MMS_DEBUG, "lm_library_config: Obtain list of cartridges in "
	    "%s library:\n%s", lm.lm_name, cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_library_config: Internal "
		    "processing error encountered while processing "
		    "for show command to obtain list of cartridges");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(slot_spec);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Error encountered while "
		    "sending show command to obtain list of cartridges in "
		    "disk library");
		handle_lmpl_cmd_error(rc, cmd, "show", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(slot_spec);
		return (LM_ERROR);
	}

	node = mms_list_head(&ele->lmpl_rsp_list);
	rsp = node->lmpl_rsp_tree;
	loc = NULL;

	do {
		(void) memset(slot_spec, 0, cell_size);
		(void) strcpy(slot_spec, "config task[\"%d\"] scope[partial] ");

		rsp_cnt = 0;
		do {
			if ((clause = mms_pn_lookup(rsp, "text",
			    MMS_PN_CLAUSE, &loc)) != NULL) {

				mms_trace(MMS_DEBUG,
				    "lm_lib_config:, Validating a "
				    "text clause");

				loc1 = NULL;
				if ((pcl = mms_pn_lookup(clause, NULL,
				    MMS_PN_STRING, &loc1)) == NULL) {
					lm_remove_lmpl_cmd(lmpl_tid, ele);
					free(slot_spec);
					return (LM_ERROR);
				}
				if ((occ = mms_pn_lookup(clause, NULL,
				    MMS_PN_STRING, &loc1)) == NULL) {
					lm_remove_lmpl_cmd(lmpl_tid, ele);
					free(slot_spec);
					return (LM_ERROR);
				}

				mms_trace(MMS_DEBUG,
				    "lm_lib_config: cartridge pcl "
				    "is %s, occ is %s", mms_pn_token(pcl),
				    mms_pn_token(occ));

				if (strcmp("true", mms_pn_token(occ)) == 0)
					(void) snprintf(cfg_str,
					    sizeof (cmd_str), CFG_SLOT,
					    mms_pn_token(pcl),
					    mms_pn_token(pcl), lm.lm_type,
					    "false");
				else
					(void) snprintf(cfg_str,
					    sizeof (cfg_str), CFG_SLOT,
					    mms_pn_token(pcl),
					    mms_pn_token(pcl), lm.lm_type,
					    "true");
				mms_trace(MMS_DEBUG, "lm_lib_config: Slot "
				    "spec - %s", cfg_str);
				(void) strcat(slot_spec, cfg_str);
				rsp_cnt++;
			} else {
				node = mms_list_next(&ele->lmpl_rsp_list, node);
				if (node != NULL) {
					rsp = node->lmpl_rsp_tree;
					loc = NULL;
				}
			}
		} while ((rsp_cnt < MAX_CONFIG_CARTS) && (node != NULL));

		(void) strcat(slot_spec, ";");

		if (lm_obtain_task_id(&cfg_tid, &cfg_ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_library_config: Unable to get a "
			    "task id for config slot command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(slot_spec);
			return (LM_ERROR);
		}

		fmt = mms_strnew(slot_spec, cfg_tid);
		free(slot_spec);
		slot_spec = fmt;

		mms_trace(MMS_DEBUG,
		    "lm_lib_config: SLOT_SPEC:\n%s", slot_spec);

		if ((rc = lm_gen_lmpl_cmd(slot_spec, cfg_ele, 0))
		    == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_library_config: Internal "
			    "processing error encountered while processing "
			    "lmpl config slot command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			lm_remove_lmpl_cmd(cfg_tid, cfg_ele);
			free(slot_spec);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_CRIT,
			    "lm_activate: Error encountered while "
			    "sending lmpl config slot command");
			handle_lmpl_cmd_error(rc, "activate", "config",
			    tid, ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			lm_remove_lmpl_cmd(cfg_tid, cfg_ele);
			free(slot_spec);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_lib_config: Got successful response "
		    "for slot creation config command");

		lm_remove_lmpl_cmd(cfg_tid, cfg_ele);

	} while (node != NULL);

	free(slot_spec);
	lm_remove_lmpl_cmd(lmpl_tid, ele);

skip_carts:

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Unable to get a task id "
		    "for show command to obtain number of drives in "
		    "library");
		return (LM_ERROR);
	}

	(void) snprintf(cmd_str, sizeof (cmd_str), LM_SHOW_DRIVE_NUM, lmpl_tid,
	    lm.lm_name);
	mms_trace(MMS_DEVP, "lm_library_config: Obtain number of drives in "
	    "disk libary:\n%s", cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_library_config: Internal "
		    "processing error encountered while processing "
		    "show command to get number of drives in library");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Error encountered while "
		    "sending show command to get number of drives in library");
		handle_lmpl_cmd_error(rc, cmd, "show", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	node = mms_list_head(&ele->lmpl_rsp_list);
	rsp = node->lmpl_rsp_tree;

	MMS_PN_LOOKUP(clause, rsp, kw = "text", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(num, clause, NULL, MMS_PN_STRING, NULL);
	num_drives = atoi(mms_pn_token(num));

	mms_trace(MMS_DEBUG, "lm_library_config: Number of drives in library "
	    "- %d", num_drives);

	lm_remove_lmpl_cmd(lmpl_tid, ele);

		/* If no drives to process return */
	if (num_drives == 0)
		return (LM_OK);

	if (num_drives > MAX_CONFIG_DRIVES)
		cell_size = MAX_CONFIG_DRIVES * DRIVE_CFG_SIZE + DRIVE_MIN;
	else
		cell_size = num_drives * DRIVE_CFG_SIZE + DRIVE_MIN;

	if ((drive_spec = (char *)malloc(cell_size)) == NULL) {
		lm_serr(MMS_CRIT, "lm_library_config: Unable to malloc space "
		    "for drive spec definitions, errno - %s",
		    strerror(errno));
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Unable to get a task id "
		    "for show command to obtain list of drives");
		free(drive_spec);
		return (LM_ERROR);
	}

	(void) snprintf(cmd_str, sizeof (cmd_str), LM_SHOW_DRIVES, lmpl_tid,
	    lm.lm_name);

	mms_trace(MMS_DEBUG, "lm_activate: Obtain list of drives in "
	    "%s libary:\n%s", lm.lm_name, cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_library_config: Internal "
		    "processing error encountered while processing "
		    "for show command to obtain list of drives");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(drive_spec);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: Error encountered while "
		    "sending show command to obtain list of drives in "
		    "disk library");
		handle_lmpl_cmd_error(rc, cmd, "show", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(drive_spec);
		return (LM_ERROR);
	}

	node = mms_list_head(&ele->lmpl_rsp_list);
	rsp = node->lmpl_rsp_tree;
	loc = NULL;

	do {

		(void) memset(drive_spec, 0, cell_size);
		(void) strcpy(drive_spec,
		    "config task[\"%d\"] scope[partial] ");
		rsp_cnt = 0;

		do {
			if ((clause = mms_pn_lookup(rsp, "text",
			    MMS_PN_CLAUSE, &loc)) != NULL) {

				mms_trace(MMS_DEVP, "lm_lib_config: "
				    "Validating a text clause");

				loc1 = NULL;
				if ((dname = mms_pn_lookup(clause, NULL,
				    MMS_PN_STRING, &loc1)) == NULL) {
					lm_remove_lmpl_cmd(lmpl_tid, ele);
					free(drive_spec);
					return (LM_ERROR);
				}

				mms_trace(MMS_DEBUG, "lm_lib_config: "
				    "drive name is %s", mms_pn_token(dname));

				if ((pcl = mms_pn_lookup(clause, NULL,
				    MMS_PN_STRING, &loc1)) == NULL) {
					lm_remove_lmpl_cmd(lmpl_tid, ele);
					free(drive_spec);
					return (LM_ERROR);
				}

				mms_trace(MMS_DEBUG, "lm_lib_config: "
				    "drive pcl is %s", mms_pn_token(pcl));

				if (strlen(mms_pn_token(pcl)) == 0) {
					(void) snprintf(cfg_str,
					    sizeof (cfg_str), CFG_DRIVE,
					    mms_pn_token(dname), "none",
					    "false", "true");
					mms_trace(MMS_DEVP, "lm_lib_config: "
					    "Drive spec - %s", cfg_str);
				} else {
					(void) snprintf(cfg_str,
					    sizeof (cfg_str), CFG_DRIVE,
					    mms_pn_token(dname),
					    mms_pn_token(pcl), "true",
					    "true");
					mms_trace(MMS_DEVP, "lm_lib_config: "
					    "Drive spec - %s", cfg_str);
				}
				(void) strcat(drive_spec, cfg_str);
				rsp_cnt++;
			} else {
				node = mms_list_next(&ele->lmpl_rsp_list, node);
				if (node != NULL) {
					rsp = node->lmpl_rsp_tree;
					loc = NULL;
				}
			}
		} while ((rsp_cnt < MAX_CONFIG_DRIVES) && (node != NULL));

		(void) strcat(drive_spec, ";");

		if (lm_obtain_task_id(&cfg_tid, &cfg_ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_lib_config: Unable to get a task id "
			    "for config drive command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(drive_spec);
			return (LM_ERROR);
		}

		fmt = mms_strnew(drive_spec, cfg_tid);
		free(drive_spec);
		drive_spec = fmt;

		mms_trace(MMS_DEBUG, "lm_lib_config: DRIVE_SPEC:\n%s",
		    drive_spec);

		if ((rc = lm_gen_lmpl_cmd(drive_spec, cfg_ele, 0))
		    == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_lib_config: Internal "
			    "processing error encountered while processing "
			    "lmpl config drive command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			lm_remove_lmpl_cmd(cfg_tid, cfg_ele);
			free(drive_spec);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_CRIT,
			    "lm_lib_config: Error encountered while "
			    "sending lmpl config drive command");
			handle_lmpl_cmd_error(rc, cmd, "config", tid, ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			lm_remove_lmpl_cmd(cfg_tid, cfg_ele);
			free(drive_spec);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_lib_config: Got successful response "
		    "for drive creation config command");

		lm_remove_lmpl_cmd(cfg_tid, cfg_ele);

	} while (node != NULL);

	free(drive_spec);
	lm_remove_lmpl_cmd(lmpl_tid, ele);

	return (LM_OK);

not_found:
	lm_remove_lmpl_cmd(lmpl_tid, ele);
	mms_trace(MMS_ERR, "lm_library_config: LMPL command has an invalid or "
	    "missing %s clause:\n%s", kw, mms_pn_build_cmd_text(rsp));
	return (LM_ERROR);
}
