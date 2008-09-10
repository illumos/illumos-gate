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

int lm_library_config(char *, char *, char *);

#define	ACS_PKT_VER	4	/* ACSLS packet version LM supports */

#define	CFG_SLOT "slot [\"%s\" \"panel %d\" \"group %d\" \
\"%s\" \"%s\" true true] "

#define	DELE_SLOT "delslots [\"%s\"] "

/* The following command formats differ from those in the  IEEE */
/* spec in the drive name. The reason this was done is that when the */
/* LM is activated initally, it does not know what the logical */
/* names are for the drives in the library, it only knows a geometry */
/* from the acsls perspective. Thus during the inital activation config */
/* LM sends up the acsls geometry and MM matches this with the geoemetry */
/* attribute of a drive. This same scheme was carried over for the */
/* partial configs assocatied when mounts and unmounts are done, even though */
/* LM knows the logical name at that time. */

#define	TEXT_CART "\"%s\" "
#define	CFG_DRIVE "drive [\"%s\" \"%d,%d,%d,%d\" \"panel %d\" \"%s\" %s %s] "

#define	CONFIG_MOUNT "config task [\"%d\"] scope [partial] \
slot [\"%s\" \"panel %d\" \"group %d\" \"none\" \"%s\" false true] \
drive [\"%s\" \"%d,%d,%d,%d\" \"panel %d\" \"%s\" true true]; "

#define	CONFIG_UNMOUNT "config task [\"%d\"] scope [partial] \
slot [\"%s\" \"panel %d\" \"group %d\" \"%s\" \"%s\" true true] \
drive [\"%s\" \"%d,%d,%d,%d\" \"panel %d\" \"none\" false true]; "

#define	CONFIG_CART_EVENT "config task [\"%d\"] scope [partial] \
slot [\"%s\" \"panel %d\" \"group %d\" \"%s\" \"%s\" true true]; "

#define	CONFIG_DRIVE_EVENT "config task [\"%d\"] scope [partial] \
drive [\"%s\" \"%d,%d,%d,%d\" \"panel %d\" \"%s\" %s %s]; "

#define	LM_SHOW_DRIVE "show task [\"%d\"] \
match [streq(DRIVE.\"DriveName\" \"%s\")] \
report[DRIVE.\"DriveGeometry\"] reportmode[namevalue]; "

#define	LM_SHOW_SERIAL "show task [\"%d\"] \
match [streq(DRIVE.\"DriveName\" \"%s\")] \
report[DRIVE.\"DriveSerialNum\"] reportmode[namevalue]; "

static	char	*_SrcFile = __FILE__;

int
/* LINTED argument unused in function */
lm_exit(mms_par_node_t *cmd, char *tid, char *ret_msg)
{

	mms_trace(MMS_DEVP, "lm_exit: Entering ACSLS exit process");
	return (LM_OK);

}

int
lm_mount(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	ACS_MOUNT_RESPONSE	*mp;
	ACS_QUERY_VOL_RESPONSE	*vol_qp;
	QU_VOL_STATUS		*vol_sp;
	VOLID			vol_id_list[MAX_ID];
	VOLID			vol_id;
	DRIVEID			drive_id;

	ACS_QUERY_MNT_RESPONSE	*mnt_qp;
	QU_MNT_STATUS		*mnt_sp;
	QU_DRV_STATUS		*drv_sp;

	acs_rsp_ele_t		*acs_rsp;

	int		i;
	int		j;
	int		rc;
	int		lmpl_tid;
	int		panel;
	char		*kw;
	char		*cptr;
	char		*cptr1;
	char		*pptr;
	char		*serial;
	char		*geometry;
	char		drive_name[20];
	char		msg_str[256];
	char		text_str[1024];
	char		cfg_str[1024];
	char		drive_list[1024];

	lmpl_rsp_ele_t	*ele;
	lmpl_rsp_node_t	*node;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*drive;
	mms_par_node_t	*slot;
	mms_par_node_t	*value;
	mms_par_node_t	*slot_name;
	mms_par_node_t	*cartridge;
	mms_par_node_t	*side;
	mms_par_node_t	*rsp;
	mms_par_node_t	*clause;
	mms_par_node_t	*attribute;

	mms_trace(MMS_DEVP, "Entering lm_mount");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "mount", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	if ((clause = mms_pn_lookup(cmd, "query", MMS_PN_KEYWORD, NULL))
	    != NULL) {
		mms_trace(MMS_DEBUG, "lm_mount: query mount requested");

		loc = NULL;
		MMS_PN_LOOKUP(slot, cmd, kw = "slot", MMS_PN_CLAUSE, NULL);
		MMS_PN_LOOKUP(slot_name, slot, NULL, MMS_PN_STRING, &loc);
		MMS_PN_LOOKUP(cartridge, slot, NULL, MMS_PN_STRING, &loc);
		MMS_PN_LOOKUP(side, slot, NULL, MMS_PN_STRING, &loc);

		mms_trace(MMS_DEBUG,
		    "lm_mount: Query mount on Cartridge PCL - %s",
		    mms_pn_token(cartridge));

		(void) strncpy(vol_id_list[0].external_label,
		    mms_pn_token(cartridge), EXTERNAL_LABEL_SIZE);
		vol_id_list[0].external_label[EXTERNAL_LABEL_SIZE] = '\0';
		if (lm_acs_query_mount(&acs_rsp, vol_id_list, 1, "mount", tid,
		    ret_msg) == LM_ERROR) {
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_mount: Recevied final response for "
		    "query_mount()");

		mnt_qp = (ACS_QUERY_MNT_RESPONSE *)acs_rsp->acs_rbuf;
		if (mnt_qp->query_mnt_status != STATUS_SUCCESS) {
			mms_trace(MMS_ERR, "lm_mount: response from "
			    "query_mount() failed, status - %s",
			    acs_status(mnt_qp->query_mnt_status));
			lm_handle_query_mount_error(mnt_qp->query_mnt_status,
			    "mount", tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}
		mnt_sp = &mnt_qp->mnt_status[0];
		if (mnt_sp->status != STATUS_VOLUME_HOME) {
			mms_trace(MMS_ERR,
			    "lm_mount: volume %s not found in slot "
			    "prior to query mount, status - %s",
			    mms_pn_token(cartridge),
			    acs_status(mnt_sp->status));
			lm_handle_acsls_error(mnt_sp->status, "acs_query_mount",
			    "mount", tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		drive_list[0] = '\0';

		for (i = 0, j = 0; i < (int)mnt_sp->drive_count; i++) {
			drv_sp = &mnt_sp->drive_status[i];
			if (drv_sp->status != STATUS_DRIVE_AVAILABLE) {
				mms_trace(MMS_DEBUG,
				    "lm_mount: drive %d,%d,%d,%d "
				    "not available for mount, status - %s",
				    drv_sp->drive_id.panel_id.lsm_id.acs,
				    drv_sp->drive_id.panel_id.lsm_id.lsm,
				    drv_sp->drive_id.panel_id.panel,
				    drv_sp->drive_id.drive,
				    acs_status(drv_sp->status));
				continue;
			}

			if (j != 0)
				(void) strcat(drive_list, " ");
			j++;
			(void) snprintf(drive_name, sizeof (drive_name),
			    "\"%d,%d,%d,%d\"",
			    drv_sp->drive_id.panel_id.lsm_id.acs,
			    drv_sp->drive_id.panel_id.lsm_id.lsm,
			    drv_sp->drive_id.panel_id.panel,
			    drv_sp->drive_id.drive);
			(void) strcat(drive_list, drive_name);
		}
		free(acs_rsp);

		(void) snprintf(text_str, sizeof (text_str), LM_TEXT_CLS,
		    drive_list);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid,
		    text_str, "");
		return (LM_OK);
	}

	MMS_PN_LOOKUP(drive, cmd, kw = "drive", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, NULL);

	mms_trace(MMS_DEBUG, "lm_mount: Drive for mount cmd - %s",
	    mms_pn_token(value));

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_mount: lm_obtain_task_id failed "
		    "trying to generate show command for event");
		return (LM_ERROR);
	}
	(void) snprintf(cfg_str, sizeof (cfg_str), LM_SHOW_SERIAL, lmpl_tid,
	    mms_pn_token(value));

	mms_trace(MMS_DEBUG, "lm_mount: drive show cmd:\n%s", cfg_str);

	if ((rc = lm_gen_lmpl_cmd(cfg_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_mount: Internal processing error "
		    "encountered while processing LMPL show cmd");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR, "lm_mount: show cmd did not receive "
		    "a successful response");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_mount: show cmd got sucess final response");
	node = mms_list_head(&ele->lmpl_rsp_list);
	rsp = node->lmpl_rsp_tree;

	loc = NULL;
	if ((clause = mms_pn_lookup(rsp, "DriveSerialNum", MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT, "lm_mount: No DriveSerialNum "
		    "attribute found in response to show cmd");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7032_MSG,
		    "cmd", "mount", "drive", mms_pn_token(value), NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT, "lm_mount: No DriveSerialNum value "
		    "found in response to show cmd");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7032_MSG,
		    "cmd", "mount", "drive", mms_pn_token(value), NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_mount: Drive %s has a serial number of %s",
	    mms_pn_token(value), mms_pn_token(attribute));

	loc = NULL;
	MMS_PN_LOOKUP(slot, cmd, kw = "slot", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(slot_name, slot, NULL, MMS_PN_STRING, &loc);

	mms_trace(MMS_DEBUG, "lm_mount: Slot for mount cmd - %s",
	    mms_pn_token(slot_name));

	MMS_PN_LOOKUP(cartridge, slot, NULL, MMS_PN_STRING, &loc);

	mms_trace(MMS_DEBUG, "lm_mount: Cartridge PCL for mount cmd - %s",
	    mms_pn_token(cartridge));

	MMS_PN_LOOKUP(side, slot, NULL, MMS_PN_STRING, &loc);

	mms_trace(MMS_DEBUG, "lm_mount: Side for mount cmd - %s",
	    mms_pn_token(side));

	(void) strncpy(vol_id_list[0].external_label, mms_pn_token(cartridge),
	    EXTERNAL_LABEL_SIZE);
	vol_id_list[0].external_label[EXTERNAL_LABEL_SIZE] = '\0';
	if ((lm_acs_query_volume(&acs_rsp, vol_id_list, 1, "mount", tid,
	    ret_msg)) == LM_ERROR) {
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_mount: Recevied final response for "
	    "query_volume()");

	vol_qp = (ACS_QUERY_VOL_RESPONSE *)acs_rsp->acs_rbuf;
	if (vol_qp->query_vol_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_mount: response from "
		    "query_volume() failed, status - %s",
		    acs_status(vol_qp->query_vol_status));
		lm_handle_query_vol_error(vol_qp->query_vol_status,
		    "mount", tid, ret_msg);
		free(acs_rsp);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}
	vol_sp = &vol_qp->vol_status[0];
	if (vol_sp->status != STATUS_VOLUME_HOME) {
		mms_trace(MMS_ERR, "lm_mount: volume %s not found in slot "
		    "prior to mount, status - %s",
		    mms_pn_token(cartridge), acs_status(vol_sp->status));
		lm_handle_acsls_error(vol_sp->status, "acs_query_vol", "mount",
		    tid, ret_msg);
		free(acs_rsp);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_mount: vol %s is in location %d,%d,%d,%d,%d "
	    "prior to mount", vol_sp->vol_id.external_label,
	    vol_sp->location.cell_id.panel_id.lsm_id.acs,
	    vol_sp->location.cell_id.panel_id.lsm_id.lsm,
	    vol_sp->location.cell_id.panel_id.panel,
	    vol_sp->location.cell_id.row,
	    vol_sp->location.cell_id.col);

	panel = vol_sp->location.cell_id.panel_id.panel;
	free(acs_rsp);

	serial = strdup(mms_pn_token(attribute));

	if (lm_obtain_geometry(serial, &geometry, "mount", tid, ret_msg)
	    != LM_OK) {
		mms_trace(MMS_ERR, "lm_mount: Trying to obtain geometry "
		    "for drive with serial number %s failed", serial);
			/* Error return message set in function */
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(serial);
		return (LM_ERROR);
	}
	if (strcmp(geometry, "") == 0) {
		mms_trace(MMS_ERR, "lm_mount: No geometry found for drive "
		    "with serial number of %s", serial);
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7126_MSG,
		    "name", mms_pn_token(value), "serial", serial, NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_DEVCMD), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(serial);
		free(geometry);
		return (LM_ERROR);
	}

	cptr = cptr1 = strdup(geometry);
	pptr = strstr(cptr, ",");
	*pptr = '\0';
	drive_id.panel_id.lsm_id.acs = atoi(cptr);
	cptr = pptr + 1;
	pptr = strstr(cptr, ",");
	*pptr = '\0';
	drive_id.panel_id.lsm_id.lsm = atoi(cptr);
	cptr = pptr + 1;
	pptr = strstr(cptr, ",");
	*pptr = '\0';
	drive_id.panel_id.panel = atoi(cptr);
	cptr = pptr + 1;
	drive_id.drive = atoi(cptr);
	free(cptr1);


	mms_trace(MMS_DEBUG, "lm_mount: Drive geometry - %d,%d,%d,%d",
	    drive_id.panel_id.lsm_id.acs, drive_id.panel_id.lsm_id.lsm,
	    drive_id.panel_id.panel, drive_id.drive);

	(void) strncpy(vol_id.external_label, mms_pn_token(cartridge),
	    EXTERNAL_LABEL_SIZE);
	vol_id.external_label[EXTERNAL_LABEL_SIZE] = '\0';
	mms_trace(MMS_DEBUG, "lm_mount: Volume to mount %s",
	    vol_id.external_label);

	if ((lm_acs_mount(&acs_rsp, vol_id, drive_id, "mount", tid,
	    ret_msg)) == LM_ERROR) {
		free(serial);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(geometry);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG,
	    "lm_mount: Received final response for acs_mount()");

	mp = (ACS_MOUNT_RESPONSE *)acs_rsp->acs_rbuf;
	if (mp->mount_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_mount: response from acs_mount() failed, "
		    "status - %s", acs_status(mp->mount_status));
		lm_handle_mount_error(mp->mount_status, mms_pn_token(value),
		    mms_pn_token(attribute), geometry,
		    drive_id.panel_id.lsm_id.lsm,
		    drive_id.panel_id.panel, "mount", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(acs_rsp);
		free(serial);
		free(geometry);
		return (LM_ERROR);
	}

	free(geometry);

		/* Clean up from drive show command */
	lm_remove_lmpl_cmd(lmpl_tid, ele);
	free(acs_rsp);

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_mount: lm_obtain_task_id failed trying "
		    "to generate config command for mount");
		free(serial);
		return (LM_ERROR);
	}

	(void) snprintf(cfg_str, sizeof (cfg_str), CONFIG_MOUNT, lmpl_tid,
	    mms_pn_token(cartridge), panel, panel, lm.lm_type, serial,
	    drive_id.panel_id.lsm_id.acs, drive_id.panel_id.lsm_id.lsm,
	    drive_id.panel_id.panel, drive_id.drive, drive_id.panel_id.panel,
	    mms_pn_token(cartridge));

	free(serial);

	mms_trace(MMS_DEBUG, "lm_mount: config for mount:\n%s", cfg_str);

	if ((rc = lm_gen_lmpl_cmd(cfg_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_mount: Internal processing error "
		    "encountered while processing lmpl config command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
			/* unmount cartridge and send error response */
		if ((lm_acs_dismount(&acs_rsp, vol_id, drive_id, "mount", tid,
		    ret_msg)) == LM_ERROR)
			mms_trace(MMS_ERR, "lm_mount: Unable to unmount "
			    "cartridge %s after mount's config failed",
			    mms_pn_token(cartridge));
		else {
			mms_trace(MMS_ERR, "lm_mount: Unmounted cartridge %s "
			    "due to mount's config failure",
			    mms_pn_token(cartridge));
			free(acs_rsp);
		}
		handle_lmpl_cmd_error(rc, "mount", "config", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_mount: Got successful response for mount "
	    "config command");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7102_MSG,
	    "cart", mms_pn_token(cartridge), "drive", mms_pn_token(value),
	    NULL);
	(void) snprintf(text_str, sizeof (text_str), LM_TEXT_MNT,
	    mms_pn_token(value), mms_pn_token(slot_name),
	    mms_pn_token(cartridge), mms_pn_token(side));
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, text_str,
	    msg_str);

	lm_remove_lmpl_cmd(lmpl_tid, ele);
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "LMPM command %s encounterd an invalid or missing "
	    "%s clause:\n%s", "mount", kw, mms_pn_build_cmd_text(cmd));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "mount", "part", kw, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}

int
lm_unmount(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	ACS_DISMOUNT_RESPONSE	*mp;
	ACS_QUERY_VOL_RESPONSE	*vol_qp;
	QU_VOL_STATUS		*vol_sp;
	VOLID			vol_id_list[MAX_ID];
	VOLID			vol_id;
	DRIVEID			drive_id;

	acs_rsp_ele_t		*acs_rsp;

	int		i;
	int		rc;
	int		lmpl_tid;
	int		panel;

	char		*kw;
	char		*cptr;
	char		*cptr1;
	char		*pptr;
	char		*serial;
	char		*geometry;
	char		msg_str[256];
	char		text_str[256];
	char		cfg_str[1024];

	lmpl_rsp_ele_t	*ele;
	lmpl_rsp_node_t	*node;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*drive;
	mms_par_node_t	*slot;
	mms_par_node_t	*value;
	mms_par_node_t	*slot_name;
	mms_par_node_t	*cartridge;
	mms_par_node_t	*side;
	mms_par_node_t	*rsp;
	mms_par_node_t	*clause;
	mms_par_node_t	*attribute;

	mms_trace(MMS_DEVP, "Entering lm_unmount");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "unmount", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	MMS_PN_LOOKUP(drive, cmd, kw = "drive", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, NULL);

	mms_trace(MMS_DEBUG, "lm_unmount: Drive for unmount cmd - %s",
	    mms_pn_token(value));

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_unmount: lm_obtain_task_id failed "
		    "trying to generate show command for event");
		return (LM_ERROR);
	}
	(void) snprintf(cfg_str, sizeof (cfg_str), LM_SHOW_SERIAL, lmpl_tid,
	    mms_pn_token(value));

	mms_trace(MMS_DEBUG, "lm_unmount: drive show cmd:\n%s", cfg_str);

	if ((rc = lm_gen_lmpl_cmd(cfg_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_unmount: Internal processing error "
		    "encountered while processing LMPL show cmd");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR, "lm_unmount: show cmd did not receive "
		    "a successful response");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_unmount: show cmd got sucess final response");
	node = mms_list_head(&ele->lmpl_rsp_list);
	rsp = node->lmpl_rsp_tree;

	loc = NULL;
	if ((clause = mms_pn_lookup(rsp, "DriveSerialNum",
	    MMS_PN_STRING, &loc)) == NULL) {
		mms_trace(MMS_CRIT, "lm_unmount: No DriveSerialNum "
		    "attribute found in response to show cmd");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7032_MSG,
		    "cmd", "unmount", "drive", mms_pn_token(value), NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT, "lm_unmount: No DriveSerialNum value "
		    "found in response to show cmd");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7032_MSG,
		    "cmd", "unmount", "drive", mms_pn_token(value), NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_unmount: Drive %s has a serial number of %s",
	    mms_pn_token(value), mms_pn_token(attribute));

	loc = NULL;
	MMS_PN_LOOKUP(slot, cmd, kw = "fromslot", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(slot_name, slot, NULL, MMS_PN_STRING, &loc);
	mms_trace(MMS_DEBUG, "lm_unmount: From Slot for unmount cmd - %s",
	    mms_pn_token(slot_name));

	MMS_PN_LOOKUP(cartridge, slot, NULL, MMS_PN_STRING, &loc);
	mms_trace(MMS_DEBUG, "lm_unmount: From Cartridge PCL for cmd - %s",
	    mms_pn_token(cartridge));

	MMS_PN_LOOKUP(side, slot, NULL, MMS_PN_STRING, &loc);
	mms_trace(MMS_DEBUG, "lm_unmount: From Side for unmount cmd - %s",
	    mms_pn_token(side));

	loc = NULL;
	MMS_PN_LOOKUP(slot, cmd, kw = "toslot", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(slot_name, slot, NULL, MMS_PN_STRING, &loc);
	mms_trace(MMS_DEBUG, "lm_unmount: To Slot for unmount cmd - %s",
	    mms_pn_token(slot_name));

	MMS_PN_LOOKUP(cartridge, slot, NULL, MMS_PN_STRING, &loc);
	mms_trace(MMS_DEBUG, "lm_unmount: To Cartridge PCL for cmd - %s",
	    mms_pn_token(cartridge));

	MMS_PN_LOOKUP(side, slot, NULL, MMS_PN_STRING, &loc);
	mms_trace(MMS_DEBUG, "lm_unmount: To Side for unmount cmd - %s",
	    mms_pn_token(side));

	serial = strdup(mms_pn_token(attribute));

	if (lm_obtain_geometry(serial, &geometry, "unmount", tid, ret_msg)
	    != LM_OK) {
		mms_trace(MMS_ERR, "lm_mount: Trying to obtain geometry "
		    "for drive with serial number %s failed", serial);
			/* Error return message set in function */
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(serial);
		return (LM_ERROR);
	}
	if (strcmp(geometry, "") == 0) {
		mms_trace(MMS_ERR, "lm_mount: No geometry found for drive "
		    "with serial number of %s", serial);
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7126_MSG,
		    "name", mms_pn_token(value), "serial", serial, NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_DEVCMD), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(serial);
		free(geometry);
		return (LM_ERROR);
	}

	cptr = cptr1 = strdup(geometry);
	pptr = strstr(cptr, ",");
	*pptr = '\0';
	drive_id.panel_id.lsm_id.acs = atoi(cptr);
	cptr = pptr + 1;
	pptr = strstr(cptr, ",");
	*pptr = '\0';
	drive_id.panel_id.lsm_id.lsm = atoi(cptr);
	cptr = pptr + 1;
	pptr = strstr(cptr, ",");
	*pptr = '\0';
	drive_id.panel_id.panel = atoi(cptr);
	cptr = pptr + 1;
	drive_id.drive = atoi(cptr);
	free(cptr1);


	mms_trace(MMS_DEBUG, "lm_unmount: Drive geometry - %d,%d,%d,%d",
	    drive_id.panel_id.lsm_id.acs, drive_id.panel_id.lsm_id.lsm,
	    drive_id.panel_id.panel, drive_id.drive);

	(void) strncpy(vol_id.external_label, mms_pn_token(cartridge),
	    EXTERNAL_LABEL_SIZE);
	vol_id.external_label[EXTERNAL_LABEL_SIZE] = '\0';
	mms_trace(MMS_DEBUG, "lm_unmount: Volume to unmount %s",
	    vol_id.external_label);

	if ((lm_acs_dismount(&acs_rsp, vol_id, drive_id, "unmount", tid,
	    ret_msg)) == LM_ERROR) {
		free(serial);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(geometry);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_unmount: Received final response for "
	    "acs_dismount()");

	mp = (ACS_DISMOUNT_RESPONSE *)acs_rsp->acs_rbuf;
	if (mp->dismount_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_unmount: response from acs_dismount() "
		    "failed, status - %s",
		    acs_status(mp->dismount_status));
		lm_handle_dismount_error(mp->dismount_status,
		    mms_pn_token(value), mms_pn_token(attribute),
		    geometry,
		    mms_pn_token(cartridge), drive_id.panel_id.lsm_id.lsm,
		    drive_id.panel_id.panel, "unmount", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(acs_rsp);
		free(serial);
		free(geometry);
		return (LM_ERROR);
	}
	free(geometry);

	if (strcmp(mms_pn_token(cartridge), mp->vol_id.external_label) != 0) {
		mms_trace(MMS_OPER, "lm_unmount: While dismounting %s from "
		    "drive %s (geometry - %s), the acs_dismount() "
		    "shows that actually cartridge %s was unmounted from "
		    "the drive", mms_pn_token(cartridge),
		    mms_pn_token(value), mms_pn_token(attribute),
		    mp->vol_id.external_label);
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7223_MSG,
		    "wcart", mp->vol_id.external_label,
		    "drive", mms_pn_token(value),
		    "ecart", mms_pn_token(cartridge),
		    NULL);
		lm_message("operator", "alert", msg_str);
	}
		/* Clean up from drive show command */
	lm_remove_lmpl_cmd(lmpl_tid, ele);
	free(acs_rsp);

	i = 0;
unmount_retry:

	(void) strncpy(vol_id_list[0].external_label, mms_pn_token(cartridge),
	    EXTERNAL_LABEL_SIZE);
	vol_id_list[0].external_label[EXTERNAL_LABEL_SIZE] = '\0';
	if ((lm_acs_query_volume(&acs_rsp, vol_id_list, 1, "unmount", tid,
	    ret_msg)) == LM_ERROR)
		return (LM_ERROR);

	mms_trace(MMS_DEBUG, "lm_unmount: Recevied final response for "
	    "query_volume()");

	vol_qp = (ACS_QUERY_VOL_RESPONSE *)acs_rsp->acs_rbuf;
	if (vol_qp->query_vol_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_unmount: response from "
		    "query_volume() failed, status - %s",
		    acs_status(vol_qp->query_vol_status));
		lm_handle_query_vol_error(vol_qp->query_vol_status,
		    "unmount", tid, ret_msg);
		free(acs_rsp);
		free(serial);
		return (LM_ERROR);
	}
	vol_sp = &vol_qp->vol_status[0];
	if (vol_sp->status != STATUS_VOLUME_HOME) {
		if (vol_sp->status == STATUS_VOLUME_IN_TRANSIT) {
			mms_trace(MMS_DEBUG,
			    "lm_unmount: volume %s is in transit "
			    "retrying acs_query_volume()",
			    mms_pn_token(cartridge));
			free(acs_rsp);
			(void) sleep(2);
			if (i < 5) {
				i++;
				goto unmount_retry;
			}
			mms_trace(MMS_DEBUG,
			    "lm_unmount: volume %s seems to be "
			    "stuck in transit sending back error "
			    "response");
		}
		mms_trace(MMS_ERR, "lm_unmount: volume %s not found in cell, "
		    "status is %s", mms_pn_token(cartridge),
		    acs_status(vol_sp->status));
		lm_handle_acsls_error(vol_sp->status, "acs_query_vol",
		    "unmount", tid, ret_msg);
		free(acs_rsp);
		free(serial);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG,
	    "lm_unmount: vol %s is now in location %d,%d,%d,%d,%d "
	    "after unmount", vol_sp->vol_id.external_label,
	    vol_sp->location.cell_id.panel_id.lsm_id.acs,
	    vol_sp->location.cell_id.panel_id.lsm_id.lsm,
	    vol_sp->location.cell_id.panel_id.panel,
	    vol_sp->location.cell_id.row,
	    vol_sp->location.cell_id.col);

	panel = vol_sp->location.cell_id.panel_id.panel;

	free(acs_rsp);

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT,
		    "lm_unmount: lm_obtain_task_id failed trying "
		    "to generate config command for unmount");
		free(serial);
		return (LM_ERROR);
	}

	(void) snprintf(cfg_str, sizeof (cfg_str), CONFIG_UNMOUNT, lmpl_tid,
	    mms_pn_token(cartridge), panel, panel, mms_pn_token(cartridge),
	    lm.lm_type, serial, drive_id.panel_id.lsm_id.acs,
	    drive_id.panel_id.lsm_id.lsm, drive_id.panel_id.panel,
	    drive_id.drive, drive_id.panel_id.panel);

	mms_trace(MMS_DEBUG, "lm_unmount: config for unmount:\n%s", cfg_str);
	free(serial);

	if ((rc = lm_gen_lmpl_cmd(cfg_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_unmount: Internal processing error "
		    "encountered while processing lmpl config command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		if ((lm_acs_mount(&acs_rsp, vol_id, drive_id, "unmount",
		    tid, ret_msg)) == LM_ERROR)
			mms_trace(MMS_ERR, "lm_unmount: Unable to mount "
			    "cartridge %s after unmount's config failed",
			    mms_pn_token(cartridge));
		else {
			mms_trace(MMS_ERR, "lm_unmount: Mounted cartridge %s "
			    "due to unmount's config failure",
			    mms_pn_token(cartridge));
			free(acs_rsp);
		}
		handle_lmpl_cmd_error(rc, "unmount", "config", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_unmount: Got successful response for unmount "
	    "config command");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7103_MSG,
	    "cart", mms_pn_token(cartridge), "drive", mms_pn_token(value),
	    NULL);
	(void) snprintf(text_str, sizeof (text_str), LM_TEXT_MNT,
	    mms_pn_token(value), mms_pn_token(slot_name),
	    mms_pn_token(cartridge), mms_pn_token(side));
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, text_str,
	    msg_str);

	lm_remove_lmpl_cmd(lmpl_tid, ele);
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "LMPM command %s encounterd an invalid or missing "
	    "%s clause:\n%s", "unmount", kw, mms_pn_build_cmd_text(cmd));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "unmount", "part", kw, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}

int
/* LINTED argument unused in function */
lm_move(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char    msg_str[256];

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7105_MSG, "cmd", "move", "type", lm.lm_type, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");
	return (LM_OK);
}

int
lm_inject(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int		i;
	int		j;
	int		rc;
	int		lmpl_tid;
	int		slot_spec_size;

	char		*kw;
	char		*slot_spec;
	char    	msg_str[256];
	char    	text_str[256];
	char		cfg_str[1024];
	char		carts[2048];
	char		err_carts[2048];
	char		text_cart[12];
	char		text_carts[2048];

	CAPID			cap_id;
	ACS_ENTER_RESPONSE 	*ep;
	ACS_QUERY_VOL_RESPONSE	*vol_qp;
	QU_VOL_STATUS		*vol_sp;
	VOLID			*vol_id;
	VOLID			vol_id_list[MAX_ID];

	mms_par_node_t	*sltgrp;
	mms_par_node_t	*value;
	acs_rsp_ele_t	*acs_rsp;
	lmpl_rsp_ele_t	*ele;

	acs_cap_t	*acs_cap;

			/* Create default final error response due to */
			/* internal processing error */
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "inject", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	carts[0] = '\0';

			/* Obtain slotgroup (Name of cap to use) */
	MMS_PN_LOOKUP(sltgrp, cmd, kw = "slotgroup", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, sltgrp, NULL, MMS_PN_STRING, NULL);

	cap_id.lsm_id.acs = lm.lm_acs;
			/* If more than one lsm can exist within the acs, */
			/* the lsm will need to be determined */
	cap_id.lsm_id.lsm = lm.lm_lsm;

	acs_cap = (acs_cap_t *)lm.lm_port;
	for (i = 0; i < lm.lm_caps; i++) {
		if (strcmp(acs_cap->cap_name, mms_pn_token(value)) == 0) {
			mms_trace(MMS_DEBUG, "Physical cap associated with "
			    "slotgroup %s found", acs_cap->cap_name);
				/* Make sure that the cap actually exists in */
				/* the library, some libraries have optional */
				/* caps */
			if (!acs_cap->cap_config) {
				mms_trace(MMS_ERR,
				    "Physcial cap associated with "
				    "slotgroup %s is not available in"
				    "the library - %s", acs_cap->cap_name);
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7108_MSG, "port", mms_pn_token(value),
				    NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_INVALID),
				    mms_sym_code_to_str(MMS_LM_E_PORT),
				    msg_str);
				return (LM_ERROR);
			}
			break;
		}
	}
	if (i == lm.lm_caps) {
		mms_trace(MMS_ERR, "lm_inject: Did not find a physical cap "
		    "associated with slotgroup - %s",
		    mms_pn_token(value));
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7117_MSG,
		    "port", mms_pn_token(value), NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INVALID),
		    mms_sym_code_to_str(MMS_LM_E_PORT), msg_str);
		return (LM_ERROR);
	}

	cap_id.cap = acs_cap->cap_capid;

	mms_trace(MMS_DEBUG, "lm_inject: Cap group name for inject - %s, %d",
	    acs_cap->cap_name, acs_cap->cap_capid);

	if ((lm_acs_enter(&acs_rsp, cap_id, "inject", tid, ret_msg)) ==
	    LM_ERROR) {
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG,
	    "lm_inject: Received final response for acs_enter()");

	ep = (ACS_ENTER_RESPONSE *)acs_rsp->acs_rbuf;
	if (ep->enter_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_inject: response for acs_enter() failed, "
		    "status - %s", acs_status(ep->enter_status));
		lm_handle_enter_error(ep->enter_status, acs_cap->cap_name,
		    cap_id.lsm_id.lsm, "inject", tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

			/* Check status of each cartridge that was in the cap */
	j = 0;
	for (i = 0; i < (int)ep->count; i++) {
		vol_id = &ep->vol_id[i];
		if (ep->vol_status[i] != STATUS_SUCCESS) {
			mms_trace(MMS_OPER, "lm_inject: volume %s failed "
			    "enter with status - %s", vol_id->external_label,
			    acs_status(ep->vol_status[i]));
			(void) strcat(err_carts, vol_id->external_label);
			(void) strcat(err_carts, " ");
			continue;
		}
		mms_trace(MMS_OPER, "lm_inject: volume %s entered into "
		    "library", vol_id->external_label);
		(void) strncpy(vol_id_list[j].external_label,
		    vol_id->external_label, EXTERNAL_LABEL_SIZE);
		vol_id_list[j++].external_label[EXTERNAL_LABEL_SIZE] = '\0';
	}

			/* There were cartridges in CAP, but none were */
			/* successfully injected into the library */
	if (j == 0 && ep->count != 0) {
		mms_trace(MMS_OPER,
		    "lm_inject: Cartridges %s were not injected "
		    "into library");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7109_MSG,
		    NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_DEVINJ), msg_str);
		free(acs_rsp);
		return (LM_ERROR);
	}

			/* Some of the cartridges in the CAP did not get */
			/* injected */
	if (j != ep->count) {
		err_carts[strlen(err_carts)-1] = '\0';
		mms_trace(MMS_OPER, "lm_inject: Send LMPL message to indicate "
		    "not all cartridges were injected into the library");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7110_MSG,
		    "cart", err_carts, NULL);
			/* Ignore return value from lm_message */
		lm_message("operator", "notice", msg_str);
	}

	free(acs_rsp);

			/* Determine if any cartridges were added to the cap */
	if (j != 0) {
		slot_spec_size = 100 * j;
		if ((slot_spec = (char *)malloc(slot_spec_size)) == NULL) {
			lm_serr(MMS_CRIT, "lm_inject: Unable to malloc space "
			    "for slot spec definitions");
			return (LM_ERROR);
		}

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_inject: lm_obtain_task_id failed "
			    "trying to generate config cmd for slot creation");
			return (LM_ERROR);
		}

		(void) snprintf(slot_spec, slot_spec_size,
		    "config task[\"%d\"] scope[partial] ",
		    lmpl_tid);

		if ((lm_acs_query_volume(&acs_rsp, vol_id_list, j, "inject",
		    tid, ret_msg)) == LM_ERROR) {
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		err_carts[0] = '\0';
		text_carts[0] = '\0';

		vol_qp = (ACS_QUERY_VOL_RESPONSE *)acs_rsp->acs_rbuf;
		if (vol_qp->query_vol_status != STATUS_SUCCESS) {
			mms_trace(MMS_ERR, "lm_inject: response from "
			    "query_volume() failed, status - %s",
			    acs_status(vol_qp->query_vol_status));
			lm_handle_query_vol_error(vol_qp->query_vol_status,
			    "inject", tid, ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(acs_rsp);
			return (LM_ERROR);
		}
		if (vol_qp->count != j) {
			mms_trace(MMS_ERR, "lm_inject: count of response for "
			    "query_volume() - %d does not equal number of "
			    "cartridges injected - %d", vol_qp->count, j);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(acs_rsp);
			return (LM_ERROR);
		}
		for (i = 0; i < (int)vol_qp->count; i++) {
			vol_sp = &vol_qp->vol_status[i];
			if (vol_sp->location_type != LOCATION_CELL) {
				mms_trace(MMS_ERR, "lm_inject: volume "
				    "%s not found in slot",
				    &vol_sp->vol_id.external_label[0]);
				(void) strcat(err_carts,
				    vol_sp->vol_id.external_label);
				(void) strcat(err_carts, " ");
				continue;
			}

			(void) snprintf(cfg_str, sizeof (cfg_str), CFG_SLOT,
			    vol_sp->vol_id.external_label,
			    vol_sp->location.cell_id.panel_id.panel,
			    vol_sp->location.cell_id.panel_id.panel,
			    vol_sp->vol_id.external_label,
			    lm.lm_type);
			mms_trace(MMS_DEBUG,
			    "lm_inject: Slot spec - %s", cfg_str);
			(void) strcat(slot_spec, cfg_str);
			(void) strcat(carts, vol_sp->vol_id.external_label);
			(void) strcat(carts, " ");
			(void) snprintf(text_cart, sizeof (text_cart),
			    TEXT_CART, vol_sp->vol_id.external_label);
			(void) strcat(text_carts, text_cart);
		}

		free(acs_rsp);

		(void) strcat(slot_spec, ";");

		mms_trace(MMS_DEBUG, "lm_inject: SLOT_SPEC:\n%s", slot_spec);
		if ((rc = lm_gen_lmpl_cmd(slot_spec, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR,
			    "lm_inject: Internal processing error "
			    "encountered while processing lmpl config command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			handle_lmpl_cmd_error(rc, "inject", "config", tid,
			    ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		if (err_carts[0] != '\0') {
			err_carts[strlen(err_carts)-1] = '\0';
				/* Some cartridges that were successfully */
				/* injected into library could not be found */
				/* in a slot of the library */
			mms_trace(MMS_OPER, "Cartridges %s were injected into "
			    "library, but were not found in a slot of the "
			    "library", err_carts);
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7111_MSG, "cart", err_carts, NULL);
			lm_message("operator", "notice", msg_str);
		}

		mms_trace(MMS_DEBUG, "lm_inject: Got successful response for "
		    "slot creation config command");

		free(slot_spec);
		lm_remove_lmpl_cmd(lmpl_tid, ele);

		carts[strlen(carts)-1] = '\0';
		if (text_carts[0] != '\0') {
			text_carts[strlen(text_carts)-1] = '\0';
			(void) snprintf(text_str, sizeof (text_str),
			    LM_TEXT_CLS, text_carts);
		} else {
			text_str[0] = '\0';
		}
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7106_MSG,
		    "cart", carts, NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, text_str,
		    msg_str);

	} else {
		mms_trace(MMS_OPER,
		    "CAP was empty, No cartridges injected into library");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7112_MSG,
		    NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid,
		    msg_str, "");
	}

	mms_trace(MMS_DEVP, "Exiting lm_inject");
	return (LM_OK);


not_found:
	mms_trace(MMS_ERR, "lm_inject: LMPM command %s encounterd an invalid "
	    "or missing %s clause:\n%s", "inject", kw,
	    mms_pn_build_cmd_text(cmd));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "inject", "part", kw, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}

int
lm_scan(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	i, j;
	int	rc;
	int	lmpl_tid;
	int	accessible = 0;
	int	occupied = 0;
	int	slot_spec_size;
	int	drive_spec_size;

	char	*kw = NULL;
	char	*slot_spec = NULL;
	char	*drive_spec = NULL;
	const	char *spec_form = NULL;
	char	*cptr = NULL;
	char	*pptr = NULL;
	char	*serial = NULL;
	char	carts[2048];
	char	err_carts[2048];
	char    msg_str[256];
	char	cfg_str[1024];
	char	cmd_str[1024];
	char	geometry[128];
	char	*err_buf = NULL;

	lmpl_rsp_ele_t	*ele = NULL;
	lmpl_rsp_node_t	*node = NULL;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*loc1 = NULL;
	mms_par_node_t	*slot = NULL;
	mms_par_node_t	*fslot = NULL;
	mms_par_node_t	*tslot = NULL;
	mms_par_node_t	*dname = NULL;
	mms_par_node_t	*rsp = NULL;
	mms_par_node_t	*clause = NULL;
	mms_par_node_t	*attribute = NULL;

	VOLID			vol_id_list[MAX_ID];
	ACS_QUERY_VOL_RESPONSE	*vol_qp = NULL;
	QU_VOL_STATUS		*vol_sp = NULL;
	ACS_QUERY_DRV_RESPONSE	*drv_qp = NULL;
	QU_DRV_STATUS		*drv_sp = NULL;
	DRIVEID			drive_id[MAX_ID];

	acs_rsp_ele_t	*acs_rsp = NULL;

	mms_trace(MMS_DEVP, "Entering lm_scan");

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "scan", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

	loc = NULL;
			/* See if scan is for cartridge(s) */
	if ((clause = mms_pn_lookup(cmd, kw = "slot", MMS_PN_CLAUSE, &loc))
	    != NULL) {
			/* Generate list of cartridges to scan for */
		for (i = 0; clause != NULL; clause = mms_pn_lookup(cmd,
		    "slot", MMS_PN_CLAUSE, &loc)) {
				/* Obtain slot-name */
			MMS_PN_LOOKUP(slot, clause, NULL, MMS_PN_STRING,
			    NULL);
			if (i == MAX_ID) {
				mms_trace(MMS_OPER,
				    "lm_scan: Number of slots to "
				    "scan exceeded the max of %d, skipping "
				    "cartridge %s", MAX_ID,
				    mms_pn_token(slot));
			} else {
				mms_trace(MMS_DEBUG,
				    "lm_scan: scan for cartridge "
				    "%s", mms_pn_token(slot));

				(void) strncpy(vol_id_list[i].external_label,
				    mms_pn_token(slot),
				    EXTERNAL_LABEL_SIZE);
				vol_id_list[i++].external_label[
				    EXTERNAL_LABEL_SIZE] = '\0';
			}
		}

				/* Query for cartridges in library */
		if ((lm_acs_query_volume(&acs_rsp, vol_id_list, i, "scan",
		    tid, ret_msg)) == LM_ERROR)
			return (LM_ERROR);

		mms_trace(MMS_DEBUG,
		    "lm_scan: Recevied sucess final response for "
		    "query_volume()");

		vol_qp = (ACS_QUERY_VOL_RESPONSE *)acs_rsp->acs_rbuf;
		if (vol_qp->query_vol_status != STATUS_SUCCESS) {
			mms_trace(MMS_ERR, "lm_scan: response from "
			    "query_volume() failed, status - %s",
			    acs_status(vol_qp->query_vol_status));
			lm_handle_query_vol_error(vol_qp->query_vol_status,
			    "scan", tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		slot_spec_size = 100 * i;
		if ((slot_spec = (char *)malloc(100 * i)) == NULL) {
			lm_serr(MMS_CRIT, "lm_scan: Unable to malloc space "
			    "for slot spec definitions");
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT, "lm_scan: lm_obtain_task_id failed "
			    "trying to generate config command for scan");
			free(acs_rsp);
			free(slot_spec);
			return (LM_ERROR);
		}

			/* Setup to send partial config for any cartridges */
			/* found in a cell of the library */
		(void) snprintf(slot_spec, slot_spec_size,
		    "config task[\"%d\"] scope[partial] ",
		    lmpl_tid);

		carts[0] = '\0';
		err_carts[0] = '\0';

			/* Check each cartridge to see if it is in a cell */
			/* of the library, only those in a cell can be */
			/* configed */
		for (j = 0; j < (int)vol_qp->count; j++) {
			vol_sp = &vol_qp->vol_status[j];
			if (vol_sp->location_type != LOCATION_CELL) {
				mms_trace(MMS_ERR, "lm_scan: cartridge %s not "
				    "found in a cell, status - %s",
				    vol_sp->vol_id.external_label,
				    acs_status(vol_sp->status));
				(void) strcat(err_carts,
				    vol_sp->vol_id.external_label);
				(void) strcat(err_carts, " ");
				continue;
			}
			(void) snprintf(cfg_str, sizeof (cfg_str), CFG_SLOT,
			    vol_sp->vol_id.external_label,
			    vol_sp->location.cell_id.panel_id.panel,
			    vol_sp->location.cell_id.panel_id.panel,
			    vol_sp->vol_id.external_label,
			    lm.lm_type);
			mms_trace(MMS_DEBUG,
			    "lm_scan: Slot spec - %s", cfg_str);
			(void) strcat(slot_spec, cfg_str);
			(void) strcat(carts, vol_sp->vol_id.external_label);
			(void) strcat(carts, " ");
		}

		free(acs_rsp);
				/* Send LMPL config command to define */
				/* any cartridges that were found in */
				/* slots of the library */
		if (carts[0] != '\0') {
			(void) strcat(slot_spec, ";");
			mms_trace(MMS_DEBUG,
			    "lm_scan: SLOT_SPEC:\n%s", slot_spec);
				/* Send LMPL config command for cartridge(s) */
				/* found in a cell of the library */
			if ((rc = lm_gen_lmpl_cmd(slot_spec, ele, 0))
			    == LM_ERROR) {
				mms_trace(MMS_ERR,
				    "lm_scan: Internal processing "
				    "error encountered while processing lmpl "
				    "config command");
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(slot_spec);
				return (LM_ERROR);
			} else if (rc != LMPL_FINAL_OK) {
				mms_trace(MMS_ERR, "lm_scan: Did not receive a "
				    "success response for lmpl config command "
				    "while processing scan command");
				handle_lmpl_cmd_error(rc, "scan", "config", tid,
				    ret_msg);
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(slot_spec);
				return (LM_ERROR);
			}

			mms_trace(MMS_DEBUG, "lm_scan: Got successful response "
			    "for scan config command");

			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7118_MSG, "carts", carts, NULL);
		} else {
				/* Since no config was sent clean up */
				/* for the taskid that was not used */
			mms_trace(MMS_DEBUG,
			    "lm_scan: No cartridges were found "
			    "in slots of the library");
			if ((rc = pthread_mutex_unlock(&lm_acc_mutex)) != 0)
				mms_trace(MMS_CRIT, "lm_scan: Unlock of "
				    "accept/unaccept mutex failed with errno "
				    "- %s", strerror(errno));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7120_MSG, NULL);
		}
		lm_remove_lmpl_cmd(lmpl_tid, ele);

		if (err_carts[0] != '\0') {
			err_carts[strlen(err_carts)-1] = '\0';
			mms_trace(MMS_OPER, "lm_scan: Send LMPL message to "
			    "indicate not all cartridges were found to "
			    "be present in the library, %s", err_carts);
			(void) mms_buf_msgcl(cfg_str, sizeof (cfg_str),
			    LM_7119_MSG, "carts", err_carts, NULL);
			lm_message("operator", "notice", cfg_str);
		}
		free(slot_spec);
	}

	else if ((clause = mms_pn_lookup(cmd, kw = "fromslot",
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
		    "supported on a ACSLS controlled library, sending error "
		    "response for scan command");

		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7116_MSG,
		    "type", lm.lm_type, NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);
		return (LM_ERROR);

	} else  if ((clause = mms_pn_lookup(cmd, kw = "drive",
	    MMS_PN_CLAUSE, &loc1)) != NULL) {
		for (i = 0; clause != NULL; clause = mms_pn_lookup(cmd,
		    "drive", MMS_PN_CLAUSE, &loc1)) {
			MMS_PN_LOOKUP(dname, clause, NULL, MMS_PN_STRING,
			    NULL);
			mms_trace(MMS_DEBUG, "lm_scan: scan for drive %s",
			    mms_pn_token(dname));

			if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
				mms_trace(MMS_CRIT,
				    "lm_scan: lm_obtain_task_id "
				    "failed trying to generate show command "
				    "for scan");
				return (LM_ERROR);
			}
			(void) snprintf(cmd_str, sizeof (cmd_str),
			    LM_SHOW_DRIVE, lmpl_tid, mms_pn_token(dname));

			mms_trace(MMS_DEBUG,
			    "lm_scan: show cmd for scan drive:\n%s", cmd_str);
			if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) ==
			    LM_ERROR) {
				mms_trace(MMS_ERR,
				    "lm_scan: Internal processing "
				    "error encountered while processing LMPL "
				    "show cmd");
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				return (LM_ERROR);
			} else if (rc != LMPL_FINAL_OK) {
				mms_trace(MMS_ERR, "lm_scan: show cmd did not "
				    "receive a successful response, unable "
				    "to get drive %s's geometry",
				    mms_pn_token(dname));
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				continue;
			}
			mms_trace(MMS_DEBUG,
			    "lm_scan: show cmd got sucess final response");
			node = mms_list_head(&ele->lmpl_rsp_list);
			rsp = node->lmpl_rsp_tree;

			loc = NULL;
			if ((clause = mms_pn_lookup(rsp, "DriveGeometry",
			    MMS_PN_STRING, &loc)) == NULL) {
				mms_trace(MMS_CRIT, "lm_scan: No DriveGeometry "
				    "attribute found in response to show cmd "
				    "for drive %s", mms_pn_token(dname));
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				continue;
			}

			if ((attribute = mms_pn_lookup(clause, NULL,
			    MMS_PN_STRING, &loc)) == NULL) {
				mms_trace(MMS_ERR,
				    "lm_scan: No DriveGeometry value"
				    " found in response to show cmd for drive "
				    "%s", mms_pn_token(dname));
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				continue;
			}
			/* Pull apart geometry string for DRIVEID */
			/* structure used in query_drive */

			/* Set err_buf for drive geometry */
			err_buf = mms_strapp(err_buf,
			    mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7235_MSG, "drive", mms_pn_token(dname),
			    NULL));

			if ((cptr = mms_pn_token(attribute)) == NULL) {
				mms_trace(MMS_ERR,
				    "lm_scan: missing drive geometry for"
				    "drive %s");
				(void)
				    lm_set_drive_disabled(mms_pn_token(dname),
				    "temporary");
				lm_message("operator", "error",
				    err_buf);
				free(err_buf);
				return (LM_ERROR);
			}
			mms_trace(MMS_DEBUG,
			    "lm_scan:, Drive %s has a geometry of "
			    "%s", mms_pn_token(dname),
			    cptr);

			if ((pptr = strstr(cptr, ",")) == NULL) {
				mms_trace(MMS_ERR,
				    "lm_scan: missing/incomplete"
				    " drive geometry for"
				    "drive %s, geometry = %s",
				    mms_pn_token(dname),
				    cptr);
				lm_set_drive_disabled(mms_pn_token(dname),
				    "temporary");
				lm_message("operator", "error",
				    err_buf);
				free(err_buf);
				return (LM_ERROR);
			}
			*pptr = '\0';
			drive_id[i].panel_id.lsm_id.acs = atoi(cptr);
			cptr = pptr + 1;
			if ((pptr = strstr(cptr, ",")) == NULL) {
				mms_trace(MMS_ERR,
				    "lm_scan: missing/incomplete"
				    " drive geometry for"
				    "drive %s, geometry = %s",
				    mms_pn_token(dname),
				    cptr);
				lm_set_drive_disabled(mms_pn_token(dname),
				    "temporary");
				lm_message("operator", "error",
				    err_buf);
				free(err_buf);
				return (LM_ERROR);
			}
			*pptr = '\0';
			drive_id[i].panel_id.lsm_id.lsm = atoi(cptr);
			cptr = pptr + 1;
			if ((pptr = strstr(cptr, ",")) == NULL) {
				lm_serr(MMS_CRIT,
				    "lm_scan: missing/incomplete"
				    " drive geometry for"
				    "drive %s, geometry = %s",
				    mms_pn_token(dname),
				    cptr);
				lm_set_drive_disabled(mms_pn_token(dname),
				    "temporary");
				lm_message("operator", "error",
				    err_buf);
				free(err_buf);
				return (LM_ERROR);
			}
			*pptr = '\0';
			drive_id[i].panel_id.panel = atoi(cptr);
			cptr = pptr + 1;
			drive_id[i].drive = atoi(cptr);
			/* free the err_buf for drive geometry */
			free(err_buf);
			err_buf = NULL;


			mms_trace(MMS_DEBUG, "lm_scan: Drive %s query_drive(), "
			    "%d,%d,%d,%d", mms_pn_token(dname),
			    drive_id[i].panel_id.lsm_id.acs,
			    drive_id[i].panel_id.lsm_id.lsm,
			    drive_id[i].panel_id.panel,
			    drive_id[i].drive);

			lm_remove_lmpl_cmd(lmpl_tid, ele);
			if (++i == MAX_ID) {
				mms_trace(MMS_OPER,
				    "lm_scan: Number of drives to "
				    "scan exceeded the max allowed of %d",
				    MAX_ID);
				break;
			}
		}

				/* Query for drives in library */
		if ((lm_acs_query_drive(&acs_rsp, drive_id, i, "scan", tid,
		    ret_msg)) == LM_ERROR)
			return (LM_ERROR);

		mms_trace(MMS_DEBUG, "lm_scan: Received final response for "
		    "query_drive");

		drv_qp = (ACS_QUERY_DRV_RESPONSE *)acs_rsp->acs_rbuf;
		if (drv_qp->query_drv_status != STATUS_SUCCESS) {
			mms_trace(MMS_ERR, "lm_scan: final response from "
			    "query_drive() failed, status - %s",
			    acs_status(drv_qp->query_drv_status));
			lm_handle_acsls_error(drv_qp->query_drv_status,
			    "acs_query_drive", "scan", tid, ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		drive_spec_size = 100 * i;
		if ((drive_spec = (char *)malloc(drive_spec_size)) == NULL) {
			lm_serr(MMS_CRIT, "lm_scan: Unable to malloc space "
			    "for drive spec definitions");
			return (LM_ERROR);
		}


			/* Setup to send partial config for any drives */
			/* found in library */
		(void) strcpy(drive_spec,
		    "config task[\"%d\"] scope[partial] ");

		carts[0] = '\0';
		err_carts[0] = '\0';
			/* Check each drive to see if it is found in */
			/* the library, also verify if is online and if */
			/* a cartridge exists in the drive */
		for (j = 0; j < (int)drv_qp->count; j++) {
			drv_sp = &drv_qp->drv_status[j];
			if (drv_sp->status == STATUS_DRIVE_IN_USE)
				occupied = 1;
			else if (drv_sp->status == STATUS_DRIVE_AVAILABLE)
				occupied = 0;
			else {
				mms_trace(MMS_ERR, "lm_scan: drive %d,%d,%d,%d "
				    "failed query_drive with a status - %s",
				    drv_sp->drive_id.panel_id.lsm_id.acs,
				    drv_sp->drive_id.panel_id.lsm_id.lsm,
				    drv_sp->drive_id.panel_id.panel,
				    drv_sp->drive_id.drive,
				    acs_status(drv_sp->status));
				(void) snprintf(cmd_str, sizeof (cmd_str),
				    "%d,%d,%d,%d",
				    drv_sp->drive_id.panel_id.lsm_id.acs,
				    drv_sp->drive_id.panel_id.lsm_id.lsm,
				    drv_sp->drive_id.panel_id.panel,
				    drv_sp->drive_id.drive);
				(void) strcat(err_carts, cmd_str);
				(void) strcat(err_carts, " ");
				continue;
			}
			if (drv_sp->state == STATE_ONLINE)
				accessible = 1;

			(void) snprintf(geometry, sizeof (geometry),
			    "%d,%d,%d,%d",
			    drv_sp->drive_id.panel_id.lsm_id.acs,
			    drv_sp->drive_id.panel_id.lsm_id.lsm,
			    drv_sp->drive_id.panel_id.panel,
			    drv_sp->drive_id.drive);
			if (lm_obtain_serial_num(geometry, &serial,
			    "scan", tid, ret_msg) != LM_OK) {
				mms_trace(MMS_ERR, "lm_scan: "
				    "Trying to obtain serial number "
				    "for drive with ACSLS geometry %s "
				    "failed", geometry);
				return (LM_ERROR);
			}
			if (strcmp(serial, "") == 0) {
				mms_trace(MMS_ERR, "lm_library_config: "
				    "No serial number found for drive "
				    "with ACSLS geometry of %s",
				    geometry);
			}
			(void) snprintf(cfg_str, sizeof (cfg_str), CFG_DRIVE,
			    serial,
			    drv_sp->drive_id.panel_id.lsm_id.acs,
			    drv_sp->drive_id.panel_id.lsm_id.lsm,
			    drv_sp->drive_id.panel_id.panel,
			    drv_sp->drive_id.drive,
			    drv_sp->drive_id.panel_id.panel,
			    occupied ? drv_sp->vol_id.external_label : "none",
			    occupied ? "true" : "false",
			    accessible ? "true" : "false");

			mms_trace(MMS_DEBUG,
			    "lm_scan: Drive Spec - %s", cfg_str);
			(void) strcat(drive_spec, cfg_str);
			(void) snprintf(cmd_str, sizeof (cmd_str),
			    "%d,%d,%d,%d",
			    drv_sp->drive_id.panel_id.lsm_id.acs,
			    drv_sp->drive_id.panel_id.lsm_id.lsm,
			    drv_sp->drive_id.panel_id.panel,
			    drv_sp->drive_id.drive);
			(void) strcat(carts, cmd_str);
			(void) strcat(carts, " ");
			accessible = 0;
			if ((lm_drive_serial_num(cmd_str, tid, ret_msg))
			    != LM_OK) {
				mms_trace(MMS_ERR,
				    "lm_scan: Unable to get serial "
				    "number for drive %s", cmd_str);
				free(drive_spec);
				free(acs_rsp);
				return (LM_ERROR);
			}
		}
		free(acs_rsp);

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT, "lm_scan: lm_obtain_task_id failed "
			    "trying to generate config command for scan");
			free(acs_rsp);
			free(drive_spec);
			return (LM_ERROR);
		}

		spec_form = strdup(drive_spec);
		(void) snprintf(drive_spec,
		    drive_spec_size,
		    spec_form,
		    lmpl_tid);
		free((char *)spec_form);

				/* Send LMPL config command to define */
				/* any drives that were found in library */
		if (carts[0] != '\0') {
			(void) strcat(drive_spec, ";");
			mms_trace(MMS_DEBUG,
			    "lm_scan: DRIVE_SPEC:\n%s", drive_spec);

			if ((rc = lm_gen_lmpl_cmd(drive_spec, ele, 0))
			    == LM_ERROR) {
				mms_trace(MMS_ERR,
				    "lm_scan: Internal processing "
				    "error encountered while processing lmpl "
				    "config cmd");
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(drive_spec);
				return (LM_ERROR);
			} else if (rc != LMPL_FINAL_OK) {
				mms_trace(MMS_ERR, "lm_scan: Did not receive a "
				    "success response for lmpl config command "
				    "while processing scan command");
				handle_lmpl_cmd_error(rc, "scan", "config", tid,
				    ret_msg);
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(drive_spec);
				return (LM_ERROR);
			}

			mms_trace(MMS_DEBUG, "lm_scan: Got successful response "
			    "for scan config drive command");

			carts[strlen(err_carts)-1] = '\0';
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7121_MSG, "geom", carts, NULL);
		} else {
				/* Since no config was sent clean up */
				/* for the taskid that was not used */
			mms_trace(MMS_DEBUG, "lm_scan: No drives were found in "
			    "in library");
			if ((rc = pthread_mutex_unlock(&lm_acc_mutex)) != 0)
				mms_trace(MMS_CRIT, "lm_scan: Unlock of "
				    "accept/unaccept mutex failed with errno "
				    "- %s", strerror(errno));
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7122_MSG, NULL);
		}
		lm_remove_lmpl_cmd(lmpl_tid, ele);

		if (err_carts[0] != '\0') {
			err_carts[strlen(err_carts)-1] = '\0';
			mms_trace(MMS_OPER, "lm_scan: Send LMPL message to "
			    "indicate not all drives were found to be "
			    "present in the library, %s", err_carts);
			(void) mms_buf_msgcl(cfg_str, sizeof (cfg_str),
			    LM_7123_MSG, "geom", err_carts, NULL);
			lm_message("operator", "notice", cfg_str);
		}
		free(drive_spec);

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
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7124_MSG,
		    NULL);
	}

	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");
	mms_trace(MMS_DEVP, "Exiting lm_scan");
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "LMPM command %s encountered an invalid or missing "
	    "%s clause:\n%s", "scan", kw, mms_pn_build_cmd_text(cmd));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "scan", "part", kw, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}
/*
 * lm_activate()()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM activate command being processed.
 *	- tid		Task id of LMPM activate command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the activate command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are ACSLS library specific
 * for the LM to process the activate command. This routine is responsible
 * for establishing the connection to the ACSLS SSI process and doing
 * the entire library configuration portion during an LM activation.
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

	int 	rc;
	int 	pkt_ver;
	int		lmpl_tid;

	char		cmd_str[512];
	char		msg_str[256];
	char		env_ssi_port[128];

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*pri_rsp;
	mms_par_node_t	*clause;
	mms_par_node_t	*attribute;

	STATUS		status;
	SEQ_NO		s;

	acs_rsp_ele_t	*acs_rsp;
	lmpl_rsp_ele_t	*ele;
	lmpl_rsp_node_t	*node;

	mms_trace(MMS_DEVP, "Entering ACSLS %s lm_activate", lm.lm_type);


	if ((rc = lm_acs_init()) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_activate: lm_acs_init failed");
		return (LM_ERROR);
	}

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_activate: Unable to get a task id "
		    "for private command to obtain libraries ACS number");
		return (LM_ERROR);
	}

	(void) snprintf(cmd_str, sizeof (cmd_str), PRIVATE_CMD, lmpl_tid,
	    PRI_GET_ACSLS);

	mms_trace(MMS_DEBUG,
	    "lm_activate: Obtain library acs cmd - \n%s", cmd_str);

	if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_activate: Internal "
		    "processing error encountered while processing "
		    "private command to obtain library acs");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_CRIT,
		    "lm_activate: Error encountered while sending "
		    "private command to obtain library acs");
		handle_lmpl_cmd_error(rc, "activate", "private",
		    tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	node = mms_list_head(&ele->lmpl_rsp_list);
	pri_rsp = node->lmpl_rsp_tree;

	mms_trace(MMS_DEBUG,
	    "lm_activate: Private cmd got success final response");


	if ((clause = mms_pn_lookup(pri_rsp, "text", MMS_PN_CLAUSE, NULL))
	    == NULL) {
		mms_trace(MMS_CRIT,
		    "lm_activate: No text clause found in finial "
		    "success response of private command to obtain library "
		    "ACS");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if ((attribute = mms_pn_lookup(clause, "LibraryACS", MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT,
		    "lm_activate: No ACS attribute found in final "
		    "success response of private command to obtain library "
		    "ACS");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7018_MSG, "object", "LibraryACS", NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_STATE),
		    mms_sym_code_to_str(MMS_LM_E_CONFIG), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT, "lm_activate: No ACS value found in final "
		    "response of private command to obtain library ACS");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7018_MSG, "object", "LibraryACS", NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_STATE),
		    mms_sym_code_to_str(MMS_LM_E_CONFIG), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	lm.lm_acs = atoi(mms_pn_token(attribute));

	/* Set LibraryLSM */
	if ((attribute = mms_pn_lookup(clause, "LibraryLSM", MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT,
		    "lm_activate: No LSM attribute found in final "
		    "success response of private command to obtain library "
		    "ACS/LSM");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7018_MSG, "object", "LibraryLSM", NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_STATE),
		    mms_sym_code_to_str(MMS_LM_E_CONFIG), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT, "lm_activate: No LSM value found in final "
		    "response of private command to obtain library LSM");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7018_MSG, "object", "LibraryLSM", NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_STATE),
		    mms_sym_code_to_str(MMS_LM_E_CONFIG), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	lm.lm_lsm = atoi(mms_pn_token(attribute));

	/* Set SSI Port number */
	if ((attribute = mms_pn_lookup(clause, "LMSSIPort", MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT,
		    "lm_activate: No SSI Port found in final "
		    "success response of private command to obtain library "
		    "info ");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7018_MSG, "object", "LMSSIPort", NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_STATE),
		    mms_sym_code_to_str(MMS_LM_E_CONFIG), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
	    &loc)) == NULL) {
		mms_trace(MMS_CRIT, "lm_activate: No SSI Port"
		    " value found in final "
		    "response of private command to obtain library info");
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
		    LM_7018_MSG, "object", "LMSSIPort", NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_STATE),
		    mms_sym_code_to_str(MMS_LM_E_CONFIG), msg_str);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	lm.lm_ssiport = atoi(mms_pn_token(attribute));

	mms_trace(MMS_DEBUG,
	    "ACSAPI_SSI_SOCKET=%d",
	    lm.lm_ssiport);
	(void) snprintf(env_ssi_port, sizeof (env_ssi_port),
	    "ACSAPI_SSI_SOCKET=%d", lm.lm_ssiport);
	(void) putenv(env_ssi_port);

	mms_trace(MMS_DEBUG, "lm_activate: Library ACS - %d, Library LSM - %d",
	    lm.lm_acs, lm.lm_lsm);

	lm_remove_lmpl_cmd(lmpl_tid, ele);

		/* See if SSI is running by query acsls server */
	s = (SEQ_NO)(LM_Q_SERVER_SEQ + pthread_self());
	if ((status = acs_query_server(s)) != STATUS_SUCCESS) {
		mms_trace(MMS_CRIT, "lm_activate: acs_query_server() failed, "
		    "status - %s, check to make sure SSI is running",
		    acs_status(status));
		lm_handle_acs_cmd_error(status, "activate", tid, ret_msg);
		return (LM_ERROR);
	}

			/* Obtain response for query_server() */
	acs_rsp = NULL;
	do {
		if (acs_rsp != NULL)
			free(acs_rsp);
		if ((acs_rsp = lm_obtain_acs_response(s, "activate",
		    tid, ret_msg)) == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "lm_activate: acs_response() "
			    "for query_server failed %s",
			    acs_status(status));
			lm_handle_acs_cmd_error(status, "activate", tid,
			    ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG, "lm_activate: Received "
			    "acknowledge response for query_server()");
			continue;
		} else if (acs_rsp->acs_type == RT_FINAL) {
			mms_trace(MMS_DEBUG, "lm_activate: Recevied final "
			    "response for query_server()");
		} else if (acs_rsp->acs_type == RT_INTERMEDIATE) {
			mms_trace(MMS_DEBUG, "lm_activate: Received "
			    "intermediate response for query_server()");
		} else {
			mms_trace(MMS_ERR, "lm_activate: Received unknow "
			    "response type for query_server() - %d",
			    acs_rsp->acs_type);
			continue;
		}
	} while (acs_rsp->acs_type != RT_FINAL);


	if ((pkt_ver = acs_get_packet_version()) != ACS_PKT_VER) {
		mms_trace(MMS_CRIT, "ACSLS server is using a packet version "
		    "of %d and LM is using a version of %d. LM and ACSLS "
		    "server are incompatiable", pkt_ver, ACS_PKT_VER);
		return (LM_ERROR);
	}

	if ((rc = lm_lib_type(lm.lm_lsm, tid, ret_msg)) != LM_OK) {
		mms_trace(MMS_ERR, "lm_activate: lm_lib_type failed");
		return (LM_ERROR);
	}

	if ((rc = lm_library_config("activate", tid, ret_msg)) != LM_OK) {
		mms_trace(MMS_ERR, "lm_activate: lm_library_config failed");
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "ACSLS %s lm_activate succeeded", lm.lm_type);

	return (LM_OK);
}

int
/* LINTED argument unused in function */
lm_reset(mms_par_node_t *cmd, char *tid, char *ret_msg)
{


	mms_trace(MMS_DEVP, "lm_reset: Entering ACSLS reset process");

	if (mms_pn_lookup(cmd, "partial", MMS_PN_KEYWORD, NULL) == NULL) {
		mms_trace(MMS_DEBUG, "lm_reset: Nothing defined to do for a "
		    "full reset of an ACSLS library");
		return (LM_OK);
	}

	mms_trace(MMS_DEBUG,
	    "lm_reset: Nothing defined to do for a partial reset "
	    "of an ACSLS library");

	return (LM_OK);

}

int
lm_eject(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int	i = 0;
	int	j;
	int	rc;
	int	lmpl_tid;
	int	slot_spec_size;

	char	*kw;
	char	*slot_spec;
	char    msg_str[256];
	char    text_str[256];
	char    tmp_str[256];
	char	dele_str[1024];
	char	carts[2048];
	char	err_carts[2048];
	char	text_cart[12];
	char	text_carts[2048];

	VOLID		volid_list[MAX_ID];
	VOLID		*vol_id;
	CAPID		cap_id;
	ACS_EJECT_RESPONSE	*ep;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*loc1 = NULL;
	mms_par_node_t	*clause;
	mms_par_node_t	*value;
	mms_par_node_t	*value1;

	acs_rsp_ele_t	*acs_rsp;
	acs_cap_t	*acs_cap;
	lmpl_rsp_ele_t	*ele;

	char	nbuf[20];

			/* Create default final error response due to */
			/* internal processing error */
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7004_MSG, "cmd", "eject", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_INTERNAL), msg_str);

			/* Obtain slotgroup (Name of cap to use) */
	MMS_PN_LOOKUP(clause, cmd, kw = "slotgroup", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, NULL);

	cap_id.lsm_id.acs = lm.lm_acs;
			/* If more than one lsm can exist within the acs, */
			/* the lsm will need to be determined */
	cap_id.lsm_id.lsm = lm.lm_lsm;

	acs_cap = (acs_cap_t *)lm.lm_port;
	for (i = 0; i < lm.lm_caps; i++) {
		if (strcmp(acs_cap->cap_name, mms_pn_token(value)) == 0) {
			mms_trace(MMS_DEBUG,
			    "lm_eject: Physical cap associated "
			    "with slotgroup %s found", acs_cap->cap_name);
			/* Make sure that the cap actually exists in */
			/* the library, some libraries have optional */
			/* caps */
			if (!acs_cap->cap_config) {
				mms_trace(MMS_ERR, "lm_eject: Physcial cap "
				    "associated with slotgroup %s is not "
				    "available in the library - %s",
				    acs_cap->cap_name);
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7108_MSG, "port", mms_pn_token(value),
				    NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_INVALID),
				    mms_sym_code_to_str(MMS_LM_E_PORT),
				    msg_str);
				return (LM_ERROR);
			}
			break;
		}
	}
	if (i == lm.lm_caps) {
		mms_trace(MMS_ERR, "lm_eject: Did not find a physical cap "
		    "associated with slotgroup - %s",
		    mms_pn_token(value));
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7117_MSG,
		    "port", mms_pn_token(value), NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INVALID),
		    mms_sym_code_to_str(MMS_LM_E_PORT), msg_str);
		return (LM_ERROR);
	}

	cap_id.cap = acs_cap->cap_capid;

	mms_trace(MMS_DEBUG, "lm_eject: Cap group name for eject - %s, %d",
	    acs_cap->cap_name, acs_cap->cap_capid);

	/* NOTE The number of cartridges that can be ejected cannot exceed */
	/* the size of the CAP, Currently the ACSLS libraries that we */
	/* support CAP size's do not exceed what can be contained in one */
	/* VOLID[MAX_ID]. If the CAP hardware is larger than MAX_ID (43) */
	/* then the code needs to be able to break the eject into multiple */
	/* acs_eject commands */

	i = 0;
	for (clause = mms_pn_lookup(cmd, kw = "slot", MMS_PN_CLAUSE, &loc);
	    clause != NULL;
	    clause = mms_pn_lookup(cmd, "slot", MMS_PN_CLAUSE, &loc)) {
		loc1 = NULL;
		MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, &loc1);
		MMS_PN_LOOKUP(value1, clause, NULL, MMS_PN_STRING, &loc1);

		mms_trace(MMS_DEBUG,
		    "lm_eject: eject cartridge %s from slot %s",
		    mms_pn_token(value1), mms_pn_token(value));

		(void) strncpy(volid_list[i].external_label,
		    mms_pn_token(value1), EXTERNAL_LABEL_SIZE);
		volid_list[i++].external_label[EXTERNAL_LABEL_SIZE] = '\0';

		if (i == acs_cap->cap_size) {
			mms_trace(MMS_ERR, "lm_eject: Trying to ejecting more "
			    "cartridges than the cap can hold, max is %d "
			    "for a %s library", acs_cap->cap_size,
			    lm.lm_type);
			(void) snprintf(nbuf, sizeof (nbuf), "%d",
			    acs_cap->cap_size);
			(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
			    LM_7113_MSG, "num", nbuf, NULL);
			(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCMD),
			    msg_str);
			return (LM_ERROR);
		}
	}

	if ((lm_acs_eject(&acs_rsp, cap_id, volid_list, i, "eject", tid,
	    ret_msg)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_eject:, acs_eject() failed");
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG,
	    "lm_eject: Received final response for acs_eject()");

	ep = (ACS_EJECT_RESPONSE *)acs_rsp->acs_rbuf;
	if (ep->eject_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_eject: response from ace_eject() failed, "
		    "status - %s", acs_status(ep->eject_status));
		lm_handle_eject_error(ep->eject_status, acs_cap->cap_name,
		    cap_id.lsm_id.lsm, "eject", tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

	if (ep->count != i) {
		mms_trace(MMS_ERR,
		    "lm_eject: response from ace_eject() does not "
		    "include the correct number of cartridges "
		    "to be ejected, expected %d, actual %d", i,
		    ep->count);
	}

	slot_spec_size = 100 * ep->count;
	if ((slot_spec = (char *)malloc(slot_spec_size)) == NULL) {
		lm_serr(MMS_CRIT, "lm_eject: Unable to malloc space "
		    "for delete slot definitions");
		free(acs_rsp);
		return (LM_ERROR);
	}

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT, "lm_eject: lm_obtain_task_id failed "
		    "trying to generate config cmd for slot deletion");
		free(acs_rsp);
		free(slot_spec);
		return (LM_ERROR);
	}

	(void) snprintf(slot_spec, slot_spec_size,
	    "config task[\"%d\"] scope[partial] ", lmpl_tid);

	carts[0] = '\0';
	err_carts[0] = '\0';
	text_carts[0] = '\0';
	for (j = 0; j < ep->count; j++) {
		vol_id = &ep->vol_id[j];
		if (ep->vol_status[j] != STATUS_SUCCESS) {
			mms_trace(MMS_OPER,
			    "lm_eject: Ejection of cartridge %s "
			    "failed, status - %s", vol_id->external_label,
			    acs_status(ep->vol_status[j]));
			(void) strcat(err_carts, vol_id->external_label);
			(void) strcat(err_carts, " ");
		} else {
			mms_trace(MMS_DEBUG,
			    "lm_eject: Cartridge %s was ejected "
			    "from library", vol_id->external_label);
			(void) snprintf(dele_str, sizeof (dele_str),
			    DELE_SLOT, vol_id->external_label);
			(void) strcat(slot_spec, dele_str);
			(void) strcat(carts, vol_id->external_label);
			(void) strcat(carts, " ");
			(void) snprintf(text_cart, sizeof (text_cart),
			    TEXT_CART, vol_id->external_label);
			(void) strlcat(text_carts, text_cart,
			    sizeof (text_carts));
		}
	}

	free(acs_rsp);

	if (carts[0] != '\0') {
		(void) strcat(slot_spec, ";");
		mms_trace(MMS_DEBUG, "lm_eject: SLOT_SPEC:\n%s", slot_spec);

		if ((rc = lm_gen_lmpl_cmd(slot_spec, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR,
			    "lm_eject: Internal processing error "
			    "encountered while processing lmpl config "
			    "command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(slot_spec);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			handle_lmpl_cmd_error(rc, "eject", "config", tid,
			    ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(slot_spec);
			return (LM_ERROR);
		}

		mms_trace(MMS_OPER, "lm_eject: Got successful response for "
		    "slot deletion config command for cartridges - %s", carts);
		free(slot_spec);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		carts[strlen(carts)-1] = '\0';
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7107_MSG,
		    "cart", carts, NULL);
	} else {
		free(slot_spec);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		mms_trace(MMS_OPER,
		    "lm_eject:, No cartridges were successfully ejected");
		mms_trace(MMS_DEBUG, "Free up accept mutex");
		if ((rc = pthread_mutex_unlock(&lm_acc_mutex)) != 0) {
			lm_serr(MMS_CRIT,
			    "lm_eject: Unable to unlock acc/unacc "
			    "mutex, errno - %s", strerror(errno));
			return (LM_ERROR);
		}
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7115_MSG,
		    NULL);
	}

	if (err_carts[0] != '\0') {
		err_carts[strlen(err_carts)-1] = '\0';
			/* Some cartridges did not successfully get ejected */
		mms_trace(MMS_OPER,
		    "Cartridges %s were not ejected from library",
		    err_carts);
		(void) mms_buf_msgcl(tmp_str, sizeof (tmp_str), LM_7114_MSG,
		    "cart", err_carts, NULL);
		lm_message("operator", "notice", tmp_str);
	}

	if (text_carts[0] != '\0') {
		text_carts[strlen(text_carts)-1] = '\0';
		(void) snprintf(text_str, sizeof (text_str), LM_TEXT_CLS,
		    text_carts);
	} else {
		text_str[0] = '\0';
	}
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, text_str,
	    msg_str);
	mms_trace(MMS_DEVP, "Exiting lm_eject");
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "lm_eject: LMPM command %s encounterd an invalid "
	    "or missing %s clause:\n%s", "eject", kw,
	    mms_pn_build_cmd_text(cmd));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "eject", "part", kw, NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}

int
/* LINTED argument unused in function */
lm_barrier(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char    msg_str[256];

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7101_MSG,
	    "cmd", "barrier", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");
	return (LM_OK);
}

/*
 * lm_private()()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM private command being processed.
 *	- tid		Task id of LMPM private command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the private command because of
 *			a failure, the error response is created here.
 *
 * This function executes the necessary steps that are ACSLS library specific
 * for the LM to process the private command. This routine is responsible
 * for calling lm_validate_private(), which validates that all data
 * elements in the get, set, and unset clauses are valid names.
 *
 * Return Values:
 *	- LM_OK		If function completed successfully
 *	- LM_ERROR	If function detected something that does not
 *			allow the LM to become active. In some cases
 *			depending on the error, ret_msg may be updated to
 *			reflect the error that was encountered as to why
 *			the LM cannot successfully process the command.
 */
int
lm_private(mms_par_node_t *cmd, char *tid, char *ret_msg)
{

	mms_trace(MMS_DEVP, "Entering ACSLS lm_private");

	if (lm_validate_private(cmd, tid, ret_msg) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_private: lm_validate_private() failed");
		return (LM_ERROR);
	}

		/* No get-name operations for ACSLS libraries, return a */
		/* empty string */
	(void) strcpy(ret_msg, "");

	mms_trace(MMS_DEVP, "Exiting ACSLS lm_private");

	return (LM_OK);
}

int
/* LINTED argument unused in function */
lm_cancel(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	char	msg_str[512];

	(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7101_MSG,
	    "cmd", "cancel", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_SUC_FINAL, tid, msg_str, "");
	return (LM_OK);
}

int
lm_event(mms_par_node_t *cmd, char *tid, char *ret_msg)
{

	ACS_QUERY_VOL_RESPONSE	*vol_qp;
	QU_VOL_STATUS		*vol_sp;
	ACS_QUERY_DRV_RESPONSE	*drv_qp;
	QU_DRV_STATUS		*drv_sp;
	VOLID			vol_id_list[MAX_ID];
	DRIVEID			drive_id[MAX_ID];

	SEQ_NO			s;
	STATUS			status;
	acs_rsp_ele_t		*acs_rsp;
	lmpl_rsp_ele_t		*ele;
	lmpl_rsp_node_t		*node;

	int		rc;
	int		panel;
	int		lmpl_tid;
	int		count;
	int		accessible = 0;
	int		occupied = 0;

	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*clause;
	mms_par_node_t	*object;
	mms_par_node_t	*attribute;
	mms_par_node_t	*library;
	mms_par_node_t	*rsp;

	char		*cptr;
	char		*pptr;
	char		*obj_val;
	char		cmd_str[1024];
	char		cfg_str[1024];

	mms_trace(MMS_DEVP, "Entering lm_event");

	if ((clause = mms_pn_lookup(cmd, NULL, MMS_PN_CLAUSE, NULL))
	    == NULL) {
		return (LM_ERROR);
	}

	MMS_PN_LOOKUP(object, clause, NULL, MMS_PN_STRING, &loc);
	obj_val = mms_pn_token(object);

	MMS_PN_LOOKUP(library, clause, NULL, MMS_PN_STRING, &loc);
	if (strcmp(lm.lm_net_cfg.cli_name,  mms_pn_token(library)) != 0) {
		mms_trace(MMS_OPER,
		    "lm_event: Event %s is for library %s, skipping",
		    mms_pn_token(object), mms_pn_token(library));
		return (LM_OK);
	} else {
		mms_trace(MMS_OPER,
		    "lm_event: Event %s is for this library, %s",
		    mms_pn_token(object), mms_pn_token(library));
	}

	if (strcmp(mms_pn_token(clause), "newdrive") == 0) {
		mms_trace(MMS_DEBUG, "lm_event:, Config new drive %s", obj_val);

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_event: lm_obtain_task_id failed "
			    "trying to generate config command for event");
			return (LM_ERROR);
		}
		(void) snprintf(cmd_str, sizeof (cmd_str), LM_SHOW_DRIVE,
		    lmpl_tid, obj_val);

		mms_trace(MMS_DEBUG, "lm_event: show cmd for drive event:\n%s",
		    cmd_str);

		if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR,
			    "lm_event: Internal processing error "
			    "encountered while processing LMPL show cmd");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_ERR, "lm_event: show cmd did not receive "
			    "a successful response");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG,
		    "lm_event: show cmd got sucess final response");
		node = mms_list_head(&ele->lmpl_rsp_list);
		rsp = node->lmpl_rsp_tree;

		loc = NULL;
		if ((clause = mms_pn_lookup(rsp, "DriveGeometry",
		    MMS_PN_STRING, &loc)) == NULL) {
			mms_trace(MMS_CRIT, "lm_event: No DriveGeometry "
			    "attribute found in response to show cmd");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		if ((attribute = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc)) == NULL) {
			mms_trace(MMS_CRIT, "lm_event:, No DriveGeometry value "
			    "found in response to show cmd");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_event: Drive %s has a geometry of %s",
		    obj_val, mms_pn_token(attribute));

		cptr = mms_pn_token(attribute);
		pptr = strstr(cptr, ",");
		*pptr = '\0';
		drive_id[0].panel_id.lsm_id.acs = atoi(cptr);
		cptr = pptr + 1;
		pptr = strstr(cptr, ",");
		*pptr = '\0';
		drive_id[0].panel_id.lsm_id.lsm = atoi(cptr);
		cptr = pptr + 1;
		pptr = strstr(cptr, ",");
		*pptr = '\0';
		drive_id[0].panel_id.panel = atoi(cptr);
		cptr = pptr + 1;
		drive_id[0].drive = atoi(cptr);

		mms_trace(MMS_DEBUG, "lm_event: Drive %s query_drive(), "
		    "%d,%d,%d,%d", obj_val, drive_id[0].panel_id.lsm_id.acs,
		    drive_id[0].panel_id.lsm_id.lsm,
		    drive_id[0].panel_id.panel,
		    drive_id[0].drive);

		lm_remove_lmpl_cmd(lmpl_tid, ele);

		s = (SEQ_NO)(LM_EVENT_SEQ + pthread_self());
		count = 1;
		if ((status = acs_query_drive(s, drive_id, count))
		    != STATUS_SUCCESS) {
			mms_trace(MMS_ERR, "lm_event: acs_query_drive() failed "
			    "status - %s", acs_status(status));
			return (LM_ERROR);
		}

		do {
			if ((acs_rsp = lm_obtain_acs_response(s, "event", tid,
			    ret_msg)) == NULL)
					/* Internal error encountered */
				return (LM_ERROR);
			if (acs_rsp->acs_status != STATUS_SUCCESS) {
				mms_trace(MMS_CRIT, "lm_event: acs_response() "
				    "for query_drive failed, status "
				    "- %s", acs_status(status));
				free(acs_rsp);
				return (LM_ERROR);
			}
			if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
				mms_trace(MMS_DEBUG, "lm_event: Received "
				    "acknowledge response for query_drive");
				continue;
			} else if (acs_rsp->acs_type != RT_FINAL) {
				mms_trace(MMS_DEBUG,
				    "lm_event: Received unknown "
				    "response type of query_drive - %d",
				    acs_rsp->acs_type);
				continue;
			}

		} while (acs_rsp->acs_type != RT_FINAL);

		mms_trace(MMS_DEBUG, "lm_event: Received final response for "
		    "query_drive");

		drv_qp = (ACS_QUERY_DRV_RESPONSE *)acs_rsp->acs_rbuf;
		if (drv_qp->query_drv_status != STATUS_SUCCESS) {
			mms_trace(MMS_ERR, "lm_event: response from "
			    "query_drive() failed, status is %s",
			    acs_status(drv_qp->query_drv_status));
			free(acs_rsp);
			return (LM_ERROR);
		}

		drv_sp = &drv_qp->drv_status[0];
		if (drv_sp->status == STATUS_DRIVE_IN_USE)
			occupied = 1;
		if (drv_sp->state == STATE_ONLINE)
			accessible = 1;

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_event: lm_obtain_task_id failed "
			    "trying to generate config command for event");
			return (LM_ERROR);
		}
		(void) snprintf(cfg_str, sizeof (cfg_str), CONFIG_DRIVE_EVENT,
		    lmpl_tid,
		    drv_sp->drive_id.panel_id.lsm_id.acs,
		    drv_sp->drive_id.panel_id.lsm_id.lsm,
		    drv_sp->drive_id.panel_id.panel,
		    drv_sp->drive_id.drive,
		    drv_sp->drive_id.panel_id.panel,
		    occupied ? drv_sp->vol_id.external_label : "none",
		    occupied ? "true" : "false",
		    accessible ? "true" : "false");

		free(acs_rsp);

	} else

	if (strcmp(mms_pn_token(clause), "newcartridge") == 0) {
		mms_trace(MMS_DEBUG,
		    "lm_event: Config new cartridge %s", obj_val);

		(void) strncpy(vol_id_list[0].external_label, obj_val,
		    EXTERNAL_LABEL_SIZE);
		vol_id_list[0].external_label[EXTERNAL_LABEL_SIZE] = '\0';
		if ((lm_acs_query_volume(&acs_rsp, vol_id_list, 1, "event", tid,
		    ret_msg)) == LM_ERROR)
			return (LM_ERROR);
		mms_trace(MMS_DEBUG, "lm_event: Recevied final response for "
		    "query_volume()");

		vol_qp = (ACS_QUERY_VOL_RESPONSE *)acs_rsp->acs_rbuf;
		if (vol_qp->query_vol_status != STATUS_SUCCESS) {
			mms_trace(MMS_ERR, "lm_event: response from "
			    "query_volume() failed, status - %s",
			    acs_status(vol_qp->query_vol_status));
			free(acs_rsp);
			return (LM_ERROR);
		}
		vol_sp = &vol_qp->vol_status[0];

		if (vol_sp->status != STATUS_VOLUME_HOME) {
			mms_trace(MMS_ERR, "lm_event: Unable to send a config "
			    "for cartridge %s, cartridge status - %s",
			    obj_val, acs_status(vol_sp->status));
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_event: vol %s is in location "
		    "%d,%d,%d,%d,%d", vol_sp->vol_id.external_label,
		    vol_sp->location.cell_id.panel_id.lsm_id.acs,
		    vol_sp->location.cell_id.panel_id.lsm_id.lsm,
		    vol_sp->location.cell_id.panel_id.panel,
		    vol_sp->location.cell_id.row,
		    vol_sp->location.cell_id.col);

		panel = vol_sp->location.cell_id.panel_id.panel;

		free(acs_rsp);

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_event: lm_obtain_task_id failed "
			    "trying to generate config command for event");
			return (LM_ERROR);
		}

		(void) snprintf(cfg_str, sizeof (cfg_str), CONFIG_CART_EVENT,
		    lmpl_tid, obj_val, panel, panel, obj_val, lm.lm_type);
	} else {
		mms_trace(MMS_ERR, "lm_event: Unsupported event type %s",
		    mms_pn_token(clause));
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_event: config for event:\n%s", cfg_str);

	if ((rc = lm_gen_lmpl_cmd(cfg_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR, "lm_event: Internal processing error "
		    "encountered while processing lmpl config command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		mms_trace(MMS_ERR, "lm_event: LMPL config command failed while "
		    "processing LMPM event command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}
	mms_trace(MMS_DEBUG,
	    "lm_event: Got successful response for event config command");
	lm_remove_lmpl_cmd(lmpl_tid, ele);
	return (LM_OK);

not_found:
	mms_trace(MMS_ERR,
	    "LMPM command event encountered an invalid or missing "
	    "%s clause, cmd:\n%s", mms_pn_token(clause),
	    mms_pn_build_cmd_text(cmd));
	return (LM_ERROR);
}

int
lm_library_config(char *cmd, char *tid, char *ret_msg)
{
	int	rc;
	int	i;
	int	count;
	int	lmpl_tid;
	int	freecells = 0;
	int	cell_size;
	int	accessible;
	int	occupied;
	int	rsp_cnt;
	int	spec_stop;
	int	loop_stop = 0;

	char	cfg_str[1024];
	char	full_str[FSBUFSIZE];
	char	geometry[128];
	char	*slot_spec;
	char	*drive_spec;
	char	*serial;

	lmpl_rsp_ele_t	*ele;
	acs_rsp_ele_t	*acs_rsp;
	acs_drive_t	*acs_drives;

	SEQ_NO			s;
	STATUS			status;

	ACS_QUERY_LSM_RESPONSE	*lsm_qp;
	QU_LSM_STATUS		*lsm_sp;
	LSMID			lsm_id[MAX_ID];

	ACS_QUERY_VOL_RESPONSE	*vol_qp;
	QU_VOL_STATUS		*vol_sp;
	VOLID			vol_id[MAX_ID];

	ACS_QUERY_DRV_RESPONSE	*drv_qp;
	QU_DRV_STATUS   	*drv_sp;
	DRIVEID			drive_id[MAX_ID];

	mms_trace(MMS_DEVP, "Entering lm_library_config");

	s = (SEQ_NO)(LM_Q_LSM_SEQ + pthread_self());

	lsm_id[0].acs = lm.lm_acs;
	lsm_id[0].lsm = lm.lm_lsm;	/* Since there is no pass throughs */
					/* for L180, L500, or L700, libraries */
					/* lsm is always set to 0 */
	count = 1;
	if ((status = acs_query_lsm(s, lsm_id, count)) != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "acs_query_lsm for acs %s failed %s",
		    lm.lm_acs, acs_status(status));
		lm_handle_acs_cmd_error(status, "activate", tid, ret_msg);
		return (LM_ERROR);
	}
					/* obtain number of freecells */
	acs_rsp = NULL;
	do {
		if (acs_rsp != NULL)
			free(acs_rsp);
		if ((acs_rsp = lm_obtain_acs_response(s, "activate",
		    tid, ret_msg)) == NULL)
				/* Internal error encountered */
			return (LM_ERROR);
		if (acs_rsp->acs_status != STATUS_SUCCESS) {
			mms_trace(MMS_CRIT, "lm_library_config: acs_response() "
			    "for query_lsm failed, status - %s",
			    acs_status(status));
			lm_handle_acs_cmd_error(status, "activate", tid,
			    ret_msg);
			free(acs_rsp);
			return (LM_ERROR);
		}

		if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
			mms_trace(MMS_DEBUG, "lm_library_config: Received "
			    "acknowledge response for query_lsm");
			continue;
		} else if (acs_rsp->acs_type != RT_FINAL) {
			mms_trace(MMS_DEBUG,
			    "lm_library_config: Received unknown "
			    "response type for query_lsm() - %d",
			    acs_rsp->acs_type);
			continue;
		}

	} while (acs_rsp->acs_type != RT_FINAL);

	mms_trace(MMS_DEBUG, "lm_library_config: Received final response for "
	    "query_lsm");

			/* Get number of free cells in lsm */
	lsm_qp = (ACS_QUERY_LSM_RESPONSE *)acs_rsp->acs_rbuf;
	if (lsm_qp->query_lsm_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_library_config: Final response "
		    "for query_lsm not success status is %s",
		    acs_status(lsm_qp->query_lsm_status));
		lm_handle_acsls_error(lsm_qp->query_lsm_status, "acs_query_lsm",
		    "activate", tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}
	lsm_sp = &lsm_qp->lsm_status[0];
	if (lsm_sp->state != STATE_ONLINE) {
		mms_trace(MMS_ERR, "lm_library_config: State of lsm is not "
		    "online, state - %s", acs_state(lsm_sp->state));
		lm_handle_acsls_state(lsm_sp->state, "acs_query_lsm",
		    "activate", tid, ret_msg);
		free(acs_rsp);
		if ((rc = lm_common_ready(LM_BROKE, tid, ret_msg)) != LM_OK) {
			mms_trace(MMS_ERR, "lm_activate: Failed to issue "
			    "ready broken command to MM.");
		}
		lm_state = LM_BROKEN;
		return (LM_ERROR);
	}
	freecells = lsm_sp->freecells;
	free(acs_rsp);

	mms_trace(MMS_DEBUG, "lm_library_config: Free cells for acs %d - %d",
	    lm.lm_acs, freecells);

	if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
		mms_trace(MMS_CRIT,
		    "lm_library_config: lm_obtain_task_id failed "
		    "trying to generate config command for bay creation");
		return (LM_ERROR);
	}


	if (lm_library_config_non_comm(lmpl_tid, &full_str[0], tid, ret_msg)
	    == LM_ERROR) {
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	if ((rc = lm_gen_lmpl_cmd(full_str, ele, 0)) == LM_ERROR) {
		mms_trace(MMS_ERR,
		    "lm_library_config: Internal processing error "
		    "encountered while processing lmpl config command");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	} else if (rc != LMPL_FINAL_OK) {
		handle_lmpl_cmd_error(rc, "activate", "config", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_library_config: Got successful response for "
	    "full config command");

	mms_trace(MMS_DEBUG, "TASK ID - %d", lmpl_tid);
	lm_remove_lmpl_cmd(lmpl_tid, ele);

	cell_size = MAX_CONFIG_CARTS * SLOT_CFG_SIZE;

	if ((slot_spec = (char *)malloc(cell_size)) == NULL) {
		lm_serr(MMS_CRIT, "lm_library_config: Unable to malloc space "
		    "for slotp spec definitions");
		return (LM_ERROR);
	}

	s = (SEQ_NO)(LM_Q_VOL2_SEQ + pthread_self());
	count = 0;
	if ((status = acs_query_volume(s, vol_id, count)) != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_library_config: acs_query_volume2() "
		    "failed, status - %s", acs_status(status));
		lm_handle_acs_cmd_error(status, "activate", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(slot_spec);
		return (LM_ERROR);
	}

	do {
		mms_trace(MMS_DEBUG, "lm_library_config: Configuring slot spec "
		    "loop");
		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_library_config: lm_obtain_task_id "
			    "failed trying to generate config cmd for slot "
			    "creation");
			free(slot_spec);
			return (LM_ERROR);
		}

		(void) snprintf(slot_spec, cell_size,
		    "config task[\"%d\"] scope[partial] ", lmpl_tid);

		rsp_cnt = 0;
		spec_stop = 0;
		acs_rsp = NULL;
		do {
			if (acs_rsp != NULL)
				free(acs_rsp);
			if ((acs_rsp = lm_obtain_acs_response(s, "activate",
			    tid, ret_msg)) == NULL) {
				/* Internal error encountered */
				free(slot_spec);
				return (LM_ERROR);
			}
			if (acs_rsp->acs_status != STATUS_SUCCESS) {
				mms_trace(MMS_CRIT, "lm_library_config: "
				    "acs_response() for query_volume2 failed, "
				    "status - %s", acs_status(status));
				lm_handle_acs_cmd_error(status, "activate", tid,
				    ret_msg);
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(acs_rsp);
				free(slot_spec);
				return (LM_ERROR);
			}

			if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
				mms_trace(MMS_DEBUG,
				    "lm_library_config: Received "
				    "acknowledge response for query_volume2()");
				continue;
			} else if (acs_rsp->acs_type == RT_FINAL) {
				mms_trace(MMS_DEBUG,
				    "lm_library_config: Recevied "
				    "final response for query_volume2()");
			} else if (acs_rsp->acs_type == RT_INTERMEDIATE) {
				mms_trace(MMS_DEBUG,
				    "lm_library_config: Received "
				    "intermediate response for "
				    "query_volume2()");
			} else {
				mms_trace(MMS_ERR,
				    "lm_library_config: Received "
				    "unknow response type for query_volume2() "
				    "- %d", acs_rsp->acs_type);
				continue;
			}

			vol_qp = (ACS_QUERY_VOL_RESPONSE *)acs_rsp->acs_rbuf;
			if (vol_qp->query_vol_status != STATUS_SUCCESS) {
				mms_trace(MMS_ERR,
				    "lm_library_config: response "
				    "from query_volume2() failed, status is %s",
				    acs_status(vol_qp->query_vol_status));
				lm_handle_acsls_error(vol_qp->query_vol_status,
				    "acs_query_vol", "activate", tid, ret_msg);
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(acs_rsp);
				free(slot_spec);
				return (LM_ERROR);
			}
			mms_trace(MMS_DEBUG,
			    "lm_library_config: count of response "
			    "for query_volume2() - %d", vol_qp->count);
			for (i = 0; i < (int)vol_qp->count; i++) {
				vol_sp = &vol_qp->vol_status[i];
				if (vol_sp->location_type != LOCATION_CELL) {
					mms_trace(MMS_DEBUG,
					    "lm_library_config: "
					    "volume %s found in drive",
					    &vol_sp->vol_id.external_label[0]);
					continue;
				}

				if (vol_sp->location.cell_id.panel_id.lsm_id.acs
				    != lm.lm_acs) {
					mms_trace(MMS_DEBUG,
					    "lm_library_config: "
					    "Skip volume %s, wrong ACS",
					    &vol_sp->vol_id.external_label[0]);
					continue;
				}
				(void) snprintf(cfg_str, sizeof (cfg_str),
				    CFG_SLOT,
				    vol_sp->vol_id.external_label,
				    vol_sp->location.cell_id.panel_id.panel,
				    vol_sp->location.cell_id.panel_id.panel,
				    vol_sp->vol_id.external_label,
				    lm.lm_type);
				mms_trace(MMS_DEBUG, "lm_library_config: "
				    "Slot spec - %s", cfg_str);
				(void) strcat(slot_spec, cfg_str);
				rsp_cnt++;
			}
				/* See if we should stop processing */
				/* query vol responses */
			if ((rsp_cnt + ACS_RESPONSE) > MAX_CONFIG_CARTS)
				spec_stop = 1;
		} while (acs_rsp->acs_type != RT_FINAL && spec_stop != 1);

		if (acs_rsp->acs_type == RT_FINAL)
			loop_stop = 1;

		free(acs_rsp);

		(void) strcat(slot_spec, ";");

		mms_trace(MMS_DEBUG, "\nlm_library_config: SLOT_SPEC:\n%s\n",
		    slot_spec);
		if ((rc = lm_gen_lmpl_cmd(slot_spec, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_library_config: Internal "
			    "processing error encountered while processing "
			    "lmpl config command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(slot_spec);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			handle_lmpl_cmd_error(rc, "activate", "config", tid,
			    ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(slot_spec);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_library_config: "
		    "Got successful response "
		    "for slot creation config command");

		lm_remove_lmpl_cmd(lmpl_tid, ele);

	} while (loop_stop != 1);

	free(slot_spec);

	acs_drives = (acs_drive_t *)lm.lm_drive;
	if (acs_drives->acs_max_drive > MAX_CONFIG_DRIVES)
		cell_size = MAX_CONFIG_DRIVES * DRIVE_CFG_SIZE;
	else
		cell_size = acs_drives->acs_max_drive * DRIVE_CFG_SIZE;

	if ((drive_spec = (char *)malloc(cell_size)) == NULL) {
		lm_serr(MMS_CRIT, "lm_library_config: Unable to malloc space "
		    "for drive spec definitions, errno - %d",
		    strerror(errno));
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		return (LM_ERROR);
	}
	s = (SEQ_NO)(LM_Q_DRIVE_SEQ + pthread_self());
	count = 0;
	if ((status = acs_query_drive(s, drive_id, count)) != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_library_config: acs_query_drive() "
		    "failed, status - %s", acs_status(status));
		lm_handle_acs_cmd_error(status, "activate", tid, ret_msg);
		lm_remove_lmpl_cmd(lmpl_tid, ele);
		free(drive_spec);
		return (LM_ERROR);
	}

	loop_stop = 0;
	do {

		mms_trace(MMS_DEBUG, "lm_library_config: "
		    "Configuring drive spec loop");
		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_library_config: lm_obtain_task_id "
			    "failed trying to generate config command for "
			    "drive creation");
			free(drive_spec);
			return (LM_ERROR);
		}

		(void) snprintf(drive_spec, cell_size,
		    "config task[\"%d\"] scope[partial] ", lmpl_tid);

		rsp_cnt = 0;
		spec_stop = 0;
		acs_rsp = NULL;
		do {
			if (acs_rsp != NULL)
				free(acs_rsp);
			if ((acs_rsp = lm_obtain_acs_response(s, "activate",
			    tid, ret_msg)) == NULL) {
				/* Internal error encountered */
				free(drive_spec);
				return (LM_ERROR);
			}
			if (acs_rsp->acs_status != STATUS_SUCCESS) {
				mms_trace(MMS_CRIT, "lm_library_config: "
				    "acs_response() for query_drive failed, "
				    "status - %s", acs_status(status));
				lm_handle_acs_cmd_error(status, "activate", tid,
				    ret_msg);
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(acs_rsp);
				free(drive_spec);
				return (LM_ERROR);
			}

			if (acs_rsp->acs_type == RT_ACKNOWLEDGE) {
				mms_trace(MMS_DEBUG,
				    "lm_library_config: Received "
				    "acknowledge response for query_drive()");
				continue;
			} else if (acs_rsp->acs_type == RT_FINAL) {
				mms_trace(MMS_DEBUG,
				    "lm_library_config: Recevied "
				    "final response for query_drive()");
			} else if (acs_rsp->acs_type == RT_INTERMEDIATE) {
				mms_trace(MMS_DEBUG,
				    "lm_library_config: Received "
				    "intermediate response for query_drive()");
			} else {
				mms_trace(MMS_ERR,
				    "lm_library_config: Received "
				    "unknow response type for query_drive() "
				    "- %d", acs_rsp->acs_type);
				continue;
			}
			drv_qp = (ACS_QUERY_DRV_RESPONSE *)acs_rsp->acs_rbuf;
			if (drv_qp->query_drv_status != STATUS_SUCCESS) {
				mms_trace(MMS_ERR,
				    "lm_library_config: response "
				    "from query_drive() failed, status is %s",
				    acs_status(drv_qp->query_drv_status));
				lm_handle_acsls_error(drv_qp->query_drv_status,
				    "acs_query_drive", "activate", tid,
				    ret_msg);
				lm_remove_lmpl_cmd(lmpl_tid, ele);
				free(acs_rsp);
				free(drive_spec);
				return (LM_ERROR);
			}
			mms_trace(MMS_DEBUG,
			    "lm_library_config: count of response "
			    "for query_drive() - %d", drv_qp->count);
			for (i = 0; i < (int)drv_qp->count; i++) {
				occupied = 0;
				accessible = 0;
				drv_sp = &drv_qp->drv_status[i];
				if (drv_sp->drive_id.panel_id.lsm_id.acs
				    != lm.lm_acs) {
					mms_trace(MMS_DEBUG,
					    "lm_library_config: "
					    "Skip drive, Wrong ACS -%d",
					    drv_sp->drive_id.panel_id.lsm_id.
					    acs);
					continue;
				}
				if (drv_sp->status == STATUS_DRIVE_IN_USE) {
					(void) snprintf(cfg_str,
					    sizeof (cfg_str),
					    CFG_SLOT,
					    drv_sp->vol_id.external_label,
					    drv_sp->drive_id.panel_id.panel,
					    drv_sp->drive_id.panel_id.panel,
					    drv_sp->vol_id.external_label,
					    lm.lm_type);
					(void) strcat(drive_spec, cfg_str);
					rsp_cnt++;
					occupied = 1;
				}
				if (drv_sp->state == STATE_ONLINE) {
					accessible = 1;
				}
				(void) snprintf(geometry, sizeof (geometry),
				    "%d,%d,%d,%d",
				    drv_sp->drive_id.panel_id.lsm_id.acs,
				    drv_sp->drive_id.panel_id.lsm_id.lsm,
				    drv_sp->drive_id.panel_id.panel,
				    drv_sp->drive_id.drive);
				if (lm_obtain_serial_num(geometry, &serial,
				    cmd, tid, ret_msg) != LM_OK) {
					mms_trace(MMS_ERR, "lm_library_config: "
					    "Trying to obtain serial number "
					    "for drive with ACSLS geometry %s "
					    "failed", geometry);
					return (LM_ERROR);
				}
				if (strcmp(serial, "") == 0) {
					mms_trace(MMS_ERR, "lm_library_config: "
					    "No serial number found for drive "
					    "with ACSLS geometry of %s",
					    geometry);
				}
				(void) snprintf(cfg_str, sizeof (cfg_str),
				    CFG_DRIVE,
				    serial,
				    drv_sp->drive_id.panel_id.lsm_id.acs,
				    drv_sp->drive_id.panel_id.lsm_id.lsm,
				    drv_sp->drive_id.panel_id.panel,
				    drv_sp->drive_id.drive,
				    drv_sp->drive_id.panel_id.panel,
				    occupied ?
				    drv_sp->vol_id.external_label : "none",
				    occupied ? "true" : "false",
				    accessible ? "true" : "false");
				mms_trace(MMS_DEBUG, "lm_library_config: "
				    "drive spec - %s", cfg_str);
				(void) strcat(drive_spec, cfg_str);
				rsp_cnt++;
			}
			if ((rsp_cnt + ACS_RESPONSE) > MAX_CONFIG_DRIVES)
				spec_stop = 1;
		} while (acs_rsp->acs_type != RT_FINAL && spec_stop != 1);

		if (acs_rsp->acs_type == RT_FINAL)
			loop_stop = 1;

		free(acs_rsp);

		(void) strcat(drive_spec, ";");

		mms_trace(MMS_DEBUG, "\nlm_library_config: DRIVE_SPEC:\n%s\n",
		    drive_spec);
		if ((rc = lm_gen_lmpl_cmd(drive_spec, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_library_config: Internal "
			    "processing error encountered while processing "
			    "lmpl config command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(drive_spec);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			handle_lmpl_cmd_error(rc, "activate", "config", tid,
			    ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			free(drive_spec);
			return (LM_ERROR);
		}

		mms_trace(MMS_DEBUG, "lm_library_config: "
		    "Got successful response "
		    "for drive creation config command");

		lm_remove_lmpl_cmd(lmpl_tid, ele);

	} while (loop_stop != 1);

	free(drive_spec);

	return (LM_OK);
}
