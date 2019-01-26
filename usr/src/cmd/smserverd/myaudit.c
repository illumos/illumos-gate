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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/errno.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <sys/smedia.h>
#include <tsol/label.h>
#include "smserver.h"
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_record.h>

/* Private Functions */
static int selected(au_event_t, au_mask_t *, int);

static int audit_selected(door_data_t *);
static int audit_na_selected(door_data_t *);
static int audit_save_namask(door_data_t *door_dp);
static int audit_save_policy(door_data_t *door_dp);

/*
 * can_audit:
 *	Return 1 if audit module is loaded.
 *	Return 0 otherwise.
 *
 */
int
can_audit(void)
{
	static int auc = AUC_UNSET;
	int cond = 0;

	if (auditon(A_GETCOND, (caddr_t)&cond, sizeof (cond))) {
		auc = AUC_DISABLED;
	} else {
		auc = cond;
	}
	if (auc == AUC_DISABLED)
		return (0);
	else return (1);
}

static int
audit_save_policy(door_data_t *door_dp)
{
	uint32_t policy;

	if (auditon(A_GETPOLICY, (caddr_t)&policy, sizeof (policy))) {
		return (-1);
	}
	door_dp->audit_policy = policy;
	return (0);
}

/*
 * audit_init():
 *	Initialize variables.
 */
void
audit_init(door_data_t *door_dp)
{
	door_dp->audit_auid = (uid_t)-1;
	door_dp->audit_uid = (uid_t)-1;
	door_dp->audit_euid = (uid_t)-1;
	door_dp->audit_gid = (gid_t)-1;
	door_dp->audit_egid = (gid_t)-1;
	door_dp->audit_pid = -1;
	door_dp->audit_tid.at_port = 0;
	door_dp->audit_tid.at_type = 0;
	door_dp->audit_tid.at_addr[0] = 0;
	door_dp->audit_tid.at_addr[1] = 0;
	door_dp->audit_tid.at_addr[2] = 0;
	door_dp->audit_tid.at_addr[3] = 0;
	door_dp->audit_namask.am_success = (int)-1;
	door_dp->audit_namask.am_failure = (int)-1;
	door_dp->audit_event = 0;
	door_dp->audit_sorf = -2;
	door_dp->audit_user = NULL;
	door_dp->audit_text[0] = '\0';
	door_dp->audit_text1[0] = '\0';
	door_dp->audit_na = 0;
	door_dp->audit_asid = (au_asid_t)(-1);
	door_dp->audit_path = NULL;
}

int
audit_save_me(door_data_t	*door_dp)
{
	door_cred_t	client_cred;
	int		ret_val;
	int		i;

	ret_val = door_cred(&client_cred);
	if (ret_val == -1)
		return (ret_val);
	door_dp->audit_ap.ap_pid = client_cred.dc_pid;
	ret_val = auditon(A_GETPINFO_ADDR, (caddr_t)&door_dp->audit_ap,
	    sizeof (door_dp->audit_ap));
	if (ret_val == -1)
		return (ret_val);

	door_dp->audit_auid = door_dp->audit_ap.ap_auid;
	door_dp->audit_euid = client_cred.dc_euid;
	door_dp->audit_egid = client_cred.dc_egid;
	door_dp->audit_uid = client_cred.dc_ruid;
	door_dp->audit_gid = client_cred.dc_rgid;
	door_dp->audit_pid = client_cred.dc_pid;
	door_dp->audit_asid = door_dp->audit_ap.ap_asid;
	door_dp->audit_tid.at_port = door_dp->audit_ap.ap_termid.at_port;
	door_dp->audit_tid.at_type = door_dp->audit_ap.ap_termid.at_type;
	for (i = 0; i < (door_dp->audit_ap.ap_termid.at_type/4); i++)
		door_dp->audit_tid.at_addr[i] =
		    door_dp->audit_ap.ap_termid.at_addr[i];
	(void) audit_save_policy(door_dp);
	return (0);
}

/*
 * audit_save_namask():
 *	Save the namask using the naflags entry in the audit_control file.
 *	Return 0 if successful.
 *	Return -1, and don't change the namask, if failed.
 *	Side Effect: Sets audit_na to -1 if error, 1 if successful.
 */
static int
audit_save_namask(door_data_t *door_dp)
{
	au_mask_t mask;

	door_dp->audit_na = -1;

	/*
	 * get non-attributable system event mask from kernel.
	 */
	if (auditon(A_GETKMASK, (caddr_t)&mask, sizeof (mask)) != 0) {
		return (-1);
	}

	door_dp->audit_namask.am_success = mask.am_success;
	door_dp->audit_namask.am_failure = mask.am_failure;
	door_dp->audit_na = 1;
	return (0);
}

/*
 * audit_audit:
 *	Cut and audit record if it is selected.
 *	Return 0, if successfully written.
 *	Return 0, if not written, and not expected to write.
 *	Return -1, if not written because of unexpected error.
 */
int
audit_audit(door_data_t *door_dp)
{
	int ad;

	if (can_audit() == 0) {
		return (0);
	}

	if (door_dp->audit_na) {
		if (!audit_na_selected(door_dp)) {
			return (0);
		}
	} else if (!audit_selected(door_dp)) {
		return (0);
	}

	if ((ad = au_open()) == -1) {
		return (-1);
	}

	(void) au_write(ad, au_to_subject_ex(door_dp->audit_auid,
	    door_dp->audit_euid,
	    door_dp->audit_egid,
	    door_dp->audit_uid, door_dp->audit_gid, door_dp->audit_pid,
	    door_dp->audit_asid, &door_dp->audit_tid));
	if (is_system_labeled())
		(void) au_write(ad, au_to_mylabel());
	if (door_dp->audit_policy & AUDIT_GROUP) {

		int ng;
		int maxgrp = getgroups(0, NULL);
		gid_t *grplst = alloca(maxgrp * sizeof (gid_t));

		if ((ng = getgroups(maxgrp, grplst))) {
			(void) au_write(ad, au_to_newgroups(ng, grplst));
		}
	}
	if (strlen(door_dp->audit_text) != 0) {
		(void) au_write(ad, au_to_text(door_dp->audit_text));
	}
	if (strlen(door_dp->audit_text1) != 0) {
		(void) au_write(ad, au_to_text(door_dp->audit_text1));
	}
	if (door_dp->audit_path != NULL) {
		(void) au_write(ad, au_to_path(door_dp->audit_path));
	}
#ifdef _LP64
	(void) au_write(ad, au_to_return64((door_dp->audit_sorf == 0) ? 0 : -1,
	    (int64_t)door_dp->audit_sorf));
#else
	(void) au_write(ad, au_to_return32((door_dp->audit_sorf == 0) ? 0 : -1,
	    (int32_t)door_dp->audit_sorf));
#endif
	if (au_close(ad, 1, door_dp->audit_event) < 0) {
		(void) au_close(ad, 0, 0);
		return (-1);
	}

	return (0);
}

static int
audit_na_selected(door_data_t *door_dp)
{
	if (door_dp->audit_na == -1) {
		return (-1);
	}

	return (selected(door_dp->audit_event,
	    &door_dp->audit_namask, door_dp->audit_sorf));
}

static int
audit_selected(door_data_t *door_dp)
{

	if (door_dp->audit_uid > MAXUID) {
		(void) audit_save_namask(door_dp);
		return (audit_na_selected(door_dp));
	}

	return (selected(door_dp->audit_event,
	    &door_dp->audit_ap.ap_mask, door_dp->audit_sorf));
}

static int
selected(au_event_t e, au_mask_t *m, int sorf)
{
	int prs_sorf;

	if (sorf == 0) {
		prs_sorf = AU_PRS_SUCCESS;
	} else if (sorf == -1) {
		prs_sorf = AU_PRS_FAILURE;
	} else {
		prs_sorf = AU_PRS_BOTH;
	}

	return (au_preselect(e, m, prs_sorf, AU_PRS_REREAD));
}
