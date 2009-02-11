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


#include "lm_acs.h"

#define	SL3000_30		30
#define	SL3000_50		50

#define	SL3000_MAX_DRIVE	32

#define	SL3000_CONFIG "config task [\"%d\"] scope [full] \
%s %s;"

#define	SL3000_GROUP "slotgroup [\"group 1\" \"panel 1\" none \"ordinary\"] "

static	char	*_SrcFile = __FILE__;

static acs_cap_t	acs_caps[MAX_SL3000_CAPS];
static acs_drive_t	acs_drives;

/*ARGSUSED2*/
int
lm_library_config_non_comm(int cmd_tid, char *full_str, char *tid,
    char *ret_msg)
{
	int	i;
	int	num_caps;
	char	cap_name[MAX_CAP_SIZE];
	char	*bay_str = NULL;
	char	*grp_str = NULL;

	CAPID	capid[MAX_ID];
	QU_CAP_STATUS		*cs;
	ACS_QUERY_CAP_RESPONSE	*cp;
	acs_rsp_ele_t		*acs_rsp;

	lm.lm_caps = num_caps = 1;
	lm.lm_lsms = 1;

	if (lm_num_panels(0, tid, ret_msg) != LM_OK) {
		mms_trace(MMS_ERR, "lm_library_config: Unable to obtain "
		    "number of panels in SL3000 library");
		return (LM_ERROR);
	}

	if ((lm_acs_query_cap(&acs_rsp, capid, "activate", tid, ret_msg)) ==
	    LM_ERROR) {
		mms_trace(MMS_ERR, "lm_library_config: query of number of caps "
		    "in SL3000 library failed");
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_library_config: Received final response for "
	    "acs_query_cap");

	cp = (ACS_QUERY_CAP_RESPONSE *)acs_rsp->acs_rbuf;
	if (cp->query_cap_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_library_config: response from "
		    "acs_query_cap() failed, defaulting to one cap "
		    ", status - %s", acs_status(cp->query_cap_status));
		return (LM_ERROR);
	}

	for (num_caps = 0, i = 0; i < cp->count; i++) {
		cs = &cp->cap_status[i];
		if (cs->cap_id.lsm_id.acs == lm.lm_acs)
			num_caps++;
	}
	lm.lm_caps = num_caps;

	for (i = 0; i < MAX_SL3000_CAPS; i++) {
		acs_caps[i].cap_size = MAX_SL3000_CAP_SIZE;
		acs_caps[i].cap_capid = i;
		(void) snprintf(cap_name, sizeof (cap_name),
		    "group cap%d", i);
		(void) strlcpy(acs_caps[i].cap_name, cap_name,
		    sizeof (acs_caps[i].cap_name));
		if (i < num_caps)
			acs_caps[i].cap_config = 1;
		else
			acs_caps[i].cap_config = 0;
	}

	lm.lm_port = (void *)&acs_caps[0];

	mms_trace(MMS_DEBUG, "lm_library_config: Number of caps for SL3000 "
	    "library - %d", num_caps);

	for (i = 1; i < lm.lm_panels; i++)
		bay_str = mms_strapp(bay_str, "bay [\"panel %d\" true] ", i);

	for (i = 1; i < lm.lm_panels; i++) {
		grp_str = mms_strapp(grp_str, "slotgroup [\"group %d\" "
		    "\"panel %d\" none \"ordinary\"]  ", i, i);
		if (i == 1)
			grp_str = mms_strapp(grp_str, "slotgroup [\"group "
			    "cap0\" \"panel 1\" both \"port\"] ");
	}

	acs_drives.acs_max_drive = SL3000_MAX_DRIVE;
	lm.lm_drive = (void *)&acs_drives;

	free(acs_rsp);

	if ((bay_str && grp_str) != NULL) {
		if ((snprintf(full_str, FSBUFSIZE,
		    SL3000_CONFIG, cmd_tid, bay_str, grp_str)) > FSBUFSIZE) {
			mms_trace(MMS_ERR, "lm_library_config: buffer size");
			free(bay_str);
			free(grp_str);
			return (LM_ERROR);
		}
	} else {
		mms_trace(MMS_ERR, "lm_library_config: bay_str and grp_str "
		    "null");
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_library_config: Bay, Group - %s", full_str);

	free(bay_str);
	free(grp_str);
	return (LM_OK);
}
