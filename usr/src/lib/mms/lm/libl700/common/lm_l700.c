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

#define	L700_156	156
#define	L700_156_R	168
#define	L700_216	216
#define	L700_216_R	228
#define	L700_324	324
#define	L700_324_R	336
#define	L700_384	384
#define	L700_384_R	396
#define	L700_618	618
#define	L700_618_R	630
#define	L700_678	678
#define	L700_678_R	690

#define	L700_MAX_DRIVE	40

#define	L700_CONFIG_1 "config task [\"%d\"] scope [full] \
bay [\"panel 0\" true] \
bay [\"panel 1\" true] \
bay [\"panel 2\" true] %s; "

#define	L700_CONFIG_2 "config task [\"%d\"] scope [full] \
bay [\"panel 0\" true] \
bay [\"panel 1\" true] \
bay [\"panel 2\" true] \
bay [\"panel 3\" true] %s; "

#define	L700_GROUP_1 "slotgroup [\"group 0\" \"panel 0\" none \"ordinary\"] \
slotgroup [\"group 1\" \"panel 1\" none \"ordinary\"] \
slotgroup [\"group 2\" \"panel 2\" none \"ordinary\"] \
slotgroup [\"group cap0\" \"panel 1\" both \"port\"]"

#define	L700_GROUP_1A "slotgroup [\"group 0\" \"panel 0\" none \"ordinary\"] \
slotgroup [\"group 1\" \"panel 1\" none \"ordinary\"] \
slotgroup [\"group 2\" \"panel 2\" none \"ordinary\"] \
slotgroup [\"group cap0\" \"panel 1\" both \"port\"] \
slotgroup [\"group cap1\" \"panel 1\" both \"port\"]"

#define	L700_GROUP_2 "slotgroup [\"group 0\" \"panel 0\" none \"ordinary\"] \
slotgroup [\"group 1\" \"panel 1\" none \"ordinary\"] \
slotgroup [\"group 2\" \"panel 2\" none \"ordinary\"] \
slotgroup [\"group 3\" \"panel 3\" none \"ordinary\"] \
slotgroup [\"group cap0\" \"panel 1\" both \"port\"]"

#define	L700_GROUP_2A "slotgroup [\"group 0\" \"panel 0\" none \"ordinary\"] \
slotgroup [\"group 1\" \"panel 1\" none \"ordinary\"] \
slotgroup [\"group 2\" \"panel 2\" none \"ordinary\"] \
slotgroup [\"group 3\" \"panel 3\" none \"ordinary\"] \
slotgroup [\"group cap0\" \"panel 1\" both \"port\"] \
slotgroup [\"group cap1\" \"panel 1\" both \"port\"]"

static	char	*_SrcFile = __FILE__;

static acs_cap_t	acs_caps[MAX_L700_CAPS];
static acs_drive_t	acs_drives;

int
lm_library_config_non_comm(int cmd_tid, char *full_str, char *tid,
    char *ret_msg)
{

	int	i;
	int	num_caps;
	char	cap_name[MAX_CAP_SIZE];
	const char	*bay_str;
	char	*grp_str;

	CAPID	capid[MAX_ID];
	QU_CAP_STATUS		*cs;
	ACS_QUERY_CAP_RESPONSE	*cp;
	acs_rsp_ele_t		*acs_rsp;

	lm.lm_caps = num_caps = 1;
	lm.lm_lsms = 1;

	if (lm_num_panels(0, tid, ret_msg) != LM_OK) {
		mms_trace(MMS_ERR, "lm_library_config: Unable to obtain "
		    "number of panels in L700 library");
		return (LM_ERROR);
	}

	if ((lm_acs_query_cap(&acs_rsp, capid, "activate", tid, ret_msg)) ==
	    LM_ERROR) {
		mms_trace(MMS_ERR, "lm_library_config: query of number of caps "
		    "in L700 library failed");
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

	for (i = 0; i < MAX_L700_CAPS; i++) {
		acs_caps[i].cap_size = MAX_L700_CAP_SIZE;
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

	mms_trace(MMS_DEBUG, "lm_library_config: Number of caps for L700 "
	    "library - %d", num_caps);

	if (lm.lm_panels <= 3) {
		bay_str = L700_CONFIG_1;
		if (num_caps == 1)
			grp_str = L700_GROUP_1;
		else if (num_caps == 2)
			grp_str = L700_GROUP_1A;
		else {
			mms_trace(MMS_ERR, "lm_library_config: "
			    "invalid number of "
			    "caps in a L700 library - %d", cp->count);
			lm.lm_caps = 1;
			grp_str = L700_GROUP_1;
		}
	} else {
		bay_str = L700_CONFIG_2;
		if (num_caps == 1)
			grp_str = L700_GROUP_2;
		else if (num_caps == 2)
			grp_str = L700_GROUP_2A;
		else {
			mms_trace(MMS_ERR, "lm_library_config: "
			    "invalid number of "
			    "caps in a L700 library - %d", cp->count);
			lm.lm_caps = 1;
			grp_str = L700_GROUP_1;
		}
	}

	acs_drives.acs_max_drive = L700_MAX_DRIVE;
	lm.lm_drive = (void *)&acs_drives;

	free(acs_rsp);

	(void) snprintf(full_str, FSBUFSIZE,
	    bay_str, cmd_tid, grp_str);
	mms_trace(MMS_DEBUG, "lm_library_config: Bay, Group - %s", full_str);
	return (LM_OK);
}
