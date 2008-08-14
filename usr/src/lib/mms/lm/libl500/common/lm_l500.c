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

#define	L500_30		30
#define	L500_50		50

#define	L500_MAX_DRIVE	18

#define	L500_CONFIG "config task [\"%d\"] scope [full] \
bay [\"panel 1\" true] %s; "

#define	L500_GROUP "slotgroup [\"group 1\" \"panel 1\" none \"ordinary\"] \
slotgroup [\"group cap0\" \"panel 1\" both \"port\"]"

static	char	*_SrcFile = __FILE__;

static acs_cap_t	acs_caps;
static acs_drive_t	acs_drives;

/*ARGSUSED2*/
int
lm_library_config_non_comm(int cmd_tid, char *full_str, char *tid,
    char *ret_msg)
{

	acs_caps.cap_size = MAX_L500_CAP_SIZE;
	acs_caps.cap_capid = 0;
	(void) strlcpy(acs_caps.cap_name, "group cap0",
	    sizeof (acs_caps.cap_name));
	acs_caps.cap_config = 1;
	lm.lm_port = (void *)&acs_caps;
	lm.lm_caps = 1;
	lm.lm_lsms = 1;

	acs_drives.acs_max_drive = L500_MAX_DRIVE;
	lm.lm_drive = (void *)&acs_drives;

	(void) snprintf(full_str, FSBUFSIZE,
	    L500_CONFIG, cmd_tid, L500_GROUP);
	mms_trace(MMS_DEBUG, "lm_library_config_non_comm: Bay, Group - %s",
	    full_str);
	return (LM_OK);
}
