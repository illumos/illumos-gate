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


/*
 * A collection of functions to ask operator questions
 *
 * These functions must be reworked when the operator interface is available
 */

#include <sys/types.h>
#include <sys/siginfo.h>
#include <sys/scsi/impl/uscsi.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/varargs.h>
#include <string.h>
#include <dm_msg.h>
#include <dm_impl.h>
#include <dm_proto.h>
#include <mms_trace.h>

static	char *_SrcFile = __FILE__;


/*
 * Function name
 *	dm_ask_reply(char *reply)
 *
 * Parameters:
 *	reply	address of reply buffer
 *
 * Description:
 *	check standard replies from operator
 *
 * Return code:
 *	DM_REP_YES
 *	DM_REP_NO
 *	DM_REP_UNATTENDED
 *	DM_REP_ABORT
 *	DM_REP_RETRY
 *	DM_REP_STRING	reply is none above.
 *
 * Note:
 *
 *
 */

int
dm_ask_reply(char *reply)
{
	int		rc;

	if (strcmp(reply, "yes") == 0) {
		rc = DM_REP_YES;
	} else if (strcmp(reply, "no") == 0) {
		rc = DM_REP_NO;
	} else if (strcmp(reply, "unattended") == 0) {
		rc = DM_REP_UNATTENDED;
	} else if (strcmp(reply, "abort") == 0) {
		rc = DM_REP_ABORT;
	} else if (strcmp(reply, "retry") == 0) {
		rc = DM_REP_RETRY;
	} else {
		rc = DM_REP_STRING;
	}

	return (rc);
}

/*
 * Function name
 *	dm_ask_preempt(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	Ask operator if reservation should be preempted
 *
 * Return code:
 *	return code from dm_ask_reply()
 *	DM_REP_ERROR	error
 *
 * Note:
 *
 *
 */

int
dm_ask_preempt(void)
{
	char		*reply = NULL;
	int		rc;

	dm_send_request(&reply, DM_6502_MSG, DM_MSG_REASON);
	if (reply == NULL) {
		return (DM_REP_ERROR);
	}
	rc = dm_ask_reply(reply);
	free(reply);
	return (rc);
}

/*
 * Function name
 *	dm_ask_freserve(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	Ask operator if DM should reserve  the  tape  unit  by   breaking
 *	reservation held by another host
 *
 * Return code:
 *	return code from dm_ask_reply()
 *	DM_REP_ERROR	error
 *
 * Note:
 *
 *
 */

int
dm_ask_freserve(void)
{
	char		*reply = NULL;
	int		rc;

	dm_send_request(&reply, DM_6502_MSG, DM_MSG_REASON);
	if (reply == NULL) {
		return (DM_REP_ERROR);
	}
	rc = dm_ask_reply(reply);
	free(reply);
	return (rc);
}

/*
 * Function name
 *	dm_ask_write_lbl(char *from, char *to, char *pcl)
 *
 * Parameters:
 *	from	from label type
 *	to	to label type
 *	pcl	cartridge PCL of new label
 *
 * Description:
 *	ask for permission to write a new VOL1 label
 *
 * Return code:
 *	0	success
 *	-1	operator replied no or error
 *
 * Note:
 *
 *
 */

int
dm_ask_write_lbl(char *from, char *to, char *pcl)
{
	int		rc;
	int		ask_lsw = 0;
	int		ask_wo = 0;
	char		*reply = NULL;

	if ((drv->drv_flags & (DRV_SWITCH_LBL | DRV_ASK_SWITCH_LBL)) == 0) {
		/* No switch labels */
		return (-1);
	}
	if ((drv->drv_flags & DRV_ASK_SWITCH_LBL) != 0) {
		ask_lsw = 1;
	}

	if ((drv->drv_flags & DRV_BLANK) == 0) {
		/* Not a blank tape */
		if (drv->drv_flags & (DRV_SWITCH_LBL | DRV_ASK_SWITCH_LBL)) {
			if ((drv->drv_flags & DRV_ASK_WRITEOVER) != 0) {
				ask_wo = 1;
			}
		} else {
			/* No writeover */
			return (-1);
		}
	}

	if (ask_lsw == 0 && ask_wo == 0) {
		/* Write label without asking */
		return (0);
	}

	if (ask_lsw == 1 && ask_wo == 1) {
		dm_send_request(&reply, DM_6520_MSG,
		    "from", from, "to", to, "pcl", pcl, DM_MSG_REASON);
	} else if (ask_lsw == 1) {
		dm_send_request(&reply, DM_6519_MSG, "from", from,
		    "to", to, DM_MSG_REASON);
	} else {
		dm_send_request(&reply, DM_6518_MSG, "pcl", pcl,
		    DM_MSG_REASON);
	}
	if (reply == NULL) {
		/* Can't get reply - means "no" */
		return (-1);
	}
	rc = dm_ask_reply(reply);
	free(reply);
	if (rc == DM_REP_ERROR) {
		/* Ask got an error, assume "no" */
		return (-1);
	}
	if (rc == DM_REP_NO) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "write label denied by operator"));
		return (-1);
	}

	/*
	 * Can write label
	 */
	return (0);
}
