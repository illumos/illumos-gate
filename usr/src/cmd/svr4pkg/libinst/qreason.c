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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


/*
 * System includes
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>

/*
 * local pkg command library includes
 */

#include "libinst.h"
#include "messages.h"

/*
 * forward declarations
 */

static char	*qreasonNoZonename(int caller, int retcode, int started);
static char	*qreasonWithZonename(int caller, int retcode, int started);

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	qreason
 * Description:	return message describing specified "quit reason"
 * Arguments:	caller - integer describing the "caller:
 *			Caller identities:
 *			0 - pkginstall - pkgask
 *			1 - pkginstall - pkgadd
 *			2 - pkginstall - mailmsg
 *			3 - pkgremove - quitmsg
 *			4 - pkgremove - mailmsg
 *		retcode - integer return code describing "reason"
 *		includeZonename - integer describing zone for reason
 *			== 0 - do not include a zone name in the message
 *			!= 0 - include a zone name in the message
 * Returns:	char *
 * NOTE:	all messages are returned from static space that does not need
 *		to be free()ed when no longer needed
 * NOTE:	imbedded "%s"s in returned messages are consistent with the
 *		caller and zone name inclusion:
 *			0 - no %s's
 *			1 - one %s - package name
 *			2 - three %s - package name, rootpath, package instance
 *			3 - one %s - package name
 *			4 - two %s - package name, rootpath
 *		If "includeZonename" is true, an extra "%s" is added at the
 *		end of each message for the zone name to be included.
 */

char *
qreason(int caller, int retcode, int started, int includeZonename)
{
	if (includeZonename == 0) {
		return (qreasonNoZonename(caller, retcode, started));
	}

	return (qreasonWithZonename(caller, retcode, started));
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

static char *
qreasonNoZonename(int caller, int retcode, int started)
{
	switch (retcode) {
	    case  0:
	    case 10:
	    case 20:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_SUC);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_SUC0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_SUC1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_SUC0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_SUC1);
		    default:
			return (MSG_UNKREQ);
		}

	    case  1:
	    case 11:
	    case 21:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_FAIL);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_FAIL0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_FAIL1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_FAIL0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_FAIL1);
		    default:
			return (MSG_UNKREQ);
		}

	    case  2:
	    case 12:
	    case 22:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_PARFAIL);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_PARFAIL0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_PARFAIL1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_PARFAIL0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_PARFAIL1);
		    default:
			return (MSG_UNKREQ);
		}

	    case  3:
	    case 13:
	    case 23:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_USER);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_USER0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_USER1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_USER0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_USER1);
		    default:
			return (MSG_UNKREQ);
		}

	    case  4:
	    case 14:
	    case 24:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_SUA);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_SUA0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_SUA1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_SUA0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_SUA1);
		    default:
			return (MSG_UNKREQ);
		}

	    case  5:
	    case 15:
	    case 25:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_SUI);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_SUI0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_SUI1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_SUI0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_SUI1);
		    default:
			return (MSG_UNKREQ);
		}

	    case 99:
		if (started) {
			switch (caller) {
			    case 0: /* pkginstall - pkgask */
				return (MSG_RE_IEPI);
			    case 1: /* pkginstall - pkgadd */
				return (MSG_IN_IEPI0);
			    case 2: /* pkginstall - mailmsg */
				return (MSG_IN_IEPI1);
			    case 3: /* pkgremove - quitmsg */
				return (MSG_RM_IEPI0);
			    case 4: /* pkgremove - mailmsg */
				return (MSG_RM_IEPI1);
			    default:
				return (MSG_UNKREQ);
			}
		}

		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_IE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_IE0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_IE1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_IE0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_IE1);
		    default:
			return (MSG_UNKREQ);
		}

	    default:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_UNK);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_UNK0);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_UNK1);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_UNK0);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_UNK1);
		    default:
			return (MSG_UNKREQ);
		}
	}
}

static char *
qreasonWithZonename(int caller, int retcode, int started)
{
	switch (retcode) {
	    case  0:
	    case 10:
	    case 20:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_SUC_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_SUC0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_SUC1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_SUC0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_SUC1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}

	    case  1:
	    case 11:
	    case 21:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_FAIL_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_FAIL0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_FAIL1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_FAIL0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_FAIL1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}

	    case  2:
	    case 12:
	    case 22:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_PARFAIL_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_PARFAIL0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_PARFAIL1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_PARFAIL0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_PARFAIL1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}

	    case  3:
	    case 13:
	    case 23:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_USER_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_USER0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_USER1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_USER0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_USER1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}

	    case  4:
	    case 14:
	    case 24:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_SUA_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_SUA0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_SUA1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_SUA0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_SUA1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}

	    case  5:
	    case 15:
	    case 25:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_SUI_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_SUI0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_SUI1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_SUI0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_SUI1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}

	    case 99:
		if (started) {
			switch (caller) {
			    case 0: /* pkginstall - pkgask */
				return (MSG_RE_IEPI_ZONE);
			    case 1: /* pkginstall - pkgadd */
				return (MSG_IN_IEPI0_ZONE);
			    case 2: /* pkginstall - mailmsg */
				return (MSG_IN_IEPI1_ZONE);
			    case 3: /* pkgremove - quitmsg */
				return (MSG_RM_IEPI0_ZONE);
			    case 4: /* pkgremove - mailmsg */
				return (MSG_RM_IEPI1_ZONE);
			    default:
				return (MSG_UNKREQ_ZONE);
			}
		}

		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_IE_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_IE0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_IE1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_IE0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_IE1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}

	    default:
		switch (caller) {
		    case 0: /* pkginstall - pkgask */
			return (MSG_RE_UNK_ZONE);
		    case 1: /* pkginstall - pkgadd */
			return (MSG_IN_UNK0_ZONE);
		    case 2: /* pkginstall - mailmsg */
			return (MSG_IN_UNK1_ZONE);
		    case 3: /* pkgremove - quitmsg */
			return (MSG_RM_UNK0_ZONE);
		    case 4: /* pkgremove - mailmsg */
			return (MSG_RM_UNK1_ZONE);
		    default:
			return (MSG_UNKREQ_ZONE);
		}
	}
}
