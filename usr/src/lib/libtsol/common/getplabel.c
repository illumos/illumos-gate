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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdlib.h>
#include	<zone.h>
#include 	<tsol/label.h>
#include 	<sys/tsol/label_macro.h>
#include	<sys/types.h>
#include	<sys/zone.h>

/*
 * getplabel(3TSOL) - get process sensitivity label
 */

int
getplabel(bslabel_t *label_p)
{
	zoneid_t zoneid;

	zoneid = (int)getzoneid();
	if (zoneid == GLOBAL_ZONEID) {
		bslhigh(label_p);
	} else {
		bslabel_t *sl;

		sl = getzonelabelbyid(zoneid);
		if (sl == NULL) {
			return (-1);
		} else {
			*label_p = *sl;
			free(sl);
		}
	}
	return (0);
}
