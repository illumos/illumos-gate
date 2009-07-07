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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <libscf.h>
#include <sys/uadmin.h>
#include <unistd.h>
#include <stdlib.h>
#include <zone.h>

int
uadmin(int cmd, int fcn, uintptr_t mdep)
{
	extern int __uadmin(int cmd, int fcn, uintptr_t mdep);
	scf_simple_prop_t *prop = NULL;
	uint8_t *ret_val = NULL;
	boolean_t update_flag = B_FALSE;
	char *fmri = "svc:/system/boot-config:default";

	if (geteuid() == 0 && getzoneid() == GLOBAL_ZONEID &&
	    (cmd == A_SHUTDOWN || cmd == A_REBOOT)) {
		prop = scf_simple_prop_get(NULL, fmri, "config",
		    "uadmin_boot_archive_sync");
		if (prop) {
			if ((ret_val = scf_simple_prop_next_boolean(prop)) !=
			    NULL)
				update_flag = (*ret_val == 0) ? B_FALSE :
				    B_TRUE;
			scf_simple_prop_free(prop);
		}

		if (update_flag == B_TRUE)
			(void) system("/sbin/bootadm update-archive");
	}

	return (__uadmin(cmd, fcn, mdep));
}
