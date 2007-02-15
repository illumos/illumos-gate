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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

nvlist_t *
cmd_fault_add_location(fmd_hdl_t *hdl, nvlist_t *flt, const char *locstr) {

	char *t;

	if (nvlist_lookup_string(flt, FM_FAULT_LOCATION, &t) == 0)
		return (flt); /* already has location value */
	if (nvlist_add_string(flt, FM_FAULT_LOCATION, locstr) != 0)
		fmd_hdl_error(hdl, "unable to alloc location for fault\n");
	return (flt);
}
