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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/hypervisor_api.h>

/*
 * Wrappers to get/set the API version with Hypervisor.
 */

int
promif_set_sun4v_api_version(void *p)
{
	cell_t *ci = (cell_t *)p;
	uint64_t api_group;
	uint64_t major;
	uint64_t minor;
	uint64_t status;
	uint64_t supported_minor;

	ASSERT(ci[1] == 3);
	ASSERT(ci[2] == 2);

	api_group = (uint64_t)p1275_cell2int(ci[3]);
	major = (uint64_t)p1275_cell2int(ci[4]);
	minor = (uint64_t)p1275_cell2int(ci[5]);

	status = hv_api_set_version(api_group, major, minor, &supported_minor);

	ci[6] = p1275_int2cell(status);
	ci[7] = p1275_int2cell(supported_minor);

	return ((status == H_EOK) ? 0 : -1);
}

int
promif_get_sun4v_api_version(void *p)
{
	cell_t *ci = (cell_t *)p;
	uint64_t api_group;
	uint64_t major;
	uint64_t minor;
	uint64_t status;

	ASSERT(ci[1] == 1);
	ASSERT(ci[2] == 3);

	api_group = (uint64_t)p1275_cell2int(ci[3]);

	status = hv_api_get_version(api_group, &major, &minor);

	ci[4] = p1275_int2cell(status);
	ci[5] = p1275_int2cell(major);
	ci[6] = p1275_int2cell(minor);

	return ((status == H_EOK) ? 0 : -1);
}
