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
#include <cmd.h>

nvlist_t *
cmd_fault_add_location(fmd_hdl_t *hdl, nvlist_t *flt, const char *locstr) {

	char *t;

	if (nvlist_lookup_string(flt, FM_FAULT_LOCATION, &t) == 0)
		return (flt); /* already has location value */
	if (nvlist_add_string(flt, FM_FAULT_LOCATION, locstr) != 0)
		fmd_hdl_error(hdl, "unable to alloc location for fault\n");
	return (flt);
}

nvlist_t *
cmd_motherboard_fru_create(fmd_hdl_t *hdl, nvlist_t *asru)
{
	nvlist_t *fru, *hcelem;
	char *serialstr, *partstr;

	if (nvlist_lookup_string(asru, FM_FMRI_HC_SERIAL_ID, &serialstr) != 0)
		serialstr = NULL;
	if (nvlist_lookup_string(asru, FM_FMRI_HC_PART, &partstr) != 0)
		partstr = NULL;

	if (nvlist_alloc(&hcelem, NV_UNIQUE_NAME, 0) != 0)
		return (NULL);

	if (nvlist_add_string(hcelem, FM_FMRI_HC_NAME, "motherboard") != 0 ||
	    nvlist_add_string(hcelem, FM_FMRI_HC_ID, "0") != 0) {
		nvlist_free(hcelem);
		return (NULL);
	}

	if (nvlist_alloc(&fru, NV_UNIQUE_NAME, 0) != 0) {
		fmd_hdl_debug(hdl, "Failed to allocate memory");
		nvlist_free(hcelem);
		return (NULL);
	}

	if (nvlist_add_uint8(fru, FM_VERSION, FM_HC_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(fru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC) != 0 ||
	    nvlist_add_string(fru, FM_FMRI_HC_ROOT, "/") != 0 ||
	    nvlist_add_uint32(fru, FM_FMRI_HC_LIST_SZ, 1) != 0 ||
	    nvlist_add_nvlist_array(fru, FM_FMRI_HC_LIST, &hcelem, 1) != 0 ||
	    (serialstr != NULL &&
	    nvlist_add_string(fru, FM_FMRI_HC_SERIAL_ID, serialstr) != 0) ||
	    (partstr != NULL &&
	    nvlist_add_string(fru, FM_FMRI_HC_PART, partstr) != 0)) {
		nvlist_free(hcelem);
		nvlist_free(fru);
		return (NULL);
	}
	nvlist_free(hcelem);
	return (fru);
}

nvlist_t *
cmd_motherboard_create_fault(fmd_hdl_t *hdl, nvlist_t *asru, const char *fltnm,
    uint_t cert)
{
	nvlist_t *mb_fru, *flt;

	mb_fru = cmd_motherboard_fru_create(hdl, asru);
	flt = cmd_nvl_create_fault(hdl, fltnm, cert, mb_fru, mb_fru, NULL);
	flt = cmd_fault_add_location(hdl, flt, "MB");
	if (mb_fru != NULL)
		nvlist_free(mb_fru);
	return (flt);
}
