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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/nvpair.h>
#include <cmd.h>
#include <errno.h>
#include <string.h>
#include <sys/fm/util.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>


/*
 * Set-up and validate the members of an hc fmri according to;
 *
 *	Member name		Type		Value
 *	===================================================
 *	version			uint8_t		0
 *	auth			nvlist_t	<auth>
 *	hc-name			string		<name>
 *	hc-id			string		<id>
 *
 * Note that auth and hc-id are optional members.
 */

#define	HC_MAXPAIRS	20
#define	HC_MAXNAMELEN	50

static int
cmd_fmri_hc_set_common(nvlist_t *fmri, int version, const nvlist_t *auth)
{
	if (version != FM_HC_SCHEME_VERSION) {
		return (0);
	}

	if (nvlist_add_uint8(fmri, FM_VERSION, version) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC) != 0) {
		return (0);
	}

	if (auth != NULL && nvlist_add_nvlist(fmri, FM_FMRI_AUTHORITY,
	    (nvlist_t *)auth) != 0) {
		return (0);
	}

	return (1);
}

int
cmd_fmri_hc_set(fmd_hdl_t *hdl, nvlist_t *fmri, int version,
    const nvlist_t *auth, nvlist_t *snvl, int npairs, ...)
{
	nvlist_t *pairs[HC_MAXPAIRS];
	va_list ap;
	int err = 0;
	int i, j;

	if (!cmd_fmri_hc_set_common(fmri, version, auth))
		return (1);

	npairs = MIN(npairs, HC_MAXPAIRS);

	va_start(ap, npairs);
	for (i = 0; i < npairs; i++) {
		const char *name = va_arg(ap, const char *);
		uint32_t id = va_arg(ap, uint32_t);
		char idstr[11];

		(void) snprintf(idstr, sizeof (idstr), "%u", id);

		if (nvlist_alloc(&pairs[i], NV_UNIQUE_NAME, 0) != 0) {
			fmd_hdl_debug(hdl, "nvlist_alloc failed\n");
			goto cleanup;
		}

		err |= nvlist_add_string(pairs[i], FM_FMRI_HC_NAME, name);
		err |= nvlist_add_string(pairs[i], FM_FMRI_HC_ID, idstr);
	}
	va_end(ap);

	err |= nvlist_add_string(fmri, FM_FMRI_HC_ROOT, "");
	err |= nvlist_add_uint32(fmri, FM_FMRI_HC_LIST_SZ, npairs);
	err |= nvlist_add_nvlist_array(fmri, FM_FMRI_HC_LIST, pairs, npairs);

	if (snvl != NULL)
		err |=  nvlist_add_nvlist(fmri, FM_FMRI_HC_SPECIFIC, snvl);

cleanup:
	for (j = 0; j < i; j++)
		nvlist_free(pairs[j]);

	if (err)
		fmd_hdl_debug(hdl, "cmd_fmri_hc_set: failed to set fmri\n");

	return (err);
}
