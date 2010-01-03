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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fm/fmd_fmri.h>

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	uint8_t version;
	ssize_t size;
	char *c;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_LEGACY_SCHEME_VERSION ||
	    nvlist_lookup_string(nvl, FM_FMRI_LEGACY_HC, &c) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	c = fmd_fmri_strescape(c);
	size = snprintf(buf, buflen, "legacy-hc:///component=%s", c);
	fmd_fmri_strfree(c);

	return (size);
}

/*ARGSUSED*/
int
fmd_fmri_present(nvlist_t *nvl)
{
	return (1);
}

/*ARGSUSED*/
int
fmd_fmri_replaced(nvlist_t *nvl)
{
	return (FMD_OBJ_STATE_UNKNOWN);
}

/*ARGSUSED*/
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	return (0);
}
