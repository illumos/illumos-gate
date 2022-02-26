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

/*
 * This routine should be kept in sync with the built-in version provided
 * as part of fmd(8) itself -- see usr/src/cmd/fm/fmd/common/fmd_scheme.c
 */
ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	char *name;

	if (nvlist_lookup_string(nvl, FM_FMRI_FMD_NAME, &name) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	return (snprintf(buf, buflen,
	    "%s:///module/%s", FM_FMRI_SCHEME_FMD, name));
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
