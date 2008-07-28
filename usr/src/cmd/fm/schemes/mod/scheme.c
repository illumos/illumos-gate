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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>
#include <strings.h>

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	int err;
	ssize_t len;
	topo_hdl_t *thp;
	char *str;

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));

	if (topo_fmri_nvl2str(thp, nvl, &str, &err) != 0) {
		fmd_fmri_topo_rele(thp);
		return (fmd_fmri_set_errno(EINVAL));
	}

	if (buf != NULL)
		len = snprintf(buf, buflen, "%s", str);
	else
		len = strlen(str);

	topo_hdl_strfree(thp, str);
	fmd_fmri_topo_rele(thp);

	return (len);
}

/*
 * fmd_fmri_present() is called by fmadm to determine if a faulty ASRU
 * is still present in the system.  In general we don't expect to get
 * ASRUs in this scheme, so it's unlikely this routine will get called.
 * In case it does, though, we just return true by default, as we have no
 * real way to look up the component in the system configuration.
 */
/*ARGSUSED*/
int
fmd_fmri_present(nvlist_t *nvl)
{
	return (1);
}

/*
 * fmd_fmri_unusable() is called by fmadm to determine if a faulty ASRU
 * is usable.  In general we don't expect to get ASRUs in this scheme,
 * so it's unlikely this routine will get called.  In case it does,
 * though, we just return false by default, as we have no real way to
 * find the component or determine the component's usability.
 */
/*ARGSUSED*/
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	return (0);
}
