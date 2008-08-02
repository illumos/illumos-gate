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

#include <strings.h>
#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>

int
fmd_fmri_init(void)
{
	return (0);
}

void
fmd_fmri_fini(void)
{
}

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	int err;
	uint8_t version;
	ssize_t len;
	topo_hdl_t *thp;
	char *str;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_HC_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

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

int
fmd_fmri_present(nvlist_t *nvl)
{
	int err, present;
	topo_hdl_t *thp;
	nvlist_t **hcprs;
	char *nm;
	uint_t hcnprs;

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcprs, &hcnprs);
	err |= nvlist_lookup_string(hcprs[0], FM_FMRI_HC_NAME, &nm);
	if (err != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	present = topo_fmri_present(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	return (present);
}

int
fmd_fmri_replaced(nvlist_t *nvl)
{
	int err, replaced;
	topo_hdl_t *thp;
	nvlist_t **hcprs;
	char *nm;
	uint_t hcnprs;

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcprs, &hcnprs);
	err |= nvlist_lookup_string(hcprs[0], FM_FMRI_HC_NAME, &nm);
	if (err != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	replaced = topo_fmri_replaced(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	return (replaced);
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
