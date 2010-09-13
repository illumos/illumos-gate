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

#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>
#include <string.h>
#include <sys/fm/protocol.h>

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

/*ARGSUSED*/
int
fmd_fmri_present(nvlist_t *nvl)
{
	uint8_t version;
	int err, present;
	topo_hdl_t *thp;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_SVC_SCHEME_VERSION)
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
	uint8_t version;
	int err, replaced;
	topo_hdl_t *thp;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_SVC_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	replaced = topo_fmri_replaced(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	return (replaced);
}

int
fmd_fmri_service_state(nvlist_t *nvl)
{
	uint8_t version;
	int err, service_state;
	topo_hdl_t *thp;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_DEV_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	err = 0;
	service_state = topo_fmri_service_state(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	if (err != 0)
		return (FMD_SERVICE_STATE_UNKNOWN);
	else
		return (service_state);
}

/*ARGSUSED*/
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	uint8_t version;
	int err, unusable;
	topo_hdl_t *thp;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_SVC_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	unusable = topo_fmri_unusable(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	return (unusable == 1 ? 1 : 0);
}
