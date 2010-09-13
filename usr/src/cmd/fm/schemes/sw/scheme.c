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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
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
fmd_fmri_service_state(nvlist_t *nvl)
{
	return (FMD_SERVICE_STATE_UNKNOWN);
}

/*ARGSUSED*/
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	return (0);
}
