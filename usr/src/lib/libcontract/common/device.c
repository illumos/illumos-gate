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

#include <sys/ctfs.h>
#include <sys/contract.h>
#include <sys/contract/device.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <libnvpair.h>
#include <limits.h>
#include <sys/stat.h>
#include <libcontract.h>
#include "libcontract_impl.h"

/*
 * Device contract template routines
 */

int
ct_dev_tmpl_set_minor(int fd, char *minor)
{
	return (ct_tmpl_set_internal_string(fd, CTDP_MINOR, minor));
}

int
ct_dev_tmpl_set_aset(int fd, uint_t aset)
{
	return (ct_tmpl_set_internal(fd, CTDP_ACCEPT, aset));
}

int
ct_dev_tmpl_set_noneg(int fd)
{
	return (ct_tmpl_set_internal(fd, CTDP_NONEG, CTDP_NONEG_SET));
}

int
ct_dev_tmpl_clear_noneg(int fd)
{
	return (ct_tmpl_set_internal(fd, CTDP_NONEG, CTDP_NONEG_CLEAR));
}

int
ct_dev_tmpl_get_minor(int fd, char *buf, size_t *buflenp)
{
	int ret = ct_tmpl_get_internal_string(fd, CTDP_MINOR, buf, *buflenp);

	if (ret == -1)
		return (errno);

	if (ret >= *buflenp) {
		*buflenp = ret + 1;
		return (EOVERFLOW);
	}

	return (0);
}

int
ct_dev_tmpl_get_aset(int fd, uint_t *aset)
{
	return (ct_tmpl_get_internal(fd, CTDP_ACCEPT, aset));
}

int
ct_dev_tmpl_get_noneg(int fd, uint_t *negp)
{
	return (ct_tmpl_get_internal(fd, CTDP_NONEG, negp));
}

/*
 * Device contract event routines
 */

/*
 * No device contract specific event routines
 */


/*
 * Device contract status routines
 */

int
ct_dev_status_get_aset(ct_stathdl_t stathdl, uint_t *aset)
{
	struct ctlib_status_info *info = stathdl;

	if (info->status.ctst_type != CTT_DEVICE)
		return (EINVAL);

	if (info->nvl == NULL)
		return (ENOENT);

	return (nvlist_lookup_uint32(info->nvl, CTDS_ASET, aset));
}

int
ct_dev_status_get_noneg(ct_stathdl_t stathdl, uint_t *negp)
{
	struct ctlib_status_info *info = stathdl;

	if (info->status.ctst_type != CTT_DEVICE)
		return (EINVAL);

	if (info->nvl == NULL)
		return (ENOENT);

	return (nvlist_lookup_uint32(info->nvl, CTDS_NONEG, negp));
}

int
ct_dev_status_get_dev_state(ct_stathdl_t stathdl, uint_t *statep)
{
	struct ctlib_status_info *info = stathdl;

	if (info->status.ctst_type != CTT_DEVICE)
		return (EINVAL);

	if (info->nvl == NULL)
		return (ENOENT);

	return (nvlist_lookup_uint32(info->nvl, CTDS_STATE, statep));
}

int
ct_dev_status_get_minor(ct_stathdl_t stathdl, char **bufp)
{
	int error;
	struct ctlib_status_info *info = stathdl;

	if (bufp == NULL)
		return (EINVAL);

	if (info->status.ctst_type != CTT_DEVICE)
		return (EINVAL);

	if (info->nvl == NULL)
		return (ENOENT);

	error = nvlist_lookup_string(info->nvl, CTDS_MINOR, bufp);
	if (error != 0) {
		return (error);
	}

	return (0);
}
