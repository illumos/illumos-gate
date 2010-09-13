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

#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <libnvpair.h>
#include <libdevinfo.h>
#include <syslog.h>
#include <sys/param.h>
#include <errno.h>
#include <assert.h>
#include <sys/systeminfo.h>
#include <sys/modctl.h>
#include <sys/fs/sdev_impl.h>

/*
 * Private interfaces for non-global /dev profile
 */

/*
 * Allocate opaque data structure for passing profile to the kernel for
 * the given mount point.
 *
 * Note that this interface returns an empty, initialized, profile.
 * It does not return what may have been previously committed.
 */
int
di_prof_init(const char *mountpt, di_prof_t *profp)
{
	nvlist_t	*nvl;

	if (nvlist_alloc(&nvl, 0, 0))
		return (-1);

	if (nvlist_add_string(nvl, SDEV_NVNAME_MOUNTPT, mountpt)) {
		nvlist_free(nvl);
		return (-1);
	}

	*profp = (di_prof_t)nvl;
	return (0);
}

/*
 * Free space allocated by di_prof_init().
 */
void
di_prof_fini(di_prof_t prof)
{
	nvlist_free((nvlist_t *)prof);
}

/*
 * Sends profile to the kernel.
 */
int
di_prof_commit(di_prof_t prof)
{
	char	*buf = NULL;
	size_t	buflen = 0;
	int	rv;

	if (nvlist_pack((nvlist_t *)prof, &buf, &buflen, NV_ENCODE_NATIVE, 0))
		return (-1);
	rv = modctl(MODDEVNAME, MODDEVNAME_PROFILE, buf, buflen);
	free(buf);
	return (rv);
}

/*
 * Add a device or directory to profile's include list.
 *
 * Note that there is no arbitration between conflicting
 * include and exclude profile entries, most recent
 * is the winner.
 */
int
di_prof_add_dev(di_prof_t prof, const char *dev)
{
	if (nvlist_add_string((nvlist_t *)prof, SDEV_NVNAME_INCLUDE, dev))
		return (-1);
	return (0);
}

/*
 * Add a device or directory to profile's exclude list.
 * This can effectively remove a previously committed device.
 */
int
di_prof_add_exclude(di_prof_t prof, const char *dev)
{
	if (nvlist_add_string((nvlist_t *)prof, SDEV_NVNAME_EXCLUDE, dev))
		return (-1);
	return (0);
}

/*
 * Add a symlink to profile.
 */
int
di_prof_add_symlink(di_prof_t prof, const char *linkname, const char *target)
{
	nvlist_t	*nvl = (nvlist_t *)prof;
	char		*syml[2];

	syml[0] = (char *)linkname;	/* 1st entry must be the symlink */
	syml[1] = (char *)target;	/* 2nd entry must be the target */
	if (nvlist_add_string_array(nvl, SDEV_NVNAME_SYMLINK, syml, 2))
		return (-1);
	return (0);
}

/*
 * Add a name mapping to profile.
 */
int
di_prof_add_map(di_prof_t prof, const char *source, const char *target)
{
	nvlist_t	*nvl = (nvlist_t *)prof;
	char		*map[2];

	map[0] = (char *)source;	/* 1st entry must be the source */
	map[1] = (char *)target;	/* 2nd entry must be the target */
	if (nvlist_add_string_array(nvl, SDEV_NVNAME_MAP, map, 2))
		return (-1);
	return (0);
}
