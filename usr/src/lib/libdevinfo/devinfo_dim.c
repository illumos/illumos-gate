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

#include "libdevinfo.h"
#include <strings.h>
#include <sys/modctl.h>

/*
 *
 * This file contains interfaces to translate <driver><instance><minorname>
 * information into /devices and /dev paths.  It does this using interfaces to
 * the kernel instance tree so that it can provide translations for devices
 * which are no longer present. An example consumer of these interfaces is
 * iostat(8) - which shows, in its first iteration, activity since reboot.
 * With persistant kstats, a device which was busy a long time ago can still
 * have a decaying presence in iostat output, and that output, when '-n' is
 * used, should show the public name.
 */

typedef	struct {
	di_devlink_handle_t	i_devlink_hdl;
} *idim_t;

di_dim_t
di_dim_init()
{
	idim_t		idim;

	if ((idim = (idim_t)malloc(sizeof (*idim))) == NULL)
		return (NULL);
	idim->i_devlink_hdl = di_devlink_init(NULL, 0);
	if (idim->i_devlink_hdl == NULL) {
		free(idim);
		return (NULL);
	}
	return ((di_dim_t)idim);
}

void
di_dim_fini(di_dim_t dim)
{
	idim_t	idim = (idim_t)dim;

	if (idim->i_devlink_hdl) {
		(void) di_devlink_fini(&idim->i_devlink_hdl);
	}
	free(idim);
}

/*ARGSUSED*/
char *
di_dim_path_devices(di_dim_t dim, char *drv_name, int instance,
    char *minor_name)
{
	major_t	major;
	int	len;
	int	mlen;
	char	*devices;

	/* convert drv_name to major_t */
	if (modctl(MODGETMAJBIND, drv_name, strlen(drv_name) + 1, &major) < 0)
		return (NULL);

	/* find the length of the devices path given major,instance */
	if (modctl(MODGETDEVFSPATH_MI_LEN, major, instance, &len) != 0)
		return (NULL);

	/*
	 * MODGETDEVFSPATH_MI_LEN result includes '\0' termination, but we
	 * may need to add space for ":<minor_name>"
	 */
	if (minor_name)
		mlen = len + 1 + strlen(minor_name);
	else
		mlen = len;
	if ((devices = (char *)malloc(mlen)) == NULL)
		return (NULL);

	if (modctl(MODGETDEVFSPATH_MI, major, instance, len, devices) != 0) {
		free(devices);
		return (NULL);
	}

	if (minor_name) {
		/* add ':<minot_name>' to the end of /devices path */
		(void) strcat(devices, ":");
		(void) strcat(devices, minor_name);
	}
	return (devices);
}

/* di_dim_path_dev di_devlink callback */
static int
di_dim_path_dev_callback(di_devlink_t dl, void *arg)
{
	char		**devp = (char **)arg;
	char		*devpath = (char *)di_devlink_path(dl);

	if (devpath)
		*devp = strdup(devpath);
	return (DI_WALK_TERMINATE);
}

char *
di_dim_path_dev(di_dim_t dim, char *drv_name, int instance, char *minor_name)
{
	idim_t	idim = (idim_t)dim;
	char	*devices;
	char	*dev = NULL;

	/* we must have a minor_name to resolve to a public name */
	if (minor_name == NULL)
		return (NULL);

	/* convert <driver><instance><minor_name> to /devices path */
	devices = di_dim_path_devices(dim, drv_name, instance, minor_name);
	if (devices == NULL)
		return (NULL);

	/* convert /devices path to /dev path */
	(void) di_devlink_walk(idim->i_devlink_hdl, NULL,
	    devices, DI_PRIMARY_LINK, (void *)&dev, di_dim_path_dev_callback);
	free(devices);
	return (dev);
}
