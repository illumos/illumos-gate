/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/nvpair.h>
#include "libdevice.h"

static int _libdevice_debug = 0;
static const char *devctl_minorname = ":devctl";
static const char *nullptr = "<null>";
static const char *devctl_target_raw = "a,raw";

typedef enum { DEVCTL_BUS, DEVCTL_DEVICE, DEVCTL_AP, DEVCTL_CLONE,
    DEVCTL_PM_DEV, DEVCTL_PM_BUS } dc_type_t;

/*
 * devctl_hdl structures are allocated by the devctl_XX_acquire()
 * interfaces and passed to the remaining interfaces in this library.
 */
struct devctl_hdl {
	char		*opath;		/* copy of the original path */
	dc_type_t	hdltype;	/* handle type */
	int		fd;		/* nexus device node */
	char		*nodename;	/* DEVCTL_DEVICE handles only */
	char		*unitaddr;	/* DEVCTL_DEVICE handles only */
};
#define	DCP(x)	((struct devctl_hdl *)(x))

static int dc_cmd(uint_t, uint_t, struct devctl_hdl *, nvlist_t *, void *);
static devctl_hdl_t dc_mkhndl(dc_type_t, char *, uint_t, devctl_hdl_t);


#pragma init(_libdevice_init)
void
_libdevice_init()
{
	_libdevice_debug = getenv("LIBDEVICE_DEBUG") != NULL;
}

/*
 * release a devctl_hdl structure
 */
void
devctl_release(devctl_hdl_t hdl)
{
	if (_libdevice_debug)
		(void) printf("devctl_release: %p\n", (void *)hdl);

	if (hdl == NULL)
		return;

	if (DCP(hdl)->fd != -1)
		(void) close(DCP(hdl)->fd);

	if (DCP(hdl)->opath != NULL)
		free(DCP(hdl)->opath);

	if (DCP(hdl)->nodename != NULL)
		free(DCP(hdl)->nodename);

	if (DCP(hdl)->unitaddr != NULL)
		free(DCP(hdl)->unitaddr);

	free(hdl);
}

/*
 * construct a handle suitable for devctl_bus_*() operations
 */
devctl_hdl_t
devctl_bus_acquire(char *devfs_path, uint_t flags)
{
	uint_t oflags;

	if (_libdevice_debug)
		(void) printf("devctl_bus_acquire: %s (%d)\n",
			((devfs_path != NULL) ? devfs_path : nullptr), flags);

	if ((devfs_path == NULL) || ((flags != 0) && (flags != DC_EXCL))) {
		errno = EINVAL;
		return (NULL);
	}

	oflags = ((flags & DC_EXCL) != 0) ? O_EXCL|O_RDWR : O_RDWR;
	return (dc_mkhndl(DEVCTL_BUS, devfs_path, oflags, NULL));
}


/*
 * construct a handle suitable for devctl_bus_*() and
 * devctl_device_*() operations.
 */
devctl_hdl_t
devctl_device_acquire(char *devfs_path, uint_t flags)
{
	uint_t oflags;

	if (_libdevice_debug)
		(void) printf("devctl_device_acquire: %s (%d)\n",
		    ((devfs_path != NULL) ? devfs_path : nullptr), flags);

	if ((devfs_path == NULL) || ((flags != 0) && (flags != DC_EXCL))) {
		errno = EINVAL;
		return (NULL);
	}

	oflags = ((flags & DC_EXCL) != 0) ? O_EXCL|O_RDWR : O_RDWR;
	return (dc_mkhndl(DEVCTL_DEVICE, devfs_path, oflags, NULL));
}


/*
 * given a devfs (/devices) pathname to an attachment point device,
 * access the device and return a handle to be passed to the
 * devctl_ap_XXX() functions.
 */
devctl_hdl_t
devctl_ap_acquire(char *devfs_path, uint_t flags)
{
	uint_t oflags;

	if (_libdevice_debug)
		(void) printf("devctl_ap_acquire: %s (%d)\n",
		    ((devfs_path != NULL) ? devfs_path : nullptr), flags);

	if ((devfs_path == NULL) ||
	    ((flags != 0) && ((flags & DC_EXCL) != 0) &&
	    ((flags & DC_RDONLY) != 0))) {
		errno = EINVAL;
		return (NULL);
	}

	oflags = ((flags & DC_EXCL) != 0) ? O_EXCL : 0;
	oflags |= ((flags & DC_RDONLY) != 0) ? O_RDONLY : O_RDWR;

	return (dc_mkhndl(DEVCTL_AP, devfs_path, oflags, NULL));
}


/*
 * given a devfs (/devices) pathname access the device and return
 * a handle to be passed to the devctl_pm_XXX() functions.
 * The minor name ":devctl" is appended.
 */
devctl_hdl_t
devctl_pm_bus_acquire(char *devfs_path, uint_t flags)
{
	uint_t oflags;

	if (_libdevice_debug)
		(void) printf("devctl_pm_bus_acquire: %s (%d)\n",
		    ((devfs_path != NULL) ? devfs_path : nullptr), flags);

	if ((devfs_path == NULL) || ((flags != 0) && (flags != DC_EXCL))) {
		errno = EINVAL;
		return (NULL);
	}

	oflags = ((flags & DC_EXCL) != 0) ? (O_EXCL | O_RDWR) : O_RDWR;
	return (dc_mkhndl(DEVCTL_PM_BUS, devfs_path, oflags, NULL));
}


/*
 * given a devfs (/devices) pathname access the device and return
 * a handle to be passed to the devctl_pm_XXX() functions.
 * The minor name is derived from the device name.
 */
devctl_hdl_t
devctl_pm_dev_acquire(char *devfs_path, uint_t flags)
{
	uint_t oflags;

	if (_libdevice_debug)
		(void) printf("devctl_pm_dev_acquire: %s (%d)\n",
		    ((devfs_path != NULL) ? devfs_path : nullptr), flags);

	if ((devfs_path == NULL) || ((flags != 0) && (flags != DC_EXCL))) {
		errno = EINVAL;
		return (NULL);
	}

	oflags = ((flags & DC_EXCL) != 0) ? (O_EXCL | O_RDWR) : O_RDWR;
	return (dc_mkhndl(DEVCTL_PM_DEV, devfs_path, oflags, NULL));
}


/*
 * allocate and initalize the devctl_hdl structure for the
 * particular handle type.
 */
static devctl_hdl_t
dc_mkhndl(dc_type_t type, char *path, uint_t oflags, devctl_hdl_t pc)
{
	struct devctl_hdl *dcp;
	struct stat sb;
	char iocpath[MAXPATHLEN];
	char *nodename, *unitsep, *minorsep, *chop;
	char *minorname;
	size_t strlcpy_size;
	char *iocpath_dup;
	char *tok;

	if ((path == NULL) || (strlen(path) > MAXPATHLEN - 1)) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * allocate handle and make a copy of the original path
	 */
	if ((dcp = calloc(1, sizeof (*dcp))) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	if ((dcp->opath = strdup(path)) == NULL) {
		devctl_release((devctl_hdl_t)dcp);
		errno = ENOMEM;
		return (NULL);
	}

	(void) strcpy(iocpath, path);
	dcp->hdltype = type;
	dcp->fd = -1;

	/*
	 * break apart the pathname according to the type handle
	 */
	switch (type) {
	case DEVCTL_PM_BUS:
		/*
		 * chop off any minor name and concatenate the
		 * ":devctl" minor node name string.
		 */
		if ((chop = strrchr(iocpath, ':')) != NULL)
			*chop = '\0';

		if (strlcat(iocpath, devctl_minorname, MAXPATHLEN) >=
		    MAXPATHLEN) {
			devctl_release((devctl_hdl_t)dcp);
			errno = EINVAL;
			return (NULL);
		} else if (_libdevice_debug) {
			(void) printf("DEVCTL_PM_BUS: iocpath %s\n", iocpath);
		}
		break;

	case DEVCTL_PM_DEV:
		/*
		 * Chop up the last device component in the pathname.
		 * Concatenate either the device name itself, or the
		 * "a,raw" string, as the minor node name, to the iocpath.
		 */
		if ((iocpath_dup = strdup(iocpath)) == NULL) {
			devctl_release((devctl_hdl_t)dcp);
			errno = ENOMEM;
			return (NULL);
		}
		if ((chop = strrchr(iocpath_dup, '/')) == NULL) {
			devctl_release((devctl_hdl_t)dcp);
			errno = EINVAL;
			return (NULL);
		}
		*chop = '\0';
		nodename = chop + 1;

		/*
		 * remove the "@0,0" string
		 */
		tok = strtok(nodename, "@");
		if ((minorname = malloc(strlen(tok) +1)) == NULL) {
			if (_libdevice_debug)
				(void) printf("DEVCTL_PM_DEV: failed malloc for"
				    " minorname\n");
			devctl_release((devctl_hdl_t)dcp);
			errno = ENOMEM;
			return (NULL);
		}
		(void) strcpy(minorname, tok);
		if (_libdevice_debug) {
			(void) printf("DEVCTL_PM_DEV: minorname %s\n",
			    minorname);
		}

		/*
		 * construct the name of the ioctl device
		 * by concatenating either ":a,raw" or ":"minorname
		 */
		(void) strlcat(iocpath, ":", MAXPATHLEN);
		if (strcmp(minorname, "disk_chan") == 0 ||
		    strcmp(minorname, "disk_wwn") == 0 ||
		    strcmp(minorname, "disk_cdrom") == 0) {
			strlcpy_size = strlcat(iocpath, devctl_target_raw,
			    MAXPATHLEN);
		} else {
			strlcpy_size = strlcat(iocpath, minorname, MAXPATHLEN);
		}
		if (strlcpy_size >= MAXPATHLEN) {
			devctl_release((devctl_hdl_t)dcp);
			errno = EINVAL;
			return (NULL);
		} else if (_libdevice_debug) {
			(void) printf("DEVCTL_PM_DEV: iocpath %s\n",
			    iocpath);
		}
		break;

	case DEVCTL_AP:
		/*
		 * take the pathname as provided.
		 */
		break;

	case DEVCTL_BUS:
		/*
		 * chop off any minor name and concatenate the
		 * ":devctl" minor node name string.
		 */
		if ((chop = strrchr(iocpath, ':')) != NULL)
			*chop = '\0';

		if (strlcat(iocpath, devctl_minorname, MAXPATHLEN) >=
		    MAXPATHLEN) {
			devctl_release((devctl_hdl_t)dcp);
			errno = EINVAL;
			return (NULL);
		}
		break;

	case DEVCTL_CLONE:
		/*
		 * create a device handle for a new device created
		 * from a call to devctl_bus_dev_create()
		 */
		dcp->hdltype = DEVCTL_DEVICE;

		/* FALLTHRU */

	case DEVCTL_DEVICE:

		/*
		 * Chop up the last device component in the pathname.
		 * The componets are passed as nodename and unitaddr
		 * in the IOCTL data for DEVCTL ops on devices.
		 */
		if ((chop = strrchr(iocpath, '/')) == NULL) {
			devctl_release((devctl_hdl_t)dcp);
			errno = EINVAL;
			return (NULL);
		}
		*chop = '\0';

		nodename = chop + 1;
		unitsep = strchr(nodename, '@');
		minorsep = strchr(nodename, ':');

		if (unitsep == NULL) {
			devctl_release((devctl_hdl_t)dcp);
			errno = EINVAL;
			return (NULL);
		}

		/*
		 * copy the nodename and unit address
		 */
		if (((dcp->nodename = malloc(MAXNAMELEN)) == NULL) ||
		    ((dcp->unitaddr = malloc(MAXNAMELEN)) == NULL)) {
			devctl_release((devctl_hdl_t)dcp);
			errno = ENOMEM;
			return (NULL);
		}
		*unitsep = '\0';
		if (minorsep != NULL)
			*minorsep = '\0';
		(void) snprintf(dcp->nodename, MAXNAMELEN, "%s", nodename);
		(void) snprintf(dcp->unitaddr, MAXNAMELEN, "%s", unitsep+1);

		/*
		 * construct the name of the ioctl device
		 */
		if (strlcat(iocpath, devctl_minorname, MAXPATHLEN) >=
		    MAXPATHLEN) {
			devctl_release((devctl_hdl_t)dcp);
			errno = EINVAL;
			return (NULL);
		}
		break;

	default:
		devctl_release((devctl_hdl_t)dcp);
		errno = EINVAL;
		return (NULL);
	}

	if (_libdevice_debug)
		(void) printf("dc_mkhndl: iocpath %s ", iocpath);

	/*
	 * verify the devctl or ap device exists and is a
	 * character device interface.
	 */
	if (stat(iocpath, &sb) == 0) {
		if ((sb.st_mode & S_IFMT) != S_IFCHR) {
			if (_libdevice_debug)
				(void) printf(" - not character device\n");
			errno = ENODEV;
			devctl_release((devctl_hdl_t)dcp);
			return (NULL);
		}
	} else {
		/*
		 * return failure with errno value set by stat
		 */
		if (_libdevice_debug)
			(void) printf(" - stat failed\n");
		devctl_release((devctl_hdl_t)dcp);
		return (NULL);
	}

	/*
	 * if this was a new device, dup the parents handle, otherwise
	 * just open the device.
	 */
	if (type == DEVCTL_CLONE)
		dcp->fd = dup(DCP(pc)->fd);
	else
		dcp->fd = open(iocpath, oflags);

	if (dcp->fd == -1) {
		if (_libdevice_debug)
			(void) printf(" - open/dup failed %d\n", errno);
		/*
		 * leave errno as set by open/dup
		 */
		devctl_release((devctl_hdl_t)dcp);
		return (NULL);
	}

	if (_libdevice_debug)
		(void) printf(" - open success\n");

	return ((devctl_hdl_t)dcp);
}

/*
 * Power up component 0, to level MAXPWR, via a pm_raise_power() call
 */
int
devctl_pm_raisepower(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_RAISE_PWR, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_raisepower: %d\n", rv);

	return (rv);
}

/*
 * Power up component 0, to level MAXPWR, via a power_has_changed() call
 */
int
devctl_pm_changepowerhigh(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_CHANGE_PWR_HIGH, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_changepowerhigh: %d\n", rv);

	return (rv);
}

/*
 * Power down component 0, to level 0, via a pm_change_power() call
 */
int
devctl_pm_changepowerlow(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_CHANGE_PWR_LOW, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_changepowerlow: %d\n", rv);

	return (rv);
}

/*
 * mark component 0 idle
 */
int
devctl_pm_idlecomponent(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_IDLE_COMP, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_idlecomponent: %d\n", rv);

	return (rv);
}

/*
 * mark component 0 busy
 */
int
devctl_pm_busycomponent(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_BUSY_COMP, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_busycomponent: %d\n", rv);

	return (rv);
}

/*
 * test pm busy state
 */
int
devctl_pm_testbusy(devctl_hdl_t dcp, uint_t *busystate)
{
	int  rv;
	uint_t	busy_state = 0;

	if (busystate == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_BUSY_COMP_TEST, 0, DCP(dcp), NULL,
	    (void *)&busy_state);

	if (rv == -1)
		*busystate = 0;
	else
		*busystate = busy_state;

	if (_libdevice_debug)
		(void) printf("devctl_pm_bus_testbusy: rv %d busystate %x\n",
		    rv, *busystate);

	return (rv);
}

/*
 * set flag to fail DDI_SUSPEND
 */
int
devctl_pm_failsuspend(devctl_hdl_t dcp)
{
	int rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_FAIL_SUSPEND, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_failsuspend: %d\n", rv);
	return (rv);
}

int
devctl_pm_bus_teststrict(devctl_hdl_t dcp, uint_t *strict)
{
	int  rv;
	uint_t	strict_state;

	if (strict == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_BUS_STRICT_TEST, 0, DCP(dcp), NULL,
	    (void *)&strict_state);

	if (rv == -1)
		*strict = 0;
	else
		*strict = strict_state;

	if (_libdevice_debug)
		(void) printf("devctl_pm_bus_teststrict: rv %d strict %x\n",
		    rv, *strict);

	return (rv);
}

/*
 * issue prom_printf() call
 */
int
devctl_pm_device_promprintf(devctl_hdl_t dcp)
{
	int rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_PROM_PRINTF, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_device_promprintf: %d\n", rv);
	return (rv);
}

/*
 * set flag to power up the device via
 * pm_power_has_changed() calls vs.
 * pm_raise_power(), during DDI_RESUME
 */
int
devctl_pm_device_changeonresume(devctl_hdl_t dcp)
{
	int rv;

	if (dcp == NULL || (DCP(dcp)->hdltype != DEVCTL_PM_DEV &&
	    DCP(dcp)->hdltype != DEVCTL_PM_BUS)) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_PWR_HAS_CHANGED_ON_RESUME, 0,
	    DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_device_changeonresume: %d\n", rv);
	return (rv);
}

/*
 * issue DEVCTL_PM_NO_LOWER_POWER to clear the LOWER_POWER_FLAG
 * flag: pm_lower_power() will not be called on device detach
 */
int
devctl_pm_device_no_lower_power(devctl_hdl_t dcp)
{
	int rv;

	if (dcp == NULL || DCP(dcp)->hdltype != DEVCTL_PM_DEV) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_NO_LOWER_POWER, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_device_no_lower_power: %d\n", rv);
	return (rv);
}

/*
 * issue DEVCTL_PM_BUS_NO_INVOL ioctl to set the NO_INVOL_FLAG
 * flag: parent driver will mark itself idle twice in
 * DDI_CTLOPS_DETACH(POST)
 */
int
devctl_pm_bus_no_invol(devctl_hdl_t dcp)
{
	int rv;

	if (dcp == NULL || DCP(dcp)->hdltype != DEVCTL_PM_BUS) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_PM_BUS_NO_INVOL, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_pm_bus_no_invol: %d\n", rv);
	return (rv);
}

/*
 * Place the device ONLINE
 */
int
devctl_device_online(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || DCP(dcp)->hdltype != DEVCTL_DEVICE) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_DEVICE_ONLINE, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_device_online: %d\n", rv);

	return (rv);
}

/*
 * take device OFFLINE
 */
int
devctl_device_offline(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || DCP(dcp)->hdltype != DEVCTL_DEVICE) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_DEVICE_OFFLINE, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_device_offline: %d\n", rv);

	return (rv);
}

/*
 * take the device OFFLINE and remove its dev_info node
 */
int
devctl_device_remove(devctl_hdl_t dcp)
{
	int  rv;

	if (dcp == NULL || DCP(dcp)->hdltype != DEVCTL_DEVICE) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_DEVICE_REMOVE, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_device_remove: %d\n", rv);

	return (rv);
}


/*
 * QUIESCE the bus
 */
int
devctl_bus_quiesce(devctl_hdl_t dcp)
{
	int  rv;

	rv = dc_cmd(DEVCTL_BUS_QUIESCE, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_bus_quiesce: %d\n", rv);

	return (rv);
}

int
devctl_bus_unquiesce(devctl_hdl_t dcp)
{
	int  rv;

	rv = dc_cmd(DEVCTL_BUS_UNQUIESCE, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_bus_unquiesce: %d\n", rv);

	return (rv);
}

int
devctl_bus_reset(devctl_hdl_t dcp)
{
	int  rv;

	rv = dc_cmd(DEVCTL_BUS_RESET, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_bus_reset: %d\n", rv);

	return (rv);
}

int
devctl_bus_resetall(devctl_hdl_t dcp)
{
	int  rv;

	rv = dc_cmd(DEVCTL_BUS_RESETALL, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_bus_resetall: %d\n", rv);

	return (rv);
}

int
devctl_device_reset(devctl_hdl_t dcp)
{
	int  rv;

	rv = dc_cmd(DEVCTL_DEVICE_RESET, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_device_reset: %d\n", rv);

	return (rv);
}

int
devctl_device_getstate(devctl_hdl_t dcp, uint_t *devstate)
{
	int  rv;
	uint_t device_state;

	if (devstate == NULL) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_DEVICE_GETSTATE, 0, DCP(dcp), NULL,
	    (void *)&device_state);

	if (rv == -1)
		*devstate = 0;
	else
		*devstate = device_state;

	if (_libdevice_debug)
		(void) printf("devctl_device_getstate: rv %d state %x\n",
		    rv, *devstate);

	return (rv);
}

int
devctl_bus_getstate(devctl_hdl_t dcp, uint_t *devstate)
{
	int  rv;
	uint_t device_state;

	if (devstate == NULL) {
		errno = EINVAL;
		return (-1);
	}

	rv = dc_cmd(DEVCTL_BUS_GETSTATE, 0, DCP(dcp), NULL,
	    (void *)&device_state);

	if (rv == -1)
		*devstate = 0;
	else
		*devstate = device_state;

	if (_libdevice_debug)
		(void) printf("devctl_bus_getstate: rv %d, state %x\n",
		    rv, *devstate);

	return (rv);
}

int
devctl_bus_configure(devctl_hdl_t dcp)
{
	int  rv;

	rv = dc_cmd(DEVCTL_BUS_CONFIGURE, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_bus_configure: %d\n", rv);

	return (rv);
}

int
devctl_bus_unconfigure(devctl_hdl_t dcp)
{
	int  rv;

	rv = dc_cmd(DEVCTL_BUS_UNCONFIGURE, 0, DCP(dcp), NULL, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_bus_unconfigure: %d\n", rv);

	return (rv);
}

/*
 * devctl_bus_dev_create() - create a new child device
 * Attempt to construct and attach a new child device below a
 * bus nexus (dcp).  The device is defined using the devctl_ddef_*()
 * routines to specify the set of bus-specific properties required
 * to initalize and attach the device.
 */
int
devctl_bus_dev_create(devctl_hdl_t dcp, devctl_ddef_t ddef_hdl,
    uint_t flags, devctl_hdl_t *new_dcp)
{
	char devname[MAXNAMELEN];
	char devpath[MAXPATHLEN];
	int  rv = 0;

	if (dcp == NULL || ddef_hdl == NULL) {
		errno = EINVAL;
		return (-1);
	}

	(void) memset(devname, 0, sizeof (devname));
	rv = dc_cmd(DEVCTL_BUS_DEV_CREATE, flags, DCP(dcp),
	    (nvlist_t *)ddef_hdl, devname);

	/*
	 * construct a device handle for the new device
	 */
	if ((rv == 0) && (new_dcp != NULL)) {
		char *minorname, *lastslash;

		(void) memset(devpath, 0, sizeof (devpath));
		(void) strcat(devpath, DCP(dcp)->opath);

		/*
		 * Take the pathname of the parent device, chop off
		 * any minor name info, and append the name@addr of
		 * the new child device.
		 * Call dc_mkhndl() with this constructed path and
		 * the CLONE handle type to create a new handle which
		 * references the new child device.
		 */
		lastslash = strrchr(devpath, '/');
		if (*(lastslash + 1) == '\0') {
			*lastslash = '\0';
		} else {
			if ((minorname = strchr(lastslash, ':')) != NULL)
				*minorname = '\0';
		}
		(void) strcat(devpath, "/");
		(void) strlcat(devpath, devname, MAXPATHLEN);
		*new_dcp = dc_mkhndl(DEVCTL_CLONE, devpath, 0, dcp);
		if (*new_dcp == NULL)
			rv = -1;
	}

	return (rv);
}

int
devctl_ap_connect(devctl_hdl_t dcp, nvlist_t *ap_data)
{
	int  rv;

	rv = dc_cmd(DEVCTL_AP_CONNECT, 0, DCP(dcp), ap_data, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_ap_connect: %d\n", rv);

	return (rv);
}

int
devctl_ap_disconnect(devctl_hdl_t dcp, nvlist_t *ap_data)
{
	int  rv;

	rv = dc_cmd(DEVCTL_AP_DISCONNECT, 0, DCP(dcp), ap_data, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_ap_disconnect: %d\n", rv);

	return (rv);
}

int
devctl_ap_insert(devctl_hdl_t dcp, nvlist_t *ap_data)
{
	int  rv;

	rv = dc_cmd(DEVCTL_AP_INSERT, 0, DCP(dcp), ap_data, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_ap_insert: %d\n", rv);

	return (rv);
}

int
devctl_ap_remove(devctl_hdl_t dcp, nvlist_t *ap_data)
{
	int  rv;

	rv = dc_cmd(DEVCTL_AP_REMOVE, 0, DCP(dcp), ap_data, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_ap_remove: %d\n", rv);

	return (rv);
}

int
devctl_ap_configure(devctl_hdl_t dcp, nvlist_t *ap_data)
{
	int  rv;

	rv = dc_cmd(DEVCTL_AP_CONFIGURE, 0, DCP(dcp), ap_data, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_ap_configure: %d\n", rv);

	return (rv);
}

int
devctl_ap_unconfigure(devctl_hdl_t dcp, nvlist_t *ap_data)
{
	int  rv;

	rv = dc_cmd(DEVCTL_AP_UNCONFIGURE, 0, DCP(dcp), ap_data, NULL);

	if (_libdevice_debug)
		(void) printf("devctl_ap_unconfigure: %d\n", rv);

	return (rv);
}

int
devctl_ap_getstate(devctl_hdl_t dcp, nvlist_t *ap_data,
    devctl_ap_state_t *apstate)
{
	int  rv;
	devctl_ap_state_t ap_state;

	rv = dc_cmd(DEVCTL_AP_GETSTATE, 0, DCP(dcp), ap_data,
	    (void *)&ap_state);

	if (rv == -1)
		(void) memset(apstate, 0, sizeof (struct devctl_ap_state));
	else
		*apstate = ap_state;

	if (_libdevice_debug)
		(void) printf("devctl_ap_getstate: %d\n", rv);

	return (rv);
}

/*
 * Allocate a device 'definition' handle, in reality a list of
 * nvpair data.
 */
/* ARGSUSED */
devctl_ddef_t
devctl_ddef_alloc(char *nodename, int flags)
{

	nvlist_t *nvlp;

	if ((nodename == NULL) || *nodename == '\0') {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * allocate nvlist structure which is returned as an
	 * opaque handle to the caller.  If this fails, return
	 * NULL with errno left set to the value
	 */
	if (nvlist_alloc(&nvlp, NV_UNIQUE_NAME_TYPE, 0) != 0) {
		errno = ENOMEM;
		return (NULL);
	}

	/*
	 * add the nodename of the new device to the list
	 */
	if (nvlist_add_string(nvlp, DC_DEVI_NODENAME, nodename) != 0) {
		nvlist_free(nvlp);
		errno = ENOMEM;
		return (NULL);
	}

	if (_libdevice_debug)
		(void) printf("devctl_ddef_alloc: node %s nvp %p\n", nodename,
		    (void *)nvlp);

	return ((devctl_ddef_t)nvlp);
}

/*
 * free the definition handle
 */
void
devctl_ddef_free(devctl_ddef_t ddef_hdl)
{
	if (_libdevice_debug)
		(void) printf("devctl_ddef_free: nvp %p\n", (void *)ddef_hdl);

	if (ddef_hdl != NULL) {
		nvlist_free((nvlist_t *)ddef_hdl);
	}
}

/*
 * define an integer property
 */
int
devctl_ddef_int(devctl_ddef_t ddef_hdl, char *name, int32_t value)
{

	int rv;

	if (ddef_hdl == NULL || name == NULL || *name == '\0') {
		errno = EINVAL;
		return (-1);
	}

	rv = nvlist_add_int32((nvlist_t *)ddef_hdl, name, value);

	if (_libdevice_debug)
		(void) printf("devctl_ddef_int: rv %d nvp %p name %s val %d\n",
		    rv, (void *)ddef_hdl, name, value);

	return (rv);
}

/*
 * define an integer array property
 */
int
devctl_ddef_int_array(devctl_ddef_t ddef_hdl, char *name, int nelements,
    int32_t *value)
{
	int rv, i;

	if (ddef_hdl == NULL || name == NULL || *name == '\0') {
		errno = EINVAL;
		return (-1);
	}

	rv = nvlist_add_int32_array((nvlist_t *)ddef_hdl, name, value,
	    nelements);

	if (_libdevice_debug) {
		(void) printf("devctl_ddef_int_array: rv %d nvp %p name %s: ",
		    rv, (void *)ddef_hdl, name);
		for (i = 0; i < nelements; i++)
			(void) printf("0x%x ", value[i]);
		(void) printf("\n");
	}

	return (rv);
}

/*
 * define a string property
 */
int
devctl_ddef_string(devctl_ddef_t ddef_hdl, char *name, char *value)
{
	int rv;

	if (ddef_hdl == NULL || name == NULL || *name == '\0') {
		errno = EINVAL;
		return (-1);
	}

	rv = nvlist_add_string((nvlist_t *)ddef_hdl, name, value);

	if (_libdevice_debug)
		(void) printf("devctl_ddef_string: rv %d nvp %p %s=\"%s\"\n",
		    rv, (void *)ddef_hdl, name, value);

	return (rv);
}

/*
 * define a string array property
 */
int
devctl_ddef_string_array(devctl_ddef_t ddef_hdl, char *name, int nelements,
    char **value)
{
	int rv, i;

	if (ddef_hdl == NULL || name == NULL || *name == '\0') {
		errno = EINVAL;
		return (-1);
	}

	rv = nvlist_add_string_array((nvlist_t *)ddef_hdl, name,
	    value, nelements);

	if (_libdevice_debug) {
		(void) printf("devctl_ddef_string_array: rv %d nvp %p "
		    "name %s:\n", rv, (void *)ddef_hdl, name);
		for (i = 0; i < nelements; i++)
			(void) printf("\t%d: \"%s\"\n", i, value[i]);
	}
	return (rv);
}

/*
 * define a byte array property
 */
int
devctl_ddef_byte_array(devctl_ddef_t ddef_hdl, char *name, int nelements,
    uchar_t *value)
{
	int rv;

	if (ddef_hdl == NULL || name == NULL || *name == '\0') {
		errno = EINVAL;
		return (-1);
	}

	rv = nvlist_add_byte_array((nvlist_t *)ddef_hdl, name, value,
	    nelements);

	return (rv);
}

/*
 * return the pathname which was used to acquire the handle
 */
char *
devctl_get_pathname(devctl_hdl_t dcp, char *pathbuf, size_t bufsz)
{
	if (dcp == NULL || pathbuf == NULL || bufsz == 0) {
		errno = EINVAL;
		return (NULL);
	}

	(void) snprintf(pathbuf, bufsz, "%s", DCP(dcp)->opath);
	return (pathbuf);
}


/*
 * execute the IOCTL request
 */
static int
dc_cmd(uint_t cmd, uint_t flags, struct devctl_hdl *dcp, nvlist_t *ulp,
    void *retinfo)
{
	struct devctl_iocdata iocdata;
	int  rv = 0;

	if (_libdevice_debug)
		(void) printf("dc_cmd: %x dcp %p ulp %p flags %x rv %p\n", cmd,
		    (void *)dcp, (void *)ulp, flags, retinfo);

	if ((dcp == NULL) || (DCP(dcp)->fd == -1)) {
		errno = EINVAL;
		return (-1);
	}

	(void) memset(&iocdata, 0, sizeof (struct devctl_iocdata));

	/*
	 * if there was any user supplied data in the form of a nvlist,
	 * pack the list prior to copyin.
	 */
	if (ulp != NULL) {
		if (rv = nvlist_pack(ulp, (char **)&iocdata.nvl_user,
		    &iocdata.nvl_usersz, NV_ENCODE_NATIVE, 0)) {
			/*
			 * exit with errno set by nvlist_pack()
			 */
			goto exit;
		}
	} else {
		iocdata.nvl_user = NULL;
		iocdata.nvl_usersz = 0;
	}

	/*
	 * finish initalizing the request and execute the IOCTL
	 */
	iocdata.cmd = cmd;
	iocdata.flags = flags;
	iocdata.c_nodename = dcp->nodename;
	iocdata.c_unitaddr = dcp->unitaddr;
	iocdata.cpyout_buf = retinfo;
	rv = ioctl(dcp->fd, cmd, &iocdata);
	if (rv < 0 && _libdevice_debug) {
		(void) printf("dc_cmd: exited with rv %d, errno(%d):%s\n",
		    rv, errno, strerror(errno));
	}

exit:
	if (iocdata.nvl_user != NULL)
		free(iocdata.nvl_user);

	return (rv);
}
