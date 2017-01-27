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
 * Copyright 2017 Nexenta Systems, Inc.
 */

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ftw.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/modctl.h>
#include <strings.h>

#include <libdevinfo.h>
#include "libdevid.h"

/*
 * Get Device Id from an open file descriptor
 */
int
devid_get(int fd, ddi_devid_t *devidp)
{
	int		len = 0;
	dev_t		dev;
	struct stat	statb;
	ddi_devid_t	mydevid;

	if (fstat(fd, &statb) != 0)
		return (-1);

	/* If not char or block device, then error */
	if (!S_ISCHR(statb.st_mode) && !S_ISBLK(statb.st_mode))
		return (-1);

	/* Get the device id size */
	dev = statb.st_rdev;
	if (modctl(MODSIZEOF_DEVID, dev, &len) != 0)
		return (-1);

	/* Allocate space to return device id */
	if ((mydevid = (ddi_devid_t)malloc(len)) == NULL)
		return (-1);

	/* Get the device id */
	if (modctl(MODGETDEVID, dev, len, mydevid) != 0) {
		free(mydevid);
		return (-1);
	}

	/* Return the device id copy */
	*devidp = mydevid;
	return (0);
}

/*
 * Get the minor name
 */
int
devid_get_minor_name(int fd, char **minor_namep)
{
	int		len = 0;
	dev_t		dev;
	int		spectype;
	char		*myminor_name;
	struct stat	statb;

	if (fstat(fd, &statb) != 0)
		return (-1);

	/* If not a char or block device, then return an error */
	if (!S_ISCHR(statb.st_mode) && !S_ISBLK(statb.st_mode))
		return (-1);

	spectype = statb.st_mode & S_IFMT;
	dev = statb.st_rdev;

	/* Get the minor name size */
	if (modctl(MODSIZEOF_MINORNAME, dev, spectype, &len) != 0)
		return (-1);

	/* Allocate space for the minor name */
	if ((myminor_name = (char *)malloc(len)) == NULL)
		return (-1);

	/* Get the minor name */
	if (modctl(MODGETMINORNAME, dev, spectype, len, myminor_name) != 0) {
		free(myminor_name);
		return (-1);
	}

	/* return the minor name copy */
	*minor_namep = myminor_name;
	return (0);
}

char *
devid_str_from_path(const char *path)
{
	int		fd;
	ddi_devid_t	devid;
	char		*minor, *ret = NULL;

	if ((fd = open(path, O_RDONLY)) < 0)
		return (NULL);

	if (devid_get(fd, &devid) == 0) {
		if (devid_get_minor_name(fd, &minor) != 0)
			minor = NULL;
		ret = devid_str_encode(devid, minor);
		if (minor != NULL)
			devid_str_free(minor);
		devid_free(devid);
	}
	(void) close(fd);

	return (ret);
}

/* list element of devid_nmlist_t information */
struct nmlist {
	struct nmlist	*nl_next;
	char		*nl_devname;
	dev_t		nl_dev;
};

/* add list element to end of nmlist headed by *nlhp */
struct nmlist *
nmlist_add(struct nmlist **nlhp, char *path)
{
	struct stat	statb;
	dev_t		dev;
	struct nmlist	*nl;

	/* stat and get the devt for char or block */
	if ((stat(path, &statb) == 0) &&
	    (S_ISCHR(statb.st_mode) || S_ISBLK(statb.st_mode)))
		dev = statb.st_rdev;
	else
		dev = NODEV;

	/* find the end of the list */
	for (; (nl = *nlhp) != NULL; nlhp = &nl->nl_next)
		;

	/* allocate and initialize new entry */
	if ((nl = malloc(sizeof (*nl))) == NULL)
		return (NULL);

	if ((nl->nl_devname = strdup(path)) == NULL) {
		free(nl);
		return (NULL);
	}
	nl->nl_next = NULL;
	nl->nl_dev = dev;

	/* link new entry at end */
	*nlhp = nl;
	return (nl);
}

/* information needed by devlink_callback to call nmlist_add */
struct devlink_cbinfo {
	struct nmlist	**cbi_nlhp;
	char		*cbi_search_path;
	int		cbi_error;
};

/* di_devlink callback to add a /dev entry to nmlist */
static int
devlink_callback(di_devlink_t dl, void *arg)
{
	struct devlink_cbinfo	*cbip = (struct devlink_cbinfo *)arg;
	char			*devpath = (char *)di_devlink_path(dl);

	if (strncmp(devpath, cbip->cbi_search_path,
	    strlen(cbip->cbi_search_path)) == 0) {
		if (nmlist_add(cbip->cbi_nlhp, devpath) == NULL) {
			cbip->cbi_error = 1;
			return (DI_WALK_TERMINATE);
		}
	}
	return (DI_WALK_CONTINUE);
}

/*
 * Resolve /dev names to DI_PRIMARY_LINK, DI_SECONDARY_LINK, or both.
 * The default is to resolve to just the DI_PRIMARY_LINK.
 */
int			devid_deviceid_to_nmlist_link = DI_PRIMARY_LINK;

/*
 * Options for the devid_deviceid_to_nmlist implementation:
 *
 *   DEVICEID_NMLIST_SLINK -	reduce overhead by reuse the previous
 *				di_devlink_init.
 */
#define	DEVICEID_NMLIST_SLINK	1
int			devid_deviceid_to_nmlist_flg = 0;
static di_devlink_handle_t devid_deviceid_to_nmlist_dlh = NULL;	/* SLINK */

#define	DEVICEID_NMLIST_NRETRY	10

/*
 * Convert the specified devid/minor_name into a devid_nmlist_t array
 * with names that resolve into /devices or /dev depending on search_path.
 *
 * The man page indicates that:
 *
 *     This function traverses the file tree, starting at search_path.
 *
 * This is not true, we reverse engineer the paths relative to
 * the specified search path to avoid attaching all devices.
 */
int
devid_deviceid_to_nmlist(char *search_path, ddi_devid_t devid, char *minor_name,
    devid_nmlist_t **retlist)
{
	char			*cp;
	int			dev;
	char			*paths = NULL;
	char			*path;
	int			lens;
	di_devlink_handle_t	dlh = NULL;
	int			ret = -1;
	struct devlink_cbinfo	cbi;
	struct nmlist		*nlh = NULL;
	struct nmlist		*nl;
	devid_nmlist_t		*rl;
	int			nret;
	int			nagain = 0;
	int			err = 0;

	*retlist = NULL;

	/* verify valid search path starts with "/devices" or "/dev" */
	if ((strcmp(search_path, "/devices") == 0) ||
	    (strncmp(search_path, "/devices/", 9) == 0))
		dev = 0;
	else if ((strcmp(search_path, "/dev") == 0) ||
	    (strncmp(search_path, "/dev/", 5) == 0))
		dev = 1;
	else {
		errno = EINVAL;
		return (-1);
	}


	/* translate devid/minor_name to /devices paths */
again:	if (modctl(MODDEVID2PATHS, devid, minor_name, 0, &lens, NULL) != 0)
		goto out;
	if ((paths = (char *)malloc(lens)) == NULL)
		goto out;
	if (modctl(MODDEVID2PATHS, devid, minor_name, 0, &lens, paths) != 0) {
		if ((errno == EAGAIN) && (nagain++ < DEVICEID_NMLIST_NRETRY)) {
			free(paths);
			paths = NULL;
			goto again;
		}
		goto out;
	}

	/*
	 * initialize for /devices path to /dev path translation. To reduce
	 * overhead we reuse the last snapshot if DEVICEID_NMLIST_SLINK is set.
	 */
	if (dev) {
		dlh = devid_deviceid_to_nmlist_dlh;
		if (dlh &&
		    !(devid_deviceid_to_nmlist_flg & DEVICEID_NMLIST_SLINK)) {
			(void) di_devlink_fini(&dlh);
			dlh = devid_deviceid_to_nmlist_dlh = NULL;
		}
		if ((dlh == NULL) &&
		    ((dlh = di_devlink_init(NULL, 0)) == NULL))
				goto out;
	}

	/*
	 * iterate over all the devtspectype resolutions of the devid and
	 * convert them into the appropriate path form and add items to return
	 * to the nmlist list;
	 */
	for (path = paths; *path; path += strlen(path) + 1) {
		if (dev) {
			/* add /dev entries */
			cbi.cbi_nlhp = &nlh;
			cbi.cbi_search_path = search_path;
			cbi.cbi_error = 0;

			(void) di_devlink_walk(dlh, NULL, path,
			    devid_deviceid_to_nmlist_link,
			    (void *)&cbi, devlink_callback);
			if (cbi.cbi_error)
				goto out;
		} else {
			/* add /devices entry */
			cp = malloc(strlen("/devices") + strlen(path) + 1);
			(void) strcpy(cp, "/devices");
			(void) strcat(cp, path);
			if (strncmp(cp, search_path,
			    strlen(search_path)) == 0) {
				if (nmlist_add(&nlh, cp) == NULL) {
					free(cp);
					goto out;
				}
			}
			free(cp);
		}
	}

	/* convert from nmlist to retlist array */
	for (nl = nlh, nret = 0; nl; nl = nl->nl_next)
		nret++;
	if (nret == 0) {
		err = ENODEV;
		goto out;
	}
	if ((*retlist = calloc(nret + 1, sizeof (devid_nmlist_t))) == NULL) {
		err = ENOMEM;
		goto out;
	}
	for (nl = nlh, rl = *retlist; nl; nl = nl->nl_next, rl++) {
		rl->devname = nl->nl_devname;
		rl->dev = nl->nl_dev;
	}
	rl->devname = NULL;
	rl->dev = NODEV;

	ret = 0;

out:
	while ((nl = nlh) != NULL) {	/* free the nmlist */
		nlh = nl->nl_next;
		free(nl);
	}
	if (paths)
		free(paths);
	if (dlh) {
		if ((ret == 0) &&
		    (devid_deviceid_to_nmlist_flg & DEVICEID_NMLIST_SLINK))
			devid_deviceid_to_nmlist_dlh = dlh;
		else
			(void) di_devlink_fini(&dlh);
	}
	if (ret && *retlist)
		free(*retlist);
	if (ret && err != 0)
		errno = err;
	return (ret);
}

/*
 * Free Device Id Name List
 */
void
devid_free_nmlist(devid_nmlist_t *list)
{
	devid_nmlist_t *p = list;

	if (list == NULL)
		return;

	/* Free all the device names */
	while (p->devname != NULL) {
		free(p->devname);
		p++;
	}

	/* Free the array */
	free(list);
}
