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

#include	<stdio.h>
#include	<stdarg.h>
#include	<ctype.h>
#include	<sys/fcntl.h>
#include	<sys/types.h>
#include	<devid.h>
#include	<ftw.h>
#include	<string.h>
#include	<mdiox.h>
#include	<sys/lvm/mdio.h>
#include 	<meta.h>
#include 	<syslog.h>
#include	<sdssc.h>
#include	<libdevinfo.h>
#include	"meta_set_prv.h"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	RAW_PATH		0x001	/* rdsk */
#define	BLOCK_PATH		0x002	/* dsk */
#define	DSK_TYPE		0x004	/* normal /dev/[r]dsk */
#define	TEST_TYPE		0x008	/* test driver path */
#define	DID_TYPE		0x010	/* cluster did path */
#define	AP_TYPE			0x020	/* should be obsolete */

typedef struct path_list {
	char			*search_path;
	char			*search_type;
	int			path_type;
} path_list_t;

/*
 * A table of the supported path types - this should ideally be generated
 * by reading the /etc/lvm/devpath file
 */
static path_list_t plist[] = {
	{"/dev/rdsk", DEVID_MINOR_NAME_ALL_CHR, RAW_PATH|DSK_TYPE},
	{"/dev/dsk", DEVID_MINOR_NAME_ALL_BLK, BLOCK_PATH|DSK_TYPE},
	{"/dev/did/rdsk", DEVID_MINOR_NAME_ALL_CHR, RAW_PATH|DID_TYPE},
	{"/dev/did/dsk", DEVID_MINOR_NAME_ALL_BLK, BLOCK_PATH|DID_TYPE},
	{"/dev/td/dsk", DEVID_MINOR_NAME_ALL_BLK, BLOCK_PATH|TEST_TYPE},
	{"/dev/td/rdsk", DEVID_MINOR_NAME_ALL_CHR, RAW_PATH|TEST_TYPE},
};
static int num = sizeof (plist)/sizeof (path_list_t);

static mddevopts_t	dev_options = 0;

/* indicate whether to print an error message or not */
static int	firsttime = 1;

#define	DEV_MATCH	0x1
#define	NAME_MATCH	0x2

#define	DEBUGON		1
#define	DEBUGOFF	2

/*
 * Debug function: to turn on devadm function debugging include DEVADM
 * in the MD_DEBUG enviroment variable: MD_DEBUG=...,DEVADM...
 */
/*PRINTFLIKE1*/
static void
mda_debug(char *format, ...)
{
	char	*p;
	static int debug_set = 0;
	va_list ap;

	if (debug_set == 0) {
		if (((p = getenv("MD_DEBUG")) != NULL) &&
		    (strstr(p, "DEVADM") != NULL))
			debug_set = DEBUGON;
		else
			debug_set = DEBUGOFF;
	}
	if (debug_set == DEBUGON) {
		va_start(ap, format);
		(void) vfprintf(stderr, format, ap);
		va_end(ap);
	}
}

/* print error messages to the terminal or syslog */
/*PRINTFLIKE1*/
static void
mda_print(char *message, ...)
{
	va_list	ap;

	va_start(ap, message);
	if (dev_options & DEV_LOG) {
		/*
		 * The program is a daemon in the sense that it
		 * is a system utility.
		 */
		(void) vsyslog((LOG_ERR | LOG_DAEMON), message, ap);
	} else {
		(void) vfprintf(stderr, message, ap);
	}
	va_end(ap);
}

/*
 * Utility to find the correct options to use for the devid search
 * based upon the path of the device.
 *
 * RETURN:
 *	-1 	Error, the path passed in is not in the table
 *      >= 0    The element number for the options within the table
 */
static int
mda_findpath(char *path)
{
	int	i = 0;

	for (i = 0; i < num; i++) {
		if (strncmp(plist[i].search_path, path,
		    strlen(plist[i].search_path)) == 0)
			return (i);
	}
	return (-1);
}

/*
 * Utility to get the path of a device
 */
static char *
mda_getpath(char *devname)
{
	char	*ptr;
	char	*pathname;
	size_t	len;

	if ((ptr = strrchr(devname, '/')) == NULL) {
		mda_debug("Invalid format: %s\n", devname);
		return (NULL);
	}
	ptr++;
	len = strlen(devname) - strlen(ptr);
	pathname = Malloc(len + 1);
	(void) strncpy(pathname, devname, len);
	pathname[len] = '\0';
	return (pathname);
}

/*
 * meta_update_devtree -- Update the /dev/md namespace for metadevices.
 *
 * Only update the specific link if a valid minor(not NODEV) is given.
 * Otherwise, update the entire /dev/md .
 */

int
meta_update_devtree(minor_t mnum)
{
	char	nodename[40];
	di_devlink_handle_t	hdl;

	/*
	 * di_devlink_init() returns once the /dev links have been
	 * updated(created or removed). If di_devlink_init returns
	 * a NULL, the link operation failed.
	 *
	 * Use the enhanced di_devlink_init interface if the mnum
	 * is available.
	 */
	if (mnum == NODEV) {
		/*
		 * NOTE: This will take a _long_ time for large numbers
		 * of metadevices.
		 */
		hdl = di_devlink_init("md", DI_MAKE_LINK);
	} else {
		/* Call di_devlink_init twice, for block and raw devices */
		(void) sprintf(nodename, "/pseudo/md@0:%lu,%lu,raw",
		    MD_MIN2SET(mnum), MD_MIN2UNIT(mnum));
		hdl = di_devlink_init(nodename, DI_MAKE_LINK);

		if (hdl == NULL)
			return (-1);
		else
			(void) di_devlink_fini(&hdl);

		(void) sprintf(nodename, "/pseudo/md@0:%lu,%lu,blk",
		    MD_MIN2SET(mnum), MD_MIN2UNIT(mnum));
		hdl = di_devlink_init(nodename, DI_MAKE_LINK);
	}

	if (hdl != NULL) {
		(void) di_devlink_fini(&hdl);
		return (0);
	}

	return (-1);
}

/*
 * update_locator_namespace -- Contains the ioctl call that will update
 *		the ctds and pathname (ie. /dev/dsk etc) within the
 *		locator block namespace.
 *
 * RETURN
 *	METADEVADM_ERR		ioctl failed and ep is updated with the error
 *	METADEVADM_SUCCESS	success
 */
static int
update_locator_namespace(
	set_t		setno,
	side_t		sideno,
	char		*devname,
	md_dev64_t	dev,
	char		*pname,
	md_error_t	*ep
)
{
	mdnm_params_t	nm;

	(void) memset(&nm, '\0', sizeof (nm));
	nm.mde = mdnullerror;
	nm.setno = setno;
	nm.side = sideno;
	nm.devname = (uintptr_t)devname;
	nm.devname_len = strlen(devname);
	nm.devt = dev;
	nm.pathname = (uintptr_t)pname;
	nm.pathname_len = strlen(pname);
	if (metaioctl(MD_IOCUPD_LOCNM, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (METADEVADM_ERR);
	}
	return (METADEVADM_SUCCESS);
}

/*
 * meta_update_namespace -- Contains the ioctl call that will update the
 * 	device name and pathname in the namespace area.
 *
 * RETURN
 *	METADEVADM_ERR		ioctl failed and ep is updated with the error
 *	METADEVADM_SUCCESS	success
 */
int
meta_update_namespace(
	set_t		setno,
	side_t		sideno,
	char		*devname,
	md_dev64_t	dev,
	mdkey_t		key,
	char		*pname,
	md_error_t	*ep
)
{
	mdnm_params_t	nm;

	(void) memset(&nm, '\0', sizeof (nm));
	nm.mde = mdnullerror;
	nm.setno = setno;
	nm.side = sideno;
	nm.devname = (uintptr_t)devname;
	nm.devname_len = strlen(devname);
	nm.mnum = meta_getminor(dev);
	nm.key = key;
	nm.pathname = (uintptr_t)pname;
	nm.pathname_len = strlen(pname);
	if (metaioctl(MD_IOCUPD_NM, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (METADEVADM_ERR);
	}
	return (METADEVADM_SUCCESS);
}

/*
 * stripS - Strip s<digits> off the end of the ctds name if it exists
 */
static void
stripS(char *name)
{
	char	*p;

	/* gobble number and 's' */
	p = name + strlen(name) - 1;
	for (; (p > name); --p) {
		if (!isdigit(*p))
			break;
	}

	if (*p == 's') {
		*p = '\0';
	}
}

/*
 * getdiskname -- to be used when scanning the input from the -u arg.
 * 	This routine will strip off input that is anything but cxtxdx.
 *	ie. it will call stripS to get rid of slice info. Will also
 *	strip off /dev/dsk, /dev/rdsk, /dev/ap/dsk, /dev/ap/rdsk,
 *	/dev/did/dsk, or /dev/did/rdsk. The caller will need to free
 *	the return value.
 *
 * RETURN
 *	 string that has the disk name in it ie. c0t0d0
 */
static char *
getdiskname(
	char	*name
)
{
	char	*p;
	char	*diskname;

	/* regular device */
	if ((strncmp(name, "/dev/dsk/", strlen("/dev/dsk/")) == 0) &&
	    (strchr((p = name + strlen("/dev/dsk/")), '/') == NULL)) {
		diskname = Strdup(p);
		stripS(diskname);
		return (diskname);
	}

	if ((strncmp(name, "/dev/rdsk/", strlen("/dev/rdsk/")) == 0) &&
	    (strchr((p = name + strlen("/dev/rdsk/")), '/') == NULL)) {
		diskname = Strdup(p);
		stripS(diskname);
		return (diskname);
	}

	if ((strncmp(name, "/dev/ap/dsk/", strlen("/dev/ap/dsk/")) == 0) &&
	    (strchr((p = name + strlen("/dev/ap/dsk/")), '/') == NULL)) {
		diskname = Strdup(p);
		stripS(diskname);
		return (diskname);
	}

	if ((strncmp(name, "/dev/ap/rdsk/", strlen("/dev/ap/rdsk/")) == 0) &&
	    (strchr((p = name + strlen("/dev/ap/rdsk/")), '/') == NULL)) {
		diskname = Strdup(p);
		stripS(diskname);
		return (diskname);
	}

	if ((strncmp(name, "/dev/did/dsk/", strlen("/dev/did/dsk/")) == 0) &&
	    (strchr((p = name + strlen("/dev/did/dsk/")), '/') == NULL)) {
		diskname = Strdup(p);
		stripS(diskname);
		return (diskname);
	}

	if ((strncmp(name, "/dev/did/rdsk/", strlen("/dev/did/rdsk/")) == 0) &&
	    (strchr((p = name + strlen("/dev/did/rdsk/")), '/') == NULL)) {
		diskname = Strdup(p);
		stripS(diskname);
		return (diskname);
	}

	diskname = Strdup(name);
	stripS(diskname);
	return (diskname);
}

/*
 * has_devid -- return the device ID for a given key
 *
 * RETURN
 *	NULL	error
 *	devid	devid found that corresponds to the given key.
 */
static ddi_devid_t
has_devid(set_t setno, side_t sideno,  mdkey_t key, md_error_t *ep)
{
	return (meta_getdidbykey(setno, sideno, key, ep));
}

/*
 * Go through the existing list of replicas and check to see
 * if their disk has moved, if so update the replica list
 *
 * RETURN
 *	-1	error
 *	 0	success
 */
static int
fix_replicanames(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	int			ret = -1;
	int			match_type = 0;
	devid_nmlist_t		*disklist = NULL;
	dev_t			small_dev = (dev_t)NODEV;
	side_t			sideno;
	set_t			setno = sp->setno;
	char			*search_path;
	int			search_number;
	char			*ctds_name;
	char			*path_name;
	int			i;

	sideno = getmyside(sp, ep);
	if (sideno == MD_SIDEWILD) {
		mda_debug("Failed to find the side number\n");
		return (-1);
	}

	if (metareplicalist(sp, MD_BASICNAME_OK | PRINT_FAST, &rlp, ep) < 0) {
		mda_debug("Unable to get a list of replicas\n");
		return (METADEVADM_ERR);
	}

	for (rl = rlp; (rl != NULL); rl = rl->rl_next) {
		md_replica_t	*r = rl->rl_repp;

		small_dev = meta_cmpldev(r->r_namep->dev);
		search_number = mda_findpath(r->r_namep->bname);
		if (search_number == -1) {
			mda_debug("replica update: invalid path: %s",
			    r->r_namep->bname);
			continue;
		} else {
			search_path = plist[search_number].search_path;
		}

		if (r->r_devid == NULL)
			continue;

		ret = meta_deviceid_to_nmlist(search_path, r->r_devid,
		    r->r_minor_name, &disklist);

		mda_debug("replica update: search_path %s\n", search_path);

		if (ret != 0) {
			/*
			 * Failed to find the disk, nothing can be done.
			 * The replica will be marked as bad later.
			 */
			mda_debug("replica update: failed to find disk %s\n",
			    r->r_namep->cname);
			continue;
		}
		mda_debug("replica update: current %s (%p)\n",
		    r->r_namep->bname, (void *) small_dev);

		/*
		 * Check to see if the returned disk matches the stored one
		 */
		for (i = 0; disklist[i].dev != NODEV; i++) {
			match_type = 0;

			mda_debug("replica update: devid list: %s (%p)\n",
			    disklist[i].devname, (void *) disklist[i].dev);

			if (disklist[i].dev == small_dev) {
				match_type |= DEV_MATCH;
			}

			if (strncmp(r->r_namep->bname, disklist[i].devname,
			    strlen(r->r_namep->bname)) == 0) {
				match_type |= NAME_MATCH;
			}

			/*
			 * break out if some sort of match is found because
			 * we already match on the devid.
			 */
			if (match_type != 0)
				break;
		}

		mda_debug("fix_replicanames: match: %x i: %d\n", match_type, i);

		if (match_type == (DEV_MATCH|NAME_MATCH)) {
			/* no change */
			mda_debug("replica update: no change %s\n",
			    disklist[i].devname);
			devid_free_nmlist(disklist);
			continue;
		}

		/* No match found - use the first entry in disklist */
		if (disklist[i].dev == NODEV)
			i = 0;

		mda_debug("replica update: reloading %s %p\n",
		    disklist[i].devname,
		    (void *)(uintptr_t)meta_expldev(disklist[i].dev));

		if (firsttime) {
			mda_print(dgettext(TEXT_DOMAIN,
			    "Disk movement detected\n"));
			mda_print(dgettext(TEXT_DOMAIN,
			    "Updating device names in Solaris Volume "
			    "Manager\n"));
			firsttime = 0;
		}

		if (dev_options & DEV_VERBOSE) {
			char	*devidstr;

			devidstr =
			    devid_str_encode(r->r_devid, r->r_minor_name);
			if (devidstr == NULL) {
				mda_print(dgettext(TEXT_DOMAIN,
				    "Failed to encode the devid\n"));
				continue;
			}
			mda_print(dgettext(TEXT_DOMAIN,
			    "%s changed to %s from device relocation "
			    "information %s\n"),
			    (char *)r->r_namep->cname, disklist[i].devname,
			    devidstr);
		}

		if (!(dev_options & DEV_NOACTION)) {
			mda_debug("Updating locator name\n");
			ctds_name = strrchr(disklist[i].devname, '/');
			ctds_name++;
			if ((path_name = mda_getpath(disklist[i].devname))
			    == NULL) {
				continue;
			}
			if (update_locator_namespace(setno, sideno,
			    ctds_name, meta_expldev(disklist[i].dev),
			    path_name, ep) != 0) {
				mda_debug("replica update: ioctl failed\n");
				if (dev_options & DEV_VERBOSE) {
					mda_print(dgettext(TEXT_DOMAIN,
					    "Failed to update locator "
					    "namespace on change from %s "
					    "to %s\n"), ctds_name,
					    disklist[i].devname);
				}
			}
		}
		Free(path_name);
		devid_free_nmlist(disklist);
	}
	metafreereplicalist(rlp);
	return (0);
}

/*
 * pathname_reload - main function for the -r option. Will reload the
 *	pathname in both the main namespace and the locator namespace.
 *	Also, checks both areas for invalid device ID's and prints them
 *	out.
 *
 *    If the set is a multi-node diskset that means there are no devid's
 *    so just return.
 *
 * RETURN
 *	METADEVADM_ERR		error
 *	METADEVADM_SUCCESS 	success
 *	METADEVADM_DEVIDINVALID	success, but invalid devids detected
 */
int
pathname_reload(
	mdsetname_t		**spp,
	set_t			setno,
	md_error_t		*ep)
{
	char			*drvnmp;
	minor_t			mnum = 0;
	md_dev64_t		dev = 0;
	mdnm_params_t		nm;
	char			*ctds_name;
	ddi_devid_t		devidp;
	md_i_didstat_t		ds;
	side_t			sideno;
	char			*search_path = NULL;
	int			search_number;
	devid_nmlist_t		*disklist = NULL;
	char			*minor_name = NULL;
	char			*devidstr = NULL;
	char			*path = NULL;
	int			ret;
	dev_t			small_dev = (dev_t)NODEV;
	int			match_type;
	char			*tmp = NULL;
	mdsetname_t		*sp = *spp;
	md_set_desc		*sd;
	int			i;

	/*
	 * Check for multi-node diskset and return if it is one.
	 */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (METADEVADM_ERR);

		if (MD_MNSET_DESC(sd))
			return (METADEVADM_SUCCESS);
	}

	/*
	 * Get the entry of the namespace via the key. To do this
	 * call MD_IOCNXTKEY until no more.
	 * For each entry in the namespace we want to check
	 * for devid and update
	 */

	(void) memset(&nm, '\0', sizeof (nm));
	nm.key = MD_KEYWILD;

	sideno = getmyside(*spp, ep);
	if (sideno == MD_SIDEWILD) {
		/* failed to find this node in the set */
		mda_debug("Failed to find the side number\n");
		return (METADEVADM_ERR);
	}

	/* LINTED */
	while (1) {
		nm.mde	= mdnullerror;
		nm.setno = setno;
		nm.side = sideno;
		/* look at each key in the namespace */
		if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde, NULL) != 0) {
			(void) mdstealerror(ep, &nm.mde);
			return (METADEVADM_ERR);
		}

		if (nm.key == MD_KEYWILD) {
			/* no more entries */
			break;
		}

		/*
		 * get the nm entry using the key. Then check to see if
		 * there's a devid associated with this entry
		 * If not, go onto next key.
		 */
		if ((nm.devname = (uintptr_t)meta_getnmentbykey(setno, sideno,
		    nm.key, &drvnmp, &mnum, &dev, ep)) == NULL) {
			mda_debug("pathname_reload: no name for key: %d\n",
			    nm.key);
			continue;
		}

		mda_debug("pathname_reload: examining %s\n",
		    (char *)(uintptr_t)nm.devname);

		if ((devidp = has_devid(setno, sideno, nm.key, ep)) == NULL) {
			/* metadevices do not have devid's in them */
			mda_debug("pathname_reload: no devid for %s\n",
			    (char *)(uintptr_t)nm.devname);
			/* Clear error if no devid and go to next nm entry */
			mdclrerror(ep);
			continue;
		}

		if ((minor_name = meta_getdidminorbykey(setno, sideno,
		    nm.key, ep)) == NULL) {
			/*
			 * In theory this is impossible because if the
			 * devidp is non-null then the minor_name has
			 * already been looked up.
			 */
			mda_debug("No minor name for %s\n",
			    (char *)(uintptr_t)nm.devname);
			free(devidp);
			continue;
		}
		/*
		 * If there is a devid then we have a real device that
		 * could have moved.
		 */
		devidstr = devid_str_encode(devidp, minor_name);
		if (devidstr == NULL) {
			mda_debug("Failed to encode the devid\n");
			free(devidp);
			continue;
		}
		mda_debug("devid: %s\n", devidstr);

		/*
		 * Find the search path that should be used. This is an
		 * optimization to try and prevent a search for the complete
		 * /dev namespace.
		 */
		search_number = mda_findpath((char *)(uintptr_t)nm.devname);
		if (search_number == -1) {
			search_path = "/dev";
		} else {
			search_path = plist[search_number].search_path;
		}

		/* now look for the disk name using the devid */
		ret = meta_deviceid_to_nmlist(search_path, devidp,
		    minor_name, &disklist);
		free(devidp);

		if (ret != 0) {
			/*
			 * Failed to find the disk
			 */
			devid_str_free(devidstr);
			continue;
		}

		small_dev = meta_cmpldev(dev);
		mda_debug("Old device lookup: %s (%p)\n",
		    (char *)(uintptr_t)nm.devname, (void *)small_dev);

		/*
		 * Check to see if the returned disk matches the stored one
		 */
		for (i = 0; disklist[i].dev != NODEV; i++) {
			match_type = 0;
			mda_debug("From devid lookup: %s (%p)\n",
			    (char *)disklist[i].devname,
			    (void *)disklist[i].dev);

			if (disklist[i].dev == small_dev) {
				match_type |= DEV_MATCH;
			}

			if (strncmp((char *)(uintptr_t)nm.devname,
			    disklist[i].devname,
			    strlen((char *)(uintptr_t)nm.devname)) == 0) {
				mda_debug("Name match: %s and %s (%d)\n",
				    disklist[i].devname,
				    (char *)(uintptr_t)nm.devname,
				    strlen((char *)(uintptr_t)nm.devname));
				match_type |= NAME_MATCH;
			}

			if (match_type == (DEV_MATCH|NAME_MATCH))
				break;
		}

		if (match_type == (DEV_MATCH|NAME_MATCH)) {
			/* no change */
			devid_str_free(devidstr);
			mda_debug("All matched %s\n", disklist[i].devname);
			devid_free_nmlist(disklist);
			continue;
		}

		/* No match found - use the first entry in disklist */
		i = 0;

		if (firsttime) {
			mda_print(dgettext(TEXT_DOMAIN,
			    "Disk movement detected\n"));
			mda_print(dgettext(TEXT_DOMAIN,
			    "Updating device names in "
			    "Solaris Volume Manager\n"));
			firsttime = 0;
		}
		if (dev_options & DEV_VERBOSE) {
			mda_print(dgettext(TEXT_DOMAIN,
			    "%s changed to %s from device relocation "
			    "information %s\n"),
			    (char *)(uintptr_t)nm.devname, disklist[i].devname,
			    devidstr);
		}
		devid_str_free(devidstr);

		/* need to build up the path of the disk */
		if ((path = Strdup(disklist[i].devname)) == NULL) {
			mda_debug("Failed to duplicate path: %s\n",
			    disklist[i].devname);
			devid_free_nmlist(disklist);
			continue;
		}
		if ((tmp = strrchr(path, '/')) == NULL) {
			mda_debug("Failed to parse %s\n", path);
			devid_free_nmlist(disklist);
			Free(path);
			continue;
		}
		tmp += sizeof (char);
		*tmp = '\0';

		if ((ctds_name = strrchr(disklist[i].devname, '/')) == NULL) {
			mda_debug("Failed to parse ctds name: %s\n",
			    disklist[i].devname);
			devid_free_nmlist(disklist);
			Free(path);
			continue;
		}
		ctds_name += sizeof (char);

		mda_debug("Reloading disk %s %s %p\n",
		    ctds_name, path,
		    (void *)(uintptr_t)meta_expldev(disklist[i].dev));

		if (!(dev_options & DEV_NOACTION)) {
			/* Something has changed so update the namespace */
			if (meta_update_namespace(setno, sideno, ctds_name,
			    meta_expldev(disklist[i].dev), nm.key, path,
			    ep) != 0) {
				mda_debug("Failed to update namespace\n");
				if (dev_options & DEV_VERBOSE) {
					mda_print(dgettext(TEXT_DOMAIN,
					    "Failed to update namespace on "
					    "change from %s to %s\n"),
					    ctds_name, disklist[i].devname);
				}
			}
		}
		devid_free_nmlist(disklist);
		Free(path);
	}

	if (fix_replicanames(*spp, ep) == -1)
		mda_debug("Failed to update replicas\n");

	/*
	 * check for invalid device id's
	 */
	(void) memset(&ds, '\0', sizeof (ds));
	ds.setno = setno;
	ds.side = sideno;
	ds.mode = MD_FIND_INVDID;
	/* get count of number of invalid device id's */
	if (metaioctl(MD_IOCDID_STAT, &ds, &ds.mde, NULL) != 0) {
		(void) mdstealerror(ep, &ds.mde);
		return (METADEVADM_ERR);
	}
	if (ds.cnt != 0) {
		char	*ctdptr, *ctdp;
		/*
		 * we have some invalid device id's so we need to
		 * print them out
		 */
		ds.mode = MD_GET_INVDID;
		/* malloc buffer for kernel to place devid list into */
		if ((ctdptr = (char *)Malloc((ds.cnt * ds.maxsz) + 1)) == 0) {
			return (METADEVADM_ERR);
		}
		ds.ctdp = (uintptr_t)ctdptr;
		/* get actual list of invalid device id's */
		if (metaioctl(MD_IOCDID_STAT, &ds, &ds.mde, NULL) != 0) {
			Free(ctdptr);
			(void) mdstealerror(ep, &ds.mde);
			return (METADEVADM_ERR);
		}

		/* print out the invalid devid's */
		mda_print(dgettext(TEXT_DOMAIN,
		    "Invalid device relocation information "
		    "detected in Solaris Volume Manager\n"));
		mda_print(dgettext(TEXT_DOMAIN,
		    "Please check the status of the following disk(s):\n"));
		ctdp = (char *)(uintptr_t)ds.ctdp;
		while (*ctdp != NULL) {
			mda_print("\t%s\n", ctdp);
			ctdp += ds.maxsz;
		}
		Free(ctdptr);
		return (METADEVADM_DEVIDINVALID);
	}
	return (METADEVADM_SUCCESS);
}

/*
 * replica_update_devid - cycle through the replica list, rlp, and
 *  update the device ids on all of the replicas that are on the
 *  device specified by lp. A side effect is to update the value of
 *  cdevidpp to contain the character representation of the device
 *  id before updating if it is not already set.
 *
 * RETURN
 *	METADEVADM_ERR		error
 *	METADEVADM_SUCCESS	success
 */
static int
replica_update_devid(
	md_replicalist_t *rlp,
	mddrivename_t	*dnp,
	set_t		setno,
	char		**cdevidpp,
	md_error_t	*ep
)
{
	mddb_config_t		db_c;
	md_replicalist_t	*rl;
	ddi_devid_t		devidp;
	int			ret;

	if (cdevidpp == NULL)
		return (METADEVADM_ERR);

	ret = devid_str_decode(dnp->devid, &devidp, NULL);
	if (ret != 0) {
		/* failed to encode the devid */
		mda_debug("Failed to decode %s into a valid devid\n",
		    dnp->devid);
		return (METADEVADM_ERR);
	}

	/* search replica list for give ctd name */
	for (rl = rlp; (rl != NULL); rl = rl->rl_next) {
		md_replica_t    *r = rl->rl_repp;
		mdname_t	*rnp = r->r_namep;

		if (strncmp(rnp->cname, dnp->cname, strlen(dnp->cname)) == 0) {

			/* found the replica, now grab the devid */
			if (*cdevidpp == NULL) {
				*cdevidpp = devid_str_encode(r->r_devid, NULL);
			}

			if (*cdevidpp == NULL) {
				devid_free(devidp);
				return (METADEVADM_ERR);
			}

			mda_debug("Updating replica %s, set %d, old devid %s\n",
			    rnp->cname, setno, *cdevidpp);

			if (dev_options & DEV_VERBOSE) {
				mda_print(dgettext(TEXT_DOMAIN,
				    "Updating replica %s of set number %d from "
				    "device id %s to device id %s\n"),
				    rnp->cname, setno, *cdevidpp, dnp->devid);
			}

			(void) memset(&db_c, '\0', sizeof (db_c));

			db_c.c_setno = setno;
			db_c.c_devt = rnp->dev;

			if (!(dev_options & DEV_NOACTION)) {

				mda_debug("Updating replica\n");

				/*
				 * call into kernel to update lb
				 * namespace device id
				 * of given devt
				 */
				if (metaioctl(MD_DB_SETDID, &db_c,
				    &db_c.c_mde, NULL) != 0) {
					devid_free(devidp);
					(void) mdstealerror(ep, &db_c.c_mde);
					return (METADEVADM_ERR);
				}
			}

		}
	}
	devid_free(devidp);
	return (METADEVADM_SUCCESS);
}

/*
 * devid_update -- main routine for the -u option. Will update both the
 * 	namespace and the locator block with the correct devid for the
 * 	disk specified.
 *
 * RETURN
 *	METADEVADM_ERR		error
 *	METADEVADM_SUCCESS	success
 */
static int
devid_update(
	mdsetname_t	**spp,
	set_t		setno,
	char		*ctd,
	md_error_t	*ep
)
{
	md_drive_desc		*dd, *ddp;
	mddrivename_t		*dnp;
	mdnm_params_t		nm;
	ddi_devid_t		devidp;
	side_t			side;
	char			*old_cdevidp = NULL;
	md_replicalist_t	*rlp = NULL;
	int			rval = METADEVADM_ERR;
	mdname_t		*np = NULL;
	uint_t			rep_slice;
	char			*pathname = NULL;
	char			*diskname = NULL;
	int			fd = -1;
	int			len;
	char			*fp;

	side = getmyside(*spp, ep);
	if (side == MD_SIDEWILD) {
		/* failed to find this node in the set */
		mda_debug("Failed to find the side number\n");
		return (METADEVADM_ERR);
	}

	if ((dnp = metadrivename(spp, ctd, ep)) == NULL) {
		mda_debug("Failed to create a dnp for %s\n", ctd);
		return (METADEVADM_ERR);
	}
	if (dnp->devid == NULL) {
		/*
		 * Disk does not have a devid! So cannot update the
		 * devid within the replica.
		 */
		mda_debug("%s does not have a devid\n", dnp->cname);
		if (dev_options & DEV_VERBOSE) {
			mda_print(dgettext(TEXT_DOMAIN,
			    "%s does not have a device id. Cannot update "
			    "device id if none exists\n"), ctd);
		}
		return (METADEVADM_ERR);
	}

	mda_debug("Devid update to: %s\n", dnp->devid);

	/*
	 * Check if we own the set, if we do then do some processing
	 * on the replicas.
	 */
	if (meta_check_ownership(*spp, ep) == 0) {

		/* get the replicas */
		if (metareplicalist(*spp, MD_BASICNAME_OK | PRINT_FAST, &rlp,
		    ep) < 0)
			return (METADEVADM_ERR);

		/* update the devids in the replicas if necessary */
		if (replica_update_devid(rlp, dnp, setno, &old_cdevidp,
		    ep) != METADEVADM_SUCCESS) {
			metafreereplicalist(rlp);
			return (METADEVADM_ERR);
		}

		metafreereplicalist(rlp);
	}

	/*
	 * If this is not the LOCAL set then need to update the LOCAL
	 * replica with the new disk record.
	 */

	if (setno != MD_LOCAL_SET) {
		mda_debug("Non-local set: %d side %d\n", setno, side);

		/*
		 * Need to find the disk record within the set and then
		 * update it.
		 */
		if ((dd =
		    metaget_drivedesc(*spp, MD_FULLNAME_ONLY, ep)) == NULL) {
			if (! mdisok(ep))
				goto out;
			/* no disks in the set - no point continuing */
			mda_debug("No disks in diskset\n");
			rval = METADEVADM_SUCCESS;
			goto out;
		}

		for (ddp = dd; ddp != NULL; ddp = ddp->dd_next) {
			if (strncmp(ddp->dd_dnp->cname, dnp->cname,
			    strlen(dnp->cname)) == 0)
				break;
		}

		if (ddp == NULL) {
			/* failed to finddisk in the set */
			mda_print(dgettext(TEXT_DOMAIN,
			    "%s not found in set %s. Check your syntax\n"),
			    ctd, (*spp)->setname);
			(void) mddserror(ep, MDE_DS_DRIVENOTINSET, setno, NULL,
			    ctd, (*spp)->setname);
			goto out;
		}

		/*
		 * Now figure out the correct slice, for a diskset the slice
		 * we care about is always the 'replica' slice.
		 */
		if (meta_replicaslice(dnp, &rep_slice, ep) != 0) {
			mda_debug("Unable to find replica slice for %s\n",
			    dnp->cname);
			goto out;
		}

		mda_debug("slice no: %d disk %s\n", rep_slice, dnp->cname);

		if ((np = metaslicename(dnp, rep_slice, ep)) == NULL) {
			mda_debug("Unable to build namespace\n");
			goto out;
		}

		mda_debug("check: ctdname: %s\n", np->cname);
		mda_debug("check: ctdname: %s\n", np->rname);
		mda_debug("check: ctdname: %s\n", np->bname);

		if (!(dev_options & DEV_NOACTION)) {

			mda_debug("Updating record: key %d name %s\n",
			    ddp->dd_dnp->side_names_key, np->cname);

			pathname = mda_getpath(np->bname);

			if (meta_update_namespace(MD_LOCAL_SET, side + SKEW,
			    np->cname, np->dev, ddp->dd_dnp->side_names_key,
			    pathname, ep) != 0) {
				goto out;
			}

			/*
			 * Now update the devid entry as well, this works
			 * correctly because the prior call to
			 * meta_update_namespace() above puts the correct dev_t
			 * in the namespace which will then be resolved
			 * to the new devid by the ioctl now called.
			 */
			nm.mde = mdnullerror;
			nm.setno = MD_LOCAL_SET;
			nm.side = side + SKEW;
			nm.key = ddp->dd_dnp->side_names_key;
			if (metaioctl(MD_SETNMDID, &nm, &nm.mde, NULL) != 0) {
				(void) mdstealerror(ep, &nm.mde);
				goto out;
			}
		}
	}

	if ((dev_options & DEV_LOCAL_SET) && (setno != MD_LOCAL_SET)) {
		/*
		 * Only want to update the local set so do not continue.
		 */
		rval = METADEVADM_SUCCESS;
		goto out;
	}

	/*
	 * Iterate through all of the metadevices looking for the
	 * passed in ctd.  If found then update the devid
	 */
	(void) memset(&nm, '\0', sizeof (nm));
	nm.key = MD_KEYWILD;
	/* LINTED */
	while (1) {
		nm.mde = mdnullerror;
		nm.setno = setno;
		nm.side = side;

		/* search each namespace entry */
		if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde, NULL) != 0) {
			(void) mdstealerror(ep, &nm.mde);
			rval = METADEVADM_ERR;
			goto out;
		}
		if (nm.key == MD_KEYWILD) {
			if (setno != MD_LOCAL_SET) {
				mda_print(dgettext(TEXT_DOMAIN,
				    "%s not found in set %s. Check your "
				    "syntax\n"), ctd, (*spp)->setname);
				goto out;
			} else {
				mda_print(dgettext(TEXT_DOMAIN,
				    "%s not found in local set. "
				    "Check your syntax\n"), ctd);
				goto out;
			}
		}

		nm.devname = (uintptr_t)meta_getnmentbykey(setno, side, nm.key,
		    NULL, NULL, NULL, ep);
		if (nm.devname == NULL) {
			rval = METADEVADM_ERR;
			goto out;
		}

		diskname = getdiskname((char *)(uintptr_t)nm.devname);

		mda_debug("Checking %s with %s\n", diskname, dnp->cname);
		if (strcmp(diskname, dnp->cname) != 0)
			continue;

		mda_debug("Updating device %s in namespace\n",
		    (char *)(uintptr_t)nm.devname);

		/*
		 * found disk, does it have a devid within the namespace ?
		 * It might not because it does not support devid's or was
		 * put into the namespace when there was no devid support
		 */
		if ((devidp = has_devid(setno, side, nm.key, ep)) == NULL) {
			mda_debug("%s has no devid in the namespace",
			    (char *)(uintptr_t)nm.devname);
			if (dev_options & DEV_VERBOSE) {
				mda_print(dgettext(TEXT_DOMAIN,
				    "SVM has no device id for "
				    "%s, cannot update.\n"),
				    (char *)(uintptr_t)nm.devname);
			}
			continue; /* no devid. go on to next */
		}
		if (old_cdevidp == NULL) {
			old_cdevidp = devid_str_encode(devidp, NULL);
		}
		free(devidp);

		/*
		 * has devid so update namespace, note the key has been set
		 * by the prior MD_IOCNXTKEY_NM ioctl.
		 */
		nm.mde = mdnullerror;
		nm.setno = setno;
		nm.side = side;
		if (!(dev_options & DEV_NOACTION)) {
			/*
			 * The call below may fail if the -u option is being
			 * used to update a disk that has been replaced.
			 * The -u option to metadevadm should not be used
			 * for this purpose because we trust the dev_t of
			 * the device in the replica and if we have replaced
			 * the device and it is a fibre one then the dev_t
			 * will have changed. This means we end up looking for
			 * the devid of a non-existant disk and we subsequently
			 * fail with NODEVID.
			 */
			if (metaioctl(MD_SETNMDID, &nm,
			    &nm.mde, NULL) != 0) {
				if (dev_options & DEV_VERBOSE) {
					mda_print(dgettext(TEXT_DOMAIN,
					    "SVM failed to update the device "
					    "id for %s probably due to both "
					    "devt and device id changing.\n"),
					    (char *)(uintptr_t)nm.devname);
				}
				(void) mdstealerror(ep, &nm.mde);
				mde_perror(ep, "");
				rval = METADEVADM_ERR;
				goto out;
			}
		}
		if (old_cdevidp == NULL) {
			rval = METADEVADM_ERR;
			goto out;
		}
		break;
	} /* end while */

	mda_print(dgettext(TEXT_DOMAIN,
	    "Updating Solaris Volume Manager device relocation "
	    "information for %s\n"), ctd);

	mda_print(dgettext(TEXT_DOMAIN,
	    "Old device reloc information:\n\t%s\n"), old_cdevidp);

	len = strlen(dnp->rname) + strlen("s0");
	if ((fp = (char *)Malloc(len + 1)) == NULL) {
		mda_print(dgettext(TEXT_DOMAIN,
		    "insufficient memory, device Reloc info not "
		    "available\n"));
	} else {
		(void) snprintf(fp, len + 1, "%ss0", dnp->rname);
		if ((fd = open(fp, O_RDONLY|O_NDELAY)) < 0) {
			mda_print(dgettext(TEXT_DOMAIN,
			    "Open of %s failed\n"), fp);
		} else {
			int		rc = -1;
			ddi_devid_t	devid1 = NULL;
			char		*cdevidp;

			rc = devid_get(fd, &devid1);
			if (close(fd) < 0) {
				mda_print(dgettext(TEXT_DOMAIN,
				    "Close of %s failed\n"), fp);
			}
			if (rc != 0) {
				mda_print(dgettext(TEXT_DOMAIN,
				    "Unable to obtain device "
				    "Reloc info for %s\n"), fp);
			} else {
				cdevidp = devid_str_encode(devid1, NULL);
				if (cdevidp == NULL) {
					mda_print(dgettext(TEXT_DOMAIN,
					    "Unable to print "
					    "device Reloc info for %s\n"), fp);
				} else {
					mda_print(dgettext(TEXT_DOMAIN,
					    "New device reloc "
					    "information:\n\t%s\n"), cdevidp);
					devid_str_free(cdevidp);
				}
				devid_free(devid1);
			}
		}
		Free(fp);
	}

	rval = METADEVADM_SUCCESS;

out:
	if (diskname)
		Free(diskname);
	if (pathname)
		Free(pathname);
	if (old_cdevidp) {
		devid_str_free(old_cdevidp);
	}
	return (rval);

}

/*
 * Check the ctd name of the disk to see if the disk has moved. If it
 * has moved then the newname is returned in 'newname', it is up to
 * the caller to free the memory associated with it.
 *
 * RETURN
 *	METADEVADM_ERR		error
 *	METADEVADM_SUCCESS	success
 *	METADEVADM_DISKMOVE	success, and the disk has moved
 *	METADEVADM_DSKNAME_ERR	error creating the disk name structures.
 */
int
meta_upd_ctdnames(
	mdsetname_t	**spp,
	set_t		setno,
	side_t		sideno,
	mddrivename_t	*dnp,
	char		**newname,
	md_error_t	*ep
)
{
	char		*drvnmp;
	int		i;
	minor_t		mnum = 0;
	md_dev64_t	dev = 0;
	dev_t		small_dev = (dev_t)NODEV;
	mdnm_params_t	nm;
	char		*pathname;
	char		*minor_name = NULL;
	ddi_devid_t	devidp;
	devid_nmlist_t	*disklist = NULL;
	int		ret = 0;
	mdsidenames_t	*snp;
	int		match_type;
	int		search_number = -1;
	char		*search_type = NULL;
	char		*search_path = NULL;
	uint_t		rep_slice;
	mddrivename_t	*newdnp;
	mdname_t	*np;
	mdsetname_t	*sp = *spp;
	md_set_desc	*sd;

	/*
	 * setno should always be 0 but we're going to
	 * check for multi-node diskset and return if it is one.
	 */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (METADEVADM_ERR);

		if (MD_MNSET_DESC(sd))
			return (METADEVADM_SUCCESS);
	}

	if (dnp->devid == NULL) {
		/* no devid, nothing can be done */
		mda_debug("meta_upd_ctdnames: %s has no devid\n", dnp->cname);
		if (dev_options & DEV_VERBOSE) {
			mda_print(dgettext(TEXT_DOMAIN,
			    "%s has no devid, cannot detect "
			    "disk movement for this disk.\n"), dnp->cname);
		}
		return (ret);
	}

	/*
	 * Find the correct side name for the disk. There is a sidename
	 * for each host associated with the diskset.
	 */
	for (snp = dnp->side_names; snp != NULL; snp = snp->next) {
		mda_debug("meta_upd_ctdnames: %s %d args: setno %d sideno %d\n",
		    snp->cname, snp->sideno, setno, sideno);
		/* only use SKEW for the local replica */
		if (setno == 0) {
			if (snp->sideno + SKEW == sideno)
				break;
		} else {
			if (snp->sideno == sideno)
				break;
		}
	}

	if (snp == NULL) {
		/*
		 * Failed to find the side name, this should not
		 * be possible. However if it does happen this is an
		 * indication of an inconsistant replica - something
		 * might have gone wrong during an add or a delete of
		 * a host.
		 */
		mda_debug("Unable to find the side information for disk %s",
		    dnp->cname);
		(void) mddserror(ep, MDE_DS_HOSTNOSIDE, (*spp)->setno, mynode(),
		    NULL, dnp->cname);
		return (METADEVADM_ERR);
	}
	/*
	 * Find the type of device we are to be searching on
	 */
	search_number = mda_findpath(snp->cname);
	if (search_number == -1) {
		search_path = "/dev";
		search_type = DEVID_MINOR_NAME_ALL;
	} else {
		search_path = plist[search_number].search_path;
		search_type = plist[search_number].search_type;
	}

	mda_debug("Search path :%s searth_type: %x\n",
	    search_path, (int)search_type);
	(void) memset(&nm, '\0', sizeof (nm));

	nm.mde = mdnullerror;
	nm.setno = setno;
	nm.side = sideno;

	/*
	 * Get the devname from the name space.
	 */
	if ((nm.devname = (uintptr_t)meta_getnmentbykey(setno, sideno,
	    dnp->side_names_key, &drvnmp, &mnum, &dev, ep)) == NULL) {
		return (METADEVADM_ERR);
	}

	ret = devid_str_decode(dnp->devid, &devidp, &minor_name);
	devid_str_free(minor_name);

	if (ret != 0) {
		/*
		 * Failed to encode the devid.
		 */
		devid_free(devidp);
		return (METADEVADM_ERR);
	}

	/*
	 * Use the stored devid to find the existing device node and check
	 * to see if the disk has moved. Use the raw devices as the name
	 * of the disk is stored as the raw device, if this is not done
	 * then the disk will not be found.
	 */
	ret = meta_deviceid_to_nmlist(search_path, devidp,
	    search_type, &disklist);

	if (ret != 0) {
		if (dev_options & DEV_VERBOSE) {
			mda_print(dgettext(TEXT_DOMAIN,
			    "Device ID %s last associated with "
			    "disk %s no longer found in system\n"),
			    dnp->devid, dnp->cname);
		}
		devid_free(devidp);
		devid_free_nmlist(disklist);
		return (METADEVADM_SUCCESS);
	}

	small_dev = meta_cmpldev(dev);
	mda_debug("Old device lookup: %s (%p)\n",
	    (char *)(uintptr_t)nm.devname, (void *)small_dev);
	/*
	 * Check to see if the returned disk matches the stored one
	 */
	for (i = 0; disklist[i].dev != NODEV; i++) {
		match_type = 0;
		mda_debug("From devid lookup: %s (%p)\n",
		    disklist[i].devname, (void *)disklist[i].dev);

		if (disklist[i].dev == small_dev) {
			match_type |= DEV_MATCH;
		}

		if (strncmp((char *)(uintptr_t)nm.devname, disklist[i].devname,
		    strlen((char *)(uintptr_t)nm.devname)) == 0) {
			match_type |= NAME_MATCH;
		}

		if (match_type != 0)
			break;
	}
	devid_free(devidp);

	mda_debug("meta_upd_ctdnames: match: %x i: %d\n", match_type, i);

	if (match_type == (DEV_MATCH|NAME_MATCH)) {
		/* no change */
		devid_free_nmlist(disklist);
		return (METADEVADM_SUCCESS);
	}

	/* No match found - use the first entry in disklist */
	if (disklist[i].dev == NODEV)
		i = 0;

	if (!(match_type & DEV_MATCH)) {
		/* did not match on the dev, so dev_t has changed */
		mda_debug("Did not match on dev: %p %p\n",
		    (void *) small_dev, (void *) disklist[i].dev);
		dev = meta_expldev(disklist[i].dev);
	}

	if (!(match_type & NAME_MATCH)) {
		mda_debug("Did not match on name: %s (%p)\n",
		    (char *)(uintptr_t)nm.devname, (void *) disklist[i].dev);
	}

	/*
	 * If here, then the name in the disklist is the one we
	 * want in any case so use it.
	 */
	mda_debug("devname: %s\n", disklist[i].devname);
	/*
	 * Need to remove the slice as metadrivename() expects a diskname
	 */
	stripS(disklist[i].devname);
	/*
	 * Build an mddrivename_t to use
	 */
	if ((newdnp = metadrivename(spp, disklist[i].devname, ep)) == NULL) {
		mda_debug("Unable to make a dnp out of %s\n",
		    disklist[i].devname);
		return (METADEVADM_DSKNAME_ERR);
	}
	/*
	 * Need to find the correct slice used for the replica
	 */
	if (meta_replicaslice(newdnp, &rep_slice, ep) != 0) {
		return (METADEVADM_DSKNAME_ERR);
	}

	if ((np = metaslicename(newdnp, rep_slice, ep)) == NULL) {
		mda_debug("Failed to build an np for %s\n", dnp->rname);
		return (METADEVADM_DSKNAME_ERR);
	}
	mda_debug("check: cname: %s\n", np->cname);
	mda_debug("check: rname: %s\n", np->rname);
	mda_debug("check: bname: %s\n", np->bname);

	if (newname != NULL)
		*newname = Strdup(np->bname);

	if (!(dev_options & DEV_NOACTION)) {

		mda_debug("update namespace\n");

		/* get the block path */
		pathname = mda_getpath(np->bname);

		if (meta_update_namespace(setno, sideno, np->cname,
		    dev, dnp->side_names_key, pathname, ep) != 0) {
			/* finished with the list so return the memory */
			Free(pathname);
			devid_free_nmlist(disklist);
			return (METADEVADM_ERR);
		}
	}
	/* finished with the list so return the memory */
	Free(pathname);
	devid_free_nmlist(disklist);
	ret = METADEVADM_DISKMOVE;
	return (ret);
}

int
meta_fixdevid(
	mdsetname_t	*sp,
	mddevopts_t	options,
	char		*diskname,
	md_error_t	*ep
)
{
	set_t		setno = sp->setno;
	int		ret = 0;
	char		*pathname = NULL;
	mdsetname_t	*local_sp = NULL;
	md_drive_desc	*d = NULL;
	char		*newname = NULL;
	md_drive_desc	*dd;
	side_t		sideno;
	md_set_desc	*sd;

	/* if MN diskset just return */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			return (METADEVADM_ERR);
		}
		if (MD_MNSET_DESC(sd))
			return (METADEVADM_SUCCESS);
	}

	dev_options |= options;
	mda_debug("dev_options: %x\n", dev_options);
	if (dev_options & DEV_RELOAD) {
		/*
		 * If it's not the local set we need to check the local
		 * namespace to see if disks have moved as it contains
		 * entries for the disks in the set.
		 */
		if (setno != MD_LOCAL_SET) {
			if ((dd = metaget_drivedesc(sp, MD_BASICNAME_OK |
			    PRINT_FAST, ep)) == NULL) {
				mde_perror(ep, "");
				mdclrerror(ep);
				return (METADEVADM_ERR);
			}
			local_sp = metasetname(MD_LOCAL_NAME, ep);
			sideno = getmyside(sp, ep) + SKEW;
			for (d = dd; d != NULL; d = d->dd_next) {
				/*
				 * Actually do the check of the disks.
				 */
				ret = meta_upd_ctdnames(&local_sp, 0, sideno,
				    d->dd_dnp, &newname, ep);

				if ((ret == METADEVADM_ERR) ||
				    (ret == METADEVADM_DSKNAME_ERR)) {
					/* check failed in unknown manner */
					mda_debug("meta_upd_ctdnames failed\n");
					return (METADEVADM_ERR);
				}
			}
		}

		/* do a reload of the devid namespace */
		ret = pathname_reload(&sp, setno, ep);
	} else if (dev_options & DEV_UPDATE) {
		pathname = getdiskname(diskname);
		ret = devid_update(&sp, setno, pathname, ep);
		free(pathname);
	}
	return (ret);
}
