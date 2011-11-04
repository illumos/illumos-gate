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

/*
 * namespace utilities
 */

#include <meta.h>

typedef struct deviceinfo {
	char	*bname;		/* block name of the device */
	char	*dname;		/* driver for the device */
	minor_t	mnum;		/* minor number for the device */
} deviceinfo_t;

static	deviceinfo_t	devlist[MD_MNMAXSIDES];

/*
 * Ask the driver for the device name, driver name, and minor number;
 * which has been stored in the metadevice state database
 * (on behalf of the utilities).
 * (by key)
 */
char *
meta_getnmentbykey(
	set_t		setno,
	side_t		sideno,
	mdkey_t		key,
	char		**drvnm,
	minor_t		*mnum,
	md_dev64_t	*dev,
	md_error_t	*ep
)
{
	struct mdnm_params	nm;
	static char		device_name[MAXPATHLEN];

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = setno;
	nm.side = sideno;
	nm.key = key;
	nm.devname = (uintptr_t)device_name;

	if (metaioctl(MD_IOCGET_NM, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (NULL);
	}

	if (drvnm != NULL)
		*drvnm = Strdup(nm.drvnm);

	if (mnum != NULL)
		*mnum = nm.mnum;

	if (dev != NULL)
		*dev = meta_expldev(makedevice(nm.major, nm.mnum));

	return (Strdup(device_name));
}

/*
 * Ask the driver for the hsp name, driver name, and minor number;
 * which has been stored in the metadevice state database
 * (on behalf of the utilities).
 * (by key)
 */
char *
meta_gethspnmentbyid(
	set_t		setno,
	side_t		sideno,
	hsp_t		hspid,
	md_error_t	*ep
)
{
	struct mdhspnm_params	nm;
	char			*device_name;

	device_name = Malloc(MAXPATHLEN);
	device_name[0] = '\0';

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = setno;
	nm.side = sideno;
	nm.hspid = hspid;
	nm.ret_hspid = MD_HSPID_WILD;
	nm.hspname_len = MAXPATHLEN;
	nm.hspname = (uintptr_t)device_name;

	if (metaioctl(MD_IOCGET_HSP_NM, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		Free(device_name);
		return (NULL);
	}

	return (device_name);
}

/*
 * Ask the driver for the hsp_self_id;
 * which has been stored in the metadevice state database
 * (on behalf of the utilities).
 * (by hsp name)
 */
hsp_t
meta_gethspnmentbyname(
	set_t		setno,
	side_t		sideno,
	char		*hspname,
	md_error_t	*ep
)
{
	struct mdhspnm_params	nm;
	char			*device_name;

	/* must have a hsp name */
	assert(hspname != NULL);

	device_name = Malloc(MAXPATHLEN);
	(void) strcpy(device_name, hspname);

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = setno;
	nm.side = sideno;
	nm.hspid = MD_HSPID_WILD;
	nm.ret_hspid = MD_HSPID_WILD;
	nm.hspname_len = strlen(device_name) + 1;
	nm.hspname = (uintptr_t)device_name;

	/*
	 * The ioctl expects the a hsp name and return its hsp_self_id.
	 */
	if (metaioctl(MD_IOCGET_HSP_NM, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		Free(device_name);
		return (MD_HSP_NONE);
	}

	if (nm.ret_hspid == MD_HSPID_WILD) {
		Free(device_name);
		return (MD_HSP_NONE);
	}

	Free(device_name);
	return (nm.ret_hspid);
}


/*
 * Ask the driver for the minor name which has been stored in the
 * metadevice state database.
 * (by key)
 */
char *
meta_getdidminorbykey(
	set_t		setno,
	side_t		sideno,
	mdkey_t		key,
	md_error_t	*ep
)
{
	struct mdnm_params	nm;
	static char		minorname[MAXPATHLEN];

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = setno;
	nm.side = sideno;
	nm.key = key;
	nm.minorname = (uintptr_t)minorname;

	if (metaioctl(MD_IOCGET_DIDMIN, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (NULL);
	}

	return (Strdup(minorname));
}

/*
 * Ask the driver for the device id string which has been stored in the
 * metadevice state database (on behalf of the utilities).
 * (by key)
 */
ddi_devid_t
meta_getdidbykey(
	set_t		setno,
	side_t		sideno,
	mdkey_t		key,
	md_error_t	*ep
)
{
	struct mdnm_params	nm;

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = setno;
	nm.side = sideno;
	nm.key = key;

	/*
	 * First ask the driver for the size of the device id string.  This is
	 * signaled by passing the driver a devid_size of zero.
	 */
	nm.devid_size = 0;
	if (metaioctl(MD_IOCGET_DID, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (NULL);
	}

	/*
	 * If the devid_size is still zero then something is wrong.
	 */
	if (nm.devid_size == 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (NULL);
	}

	/*
	 * Now go get the actual device id string.  Caller is responsible for
	 * free'ing device id memory buffer.
	 */
	if ((nm.devid = (uintptr_t)malloc(nm.devid_size)) == NULL) {
		return (NULL);
	}
	if (metaioctl(MD_IOCGET_DID, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		(void) free((void *)(uintptr_t)nm.devid);
		return (NULL);
	}

	return ((void *)(uintptr_t)nm.devid);
}

/*
 * set the devid.
 */
int
meta_setdid(
	set_t		setno,
	side_t		sideno,
	mdkey_t		key,
	md_error_t	*ep
)
{
	struct mdnm_params	nm;
	int			i;

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = setno;
	nm.side = sideno;
	nm.key = key;

	if (metaioctl(MD_IOCSET_DID, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (-1);
	}

	if (setno == MD_LOCAL_SET) {
		/*
		 * If this is the local set then we are adding in the devids
		 * for the disks in the diskset and so this means adding
		 * a reference count for each side. Need to do this after
		 * the initial add so that the correct devid is picked up.
		 * The key is the key of the drive record and as such this
		 * means the minor number of the device which is used to
		 * get the devid. If the wrong side is used then it would
		 * be possible to get the wrong devid in the namespace, hence
		 * the requirement to process the local side first of all.
		 */
		for (i = 0 + SKEW; i < MD_MAXSIDES; i++) {
			/*
			 * We can just call the ioctl again because it will
			 * fail with ENOENT if the side does not exist, and
			 * more importantly does not increment the usage count
			 * on the devid.
			 */
			nm.side = (side_t)i;
			if (nm.side == sideno)
				continue;
			if (metaioctl(MD_IOCSET_DID, &nm, &nm.mde, NULL) != 0) {
				if (mdissyserror(&nm.mde, ENODEV)) {
					mdclrerror(&nm.mde);
				} else {
					(void) mdstealerror(ep, &nm.mde);
					return (-1);
				}
			}
		}
	}
	return (0);
}
/*
 * Ask the driver for the name, which has been stored in the
 * metadevice state database (on behalf of the utilities).
 * (by key)
 */
char *
meta_getnmbykey(
	set_t		setno,
	side_t		sideno,
	mdkey_t		key,
	md_error_t	*ep
)
{
	return (meta_getnmentbykey(setno, sideno, key, NULL, NULL, NULL, ep));
}

/*
 * Ask the driver for the device name, driver name, minor number, and key;
 * which has been stored in the metadevice state database
 * (on behalf of the utilities).
 * (by md_dev64_t)
 */
char *
meta_getnmentbydev(
	set_t		setno,
	side_t		sideno,
	md_dev64_t	dev,
	char		**drvnm,
	minor_t		*mnum,
	mdkey_t		*key,
	md_error_t	*ep
)
{
	struct mdnm_params	nm;
	static char		device_name[MAXPATHLEN];

	/* must have a dev */
	assert(dev != NODEV64);

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = setno;
	nm.side = sideno;
	nm.key = MD_KEYWILD;
	nm.major = meta_getmajor(dev);
	nm.mnum = meta_getminor(dev);
	nm.devname = (uintptr_t)device_name;

	if (metaioctl(MD_IOCGET_NM, &nm, &nm.mde, NULL) != 0) {
		(void) mdstealerror(ep, &nm.mde);
		return (NULL);
	}

	/*
	 * With the friendly name work, each metadevice will have
	 * an NM entry. However, to allow backward compatibility,
	 * systems upgraded to a friendly name release won't have
	 * NM entries for the pre-existing top level metadevices. This
	 * implementation allows users to downgrade to a pre-friendly
	 * name release since the configuration information (mddb) is
	 * not modified.
	 *
	 * meta_getnmentbydev is called to get nm entry for all metadevices
	 * and expects the minor and major number and returns a key and
	 * name. For upgraded systems with pre-existing metadevices,
	 * the only returning value will be the name since there's no nm
	 * entry for pre-friendly name top level metadevices. So a return
	 * key for the device will not be available and will be NULL.
	 * Thus, the caller is responsible for making sure the returned key
	 * is valid, not NULL.
	 */
	if (drvnm != NULL)
		*drvnm = Strdup(nm.drvnm);
	if (mnum != NULL)
		*mnum = nm.mnum;

	if (key != NULL)
		*key = nm.retkey;

	return (Strdup(device_name));
}

/*
 * The arguments, minorname and devid, are only used with the partial
 * import code and should be NULL otherwise.
 */
int
add_name(
	mdsetname_t	*sp,
	side_t		sideno,
	mdkey_t		key,
	char		*dname,
	minor_t		mnum,
	char		*bname,
	char		*minorname,	/* only used with a partial import */
	ddi_devid_t	devid,		/* only used with a partial import */
	md_error_t	*ep
)
{
	struct mdnm_params	nm;

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = sp->setno;
	nm.side = sideno;
	nm.key = key;
	nm.mnum = mnum;
	(void) strncpy(nm.drvnm, dname, sizeof (nm.drvnm));
	nm.devname_len = strlen(bname) + 1;
	nm.devname = (uintptr_t)bname;
	if (devid && minorname) {
		nm.minorname_len = strlen(minorname) + 1;
		nm.minorname = (uintptr_t)minorname;
		nm.devid_size = devid_sizeof(devid);
		nm.devid = (uintptr_t)devid;
		nm.imp_flag = MDDB_C_IMPORT;
	}
	if (metaioctl(MD_IOCSET_NM, &nm, &nm.mde, bname) < 0)
		return (mdstealerror(ep, &nm.mde));

	return (nm.key);
}

/*
 * Remove the device name which corresponds to the given device number.
 */
int
del_name(
	mdsetname_t	*sp,
	side_t		sideno,
	mdkey_t		key,
	md_error_t	*ep
)
{
	struct mdnm_params	nm;

	(void) memset(&nm, '\0', sizeof (nm));
	nm.setno = sp->setno;
	nm.side = sideno;
	nm.key = key;

	if (metaioctl(MD_IOCREM_NM, &nm, &nm.mde, NULL) != 0)
		return (mdstealerror(ep, &nm.mde));

	return (0);
}

static void
empty_devicelist()
{
	side_t	sideno;

	for (sideno = 0; sideno < MD_MNMAXSIDES; sideno++) {
		if (devlist[sideno].bname != (char *)NULL) {
			Free(devlist[sideno].bname);
			Free(devlist[sideno].dname);
			devlist[sideno].mnum = NODEV;
		}
	}
}

static void
add_to_devicelist(
	side_t		sideno,
	char		*bname,
	char		*dname,
	minor_t		mnum
)
{
	devlist[sideno].bname = Strdup(bname);
	devlist[sideno].dname = Strdup(dname);

	devlist[sideno].mnum = mnum;
}

/*
 * Build a list of the names on the systems, if this fails the caller
 * will tidy up the entries in the devlist.
 */
static int
build_sidenamelist(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	side_t		sideno = MD_SIDEWILD;
	minor_t		mnum = NODEV;
	char		*bname = NULL;
	char		*dname = NULL;
	int		err;

	/*CONSTCOND*/
	while (1) {

		if ((err = meta_getnextside_devinfo(sp, np->bname, &sideno,
		    &bname, &dname, &mnum, ep)) == -1)
			return (-1);

		if (err == 0)
			break;

		/* the sideno gives us the index into the array */
		add_to_devicelist(sideno, bname, dname, mnum);
	}
	return (0);
}

/*
 * add name key
 * the meta_create* functions should be the only ones using this. The
 * adding of a name to the namespace must be done in a particular order
 * to devid support for the disksets. The order is: add the 'local' side
 * first of all, so the devid lookup in the kernel will use the correct
 * device information and then add in the other sides.
 */
int
add_key_name(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdnamelist_t	**nlpp,
	md_error_t	*ep
)
{
	int		err;
	side_t		sideno = MD_SIDEWILD;
	side_t		thisside;
	mdkey_t		key = MD_KEYWILD;
	md_set_desc	*sd;
	int		maxsides;

	/* should have a set */
	assert(sp != NULL);

	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			return (-1);
		}
	}

	if (build_sidenamelist(sp, np, ep) == -1) {
		empty_devicelist();
		return (-1);
	}

	/*
	 * When a disk is added into the namespace the local information for
	 * that disk is added in first of all. For the local set this is not
	 * a concern and for the host that owns the diskset it is not a concern
	 * but when a disk is added in the remote namespace we *must* use the
	 * local information for that disk first of all. This is because when
	 * in the kernel (md_setdevname) the passed in dev_t is used to find
	 * the devid of the disk. This means we have to cater for the following:
	 *
	 * - a disk on the remote host having the dev_t that has been passed
	 *   into the kernel and this disk is not actually the disk that is
	 *   being added into the diskset.
	 * - the dev_t does not exist on this node
	 *
	 * So putting in the local information first of all makes sure that the
	 * dev_t passed into the kernel is correct with respect to that node
	 * and then any further additions for that name match on the key
	 * passed back.
	 */
	thisside = getmyside(sp, ep);

	if (devlist[thisside].dname == NULL ||
	    strlen(devlist[thisside].dname) == 0) {
		/*
		 * Did not find the disk information for the disk. This can
		 * be because of an inconsistancy in the namespace: that is the
		 * devid we have in the namespace does not exist on the
		 * system and thus when looking up the disk information
		 * using this devid we fail to find anything.
		 */
		(void) mdcomperror(ep, MDE_SP_COMP_OPEN_ERR, 0, np->dev,
		    np->cname);
		empty_devicelist();
		return (-1);
	}

	if ((err = add_name(sp, thisside, key, devlist[thisside].dname,
	    devlist[thisside].mnum, devlist[thisside].bname, NULL,
	    NULL, ep)) == -1) {
		empty_devicelist();
		return (-1);
	}

	/* We now have a 'key' so add in the other sides */
	key = (mdkey_t)err;

	if (metaislocalset(sp))
		goto done;

	if (MD_MNSET_DESC(sd))
		maxsides = MD_MNMAXSIDES;
	else
		maxsides = MD_MAXSIDES;

	for (sideno = 0; sideno < maxsides; sideno++) {
		/* ignore thisside, as it has been added above */
		if (sideno == thisside)
			continue;

		if (devlist[sideno].dname != NULL) {
			err = add_name(sp, sideno, key, devlist[sideno].dname,
			    devlist[sideno].mnum, devlist[sideno].bname,
			    NULL, NULL, ep);
			if (err == -1) {
				empty_devicelist();
				return (-1);
			}
		}
	}

done:
	empty_devicelist();
	/* save key, return success */
	np->key = key;
	if (nlpp != NULL)
		(void) metanamelist_append(nlpp, np);
	return (0);
}

/*
 * delete name key
 * the meta_create* functions should be the only ones using this. The
 * removal of the names must be done in a particular order: remove the
 * non-local entries first of all and then finally the local entry.
 */
int
del_key_name(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	side_t		sideno = MD_SIDEWILD;
	int		err;
	int		retval = 0;
	side_t		thisside;

	/* should have a set */
	assert(sp != NULL);

	/* should have a key */
	assert((np->key != MD_KEYWILD) && (np->key != MD_KEYBAD));

	thisside = getmyside(sp, ep);

	/* remove the remote sides first of all */
	for (;;) {
		if ((err = meta_getnextside_devinfo(sp, np->bname, &sideno,
		    NULL, NULL, NULL, ep)) == -1)
			return (-1);

		if (err == 0)
			break;

		/* ignore thisside */
		if (thisside == sideno) {
			continue;
		}
		if ((err = del_name(sp, sideno, np->key, ep)) == -1)
			retval = -1;
	}

	/* now remove this side */
	if (retval == 0)
		if ((err = del_name(sp, thisside, np->key, ep)) == -1)
			retval = -1;

	np->key = MD_KEYBAD;
	return (retval);
}

/*
 * delete namelist keys
 * the meta_create* functions should be the only ones using this
 */
int
del_key_names(
	mdsetname_t	*sp,
	mdnamelist_t	*nlp,
	md_error_t	*ep
)
{
	mdnamelist_t	*p;
	md_error_t	status = mdnullerror;
	int		rval = 0;

	/* if ignoring errors */
	if (ep == NULL)
		ep = &status;

	/* delete names */
	for (p = nlp; (p != NULL); p = p->next) {
		mdname_t	*np = p->namep;

		if (del_key_name(sp, np, ep) != 0)
			rval = -1;
	}

	/* cleanup, return success */
	if (ep == &status)
		mdclrerror(&status);
	return (rval);
}


/*
 * This routine when is called will store the metadevice name
 * when it is first created
 */
mdkey_t
add_self_name(
	mdsetname_t	*sp,
	char 		*uname,
	md_mkdev_params_t	*params,
	md_error_t	*ep
)
{
	char		*p, *devname;
	side_t		myside, side;
	mdkey_t		key;
	md_set_desc	*sd;
	int		len;
	char		*drvname = params->md_driver.md_drivername;
	minor_t		minor = MD_MKMIN(sp->setno, params->un);
	md_mnnode_desc	*mnside;

	p = strrchr(uname, '/');
	if (p == NULL)
		p = uname;
	else
		p++;

	/*
	 * The valid qualified name
	 */
	if (metaislocalset(sp)) {
		len = strlen(p) + strlen("/dev/md/dsk/") + 1;
		devname = Malloc(len);
		(void) strcpy(devname, "/dev/md/dsk/");
		(void) strcat(devname, p);
	} else {
		len = strlen(sp->setname) + strlen(p) +
		    strlen("/dev/md//dsk/") + 1;
		devname = Malloc(len);
		(void) snprintf(devname, len, "/dev/md/%s/dsk/%s",
		    sp->setname, p);
	}

	/*
	 * Add self to the namespace
	 */
	if ((myside = getmyside(sp, ep)) == MD_SIDEWILD) {
		Free(devname);
		return (-1);
	}

	if (metaislocalset(sp)) {
		if ((key = add_name(sp, myside, MD_KEYWILD, drvname,
		    minor, devname, NULL, NULL, ep)) == MD_KEYBAD) {
			Free(devname);
			return (-1);
		}
	} else {
		/*
		 * Add myside first and use the returned key to add other sides
		 */
		if ((key = add_name(sp, myside, MD_KEYWILD, drvname,
		    minor, devname, NULL, NULL, ep)) == MD_KEYBAD) {
			Free(devname);
			return (-1);
		}

		/*
		 * Add for all other sides
		 */
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			Free(devname);
			return (-1);
		}

		if (MD_MNSET_DESC(sd)) {
			for (mnside = sd->sd_nodelist; mnside != NULL;
			    mnside = mnside->nd_next) {
				if (mnside->nd_nodeid == myside)
					continue;
				if (add_name(sp, mnside->nd_nodeid, key,
				    drvname, minor, devname, NULL, NULL,
				    ep) == -1) {
					Free(devname);
					return (-1);
				}
			}
		} else {
			for (side = 0; side < MD_MAXSIDES; side++) {
				if (sd->sd_nodes[side][0] == '\0')
					continue;
				if (side == myside)
					continue;
				if (add_name(sp, side, key, drvname, minor,
				    devname, NULL, NULL, ep) == -1) {
					Free(devname);
					return (-1);
				}
			}
		}
	}

	Free(devname);
	return (key);
}


/*
 * This routine when is called will remove the metadevice name
 * from the namespace and it is the last thing to do in the
 * metaclear operation
 */
int
del_self_name(
	mdsetname_t	*sp,
	mdkey_t		key,
	md_error_t	*ep
)
{
	side_t		myside;
	int		rval = 0;
	side_t		side;
	md_set_desc	*sd;
	md_mnnode_desc	*mnside;

	assert(key != MD_KEYBAD);

	if ((myside = getmyside(sp, ep)) == MD_SIDEWILD)
		return (-1);

	if (metaislocalset(sp)) {
		rval = del_name(sp, myside, key, ep);
	} else {
		/*
		 * Remove all other sides first
		 */
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			return (-1);
		}

		if (MD_MNSET_DESC(sd)) {
			for (mnside = sd->sd_nodelist; mnside != NULL;
			    mnside = mnside->nd_next) {
				if (mnside->nd_nodeid == myside)
					continue;
				if ((rval = del_name(sp, mnside->nd_nodeid, key,
				    ep)) == -1) {
					goto out;
				}
			}
		} else {
			for (side = 0; side < MD_MAXSIDES; side++) {
				if (sd->sd_nodes[side][0] == '\0')
					continue;
				if (side == myside)
					continue;
				if ((rval = del_name(sp, side, key,
				    ep)) == -1) {
					goto out;
				}
			}
		}

		/*
		 * del myside
		 */
		rval = del_name(sp, myside, key, ep);
	}

out:
	return (rval);
}
