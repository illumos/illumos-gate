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

/*
 * get dev_t list
 */

#include <meta.h>

#include <sys/mhd.h>
#include <strings.h>

/*
 * private version of minor(), able to handle 64 bit and 32 bit devices.
 * print a warning out in case a 32 bit dev is specified.
 */
minor_t
meta_getminor(md_dev64_t dev64)
{
	/* check if it's a real 64 bit dev */
	if ((dev64 >> NBITSMAJOR64) > 0) {
		return ((minor_t)(dev64 & MAXMIN64));
	} else {
		if (getenv("META_DEBUG"))
			(void) printf(
			    "meta_getminor called with 32 bit dev: 0x%llx\n",
			    dev64);
		return ((minor_t)(dev64 & MAXMIN32));
	}
}

/*
 * private version of major(), able to handle 64 bit and 32 bit devices.
 * print a warning out in case a 32 bit dev is specified.
 */
major_t
meta_getmajor(md_dev64_t dev64)
{
	/* check if it's a real 64 bit dev */
	if ((dev64 >> NBITSMAJOR64) > 0) {
		return ((major_t)((dev64 >> NBITSMINOR64) & MAXMAJ64));
	} else {
		if (getenv("META_DEBUG"))
			(void) printf(
			    "meta_getmajor called with 32 bit dev: 0x%llx\n",
			    dev64);
		return ((major_t)((dev64 >> NBITSMINOR32) & MAXMAJ32));
	}
}

/*
 * private version of cmpldev(), able to handle 64 bit and 32 bit devices.
 */
dev32_t
meta_cmpldev(md_dev64_t dev64)
{
	minor_t minor;
	major_t major;

	major = (major_t)(dev64 >> NBITSMAJOR64);
	if (major == 0) {
		return ((dev32_t)dev64);
	}
	minor = (dev32_t)dev64 & MAXMIN32;
	return ((major << NBITSMINOR32) | minor);
}

/*
 * private version of expldev(), able to handle 64 bit and 32 bit devices.
 */
md_dev64_t
meta_expldev(md_dev64_t dev64)
{
	minor_t minor;
	major_t major;

	major = (major_t)(dev64 >> NBITSMAJOR64);
	if (major > 0) { /* a 64 bit device was given, return unchanged */
		return (dev64);
	}
	minor = (minor_t)(dev64) & MAXMIN32;
	major = ((major_t)dev64 >> NBITSMINOR32) & MAXMAJ32;
	return (((md_dev64_t)major << NBITSMINOR64) | minor);
}

/*
 * get underlying devices (recursively)
 */
int
meta_getdevs(
	mdsetname_t		*sp,
	mdname_t		*namep,
	mdnamelist_t		**nlpp,
	md_error_t		*ep
)
{
	char			*miscname;
	md_dev64_t		*mydevs = NULL;
	md_getdevs_params_t	mgd;
	size_t			i;
	int			rval = -1;
	md_sys_error_t		*ip;

	/* must have local set */
	assert(sp != NULL);

	/* if no valid name then return an error */
	if (namep == NULL)
		return (-1);

	/* just add regular devices */
	if (! metaismeta(namep)) {
		mdnamelist_t	*p;

		/*
		 * If the dev_t is in the array already
		 * then let's continue.
		 */
		for (p = *nlpp; (p != NULL); p = p->next) {
			if (strcmp(namep->bname, p->namep->bname) == 0) {
				rval = 0;
				goto out;
			}
		}

		/* add to list */
		(void) metanamelist_append(nlpp, namep);
		rval = 0;
		goto out;
	}

	/* get MD misc module */
	if ((miscname = metagetmiscname(namep, ep)) == NULL)
		goto out;

	/* get count of underlying devices */
	(void) memset(&mgd, '\0', sizeof (mgd));
	MD_SETDRIVERNAME(&mgd, miscname, sp->setno);
	mgd.mnum = meta_getminor(namep->dev);
	mgd.cnt = 0;
	mgd.devs = NULL;
	if (metaioctl(MD_IOCGET_DEVS, &mgd, &mgd.mde, namep->cname) != 0) {
		if (mgd.mde.info.errclass == MDEC_SYS) {
			ip = &mgd.mde.info.md_error_info_t_u.sys_error;
			if (ip->errnum == ENODEV) {
				rval = 0;
				goto out;
			}
		}
		(void) mdstealerror(ep, &mgd.mde);
		goto out;
	} else if (mgd.cnt <= 0) {
		assert(mgd.cnt >= 0);
		rval = 0;
		goto out;
	}

	/* get underlying devices */
	mydevs = Zalloc(sizeof (*mydevs) * mgd.cnt);
	mgd.devs = (uintptr_t)mydevs;
	if (metaioctl(MD_IOCGET_DEVS, &mgd, &mgd.mde, namep->cname) != 0) {
		if (mgd.mde.info.errclass == MDEC_SYS) {
			ip = &mgd.mde.info.md_error_info_t_u.sys_error;
			if (ip->errnum == ENODEV) {
				rval = 0;
				goto out;
			}
		}
		(void) mdstealerror(ep, &mgd.mde);
		goto out;
	} else if (mgd.cnt <= 0) {
		assert(mgd.cnt >= 0);
		rval = 0;
		goto out;
	}
	/* recurse */
	for (i = 0; (i < mgd.cnt); ++i) {
		mdname_t	*devnp;

		if (mydevs[i] == NODEV64) {
			continue;
		}
		if ((devnp = metadevname(&sp, mydevs[i], ep)) == NULL) {
			if (mdissyserror(ep, ENOENT)) {
				mdclrerror(ep);
				/*
				 * If the device doesn't exist, it could be
				 * that we have a wrong dev_t/name
				 * combination in the namespace, so
				 * meta_fix_compnames try to check this
				 * with the unit structure and fix this.
				 */
				if (meta_fix_compnames(sp, namep,
				    mydevs[i], ep) == 0)
					continue;
			}
			goto out;
		}
		if (meta_getdevs(sp, devnp, nlpp, ep) != 0)
			goto out;
	}

	/* success */
	rval = 0;

	/* cleanup, return error */
out:
	if (mydevs != NULL)
		Free(mydevs);
	return (rval);
}

/*
 * get all dev_t for a set
 */
int
meta_getalldevs(
	mdsetname_t		*sp,		/* set to look in */
	mdnamelist_t		**nlpp,		/* returned devices */
	int			check_db,
	md_error_t		*ep
)
{
	md_replicalist_t	*rlp, *rp;
	mdnamelist_t		*nlp, *np;
	mdhspnamelist_t		*hspnlp, *hspp;
	int			rval = 0;

	assert(sp != NULL);

	/*
	 * Get a replica namelist,
	 * and then get all the devs within the replicas.
	 */
	if (check_db == TRUE) {
		rlp = NULL;
		if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) < 0)
			rval = -1;
		for (rp = rlp; (rp != NULL); rp = rp->rl_next) {
			if (meta_getdevs(sp, rp->rl_repp->r_namep,
			    nlpp, ep) != 0)
				rval = -1;
		}
		metafreereplicalist(rlp);
	}

	/*
	 * Get a stripe namelist,
	 * and then get all the devs within the stripes.
	 */
	nlp = NULL;
	if (meta_get_stripe_names(sp, &nlp, 0, ep) < 0)
		rval = -1;
	for (np = nlp; (np != NULL); np = np->next) {
		if (meta_getdevs(sp, np->namep, nlpp, ep) != 0)
			rval = -1;
	}
	metafreenamelist(nlp);

	/*
	 * Get a mirror namelist,
	 * and then get all the devs within the mirrors.
	 */
	nlp = NULL;
	if (meta_get_mirror_names(sp, &nlp, 0, ep) < 0)
		rval = -1;
	for (np = nlp; (np != NULL); np = np->next) {
		if (meta_getdevs(sp, np->namep, nlpp, ep) != 0)
			rval = -1;
	}
	metafreenamelist(nlp);

	/*
	 * Get a trans namelist,
	 * and then get all the devs within the trans.
	 */
	nlp = NULL;

	if (meta_get_trans_names(sp, &nlp, 0, ep) < 0)
		rval = -1;
	for (np = nlp; (np != NULL); np = np->next) {
		if (meta_getdevs(sp, np->namep, nlpp, ep) != 0)
			rval = -1;
	}
	metafreenamelist(nlp);

	/*
	 * Get a hot spare pool namelist,
	 * and then get all the devs within the hot spare pools.
	 */
	hspnlp = NULL;
	if (meta_get_hsp_names(sp, &hspnlp, 0, ep) < 0)
		rval = -1;
	for (hspp = hspnlp; (hspp != NULL); hspp = hspp->next) {
		md_hsp_t	*hsp;
		uint_t		i;

		if ((hsp = meta_get_hsp(sp, hspp->hspnamep, ep)) == NULL)
			rval = -1;
		else for (i = 0; (i < hsp->hotspares.hotspares_len); ++i) {
			md_hs_t	*hs = &hsp->hotspares.hotspares_val[i];

			if (meta_getdevs(sp, hs->hsnamep, nlpp, ep) != 0)
				rval = -1;
		}
	}
	metafreehspnamelist(hspnlp);

	/*
	 * Get a raid namelist,
	 * and then get all the devs within the raids.
	 */
	nlp = NULL;
	if (meta_get_raid_names(sp, &nlp, 0, ep) < 0)
		rval = -1;
	for (np = nlp; (np != NULL); np = np->next) {
		if (meta_getdevs(sp, np->namep, nlpp, ep) != 0)
			rval = -1;
	}
	metafreenamelist(nlp);

	/*
	 * Get a soft partition namelist,
	 * and then get all the devs within the softpartitions
	 */
	nlp = NULL;
	if (meta_get_sp_names(sp, &nlp, 0, ep) < 0)
		rval = -1;
	for (np = nlp; (np != NULL); np = np->next) {
		if (meta_getdevs(sp, np->namep, nlpp, ep) != 0)
			rval = -1;
	}
	metafreenamelist(nlp);

	return (rval);
}

/*
 * get vtoc from a device already opened.
 * returns
 *	0 on success,
 *	-1 on error. If the error was  ENOTSUP, partno will be set to
 *		VT_ENOTSUP if possible.
 */
int
meta_getvtoc(
	int		fd,		/* fd for named device */
	char		*devname,	/* name of device */
	struct vtoc	*vtocbufp,	/* vtoc buffer to fill */
	int		*partno,	/* return partno here */
	md_error_t	*ep
)
{
	int		part;

	(void) memset(vtocbufp, 0, sizeof (*vtocbufp));
	if ((part = read_vtoc(fd, vtocbufp)) < 0) {
		int	err = errno;

		if (ioctl(fd, MHIOCSTATUS, NULL) == 1)
			err = EACCES;
		else if (part == VT_EINVAL)
			err = EINVAL;
		else if (part == VT_EIO)
			err = EIO;
		else if (part == VT_ENOTSUP) {
			if (partno) {
				*partno = VT_ENOTSUP;
				return (-1);
			}
		}
		return (mdsyserror(ep, err, devname));
	}

	/* Slice number for *p0 partition (whole disk on x86) is 16 */
	if (part >= V_NUMPAR)
		return (mdsyserror(ep, EINVAL, devname));

	if (partno)
		*partno = part;
	return (0);
}
/*
 * set mdvtoc for a meta devices
 */
int
meta_setmdvtoc(
	int		fd,		/* fd for named device */
	char		*devname,	/* name of device */
	mdvtoc_t	*mdvtocp,	/* mdvtoc buffer to fill */
	md_error_t	*ep
)
{
	uint_t i;

	/*
	 * Sanity-check the mdvtoc
	 */

	if (mdvtocp->nparts > V_NUMPAR) {
		return (-1);
	}

	/*
	 * since many drivers won't allow opening a device make sure
	 * all partitions aren't being set to zero. If all are zero then
	 * we have no way to set them to something else
	 */

	for (i = 0; i < mdvtocp->nparts; i++)
		if (mdvtocp->parts[i].size > 0)
			break;
	if (i == mdvtocp->nparts)
		return (-1);

	/*
	 * Write the mdvtoc
	 */
	if (ioctl(fd, DKIOCSVTOC, (caddr_t)mdvtocp) == -1) {
		return (mdsyserror(ep, errno, devname));
	}

	return (0);
}

/*
 * set vtoc
 */
int
meta_setvtoc(
	int		fd,		/* fd for named device */
	char		*devname,	/* name of device */
	struct vtoc	*vtocbufp,	/* vtoc buffer to fill */
	md_error_t	*ep
)
{
	int		part;
	int		err;

	if ((part = write_vtoc(fd, vtocbufp)) < 0) {
		if (part == VT_EINVAL)
			err = EINVAL;
		else if (part == VT_EIO)
			err = EIO;
		else
			err = errno;
		return (mdsyserror(ep, err, devname));
	}

	return (0);
}

/*
 * FUNCTION:	meta_get_names()
 * INPUT:	drivername - char string containing the driver name
 *		sp	- the set name to get soft partitions from
 *		options	- options from the command line
 * OUTPUT:	nlpp	- list of all soft partition names
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 success
 * PURPOSE:	returns a list of all specified devices in the metadb
 *		for all devices in the specified set
 */
int
meta_get_names(
	char		*drivername,
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	md_i_getnum_t	gn;		/* MD_IOCGET_NUM params */
	mdnamelist_t	**tailpp = nlpp;
	minor_t		*minors = NULL;
	minor_t		*m_ptr;
	int		i;

	(void) memset(&gn, '\0', sizeof (gn));
	MD_SETDRIVERNAME(&gn, drivername, sp->setno);

	/* get number of devices */
	if (metaioctl(MD_IOCGET_NUM, &gn, &gn.mde, NULL) != 0) {
		if (mdiserror(&gn.mde, MDE_UNIT_NOT_FOUND)) {
			mdclrerror(&gn.mde);
		} else {
			(void) mdstealerror(ep, &gn.mde);
			return (-1);
		}
	}

	if (gn.size > 0) {
		/* malloc minor number buffer to be filled by ioctl */
		if ((minors = (minor_t *)malloc(
		    gn.size * sizeof (minor_t))) == 0) {
			return (ENOMEM);
		}
		gn.minors = (uintptr_t)minors;
		if (metaioctl(MD_IOCGET_NUM, &gn, &gn.mde, NULL) != 0) {
			(void) mdstealerror(ep, &gn.mde);
			free(minors);
			return (-1);
		}
		m_ptr = minors;
		for (i = 0; i < gn.size; i++) {
			mdname_t	*np;

			/* get name */
			np = metamnumname(&sp, *m_ptr,
			    ((options & PRINT_FAST) ? 1 : 0), ep);

			/*
			 * np can be NULL if the /dev/md namespace entries
			 * do not exist. This could have happened due to
			 * devfsadmd not having created them.
			 * Therefore assume devfsadmd has not run and tell
			 * it to run for the specific device that is missing.
			 * Ignore any error return from meta_update_devtree
			 * as a failure to create the device nodes will be
			 * picked up in the metamnumname() call. Note that
			 * the call to meta_update_devtree should not return
			 * until the /dev/md links have been created or if
			 * there has been a failure of some sort.
			 */
			if (np == NULL) {
				(void) meta_update_devtree(*m_ptr);
				np = metamnumname(&sp, *m_ptr,
				    ((options & PRINT_FAST) ? 1 : 0), ep);
			}

			if (np == NULL)
				goto out;

			tailpp = meta_namelist_append_wrapper(tailpp, np);

			/* next device */
			m_ptr++;
		}
		free(minors);
	}
	return (gn.size);

out:
	if (minors != NULL)
		free(minors);
	metafreenamelist(*nlpp);
	*nlpp = NULL;
	return (-1);
}

/*
 * Wrap lib/libdevid/devid_deviceid_to_nmlist.  We want to take the
 * results from that function and filter out the c[t]dp style names that
 * we typically see on x86 so that we never see them.
 */
int
meta_deviceid_to_nmlist(char *search_path, ddi_devid_t devid, char *minor_name,
	devid_nmlist_t	**retlist)
{
	int		res;
	devid_nmlist_t	*dp;
	devid_nmlist_t	*tmp_retlist;
	int		i = 1;
	devid_nmlist_t	*rp;

	res = devid_deviceid_to_nmlist(search_path, devid, minor_name, retlist);
	if (res != 0) {
		return (res);
	}


	/* first count the number of non c[t]dp items in retlist */
	for (dp = *retlist; dp->dev != NODEV; dp++) {
		uint_t		s;

		/* Check if this is a c[t]dp style name.  */
		if (parse_ctd(basename(dp->devname), &s) != 1) {
			i++;
		}
	}

	/* create an array to hold the non c[t]dp items */
	tmp_retlist = Malloc(sizeof (devid_nmlist_t) * i);
	/* copy the non c[t]dp items to the array */
	for (dp = *retlist, rp = tmp_retlist; dp->dev != NODEV; dp++) {
		uint_t		s;

		/* Check if this is a c[t]dp style name.  */
		if (parse_ctd(basename(dp->devname), &s) != 1) {
			/* nope, so copy and go to the next */
			rp->dev = dp->dev;
			rp->devname = Strdup(dp->devname);
			rp++;
		}
		/* if it is c[t]dp, just skip the element */
	}
	/* copy the list terminator */
	rp->dev = NODEV;
	rp->devname = NULL;
	devid_free_nmlist (*retlist);
	*retlist = tmp_retlist;
	return (res);
}

/*
 * Check each real device that makes up a metadevice so that
 * un_dev entries can be matched against the entries in the
 * namespace.
 *
 * RETURN:
 *      -1      error
 *       0      success
 */
int
meta_fix_compnames(
	mdsetname_t	*sp,
	mdname_t	*namep,
	md_dev64_t	dev,
	md_error_t	*ep
)
{
	int	ret = 0;
	char	*miscname;

	/* get miscname and unit */
	if ((miscname = metagetmiscname(namep, ep)) == NULL)
		return (-1);
	if (strcmp(miscname, MD_STRIPE) == 0) {
		if (meta_stripe_check_component(sp, namep, dev, ep) < 0) {
			ret = -1;
		}
	} else if (strcmp(miscname, MD_SP) == 0) {
		if (meta_sp_check_component(sp, namep, ep) < 0) {
			ret = -1;
		}
	} else if (strcmp(miscname, MD_RAID) == 0) {
		if (meta_raid_check_component(sp, namep, dev, ep) < 0) {
			ret = -1;
		}
	} else {
		(void) mdmderror(ep, MDE_INVAL_UNIT, 0, namep->cname);
		return (-1);
	}
	return (ret);
}
