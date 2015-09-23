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
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * check componets
 */

#include <meta.h>
#include "meta_lib_prv.h"

#include <sys/mnttab.h>
#include <sys/swap.h>
#include <devid.h>
#include <sys/dumpadm.h>

/* possible returns from meta_check_samedrive */
#define	CANT_TELL		-1
#define	NOT_SAMEDRIVE		0
#define	IDENTICAL_NAME_DEVT	1
#define	IDENTICAL_DEVIDS	2

/*
 * static list(s)
 */
typedef struct dev_list {
	char			*dev_name;
	ddi_devid_t		devid;
	struct dev_list		*dev_nxt;
} dev_list_t;

static dev_list_t	*devnamelist = NULL;

static char	*skip_these_mntents[] = {
	"nfs",
	"autofs",
	"proc",
	"tmpfs",
	"rfs",
	"fd",
	"mntfs",
	"lofs",
	"devfs",
	"dev",
	"ctfs",
	"objfs",
	"sharefs",
	NULL
};

/*
 * free swap info
 */
static void
free_swapinfo(
	struct swaptable	*swtp
)
{
	int			i;

	if (swtp == NULL)
		return;

	for (i = 0; (i < swtp->swt_n); ++i) {
		if (swtp->swt_ent[i].ste_path != NULL)
			Free(swtp->swt_ent[i].ste_path);
	}

	Free(swtp);
}

/*
 * get swap info
 */
static int
get_swapinfo(
	struct swaptable	**swtpp,
	int			*nswap,
	md_error_t		*ep
)
{
	int			i;
	size_t			swtsize;

	*swtpp = NULL;

	/* get number of entries */
	if ((*nswap = swapctl(SC_GETNSWP, NULL)) < 0) {
		return (mdsyserror(ep, errno, "swapctl(SC_GETNSWP)"));
	}

	/* allocate structure */
	swtsize = sizeof ((*swtpp)->swt_n) +
	    ((*nswap) * sizeof ((*swtpp)->swt_ent[0]));
	*swtpp = (struct swaptable *)Zalloc(swtsize);
	(*swtpp)->swt_n = *nswap;
	for (i = 0; (i < (*nswap)); ++i)
		(*swtpp)->swt_ent[i].ste_path = Zalloc(MAXPATHLEN);

	/* get info */
	if (((*nswap) = swapctl(SC_LIST, (*swtpp))) < 0) {
		(void) mdsyserror(ep, errno, "swapctl(SC_LIST)");
		free_swapinfo(*swtpp);
		return (-1);
	}

	/* return success */
	return (0);
}

/*
 * check whether device is swapped on
 */
static int
meta_check_swapped(
	mdsetname_t		*sp,
	mdname_t		*np,
	md_error_t		*ep
)
{
	struct swaptable	*swtp;
	int			nswap;
	int			i;
	int			rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* get swap info */
	if (get_swapinfo(&swtp, &nswap, ep) != 0)
		return (-1);

	/* look for match */
	for (i = 0; ((i < nswap) && (rval == 0)); ++i) {
		mdname_t	*snp;

		if ((snp = metaname(&sp, swtp->swt_ent[i].ste_path,
		    UNKNOWN, ep)) == NULL) {
			mdclrerror(ep);
			continue;
		}
		if (np->dev == snp->dev) {
			rval = mddeverror(ep, MDE_IS_SWAPPED,
			    np->dev, np->cname);
		} else { /* not swap - does it overlap */
			rval = meta_check_overlap(snp->cname, np, 0, -1,
			    snp, 0, -1, ep);
			if (rval != 0) {
				(void) mdoverlaperror(ep, MDE_OVERLAP_SWAP,
				    np->cname, NULL, snp->cname);
			}
		}
	}
	free_swapinfo(swtp);

	/* return success */
	return (rval);
}

/*
 * Is a driver currently swapped on?
 */
int
meta_check_driveswapped(
	mdsetname_t		*sp,
	mddrivename_t		*dnp,
	md_error_t		*ep
)
{
	struct swaptable	*swtp;
	int			nswap;
	int			i;
	int			rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* get swap info */
	if (get_swapinfo(&swtp, &nswap, ep) != 0)
		return (-1);

	/* look for match */
	for (i = 0; (i < nswap); ++i) {
		mdname_t	*snp;

		if ((snp = metaname(&sp, swtp->swt_ent[i].ste_path,
		    LOGICAL_DEVICE, ep)) == NULL) {
			mdclrerror(ep);
			continue;
		}

		if (strcmp(dnp->cname, snp->drivenamep->cname) == 0) {
			rval = mddeverror(ep, MDE_IS_SWAPPED, NODEV64,
			    dnp->cname);
		}
	}
	free_swapinfo(swtp);

	/* return success */
	return (rval);
}

/*
 * check whether device is a dump device
 */
static int
meta_check_dump(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	int		rval = 0;
	int		dump_fd;
	char		device[MAXPATHLEN];


	if ((dump_fd = open("/dev/dump", O_RDONLY)) < 0)
		return (mdsyserror(ep, errno, "/dev/dump"));

	if (ioctl(dump_fd, DIOCGETDEV, device) != -1) {
		mdname_t	*dump_np;

		if ((dump_np = metaname(&sp, device, UNKNOWN, ep)) == NULL) {
			mdclrerror(ep);
			(void) close(dump_fd);
			return (0);
		}

		if (np->dev == dump_np->dev) {
			rval = mddeverror(ep, MDE_IS_DUMP,
			    np->dev, np->cname);
		} else { /* not a dump device - but does it overlap? */
			rval = meta_check_overlap(dump_np->cname, np, 0, -1,
			    dump_np, 0, -1, ep);
			if (rval != 0) {
				(void) mdoverlaperror(ep, MDE_OVERLAP_DUMP,
				    np->cname, NULL, dump_np->cname);
			}
		}
	}
	(void) close(dump_fd);
	return (rval);
}

/*
 * check whether device is mounted
 */
static int
meta_check_mounted(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	FILE		*mfp;
	struct mnttab	m;
	int		rval = 0;
	char		mountp[MNT_LINE_MAX];
	char		mnt_special[MNT_LINE_MAX];

	/* should have a set */
	assert(sp != NULL);

	/* look in mnttab */
	if ((mfp = open_mnttab()) == NULL)
		return (mdsyserror(ep, errno, MNTTAB));
	while ((getmntent(mfp, &m) == 0) && (rval == 0)) {
		char		**fstype = skip_these_mntents;
		int		skipit = 0;
		mdname_t	*mnp;

		if ((m.mnt_special == NULL) || (m.mnt_mountp == NULL))
			continue;

		if (m.mnt_mountp[0] != '/')
			continue;

		while (*fstype != NULL)
			if (strcmp(m.mnt_fstype, *fstype++) == 0) {
				skipit++;
				break;
			}

		if (skipit == 1)
			continue;

		(void) strcpy(mountp, m.mnt_mountp);
		(void) strcpy(mnt_special, m.mnt_special);

		if ((mnp = metaname(&sp, mnt_special, UNKNOWN, ep)) == NULL) {
			mdclrerror(ep);
			continue;
		}

		if (np->dev == mnp->dev) {
			rval = mduseerror(ep, MDE_IS_MOUNTED,
			    np->dev, mountp, np->cname);
		} else { /* device isn't in mnttab - does it overlap? */
			rval = meta_check_overlap(mnp->cname, np, 0, -1,
			    mnp, 0, -1, ep);
			if (rval != 0) {
				(void) mdoverlaperror(ep, MDE_OVERLAP_MOUNTED,
				    np->cname, mountp, mnp->cname);
			}
		}
	}

	/* return success */
	return (rval);
}


/*
 * Is a file system currently mounted on this disk drive?
 */
int
meta_check_drivemounted(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,
	md_error_t	*ep
)
{
	FILE		*mfp;
	struct mnttab	m;
	int		rval = 0;
	char		mountp[MNT_LINE_MAX];
	char		mnt_special[MNT_LINE_MAX];

	/* should have a set */
	assert(sp != NULL);

	/* look in mnttab */
	if ((mfp = open_mnttab()) == NULL)
		return (mdsyserror(ep, errno, MNTTAB));
	while ((getmntent(mfp, &m) == 0) && (rval == 0)) {
		char		**fstype = skip_these_mntents;
		int		skipit = 0;
		mdname_t	*mnp;

		if ((m.mnt_special == NULL) || (m.mnt_mountp == NULL))
			continue;

		if (m.mnt_mountp[0] != '/')
			continue;

		while (*fstype != NULL)
			if (strcmp(m.mnt_fstype, *fstype++) == 0) {
				skipit++;
				break;
			}

		if (skipit == 1)
			continue;

		(void) strcpy(mountp, m.mnt_mountp);
		(void) strcpy(mnt_special, m.mnt_special);
		if ((mnp = metaname(&sp, mnt_special,
		    LOGICAL_DEVICE, ep)) == NULL) {
			mdclrerror(ep);
			continue;
		}
		if (strcmp(dnp->cname, mnp->drivenamep->cname) == 0) {
			rval = mduseerror(ep, MDE_IS_MOUNTED, NODEV64,
			    mountp, dnp->cname);
		}
	}

	/* return success */
	return (rval);
}

/*
 * Check to see if the specified name is already in use or overlaps
 * with a device already in use. Checks are made to determine whether
 * the device is mounted, is a swap device, or a dump device.  In each
 * case if the device is not in use then an overlap check is done to ensure
 * that the specified slice does not overlap.
 */
int
meta_check_inuse(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdinuseopts_t	inuse_flags,
	md_error_t	*ep
)
{
	int			rval = 0;

	if ((inuse_flags & MDCHK_MOUNTED) &&
	    (rval = meta_check_mounted(sp, np, ep)) != 0)
		return (rval);

	if ((inuse_flags & MDCHK_SWAP) &&
	    (rval = meta_check_swapped(sp, np, ep)) != 0)
		return (rval);

	if ((inuse_flags & MDCHK_DUMP) &&
	    (rval = meta_check_dump(sp, np, ep)) != 0)
		return (rval);

	return (rval);
}

int
meta_check_driveinset(mdsetname_t *sp, mddrivename_t *dn, md_error_t *ep)
{
	set_t		setno;
	set_t		max_sets;

	if ((max_sets = get_max_sets(ep)) == 0)
		return (-1);

	for (setno = 1; setno < max_sets; setno++) {
		mdsetname_t	*sp1;
		int		is_it;

		if (setno == sp->setno)
			continue;

		if ((sp1 = metasetnosetname(setno, ep)) == NULL) {
			if (mdismddberror(ep, MDE_DB_NODB)) {
				mdclrerror(ep);
				return (0);
			}
			if (mdiserror(ep, MDE_NO_SET)) {
				mdclrerror(ep);
				continue;
			}
			return (-1);
		}

		metaflushsetname(sp1);

		if ((is_it = meta_is_drive_in_thisset(sp1, dn, FALSE, ep))
		    == -1)
			return (-1);

		if (is_it)
			return (mddserror(ep, MDE_DS_DRIVEINSET, sp->setno,
			    sp1->setname, dn->cname, sp->setname));
	}

	return (0);
}

/*
 * Add a device/device id tuple to the devname cache
 */
static void
add_to_devname_list(
	char 		*device_name,		/* fully qualified dev name */
	ddi_devid_t	devid			/* device id */
)
{
	dev_list_t	*dnlp;

	dnlp = Zalloc(sizeof (*dnlp));
	dnlp->dev_name = Strdup(device_name);
	dnlp->devid = devid;

	/* link the node into the devname list */
	dnlp->dev_nxt = devnamelist;
	devnamelist = dnlp;
}

/*
 * check for same drive
 *
 * Differentiate between matching on name/dev_t and devid.  In the latter
 * case it is correct to fail but misleading to give the same error msg as
 * for an overlapping slice.
 *
 */
int
meta_check_samedrive(
	mdname_t	*np1,		/* first comp */
	mdname_t	*np2,		/* second comp */
	md_error_t	*ep
)
{

	mdcinfo_t	*cinfop1, *cinfop2;
	mdnmtype_t	type1 = np1->drivenamep->type;
	mdnmtype_t	type2 = np2->drivenamep->type;
	int		l = 0;

	char		*name1 = NULL;
	char		*name2 = NULL;

	int		retval = CANT_TELL;
	int		fd1 = -1;
	int		fd2 = -1;
	int		rc1 = -2, rc2 = -2;
	uint_t		strl1 = 0, strl2 = 0;
	int		devid1_found = 0;
	int		devid2_found = 0;

	ddi_devid_t	devid1 = NULL;
	ddi_devid_t	devid2 = NULL;
	dev_list_t	*dnlp = NULL;

	assert(type1 != MDT_FAST_META && type1 != MDT_FAST_COMP);
	assert(type2 != MDT_FAST_META && type2 != MDT_FAST_COMP);

	/*
	 * The process of determining if 2 names are the same drive is
	 * as follows:
	 *
	 * Case 1 - The filenames are identical
	 *
	 * Case 2 - Both devices have a devid
	 * 	get and compare the devids for the devices. If both
	 * 	devices have a devid then the compare will is all
	 *	that is needed we are done.
	 *
	 * Case 3 - One or more devices does not have a devid
	 *	start by doing a simple compare of the name, if they
	 *	are the same just return.
	 *
	 *	If the names differ then keep going and see if the
	 *	may be the same underlying devic.  First check to
	 *	see if the sd name is the same (old code).
	 *
	 *	Then check the major and minor numbers to see if
	 *	they are the same.  If they are then return (old code).
	 *
	 *	Next compare the raw name and the component name and
	 *	if they are the same then return.
	 *
	 *	All else has failed so use the component name (cname)
	 *	component number and unit number.  If they all are
	 *	equal then call them the same drive.
	 *
	 */

	if ((np1 == NULL) || (np2 == NULL))
		return (NOT_SAMEDRIVE);

	/* if the name structs are the same then the drives must be */
	if (np1 == np2)
		return (IDENTICAL_NAME_DEVT);

	name1 = np1->bname;
	name2 = np2->bname;

	if ((name1 == NULL) || ((strl1 = strlen(name1)) == 0) ||
	    (name2 == NULL) || ((strl2 = strlen(name2)) == 0))
		return (NOT_SAMEDRIVE);

	if ((strl1 == strl2) && (strcmp(name1, name2) == 0)) {
		/* names are identical */
		return (IDENTICAL_NAME_DEVT);
	}

	if (is_metaname(name1) || is_metaname(name2))
		return (NOT_SAMEDRIVE);

	/*
	 * Check to see if the devicename is in the static list.  If so,
	 * use its devid.  Otherwise do the expensive operations
	 * of opening the device, getting the devid, and closing the
	 * device.  Add the result into the static list.
	 *
	 * The case where this list will be useful is when there are soft
	 * partitions on multiple drives and a new soft partition is being
	 * created.  In that situation the underlying physical device name
	 * for the new soft partition would be compared against each of the
	 * existing soft partititions.  Without this static list that would
	 * involve 2 opens, closes, and devid gets for each existing soft
	 * partition
	 */
	for (dnlp = devnamelist; (dnlp != NULL) &&
	    !(devid1_found && devid2_found); dnlp = dnlp->dev_nxt) {
		if (!devid1_found && (strcmp(dnlp->dev_name, name1) == 0)) {
			devid1_found = 1;
			devid1 = dnlp->devid;
			if (devid1 == NULL)
				rc1 = 1;
			else
				rc1 = 0;
			continue;
		}
		if (!devid2_found && (strcmp(dnlp->dev_name, name2) == 0)) {
			devid2_found = 1;
			devid2 = dnlp->devid;
			if (devid2 == NULL)
				rc2 = 1;
			else
				rc2 = 0;
			continue;
		}
	}

	/*
	 * Start by checking if the device has a device id, and if they
	 * are equal.  If they are there is no question there is a match.
	 *
	 * The process here is open each disk, get the devid for each
	 * disk.  If they both have a devid compare them and return
	 * the results.
	 */
	if (!devid1_found) {
		if ((fd1 = open(name1, O_RDONLY | O_NDELAY)) < 0) {
			return (NOT_SAMEDRIVE);
		}
		rc1 = devid_get(fd1, &devid1);
		(void) close(fd1);

		/* add the name and devid to the cache */
		add_to_devname_list(name1, devid1);
	}

	if (!devid2_found) {
		if ((fd2 = open(name2, O_RDONLY | O_NDELAY)) < 0) {
			return (NOT_SAMEDRIVE);
		}
		rc2 = devid_get(fd2, &devid2);
		(void) close(fd2);

		/* add the name and devid to the cache */
		add_to_devname_list(name2, devid2);
	}


	if ((rc1 == 0) && (rc2 == 0)) {
		if (devid_compare(devid1, devid2) == 0)
			retval = IDENTICAL_DEVIDS; /* same devid */
		else
			retval = NOT_SAMEDRIVE; /* different drives */

	}

	if (retval >= 0) {
		return (retval);
	}

	/*
	 * At this point in time one of the two drives did not have a
	 * device ID.  Do not make the assumption that is one drive
	 * did have a device id and the other did not that they are not
	 * the same.  One drive could be covered by a device and still
	 * be the same drive.  This is a general flaw in the system at
	 * this time.
	 */

	/*
	 * The optimization can not happen if we are given an old style name
	 * in the form /dev/XXNN[a-h], since the name caches differently and
	 * allows overlaps to happen.
	 */
	if (! ((sscanf(np1->bname, "/dev/%*[^0-9/]%*u%*[a-h]%n", &l) == 0 &&
	    l == strlen(np1->bname)) ||
	    (sscanf(np2->bname, "/dev/%*[^0-9/]%*u%*[a-h]%n", &l) == 0 &&
	    l == strlen(np2->bname))) &&
	    ((type1 == MDT_COMP) || (type1 == MDT_META)) &&
	    ((type2 == MDT_COMP) || (type2 == MDT_META)))
		if (np1->drivenamep == np2->drivenamep)
			return (IDENTICAL_NAME_DEVT);
		else
			return (NOT_SAMEDRIVE);

	/* check for same drive */
	if (meta_getmajor(np1->dev) != meta_getmajor(np2->dev))
		return (NOT_SAMEDRIVE);		/* not same drive */

	if (((cinfop1 = metagetcinfo(np1, ep)) == NULL) ||
	    ((cinfop2 = metagetcinfo(np2, ep)) == NULL)) {
		if ((strcmp(np1->drivenamep->cname,
		    np2->drivenamep->cname) != 0) &&
		    (strcmp(np1->drivenamep->rname,
		    np2->drivenamep->rname) != 0)) {
			mdclrerror(ep);
			return (NOT_SAMEDRIVE);	/* not same drive */
		} else {
			return (CANT_TELL);	/* can't tell */
		}
	} else if ((strncmp(cinfop1->cname, cinfop2->cname,
	    sizeof (cinfop1->cname)) != 0) ||
	    (cinfop1->cnum != cinfop2->cnum) ||
	    (cinfop1->unit != cinfop2->unit)) {
		return (NOT_SAMEDRIVE);		/* not same drive */
	}

	/* same drive */
	return (IDENTICAL_NAME_DEVT);
}

/*
 * check for overlap
 */
int
meta_check_overlap(
	char		*uname,		/* user supplied name for errors */
	mdname_t	*np1,		/* first comp */
	diskaddr_t	slblk1,		/* first comp - start logical block */
	diskaddr_t	nblks1,		/* first comp - # of blocks */
	mdname_t	*np2,		/* second comp */
	diskaddr_t	slblk2,		/* second comp - start logical block */
	diskaddr_t	nblks2,		/* second comp - # of blocks */
	md_error_t	*ep
)
{
	diskaddr_t	sblk1, sblk2;
	mdvtoc_t	*vtocp1, *vtocp2;
	uint_t		partno1, partno2;
	mdpart_t	*partp1, *partp2;
	int		ret;

	/* verify args */
	if (slblk1 == MD_DISKADDR_ERROR) {
		assert(0);
		return (mdsyserror(ep, EINVAL, np1->cname));
	}
	if (slblk2 == MD_DISKADDR_ERROR) {
		assert(0);
		return (mdsyserror(ep, EINVAL, np2->cname));
	}

	/* check for same drive */
	if ((ret = meta_check_samedrive(np1, np2, ep)) == 0) {
		return (0);			/* not same drive */
	} else if (ret < 0) {
		return (-1);			/* can't tell */
	}

	/* check for overlap */
	if (((vtocp1 = metagetvtoc(np1, FALSE, &partno1, ep)) == NULL) ||
	    ((vtocp2 = metagetvtoc(np2, FALSE, &partno2, ep)) == NULL)) {
		return (-1);			/* can't tell */
	}
	partp1 = &vtocp1->parts[partno1];
	partp2 = &vtocp2->parts[partno2];
	sblk1 = partp1->start + slblk1;
	if (nblks1 == -1)
		nblks1 = partp1->size - slblk1;
	sblk2 = partp2->start + slblk2;
	if (nblks2 == -1)
		nblks2 = partp2->size - slblk2;
	if (((sblk1 >= sblk2) && (sblk1 < (sblk2 + nblks2))) ||
	    ((sblk2 >= sblk1) && (sblk2 < (sblk1 + nblks1)))) {
		if (np1->dev == np2->dev) {	/* slice in use */
			return (mduseerror(ep, MDE_ALREADY, np1->dev,
			    uname, np1->cname));
		}
		if (ret == IDENTICAL_NAME_DEVT)
			return (mduseerror(ep,		/* slice overlaps */
			    MDE_OVERLAP, np1->dev, uname, np1->cname));
		else
			return (mduseerror(ep,		/* same devid */
			    MDE_SAME_DEVID, np1->dev, uname, np2->cname));
	}

	/* return success */
	return (0);				/* no overlap */
}

/*
 * check to see if a device is in a metadevice
 */
int
meta_check_inmeta(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdchkopts_t	options,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	uint_t		partno;

	/* see if replica slice is ok, only applies to disks in sets */
	if (! (options & MDCHK_ALLOW_REPSLICE) &&
	    ! metaislocalset(sp)) {
		uint_t	rep_slice;

		if (metagetvtoc(np, FALSE, &partno, ep) == NULL)
			return (-1);
		if (meta_replicaslice(np->drivenamep, &rep_slice, ep)
		    != 0)
			return (-1);
		if (partno == rep_slice)
			return (mddeverror(ep, MDE_REPCOMP_INVAL, np->dev,
			    np->cname));
	}

	/* check for databases */
	if (meta_check_inreplica(sp, np, slblk, nblks, ep) != 0) {
		if (mdisuseerror(ep, MDE_ALREADY)) {
			if (options & MDCHK_ALLOW_MDDB) {
				mdclrerror(ep);
			} else {
				return (mddeverror(ep, MDE_HAS_MDDB,
				    np->dev, np->cname));
			}
		} else {
			return (-1);
		}
	}

	/* check metadevices */
	if (meta_check_instripe(sp, np, slblk, nblks, ep) != 0)
		return (-1);
	if (meta_check_inmirror(sp, np, slblk, nblks, ep) != 0)
		return (-1);
	if (meta_check_intrans(sp, np, options, slblk, nblks, ep) != 0)
		return (-1);
	if (meta_check_insp(sp, np, slblk, nblks, ep) != 0)
		return (-1);
	if (! (options & MDCHK_ALLOW_HS)) {
		if (meta_check_inhsp(sp, np, slblk, nblks, ep) != 0)
			return (-1);
	}
	if (meta_check_inraid(sp, np, slblk, nblks, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * check to see if a device is in its set
 */
int
meta_check_inset(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	mdsetname_t	*npsp;
	int		bypass_daemon = FALSE;


	/* check devices set */
	if (metaislocalset(sp))
		bypass_daemon = TRUE;
	if ((npsp = metagetset(np, bypass_daemon, ep)) == NULL) {
		if ((! metaismeta(np)) &&
		    (metaislocalset(sp)) &&
		    (mdismddberror(ep, MDE_DB_NODB))) {
			mdclrerror(ep);
			npsp = sp;
		} else {
			return (-1);
		}
	}

	/* check set */
	if (metaissameset(sp, npsp))
		return (0);

	/* return appropriate error */
	if (metaislocalset(sp))
		return (mddeverror(ep, MDE_IN_SHARED_SET, np->dev, np->cname));
	else
		return (mddeverror(ep, MDE_NOT_IN_SET, np->dev, np->cname));
}

/*
 * check to see if current user is root
 */
int
meta_check_root(md_error_t *ep)
{
	if (geteuid() != 0) {
		(void) mderror(ep, MDE_NOPERM, "");
		return (-1);
	}
	return (0);
}
