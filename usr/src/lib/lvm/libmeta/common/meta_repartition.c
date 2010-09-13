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

#include <stdio.h>
#include <meta.h>
#include "meta_repartition.h"



/*
 * FUNCTION:	meta_replicaslice()
 * INPUT:	dnp	- the name of the drive to check
 * OUTPUT:	slicep	- pointer to slice number
 *		ep	- pointer to an md_error_t structure in which
 *			  to return errors to the caller
 * RETURNS:	int	-  0 - value pointed to by slicep is valid
 *			  -1 - otherwise
 *
 * PURPOSE:	Determine which slice of the specified drive to
 *		reserve, presumably for metadb replica usage.
 *
 * NOTE:	If slicep is NULL, the return code will indicate
 *		whether or not the slice number could be determined
 */
int
meta_replicaslice(
	mddrivename_t	*dnp,
	uint_t		*slicep,
	md_error_t	*ep
)
{
	int		err = 0;
	int		ioctl_return;
	int		fd;
	char		*rname;
	struct dk_geom	geom;

	rname = dnp->rname;
	if ((fd = open(rname, (O_RDONLY|O_NDELAY), 0)) < 0) {
		char	*n;
		int	open_errno;
		size_t	len;

		if (errno != ENOENT)
			return (mdsyserror(ep, errno, rname));

		len = strlen(rname) + 3;
		n = Zalloc(len);
		(void) snprintf(n, len, "%ss0", rname);
		fd = open(n, (O_RDONLY|O_NDELAY), 0);
		open_errno = errno;
		Free(n);
		if (fd < 0) {
			return (mdsyserror(ep, open_errno, rname));
		}
	}

	/*
	 * if our drivenamep points to a device not supporting
	 * DKIOCGGEOM, we have an EFI label.
	 */
	errno = 0;
	ioctl_return = ioctl(fd, DKIOCGGEOM, &geom);
	err = errno;

	(void) close(fd);

	/*
	 * If the DKIOCGGEOM ioctl succeeded, then the device has a
	 * VTOC style label.  In this case, we use slice 7.
	 */
	if (ioctl_return == 0) {
		if (slicep != NULL) {
			*slicep = MD_SLICE7;
		}
		return (0);
	}

	/*
	 * ENOTSUP indicates an EFI style label, in which case slice 7
	 * cannot be used because its minor number is reserved.  In
	 * this case, use slice 6.
	 */
	if (err == ENOTSUP) {
		if (slicep != NULL) {
			*slicep = MD_SLICE6;
		}
		return (0);
	}

	/*
	 * Those are the only two cases we know how to deal with;
	 * either the drivenamep didn't point to a disk, or the ioctl
	 * failed for some other reason.
	 */
	if (err == ENOTTY) {
		return (mddeverror(ep, MDE_NOT_DISK, NODEV, rname));
	}

	return (mdsyserror(ep, err, rname));
}



/*
 * FUNCTION:	meta_repartition_drive()
 * INPUT:	sp	- the set name for the device to check
 *		dnp	- the name of the drive to partition
 *              options - options (see NOTES)
 * OUTPUT:	vtocp	- pointer to an mdvtoc_t structure in which
 *			  to return the new VTOC to the caller
 *		ep	- pointer to an md_error_t structure in which
 *			  to return errors to the caller
 * RETURNS:	int	-  0 - drive was or can be repartitioned
 *			  -1 - drive could not or should not be
 *			       repartitioned
 * PURPOSE:	Repartition a disk for use in a disk set or in order
 *		to create soft partitions on it.  Alternatively,
 *		return the VTOC that the disk would have if it were
 *		repartitioned without actually repartitioning it.
 *
 * NOTES:
 *
 *     This routine will repartition a drive to make it suitable for
 *     inclusion in a diskset.  Specifically, it will create a
 *     proposed VTOC that specifies a replica slice that begins at the
 *     first valid lba, is large enough to hold a label and a metadb
 *     replica, does not overlap any other slices, and is unmountable.
 *     If the current replica slice already satisfies those criteria,
 *     the routine will neither create a proposed VTOC nor repartition
 *     the drive unless the MD_REPART_FORCE flag is passed into the
 *     routine in the options argument.  If the routine does create a
 *     proposed VTOC, it will return the proposed VTOC in *vtocp if
 *     vtocp isn't NULL.
 *
 *     The slice to be used as the replica slice is determined by the
 *     function meta_replicaslice().
 *
 *     If the replica slice does not satisfy the above criteria or the
 *     MD_REPART_FORCE flag is set, the proposed VTOC will specify a
 *     replica slice that satisfies the above criteria, a slice zero
 *     that contains the remaining space on the disk, and no other
 *     slices.  If that repartitioning would cause the replica slice
 *     to move or shrink, and the MD_REPART_LEAVE_REP option is set,
 *     the routine will return -1 without creating or returning a
 *     proposed vtoc, and without repartitioning the disk.  Otherwise
 *     the routine will repartition the disk unless the
 *     MD_REPART_DONT_LABEL flag is set in the options argument.
 *
 *     If the MD_REPART_DONT_LABEL flag is set in the options argument,
 *     but the routine would otherwise repartition the drive, the
 *     routine won't repartition the drive, but will create a proposed
 *     VTOC that satisfies the criteria defined above and return it
 *     it in *vtocp if vtocp isn't NULL,  The MD_REPART_DONT_LABEL
 *     option allows calling routines to determine what the contents of
 *     the drive's VTOC would be if the drive were repartitioned without
 *     actually repartitioning the drive.
 */
int
meta_repartition_drive(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,
	int		options,
	mdvtoc_t	*vtocp,
	md_error_t	*ep
)
{
	uint_t			 replicaslice;
	diskaddr_t		 first_lba, last_lba;
	int			 round_sizes = 1;
	unsigned long long	 cylsize;
	unsigned long long	 drvsize;
	int			 i;
	mdgeom_t		*mdgp;
	mdvtoc_t		*mdvp;
	mdvtoc_t		 proposed_vtoc;
	uint_t			 reservedcyl;
	ushort_t		 resflag;
	mdname_t		*resnp;
	unsigned long long	 ressize;
	md_set_desc		*sd;
	daddr_t			 dbsize;
	diskaddr_t		 replica_start;
	diskaddr_t		 replica_size;
	diskaddr_t		 replica_end;
	diskaddr_t		 data_start;
	diskaddr_t		 data_size;

	if (meta_replicaslice(dnp, &replicaslice, ep) != 0) {
		return (-1);
	}

	/* Don't round for EFI disks */
	if (replicaslice == MD_SLICE6)
		round_sizes = 0;

	/*
	 * We took as argument a drive name pointer, but we need a
	 * slice name pointer to retrieve vtoc information.  So get
	 * the name pointer for slice zero first, then use it to get
	 * the vtoc info for the disk.
	 */
	if ((resnp = metaslicename(dnp, MD_SLICE0, ep)) == NULL)
		return (-1);

	if ((mdvp = metagetvtoc(resnp, FALSE, NULL, ep)) == NULL)
		return (-1);

	/*
	 * Determine the metadb size.
	 */
	dbsize = MD_DBSIZE;
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);

		if (MD_MNSET_DESC(sd))
			dbsize = MD_MN_DBSIZE;
	}

	/* If we've got an efi disk, we better have lba info */
	first_lba = mdvp->first_lba;
	last_lba = mdvp->last_lba;
	ASSERT((round_sizes != 0) || (last_lba > 0));

	/*
	 * At this point, ressize is used as a minimum value.  Later
	 * it will be rounded up to a cylinder boundary if
	 * appropriate.  ressize is in units of disk sectors.
	 */
	ressize = dbsize + VTOC_SIZE;
	resflag = V_UNMNT;

	/*
	 * If we're forcing the repartition, we can skip the replica
	 * slice and overlap tests.
	 */
	if (options & MD_REPART_FORCE) {
		goto do_repartition;
	}

	/*
	 * Replica slice tests: it must begin at first_lba, be long
	 * enough, have the right flags, and not overlap any other
	 * slices.  If any of these conditions is violated, we need to
	 * repartition the disk.
	 */
	if (mdvp->parts[replicaslice].start != first_lba) {
		goto do_repartition;
	}

	if (mdvp->parts[replicaslice].size < ressize) {
		goto do_repartition;
	}

	if (mdvp->parts[replicaslice].flag != resflag) {
		goto do_repartition;
	}

	/*
	 * Check for overlap: this test should use the actual size of
	 * the replica slice, as contained in the vtoc, and NOT the
	 * minimum size calculated above.
	 */
	replica_end = first_lba + mdvp->parts[replicaslice].size;
	for (i = 0; i < mdvp->nparts; i++) {
		if (i != replicaslice) {
			if ((mdvp->parts[i].size > 0) &&
			    (mdvp->parts[i].start < replica_end)) {
				goto do_repartition;
			}
		}
	}

	/*
	 * If we passed the above tests, then the disk is already
	 * partitioned appropriately, and we're not being told to
	 * force a change.
	 */
	return (0);

do_repartition:

	/* Retrieve disk geometry info and round to cylinder sizes */
	if (round_sizes != 0) {

		if ((mdgp = metagetgeom(resnp, ep)) == NULL)
			return (-1);

		/*
		 * Both cylsize and drvsize are in units of disk
		 * sectors.
		 *
		 * The intended results are of type unsigned long
		 * long.  Since each operand of the first
		 * multiplication is of type unsigned int, we risk
		 * overflow by multiplying and then converting the
		 * result.  Therefore we explicitly cast (at least)
		 * one of the operands, forcing conversion BEFORE
		 * multiplication, and avoiding overflow.  The second
		 * assignment is OK, since one of the operands is
		 * already of the desired type.
		 */
		cylsize =
		    ((unsigned long long)mdgp->nhead) * mdgp->nsect;
		drvsize = cylsize * mdgp->ncyl;

		/*
		 * How many cylinders must we reserve for the replica
		 * slice to ensure that it meets the previously
		 * calculated minimum size?
		 */
		reservedcyl = (ressize + cylsize - 1) / cylsize;
		ressize = reservedcyl * cylsize;
	} else {
		drvsize = last_lba - first_lba;
	}

	/* Would this require a forbidden change? */
	if (options & MD_REPART_LEAVE_REP) {
		if ((mdvp->parts[replicaslice].start != first_lba) ||
		    (mdvp->parts[replicaslice].size < ressize)) {
			return (mddeverror(ep, MDE_REPART_REPLICA,
			    resnp->dev, NULL));
		}
	}

	/*
	 * It seems unlikely that someone would pass us too small a
	 * disk, but it's still worth checking for...
	 */
	if (((round_sizes != 0) && (reservedcyl >= (int)mdgp->ncyl)) ||
	    ((round_sizes == 0) && (ressize + first_lba >= last_lba))) {
		return (mdmddberror(ep, MDE_DB_TOOSMALL,
		    meta_getminor(resnp->dev), sp->setno, 0, NULL));
	}

	replica_start = first_lba;
	replica_size = ressize;
	data_start = first_lba + ressize;
	data_size = drvsize - ressize;

	/*
	 * Create the proposed VTOC.  First copy the current VTOC
	 * into the proposed VTOC to duplicate the values that don't
	 * need to change.  Then change the partition table and set
	 * the flag value for the replica slice to resflag to reserve it
	 * for metadata.
	 */
	proposed_vtoc = *mdvp;
	/* We need at least replicaslice partitions in the proposed vtoc */
	if (replicaslice >= proposed_vtoc.nparts) {
		proposed_vtoc.nparts = replicaslice + 1;
	}
	for (i = 0; i < proposed_vtoc.nparts; i++) {
		/* don't change the reserved partition of an EFI device */
		if (proposed_vtoc.parts[i].tag == V_RESERVED)
			data_size = proposed_vtoc.parts[i].start - data_start;
		else
			(void) memset(&proposed_vtoc.parts[i], '\0',
				sizeof (proposed_vtoc.parts[i]));
	}

	proposed_vtoc.parts[MD_SLICE0].start = data_start;
	proposed_vtoc.parts[MD_SLICE0].size = data_size;
	proposed_vtoc.parts[MD_SLICE0].tag = V_USR;
	proposed_vtoc.parts[replicaslice].start = replica_start;
	proposed_vtoc.parts[replicaslice].size = replica_size;
	proposed_vtoc.parts[replicaslice].flag = resflag;
	proposed_vtoc.parts[replicaslice].tag = V_USR;

	if (!(options & MD_REPART_DONT_LABEL)) {
		/*
		 * Label the disk with the proposed VTOC.
		 */
		*mdvp = proposed_vtoc;
		if (metasetvtoc(resnp, ep) != 0) {
			return (-1);
		}
	}

	if (vtocp != NULL) {
		/*
		 * Return the proposed VTOC.
		 */
		*vtocp = proposed_vtoc;
	}

	return (0);
}
