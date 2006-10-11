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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Metadevice diskset interfaces
 */

#include "meta_set_prv.h"
#include <sys/lvm/md_crc.h>
#include <strings.h>
#include <sys/bitmap.h>

extern	char	*blkname(char *);

static int
upd_dr_dbinfo(
	mdsetname_t		*sp,
	md_set_desc		*sd,
	md_drive_desc		*dd,
	md_replicalist_t	*rlp,
	int			forceflg,
	md_error_t		*ep
)
{
	md_drive_desc		*p;
	md_replica_t		*r;
	md_replicalist_t	*rl;
	int			i;
	int			dbcnt;
	int			rval = 0;
	daddr_t			nblks = 0;
	md_setkey_t		*cl_sk;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;
	ddi_devid_t		devid;

	/* find the smallest existing replica */
	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		r = rl->rl_repp;
		nblks = ((nblks == 0) ? r->r_nblk : min(r->r_nblk, nblks));
	}

	if (nblks <= 0)
		nblks = (MD_MNSET_DESC(sd)) ? MD_MN_DBSIZE : MD_DBSIZE;

	for (p = dd; p != NULL; p = p->dd_next) {
		dbcnt = 0;
		for (rl = rlp; rl != NULL; rl = rl->rl_next) {
			r = rl->rl_repp;

			/*
			 * Before we bump up the dbcnt, if we're
			 * running with device ids in disksets, let's
			 * compare the device ids otherwise we compare
			 * the ctd names.
			 *
			 * There is a possibility the device ids might
			 * have changed. To account for that case, we
			 * fallback to comparing the ctd names if the
			 * device id comparison fails. If we aren't running
			 * in device id mode and a disk has moved, the ctd's
			 * won't match.
			 */
			if ((p->dd_dnp->devid != NULL) &&
			    (r->r_devid != NULL) && (!MD_MNSET_DESC(sd))) {
				(void) devid_str_decode(p->dd_dnp->devid,
				    &devid, NULL);
				if ((devid_compare(devid, r->r_devid) == 0) ||
				    (strcmp(r->r_namep->drivenamep->cname,
				    p->dd_dnp->cname) == 0))
					dbcnt++;
				devid_free(devid);
			} else {
				if (strcmp(r->r_namep->drivenamep->cname,
				    p->dd_dnp->cname) == 0)
					dbcnt++;
			}
		}
		p->dd_dbcnt = dbcnt;
		p->dd_dbsize = dbcnt > 0 ? nblks : 0;
	}

	/* Lock the set on current set members */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* If this is forced, don't lock other sides */
			if (forceflg && strcmp(mynode(), nd->nd_nodename)
			    != 0) {
				nd = nd->nd_next;
				continue;
			}

			/* We already locked this side in the caller */
			if (strcmp(mynode(), nd->nd_nodename) == 0) {
				nd = nd->nd_next;
				continue;
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
				rval = -1;
				goto out;
			}
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* If this is forced, don't lock other sides */
			if (forceflg && strcmp(mynode(), sd->sd_nodes[i]) != 0)
				continue;

			/* We already locked this side in the caller */
			if (strcmp(mynode(), sd->sd_nodes[i]) == 0)
				continue;

			if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
				rval = -1;
				goto out;
			}
		}
	}

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* If this is forced, then only care about this node */
			if (forceflg && strcmp(mynode(), nd->nd_nodename)
			    != 0) {
				nd = nd->nd_next;
				continue;
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_upd_dr_dbinfo(nd->nd_nodename, sp, dd,
			    ep) == -1) {
				if (! mdiserror(ep, MDE_NO_SET) &&
				    ! mdismddberror(ep, MDE_DB_NODB)) {
					rval = -1;
					break;
				}
				mdclrerror(ep);
			}
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* If this is forced, then only care about this node */
			if (forceflg && strcmp(mynode(), sd->sd_nodes[i]) != 0)
				continue;

			if (clnt_upd_dr_dbinfo(sd->sd_nodes[i], sp, dd,
			    ep) == -1) {
				if (! mdiserror(ep, MDE_NO_SET) &&
				    ! mdismddberror(ep, MDE_DB_NODB)) {
					rval = -1;
					break;
				}
				mdclrerror(ep);
			}
		}
	}

out:
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* If this is forced, don't unlock other sides */
			if (forceflg && strcmp(mynode(), nd->nd_nodename)
			    != 0) {
				nd = nd->nd_next;
				continue;
			}

			/* We will unlocked this side in the caller */
			if (strcmp(mynode(), nd->nd_nodename) == 0) {
				nd = nd->nd_next;
				continue;
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* If this is forced, don't unlock other sides */
			if (forceflg && strcmp(mynode(), sd->sd_nodes[i]) != 0)
				continue;

			/* We will unlocked this side in the caller */
			if (strcmp(mynode(), sd->sd_nodes[i]) == 0)
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
		}
	}
	/* Do not clear the key, via cl_set_setkey(NULL) this is nested */

	return (rval);
}

static int
usetag_take(set_t setno, int usetag, md_error_t *ep)
{
	mddb_dtag_use_parm_t	dtup;

	(void) memset(&dtup, '\0', sizeof (mddb_dtag_use_parm_t));
	dtup.dtup_id = usetag;
	dtup.dtup_setno = setno;

	if (metaioctl(MD_MED_USE_TAG, &dtup, &dtup.dtup_mde, NULL) != 0)
		return (mdstealerror(ep, &dtup.dtup_mde));

	return (0);
}

static int
useit_take(set_t setno, md_error_t *ep)
{
	mddb_accept_parm_t	accp;

	(void) memset(&accp, '\0', sizeof (mddb_accept_parm_t));
	accp.accp_setno = setno;

	if (metaioctl(MD_MED_ACCEPT, &accp, &accp.accp_mde, NULL) != 0)
		return (mdstealerror(ep, &accp.accp_mde));

	return (0);
}

/*
 * Update the master block with the device id information for the disks
 * in the diskset. The device id information will be consumed by the
 * diskset import code in case of remotely replicated disksets.
 *
 * For the drives that have a valid diskset mddb on them, we add the
 * device id for the drive to the unused portion of the mddb.
 *
 * For the drives that don't have a diskset mddb on them, we add a dummy
 * master block that contains the device id for the drive. A dummy master
 * block is signified by changing the master block magic number, mb_magic,
 * to MDDB_MAGIC_DU.
 *
 * This code is responsible primarily for adding the appropriate device id
 * information to diskset disks that didn't have the information. This would
 * typically occur when the OS has been upgraded from an OS release prior to
 * Solaris 10
 *
 * The error path in this routine is defined as - if an error occurs while
 * updating the mddb for one disk in the diskset, don't bother updating *any*
 * of the mddbs because it's game over anyways as far as disaster recovery for
 * that diskset is concerned.
 *
 * This code will need to be revisited if and when support for importing
 * partial disksets is added.
 *
 * NOTE: This code relies heavily on the meta_repartition() working correctly
 * and reformatting a drive, so that there's enough room for a dummy master
 * block, every time a drive is added to a diskset. Should
 * the meta_repartition() code change in future, this code will have to be
 * revisited.
 *
 * Returns 0 on success and -1 on failure
 */
int
meta_update_mb(mdsetname_t *sp, md_drive_desc *drivedesc, md_error_t *ep)
{
	uint_t			sliceno, offset;
	void			*mb;
	mddb_mb_t		*mbp;
	int			fd = -1;
	ddi_devid_t		devid = NULL;
	md_drive_desc		*dd;
	mddrivename_t		*dnp;
	mdname_t		*rsp;
	int			dbcnt;
	int			dbsize;
	size_t 			len;
	md_set_desc		*sd;

	/*
	 * Don't do anything for MN diskset for now.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);

		if (MD_MNSET_DESC(sd))
			return (0);
	}

	mb = Malloc(DEV_BSIZE);
	mbp = (mddb_mb_t *)mb;

	/*
	 * For every drive in the drive descriptor, iterate through all
	 * the mddbs present on it and check to see if mb_devid_magic is
	 * set. If it isn't, then update the master block with the correct
	 * device id information
	 */
	for (dd = drivedesc; dd != NULL; dd = dd->dd_next) {
		int i = 0;

		dnp = dd->dd_dnp;
		dbcnt = dd->dd_dbcnt;
		dbsize = dd->dd_dbsize;

		/*
		 * When the import support for remotely replicated
		 * disksets gets implemented, we probably want to
		 * inform the user that the disks won't be self
		 * identifying if any of these calls fails
		 */
		if (meta_replicaslice(dnp, &sliceno, ep) != 0)
			return (-1);

		if ((rsp = metaslicename(dnp, sliceno, ep)) == NULL)
			return (-1);

		if ((fd = open(rsp->rname, O_RDWR)) < 0)
			goto cleanup;

		/* if devid_str_decode fails, make sure devid is null */
		if (devid_str_decode(dnp->devid, &devid, NULL) != 0) {
			devid = NULL;
		}

		do {
			int push = 0;

			offset = (i * dbsize + 16);
			++i;

			if (lseek(fd, (off_t)dbtob(offset), SEEK_SET) < 0)
				goto cleanup;

			if (read(fd, mbp, DEV_BSIZE) != DEV_BSIZE)
				goto cleanup;

			if (crcchk((uchar_t *)mbp, (uint_t *)&mbp->mb_checksum,
			    (uint_t)DEV_BSIZE, (crc_skip_t *)NULL))
				goto cleanup;

			/*
			 * If the disk is one of the ones that doesn't
			 * have a shared mddb on it, we put a dummy
			 * master block on it.
			 */
			if (mbp->mb_devid_magic != MDDB_MAGIC_DE) {
				if (dbcnt == 0) {
					meta_mkdummymaster(sp, fd, 16);
					break;
				}
			}

			/*
			 * if mb_setcreatetime is 0, this field was never
			 * filled in so do it now.
			 */
			if ((mbp->mb_setcreatetime.tv_sec == 0) &&
			    (mbp->mb_setcreatetime.tv_usec == 0)) {
				mbp->mb_setcreatetime =
				    meta_get_lb_inittime(sp, ep);
				push = 1;
			}

			/*
			 * If MDDB_MAGIC_DE is set in the
			 * mb_devid_magic field then we know we
			 * have a valid device id and we don't
			 * need to add it to the master block.
			 *
			 * This would have to be revisited if device
			 * ids change as a result of device id
			 * algorithms changing or somesuch.
			 */
			if (mbp->mb_devid_magic != MDDB_MAGIC_DE) {
				if (devid != NULL) {
					len = devid_sizeof(devid);
					if (len <= (DEV_BSIZE -
					    sizeof (mddb_mb_t))) {
						/*
						 * there's enough space to
						 * store the devid
						 */
						mbp->mb_devid_magic =
						    MDDB_MAGIC_DE;
						mbp->mb_devid_len = len;
						(void) memcpy(mbp->mb_devid,
						    (char *)devid, len);
						push = 1;
					}
				}
			}

			/*
			 * write out (push) any changes we have to the mb
			 */
			if (push) {
				crcgen((uchar_t *)mbp,
				    (uint_t *)&mbp->mb_checksum,
				    (uint_t)DEV_BSIZE, (crc_skip_t *)NULL);

				if (lseek(fd, (off_t)dbtob(offset), SEEK_SET)
				    < 0)
					goto cleanup;

				if (write(fd, mbp, DEV_BSIZE) != DEV_BSIZE)
					goto cleanup;
			}
			if (devid)
				devid_free(devid);
		} while (i < dbcnt);
		(void) close(fd);
	}
	/* success */
	return (0);

cleanup:
	if (fd != -1)
		(void) close(fd);
	if (devid)
		devid_free(devid);
	return (-1);
}

extern int *replicated_disk_list_built;
extern int replicated_disk_list_built_pass1;
/*
 * Exported Entry Points
 */
int
meta_set_take(
	mdsetname_t		*sp,
	mhd_mhiargs_t		*mhiargsp,
	int			flags,
	int			usetag,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	md_drive_desc		*dd;
	md_drive_desc		*d = NULL;
	char			*owner = NULL;
	int			rval = 0;
	int			pathname_return = 0;
	int			i;
	int			has_set;
	int			matches = 0;
	int			numsides = 0;
	md_replicalist_t	*rlp = NULL;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	int			rb_level = 0;
	md_error_t		xep = mdnullerror;
	mdsetname_t		*local_sp = NULL;
	side_t			side;
	int			ret = 0;
	char			*newname = NULL;
	mdkey_t			side_names_key;
	int			unrslv_replicated = 0;
	mddrivenamelist_t	*dnlp = NULL;
	int			retake_flag = 0;
	unsigned long 		node_active[BT_BITOUL(MD_MAXSIDES)];

	bzero(node_active, sizeof (unsigned long) * BT_BITOUL(MD_MAXSIDES));

	if ((flags & TAKE_USETAG) || (flags & TAKE_USEIT)) {
		if (flags & TAKE_USETAG) {
			if (usetag_take(sp->setno, usetag, ep))
				return (-1);
		} else {
			if (useit_take(sp->setno, ep))
				return (-1);
		}

		if (meta_resync_all(sp, MD_DEF_RESYNC_BUF_SIZE, ep) != 0)
			mdclrerror(ep);
	}

	/* Do we own the set? */
	i = own_set(sp, &owner, (flags & TAKE_FORCE), ep);
	if (! mdisok(ep)) {
		if (owner != NULL)
			Free(owner);
		return (-1);
	}

	if (i == MD_SETOWNER_NO) {
		(void) mddserror(ep, MDE_DS_NOTOWNER, sp->setno, owner, NULL,
		    sp->setname);
		if (owner != NULL)
			Free(owner);
		return (-1);
	}

	if (owner != NULL) {
		Free(owner);
		owner = NULL;
	}

	/* We already own it, we are done. */
	if (i == MD_SETOWNER_YES)
		return (0);

	if ((sd = metaget_setdesc(sp, &xep)) == NULL)
		return (-1);

	/* You can not take ownership of a set that has no drives */
	if (sd->sd_flags & MD_SR_MB_DEVID)
		dd = metaget_drivedesc(sp, MD_BASICNAME_OK | PRINT_FAST, ep);
	else
		dd = metaget_drivedesc(sp, MD_BASICNAME_OK, ep);

	if (dd == NULL) {
		if (! mdisok(ep))
			return (-1);
		return (0);
	}

	/* END CHECK CODE */

	md_rb_sig_handling_on();

	/* Lock the set on our side */
	if (clnt_lock_set(mynode(), sp, ep)) {
		rval = -1;
		goto out;
	}

	/*
	 * Find the "side" value so that it can be used to deal with
	 * the devids.
	 */
	side = getnodeside(mynode(), sd);

	if (side == MD_SIDEWILD) {
	    (void) mddserror(ep, MDE_DS_HOSTNOSIDE, sp->setno, mynode(),
		NULL, mynode());
	    rval = -1;
	    goto out;
	}

	/*
	 * A local sets' side 0 references records associated with
	 * that node's local set. As this is a non-local set, "side"
	 * must be modified (by adding a SKEW) before we reference
	 * records in the local set [setno = 0] for the non-local set
	 * [setno = 1..n].
	 */
	side += SKEW;

	/*
	 * If this set had been previously imported as a partial replicated
	 * diskset, then must attempt to updated any unresolved drive
	 * records in diskset with new devid information.  Must set
	 * flags in drivedesc list before loading up set so that the
	 * md driver will fix up names and devids correctly in the
	 * locator block.
	 */
	if (sd->sd_flags & MD_SR_UNRSLV_REPLICATED) {
		md_im_names_t		cnames = { 0, NULL};
		ddi_devid_t		old_devid, new_devid;
		char			*search_path = "/dev";
		devid_nmlist_t		*nmlist;
		int			indx;
		mddrivenamelist_t	**dnlpp = &dnlp;

		if (meta_list_disks(ep, &cnames) != 0) {
			rval = -1;
			goto out;
		}

		for (indx = 0; indx < cnames.min_count; ++indx) {
			mddrivename_t   *dnp;
			mdsetname_t	*sp =  metasetname(MD_LOCAL_NAME, ep);
			int		fd = -1;
			ddi_devid_t	devid1;
			char		*cdevidp;
			int		len;
			char		*fp;

			/*
			 * We may have name collision here so we need to get
			 * the dnp using the devid and not the name.
			 */
			len = strlen(cnames.min_names[indx]) + strlen("s0");
			if ((fp = (char *)Malloc(len+1)) == NULL) {
				(void) mdsyserror(ep, ENOMEM, NULL);
				rval = -1;
				goto out;
			}
			(void) snprintf(fp, len + 1, "%ss0",
			    cnames.min_names[indx]);
			if ((fd = open(fp, O_RDONLY|O_NDELAY)) < 0) {
				(void) mdsyserror(ep, EIO, fp);
				rval = -1;
				goto out;
			}
			Free(fp);
			/* if no device id, what error?) */
			if (devid_get(fd, &devid1) != 0) {
				(void) mdsyserror(ep, EIO, fp);
				rval = -1;
				goto out;
			}
			if (close(fd) < 0) {
				(void) mdsyserror(ep, EIO, fp);
				rval = -1;
				goto out;
			}
			cdevidp = devid_str_encode(devid1, NULL);
			if (cdevidp == NULL) {
				(void) mdsyserror(ep, EIO, fp);
				rval = -1;
				goto out;
			}
			devid_free(devid1);
			dnp = metadrivenamebydevid(&sp, cdevidp,
			    cnames.min_names[indx], ep);
			devid_str_free(cdevidp);
			if (dnp == NULL) {
				/*
				 * Assuming we're interested in knowing about
				 * whatever error occurred, but not in stopping.
				 */
				mde_perror(ep, cnames.min_names[indx]);
				mdclrerror(ep);
				continue;
			}

			dnlpp = meta_drivenamelist_append_wrapper(dnlpp, dnp);
		}
		/* Reget sd and dd since freed by meta_prune_cnames. */
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			rval = -1;
			goto out;
		}

		if (sd->sd_flags & MD_SR_MB_DEVID)
			dd = metaget_drivedesc(sp,
				MD_BASICNAME_OK | PRINT_FAST, ep);
		else
			dd = metaget_drivedesc(sp,
				MD_BASICNAME_OK, ep);
		/* If ep has error, then there was a failure, set rval */
		if (!mdisok(ep)) {
			rval = -1;
			goto out;
		}

		/* Builds global replicated disk list */
		replicated_disk_list_built = &replicated_disk_list_built_pass1;

		/* If success, then clear error structure */
		if (build_replicated_disks_list(ep, dnlp) == 1)
			mdclrerror(ep);
		/* If ep has error, then there was a failure, set rval */
		if (! mdisok(ep)) {
			rval = -1;
			goto out;
		}

		for (d = dd; d != NULL; d = d->dd_next) {
			if (d->dd_flags & MD_DR_UNRSLV_REPLICATED) {
				/* Get old devid from drive record */
				(void) devid_str_decode(d->dd_dnp->devid,
				    &old_devid, NULL);

				/*
				 * If the devid stored in the drive record
				 * (old_devid) matches a devid known by
				 * the system, then this disk has already
				 * been partially resolved.  This situation
				 * could occur if a panic happened during a
				 * previous take of this diskset.
				 * Set flag to later handle fixing the master
				 * block on disk and turning off the unresolved
				 * replicated flag.
				 */
				if (meta_deviceid_to_nmlist(search_path,
				    (ddi_devid_t)old_devid,
				    DEVID_MINOR_NAME_ALL,
				    &nmlist) == 0) {
					d->dd_flags |= MD_DR_FIX_MB_DID;
					retake_flag = 1;
					continue;
				}

				/*
				 * If the devid stored in the drive record
				 * is on the list of replicated disks found
				 * during a system scan then set both flags
				 * so that the locator block, namespaces
				 * (diskset and local set), master block
				 * and unresolved replicated flag are updated.
				 */
				new_devid = replicated_list_lookup(
				    devid_sizeof((ddi_devid_t)old_devid),
				    old_devid);
				devid_free(old_devid);

				/*
				 * If devid stored in the drive record is
				 * not found then set flag to mark
				 * that set is still unresolved and
				 * continue to next drive record.
				 */
				if (new_devid == NULL) {
					unrslv_replicated = 1;
					continue;
				}

				/*
				 * Set flags to fix up the master block,
				 * locator block of the diskset, diskset
				 * namespace and the local set namespace.
				 */
				d->dd_flags |= (MD_DR_FIX_MB_DID |
						MD_DR_FIX_LB_NM_DID);
				retake_flag = 1;
			}
		}

	}

	/*
	 * Check the local devid namespace to see if the disks
	 * have been moved. Use the local set first of all as this contains
	 * entries for the disks in the set.
	 *
	 * This is being done before the tk_own_bydd because the disks
	 * in the dd list could be wrong! But it should be done with the lock
	 * held for the set.
	 */
	local_sp = metasetname(MD_LOCAL_NAME, ep);
	for (d = dd; d != NULL; d = d->dd_next) {
		/*
		 * Actually do the check of the disks.
		 */
		ret = meta_upd_ctdnames(&local_sp, 0, side, d->dd_dnp, &newname,
		    ep);

		if ((ret == METADEVADM_ERR) ||
		    (ret == METADEVADM_DSKNAME_ERR)) {
			/* check failed in some unknown manner */
			rval = -1;
			goto out;
		} else if (ret == METADEVADM_DISKMOVE) {

			/*
			 * Update the dd namelist so that the rpc.metamhd
			 * gets the correct disks to reserve - it is the rname
			 * we are interested in.
			 */
			if (newname != NULL) {
				char	*save_devid;
				/*
				 * Need to save the side names key as this
				 * points to the namespace entry that will
				 * need to be updated. In addition the call
				 * to meta_make_sidenmlist does not actually
				 * set the namespace key.
				 */
				side_names_key = d->dd_dnp->side_names_key;

				/*
				 * There is the possibility that there
				 * will be multiple disks with the same
				 * name but different devids in the
				 * drivelist. Because of this, we need
				 * to look for a new dnp based on devid
				 * and not name.
				 */
				save_devid = Strdup(d->dd_dnp->devid);
				metafreedrivename(d->dd_dnp);
				d->dd_dnp = metadrivenamebydevid(&sp,
				    save_devid, newname, ep);
				Free(save_devid);
				Free(newname);
				/*
				 * null newname so we are reset for next time
				 * through
				 */
				newname = NULL;
				ret = meta_make_sidenmlist(sp,
					    d->dd_dnp, 0, NULL, ep);
				d->dd_dnp->side_names_key = side_names_key;
				if (ret == -1) {
					rval = -1;
					goto out;
				}
			}
		}
	}


	RB_TEST(1, "take", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "take", ep)

	if (!MD_ATSET_DESC(sd)) {
		if (tk_own_bydd(sp, dd, mhiargsp,
		    flags & MD_IM_PARTIAL_DISKSET, ep))
			goto rollback;
	}

	RB_TEST(3, "take", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(4, "take", ep)

	if (clnt_stimeout(mynode(), sp, mhiargsp, ep) == -1)
		goto rollback;

	if (setup_db_bydd(sp, dd, (flags & TAKE_FORCE), ep) == -1) {
		if (! mdismddberror(ep, MDE_DB_ACCOK) &&
		    ! mdismddberror(ep, MDE_DB_TAGDATA))
			goto rollback;
		mdclrerror(ep);
	}

	RB_TEST(5, "take", ep)

	RB_PREEMPT;
	rb_level = 3;	/* level 3 */

	RB_TEST(6, "take", ep)

	/* Snarf set of traditional diskset doesn't use stale information */
	if (snarf_set(sp, FALSE, ep)) {
		if (mdismddberror(ep, MDE_DB_STALE) ||
		    mdismddberror(ep, MDE_DB_ACCOK) ||
		    mdismddberror(ep, MDE_DB_TAGDATA)) {
			rval = -1;
			goto out;
		}

		if (! mdismddberror(ep, MDE_DB_NODB) &&
		    ! mdismddberror(ep, MDE_DB_NOTOWNER))
			goto rollback;

		/*
		 * Look at the set on all other hosts, if every other host
		 * has the same set with a larger genid, then we destroy this
		 * copy.
		 */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip this node */
			if (strcmp(sd->sd_nodes[i], mynode()) == 0)
				continue;

			numsides++;

			has_set = nodehasset(sp, sd->sd_nodes[i],
			    NHS_NST_EQ_G_GT, &xep);

			if (has_set < 0) {
				if (! mdiserror(&xep, MDE_NO_SET) &&
				    ! mdismddberror(&xep, MDE_DB_NODB))
					goto rollback;
				matches++;
				mdclrerror(&xep);
				continue;
			}

			if (has_set)
				matches++;
		}

		/* Destroy the set */
		if (numsides > 0 && (numsides - matches) == 0) {
			if (meta_set_destroy(sp, FALSE, &xep))
				mdclrerror(&xep);
			(void) mddserror(ep, MDE_DS_SETCLEANUP, sp->setno,
			    sp->setname, NULL, mynode());
			rval = -1;
		}
		goto rollback;
	}

	/*
	 * If an unresolved replicated diskset, fix up diskset
	 * and local namespaces, master block and drive record
	 * with the new devid.  If all drives in diskset are
	 * now resolved, then clear set unresolved replicated flag.
	 * If an error is encountered, don't fail the take, but
	 * don't proceed any further in resolving the replicated disks.
	 */
	if (sd->sd_flags & MD_SR_UNRSLV_REPLICATED) {
		/* Fix up diskset and local namespaces with new devids */
		meta_unrslv_replicated_nm(sp, dd, dnlp, ep);
		if (mdisok(ep)) {
			/* Fix up master block with new devids  */
			meta_unrslv_replicated_mb(sp, dd, dnlp, ep);
		}

		/* If all drives are resolved, set OK flag in set record. */
		if (mdisok(ep) && (unrslv_replicated == 0)) {
			/* Ignore failure since no bad effect. */
			(void) clnt_upd_sr_flags(mynode(), sp, MD_SR_OK, ep);
		}
		mdclrerror(ep);

	}

	pathname_return = pathname_reload(&sp, sp->setno, ep);
	if ((pathname_return == METADEVADM_ERR) ||
	    (pathname_return == METADEVADM_DSKNAME_ERR)) {
		goto rollback;
	}


	if (metareplicalist(sp, (MD_BASICNAME_OK | PRINT_FAST), &rlp, ep) < 0)
		goto rollback;

	if (upd_dr_dbinfo(sp, sd, dd, rlp, (flags & TAKE_FORCE), ep) < 0) {
		metafreereplicalist(rlp);
		goto rollback;
	}

	metafreereplicalist(rlp);

	/*
	 * If the set doesn't have the MD_SR_MB_DEVID bit set, i.e
	 * the drives in the set don't have the device id information,
	 * then stick it in if possible.
	 *
	 * If updating the master block fails for whatever reason, it's
	 * okay. It just means the disk(s) in the diskset won't be self
	 * identifying.
	 */
	if (!(sd->sd_flags & MD_SR_MB_DEVID)) {
		/* Lock the set on current set members */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* We already locked this side */
			if (strcmp(mynode(), sd->sd_nodes[i]) == 0)
				continue;

			if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
				/*
				 * Ignore any RPC errors on a force
				 * take. The set will have been taken
				 * above and we still need to continue.
				 */
				if (flags & TAKE_FORCE)
					continue;
				rval = -1;
				goto out;
			}
			BT_SET(node_active, i);
		}
		rb_level = 4;	/* level 4 */

		if (meta_update_mb(sp, dd, ep) == 0)
			/* update the sr_flags on all hosts */
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/*
				 * Only update those nodes that
				 * are active (ie those that the
				 * set is locked on).
				 */
				if (!BT_TEST(node_active, i))
					continue;

				if (clnt_upd_sr_flags(sd->sd_nodes[i],
				    sp, (sd->sd_flags | MD_SR_MB_DEVID), ep))
					goto rollback;
			}

		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Unlocked of this side is done later */
			if (strcmp(mynode(), sd->sd_nodes[i]) == 0)
				continue;

			/* no point calling dead nodes */
			if (!BT_TEST(node_active, i))
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
		}
	}

	/*
	 * If we get here, we need to unlock the set before the resync
	 * gets called, otherwise the "daemon" will hold the set lock
	 * until the resync is done!
	 */

	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(mynode(), cl_sk, &xep)) {
		if (rval == 0)
			(void) mdstealerror(ep, &xep);
		rval = -1;
	}
	cl_set_setkey(NULL);

	md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	/* We try to get things resync'ed, but this can fail */
	mdclrerror(&xep);
	if (meta_resync_all(sp, MD_DEF_RESYNC_BUF_SIZE, &xep) != 0) {
		if (rval == 0)
			(void) mdstealerror(ep, &xep);
		rval = -1;
	}

	RB_TEST(7, "take", ep)

	/*
	 * In order to resolve the namespace major driver names and
	 * to have the subdrivers attempt to re-associate devts from
	 * the newly resolved replicated device ids, return a '2'.
	 * This instructs metaset to release the diskset and re-take.
	 *
	 * Return a 2 if
	 * 	- no error was detected on the take
	 *	- a replicated unresolved devid was resolved during take
	 *	- take isn't being called during an import
	 *	- this isn't already a re-take situation
	 */
	if ((rval == 0) && (retake_flag == 1) &&
	    ((flags & (TAKE_RETAKE | TAKE_IMP)) == 0)) {
		rval = 2;
	}

	return (rval);

out:
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(mynode(), cl_sk, &xep)) {
		if (rval == 0)
			(void) mdstealerror(ep, &xep);
		rval = -1;
	}
	if (!(sd->sd_flags & MD_SR_MB_DEVID) && (rb_level > 2)) {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* We already unlocked this side */
			if (strcmp(mynode(), sd->sd_nodes[i]) == 0)
				continue;

			/* no point calling dead nodes */
			if (!BT_TEST(node_active, i))
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
		}
	}
	cl_set_setkey(NULL);

	md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	return (rval);

rollback:
	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	rval = -1;

	/* level 4 */
	if (rb_level > 3) {
		if (sd->sd_flags & MD_SR_MB_DEVID) {
			/* update the sr_flags on all hosts */
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/* no point calling dead nodes */
				if (!BT_TEST(node_active, i))
					continue;

				if (clnt_upd_sr_flags(sd->sd_nodes[i], sp,
				    (sd->sd_flags & ~MD_SR_MB_DEVID), &xep))
					mdclrerror(&xep);
			}
		}

		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* We will unlocked this side below */
			if (strcmp(mynode(), sd->sd_nodes[i]) == 0)
				continue;

			/* no point calling dead nodes */
			if (!BT_TEST(node_active, i))
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 3 */
	if (rb_level > 2) {
		if (halt_set(sp, &xep))
			mdclrerror(&xep);
	}

	/* level 2 */
	if (rb_level > 1) {
		if (clnt_stimeout(mynode(), sp, &defmhiargs, &xep) == -1)
			mdclrerror(&xep);
	}

	/* level 1 */
	if (rb_level > 0) {
		if (!MD_ATSET_DESC(sd)) {
			if (rel_own_bydd(sp, dd, FALSE, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(mynode(), cl_sk, &xep))
		mdclrerror(&xep);
	cl_set_setkey(NULL);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	return (rval);
}

int
meta_set_release(
	mdsetname_t		*sp,
	md_error_t		*ep
)
{
	int			rval = 0;
	md_drive_desc		*dd;
	mhd_mhiargs_t		mhiargs;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	int			rb_level = 0;
	md_error_t		xep = mdnullerror;

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	/* Get the drive descriptors */
	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL)
		if (! mdisok(ep))
			return (-1);

	/* Get timeout values in case we need to roll back this release */
	(void) memset(&mhiargs, '\0', sizeof (mhiargs));
	if (clnt_gtimeout(mynode(), sp, &mhiargs, ep) != 0)
		return (-1);

	/* END CHECK CODE */

	md_rb_sig_handling_on();

	/* Lock the set on our side */
	if (clnt_lock_set(mynode(), sp, ep)) {
		rval = -1;
		goto out;
	}

	RB_TEST(1, "release", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "release", ep)

	if (halt_set(sp, ep))
		goto rollback;

	RB_TEST(3, "release", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(4, "release", ep)

	if (rel_own_bydd(sp, dd, FALSE, ep))
		goto rollback;

	RB_TEST(5, "release", ep)

	RB_PREEMPT;
	rb_level = 3;	/* level 3 */

	RB_TEST(6, "release", ep)

	if (clnt_stimeout(mynode(), sp, &defmhiargs, ep) == -1)
		goto rollback;

	RB_TEST(7, "release", ep)

out:
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(mynode(), cl_sk, &xep)) {
		if (rval == 0)
			(void) mdstealerror(ep, &xep);
		rval = -1;
	}
	cl_set_setkey(NULL);

	md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	return (rval);

rollback:
	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	rval = -1;

	/* level 3 */
	if (rb_level > 2) {
		if (clnt_stimeout(mynode(), sp, &mhiargs, &xep) == -1)
			mdclrerror(&xep);
	}

	/* level 2 */
	if (rb_level > 1) {
		if (tk_own_bydd(sp, dd, &mhiargs, FALSE, &xep))
			mdclrerror(&xep);
	}

	/* level 1 */
	if (rb_level > 0) {
		if (setup_db_bydd(sp, dd, TRUE, &xep) == -1)
			mdclrerror(&xep);

		/* Snarf set of trad diskset doesn't use stale information */
		if (snarf_set(sp, FALSE, &xep))
			mdclrerror(&xep);
	}

	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(mynode(), cl_sk, &xep))
		mdclrerror(&xep);
	cl_set_setkey(NULL);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	return (rval);
}
