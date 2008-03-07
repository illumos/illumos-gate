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
 * Metadevice diskset interfaces
 */

#include "meta_set_prv.h"
#include <meta.h>
#include <sys/lvm/md_mddb.h>
#include <sys/cladm.h>
#include <devid.h>
#include <sys/lvm/md_convert.h>
#include <sdssc.h>

/*
 * Exported Entry Points
 */

int
checkdrive_onnode(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,
	char		*node,
	md_error_t	*ep)
{
	time_t			mystamp, otherstamp;
	md_dev64_t		otherdev;
	mdname_t		*np, *remote_np;
	mddrivename_t		*remote_dnp;
	int			release = 0;
	md_drive_desc		dd;
	int			rval = 0;
	int			ret = -1;
	mhd_mhiargs_t		mhiargs;
	md_set_desc		*sd;
	int			is_efi = 0;
	int			do_fallback = 0;

	(void) memset(&mhiargs, '\0', sizeof (mhiargs));

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (meta_is_drive_in_thisset(sp, dnp, FALSE, ep)) {
		release = 1;
		dd.dd_next = NULL;
		dd.dd_dbcnt = 0;
		dd.dd_dbsize = 0;
		dd.dd_dnp = dnp;
		if (clnt_gtimeout(mynode(), sp, &mhiargs, ep) != 0)
			return (-1);
		if (!(MD_MNSET_DESC(sd)) && !MD_ATSET_DESC(sd)) {
			if (rel_own_bydd(sp, &dd, TRUE, ep))
				return (-1);
		}
	}
	if ((np = metaslicename(dnp, MD_SLICE0, ep)) == NULL) {
		rval = -1;
		goto out;
	}

	/*
	 * First try and operate assuming the other side
	 * is running a SVM version that supports device id
	 * in disksets i.e. is running SVM RPC version 2.
	 *
	 * If this call fails due to the other side running
	 * a SVM version that does not support device id
	 * in disksets i.e. is running SVM RPC version 1, we
	 * fallback to the old behaviour.
	 */
	if (dnp->devid != NULL) {
		char		*rname = NULL;
		md_dev64_t	dev = NODEV64;

		/*
		 * If the disk is connected to the remote node then the
		 * only thing we can be certain of is that the disk will
		 * have the same devid on that node, it may not have the
		 * same minor number nor the same ctd name. But if it
		 * does have the same ctd name then use it.  In most cases
		 * there will only be a single entry returned but if the
		 * system has multi-path disks with MPXIO turned off there
		 * will be multiple entries. Attempting to choose the same
		 * name will give  the user as consistent a view across the
		 * nodes as possible.
		 */
		ret = clnt_devinfo_by_devid(node, sp, dnp->devid, &dev,
		    np->rname, &rname, NULL, ep);

		/*
		 * If the return value was ENOTSUP, we know the
		 * other side is not running a SVM version that
		 * supports device id in disksets. We fallback
		 * to the previous behaviour in that case.
		 */
		if (ret == ENOTSUP) {
			do_fallback++;
			goto fallback;
		} else if (ret == -1) {
			rval = -1;
			goto out;
		}

		/*
		 * If the device does not exist on the remote node then
		 * the returned dev should indicate this (NODEV64) but
		 * we also check to make sure the returned name is not
		 * empty to make sure that the namespace does not get
		 * created with a NULL/empty entry (should not be possbile
		 * but being paranoid).
		 */
		if (dev == NODEV64 || rname == (char *)NULL ||
		    strcmp(rname, "") == 0) {
			rval = mddserror(ep, MDE_DS_DRIVENOTCOMMON, sp->setno,
			    node, dnp->cname, sp->setname);
			goto out;
		}

		/*
		 * The rname returned from the remote node maybe different
		 * to the rname on this node, therefore we need to build up
		 * a dnp for this new rname.
		 */
		if (strcmp(np->rname, rname) != 0) {
			/* different rname */
			remote_np = metaname_fast(&sp, rname,
			    LOGICAL_DEVICE, ep);
			if (remote_np != NULL) {
				remote_dnp = remote_np->drivenamep;
			}
		} else {
			remote_dnp = dnp;
		}
	} else {
		do_fallback++;
	}

fallback:
	if (do_fallback) {
		ret = setdevstamp(dnp, &mystamp, ep);
		/*
		 * Check if the disk in question is an EFI disk.
		 */
		if (ret == ENOTSUP)
			is_efi++;
		else if (ret == -1)
			return (-1);

		if ((np = metaslicename(dnp, MD_SLICE0, ep)) == NULL) {
			rval = -1;
			goto out;
		}

		if (is_efi) {
			/*
			 * For EFI disks, we compare the device
			 * id for the disks in question.
			 */
			ddi_devid_t	thisdevid, otherdevid;
			char		*encoded_otherdevid = NULL;
			char		*encoded_thisdevid = NULL;

			if (clnt_devinfo(node, sp, dnp, &otherdev, NULL, ep)
			    == -1) {
				rval = -1;
				goto out;
			}
			if (np->dev != otherdev) {
				rval = mddserror(ep, MDE_DS_DRIVENOTCOMMON,
				    sp->setno, node, dnp->cname, sp->setname);
				goto out;
			}

			if (clnt_devid(node, sp, dnp, &encoded_otherdevid,
			    ep) == -1) {
				rval = -1;
				goto out;
			}
			if (encoded_otherdevid == NULL) {
				rval = -1;
				goto out;
			}
			if (devid_str_decode(encoded_otherdevid, &otherdevid,
			    NULL) == 0) {
				/*
				 * If we are here, it means that dnp->devid
				 * is NULL. This will typically happen if
				 * we are dealing with SunCluster DID devices.
				 *
				 * We want to explicitly get the device id
				 * for such a disk
				 */
				encoded_thisdevid = meta_get_devid(dnp->rname);
				ret = devid_str_decode(encoded_thisdevid,
				    &thisdevid, NULL);
				if (ret == 0) {
					ret = devid_compare(thisdevid,
					    otherdevid);
					devid_free(thisdevid);
				}
				devid_free(otherdevid);
				if (encoded_thisdevid)
					Free(encoded_thisdevid);
			}

			Free(encoded_otherdevid);
			if (ret != 0) {
				rval = mddserror(ep, MDE_DS_DRIVENOTCOMMON,
				    sp->setno, node, dnp->cname, sp->setname);
				goto out;
			}
		} else {
			/*
			 * For VTOC disks, we compare the dev_t and
			 * timestamp for the disks in question.
			 */
			if (clnt_devinfo(node, sp, dnp, &otherdev,
			    &otherstamp, ep) == -1) {
				rval = -1;
				goto out;
			}
			if ((mystamp != otherstamp) || (np->dev != otherdev)) {
				rval = mddserror(ep, MDE_DS_DRIVENOTCOMMON,
				    sp->setno, node, dnp->cname, sp->setname);
				goto out;
			}
		}
		remote_dnp = dnp;
	}

	if (clnt_drvused(node, sp, remote_dnp, ep) == -1)
		rval = -1;

out:
	if (release)
		if (!(MD_MNSET_DESC(sd)) && !MD_ATSET_DESC(sd)) {
			if (tk_own_bydd(sp, &dd, &mhiargs, TRUE, ep))
				rval = -1;
		}

	return (rval);
}

side_t
getnodeside(char *node, md_set_desc *sd)
{
	side_t			sideno;
	int			nid;
	md_mnnode_desc		*nd;

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (strcmp(nd->nd_nodename, node) == 0) {
				return (nd->nd_nodeid);
			}
			nd = nd->nd_next;
		}
		return (MD_SIDEWILD);
	}


	/* If regular diskset */
	for (sideno = 0; sideno < MD_MAXSIDES; sideno++) {
		if (sd->sd_nodes[sideno] == NULL ||
		    sd->sd_nodes[sideno][0] == '\0')
			continue;

		if (strcmp(sd->sd_nodes[sideno], node) == 0) {
			return (sideno);
		}
	}

	/*
	 * If the first loop fails we may be in a situation where this host
	 * is configured as part of a cluster yet not running in the cluster
	 * mode. If so, the names stored in sd->sd_nodes[] are going to be
	 * nodeid's instead of hostnames. See if we can find a match that way.
	 */
	if (_cladm(CL_CONFIG, CL_NODEID, &nid) == 0) {
		for (sideno = 0; sideno < MD_MAXSIDES; sideno++) {
			if (sd->sd_nodes[sideno] == NULL ||
			    sd->sd_nodes[sideno][0] == '\0')
				continue;
			if (atoi(sd->sd_nodes[sideno]) == nid)
				return (sideno);
		}
	}

	return (MD_SIDEWILD);
}

int
halt_set(mdsetname_t *sp, md_error_t *ep)
{
	mddb_config_t	c;

	(void) memset(&c, 0, sizeof (c));
	c.c_setno = sp->setno;
	if ((c.c_sideno = getmyside(sp, ep)) == MD_SIDEWILD)
		return (-1);

	if (s_ownset(sp->setno, ep) == MD_SETOWNER_YES) {
		/* Don't need device id information from this ioctl */
		c.c_locator.l_devid = (uint64_t)0;
		c.c_locator.l_devid_flags = 0;
		/* Kill any resyncs that are running on mirrors in this set */
		meta_mirror_resync_kill(sp);
		if (metaioctl(MD_RELEASE_SET, &c, &c.c_mde, NULL) != 0)
			return (mdstealerror(ep, &c.c_mde));
	}

	return (0);
}

md_drive_desc *
metadrivedesc_append(
	md_drive_desc	**dd,
	mddrivename_t	*dnp,
	int		dbcnt,
	int		dbsize,
	md_timeval32_t	timestamp,
	ulong_t		genid,
	uint_t		flags
)
{
	md_drive_desc	*p;

	/* run to end of list */
	for (/* void */; (*dd != NULL); dd = &(*dd)->dd_next)
		/* void */;

	/* allocate new list element */
	p = *dd = Zalloc(sizeof (*p));

	p->dd_dnp = dnp;
	p->dd_dbcnt = dbcnt;
	p->dd_dbsize = dbsize;
	p->dd_ctime = timestamp;
	p->dd_genid = genid;
	p->dd_flags = flags;
	return (p);
}

int
nodehasset(
	mdsetname_t	*sp,
	char		*node,
	uint_t		match_flag,
	md_error_t	*ep
)
{
	md_set_desc	*sd;
	md_set_record	*sr;
	int		rval = 0;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Don't care if set record is MN or not */
	if (clnt_getset(node, sp->setname, MD_SET_BAD, &sr, ep))
		return (-1);

	if (sr == NULL) {
		if (! mdisok(ep))
			return (-1);
		return (0);
	}

	/* Looking for name only match */
	if ((match_flag & NHS_N_EQ) == NHS_N_EQ) {
		rval = 1;
		goto out;
	}

	if (sd->sd_setno != sr->sr_setno)
		goto out;

	/* Looking for name and setno match */
	if ((match_flag & NHS_NS_EQ) == NHS_NS_EQ) {
		rval = 1;
		goto out;
	}

	if (sd->sd_ctime.tv_sec != sr->sr_ctime.tv_sec ||
	    sd->sd_ctime.tv_usec != sr->sr_ctime.tv_usec)
		goto out;

	/* Looking for name, setno, and timestamp match */
	if ((match_flag & NHS_NST_EQ) == NHS_NST_EQ) {
		rval = 1;
		goto out;
	}

	if (sd->sd_genid != sr->sr_genid) {
		if (sd->sd_genid < sr->sr_genid) {
			/*
			 * Looking for name, setno, timestamp, and genid on
			 * other host is GT than other host.
			 */
			if ((match_flag & NHS_NST_EQ_G_GT) == NHS_NST_EQ_G_GT) {
				rval = 1;
				goto out;
			}
		}
		goto out;
	}

	/* Looking for name, setno, timestamp, and genid match */
	if ((match_flag & NHS_NSTG_EQ) == NHS_NSTG_EQ)
		rval = 1;

out:
	/*
	 * Set record structure was allocated from RPC routine getset
	 * so this structure is only of size md_set_record even if
	 * the MN flag is set.  So, clear the flag so that the free
	 * code doesn't attempt to free a structure the size of
	 * md_mnset_record.
	 */
	sr->sr_flags &= ~MD_SR_MN;
	free_sr(sr);

	return (rval);
}

int
nodesuniq(mdsetname_t *sp, int cnt, char **strings, md_error_t *ep)
{
	int i, j;
	for (i = 0; i < cnt; i++)
		for (j = i + 1; j < cnt; j++)
			if (strcmp(strings[i], strings[j]) == 0)
				return (mddserror(ep, MDE_DS_DUPHOST,
				    sp->setno, strings[i], NULL, sp->setname));
	return (0);
}

int
own_set(mdsetname_t *sp, char **owner_of_set, int forceflg, md_error_t *ep)
{
	md_set_desc		*sd;
	int			am_i_owner;
	int			i;

	if (metaislocalset(sp)) {
		if (owner_of_set != NULL)
			*owner_of_set = Strdup(mynode());
		return (MD_SETOWNER_YES);
	}

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (clnt_ownset(mynode(), sp, &am_i_owner, ep) == -1)
		return (-1);

	if (MD_MNSET_DESC(sd)) {
		if (am_i_owner == TRUE)
			return (MD_SETOWNER_YES);
		else
			return (MD_SETOWNER_NO);
	}

	if (forceflg == TRUE) {
		if (am_i_owner == TRUE) {
			if (owner_of_set != NULL)
				*owner_of_set = Strdup(mynode());
			return (MD_SETOWNER_YES);
		}

		if (owner_of_set != NULL)
			*owner_of_set = NULL;
		return (MD_SETOWNER_NONE);
	}

	if (am_i_owner == TRUE) {
		if (owner_of_set != NULL)
			*owner_of_set = Strdup(mynode());
		return (MD_SETOWNER_YES);
	}


	for (i = 0; i < MD_MAXSIDES; i++) {
		/*
		 * Skip empty slots, and my own slot.
		 */
		if (sd->sd_nodes[i][0] == '\0' ||
		    strcmp(sd->sd_nodes[i], mynode()) == 0)
			continue;

		if (clnt_ownset(sd->sd_nodes[i], sp, &am_i_owner, ep) == -1)
			return (-1);

		if (am_i_owner == TRUE) {
			if (owner_of_set != NULL)
				*owner_of_set = Strdup(sd->sd_nodes[i]);
			return (MD_SETOWNER_NO);
		}
	}

	/* We get here, we currently have no owner. */
	if (owner_of_set != NULL)
		*owner_of_set = NULL;
	return (MD_SETOWNER_NONE);
}

void
resync_genid(
	mdsetname_t		*sp,
	md_set_desc		*sd,
	ulong_t			max_genid,
	int			node_c,
	char			**node_v
)
{
	int			i, j;
	ulong_t			cur_genid[MD_MAXSIDES];
	md_set_record		*sr;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;
	md_mnset_record		*mnsr;

	if (node_c > 0 && node_v && *node_v) {
		/*
		 * Mark the set record MD_SR_OK.
		 */
		for (i = 0; i < node_c; i++)
			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_OK, &xep))
				mdclrerror(&xep);
		max_genid++;
	}

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			/* Will only return a multi-node diskset record */
			if (clnt_mngetset(nd->nd_nodename, sp->setname,
			    MD_SET_BAD, &mnsr, &xep) == -1) {
				mdclrerror(&xep);
				nd = nd->nd_next;
				continue;
			}
			for (j = mnsr->sr_genid; j < max_genid; j++) {
				if (clnt_upd_sr_flags(nd->nd_nodename, sp,
				    MD_SR_OK, &xep))
					mdclrerror(&xep);
			}
			free_sr((struct md_set_record *)mnsr);
			nd = nd->nd_next;
		}
		return;
	}

	/*
	 * Get current genid for each node.
	 */
	for (i = 0; i < MD_MAXSIDES; i++) {
		cur_genid[i] = 0;

		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		/* Should be a non-multinode diskset */
		if (clnt_getset(sd->sd_nodes[i], sp->setname,
		    MD_SET_BAD, &sr, &xep) == -1) {
			mdclrerror(&xep);
			continue;
		}

		if (MD_MNSET_REC(sr)) {
			/*
			 * Set record structure was allocated from RPC routine
			 * getset so this structure is only of size
			 * md_set_record even if the MN flag is set.  So,
			 * clear the flag so that the free code doesn't
			 * attempt to free a structure the size of
			 * md_mnset_record.
			 */
			sr->sr_flags &= ~MD_SR_MN;
			free_sr(sr);
			continue;
		}

		cur_genid[i] = sr->sr_genid;

		free_sr(sr);
	}

	/*
	 * Mark the set record MD_SR_OK
	 */
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		for (j = cur_genid[i]; j < max_genid; j++)
			if (clnt_upd_sr_flags(sd->sd_nodes[i], sp, MD_SR_OK,
			    &xep))
				mdclrerror(&xep);

	}
}

int
setup_db_bydd(mdsetname_t *sp, md_drive_desc *dd, int force, md_error_t *ep)
{
	md_drive_desc		*p;
	struct mddb_config	c;
	int			i;
	md_set_desc		*sd;
	int			use_devid = 1;
	ddi_devid_t		devidp, new_devidp;
	char			*minor_name = NULL;
	size_t			sz;
	char			*devid_str = NULL;
	sdssc_version_t		version;
	int			need_to_free_devidp = 0;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);
	(void) memset(&c, 0, sizeof (c));

	c.c_setno = sp->setno;
	(void) strcpy(c.c_setname, sp->setname);
	if ((c.c_sideno = getmyside(sp, ep)) == MD_SIDEWILD)
		return (-1);

	c.c_timestamp = sd->sd_ctime;

	if (setup_med_cfg(sp, &c, force, ep))
		return (-1);

	for (p = dd; p != NULL; p = p->dd_next) {
		mddrivename_t	*dnp;
		mdname_t	*np;
		mdcinfo_t	*cinfo;
		mdsidenames_t	*sn = NULL;

		if (p->dd_dbcnt == 0)
			continue;

		dnp = p->dd_dnp;

		assert(dnp != NULL);

		for (sn = dnp->side_names; sn != NULL; sn = sn->next) {
			if (sn->sideno == c.c_sideno)
				break;
		}

		/*
		 * The disk has no side name information
		 */
		if (sn == NULL) {
			uint_t	rep_slice;

			if ((meta_replicaslice(dnp, &rep_slice, ep) != 0) ||
			    ((np = metaslicename(dnp, rep_slice, ep))
			    == NULL)) {
				mdclrerror(ep);
				continue;
			}

			if (np->dev == NODEV64)
				continue;

			c.c_locator.l_dev = meta_cmpldev(np->dev);
			c.c_locator.l_mnum = meta_getminor(np->dev);

			if (!MD_MNSET_DESC(sd)) {
				/*
				 * minor_name will be NULL if dnp->devid == NULL
				 * - see metagetvtoc()
				 */
				if (np->minor_name != NULL) {
					minor_name = Strdup(np->minor_name);
				}
			}

			if ((cinfo = metagetcinfo(np, ep)) == NULL) {
				mdclrerror(ep);
				continue;
			}

			(void) strncpy(c.c_locator.l_driver, cinfo->dname,
			    sizeof (c.c_locator.l_driver));
		} else {
			c.c_locator.l_dev = NODEV32;
			c.c_locator.l_mnum = sn->mnum;
			(void) strncpy(c.c_locator.l_driver, sn->dname,
			    sizeof (c.c_locator.l_driver));

			if (!MD_MNSET_DESC(sd)) {
				if (dnp->devid != NULL) {
					minor_name = meta_getdidminorbykey(
					    MD_LOCAL_SET, sn->sideno + SKEW,
					    dnp->side_names_key, ep);
				}
			}
		}

		/*
		 * If the device does not have a devid or is a multinode
		 * diskset or we are in a SunCluster 3.x enviroment then
		 * do not use devids.
		 */
		if ((dnp->devid == NULL) || MD_MNSET_DESC(sd) ||
		    ((sdssc_version(&version) == SDSSC_OKAY) &&
		    (version.major >= 3))) {
			use_devid = 0;
		}

		if (use_devid) {
			/*
			 * The devid associated with the dnp does not have
			 * a minor name and so we must add it in.
			 */
			size_t	len = strlen(dnp->devid) +
			    strlen(minor_name) + 2;
			devid_str = (char *)Malloc(len);
			(void) snprintf(devid_str, len, "%s/%s", dnp->devid,
			    minor_name);
			(void) devid_str_decode(devid_str, &devidp, NULL);
			need_to_free_devidp = 1;

			/* If need to fix LB then setup old_devid info */
			if (p->dd_flags & MD_DR_FIX_LB_NM_DID) {
				sz = devid_sizeof(devidp);
				c.c_locator.l_old_devid_sz = sz;
				c.c_locator.l_old_devid = (uintptr_t)malloc(sz);
				(void) memcpy((void *)(uintptr_t)
				    c.c_locator.l_old_devid,
				    devidp, sz);

				new_devidp = replicated_list_lookup(
				    devid_sizeof((ddi_devid_t)devidp),
				    (void *)(uintptr_t)devidp);
				devid_free(devidp);
				need_to_free_devidp = 0;
				devidp = new_devidp;

			}
			sz = devid_sizeof(devidp);
			c.c_locator.l_devid = (uintptr_t)malloc(sz);
			c.c_locator.l_devid_sz = sz;
			(void) memcpy((void *)(uintptr_t)
			    c.c_locator.l_devid,
			    devidp, sz);
			if (need_to_free_devidp) {
				devid_free(devidp);
				need_to_free_devidp = 0;
			}
			if (minor_name == NULL) {
				/* ERROR fix up */
				Free(devid_str);
				Free((void *)(uintptr_t)c.c_locator.l_devid);
				if (c.c_locator.l_old_devid_sz) {
					Free((void *)
					    (uintptr_t)c.c_locator.l_old_devid);
					c.c_locator.l_old_devid_sz = 0;
					c.c_locator.l_old_devid =
					    (uintptr_t)NULL;
				}
				return (-1);
			}
			(void) strcpy(c.c_locator.l_minor_name,
			    minor_name);
			c.c_locator.l_devid_flags = MDDB_DEVID_VALID |
			    MDDB_DEVID_SPACE | MDDB_DEVID_SZ;
		} else {
			/*
			 * Don't need device id information from
			 * this ioctl
			 */
			c.c_locator.l_devid = (uint64_t)0;
			c.c_locator.l_devid_flags = 0;
		}


		for (i = 0; i < p->dd_dbcnt; i++) {
			c.c_locator.l_flags = 0;
			c.c_locator.l_blkno = 16 + i * p->dd_dbsize;

			if (metaioctl(MD_DB_USEDEV, &c, &c.c_mde, NULL) != 0) {
				if (use_devid) {
					Free(devid_str);
					Free((void *)
					    (uintptr_t)c.c_locator.l_devid);
					if (c.c_locator.l_old_devid_sz) {
						Free((void *)(uintptr_t)
						    c.c_locator.l_old_devid);
						c.c_locator.l_old_devid_sz = 0;
						c.c_locator.l_old_devid =
						    (uintptr_t)NULL;
					}
				}
				Free(minor_name);
				return (mdstealerror(ep, &c.c_mde));
			}
		}
		if (use_devid) {
			Free(devid_str);
			Free((void *)(uintptr_t)c.c_locator.l_devid);
			if (c.c_locator.l_old_devid_sz) {
				Free((void *)
				    (uintptr_t)c.c_locator.l_old_devid);
				c.c_locator.l_old_devid_sz = 0;
				c.c_locator.l_old_devid = (uintptr_t)NULL;
			}
		}
		Free(minor_name);
	}

	/* return success */
	return (0);
}

int
snarf_set(mdsetname_t *sp, bool_t stale_bool, md_error_t *ep)
{
	mddb_config_t	c;

	(void) memset(&c, '\0', sizeof (c));

	c.c_setno = sp->setno;
	if ((c.c_sideno = getmyside(sp, ep)) == MD_SIDEWILD)
		return (-1);

	/* Don't need device id information from this ioctl */
	c.c_locator.l_devid = (uint64_t)0;
	c.c_locator.l_devid_flags = 0;
	if (stale_bool == TRUE) {
		c.c_flags = MDDB_C_STALE;
	}
	if (metaioctl(MD_GRAB_SET, &c, &c.c_mde, NULL) != 0)
		return (mdstealerror(ep, &c.c_mde));

	if (c.c_flags & MDDB_C_STALE)
		return (mdmddberror(ep, MDE_DB_STALE, (minor_t)NODEV64,
		    sp->setno, 0, NULL));

	return (0);
}
