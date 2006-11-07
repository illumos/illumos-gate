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

#include <meta.h>
#include <mdmn_changelog.h>
#include "meta_set_prv.h"
#include "meta_repartition.h"

static int
check_setnodes_againstdrivelist(
	mdsetname_t		*sp,
	mddrivenamelist_t	*dnlp,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	mddrivenamelist_t	*p;
	int 			i;
	md_mnnode_desc		*nd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			for (p = dnlp; p != NULL; p = p->next)
				if (checkdrive_onnode(sp, p->drivenamep,
				    nd->nd_nodename, ep))
					return (-1);
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			for (p = dnlp; p != NULL; p = p->next)
				if (checkdrive_onnode(sp, p->drivenamep,
				    sd->sd_nodes[i], ep))
					return (-1);
		}
	}
	return (0);
}

static int
drvsuniq(mdsetname_t *sp, mddrivenamelist_t *dnlp, md_error_t *ep)
{
	mddrivenamelist_t *dl1, *dl2;
	mddrivename_t *dn1, *dn2;

	for (dl1 = dnlp; dl1 != NULL; dl1 = dl1->next) {
		dn1 = dl1->drivenamep;

		for (dl2 = dl1->next; dl2 != NULL; dl2 = dl2->next) {
			dn2 = dl2->drivenamep;
			if (strcmp(dn1->cname, dn2->cname) != 0)
				continue;

			return (mddserror(ep, MDE_DS_DUPDRIVE, sp->setno,
			    NULL, dn1->cname, sp->setname));
		}
	}
	return (0);
}

static md_drive_desc *
metaget_drivedesc_fromdrivelist(
	mdsetname_t		*sp,
	mddrivenamelist_t	*dnlp,
	uint_t			flags,
	md_error_t		*ep
)
{
	mddrivenamelist_t	*p;
	md_drive_desc		*dd = NULL;
	md_set_desc		*sd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (NULL);

	for (p = dnlp; p != NULL; p = p->next) {
		(void) metadrivedesc_append(&dd, p->drivenamep, 0, 0,
		    sd->sd_ctime, sd->sd_genid, flags);
	}

	return (dd);
}

/*
 * Exported Entry Points
 */

int
meta_make_sidenmlist(
	mdsetname_t		*sp,
	mddrivename_t		*dnp,
	int			import_flag, /* flags partial import */
	md_im_drive_info_t	*midp,	/* import drive information */
	md_error_t		*ep
)
{
	mdsidenames_t		*sn, **sn_next;
	mdname_t		*np;
	int			done;
	side_t			sideno = MD_SIDEWILD;
	uint_t			rep_slice;
	char			*bname;

	if (!import_flag) {
		/*
		 * Normal (aka NOT partial import) code path.
		 */
		if (meta_replicaslice(dnp, &rep_slice, ep) != 0) {
			return (-1);
		}

		dnp->side_names_key = MD_KEYWILD;

		if ((np = metaslicename(dnp, rep_slice, ep)) == NULL)
			return (-1);
		bname = Strdup(np->bname);
	} else {
		/*
		 * When doing a partial import, we'll get the needed
		 * information from somewhere other than the system.
		 */
		dnp->side_names_key = MD_KEYWILD;
		bname = Strdup(midp->mid_devname);
	}
	metaflushsidenames(dnp);
	sn_next = &dnp->side_names;
	/*CONSTCOND*/
	while (1) {
		sn = Zalloc(sizeof (*sn));

		if ((done = meta_getnextside_devinfo(sp, bname, &sideno,
		    &sn->cname, &sn->dname, &sn->mnum, ep)) == -1) {
			if (import_flag) {
				mdclrerror(ep);
				sn->dname = Strdup(midp->mid_driver_name);
				sn->mnum = midp->mid_mnum;
			} else {
				Free(sn);
				Free(bname);
				return (-1);
			}
		}

		if (done == 0) {
			Free(sn);
			Free(bname);
			return (0);
		}

		sn->sideno = sideno;

		/* Add to the end of the linked list */
		assert(*sn_next == NULL);
		*sn_next = sn;
		sn_next = &sn->next;
	}
	/*NOTREACHED*/
}

int
meta_set_adddrives(
	mdsetname_t		*sp,
	mddrivenamelist_t	*dnlp,
	daddr_t			dbsize,
	int			force_label,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	md_drive_desc		*dd = NULL, *curdd = NULL, *ddp;
	int			i;
	mddrivenamelist_t	*p;
	mhd_mhiargs_t		mhiargs;
	int			rval = 0;
	md_timeval32_t		now;
	sigset_t		oldsigs;
	ulong_t			genid;
	ulong_t			max_genid = 0;
	md_setkey_t		*cl_sk;
	int			rb_level = 0;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;
	int			suspendall_flag = 0;
	int			suspend1_flag = 0;
	int			lock_flag = 0;
	int			flush_set_onerr = 0;
	md_replicalist_t	*rlp = NULL, *rl;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	/*
	 * The drive and node records are stored in the local mddbs of each
	 * node in the diskset.  Each node's rpc.metad daemon reads in the set,
	 * drive and node records from that node's local mddb and caches them
	 * internally. Any process needing diskset information contacts its
	 * local rpc.metad to get this information.  Since each node in the
	 * diskset is independently reading the set information from its local
	 * mddb, the set, drive and node records in the local mddbs must stay
	 * in-sync, so that all nodes have a consistent view of the diskset.
	 *
	 * For a multinode diskset, explicitly verify that all nodes in the
	 * diskset are ALIVE (i.e. are in the API membership list).  Otherwise,
	 * fail this operation since all nodes must be ALIVE in order to add
	 * the new drive record to their local mddb.  If a panic of this node
	 * leaves the local mddbs set, node and drive records out-of-sync, the
	 * reconfig cycle will fix the local mddbs and force them back into
	 * synchronization.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST,
					sp->setno,
					nd->nd_nodename, NULL, sp->setname);
				return (-1);
			}
			nd = nd->nd_next;
		}
	}

	if (drvsuniq(sp, dnlp, ep) == -1)
		return (-1);

	/*
	 * Lock the set on current set members.
	 * Set locking done much earlier for MN diskset than for traditional
	 * diskset since lock_set and SUSPEND are used to protect against
	 * other meta* commands running on the other nodes.
	 */
	if (MD_MNSET_DESC(sd)) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);

		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
				rval = -1;
				goto out;
			}
			lock_flag = 1;
			nd = nd->nd_next;
		}
		/*
		 * Lock out other meta* commands by suspending
		 * class 1 messages across the diskset.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename,
			    COMMDCTL_SUSPEND, sp, MD_MSG_CLASS1,
			    MD_MSCF_NO_FLAGS, ep)) {
				rval = -1;
				goto out;
			}
			suspend1_flag = 1;
			nd = nd->nd_next;
		}
	}

	if (check_setnodes_againstdrivelist(sp, dnlp, ep)) {
		rval = -1;
		goto out;
	}

	for (p = dnlp; p != NULL; p = p->next) {
		mdsetname_t	*tmp;

		if (meta_is_drive_in_anyset(p->drivenamep, &tmp, FALSE,
		    ep) == -1) {
			rval = -1;
			goto out;
		}

		if (tmp != NULL) {
			(void) mddserror(ep, MDE_DS_DRIVEINSET, sp->setno,
			    tmp->setname, p->drivenamep->cname, sp->setname);
			rval = -1;
			goto out;
		}
	}

	/* END CHECK CODE */

	/*
	 * This is a separate loop (from above) so that we validate all the
	 * drives handed to us before we repartition any one drive.
	 */
	for (p = dnlp; p != NULL; p = p->next) {
		if (meta_repartition_drive(sp,
		    p->drivenamep, force_label == TRUE ? MD_REPART_FORCE : 0,
		    NULL, /* Don't return the VTOC. */
		    ep) != 0) {
			rval = -1;
			goto out;
		}
		/*
		 * Create the names for the drives we are adding per side.
		 */
		if (meta_make_sidenmlist(sp, p->drivenamep, 0, NULL,
		    ep) == -1) {
			rval = -1;
			goto out;
		}
	}

	/*
	 * Get the list of drives descriptors that we are adding.
	 */
	dd = metaget_drivedesc_fromdrivelist(sp, dnlp, MD_DR_ADD, ep);

	if (! mdisok(ep)) {
		rval = -1;
		goto out;
	}

	/*
	 * Get the set timeout information.
	 */
	(void) memset(&mhiargs, '\0', sizeof (mhiargs));
	if (clnt_gtimeout(mynode(), sp, &mhiargs, ep) == -1) {
		rval = -1;
		goto out;
	}

	/*
	 * Get timestamp and generation id for new records
	 */
	now = sd->sd_ctime;
	genid = sd->sd_genid;


	/* At this point, in case of error, set should be flushed. */
	flush_set_onerr = 1;

	/* Lock the set on current set members */
	if (!(MD_MNSET_DESC(sd))) {
		md_rb_sig_handling_on();
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
				rval = -1;
				goto out;
			}
			lock_flag = 1;
		}
	}

	/*
	 * Get drive descriptors for the drives that are currently in the set.
	 */
	curdd = metaget_drivedesc(sp, MD_FULLNAME_ONLY, ep);
	if (! mdisok(ep))
		goto rollback;

	/*
	 * If first drive being added to set, set the mastership
	 * of the multinode diskset to be this node.
	 * Only set it on this node.  If all goes well
	 * and there are no errors, the mastership of this node will be set
	 * on all nodes in user space and in the kernel.
	 */
	if ((MD_MNSET_DESC(sd)) && (curdd == NULL)) {
		if (clnt_mnsetmaster(mynode(), sp,
		    sd->sd_mn_mynode->nd_nodename,
		    sd->sd_mn_mynode->nd_nodeid, ep)) {
			goto rollback;
		}
		/*
		 * Set this up in my local cache of the set desc so that
		 * the set descriptor won't have to be gotten again from
		 * rpc.metad.  If it is flushed and gotten again, these
		 * values will be set in sr2setdesc.
		 */
		sd->sd_mn_master_nodeid = sd->sd_mn_mynode->nd_nodeid;
		(void) strcpy(sd->sd_mn_master_nodenm,
		    sd->sd_mn_mynode->nd_nodename);
		sd->sd_mn_am_i_master = 1;
	}

	RB_TEST(1, "adddrives", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "adddrives", ep)

	/*
	 * Add the drive records for the drives that we are adding to
	 * each host in the set.  Marks the drive as MD_DR_ADD.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_adddrvs(nd->nd_nodename, sp, dd, now, genid,
			    ep) == -1)
				goto rollback;

			RB_TEST(3, "adddrives", ep)
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_adddrvs(sd->sd_nodes[i], sp, dd, now, genid,
			    ep) == -1)
				goto rollback;

			RB_TEST(3, "adddrives", ep)
		}
	}

	RB_TEST(4, "adddrives", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(5, "adddrives", ep)

	/*
	 * Take ownership of the added drives.
	 */
	if (!(MD_MNSET_DESC(sd)) && !MD_ATSET_DESC(sd)) {
		if (tk_own_bydd(sp, dd, &mhiargs, TRUE, ep))
			goto rollback;
	}

	/*
	 * If this is not a MN set and the state flags do not indicate the
	 * presence of devids, update the set records on all nodes.
	 */
	if (!(sd->sd_flags & MD_SR_MB_DEVID) && !(MD_MNSET_DESC(sd))) {
		if (meta_update_mb(sp, dd, ep) == 0) {
			mdclrerror(ep);

			/* update the sr_flags on all hosts */
			for (i = 0; i < MD_MAXSIDES; i++) {
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_upd_sr_flags(sd->sd_nodes[i],
				    sp, (sd->sd_flags | MD_SR_MB_DEVID), ep))
					goto rollback;
			}
		}
	}

	RB_TEST(6, "adddrives", ep)

	RB_PREEMPT;
	rb_level = 3;	/* level 3 */

	RB_TEST(7, "adddrives", ep)

	/*
	 * Balance the DB's according to the list of existing drives and the
	 * list of added drives.
	 */
	if ((rval = meta_db_balance(sp, dd, curdd, dbsize, ep)) == -1)
		goto rollback;

	/*
	 * Slam a dummy master block on all the disks that we are adding
	 * that don't have replicas on them.
	 * Used by diskset import if the disksets are remotely replicated
	 */
	if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) >= 0) {
		for (ddp = dd; ddp != NULL; ddp = ddp->dd_next) {
			uint_t		rep_slice;
			int		fd = -1;
			mdname_t	*np = NULL;
			char		*drive_name;

			drive_name = ddp->dd_dnp->cname;

			for (rl = rlp; rl != NULL; rl = rl->rl_next) {
				char	*rep_name;

				rep_name =
				    rl->rl_repp->r_namep->drivenamep->cname;

				if (strcmp(drive_name, rep_name) == 0) {
					/*
					 * Disk has a replica on it so don't
					 * add dummy master block.
					 */
					break;
				}
			}
			if (rl == NULL) {
				/*
				 * Drive doesn't have a replica on it so
				 * we need a dummy master block. Add it.
				 */
				if (meta_replicaslice(ddp->dd_dnp, &rep_slice,
				    &xep) != 0) {
					mdclrerror(&xep);
					continue;
				}

				if ((np = metaslicename(ddp->dd_dnp, rep_slice,
				    &xep)) == NULL) {
					mdclrerror(&xep);
					continue;
				}

				if ((fd = open(np->rname, O_RDWR)) >= 0) {
					meta_mkdummymaster(sp, fd, 16);
					(void) close(fd);
				}
			}
		}
	}

	if ((curdd == NULL) && (MD_MNSET_DESC(sd))) {
		/*
		 * Notify rpc.mdcommd on all nodes of a nodelist change.
		 * Start by suspending rpc.mdcommd (which drains it of all
		 * messages), then change the nodelist followed by a reinit
		 * and resume.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_SUSPEND,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, ep)) {
				rval = -1;
				goto out;
			}
			suspendall_flag = 1;
			nd = nd->nd_next;
		}
	}

	/*
	 * If a MN diskset and this is the first disk(s) being added
	 * to set, then pre-allocate change log records here.
	 * When the other nodes are joined into the MN diskset, the
	 * USER records will just be snarfed in.
	 */
	if ((MD_MNSET_DESC(sd)) && (curdd == NULL)) {
		if (mdmn_allocate_changelog(sp, ep) != 0)
			goto rollback;
	}

	/*
	 * Mark the drives MD_DR_OK.
	 * If first drive being added to MN diskset, then set
	 * master on all nodes to be this node and then join
	 * all alive nodes (nodes in membership list) to set.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* don't set master on this node - done earlier */
			if ((curdd == NULL) && (nd->nd_nodeid !=
			    sd->sd_mn_mynode->nd_nodeid)) {
				/*
				 * Set master on all alive nodes since
				 * all alive nodes will become joined nodes.
				 */
				if (clnt_mnsetmaster(nd->nd_nodename, sp,
				    sd->sd_mn_mynode->nd_nodename,
				    sd->sd_mn_mynode->nd_nodeid, ep)) {
					goto rollback;
				}
			}

			if (curdd == NULL) {
				/*
				 * No special flags for join set.  Since
				 * all nodes are joining if 1st drive is being
				 * added to set then all nodes will be either
				 * STALE or non-STALE and each node can
				 * determine this on its own.
				 */
				if (clnt_joinset(nd->nd_nodename, sp,
				    NULL, ep)) {
					goto rollback;
				}
				/* Sets join node flag on all nodes in list */
				if (clnt_upd_nr_flags(nd->nd_nodename, sp,
				    sd->sd_nodelist, MD_NR_JOIN, NULL, ep)) {
					goto rollback;
				}
			}

			/*
			 * Set MD_DR_OK as last thing before unlock.
			 * In case of panic on this node, recovery
			 * code can check for MD_DR_OK to determine
			 * status of diskset.
			 */
			if (clnt_upd_dr_flags(nd->nd_nodename, sp, dd,
			    MD_DR_OK, ep) == -1)
				goto rollback;


			RB_TEST(8, "adddrives", ep)
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_upd_dr_flags(sd->sd_nodes[i], sp, dd, MD_DR_OK,
			    ep) == -1)
				goto rollback;

			RB_TEST(8, "adddrives", ep)
		}
	}

	RB_TEST(9, "adddrives", ep)

out:
	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send reinit command to mdcommd which forces it to get
	 * fresh set description.
	 */
	if (suspendall_flag) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* Class is ignored for REINIT */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_REINIT,
			    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to reinit rpc.mdcommd.\n"));
			}
			nd = nd->nd_next;
		}
	}
	/*
	 * Unlock diskset by resuming messages across the diskset.
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	if (lock_flag) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (clnt_unlock_set(nd->nd_nodename,
				    cl_sk, &xep)) {
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

				if (clnt_unlock_set(sd->sd_nodes[i],
				    cl_sk, &xep)) {
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
				}
			}
		}
		cl_set_setkey(NULL);
	}

	metafreedrivedesc(&dd);

	if (flush_set_onerr) {
		metaflushsetname(sp);
		if (!(MD_MNSET_DESC(sd))) {
			md_rb_sig_handling_off(md_got_sig(), md_which_sig());
		}
	}

	if (MD_MNSET_DESC(sd)) {
		/* release signals back to what they were on entry */
		if (procsigs(FALSE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	}

	return (rval);

rollback:
	/* all signals already blocked for MN disket */
	if (!(MD_MNSET_DESC(sd))) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	}

	rval = -1;

	max_genid = sd->sd_genid;

	/* level 3 */
	if (rb_level > 2) {
		/*
		 * Since the add drive operation is failing, need
		 * to reset config back to the way it was
		 * before the add drive opration.
		 * If a MN diskset and this is the first drive being added,
		 * then reset master on all ALIVE nodes (which is all nodes)
		 * since the master would have not been set previously.
		 * Don't reset master on this node, since this
		 * is done later.
		 * This is ok to fail since next node to add first
		 * disk to diskset will also set the master on all nodes.
		 *
		 * Also, if this is the first drive being added,
		 * need to have each node withdraw itself from the set.
		 */
		if ((MD_MNSET_DESC(sd)) && (curdd == NULL)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				/*
				 * Be careful with ordering in case of
				 * panic between the steps and the
				 * effect on recovery during reconfig.
				 */
				if (clnt_withdrawset(nd->nd_nodename, sp, &xep))
					mdclrerror(&xep);

				/* Sets withdraw flag on all nodes in list */
				if (clnt_upd_nr_flags(nd->nd_nodename, sp,
				    sd->sd_nodelist, MD_NR_WITHDRAW,
				    NULL, &xep)) {
					mdclrerror(&xep);
				}

				/* Skip this node */
				if (nd->nd_nodeid ==
				    sd->sd_mn_mynode->nd_nodeid) {
					nd = nd->nd_next;
					continue;
				}
				/* Reset master on all of the other nodes. */
				if (clnt_mnsetmaster(nd->nd_nodename, sp,
				    "", MD_MN_INVALID_NID, &xep))
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		}
	}

	/*
	 * Send resume command to mdcommd.  Don't send reinit command
	 * since nodelist should not have changed.
	 * If suspendall_flag is set, then user would have been adding
	 * first drives to set.  Since this failed, there is certainly
	 * no reinit message to send to rpc.commd since no nodes will
	 * be joined to set at the end of this metaset command.
	 */
	if (suspendall_flag) {
		/* Send resume */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/*
			 * Resume all classes but class 1 so that lock is held
			 * against meta* commands.
			 * To later resume class1, must issue a class0 resume.
			 */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0,
			    MD_MSCF_DONT_RESUME_CLASS1, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	/* level 3 */
	if (rb_level > 2) {
		mdnamelist_t	*nlp;
		mdname_t	*np;

		for (ddp = dd; ddp != NULL; ddp = ddp->dd_next) {
			uint_t	rep_slice;

			if ((meta_replicaslice(ddp->dd_dnp,
			    &rep_slice, &xep) != 0) ||
			    ((np = metaslicename(ddp->dd_dnp, rep_slice,
				&xep)) == NULL)) {
				mdclrerror(&xep);
				continue;
			}
			nlp = NULL;
			(void) metanamelist_append(&nlp, np);

			if (meta_db_detach(sp, nlp,
			    (MDFORCE_DS | MDFORCE_SET_LOCKED), NULL, &xep))
				mdclrerror(&xep);

			metafreenamelist(nlp);
		}

		/* Re-balance */
		if (meta_db_balance(sp, NULL, curdd, 0, &xep) == -1)
			mdclrerror(&xep);

		/* Only if we are adding the first drive */
		/* Handled MN diskset above. */
		if ((curdd == NULL) && !(MD_MNSET_DESC(sd))) {
			if (clnt_stimeout(mynode(), sp, &defmhiargs,
			    &xep) == -1)
				mdclrerror(&xep);

			/* This is needed because of a corner case */
			if (halt_set(sp, &xep))
				mdclrerror(&xep);
		}
		max_genid++;
	}

	/* level 2 */
	if (rb_level > 1) {
		if (!(MD_MNSET_DESC(sd)) && !MD_ATSET_DESC(sd)) {
			if (rel_own_bydd(sp, dd, TRUE, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 1 */
	if (rb_level > 0) {
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (clnt_deldrvs(nd->nd_nodename, sp, dd,
				    &xep) == -1)
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_deldrvs(sd->sd_nodes[i], sp, dd,
				    &xep) == -1)
					mdclrerror(&xep);
			}
		}
		max_genid += 2;
		resync_genid(sp, sd, max_genid, 0, NULL);
	}

	if ((suspend1_flag) || (suspendall_flag)) {
		/* Send resume */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/*
			 * Just resume all classes so that resume is the
			 * same whether just one class was locked or all
			 * classes were locked.
			 */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	/* Don't test lock flag since guaranteed to be set if in rollback */
	if (MD_MNSET_DESC(sd)) {
		/*
		 * Since the add drive operation is failing, need
		 * to reset config back to the way it was
		 * before the add drive opration.
		 * If a MN diskset and this is the first drive being
		 * added, then reset master on this node since
		 * the master would have not been set previously.
		 * This is ok to fail since next node to add first
		 * disk to diskset will also set the master on all nodes.
		 */
		if (curdd == NULL) {
			/* Reset master on mynode */
			if (clnt_mnsetmaster(mynode(), sp, "",
			    MD_MN_INVALID_NID, &xep))
				mdclrerror(&xep);
		}
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep))
				mdclrerror(&xep);
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep))
				mdclrerror(&xep);
		}
	}
	cl_set_setkey(NULL);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	metafreedrivedesc(&dd);

	if (flush_set_onerr) {
		metaflushsetname(sp);
		if (!(MD_MNSET_DESC(sd))) {
			md_rb_sig_handling_off(md_got_sig(), md_which_sig());
		}
	}

	return (rval);
}

/*
 * Add drives routine used during import of a diskset.
 */
int
meta_imp_set_adddrives(
	mdsetname_t		*sp,
	mddrivenamelist_t	*dnlp,
	md_im_set_desc_t	*misp,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	mddrivenamelist_t	*p;
	md_drive_desc		*dd = NULL, *ddp;
	int			flush_set_onerr = 0;
	md_timeval32_t		now;
	ulong_t			genid;
	mhd_mhiargs_t		mhiargs;
	md_im_replica_info_t	*mirp;
	md_im_drive_info_t	*midp;
	int			rval = 0;
	sigset_t		oldsigs;
	ulong_t			max_genid = 0;
	int			rb_level = 0;
	md_error_t		xep = mdnullerror;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	for (p = dnlp; p != NULL; p = p->next) {
		int		imp_flag = 0;

		/*
		 * If we have a partial diskset, meta_make_sidenmlist will
		 * need information from midp to complete making the
		 * side name structure.
		 */
		if (misp->mis_partial) {
			imp_flag = MDDB_C_IMPORT;
			for (midp = misp->mis_drives; midp != NULL;
			    midp = midp->mid_next) {
				if (midp->mid_dnp == p->drivenamep)
					break;
			}
			if (midp == NULL) {
				(void) mddserror(ep, MDE_DS_SETNOTIMP,
				    MD_SET_BAD, mynode(), NULL, sp->setname);
				rval = -1;
				goto out;
			}
		}
		/*
		 * Create the names for the drives we are adding per side.
		 */
		if (meta_make_sidenmlist(sp, p->drivenamep, imp_flag,
		    midp, ep) == -1) {
			rval = -1;
			goto out;
		}
	}

	/*
	 * Get the list of drives descriptors that we are adding.
	 */
	dd = metaget_drivedesc_fromdrivelist(sp, dnlp, MD_DR_ADD, ep);

	if (! mdisok(ep)) {
		rval = -1;
		goto out;
	}

	/*
	 * Get the set timeout information.
	 */
	(void) memset(&mhiargs, '\0', sizeof (mhiargs));
	if (clnt_gtimeout(mynode(), sp, &mhiargs, ep) == -1) {
		rval = -1;
		goto out;
	}

	/*
	 * Get timestamp and generation id for new records
	 */
	now = sd->sd_ctime;
	genid = sd->sd_genid;

	/* At this point, in case of error, set should be flushed. */
	flush_set_onerr = 1;

	rb_level = 1;   /* level 1 */

	for (midp = misp->mis_drives; midp != NULL; midp = midp->mid_next) {
		for (ddp = dd; ddp != NULL; ddp = ddp->dd_next) {
			if (ddp->dd_dnp == midp->mid_dnp) {
				/* same disk */
				ddp->dd_dnp->devid =
				    devid_str_encode(midp->mid_devid,
				    midp->mid_minor_name);

				ddp->dd_dbcnt = 0;
				mirp = midp->mid_replicas;
				if (mirp) {
					ddp->dd_dbsize = mirp->mir_length;
					for (; mirp != NULL;
					    mirp = mirp->mir_next) {
						ddp->dd_dbcnt++;
					}
				}
				if ((midp->mid_available &
				    MD_IM_DISK_NOT_AVAILABLE) &&
				    (misp->mis_flags & MD_IM_SET_REPLICATED)) {
					ddp->dd_flags = MD_DR_UNRSLV_REPLICATED;
				}
			}
		}
	}

	/*
	 * Add the drive records for the drives that we are adding to
	 * each host in the set.  Marks the drive records as MD_DR_ADD.
	 * May also mark a drive record as MD_DR_UNRSLV_REPLICATED if
	 * this flag was set in the dd_flags for that drive.
	 */
	if (clnt_imp_adddrvs(mynode(), sp, dd, now, genid, ep) == -1)
		goto rollback;

	rb_level = 2;   /* level 2 */

	/*
	 * Take ownership of the added drives.
	 */
	if (tk_own_bydd(sp, dd, &mhiargs, TRUE, ep))
		goto rollback;

out:
	metafreedrivedesc(&dd);

	if (flush_set_onerr) {
		metaflushsetname(sp);
	}

	return (rval);

rollback:
	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	rval = -1;

	max_genid = sd->sd_genid;

	/* level 2 */
	if (rb_level > 1) {
		if (!MD_ATSET_DESC(sd)) {
			if (rel_own_bydd(sp, dd, TRUE, &xep)) {
				mdclrerror(&xep);
			}
		}
	}

	/* level 1 */
	if (rb_level > 0) {
		if (clnt_deldrvs(mynode(), sp, dd, &xep) == -1) {
			mdclrerror(&xep);
		}
		max_genid += 2;
		resync_genid(sp, sd, max_genid, 0, NULL);
	}

	/* level 0 */

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	metafreedrivedesc(&dd);

	if (flush_set_onerr) {
		metaflushsetname(sp);
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}

	return (rval);
}

int
meta_set_deletedrives(
	mdsetname_t		*sp,
	mddrivenamelist_t	*dnlp,
	int			forceflg,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	md_drive_desc		*ddp, *dd = NULL, *curdd = NULL;
	md_replicalist_t	*rlp = NULL, *rl;
	mddrivenamelist_t	*p;
	int			deldrvcnt = 0;
	int			rval = 0;
	mhd_mhiargs_t		mhiargs;
	int			i;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	ulong_t			max_genid = 0;
	int			rb_level = 0;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;
	int			has_set;
	int			current_drv_cnt = 0;
	int			suspendall_flag = 0, suspendall_flag_rb = 0;
	int			suspend1_flag = 0;
	int			lock_flag = 0;
	bool_t			stale_bool = FALSE;
	int			flush_set_onerr = 0;
	mdnamelist_t		*nlp;
	mdname_t		*np;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	if (drvsuniq(sp, dnlp, ep) == -1)
		return (-1);

	/*
	 * Check and see if all the nodes have the set.
	 *
	 * The drive and node records are stored in the local mddbs of each
	 * node in the diskset.  Each node's rpc.metad daemon reads in the set,
	 * drive and node records from that node's local mddb and caches them
	 * internally. Any process needing diskset information contacts its
	 * local rpc.metad to get this information.  Since each node in the
	 * diskset is independently reading the set information from its local
	 * mddb, the set, drive and node records in the local mddbs must stay
	 * in-sync, so that all nodes have a consistent view of the diskset.
	 *
	 * For a multinode diskset, explicitly verify that all nodes in the
	 * diskset are ALIVE (i.e. are in the API membership list).  Otherwise,
	 * fail this operation since all nodes must be ALIVE in order to delete
	 * a drive record from their local mddb.  If a panic of this node
	 * leaves the local mddbs set, node and drive records out-of-sync, the
	 * reconfig cycle will fix the local mddbs and force them back into
	 * synchronization.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST,
					sp->setno,
					nd->nd_nodename, NULL, sp->setname);
				return (-1);
			}
			nd = nd->nd_next;
		}

		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);

		/*
		 * Lock the set on current set members.
		 * Set locking done much earlier for MN diskset than for
		 * traditional diskset since lock_set and SUSPEND are used
		 * to protect against other meta* commands running on the
		 * other nodes.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
				rval = -1;
				goto out;
			}
			lock_flag = 1;
			nd = nd->nd_next;
		}
		/*
		 * Lock out other meta* commands by suspending
		 * class 1 messages across the diskset.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename,
			    COMMDCTL_SUSPEND, sp, MD_MSG_CLASS1,
			    MD_MSCF_NO_FLAGS, ep)) {
				rval = -1;
				goto out;
			}
			suspend1_flag = 1;
			nd = nd->nd_next;
		}

		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (strcmp(nd->nd_nodename, mynode()) == 0) {
				nd = nd->nd_next;
				continue;
			}

			has_set = nodehasset(sp, nd->nd_nodename,
				    NHS_NSTG_EQ, ep);
			if (has_set < 0) {
				rval = -1;
				goto out;
			}

			if (! has_set) {
				(void) mddserror(ep, MDE_DS_NODENOSET,
					sp->setno, nd->nd_nodename,
					NULL, sp->setname);
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

			if (strcmp(sd->sd_nodes[i], mynode()) == 0)
				continue;

			has_set = nodehasset(sp, sd->sd_nodes[i], NHS_NSTG_EQ,
				ep);
			if (has_set < 0) {
				/*
				 * Can directly return since !MN diskset;
				 * nothing to unlock.
				 */
				return (-1);
			}

			if (! has_set) {
				/*
				 * Can directly return since !MN diskset;
				 * nothing to unlock.
				 */
				return (mddserror(ep, MDE_DS_NODENOSET,
				    sp->setno, sd->sd_nodes[i], NULL,
				    sp->setname));
			}
		}
	}

	for (p = dnlp; p != NULL; p = p->next) {
		int		is_it;
		mddrivename_t	*dnp;

		dnp = p->drivenamep;

		if ((is_it = meta_is_drive_in_thisset(sp, dnp, FALSE, ep))
		    == -1) {
			rval = -1;
			goto out;
		}

		if (! is_it) {
			(void) mddserror(ep, MDE_DS_DRIVENOTINSET, sp->setno,
			    NULL, dnp->cname, sp->setname);
			rval = -1;
			goto out;
		}

		if ((meta_check_drive_inuse(sp, dnp, FALSE, ep)) == -1) {
			rval = -1;
			goto out;
		}

		deldrvcnt++;
	}
	current_drv_cnt = deldrvcnt;

	/*
	 * Get drive descriptors for the drives that are currently in the set.
	 */
	curdd = metaget_drivedesc(sp, MD_BASICNAME_OK, ep);
	if (! mdisok(ep)) {
		rval = -1;
		goto out;
	}

	/*
	 * Decrement the the delete drive count for each drive currently in the
	 * set.
	 */
	for (ddp = curdd; ddp != NULL; ddp = ddp->dd_next)
		deldrvcnt--;

	/*
	 * If the count of drives we are deleting is equal to the drives in the
	 * set, and we haven't specified forceflg, return an error
	 */
	if (deldrvcnt == 0 && forceflg == FALSE) {
		(void) mderror(ep, MDE_FORCE_DEL_ALL_DRV, NULL);
		rval = -1;
		goto out;
	}

	/*
	 * Get the list of drive descriptors that we are deleting.
	 */
	dd = metaget_drivedesc_fromdrivelist(sp, dnlp, MD_DR_DEL, ep);
	if (! mdisok(ep)) {
		rval = -1;
		goto out;
	}

	/*
	 * Get the set timeout information in case we have to roll back.
	 */
	(void) memset(&mhiargs, '\0', sizeof (mhiargs));
	if (clnt_gtimeout(mynode(), sp, &mhiargs, ep) == -1) {
		rval = -1;
		goto out;
	}

	/* At this point, in case of error, set should be flushed. */
	flush_set_onerr = 1;

	/* END CHECK CODE */

	/* Lock the set on current set members */
	if (!(MD_MNSET_DESC(sd))) {
		md_rb_sig_handling_on();
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
				rval = -1;
				goto out;
			}
			lock_flag = 1;
		}
	}

	if ((deldrvcnt == 0) && (MD_MNSET_DESC(sd))) {
		mddb_config_t		c;
		/*
		 * Is current set STALE?
		 */
		(void) memset(&c, 0, sizeof (c));
		c.c_id = 0;
		c.c_setno = sp->setno;
		if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
			(void) mdstealerror(ep, &c.c_mde);
			rval = -1;
			goto out;
		}
		if (c.c_flags & MDDB_C_STALE) {
			stale_bool = TRUE;
		}
	}

	RB_TEST(1, "deletedrives", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "deletedrives", ep)

	/*
	 * Mark the drives MD_DR_DEL
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_upd_dr_flags(nd->nd_nodename, sp, dd,
			    MD_DR_DEL, ep) == -1)
				goto rollback;

			RB_TEST(3, "deletedrives", ep)
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_upd_dr_flags(sd->sd_nodes[i], sp, dd,
			    MD_DR_DEL, ep) == -1)
				goto rollback;

			RB_TEST(3, "deletedrives", ep)
		}
	}

	RB_TEST(4, "deletedrives", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(5, "deletedrives", ep)

	/*
	 * Balance the DB's according to the list of existing drives and the
	 * list of deleted drives.
	 */
	if (meta_db_balance(sp, dd, curdd, 0, ep) == -1)
		goto rollback;

	/*
	 * If the drive(s) to be deleted cannot be accessed,
	 * they haven't really been deleted yet. Check and delete now
	 * if need be.
	 */
	if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) >= 0) {
		nlp = NULL;
		for (ddp = dd; ddp != NULL; ddp = ddp->dd_next) {
			char	*delete_name;

			delete_name = ddp->dd_dnp->cname;

			for (rl = rlp; rl != NULL; rl = rl->rl_next) {
				char	*cur_name;

				cur_name =
				    rl->rl_repp->r_namep->drivenamep->cname;

				if (strcmp(delete_name, cur_name) == 0) {
					/* put it on the delete list */
					np = rl->rl_repp->r_namep;
					(void) metanamelist_append(&nlp, np);

				}
			}
		}

		if (nlp != NULL) {
			if (meta_db_detach(sp, nlp,
			    (MDFORCE_DS | MDFORCE_SET_LOCKED), NULL,
			    ep) == -1) {
				metafreenamelist(nlp);
				goto rollback;
			}
			metafreenamelist(nlp);
		}
	}

	RB_TEST(6, "deletedrives", ep)

	RB_PREEMPT;
	rb_level = 3;	/* level 3 */

	RB_TEST(7, "deletedrives", ep)

	/*
	 * Cannot suspend set until after meta_db_balance since
	 * meta_db_balance uses META_DB_ATTACH/DETACH messages.
	 */
	if ((deldrvcnt == 0) && (MD_MNSET_DESC(sd))) {
		/*
		 * Notify rpc.mdcommd on all nodes of a nodelist change.
		 * Start by suspending rpc.mdcommd (which drains it of all
		 * messages), then change the nodelist followed by a reinit
		 * and resume.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_SUSPEND,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, ep)) {
				rval = -1;
				goto out;
			}
			suspendall_flag = 1;
			nd = nd->nd_next;
		}
	}

	/*
	 * Remove the drive records for the drives that were deleted from
	 * each host in the set.  This removes the record and dr_flags.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_deldrvs(nd->nd_nodename, sp, dd, ep) == -1)
				goto rollback;

			RB_TEST(8, "deletedrives", ep)
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_deldrvs(sd->sd_nodes[i], sp, dd, ep) == -1)
				goto rollback;

			RB_TEST(8, "deletedrives", ep)
		}
	}

	RB_TEST(9, "deletedrives", ep)

	RB_PREEMPT;
	rb_level = 4;	/* level 4 */

	RB_TEST(10, "deletedrives", ep)

	if (!(MD_MNSET_DESC(sd)) && !MD_ATSET_DESC(sd)) {
		if (rel_own_bydd(sp, dd, TRUE, ep))
			goto rollback;
	}

	/* If we deleted all the drives, then we need to halt the set. */
	if (deldrvcnt == 0) {
		RB_TEST(11, "deletedrives", ep)

		RB_PREEMPT;
		rb_level = 5;	/* level 5 */

		RB_TEST(12, "deletedrives", ep)

		if (clnt_stimeout(mynode(), sp, &defmhiargs, ep) == -1)
			goto rollback;

		RB_TEST(13, "deletedrives", ep)

		RB_PREEMPT;
		rb_level = 6;	/* level 6 */

		RB_TEST(14, "deletedrives", ep)

		/* Halt MN diskset on all nodes by having node withdraw */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				/* Only withdraw nodes that are joined */
				if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
					nd = nd->nd_next;
					continue;
				}
				/*
				 * Going to set locally cached node flags to
				 * rollback join so in case of error, the
				 * rollback code knows which nodes to re-join.
				 */
				nd->nd_flags |= MD_MN_NODE_RB_JOIN;

				/*
				 * Be careful in ordering of following steps
				 * so that recovery from a panic between
				 * the steps is viable.
				 * Only reset master info in rpc.metad -
				 * don't reset local cached information
				 * which will be used to set master information
				 * back in case of failure (rollback).
				 */
				if (clnt_withdrawset(nd->nd_nodename, sp, ep))
					goto rollback;
				/* Sets withdraw flag on all nodes in list */
				if (clnt_upd_nr_flags(nd->nd_nodename, sp,
				    sd->sd_nodelist, MD_NR_WITHDRAW,
				    NULL, ep)) {
					goto rollback;
				}
				if (clnt_mnsetmaster(nd->nd_nodename, sp,
				    "", MD_MN_INVALID_NID, ep)) {
					goto rollback;
				}
				nd = nd->nd_next;
			}
		} else {
			if (halt_set(sp, ep))
				goto rollback;
		}

		RB_TEST(15, "deletedrives", ep)
	}

	RB_TEST(16, "deletedrives", ep)

out:
	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send reinit command to mdcommd which forces it to get
	 * fresh set description.
	 */
	if (suspendall_flag) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* Class is ignored for REINIT */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_REINIT,
			    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to reinit rpc.mdcommd.\n"));
			}
			nd = nd->nd_next;
		}
	}

	/*
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag)) {
		/* Send resume */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}
	if (lock_flag) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (clnt_unlock_set(nd->nd_nodename,
				    cl_sk, &xep)) {
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

				if (clnt_unlock_set(sd->sd_nodes[i],
				    cl_sk, &xep)) {
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
				}
			}
		}
		cl_set_setkey(NULL);
	}

	metafreedrivedesc(&dd);

	if (flush_set_onerr) {
		metaflushsetname(sp);
		if (!(MD_MNSET_DESC(sd))) {
			md_rb_sig_handling_off(md_got_sig(), md_which_sig());
		}
	}

	if (MD_MNSET_DESC(sd)) {
		/* release signals back to what they were on entry */
		if (procsigs(FALSE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	}

	return (rval);

rollback:
	/* all signals already blocked for MN disket */
	if (!(MD_MNSET_DESC(sd))) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	}

	rval = -1;

	max_genid = sd->sd_genid;

	/* Set the master on all nodes first thing */
	if (rb_level > 5) {
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (!(nd->nd_flags & MD_MN_NODE_RB_JOIN)) {
					continue;
				}
				/*
				 * Set master on all re-joining nodes to be
				 * my cached view of master.
				 */
				if (clnt_mnsetmaster(nd->nd_nodename, sp,
				    sd->sd_mn_master_nodenm,
				    sd->sd_mn_master_nodeid, &xep)) {
					mdclrerror(&xep);
				}
			}
		}
	}

	/* level 3 */
	if (rb_level > 2) {
		md_set_record		*sr;
		md_mnset_record		*mnsr;
		md_drive_record		*dr;
		int			sr_drive_cnt;

		/*
		 * See if we have to re-add the drives specified.
		 */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				/*
				 * Must get current set record from each
				 * node to see what else must be done
				 * to recover.
				 * Record should be for a multi-node diskset.
				 */
				if (clnt_mngetset(nd->nd_nodename, sp->setname,
				    MD_SET_BAD, &mnsr, &xep) == -1) {
					mdclrerror(&xep);
					nd = nd->nd_next;
					continue;
				}

				/*
				 * If all drives are already there, skip
				 * to next node.
				 */
				sr_drive_cnt = 0;
				dr = mnsr->sr_drivechain;
				while (dr) {
					sr_drive_cnt++;
					dr = dr->dr_next;
				}
				if (sr_drive_cnt == current_drv_cnt) {
					free_sr((md_set_record *)mnsr);
					nd = nd->nd_next;
					continue;
				}

				/* Readd all drives */
				if (clnt_adddrvs(nd->nd_nodename, sp, dd,
				    mnsr->sr_ctime, mnsr->sr_genid, &xep) == -1)
					mdclrerror(&xep);

				free_sr((struct md_set_record *)mnsr);
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/* Record should be for a non-multi-node set */
				if (clnt_getset(sd->sd_nodes[i], sp->setname,
				    MD_SET_BAD, &sr, &xep) == -1) {
					mdclrerror(&xep);
					continue;
				}

				/*
				 * Set record structure was allocated from RPC
				 * routine getset so this structure is only of
				 * size md_set_record even if the MN flag is
				 * set.  So, clear the flag so that the free
				 * code doesn't attempt to free a structure
				 * the size of md_mnset_record.
				 */
				if (MD_MNSET_REC(sr)) {
					sr->sr_flags &= ~MD_SR_MN;
					free_sr(sr);
					continue;
				}

				/* Drive already added, skip to next node */
				if (sr->sr_drivechain != NULL) {
					free_sr(sr);
					continue;
				}

				if (clnt_adddrvs(sd->sd_nodes[i], sp, dd,
				    sr->sr_ctime, sr->sr_genid, &xep) == -1)
					mdclrerror(&xep);

				free_sr(sr);
			}
		}
		max_genid += 2;
	}

	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * At this point in time, don't know which nodes are joined
	 * to the set.  So, send a reinit command to mdcommd
	 * which forces it to get fresh set description.  Then send resume.
	 *
	 * Later, this code will use rpc.mdcommd messages to reattach disks
	 * and then rpc.mdcommd may be suspended again, rest of the nodes
	 * joined, rpc.mdcommd reinited and then resumed.
	 */
	if (suspendall_flag) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* Class is ignored for REINIT */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_REINIT,
			    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to reinit rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}

		/* Send resume */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/*
			 * Resume all classes but class 1 so that lock is held
			 * against meta* commands.
			 * To later resume class1, must issue a class0 resume.
			 */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0,
			    MD_MSCF_DONT_RESUME_CLASS1, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	/* level 2 */
	if (rb_level > 1) {
		mdnamelist_t	*nlp;
		mdname_t	*np;

		for (ddp = dd; ddp != NULL; ddp = ddp->dd_next) {
			uint_t	rep_slice;

			if ((meta_replicaslice(ddp->dd_dnp,
			    &rep_slice, &xep) != 0) ||
			    ((np = metaslicename(ddp->dd_dnp, rep_slice,
				&xep)) == NULL)) {
				mdclrerror(&xep);
				continue;
			}
			nlp = NULL;
			(void) metanamelist_append(&nlp, np);

			if (meta_db_attach(sp, nlp,
			    (MDCHK_DRVINSET | MDCHK_SET_LOCKED),
			    &sd->sd_ctime, ddp->dd_dbcnt, ddp->dd_dbsize,
			    NULL, &xep) == -1)
				mdclrerror(&xep);

			metafreenamelist(nlp);
		}
		/* Re-balance */
		if (meta_db_balance(sp, NULL, curdd, 0, &xep) == -1)
			mdclrerror(&xep);
	}

	/* level 4 */
	if (rb_level > 3) {
		if (!(MD_MNSET_DESC(sd)) && !MD_ATSET_DESC(sd)) {
			if (tk_own_bydd(sp, dd, &mhiargs, TRUE, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 5 */
	if (rb_level > 4) {
		if (clnt_stimeout(mynode(), sp, &mhiargs, &xep) == -1)
			mdclrerror(&xep);
	}

	/*
	 * If at least one node needs to be rejoined to MN diskset,
	 * then suspend commd again.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_RB_JOIN)) {
				nd = nd->nd_next;
				continue;
			}
			break;
		}
		if (nd) {
			/*
			 * Found node that will be rejoined so
			 * notify rpc.mdcommd on all nodes of a nodelist change.
			 * Start by suspending rpc.mdcommd (which drains it of
			 * all messages), then change the nodelist followed by
			 * a reinit and resume.
			 */
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (clnt_mdcommdctl(nd->nd_nodename,
				    COMMDCTL_SUSPEND, sp, MD_MSG_CLASS0,
				    MD_MSCF_NO_FLAGS, &xep)) {
					mdclrerror(&xep);
				}
				suspendall_flag_rb = 1;
				nd = nd->nd_next;
			}
		}
	}



	/* level 6 */
	if (rb_level > 5) {
		if (MD_MNSET_DESC(sd)) {
			int	join_flags = 0;

			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				/* Only rejoin nodes that were joined before */
				if (!(nd->nd_flags & MD_MN_NODE_RB_JOIN)) {
					nd = nd->nd_next;
					continue;
				}
				/*
				 * Rejoin nodes to same state as before -
				 * either STALE or non-STALE.
				 */
				if (stale_bool == TRUE)
					join_flags = MNSET_IS_STALE;
				if (clnt_joinset(nd->nd_nodename, sp,
				    join_flags, &xep))
					mdclrerror(&xep);
				/* Sets OWN flag on all nodes in list */
				if (clnt_upd_nr_flags(nd->nd_nodename, sp,
				    sd->sd_nodelist, MD_NR_JOIN, NULL, &xep)) {
					mdclrerror(&xep);
				}
				nd = nd->nd_next;
			}
		} else {
			if (setup_db_bydd(sp, dd, TRUE, &xep) == -1)
				mdclrerror(&xep);

			/* No special flag for traditional diskset */
			if (snarf_set(sp, NULL, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 1 */
	if (rb_level > 0) {
		/*
		 * Mark the drives as OK.
		 */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				/*
				 * Must be last action before unlock.
				 * In case of panic, recovery code checks
				 * for MD_DR_OK to know that drive
				 * and possible master are fully added back.
				 */
				if (clnt_upd_dr_flags(nd->nd_nodename, sp, dd,
				    MD_DR_OK, &xep) == -1)
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_upd_dr_flags(sd->sd_nodes[i], sp, dd,
				    MD_DR_OK, &xep) == -1)
					mdclrerror(&xep);

			}
		}
		max_genid += 2;
		resync_genid(sp, sd, max_genid, 0, NULL);
	}
	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send a reinit command to mdcommd which forces it to get
	 * fresh set description.
	 */
	if (suspendall_flag_rb) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* Class is ignored for REINIT */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_REINIT,
			    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to reinit rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}
	}

	/*
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag_rb) || (suspendall_flag)) {
		/* Send resume */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}


	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	/* Don't test lock flag since guaranteed to be set if in rollback */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep))
				mdclrerror(&xep);
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep))
				mdclrerror(&xep);
		}
	}
	cl_set_setkey(NULL);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	metafreedrivedesc(&dd);

	if (flush_set_onerr) {
		metaflushsetname(sp);
		if (!(MD_MNSET_DESC(sd))) {
			md_rb_sig_handling_off(md_got_sig(), md_which_sig());
		}
	}

	return (rval);
}
