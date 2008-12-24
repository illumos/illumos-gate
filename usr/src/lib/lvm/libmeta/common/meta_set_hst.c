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

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * Metadevice diskset interfaces
 */

#include "meta_set_prv.h"
#include <meta.h>
#include <sys/lvm/md_crc.h>
#include <sys/time.h>
#include <sdssc.h>

static int
add_db_sidenms(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	int			rval = 0;

	if (metareplicalist(sp, MD_FULLNAME_ONLY, &rlp, ep) < 0)
		return (-1);

	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		md_replica_t	*r = rl->rl_repp;

		/*
		 * This is not the first replica being added to the
		 * diskset so call with ADDSIDENMS_BCAST.  If this
		 * is a traditional diskset, the bcast flag is ignored
		 * since traditional disksets don't use the rpc.mdcommd.
		 */
		if (meta_db_addsidenms(sp, r->r_namep, r->r_blkno,
		    DB_ADDSIDENMS_BCAST, ep)) {
			rval = -1;
			goto out;
		}
	}

out:
	metafreereplicalist(rlp);
	return (rval);
}

static int
add_drvs_to_hosts(
	mdsetname_t	*sp,
	int		node_c,
	char		**node_v,
	md_error_t	*ep
)
{
	int		i;
	md_set_desc	*sd;
	md_drive_desc	*dd;
	md_timeval32_t	now;
	ulong_t		genid;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if ((dd = metaget_drivedesc(sp, MD_FULLNAME_ONLY, ep)) == NULL) {
		if (! mdisok(ep))
			return (-1);
		return (0);
	}

	now = sd->sd_ctime;
	genid = sd->sd_genid - 1;

	for (i = 0; i < node_c; i++) {
		if (clnt_adddrvs(node_v[i], sp, dd, now, genid, ep) == -1)
			return (-1);
	}

	return (0);
}

static int
add_md_sidenms(mdsetname_t *sp, side_t sideno, side_t otherside, md_error_t *ep)
{
	mdnm_params_t	nm;
	char		*cname, *dname;
	side_t		tmp_sideno;
	minor_t		mnum;
	int		done, i;
	int		rval = 0;
	md_set_desc	*sd;

	(void) memset(&nm, '\0', sizeof (nm));
	nm.key   = MD_KEYWILD;

	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
	}
	/* Use rpc.mdcommd to add md side info from all nodes */
	if ((! metaislocalset(sp)) && MD_MNSET_DESC(sd) &&
	    (sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)) {
		md_mn_result_t			*resultp = NULL;
		md_mn_msg_meta_md_addside_t	md_as;
		int				send_rval;

		md_as.msg_sideno = sideno;
		md_as.msg_otherside = otherside;
		/*
		 * If reconfig cycle has been started, this node is stuck in
		 * in the return step until this command has completed.  If
		 * mdcommd is suspended, ask send_message to fail (instead of
		 * retrying) so that metaset can finish allowing the
		 * reconfig cycle to proceed.
		 */
		send_rval = mdmn_send_message(sp->setno,
		    MD_MN_MSG_META_MD_ADDSIDE,
		    MD_MSGF_FAIL_ON_SUSPEND | MD_MSGF_PANIC_WHEN_INCONSISTENT,
		    0, (char *)&md_as, sizeof (md_mn_msg_meta_md_addside_t),
		    &resultp, ep);
		if (send_rval != 0) {
			(void) mdstealerror(ep, &(resultp->mmr_ep));
			if (resultp)
				free_result(resultp);
			return (-1);
		}
		if (resultp)
			free_result(resultp);
		return (0);
	} else {
		/*CONSTCOND*/
		while (1) {
			char	*drvnm = NULL;

			nm.mde   = mdnullerror;
			nm.setno = sp->setno;
			nm.side  = otherside;
			if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde, NULL) != 0)
				return (mdstealerror(ep, &nm.mde));

			if (nm.key == MD_KEYWILD)
				return (0);

			/*
			 * Okay we have a valid key
			 * Let's see if it is hsp or not
			 */
			nm.devname = (uintptr_t)meta_getnmentbykey(sp->setno,
			    otherside, nm.key, &drvnm, NULL, NULL, ep);
			if (nm.devname == NULL || drvnm == NULL) {
				if (nm.devname)
					Free((void *)(uintptr_t)nm.devname);
				if (drvnm)
					Free((void *)(uintptr_t)drvnm);
				return (-1);
			}

			/*
			 * If it is hsp add here
			 */
			if (strcmp(drvnm, MD_HOTSPARES) == 0) {
				if (add_name(sp, sideno, nm.key, MD_HOTSPARES,
				    minor(NODEV), (char *)(uintptr_t)nm.devname,
				    NULL, NULL, ep) == -1) {
					Free((void *)(uintptr_t)nm.devname);
					Free((void *)(uintptr_t)drvnm);
					return (-1);
				} else {
					Free((void *)(uintptr_t)nm.devname);
					Free((void *)(uintptr_t)drvnm);
					continue;
				}
			}

			nm.side = sideno;
			if (MD_MNSET_DESC(sd)) {
				tmp_sideno = sideno;
			} else {
				tmp_sideno = sideno - 1;
			}

			if ((done = meta_getnextside_devinfo(sp,
			    (char *)(uintptr_t)nm.devname, &tmp_sideno,
			    &cname, &dname, &mnum, ep)) == -1) {
				Free((void *)(uintptr_t)nm.devname);
				return (-1);
			}

			assert(done == 1);
			Free((void *)(uintptr_t)nm.devname);
			Free((void *)(uintptr_t)drvnm);

			/*
			 * The device reference count can be greater than 1 if
			 * more than one softpart is configured on top of the
			 * same device.  If this is the case then we want to
			 * increment the count to sync up with the other sides.
			 */
			for (i = 0; i < nm.ref_count; i++) {
				if (add_name(sp, sideno, nm.key, dname, mnum,
				    cname, NULL, NULL, ep) == -1)
					rval = -1;
			}

			Free(cname);
			Free(dname);

			if (rval != 0)
				return (rval);
		}
	}

	/*NOTREACHED*/
}

static int
check_setdrvs_againstnode(mdsetname_t *sp, char *node, md_error_t *ep)
{
	mddrivename_t	*dp;
	md_drive_desc	*dd, *ddp;

	if ((dd = metaget_drivedesc(sp, MD_FULLNAME_ONLY, ep)) == NULL)
		if (! mdisok(ep))
			return (-1);

	for (ddp = dd; ddp != NULL; ddp = ddp->dd_next) {
		dp = ddp->dd_dnp;

		if (checkdrive_onnode(sp, dp, node, ep))
			return (-1);
	}

	return (0);
}

static int
create_multinode_set_on_hosts(
	mdsetname_t	*sp,
	int		node_c,		/* Number of new nodes */
	char		**node_v,	/* Nodes which are being added */
	int		new_set,
	md_error_t	*ep
)
{
	int				i;
	md_set_desc			*sd;
	md_timeval32_t			now;
	ulong_t				genid;
	int				rval = 0;
	md_mnnode_desc			*nd, *ndm = NULL;
	md_mnnode_desc			*nd_prev, *nd_curr;
	int				nodecnt;
	mndiskset_membershiplist_t	*nl, *nl2;

	if (!new_set) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		now = sd->sd_ctime;
		genid = sd->sd_genid - 1;
		if (sd->sd_drvs)
			genid--;
	} else {
		sd = Zalloc(sizeof (*sd));

		if (meta_gettimeofday(&now) == -1) {
			(void) mdsyserror(ep, errno,
			    dgettext(TEXT_DOMAIN, "meta_gettimeofday()"));
			rval = -1;
			goto out;
		}

		/* Put the new entries into the set */
		/*
		 * Get membershiplist from API routine.  If there's
		 * an error, fail to create set and pass back error.
		 */
		if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
			rval = -1;
			goto out;
		}

		/*
		 * meta_set_addhosts has already verified that
		 * this node list is in the membership list
		 * so set ALIVE flag.
		 * Since this is a new set, all hosts being
		 * added are new to the set, so also set ADD flag.
		 */
		for (i = 0; i < node_c; i++) {
			nd = Zalloc(sizeof (*nd));
			(void) strcpy(nd->nd_nodename, node_v[i]);
			nd->nd_ctime = now;
			nd->nd_flags = (MD_MN_NODE_ALIVE |
			    MD_MN_NODE_ADD);
			nl2 = nl;
			while (nl2) {
				if (strcmp(nl2->msl_node_name,
				    node_v[i]) == 0) {
					nd->nd_nodeid = nl2->msl_node_id;
					(void) strcpy(nd->nd_priv_ic,
					    nl2->msl_node_addr);
					break;
				}
				nl2 = nl2->next;
			}

			/*
			 * Nodelist must be kept in ascending
			 * nodeid order.
			 */
			if (sd->sd_nodelist == NULL) {
				/* Nothing in list, just add it */
				sd->sd_nodelist = nd;
			} else if (nd->nd_nodeid < sd->sd_nodelist->nd_nodeid) {
				/* Add to head of list */
				nd->nd_next = sd->sd_nodelist;
				sd->sd_nodelist = nd;
			} else {
				nd_curr = sd->sd_nodelist->nd_next;
				nd_prev = sd->sd_nodelist;
				/* Search for place ot add it */
				while (nd_curr) {
					if (nd->nd_nodeid <
					    nd_curr->nd_nodeid) {
						/* Add before nd_curr */
						nd->nd_next = nd_curr;
						nd_prev->nd_next = nd;
						break;
					}
					nd_prev = nd_curr;
					nd_curr = nd_curr->nd_next;
				}
				/* Add to end of list */
				if (nd_curr == NULL) {
					nd_prev->nd_next = nd;
				}

			}
			/* Set master to be first node added */
			if (ndm == NULL)
				ndm = nd;
		}

		meta_free_nodelist(nl);
		/*
		 * Creating mnset for first time.
		 * Set master to be invalid until first drive is
		 * in set.
		 */
		(void) strcpy(sd->sd_mn_master_nodenm, "");
		sd->sd_mn_master_nodeid = MD_MN_INVALID_NID;
		sd->sd_mn_masternode = ndm;
		sd->sd_ctime = now;
		genid = sd->sd_genid = 0;
	}

	/* Create the set where needed */
	for (i = 0; i < node_c; i++) {
		/*
		 * Create the set on each new node.  If the set already
		 * exists, then the node list being created on each new node
		 * is the current node list from before the new nodes
		 * were added.  If the set doesn't exist, then the node
		 * list being created on each new node is the entire
		 * new node list.
		 */
		if (clnt_mncreateset(node_v[i], sp, sd->sd_nodelist,
		    now, genid, sd->sd_mn_master_nodenm,
		    sd->sd_mn_master_nodeid, ep) == -1) {
			rval = -1;
			break;
		}
	}

out:
	if (new_set) {
		nd = sd->sd_nodelist;
		while (nd) {
			sd->sd_nodelist = nd->nd_next;
			Free(nd);
			nd = sd->sd_nodelist;
		}
		Free(sd);
	}

	if (rval != 0 || new_set)
		return (rval);

	/*
	 * Add the drive records to the new sets
	 * and names for the new sides.
	 */
	return (add_drvs_to_hosts(sp, node_c, node_v, ep));
}


static int
create_traditional_set_on_hosts(
	mdsetname_t	*sp,
	int		node_c,		/* Number of new nodes */
	char		**node_v,	/* Nodes which are being added */
	int		new_set,
	md_error_t	*ep
)
{
	int		i;
	md_set_desc	*sd;
	md_timeval32_t	now;
	ulong_t		genid;
	int		rval = 0;

	if (!new_set) {

		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		now = sd->sd_ctime;

		genid = sd->sd_genid;

		if (sd->sd_drvs)
			genid--;
	} else {
		if (node_c > MD_MAXSIDES)
			return (mddserror(ep, MDE_DS_SIDENUMNOTAVAIL,
			    sp->setno, NULL, NULL, sp->setname));

		sd = Zalloc(sizeof (*sd));

		/* Put the new entries into the set */
		for (i = 0; i < node_c; i++) {
			(void) strcpy(sd->sd_nodes[i], node_v[i]);
		}

		if (meta_gettimeofday(&now) == -1) {
			(void) mdsyserror(ep, errno, "meta_gettimeofday()");
			rval = -1;
			goto out;
		}

		sd->sd_ctime = now;
		genid = sd->sd_genid = 0;
	}

	/* Create the set where needed */
	for (i = 0; i < node_c; i++) {
		/*
		 * Create the set on each new host
		 */
		if (clnt_createset(node_v[i], sp, sd->sd_nodes, now, genid,
		    ep) == -1) {
			rval = -1;
			break;
		}
	}

out:
	if (new_set)
		Free(sd);

	if (rval != 0 || new_set)
		return (rval);

	/*
	 * Add the drive records to the new sets
	 * and names for the new sides.
	 */
	return (add_drvs_to_hosts(sp, node_c, node_v, ep));
}

static int
create_set_on_hosts(
	mdsetname_t	*sp,
	int		multi_node,	/* Multi_node diskset or not? */
	int		node_c,		/* Number of new nodes */
	char		**node_v,	/* Nodes which are being added */
	int		new_set,
	md_error_t	*ep
)
{
	if (multi_node)
		return (create_multinode_set_on_hosts(sp, node_c, node_v,
		    new_set, ep));
	else
		return (create_traditional_set_on_hosts(sp, node_c, node_v,
		    new_set, ep));
}

static int
create_set(
	mdsetname_t	*sp,
	int		multi_node,	/* Multi-node diskset or not? */
	int		node_c,
	char		**node_v,
	int		auto_take,
	md_error_t	*ep
)
{
	int		i;
	int		rval = 0;
	set_t		max_sets;
	set_t		setno;
	int		bool;
	uint_t		sr_flags;
	sigset_t	oldsigs;
	md_setkey_t	*cl_sk;
	int		rb_level = 0;
	md_error_t	xep = mdnullerror;
	rval_e		sdssc_rval;
	int		lock_flag = 0;
	int		sig_flag = 0;

	if ((max_sets = get_max_sets(ep)) == 0)
		return (-1);

	/* We must be a member of the set we are creating */
	if (! strinlst(mynode(), node_c, node_v))
		return (mddserror(ep, MDE_DS_SELFNOTIN,
		    sp->setno, mynode(), NULL, sp->setname));

	/*
	 * If auto_take then we must be the only member of the set
	 * that we are creating.
	 */
	if (auto_take && node_c > 1)
		return (mddserror(ep, MDE_DS_SINGLEHOST, sp->setno, NULL, NULL,
		    sp->setname));

	/*
	 * If we're part of SC3.0 we'll already have allocated the
	 * set number so we can skip the allocation algorithm used.
	 * Set number is unique across traditional and MN disksets.
	 */
	if ((sdssc_rval = sdssc_get_index(sp->setname, &setno))
	    == SDSSC_NOT_BOUND) {

		for (i = 0; i < node_c; i++) {
			int	has_set;

			/* Skip my node */
			if (strcmp(mynode(), node_v[i]) == 0)
				continue;

			/*
			 * Make sure this set name is not used on the
			 * other hosts
			 */
			has_set = nodehasset(sp, node_v[i], NHS_N_EQ, ep);
			if (has_set < 0) {
				if (! mdiserror(ep, MDE_NO_SET)) {
					rval = -1;
					goto out;
				}
				mdclrerror(ep);
				continue;
			}

			if (has_set) {
				(void) mddserror(ep, MDE_DS_NODEHASSET,
				    sp->setno, node_v[i], NULL, sp->setname);
				rval = -1;
				goto out;
			}
		}

		for (setno = 1; setno < max_sets; setno++) {
			for (i = 0; i < node_c; i++) {
				if (clnt_setnumbusy(node_v[i], setno,
				    &bool, ep) == -1) {
					rval = -1;
					goto out;
				}

				if (bool == TRUE)
					break;
			}
			if (i == node_c)
				break;
		}
	} else if (sdssc_rval != SDSSC_OKAY) {
		(void) mddserror(ep, MDE_DS_SETNUMNOTAVAIL, MD_SET_BAD, NULL,
		    NULL, sp->setname);
		rval = -1;
		goto out;
	}

	if (setno == max_sets) {
		(void) mddserror(ep, MDE_DS_SETNUMNOTAVAIL, MD_SET_BAD, NULL,
		    NULL, sp->setname);
		rval = -1;
		goto out;
	}

	sp->setno = setno;

	/*
	 * Lock the set on current set members.
	 * Set locking done much earlier for MN diskset than for traditional
	 * diskset since lock_set is used to protect against
	 * other meta* commands running on the other nodes.
	 * Don't issue mdcommd SUSPEND command since there is nothing
	 * to suspend since there currently is no set.
	 */
	if (multi_node) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
		sig_flag = 1;

		/* Lock the set on new set members */
		for (i = 0; i < node_c; i++) {
			if (clnt_lock_set(node_v[i], sp, ep)) {
				rval = -1;
				goto out;
			}
			lock_flag = 1;
		}
		/* Now have the diskset locked, verify set number is still ok */
		for (i = 0; i < node_c; i++) {
			if (clnt_setnumbusy(node_v[i], setno,
			    &bool, ep) == -1) {
				rval = -1;
				goto out;
			}
		}
	}


	if (meta_set_checkname(sp->setname, ep)) {
		rval = -1;
		goto out;
	}

	for (i = 0; i < node_c; i++) {
		if (clnt_setnameok(node_v[i], sp, &bool, ep) == -1) {
			rval = -1;
			goto out;
		}
		if (bool == FALSE) {
			(void) mddserror(ep, MDE_DS_SETNAMEBUSY, sp->setno,
			    node_v[i], NULL, sp->setname);
			rval = -1;
			goto out;
		}
	}

	/* END CHECK CODE */

	/* Lock the set on new set members */
	if (!multi_node) {
		md_rb_sig_handling_on();
		sig_flag = 1;
		for (i = 0; i < node_c; i++) {
			if (clnt_lock_set(node_v[i], sp, ep)) {
				rval = -1;
				goto out;
			}
			lock_flag = 1;
		}
	}

	RB_TEST(1, "create_set", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "create_set", ep)

	if ((rval = create_set_on_hosts(sp, multi_node, node_c, node_v,
	    1, ep)) == -1)
		goto rollback;

	RB_TEST(3, "create_set", ep)

	if (auto_take)
		sr_flags = MD_SR_OK | MD_SR_AUTO_TAKE;
	else
		sr_flags = MD_SR_OK;

	/*
	 * Mark the set record MD_SR_OK
	 */
	for (i = 0; i < node_c; i++)
		if (clnt_upd_sr_flags(node_v[i], sp, sr_flags, ep))
			goto rollback;

	rb_level = 2;	/* level 2 */

	/*
	 * For MN diskset:
	 * On each added node, set the node record for that node
	 * to OK.  Then set all node records for the newly added
	 * nodes on all nodes to ok.
	 *
	 * By setting a node's own node record to ok first, even if
	 * the node adding the hosts panics, the rest of the nodes can
	 * determine the same node list during the choosing of the master
	 * during reconfig.  So, only nodes considered for mastership
	 * are nodes that have both MD_MN_NODE_OK and MD_SR_OK set
	 * on that node's rpc.metad.  If all nodes have MD_SR_OK set,
	 * but no node has its own MD_MN_NODE_OK set, then the set will
	 * be removed during reconfig since a panic occurred during the
	 * creation of the initial diskset.
	 */

	if (multi_node) {
		md_mnnode_desc	*nd, *saved_nd_next;
		md_set_desc	*sd;

		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			goto rollback;
		}

		for (i = 0; i < node_c; i++) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			/* Something wrong, will pick this up in next loop */
			if (nd == NULL)
				continue;

			/* Only changing my local cache of node list */
			saved_nd_next = nd->nd_next;
			nd->nd_next = NULL;

			/* Set node record for added host to ok on that host */
			if (clnt_upd_nr_flags(node_v[i], sp,
			    nd, MD_NR_OK, NULL, ep)) {
				nd->nd_next = saved_nd_next;
				goto rollback;
			}
			nd->nd_next = saved_nd_next;
		}

		/* Now set all node records on all nodes to be ok */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_upd_nr_flags(nd->nd_nodename, sp,
			    sd->sd_nodelist, MD_NR_OK, NULL, ep)) {
				goto rollback;
			}
			nd = nd->nd_next;
		}
	}

	RB_TEST(4, "create_set", ep)

out:
	if ((rval == 0) && multi_node) {
		/*
		 * Set successfully created.
		 * Notify rpc.mdcommd on all nodes of a nodelist change.
		 * Send reinit command to mdcommd which forces it to get
		 * fresh set description.  Then send resume.
		 * Resume on class 0 will resume all classes.
		 */
		for (i = 0; i < node_c; i++) {
			/* Class is ignored for REINIT */
			if (clnt_mdcommdctl(node_v[i], COMMDCTL_REINIT,
			    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to reinit rpc.mdcommd.\n"));
			}
		}
		for (i = 0; i < node_c; i++) {
			if (clnt_mdcommdctl(node_v[i], COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
			}
		}
		meta_ping_mnset(sp->setno);
	}
	if (lock_flag) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		for (i = 0; i < node_c; i++) {
			if (clnt_unlock_set(node_v[i], cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
		}
		cl_set_setkey(NULL);
	}

	if (sig_flag) {
		if (multi_node) {
			/* release signals back to what they were on entry */
			if (procsigs(FALSE, &oldsigs, &xep) < 0)
				mdclrerror(&xep);
		} else {
			md_rb_sig_handling_off(md_got_sig(), md_which_sig());
		}
	}

	return (rval);

rollback:
	/* all signals already blocked for MN disket */
	if (!multi_node) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	}

	rval = -1;

	/*
	 * For MN diskset:
	 * On each added node (which is now each node to be deleted),
	 * set the node record for that node to DEL.  Then set all
	 * node records for the newly added (soon to be deleted) nodes
	 * on all nodes to ok.
	 *
	 * By setting a node's own node record to DEL first, even if
	 * the node doing the rollback panics, the rest of the nodes can
	 * determine the same node list during the choosing of the master
	 * during reconfig.
	 */

	/* level 3 */
	if ((rb_level > 1) && (multi_node)) {
		md_mnnode_desc	*nd, *saved_nd_next;
		md_set_desc	*sd;

		if ((sd = metaget_setdesc(sp, &xep)) == NULL) {
			mdclrerror(&xep);
		}

		for (i = 0; i < node_c; i++) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			/* Something wrong, will pick this up in next loop */
			if (nd == NULL)
				continue;

			/* Only changing my local cache of node list */
			saved_nd_next = nd->nd_next;
			nd->nd_next = NULL;

			/* Set node record for added host to DEL on that host */
			if (clnt_upd_nr_flags(node_v[i], sp,
			    nd, MD_NR_DEL, NULL, &xep)) {
				nd->nd_next = saved_nd_next;
				mdclrerror(&xep);
			}
			nd->nd_next = saved_nd_next;
		}

		/* Now set all node records on all nodes to be DEL */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_upd_nr_flags(nd->nd_nodename, sp,
			    sd->sd_nodelist, MD_NR_DEL, NULL, &xep)) {
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}

		/* Mark set record on all hosts to be DELETED */
		for (i = 0; i < node_c; i++) {
			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_DEL, &xep)) {
				mdclrerror(&xep);
			}
		}
	}
	/* level 1 */
	if (rb_level > 0) {
		for (i = 0; i < node_c; i++) {
			if (clnt_delset(node_v[i], sp, &xep) == -1)
				mdclrerror(&xep);
		}
	}

	/* level 0 */
	/* Don't test lock flag since guaranteed to be set if in rollback */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	for (i = 0; i < node_c; i++) {
		if (clnt_unlock_set(node_v[i], cl_sk, &xep))
			mdclrerror(&xep);
	}
	cl_set_setkey(NULL);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	if ((sig_flag) && (!multi_node))
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	return (rval);
}

static int
del_db_sidenms(
	mdsetname_t	*sp,
	side_t		sideno,
	md_error_t	*ep
)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	int			rval = 0;

	if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) < 0)
		return (-1);

	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		md_replica_t	*r = rl->rl_repp;

		if (meta_db_delsidenm(sp, sideno, r->r_namep, r->r_blkno, ep)) {
			rval = -1;
			goto out;
		}
	}

out:
	metafreereplicalist(rlp);
	return (rval);
}

static int
del_drvs_from_hosts(
	mdsetname_t	*sp,
	md_set_desc	*sd,
	md_drive_desc	*dd,
	int		node_c,
	char		**node_v,
	int		oha,
	md_error_t	*ep
)
{
	int 		i;
	md_mnnode_desc	*nd;

	for (i = 0; i < node_c; i++) {
		if (MD_MNSET_DESC(sd) && (oha == TRUE)) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			if (nd == NULL) {
				return (mddserror(ep, MDE_DS_NOTINMEMBERLIST,
				    sp->setno, nd->nd_nodename,
				    NULL, sp->setname));
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				continue;
			}
			if (clnt_deldrvs(node_v[i], sp, dd, ep)) {
				return (-1);
			}
		} else if (MD_MNSET_DESC(sd) && (oha == FALSE)) {
			/*
			 * All nodes should be alive in non-oha mode.
			 */
			if (clnt_deldrvs(node_v[i], sp, dd, ep)) {
				return (-1);
			}
		} else {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_deldrvs(node_v[i], sp, dd, ep)) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				return (-1);
			}
		}
	}

	return (0);
}

static int
del_host_noset(
	mdsetname_t	*sp,
	char		**anode,
	md_error_t	*ep
)
{
	int		rval = 0;
	md_setkey_t	*cl_sk;
	md_drive_desc	*dd;
	md_error_t	xep = mdnullerror;
	md_set_desc	*sd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	/* Lock the set on our side */
	if (clnt_lock_set(mynode(), sp, ep)) {
		rval = -1;
		goto out;
	}

	if (clnt_delhosts(mynode(), sp, 1, anode, ep)) {
		rval = -1;
		goto out;
	}

	if (!MD_MNSET_DESC(sd)) {
		if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
		    ep)) == NULL) {
			if (! mdisok(ep)) {
				rval = -1;
				goto out;
			}
		}

		/* If we have drives */
		if (dd != NULL) {
			if (clnt_del_drv_sidenms(mynode(), sp, ep)) {
				rval = -1;
				goto out;
			}
		}
	}

out:
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(mynode(), cl_sk, &xep)) {
		if (rval == 0)
			(void) mdstealerror(ep, &xep);
		rval = -1;
	}
	cl_set_setkey(NULL);

	metaflushsetname(sp);

	return (rval);
}

static int
del_md_sidenms(mdsetname_t *sp, side_t sideno, md_error_t *ep)
{
	mdnm_params_t		nm;
	md_set_desc		*sd;
	int			i;

	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
	}
	/* Use rpc.mdcommd to add md side info from all nodes */
	if ((! metaislocalset(sp)) && MD_MNSET_DESC(sd) &&
	    (sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)) {
		md_mn_result_t			*resultp = NULL;
		md_mn_msg_meta_md_delside_t	md_ds;
		int				send_rval;

		md_ds.msg_sideno = sideno;
		/*
		 * If reconfig cycle has been started, this node is stuck in
		 * in the return step until this command has completed.  If
		 * mdcommd is suspended, ask send_message to fail (instead of
		 * retrying) so that metaset can finish allowing the
		 * reconfig cycle to proceed.
		 */
		send_rval = mdmn_send_message(sp->setno,
		    MD_MN_MSG_META_MD_DELSIDE,
		    MD_MSGF_FAIL_ON_SUSPEND | MD_MSGF_PANIC_WHEN_INCONSISTENT,
		    0, (char *)&md_ds, sizeof (md_mn_msg_meta_md_delside_t),
		    &resultp, ep);
		if (send_rval != 0) {
			(void) mdstealerror(ep, &(resultp->mmr_ep));
			if (resultp)
				free_result(resultp);
			return (-1);
		}
		if (resultp)
			free_result(resultp);
	} else {
		(void) memset(&nm, '\0', sizeof (nm));
		nm.key   = MD_KEYWILD;

		/*CONSTCOND*/
		while (1) {
			nm.mde   = mdnullerror;
			nm.setno = sp->setno;
			nm.side  = MD_SIDEWILD;
			if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde, NULL) != 0)
				return (mdstealerror(ep, &nm.mde));

			if (nm.key == MD_KEYWILD)
				return (0);

			/*
			 * The device reference count can be greater than 1 if
			 * more than one softpart is configured on top of the
			 * same device.  If this is the case then we want to
			 * decrement the count to zero so the entry can be
			 * actually removed.
			 */
			for (i = 0; i < nm.ref_count; i++) {
				if (del_name(sp, sideno, nm.key, ep) == -1)
					return (-1);
			}
		}
	}
	return (0);
}

static void
recreate_set(
	mdsetname_t		*sp,
	md_set_desc		*sd
)
{
	int			i;
	int			has_set;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			has_set = nodehasset(sp, nd->nd_nodename,
			    NHS_NST_EQ, &xep);

			if (has_set >= 0) {
				nd = nd->nd_next;
				continue;
			}

			mdclrerror(&xep);

			if (clnt_mncreateset(nd->nd_nodename, sp,
			    sd->sd_nodelist,
			    sd->sd_ctime, sd->sd_genid,
			    sd->sd_mn_master_nodenm,
			    sd->sd_mn_master_nodeid, &xep) == -1)
				mdclrerror(&xep);
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			has_set = nodehasset(sp, sd->sd_nodes[i],
			    NHS_NST_EQ, &xep);

			if (has_set >= 0)
				continue;

			mdclrerror(&xep);

			if (clnt_createset(sd->sd_nodes[i], sp, sd->sd_nodes,
			    sd->sd_ctime, sd->sd_genid, &xep) == -1)
				mdclrerror(&xep);
		}
	}
}

/*
 * If a MN diskset, set is already locked on all nodes via clnt_lock_set.
 */
static int
del_set_nodrives(
	mdsetname_t		*sp,
	int			node_c,
	char			**node_v,
	int			oha,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	int			i;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	int			rb_level = 0;
	ulong_t			max_genid = 0;
	int			rval = 0;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;
	int			delete_end = 1;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (MD_MNSET_DESC(sd)) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	} else {
		md_rb_sig_handling_on();
	}

	/*
	 * Lock the set on current set members for traditional disksets.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		for (i = 0; i < node_c; i++) {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_lock_set(node_v[i], sp, ep)) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				rval = -1;
				goto out;
			}
		}
	}


	RB_TEST(1, "deletehosts", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "deletehosts", ep)

	/*
	 * Mark the set record MD_SR_DEL
	 */
	for (i = 0; i < node_c; i++) {

		RB_TEST(3, "deletehosts", ep)

		if (MD_MNSET_DESC(sd) && (oha == TRUE)) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			if (nd == NULL) {
				(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST,
				    sp->setno, nd->nd_nodename,
				    NULL, sp->setname);
				goto rollback;
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				continue;
			}

			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_DEL, ep)) {
				goto rollback;
			}
		} else if (MD_MNSET_DESC(sd) && (oha == FALSE)) {
			/*
			 * All nodes should be alive in non-oha mode.
			 */
			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_DEL, ep)) {
				goto rollback;
			}
		} else {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_DEL, ep)) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}
		}

		RB_TEST(4, "deletehosts", ep)
	}

	RB_TEST(5, "deletehosts", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(6, "deletehosts", ep)

	if (sdssc_delete_begin(sp->setname) == SDSSC_ERROR)
		if (metad_isautotakebyname(sp->setname))
			delete_end = 0;
		else
			goto rollback;

	/* The set is OK to delete, make it so. */
	for (i = 0; i < node_c; i++) {

		RB_TEST(7, "deletehosts", ep)

		if (MD_MNSET_DESC(sd) && (oha == TRUE)) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			if (nd == NULL) {
				(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST,
				    sp->setno, nd->nd_nodename,
				    NULL, sp->setname);
				goto rollback;
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				continue;
			}

			if (clnt_delset(node_v[i], sp, ep) == -1) {
				goto rollback;
			}
		} else if (MD_MNSET_DESC(sd) && (oha == FALSE)) {
			/*
			 * All nodes should be alive in non-oha mode.
			 */
			if (clnt_delset(node_v[i], sp, ep) == -1) {
				goto rollback;
			}
		} else {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_delset(node_v[i], sp, ep) == -1) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}
		}

		RB_TEST(8, "deletehosts", ep)
	}

	RB_TEST(9, "deletehosts", ep)

out:
	/*
	 * Unlock the set on current set members
	 * for traditional disksets.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		for (i = 0; i < node_c; i++) {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_unlock_set(node_v[i], cl_sk, &xep)) {
				if (oha == TRUE && mdanyrpcerror(&xep)) {
					mdclrerror(&xep);
					continue;
				}
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
		}
		cl_set_setkey(NULL);
	}

	/*
	 * A MN diskset has the clnt_locks held by meta_set_deletehosts so
	 * don't flush that data until meta_set_deletehosts has finished
	 * with it.  meta_set_deletehosts will handle the flush of the
	 * setname.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		metaflushsetname(sp);
	}

	if (delete_end &&
	    sdssc_delete_end(sp->setname, SDSSC_COMMIT) == SDSSC_ERROR)
		rval = -1;

	if (MD_MNSET_DESC(sd)) {
		/* release signals back to what they were on entry */
		if (procsigs(FALSE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	} else {
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
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

	/* level 2 */
	if (rb_level > 1) {
		recreate_set(sp, sd);
		max_genid++;

		if (delete_end)
			(void) sdssc_delete_end(sp->setname, SDSSC_CLEANUP);
	}

	/* level 1 */
	if (rb_level > 0) {
		max_genid++;
		resync_genid(sp, sd, max_genid, node_c, node_v);
	}

	/* level 0 */
	/*
	 * Unlock the set on current set members
	 * for traditional disksets.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		for (i = 0; i < node_c; i++) {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_unlock_set(node_v[i], cl_sk, &xep))
				mdclrerror(&xep);
		}
		cl_set_setkey(NULL);
	}

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	/*
	 * A MN diskset has the clnt_locks held by meta_set_deletehosts so
	 * don't flush that data until meta_set_deletehosts has finished
	 * with it.  meta_set_deletehosts will handle the flush of the
	 * setname.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		metaflushsetname(sp);
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}

	return (rval);
}

/*
 * On entry:
 *   procsigs already called for MN diskset.
 *   md_rb_sig_handling already called for traditional diskset.
 */
static int
del_set_on_hosts(
	mdsetname_t		*sp,
	md_set_desc		*sd,
	md_drive_desc		*dd,
	int			node_c,		/* Number of nodes */
	char			**node_v,	/* Nodes being deleted */
	int			oha,
	md_error_t		*ep
)
{
	int			i;
	int			j;
	side_t			sideno;
	md_replicalist_t	*rlp = NULL;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	ulong_t			max_genid = 0;
	int			rb_level = 1;	/* This is a special case */
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;

	RB_PREEMPT;

	RB_TEST(7, "deletehosts", ep)

	if (dd != NULL) {
		/*
		 * May need this to re-add sidenames on roll back.
		 */
		if (metareplicalist(sp, (MD_BASICNAME_OK | PRINT_FAST), &rlp,
		    ep) < 0)
			goto rollback;

		RB_TEST(8, "deletehosts", ep)

		RB_PREEMPT;
		rb_level = 2;	/* level 2 */

		RB_TEST(9, "deletehosts", ep)

		if (del_drvs_from_hosts(sp, sd, dd, node_c, node_v, oha, ep))
			goto rollback;

		RB_TEST(10, "deletehosts", ep)

		RB_PREEMPT;
		rb_level = 3;	/* level 3 */

		RB_TEST(11, "deletehosts", ep)

		/*
		 * Delete the db replica sides
		 * This is done before the next loop, so that
		 * the db does not get unloaded before we are finished
		 * deleting the sides.
		 */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* Skip hosts not being deleted */
				if (! strinlst(nd->nd_nodename, node_c,
				    node_v)) {
					nd = nd->nd_next;
					continue;
				}

				if (del_db_sidenms(sp, nd->nd_nodeid, ep))
					goto rollback;

				RB_TEST(12, "deletehosts", ep)
				nd = nd->nd_next;
			}
		} else {
			for (sideno = 0; sideno < MD_MAXSIDES; sideno++) {
				/* Skip empty slots */
				if (sd->sd_nodes[sideno][0] == '\0')
					continue;

				/* Skip hosts not being deleted */
				if (! strinlst(sd->sd_nodes[sideno], node_c,
				    node_v))
					continue;

				if (del_db_sidenms(sp, sideno, ep))
					goto rollback;

				RB_TEST(12, "deletehosts", ep)
			}
		}

		RB_TEST(13, "deletehosts", ep)

		RB_PREEMPT;
		rb_level = 4;	/* level 4 */

		RB_TEST(14, "deletehosts", ep)

		/* Delete the names from the namespace */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* Skip hosts not being deleted */
				if (! strinlst(nd->nd_nodename, node_c,
				    node_v)) {
					nd = nd->nd_next;
					continue;
				}

				if (del_md_sidenms(sp, nd->nd_nodeid, ep))
					goto rollback;

				RB_TEST(15, "deletehosts", ep)
				nd = nd->nd_next;
			}
		} else {
			for (sideno = 0; sideno < MD_MAXSIDES; sideno++) {
				/* Skip empty slots */
				if (sd->sd_nodes[sideno][0] == '\0')
					continue;

				/* Skip hosts not being deleted */
				if (! strinlst(sd->sd_nodes[sideno], node_c,
				    node_v))
					continue;

				if (del_md_sidenms(sp, sideno, ep))
					goto rollback;

				RB_TEST(15, "deletehosts", ep)
			}
		}
	}

	RB_TEST(16, "deletehosts", ep)

	RB_PREEMPT;
	rb_level = 5;	/* level 6 */

	RB_TEST(17, "deletehosts", ep)

	for (i = 0; i < node_c; i++) {
		if (MD_MNSET_DESC(sd) && (oha == TRUE)) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			if (nd == NULL) {
				(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST,
				    sp->setno, nd->nd_nodename,
				    NULL, sp->setname);
				goto rollback;
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				continue;
			}

			if (clnt_delset(node_v[i], sp, ep) == -1) {
				goto rollback;
			}
		} else if (MD_MNSET_DESC(sd) && (oha == FALSE)) {
			/*
			 * All nodes should be alive in non-oha mode.
			 */
			if (clnt_delset(node_v[i], sp, ep) == -1) {
				goto rollback;
			}
		} else {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_delset(node_v[i], sp, ep) == -1) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}
		}

		RB_TEST(18, "deletehosts", ep)
	}

	metafreereplicalist(rlp);

	if (MD_MNSET_DESC(sd)) {
		/* release signals back to what they were on entry */
		if (procsigs(FALSE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	} else {
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}

	return (0);

rollback:
	/* all signals already blocked for MN disket */
	if (!(MD_MNSET_DESC(sd))) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	}

	max_genid = sd->sd_genid;

	/* level 5 */
	if (rb_level > 4) {
		recreate_set(sp, sd);
		max_genid++;
	}

	/* level 2 */
	if (rb_level > 1 && dd != NULL) {
		/*
		 * See if we have to re-add the drives specified.
		 */
		for (i = 0; i < node_c; i++) {
			md_set_record	*sr;

			if (MD_MNSET_DESC(sd) && (oha == TRUE)) {
				/*
				 * During OHA mode, don't issue RPCs to
				 * non-alive nodes since there is no reason to
				 * wait for RPC timeouts.
				 */
				nd = sd->sd_nodelist;
				while (nd) {
					if (strcmp(nd->nd_nodename, node_v[i])
					    == 0)
						break;
					nd = nd->nd_next;
				}
				if (nd == NULL)
					continue;

				if (!(nd->nd_flags & MD_MN_NODE_ALIVE))
					continue;
			}

			/* Don't care if set record is MN or not */
			if (clnt_getset(node_v[i], sp->setname,
			    MD_SET_BAD, &sr, &xep) == -1) {
				mdclrerror(&xep);
				continue;
			}

			/* Drive already added, skip to next node */
			if (sr->sr_drivechain != NULL) {
				/*
				 * Set record structure was allocated from RPC
				 * routine getset so this structure is only of
				 * size md_set_record even if the MN flag is
				 * set.  So, clear the flag so that the free
				 * code doesn't attempt to free a structure
				 * the size of md_mnset_record.
				 */
				sr->sr_flags &= ~MD_SR_MN;
				free_sr(sr);
				continue;
			}

			if (clnt_adddrvs(node_v[i], sp, dd,
			    sr->sr_ctime, sr->sr_genid, &xep) == -1)
				mdclrerror(&xep);

			if (clnt_upd_dr_flags(node_v[i], sp, dd,
			    MD_DR_OK, &xep) == -1)
				mdclrerror(&xep);

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
		}
		max_genid += 3;
	}

	/* level 3 */
	if (rb_level > 2 && dd != NULL) {
		md_replicalist_t	*rl;

		for (rl = rlp; rl != NULL; rl = rl->rl_next) {
			md_replica_t	*r = rl->rl_repp;

			/*
			 * This is not the first replica being added to the
			 * diskset so call with ADDSIDENMS_BCAST.  If this
			 * is a traditional diskset, the bcast flag is ignored
			 * since traditional disksets don't use the rpc.mdcommd.
			 */
			if (meta_db_addsidenms(sp, r->r_namep, r->r_blkno,
			    DB_ADDSIDENMS_BCAST, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 4 */
	if (rb_level > 3 && dd != NULL) {
		int	nodeid_addsides = 0;
		/*
		 * Add the device names for the new sides into the namespace,
		 * on all hosts not being deleted.
		 */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* Find a node that is not being deleted */
				if (! strinlst(nd->nd_nodename, node_c,
				    node_v)) {
					nodeid_addsides = nd->nd_nodeid;
					break;
				}
				nd = nd->nd_next;
			}
		} else {
			for (j = 0; j < MD_MAXSIDES; j++) {
				/* Skip empty slots */
				if (sd->sd_nodes[j][0] == '\0')
					continue;

				/* Find a node that is not being deleted */
				if (! strinlst(sd->sd_nodes[j], node_c,
				    node_v))
					break;
			}
			nodeid_addsides = j;
		}

		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* Skip nodes not being deleted */
				if (!strinlst(nd->nd_nodename, node_c,
				    node_v)) {
					nd = nd->nd_next;
					continue;
				}

				/* this side was just created, add the names */
				if (add_md_sidenms(sp, nd->nd_nodeid,
				    nodeid_addsides, &xep))
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/* Skip nodes not being deleted */
				if (!strinlst(sd->sd_nodes[i], node_c, node_v))
					continue;

				/* this side was just created, add the names */
				if (add_md_sidenms(sp, i, nodeid_addsides,
				    &xep))
					mdclrerror(&xep);
			}
		}
	}

	/* level 1 */
	if (rb_level > 0) {
		max_genid++;
		resync_genid(sp, sd, max_genid, node_c, node_v);
	}

	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE))
				continue;
			/* To balance lock/unlock; can send to dead node */
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

	metafreereplicalist(rlp);

	if (!(MD_MNSET_DESC(sd))) {
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}

	return (-1);
}

static int
make_sideno_sidenm(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,
	side_t		sideno,
	md_error_t	*ep
)
{
	mdsidenames_t	*sn, **sn_next;
	md_set_desc	*sd;
	mdname_t	*np;
	uint_t		rep_slice;
	int		err = 0;

	assert(dnp->side_names_key != MD_KEYWILD);

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* find the end of the link list */
	for (sn = dnp->side_names; sn->next != NULL; sn = sn->next)
		;
	sn_next = &sn->next;

	if (meta_replicaslice(dnp, &rep_slice, ep) != 0)
		return (-1);

	if ((np = metaslicename(dnp, rep_slice, ep)) == NULL)
		return (-1);

	sn = Zalloc(sizeof (*sn));
	sn->sideno = sideno;

	if (MD_MNSET_DESC(sd)) {
		/*
		 * For MO diskset the sideno is not an index into
		 * the array of nodes.  Hence getside_devinfo is
		 * used instead of meta_getnextside_devinfo.
		 */
		if (meta_getside_devinfo(sp, np->bname, sideno, &sn->cname,
		    &sn->dname, &sn->mnum, ep) == -1)
			err = -1;
	} else {
		/* decrement sideno, to look like the previous sideno */
		sideno--;
		if (meta_getnextside_devinfo(sp, np->bname, &sideno,
		    &sn->cname, &sn->dname, &sn->mnum, ep) == -1)
			err = -1;
	}

	if (err) {
		Free(sn);
		return (err);
	}
	assert(sn->sideno == sideno);

	/* Add to the end of the linked list */
	*sn_next = sn;
	return (0);
}

static int
validate_nodes(
	mdsetname_t	*sp,
	int		node_c,
	char		**node_v,
	md_error_t	*ep
)
{
	char		*hostname;
	int		i;


	for (i = 0; i < node_c; i++) {
		if (strlen(node_v[i]) > (size_t)MD_MAX_NODENAME)
			return (mddserror(ep, MDE_DS_NODENAMETOOLONG,
			    sp->setno, node_v[i], NULL, sp->setname));
		if (clnt_hostname(node_v[i], &hostname, ep))
			return (-1);
		if (strcmp(node_v[i], hostname) != 0) {
			Free(hostname);
			return (mddserror(ep, MDE_DS_NOTNODENAME, sp->setno,
			    node_v[i], NULL, sp->setname));
		}
		Free(hostname);
	}
	return (0);
}

/*
 * Exported Entry Points
 */

/*
 * Check the given disk set name for syntactic correctness.
 */
int
meta_set_checkname(char *setname, md_error_t *ep)
{
	char	*cp;

	if (strlen(setname) > (size_t)MD_MAX_SETNAME)
		return (mddserror(ep, MDE_DS_SETNAMETOOLONG,
		    MD_SET_BAD, NULL, NULL, setname));

	for (cp = setname; *cp; cp++)
		if (!isprint(*cp) || strchr(INVALID_IN_NAMES, *cp) != NULL)
			return (mddserror(ep, MDE_DS_INVALIDSETNAME,
			    MD_SET_BAD, NULL, NULL, setname));
	return (0);
}

/*
 * Add host(s) to the multi-node diskset provided in sp.
 * 	- create set if non-existent.
 */
static int
meta_multinode_set_addhosts(
	mdsetname_t	*sp,
	int		multi_node,
	int		node_c,
	char		**node_v,
	int		auto_take,
	md_error_t	*ep
)
{
	md_set_desc			*sd;
	md_drive_desc			*dd, *p;
	int				rval = 0;
	int				bool;
	int				nodeindex;
	int 				i;
	int				has_set;
	sigset_t			oldsigs;
	md_setkey_t			*cl_sk;
	int				rb_level = 0;
	md_error_t			xep = mdnullerror;
	md_mnnode_desc			*nd, *nd_curr, *nd_prev;
	md_timeval32_t			now;
	int				nodecnt;
	mndiskset_membershiplist_t	*nl, *nl2;
	int				suspendall_flag = 0;
	int				suspend1_flag = 0;
	int				lock_flag = 0;
	int				stale_flag = 0;
	md_mnnode_desc			*saved_nd_next;
	int				remote_sets_created = 0;

	/*
	 * Check membershiplist first.  If there's
	 * an error, fail to create set and pass back error.
	 */
	if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
		return (-1);
	}
	/* Verify that all nodes are in member list */
	for (i = 0; i < node_c; i++) {
		/*
		 * If node in list isn't a member of the membership,
		 * just return error.
		 */
		if (meta_is_member(node_v[i], NULL, nl) == 0) {
			meta_free_nodelist(nl);
			return (mddserror(ep, MDE_DS_NOTINMEMBERLIST,
			    sp->setno, node_v[i], NULL, sp->setname));
		}
	}
	/*
	 * Node list is needed later, but there is a lot of error
	 * checking and possible failures between here and there, so
	 * just re-get the list later if there are no errors.
	 */
	meta_free_nodelist(nl);
	nl = NULL;

	/*
	 * Verify that list of nodes being added contains no
	 * duplicates.
	 */
	if (nodesuniq(sp, node_c, node_v, ep))
		return (-1);

	/*
	 * Verify that each node being added thinks that its nodename
	 * is the same as the nodename given.
	 */
	if (validate_nodes(sp, node_c, node_v, ep))
		return (-1);

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		if (! mdiserror(ep, MDE_NO_SET))
			return (-1);
		mdclrerror(ep);
		return (create_set(sp, multi_node, node_c, node_v, auto_take,
		    ep));
	} else {
		/*
		 * If this node and another node were both attempting to
		 * create the same setname at the same time, and the other
		 * node has just created the set on this node then sd would
		 * be non-NULL, but sp->setno would be null (setno is filled
		 * in by the create_set). If this is true, then fail since
		 * the other node has already won this race.
		 */
		if (sp->setno == NULL) {
			return (mddserror(ep, MDE_DS_NODEINSET,
			    NULL, mynode(), NULL, sp->setname));
		}
	}

	/* The auto_take behavior is inconsistent with multiple hosts. */
	if (auto_take || sd->sd_flags & MD_SR_AUTO_TAKE) {
		(void) mddserror(ep, MDE_DS_SINGLEHOST, sp->setno, NULL, NULL,
		    sp->setname);
		return (-1);
	}

	/*
	 * We already have the set.
	 */

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
	 * the new node record to their local mddb.  If a panic of this node
	 * leaves the local mddbs set, node and drive records out-of-sync, the
	 * reconfig cycle will fix the local mddbs and force them back into
	 * synchronization.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			return (mddserror(ep, MDE_DS_NOTINMEMBERLIST,
			    sp->setno, nd->nd_nodename, NULL,
			    sp->setname));
		}
		nd = nd->nd_next;
	}

	/*
	 * Check if node is already in set.
	 */
	for (i = 0; i < node_c; i++) {
		/* Is node already in set? */
		nd = sd->sd_nodelist;
		while (nd) {
			if (strcmp(nd->nd_nodename, node_v[i]) == 0)
				break;
			nd = nd->nd_next;
		}
		if (nd) {
			return (mddserror(ep, MDE_DS_NODEINSET,
			    sp->setno, node_v[i], NULL,
			    sp->setname));
		}
	}

	/*
	 * Lock the set on current set members.
	 * Set locking done much earlier for MN diskset than for traditional
	 * diskset since lock_set and SUSPEND are used to protect against
	 * other meta* commands running on the other nodes.
	 */
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
	/* Send suspend to nodes in nodelist before addhosts call */
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

	/* Lock the set on new set members */
	for (i = 0; i < node_c; i++) {
		/* Already verified to be alive */
		if (clnt_lock_set(node_v[i], sp, ep)) {
			rval = -1;
			goto out;
		}
		lock_flag = 1;
	}

	/*
	 * Perform the required checks for new hosts
	 */
	for (i = 0; i < node_c; i++) {
		/* Make sure this set name is not used on the other hosts */
		has_set = nodehasset(sp, node_v[i], NHS_N_EQ, ep);
		if (has_set < 0) {
			if (! mdiserror(ep, MDE_NO_SET)) {
				rval = -1;
				goto out;
			}
			/* Keep on truck'n */
			mdclrerror(ep);
		} else if (has_set) {
			(void) mddserror(ep, MDE_DS_NODEHASSET, sp->setno,
			    node_v[i], NULL, sp->setname);
			rval = -1;
			goto out;
		}

		if (clnt_setnumbusy(node_v[i], sp->setno, &bool, ep) == -1) {
			rval = -1;
			goto out;
		}

		if (bool == TRUE) {
			(void) mddserror(ep, MDE_DS_SETNUMBUSY, sp->setno,
			    node_v[i], NULL, sp->setname);
			rval = -1;
			goto out;
		}

		if (clnt_setnameok(node_v[i], sp, &bool, ep) == -1) {
			rval = -1;
			goto out;
		}

		if (bool == FALSE) {
			(void) mddserror(ep, MDE_DS_SETNAMEBUSY, sp->setno,
			    node_v[i], NULL, sp->setname);
			rval = -1;
			goto out;
		}

		if (check_setdrvs_againstnode(sp, node_v[i], ep)) {
			rval = -1;
			goto out;
		}
	}

	/* Get drive descriptors for the set */
	if ((dd = metaget_drivedesc(sp, MD_FULLNAME_ONLY, ep)) == NULL) {
		if (! mdisok(ep)) {
			rval = -1;
			goto out;
		}
	}

	/* END CHECK CODE */

	RB_TEST(1, "addhosts", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "addhosts", ep)

	/*
	 * Create the set where needed
	 */
	if (create_set_on_hosts(sp, multi_node, node_c, node_v, 0, ep)) {
		goto rollback;
	}

	/*
	 * Send suspend to rpc.mdcommd on nodes where a set has been
	 * created since rpc.mdcommd must now be running on the remote nodes.
	 */
	remote_sets_created = 1;
	for (i = 0; i < node_c; i++) {
		/*
		 * Lock out other meta* commands by suspending
		 * class 1 messages across the diskset.
		 */
		if (clnt_mdcommdctl(node_v[i],
		    COMMDCTL_SUSPEND, sp, MD_MSG_CLASS1,
		    MD_MSCF_NO_FLAGS, ep)) {
			rval = -1;
			goto rollback;
		}
	}

	/*
	 * Merge the new entries into the set with the existing sides.
	 * Get membershiplist from API routine.  If there's
	 * an error, fail to create set and pass back error.
	 */
	if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
		goto rollback;
	}
	if (meta_gettimeofday(&now) == -1) {
		meta_free_nodelist(nl);
		(void) mdsyserror(ep, errno,
		    dgettext(TEXT_DOMAIN, "meta_gettimeofday()"));
		goto rollback;
	}
	for (nodeindex = 0; nodeindex < node_c; nodeindex++) {
		nd = Zalloc(sizeof (*nd));
		(void) strcpy(nd->nd_nodename, node_v[nodeindex]);
		nd->nd_ctime = now;
		nl2 = nl;
		while (nl2) {
			if (strcmp(nl2->msl_node_name,
			    node_v[nodeindex]) == 0) {
				nd->nd_nodeid = nl2->msl_node_id;
				(void) strcpy(nd->nd_priv_ic,
				    nl2->msl_node_addr);
				break;
			}
			nl2 = nl2->next;
		}

		/*
		 * Nodelist must be kept in ascending nodeid order.
		 */
		if (sd->sd_nodelist == NULL) {
			/* Nothing in list, just add it */
			sd->sd_nodelist = nd;
		} else if (nd->nd_nodeid <
		    sd->sd_nodelist->nd_nodeid) {
			/* Add to head of list */
			nd->nd_next = sd->sd_nodelist;
			sd->sd_nodelist = nd;
		} else {
			nd_curr = sd->sd_nodelist->nd_next;
			nd_prev = sd->sd_nodelist;
			/* Search for place to add it */
			while (nd_curr) {
				if (nd->nd_nodeid < nd_curr->nd_nodeid) {
					/* Add before nd_curr */
					nd->nd_next = nd_curr;
					nd_prev->nd_next = nd;
					break;
				}
				nd_prev = nd_curr;
				nd_curr = nd_curr->nd_next;
			}
			/* Add to end of list */
			if (nd_curr == NULL) {
				nd_prev->nd_next = nd;
			}

		}
		/* Node already verified to be in membership */
		nd->nd_flags |= MD_MN_NODE_ALIVE;
	}
	meta_free_nodelist(nl);

	/* If we have drives */
	if (dd != NULL) {
		/*
		 * For all the hosts being added, create a sidename structure
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip nodes not being added */
			if (!strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}
			for (p = dd; p != NULL; p = p->dd_next) {
				if (make_sideno_sidenm(sp, p->dd_dnp,
				    nd->nd_nodeid, ep) != 0)
					goto rollback;
			}
			nd = nd->nd_next;
		}

		RB_PREEMPT;
		rb_level = 2;   /* level 2 */

		RB_TEST(4, "addhosts", ep)

		/*
		 * Add the new sidename for each drive to all the hosts
		 *
		 * If a multi-node diskset, each host only stores
		 * the side information for itself.  So, only send
		 * side information to the new hosts where each host
		 * will add the appropriate side information to its
		 * local mddb.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip nodes not being added */
			if (!strinlst(nd->nd_nodename, node_c,
			    node_v)) {
				nd = nd->nd_next;
				continue;
			}

			/* Add side info to new hosts */
			if (clnt_add_drv_sidenms(nd->nd_nodename,
			    mynode(), sp, sd, node_c, node_v, ep))
				goto rollback;

			nd = nd->nd_next;
		}

		RB_TEST(5, "addhosts", ep)

		RB_PREEMPT;
		rb_level = 3;	/* level 3 */

		RB_TEST(6, "addhosts", ep)

		/*
		 * Add the device names for the new sides into the namespace
		 * for all hosts being added.  This is adding the side
		 * names to the diskset's mddb so add sidenames for all
		 * of the new hosts.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip nodes not being added */
			if (!strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}

			/* this side was just created, add the names */
			if (add_md_sidenms(sp, nd->nd_nodeid,
			    MD_SIDEWILD, ep))
				goto rollback;

			nd = nd->nd_next;
		}

		RB_TEST(7, "addhosts", ep)

		RB_PREEMPT;
		rb_level = 4;   /* level 4 */

		RB_TEST(8, "addhosts", ep)

		if (add_db_sidenms(sp, ep))
			goto rollback;

	} else {
		RB_PREEMPT;
		rb_level = 4;
	}

	RB_TEST(9, "addhosts", ep)

	RB_PREEMPT;
	rb_level = 5;	/* level 5 */

	RB_TEST(10, "addhosts", ep)

	if (dd != NULL) {
		/*
		 * Notify rpc.mdcommd on all nodes of a nodelist change.
		 * Start by suspending rpc.mdcommd (which drains it of all
		 * messages), then change the nodelist followed by a reinit
		 * and resume.
		 */
		nd = sd->sd_nodelist;
		/* Send suspend_all to nodes in nodelist (existing + new) */
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_SUSPEND,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, ep)) {
				rval = -1;
				goto rollback;
			}
			suspendall_flag = 1;
			nd = nd->nd_next;
		}
	}

	/* Add the node(s) to the each host that is currently in the set */
	nd = sd->sd_nodelist;
	/* All nodes are guaranteed to be ALIVE */
	while (nd) {
		if (clnt_addhosts(nd->nd_nodename, sp, node_c, node_v, ep)) {
			goto rollback;
		}
		nd = nd->nd_next;
	}

	RB_TEST(11, "addhosts", ep)

	if (dd != NULL) {
		/*
		 * Mark the drives MD_DR_OK.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_upd_dr_flags(nd->nd_nodename, sp, dd,
			    MD_DR_OK, ep) == -1)
				goto rollback;
			nd = nd->nd_next;
		}
	}

	RB_TEST(12, "addhosts", ep)

	RB_PREEMPT;
	rb_level = 6;   /* level 6 */

	RB_TEST(13, "addhosts", ep)


	/* Add the mediator information to all hosts in the set. */
	nd = sd->sd_nodelist;
	/* All nodes are guaranteed to be ALIVE */
	while (nd) {
		if (clnt_updmeds(nd->nd_nodename, sp, &sd->sd_med, ep))
			goto rollback;
		nd = nd->nd_next;
	}

	RB_TEST(14, "addhosts", ep)

	/*
	 * If a MN diskset and there are drives in the set,
	 * set the master on the new nodes and
	 * automatically join the new nodes into the set.
	 */
	if (dd != NULL) {
		mddb_config_t   c;
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
			stale_flag = MNSET_IS_STALE;
		}

		/* Set master on newly added nodes */
		for (i = 0; i < node_c; i++) {
			if (clnt_mnsetmaster(node_v[i], sp,
			    sd->sd_mn_master_nodenm,
			    sd->sd_mn_master_nodeid, ep)) {
				goto rollback;
			}
		}
		/* Join newly added nodes to diskset and set OWN flag */
		for (i = 0; i < node_c; i++) {
			if (clnt_joinset(node_v[i], sp, stale_flag, ep))
				goto rollback;
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0) {
					nd->nd_flags |= MD_MN_NODE_OWN;
					/*
					 * Also set ADD flag since this flag
					 * is already set in rpc.metad - it's
					 * just not in the local copy.
					 * Could flush local cache and call
					 * metaget_setdesc, but this just
					 * adds time.  Since this node knows
					 * the state of the node flags in
					 * rpc.metad, just set the ADD
					 * flag and save time.
					 */
					nd->nd_flags |= MD_MN_NODE_ADD;
					break;
				}
				nd = nd->nd_next;
			}
		}

		/* Send new node flag list to all Owner nodes */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
				nd = nd->nd_next;
				continue;
			}
			/*
			 * Will effectively set OWN flag in records kept
			 * cached in rpc.metad.  The ADD flag would have
			 * already been set by the call to clnt_addhosts.
			 */
			if (clnt_upd_nr_flags(nd->nd_nodename, sp,
			    sd->sd_nodelist, MD_NR_SET, NULL, ep)) {
				goto rollback;
			}
			nd = nd->nd_next;
		}
	}

	/*
	 * Mark the set record MD_SR_OK
	 */
	nd = sd->sd_nodelist;
	/* All nodes are guaranteed to be ALIVE */
	while (nd) {
		if (clnt_upd_sr_flags(nd->nd_nodename, sp, MD_SR_OK,
		    ep)) {
			goto rollback;
		}
		nd = nd->nd_next;
	}

	/*
	 * For MN diskset:
	 * On each newly added node, set the node record for that node
	 * to OK.  Then set all node records for the newly added
	 * nodes on all nodes to ok.
	 *
	 * By setting a node's own node record to ok first, even if
	 * the node adding the hosts panics, the rest of the nodes can
	 * determine the same node list during the choosing of the master
	 * during reconfig.  So, only nodes considered for mastership
	 * are nodes that have both MD_MN_NODE_OK and MD_SR_OK set
	 * on that node's rpc.metad.  If all nodes have MD_SR_OK set,
	 * but no node has its own MD_MN_NODE_OK set, then the set will
	 * be removed during reconfig since a panic occurred during the
	 * creation of the initial diskset.
	 */

	for (i = 0; i < node_c; i++) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (strcmp(nd->nd_nodename, node_v[i]) == 0)
				break;
			nd = nd->nd_next;
		}
		/* Something wrong, will pick this up in next loop */
		if (nd == NULL)
			continue;

		/* Only changing my local cache of node list */
		saved_nd_next = nd->nd_next;
		nd->nd_next = NULL;

		/* Set node record for added host to ok on that host */
		if (clnt_upd_nr_flags(node_v[i], sp,
		    nd, MD_NR_OK, NULL, ep)) {
			nd->nd_next = saved_nd_next;
			goto rollback;
		}
		nd->nd_next = saved_nd_next;
	}

	/* Now set all node records on all nodes to be ok */
	nd = sd->sd_nodelist;
	/* All nodes are guaranteed to be ALIVE */
	while (nd) {
		if (clnt_upd_nr_flags(nd->nd_nodename, sp,
		    sd->sd_nodelist, MD_NR_OK, NULL, ep)) {
			goto rollback;
		}
		nd = nd->nd_next;
	}

	RB_TEST(15, "addhosts", ep)
out:
	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send reinit command to mdcommd which forces it to get
	 * fresh set description.  Then send resume.
	 * Resume on class 0 will resume all classes, so can skip
	 * doing an explicit resume of class1 (ignore suspend1_flag).
	 */
	if (suspendall_flag) {
		/*
		 * Don't know if nodelist contains the nodes being added
		 * or not, so do reinit to nodes not being added (by skipping
		 * any nodes in the nodelist being added) and then do
		 * reinit to nodes being added if remote_sets_created is 1.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* Skip nodes being added - handled later */
			if (strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}
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
		/*
		 * Send reinit to added nodes that had a set created since
		 * rpc.mdcommd is running on the nodes with a set.
		 */
		if (remote_sets_created == 1) {
			for (i = 0; i < node_c; i++) {
				if (clnt_mdcommdctl(node_v[i], COMMDCTL_REINIT,
				    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to reinit rpc.mdcommd.\n"));
				}
			}
		}
	}
	if ((suspend1_flag) || (suspendall_flag)) {
		/*
		 * Unlock diskset by resuming messages across the diskset.
		 * Just resume all classes so that resume is the same whether
		 * just one class was locked or all classes were locked.
		 *
		 * Don't know if nodelist contains the nodes being added
		 * or not, so do resume_all to nodes not being added (by
		 * skipping any nodes in the nodelist being added) and then do
		 * resume_all to nodes being added if remote_sets_created is 1.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* Skip nodes being added - handled later */
			if (strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}
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
		/*
		 * Send resume to added nodes that had a set created since
		 * rpc.mdcommd is be running on the nodes with a set.
		 */
		if (remote_sets_created == 1) {
			for (i = 0; i < node_c; i++) {
				/* Already verified to be alive */
				if (clnt_mdcommdctl(node_v[i], COMMDCTL_RESUME,
				    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS,
				    &xep)) {
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to resume rpc.mdcommd.\n"));
				}
			}
		}
		meta_ping_mnset(sp->setno);
		/*
		 * Start a resync thread on the newly added nodes
		 * if set is not stale. Also start a thread to update the
		 * abr state of all soft partitions
		 */
		if (stale_flag != MNSET_IS_STALE) {
			for (i = 0; i < node_c; i++) {
				if (clnt_mn_mirror_resync_all(node_v[i],
				    sp->setno, &xep)) {
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to start resync "
					    "thread.\n"));
				}
				if (clnt_mn_sp_update_abr(node_v[i],
				    sp->setno, &xep)) {
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to start sp update "
					    "thread.\n"));
				}
			}
		}
	}
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	/*
	 * Don't know if nodelist contains the nodes being added
	 * or not, so do clnt_unlock_set to nodes not being added (by
	 * skipping any nodes in the nodelist being added) and then do
	 * clnt_unlock_set to nodes being added.
	 */
	if (lock_flag) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			/* Skip hosts we get in the next loop */
			if (strinlst(nd->nd_nodename, node_c, node_v)) {
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
		for (i = 0; i < node_c; i++) {
			/* Already verified to be alive */
			if (clnt_unlock_set(node_v[i], cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
		}
	}
	cl_set_setkey(NULL);

	metaflushsetname(sp);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	return (rval);

rollback:
	rval = -1;

	/* level 6 */
	if (rb_level > 5) {
		/*
		 * For each node being deleted, set DEL flag and
		 * reset OK flag on that node first.
		 * Until a node has turned off its own
		 * rpc.metad's NODE_OK flag, that node could be
		 * considered for master during a reconfig.
		 */
		for (i = 0; i < node_c; i++) {
			nd = sd->sd_nodelist;
			/* All nodes are guaranteed to be ALIVE */
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			/* Something wrong, handle this in next loop */
			if (nd == NULL)
				continue;

			/* Only changing my local cache of node list */
			saved_nd_next = nd->nd_next;
			nd->nd_next = NULL;

			/* Set flags for del host to DEL on that host */
			if (clnt_upd_nr_flags(node_v[i], sp,
			    nd, MD_NR_DEL, NULL, &xep)) {
				mdclrerror(&xep);
			}
			nd->nd_next = saved_nd_next;
		}

		for (i = 0; i < node_c; i++) {
			if (dd != NULL) {
				/* Reset master on newly added node */
				if (clnt_mnsetmaster(node_v[i], sp, "",
				    MD_MN_INVALID_NID, &xep))
					mdclrerror(&xep);
				/* Withdraw set on newly added node */
				if (clnt_withdrawset(node_v[i], sp, &xep))
					mdclrerror(&xep);
			}
			/*
			 * Turn off owner flag in nodes to be deleted
			 * if there are drives in the set.
			 * Also, turn off NODE_OK and turn on NODE_DEL
			 * for nodes to be deleted.
			 * These flags are used to set the node
			 * record flags in all nodes in the set.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0) {
					if (dd != NULL) {
						nd->nd_flags &= ~MD_MN_NODE_OWN;
					}
					nd->nd_flags |= MD_MN_NODE_DEL;
					nd->nd_flags &= ~MD_MN_NODE_OK;
					break;
				}
				nd = nd->nd_next;
			}
		}

		/*
		 * Now, reset owner and set delete flags for the deleted
		 * nodes on all nodes.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			if (clnt_upd_nr_flags(nd->nd_nodename, sp,
			    sd->sd_nodelist, MD_NR_SET, NULL, &xep)) {
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}

		/*
		 * On each node being deleted, set the set record
		 * to be in DEL state.
		 */
		for (i = 0; i < node_c; i++) {
			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_DEL, &xep)) {
				mdclrerror(&xep);
			}
		}
	}

	/* level 5 */
	if (rb_level > 4) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_delhosts(nd->nd_nodename, sp, node_c,
			    node_v, &xep) == -1)
				mdclrerror(&xep);
			nd = nd->nd_next;
		}
	}

	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send reinit command to mdcommd which forces it to get
	 * fresh set description.  Then send resume.
	 * Nodelist contains all nodes (existing + added).
	 */
	if (suspendall_flag) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		/* Send reinit to nodes in nodelist before addhosts call */
		while (nd) {
			/*
			 * Skip nodes being added if remote sets were not
			 * created since rpc.mdcommd may not be running
			 * on the remote nodes.
			 */
			if ((remote_sets_created == 0) &&
			    (strinlst(nd->nd_nodename, node_c, node_v))) {
				nd = nd->nd_next;
				continue;
			}
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
			 * Skip nodes being added if remote sets were not
			 * created since rpc.mdcommd may not be running
			 * on the remote nodes.
			 */
			if ((remote_sets_created == 0) &&
			    (strinlst(nd->nd_nodename, node_c, node_v))) {
				nd = nd->nd_next;
				continue;
			}
			/*
			 * Resume all classes but class 1 so that lock is held
			 * against meta* commands.
			 * Send resume_all_but_1 to nodes in nodelist
			 * before addhosts call.
			 */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_DONT_RESUME_CLASS1,
			    &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	/* level 4 */
	/* Nodelist may or may not contain nodes being added. */
	if (rb_level > 3 && dd != NULL) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip nodes not being added */
			if (!strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}

			if (del_db_sidenms(sp, nd->nd_nodeid, &xep))
				mdclrerror(&xep);
			nd = nd->nd_next;
		}
	}

	/* level 3 */
	/* Nodelist may or may not contain nodes being added. */
	if (rb_level > 2 && dd != NULL) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip nodes not being added */
			if (!strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}

			if (del_md_sidenms(sp, nd->nd_nodeid, &xep))
				mdclrerror(&xep);
			nd = nd->nd_next;
		}
	}

	/* level 1 */
	if (rb_level > 0) {
		if (dd != NULL) {
			/* delete the drive records */
			for (i = 0; i < node_c; i++) {
				if (clnt_deldrvs(node_v[i], sp, dd, &xep) == -1)
					mdclrerror(&xep);
			}
		}

		/* delete the set record */
		for (i = 0; i < node_c; i++) {
			if (clnt_delset(node_v[i], sp, &xep) == -1)
				mdclrerror(&xep);
		}
	}

	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	/* Don't test lock flag since guaranteed to be set if in rollback */
	/* Nodelist may or may not contain nodes being added. */
	/*
	 * Unlock diskset by resuming messages across the diskset.
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag)) {
		/* All nodes are guaranteed to be ALIVE */
		nd = sd->sd_nodelist;
		while (nd) {
			/*
			 * Skip nodes being added since remote sets
			 * were either created and then deleted or
			 * were never created.  Either way - rpc.mdcommd
			 * may not be running on the remote node.
			 */
			if (strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename,
			    COMMDCTL_RESUME, sp, MD_MSG_CLASS0,
			    MD_MSCF_NO_FLAGS, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}
	nd = sd->sd_nodelist;
	/* All nodes are guaranteed to be ALIVE */
	while (nd) {
		/* Skip hosts we get in the next loop */
		if (strinlst(nd->nd_nodename, node_c, node_v)) {
			nd = nd->nd_next;
			continue;
		}

		if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep))
			mdclrerror(&xep);
		nd = nd->nd_next;
	}

	for (i = 0; i < node_c; i++)
		if (clnt_unlock_set(node_v[i], cl_sk, &xep))
			mdclrerror(&xep);
	cl_set_setkey(NULL);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	metaflushsetname(sp);

	return (rval);
}

/*
 * Add host(s) to the traditional diskset provided in sp.
 *	- create set if non-existent.
 */
static int
meta_traditional_set_addhosts(
	mdsetname_t	*sp,
	int		multi_node,
	int		node_c,
	char		**node_v,
	int		auto_take,
	md_error_t	*ep
)
{
	md_set_desc	*sd;
	md_drive_desc	*dd, *p;
	med_rec_t	medr;
	med_rec_t	rb_medr;
	int		rval = 0;
	int		bool;
	int		nodeindex;
	int 		i;
	int		has_set;
	int		numsides;
	sigset_t	oldsigs;
	md_setkey_t	*cl_sk;
	int		rb_level = 0;
	md_error_t	xep = mdnullerror;
	int		max_meds;

	if (nodesuniq(sp, node_c, node_v, ep))
		return (-1);

	if (validate_nodes(sp, node_c, node_v, ep))
		return (-1);

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		if (! mdiserror(ep, MDE_NO_SET))
			return (-1);
		mdclrerror(ep);
		return (create_set(sp, multi_node, node_c, node_v, auto_take,
		    ep));
	}

	/* The auto_take behavior is inconsistent with multiple hosts. */
	if (auto_take || sd->sd_flags & MD_SR_AUTO_TAKE) {
		(void) mddserror(ep, MDE_DS_SINGLEHOST, sp->setno, NULL, NULL,
		    sp->setname);
		return (-1);
	}

	/*
	 * We already have the set.
	 */

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	/*
	 * Perform the required checks for new hosts
	 */
	for (i = 0; i < node_c; i++) {
		if (getnodeside(node_v[i], sd) != MD_SIDEWILD)
			return (mddserror(ep, MDE_DS_NODEINSET, sp->setno,
			    node_v[i], NULL, sp->setname));

		/* Make sure this set name is not used on the other hosts */
		has_set = nodehasset(sp, node_v[i], NHS_N_EQ, ep);
		if (has_set < 0) {
			if (! mdiserror(ep, MDE_NO_SET))
				return (-1);
			/* Keep on truck'n */
			mdclrerror(ep);
		} else if (has_set)
			return (mddserror(ep, MDE_DS_NODEHASSET, sp->setno,
			    node_v[i], NULL, sp->setname));

		if (clnt_setnumbusy(node_v[i], sp->setno, &bool, ep) == -1)
			return (-1);

		if (bool == TRUE)
			return (mddserror(ep, MDE_DS_SETNUMBUSY, sp->setno,
			    node_v[i], NULL, sp->setname));

		if (clnt_setnameok(node_v[i], sp, &bool, ep) == -1)
			return (-1);

		if (bool == FALSE)
			return (mddserror(ep, MDE_DS_SETNAMEBUSY, sp->setno,
			    node_v[i], NULL, sp->setname));

		if (check_setdrvs_againstnode(sp, node_v[i], ep))
			return (-1);
	}

	/* Count the number of occupied slots */
	numsides = 0;
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Count occupied slots */
		if (sd->sd_nodes[i][0] != '\0')
			numsides++;
	}

	/* Make sure the we have space to add the new sides */
	if ((numsides + node_c) > MD_MAXSIDES) {
		(void) mddserror(ep, MDE_DS_SIDENUMNOTAVAIL, sp->setno, NULL,
		    NULL, sp->setname);
		return (-1);
	}

	/* Get drive descriptors for the set */
	if ((dd = metaget_drivedesc(sp, MD_FULLNAME_ONLY, ep)) == NULL)
		if (! mdisok(ep))
			return (-1);

	/* Setup the mediator record roll-back structure */
	(void) memset(&rb_medr, '\0', sizeof (med_rec_t));
	rb_medr.med_rec_mag = MED_REC_MAGIC;
	rb_medr.med_rec_rev = MED_REC_REV;
	rb_medr.med_rec_fl  = 0;
	rb_medr.med_rec_sn  = sp->setno;
	(void) strcpy(rb_medr.med_rec_snm, sp->setname);
	for (i = 0; i < MD_MAXSIDES; i++)
		(void) strcpy(rb_medr.med_rec_nodes[i], sd->sd_nodes[i]);
	rb_medr.med_rec_meds = sd->sd_med;	/* structure assigment */
	(void) memset(&rb_medr.med_rec_data, '\0', sizeof (med_data_t));
	rb_medr.med_rec_foff = 0;
	crcgen(&rb_medr, &rb_medr.med_rec_cks, sizeof (med_rec_t), NULL);

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	/* END CHECK CODE */

	md_rb_sig_handling_on();

	/* Lock the set on current set members */
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
			rval = -1;
			goto out;
		}
	}

	/* Lock the set on new set members */
	for (i = 0; i < node_c; i++) {
		if (clnt_lock_set(node_v[i], sp, ep)) {
			rval = -1;
			goto out;
		}
	}

	RB_TEST(1, "addhosts", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "addhosts", ep)

	/*
	 * Add the new hosts to the existing set record on the existing hosts
	 */
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		if (clnt_addhosts(sd->sd_nodes[i], sp, node_c, node_v, ep))
			goto rollback;
	}

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(3, "addhosts", ep);

	/* Merge the new entries into the set with the existing sides */
	nodeindex = 0;
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip full slots */
		if (sd->sd_nodes[i][0] != '\0')
			continue;

		(void) strcpy(sd->sd_nodes[i], node_v[nodeindex++]);
		if (nodeindex == node_c)
			break;
	}

	/* If we have drives */
	if (dd != NULL) {
		/*
		 * For all the hosts being added, create a sidename structure
		 */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip nodes not being added */
			if (! strinlst(sd->sd_nodes[i], node_c, node_v))
				continue;

			for (p = dd; p != NULL; p = p->dd_next) {
				if (make_sideno_sidenm(sp, p->dd_dnp, i,
				    ep) != 0)
					goto rollback;
			}
		}

		/*
		 * Add the new sidename for each drive to the existing hosts
		 */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip nodes being added */
			if (strinlst(sd->sd_nodes[i], node_c, node_v))
				continue;

			if (clnt_add_drv_sidenms(sd->sd_nodes[i], mynode(), sp,
			    sd, node_c, node_v, ep)) {
				goto rollback;
			}
		}

		RB_TEST(4, "addhosts", ep)

		RB_PREEMPT;
		rb_level = 3;	/* level 3 */

		RB_TEST(5, "addhosts", ep)

		if (add_db_sidenms(sp, ep)) {
			goto rollback;
		}

	} else {
		RB_PREEMPT;
		rb_level = 3;
	}

	RB_TEST(6, "addhosts", ep)

	RB_PREEMPT;
	rb_level = 4;	/* level 4 */

	RB_TEST(7, "addhosts", ep)


	/* create the set on the new nodes, this adds the drives as well */
	if (create_set_on_hosts(sp, multi_node, node_c, node_v, 0, ep)) {
		goto rollback;
	}

	RB_TEST(8, "addhosts", ep)

	RB_PREEMPT;
	rb_level = 5;	/* level 5 */

	RB_TEST(9, "addhosts", ep)

	if (dd != NULL) {

		/*
		 * Add the device entries for the new sides into the namespace.
		 */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip nodes not being added */
			if (! strinlst(sd->sd_nodes[i], node_c, node_v))
				continue;

			if (add_md_sidenms(sp, i, MD_SIDEWILD, ep))
				goto rollback;
		}
	}

	RB_TEST(10, "addhosts", ep)

	RB_PREEMPT;
	rb_level = 6;	/* level 6 */

	RB_TEST(11, "addhosts", ep);

	if (dd != NULL) {
		/*
		 * Mark the drives MD_DR_OK.
		 */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_upd_dr_flags(sd->sd_nodes[i], sp, dd,
			    MD_DR_OK, ep) == -1) {
				goto rollback;
			}
		}
	}

	RB_TEST(12, "addhosts", ep)

	/* Bring the mediator record up to date with the set record */
	medr = rb_medr;				/* structure assignment */
	for (i = 0; i < MD_MAXSIDES; i++)
		(void) strcpy(medr.med_rec_nodes[i], sd->sd_nodes[i]);
	crcgen(&medr, &medr.med_rec_cks, sizeof (med_rec_t), NULL);

	/* Inform the mediator hosts of the new node list */
	for (i = 0; i < max_meds; i++) {
		if (sd->sd_med.n_lst[i].a_cnt == 0)
			continue;

		if (clnt_med_upd_rec(&sd->sd_med.n_lst[i], sp, &medr, ep))
			goto rollback;
	}

	/* Add the mediator information to all hosts in the set */
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		if (clnt_updmeds(sd->sd_nodes[i], sp, &sd->sd_med, ep))
			goto rollback;
	}

	RB_TEST(13, "addhosts", ep)

	/*
	 * Mark the set record MD_SR_OK
	 */
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		if (clnt_upd_sr_flags(sd->sd_nodes[i], sp, MD_SR_OK, ep))
			goto rollback;
	}

	RB_TEST(14, "addhosts", ep)

out:
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		/* Skip hosts we get in the next loop */
		if (strinlst(sd->sd_nodes[i], node_c, node_v))
			continue;

		if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep)) {
			if (rval == 0)
				(void) mdstealerror(ep, &xep);
			rval = -1;
		}
	}

	if (rval == 0) {
		for (i = 0; i < node_c; i++)
			if (clnt_unlock_set(node_v[i], cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
	}
	cl_set_setkey(NULL);

	metaflushsetname(sp);

	md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	return (rval);

rollback:
	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	rval = -1;

	/* level 6 */
	if (rb_level > 5) {
		for (i = 0; i < max_meds; i++) {
			if (sd->sd_med.n_lst[i].a_cnt == 0)
				continue;

			if (clnt_med_upd_rec(&sd->sd_med.n_lst[i], sp,
			    &rb_medr, &xep))
				mdclrerror(&xep);
		}
		if (dd != NULL) {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/* Skip nodes not being added */
				if (! strinlst(sd->sd_nodes[i], node_c, node_v))
					continue;

				if (del_md_sidenms(sp, i, &xep))
					mdclrerror(&xep);
			}
		}
	}

	/* level 5 */
	if (rb_level > 4) {
		if (dd != NULL) {
			/* delete the drive records */
			for (i = 0; i < node_c; i++) {
				if (clnt_deldrvs(node_v[i], sp, dd, &xep) == -1)
					mdclrerror(&xep);
			}
		}
		/* delete the set record on the 'new' hosts */
		for (i = 0; i < node_c; i++) {
			if (clnt_delset(node_v[i], sp, &xep) == -1)
				mdclrerror(&xep);
		}
	}

	/* level 4 */
	if (rb_level > 3 && dd != NULL) {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip nodes not being added */
			if (! strinlst(sd->sd_nodes[i], node_c, node_v))
				continue;

			if (del_db_sidenms(sp, i, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 3 */
	if (rb_level > 2 && dd != NULL) {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip nodes not being added */
			if (! strinlst(sd->sd_nodes[i], node_c, node_v))
				continue;

			if (clnt_del_drv_sidenms(sd->sd_nodes[i], sp,
			    &xep) == -1)
				mdclrerror(&xep);
		}
	}

	/* level 2 */
	if (rb_level > 1) {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_delhosts(sd->sd_nodes[i], sp, node_c, node_v,
			    &xep) == -1)
				mdclrerror(&xep);
		}
	}

	/* level 1 */
	if (rb_level > 0) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip hosts we get in the next loop */
			if (strinlst(sd->sd_nodes[i], node_c, node_v))
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep))
				mdclrerror(&xep);
		}

		for (i = 0; i < node_c; i++)
			if (clnt_unlock_set(node_v[i], cl_sk, &xep))
				mdclrerror(&xep);
		cl_set_setkey(NULL);
	}

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	metaflushsetname(sp);

	md_rb_sig_handling_off(md_got_sig(), md_which_sig());

	return (rval);
}

/*
 * Add host(s) to the diskset provided in sp.
 * 	- create set if non-existent.
 */
int
meta_set_addhosts(
	mdsetname_t	*sp,
	int		multi_node,
	int		node_c,
	char		**node_v,
	int		auto_take,
	md_error_t	*ep
)
{
	if (multi_node)
		return (meta_multinode_set_addhosts(sp, multi_node, node_c,
		    node_v, auto_take, ep));
	else
		return (meta_traditional_set_addhosts(sp, multi_node, node_c,
		    node_v, auto_take, ep));
}

/*
 * Delete host(s) from the diskset provided in sp.
 * 	- destroy set if last host in set is removed.
 */
int
meta_set_deletehosts(
	mdsetname_t		*sp,
	int			node_c,
	char			**node_v,
	int			forceflg,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	md_drive_desc		*dd;
	med_rec_t		medr;
	med_rec_t		rb_medr;
	int			i, j;
	int			has_set;
	int			numsides = 0;
	int			oha = FALSE;
	sigset_t		oldsigs;
	mhd_mhiargs_t		mhiargs;
	md_replicalist_t	*rlp = NULL;
	md_setkey_t		*cl_sk;
	ulong_t			max_genid = 0;
	int			rval = 0;
	int			rb_level = 0;
	int			max_meds = 0;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;
	md_mnnode_record	*nr;
	int			delete_master = 0;
	int			suspendall_flag = 0, suspendall_flag_rb = 0;
	int			suspend1_flag = 0;
	int			lock_flag = 0;
	int			stale_flag = 0;
	int			*node_id_list = NULL;
	int			remote_sets_deleted = 0;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/*
	 * Verify that list of nodes being deleted contains no
	 * duplicates.
	 */
	if (nodesuniq(sp, node_c, node_v, ep))
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
	 * diskset are ALIVE (i.e. are in the API membership list) if the
	 * forceflag is FALSE.  (The case of forceflag being TRUE is handled
	 * in OHA check above.)
	 *
	 * If forceflag is FALSE and a node in the diskset is not in
	 * the membership list, then fail this operation since all nodes must
	 * be ALIVE in order to delete the node record from their local mddb.
	 * If a panic of this node leaves the local mddbs set, node and drive
	 * records out-of-sync, the reconfig cycle will fix the local mddbs
	 * and force them back into synchronization.
	 */
	if ((forceflg == FALSE) && (MD_MNSET_DESC(sd))) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				return (mddserror(ep, MDE_DS_NOTINMEMBERLIST,
				    sp->setno, nd->nd_nodename,
				    NULL, sp->setname));
			}
			nd = nd->nd_next;
		}
	}


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
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
				rval = -1;
				goto out2;
			}
			lock_flag = 1;
			nd = nd->nd_next;
		}
		/*
		 * Lock out other meta* commands by suspending
		 * class 1 messages across the diskset.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename,
			    COMMDCTL_SUSPEND, sp, MD_MSG_CLASS1,
			    MD_MSCF_NO_FLAGS, ep)) {
				rval = -1;
				goto out2;
			}
			suspend1_flag = 1;
			nd = nd->nd_next;
		}
	}

	for (i = 0; i < node_c; i++)
		if (getnodeside(node_v[i], sd) == MD_SIDEWILD) {
			(void) mddserror(ep, MDE_DS_NODENOTINSET, sp->setno,
			    node_v[i], NULL, sp->setname);
			rval = -1;
			goto out2;
		}

	/*
	 * Count the number of nodes currently in the set.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			numsides++;
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++)
			/* Count full slots */
			if (sd->sd_nodes[i][0] != '\0')
				numsides++;
	}

	/*
	 * OHA mode == -f -h <hostname>
	 * OHA is One Host Administration that occurs when the forceflag (-f)
	 * is set and at least one host in the diskset isn't responding
	 * to RPC requests.
	 *
	 * When in OHA mode, a node cannot delete itself from a diskset.
	 * When in OHA mode, a node can delete a list of nodes from a diskset
	 * even if some of the nodes in the diskset are unresponsive.
	 *
	 * For multinode diskset, only allow OHA mode when the nodes that
	 * aren't responding in the diskset are not in the membership list
	 * (i.e. nodes that aren't responding are not marked ALIVE).
	 * Nodes that aren't in the membership list will be rejoining
	 * the diskset through a reconfig cycle and the local mddb set
	 * and node records can be reconciled during the reconfig cycle.
	 *
	 * If a node isn't responding, but is still in the membership list,
	 * fail the request since the node may not be responding because
	 * rpc.metad died and is restarting.  In this case, no reconfig
	 * cycle will be started, so there's no way to recover if
	 * the host delete operation was allowed.
	 *
	 * NOTE: if nodes that weren't in the membership when the OHA host
	 * delete occurred are now the only nodes in membership list,
	 * those nodes will see the old view of the diskset.  As soon as
	 * a node re-enters the cluster that was present in the cluster
	 * during the host deletion, the diskset will reflect the host
	 * deletion on all nodes presently in the cluster.
	 */
	if (forceflg == TRUE) {
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/*
				 * If a node isn't ALIVE (in member list),
				 * then allow a force-able delete in OHA mode.
				 */
				if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
					oha = TRUE;
					break;
				}
				/*
				 * Don't test for clnt_nullproc since already
				 * tested the RPC connections by clnt_lock_set.
				 */
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_nullproc(sd->sd_nodes[i], ep) == -1) {
					/*
					 * If we timeout to at least one
					 * client, then we can allow OHA mode,
					 * otherwise, we are in normal mode.
					 */
					if (mdanyrpcerror(ep)) {
						mdclrerror(ep);
						if (strinlst(sd->sd_nodes[i],
						    node_c, node_v)) {
							oha = TRUE;
							break;
						}
					}
				}
			}
		}
	}

	/*
	 * Don't allow this for MN diskset since meta_set_destroy of 1 node
	 * does NOT remove this node's node record from the other node's set
	 * records in their local mddb.  This leaves a MN diskset in a very
	 * messed up state.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		/* Destroy set */
		if (forceflg == TRUE && node_c == 1 &&
		    strcmp(mynode(), node_v[0]) == 0) {
			/* Can return since !MN diskset so nothing to unlock */
			return (meta_set_destroy(sp, TRUE, ep));
		}
	}


	/*
	 * In multinode diskset, can only delete self if this
	 * is the last node in the set or if all nodes in
	 * the set are being deleted.  The traditional diskset code
	 * allows a node to delete itself (when there are other nodes
	 * in the diskset) when using the force flag, but that code
	 * path doesn't have the node remove itself from
	 * the set node list on the other nodes.  Since this isn't
	 * satisfactory for the multinode diskset, just don't
	 * allow this operation.
	 */
	if (MD_MNSET_DESC(sd) && (numsides > 1) && (node_c != numsides) &&
	    strinlst(mynode(), node_c, node_v)) {
		(void) mddserror(ep, MDE_DS_MNCANTDELSELF, sp->setno,
		    mynode(), NULL, sp->setname);
		rval = -1;
		goto out2;
	}

	/*
	 * In multinode diskset, don't allow deletion of master node unless
	 * this is the only node left or unless all nodes are being
	 * deleted since there is no way to switch
	 * master ownership (unless via a cluster reconfig cycle).
	 */
	delete_master = strinlst(sd->sd_mn_master_nodenm, node_c, node_v);
	if (MD_MNSET_DESC(sd) && (numsides > 1) && (node_c != numsides) &&
	    delete_master) {
		(void) mddserror(ep, MDE_DS_CANTDELMASTER, sp->setno,
		    sd->sd_mn_master_nodenm, NULL, sp->setname);
		rval = -1;
		goto out2;
	}


	/* Deleting self w/o forceflg */
	if (forceflg == FALSE && numsides > 1 &&
	    strinlst(mynode(), node_c, node_v)) {
		(void) mddserror(ep, MDE_DS_CANTDELSELF, sp->setno,
		    mynode(), NULL, sp->setname);
		rval = -1;
		goto out2;
	}

	/*
	 * Setup the mediator record roll-back structure for a trad diskset.
	 *
	 * For a MN diskset, the deletion of a host in the diskset
	 * does not cause an update of the mediator record.  If the
	 * host deletion will cause the diskset to be removed (this is
	 * the last host being removed or all hosts are being removed)
	 * then the mediator record must have already been removed by the
	 * user or this delete host operation will fail (a check for
	 * this is done later in this routine).
	 */
	if (!(MD_MNSET_DESC(sd))) {
		(void) memset(&rb_medr, '\0', sizeof (med_rec_t));
		rb_medr.med_rec_mag = MED_REC_MAGIC;
		rb_medr.med_rec_rev = MED_REC_REV;
		rb_medr.med_rec_fl = 0;
		rb_medr.med_rec_sn  = sp->setno;
		(void) strcpy(rb_medr.med_rec_snm, sp->setname);
		for (i = 0; i < MD_MAXSIDES; i++)
			(void) strcpy(rb_medr.med_rec_nodes[i],
			    sd->sd_nodes[i]);
		rb_medr.med_rec_meds = sd->sd_med;  /* structure assigment */
		(void) memset(&rb_medr.med_rec_data, '\0', sizeof (med_data_t));
		rb_medr.med_rec_foff = 0;
		crcgen(&rb_medr, &rb_medr.med_rec_cks,
		    sizeof (med_rec_t), NULL);

		/* Bring the mediator record up to date with the set record */
		medr = rb_medr;			/* structure assignment */

		if ((max_meds = get_max_meds(ep)) == 0) {
			rval = -1;
			goto out2;
		}
	}

	/*
	 * For traditional diskset:
	 * Check to see if all the hosts we are trying to delete the set from
	 * have a set "setname" that is the same as ours, i.e. - same name,
	 * same time stamp, same genid.  We only do this if forceflg is not
	 * specified or we are in OHA mode.
	 */
	if (!(MD_MNSET_DESC(sd)) && (forceflg == FALSE || oha == TRUE)) {
		int	fix_node_v = FALSE;
		int	j;

		for (i = 0; i < node_c; i++) {
			/* We skip this side */
			if (strcmp(mynode(), node_v[i]) == 0)
				continue;

			has_set = nodehasset(sp, node_v[i], NHS_NSTG_EQ, ep);

			if (has_set < 0) {
				char	 *anode[1];

				/*
				 * Can't talk to the host only allowed in OHA
				 * mode.
				 */
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}

				/*
				 * We got an error we do not, or are not,
				 * prepared to handle.
				 */
				if (! mdiserror(ep, MDE_NO_SET) &&
				    ! mdismddberror(ep, MDE_DB_NODB)) {
					rval = -1;
					goto out2;
				}
				mdclrerror(ep);

				/*
				 * If we got here: both hosts are up; a host in
				 * our set record does not have the set. So we
				 * delete the host from our set and invalidate
				 * the node.
				 */
				anode[0] = Strdup(node_v[i]);

				rval = del_host_noset(sp, anode, ep);

				/*
				 * If we delete a host, make sure the mediator
				 * hosts are made aware of this.
				 */
				for (j = 0; j < MD_MAXSIDES; j++) {
					if (strcmp(medr.med_rec_nodes[j],
					    node_v[i]) != 0)
						continue;
					(void) memset(&medr.med_rec_nodes[j],
					    '\0', sizeof (md_node_nm_t));
				}
				crcgen(&medr, &medr.med_rec_cks,
				    sizeof (med_rec_t), NULL);

				rb_medr = medr;		/* struct assignment */

				Free(anode[0]);

				if (rval == -1)
					goto out2;

				node_v[i][0] = '\0';
				fix_node_v = TRUE;
				continue;
			}

			/*
			 * If we can talk to the host, and they do not have the
			 * exact set, then we disallow the operation.
			 */
			if (has_set == FALSE) {
				(void) mddserror(ep, MDE_DS_NODENOSET,
				    sp->setno, node_v[i], NULL, sp->setname);
				rval = -1;
				goto out2;
			}
		}

		/*
		 * Here we prune the node_v's that were invalidated above.
		 */
		if (fix_node_v == TRUE) {
			i = 0;
			while (i < node_c) {
				if (node_v[i][0] == '\0') {
					for (j = i; (j + 1) < node_c; j++)
						node_v[j] = node_v[j + 1];
					node_c--;
				}
				i++;
			}
			/*
			 * If we are left with no nodes, then we have
			 * compeleted the operation.
			 */
			if (node_c == 0) {
				/*
				 * Inform the mediator hosts of the new node
				 * list
				 */
				for (i = 0; i < max_meds; i++) {
					if (sd->sd_med.n_lst[i].a_cnt == 0)
						continue;

					if (clnt_med_upd_rec(
					    &sd->sd_med.n_lst[i], sp, &medr,
					    ep))
						mdclrerror(ep);
				}
				rval = 0;
				goto out2;
			}
		}
	}

	/*
	 * For multinode diskset:
	 * If forceflag is FALSE then check to see if all the hosts we
	 * are trying to delete the set from have a set "setname" that
	 * is the same as ours, i.e. - same name, same time stamp, same genid.
	 * If forceflag is TRUE, then we don't care if the hosts being
	 * deleted have the same set information or not since user is forcing
	 * those hosts to be deleted.
	 */
	if ((MD_MNSET_DESC(sd)) && (forceflg == FALSE)) {
		for (i = 0; i < node_c; i++) {
			/* We skip this node since comparing against it */
			if (strcmp(mynode(), node_v[i]) == 0)
				continue;

			has_set = nodehasset(sp, node_v[i], NHS_NSTG_EQ, ep);

			if (has_set < 0) {
				rval = -1;
				goto out2;
			}

			/*
			 * If we can talk to the host, and they do not have the
			 * exact set, then we disallow the operation.
			 */
			if (has_set == FALSE) {
				(void) mddserror(ep, MDE_DS_NODENOSET,
				    sp->setno, node_v[i], NULL, sp->setname);
				rval = -1;
				goto out2;
			}
		}
	}

	/*
	 * For traditional diskset:
	 * Can't allow user to delete their node (without deleting all nodes)
	 * out of a set in OHA mode, would leave a real mess.
	 * This action was already failed above for a MN diskset.
	 */
	if (!(MD_MNSET_DESC(sd)) && (oha == TRUE) &&
	    strinlst(mynode(), node_c, node_v)) {
		/* Can directly return since !MN diskset; nothing to unlock */
		return (mddserror(ep, MDE_DS_OHACANTDELSELF, sp->setno,
		    mynode(), NULL, sp->setname));
	}


	/* Get the drive descriptors for this set */
	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) {
		if (! mdisok(ep)) {
			rval = -1;
			goto out2;
		}
	}

	/*
	 * We have been asked to delete all the hosts in the set, i.e. - delete
	 * the whole set.
	 */
	if (node_c == numsides) {
		/*
		 * This is only a valid operation if all drives have been
		 * removed first.
		 */

		if (dd != NULL) {
			(void) mddserror(ep, MDE_DS_HASDRIVES, sp->setno,
			    NULL, NULL, sp->setname);
			rval = -1;
			goto out2;
		}

		/*
		 * If a mediator is currently associated with this set,
		 * fail the deletion of the last host(s).
		 */
		if (sd->sd_med.n_cnt != 0) {
			(void) mddserror(ep, MDE_DS_HASMED, sp->setno,
			    NULL, NULL, sp->setname);
			rval = -1;
			goto out2;
		}

		if (! mdisok(ep)) {
			rval = -1;
			goto out2;
		}

		rval = del_set_nodrives(sp, node_c, node_v, oha, ep);
		remote_sets_deleted = 1;
		goto out2;
	}

	/*
	 * Get timeout values in case we need to roll back
	 */
	(void) memset(&mhiargs, '\0', sizeof (mhiargs));
	if (clnt_gtimeout(mynode(), sp, &mhiargs, ep) != 0) {
		rval = -1;
		goto out2;
	}

	if (dd != NULL) {
		/*
		 * We need this around for re-adding DB side names later.
		 */
		if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) < 0) {
			rval = -1;
			goto out2;
		}

		/*
		 * Alloc nodeid list if drives are present in diskset.
		 * nodeid list is used to reset mirror owners if the
		 * owner is a deleted node.
		 */
		if (MD_MNSET_DESC(sd)) {
			node_id_list = Zalloc(sizeof (int) * node_c);
		}
	}

	/* Lock the set on current set members */
	if (!(MD_MNSET_DESC(sd))) {
		md_rb_sig_handling_on();
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				rval = -1;
				goto out2;
			}
			lock_flag = 1;
		}
	}

	RB_TEST(1, "deletehosts", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "deletehosts", ep)

	if (MD_MNSET_DESC(sd)) {
		md_mnnode_desc		*saved_nd_next;
		mddb_config_t		c;

		if (dd != NULL) {
			/*
			 * Notify rpc.mdcommd on all nodes of a nodelist change.
			 * Start by suspending rpc.mdcommd (which drains it of
			 * all messages), then change the nodelist followed
			 * by a reinit and resume.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
					nd = nd->nd_next;
					continue;
				}
				if (clnt_mdcommdctl(nd->nd_nodename,
				    COMMDCTL_SUSPEND, sp,
				    MD_MSG_CLASS0,
				    MD_MSCF_NO_FLAGS, ep)) {
					rval = -1;
					goto out2;
				}
				suspendall_flag = 1;
				nd = nd->nd_next;
			}
			/*
			 * Is current set STALE?
			 * Need to know this if delete host fails and node
			 * is re-joined to diskset.
			 */
			(void) memset(&c, 0, sizeof (c));
			c.c_id = 0;
			c.c_setno = sp->setno;
			if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
				(void) mdstealerror(ep, &c.c_mde);
				rval = -1;
				goto out2;
			}
			if (c.c_flags & MDDB_C_STALE) {
				stale_flag = MNSET_IS_STALE;
			}
		}

		/*
		 * For each node being deleted, set DEL flag and
		 * reset OK flag on that node first.
		 * Until a node has turned off its own
		 * rpc.metad's NODE_OK flag, that node could be
		 * considered for master during a reconfig.
		 */
		for (i = 0; i < node_c; i++) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0)
					break;
				nd = nd->nd_next;
			}
			/* Something wrong, handle this in next loop */
			if (nd == NULL)
				continue;

			/* If node_id_list is alloc'd, fill in for later use */
			if (node_id_list)
				node_id_list[i] = nd->nd_nodeid;

			/* All nodes are guaranteed to be ALIVE unless OHA */
			if ((oha == TRUE) &&
			    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
				continue;
			}

			/* Only changing my local cache of node list */
			saved_nd_next = nd->nd_next;
			nd->nd_next = NULL;

			/* Set flags for del host to DEL on that host */
			if (clnt_upd_nr_flags(node_v[i], sp,
			    nd, MD_NR_DEL, NULL, ep)) {
				nd->nd_next = saved_nd_next;
				goto rollback;
			}
			nd->nd_next = saved_nd_next;
		}
		for (i = 0; i < node_c; i++) {
			/*
			 * Turn off owner flag in nodes to be deleted
			 * if this node has been joined.
			 * Also, turn off NODE_OK and turn on NODE_DEL
			 * for nodes to be deleted.
			 * These flags are used to set the node
			 * record flags in all nodes in the set.
			 * Only withdraw nodes that are joined.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				/*
				 * Don't communicate with non-ALIVE node if
				 * in OHA - but set flags in master list so
				 * alive nodes are updated correctly.
				 */
				if (strcmp(nd->nd_nodename, node_v[i]) == 0) {
					if ((oha == TRUE) && (!(nd->nd_flags &
					    MD_MN_NODE_ALIVE))) {
						nd->nd_flags |= MD_MN_NODE_DEL;
						nd->nd_flags &= ~MD_MN_NODE_OK;
						nd = nd->nd_next;
						continue;
					}
					if (nd->nd_flags & MD_MN_NODE_OWN) {
						/*
						 * Going to set locally cached
						 * node flags to rollback join
						 * so in case of error, the
						 * rollback code knows which
						 * nodes to re-join.  rpc.metad
						 * ignores the RB_JOIN flag.
						 */
						nd->nd_flags |=
						    MD_MN_NODE_RB_JOIN;
						nd->nd_flags &= ~MD_MN_NODE_OWN;

						/*
						 * Be careful in ordering of
						 * following steps so that
						 * recovery from a panic
						 * between the steps is viable.
						 * Only reset master info in
						 * rpc.metad - don't reset
						 * local cached info which will
						 * be used to set master info
						 * back if failure (rollback).
						 */
						if (clnt_withdrawset(
						    nd->nd_nodename, sp, ep))
							goto rollback;

						/*
						 * Reset master on deleted node
						 */
						if (clnt_mnsetmaster(node_v[i],
						    sp, "", MD_MN_INVALID_NID,
						    ep))
							goto rollback;
					}

					nd->nd_flags |= MD_MN_NODE_DEL;
					nd->nd_flags &= ~MD_MN_NODE_OK;
				}
				nd = nd->nd_next;
			}
		}

		/*
		 * Now, reset owner and set delete flags for the
		 * deleted nodes on all nodes.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip non-ALIVE node if in OHA */
			if ((oha == TRUE) &&
			    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_upd_nr_flags(nd->nd_nodename, sp,
			    sd->sd_nodelist, MD_NR_SET, NULL, ep)) {
				goto rollback;
			}
			nd = nd->nd_next;
		}
		/*
		 * Notify rpc.mdcommd on all nodes of a nodelist change.
		 * Send reinit command to mdcommd which forces it to get
		 * fresh set description.
		 */
		if (suspendall_flag) {
			/* Send reinit */
			nd = sd->sd_nodelist;
			while (nd) {
				if ((oha == TRUE) &&
				    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
					nd = nd->nd_next;
					continue;
				}
				/* Class is ignored for REINIT */
				if (clnt_mdcommdctl(nd->nd_nodename,
				    COMMDCTL_REINIT, sp, NULL,
				    MD_MSCF_NO_FLAGS, ep)) {
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to reinit rpc.mdcommd.\n"));
					goto rollback;
				}
				nd = nd->nd_next;
			}
			/* Send resume */
			nd = sd->sd_nodelist;
			while (nd) {
				if ((oha == TRUE) &&
				    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
					nd = nd->nd_next;
					continue;
				}
				if (clnt_mdcommdctl(nd->nd_nodename,
				    COMMDCTL_RESUME, sp, MD_MSG_CLASS0,
				    MD_MSCF_DONT_RESUME_CLASS1, ep)) {
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to resume rpc.mdcommd.\n"));
					goto rollback;
				}
				nd = nd->nd_next;
			}
			meta_ping_mnset(sp->setno);
		}
	}


	/*
	 * Mark the set record MD_SR_DEL on the hosts we are deleting
	 * If a MN diskset and OHA mode, don't issue RPC to nodes that
	 * are not ALIVE.
	 * If a MN diskset and not in OHA mode, then all nodes must respond
	 * to RPC (be alive) or this routine will return failure.
	 * If a traditional diskset, all RPC failures if in OHA mode.
	 */
	for (i = 0; i < node_c; i++) {

		RB_TEST(3, "deletehosts", ep)

		if ((MD_MNSET_DESC(sd)) && (oha == TRUE)) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i]) == 0) {
					break;
				}
				nd = nd->nd_next;
			}
			if (nd == NULL) {
				(void) mddserror(ep, MDE_DS_NODENOTINSET,
				    sp->setno, node_v[i], NULL, sp->setname);
				goto rollback;
			} else if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				/* Skip non-ALIVE node if in OHA mode */
				continue;
			} else {
				if (clnt_upd_sr_flags(node_v[i], sp,
				    MD_SR_DEL, ep)) {
					goto rollback;
				}
			}
		} else if ((MD_MNSET_DESC(sd)) && (oha == FALSE)) {
			/*
			 * All nodes should be alive in non-oha mode.
			 */
			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_DEL, ep)) {
				goto rollback;
			}
		} else {
			/*
			 * For traditional diskset, issue the RPC and
			 * ignore RPC failure if in OHA mode.
			 */
			if (clnt_upd_sr_flags(node_v[i], sp, MD_SR_DEL, ep)) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}
		}

		RB_TEST(4, "deletehosts", ep)
	}

	RB_TEST(5, "deletehosts", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(6, "deletehosts", ep)

	/* Delete the set on the hosts we are deleting */
	if (del_set_on_hosts(sp, sd, dd, node_c, node_v, oha, ep)) {
		if (node_id_list)
			Free(node_id_list);
		/*
		 * Failure during del_set_on_hosts would have recreated
		 * the diskset on the remote hosts, but for multi-owner
		 * disksets need to set node flags properly and REINIT and
		 * RESUME rpc.mdcommd, so just let the rollback code
		 * do this.
		 */
		if (MD_MNSET_DESC(sd))
			goto rollback;
		return (-1);
	}
	remote_sets_deleted = 1;

	RB_TEST(19, "deletehosts", ep)

	RB_PREEMPT;
	rb_level = 3;	/* level 3 */

	RB_TEST(20, "deletehosts", ep)

	/* Delete the host from sets on hosts not being deleted */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE unless in oha mode */
		while (nd) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			if ((oha == TRUE) &&
			    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
				nd = nd->nd_next;
				continue;
			}

			/* Skip nodes being deleted */
			if (strinlst(nd->nd_nodename, node_c, node_v)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_delhosts(nd->nd_nodename, sp, node_c, node_v,
			    ep) == -1) {
				goto rollback;
			}

			RB_TEST(21, "deletehosts", ep)
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip nodes being deleted */
			if (strinlst(sd->sd_nodes[i], node_c, node_v))
				continue;

			if (clnt_delhosts(sd->sd_nodes[i], sp, node_c, node_v,
			    ep) == -1) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}

			RB_TEST(21, "deletehosts", ep)
		}
	}

	/* We have drives */
	if (dd != NULL) {
		RB_TEST(22, "deletehosts", ep)

		RB_PREEMPT;
		rb_level = 4;	/* level 4 */

		RB_TEST(23, "deletehosts", ep)

		/*
		 * Delete the old sidename for each drive on all the hosts.
		 * If a multi-node diskset, each host only stores
		 * the side information for itself.  So, a multi-node
		 * diskset doesn't delete the old sidename for
		 * an old host.
		 *
		 * If a MN diskset, reset owners of mirrors that are
		 * owned by the deleted nodes.
		 */
		if (!(MD_MNSET_DESC(sd))) {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/* Skip nodes being deleted */
				if (strinlst(sd->sd_nodes[i], node_c, node_v))
					continue;

				if (clnt_del_drv_sidenms(sd->sd_nodes[i], sp,
				    ep)) {
					if (oha == TRUE && mdanyrpcerror(ep)) {
						mdclrerror(ep);
						continue;
					}
					metaflushsetname(sp);
					goto rollback;
				}

				RB_TEST(24, "deletehosts", ep)
			}
		} else {
			nd = sd->sd_nodelist;
			/* All nodes guaranteed ALIVE unless in oha mode */
			while (nd) {
				/*
				 * If mirror owner was set to a deleted node,
				 * then each existing node resets mirror owner
				 * to NULL.
				 *
				 * During OHA mode, don't issue RPCs to
				 * non-alive nodes since there is no reason to
				 * wait for RPC timeouts.
				 */
				if ((oha == TRUE) &&
				    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
					nd = nd->nd_next;
					continue;
				}

				/* Skip nodes being deleted */
				if (strinlst(nd->nd_nodename, node_c, node_v)) {
					nd = nd->nd_next;
					continue;
				}

				/*
				 * If mirror owner is a deleted node, reset
				 * mirror owners to NULL.  If an error occurs,
				 * print a warning and continue.  Don't fail
				 * metaset because of mirror owner reset
				 * problem since next node to grab mirror
				 * will resolve this issue.  Before next node
				 * grabs mirrors, metaset will show the deleted
				 * node as owner which is why an attempt to
				 * reset the mirror owner is made.
				 */
				if (clnt_reset_mirror_owner(nd->nd_nodename, sp,
				    node_c, &node_id_list[0], &xep) == -1) {
					mde_perror(&xep, dgettext(TEXT_DOMAIN,
					    "Unable to reset mirror owner on"
					    " node %s\n"), nd->nd_nodename);
					mdclrerror(&xep);
				}

				RB_TEST(21, "deletehosts", ep)
				nd = nd->nd_next;
			}
		}
	}

	RB_TEST(25, "deletehosts", ep)

	RB_PREEMPT;
	rb_level = 4;	/* level 4 */

	RB_TEST(26, "deletehosts", ep)

	/*
	 * Bring the mediator record up to date with the set record for
	 * traditional diskset.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		medr = rb_medr;			/* structure assignment */
		for (i = 0; i < MD_MAXSIDES; i++) {
			if (strinlst(sd->sd_nodes[i], node_c, node_v))
				(void) memset(&medr.med_rec_nodes[i],
				    '\0', sizeof (md_node_nm_t));
			else
				(void) strcpy(medr.med_rec_nodes[i],
				    sd->sd_nodes[i]);
		}
		crcgen(&medr, &medr.med_rec_cks, sizeof (med_rec_t), NULL);

		/* Inform the mediator hosts of the new node list */
		for (i = 0; i < max_meds; i++) {
			if (sd->sd_med.n_lst[i].a_cnt == 0)
				continue;

			if (clnt_med_upd_rec(&sd->sd_med.n_lst[i], sp,
			    &medr, ep)) {
				if (oha == TRUE && mdanyrpcerror(ep)) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}
		}
	}

	RB_TEST(27, "deletehosts", ep)

	/*
	 * For traditional diskset:
	 * We are deleting ourselves out of the set and we have drives to
	 * consider; so we need to halt the set, release the drives and
	 * reset the timeout.  **** THIS IS A ONE WAY TICKET, NO ROLL BACK
	 * IS POSSIBLE AS SOON AS THE HALT SET COMPLETES, SO THIS IS DONE
	 * WITH ALL SIGNALS BLOCKED AND LAST ****
	 *
	 * This situation cannot occur in a MN diskset since a node can't
	 * delete itself unless all nodes are being deleted and a diskset
	 * cannot contain any drives if all nodes are being deleted.
	 * So, don't even test for this if a MN diskset.
	 */
	if (!(MD_MNSET_DESC(sd)) && (dd != NULL) &&
	    strinlst(mynode(), node_c, node_v)) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, ep) < 0) {
			rval = -1;
			goto out1;
		}

		if (halt_set(sp, ep)) {
			rval = -1;
			goto out1;
		}

		if (rel_own_bydd(sp, dd, FALSE, ep))
			rval = -1;

out1:
		/* release signals back to what they were on entry */
		if (procsigs(FALSE, &oldsigs, &xep) < 0) {
			if (rval == 0)
				(void) mdstealerror(ep, &xep);
			rval = -1;
		}
	}

out2:
	/*
	 * Unlock diskset by resuming messages across the diskset.
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag)) {
		/* Send resume */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			/*
			 * Skip nodes being deleted if remote set
			 * was deleted since rpc.mdcommd may no longer
			 * be running on remote node.
			 */
			if ((remote_sets_deleted == 1) &&
			    (strinlst(nd->nd_nodename, node_c, node_v))) {
				nd = nd->nd_next;
				continue;
			}
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

	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (lock_flag) {
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/*
				 * During OHA mode, don't issue RPCs to
				 * non-alive nodes since there is no reason to
				 * wait for RPC timeouts.
				 */
				if ((oha == TRUE) &&
				    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
					nd = nd->nd_next;
					continue;
				}
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
					if (oha == TRUE &&
					    mdanyrpcerror(&xep)) {
						mdclrerror(&xep);
						continue;
					}
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
				}
			}
		}
	}
	cl_set_setkey(NULL);

out3:
	metafreereplicalist(rlp);
	if (node_id_list)
		Free(node_id_list);

	metaflushsetname(sp);

	if (MD_MNSET_DESC(sd)) {
		/* release signals back to what they were on entry */
		if (procsigs(FALSE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	} else {
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}


	return (rval);

rollback:
	/* all signals already blocked for MN disket */
	if (!(MD_MNSET_DESC(sd))) {
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
	}

	rval = -1;

	max_genid = sd->sd_genid;


	/*
	 * Send reinit command to rpc.mdcommd which forces it to get
	 * fresh set description and resume all classes but class 0.
	 * Don't send any commands to rpc.mdcommd if set on that node
	 * has been removed.
	 */
	if (suspendall_flag) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			/*
			 * If the remote set was deleted, rpc.mdcommd
			 * may no longer be running so send nothing to it.
			 */
			if ((remote_sets_deleted == 1) &&
			    (strinlst(nd->nd_nodename, node_c, node_v))) {
				nd = nd->nd_next;
				continue;
			}
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
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			/*
			 * If the remote set was deleted, rpc.mdcommd
			 * may no longer be running so send nothing to it.
			 */
			if ((remote_sets_deleted == 1) &&
			    (strinlst(nd->nd_nodename, node_c, node_v))) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_DONT_RESUME_CLASS1,
			    &xep)) {
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
		md_set_record		*sr;
		md_replicalist_t	*rl;

		recreate_set(sp, sd);

		/*
		 * Lock out other meta* commands on nodes with the newly
		 * re-created sets by suspending class 1 messages
		 * across the diskset.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip nodes not being deleted */
			if (!(strinlst(nd->nd_nodename, node_c, node_v))) {
				nd = nd->nd_next;
				continue;
			}
			/* Suspend commd on nodes with re-created sets */
			if (clnt_mdcommdctl(nd->nd_nodename,
			    COMMDCTL_SUSPEND, sp, MD_MSG_CLASS1,
			    MD_MSCF_NO_FLAGS, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to suspend rpc.mdcommd.\n"));
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}

		max_genid++;

		/*
		 * See if we have to re-add the drives specified.
		 */
		for (i = 0; i < node_c; i++) {
			if (MD_MNSET_DESC(sd) && (oha == TRUE)) {
				/*
				 * During OHA mode, don't issue RPCs to
				 * non-alive nodes since there is no reason to
				 * wait for RPC timeouts.
				 */
				nd = sd->sd_nodelist;
				while (nd) {
					if (strcmp(nd->nd_nodename, node_v[i])
					    == 0) {
						break;
					}
					nd = nd->nd_next;
				}
				if (nd == 0)
					continue;
				if (!(nd->nd_flags & MD_MN_NODE_ALIVE))
					continue;
			}

			/* Don't care if set record is MN or not */
			if (clnt_getset(node_v[i], sp->setname, MD_SET_BAD, &sr,
			    &xep) == -1) {
				mdclrerror(&xep);
				continue;
			}

			/* Drive already added, skip to next node */
			if (sr->sr_drivechain != NULL) {
				/*
				 * Set record structure was allocated from RPC
				 * routine getset so this structure is only of
				 * size md_set_record even if the MN flag is
				 * set.  So, clear the flag so that the free
				 * code doesn't attempt to free a structure
				 * the size of md_mnset_record.
				 */
				sr->sr_flags &= ~MD_SR_MN;
				free_sr(sr);
				continue;
			}

			if (clnt_adddrvs(node_v[i], sp, dd, sr->sr_ctime,
			    sr->sr_genid, &xep) == -1)
				mdclrerror(&xep);

			if (clnt_upd_dr_flags(node_v[i], sp, dd, MD_DR_OK,
			    &xep) == -1)
				mdclrerror(&xep);

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
		}
		max_genid += 3;

		for (rl = rlp; rl != NULL; rl = rl->rl_next) {
			md_replica_t	*r = rl->rl_repp;
			/*
			 * This is not the first replica being added to the
			 * diskset so call with ADDSIDENMS_BCAST.  If this
			 * is a traditional diskset, the bcast flag is ignored
			 * since traditional disksets don't use the rpc.mdcommd.
			 */
			if (meta_db_addsidenms(sp, r->r_namep, r->r_blkno,
			    DB_ADDSIDENMS_BCAST, &xep))
				mdclrerror(&xep);
		}

		/*
		 * Add the device names for the new sides into the namespace,
		 * on all hosts not being deleted.
		 */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* Find a node that is not being deleted */
				if (!strinlst(nd->nd_nodename, node_c,
				    node_v)) {
					j = nd->nd_nodeid;
					break;
				}
				nd = nd->nd_next;
			}
		} else {
			for (j = 0; j < MD_MAXSIDES; j++) {
				/* Skip empty slots */
				if (sd->sd_nodes[j][0] == '\0')
					continue;

				/* Find a node that is not being deleted */
				if (!strinlst(sd->sd_nodes[j], node_c, node_v))
					break;
			}
		}

		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* Skip nodes not being deleted */
				if (!strinlst(nd->nd_nodename, node_c,
				    node_v)) {
					nd = nd->nd_next;
					continue;
				}

				/* this side was just created, add the names */
				if (add_md_sidenms(sp, nd->nd_nodeid, j, &xep))
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/* Skip nodes not being deleted */
				if (!strinlst(sd->sd_nodes[i], node_c, node_v))
					continue;

				/* this side was just created, add the names */
				if (add_md_sidenms(sp, i, j, &xep))
					mdclrerror(&xep);
			}
		}
	}

	/* level 4 */
	if (rb_level > 3 && dd != NULL) {
		/*
		 * Add the new sidename for each drive to all the hosts
		 * Multi-node disksets only store the sidename for
		 * that host, so there is nothing to re-add.
		 */
		if (!(MD_MNSET_DESC(sd))) {
			for (j = 0; j < MD_MAXSIDES; j++) {
				/* Skip empty slots */
				if (sd->sd_nodes[j][0] == '\0')
					continue;

				/* Skip nodes not being deleted */
				if (!strinlst(sd->sd_nodes[j], node_c, node_v))
					break;
			}
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_add_drv_sidenms(sd->sd_nodes[i],
				    sd->sd_nodes[j], sp, sd, node_c, node_v,
				    &xep))
					mdclrerror(&xep);
			}
		}

	}

	/* level 5 */
	if ((rb_level > 4) && (!(MD_MNSET_DESC(sd)))) {
		/* rollback the mediator record */
		for (i = 0; i < max_meds; i++) {
			if (sd->sd_med.n_lst[i].a_cnt == 0)
				continue;

			if (clnt_med_upd_rec(&sd->sd_med.n_lst[i], sp,
			    &rb_medr, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 3 */
	if (rb_level > 2) {
		md_set_record		*sr;
		md_mnset_record		*mnsr;

		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			while (nd) {
				if ((oha == TRUE) &&
				    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
					nd = nd->nd_next;
					continue;
				}
				/* Record should be for a multi-node diskset */
				if (clnt_mngetset(nd->nd_nodename, sp->setname,
				    MD_SET_BAD, &mnsr, &xep) == -1) {
					mdclrerror(&xep);
					nd = nd->nd_next;
					continue;
				}

				has_set = 1;

				nr = mnsr->sr_nodechain;
				while (nr) {
					if (nd->nd_nodeid == nr->nr_nodeid) {
						break;
					}
					nr = nr->nr_next;
				}
				if (nr == NULL)
					has_set = 0;

				free_sr((struct md_set_record *)mnsr);
				if (has_set) {
					nd = nd->nd_next;
					continue;
				}

				if (clnt_addhosts(nd->nd_nodename, sp, node_c,
				    node_v, &xep) == -1)
					mdclrerror(&xep);

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

				has_set = 1;
				for (j = 0; j < MD_MAXSIDES; j++) {
					/* Skip empty slots */
					if (sd->sd_nodes[j][0] == '\0')
						continue;

					if (sr->sr_nodes[j][0] == '\0') {
						has_set = 0;
						break;
					}
				}

				free_sr(sr);
				if (has_set)
					continue;

				if (clnt_addhosts(sd->sd_nodes[i], sp, node_c,
				    node_v, &xep) == -1)
					mdclrerror(&xep);
			}
		}
		max_genid++;
	}

	/* level 1 */
	if (rb_level > 0) {
		max_genid++;
		/* Sets MD_SR_OK on given nodes. */
		resync_genid(sp, sd, max_genid, node_c, node_v);

		/*
		 * For MN diskset:
		 * On each newly re-added node, set the node record for that
		 * node to OK.  Then set all node records for the newly added
		 * nodes on all nodes to ok.
		 *
		 * By setting a node's own node record to ok first, even if
		 * the node re-adding the hosts panics, the rest of the nodes
		 * can determine the same node list during the choosing of the
		 * master during reconfig.  So, only nodes considered for
		 * mastership are nodes that have both MD_MN_NODE_OK and
		 * MD_SR_OK set on that node's rpc.metad.  If all nodes have
		 * MD_SR_OK set, but no node has its own MD_MN_NODE_OK set,
		 * then the set will be removed during reconfig since a panic
		 * occurred during the re-creation of the deletion of
		 * the initial diskset.
		 */
		if (MD_MNSET_DESC(sd)) {
			md_mnnode_desc	*saved_nd_next;
			if (dd != NULL) {
				/*
				 * Notify rpc.mdcommd on all nodes of a
				 * nodelist change.  Start by suspending
				 * rpc.mdcommd (which drains it of all
				 * messages), then change the nodelist
				 * followed by a reinit and resume.
				 */
				nd = sd->sd_nodelist;
				while (nd) {
					if (!(nd->nd_flags &
					    MD_MN_NODE_ALIVE)) {
						nd = nd->nd_next;
						continue;
					}
					if (clnt_mdcommdctl(nd->nd_nodename,
					    COMMDCTL_SUSPEND, sp,
					    MD_MSG_CLASS0,
					    MD_MSCF_NO_FLAGS, &xep)) {
						mde_perror(&xep,
						    dgettext(TEXT_DOMAIN,
						    "Unable to suspend "
						    "rpc.mdcommd.\n"));
						mdclrerror(&xep);
					}
					suspendall_flag_rb = 1;
					nd = nd->nd_next;
				}
			}
			for (i = 0; i < node_c; i++) {
				/*
				 * During OHA mode, don't issue RPCs to
				 * non-alive nodes since there is no reason to
				 * wait for RPC timeouts.
				 */
				nd = sd->sd_nodelist;
				while (nd) {
					if (strcmp(nd->nd_nodename, node_v[i])
					    == 0)
						break;
					nd = nd->nd_next;
				}
				/* Something wrong, finish this in next loop */
				if (nd == NULL)
					continue;

				if ((oha == TRUE) &&
				    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
					continue;
				}

				if (dd != NULL) {
					/* Set master on re-joining node. */
					if (clnt_mnsetmaster(node_v[i], sp,
					    sd->sd_mn_master_nodenm,
					    sd->sd_mn_master_nodeid, &xep)) {
						mdclrerror(&xep);
					}

					/*
					 * Re-join set to same state as
					 * before - stale or non-stale.
					 */
					if (clnt_joinset(node_v[i], sp,
					    stale_flag, &xep)) {
						mdclrerror(&xep);
					}
				}

				/* Only changing my local cache of node list */
				saved_nd_next = nd->nd_next;
				nd->nd_next = NULL;

				/* Set record for host to ok on that host */
				if (clnt_upd_nr_flags(node_v[i], sp,
				    nd, MD_NR_OK, NULL, &xep)) {
					mdclrerror(&xep);
				}
				nd->nd_next = saved_nd_next;
			}

			/* Now set all node records on all nodes to be ok */
			nd = sd->sd_nodelist;
			while (nd) {
				/*
				 * During OHA mode, don't issue RPCs to
				 * non-alive nodes since there is no reason to
				 * wait for RPC timeouts.
				 */
				if ((oha == TRUE) &&
				    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
					nd = nd->nd_next;
					continue;
				}
				if (clnt_upd_nr_flags(nd->nd_nodename, sp,
				    sd->sd_nodelist, MD_NR_OK, NULL, &xep)) {
					mdclrerror(&xep);
				}
				nd = nd->nd_next;
			}
		}
	}

	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send reinit command to mdcommd which forces it to get
	 * fresh set description.
	 */
	if (suspendall_flag_rb) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

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
	 * Unlock diskset by resuming messages across the diskset.
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag) || (suspendall_flag_rb)) {
		/* Send resume */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				mde_perror(&xep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd.\n"));
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	/*
	 * Start a resync thread on the re-added nodes
	 * if set is not stale. Also start a thread to update the
	 * abr state of all soft partitions
	 */
	if (stale_flag != MNSET_IS_STALE) {
		for (i = 0; i < node_c; i++) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (strcmp(nd->nd_nodename, node_v[i])
				    == 0)
					break;
				nd = nd->nd_next;
			}
			if (nd == NULL)
				continue;

			if ((oha == TRUE) &&
			    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
				continue;
			}

			if (dd != 0) {
				if (clnt_mn_mirror_resync_all(node_v[i],
				    sp->setno, &xep)) {
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to start resync "
					    "thread.\n"));
				}
				if (clnt_mn_sp_update_abr(node_v[i],
				    sp->setno, &xep)) {
					mde_perror(ep, dgettext(TEXT_DOMAIN,
					    "Unable to start sp update "
					    "thread.\n"));
				}
			}
		}
	}

	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	/* Don't test lock flag since guaranteed to be set if in rollback */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			/*
			 * During OHA mode, don't issue RPCs to
			 * non-alive nodes since there is no reason to
			 * wait for RPC timeouts.
			 */
			if ((oha == TRUE) &&
			    (!(nd->nd_flags & MD_MN_NODE_ALIVE))) {
				nd = nd->nd_next;
				continue;
			}
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

	metafreereplicalist(rlp);
	if (node_id_list)
		Free(node_id_list);

	metaflushsetname(sp);

	if (!(MD_MNSET_DESC(sd))) {
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}

	return (rval);
}

int
meta_set_auto_take(
	mdsetname_t	*sp,
	int		take_val,
	md_error_t	*ep
)
{
	int		i;
	md_set_desc	*sd;
	int		rval = 0;
	md_setkey_t	*cl_sk;
	md_error_t	xep = mdnullerror;
	char		*hostname;
	md_drive_desc	*dd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	hostname = mynode();

	/* Lock the set on our side */
	if (clnt_lock_set(hostname, sp, ep)) {
		rval = -1;
		goto out;
	}

	if (take_val) {
		/* enable auto_take but only if it is not already set */
		if (! (sd->sd_flags & MD_SR_AUTO_TAKE)) {
			/* verify that we're the only host in the set */
			for (i = 0; i < MD_MAXSIDES; i++) {
				if (sd->sd_nodes[i] == NULL ||
				    sd->sd_nodes[i][0] == '\0')
					continue;

				if (strcmp(sd->sd_nodes[i], hostname) != 0) {
					(void) mddserror(ep, MDE_DS_SINGLEHOST,
					    sp->setno, NULL, NULL, sp->setname);
					rval = -1;
					goto out;
				}
			}

			if (clnt_enable_sr_flags(hostname, sp,
			    MD_SR_AUTO_TAKE, ep))
				rval = -1;

			/* Disable SCSI reservations */
			if (sd->sd_flags & MD_SR_MB_DEVID)
				dd = metaget_drivedesc(sp, MD_BASICNAME_OK |
				    PRINT_FAST, &xep);
			else
				dd = metaget_drivedesc(sp, MD_BASICNAME_OK,
				    &xep);

			if (! mdisok(&xep))
				mdclrerror(&xep);

			if (dd != NULL) {
				if (rel_own_bydd(sp, dd, TRUE, &xep))
					mdclrerror(&xep);
			}
		}

	} else {
		/* disable auto_take, if set, or error */
		if (sd->sd_flags & MD_SR_AUTO_TAKE) {
			if (clnt_disable_sr_flags(hostname, sp,
			    MD_SR_AUTO_TAKE, ep))
				rval = -1;

			/* Enable SCSI reservations */
			if (sd->sd_flags & MD_SR_MB_DEVID)
				dd = metaget_drivedesc(sp, MD_BASICNAME_OK |
				    PRINT_FAST, &xep);
			else
				dd = metaget_drivedesc(sp, MD_BASICNAME_OK,
				    &xep);

			if (! mdisok(&xep))
				mdclrerror(&xep);

			if (dd != NULL) {
				mhd_mhiargs_t	mhiargs = defmhiargs;

				if (tk_own_bydd(sp, dd, &mhiargs, TRUE, &xep))
					mdclrerror(&xep);
			}
		} else {
			(void) mddserror(ep, MDE_DS_AUTONOTSET, sp->setno,
			    NULL, NULL, sp->setname);
			rval = -1;
		}
	}

out:
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(hostname, cl_sk, &xep)) {
		if (rval == 0)
			(void) mdstealerror(ep, &xep);
		rval = -1;
	}
	cl_set_setkey(NULL);

	return (rval);
}
