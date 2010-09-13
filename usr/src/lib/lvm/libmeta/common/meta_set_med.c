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

/*
 * Metadevice diskset interfaces
 */

#include "meta_set_prv.h"
#include <sys/lvm/md_crc.h>
#include <sys/lvm/mdmed.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

#define	MALSIZ	32

static int
add_lst(char ***listp, char *item)
{
	int	i, j;

	if (*listp) {
		for (i = 0; (*listp)[i]; i++)
			/* void */;
	} else {
		*listp = (char **)Zalloc(MALSIZ * sizeof (char *));
		i = 0;
	}

	(*listp)[i] = Strdup(item);

	if ((++i % MALSIZ) == 0) {
		*listp = (char **)Realloc((void *)*listp,
			(i + MALSIZ) * sizeof (char *));
		for (j = i; j < (i + MALSIZ); j++)
			(*listp)[j] = (char *)NULL;
	}
	return (i);
}

static int
del_lst(char ***listp)
{
	int	i;

	if (*listp) {
		for (i = 0; (*listp)[i]; i++)
			free((*listp)[i]);
		free(*listp);
		*listp = NULL;
		return (1);
	} else
		return (0);
}


static int
validate_med_nodes(
	mdsetname_t	*sp,
	md_h_arr_t	*mhp,
	md_error_t	*ep
)
{
	char		*hostname;
	char		*nodename;
	char		*nm;
	char		*cp;
	int		i, j;


	for (i = 0; i < MED_MAX_HOSTS; i++) {
		if (mhp->n_lst[i].a_cnt == 0)
			continue;

		for (j = 0; j < mhp->n_lst[i].a_cnt; j++) {
			nm = mhp->n_lst[i].a_nm[j];

			for (cp = nm; *cp; cp++)
				if (!isprint(*cp) ||
				    strchr(INVALID_IN_NAMES, *cp) != NULL)
					return (mddserror(ep,
					    MDE_DS_INVALIDMEDNAME,
					    sp->setno, nm, NULL, sp->setname));

			if (clnt_med_hostname(nm, &hostname, ep))
				return (-1);

			if (j == 0) {
				if (strcmp(nm, hostname) != 0) {
					Free(hostname);
					return (mddserror(ep,
					    MDE_DS_NOTNODENAME, sp->setno, nm,
					    NULL, sp->setname));
				}
				nodename = nm;
			} else {
				if (strcmp(nodename, hostname) != 0) {
					Free(hostname);
					return (mddserror(ep,
					    MDE_DS_ALIASNOMATCH, sp->setno, nm,
					    nodename, sp->setname));
				}
			}
			Free(hostname);
		}
	}
	return (0);
}

/*
 * Exported Entry Points
 */

int
meta_set_addmeds(
	mdsetname_t		*sp,
	int			node_c,
	char			**node_v,
	md_error_t		*ep
)
{
	md_set_desc		*sd = NULL;
	md_drive_desc		*dd = NULL;
	mddb_med_parm_t		mp;
	mddb_med_upd_parm_t	mup;
	md_h_arr_t		t;
	md_h_arr_t		rb_t;
	med_rec_t		medr;
	med_rec_t		rb_medr;
	char			*cp;
	char			**n_l = NULL;
	int			n_c = 0;
	int			i, j;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	int			rb_level = 0;
	md_error_t		xep = mdnullerror;
	int			rval = 0;
	int			max_meds;
	md_mnnode_desc		*nd;
	int			suspend1_flag = 0;
	int			lock_flag = 0;

	/* Initialize */
	(void) memset(&t, '\0', sizeof (t));
	t.n_cnt = node_c;
	mdclrerror(ep);

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	/*
	 * The mediator information (which is part of the set record) is
	 * stored in the local mddbs of each node in the diskset.
	 * Each node's rpc.metad daemon reads in the set
	 * records from that node's local mddb and caches them
	 * internally. Any process needing diskset information contacts its
	 * local rpc.metad to get this information.  Since each node in the
	 * diskset is independently reading the set information from its local
	 * mddb, the set records in the local mddbs must stay
	 * in-sync, so that all nodes have a consistent view of the diskset.
	 *
	 * For a multinode diskset, explicitly verify that all nodes in the
	 * diskset are ALIVE (i.e. are in the API membership list).  Otherwise,
	 * fail this operation since all nodes must be ALIVE in order to add
	 * the mediator information to the set record in their local mddb.
	 * If a panic of this node leaves the local mddbs set records
	 * out-of-sync, the reconfig cycle will fix the local mddbs and
	 * force them back into synchronization.
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

	/* Parse the command line into a the md_h_arr_t structure */
	for (i = 0; i < t.n_cnt; i++) {
		cp = strtok(node_v[i], ",");
		j = 0;
		while (cp) {
			if (strlen(cp) > (size_t)MD_MAX_NODENAME)
				return (mddserror(ep, MDE_DS_NODENAMETOOLONG,
				    sp->setno, cp, NULL, sp->setname));
			if (j >= MAX_HOST_ADDRS)
				return (mddserror(ep, MDE_DS_TOOMANYALIAS,
				    sp->setno, cp, NULL, sp->setname));

			(void) strcpy(t.n_lst[i].a_nm[j], cp);

			j++;

			cp = strtok(NULL, ",");
		}
		t.n_lst[i].a_cnt = j;
	}

	/* Make a list of nodes to check */
	for (i = 0; i < t.n_cnt; i++)
		for (j = 0; j < t.n_lst[i].a_cnt; j++)
			n_c = add_lst(&n_l, t.n_lst[i].a_nm[j]);

	/* Make sure that there are no redundant nodes */
	rval = nodesuniq(sp, n_c, n_l, ep);

	(void) del_lst(&n_l);

	if (rval != 0)
		return (rval);

	/*
	 * Lock the set on current set members.
	 * Set locking done much earlier for MN diskset than for traditional
	 * diskset since lock_set and SUSPEND are used to protect against
	 * other metaset commands running on the other nodes.
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

	if (validate_med_nodes(sp, &t, ep)) {
		rval = -1;
		goto out;
	}

	/* Check existing mediators against new, if any */
	if (sd->sd_med.n_cnt > 0) {
		for (i = 0; i < max_meds; i++)
			if (sd->sd_med.n_lst[i].a_cnt > 0)
				n_c = add_lst(&n_l,
				    sd->sd_med.n_lst[i].a_nm[0]);

		for (i = 0; i < t.n_cnt; i++) {
			if (strinlst(t.n_lst[i].a_nm[0], n_c, n_l)) {
				(void) del_lst(&n_l);
				(void) mddserror(ep, MDE_DS_ISMED, sp->setno,
				    t.n_lst[i].a_nm[0], NULL,
				    sp->setname);
				rval = -1;
				goto out;
			}
		}
		(void) del_lst(&n_l);
	}

	if ((t.n_cnt + sd->sd_med.n_cnt) > max_meds) {
		(void) mderror(ep, MDE_TOOMANYMED, NULL);
		rval = -1;
		goto out;
	}

	/* Copy the current mediator list for rollback */
	rb_t = sd->sd_med;			/* structure assignment */

	/* Setup the mediator record roll-back structure */
	(void) memset(&rb_medr, '\0', sizeof (med_rec_t));
	rb_medr.med_rec_mag = MED_REC_MAGIC;
	rb_medr.med_rec_rev = MED_REC_REV;
	rb_medr.med_rec_fl  = 0;
	rb_medr.med_rec_sn  = sp->setno;
	(void) strcpy(rb_medr.med_rec_snm, sp->setname);
	if (MD_MNSET_DESC(sd)) {
		/*
		 * For a MN diskset the mediator is not given a list of
		 * hosts in the set.  Instead a generic name (multiowner) is
		 * given to the mediator which will allow any node to access
		 * the mediator data as long as it provides the correct
		 * setname and set number.  In a MN diskset, the mediator
		 * data is only used when a first node joins the diskset
		 * and becomes the master of the MN diskset.
		 *
		 * The traditional diskset code keeps the host list in
		 * the mediator record up to date with respect to the host
		 * list in the traditional diskset.  This keeps an unauthorized
		 * node in the traditional diskset from accessing the data
		 * in the mediator record and being able to 'take' the
		 * diskset.
		 *
		 * This additional check is needed in the traditional diskset
		 * since a panic during the metaset command can leave
		 * the diskset with some nodes thinking that an
		 * action has occurred and other nodes thinking the opposite.
		 * A node may have really been removed from a diskset, but
		 * that node doesn't realize this so this node must be
		 * blocked from using the mediator data when attempting
		 * to 'take' the diskset.
		 * (Traditional diskset code has each node's rpc.metad
		 * cleaning up from an inconsistent state without any
		 * knowledge from the other nodes in the diskset).
		 *
		 * In the MN diskset, the reconfig steps force a consistent
		 * state across all nodes in the diskset, so no node
		 * needs to be blocked from accessing the mediator data.
		 * This allow the MN diskset to use a common 'nodename'
		 * in the mediator record.  This allows the mediator
		 * daemon to remain unchanged even though a large number of
		 * nodes are supported by the MN diskset.
		 */
		(void) strlcpy(rb_medr.med_rec_nodes[0], MED_MN_CALLER,
		    MD_MAX_NODENAME_PLUS_1);
	} else {
		for (i = 0; i < MD_MAXSIDES; i++)
			(void) strcpy(rb_medr.med_rec_nodes[i],
				sd->sd_nodes[i]);
	}
	rb_medr.med_rec_meds = sd->sd_med;	/* structure assigment */
	(void) memset(&rb_medr.med_rec_data, '\0', sizeof (med_data_t));
	rb_medr.med_rec_foff = 0;
	crcgen(&rb_medr, &rb_medr.med_rec_cks, sizeof (med_rec_t), NULL);

	/* Merge new mediators into the set record */
	for (i = 0; i < t.n_cnt; i++) {
		for (j = 0; j < max_meds; j++) {
			if (sd->sd_med.n_lst[j].a_cnt > 0)
				continue;
			sd->sd_med.n_lst[j] = t.n_lst[i];
			SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_MEDIATOR,
			    sp->setno, j);
			sd->sd_med.n_cnt++;
			break;
		}
	}

	/*
	 * Setup the kernel mediator list, which also validates that the
	 * hosts have valid IP addresses
	 */
	(void) memset(&mp, '\0', sizeof (mddb_med_parm_t));
	mp.med_setno = sp->setno;

	/* Copy the hostnames */
	if (meta_h2hi(&sd->sd_med, &mp.med, ep)) {
		rval = -1;
		goto out;
	}

	/* Resolve the IP addresses for the host list */
	if (meta_med_hnm2ip(&mp.med, ep)) {
		rval = -1;
		goto out;
	}

	/* Bring the mediator record up to date with the set record */
	medr = rb_medr;				/* structure assignment */
	medr.med_rec_meds = sd->sd_med;		/* structure assigment */
	crcgen(&medr, &medr.med_rec_cks, sizeof (med_rec_t), NULL);

	/* END CHECK CODE */

	/* Lock the set on current set members */
	if (!(MD_MNSET_DESC(sd))) {
		/* all signals already blocked for MN disket */
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

	RB_TEST(1, "meta_set_addmeds", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "meta_set_addmeds", ep)

	/*
	 * Add the new mediator information to all hosts in the set.
	 * For MN diskset, each node sends mediator list to its kernel.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* All nodes are guaranteed to be ALIVE */
			if (clnt_updmeds(nd->nd_nodename, sp, &sd->sd_med, ep))
				goto rollback;
			nd = nd->nd_next;
		}
	} else  {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_updmeds(sd->sd_nodes[i], sp, &sd->sd_med, ep))
				goto rollback;
		}
	}

	RB_TEST(3, "meta_set_addmeds", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(4, "meta_set_addmeds", ep)

	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) {
		if (! mdisok(ep))
			goto rollback;
	}

	RB_TEST(5, "meta_set_addmeds", ep)

	RB_PREEMPT;
	rb_level = 3;	/* level 3 */

	RB_TEST(6, "meta_set_addmeds", ep)

	/* Inform the mediator hosts of the new information */
	for (i = 0; i < max_meds; i++) {
		if (sd->sd_med.n_lst[i].a_cnt == 0)
			continue;

		/* medr contains new mediator node list */
		if (clnt_med_upd_rec(&sd->sd_med.n_lst[i], sp, &medr, ep))
			goto rollback;
	}

	RB_TEST(7, "meta_set_addmeds", ep)

	RB_PREEMPT;
	rb_level = 4;	/* level 4 */

	RB_TEST(8, "meta_set_addmeds", ep)

	/* In MN diskset, mediator list updated in clnt_updmeds call */
	if (dd != NULL) {
		if (!(MD_MNSET_DESC(sd))) {
			if (metaioctl(MD_MED_SET_LST, &mp, &mp.med_mde,
			    NULL) != 0) {
				(void) mdstealerror(ep, &mp.med_mde);
				goto rollback;
			}
		}

		/*
		 * If only 50% mddbs available, mediator will be
		 * golden by this ioctl on a traditional diskset.
		 *
		 * On a MN disket, this only happens if the mediator
		 * add operation is executed on the master node.
		 * If a slave node is adding the mediator, the mediator
		 * won't be marked golden until the next mddb change.
		 */
		(void) memset(&mup, '\0', sizeof (mddb_med_upd_parm_t));
		mup.med_setno = sp->setno;
		if (metaioctl(MD_MED_UPD_MED, &mup, &mup.med_mde, NULL) != 0)
			mdclrerror(&mup.med_mde);
	}

out:
	if (suspend1_flag) {
		/*
		 * Unlock diskset by resuming messages across the diskset.
		 * Just resume all classes so that resume is the same whether
		 * just one class was locked or all classes were locked.
		 */
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
			while (nd) {
				/* All nodes are guaranteed to be ALIVE */
				if (clnt_unlock_set(nd->nd_nodename,
				    cl_sk, &xep)) {
					if (rval == 0)
						(void) mdstealerror(ep, &xep);
					rval = -1;
				}
				nd = nd->nd_next;
			}
		} else  {
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

	/*
	 * level 4
	 * In MN diskset, mediator list updated in clnt_updmeds call
	 */
	if (rb_level > 3 && (dd != NULL) && (!(MD_MNSET_DESC(sd)))) {
		(void) memset(&mp, '\0', sizeof (mddb_med_parm_t));
		mp.med_setno = sp->setno;
		(void) meta_h2hi(&rb_t, &mp.med, &xep);
		mdclrerror(&xep);
		(void) meta_med_hnm2ip(&mp.med, &xep);
		mdclrerror(&xep);
		(void) metaioctl(MD_MED_SET_LST, &mp, &mp.med_mde, NULL);
	}

	/* level 3 */
	if (rb_level > 2) {
		for (i = 0; i < max_meds; i++) {
			if (sd->sd_med.n_lst[i].a_cnt == 0)
				continue;

			/*
			 * rb_medr contains the rollback mediator node list.
			 * Send the rollback mediator information to the
			 * new mediator node list.  If a node had this RPC
			 * called, but its node is not in the mediator node
			 * list, rpc.metamedd will delete the mediator
			 * record on that node.
			 */
			if (clnt_med_upd_rec(&sd->sd_med.n_lst[i], sp,
			    &rb_medr, &xep))
				mdclrerror(&xep);
		}
	}

	/* level 2 */
	if (rb_level > 1) {
		metafreedrivedesc(&dd);
	}

	/* level 1 */
	if (rb_level > 0) {
		/* Delete mediator information from all hosts in the set */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* All nodes are guaranteed to be ALIVE */
				if (clnt_updmeds(nd->nd_nodename, sp, &rb_t,
				    &xep))
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		} else  {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_updmeds(sd->sd_nodes[i], sp, &rb_t,
				    &xep))
					mdclrerror(&xep);
			}
		}
	}

	/* level 0 */
	if (suspend1_flag) {
		/*
		 * Unlock diskset by resuming messages across the diskset.
		 * Just resume all classes so that resume is the same whether
		 * just one class was locked or all classes were locked.
		 */
		nd = sd->sd_nodelist;
		/* All nodes are guaranteed to be ALIVE */
		while (nd) {
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				mdclrerror(&xep);
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
			while (nd) {
				/* All nodes are guaranteed to be ALIVE */
				if (clnt_unlock_set(nd->nd_nodename,
				    cl_sk, &xep)) {
					mdclrerror(&xep);
				}
				nd = nd->nd_next;
			}
		} else  {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_unlock_set(sd->sd_nodes[i],
				    cl_sk, &xep)) {
					mdclrerror(&xep);
				}
			}
		}
		cl_set_setkey(NULL);
	}

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	if (!(MD_MNSET_DESC(sd))) {
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}

	return (rval);
}

int
meta_set_deletemeds(
	mdsetname_t		*sp,
	int			node_c,
	char			**node_v,
	int			forceflg,
	md_error_t		*ep
)
{
	md_set_desc		*sd = NULL;
	md_drive_desc		*dd = NULL;
	mddb_med_parm_t		mp;
	md_h_arr_t		rb_t;
	med_rec_t		medr;
	med_rec_t		rb_medr;
	int			i, j;
	char			**n_l = NULL;
	int			n_c = 0;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	int			rb_level = 0;
	md_error_t		xep = mdnullerror;
	int			rval = 0;
	int			max_meds;
	md_mnnode_desc		*nd;
	int			suspend1_flag = 0;
	int			lock_flag = 0;

	mdclrerror(ep);

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	for (i = 0; i < node_c; i++)
		if (strchr(node_v[i], ',') != NULL)
			return (mderror(ep, MDE_ONLYNODENAME, node_v[i]));

	if (nodesuniq(sp, node_c, node_v, ep))
		return (-1);

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	/*
	 * The mediator information (which is part of the set record) is
	 * stored in the local mddbs of each node in the diskset.
	 * Each node's rpc.metad daemon reads in the set
	 * records from that node's local mddb and caches them
	 * internally. Any process needing diskset information contacts its
	 * local rpc.metad to get this information.  Since each node in the
	 * diskset is independently reading the set information from its local
	 * mddb, the set records in the local mddbs must stay
	 * in-sync, so that all nodes have a consistent view of the diskset.
	 *
	 * For a multinode diskset, explicitly verify that all nodes in the
	 * diskset are ALIVE (i.e. are in the API membership list).  Otherwise,
	 * fail this operation since all nodes must be ALIVE in order to delete
	 * the mediator information from the set record in their local mddb.
	 * If a panic of this node leaves the local mddbs set records
	 * out-of-sync, the reconfig cycle will fix the local mddbs and
	 * force them back into synchronization.
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

	if (sd->sd_med.n_cnt == 0)
		return (mderror(ep, MDE_NOMED, NULL));

	/* Make a list of nodes to check */
	for (i = 0; i < max_meds; i++)
		if (sd->sd_med.n_lst[i].a_cnt > 0)
			n_c = add_lst(&n_l, sd->sd_med.n_lst[i].a_nm[0]);

	for (i = 0; i < node_c; i++) {
		if (! strinlst(node_v[i], n_c, n_l)) {
			(void) del_lst(&n_l);
			return (mddserror(ep, MDE_DS_ISNOTMED, sp->setno,
			    node_v[i], NULL, sp->setname));
		}
	}

	(void) del_lst(&n_l);

	/* Save a copy of the current mediator information */
	rb_t = sd->sd_med;			/* structure assignment */

	/* Setup the mediator record for rollback */
	(void) memset(&rb_medr, '\0', sizeof (med_rec_t));
	rb_medr.med_rec_mag = MED_REC_MAGIC;
	rb_medr.med_rec_rev = MED_REC_REV;
	rb_medr.med_rec_fl  = 0;
	rb_medr.med_rec_sn  = sp->setno;
	(void) strcpy(rb_medr.med_rec_snm, sp->setname);
	if (MD_MNSET_DESC(sd)) {
		/*
		 * In MN diskset, use a generic nodename, multiowner, in the
		 * mediator record which allows any node to access mediator
		 * information.  MN diskset reconfig cycle forces consistent
		 * view of set/node/drive/mediator information across all nodes
		 * in the MN diskset.  This allows the relaxation of
		 * node name checking in rpc.metamedd for MN disksets.
		 *
		 * In the traditional diskset, only a node that is in the
		 * mediator record's diskset nodelist can access mediator
		 * data.
		 */
		(void) strlcpy(rb_medr.med_rec_nodes[0], MED_MN_CALLER,
		    MD_MAX_NODENAME_PLUS_1);
	} else {
		for (i = 0; i < MD_MAXSIDES; i++)
			(void) strcpy(rb_medr.med_rec_nodes[i],
				sd->sd_nodes[i]);
	}
	rb_medr.med_rec_meds = sd->sd_med;	/* structure assignment */
	(void) memset(&rb_medr.med_rec_data, '\0', sizeof (med_data_t));
	rb_medr.med_rec_foff = 0;
	crcgen(&rb_medr, &rb_medr.med_rec_cks, sizeof (med_rec_t), NULL);

	/* Delete the mediators requested from the set */
	for (i = 0; i < node_c; i++) {
		for (j = 0; j < max_meds; j++) {
			if (sd->sd_med.n_lst[j].a_cnt == 0)
				continue;
			if (strcmp(node_v[i],
			    sd->sd_med.n_lst[j].a_nm[0]) != 0)
				continue;
			SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE,
			    SVM_TAG_MEDIATOR, sp->setno, j);
			(void) memset(&sd->sd_med.n_lst[j], '\0',
			    sizeof (md_h_t));
			sd->sd_med.n_cnt--;
			break;
		}
	}

	medr = rb_medr;				/* structure assignment */
	medr.med_rec_meds = sd->sd_med;		/* structure assignment */
	crcgen(&medr, &medr.med_rec_cks, sizeof (med_rec_t), NULL);

	/* END CHECK CODE */

	/* Lock the set on current set members */
	if (MD_MNSET_DESC(sd)) {
		/* Make sure we are blocking all signals */
		if (procsigs(TRUE, &oldsigs, &xep) < 0)
			mdclrerror(&xep);
		/*
		 * Lock the set on current set members.
		 * lock_set and SUSPEND are used to protect against
		 * other metaset commands running on the other nodes.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* All nodes are guaranteed to be ALIVE */
			if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
				if (forceflg && strcmp(mynode(),
				    nd->nd_nodename) != 0) {
					mdclrerror(ep);
					nd = nd->nd_next;
					continue;
				}
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
	} else  {
		md_rb_sig_handling_on();
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
				if (forceflg &&
				    strcmp(mynode(), sd->sd_nodes[i]) != 0) {
					mdclrerror(ep);
					continue;
				}
				rval = -1;
				goto out;
			}
			lock_flag = 1;
		}
	}

	RB_TEST(1, "meta_set_deletemeds", ep)

	RB_PREEMPT;
	rb_level = 1;	/* level 1 */

	RB_TEST(2, "meta_set_deletemeds", ep)

	/* Update the mediator information on all hosts in the set */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* All nodes are guaranteed to be ALIVE */
			if (clnt_updmeds(nd->nd_nodename, sp, &sd->sd_med,
			    ep)) {
				if (forceflg && strcmp(mynode(),
				    nd->nd_nodename) != 0) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}
			nd = nd->nd_next;
		}
	} else  {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_updmeds(sd->sd_nodes[i], sp, &sd->sd_med,
			    ep)) {
				if (forceflg && strcmp(mynode(),
				    sd->sd_nodes[i]) != 0) {
					mdclrerror(ep);
					continue;
				}
				goto rollback;
			}
		}
	}

	RB_TEST(3, "meta_set_deletemeds", ep)

	RB_PREEMPT;
	rb_level = 2;	/* level 2 */

	RB_TEST(5, "meta_set_deletemeds", ep)

	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) {
		if (! mdisok(ep))
			goto rollback;
	}

	RB_TEST(5, "meta_set_deletemeds", ep)

	RB_PREEMPT;
	rb_level = 3;	/* level 3 */

	RB_TEST(6, "meta_set_deletemeds", ep)

	if (dd != NULL) {
		/*
		 * Set up the parameters to the call to update the
		 * kernel mediator list
		 */
		(void) memset(&mp, '\0', sizeof (mddb_med_parm_t));
		mp.med_setno = sp->setno;
		if (meta_h2hi(&sd->sd_med, &mp.med, ep))
			goto rollback;

		/* Resolve the IP addresses for the host list */
		if (meta_med_hnm2ip(&mp.med, ep))
			goto rollback;

		if (metaioctl(MD_MED_SET_LST, &mp, &mp.med_mde, NULL) != 0) {
			(void) mdstealerror(ep, &mp.med_mde);
			goto rollback;
		}
	}

	RB_TEST(7, "meta_set_deletemeds", ep)

	RB_PREEMPT;
	rb_level = 4;	/* level 4 */

	RB_TEST(8, "meta_set_deletemeds", ep)

	/* Inform the mediator hosts of the new status */
	for (i = 0; i < max_meds; i++) {
		if (rb_t.n_lst[i].a_cnt == 0)
			continue;

		/*
		 * medr contains the new mediator node list.
		 * Send the new mediator information to the
		 * new mediator node list.  If a node had this RPC
		 * called, but its node is no longer in the new mediator
		 * node list, rpc.metamedd will delete the mediator
		 * record on that node.
		 */
		if (clnt_med_upd_rec(&rb_t.n_lst[i], sp, &medr, ep)) {
			if ((forceflg && mdanyrpcerror(ep)) ||
			    mdisrpcerror(ep, RPC_PROGNOTREGISTERED)) {
				mdclrerror(ep);
				continue;
			}
			goto rollback;
		}
	}

out:
	if (dd)
		metafreedrivedesc(&dd);

	if (suspend1_flag) {
		/*
		 * Unlock diskset by resuming messages across the diskset.
		 * Just resume all classes so that resume is the same whether
		 * just one class was locked or all classes were locked.
		 */
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

	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (lock_flag) {
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* All nodes are guaranteed to be ALIVE */
				if (clnt_unlock_set(nd->nd_nodename,
				    cl_sk, &xep)) {
					if (forceflg &&
					    strcmp(mynode(),
					    nd->nd_nodename) != 0) {
						mdclrerror(ep);
						continue;
					}
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
					if (forceflg &&
					    strcmp(mynode(),
					    sd->sd_nodes[i]) != 0) {
						mdclrerror(ep);
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

	(void) del_lst(&n_l);

	/* level 4 */
	if (rb_level > 4) {
		for (i = 0; i < max_meds; i++) {
			if (rb_t.n_lst[i].a_cnt == 0)
				continue;

			/*
			 * rb_medr contains the rollback mediator node list.
			 * Send the rollback mediator information to the
			 * new mediator node list.  This will recreate the
			 * mediator record on all nodes where the mediator
			 * record had been removed.
			 */
			if (clnt_med_upd_rec(&rb_t.n_lst[i], sp, &rb_medr,
			    &xep))
				mdclrerror(&xep);
		}
	}

	/* level 3 */
	if (rb_level > 2 && dd != NULL) {
		(void) memset(&mp, '\0', sizeof (mddb_med_parm_t));
		mp.med_setno = sp->setno;
		(void) meta_h2hi(&rb_t, &mp.med, &xep);
		mdclrerror(&xep);
		(void) meta_med_hnm2ip(&mp.med, &xep);
		mdclrerror(&xep);
		(void) metaioctl(MD_MED_SET_LST, &mp, &mp.med_mde, NULL);
	}

	/* level 2 */
	if (rb_level > 1) {
		metafreedrivedesc(&dd);
	}

	/* level 1 */
	if (rb_level > 0) {
		/* Delete mediator information from all hosts in the set */
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				/* All nodes are guaranteed to be ALIVE */
				if (clnt_updmeds(nd->nd_nodename, sp, &rb_t,
				    &xep))
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		} else  {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (clnt_updmeds(sd->sd_nodes[i], sp, &rb_t,
				    &xep))
					mdclrerror(&xep);
			}
		}
	}

	/* level 0 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	/* Unlock the set */
	/* Don't test lock flag since guaranteed to be set if in rollback */
	if (MD_MNSET_DESC(sd)) {
		/*
		 * Unlock diskset by resuming messages across the diskset.
		 * Just resume all classes so that resume is the same whether
		 * just one class was locked or all classes were locked.
		 */
		if (suspend1_flag) {
			/* All nodes are guaranteed to be ALIVE */
			nd = sd->sd_nodelist;
			while (nd) {
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
			if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep))
				mdclrerror(&xep);
			nd = nd->nd_next;
		}
	} else  {
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

	if (!(MD_MNSET_DESC(sd))) {
		md_rb_sig_handling_off(md_got_sig(), md_which_sig());
	}

	return (rval);
}
