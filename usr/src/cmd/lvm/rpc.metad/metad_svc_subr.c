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

#include "metad_local.h"
#include <metad.h>
#include <sys/lvm/md_mddb.h>
#include <sdssc.h>
#include <sys/lvm/md_mirror.h>
#include <syslog.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>
#include <thread.h>

#define	MDDOORS		"/usr/lib/lvm/mddoors"

/*
 * rpc.metad daemon
 *
 * The rpc.metad deamon supports two versions of the svm rpc calls - version 1
 * and version 2. The over-the-wire structures sent as part of these rpc calls
 * are also versioned - version 1 and version 2 exist. It must be noted that
 * the version 2 structures have sub-versions or revisions as well. The
 * revisions in the version 2 structures allow for flexiblility in changing
 * over the wire structures without creating a new version of the svm rpc
 * calls. No changes may be made to the version 1 routines or structures used
 * by these routines.
 *
 * If, for example, the version 2 mdrpc_devinfo_args over the wire structure
 * (mdrpc_devinfo_2_args*) is changed then the structure change must be
 * accompanied by the following:
 *
 * Header file changes:
 * . May need to introduce a new structure revision MD_METAD_ARGS_REV_X, where
 *   X is the revision number.
 * . Create mdrpc_devinfo_2_args_rX, where X is the new revision of the
 *   structure.
 * . Add a switch statement in mdrpc_devinfo_2_args.
 *
 * rpc.metad changes:
 * . Check for the structure revision in the appropriate mdrpc_devinfo_svc
 *   routine (mdrpc_devinfo_2_svc).
 *
 * libmeta changes:
 * . In the libmeta code that makes the mdrpc_devinfo rpc call, the arguments
 *   being passed as part of this call (namely mdrpc_devinfo_Y_args) must have
 *   the revision field and associated structure populated correctly.
 */

static	md_setkey_t	*my_svc_sk = NULL;

/*
 * Add namespace entry to local mddb for using given sideno, key
 * and names.
 */
static int
add_sideno_sidenm(
	mdsidenames_t	*sidenms,
	mdkey_t		local_key,
	side_t		sideno,
	md_set_desc	*sd,		/* Only used with Version 2 */
	md_error_t	*ep
)
{
	mdsidenames_t	*sn;
	mdsetname_t	*local_sp;
	char		*nm;

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL)
		return (-1);

	for (sn = sidenms; sn != NULL; sn = sn->next)
		if (sn->sideno == sideno)
			break;

	assert(sn != NULL);


	/*
	 * SKEW will be used on the traditional diskset despite of the
	 * rpc version.  SKEW is not used on the multinode diskset
	 */
	if (MD_MNSET_DESC(sd)) {
		nm = meta_getnmbykey(MD_LOCAL_SET, sideno, local_key, ep);
	} else {
		nm = meta_getnmbykey(MD_LOCAL_SET, sideno+SKEW, local_key, ep);
	}

	if (nm == NULL) {
		if (! mdisok(ep)) {
			if (! mdissyserror(ep, ENOENT))
				return (-1);
			mdclrerror(ep);
		}

		/*
		 * Ignore returned key from add_name, only care about errs
		 *
		 * SKEW is used for a regular diskset since sideno could
		 * have a value of 0 in that diskset type.  add_name is
		 * writing to the local mddb and a sideno of 0 in the
		 * local mddb is reserved for non-diskset names.
		 * SKEW is added to the sideno in the local mddb so that
		 * the sideno for the diskset will never be 0.
		 *
		 * In a MNdiskset, the sideno will never be 0 (by design).
		 * So, no SKEW is needed when writing to the local mddb.
		 */
		if (MD_MNSET_DESC(sd)) {
			if (add_name(local_sp, sideno, local_key,
			    sn->dname, sn->mnum, sn->cname, NULL, NULL,
			    ep) == -1)
				return (-1);
		} else {
			if (add_name(local_sp, sideno+SKEW, local_key,
			    sn->dname, sn->mnum, sn->cname, NULL, NULL,
			    ep) == -1)
				return (-1);
		}
	} else
		Free(nm);

	return (0);
}

/*
 * Delete sidename entry from local set using key and sideno.
 */
static int
del_sideno_sidenm(
	mdkey_t		sidekey,
	side_t		sideno,
	md_error_t	*ep
)
{
	mdsetname_t	*local_sp;

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL)
		return (-1);

	if (del_name(local_sp, sideno, sidekey, ep) == -1)
		mdclrerror(ep); /* ignore errs */

	return (0);
}


/*
 * Add namespace entries to local mddb for drives in drive list in
 * set descriptor.
 *
 * If a MNset and if this host is being added to the set (this host
 * is in the node_v list), add a namespace entry for the name of
 * each drive using this host's sideno.
 *
 * If not a MNset, add namespace entries for all the new hosts being
 * added to this set (list in node_v).
 */
static void
add_drv_sidenms(
	char		*hostname,
	mdsetname_t	*sp,
	md_set_desc	*sd,
	int		node_c,
	char		**node_v,
	md_error_t	*ep
)
{
	mdsetname_t	*my_sp;
	md_drive_desc	*dd, *my_dd, *p, *q;
	mddrivename_t	*dn, *my_dn;
	int		i;
	side_t		sideno = 0, mysideno = 0;
	ddi_devid_t	devid_remote = NULL;
	ddi_devid_t	devid_local = NULL;
	int		devid_same = -1;
	int		using_devid = 0;
	md_mnnode_desc	*nd;

	assert(sd->sd_drvs != NULL);
	dd = sd->sd_drvs;

	if (dd->dd_dnp == NULL)
		return;

	if ((my_sp = metasetname(sp->setname, ep)) == NULL)
		return;
	metaflushsetname(my_sp);

	/* If a MN diskset */
	if (MD_MNSET_DESC(sd)) {
		/* Find sideno associated with RPC client. */
		nd = sd->sd_nodelist;
		while (nd) {

			if (strcmp(nd->nd_nodename, hostname) == 0) {
				sideno = nd->nd_nodeid;
			}

			/* While looping, find my side num as well */
			if (strcmp(nd->nd_nodename, mynode()) == 0) {
				mysideno = nd->nd_nodeid;
			}

			if ((sideno) && (mysideno)) {
				break;
			}
			nd = nd->nd_next;
		}

		if (!sideno) {
			(void) mddserror(ep, MDE_DS_HOSTNOSIDE,
			    sp->setno, hostname, NULL, sp->setname);
			return;
		}
	} else {
		/*
		 * if not a MN diskset
		 * do action for traditional diskset.
		 * despite of the rpc version
		 */
		for (sideno = 0; sideno < MD_MAXSIDES; sideno++) {
			/* Skip empty slots */
			if (sd->sd_nodes[sideno][0] == '\0')
				continue;

			if (strcmp(hostname, sd->sd_nodes[sideno]) == 0)
				break;
		}

		if (sideno == MD_MAXSIDES) {
			(void) mddserror(ep, MDE_DS_HOSTNOSIDE, sp->setno,
			    hostname, NULL, sp->setname);
			return;
		}
	}
	if ((my_dd = metaget_drivedesc_sideno(my_sp, sideno, MD_BASICNAME_OK,
	    ep)) == NULL) {
		if (! mdisok(ep))
			return;
		/* we are supposed to have drives!!!! */
		assert(0);
	}

	/*
	 * The system is either all devid or all
	 * non-devid so we look at the first item
	 * in the list to determine if we're using devids or not.
	 * We also check to make sure it's not a multi-node diskset.
	 * If it is, we don't use devid's.
	 *
	 * For did disks, the dd_dnp->devid is a valid pointer which
	 * points to a '' string of devid.  We need to check this
	 * before set the using_devid.
	 */
	if ((dd->dd_dnp->devid != NULL) && (dd->dd_dnp->devid[0] != '\0') &&
	    (!(MD_MNSET_DESC(sd))))
		using_devid = 1;

	/*
	 * We have to match-up the dd that were passed
	 * across the wire to the dd we have in this daemon.
	 * That way we can pick up the new sidenames that were
	 * passed to us and match them up with the local namespace key.
	 * Only we have the key, this cannot be passed in.
	 */
	for (p = dd; p != NULL; p = p->dd_next) {
		dn = p->dd_dnp;
		devid_remote = NULL;

		if (dn->devid != NULL && (strlen(dn->devid) != 0) &&
		    using_devid) {
			/*
			 * We have a devid so use it
			 */
			(void) devid_str_decode(dn->devid, &devid_remote, NULL);
		}

		/* check to make sure using_devid agrees with reality... */
		if ((using_devid == 1) && (devid_remote == NULL)) {
			/* something went really wrong. Can't process */
			(void) mddserror(ep, MDE_DS_INVALIDDEVID, sp->setno,
			    hostname, dn->cname, sp->setname);
			return;
		}

		for (q = my_dd; q != NULL; q = q->dd_next) {
			my_dn = q->dd_dnp;
			devid_same = -1;

			if (my_dn->devid != NULL && using_devid) {
				if (devid_str_decode(my_dn->devid,
				    &devid_local, NULL) == 0) {
					devid_same = devid_compare(devid_remote,
					    devid_local);
					devid_free(devid_local);
				}
			}

			if (using_devid && devid_same == 0) {
				break;
			}

			if (!using_devid &&
			    strcmp(my_dn->cname, dn->cname) == 0)
				break;
		}

		if (devid_remote) {
			devid_free(devid_remote);
		}
		assert(q != NULL);
		assert(my_dn->side_names_key != MD_KEYWILD);

		if (MD_MNSET_DESC(sd)) {
			/*
			 * Add the side names to the local db
			 * for this node only.
			 */
			if (add_sideno_sidenm(dn->side_names,
			    my_dn->side_names_key, mysideno, sd, ep))
				return;
			/*
			 * Sidenames for this drive were added
			 * to this host during the routine adddrvs.
			 * The sidenames that were added are the
			 * names associated with this drive on
			 * each of the hosts that were previously
			 * in the set.
			 * When the sidename for this drive on
			 * this host is added, the sidename
			 * from the host executing the command
			 * (not this host) is sent to this host.
			 * This host finds the originating host's
			 * sidename and can then determine this
			 * host's sidename.
			 * The sidenames from the other hosts serve
			 * only as temporary sidenames until this
			 * host's sidename can be added.
			 * In order to conserve space in the
			 * local mddb, the code now deletes the
			 * temporary sidenames added during adddrvs.
			 * When finished, only the sidename for this
			 * node should be left.
			 * Ignore any errors during this process since
			 * a failure to delete the extraneous
			 * sidenames shouldn't cause this routine
			 * to fail (in case that sidename didn't exist).
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if (nd->nd_nodeid != mysideno) {
					if (del_sideno_sidenm(
					    dn->side_names_key,
					    nd->nd_nodeid, ep) == -1)
						mdclrerror(ep);
				}
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				/* Skip nodes not being added */
				if (! strinlst(sd->sd_nodes[i],
				    node_c, node_v))
					continue;

				/* Add the per side names to local db */
				if (add_sideno_sidenm(dn->side_names,
				    my_dn->side_names_key, i, sd, ep))
					return;
			}
		}
	}
}

/* ARGSUSED */
bool_t
mdrpc_flush_internal_common(mdrpc_null_args *args, mdrpc_generic_res *res,
    struct svc_req *rqstp)
{
	md_error_t	*ep = &res->status;
	int		err, op_mode = W_OK;

	(void) memset(res, 0, sizeof (*res));
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	metaflushnames(1);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_flush_internal_1_svc(mdrpc_null_args *args, mdrpc_generic_res *res,
    struct svc_req *rqstp)
{
	return (mdrpc_flush_internal_common(args, res, rqstp));
}

bool_t
mdrpc_flush_internal_2_svc(mdrpc_null_args *args, mdrpc_generic_res *res,
    struct svc_req *rqstp)
{
	return (mdrpc_flush_internal_common(args, res, rqstp));
}

/*
 * add 1 or more namespace entries per drive record.
 * (into the local namespace)
 */
bool_t
mdrpc_add_drv_sidenms_common(
	mdrpc_drv_sidenm_2_args_r1	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	add_drv_sidenms(args->hostname, args->sp, args->sd,
	    args->node_v.node_v_len, args->node_v.node_v_val, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * version 1 of the remote procedure. This procedure is called if the
 * client is running in version 1. We first convert version 1 arguments
 * into version 2 arguments and then call the common remote procedure.
 */
bool_t
mdrpc_add_drv_sidenms_1_svc(
	mdrpc_drv_sidenm_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	bool_t				retval;
	mdrpc_drv_sidenm_2_args_r1	v2_args;
	int				i, j;

	/* allocate memory */
	v2_args.sd = Zalloc(sizeof (md_set_desc));
	alloc_newdrvdesc(args->sd->sd_drvs, &v2_args.sd->sd_drvs);
	(void) memset(res, 0, sizeof (*res));

	/* build args */
	v2_args.hostname = args->hostname;
	v2_args.cl_sk = args->cl_sk;
	v2_args.sp = args->sp;
	/* set descriptor */
	v2_args.sd->sd_ctime = args->sd->sd_ctime;
	v2_args.sd->sd_genid = args->sd->sd_genid;
	v2_args.sd->sd_setno = args->sd->sd_setno;
	v2_args.sd->sd_flags = args->sd->sd_flags;
	for (i = 0; i < MD_MAXSIDES; i++) {
		v2_args.sd->sd_isown[i] = args->sd->sd_isown[i];

		for (j = 0; j < MD_MAX_NODENAME_PLUS_1; j++)
			v2_args.sd->sd_nodes[i][j] =
			    args->sd->sd_nodes[i][j];
	}
	v2_args.sd->sd_med = args->sd->sd_med;
	/* convert v1 args to v2 (revision 1) args */
	meta_conv_drvdesc_old2new(args->sd->sd_drvs, v2_args.sd->sd_drvs);
	v2_args.node_v.node_v_len = args->node_v.node_v_len;
	v2_args.node_v.node_v_val = args->node_v.node_v_val;

	retval = mdrpc_add_drv_sidenms_common(&v2_args, res, rqstp);

	free(v2_args.sd);
	free_newdrvdesc(v2_args.sd->sd_drvs);

	return (retval);
}

bool_t
mdrpc_add_drv_sidenms_2_svc(
	mdrpc_drv_sidenm_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_add_drv_sidenms_common(
		    &args->mdrpc_drv_sidenm_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static int
add_sidenamelist(
	mddrivename_t	*dn,
	side_t		thisside,
	md_set_record	*sr, 		/* used by RPC version 2 */
	md_error_t	*ep
)
{
	mdsidenames_t	*sn;
	mdkey_t		key;
	int		err;
	mdsetname_t	*local_sp;
	md_mnset_record	*mnsr;
	md_mnnode_record *nr;
	uint_t		nodeid = 0;

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL)
		return (-1);

	key = MD_KEYWILD;

	/*
	 * If a multi-node diskset, find nodeid associated with this node.
	 */
	if (MD_MNSET_REC(sr)) {
		mnsr = (struct md_mnset_record *)sr;
		nr = mnsr->sr_nodechain;
		while (nr) {
			if (strcmp(nr->nr_nodename, mynode()) == 0) {
				break;
			}
			nr = nr->nr_next;
		}
		/*
		 * If node is found, then a new drive is being added to
		 * a MN set of which this node is a member.
		 * If node is not found, then this host is being added to
		 * a MN set that has drives associated with it.
		 */
		if (nr)
			nodeid = nr->nr_nodeid;
	}
	for (sn = dn->side_names; sn != NULL; sn = sn->next) {
		if (MD_MNSET_REC(sr)) {
			/*
			 * In multi-node disksets, only add side information
			 * to the local mddb about this node.
			 * If the sideno for this node is found, then
			 * a new drive is being added to a MN set of
			 * which this node is a member.
			 * If the sideno for this node is not found, then
			 * this host is being added to a MNset that
			 * has drives associated with it.  In this case,
			 * need to add the sidename associated with the
			 * rpc client, but since we don't know which node
			 * is the client, then add temp entries for all sides.
			 * Later, the sidename for this node will be set
			 * via add_drv_sidenms and then the temp
			 * sidenames can be removed.
			 */
			if (nodeid == sn->sideno) {
				if ((err = add_name(local_sp, sn->sideno, key,
				    sn->dname, sn->mnum, sn->cname,
				    NULL, NULL, ep)) == -1)
					return (-1);
				key = (mdkey_t)err;
				break;
			}
		} else {
			/*
			 * When a sidename is added into the namespace the local
			 * side information for the name is added first of all.
			 * When the first sidename is created this causes the
			 * devid of the disk to be recorded in the namespace, if
			 * the non-local side information is added first then
			 * there is the possibility of getting the wrong devid
			 * because there is no guarantee that the dev_t (mnum in
			 * this instance) is the same across all the nodes in
			 * the set. So the only way to make sure that the
			 * correct dev_t is used is to force the adding in of
			 * the local sidename record first of all. This same
			 * issue affects add_key_name().
			 */
			if (sn->sideno != thisside)
				continue;
			if ((err = add_name(local_sp, sn->sideno+SKEW, key,
			    sn->dname, sn->mnum, sn->cname, NULL,
			    NULL, ep)) == -1)
				return (-1);
			key = (mdkey_t)err;
			break;
		}
	}

	/*
	 * Now the other sides for non-MN set
	 */
	if (!MD_MNSET_REC(sr)) {
		for (sn = dn->side_names; sn != NULL; sn = sn->next) {
			if (sn->sideno == thisside)
				continue;
			if ((err = add_name(local_sp, sn->sideno+SKEW, key,
			    sn->dname, sn->mnum, sn->cname, NULL, NULL,
			    ep)) == -1)
				return (-1);
			key = (mdkey_t)err;
		}
	}

	/* Temporarily add all sides. */
	if ((key == MD_KEYWILD) && (MD_MNSET_REC(sr))) {
		for (sn = dn->side_names; sn != NULL; sn = sn->next) {
			sn = dn->side_names;
			if (sn) {
				if ((err = add_name(local_sp, sn->sideno, key,
				    sn->dname, sn->mnum, sn->cname,
				    NULL, NULL, ep)) == -1)
						return (-1);
				key = (mdkey_t)err;
			}
		}
	}

	dn->side_names_key = key;
	return (0);
}

/*
 * imp_adddrvs
 *    This is a version of adddrvs that is specific to the
 *    metaimport command. Due to the unavailability of some disks,
 *    information needs to be obtained about the disk from the devid so
 *    it can eventually be passed down to add_sidenamelist.
 *    Go ahead and set drive state to MD_DR_OK here so that no
 *    later RPC is needed to set OK where UNRLSV_REPLICATED could
 *    be cleared.  Set record is still set to MD_SR_ADD which will force
 *    a cleanup of the set in case of panic.
 */
void
imp_adddrvs(
	char		*setname,
	md_drive_desc	*dd,
	md_timeval32_t	timestamp,
	ulong_t		genid,
	md_error_t	*ep
)
{
	mddb_userreq_t	req;
	md_drive_record	*dr, *tdr;
	md_set_record	*sr;
	md_drive_desc	*p;
	mddrivename_t	*dn;
	mdname_t	*np;
	md_dev64_t	dev;
	md_error_t	xep = mdnullerror;
	char		*minorname = NULL;
	ddi_devid_t	devidp = NULL;
	mdsidenames_t	*sn;
	mdsetname_t	*local_sp;


	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		return;
	}

	if ((sr = getsetbyname(setname, ep)) == NULL)
		return;

	for (p = dd; p != NULL; p = p->dd_next) {
		uint_t	rep_slice;
		int	ret = 0;

		dn = p->dd_dnp;

		/*
		 * We need the minorname and devid string decoded from the
		 * devid to add the sidename for this drive to the
		 * local set.
		 */
		ret = devid_str_decode(dn->devid, &devidp, &minorname);
		if (ret != 0) {
			/* failed to decode the devid */
			goto out;
		}

		sn = dn->side_names;
		if (sn == NULL) {
			dn->side_names_key = MD_KEYWILD;
			continue;
		}

		if ((dn->side_names_key = add_name(local_sp, SKEW, MD_KEYWILD,
		    sn->dname, sn->mnum, sn->cname, minorname, devidp,
		    ep)) == -1) {
			devid_free(devidp);
			devid_str_free(minorname);
			goto out;
		}

		devid_free(devidp);
		devid_str_free(minorname);

		/* Create the drive record */
		(void) memset(&req, 0, sizeof (req));
		METAD_SETUP_DR(MD_DB_CREATE, 0);
		req.ur_size = sizeof (*dr);
		if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
			(void) mdstealerror(ep, &req.ur_mde);
			goto out;
		}

		/* Fill in the drive record values */
		dr = Zalloc(sizeof (*dr));
		dr->dr_selfid = req.ur_recid;
		dr->dr_dbcnt = p->dd_dbcnt;
		dr->dr_dbsize = p->dd_dbsize;
		dr->dr_key = dn->side_names_key;

		dr->dr_ctime = timestamp;
		dr->dr_genid = genid;
		dr->dr_revision = MD_DRIVE_RECORD_REVISION;
		dr->dr_flags = MD_DR_OK;
		if (p->dd_flags & MD_DR_UNRSLV_REPLICATED) {
			dr->dr_flags |= MD_DR_UNRSLV_REPLICATED;
			sr->sr_flags |= MD_SR_UNRSLV_REPLICATED;
		}

		/* Link the drive records and fill in in-core data */
		dr_cache_add(sr, dr);

		dev = NODEV64;
		if ((meta_replicaslice(dn, &rep_slice, &xep) == 0) &&
		    ((np = metaslicename(dn, rep_slice, &xep)) != NULL))
			dev = np->dev;
		else
			mdclrerror(&xep);

		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE, SVM_TAG_DRIVE,
		    MD_LOCAL_SET, dev);
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_DRIVE,
		    sr->sr_setno, dev);
	}

	/* Commit all the records atomically */
	commitset(sr, TRUE, ep);
	free_sr(sr);
	return;

out:
	/* If failures, remove drive records. */
	dr = tdr = sr->sr_drivechain;
	while (dr != NULL) {
		tdr = dr->dr_next;
		if (del_name(local_sp, 0, dr->dr_key, &xep))
			mdclrerror(&xep);
		sr_del_drv(sr, dr->dr_selfid);
		dr = tdr;
	}
}

static void
adddrvs(
	char 		*setname,
	md_drive_desc	*dd,
	md_timeval32_t	timestamp,
	ulong_t		genid,
	md_error_t	*ep
)
{
	mddb_userreq_t	req;
	md_drive_record	*dr;
	md_set_record	*sr;
	md_drive_desc	*p;
	mddrivename_t	*dn;
	mdname_t	*np;
	md_dev64_t	dev;
	md_error_t	xep = mdnullerror;
	int		i;

	if ((sr = getsetbyname(setname, ep)) == NULL)
		return;

	if (MD_MNSET_REC(sr))
		i = 0;
	else {
		/* get thisside */
		for (i = 0; i < MD_MAXSIDES; i++) {
			if (sr->sr_nodes[i][0] == '\0')
				continue;
			if (strcmp(mynode(), sr->sr_nodes[i]) == 0)
				break;
		}

		if (i == MD_MAXSIDES) {
			/* so find the first free slot! */
			for (i = 0; i < MD_MAXSIDES; i++) {
				if (sr->sr_nodes[i][0] == '\0')
					break;
			}
		}
	}

	for (p = dd; p != NULL; p = p->dd_next) {
		uint_t	rep_slice;

		dn = p->dd_dnp;

		/* Add the per side names to the local db */
		if (add_sidenamelist(dn, (side_t)i,  sr, ep)) {
				free_sr(sr);
				return;
		}

		/* Create the drive record */
		(void) memset(&req, 0, sizeof (req));
		METAD_SETUP_DR(MD_DB_CREATE, 0);
		req.ur_size = sizeof (*dr);
		if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
			(void) mdstealerror(ep, &req.ur_mde);
			free_sr(sr);
			return;
		}

		/* Fill in the drive record values */
		dr = Zalloc(sizeof (*dr));
		dr->dr_selfid = req.ur_recid;
		dr->dr_dbcnt = p->dd_dbcnt;
		dr->dr_dbsize = p->dd_dbsize;
		dr->dr_key = dn->side_names_key;

		dr->dr_ctime = timestamp;
		dr->dr_genid = genid;
		dr->dr_revision = MD_DRIVE_RECORD_REVISION;
		dr->dr_flags = MD_DR_ADD;

		/* Link the drive records and fill in in-core data */
		dr_cache_add(sr, dr);

		dev = NODEV64;
		if ((meta_replicaslice(dn, &rep_slice, &xep) == 0) &&
		    ((np = metaslicename(dn, rep_slice, &xep)) != NULL))
			dev = np->dev;
		else
			mdclrerror(&xep);

		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE, SVM_TAG_DRIVE,
		    MD_LOCAL_SET, dev);
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_DRIVE,
		    sr->sr_setno, dev);
	}

	/* Commit all the records atomically */
	commitset(sr, TRUE, ep);
	free_sr(sr);
}

/*
 * add 1 or more drive records to a set.
 */
bool_t
mdrpc_adddrvs_common(
	mdrpc_drives_2_args_r1	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	adddrvs(args->sp->setname, args->drivedescs, args->timestamp,
	    args->genid, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * version 1 of the remote procedure. This procedure is called if the
 * client is running in version 1. We first convert version 1 arguments
 * into version 2 arguments and then call the common remote procedure.
 */
bool_t
mdrpc_adddrvs_1_svc(
	mdrpc_drives_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	bool_t			retval;
	mdrpc_drives_2_args_r1	v2_args;

	/* allocate memory */
	alloc_newdrvdesc(args->drivedescs, &v2_args.drivedescs);
	(void) memset(res, 0, sizeof (*res));

	/* build args */
	v2_args.cl_sk = args->cl_sk;
	v2_args.sp = args->sp;
	/* convert v1 args to v2 (revision 1) args */
	meta_conv_drvdesc_old2new(args->drivedescs, v2_args.drivedescs);
	v2_args.timestamp = args->timestamp;
	v2_args.genid = args->genid;

	retval = mdrpc_adddrvs_common(&v2_args, res, rqstp);

	free_newdrvdesc(v2_args.drivedescs);

	return (retval);
}

bool_t
mdrpc_adddrvs_2_svc(
	mdrpc_drives_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_adddrvs_common(
		    &args->mdrpc_drives_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * add 1 or more drive records to a set when importing.
 */
bool_t
mdrpc_imp_adddrvs_2_svc(
	mdrpc_drives_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	mdrpc_drives_2_args_r1	*v2_args;
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		v2_args = &args->mdrpc_drives_2_args_u.rev1;
		if (v2_args == NULL) {
			return (FALSE);
		}
		break;
	default:
		return (FALSE);
	}

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, v2_args->cl_sk, ep))
		return (TRUE);

	/* doit */
	imp_adddrvs(v2_args->sp->setname, v2_args->drivedescs,
	    v2_args->timestamp, v2_args->genid, ep);

	err = svc_fini(ep);

	return (TRUE);
}

static void
addhosts(
	char		*setname,
	int		node_c,
	char		**node_v,
	int		version,	/* RPC version of calling routine */
	md_error_t	*ep
)
{
	mddb_userreq_t		req;
	md_set_record		*sr;
	int			i, j;
	md_mnset_record		*mnsr;
	md_mnnode_record	*nr;
	mddb_set_node_params_t	snp;
	int			nodecnt;
	mndiskset_membershiplist_t *nl, *nl2;

	if ((sr = getsetbyname(setname, ep)) == NULL)
		return;

	/* Do MN operation if rpc version supports it and if a MN set */
	if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
		mnsr = (md_mnset_record *)sr;
		/*
		 * Verify nodes are in membership list on THIS node.
		 * Initiating node has verified that nodes are in membership
		 * list on the initiating node.
		 * Get membershiplist from API routine.  If there's
		 * an error, fail to add hosts and pass back error.
		 */
		if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
			free_sr(sr);
			return;
		}
		/* Verify that all nodes are in member list */
		for (i = 0; i < node_c; i++) {
			/*
			 * If node in list isn't a member of the membership,
			 * just return error.
			 */
			if (meta_is_member(node_v[i], NULL, nl) == 0) {
				meta_free_nodelist(nl);
				(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST,
				    sr->sr_setno, node_v[i], NULL, setname);
				free_sr(sr);
				return;
			}
		}
	}

	for (i = 0; i < node_c; i++) {
		/* Do MN operation if rpc version supports it and if a MN set */
		if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
			mnsr = (md_mnset_record *)sr;
			/* Create the node record */
			(void) memset(&req, 0, sizeof (req));
			METAD_SETUP_NR(MD_DB_CREATE, 0);
			req.ur_size = sizeof (*nr);
			if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL)
			    != 0) {
				(void) mdstealerror(ep, &req.ur_mde);
				meta_free_nodelist(nl);
				free_sr(sr);
				return;
			}

			nr = Zalloc(sizeof (*nr));
			nr->nr_revision = MD_MNNODE_RECORD_REVISION;
			nr->nr_selfid = req.ur_recid;
			nr->nr_ctime = sr->sr_ctime;
			nr->nr_genid = sr->sr_genid;
			nr->nr_flags = MD_MN_NODE_ADD;
			nl2 = nl;
			while (nl2) {
				if (strcmp(nl2->msl_node_name, node_v[i])
				    == 0) {
					nr->nr_nodeid = nl2->msl_node_id;
					break;
				}
				nl2 = nl2->next;
			}

			(void) strcpy(nr->nr_nodename, node_v[i]);

			/*
			 * When a node is added to a MN diskset, set the
			 * nodeid of this node in the md_set structure
			 * in the kernel.
			 */
			if (strcmp(nr->nr_nodename, mynode()) == 0) {
				(void) memset(&snp, 0, sizeof (snp));
				snp.sn_nodeid = nr->nr_nodeid;
				snp.sn_setno = mnsr->sr_setno;
				if (metaioctl(MD_MN_SET_NODEID, &snp,
				    &snp.sn_mde, NULL) != 0) {
					(void) mdstealerror(ep, &snp.sn_mde);
					meta_free_nodelist(nl);
					free_sr(sr);
					return;
				}
			}

			/* Link the node records and fill in in-core data */
			mnnr_cache_add(mnsr, nr);

			SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_HOST,
			    mnsr->sr_setno, nr->nr_nodeid);
		} else {
			for (j = 0; j < MD_MAXSIDES; j++) {
				if (sr->sr_nodes[j][0] != '\0')
					continue;
				(void) strcpy(sr->sr_nodes[j], node_v[i]);
				SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD,
				    SVM_TAG_HOST, sr->sr_setno, j);
				break;
			}
		}
	}
	/* Do MN operation if rpc version supports it and if a MN set */
	if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
		meta_free_nodelist(nl);
	}

	(void) memset(&req, '\0', sizeof (req));

	METAD_SETUP_SR(MD_DB_SETDATA, sr->sr_selfid)

	/* Do MN operation if rpc version supports it and if a MN set */
	if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
		req.ur_size = sizeof (*mnsr);
	} else {
		req.ur_size = sizeof (*sr);
	}
	req.ur_data = (uintptr_t)sr;
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		free_sr(sr);
		return;
	}

	commitset(sr, TRUE, ep);

	free_sr(sr);
}

/*
 * add 1 or more hosts to a set.
 */
bool_t
mdrpc_addhosts_common(
	mdrpc_host_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp,		/* RPC stuff */
	int			version		/* RPC version */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	addhosts(args->sp->setname, args->hosts.hosts_len,
	    args->hosts.hosts_val, version, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_addhosts_1_svc(
	mdrpc_host_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	/* Pass RPC version (METAD_VERSION) to common routine */
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_addhosts_common(args, res, rqstp, METAD_VERSION));
}

bool_t
mdrpc_addhosts_2_svc(
	mdrpc_host_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* Pass RPC version (METAD_VERSION_DEVID) to common routine */
		return (mdrpc_addhosts_common(
		    &args->mdrpc_host_2_args_u.rev1, res,
		    rqstp, METAD_VERSION_DEVID));
	default:
		return (FALSE);
	}
}

static void
createset(
	mdsetname_t		*sp,
	md_node_nm_arr_t	nodes,
	md_timeval32_t		timestamp,
	ulong_t			genid,
	md_error_t		*ep
)
{
	mddb_userreq_t		req;
	md_set_record		*sr;
	int			i;

	(void) memset(&req, 0, sizeof (req));
	METAD_SETUP_SR(MD_DB_CREATE, 0);
	req.ur_size = sizeof (*sr);
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		return;
	}

	sr = Zalloc(sizeof (*sr));

	sr->sr_selfid = req.ur_recid;
	sr->sr_setno = sp->setno;
	(void) strcpy(sr->sr_setname, sp->setname);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_SET, sp->setno,
	    NODEV64);

	(void) meta_smf_enable(META_SMF_DISKSET, NULL);

	for (i = 0; i < MD_MAXSIDES; i++) {
		(void) strcpy(sr->sr_nodes[i], nodes[i]);
		/* Skip empty slots */
		if (sr->sr_nodes[i][0] == '\0')
			continue;
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_HOST, sp->setno,
		    i);
	}

	sr->sr_ctime = timestamp;
	sr->sr_genid = genid;
	sr->sr_revision = MD_SET_RECORD_REVISION;
	sr->sr_flags |= MD_SR_ADD;

	sr->sr_mhiargs = defmhiargs;

	sr_cache_add(sr);

	commitset(sr, TRUE, ep);
}

static void
mncreateset(
	mdsetname_t		*sp,
	md_mnnode_desc		*nodelist,
	md_timeval32_t		timestamp,
	ulong_t			genid,
	md_node_nm_t		master_nodenm,
	int			master_nodeid,
	md_error_t		*ep
)
{
	mddb_userreq_t			req;
	md_mnset_record			*mnsr;
	md_mnnode_record		*nr;
	md_mnnode_desc			*nd;
	mddb_set_node_params_t		snp;
	int				nodecnt;
	mndiskset_membershiplist_t	*nl;

	/*
	 * Validate that nodes in set being created are in the
	 * membership list on THIS node.
	 * Initiating node has verified that nodes are in membership
	 * list on the initiating node.
	 * Get membershiplist from API routine.  If there's
	 * an error, fail to add set and pass back error.
	 */
	if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
		return;
	}
	/* Verify that all nodes are in member list */
	nd = nodelist;
	while (nd) {
		/*
		 * If node in list isn't a member of the membership,
		 * just return error.
		 */
		if (meta_is_member(nd->nd_nodename, 0, nl) == 0) {
			meta_free_nodelist(nl);
			(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST,
			    sp->setno, nd->nd_nodename, NULL, sp->setname);
			return;
		}
		nd = nd->nd_next;
	}
	meta_free_nodelist(nl);

	(void) memset(&req, 0, sizeof (req));
	METAD_SETUP_SR(MD_DB_CREATE, 0);
	req.ur_size = sizeof (*mnsr);
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		return;
	}

	mnsr = Zalloc(sizeof (*mnsr));
	mnsr->sr_selfid = req.ur_recid;
	mnsr->sr_setno = sp->setno;
	(void) strlcpy(mnsr->sr_setname, sp->setname, MD_MAX_SETNAME);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_SET, sp->setno,
	    NODEV64);

	(void) meta_smf_enable(META_SMF_DISKSET | META_SMF_MN_DISKSET, NULL);

	nd = nodelist;
	while (nd) {
		/* Create the node record */
		(void) memset(&req, 0, sizeof (req));
		METAD_SETUP_NR(MD_DB_CREATE, 0);
		req.ur_size = sizeof (*nr);
		if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
			/* Frees mnsr and any alloc'd node records */
			free_sr((struct md_set_record *)mnsr);
			(void) mdstealerror(ep, &req.ur_mde);
			return;
		}

		nr = Zalloc(sizeof (*nr));
		nr->nr_revision = MD_MNNODE_RECORD_REVISION;
		nr->nr_selfid = req.ur_recid;
		nr->nr_ctime = timestamp;
		nr->nr_genid = genid;
		nr->nr_nodeid = nd->nd_nodeid;
		nr->nr_flags = nd->nd_flags;
		(void) strlcpy(nr->nr_nodename, nd->nd_nodename,
		    MD_MAX_NODENAME);

		/* Link the node records and fill in in-core data */
		mnnr_cache_add(mnsr, nr);

		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_HOST, sp->setno,
		    nr->nr_nodeid);

		nd = nd->nd_next;
	}

	/*
	 * For backward compatibility, fill in mynode name
	 * as the only name in the sr_nodes array.  This
	 * allows the pre-MNdiskset code to see that there
	 * is a node in this diskset.  This will keep the
	 * pre-MNdiskset code from removing this set.
	 */
	(void) strlcpy(mnsr->sr_nodes_bw_compat[0], mynode(), MD_MAX_NODENAME);

	mnsr->sr_ctime = timestamp;
	mnsr->sr_genid = genid;
	mnsr->sr_revision = MD_SET_RECORD_REVISION;
	mnsr->sr_flags |= MD_SR_ADD;

	mnsr->sr_flags |= MD_SR_MN;
	strcpy(mnsr->sr_master_nodenm, master_nodenm);
	mnsr->sr_master_nodeid = master_nodeid;

	mnsr->sr_mhiargs = defmhiargs;

	sr_cache_add((struct md_set_record *)mnsr);

	commitset((struct md_set_record *)mnsr, TRUE, ep);

	/*
	 * When a set is created for the first time, the nodelist
	 * will contain this node.
	 * When a node is just being added to a set, the nodelist
	 * will not contain this node.  This node is added to the
	 * set structure with a later call to addhosts.
	 *
	 * So, if the nodelist contains an entry for this node
	 * then set the nodeid of this node in the md_set kernel
	 * data structure.
	 */
	nd = nodelist;
	while (nd) {
		if (strcmp(nd->nd_nodename, mynode()) == 0) {
			break;
		}
		nd = nd->nd_next;
	}
	if (nd) {
		(void) memset(&snp, 0, sizeof (snp));
		snp.sn_nodeid = nd->nd_nodeid;
		snp.sn_setno = sp->setno;
		if (metaioctl(MD_MN_SET_NODEID, &snp, &snp.sn_mde, NULL) != 0) {
			(void) mdstealerror(ep, &snp.sn_mde);
			return;
		}
	}
}

/*
 * create a set on a host
 */
bool_t
mdrpc_createset_common(
	mdrpc_createset_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	char			stringbuf1[MAXPATHLEN];
	char			stringbuf2[MAXPATHLEN];
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* create the arguments for the symlink() and unlink() calls */
	(void) snprintf(stringbuf2, sizeof (stringbuf2), "/dev/md/%s",
	    args->sp->setname);
	(void) snprintf(stringbuf1, sizeof (stringbuf1), "shared/%d",
	    args->sp->setno);

	/*
	 * Since we already verified that the setname was OK, make sure to
	 * cleanup before proceeding.
	 */
	if (unlink(stringbuf2) == -1) {
		if (errno != ENOENT) {
			(void) mdsyserror(ep, errno, stringbuf2);
			return (TRUE);
		}
	}

	/* create the set */
	createset(args->sp, args->nodes, args->timestamp, args->genid, ep);

	if (! mdisok(ep))
		return (TRUE);

	/* create the symlink */
	if (symlink(stringbuf1, stringbuf2) == -1)
		(void) mdsyserror(ep, errno, stringbuf2);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_createset_1_svc(
	mdrpc_createset_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_createset_common(args, res, rqstp));
}

bool_t
mdrpc_createset_2_svc(
	mdrpc_createset_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_createset_common(
		    &args->mdrpc_createset_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

bool_t
mdrpc_mncreateset_common(
	mdrpc_mncreateset_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	char			stringbuf1[MAXPATHLEN];
	char			stringbuf2[MAXPATHLEN];
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* create the arguments for the symlink() and unlink() calls */
	(void) snprintf(stringbuf2, sizeof (stringbuf2), "/dev/md/%s",
	    args->sp->setname);
	(void) snprintf(stringbuf1, sizeof (stringbuf1), "shared/%d",
	    args->sp->setno);

	/*
	 * Since we already verified that the setname was OK, make sure to
	 * cleanup before proceeding.
	 */
	if (unlink(stringbuf2) == -1) {
		if (errno != ENOENT) {
			(void) mdsyserror(ep, errno, stringbuf2);
			return (TRUE);
		}
	}

	/* create the set */
	mncreateset(args->sp, args->nodelist, args->timestamp, args->genid,
	    args->master_nodenm, args->master_nodeid, ep);

	if (! mdisok(ep)) {
		return (TRUE);
	}

	/* create the symlink */
	if (symlink(stringbuf1, stringbuf2) == -1)
		(void) mdsyserror(ep, errno, stringbuf2);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_mncreateset_2_svc(
	mdrpc_mncreateset_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_mncreateset_common(
		    &args->mdrpc_mncreateset_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static void
del_drv_sidenms(
	mdsetname_t	*sp,
	int		version,	/* RPC version of calling routine */
	md_error_t	*ep
)
{
	md_set_record	*sr;
	md_drive_desc	*dd, *p;
	mddrivename_t	*dn;
	mdsetname_t	*local_sp;
	int		i;
	int		rb_mode = 0;

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL)
		return;

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return;

	/* Do MN operation if rpc version supports it and if a MN set */
	if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
		/*
		 * In the multi-node diskset, there are no diskset
		 * entries in the local set for other nodes, so there's
		 * nothing to do.
		 */
		free_sr(sr);
		return;
	}

	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) {
		if (! mdisdserror(ep, MDE_DS_HOSTNOSIDE)) {
			metaflushsetname(sp);
			if (! mdisok(ep)) {
				free_sr(sr);
				return;
			}
			/* we are supposed to have drives!!!! */
			assert(0);
		}
		rb_mode = 1;
		mdclrerror(ep);
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty sides of the diskset */
			if (sr->sr_nodes[i][0] == '\0')
				continue;
			dd = metaget_drivedesc_sideno(sp, i,
			    (MD_BASICNAME_OK | PRINT_FAST), ep);
			/* Got dd, get out of loop */
			if (dd != NULL)
				break;

			/* some error occurred, get out of loop */
			if (! mdisok(ep))
				break;
		}
		/*
		 * At this point, we have one of three possibilities:
		 *	1) dd != NULL (we have found drives using an alternate
		 *	   side.)
		 *	2) dd == NULL (no drives) && mdisok(ep) : assert(0)
		 *	3) dd == NULL (no drives) && ! mdisok(ep) : return
		 *	   error information to caller.
		 */
		if (dd == NULL) {
			metaflushsetname(sp);
			if (! mdisok(ep)) {
				free_sr(sr);
				return;
			}
			/* we are supposed to have drives!!!! */
			assert(0);
		}
	}

	/*
	 * Let's run through each drive descriptor, and delete the
	 * sidename for all sides that are not in the sr_nodes array.
	 * We will ignore errors, cause the empty side may not
	 * have had any names to begin with.
	 */
	for (p = dd; p != NULL; p = p->dd_next) {
		dn = p->dd_dnp;

		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip existing sides of the diskset */
			if (!rb_mode && sr->sr_nodes[i][0] != '\0')
				continue;
			/* An empty side, delete the sidename */
			if (del_name(local_sp, i+SKEW,
			    dn->side_names_key, ep)) {
				if (!mdissyserror(ep, ENOENT)) {
					free_sr(sr);
					return;
				}
				mdclrerror(ep);
			}
		}
	}
	free_sr(sr);
	metaflushsetname(sp);
}

/*
 * delete 1 or more sidenames per drive desc, from the local namespace
 */
bool_t
mdrpc_del_drv_sidenms_common(
	mdrpc_sp_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp,		/* RPC stuff */
	int			version		/* RPC version */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	del_drv_sidenms(args->sp, version, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_del_drv_sidenms_1_svc(
	mdrpc_sp_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	/* Pass RPC version (METAD_VERSION) to common routine */
	return (mdrpc_del_drv_sidenms_common(args, res, rqstp, METAD_VERSION));
}

bool_t
mdrpc_del_drv_sidenms_2_svc(
	mdrpc_sp_2_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* Pass RPC version (METAD_VERSION_DEVID) to common routine */
		return (mdrpc_del_drv_sidenms_common(
		    &args->mdrpc_sp_2_args_u.rev1, res,
		    rqstp, METAD_VERSION_DEVID));
	default:
		return (FALSE);
	}
}

static int
del_sidenamelist(
	md_set_record	*sr,
	mddrivename_t	*dn,
	md_error_t	*ep
)
{
	mdsidenames_t	*sn;
	mdsetname_t	*local_sp;
	md_mnset_record	*mnsr;
	md_mnnode_record *nr;

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL)
		return (-1);

	for (sn = dn->side_names; sn != NULL; sn = sn->next)
		if (MD_MNSET_REC(sr)) {
			mnsr = (struct md_mnset_record *)sr;
			/*
			 * Only delete side name entries for this node
			 * on a multi-node diskset.
			 */
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (nr->nr_nodeid == sn->sideno) {
					if (del_name(local_sp, sn->sideno,
					    dn->side_names_key, ep) == -1)
						mdclrerror(ep); /* ignore err */
					break;
				}
				nr = nr->nr_next;
			}
		} else {
			if (del_name(local_sp, sn->sideno+SKEW,
			    dn->side_names_key, ep) == -1)
				mdclrerror(ep);	/* ignore errors */
		}

	dn->side_names_key = MD_KEYBAD;
	return (0);
}

static void
deldrvs(
	char		*setname,
	md_drive_desc	*dd,
	md_error_t	*ep
)
{
	mdsetname_t	*sp;
	md_set_record	*sr;
	md_drive_record	*dr;
	mddb_userreq_t	req;
	md_drive_desc	*p;
	mddrivename_t	*dn, *dn1;
	side_t		sideno;
	int		i;
	int		rb_mode = 0;
	mdname_t	*np;
	md_dev64_t	dev;
	md_error_t	xep = mdnullerror;
	ddi_devid_t	devid_remote = NULL;
	ddi_devid_t	devid_local = NULL;
	int		devid_same = -1;
	int		using_devid = 0;
	md_mnnode_record	*nr;
	md_mnset_record		*mnsr;

	if ((sp = metasetname(setname, ep)) == NULL)
		return;

	metaflushsetname(sp);

	if ((sideno = getmyside(sp, ep)) == MD_SIDEWILD) {
		if (! mdisdserror(ep, MDE_DS_HOSTNOSIDE))
			return;
		mdclrerror(ep);
		/*
		 * The set record is incomplete, so we need to make note
		 * here so that we can do some special handling later.
		 */
		rb_mode = 1;
	}

	if ((sr = getsetbyname(setname, ep)) == NULL)
		return;

	if (dd->dd_dnp == NULL)
		return;

	/*
	 * The system is either all devid or all
	 * non-devid so we determine this by looking
	 * at the first item in the list.
	 *
	 * For did disks, the dd_dnp->devid is a valid pointer which
	 * points to a '' string of devid.  We need to check this
	 * before set the using_devid.
	 */
	if ((dd->dd_dnp->devid != NULL) && (dd->dd_dnp->devid[0] != '\0') &&
	    (!(MD_MNSET_REC(sr))))
		using_devid = 1;

	for (p = dd; p != NULL; p = p->dd_next) {
		dn = p->dd_dnp;
		devid_remote = NULL;

		if (dn->devid != NULL && (strlen(dn->devid) != 0) &&
		    using_devid) {
			/*
			 * We have a devid so use it
			 */
			(void) devid_str_decode(dn->devid, &devid_remote, NULL);
		}

		/* check to make sure using_devid agrees with reality... */
		if ((using_devid == 1) && (devid_remote == NULL)) {
			/* something went really wrong. Can't process */
			(void) mddserror(ep, MDE_DS_INVALIDDEVID, sp->setno,
			    mynode(), dn->cname, sp->setname);
			return;
		}

		for (dr = sr->sr_drivechain; dr; dr = dr->dr_next) {
			devid_same = -1;

			if (! rb_mode) {
				dn1 = metadrivename_withdrkey(sp, sideno,
				    dr->dr_key, MD_BASICNAME_OK, ep);
				if (dn1 == NULL) {
					free_sr(sr);
					if (devid_remote)
						devid_free(devid_remote);
					return;
				}
			} else {
				/*
				 * Handle special case here where sidenames
				 * from other hosts for this drive may be
				 * in the local mddb, but there is no
				 * sidename entry for this host for this drive.
				 * This could have happened if the node
				 * panic'd between the 2 operations when
				 * adding this node to the set.
				 * So, delete all sidename entries for this
				 * drive.
				 */
				if (MD_MNSET_REC(sr)) {
					mnsr = (struct md_mnset_record *)sr;
					nr = mnsr->sr_nodechain;
					while (nr) {
						/* We delete all dr sides */
						dn1 = metadrivename_withdrkey(
						    sp, nr->nr_nodeid,
						    dr->dr_key,
						    MD_BASICNAME_OK, ep);

						/* if we do, get out of loop */
						if (dn1 != NULL)
							break;

						/* save error for later */
						(void) mdstealerror(&xep, ep);

						mdclrerror(ep);

						nr = nr->nr_next;
					}
				} else {
					/*
					 * Handle special case here
					 * for traditional diskset
					 */
					for (i = 0; i < MD_MAXSIDES; i++) {
						/* We delete all dr sides */
						dn1 = metadrivename_withdrkey(
						    sp, i, dr->dr_key,
						    MD_BASICNAME_OK, ep);

						/* if we do, get out of loop */
						if (dn1 != NULL)
							break;

						/* save error for later */
						(void) mdstealerror(&xep, ep);

						mdclrerror(ep);
					}
				}

				if (dn1 == NULL) {
					(void) mdstealerror(ep, &xep);
					free_sr(sr);
					if (devid_remote)
						devid_free(devid_remote);
					return;
				}

				if (!using_devid)
					mdclrerror(ep);
			}

			if (dn1->devid != NULL && using_devid) {
				if (devid_str_decode(dn1->devid, &devid_local,
				    NULL) == 0) {
					devid_same = devid_compare(devid_remote,
					    devid_local);
					devid_free(devid_local);
				}
			}

			/*
			 * Has the required disk been found - either the devids
			 * match if devid are being used or the actual name of
			 * the disk matches.
			 */
			if ((using_devid && devid_same == 0) ||
			    (!using_devid &&
			    strcmp(dn->cname, dn1->cname) == 0)) {
				uint_t	rep_slice;

				dev = NODEV64;
				np = NULL;
				if (meta_replicaslice(dn1,
				    &rep_slice, &xep) == 0) {
					np = metaslicename(dn1,
					    rep_slice, &xep);
				}

				if (np != NULL)
					dev = np->dev;
				else
					mdclrerror(&xep);
				break;
			}
		}

		if (dr) {
			(void) memset(&req, 0, sizeof (req));
			METAD_SETUP_DR(MD_DB_DELETE, dr->dr_selfid)
			if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL)
			    != 0) {
				(void) mdstealerror(ep, &req.ur_mde);
				if (devid_remote)
					devid_free(devid_remote);
				free_sr(sr);
				return;
			}

			dr_cache_del(sr, dr->dr_selfid);

			if (del_sidenamelist(sr, dn1, ep) == -1) {
				goto out;
			}

			SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE, SVM_TAG_DRIVE,
			    sr->sr_setno, dev);
			SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_DRIVE,
			    MD_LOCAL_SET, dev);

			continue;
		}

		if (devid_remote)
			devid_free(devid_remote);
	}

out:
	commitset(sr, TRUE, ep);

	free_sr(sr);
}

/*
 * delete 1 or more drive records from a host.
 */
bool_t
mdrpc_deldrvs_common(
	mdrpc_drives_2_args_r1	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	deldrvs(args->sp->setname, args->drivedescs, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * version 1 of the remote procedure. This procedure is called if the
 * client is running in version 1. We first convert version 1 arguments
 * into version 2 arguments and then call the common remote procedure.
 */
bool_t
mdrpc_deldrvs_1_svc(
	mdrpc_drives_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	bool_t			retval;
	mdrpc_drives_2_args_r1	v2_args;

	/* allocate memory */
	alloc_newdrvdesc(args->drivedescs, &v2_args.drivedescs);
	(void) memset(res, 0, sizeof (*res));

	/* build args */
	v2_args.cl_sk = args->cl_sk;
	v2_args.sp = args->sp;
	/* convert v1 args to v2 (revision 1) args */
	meta_conv_drvdesc_old2new(args->drivedescs, v2_args.drivedescs);
	v2_args.timestamp = args->timestamp;
	v2_args.genid = args->genid;

	retval = mdrpc_deldrvs_common(&v2_args, res, rqstp);

	free_newdrvdesc(v2_args.drivedescs);

	return (retval);
}

bool_t
mdrpc_deldrvs_2_svc(
	mdrpc_drives_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_deldrvs_common(
		    &args->mdrpc_drives_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static void
delhosts(
	char		*setname,
	int		node_c,
	char		**node_v,
	int		version,	/* RPC version of calling routine */
	md_error_t	*ep
)
{
	mddb_userreq_t		req;
	md_set_record		*sr;
	int			i, j;
	md_mnset_record		*mnsr;
	md_mnnode_record	*nr;

	if ((sr = getsetbyname(setname, ep)) == NULL)
		return;

	for (i = 0; i < node_c; i++) {
		/* Do MN operation if rpc version supports it and if a MN set */
		if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
			mnsr = (struct md_mnset_record *)sr;
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (strcmp(nr->nr_nodename, node_v[i]) == 0) {
					SE_NOTIFY(EC_SVM_CONFIG,
					    ESC_SVM_REMOVE, SVM_TAG_HOST,
					    sr->sr_setno, nr->nr_nodeid);
					(void) memset(&req, '\0', sizeof (req));
					METAD_SETUP_NR(MD_DB_DELETE,
					    nr->nr_selfid);
					if (metaioctl(MD_DB_USERREQ, &req,
					    &req.ur_mde, NULL) != 0) {
						(void) mdstealerror(ep,
						    &req.ur_mde);
						free_sr(sr);
						return;
					}
					mnnr_cache_del(mnsr, nr->nr_selfid);
					break;
				}
				nr = nr->nr_next;
			}
		} else {
			for (j = 0; j < MD_MAXSIDES; j++) {
				if (sr->sr_nodes[j][0] == '\0')
					continue;
				if (strcmp(sr->sr_nodes[j], node_v[i]) != 0)
					continue;
				(void) memset(sr->sr_nodes[j], '\0',
				    sizeof (sr->sr_nodes[j]));
				SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE,
				    SVM_TAG_HOST, sr->sr_setno, j);
				break;
			}
		}
	}

	(void) memset(&req, '\0', sizeof (req));
	METAD_SETUP_SR(MD_DB_SETDATA, sr->sr_selfid)
	/* Do MN operation if rpc version supports it and if a MN set */
	if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
		req.ur_size = sizeof (*mnsr);
	} else {
		req.ur_size = sizeof (*sr);
	}
	req.ur_data = (uintptr_t)sr;
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		free_sr(sr);
		return;
	}

	commitset(sr, TRUE, ep);
	free_sr(sr);
}

/*
 * delete 1 or more a hosts from a set.
 */
bool_t
mdrpc_delhosts_common(
	mdrpc_host_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp,		/* RPC stuff */
	int			version		/* RPC version */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	delhosts(args->sp->setname, args->hosts.hosts_len,
	    args->hosts.hosts_val, version, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_delhosts_1_svc(
	mdrpc_host_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	/* Pass RPC version (METAD_VERSION) to common routine */
	return (mdrpc_delhosts_common(args, res, rqstp, METAD_VERSION));
}

bool_t
mdrpc_delhosts_2_svc(
	mdrpc_host_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* Pass RPC version (METAD_VERSION_DEVID) to common routine */
		return (mdrpc_delhosts_common(
		    &args->mdrpc_host_2_args_u.rev1, res,
		    rqstp, METAD_VERSION_DEVID));
	default:
		return (FALSE);
	}
}

/*
 * delete a set.
 */
bool_t
mdrpc_delset_common(
	mdrpc_sp_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	s_delset(args->sp->setname, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_delset_1_svc(
	mdrpc_sp_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_delset_common(args, res, rqstp));
}

bool_t
mdrpc_delset_2_svc(
	mdrpc_sp_2_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_delset_common(
		    &args->mdrpc_sp_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * return device info
 */
static void
devinfo(
	mdsetname_t		*sp,
	mddrivename_t		*dp,
	mdrpc_devinfo_2_res 	*res,
	md_error_t		*ep
)
{
	mdname_t		*np, *real_np;

	if ((np = metaslicename(dp, MD_SLICE0, ep)) == NULL)
		return;

	if ((real_np = metaname(&sp, np->bname, LOGICAL_DEVICE, ep)) == NULL)
		return;

	res->dev = real_np->dev;
	(void) getdevstamp(dp, (long *)&res->vtime, ep);
	res->enc_devid = meta_get_devid(np->rname);
}

bool_t
mdrpc_devinfo_common(
	mdrpc_devinfo_2_args_r1	*args,
	mdrpc_devinfo_2_res 	*res,
	struct svc_req		*rqstp			/* RPC stuff */
)
{
	int			slice;
	mdname_t		*np;
	mddrivename_t		*dnp = args->drivenamep;
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/*
	 * fix all the drivenamep's in the mdname_t's to
	 * point to the right place.
	 */
	for (slice = 0; (slice < dnp->parts.parts_len); ++slice) {
		if ((np = metaslicename(dnp, slice, ep)) == NULL)
			return (TRUE);
		np->drivenamep = dnp;
	}

	/* doit */
	devinfo(args->sp, dnp, res, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * version 1 of the remote procedure. This procedure is called if the
 * client is running in version 1. We first convert version 1 arguments
 * into version 2 arguments and then call the common remote procedure.
 */
bool_t
mdrpc_devinfo_1_svc(
	mdrpc_devinfo_args	*args,
	mdrpc_devinfo_res 	*res,
	struct svc_req		*rqstp			/* RPC stuff */
)
{
	bool_t			retval;
	mdrpc_devinfo_2_args_r1	v2_args;
	mdrpc_devinfo_2_res	v2_res;

	/* allocate memory */
	v2_args.drivenamep = Zalloc(sizeof (mddrivename_t));
	v2_args.drivenamep->parts.parts_val =
	    Zalloc(sizeof (mdname_t) * args->drivenamep->parts.parts_len);
	(void) memset(res, 0, sizeof (*res));

	/* convert v1 args to v2 (revision 1) args */
	meta_conv_drvname_old2new(args->drivenamep, v2_args.drivenamep);
	retval = mdrpc_devinfo_common(&v2_args, &v2_res, rqstp);

	/*
	 * Fill in the result appropriately.
	 * Since dev_t's for version 2 are 64-bit,
	 * we need to convert them to 32-bit for version 1.
	 */
	res->dev = meta_cmpldev(v2_res.dev);
	res->vtime = v2_res.vtime;
	res->status = v2_res.status;

	free(v2_args.drivenamep);
	free(v2_args.drivenamep->parts.parts_val);

	return (retval);
}

bool_t
mdrpc_devinfo_2_svc(
	mdrpc_devinfo_2_args	*args,
	mdrpc_devinfo_2_res 	*res,
	struct svc_req		*rqstp			/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_devinfo_common(
		    &args->mdrpc_devinfo_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * return device id
 */
static void
mdrpc_get_devid(
	mdsetname_t		*sp,
	mddrivename_t		*dp,
	mdrpc_devid_res 	*res,
	md_error_t		*ep
)
{
	mdname_t	*np;

	if ((np = metaslicename(dp, MD_SLICE0, ep)) == NULL)
		return;

	if (metaname(&sp, np->bname, LOGICAL_DEVICE, ep) == NULL)
		return;

	res->enc_devid = meta_get_devid(np->rname);
}

bool_t
mdrpc_devid_2_svc(
	mdrpc_devid_2_args	*args,
	mdrpc_devid_res 	*res,
	struct svc_req		*rqstp			/* RPC stuff */
)
{
	int			slice;
	mdname_t		*np;
	mddrivename_t		*dnp;
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		dnp = (&(args->mdrpc_devid_2_args_u.rev1))->drivenamep;
		break;
	default:
		return (FALSE);
	}

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/*
	 * fix all the drivenamep's in the mdname_t's to
	 * point to the right place.
	 */
	for (slice = 0; (slice < dnp->parts.parts_len); ++slice) {
		if ((np = metaslicename(dnp, slice, ep)) == NULL)
			return (TRUE);
		np->drivenamep = dnp;
	}

	/* doit */
	mdrpc_get_devid((&(args->mdrpc_devid_2_args_u.rev1))->sp, dnp, res, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * This routine should not be called for a multi-node diskset.
 *
 * The devid support is disabled for MN diskset so this routine
 * will not be called if the set is MN diskset.  The check has
 * been done early in meta_getnextside_devinfo.  However this
 * routine will be called when the devid support for MN set is
 * enabled and check is removed.
 */
bool_t
mdrpc_devinfo_by_devid_2_svc(
	mdrpc_devidstr_args	*args,
	mdrpc_devinfo_2_res	*res,
	struct svc_req	  *rqstp		  /* RPC stuff */
)
{

	char		*devidstr = args->enc_devid;
	md_error_t	*ep = &res->status;
	ddi_devid_t	devid;
	char		*minor_name = NULL;
	int		ret = 0;
	int		err;
	devid_nmlist_t	*disklist = NULL;
	int		op_mode = R_OK;
	mdname_t	*np;
	mdsetname_t	*sp = args->sp;

	/* setup, check permissions */
	(void) memset(res, 0, sizeof (*res));
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	if (devid_str_decode(devidstr, &devid, &minor_name) != 0)
		return (TRUE);

	/*
	 * if we do not have a minor name then look for a character device.
	 * This is because the caller (checkdrive_onnode) expects a character
	 * device to be returned. The other client of this interface is
	 * meta_getnextside_devinfo and this supplies a minor name.
	 */
	if (minor_name == NULL) {
		ret = meta_deviceid_to_nmlist("/dev", devid,
		    DEVID_MINOR_NAME_ALL_CHR, &disklist);
	} else {
		ret = meta_deviceid_to_nmlist("/dev", devid, minor_name,
		    &disklist);
		devid_str_free(minor_name);
	}

	devid_free(devid);
	if (ret != 0) {
		res->dev = NODEV64;
		devid_free_nmlist(disklist);
		return (TRUE);
	}

	np = metaname(&sp, disklist[0].devname, LOGICAL_DEVICE, ep);
	if (np != NULL) {
		mdcinfo_t	*cinfo;
		if ((cinfo = metagetcinfo(np, ep)) != NULL) {
			res->drivername = Strdup(cinfo->dname);
		}
	}

	res->dev = meta_expldev(disklist[0].dev);
	res->devname = strdup(disklist[0].devname);

	devid_free_nmlist(disklist);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * This routine should not be called for a multi-node diskset.
 *
 * The devid support is disabled for MN diskset so this routine
 * will not be called if the set is MN diskset.  The check has
 * been done early in meta_getnextside_devinfo.  However this
 * routine will be called when the devid support for MN set is
 * enabled and check is removed.
 *
 * This function will return the device info attempting to use
 * both the passed in devid and device name.  This is to deal
 * with systems that use multi-path disks but not running mpxio.
 * In this situation meta_deviceid_to_nmlist will return multiple
 * devices.  The orig_devname is used to disambiguate.
 *
 */
bool_t
mdrpc_devinfo_by_devid_name_2_svc(
	mdrpc_devid_name_2_args	*args,
	mdrpc_devinfo_2_res	*res,
	struct svc_req	  *rqstp		  /* RPC stuff */
)
{

	char		*devidstr;
	char		*orig_devname;
	md_error_t	*ep = &res->status;
	ddi_devid_t	devid;
	char		*minor_name = NULL;
	int		ret = 0;
	int		err;
	int		i;
	devid_nmlist_t	*disklist = NULL;
	int		op_mode = R_OK;
	mdname_t	*np;
	mdsetname_t	*sp;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		sp = (&(args->mdrpc_devid_name_2_args_u.rev1))->sp;
		devidstr = (&(args->mdrpc_devid_name_2_args_u.rev1))->enc_devid;
		orig_devname =
		    (&(args->mdrpc_devid_name_2_args_u.rev1))->orig_devname;
		break;
	default:
		return (FALSE);
	}

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	if (devid_str_decode(devidstr, &devid, &minor_name) != 0)
		return (TRUE);

	/*
	 * if we do not have a minor name then look for a character device.
	 * This is because the caller (checkdrive_onnode) expects a character
	 * device to be returned. The other client of this interface is
	 * meta_getnextside_devinfo and this supplies a minor name.
	 */
	if (minor_name == NULL) {
		ret = meta_deviceid_to_nmlist("/dev", devid,
		    DEVID_MINOR_NAME_ALL_CHR, &disklist);
	} else {
		ret = meta_deviceid_to_nmlist("/dev", devid, minor_name,
		    &disklist);
		devid_str_free(minor_name);
	}

	devid_free(devid);
	if (ret != 0) {
		res->dev = NODEV64;
		devid_free_nmlist(disklist);
		return (TRUE);
	}

	/* attempt to match to the device name on the originating node */
	for (i = 0; disklist[i].dev != NODEV; i++) {
		if (strncmp(orig_devname, disklist[i].devname,
		    strlen(disklist[i].devname)) == 0)
			break;
	}

	/* if it's not found then use the first disk in the list */
	if (disklist[i].dev == NODEV)
		i = 0;

	np = metaname(&sp, disklist[i].devname, LOGICAL_DEVICE, ep);
	if (np != NULL) {
		mdcinfo_t	*cinfo;
		if ((cinfo = metagetcinfo(np, ep)) != NULL) {
			res->drivername = Strdup(cinfo->dname);
		}
	}

	res->dev = meta_expldev(disklist[i].dev);
	res->devname = strdup(disklist[i].devname);

	devid_free_nmlist(disklist);

	err = svc_fini(ep);

	return (TRUE);
}

static void
drvused(mdsetname_t *sp, mddrivename_t *dnp, md_error_t *ep)
{
	if (meta_check_drivemounted(sp, dnp, ep))
		return;

	if (meta_check_driveswapped(sp, dnp, ep))
		return;

	if (meta_check_drive_inuse(metasetname(MD_LOCAL_NAME, ep), dnp,
	    TRUE, ep))
		return;

	(void) meta_check_driveinset(sp, dnp, ep);
}

/*
 * determine if a device is in use.
 */
bool_t
mdrpc_drvused_common(
	mdrpc_drvused_2_args_r1	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			slice;
	mdname_t		*np;
	mddrivename_t		*dnp = args->drivenamep;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	if (dnp == NULL) {
		/* no drive pointer specified */
		return (TRUE);
	}
	/*
	 * fix all the drivenamep's in the mdname_t's to
	 * point to the right place.
	 */
	for (slice = 0; (slice < dnp->parts.parts_len); ++slice) {
		if ((np = metaslicename(dnp, slice, ep)) == NULL)
			return (TRUE);
		np->drivenamep = dnp;
	}

	/* doit */
	drvused(args->sp, dnp, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * version 1 of the remote procedure. This procedure is called if the
 * client is running in version 1. We first convert version 1 arguments
 * into version 2 arguments and then call the common remote procedure.
 */
bool_t
mdrpc_drvused_1_svc(
	mdrpc_drvused_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	bool_t			retval;
	mdrpc_drvused_2_args_r1	v2_args;

	/* allocate memory */
	v2_args.drivenamep = Zalloc(sizeof (mddrivename_t));
	v2_args.drivenamep->parts.parts_val =
	    Zalloc(sizeof (mdname_t) * args->drivenamep->parts.parts_len);
	(void) memset(res, 0, sizeof (*res));

	/* build args */
	v2_args.sp = args->sp;
	v2_args.cl_sk = args->cl_sk;

	/* convert v1 args to v2 (revision 1) args */
	meta_conv_drvname_old2new(args->drivenamep, v2_args.drivenamep);
	retval = mdrpc_drvused_common(&v2_args, res, rqstp);

	free(v2_args.drivenamep);
	free(v2_args.drivenamep->parts.parts_val);

	return (retval);
}

bool_t
mdrpc_drvused_2_svc(
	mdrpc_drvused_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_drvused_common(
		    &args->mdrpc_drvused_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * return a set records selected by name or number.
 */
bool_t
mdrpc_getset_common(
	mdrpc_getset_args	*args,
	mdrpc_getset_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* Don't have a setno, so we don't check the lock */
	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	if (args->setname && *args->setname)
		res->sr = setdup(getsetbyname(args->setname, ep));
	else if (args->setno > 0)
		res->sr = setdup(getsetbynum(args->setno, ep));
	else
		res->sr = NULL;

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_getset_1_svc(
	mdrpc_getset_args	*args,
	mdrpc_getset_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_getset_common(args, res, rqstp));
}

bool_t
mdrpc_getset_2_svc(
	mdrpc_getset_2_args	*args,
	mdrpc_getset_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_getset_common(
		    &args->mdrpc_getset_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * return a MN set record selected by name or number.
 */
bool_t
mdrpc_mngetset_common(
	mdrpc_getset_args	*args,
	mdrpc_mngetset_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;
	md_set_record		*sr = NULL;
	md_mnset_record		*mnsr = NULL;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* Don't have a setno, so we don't check the lock */
	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	res->mnsr = NULL;
	if (args->setname && *args->setname)
		sr = getsetbyname(args->setname, ep);
	else if (args->setno > 0)
		sr = getsetbynum(args->setno, ep);

	if ((sr) && (MD_MNSET_REC(sr))) {
		mnsr = (struct md_mnset_record *)sr;
		res->mnsr = mnsetdup(mnsr);
	}

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_mngetset_2_svc(
	mdrpc_getset_2_args	*args,
	mdrpc_mngetset_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_mngetset_common(
		    &args->mdrpc_getset_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static void
upd_setmaster(
	mdsetname_t	*sp,
	md_node_nm_t	master_nodenm,
	int		master_nodeid,
	md_error_t	*ep
)
{
	mdsetname_t	*local_sp;
	md_set_record	*sr;
	md_mnset_record	*mnsr;
	mddb_setmaster_config_t	sm;

	if ((local_sp = metasetname(sp->setname, ep)) == NULL)
		return;

	metaflushsetname(local_sp);

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return;

	if (MD_MNSET_REC(sr)) {
		mnsr = (struct md_mnset_record *)sr;
		strlcpy(mnsr->sr_master_nodenm, master_nodenm,
		    MD_MAX_NODENAME);
		mnsr->sr_master_nodeid = master_nodeid;
		if (master_nodeid != 0) {
			(void) memset(&sm, 0, sizeof (sm));
			sm.c_setno = sp->setno;
			/* Use magic to help protect ioctl against attack. */
			sm.c_magic = MDDB_SETMASTER_MAGIC;
			if (strcmp(master_nodenm, mynode()) == 0) {
				sm.c_current_host_master = 1;
			} else {
				sm.c_current_host_master = 0;
			}
			(void) metaioctl(MD_SETMASTER, &sm, &sm.c_mde, NULL);
			mdclrerror(&sm.c_mde);
		}
	}

out:
	commitset(sr, FALSE, ep);
	free_sr(sr);
}

/*
 * set the master and nodeid in node record
 */
bool_t
mdrpc_mnsetmaster_common(
	mdrpc_mnsetmaster_args	*args,
	mdrpc_generic_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	upd_setmaster(args->sp, args->master_nodenm, args->master_nodeid, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_mnsetmaster_2_svc(
	mdrpc_mnsetmaster_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_mnsetmaster_common(
		    &args->mdrpc_mnsetmaster_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * Join this node to the diskset.
 * Pass stale_flag information to snarf_set so that snarf code
 * can choose a STALE or non-STALE state when starting the set.
 * If master is STALE, any joining node will join a stale set regardless
 * of the number of accessible mddbs.  Also, if master is at 50%
 * accessible replicas and is in the TOOFEW state, don't mark newly
 * joining node as STALE; mark it TOOFEW instead.
 */
static void
joinset(
	mdsetname_t	*sp,
	int		flags,
	md_error_t	*ep
)
{
	mdsetname_t		*local_sp;
	md_drive_desc		*mydd;
	bool_t			stale_bool;
	mddb_block_parm_t	mbp;
	md_error_t		xep = mdnullerror;

	if ((local_sp = metasetname(sp->setname, ep)) == NULL)
		return;

	/*
	 * Start mddoors daemon here.
	 * mddoors itself takes care there will be
	 * only one instance running, so starting it twice won't hurt
	 */
	pclose(popen(MDDOORS, "w"));

	/*
	 * Get latest copy of data.  If a drive was just added causing
	 * nodes to get joined - this drive won't be in the local
	 * name caches drive list yet.
	 */
	metaflushsetname(local_sp);

	mydd = metaget_drivedesc(local_sp, (MD_BASICNAME_OK | PRINT_FAST), ep);
	if (mydd) {
		/*
		 * Causes mddbs to be loaded into the kernel.
		 * Set the force flag so that replica locations can be loaded
		 * into the kernel even if a mediator node was unavailable.
		 * This allows a node to join an MO diskset when there are
		 * sufficient replicas available, but a mediator node
		 * in unavailable.
		 */
		if (setup_db_bydd(local_sp, mydd, TRUE, ep) == -1) {
			/* If ep isn't set for some reason, set it */
			if (mdisok(ep)) {
				(void) mdmddberror(ep, MDE_DB_NOTNOW,
				    (minor_t)NODEV64, sp->setno, 0, NULL);
			}
			return;
		}

		if (flags & MNSET_IS_STALE)
			stale_bool = TRUE;
		else
			stale_bool = FALSE;

		/*
		 * Snarf the set.  No failure has occurred if STALE or
		 * ACCOK error was set.  Otherwise, fail the call setting
		 * a generic error if no error was already set.
		 *
		 * STALE means that set has < 50% mddbs.
		 * ACCOK means that the mediator provided an extra vote.
		 */
		if (snarf_set(local_sp, stale_bool, ep) != 0) {
			if (!(mdismddberror(ep, MDE_DB_STALE)) &&
			    !(mdismddberror(ep, MDE_DB_ACCOK))) {
				return;
			} else if (mdisok(ep)) {
				/* If snarf failed, but no error set - set it */
				(void) mdmddberror(ep, MDE_DB_NOTNOW,
				    (minor_t)NODEV64, sp->setno, 0, NULL);
				return;
			}
		}

		/*
		 * If node is joining during reconfig cycle, then
		 * set mddb_parse to be in blocked state so that
		 * mddb reparse messages are not generated until
		 * the commd has been resumed later in the reconfig
		 * cycle.
		 */
		if (flags & MNSET_IN_RECONFIG) {
			(void) memset(&mbp, 0, sizeof (mbp));
			if (s_ownset(sp->setno, &xep) == MD_SETOWNER_YES) {
				(void) memset(&mbp, 0, sizeof (mbp));
				mbp.c_setno = local_sp->setno;
				mbp.c_blk_flags = MDDB_BLOCK_PARSE;
				if (metaioctl(MD_MN_MDDB_BLOCK, &mbp,
				    &mbp.c_mde, NULL)) {
					mdstealerror(&xep, &mbp.c_mde);
					mde_perror(ep, gettext(
					    "Could not block set %s"),
					    sp->setname);
					return;
				}
			}
			/*
			 * If s_ownset fails and snarf_set succeeded,
			 * then can steal the ownset failure information
			 * and store it into ep. If snarf_set failed,
			 * don't overwrite critical ep information even
			 * if s_ownset failed.
			 */
			if (!mdisok(&xep)) {
				/*
				 * If snarf_set succeeded or snarf_set failed
				 * with MDE_DB_ACCOK (which is set if the
				 * mediator provided the extra vote) then
				 * steal the xep failure information and put
				 * into ep.
				 */
				if (mdisok(ep) ||
				    mdismddberror(ep, MDE_DB_ACCOK)) {
					mdstealerror(ep, &xep);
				}
			}
		}
	}
}

/*
 * Have this node join the set.
 * This is called when a node has been
 * added to a MN diskset that has drives.
 * Also, called when a node is an alive
 * member of a MN diskset and the first
 * drive has been added.
 */
bool_t
mdrpc_joinset_common(
	mdrpc_sp_flags_args	*args,
	mdrpc_generic_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/*
	 * During reconfig, joinset can happen without
	 * locking first.  Turn off reconfig flag before calling
	 * joinset.
	 */
	if (!(args->flags & MNSET_IN_RECONFIG)) {
		if (check_set_lock(op_mode, args->cl_sk, ep))
			return (TRUE);
	}

	/* doit */
	joinset(args->sp, args->flags, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_joinset_2_svc(
	mdrpc_sp_flags_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_joinset_common(
		    &args->mdrpc_sp_flags_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static void
withdrawset(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	mdsetname_t	*my_sp;

	if ((my_sp = metasetname(sp->setname, ep)) == NULL)
		return;

	(void) halt_set(my_sp, ep);
}

/*
 * Have this node withdraw from set.
 * In response to a failure that occurred
 * on the client after a joinset.
 */
bool_t
mdrpc_withdrawset_common(
	mdrpc_sp_args		*args,
	mdrpc_generic_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	withdrawset(args->sp, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_withdrawset_2_svc(
	mdrpc_sp_2_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_withdrawset_common(
		    &args->mdrpc_sp_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static mhd_mhiargs_t *
gtimeout(mdsetname_t *sp, md_error_t *ep)
{
	md_set_record		*sr;
	mhd_mhiargs_t		*mhiargs;

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return (NULL);

	mhiargs = Zalloc(sizeof (*mhiargs));
	*mhiargs = sr->sr_mhiargs;

	free_sr(sr);
	return (mhiargs);
}

/*
 * Get the MH timeout values for this set.
 */
bool_t
mdrpc_gtimeout_common(
	mdrpc_sp_args		*args,
	mdrpc_gtimeout_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	res->mhiargsp = gtimeout(args->sp, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_gtimeout_1_svc(
	mdrpc_sp_args		*args,
	mdrpc_gtimeout_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_gtimeout_common(args, res, rqstp));
}

bool_t
mdrpc_gtimeout_2_svc(
	mdrpc_sp_2_args		*args,
	mdrpc_gtimeout_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_gtimeout_common(
		    &args->mdrpc_sp_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * return the official host name for the callee
 */
/*ARGSUSED*/
bool_t
mdrpc_hostname_common(
	mdrpc_null_args		*args,
	mdrpc_hostname_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	(void) memset(res, 0, sizeof (*res));
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	res->hostname = Strdup(mynode());

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_hostname_1_svc(
	mdrpc_null_args		*args,
	mdrpc_hostname_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	return (mdrpc_hostname_common(args, res, rqstp));
}

bool_t
mdrpc_hostname_2_svc(
	mdrpc_null_args		*args,
	mdrpc_hostname_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	return (mdrpc_hostname_common(args, res, rqstp));
}

/*
 * return a response
 */
/*ARGSUSED*/
bool_t
mdrpc_nullproc_common(
	void		*args,
	md_error_t	*ep,
	struct svc_req	*rqstp		/* RPC stuff */
)
{
	*ep = mdnullerror;
	/* do nothing */
	return (TRUE);
}

bool_t
mdrpc_nullproc_1_svc(
	void		*args,
	md_error_t	*ep,
	struct svc_req	*rqstp		/* RPC stuff */
)
{
	return (mdrpc_nullproc_common(args, ep, rqstp));
}

bool_t
mdrpc_nullproc_2_svc(
	void		*args,
	md_error_t	*ep,
	struct svc_req	*rqstp		/* RPC stuff */
)
{
	return (mdrpc_nullproc_common(args, ep, rqstp));
}

/*
 * determine if the caller owns the set.
 */
bool_t
mdrpc_ownset_common(
	mdrpc_sp_args		*args,
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	if (s_ownset(args->sp->setno, ep))
		res->value = TRUE;
	else
		res->value = FALSE;

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_ownset_1_svc(
	mdrpc_sp_args		*args,
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_ownset_common(args, res, rqstp));
}

bool_t
mdrpc_ownset_2_svc(
	mdrpc_sp_2_args		*args,
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_ownset_common(
		    &args->mdrpc_sp_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static int
setnameok(char *setname, md_error_t *ep)
{
	int			rval = 0;
	struct	stat		statb;
	md_set_record		*sr = NULL;
	char			*setlink = NULL;

	setlink = Strdup("/dev/md/");
	setlink = Realloc(setlink, strlen(setlink) + strlen(setname) + 1);
	(void) strcat(setlink, setname);

	if (lstat(setlink, &statb) == -1) {
		/*
		 * If lstat() fails with ENOENT, setname is OK, if it
		 * fails for other than that, we fail the RPC
		 */
		if (errno == ENOENT) {
			rval = 1;
			goto out;
		}

		(void) mdsyserror(ep, errno, setlink);
		goto out;
	}

	/*
	 * If the lstat() succeeded, then we see what type of object
	 * we are dealing with, if it is a symlink, we do some further
	 * checking, if it is not a symlink, then we return an
	 * indication that the set name is NOT acceptable.
	 */
	if (! S_ISLNK(statb.st_mode))
		goto out;

	/*
	 * We look up the setname to see if there is a set
	 * with that name, if there is, then we return
	 * an indication that the set name is NOT acceptable.
	 */
	if ((sr = getsetbyname(setname, ep)) != NULL)
		goto out;

	if (! mdiserror(ep, MDE_NO_SET))
		goto out;

	mdclrerror(ep);

	rval = 1;
out:
	if (sr != NULL)
		free_sr(sr);
	Free(setlink);
	return (rval);
}

/*
 * Make sure the name of the set is OK.
 */
bool_t
mdrpc_setnameok_common(
	mdrpc_sp_args		*args,	/* device name */
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp	/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	res->value = setnameok(args->sp->setname, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_setnameok_1_svc(
	mdrpc_sp_args		*args,	/* device name */
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp	/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_setnameok_common(args, res, rqstp));
}

bool_t
mdrpc_setnameok_2_svc(
	mdrpc_sp_2_args		*args,	/* device name */
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp	/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_setnameok_common(
		    &args->mdrpc_sp_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * determine if the setnumber we want to share is in use.
 */
bool_t
mdrpc_setnumbusy_common(
	mdrpc_setno_args	*args,
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	md_set_record		*sr = NULL;
	int			err;
	int			op_mode = R_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	if ((sr = getsetbynum(args->setno, ep)) != NULL) {
		res->value = TRUE;
		free_sr(sr);
		return (TRUE);
	}
	res->value = FALSE;
	if (mdiserror(ep, MDE_NO_SET))
		mdclrerror(ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_setnumbusy_1_svc(
	mdrpc_setno_args	*args,
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_setnumbusy_common(args, res, rqstp));
}

bool_t
mdrpc_setnumbusy_2_svc(
	mdrpc_setno_2_args	*args,
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_setnumbusy_common(
		    &args->mdrpc_setno_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static void
stimeout(
	mdsetname_t	*sp,
	mhd_mhiargs_t	*mhiargsp,
	int		version,	/* RPC version of calling routine */
	md_error_t	*ep
)
{
	mddb_userreq_t		req;
	md_set_record		*sr;

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return;

	sr->sr_mhiargs = *mhiargsp;

	(void) memset(&req, '\0', sizeof (req));

	METAD_SETUP_SR(MD_DB_SETDATA, sr->sr_selfid)
	/* Do MN operation if rpc version supports it and if a MN set */
	if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
		req.ur_size = sizeof (struct md_mnset_record);
	} else {
		req.ur_size = sizeof (*sr);
	}
	req.ur_data = (uintptr_t)sr;

	/*
	 * Cluster nodename support
	 * Convert nodename -> nodeid
	 * Don't do this for MN disksets since we've already stored
	 * both the nodeid and name.
	 */
	if ((version == METAD_VERSION) ||
	    ((version == METAD_VERSION_DEVID) && (!(MD_MNSET_REC(sr)))))
		sdssc_cm_sr_nm2nid(sr);

	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		return;
	}

	(void) memset(&req, '\0', sizeof (req));
	METAD_SETUP_SR(MD_DB_COMMIT_ONE, sr->sr_selfid)
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0)
		(void) mdstealerror(ep, &req.ur_mde);

	/*
	 * Cluster nodename support
	 * Convert nodeid -> nodename
	 * Don't do this for MN disksets since we've already stored
	 * both the nodeid and name.
	 */
	if ((version == METAD_VERSION) ||
	    ((version == METAD_VERSION_DEVID) && (!(MD_MNSET_REC(sr)))))
		sdssc_cm_sr_nid2nm(sr);

	free_sr(sr);
}

/*
 * Set MH ioctl timeout values.
 */
bool_t
mdrpc_stimeout_common(
	mdrpc_stimeout_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp,		/* RPC stuff */
	int			version		/* RPC version */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, NULL, ep))
		return (TRUE);

	/* doit */
	stimeout(args->sp, args->mhiargsp, version, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_stimeout_1_svc(
	mdrpc_stimeout_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	/* Pass RPC version (METAD_VERSION) to common routine */
	return (mdrpc_stimeout_common(args, res, rqstp, METAD_VERSION));
}

bool_t
mdrpc_stimeout_2_svc(
	mdrpc_stimeout_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* Pass RPC version (METAD_VERSION_DEVID) to common routine */
		return (mdrpc_stimeout_common(
		    &args->mdrpc_stimeout_2_args_u.rev1, res,
		    rqstp, METAD_VERSION_DEVID));
	default:
		return (FALSE);
	}
}

static void
upd_dr_dbinfo(
	mdsetname_t	*sp,
	md_drive_desc	*dd,
	md_error_t	*ep
)
{
	mdsetname_t	*local_sp;
	md_set_record	*sr;
	md_drive_record	*dr;
	md_drive_desc	*p;
	mddrivename_t	*dn, *dn1;
	ddi_devid_t	devid_remote = NULL;
	ddi_devid_t	devid_local = NULL;
	int		devid_same = -1;
	side_t		sideno;
	int		using_devid = 0;

	if ((local_sp = metasetname(sp->setname, ep)) == NULL)
		return;

	metaflushsetname(local_sp);

	if ((sideno = getmyside(local_sp, ep)) == MD_SIDEWILD)
		return;

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return;

	if (dd->dd_dnp == NULL)
		return;

	/*
	 * The system is either all devid or all
	 * non-devid so we determine this by looking
	 * at the first item in the list.
	 *
	 * For did disks, the dd_dnp->devid is a valid pointer which
	 * points to a '' string of devid.  We need to check this
	 * before set the using_devid.
	 */
	if ((dd->dd_dnp->devid != NULL) && (dd->dd_dnp->devid[0] != '\0') &&
	    (!(MD_MNSET_REC(sr))))
		using_devid = 1;

	for (p = dd; p != NULL; p = p->dd_next) {
		dn = p->dd_dnp;
		devid_remote = NULL;

		if (dn->devid != NULL && (strlen(dn->devid) != 0) &&
		    using_devid) {
			/*
			 * We have a devid so use it.
			 */
			(void) devid_str_decode(dn->devid, &devid_remote, NULL);
		}

		/* check to make sure using_devid agrees with reality... */
		if ((using_devid == 1) && (devid_remote == NULL)) {
			/* something went really wrong. Can't process */
			(void) mddserror(ep, MDE_DS_INVALIDDEVID, sp->setno,
			    mynode(), dn->cname, sp->setname);
			return;
		}

		for (dr = sr->sr_drivechain; dr; dr = dr->dr_next) {
			devid_same = -1;

			dn1 = metadrivename_withdrkey(local_sp, sideno,
			    dr->dr_key, MD_BASICNAME_OK, ep);

			if (dn1 == NULL) {
				if (devid_remote)
					devid_free(devid_remote);
				goto out;
			}

			if (dn1->devid != NULL && using_devid) {
				if (devid_str_decode(dn1->devid, &devid_local,
				    NULL) == 0) {
					devid_same = devid_compare(devid_remote,
					    devid_local);
					devid_free(devid_local);
				}
			}

			if (using_devid && devid_same == 0)
				break;

			if (!using_devid &&
			    strcmp(dn->cname, dn1->cname) == 0)
				break;
		}

		if (dr) {
			/* Adjust the fields in the copy */
			dr->dr_dbcnt = p->dd_dbcnt;
			dr->dr_dbsize = p->dd_dbsize;
		}
		if (devid_remote)
			devid_free(devid_remote);
	}


out:
	commitset(sr, FALSE, ep);
	free_sr(sr);
}

/*
 * update the database count and size field of drive records.
 */
bool_t
mdrpc_upd_dr_dbinfo_common(
	mdrpc_drives_2_args_r1	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	upd_dr_dbinfo(args->sp, args->drivedescs, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * version 1 of the remote procedure. This procedure is called if the
 * client is running in version 1. We first convert version 1 arguments
 * into version 2 arguments and then call the common remote procedure.
 */
bool_t
mdrpc_upd_dr_dbinfo_1_svc(
	mdrpc_drives_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	bool_t			retval;
	mdrpc_drives_2_args_r1	v2_args;

	/* allocate memory */
	alloc_newdrvdesc(args->drivedescs, &v2_args.drivedescs);
	(void) memset(res, 0, sizeof (*res));

	/* build args */
	v2_args.cl_sk = args->cl_sk;
	v2_args.sp = args->sp;
	/* convert v1 args to v2 (revision 1) args */
	meta_conv_drvdesc_old2new(args->drivedescs, v2_args.drivedescs);
	v2_args.timestamp = args->timestamp;
	v2_args.genid = args->genid;

	retval = mdrpc_upd_dr_dbinfo_common(&v2_args, res, rqstp);

	free_newdrvdesc(v2_args.drivedescs);

	return (retval);
}

bool_t
mdrpc_upd_dr_dbinfo_2_svc(
	mdrpc_drives_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_upd_dr_dbinfo_common(
		    &args->mdrpc_drives_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static void
upd_dr_flags(
	mdsetname_t	*sp,
	md_drive_desc	*dd,
	uint_t		new_flags,
	md_error_t	*ep
)
{
	mdsetname_t	*local_sp;
	md_set_record	*sr;
	md_drive_record	*dr;
	md_drive_desc	*p;
	mddrivename_t	*dn, *dn1;
	ddi_devid_t	devid_remote = NULL;
	ddi_devid_t	devid_local = NULL;
	int		devid_same = -1;
	side_t		sideno;
	int		using_devid = 0;

	if ((local_sp = metasetname(sp->setname, ep)) == NULL)
		return;

	metaflushsetname(local_sp);

	if ((sideno = getmyside(local_sp, ep)) == MD_SIDEWILD)
		return;

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return;

	if (dd->dd_dnp == NULL)
		return;

	/*
	 * The system is either all devid or all
	 * non-devid so we determine this by looking
	 * at the first item in the list.
	 *
	 * For did disks, the dd_dnp->devid is a valid pointer which
	 * points to a '' string of devid.  We need to check this
	 * before set the using_devid.
	 */
	if ((dd->dd_dnp->devid != NULL) && (dd->dd_dnp->devid[0] != '\0') &&
	    (!(MD_MNSET_REC(sr))))
		using_devid = 1;

	for (p = dd; p != NULL; p = p->dd_next) {
		dn = p->dd_dnp;
		devid_remote = NULL;

		if (dn->devid != NULL && (strlen(dn->devid) != 0) &&
		    using_devid) {
			/*
			 * We have a devid so use it.
			 */
			(void) devid_str_decode(dn->devid, &devid_remote, NULL);
		}

		/* check to make sure using_devid agrees with reality... */
		if ((using_devid == 1) && (devid_remote == NULL)) {
			/* something went really wrong. Can't process */
			(void) mddserror(ep, MDE_DS_INVALIDDEVID, sp->setno,
			    mynode(), dn->cname, sp->setname);
			return;
		}

		for (dr = sr->sr_drivechain; dr; dr = dr->dr_next) {
			devid_same = -1;

			dn1 = metadrivename_withdrkey(local_sp, sideno,
			    dr->dr_key, MD_BASICNAME_OK, ep);

			if (dn1 == NULL) {
				if (devid_remote)
					devid_free(devid_remote);
				goto out;
			}

			if (dn1->devid != NULL && using_devid) {
				if (devid_str_decode(dn1->devid,
				    &devid_local, NULL) == 0) {
					devid_same = devid_compare(devid_remote,
					    devid_local);
					devid_free(devid_local);
				}
			}

			if (using_devid && devid_same == 0)
				break;

			if (!using_devid &&
			    strcmp(dn->cname, dn1->cname) == 0)
				break;
		}

		if (dr)
			dr->dr_flags = new_flags;
		if (devid_remote)
			devid_free(devid_remote);
	}
out:
	commitset(sr, TRUE, ep);
	free_sr(sr);
}

/*
 * update the database count and size field of drive records.
 */
bool_t
mdrpc_upd_dr_flags_common(
	mdrpc_upd_dr_flags_2_args_r1	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	upd_dr_flags(args->sp, args->drivedescs, args->new_flags, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * version 1 of the remote procedure. This procedure is called if the
 * client is running in version 1. We first convert version 1 arguments
 * into version 2 arguments and then call the common remote procedure.
 */
bool_t
mdrpc_upd_dr_flags_1_svc(
	mdrpc_upd_dr_flags_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	bool_t				retval;
	mdrpc_upd_dr_flags_2_args_r1	v2_args;

	/* allocate memory */
	alloc_newdrvdesc(args->drivedescs, &v2_args.drivedescs);
	(void) memset(res, 0, sizeof (*res));

	/* build args */
	v2_args.cl_sk = args->cl_sk;
	v2_args.sp = args->sp;
	/* convert v1 args to v2 (revision 1) args */
	meta_conv_drvdesc_old2new(args->drivedescs, v2_args.drivedescs);
	v2_args.new_flags = args->new_flags;

	retval = mdrpc_upd_dr_flags_common(&v2_args, res, rqstp);

	free_newdrvdesc(v2_args.drivedescs);

	return (retval);
}

bool_t
mdrpc_upd_dr_flags_2_svc(
	mdrpc_upd_dr_flags_2_args	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_upd_dr_flags_common(
		    &args->mdrpc_upd_dr_flags_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

static void
upd_sr_flags(
	mdsetname_t	*sp,
	uint_t		new_flags,
	md_error_t	*ep
)
{
	md_set_record	*sr;

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return;

	sr->sr_flags = new_flags;
	commitset(sr, TRUE, ep);
	free_sr(sr);
}

/*
 * update the set record flags
 */
bool_t
mdrpc_upd_sr_flags_common(
	mdrpc_upd_sr_flags_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	upd_sr_flags(args->sp, args->new_flags, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_upd_sr_flags_1_svc(
	mdrpc_upd_sr_flags_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	return (mdrpc_upd_sr_flags_common(args, res, rqstp));
}

bool_t
mdrpc_upd_sr_flags_2_svc(
	mdrpc_upd_sr_flags_2_args	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_upd_sr_flags_common(
		    &args->mdrpc_upd_sr_flags_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * upd_nr_flags updates the node records stored in this node's local mddb
 * given a node desciptor list and an action.  upd_nr_flags then commits
 * the node records to the local mddb.
 *
 * nd - A linked list of node descriptors that describes the node records
 *	in this diskset on which the action applies.
 * flag_action: action to be taken on node records that match the nd list.
 *	flag_action can be:
 *		MD_NR_JOIN: set OWN flag in node records
 *		MD_NR_WITHDRAW: reset OWN flag in node records
 *		MD_NR_OK: reset ADD flags and set OK flag in node records
 *		MD_NR_SET: set node record flags based on flags stored in nd
 *
 * Typically, the JOIN, WITHDRAW and OK flag_actions are used when setting
 * all nodes in a diskset to JOIN (add first disk to set), WITHDRAW
 * (remove last disk from set) or OK (after addition of host to set).
 *
 * The SET flag_action is typically used when nodelist contains all nodes
 * in the diskset, but specific nodes have had flag changes.  An example of
 * this would be the join/withdraw of a specific node to/from the set.
 *
 * Ignore the MD_MN_NODE_RB_JOIN flag if set in node record flag.  This
 * flag is used by the client to recover in case of failure and should not
 * be set in the node record flags.
 */
static void
upd_nr_flags(
	mdsetname_t	*sp,
	md_mnnode_desc	*nd,
	uint_t		flag_action,
	md_error_t	*ep
)
{
	mdsetname_t		*local_sp;
	md_set_record		*sr;
	md_mnset_record		*mnsr;
	md_mnnode_desc		*ndp;
	md_mnnode_record	*nrp;

	if ((local_sp = metasetname(sp->setname, ep)) == NULL)
		return;

	metaflushsetname(local_sp);

	if ((sr = getsetbyname(sp->setname, ep)) == NULL)
		return;

	if (!(MD_MNSET_REC(sr))) {
		return;
	}
	mnsr = (struct md_mnset_record *)sr;

	switch (flag_action) {
	case MD_NR_JOIN:
	case MD_NR_WITHDRAW:
	case MD_NR_SET:
	case MD_NR_OK:
	case MD_NR_DEL:
		break;
	default:
		return;
	}

	for (ndp = nd; ndp != NULL; ndp = ndp->nd_next) {
		/* Find matching node record for given node descriptor */
		for (nrp = mnsr->sr_nodechain; nrp != NULL;
		    nrp = nrp->nr_next) {
			if (ndp->nd_nodeid == nrp->nr_nodeid) {
				switch (flag_action) {
				case MD_NR_JOIN:
					nrp->nr_flags |= MD_MN_NODE_OWN;
					break;
				case MD_NR_WITHDRAW:
					nrp->nr_flags &= ~MD_MN_NODE_OWN;
					break;
				case MD_NR_OK:
					nrp->nr_flags &=
					    ~(MD_MN_NODE_ADD | MD_MN_NODE_DEL);
					nrp->nr_flags |= MD_MN_NODE_OK;
					break;
				case MD_NR_DEL:
					nrp->nr_flags &=
					    ~(MD_MN_NODE_OK | MD_MN_NODE_ADD);
					nrp->nr_flags |= MD_MN_NODE_DEL;
					break;
				case MD_NR_SET:
					/* Do not set RB_JOIN flag */
					nrp->nr_flags =
					    ndp->nd_flags & ~MD_MN_NODE_RB_JOIN;
					break;
				}
				break;
			}
		}
	}
out:
	/* Don't increment set genid for node record flag update */
	commitset(sr, FALSE, ep);
	free_sr(sr);
}

/*
 * init/fini wrapper around upd_nr_flags
 */
bool_t
mdrpc_upd_nr_flags_common(
	mdrpc_upd_nr_flags_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/*
	 * During reconfig, node record flags can be updated without
	 * locking first.
	 */
	if (!(args->flags & MNSET_IN_RECONFIG)) {
		if (check_set_lock(op_mode, args->cl_sk, ep))
			return (TRUE);
	}

	/* doit */
	upd_nr_flags(args->sp, args->nodedescs, args->flag_action, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * update the node records using given flag action.
 */
bool_t
mdrpc_upd_nr_flags_2_svc(
	mdrpc_upd_nr_flags_2_args	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_upd_nr_flags_common(
		    &args->mdrpc_upd_nr_flags_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

void
free_sk(md_setkey_t *skp)
{
	Free(skp->sk_setname);
	Free(skp->sk_host);
	Free(skp);
}

void
del_sk(set_t setno)
{
	md_setkey_t	*skp;
	md_setkey_t	*tskp;

	for (skp = tskp = my_svc_sk; skp; tskp = skp, skp = skp->sk_next) {
		if (setno == skp->sk_setno) {
			if (skp == my_svc_sk)
				my_svc_sk = skp->sk_next;
			else
				tskp->sk_next = skp->sk_next;

			Free(skp->sk_setname);
			Free(skp->sk_host);
			Free(skp);
			break;
		}
	}
}

md_setkey_t *
dupsk(md_setkey_t *skp)
{
	md_setkey_t	*tskp;

	tskp = Zalloc(sizeof (md_setkey_t));

	*tskp = *skp;
	tskp->sk_host = Strdup(skp->sk_host);
	tskp->sk_setname = Strdup(skp->sk_setname);

	return (tskp);
}

md_setkey_t *
svc_get_setkey(set_t setno)
{
	md_setkey_t	*skp;

	for (skp = my_svc_sk; skp != NULL; skp = skp->sk_next)
		if (setno == skp->sk_setno)
			return (dupsk(skp));
	return (NULL);
}

void
svc_set_setkey(md_setkey_t *svc_sk)
{
	md_setkey_t	*skp;

	if (my_svc_sk == NULL) {
		my_svc_sk = dupsk(svc_sk);
		return;
	}

	for (skp = my_svc_sk; skp->sk_next != NULL; skp = skp->sk_next)
		assert(svc_sk->sk_setno != skp->sk_setno);

	skp->sk_next = dupsk(svc_sk);
}

/*
 * Unlock the set
 *
 * To unlock the set, the user must have the correct key, once this is verified
 * the set is unlocked and the cached information for the set is flushed.
 */
bool_t
mdrpc_unlock_set_common(
	mdrpc_null_args		*args,
	mdrpc_setlock_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;
	md_setkey_t		*svc_skp;
	md_set_desc		*sd;
	mdsetname_t		*sp;
	int			multi_node = 0;
	md_error_t		xep = mdnullerror;

	/* setup, check permissions */
	(void) memset(res, 0, sizeof (*res));
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/*
	 * Is diskset a MN diskset?
	 * Don't set error from this check since unlock set can be
	 * called after a set has been deleted.
	 */
	if (((sp = metasetnosetname(args->cl_sk->sk_setno, &xep)) != NULL) &&
	    ((sd = metaget_setdesc(sp, &xep)) != NULL)) {
		if ((MD_MNSET_DESC(sd))) {
			multi_node = 1;
		}
	}

	/* Get the set key, if any */
	svc_skp = svc_get_setkey(args->cl_sk->sk_setno);

	/* The set is locked */
	if (svc_skp != NULL) {

		/* Make sure the opener has the right key. */
		if (args->cl_sk->sk_key.tv_sec != svc_skp->sk_key.tv_sec ||
		    args->cl_sk->sk_key.tv_usec != svc_skp->sk_key.tv_usec) {
			(void) mddserror(ep, MDE_DS_ULKSBADKEY,
			    svc_skp->sk_setno, mynode(), svc_skp->sk_host,
			    svc_skp->sk_setname);
			free_sk(svc_skp);
			return (TRUE);
		}

		/* Unlock the set */
		del_sk(args->cl_sk->sk_setno);

		/* Cleanup */
		free_sk(svc_skp);

		goto out;
	}


	/*
	 * It is possible on a MN diskset to attempt to unlock a set that
	 * is unlocked.  This could occur when the metaset or metadb  command
	 * is failing due to another metaset or metadb command running.
	 * So, print no warning for MN disksets.
	 */
	if (multi_node == 0) {
		md_eprintf("Warning: set unlocked when unlock_set called!\n");
	}

out:
	res->cl_sk = svc_get_setkey(args->cl_sk->sk_setno);

	/* Flush the set cache */
	sr_cache_flush_setno(args->cl_sk->sk_setno);

	return (TRUE);
}

bool_t
mdrpc_unlock_set_1_svc(
	mdrpc_null_args		*args,
	mdrpc_setlock_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	return (mdrpc_unlock_set_common(args, res, rqstp));
}

bool_t
mdrpc_unlock_set_2_svc(
	mdrpc_null_args		*args,
	mdrpc_setlock_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	return (mdrpc_unlock_set_common(args, res, rqstp));
}

/*
 * Lock the set
 *
 * If the user does not hand us a key, then we generate a new key and lock the
 * set using this new key that was generated, if the user hands us a key then
 * we use the key to lock the set.
 */
bool_t
mdrpc_lock_set_common(
	mdrpc_null_args		*args,
	mdrpc_setlock_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	md_error_t		xep = mdnullerror;
	int			op_mode = W_OK;
	md_setkey_t		*svc_skp;
	md_setkey_t		new_sk;
	md_set_desc		*sd = NULL;
	mdsetname_t		*sp = NULL;

	/* setup, check permissions */
	(void) memset(res, 0, sizeof (*res));
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	svc_skp = svc_get_setkey(args->cl_sk->sk_setno);

	/* The set is locked */
	if (svc_skp != NULL) {

		/*
		 * This lock request could be for a new diskset, as
		 * such metasetnosetname() may not return anything
		 * useful. Only call it if there is already a key.
		 */
		if ((sp = metasetnosetname(args->cl_sk->sk_setno, ep))
		    != NULL) {
			sd = metaget_setdesc(sp, ep);
		}

		/*
		 * meta_lock() provides local locking for non-MN
		 * disksets. The local lock is held before we call
		 * this RPC function. We should not receive a lock
		 * request from the host which owns the lock. If we
		 * do, release the lock.
		 */
		if (!((sd != NULL) && (MD_MNSET_DESC(sd))) &&
		    (strcmp(svc_skp->sk_host, args->cl_sk->sk_host) == 0)) {
			md_eprintf(
			    "Warning: set locked when lock_set called!\n");

			md_eprintf("Held lock info:\n");

			md_eprintf("\tLock:\n");
			md_eprintf("\t\tSetname: %s\n", svc_skp->sk_setname);
			md_eprintf("\t\tSetno:   %d\n", svc_skp->sk_setno);
			md_eprintf("\t\tHost:    %s\n", svc_skp->sk_host);
			md_eprintf("\t\tKey:     %d/%d %s\n",
			    svc_skp->sk_key.tv_sec, svc_skp->sk_key.tv_usec,
			    ctime((const time_t *)&svc_skp->sk_key.tv_sec));

			/* Unlock set */
			del_sk(svc_skp->sk_setno);
			free_sk(svc_skp);
			svc_skp = NULL;

			md_eprintf("Released lock held by requesting host\n");
		}
	}

	/* The set is unlocked */
	if (svc_skp == NULL) {
		/* If we have been given a key, use it. */
		if (args->cl_sk->sk_key.tv_sec || args->cl_sk->sk_key.tv_usec) {
			svc_set_setkey(args->cl_sk);
			res->cl_sk = svc_get_setkey(args->cl_sk->sk_setno);
			goto out;
		}

		/* We need to lock it, with a new key */
		new_sk = *args->cl_sk;
		if (meta_gettimeofday(&new_sk.sk_key) == -1) {
			(void) mdsyserror(ep, errno, "meta_gettimeofday()");
			mde_perror(&xep, "");
			md_exit(NULL, 1);
		}
		svc_set_setkey(&new_sk);

		res->cl_sk = svc_get_setkey(args->cl_sk->sk_setno);
		goto out;
	}

	/*
	 * If a MN diskset, the lock_set routine is used as a locking
	 * mechanism to keep multiple metaset and/or metadb commads
	 * from interfering with each other.  If two metaset/metadb
	 * commands are issued at the same time - one will complete
	 * and the other command will fail with MDE_DS_NOTNOW_CMD.
	 */
	if ((sd != NULL) && MD_MNSET_DESC(sd)) {
		(void) mddserror(ep, MDE_DS_NOTNOW_CMD,
		    svc_skp->sk_setno, mynode(),
		    svc_skp->sk_host, svc_skp->sk_setname);
		goto out;
	}

	md_eprintf("Warning: set locked when lock_set called!\n");

	md_eprintf("Lock info:\n");

	md_eprintf("\tLock(svc):\n");
	md_eprintf("\t\tSetname: %s\n", svc_skp->sk_setname);
	md_eprintf("\t\tSetno:   %d\n", svc_skp->sk_setno);
	md_eprintf("\t\tHost:    %s\n", svc_skp->sk_host);
	md_eprintf("\t\tKey:     %d/%d %s",
	    svc_skp->sk_key.tv_sec, svc_skp->sk_key.tv_usec,
	    ctime((const time_t *)&svc_skp->sk_key.tv_sec));

	md_eprintf("\tLock(cl):\n");
	md_eprintf("\t\tSetname: %s\n", args->cl_sk->sk_setname);
	md_eprintf("\t\tSetno:   %d\n", args->cl_sk->sk_setno);
	md_eprintf("\t\tHost:    %s\n", args->cl_sk->sk_host);
	md_eprintf("\t\tKey:     %d/%d %s",
	    args->cl_sk->sk_key.tv_sec, args->cl_sk->sk_key.tv_usec,
	    ctime((const time_t *)&args->cl_sk->sk_key.tv_sec));

	/* The set is locked, do we have the key? */
	if (args->cl_sk->sk_key.tv_sec == svc_skp->sk_key.tv_sec &&
	    args->cl_sk->sk_key.tv_usec == svc_skp->sk_key.tv_usec) {
		res->cl_sk = svc_get_setkey(args->cl_sk->sk_setno);
		goto out;
	}

	/*
	 * The set is locked and we do not have the key, so we set up an error.
	 */
	(void) mddserror(ep, MDE_DS_LKSBADKEY, svc_skp->sk_setno, mynode(),
	    svc_skp->sk_host, args->cl_sk->sk_setname);

out:
	if (svc_skp != NULL)
		free_sk(svc_skp);

	/* Flush the set cache */
	sr_cache_flush_setno(args->cl_sk->sk_setno);

	return (TRUE);
}

bool_t
mdrpc_lock_set_1_svc(
	mdrpc_null_args		*args,
	mdrpc_setlock_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	return (mdrpc_lock_set_common(args, res, rqstp));
}

bool_t
mdrpc_lock_set_2_svc(
	mdrpc_null_args		*args,
	mdrpc_setlock_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	return (mdrpc_lock_set_common(args, res, rqstp));
}

static void
updmeds(
	char		*setname,
	md_h_arr_t	*medp,
	int		version,	/* RPC version of calling routine */
	md_error_t	*ep
)
{
	mddb_userreq_t		req;
	md_set_record		*sr;
	mddb_med_parm_t		mp;

	if ((sr = getsetbyname(setname, ep)) == NULL)
		return;

	sr->sr_med = *medp;			/* structure assignment */

	(void) memset(&req, '\0', sizeof (req));

	METAD_SETUP_SR(MD_DB_SETDATA, sr->sr_selfid)
	/* Do MN operation if rpc version supports it and if a MN set */
	if ((version != METAD_VERSION) && (MD_MNSET_REC(sr))) {
		req.ur_size = sizeof (struct md_mnset_record);
	} else {
		req.ur_size = sizeof (*sr);
	}
	req.ur_data = (uintptr_t)sr;
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		free_sr(sr);
		return;
	}

	commitset(sr, TRUE, ep);

	/*
	 * If a MN disket, send the mediator list to the kernel.
	 */
	if (MD_MNSET_REC(sr)) {
		(void) memset(&mp, '\0', sizeof (mddb_med_parm_t));
		mp.med_setno = sr->sr_setno;
		if (meta_h2hi(medp, &mp.med, ep)) {
			free_sr(sr);
			return;
		}

		/* Resolve the IP addresses for the host list */
		if (meta_med_hnm2ip(&mp.med, ep)) {
			free_sr(sr);
			return;
		}

		/* If node not yet joined to set, failure is ok. */
		if (metaioctl(MD_MED_SET_LST, &mp, &mp.med_mde, NULL) != 0) {
			if (!mdismddberror(&mp.med_mde, MDE_DB_NOTOWNER)) {
				(void) mdstealerror(ep, &mp.med_mde);
			}
		}
	}
	free_sr(sr);
}

/*
 * Update the mediator data in the set record
 */
bool_t
mdrpc_updmeds_common(
	mdrpc_updmeds_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp,		/* RPC stuff */
	int			version		/* RPC version */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	updmeds(args->sp->setname, &args->meds, version, ep);

	err = svc_fini(ep);

	return (TRUE);
}

bool_t
mdrpc_updmeds_1_svc(
	mdrpc_updmeds_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	/* Pass RPC version (METAD_VERSION) to common routine */
	return (mdrpc_updmeds_common(args, res, rqstp, METAD_VERSION));
}

bool_t
mdrpc_updmeds_2_svc(
	mdrpc_updmeds_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* Pass RPC version (METAD_VERSION_DEVID) to common routine */
		return (mdrpc_updmeds_common(
		    &args->mdrpc_updmeds_2_args_u.rev1, res,
		    rqstp, METAD_VERSION_DEVID));
	default:
		return (FALSE);
	}
}

/*
 * Call routines to suspend, reinit and resume mdcommd.
 * Called during metaset and metadb command.
 * NOT called during reconfig cycle.
 */
bool_t
mdrpc_mdcommdctl_2_svc(
	mdrpc_mdcommdctl_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	mdrpc_mdcommdctl_args	*args_cc;
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;
	int			suspend_ret;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* setup, check permissions */
		if ((err = svc_init(rqstp, op_mode, ep)) < 0)
			return (FALSE);
		else if (err != 0)
			return (TRUE);

		args_cc = &(args->mdrpc_mdcommdctl_2_args_u.rev1);
		switch (args_cc->flag_action) {
			case COMMDCTL_SUSPEND:
				suspend_ret = mdmn_suspend(args_cc->setno,
				    args_cc->class, 0);
				if (suspend_ret != 0) {
					(void) mddserror(ep, suspend_ret,
					    args_cc->setno, mynode(),
					    NULL, mynode());
				}
				break;
			case COMMDCTL_RESUME:
				if (mdmn_resume(args_cc->setno,
				    args_cc->class, args_cc->flags, 0)) {
					(void) mddserror(ep,
					    MDE_DS_COMMDCTL_RESUME_FAIL,
					    args_cc->setno, mynode(),
					    NULL, mynode());
				}
				break;
			case COMMDCTL_REINIT:
				if (mdmn_reinit_set(args_cc->setno, 0)) {
					(void) mddserror(ep,
					    MDE_DS_COMMDCTL_REINIT_FAIL,
					    args_cc->setno, mynode(),
					    NULL, mynode());
				}
				break;
		}
		err = svc_fini(ep);
		return (TRUE);

	default:
		return (FALSE);
	}
}

/*
 * Return TRUE if set is stale.
 */
bool_t
mdrpc_mn_is_stale_2_svc(
	mdrpc_setno_2_args	*args,
	mdrpc_bool_res		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t	*ep = &res->status;
	mddb_config_t	c;
	int		err;
	int		op_mode = R_OK;

	(void) memset(res, 0, sizeof (*res));
	(void) memset(&c, 0, sizeof (c));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		c.c_id = 0;
		c.c_setno = args->mdrpc_setno_2_args_u.rev1.setno;

		/* setup, check permissions */
		(void) memset(res, 0, sizeof (*res));
		if ((err = svc_init(rqstp, op_mode, ep)) < 0)
			return (FALSE);
		else if (err != 0)
			return (TRUE);

		if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
			mdstealerror(ep, &c.c_mde);
			return (TRUE);
		}

		if (c.c_flags & MDDB_C_STALE) {
			res->value = TRUE;
		} else {
			res->value = FALSE;
		}

		err = svc_fini(ep);
		return (TRUE);

	default:
		return (FALSE);
	}
}

/*
 * Clear out all clnt_locks held by all MN disksets.
 * This is only used during a reconfig cycle.
 */
/* ARGSUSED */
int
mdrpc_clr_mnsetlock_2_svc(
	mdrpc_null_args		*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	set_t			max_sets, setno;
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;
	mdsetname_t		*sp;

	/* setup, check permissions */
	(void) memset(res, 0, sizeof (*res));

	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/*
	 * Walk through all possible disksets.
	 * For each MN set, delete all keys associated with that set.
	 */
	if ((max_sets = get_max_sets(ep)) == 0) {
		return (TRUE);
	}

	/* start walking through all possible disksets */
	for (setno = 1; setno < max_sets; setno++) {
		if ((sp = metasetnosetname(setno, ep)) == NULL) {
			if (mdiserror(ep, MDE_NO_SET)) {
				/* No set for this setno - continue */
				mdclrerror(ep);
				continue;
			} else {
				mde_perror(ep, gettext(
				    "Unable to get set %s information"),
				    sp->setname);
				mdclrerror(ep);
				continue;
			}
		}

		/* only check multi-node disksets */
		if (!meta_is_mn_set(sp, ep)) {
			mdclrerror(ep);
			continue;
		}

		/* Delete keys associated with rpc.metad clnt_lock */
		del_sk(setno);
	}

	*ep = mdnullerror;

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * Get drive desc on this host for given setno.
 * This is only used during a reconfig cycle.
 * Returns a drive desc structure for the given mdsetname
 * from this host.
 *
 * Returned drive desc structure is partially filled in with
 * the drive name but is not filled in with any other strings
 * in the drivename structure.
 */
bool_t
mdrpc_getdrivedesc_2_svc(
	mdrpc_sp_2_args		*args,
	mdrpc_getdrivedesc_res 	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_drive_desc		*dd;
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;
	mdsetname_t		*my_sp;
	mdrpc_sp_args		*args_r1;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* setup, check permissions */
		if ((err = svc_init(rqstp, op_mode, ep)) < 0)
			return (FALSE);
		else if (err != 0)
			return (TRUE);

		/* doit */
		args_r1 = &args->mdrpc_sp_2_args_u.rev1;
		if ((my_sp = metasetname(args_r1->sp->setname, ep)) == NULL)
			return (TRUE);

		dd = metaget_drivedesc(my_sp,
		    (MD_BASICNAME_OK | PRINT_FAST), ep);

		res->dd = dd_list_dup(dd);

		err = svc_fini(ep);

		return (TRUE);
	default:
		return (FALSE);
	}
}

/*
 * Update drive records given list from master during reconfig.
 * Make this node's list match the master's list which may include
 * deleting a drive record that is known by this node and not known
 * by the master node.
 *
 * Sync up the set/node/drive record genids to match the genid
 * passed in the dd structure (all genids in this structure
 * are the same).
 */
bool_t
mdrpc_upd_dr_reconfig_common(
	mdrpc_upd_dr_flags_2_args_r1	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	mdsetname_t		*local_sp;
	md_set_record		*sr;
	md_mnset_record		*mnsr;
	md_drive_record		*dr, *dr_placeholder = NULL;
	md_drive_desc		*dd;
	mddrivename_t		*dn, *dn1;
	side_t			sideno;
	md_mnnode_record	*nrp;
	int			op_mode = W_OK;
	int			change = 0;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if ((local_sp = metasetname(args->sp->setname, ep)) == NULL)
		return (TRUE);

	metaflushsetname(local_sp);

	if ((sideno = getmyside(local_sp, ep)) == MD_SIDEWILD)
		return (TRUE);

	if ((sr = getsetbyname(args->sp->setname, ep)) == NULL)
		return (TRUE);

	if (!(MD_MNSET_REC(sr))) {
		free_sr(sr);
		return (TRUE);
	}

	mnsr = (md_mnset_record *)sr;
	/* Setup genid on set and node records */
	if (args->drivedescs) {
		if (mnsr->sr_genid != args->drivedescs->dd_genid) {
			change = 1;
			mnsr->sr_genid = args->drivedescs->dd_genid;
		}
		nrp = mnsr->sr_nodechain;
		while (nrp) {
			if (nrp->nr_genid != args->drivedescs->dd_genid) {
				change = 1;
				nrp->nr_genid = args->drivedescs->dd_genid;
			}
			nrp = nrp->nr_next;
		}
	}
	for (dr = mnsr->sr_drivechain; dr; dr = dr->dr_next) {
		dn1 = metadrivename_withdrkey(local_sp, sideno,
		    dr->dr_key, (MD_BASICNAME_OK | PRINT_FAST), ep);
		if (dn1 == NULL)
			goto out;
		for (dd = args->drivedescs; dd != NULL; dd = dd->dd_next) {
			dn = dd->dd_dnp;
			/* Found this node's drive rec to match dd */
			if (strcmp(dn->cname, dn1->cname) == 0)
				break;
		}

		/*
		 * If drive found in master's list, make slave match master.
		 * If drive not found in master's list, remove drive.
		 */
		if (dd) {
			if ((dr->dr_flags != dd->dd_flags) ||
			    (dr->dr_genid != dd->dd_genid)) {
				change = 1;
				dr->dr_flags = dd->dd_flags;
				dr->dr_genid = dd->dd_genid;
			}
		} else {
			/*
			 * Delete entry from linked list.  Need to use
			 * dr_placeholder so that dr->dr_next points to
			 * the next drive record in the list.
			 */
			if (dr_placeholder == NULL) {
				dr_placeholder =
				    Zalloc(sizeof (md_drive_record));
			}
			dr_placeholder->dr_next = dr->dr_next;
			dr_placeholder->dr_key = dr->dr_key;
			sr_del_drv(sr, dr->dr_selfid);
			(void) del_sideno_sidenm(dr_placeholder->dr_key,
			    sideno, ep);
			change = 1;
			dr = dr_placeholder;
		}
	}
out:
	/* If incore records are correct, don't need to write to disk */
	if (change) {
		/* Don't increment the genid in commitset */
		commitset(sr, FALSE, ep);
	}
	free_sr(sr);

	err = svc_fini(ep);

	if (dr_placeholder != NULL)
		Free(dr_placeholder);

	return (TRUE);
}

/*
 * Version 2 routine to update this node's drive records based on
 * list passed in from master node.
 */
bool_t
mdrpc_upd_dr_reconfig_2_svc(
	mdrpc_upd_dr_flags_2_args	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_upd_dr_reconfig_common(
		    &args->mdrpc_upd_dr_flags_2_args_u.rev1, res, rqstp));
	default:
		return (FALSE);
	}
}

/*
 * reset mirror owner for mirrors owned by deleted
 * or withdrawn host(s).  Hosts being deleted or
 * withdrawn are designated by nodeid since host is
 * already deleted or withdrawn from set and may not
 * be able to translate between a nodename and a nodeid.
 * If an error occurs, ep will be set to that error information.
 */
static void
reset_mirror_owner(
	char		*setname,
	int		node_c,
	int		*node_id,	/* Array of node ids */
	md_error_t	*ep
)
{
	mdsetname_t		*local_sp;
	int			i;
	mdnamelist_t		*devnlp = NULL;
	mdnamelist_t		*p;
	mdname_t		*devnp = NULL;
	md_set_mmown_params_t	ownpar_p;
	md_set_mmown_params_t	*ownpar = &ownpar_p;
	char			*miscname;

	if ((local_sp = metasetname(setname, ep)) == NULL)
		return;

	/* get a list of all the mirrors for current set */
	if (meta_get_mirror_names(local_sp, &devnlp, 0, ep) < 0)
		return;

	/* for each mirror */
	for (p = devnlp; (p != NULL); p = p->next) {
		devnp = p->namep;

		/*
		 * we can only do these for mirrors so make sure we
		 * really have a mirror device and not a softpartition
		 * imitating one. meta_get_mirror_names seems to think
		 * softparts on top of a mirror are mirrors!
		 */
		if ((miscname = metagetmiscname(devnp, ep)) == NULL)
			goto out;
		if (strcmp(miscname, MD_MIRROR) != 0)
			continue;

		(void) memset(ownpar, 0, sizeof (*ownpar));
		ownpar->d.mnum = meta_getminor(devnp->dev);
		MD_SETDRIVERNAME(ownpar, MD_MIRROR, local_sp->setno);

		/* get the current owner id */
		if (metaioctl(MD_MN_GET_MM_OWNER, ownpar, ep,
		    "MD_MN_GET_MM_OWNER") != 0) {
			mde_perror(ep, gettext(
			    "Unable to get mirror owner for %s/%s"),
			    local_sp->setname,
			    get_mdname(local_sp, ownpar->d.mnum));
			goto out;
		}

		if (ownpar->d.owner == MD_MN_MIRROR_UNOWNED) {
			mdclrerror(ep);
			continue;
		}
		/*
		 * reset owner only if the current owner is
		 * in the list of nodes being deleted.
		 */
		for (i = 0; i < node_c; i++) {
			if (ownpar->d.owner == node_id[i]) {
				if (meta_mn_change_owner(&ownpar,
				    local_sp->setno, ownpar->d.mnum,
				    MD_MN_MIRROR_UNOWNED,
				    MD_MN_MM_ALLOW_CHANGE) == -1) {
					mde_perror(ep, gettext(
					    "Unable to reset mirror owner for"
					    " %s/%s"), local_sp->setname,
					    get_mdname(local_sp,
					    ownpar->d.mnum));
					goto out;
				}
				break;
			}
		}
	}

out:
	/* cleanup */
	metafreenamelist(devnlp);
}

/*
 * Wrapper routine for reset_mirror_owner.
 * Called when hosts are deleted or withdrawn
 * in order to reset any mirror owners that are needed.
 */
bool_t
mdrpc_reset_mirror_owner_common(
	mdrpc_nodeid_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = W_OK;

	/* setup, check permissions */
	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	if (check_set_lock(op_mode, args->cl_sk, ep))
		return (TRUE);

	/* doit */
	reset_mirror_owner(args->sp->setname, args->nodeid.nodeid_len,
	    args->nodeid.nodeid_val, ep);

	err = svc_fini(ep);

	return (TRUE);
}

/*
 * RPC service routine to reset the mirror owner for mirrors owned
 * by the given hosts.  Typically, the list of given hosts is a list
 * of nodes being deleted or withdrawn from a diskset.
 * The given hosts are designated by nodeid since host may
 * already be deleted or withdrawn from set and may not
 * be able to translate between a nodename and a nodeid.
 */
bool_t
mdrpc_reset_mirror_owner_2_svc(
	mdrpc_nodeid_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		return (mdrpc_reset_mirror_owner_common(
		    &args->mdrpc_nodeid_2_args_u.rev1, res,
		    rqstp));
	default:
		return (FALSE);
	}
}

/*
 * Call routines to suspend and resume I/O for the given diskset(s).
 * Called during reconfig cycle.
 * Diskset of 0 represents all MN disksets.
 */
bool_t
mdrpc_mn_susp_res_io_2_svc(
	mdrpc_mn_susp_res_io_2_args	*args,
	mdrpc_generic_res		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	mdrpc_mn_susp_res_io_args	*args_sr;
	md_error_t			*ep = &res->status;
	int				err;
	int				op_mode = R_OK;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* setup, check permissions */
		if ((err = svc_init(rqstp, op_mode, ep)) < 0)
			return (FALSE);
		else if (err != 0)
			return (TRUE);

		args_sr = &(args->mdrpc_mn_susp_res_io_2_args_u.rev1);
		switch (args_sr->susp_res_cmd) {
		case MN_SUSP_IO:
			(void) (metaioctl(MD_MN_SUSPEND_SET,
			    &args_sr->susp_res_setno, ep, NULL));
			break;
		case MN_RES_IO:
			(void) (metaioctl(MD_MN_RESUME_SET,
			    &args_sr->susp_res_setno, ep, NULL));
			break;
		}
		err = svc_fini(ep);
		return (TRUE);

	default:
		return (FALSE);
	}
}

/*
 * Resnarf a set after it has been imported
 */
bool_t
mdrpc_resnarf_set_2_svc(
	mdrpc_setno_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	mdrpc_setno_args	*setno_args;
	md_error_t		*ep = &res->status;
	int			err;
	int			op_mode = R_OK;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		setno_args = &args->mdrpc_setno_2_args_u.rev1;
		break;
	default:
		return (FALSE);
	}

	if ((err = svc_init(rqstp, op_mode, ep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* do it */
	if (resnarf_set(setno_args->setno, ep) < 0)
		return (FALSE);

	err = svc_fini(ep);
	return (TRUE);
}

/*
 * Creates a resync thread.
 * Always returns true.
 */
bool_t
mdrpc_mn_mirror_resync_all_2_svc(
	mdrpc_setno_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	mdrpc_setno_args	*setno_args;
	int			err;
	int			op_mode = R_OK;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* setup, check permissions */
		if ((err = svc_init(rqstp, op_mode, ep)) < 0)
			return (FALSE);
		else if (err != 0)
			return (TRUE);
		setno_args = &args->mdrpc_setno_2_args_u.rev1;

		/*
		 * Need to invoke a metasync on a node newly added to a set.
		 */
		meta_mn_mirror_resync_all(&(setno_args->setno));

		err = svc_fini(ep);
		return (TRUE);

	default:
		return (FALSE);
	}
}

/*
 * Updates ABR state for all softpartitions. Calls meta_mn_sp_update_abr(),
 * which forks a daemon process to perform this action.
 * Always returns true.
 */
bool_t
mdrpc_mn_sp_update_abr_2_svc(
	mdrpc_setno_2_args	*args,
	mdrpc_generic_res	*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	md_error_t		*ep = &res->status;
	mdrpc_setno_args	*setno_args;
	int			err;
	int			op_mode = R_OK;

	(void) memset(res, 0, sizeof (*res));
	switch (args->rev) {
	case MD_METAD_ARGS_REV_1:
		/* setup, check permissions */
		if ((err = svc_init(rqstp, op_mode, ep)) < 0)
			return (FALSE);
		else if (err != 0)
			return (TRUE);
		setno_args = &args->mdrpc_setno_2_args_u.rev1;

		meta_mn_sp_update_abr(&(setno_args->setno));

		err = svc_fini(ep);
		return (TRUE);

	default:
		return (FALSE);
	}
}
