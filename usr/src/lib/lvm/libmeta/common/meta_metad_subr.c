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
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * interface between user land and the set records
 */

#include <meta.h>
#include <metad.h>
#include <sdssc.h>
#include <syslog.h>
#include <sys/cladm.h>
#include "meta_set_prv.h"

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

static	md_set_record	*setrecords = NULL; /* head of cache linked list */
static	int		setsnarfdone = 0;

typedef struct key_lst_t {
	side_t			kl_side;
	mdkey_t			kl_key;
	struct key_lst_t	*kl_next;
} key_lst_t;

typedef struct ur_recid_lst {
	mddb_recid_t		url_recid;
	struct	ur_recid_lst	*url_nx;
} ur_recid_lst_t;

static ur_recid_lst_t		*url_used = NULL;
static ur_recid_lst_t		*url_tode = NULL;

static void
url_addl(ur_recid_lst_t **urlpp, mddb_recid_t recid)
{
	/* Run to the end of the list */
	for (/* void */; (*urlpp != NULL); urlpp = &(*urlpp)->url_nx)
		if ((*urlpp)->url_recid == recid)
			return;

	/* Add the new member */
	*urlpp = Zalloc(sizeof (**urlpp));
	if (*urlpp == NULL)
		return;

	(*urlpp)->url_recid = recid;
}

static int
url_findl(ur_recid_lst_t *urlp, mddb_recid_t recid)
{
	while (urlp != NULL) {
		if (urlp->url_recid == recid)
			return (1);
		urlp = urlp->url_nx;
	}
	return (0);
}

static void
url_freel(ur_recid_lst_t **urlpp)
{
	ur_recid_lst_t	*urlp;
	ur_recid_lst_t	*turlp;

	for (turlp = *urlpp; turlp != NULL; turlp = urlp) {
		urlp = turlp->url_nx;
		Free(turlp);
	}
	*urlpp = (ur_recid_lst_t *)NULL;
}

static int
ckncvt_set_record(mddb_userreq_t *reqp, md_error_t *ep)
{
	mddb_userreq_t	req;
	md_set_record	*sr;
	int		recs[3];

	if (reqp->ur_size == sizeof (*sr))
		return (0);

	if (! md_in_daemon) {
		if (reqp->ur_size >= sizeof (*sr))
			return (0);

		reqp->ur_data = (uintptr_t)Realloc((void *)(uintptr_t)
		    reqp->ur_data, sizeof (*sr));
		(void) memset(
		    ((char *)(uintptr_t)reqp->ur_data) + reqp->ur_size,
		    '\0', sizeof (*sr) - reqp->ur_size);
		reqp->ur_size = sizeof (*sr);
		return (0);
	}

	/*
	 * If here, then the daemon is calling, and so the automatic
	 * conversion will be performed.
	 */

	/* shorthand */
	req = *reqp;			/* structure assignment */
	sr = (md_set_record *)(uintptr_t)req.ur_data;

	if (sr->sr_flags & MD_SR_CVT)
		return (0);

	/* Leave multi-node set records alone */
	if (MD_MNSET_REC(sr)) {
		return (0);
	}

	/* Mark the old record as converted */
	sr->sr_flags |= MD_SR_CVT;

	METAD_SETUP_SR(MD_DB_SETDATA, sr->sr_selfid)

	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0)
		return (mdstealerror(ep, &req.ur_mde));

	/* Create space for the new record */
	METAD_SETUP_SR(MD_DB_CREATE, 0);
	req.ur_size = sizeof (*sr);

	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0)
		return (mdstealerror(ep, &req.ur_mde));

	/* Allocate the new record */
	sr = Zalloc(sizeof (*sr));

	/* copy all the data from the record being converted */
	(void) memmove(sr, (void *)(uintptr_t)reqp->ur_data, reqp->ur_size);
	sr->sr_flags &= ~MD_SR_CVT;

	/* adjust the selfid to point to the new record */
	sr->sr_selfid = req.ur_recid;

	METAD_SETUP_SR(MD_DB_SETDATA, sr->sr_selfid)
	req.ur_size = sizeof (*sr);
	req.ur_data = (uintptr_t)sr;

	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		Free(sr);
		return (mdstealerror(ep, &req.ur_mde));
	}

	/* Commit the old and the new */
	recs[0] = ((md_set_record *)(uintptr_t)reqp->ur_data)->sr_selfid;
	recs[1] = sr->sr_selfid;
	recs[2] = 0;

	METAD_SETUP_UR(MD_DB_COMMIT_MANY, 0, 0);
	req.ur_size = sizeof (recs);
	req.ur_data = (uintptr_t)recs;

	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		Free(sr);
		return (mdstealerror(ep, &req.ur_mde));
	}

	/* Add the the old record to the list of records to delete */
	url_addl(&url_tode,
	    ((md_set_record *)(uintptr_t)reqp->ur_data)->sr_selfid);

	/* Free the old records space */
	Free((void *)(uintptr_t)reqp->ur_data);

	/* Adjust the reqp structure to point to the new record and size */
	reqp->ur_recid = sr->sr_selfid;
	reqp->ur_size = sizeof (*sr);
	reqp->ur_data = (uintptr_t)sr;

	return (0);
}

mddb_userreq_t *
get_db_rec(
	md_ur_get_cmd_t	cmd,
	set_t		setno,
	mddb_type_t	type,
	uint_t		type2,
	mddb_recid_t	*idp,
	md_error_t	*ep
)
{
	mddb_userreq_t	*reqp = Zalloc(sizeof (*reqp));
	mdsetname_t	*sp;
	md_set_desc	*sd;
	int		ureq;

	if ((sp = metasetnosetname(setno, ep)) == NULL) {
		Free(reqp);
		return (NULL);
	}

	if (metaislocalset(sp)) {
		ureq = MD_DB_USERREQ;
	} else {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			Free(reqp);
			return (NULL);
		}
		ureq = MD_MNSET_DESC(sd) ? MD_MN_DB_USERREQ : MD_DB_USERREQ;
	}

	reqp->ur_setno = setno;
	reqp->ur_type = type;
	reqp->ur_type2 = type2;

	switch (cmd) {
	case MD_UR_GET_NEXT:
		reqp->ur_cmd = MD_DB_GETNEXTREC;
		reqp->ur_recid = *idp;
		if (metaioctl(ureq, reqp, &reqp->ur_mde, NULL) != 0) {
			(void) mdstealerror(ep, &reqp->ur_mde);
			Free(reqp);
			return (NULL);
		}
		*idp = reqp->ur_recid;
		break;
	case MD_UR_GET_WKEY:
		reqp->ur_recid = *idp;
		break;
	}

	if (*idp <= 0) {
		Free(reqp);
		return (NULL);
	}

	reqp->ur_cmd = MD_DB_GETSIZE;
	if (metaioctl(ureq, reqp, &reqp->ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &reqp->ur_mde);
		Free(reqp);

		*idp = 0;
		return (NULL);
	}

	reqp->ur_cmd = MD_DB_GETDATA;
	reqp->ur_data = (uintptr_t)Zalloc(reqp->ur_size);
	if (metaioctl(ureq, reqp, &reqp->ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &reqp->ur_mde);
		Free((void *)(uintptr_t)reqp->ur_data);
		Free(reqp);
		*idp = 0;
		return (NULL);
	}

	switch (reqp->ur_type) {
	case MDDB_USER:
		switch (reqp->ur_type2) {
		case MDDB_UR_SR:
			if (ckncvt_set_record(reqp, ep)) {
				Free((void *)(uintptr_t)reqp->ur_data);
				Free(reqp);
				return (NULL);
			}
			break;
		}
		break;
	}

	return (reqp);
}

void *
get_ur_rec(
	set_t		setno,
	md_ur_get_cmd_t	cmd,
	uint_t		type2,
	mddb_recid_t	*idp,
	md_error_t	*ep
)
{
	mddb_userreq_t	*reqp = NULL;
	void		*ret_val;

	assert(idp != NULL);

	reqp = get_db_rec(cmd, setno, MDDB_USER, type2, idp, ep);
	if (reqp == NULL)
		return (NULL);

	ret_val = (void *)(uintptr_t)reqp->ur_data;
	Free(reqp);
	return (ret_val);
}

/*
 * Called by rpc.metad on startup of disksets to cleanup
 * the host entries associated with a diskset.  This is needed if
 * a node failed or the metaset command was killed during the addition
 * of a node to a diskset.
 *
 * This is called for all traditional disksets.
 * This is only called for MNdisksets when in there is only one node
 * in all of the MN disksets and this node is not running SunCluster.
 * (Otherwise, the cleanup of the host entries is handled by a
 * reconfig cycle that the SunCluster software calls).
 */
static int
sr_hosts(md_set_record *sr)
{
	int		i;
	int		nid = 0;
	int		self_in_set = FALSE;
	md_error_t	xep = mdnullerror;
	md_mnnode_record	*nr;
	md_mnset_record		*mnsr;

	if (MD_MNSET_REC(sr)) {
		mnsr = (struct md_mnset_record *)sr;
		nr = mnsr->sr_nodechain;
		/*
		 * Already guaranteed to be only 1 node in set which
		 * is mynode (done in sr_validate).
		 * Now, check if node is in the OK state.  If not in
		 * the OK state, leave self_in_set FALSE so that
		 * set will be removed.
		 */
		if (nr->nr_flags & MD_MN_NODE_OK)
			self_in_set = TRUE;
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sr->sr_nodes[i][0] == '\0')
				continue;

			/* Make sure we are in the set and skip this node */
			if (strcmp(sr->sr_nodes[i], mynode()) == 0) {
				self_in_set = TRUE;
				break;
			}
		}
	}

	if ((self_in_set == FALSE) && (!(MD_MNSET_REC(sr)))) {
		/*
		 * Under some circumstances (/etc/cluster/nodeid file is
		 * missing) it is possible for the call to _cladm() to
		 * return 0 and a nid of 0. In this instance do not remove
		 * the set as it is Sun Cluster error that needs to be fixed.
		 */
		if (_cladm(CL_CONFIG, CL_NODEID, &nid) == 0 && nid > 0) {

			/*
			 * See if we've got a node which has been booted in
			 * non-cluster mode. If true the nodeid will match
			 * one of the sr_nodes values because the conversion
			 * from nodeid to hostname failed to occur.
			 */
			for (i = 0; i < MD_MAXSIDES; i++) {
				if (sr->sr_nodes[i][0] == 0)
					continue;
				if (atoi(sr->sr_nodes[i]) == nid)
					self_in_set = TRUE;
			}

			/* If we aren't in the set, delete the set */
			if (self_in_set == FALSE) {
				syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
				    "Removing set %s from database\n"),
				    sr->sr_setname);
				s_delset(sr->sr_setname, &xep);
				if (! mdisok(&xep))
					mdclrerror(&xep);
				return (1);
			}
		} else {
			/*
			 * Send a message to syslog and return without
			 * deleting any sets
			 */
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
			    "Call to _cladm failed for set %s nodeid %d\n"),
			    sr->sr_setname, nid);
			return (1);
		}
	}
	return (0);
}

void
sr_del_drv(md_set_record *sr, mddb_recid_t recid)
{
	mddb_userreq_t		req;
	md_error_t		xep = mdnullerror;

	if (!s_ownset(sr->sr_setno, &xep)) {
		if (! mdisok(&xep))
			mdclrerror(&xep);
		goto skip;
	}

	/* delete the replicas? */
	/* release ownership of the drive? */
	/* NOTE: We may not have a name, so both of the above are ugly! */

skip:
	(void) memset(&req, 0, sizeof (req));
	METAD_SETUP_DR(MD_DB_DELETE, recid)
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0)
		mdclrerror(&req.ur_mde);

	dr_cache_del(sr, recid);
}

static void
sr_drvs(md_set_record *sr)
{
	md_drive_record		*dr;
	int			i;
	int			modified = 0;
	int			sidesok;
	mdnm_params_t		nm;
	static	char		device_name[MAXPATHLEN];
	md_error_t		xep = mdnullerror;
	md_mnnode_record	*nr;
	md_mnset_record		*mnsr;

	for (dr = sr->sr_drivechain; dr != NULL; dr = dr->dr_next) {
		/* If we were mid-add, cleanup */
		if ((dr->dr_flags & MD_DR_ADD)) {
			sr_del_drv(sr, dr->dr_selfid);
			modified++;
			continue;
		}

		sidesok = TRUE;
		if (MD_MNSET_REC(sr)) {
			mnsr = (md_mnset_record *)sr;
			nr = mnsr->sr_nodechain;
			/*
			 * MultiNode disksets only have entries for
			 * their side in the local set.  Verify
			 * that drive has a name associated with
			 * this node's side.
			 */
			while (nr) {
				/* Find my node */
				if (strcmp(mynode(), nr->nr_nodename) != 0) {
					nr = nr->nr_next;
					continue;
				}

				(void) memset(&nm, '\0', sizeof (nm));
				nm.setno = MD_LOCAL_SET;
				nm.side = nr->nr_nodeid;
				nm.key = dr->dr_key;
				nm.devname = (uintptr_t)device_name;

				if (metaioctl(MD_IOCGET_NM, &nm, &nm.mde,
				    NULL) != 0) {
					if (! mdissyserror(&nm.mde, ENOENT)) {
						mdclrerror(&nm.mde);
						return;
					}
				}

				/*
				 * If entry is found for this node, then
				 * break out of loop walking through
				 * node list.  For a multi-node diskset,
				 * there should only be an entry for
				 * this node.
				 */
				if (nm.key != MD_KEYWILD &&
				    ! mdissyserror(&nm.mde, ENOENT)) {
					break;
				}

				/*
				 * If entry is not found for this node,
				 * then delete the drive.  No need to
				 * continue through the node loop since
				 * our node has already been found.
				 */
				sidesok = FALSE;
				mdclrerror(&nm.mde);

				/* If we are missing a sidename, cleanup */
				sr_del_drv(sr, dr->dr_selfid);
				modified++;

				break;
			}
		} else  {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sr->sr_nodes[i][0] == '\0')
					continue;

				(void) memset(&nm, '\0', sizeof (nm));
				nm.setno = MD_LOCAL_SET;
				nm.side = i + SKEW;
				nm.key = dr->dr_key;
				nm.devname = (uintptr_t)device_name;

				if (metaioctl(MD_IOCGET_NM, &nm, &nm.mde,
				    NULL) != 0) {
					if (! mdissyserror(&nm.mde, ENOENT)) {
						mdclrerror(&nm.mde);
						return;
					}
				}

				if (nm.key != MD_KEYWILD &&
				    ! mdissyserror(&nm.mde, ENOENT))
					continue;

				sidesok = FALSE;
				mdclrerror(&nm.mde);

				/* If we are missing a sidename, cleanup */
				sr_del_drv(sr, dr->dr_selfid);
				modified++;

				break;
			}
		}

		if (sidesok == FALSE)
			continue;

		/*
		 * If we got this far, the drive record is either in the OK
		 * or DEL state, if it is in the DEL state and the sidenames
		 * all checked out, then we will make it OK.
		 */
		if ((dr->dr_flags & MD_DR_OK))
			continue;

		dr->dr_flags = MD_DR_OK;

		modified++;
	}

	if (modified) {
		commitset(sr, FALSE, &xep);
		if (! mdisok(&xep))
			mdclrerror(&xep);
	}
}

static void
add_key_to_lst(key_lst_t **klpp, side_t side, mdkey_t key)
{
	key_lst_t	*klp;

	assert(klpp != NULL);

	for (/* void */; *klpp != NULL; klpp = &(*klpp)->kl_next)
		/* void */;

	/* allocate new list element */
	klp = *klpp = Zalloc(sizeof (*klp));

	klp->kl_side = side;
	klp->kl_key  = key;
}

#ifdef DUMPKEYLST
static void
pr_key_lst(char *tag, key_lst_t *klp)
{
	key_lst_t	*tklp;

	md_eprintf("Tag=%s\n", tag);
	for (tklp = klp; tklp != NULL; tklp = tklp->kl_next)
		md_eprintf("side=%d, key=%lu\n", tklp->kl_side, tklp->kl_key);
}
#endif	/* DUMPKEYLST */

static int
key_in_key_lst(key_lst_t *klp, side_t side, mdkey_t key)
{
	key_lst_t	*tklp;

	for (tklp = klp; tklp != NULL; tklp = tklp->kl_next)
		if (tklp->kl_side == side && tklp->kl_key == key)
			return (1);

	return (0);
}

static void
destroy_key_lst(key_lst_t **klpp)
{
	key_lst_t	*tklp, *klp;

	assert(klpp != NULL);

	tklp = klp = *klpp;
	while (klp != NULL) {
		tklp = klp;
		klp = klp->kl_next;
		Free(tklp);
	}
	*klpp = NULL;
}

static void
sr_sidenms(void)
{
	md_drive_record		*dr;
	md_set_record		*sr;
	key_lst_t		*use = NULL;
	mdnm_params_t		nm;
	int			i;
	md_mnset_record		*mnsr;
	md_mnnode_record	*nr;
	side_t			myside = 0;

	/*
	 * We now go through the list of set and drive records collecting
	 * the key/side pairs that are being used.
	 */
	for (sr = setrecords; sr != NULL; sr = sr->sr_next) {
		/*
		 * To handle the multi-node diskset case, get the sideno
		 * associated with this node.  This sideno will be the
		 * same across all multi-node disksets.
		 */
		if ((myside == 0) && (MD_MNSET_REC(sr))) {
			mnsr = (struct md_mnset_record *)sr;
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (strcmp(mynode(), nr->nr_nodename) == 0) {
					myside = nr->nr_nodeid;
					break;
				}
				nr = nr->nr_next;
			}
			/*
			 * If this node is not in this MNset -
			 * then skip this set.
			 */
			if (!nr) {
				continue;
			}
		}

		for (dr = sr->sr_drivechain; dr != NULL; dr = dr->dr_next) {
			if (MD_MNSET_REC(sr)) {
				/*
				 * There are no non-local sidenames in the
				 * local set for a multi-node diskset.
				 */
				add_key_to_lst(&use, myside, dr->dr_key);
			} else {
				for (i = 0; i < MD_MAXSIDES; i++) {
					/* Skip empty slots */
					if (sr->sr_nodes[i][0] == '\0')
						continue;

					add_key_to_lst(&use, i + SKEW,
					    dr->dr_key);
				}
			}
		}
	}

#ifdef DUMPKEYLST
	pr_key_lst("use", use);
#endif	/* DUMPKEYLST */

	/*
	 * We take the list above and get all non-local sidenames, checking
	 * each to see if they are in use, if they are not used, we delete them.
	 * Do the check for myside to cover multinode disksets.
	 * Then do the check for MD_MAXSIDES to cover non-multinode disksets.
	 * If any multi-node disksets were present, myside would be non-zero.
	 * myside is the same for all multi-node disksets for this node.
	 */
	if (myside) {
		(void) memset(&nm, '\0', sizeof (nm));
		nm.setno = MD_LOCAL_SET;
		nm.side = myside;
		nm.key = MD_KEYWILD;

		/*CONSTCOND*/
		while (1) {
			if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde,
			    NULL) != 0) {
				mdclrerror(&nm.mde);
				break;
			}

			if (nm.key == MD_KEYWILD)
				break;

			if (! key_in_key_lst(use, nm.side, nm.key)) {
				if (metaioctl(MD_IOCREM_NM, &nm, &nm.mde,
				    NULL) != 0) {
					mdclrerror(&nm.mde);
					continue;
				}
			}
		}
	}
	/* Now handle the non-multinode disksets */
	for (i = 0; i < MD_MAXSIDES; i++) {
		(void) memset(&nm, '\0', sizeof (nm));
		nm.setno = MD_LOCAL_SET;
		nm.side = i + SKEW;
		nm.key = MD_KEYWILD;

		/*CONSTCOND*/
		while (1) {
			if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde,
			    NULL) != 0) {
				mdclrerror(&nm.mde);
				break;
			}

			if (nm.key == MD_KEYWILD)
				break;

			if (! key_in_key_lst(use, nm.side, nm.key)) {
				if (metaioctl(MD_IOCREM_NM, &nm, &nm.mde,
				    NULL) != 0) {
					mdclrerror(&nm.mde);
					continue;
				}
			}
		}
	}

	/* Cleanup */
	destroy_key_lst(&use);
}

void
sr_validate(void)
{
	md_set_record			*sr;
	md_error_t			xep = mdnullerror;
	int				mnset_single_node;
	md_mnnode_record		*nr;
	md_mnset_record			*mnsr;

	assert(setsnarfdone != 0);

	/* We have validated the records already */
	if (setsnarfdone == 3)
		return;

	/*
	 * Check if we are in a single node non-SC3.x environmemnt
	 */
	mnset_single_node = meta_mn_singlenode();
	/*
	 * If a possible single_node situation, verify that all
	 * MN disksets have only one node (which is mynode()).
	 */
	if (mnset_single_node) {
		for (sr = setrecords; sr != NULL; sr = sr->sr_next) {
			if (MD_MNSET_REC(sr)) {
				mnsr = (struct md_mnset_record *)sr;
				nr = mnsr->sr_nodechain;
				/*
				 * If next pointer is non-null (more than
				 * one node in list) or if the single node
				 * isn't my node - reset single node flag.
				 */
				if ((nr->nr_next) ||
				    (strcmp(nr->nr_nodename, mynode()) != 0)) {
					mnset_single_node = 0;
					break;
				}
			}
		}
	}

	for (sr = setrecords; sr != NULL; sr = sr->sr_next) {
		/*
		 * If a MN diskset and not in the single node
		 * situation, then don't validate the MN set.
		 * This is done during a reconfig cycle since all
		 * nodes must take the same action.
		 */
		if (MD_MNSET_REC(sr) && (mnset_single_node == 0))
			continue;

		/* Since we do "partial" snarf's, we only check new entries */
		if (! (sr->sr_flags & MD_SR_CHECK))
			continue;

		/* If we were mid-add, cleanup */
		if ((sr->sr_flags & MD_SR_ADD)) {
			s_delset(sr->sr_setname, &xep);
			if (! mdisok(&xep))
				mdclrerror(&xep);
			continue;
		}

		/* Make sure we are in the set. */
		if (sr_hosts(sr))
			continue;

		/* Check has been done, clear the flag */
		if ((sr->sr_flags & MD_SR_CHECK))
			sr->sr_flags &= ~MD_SR_CHECK;

		/*
		 * If we got here, we are in the set, make sure the flags make
		 * sense.
		 */
		if (! (sr->sr_flags & MD_SR_OK)) {
			sr->sr_flags &= ~MD_SR_STATE_FLAGS;
			sr->sr_flags |= MD_SR_OK;
			commitset(sr, FALSE, &xep);
			if (! mdisok(&xep))
				mdclrerror(&xep);
		}

		/* Make sure all the drives are in a stable state. */
		sr_drvs(sr);
	}

	/* Cleanup any stray sidenames */
	sr_sidenms();

	setsnarfdone = 3;
}

static md_set_record *
sr_in_cache(mddb_recid_t recid)
{
	md_set_record *tsr;

	for (tsr = setrecords; tsr != NULL; tsr = tsr->sr_next)
		if (tsr->sr_selfid == recid)
			return (tsr);
	return ((md_set_record *)NULL);
}

int
set_snarf(md_error_t *ep)
{
	md_set_record			*sr;
	md_mnset_record			*mnsr;
	md_set_record			*tsr;
	md_drive_record			*dr;
	mddb_userreq_t			*reqp;
	ur_recid_lst_t			*urlp;
	mddb_recid_t			id;
	mddb_recid_t			*p;
	md_error_t			xep = mdnullerror;
	md_mnnode_record		*nr;
	mddb_set_node_params_t		snp;
	int				nodecnt;
	mndiskset_membershiplist_t	 *nl, *nl2;

	/* We have done the snarf call */
	if (setsnarfdone != 0)
		return (0);

	if (meta_setup_db_locations(ep) != 0) {
		if (! mdismddberror(ep, MDE_DB_STALE))
			return (-1);
		mdclrerror(ep);
	}

	/*
	 * Get membershiplist from API routine.
	 * If there's an error, just use a NULL
	 * nodelist.
	 */
	if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
		nodecnt = 0;  /* no nodes are alive */
		nl = NULL;
		mdclrerror(ep);
	}

	/* Let sr_cache_add and dr_cache_add know we are doing the snarf */
	setsnarfdone = 1;

	/* Go get the set records */
	id = 0;
	while ((sr = get_ur_rec(MD_LOCAL_SET, MD_UR_GET_NEXT, MDDB_UR_SR,
	    &id, ep)) != NULL) {
		sr->sr_next = NULL;
		sr->sr_drivechain = NULL;

		/*
		 * Cluster nodename support
		 * Convert nodeid -> nodename
		 * Don't do this for MN disksets since we've already stored
		 * both the nodeid and name.
		 */
		if (!(MD_MNSET_REC(sr)))
			sdssc_cm_sr_nid2nm(sr);

		/* If we were mid-cvt, cleanup */
		if (sr->sr_flags & MD_SR_CVT) {
			/* If the daemon is calling, cleanup */
			if (md_in_daemon)
				url_addl(&url_tode, sr->sr_selfid);
			continue;
		}

		if (md_in_daemon)
			url_addl(&url_used, sr->sr_selfid);

		/* Skip cached records */
		tsr = sr_in_cache(sr->sr_selfid);
		if (tsr != (md_set_record *)NULL) {
			if (MD_MNSET_REC(sr)) {
				mnsr = (struct md_mnset_record *)sr;
				Free(mnsr);
			} else {
				Free(sr);
			}
			if (md_in_daemon)
				for (dr = tsr->sr_drivechain;
				    dr != (md_drive_record *)NULL;
				    dr = dr->dr_next)
					url_addl(&url_used, dr->dr_selfid);
			continue;
		}

		/* Mark the record as one to be checked */
		sr->sr_flags |= MD_SR_CHECK;

		sr_cache_add(sr);

		/* If MNdiskset, go get the node records */
		if (MD_MNSET_REC(sr)) {
			mnsr = (struct md_mnset_record *)sr;
			mnsr->sr_nodechain = NULL;
			p = &mnsr->sr_noderec;
			while ((nr = get_ur_rec(MD_LOCAL_SET, MD_UR_GET_WKEY,
			    MDDB_UR_NR, p, ep)) != NULL) {
				nr->nr_next = NULL;

				if (md_in_daemon)
					url_addl(&url_used, nr->nr_selfid);

				/*
				 * Turn off ALIVE node flag based on member
				 * list.
				 * If ALIVE flag is not set, reset OWN flag.
				 * If this node is mynode, set the OWN flag
				 * to match the ownership of the diskset.
				 */
				if (md_in_daemon) {
					nr->nr_flags &= ~MD_MN_NODE_ALIVE;
					nl2 = nl;
					while (nl2) {
						/*
						 * If in member list,
						 * set alive.
						 */
						if (nl2->msl_node_id ==
						    nr->nr_nodeid) {
							nr->nr_flags |=
							    MD_MN_NODE_ALIVE;
							break;
						}
						nl2 = nl2->next;
					}
					/*
					 * If mynode is in member list, then
					 * check to see if set is snarfed.
					 * If set snarfed, set own flag;
					 * otherwise reset it.
					 * Don't change master even if
					 * node isn't an owner node, since
					 * node may be master, but hasn't
					 * joined the set yet.
					 */
					if (nr->nr_flags & MD_MN_NODE_ALIVE) {
					    if (strcmp(nr->nr_nodename,
						mynode()) == 0) {
						    if (s_ownset(
							mnsr->sr_setno, ep)) {
							nr->nr_flags |=
							    MD_MN_NODE_OWN;
						    } else {
							nr->nr_flags &=
							    ~MD_MN_NODE_OWN;
						    }
					    }
					} else {
					    if (strcmp(nr->nr_nodename,
						mynode()) == 0) {
						/*
						 * If my node isn't in member
						 * list then reset master.
						 */
						mnsr = (struct
						    md_mnset_record *)sr;
						mnsr->sr_master_nodeid =
							MD_MN_INVALID_NID;
						mnsr->sr_master_nodenm[0] =
							'\0';
					    }
					    nr->nr_flags &= ~MD_MN_NODE_OWN;
					}
				}

				/*
				 * Must grab nr_nextrec now since
				 * mnnr_cache_add may change it
				 * (mnnr_cache_add is storing the nodes in
				 * an ascending nodeid order list in order
				 * to support reconfig).
				 */
				if (nr->nr_nextrec != 0)
					p = &nr->nr_nextrec;
				else
					p = NULL;

				mnnr_cache_add((struct md_mnset_record *)sr,
				    nr);

				if ((md_in_daemon) &&
				    (strcmp(nr->nr_nodename, mynode()) == 0)) {
					(void) memset(&snp, 0, sizeof (snp));
					snp.sn_nodeid = nr->nr_nodeid;
					snp.sn_setno = mnsr->sr_setno;
					if (metaioctl(MD_MN_SET_NODEID, &snp,
					    &snp.sn_mde, NULL) != 0) {
						(void) mdstealerror(ep,
						    &snp.sn_mde);
					}
				}

				if (p == NULL)
					break;
			}
			if (! mdisok(ep)) {
				if (! mdissyserror(ep, ENOENT))
					goto out;
				mdclrerror(ep);
			}
		}

		if (sr->sr_driverec == 0)
			continue;

		/* Go get the drive records */
		p = &sr->sr_driverec;
		while ((dr = get_ur_rec(MD_LOCAL_SET, MD_UR_GET_WKEY,
		    MDDB_UR_DR, p, ep)) != NULL) {
			dr->dr_next = NULL;

			if (md_in_daemon)
				url_addl(&url_used, dr->dr_selfid);

			dr_cache_add(sr, dr);

			if (dr->dr_nextrec == 0)
				break;

			p = &dr->dr_nextrec;
		}
		if (! mdisok(ep)) {
			if (! mdissyserror(ep, ENOENT))
				goto out;
			mdclrerror(ep);
			/*
			 * If dr_nextrec was not valid, or we had some
			 * problem getting the record, we end up here.
			 * get_ur_rec() zeroes the recid we passed in,
			 * if we had a failure getting a record using a key,
			 * so we simply commit the set record and valid
			 * drive records, if this fails, we hand an error
			 * back to the caller.
			 */
			commitset(sr, FALSE, ep);
			if (! mdisok(ep))
				goto out;
		}
	}
	if (! mdisok(ep)) {
		if (! mdissyserror(ep, ENOENT))
			goto out;
		mdclrerror(ep);
	}

	/*
	 * If the daemon called, go through the USER records and cleanup
	 * any that are not used by valid sets.
	 */
	if (md_in_daemon) {
		id = 0;
		/* Make a list of records to delete */
		while ((reqp = get_db_rec(MD_UR_GET_NEXT, MD_LOCAL_SET,
		    MDDB_USER, 0, &id, ep)) != NULL) {
			if (reqp->ur_type2 != MDDB_UR_SR &&
			    reqp->ur_type2 != MDDB_UR_DR) {
				Free((void *)(uintptr_t)reqp->ur_data);
				Free(reqp);
				continue;
			}
			if (! url_findl(url_used, reqp->ur_recid))
				url_addl(&url_tode, reqp->ur_recid);
			Free((void *)(uintptr_t)reqp->ur_data);
			Free(reqp);
		}
		if (! mdisok(ep)) {
			if (! mdissyserror(ep, ENOENT))
				goto out;
			mdclrerror(ep);
		}

		/* Delete all the delete listed records */
		for (urlp = url_tode; urlp != NULL; urlp = urlp->url_nx) {
			s_delrec(urlp->url_recid, &xep);
			if (! mdisok(&xep))
				mdclrerror(&xep);
		}
	}

	url_freel(&url_used);
	url_freel(&url_tode);

	if (nodecnt)
		meta_free_nodelist(nl);

	/* Mark the snarf complete */
	setsnarfdone = 2;
	return (0);

out:
	url_freel(&url_used);
	url_freel(&url_tode);

	sr_cache_flush(1);

	if (nodecnt)
		meta_free_nodelist(nl);

	/* Snarf failed, reset state */
	setsnarfdone = 0;

	return (-1);
}

void
sr_cache_add(md_set_record *sr)
{
	md_set_record *tsr;

	assert(setsnarfdone != 0);

	if (setrecords == NULL) {
		setrecords = sr;
		return;
	}

	for (tsr = setrecords; tsr->sr_next != NULL; tsr = tsr->sr_next)
		/* void */;
	tsr->sr_next = sr;
}

void
sr_cache_del(mddb_recid_t recid)
{
	md_set_record	*sr, *tsr;
	md_mnset_record	*mnsr;

	assert(setsnarfdone != 0);

	for (sr = tsr = setrecords; sr != NULL; tsr = sr, sr = sr->sr_next) {
		if (sr->sr_selfid != recid)
			continue;
		if (sr == setrecords)
			setrecords = sr->sr_next;
		else
			tsr->sr_next = sr->sr_next;
		if (MD_MNSET_REC(sr)) {
			mnsr = (struct md_mnset_record *)sr;
			Free(mnsr);
		} else {
			Free(sr);
		}
		break;
	}
	if (setrecords == NULL)
		setsnarfdone = 0;
}

void
dr_cache_add(md_set_record *sr, md_drive_record *dr)
{
	md_drive_record	*tdr;

	assert(setsnarfdone != 0);

	assert(sr != NULL);

	if (sr->sr_drivechain == NULL) {
		sr->sr_drivechain = dr;
		sr->sr_driverec = dr->dr_selfid;
		return;
	}

	for (tdr = sr->sr_drivechain; tdr->dr_next != NULL; tdr = tdr->dr_next)
		/* void */;

	tdr->dr_next = dr;
	tdr->dr_nextrec = dr->dr_selfid;
}

void
dr_cache_del(md_set_record *sr, mddb_recid_t recid)
{
	md_drive_record *dr;
	md_drive_record *tdr;

	assert(setsnarfdone != 0);

	assert(sr != NULL);

	for (dr = tdr = sr->sr_drivechain; dr != NULL;
	    tdr = dr, dr = dr->dr_next) {
		if (dr->dr_selfid != recid)
			continue;

		if (dr == sr->sr_drivechain) {
			sr->sr_drivechain = dr->dr_next;
			sr->sr_driverec = dr->dr_nextrec;
		} else {
			tdr->dr_next = dr->dr_next;
			tdr->dr_nextrec = dr->dr_nextrec;
		}
		Free(dr);
		break;
	}
}

/*
 * Nodes must be kept in ascending node id order in order to
 * support reconfig.
 *
 * This routine may change nr->nr_next and nr->nr_nextrec.
 */
void
mnnr_cache_add(md_mnset_record *mnsr, md_mnnode_record *nr)
{
	md_mnnode_record	*tnr, *tnr_prev;

	assert(mnsr != NULL);

	if (mnsr->sr_nodechain == NULL) {
		mnsr->sr_nodechain = nr;
		mnsr->sr_noderec = nr->nr_selfid;
		return;
	}

	/*
	 * If new_record->nodeid < first_record->nodeid,
	 * put new_record at beginning of list.
	 */
	if (nr->nr_nodeid < mnsr->sr_nodechain->nr_nodeid) {
		nr->nr_next = mnsr->sr_nodechain;
		nr->nr_nextrec = mnsr->sr_noderec;
		mnsr->sr_nodechain = nr;
		mnsr->sr_noderec = nr->nr_selfid;
		return;
	}

	/*
	 * Walk list looking for place to insert record.
	 */

	tnr_prev = mnsr->sr_nodechain;
	tnr = tnr_prev->nr_next;
	while (tnr) {
		/* Insert new record between tnr_prev and tnr */
		if (nr->nr_nodeid < tnr->nr_nodeid) {
			nr->nr_next = tnr;
			nr->nr_nextrec = tnr->nr_selfid; /* tnr's recid */
			tnr_prev->nr_next = nr;
			tnr_prev->nr_nextrec = nr->nr_selfid;
			return;
		}
		tnr_prev = tnr;
		tnr = tnr->nr_next;
	}

	/*
	 * Add record to end of list.
	 */
	tnr_prev->nr_next = nr;
	tnr_prev->nr_nextrec = nr->nr_selfid;
}

void
mnnr_cache_del(md_mnset_record *mnsr, mddb_recid_t recid)
{
	md_mnnode_record *nr;
	md_mnnode_record *tnr;

	assert(mnsr != NULL);

	tnr = 0;
	nr = mnsr->sr_nodechain;
	while (nr) {
		if (nr->nr_selfid != recid) {
			tnr = nr;
			nr = nr->nr_next;
			continue;
		}

		if (nr == mnsr->sr_nodechain) {
			mnsr->sr_nodechain = nr->nr_next;
			mnsr->sr_noderec = nr->nr_nextrec;
		} else {
			tnr->nr_next = nr->nr_next;
			tnr->nr_nextrec = nr->nr_nextrec;
		}
		Free(nr);
		break;
	}
}

int
metad_isautotakebyname(char *setname)
{
	md_error_t	error = mdnullerror;
	md_set_record	*sr;

	if (md_in_daemon) {
		assert(setsnarfdone != 0);
	} else if (set_snarf(&error)) {
		mdclrerror(&error);
		return (0);
	}

	for (sr = setrecords; sr != NULL; sr = sr->sr_next) {
		if (strcmp(setname, sr->sr_setname) == 0) {
			if (sr->sr_flags & MD_SR_AUTO_TAKE)
				return (1);
			return (0);
		}
	}

	return (0);
}

int
metad_isautotakebynum(set_t setno)
{
	md_error_t	error = mdnullerror;
	md_set_record	*sr;

	if (md_in_daemon) {
		assert(setsnarfdone != 0);
	} else if (set_snarf(&error)) {
		mdclrerror(&error);
		return (0);
	}

	for (sr = setrecords; sr != NULL; sr = sr->sr_next) {
		if (setno == sr->sr_setno) {
			if (sr->sr_flags & MD_SR_AUTO_TAKE)
				return (1);
			return (0);
		}
	}

	return (0);
}

md_set_record *
metad_getsetbyname(char *setname, md_error_t *ep)
{
	md_set_record	*sr;
	char		buf[100];

	assert(setsnarfdone != 0);

	for (sr = setrecords; sr != NULL; sr = sr->sr_next)
		if (strcmp(setname, sr->sr_setname) == 0)
			return (sr);

	(void) snprintf(buf, sizeof (buf), "setname \"%s\"", setname);
	(void) mderror(ep, MDE_NO_SET, buf);
	return (NULL);
}

md_set_record *
metad_getsetbynum(set_t setno, md_error_t *ep)
{
	md_set_record	*sr;
	char		buf[100];

	if (md_in_daemon)
		assert(setsnarfdone != 0);
	else if (set_snarf(ep))		/* BYPASS DAEMON mode */
		return (NULL);

	for (sr = setrecords; sr != NULL; sr = sr->sr_next)
		if (setno == sr->sr_setno)
			return (sr);

	(void) sprintf(buf, "setno %u", setno);
	(void) mderror(ep, MDE_NO_SET, buf);
	return (NULL);
}


/*
 * Commit the set record and all of its associated records
 * (drive records, node records for a MNset) to the local mddb.
 */
void
commitset(md_set_record *sr, int inc_genid, md_error_t *ep)
{
	int		drc, nrc, rc;
	int		*recs;
	uint_t		size;
	md_drive_record	*dr;
	mddb_userreq_t	req;
	md_mnset_record	*mnsr;
	md_mnnode_record	*nr;

	assert(setsnarfdone != 0);

	/*
	 * Cluster nodename support
	 * Convert nodename -> nodeid
	 * Don't do this for MN disksets since we've already stored
	 * both the nodeid and name.
	 */
	if (!(MD_MNSET_REC(sr)))
		sdssc_cm_sr_nm2nid(sr);

	/* Send down to kernel the data in mddb USER set record */
	if (inc_genid)
		sr->sr_genid++;
	(void) memset(&req, 0, sizeof (req));
	METAD_SETUP_SR(MD_DB_SETDATA, sr->sr_selfid)
	if (MD_MNSET_REC(sr)) {
		req.ur_size = sizeof (*mnsr);
	} else {
		req.ur_size = sizeof (*sr);
	}
	req.ur_data = (uintptr_t)sr;
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		return;
	}

	/*
	 * Walk through the drive records associated with this set record
	 * and send down to kernel the data in mddb USER drive record.
	 */
	drc = 0;
	dr = sr->sr_drivechain;
	while (dr) {
		if (inc_genid)
			dr->dr_genid++;
		METAD_SETUP_DR(MD_DB_SETDATA, dr->dr_selfid)
		req.ur_size = sizeof (*dr);
		req.ur_data = (uintptr_t)dr;
		if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
			(void) mdstealerror(ep, &req.ur_mde);
			return;
		}
		drc++;
		dr = dr->dr_next;
	}


	/*
	 * If this set is a multi-node set -
	 * walk through the node records associated with this set record
	 * and send down to kernel the data in mddb USER node record.
	 */
	nrc = 0;
	if (MD_MNSET_REC(sr)) {
		mnsr = (struct md_mnset_record *)sr;
		nr = mnsr->sr_nodechain;
		while (nr) {
			if (inc_genid)
				nr->nr_genid++;
			METAD_SETUP_NR(MD_DB_SETDATA, nr->nr_selfid)
			req.ur_size = sizeof (*nr);
			req.ur_data = (uint64_t)(uintptr_t)nr;
			if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL)
			    != 0) {
				(void) mdstealerror(ep, &req.ur_mde);
				return;
			}
			nrc++;
			nr = nr->nr_next;
		}
	}

	/*
	 * Set up list of mddb USER recids containing set and drive records
	 * and node records if a MNset.
	 */
	rc = 0;
	size = (nrc + drc + 2) * sizeof (int);
	recs = Zalloc(size);
	/* First recid in list is the set record's id */
	recs[rc] = sr->sr_selfid;
	rc++;
	dr = sr->sr_drivechain;
	while (dr) {
		/* Now, fill in the drive record ids */
		recs[rc] = dr->dr_selfid;
		dr = dr->dr_next;
		rc++;
	}
	if (MD_MNSET_REC(sr)) {
		nr = mnsr->sr_nodechain;
		while (nr) {
			/* If a MNset, fill in the node record ids */
			recs[rc] = nr->nr_selfid;
			nr = nr->nr_next;
			rc++;
		}
	}
	/* Set last record to null recid */
	recs[rc] = 0;

	/* Write out the set and drive and node records to the local mddb */
	METAD_SETUP_UR(MD_DB_COMMIT_MANY, 0, 0);
	req.ur_size = size;
	req.ur_data = (uintptr_t)recs;
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		return;
	}

	/*
	 * Cluster nodename support
	 * Convert nodeid -> nodename
	 * Don't do this for MN disksets since we've already stored
	 * both the nodeid and name.
	 */
	if (!(MD_MNSET_REC(sr)))
		sdssc_cm_sr_nid2nm(sr);

	Free(recs);
}

/*
 * This routine only handles returns a md_set_record structure even
 * if the set record describes a MN set.  This will allow pre-MN
 * SVM RPC code to access a MN set record and to display it.
 *
 * The MN SVM RPC code detects if the set record returned describes
 * a MN set and then will copy it using mnsetdup.
 */
md_set_record *
setdup(md_set_record *sr)
{
	md_set_record		*tsr = NULL;
	md_drive_record		**tdrpp = NULL;

	if (sr && (tsr = Malloc(sizeof (*sr))) != NULL) {
		(void) memmove(tsr, sr, sizeof (*sr));
		tsr->sr_next = NULL;
		tdrpp = &tsr->sr_drivechain;
		while (*tdrpp) {
			*tdrpp = drdup(*tdrpp);
			tdrpp = &(*tdrpp)->dr_next;
		}
	}
	return (tsr);
}

/*
 * This routine only copies MN set records.   If a non-MN set
 * record was passed in NULL pointer will be returned.
 */
md_mnset_record *
mnsetdup(md_mnset_record *mnsr)
{
	md_mnset_record		*tmnsr = NULL;
	md_drive_record		**tdrpp = NULL;
	md_mnnode_record	**tnrpp = NULL;

	if (!MD_MNSET_REC(mnsr)) {
		return (NULL);
	}

	if (mnsr && (tmnsr = Malloc(sizeof (*mnsr))) != NULL) {
		(void) memmove(tmnsr, mnsr, sizeof (*mnsr));
		tmnsr->sr_next = NULL;
		tdrpp = &tmnsr->sr_drivechain;
		while (*tdrpp) {
			*tdrpp = drdup(*tdrpp);
			tdrpp = &(*tdrpp)->dr_next;
		}
		tnrpp = &tmnsr->sr_nodechain;
		while (*tnrpp) {
			*tnrpp = nrdup(*tnrpp);
			tnrpp = &(*tnrpp)->nr_next;
		}
	}
	return (tmnsr);
}

md_drive_record *
drdup(md_drive_record *dr)
{
	md_drive_record		*tdr = NULL;

	if (dr && (tdr = Malloc(sizeof (*dr))) != NULL)
		(void) memmove(tdr, dr, sizeof (*dr));
	return (tdr);
}

md_mnnode_record *
nrdup(md_mnnode_record *nr)
{
	md_mnnode_record	*tnr = NULL;

	if (nr && (tnr = Malloc(sizeof (*nr))) != NULL)
		(void) memmove(tnr, nr, sizeof (*nr));
	return (tnr);
}

/*
 * Duplicate parts of the drive decriptor list for this node.
 * Only duplicate the drive name string in the mddrivename structure, don't
 * need to copy any other pointers since only interested in the flags and
 * the drive name (i.e. other pointers will be set to NULL).
 *	Returns NULL if failure due to Malloc failure.
 *	Returns pointer (non-NULL) to dup'd list if successful.
 */
md_drive_desc *
dd_list_dup(md_drive_desc *dd)
{
	md_drive_desc	*orig_dd;
	md_drive_desc	*copy_dd = NULL, *copy_dd_prev = NULL;
	md_drive_desc	*copy_dd_head = NULL;
	mddrivename_t	*copy_dnp;
	char		*copy_cname;
	char		*copy_devid;

	if (dd == NULL)
		return (NULL);

	orig_dd = dd;

	while (orig_dd) {
		copy_dd = Zalloc(sizeof (*copy_dd));
		copy_dnp = Zalloc(sizeof (mddrivename_t));
		copy_cname = Zalloc(sizeof (orig_dd->dd_dnp->cname));
		if (orig_dd->dd_dnp->devid) {
			copy_devid = Zalloc(sizeof (orig_dd->dd_dnp->devid));
		} else {
			copy_devid = NULL;
		}
		copy_dd->dd_next = NULL;
		if ((copy_dd == NULL) || (copy_dnp == NULL) ||
		    (copy_cname == NULL)) {
			while (copy_dd_head) {
				copy_dd = copy_dd_head->dd_next;
				Free(copy_dd_head);
				copy_dd_head = copy_dd;
			}
			if (copy_dnp)
				Free(copy_dnp);
			if (copy_dd)
				Free(copy_dd);
			if (copy_cname)
				Free(copy_cname);
			if (copy_devid)
				Free(copy_devid);
			return (NULL);
		}
		(void) memmove(copy_dd, orig_dd, sizeof (*orig_dd));
		(void) strlcpy(copy_cname, orig_dd->dd_dnp->cname,
		    sizeof (orig_dd->dd_dnp->cname));
		copy_dd->dd_next = NULL;
		copy_dd->dd_dnp = copy_dnp;
		copy_dd->dd_dnp->cname = copy_cname;
		if (copy_devid) {
			(void) strlcpy(copy_devid, orig_dd->dd_dnp->devid,
			    sizeof (orig_dd->dd_dnp->devid));
		}

		if (copy_dd_prev == NULL) {
			copy_dd_head = copy_dd;
			copy_dd_prev = copy_dd;
		} else {
			copy_dd_prev->dd_next = copy_dd;
			copy_dd_prev = copy_dd;
		}
		orig_dd = orig_dd->dd_next;
	}
	copy_dd->dd_next = NULL;
	return (copy_dd_head);
}

void
sr_cache_flush(int flushnames)
{
	md_set_record	*sr, *tsr;
	md_mnset_record	*mnsr;
	md_drive_record *dr, *tdr;
	md_mnnode_record *nr, *tnr;

	sr = tsr = setrecords;
	while (sr != NULL) {
		dr = tdr = sr->sr_drivechain;
		while (dr != NULL) {
			tdr = dr;
			dr = dr->dr_next;
			Free(tdr);
		}
		tsr = sr;
		sr = sr->sr_next;
		if (MD_MNSET_REC(tsr)) {
			mnsr = (struct md_mnset_record *)tsr;
			nr = tnr = mnsr->sr_nodechain;
			while (nr != NULL) {
				tnr = nr;
				nr = nr->nr_next;
				Free(tnr);
			}
			Free(mnsr);
		} else {
			Free(tsr);
		}
	}

	setrecords = NULL;

	setsnarfdone = 0;

	/* This will cause the other caches to be cleared */
	if (flushnames)
		metaflushnames(0);
}

void
sr_cache_flush_setno(set_t setno)
{
	md_set_record	*sr, *tsr;
	md_mnset_record	*mnsr;
	md_drive_record *dr, *tdr;

	assert(setsnarfdone != 0);

	for (sr = tsr = setrecords; sr; tsr = sr, sr = sr->sr_next) {
		if (sr->sr_setno != setno)
			continue;

		dr = tdr = sr->sr_drivechain;
		while (dr != NULL) {
			tdr = dr;
			dr = dr->dr_next;
			Free(tdr);
		}
		if (sr == setrecords)
			setrecords = sr->sr_next;
		else
			tsr->sr_next = sr->sr_next;
		if (MD_MNSET_REC(sr)) {
			mnsr = (struct md_mnset_record *)sr;
			Free(mnsr);
		} else {
			Free(sr);
		}
		break;
	}

	setsnarfdone = 0;

	/* This will cause the other caches to be cleared */
	metaflushnames(0);
}

int
s_ownset(set_t setno, md_error_t *ep)
{
	mddb_ownset_t		ownset_arg;

	ownset_arg.setno = setno;
	ownset_arg.owns_set = MD_SETOWNER_NONE;

	if (metaioctl(MD_DB_OWNSET, &ownset_arg, ep, NULL) != 0)
		return (0);

	return (ownset_arg.owns_set);
}

void
s_delset(char *setname, md_error_t *ep)
{
	md_set_record		*sr;
	md_set_record		*tsr;
	md_drive_record		*dr;
	md_drive_record		*tdr;
	md_mnnode_record	*nr, *tnr;
	mddb_userreq_t		req;
	char			stringbuf[100];
	int			i;
	mdsetname_t		*sp = NULL;
	mddrivename_t		*dn = NULL;
	mdname_t		*np = NULL;
	md_dev64_t		dev;
	side_t			myside = MD_SIDEWILD;
	md_error_t		xep = mdnullerror;
	md_mnset_record		*mnsr;
	int			num_sets = 0;
	int			num_mn_sets = 0;

	(void) memset(&req, 0, sizeof (mddb_userreq_t));

	if ((sr = getsetbyname(setname, ep)) == NULL)
		return;

	sp = metasetnosetname(sr->sr_setno, &xep);
	mdclrerror(&xep);

	if (MD_MNSET_REC(sr)) {
		/*
		 * If this node is a set owner, halt the set before
		 * deleting the set records.  Ignore any errors since
		 * s_ownset and halt_set could fail if panic had occurred
		 * during the add/delete of a node.
		 */
		if (s_ownset(sr->sr_setno, &xep)) {
			mdclrerror(&xep);
			if (halt_set(sp, &xep))
				mdclrerror(&xep);
		}
	}

	(void) snprintf(stringbuf, sizeof (stringbuf), "/dev/md/%s", setname);
	(void) unlink(stringbuf);
	(void) unlink(meta_lock_name(sr->sr_setno));

	if (MD_MNSET_REC(sr)) {
		mnsr = (struct md_mnset_record *)sr;
		nr = mnsr->sr_nodechain;
		while (nr) {
			/* Setting myside for later use */
			if (strcmp(mynode(), nr->nr_nodename) == 0)
				myside = nr->nr_nodeid;

			(void) memset(&req, 0, sizeof (req));
			METAD_SETUP_NR(MD_DB_DELETE, nr->nr_selfid)
			if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde,
			    NULL) != 0) {
				(void) mdstealerror(ep, &req.ur_mde);
				free_sr(sr);
				return;
			}
			tnr = nr;
			nr = nr->nr_next;

			SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE, SVM_TAG_HOST,
			    sr->sr_setno, tnr->nr_nodeid);

			mnnr_cache_del((struct md_mnset_record *)sr,
			    tnr->nr_selfid);
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sr->sr_nodes[i][0] == '\0')
				continue;

			if (strcmp(mynode(), sr->sr_nodes[i]) == 0)
				myside = i;

			SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE, SVM_TAG_HOST,
			    sr->sr_setno, i);
		}
	}

	dr = sr->sr_drivechain;
	while (dr) {
		(void) memset(&req, 0, sizeof (req));
		METAD_SETUP_DR(MD_DB_DELETE, dr->dr_selfid)
		if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
			(void) mdstealerror(ep, &req.ur_mde);
			free_sr(sr);
			return;
		}
		tdr = dr;
		dr = dr->dr_next;

		dev = NODEV64;
		if (myside != MD_SIDEWILD && sp != NULL) {
			dn = metadrivename_withdrkey(sp, myside,
			    tdr->dr_key, MD_BASICNAME_OK, &xep);
			if (dn != NULL) {
				uint_t	rep_slice;

				np = NULL;
				if (meta_replicaslice(dn, &rep_slice,
				    &xep) == 0) {
					np = metaslicename(dn, rep_slice, &xep);
				}

				if (np != NULL)
					dev = np->dev;
				else
					mdclrerror(&xep);
			} else
				mdclrerror(&xep);
		} else
			mdclrerror(&xep);

		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE, SVM_TAG_DRIVE,
		    sr->sr_setno, dev);
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_DRIVE,
		    MD_LOCAL_SET, dev);

		dr_cache_del(sr, tdr->dr_selfid);

	}

	(void) memset(&req, 0, sizeof (req));
	METAD_SETUP_SR(MD_DB_DELETE, sr->sr_selfid)
	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
		free_sr(sr);
		return;
	}

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, SVM_TAG_SET, sr->sr_setno,
	    NODEV64);

	for (tsr = setrecords; tsr; tsr = tsr->sr_next) {
		if (tsr == sr)
			continue;

		num_sets++;
		if (MD_MNSET_REC(tsr))
			num_mn_sets++;
	}

	if (num_mn_sets == 0)
		(void) meta_smf_disable(META_SMF_MN_DISKSET, NULL);

	/* The set we just deleted is the only one left */
	if (num_sets == 0)
		(void) meta_smf_disable(META_SMF_DISKSET, NULL);

	sr_cache_del(sr->sr_selfid);
	free_sr(sr);

}

void
s_delrec(mddb_recid_t recid, md_error_t *ep)
{
	mddb_userreq_t		req;

	(void) memset(&req, 0, sizeof (req));

	METAD_SETUP_SR(MD_DB_DELETE, recid)

	if (metaioctl(MD_DB_USERREQ, &req, &req.ur_mde, NULL) != 0)
		(void) mdstealerror(ep, &req.ur_mde);
}

/*
 * resnarf the imported set
 */
int
resnarf_set(
	set_t			setno,
	md_error_t		*ep
)
{
	md_set_record	*sr;
	md_drive_record	*dr;
	mddb_recid_t	id, *p;

	if (meta_setup_db_locations(ep) != 0) {
		if (! mdismddberror(ep, MDE_DB_STALE))
			return (-1);
		mdclrerror(ep);
	}

	setsnarfdone = 1;

	id = 0;
	while ((sr = get_ur_rec(MD_LOCAL_SET, MD_UR_GET_NEXT, MDDB_UR_SR, &id,
	    ep)) != NULL) {

		if (sr->sr_setno != setno)
			continue;

		/* Don't allow resnarf of a multi-node diskset */
		if (MD_MNSET_REC(sr))
			goto out;

		sr->sr_next = NULL;
		sr->sr_drivechain = NULL;

		if (md_in_daemon)
			url_addl(&url_used, sr->sr_selfid);

		sr->sr_flags |= MD_SR_CHECK;

		sr_cache_add(sr);

		if (sr->sr_driverec == 0)
			break;

		p = &sr->sr_driverec;
		while ((dr = get_ur_rec(MD_LOCAL_SET, MD_UR_GET_WKEY,
		    MDDB_UR_DR, p, ep)) != NULL) {
			dr->dr_next = NULL;

			if (md_in_daemon)
				url_addl(&url_used, dr->dr_selfid);

			dr_cache_add(sr, dr);

			if (dr->dr_nextrec == 0)
				break;

			p = &dr->dr_nextrec;
		}
		if (! mdisok(ep)) {
			if (! mdissyserror(ep, ENOENT))
				goto out;
			mdclrerror(ep);
			commitset(sr, FALSE, ep);
			if (! mdisok(ep))
				goto out;
		}
	}
	if (! mdisok(ep)) {
		if (! mdissyserror(ep, ENOENT))
			goto out;
		mdclrerror(ep);
	}

	setsnarfdone = 2;

	url_freel(&url_used);
	url_freel(&url_tode);
	return (0);

out:
	url_freel(&url_used);
	url_freel(&url_tode);

	sr_cache_flush(1);

	setsnarfdone = 0;

	return (-1);
}
