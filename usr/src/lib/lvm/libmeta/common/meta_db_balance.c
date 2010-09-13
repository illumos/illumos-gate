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
 * Database location balancing code.
 */

#include <meta.h>
#include <sys/lvm/md_mddb.h>
#include <sdssc.h>

#define	MD_MINBALREP	2

/*
 * Stuff for DB balancing.
 */
enum md_ctlr_ops_t {
	DRV_NOP = 0,
	DRV_ADD = 1,
	DRV_DEL = 2
};
typedef enum md_ctlr_ops_t md_ctlr_ops_t;

/* drive flag fields */
#define	DRV_F_ERROR	0x1
#define	DRV_F_INDISKSET	0x2

struct md_ctlr_drv_t {
	md_ctlr_ops_t drv_op;
	int drv_flags;
	int drv_dbcnt;
	int drv_new_dbcnt;
	daddr_t drv_dbsize;
	mddrivename_t *drv_dnp;
	struct md_ctlr_drv_t *drv_next;
};
typedef struct md_ctlr_drv_t md_ctlr_drv_t;

struct md_ctlr_ctl_t {
	mdcinfo_t *ctl_cinfop;
	int ctl_dbcnt;
	int ctl_drcnt;
	md_ctlr_drv_t *ctl_drvs;
	struct md_ctlr_ctl_t *ctl_next;
};
typedef struct md_ctlr_ctl_t md_ctlr_ctl_t;

static int
add_replica(
	mdsetname_t		*sp,
	mddrivename_t		*dnp,
	int			dbcnt,
	daddr_t			dbsize,
	md_error_t		*ep
)
{
	mdnamelist_t		*nlp = NULL;
	mdname_t		*np;
	md_set_desc		*sd;
	uint_t			rep_slice;

	if (meta_replicaslice(dnp, &rep_slice, ep) != 0)
		return (-1);

	if ((np = metaslicename(dnp, rep_slice, ep)) == NULL)
		return (-1);

	(void) metanamelist_append(&nlp, np);

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		metafreenamelist(nlp);
		return (-1);
	}

	if (meta_db_attach(sp, nlp, (MDCHK_DRVINSET | MDCHK_SET_LOCKED),
	    (&sd->sd_ctime), dbcnt, dbsize, NULL, ep) == -1) {
		metafreenamelist(nlp);
		return (-1);
	}

	metafreenamelist(nlp);
	return (0);
}

static int
del_replica(
	mdsetname_t		*sp,
	mddrivename_t		*dnp,
	md_error_t		*ep
)
{
	mdnamelist_t		*nlp = NULL;
	mdname_t		*np;
	uint_t			rep_slice;

	if (meta_replicaslice(dnp, &rep_slice, ep) != 0)
		return (-1);

	if ((np = metaslicename(dnp, rep_slice, ep)) == NULL)
		return (-1);

	(void) metanamelist_append(&nlp, np);

	if (meta_db_detach(sp, nlp, (MDFORCE_DS | MDFORCE_SET_LOCKED),
	    NULL, ep) == -1) {
		metafreenamelist(nlp);
		return (-1);
	}

	metafreenamelist(nlp);
	return (0);
}

static int
rep_has_err(md_replicalist_t *rlp, mdname_t *np)
{
	md_replicalist_t	*rl;

	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		md_replica_t	*r = rl->rl_repp;

		if (strcmp(r->r_namep->cname, np->cname) != 0)
			continue;

		if (r->r_flags & (MDDB_F_EREAD | MDDB_F_EFMT | MDDB_F_EDATA |
		    MDDB_F_EMASTER | MDDB_F_EWRITE))
			return (1);

	}
	return (0);
}

static int
add_drv_to_ctl_lst(
	md_ctlr_ctl_t		**clpp,
	md_replicalist_t	*rlp,
	mddrivename_t		*dnp,
	int			dbcnt,
	daddr_t			dbsize,
	mdcinfo_t		*cinfop,
	int			indiskset,
	int			with_bus,
	int			errored,
	md_error_t		*ep
)
{
	md_ctlr_drv_t		**dpp;
	mdname_t		*np;
	mdcinfo_t		*tcinfop;
	char			*cmp_name_1, *cmp_name_2;
	int			not_found;

	/*
	 * The user must pass in a list head.
	 */
	assert(clpp != NULL);

	if (cinfop == NULL) {
		uint_t	rep_slice;

		if (meta_replicaslice(dnp, &rep_slice, ep) != 0) {
			/*
			 * A failure to get the slice information can occur
			 * because the drive has failed, if this is the
			 * case then there is nothing that can be done
			 * with this drive, so do not include it in the
			 * list of drives. Clear the error and return.
			 */
			mdclrerror(ep);
			return (0);
		}

		if ((np = metaslicename(dnp, rep_slice, ep)) == NULL)
			return (-1);

		if ((tcinfop = metagetcinfo(np, ep)) == NULL)
			return (-1);

		if (metagetvtoc(np, FALSE, NULL, ep) == NULL)
			errored = 1;

		if (rep_has_err(rlp, np))
			errored = 1;
	} else
		tcinfop = cinfop;

	for (/* void */; *clpp != NULL; clpp = &(*clpp)->ctl_next) {
		/*
		 * Try to locate ctlr.
		 */
		(void) sdssc_convert_cluster_path(tcinfop->cname, &cmp_name_1);
		(void) sdssc_convert_cluster_path((*clpp)->ctl_cinfop->cname,
		    &cmp_name_2);

		if (tcinfop->ctype != (*clpp)->ctl_cinfop->ctype ||
		    tcinfop->cnum != (*clpp)->ctl_cinfop->cnum ||
		    strncmp(cmp_name_1, cmp_name_2, 16) != 0 ||
		    (with_bus && tcinfop->bus != (*clpp)->ctl_cinfop->bus)) {
			not_found = 1;
		} else
			not_found = 0;


		sdssc_convert_path_free(cmp_name_1);
		sdssc_convert_path_free(cmp_name_2);

		if (not_found)
			continue;

		/*
		 * Found ctlr, try to locate the drive.
		 */
		for (dpp = &(*clpp)->ctl_drvs; *dpp != NULL;
		    dpp = &(*dpp)->drv_next) {
			(void) sdssc_convert_cluster_path(
			    (*dpp)->drv_dnp->cname, &cmp_name_1);
			(void) sdssc_convert_cluster_path(dnp->cname,
			    &cmp_name_2);

			not_found = strcmp(cmp_name_1, cmp_name_2);

			sdssc_convert_path_free(cmp_name_1);
			sdssc_convert_path_free(cmp_name_2);

			if (not_found)
				continue;

			/*
			 * Found drive, must be deleting.
			 */
			(*dpp)->drv_op = DRV_DEL;
			if (indiskset)
				(*dpp)->drv_flags |= DRV_F_INDISKSET;
			if (errored) {
				mdclrerror(ep);
				(*dpp)->drv_flags |= DRV_F_ERROR;
			}
			(*clpp)->ctl_dbcnt -= (*dpp)->drv_dbcnt;
			(*clpp)->ctl_drcnt--;
			return (0);
		}
		/*
		 * The ctlr was found, but not the drive, so add
		 * the drive
		 */
		(*dpp) = Zalloc(sizeof (**dpp));


		if (indiskset) {
			(*dpp)->drv_op = DRV_NOP;
			(*dpp)->drv_flags |= DRV_F_INDISKSET;
			if (errored) {
				mdclrerror(ep);
				(*dpp)->drv_flags |= DRV_F_ERROR;
			}
		} else {
			(*dpp)->drv_op = DRV_ADD;
			if (errored) {
				(*dpp)->drv_flags |= DRV_F_ERROR;
				return (-1);
			}
			assert(dbsize != 0);
		}
		(*dpp)->drv_dbcnt = dbcnt;
		(*dpp)->drv_dbsize = dbsize;
		(*dpp)->drv_dnp = dnp;
		(*clpp)->ctl_dbcnt += dbcnt;
		(*clpp)->ctl_drcnt++;
		return (0);
	}
	/*
	 * No ctlr was located, so add the ctlr, then recurse to add the
	 * drive to the ctlr.
	 */
	(*clpp) = Zalloc(sizeof (**clpp));

	(*clpp)->ctl_cinfop = tcinfop;

	return (add_drv_to_ctl_lst(clpp, rlp, dnp, dbcnt, dbsize, tcinfop,
	    indiskset, with_bus, errored, ep));
}

static int
add_replica_to_ctl(
	mdsetname_t		*sp,
	md_ctlr_ctl_t		*c,
	int			minimum_replicas,
	md_error_t		*ep
)
{
	md_ctlr_drv_t		*d;
	int			maxdb = 0;

	/*
	 * If this ctrl has no "usable" drives, assert() or just return if
	 * assert()'s are turned off.
	 */
	if (c->ctl_drcnt == 0) {
		assert(0);
		return (0);
	}

	/*
	 * Determine the largest DB count on a drive.
	 */
	for (d = c->ctl_drvs; d != NULL; d = d->drv_next)
		if (d->drv_dbcnt > maxdb && d->drv_op != DRV_DEL)
			maxdb = d->drv_dbcnt;

	/*
	 * Make sure we start at a reasonable number
	 */
	if (maxdb == 0)
		maxdb = 1;

	/*
	 * Add a replica to a drive on this ctrl.
	 */
	/*CONSTCOND*/
	while (1) {
		for (d = c->ctl_drvs; d != NULL; d = d->drv_next) {
			/*
			 * If this drive is being deleted, skip it.
			 */
			if (d->drv_op == DRV_DEL)
				continue;

			if (d->drv_flags & DRV_F_ERROR)
				continue;
			/*
			 * Make sure that the replicas are distributed across
			 * the drives.
			 */
			if (d->drv_dbcnt >= maxdb)
				continue;
			/*
			 * See if the drive already has replicas,
			 * if it does, then delete the exisiting
			 * replica(s) and re-add n+1 replicas to the drive.
			 */
			/* ==== Vulnerability - no DB's start ==== */
			if (d->drv_dbcnt > 0) {
				if (del_replica(sp, d->drv_dnp, ep) == -1) {
					d->drv_flags |= DRV_F_ERROR;
					if (! (d->drv_flags & DRV_F_INDISKSET))
						return (-1);
					mdclrerror(ep);
					continue;
				}
			}
			if (add_replica(sp, d->drv_dnp, (d->drv_dbcnt + 1),
			    d->drv_dbsize, ep) == -1) {
				md_error_t nep = mdnullerror;

				if (d->drv_dbcnt) {
					/*
					 * We have to to bring the replica
					 * in the drive to the previous
					 * status by adding the original no
					 * of replicas to the drive since
					 * the addition of (drv_dbcnt+1) no
					 * of replicas has failed. If we
					 * leave it at this state, we might
					 * end up having no replicas at
					 * all for the diskset.
					 */
					if (add_replica(sp, d->drv_dnp,
					    d->drv_dbcnt, d->drv_dbsize,
					    &nep) == -1) {
						c->ctl_dbcnt -= d->drv_dbcnt;
						d->drv_dbcnt = 0;
						mdclrerror(&nep);
					}
				}

				if (mdismddberror(ep, MDE_TOOMANY_REPLICAS))
					return (-1);

				if (mdismddberror(ep, MDE_REPLICA_TOOSMALL))
					continue;

				d->drv_flags |= DRV_F_ERROR;
				if (! (d->drv_flags & DRV_F_INDISKSET))
					return (-1);
				mdclrerror(ep);
				continue;
			}

			d->drv_dbcnt++;
			c->ctl_dbcnt++;
			/* ==== Vulnerability - no DB's end ==== */
			return (1);
		}
		maxdb++;
		if (maxdb > minimum_replicas)
			return (0);
	}
	/*NOTREACHED*/
}

static int
del_replica_from_ctl(
	mdsetname_t		*sp,
	md_ctlr_ctl_t		*c,
	md_error_t		*ep
)
{
	md_ctlr_drv_t		*d;
	int			maxdb = 0;

	/*
	 * If this ctrl has no "usable" drives, assert() or just return if
	 * assert()'s are turned off.
	 */
	if (c->ctl_drcnt == 0) {
		assert(0);
		return (0);
	}

	/*
	 * Determine the largest DB count on a drive.
	 */
	for (d = c->ctl_drvs; d != NULL; d = d->drv_next)
		if (d->drv_dbcnt > maxdb && d->drv_op != DRV_DEL)
			maxdb = d->drv_dbcnt;

	if (maxdb == 0)
		return (0);

	/*
	 * Delete a replica from a drive on this ctrl.
	 */
	/*CONSTCOND*/
	while (1) {
		for (d = c->ctl_drvs; d != NULL; d = d->drv_next) {
			/*
			 * If this drive is being deleted, skip it.
			 */
			if (d->drv_op == DRV_DEL)
				continue;

			/*
			 * Make sure that there are replicas on this drive to
			 * delete.
			 */
			if (d->drv_dbcnt == 0)
				continue;

			if (d->drv_flags & DRV_F_ERROR)
				continue;

			/*
			 * We need to keep the DB's distributed across the
			 * drives.
			 */
			if (d->drv_dbcnt < maxdb)
				continue;

			/*
			 * Delete all the replicas on the drive.
			 */
			/* ==== Vulnerability - no DB's start ==== */
			if (del_replica(sp, d->drv_dnp, ep) == -1) {
				d->drv_flags |= DRV_F_ERROR;
				if (! (d->drv_flags & DRV_F_INDISKSET))
					return (-1);
				mdclrerror(ep);
				continue;
			}
			d->drv_dbcnt--;
			c->ctl_dbcnt--;
			/*
			 * If there is still a dbcnt for this drive, then add
			 * back the needed DB's.
			 */
			if (d->drv_dbcnt > 0) {
				if (add_replica(sp, d->drv_dnp, d->drv_dbcnt,
				    d->drv_dbsize, ep) == -1) {
					c->ctl_dbcnt -= d->drv_dbcnt;
					d->drv_dbcnt = 0;

					if (mdismddberror(ep,
					    MDE_TOOMANY_REPLICAS))
						return (-1);

					d->drv_flags |= DRV_F_ERROR;
					if (! (d->drv_flags & DRV_F_INDISKSET))
						return (-1);
					mdclrerror(ep);
					continue;
				}
			}
			/* ==== Vulnerability - no DB's end ==== */
			return (1);
		}
		maxdb--;
		if (maxdb <= 0)
			return (0);
	}
	/*NOTREACHED*/
}

static int
del_replicas(mdsetname_t *sp, md_ctlr_ctl_t *clp, md_error_t *ep)
{
	md_ctlr_ctl_t		*c;
	md_ctlr_drv_t		*d;
	mdnamelist_t		*nlp;
	mdname_t		*np;

	for (c = clp; c != NULL; c = c->ctl_next) {
		for (d = c->ctl_drvs; d != NULL; d = d->drv_next) {
			uint_t	rep_slice;

			if (! (d->drv_flags & DRV_F_ERROR) &&
			    (d->drv_op != DRV_DEL))
				continue;

			if (d->drv_dbcnt == 0)
				continue;

			if (meta_replicaslice(d->drv_dnp,
			    &rep_slice, ep) != 0)
				return (-1);

			np = metaslicename(d->drv_dnp, rep_slice, ep);
			if (np == NULL)
				return (-1);

			nlp = NULL;
			(void) metanamelist_append(&nlp, np);

			/*
			 * Delete the replicas listed.
			 */
			if (meta_db_detach(sp, nlp,
			    (MDFORCE_DS | MDFORCE_SET_LOCKED), NULL,
			    ep) == -1) {
				metafreenamelist(nlp);
				if (d->drv_flags & DRV_F_INDISKSET) {
					mdclrerror(ep);
					continue;
				}
				return (-1);
			}
			metafreenamelist(nlp);
		}
	}

	return (0);
}

static void
free_ctlr_lst(md_ctlr_ctl_t **clpp)
{
	md_ctlr_ctl_t		*c, *tc = NULL;
	md_ctlr_drv_t		*d, *td = NULL;

	for (c = *clpp; c != NULL; c = tc) {
		tc = c->ctl_next;
		for (d = c->ctl_drvs; d != NULL; d = td) {
			td = d->drv_next;
			Free(d);
		}
		Free(c);
	}
	*clpp = NULL;
}

static int
build_ctlr_lst(
	mdsetname_t		*sp,
	md_ctlr_ctl_t		**clpp,
	md_drive_desc		*opdd,
	md_drive_desc		*curdd,
	int			with_bus,
	daddr_t			dbsize,
	md_error_t		*ep
)
{
	md_drive_desc			*d;
	md_set_desc			*sd;
	daddr_t				nblks;
	md_replicalist_t		*rlp = NULL;
	static	daddr_t			min_dbsize = 0;

	if (min_dbsize == 0) {
		if ((nblks = meta_db_minreplica(sp, ep)) < 0) {
			min_dbsize = MD_DBSIZE;

			if (! metaislocalset(sp)) {
				if ((sd = metaget_setdesc(sp, ep)) == NULL)
					return (-1);

				if (MD_MNSET_DESC(sd))
					min_dbsize = MD_MN_DBSIZE;
			}
			mdclrerror(ep);
		} else
			min_dbsize = nblks;
	}

	if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) < 0) {
		if (! mdismddberror(ep, MDE_DB_NODB) &&
		    ! mdismddberror(ep, MDE_DB_NOTOWNER))
			return (-1);
		mdclrerror(ep);
	}

	/*
	 * Add drives currently in the set to the ctlr list.
	 */
	for (d = curdd; d != NULL; d = d->dd_next) {
		daddr_t	this_dbsize = d->dd_dbsize;

		if (this_dbsize == 0)
			this_dbsize = min_dbsize;

		if (add_drv_to_ctl_lst(clpp, rlp, d->dd_dnp, d->dd_dbcnt,
		    this_dbsize, NULL, TRUE, with_bus, 0, ep) == -1)
			return (-1);
	}

	/*
	 * Add the drives that are being operated on to the ctlr list.
	 */
	for (d = opdd; d != NULL; d = d->dd_next)
		if (add_drv_to_ctl_lst(clpp, rlp, d->dd_dnp, 0, dbsize, NULL,
		    FALSE, with_bus, 0, ep) == -1)
			return (-1);

	metafreereplicalist(rlp);
	return (0);
}

static int
count_replica_on_ctl(
	md_ctlr_ctl_t		*c,
	int			adding,
	int			*db_cnt,
	int			minimum_replicas
)
{
	md_ctlr_drv_t		*d;
	int			maxdb = 0;

	/*
	 * If this ctrl has no "usable" drives, nothing to do.
	 */
	if (c->ctl_drcnt == 0)
		return (0);

	/*
	 * Determine the largest DB count on a drive.
	 */
	for (d = c->ctl_drvs; d != NULL; d = d->drv_next)
		if (d->drv_new_dbcnt > maxdb && d->drv_op != DRV_DEL)
			maxdb = d->drv_new_dbcnt;

	/*
	 * Make sure we start at a reasonable number
	 */
	if (maxdb == 0) {
		if (!adding)
			return (0);
		maxdb = 1;
	}

	/*
	 * Count or Un-Count replicas that would be
	 * added or deleted respectively.
	 */
	/*CONSTCOND*/
	while (1) {
		for (d = c->ctl_drvs; d != NULL; d = d->drv_next) {
			/*
			 * If this drive is being deleted, skip it.
			 */
			if (d->drv_op == DRV_DEL)
				continue;

			/*
			 * If the drive is errored and adding, skip it.
			 */
			if (adding && (d->drv_flags & DRV_F_ERROR))
				continue;

			/*
			 * Make sure that the replicas are distributed across
			 * the drives.
			 */
			if (adding) {
				if (d->drv_new_dbcnt >= maxdb)
					continue;
			} else {
				if (d->drv_new_dbcnt == 0)
					continue;
				if (d->drv_new_dbcnt < maxdb)
					continue;
			}

			/*
			 * Count or Un-Count replicas here.
			 */
			if (adding) {
				mdpart_t	*partp;
				uint_t		rep_slice;
				md_error_t	mde = mdnullerror;

				if (meta_replicaslice(d->drv_dnp,
				    &rep_slice, &mde) != 0) {
					mdclrerror(&mde);
					continue;
				}

				partp = &d->drv_dnp->vtoc.parts[rep_slice];
				if (! partp)
					continue;

				if (((d->drv_new_dbcnt + 1) * d->drv_dbsize) >
				    (partp->size - 16))
					continue;
				(*db_cnt)++;
				d->drv_new_dbcnt++;
			} else {
				(*db_cnt)--;
				d->drv_new_dbcnt--;
			}
			return (0);
		}

		/*
		 * This should make sure they get spread
		 * around.  This is to emulate the {add,del}_replica
		 * routines.
		 */
		if (adding) {
			maxdb++;
			if (maxdb > minimum_replicas)
				return (-1);
		} else {
			maxdb--;
			if (maxdb <= 0)
				return (-1);
		}
	}
	/*NOTREACHED*/
}

static int
count_replicas(
	md_ctlr_ctl_t		*clp,
	int			min_reps
)
{
	md_ctlr_ctl_t		*c;
	md_ctlr_drv_t		*d;
	int			db_cnt;
	int			uctlrs = 0;
	int			total_cnt = 0;

	/*
	 * Count the number of controllers,
	 * counting the replicas is slightly different based
	 * on the controller count.
	 */
	for (c = clp; c != NULL; c = c->ctl_next)
		if (c->ctl_drcnt > 0) {
			uctlrs++;
			for (d = c->ctl_drvs; d != NULL; d = d->drv_next)
				d->drv_new_dbcnt = d->drv_dbcnt;
		}

	if (uctlrs > 2) {
		for (c = clp; c != NULL; c = c->ctl_next) {
			if (c->ctl_drcnt == 0)
				continue;

			db_cnt = c->ctl_dbcnt;
			/*
			 * Count the replicas that would be added.
			 */
			while (db_cnt < min_reps)
				if (count_replica_on_ctl(c, TRUE,
				    &db_cnt, min_reps))
					return (-1);

			/*
			 * Un-Count the replicas that would be deleted.
			 */
			while (db_cnt > min_reps)
				if (count_replica_on_ctl(c, FALSE,
				    &db_cnt, min_reps))
					return (-1);
			total_cnt += db_cnt;
		}
	} else {
		for (c = clp; c != NULL; c = c->ctl_next) {
			if (c->ctl_drcnt == 0)
				continue;

			db_cnt = c->ctl_dbcnt;
			/*
			 * Count the replicas that woud be added.
			 */
			while (db_cnt < (min_reps * c->ctl_drcnt))
				if (count_replica_on_ctl(c, TRUE,
				    &db_cnt, min_reps))
					return (-1);

			total_cnt += db_cnt;
		}
	}

	return (total_cnt);
}

static int
balance_replicas(
	mdsetname_t		*sp,
	md_ctlr_ctl_t		**clpp,
	md_drive_desc		*opdd,
	md_drive_desc		*curdd,
	daddr_t			dbsize,
	int			*minimum_replicas,
	md_error_t		*ep
)
{
	int			n;
	int			rctlrs = 0;
	int			uctlrs;
	int			ructlrs;
	int			octlrs;
	int			save_done;
	int			prevcnt = 0, issame = 1;
	uint_t			drvcnt = ~0U;
	uint_t			save_cnum;
	mhd_ctlrtype_t		save_ctype;
	char			save_cname[16];
	char			*cmp_name_1, *cmp_name_2;
	int			reps;
	md_ctlr_ctl_t		*c;

	/*
	 * Build a ctlr list with SSA-100 busses NOT as separate controllers.
	 */
	if (build_ctlr_lst(sp, clpp, opdd, curdd, FALSE, dbsize, ep) == -1)
		return (-1);

	/*
	 * Determine what controllers are usable in the sense of being able to
	 * add a replica to a drive on the controller.
	 * Also find the minimum number of drives on a controller.
	 */
	for (c = *clpp; c != NULL; c = c->ctl_next) {
		if (c->ctl_drcnt > 0) {
			rctlrs++;
			drvcnt = min(drvcnt, c->ctl_drcnt);
			if (prevcnt == 0)
				prevcnt = c->ctl_drcnt;
			else if (prevcnt != c->ctl_drcnt)
				issame = 0;
		}
	}

	if ((rctlrs <= 2) || (issame && (drvcnt >= 30)))
		goto cont;

	/*
	 * If here: Handling 3 or more controllers most
	 *	    likely with non-symmetrical number of
	 *	    disks. The number of replicas will be
	 *	    the minimum number of disks on a controller.
	 *
	 *	    The main point is to insure that a
	 *	    controller does not have more than half
	 *	    of the replicas.
	 */
	drvcnt = min(drvcnt, 12);
	drvcnt = max(drvcnt, MD_MINBALREP);

	/*
	 * Can we find fewer than the maximum replicas by reducing the
	 * number of replicas per drive.
	 */
	for (n = drvcnt; n > 0; n--) {
		reps = count_replicas(*clpp, n);
		if (reps > 0 && reps <= MDDB_NLB) {
			*minimum_replicas = n;
			return (0);
		}
	}

cont:
	free_ctlr_lst(clpp);

	/*
	 * Build a ctlr list with SSA-100 busses as separate controllers.
	 *
	 * If Here: Try to put 2 replicas per controller/bus
	 *	    If that doesn't work put 1 replica per controller/bus
	 */
	if (build_ctlr_lst(sp, clpp, opdd, curdd, TRUE, dbsize, ep) == -1)
		return (-1);

	/*
	 * If the number of "real" controllers is 2, special handling may be
	 * needed.
	 */
	if (rctlrs != 2) {
		drvcnt = MD_MINBALREP;
		goto other;
	}

	/*
	 * Determine what controllers are usable in the sense of being able to
	 * add a replica to a drive on the controller.
	 * Also find the minimum number of drives on a controller.
	 */
	drvcnt = ~0U;
	uctlrs = 0;
	for (c = *clpp; c != NULL; c = c->ctl_next) {
		if (c->ctl_drcnt > 0) {
			uctlrs++;
			drvcnt = min(drvcnt, c->ctl_drcnt);
		}
	}

	/*
	 * If the number of controllers is not changed, continue with original
	 * strategy.
	 */
	if (uctlrs == rctlrs) {
		drvcnt = MD_MINBALREP;
		goto other;
	}

	/*
	 * Check the distribution of bus ctlrs across real controllers.
	 */
	ructlrs = 0;
	octlrs = 0;
	save_done = 0;
	for (c = *clpp; c != NULL; c = c->ctl_next) {
		if (c->ctl_drcnt == 0)
			continue;

		if (! save_done) {
			save_cnum = c->ctl_cinfop->cnum;
			save_ctype = c->ctl_cinfop->ctype;
			(void) strncpy(save_cname, c->ctl_cinfop->cname, 16);
			save_done = 1;
		}

		(void) sdssc_convert_cluster_path(c->ctl_cinfop->cname,
		    &cmp_name_1);
		(void) sdssc_convert_cluster_path(save_cname, &cmp_name_2);

		if (save_ctype != c->ctl_cinfop->ctype ||
		    save_cnum != c->ctl_cinfop->cnum ||
		    strncmp(cmp_name_1, cmp_name_2, 16) != 0)
			octlrs++;
		else
			ructlrs++;

		sdssc_convert_path_free(cmp_name_1);
		sdssc_convert_path_free(cmp_name_2);
	}

	/*
	 * Take the largest of the counts
	 */
	ructlrs = max(ructlrs, octlrs);

	/*
	 * If the distribution of bus controlers is half of the total, then
	 * this layout strategy will work, doit.
	 */
	if ((uctlrs / 2) == ructlrs) {
		drvcnt = MD_MINBALREP;
		goto other;
	}

	/*
	 * If here, there is a distribution of bus controllers that will cause
	 * the real controller distribution to be unbalanced, so a different
	 * strategy is used.
	 */
	free_ctlr_lst(clpp);

	/*
	 * Build the ctlr list with SSA-100 busses NOT as separate controllers.
	 */
	if (build_ctlr_lst(sp, clpp, opdd, curdd, FALSE, dbsize, ep) == -1)
		return (-1);

	/*
	 * Make ctl_drcnt limit the number of replicas
	 */
	for (c = *clpp; c != NULL; c = c->ctl_next)
		c->ctl_drcnt = min(drvcnt, c->ctl_drcnt);

	/*
	 * Try at least MD_MINBALREP's per controller after changing ctl_drcnt
	 */
	drvcnt = MD_MINBALREP;

other:
	/*
	 * Can we find fewer than the maximum replicas by reducing the number
	 * of replicas per drive.
	 */
	for (n = drvcnt; n > 0; n--) {
		reps = count_replicas(*clpp, n);
		if (reps > 0 && reps <= MDDB_NLB) {
			*minimum_replicas = n;
			return (0);
		}
	}

	free_ctlr_lst(clpp);

	/*
	 * Build a ctlr list with SSA-100 busses NOT as separate controllers.
	 *
	 * If Here: Try to put 2 replicas per controller (not on busses)
	 *	    If that doesn't work put 1 replica per controller
	 */
	if (build_ctlr_lst(sp, clpp, opdd, curdd, FALSE, dbsize, ep) == -1)
		return (-1);

	/*
	 * Can we find fewer than the maximum replicas by reducing the
	 * number of replicas per drive.
	 */
	for (n = MD_MINBALREP; n > 0; n--) {
		reps = count_replicas(*clpp, n);
		if (reps > 0 && reps <= MDDB_NLB) {
			*minimum_replicas = n;
			return (0);
		}
	}

	/*
	 * Return a ctrl list that does not include the SSA-100 buses as
	 * separate controllers.  This will create fewer separate controllers.
	 */
	*minimum_replicas = 1;
	return (0);
}

static int
morethan2_ctl_balance(
	mdsetname_t		*sp,
	md_ctlr_ctl_t		*clp,
	int			min_reps,
	md_error_t		*ep
)
{
	md_ctlr_ctl_t		*c;
	int			err;
	int			multiple_reps = 0;
	md_ctlr_drv_t		*d;

	for (c = clp; c != NULL; c = c->ctl_next) {
		if (c->ctl_drcnt == 0)
			continue;

		/*
		 * check for multiple databases on a disk and compensate
		 */
		for (d = c->ctl_drvs; d != NULL; d = d->drv_next) {
			if (d->drv_dbcnt)
				multiple_reps += d->drv_dbcnt - 1;
		}

		/*
		 * remove the number of multiple databases count from the
		 * total db count. This enables us to rebalance if one of
		 * the disks has a large enough slice for 2 metadb's. If we
		 * then add a disk with a smaller slice into the set, we want
		 * that disk to get a replica on it. If we just compare to
		 * ctl_dbcnt, it won't.
		 */
		while ((c->ctl_dbcnt - multiple_reps) <
		    min_reps) {
			if ((err = add_replica_to_ctl(sp, c, min_reps, ep)) < 0)
				return (-1);
			if (err == 0)
				break;
		}

		while (c->ctl_dbcnt > min_reps) {
			if ((err = del_replica_from_ctl(sp, c, ep)) < 0)
				return (-1);
			if (err == 0)
				break;
		}
	}

	return (0);
}

static int
lessthan3_ctl_balance(
	mdsetname_t		*sp,
	md_ctlr_ctl_t		*clp,
	int			min_reps,
	md_error_t		*ep
)
{
	md_ctlr_ctl_t		*c;
	int			err;
	int			multiple_reps = 0;
	md_ctlr_drv_t		*d;

	for (c = clp; c != NULL; c = c->ctl_next) {
		if (c->ctl_drcnt == 0)
			continue;

		/*
		 * check for multiple databases on a disk and compensate
		 */
		for (d = c->ctl_drvs; d != NULL; d = d->drv_next) {
			if (d->drv_dbcnt)
				multiple_reps += d->drv_dbcnt - 1;
		}

		/*
		 * remove the number of multiple databases count from the
		 * total db count. This enables us to rebalance if one of
		 * the disks has a large enough slice for 2 metadb's. If we
		 * then add a disk with a smaller slice into the set, we want
		 * that disk to get a replica on it. If we just compare to
		 * ctl_dbcnt, it won't.
		 */
		while ((c->ctl_dbcnt - multiple_reps) <
		    (min_reps * c->ctl_drcnt)) {
			if ((err = add_replica_to_ctl(sp, c, min_reps, ep)) < 0)
				return (-1);
			if (err == 0)
				break;
		}

		while (c->ctl_dbcnt > (min_reps * c->ctl_drcnt)) {
			if ((err = del_replica_from_ctl(sp, c, ep)) < 0)
				return (-1);
			if (err == 0)
				break;
		}
	}

	return (0);
}

static int
try_again(
	md_ctlr_ctl_t	*clp,
	md_error_t	*ep
)
{
	md_ctlr_ctl_t	*c;
	md_ctlr_drv_t	*d;

	if (mdismddberror(ep, MDE_TOOMANY_REPLICAS))
		return (TRUE);

	/*
	 * retry if all the errored drives are already in the diskset.
	 */
	for (c = clp; c != NULL; c = c->ctl_next) {
		for (d = c->ctl_drvs; d != NULL; d = d->drv_next) {
			if ((d->drv_flags & (DRV_F_INDISKSET|DRV_F_ERROR))
			    == DRV_F_ERROR)
				return (FALSE);
		}
	}
	return (TRUE);
}

int
meta_db_balance(
	mdsetname_t		*sp,
	md_drive_desc		*opdd,
	md_drive_desc		*curdd,
	daddr_t			dbsize,
	md_error_t		*ep
)
{
	int			min_reps;
	md_ctlr_ctl_t		*c, *cl = NULL;
	int			uctlrs = 0;
	int			retry = 0;
	int			rval = 0;

	if (balance_replicas(sp, &cl, opdd, curdd, dbsize, &min_reps, ep) == -1)
		return (-1);

	/*
	 * Determine what controllers are usable in the sense of being able to
	 * add a replica to a drive on the controller.
	 */
	for (c = cl; c != NULL; c = c->ctl_next)
		if (c->ctl_drcnt > 0)
			uctlrs++;

	/*
	 * Add replicas to achieve a balance.
	 */
	if (uctlrs > 2)
		rval = morethan2_ctl_balance(sp, cl, min_reps, ep);
	else
		rval = lessthan3_ctl_balance(sp, cl, min_reps, ep);

	if (rval) {
		if ((retry = try_again(cl, ep)) == TRUE) {
			mdclrerror(ep);
			rval = 0;
		}
	}

	/*
	 * Delete all the replicas from drives that are so marked.
	 */
	if (! rval)
		rval = del_replicas(sp, cl, ep);

	if (retry) {
		if (uctlrs > 2)
			rval = morethan2_ctl_balance(sp, cl, min_reps, ep);
		else
			rval = lessthan3_ctl_balance(sp, cl, min_reps, ep);

		if (rval && mdismddberror(ep, MDE_TOOMANY_REPLICAS)) {
			mdclrerror(ep);
			rval = 0;
		}
	}

	/*
	 * Free up the ctlr list.
	 */
	free_ctlr_lst(&cl);

	return (rval);
}
