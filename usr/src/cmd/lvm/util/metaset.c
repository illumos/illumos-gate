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
 */

/*
 * Metadevice diskset utility.
 */

#include <meta.h>
#include <sys/lvm/md_mddb.h>
#include <sdssc.h>

enum metaset_cmd {
	notspecified,
	add,
	balance,
	delete,
	cluster,
	isowner,
	purge,
	query,
	release,
	take,
	join,			/* Join a multinode diskset */
	withdraw		/* Withdraw from a multinode diskset */
};

enum cluster_cmd {
	ccnotspecified,
	clusterversion,		/* Return the version of the cluster I/F */
	clusterdisksin,		/* List disks in a given diskset */
	clustertake,		/* back door for Cluster take */
	clusterrelease,		/* ditto */
	clusterpurge,		/* back door for Cluster purge */
	clusterproxy		/* proxy the args after '--' to primary */
};

static void
usage(
	mdsetname_t	*sp,
	char		*string)
{
	if ((string != NULL) && (*string != '\0'))
		md_eprintf("%s\n", string);
	(void) fprintf(stderr, gettext(
	    "usage:\t%s -s setname -a [-A enable | disable] -h hostname ...\n"
	    "	%s -s setname -a [-M] -h hostname ...\n"
	    "	%s -s setname -a [-M] [-l length] [-L] drivename ...\n"
	    "	%s -s setname -d [-M] -h hostname ...\n"
	    "	%s -s setname -d [-M] -f -h all-hostnames\n"
	    "	%s -s setname -d [-M] [-f] drivename ...\n"
	    "	%s -s setname -d [-M] [-f] hostname ...\n"
	    "	%s -s setname -A enable | disable\n"
	    "	%s -s setname -t [-f]\n"
	    "	%s -s setname -r\n"
	    "	%s [-s setname] -j [-M]\n"
	    "	%s [-s setname] -w [-M]\n"
	    "	%s -s setname -P [-M]\n"
	    "	%s -s setname -b [-M]\n"
	    "	%s -s setname -o [-M] [-h hostname]\n"
	    "	%s [-s setname]\n"
	    "\n"
	    "		hostname = contents of /etc/nodename\n"
	    "		drivename = cNtNdN no slice\n"
	    "		[-M] for multi-owner set is optional except"
	    " on set creation\n"),
	    myname, myname, myname, myname, myname, myname, myname, myname,
	    myname, myname, myname, myname, myname, myname, myname, myname);
	md_exit(sp, (string == NULL) ? 0 : 1);
}

/*
 * The svm.sync rc script relies heavily on the metaset output.
 * Any changes to the metaset output MUST verify that the rc script
 * does not break. Not doing so may potentially leave the system
 * unusable. You have been WARNED.
 */
static int
printset(mdsetname_t *sp, md_error_t *ep)
{
	int			i, j;
	md_set_desc		*sd;
	md_drive_desc		*dd, *p;
	int			max_meds;
	md_mnnode_desc		*nd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/*
	 * Only get set owner information for traditional diskset.
	 * This set owner information is stored in the node records
	 * for a MN diskset.
	 */
	if (!(MD_MNSET_DESC(sd))) {
		if (metaget_setownership(sp, ep) == -1)
			return (-1);
	}

	if (((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) && !mdisok(ep))
		return (-1);

	if (MD_MNSET_DESC(sd)) {
		(void) printf(gettext(
		"\nMulti-owner Set name = %s, Set number = %d, Master = %s\n"),
		    sp->setname, sp->setno, sd->sd_mn_master_nodenm);
		if ((sd->sd_mn_master_nodeid == MD_MN_INVALID_NID) &&
		    (dd != NULL)) {
			(void) printf(gettext(
			    "Master and owner information unavailable "
			    "until joined (metaset -j)\n"));
		}
	} else {
		(void) printf(gettext(
		    "\nSet name = %s, Set number = %d\n"),
		    sp->setname, sp->setno);
	}

	if (MD_MNSET_DESC(sd)) {
		(void) printf(gettext("\n%-19.19s %-14.14s %-6.6s\n"),
		    gettext("Host"), gettext("Owner"), gettext("Member"));
		nd = sd->sd_nodelist;
		while (nd) {
			/*
			 * Don't print nodes that aren't ok since they may be
			 * removed from config during a reconfig cycle.  If a
			 * node was being added to a diskset and the entire
			 * cluster went down but the node being added was unable
			 * to reboot, there's no way to know if that node had
			 * its own node record set to OK or not.  So, node
			 * record is left in ADD state during reconfig cycle.
			 * When that node reboots and returns to the cluster,
			 * the reconfig cycle will either remove the node
			 * record (if not marked OK on that node) or will mark
			 * it OK on all nodes.
			 * It is very important to only remove a node record
			 * from the other nodes when that node record is not
			 * marked OK on its own node - otherwise, different
			 * nodes would have different nodelists possibly
			 * causing different nodes to to choose different
			 * masters.
			 */
			if (!(nd->nd_flags & MD_MN_NODE_OK)) {
				nd = nd->nd_next;
				continue;
			}
			if ((nd->nd_flags & MD_MN_NODE_ALIVE) &&
			    (nd->nd_flags & MD_MN_NODE_OWN)) {
				(void) printf(
				    gettext("  %-17.17s  %-12.12s  %-4.4s\n"),
				    nd->nd_nodename, gettext("multi-owner"),
				    gettext("Yes"));
			} else if ((!(nd->nd_flags & MD_MN_NODE_ALIVE)) &&
			    (nd->nd_flags & MD_MN_NODE_OWN)) {
				/* Should never be able to happen */
				(void) printf(
				    gettext("  %-17.17s  %-12.12s  %-4.4s\n"),
				    nd->nd_nodename, gettext("multi-owner"),
				    gettext("No"));
			} else if ((nd->nd_flags & MD_MN_NODE_ALIVE) &&
			    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
				(void) printf(
				    gettext("  %-17.17s  %-12.12s  %-4.4s\n"),
				    nd->nd_nodename, gettext(""),
				    gettext("Yes"));
			} else if ((!(nd->nd_flags & MD_MN_NODE_ALIVE)) &&
			    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
				(void) printf(
				    gettext("  %-17.17s  %-12.12s  %-4.4s\n"),
				    nd->nd_nodename, gettext(""),
				    gettext("No"));
			}
			nd = nd->nd_next;
		}
	} else {
		(void) printf("\n%-19.19s %-5.5s\n",
		    gettext("Host"), gettext("Owner"));
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/*
			 * Standard hostname field is 17 bytes but metaset will
			 * display up to MD_MAX_NODENAME, def in meta_basic.h
			 */
			(void) printf("  %-17.*s  %s\n", MD_MAX_NODENAME,
			    sd->sd_nodes[i], (sd->sd_flags & MD_SR_AUTO_TAKE ?
			    (sd->sd_isown[i] ? gettext("Yes (auto)") :
			    gettext("No (auto)"))
			    : (sd->sd_isown[i] ? gettext("Yes") : "")));
		}
	}

	if (sd->sd_med.n_cnt > 0)
		(void) printf("\n%-19.19s %-7.7s\n",
		    gettext("Mediator Host(s)"), gettext("Aliases"));

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	for (i = 0; i < max_meds; i++) {
		if (sd->sd_med.n_lst[i].a_cnt == 0)
			continue;
		/*
		 * Standard hostname field is 17 bytes but metaset will
		 * display up to MD_MAX_NODENAME, def in meta_basic.h
		 */
		(void) printf("  %-17.*s   ", MD_MAX_NODENAME,
		    sd->sd_med.n_lst[i].a_nm[0]);
		for (j = 1; j < sd->sd_med.n_lst[i].a_cnt; j++) {
			(void) printf("%s", sd->sd_med.n_lst[i].a_nm[j]);
			if (sd->sd_med.n_lst[i].a_cnt - j > 1)
				(void) printf(gettext(", "));
		}
		(void) printf("\n");
	}

	if (dd) {
		int	len = 0;


		/*
		 * Building a format string on the fly that will
		 * be used in (f)printf. This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		for (p = dd; p != NULL; p = p->dd_next)
			len = max(len, strlen(p->dd_dnp->cname));

		len += 2;
		(void) printf("\n%-*.*s %-5.5s\n", len, len,
		    gettext("Drive"),
		    gettext("Dbase"));
		for (p = dd; p != NULL; p = p->dd_next) {
			(void) printf("\n%-*.*s %-5.5s\n", len, len,
			    p->dd_dnp->cname,
			    (p->dd_dbcnt ? gettext("Yes") :
			    gettext("No")));
		}
	}

	return (0);
}

static int
printsets(mdsetname_t *sp, md_error_t *ep)
{
	int			i;
	mdsetname_t		*sp1;
	set_t			max_sets;

	/*
	 * print setname given.
	 */
	if (! metaislocalset(sp)) {
		if (printset(sp, ep))
			return (-1);
		return (0);
	}

	if ((max_sets = get_max_sets(ep)) == 0)
		return (-1);

	/*
	 * Print all known sets
	 */
	for (i = 1; i < max_sets; i++) {
		if ((sp1 = metasetnosetname(i, ep)) == NULL) {
			if (! mdiserror(ep, MDE_NO_SET))
				break;
			mdclrerror(ep);
			continue;
		}

		if (printset(sp1, ep))
			break;
	}
	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Print the current versionn of the cluster contract private interface.
 */
static void
printclusterversion()
{
	(void) printf("%s\n", METASETIFVERSION);
}

/*
 * Print the disks that make up the given disk set. This is used
 * exclusively by Sun Cluster and is contract private.
 * Should never be called with sname of a Multinode diskset.
 */
static int
printdisksin(char *sname, md_error_t *ep)
{
	mdsetname_t	*sp;
	md_drive_desc	*dd, *p;

	if ((sp = metasetname(sname, ep)) == NULL) {

		/*
		 * During a deletion of a set the associated service is
		 * put offline. The SC3.0 reservation code calls disksuite
		 * to find a list of disks associated with the set so that
		 * it can release the reservation on those disks. In this
		 * case there won't be any disks or even a set left. So just
		 * return.
		 */
		return (0);
	}

	if (metaget_setownership(sp, ep) == -1)
		return (-1);

	if (((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) && !mdisok(ep))
		return (-1);

	for (p = dd; p != NULL; p = p->dd_next)
		(void) printf("%s\n", p->dd_dnp->rname);

	return (0);
}

static void
parse_printset(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL;
	char		*sname = MD_LOCAL_NAME;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:")) != -1) {
		switch (c) {
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(sp, gettext("too many args"));

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (printsets(sp, ep) && !mdiserror(ep, MDE_SMF_NO_SERVICE)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_smf_isonline(meta_smf_getmask(), ep) == 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	md_exit(sp, 0);
}

static void
parse_add(int argc, char **argv)
{
	int			c, created_set;
	int			hosts = FALSE;
	int			meds = FALSE;
	int			auto_take = FALSE;
	int			force_label = FALSE;
	int			default_size = TRUE;
	mdsetname_t		*sp = NULL;
	char			*sname = MD_LOCAL_NAME;
	md_error_t		status = mdnullerror;
	md_error_t		 *ep = &status;
	mddrivenamelist_t	*dnlp = NULL;
	mddrivenamelist_t	*p;
	daddr_t			dbsize, nblks;
	mdsetname_t		*local_sp = NULL;
	int			multi_node = 0;
	md_set_desc		*sd;
	rval_e			sdssc_rval;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "MaA:hl:Lms:")) != -1) {
		switch (c) {
		case 'M':
			multi_node = 1;
			break;
		case 'A':
			/* verified sub-option in main */
			if (strcmp(optarg, "enable") == 0)
				auto_take = TRUE;
			break;
		case 'a':
			break;
		case 'h':
		case 'm':
			if (meds == TRUE || hosts == TRUE)
				usage(sp, gettext(
				    "only one -m or -h option allowed"));

			if (default_size == FALSE || force_label == TRUE)
				usage(sp, gettext(
				    "conflicting options"));

			if (c == 'h')
				hosts = TRUE;
			else
				meds = TRUE;
			break;
		case 'l':
			if (hosts == TRUE || meds == TRUE)
				usage(sp, gettext(
				    "conflicting options"));
			if (sscanf(optarg, "%ld", &dbsize) != 1) {
				md_eprintf(gettext(
				    "%s: bad format\n"), optarg);
				usage(sp, "");
			}

			default_size = FALSE;
			break;
		case 'L':
			/* Same criteria as -l */
			if (hosts == TRUE || meds == TRUE)
				usage(sp, gettext(
				    "conflicting options"));
			force_label = TRUE;
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext(
			    "unknown options"));
		}
	}

	/* Can only use -A enable when creating the single-node set */
	if (auto_take && hosts != TRUE)
		usage(sp, gettext("conflicting options"));

	argc -= optind;
	argv += optind;

	/*
	 * Add hosts
	 */
	if (hosts == TRUE) {

		if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		if (meta_lock(local_sp, TRUE, ep) != 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		/*
		 * Keep track of Cluster set creation. Need to complete
		 * the transaction no matter if the set was created or not.
		 */
		created_set = 0;

		/*
		 * Have no set, cannot take the lock, so only take the
		 * local lock.
		 */
		if ((sp = metasetname(sname, ep)) == NULL) {
			sdssc_rval = 0;
			if (multi_node) {
				/*
				 * When running on a cluster system that
				 * does not support MN disksets, the routine
				 * sdssc_mo_create_begin will be bound
				 * to the SVM routine not_bound_error
				 * which returns SDSSC_NOT_BOUND_ERROR.
				 *
				 * When running on a cluster system that
				 * does support MN disksets, the routine
				 * sdssc_mo_create_begin will be bound to
				 * the sdssc_mo_create_begin routine in
				 * library libsdssc_so.  A call to
				 * sdssc_mo_create_begin will return with
				 * either SDSSC_ERROR or SDSSC_OKAY. If
				 * an SDSSC_OKAY is returned, then the
				 * cluster framework has allocated a
				 * set number for this new set that is unique
				 * across traditional and MN disksets.
				 * Libmeta will get this unique set number
				 * by calling sdssc_get_index.
				 *
				 * When running on a non-cluster system,
				 * the routine sdssc_mo_create_begin
				 * will be bound to the SVM routine
				 * not_bound which returns SDSSC_NOT_BOUND.
				 * In this case, all sdssc routines will
				 * return SDSSC_NOT_BOUND.  No need to check
				 * for return value of SDSSC_NOT_BOUND since
				 * the libmeta call to get the set number
				 * (sdssc_get_index) will also fail with
				 * SDSSC_NOT_BOUND causing libmeta to
				 * determine its own set number.
				 */
				sdssc_rval = sdssc_mo_create_begin(sname, argc,
				    argv, SDSSC_PICK_SETNO);
				if (sdssc_rval == SDSSC_NOT_BOUND_ERROR) {
					(void) mderror(ep, MDE_NOT_MN, NULL);
					mde_perror(ep,
					"Cluster node does not support "
					"multi-owner diskset operations");
					md_exit(local_sp, 1);
				} else if (sdssc_rval == SDSSC_ERROR) {
					mde_perror(ep, "");
					md_exit(local_sp, 1);
				}
			} else {
				sdssc_rval = sdssc_create_begin(sname, argc,
				    argv, SDSSC_PICK_SETNO);
				if (sdssc_rval == SDSSC_ERROR) {
					mde_perror(ep, "");
					md_exit(local_sp, 1);
				}
			}
			/*
			 * Created diskset (as opposed to adding a
			 * host to an existing diskset).
			 */
			created_set = 1;

			sp = Zalloc(sizeof (*sp));
			sp->setname = Strdup(sname);
			sp->lockfd = MD_NO_LOCK;
			mdclrerror(ep);
		} else {
			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				mde_perror(ep, "");
				md_exit(local_sp, 1);
			}
			if (MD_MNSET_DESC(sd)) {
				multi_node = 1;
			}

			/*
			 * can't add hosts to an existing set & enable
			 * auto-take
			 */
			if (auto_take)
				usage(sp, gettext("conflicting options"));

			/*
			 * Have a valid set, take the set lock also.
			 *
			 * A MN diskset does not use the set meta_lock but
			 * instead uses the clnt_lock of rpc.metad and the
			 * suspend/resume feature of the rpc.mdcommd.  Can't
			 * use set meta_lock since class 1 messages are
			 * grabbing this lock and if this thread is holding
			 * the set meta_lock then no rpc.mdcommd suspend
			 * can occur.
			 */
			if (!multi_node) {
				if (meta_lock(sp, TRUE, ep) != 0) {
					mde_perror(ep, "");
					md_exit(local_sp, 1);
				}
			}
		}

		if (meta_set_addhosts(sp, multi_node, argc, argv, auto_take,
		    ep)) {
			if (created_set)
				sdssc_create_end(sname, SDSSC_CLEANUP);
			mde_perror(&status, "");
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}

		if (created_set)
			sdssc_create_end(sname, SDSSC_COMMIT);

		else {
			/*
			 * If adding hosts to existing diskset,
			 * call DCS svcs
			 */
			sdssc_add_hosts(sname, argc, argv);
		}
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 0);
	}

	/*
	 * Add mediators
	 */
	if (meds == TRUE) {

		if ((sp = metasetname(sname, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}
		if (MD_MNSET_DESC(sd)) {
			multi_node = 1;
		}

		if (meta_lock(local_sp, TRUE, ep) != 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}
		/*
		 * A MN diskset does not use the set meta_lock but
		 * instead uses the clnt_lock of rpc.metad and the
		 * suspend/resume feature of the rpc.mdcommd.  Can't
		 * use set meta_lock since class 1 messages are
		 * grabbing this lock and if this thread is holding
		 * the set meta_lock then no rpc.mdcommd suspend
		 * can occur.
		 */
		if (!multi_node) {
			if (meta_lock(sp, TRUE, ep) != 0) {
				mde_perror(ep, "");
				md_exit(local_sp, 1);
			}
		}

		if (meta_set_addmeds(sp, argc, argv, ep)) {
			mde_perror(&status, "");
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}

		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 0);
	}

	/*
	 * Add drives
	 */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	/* Determine if diskset is a MN diskset or not */
	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}
	if (MD_MNSET_DESC(sd)) {
		multi_node = 1;
	}

	if (meta_lock(local_sp, TRUE, ep) != 0) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	/* Make sure database size is within limits */
	if (default_size == FALSE) {
		if ((multi_node && dbsize < MDDB_MN_MINBLKS) ||
		    (!multi_node && dbsize < MDDB_MINBLKS))
			usage(sp, gettext(
			    "size (-l) is too small"));

		if ((multi_node && dbsize > MDDB_MN_MAXBLKS) ||
		    (!multi_node && dbsize > MDDB_MAXBLKS))
			usage(sp, gettext(
			    "size (-l) is too big"));
	}

	/*
	 * Have a valid set, take the set lock also.
	 *
	 * A MN diskset does not use the set meta_lock but
	 * instead uses the clnt_lock of rpc.metad and the
	 * suspend/resume feature of the rpc.mdcommd.  Can't
	 * use set meta_lock since class 1 messages are
	 * grabbing this lock and if this thread is holding
	 * the set meta_lock then no rpc.mdcommd suspend
	 * can occur.
	 */
	if (!multi_node) {
		if (meta_lock(sp, TRUE, ep) != 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}
	}


	/*
	 * If using the default size,
	 *   then let's adjust the default to the minimum
	 *   size currently in use.
	 */
	if (default_size) {
		dbsize = multi_node ? MD_MN_DBSIZE : MD_DBSIZE;
		if ((nblks = meta_db_minreplica(sp, ep)) < 0)
			mdclrerror(ep);
		else
			dbsize = nblks;	/* adjust replica size */
	}

	if ((c = metadrivenamelist(&sp, &dnlp, argc, argv, ep)) < 0) {
		mde_perror(ep, "");
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 1);
	}

	if (c == 0) {
		md_perror(gettext(
		    "No drives specified to add.\n"));
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 1);
	}

	if (meta_set_adddrives(sp, dnlp, dbsize, force_label, ep)) {
		metafreedrivenamelist(dnlp);
		mde_perror(ep, "");
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 1);
	}

	/*
	 * MN disksets don't have a device id in the master block
	 * For traditional disksets, check for the drive device
	 * id not fitting in the master block
	 */
	if (!multi_node) {
		for (p = dnlp; p != NULL; p = p->next) {
			int 		fd;
			ddi_devid_t	devid;
			mdname_t	*np;

			np = metaslicename(p->drivenamep, 0, ep);
			if (np == NULL)
				continue;

			if ((fd = open(np->rname, O_RDONLY | O_NDELAY)) < 0)
				continue;

			if (devid_get(fd, &devid) == 0) {
				size_t len;

				len = devid_sizeof(devid);
				if (len > (DEV_BSIZE - sizeof (mddb_mb_t)))
					(void) mddserror(ep,
					    MDE_DS_NOTSELFIDENTIFY, NULL, NULL,
					    np->rname, NULL);
				devid_free(devid);
			} else {
				(void) mddserror(ep, MDE_DS_NOTSELFIDENTIFY,
				    NULL, NULL, np->rname, NULL);
			}
			(void) close(fd);
		}
	}

	/*
	 * MN disksets don't use DCS clustering services.
	 * For traditional disksets:
	 * There's not really much we can do here if this call fails.
	 * The drives have been added to the set and DiskSuite believes
	 * it owns the drives.
	 * Relase the set and hope for the best.
	 */
	if ((!multi_node) &&
	    (sdssc_notify_service(sname, Make_Primary) == SDSSC_ERROR)) {
		(void) meta_set_release(sp, ep);
		(void) printf(gettext(
		    "Sun Clustering failed to make set primary\n"));
	}

	metafreedrivenamelist(dnlp);
	if (!multi_node)
		(void) meta_unlock(sp, ep);
	md_exit(local_sp, 0);
}

static void
parse_balance(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL;
	char		*sname = MD_LOCAL_NAME;
	md_error_t	status = mdnullerror;
	md_set_desc	*sd;
	int		multi_node = 0;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "Mbs:")) != -1) {
		switch (c) {
		case 'M':
			break;
		case 'b':
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(sp, gettext("too many args"));

	if ((sp = metasetname(sname, &status)) == NULL) {
		mde_perror(&status, "");
		md_exit(sp, 1);
	}
	if ((sd = metaget_setdesc(sp, &status)) == NULL) {
		mde_perror(&status, "");
		md_exit(sp, 1);
	}
	if (MD_MNSET_DESC(sd)) {
		multi_node = 1;
	}
	/*
	 * Have a valid set, take the set lock also.
	 *
	 * A MN diskset does not use the set meta_lock but
	 * instead uses the clnt_lock of rpc.metad and the
	 * suspend/resume feature of the rpc.mdcommd.  Can't
	 * use set meta_lock since class 1 messages are
	 * grabbing this lock and if this thread is holding
	 * the set meta_lock then no rpc.mdcommd suspend
	 * can occur.
	 */
	if (!multi_node) {
		if (meta_lock(sp, TRUE, &status) != 0) {
			mde_perror(&status, "");
			md_exit(sp, 1);
		}
	}

	if (meta_set_balance(sp, &status) != 0) {
		mde_perror(&status, "");
		md_exit(sp, 1);
	}
	md_exit(sp, 0);
}

static void
parse_autotake(int argc, char **argv)
{
	int			c;
	int			enable = 0;
	mdsetname_t		*sp = NULL;
	char			*sname = MD_LOCAL_NAME;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "A:s:")) != -1) {
		switch (c) {
		case 'A':
			/* verified sub-option in main */
			if (strcmp(optarg, "enable") == 0)
				enable = 1;
			break;
		case 's':
			/* verified presence of setname in main */
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_lock(sp, TRUE, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_set_auto_take(sp, enable, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	md_exit(sp, 0);
}

static void
parse_del(int argc, char **argv)
{
	int			c;
	mdsetname_t		*sp = NULL;
	char			*sname = MD_LOCAL_NAME;
	int			hosts = FALSE;
	int			meds = FALSE;
	int			forceflg = FALSE;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;
	mddrivenamelist_t	*dnlp = NULL;
	mdsetname_t		*local_sp = NULL;
	md_set_desc		*sd;
	int			multi_node = 0;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "Mdfhms:")) != -1) {
		switch (c) {
		case 'M':
			break;
		case 'd':
			break;
		case 'f':
			forceflg = TRUE;
			break;
		case 'h':
		case 'm':
			if (meds == TRUE || hosts == TRUE)
				usage(sp, gettext(
				    "only one -m or -h option allowed"));

			if (c == 'h')
				hosts = TRUE;
			else
				meds = TRUE;
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}
	if (MD_MNSET_DESC(sd))
		multi_node = 1;

	if (meta_lock(local_sp, TRUE, ep) != 0) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	/*
	 * Have a valid set, take the set lock also.
	 *
	 * A MN diskset does not use the set meta_lock but
	 * instead uses the clnt_lock of rpc.metad and the
	 * suspend/resume feature of the rpc.mdcommd.  Can't
	 * use set meta_lock since class 1 messages are
	 * grabbing this lock and if this thread is holding
	 * the set meta_lock then no rpc.mdcommd suspend
	 * can occur.
	 */
	if (!multi_node) {
		if (meta_lock(sp, TRUE, ep) != 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}
	}

	/*
	 * Delete hosts
	 */
	if (hosts == TRUE) {
		if (meta_check_ownership(sp, ep) != 0) {
			/*
			 * If we don't own the set bail out here otherwise
			 * we could delete the node from the DCS service
			 * yet not delete the host from the set.
			 */
			mde_perror(ep, "");
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}
		if (sdssc_delete_hosts(sname, argc, argv) == SDSSC_ERROR) {
			if (!metad_isautotakebyname(sname)) {
				/*
				 * SC could have been installed after the set
				 * was created. We still want to be able to
				 * delete these sets.
				 */
				md_perror(gettext(
				    "Failed to delete hosts from DCS service"));
				if (!multi_node)
					(void) meta_unlock(sp, ep);
				md_exit(local_sp, 1);
			}
		}
		if (meta_set_deletehosts(sp, argc, argv, forceflg, ep)) {
			if (sdssc_add_hosts(sname, argc, argv) == SDSSC_ERROR) {
				(void) printf(gettext(
				    "Failed to restore host(s) in DCS "
				    "database\n"));
			}
			mde_perror(ep, "");
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 0);
	}

	/*
	 * Delete mediators
	 */
	if (meds == TRUE) {
		if (meta_set_deletemeds(sp, argc, argv, forceflg, ep)) {
			mde_perror(ep, "");
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 0);
	}

	/*
	 * Delete drives
	 */

	if ((c = metadrivenamelist(&sp, &dnlp, argc, argv, ep)) < 0) {
		mde_perror(ep, "");
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 1);
	}

	if (c == 0) {
		md_perror(gettext(
		    "No drives specified to delete.\n"));
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 1);
	}

	if (meta_set_deletedrives(sp, dnlp, forceflg, ep)) {
		metafreedrivenamelist(dnlp);
		mde_perror(ep, "");
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, 1);
	}

	metafreedrivenamelist(dnlp);
	if (!multi_node)
		(void) meta_unlock(sp, ep);
	md_exit(local_sp, 0);
}

static void
parse_isowner(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL;
	char		*sname = MD_LOCAL_NAME;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	char		*host = NULL;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "Moh:s:")) != -1) {
		switch (c) {
		case 'M':
			break;
		case 'o':
			break;
		case 'h':
			if (host != NULL) {
				usage(sp, gettext(
				    "only one -h option allowed"));
			}
			host = optarg;
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(sp, gettext("too many args"));

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (host == NULL) {
		if (meta_check_ownership(sp, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else {
		if (meta_check_ownership_on_host(sp, host, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}
	md_exit(sp, 0);
}

static void
parse_purge(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL;
	mdsetname_t	*local_sp = NULL;
	md_drive_desc	*dd;
	char		*sname = MD_LOCAL_NAME;
	char		*thishost = mynode();
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		bypass_cluster_purge = 0;
	int		forceflg = FALSE;
	int		ret = 0;
	int		multi_node = 0;
	md_set_desc		*sd;

	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "C:fPs:")) != -1) {
		switch (c) {
		case 'M':
			break;
		case 'C':
			bypass_cluster_purge = 1;
			break;
		case 'f':
			forceflg = TRUE;
			break;
		case 'P':
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(sp, gettext("too many arguments"));

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	if (meta_lock(local_sp, TRUE, ep) != 0) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}
	if (MD_MNSET_DESC(sd))
		multi_node = 1;

	if (!multi_node) {
		if (meta_lock(sp, TRUE, ep) != 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}
	}

	/* Must not own the set if purging it from this host */
	if (meta_check_ownership(sp, ep) == 0) {
		/*
		 * Need to see if there are disks in the set, if not then
		 * there is no ownership but meta_check_ownership returns 0
		 */
		dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST), ep);
		if (!mdisok(ep)) {
			mde_perror(ep, "");
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}
		if (dd != NULL) {
			(void) printf(gettext
			    ("Must not be owner of the set when purging it\n"));
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}
	}
	/*
	 * Remove the node from the DCS service
	 */
	if (!bypass_cluster_purge) {
		if (sdssc_delete_hosts(sname, 1, &thishost) == SDSSC_ERROR) {
			md_perror(gettext
			    ("Failed to purge hosts from DCS service"));
			if (!multi_node)
				(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
		}
	}

	if ((ret = meta_set_purge(sp, bypass_cluster_purge, forceflg,
	    ep)) != 0) {
		if (!bypass_cluster_purge) {
			if (sdssc_add_hosts(sname, 1, &thishost) ==
			    SDSSC_ERROR) {
				(void) printf(gettext(
				    "Failed to restore host in DCS "
				    "database\n"));
			}
		}
		mde_perror(ep, "");
		if (!multi_node)
			(void) meta_unlock(sp, ep);
		md_exit(local_sp, ret);
	}

	if (!multi_node)
		(void) meta_unlock(sp, ep);
	md_exit(local_sp, 0);
}

static void
parse_query(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL;
	mddb_dtag_lst_t	*dtlp = NULL;
	mddb_dtag_lst_t	*tdtlp;
	char		*sname = MD_LOCAL_NAME;
	md_error_t	status = mdnullerror;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "Mqs:")) != -1) {
		switch (c) {
		case 'M':
			break;
		case 'q':
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(sp, gettext("too many args"));

	if ((sp = metasetname(sname, &status)) == NULL) {
		mde_perror(&status, "");
		md_exit(sp, 1);
	}

	if (meta_lock(sp, TRUE, &status) != 0) {
		mde_perror(&status, "");
		md_exit(sp, 1);
	}

	if (meta_set_query(sp, &dtlp, &status) != 0) {
		mde_perror(&status, "");
		md_exit(sp, 1);
	}

	if (dtlp != NULL)
		(void) printf("The following tag(s) were found:\n");

	for (tdtlp = dtlp; tdtlp != NULL; tdtlp = dtlp) {
		dtlp = tdtlp->dtl_nx;
		(void) printf("%2d - %s - %s", tdtlp->dtl_dt.dt_id,
		    tdtlp->dtl_dt.dt_hn,
		    ctime((long *)&tdtlp->dtl_dt.dt_tv.tv_sec));
		Free(tdtlp);
	}

	md_exit(sp, 0);
}

/* Should never be called with sname of a Multinode diskset. */
static void
parse_releaseset(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	char		*sname = MD_LOCAL_NAME;
	sdssc_boolean_e	cluster_release = SDSSC_False;
	sdssc_version_t	vers;
	rval_e		rval;
	md_set_desc	*sd;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "C:s:r")) != -1) {
		switch (c) {
		case 'C':
			cluster_release = SDSSC_True;
			break;
		case 's':
			sname = optarg;
			break;
		case 'r':
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage(sp, gettext("too many args"));

	(void) memset(&vers, 0, sizeof (vers));

	if ((sdssc_version(&vers) == SDSSC_OKAY) &&
	    (vers.major == 3) &&
	    (cluster_release == SDSSC_False)) {

		/*
		 * If the release is being done by the user via the CLI
		 * we need to notify the DCS to release this node as being
		 * the primary. The reason nothing else needs to be done
		 * is due to the fact that the reservation code will exec
		 * metaset -C release to complete the operation.
		 */
		rval = sdssc_notify_service(sname, Release_Primary);
		if (rval == SDSSC_ERROR) {
			(void) printf(gettext(
			    "metaset: failed to notify DCS of release\n"));
		}
		md_exit(NULL, rval == SDSSC_ERROR);
	}

	if ((sp = metasetname(sname, ep)) == NULL) {

		/*
		 * It's entirely possible for the SC3.0 reservation code
		 * to call for DiskSet to release a diskset and have that
		 * diskset not exist. During a diskset removal DiskSuite
		 * maybe able to remove all traces of the diskset before
		 * the reservation code execs metaset -C release in which
		 * case the metasetname will fail, but the overall command
		 * shouldn't.
		 */
		if (vers.major == 3)
			md_exit(sp, 0);
		else {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (sd->sd_flags & MD_SR_AUTO_TAKE) {
		md_eprintf(gettext("cannot release auto-take diskset\n"));
		md_exit(sp, 1);
	}

	if (meta_lock_nowait(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 10);	/* special errcode */
	}

	if (meta_set_release(sp, ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	md_exit(sp, 0);
}

/* Should never be called with sname of a Multinode diskset. */
static void
parse_takeset(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL;
	int		flags = 0;
	char		*sname = MD_LOCAL_NAME;
	mhd_mhiargs_t	mhiargs;
	char 		*cp = NULL;
	int		pos = -1;	/* position of timeout value */
	int		usetag = 0;
	static char	*nullopts[] = { NULL };
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	sdssc_boolean_e	cluster_take = SDSSC_False;
	sdssc_version_t	vers;
	rval_e		rval;
	int		set_take_rval;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "C:fs:tu:y")) != -1) {
		switch (c) {
		case 'C':
			cluster_take = SDSSC_True;
			break;
		case 'f':
			flags |= TAKE_FORCE;
			break;
		case 's':
			sname = optarg;
			break;
		case 't':
			break;
		case 'u':
			usetag = atoi(optarg);
			flags |= TAKE_USETAG;
			break;
		case 'y':
			flags |= TAKE_USEIT;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	mhiargs = defmhiargs;

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage(sp, gettext("too many args"));

	/*
	 * If we have a list of timeout value overrides, handle it here
	 */
	while (argv[0] != NULL && *argv[0] != '\0') {
		/*
		 * The use of the nullopts[] "token list" here is to make
		 * getsubopts() simply parse a comma separated list
		 * returning either "" or the contents of the field, the
		 * end condition is exaustion of the initial string, which
		 * is modified in the process.
		 */
		(void) getsubopt(&argv[0], nullopts, &cp);

		c = 0;			/* re-use c as temp value of timeout */

		if (*cp != '-')		/* '-' uses default */
			c = atoi(cp);

		if (c < 0) {
			usage(sp, gettext(
			    "time out values must be > 0"));
		}

		if (++pos > 3) {
			usage(sp, gettext(
			    "too many timeout values specified."));
		}

		if (c == 0)		/* 0 or "" field uses default */
			continue;

		/*
		 * Assign temp value to appropriate structure member based on
		 * its position in the comma separated list.
		 */
		switch (pos) {
			case 0:
				mhiargs.mh_ff = c;
				break;

			case 1:
				mhiargs.mh_tk.reinstate_resv_delay = c;
				break;

			case 2:
				mhiargs.mh_tk.min_ownership_delay = c;
				break;

			case 3:
				mhiargs.mh_tk.max_ownership_delay = c;
				break;
		}
	}

	(void) memset(&vers, 0, sizeof (vers));

	if ((sdssc_version(&vers) == SDSSC_OKAY) &&
	    (vers.major == 3) &&
	    (cluster_take == SDSSC_False)) {

		/*
		 * If the take is beging done by the user via the CLI we need
		 * to notify the DCS to make this current node the primary.
		 * The SC3.0 reservation code will in turn exec metaset with
		 * the -C take arg to complete this operation.
		 */
		if ((rval = sdssc_notify_service(sname, Make_Primary)) ==
		    SDSSC_ERROR) {
			(void) printf(gettext(
			    "metaset: failed to notify DCS of take\n"));
		}
		md_exit(NULL, rval == SDSSC_ERROR);
	}

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if ((vers.major == 3) && (meta_check_ownership(sp, ep) == 0)) {

		/*
		 * If we're running in a cluster environment and this
		 * node already owns the set. Don't bother trying to
		 * take the set again. There's one case where an adminstrator
		 * is adding disks to a set for the first time. metaset
		 * will take the ownership of the set at that point. During
		 * that add operation SC3.0 notices activity on the device
		 * and also tries to perform a take operation. The SC3.0 take
		 * will fail because the adminstrative add has the set locked
		 */
		md_exit(sp, 0);
	}

	if (meta_lock_nowait(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 10);	/* special errcode */
	}

	/*
	 * If a 2 is returned from meta_set_take, this take was able to resolve
	 * an unresolved replicated disk (i.e. a disk is now available that
	 * had been missing during the import of the replicated diskset).
	 * Need to release the diskset and re-take in order to have
	 * the subdrivers re-snarf using the newly resolved (or newly mapped)
	 * devids.  This also allows the namespace to be updated with the
	 * correct major names in the case where the disk being replicated
	 * was handled by a different driver than the replicated disk.
	 */
	set_take_rval = meta_set_take(sp, &mhiargs, flags, usetag, &status);
	if (set_take_rval == 2) {
		if (meta_set_release(sp, &status)) {
			mde_perror(&status,
			    "Need to release and take set to resolve names.");
			md_exit(sp, 1);
		}
		metaflushdrivenames();
		metaflushsetname(sp);
		set_take_rval = meta_set_take(sp, &mhiargs,
		    (flags | TAKE_RETAKE), usetag, &status);
	}

	if (set_take_rval == -1) {
		mde_perror(&status, "");
		if (mdismddberror(&status, MDE_DB_TAGDATA))
			md_exit(sp, 2);
		if (mdismddberror(&status, MDE_DB_ACCOK))
			md_exit(sp, 3);
		if (mdismddberror(&status, MDE_DB_STALE))
			md_exit(sp, 66);
		md_exit(sp, 1);
	}
	md_exit(sp, 0);
}

/*
 * Joins a node to a specific set or to all multinode disksets known
 * by this node.  If set is specified then caller should have verified
 * that the set is a multinode diskset.
 *
 * If an error occurs, metaset exits with a 1.
 * If there is no error, metaset exits with a 0.
 */
static void
parse_joinset(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL, *local_sp = NULL;
	char		*sname = MD_LOCAL_NAME;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	md_set_desc	*sd;
	char		buf[BUFSIZ];
	char		*p = buf;
	set_t		max_sets, setno;
	int		err, cumm_err = 0;
	size_t		bufsz;

	bufsz = sizeof (buf);
	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "Ms:j")) != -1) {
		switch (c) {
		case 'M':
			break;
		case 'j':
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage(sp, gettext("too many args"));

	/*
	 * If no setname option was used, then join all disksets
	 * that this node knows about.   Attempt to join all
	 * disksets that this node knows about.
	 *
	 * Additional text is added to the error messages during
	 * this section of code in order to help the user understand
	 * why the 'join of all sets' failed and which set caused
	 * the failure.
	 */

	/*
	 * Hold local set lock throughout this call to keep
	 * other actions from interfering (such as creating a new
	 * set, etc.).
	 */
	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_lock(local_sp, TRUE, ep) != 0) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	if (strcmp(sname, MD_LOCAL_NAME) == 0) {
		/*
		 * If no set name is given, then walk through all sets
		 * on this node which could include:
		 * 	- MN disksets
		 *	- traditional disksets
		 *	- non-existent disksets
		 * Attempt to join the MN disksets.
		 * If the join of one set fails, print out an error message
		 * about that set and continue the walk.
		 */
		if ((max_sets = get_max_sets(ep)) == 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		/* Start walking through all possible disksets */
		for (setno = 1; setno < max_sets; setno++) {
			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else {
					(void) sprintf(p, gettext(
					"Unable to get set %d information"),
					    setno);
					mde_perror(ep, p);
					cumm_err = 1;
					mdclrerror(ep);
					continue;
				}
			}

			/* If setname is there, set desc should exist. */
			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				(void) snprintf(p, bufsz, gettext(
				    "Unable to get set %s desc information"),
				    sp->setname);
				mde_perror(ep, p);
				cumm_err = 1;
				mdclrerror(ep);
				continue;
			}

			/* Only check MN disksets */
			if (!MD_MNSET_DESC(sd)) {
				continue;
			}

			/*
			 * Return value of 0 is success.
			 * Return value of -1 means a failure.
			 * Return value of -2 means set could not be
			 * joined, but shouldn't cause an error.
			 * Reasons would be:
			 * 	- no drives in set
			 * 	- node already joined to set
			 * Return value of -3 means joined stale set.
			 * Can't check for all reasons here
			 * since set isn't locked yet across all
			 * nodes in the cluster.  The call
			 * to libmeta routine, meta_set_join, will
			 * lock across the cluster and perform
			 * the checks.
			 */
			if ((err = meta_set_join(sp, ep)) == -1) {
				/* Print error of diskset join failure */
				(void) snprintf(p, bufsz,
				    gettext("Join to diskset %s failed"),
				    sp->setname);
				mde_perror(ep, p);
				cumm_err = 1;
				mdclrerror(ep);
				continue;
			}

			if (err == -3) {
				/* Print error of diskset join failure */
				(void) snprintf(p, bufsz,
				    gettext("Joined to stale diskset %s"),
				    sp->setname);
				mde_perror(ep, p);
				mdclrerror(ep);
			}

			mdclrerror(ep);
		}

		md_exit(local_sp, cumm_err);
	}

	/*
	 * Code for a specific set is much simpler.
	 * Error messages don't need extra text since specific setname
	 * was used.
	 * Don't need to lock the local set, just the specific set given.
	 */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	/*
	 * Fail command if meta_set_join returns -1.
	 *
	 * Return of 0 means that node joined set.
	 *
	 * Return of -2 means that node was unable to
	 * join a set since that set had no drives
	 * or that had already joined the set.  No
	 * need to fail the command for these reasons.
	 *
	 * Return of -3 means that set is stale.
	 * Return a value of 66 to historically match traditional disksets.
	 */
	if ((err = meta_set_join(sp, ep)) == -1) {
		mde_perror(&status, "");
		md_exit(local_sp, 1);
	}

	if (err == -3) {
		/* Print error of diskset join failure */
		(void) snprintf(p, bufsz,
		    gettext("Joined to stale diskset %s"),
		    sp->setname);
		mde_perror(&status, "");
		md_exit(local_sp, 66);
	}

	md_exit(local_sp, 0);
}

/*
 * Withdraws a node from a specific set or from all multinode disksets known
 * by this node.  If set is specified then caller should have verified
 * that the set is a multinode diskset.
 *
 * If an error occurs, metaset exits with a 1.
 * If there is no error, metaset exits with a 0.
 */
static void
parse_withdrawset(int argc, char **argv)
{
	int		c;
	mdsetname_t	*sp = NULL, *local_sp = NULL;
	char		*sname = MD_LOCAL_NAME;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	char		buf[BUFSIZ];
	char		*p = buf;
	md_set_desc	*sd;
	set_t		max_sets, setno;
	int		err, cumm_err = 0;
	size_t		bufsz;

	bufsz = sizeof (buf);
	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "Ms:w")) != -1) {
		switch (c) {
		case 'M':
			break;
		case 'w':
			break;
		case 's':
			sname = optarg;
			break;
		default:
			usage(sp, gettext("unknown options"));
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage(sp, gettext("too many args"));

	/*
	 * If no setname option was used, then withdraw from all disksets
	 * that this node knows about.
	 *
	 * Additional text is added to the error messages during
	 * this section of code in order to help the user understand
	 * why the 'withdraw from all sets' failed and which set caused
	 * the failure.
	 */

	/*
	 * Hold local set lock throughout this call to keep
	 * other actions from interfering (such as creating a new
	 * set, etc.).
	 */
	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_lock(local_sp, TRUE, ep) != 0) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	if (strcmp(sname, MD_LOCAL_NAME) == 0) {
		/*
		 * If no set name is given, then walk through all sets
		 * on this node which could include:
		 * 	- MN disksets
		 *	- traditional disksets
		 *	- non-existent disksets
		 * Attempt to withdraw from the MN disksets.
		 * If the withdraw of one set fails, print out an error
		 * message about that set and continue the walk.
		 */
		if ((max_sets = get_max_sets(ep)) == 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		/* Start walking through all possible disksets */
		for (setno = 1; setno < max_sets; setno++) {
			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else {
					(void) sprintf(p, gettext(
					    "Unable to get set %d information"),
					    setno);
					mde_perror(ep, p);
					cumm_err = 1;
					mdclrerror(ep);
					continue;
				}
			}

			/* If setname is there, set desc should exist. */
			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				(void) snprintf(p, bufsz, gettext(
				    "Unable to get set %s desc information"),
				    sp->setname);
				mde_perror(ep, p);
				cumm_err = 1;
				mdclrerror(ep);
				continue;
			}

			/* Only check MN disksets */
			if (!MD_MNSET_DESC(sd)) {
				continue;
			}

			/*
			 * Return value of 0 is success.
			 * Return value of -1 means a failure.
			 * Return value of -2 means set could not be
			 * withdrawn from, but this shouldn't cause
			 * an error.  Reasons would be:
			 * 	- no drives in set
			 * 	- node already withdrawn from set
			 * Can't check for all reasons here
			 * since set isn't locked yet across all
			 * nodes in the cluster.  The call
			 * to libmeta routine, meta_set_withdraw, will
			 * lock across the cluster and perform
			 * the checks.
			 */
			if ((err = meta_set_withdraw(sp, ep)) == -1) {
				/* Print error of diskset withdraw failure */
				(void) snprintf(p, bufsz,
				    gettext("Withdraw from diskset %s failed"),
				    sp->setname);
				mde_perror(ep, p);
				mdclrerror(ep);
				cumm_err = 1;
				continue;
			}

			if (err == -2) {
				mdclrerror(ep);
				continue;
			}

			mdclrerror(ep);
		}
		md_exit(local_sp, cumm_err);
	}


	/*
	 * Code for a specific set is much simpler.
	 * Error messages don't need extra text since specific setname
	 * was used.
	 * Don't need to lock the local set, just the specific set given.
	 */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(local_sp, 1);
	}

	/*
	 * Fail command if meta_set_withdraw returns -1.
	 *
	 * Return of 0 means that node withdrew from set.
	 *
	 * Return of -2 means that node was unable to
	 * withdraw from a set since that set had no drives
	 * or node was not joined to set.  No
	 * need to fail the command for these reasons.
	 */
	if (meta_set_withdraw(sp, ep) == -1) {
		mde_perror(&status, "");
		md_exit(local_sp, 1);
	}

	md_exit(local_sp, 0);
}

static void
parse_cluster(int argc, char **argv, int multi_node)
{
	int			c, error, new_argc, x;
	enum cluster_cmd	cmd = ccnotspecified;
	char			*hostname = SDSSC_PROXY_PRIMARY;
	char			*argument = NULL;
	char			*sname = MD_LOCAL_NAME;
	char			primary_node[SDSSC_NODE_NAME_LEN];
	char			**new_argv = NULL;
	char			**np = NULL;
	mdsetname_t		*sp = NULL;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "C:s:h:ftu:yr")) != -1) {
		switch (c) {
		case 'C':
			if (cmd != ccnotspecified) {
				md_exit(sp, -1);
			}
			argument = optarg;

			if (strcmp(argument, "disksin") == 0) {
				cmd = clusterdisksin;
			} else if (strcmp(argument, "version") == 0) {
				cmd = clusterversion;
			} else if (strcmp(argument, "release") == 0) {
				cmd = clusterrelease;
			} else if (strcmp(argument, "take") == 0) {
				cmd = clustertake;
			} else if (strcmp(argument, "proxy") == 0) {
				cmd = clusterproxy;
			} else if (strcmp(argument, "purge") == 0) {
				cmd = clusterpurge;
			} else {
				md_exit(sp, -1);
			}

			break;

		case 'h':
			hostname = optarg;
			break;

		case 's':
			sname = optarg;
			break;

		case 'f':
		case 't':
		case 'u':
		case 'y':
		case 'r':
			break;

		default:
			md_exit(sp, -1);
		}
	}

	/* Now call the appropriate command function. */
	switch (cmd) {
	case clusterversion:
		printclusterversion();
		break;

	case clusterdisksin:
		if (printdisksin(sname, ep)) {
			md_exit(sp, -1);
		}
		break;

	case clusterrelease:
		if (multi_node) {
			usage(sp, gettext(
			    "-C release is not allowed on multi-owner"
			    " disksets"));
		}
		parse_releaseset(argc, argv);
		break;

	case clustertake:
		if (multi_node) {
			usage(sp, gettext(
			    "-C take is not allowed on multi-owner disksets"));
		}
		parse_takeset(argc, argv);
		break;

	case clusterproxy:
		if (multi_node) {
			usage(sp, gettext(
			    "-C proxy is not allowed on multi-owner disksets"));
		}

		if ((new_argv = calloc(argc, sizeof (char *))) == NULL) {
			(void) printf(gettext("Out of memory\n"));
			md_exit(sp, 1);
		}

		np = new_argv;
		new_argc = 0;
		(void) memset(primary_node, '\0', SDSSC_NODE_NAME_LEN);

		for (x = 0; x < argc; x++) {
			if (strcmp(argv[x], "-C") == 0) {

				/*
				 * Need to skip the '-C proxy' args so
				 * just increase x by one and the work is
				 * done.
				 */
				x++;
			} else {
				*np++ = strdup(argv[x]);
				new_argc++;
			}
		}

		switch (sdssc_get_primary_host(sname, primary_node,
		    SDSSC_NODE_NAME_LEN)) {
		case SDSSC_ERROR:
			md_exit(sp, 1);
			break;

		case SDSSC_NO_SERVICE:
			if (hostname != SDSSC_PROXY_PRIMARY) {
				(void) strlcpy(primary_node, hostname,
				    SDSSC_NODE_NAME_LEN);
			}
			break;
		}

		if (sdssc_cmd_proxy(new_argc, new_argv,
		    primary_node[0] == '\0' ? SDSSC_PROXY_PRIMARY :
		    primary_node, &error) == SDSSC_PROXY_DONE) {
			md_exit(sp, error);
		} else {
			(void) printf(gettext(
			    "Couldn't proxy command\n"));
			md_exit(sp, 1);
		}
		break;

	case clusterpurge:
		parse_purge(argc, argv);
		break;

	default:
		break;
	}

	md_exit(sp, 0);
}

/*
 * parse args and do it
 */
int
main(int argc, char *argv[])
{
	enum metaset_cmd	cmd = notspecified;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;
	mdsetname_t		*sp = NULL;
	char			*hostname = SDSSC_PROXY_PRIMARY;
	char			*sname = MD_LOCAL_NAME;
	char			*auto_take_option = NULL;
	char			primary_node[SDSSC_NODE_NAME_LEN];
	int			error, c, stat;
	int			auto_take = FALSE;
	md_set_desc		*sd;
	int			mflag = 0;
	int			multi_node = 0;
	rval_e			sdssc_res;

	/*
	 * Get the locale set up before calling any other routines
	 * with messages to ouput.  Just in case we're not in a build
	 * environment, make sure that TEXT_DOMAIN gets set to
	 * something.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	sdssc_res = sdssc_bind_library();
	if (sdssc_res == SDSSC_ERROR) {
		(void) printf(gettext(
		    "%s: Interface error with libsds_sc.so\n"), argv[0]);
		exit(1);
	}

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	optind = 1;
	opterr = 1;

	/*
	 * NOTE: The "C" option is strictly for cluster use. it is not
	 * and should not be documented for the customer. - JST
	 */
	while ((c = getopt(argc, argv, "C:MaA:bdfh:jl:Lm:oPqrs:tu:wy?"))
	    != -1) {
		switch (c) {
		case 'M':
			mflag = 1;
			break;
		case 'A':
			auto_take = TRUE;
			if (optarg == NULL || !(strcmp(optarg, "enable") == 0 ||
			    strcmp(optarg, "disable") == 0))
				usage(sp, gettext(
				    "-A: enable or disable must be specified"));
			auto_take_option = optarg;
			break;
		case 'a':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = add;
			break;
		case 'b':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = balance;
			break;
		case 'd':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = delete;
			break;
		case 'C':	/* cluster commands */
			if (cmd != notspecified) {
				md_exit(sp, -1);    /* conflicting options */
			}
			cmd = cluster;
			break;
		case 'f':
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'j':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = join;
			break;
		case 'l':
			break;
		case 'L':
			break;
		case 'm':
			break;
		case 'o':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = isowner;
			break;
		case 'P':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = purge;
			break;
		case 'q':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = query;
			break;
		case 'r':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = release;
			break;
		case 's':
			sname = optarg;
			break;
		case 't':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = take;
			break;
		case 'u':
			break;
		case 'w':
			if (cmd != notspecified) {
				usage(sp, gettext(
				    "conflicting options"));
			}
			cmd = withdraw;
			break;
		case 'y':
			break;
		case '?':
			if (optopt == '?')
				usage(sp, NULL);
			/*FALLTHROUGH*/
		default:
			if (cmd == cluster) {    /* cluster is silent */
				md_exit(sp, -1);
			} else {
				usage(sp, gettext(
				    "unknown command"));
			}
		}
	}

	/* check if suncluster is installed and -A enable specified */
	if (auto_take && sdssc_res != SDSSC_NOT_BOUND &&
	    strcmp(auto_take_option, "enable") == 0) {
		md_eprintf(gettext(
		    "cannot enable auto-take when SunCluster is installed\n"));
		md_exit(sp, 1);
	}

	/*
	 * At this point we know that if the -A enable option is specified
	 * for an auto-take diskset that SC is not installed on the machine, so
	 * all of the sdssc calls will just be no-ops.
	 */

	/* list sets */
	if (cmd == notspecified && auto_take == FALSE) {
		parse_printset(argc, argv);
		/*NOTREACHED*/
	}

	if (meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* snarf MDDB */
	if (meta_setup_db_locations(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/*
	 * If sname is a diskset - check for multi_node.
	 * It is possible for sname to not exist.
	 */
	if (strcmp(sname, MD_LOCAL_NAME)) {
		if ((sp = metasetname(sname, ep)) != NULL) {
			/* Set exists - check for MN diskset */
			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				mde_perror(ep, "");
				md_exit(sp, 1);
			}
			if (MD_MNSET_DESC(sd)) {
				/*
				 * If a MN diskset always set multi_node
				 * regardless of whether the -M option was
				 * used or not (mflag).
				 */
				multi_node = 1;
			} else {
				/*
				 * If a traditional diskset, mflag must
				 * not be set.
				 */
				if (mflag) {
					usage(sp, gettext(
					    "-M option only allowed "
					    "on multi-owner diskset"));
				}
			}
		} else {
			/*
			 * Set name does not exist, set multi_node
			 * based on -M option.
			 */
			if (mflag) {
				multi_node = 1;
			}
		}
	}

	if (auto_take && multi_node) {
		/* Can't mix multinode and auto-take on a diskset */
		usage(sp,
		    gettext("-A option not allowed on multi-owner diskset"));
	}

	/*
	 * MN disksets don't use DCS clustering services, so
	 * do not get primary_node for MN diskset since no command
	 * proxying is done to Primary cluster node.  Do not proxy
	 * MN diskset commands of join and withdraw when issued without
	 * a valid setname.
	 * For traditional disksets: proxy all commands except a take
	 * and release.  Use first host listed as the host to send the
	 * command to if there isn't already a primary
	 */
	if (strcmp(sname, MD_LOCAL_NAME) && (multi_node == 0) &&
	    (cmd != take) && (cmd != release) &&
	    (cmd != cluster) && (cmd != join) &&
	    (cmd != withdraw) && (cmd != purge)) {
		stat = sdssc_get_primary_host(sname, primary_node,
		    SDSSC_NODE_NAME_LEN);
		switch (stat) {
			case SDSSC_ERROR:
				return (0);

			case SDSSC_NO_SERVICE:
				if (hostname != SDSSC_PROXY_PRIMARY) {
					(void) strlcpy(primary_node, hostname,
					    SDSSC_NODE_NAME_LEN);
				} else {
					(void) memset(primary_node, '\0',
					    SDSSC_NODE_NAME_LEN);
				}
				break;
		}

		/*
		 * We've got a complicated decision here regarding
		 * the hostname. If we didn't get a primary host
		 * and a host name wasn't supplied on the command line
		 * then we need to revert to SDSSC_PROXY_PRIMARY. Otherwise
		 * use what's been found.
		 */
		if (sdssc_cmd_proxy(argc, argv,
		    primary_node[0] == '\0' ?
		    SDSSC_PROXY_PRIMARY : primary_node,
		    &error) == SDSSC_PROXY_DONE) {
			exit(error);
		}
	}

	/* cluster-specific commands */
	if (cmd == cluster) {
		parse_cluster(argc, argv, multi_node);
		/*NOTREACHED*/
	}

	/* join MultiNode diskset */
	if (cmd == join) {
		/*
		 * If diskset specified, verify that it exists
		 * and is a multinode diskset.
		 */
		if (strcmp(sname, MD_LOCAL_NAME)) {
			if ((sp = metasetname(sname, ep)) == NULL) {
				mde_perror(ep, "");
				md_exit(sp, 1);
			}

			if (!multi_node) {
				usage(sp, gettext(
				    "-j option only allowed on "
				    "multi-owner diskset"));
			}
		}
		/*
		 * Start mddoors daemon here.
		 * mddoors itself takes care there will be only one
		 * instance running, so starting it twice won't hurt
		 */
		(void) pclose(popen("/usr/lib/lvm/mddoors", "w"));
		parse_joinset(argc, argv);
		/*NOTREACHED*/
	}

	/* withdraw from MultiNode diskset */
	if (cmd == withdraw) {
		/*
		 * If diskset specified, verify that it exists
		 * and is a multinode diskset.
		 */
		if (strcmp(sname, MD_LOCAL_NAME)) {
			if ((sp = metasetname(sname, ep)) == NULL) {
				mde_perror(ep, "");
				md_exit(sp, 1);
			}

			if (!multi_node) {
				usage(sp, gettext(
				    "-w option only allowed on "
				    "multi-owner diskset"));
			}
		}
		parse_withdrawset(argc, argv);
		/*NOTREACHED*/
	}

	/* must have set for everything else */
	if (strcmp(sname, MD_LOCAL_NAME) == 0)
		usage(sp, gettext("setname must be specified"));

	/* add hosts or drives */
	if (cmd == add) {
		/*
		 * In the multi node case start mddoors daemon.
		 * mddoors itself takes care there will be
		 * only one instance running, so starting it twice won't hurt
		 */
		if (multi_node) {
			(void) pclose(popen("/usr/lib/lvm/mddoors", "w"));
		}

		parse_add(argc, argv);
		/*NOTREACHED*/
	}

	/* re-balance the replicas */
	if (cmd == balance) {
		parse_balance(argc, argv);
		/*NOTREACHED*/
	}

	/* delete hosts or drives */
	if (cmd == delete) {
		parse_del(argc, argv);
		/*NOTREACHED*/
	}

	/* check ownership */
	if (cmd == isowner) {
		parse_isowner(argc, argv);
		/*NOTREACHED*/
	}

	/* purge the diskset */
	if (cmd == purge) {
		parse_purge(argc, argv);
		/*NOTREACHED*/
	}

	/* query for data marks */
	if (cmd == query) {
		parse_query(argc, argv);
		/*NOTREACHED*/
	}

	/* release ownership */
	if (cmd == release) {
		if (multi_node) {
			/* Can't release multinode diskset */
			usage(sp, gettext(
			    "-r option not allowed on multi-owner diskset"));
		} else {
			parse_releaseset(argc, argv);
			/*NOTREACHED*/
		}
	}

	/* take ownership */
	if (cmd == take) {
		if (multi_node) {
			/* Can't take multinode diskset */
			usage(sp, gettext(
			    "-t option not allowed on multi-owner diskset"));
		} else {
			parse_takeset(argc, argv);
			/*NOTREACHED*/
		}
	}

	/* take ownership of auto-take sets */
	if (auto_take) {
		parse_autotake(argc, argv);
		/*NOTREACHED*/
	}

	/*NOTREACHED*/
	return (0);
}
