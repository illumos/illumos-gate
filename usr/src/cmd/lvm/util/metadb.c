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
 * Metadevice database utility.
 */

#include <meta.h>
#define	MDDB
#include <sys/lvm/md_mddb.h>
#include <sdssc.h>

enum mddb_cmd {none, attach, detach, patch, infolong, infoshort};

extern int	procsigs(int block, sigset_t *oldsigs, md_error_t *ep);

static void
usage(
	mdsetname_t	*sp,
	char		*string
)
{
	if ((string != NULL) && (*string != '\0'))
		md_eprintf("%s\n", string);

	(void) fprintf(stderr, gettext(
"usage:  %s [-s setname] -a [options] mddbnnn\n"
"	%s [-s setname] -a [options] device ...\n"
"	%s [-s setname] -d [options] mddbnnn\n"
"	%s [-s setname] -d [options] device ...\n"
"	%s [-s setname] -i \n"
"	%s -p [options] [ mddb.cf-file ]\n"
"options:\n"
"-c count	number of replicas (for use with -a only)\n"
"-f		force adding or deleting of replicas\n"
"-k filename	alternate /etc/system file\n"
"-l length	specify size of replica (for use with -a only)\n"),
	    myname, myname, myname, myname, myname, myname);

	md_exit(sp, (string == NULL) ? 0 : 1);
}

static mdname_t *
make_dbname(
	mdsetname_t	*sp,
	mdnamelist_t	**nlp,
	char		*name,
	md_error_t	*ep
)
{
	mdname_t	*np;

	if ((np = metaname(&sp, name, LOGICAL_DEVICE, ep)) == NULL)
		return (NULL);

	return (metanamelist_append(nlp, np));
}

static mdnamelist_t *
get_dbnames_fromfile(
	mdsetname_t	*sp,
	mdnamelist_t	**nlp,
	char		*tabname,
	int		*dbsize,
	int		*dbcnt,
	int		*default_size,
	md_error_t	*ep
)
{
	md_tab_t	*tabp = NULL;
	md_tab_line_t	*linep = NULL;
	int		argc;
	char		**argv;
	char		*context;
	int		save = optind;
	int		c;

	/* look in md.tab */
	if ((tabp = meta_tab_parse(NULL, ep)) == NULL) {
		if (! mdissyserror(ep, ENOENT))
			mde_perror(ep, "");
		mdclrerror(ep);
		return (NULL);
	}

	if ((linep = meta_tab_find(sp, tabp, tabname, TAB_MDDB)) == NULL) {
		(void) mdsyserror(ep, ENOENT, tabname);
		goto out;
	}
	argc = linep->argc;
	argv = linep->argv;
	context = linep->context;

	/* parse up entry */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "c:l:")) != -1) {
		switch (c) {
		case 'c':
			if (sscanf(optarg, "%d", dbcnt) != 1) {
				md_eprintf("%s: %s\n",
				    context, gettext("bad format"));
				usage(sp, "");
			}
			break;

		case 'l':
			if (sscanf(optarg, "%d", dbsize) != 1) {
				md_eprintf("%s: %s\n",
				    context, gettext("bad format"));
				usage(sp, "");
			}
			*default_size = FALSE;
			break;

		default:
			usage(sp, "");
		}
	}
	argc -= optind;
	argv += optind;
	for (; (argc > 0); --argc, ++argv) {
		char	*token = argv[0];

		if (make_dbname(sp, nlp, token, ep) == NULL) {
			metafreenamelist(*nlp);
			*nlp = NULL;
			goto out;
		}
	}

	/* cleanup, return list */
out:
	if (tabp != NULL)
		meta_tab_free(tabp);
	optind = save;
	return (*nlp);
}

/*
 * built list of all devices which are to be detached
 */
static mdnamelist_t *
build_a_namelist(
	mdsetname_t	*sp,
	int		argc,
	char		**argv,
	md_error_t	*ep
)
{
	int		i;
	int		dbsize, dbcnt, default_size;
	mdnamelist_t	*dbnlp = NULL;

	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "mddb", 4) == 0) {
			if (get_dbnames_fromfile(sp, &dbnlp, argv[i],
			    &dbsize, &dbcnt, &default_size, ep) == NULL) {
				/* don't freelist here - already been done */
				return (NULL);
			}
			continue;
		}
		if (make_dbname(sp, &dbnlp, argv[i], ep) == NULL) {
			metafreenamelist(dbnlp);
			return (NULL);
		}
	}

	return (dbnlp);
}


/*
 * built the next list of devices which are to be attached
 * that have the same size and count of replicas.
 */
static mdnamelist_t *
build_next_namelist(
	mdsetname_t	*sp,
	int		argc,
	char		**argv,
	int		*arg_index,
	int		*dbsize,
	int		*dbcnt,
	int		*default_size,
	md_error_t	*ep
)
{
	int		i;
	mdnamelist_t	*dbnlp = NULL;

	for (i = *arg_index; i < argc; i++) {
		if (strncmp(argv[i], "mddb", 4) == 0) {
			/*
			 * If we have stuff in the namelist
			 * return it before processing the mddb entry.
			 */
			if (dbnlp) {
				*arg_index = i;
				return (dbnlp);
			}
			if (get_dbnames_fromfile(sp, &dbnlp, argv[i],
			    dbsize, dbcnt, default_size, ep) == NULL) {
				/* don't freelist here - already been done */
				return (NULL);
			}
			*arg_index = i + 1;
			return (dbnlp);
		}
		if (make_dbname(sp, &dbnlp, argv[i], ep) == NULL) {
			metafreenamelist(dbnlp);
			return (NULL);
		}
	}
	*arg_index = argc;
	return (dbnlp);
}


static int
chngdb(
	mdsetname_t	*sp,
	enum mddb_cmd	cmd,
	int		argc,
	char		*argv[],
	uint_t		options,
	md_error_t	*ep
)
{
	int		c;
	int		i;
	md_error_t	xep = mdnullerror;
	mdnamelist_t	*dbnlp = NULL;
	int		dbsize = MD_DBSIZE;
	int		maxblks = MDDB_MAXBLKS;
	int		minblks = MDDB_MINBLKS;
	int		dbcnt = 1;
	mdforceopts_t	force = MDFORCE_NONE;
	int		rval = 0;
	char		*sysfilename = NULL;
	int		default_size = TRUE;
	md_set_desc	*sd;
	md_setkey_t	*cl_sk;
	md_mnnode_desc	*nd;
	int		suspend1_flag = 0;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "ac:dfk:pl:s:")) != -1) {
		switch (c) {
		case 'a':
			break;
		case 'c':
			if (sscanf(optarg, "%d", &dbcnt) != 1) {
				md_eprintf("%s: %s\n",
				    optarg, gettext("bad format"));
				usage(sp, "");
			}
			break;
		case 'd':
			break;
		case 'f':
			force = MDFORCE_LOCAL;
			break;
		case 'k':
			sysfilename = optarg;
			break;
		case 'l':
			if (sscanf(optarg, "%d", &dbsize) != 1) {
				md_eprintf("%s: %s\n",
				    optarg, gettext("bad format"));
				usage(sp, "");
			}
			default_size = FALSE;
			break;
		case 'p':
			break;
		case 's':
			break;
		default:
			usage(sp, "");
		}
	}

	/*
	 * If it is a multinode diskset, use appropriate metadb size.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);

		if (MD_MNSET_DESC(sd)) {
			maxblks = MDDB_MN_MAXBLKS;
			minblks = MDDB_MN_MINBLKS;
			if (default_size)
				dbsize = MD_MN_DBSIZE;
		}
	}

	if (dbsize > maxblks)
		usage(sp, gettext("size (-l) is too big"));


	if (dbsize < minblks)
		usage(sp, gettext("size (-l) is too small"));

	if (dbcnt < 1)
		usage(sp, gettext(
		    "count (-c) must be 1 or more"));


	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		usage(sp, gettext(
		    "no devices specified to attach or detach"));
	}

	if (! metaislocalset(sp)) {

		if (MD_MNSET_DESC(sd)) {
			md_error_t xep = mdnullerror;
			sigset_t sigs;

			/* Make sure we are blocking all signals */
			if (procsigs(TRUE, &sigs, &xep) < 0)
				mdclrerror(&xep);

			/*
			 * Lock out other metaset or metadb commands
			 * across the diskset.
			 */
			nd = sd->sd_nodelist;
			while (nd) {
				if ((force & MDFORCE_LOCAL) &&
				    strcmp(nd->nd_nodename, mynode()) != 0) {
					nd = nd->nd_next;
					continue;
				}

				if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
					nd = nd->nd_next;
					continue;
				}

				if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
					rval = -1;
					goto done;
				}
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
					goto done;
				}
				suspend1_flag = 1;
				nd = nd->nd_next;
			}
		} else {
			/* Lock the set on current set members */
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if ((force & MDFORCE_LOCAL) &&
				    strcmp(sd->sd_nodes[i], mynode()) != 0)
					continue;

				if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
					rval = -1;
					goto done;
				}
			}
		}

		force |= MDFORCE_SET_LOCKED;
		options |= MDCHK_SET_LOCKED;
	}

	if (cmd == detach) {
		if ((dbnlp = build_a_namelist(sp, argc, argv, ep)) == NULL) {
			rval = -1;
			goto done;
		}

		rval = meta_db_detach(sp, dbnlp, force, sysfilename, ep);

		metafreenamelist(dbnlp);
	}

	if (cmd == attach) {
		daddr_t	nblks = 0;
		int	arg_index = 0;
		int	saved_dbsize = dbsize;
		int	saved_dbcnt = dbcnt;
		int	saved_default_size = default_size;

		if (force & MDFORCE_LOCAL)
			options |= MDCHK_SET_FORCE;

		if (default_size)
			if ((nblks = meta_db_minreplica(sp, ep)) < 0)
				mdclrerror(ep);
		/*
		 * Loop through build a new namelist
		 * for each "mddb" entry or the devices list
		 * on the command line.  This allows each "mddb"
		 * entry to have unique dbsize and dbcnt.
		 */
		while (arg_index < argc) {

			dbnlp = build_next_namelist(sp, argc, argv,
			    &arg_index, &dbsize, &dbcnt, &default_size, ep);
			if (dbnlp == NULL) {
				rval = -1;
				goto done;
			}
			/*
			 * If using the default size,
			 *   then let's adjust the default to the minimum
			 *   size currently in use.
			 */
			if (default_size && (nblks > 0))
				dbsize = nblks;	/* adjust replica size */

			if (dbsize > maxblks)
				usage(sp, gettext("size (-l) is too big"));

			rval = meta_db_attach(sp, dbnlp, options, NULL, dbcnt,
			    dbsize, sysfilename, ep);
			if (rval) {
				metafreenamelist(dbnlp);
				break;
			}
			dbsize = saved_dbsize;
			dbcnt = saved_dbcnt;
			default_size = saved_default_size;

			metafreenamelist(dbnlp);
		}
	}

done:
	if (! metaislocalset(sp)) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		if (MD_MNSET_DESC(sd)) {
			/*
			 * Unlock diskset by resuming
			 * class 1 messages across the diskset.
			 */
			if (suspend1_flag) {
				nd = sd->sd_nodelist;
				while (nd) {
					if (!(nd->nd_flags &
					    MD_MN_NODE_ALIVE)) {
						nd = nd->nd_next;
						continue;
					}

					if (clnt_mdcommdctl(nd->nd_nodename,
					    COMMDCTL_RESUME, sp,
					    MD_MSG_CLASS1,
					    MD_MSCF_NO_FLAGS, &xep)) {
						mde_perror(&xep, "");
						mdclrerror(&xep);
					}
					nd = nd->nd_next;
				}
			}
			nd = sd->sd_nodelist;
			while (nd) {
				if ((force & MDFORCE_LOCAL) &&
				    strcmp(nd->nd_nodename, mynode()) != 0) {
					nd = nd->nd_next;
					continue;
				}
				if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
					nd = nd->nd_next;
					continue;
				}

				if (clnt_unlock_set(nd->nd_nodename, cl_sk,
				    &xep))
					mdclrerror(&xep);
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if ((force & MDFORCE_LOCAL) &&
				    strcmp(sd->sd_nodes[i], mynode()) != 0)
					continue;

				if (clnt_unlock_set(sd->sd_nodes[i], cl_sk,
				    &xep))
					mdclrerror(&xep);
			}
		}
		cl_set_setkey(NULL);
	}

	return (rval);
}

static int
info(
	mdsetname_t	*sp,
	enum mddb_cmd	cmd,
	int		print_headers,
	int		print_footers,
	md_error_t	*ep
)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	md_replica_t		*r;
	int			i;
	char			*unk_str = NULL;

	/* get list of replicas, quit if none */
	if (metareplicalist(sp, (MD_BASICNAME_OK | PRINT_FAST), &rlp, ep) < 0)
		return (-1);
	else if (rlp == NULL)
		return (0);

	if (print_headers) {
		(void) printf("\t%5.5s\t\t%9.9s\t%11.11s\n", gettext("flags"),
		    gettext("first blk"), gettext("block count"));
	}

	unk_str = gettext("unknown");
	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		r = rl->rl_repp;

		for (i = 0; i < MDDB_FLAGS_LEN; i++) {
			if (r->r_flags & (1 << i))
				(void) putchar(MDDB_FLAGS_STRING[i]);
			else
				(void) putchar(' ');
		}

		if ((r->r_blkno == -1) && (r->r_nblk == -1)) {
			(void) printf("\t%7.7s\t\t%7.7s\t", unk_str, unk_str);
		} else if (r->r_nblk == -1) {
			(void) printf("\t%ld\t\t%7.7s\t", r->r_blkno, unk_str);
		} else {
			(void) printf("\t%ld\t\t%ld\t", r->r_blkno, r->r_nblk);
		}

		(void) printf("\t%s\n", r->r_namep->bname);

	}

	metafreereplicalist(rlp);

	if (cmd == infoshort)
		return (0);

	if (!print_footers)
		return (0);

	(void) printf(gettext(
	    " r - replica does not have device relocation information\n"
	    " o - replica active prior to last mddb configuration change\n"
	    " u - replica is up to date\n"
	    " l - locator for this replica was read successfully\n"
	    " c - replica's location was in %s\n"
	    " p - replica's location was patched in kernel\n"
	    " m - replica is master, this is replica selected as input\n"
	    " t - tagged data is associated with the replica\n"
	    " W - replica has device write errors\n"
	    " a - replica is active, commits are occurring to this replica\n"
	    " M - replica had problem with master blocks\n"
	    " D - replica had problem with data blocks\n"
	    " F - replica had format problems\n"
	    " S - replica is too small to hold current data base\n"
	    " R - replica had device read errors\n"
	    " B - tagged data associated with the replica is not valid\n"),
	    META_DBCONF);
	return (0);
}

int
main(int argc, char **argv)
{
	mdsetname_t	*sp = NULL;
	int		c;
	enum mddb_cmd	cmd = none;
	char		*sname = MD_LOCAL_NAME;
	char		*cffilename = NULL;
	char		*sysfilename = NULL;
	int		forceflg = FALSE;
	mdchkopts_t	options = 0;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		error;
	md_set_desc	*sd;
	int		multi_node = 0;

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

	if (sdssc_bind_library() == SDSSC_OKAY)
		if (sdssc_cmd_proxy(argc, argv, SDSSC_PROXY_PRIMARY,
		    &error) == SDSSC_PROXY_DONE)
			exit(error);

	/* parse args */
	optind = 1;
	opterr = 1;

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "ac:dfhik:l:ps:?")) != -1) {
		switch (c) {
		case 'a':
			cmd = attach;
			break;
		case 'c':
			break;
		case 'd':
			cmd = detach;
			break;
		case 'f':
			forceflg = TRUE;
			break;
		case 'h':
			usage(sp, (char *)0);
			break;
		case 'i':
			cmd = infolong;
			break;
		case 'k':
			sysfilename = optarg;
			break;
		case 'l':
			break;
		case 'p':
			cmd = patch;
			break;
		case 's':
			sname = optarg;
			break;

		case '?':
			if (optopt == '?')
				usage(sp, NULL);
			/*FALLTHROUGH*/
		default:
			usage(sp, gettext("unknown command"));
		}
	}
	if (cmd == none)
		cmd = infoshort;

	/* get set context */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* print status */
	if (cmd == infoshort || cmd == infolong) {
		if (optind != argc)
			usage(sp, gettext(
				"too many arguments"));

		if (info(sp, cmd, 1, 1, ep)) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		if (meta_smf_isonline(meta_smf_getmask(), ep) == 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		md_exit(sp, 0);
	}

	if (meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		if (MD_MNSET_DESC(sd)) {
			multi_node = 1;
		}
	}

	/*
	 * Adjust lock for traditional and local diskset.
	 *
	 * A MN diskset does not use the set meta_lock but instead
	 * uses the clnt_lock of rpc.metad and the suspend/resume
	 * feature of the rpc.mdcommd.  Can't use set meta_lock since
	 * class 1 messages are grabbing this lock and if this thread
	 * is holding the set meta_lock then no rpc.mdcommd suspend
	 * can occur.
	 */
	if ((!multi_node) && (meta_lock(sp, TRUE, ep) != 0)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* check for ownership */
	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* snarf MDDB locations */
	if (cmd != patch) {
		if (meta_setup_db_locations(ep) != 0) {
			if (! mdismddberror(ep, MDE_DB_STALE)) {
				if (forceflg == FALSE) {
					mde_perror(ep, "");
					md_exit(sp, 1);
				}
				options = MDCHK_ALLOW_NODBS;
			}
			mdclrerror(ep);
		}
	}

	/* patch MDDB locations */
	if (cmd == patch) {
		if (optind < (argc - 1)) {
			usage(sp, gettext(
			    "too many arguments to -p"));
		}

		if (optind == (argc - 1))
			cffilename = argv[optind];

		if (metaislocalset(sp)) {
			if (meta_db_patch(sysfilename, cffilename, 1, ep)) {
				mde_perror(ep, "");
				md_exit(sp, 1);
			}
		}
	}

	/* add/delete replicas */
	if (cmd == attach || cmd == detach) {
		if (chngdb(sp, cmd, argc, argv, options, ep)) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
