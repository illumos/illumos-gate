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
 * initialize metadevices
 */

#include <meta.h>

#include <sdssc.h>
#include <sys/lvm/md_mirror.h>
#include <syslog.h>
#include "meta_set_prv.h"

/*
 * try to initialize devices
 */
#define	DO_AGAIN	0
#define	DONT_DO		1
#define	IS_DONE		2

/*
 * mn_send_command
 *
 * generate a command of the form "metainit -s setname [-n] [-f] ....."
 *
 * If -n option is *not* set, send the metainit command *with -n set* to
 * all nodes first. Do this with MD_MSGF_STOP_ON_ERROR set.
 * That means if it fails on one node, it'll return immediately,
 * reporting the error.
 * By doing so, we have a dryrun first that has to succeed on every node
 * before we start the command for real.
 * This saves us from backing out a metainit command that succeeded on
 * some nodes but failed on one.
 */
static int
mn_send_command(
	mdsetname_t	**spp,
	int		argc,
	char		**argv,
	mdcmdopts_t	options,
	int		flags,
	char		*context,
	md_error_t	*ep
)
{
	int		newargc;
	char		**newargv;
	int		i;
	int		ret;
	int		dryrun_only = 0;


	newargv = calloc(argc+5, sizeof (char *));
	newargv[0] = "metainit";
	newargv[1] = "-s";
	newargv[2] = (*spp)->setname;
	newargv[3] = "-n"; /* always do "-n" first */
	newargc = 4;
	if ((options & MDCMD_DOIT) == 0) {
		dryrun_only = 1;
	}
	if ((options & MDCMD_FORCE) != 0) {
		newargv[newargc] = "-f";
		newargc++;
	}
	for (i = 0; i < argc; i++, newargc++)
		newargv[newargc] = argv[i];
	ret = meta_mn_send_command(*spp, newargc, newargv,
	    flags | MD_DRYRUN | MD_NOLOG, context, ep);

	if ((dryrun_only == 0) && (ret == 0)) {
		/*
		 * Do it for real now. Remove "-n" from the arguments and
		 * MD_DRYRUN from the flags. If we fail this time the master
		 * must panic as the mddbs may be inconsistent.
		 */
		newargv[3] = ""; /* this was "-n" before */
		ret = meta_mn_send_command(*spp, newargc, newargv,
		    flags | MD_RETRY_BUSY | MD_PANIC_WHEN_INCONSISTENT,
		    context,  ep);
	}

	free(newargv);
	return (ret);
}

static int
init_entries(
	mdsetname_t	**spp,
	md_tab_t	*tabp,
	mdcmdopts_t	options,
	uint_t		flags,
	bool_t		called_thru_rpc,
	md_error_t	*ep
)
{
	uint_t		cnt = 0;
	uint_t		line;
	int		rval = 0;
	int		ret;

	/* for all matching entries, which haven't already been done */
	for (line = 0; (line < tabp->nlines); ++line) {
		md_tab_line_t	*linep = &tabp->lines[line];
		char		*uname = linep->argv[0];

		/* see if already done */
		if (linep->flags != DO_AGAIN)
			continue;

		/* clear the metadev/hsp caches between inits */
		metaflushmetanames();

		/* try it */
		if ((called_thru_rpc == FALSE) &&
		    meta_is_mn_name(spp, uname, ep)) {
			/*
			 * MN set, send command to all nodes
			 * Note that is sp is NULL, meta_is_mn_name() derives
			 * sp from linep->argv which is the metadevice arg
			 */
			ret = mn_send_command(spp, linep->argc, linep->argv,
			    options, flags, linep->context, ep);
		} else {
			char		*cname = NULL;

			cname = meta_name_getname(spp, uname, META_DEVICE, ep);
			if (cname == NULL) {
				mde_perror(ep, "");
				mdclrerror(ep);
			} else {

				ret = meta_init_name(spp, linep->argc,
				    linep->argv, cname, options, ep);
				Free(cname);

				if (ret != 0) {
					if (!(flags & MD_IGNORE_STDERR)) {
					    mderrorextra(ep, linep->context);
					    mde_perror(ep, "");
					    rval = -1;
					}
					mdclrerror(ep);
				}
			}
		}
		if (ret == 0) {
			linep->flags = IS_DONE;
			++cnt;
		}
	}

	/* return success */
	if (rval != 0)
		return (rval);
	return (cnt);
}

/*
 * initialize all devices in set
 */
static int
init_all(
	mdsetname_t	**spp,
	mdcmdopts_t	options,
	bool_t		called_thru_rpc,
	md_error_t	*ep
)
{
	md_tab_t	*tabp = NULL;
	size_t		setlen;
	uint_t		more;
	int		done;
	int		eval = -1;

	/*
	 * Only take the lock if this is not a MN set
	 * We can only enter this code for a MN set if we are the initiator
	 * and in this case, we don't want to take locks.
	 */
	if (meta_is_mn_set((*spp), ep) == 0) {
		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep)) {
			mde_perror(ep, "");
			mdclrerror(ep);
			return (eval);
		}

		/* check for ownership */
		if (meta_check_ownership(*spp, ep) != 0) {
			mde_perror(ep, "");
			mdclrerror(ep);
			return (eval);
		}

		/* lock is held across init_entries */
		options |= MDCMD_NOLOCK;
	}

	/* get md.tab, preen entries */
	if ((tabp = meta_tab_parse(NULL, ep)) == NULL) {
		mde_perror(ep, "");
		mdclrerror(ep);
		return (eval);
	}

	setlen = strlen((*spp)->setname);
	for (more = 0; (more < tabp->nlines); ++more) {
		md_tab_line_t	*linep = &tabp->lines[more];
		char		*cname = linep->cname;
		char		*p;
		size_t		len;

		/* better have args */
		assert((linep->argc > 0) && (linep->argv[0] != NULL));

		/* only do metadevices and hotspare pools in set */
		if (linep->type & TAB_MD_HSP) {
			if ((p = strrchr(cname, '/')) == NULL) {
				len = 0;
			} else {
				len = p - cname;
			}
			if ((len == setlen) &&
			    (strncmp(cname, (*spp)->setname, len) == 0)) {
				linep->flags = DO_AGAIN;
			} else {
				linep->flags = DONT_DO;
			}

		} else {
			linep->flags = DONT_DO;
		}
	}

	eval = 1;

	/* while more devices get made */
	do {
		done = init_entries(spp, tabp, options,
		    MD_IGNORE_STDERR|MD_RETRY_BUSY, called_thru_rpc, ep);
	} while (done > 0);

	/* now do it and report errors */
	if (init_entries(spp, tabp, options, MD_RETRY_BUSY,
	    called_thru_rpc, ep) >= 0)
		eval = 0;	/* success */
	mdclrerror(ep);

	/* cleanup, return success */
out:
	meta_tab_free(tabp);
	return (eval);
}

/*
 * initialize named device or hotspare pool
 */
static int
init_name(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	int		called_thru_rpc,
	md_error_t	*ep
)
{
	md_tab_t	*tabp = NULL;
	md_tab_line_t	*linep = NULL;
	int		rval = -1;
	int		ret;
	char		*uname = argv[0];

	/* look in md.tab */
	if (argc == 1) {
		/* get md.tab entries */
		if ((tabp = meta_tab_parse(NULL, ep)) == NULL) {
			if (! mdissyserror(ep, ENOENT))
				return (-1);
		}

		/* look in md.tab */
		if ((linep = meta_tab_find(*spp, tabp, uname, TAB_MD_HSP))
								!= NULL) {
			argc = linep->argc;
			argv = linep->argv;
		}
	}

	if ((called_thru_rpc == FALSE) &&
	    meta_is_mn_name(spp, uname, ep)) {
		/*
		 * MN set, send command to all nodes
		 */
		ret = mn_send_command(spp, argc, argv, options,
		    MD_DISP_STDERR, NO_CONTEXT_STRING, ep);
	} else {
		char		*cname = NULL;

		cname = meta_name_getname(spp, uname, META_DEVICE, ep);
		if (cname == NULL) {
			goto out;
		}

		/* check for ownership */
		if (meta_check_ownership(*spp, ep) != 0) {
			Free(cname);
			goto out;
		}

		ret = meta_init_name(spp, argc, argv, cname, options, ep);
		Free(cname);
	}

	if (ret != 0) {
		if (linep != NULL)
			mderrorextra(ep, linep->context);
		goto out;
	}
	rval = 0;	/* success */

	/* cleanup, return error */
out:
	if (tabp != NULL)
		meta_tab_free(tabp);
	return (rval);
}

/*
 * print usage message
 */
static void
usage(
	mdsetname_t	*sp,
	int		eval
)
{
#ifndef	lint
	(void) fprintf(stderr, gettext("\
usage:	%s [-s setname] [-n] [-f] concat/stripe numstripes\n\
		width component... [-i interlace]\n\
		[width component... [-i interlace]] [-h hotspare_pool]\n\
	%s [-s setname] [-n] [-f] mirror -m submirror...\n\
		[read_options] [write_options] [pass_num]\n\
	%s [-s setname] [-n] [-f] RAID -r component...\n\
		[-i interlace] [-h hotspare_pool]\n\
		[-k] [-o original_column_count]\n\
	%s [-s setname] [-n] [-f] hotspare_pool [hotspare...]\n\
	%s [-s setname] [-n] [-f] softpart -p [-A alignment]\n\
		[-e] device size|all\n\
	%s [-s setname] [-n] [-f] md.tab_entry\n\
	%s [-s setname] [-n] [-f] -a\n\
	%s -r\n"), myname, myname, myname, myname, myname, myname, myname,
	    myname);
#endif	/* ! lint */
	md_exit(sp, eval);
}

/*
 * If we fail during the attempt to take the auto-take disksets
 * we need to tell the kernel to cleanup the in-core set struct
 * so that we have a chance to take the set again later.
 */
static void
auto_take_cleanup(mdsetname_t *sp, side_t sideno)
{
	mddb_config_t   c;

	(void) memset(&c, 0, sizeof (c));
	c.c_setno = sp->setno;
	c.c_sideno = sideno;

	if (metaioctl(MD_RELEASE_SET, &c, &c.c_mde, NULL) != 0) {
		mde_perror(&c.c_mde, "auto_take_cleanup");
		return;
	}
}

/*
 * Take the diskset.
 *
 * This is a clean auto-take set, so do the work to take it.
 * This is a streamlined version of the code in meta_set_take.  We avoid the
 * need for talking to the rpc.metad since that can't run this early during the
 * boot.  We don't need to talk to the metad for this diskset since we're the
 * only host in the set.
 */
static void
take_set(md_set_record *sr)
{
	mdsetname_t		sn;
	md_drive_desc		*dd;
	md_error_t		error = mdnullerror;
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	daddr_t			nblks = 0;
	md_drive_record		*dr;
	side_t			sideno;

	/*
	 * Several of the functions we call take a sp param so
	 * construct one from the set record.
	 */
	sn.setname = sr->sr_setname;
	sn.setno = sr->sr_setno;
	sn.setdesc = sr2setdesc(sr);
	sn.lockfd = MD_NO_LOCK;

	if (sr->sr_flags & MD_SR_MB_DEVID)
		dd = metaget_drivedesc(&sn, MD_BASICNAME_OK | PRINT_FAST,
		    &error);
	else
		dd = metaget_drivedesc(&sn, MD_BASICNAME_OK, &error);

	if (dd == NULL) {
	    mde_perror(&error, "");
	    mdclrerror(&error);
	    return;
	}

	/*
	 * Skip call to tk_own_bydd.  This talks to rpc.metamhd (which we can't
	 * do yet) and is not needed for auto-take disksets since we are not
	 * doing SCSI reservations on these drives.
	 */

	if (setup_db_bydd(&sn, dd, 0, &error) != 0) {
	    if (! mdismddberror(&error, MDE_DB_ACCOK) &&
		! mdismddberror(&error, MDE_DB_TAGDATA)) {
		/*
		 * Skip call to rel_own_bydd since that really just
		 * calls rpc.metamhd which we don't need to do,
		 * so there really isn't anything to rollback here.
		 */
		mde_perror(&error, "");
		mdclrerror(&error);
		return;
	    }
	    mdclrerror(&error);
	}

	if ((sideno = getmyside(&sn, &error)) == MD_SIDEWILD) {
	    mde_perror(&error, "");
	    return;
	}

	if (snarf_set(&sn, FALSE, &error) != 0) {
	    if (mdismddberror(&error, MDE_DB_STALE) ||
		mdismddberror(&error, MDE_DB_TAGDATA) ||
		! mdismddberror(&error, MDE_DB_NODB) &&
		! mdismddberror(&error, MDE_DB_NOTOWNER)) {
		/*
		 * rollback
		 * Normally MDE_DB_STALE or MDE_DB_TAGDATA
		 * would still keep the set but in this case we don't
		 * want to do that.  This will probably result in the
		 * boot going in to single-user since we won't have the
		 * set so any attempted mounts using the set's metadevices
		 * will fail.  However, that is a "good thing" so the
		 * sysadmin can fix the set.  Normally they would see
		 * all of these problems when they ran the take and be
		 * able to immediately fix the problem.
		 */
		mde_perror(&error, "");
		auto_take_cleanup(&sn, sideno);
		return;
	    }
	}

	/*
	 * Call metareplicalist and upd_dr_dbinfo.
	 * Most of that code is only needed to synchronize amongst the multiple
	 * hosts in a set, which is not applicable in our case.  But we do a
	 * subset here to handle the case when the user had been
	 * adding/deleting/balancing mddbs when this node panic'd.  We are
	 * synchronizing the ondisk mddbs to the list of drive records stored
	 * in the local mddb.
	 */
	if (metareplicalist(&sn, (MD_BASICNAME_OK | PRINT_FAST), &rlp, &error)
	    < 0) {
	    /* rollback */
	    mde_perror(&error, "");
	    auto_take_cleanup(&sn, sideno);
	    return;
	}

	/*
	 * The following code is equivalent to upd_dr_dbinfo for syncronizing
	 * the local host only.  That function is normally run through the
	 * metad with a local and daemon side but we'll do all of the work
	 * here.
	 */

	/* find the smallest existing replica */
	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
	    md_replica_t *r;

	    r = rl->rl_repp;
	    nblks = ((nblks == 0) ? r->r_nblk : min(r->r_nblk, nblks));
	}

	if (nblks <= 0)
	    nblks = MD_DBSIZE;

	for (dr = sr->sr_drivechain; dr; dr = dr->dr_next) {
	    int			dbcnt;
	    mddrivename_t	*dnp;
	    md_replicalist_t	*rl;

		/*
		 * The cname style for dnp and replica list will be same since
		 * both use the the same flags MD_BASICNAME_OK|PRINT_FAST which
		 * will always provide the cached value.
		 */
	    if ((dnp = metadrivename_withdrkey(&sn, sideno, dr->dr_key,
		MD_BASICNAME_OK | PRINT_FAST, &error)) == NULL) {
		mde_perror(&error, "");
		metafreereplicalist(rlp);
		auto_take_cleanup(&sn, sideno);
		return;
	    }

	    dbcnt = 0;
	    /* see how many replicas are on this drive */
	    for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		if (strcmp(rl->rl_repp->r_namep->drivenamep->cname, dnp->cname)
		    == 0)
		    dbcnt++;
	    }

	    /* Adjust the fields in the copy */
	    dr->dr_dbcnt = dbcnt;
	    dr->dr_dbsize = dbcnt > 0 ? nblks : 0;
	}

	/*
	 * If the set doesn't have the MD_SR_MB_DEVID bit set, i.e
	 * the drives in the set don't have the device id information,
	 * then stick it in if possible.
	 *
	 * If updating the master block fails for whatever reason, it's
	 * okay. It just means the disk(s) in the diskset won't be self
	 * identifying.
	 */
	if (!(sr->sr_flags & MD_SR_MB_DEVID)) {
		if (meta_update_mb(&sn, dd, &error) == 0) {
			sr->sr_flags |= MD_SR_MB_DEVID;
			mdclrerror(&error);
		}
	}

	commitset(sr, FALSE, &error);

	metafreereplicalist(rlp);

	/*
	 * This finishes up the logical equivalent of meta_set_take.
	 */
	if (meta_resync_all(&sn, MD_DEF_RESYNC_BUF_SIZE, &error) != 0) {
	    mde_perror(&error, "");
	    mdclrerror(&error);
	}
}

/*
 * Take the disksets that are marked to be taken at boot time.
 */
static void
auto_take_sets()
{
	int		max_sets;
	int		i;
	md_error_t	error = mdnullerror;
	char		*hostname;

	if ((max_sets = get_max_sets(&error)) == 0)
	    return;

	if (!mdisok(&error)) {
	    mde_perror(&error, "");
	    return;
	}

	/* set up so auto-take errors also go to syslog */
	openlog("metainit", LOG_ODELAY, LOG_USER);
	metasyslog = 1;

	hostname = mynode();

	/*
	 * For each possible set number (skip set 0 which is the unnamed local
	 * set), see if we really have a diskset.  If so, check if auto-take
	 * is enabled.
	 *
	 * In order to take the set it must have drives and it must not be
	 * stuck in mid-add.  The sr_validate routine within rpc.metad will
	 * delete sets that are in mid-add when it runs.
	 */
	for (i = 1; i < max_sets; i++) {
	    md_set_record	*sr;

	    if ((sr = metad_getsetbynum(i, &error)) == NULL) {
		mdclrerror(&error);
		continue;
	    }

	    if (sr->sr_flags & MD_SR_AUTO_TAKE && !(sr->sr_flags & MD_SR_ADD)) {
		int	j;
		int	cnt = 0;
		int	host_mismatch = 0;
		int	take = 0;
		md_drive_record	*dr;

		/* check for host renames or multiple hosts in set */
		for (j = 0; j < MD_MAXSIDES; j++) {
		    /* Skip empty slots */
		    if (sr->sr_nodes[j][0] == '\0')
			continue;

		    cnt++;
		    if (strcmp(sr->sr_nodes[j], hostname) != 0)
			host_mismatch = 1;
		}

		/* paranoid check that we're the only host in the set */
		if (cnt > 1) {
			md_eprintf(gettext(
		"diskset %s: auto-take enabled and multiple hosts in set\n"),
			    sr->sr_setname);
			continue;
		}

		if (host_mismatch) {
			/* The host was renamed, repair the set. */
			for (j = 0; j < MD_MAXSIDES; j++) {
				/* Skip empty slots */
				if (sr->sr_nodes[j][0] == '\0')
					continue;

				(void) strncpy(sr->sr_nodes[j], hostname,
				    sizeof (sr->sr_nodes[j]));
				commitset(sr, FALSE, &error);
				if (!mdisok(&error)) {
					mde_perror(&error, "");
					mdclrerror(&error);
				} else {
					md_eprintf(gettext(
			"new hostname %s, update auto-take diskset %s\n"),
						hostname, sr->sr_setname);
				}
				break;
			}
		}

		/* set must have at least one drive to be taken */
		for (dr = sr->sr_drivechain; dr != NULL; dr = dr->dr_next) {
			/* ignore drives in mid-add */
			if (!(dr->dr_flags & MD_DR_ADD)) {
			    take = 1;
			    break;
			}
		}

		if (take)
			take_set(sr);
		else
			md_eprintf(gettext(
		"diskset %s: auto-take enabled but set has no drives\n"),
			    sr->sr_setname);
	    }
	}
}

/*
 * mainline. crack command line arguments.
 */
int
main(
	int		argc,
	char		*argv[]
)
{
	char		*sname = MD_LOCAL_NAME;
	mdsetname_t	*sp = NULL;
	enum action {
		NONE,
		INIT,
		ALL
	}		todo = NONE;
	mdcmdopts_t	options = (MDCMD_DOIT | MDCMD_PRINT);
	int		c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;

	md_error_t	dummystatus = mdnullerror;
	md_error_t	*dummyep = &dummystatus;
	int		eval = 1;
	int		error;
	bool_t		called_thru_rpc = FALSE;
	char		*cp;
	pid_t		pid;

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
	if ((cp = strstr(argv[0], ".rpc_call")) != NULL) {
		*cp = '\0'; /* cut off ".rpc_call" */
		called_thru_rpc = TRUE;
	} else {
		if (sdssc_bind_library() == SDSSC_OKAY)
			if (sdssc_cmd_proxy(argc, argv, SDSSC_PROXY_PRIMARY,
						&error) == SDSSC_PROXY_DONE)
				exit(error);
	}

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0 ||
			meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "afhnrs:?")) != -1) {
		switch (c) {

		/* help */
		case 'h':
			usage(sp, 0);
			break;

		/* set name */
		case 's':
			sname = optarg;
			break;

		/* all devices in md.tab */
		case 'a':
			if (todo != NONE)
				usage(sp, 1);
			todo = ALL;
			options |= MDCMD_ALLOPTION;
			break;
		/* check for validity, but don't really init */
		case 'n':
			options &= ~MDCMD_DOIT;
			break;

		/* for recovery */
		case 'r':
			if (todo != NONE)
				usage(sp, 1);
			todo = INIT;
			break;

		/* mounted and swapped components are OK */
		case 'f':
			options |= MDCMD_FORCE;
			break;

		case '?':
			if (optopt == '?')
				usage(sp, 0);
			/*FALLTHROUGH*/
		default:
			usage(sp, 1);
			break;
		}
	}

	/* sname is MD_LOCAL_NAME if not specified on the command line */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	argc -= optind;
	argv += optind;
	if (todo == NONE) {
		if (argc <= 0) {
			usage(sp, 1);
		}
	} else if (argc > 0) {
		usage(sp, 1);
	}


	/* setup database locations */
	if (meta_setup_db_locations(ep) != 0) {
		mde_perror(ep, "");
		if (mdismddberror(ep, MDE_DB_STALE))
			md_exit(sp, 66);
		if (! mdiserror(ep, MDE_MDDB_CKSUM))	/* relatively benign */
			md_exit(sp, 1);
	}
	if (todo == INIT) {		/* load and take auto-take sets */
		auto_take_sets();

		/*
		 * During the boot sequence we need to update the mediator
		 * records, however this depends upon the rpc.metamedd
		 * running. So, in order to not introduce a delay in the
		 * boot time, fork a new process to do this work in the
		 * background.
		 */
		pid = fork1();
		if (pid == (pid_t)-1) {
			/*
			 * We could not fork a child process to udpate mediator
			 * information on this node. There is no need to panic.
			 * We shall simply return 1.
			 */
			mde_perror(ep, "Could not fork a child process to"
			    " update mediator record");
			md_exit(sp, 1);
		} else if (pid == (pid_t)0) {
			/* child */
			if (meta_mediator_info_from_file(NULL, 0, ep) == 1) {
				/*
				 * No need to print any error messages.
				 * All the errors messages are printed in the
				 * library routine itself.
				 */
				md_exit(sp, 1);
			} else {
				md_exit(sp, 0);
			}
		} else {
			/* Parent process */
			md_exit(sp, 0);
		}
	} else if (todo == ALL) {	/* initialize all devices in md.tab */
		eval = init_all(&sp, options, called_thru_rpc, ep);
	} else {			/* initialize the named device */
		eval = 0;
		if (init_name(&sp, argc, argv, options, called_thru_rpc,
		    ep) != 0) {
			/*
			 * If we're dealing with MN metadevices and we are
			 * directly called, then the appropriate error message
			 * has already been displayed. So just exit.
			 */
			if (meta_is_mn_set(sp, dummyep) && (!called_thru_rpc)) {
				md_exit(sp, 1);
			}
			mde_perror(ep, "");
			mdclrerror(ep);
			eval = 1;
			goto nomdcf;
		}
	}

domdcf:
	/* update md.cf, return success */
	if (meta_update_md_cf(sp, ep) != 0) {
		mde_perror(ep, "");
		eval = 1;
	}

nomdcf:
	md_exit(sp, eval);
	/*NOTREACHED*/
	return (eval);
}
