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

#include <meta.h>
#include <sdssc.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/lvm/md_mirror.h>
#include <metad.h>

#define	MY_VERSION		"1.0"	/* the highest supported version */
#define	MAX_DEBUG_LEVEL		5	/* maximum verbosity level */

#define	RESET_OWNER		0x0001
#define	CHOOSE_OWNER		0x0002
#define	RESET_ABR		0x0004
#define	UPDATE_ABR		0x0008
#define	GET_MIRROR_STATE	0x0010

#define	SET_INFO_NO_WR	0x0002
#define	SET_INFO_MN	0x0004

/*
 * This table defines all the metaclust reconfig steps we understand
 */
typedef enum stpnum {
	MC_UNK = 0,
	MC_START,
	MC_STOP,
	MC_ABORT,
	MC_RETURN,
	MC_STEP1,
	MC_STEP2,
	MC_STEP3,
	MC_STEP4
} stepnum_t;

/*
 * Structure for step_name -> step_number mapping
 */
struct step_t {
	char		*step_nam;
	stepnum_t	step_num;
};

/*
 * Step name to step number mapping table
 * This table MUST be sorted alphabetically in ascending order of step name
 */
static struct step_t step_table[] = {
	{ "abort",	MC_ABORT },
	{ "return",	MC_RETURN },
	{ "start",	MC_START },
	{ "step1",	MC_STEP1 },
	{ "step2",	MC_STEP2 },
	{ "step3",	MC_STEP3 },
	{ "step4",	MC_STEP4 },
	{ "stop",	MC_STOP }
};

/*
 * If support for a different version is added, the new version number should
 * be appended to the version_table below. This list will be searched to
 * determine if a version requested via the -V option is supported or not.
 */
static char *version_table[] = {
	MY_VERSION
};

uint_t	timeout = 0;			/* disable timeout by default */
char	*version = MY_VERSION;		/* use latest version by default */
int	stepnum = MC_UNK;		/* reconfiguration step number */
pid_t	c_pid;				/* child process id */

/*
 * Binary search comparison routine
 */
static int
mc_compare(const void *stp1, const void *stp2)
{
	return (strcmp((const char *)stp1,
	    ((const struct step_t *)stp2)->step_nam));
}

/*
 * Timeout expiry alarm signal handler
 */
/*ARGSUSED*/
static void
sigalarmhandler(int sig)
{
	int	i, n, ret, stat_loc = 0;

	n = sizeof (step_table) / sizeof (step_table[0]);
	for (i = 0; i < n; i++) {
		if (stepnum == step_table[i].step_num)
			break;
	}

	assert(i != n);

	meta_mc_log(MC_LOG1, gettext("Timeout expired in %s: %s"),
	    step_table[i].step_nam,
	    meta_print_hrtime(gethrtime() - start_time));

	if ((ret = kill(c_pid, SIGKILL)) == 0) {
		/*
		 * The child will wait forever until the status is retrieved
		 * so get it now. Keep retrying if the call is interrupted.
		 *
		 * The possible results are,
		 *
		 *	- child killed successfully
		 *	- signal sent but child not killed
		 *	- waitpid failed/interrupted
		 */
		sleep(2);
		while ((ret = waitpid(c_pid, &stat_loc, WNOHANG)) < 0) {
			if (errno != EINTR) {
				break;
			}
		}
		if ((ret == c_pid) || (errno == ECHILD)) {
			ret = 0;
		} else {
			ret = 1;
		}
	} else if (errno == ESRCH) {
		/*
		 * If the kill did not catch the child then it means the child
		 * exited immediately after the timeout occured.
		 */
		ret = 0;
	}

	/*
	 * make sure not to exit with 205 for any steps other than step1-step4.
	 * Suncluster reconfiguration can't handle it otherwise.
	 */
	switch (stepnum) {
	case MC_STEP1:
	case MC_STEP2:
	case MC_STEP3:
	case MC_STEP4:
		/*
		 * If the child was killed successfully return 205 for a
		 * new reconfig cycle otherwise send 1 to panic the node.
		 */
		if (ret != 0) {
			md_eprintf(gettext("Could not kill child\n"));
			exit(1);
		} else {
			exit(205);
		}
		break;
	case MC_START:
	case MC_STOP:
	case MC_ABORT:
	case MC_RETURN:
	default:
		exit(1);
		break;
	}
}

/*
 * Attempt to load local set.
 * Returns:
 *	pointer to mdsetname_t for local set (local_sp) is successful.
 *	0 if failure
 *		if there are no local set mddbs, no error message is printed.
 *		Otherwise, error message is printed so that user
 *		can determine why the local set didn't start.
 */
mdsetname_t *
load_local_set(md_error_t *ep)
{
	mdsetname_t	*local_sp = NULL;

	/* Does local set exist? If not, give no error */
	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		return (0);
	}

	/*
	 * snarf local set
	 * If fails with MDE_DB_NODB, then just return 1 printing
	 * no failure.
	 * Otherwise, print error message, and return 1.
	 */
	if (meta_setup_db_locations(ep) != 0) {
		if (!(mdismddberror(ep, MDE_DB_NODB)))
			mde_perror(ep, "");
		return (0);
	}

	/* local set loaded successfully */
	return (local_sp);
}

/*
 * Purpose:	Compose a full path name for a metadevice
 *
 * On entry:	sp	- setname pointer
 *		mnum	- minor number of metadevice
 *		pathname - pointer to array to return path string
 *		pathlen	- max length of pathname array
 */
static int
compose_path(mdsetname_t *sp, int mnum, char *pathname, int pathlen)
{
	int	rtn;
	mdname_t	*np;
	md_error_t	status = mdnullerror;

	if (MD_MIN2SET(mnum) != sp->setno) {
		md_eprintf(gettext("minor number 0x%x invalid for set %d\n"),
		    mnum, sp->setno);
		return (-1);
	}

	if ((np = metamnumname(&sp, mnum, 0, &status)) == NULL) {
		return (-1);
	}

	rtn = snprintf(pathname, pathlen, "%s", np->rname);

	if ((pathname[0] == '\0') || (rtn >= pathlen)) {
		md_eprintf(gettext(
		    "Could not create path for device %s\n"),
		    get_mdname(sp, mnum));
		return (-1);
	}
	return (0);
}

/*
 * Purpose:	Walk through all the devices specified for the given set
 *		and do the action specified in mode
 */
static int
reset_state(uint_t mode, mdsetname_t *sp, char *drivername, md_error_t *ep)
{
	mdnamelist_t			*devnlp = NULL;
	mdnamelist_t			*p;
	mdname_t			*devnp = NULL;
	md_set_mmown_params_t		ownpar_p;
	md_set_mmown_params_t		*ownpar = &ownpar_p;
	md_unit_t			*mm;
	int				mirror_dev = 0;
	mndiskset_membershiplist_t	*nl;
	int				cnt;
	int				has_parent;
	md_mn_get_mir_state_t		mir_state_p;
	md_mn_get_mir_state_t		*mir_state = &mir_state_p;

	/*
	 * if we are choosing or resetting the owners then make sure
	 * we are only doing it for mirror devices
	 */
	mirror_dev = (strcmp(MD_MIRROR, drivername) == 0);
	if ((mode & (RESET_OWNER | CHOOSE_OWNER)) && !mirror_dev) {
		return (-1);
	}

	/* get a list of all the metadevices for current set */
	if (mirror_dev && meta_get_mirror_names(sp, &devnlp, 0, ep) < 0) {
		mde_perror(ep, gettext("Could not get mirrors for set %s"),
		    sp->setname);
		return (-1);
	} else if (meta_get_sp_names(sp, &devnlp, 0, ep) < 0) {
		mde_perror(ep, gettext(
		    "Could not get soft partitions for set %s"), sp->setname);
		return (-1);
	}

	/* If resetting the owner, get the known membership list */
	if (mode & RESET_OWNER) {
		if (meta_read_nodelist(&cnt, &nl, ep)) {
			mde_perror(ep, "Could not get nodelist");
			return (-1);
		}
	}

	/* for each metadevice */
	for (p = devnlp; (p != NULL); p = p->next) {
		devnp = p->namep;

		/*
		 * Get the current setting for mirror ABR state and all of the
		 * submirror state and flags from the master node. We only
		 * perform this when going through a 'start' cycle.
		 */
		if ((mode & GET_MIRROR_STATE) && mirror_dev) {
			char	*miscname;

			/*
			 * Ensure that we ignore soft-parts that are returned
			 * from the meta_get_mirror_names() call
			 */
			if ((miscname = metagetmiscname(devnp, ep)) == NULL)
				goto out;
			if (strcmp(miscname, MD_MIRROR) != 0)
				continue;

			mir_state->mnum = meta_getminor(devnp->dev);
			MD_SETDRIVERNAME(mir_state, MD_MIRROR, sp->setno);
			meta_mc_log(MC_LOG4, gettext("Getting mirror state"
			    " for %s: %s"), get_mdname(sp, mir_state->mnum),
			    meta_print_hrtime(gethrtime() - start_time));

			if (metaioctl(MD_MN_GET_MIRROR_STATE, mir_state, ep,
			    "MD_MN_GET_MIRROR_STATE") != 0) {
				mde_perror(ep, gettext("Unable to get "
				    "mirror state for %s"),
				    get_mdname(sp, mir_state->mnum));
				goto out;
			} else {
				continue;
			}
		}

		/* check if this is a top level metadevice */
		if ((mm = meta_get_mdunit(sp, devnp, ep)) == NULL)
			goto out;
		if (MD_HAS_PARENT(MD_PARENT(mm))) {
			has_parent = 1;
		} else {
			has_parent = 0;
		}
		Free(mm);

		if (mode & (RESET_OWNER | CHOOSE_OWNER)) {
			char	*miscname;

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
			MD_SETDRIVERNAME(ownpar, MD_MIRROR, sp->setno);

			meta_mc_log(MC_LOG4, gettext("Setting owner "
			    "for %s: %s"), get_mdname(sp, ownpar->d.mnum),
			    meta_print_hrtime(gethrtime() - start_time));

			/* get the current owner id */
			if (metaioctl(MD_MN_GET_MM_OWNER, ownpar, ep,
			    "MD_MN_GET_MM_OWNER") != 0) {
				mde_perror(ep, gettext("Unable to get "
				    "mirror owner for %s"),
				    get_mdname(sp, ownpar->d.mnum));
				goto out;
			}
		}

		if (mode & RESET_OWNER) {
			if (ownpar->d.owner == MD_MN_MIRROR_UNOWNED) {
				mdclrerror(ep);
				continue;
			}

			/*
			 * reset owner only if the current owner is
			 * not in the membership list
			 * Also kill the resync thread so that when the resync
			 * is started, it will perform an optimized resync
			 * for any resync regions that were dirty when the
			 * current owner left the membership.
			 */
			if (meta_is_member(NULL, ownpar->d.owner, nl) != 1) {
				if (meta_mn_change_owner(&ownpar,
				    sp->setno, ownpar->d.mnum,
				    MD_MN_MIRROR_UNOWNED,
				    MD_MN_MM_ALLOW_CHANGE) == -1) {
					md_eprintf(gettext(
					    "Unable to reset mirror owner "
					    "for %s\n"),
					    get_mdname(sp, ownpar->d.mnum));
					goto out;
				}
				if (meta_mirror_resync(sp, devnp, 0, ep,
				    MD_RESYNC_KILL_NO_WAIT) != 0) {
					md_eprintf(gettext(
					    "Unable to kill resync for"
					    " %s\n"),
					    get_mdname(sp, ownpar->d.mnum));
					goto out;
				}
			}
		}

		if (mode & CHOOSE_OWNER) {
			/*
			 * only orphaned resyncs will have no owner.
			 * if that is the case choose a new owner. Otherwise
			 * re-establish the existing owner. This covers the
			 * case where a node that owned the mirror
			 * reboots/panics and comes back into the cluster before
			 * the reconfig cycle has completed. In this case the
			 * other cluster nodes will have the mirror owner marked
			 * as the rebooted node while it has the owner marked
			 * as 'None'. We have to reestablish the ownership so
			 * that the subsequent resync can continue.
			 */
			if (meta_mn_change_owner(&ownpar, sp->setno,
			    ownpar->d.mnum, ownpar->d.owner,
			    MD_MN_MM_CHOOSE_OWNER) == -1) {
				md_eprintf(gettext("Unable to choose "
				    "mirror owner for %s\n"),
				    get_mdname(sp, ownpar->d.mnum));
				goto out;
			}
		}

		/*
		 * For RESET_ABR and UPDATE_ABR - only handle top
		 * level metadevices.
		 */
		if (has_parent)
			continue;

		if (mode & RESET_ABR) {
			/*
			 * Reset the ABR (application based recovery)
			 * value on all nodes. We are dealing with
			 * the possibility that we have ABR set but the
			 * only node that had the device open with ABR has
			 * left the cluster. We simply open and close the
			 * device and if this is the last close in the
			 * cluster, ABR will be cleared on all nodes.
			 */
			char		*miscname;
			char		name[MAXPATHLEN];
			int		mnum, fd;

			name[0] = '\0';
			mnum = meta_getminor(devnp->dev);

			/*
			 * Ensure that we don't include soft-parts in the
			 * mirror-only call to RESET_ABR. meta_get_mirror_names
			 * returns a bogus list that includes all soft-parts
			 * built on mirrors.
			 */
			if ((miscname = metagetmiscname(devnp, ep)) == NULL)
				goto out;
			if (mirror_dev && (strcmp(miscname, MD_MIRROR) != 0))
				continue;

			meta_mc_log(MC_LOG4, gettext("Re-setting ABR state "
			    "for %s: %s"), get_mdname(sp, mnum),
			    meta_print_hrtime(gethrtime() - start_time));

			/* compose the absolute device path and open it */
			if (compose_path(sp, mnum, &name[0],
			    sizeof (name)) != 0)
				goto out;
			if ((fd = open(name, O_RDWR, 0)) < 0) {
				md_perror(gettext("Could not open device %s"),
				    name);
				continue;
			}

			(void) close(fd);
		}

		if (mode & UPDATE_ABR) {
			/*
			 * Update the ABR value on this node. We obtain the
			 * current ABR state from the master node.
			 */

			char		*miscname;
			char		name[MAXPATHLEN];
			int		mnum, fd;
			volcap_t	vc;
			uint_t		tstate;

			name[0] = '\0';
			mnum = meta_getminor(devnp->dev);

			/*
			 * Ensure that we don't include soft-parts in the
			 * mirror-only call to UPDATE_ABR. meta_get_mirror_names
			 * returns a bogus list that includes all soft-parts
			 * built on mirrors.
			 */
			if ((miscname = metagetmiscname(devnp, ep)) == NULL)
				goto out;
			if (mirror_dev && (strcmp(miscname, MD_MIRROR) != 0))
				continue;

			/* Get tstate from Master */
			if (meta_mn_send_get_tstate(devnp->dev, &tstate, ep)
			    != 0)
				continue;
			/* If not set on the master, nothing to do */
			if (!(tstate & MD_ABR_CAP))
				continue;

			meta_mc_log(MC_LOG4, gettext("Updating ABR state "
			    "for %s: %s"), get_mdname(sp, mnum),
			    meta_print_hrtime(gethrtime() - start_time));

			/* compose the absolute device path and open it */
			if (compose_path(sp, mnum, &name[0],
			    sizeof (name)) != 0)
				goto out;
			if ((fd = open(name, O_RDWR, 0)) < 0) {
				md_perror(gettext("Could not open device %s"),
				    name);
				continue;
			}

			/* set ABR state */
			vc.vc_info = 0;
			vc.vc_set = 0;
			if (ioctl(fd, DKIOCGETVOLCAP, &vc) < 0) {
				/*
				 * Ignore if device does not support this
				 * ioctl
				 */
				if ((errno != ENOTTY) && (errno != ENOTSUP)) {
					md_perror(gettext("Could not get "
					    "ABR/DMR state for device %s"),
					    name);
				}
				(void) close(fd);
				continue;
			}
			if (!(vc.vc_info & (DKV_ABR_CAP | DKV_DMR_CAP))) {
				(void) close(fd);
				continue;
			}

			vc.vc_set = DKV_ABR_CAP;
			if (ioctl(fd, DKIOCSETVOLCAP, &vc) < 0) {
				md_perror(gettext(
				    "Could not set ABR state for "
				    "device %s"), name);
				(void) close(fd);
				goto out;
			} else {
				md_eprintf(gettext(
				    "Setting ABR state on device %s\n"), name);
			}

			(void) close(fd);
		}
	}

	/* cleanup */
	if (mode & RESET_OWNER) {
		meta_free_nodelist(nl);
	}
	metafreenamelist(devnlp);
	return (0);

out:
	/* cleanup */
	if (mode & RESET_OWNER) {
		meta_free_nodelist(nl);
	}
	metafreenamelist(devnlp);
	return (-1);
}

/*
 * Print usage message
 */
static void
usage(mdsetname_t *sp, int eval)
{
	(void) fprintf(stderr, gettext("usage:"
	    "\t%s [-V version] [-t timeout] [-d level] start localnodeid\n"
	    "\t%s [-V version] [-t timeout] [-d level] step nodelist...\n"
	    "\t%s [-V version] [-t timeout] [-d level] abort | stop\n"
	    "\t%s [-V | -? | -h]\n"),
	    myname, myname, myname, myname);
	if (!eval) {
		fprintf(stderr, gettext("\n"
		    "\tValid debug (-d) levels are 1-%d for increasing "
		    "verbosity.\n\tDefault is -d 3.\n\n"
		    "\tValid step values are: return | step1 | step2 | "
		    "step3 | step4\n\n"
		    "\tNodelist is a space-separated list of node id's\n\n"),
		    MAX_DEBUG_LEVEL);
	}
	md_exit(sp, eval);
}

/*
 * Input:	Input takes a config step name followed by a list of
 *		possible node id's.
 *
 * Returns:	  0 - Success
 *		  1 - Fail
 *			Node will be removed from cluster membership
 *			by forcing node to panic.
 *		205 - Unsuccessful. Start another reconfig cycle.
 *			Problem was encountered that could be fixed by
 *			running another reconfig cycle.
 *			Problem could be a result of a failure to read
 *			the nodelist file or that all work could not be
 *			accomplished in a reconfig step in the amount of
 *			time given so another reconfig cycle is needed in
 *			order to finish the current step.
 */
int
main(int argc, char **argv)
{
	mdsetname_t		*sp = NULL;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;
	set_t			max_sets, setno;
	int			c, clust = 0;
	struct sigaction	nsa, osa;
	struct step_t		*step_ptr;
	mdsetname_t		*local_sp = NULL;
	md_drive_desc		*dd;
	int			rval = 0;
	md_set_desc		*sd;
	mddb_block_parm_t	mbp;
	uint_t			debug = 3; /* log upto MC_LOG3 by default */
	int			version_table_size;
	mddb_setflags_config_t	sf;
	int			ret_val;
	mddb_config_t		cfg;
	int			set_info[MD_MAXSETS];
	long			commd_timeout = 0;

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

	if ((clust = sdssc_bind_library()) == SDSSC_ERROR) {
		md_eprintf(gettext("Interface error with libsds_sc.so\n"));
		exit(1);
	}

	if (md_init(argc, argv, 1, 1, ep) != 0 || meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/*
	 * open log and enable libmeta logging. Do it here explicitly
	 * rather than letting md_init() do it because we are not really
	 * a daemon and that is what md_init() opens the log as.
	 */
	openlog("metaclust", LOG_CONS, LOG_USER);

	version_table_size = sizeof (version_table) / sizeof (version_table[0]);

	optind = 1;
	opterr = 0;
	while ((c = getopt(argc, argv, "hd:V:t:?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 'd':
			if (sscanf(optarg, "%u", &debug) != 1) {
				md_eprintf(gettext("Invalid debug level\n"));
				md_exit(sp, 1);
			} else if ((debug < 1) || (debug > MAX_DEBUG_LEVEL)) {
				debug = min(max(debug, 1), MAX_DEBUG_LEVEL);
				md_eprintf(gettext("Debug level must be "
				    "between 1 and %d inclusive.\n"),
				    MAX_DEBUG_LEVEL);
				md_eprintf(gettext("Debug level set to %d.\n"),
				    debug);
			}
			break;

		case 'V':
			version = Strdup(optarg);
			break;

		case 't':
			if (sscanf(optarg, "%u", &timeout) != 1) {
				md_eprintf(gettext("Invalid timeout value\n"));
				md_exit(sp, 1);
			}
			break;

		case '?':
			if (optopt == '?') {
				usage(sp, 0);
			} else if (optopt == 'V') {
				int	i;

				fprintf(stdout, gettext(
				    "%s: Versions Supported:"), myname);
				for (i = 0; i < version_table_size; i++) {
					fprintf(stdout, " %s",
					    version_table[i]);
				}
				fprintf(stdout, "\n");
				md_exit(sp, 0);
			}
			/*FALLTHROUGH*/

		default:
			usage(sp, 1);
			break;
		}
	}

	/* initialise the debug level and start time */
	setup_mc_log(debug);

	/*
	 * check that the version specified (if any) is supported.
	 */
	if (version != NULL) {
		int	i, found = 0;

		for (i = 0; i < version_table_size; i++) {
			if (strcmp(version, version_table[i]) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			md_eprintf(gettext("Version %s not supported\n"),
			    version);
			md_exit(sp, 1);
		}
	}

	argc -= optind;
	argv += optind;

	/* parse arguments */
	if (argc <= 0) {
		usage(sp, 1);
	}

	/* convert the step name to the corresponding number */
	step_ptr = bsearch(argv[0], step_table, (sizeof (step_table) /
	    sizeof (step_table[0])), sizeof (step_table[0]), mc_compare);
	if (step_ptr != NULL) {
		stepnum = step_ptr->step_num;
	}

	--argc;
	++argv;

	/* set timeout alarm signal, a value of 0 will disable timeout */
	if (timeout > 0) {
		int	stat_loc = 0;
		commd_timeout = (long)(timeout * .75);

		c_pid = fork();

		if (c_pid == (pid_t)-1) {
			md_perror(gettext("Unable to fork"));
			md_exit(sp, 1);
		} else if (c_pid) {
			/* parent */
			nsa.sa_flags = 0;
			if (sigfillset(&nsa.sa_mask) < 0) {
				md_perror(gettext("Unable to set signal mask"));
				md_exit(sp, 1);
			}

			nsa.sa_handler = sigalarmhandler;
			if (sigaction(SIGALRM, &nsa, &osa) == -1) {
				md_perror(gettext("Unable to set alarm "
				    "handler"));
				md_exit(sp, 1);
			}

			(void) alarm(timeout);

			/*
			 * wait for child to exit or timeout to expire.
			 * keep retrying if the call is interrupted
			 */
			while ((ret_val = waitpid(c_pid, &stat_loc, 0)) < 0) {
				if (errno != EINTR) {
					break;
				}
			}
			if (ret_val == c_pid) {
				/* exit with the childs exit value */
				exit(WEXITSTATUS(stat_loc));
			} else if (errno == ECHILD) {
				md_exit(sp, 0);
			} else {
				perror(myname);
				md_exit(sp, 1);
			}
		}
	}

	/*
	 * If a timeout value is given, everything from this point onwards is
	 * executed in the child process.
	 */

	switch (stepnum) {
	case MC_START:
		/*
		 * Start Step
		 *
		 * - Suspend all rpc.mdcommd messages
		 */

		/* expect the local node id to be given only */
		if (argc != 1)
			usage(sp, 1);

		meta_mc_log(MC_LOG2, gettext("Starting Start step: %s"),
		    meta_print_hrtime(0));

		/*
		 * Does local set exist? If not, exit with 0
		 * since there's no reason to have this node panic if
		 * the local set cannot be started.
		 */
		if ((local_sp = load_local_set(ep)) == NULL) {
			md_exit(local_sp, 0);
		}

		if ((max_sets = get_max_sets(ep)) == 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		/* start walking through all possible disksets */
		for (setno = 1; setno < max_sets; setno++) {
			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else {
					mde_perror(ep, gettext("Unable to "
					    "get set %d information"), setno);
					md_exit(sp, 1);
				}
			}

			/* only check multi-node disksets */
			if (!meta_is_mn_set(sp, ep)) {
				mdclrerror(ep);
				continue;
			}

			meta_mc_log(MC_LOG3, gettext("Start - block parse "
			    "messages for set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));

			/*
			 * Mddb parse messages are sent amongst the nodes
			 * in a diskset whenever the locator block or
			 * locator names structure has been changed.
			 * A locator block change could occur as a result
			 * of a disk failure during the reconfig cycle,
			 * so block the mddb parse messages while the
			 * rpc.mdcommd is suspended during the reconfig cycle.
			 */
			if (s_ownset(sp->setno, ep) == MD_SETOWNER_YES) {
				(void) memset(&mbp, 0, sizeof (mbp));
				mbp.c_setno = setno;
				mbp.c_blk_flags = MDDB_BLOCK_PARSE;
				if (metaioctl(MD_MN_MDDB_BLOCK, &mbp,
				    &mbp.c_mde, NULL)) {
					mdstealerror(ep, &mbp.c_mde);
					mde_perror(ep, gettext("Could not "
					    "block set %s"), sp->setname);
					md_exit(sp, 1);
				}
			}

			/* suspend commd and spin waiting for drain */
			while ((ret_val = mdmn_suspend(setno,
			    MD_COMM_ALL_CLASSES, commd_timeout)) ==
			    MDE_DS_COMMDCTL_SUSPEND_NYD) {
				sleep(1);
			}

			if (ret_val) {
				md_eprintf(gettext("Could not suspend "
				    "rpc.mdcommd for set %s\n"), sp->setname);
				md_exit(sp, 1);
			}

			/*
			 * Set start step flag for set. This is set to indicate
			 * that this node entered the reconfig cycle through
			 * the start step.  This is used during the reconfig
			 * cycle to determine whether the node had entered
			 * through the start step or the return step.
			 */
			(void) memset(&sf, 0, sizeof (sf));
			sf.sf_setno = sp->setno;
			sf.sf_setflags = MD_SET_MN_START_RC;
			sf.sf_flags = MDDB_NM_SET;
			/* Use magic to help protect ioctl against attack. */
			sf.sf_magic = MDDB_SETFLAGS_MAGIC;
			if (metaioctl(MD_MN_SET_SETFLAGS, &sf,
			    &sf.sf_mde, NULL)) {
				mdstealerror(ep, &sf.sf_mde);
				mde_perror(ep, gettext("Could not set "
				    "start_step flag for set %s"), sp->setname);
				md_exit(sp, 1);
			}

		}

		meta_mc_log(MC_LOG2, gettext("Start step completed: %s"),
		    meta_print_hrtime(gethrtime() - start_time));

		break;

	case MC_STOP:
		/*
		 * Stop Step
		 *
		 * - ???
		 */

		/* don't expect any more arguments to follow the step name */
		if (argc != 0)
			usage(sp, 1);

		break;

	case MC_ABORT:
		/*
		 * Abort Step
		 *
		 * - Abort rpc.mdcommd
		 */

		/* don't expect any more arguments to follow the step name */
		if (argc != 0)
			usage(sp, 1);

		meta_mc_log(MC_LOG2, gettext("Starting Abort step: %s"),
		    meta_print_hrtime(0));

		/*
		 * Does local set exist? If not, exit with 0
		 * since there's no reason to have this node panic if
		 * the local set cannot be started.
		 */
		if ((local_sp = load_local_set(ep)) == NULL) {
			md_exit(local_sp, 0);
		}

		/*
		 * abort the rpc.mdcommd.  The abort is only issued on this node
		 * meaning that the abort reconfig step is called on this
		 * node before a panic while the rest of the cluster will
		 * undergo a reconfig cycle.
		 * There is no time relation between this node running a
		 * reconfig abort and the the rest of the cluster
		 * running a reconfig cycle meaning that this node may
		 * panic before, during or after the cluster has run
		 * a reconfig cycle.
		 */
		mdmn_abort();

		meta_mc_log(MC_LOG2, gettext("Abort step completed: %s"),
		    meta_print_hrtime(gethrtime() - start_time));

		break;

	case MC_RETURN:
		/*
		 * Return Step
		 *
		 * - Grab local set lock, issue rpc.mdcommd DRAIN ALL
		 *   and release local set lock.  Grabbing the local set
		 *   lock allows any active metaset/metadb commands to
		 *   terminate gracefully and will keep a metaset/metadb
		 *   command from starting until the DRAIN ALL is issued.
		 *   The metaset/metadb commands can issue
		 *   DRAIN ALL/RESUME ALL commands to rpc.mdcommd,
		 *   so the return step must not issue the DRAIN ALL command
		 *   until metaset/metadb have finished or metaset may issue
		 *   a RESUME ALL after this return reconfig step has issued
		 *   the DRAIN ALL command.
		 *   After this reconfig step has issued the DRAIN_ALL and
		 *   released the local set lock, metaset/metadb will fail
		 *   when attempting to contact the rpc.mdcommd and will
		 *   terminate without making any configuration changes.
		 *   The DRAIN ALL command will keep all other meta* commands
		 *   from running during the reconfig cycle (these commands
		 *   will wait until the rpc.mdcommd is resumed) since the
		 *   reconfig cycle may be changing the diskset configuration.
		 */

		/* expect the nodelist to follow the step name */
		if (argc < 1)
			usage(sp, 1);

		meta_mc_log(MC_LOG2, gettext("Starting Return step: %s"),
		    meta_print_hrtime(0));

		/*
		 * Does local set exist? If not, exit with 0
		 * since there's no reason to have this node panic if
		 * the local set cannot be started.
		 */
		if ((local_sp = load_local_set(ep)) == NULL) {
			md_exit(local_sp, 0);
		}

		/*
		 * Suspend any mirror resyncs that are in progress. This
		 * stops unnecessary timeouts.
		 */
		meta_mirror_resync_block_all();

		if (meta_lock(local_sp, TRUE, ep) != 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		/*
		 * All metaset and metadb commands on this node have now
		 * terminated gracefully.  Now, issue a drain all to
		 * the rpc.mdcommd.  Any meta command issued after the
		 * drain all will either spin sending the command to the
		 * master until after the reconfig cycle has finished OR
		 * will terminate gracefully (metaset/metadb).
		 */
		if ((max_sets = get_max_sets(ep)) == 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		/* start walking through all possible disksets */
		for (setno = 1; setno < max_sets; setno++) {
			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else {
					mde_perror(ep, gettext("Unable to "
					    "get set %d information"), setno);
					md_exit(sp, 1);
				}
			}

			/* only check multi-node disksets */
			if (!meta_is_mn_set(sp, ep)) {
				mdclrerror(ep);
				continue;
			}

			meta_mc_log(MC_LOG3, gettext("Return - block parse "
			    "messages for set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));

			/*
			 * Mddb parse messages are sent amongst the nodes
			 * in a diskset whenever the locator block or
			 * locator names structure has been changed.
			 * A locator block change could occur as a result
			 * of a disk failure during the reconfig cycle,
			 * so block the mddb parse messages while the
			 * rpc.commd is suspended during the reconfig cycle.
			 */
			if (s_ownset(sp->setno, ep) == MD_SETOWNER_YES) {
				(void) memset(&mbp, 0, sizeof (mbp));
				mbp.c_setno = setno;
				mbp.c_blk_flags = MDDB_BLOCK_PARSE;
				if (metaioctl(MD_MN_MDDB_BLOCK, &mbp,
				    &mbp.c_mde, NULL)) {
					mdstealerror(ep, &mbp.c_mde);
					mde_perror(ep, gettext("Could not "
					    "block set %s"), sp->setname);
					md_exit(sp, 1);
				}
			}

			/* suspend commd and spin waiting for drain */
			while ((ret_val = mdmn_suspend(setno,
			    MD_COMM_ALL_CLASSES, commd_timeout)) ==
			    MDE_DS_COMMDCTL_SUSPEND_NYD) {
				sleep(1);
			}

			if (ret_val) {
				md_eprintf(gettext("Could not suspend "
				    "rpc.mdcommd for set %s\n"), sp->setname);
				md_exit(sp, 1);
			}
		}
		/*
		 * Resume all I/Os for this node for all MN sets in
		 * case master node had suspended I/Os but panic'd
		 * before resuming I/Os.  In case of failure, exit
		 * with a 1 since unable to resume I/Os on this node.
		 */
		if (clnt_mn_susp_res_io(mynode(), 0, MN_RES_IO, ep)) {
			mde_perror(ep, gettext(
			    "Unable to resume I/O on node %s for all sets"),
			    mynode());
			md_exit(sp, 1);
		}


		/*
		 * Can now unlock local set lock.  New metaset/metadb
		 * commands are now held off using drain all.
		 */
		(void) meta_unlock(local_sp, ep);

		meta_mc_log(MC_LOG2, gettext("Return step completed: %s"),
		    meta_print_hrtime(gethrtime() - start_time));

		break;

	case MC_STEP1:
		/*
		 * Step 1
		 *
		 * - Populate nodelist file if we are on clustering
		 *   and pick a master node for each MN diskset.
		 */

		/* expect the nodelist to follow the step name */
		if (argc < 1)
			usage(sp, 1);

		meta_mc_log(MC_LOG2, gettext("Starting Step1: %s"),
		    meta_print_hrtime(0));

		/* Always write nodelist file even if no local set exists */
		if (clust == SDSSC_OKAY) {
			/* skip to the nodelist args */
			if (meta_write_nodelist(argc, argv, ep) != 0) {
				mde_perror(ep, gettext(
				    "Could not populate nodelist file"));
				md_exit(sp, 1);
			}
		}

		/*
		 * Does local set exist? If not, exit with 0
		 * since there's no reason to have this node panic if
		 * the local set cannot be started.
		 */
		if ((local_sp = load_local_set(ep)) == NULL) {
			md_exit(local_sp, 0);
		}

		/*
		 * At this point, all meta* commands are blocked across
		 * all disksets since the master rpc.mdcommd has drained or
		 * the master node has died.
		 * If a metaset or metadb command had been in progress
		 * at the start of the reconfig cycle, this command has
		 * either completed or it has been terminated due to
		 * the death of the master node.
		 *
		 * This means that that it is now ok to remove any
		 * outstanding clnt_locks associated with multinode
		 * disksets on this node due to a node panic during
		 * a metaset operation.  This allows the routines that
		 * choose the master to use rpc.metad to determine the
		 * master of the diskset.
		 */
		if (clnt_clr_mnsetlock(mynode(), ep) != 0) {
			meta_mc_log(MC_LOG2, gettext("Step1 aborted:"
			    "clear locks failed %s"),
			    meta_print_hrtime(gethrtime() - start_time));
			md_exit(local_sp, 1);
		}

		/*
		 * Call reconfig_choose_master to choose a master for
		 * each MN diskset, update the nodelist for each diskset
		 * given the member information and send a reinit message
		 * to rpc.mdcommd to reload the nodelist.
		 */
		rval = meta_reconfig_choose_master(commd_timeout, ep);
		if (rval == 205) {
			/*
			 * NOTE: Should issue call to reboot remote host that
			 * is causing the RPC failure.  Clustering to
			 * provide interface in the future.  This should
			 * stop a never-ending set of 205 reconfig cycles.
			 * Remote host causing failure is stored in
			 * ep->host if ep is an RPC error.
			 * if (mdanyrpcerror(ep))
			 * 	reboot (ep->host);
			 */
			meta_mc_log(MC_LOG2, gettext("Step1 aborted:"
			    "choose master failure of 205 %s"),
			    meta_print_hrtime(gethrtime() - start_time));
			md_exit(local_sp, 205);
		} else if (rval != 0) {
			meta_mc_log(MC_LOG2, gettext("Step1 failure: "
			    "choose master failure %s"),
			    meta_print_hrtime(gethrtime() - start_time));
			md_exit(local_sp, 1);
		}

		meta_mc_log(MC_LOG2, gettext("Step1 completed: %s"),
		    meta_print_hrtime(gethrtime() - start_time));

		md_exit(local_sp, rval);
		break;

	case MC_STEP2:
		/*
		 * Step 2
		 *
		 * In Step 2, each node walks the list of disksets.  If a
		 * node is a master of a MN diskset, it synchronizes
		 * the local set USER records for that diskset.
		 *
		 * If disks exist in the diskset and there is a joined
		 * (owner) node in the diskset, the master will also:
		 *	- synchronize the diskset mddbs to the master
		 *	- play the change log
		 *
		 * The master node will now attempt to join any unjoined
		 * nodes that are currently members in the membership list.
		 */

		/* expect the nodelist to follow the step name */
		if (argc < 1)
			usage(sp, 1);

		meta_mc_log(MC_LOG2, gettext("Starting Step2: %s"),
		    meta_print_hrtime(0));

		/*
		 * Does local set exist? If not, exit with 0
		 * since there's no reason to have this node panic if
		 * the local set cannot be started.
		 */
		if ((local_sp = load_local_set(ep)) == NULL) {
			md_exit(local_sp, 0);
		}

		if ((max_sets = get_max_sets(ep)) == 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		/* start walking through all possible disksets */
		for (setno = 1; setno < max_sets; setno++) {
			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else if (mdanyrpcerror(ep)) {
					/* Fail on RPC failure to self */
					mde_perror(ep, gettext(
					    "Unable to get information for "
					    "set number %d"), setno);
					md_exit(local_sp, 1);
				} else {
					mde_perror(ep, gettext(
					    "Unable to get information for "
					    "set number %d"), setno);
					mdclrerror(ep);
					continue;
				}
			}

			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				if (mdanyrpcerror(ep)) {
					/* Fail on RPC failure to self */
					mde_perror(ep, gettext(
					    "Unable to get information for "
					    "set number %d"), setno);
					md_exit(local_sp, 1);
				}
				mde_perror(ep, gettext("Unable to get set "
				    "%s desc information"), sp->setname);
				mdclrerror(ep);
				continue;
			}

			/* Only check MN disksets */
			if (!(MD_MNSET_DESC(sd))) {
				continue;
			}

			/* All actions in step 2 are driven by master */
			if (!(sd->sd_mn_am_i_master)) {
				continue;
			}

			meta_mc_log(MC_LOG3, gettext("Step2 - begin record "
			    "synchronization for set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));

			/*
			 * Synchronize the USER records in the local mddbs
			 * for hosts that are members.  The USER records
			 * contain set, drive and host information.
			 */
			rval = meta_mnsync_user_records(sp, ep);
			if (rval != 0) {
				mde_perror(ep, gettext(
				    "Synchronization of user records "
				    "in set %s failed\n"), sp->setname);
				if (rval == 205) {
					/*
					 * NOTE: Should issue call to reboot
					 * remote host that is causing the RPC
					 * failure.  Clustering to provide
					 * interface in the future.  This
					 * should stop a never-ending set of
					 * 205 reconfig cycles.
					 * Remote host causing failure is
					 * stored in ep->host if ep is an
					 * RPC error.
					 * if (mdanyrpcerror(ep))
					 * 	reboot (ep->host);
					 */
					md_exit(local_sp, 205);
				} else {
					md_exit(local_sp, 1);
				}
			}

			/* Reget sd since sync_user_recs may have flushed it */
			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				mde_perror(ep, gettext("Unable to get set "
				    "%s desc information"), sp->setname);
				md_exit(local_sp, 1);
			}

			dd = metaget_drivedesc(sp,
			    (MD_BASICNAME_OK | PRINT_FAST), ep);
			if (! mdisok(ep)) {
				mde_perror(ep, gettext("Unable to get set "
				    "%s drive information"), sp->setname);
				md_exit(local_sp, 1);
			}

			/*
			 * No drives in set, continue to next set.
			 */
			if (dd == NULL) {
				/* Done with this set */
				continue;
			}

			meta_mc_log(MC_LOG3, gettext("Step2 - local set user "
			    "records completed for set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));

			/*
			 * Synchronize the diskset mddbs for hosts
			 * that are members.  This may involve
			 * playing the changelog and writing out
			 * to the diskset mddbs.
			 */
			rval = meta_mnsync_diskset_mddbs(sp, ep);
			if (rval != 0) {
				mde_perror(ep, gettext(
				    "Synchronization of diskset mddbs "
				    "in set %s failed\n"), sp->setname);
				meta_mc_log(MC_LOG3, gettext("Step2 - diskset "
				    "mddb synchronization failed for "
				    "set %s: %s"), sp->setname,
				    meta_print_hrtime(gethrtime() -
				    start_time));
				if (rval == 205) {
					/*
					 * NOTE: Should issue call to reboot
					 * remote host that is causing the RPC
					 * failure.  Clustering to provide
					 * interface in the future.  This
					 * should stop a never-ending set of
					 * 205 reconfig cycles.
					 * Remote host causing failure is
					 * stored in ep->host if ep is an
					 * RPC error.
					 * if (mdanyrpcerror(ep))
					 * 	reboot (ep->host);
					 */
					md_exit(local_sp, 205);
				} else if (rval == 1) {
					continue;
				} else {
					md_exit(local_sp, 1);
				}
			}

			meta_mc_log(MC_LOG3, gettext("Step2 - diskset mddb "
			    "synchronization completed for set %s: %s"),
			    sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));

			/* Join the starting nodes to the diskset */
			rval = meta_mnjoin_all(sp, ep);
			if (rval != 0) {
				mde_perror(ep, gettext(
				    "Join of non-owner (starting) nodes "
				    "in set %s failed\n"), sp->setname);
				meta_mc_log(MC_LOG3, gettext("Step2 - non owner"
				    "nodes joined for set %s: %s"),
				    sp->setname,
				    meta_print_hrtime(gethrtime() -
				    start_time));
				if (rval == 205) {
					/*
					 * NOTE: Should issue call to reboot
					 * remote host that is causing the RPC
					 * failure.  Clustering to provide
					 * interface in the future.  This
					 * should stop a never-ending set of
					 * 205 reconfig cycles.
					 * Remote host causing failure is
					 * stored in ep->host if ep is an
					 * RPC error.
					 * if (mdanyrpcerror(ep))
					 * 	reboot (ep->host);
					 */
					md_exit(local_sp, 205);
				} else {
					md_exit(local_sp, 1);
				}
			}

			meta_mc_log(MC_LOG3, gettext("Step2 - non owner nodes "
			    "joined for set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));

		}

		meta_mc_log(MC_LOG2, gettext("Step2 completed: %s"),
		    meta_print_hrtime(gethrtime() - start_time));

		break;

	case MC_STEP3:
		/*
		 * Step 3
		 *
		 * For all multinode sets do,
		 * - Reinitialise rpc.mdcommd
		 * - Reset mirror owners to null if the current owner is
		 *   no longer in the membership list
		 */

		/* expect the nodelist to follow the step name */
		if (argc < 1)
			usage(sp, 1);

		meta_mc_log(MC_LOG2, gettext("Starting Step3: %s"),
		    meta_print_hrtime(0));

		/*
		 * Does local set exist? If not, exit with 0
		 * since there's no reason to have this node panic if
		 * the local set cannot be started.
		 */
		if ((local_sp = load_local_set(ep)) == NULL) {
			md_exit(local_sp, 0);
		}

		/*
		 * walk through all sets on this node which could include:
		 *	- MN disksets
		 *	- traditional disksets
		 *	- non-existent disksets
		 * start mirror resync for all MN sets
		 */
		if ((max_sets = get_max_sets(ep)) == 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		/* start walking through all possible disksets */
		for (setno = 1; setno < max_sets; setno++) {
			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else {
					mde_perror(ep, gettext("Unable to "
					    "get set %d information"), setno);
					md_exit(local_sp, 1);
				}
			}

			/* only check multi-node disksets */
			if (!meta_is_mn_set(sp, ep)) {
				mdclrerror(ep);
				continue;
			}

			if (meta_lock(sp, TRUE, ep) != 0) {
				mde_perror(ep, "");
				md_exit(local_sp, 1);
			}

			/* If this node isn't joined to set, do nothing */
			if (s_ownset(sp->setno, ep) != MD_SETOWNER_YES) {
				if (!mdisok(ep)) {
					mde_perror(ep, gettext("Could "
					    "not get set %s ownership"),
					    sp->setname);
					md_exit(sp, 1);
				}
				mdclrerror(ep);
				meta_unlock(sp, ep);
				continue;
			}

			meta_mc_log(MC_LOG3, gettext("Step3 - begin "
			    "re-initialising rpc.mdcommd and resetting mirror "
			    "owners for set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));

			/* reinitialzse rpc.mdcommd with new nodelist */
			if (mdmn_reinit_set(setno, commd_timeout)) {
				md_eprintf(gettext(
				    "Could not re-initialise rpc.mdcommd for "
				    "set %s\n"), sp->setname);
				md_exit(sp, 1);
			}

			(void) memset(&cfg, 0, sizeof (cfg));
			cfg.c_id = 0;
			cfg.c_setno = sp->setno;
			if (metaioctl(MD_DB_GETDEV, &cfg, &cfg.c_mde,
			    NULL) != 0) {
				mdstealerror(ep, &cfg.c_mde);
				mde_perror(ep, gettext("Could "
				    "not get set %s information"),
				    sp->setname);
				md_exit(sp, 1);
			}

			/* Don't do anything else if set is stale */
			if (cfg.c_flags & MDDB_C_STALE) {
				meta_unlock(sp, ep);
				mdclrerror(ep);
				continue;
			}

			/* reset mirror owners */
			if (reset_state(RESET_OWNER, sp, MD_MIRROR, ep) == -1) {
				md_exit(sp, 1);
			}

			meta_unlock(sp, ep);

			meta_mc_log(MC_LOG3, gettext("Step3 - rpc.mdcommd "
			    "re-initialised and mirror owners reset for "
			    "set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));
		}

		meta_mc_log(MC_LOG2, gettext("Step3 completed: %s"),
		    meta_print_hrtime(gethrtime() - start_time));

		break;

	case MC_STEP4:
		/*
		 * Step 4
		 *
		 * For all multinode sets do:
		 * - Resume the rpc.mdcommd messages.  Must resume all
		 *	sets before issuing I/O to any set since an error
		 * 	encountered in a commd suspended set could be
		 *	blocked waiting for commd in another set to resume.
		 *	(This happens since the daemon queues service
		 *	all sets).  An open of a soft partition causes
		 *	a read of the watermarks during the open.
		 * - If set is non-writable (not an owner or STALE), then
		 *	continue to next set.
		 *
		 * For all multinode sets do,
		 * - Reset ABR states for all mirrors, ie clear ABR if not
		 *	open on any node.
		 * - Reset ABR states for all soft partitions, ie clear ABR if
		 *	not open on any node.
		 * - For all slave nodes that have entered through the start
		 *	step, update the ABR state to that of the master and
		 *	get the submirror state from the master
		 * - meta_lock set
		 * - Resync all mirrors
		 * - unlock meta_lock for this set.
		 * - Choose a new owner for any orphaned resyncs
		 *
		 * There is one potential issue here. when concurrently
		 * resetting and updating the ABR state. If the master has ABR
		 * set, but should no longer have because the only node that
		 * had the metadevice open and had ABR set has paniced, the
		 * master will send a message to all nodes to clear the ABR
		 * state. Meanwhile any node that has come through the
		 * start step will get tstate from the master and will update
		 * ABR if it was set in tstate. So, we appear to have a problem
		 * if the following sequence occurs:-
		 * - The slave gets tstate with ABR set
		 * - The master sends a message to clear ABR
		 * - The slave updates ABR with the value it got from tstate.
		 * We now have the master with ABR clear and the slave with ABR
		 * set. Fortunately, having set ABR, the slave will close the
		 * metadevice after setting ABR and as there are no nodes with
		 * the device open, the close will send a message to clear ABR
		 * on all nodes. So, the nodes will all have ABR unset.
		 */

		/* expect the nodelist to follow the step name */
		if (argc < 1)
			usage(sp, 1);

		meta_mc_log(MC_LOG2, gettext("Starting Step4: %s"),
		    meta_print_hrtime(0));

		/*
		 * Does local set exist? If not, exit with 0
		 * since there's no reason to have this node panic if
		 * the local set cannot be started.
		 */
		if ((local_sp = load_local_set(ep)) == NULL) {
			md_exit(local_sp, 0);
		}

		/*
		 * walk through all sets on this node which could include:
		 *	- MN disksets
		 *	- traditional disksets
		 *	- non-existent disksets
		 * start mirror resync for all MN sets
		 */
		if ((max_sets = get_max_sets(ep)) == 0) {
			mde_perror(ep, "");
			md_exit(local_sp, 1);
		}

		/* Clear set_info structure */
		for (setno = 1; setno < max_sets; setno++) {
			set_info[setno] = 0;
		}

		/* start walking through all possible disksets */
		for (setno = 1; setno < max_sets; setno++) {
			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else {
					mde_perror(ep, gettext("Unable to "
					    "get set %d information"), setno);
					md_exit(local_sp, 1);
				}
			}

			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				mde_perror(ep, gettext("Unable to get set "
				    "%s desc information"), sp->setname);
				mdclrerror(ep);
				continue;
			}

			/* only check multi-node disksets */
			if (!meta_is_mn_set(sp, ep)) {
				mdclrerror(ep);
				continue;
			}

			set_info[setno] |= SET_INFO_MN;

			/*
			 * If not an owner (all mddbs failed) or stale
			 * (< 50% mddbs operational), then set is
			 * non-writable so just resume commd and
			 * unblock mddb messages.
			 */
			mdclrerror(ep);
			if (s_ownset(sp->setno, ep) != MD_SETOWNER_YES) {
				set_info[setno] |= SET_INFO_NO_WR;
			}
			if (!mdisok(ep)) {
				mde_perror(ep, gettext("Could "
				    "not get set %s ownership"),
				    sp->setname);
				md_exit(local_sp, 1);
			}
			/* Set is owned - is it stale? */
			if (!set_info[setno] & SET_INFO_NO_WR) {
				(void) memset(&cfg, 0, sizeof (cfg));
				cfg.c_id = 0;
				cfg.c_setno = sp->setno;
				if (metaioctl(MD_DB_GETDEV, &cfg, &cfg.c_mde,
				    NULL) != 0) {
					mdstealerror(ep, &cfg.c_mde);
					mde_perror(ep, gettext("Could "
					    "not get set %s information"),
					    sp->setname);
					md_exit(local_sp, 1);
				}
				if (cfg.c_flags & MDDB_C_STALE) {
					set_info[setno] |= SET_INFO_NO_WR;
				}
			}

			/* resume rpc.mdcommd */
			if (mdmn_resume(setno, MD_COMM_ALL_CLASSES, 0,
			    commd_timeout)) {
				md_eprintf(gettext("Unable to resume "
				    "rpc.mdcommd for set %s\n"), sp->setname);
				md_exit(local_sp, 1);
			}
			meta_ping_mnset(setno);

			/* Unblock mddb parse messages */
			if (s_ownset(sp->setno, ep) == MD_SETOWNER_YES) {
				(void) memset(&mbp, 0, sizeof (mbp));
				mbp.c_setno = setno;
				mbp.c_blk_flags = MDDB_UNBLOCK_PARSE;
				if (metaioctl(MD_MN_MDDB_BLOCK, &mbp,
				    &mbp.c_mde, NULL)) {
					mdstealerror(ep, &mbp.c_mde);
					mde_perror(ep, gettext("Could not "
					    "unblock set %s"), sp->setname);
					md_exit(local_sp, 1);
				}
			}
			meta_mc_log(MC_LOG3, gettext("Step4 - rpc.mdcommd "
			    "resumed and messages unblocked for set %s: %s"),
			    sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));
		}

		for (setno = 1; setno < max_sets; setno++) {
			int			start_step;

			/* Skip traditional disksets. */
			if ((set_info[setno] & SET_INFO_MN) == 0)
				continue;

			/*
			 * If already determined that this set is
			 * a non-writable set, then just continue
			 * to next set since there's nothing else
			 * to do for a non-writable set.
			 */
			if (set_info[setno] & SET_INFO_NO_WR)
				continue;

			if ((sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdiserror(ep, MDE_NO_SET)) {
					/* No set for this setno - continue */
					mdclrerror(ep);
					continue;
				} else {
					mde_perror(ep, gettext("Unable to "
					    "get set %d information"), setno);
					md_exit(local_sp, 1);
				}
			}

			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				mde_perror(ep, gettext("Unable to get set "
				    "%s desc information"), sp->setname);
				mdclrerror(ep);
				continue;
			}

			/* See if this node came through the start step */
			(void) memset(&sf, 0, sizeof (sf));
			sf.sf_setno = sp->setno;
			sf.sf_flags = MDDB_NM_GET;
			/* Use magic to help protect ioctl against attack. */
			sf.sf_magic = MDDB_SETFLAGS_MAGIC;
			if (metaioctl(MD_MN_GET_SETFLAGS, &sf,
			    &sf.sf_mde, NULL)) {
				mdstealerror(ep, &sf.sf_mde);
				mde_perror(ep, gettext("Could not get "
				    "start_step flag for set %s"), sp->setname);
				md_exit(local_sp, 1);
			}
			start_step =
			    (sf.sf_setflags & MD_SET_MN_START_RC)? 1: 0;

			/*
			 * We can now reset the start_step flag for the set
			 * if it was already set.
			 */
			if (start_step) {
				(void) memset(&sf, 0, sizeof (sf));
					sf.sf_setno = sp->setno;
				sf.sf_setflags = MD_SET_MN_START_RC;
				sf.sf_flags = MDDB_NM_RESET;
				/*
				 * Use magic to help protect ioctl
				 * against attack.
				 */
				sf.sf_magic = MDDB_SETFLAGS_MAGIC;
				if (metaioctl(MD_MN_SET_SETFLAGS, &sf,
				    &sf.sf_mde, NULL)) {
					mdstealerror(ep, &sf.sf_mde);
					mde_perror(ep,
					    gettext("Could not reset "
					    "start_step flag for set %s"),
					    sp->setname);
				}
			}

			meta_mc_log(MC_LOG3, gettext("Step4 - begin setting "
			    "ABR state and restarting io's for "
			    "set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));


			/*
			 * If we are not the master and we have come through
			 * the start step, we must update the ABR states
			 * for mirrors and soft partitions. Also the submirror
			 * states need to be synchronised so that we see the
			 * same status as other previously joined members.
			 * This _must_ be done before starting the resync.
			 */
			if (!(sd->sd_mn_am_i_master) && start_step) {
				if (reset_state(GET_MIRROR_STATE, sp, MD_MIRROR,
				    ep) == -1) {
					md_exit(local_sp, 1);
				}
				if (reset_state(UPDATE_ABR, sp, MD_SP,
				    ep) == -1) {
					md_exit(local_sp, 1);
				}
				/*
				 * Mark the fact that we've got the mirror
				 * state. This allows the resync thread to
				 * determine if _it_ needs to issue this. This
				 * can happen if a node is added to a set after
				 * a reconfig cycle has completed.
				 */
				(void) memset(&sf, 0, sizeof (sf));
					sf.sf_setno = sp->setno;
				sf.sf_setflags = MD_SET_MN_MIR_STATE_RC;
				sf.sf_flags = MDDB_NM_SET;
				/*
				 * Use magic to help protect ioctl
				 * against attack.
				 */
				sf.sf_magic = MDDB_SETFLAGS_MAGIC;
				if (metaioctl(MD_MN_SET_SETFLAGS, &sf,
				    &sf.sf_mde, NULL)) {
					mdstealerror(ep, &sf.sf_mde);
					mde_perror(ep,
					    gettext("Could not set "
					    "submirror state flag for set %s"),
					    sp->setname);
				}
			}

			/*
			 * All remaining actions are only performed by the
			 * master
			 */
			if (!(sd->sd_mn_am_i_master)) {
				if (meta_lock(sp, TRUE, ep) != 0) {
					mde_perror(ep, "");
					md_exit(local_sp, 1);
				}
				meta_mirror_resync_unblock(sp);
				meta_unlock(sp, ep);
				continue;
			}

			/*
			 * If the master came through the start step, this
			 * implies that all of the nodes must have done the
			 * same and hence there can be no applications
			 * running. Hence no need to reset ABR
			 */
			if (!start_step) {
				/* Reset ABR state for mirrors */
				if (reset_state(RESET_ABR, sp, MD_MIRROR,
				    ep) == -1) {
					md_exit(local_sp, 1);
				}
				/* ...and now the same for soft partitions */
				if (reset_state(RESET_ABR, sp, MD_SP,
				    ep) == -1) {
					md_exit(local_sp, 1);
				}
			}

			/*
			 * choose owners for orphaned resyncs and reset
			 * non-orphaned resyncs so that an owner node that
			 * reboots will restart the resync if needed.
			 */
			if (reset_state(CHOOSE_OWNER, sp, MD_MIRROR, ep) == -1)
				md_exit(local_sp, 1);

			/*
			 * Must unlock set lock before meta_mirror_resync_all
			 * sends a message to run the metasync command
			 * which also grabs the meta_lock.
			 */
			if (meta_lock(sp, TRUE, ep) != 0) {
				mde_perror(ep, "");
				md_exit(local_sp, 1);
			}
			meta_mirror_resync_unblock(sp);
			meta_unlock(sp, ep);

			/* resync all mirrors in set */
			if (meta_mirror_resync_all(sp, 0, ep) != 0) {
				mde_perror(ep, gettext("Mirror resyncs "
				    "failed for set %s"), sp->setname);
				md_exit(local_sp, 1);
			}

			meta_mc_log(MC_LOG3, gettext("Step4 - io's restarted "
			    "for set %s: %s"), sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));
		}

		meta_mc_log(MC_LOG2, gettext("Step4 completed: %s"),
		    meta_print_hrtime(gethrtime() - start_time));

		break;

	default:
		usage(sp, 1);
		break;
	}

	md_exit(sp, 0);
	/* NOTREACHED */
	return (0);
}
