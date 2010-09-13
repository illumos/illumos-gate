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
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * setup utility
 */

#include "meta_set_prv.h"
#include <sys/resource.h>
#include <syslog.h>


/* globals */
char		*myname = "";
FILE		*metalogfp = NULL;
int		metasyslog = 0;
uint_t		verbosity = 0;
hrtime_t	start_time = 0;
sigset_t	allsigs;

/* locals */
static	int	rb_signal_handling = FALSE;
static	int	rb_signal_caught = FALSE;
static	int	rb_signal_which = 0;
static	size_t	metansig = 0;
static	struct	sigaction	*metahandlers = NULL;
#ifdef	_DEBUG_MALLOC_INC
static	ulong_t	malloc_histid_begin;
static	ulong_t	malloc_histid_end;
static	ulong_t	malloc_inuse_begin;
static	ulong_t	malloc_inuse_end;
#endif	/* _DEBUG_MALLOC_INC */

/* forwards */
static	void	md_catcher(int sig);

/*
 * push/pop signal handlers
 */
static int
md_pushsig(
	unsigned	sig,
	void		(*handler)(int sig),
	md_error_t	*ep
)
{
	struct	sigaction	newhandler;

	/* expand vector as neccessary */
	if (sig >= metansig) {
		if (metahandlers == NULL) {
			metahandlers = Zalloc(
			    (sig + 1) * sizeof (metahandlers[0]));
		} else {
			metahandlers = Realloc(metahandlers,
			    ((sig + 1) * sizeof (metahandlers[0])));
			(void) memset(&metahandlers[metansig], 0,
			    ((sig - metansig) * sizeof (metahandlers[0])));
		}
		metansig = sig;
	}

	/* We need to have a seperate stack to handle rollback properly */
	newhandler.sa_flags = 0;
	if (sigfillset(&newhandler.sa_mask) < 0)
		return (mdsyserror(ep, errno,
		    "sigfillset(&newhandler.sa_mask)"));
	newhandler.sa_handler = handler;

	/* push handler */
	if (sigaction(sig, &newhandler, &metahandlers[sig]) < 0)
		return (mdsyserror(ep, errno, "sigaction(&newhandler)"));

	/* return success */
	return (0);
}

static int
md_popsig(
	unsigned	sig,
	md_error_t	*ep
)
{
	/* can't pop what isn't pushed */
	assert(sig <= metansig);
	assert(metahandlers[sig].sa_handler != md_catcher);

	/* pop handler */
	if (sigaction(sig, &metahandlers[sig], NULL) < 0)
		return (mdsyserror(ep, errno, "sigaction(&metahandlers)"));

	/* return success */
	return (0);
}

char *
meta_lock_name(
	set_t	setno
)
{
	char	lockname[30];

	if (setno == MD_LOCAL_SET)
		return (strdup(METALOCK));

	(void) snprintf(lockname, sizeof (lockname), "%s.%ld", METALOCK, setno);
	return (strdup(lockname));
}

#define	META_LOCK_FD(sp)	((sp)->lockfd)
#define	META_LOCK_NAME(sp)	(meta_lock_name((sp)->setno))

/*
 * open lock
 */
static int
meta_lock_open(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	int	lockfd = META_LOCK_FD(sp);
	char	*lockname = META_LOCK_NAME(sp);

	/* check for already open */
	if (lockfd >= 0)
		goto success;
	assert(lockfd == MD_NO_LOCK);

	/* open and/or create lock file */
	if ((lockfd = open(lockname, O_WRONLY, 0)) < 0) {
		if (errno == EROFS) {
			lockfd = MD_NO_LOCK;
			goto success;
		}
		if (errno != ENOENT) {
			(void) mdsyserror(ep, errno, lockname);
			goto failure;
		}
		if ((lockfd = open(lockname, (O_WRONLY|O_CREAT),
		    0644)) < 0) {
			(void) mdsyserror(ep, errno, lockname);
			goto failure;
		}
		if (fchmod(lockfd, 0644) != 0) {
			(void) mdsyserror(ep, errno, lockname);
			goto failure;
		}
	}

	/* return success */
success:
	if (lockname != NULL)
		free(lockname);
	META_LOCK_FD(sp) = lockfd;
	return (0);

	/* flag failure */
failure:
	if (lockname != NULL)
		free(lockname);
	if (lockfd >= 0)
		(void) close(lockfd);
	return (-1);
}

static int
meta_lock_close(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	int	retval = 0;

	if (close(META_LOCK_FD(sp)) != 0) {
		if (ep != NULL) {
			char	*lockname = META_LOCK_NAME(sp);
			(void) mdsyserror(ep, errno, lockname);
			if (lockname != NULL)
				free(lockname);
		}

		retval = -1;
	}
	META_LOCK_FD(sp) = MD_NO_LOCK;
	return (retval);
}

/*
 * unlock
 */
int
meta_unlock(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	int	lockfd = META_LOCK_FD(sp);

	/* ignore read-only filesystem */
	if (lockfd == MD_NO_LOCK)
		return (0);

	assert(lockfd >= 0);

	/* unlock and discard */
	if (lockf(lockfd, F_ULOCK, 0) != 0) {
		(void) mdsyserror(ep, errno, METALOCK);
		(void) meta_lock_close(sp, NULL);
		return (-1);
	}
	return (meta_lock_close(sp, ep));
}

/*
 * lock
 */
int
meta_lock(
	mdsetname_t	*sp,
	int		print_status,
	md_error_t	*ep
)
{
	int	lockfd;
	char	*lockname = NULL;

	/* open lock file */
	if (meta_lock_open(sp, ep) != 0) {
		assert(META_LOCK_FD(sp) == MD_NO_LOCK);
		goto failure;
	}

	/* ignore read-only filesystem */
	if ((lockfd = META_LOCK_FD(sp)) == MD_NO_LOCK)
		goto success;
	assert(lockfd >= 0);

	lockname = META_LOCK_NAME(sp);

	/* grab lock */
	if (lockf(lockfd, F_TLOCK, 0) != 0) {
		if ((errno != EACCES) && (errno != EAGAIN)) {
			(void) mdsyserror(ep, errno, lockname);
			goto failure;
		}
		if (print_status)
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: waiting on %s\n"),
			    myname, lockname);
		if (lockf(lockfd, F_LOCK, 0) != 0) {
			(void) mdsyserror(ep, errno, lockname);
			goto failure;
		}
	}

	/* return success */
success:
	if (lockname != NULL)
		free(lockname);
	return (0);

	/* flag failure */
failure:
	if (lockname != NULL)
		free(lockname);
	if (lockfd >= 0)
		(void) meta_lock_close(sp, ep);
	return (-1);
}

int
meta_lock_nowait(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	int	lockfd;
	char	*lockname = NULL;

	/* open lock file */
	if (meta_lock_open(sp, ep) != 0) {
		assert(META_LOCK_FD(sp) == MD_NO_LOCK);
		goto failure;
	}

	/* ignore read-only filesystem */
	if ((lockfd = META_LOCK_FD(sp)) == MD_NO_LOCK)
		goto success;
	assert(lockfd >= 0);

	lockname = META_LOCK_NAME(sp);

	/* grab lock */
	if (lockf(lockfd, F_TLOCK, 0) != 0) {
		if ((errno != EACCES) && (errno != EAGAIN)) {
			(void) mdsyserror(ep, errno, lockname);
			goto failure;
		}
		(void) mdsyserror(ep, EAGAIN, lockname);
		goto failure;
	}

	/* return success */
success:
	if (lockname != NULL)
		free(lockname);
	return (0);

	/* flag failure */
failure:
	if (lockname != NULL)
		free(lockname);
	if (lockfd >= 0)
		(void) meta_lock_close(sp, ep);
	return (-1);
}

/*
 * lock status
 */
int
meta_lock_status(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	int lockfd;

	/* open lock file */
	if (meta_lock_open(sp, ep) != 0) {
		assert(META_LOCK_FD(sp) == MD_NO_LOCK);
		return (-1);
	}

	lockfd = META_LOCK_FD(sp);
	/* ignore read-only filesystem */
	if (lockfd == MD_NO_LOCK)
		return (0);
	assert(lockfd >= 0);

	/* test lock */
	if (lockf(lockfd, F_TEST, 0) != 0) {
		char *lockname = META_LOCK_NAME(sp);
		(void) mdsyserror(ep, errno, lockname);
		if (lockname != NULL)
			free(lockname);
		return (-1);
	}

	return (0);
}

/*
 * setup for syslog daemon output
 */
static void
md_syslog(
	char	*name	/* name of program */
)
{
	if ((name == NULL) || (*name == '\0'))
		name = "md";
	openlog(name, LOG_CONS, LOG_DAEMON);
	metasyslog = 1;
}

/*
 * daemonize: put in background
 */
int
md_daemonize(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	char		*p;
	struct rlimit	rlim;
	pid_t		pid;
	int		i;

	/* debug */
	if (((p = getenv("MD_DEBUG")) != NULL) &&
	    (strstr(p, "NODAEMON") != NULL)) {
		return (0);	/* do nothing */
	}

	/* get number of file descriptors */
	if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
		return (mdsyserror(ep, errno, "getrlimit(RLIMIT_NOFILE)"));
	}

	/* fork and kill parent */
	if ((pid = fork()) == -1)
		return (mdsyserror(ep, errno, "fork"));
	else if (pid != 0)
		return (pid);

	/*
	 * We need to close the admin device and reset the specialfd to force
	 * the child process to reopen it, since we are going to close all
	 * descriptors from 3 up to RLIMIT_NOFILE in the child.
	 */
	if (close_admin(ep) != 0)
		return (-1);

	/* close RPC connections */
	metarpccloseall();

	/* drop lock */
	if (meta_unlock(sp, ep) != 0)
		return (-1);

	if (rlim.rlim_cur != RLIM_INFINITY) {
		/*
		 * close all but stdout, stderr, and metalogfp
		 */

		for (i = 0; (i < rlim.rlim_cur); ++i) {
			if ((i == fileno(stdout)) ||
			    (i == fileno(stderr)) ||
			    ((metalogfp != NULL) &&
			    (i == fileno(metalogfp)))) {
				continue;
			}
			(void) close(i);
		}
	}

	/* put in own process group */
	if (setsid() == -1)
		return (mdsyserror(ep, errno, "setsid"));

	/* setup syslog */
	md_syslog(myname);

	/* return success */
	return (0);
}

/*
 * flush and sync fp
 */
static void
flushfp(
	FILE	*fp
)
{
	(void) fflush(fp);
	(void) fsync(fileno(fp));
}

/*
 * reset and exit utility
 */
void
md_exit(
	mdsetname_t	*sp,
	int		eval
)
{
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;


	/* close RPC connections */
	metarpccloseall();

	if (sp != NULL) {
		if (meta_unlock(sp, ep) != 0) {
			mde_perror(ep, "");
			mdclrerror(ep);
			if (eval == 0)
				eval = 1;
		}
	}

	/* flush name caches */
#ifdef	DEBUG
	metaflushnames(1);
#endif	/* DEBUG */

	/* log exit */
	if (metalogfp != NULL) {
		md_logpfx(metalogfp);
		(void) fprintf(metalogfp, dgettext(TEXT_DOMAIN,
		    "exiting with %d\n"), eval);
		flushfp(metalogfp);
		(void) fclose(metalogfp);
		metalogfp = NULL;
	}
	if ((metasyslog) && (eval != 0)) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "exiting with %d\n"), eval);
		closelog();
		metasyslog = 0;
	}

	/* check arena, print malloc usage */
#ifdef	_DEBUG_MALLOC_INC
	(void) malloc_chain_check(1);
	{
		char	*p;

		if (((p = getenv("MD_DEBUG")) != NULL) &&
		    (strstr(p, "MALLOC") != NULL)) {
			malloc_inuse_end = malloc_inuse(&malloc_histid_end);
			(void) fprintf(stderr, "%s: end malloc_inuse %lu\n",
			    myname, malloc_inuse_end);
			if (malloc_inuse_end != malloc_inuse_begin) {
				malloc_list(fileno(stderr),
				    malloc_histid_begin, malloc_histid_end);
			}
		}
	}
#endif	/* _DEBUG_MALLOC_INC */

	/* exit with value */
	exit(eval);
}

/*
 * signal catcher
 */
static void
md_catcher(
	int			sig
)
{
	char			buf[128];
	char			*msg;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;
	struct sigaction	defhandler;

	/* log signal */
	if ((msg = strsignal(sig)) == NULL) {
		(void) snprintf(buf, sizeof (buf),
		    dgettext(TEXT_DOMAIN, "unknown signal %d"), sig);
		msg = buf;
	}
	md_eprintf("%s\n", msg);

	/*
	 * In roll_back crtical section handling, the first instance of a user
	 * generated signal is caught, a flag is set to allow preemption at a
	 * "convenient" point and md_catcher returns.  If the user continues
	 * generate the signal, the second instance will invoke the default
	 * handler and exit.
	 */
	if (rb_signal_handling == TRUE) {
		if (sig != SIGABRT && sig != SIGBUS && sig != SIGSEGV) {
			if (rb_signal_caught == FALSE) {
				rb_signal_caught = TRUE;
				rb_signal_which  = sig;
				return;
			}
		}
	}

	/* let default handler do it's thing */
	if (md_popsig(sig, ep) != 0) {
		mde_perror(ep, "");
		mdclrerror(ep);
		defhandler.sa_flags = 0;
		if (sigfillset(&defhandler.sa_mask) < 0) {
			(void) mdsyserror(ep, errno,
			    "sigfillset(&defhandler.sa_mask)");
			mde_perror(ep, "");
			md_exit(NULL, 1);
		}
		defhandler.sa_handler = SIG_DFL;
		if (sigaction(sig, &defhandler, NULL) < 0) {
			(void) mdsyserror(ep, errno, "sigaction(&defhandler)");
			mde_perror(ep, "");
			md_exit(NULL, 1);
		}
	}

	md_post_sig(sig);
}

void
md_post_sig(int sig)
{
	if (kill(getpid(), sig) != 0) {
		md_perror("kill(getpid())");
		md_exit(NULL, -sig);
	}
}

int
md_got_sig(void)
{
	return (rb_signal_caught);
}

int
md_which_sig(void)
{
	return (rb_signal_which);
}

void
md_rb_sig_handling_on(void)
{
	rb_signal_handling = TRUE;
}

void
md_rb_sig_handling_off(int sig_seen, int sig)
{
	rb_signal_handling = FALSE;
	rb_signal_caught = FALSE;
	rb_signal_which  = 0;
	if (sig_seen)
		md_post_sig(sig);
}

/*
 * setup metaclust variables
 */
void
setup_mc_log(
	uint_t	level
)
{
	/* initialise externals */
	verbosity = level;
	start_time = gethrtime();
}

/*
 * initilize utility
 */
int
md_init(
	int		argc,
	char		*argv[],
	int		dosyslog,
	int		doadmin,
	md_error_t	*ep
)
{
	int ret = 0;

	/* initialize everything but the signals */
	if ((ret = md_init_nosig(argc, argv, dosyslog,
			doadmin, ep)) != 0)
		return (ret);


	if (sigfillset(&allsigs) < 0)
		return (mdsyserror(ep, errno, "sigfillset(&allsigs)"));

	/* catch common signals */
	if ((md_pushsig(SIGHUP, md_catcher, ep) != 0) ||
	    (md_pushsig(SIGINT, md_catcher, ep) != 0) ||
	    (md_pushsig(SIGQUIT, md_catcher, ep) != 0) ||
	    (md_pushsig(SIGABRT, md_catcher, ep) != 0) ||
	    (md_pushsig(SIGBUS, md_catcher, ep) != 0) ||
	    (md_pushsig(SIGSEGV, md_catcher, ep) != 0) ||
	    (md_pushsig(SIGPIPE, md_catcher, ep) != 0) ||
	    (md_pushsig(SIGTERM, md_catcher, ep) != 0)) {
		return (-1);
	}

	/* return success */
	return (0);
}


/*
 * initilize utility without setting up sighandlers
 * setting up signal handlers in libmeta can affect others
 * programs that link with libmeta but have their own handlers
 */
int
md_init_nosig(
	int		argc,
	char		*argv[],
	int		dosyslog,
	int		doadmin,
	md_error_t	*ep
)
{
	/* setup myname */
	if ((myname = strrchr(argv[0], '/')) != NULL)
		++myname;
	else
		myname = argv[0];

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	/* print malloc usage */
#ifdef	_DEBUG_MALLOC_INC
	{
		char	*p;

		if (((p = getenv("MD_DEBUG")) != NULL) &&
		    (strstr(p, "MALLOC") != NULL)) {
			malloc_inuse_begin =
			    malloc_inuse(&malloc_histid_begin);
			(void) fprintf(stderr, "%s: begin malloc_inuse %lu\n",
			    myname, malloc_inuse_begin);
		}
	}
#endif	/* _DEBUG_MALLOC_INC */

	/* open syslog */
	if (dosyslog)
		md_syslog(myname);

	/* log command */
	if (getenv(METALOGENV) != NULL) {
		if ((metalogfp = fopen(METALOG, "a")) != NULL) {
			int	i;

			(void) fchmod(fileno(metalogfp), 0664);
			md_logpfx(metalogfp);
			for (i = 1; (i < argc); ++i)
				(void) fprintf(metalogfp, " %s", argv[i]);
			(void) fprintf(metalogfp, "\n");
			flushfp(metalogfp);
		}
	}

	/* make sure we can open the admin device before we do anything else */
	if (doadmin)
		if (open_admin(ep) < 0)
			return (-1);

	/* flush name caches */
	metaflushnames(1);

	/* return success */
	return (0);
}

/*
 * (re)initilize daemon
 */
int
md_init_daemon(
	char		*name,
	md_error_t	*ep
)
{
	static int	already = 0;
	int		dosyslog = 1;
	int		doadmin = 1;

	/* setup */
	if (! already) {
		if (md_init(1, &name, dosyslog, doadmin, ep) != 0)
			return (-1);
		already = 1;
	}

	/* return success */
	return (0);
}

/*
 * Roll back functions for handling sync and async cleanup.
 */

int
procsigs(int block, sigset_t *oldsigs, md_error_t *ep)
{
	if (block == TRUE) {
		if (sigprocmask(SIG_BLOCK, &allsigs, oldsigs) < 0) {
			(void) mdsyserror(ep, errno, "sigprocmask(SIG_BLOCK)");
			return (-1);
		}
	} else {
		if (sigprocmask(SIG_SETMASK, oldsigs, NULL) < 0) {
			(void) mdsyserror(ep, errno,
			    "sigprocmask(SIG_SETMASK)");
			return (-1);
		}
	}
	return (0);
}

#ifdef DEBUG
int
rb_test(
	int		rbt_sel_tpt,
	char		*rbt_sel_tag,
	md_error_t	*ep
)
{
	char		*rbt_env_tpt = getenv("META_RBT_TPT");
	char		*rbt_env_tag = getenv("META_RBT_TAG");
	int		sig = 0;
	int		rbt_int_tpt;
	int		rbt_tag_match = 1;
	sigset_t	curmask;
	md_error_t	xep = mdnullerror;

	if (rbt_env_tpt) {
		rbt_int_tpt = atoi(rbt_env_tpt);
		if (rbt_int_tpt < 0) {
			sig = 1;
			rbt_int_tpt = -1 * rbt_int_tpt;
		}

		assert(rbt_sel_tpt != 0);

		if (rbt_int_tpt == 0)
			return (0);

		if (rbt_env_tag && rbt_sel_tag)
			if (strcmp(rbt_env_tag, rbt_sel_tag) != 0)
				rbt_tag_match = 0;

		if (rbt_int_tpt == rbt_sel_tpt && rbt_tag_match) {
			md_eprintf(
			    "******************** RB_TEST(%s, %d, sig=%s)\n",
			    rbt_sel_tag, rbt_sel_tpt,
			    (sig != 0) ? "True" : "False");
			if (sig) {
				md_eprintf("********** sigsuspend()\n");
				if (sigprocmask(NULL, NULL, &curmask) < 0) {
					(void) mdsyserror(&xep, errno, NULL);
					mde_perror(&xep, "sigprocmask(GET)");
					md_exit(NULL, 1);
				}

				if (sigsuspend(&curmask) < 0) {
					(void) mdsyserror(&xep, errno, NULL);
					mde_perror(&xep,
					    "sigsuspend(&curmask)");
					md_exit(NULL, 1);
				}

				if (md_got_sig())
					return (-1);
			}
			(void) mderror(ep, MDE_TESTERROR,
			    "********** rb_test()");
			md_eprintf("******************** rollback\n");
			return (-1);
		}
	}
	return (0);
}
#else
/* ARGSUSED */
int
rb_test(
	int		rbt_sel_tpt,
	char		*rbt_sel_tag,
	md_error_t	*ep
)
{
	(void) mderror(ep, MDE_TESTERROR, "******** rb_test:Not supported\n");
	return (-1);

}
#endif	/* DEBUG */
