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

#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <signal.h>
#include <fcntl.h>
#include <door.h>
#include <thread.h>
#include <priv_utils.h>
#include <locale.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <nfs/nfs4.h>
#include <nfs/nfsid_map.h>
#include <rpcsvc/daemon_utils.h>
#include <arpa/nameser.h>
#include <nfs/nfssys.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

extern struct group *_uncached_getgrgid_r(gid_t, struct group *, char *, int);
extern struct group *_uncached_getgrnam_r(const char *, struct group *,
    char *, int);
extern struct passwd *_uncached_getpwuid_r(uid_t, struct passwd *, char *, int);
extern struct passwd *_uncached_getpwnam_r(const char *, struct passwd *,
    char *, int);

/*
 * seconds to cache nfsmapid domain info
 */
#define	NFSCFG_DEFAULT_DOMAIN_TMOUT	(5 * 60)
#define	NFSMAPID_DOOR   "/var/run/nfsmapid_door"

extern void	nfsmapid_func(void *, char *, size_t, door_desc_t *, uint_t);

extern void	check_domain(int);
extern void	idmap_kcall(int);
extern void	open_diag_file(void);

size_t		pwd_buflen = 0;
size_t		grp_buflen = 0;
thread_t	sig_thread;
static char	*MyName;

/*
 * nfscfg_domain_tmout is used by nfsv4-test scripts to query
 * the nfsmapid daemon for the proper timeout. Don't delete !
 */
time_t		 nfscfg_domain_tmout = NFSCFG_DEFAULT_DOMAIN_TMOUT;

/*
 * Processing for daemonization
 */
static void
daemonize(void)
{
	switch (fork()) {
		case -1:
			perror("nfsmapid: can't fork");
			exit(2);
			/* NOTREACHED */
		case 0:		/* child */
			break;

		default:	/* parent */
			_exit(0);
	}

	if (chdir("/") < 0)
		syslog(LOG_ERR, gettext("chdir /: %m"));

	/*
	 * Close stdin, stdout, and stderr.
	 * Open again to redirect input+output
	 */
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();
}

/* ARGSUSED */
static void *
sig_handler(void *arg)
{
	siginfo_t	si;
	sigset_t	sigset;
	struct timespec	tmout;
	int		ret;

	tmout.tv_nsec = 0;
	(void) sigemptyset(&sigset);
	(void) sigaddset(&sigset, SIGHUP);
	(void) sigaddset(&sigset, SIGTERM);
#ifdef	DEBUG
	(void) sigaddset(&sigset, SIGINT);
#endif

	/*CONSTCOND*/
	while (1) {
		tmout.tv_sec = nfscfg_domain_tmout;
		if ((ret = sigtimedwait(&sigset, &si, &tmout)) != 0) {
			/*
			 * EAGAIN: no signals arrived during timeout.
			 * check/update config files and continue.
			 */
			if (ret == -1 && errno == EAGAIN) {
				check_domain(0);
				continue;
			}

			switch (si.si_signo) {
				case SIGHUP:
					check_domain(1);
					break;
#ifdef DEBUG
				case SIGINT:
					exit(0);
#endif
				case SIGTERM:
				default:
					exit(si.si_signo);
			}
		}
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * Thread initialization. Mask out all signals we want our
 * signal handler to handle for us from any other threads.
 */
static void
thr_init(void)
{
	sigset_t sigset;
	long	 thr_flags = (THR_NEW_LWP|THR_DAEMON|THR_SUSPENDED);

	/*
	 * Before we kick off any other threads, mask out desired
	 * signals from main thread so that any subsequent threads
	 * don't receive said signals.
	 */
	(void) thr_sigsetmask(0, NULL, &sigset);
	(void) sigaddset(&sigset, SIGHUP);
	(void) sigaddset(&sigset, SIGTERM);
#ifdef	DEBUG
	(void) sigaddset(&sigset, SIGINT);
#endif
	(void) thr_sigsetmask(SIG_SETMASK, &sigset, NULL);

	/*
	 * Create the signal handler thread suspended ! We do things
	 * this way at setup time to minimize the probability of
	 * introducing any race conditions _if_ the process were to
	 * get a SIGHUP signal while creating a new DNS query thread
	 * in get_dns_txt_domain().
	 */
	if (thr_create(NULL, 0, sig_handler, 0, thr_flags, &sig_thread)) {
		syslog(LOG_ERR,
			gettext("Failed to create signal handling thread"));
		exit(4);
	}
}

static void
daemon_init(void)
{
	struct passwd pwd;
	struct group grp;
	char *pwd_buf;
	char *grp_buf;

	/*
	 * passwd/group reentrant interfaces limits
	 */
	pwd_buflen = (size_t)sysconf(_SC_GETPW_R_SIZE_MAX);
	grp_buflen = (size_t)sysconf(_SC_GETGR_R_SIZE_MAX);

	/*
	 * MT initialization is done first so that if there is the
	 * need to fire an additional thread to continue to query
	 * DNS, that thread is started off with the main thread's
	 * sigmask.
	 */
	thr_init();

	/*
	 * Determine nfsmapid domain.
	 */
	check_domain(0);

	/*
	 * In the case of nfsmapid running diskless, it is important
	 * to get the initial connections to the nameservices
	 * established to prevent problems like opening a devfs
	 * node to contact a nameservice being blocked by the
	 * resolution of an active devfs lookup.
	 * First issue a set*ent to "open" the databases and then
	 * get an entry and finally lookup a bogus entry to trigger
	 * any lazy opens.
	 */
	setpwent();
	setgrent();
	(void) getpwent();
	(void) getgrent();
	if ((pwd_buf = malloc(pwd_buflen)) == NULL)
		return;

	(void) _uncached_getpwnam_r("NF21dmvP", &pwd, pwd_buf, pwd_buflen);
	(void) _uncached_getpwuid_r(1181794, &pwd, pwd_buf, pwd_buflen);

	if ((grp_buf = realloc(pwd_buf, grp_buflen)) == NULL) {
		free(pwd_buf);
		return;
	}

	(void) _uncached_getgrnam_r("NF21dmvP", &grp, grp_buf, grp_buflen);
	(void) _uncached_getgrgid_r(1181794, &grp, grp_buf, grp_buflen);
	free(grp_buf);
}

static int
start_svcs(void)
{
	int doorfd = -1;
#ifdef DEBUG
	int dfd;
#endif

	if ((doorfd = door_create(nfsmapid_func, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		syslog(LOG_ERR, "Unable to create door: %m\n");
		return (1);
	}

#ifdef DEBUG
	/*
	 * Create a file system path for the door
	 */
	if ((dfd = open(NFSMAPID_DOOR, O_RDWR|O_CREAT|O_TRUNC,
				S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1) {
		syslog(LOG_ERR, "Unable to open %s: %m\n", NFSMAPID_DOOR);
		(void) close(doorfd);
		return (1);
	}

	/*
	 * Clean up any stale associations
	 */
	(void) fdetach(NFSMAPID_DOOR);

	/*
	 * Register in namespace to pass to the kernel to door_ki_open
	 */
	if (fattach(doorfd, NFSMAPID_DOOR) == -1) {
		syslog(LOG_ERR, "Unable to fattach door: %m\n");
		(void) close(dfd);
		(void) close(doorfd);
		return (1);
	}
	(void) close(dfd);
#endif

	/*
	 * Now that we're actually running, go
	 * ahead and flush the kernel flushes
	 * Pass door name to kernel for door_ki_open
	 */
	idmap_kcall(doorfd);

	/*
	 * Wait for incoming calls
	 */
	/*CONSTCOND*/
	while (1)
		(void) pause();

	syslog(LOG_ERR, gettext("Door server exited"));
	return (10);
}

/* ARGSUSED */
int
main(int argc, char **argv)
{
	MyName = argv[0];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* _check_services() framework setup */
	(void) _create_daemon_lock(NFSMAPID, DAEMON_UID, DAEMON_GID);

	/*
	 * Open diag file in /var/run while we've got the perms
	 */
	open_diag_file();

	/*
	 * Initialize the daemon to basic + sys_nfs
	 */
#ifndef	DEBUG
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID, PRIV_SYS_NFS, (char *)NULL) == -1) {
		(void) fprintf(stderr, gettext("%s PRIV_SYS_NFS privilege "
			"missing\n"), MyName);
		exit(1);
	}
#endif

	/*
	 * Take away a subset of basic, while this is not the absolute
	 * minimum, it is important that it is unique among other
	 * daemons to insure that we get a unique cred that will
	 * result in a unique open_owner.  If not, we run the risk
	 * of a diskless client deadlocking with a thread holding
	 * the open_owner seqid lock while upcalling the daemon.
	 * XXX This restriction will go away once we stop holding
	 * XXX open_owner lock across rfscalls!
	 */
	(void) priv_set(PRIV_OFF, PRIV_PERMITTED,
		PRIV_FILE_LINK_ANY, PRIV_PROC_SESSION,
		(char *)NULL);

#ifndef DEBUG
	daemonize();
	switch (_enter_daemon_lock(NFSMAPID)) {
		case 0:
			break;

		case -1:
			syslog(LOG_ERR, "error locking for %s: %s", NFSMAPID,
			    strerror(errno));
			exit(3);

		default:
			/* daemon was already running */
			exit(0);
	}
#endif
	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/* Initialize daemon subsystems */
	daemon_init();

	/* start services */
	return (start_svcs());
}
