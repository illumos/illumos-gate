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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioccom.h>
#include <sys/corectl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <wait.h>
#include <signal.h>
#include <atomic.h>
#include <libscf.h>
#include <limits.h>
#include <priv_utils.h>
#include <door.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <libscf.h>
#include <zone.h>
#include <libgen.h>
#include <pwd.h>
#include <grp.h>

#include <smbsrv/smb_door.h>
#include <smbsrv/smb_ioctl.h>
#include <smbsrv/string.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include "smbd.h"

#define	SECSPERMIN			60
#define	SMBD_ONLINE_WAIT_INTERVAL	10
#define	SMBD_REFRESH_INTERVAL		10
#define	SMB_DBDIR "/var/smb"

static int smbd_daemonize_init(void);
static void smbd_daemonize_fini(int, int);
static int smb_init_daemon_priv(int, uid_t, gid_t);

static int smbd_kernel_bind(void);
static void smbd_kernel_unbind(void);
static int smbd_already_running(void);

static int smbd_service_init(void);
static void smbd_service_fini(void);

static int smbd_setup_options(int argc, char *argv[]);
static void smbd_usage(FILE *fp);

static int32_t smbd_gmtoff(void);
static void smbd_localtime_init(void);
static void *smbd_localtime_monitor(void *arg);

static void smbd_dyndns_init(void);
static void smbd_load_shares(void);
static void *smbd_share_loader(void *);

static void smbd_refresh_handler(void);

static int smbd_kernel_start(void);

smbd_t smbd;

/*
 * Use SMF error codes only on return or exit.
 */
int
main(int argc, char *argv[])
{
	sigset_t		set;
	uid_t			uid;
	int			pfd = -1;
	int			sigval;
	struct rlimit		rl;
	int			orig_limit;

#ifdef	FKSMBD
	fksmbd_init();
#endif
	smbd.s_pname = basename(argv[0]);
	openlog(smbd.s_pname, LOG_PID | LOG_NOWAIT, LOG_DAEMON);

	if (smbd_setup_options(argc, argv) != 0)
		return (SMF_EXIT_ERR_FATAL);

	if ((uid = getuid()) != smbd.s_uid) {
#ifdef	FKSMBD
		/* Can't manipulate privileges in daemonize. */
		if (smbd.s_fg == 0) {
			smbd.s_fg = 1;
			smbd_report("user %d (forced -f)", uid);
		}
#else	/* FKSMBD */
		smbd_report("user %d: %s", uid, strerror(EPERM));
		return (SMF_EXIT_ERR_FATAL);
#endif	/* FKSMBD */
	}

	if (is_system_labeled()) {
		smbd_report("Trusted Extensions not supported");
		return (SMF_EXIT_ERR_FATAL);
	}

	if (smbd_already_running())
		return (SMF_EXIT_OK);

	/*
	 * Raise the file descriptor limit to accommodate simultaneous user
	 * authentications/file access.
	 */
	if ((getrlimit(RLIMIT_NOFILE, &rl) == 0) &&
	    (rl.rlim_cur < rl.rlim_max)) {
		orig_limit = rl.rlim_cur;
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			smbd_report("Failed to raise file descriptor limit"
			    " from %d to %d", orig_limit, rl.rlim_cur);
	}

	/*
	 * Block async signals in all threads.
	 */
	(void) sigemptyset(&set);

	(void) sigaddset(&set, SIGHUP);
	(void) sigaddset(&set, SIGINT);
	(void) sigaddset(&set, SIGQUIT);
	(void) sigaddset(&set, SIGPIPE);
	(void) sigaddset(&set, SIGTERM);
	(void) sigaddset(&set, SIGUSR1);
	(void) sigaddset(&set, SIGUSR2);

	(void) sigprocmask(SIG_SETMASK, &set, NULL);

	if (smbd.s_fg) {
		if (smbd_service_init() != 0) {
			smbd_report("service initialization failed");
			exit(SMF_EXIT_ERR_FATAL);
		}
	} else {
		/*
		 * "pfd" is a pipe descriptor -- any fatal errors
		 * during subsequent initialization of the child
		 * process should be written to this pipe and the
		 * parent will report this error as the exit status.
		 */
		pfd = smbd_daemonize_init();

		if (smbd_service_init() != 0) {
			smbd_report("daemon initialization failed");
			exit(SMF_EXIT_ERR_FATAL);
		}

		smbd_daemonize_fini(pfd, SMF_EXIT_OK);
	}

	while (!smbd.s_shutting_down) {
		sigval = sigwait(&set);

		switch (sigval) {
		case -1:
			syslog(LOG_DEBUG, "sigwait failed: %s",
			    strerror(errno));
			break;
		case SIGPIPE:
			break;

		case SIGHUP:
			syslog(LOG_DEBUG, "refresh requested");
			smbd_refresh_handler();
			break;

		case SIGUSR1:
			syslog(LOG_DEBUG, "SIGUSR1 ignored");
			break;

		default:
			/*
			 * Typically SIGINT or SIGTERM.
			 */
			smbd.s_shutting_down = B_TRUE;
			break;
		}
	}

	/*
	 * Allow termination signals while shutting down.
	 */
	(void) sigemptyset(&set);

	if (smbd.s_fg) {
		(void) sigaddset(&set, SIGHUP);
		(void) sigaddset(&set, SIGINT);
	}
	(void) sigaddset(&set, SIGTERM);

	(void) sigprocmask(SIG_UNBLOCK, &set, NULL);

	smbd_service_fini();
	return ((smbd.s_fatal_error) ? SMF_EXIT_ERR_FATAL : SMF_EXIT_OK);
}

/*
 * This function will fork off a child process,
 * from which only the child will return.
 *
 * Use SMF error codes only on exit.
 */
static int
smbd_daemonize_init(void)
{
	int status, pfds[2];
	sigset_t set, oset;
	pid_t pid;
	int rc;

	/*
	 * Reset privileges to the minimum set required. We continue
	 * to run as root to create and access files in /var.
	 */
	rc = smb_init_daemon_priv(PU_RESETGROUPS, smbd.s_uid, smbd.s_gid);

	if (rc != 0) {
		smbd_report("insufficient privileges");
		exit(SMF_EXIT_ERR_FATAL);
	}

	/*
	 * Block all signals prior to the fork and leave them blocked in the
	 * parent so we don't get in a situation where the parent gets SIGINT
	 * and returns non-zero exit status and the child is actually running.
	 * In the child, restore the signal mask once we've done our setsid().
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);

	if (pipe(pfds) == -1) {
		smbd_report("unable to create pipe");
		exit(SMF_EXIT_ERR_FATAL);
	}

	closelog();

	if ((pid = fork()) == -1) {
		openlog(smbd.s_pname, LOG_PID | LOG_NOWAIT, LOG_DAEMON);
		smbd_report("unable to fork");
		closelog();
		exit(SMF_EXIT_ERR_FATAL);
	}

	/*
	 * If we're the parent process, wait for either the child to send us
	 * the appropriate exit status over the pipe or for the read to fail
	 * (presumably with 0 for EOF if our child terminated abnormally).
	 * If the read fails, exit with either the child's exit status if it
	 * exited or with SMF_EXIT_ERR_FATAL if it died from a fatal signal.
	 */
	if (pid != 0) {
		(void) close(pfds[1]);

		if (read(pfds[0], &status, sizeof (status)) == sizeof (status))
			_exit(status);

		if (waitpid(pid, &status, 0) == pid && WIFEXITED(status))
			_exit(WEXITSTATUS(status));

		_exit(SMF_EXIT_ERR_FATAL);
	}

	openlog(smbd.s_pname, LOG_PID | LOG_NOWAIT, LOG_DAEMON);
	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) chdir("/");
	(void) umask(022);
	(void) close(pfds[0]);

	return (pfds[1]);
}

/*
 * This function is based on __init_daemon_priv() and replaces
 * __init_daemon_priv() since we want smbd to have all privileges so that it
 * can execute map/unmap commands with all privileges during share
 * connection/disconnection.  Unused privileges are disabled until command
 * execution.  The permitted and the limit set contains all privileges.  The
 * inheritable set contains no privileges.
 */

static const char root_cp[] = "/core.%f.%t";
static const char daemon_cp[] = "/var/tmp/core.%f.%t";

static int
smb_init_daemon_priv(int flags, uid_t uid, gid_t gid)
{
	priv_set_t *perm = NULL;
	int ret = -1;
	char buf[1024];

	/*
	 * This is not a significant failure: it allows us to start programs
	 * with sufficient privileges and with the proper uid.   We don't
	 * care enough about the extra groups in that case.
	 */
	if (flags & PU_RESETGROUPS)
		(void) setgroups(0, NULL);

	if (gid != (gid_t)-1 && setgid(gid) != 0)
		goto end;

	perm = priv_allocset();
	if (perm == NULL)
		goto end;

	/* E = P */
	(void) getppriv(PRIV_PERMITTED, perm);
	(void) setppriv(PRIV_SET, PRIV_EFFECTIVE, perm);

	/* Now reset suid and euid */
	if (uid != (uid_t)-1 && setreuid(uid, uid) != 0)
		goto end;

	/* I = 0 */
	priv_emptyset(perm);
	ret = setppriv(PRIV_SET, PRIV_INHERITABLE, perm);
end:
	priv_freeset(perm);

	if (core_get_process_path(buf, sizeof (buf), getpid()) == 0 &&
	    strcmp(buf, "core") == 0) {

		if ((uid == (uid_t)-1 ? geteuid() : uid) == 0) {
			(void) core_set_process_path(root_cp, sizeof (root_cp),
			    getpid());
		} else {
			(void) core_set_process_path(daemon_cp,
			    sizeof (daemon_cp), getpid());
		}
	}
	(void) setpflags(__PROC_PROTECT, 0);

	return (ret);
}

/*
 * Most privileges, except the ones that are required for smbd, are turn off
 * in the effective set.  They will be turn on when needed for command
 * execution during share connection/disconnection.
 */
static void
smbd_daemonize_fini(int fd, int exit_status)
{
	priv_set_t *pset;

	/*
	 * Now that we're running, if a pipe fd was specified, write an exit
	 * status to it to indicate that our parent process can safely detach.
	 * Then proceed to loading the remaining non-built-in modules.
	 */
	if (fd >= 0)
		(void) write(fd, &exit_status, sizeof (exit_status));

	(void) close(fd);

	pset = priv_allocset();
	if (pset == NULL)
		return;

	priv_basicset(pset);

	/* list of privileges for smbd */
	(void) priv_addset(pset, PRIV_NET_MAC_AWARE);
	(void) priv_addset(pset, PRIV_NET_PRIVADDR);
	(void) priv_addset(pset, PRIV_PROC_AUDIT);
	(void) priv_addset(pset, PRIV_SYS_DEVICES);
	(void) priv_addset(pset, PRIV_SYS_SMB);
	(void) priv_addset(pset, PRIV_SYS_MOUNT);

	priv_inverse(pset);

	/* turn off unneeded privileges */
	(void) setppriv(PRIV_OFF, PRIV_EFFECTIVE, pset);

	priv_freeset(pset);

	/* reenable core dumps */
	__fini_daemon_priv(NULL);
}

/*
 * smbd_service_init
 */
static int
smbd_service_init(void)
{
	static struct dir {
		char	*name;
		int	perm;
	} dir[] = {
		{ SMB_DBDIR,	0700 },
		{ SMB_CVOL,	0755 },
		{ SMB_SYSROOT,	0755 },
		{ SMB_SYSTEM32,	0755 },
		{ SMB_VSS,	0755 },
		{ SMB_PIPE_DIR,	0755 },
		{ "/var/smb/lipc", 0755 },
	};
	int	rc, i;

	smbd.s_pid = getpid();

	/*
	 * Stop for a debugger attach here, which is after the
	 * fork() etc. in smb_daemonize_init()
	 */
	if (smbd.s_dbg_stop) {
		smbd_report("pid %d stop for debugger attach", smbd.s_pid);
		(void) kill(smbd.s_pid, SIGSTOP);
	}
	smbd_report("smbd starting, pid %d", smbd.s_pid);

	for (i = 0; i < sizeof (dir)/sizeof (dir[0]); ++i) {
		if ((mkdir(dir[i].name, dir[i].perm) < 0) &&
		    (errno != EEXIST)) {
			smbd_report("mkdir %s: %s", dir[i].name,
			    strerror(errno));
			return (-1);
		}
	}

	/*
	 * This environment variable tells mech_krb5 to give us
	 * MS-compatible behavior.
	 */
	(void) putenv("MS_INTEROP=1");

	if ((rc = smb_ccache_init(SMB_VARRUN_DIR, SMB_CCACHE_FILE)) != 0) {
		if (rc == -1)
			smbd_report("mkdir %s: %s", SMB_VARRUN_DIR,
			    strerror(errno));
		else
			smbd_report("unable to set KRB5CCNAME");
		return (-1);
	}

	smb_codepage_init();

	rc = smbd_cups_init();
	if (smb_config_getbool(SMB_CI_PRINT_ENABLE))
		smbd_report("print service %savailable", (rc == 0) ? "" : "un");

	if (smbd_nicmon_start(SMBD_DEFAULT_INSTANCE_FMRI) != 0)
		smbd_report("NIC monitor failed to start");

	smbd_dyndns_init();
	smb_ipc_init();

	if (smb_config_getbool(SMB_CI_NETBIOS_ENABLE) == 0)
		smbd_report("NetBIOS services disabled");
	else if (smb_netbios_start() != 0)
		smbd_report("NetBIOS services failed to start");
	else
		smbd_report("NetBIOS services started");

	smbd.s_secmode = smb_config_get_secmode();
	if ((rc = smb_domain_init(smbd.s_secmode)) != 0) {
		if (rc == SMB_DOMAIN_NOMACHINE_SID) {
			smbd_report(
			    "no machine SID: check idmap configuration");
			return (-1);
		}
	}

	if (smbd_dc_monitor_init() != 0)
		smbd_report("DC monitor initialization failed %s",
		    strerror(errno));

	if (smbd_pipesvc_start() != 0) {
		smbd_report("pipesvc initialization failed");
		return (-1);
	}

	if (smbd_authsvc_start() != 0) {
		smbd_report("authsvc initialization failed");
		return (-1);
	}

	smbd.s_door_srv = smbd_door_start();
	if (smbd.s_door_srv < 0) {
		smbd_report("door initialization failed %s", strerror(errno));
		return (-1);
	}

	dyndns_update_zones();
	smbd_localtime_init();
	(void) smb_lgrp_start();
	smb_pwd_init(B_TRUE);

	if (smb_shr_start() != 0) {
		smbd_report("share initialization failed: %s", strerror(errno));
		return (-1);
	}

	smbd.s_door_lmshr = smbd_share_start();
	if (smbd.s_door_lmshr < 0)
		smbd_report("share initialization failed");

	/* Open the driver, load the kernel config. */
	if (smbd_kernel_bind() != 0) {
		return (-1);
	}

	smbd_load_shares();
	smbd_load_printers();
	smbd_spool_start();

	smbd.s_initialized = B_TRUE;
	smbd_report("service initialized");

	return (0);
}

/*
 * Shutdown smbd and smbsrv kernel services.
 *
 * Called only by the main thread.
 */
static void
smbd_service_fini(void)
{

	smbd.s_shutting_down = B_TRUE;
	smbd_report("service shutting down");

	smb_kmod_stop();
	smb_logon_abort();
	smb_lgrp_stop();
	smbd_pipesvc_stop();
	smbd_door_stop();
	smbd_authsvc_stop();
	smbd_spool_stop();
	smbd_kernel_unbind();
	smbd_share_stop();
	smb_shr_stop();
	dyndns_stop();
	smbd_nicmon_stop();
	smb_ccache_remove(SMB_CCACHE_PATH);
	smb_pwd_fini();
	smb_domain_fini();
	mlsvc_fini();
	smb_netbios_stop();
	smbd_cups_fini();

	smbd.s_initialized = B_FALSE;
	smbd_report("service terminated");
	closelog();
}

/*
 * Called when SMF sends us a SIGHUP.  Update the smbd configuration
 * from SMF and check for changes that require service reconfiguration.
 */
static void
smbd_refresh_handler()
{
	int new_debug;

	if (smbd.s_shutting_down)
		return;

	smbd.s_refreshes++;

	new_debug = smb_config_get_debug();
	if (smbd.s_debug || new_debug)
		smbd_report("debug=%d", new_debug);
	smbd.s_debug = new_debug;

	smbd_spool_stop();
	smbd_dc_monitor_refresh();
	smb_ccache_remove(SMB_CCACHE_PATH);

	/*
	 * Clear the DNS zones for the existing interfaces
	 * before updating the NIC interface list.
	 */
	dyndns_clear_zones();

	if (smbd_nicmon_refresh() != 0)
		smbd_report("NIC monitor refresh failed");

	smb_netbios_name_reconfig();
	smb_browser_reconfig();
	dyndns_update_zones();

	/* This reloads the in-kernel config. */
	(void) smbd_kernel_bind();

	smbd_load_shares();
	smbd_load_printers();
	smbd_spool_start();
}

void
smbd_set_secmode(int secmode)
{
	switch (secmode) {
	case SMB_SECMODE_WORKGRP:
	case SMB_SECMODE_DOMAIN:
		(void) smb_config_set_secmode(secmode);
		smbd.s_secmode = secmode;
		break;

	default:
		syslog(LOG_ERR, "invalid security mode: %d", secmode);
		syslog(LOG_ERR, "entering maintenance mode");
		(void) smb_smf_maintenance_mode();
	}
}

/*
 * The service is online if initialization is complete and shutdown
 * has not begun.
 */
boolean_t
smbd_online(void)
{
	return (smbd.s_initialized && !smbd.s_shutting_down);
}

/*
 * Wait until the service is online.  Provided for threads that
 * should wait until the service has been fully initialized before
 * they start performing operations.
 */
void
smbd_online_wait(const char *text)
{
	while (!smbd_online())
		(void) sleep(SMBD_ONLINE_WAIT_INTERVAL);

	if (text != NULL) {
		syslog(LOG_DEBUG, "%s: online", text);
		(void) fprintf(stderr, "%s: online\n", text);
	}
}

/*
 * If the door has already been opened by another process (non-zero pid
 * in target), we assume that another smbd is already running.  If there
 * is a race here, it will be caught later when smbsrv is opened because
 * only one process is allowed to open the device at a time.
 */
static int
smbd_already_running(void)
{
	door_info_t	info;
	char 		*door_name;
	int		door;

	door_name = getenv("SMBD_DOOR_NAME");
	if (door_name == NULL)
		door_name = SMBD_DOOR_NAME;

	if ((door = open(door_name, O_RDONLY)) < 0)
		return (0);

	if (door_info(door, &info) < 0)
		return (0);

	if (info.di_target > 0) {
		smbd_report("already running: pid %ld\n", info.di_target);
		(void) close(door);
		return (1);
	}

	(void) close(door);
	return (0);
}

/*
 * smbd_kernel_bind
 *
 * If smbsrv is already bound, reload the configuration and update smbsrv.
 * Otherwise, open the smbsrv device and start the kernel service.
 */
static int
smbd_kernel_bind(void)
{
	smb_kmod_cfg_t	cfg;
	int		rc;

	if (smbd.s_kbound) {
		smb_load_kconfig(&cfg);
		smbd_get_authconf(&cfg);
		rc = smb_kmod_setcfg(&cfg);
		if (rc < 0)
			smbd_report("kernel configuration update failed: %s",
			    strerror(rc));
		return (rc);
	}

	if (smb_kmod_isbound())
		smbd_kernel_unbind();

	if ((rc = smb_kmod_bind()) == 0) {
		rc = smbd_kernel_start();
		if (rc != 0)
			smb_kmod_unbind();
		else
			smbd.s_kbound = B_TRUE;
	} else {
		smbd_report("kernel bind error: %s", strerror(rc));
	}

	return (rc);
}

static int
smbd_kernel_start(void)
{
	smb_kmod_cfg_t	cfg;
	int		rc;

	smb_load_kconfig(&cfg);
	smbd_get_authconf(&cfg);
	rc = smb_kmod_setcfg(&cfg);
	if (rc != 0) {
		smbd_report("kernel config ioctl error: %s", strerror(rc));
		return (rc);
	}

	rc = smb_kmod_setgmtoff(smbd_gmtoff());
	if (rc != 0) {
		smbd_report("kernel gmtoff ioctl error: %s", strerror(rc));
		return (rc);
	}

	rc = smb_kmod_start(smbd.s_door_opipe, smbd.s_door_lmshr,
	    smbd.s_door_srv);

	if (rc != 0) {
		smbd_report("kernel start ioctl error: %s", strerror(rc));
		return (rc);
	}

	return (0);
}

/*
 * smbd_kernel_unbind
 */
static void
smbd_kernel_unbind(void)
{
	smb_kmod_unbind();
	smbd.s_kbound = B_FALSE;
}

/*
 * Create the Dynamic DNS publisher thread.
 */
static void
smbd_dyndns_init(void)
{
	pthread_t	tid;
	pthread_attr_t	attr;
	int		rc;

	dyndns_start();

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, dyndns_publisher, NULL);
	(void) pthread_attr_destroy(&attr);

	if (rc != 0)
		smbd_report("unable to start dyndns publisher: %s",
		    strerror(errno));
}

/*
 * Launches a thread to populate the share cache by share information
 * stored in sharemgr
 */
static void
smbd_load_shares(void)
{
	pthread_t	tid;
	pthread_attr_t	attr;
	int		rc;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, smbd_share_loader, NULL);
	(void) pthread_attr_destroy(&attr);

	if (rc != 0)
		smbd_report("unable to load disk shares: %s", strerror(errno));
}

static void *
smbd_share_loader(void *args)
{
	(void) smb_shr_load(args);
	return (NULL);
}

/*
 * Initialization of the localtime thread.
 * Returns 0 on success, an error number if thread creation fails.
 */

static void
smbd_localtime_init(void)
{
	pthread_attr_t	attr;
	int		rc;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&smbd.s_localtime_tid, &attr,
	    smbd_localtime_monitor, NULL);
	(void) pthread_attr_destroy(&attr);

	if (rc != 0)
		smbd_report("unable to monitor localtime: %s", strerror(errno));
}

/*
 * Send local gmtoff to the kernel module one time at startup and each
 * time it changes (up to twice a year).
 * Local gmtoff is checked once every 15 minutes since some timezones
 * are aligned on half and quarter hour boundaries.
 */
/*ARGSUSED*/
static void *
smbd_localtime_monitor(void *arg)
{
	struct tm local_tm;
	time_t secs;
	int32_t gmtoff, last_gmtoff = -1;
	int timeout;
	int error;

	smbd_online_wait("smbd_localtime_monitor");

	for (;;) {
		gmtoff = smbd_gmtoff();

		if ((last_gmtoff != gmtoff) && smbd.s_kbound) {
			error = smb_kmod_setgmtoff(gmtoff);
			if (error != 0)
				smbd_report("localtime set failed: %s",
				    strerror(error));
		}

		/*
		 * Align the next iteration on a fifteen minute boundary.
		 */
		secs = time(0);
		(void) localtime_r(&secs, &local_tm);
		timeout = ((15 - (local_tm.tm_min % 15)) * SECSPERMIN);
		(void) sleep(timeout);

		last_gmtoff = gmtoff;
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * smbd_gmtoff
 *
 * Determine offset from GMT. If daylight saving time use altzone,
 * otherwise use timezone.
 */
static int32_t
smbd_gmtoff(void)
{
	time_t clock_val;
	struct tm *atm;
	int32_t gmtoff;

	(void) time(&clock_val);
	atm = localtime(&clock_val);

	gmtoff = (atm->tm_isdst) ? altzone : timezone;

	return (gmtoff);
}

/*
 * Set up configuration options and parse the command line.
 * This function will determine if we will run as a daemon
 * or in the foreground.
 *
 * Failure to find a uid or gid results in using the default (0).
 */
static int
smbd_setup_options(int argc, char *argv[])
{
	struct passwd *pwd;
	struct group *grp;
	int c;

	if ((pwd = getpwnam("root")) != NULL)
		smbd.s_uid = pwd->pw_uid;

	if ((grp = getgrnam("sys")) != NULL)
		smbd.s_gid = grp->gr_gid;

	smbd.s_debug = smb_config_get_debug();
	smbd.s_fg = smb_config_get_fg_flag();

	while ((c = getopt(argc, argv, ":dfs")) != -1) {
		switch (c) {
		case 'd':
			smbd.s_debug++;
			break;
		case 'f':
			smbd.s_fg = 1;
			break;
		case 's':
			smbd.s_dbg_stop = 1;
			break;
		case ':':
		case '?':
		default:
			smbd_usage(stderr);
			return (-1);
		}
	}

	return (0);
}

static void
smbd_usage(FILE *fp)
{
	static char *help[] = {
		"-d  enable debug messages"
		"-f  run program in foreground"
	};

	int i;

	(void) fprintf(fp, "Usage: %s [-f]\n", smbd.s_pname);

	for (i = 0; i < sizeof (help)/sizeof (help[0]); ++i)
		(void) fprintf(fp, "    %s\n", help[i]);
}

void
smbd_report(const char *fmt, ...)
{
	char buf[128];
	va_list ap;

	if (fmt == NULL)
		return;

	va_start(ap, fmt);
	(void) vsnprintf(buf, 128, fmt, ap);
	va_end(ap);

	(void) fprintf(stderr, "smbd: %s\n", buf);
}

/*
 * Enable libumem debugging by default on DEBUG builds.
 */
#ifdef DEBUG
const char *
_umem_debug_init(void)
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
#endif
