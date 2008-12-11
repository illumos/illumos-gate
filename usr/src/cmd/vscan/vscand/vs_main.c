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
 * vscand Daemon Program
 */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/filio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <zone.h>
#include <tsol/label.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <wait.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <libscf.h>
#include <signal.h>
#include <atomic.h>
#include <libintl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <syslog.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>
#include <priv_utils.h>
#include <rctl.h>
#include "vs_incl.h"

#define	VS_FILE_DESCRIPTORS	512

static int vscand_fg = 0; /* daemon by default */
static vs_daemon_state_t vscand_state = VS_STATE_INIT;
static volatile uint_t vscand_sigval = 0;
static volatile uint_t vscand_n_refresh = 0;
static int vscand_kdrv_fd = -1;
static pthread_mutex_t vscand_cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vscand_cfg_cv;
static pthread_t vscand_cfg_tid = 0;

/* virus log path */
static char vscand_vlog[MAXPATHLEN];

/* user and group ids - default to 0 */
static uid_t root_uid = 0, daemon_uid = 0;
static gid_t sys_gid = 0;


/* local function prototypes */
static void vscand_sig_handler(int);
static int vscand_parse_args(int, char **);
static void vscand_get_uid_gid();
static int vscand_init_file(char *, uid_t, gid_t, mode_t);
static void vscand_usage(char *);
static int vscand_daemonize_init(void);
static void vscand_daemonize_fini(int, int);
static int vscand_init(void);
static void vscand_fini(void);
static int vscand_cfg_init(void);
static void vscand_cfg_fini(void);
static void *vscand_cfg_handler(void *);
static int vscand_configure(void);
static void vscand_dtrace_cfg(vs_props_all_t *);
static int vscand_kernel_bind(void);
static void vscand_kernel_unbind(void);
static int vscand_kernel_enable(int);
static void vscand_kernel_disable(void);
static int vscand_kernel_config(vs_config_t *);
static int vscand_kernel_max_req(uint32_t *);
static void vscand_error(const char *);
static int vscand_get_viruslog(void);
static int vscand_set_resource_limits(void);


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


/*
 * vscand_sig_handler
 */
static void
vscand_sig_handler(int sig)
{
	if (vscand_sigval == 0)
		(void) atomic_swap_uint(&vscand_sigval, sig);

	if (sig == SIGHUP)
		atomic_inc_uint(&vscand_n_refresh);
}


/*
 * main
 *
 * main must return SMF return code (see smf_method (5)) if vscand
 * is invoked directly by smf (see manifest: vscan.xml)
 * Exit codes: SMF_EXIT_ERR_CONFIG - error
 *             SMF_EXIT_ERR_FATAL - fatal error
 *             SMF_EXIT_OK - success
 */
int
main(int argc, char **argv)
{
	int err_stat = 0, pfd = -1;
	sigset_t set;
	struct sigaction act;
	int sigval;

	mode_t log_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	mode_t door_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	(void) setlocale(LC_ALL, "");
	openlog("vscand", 0, LOG_DAEMON);

	/* check if running in global zone; other zones not supported */
	if (getzoneid() != GLOBAL_ZONEID) {
		vscand_error(gettext("non-global zone not supported"));
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* check for a Trusted Solaris environment; not supported */
	if (is_system_labeled()) {
		vscand_error(gettext("Trusted Extensions not supported"));
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* Parse arguments */
	if (vscand_parse_args(argc, argv) != 0)
		exit(SMF_EXIT_ERR_CONFIG);

	vscand_get_uid_gid();

	/*
	 * Initializetion of virus log and statistic door file
	 * MUST be done BEFORE vscand_daemonize_init resets uid/gid.
	 * Only root can create the files in /var/log and /var/run.
	 */
	if ((vscand_get_viruslog() != 0) ||
	    (vscand_vlog[0] == '\0') ||
	    (vscand_init_file(vscand_vlog, root_uid, sys_gid, log_mode) != 0)) {
		*vscand_vlog = 0;
	}

	(void) vscand_init_file(VS_STATS_DOOR_NAME,
	    daemon_uid, sys_gid, door_mode);

	/*
	 * Once we're done setting our global state up, set up signal handlers
	 * for ensuring orderly termination on SIGTERM.
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT); /* always unblocked for ASSERT() */

	(void) sigfillset(&act.sa_mask);
	act.sa_handler = vscand_sig_handler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL); /* Refresh config */
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGPIPE, &act, NULL);
	(void) sigdelset(&set, SIGTERM);
	(void) sigdelset(&set, SIGHUP);
	(void) sigdelset(&set, SIGINT);
	(void) sigdelset(&set, SIGPIPE);

	if (vscand_fg) {
		(void) sigdelset(&set, SIGTSTP);
		(void) sigdelset(&set, SIGTTIN);
		(void) sigdelset(&set, SIGTTOU);

		if (vscand_init() != 0) {
			vscand_error(gettext("failed to initialize service"));
			exit(SMF_EXIT_ERR_CONFIG);
		}
	} else {
		/*
		 * "pfd" is a pipe descriptor -- any fatal errors
		 * during subsequent initialization of the child
		 * process should be written to this pipe and the
		 * parent will report this error as the exit status.
		 */
		pfd = vscand_daemonize_init();

		if (vscand_init() != 0) {
			vscand_error(gettext("failed to initialize service"));
			exit(SMF_EXIT_ERR_CONFIG);
		}

		vscand_daemonize_fini(pfd, err_stat);
	}

	vscand_state = VS_STATE_RUNNING;

	/* Wait here until shutdown */
	while (vscand_state == VS_STATE_RUNNING) {
		if (vscand_sigval == 0 && vscand_n_refresh == 0)
			(void) sigsuspend(&set);

		sigval = atomic_swap_uint(&vscand_sigval, 0);

		switch (sigval) {
		case 0:
		case SIGPIPE:
		case SIGHUP:
			break;
		default:
			vscand_state = VS_STATE_SHUTDOWN;
			break;
		}

		if (atomic_swap_uint(&vscand_n_refresh, 0) != 0)
			(void) pthread_cond_signal(&vscand_cfg_cv);
	}

	vscand_fini();
	return (SMF_EXIT_OK);
}


/*
 * vscand_parse_args
 * Routine to parse the arguments to the daemon program
 * 'f' argument runs process in the foreground instead of as a daemon
 */
int
vscand_parse_args(int argc, char **argv)
{
	int	optchar;

	while ((optchar = getopt(argc, argv, "f?")) != EOF) {
		switch (optchar) {
		case 'f':
			vscand_fg = 1;
			break;
		default:
			vscand_usage(argv[0]);
			return (-1);
		}
	}
	return (0);
}


/*
 * vscand_usage
 */
static void
vscand_usage(char *progname)
{
	char buf[128];

	(void) snprintf(buf, sizeof (buf), "%s %s [-f]",
	    gettext("Usage"), progname);
	vscand_error(buf);

	(void) snprintf(buf, sizeof (buf), "\t-f %s\n",
	    gettext("run program in foreground"));
	vscand_error(buf);
}


/*
 * vscand_get_uid_gid
 *
 * failure to access a uid/gid results in the default (0) being used.
 */
static void
vscand_get_uid_gid()
{
	struct passwd *pwd;
	struct group *grp;

	if ((pwd = getpwnam("root")) != NULL)
		root_uid = pwd->pw_uid;

	if ((pwd = getpwnam("daemon")) != NULL)
		daemon_uid = pwd->pw_uid;

	if ((grp = getgrnam("sys")) != NULL)
		sys_gid = grp->gr_gid;
}


/*
 * vscand_daemonize_init
 *
 * This function will fork off a child process, from which
 * only the child will return.
 */
static int
vscand_daemonize_init(void)
{
	int status, pfds[2];
	sigset_t set, oset;
	pid_t pid;

	/*
	 * Reset process owner/group to daemon/sys. Root ownership is only
	 * required to initialize virus log file in /var/log
	 */
	if (__init_daemon_priv(PU_RESETGROUPS | PU_LIMITPRIVS,
	    daemon_uid, sys_gid,
	    PRIV_PROC_AUDIT, PRIV_FILE_DAC_SEARCH, PRIV_FILE_DAC_READ,
	    PRIV_FILE_FLAG_SET, NULL) != 0) {
		vscand_error(gettext("failed to initialize privileges"));
		_exit(SMF_EXIT_ERR_FATAL);
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
		vscand_error(gettext("failed to create pipe for daemonize"));
		_exit(SMF_EXIT_ERR_FATAL);
	}

	if ((pid = fork()) == -1) {
		vscand_error(gettext("failed to fork for daemonize"));
		_exit(SMF_EXIT_ERR_FATAL);
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

		vscand_error(gettext("failed to daemonize"));
		_exit(SMF_EXIT_ERR_FATAL);
	}


	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) chdir("/");
	(void) umask(022);
	(void) close(pfds[0]);

	return (pfds[1]);
}


/*
 * vscand_daemonize_fini
 * Now that we're running, if a pipe fd was specified, write an exit
 * status to it to indicate that our parent process can safely detach.
 */
static void
vscand_daemonize_fini(int fd, int err_status)
{
	if (fd >= 0)
		(void) write(fd, &err_status, sizeof (err_status));

	(void) close(fd);

	/* Restore standard file descriptors */
	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		(void) fcntl(fd, F_DUP2FD, STDIN_FILENO);
		(void) fcntl(fd, F_DUP2FD, STDOUT_FILENO);
		(void) fcntl(fd, F_DUP2FD, STDERR_FILENO);
		(void) close(fd);
	}

	/* clear basic privileges not required by vscand */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, (char *)NULL);
}


/*
 * vscand_init_file
 *
 * create specified file and set its uid, gid and mode
 */
static int
vscand_init_file(char *filepath, uid_t uid, gid_t gid, mode_t access_mode)
{
	int fd, rc = 0;
	struct stat stat_buf;
	char buf[MAXPATHLEN];

	if ((fd = open(filepath, O_RDONLY | O_CREAT, access_mode)) == -1) {
		rc = -1;
	} else {
		if (fstat(fd, &stat_buf) != 0) {
			rc = -1;
		} else {
			if ((stat_buf.st_mode & S_IAMB) != access_mode) {
				if (fchmod(fd, access_mode) != 0)
					rc = -1;
			}

			if ((stat_buf.st_uid != uid) ||
			    (stat_buf.st_gid != gid)) {
				if (fchown(fd, uid, gid) != 0)
					rc = -1;
			}
		}

		(void) close(fd);
	}

	if (rc == -1) {
		(void) snprintf(buf, MAXPATHLEN, "%s %s",
		    gettext("Failed to initialize"), filepath);
		vscand_error(buf);
	}

	return (rc);
}


/*
 * vscand_init
 *
 * There are some requirements on the order in which the daemon
 * initialization functions are called.
 *
 * - vscand_kernel_bind - bind to kernel module
 * - vs_eng_init populates vs_icap data and thus vs_icap_init MUST be
 *   called before vs_eng_init
 * - vscand_configure - load the configuration
 * - vs_door_init - start vscan door server
 * - vscand_kernel_enable - enable scan requests from kernel
 */
static int
vscand_init(void)
{
	int door_fd = -1;
	uint32_t max_req;

	if (vscand_kernel_bind() < 0)
		return (-1);

	if (vscand_kernel_max_req(&max_req) == -1)
		return (-1);

	if (vs_svc_init(max_req) != 0)
		return (-1);

	if (vs_stats_init() != 0)
		vscand_error(
		    gettext("failed to initialize statistics interface"));

	vs_icap_init();
	vs_eng_init();

	/* initialize configuration and handler thread */
	if (vscand_cfg_init() != 0) {
		vscand_error(gettext("failed to initialize configuration"));
		vscand_fini();
		return (-1);
	}

	(void) vscand_set_resource_limits();

	if (((door_fd = vs_door_init()) < 0) ||
	    (vscand_kernel_enable(door_fd) < 0)) {
		vscand_fini();
		return (-1);
	}

	return (0);
}


/*
 * vscand_fini
 *
 * vscand_kernel_disable - should be called first to ensure that no
 *	more scan requests are initiated from the kernel module
 * vs_svc_terminate - terminate requests and wait for thread completion
 * vs_xxx_fini - module cleanup routines
 * vscand_kernel_unbind - should be called last to tell the kernel module
 *	that vscand is shutdown.
 */
static void
vscand_fini(void)
{
	vscand_kernel_disable();

	/* terminate reconfiguration handler thread */
	vscand_cfg_fini();

	/* terminate requests and wait for completion */
	vs_svc_terminate();

	/* clean up */
	vs_svc_fini();
	vs_eng_fini();
	vs_icap_fini();
	vs_door_fini();
	vs_stats_fini();

	vscand_kernel_unbind();
}


/*
 * vscand_cfg_init
 *
 * initialize configuration and reconfiguration handler thread
 */
static int
vscand_cfg_init(void)
{
	int rc;

	(void) pthread_cond_init(&vscand_cfg_cv, NULL);

	(void) pthread_mutex_lock(&vscand_cfg_mutex);
	rc = vscand_configure();
	(void) pthread_mutex_unlock(&vscand_cfg_mutex);

	if (rc != 0)
		return (-1);

	if (pthread_create(&vscand_cfg_tid, NULL, vscand_cfg_handler, 0) != 0) {
		vscand_cfg_tid = 0;
		return (-1);
	}

	return (0);
}


/*
 * vscand_cfg_fini
 *
 * terminate reconfiguration handler thread
 */
static void
vscand_cfg_fini()
{
	if (vscand_cfg_tid != 0) {
		(void) pthread_cond_signal(&vscand_cfg_cv);
		(void) pthread_join(vscand_cfg_tid, NULL);
		vscand_cfg_tid = 0;
	}
	(void) pthread_cond_destroy(&vscand_cfg_cv);
}


/*
 * vscand_cfg_handler
 * wait for reconfiguration event and reload configuration
 * exit on VS_STATE_SHUTDOWN
 */
/*ARGSUSED*/
static void *
vscand_cfg_handler(void *arg)
{
	(void) pthread_mutex_lock(&vscand_cfg_mutex);

	while (pthread_cond_wait(&vscand_cfg_cv, &vscand_cfg_mutex) == 0) {
		if (vscand_state == VS_STATE_SHUTDOWN)
			break;

		(void) vscand_configure();
	}

	(void) pthread_mutex_unlock(&vscand_cfg_mutex);

	return (NULL);
}


/*
 * vscand_configure
 */
static int
vscand_configure(void)
{
	uint32_t len;
	vs_config_t kconfig;
	vs_props_all_t config;

	(void) memset(&config, 0, sizeof (vs_props_all_t));
	if (vs_props_get_all(&config) != VS_ERR_NONE) {
		vscand_error(gettext("configuration data error"));
		return (-1);
	}

	(void) memset(&kconfig, 0, sizeof (vs_config_t));
	len = sizeof (kconfig.vsc_types);
	if (vs_parse_types(config.va_props.vp_types,
	    kconfig.vsc_types, &len) != 0) {
		vscand_error(gettext("configuration data error - types"));
		return (-1);
	}
	kconfig.vsc_types_len = len;

	/* Convert the maxfsize string from the configuration into bytes */
	if (vs_strtonum(config.va_props.vp_maxsize,
	    &kconfig.vsc_max_size) != 0) {
		vscand_error(gettext("configuration data error - max-size"));
		return (-1);
	}
	kconfig.vsc_allow = config.va_props.vp_maxsize_action ? 1LL : 0LL;

	/* Send configuration update to kernel */
	if (vscand_kernel_config(&kconfig) != 0) {
		return (-1);
	}

	/* dtrace the configuration data */
	vscand_dtrace_cfg(&config);

	/* propagate configuration changes */
	vs_eng_config(&config);
	vs_stats_config(&config);

	return (0);
}


/*
 * vscand_get_state
 */
vs_daemon_state_t
vscand_get_state(void)
{
	return (vscand_state);
}


/*
 * vscand_get_viruslog
 */
static int
vscand_get_viruslog()
{
	vs_props_t props;
	uint64_t propids;
	int rc;

	propids = VS_PROPID_VLOG;
	if ((rc = vs_props_get(&props, propids)) != VS_ERR_NONE) {
		vscand_error(vs_strerror(rc));
		return (-1);
	}

	(void) strlcpy(vscand_vlog, props.vp_vlog, sizeof (vscand_vlog));
	return (0);
}


/*
 * vscand_viruslog
 */
char *
vscand_viruslog(void)
{
	if (vscand_vlog[0] == '\0')
		return (NULL);

	return (vscand_vlog);
}


/*
 * vscand_kernel_bind
 */
static int
vscand_kernel_bind(void)
{
	char devname[MAXPATHLEN];
	int inst = 0;

	(void) snprintf(devname, MAXPATHLEN, "%s%d", VS_DRV_PATH, inst);

	if ((vscand_kdrv_fd = open(devname, O_RDONLY)) < 0) {
		vscand_error(gettext("failed to bind to kernel"));
		return (-1);
	}

	return (0);
}


/*
 * vscand_kernel_unbind
 */
static void
vscand_kernel_unbind(void)
{
	if (vscand_kdrv_fd >= 0)
		(void) close(vscand_kdrv_fd);
}


/*
 * vscand_kernel_enable
 */
static int
vscand_kernel_enable(int door_fd)
{
	if (ioctl(vscand_kdrv_fd, VS_IOCTL_ENABLE, door_fd) < 0) {
		vscand_error(gettext("failed to bind to kernel"));
		(void) close(vscand_kdrv_fd);
		vscand_kdrv_fd = -1;
		return (-1);
	}
	return (0);
}


/*
 * vscand_kernel_disable
 */
static void
vscand_kernel_disable()
{
	if (vscand_kdrv_fd >= 0)
		(void) ioctl(vscand_kdrv_fd, VS_IOCTL_DISABLE);
}


/*
 * vscand_kernel_config
 */
int
vscand_kernel_config(vs_config_t *conf)
{
	if ((vscand_kdrv_fd < 0) ||
	    (ioctl(vscand_kdrv_fd, VS_IOCTL_CONFIG, conf) < 0)) {
		vscand_error(gettext("failed to send config to kernel"));
		return (-1);
	}

	return (0);
}


/*
 * vscand_kernel_result
 */
int
vscand_kernel_result(vs_scan_rsp_t *scan_rsp)
{
	if ((vscand_kdrv_fd < 0) ||
	    (ioctl(vscand_kdrv_fd, VS_IOCTL_RESULT, scan_rsp) < 0)) {
		vscand_error(gettext("failed to send result to kernel"));
		return (-1);
	}

	return (0);
}


/*
 * vscand_kernel_max_req
 */
int
vscand_kernel_max_req(uint32_t *max_req)
{
	if ((vscand_kdrv_fd < 0) ||
	    (ioctl(vscand_kdrv_fd, VS_IOCTL_MAX_REQ, max_req) < 0)) {
		vscand_error(gettext("failed to get config data from kernel"));
		return (-1);
	}

	return (0);
}


/*
 * vscand_set_resource_limits
 *
 * If the process's max file descriptor limit is less than
 * VS_FILE_DESCRIPTORS, increae it to VS_FILE_DESCRIPTORS.
 */
static int
vscand_set_resource_limits(void)
{
	int rc = -1;
	rctlblk_t *rblk;
	char *limit = "process.max-file-descriptor";

	rblk = (rctlblk_t *)malloc(rctlblk_size());

	if (rblk != NULL) {
		rc = getrctl(limit, NULL, rblk, 0);
		if ((rc == 0) &&
		    (rctlblk_get_value(rblk) < VS_FILE_DESCRIPTORS)) {
			rctlblk_set_value(rblk, VS_FILE_DESCRIPTORS);
			rc = setrctl(limit, NULL, rblk, 0);
		}
		(void) free(rblk);
	}

	return (rc);
}


/*
 * vscand_error
 */
static void
vscand_error(const char *errmsg)
{
	(void) fprintf(stderr, "vscand: %s", errmsg);
	syslog(LOG_ERR, "%s\n", errmsg);
}


/*
 * vscand_dtrace_cfg
 * vscand_dtrace_gen
 * vscand_dtrace_eng
 *
 * Support for dtracing vscand configuration when processing
 * a reconfiguration event (SIGHUP)
 */
/*ARGSUSED*/
static void
vscand_dtrace_eng(char *id, boolean_t enable, char *host, int port, int conn)
{
}
/*ARGSUSED*/
static void
vscand_dtrace_gen(char *size, boolean_t action, char *types, char *log)
{
}
static void
vscand_dtrace_cfg(vs_props_all_t *config)
{
	int i;

	vscand_dtrace_gen(config->va_props.vp_maxsize,
	    config->va_props.vp_maxsize_action,
	    config->va_props.vp_types,
	    config->va_props.vp_vlog);

	for (i = 0; i < VS_SE_MAX; i++) {
		if (config->va_se[i].vep_engid[0] != 0)
				vscand_dtrace_eng(config->va_se[i].vep_engid,
				    config->va_se[i].vep_enable,
				    config->va_se[i].vep_host,
				    config->va_se[i].vep_port,
				    config->va_se[i].vep_maxconn);
	}
}
