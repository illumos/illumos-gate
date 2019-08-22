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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Reparsed daemon
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <memory.h>
#include <alloca.h>
#include <ucontext.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <door.h>
#include <wait.h>
#include <libintl.h>
#include <locale.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/thread.h>
#include <rpc/xdr.h>
#include <priv.h>
#include <sys/fs_reparse.h>
#include <priv_utils.h>
#include <rpcsvc/daemon_utils.h>

#define	REPARSED_CMD_OPTS	"v"
#define	DOOR_RESULT_BUFSZ	(MAXPATHLEN + sizeof (reparsed_door_res_t))
#define	SAFETY_BUFFER		8*1024

static char *MyName;
static int verbose = 0;

static int start_reparsed_svcs();
static void daemonize(void);
static void reparsed_door_call_error(int error, int buflen);
static void reparsed_doorfunc(void *cookie, char *argp, size_t arg_size,
			door_desc_t *dp, uint_t n_desc);

static void
usage()
{
	syslog(LOG_ERR, "Usage: %s", MyName);
	syslog(LOG_ERR, "\t[-v]\t\tverbose error messages)");
	exit(1);
}

static void
warn_hup(int i)
{
	syslog(LOG_ERR, "SIGHUP received: ignored");
	(void) signal(SIGHUP, warn_hup);
}

/*
 * Processing for daemonization
 */
static void
daemonize(void)
{
	switch (fork()) {
	case -1:
		syslog(LOG_ERR, "reparsed: can't fork - errno %d", errno);
		exit(2);
		/* NOTREACHED */
	case 0:		/* child */
		break;

	default:	/* parent */
		_exit(0);
	}
	(void) chdir("/");

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

int
main(int argc, char *argv[])
{
	pid_t pid;
	int c, error;
	struct rlimit rlset;
	char *defval;

	/*
	 * There is no check for non-global zone and Trusted Extensions.
	 * Reparsed works in both of these environments as long as the
	 * services that use reparsed are supported.
	 */

	MyName = argv[0];
	if (geteuid() != 0) {
		syslog(LOG_ERR, "%s must be run as root", MyName);
		exit(1);
	}

	while ((c = getopt(argc, argv, REPARSED_CMD_OPTS)) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	daemonize();
	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	(void) _create_daemon_lock(REPARSED, DAEMON_UID, DAEMON_GID);
	(void) enable_extended_FILE_stdio(-1, -1);
	switch (_enter_daemon_lock(REPARSED)) {
	case 0:
		break;
	case -1:
		syslog(LOG_ERR, "Error locking for %s", REPARSED);
		exit(2);
	default:
		/* daemon was already running */
		exit(0);
	}

	(void) signal(SIGHUP, warn_hup);

	/*
	 * Make the process a privilege aware daemon.
	 * Only "basic" privileges are required.
	 *
	 */
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET, 0, 0,
	    (char *)NULL) == -1) {
		syslog(LOG_ERR, "should be run with sufficient privileges");
		exit(3);
	}

	/*
	 * Clear basic privileges not required by reparsed.
	 */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, (char *)NULL);

	return (start_reparsed_svcs());
}

__NORETURN static void
reparsed_door_call_error(int error, int buflen)
{
	reparsed_door_res_t rpd_res;

	memset(&rpd_res, 0, sizeof (reparsed_door_res_t));
	rpd_res.res_status = error;
	rpd_res.res_len = buflen;
	(void) door_return((char *)&rpd_res,
	    sizeof (reparsed_door_res_t), NULL, 0);

	(void) door_return(NULL, 0, NULL, 0);
	abort();
}

/*
 *  reparsed_doorfunc
 *
 *  argp:  "service_type:service_data" string
 *  dp & n_desc: not used.
 */
static void
reparsed_doorfunc(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
	int err;
	size_t bufsz;
	char *svc_type, *svc_data;
	char *cp, *buf, *sbuf, res_buf[DOOR_RESULT_BUFSZ];
	reparsed_door_res_t *resp;

	if ((argp == NULL) || (arg_size == 0)) {
		reparsed_door_call_error(EINVAL, 0);
		/* NOTREACHED */
	}

	if (verbose)
		syslog(LOG_NOTICE, "reparsed_door: [%s, %d]", argp, arg_size);

	if ((svc_type = strdup(argp)) == NULL) {
		reparsed_door_call_error(ENOMEM, 0);
		/* NOTREACHED */
	}

	/*
	 * Door argument string comes in "service_type:service_data" format.
	 * Need to break it into separate "service_type" and "service_data"
	 * string before passing them to reparse_deref() to process them.
	 */
	if ((cp = strchr(svc_type, ':')) == NULL) {
		free(svc_type);
		reparsed_door_call_error(EINVAL, 0);
		/* NOTREACHED */
	}
	*cp++ = '\0';
	svc_data = cp;

	/*
	 * Setup buffer for reparse_deref(). 'bufsz' is the actual
	 * buffer size to hold the result returned by reparse_deref().
	 */
	resp = (reparsed_door_res_t *)res_buf;
	buf = resp->res_data;
	bufsz = sizeof (res_buf) - sizeof (reparsed_door_res_t);

	/*
	 * reparse_deref() calls the service type plugin library to process
	 * the service data. The plugin library function should understand
	 * the context of the service data and should be the one to XDR the
	 * results before returning it to the caller.
	 */
	err = reparse_deref(svc_type, svc_data, buf, &bufsz);

	if (verbose)
		syslog(LOG_NOTICE,
		    "reparsed_deref(svc_type: %s, data: %s, size: %d) -> %d",
		    svc_type, svc_data, bufsz, err);

	switch (err) {
	case 0:
		break;

	case EOVERFLOW:
		/*
		 * bufsz was returned with size needed by reparse_deref().
		 *
		 * We cannot use malloc() here because door_return() never
		 * returns, and memory allocated by malloc() would get leaked.
		 */
		sbuf = alloca(bufsz + sizeof (reparsed_door_res_t));
		if (sbuf == NULL || stack_inbounds(buf) == 0 ||
		    stack_inbounds(buf + sizeof (reparsed_door_res_t) +
		    SAFETY_BUFFER - 1) == 0) {
			free(svc_type);
			reparsed_door_call_error(ENOMEM, 0);
			/* NOTREACHED */
		}

		resp = (reparsed_door_res_t *)sbuf;
		if ((err = reparse_deref(svc_type, svc_data, resp->res_data,
		    &bufsz)) == 0)
			break;

		/* fall through */

	default:
		free(svc_type);
		reparsed_door_call_error(err, 0);
		/* NOTREACHED */
	}

	free(svc_type);

	if (verbose)
		syslog(LOG_NOTICE, "reparsed_door_return <buf=%s> size=%d",
		    buf, bufsz);

	resp->res_status = 0;
	resp->res_len = bufsz;
	(void) door_return((char *)resp, bufsz + sizeof (reparsed_door_res_t),
	    NULL, 0);

	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */
}

static int
start_reparsed_svcs()
{
	int doorfd;
	int dfd;

	if ((doorfd = door_create(reparsed_doorfunc, NULL,
	    DOOR_REFUSE_DESC|DOOR_NO_CANCEL)) == -1) {
		syslog(LOG_ERR, "Unable to create door");
		return (1);
	}

	/*
	 * Create a file system path for the door
	 */
	if ((dfd = open(REPARSED_DOOR, O_RDWR|O_CREAT|O_TRUNC,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1) {
		syslog(LOG_ERR, "unable to open %s", REPARSED_DOOR);
		(void) close(doorfd);
		return (1);
	}

	/*
	 * Clean up any stale associations
	 */
	(void) fdetach(REPARSED_DOOR);

	/*
	 * Register in the kernel namespace for door_ki_open().
	 */
	if (fattach(doorfd, REPARSED_DOOR) == -1) {
		syslog(LOG_ERR, "Unable to fattach door %s", REPARSED_DOOR);
		(void) close(doorfd);
		(void) close(dfd);
		return (1);
	}
	(void) close(dfd);

	/*
	 * Wait for incoming calls
	 */
	while (1)
		(void) pause();
}
