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
 * sun4v DR daemon
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <syslog.h>
#include <door.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/drctl_impl.h>
#include <sys/drctl.h>
#include "drd.h"

boolean_t drd_debug = B_FALSE;
boolean_t drd_daemonized = B_FALSE;

#define	DRD_DOOR_FILE		"/tmp/drd_door"
#define	DRD_DOOR_RETURN_ERR()	(void) door_return(NULL, 0, NULL, 0)

static char *cmdname;
static int drctl_fd;
static drctl_rsrc_t *drd_result = NULL;

/*
 * Currently, the only supported backend is for the Reconfiguration
 * Coordination Manager (RCM). When there are other backends, this
 * variable should be set dynamically.
 */
static drd_backend_t *drd_backend = &drd_rcm_backend;

static void drd_daemonize(void);
static int drd_init_drctl_dev(boolean_t standalone);
static int drd_init_door_server(boolean_t standalone);
static void drd_door_server(void *, char *, size_t, door_desc_t *, uint_t);

int
main(int argc, char **argv)
{
	int		opt;
	boolean_t	standalone = B_FALSE;

	cmdname = basename(argv[0]);

	/*
	 * Process command line arguments
	 */
	opterr = 0;	/* disable getopt error messages */
	while ((opt = getopt(argc, argv, "ds")) != EOF) {

		switch (opt) {
		case 'd':
			drd_debug = B_TRUE;
			break;
		case 's':
			standalone = B_TRUE;
			break;
		default:
			drd_err("unkown option: -%c", optopt);
			exit(1);
		}
	}

	drd_dbg("initializing %s...", cmdname);

	/* must be root */
	if (geteuid() != 0) {
		drd_err("permission denied: must run as root");
		exit(1);
	}

	/* open the drctl device */
	if (drd_init_drctl_dev(standalone) != 0) {
		drd_err("unable to initialize drctl device");
		exit(1);
	}

	/* daemonize */
	if (!standalone) {
		drd_daemonize();
	}

	/* initialize door server */
	if (drd_init_door_server(standalone) != 0) {
		drd_err("unable to initialize door server");
		exit(1);
	}

	/* initialize the backend */
	if ((*drd_backend->init)() != 0) {
		drd_err("unable to initialize backend processor");
		exit(1);
	}

	/* loop forever */
	for (;;) {
		pause();
	}

	/*NOTREACHED*/
	return (0);
}

static void
drd_daemonize(void)
{
	pid_t	pid;

	if ((pid = fork()) == -1) {
		drd_err("failed to fork: %s", strerror(errno));
		exit(1);
	}

	if (pid != 0) {
		/* parent */
		exit(0);
	}

	/*
	 * Initialize child process
	 */
	(void) setsid();
	(void) chdir("/");
	(void) umask(0);

	/*
	 * Initialize file descriptors. Do not touch stderr
	 * which is initialized by SMF to point to the drd
	 * specific log file.
	 */
	assert(drctl_fd == (STDERR_FILENO + 1));

	(void) close(STDIN_FILENO);
	(void) open("/dev/null", O_RDWR);
	(void) dup2(STDIN_FILENO, STDOUT_FILENO);

	closefrom(drctl_fd + 1);

	/* initialize logging */
	openlog(cmdname, LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	drd_daemonized = B_TRUE;
}

static int
drd_init_drctl_dev(boolean_t standalone)
{
	void (*drd_output)(char *, ...);

	drd_output = (standalone) ? drd_info : drd_err;

	/* open the drctl device */
	if ((drctl_fd = open(DRCTL_DEV, O_RDWR)) == -1) {
		drd_output("open %s failed: %s", DRCTL_DEV, strerror(errno));
		return ((standalone) ? 0 : -1);
	}

	return (0);
}

static int
drd_init_door_server(boolean_t standalone)
{
	int		door_fd;
	int		dbg_fd;
	drctl_setup_t	setup;

	assert((drctl_fd != -1) || standalone);

	/* create the door */
	if ((door_fd = door_create(drd_door_server, NULL, 0)) == -1) {
		drd_err("door_create failed: %s", strerror(errno));
		return (-1);
	}

	if (drctl_fd != -1) {

		setup.did = door_fd;

		/* send the door descriptor to drctl */
		if (ioctl(drctl_fd, DRCTL_IOCTL_CONNECT_SERVER, &setup) == -1) {
			drd_err("drctl ioctl failed: %s", strerror(errno));
			(void) door_revoke(door_fd);
			return (-1);
		}

		drd_dbg("connection to drctl established");

		/* setup is complete in daemon mode */
		if (!standalone) {
			return (0);
		}
	}

	/*
	 * At this point, the daemon is running in standalone
	 * mode for testing purposes. This allows the daemon
	 * to be controlled directly through a door exported
	 * to the filesystem. No drctl device is required in
	 * this mode.
	 */

	/* create the door file */
	unlink(DRD_DOOR_FILE);
	if ((dbg_fd = creat(DRD_DOOR_FILE, 0644)) == -1) {
		drd_err("failed to create door file '%s': %s",
		    DRD_DOOR_FILE, strerror(errno));
		(void) door_revoke(door_fd);
		return (-1);
	}
	close(dbg_fd);

	/* attach the door file to the door descriptor */
	if (fattach(door_fd, DRD_DOOR_FILE) == -1) {
		drd_err("failed to fattach door file '%s': %s",
		    DRD_DOOR_FILE, strerror(errno));
		unlink(DRD_DOOR_FILE);
		(void) door_revoke(door_fd);
		return (-1);
	}

	drd_dbg("door server attached to '%s'", DRD_DOOR_FILE);

	return (0);
}

static size_t
drd_pack_response(drctl_rsrc_t *rsrcs, int nrsrc)
{
	drctl_rsrc_t	*orsrcsp;
	void		*resizep;
	size_t		osize;
	char		*str;
	size_t		offset;
	char		*off;
	int		idx;
	size_t		len;

	drd_dbg("drd_pack_response...");

	/*
	 * Deallocate the global response buffer if it is
	 * in use. This assumes that there will only ever
	 * be one pending operation in the daemon. This is
	 * enforced by the kernel.
	 */
	s_free(drd_result);

	orsrcsp = calloc(sizeof (*orsrcsp), nrsrc);
	osize = sizeof (*orsrcsp) * nrsrc;
	bcopy(rsrcs, orsrcsp, osize);

	offset = osize;

	/*
	 * Loop through all the resources and concatenate
	 * all the error strings to the end of the resource
	 * array. Also, update the offset field of each
	 * resource.
	 */
	for (idx = 0; idx < nrsrc; idx++) {

		str = (char *)(uintptr_t)rsrcs[idx].offset;

		/* skip if no error string */
		if (str == NULL)
			continue;

		len = strlen(str) + 1;

		/* increase the size of the buffer */
		resizep = realloc(orsrcsp, osize + len);
		if (resizep == NULL) {
			drd_err("realloc failed: %s", strerror(errno));
			s_free(orsrcsp);

			/* clean up any remaining strings */
			while (idx < nrsrc) {
				str = (char *)(uintptr_t)rsrcs[idx++].offset;
				s_free(str);
			}
			return (0);
		}

		orsrcsp = resizep;

		/* copy the error string into the response */
		off = (char *)orsrcsp + offset;
		bcopy(str, off, len);
		orsrcsp[idx].offset = offset;

		/*
		 * Now that the error string has been copied
		 * into the response message, the memory that
		 * was allocated for it is no longer needed.
		 */
		s_free(str);
		rsrcs[idx].offset = 0;

		/* update size and offset */
		offset += len;
		osize += len;
	}

	drd_result = orsrcsp;
	return (osize);
}

/*ARGSUSED*/
static void
drd_door_server(void *cookie, char *argp, size_t arg_sz, door_desc_t *dp,
    uint_t n_desc)
{
	drd_msg_t	*msg = (drd_msg_t *)(uintptr_t)argp;
	drctl_rsrc_t	*rsrcs;
	size_t		osize;
	int		nrsrc;

	drd_dbg("drd_door_server...");
	drd_dbg("message received: %d bytes", arg_sz);

	/* sanity check incoming arg */
	if ((argp == NULL) || (arg_sz == 0))
		DRD_DOOR_RETURN_ERR();

	drd_dbg("  cmd=%d, count=%d, flags=%d", msg->cmd,
	    msg->count, msg->flags);

	rsrcs = (drctl_rsrc_t *)(uintptr_t)msg->data;
	nrsrc = msg->count;

	/* pass off to backend for processing */
	switch (msg->cmd) {
	case DRCTL_CPU_CONFIG_REQUEST:
		(*drd_backend->cpu_config_request)(rsrcs, nrsrc);
		break;

	case DRCTL_CPU_CONFIG_NOTIFY:
		(*drd_backend->cpu_config_notify)(rsrcs, nrsrc);
		break;

	case DRCTL_CPU_UNCONFIG_REQUEST:
		(*drd_backend->cpu_unconfig_request)(rsrcs, nrsrc);
		break;

	case DRCTL_CPU_UNCONFIG_NOTIFY:
		(*drd_backend->cpu_unconfig_notify)(rsrcs, nrsrc);
		break;

	case DRCTL_MEM_CONFIG_REQUEST:
	case DRCTL_MEM_CONFIG_NOTIFY:
	case DRCTL_MEM_UNCONFIG_REQUEST:
	case DRCTL_MEM_UNCONFIG_NOTIFY:
		drd_err("memory DR operations not supported yet");
		DRD_DOOR_RETURN_ERR();
		break;

	case DRCTL_IO_CONFIG_REQUEST:
		(*drd_backend->io_config_request)(rsrcs, nrsrc);
		break;

	case DRCTL_IO_CONFIG_NOTIFY:
		(*drd_backend->io_config_notify)(rsrcs, nrsrc);
		break;

	case DRCTL_IO_UNCONFIG_REQUEST:
		(*drd_backend->io_unconfig_request)(rsrcs, nrsrc);
		break;

	case DRCTL_IO_UNCONFIG_NOTIFY:
		(*drd_backend->io_unconfig_notify)(rsrcs, nrsrc);
		break;

	default:
		drd_err("unknown command: %d", msg->cmd);
		DRD_DOOR_RETURN_ERR();
		break;
	}

	osize = drd_pack_response(rsrcs, nrsrc);
	if (osize == 0)
		DRD_DOOR_RETURN_ERR();

	(void) door_return((char *)drd_result, osize, NULL, 0);
}
