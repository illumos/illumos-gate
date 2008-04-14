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
 * This is the SMB NIC monitoring module.
 */
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <syslog.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>

static pthread_t smb_nicmon_thread;

static void smb_nicmon_setup_rtsock(int, int *);
static int smb_nicmon_needscan(int);
static void *smb_nicmon_daemon(void *);
static int smb_nicmon_setup_eventpipe(int *, int *);

/* Use this to stop monitoring */
static int eventpipe_write = -1;

/* Use this to refresh service instance */
static char *smb_nicmon_caller_fmri = NULL;

/*
 * Start the nic monitor thread.
 */
int
smb_nicmon_start(const char *svc_fmri)
{
	int rc = 0;

	if ((rc = smb_nic_init()) != 0) {
		syslog(LOG_ERR, "NIC monitor failed to initialize (%s)",
		    strerror(errno));
		return (rc);
	}

	rc = pthread_create(&smb_nicmon_thread, NULL, smb_nicmon_daemon, 0);
	if (rc != 0) {
		syslog(LOG_ERR, "NIC monitor failed to start (%s)",
		    strerror(errno));
		return (rc);
	}

	if (svc_fmri)
		smb_nicmon_caller_fmri = (char *)svc_fmri;

	return (rc);
}

/*
 * Stop the nic monitor.
 */
void
smb_nicmon_stop(void)
{
	uchar_t buf = 1;

	if (eventpipe_write < 0)
		return;

	(void) write(eventpipe_write, &buf, sizeof (buf));
	smb_nicmon_caller_fmri = NULL;
	smb_nic_fini();
}

/*
 * Setup routing socket for getting RTM messages.
 */
static void
smb_nicmon_setup_rtsock(int af, int *s)
{
	int flags;

	*s = socket(PF_ROUTE, SOCK_RAW, af);
	if (*s == -1) {
		syslog(LOG_ERR, "smb_nicmon_daemon: failed to "
		    "create routing socket");
		return;
	}
	if ((flags = fcntl(*s, F_GETFL, 0)) < 0) {
		syslog(LOG_ERR, "smb_nicmon_daemon: "
		    "failed to fcntl F_GETFL");
		(void) close(*s);
		*s = -1;
		return;
	}
	if ((fcntl(*s, F_SETFL, flags | O_NONBLOCK)) < 0) {
		syslog(LOG_ERR, "smb_nicmon_daemon: "
		    "failed to fcntl F_SETFL");
		(void) close(*s);
		*s = -1;
		return;
	}
}

static int
smb_nicmon_needscan(int sock)
{
	int	nbytes;
	int64_t msg[2048 / 8];
	struct rt_msghdr *rtm;
	int need_if_scan = 0;

	/* Read as many messages as possible and try to empty the sockets */
	for (;;) {
		nbytes = read(sock, msg, sizeof (msg));
		if (nbytes <= 0) {
			break;
		}
		rtm = (struct rt_msghdr *)msg;
		if (rtm->rtm_version != RTM_VERSION) {
			continue;
		}
		if (nbytes < rtm->rtm_msglen) {
			syslog(LOG_DEBUG, "smb_nicmon_daemon: short read: %d "
			    "of %d", nbytes, rtm->rtm_msglen);
			continue;
		}

		switch (rtm->rtm_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_IFINFO:
			need_if_scan = 1;
			break;
		default:
			break;
		}
	}

	return (need_if_scan);
}

/*
 * Create pipe for signal delivery and set up signal handlers.
 */
static int
smb_nicmon_setup_eventpipe(int *read_pipe, int *write_pipe)
{
	int fds[2];

	if ((pipe(fds)) < 0) {
		syslog(LOG_ERR, "smb_nicmon_daemon: failed to open pipe");
		return (1);
	}
	*read_pipe = fds[0];
	*write_pipe = fds[1];
	return (0);
}

/*ARGSUSED*/
static void *
smb_nicmon_daemon(void *args)
{
	struct pollfd pollfds[2];
	int pollfd_num = 2;
	int i, nic_changed;
	/* AF_INET routing socket add AF_INET6 when we support IPv6 */
	static int rtsock_v4;
	static int eventpipe_read = -1;

	/*
	 * Create the global routing socket.  We use this to
	 * monitor changes in NIC interfaces. We are only interested
	 * in new inerface addition/deletion and change in UP/DOWN status.
	 */
	smb_nicmon_setup_rtsock(AF_INET, &rtsock_v4);
	if (rtsock_v4 == -1) {
		syslog(LOG_ERR, "smb_nicmon_daemon: "
		    "cannot open routing socket");
		return (NULL);
	}

	if (smb_nicmon_setup_eventpipe(&eventpipe_read, &eventpipe_write)
	    != 0) {
		syslog(LOG_ERR, "smb_nicmon_daemon: cannot open event pipes");
		return (NULL);
	}

	/*
	 * Keep listening for activity on any of the sockets.
	 */
	for (;;) {
		nic_changed = 0;
		pollfds[0].fd = rtsock_v4;
		pollfds[0].events = POLLIN;
		pollfds[1].fd = eventpipe_read;
		pollfds[1].events = POLLIN;
		if (poll(pollfds, pollfd_num, -1) < 0) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "smb_nicmon_daemon: "
			    "poll failed with errno %d", errno);
			break;
		}
		for (i = 0; i < pollfd_num; i++) {
			if ((pollfds[i].fd < 0) ||
			    !(pollfds[i].revents & POLLIN))
				continue;
			if (pollfds[i].fd == rtsock_v4)
				nic_changed = smb_nicmon_needscan(rtsock_v4);
			if (pollfds[i].fd == eventpipe_read)
				goto done;
		}

		/*
		 * If anything changed, do refresh the instance
		 * of the registered SMF service.
		 */
		if (nic_changed && smb_nicmon_caller_fmri)
			if (smf_refresh_instance(smb_nicmon_caller_fmri) != 0)
				syslog(LOG_ERR, "smb_nicmon_daemon: "
				    "failed to refresh SMF instance %s",
				    smb_nicmon_caller_fmri);
	}
done:
	/* Close sockets */
	(void) close(rtsock_v4);
	(void) close(eventpipe_read);
	(void) close(eventpipe_write);
	eventpipe_write = -1;
	return (NULL);
}
