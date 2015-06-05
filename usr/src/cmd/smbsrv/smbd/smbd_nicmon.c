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
 */

/*
 * smbd NIC monitor.
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
#include "smbd.h"

#define	SMBD_NICMON_ENABLE	"nicmon_enable"
#define	SMBD_NICMON_THROTTLE	100
#define	SMBD_NICMON_DEBOUNCE	2

extern smbd_t smbd;

static boolean_t smbd_nicmon_enabled = B_TRUE;

/* Use this to stop monitoring */
static int eventpipe_write = -1;

/* Use this to refresh service instance */
static char *smbd_nicmon_caller_fmri = NULL;

static void smbd_nicmon_run_check(void);
static int smbd_nicmon_setup_rtsock(int);
static int smbd_nicmon_needscan(int);
static int smbd_nicmon_setup_eventpipe(int *, int *);
static void *smbd_nicmon_daemon(void *);

/*
 * Start the nic monitor thread.
 */
int
smbd_nicmon_start(const char *svc_fmri)
{
	pthread_t	smbd_nicmon_tid;
	int		rc;

	if (smb_nic_init() != SMB_NIC_SUCCESS)
		return (-1);

	rc = pthread_create(&smbd_nicmon_tid, NULL, smbd_nicmon_daemon, NULL);
	if (rc != 0)
		return (-1);

	if (svc_fmri)
		smbd_nicmon_caller_fmri = (char *)svc_fmri;

	smbd_nicmon_run_check();
	return (0);
}

void
smbd_nicmon_stop(void)
{
	uchar_t buf = 1;

	if (eventpipe_write < 0)
		return;

	(void) write(eventpipe_write, &buf, sizeof (buf));
	smbd_nicmon_caller_fmri = NULL;
	smb_nic_fini();
}

int
smbd_nicmon_refresh(void)
{
	if (smb_nic_init() != SMB_NIC_SUCCESS)
		return (-1);

	smbd_nicmon_run_check();
	return (0);
}

/*
 * The monitor is enabled unless it is explicitly
 * disabled by setting smbd/nicmon_enable to false.
 * smbd/nicmon_enable is not defined by default.
 */
static void
smbd_nicmon_run_check(void)
{
	smb_scfhandle_t	*hd;
	uint8_t		status;
	int		rc;

	smbd_nicmon_enabled = B_TRUE;

	if ((hd = smb_smf_scf_init(SMBD_FMRI_PREFIX)) == NULL) {
		syslog(LOG_DEBUG,
		    "smbd_nicmon: smb_smf_scf_init failed");
		return;
	}

	rc = smb_smf_create_service_pgroup(hd, SMBD_PG_NAME);
	if (rc != SMBD_SMF_OK) {
		smb_smf_scf_fini(hd);
		syslog(LOG_DEBUG,
		    "smbd_nicmon: smb_smf_create_service_pgroup failed");
		return;
	}

	rc = smb_smf_get_boolean_property(hd, SMBD_NICMON_ENABLE, &status);
	if (rc == SMBD_SMF_OK && status == 0)
		smbd_nicmon_enabled = B_FALSE;

	smb_smf_scf_fini(hd);
}

/*
 * Setup routing socket for getting RTM messages.
 */
static int
smbd_nicmon_setup_rtsock(int af)
{
	int sd;
	int flags;

	if ((sd = socket(PF_ROUTE, SOCK_RAW, af)) == -1) {
		syslog(LOG_ERR,
		    "smbd_nicmon: routing socket failed: %d", errno);
		return (-1);
	}

	if ((flags = fcntl(sd, F_GETFL, 0)) < 0) {
		syslog(LOG_ERR,
		    "smbd_nicmon: fcntl F_GETFL failed: %d", errno);
		(void) close(sd);
		return (-1);
	}

	if ((fcntl(sd, F_SETFL, flags | O_NONBLOCK)) < 0) {
		syslog(LOG_ERR,
		    "smbd_nicmon: fcntl F_SETFL failed: %d", errno);
		(void) close(sd);
		return (-1);
	}

	return (sd);
}

static int
smbd_nicmon_needscan(int sock)
{
	static uint32_t		throttle;
	struct rt_msghdr	*rtm;
	int64_t			msg[2048 / 8];
	int			need_if_scan = 0;
	int			nbytes;

	/* Read as many messages as possible and try to empty the sockets */
	for (;;) {
		nbytes = read(sock, msg, sizeof (msg));
		if (nbytes <= 0)
			break;

		rtm = (struct rt_msghdr *)msg;
		if (rtm->rtm_version != RTM_VERSION)
			continue;

		if (nbytes < rtm->rtm_msglen) {
			if ((throttle % SMBD_NICMON_THROTTLE) == 0) {
				syslog(LOG_DEBUG,
				    "smbd_nicmon: short read: %d of %d",
				    nbytes, rtm->rtm_msglen);
			}
			++throttle;
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
smbd_nicmon_setup_eventpipe(int *read_pipe, int *write_pipe)
{
	int fds[2];

	if ((pipe(fds)) < 0) {
		syslog(LOG_ERR,
		    "smbd_nicmon: event pipe failed: %d", errno);
		return (-1);
	}

	*read_pipe = fds[0];
	*write_pipe = fds[1];
	return (0);
}

/*
 * Create the global routing socket to monitor changes in NIC interfaces.
 * We are only interested in new inerface addition/deletion and changes
 * in UP/DOWN status.
 *
 * Note: only supports AF_INET routing socket.  Need to add AF_INET6 to
 * support IPv6.
 */
/*ARGSUSED*/
static void *
smbd_nicmon_daemon(void *arg)
{
	static uint32_t	throttle;
	static int	rtsock_v4;
	static int	eventpipe_read = -1;
	struct pollfd	pollfds[2];
	int		pollfd_num = 2;
	int		i, nic_changed;
	int		rc;

	if ((rtsock_v4 = smbd_nicmon_setup_rtsock(AF_INET)) == -1)
		return (NULL);

	rc = smbd_nicmon_setup_eventpipe(&eventpipe_read, &eventpipe_write);
	if (rc != 0)
		return (NULL);

	/*
	 * Listen for activity on any of the sockets.
	 * The delay before checking the rtsock will hopefully
	 * smooth things out when there is a lot of activity.
	 */
	for (;;) {
		errno = 0;
		nic_changed = 0;
		pollfds[0].fd = rtsock_v4;
		pollfds[0].events = POLLIN;
		pollfds[1].fd = eventpipe_read;
		pollfds[1].events = POLLIN;

		if (poll(pollfds, pollfd_num, -1) < 0) {
			if (errno == EINTR)
				continue;
			if ((throttle % SMBD_NICMON_THROTTLE) == 0)
				syslog(LOG_DEBUG,
				    "smbd_nicmon: poll failed: %d", errno);
			++throttle;
			break;
		}

		for (i = 0; i < pollfd_num; i++) {
			if ((pollfds[i].fd < 0) ||
			    !(pollfds[i].revents & POLLIN))
				continue;
			if (pollfds[i].fd == rtsock_v4) {
				(void) sleep(SMBD_NICMON_DEBOUNCE);
				nic_changed = smbd_nicmon_needscan(rtsock_v4);
			}
			if (pollfds[i].fd == eventpipe_read)
				goto done;
		}

		/*
		 * If the monitor is enabled and something has changed,
		 * refresh the registered SMF service.
		 */
		if (smbd_nicmon_enabled && nic_changed &&
		    smbd_nicmon_caller_fmri) {
			if (smf_refresh_instance(smbd_nicmon_caller_fmri) != 0)
				syslog(LOG_ERR,
				    "smbd_nicmon: %s refresh failed",
				    smbd_nicmon_caller_fmri);
		}
	}
done:
	(void) close(rtsock_v4);
	(void) close(eventpipe_read);
	(void) close(eventpipe_write);
	eventpipe_write = -1;
	return (NULL);
}
