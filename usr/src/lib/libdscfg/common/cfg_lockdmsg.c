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

#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "cfg_lockd.h"

static daemonaddr_t	clientaddr;
static daemonaddr_t	server;

static unsigned short	server_port = CFG_SERVER_PORT;
static int	lock_soc = 0;
static int	pf_inet = AF_INET;
static int	locked;
static int	initdone;
static int	initresult;
static pid_t	socket_pid;

static void	cfg_lockd_reinit();

static int last_cmd = -1;
static uint8_t seq = 0;

static void
send_cmd(int cmd)
{
	struct lock_msg message_buf;
	int rc;

	if (last_cmd == cmd) {
		message_buf.seq = seq;
	} else {
		message_buf.seq = ++seq;
		last_cmd = cmd;
	}
	message_buf.message = cmd;
	if ((message_buf.pid = getpid()) != socket_pid)
		cfg_lockd_reinit();

	do {
		rc = sendto(lock_soc, &message_buf, sizeof (message_buf), 0,
			(struct sockaddr *)&server, sizeof (server));
	} while (rc == -1 && errno == EINTR);
#ifdef CFG_LOCKD_DEBUG
	if (rc < 0) {
		perror("send");
	}
#endif
}

static void
read_msg(struct lock_msg *mp)
{
	struct sockaddr from;
	int rc, len;

	/* wait for response */
	do {
		struct pollfd fds;

		fds.fd = lock_soc;
		fds.events = POLLIN;
		fds.revents = 0;

		rc = poll(&fds, 1, 500);
		if (!rc) {
#ifdef CFG_LOCKD_DEBUG
			fprintf(stderr, "LOCKD: resending last command (%d)\n",
			    last_cmd);
#endif
			send_cmd(last_cmd);
		}
	} while (rc == 0 ||
		(rc == -1 && errno == EINTR));

	do {
		len = sizeof (from);
		rc = recvfrom(lock_soc, mp, sizeof (*mp), 0,
			&from, &len);
	} while (rc == -1 && errno == EINTR);
#ifdef CFG_LOCKD_DEBUG
	if (rc < 0) {
		perror("revcfrom");
	}
#endif
}

static void
read_reply()
{
	struct lock_msg message_buf;

	do {
		read_msg(&message_buf);
	} while (message_buf.seq != seq || message_buf.message != LOCK_LOCKED);
}

static void
read_ack()
{
	struct lock_msg message_buf;

	do {
		read_msg(&message_buf);
	} while (message_buf.seq != seq || message_buf.message != LOCK_ACK);
}

void
cfg_lockd_rdlock()
{
#ifdef CFG_LOCKD_DEBUG
	FILE *fp;
#endif

	send_cmd(LOCK_READ);
	locked = 1;
	read_reply();

#ifdef CFG_LOCKD_DEBUG
	fp = fopen("/tmp/locktag", "a");
	if (fp) {
		time_t t = time(0);
		fprintf(fp, "%19.19s read  lock acquired\n", ctime(&t));
		fclose(fp);
	}
	sleep(3);
#endif
}

void
cfg_lockd_wrlock()
{
#ifdef CFG_LOCKD_DEBUG
	FILE *fp;
#endif

	send_cmd(LOCK_WRITE);
	locked = 1;
	read_reply();

#ifdef CFG_LOCKD_DEBUG
	fp = fopen("/tmp/locktag", "a");
	if (fp) {
		time_t t = time(0);
		fprintf(fp, "%19.19s write lock acquired\n", ctime(&t));
		fclose(fp);
	}
	sleep(3);
#endif
}

void
cfg_lockd_unlock()
{
#ifdef CFG_LOCKD_DEBUG
	FILE *fp;
#endif

	send_cmd(LOCK_NOTLOCKED);
	read_ack();
	locked = 0;

#ifdef CFG_LOCKD_DEBUG
	fp = fopen("/tmp/locktag", "a");
	if (fp) {
		time_t t = time(0);
		fprintf(fp, "%19.19s ----- lock released\n", ctime(&t));
		fclose(fp);
	}
	sleep(3);
#endif
}

void
cfg_lockd_stat()
{
	send_cmd(LOCK_STAT);
}

cfglockd_t
cfg_lockedby(pid_t *pidp)
{
	struct lock_msg message_buf;
	send_cmd(LOCK_LOCKEDBY);
	read_msg(&message_buf);
	*pidp = message_buf.pid;
	return ((cfglockd_t)message_buf.message);
}

static void
cfg_atexit()
{
	if (locked)
		cfg_lockd_unlock();
}

static int
cfg_lockd_socket()
{
	if ((lock_soc = socket(pf_inet, SOCK_DGRAM, 0)) < 0) {
#ifdef CFG_LOCKD_DEBUG
		fprintf(stderr, "libcfg: failed to create socket\n");
		perror("socket");
#endif
		return (-1);
	}
	clientaddr.sin_family = AF_INET;
	clientaddr.sin_addr.s_addr = INADDR_ANY;
	clientaddr.sin_port = htons(0);
	if (bind(lock_soc, (struct sockaddr *)&clientaddr,
	    sizeof (clientaddr)) < 0) {
#ifdef CFG_LOCKD_DEBUG
		perror("bind");
#endif
		return (-1);
	}
	socket_pid = getpid();
	return (0);
}

/*
 * Re-initialise after a fork has been detected.
 *
 * Needs to create a new socket for new process to receive messages
 * from the lock daemon and enter pid into lock file so that the daemon
 * can detect new processes exit if it doesn't call unlock first.
 */

static void
cfg_lockd_reinit()
{
	if (lock_soc)
		close(lock_soc);
	lock_soc = 0;
	if (cfg_lockd_socket()) {
		initresult = 0;
		return;
	}
	cfg_enterpid();
	initresult = 1;
}

int
cfg_lockd_init()
{
	struct	hostent *hp;
	FILE	*fp;
	int	pid = 0x12345678;

	if (initdone) {
		/* only perform reinit if init worked first time */
		if (getpid() != socket_pid && initresult != 0)
			cfg_lockd_reinit();
		return (initresult);
	}

	initdone = 1;
	initresult = 0;

	/* check if there's a lock daemon out there */
	if ((fp = fopen(CFG_PIDFILE, "r")) == NULL)
		return (0);
	if (fscanf(fp, "%d\n", &pid) != 1) {
		fclose(fp);
		return (0);
	}
	fclose(fp);
	if (kill((pid_t)pid, 0) != 0)
		return (0);

	/* there is a lock daemon */
	cfg_lfinit();
	cfg_enterpid();
	if (cfg_lockd_socket())
		return (0);

	if ((hp = gethostbyname("localhost")) == NULL) {
#ifdef CFG_LOCKD_DEBUG
		fprintf(stderr, "Can't find hostent for %s\n", "localhost");
#endif
		return (0);
	}
	(void) memcpy(&(server.sin_addr.s_addr), *(hp->h_addr_list),
				sizeof (server.sin_addr));
	server.sin_port = htons(server_port);
	server.sin_family = hp->h_addrtype;
	endhostent();
	atexit(cfg_atexit);
	initresult = 1;
	return (1);
}
