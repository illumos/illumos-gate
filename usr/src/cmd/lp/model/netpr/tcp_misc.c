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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "netpr.h"
#include "netdebug.h"

#define	MAX_NLPS	60	/* Max no. loops in while */

np_tcpjob_t *
create_tcp_job(np_job_t *genjob, int filesize)
{
	np_tcpjob_t *tcpjob;

	if (genjob == NULL)
		return (NULL);

	tcpjob = (np_tcpjob_t *)malloc(sizeof (np_tcpjob_t));
	ASSERT(tcpjob, MALLOC_ERR);
	(void) memset(tcpjob, 0, sizeof (np_tcpjob_t));

	tcpjob->np_port = "9100";
	tcpjob->gen_data = genjob;
	tcpjob->gen_data->filesize = filesize;

	return (tcpjob);
}

int
tcp_open(char *dest, np_tcpjob_t *tcpjob, int timeout)
{
	struct hostent *hp;
	struct sockaddr_in6 serv_addr;
	int	s,
		err,
		error_num;
	unsigned timo = 1;
	int retry;
	int rtnerr;

	/*
	 * Get the host address and port number to connect to.
	 */
	if (dest == NULL) {
		return (-1);
	}

	if ((hp = (getipnodebyname(dest, AF_INET6, AI_DEFAULT,
		    &error_num))) == NULL) {
		(void) fprintf(stderr,
		gettext("Netpr: System call getipnodebyname fails\n"));
		syslog(LOG_DEBUG, "System call getipnodebyname fails "
		    "getipnodebyname() returned %d", error_num);
		return (-1);
	}

	(void) memset(&serv_addr, 0, sizeof (struct sockaddr_in6));
	bcopy(hp->h_addr, (caddr_t)&serv_addr.sin6_addr, hp->h_length);
	serv_addr.sin6_family = hp->h_addrtype;
	serv_addr.sin6_port = (int)htons(atoi(tcpjob->np_port));

	do {

	retry = 0;
	rtnerr = 0;
	/*
	 * Try connecting to the printer.
	 */
	s = socket(PF_INET6, SOCK_STREAM, 0);
	if (s < 0) {
		(void) fprintf(stderr,
		    gettext("Netpr: System call socket fails\n"));
		syslog(LOG_DEBUG, "System call socket fails");
		rtnerr = -1;
	} else {
		(void) signal(SIGALRM, null_sighandler);
		(void) alarm(timeout);
		if (connect(s, (struct sockaddr *)&serv_addr,
					sizeof (serv_addr)) < 0) {
			err = errno;
			(void) alarm(0);
			errno = err;

			if (errno == ECONNREFUSED && timo <= 16) {
				(void) sleep(timo);
				timo *= 2;
				retry++;
			} else {
			(void) fprintf(stderr,
				gettext("Netpr: Cannot connect to printer\n"));
				syslog(LOG_DEBUG, "Cannot connect to printer");
				rtnerr = -1;
			}
			/* The connect on this socket failed; close it */
			(void) close(s);
		} else
			(void) alarm(0);
	}

	} while (retry);

	return ((rtnerr) ? rtnerr : s);
}


int
tcp_print(int sockfd, caddr_t pa, np_tcpjob_t *tcpjob)
{
	char c;
	int xfer;
	char buf[BUFSIZ + 1];
	int nr = 0;
	int ctr = 0;
	int msg_given = 0;
	int nlps = 0;

	if ((xfer = xfer_file(sockfd, pa,
		tcpjob->gen_data->filesize, tcpjob->gen_data->timeout)) < 0) {
			return (xfer);
	}

	if ((shutdown(sockfd, 1)) != 0) {
		(void) fprintf(stderr,
		gettext("Netpr: System error: possible loss of data\n"));
			syslog(LOG_DEBUG,
				"shutdown error; possible loss of data");
		return (E_SYSTEM_ERROR);
	}


	/* read in single character ack or msg from printer */

	(void) memset(buf, 0, BUFSIZ + 1);
	while (ctr < BUFSIZ) {
		(void) signal(SIGALRM, null_sighandler);
		(void) alarm(2);
		errno = 0;
		nr = read(sockfd, &c, 1);
		(void) alarm(0);
		if (errno == EINTR) {
			if (msg_given == 0) {
				tell_lptell(ERRORMSG,
				gettext("Printer not responding;" \
				"Either warming up or needs attention\n"));
				msg_given++;
			}

			/* if no ACK received, do not loop forever */

			if (nlps++ >= MAX_NLPS) {
				syslog(LOG_DEBUG, "No final ack received");
				break;
			}
		} else {
			if ((buf[ctr++] = c) == '\n' || (nr == 0))
				break;
		}
	}
	if (ctr > 1)
		syslog(LOG_DEBUG, "Message from tcp printer on read: %s",
			buf);

	if (msg_given && (nlps < MAX_NLPS)) {
		(void) fprintf(stderr, gettext("Printer ok\n"));
		tell_lptell(OKMSG, "Current");
	}

	return (E_SUCCESS);
}
