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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <libintl.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include "netpr.h"

#define	TIMEOUT		1

static int netpr_send_message(int, char *, ...);
static int xfer_cfAfile(int, char *, char *, uint);

int
bsd_print(int sockfd, caddr_t pa, np_bsdjob_t * bsdjob)
{
	int filesize;
	int xfer;
	int net;

	syslog(LOG_DEBUG, "bsd_print");

	filesize = bsdjob->np_data->np_data_size;
	syslog(LOG_DEBUG, "filesize is %d", filesize);


	if (netpr_send_message(sockfd, "%c%s\n", XFER_REQUEST,
		bsdjob->np_printer) != 0) {
		return (NETWORK_ERROR_SEND_RESPONSE);
	}

	/*
	 * control file
	 */

	if (bsdjob->np_print_order == CONTROL_FIRST) {
		if ((xfer_cfAfile(sockfd, bsdjob->np_cfAfile,
		    bsdjob->np_cfAfilename,
		    bsdjob->np_cfAfilesize)) != 0) {
			(void) fprintf(stderr,
			    gettext("Netpr: Error sending control file\n"));
			syslog(LOG_DEBUG, "Error sending control file");
			    return (NETWORK_ERROR_UNKNOWN);

		}
	}

	/* send msg - get ready for transfer */

	if ((netpr_send_message(sockfd, "%c%d %s\n", XFER_DATA, filesize,
	    bsdjob->np_data->np_dfAfilename)) != 0) {
		return (NETWORK_ERROR_SEND_RESPONSE);
	}

	/*
	 * send the file
	 */

	if ((xfer = xfer_file(sockfd, pa, filesize, bsdjob->np_timeout)) != 0) {
		return (xfer);
	}

	/* send msg - done */
	if ((net = netpr_send_message(sockfd, "", NULL)) != 0) {
		(void) fprintf(stderr,
		gettext("Netpr: network error transfering %s returns: %d\n"),
			bsdjob->np_filename, net);
		syslog(LOG_DEBUG,
			"network error transfering %s returns: %d",
			bsdjob->np_filename, net);
		return (NETWORK_ERROR_WRITE_FAILED);
	}

	/*
	 * control file
	 */

	if (bsdjob->np_print_order == DATA_FIRST) {
		if ((xfer_cfAfile(sockfd, bsdjob->np_cfAfile,
		    bsdjob->np_cfAfilename,
		    bsdjob->np_cfAfilesize)) != 0) {

			(void) fprintf(stderr,
			    gettext("Netpr: Error sending control file\n"));
			    syslog(LOG_DEBUG, "Error sending control file");
			    return (NETWORK_ERROR_UNKNOWN);
		}
	}

	return (0);
}

int
xfer_file(int sockfd, caddr_t pa, int filesize, int seed)
{
	int ctr;
	int timeout;
	int nw;
	int error_msg = 0;
	int pause = 0;

	syslog(LOG_DEBUG, "xfer_file");

	/* send file */
	ctr = filesize;
	timeout = seed = seed ? seed : 10;

	while (ctr > 0) {

	syslog(LOG_DEBUG, "xfer_file: write while loop => ctr = %d", ctr);
	syslog(LOG_DEBUG, "xfer_file: timeout = %d", timeout);

		(void) signal(SIGALRM, null_sighandler);
		(void) alarm(10);
		nw = write(sockfd, pa, ctr);
	syslog(LOG_DEBUG, "xfer_file: write while loop => nw = %d", nw);
		(void) alarm(0);
		if ((nw == 0) || (nw < 0)) {
			if (timeout < (seed * 4)) {
				(void) sleep(timeout);
				timeout *= 2;
			} else if (timeout == (seed * 4)) {
				(void) sleep(timeout);
				timeout *= 2;

				/*
				 * Send message to user once
				 */
				if (error_msg == 0) {
					error_msg++;
					tell_lptell(ERRORMSG,
					gettext("Printer not accepting input;"
					"possibly offline or out of paper."));
				}

			} else if (timeout > (seed * 4)) {
				(void) sleep(timeout);
				if (pause++ > 3)
					timeout = (seed * 10);
			}

		} else {
			ctr -= nw;
			pa += nw;
			if (error_msg) {
				tell_lptell(OKMSG, "Current");
				error_msg = 0;
				pause = 0;
			}
			timeout = seed;
		}
	}

	return (E_SUCCESS);
}

static int
xfer_cfAfile(int sockfd, char * cfAfile, char * cfAname, uint size)
{
	int ctr;
	caddr_t pa;
	int nw = 0;
	int timeout;
	int printererr;

	syslog(LOG_DEBUG, "xfer_cfAfile");

	if ((netpr_send_message(sockfd, "%c%d %s\n", XFER_CONTROL,
		size, cfAname)) != 0) {
		return (NETWORK_ERROR_MSG_FAILED);
	}

	/* send the control file */
	pa = cfAfile;
	ctr = size;
	syslog(LOG_DEBUG, "xfer_cfAfile : cfAfile %s", pa);
	syslog(LOG_DEBUG, "xfer_cfAfile : size %d", size);

	/* send control file */
	timeout = TIMEOUT;
	printererr = 0;
	while (ctr > 0) {
		(void) signal(SIGALRM, null_sighandler);
		(void) alarm(2);
		nw = write(sockfd, pa, size);
		(void) alarm(0);
		if (nw <= 0) {
			if (timeout < 16) {
				(void) sleep(timeout);
				timeout *= 2;
			} else if (timeout == 16) {
			/* talk with the printer and see what's happening */
				/* send message back to caller */
				(void) sleep(timeout);
				timeout *= 2;
				printererr = 1;

				tell_lptell(ERRORMSG,
				gettext("Printer not accepting input;"
				"possibly offline or out of paper."));

			} else if (timeout > 16) {
				(void) sleep(timeout);
			}
		}
		ctr -= nw;
		pa += nw;
	}

	if (printererr == 1) {
		(void) fprintf(stderr, gettext("Printer status ok\n"));
		tell_lptell(OKMSG, "Current");
	}


	/* send msg - done */
	if (netpr_send_message(sockfd, "", NULL) != 0) {
		return (NETWORK_ERROR_MSG_FAILED);
	}

	return (0);
}

/*
 *  netpr_response() reads in a byte from the network printer
 */
static int
netpr_response(int nd)
{
	char    c;
	int msg_given = 0;
	int firstloop = 0;

	syslog(LOG_DEBUG, "netpr_response");

	(void) signal(SIGALRM, null_sighandler);
	(void) alarm(2);
	while (1) {
		errno = 0;
		if ((read(nd, &c, 1) != 1)) {

			if (firstloop == 0) {
				(void) alarm(0);
				firstloop++;
			}

			if (errno == EINTR) {
				if (msg_given == 0) {
				    tell_lptell(ERRORMSG,
				    gettext("Printer not responding;"
				    "Either warming up or needs attention"));
				    msg_given++;
				    syslog(LOG_DEBUG,
					"read hanging in netpr_response: %m");
				}

			} else {
				syslog(LOG_DEBUG,
					"read in netpr_response failed: %m");
				return (NETWORK_READ_RESPONSE_FAILED);
			}

		} else {
			if (c) {
				syslog(LOG_DEBUG,
					"Printer returned error: %m");
				return (NETWORK_PRINTER_REFUSED_CONN);
			} else {
				if (msg_given)
					tell_lptell(OKMSG, "Current");
				return (0);
			}
		}
	}

}

static int
netpr_send_message(int nd, char *fmt, ...)
{
	char    buf[BUFSIZ];
	int ctr;
	char * pa;
	va_list ap;
	int timeout = 1;
	int nw;
	int err_msg = 0;

	syslog(LOG_DEBUG, "netpr_send_message");
	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	pa = buf;
	ctr = (strlen(buf) != 0) ? strlen(buf) : 1;

	syslog(LOG_DEBUG, "netpr_send_message : ctr = %d", ctr);
	while (ctr > 0) {
		(void) signal(SIGALRM, null_sighandler);
		(void) alarm(2);
		nw = write(nd, pa, ctr);
	syslog(LOG_DEBUG, "netpr_send_message : nw = %d", nw);
		(void) alarm(0);

		if (nw <= 0) {
			if (timeout < 16) {
				(void) sleep(timeout);
				timeout *= 2;
			} else if (timeout == 16) {
				(void) sleep(timeout);
				timeout *= 2;
				if (err_msg == 0) {
					err_msg++;
					tell_lptell(ERRORMSG,
					gettext("Printer not accepting input;"
					"possibly offline or out of paper."));
				}
			} else
				(void) sleep(timeout);
		} else {
			ctr -= nw;
			pa += nw;
			if (err_msg)
				tell_lptell(OKMSG, "Current");
		}
	}

	return (netpr_response(nd));
}

/*
 *  null() is to be used as a signal handler that does nothing.  It is used in
 *      place of SIG_IGN, because we want the signal to be delivered and
 *      interupt the current system call.
 */
/*ARGSUSED*/
void
null_sighandler(int i)
{
}
