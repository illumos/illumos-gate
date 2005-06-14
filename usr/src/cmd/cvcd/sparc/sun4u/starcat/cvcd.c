/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This code implements the Starcat Virtual Console host daemon (see cvcd(1M)).
 * It accepts one TCP connection at a time on a well-known port.  Once a
 * connection is accepted, the console redirection driver (cvcdredir(7D)) is
 * opened, and console I/O is routed back and forth between the two file
 * descriptors (network and redirection driver).  No security is provided or
 * enforced within the daemon, as the Starcat platform uses a network security
 * solution that is transparent to domain-side daemons.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <fcntl.h>
#include <sys/filio.h>		/* Just to get FIONBIO... */
#include <unistd.h>
#include <errno.h>
#include <stropts.h>
#include <signal.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <locale.h>
#include <limits.h>

#include <sys/priocntl.h>
#include <sys/tspriocntl.h>
#include <sys/rtpriocntl.h>

#include <netdb.h>
#include <sys/socket.h>
#include <tiuser.h>

#include <sys/sc_cvcio.h>


/*
 *  Misc. defines.
 */
#define	NODENAME	"/etc/nodename"
#define	NETWORK_PFD	0
#define	REDIR_PFD	1
#define	LISTEN_PFD	2
#define	NUM_PFDS	3

/*
 * Function prototypes
 */
static void cvcd_set_priority(void);
static int  cvcd_init_host_socket(int port);
static void cvcd_do_network_console(void);
static void cvcd_err(int code, char *format, ...);
static void cvcd_usage(void);

/*
 *  Globals
 */
static struct pollfd	pfds[NUM_PFDS];
static char		progname[MAXPATHLEN];
static int		debug = 0;

main(int argc, char **argv)
{
	int			err;
	int			opt;
	int			tport = 0;
	char			*hostname;
	struct utsname		utsname;
	int			fd;
	int			i;
	struct servent		*se;
	char 			prefix[256];

	(void) setlocale(LC_ALL, "");
	(void) strcpy(progname, argv[0]);

#ifdef DEBUG
	while ((opt = getopt(argc, argv, "dp:")) != EOF) {
#else
	while ((opt = getopt(argc, argv, "")) != EOF) {
#endif
		switch (opt) {
#ifdef DEBUG
			case 'd' :	debug = 1;
					break;

			case 'p' :	tport = atoi(optarg);
					break;
#endif  /* DEBUG */

			default  :	cvcd_usage();
					exit(1);
		}
	}

	if (uname(&utsname) == -1) {
		perror("HOSTNAME not defined");
		exit(1);
	}
	hostname = utsname.nodename;

	/*
	 * hostname may still be NULL, depends on when cvcd was started
	 * in the boot sequence.  If it is NULL, try one more time
	 * to get a hostname -> look in the /etc/nodename file.
	 */
	if (!strlen(hostname)) {
		/*
		 * try to get the hostname from the /etc/nodename file
		 * we reuse the utsname.nodename buffer here!  hostname
		 * already points to it.
		 */
		if ((fd = open(NODENAME, O_RDONLY)) > 0) {
			if ((i = read(fd, utsname.nodename, SYS_NMLN)) <= 0) {
				cvcd_err(LOG_WARNING,
				    "failed to acquire hostname");
			} else {
				utsname.nodename[i-1] = '\0';
			}
			(void) close(fd);
		}
	}
	/*
	 * If all attempts to get the hostname have failed, put something
	 * meaningful in the buffer.
	 */
	if (!strlen(hostname)) {
		(void) strcpy(utsname.nodename, "(unknown)");
	}

	/*
	 * Must be root.
	 */
	if (debug == 0 && geteuid() != 0) {
		fprintf(stderr, "cvcd: Must be root");
		exit(1);
	}

	/*
	 * Daemonize...
	 */
	if (debug == 0) {
		for (i = 0; i < OPEN_MAX; i++) {
			if (debug && (i == STDERR_FILENO)) {
				/* Don't close stderr in debug mode! */
				continue;
			}
			(void) close(i);
		}
		(void) chdir("/");
		(void) umask(0);
		if (fork() != 0) {
			exit(0);
		}
		(void) setpgrp();
		(void) sprintf(prefix, "%s-(HOSTNAME:%s)", progname, hostname);
		openlog(prefix, LOG_CONS | LOG_NDELAY, LOG_LOCAL0);
	}

	/*
	 * Initialize the array of pollfds used to track the listening socket,
	 * the connection to the console redirection driver, and the network
	 * connection.
	 */
	(void) memset((void *)pfds, 0, NUM_PFDS * sizeof (struct pollfd));
	for (i = 0; i < NUM_PFDS; i++) {
		pfds[i].fd = -1;
	}

	/* SPR 94004 */
	(void) sigignore(SIGTERM);

	/*
	 * SPR 83644: cvc and kadb are not compatible under heavy loads.
	 *	Fix: will give cvcd highest TS priority at execution time.
	 */
	cvcd_set_priority();

	/*
	 * If not already determined by a command-line flag, figure out which
	 * port we're supposed to be listening on.
	 */
	if (tport == 0) {
		if ((se = getservbyname(CVCD_SERVICE, "tcp")) == NULL) {
			cvcd_err(LOG_ERR, "getservbyname(%s) not found",
				CVCD_SERVICE);
			exit(1);
		}
		tport = se->s_port;
	}

	if (debug == 1) {
		cvcd_err(LOG_DEBUG, "tport = %d, debug = %d", tport, debug);
	}

	/*
	 * Attempt to initialize the socket we'll use to listen for incoming
	 * connections.  No need to check the return value, as the call will
	 * exit if it fails.
	 */
	pfds[LISTEN_PFD].fd = cvcd_init_host_socket(tport);

	/*
	 * Now that we're all set up, we loop forever waiting for connections
	 * (one at a time) and then driving network console activity over them.
	 */
	for (;;) {
		/*
		 * Start by waiting for an incoming connection.
		 */
		do {
			pfds[LISTEN_PFD].events = POLLIN;
			err = poll(&(pfds[LISTEN_PFD]), 1, -1);
			if (err == -1) {
				cvcd_err(LOG_ERR, "poll: %s", strerror(errno));
				exit(1);
			}
			if ((err > 0) &&
			    (pfds[LISTEN_PFD].revents & POLLIN)) {
				fd = accept(pfds[LISTEN_PFD].fd, NULL, NULL);
				if ((fd == -1) && (errno != EWOULDBLOCK)) {
					cvcd_err(LOG_ERR, "accept: %s",
					    strerror(errno));
					exit(1);
				}
			}
		} while (fd == -1);

		/*
		 * We have a connection.  Set the new socket nonblocking, and
		 * initialize the appropriate pollfd.  In theory, the new socket
		 * is _already_ non-blocking because accept() is supposed to
		 * hand us a socket with the same properties as the socket we're
		 * listening on, but it won't hurt to make sure.
		 */
		opt = 1;
		err = ioctl(fd, FIONBIO, &opt);
		if (err == -1) {
			cvcd_err(LOG_ERR, "ioctl: %s", strerror(errno));
			(void) close(fd);
			continue;
		}
		pfds[NETWORK_PFD].fd = fd;

		/*
		 * Since we're ready to do network console stuff, go ahead and
		 * open the Network Console redirection driver, which will
		 * switch traffic from the IOSRAM path to the network path if
		 * the network path has been selected in cvc.
		 */
		fd = open(CVCREDIR_DEV, O_RDWR|O_NDELAY);
		if (fd == -1) {
			cvcd_err(LOG_ERR, "open(redir): %s", strerror(errno));
			exit(1);
		}
		pfds[REDIR_PFD].fd = fd;

		/*
		 * We have a network connection and we have the redirection
		 * driver open, so drive the network console until something
		 * changes.
		 */
		cvcd_do_network_console();

		/*
		 * cvcd_do_network_console doesn't return until there's a
		 * problem, so we need to close the network connection and the
		 * redirection driver and start the whole loop over again.
		 */
		(void) close(pfds[NETWORK_PFD].fd);
		pfds[NETWORK_PFD].fd = -1;
		(void) close(pfds[REDIR_PFD].fd);
		pfds[REDIR_PFD].fd = -1;
	}

	/* NOTREACHED */
	return (1);
}


/*
 * cvcd_set_priority
 *
 * DESCRIBE
 * SPR 83644: cvc and kadb are not compatible under heavy loads.
 *	Fix: will give cvcd highest TS priority at execution time.
 */
static void
cvcd_set_priority(void)
{
	id_t		pid, tsID;
	pcparms_t	pcparms;
	tsparms_t	*tsparmsp;
	short		tsmaxpri;
	pcinfo_t	info;

	pid = getpid();
	pcparms.pc_cid = PC_CLNULL;
	tsparmsp = (tsparms_t *)pcparms.pc_clparms;

	/* Get scheduler properties for this PID */
	if (priocntl(P_PID, pid, PC_GETPARMS, (caddr_t)&pcparms) == -1L) {
		cvcd_err(LOG_ERR, "Warning: can't set priority.");
		cvcd_err(LOG_ERR, "priocntl(GETPARMS): %s", strerror(errno));
		return;
	}

	/* Get class ID and maximum priority for TS process class */
	(void) strcpy(info.pc_clname, "TS");
	if (priocntl(0L, 0L, PC_GETCID, (caddr_t)&info) == -1L) {
		cvcd_err(LOG_ERR, "Warning: can't set priority.");
		cvcd_err(LOG_ERR, "priocntl(GETCID): %s", strerror(errno));
		return;
	}
	tsmaxpri = ((struct tsinfo *)info.pc_clinfo)->ts_maxupri;
	tsID = info.pc_cid;

	/* Print priority info in debug mode */
	if (debug) {
		if (pcparms.pc_cid == tsID) {
			cvcd_err(LOG_DEBUG,
			    "PID: %d, current priority: %d, Max priority: %d.",
			    pid, tsparmsp->ts_upri, tsmaxpri);
		}
	}
	/* Change proc's priority to maxtspri */
	pcparms.pc_cid = tsID;
	tsparmsp->ts_upri = tsmaxpri;
	tsparmsp->ts_uprilim = tsmaxpri;

	if (priocntl(P_PID, pid, PC_SETPARMS, (caddr_t)&pcparms) == -1L) {
		cvcd_err(LOG_ERR, "Warning: can't set priority.");
		cvcd_err(LOG_ERR, "priocntl(SETPARMS): %s", strerror(errno));
	}

	/* Print new priority info in debug mode */
	if (debug) {
		if (priocntl(P_PID, pid, PC_GETPARMS, (caddr_t)&pcparms) ==
		    -1L) {
			cvcd_err(LOG_ERR, "priocntl(GETPARMS): %s",
			    strerror(errno));
		} else {
			cvcd_err(LOG_DEBUG, "PID: %d, new priority: %d.", pid,
			    tsparmsp->ts_upri);
		}
	}
}


/*
 * cvcd_init_host_socket
 *
 * Given a TCP port number, create and initialize a socket appropriate for
 * accepting incoming connections to that port.
 */
static int
cvcd_init_host_socket(int port)
{
	int			err;
	int			fd;
	int			optval;
	int 			optlen = sizeof (optval);
	struct sockaddr_in6	sin6;

	/*
	 * Start by creating the socket, which needs to support IPv6.
	 */
	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		cvcd_err(LOG_ERR, "socket: %s", strerror(errno));
		exit(1);
	}

	/*
	 * Set the SO_REUSEADDR option, and make the socket non-blocking.
	 */
	optval = 1;
	err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
	if (err == -1) {
		cvcd_err(LOG_ERR, "setsockopt: %s", strerror(errno));
		exit(1);
	}

	err = ioctl(fd, FIONBIO, &optval);
	if (err == -1) {
		cvcd_err(LOG_ERR, "ioctl: %s", strerror(errno));
		exit(1);
	}

	/*
	 * Bind the socket to our local address and port.
	 */
	bzero(&sin6, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(port);
	sin6.sin6_addr = in6addr_any;
	err = bind(fd, (struct sockaddr *)&sin6, sizeof (sin6));
	if (err == -1) {
		cvcd_err(LOG_ERR, "bind: %s", strerror(errno));
		exit(1);
	}

	/*
	 * Indicate that we want to accept connections on this socket.  Since we
	 * only allow one connection at a time anyway, specify a maximum backlog
	 * of 1.
	 */
	err = listen(fd, 1);
	if (err == -1) {
		cvcd_err(LOG_ERR, "listen: %s", strerror(errno));
		exit(1);
	}

	return (fd);
}


/*
 * cvcd_do_network_console
 *
 * With established connections to the network and the redirection driver,
 * shuttle data between the two until something goes wrong.
 */
static void
cvcd_do_network_console(void)
{
	int	i;
	int	err;
	int	count;
	short	revents;
	int	input_len = 0;
	int	output_len = 0;
	int	input_off = 0;
	int	output_off = 0;
	char	input_buf[MAXPKTSZ];
	char	output_buf[MAXPKTSZ];

	for (;;) {
		/*
		 * Wait for activity on any of the open file descriptors, which
		 * includes the ability to write data if we have any to write.
		 * If poll() fails, break out of the network console processing
		 * loop.
		 */
		pfds[LISTEN_PFD].events = POLLIN;
		pfds[NETWORK_PFD].events = POLLIN;
		if (output_len != 0) {
			pfds[NETWORK_PFD].events |= POLLOUT;
		}
		pfds[REDIR_PFD].events = POLLIN;
		if (input_len != 0) {
			pfds[REDIR_PFD].events |= POLLOUT;
		}
		err = poll(pfds, NUM_PFDS, -1);
		if (err == -1) {
			cvcd_err(LOG_ERR, "poll: %s", strerror(errno));
			break;
		}

		/*
		 * If any errors or hangups were detected, or one of our file
		 * descriptors is bad, bail out of the network console
		 * processing loop.
		 */
		for (i = 0; i < NUM_PFDS; i++) {
			revents = pfds[i].revents;
			if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
				cvcd_err(LOG_NOTICE,
				    "poll: status on %s fd:%s%s%s",
				    ((i == LISTEN_PFD) ? "listen" :
				    ((i == NETWORK_PFD) ? "network" : "redir")),
				    (revents & POLLERR) ? " error" : "",
				    (revents & POLLHUP) ? " hangup" : "",
				    (revents & POLLNVAL) ? " bad fd" : "");
				goto fail;	/* 'break' wouldn't work here */
			}
		}

		/*
		 * Start by rejecting any connection attempts, since we only
		 * allow one network connection at a time.
		 */
		if (pfds[LISTEN_PFD].revents & POLLIN) {
			int	fd;

			fd = accept(pfds[LISTEN_PFD].fd, NULL, NULL);
			if (fd > 0) {
				(void) close(fd);
			}
		}

		/*
		 * If we have data waiting to be written in one direction or the
		 * other, go ahead and try to send the data on its way.  We're
		 * going to attempt the writes regardless of whether the poll
		 * indicated that the destinations are ready, because we want to
		 * find out if either descriptor has a problem (e.g. broken
		 * network link).
		 * If an "unexpected" error is detected, give up and break out
		 * of the network console processing loop.
		 */
		if (output_len != 0) {
			count = write(pfds[NETWORK_PFD].fd,
			    &(output_buf[output_off]), output_len);
			if ((count == -1) && (errno != EAGAIN)) {
				cvcd_err(LOG_ERR, "write(network): %s",
				    strerror(errno));
				break;
			} else if (count > 0) {
				output_len -= count;
				if (output_len == 0) {
					output_off = 0;
				} else {
					output_off += count;
				}
			}
		}

		if (input_len != 0) {
			count = write(pfds[REDIR_PFD].fd,
			    &(input_buf[input_off]), input_len);
			if ((count == -1) && (errno != EAGAIN)) {
				cvcd_err(LOG_ERR, "write(redir): %s",
				    strerror(errno));
				break;
			} else if (count > 0) {
				input_len -= count;
				if (input_len == 0) {
					input_off = 0;
				} else {
					input_off += count;
				}
			}
		}

		/*
		 * Finally, take a look at each data source and, if there isn't
		 * any residual data from that source still waiting to be
		 * processed, see if more data can be read.  We don't want to
		 * read more data from a source if we haven't finished
		 * processing the last data we read from it because doing so
		 * would maximize the amount of data lost if the network console
		 * failed or was closed.
		 * If an "unexpected" error is detected, give up and break out
		 * of the network console processing loop.
		 * The call to read() appears to be in the habit of returning 0
		 * when you've read all of the data from a stream that has been
		 * hung up, and poll apparently feels that that condition
		 * justifies setting POLLIN, so we're going to treat 0 as an
		 * error return from read().
		 */
		if ((output_len == 0) && (pfds[REDIR_PFD].revents & POLLIN)) {
			count = read(pfds[REDIR_PFD].fd, output_buf, MAXPKTSZ);
			if (count <= 0) {
				/*
				 * Reading 0 simply means there is no data
				 * available, since this is a terminal.
				 */
				if ((count < 0) && (errno != EAGAIN)) {
					cvcd_err(LOG_ERR, "read(redir): %s",
					    strerror(errno));
					break;
				}
			} else {
				output_len = count;
				output_off = 0;
			}
		}

		if ((input_len == 0) && (pfds[NETWORK_PFD].revents & POLLIN)) {
			count = read(pfds[NETWORK_PFD].fd, input_buf, MAXPKTSZ);
			if (count <= 0) {
				/*
				 * Reading 0 here implies a hangup, since this
				 * is a non-blocking socket that poll() reported
				 * as having data available.  This will
				 * typically occur when the console user drops
				 * to OBP or intentially switches to IOSRAM
				 * mode.
				 */
				if (count == 0) {
					cvcd_err(LOG_NOTICE,
					    "read(network): hangup detected");
					break;
				} else if (errno != EAGAIN) {
					cvcd_err(LOG_ERR, "read(network): %s",
					    strerror(errno));
					break;
				}
			} else {
				input_len = count;
				input_off = 0;
			}
		}
	} /* End forever loop */

	/*
	 * If we get here, something bad happened during an attempt to access
	 * either the redirection driver or the network connection.  There
	 * doesn't appear to be any way to avoid the possibility of losing
	 * console input and/or input in that case, so we should at least report
	 * the loss if it happens.
	 * XXX - We could do more, but is it worth the effort?  Logging the
	 *	 lost data would be pretty easy... actually preserving it
	 *	 in the console flow would be a lot harder.  We're more robust
	 *	 than the previous generation at this point, at least, so
	 *	 perhaps that's enough for now?
	 */
fail:
	if (input_len != 0) {
		cvcd_err(LOG_ERR, "console input lost");
	}
	if (output_len != 0) {
		cvcd_err(LOG_ERR, "console output lost");
	}
}


static void
cvcd_usage()
{
#if defined(DEBUG)
	(void) printf("%s [-d] [-p port]\n", progname);
#else
	(void) printf("%s\n", progname);
#endif  /* DEBUG */
}

/*
 * cvcd_err ()
 *
 * Description:
 * Log messages via syslog daemon.
 *
 * Input:
 * code - logging code
 * format - messages to log
 *
 * Output:
 * void
 *
 */
static void
cvcd_err(int code, char *format, ...)
{
	va_list	varg_ptr;
	char	buf[MAXPKTSZ];

	va_start(varg_ptr, format);
	(void) vsnprintf(buf, MAXPKTSZ, format, varg_ptr);
	va_end(varg_ptr);

	if (debug == 0) {
		syslog(code, buf);
	} else {
		(void) fprintf(stderr, "%s: %s\n", progname, buf);
	}
}
