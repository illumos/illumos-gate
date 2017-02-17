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
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Trivial file transfer protocol server.  A top level process runs in
 * an infinite loop fielding new TFTP requests.  A child process,
 * communicating via a pipe with the top level process, sends delayed
 * NAKs for those that we can't handle.  A new child process is created
 * to service each request that we can handle.  The top level process
 * exits after a period of time during which no new requests are
 * received.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <setjmp.h>
#include <syslog.h>
#include <sys/param.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <priv_utils.h>
#include "tftpcommon.h"

#define	TIMEOUT		5
#define	DELAY_SECS	3
#define	DALLYSECS 60

#define	SYSLOG_MSG(message) \
	(syslog((((errno == ENETUNREACH) || (errno == EHOSTUNREACH) || \
		(errno == ECONNREFUSED)) ? LOG_WARNING : LOG_ERR), message))

static int			rexmtval = TIMEOUT;
static int			maxtimeout = 5*TIMEOUT;
static int			securetftp;
static int			debug;
static int			disable_pnp;
static int			standalone;
static uid_t			uid_nobody = UID_NOBODY;
static uid_t			gid_nobody = GID_NOBODY;
static int			reqsock = -1;
				/* file descriptor of request socket */
static socklen_t		fromlen;
static socklen_t		fromplen;
static struct sockaddr_storage	client;
static struct sockaddr_in6 	*sin6_ptr;
static struct sockaddr_in	*sin_ptr;
static struct sockaddr_in6	*from6_ptr;
static struct sockaddr_in	*from_ptr;
static int			addrfmly;
static int			peer;
static off_t			tsize;
static tftpbuf			ackbuf;
static struct sockaddr_storage	from;
static boolean_t		tsize_set;
static pid_t			child;
				/* pid of child handling delayed replys */
static int			delay_fd [2];
				/* pipe for communicating with child */
static FILE			*file;
static char			*filename;

static union {
	struct tftphdr	hdr;
	char		data[SEGSIZE + 4];
} buf;

static union {
	struct tftphdr	hdr;
	char		data[SEGSIZE];
} oackbuf;

struct	delay_info {
	long	timestamp;		/* time request received */
	int	ecode;			/* error code to return */
	struct	sockaddr_storage from;	/* address of client */
};

int	blocksize = SEGSIZE;	/* Number of data bytes in a DATA packet */

/*
 * Default directory for unqualified names
 * Used by TFTP boot procedures
 */
static char	*homedir = "/tftpboot";

struct formats {
	char	*f_mode;
	int	(*f_validate)(int);
	void	(*f_send)(struct formats *, int);
	void	(*f_recv)(struct formats *, int);
	int	f_convert;
};

static void	delayed_responder(void);
static void	tftp(struct tftphdr *, int);
static int	validate_filename(int);
static void	tftpd_sendfile(struct formats *, int);
static void	tftpd_recvfile(struct formats *, int);
static void	nak(int);
static char	*blksize_handler(int, char *, int *);
static char	*timeout_handler(int, char *, int *);
static char	*tsize_handler(int, char *, int *);

static struct formats formats[] = {
	{ "netascii",	validate_filename, tftpd_sendfile, tftpd_recvfile, 1 },
	{ "octet",	validate_filename, tftpd_sendfile, tftpd_recvfile, 0 },
	{ NULL }
};

struct options {
	char	*opt_name;
	char	*(*opt_handler)(int, char *, int *);
};

static struct options options[] = {
	{ "blksize",	blksize_handler },
	{ "timeout",	timeout_handler },
	{ "tsize",	tsize_handler },
	{ NULL }
};

static char		optbuf[MAX_OPTVAL_LEN];
static int		timeout;
static sigjmp_buf	timeoutbuf;

int
main(int argc, char **argv)
{
	struct tftphdr *tp;
	int n;
	int c;
	struct	passwd *pwd;		/* for "nobody" entry */
	struct in_addr ipv4addr;
	char abuf[INET6_ADDRSTRLEN];
	socklen_t addrlen;

	openlog("tftpd", LOG_PID, LOG_DAEMON);

	pwd = getpwnam("nobody");
	if (pwd != NULL) {
		uid_nobody = pwd->pw_uid;
		gid_nobody = pwd->pw_gid;
	}

	/* Tftp will not start new executables; clear the limit set.  */
	(void) __init_daemon_priv(PU_CLEARLIMITSET, uid_nobody, gid_nobody,
	    PRIV_PROC_CHROOT, PRIV_NET_PRIVADDR, NULL);

	/* Remove the unneeded basic privileges everywhere. */
	(void) priv_set(PRIV_OFF, PRIV_ALLSETS, PRIV_PROC_EXEC,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, PRIV_PROC_SESSION, NULL);

	/* Remove the other privileges from E until we need them. */
	(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_CHROOT,
	    PRIV_NET_PRIVADDR, NULL);

	while ((c = getopt(argc, argv, "dspST:")) != EOF)
		switch (c) {
		case 'd':		/* enable debug */
			debug++;
			continue;
		case 's':		/* secure daemon */
			securetftp = 1;
			continue;
		case 'p':		/* disable name pnp mapping */
			disable_pnp = 1;
			continue;
		case 'S':
			standalone = 1;
			continue;
		case 'T':
			rexmtval = atoi(optarg);
			if (rexmtval <= 0 || rexmtval > MAX_TIMEOUT) {
				(void) fprintf(stderr,
				    "%s: Invalid retransmission "
				    "timeout value: %s\n", argv[0], optarg);
				exit(1);
			}
			maxtimeout = 5 * rexmtval;
			continue;
		case '?':
		default:
usage:
			(void) fprintf(stderr,
			    "usage: %s [-T rexmtval] [-spd] [home-directory]\n",
			    argv[0]);
			for (; optind < argc; optind++)
				syslog(LOG_ERR, "bad argument %s",
				    argv[optind]);
			exit(1);
		}

	if (optind < argc)
		if (optind == argc - 1 && *argv [optind] == '/')
			homedir = argv [optind];
		else
			goto usage;

	if (pipe(delay_fd) < 0) {
		syslog(LOG_ERR, "pipe (main): %m");
		exit(1);
	}

	(void) sigset(SIGCHLD, SIG_IGN); /* no zombies please */

	if (standalone) {
		socklen_t clientlen;

		sin6_ptr = (struct sockaddr_in6 *)&client;
		clientlen = sizeof (struct sockaddr_in6);
		reqsock = socket(AF_INET6, SOCK_DGRAM, 0);
		if (reqsock == -1) {
			perror("socket");
			exit(1);
		}
		(void) memset(&client, 0, clientlen);
		sin6_ptr->sin6_family = AF_INET6;
		sin6_ptr->sin6_port = htons(IPPORT_TFTP);

		/* Enable privilege as tftp port is < 1024 */
		(void) priv_set(PRIV_ON,
		    PRIV_EFFECTIVE, PRIV_NET_PRIVADDR, NULL);
		if (bind(reqsock, (struct sockaddr *)&client,
		    clientlen) == -1) {
			perror("bind");
			exit(1);
		}
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_NET_PRIVADDR,
		    NULL);

		if (debug)
			(void) puts("running in standalone mode...");
	} else {
		/* request socket passed on fd 0 by inetd */
		reqsock = 0;
	}
	if (debug) {
		int on = 1;

		(void) setsockopt(reqsock, SOL_SOCKET, SO_DEBUG,
		    (char *)&on, sizeof (on));
	}

	(void) chdir(homedir);

	(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);
	if ((child = fork()) < 0) {
		syslog(LOG_ERR, "fork (main): %m");
		exit(1);
	}
	(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);

	if (child == 0) {
		delayed_responder();
	} /* child */

	/* close read side of pipe */
	(void) close(delay_fd[0]);


	/*
	 * Top level handling of incomming tftp requests.  Read a request
	 * and pass it off to be handled.  If request is valid, handling
	 * forks off and parent returns to this loop.  If no new requests
	 * are received for DALLYSECS, exit and return to inetd.
	 */

	for (;;) {
		fd_set readfds;
		struct timeval dally;

		FD_ZERO(&readfds);
		FD_SET(reqsock, &readfds);
		dally.tv_sec = DALLYSECS;
		dally.tv_usec = 0;

		n = select(reqsock + 1, &readfds, NULL, NULL, &dally);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "select: %m");
			(void) kill(child, SIGKILL);
			exit(1);
		}
		if (n == 0) {
			/* Select timed out.  Its time to die. */
			if (standalone)
				continue;
			else {
				(void) kill(child, SIGKILL);
				exit(0);
			}
		}
		addrlen = sizeof (from);
		if (getsockname(reqsock, (struct sockaddr  *)&from,
		    &addrlen) < 0) {
			syslog(LOG_ERR, "getsockname: %m");
			exit(1);
		}

		switch (from.ss_family) {
		case AF_INET:
			fromlen = (socklen_t)sizeof (struct sockaddr_in);
			break;
		case AF_INET6:
			fromlen = (socklen_t)sizeof (struct sockaddr_in6);
			break;
		default:
			syslog(LOG_ERR,
			    "Unknown address Family on peer connection %d",
			    from.ss_family);
			exit(1);
		}

		n = recvfrom(reqsock, &buf, sizeof (buf), 0,
		    (struct sockaddr *)&from, &fromlen);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (standalone)
				perror("recvfrom");
			else
				syslog(LOG_ERR, "recvfrom: %m");
			(void) kill(child, SIGKILL);
			exit(1);
		}

		(void) alarm(0);

		switch (from.ss_family) {
		case AF_INET:
			addrfmly = AF_INET;
			fromplen = sizeof (struct sockaddr_in);
			sin_ptr = (struct sockaddr_in *)&client;
			(void) memset(&client, 0, fromplen);
			sin_ptr->sin_family = AF_INET;
			break;
		case AF_INET6:
			addrfmly = AF_INET6;
			fromplen = sizeof (struct sockaddr_in6);
			sin6_ptr = (struct sockaddr_in6 *)&client;
			(void) memset(&client, 0, fromplen);
			sin6_ptr->sin6_family = AF_INET6;
			break;
		default:
			syslog(LOG_ERR,
			    "Unknown address Family on peer connection");
			exit(1);
		}
		peer = socket(addrfmly, SOCK_DGRAM, 0);
		if (peer < 0) {
			if (standalone)
				perror("socket (main)");
			else
				syslog(LOG_ERR, "socket (main): %m");
			(void) kill(child, SIGKILL);
			exit(1);
		}
		if (debug) {
			int on = 1;

			(void) setsockopt(peer, SOL_SOCKET, SO_DEBUG,
			    (char *)&on, sizeof (on));
		}

		if (bind(peer, (struct sockaddr *)&client, fromplen) < 0) {
			if (standalone)
				perror("bind (main)");
			else
				syslog(LOG_ERR, "bind (main): %m");
			(void) kill(child, SIGKILL);
			exit(1);
		}
		if (standalone && debug) {
			sin6_ptr = (struct sockaddr_in6 *)&client;
			from6_ptr = (struct sockaddr_in6 *)&from;
			if (IN6_IS_ADDR_V4MAPPED(&from6_ptr->sin6_addr)) {
				IN6_V4MAPPED_TO_INADDR(&from6_ptr->sin6_addr,
				    &ipv4addr);
				(void) inet_ntop(AF_INET, &ipv4addr, abuf,
				    sizeof (abuf));
			} else {
				(void) inet_ntop(AF_INET6,
				    &from6_ptr->sin6_addr, abuf,
				    sizeof (abuf));
			}
			/* get local port */
			if (getsockname(peer, (struct sockaddr *)&client,
			    &fromplen) < 0)
				perror("getsockname (main)");
			(void) fprintf(stderr,
			    "request from %s port %d; local port %d\n",
			    abuf, from6_ptr->sin6_port, sin6_ptr->sin6_port);
		}
		tp = &buf.hdr;
		tp->th_opcode = ntohs((ushort_t)tp->th_opcode);
		if (tp->th_opcode == RRQ || tp->th_opcode == WRQ)
			tftp(tp, n);

		(void) close(peer);
		(void) fclose(file);
	}

	/*NOTREACHED*/
	return (0);
}

static void
delayed_responder(void)
{
	struct delay_info dinfo;
	long now;

	/* we don't use the descriptors passed in to the parent */
	(void) close(0);
	(void) close(1);
	if (standalone)
		(void) close(reqsock);

	/* close write side of pipe */
	(void) close(delay_fd[1]);

	for (;;) {
		int n;

		if ((n = read(delay_fd[0], &dinfo,
		    sizeof (dinfo))) != sizeof (dinfo)) {
			if (n < 0) {
				if (errno == EINTR)
					continue;
				if (standalone)
					perror("read from pipe "
					    "(delayed responder)");
				else
					syslog(LOG_ERR, "read from pipe: %m");
			}
			exit(1);
		}
		switch (dinfo.from.ss_family) {
		case AF_INET:
			addrfmly = AF_INET;
			fromplen = sizeof (struct sockaddr_in);
			sin_ptr = (struct sockaddr_in *)&client;
			(void) memset(&client, 0, fromplen);
			sin_ptr->sin_family = AF_INET;
			break;
		case AF_INET6:
			addrfmly = AF_INET6;
			fromplen = sizeof (struct sockaddr_in6);
			sin6_ptr = (struct sockaddr_in6 *)&client;
			(void) memset(&client, 0, fromplen);
			sin6_ptr->sin6_family = AF_INET6;
			break;
		}
		peer = socket(addrfmly, SOCK_DGRAM, 0);
		if (peer == -1) {
			if (standalone)
				perror("socket (delayed responder)");
			else
				syslog(LOG_ERR, "socket (delay): %m");
			exit(1);
		}
		if (debug) {
			int on = 1;

			(void) setsockopt(peer, SOL_SOCKET, SO_DEBUG,
			    (char *)&on, sizeof (on));
		}

		if (bind(peer, (struct sockaddr *)&client, fromplen) < 0) {
			if (standalone)
				perror("bind (delayed responder)");
			else
				syslog(LOG_ERR, "bind (delay): %m");
			exit(1);
		}
		if (client.ss_family == AF_INET) {
			from_ptr = (struct sockaddr_in *)&dinfo.from;
			from_ptr->sin_family = AF_INET;
		} else {
			from6_ptr = (struct sockaddr_in6 *)&dinfo.from;
			from6_ptr->sin6_family = AF_INET6;
		}
		/*
		 * Since a request hasn't been received from the client
		 * before the delayed responder process is forked, the
		 * from variable is uninitialized.  So set it to contain
		 * the client address.
		 */
		from = dinfo.from;

		/*
		 * only sleep if DELAY_SECS has not elapsed since
		 * original request was received.  Ensure that `now'
		 * is not earlier than `dinfo.timestamp'
		 */
		now = time(0);
		if ((uint_t)(now - dinfo.timestamp) < DELAY_SECS)
			(void) sleep(DELAY_SECS - (now - dinfo.timestamp));
		nak(dinfo.ecode);
		(void) close(peer);
	} /* for */

	/* NOTREACHED */
}

/*
 * Handle the Blocksize option.
 * Return the blksize option value string to include in the OACK reply.
 */
/*ARGSUSED*/
static char *
blksize_handler(int opcode, char *optval, int *errcode)
{
	char *endp;
	int value;

	*errcode = -1;
	errno = 0;
	value = (int)strtol(optval, &endp, 10);
	if (errno != 0 || value < MIN_BLKSIZE || *endp != '\0')
		return (NULL);
	/*
	 * As the blksize value in the OACK reply can be less than the value
	 * requested, to support broken clients if the value requested is larger
	 * than allowed in the RFC, reply with the maximum value permitted.
	 */
	if (value > MAX_BLKSIZE)
		value = MAX_BLKSIZE;

	blocksize = value;
	(void) snprintf(optbuf, sizeof (optbuf), "%d", blocksize);
	return (optbuf);
}

/*
 * Handle the Timeout Interval option.
 * Return the timeout option value string to include in the OACK reply.
 */
/*ARGSUSED*/
static char *
timeout_handler(int opcode, char *optval, int *errcode)
{
	char *endp;
	int value;

	*errcode = -1;
	errno = 0;
	value = (int)strtol(optval, &endp, 10);
	if (errno != 0 || *endp != '\0')
		return (NULL);
	/*
	 * The timeout value in the OACK reply must match the value specified
	 * by the client, so if an invalid timeout is requested don't include
	 * the timeout option in the OACK reply.
	 */
	if (value < MIN_TIMEOUT || value > MAX_TIMEOUT)
		return (NULL);

	rexmtval = value;
	maxtimeout = 5 * rexmtval;
	(void) snprintf(optbuf, sizeof (optbuf), "%d", rexmtval);
	return (optbuf);
}

/*
 * Handle the Transfer Size option.
 * Return the tsize option value string to include in the OACK reply.
 */
static char *
tsize_handler(int opcode, char *optval, int *errcode)
{
	char *endp;
	longlong_t value;

	*errcode = -1;
	errno = 0;
	value = strtoll(optval, &endp, 10);
	if (errno != 0 || value < 0 || *endp != '\0')
		return (NULL);

	if (opcode == RRQ) {
		if (tsize_set == B_FALSE)
			return (NULL);
		/*
		 * The tsize value should be 0 for a read request, but to
		 * support broken clients we don't check that it is.
		 */
	} else {
#if _FILE_OFFSET_BITS == 32
		if (value > MAXOFF_T) {
			*errcode = ENOSPACE;
			return (NULL);
		}
#endif
		tsize = value;
		tsize_set = B_TRUE;
	}
	(void) snprintf(optbuf, sizeof (optbuf), OFF_T_FMT, tsize);
	return (optbuf);
}

/*
 * Process any options included by the client in the request packet.
 * Return the size of the OACK reply packet built or 0 for no OACK reply.
 */
static int
process_options(int opcode, char *opts, char *endopts)
{
	char *cp, *optname, *optval, *ostr, *oackend;
	struct tftphdr *oackp;
	int i, errcode;

	/*
	 * To continue to interoperate with broken TFTP clients, ignore
	 * null padding appended to requests which don't include options.
	 */
	cp = opts;
	while ((cp < endopts) && (*cp == '\0'))
		cp++;
	if (cp == endopts)
		return (0);

	/*
	 * Construct an Option ACKnowledgement packet if any requested option
	 * is recognized.
	 */
	oackp = &oackbuf.hdr;
	oackend = oackbuf.data + sizeof (oackbuf.data);
	oackp->th_opcode = htons((ushort_t)OACK);
	cp = (char *)&oackp->th_stuff;
	while (opts < endopts) {
		optname = opts;
		if ((optval = next_field(optname, endopts)) == NULL) {
			nak(EOPTNEG);
			exit(1);
		}
		if ((opts = next_field(optval, endopts)) == NULL) {
			nak(EOPTNEG);
			exit(1);
		}
		for (i = 0; options[i].opt_name != NULL; i++) {
			if (strcasecmp(optname, options[i].opt_name) == 0)
				break;
		}
		if (options[i].opt_name != NULL) {
			ostr = options[i].opt_handler(opcode, optval, &errcode);
			if (ostr != NULL) {
				cp += strlcpy(cp, options[i].opt_name,
				    oackend - cp) + 1;
				if (cp <= oackend)
					cp += strlcpy(cp, ostr, oackend - cp)
					    + 1;

				if (cp > oackend) {
					nak(EOPTNEG);
					exit(1);
				}
			} else if (errcode >= 0) {
				nak(errcode);
				exit(1);
			}
		}
	}
	if (cp != (char *)&oackp->th_stuff)
		return (cp - oackbuf.data);
	return (0);
}

/*
 * Handle access errors caused by client requests.
 */

static void
delay_exit(int ecode)
{
	struct delay_info dinfo;

	/*
	 * The most likely cause of an error here is that
	 * something has broadcast an RRQ packet because it's
	 * trying to boot and doesn't know who the server is.
	 * Rather then sending an ERROR packet immediately, we
	 * wait a while so that the real server has a better chance
	 * of getting through (in case client has lousy Ethernet
	 * interface).  We write to a child that handles delayed
	 * ERROR packets to avoid delaying service to new
	 * requests.  Of course, we would rather just not answer
	 * RRQ packets that are broadcasted, but there's no way
	 * for a user process to determine this.
	 */

	dinfo.timestamp = time(0);

	/*
	 * If running in secure mode, we map all errors to EACCESS
	 * so that the client gets no information about which files
	 * or directories exist.
	 */
	if (securetftp)
		dinfo.ecode = EACCESS;
	else
		dinfo.ecode = ecode;

	dinfo.from = from;
	if (write(delay_fd[1], &dinfo, sizeof (dinfo)) !=
	    sizeof (dinfo)) {
		syslog(LOG_ERR, "delayed write failed.");
		(void) kill(child, SIGKILL);
		exit(1);
	}
	exit(0);
}

/*
 * Handle initial connection protocol.
 */
static void
tftp(struct tftphdr *tp, int size)
{
	char *cp;
	int readmode, ecode;
	struct formats *pf;
	char *mode;
	int fd;
	static boolean_t firsttime = B_TRUE;
	int oacklen;
	struct stat statb;

	readmode = (tp->th_opcode == RRQ);
	filename = (char *)&tp->th_stuff;
	mode = next_field(filename, &buf.data[size]);
	cp = (mode != NULL) ? next_field(mode, &buf.data[size]) : NULL;
	if (cp == NULL) {
		nak(EBADOP);
		exit(1);
	}
	if (debug && standalone) {
		(void) fprintf(stderr, "%s for %s %s ",
		    readmode ? "RRQ" : "WRQ", filename, mode);
		print_options(stderr, cp, size + buf.data - cp);
		(void) putc('\n', stderr);
	}
	for (pf = formats; pf->f_mode != NULL; pf++)
		if (strcasecmp(pf->f_mode, mode) == 0)
			break;
	if (pf->f_mode == NULL) {
		nak(EBADOP);
		exit(1);
	}

	/*
	 * XXX fork a new process to handle this request before
	 * chroot(), otherwise the parent won't be able to create a
	 * new socket as that requires library access to system files
	 * and devices.
	 */
	(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);
	switch (fork()) {
	case -1:
		syslog(LOG_ERR, "fork (tftp): %m");
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);
		return;
	case 0:
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);
		break;
	default:
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);
		return;
	}

	/*
	 * Try to see if we can access the file.  The access can still
	 * fail later if we are running in secure mode because of
	 * the chroot() call.  We only want to execute the chroot()  once.
	 */
	if (securetftp && firsttime) {
		(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_PROC_CHROOT,
		    NULL);
		if (chroot(homedir) == -1) {
			syslog(LOG_ERR,
			    "tftpd: cannot chroot to directory %s: %m\n",
			    homedir);
			delay_exit(EACCESS);
		}
		else
		{
			firsttime = B_FALSE;
		}
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_CHROOT,
		    NULL);
		(void) chdir("/");  /* cd to  new root */
	}
	(void) priv_set(PRIV_OFF, PRIV_ALLSETS, PRIV_PROC_CHROOT,
	    PRIV_NET_PRIVADDR, NULL);

	ecode = (*pf->f_validate)(tp->th_opcode);
	if (ecode != 0)
		delay_exit(ecode);

	/* we don't use the descriptors passed in to the parent */
	(void) close(STDIN_FILENO);
	(void) close(STDOUT_FILENO);

	/*
	 * Try to open file as low-priv setuid/setgid.  Note that
	 * a chroot() has already been done.
	 */
	fd = open(filename,
	    (readmode ? O_RDONLY : (O_WRONLY|O_TRUNC)) | O_NONBLOCK);
	if ((fd < 0) || (fstat(fd, &statb) < 0))
		delay_exit((errno == ENOENT) ? ENOTFOUND : EACCESS);

	if (((statb.st_mode & ((readmode) ? S_IROTH : S_IWOTH)) == 0) ||
	    ((statb.st_mode & S_IFMT) != S_IFREG))
		delay_exit(EACCESS);

	file = fdopen(fd, readmode ? "r" : "w");
	if (file == NULL)
		delay_exit(errno + 100);

	/* Don't know the size of transfers which involve conversion */
	tsize_set = (readmode && (pf->f_convert == 0));
	if (tsize_set)
		tsize = statb.st_size;

	/* Deal with any options sent by the client */
	oacklen = process_options(tp->th_opcode, cp, buf.data + size);

	if (tp->th_opcode == WRQ)
		(*pf->f_recv)(pf, oacklen);
	else
		(*pf->f_send)(pf, oacklen);

	exit(0);
}

/*
 *	Maybe map filename into another one.
 *
 *	For PNP, we get TFTP boot requests for filenames like
 *	<Unknown Hex IP Addr>.<Architecture Name>.   We must
 *	map these to 'pnp.<Architecture Name>'.  Note that
 *	uppercase is mapped to lowercase in the architecture names.
 *
 *	For names <Hex IP Addr> there are two cases.  First,
 *	it may be a buggy prom that omits the architecture code.
 *	So first check if <Hex IP Addr>.<arch> is on the filesystem.
 *	Second, this is how most Sun3s work; assume <arch> is sun3.
 */

static char *
pnp_check(char *origname)
{
	static char buf [MAXNAMLEN + 1];
	char *arch, *s, *bufend;
	in_addr_t ipaddr;
	int len = (origname ? strlen(origname) : 0);
	DIR *dir;
	struct dirent *dp;

	if (securetftp || disable_pnp || len < 8 || len > 14)
		return (NULL);

	/*
	 * XXX see if this cable allows pnp; if not, return NULL
	 * Requires YP support for determining this!
	 */

	ipaddr = htonl(strtol(origname, &arch, 16));
	if ((arch == NULL) || (len > 8 && *arch != '.'))
		return (NULL);
	if (len == 8)
		arch = "SUN3";
	else
		arch++;

	/*
	 * Allow <Hex IP Addr>* filename request to to be
	 * satisfied by <Hex IP Addr><Any Suffix> rather
	 * than enforcing this to be Sun3 systems.  Also serves
	 * to make case of suffix a don't-care.
	 */
	if ((dir = opendir(homedir)) == NULL)
		return (NULL);
	while ((dp = readdir(dir)) != NULL) {
		if (strncmp(origname, dp->d_name, 8) == 0) {
			(void) strlcpy(buf, dp->d_name, sizeof (buf));
			(void) closedir(dir);
			return (buf);
		}
	}
	(void) closedir(dir);

	/*
	 * XXX maybe call YP master for most current data iff
	 * pnp is enabled.
	 */

	/*
	 * only do mapping PNP boot file name for machines that
	 * are not in the hosts database.
	 */
	if (gethostbyaddr((char *)&ipaddr, sizeof (ipaddr), AF_INET) != NULL)
		return (NULL);

	s = buf + strlcpy(buf, "pnp.", sizeof (buf));
	bufend = &buf[sizeof (buf) - 1];
	while ((*arch != '\0') && (s < bufend))
		*s++ = tolower (*arch++);
	*s = '\0';
	return (buf);
}


/*
 * Try to validate filename. If the filename doesn't exist try PNP mapping.
 */
static int
validate_filename(int mode)
{
	struct stat stbuf;
	char *origfile;

	if (stat(filename, &stbuf) < 0) {
		if (errno != ENOENT)
			return (EACCESS);
		if (mode == WRQ)
			return (ENOTFOUND);

		/* try to map requested filename into a pnp filename */
		origfile = filename;
		filename = pnp_check(origfile);
		if (filename == NULL)
			return (ENOTFOUND);

		if (stat(filename, &stbuf) < 0)
			return (errno == ENOENT ? ENOTFOUND : EACCESS);
		syslog(LOG_NOTICE, "%s -> %s\n", origfile, filename);
	}

	return (0);
}

/* ARGSUSED */
static void
timer(int signum)
{
	timeout += rexmtval;
	if (timeout >= maxtimeout)
		exit(1);
	siglongjmp(timeoutbuf, 1);
}

/*
 * Send the requested file.
 */
static void
tftpd_sendfile(struct formats *pf, int oacklen)
{
	struct tftphdr *dp;
	volatile ushort_t block = 1;
	int size, n, serrno;

	if (oacklen != 0) {
		(void) sigset(SIGALRM, timer);
		timeout = 0;
		(void) sigsetjmp(timeoutbuf, 1);
		if (debug && standalone) {
			(void) fputs("Sending OACK ", stderr);
			print_options(stderr, (char *)&oackbuf.hdr.th_stuff,
			    oacklen - 2);
			(void) putc('\n', stderr);
		}
		if (sendto(peer, &oackbuf, oacklen, 0,
		    (struct sockaddr *)&from, fromplen) != oacklen) {
			if (debug && standalone) {
				serrno = errno;
				perror("sendto (oack)");
				errno = serrno;
			}
			SYSLOG_MSG("sendto (oack): %m");
			goto abort;
		}
		(void) alarm(rexmtval); /* read the ack */
		for (;;) {
			(void) sigrelse(SIGALRM);
			n = recv(peer, &ackbuf, sizeof (ackbuf), 0);
			(void) sighold(SIGALRM);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				serrno = errno;
				SYSLOG_MSG("recv (ack): %m");
				if (debug && standalone) {
					errno = serrno;
					perror("recv (ack)");
				}
				goto abort;
			}
			ackbuf.tb_hdr.th_opcode =
			    ntohs((ushort_t)ackbuf.tb_hdr.th_opcode);
			ackbuf.tb_hdr.th_block =
			    ntohs((ushort_t)ackbuf.tb_hdr.th_block);

			if (ackbuf.tb_hdr.th_opcode == ERROR) {
				if (debug && standalone) {
					(void) fprintf(stderr,
					    "received ERROR %d",
					    ackbuf.tb_hdr.th_code);
					if (n > 4)
						(void) fprintf(stderr,
						    " %.*s", n - 4,
						    ackbuf.tb_hdr.th_msg);
					(void) putc('\n', stderr);
				}
				goto abort;
			}

			if (ackbuf.tb_hdr.th_opcode == ACK) {
				if (debug && standalone)
					(void) fprintf(stderr,
					    "received ACK for block %d\n",
					    ackbuf.tb_hdr.th_block);
				if (ackbuf.tb_hdr.th_block == 0)
					break;
				/*
				 * Don't resend the OACK, avoids getting stuck
				 * in an OACK/ACK loop if the client keeps
				 * replying with a bad ACK. Client will either
				 * send a good ACK or timeout sending bad ones.
				 */
			}
		}
		cancel_alarm();
	}
	dp = r_init();
	do {
		(void) sigset(SIGALRM, timer);
		size = readit(file, &dp, pf->f_convert);
		if (size < 0) {
			nak(errno + 100);
			goto abort;
		}
		dp->th_opcode = htons((ushort_t)DATA);
		dp->th_block = htons((ushort_t)block);
		timeout = 0;
		(void) sigsetjmp(timeoutbuf, 1);
		if (debug && standalone)
			(void) fprintf(stderr, "Sending DATA block %d\n",
			    block);
		if (sendto(peer, dp, size + 4, 0,
		    (struct sockaddr *)&from,  fromplen) != size + 4) {
			if (debug && standalone) {
				serrno = errno;
				perror("sendto (data)");
				errno = serrno;
			}
			SYSLOG_MSG("sendto (data): %m");
			goto abort;
		}
		read_ahead(file, pf->f_convert);
		(void) alarm(rexmtval); /* read the ack */
		for (;;) {
			(void) sigrelse(SIGALRM);
			n = recv(peer, &ackbuf, sizeof (ackbuf), 0);
			(void) sighold(SIGALRM);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				serrno = errno;
				SYSLOG_MSG("recv (ack): %m");
				if (debug && standalone) {
					errno = serrno;
					perror("recv (ack)");
				}
				goto abort;
			}
			ackbuf.tb_hdr.th_opcode =
			    ntohs((ushort_t)ackbuf.tb_hdr.th_opcode);
			ackbuf.tb_hdr.th_block =
			    ntohs((ushort_t)ackbuf.tb_hdr.th_block);

			if (ackbuf.tb_hdr.th_opcode == ERROR) {
				if (debug && standalone) {
					(void) fprintf(stderr,
					    "received ERROR %d",
					    ackbuf.tb_hdr.th_code);
					if (n > 4)
						(void) fprintf(stderr,
						    " %.*s", n - 4,
						    ackbuf.tb_hdr.th_msg);
					(void) putc('\n', stderr);
				}
				goto abort;
			}

			if (ackbuf.tb_hdr.th_opcode == ACK) {
				if (debug && standalone)
					(void) fprintf(stderr,
					    "received ACK for block %d\n",
					    ackbuf.tb_hdr.th_block);
				if (ackbuf.tb_hdr.th_block == block) {
					break;
				}
				/*
				 * Never resend the current DATA packet on
				 * receipt of a duplicate ACK, doing so would
				 * cause the "Sorcerer's Apprentice Syndrome".
				 */
			}
		}
		cancel_alarm();
		block++;
	} while (size == blocksize);

abort:
	cancel_alarm();
	(void) fclose(file);
}

/* ARGSUSED */
static void
justquit(int signum)
{
	exit(0);
}

/*
 * Receive a file.
 */
static void
tftpd_recvfile(struct formats *pf, int oacklen)
{
	struct tftphdr *dp;
	struct tftphdr *ap;    /* ack buffer */
	ushort_t block = 0;
	int n, size, acklen, serrno;

	dp = w_init();
	ap = &ackbuf.tb_hdr;
	do {
		(void) sigset(SIGALRM, timer);
		timeout = 0;
		if (oacklen == 0) {
			ap->th_opcode = htons((ushort_t)ACK);
			ap->th_block = htons((ushort_t)block);
			acklen = 4;
		} else {
			/* copy OACK packet to the ack buffer ready to send */
			(void) memcpy(&ackbuf, &oackbuf, oacklen);
			acklen = oacklen;
			oacklen = 0;
		}
		block++;
		(void) sigsetjmp(timeoutbuf, 1);
send_ack:
		if (debug && standalone) {
			if (ap->th_opcode == htons((ushort_t)ACK)) {
				(void) fprintf(stderr,
				    "Sending ACK for block %d\n", block - 1);
			} else {
				(void) fprintf(stderr, "Sending OACK ");
				print_options(stderr, (char *)&ap->th_stuff,
				    acklen - 2);
				(void) putc('\n', stderr);
			}
		}
		if (sendto(peer, &ackbuf, acklen, 0, (struct sockaddr *)&from,
		    fromplen) != acklen) {
			if (ap->th_opcode == htons((ushort_t)ACK)) {
				if (debug && standalone) {
					serrno = errno;
					perror("sendto (ack)");
					errno = serrno;
				}
				syslog(LOG_ERR, "sendto (ack): %m\n");
			} else {
				if (debug && standalone) {
					serrno = errno;
					perror("sendto (oack)");
					errno = serrno;
				}
				syslog(LOG_ERR, "sendto (oack): %m\n");
			}
			goto abort;
		}
		if (write_behind(file, pf->f_convert) < 0) {
			nak(errno + 100);
			goto abort;
		}
		(void) alarm(rexmtval);
		for (;;) {
			(void) sigrelse(SIGALRM);
			n = recv(peer, dp, blocksize + 4, 0);
			(void) sighold(SIGALRM);
			if (n < 0) { /* really? */
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "recv (data): %m");
				goto abort;
			}
			dp->th_opcode = ntohs((ushort_t)dp->th_opcode);
			dp->th_block = ntohs((ushort_t)dp->th_block);
			if (dp->th_opcode == ERROR) {
				cancel_alarm();
				if (debug && standalone) {
					(void) fprintf(stderr,
					    "received ERROR %d", dp->th_code);
					if (n > 4)
						(void) fprintf(stderr,
						    " %.*s", n - 4, dp->th_msg);
					(void) putc('\n', stderr);
				}
				return;
			}
			if (dp->th_opcode == DATA) {
				if (debug && standalone)
					(void) fprintf(stderr,
					    "Received DATA block %d\n",
					    dp->th_block);
				if (dp->th_block == block) {
					break;   /* normal */
				}
				/* Re-synchronize with the other side */
				if (synchnet(peer) < 0) {
					nak(errno + 100);
					goto abort;
				}
				if (dp->th_block == (block-1))
					goto send_ack; /* rexmit */
			}
		}
		cancel_alarm();
		/*  size = write(file, dp->th_data, n - 4); */
		size = writeit(file, &dp, n - 4, pf->f_convert);
		if (size != (n - 4)) {
			nak((size < 0) ? (errno + 100) : ENOSPACE);
			goto abort;
		}
	} while (size == blocksize);
	if (write_behind(file, pf->f_convert) < 0) {
		nak(errno + 100);
		goto abort;
	}
	n = fclose(file);	/* close data file */
	file = NULL;
	if (n == EOF) {
		nak(errno + 100);
		goto abort;
	}

	ap->th_opcode = htons((ushort_t)ACK);    /* send the "final" ack */
	ap->th_block = htons((ushort_t)(block));
	if (debug && standalone)
		(void) fprintf(stderr, "Sending ACK for block %d\n", block);
	if (sendto(peer, &ackbuf, 4, 0, (struct sockaddr *)&from,
	    fromplen) == -1) {
		if (debug && standalone)
			perror("sendto (ack)");
	}
	(void) sigset(SIGALRM, justquit); /* just quit on timeout */
	(void) alarm(rexmtval);
	/* normally times out and quits */
	n = recv(peer, dp, blocksize + 4, 0);
	(void) alarm(0);
	dp->th_opcode = ntohs((ushort_t)dp->th_opcode);
	dp->th_block = ntohs((ushort_t)dp->th_block);
	if (n >= 4 &&		/* if read some data */
	    dp->th_opcode == DATA && /* and got a data block */
	    block == dp->th_block) {	/* then my last ack was lost */
		if (debug && standalone) {
			(void) fprintf(stderr, "Sending ACK for block %d\n",
			    block);
		}
		/* resend final ack */
		if (sendto(peer, &ackbuf, 4, 0, (struct sockaddr *)&from,
		    fromplen) == -1) {
			if (debug && standalone)
				perror("sendto (last ack)");
		}
	}

abort:
	cancel_alarm();
	if (file != NULL)
		(void) fclose(file);
}

/*
 * Send a nak packet (error message).
 * Error code passed in is one of the
 * standard TFTP codes, or a UNIX errno
 * offset by 100.
 * Handles connected as well as unconnected peer.
 */
static void
nak(int error)
{
	struct tftphdr *tp;
	int length;
	struct errmsg *pe;
	int ret;

	tp = &buf.hdr;
	tp->th_opcode = htons((ushort_t)ERROR);
	tp->th_code = htons((ushort_t)error);
	for (pe = errmsgs; pe->e_code >= 0; pe++)
		if (pe->e_code == error)
			break;
	if (pe->e_code < 0) {
		pe->e_msg = strerror(error - 100);
		tp->th_code = EUNDEF;   /* set 'undef' errorcode */
	}
	(void) strlcpy(tp->th_msg, (pe->e_msg != NULL) ? pe->e_msg : "UNKNOWN",
	    sizeof (buf) - sizeof (struct tftphdr));
	length = strlen(tp->th_msg);
	length += sizeof (struct tftphdr);
	if (debug && standalone)
		(void) fprintf(stderr, "Sending NAK: %s\n", tp->th_msg);

	ret = sendto(peer, &buf, length, 0, (struct sockaddr *)&from,
	    fromplen);
	if (ret == -1 && errno == EISCONN) {
		/* Try without an address */
		ret = send(peer, &buf, length, 0);
	}
	if (ret == -1) {
		if (standalone)
			perror("sendto (nak)");
		else
			syslog(LOG_ERR, "tftpd: nak: %m\n");
	} else if (ret != length) {
		if (standalone)
			perror("sendto (nak) lost data");
		else
			syslog(LOG_ERR, "tftpd: nak: %d lost\n", length - ret);
	}
}
