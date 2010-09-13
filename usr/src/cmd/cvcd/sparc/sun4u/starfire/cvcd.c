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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * This code implements the Starfire Virtual Console host daemon
 * (see cvcd(1M)).  It accepts a connection from netcon_server
 * and transfers console I/O to/from the SSP across the
 * network via TLI.  The I/O is sent to the cvcredir device
 * on the host (see cvc(7) and cvcredir(7)).  It also sends
 * disconnect and break ioctl's to the kernel CVC drivers.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <tiuser.h>
#include <sys/timod.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/conf.h>
#include <pwd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <locale.h>
#include <termio.h>
#include <signal.h>
#include <sys/cvc.h>

#include <string.h>

#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/sockio.h>

#include <sys/tihdr.h>

#include <netdb.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <inet/common.h>
#include <sys/systeminfo.h>

/* Process priority control */
#include <sys/priocntl.h>
#include <sys/tspriocntl.h>
#include <sys/rtpriocntl.h>

/*
 *  Misc. defines.
 */
#define	CONREF "connection request from illegal host"
#define	SSPHOSTNAMEFILE	"/etc/ssphostname"
#define	NODENAME	"/etc/nodename"
#define	MAXIFS		256

/*
 * Function prototypes
 */
static void cvcd_connect(int fd, struct pollfd *);
static void cvcd_reject(int fd);
static void cvcd_read(struct pollfd *);
static void cvcd_write(char *data, int size);
static void cvcd_status(int fd);
static void cvcd_winch(int, char *, int);
static void cvcd_ioctl(int fd, int cmd);
static void cvcd_err(int code, char *format, ...);
static void usage(void);
static id_t schedinfo(char *name, short *maxpri);
static void cvcd_setopt(int fd, int name);

/*
 *  Globals
 */
static int		rconsfd;	/* Console redirection driver */
static char		progname[MAXPATHLEN];
static char		ssphostname[MAXPATHLEN];
static int		debug = 0;
static int		connected = 0;
static int		peercheck = 1;
static char		nic_name[32];

int
main(int argc, char **argv)
{
	int			opt;
	int			tport = 0;
	char			*hostname;
	struct utsname		utsname;
	struct t_info		tinfo;
	int			cvcd_ssp;
	int			nfd;
	struct pollfd		*cvcd_pfd;
	int			i;
	int			j;
	struct servent		*se;
	struct sockaddr_in	*sin;
	struct t_bind		*reqb;
	struct t_bind		*retb;
	struct t_optmgmt	*topt, *tropt;
	struct opthdr		*sockopt;
	int			on = 1;
	int			tmperr = 0;
	int			event;
	char 			prefix[256];
	pcparms_t	pcparms;
	tsparms_t	*tsparmsp;
	id_t	pid, tsID;
	short	tsmaxpri;
	static int netcon_fail = 0;

	(void) setlocale(LC_ALL, "");
	(void) strcpy(progname, argv[0]);
	(void) memset(ssphostname, 0, MAXPATHLEN);

	if ((cvcd_ssp = open(SSPHOSTNAMEFILE, O_RDONLY)) < 0) {
		/*
		 * If there is no /etc/ssphostname disable peer check after
		 * issuing warning.
		 */
		tmperr = errno;
		peercheck = 0;
	} else {
		if ((i = read(cvcd_ssp, ssphostname, MAXPATHLEN)) < 0) {
			cvcd_err(LOG_ERR, "failed to read ssphostname");
		}
		/*
		 * The ssp-config(1M) command newline terminates the
		 * ssphostname in the /etc/ssphostname file
		 */
		ssphostname[i-1] = '\0';
		(void) close(cvcd_ssp);

		(void) memset(nic_name, 0, sizeof (nic_name));
	}

#if defined(DEBUG)
	while ((opt = getopt(argc, argv, "dp:r:")) != EOF) {
#else
	while ((opt = getopt(argc, argv, "r:")) != EOF) {
#endif  /* DEBUG */
		switch (opt) {

#if defined(DEBUG)
			case 'd' :	debug = 1;
					break;

			case 'p' :	tport = atoi(optarg);
					break;
#endif  /* DEBUG */

			case 'r' :	(void) strcpy(ssphostname, optarg);
					break;

			default  :	usage();
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
		if ((nfd = open(NODENAME, O_RDONLY)) > 0) {
			if ((i = read(nfd, utsname.nodename, SYS_NMLN)) <= 0) {
				cvcd_err(LOG_WARNING,
				"failed to acquire hostname");
			}
			utsname.nodename[i-1] = '\0';
			(void) close(nfd);
		}
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
		for (i = 0; i < NOFILE; i++) {
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
	if (peercheck == 0) {
		cvcd_err(LOG_ERR, "open(SSPHOSTNAMEFILE):%s",
		    strerror(tmperr));
	}

	cvcd_pfd = (struct pollfd *)malloc(3*sizeof (struct pollfd));
	if (cvcd_pfd == (struct pollfd *)NULL) {
		cvcd_err(LOG_ERR, "malloc:", strerror(errno));
		exit(1);
	}
	(void) memset((void *)cvcd_pfd, 0, 3*sizeof (struct pollfd));
	cvcd_pfd[0].fd = -1;
	cvcd_pfd[1].fd = -1;
	cvcd_pfd[2].fd = -1;

	/* SPR 94004 */
	(void) sigignore(SIGTERM);

	/*
	 * SPR 83644: cvc and kadb are not compatible under heavy loads.
	 *	Fix: will give cvcd highest TS priority at execution time.
	 */
	pid = getpid();
	pcparms.pc_cid = PC_CLNULL;
	tsparmsp = (tsparms_t *)pcparms.pc_clparms;

	/* Get scheduler properties for this PID */
	if (priocntl(P_PID, pid, PC_GETPARMS, (caddr_t)&pcparms) == -1L) {
		cvcd_err(LOG_ERR,
			"cvcd: GETPARMS failed. Warning: can't get ",
			"TS priorities.");
	} else {
		/* Get class IDs and maximum priorities for a TS process */
		if ((tsID = schedinfo("TS", &tsmaxpri)) == -1) {
			cvcd_err(LOG_ERR, "cvcd: Warning, can't get ",
				"TS scheduler info.");
		} else {
			if (debug) {	/* Print priority info */
				if (pcparms.pc_cid == tsID) {
					cvcd_err(LOG_DEBUG, "%s%d%s%d%s%d\n",
						"cvcd:: PID:", pid,
						", TS priority:",
						tsparmsp->ts_upri,
						", TS max_pri:", tsmaxpri);
				}
			}
			/* Change proc's priority to maxtspri */
			pcparms.pc_cid = tsID;
			tsparmsp = (struct tsparms *)pcparms.pc_clparms;
			tsparmsp->ts_upri = tsmaxpri;
			tsparmsp->ts_uprilim = tsmaxpri;

			if (priocntl(P_PID, pid, PC_SETPARMS,
				(caddr_t)&pcparms) == -1L) {
				cvcd_err(LOG_ERR, "cvcd: Warning, ",
					"can't set TS maximum priority.");
			}
			/* Done */
			if (debug) { /* Get new scheduler properties for PID */
				if (priocntl(P_PID, pid, PC_GETPARMS,
					(caddr_t)&pcparms) == -1L) {
					cvcd_err(LOG_DEBUG, "GETPARMS failed");
					exit(1);
				} else {
					cvcd_err(LOG_DEBUG, "%s%d%s%d%s%d\n",
						"cvcd:: PID:", pid,
						", New TS priority:",
						tsparmsp->ts_upri,
						", TS max_pri:", tsmaxpri);
				}
			}
		}
	}

	if (debug == 1) {
		cvcd_err(LOG_DEBUG, "tport = %d, debug = %d", tport, debug);
	}

	if (tport == 0) {
		if ((se = getservbyname(CVCD_SERVICE, "tcp")) == NULL) {
			cvcd_err(LOG_ERR, "getservbyname(%s) not found",
				CVCD_SERVICE);
			exit(1);
		}
		tport = se->s_port;
	}

	cvcd_ssp = t_open(TCP_DEV, O_RDWR, &tinfo);
	if (cvcd_ssp == -1) {
		cvcd_err(LOG_ERR, "t_open: %s", t_errlist[t_errno]);
		exit(1);
	}

	/*
	 * Set the SO_REUSEADDR option for this TLI endpoint.
	 */
	cvcd_setopt(cvcd_ssp, SO_REUSEADDR);

	/*
	 * Set the SO_DONTROUTE option for this TLI endpoint, if
	 * /etc/ssphostname exists.
	 */
	if (peercheck == 1)
		cvcd_setopt(cvcd_ssp, SO_DONTROUTE);

	/*
	 * Bind it.
	 */
	if (((reqb = (struct t_bind *)t_alloc(cvcd_ssp, T_BIND, T_ALL))
		== (struct t_bind *)NULL)) {
			cvcd_err(LOG_ERR, "%s", t_errlist[t_errno]);
			exit(1);
	}
	if (((retb = (struct t_bind *)t_alloc(cvcd_ssp, T_BIND, T_ALL))
		== (struct t_bind *)NULL)) {
			cvcd_err(LOG_ERR, "%s", t_errlist[t_errno]);
			exit(1);
	}
	reqb->qlen = 1;
	reqb->addr.len = sizeof (struct sockaddr_in);
	sin = (struct sockaddr_in *)reqb->addr.buf;
	(void) memset((void *)sin, 0, sizeof (struct sockaddr_in));
	sin->sin_family = AF_INET;


	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_port = htons(tport);
	if (t_bind(cvcd_ssp, reqb, retb) == -1) {
		cvcd_err(LOG_ERR, "t_bind: %s", t_errlist[t_errno]);
		exit(1);
	}
	sin = (struct sockaddr_in *)retb->addr.buf;
	if (sin->sin_port != htons(tport)) {
		cvcd_err(LOG_ERR, "t_bind: bound to wrong port");
		cvcd_err(LOG_ERR, "Wanted %d, got %d", tport,
			ntohs(sin->sin_port));
		exit(1);
	}

	t_free((char *)reqb, T_BIND);
	t_free((char *)retb, T_BIND);


	/*
	 *  Wait for connect from OBP.
	 */
	cvcd_pfd[2].fd = cvcd_ssp;
	cvcd_pfd[2].events = POLLIN|POLLPRI;
	if ((event = poll(&cvcd_pfd[2], 1, -1)) == -1) {
			cvcd_err(LOG_ERR, "poll: %s", strerror(errno));
			exit(1);
	}
	/*
	 * cvcd_connect sets global
	 * connected = 1 if successful.
	 */
	cvcd_connect(cvcd_ssp, cvcd_pfd);

	/*
	 * Now set up the Network Console redirection driver.
	 */
	rconsfd = open(CVCREDIR_DEV, O_RDWR|O_NDELAY);
	if (rconsfd < 0) {
		cvcd_err(LOG_ERR, "open: %s", strerror(errno));
		exit(1);
	}

	/*
	 * cvcd_pfd holds three file descriptors we need to poll from:
	 * 0 will be connected to in_cvcd;  1 is the CVC Redirection driver;
	 * and 2 is the listen endpoint for new connections.
	 */
	cvcd_pfd[1].fd = rconsfd;
	cvcd_pfd[1].events = POLLIN;
	/*
	 *  Loop through main service routine.  We check for inbound in.cvcd
	 * connection and data xfer between host and in.cvcd.
	 */
	for (;;) {

		char	buf[MAXPKTSZ];

		/*
		 * Check for in_cvcd connect requests.
		 */
		switch ((event = t_look(cvcd_ssp))) {
			case -1 :
				cvcd_err(LOG_ERR, "%s", t_errlist[t_errno]);
				exit(1);
				/* NOTREACHED */
				break;
			case 0  : /* Nothing to do */
				break;
			case T_LISTEN :
				if (connected == 1) {
					/*
					 * Someone already connected.
					 */
					cvcd_reject(cvcd_ssp);
				} else {
					/*
					 * cvcd_connect sets global
					 * connected = 1 if successful.
					 */
					cvcd_connect(cvcd_ssp, cvcd_pfd);

					/*
					 * Re-open the cvcredir driver if
					 * the netcon_fail is true.  This
					 * indicates there was a previous
					 * network connection that got closed.
					 */
					if (netcon_fail) {
						rconsfd = open(CVCREDIR_DEV,
							O_RDWR|O_NDELAY);
						if (rconsfd < 0) {
							cvcd_err(LOG_ERR,
							"open: %s",
							strerror(errno));
							exit(1);
						}
						cvcd_pfd[1].fd = rconsfd;
						cvcd_pfd[1].events = POLLIN;
						netcon_fail = 0;
					}
				}
				break;
			default :
				cvcd_err(LOG_ERR,
					"Illegal event %d for cvcd_ssp", event);
				exit(1);
		}
		/*
		 * Take a look for console I/O or connect request.
		 */
		if ((event = poll(cvcd_pfd, 3, -1)) == -1) {
			cvcd_err(LOG_ERR, "poll: %s", strerror(errno));
			exit(1);
		}

		/*
		 * The following for loop is to detect any bad
		 * things(ie hangup,errors,invalid fd) have happened
		 * to the file descriptors we're interested in.
		 * If so, disconnect current network console connection.
		 */
		for (j = 0; j < 3; j++) {
			if (cvcd_pfd[j].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				cvcd_err(LOG_WARNING,
					"poll: status on %s fd:%s%s%s",
					((j == 2) ? "listen" :
					((j == 0) ? "network" : "redir")),
					(cvcd_pfd[j].revents & POLLERR) ?
						" error" : "",
					(cvcd_pfd[j].revents & POLLHUP) ?
						" hangup" : "",
					(cvcd_pfd[j].revents & POLLNVAL) ?
						" bad fd" : "");

				(void) t_close(cvcd_pfd[0].fd);
				cvcd_pfd[0].fd = -1;

				(void) close(cvcd_pfd[1].fd);
				cvcd_pfd[1].fd = -1;
				connected = 0;
				netcon_fail = 1;
				break;
			}
		}

		/*
		 * Check if dummy netcon_fail flag is set, if set returns
		 * to the beginning of the main service routine.
		 */
		if (netcon_fail)
			continue;

		if (event != 0) {
			if (cvcd_pfd[0].revents == POLLIN) {
				/*
				 * Process cvcd_ssp data and commands.
				 */
				cvcd_read(cvcd_pfd);
			}
			if (cvcd_pfd[1].revents == POLLIN) {
				int s;

				if ((s = read(rconsfd, buf, MAXPKTSZ)) == -1) {
					cvcd_err(LOG_ERR, "read: %s",
						strerror(errno));
					exit(1);
				}
				if ((s > 0) && (connected == 1)) {
					if (write(cvcd_pfd[0].fd, buf, s) !=
					    s) {
						cvcd_err(LOG_ERR,
							"lost data output");
					}
				}
			}
		}
	} /* End forever loop */

#ifdef lint
	/* NOTREACHED */
	return (1);
#endif /* lint */
}

static void
cvcd_reject(int fd)
{
	struct t_call		*tcall;

	tcall = (struct t_call *)t_alloc(fd, T_CALL, T_ALL);
	if (tcall == (struct t_call *)NULL) {
		cvcd_err(LOG_ERR, "cvcd_reject: t_alloc: %s",
			t_errlist[t_errno]);
		return;
	}
	if (t_listen(fd, tcall) == -1) {
		if (t_errno == TNODATA) {
			cvcd_err(LOG_ERR, "cvcd_reject: No client data!");
		}
		cvcd_err(LOG_ERR, "cvcd_reject: t_listen: %s",
			t_errlist[t_errno]);
		t_free((char *)tcall, T_CALL);
		return;
	}
	if (t_snddis(fd, tcall) < 0) {
		cvcd_err(LOG_ERR, "cvcd_reject: t_snddis: %s",
			t_errlist[t_errno]);
	}
	t_free((char *)tcall, T_CALL);
}

static void
cvcd_connect(int fd, struct pollfd *pfd)
{
	struct t_call		*tcall;
	int			newfd;
	struct sockaddr_in	*peer;
	int			badpeer = 1;
	struct hostent		*he;
	struct netbuf		netbuf;
	char			addr[100];
	ulong_t			tmpaddr;	/* network byte order */
	char			**pp;

	tcall = (struct t_call *)t_alloc(fd, T_CALL, T_ALL);
	if (tcall == (struct t_call *)NULL) {
		cvcd_err(LOG_ERR, "cvcd_connect: t_alloc: %s",
			t_errlist[t_errno]);
		return;
	}
	if (t_listen(fd, tcall) == -1) {
		if (t_errno == TNODATA) {
			cvcd_err(LOG_ERR, "cvcd_connect: No client data!");
		}
		cvcd_err(LOG_ERR, "cnctip_connect: t_listen: %s",
			t_errlist[t_errno]);
		t_free((char *)tcall, T_CALL);
		return;
	}
	if (pfd[0].fd != -1) {
		cvcd_err(LOG_ERR, "cvcd_connect: no free file descriptors!");
		t_free((char *)tcall, T_CALL);
		return;
	}
	newfd = t_open(TCP_DEV, O_RDWR|O_NDELAY, NULL);
	if (newfd == -1) {
		cvcd_err(LOG_ERR, "cvcd_connect: t_open: %s",
			t_errlist[t_errno]);
		t_free((char *)tcall, T_CALL);
		return;
	}
	if (t_accept(fd, newfd, tcall) < 0) {
		cvcd_err(LOG_ERR, "cvcd_connect: t_accept: %s",
			t_errlist[t_errno]);
		t_close(newfd);
		t_free((char *)tcall, T_CALL);
		return;
	}
	t_free((char *)tcall, T_CALL);

	/*
	 *  If /etc/ssphostname doesnt exists, dont bother verifying
	 * peer since we cant do gethostbyname.
	 */
	if (peercheck == 1) {
		he = gethostbyname(ssphostname);
		if (he == NULL) {
			cvcd_err(LOG_ERR, "gethostbyname: %s",
			    strerror(h_errno));
			cvcd_err(LOG_ERR, "unable to get SSP name %s!",
			    ssphostname);
			exit(1);
		}
		/*
		 *  Verify peer is from specified host by comparing the
		 *  address (in network byte order) of the TLI endpoint
		 *  and the address (in network byte order) of the ssp
		 *  (using the hostname found in /etc/ssphostname).
		 */
		(void) memset(addr, 0, 100);
		netbuf.buf = addr;
		netbuf.len = 0;
		netbuf.maxlen = 100;
		if (ioctl(newfd, TI_GETPEERNAME, &netbuf) < 0) {
			cvcd_err(LOG_ERR, "ioctl(TI_GETPEERNAME): %s",
			    strerror(errno));
			t_close(newfd);
			return;
		}

		/*
		 * cvcd doesn't check multi-homed ssphostname
		 * properly (only checks 1st address)
		 */
		peer = (struct sockaddr_in *)addr;
		for (pp = he->h_addr_list; *pp != 0; pp++) {
			tmpaddr = htonl(*(ulong_t *)*pp);
			if (memcmp(&peer->sin_addr.s_addr, &tmpaddr,
				he->h_length) == 0) {
				badpeer = 0;
				break;
			}
		}

		if (badpeer) {
			cvcd_err(LOG_ERR, CONREF);
			cvcd_err(LOG_ERR, "remote host = %s.",
				inet_ntoa(peer->sin_addr));
			t_close(newfd);
			return;
		}
	}
	pfd[0].fd = newfd;
	pfd[0].events = POLLIN;
	connected = 1;
}

/*
 *  Read in data from client.
 */
static void
cvcd_read(struct pollfd *pd)
{
	register char *data;
	register int fd = pd[0].fd;
	char	buf[MAXPKTSZ];
	int	flags = 0;

	data = buf;

	if (pd[0].revents & POLLIN) {
		int	n;

		if ((n = t_rcv(fd, data, MAXPKTSZ, &flags)) == -1) {
			cvcd_err(LOG_ERR, "cvcd_read: t_rcv: %s",
				t_errlist[t_errno]);
			(void) t_close(pd[0].fd);
			pd[0].fd = -1;
			connected = 0;
			return;
		}
		if (flags & T_EXPEDITED) {
			if (n != 1) {
				cvcd_err(LOG_ERR,
					"cvcd_read: %d bytes EXD!!",
					n);
			}
			/*
			 * Deal with cvcd_ssp_commands.
			 */
			switch (data[n-1]) {
				case CVC_CONN_BREAK :
					cvcd_ioctl(rconsfd, CVC_BREAK);
					break;

				case CVC_CONN_DIS :
					(void) t_close(pd[0].fd);
					pd[0].fd = -1;
					cvcd_ioctl(rconsfd, CVC_DISCONNECT);
					connected = 0;
					break;

				case CVC_CONN_STAT :
					cvcd_status(fd);
					break;

				default :
					cvcd_err(LOG_ERR,
						"Illegal cmd 0x%x", buf[n-1]);
					break;
			}
		} else {
			if (((data[0] & 0377) == 0377) &&
			    ((data[1] & 0377) == 0377)) {
				/*
				 * Pass on window size changes (TIOCSWINSZ).
				 */
				cvcd_winch(rconsfd, data, n);
				(void) memset(data, 0, n);
			} else {
				cvcd_write(buf, n);
			}
		}
	}

}

static void
cvcd_ioctl(int fd, int flags)
{
	struct strioctl cmd;

	cmd.ic_cmd = flags;
	cmd.ic_timout = 0;
	cmd.ic_len = 0;
	cmd.ic_dp = NULL;

	if (ioctl(fd, I_STR, &cmd) == -1) {
		cvcd_err(LOG_ERR, "cvcd_ioctl: %s", strerror(errno));
		exit(1);
	}
}


/* ARGSUSED */
static void
cvcd_status(int fd)
{
}


/*
 * Write input to console - called from cvcd_read.
 */
static void
cvcd_write(char *data, int size)
{
	int n;

	if ((n = write(rconsfd, data, size)) == -1) {
		cvcd_err(LOG_ERR, "cvcd_write: write: %s", strerror(errno));
		exit(1);
	}
	if (n != size) {
		cvcd_err(LOG_ERR, "cvcd_write: wrote %d of %d bytes", n, size);
	}
}

static void
usage()
{
#if defined(DEBUG)
	(void) printf("%s [-d] [-p port]\n", progname);
#else
	(void) printf("%s -r [ssp host]\n", progname);
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
	(void) vsprintf(buf, format, varg_ptr);
	va_end(varg_ptr);

	if (debug == 0)
		syslog(code, buf);
	else
		(void) fprintf(stderr, "%s: %s\n", progname, buf);
}

/*
 * Handle a "control" request (signaled by magic being present)
 * in the data stream.  For now, we are only willing to handle
 * window size changes.
 */
void
cvcd_winch(int pty, char *cp, int n)
{
	struct	winsize	w;

	if (n < 4+sizeof (w) || cp[2] != 's' || cp[3] != 's')
		return;
	(void) memcpy(&w, cp + 4, sizeof (w));
	w.ws_row = ntohs(w.ws_row);
	w.ws_col = ntohs(w.ws_col);
	w.ws_xpixel = ntohs(w.ws_xpixel);
	w.ws_ypixel = ntohs(w.ws_ypixel);
	(void) ioctl(pty, TIOCSWINSZ, &w);
}


/*
 * Return class ID and maximum priority of it.
 * Input:
 *	name: is class name (either TS or RT).
 *	maxpri: maximum priority for the class, returned in *maxpri.
 * Output:
 *	pc_cid: class ID
 */
static id_t
schedinfo(char *name, short *maxpri)
{
	pcinfo_t info;
	tsinfo_t *tsinfop;
	rtinfo_t *rtinfop;

	(void) strcpy(info.pc_clname, name);
	if (priocntl(0L, 0L, PC_GETCID, (caddr_t)&info) == -1L) {
		return (-1);
	}
	if (strcmp(name, "TS") == 0) {	/* Time Shared */
		tsinfop = (struct tsinfo *)info.pc_clinfo;
		*maxpri = tsinfop->ts_maxupri;
	} else if (strcmp(name, "RT") == 0) {	/* Real Time */
		rtinfop = (struct rtinfo *)info.pc_clinfo;
		*maxpri = rtinfop->rt_maxpri;
	} else {
		return (-1);
	}
	return (info.pc_cid);
}


/*
 * set the tli options for the given endpoint represented by fd
 */
static void
cvcd_setopt(int fd, int name)
{
	struct t_optmgmt	*topt, *tropt;
	struct opthdr		*sockopt;
	int			on = 1;

	topt = (struct t_optmgmt *)t_alloc(fd, T_OPTMGMT, 0);
	if (topt == NULL) {
		cvcd_err(LOG_ERR, "t_alloc: %s", t_errlist[t_errno]);
		exit(1);
	}
	tropt = (struct t_optmgmt *)t_alloc(fd, T_OPTMGMT, 0);
	if (tropt == NULL) {
		cvcd_err(LOG_ERR, "t_alloc: %s", t_errlist[t_errno]);
		exit(1);
	}
	topt->opt.buf = (char *)malloc(sizeof (struct opthdr) + sizeof (int));
	topt->opt.maxlen = 0;
	topt->opt.len = sizeof (struct opthdr) + sizeof (int);
	topt->flags = T_NEGOTIATE;
	sockopt = (struct opthdr *)topt->opt.buf;
	sockopt->level = SOL_SOCKET;
	sockopt->name = name;
	sockopt->len = sizeof (int);
	(void) memcpy((char *)(topt->opt.buf + sizeof (struct opthdr)),
		(char *)&on, sizeof (on));
	tropt->opt.buf = (char *)malloc(sizeof (struct opthdr) + sizeof (int));
	tropt->opt.maxlen = sizeof (struct opthdr) + sizeof (int);

	if (t_optmgmt(fd, topt, tropt) == -1) {
		t_error("t_optmgmt");
		exit(1);
	}

	t_free((char *)topt, T_OPTMGMT);
	t_free((char *)tropt, T_OPTMGMT);
}
