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
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#include "ftp_var.h"
#include <arpa/nameser.h>
#include <sys/types.h>

/*
 * WRITE() returns:
 * 	>0	no error
 *	-1	error, errorno is set
 *	-2	security error (secure_write() only)
 */
#define	PUTC(x, y)	secure_putc(x, y)
#define	READ(x, y, z)	secure_read(x, y, z)
#define	WRITE(x, y, z)	secure_write(x, y, z)

static struct	sockaddr_in6 data_addr;
int	data = -1;
static int	abrtflag = 0;
static int	ptflag = 0;
int		connected;
static jmp_buf	sendabort;
static jmp_buf	recvabort;
static jmp_buf 	ptabort;
static int ptabflg;
static boolean_t pasv_refused;
boolean_t	eport_supported = B_TRUE;
/*
 * For IPv6 addresses, EPSV will be the default (rather than EPRT/LPRT).
 * The EPSV/ERPT ftp protocols are specified in RFC 2428.
 *
 * Perform EPSV if passivemode is set and ipv6rem is TRUE.
 */
static boolean_t ipv6rem;
int	use_eprt = 0;	/* Testing option that specifies EPRT by default */
FILE	*ctrl_in, *ctrl_out;

static void abortsend(int sig);
static void abortpt(int sig);
static void proxtrans(char *cmd, char *local, char *remote);
static void cmdabort(int sig);
static int empty(struct fd_set *mask, int sec, int nfds);
static void abortrecv(int sig);
static int initconn(void);
static FILE *dataconn(char *mode);
static void ptransfer(char *direction, off_t bytes, hrtime_t t0,
    hrtime_t t1, char *local, char *remote);
static void psabort(int sig);
static char *gunique(char *local);
static const char *inet_ntop_native(int af, const void *src, char *dst,
    size_t size);
static ssize_t timedread(int fd, void *buf, size_t maxlen, int timeout);

static int secure_command(char *);
static int decode_reply(uchar_t *, int, uchar_t *, int, boolean_t *);

static ssize_t	bufcnt;		/* number of bytes in buf[]	*/
static char	*bufp;		/* next character in buf	*/
static int	buferr;		/* last errno			*/
static size_t	bufsize;

static void fdio_setbuf(char *buffer, size_t bufsize);
static int fdio_fillbuf(int fd);
static int fdio_error(int fd);
#define	fdio_getc(fd)	(--bufcnt < 0 ? fdio_fillbuf((fd)) : \
			    ((unsigned char)*bufp++))

#define	MAX(a, b) ((a) > (b) ? (a) : (b))
#define	NONZERO(x)	((x) == 0 ? 1 : (x))

static void
fdio_setbuf(char *buffer, size_t maxsize)
{
	buf = buffer;
	bufp = buf;
	bufcnt = 0;
	buferr = 0;
	bufsize = maxsize;
}

static int
fdio_fillbuf(int fd)
{
	bufcnt = timedread(fd, buf, bufsize, timeout);
	if (bufcnt < 0)
		buferr = errno;
	if (bufcnt <= 0)
		return (EOF);
	bufp = buf;
	bufcnt--;
	return ((unsigned char)*bufp++);
}

/*
 * fdio_error - used on a file descriptor instead of ferror()
 */

/*ARGSUSED*/
static int
fdio_error(int fd)
{
	return (buferr);
}

/*
 * timedread - read buffer (like "read"), but with timeout (in seconds)
 */

static ssize_t
timedread(int fd, void *buf, size_t size, int timeout)
{
	struct fd_set mask;
	struct timeval tv;
	int err;

	if (!timeout)
		return (READ(fd, buf, size));

	tv.tv_sec = (time_t)timeout;
	tv.tv_usec = 0;

	FD_ZERO(&mask);
	FD_SET(fd, &mask);

	err = select(fd + 1, &mask, NULL, NULL, &tv);
	if (err == 0)
		errno = ETIMEDOUT;
	if (err <= 0)
		return (-1);

	return (READ(fd, buf, size));
}


char *
hookup(char *host, char *service)
{
	struct addrinfo hints, *ai = NULL, *ai_head;
	int s;
	socklen_t len;
	static char hostnamebuf[80];
	struct in6_addr ipv6addr;
	char abuf[INET6_ADDRSTRLEN];
	int error_num;
	int on = 1;

	/*
	 * There appears to be a bug in getaddrinfo() where, if the
	 * ai_family is set to AF_INET6, and the host is a v4-only
	 * host, getaddrinfo() returns an error instead of returning
	 * an v4-mapped ipv6 address. Therefore the ai_family is
	 * set to AF_UNSPEC and any returned v4 addresses are
	 * explicitly mapped within ftp.
	 */
	bzero((char *)&remctladdr, sizeof (remctladdr));
	bzero((char *)&hints, sizeof (hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error_num = getaddrinfo(host, service, &hints, &ai);
	if (error_num != 0) {
		if (error_num == EAI_AGAIN) {
			(void) printf(
			    "%s: unknown host or invalid literal address "
			    "(try again later)\n", host);
		} else {
			(void) printf(
			    "%s: unknown host or invalid literal address\n",
			    host);
		}
		code = -1;
		return ((char *)0);
	}
	ai_head = ai;


	/*
	 * If ai_canonname is a IPv4-mapped IPv6 literal, we'll convert it to
	 * IPv4 literal address.
	 */
	if (ai->ai_canonname != NULL &&
	    (inet_pton(AF_INET6, ai->ai_canonname, &ipv6addr) > 0) &&
	    IN6_IS_ADDR_V4MAPPED(&ipv6addr)) {
		struct in_addr src4;
		hostnamebuf[0] = '\0';
		IN6_V4MAPPED_TO_INADDR(&ipv6addr, &src4);
		(void) inet_ntop(AF_INET, &src4, hostnamebuf,
		    sizeof (hostnamebuf));

		/*
		 * It can even be the case that the "host" supplied by the user
		 * can be a IPv4-mapped IPv6 literal. So, let's fix that too.
		 */
		if ((inet_pton(AF_INET6, host, &ipv6addr) > 0) &&
		    IN6_IS_ADDR_V4MAPPED(&ipv6addr) &&
		    strlen(hostnamebuf) <= strlen(host)) {
			(void) strlcpy(host, hostnamebuf, strlen(host) + 1);
		}
	} else {
		reset_timer();
		(void) strlcpy(hostnamebuf,
		    (ai->ai_canonname ? ai->ai_canonname : host),
		    sizeof (hostnamebuf));
	}

	hostname = hostnamebuf;
	for (;;) {
		int oerrno;

		bcopy(ai->ai_addr, &remctladdr, ai->ai_addrlen);
		if (ai->ai_addr->sa_family == AF_INET) {
			IN6_INADDR_TO_V4MAPPED(
			    &(((struct sockaddr_in *)ai->ai_addr)->sin_addr),
			    &remctladdr.sin6_addr);
			remctladdr.sin6_family = AF_INET6;
		}

		s = socket(AF_INET6, SOCK_STREAM, 0);
		if (s < 0) {
			perror("ftp: socket");
			code = -1;
			freeaddrinfo(ai_head);
			return (0);
		}
		if (timeout && setsockopt(s, IPPROTO_TCP, TCP_ABORT_THRESHOLD,
		    (char *)&timeoutms, sizeof (timeoutms)) < 0 && debug)
			perror("ftp: setsockopt (TCP_ABORT_THRESHOLD)");
		reset_timer();

		error_num = connect(s, (struct sockaddr *)&remctladdr,
		    sizeof (remctladdr));
		oerrno = errno;
		if (error_num >= 0)
			break;

		/*
		 * Maintain message behavior: only include the address in
		 * our error message if we have another one to try; if this
		 * is the last address on our list, just print the error.
		 */
		if (ai->ai_next != NULL) {
			(void) fprintf(stderr, "ftp: connect to address %s: ",
			    inet_ntop_native(ai->ai_addr->sa_family,
			    (void *)ai->ai_addr, abuf, sizeof (abuf)));
			errno = oerrno;
			perror((char *)0);
		} else {
			perror("ftp: connect");
			code = -1;
			freeaddrinfo(ai_head);
			goto bad;
		}
		ai = ai->ai_next;
		(void) fprintf(stdout, "Trying %s...\n",
		    inet_ntop_native(ai->ai_addr->sa_family,
		    (void *)ai->ai_addr, abuf, sizeof (abuf)));
		(void) close(s);

	}

	/* Set ipv6rem to TRUE if control connection is a native IPv6 address */
	if (IN6_IS_ADDR_V4MAPPED(&remctladdr.sin6_addr))
		ipv6rem = B_FALSE;
	else
		ipv6rem = B_TRUE;


	freeaddrinfo(ai_head);
	ai = NULL;

	/*
	 * Set passive mode flag on by default only if a native IPv6 address
	 * is being used -and- the use_eprt is not set.
	 */
	if (ipv6rem == B_TRUE && use_eprt == 0)
		passivemode = 1;

	len = sizeof (myctladdr);
	if (getsockname(s, (struct sockaddr *)&myctladdr, &len) < 0) {
		perror("ftp: getsockname");
		code = -1;
		goto bad;
	}
	ctrl_in = fdopen(s, "r");
	ctrl_out = fdopen(s, "w");
	if (ctrl_in == NULL || ctrl_out == NULL) {
		(void) fprintf(stderr, "ftp: fdopen failed.\n");
		if (ctrl_in)
			(void) fclose(ctrl_in);
		if (ctrl_out)
			(void) fclose(ctrl_out);
		code = -1;
		goto bad;
	}
	if (verbose)
		(void) printf("Connected to %s.\n", hostname);
	if (getreply(0) > 2) {	/* read startup message from server */
		if (ctrl_in)
			(void) fclose(ctrl_in);
		if (ctrl_out)
			(void) fclose(ctrl_out);
		ctrl_in = ctrl_out = NULL;
		ctrl_in = ctrl_out = NULL;
		code = -1;
		goto bad;
	}
	if (setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&on,
	    sizeof (on)) < 0 && debug)
		perror("ftp: setsockopt (SO_OOBINLINE)");

	return (hostname);
bad:
	(void) close(s);
	return ((char *)0);
}

int
login(char *host)
{
	char tmp[80];
	char *user, *pass, *acct;
	int n, aflag = 0;

	user = pass = acct = 0;
	if (ruserpass(host, &user, &pass, &acct) < 0) {
		disconnect(0, NULL);
		code = -1;
		return (0);
	}
	if (user == NULL) {
		char *myname = getlogin();

		if (myname == NULL) {
			struct passwd *pp = getpwuid(getuid());

			if (pp != NULL)
				myname = pp->pw_name;
		}
		stop_timer();
		(void) printf("Name (%s:%s): ", host,
			(myname == NULL) ? "" : myname);
		*tmp = '\0';
		if (fgets(tmp, sizeof (tmp) - 1, stdin) != NULL)
			tmp[strlen(tmp) - 1] = '\0';
		if (*tmp != '\0')
			user = tmp;
		else if (myname != NULL)
			user = myname;
		else
			return (0);
	}
	n = command("USER %s", user);
	if (n == CONTINUE) {
		int oldclevel;
		if (pass == NULL)
			pass = mygetpass("Password:");
		oldclevel = clevel;
		clevel = PROT_P;
		n = command("PASS %s", pass);
		/* level may have changed */
		if (clevel == PROT_P)
			clevel = oldclevel;
	}
	if (n == CONTINUE) {
		aflag++;
		if (acct == NULL)
			acct = mygetpass("Account:");
		n = command("ACCT %s", acct);
	}
	if (n != COMPLETE) {
		(void) fprintf(stderr, "Login failed.\n");
		return (0);
	}
	if (!aflag && acct != NULL)
		(void) command("ACCT %s", acct);
	if (proxy)
		return (1);
	for (n = 0; n < macnum; ++n) {
		if (strcmp("init", macros[n].mac_name) == 0) {
			(void) strlcpy(line, "$init", sizeof (line));
			makeargv();
			domacro(margc, margv);
			break;
		}
	}
	return (1);
}

/*ARGSUSED*/
static void
cmdabort(int sig)
{
	(void) printf("\n");
	(void) fflush(stdout);
	abrtflag++;
	if (ptflag)
		longjmp(ptabort, 1);
}

int
command(char *fmt, ...)
{
	int r;
	void (*oldintr)();
	va_list ap;
	char command_buf[FTPBUFSIZ];

	va_start(ap, fmt);
	abrtflag = 0;
	if (debug) {
		(void) printf("---> ");
		if (strncmp("PASS ", fmt, 5) == 0)
			(void) printf("PASS XXXX");
		else if (strncmp("ACCT ", fmt, 5) == 0)
			(void) printf("ACCT XXXX");
		else
			(void) vfprintf(stdout, fmt, ap);
		(void) printf("\n");
		(void) fflush(stdout);
	}
	if (ctrl_out == NULL) {
		perror("No control connection for command");
		code = -1;
		return (0);
	}
	oldintr = signal(SIGINT, cmdabort);
	(void) vsnprintf(command_buf, FTPBUFSIZ, fmt, ap);
	va_end(ap);

again:	if (secure_command(command_buf) == 0)
		return (0);

	cpend = 1;
	r = getreply(strcmp(fmt, "QUIT") == 0);

	if (r == 533 && clevel == PROT_P) {
		(void) fprintf(stderr, "ENC command not supported at server; "
			"retrying under MIC...\n");
		clevel = PROT_S;
		goto again;
	}

	if (abrtflag && oldintr != SIG_IGN)
		(*oldintr)();
	(void) signal(SIGINT, oldintr);
	return (r);
}

/* Need to save reply reponse from server for use in EPSV mode */
char reply_string[BUFSIZ];

int
getreply(int expecteof)
{
	/*
	 * 'code' is the 3 digit reply code, form xyz
	 * 'dig'  counts the number of digits we are along in the code
	 * 'n'	is the first digit of 'code'
	 *	4yz: resource unavailable
	 *	5yz: an error occurred, failure
	 *	6yz: protected reply (is_base64 == TRUE)
	 *		631 - base 64 encoded safe message
	 * 		632 - base 64 encoded private message
	 * 		633 - base 64 encoded confidential message
	 * 'c'	is a wide char type, for international char sets
	 */
	wint_t c;
	int i, n;
	int dig;
	int originalcode = 0, continuation = 0;
	void (*oldintr)();
	int pflag = 0;
	char *pt = pasv;
	/*
	 * this is the input and output buffers needed for
	 * radix_encode()
	 */
	unsigned char ibuf[FTPBUFSIZ];
	unsigned char obuf[FTPBUFSIZ];
	boolean_t is_base64;
	int len;
	char *cp;

	if (!ctrl_in)
		return (0);
	oldintr = signal(SIGINT, cmdabort);

	ibuf[0] = '\0';

	if (reply_parse)
		reply_ptr = reply_buf;

	for (;;) {
		obuf[0] = '\0';
		dig = n = code = 0;
		i = is_base64 = 0;
		cp = reply_string;
		reset_timer();	/* once per line */

		while ((c = ibuf[0] ?
		    (wint_t)ibuf[i++] : fgetwc(ctrl_in)) != '\n') {

		    if (i >= FTPBUFSIZ)
			break;

		    if (c == IAC) {	/* handle telnet commands */
			switch (c = fgetwc(ctrl_in)) {
			    case WILL:
			    case WONT:
				c = fgetwc(ctrl_in);
				(void) fprintf(ctrl_out, "%c%c%wc", IAC,
				    WONT, c);
				(void) fflush(ctrl_out);
				break;
			    case DO:
			    case DONT:
				c = fgetwc(ctrl_in);
				(void) fprintf(ctrl_out, "%c%c%wc", IAC,
				    DONT, c);
				(void) fflush(ctrl_out);
				break;
			    default:
				break;
			}
			continue;
		    }
		    dig++;
		    if (c == EOF) {
			if (expecteof) {
				(void) signal(SIGINT, oldintr);
				code = 221;
				return (0);
			}
			lostpeer(0);
			if (verbose) {
				(void) printf(
				    "421 Service not available, remote"
				    " server has closed connection\n");
			} else
				(void) printf("Lost connection\n");
			(void) fflush(stdout);
			code = 421;
			return (4);
		    }
		    if (n == 0)
			n = c;

		    if (n == '6')
			is_base64 = 1;

		    if ((auth_type != AUTHTYPE_NONE) && !ibuf[0] &&
			(is_base64 || continuation))  {
			/* start storing chars in obuf */
			if (c != '\r' && dig > 4)
				obuf[i++] = (char)c;
		    } else {
			if ((auth_type != AUTHTYPE_NONE) && !ibuf[0] &&
			    dig == 1 && verbose)
			    (void) printf("Unauthenticated reply received "
				"from server:\n");
			if (reply_parse)
				*reply_ptr++ = (char)c;
			if (c != '\r' && (verbose > 0 ||
			    (verbose > -1 && n == '5' && dig > 4))) {
				if (proxflag &&
				    (dig == 1 || dig == 5 && verbose == 0))
					(void) printf("%s:", hostname);
				(void) putwchar(c);
			}
		    } /* endif auth_type && !ibuf[0] ... */

		    if ((auth_type != AUTHTYPE_NONE) && !ibuf[0] && !is_base64)
			continue;

		    /* we are still extracting the 3 digit code */
		    if (dig < 4 && isascii(c) && isdigit(c))
			code = code * 10 + (c - '0');

		    /* starting passive mode */
		    if (!pflag && code == 227)
			pflag = 1;

		    /* start to store characters, when dig > 4 */
		    if (dig > 4 && pflag == 1 && isascii(c) && isdigit(c))
			pflag = 2;
		    if (pflag == 2) {
			if (c != '\r' && c != ')') {
				/* the mb array is to deal with the wchar_t */
				char mb[MB_LEN_MAX];
				int avail;

				/*
				 * space available in pasv[], accounting
				 * for trailing NULL
				 */
				avail = &pasv[sizeof (pasv)] - pt - 1;

				len = wctomb(mb, c);
				if (len <= 0 && avail > 0) {
					*pt++ = (unsigned char)c;
				} else if (len > 0 && avail >= len) {
					bcopy(mb, pt, (size_t)len);
					pt += len;
				} else {
					/*
					 * no room in pasv[];
					 * close connection
					 */
					(void) printf("\nReply too long - "
					    "closing connection\n");
					lostpeer(0);
					(void) fflush(stdout);
					(void) signal(SIGINT, oldintr);
					return (4);
				}
			} else {
				*pt = '\0';
				pflag = 3;
			}
		    } /* endif pflag == 2 */
		    if (dig == 4 && c == '-' && !is_base64) {
			if (continuation)
				code = 0;
			continuation++;
		    }
		    if (cp < &reply_string[sizeof (reply_string) - 1])
			*cp++ = c;

		} /* end while */

		if ((auth_type != AUTHTYPE_NONE) && !ibuf[0] && !is_base64)
			return (getreply(expecteof));

		ibuf[0] = obuf[i] = '\0';

		if (code && is_base64) {
		    boolean_t again = 0;
		    n = decode_reply(ibuf, sizeof (ibuf), obuf, n, &again);
		    if (again)
			continue;
		} else

		if (verbose > 0 || verbose > -1 && n == '5') {
			(void) putwchar(c);
			(void) fflush(stdout);
		}

		if (continuation && code != originalcode) {
			ibuf[0] = obuf[i] = '\0';
			if (originalcode == 0)
				originalcode = code;
			continue;
		}
		*cp = '\0';
		if (n != '1')
			cpend = 0;
		(void) signal(SIGINT, oldintr);
		if (code == 421 || originalcode == 421)
			lostpeer(0);
		if (abrtflag && oldintr != cmdabort && oldintr != SIG_IGN)
			(*oldintr)();

		if (reply_parse) {
		    *reply_ptr = '\0';
		    if (reply_ptr = strstr(reply_buf, reply_parse)) {
			reply_parse = reply_ptr + strlen(reply_parse);
			if (reply_ptr = strpbrk(reply_parse, " \r"))
				*reply_ptr = '\0';
		    } else
			reply_parse = reply_ptr;
		}

		return (n - '0');
	} /* end for */
}

static int
empty(struct fd_set *mask, int sec, int nfds)
{
	struct timeval t;

	reset_timer();
	t.tv_sec = (time_t)sec;
	t.tv_usec = 0;
	return (select(nfds, mask, NULL, NULL, &t));
}

/*ARGSUSED*/
static void
abortsend(int sig)
{
	mflag = 0;
	abrtflag = 0;
	(void) printf("\nsend aborted\n");
	(void) fflush(stdout);
	longjmp(sendabort, 1);
}

void
sendrequest(char *cmd, char *local, char *remote, int allowpipe)
{
	FILE *fin, *dout = 0;
	int (*closefunc)();
	void (*oldintr)(), (*oldintp)();
	off_t bytes = 0, hashbytes = HASHSIZ;
	int c;
	/*
	 * d >=	 0 if there is no error
	 *	-1 if there was a normal file i/o error
	 *	-2 if there was a security error
	 */
	int d;
	struct stat st;
	hrtime_t start, stop;
	char *dmode;

	if (proxy) {
		proxtrans(cmd, local, remote);
		return;
	}
	closefunc = NULL;
	oldintr = NULL;
	oldintp = NULL;
	dmode = "w";
	if (setjmp(sendabort)) {
		while (cpend) {
			(void) getreply(0);
		}
		if (data >= 0) {
			(void) close(data);
			data = -1;
		}
		if (oldintr)
			(void) signal(SIGINT, oldintr);
		if (oldintp)
			(void) signal(SIGPIPE, oldintp);
		code = -1;
		restart_point = 0;
		return;
	}
	oldintr = signal(SIGINT, abortsend);
	if (strcmp(local, "-") == 0)
		fin = stdin;
	else if (allowpipe && *local == '|') {
		oldintp = signal(SIGPIPE, SIG_IGN);
		fin = mypopen(local + 1, "r");
		if (fin == NULL) {
			perror(local + 1);
			(void) signal(SIGINT, oldintr);
			(void) signal(SIGPIPE, oldintp);
			code = -1;
			restart_point = 0;
			return;
		}
		closefunc = mypclose;
	} else {
		fin = fopen(local, "r");
		if (fin == NULL) {
			perror(local);
			(void) signal(SIGINT, oldintr);
			code = -1;
			restart_point = 0;
			return;
		}
		closefunc = fclose;
		if (fstat(fileno(fin), &st) < 0 ||
		    (st.st_mode&S_IFMT) != S_IFREG) {
			(void) fprintf(stdout,
				"%s: not a plain file.\n", local);
			(void) signal(SIGINT, oldintr);
			code = -1;
			(void) fclose(fin);
			restart_point = 0;
			return;
		}
	}
	if (initconn()) {
		(void) signal(SIGINT, oldintr);
		if (oldintp)
			(void) signal(SIGPIPE, oldintp);
		code = -1;
		if (closefunc != NULL)
			(*closefunc)(fin);
		restart_point = 0;
		return;
	}
	if (setjmp(sendabort))
		goto abort;
	if ((restart_point > 0) &&
	    (strcmp(cmd, "STOR") == 0 || strcmp(cmd, "APPE") == 0)) {
		if (fseeko(fin, restart_point, SEEK_SET) < 0) {
			perror(local);
			if (closefunc != NULL)
				(*closefunc)(fin);
			restart_point = 0;
			return;
		}
		if (command("REST %lld", (longlong_t)restart_point)
			!= CONTINUE) {
			if (closefunc != NULL)
				(*closefunc)(fin);
			restart_point = 0;
			return;
		}
		dmode = "r+w";
	}
	restart_point = 0;
	if (remote) {
		if (command("%s %s", cmd, remote) != PRELIM) {
			(void) signal(SIGINT, oldintr);
			if (oldintp)
				(void) signal(SIGPIPE, oldintp);
			if (closefunc != NULL)
				(*closefunc)(fin);
			if (data >= 0) {
				(void) close(data);
				data = -1;
			}
			return;
		}
	} else
		if (command("%s", cmd) != PRELIM) {
			(void) signal(SIGINT, oldintr);
			if (oldintp)
				(void) signal(SIGPIPE, oldintp);
			if (closefunc != NULL)
				(*closefunc)(fin);
			if (data >= 0) {
				(void) close(data);
				data = -1;
			}
			return;
		}
	dout = dataconn(dmode);
	if (dout == NULL)
		goto abort;
	stop_timer();
	oldintp = signal(SIGPIPE, SIG_IGN);
	start = gethrtime();
	switch (type) {

	case TYPE_I:
	case TYPE_L:
		errno = d = 0;
		while ((c = read(fileno(fin), buf, FTPBUFSIZ)) > 0) {
			if ((d = WRITE(fileno(dout), buf, c)) < 0)
				break;
			bytes += c;
			if (hash) {
				while (bytes >= hashbytes) {
					(void) putchar('#');
					hashbytes += HASHSIZ;
				}
				(void) fflush(stdout);
			}
		}
		if (hash && bytes > 0) {
			if (bytes < hashbytes)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (c < 0)
			perror(local);

		if (d >= 0)
			d = secure_flush(fileno(dout));

		if (d < 0) {
			if ((d == -1) && (errno != EPIPE))
				perror("netout");
			bytes = -1;
		}
		break;

	case TYPE_A:
		while ((c = getc(fin)) != EOF) {
			if (c == '\n') {
				while (hash && (bytes >= hashbytes)) {
					(void) putchar('#');
					(void) fflush(stdout);
					hashbytes += HASHSIZ;
				}
				if (ferror(dout) || PUTC('\r', dout) < 0)
					break;
				bytes++;
			}

			if (PUTC(c, dout) < 0)
				break;
			bytes++;
#ifdef notdef
			if (c == '\r') {
				/* this violates rfc */
				(void) PUTC('\0', dout);
				bytes++;
			}
#endif
		}
		if (hash && bytes > 0) {
			if (bytes < hashbytes)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (ferror(fin))
			perror(local);

		d = ferror(dout) ? -1 : 0;
		if (d == 0)
			d = secure_flush(fileno(dout));

		if (d < 0) {
			if ((d == -1) && (errno != EPIPE))
				perror("netout");
			bytes = -1;
		}
		break;
	}
	reset_timer();
	if (closefunc != NULL)
		(*closefunc)(fin);
	if (ctrl_in != NULL) {
		int	dfn	= fileno(dout);
		int	nfds	= fileno(ctrl_in);
		fd_set  mask;

		/*
		 * There could be data not yet written to dout,
		 * in the stdio buffer; so, before a shutdown()
		 * on further sends, do fflush(dout)
		 */
		(void) fflush(dout);

		/* sending over; shutdown sending on dfn */
		(void) shutdown(dfn, SHUT_WR);
		FD_ZERO(&mask);
		FD_SET(dfn, &mask);
		FD_SET(nfds, &mask);
		nfds = MAX(dfn, nfds);

		/*
		 * Wait for remote end to either close data socket
		 * or ack that we've closed our end; it doesn't
		 * matter which happens first.
		 */
		(void) select(nfds + 1, &mask, NULL, NULL, NULL);
	}
	(void) fclose(dout); data = -1;
	stop = gethrtime();
	(void) getreply(0);
	(void) signal(SIGINT, oldintr);
	if (oldintp)
		(void) signal(SIGPIPE, oldintp);

	/*
	 * Only print the transfer successful message if the code returned
	 * from remote is 226 or 250. All other codes are error codes.
	 */
	if ((bytes > 0) && verbose && ((code == 226) || (code == 250)))
		ptransfer("sent", bytes, start, stop, local, remote);
	if (!ctrl_in)
		(void) printf("Lost connection\n");
	return;
abort:
	(void) signal(SIGINT, oldintr);
	if (oldintp)
		(void) signal(SIGPIPE, oldintp);
	if (!cpend) {
		code = -1;
		return;
	}
	if (data >= 0) {
		(void) close(data);
		data = -1;
	}
	if (dout) {
		(void) fclose(dout);
		data = -1;
	}
	(void) getreply(0);
	code = -1;
	if (closefunc != NULL && fin != NULL)
		(*closefunc)(fin);
	stop = gethrtime();
	/*
	 * Only print the transfer successful message if the code returned
	 * from remote is 226 or 250. All other codes are error codes.
	 */
	if ((bytes > 0) && verbose && ((code == 226) || (code == 250)))
		ptransfer("sent", bytes, start, stop, local, remote);
	if (!ctrl_in)
		(void) printf("Lost connection\n");
	restart_point = 0;
}

/*ARGSUSED*/
static void
abortrecv(int sig)
{
	mflag = 0;
	abrtflag = 0;
	(void) printf("\n");
	(void) fflush(stdout);
	longjmp(recvabort, 1);
}

void
recvrequest(char *cmd, char *local, char *remote, char *mode, int allowpipe)
{
	FILE *fout, *din = 0;
	int (*closefunc)();
	void (*oldintr)(), (*oldintp)();
	int oldverbose, oldtype = 0, tcrflag, nfnd;
	char msg;
	off_t bytes = 0, hashbytes = HASHSIZ;
	struct fd_set mask;
	int c, d, n;
	hrtime_t start, stop;
	int errflg = 0;
	int infd;
	int nfds;
	int retrcmd;

	retrcmd = (strcmp(cmd, "RETR") == 0);
	if (proxy && retrcmd) {
		proxtrans(cmd, local, remote);
		return;
	}
	closefunc = NULL;
	oldintr = NULL;
	oldintp = NULL;
	tcrflag = !crflag && retrcmd;
	if (setjmp(recvabort)) {
		while (cpend) {
			(void) getreply(0);
		}
		if (data >= 0) {
			(void) close(data);
			data = -1;
		}
		if (oldintr)
			(void) signal(SIGINT, oldintr);
		code = -1;
		return;
	}
	oldintr = signal(SIGINT, abortrecv);
	if (local != NULL &&
	    strcmp(local, "-") != 0 &&
	    (*local != '|' || !allowpipe)) {
		if (access(local, W_OK) < 0) {
			char *dir = rindex(local, '/');
			int file_errno = errno;

			if (file_errno != ENOENT && file_errno != EACCES) {
				perror(local);
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
			if ((dir != NULL) && (dir != local))
				*dir = 0;
			if (dir == local)
				d = access("/", W_OK);
			else
				d = access(dir ? local : ".", W_OK);
			if ((dir != NULL) && (dir != local))
				*dir = '/';
			if (d < 0) {
				perror(local);
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
			if (!runique && file_errno == EACCES) {
				errno = file_errno;
				perror(local);
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
			if (runique && file_errno == EACCES &&
			    (local = gunique(local)) == NULL) {
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
		} else if (runique && (local = gunique(local)) == NULL) {
			(void) signal(SIGINT, oldintr);
			code = -1;
			return;
		}
	}
	if (initconn()) {
		(void) signal(SIGINT, oldintr);
		code = -1;
		return;
	}
	if (setjmp(recvabort))
		goto abort;
	if (!retrcmd && type != TYPE_A) {
		oldtype = type;
		oldverbose = verbose;
		if (!debug)
			verbose = 0;
		setascii(0, NULL);
		verbose = oldverbose;
	}
	if ((restart_point > 0) && retrcmd &&
	    command("REST %lld", (longlong_t)restart_point) != CONTINUE) {
		return;
	}
	if (remote) {
		if (command("%s %s", cmd, remote) != PRELIM) {
			(void) signal(SIGINT, oldintr);
			if (oldtype) {
				if (!debug)
					verbose = 0;
				switch (oldtype) {
					case TYPE_I:
						setbinary(0, NULL);
						break;
					case TYPE_E:
						setebcdic(0, NULL);
						break;
					case TYPE_L:
						settenex(0, NULL);
						break;
				}
				verbose = oldverbose;
			}
			return;
		}
	} else {
		if (command("%s", cmd) != PRELIM) {
			(void) signal(SIGINT, oldintr);
			if (oldtype) {
				if (!debug)
					verbose = 0;
				switch (oldtype) {
					case TYPE_I:
						setbinary(0, NULL);
						break;
					case TYPE_E:
						setebcdic(0, NULL);
						break;
					case TYPE_L:
						settenex(0, NULL);
						break;
				}
				verbose = oldverbose;
			}
			return;
		}
	}
	din = dataconn("r");
	if (din == NULL)
		goto abort;

	if (local == NULL) {
		fout = tmp_nlst;
	} else if (strcmp(local, "-") == 0) {
		fout = stdout;
	} else if (allowpipe && *local == '|') {
		oldintp = signal(SIGPIPE, SIG_IGN);
		fout = mypopen(local + 1, "w");
		if (fout == NULL) {
			perror(local+1);
			goto abort;
		}
		closefunc = mypclose;
	} else {
		fout = fopen(local, mode);
		if (fout == NULL) {
			perror(local);
			goto abort;
		}
		closefunc = fclose;
	}
	start = gethrtime();
	stop_timer();
	switch (type) {

	case TYPE_I:
	case TYPE_L:
		if ((restart_point > 0) && retrcmd &&
		    lseek(fileno(fout), restart_point, SEEK_SET) < 0) {
			perror(local);
			goto abort;
		}
		errno = d = 0;
		infd = fileno(din);
		while ((c = timedread(infd, buf, FTPBUFSIZ, timeout)) > 0) {
			for (n = 0; n < c; n += d) {
				d = write(fileno(fout), &buf[n], c - n);
				if (d == -1)
					goto writeerr;
			}
			bytes += c;
			if (hash) {
				while (bytes >= hashbytes) {
					(void) putchar('#');
					hashbytes += HASHSIZ;
				}
				(void) fflush(stdout);
			}
		}
		if (hash && bytes > 0) {
			if (bytes < hashbytes)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (c < 0) {
			errflg = 1;
			perror("netin");
		}
		if ((d < 0) || ((c == 0) && (fsync(fileno(fout)) == -1))) {
writeerr:
			errflg = 1;
			perror(local);
		}
		break;

	case TYPE_A:
		if ((restart_point > 0) && retrcmd) {
			int c;
			off_t i = 0;

			if (fseek(fout, 0L, SEEK_SET) < 0) {
				perror(local);
				goto abort;
			}
			while (i++ < restart_point) {
				if ((c = getc(fout)) == EOF) {
					if (ferror(fout))
						perror(local);
					else
						(void) fprintf(stderr,
						"%s: Unexpected end of file\n",
							local);
					goto abort;
				}
				if (c == '\n')
					i++;
			}
			if (fseeko(fout, 0L, SEEK_CUR) < 0) {
				perror(local);
				goto abort;
			}
		}
		fdio_setbuf(buf, FTPBUFSIZ);
		infd = fileno(din);
		while ((c = fdio_getc(infd)) != EOF) {
			while (c == '\r') {
				while (hash && (bytes >= hashbytes)) {
					(void) putchar('#');
					(void) fflush(stdout);
					hashbytes += HASHSIZ;
				}
				bytes++;

				if ((c = fdio_getc(infd)) != '\n' || tcrflag) {
					if (ferror(fout))
						break;
					if (putc('\r', fout) == EOF)
						goto writer_ascii_err;
				}
#ifdef notdef
				if (c == '\0') {
					bytes++;
					continue;
				}
#endif
				if (c == EOF)
					goto endread;
			}
			if (putc(c, fout) == EOF)
				goto writer_ascii_err;
			bytes++;
		}
endread:
		if (hash && bytes > 0) {
			if (bytes < hashbytes)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (fdio_error(infd)) {
			errflg = 1;
			perror("netin");
		}
		if ((fflush(fout) == EOF) || ferror(fout) ||
			(fsync(fileno(fout)) == -1)) {
writer_ascii_err:
			errflg = 1;
			perror(local);
		}
		break;
	}
	reset_timer();
	if (closefunc != NULL)
		(*closefunc)(fout);
	(void) signal(SIGINT, oldintr);
	if (oldintp)
		(void) signal(SIGPIPE, oldintp);
	(void) fclose(din); data = -1;
	stop = gethrtime();
	(void) getreply(0);
	if (bytes > 0 && verbose && !errflg)
		ptransfer("received", bytes, start, stop, local, remote);
	if (!ctrl_in)
		(void) printf("Lost connection\n");
	if (oldtype) {
		if (!debug)
			verbose = 0;
		switch (oldtype) {
			case TYPE_I:
				setbinary(0, NULL);
				break;
			case TYPE_E:
				setebcdic(0, NULL);
				break;
			case TYPE_L:
				settenex(0, NULL);
				break;
		}
		verbose = oldverbose;
	}
	return;
abort:

/* abort using RFC959 recommended IP, SYNC sequence  */

	stop = gethrtime();
	if (oldintp)
		(void) signal(SIGPIPE, oldintp);
	(void) signal(SIGINT, SIG_IGN);
	if (!cpend) {
		code = -1;
		(void) signal(SIGINT, oldintr);
		return;
	}

	(void) fprintf(ctrl_out, "%c%c", IAC, IP);
	(void) fflush(ctrl_out);
	msg = (char)IAC;
	/*
	 * send IAC in urgent mode instead of DM because UNIX places oob
	 * mark after urgent byte rather than before as now is protocol
	 */
	if (send(fileno(ctrl_out), &msg, 1, MSG_OOB) != 1) {
		perror("abort");
	}
	(void) fprintf(ctrl_out, "%cABOR\r\n", DM);
	(void) fflush(ctrl_out);
	nfds = fileno(ctrl_in) + 1;
	FD_ZERO(&mask);
	FD_SET(fileno(ctrl_in), &mask);
	if (din) {
		FD_SET(fileno(din), &mask);
		nfds = MAX(fileno(din) + 1, nfds);
	}
	if ((nfnd = empty(&mask, 10, nfds)) <= 0) {
		if (nfnd < 0) {
			perror("abort");
		}
		code = -1;
		lostpeer(0);
	}
	if (din && FD_ISSET(fileno(din), &mask)) {
		do {
			reset_timer();
		} while ((c = read(fileno(din), buf, FTPBUFSIZ)) > 0);
	}
	if ((c = getreply(0)) == ERROR && code == 552) {
		/* needed for nic style abort */
		if (data >= 0) {
			(void) close(data);
			data = -1;
		}
		(void) getreply(0);
	}
	if (oldtype) {
		if (!debug)
			verbose = 0;
		switch (oldtype) {
		case TYPE_I:
			setbinary(0, NULL);
			break;
		case TYPE_E:
			setebcdic(0, NULL);
			break;
		case TYPE_L:
			settenex(0, NULL);
			break;
		}
		verbose = oldverbose;
	}
	(void) getreply(0);
	code = -1;
	if (data >= 0) {
		(void) close(data);
		data = -1;
	}
	if (closefunc != NULL && fout != NULL)
		(*closefunc)(fout);
	if (din) {
		(void) fclose(din);
		data = -1;
	}
	if (bytes > 0 && verbose)
		ptransfer("received", bytes, start, stop, local, remote);
	if (!ctrl_in)
		(void) printf("Lost connection\n");
	(void) signal(SIGINT, oldintr);
}

/*
 * Need to start a listen on the data channel
 * before we send the command, otherwise the
 * server's connect may fail.
 */

static int
initconn(void)
{
	unsigned char *p, *a;
	int result, tmpno = 0;
	int on = 1;
	socklen_t len;
	int v4_addr;
	char *c, *c2, delm;
	in_port_t ports;

	pasv_refused = B_FALSE;
	if (passivemode) {
		data = socket(AF_INET6, SOCK_STREAM, 0);
		if (data < 0) {
			perror("socket");
			return (1);
		}
		if (timeout && setsockopt(data, IPPROTO_TCP,
		    TCP_ABORT_THRESHOLD, (char *)&timeoutms,
		    sizeof (timeoutms)) < 0 && debug)
			perror("ftp: setsockopt (TCP_ABORT_THRESHOLD)");
		if ((options & SO_DEBUG) &&
		    setsockopt(data, SOL_SOCKET, SO_DEBUG, (char *)&on,
			    sizeof (on)) < 0)
			perror("setsockopt (ignored)");
		/*
		 * Use the system wide default send and receive buffer sizes
		 * unless one has been specified.
		 */
		if (tcpwindowsize) {
			if (setsockopt(data, SOL_SOCKET, SO_SNDBUF,
			    (char *)&tcpwindowsize, sizeof (tcpwindowsize)) < 0)
				perror("ftp: setsockopt (SO_SNDBUF - ignored)");
			if (setsockopt(data, SOL_SOCKET, SO_RCVBUF,
			    (char *)&tcpwindowsize, sizeof (tcpwindowsize)) < 0)
				perror("ftp: setsockopt (SO_RCVBUF - ignored)");
		}

		data_addr = remctladdr;

		if (ipv6rem == B_TRUE) {
			if (command("EPSV") != COMPLETE) {
				(void) fprintf(stderr,
					"Passive mode refused. Try EPRT\n");
				pasv_refused = B_TRUE;
				goto noport;
			}

			/*
			 * Get the data port from reply string from the
			 * server.  The format of the reply string is:
			 * 229 Entering Extended Passive Mode (|||port|)
			 * where | is the delimiter being used.
			 */
			c = strchr(reply_string, '(');
			c2 = strchr(reply_string, ')');
			if (c == NULL || c2 == NULL) {
				(void) fprintf(stderr, "Extended passive mode"
				    "parsing failure.\n");
				goto bad;
			}
			*(c2 - 1) = '\0';
			/* Delimiter is the next char in the reply string */
			delm = *(++c);
			while (*c == delm) {
				if (!*(c++)) {
					(void) fprintf(stderr,
					    "Extended passive mode"
					    "parsing failure.\n");
					goto bad;
				}
			}
			/* assign the port for data connection */
			ports = (in_port_t)atoi(c);
			data_addr.sin6_port =  htons(ports);
		} else {
			int a1, a2, a3, a4, p1, p2;

			if (command("PASV") != COMPLETE) {
				(void) fprintf(stderr,
					"Passive mode refused. Try PORT\n");
				pasv_refused = B_TRUE;
				goto noport;
			}

			/*
			 * Get the data port from reply string from the
			 * server.  The format of the reply string is:
			 * 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
			 */
			if (sscanf(pasv, "%d,%d,%d,%d,%d,%d",
					&a1, &a2, &a3, &a4, &p1, &p2) != 6) {
				(void) fprintf(stderr,
					"Passive mode parsing failure.\n");
				goto bad;
			}
			/*
			 * Set the supplied address and port in an
			 * IPv4-mapped IPv6 address.
			 */
			a = (unsigned char *)&data_addr.sin6_addr +
				sizeof (struct in6_addr) -
				sizeof (struct in_addr);
#define	UC(b)	((b)&0xff)
			a[0] = UC(a1);
			a[1] = UC(a2);
			a[2] = UC(a3);
			a[3] = UC(a4);
			p = (unsigned char *)&data_addr.sin6_port;
			p[0] = UC(p1);
			p[1] = UC(p2);
		}

		if (connect(data, (struct sockaddr *)&data_addr,
		    sizeof (data_addr)) < 0) {
			perror("connect");
			goto bad;
		}
		return (0);
	}

noport:
	data_addr = myctladdr;
	if (sendport)
		data_addr.sin6_port = 0;	/* let system pick one */

	if (data != -1)
		(void) close(data);
	data = socket(AF_INET6, SOCK_STREAM, 0);
	if (data < 0) {
		perror("ftp: socket");
		if (tmpno)
			sendport = 1;
		return (1);
	}
	if (!sendport)
		if (setsockopt(data, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&on, sizeof (on)) < 0) {
			perror("ftp: setsockopt (SO_REUSEADDR)");
			goto bad;
		}
	if (bind(data,
	    (struct sockaddr *)&data_addr, sizeof (data_addr)) < 0) {
		perror("ftp: bind");
		goto bad;
	}
	if (timeout && setsockopt(data, IPPROTO_TCP, TCP_ABORT_THRESHOLD,
	    (char *)&timeoutms, sizeof (timeoutms)) < 0 && debug)
		perror("ftp: setsockopt (TCP_ABORT_THRESHOLD)");
	if (options & SO_DEBUG &&
	    setsockopt(data, SOL_SOCKET, SO_DEBUG,
	    (char *)&on, sizeof (on)) < 0)
		perror("ftp: setsockopt (SO_DEBUG - ignored)");
	/*
	 * Use the system wide default send and receive buffer sizes unless
	 * one has been specified.
	 */
	if (tcpwindowsize) {
		if (setsockopt(data, SOL_SOCKET, SO_SNDBUF,
		    (char *)&tcpwindowsize, sizeof (tcpwindowsize)) < 0)
			perror("ftp: setsockopt (SO_SNDBUF - ignored)");
		if (setsockopt(data, SOL_SOCKET, SO_RCVBUF,
		    (char *)&tcpwindowsize, sizeof (tcpwindowsize)) < 0)
			perror("ftp: setsockopt (SO_RCVBUF - ignored)");
	}
	len = sizeof (data_addr);
	if (getsockname(data, (struct sockaddr *)&data_addr, &len) < 0) {
		perror("ftp: getsockname");
		goto bad;
	}

	v4_addr = IN6_IS_ADDR_V4MAPPED(&data_addr.sin6_addr);
	if (listen(data, 1) < 0)
		perror("ftp: listen");

	if (sendport) {
		a = (unsigned char *)&data_addr.sin6_addr;
		p = (unsigned char *)&data_addr.sin6_port;
		if (v4_addr) {
			result =
			    command("PORT %d,%d,%d,%d,%d,%d",
			    UC(a[12]), UC(a[13]), UC(a[14]), UC(a[15]),
			    UC(p[0]), UC(p[1]));
		} else {
			char hname[INET6_ADDRSTRLEN];

			result = COMPLETE + 1;
			/*
			 * if on previous try to server, it was
			 * determined that the server doesn't support
			 * EPRT, don't bother trying again.  Just try
			 * LPRT.
			 */
			if (eport_supported == B_TRUE) {
				if (inet_ntop(AF_INET6, &data_addr.sin6_addr,
				    hname, sizeof (hname)) != NULL) {
					result = command("EPRT |%d|%s|%d|", 2,
					    hname, htons(data_addr.sin6_port));
					if (result != COMPLETE)
						eport_supported = B_FALSE;
				    }
			}
			/* Try LPRT */
			if (result != COMPLETE) {
				result = command(
"LPRT %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
6, 16,
UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
UC(a[4]), UC(a[5]), UC(a[6]), UC(a[7]),
UC(a[8]), UC(a[9]), UC(a[10]), UC(a[11]),
UC(a[12]), UC(a[13]), UC(a[14]), UC(a[15]),
2, UC(p[0]), UC(p[1]));
			}
		}

		if (result == ERROR && sendport == -1) {
			sendport = 0;
			tmpno = 1;
			goto noport;
		}
		return (result != COMPLETE);
	}
	if (tmpno)
		sendport = 1;
	return (0);
bad:
	(void) close(data), data = -1;
	if (tmpno)
		sendport = 1;
	return (1);
}

static FILE *
dataconn(char *mode)
{
	struct sockaddr_in6 from;
	int s;
	socklen_t fromlen = sizeof (from);

	reset_timer();
	if (passivemode && !pasv_refused)
		return (fdopen(data, mode));

	s = accept(data, (struct sockaddr *)&from, &fromlen);
	if (s < 0) {
		perror("ftp: accept");
		(void) close(data), data = -1;
		return (NULL);
	}
	(void) close(data);
	data = s;
	return (fdopen(data, mode));
}

static void
ptransfer(char *direction, off_t bytes, hrtime_t t0,
    hrtime_t t1, char *local, char *remote)
{
	hrtime_t td; /* nanoseconds in a 64 bit int */
	double s, bs;

	td = t1 - t0;
	s = (double)td / 1000000000.0; /* seconds */
	bs = (double)bytes / NONZERO(s);
	if (local && *local != '-')
		(void) printf("local: %s ", local);
	if (remote)
		(void) printf("remote: %s\n", remote);
	(void) printf("%lld bytes %s in %.2g seconds (%.2f Kbytes/s)\n",
		(longlong_t)bytes, direction, s, bs / 1024.0);
}

/*ARGSUSED*/
static void
psabort(int sig)
{
	abrtflag++;
}

void
pswitch(int flag)
{
	void (*oldintr)();
	static struct comvars {
		int connect;
		char name[MAXHOSTNAMELEN];
		struct sockaddr_in6 mctl;
		struct sockaddr_in6 hctl;
		FILE *in;
		FILE *out;
		int tpe;
		int cpnd;
		int sunqe;
		int runqe;
		int mcse;
		int ntflg;
		char nti[17];
		char nto[17];
		int mapflg;
		char mi[MAXPATHLEN];
		char mo[MAXPATHLEN];
		int authtype;
		int clvl;
		int dlvl;
		} proxstruct, tmpstruct;
	struct comvars *ip, *op;

	abrtflag = 0;
	oldintr = signal(SIGINT, psabort);
	if (flag) {
		if (proxy)
			return;
		ip = &tmpstruct;
		op = &proxstruct;
		proxy++;
	} else {
		if (!proxy)
			return;
		ip = &proxstruct;
		op = &tmpstruct;
		proxy = 0;
	}
	ip->connect = connected;
	connected = op->connect;
	if (hostname)
		(void) strlcpy(ip->name, hostname, sizeof (ip->name));
	else
		ip->name[0] = 0;
	hostname = op->name;
	ip->hctl = remctladdr;
	remctladdr = op->hctl;
	ip->mctl = myctladdr;
	myctladdr = op->mctl;
	ip->in = ctrl_in;
	ctrl_in = op->in;
	ip->out = ctrl_out;
	ctrl_out = op->out;
	ip->tpe = type;
	type = op->tpe;
	if (!type)
		type = 1;
	ip->cpnd = cpend;
	cpend = op->cpnd;
	ip->sunqe = sunique;
	sunique = op->sunqe;
	ip->runqe = runique;
	runique = op->runqe;
	ip->mcse = mcase;
	mcase = op->mcse;
	ip->ntflg = ntflag;
	ntflag = op->ntflg;
	(void) strlcpy(ip->nti, ntin, sizeof (ip->nti));
	(void) strlcpy(ntin, op->nti, sizeof (ntin));
	(void) strlcpy(ip->nto, ntout, sizeof (ip->nto));
	(void) strlcpy(ntout, op->nto, sizeof (ntout));
	ip->mapflg = mapflag;
	mapflag = op->mapflg;
	(void) strlcpy(ip->mi, mapin, sizeof (ip->mi));
	(void) strlcpy(mapin, op->mi, sizeof (mapin));
	(void) strlcpy(ip->mo, mapout, sizeof (ip->mo));
	(void) strlcpy(mapout, op->mo, sizeof (mapout));

	ip->authtype = auth_type;
	auth_type = op->authtype;
	ip->clvl = clevel;
	clevel = op->clvl;
	ip->dlvl = dlevel;
	dlevel = op->dlvl;
	if (!clevel)
		clevel = PROT_C;
	if (!dlevel)
		dlevel = PROT_C;

	(void) signal(SIGINT, oldintr);
	if (abrtflag) {
		abrtflag = 0;
		(*oldintr)();
	}
}

/*ARGSUSED*/
static void
abortpt(int sig)
{
	(void) printf("\n");
	(void) fflush(stdout);
	ptabflg++;
	mflag = 0;
	abrtflag = 0;
	longjmp(ptabort, 1);
}

static void
proxtrans(char *cmd, char *local, char *remote)
{
	void (*oldintr)();
	int tmptype, oldtype = 0, secndflag = 0, nfnd;
	extern jmp_buf ptabort;
	char *cmd2;
	struct fd_set mask;
	int ipv4_addr = IN6_IS_ADDR_V4MAPPED(&remctladdr.sin6_addr);

	if (strcmp(cmd, "RETR"))
		cmd2 = "RETR";
	else
		cmd2 = runique ? "STOU" : "STOR";
	if (command(ipv4_addr ? "PASV" : "EPSV") != COMPLETE) {
		(void) printf(
		    "proxy server does not support third part transfers.\n");
		return;
	}
	tmptype = type;
	pswitch(0);
	if (!connected) {
		(void) printf("No primary connection\n");
		pswitch(1);
		code = -1;
		return;
	}
	if (type != tmptype) {
		oldtype = type;
		switch (tmptype) {
			case TYPE_A:
				setascii(0, NULL);
				break;
			case TYPE_I:
				setbinary(0, NULL);
				break;
			case TYPE_E:
				setebcdic(0, NULL);
				break;
			case TYPE_L:
				settenex(0, NULL);
				break;
		}
	}
	if (command(ipv4_addr ? "PORT %s" : "EPRT %s", pasv) != COMPLETE) {
		switch (oldtype) {
			case 0:
				break;
			case TYPE_A:
				setascii(0, NULL);
				break;
			case TYPE_I:
				setbinary(0, NULL);
				break;
			case TYPE_E:
				setebcdic(0, NULL);
				break;
			case TYPE_L:
				settenex(0, NULL);
				break;
		}
		pswitch(1);
		return;
	}
	if (setjmp(ptabort))
		goto abort;
	oldintr = signal(SIGINT, (void (*)())abortpt);
	if (command("%s %s", cmd, remote) != PRELIM) {
		(void) signal(SIGINT, oldintr);
		switch (oldtype) {
			case 0:
				break;
			case TYPE_A:
				setascii(0, NULL);
				break;
			case TYPE_I:
				setbinary(0, NULL);
				break;
			case TYPE_E:
				setebcdic(0, NULL);
				break;
			case TYPE_L:
				settenex(0, NULL);
				break;
		}
		pswitch(1);
		return;
	}
	(void) sleep(2);
	pswitch(1);
	secndflag++;
	if (command("%s %s", cmd2, local) != PRELIM)
		goto abort;
	ptflag++;
	(void) getreply(0);
	pswitch(0);
	(void) getreply(0);
	(void) signal(SIGINT, oldintr);
	switch (oldtype) {
		case 0:
			break;
		case TYPE_A:
			setascii(0, NULL);
			break;
		case TYPE_I:
			setbinary(0, NULL);
			break;
		case TYPE_E:
			setebcdic(0, NULL);
			break;
		case TYPE_L:
			settenex(0, NULL);
			break;
	}
	pswitch(1);
	ptflag = 0;
	(void) printf("local: %s remote: %s\n", local, remote);
	return;
abort:
	(void) signal(SIGINT, SIG_IGN);
	ptflag = 0;
	if (strcmp(cmd, "RETR") && !proxy)
		pswitch(1);
	else if ((strcmp(cmd, "RETR") == 0) && proxy)
		pswitch(0);
	if (!cpend && !secndflag) {  /* only here if cmd = "STOR" (proxy=1) */
		if (command("%s %s", cmd2, local) != PRELIM) {
			pswitch(0);
			switch (oldtype) {
				case 0:
					break;
				case TYPE_A:
					setascii(0, NULL);
					break;
				case TYPE_I:
					setbinary(0, NULL);
					break;
				case TYPE_E:
					setebcdic(0, NULL);
					break;
				case TYPE_L:
					settenex(0, NULL);
					break;
			}
			if (cpend) {
				char msg[2];

				(void) fprintf(ctrl_out, "%c%c", IAC, IP);
				(void) fflush(ctrl_out);
				*msg = (char)IAC;
				*(msg+1) = (char)DM;
				if (send(fileno(ctrl_out), msg, 2, MSG_OOB)
				    != 2)
					perror("abort");
				(void) fprintf(ctrl_out, "ABOR\r\n");
				(void) fflush(ctrl_out);
				FD_ZERO(&mask);
				FD_SET(fileno(ctrl_in), &mask);
				if ((nfnd = empty(&mask, 10,
				    fileno(ctrl_in) + 1)) <= 0) {
					if (nfnd < 0) {
						perror("abort");
					}
					if (ptabflg)
						code = -1;
					lostpeer(0);
				}
				(void) getreply(0);
				(void) getreply(0);
			}
		}
		pswitch(1);
		if (ptabflg)
			code = -1;
		(void) signal(SIGINT, oldintr);
		return;
	}
	if (cpend) {
		char msg[2];

		(void) fprintf(ctrl_out, "%c%c", IAC, IP);
		(void) fflush(ctrl_out);
		*msg = (char)IAC;
		*(msg+1) = (char)DM;
		if (send(fileno(ctrl_out), msg, 2, MSG_OOB) != 2)
			perror("abort");
		(void) fprintf(ctrl_out, "ABOR\r\n");
		(void) fflush(ctrl_out);
		FD_ZERO(&mask);
		FD_SET(fileno(ctrl_in), &mask);
		if ((nfnd = empty(&mask, 10, fileno(ctrl_in) + 1)) <= 0) {
			if (nfnd < 0) {
				perror("abort");
			}
			if (ptabflg)
				code = -1;
			lostpeer(0);
		}
		(void) getreply(0);
		(void) getreply(0);
	}
	pswitch(!proxy);
	if (!cpend && !secndflag) {  /* only if cmd = "RETR" (proxy=1) */
		if (command("%s %s", cmd2, local) != PRELIM) {
			pswitch(0);
			switch (oldtype) {
				case 0:
					break;
				case TYPE_A:
					setascii(0, NULL);
					break;
				case TYPE_I:
					setbinary(0, NULL);
					break;
				case TYPE_E:
					setebcdic(0, NULL);
					break;
				case TYPE_L:
					settenex(0, NULL);
					break;
			}
			if (cpend) {
				char msg[2];

				(void) fprintf(ctrl_out, "%c%c", IAC, IP);
				(void) fflush(ctrl_out);
				*msg = (char)IAC;
				*(msg+1) = (char)DM;
				if (send(fileno(ctrl_out), msg, 2, MSG_OOB)
				    != 2)
					perror("abort");
				(void) fprintf(ctrl_out, "ABOR\r\n");
				(void) fflush(ctrl_out);
				FD_ZERO(&mask);
				FD_SET(fileno(ctrl_in), &mask);
				if ((nfnd = empty(&mask, 10,
				    fileno(ctrl_in) + 1)) <= 0) {
					if (nfnd < 0) {
						perror("abort");
					}
					if (ptabflg)
						code = -1;
					lostpeer(0);
				}
				(void) getreply(0);
				(void) getreply(0);
			}
			pswitch(1);
			if (ptabflg)
				code = -1;
			(void) signal(SIGINT, oldintr);
			return;
		}
	}
	if (cpend) {
		char msg[2];

		(void) fprintf(ctrl_out, "%c%c", IAC, IP);
		(void) fflush(ctrl_out);
		*msg = (char)IAC;
		*(msg+1) = (char)DM;
		if (send(fileno(ctrl_out), msg, 2, MSG_OOB) != 2)
			perror("abort");
		(void) fprintf(ctrl_out, "ABOR\r\n");
		(void) fflush(ctrl_out);
		FD_ZERO(&mask);
		FD_SET(fileno(ctrl_in), &mask);
		if ((nfnd = empty(&mask, 10, fileno(ctrl_in) + 1)) <= 0) {
			if (nfnd < 0) {
				perror("abort");
			}
			if (ptabflg)
				code = -1;
			lostpeer(0);
		}
		(void) getreply(0);
		(void) getreply(0);
	}
	pswitch(!proxy);
	if (cpend) {
		FD_ZERO(&mask);
		FD_SET(fileno(ctrl_in), &mask);
		if ((nfnd = empty(&mask, 10, fileno(ctrl_in) + 1)) <= 0) {
			if (nfnd < 0) {
				perror("abort");
			}
			if (ptabflg)
				code = -1;
			lostpeer(0);
		}
		(void) getreply(0);
		(void) getreply(0);
	}
	if (proxy)
		pswitch(0);
	switch (oldtype) {
		case 0:
			break;
		case TYPE_A:
			setascii(0, NULL);
			break;
		case TYPE_I:
			setbinary(0, NULL);
			break;
		case TYPE_E:
			setebcdic(0, NULL);
			break;
		case TYPE_L:
			settenex(0, NULL);
			break;
	}
	pswitch(1);
	if (ptabflg)
		code = -1;
	(void) signal(SIGINT, oldintr);
}

/*ARGSUSED*/
void
reset(int argc, char *argv[])
{
	struct fd_set mask;
	int nfnd = 1;

	FD_ZERO(&mask);
	while (nfnd > 0) {
		FD_SET(fileno(ctrl_in), &mask);
		if ((nfnd = empty(&mask, 0, fileno(ctrl_in) + 1)) < 0) {
			perror("reset");
			code = -1;
			lostpeer(0);
		} else if (nfnd > 0) {
			(void) getreply(0);
		}
	}
}

static char *
gunique(char *local)
{
	static char new[MAXPATHLEN];
	char *cp = rindex(local, '/');
	int d, count = 0;
	char ext = '1';

	if (cp)
		*cp = '\0';
	d = access(cp ? local : ".", 2);
	if (cp)
		*cp = '/';
	if (d < 0) {
		perror(local);
		return ((char *)0);
	}
	if (strlcpy(new, local, sizeof (new)) >= sizeof (new))
		(void) printf("gunique: too long: local %s, %d, new %d\n",
		    local, strlen(local), sizeof (new));

	cp = new + strlen(new);
	*cp++ = '.';
	while (!d) {
		if (++count == 100) {
			(void) printf(
				"runique: can't find unique file name.\n");
			return ((char *)0);
		}
		*cp++ = ext;
		*cp = '\0';
		if (ext == '9')
			ext = '0';
		else
			ext++;
		if ((d = access(new, 0)) < 0)
			break;
		if (ext != '0')
			cp--;
		else if (*(cp - 2) == '.')
			*(cp - 1) = '1';
		else {
			*(cp - 2) = *(cp - 2) + 1;
			cp--;
		}
	}
	return (new);
}

/*
 * This is a wrap-around function for inet_ntop(). In case the af is AF_INET6
 * and the address pointed by src is a IPv4-mapped IPv6 address, it
 * returns printable IPv4 address, not IPv4-mapped IPv6 address. In other cases
 * it behaves just like inet_ntop().
 */
const char *
inet_ntop_native(int af, const void *src, char *dst, size_t size)
{
	struct in_addr src4;
	const char *result;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (af == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)src;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr, &src4);
			result = inet_ntop(AF_INET, &src4, dst, size);
		} else {
			result = inet_ntop(AF_INET6, &sin6->sin6_addr,
			    dst, size);
		}
	} else {
		sin = (struct sockaddr_in *)src;
		result = inet_ntop(af, &sin->sin_addr, dst, size);
	}

	return (result);
}

int
secure_command(char *cmd)
{
	unsigned char *in = NULL, *out = NULL;
	int length = 0;
	size_t inlen;

	if ((auth_type != AUTHTYPE_NONE) && clevel != PROT_C) {
		gss_buffer_desc in_buf, out_buf;
		OM_uint32 maj_stat, min_stat;

		/* secure_command (based on level) */
		if (auth_type == AUTHTYPE_GSSAPI) {
			OM_uint32 expire_time;
			int conf_state;
			/* clevel = PROT_P; */
			in_buf.value = cmd;
			in_buf.length = strlen(cmd) + 1;

			maj_stat = gss_context_time(&min_stat, gcontext,
				&expire_time);
			if (GSS_ERROR(maj_stat)) {
				user_gss_error(maj_stat, min_stat,
					"gss context has expired");
				fatal("Your gss credentials have expired.  "
					"Good-bye!");
			}
			maj_stat = gss_seal(&min_stat, gcontext,
					    (clevel == PROT_P), /* private */
					    GSS_C_QOP_DEFAULT,
					    &in_buf, &conf_state,
					    &out_buf);
			if (maj_stat != GSS_S_COMPLETE) {
				/* generally need to deal */
				user_gss_error(maj_stat, min_stat,
					(clevel == PROT_P) ?
					"gss_seal ENC didn't complete":
					"gss_seal MIC didn't complete");
			} else if ((clevel == PROT_P) && !conf_state) {
				(void) fprintf(stderr,
					"GSSAPI didn't encrypt message");
				out = out_buf.value;
			} else {
				if (debug)
				(void) fprintf(stderr,
					"sealed (%s) %d bytes\n",
					clevel == PROT_P ? "ENC" : "MIC",
					out_buf.length);

				out = out_buf.value;
			}
		}
		/* Other auth types go here ... */
		inlen = ((4 * out_buf.length) / 3) + 4;
		in = (uchar_t *)malloc(inlen);
		if (in == NULL) {
			gss_release_buffer(&min_stat, &out_buf);
			fatal("Memory error allocating space for response.");
		}
		length = out_buf.length;
		if (auth_error = radix_encode(out, in, inlen, &length, 0)) {
			(void) fprintf(stderr,
				"Couldn't base 64 encode command (%s)\n",
				radix_error(auth_error));
			free(in);
			gss_release_buffer(&min_stat, &out_buf);
			return (0);
		}

		(void) fprintf(ctrl_out, "%s %s",
			clevel == PROT_P ? "ENC" : "MIC", in);

		free(in);
		gss_release_buffer(&min_stat, &out_buf);

		if (debug)
			(void) fprintf(stderr,
			    "secure_command(%s)\nencoding %d bytes %s %s\n",
			    cmd, length,
			    (clevel == PROT_P) ? "ENC" : "MIC", in);
	} else {
		/*
		 * auth_type = AUTHTYPE_NONE or
		 * command channel is not protected
		 */
		fputs(cmd, ctrl_out);
	}

	(void) fprintf(ctrl_out, "\r\n");
	(void) fflush(ctrl_out);
	return (1);
}

unsigned int maxbuf;
unsigned char *ucbuf;

void
setpbsz(unsigned int size)
{
	unsigned int actualbuf;
	int oldverbose;

	if (ucbuf)
		(void) free(ucbuf);
	actualbuf = size;
	while ((ucbuf = (unsigned char *)malloc(actualbuf)) == NULL) {
		if (actualbuf)
			actualbuf >>= 2;
		else {
			perror("Error while trying to malloc PROT buffer:");
			exit(1);
		}
	}
	oldverbose = verbose;
	verbose = 0;
	reply_parse = "PBSZ=";
	if (command("PBSZ %u", actualbuf) != COMPLETE)
		fatal("Cannot set PROT buffer size");
	if (reply_parse) {
		if ((maxbuf = (unsigned int) atol(reply_parse)) > actualbuf)
			maxbuf = actualbuf;
	} else
		maxbuf = actualbuf;
	reply_parse = NULL;
	verbose = oldverbose;
}

/*
 * Do the base 64 decoding of the raw input buffer, b64_buf.
 * Also do the verification and decryption, if required.
 * retval contains the current error code number
 *
 * returns:
 *	(RFC 2228:  error returns are 3 digit numbers of the form 5xy)
 *	5	if an error occurred
 */
static int
decode_reply(uchar_t *plain_buf,
		int ilen,
		uchar_t *b64_buf,
		int retval,
		boolean_t *again)
{
	int len;
	int safe = 0;

	*again = 0;

	if (!b64_buf[0])	/* if there is no string, no problem */
	    return (retval);

	if ((auth_type == AUTHTYPE_NONE)) {
	    (void) printf("Cannot decode reply:\n%d %s\n", code, b64_buf);
	    return ('5');
	}

	switch (code) {

	    case 631:	/* 'safe' */
		safe = 1;
		break;

	    case 632:	/* 'private' */
		break;

	    case 633:	/* 'confidential' */
		break;

	    default:
		(void) printf("Unknown reply: %d %s\n", code, b64_buf);
		return ('5');
	}

	/* decode the base64 encoded message */
	auth_error = radix_encode(b64_buf, plain_buf, ilen, &len, 1);

	if (auth_error) {
		(void) printf("Can't base 64 decode reply %d (%s)\n\"%s\"\n",
			code, radix_error(auth_error), b64_buf);
		return ('5');
	}

	if (auth_type == AUTHTYPE_GSSAPI) {
		gss_buffer_desc xmit_buf, msg_buf;
		OM_uint32 maj_stat, min_stat;
		int conf_state = safe;
		xmit_buf.value = plain_buf;
		xmit_buf.length = len;

		/* decrypt/verify the message */
		maj_stat = gss_unseal(&min_stat, gcontext,
			&xmit_buf, &msg_buf, &conf_state, NULL);
		if (maj_stat != GSS_S_COMPLETE) {
			user_gss_error(maj_stat, min_stat,
				"failed unsealing reply");
			return ('5');
		}
		if (msg_buf.length < ilen - 2 - 1) {
			memcpy(plain_buf, msg_buf.value, msg_buf.length);
			strcpy((char *)&plain_buf[msg_buf.length], "\r\n");
			gss_release_buffer(&min_stat, &msg_buf);
			*again = 1;
		} else {
			user_gss_error(maj_stat, min_stat,
				"reply was too long");
			return ('5');
		}
	} /* end if GSSAPI */

	/* Other auth types go here... */

	return (retval);
}
