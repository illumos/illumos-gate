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
 * on - user interface program for remote execution service
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	BSD_COMP

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <rpc/rpc.h>
#include <rpc/clnt_soc.h>
#include <rpc/key_prot.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stat.h>
#include <sys/time.h>


#include <sys/ttold.h>


#include "rex.h"

#include <stropts.h>
#include <sys/stream.h>
#include <sys/ttcompat.h>


#define	bcmp(b1, b2, len)	memcmp(b1, b2, len)
#define	bzero(b, len)		memset(b, '\0', len)
#define	bcopy(b1, b2, len)	memcpy(b2, b1, len)

#define	CommandName "on"	/* given as argv[0] */
#define	AltCommandName "dbon"

extern int errno;

/*
 * Note - the following must be long enough for at least two portmap
 * timeouts on the other side.
 */
struct timeval LongTimeout = { 123, 0 };
struct timeval testtimeout = { 5, 0 };

int Debug = 0;			/* print extra debugging information */
int Only2 = 0;			/* stdout and stderr are the same */
int Interactive = 0;		/* use a pty on server */
int NoInput = 0;		/* don't read standard input */
int child = 0;			/* pid of the executed process */
int ChildDied = 0;		/* true when above is valid */
int HasHelper = 0;		/* must kill helpers (interactive mode) */

int InOut;			/* socket for stdin/stdout */
int Err;			/* socket for stderr */

struct sgttyb OldFlags;		/* saved tty flags */
struct sgttyb NewFlags;		/* for stop/continue job control */
CLIENT *Client;			/* RPC client handle */
struct rex_ttysize WindowSize;	/* saved window size */

static int Argc;
static char **Argv;		/* saved argument vector (for ps) */
static char *LastArgv;		/* saved end-of-argument vector */

void	usage(void);
void	Die(int stat);
void	doaccept(int *fdp);
u_short makeport(int *fdp);


/*
 * window change handler - propagate to remote server
 */
void
sigwinch(int junk)
{
	struct	winsize	newsize; /* the modern way to get row and col	*/
	struct	rex_ttysize	size;	/* the old way no body */
					/* bothered to change */
	enum	clnt_stat	clstat;

	ioctl(0, TIOCGWINSZ, &newsize);

	/*
	 * compensate for the struct change
	 */
	size.ts_lines = (int)newsize.ws_row; /* typecast important! */
	size.ts_cols = (int)newsize.ws_col;

	if (bcmp(&size, &WindowSize, sizeof (size)) == 0)
		return;

	WindowSize = size;
	if (clstat = clnt_call(Client, REXPROC_WINCH,
				xdr_rex_ttysize, (caddr_t)&size, xdr_void,
				NULL, LongTimeout)) {
		fprintf(stderr, "on (size): ");
		clnt_perrno(clstat);
		fprintf(stderr, "\r\n");
	}
}

/*
 * signal handler - propagate to remote server
 */
void
sendsig(int sig)
{
	enum clnt_stat clstat;

	if (clstat = clnt_call(Client, REXPROC_SIGNAL,
				xdr_int, (caddr_t) &sig, xdr_void,
				NULL, LongTimeout)) {
		fprintf(stderr, "on (signal): ");
		clnt_perrno(clstat);
		fprintf(stderr, "\r\n");
	}
}


void
cont(int junk)
{
	/*
	 * Put tty modes back the way they were and tell the rexd server
	 * to send the command a SIGCONT signal.
	 */
	if (Interactive) {
		ioctl(0, TIOCSETN, &NewFlags);
		(void) send(InOut, "", 1, MSG_OOB);
	}
}

/*
 * oob -- called when the command invoked by the rexd server is stopped
 *	  with a SIGTSTP or SIGSTOP signal.
 */
void
oob(int junk)
{
	int atmark;
	char waste[BUFSIZ], mark;

	for (;;) {
		if (ioctl(InOut, SIOCATMARK, &atmark) < 0) {
			perror("ioctl");
			break;
		}
		if (atmark)
			break;
		(void) read(InOut, waste, sizeof (waste));
	}
	(void) recv(InOut, &mark, 1, MSG_OOB);
	/*
	 * Reset tty modes to something sane and stop myself
	 */
	if (Interactive) {
		ioctl(0, TIOCSETN, &OldFlags);
		printf("\r\n");
	}
	kill(getpid(), SIGSTOP);
}



int
main(int argc, char **argv)
{
	struct	winsize	newsize; /* the modern way to get row and col	*/
	char *rhost, **cmdp;
	char curdir[MAXPATHLEN];
	char wdhost[MAXHOSTNAMELEN];
	char fsname[MAXPATHLEN];
	char dirwithin[MAXPATHLEN];
	struct rex_start rst;
	struct rex_result result;
	extern char **environ;
	enum clnt_stat clstat;
	struct hostent *hp;
	struct sockaddr_in server_addr;
	int sock = RPC_ANYSOCK;
	fd_set selmask, zmask, remmask;
	int nfds, cc;
	char *chi, *cho;
	int trying_authdes;
	char netname[MAXNETNAMELEN+1];
	char hostname[MAXHOSTNAMELEN+1];
	char publickey[HEXKEYBYTES+1];
	int i;
	char *domain;
	static char buf[4096];

	/*
	 * we check the invoked command name to see if it should
	 * really be a host name.
	 */
	if ((rhost = strrchr(argv[0], '/')) == NULL) {
		rhost = argv[0];
	} else {
		rhost++;
	}

	/*
	 * argv start and extent for setproctitle()
	 */
	Argc = argc;
	Argv = argv;
	if (argc > 0)
		LastArgv = argv[argc-1] + strlen(argv[argc-1]);
	else
		LastArgv = NULL;

	while (argc > 1 && argv[1][0] == '-') {
		switch (argv[1][1]) {
		case 'd': Debug = 1;
			break;
		case 'i': Interactive = 1;
			break;
		case 'n': NoInput = 1;
			break;
		default:
			printf("Unknown option %s\n", argv[1]);
		}
		argv++;
		argc--;
	}

	if (strcmp(rhost, CommandName) && strcmp(rhost, AltCommandName)) {
		cmdp = &argv[1];
		Interactive = 1;
	} else {
		if (argc < 2)
			usage();
		rhost = argv[1];
		cmdp = &argv[2];
	}

	/*
	 * Can only have one of these
	 */
	if (Interactive && NoInput)
		usage();

	if ((hp = gethostbyname(rhost)) == NULL) {
		fprintf(stderr, "on: unknown host %s\n", rhost);
		exit(1);
	}

	bcopy(hp->h_addr, (caddr_t)&server_addr.sin_addr, hp->h_length);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = 0; /* use pmapper */

	if (Debug)
		printf("Got the host named %s (%s)\n",
			rhost, inet_ntoa(server_addr.sin_addr));
	trying_authdes = 1;

try_auth_unix:
	sock = RPC_ANYSOCK;

	if (Debug)
		printf("clnt_create: Server_Addr %u Prog %d Vers %d Sock %d\n",
			&server_addr, REXPROG, REXVERS, sock);

	if ((Client = clnttcp_create(&server_addr, REXPROG, REXVERS, &sock,
					0, 0)) == NULL) {
		fprintf(stderr, "on: cannot connect to server on %s\n",
			rhost);
		clnt_pcreateerror("on:");
		exit(1);
	}

	if (Debug)
		printf("TCP RPC connection created\n");

	if (trying_authdes) {
		yp_get_default_domain(&domain);

		cho =  hostname;
		*cho = 0;
		chi =  hp->h_name;

		for (i = 0; (*chi && (i < MAXHOSTNAMELEN)); i++)
			{
				if (isupper(*chi))
					*cho = tolower(*chi);
				else
					*cho = *chi;
				cho++;
				chi++;
			}
		*cho = 0;

		if (domain != NULL)	{
			if (host2netname(netname, hostname, domain) == 0) {
				trying_authdes = 0;
				if (Debug)
					printf("host2netname failed %s\n",
						hp->h_name);
			}
			/* #ifdef	NOWAY */
			else {

				if (getpublickey(netname, publickey) == 0) {
					trying_authdes = 0;
					cho = strchr(hostname, '.');

					if (cho) {
						*cho = 0;

						if (!host2netname(netname,
						    hostname,
						    domain)) {
							if (Debug)
				printf("host2netname failed %s\n", hp->h_name);
						} else {
							if (getpublickey(
							    netname,
							    publickey) != 0)
							trying_authdes = 1;
						}
					}
				}
			}
		} else {
			trying_authdes = 0;
			if (Debug)
				printf("yp_get_default_domain failed \n");
		}
	}

	if (trying_authdes) {
		Client->cl_auth = (AUTH *)authdes_create(netname, 60*60,
						&server_addr, NULL);

		if (Client->cl_auth == NULL) {

			if (Debug)
				printf("authdes_create failed %s\n", netname);
			trying_authdes = 0;
		}
	}


	if (trying_authdes == 0)
		if ((Client->cl_auth = authsys_create_default()) == NULL) {
			clnt_destroy(Client);
			fprintf(stderr,"on: can't create authunix structure.\n");
			exit(1);
		}


	/*
	 * Now that we have created the TCP connection, we do some
	 * work while the server daemon is being swapped in.
	 */
	if (getcwd(curdir, MAXPATHLEN) == (char *)NULL) {
		fprintf(stderr, "on: can't find . (%s)\n", curdir);
		exit(1);
	}

	if (findmount(curdir, wdhost, fsname, dirwithin) == 0) {

		if (Debug) {
			fprintf(stderr,
				"findmount failed: curdir %s\twdhost %s\t",
				curdir, wdhost);
			fprintf(stderr, "fsname %s\tdirwithin %s\n",
				fsname, dirwithin);
		}

		fprintf(stderr, "on: can't locate mount point for %s (%s)\n",
			curdir, dirwithin);
		exit(1);
	}

	if (Debug) {
		printf("findmount suceeds: cwd= %s, wd host %s, fs %s,",
			curdir, wdhost, fsname);
		printf("dir within %s\n", dirwithin);
	}

	Only2 = samefd(1, 2);

	rst.rst_cmd = (void *)(cmdp);
	rst.rst_host = (void *)wdhost;
	rst.rst_fsname = (void *)fsname;
	rst.rst_dirwithin = (void *)dirwithin;
	rst.rst_env = (void *)environ;
	rst.rst_port0 = makeport(&InOut);
	rst.rst_port1 =  rst.rst_port0;	/* same port for stdin */
	rst.rst_flags = 0;

	if (Debug)
		printf("before Interactive flags\n");

	if (Interactive) {
		rst.rst_flags |= REX_INTERACTIVE;
		ioctl(0, TIOCGETP, &OldFlags);
		NewFlags = OldFlags;
		NewFlags.sg_flags |= (u_int)RAW;
		NewFlags.sg_flags &= (u_int)~ECHO;
		ioctl(0, TIOCSETN, &NewFlags);
	}

	if (Only2) {
		rst.rst_port2 = rst.rst_port1;
	} else {
		rst.rst_port2 = makeport(&Err);
	}

	if (Debug)
		printf("before client call REXPROC_START\n");

	(void) memset(&result, '\0', sizeof(result));

	if (clstat = clnt_call(Client, REXPROC_START,
			       xdr_rex_start, (caddr_t)&rst,
			       xdr_rex_result, (caddr_t)&result, LongTimeout)) {

		if (Debug)
			printf("Client call failed for REXPROC_START\r\n");

		if (trying_authdes) {
			auth_destroy(Client->cl_auth);
			clnt_destroy(Client);
			trying_authdes = 0;
			if (Interactive)
				ioctl(0, TIOCSETN, &OldFlags);
			goto try_auth_unix;
		} else {
			fprintf(stderr, "on %s: ", rhost);
			clnt_perrno(clstat);
			fprintf(stderr, "\n");
			Die(1);
		}
	}

	if (result.rlt_stat != 0) {
		fprintf(stderr, "on %s: %s\n\r", rhost, result.rlt_message);
		Die(1);
	}
	
	clnt_freeres(Client, xdr_rex_result, (caddr_t)&result);
	
	if (Debug)
		printf("Client call suceeded for REXPROC_START\r\n");

	if (Interactive) {
		/*
		 * Pass the tty modes along to the server
		 */
		struct rex_ttymode mode;
		int err;

		mode.basic.sg_ispeed = OldFlags.sg_ispeed;
		mode.basic.sg_ospeed = OldFlags.sg_ospeed;
		mode.basic.sg_erase = OldFlags.sg_erase;
		mode.basic.sg_kill = OldFlags.sg_kill;
		mode.basic.sg_flags = (short) (OldFlags.sg_flags & 0xFFFF);
		err =  (ioctl(0, TIOCGETC, &mode.more) < 0 ||
			ioctl(0, TIOCGLTC, &mode.yetmore) < 0 ||
			ioctl(0, TIOCLGET, &mode.andmore) < 0);
		if (Debug)
			printf("Before clnt_call(REXPROC_MODES) err=%d\n", err);

		if (!err && (clstat = clnt_call(Client, REXPROC_MODES,
					xdr_rex_ttymode, (caddr_t)&mode,
					xdr_void, NULL, LongTimeout))) {

			fprintf(stderr, "on (modes) %s: ", rhost);
			clnt_perrno(clstat);
			fprintf(stderr, "\r\n");
		}

		err = ioctl(0, TIOCGWINSZ, &newsize) < 0;
		/* typecast important in following lines */
		WindowSize.ts_lines = (int)newsize.ws_row;
		WindowSize.ts_cols = (int)newsize.ws_col;

		if (Debug)
			printf("Before client call REXPROC_WINCH\n");

		if (!err && (clstat = clnt_call(Client, REXPROC_WINCH,
					xdr_rex_ttysize, (caddr_t)&WindowSize,
					xdr_void, NULL, LongTimeout))) {

			fprintf(stderr, "on (size) %s: ", rhost);
			clnt_perrno(clstat);
			fprintf(stderr, "\r\n");
		}

		sigset(SIGWINCH, sigwinch);
		sigset(SIGINT, sendsig);
		sigset(SIGQUIT, sendsig);
		sigset(SIGTERM, sendsig);
	}
	sigset(SIGCONT, cont);
	sigset(SIGURG, oob);
	doaccept(&InOut);
	(void) fcntl(InOut, F_SETOWN, getpid());
	FD_ZERO(&remmask);
	FD_SET(InOut, &remmask);
	if (Debug)
		printf("accept on stdout\r\n");

	if (!Only2) {

		doaccept(&Err);
		shutdown(Err, 1); /* 1=> further sends disallowed */
		if (Debug)
			printf("accept on stderr\r\n");
		FD_SET(Err, &remmask);
	}

	FD_ZERO(&zmask);
	if (NoInput) {

		/*
		 * no input - simulate end-of-file instead
		 */
		shutdown(InOut, 1); /* 1=> further sends disallowed */
	} else {
		/*
		 * set up to read standard input, send to remote
		 */
		FD_SET(0, &zmask);
	}

	FD_ZERO(&selmask);
	while (FD_ISSET(InOut, &remmask) || FD_ISSET(Err, &remmask)) {
		if (FD_ISSET(InOut, &remmask))
			FD_SET(InOut, &selmask);
		else
			FD_CLR(InOut, &selmask);
		if (FD_ISSET(Err, &remmask))
			FD_SET(Err, &selmask);
		else
			FD_CLR(Err, &selmask);
		if (FD_ISSET(0, &zmask))
			FD_SET(0, &selmask);
		else
			FD_CLR(0, &selmask);
		nfds = select(FD_SETSIZE, &selmask, (fd_set *) 0, (fd_set *) 0,
			      (struct timeval *) 0);
		

 		if (nfds <= 0) {
			if (errno == EINTR) continue;
			perror("on: select");
			Die(1);
		}
		if (FD_ISSET(InOut, &selmask)) {

			cc = read(InOut, buf, sizeof buf);
			if (cc > 0)
				write(1, buf, cc);
			else
				FD_CLR(InOut, &remmask);
		}

		if (!Only2 && FD_ISSET(Err, &selmask)) {

			cc = read(Err, buf, sizeof buf);
			if (cc > 0)
				write(2, buf, cc);
			else
				FD_CLR(Err, &remmask);
		}

		if (!NoInput && FD_ISSET(0, &selmask)) {

			cc = read(0, buf, sizeof buf);
			if (cc > 0)
				write(InOut, buf, cc);
			else {
				/*
				 * End of standard input - shutdown outgoing
				 * direction of the TCP connection.
				 */
				if (Debug)
					printf("Got EOF - shutting down connection\n");
				FD_CLR(0, &zmask);
				shutdown(InOut, 1); /* further sends disallowed */
			}
		}
	}

	close(InOut);
	if (!Only2)
		close(Err);

	(void) memset(&result, '\0', sizeof(result));

	if (clstat = clnt_call(Client, REXPROC_WAIT,
			       xdr_void, 0, xdr_rex_result, (caddr_t)&result,
			       LongTimeout)) {

		fprintf(stderr, "on: ");
		clnt_perrno(clstat);
		fprintf(stderr, "\r\n");
		Die(1);
	}
	Die(result.rlt_stat);
	return (0);	/* Should never get here. */
}

/*
 * like exit, but resets the terminal state first
 */
void
Die(int stat)

{
	if (Interactive) {
		ioctl(0, TIOCSETN, &OldFlags);
		printf("\r\n");
	}
	exit(stat);
}


void
remstop()

{
	Die(23);
}

/*
 * returns true if we can safely say that the two file descriptors
 * are the "same" (both are same file).
 */
int
samefd(a, b)
{
	struct stat astat, bstat;

	if (fstat(a, &astat) || fstat(b, &bstat))
		return (0);
	if (astat.st_ino == 0 || bstat.st_ino == 0)
		return (0);
	return (!bcmp(&astat, &bstat, sizeof (astat)));
}


/*
 * accept the incoming connection on the given
 * file descriptor, and return the new file descritpor
 */
void
doaccept(fdp)
	int *fdp;
{
	int fd;

	fd = accept(*fdp, 0, 0);

	if (fd < 0) {
		perror("accept");
		remstop();
	}
	close(*fdp);
	*fdp = fd;
}

/*
 * create a socket, and return its the port number.
 */
u_short
makeport(fdp)
	int *fdp;
{
	struct sockaddr_in sin;
	socklen_t len = (socklen_t)sizeof (sin);
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	bzero((char *)&sin, sizeof (sin));
	sin.sin_family = AF_INET;
	bind(fd, (struct sockaddr *)&sin, sizeof (sin));
	getsockname(fd, (struct sockaddr *)&sin, &len);
	listen(fd, 1);
	*fdp = fd;
	return (htons(sin.sin_port));
}

void
usage(void)
{
	fprintf(stderr, "Usage: on [-i|-n] [-d] machine cmd [args]...\n");
	exit(1);
}

/*
 *  SETPROCTITLE -- set the title of this process for "ps"
 *
 *	Does nothing if there were not enough arguments on the command
 * 	line for the information.
 *
 *	Side Effects:
 *		Clobbers argv[] of our main procedure.
 */
void
setproctitle(user, host)
	char *user, *host;
{
	register char *tohere;

	tohere = Argv[0];
	if ((int)LastArgv == (int)((char *)NULL) ||
	    (int)(strlen(user) + strlen(host)+3) > (int)(LastArgv - tohere))
		return;
	*tohere++ = '-';		/* So ps prints (rpc.rexd) */
	sprintf(tohere, "%s@%s", user, host);
	while (*tohere++)		/* Skip to end of printf output	*/
		;
	while (tohere < LastArgv)	/* Avoid confusing ps		*/
		*tohere++ = ' ';
}
