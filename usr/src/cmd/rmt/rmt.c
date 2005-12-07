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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Multi-process streaming 4.3bsd /etc/rmt server.
 *  Has three locks (for stdin, stdout, and the tape)
 *  that are passed by signals and received by sigpause().
 */

#include <stdio.h>
#include <locale.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>

static sigset_t	cmdmask, maskall, newmask;
static sigset_t	sendmask, tapemask;

static struct mtop mtop;
static struct mtget mtget;
static jmp_buf sjbuf;

#define	RECV	SIGIO
#define	TAPE	SIGURG
#define	SEND	SIGALRM
#define	ERROR	SIGTERM
#define	OPEN	SIGUSR1
#define	CLOSE	SIGUSR2

/*
 * Support for Version 1 of the extended RMT protocol:
 * Placing RMTIVERSION (-1) into the mt_op field of the ioctl ('I')
 * request will return the current version of the RMT protocol that
 * the server supports.  For servers that don't support Version 1,
 * an error is returned and the client knows to only use Version 0
 * (stock BSD) calls, which include mt_op values in the range of [0-7].
 *
 * Note: The RMTIVERSION request must be made in order for the extended
 * protocol commands to be recognized.
 */
#define	RMTIVERSION	-1
#define	RMT_VERSION	1

/*
 * These requests are made to the extended RMT protocol by specifying the
 * new 'i' command of RMT Protocol Version 1.  They are intended to allow
 * an intelligent client to communicate with both BSD and Solaris RMT
 * servers heterogeneously.  The 'i' command taks an mtop structure as
 * argument, exactly like the 'I' command does.
 */
#define	RMTICACHE	0
#define	RMTINOCACHE	1
#define	RMTIRETEN	2
#define	RMTIERASE	3
#define	RMTIEOM		4
#define	RMTINBSF	5

/*
 * These requests are made to the extended RMT protocol by specifying the
 * new 's' command of RMT Protocol Version 1.  They are intended to allow
 * an intelligent client to obtain "mt status" information with both BSD
 * and Solaris RMT servers heterogeneously.  They return the requested
 * piece of the mtget structure as an ascii integer.  The request is made
 * by sending the required character immediately after the 's' character
 * without any trailing newline.  A single ascii integer is returned, else
 * an error is returned.
 */
#define	MTS_TYPE	'T'		/* mtget.mt_type */
#define	MTS_DSREG	'D'		/* mtget.mt_dsreg */
#define	MTS_ERREG	'E'		/* mtget.mt_erreg */
#define	MTS_RESID	'R'		/* mtget.mt_resid */
#define	MTS_FILENO	'F'		/* mtget.mt_fileno */
#define	MTS_BLKNO	'B'		/* mtget.mt_blkno */
#define	MTS_FLAGS	'f'		/* mtget.mt_flags */
#define	MTS_BF		'b'		/* mtget.mt_bf */

#define	MAXCHILD 1
static pid_t	childpid[MAXCHILD];
static int	children;

static int	tape = -1;
static size_t	maxrecsize = 0;
static char	*record;

#define	SSIZE	64
static char	pos[SSIZE], op[SSIZE], mode[SSIZE], count[SSIZE];
static char	device[MAXPATHLEN];

static FILE	*debug;
#define	DEBUG(f)		if (debug) (void) fprintf(debug, (f))
#define	DEBUG1(f, a)		if (debug) (void) fprintf(debug, (f), (a))
#define	DEBUG2(f, a, b)		if (debug) (void) fprintf(debug, (f), (a), (b))
#define	DEBUG3(f, a, b, c)	if (debug) \
				    (void) fprintf(debug, (f), (a), (b), (c))

static char key;

#ifdef __STDC__
static void respond(offset_t, int);
static void getstring(char *, size_t);
static void checkbuf(size_t);
#else
static void respond();
static void getstring();
static void checkbuf();
#endif

static void
catch(int sig)
{
	switch (sig) {
	default:    return;
	case OPEN:  key = 'O';	break;
	case CLOSE: key = 'C';	break;
	case ERROR: key = 'E';	break;
	}
	(void) sigprocmask(SIG_SETMASK, &maskall, (sigset_t *)0);
	longjmp(sjbuf, 1);
}

int
main(int argc, char *argv[])
{
	struct sigaction sa;
	pid_t parent = getpid(), next = parent;
	int saverr;
	offset_t rval;
	ssize_t cc;
	size_t n, i;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc > 1) {
		if ((debug = fopen(argv[1], "w")) == NULL)
			exit(1);
		setbuf(debug, NULL);
	}
	(void) sigemptyset(&maskall);
	(void) sigaddset(&maskall, RECV);
	(void) sigaddset(&maskall, OPEN);
	(void) sigaddset(&maskall, CLOSE);
	(void) sigaddset(&maskall, ERROR);
	(void) sigaddset(&maskall, TAPE);
	(void) sigaddset(&maskall, SEND);

	tapemask = maskall;
	(void) sigdelset(&tapemask, TAPE);

	sendmask = maskall;
	(void) sigdelset(&sendmask, SEND);

	(void) sigemptyset(&cmdmask);
	(void) sigaddset(&cmdmask, TAPE);
	(void) sigaddset(&cmdmask, SEND);

	(void) sigemptyset(&sa.sa_mask);

	sa.sa_handler = catch;
	sa.sa_flags = SA_RESTART;
	(void) sigaction(RECV, &sa, (struct sigaction *)0);
	(void) sigaction(SEND, &sa, (struct sigaction *)0);
	(void) sigaction(TAPE, &sa, (struct sigaction *)0);
	(void) sigaction(OPEN, &sa, (struct sigaction *)0);
	(void) sigaction(CLOSE, &sa, (struct sigaction *)0);
	(void) sigaction(ERROR, &sa, (struct sigaction *)0);

	(void) sigprocmask(SIG_SETMASK, &maskall, (sigset_t *)0);

	(void) kill(parent, TAPE);
	(void) kill(parent, SEND);

	while (read(0, &key, 1) == 1) {
		switch (key) {
		case 'L':		/* lseek */
			getstring(count, sizeof (count));
			getstring(pos, sizeof (pos));
			DEBUG2("rmtd: L %s %s\n", count, pos);
			(void) kill(next, RECV);
			(void) sigsuspend(&tapemask);
			rval = llseek(tape, atoll(count), atoi(pos));
			saverr = errno;
			(void) kill(next, TAPE);
			(void) sigsuspend(&sendmask);
			respond(rval, saverr);
			break;

		case 'I':		/* ioctl */
		case 'i': {		/* extended version ioctl */
			int bad = 0;

			getstring(op, sizeof (op));
			getstring(count, sizeof (count));
			DEBUG3("rmtd: %c %s %s\n", key, op, count);
			mtop.mt_op = atoi(op);
			mtop.mt_count = atoi(count);
			if (key == 'i') {
				/*
				 * Map the supported compatibility defines
				 * into real ioctl values.
				 */
				switch (mtop.mt_op) {
				case RMTICACHE:
				case RMTINOCACHE:	/* not support on Sun */
					bad = 1;
					break;
				case RMTIRETEN:
					mtop.mt_op = MTRETEN;
					break;
				case RMTIERASE:
					mtop.mt_op = MTERASE;
					break;
				case RMTIEOM:
					mtop.mt_op = MTEOM;
					break;
				case RMTINBSF:
					mtop.mt_op = MTNBSF;
					break;
				default:
					bad = 1;
					break;
				}
			}
			if (bad) {
				respond(-1LL, EINVAL);
			} else {
				(void) kill(next, RECV);
				(void) sigsuspend(&tapemask);
				if (mtop.mt_op == RMTIVERSION) {
					mtop.mt_count = RMT_VERSION;
					rval = (offset_t)mtop.mt_count;
				} else {
					rval = (offset_t)ioctl(tape, MTIOCTOP,
					    (char *)&mtop);
				}
				saverr = errno;
				(void) kill(next, TAPE);
				(void) sigsuspend(&sendmask);
				respond(rval < 0 ?
				    rval : (offset_t)mtop.mt_count,
				    saverr);
			}
			break;
		}

		case 'S':		/* status */
		case 's': {		/* extended status */
			char skey;

			DEBUG1("rmtd: %c\n", key);
			if (key == 's') {
				if (read(0, &skey, 1) != 1)
					continue;
			}
			(void) kill(next, RECV);
			(void) sigsuspend(&tapemask);
			errno = 0;
			rval = (offset_t)ioctl(tape, MTIOCGET, (char *)&mtget);
			saverr = errno;
			(void) kill(next, TAPE);
			(void) sigsuspend(&sendmask);
			if (rval < 0)
				respond(rval, saverr);
			else {
				if (key == 's') {	/* extended status */
					DEBUG1("rmtd: s%c\n", key);
					switch (skey) {
					case MTS_TYPE:
						respond(
						    (offset_t)mtget.mt_type,
						    saverr);
						break;
					case MTS_DSREG:
						respond(
						    (offset_t)mtget.mt_dsreg,
						    saverr);
						break;
					case MTS_ERREG:
						respond(
						    (offset_t)mtget.mt_erreg,
						    saverr);
						break;
					case MTS_RESID:
						respond(
						    (offset_t)mtget.mt_resid,
						    saverr);
						break;
					case MTS_FILENO:
						respond(
						    (offset_t)mtget.mt_fileno,
						    saverr);
						break;
					case MTS_BLKNO:
						respond(
						    (offset_t)mtget.mt_blkno,
						    saverr);
						break;
					case MTS_FLAGS:
						respond(
						    (offset_t)mtget.mt_flags,
						    saverr);
						break;
					case MTS_BF:
						respond((offset_t)mtget.mt_bf,
						    saverr);
						break;
					default:
						respond(-1LL, EINVAL);
						break;
					}
				} else {
					respond((offset_t)sizeof (mtget),
					    saverr);
					(void) write(1, (char *)&mtget,
					    sizeof (mtget));
				}
			}
			break;
		}

		case 'W':
			getstring(count, sizeof (count));
			n = (size_t)atol(count);
			checkbuf(n);
			DEBUG1("rmtd: W %s\n", count);
#ifdef lint
			cc = 0;
#endif
			for (i = 0; i < n; i += (size_t)cc) {
				cc = read(0, &record[i], n - i);
				if (cc <= 0) {
					DEBUG1(gettext("%s: premature eof\n"),
						"rmtd");
					exit(2);
				}
			}
			(void) kill(next, RECV);
			(void) sigsuspend(&tapemask);
			rval = (offset_t)write(tape, record, n);
			saverr = errno;
			(void) kill(next, TAPE);
			(void) sigsuspend(&sendmask);
			respond(rval, saverr);
			break;

		case 'R':
			getstring(count, sizeof (count));
			n = (size_t)atol(count);
			checkbuf(n);
			DEBUG1("rmtd: R %s\n", count);
			(void) kill(next, RECV);
			(void) sigsuspend(&tapemask);
			rval = (offset_t)read(tape, record, n);
			saverr = errno;
			(void) kill(next, TAPE);
			(void) sigsuspend(&sendmask);
			respond(rval, saverr);
			(void) write(1, record, (size_t)rval);
			break;

		default:
			DEBUG2(gettext("%s: garbage command '%c'\n"),
				"rmtd", key);
			/*FALLTHROUGH*/

		case 'C':
		case 'O':
			/* rendezvous back into a single process */
			if (setjmp(sjbuf) == 0 || getpid() != parent) {
				(void) sigsuspend(&tapemask);
				(void) sigsuspend(&sendmask);
				(void) kill(parent, key == 'O' ? OPEN :
					key == 'C' ? CLOSE : ERROR);
				(void) sigemptyset(&newmask);
				(void) sigsuspend(&newmask);
			}
			while (children > 0) {
				(void) kill(childpid[--children], SIGKILL);
				while (wait(NULL) != childpid[children])
					;
			}
			next = parent;
			if (key == 'C') {
				getstring(device, sizeof (device));
				DEBUG1("rmtd: C %s\n", device);
				rval = (offset_t)close(tape);
				respond(rval, errno);
				(void) kill(parent, TAPE);
				(void) kill(parent, SEND);
				continue;
			}
			if (key != 'O') 		/* garbage command */
				exit(3);
			(void) close(tape);
			getstring(device, sizeof (device));
			getstring(mode, sizeof (mode));
			DEBUG2("rmtd: O %s %s\n", device, mode);
			/*
			 * Due to incompatibilities in the
			 * assignment of mode bits between
			 * BSD and System V, we strip all
			 * but the read/write bits.  However,
			 * we also want to handle things larger
			 * than 2GB, so we also force O_LARGEFILE.
			 */
			tape = open(device, O_LARGEFILE |
			    (atoi(mode) & (O_RDONLY|O_WRONLY|O_RDWR)));
			respond((offset_t)tape, errno);
			if (tape >= 0)			/* fork off */
				while (children < MAXCHILD &&
					(childpid[children] = fork()) > 0)
						next = childpid[children++];
			if (next == parent) {
				(void) kill(parent, RECV);
				(void) kill(parent, TAPE);
				(void) kill(parent, SEND);
			}
			(void) sigsuspend(&cmdmask);
			continue;
		}
		(void) kill(next, SEND);
		(void) sigsuspend(&cmdmask);
	}
	(void) kill(next, RECV);
	return (0);
}

static void
respond(offset_t rval, int Errno)
{
	char resp[SSIZE];
	char *errstr = strerror(Errno);

	if (rval < 0) {
		(void) snprintf(resp, SSIZE, "E%d\n%s\n", Errno, errstr);
		DEBUG2("rmtd: E %d (%s)\n", Errno, errstr);
	} else {
		(void) snprintf(resp, SSIZE, "A%lld\n", rval);
		DEBUG1("rmtd: A %lld\n", rval);
	}
	resp[SSIZE - 1] = '\0';
	(void) write(1, resp, (int)strlen(resp));
}

static void
getstring(char *cp, size_t size)
{
	char *limit = cp + size - 1;

	cp--;			/* nullify first increment */
	do {
		cp++;
		if (read(0, cp, 1) != 1)
			exit(0);
	} while ((*cp != '\n') && (cp < limit));
	*cp = '\0';
}

static void
checkbuf(size_t size)
{
	if (size <= maxrecsize)
		return;
	if (record != 0)
		free(record);
	if ((record = malloc(size)) == NULL) {
		DEBUG2(gettext("%s: cannot allocate %ld-byte buffer\n"),
		    size, "rmtd");
		exit(4);
	}
	maxrecsize = size;
}
