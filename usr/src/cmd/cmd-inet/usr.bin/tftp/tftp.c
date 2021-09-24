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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * TFTP User Program -- Protocol Machines
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <inttypes.h>

#include "tftpcommon.h"
#include "tftpprivate.h"

static char	*blksize_str(void);
static char	*timeout_str(void);
static char	*tsize_str(void);
static int	blksize_handler(char *);
static int	timeout_handler(char *);
static int	tsize_handler(char *);
static int	add_options(char *, char *);
static int	process_oack(tftpbuf *, int);
static void	nak(int);
static void	startclock(void);
static void	stopclock(void);
static void	printstats(char *, off_t);
static int	makerequest(int, char *, struct tftphdr *, char *);
static void	tpacket(char *, struct tftphdr *, int);

static struct options {
	char	*opt_name;
	char	*(*opt_str)(void);
	int	(*opt_handler)(char *);
} options[] = {
	{ "blksize",	blksize_str, blksize_handler },
	{ "timeout",	timeout_str, timeout_handler },
	{ "tsize",	tsize_str, tsize_handler },
	{ NULL }
};

static char	optbuf[MAX_OPTVAL_LEN];
static bool	tsize_set;

static tftpbuf	ackbuf;
static int	timeout;
static off_t	tsize;
static jmp_buf	timeoutbuf;

int	blocksize = SEGSIZE;	/* Number of data bytes in a DATA packet */

/*ARGSUSED*/
static void
timer(int signum)
{
	timeout += rexmtval;
	if (timeout >= maxtimeout) {
		(void) fputs("Transfer timed out.\n", stderr);
		longjmp(toplevel, -1);
	}
	(void) signal(SIGALRM, timer);
	longjmp(timeoutbuf, 1);
}

/*
 * Send the requested file.
 */
void
tftp_sendfile(int fd, char *name, char *mode)
{
	struct tftphdr *ap;	/* data and ack packets */
	struct tftphdr *dp;
	int n;
	volatile int count = 0, size;
	volatile ushort_t block = 0;
	volatile off_t amount = 0;
	struct sockaddr_in6 from;
	socklen_t fromlen;
	int convert;	/* true if doing nl->crlf conversion */
	FILE *file;
	struct stat statb;
	int errcode;

	startclock();	/* start stat's clock */
	dp = r_init();	/* reset fillbuf/read-ahead code */
	ap = &ackbuf.tb_hdr;
	file = fdopen(fd, "r");
	convert = (strcmp(mode, "netascii") == 0);

	tsize_set = ((tsize_opt != 0) && !convert && (fstat(fd, &statb) == 0));
	if (tsize_set)
		tsize = statb.st_size;

	do {
		(void) signal(SIGALRM, timer);
		if (count == 0) {
			if ((size = makerequest(WRQ, name, dp, mode)) == -1) {
				(void) fprintf(stderr,
				    "tftp: Error: Write request packet too "
				    "big\n");
				(void) fclose(file);
				return;
			}
			size -= 4;
		} else {
			size = readit(file, &dp, convert);
			if (size < 0) {
				nak(errno + 100);
				break;
			}
			dp->th_opcode = htons((ushort_t)DATA);
			dp->th_block = htons((ushort_t)block);
		}
		timeout = 0;
		(void) setjmp(timeoutbuf);
		if (trace)
			tpacket("sent", dp, size + 4);
		n = sendto(f, dp, size + 4, 0,
		    (struct sockaddr *)&sin6, sizeof (sin6));
		if (n != size + 4) {
			perror("tftp: sendto");
			goto abort;
		}
		/* Can't read-ahead first block as OACK may change blocksize */
		if (count != 0)
			read_ahead(file, convert);
		(void) alarm(rexmtval);
		for (; ; ) {
			(void) sigrelse(SIGALRM);
			do {
				fromlen = (socklen_t)sizeof (from);
				n = recvfrom(f, ackbuf.tb_data,
				    sizeof (ackbuf.tb_data), 0,
				    (struct sockaddr *)&from, &fromlen);
				if (n < 0) {
					perror("tftp: recvfrom");
					goto abort;
				}
			} while (n < offsetof(struct tftphdr, th_data));
			(void) sighold(SIGALRM);
			sin6.sin6_port = from.sin6_port;   /* added */
			if (trace)
				tpacket("received", ap, n);
			/* should verify packet came from server */
			ap->th_opcode = ntohs(ap->th_opcode);
			if (ap->th_opcode == ERROR) {
				ap->th_code = ntohs(ap->th_code);
				(void) fprintf(stderr,
				    "Error code %d", ap->th_code);
				if (n > offsetof(struct tftphdr, th_data))
					(void) fprintf(stderr, ": %.*s", n -
					    offsetof(struct tftphdr, th_data),
					    ap->th_msg);
				(void) fputc('\n', stderr);
				goto abort;
			}
			if ((count == 0) && (ap->th_opcode == OACK)) {
				errcode = process_oack(&ackbuf, n);
				if (errcode >= 0) {
					nak(errcode);
					(void) fputs("Rejected OACK\n",
					    stderr);
					goto abort;
				}
				break;
			}
			if (ap->th_opcode == ACK) {
				ap->th_block = ntohs(ap->th_block);
				if (ap->th_block == block) {
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
		if (count > 0)
			amount += size;
		block++;
		count++;
	} while (size == blocksize || count == 1);
abort:
	cancel_alarm();
	(void) fclose(file);
	stopclock();
	if (amount > 0)
		printstats("Sent", amount);
}

/*
 * Receive a file.
 */
void
tftp_recvfile(int fd, char *name, char *mode)
{
	struct tftphdr *ap;
	struct tftphdr *dp;
	volatile ushort_t block = 1;
	int n;
	volatile int size;
	volatile unsigned long amount = 0;
	struct sockaddr_in6 from;
	socklen_t fromlen;
	volatile bool firsttrip = true;
	FILE *file;
	int convert;	/* true if converting crlf -> lf */
	int errcode;

	startclock();
	dp = w_init();
	ap = &ackbuf.tb_hdr;
	file = fdopen(fd, "w");
	convert = (strcmp(mode, "netascii") == 0);

	tsize_set = (tsize_opt != 0);
	if (tsize_set)
		tsize = 0;

	if ((size = makerequest(RRQ, name, ap, mode)) == -1) {
		(void) fprintf(stderr,
		    "tftp: Error: Read request packet too big\n");
		(void) fclose(file);
		return;
	}

	do {
		(void) signal(SIGALRM, timer);
		if (firsttrip) {
			firsttrip = false;
		} else {
			ap->th_opcode = htons((ushort_t)ACK);
			ap->th_block = htons((ushort_t)(block));
			size = 4;
			block++;
		}

send_oack_ack:
		timeout = 0;
		(void) setjmp(timeoutbuf);
send_ack:
		if (trace)
			tpacket("sent", ap, size);
		if (sendto(f, ackbuf.tb_data, size, 0, (struct sockaddr *)&sin6,
		    sizeof (sin6)) != size) {
			(void) alarm(0);
			perror("tftp: sendto");
			goto abort;
		}
		if (write_behind(file, convert) < 0) {
			nak(errno + 100);
			goto abort;
		}
		(void) alarm(rexmtval);
		for (; ; ) {
			(void) sigrelse(SIGALRM);
			do  {
				fromlen = (socklen_t)sizeof (from);
				n = recvfrom(f, dp, blocksize + 4, 0,
				    (struct sockaddr *)&from, &fromlen);
				if (n < 0) {
					perror("tftp: recvfrom");
					goto abort;
				}
			} while (n < offsetof(struct tftphdr, th_data));
			(void) sighold(SIGALRM);
			sin6.sin6_port = from.sin6_port;   /* added */
			if (trace)
				tpacket("received", dp, n);
			/* should verify client address */
			dp->th_opcode = ntohs(dp->th_opcode);
			if (dp->th_opcode == ERROR) {
				dp->th_code = ntohs(dp->th_code);
				(void) fprintf(stderr, "Error code %d",
				    dp->th_code);
				if (n > offsetof(struct tftphdr, th_data))
					(void) fprintf(stderr, ": %.*s", n -
					    offsetof(struct tftphdr, th_data),
					    dp->th_msg);
				(void) fputc('\n', stderr);
				goto abort;
			}
			if ((block == 1) && (dp->th_opcode == OACK)) {
				errcode = process_oack((tftpbuf *)dp, n);
				if (errcode >= 0) {
					cancel_alarm();
					nak(errcode);
					(void) fputs("Rejected OACK\n",
					    stderr);
					(void) fclose(file);
					return;
				}
				ap->th_opcode = htons((ushort_t)ACK);
				ap->th_block = htons(0);
				size = 4;
				goto send_oack_ack;
			}
			if (dp->th_opcode == DATA) {
				int j;

				dp->th_block = ntohs(dp->th_block);
				if (dp->th_block == block) {
					break;	/* have next packet */
				}
				/*
				 * On an error, try to synchronize
				 * both sides.
				 */
				j = synchnet(f);
				if (j < 0) {
					perror("tftp: recvfrom");
					goto abort;
				}
				if ((j > 0) && trace) {
					(void) printf("discarded %d packets\n",
					    j);
				}
				if (dp->th_block == (block-1)) {
					goto send_ack;  /* resend ack */
				}
			}
		}
		cancel_alarm();
		size = writeit(file, &dp, n - 4, convert);
		if (size < 0) {
			nak(errno + 100);
			goto abort;
		}
		amount += size;
	} while (size == blocksize);

	cancel_alarm();
	if (write_behind(file, convert) < 0) {	/* flush last buffer */
		nak(errno + 100);
		goto abort;
	}
	n = fclose(file);
	file = NULL;
	if (n == EOF) {
		nak(errno + 100);
		goto abort;
	}

	/* ok to ack, since user has seen err msg */
	ap->th_opcode = htons((ushort_t)ACK);
	ap->th_block = htons((ushort_t)block);
	if (trace)
		tpacket("sent", ap, 4);
	if (sendto(f, ackbuf.tb_data, 4, 0,
	    (struct sockaddr *)&sin6, sizeof (sin6)) != 4)
		perror("tftp: sendto");

abort:
	cancel_alarm();
	if (file != NULL)
		(void) fclose(file);
	stopclock();
	if (amount > 0)
		printstats("Received", amount);
}

static int
makerequest(int request, char *name, struct tftphdr *tp, char *mode)
{
	char *cp, *cpend;
	int len;

	tp->th_opcode = htons((ushort_t)request);
	cp = (char *)&tp->th_stuff;

	/* Maximum size of a request packet is 512 bytes (RFC 2347) */
	cpend = (char *)tp + SEGSIZE;

	len = strlcpy(cp, name, cpend - cp) + 1;
	cp += len;
	if (cp > cpend)
		return (-1);

	len = strlcpy(cp, mode, cpend - cp) + 1;
	cp += len;
	if (cp > cpend)
		return (-1);

	len = add_options(cp, cpend);
	if (len == -1)
		return (-1);
	cp += len;

	return (cp - (char *)tp);
}

/*
 * Return the blksize option value string to include in the request packet.
 */
static char *
blksize_str(void)
{
	blocksize = SEGSIZE;
	if (blksize == 0)
		return (NULL);

	(void) snprintf(optbuf, sizeof (optbuf), "%d", blksize);
	return (optbuf);
}

/*
 * Return the timeout option value string to include in the request packet.
 */
static char *
timeout_str(void)
{
	if (srexmtval == 0)
		return (NULL);

	(void) snprintf(optbuf, sizeof (optbuf), "%d", srexmtval);
	return (optbuf);
}

/*
 * Return the tsize option value string to include in the request packet.
 */
static char *
tsize_str(void)
{
	if (tsize_set == false)
		return (NULL);

	(void) snprintf(optbuf, sizeof (optbuf), OFF_T_FMT, tsize);
	return (optbuf);
}

/*
 * Validate and action the blksize option value string from the OACK packet.
 * Returns -1 on success or an error code on failure.
 */
static int
blksize_handler(char *optstr)
{
	char *endp;
	int value;

	/* Make sure the option was requested */
	if (blksize == 0)
		return (EOPTNEG);
	errno = 0;
	value = (int)strtol(optstr, &endp, 10);
	if (errno != 0 || value < MIN_BLKSIZE || value > blksize ||
	    *endp != '\0')
		return (EOPTNEG);
	blocksize = value;
	return (-1);
}

/*
 * Validate and action the timeout option value string from the OACK packet.
 * Returns -1 on success or an error code on failure.
 */
static int
timeout_handler(char *optstr)
{
	char *endp;
	int value;

	/* Make sure the option was requested */
	if (srexmtval == 0)
		return (EOPTNEG);
	errno = 0;
	value = (int)strtol(optstr, &endp, 10);
	if (errno != 0 || value != srexmtval || *endp != '\0')
		return (EOPTNEG);
	/*
	 * Nothing to set, client and server retransmission intervals are
	 * set separately in the client.
	 */
	return (-1);
}

/*
 * Validate and action the tsize option value string from the OACK packet.
 * Returns -1 on success or an error code on failure.
 */
static int
tsize_handler(char *optstr)
{
	char *endp;
	longlong_t value;

	/* Make sure the option was requested */
	if (tsize_set == false)
		return (EOPTNEG);
	errno = 0;
	value = strtoll(optstr, &endp, 10);
	if (errno != 0 || value < 0 || *endp != '\0')
		return (EOPTNEG);
#if _FILE_OFFSET_BITS == 32
	if (value > MAXOFF_T)
		return (ENOSPACE);
#endif
	/*
	 * Don't bother checking the tsize value we specified in a write
	 * request is echoed back in the OACK.
	 */
	if (tsize == 0)
		tsize = value;
	return (-1);
}

/*
 * Add TFTP options to a request packet.
 */
static int
add_options(char *obuf, char *obufend)
{
	int i;
	char *cp, *ostr;

	cp = obuf;
	for (i = 0; options[i].opt_name != NULL; i++) {
		ostr = options[i].opt_str();
		if (ostr != NULL) {
			cp += strlcpy(cp, options[i].opt_name, obufend - cp)
			    + 1;
			if (cp > obufend)
				return (-1);

			cp += strlcpy(cp, ostr, obufend - cp) + 1;
			if (cp > obufend)
				return (-1);
		}
	}
	return (cp - obuf);
}

/*
 * Process OACK packet sent by server in response to options in the request
 * packet. Returns -1 on success or an error code on failure.
 */
static int
process_oack(tftpbuf *oackbuf, int n)
{
	char *cp, *oackend, *optname, *optval;
	struct tftphdr *oackp;
	int i, errcode;

	oackp = &oackbuf->tb_hdr;
	cp = (char *)&oackp->th_stuff;
	oackend = (char *)oackbuf + n;

	while (cp < oackend) {
		optname = cp;
		if ((optval = next_field(optname, oackend)) == NULL)
			return (EOPTNEG);
		if ((cp = next_field(optval, oackend)) == NULL)
			return (EOPTNEG);
		for (i = 0; options[i].opt_name != NULL; i++) {
			if (strcasecmp(optname, options[i].opt_name) == 0)
				break;
		}
		if (options[i].opt_name == NULL)
			return (EOPTNEG);
		errcode = options[i].opt_handler(optval);
		if (errcode >= 0)
			return (errcode);
	}
	return (-1);
}

/*
 * Send a nak packet (error message).
 * Error code passed in is one of the
 * standard TFTP codes, or a UNIX errno
 * offset by 100.
 */
static void
nak(int error)
{
	struct tftphdr *tp;
	int length;
	struct errmsg *pe;

	tp = &ackbuf.tb_hdr;
	tp->th_opcode = htons((ushort_t)ERROR);
	tp->th_code = htons((ushort_t)error);
	for (pe = errmsgs; pe->e_code >= 0; pe++)
		if (pe->e_code == error)
			break;
	if (pe->e_code < 0) {
		pe->e_msg = strerror(error - 100);
		tp->th_code = EUNDEF;
	}
	(void) strlcpy(tp->th_msg, pe->e_msg,
	    sizeof (ackbuf) - sizeof (struct tftphdr));
	length = strlen(pe->e_msg) + 4;
	if (trace)
		tpacket("sent", tp, length);
	if (sendto(f, ackbuf.tb_data, length, 0,
	    (struct sockaddr *)&sin6, sizeof (sin6)) != length)
		perror("nak");
}

static void
tpacket(char *s, struct tftphdr *tp, int n)
{
	static char *opcodes[] = {
	    "#0", "RRQ", "WRQ", "DATA", "ACK", "ERROR", "OACK"
	};
	char *cp, *file, *mode;
	ushort_t op = ntohs(tp->th_opcode);
	char *tpend;

	if (op < RRQ || op > OACK)
		(void) printf("%s opcode=%x ", s, op);
	else
		(void) printf("%s %s ", s, opcodes[op]);

	switch (op) {
	case RRQ:
	case WRQ:
		tpend = (char *)tp + n;
		n -= sizeof (tp->th_opcode);
		file = (char *)&tp->th_stuff;
		if ((mode = next_field(file, tpend)) == NULL) {
			(void) printf("<file=%.*s>\n", n, file);
			break;
		}
		n -= mode - file;
		if ((cp = next_field(mode, tpend)) == NULL) {
			(void) printf("<file=%s, mode=%.*s>\n", file, n, mode);
			break;
		}
		(void) printf("<file=%s, mode=%s", file, mode);
		n -= cp - mode;
		if (n > 0) {
			(void) printf(", options: ");
			print_options(stdout, cp, n);
		}
		(void) puts(">");
		break;

	case DATA:
		(void) printf("<block=%d, %d bytes>\n", ntohs(tp->th_block),
		    n - sizeof (tp->th_opcode) - sizeof (tp->th_block));
		break;

	case ACK:
		(void) printf("<block=%d>\n", ntohs(tp->th_block));
		break;

	case OACK:
		(void) printf("<options: ");
		print_options(stdout, (char *)&tp->th_stuff,
		    n - sizeof (tp->th_opcode));
		(void) puts(">");
		break;

	case ERROR:
		(void) printf("<code=%d", ntohs(tp->th_code));
		n = n - sizeof (tp->th_opcode) - sizeof (tp->th_code);
		if (n > 0)
			(void) printf(", msg=%.*s", n, tp->th_msg);
		(void) puts(">");
		break;
	}
}

static hrtime_t	tstart, tstop;

static void
startclock(void)
{
	tstart = gethrtime();
}

static void
stopclock(void)
{
	tstop = gethrtime();
}

static void
printstats(char *direction, off_t amount)
{
	hrtime_t	delta, tenths;

	delta = tstop - tstart;
	tenths = delta / (NANOSEC / 10);
	(void) printf("%s " OFF_T_FMT " bytes in %" PRId64 ".%" PRId64
	    " seconds", direction, amount, tenths / 10, tenths % 10);
	if (verbose)
		(void) printf(" [%" PRId64 " bits/sec]\n",
		    ((hrtime_t)amount * 8 * NANOSEC) / delta);
	else
		(void) putchar('\n');
}
