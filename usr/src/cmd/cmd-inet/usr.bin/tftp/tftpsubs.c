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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Simple minded read-ahead/write-behind subroutines for tftp user and
 * server.  Written originally with multiple buffers in mind, but current
 * implementation has two buffer logic wired in.
 *
 * Todo:  add some sort of final error check so when the write-buffer
 * is finally flushed, the caller can detect if the disk filled up
 * (or had an i/o error) and return a nak to the other side.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/filio.h>

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <string.h>

#include "tftpcommon.h"

struct errmsg errmsgs[] = {
	{ EUNDEF,	"Undefined error code" },
	{ ENOTFOUND,	"File not found" },
	{ EACCESS,	"Access violation" },
	{ ENOSPACE,	"Disk full or allocation exceeded" },
	{ EBADOP,	"Illegal TFTP operation" },
	{ EBADID,	"Unknown transfer ID" },
	{ EEXISTS,	"File already exists" },
	{ ENOUSER,	"No such user" },
	{ EOPTNEG,	"Option negotiation error" },
	{ -1,		NULL }
};

static struct bf {
	int	counter;	/* size of data in buffer, or flag */
	tftpbuf	buf;		/* room for data packet */
} bfs[2];

extern int blocksize;		/* Number of data bytes in a DATA packet */
				/* Values for bf.counter  */
#define	BF_ALLOC -3	/* alloc'd but not yet filled */
#define	BF_FREE  -2	/* free */
/* [-1 .. blocksize] = size of data in the data buffer */

static int nextone;	/* index of next buffer to use */
static int current;	/* index of buffer in use */

			/* control flags for crlf conversions */
static int newline = 0;	/* fillbuf: in middle of newline expansion */
static int prevchar = -1;	/* putbuf: previous char (cr check) */

static struct tftphdr *rw_init(int);

struct tftphdr *w_init() { return (rw_init(0)); }	/* write-behind */
struct tftphdr *r_init() { return (rw_init(1)); }	/* read-ahead */

/*
 * Init for either read-ahead or write-behind.
 * x is zero for write-behind, one for read-head.
 */
static struct tftphdr *
rw_init(int x)
{
	newline = 0;	/* init crlf flag */
	prevchar = -1;
	bfs[0].counter = BF_ALLOC;	/* pass out the first buffer */
	current = 0;
	bfs[1].counter = BF_FREE;
	nextone = x;	/* ahead or behind? */
	return (&bfs[0].buf.tb_hdr);
}


/*
 * Have emptied current buffer by sending to net and getting ack.
 * Free it and return next buffer filled with data.
 */
int
readit(FILE *file, struct tftphdr **dpp, int convert)
{
	struct bf *b;

	bfs[current].counter = BF_FREE; /* free old one */
	current = !current;	/* "incr" current */

	b = &bfs[current];	/* look at new buffer */
	if (b->counter == BF_FREE)	/* if it's empty */
		read_ahead(file, convert);	/* fill it */
	*dpp = &b->buf.tb_hdr;	/* set caller's ptr */
	return (b->counter);
}

/*
 * fill the input buffer, doing ascii conversions if requested
 * conversions are  lf -> cr,lf  and cr -> cr, nul
 */
void
read_ahead(FILE *file, int convert)
{
	int i;
	char *p;
	int c;
	struct bf *b;
	struct tftphdr *dp;

	b = &bfs[nextone];	/* look at "next" buffer */
	if (b->counter != BF_FREE)	/* nop if not free */
		return;
	nextone = !nextone;	/* "incr" next buffer ptr */

	dp = &b->buf.tb_hdr;

	if (!convert) {
		b->counter = fread(dp->th_data, sizeof (char), blocksize,
		    file);
		if (ferror(file))
			b->counter = -1;
		return;
	}

	p = dp->th_data;
	for (i = 0; i < blocksize; i++) {
		if (newline) {
			if (prevchar == '\n')
				c = '\n';	/* lf to cr,lf */
			else    c = '\0';	/* cr to cr,nul */
			newline = 0;
		} else {
			c = getc(file);
			if (c == EOF) break;
			if (c == '\n' || c == '\r') {
				prevchar = c;
				c = '\r';
				newline = 1;
			}
		}
		*p++ = c;
	}
	b->counter = (int)(p - dp->th_data);
}

/*
 * Update count associated with the buffer, get new buffer
 * from the queue.  Calls write_behind only if next buffer not
 * available.
 */
int
writeit(FILE *file, struct tftphdr **dpp, int ct, int convert)
{
	bfs[current].counter = ct;	/* set size of data to write */
	current = !current;		/* switch to other buffer */
	if (bfs[current].counter != BF_FREE)	/* if not free */
		if (write_behind(file, convert) < 0)	/* flush it */
			ct = -1;
	bfs[current].counter = BF_ALLOC;	/* mark as alloc'd */
	*dpp = &bfs[current].buf.tb_hdr;
	return (ct);	/* this is a lie of course */
}

/*
 * Output a buffer to a file, converting from netascii if requested.
 * CR,NUL -> CR  and CR,LF => LF.
 * Note spec is undefined if we get CR as last byte of file or a
 * CR followed by anything else.  In this case we leave it alone.
 */
int
write_behind(FILE *file, int convert)
{
	char *buf;
	int count;
	int ct;
	char *p;
	int c;	/* current character */
	struct bf *b;
	struct tftphdr *dp;

	b = &bfs[nextone];
	if (b->counter < -1)	/* anything to flush? */
		return (0);	/* just nop if nothing to do */

	count = b->counter;	/* remember byte count */
	b->counter = BF_FREE;	/* reset flag */
	dp = &b->buf.tb_hdr;
	nextone = !nextone;	/* incr for next time */
	buf = dp->th_data;

	if (count <= 0)
		return (0);	/* nak logic? */

	if (!convert) {
		size_t	left = count;

		while (left > 0) {
			size_t	written;

			written = fwrite(buf, sizeof (char), left, file);
			if (ferror(file)) {
				/* Retry if we were interrupted by a signal. */
				if (errno == EINTR)
					continue;
				return (-1);
			}
			if (written == 0)
				return (-1);

			left -= written;
			buf += written;
		}

		return (count);
	}

	p = buf;
	ct = count;
	while (ct--) {	/* loop over the buffer */
		c = *p++;	/* pick up a character */
		if (prevchar == '\r') {	/* if prev char was cr */
			if (c == '\n') { /* if have cr,lf then just */
				/* smash lf on top of the cr */
				if (fseek(file, -1, SEEK_CUR) < 0)
					return (-1);
			} else {
				if (c == '\0') {
					/*
					 * If we have cr,nul then
					 * just skip over the putc.
					 */
					prevchar = 0;
					continue;
				}
			}
			/* else just fall through and allow it */
		}
		if (putc(c, file) == EOF)
			return (-1);
		prevchar = c;
	}
	return (count);
}


/*
 * When an error has occurred, it is possible that the two sides
 * are out of synch.  Ie: that what I think is the other side's
 * response to packet N is really their response to packet N-1.
 *
 * So, to try to prevent that, we flush all the input queued up
 * for us on the network connection on our host.
 *
 * We return the number of packets we flushed (mostly for reporting
 * when trace is active) or -1 in case of an error.
 */

int
synchnet(int socket)
{
	struct pollfd	pfd;
	int 		packets;

	pfd.fd = socket;
	pfd.events = POLLRDNORM;
	for (packets = 0; ; packets++) {
		char			buf;
		struct sockaddr_in6	from;
		socklen_t		fromlen;

		if (poll(&pfd, 1, 0) <= 0)
			break;

		/*
		 * A one byte buffer is enough because recvfrom() will
		 * discard the remaining data of the packet.
		 */
		fromlen = sizeof (from);
		if (recvfrom(socket, &buf, sizeof (buf), 0,
		    (struct sockaddr *)&from, &fromlen) < 0)
			return (-1);
	}

	return (packets);
}

/*
 * Return a pointer to the next field in string s, or return NULL if no
 * terminating NUL is found for the current field before end.
 */
char *
next_field(const char *s, const char *end)
{
	if (s < end) {
		s = memchr(s, 0, end - s);
		if (s != NULL)
			return ((char *)s + 1);
	}
	return (NULL);
}

/*
 * Print to stream options in the format option_name=option_value
 */
void
print_options(FILE *stream, char *opts, int len)
{
	char *cp, *optname, *optval;
	char *endopts = opts + len;
	int first = 1;

	/*
	 * Ignore null padding, appended by broken TFTP clients to
	 * requests which don't include options.
	 */
	cp = opts;
	while ((cp < endopts) && (*cp == '\0'))
		cp++;
	if (cp == endopts)
		return;

	while (opts < endopts) {
		optname = opts;
		if ((optval = next_field(optname, endopts)) == NULL) {
			(void) putc('?', stream);
			return;
		}
		if (first)
			first = 0;
		else
			(void) putc(' ', stream);
		(void) fputs(optname, stream);
		if ((opts = next_field(optval, endopts)) == NULL) {
			(void) putc('?', stream);
			return;
		}
		(void) fprintf(stream, "=%s", optval);
	}
}

/*
 * Turn off the alarm timer and ensure any pending SIGALRM signal is ignored.
 */
void
cancel_alarm(void)
{
	(void) alarm(0);
	(void) signal(SIGALRM, SIG_IGN);
	(void) sigrelse(SIGALRM);
}
