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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Routing Table Management Daemon
 */
#include "defs.h"

#define	NRECORDS	50		/* size of circular trace buffer */

boolean_t	tracepackets;		/* watch packets as they go by */
int		tracing;		/* bitmask: */
FILE		*ftrace;		/* output trace file */

static int	iftraceinit(struct interface *ifp, struct ifdebug *ifd);
static void	dumpif(FILE *fp, struct interface *ifp);
static void	dumptrace(FILE *fp, char *dir, struct ifdebug *ifd);

void
traceinit(struct interface *ifp)
{
	if (iftraceinit(ifp, &ifp->int_input) &&
	    iftraceinit(ifp, &ifp->int_output))
		return;
	tracing = 0;
	(void) fprintf(stderr, "traceinit: can't init %s\n",
	    (ifp->int_name != NULL) ? ifp->int_name : "(noname)");
}

static int
iftraceinit(struct interface *ifp, struct ifdebug *ifd)
{
	struct iftrace *t;

	ifd->ifd_records = (struct iftrace *)
	    malloc((size_t)NRECORDS * sizeof (struct iftrace));
	if (ifd->ifd_records == NULL)
		return (0);
	ifd->ifd_front = ifd->ifd_records;
	ifd->ifd_count = 0;
	for (t = ifd->ifd_records; t < ifd->ifd_records + NRECORDS; t++) {
		t->ift_size = 0;
		t->ift_packet = NULL;
	}
	ifd->ifd_if = ifp;
	return (1);
}

void
traceon(char *file)
{
	struct stat stbuf;

	if (ftrace != NULL)
		return;
	if (stat(file, &stbuf) >= 0 && (stbuf.st_mode & S_IFMT) != S_IFREG)
		return;
	ftrace = fopen(file, "a");
	if (ftrace == NULL)
		return;
	(void) dup2(fileno(ftrace), 1);
	(void) dup2(fileno(ftrace), 2);
}

void
traceonfp(FILE *fp)
{
	if (ftrace != NULL)
		return;
	ftrace = fp;
	if (ftrace == NULL)
		return;
	(void) dup2(fileno(ftrace), 1);
	(void) dup2(fileno(ftrace), 2);
}

void
trace(struct ifdebug *ifd, struct sockaddr_in6 *who, char *p, int len, int m)
{
	struct iftrace *t;

	if (ifd->ifd_records == 0)
		return;
	t = ifd->ifd_front++;
	if (ifd->ifd_front >= ifd->ifd_records + NRECORDS)
		ifd->ifd_front = ifd->ifd_records;
	if (ifd->ifd_count < NRECORDS)
		ifd->ifd_count++;
	if (t->ift_size > 0 && t->ift_size < len && t->ift_packet != NULL) {
		free(t->ift_packet);
		t->ift_packet = NULL;
	}
	(void) time(&t->ift_stamp);
	t->ift_who = *who;
	if (len > 0 && t->ift_packet == NULL) {
		t->ift_packet = (char *)malloc((size_t)len);
		if (t->ift_packet == NULL)
			len = 0;
	}
	if (len > 0)
		bcopy(p, t->ift_packet, len);
	t->ift_size = len;
	t->ift_metric = m;
}

void
traceaction(FILE *fp, char *action, struct rt_entry *rt)
{
	static struct bits {
		ulong_t	t_bits;
		char	*t_name;
	} flagbits[] = {
		/* BEGIN CSTYLED */
		{ RTF_UP,		"UP" },
		{ RTF_GATEWAY,		"GATEWAY" },
		{ RTF_HOST,		"HOST" },
		{ 0,			NULL }
		/* END CSTYLED */
	}, statebits[] = {
		/* BEGIN CSTYLED */
		{ RTS_INTERFACE,	"INTERFACE" },
		{ RTS_CHANGED,		"CHANGED" },
		{ RTS_PRIVATE,		"PRIVATE" },
		{ 0,			NULL }
		/* END CSTYLED */
	};
	struct bits *p;
	boolean_t first;
	char c;
	time_t t;

	if (fp == NULL)
		return;
	(void) time(&t);
	(void) fprintf(fp, "%.15s %s ", ctime(&t) + 4, action);
	if (rt != NULL) {
		char buf1[INET6_ADDRSTRLEN];

		(void) fprintf(fp, "prefix %s/%d ",
		    inet_ntop(AF_INET6, (void *)&rt->rt_dst, buf1,
			sizeof (buf1)),
		    rt->rt_prefix_length);
		(void) fprintf(fp, "via %s metric %d",
		    inet_ntop(AF_INET6, (void *)&rt->rt_router, buf1,
			sizeof (buf1)),
		    rt->rt_metric);
		if (rt->rt_ifp != NULL) {
			(void) fprintf(fp, " if %s",
			    (rt->rt_ifp->int_name != NULL) ?
				rt->rt_ifp->int_name : "(noname)");
		}
		(void) fprintf(fp, " state");
		c = ' ';
		for (first = _B_TRUE, p = statebits; p->t_bits > 0; p++) {
			if ((rt->rt_state & p->t_bits) == 0)
				continue;
			(void) fprintf(fp, "%c%s", c, p->t_name);
			if (first) {
				c = '|';
				first = _B_FALSE;
			}
		}
		if (first)
			(void) fprintf(fp, " 0");
		if (rt->rt_flags & (RTF_UP | RTF_GATEWAY)) {
			c = ' ';
			for (first = _B_TRUE, p = flagbits; p->t_bits > 0;
			    p++) {
				if ((rt->rt_flags & p->t_bits) == 0)
					continue;
				(void) fprintf(fp, "%c%s", c, p->t_name);
				if (first) {
					c = '|';
					first = _B_FALSE;
				}
			}
		}
	}
	(void) putc('\n', fp);
	if (!tracepackets && rt != NULL && rt->rt_ifp != NULL)
		dumpif(fp, rt->rt_ifp);
	(void) fflush(fp);
}

static void
dumpif(FILE *fp, struct interface *ifp)
{
	if (ifp->int_input.ifd_count != 0 || ifp->int_output.ifd_count != 0) {
		(void) fprintf(fp, "*** Packet history for interface %s ***\n",
		    (ifp->int_name != NULL) ? ifp->int_name : "(noname)");
		dumptrace(fp, "to", &ifp->int_output);
		dumptrace(fp, "from", &ifp->int_input);
		(void) fprintf(fp, "*** end packet history ***\n");
	}
	(void) fflush(fp);
}

static void
dumptrace(FILE *fp, char *dir, struct ifdebug *ifd)
{
	struct iftrace *t;
	char *cp = (strcmp(dir, "to") != 0) ? "Output" : "Input";

	if (ifd->ifd_front == ifd->ifd_records &&
	    ifd->ifd_front->ift_size == 0) {
		(void) fprintf(fp, "%s: no packets.\n", cp);
		(void) fflush(fp);
		return;
	}
	(void) fprintf(fp, "%s trace:\n", cp);
	t = ifd->ifd_front - ifd->ifd_count;
	if (t < ifd->ifd_records)
		t += NRECORDS;
	for (; ifd->ifd_count; ifd->ifd_count--, t++) {
		if (t >= ifd->ifd_records + NRECORDS)
			t = ifd->ifd_records;
		if (t->ift_size == 0)
			continue;
		(void) fprintf(fp, "%.24s: metric=%d\n", ctime(&t->ift_stamp),
		    t->ift_metric);
		dumppacket(fp, dir, (struct sockaddr_in6 *)&t->ift_who,
		    t->ift_packet, t->ift_size);
	}
}

/*ARGSUSED*/
void
dumppacket(FILE *fp, char *dir, struct sockaddr_in6 *who, char *cp, int size)
{
	/* XXX Output contents of the RIP packet */
}
