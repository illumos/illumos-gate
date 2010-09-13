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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routing Table Management Daemon
 */
#include "defs.h"

/*
 * Find the interface with given name.
 */
struct interface *
if_ifwithname(char *name)
{
	struct interface *ifp;

	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
		if (ifp->int_name != NULL &&
		    strcmp(ifp->int_name, name) == 0)
			break;
	}
	return (ifp);
}

/*
 * An interface has declared itself down - remove it completely
 * from our routing tables but keep the interface structure around.
 */
void
if_purge(struct interface *pifp)
{
	rtpurgeif(pifp);
	pifp->int_flags &= ~RIP6_IFF_UP;
}

static void
if_dump2(FILE *fp)
{
	struct interface *ifp;
	char buf1[INET6_ADDRSTRLEN];
	static struct bits {
		uint_t	t_bits;
		char	*t_name;
	} flagbits[] = {
		/* BEGIN CSTYLED */
		{ RIP6_IFF_UP,		"UP" },
		{ RIP6_IFF_POINTOPOINT,	"POINTOPOINT" },
		{ RIP6_IFF_MARKED,	"MARKED" },
		{ RIP6_IFF_NORTEXCH,	"NORTEXCH" },
		{ RIP6_IFF_PRIVATE,	"PRIVATE" },
		{ 0,			NULL }
		/* END CSTYLED */
	};
	struct bits *p;
	char c;
	boolean_t first;

	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
		(void) fprintf(fp, "interface %s:\n",
		    (ifp->int_name != NULL) ? ifp->int_name : "(noname)");

		(void) fprintf(fp, "\tflags ");
		c = ' ';
		for (first = _B_TRUE, p = flagbits; p->t_bits > 0; p++) {
			if ((ifp->int_flags & p->t_bits) == 0)
				continue;
			(void) fprintf(fp, "%c%s", c, p->t_name);
			if (first) {
				c = '|';
				first = _B_FALSE;
			}
		}
		if (first)
			(void) fprintf(fp, " 0");

		(void) fprintf(fp, "\n\tpackets received %d\n",
		    ifp->int_ipackets);
		(void) fprintf(fp, "\tpackets sent %d\n", ifp->int_opackets);
		(void) fprintf(fp, "\ttransitions %d\n", ifp->int_transitions);
		if ((ifp->int_flags & RIP6_IFF_UP) == 0)
			continue;
		if (ifp->int_flags & RIP6_IFF_POINTOPOINT) {
			(void) fprintf(fp, "\tlocal %s\n",
			    inet_ntop(AF_INET6, (void *)&ifp->int_addr, buf1,
				sizeof (buf1)));
			(void) fprintf(fp, "\tremote %s\n",
			    inet_ntop(AF_INET6, (void *)&ifp->int_dstaddr, buf1,
				sizeof (buf1)));
		} else {
			(void) fprintf(fp, "\tprefix %s/%d\n",
			    inet_ntop(AF_INET6, (void *)&ifp->int_addr, buf1,
				sizeof (buf1)),
			    ifp->int_prefix_length);
		}
		(void) fprintf(fp, "\tmetric %d\n", ifp->int_metric);
		(void) fprintf(fp, "\tmtu %d\n", ifp->int_mtu);
	}
	(void) fflush(fp);
}

void
if_dump(void)
{
	if (ftrace != NULL)
		if_dump2(ftrace);
	else
		if_dump2(stderr);
}
