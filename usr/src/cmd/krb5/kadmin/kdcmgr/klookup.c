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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

int
/* ARGSUSED */
main(int argc, char **argv)
{
	unsigned char answer[NS_MAXMSG], *ansp = NULL, *end;
	int len = 0, anslen, hostlen, nq, na, type, class;
	char hostname[MAXHOSTNAMELEN], *cp;
	struct __res_state stat;
	int found = 0;
	HEADER *h;

	if (argc != 1)
		exit(1);

	if (gethostname(hostname, MAXHOSTNAMELEN) != 0)
		exit(1);

	(void) memset(&stat, 0, sizeof (stat));

	if (res_ninit(&stat) == -1)
		exit(1);

	anslen = sizeof (answer);
	len = res_nsearch(&stat, hostname, C_IN, T_A, answer, anslen);

	if (len < sizeof (HEADER))
		exit(1);

	ansp = answer;
	end = ansp + anslen;

	/* LINTED */
	h = (HEADER *)answer;
	nq = ntohs(h->qdcount);
	na = ntohs(h->ancount);
	ansp += HFIXEDSZ;

	if (nq != 1 || na < 1)
		exit(1);

	hostlen = sizeof (hostname);
	len = dn_expand(answer, end, ansp, hostname, hostlen);
	if (len < 0)
		exit(1);

	ansp += len + QFIXEDSZ;

	if (ansp > end)
		exit(1);

	while (na-- > 0 && ansp < end) {
		len = dn_expand(answer, end, ansp, hostname, hostlen);

		if (len < 0)
			continue;
		ansp += len;			/* hostname */
		type = ns_get16(ansp);
		ansp += INT16SZ;		/* type */
		class = ns_get16(ansp);
		ansp += INT16SZ;		/* class */
		ansp += INT32SZ;		/* ttl */
		len = ns_get16(ansp);
		ansp += INT16SZ;		/* size */
		ansp += len;
		if (type == T_A && class == C_IN) {
			found = 1;
			break;
		}
	}

	if (found != 1)
		exit(1);

	for (cp = hostname; *cp; cp++) {
		*cp = tolower(*cp);
	}

	(void) printf("%s\n", hostname);

	return (0);
}
