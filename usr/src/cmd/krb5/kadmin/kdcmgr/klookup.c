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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

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

/*
 * Private resolver of target and type with arguments:
 * klooukp [ target [ RR_type ] ]
 *
 * Utitilizes DNS lookups to discover domain and realm information.  This CLI
 * is used primarily by kdcmgr(1M) and kclient(1M).
 */

int
/* ARGSUSED */
main(int argc, char **argv)
{
	unsigned char answer[NS_MAXMSG], *ansp = NULL, *end, a, b, c, d;
	int len = 0, anslen, hostlen, nq, na, type, class;
	int ttl __unused, priority __unused, weight __unused, port, size;
	char name[NS_MAXDNAME], *cp, *typestr = NULL;
	char nbuf[INET6_ADDRSTRLEN];
	struct __res_state stat;
	int found = 0;
	int rr_type = T_A;
	HEADER *h;

	if (argc > 3)
		exit(1);

	if (argc == 1) {
		if (gethostname(name, MAXHOSTNAMELEN) != 0)
			exit(1);
	} else {
		(void) strncpy(name, (char *)argv[1], NS_MAXDNAME);
		if (argc == 3) {
			typestr = argv[2];

			switch (*typestr) {
			case 'A':
				rr_type = T_A;
				break;
			case 'C':
				rr_type = T_CNAME;
				break;
			case 'I':
				rr_type = T_A;
				break;
			case 'P':
				rr_type = T_PTR;
				(void) sscanf(name, "%hhd.%hhd.%hhd.%hhd",
				    &a, &b, &c, &d);
				(void) sprintf(name, "%d.%d.%d.%d.in-addr.arpa",
				    d, c, b, a);
				break;
			case 'S':
				rr_type = T_SRV;
				break;
			default:
				exit(1);
			}
		}
	}

	(void) memset(&stat, 0, sizeof (stat));

	if (res_ninit(&stat) == -1)
		exit(1);

	anslen = sizeof (answer);
	len = res_nsearch(&stat, name, C_IN, rr_type, answer, anslen);

	if (len < sizeof (HEADER)) {
		res_ndestroy(&stat);
		exit(1);
	}

	ansp = answer;
	end = ansp + anslen;

	/* LINTED */
	h = (HEADER *)answer;
	nq = ntohs(h->qdcount);
	na = ntohs(h->ancount);
	ansp += HFIXEDSZ;

	if (nq != 1 || na < 1) {
		res_ndestroy(&stat);
		exit(1);
	}

	hostlen = sizeof (name);
	len = dn_expand(answer, end, ansp, name, hostlen);
	if (len < 0) {
		res_ndestroy(&stat);
		exit(1);
	}

	ansp += len + QFIXEDSZ;

	if (ansp > end) {
		res_ndestroy(&stat);
		exit(1);
	}

	while (na-- > 0 && ansp < end) {

		len = dn_expand(answer, end, ansp, name, hostlen);

		if (len < 0)
			continue;
		ansp += len;			/* name */
		NS_GET16(type, ansp);		/* type */
		NS_GET16(class, ansp);		/* class */
		NS_GET32(ttl, ansp);		/* ttl */
		NS_GET16(size, ansp);		/* size */

		if ((ansp + size) > end) {
			res_ndestroy(&stat);
			exit(1);
		}
		if (type == T_SRV) {
			NS_GET16(priority, ansp);
			NS_GET16(weight, ansp);
			NS_GET16(port, ansp);
			len = dn_expand(answer, end, ansp, name, hostlen);
			if (len < 0) {
				res_ndestroy(&stat);
				exit(1);
			}
			for (cp = name; *cp; cp++) {
				*cp = tolower(*cp);
			}
			(void) printf("%s %d\n", name, port);
		} else if (typestr && *typestr == 'I') {
			(void) inet_ntop(AF_INET, (void *)ansp, nbuf,
			    INET6_ADDRSTRLEN);
			len = size;
			(void) printf("%s\n", nbuf);
		} else if (type == T_PTR) {
			len = dn_expand(answer, end, ansp, name, hostlen);
			if (len < 0) {
				res_ndestroy(&stat);
				exit(1);
			}
		}
		ansp += len;
		if (type == rr_type && class == C_IN) {
			found = 1;
			if (type != T_SRV && !(typestr && *typestr == 'I'))
				break;
		}
	}

	if (found != 1) {
		res_ndestroy(&stat);
		exit(1);
	}

	for (cp = name; *cp; cp++) {
		*cp = tolower(*cp);
	}

	if (type != T_SRV && !(typestr && *typestr == 'I'))
		(void) printf("%s\n", name);

	res_ndestroy(&stat);

	return (0);
}
