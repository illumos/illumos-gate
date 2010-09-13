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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/dhcp.h>
#include <netdb.h>
#include "dhcpd.h"

static char	*dhcp_msg_cats[] = {
	/* L_ASSIGN */		"ASSIGN",
	/* L_REPLY */		"EXTEND",
	/* L_RELEASE */		"RELEASE",
	/* L_DECLINE */		"DECLINE",
	/* L_INFORM */		"INFORM",
	/* L_NAK */		"NAK",
	/* L_ICMP_ECHO */	"ICMP-ECHO",
	/* L_RELAY_REQ */	"RELAY-SRVR",
	/* L_RELAY_REP */	"RELAY-CLNT"
};

static char	*protos[] = {
	/* P_BOOTP */		"BOOTP",
	/* P_DHCP */		"DHCP"
};

/*
 * Transaction logging. Note - if we're in debug mode, the transactions
 * are logged to the console!
 *
 * 'cip' and 'sip' are expected in network order.
 */
void
logtrans(DHCP_PROTO p, DHCP_MSG_CATEGORIES type, time_t lease,
    struct in_addr cip, struct in_addr sip, PKT_LIST *plp)
{
	char	*cat, *proto, *t, *class_id;
	uint_t	maclen;
	char	class_idbuf[DHCP_MAX_OPT_SIZE];
	char	cidbuf[DHCP_MAX_OPT_SIZE];
	char	ntoabc[INET_ADDRSTRLEN], ntoabs[INET_ADDRSTRLEN];
	char	macbuf[(sizeof (((PKT *)NULL)->chaddr) * 2) + 1];

	if (log_local < 0)
		return;

	proto = protos[p];
	cat = dhcp_msg_cats[type];

	(void) disp_cid(plp, cidbuf, sizeof (cidbuf));

	class_id = get_class_id(plp, class_idbuf, sizeof (class_idbuf));

	/* convert white space in class id into periods (.) */
	if (class_id != NULL) {
		for (t = class_id; *t != '\0'; t++) {
			if (isspace(*t))
				*t = '.';
		}
	} else
		class_id = "N/A";

	maclen = sizeof (macbuf);
	macbuf[0] = '\0';
	(void) octet_to_hexascii(plp->pkt->chaddr, plp->pkt->hlen, macbuf,
	    &maclen);

	dhcpmsg(log_local | LOG_NOTICE, "%s %s %010ld %010ld %s %s %s %s %s\n",
	    proto, cat, time(NULL), lease,
	    inet_ntop(AF_INET, &cip, ntoabc, sizeof (ntoabc)),
	    inet_ntop(AF_INET, &sip, ntoabs, sizeof (ntoabs)),
	    cidbuf, class_id, macbuf);
}
