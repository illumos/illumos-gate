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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <thread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/dhcp.h>
#include "dhcpd.h"
#include "per_dnet.h"
#include "interfaces.h"
#include <v4_sum_impl.h>
#include <locale.h>

#define	ICMP_ECHO_SIZE	(sizeof (struct icmp) + 36)

/*
 * An implementation of ICMP ECHO for use in detecting addresses already
 * in use. Address argument expected in network order. Result is set to
 * B_TRUE if a ICMP ECHO reply is received, B_FALSE if not. Returns 0 if
 * no errors were encountered, nonzero otherwise.
 *
 * NOTES: Not interface specific. We use our routing tables to route the
 * messages correctly, and collect responses. This may mean that we
 * receive an ICMP ECHO reply thru an interface the daemon has not been
 * directed to watch. However, I believe that *ANY* echo reply means
 * trouble, regardless of the route taken!
 *
 * 'cip' is expected in network order.
 */

int
icmp_echo_check(struct in_addr *cip, boolean_t	*result)
{
	struct icmp 		*icp;
	struct ip		*ipp;
	int			sequence = 0, i, s, s_cnt, r_cnt,
				icmp_identifier, error = 0;
	socklen_t		fromlen;
	ushort_t		ip_hlen;
	hrtime_t		recv_intrvl;
	struct sockaddr_in	to, from;
	struct pollfd		pfd;
	char			ntoab[INET_ADDRSTRLEN];
	ulong_t			outpack[DHCP_SCRATCH/sizeof (ulong_t)];
	ulong_t			inpack[DHCP_SCRATCH/sizeof (ulong_t)];

	*result = B_FALSE;

	(void) inet_ntop(AF_INET, cip, ntoab, sizeof (ntoab));

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		error = errno;
		dhcpmsg(LOG_ERR,
		    "Error opening raw socket for ICMP (ping %s).\n", ntoab);
		return (error);
	}

	if (fcntl(s, F_SETFL, O_NDELAY) == -1) {
		error = errno;
		dhcpmsg(LOG_ERR,
		    "Error setting ICMP socket to no delay. (ping %s)\n",
		    ntoab);
		(void) close(s);
		return (error);
	}

	pfd.fd = s;
	pfd.events = POLLIN | POLLPRI;
	pfd.revents = 0;

	icmp_identifier = (int)thr_self() & (ushort_t)-1;
	(void) memset((void *)outpack, 0, sizeof (outpack));
	outpack[10] = 0x12345678;
	icp = (struct icmp *)outpack;
	icp->icmp_code = 0;
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_id = icmp_identifier;

	(void) memset((void *)&to, 0, sizeof (struct sockaddr_in));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = cip->s_addr;

	/*
	 * We make icmp_tries attempts to contact the target. We
	 * wait the same length of time for a response in both cases.
	 */
	for (i = 0; i < icmp_tries; i++) {
		icp->icmp_seq = sequence++;
		icp->icmp_cksum = 0;
		icp->icmp_cksum = ipv4cksum((uint16_t *)icp, ICMP_ECHO_SIZE);

		/* Deliver our ECHO. */
		s_cnt = sendto(s, (char *)outpack, ICMP_ECHO_SIZE, 0,
		    (struct sockaddr *)&to, sizeof (struct sockaddr));

		if (s_cnt < 0 || s_cnt != ICMP_ECHO_SIZE) {
			error = errno;
			dhcpmsg(LOG_ERR,
			    "Error sending ICMP message. (ping %s).\n",
			    ntoab);
			(void) close(s);
			return (error);
		}

		/* Collect replies. */
		recv_intrvl = gethrtime() +
		    (hrtime_t)(icmp_timeout) * 1000000;

		while (gethrtime() < recv_intrvl) {
			if (poll(&pfd, (nfds_t)1, icmp_timeout) < 0 ||
			    pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				/* EINTR is masked  - must be serious */
				error = errno;
				dhcpmsg(LOG_ERR, "Poll: ICMP reply for %s.\n",
				    ntoab);
				(void) close(s);
				return (error);
			}

			if (!pfd.revents) {
				continue;	/* no data, timeout */
			}

			fromlen = sizeof (from);
			if ((r_cnt = recvfrom(s, (char *)inpack,
			    sizeof (inpack), 0, (struct sockaddr *)&from,
			    &fromlen)) < 0) {
				error = errno;
				if (error == EAGAIN) {
					error = 0;
					continue;
				}
				/* EINTR is masked  - must be serious */
				dhcpmsg(LOG_ERR,
				    "recvfrom: ICMP reply for %s.\n",
				    ntoab);
				(void) close(s);
				return (error);
			}

			if (from.sin_addr.s_addr != cip->s_addr)
				continue; /* Not from the IP of interest */
			/*
			 * We know we got an ICMP message of some type from
			 * the IP of interest. Be conservative and
			 * consider it in use. The following logic is just
			 * for identifying problems in the response.
			 */
			*result = B_TRUE;

			if (!debug)
				break;

			ipp = (struct ip *)inpack;
			if (r_cnt != ntohs(ipp->ip_len)) {
				/* bogus IP header */
				dhcpmsg(LOG_NOTICE, "Malformed ICMP message "
				    "received from host %s: len %d != %d\n",
				    ntoab, r_cnt, ntohs(ipp->ip_len));
				break;
			}
			ip_hlen = ipp->ip_hl << 2;
			if (r_cnt < (int)(ip_hlen + ICMP_MINLEN)) {
				dhcpmsg(LOG_NOTICE, "ICMP message received "
				    "from host %s is too small.\n", ntoab);
				break;
			}
			icp = (struct icmp *)((uint_t)inpack + ip_hlen);
			if (ipv4cksum((uint16_t *)icp,
			    ntohs(ipp->ip_len) - ip_hlen) != 0) {
				dhcpmsg(LOG_NOTICE, "Bad checksum on incoming "
				    "ICMP echo reply. (ping %s)\n", ntoab);
			}
			if (icp->icmp_type != ICMP_ECHOREPLY) {
				dhcpmsg(LOG_NOTICE,
				    "Unexpected ICMP type %d from %s.\n",
				    icp->icmp_type, ntoab);
			}
			if (icp->icmp_id != icmp_identifier) {
				dhcpmsg(LOG_NOTICE,
				    "ICMP message id mismatch (from %s).\n",
				    ntoab);
			}
			if (icp->icmp_seq != (sequence - 1)) {
				dhcpmsg(LOG_NOTICE, "ICMP sequence mismatch: "
				    "%d != %d (ping %s)\n", icp->icmp_seq,
				    sequence - 1, ntoab);
			}
			break;
		}
	}
	(void) close(s);

	return (error);
}
