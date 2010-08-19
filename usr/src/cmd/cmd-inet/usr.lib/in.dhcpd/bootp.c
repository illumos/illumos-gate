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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include <netinet/dhcp.h>
#include <netdb.h>
#include <dhcp_symbol.h>
#include "dhcpd.h"
#include "per_dnet.h"
#include "interfaces.h"
#include <locale.h>

/*
 * This file contains the code which implements the BOOTP compatibility.
 */

/*
 * We are guaranteed that the packet received is a BOOTP request packet,
 * e.g., *NOT* a DHCP packet.
 */
void
bootp(dsvc_clnt_t *pcd, PKT_LIST *plp)
{
	boolean_t	result, existing_offer = B_FALSE;
	int		err, write_error = DSVC_SUCCESS, flags = 0;
	int		pkt_len;
	uint_t		crecords = 0, irecords = 0, srecords = 0, clen;
	uint32_t	query;
	PKT		*rep_pktp = NULL;
	IF		*ifp = pcd->ifp;
	dsvc_dnet_t	*pnd = pcd->pnd;
	uchar_t		*optp;
	dn_rec_t	dn, ndn, *dnp;
	dn_rec_list_t	*dncp = NULL, *dnip = NULL, *dnlp = NULL;
	struct in_addr	ciaddr;
	struct in_addr	no_ip;	/* network order IP */
	ENCODE		*ecp, *hecp;
	MACRO		*mp, *nmp, *cmp;
	time_t		now = time(NULL);
	DHCP_MSG_CATEGORIES	log;
	struct		hostent	h, *hp;
	char		ntoab[INET_ADDRSTRLEN], cipbuf[INET_ADDRSTRLEN];
	char		cidbuf[DHCP_MAX_OPT_SIZE];
	char		hbuf[NSS_BUFLEN_HOSTS];

	ciaddr.s_addr = htonl(INADDR_ANY);

#ifdef	DEBUG
	dhcpmsg(LOG_DEBUG, "BOOTP request received on %s\n", ifp->nm);
#endif	/* DEBUG */

	if (pcd->off_ip.s_addr != htonl(INADDR_ANY) &&
	    PCD_OFFER_TIMEOUT(pcd, now))
		purge_offer(pcd, B_TRUE, B_TRUE);

	if (pcd->off_ip.s_addr != htonl(INADDR_ANY)) {
		existing_offer = B_TRUE;
		dnlp = pcd->dnlp;
		assert(dnlp != NULL);
		dnp = dnlp->dnl_rec;
		no_ip.s_addr = htonl(dnp->dn_cip.s_addr);
		crecords = 1;
	} else {
		/*
		 * Try to find a CID entry for the client. We don't care about
		 * lease info here, since a BOOTP client always has a permanent
		 * lease. We also don't care about the entry owner either,
		 * unless we end up allocating a new entry for the client.
		 */
		DSVC_QINIT(query);

		DSVC_QEQ(query, DN_QCID);
		(void) memcpy(dn.dn_cid, pcd->cid, pcd->cid_len);
		dn.dn_cid_len = pcd->cid_len;

		DSVC_QEQ(query, DN_QFBOOTP_ONLY);
		dn.dn_flags = DN_FBOOTP_ONLY;

		/*
		 * If a client address (ciaddr) is given, we simply trust that
		 * the client knows what it's doing, and we use that IP address
		 * to locate the client's record. If we can't find the client's
		 * record, then we keep silent. If the client id of the record
		 * doesn't match this client, then either the client or our
		 * database is inconsistent, and we'll ignore it (notice
		 * message generated).
		 */
		ciaddr.s_addr = plp->pkt->ciaddr.s_addr;
		if (ciaddr.s_addr != htonl(INADDR_ANY)) {
			DSVC_QEQ(query, DN_QCIP);
			dn.dn_cip.s_addr = ntohl(ciaddr.s_addr);
		}

		dnlp = dhcp_lookup_dd_classify(pcd->pnd, B_FALSE, query,
		    -1, &dn, (void **)&dncp, S_CID);
		if (dnlp != NULL) {
			crecords = 1;
			dnp = dnlp->dnl_rec;
			if (dnp->dn_flags & DN_FUNUSABLE)
				goto leave_bootp;
			no_ip.s_addr = htonl(dnp->dn_cip.s_addr);
		}
	}

	(void) inet_ntop(AF_INET, &no_ip, cipbuf, sizeof (cipbuf));

	if (crecords == 0 && !be_automatic) {
		if (verbose) {
			dhcpmsg(LOG_INFO, "BOOTP client: %1$s is looking for "
			    "a configuration on net %2$s\n", pcd->cidbuf,
			    pnd->network);
		}
		goto leave_bootp;
	}

	/*
	 * If the client thinks it knows who it is (ciaddr), and this doesn't
	 * match our registered IP address, then display an error message and
	 * give up.
	 */
	if (ciaddr.s_addr != htonl(INADDR_ANY) && crecords == 0) {
		/*
		 * If the client specified an IP address, then let's check
		 * whether it is available, since we have no CID mapping
		 * registered for this client. If it is available and
		 * unassigned but owned by a different server, we ignore the
		 * client.
		 */
		DSVC_QINIT(query);

		DSVC_QEQ(query, DN_QCIP);
		dn.dn_cip.s_addr = ntohl(ciaddr.s_addr);
		(void) inet_ntop(AF_INET, &ciaddr, cipbuf, sizeof (cipbuf));

		DSVC_QEQ(query, DN_QFBOOTP_ONLY);
		dn.dn_flags = DN_FBOOTP_ONLY;

		dnip = NULL;
		dnlp = dhcp_lookup_dd_classify(pcd->pnd, B_FALSE, query,
		    -1, &dn, (void **)&dncp, S_CID);
		if (dnlp == NULL) {
			/*
			 * We have no record of this client's IP address, thus
			 * we really can't respond to this client, because it
			 * doesn't have a configuration.
			 */
			if (verbose) {
				dhcpmsg(LOG_INFO, "No configuration for BOOTP "
				    "client: %1$s. IP address: %2$s not "
				    "administered by this server.\n",
				    pcd->cidbuf, inet_ntop(AF_INET, &ciaddr,
				    ntoab, sizeof (ntoab)));
			}
			goto leave_bootp;
		} else
			irecords = 1;

		dnp = dnlp->dnl_rec;
		if (dnp->dn_flags & DN_FUNUSABLE)
			goto leave_bootp;

		if (dn.dn_cid_len != 0) {
			if (dn.dn_cid_len != pcd->cid_len || memcmp(dn.dn_cid,
			    pcd->cid, pcd->cid_len) != 0) {
				if (verbose) {
					clen = sizeof (cidbuf);
					(void) octet_to_hexascii(dn.dn_cid,
					    dn.dn_cid_len, cidbuf, &clen);
					dhcpmsg(LOG_INFO, "BOOTP client: %1$s "
					    "thinks it owns %2$s, but that "
					    "address belongs to %3$s. Ignoring "
					    "client.\n", pcd->cidbuf, cipbuf,
					    cidbuf);
				}
				goto leave_bootp;
			}
		} else {
			if (match_ownerip(htonl(dn.dn_sip.s_addr)) == NULL) {
				if (verbose) {
					no_ip.s_addr =
					    htonl(dnp->dn_sip.s_addr);
					dhcpmsg(LOG_INFO, "BOOTP client: %1$s "
					    "believes it owns %2$s. That "
					    "address is free, but is owned by "
					    "DHCP server %3$s. Ignoring "
					    "client.\n", pcd->cidbuf, cipbuf,
					    inet_ntop(AF_INET, &no_ip, ntoab,
					    sizeof (ntoab)));
				}
				goto leave_bootp;
			}
		}
		no_ip.s_addr = htonl(dnp->dn_cip.s_addr);
		(void) inet_ntop(AF_INET, &no_ip, cipbuf, sizeof (cipbuf));
	}

	if (crecords == 0) {
		/*
		 * The dhcp-network table did not have any matching entries.
		 * Try to allocate a new one if possible.
		 */
		if (irecords == 0 && select_offer(pnd, plp, pcd, &dnlp)) {
			dnp = dnlp->dnl_rec;
			no_ip.s_addr = htonl(dnp->dn_cip.s_addr);
			(void) inet_ntop(AF_INET, &no_ip, cipbuf,
			    sizeof (cipbuf));
			srecords = 1;
		}
	}

	if (crecords == 0 && irecords == 0 && srecords == 0) {
		dhcpmsg(LOG_NOTICE,
		    "(%1$s) No more BOOTP IP addresses for %2$s network.\n",
		    pcd->cidbuf, pnd->network);
		goto leave_bootp;
	}

	/* Check the address. But only if client doesn't know its address. */
	ndn = *dnp;	/* struct copy */
	no_ip.s_addr = htonl(ndn.dn_cip.s_addr);
	(void) inet_ntop(AF_INET, &no_ip, cipbuf, sizeof (cipbuf));
	if (ciaddr.s_addr == htonl(INADDR_ANY)) {
		if ((ifp->flags & IFF_NOARP) == 0)
			(void) set_arp(ifp, &no_ip, NULL, 0, DHCP_ARP_DEL);
		if (!noping) {
			/*
			 * If icmp echo check fails,
			 * let the plp fall by the wayside.
			 */
			errno = icmp_echo_check(&no_ip, &result);
			if (errno != 0) {
				dhcpmsg(LOG_ERR, "ICMP ECHO check cannot be "
				    "performed for: %s, ignoring\n", cipbuf);
				goto leave_bootp;
			}
			if (result) {
				dhcpmsg(LOG_ERR, "ICMP ECHO reply to BOOTP "
				    "OFFER candidate: %s, disabling.\n",
				    cipbuf);

				ndn.dn_flags |= DN_FUNUSABLE;

				if ((err = dhcp_modify_dd_entry(pnd->dh,
				    dnp, &ndn)) == DSVC_SUCCESS) {
					/* Keep the cached entry current. */
					*dnp = ndn;    /* struct copy */
				}

				logtrans(P_BOOTP, L_ICMP_ECHO, 0, no_ip,
				    server_ip, plp);

				goto leave_bootp;
			}
		}
	}

	/*
	 * It is possible that the client could specify a REQUEST list,
	 * but then it would be a DHCP client, wouldn't it? Only copy the
	 * std option list, since that potentially could be changed by
	 * load_options().
	 */
	ecp = NULL;
	if (!no_dhcptab) {
		open_macros();
		if ((nmp = get_macro(pnd->network)) != NULL)
			ecp = dup_encode_list(nmp->head);
		if ((mp = get_macro(dnp->dn_macro)) != NULL)
			ecp = combine_encodes(ecp, mp->head, ENC_DONT_COPY);
		if ((cmp = get_macro(pcd->cidbuf)) != NULL)
			ecp = combine_encodes(ecp, cmp->head, ENC_DONT_COPY);

		/* If dhcptab configured to return hostname, do so. */
		if (find_encode(ecp, DSYM_INTERNAL, CD_BOOL_HOSTNAME) !=
		    NULL) {
			hp = gethostbyaddr_r((char *)&ndn.dn_cip,
			    sizeof (struct in_addr), AF_INET, &h, hbuf,
			    sizeof (hbuf), &err);
			if (hp != NULL) {
				hecp = make_encode(DSYM_STANDARD,
				    CD_HOSTNAME, strlen(hp->h_name),
				    hp->h_name, ENC_COPY);
				replace_encode(&ecp, hecp, ENC_DONT_COPY);
			}
		}
	}

	/* Produce a BOOTP reply. */
	rep_pktp = gen_bootp_pkt(sizeof (PKT), plp->pkt);

	rep_pktp->op = BOOTREPLY;
	optp = rep_pktp->options;

	/*
	 * Set the client's "your" IP address if client doesn't know it,
	 * otherwise echo the client's ciaddr back to him.
	 */
	if (ciaddr.s_addr == htonl(INADDR_ANY))
		rep_pktp->yiaddr.s_addr = htonl(ndn.dn_cip.s_addr);
	else
		rep_pktp->ciaddr.s_addr = ciaddr.s_addr;

	/*
	 * Omit lease time options implicitly, e.g.
	 * ~(DHCP_DHCP_CLNT | DHCP_SEND_LEASE)
	 */

	if (!plp->rfc1048)
		flags |= DHCP_NON_RFC1048;

	/* Now load in configured options. */
	pkt_len = load_options(flags, plp, rep_pktp, sizeof (PKT), optp, ecp,
	    NULL);

	free_encode_list(ecp);
	if (!no_dhcptab)
		close_macros();

	if (pkt_len < sizeof (PKT))
		pkt_len = sizeof (PKT);

	/*
	 * Only perform a write if we have selected an entry not yet
	 * assigned to the client (a matching DN_FBOOTP_ONLY entry from
	 * ip address lookup, or an unassigned entry from select_offer()).
	 */
	if (srecords > 0 || irecords > 0) {
		(void) memcpy(&ndn.dn_cid, pcd->cid, pcd->cid_len);
		ndn.dn_cid_len = pcd->cid_len;

		write_error = dhcp_modify_dd_entry(pnd->dh, dnp, &ndn);

		/* Keep state of the cached entry current. */
		*dnp = ndn;	/* struct copy */

		log = L_ASSIGN;
	} else {
		if (verbose) {
			dhcpmsg(LOG_INFO, "Database write unnecessary for "
			    "BOOTP client: %1$s, %2$s\n",
			    pcd->cidbuf, cipbuf);
		}
		log = L_REPLY;
	}

	if (write_error == DSVC_SUCCESS) {
		if (send_reply(ifp, rep_pktp, pkt_len, &no_ip) != 0) {
			dhcpmsg(LOG_ERR,
			    "Reply to BOOTP client %1$s with %2$s failed.\n",
			    pcd->cidbuf, cipbuf);
		} else {
			/* Note that the conversation has completed. */
			pcd->state = ACK;

			(void) update_offer(pcd, &dnlp, 0, &no_ip, B_TRUE);
			existing_offer = B_TRUE;
		}

		logtrans(P_BOOTP, log, ndn.dn_lease, no_ip, server_ip, plp);
	}

leave_bootp:
	if (rep_pktp != NULL)
		free(rep_pktp);
	if (dncp != NULL)
		dhcp_free_dd_list(pnd->dh, dncp);
	if (dnip != NULL)
		dhcp_free_dd_list(pnd->dh, dnip);
	if (dnlp != NULL && !existing_offer)
		dhcp_free_dd_list(pnd->dh, dnlp);
}
