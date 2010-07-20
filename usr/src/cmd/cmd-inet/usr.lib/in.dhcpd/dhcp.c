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
#include <alloca.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/byteorder.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <syslog.h>
#include <sys/errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/dhcp.h>
#include <dhcp_symbol.h>
#include <nss_dbdefs.h>
#include <dlfcn.h>
#include "dhcpd.h"
#include "per_dnet.h"
#include "interfaces.h"
#include <locale.h>
#include <resolv.h>

static void dhcp_offer(dsvc_clnt_t *, PKT_LIST *);
static void dhcp_req_ack(dsvc_clnt_t *, PKT_LIST *);
static void dhcp_dec_rel(dsvc_clnt_t *, PKT_LIST *, int);
static void dhcp_inform(dsvc_clnt_t *, PKT_LIST *);
static PKT *gen_reply_pkt(dsvc_clnt_t *, PKT_LIST *, int, uint_t *,
    uchar_t **, struct in_addr *);
static void set_lease_option(ENCODE **, lease_t);
static int config_lease(PKT_LIST *, dn_rec_t *, ENCODE **, lease_t, boolean_t);
static int is_option_requested(PKT_LIST *, ushort_t);
static void add_request_list(IF *, PKT_LIST *, ENCODE **, struct in_addr *);
static char *disp_clnt_msg(PKT_LIST *, char *, int);
static void add_dnet_cache(dsvc_dnet_t *, dn_rec_list_t *);
static void purge_dnet_cache(dsvc_dnet_t *, dn_rec_t *);

static boolean_t addr_avail(dsvc_dnet_t *, dsvc_clnt_t *, dn_rec_list_t **,
    struct in_addr, boolean_t);
static boolean_t name_avail(char *, dsvc_clnt_t *, PKT_LIST *,
    dn_rec_list_t **, ENCODE *, struct in_addr **);
static boolean_t entry_available(dsvc_clnt_t *, dn_rec_t *);
static boolean_t do_nsupdate(struct in_addr, ENCODE *, PKT_LIST *);

extern int dns_puthostent(struct hostent *, time_t);

/*
 * Offer cache.
 *
 * The DHCP server maintains a cache of DHCP OFFERs it has extended to DHCP
 * clients. It does so because:
 *	a) Subsequent requests get the same answer, and the same IP address
 *	   isn't offered to a different client.
 *
 *	b) No ICMP validation is required the second time through, nor is a
 *	   database lookup required.
 *
 *	c) If the client accepts the OFFER and sends a REQUEST, we can simply
 *	   lookup the record by client IP address, the one field guaranteed to
 *	   be unique within the dhcp network table.
 *
 * We don't explicitly delete entries from the offer cache. We let them time
 * out on their own. This is done to ensure the server responds correctly when
 * many pending client requests are queued (duplicates). We don't want to ICMP
 * validate an IP address we just allocated.
 *
 * The offer cache (and any database records cached in select_offer()) will
 * diverge from the database for the length of the D_OFFER lifetime.
 * SIGHUP flushes the offer cache, allowing management tools to inform the
 * server of changes in a timely manner.
 */

/*
 * Dispatch the DHCP packet based on its type.
 */
void
dhcp(dsvc_clnt_t *pcd, PKT_LIST *plp)
{
	if (plp->opts[CD_DHCP_TYPE]->len != 1) {
		dhcpmsg(LOG_ERR,
		    "Garbled DHCP Message type option from client: %s\n",
		    pcd->cidbuf);
		return;
	}

	pcd->state = *plp->opts[CD_DHCP_TYPE]->value;
	switch (pcd->state) {
	case DISCOVER:
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processing OFFER...\n");
#endif	/* DEBUG */
		dhcp_offer(pcd, plp);
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processed OFFER.\n");
#endif	/* DEBUG */
		break;
	case REQUEST:
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processing REQUEST...\n");
#endif	/* DEBUG */
		dhcp_req_ack(pcd, plp);
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processed REQUEST.\n");
#endif	/* DEBUG */
		break;
	case DECLINE:
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processing DECLINE...\n");
#endif	/* DEBUG */
		dhcp_dec_rel(pcd, plp, DECLINE);
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processed DECLINE.\n");
#endif	/* DEBUG */
		break;
	case RELEASE:
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processing RELEASE...\n");
#endif	/* DEBUG */
		dhcp_dec_rel(pcd, plp, RELEASE);
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processed RELEASE.\n");
#endif	/* DEBUG */
		break;
	case INFORM:
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processing INFORM...\n");
#endif	/* DEBUG */
		dhcp_inform(pcd, plp);
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "dhcp() - processed INFORM.\n");
#endif	/* DEBUG */
		break;
	default:
		dhcpmsg(LOG_INFO,
		    "Unexpected DHCP message type: %d from client: %s.\n",
		    pcd->state, pcd->cidbuf);
		break;
	}
}

/*
 * Responding to a DISCOVER message. icmp echo check (if done) is synchronous.
 * Previously known requests are in the OFFER cache.
 */
static void
dhcp_offer(dsvc_clnt_t *pcd, PKT_LIST *plp)
{
	IF		*ifp = pcd->ifp;
	boolean_t	result;
	struct in_addr	nsip, ncip;
	dsvc_dnet_t	*pnd = pcd->pnd;
	uint_t		replen;
	int		used_pkt_len;
	PKT 		*rep_pktp = NULL;
	uchar_t		*optp;
	ENCODE		*ecp, *vecp, *macro_ecp, *macro_vecp,
	    *class_ecp, *class_vecp,
	    *cid_ecp, *cid_vecp,
	    *net_ecp, *net_vecp;
	MACRO		*net_mp, *pkt_mp, *class_mp, *cid_mp;
	char		*class_id;
	time_t		now = time(NULL);
	lease_t		newlease, oldlease = 0;
	int		err = 0;
	boolean_t	existing_allocation = B_FALSE;
	boolean_t	existing_offer = B_FALSE;
	char		sipstr[INET_ADDRSTRLEN], cipstr[INET_ADDRSTRLEN];
	char		class_idbuf[DSYM_CLASS_SIZE];
	dn_rec_t	*dnp, dn, ndn;
	uint32_t	query;
	dn_rec_list_t	*dncp = NULL, *dnlp = NULL;
	boolean_t	unreserve = B_FALSE;

	class_id = get_class_id(plp, class_idbuf, sizeof (class_idbuf));

	/*
	 * Purge offers when expired or the database has been re-read.
	 *
	 * Multi-threading: to better distribute garbage collection
	 * and data structure aging tasks, each thread must actively
	 * implement policy, rather then specialized, non-scalable
	 * threads which halt the server and update all data
	 * structures.
	 *
	 * The test below checks whether the offer has expired,
	 * due to aging, or re-reading of the dhcptab, via timeout
	 * or explicit signal.
	 */
	if (pcd->off_ip.s_addr != htonl(INADDR_ANY) &&
	    PCD_OFFER_TIMEOUT(pcd, now))
		purge_offer(pcd, B_TRUE, B_TRUE);

	if (pcd->off_ip.s_addr != htonl(INADDR_ANY)) {
		/*
		 * We've already validated this IP address in the past, and
		 * due to the OFFER hash table, we would not have offered this
		 * IP address to another client, so use the offer-cached record.
		 */
		existing_offer = B_TRUE;
		dnlp = pcd->dnlp;
		dnp = dnlp->dnl_rec;
		ncip.s_addr = htonl(dnp->dn_cip.s_addr);
	} else {
		/* Try to find an existing usable entry for the client. */
		DSVC_QINIT(query);
		DSVC_QEQ(query, DN_QCID);
		(void) memcpy(dn.dn_cid, pcd->cid, pcd->cid_len);
		dn.dn_cid_len = pcd->cid_len;

		/* No bootp records, thank you. */
		DSVC_QNEQ(query, DN_QFBOOTP_ONLY);
		dn.dn_flags = DN_FBOOTP_ONLY;

		/*
		 * We don't limit this search by SIP, because this client
		 * may be owned by another server, and we need to detect this
		 * since that record may be MANUAL.
		 */
		dncp = NULL;
		dnlp = dhcp_lookup_dd_classify(pcd->pnd, B_FALSE, query,
		    -1, &dn, (void **)&dncp, S_CID);

		while (dnlp != NULL) {

			dnp = dnlp->dnl_rec;
			if (match_ownerip(htonl(dnp->dn_sip.s_addr)) == NULL) {
				/*
				 * An IP address, but not ours! It's up to the
				 * primary to respond to DISCOVERs on this
				 * address.
				 */
				if (verbose) {
					char	*m1, *m2;

					if (dnp->dn_flags & DN_FMANUAL) {
						m1 = "MANUAL";
						m2 = " No other IP address "
						    "will be allocated.";
					} else {
						m1 = "DYNAMIC";
						m2 = "";
					}

					nsip.s_addr = htonl(dnp->dn_sip.s_addr);
					(void) inet_ntop(AF_INET, &nsip, sipstr,
					    sizeof (sipstr));
					ncip.s_addr = htonl(dnp->dn_cip.s_addr);
					(void) inet_ntop(AF_INET, &ncip, cipstr,
					    sizeof (cipstr));
					dhcpmsg(LOG_INFO, "Client: %1$s has "
					    "%2$s %3$s owned by server: "
					    "%4$s.%5$s\n", pcd->cidbuf,
					    m1, cipstr, sipstr, m2);
				}

				/* We give up if that IP address is manual */
				if (dnp->dn_flags & DN_FMANUAL)
					goto leave_offer;
			} else {
				uint_t bits = DN_FUNUSABLE | DN_FMANUAL;
				if ((dnp->dn_flags & bits) == bits) {
					ncip.s_addr = htonl(dnp->dn_cip.s_addr);
					(void) inet_ntop(AF_INET, &ncip, cipstr,
					    sizeof (cipstr));
					dhcpmsg(LOG_WARNING, "Client: %1$s "
					    "MANUAL record %2$s is UNUSABLE. "
					    "No other IP address will be "
					    "allocated.\n", pcd->cidbuf,
					    cipstr);
					goto leave_offer;
				} else
					break;	/* success */
			}

			free_dnrec_list(dnlp);
			dnlp = detach_dnrec_from_list(NULL, dncp, &dncp);
		}

		if (dnlp == NULL) {
			/*
			 * select_offer() ONLY selects IP addresses owned
			 * by us. Only log a notice if we own any IP addresses
			 * at all. Otherwise, this is an informational server.
			 */
			if (!select_offer(pnd, plp, pcd, &dnlp)) {
				if (pnd->naddrs > 0) {
					dhcpmsg(LOG_NOTICE,
					    "No more IP addresses on %1$s "
					    "network (%2$s)\n", pnd->network,
					    pcd->cidbuf);
				}
				goto leave_offer;
			}
			dnp = dnlp->dnl_rec;
		} else
			existing_allocation = B_TRUE;

		ncip.s_addr = htonl(dnp->dn_cip.s_addr);
		(void) inet_ntop(AF_INET, &ncip, cipstr, sizeof (cipstr));

		/*
		 * ICMP echo validate the address.
		 */
		if (!noping) {
			/*
			 * If icmp echo validation fails, let the plp fall by
			 * the wayside.
			 */
			if (icmp_echo_check(&ncip, &result) != 0) {
				dhcpmsg(LOG_ERR, "ICMP ECHO check cannot be "
				    "registered for: %s, ignoring\n", cipstr);
				unreserve = B_TRUE;
				goto leave_offer;
			}
			if (result) {
				dhcpmsg(LOG_WARNING,
				    "ICMP ECHO reply to OFFER candidate: "
				    "%s, disabling.\n", cipstr);

				ndn = *dnp;	/* struct copy */
				ndn.dn_flags |= DN_FUNUSABLE;

				if ((err = dhcp_modify_dd_entry(pnd->dh, dnp,
				    &ndn)) != DSVC_SUCCESS) {
					dhcpmsg(LOG_ERR,
					    "ICMP ECHO reply to OFFER "
					    "candidate: %1$s. No "
					    "modifiable dhcp network "
					    "record. (%2$s)\n", cipstr,
					    dhcpsvc_errmsg(err));
				} else {
					/* Keep the cached entry current. */
					*dnp = ndn;    /* struct copy */
				}

				logtrans(P_DHCP, L_ICMP_ECHO, 0, ncip,
				    server_ip, plp);

				unreserve = B_TRUE;

				goto leave_offer;
			}
		}
	}

	/*
	 * At this point, we've ICMP validated (if requested) the IP
	 * address, and can go about producing an OFFER for the client.
	 */

	ecp = vecp = NULL;
	net_vecp = net_ecp = NULL;
	macro_vecp = macro_ecp = NULL;
	class_vecp = class_ecp = NULL;
	cid_vecp = cid_ecp = NULL;
	if (!no_dhcptab) {
		open_macros();

		/*
		 * Macros are evaluated this way: First apply parameters from
		 * a client class macro (if present), then apply those from the
		 * network macro (if present), then apply those from the
		 * dhcp network macro (if present), and finally apply those
		 * from a client id macro (if present).
		 */

		/*
		 * First get a handle on network, dhcp network table macro,
		 * and client id macro values.
		 */
		if ((net_mp = get_macro(pnd->network)) != NULL)
			net_ecp = net_mp->head;
		if ((pkt_mp = get_macro(dnp->dn_macro)) != NULL)
			macro_ecp = pkt_mp->head;
		if ((cid_mp = get_macro(pcd->cidbuf)) != NULL)
			cid_ecp = cid_mp->head;

		if (class_id != NULL) {
			/* Get a handle on the class id macro (if it exists). */
			if ((class_mp = get_macro(class_id)) != NULL) {
				/*
				 * Locate the ENCODE list for encapsulated
				 * options associated with our class id within
				 * the class id macro.
				 */
				class_vecp = vendor_encodes(class_mp, class_id);
				class_ecp = class_mp->head;
			}

			/*
			 * Locate the ENCODE list for encapsulated options
			 * associated with our class id within the network,
			 * dhcp network, and client macros.
			 */
			if (net_mp != NULL)
				net_vecp = vendor_encodes(net_mp, class_id);
			if (pkt_mp != NULL)
				macro_vecp = vendor_encodes(pkt_mp, class_id);
			if (cid_mp != NULL)
				cid_vecp = vendor_encodes(cid_mp, class_id);

			/*
			 * Combine the encapsulated option encode lists
			 * associated with our class id in the order defined
			 * above (class, net, dhcp network, client id)
			 */
			vecp = combine_encodes(class_vecp, net_vecp, ENC_COPY);
			vecp = combine_encodes(vecp, macro_vecp, ENC_DONT_COPY);
			vecp = combine_encodes(vecp, cid_vecp, ENC_DONT_COPY);
		}

		/*
		 * Combine standard option encode lists in the order defined
		 * above (class, net, dhcp network, and client id).
		 */
		if (class_ecp != NULL)
			ecp = combine_encodes(class_ecp, net_ecp, ENC_COPY);
		else
			ecp = dup_encode_list(net_ecp);

		ecp = combine_encodes(ecp, macro_ecp, ENC_DONT_COPY);
		ecp = combine_encodes(ecp, cid_ecp, ENC_DONT_COPY);

		/* If dhcptab configured to return hostname, do so. */
		if (find_encode(ecp, DSYM_INTERNAL, CD_BOOL_HOSTNAME) != NULL) {
			struct		hostent	h, *hp;
			char		hbuf[NSS_BUFLEN_HOSTS];
			ENCODE		*hecp;
			hp = gethostbyaddr_r((char *)&ncip, sizeof (ncip),
			    AF_INET, &h, hbuf, sizeof (hbuf), &err);
			if (hp != NULL) {
				hecp = make_encode(DSYM_STANDARD,
				    CD_HOSTNAME, strlen(hp->h_name),
				    hp->h_name, ENC_COPY);
				replace_encode(&ecp, hecp, ENC_DONT_COPY);
			}
		}

		/* If dhcptab configured to echo client class, do so. */
		if (plp->opts[CD_CLASS_ID] != NULL &&
		    find_encode(ecp, DSYM_INTERNAL, CD_BOOL_ECHO_VCLASS) !=
		    NULL) {
			ENCODE		*echo_ecp;
			DHCP_OPT	*op = plp->opts[CD_CLASS_ID];
			echo_ecp = make_encode(DSYM_STANDARD, CD_CLASS_ID,
			    op->len, op->value, ENC_COPY);
			replace_encode(&ecp, echo_ecp, ENC_DONT_COPY);
		}
	}

	if ((ifp->flags & IFF_NOARP) == 0)
		(void) set_arp(ifp, &ncip, NULL, 0, DHCP_ARP_DEL);

	/*
	 * For OFFERs, we don't check the client's lease nor LeaseNeg,
	 * regardless of whether the client has an existing allocation
	 * or not. Lease expiration (w/o LeaseNeg) only occur during
	 * RENEW/REBIND or INIT-REBOOT client states, not SELECTing state.
	 */
	if (existing_allocation) {
		if (dnp->dn_lease == DHCP_PERM ||
		    (dnp->dn_flags & DN_FAUTOMATIC)) {
			oldlease = DHCP_PERM;
		} else {
			if ((lease_t)dnp->dn_lease < (lease_t)now)
				oldlease = (lease_t)0;
			else {
				oldlease = (lease_t)dnp->dn_lease -
				    (lease_t)now;
			}
		}
	}

	/* First get a generic reply packet. */
	rep_pktp = gen_reply_pkt(pcd, plp, OFFER, &replen, &optp, &ifp->addr);

	/* Set the client's IP address */
	rep_pktp->yiaddr.s_addr = htonl(dnp->dn_cip.s_addr);

	/* Calculate lease time. */
	newlease = config_lease(plp, dnp, &ecp, oldlease, B_TRUE);

	/*
	 * Client is requesting specific options. let's try and ensure it
	 * gets what it wants, if at all possible.
	 */
	if (plp->opts[CD_REQUEST_LIST] != NULL)
		add_request_list(ifp, plp, &ecp, &ncip);

	/* Now load all the asked for / configured options */
	used_pkt_len = load_options(DHCP_DHCP_CLNT | DHCP_SEND_LEASE, plp,
	    rep_pktp, replen, optp, ecp, vecp);

	free_encode_list(ecp);
	free_encode_list(vecp);
	if (!no_dhcptab)
		close_macros();

	if (used_pkt_len < sizeof (PKT))
		used_pkt_len = sizeof (PKT);

	if (send_reply(ifp, rep_pktp, used_pkt_len, &ncip) == 0) {
		if (newlease == DHCP_PERM)
			newlease = htonl(newlease);
		else
			newlease = htonl(now + newlease);
		(void) update_offer(pcd, &dnlp, newlease, NULL, B_TRUE);
		existing_offer = B_TRUE;
	} else {
		unreserve = B_TRUE;
	}

leave_offer:
	if (unreserve)
		purge_offer(pcd, B_FALSE, B_TRUE);
	if (rep_pktp != NULL)
		free(rep_pktp);
	if (dncp != NULL)
		dhcp_free_dd_list(pnd->dh, dncp);
	if (dnlp != NULL && !existing_offer)
		dhcp_free_dd_list(pnd->dh, dnlp);
}

/*
 * Responding to REQUEST message.
 *
 * Very similar to dhcp_offer(), except that we need to be more
 * discriminating.
 *
 * The ciaddr field is TRUSTED. A INIT-REBOOTing client will place its
 * notion of its IP address in the requested IP address option. INIT
 * clients will place the value in the OFFERs yiaddr in the requested
 * IP address option. INIT-REBOOT packets are differentiated from INIT
 * packets in that the server id option is missing. ciaddr will only
 * appear from clients in the RENEW/REBIND states.
 *
 * Error messages may be generated. Database write failures are no longer
 * fatal, since we'll only respond to the client if the write succeeds.
 */
static void
dhcp_req_ack(dsvc_clnt_t *pcd, PKT_LIST *plp)
{
	dn_rec_t	dn, ndn, *dnp;
	struct in_addr	serverid, ciaddr, claddr, nreqaddr, cipaddr,
	    ncipaddr, sipaddr;
	struct in_addr	dest_in;
	dsvc_dnet_t	*pnd = pcd->pnd;
	uint_t		replen;
	int		actual_len;
	int		pkt_type = ACK;
	DHCP_MSG_CATEGORIES	log;
	PKT 		*rep_pktp = NULL;
	uchar_t		*optp;
	ENCODE		*ecp, *vecp,
	    *class_ecp, *class_vecp,
	    *net_ecp, *net_vecp,
	    *macro_ecp, *macro_vecp,
	    *cid_ecp, *cid_vecp;
	MACRO		*class_mp, *pkt_mp, *net_mp, *cid_mp;
	char		*class_id;
	char		nak_mesg[DHCP_SCRATCH];
	time_t		now;
	lease_t		newlease, oldlease;
	boolean_t	negot;
	int		err = 0;
	int		write_error = DSVC_SUCCESS, clnt_state;
	ushort_t	boot_secs;
	char		ntoaa[INET_ADDRSTRLEN], ntoab[INET_ADDRSTRLEN],
	    ntoac[INET_ADDRSTRLEN];
	char		class_idbuf[DSYM_CLASS_SIZE];
	boolean_t	hostname_update = B_FALSE;
	dn_rec_list_t	*nlp, *dncp = NULL, *dnlp = NULL;
	uint32_t	query;
	IF		*ifp = pcd->ifp;
	boolean_t	existing_offer = B_FALSE;

	ciaddr.s_addr = plp->pkt->ciaddr.s_addr;
	boot_secs = ntohs(plp->pkt->secs);
	now = time(NULL);

	class_id = get_class_id(plp, class_idbuf, sizeof (class_idbuf));

	/* Determine type of REQUEST we've got. */
	if (plp->opts[CD_SERVER_ID] != NULL) {
		if (plp->opts[CD_SERVER_ID]->len != sizeof (struct in_addr)) {
			dhcpmsg(LOG_ERR, "Garbled DHCP Server ID option from "
			    "client: '%1$s'. Len is %2$d, when it should be "
			    "%3$d \n", pcd->cidbuf,
			    plp->opts[CD_SERVER_ID]->len,
			    sizeof (struct in_addr));
			goto leave_ack;
		}

		/*
		 * Request in response to an OFFER. ciaddr must not
		 * be set. Requested IP address option will hold address
		 * we offered the client.
		 */
		clnt_state = INIT_STATE;
		(void) memcpy((void *)&serverid,
		    plp->opts[CD_SERVER_ID]->value, sizeof (struct in_addr));

		if (plp->opts[CD_REQUESTED_IP_ADDR] == NULL) {
			if (verbose) {
				dhcpmsg(LOG_NOTICE, "%1$s: REQUEST on %2$s is "
				    "missing requested IP option.\n",
				    pcd->cidbuf, pcd->pnd->network);
			}
			goto leave_ack;
		}
		if (plp->opts[CD_REQUESTED_IP_ADDR]->len !=
		    sizeof (struct in_addr)) {
			dhcpmsg(LOG_ERR, "Garbled Requested IP option from "
			    "client: '%1$s'. Len is %2$d, when it should be "
			    "%3$d \n",
			    pcd->cidbuf, plp->opts[CD_REQUESTED_IP_ADDR]->len,
			    sizeof (struct in_addr));
			goto leave_ack;
		}
		(void) memcpy((void *)&nreqaddr,
		    plp->opts[CD_REQUESTED_IP_ADDR]->value,
		    sizeof (struct in_addr));

		if (serverid.s_addr != ifp->addr.s_addr) {
			/*
			 * Another server address was selected.
			 *
			 * If the server address is handled by another
			 * thread of our process, do nothing in the
			 * hope that the other thread will eventually
			 * receive a REQUEST with its server address.
			 *
			 * If a server address was selected which is
			 * not handled by this process, see if we made
			 * an offer, and clear it if we did. If offer
			 * expired before client responded, then no
			 * need to do anything.
			 */
			if (is_our_address(serverid.s_addr)) {
				if (verbose) {
					dhcpmsg(LOG_INFO,
					    "Client: %1$s chose %2$s from "
					    "server: %3$s, which is being "
					    "handled by another thread\n",
					    pcd->cidbuf,
					    inet_ntop(AF_INET, &nreqaddr, ntoaa,
					    sizeof (ntoaa)),
					    inet_ntop(AF_INET, &serverid, ntoab,
					    sizeof (ntoab)));
				}
			} else {
				purge_offer(pcd, B_FALSE, B_TRUE);
				if (verbose) {
					dhcpmsg(LOG_INFO,
					    "Client: %1$s chose %2$s from "
					    "server: %3$s, not %4$s\n",
					    pcd->cidbuf,
					    inet_ntop(AF_INET, &nreqaddr, ntoaa,
					    sizeof (ntoaa)),
					    inet_ntop(AF_INET, &serverid, ntoab,
					    sizeof (ntoab)),
					    inet_ntop(AF_INET, &ifp->addr,
					    ntoac, sizeof (ntoac)));
				}
			}
			goto leave_ack;
		}

		/*
		 * See comment at the top of the file for description of
		 * OFFER cache.
		 *
		 * If the offer expires before the client got around to
		 * requesting, and we can't confirm the address is still free,
		 * we'll silently ignore the client, until it drops back and
		 * tries to discover again. We will print a message in
		 * verbose mode however. If the Offer hasn't timed out, we
		 * bump it up again in case we have a bounce of queued up
		 * INIT requests to respond to.
		 */
		if (pcd->off_ip.s_addr == htonl(INADDR_ANY) ||
		    PCD_OFFER_TIMEOUT(pcd, now)) {
			/*
			 * Hopefully, the timeout value is fairly long to
			 * prevent this.
			 */
			purge_offer(pcd, B_TRUE, B_TRUE);
			if (verbose) {
				dhcpmsg(LOG_INFO,
				    "Offer on %1$s expired for client: %2$s\n",
				    pcd->pnd->network, pcd->cidbuf);
			}
			goto leave_ack;
		} else
			(void) update_offer(pcd, NULL, 0, NULL, B_TRUE);

		/*
		 * The client selected us. Create a ACK, and send
		 * it off to the client, commit to permanent
		 * storage the new binding.
		 */
		existing_offer = B_TRUE;
		dnlp = pcd->dnlp;
		dnp = dnlp->dnl_rec;
		ndn = *dnp;	/* struct copy */
		ndn.dn_lease = pcd->lease;
		ncipaddr.s_addr = htonl(dnp->dn_cip.s_addr);

		/*
		 * If client thinks we offered it a different address, then
		 * ignore it.
		 */
		if (memcmp((char *)&ncipaddr,
		    plp->opts[CD_REQUESTED_IP_ADDR]->value,
		    sizeof (struct in_addr)) != 0) {
			if (verbose) {
				dhcpmsg(LOG_INFO, "Client %1$s believes "
				    "offered IP address %2$s is different than "
				    "what was offered.\n", pcd->cidbuf,
				    inet_ntop(AF_INET, &ncipaddr, ntoab,
				    sizeof (ntoab)));
			}
			goto leave_ack;
		}

		/*
		 * Clear out any temporary ARP table entry we may have
		 * created during the offer.
		 */
		if ((ifp->flags & IFF_NOARP) == 0)
			(void) set_arp(ifp, &ncipaddr, NULL, 0, DHCP_ARP_DEL);
	} else {
		/*
		 * Either a client in the INIT-REBOOT state, or one in
		 * either RENEW or REBIND states. The latter will have
		 * ciaddr set, whereas the former will place its concept
		 * of its IP address in the requested IP address option.
		 */
		if (ciaddr.s_addr == htonl(INADDR_ANY)) {
			clnt_state = INIT_REBOOT_STATE;
			/*
			 * Client isn't sure of its IP address. It's
			 * attempting to verify its address, thus requested
			 * IP option better be present, and correct.
			 */
			if (plp->opts[CD_REQUESTED_IP_ADDR] == NULL) {
				dhcpmsg(LOG_ERR,
				    "Client: %s REQUEST is missing "
				    "requested IP option.\n", pcd->cidbuf);
				goto leave_ack;
			}
			if (plp->opts[CD_REQUESTED_IP_ADDR]->len !=
			    sizeof (struct in_addr)) {
				dhcpmsg(LOG_ERR, "Garbled Requested IP option "
				    "from client: '%1$s'. Len is %2$d, when it "
				    "should be %3$d \n", pcd->cidbuf,
				    plp->opts[CD_REQUESTED_IP_ADDR]->len,
				    sizeof (struct in_addr));
				goto leave_ack;
			}
			(void) memcpy(&claddr,
			    plp->opts[CD_REQUESTED_IP_ADDR]->value,
			    sizeof (struct in_addr));

			DSVC_QINIT(query);
			DSVC_QEQ(query, DN_QCID);
			(void) memcpy(dn.dn_cid, pcd->cid, pcd->cid_len);
			dn.dn_cid_len = pcd->cid_len;

			/* No bootp records, thank you. */
			DSVC_QNEQ(query, DN_QFBOOTP_ONLY);
			dn.dn_flags = DN_FBOOTP_ONLY;

		} else {
			clnt_state = RENEW_REBIND_STATE;
			/*
			 * Client knows its IP address. It is trying to
			 * RENEW/REBIND (extend its lease). We trust ciaddr,
			 * and use it to locate the client's record. If we
			 * can't find the client's record, then we keep
			 * silent. If the client id of the record doesn't
			 * match this client, then the database is
			 * inconsistent, and we'll ignore it.
			 */
			DSVC_QINIT(query);
			DSVC_QEQ(query, DN_QCID|DN_QCIP);
			(void) memcpy(dn.dn_cid, pcd->cid, pcd->cid_len);
			dn.dn_cid_len = pcd->cid_len;
			dn.dn_cip.s_addr = ntohl(ciaddr.s_addr);

			/* No bootp records, thank you. */
			DSVC_QNEQ(query, DN_QFBOOTP_ONLY);
			dn.dn_flags = DN_FBOOTP_ONLY;

			claddr.s_addr = ciaddr.s_addr;
		}

		dncp = NULL;
		dnlp = dhcp_lookup_dd_classify(pcd->pnd, B_FALSE, query,
		    -1, &dn, (void **)&dncp, S_CID);

		if (dnlp != NULL) {
			dnp = dnlp->dnl_rec;
			if (dnp->dn_flags & DN_FUNUSABLE)
				goto leave_ack;

			sipaddr.s_addr = htonl(dnp->dn_sip.s_addr);
			cipaddr.s_addr = htonl(dnp->dn_cip.s_addr);

			/*
			 * If this address is not owned by this server and
			 * the client is trying to verify the address, then
			 * ignore the client. If the client is simply trying
			 * to rebind, then don't respond until after
			 * renog_secs passes, to give the server that *OWNS*
			 * the address time to respond first.
			 */
			if (match_ownerip(sipaddr.s_addr) == NULL) {
				if (clnt_state == INIT_REBOOT_STATE) {
					if (verbose) {
						dhcpmsg(LOG_NOTICE, "Client: "
						    "%1$s is requesting "
						    "verification of %2$s "
						    "owned by %3$s\n",
						    pcd->cidbuf,
						    inet_ntop(AF_INET, &cipaddr,
						    ntoab, sizeof (ntoab)),
						    inet_ntop(AF_INET, &sipaddr,
						    ntoac, sizeof (ntoac)));
					}
					goto leave_ack;
				} else {
					/* RENEW/REBIND - wait for primary */
					if (boot_secs < (ushort_t)renog_secs)
						goto leave_ack;
				}

			}
			if (claddr.s_addr != htonl(dnp->dn_cip.s_addr)) {
				/*
				 * Client has the wrong IP address. Nak.
				 */
				(void) snprintf(nak_mesg, sizeof (nak_mesg),
				    "Incorrect IP address.");
				pkt_type = NAK;
			} else {
				if (!(dnp->dn_flags & DN_FAUTOMATIC) &&
				    (lease_t)dnp->dn_lease < (lease_t)now) {
					(void) snprintf(nak_mesg,
					    sizeof (nak_mesg),
					    "Lease has expired.");
					pkt_type = NAK;
				}
			}
		} else {
			if (clnt_state == RENEW_REBIND_STATE) {
				dhcpmsg(LOG_ERR, "Client: %1$s is trying to "
				    "renew %2$s, an IP address it has not "
				    "leased.\n", pcd->cidbuf, inet_ntop(AF_INET,
				    &ciaddr, ntoab, sizeof (ntoab)));
				goto leave_ack;
			}
			/*
			 * There is no such client registered for this
			 * address. Check if their address is on the correct
			 * net. If it is, then we'll assume that some other,
			 * non-database sharing DHCP server knows about this
			 * client. If the client is on the wrong net, NAK'em.
			 */
			if ((claddr.s_addr & pnd->subnet.s_addr) ==
			    pnd->net.s_addr) {
				/* Right net, but no record of client. */
				if (verbose) {
					dhcpmsg(LOG_INFO,
					    "Client: %1$s is trying to verify "
					    "unrecorded address: %2$s, "
					    "ignored.\n", pcd->cidbuf,
					    inet_ntop(AF_INET, &claddr,
					    ntoab, sizeof (ntoab)));
				}
				goto leave_ack;
			} else {
				if (ciaddr.s_addr == 0L) {
					(void) snprintf(nak_mesg,
					    sizeof (nak_mesg),
					    "No valid configuration exists on "
					    "network: %s", pnd->network);
					pkt_type = NAK;
				} else {
					if (verbose) {
						dhcpmsg(LOG_INFO,
						    "Client: %1$s is not "
						    "recorded as having "
						    "address: %2$s\n",
						    pcd->cidbuf,
						    inet_ntop(AF_INET, &ciaddr,
						    ntoab, sizeof (ntoab)));
					}
					goto leave_ack;
				}
			}
		}
	}

	/*
	 * Produce the appropriate response.
	 */
	if (pkt_type == NAK) {
		rep_pktp = gen_reply_pkt(pcd, plp, NAK, &replen, &optp,
		    &ifp->addr);
		/*
		 * Setting yiaddr to the client's ciaddr abuses the
		 * semantics of yiaddr, So we set this to 0L.
		 *
		 * We twiddle the broadcast flag to force the
		 * server/relay agents to broadcast the NAK.
		 *
		 * Exception: If a client's lease has expired, and it
		 * is still trying to renegotiate its lease, AND ciaddr
		 * is set, AND ciaddr is on a "remote" net, unicast the
		 * NAK. Gross, huh? But SPA could make this happen with
		 * super short leases.
		 */
		rep_pktp->yiaddr.s_addr = 0L;
		if (ciaddr.s_addr != 0L &&
		    (ciaddr.s_addr & pnd->subnet.s_addr) != pnd->net.s_addr) {
			dest_in.s_addr = ciaddr.s_addr;
		} else {
			rep_pktp->flags |= htons(BCAST_MASK);
			dest_in.s_addr = INADDR_BROADCAST;
		}

		*optp++ = CD_MESSAGE;
		*optp++ = (uchar_t)strlen(nak_mesg);
		(void) memcpy(optp, nak_mesg, strlen(nak_mesg));
		optp += strlen(nak_mesg);
		*optp = CD_END;
		actual_len = BASE_PKT_SIZE + (uint_t)(optp - rep_pktp->options);
		if (actual_len < sizeof (PKT))
			actual_len = sizeof (PKT);

		(void) send_reply(ifp, rep_pktp, actual_len, &dest_in);

		logtrans(P_DHCP, L_NAK, 0, dest_in, server_ip, plp);
	} else {
		rep_pktp = gen_reply_pkt(pcd, plp, ACK, &replen, &optp,
		    &ifp->addr);

		/* Set the client's IP address */
		rep_pktp->yiaddr.s_addr = htonl(dnp->dn_cip.s_addr);
		dest_in.s_addr = htonl(dnp->dn_cip.s_addr);

		/*
		 * Macros are evaluated this way: First apply parameters
		 * from a client class macro (if present), then apply
		 * those from the network macro (if present), then apply
		 * those from the server macro (if present), and finally
		 * apply those from a client id macro (if present).
		 */
		ecp = vecp = NULL;
		class_vecp = class_ecp = NULL;
		net_vecp = net_ecp = NULL;
		macro_vecp = macro_ecp = NULL;
		cid_vecp = cid_ecp = NULL;

		if (!no_dhcptab) {
			open_macros();
			if ((net_mp = get_macro(pnd->network)) != NULL)
				net_ecp = net_mp->head;
			if ((pkt_mp = get_macro(dnp->dn_macro)) != NULL)
				macro_ecp = pkt_mp->head;
			if ((cid_mp = get_macro(pcd->cidbuf)) != NULL)
				cid_ecp = cid_mp->head;
			if (class_id != NULL) {
				if ((class_mp = get_macro(class_id)) != NULL) {
					class_vecp = vendor_encodes(class_mp,
					    class_id);
					class_ecp = class_mp->head;
				}
				if (net_mp != NULL) {
					net_vecp = vendor_encodes(net_mp,
					    class_id);
				}
				if (pkt_mp != NULL)
					macro_vecp = vendor_encodes(pkt_mp,
					    class_id);
				if (cid_mp != NULL) {
					cid_vecp = vendor_encodes(cid_mp,
					    class_id);
				}
				vecp = combine_encodes(class_vecp, net_vecp,
				    ENC_COPY);
				vecp = combine_encodes(vecp, macro_vecp,
				    ENC_DONT_COPY);
				vecp = combine_encodes(vecp, cid_vecp,
				    ENC_DONT_COPY);
			}
			if (class_ecp != NULL) {
				ecp = combine_encodes(class_ecp, net_ecp,
				    ENC_COPY);
			} else
				ecp = dup_encode_list(net_ecp);

			ecp = combine_encodes(ecp, macro_ecp, ENC_DONT_COPY);
			ecp = combine_encodes(ecp, cid_ecp, ENC_DONT_COPY);

			ncipaddr.s_addr = htonl(dnp->dn_cip.s_addr);
			/*
			 * If the server is configured to do host name updates
			 * and the REQUEST packet contains a hostname request,
			 * see whether we can honor it.
			 *
			 * First, determine (via name_avail()) whether the host
			 * name is unassigned or belongs to an unleased IP
			 * address under our control.  If not, we won't do a
			 * host name update on behalf of the client.
			 *
			 * Second, if we own the IP address and it is in the
			 * correct network table, see whether an update is
			 * necessary (or, in the lucky case, whether the name
			 * requested already belongs to that address), in which
			 * case we need do nothing more than return the option.
			 */
			if ((nsutimeout_secs != DHCP_NO_NSU) &&
			    (plp->opts[CD_HOSTNAME] != NULL)) {
				char		hname[MAXHOSTNAMELEN + 1];
				int		hlen;
				struct in_addr	ia, *iap = &ia;

				/* turn hostname option into a string */
				hlen = plp->opts[CD_HOSTNAME]->len;
				hlen = MIN(hlen, MAXHOSTNAMELEN);
				(void) memcpy(hname,
				    plp->opts[CD_HOSTNAME]->value, hlen);
				hname[hlen] = '\0';

				nlp = NULL;
				if (name_avail(hname, pcd, plp, &nlp, ecp,
				    &iap)) {
					ENCODE	*hecp;

					/*
					 * If we pass this test, it means either
					 * no address is currently associated
					 * with the requested host name (iap is
					 * NULL) or the address doesn't match
					 * the one to be leased;  in either case
					 * an update attempt is needed.
					 *
					 * Otherwise (in the else case), we need
					 * only send the response - the name and
					 * address already match.
					 */
					if ((iap == NULL) || (iap->s_addr !=
					    dnp->dn_cip.s_addr)) {
						if (do_nsupdate(dnp->dn_cip,
						    ecp, plp)) {
							hecp = make_encode(
							    DSYM_STANDARD,
							    CD_HOSTNAME,
							    strlen(hname),
							    hname,
							    ENC_COPY);
							replace_encode(&ecp,
							    hecp,
							    ENC_DONT_COPY);
							hostname_update =
							    B_TRUE;
						}
					} else {
						hecp = make_encode(
						    DSYM_STANDARD,
						    CD_HOSTNAME,
						    strlen(hname), hname,
						    ENC_COPY);
						replace_encode(&ecp, hecp,
						    ENC_DONT_COPY);
						hostname_update = B_TRUE;
					}
					if (nlp != NULL)
						dhcp_free_dd_list(pnd->dh, nlp);
				}
			}

			/*
			 * If dhcptab configured to return hostname, do so.
			 */
			if ((hostname_update == B_FALSE) &&
			    (find_encode(ecp, DSYM_INTERNAL,
			    CD_BOOL_HOSTNAME) != NULL)) {
				struct		hostent	h, *hp;
				ENCODE		*hecp;
				char		hbuf[NSS_BUFLEN_HOSTS];
				hp = gethostbyaddr_r((char *)&ncipaddr,
				    sizeof (struct in_addr), AF_INET, &h, hbuf,
				    sizeof (hbuf), &err);
				if (hp != NULL) {
					hecp = make_encode(DSYM_STANDARD,
					    CD_HOSTNAME, strlen(hp->h_name),
					    hp->h_name, ENC_COPY);
					replace_encode(&ecp, hecp,
					    ENC_DONT_COPY);
				}
			}

			/*
			 * If dhcptab configured to echo client class, do so.
			 */
			if (plp->opts[CD_CLASS_ID] != NULL &&
			    find_encode(ecp, DSYM_INTERNAL,
			    CD_BOOL_ECHO_VCLASS) != NULL) {
				ENCODE		*echo_ecp;
				DHCP_OPT	*op = plp->opts[CD_CLASS_ID];
				echo_ecp = make_encode(DSYM_STANDARD,
				    CD_CLASS_ID, op->len, op->value,
				    ENC_COPY);
				replace_encode(&ecp, echo_ecp, ENC_DONT_COPY);
			}
		}

		if (dnp->dn_flags & DN_FAUTOMATIC || dnp->dn_lease == DHCP_PERM)
			oldlease = DHCP_PERM;
		else {
			if (plp->opts[CD_SERVER_ID] != NULL) {
				/*
				 * Offered absolute Lease time is cached
				 * in the lease field of the record. If
				 * that's expired, then they'll get the
				 * policy value again here. Must have been
				 * LONG time between DISC/REQ!
				 */
				if ((lease_t)dnp->dn_lease < (lease_t)now)
					oldlease = (lease_t)0;
				else
					oldlease = dnp->dn_lease - now;
			} else
				oldlease = dnp->dn_lease - now;
		}

		if (find_encode(ecp, DSYM_INTERNAL, CD_BOOL_LEASENEG) !=
		    NULL)
			negot = B_TRUE;
		else
			negot = B_FALSE;

		/*
		 * Modify changed fields in new database record.
		 */
		ndn = *dnp;	/* struct copy */
		(void) memcpy(ndn.dn_cid, pcd->cid, pcd->cid_len);
		ndn.dn_cid_len = pcd->cid_len;

		/*
		 * This is a little longer than we offered (not taking into
		 * account the secs field), but since I trust the UNIX
		 * clock better than the PC's, it is a good idea to give
		 * the PC a little more time than it thinks, just due to
		 * clock slop on PC's.
		 */
		newlease = config_lease(plp, &ndn, &ecp, oldlease, negot);

		if (newlease != DHCP_PERM)
			ndn.dn_lease = now + newlease;
		else
			ndn.dn_lease = DHCP_PERM;


		/*
		 * It is critical to write the database record if the
		 * client is in the INIT state, so we don't reply to the
		 * client if this fails. However, if the client is simply
		 * trying to verify its address or extend its lease, then
		 * we'll reply regardless of the status of the write,
		 * although we'll return the old lease time.
		 *
		 * If the client is in the INIT_REBOOT state, and the
		 * lease time hasn't changed, we don't bother with the
		 * write, since nothing has changed.
		 */
		if (clnt_state == INIT_STATE || oldlease != newlease) {

			write_error = dhcp_modify_dd_entry(pnd->dh, dnp, &ndn);

			/* Keep state of the cached entry current. */
			if (write_error == DSVC_SUCCESS) {
				*dnp = ndn;    /* struct copy */
			}
		} else {
			if (verbose) {
				dhcpmsg(LOG_INFO,
				    "Database write unnecessary for "
				    "DHCP client: "
				    "%1$s, %2$s\n", pcd->cidbuf,
				    inet_ntop(AF_INET, &ncipaddr,
				    ntoab, sizeof (ntoab)));
			}
		}
		if (write_error == DSVC_SUCCESS ||
		    clnt_state == INIT_REBOOT_STATE) {

			if (write_error != DSVC_SUCCESS)
				set_lease_option(&ecp, oldlease);
			else {
				/* Note that the conversation has completed. */
				pcd->state = ACK;
			}

			if (plp->opts[CD_REQUEST_LIST])
				add_request_list(ifp, plp, &ecp, &ncipaddr);

			/* Now load all the asked for / configured options */
			actual_len = load_options(DHCP_DHCP_CLNT |
			    DHCP_SEND_LEASE, plp, rep_pktp, replen, optp, ecp,
			    vecp);

			if (actual_len < sizeof (PKT))
				actual_len = sizeof (PKT);
			if (verbose) {
				dhcpmsg(LOG_INFO,
				    "Client: %1$s maps to IP: %2$s\n",
				    pcd->cidbuf,
				    inet_ntop(AF_INET, &ncipaddr,
				    ntoab, sizeof (ntoab)));
			}
			(void) send_reply(ifp, rep_pktp, actual_len, &dest_in);

			if (clnt_state == INIT_STATE)
				log = L_ASSIGN;
			else
				log = L_REPLY;

			logtrans(P_DHCP, log, ndn.dn_lease, ncipaddr,
			    server_ip, plp);
		}

		free_encode_list(ecp);
		free_encode_list(vecp);
		if (!no_dhcptab)
			close_macros();
	}

leave_ack:
	if (rep_pktp != NULL)
		free(rep_pktp);
	if (dncp != NULL)
		dhcp_free_dd_list(pnd->dh, dncp);
	if (dnlp != NULL && !existing_offer)
		dhcp_free_dd_list(pnd->dh, dnlp);
}

/* Reacting to a client's DECLINE or RELEASE. */
static void
dhcp_dec_rel(dsvc_clnt_t *pcd, PKT_LIST *plp, int type)
{
	char		*fmtp;
	dn_rec_t	*dnp, dn, ndn;
	dsvc_dnet_t	*pnd;
	struct in_addr	ip;
	int		err = 0;
	DHCP_MSG_CATEGORIES	log;
	dn_rec_list_t	*dncp, *dnlp = NULL;
	uint32_t	query;
	char		ipb[INET_ADDRSTRLEN];
	char		clnt_msg[DHCP_MAX_OPT_SIZE];

	pnd = pcd->pnd;

	if (type == DECLINE) {
		if (plp->opts[CD_REQUESTED_IP_ADDR] &&
		    plp->opts[CD_REQUESTED_IP_ADDR]->len ==
		    sizeof (struct in_addr)) {
			(void) memcpy((char *)&ip,
			    plp->opts[CD_REQUESTED_IP_ADDR]->value,
			    sizeof (struct in_addr));
		}
	} else
		ip.s_addr = plp->pkt->ciaddr.s_addr;

	(void) inet_ntop(AF_INET, &ip, ipb, sizeof (ipb));

	/* Look for a matching IP address and Client ID */

	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QCID|DN_QCIP);
	(void) memcpy(dn.dn_cid, pcd->cid, pcd->cid_len);
	dn.dn_cid_len = pcd->cid_len;
	dn.dn_cip.s_addr = ntohl(ip.s_addr);

	dncp = NULL;
	dnlp = dhcp_lookup_dd_classify(pcd->pnd, B_FALSE, query, -1,
	    &dn, (void **)&dncp, S_CID);
	assert(dncp == NULL);

	if (dnlp == NULL) {
		if (verbose) {
			if (type == DECLINE) {
				fmtp = "Unregistered client: %1$s is "
				    "DECLINEing address: %2$s.\n";
			} else {
				fmtp = "Unregistered client: %1$s is "
				    "RELEASEing address: %2$s.\n";
			}
			dhcpmsg(LOG_INFO, fmtp, pcd->cidbuf, ipb);
		}
		return;
	}

	dnp = dnlp->dnl_rec;
	ndn = *dnp; /* struct copy */

	/* If the entry is not one of ours, then give up. */
	if (match_ownerip(htonl(ndn.dn_sip.s_addr)) == NULL) {
		if (verbose) {
			if (type == DECLINE) {
				fmtp = "Client: %1$s is DECLINEing: "
				    "%2$s not owned by this server.\n";
			} else {
				fmtp = "Client: %1$s is RELEASEing: "
				    "%2$s not owned by this server.\n";
			}
			dhcpmsg(LOG_INFO, fmtp, pcd->cidbuf, ipb);
		}
		goto leave_dec_rel;
	}

	if (type == DECLINE) {
		log = L_DECLINE;
		dhcpmsg(LOG_ERR, "Client: %1$s DECLINED address: %2$s.\n",
		    pcd->cidbuf, ipb);
		if (plp->opts[CD_MESSAGE]) {
			dhcpmsg(LOG_ERR, "DECLINE: client message: %s\n",
			    disp_clnt_msg(plp, clnt_msg, sizeof (clnt_msg)));
		}
		ndn.dn_flags |= DN_FUNUSABLE;
	} else {
		log = L_RELEASE;
		if (ndn.dn_flags & DN_FMANUAL) {
			dhcpmsg(LOG_ERR,
			    "Client: %1$s is trying to RELEASE manual "
			    "address: %2$s\n", pcd->cidbuf, ipb);
			goto leave_dec_rel;
		}
		if (verbose) {
			dhcpmsg(LOG_INFO,
			    "Client: %1$s RELEASED address: %2$s\n",
			    pcd->cidbuf, ipb);
			if (plp->opts[CD_MESSAGE]) {
				dhcpmsg(LOG_INFO,
				    "RELEASE: client message: %s\n",
				    disp_clnt_msg(plp, clnt_msg,
				    sizeof (clnt_msg)));
			}
		}
	}

	/* Clear out the cid and lease fields */
	if (!(ndn.dn_flags & DN_FMANUAL)) {
		ndn.dn_cid[0] = '\0';
		ndn.dn_cid_len = 1;
		ndn.dn_lease = (lease_t)0;
	}

	/* Ignore write errors. */
	err = dhcp_modify_dd_entry(pnd->dh, dnp, &ndn);
	if (err != DSVC_SUCCESS) {
		dhcpmsg(LOG_NOTICE,
		    "%1$s: ERROR modifying database: %2$s for client %3$s\n",
		    log == L_RELEASE ? "RELEASE" : "DECLINE",
		    dhcpsvc_errmsg(err), ipb);
	} else {
		if (type == RELEASE) {
			/*
			 * performance: save select_offer() lots of work by
			 * caching this perfectly good ip address in freerec.
			 */
			*(dnlp->dnl_rec) = ndn; /* struct copy */
			add_dnet_cache(pnd, dnlp);
			dnlp = NULL;
		}
	}

	logtrans(P_DHCP, log, ndn.dn_lease, ip, server_ip, plp);

leave_dec_rel:

	if (dnlp != NULL)
		dhcp_free_dd_list(pnd->dh, dnlp);
}

/*
 * Responding to an INFORM message.
 *
 * INFORM messages are received from clients that already have their network
 * parameters (such as IP address and subnet mask), but wish to receive
 * other configuration parameters. The server will not check for an existing
 * lease as clients may have obtained their network parameters by some
 * means other than DHCP. Similarly, the DHCPACK generated in response to
 * the INFORM message will not include lease time information. All other
 * configuration parameters are returned.
 */
static void
dhcp_inform(dsvc_clnt_t *pcd, PKT_LIST *plp)
{
	uint_t		replen;
	int		used_pkt_len;
	PKT 		*rep_pktp = NULL;
	uchar_t		*optp;
	ENCODE		*ecp, *vecp, *class_ecp, *class_vecp,
	    *cid_ecp, *cid_vecp, *net_ecp, *net_vecp;
	MACRO		*net_mp, *class_mp, *cid_mp;
	dsvc_dnet_t	*pnd;
	char		*class_id;
	char		class_idbuf[DSYM_CLASS_SIZE];
	IF		*ifp = pcd->ifp;

	pnd = pcd->pnd;
	class_id = get_class_id(plp, class_idbuf, sizeof (class_idbuf));

	/*
	 * Macros are evaluated this way: First apply parameters from
	 * a client class macro (if present), then apply those from the
	 * network macro (if present),  and finally apply those from a
	 * client id macro (if present).
	 */
	ecp = vecp = NULL;
	net_vecp = net_ecp = NULL;
	class_vecp = class_ecp = NULL;
	cid_vecp = cid_ecp = NULL;

	if (!no_dhcptab) {
		open_macros();
		if ((net_mp = get_macro(pnd->network)) != NULL)
			net_ecp = net_mp->head;
		if ((cid_mp = get_macro(pcd->cidbuf)) != NULL)
			cid_ecp = cid_mp->head;
		if (class_id != NULL) {
			if ((class_mp = get_macro(class_id)) != NULL) {
				class_vecp = vendor_encodes(class_mp,
				    class_id);
				class_ecp = class_mp->head;
			}
			if (net_mp != NULL)
				net_vecp = vendor_encodes(net_mp, class_id);
			if (cid_mp != NULL)
				cid_vecp = vendor_encodes(cid_mp, class_id);
			vecp = combine_encodes(class_vecp, net_vecp,
			    ENC_COPY);
			vecp = combine_encodes(vecp, cid_vecp, ENC_DONT_COPY);
		}

		ecp = combine_encodes(class_ecp, net_ecp, ENC_COPY);
		ecp = combine_encodes(ecp, cid_ecp, ENC_DONT_COPY);
	}

	/* First get a generic reply packet. */
	rep_pktp = gen_reply_pkt(pcd, plp, ACK, &replen, &optp, &ifp->addr);

	/*
	 * Client is requesting specific options. let's try and ensure it
	 * gets what it wants, if at all possible.
	 */
	if (plp->opts[CD_REQUEST_LIST] != NULL)
		add_request_list(ifp, plp, &ecp, &plp->pkt->ciaddr);

	/*
	 * Explicitly set the ciaddr to be that which the client gave
	 * us.
	 */
	rep_pktp->ciaddr.s_addr = plp->pkt->ciaddr.s_addr;

	/*
	 * Now load all the asked for / configured options. DON'T send
	 * any lease time info!
	 */
	used_pkt_len = load_options(DHCP_DHCP_CLNT, plp, rep_pktp, replen, optp,
	    ecp, vecp);

	free_encode_list(ecp);
	free_encode_list(vecp);
	if (!no_dhcptab)
		close_macros();

	if (used_pkt_len < sizeof (PKT))
		used_pkt_len = sizeof (PKT);

	(void) send_reply(ifp, rep_pktp, used_pkt_len, &plp->pkt->ciaddr);

	logtrans(P_DHCP, L_INFORM, 0, plp->pkt->ciaddr, server_ip, plp);

leave_inform:
	if (rep_pktp != NULL)
		free(rep_pktp);
}

static char *
disp_clnt_msg(PKT_LIST *plp, char *bufp, int len)
{
	uchar_t tlen;

	bufp[0] = '\0';	/* null string */

	if (plp && plp->opts[CD_MESSAGE]) {
		tlen = ((uchar_t)len < plp->opts[CD_MESSAGE]->len) ?
		    (len - 1) : plp->opts[CD_MESSAGE]->len;
		(void) memcpy(bufp, plp->opts[CD_MESSAGE]->value, tlen);
		bufp[tlen] = '\0';
	}
	return (bufp);
}

/*
 * serverip expected in host order
 */
static PKT *
gen_reply_pkt(dsvc_clnt_t *pcd, PKT_LIST *plp, int type, uint_t *len,
    uchar_t **optpp, struct in_addr *serverip)
{
	PKT		*reply_pktp;
	uint16_t	plen;

	/*
	 * We need to determine the packet size. Perhaps the client has told
	 * us?
	 */
	if (plp->opts[CD_MAX_DHCP_SIZE]) {
		if (plp->opts[CD_MAX_DHCP_SIZE]->len != sizeof (uint16_t)) {
			dhcpmsg(LOG_ERR, "Garbled MAX DHCP message size option "
			    "from\nclient: '%1$s'. Len is %2$d, when it should "
			    "be %3$d. Defaulting to %4$d.\n",
			    pcd->cidbuf,
			    plp->opts[CD_MAX_DHCP_SIZE]->len,
			    sizeof (uint16_t), DHCP_DEF_MAX_SIZE);
			plen = DHCP_DEF_MAX_SIZE;
		} else {
			(void) memcpy(&plen, plp->opts[CD_MAX_DHCP_SIZE]->value,
			    sizeof (uint16_t));
			plen = ntohs(plen);
			if (plen < DHCP_DEF_MAX_SIZE)
				plen = DHCP_DEF_MAX_SIZE;
		}
	} else {
		/*
		 * Define size to be a fixed length. Too hard to add up all
		 * possible class id, macro, and hostname/lease time options
		 * without doing just about as much work as constructing the
		 * whole reply packet.
		 */
		plen = DHCP_MAX_REPLY_SIZE;
	}

	/* Generate a generically initialized BOOTP packet */
	reply_pktp = gen_bootp_pkt(plen, plp->pkt);

	reply_pktp->op = BOOTREPLY;
	*optpp = reply_pktp->options;

	/*
	 * Set pkt type.
	 */
	*(*optpp)++ = (uchar_t)CD_DHCP_TYPE;
	*(*optpp)++ = (uchar_t)1;
	*(*optpp)++ = (uchar_t)type;

	/*
	 * All reply packets have server id set.
	 */
	*(*optpp)++ = (uchar_t)CD_SERVER_ID;
	*(*optpp)++ = (uchar_t)4;
#if	defined(_LITTLE_ENDIAN)
	*(*optpp)++ = (uchar_t)(serverip->s_addr & 0xff);
	*(*optpp)++ = (uchar_t)((serverip->s_addr >>  8) & 0xff);
	*(*optpp)++ = (uchar_t)((serverip->s_addr >> 16) & 0xff);
	*(*optpp)++ = (uchar_t)((serverip->s_addr >> 24) & 0xff);
#else
	*(*optpp)++ = (uchar_t)((serverip->s_addr >> 24) & 0xff);
	*(*optpp)++ = (uchar_t)((serverip->s_addr >> 16) & 0xff);
	*(*optpp)++ = (uchar_t)((serverip->s_addr >>  8) & 0xff);
	*(*optpp)++ = (uchar_t)(serverip->s_addr & 0xff);
#endif	/* _LITTLE_ENDIAN */

	*len = plen;
	return (reply_pktp);
}

/*
 * If the client requests it, and either it isn't currently configured
 * or hasn't already been added, provide the option now.  Will also work
 * for NULL ENCODE lists, but initializing them to point to the requested
 * options.
 *
 * If nsswitch contains host name services which hang, big problems occur
 * with dhcp server, since the main thread hangs waiting for that name
 * service's timeout.
 *
 * NOTE: this function should be called only after all other parameter
 * merges have taken place (combine_encode).
 */
static void
add_request_list(IF *ifp, PKT_LIST *plp, ENCODE **ecp, struct in_addr *ip)
{
	ENCODE	*ep, *ifecp, *end_ecp = NULL;
	struct hostent	h, *hp;
	char hbuf[NSS_BUFLEN_HOSTS];
	int herrno;

	/* Find the end. */
	if (*ecp) {
		for (ep = *ecp; ep->next; ep = ep->next)
			/* null */;
		end_ecp = ep;
	}

	/* HOSTNAME */
	if (is_option_requested(plp, CD_HOSTNAME) &&
	    (find_encode(*ecp, DSYM_STANDARD, CD_HOSTNAME) == NULL) &&
	    (find_encode(*ecp, DSYM_INTERNAL, CD_BOOL_HOSTNAME) == NULL)) {
		hp = gethostbyaddr_r((char *)ip, sizeof (struct in_addr),
		    AF_INET, &h, hbuf, sizeof (hbuf), &herrno);
		if (hp != NULL) {
			if (end_ecp) {
				end_ecp->next = make_encode(DSYM_STANDARD,
				    CD_HOSTNAME, strlen(hp->h_name),
				    hp->h_name, ENC_COPY);
				end_ecp = end_ecp->next;
			} else {
				end_ecp = make_encode(DSYM_STANDARD,
				    CD_HOSTNAME, strlen(hp->h_name),
				    hp->h_name, ENC_COPY);
			}
		}
	}

	/*
	 * all bets off for the following if thru a relay agent.
	 */
	if (plp->pkt->giaddr.s_addr != 0L)
		return;

	/* SUBNET MASK */
	if (is_option_requested(plp, CD_SUBNETMASK) && find_encode(*ecp,
	    DSYM_STANDARD, CD_SUBNETMASK) == NULL) {
		ifecp = find_encode(ifp->ecp, DSYM_STANDARD, CD_SUBNETMASK);
		if (end_ecp) {
			end_ecp->next = dup_encode(ifecp);
			end_ecp = end_ecp->next;
		} else
			end_ecp = dup_encode(ifecp);
	}

	/* BROADCAST ADDRESS */
	if (is_option_requested(plp, CD_BROADCASTADDR) && find_encode(*ecp,
	    DSYM_STANDARD, CD_BROADCASTADDR) == NULL) {
		ifecp = find_encode(ifp->ecp, DSYM_STANDARD,
		    CD_BROADCASTADDR);
		if (end_ecp) {
			end_ecp->next = dup_encode(ifecp);
			end_ecp = end_ecp->next;
		} else
			end_ecp = dup_encode(ifecp);
	}

	/* IP MTU */
	if (is_option_requested(plp, CD_MTU) && find_encode(*ecp,
	    DSYM_STANDARD, CD_MTU) == NULL) {
		ifecp = find_encode(ifp->ecp, DSYM_STANDARD, CD_MTU);
		if (end_ecp) {
			end_ecp->next = dup_encode(ifecp);
			end_ecp = end_ecp->next;
		} else
			end_ecp = dup_encode(ifecp);
	}

	if (*ecp == NULL)
		*ecp = end_ecp;
}

/*
 * Is a specific option requested? Returns True if so, False otherwise.
 */
static int
is_option_requested(PKT_LIST *plp, ushort_t code)
{
	uchar_t c, *tp;
	DHCP_OPT *cp = plp->opts[CD_REQUEST_LIST];

	for (c = 0, tp = (uchar_t *)cp->value; c < cp->len; c++, tp++) {
		if (*tp == (uchar_t)code)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Locates lease option, if possible, otherwise allocates an encode and
 * appends it to the end. Changes current lease setting.
 *
 * TODO: ugh. We don't address the case where the Lease time changes, but
 * T1 and T2 don't. We don't want T1 or T2 to be greater than the lease
 * time! Perhaps T1 and T2 should be a percentage of lease time... Later..
 */
static void
set_lease_option(ENCODE **ecpp, lease_t lease)
{
	ENCODE	*ep, *prev_ep, *lease_ep;

	lease = htonl(lease);

	if (ecpp != NULL && (lease_ep = find_encode(*ecpp, DSYM_STANDARD,
	    CD_LEASE_TIME)) != NULL && lease_ep->len == sizeof (lease_t)) {
		(void) memcpy(lease_ep->data, (void *)&lease, sizeof (lease_t));
	} else {
		if (*ecpp != NULL) {
			for (prev_ep = ep = *ecpp; ep != NULL; ep = ep->next)
				prev_ep = ep;
			prev_ep->next = make_encode(DSYM_STANDARD,
			    CD_LEASE_TIME, sizeof (lease_t), &lease, ENC_COPY);
		} else {
			*ecpp = make_encode(DSYM_STANDARD, CD_LEASE_TIME,
			    sizeof (lease_t), &lease, ENC_COPY);
			(*ecpp)->next = NULL;
		}
	}
}
/*
 * Sets appropriate option in passed ENCODE list for lease. Returns
 * calculated relative lease time.
 */
static int
config_lease(PKT_LIST *plp, dn_rec_t *dnp, ENCODE **ecpp, lease_t oldlease,
    boolean_t negot)
{
	lease_t		newlease, rel_current;
	ENCODE		*lease_ecp;

	if (ecpp != NULL && (lease_ecp = find_encode(*ecpp, DSYM_STANDARD,
	    CD_LEASE_TIME)) != NULL && lease_ecp->len == sizeof (lease_t)) {
		(void) memcpy((void *)&rel_current, lease_ecp->data,
		    sizeof (lease_t));
		rel_current = htonl(rel_current);
	} else
		rel_current = (lease_t)DEFAULT_LEASE;

	if (dnp->dn_flags & DN_FAUTOMATIC || !negot) {
		if (dnp->dn_flags & DN_FAUTOMATIC)
			newlease = ntohl(DHCP_PERM);
		else {
			/* sorry! */
			if (oldlease)
				newlease = oldlease;
			else
				newlease = rel_current;
		}
	} else {
		/*
		 * lease is not automatic and is negotiable!
		 * If the dhcp-network lease is bigger than the current
		 * policy value, then let the client benefit from this
		 * situation.
		 */
		if (oldlease > rel_current)
			rel_current = oldlease;

		if (plp->opts[CD_LEASE_TIME] &&
		    plp->opts[CD_LEASE_TIME]->len == sizeof (lease_t)) {
			/*
			 * Client is requesting a lease renegotiation.
			 */
			(void) memcpy((void *)&newlease,
			    plp->opts[CD_LEASE_TIME]->value, sizeof (lease_t));

			newlease = ntohl(newlease);

			/*
			 * Note that this comparison handles permanent
			 * leases as well. Limit lease to configured value.
			 */
			if (newlease > rel_current)
				newlease = rel_current;
		} else
			newlease = rel_current;
	}

	set_lease_option(ecpp, newlease);

	return (newlease);
}

/*
 * If a packet has the classid set, return the value, else return null.
 */
char *
get_class_id(PKT_LIST *plp, char *bufp, int len)
{
	uchar_t	*ucp, ulen;
	char	*retp;

	if (plp->opts[CD_CLASS_ID]) {
		/*
		 * If the class id is set, see if there is a macro by this
		 * name. If so, then "OR" the ENCODE settings of the class
		 * macro with the packet macro. Settings in the packet macro
		 * OVERRIDE settings in the class macro.
		 */
		ucp = plp->opts[CD_CLASS_ID]->value;
		ulen = plp->opts[CD_CLASS_ID]->len;
		if (len < ulen)
			ulen = len;
		(void) memcpy(bufp, ucp, ulen);
		bufp[ulen] = '\0';

		retp = bufp;
	} else
		retp = NULL;

	return (retp);
}

/*
 * Checks whether an offer ip address in the per net inet address
 * cache.
 *
 * pnd - per net structure
 * reservep - address to check, in network order.
 */
static boolean_t
check_offer(dsvc_dnet_t *pnd, struct in_addr *reservep)
{
	dsvc_clnt_t	tpcd;

	tpcd.off_ip.s_addr = reservep->s_addr;

	return (hash_Lookup(pnd->itable, reservep, sizeof (struct in_addr),
	    clnt_netcmp, &tpcd, B_FALSE) == NULL ? B_TRUE : B_FALSE);
}

/*
 * Adds or updates an offer to the per client data structure. The client
 * struct is hashed by clientid into the per net ctable hash table, and
 * by offer address in the itable hash table, which is used to reserve the
 * ip address. Lease time is expected to be set by caller.
 * Will update existing OFFER if already provided.
 *
 * This implementation does not consider the fact that an offer can be
 * sent out via more than one interface, so dsvc_clnt_t.ifp should
 * really be a list or the itable's entries should be lists of
 * dsvc_clnt_ts. As long as we don't change this, we assume that the
 * client will eventually REQUEST the last offer we have sent out
 * because when we receive the same DISCOVER via multiple interfaces,
 * we always update the same offer cache entry so its ifp is always
 * the interface we received the last DISCOVER on.
 *
 * pcd - per client data struct.
 * dnlp - pointer to pointer to current container entry. Performance: caching
 * reduces datastore activity, structure copying.
 * nlease - new lease time.
 * reservep - new offer address (expected in network order).
 * purge_cache - Multithreading: avoid redundant cache purging in
 * select_offer().
 */
boolean_t
update_offer(dsvc_clnt_t *pcd, dn_rec_list_t **dnlp, lease_t nlease,
	struct in_addr *reservep, boolean_t purge_cache)
{
	char		ntoab[INET_ADDRSTRLEN];
	boolean_t	insert = B_TRUE;
	boolean_t	update = B_FALSE;
	boolean_t	offer = B_FALSE;
	dsvc_dnet_t	*pnd = pcd->pnd;
	IF		*ifp = pcd->ifp;
	dn_rec_t	*dnp = NULL;
	struct in_addr	off_ip;

	/* Save the original datastore record. */
	if (dnlp != NULL && *dnlp != NULL) {
		if (pcd->dnlp != NULL && pcd->dnlp != *dnlp)
			dhcp_free_dd_list(pnd->dh, pcd->dnlp);
		pcd->dnlp = *dnlp;
	}
	if (pcd->dnlp != NULL)
		dnp = pcd->dnlp->dnl_rec;

	/* Determine the offer address. */
	if (reservep == NULL && dnp != NULL)
		off_ip.s_addr = htonl(dnp->dn_cip.s_addr);
	else if (reservep != NULL)
		off_ip.s_addr = reservep->s_addr;
	else {
		dhcpmsg(LOG_DEBUG,
		    "Neither offer IP nor IP to reserve present\n");
		assert(B_FALSE);
		return (B_FALSE);
	}

	/* If updating, release the old offer address. */
	if (pcd->off_ip.s_addr == htonl(INADDR_ANY)) {
		offer = B_TRUE;
	} else {
		update = B_TRUE;
		if (pcd->off_ip.s_addr != off_ip.s_addr) {
			purge_offer(pcd, B_FALSE, purge_cache);
			offer = B_TRUE;
		} else
			insert = B_FALSE;
	}

	if (nlease != 0)
		pcd->lease = nlease;

	/* Prepare to insert pcd into the offer hash table. */
	pcd->mtime = reinit_time;

	pcd->off_ip.s_addr = off_ip.s_addr;

	assert(pcd->off_ip.s_addr != htonl(INADDR_ANY));

	if (insert) {
		if ((pcd->ihand = hash_Insert(pnd->itable, &pcd->off_ip,
		    sizeof (struct in_addr), clnt_netcmp, pcd, pcd)) == NULL) {
			if (reservep == NULL) {
				dhcpmsg(LOG_WARNING, "Duplicate offer of %1$s "
				    "to client: %2$s\n",
				    inet_ntop(AF_INET, &pcd->off_ip, ntoab,
				    sizeof (ntoab)), pcd->cidbuf);
			}
			pcd->off_ip.s_addr = htonl(INADDR_ANY);
			dhcp_free_dd_list(pnd->dh, pcd->dnlp);
			if (dnlp != NULL && *dnlp != NULL &&
			    pcd->dnlp == *dnlp) {
				*dnlp = NULL;
			}
			pcd->dnlp = NULL;
			return (B_FALSE);
		}
	} else
		hash_Dtime(pcd->ihand, time(NULL) + off_secs);

	if (offer) {
		(void) mutex_lock(&ifp->ifp_mtx);
		ifp->offers++;
		(void) mutex_unlock(&ifp->ifp_mtx);
	}

	if (debug) {
		if (reservep != NULL) {
			dhcpmsg(LOG_INFO, "Reserved offer: %s\n",
			    inet_ntop(AF_INET, &pcd->off_ip,
			    ntoab, sizeof (ntoab)));
		} else if (update) {
			dhcpmsg(LOG_INFO, "Updated offer: %s\n",
			    inet_ntop(AF_INET, &pcd->off_ip,
			    ntoab, sizeof (ntoab)));
		} else {
			dhcpmsg(LOG_INFO, "Added offer: %s\n",
			    inet_ntop(AF_INET, &pcd->off_ip,
			    ntoab, sizeof (ntoab)));
		}
	}
	return (B_TRUE);
}

/*
 * Deletes an offer.
 *
 * pcd - per client struct
 * expired - has offer expired, or been purged
 * purge_cache - Multi-threading: avoid redundant cache purging in
 * select_offer().
 */
void
purge_offer(dsvc_clnt_t *pcd, boolean_t expired, boolean_t purge_cache)
{
	char		ntoab[INET_ADDRSTRLEN];
	dsvc_dnet_t	*pnd = pcd->pnd;
	IF		*ifp = pcd->ifp;

	if (pcd->off_ip.s_addr != htonl(INADDR_ANY)) {
		if (debug) {
			if (expired == B_TRUE)
				dhcpmsg(LOG_INFO, "Freeing offer: %s\n",
				    inet_ntop(AF_INET, &pcd->off_ip,
				    ntoab, sizeof (ntoab)));
			else
				dhcpmsg(LOG_INFO, "Purging offer: %s\n",
				    inet_ntop(AF_INET, &pcd->off_ip,
				    ntoab, sizeof (ntoab)));
		}

		/*
		 * The offer cache ensures that recently granted offer
		 * addresses won't attempt to be reused from the dnet
		 * caches. When purging one of these offers, be sure to
		 * remove the associated record from the dnet cache,
		 * to avoid collisions.
		 */
		if (pcd->state == ACK && pcd->dnlp != NULL) {
			if (purge_cache)
				purge_dnet_cache(pnd, pcd->dnlp->dnl_rec);
			dhcp_free_dd_list(pnd->dh, pcd->dnlp);
			pcd->dnlp = NULL;
		}


		/* Prepare to delete pcd from the offer hash table. */
		(void) hash_Delete(pnd->itable, &pcd->off_ip,
		    sizeof (struct in_addr), clnt_netcmp, pcd, NULL);

		pcd->off_ip.s_addr = htonl(INADDR_ANY);

		(void) mutex_lock(&ifp->ifp_mtx);
		if (ifp->offers > 0)
			ifp->offers--;
		if (expired)
			ifp->expired++;
		(void) mutex_unlock(&ifp->ifp_mtx);
	}
}

/*
 * Allocate a new entry in the dhcp-network db for the cid, taking into
 * account requested IP address. Verify address.
 *
 * The network portion of the address doesn't have to be the same as ours,
 * just owned by us. We also make sure we don't select a record which is
 * currently in use, by reserving the address in the offer cache. Database
 * records are cached up to the D_OFFER lifetime to improve performance.
 *
 * Returns:	1 if there's a usable entry for the client, 0
 *		if not. Places the record in the dn_rec_list_t structure
 *		pointer handed in.
 */
/*ARGSUSED*/
boolean_t
select_offer(dsvc_dnet_t *pnd, PKT_LIST *plp, dsvc_clnt_t *pcd,
	dn_rec_list_t **dnlpp)
{
	struct in_addr	req_ip, *req_ipp = &req_ip, tip;
	boolean_t	found = B_FALSE;
	time_t		now;
	dn_rec_t	dn, *dnp;
	dn_rec_list_t	*dncp, *dnsp, *tlp;
	int		nrecords;
	uint32_t	query;
	int		retry;
	boolean_t	io_done, is_bootp;
	struct in_addr	*oip;

	if (plp->opts[CD_DHCP_TYPE] == NULL)
		is_bootp = B_TRUE;
	else
		is_bootp = B_FALSE;

	*dnlpp = NULL;
	if (!is_bootp) {
		/*
		 * Is the DHCP client requesting a specific address? Is so, and
		 * we can satisfy him, do so.
		 */
		if (plp->opts[CD_REQUESTED_IP_ADDR] != NULL) {
			(void) memcpy((void *)&req_ip,
			    plp->opts[CD_REQUESTED_IP_ADDR]->value,
			    sizeof (struct in_addr));

			if ((req_ip.s_addr & pnd->subnet.s_addr) ==
			    pnd->net.s_addr)
				found = B_TRUE;

		} else if (plp->opts[CD_HOSTNAME] != NULL) {
			char		hname[MAXHOSTNAMELEN + 1];
			int		hlen;

			/* turn hostname option into a string */
			hlen = plp->opts[CD_HOSTNAME]->len;
			hlen = MIN(hlen, MAXHOSTNAMELEN);
			(void) memcpy(hname, plp->opts[CD_HOSTNAME]->value,
			    hlen);
			hname[hlen] = '\0';

			dhcpmsg(LOG_DEBUG,
			    "select_offer:  hostname request for %s\n", hname);
			if (name_avail(hname, pcd, plp, dnlpp, NULL,
			    &req_ipp) && req_ipp) {
				if ((req_ip.s_addr & pnd->subnet.s_addr) ==
				    pnd->net.s_addr) {
					found = B_TRUE;
				} else if (*dnlpp != NULL) {
					dhcp_free_dd_list(pnd->dh, *dnlpp);
					*dnlpp = NULL;
				}
				dhcpmsg(LOG_DEBUG, "select_offer:  hostname %s "
				    "available, req_ip %x\n", hname,
				    ntohl(req_ip.s_addr));
			} else
				dhcpmsg(LOG_DEBUG, "select_offer:  name_avail "
				    "false or no address for %s\n", hname);
		}
	}

	/*
	 *  Check the offer list and table entry.
	 */
	if (found && *dnlpp == NULL)
		found = addr_avail(pnd, pcd, dnlpp, req_ip, B_FALSE);

	if (!found) {
		/*
		 * Try to find a free entry. Look for an AVAILABLE entry
		 * (cid == 0x00, len == 1), owned by us.
		 * The outer loop runs through the server ips owned by us.
		 *
		 * Multi-threading: to improve performance, the following
		 * algorithm coordinates accesses to the underlying table,
		 * so only one thread is initiating lookups per network.
		 * This is crucial, as lookup operations are expensive,
		 * and not sufficiently malleable to allow partitioned
		 * lookups (e.g. all that can be asked for are n free or
		 * server-owned entries, multiple threads will retrieve
		 * the same records).
		 *
		 * The three iterations through the inner loop attempt to use
		 *
		 * 1) the next cached entry
		 * 2) all cached entries
		 * 3) all free or per-server entries in the underlying table
		 *
		 * Since many threads are consuming the cached entries,
		 * any thread may find itself in the role of having to
		 * refresh the cache. We always read at least enough
		 * entries to satisfy all current threads. Reading all
		 * records is prohibitively expensive, and should only
		 * be done as a last resort.
		 *
		 * As always,  to better distribute garbage
		 * collection and data structure aging tasks, each
		 * thread must actively implement policy, checking
		 * for offer expiration (which invalidates the cache).
		 */

		for (oip = owner_ip; oip->s_addr != INADDR_ANY; oip++) {
			/*
			 * Initialize query.
			 */
			DSVC_QINIT(query);
			DSVC_QEQ(query, DN_QCID|DN_QSIP);
			dn.dn_cid[0] = '\0';
			dn.dn_cid_len = 1;
			dn.dn_sip.s_addr = ntohl(oip->s_addr);

			/*
			 * Decide whether a bootp record is required.
			 */
			dn.dn_flags = 0;
			DSVC_QEQ(query, DN_QFBOOTP_ONLY);
			if (is_bootp)
				dn.dn_flags = DN_FBOOTP_ONLY;

			/*
			 * These flags are used counter-intuitively.
			 * This says that the setting of the bit
			 * (off) in the dn.dn_flags matches the
			 * setting in the record (off).
			 */
			DSVC_QEQ(query, DN_QFUNUSABLE|DN_QFMANUAL);

			for (retry = 0; !found && retry < 3; retry++) {
				now = time(NULL);
				(void) mutex_lock(&pnd->thr_mtx);
				nrecords = pnd->nthreads < DHCP_MIN_RECORDS ?
				    DHCP_MIN_RECORDS : pnd->nthreads;
				(void) mutex_unlock(&pnd->thr_mtx);

				/*
				 * Purge cached records when expired or database
				 * re-read.
				 */

				(void) mutex_lock(&pnd->free_mtx);
				dncp = pnd->freerec;
				if (dncp != NULL &&
				    PND_FREE_TIMEOUT(pnd, now)) {
				pnd->freerec = NULL;
				dhcp_free_dd_list(pnd->dh, dncp);
				dncp = NULL;
				}

				if (dncp != NULL) {
					if (retry == 0) {
						/* Try the next cached record */
						pnd->freerec = dncp->dnl_next;
						dncp->dnl_next = NULL;
					} else if (retry == 1) {
						/*
						 * Try all remaining cached
						 * records
						 */
						pnd->freerec = NULL;
					}
				}
				if (retry > 1) {
				/* Try all possible records in datastore. */
					pnd->freerec = NULL;
					nrecords = -1;
					if (dncp != NULL) {
						dhcp_free_dd_list(
						    pnd->dh, dncp);
						dncp = NULL;
					}
				}
				(void) mutex_unlock(&pnd->free_mtx);

				io_done = (dncp == NULL);
				*dnlpp = dhcp_lookup_dd_classify(pcd->pnd,
				    nrecords == -1 ? B_FALSE : B_TRUE, query,
				    nrecords, &dn, (void **)&dncp,
				    S_CID | S_FREE);
				if (*dnlpp != NULL) {
					dnp = (*dnlpp)->dnl_rec;
					tip.s_addr = htonl(dnp->dn_cip.s_addr);
					(void) update_offer(pcd, NULL, 0,
					    &tip, B_TRUE);
					found = B_TRUE;
				}

				(void) mutex_lock(&pnd->free_mtx);
				if (io_done) {
					/*
					 * Note time when records were read.
					 */
					if (dncp != NULL) {
						now = time(NULL);
						pnd->free_mtime = reinit_time;
						pnd->free_stamp = now +
						    cache_secs;
					}
				}

				/* Save any leftover records for later use. */
				if (dncp != NULL) {
					for (tlp = dncp;
					    tlp != NULL && tlp->dnl_next;
					    tlp = tlp->dnl_next)
						/* null statement */;
					tlp->dnl_next = pnd->freerec;
					pnd->freerec = dncp;
				}
				(void) mutex_unlock(&pnd->free_mtx);
			}
		}
	}

	if (!found && !is_bootp) {
		/*
		 * Struck out. No usable available addresses. Let's look for
		 * the LRU expired address. Only makes sense for dhcp
		 * clients. First we'll try the next record from
		 * the lru list (this assumes lru database search capability).
		 * Next we'll try all records. Finally we'll go get all
		 * free records.
		 *
		 * Multi-threading: to improve performance, the following
		 * algorithm coordinates accesses to the underlying table,
		 * so only one thread is initiating lookups per network.
		 * This is crucial, as lookup operations are expensive,
		 * and not sufficiently malleable to allow partitioned
		 * lookups (e.g. all that can be asked for are n free or
		 * server-owned entries, multiple threads will retrieve
		 * the same records).
		 *
		 * We only consider clients owned by us.
		 * The outer loop runs through the server ips owned by us
		 *
		 * The three iterations through the inner loop attempt to use
		 *
		 * 1) the next cached entry
		 * 2) all cached entries
		 * 3) all free or per-server entries in the underlying table
		 *
		 * Since many threads are consuming the cached entries,
		 * any thread may find itself in the role of having to
		 * refresh the cache. We always read at least enough
		 * entries to satisfy all current threads. Reading all
		 * records is prohibitively expensive, and should only
		 * be done as a last resort.
		 *
		 * As always,  to better distribute garbage
		 * collection and data structure aging tasks, each
		 * thread must actively implement policy, checking
		 * for offer expiration (which invalidates the cache).
		 */

		for (oip = owner_ip; oip->s_addr != INADDR_ANY; oip++) {
			/*
			 * Initialize query.
			 */
			DSVC_QINIT(query);
			DSVC_QEQ(query, DN_QSIP);
			dn.dn_sip.s_addr = ntohl(oip->s_addr);

			/*
			 * These flags are used counter-intuitively.
			 * This says that the setting of the bit
			 * (off) in the dn.dn_flags matches the
			 * setting in the record (off).
			 */
			DSVC_QEQ(query, DN_QFBOOTP_ONLY|
			    DN_QFMANUAL|DN_QFUNUSABLE);
			dn.dn_flags = 0;

			for (retry = 0; !found && retry < 3; retry++) {
				now = time(NULL);
				(void) mutex_lock(&pnd->thr_mtx);
				nrecords = pnd->nthreads < DHCP_MIN_RECORDS ?
				    DHCP_MIN_RECORDS : pnd->nthreads;
				(void) mutex_unlock(&pnd->thr_mtx);

				/*
				 * Purge cached records when expired or database
				 * re-read.
				 */

				(void) mutex_lock(&pnd->lru_mtx);
				dnsp = pnd->lrurec;
				if (dnsp != NULL && PND_LRU_TIMEOUT(pnd, now)) {
					pnd->lrurec = NULL;
					dhcp_free_dd_list(pnd->dh, dnsp);
					dnsp = NULL;
				}

				if (dnsp != NULL) {
					if (retry == 0) {
						/* Try the next cached record */
						pnd->lrurec = dnsp->dnl_next;
						dnsp->dnl_next = NULL;
					} else if (retry == 1) {
						/*
						 * Try all remaining cached
						 * records
						 */
						pnd->lrurec = NULL;
					}
				}
				if (retry > 1) {
				/* Try all possible records */
					pnd->lrurec = NULL;
					nrecords = -1;
					if (dnsp != NULL) {
						dhcp_free_dd_list(pnd->dh,
						    dnsp);
						dnsp = NULL;
					}
				}
				(void) mutex_unlock(&pnd->lru_mtx);

				io_done = (dnsp == NULL);
				*dnlpp = dhcp_lookup_dd_classify(pcd->pnd,
				    nrecords == -1 ? B_FALSE : B_TRUE, query,
				    nrecords, &dn, (void **)&dnsp, S_LRU);
				if (*dnlpp != NULL) {
					dnp = (*dnlpp)->dnl_rec;
					tip.s_addr = htonl(dnp->dn_cip.s_addr);
					(void) update_offer(pcd, NULL, 0, &tip,
					    B_TRUE);
					found = B_TRUE;
				}

				(void) mutex_lock(&pnd->lru_mtx);
				if (io_done) {
					if (dnsp != NULL) {
						now = time(NULL);
						pnd->lru_mtime = reinit_time;
						pnd->lru_stamp = now +
						    cache_secs;
					}
				}

				/*
				 * Save any leftover records for possible
				 * later use
				 */
				if (dnsp != NULL) {
					for (tlp = dnsp;
					    tlp != NULL && tlp->dnl_next;
					    tlp = tlp->dnl_next)
						/* null statement */;
					tlp->dnl_next = pnd->lrurec;
					pnd->lrurec = dnsp;
				}
				(void) mutex_unlock(&pnd->lru_mtx);
			}
		}
	}

	return (found);
}

/*
 * purge_dnet_cache() - remove conflicting entries from the
 * free and lru dnet caches when records are modified. Expensive
 * but necessary.
 *
 * pnd - per net struct
 * dnp - pointer to cached/modified entry
 */
static void
purge_dnet_cache(dsvc_dnet_t *pnd, dn_rec_t *dnp)
{
	dn_rec_list_t	*tlp;
	dn_rec_list_t	*plp;

	(void) mutex_lock(&pnd->free_mtx);

	for (plp = tlp = pnd->freerec; tlp != NULL; tlp = tlp->dnl_next) {
		if (tlp->dnl_rec->dn_cip.s_addr == dnp->dn_cip.s_addr) {
			if (tlp == plp) {
				pnd->freerec = tlp->dnl_next;
			} else {
				plp->dnl_next = tlp->dnl_next;
			}
			tlp->dnl_next = NULL;
			break;
		}
		plp = tlp;
	}
	(void) mutex_unlock(&pnd->free_mtx);
	if (tlp != NULL)
		dhcp_free_dd_list(pnd->dh, tlp);

	(void) mutex_lock(&pnd->lru_mtx);
	for (plp = tlp = pnd->lrurec; tlp != NULL; tlp = tlp->dnl_next) {
		if (tlp->dnl_rec->dn_cip.s_addr == dnp->dn_cip.s_addr) {
			if (tlp == plp) {
				pnd->lrurec = tlp->dnl_next;
			} else {
				plp->dnl_next = tlp->dnl_next;
			}
			tlp->dnl_next = NULL;
			break;
		}
		plp = tlp;
	}
	(void) mutex_unlock(&pnd->lru_mtx);
	if (tlp != NULL)
		dhcp_free_dd_list(pnd->dh, tlp);
}

/*
 * add_dnet_cache() - add a free entry back to the free dnet cache.
 *
 * Performance: this can greatly reduce the amount of work select_offer()
 * must perform.
 *
 * pnd - per net struct
 * dnlp - pointer to cached/modified entry.
 */
static void
add_dnet_cache(dsvc_dnet_t *pnd, dn_rec_list_t *dnlp)
{
	(void) mutex_lock(&pnd->free_mtx);
	dnlp->dnl_next = pnd->freerec;
	pnd->freerec = dnlp;
	(void) mutex_unlock(&pnd->free_mtx);
}

static char	unowned_net[] = "the DHCP server believes the IP address that"
	" corresponds to the requested host name belongs to a network not"
	" managed by the DHCP server.\n";
static char	unowned_addr[] = "the DHCP server believes the IP address that"
	" corresponds to the requested host name is not managed by the DHCP"
	" server.\n";

/*
 * Determine whether the requested IP address is available to the requesting
 * client.  To be so, its IP address must be managed by us, be on the ``right''
 * network and neither currently leased nor currently under offer to another
 * client.
 */
static boolean_t
addr_avail(dsvc_dnet_t *pnd, dsvc_clnt_t *pcd, dn_rec_list_t **dnlpp,
    struct in_addr req_ip, boolean_t isname)
{
	dn_rec_t	dn;
	dn_rec_list_t	*dnip;
	uint32_t	query;

	*dnlpp = NULL;
	/*
	 * first, check the ICMP list or offer list.
	 */
	if (isname) {
		if (pcd->off_ip.s_addr != req_ip.s_addr &&
		    check_offer(pnd, &req_ip) == B_FALSE) {
			/* Offered to someone else. Sorry. */
			dhcpmsg(LOG_DEBUG, "name_avail(F):"
			    "  check_offer failed\n");
			return (B_FALSE);
		}
	} else {
		if (update_offer(pcd, NULL, 0, &req_ip, B_TRUE) == B_FALSE) {
			/* Offered to someone else. Sorry. */
			if (isname) {
				dhcpmsg(LOG_DEBUG, "name_avail(F):"
				    "  check_other_offers failed\n");
			}
			return (B_FALSE);
		}
	}

	/*
	 * entry_available() searches for owner_ips
	 * query on DN_QCIP will suffice here
	 */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QCIP);
	dn.dn_cip.s_addr = ntohl(req_ip.s_addr);

	dnip = NULL;
	*dnlpp = dhcp_lookup_dd_classify(pnd, B_FALSE, query, -1, &dn,
	    (void **)&dnip, 0);
	dhcp_free_dd_list(pnd->dh, dnip);
	if (*dnlpp != NULL) {
		/*
		 * Ok, the requested IP exists. But is it available?
		 */
		if (!entry_available(pcd, (*dnlpp)->dnl_rec)) {
			dhcp_free_dd_list(pnd->dh, *dnlpp);
			*dnlpp = NULL;
			purge_offer(pcd, B_FALSE, B_TRUE);
			return (B_FALSE);
		}
	} else {
		if (isname)
			dhcpmsg(LOG_DEBUG, "name_avail(F):  %s", unowned_addr);
		else
			purge_offer(pcd, B_FALSE, B_TRUE);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Determine whether "name" is available.  To be so, it must either not have
 * a corresponding IP address, or its IP address must be managed by us and
 * neither currently leased nor currently under offer to a client.
 *
 * To determine this, we first attempt to translate the name to an address.
 * If no name-to-address translation exists, it's automatically available.
 * Otherwise, we next check for any outstanding offers. Finally, we look
 * at the flags in the corresponding per-network table to see whether the
 * address is currently leased.
 *
 * Upon successful completion, we also return the vetted IP address as a
 * value result parameter.
 */
static boolean_t
name_avail(char *name, dsvc_clnt_t *pcd, PKT_LIST *plp, dn_rec_list_t **dnlpp,
    ENCODE *ecp, struct in_addr **iap)
{
	struct		hostent h, *hp, *owner_hp;
	char		hbuf[NSS_BUFLEN_HOSTS];
	char		fqname [NS_MAXDNAME+1];
	char		owner [NS_MAXDNAME+1];
	int		err, ho_len;
	struct in_addr	ia, ma;
	dsvc_dnet_t	*pnd;
	boolean_t	isopen = B_FALSE;
	ENCODE		*ep;

	*dnlpp = NULL;
	/*
	 *	If possible, use a fully-qualified name to do the name-to-
	 *	address query.  The complication is that the domain name
	 *	with which to qualify the client's host name resides in a
	 *	dhcptab macro unavailable at the time of the DHCPOFFER.
	 *	ecp will be non-NULL if we may have the means to fully-qualify
	 *	the name given.
	 */
	if (strchr(name, '.') != NULL) {
		(void) strlcpy(fqname, name, sizeof (fqname));
		if (fqname[(strlen(fqname))-1] != '.')
			(void) strcat(fqname, ".");
	} else {
		/*
		 * Append '.' domain-name '.' to hostname.
		 * Note the use of the trailing '.' to avoid any surprises
		 * because of the ndots value (see resolv.conf(4) for more
		 * information about the latter).
		 *
		 * First see whether we can dredge up domain-name from the
		 * ENCODE list.
		 */
		if ((ecp != NULL) && ((ep = find_encode(ecp,
		    DSYM_STANDARD, CD_DNSDOMAIN)) != NULL)) {
			DHCP_OPT	*ho = plp->opts[CD_HOSTNAME];

			/*
			 *	name_avail() should never be called unless the
			 *	CD_HOSTNAME option is present in the client's
			 *	packet.
			 */
			assert(ho != NULL);
			ho_len = ho->len;
			if (ho->value[ho_len - 1] == '\0') {
				/* null at end of the hostname */
				ho_len = strlen((char *)ho->value);
			}

			if (qualify_hostname(fqname, (char *)ho->value,
			    (char *)ep->data, ho_len, ep->len) == -1)
				return (B_FALSE);

			dhcpmsg(LOG_DEBUG, "name_avail:  unqualified name\n"
			    "found CD_DNSDOMAIN and qualified:  %s\n", fqname);
		} else {
			/*
			 * No DNS domain in the ENCODE list, have to use
			 * local domain name.
			 */
			if ((resolv_conf.defdname == NULL) ||
			    (qualify_hostname(fqname, name,
			    resolv_conf.defdname,
			    strlen(name),
			    strlen(resolv_conf.defdname)) == -1))
				return (B_FALSE);

			dhcpmsg(LOG_DEBUG,
			    "name_avail:  unqualified name\n"
			    "qualified with local domain: %s\n", fqname);
		}
	}

	/*
	 *	Try a forward lookup on the requested name.
	 *	Consider the name available if we get a definitive
	 *	``name doesn't exist'' indication.
	 */
	hp = gethostbyname_r(fqname, &h, hbuf, sizeof (hbuf), &err);
	if (hp == NULL)
		if ((err == HOST_NOT_FOUND) || (err == NO_DATA)) {
			*iap = NULL;
			dhcpmsg(LOG_DEBUG,
			    "name_avail(T):  gethostbyname_r failed\n");
			return (B_TRUE);
		} else {
			dhcpmsg(LOG_DEBUG,
			    "name_avail(F):  gethostbyname_r failed, err %d\n",
			    err);
			return (B_FALSE);
		}

	/*
	 * Check that the address has not been leased to someone else.
	 * Bear in mind that there may be inactive A records in the DNS
	 * (since we don't delete them when a lease expires or is released).
	 * Try a reverse lookup on the address returned in hp.
	 * If the owner of this address is different to the requested name
	 * we can infer that owner is a stale A record.
	 */

	(void) memcpy(&ia, hp->h_addr, sizeof (struct in_addr));
	owner_hp = gethostbyaddr_r((char *)&ia, sizeof (struct in_addr),
	    AF_INET, &h, hbuf, sizeof (hbuf), &err);

	if (owner_hp == NULL) {
		/* If there's no PTR record the address can't be in use */
		if ((err == HOST_NOT_FOUND) || (err == NO_DATA)) {
			*iap = NULL;
			dhcpmsg(LOG_DEBUG,
			    "name_avail(T):  gethostbyaddr_r failed\n");
			return (B_TRUE);
		} else {
			dhcpmsg(LOG_DEBUG,
			    "name_avail(F):  gethostbyaddr_r failed\n");
			return (B_FALSE);
		}
	}

	/* If name returned is not a FQDN, qualify with local domain name */

	if (strchr(owner_hp->h_name, '.') != NULL) {
		(void) strlcpy(owner, owner_hp->h_name, sizeof (owner));
		if (owner[(strlen(owner))-1] != '.')
			(void) strcat(owner, ".");
	} else {
		if ((resolv_conf.defdname == NULL) ||
		    (qualify_hostname(owner, owner_hp->h_name,
		    resolv_conf.defdname,
		    strlen(owner_hp->h_name),
		    strlen(resolv_conf.defdname)) == -1))
			return (B_FALSE);

		dhcpmsg(LOG_DEBUG,
		    "name_avail: address owner qualified with %s\n",
		    resolv_conf.defdname);
	}

	if ((strncmp(owner, fqname, NS_MAXDNAME)) != 0) {
		/* Forward lookup found an inactive record - ignore it */
		*iap = NULL;
		dhcpmsg(LOG_DEBUG, "name_avail(T):  'A' record inactive: %s\n",
		    owner);
		return (B_TRUE);
	}

	/* Get pnd of the current client */
	pnd = pcd->pnd;
	get_netmask(&ia, &ma);
	if (pnd->net.s_addr != (ia.s_addr & ma.s_addr)) {
		/* get pnd of previous owner of the hostname */
		if (open_dnet(&pnd, &ia, &ma) != DSVC_SUCCESS) {
			/* we must not manage the net containing this address */
			dhcpmsg(LOG_DEBUG, "name_avail(F):  %s", unowned_net);
			return (B_FALSE);
		}
		isopen = B_TRUE;
	}

	/*
	 * Test that the address has not been offered to someone else.
	 */
	if (!addr_avail(pnd, pcd, dnlpp, ia, B_TRUE)) {
		if (isopen) {
			close_dnet(pnd, B_FALSE);
		}
		return (B_FALSE);
	}
	if (isopen)
		close_dnet(pnd, B_FALSE);

	/* LINTED */
	**iap = *((struct in_addr *)hp->h_addr);
	dhcpmsg(LOG_DEBUG, "name_avail(T)\n");
	return (B_TRUE);
}

static boolean_t
entry_available(dsvc_clnt_t *pcd, dn_rec_t *dnp)
{
	char		ntoab[INET_ADDRSTRLEN];
	boolean_t	isme = dnp->dn_cid_len == pcd->cid_len &&
	    memcmp(pcd->cid, dnp->dn_cid, pcd->cid_len) == 0;
	(void) inet_ntop(AF_INET, &(dnp->dn_sip), ntoab, sizeof (ntoab));

	if ((dnp->dn_flags & (DN_FMANUAL|DN_FUNUSABLE)) != 0) {
		dhcpmsg(LOG_DEBUG, "entry_available():"
		    "  %s is manually allocated or not usable\n",
		    ntoab);
		return (B_FALSE);
	}

	if (dnp->dn_cid_len != 0 && isme == B_FALSE &&
	    (dnp->dn_flags & (DN_FAUTOMATIC|DN_FBOOTP_ONLY))) {
		dhcpmsg(LOG_DEBUG, "entry_available():"
		    "  %s is a permanent address or reserved for BOOTP\n",
		    ntoab);
		return (B_FALSE);
	}

	if (dnp->dn_cid_len != 0 && isme == B_FALSE &&
	    (lease_t)time(NULL) < (lease_t)ntohl(dnp->dn_lease)) {
		dhcpmsg(LOG_DEBUG, "entry_available():"
		    "  lease on %s has not expired\n",
		    ntoab);
		return (B_FALSE);
	}

	if (match_ownerip(htonl(dnp->dn_sip.s_addr)) == NULL) {
		dhcpmsg(LOG_DEBUG, "entry_available():"
		    "  %s does not match owner_ip\n",
		    ntoab);
		return (B_FALSE);
	}

	/* Input IP is good. */
	return (B_TRUE);
}

static char	msft_classid[] = "MSFT ";
static char	no_domain[] = "name service update on behalf of client with ID"
" %s failed because requested name was not fully-qualified and no DNS"
" domain name was specified for this client in the dhcptab\n";

/*
 * Given a host name and IP address, try to do a host name update.
 */
static boolean_t
do_nsupdate(struct in_addr ia, ENCODE *ecp, PKT_LIST *plp)
{
	struct hostent	*hp;
	DHCP_OPT	*ho;
	ENCODE		*ep;
	char		class_idbuf[DSYM_CLASS_SIZE];
	int		puthostent_ret;

	/*
	 * hostent information is dynamically allocated so that threads spawned
	 * by dns_puthostent() will have access to it after the calling thread
	 * has returned.
	 */
	hp = (struct hostent *)smalloc(sizeof (struct hostent));
	hp->h_addr_list = (char **)smalloc(2 * sizeof (char **));
	hp->h_addr_list[1] = NULL;
	hp->h_addr = smalloc(sizeof (struct in_addr));
	hp->h_aliases = NULL;
	hp->h_addrtype = AF_INET;
	hp->h_length = sizeof (struct in_addr);
	/*
	 * Convert address to network order, as that's what hostent's are
	 * expected to be.
	 */
	/* LINTED */
	((struct in_addr *)hp->h_addr)->s_addr = htonl(ia.s_addr);

	/*
	 * Is the host name unqualified?  If so, try to qualify it.  If that
	 * can't be done, explain why the update won't be attempted.
	 */
	ho = plp->opts[CD_HOSTNAME];
	if (memchr(ho->value, '.', ho->len) == NULL) {
		/*
		 * See whether we can dredge up the DNS domain from the
		 * ENCODE list.
		 */
		if ((ep = find_encode(ecp, DSYM_STANDARD, CD_DNSDOMAIN)) !=
		    NULL) {
			char *fqname;
			int ho_len = ho->len;

			/*
			 *	We need room for
			 *
			 *	hostname len	+
			 *	strlen(".")	+
			 *	domainname len	+
			 *	strlen(".")	+
			 *	trailing '\0'
			 *
			 *	Note the use of the trailing '.' to avoid any
			 *	surprises because of the ndots value (see
			 *	resolv.conf(4) for more information about
			 *	the latter).
			 */
			if (ho->value[ho_len - 1] == '\0') {
				ho_len = strlen((char *)ho->value);
			}
			fqname = smalloc(ho_len + ep->len + 1 + 1 + 1);
			/* first copy host name, ... */
			(void) memcpy(fqname, ho->value, ho_len);
			/* then '.', ... */
			(void) memcpy(fqname + ho_len, ".", 1);
			/* ... then domain name, */
			(void) memcpy(fqname + ho_len + 1, ep->data, ep->len);
			/* then a trailing '.', ... */
			(void) memcpy(fqname + ho_len + ep->len + 1, ".", 1);
			/* no need to null-terminate - smalloc() did it */

			hp->h_name = fqname;
			dhcpmsg(LOG_DEBUG, "do_nsupdate:  unqualified name\n"
			    "found CD_DNSDOMAIN and qualified:  %s\n", fqname);
		} else {
			char cidbuf[BUFSIZ];

			(void) disp_cid(plp, cidbuf, sizeof (cidbuf));
			dhcpmsg(LOG_INFO, no_domain, cidbuf);
		}
	} else {
		hp->h_name = smalloc(ho->len + 1);
		(void) memcpy(hp->h_name, ho->value, ho->len);
		dhcpmsg(LOG_DEBUG, "do_nsupdate:  fully qualified name:  %s\n",
		    hp->h_name);
	}

	/* returns -1 or the number of name service updates done */
	puthostent_ret = dns_puthostent(hp, nsutimeout_secs);
	dhcpmsg(LOG_DEBUG, "do_nsupdate:  dns_puthostent returned %d\n",
	    puthostent_ret);
	if (puthostent_ret == -1) {
		return (B_FALSE);
	} else if (puthostent_ret == 0) {
		/*
		 *	dns_puthostent() didn't see any errors occur,
		 *	but no updates were done;  Microsoft clients
		 *	(i.e. clients with a Microsoft class ID) expect
		 *	it to succeed, so we lie to them.
		 */
		if (((get_class_id(plp, class_idbuf,
		    sizeof (class_idbuf))) != NULL) &&
		    (strncmp(msft_classid, class_idbuf,
		    sizeof (msft_classid)) == 0)) {
			dhcpmsg(LOG_DEBUG, "do_nsupdate:  class ID \"%s\"\n",
			    class_idbuf);
			return (B_TRUE);
		} else
			return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}
