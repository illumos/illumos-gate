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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains routines that are shared between the DHCP server
 * implementation and BOOTP server compatibility.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <stdarg.h>
#include <errno.h>
#include <alloca.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/syslog.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/dhcp.h>
#include <search.h>
#include <dhcp_symbol.h>
#include "dhcpd.h"
#include "per_dnet.h"
#include "interfaces.h"
#include <locale.h>
#include <resolv.h>

/*
 * Get the client id. Sets cid and len.
 */
void
get_clnt_id(PKT_LIST *plp, uchar_t *cid, int cidlen,  uchar_t *len)
{
	DHCP_OPT *optp = plp->opts[CD_CLIENT_ID];

	/*
	 * If the DHCP client specified the client id option, use that,
	 * otherwise use the client's hardware type and hardware address.
	 */
	if (plp->opts[CD_DHCP_TYPE] != NULL && optp != NULL) {
		/* DHCP client w/ client id */
		if (cidlen < optp->len)
			*len = (uchar_t)cidlen;
		else
			*len = optp->len;
		(void) memcpy(cid, optp->value, *len);
	} else {
		/* BOOTP client or DHCP client w/o client id. */
		*cid++ = plp->pkt->htype;
		*len = plp->pkt->hlen + 1;
		if (cidlen < *len)
			*len = cidlen;
		(void) memcpy(cid, plp->pkt->chaddr, *len);
	}
}

/*
 * Return a string representing an ASCII version of the client_id.
 */
char *
disp_cid(PKT_LIST *plp, char *bufp, int len)
{
	DHCP_OPT	*optp = plp->opts[CD_CLIENT_ID];
	uchar_t	*cp;
	uchar_t cplen;
	uint_t tlen;

	if (optp != (DHCP_OPT *)0) {
		cp =  optp->value;
		cplen = optp->len;
	} else {
		cp = plp->pkt->chaddr;
		cplen =  plp->pkt->hlen;
	}

	tlen = len;
	(void) octet_to_hexascii(cp, cplen, bufp, &tlen);
	return (bufp);
}

/*
 * Based on the contents of the PKT_LIST structure for an incoming
 * packet, determine the net address and subnet mask identifying the
 * dhcp-network database. This centralizes choices that were formerly
 * made in the specific protocol routines.
 */
void
determine_network(IF *ifp, PKT_LIST *plp, struct in_addr *netp,
    struct in_addr *subp)
{
	/*
	 * For BOOTP, REQUEST, RELEASE, and INFORM packets, trust client's
	 * notion of IP address if ciaddr is set. Use it to figure out correct
	 * dhcp-network.
	 */
	netp->s_addr = plp->pkt->ciaddr.s_addr;
	if (netp->s_addr != htonl(INADDR_ANY) &&
	    (plp->opts[CD_DHCP_TYPE] == NULL ||
	    (*plp->opts[CD_DHCP_TYPE]->value == REQUEST ||
	    *plp->opts[CD_DHCP_TYPE]->value == RELEASE ||
	    *plp->opts[CD_DHCP_TYPE]->value == INFORM))) {
		/*
		 * Calculate client's default net mask, consult netmasks
		 * database to see if net is further subnetted. Use resulting
		 * subnet mask with client's address to produce dhcp-network
		 * database name.
		 */
		get_netmask(netp, subp);
	} else
		netp->s_addr = htonl(INADDR_ANY);

	/*
	 * If no trusted IP address, examine giaddr.
	 */
	if (netp->s_addr == htonl(INADDR_ANY)) {
		if (plp->pkt->giaddr.s_addr != htonl(INADDR_ANY)) {
			netp->s_addr = plp->pkt->giaddr.s_addr;
			/*
			 * Packet received thru a relay agent. Calculate the
			 * net's address using subnet mask and giaddr.
			 */
			get_netmask(netp, subp);
		} else {
			/* Locally connected net. */
			netp->s_addr = ifp->addr.s_addr;
			subp->s_addr = ifp->mask.s_addr;
		}
	}
}

struct netmask_node;

typedef struct netmask_node {
	struct in_addr net;			/* cached network */
	struct in_addr mask;			/* cached netmask */
} NNODE;

static void		*nroot;			/* root of netmask tree */
static time_t		nroot_mtime;		/* time for dynamic free */
static time_t		nroot_stamp;		/* time for dynamic free */
static rwlock_t		nroot_rwlock;		/* synchronization variable */

/*
 * nm_cmp() - determine whether key n1 is within range of net/mask n2
 */
static int
nm_cmp(const void *n1, const void *n2)
{
	void *v1 = (void *) (((NNODE *)n1)->net.s_addr &
	    ((NNODE *)n2)->mask.s_addr);
	void *v2 = (void *) ((NNODE *)n2)->net.s_addr;

	return (memcmp(&v1, &v2, sizeof (struct in_addr)));
}

/*
 * Given a network-order address, calculate client's default net mask.
 * Consult local cache, then netmasks database to see if net is further
 * subnetted. We'll only snag the first netmask that matches our criteria.
 */
void
get_netmask(struct in_addr *n_addrp, struct in_addr *s_addrp)
{
	NNODE key;
	NNODE *node;
	NNODE **ret;
	struct in_addr haddr;

	assert(n_addrp != NULL && s_addrp != NULL);

	/*
	 * First check locally maintained, incomplete cache.
	 */
	(void) rw_rdlock(&nroot_rwlock);
	if (nroot != NULL) {
		/* Delete expired tree. */
		if (nroot_mtime != reinit_time || nroot_stamp < time(NULL)) {
			(void) rw_unlock(&nroot_rwlock);
			(void) rw_wrlock(&nroot_rwlock);
			while ((ret = (NNODE **)nroot) != NULL) {
				node = *ret;
				(void) tdelete(node, &nroot, nm_cmp);
				free(node);
			}
			nroot_mtime = reinit_time;
			nroot_stamp = time(NULL) + DHCP_NSS_TIME;
		} else {
			key.net.s_addr = ntohl(n_addrp->s_addr);
			key.mask.s_addr = INADDR_ANY;
			if ((ret = (NNODE **)tfind((void *)&key,
			    (void * const *)&nroot, nm_cmp)) != NULL) {
				s_addrp->s_addr = htonl((*ret)->mask.s_addr);
				(void) rw_unlock(&nroot_rwlock);
				return;
			}
		}
	}

	/*
	 * Note: workaround for 4336124: single-thread access to
	 * nss search routines to avoid getting incorrect results.
	 */
	node = (NNODE *)smalloc(sizeof (NNODE));

	/* Convert to and from host order. */
	haddr.s_addr = ntohl(n_addrp->s_addr);
	get_netmask4(&haddr, s_addrp);
	node->mask.s_addr = s_addrp->s_addr;
	node->net.s_addr = haddr.s_addr & node->mask.s_addr;
	s_addrp->s_addr = htonl(s_addrp->s_addr);

	/* While inserting check that another insert has not occurred. */
	ret = (NNODE **)tsearch((void *)node, &nroot, nm_cmp);
	if (ret != NULL && *ret != node)
		free(node);

	(void) rw_unlock(&nroot_rwlock);
}

/*
 * This function is charged with loading the options field with the
 * configured and/or asked for options. Note that if the packet is too
 * small to fit the options, then option overload is enabled.
 *
 * Note that the caller is expected to free any allocated ENCODE lists,
 * with the exception of locally-allocated lists in the case where ecp is
 * NULL, but vecp is not. In this case, the resultant ecp list (ecp == tvep)
 * is freed locally.
 *
 * Returns: The actual size of the utilized packet buffer.
 */

int
load_options(int flags, PKT_LIST *c_plp, PKT *r_pktp, int replen, uchar_t *optp,
    ENCODE *ecp, ENCODE *vecp)
{
	ENCODE		*ep, *prevep, *tvep = NULL;
	ENCODE		*router_ecp = NULL;
	PKT		*c_pktp = c_plp->pkt;
	uchar_t		cat;
	ushort_t	code;
	uint_t		vend_len;
	uchar_t		len, *vp, *vdata, *data, *endp, *main_optp, *opt_endp;
	uchar_t		overload = DHCP_OVRLD_CLR;
	uchar_t		using_overload = DHCP_OVRLD_CLR;
	boolean_t	srv_using_file = B_FALSE, clnt_ovrld_file = B_FALSE;
	boolean_t	echo_clnt_file;

	if (c_plp->opts[CD_OPTION_OVERLOAD] != NULL &&
	    *c_plp->opts[CD_OPTION_OVERLOAD]->value & DHCP_OVRLD_FILE)
		clnt_ovrld_file = B_TRUE;

	opt_endp = (uchar_t *)((uint_t)r_pktp->options + replen -
	    BASE_PKT_SIZE);
	endp = opt_endp;

	/*
	 * We handle vendor options by fabricating an ENCODE of type
	 * CD_VENDOR_SPEC, and setting its datafield equal to vecp.
	 *
	 * We assume we've been handed the proper class list.
	 */
	if (vecp != NULL && (flags & DHCP_NON_RFC1048) == 0) {
		vend_len = 0;
		for (ep = vecp, vend_len = 0; ep != NULL; ep = ep->next)
			vend_len += (ep->len + 2);

		if (vend_len != 0) {
			if (vend_len > (uint_t)0xff) {
				dhcpmsg(LOG_WARNING,
				    "Warning: Too much vendor data (> 255) to "
				    "encapsulate within option %d.\n",
				    CD_VENDOR_SPEC);
				vend_len = (uint_t)0xff;
			}
			vdata = (uchar_t *)smalloc(vend_len);

			for (vp = vdata, tvep = vecp; tvep != NULL &&
			    (uchar_t *)(vp + tvep->len + 2) <= &vdata[vend_len];
			    tvep = tvep->next) {
				*vp++ = tvep->code;
				*vp++ = tvep->len;
				(void) memcpy(vp, tvep->data, tvep->len);
				vp += tvep->len;
			}

			/* this make_encode *doesn't* copy data */
			tvep = make_encode(DSYM_VENDOR, CD_VENDOR_SPEC,
			    vend_len, vdata, ENC_DONT_COPY);

			/* Tack it on the end of standard list. */
			for (ep = prevep = ecp; ep != NULL; ep = ep->next)
				prevep = ep;
			if (prevep != NULL)
				prevep->next = tvep;
			else
				ecp = tvep;
		}
	}

	/*
	 * Scan the options first to determine if we could potentially
	 * option overload.
	 */
	if (flags & DHCP_DHCP_CLNT) {
		for (ep = ecp; ep != NULL; ep = ep->next) {
			if (ep->category == DSYM_FIELD)
				switch (ep->code) {
				case CD_SNAME:
					overload |= DHCP_OVRLD_SNAME;
					break;
				case CD_BOOTFILE:
					overload |= DHCP_OVRLD_FILE;
					srv_using_file = B_TRUE;
					break;
				}
		}
	} else {
		/* BOOTP uses these fields for fixed parameters, no overload */
		overload = DHCP_OVRLD_ALL;
	}

	if (c_pktp->file[0] != '\0' && !clnt_ovrld_file && !srv_using_file) {
		/*
		 * simply echo back client's boot file, and don't overload.
		 * if CD_BOOTPATH is set, we'll simply rewrite the r_pktp
		 * file field to include it along with the client's requested
		 * name during the load pass through the internal options.
		 * Here we let the overload code know we're not to overload
		 * the file field.
		 */
		(void) memcpy(r_pktp->file, c_pktp->file,
		    sizeof (r_pktp->file));
		overload |= DHCP_OVRLD_FILE;
		echo_clnt_file = B_TRUE;
	} else
		echo_clnt_file = B_FALSE;

	/* Now actually load the options! */
	for (ep = ecp; ep != NULL; ep = ep->next) {
		cat = ep->category;
		code = ep->code;
		len = ep->len;
		data = ep->data;

		/*
		 * non rfc1048 clients can only get packet fields and
		 * the CD_BOOTPATH internal pseudo opt, which only potentially
		 * affects the file field.
		 */
		if ((flags & DHCP_NON_RFC1048) &&
		    !(cat == DSYM_FIELD || (cat == DSYM_INTERNAL &&
		    code == CD_BOOTPATH))) {
			continue;
		}

		if ((flags & DHCP_SEND_LEASE) == 0 &&
		    cat == DSYM_STANDARD &&
		    (code == CD_T1_TIME || code == CD_T2_TIME ||
		    code == CD_LEASE_TIME)) {
			continue;
		}

		/* standard and site options */
		if (cat == DSYM_STANDARD || cat == DSYM_SITE ||
		    cat == DSYM_VENDOR) {

			uchar_t	*need_optp;

			/*
			 * This horrible kludge is necessary because the DHCP
			 * options RFCs require that the subnet option MUST
			 * precede the router option.  To accomplish this, we
			 *
			 *	inspect each of the standard options, waiting
			 *	for CD_ROUTER to turn up (if it never does,
			 *	no special handling is needed)
			 *
			 *	search the remaining options for CD_SUBNETMASK
			 *	If it occurs, we
			 *		set router_ecp to indicate where to find
			 *		the router option's values that we have
			 *		not yet emitted
			 *
			 *		reinitialize code, len, and data to emit
			 *		the CD_SUBNETMASK option now
			 *
			 *		when CD_SUBNETMASK is encountered, we
			 *		reinitialize code, len, and data to emit
			 *		the CD_ROUTER option
			 */
			if ((cat == DSYM_STANDARD) && (code == CD_ROUTER)) {
				ENCODE *tp;

				for (tp = ep->next; tp != NULL; tp = tp->next)
					if ((tp->category == DSYM_STANDARD) &&
					    (tp->code == CD_SUBNETMASK)) {
						router_ecp = ep;
						code = CD_SUBNETMASK;
						len = tp->len;
						data = tp->data;
					}
			} else if ((cat == DSYM_STANDARD) &&
			    (code == CD_SUBNETMASK) && (router_ecp != NULL)) {
				code = CD_ROUTER;
				len = router_ecp->len;
				data = router_ecp->data;
			}

			/*
			 * Keep an eye on option field. Option overload. Note
			 * that we need to keep track of the space necessary
			 * to place the Overload option in the options section
			 * (that's the 3 octets below.) The 2 octets cover the
			 * necessary code and len portion of the payload.
			 */
			if (using_overload == DHCP_OVRLD_CLR) {
				/* 2 for code/len, 3 for overload option */
				need_optp = &optp[len + 2 + 3];
			} else {
				/* Just need 2 for code/len */
				need_optp = &optp[len + 2];
			}
			if (need_optp > endp) {
				/*
				 * If overload is not possible, we will
				 * keep going, hoping to find an option
				 * that will fit in the remaining space,
				 * rather than just give up.
				 */
				if (overload != DHCP_OVRLD_ALL) {
					if (using_overload == DHCP_OVRLD_CLR) {
						*optp++ = CD_OPTION_OVERLOAD;
						*optp++ = 1;
						main_optp = optp;
					} else {
						if (optp < endp)
							*optp = CD_END;
						overload |= using_overload;
					}
				}
				switch (overload) {
				case DHCP_OVRLD_CLR:
					/* great, can use both */
					/* FALLTHRU */
				case DHCP_OVRLD_FILE:
					/* Can use sname. */
					optp = r_pktp->sname;
					endp = r_pktp->file;
					using_overload |= DHCP_OVRLD_SNAME;
					break;
				case DHCP_OVRLD_SNAME:
					/* Using sname, can use file. */
					optp = r_pktp->file;
					endp = r_pktp->cookie;
					using_overload |= DHCP_OVRLD_FILE;
					break;
				}
			}
			/* Skip the option if it's too long to fit */
			if (len < (endp - optp - 1)) {
				/* Load options. */
				*optp++ = (uchar_t)code;
				*optp++ = len;
				(void) memcpy(optp, data, len);
				optp += len;
			}
		} else if (cat == DSYM_FIELD) {
			/* packet field pseudo options */
			switch (code) {
			case CD_SIADDR:
				/*
				 * Configuration includes Boot server addr
				 */
				(void) memcpy((void *)&r_pktp->siaddr, data,
				    len);
				break;
			case CD_SNAME:
				/*
				 * Configuration includes Boot server name
				 */
				(void) memcpy(r_pktp->sname, data, len);
				break;
			case CD_BOOTFILE:
				/*
				 * Configuration includes boot file.
				 * Always authoritative.
				 */
				(void) memset(r_pktp->file, 0,
				    sizeof (r_pktp->file));
				(void) memcpy(r_pktp->file, data, len);
				break;
			default:
				dhcpmsg(LOG_ERR,
				    "Unsettable DHCP packet field: %d\n", code);
				break;
			}
		} else if (cat == DSYM_INTERNAL) {
			/* Internal server pseudo options */
			switch (code) {
			case CD_BOOTPATH:
				/*
				 * Prefix for boot file. Only used if
				 * client provides bootfile and server doesn't
				 * specify one. Prepended on client's bootfile
				 * value. Otherwise ignored.
				 */
				if (echo_clnt_file) {
					uchar_t alen, flen;

					alen = sizeof (c_pktp->file);
					flen = alen - 1;
					if (c_pktp->file[flen] != '\0')
						flen++;
					else
						flen = strlen(
						    (char *)c_pktp->file);

					if ((len + flen + 1) > alen) {
						char *bp = alloca(alen + 1);
						char *bf = alloca(alen + 1);
						(void) memcpy(bp, data, len);
						bp[len] = '\0';
						(void) memcpy(bf, c_pktp->file,
						    flen);
						bf[flen] = '\0';
						dhcpmsg(LOG_ERR,
						    "BootPath(%1$s) + "
						    "BootFile(%2$s) too "
						    "long: %3$d > %4$d\n",
						    bp, bf, (len + flen), alen);
					} else {
						(void) memcpy(r_pktp->file,
						    data, len);
						r_pktp->file[len] = '/';
						(void) memcpy(
						    &r_pktp->file[len + 1],
						    c_pktp->file, flen);
					}
				}
				break;
			case CD_BOOL_HOSTNAME:
				/* FALLTHRU */
			case CD_BOOL_LEASENEG:
				/* FALLTHRU */
			case CD_BOOL_ECHO_VCLASS:
				/*
				 * These pseudo opts have had their
				 * affect elsewhere, such as dhcp.c.
				 */
				break;
			default:
				dhcpmsg(LOG_ERR,
				    "Unknown Internal pseudo opt: %d\n", code);
				break;
			}
		} else {
			dhcpmsg(LOG_ERR,
			    "Unrecognized option with code: %d %d\n", cat,
			    code);
		}
	}

	if (using_overload != DHCP_OVRLD_CLR) {
		*main_optp++ = using_overload;
		if (optp < endp)
			*optp = CD_END;
	} else
		main_optp = optp;	/* no overload */

	if (main_optp < opt_endp)
		*main_optp++ = CD_END;

	if (ecp == tvep)
		free_encode_list(ecp);

	return (BASE_PKT_SIZE + (uint_t)(main_optp - r_pktp->options));
}

/*
 * Reinitialize the dhcptab database, as a result of timeout or
 * user signal. Note: if_head_mtx cannot be held by caller.
 */
void *
reinitialize(void *arg)
{
	int	totpkts;
	IF	*ifp;
	thread_t *tp = (thread_t *)arg;
	int err;

	/*
	 * Got a signal to reinitialize
	 */

	if (verbose)
		dhcpmsg(LOG_INFO, "Reinitializing server\n");

	if (!no_dhcptab) {
		if (checktab() != 0) {
			dhcpmsg(LOG_WARNING,
			    "WARNING: Cannot access dhcptab.\n");
		} else {
			if ((err = readtab(PRESERVE_DHCPTAB)) != 0) {
				dhcpmsg(LOG_ERR,
				    "Error reading dhcptab.\n");
				return ((void *)err);
			}
		}
	}

	/*
	 * Drop all pending offers, display interface statistics.
	 */
	if (verbose) {
		(void) mutex_lock(&if_head_mtx);
		for (ifp = if_head, totpkts = 0; ifp != NULL; ifp = ifp->next) {
			(void) mutex_lock(&ifp->ifp_mtx);
			disp_if_stats(ifp);
			totpkts += ifp->received;
			(void) mutex_unlock(&ifp->ifp_mtx);
		}
		(void) mutex_unlock(&if_head_mtx);

		dhcpmsg(LOG_INFO,
		    "Total Packets received on all interfaces: %d\n", totpkts);
		dhcpmsg(LOG_INFO, "Server reinitialized.\n");
	}

	/* Default domain may have changed */
	if (res_ninit(&resolv_conf) == -1)
		dhcpmsg(LOG_ERR, "Cannot acquire resolver configuration.\n");

	/* Release reinitialization thread */
	reinit_time = time(NULL);
	*tp = NULL;
	thr_exit(NULL);

	return (NULL);
}
