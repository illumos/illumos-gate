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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stropts.h>
#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <netinet/dhcp.h>
#include <dhcp_symbol.h>
#include "dhcpd.h"
#include "per_dnet.h"
#include "interfaces.h"
#include <v4_sum_impl.h>
#include <locale.h>

static int socksize = 64 * 1024;	/* large socket window size for data */
static const uchar_t magic_cookie[] = BOOTMAGIC;
static void disp_if(IF *);

/*
 * Network interface configuration. This file contains routines which
 * handle the input side of the DHCP/BOOTP/Relay agent. Multiple interfaces
 * are handled by identifying explicitly each interface, and creating a
 * stream for each. If only one usable interface exists, then a "normal"
 * UDP socket is used for simplicity's sake.
 */

IF	*if_head;		/* head of interfaces list */
mutex_t	if_head_mtx;		/* mutex for adding/deleting IF list entries */
char	*interfaces;		/* user specified interfaces */
static int	num_interfaces;	/* # of usable interfaces on the system */

static char *
dsrvr_socktype(dsrvr_socktype_t stype)
{
	char *rp;

	switch (stype) {
	case DSRVR_LBCAST:
		rp = "limited broadcast";
		break;
	case DSRVR_DBCAST:
		rp = "directed broadcast";
		break;
	case DSRVR_UCAST:
		rp = "unicast";
		break;
	}
	return (rp);
}

/*
 * Given two packets, match them based on BOOTP header operation, packet len,
 * hardware type, flags, ciaddr, DHCP type, client id, or chaddr.
 * Returns B_TRUE if they match, B_FALSE otherwise.
 */
static boolean_t
match_plp(PKT_LIST *alp, PKT_LIST *blp)
{
	DHCP_OPT	*a, *b;

	assert(alp != NULL && blp != NULL);

	if (alp->pkt->op != blp->pkt->op ||
	    alp->len != alp->len ||
	    alp->pkt->htype != blp->pkt->htype ||
	    alp->pkt->flags != blp->pkt->flags ||
	    alp->pkt->ciaddr.s_addr != blp->pkt->ciaddr.s_addr)
		return (B_FALSE);	/* not even the same BOOTP type. */

#ifdef DEBUG
	if (alp->pkt->giaddr.s_addr != blp->pkt->giaddr.s_addr) {
		dhcpmsg(LOG_DEBUG,
		    "%04d match_plp: giaddr mismatch on 0x%x, 0x%x\n",
		    thr_self());
	}
#endif	/* DEBUG */

	a = alp->opts[CD_DHCP_TYPE];
	b = blp->opts[CD_DHCP_TYPE];
	if (a == NULL && b == NULL) {
		/* bootp */
		if (memcmp(alp->pkt->chaddr, blp->pkt->chaddr,
		    alp->pkt->hlen) == 0)
			return (B_TRUE);
	} else if (a != NULL && b != NULL) {
		if (a->value[0] == b->value[0]) {
			/* dhcp - packet types match. */
			a = alp->opts[CD_CLIENT_ID];
			b = blp->opts[CD_CLIENT_ID];
			if (a != NULL && b != NULL) {
				if (memcmp(a->value, b->value, a->len) == 0)
					return (B_TRUE);
			} else {
				if (memcmp(alp->pkt->chaddr, blp->pkt->chaddr,
				    alp->pkt->hlen) == 0)
					return (B_TRUE);
			}
		}
	}
	return (B_FALSE);
}

/*
 * Given a packet, searches for a later packet in the
 * interface's client list. If the search is successful, the argument
 * packet is deleted, and the later packet is returned with the appropriate
 * fields/options modified.
 *
 * Matches are based on match_plp(). The list is scanned until the final packet
 * which "matches" is found. The last match replaces
 * the argument plp. Duplicates are deleted.
 *
 * General Notes: After the first candidate is found, the list is checked to
 * the tail of the list for other matches. For each packet  which is deleted.
 * the duplicate statistic is incremented for each one. If no candidate is
 * found, then the argument plp is returned.
 *
 * Caveats: What about length and contents of packets? By definition, a
 * client is not supposed to be altering this between frames, so we should
 * be ok. Since the argument plp may be destroyed, it is assumed to be
 * detached.
 */
PKT_LIST *
refresh_pktlist(dsvc_clnt_t *pcd, PKT_LIST *plp)
{
	PKT_LIST	*wplp, *tplp, *retplp = NULL;
	IF		*ifp = pcd->ifp;

	assert(MUTEX_HELD(&pcd->pkt_mtx));

	wplp = pcd->pkthead;
	while (wplp != NULL) {
		if (match_plp(plp, wplp)) {
			pcd->pending--;

			(void) mutex_lock(&ifp->ifp_mtx);
			ifp->duplicate++;
			(void) mutex_unlock(&ifp->ifp_mtx);

			/*
			 * Note that tplp, retplp can be synonyms for
			 * wplp. The synonyms are used because moldy plp's
			 * will be nuked, and the plp to return will be
			 * detached.
			 */
			tplp = wplp;
			wplp = wplp->next;

			if (retplp != NULL) {
				/* moldy duplicates */
				free_plp(retplp);
			}
			retplp = tplp;
			detach_plp(pcd, retplp);
		} else {
			wplp = wplp->next;
		}
	}

	if (retplp == NULL)
		retplp = plp;
	else {
		if (debug) {
			dhcpmsg(LOG_DEBUG,
			    "%04d: Refreshed (0x%p) to (0x%p)\n",
			    thr_self(), (void *)plp, (void *)retplp);
		}
		free_plp(plp);
	}

	return (retplp);
}

/*
 * Queries the IP transport layer for configured interfaces. Those that
 * are acceptable for use by our daemon have these characteristics:
 *
 *	Not loopback
 *	Is UP
 *
 * Sets num_interfaces global to number of valid, selected interfaces.
 *
 * Returns: 0 for success, the appropriate errno on fatal failure.
 *
 * Notes: Code gleaned from the in.rarpd, solaris 2.2.
 */
static int
find_interfaces(void)
{
	int			i, k, ip, reqsize, numifs;
	boolean_t		found;
	ushort_t		mtu_tmp;
	struct ifreq		*reqbuf, *ifr;
	struct ifconf		ifconf;
	IF			*ifp, *if_tail;
	struct sockaddr_in	*sin;
	char			**user_if;
	ENCODE 			*hecp;

	if ((ip = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		dhcpmsg(LOG_ERR, "Error opening socket: %s\n",
		    strerror(errno));
		return (1);
	}

	if (ioctl(ip, SIOCGIFNUM, &numifs) < 0) {
		dhcpmsg(LOG_WARNING,
		    "Error discovering number of network interfaces: %s\n",
		    strerror(errno));
		(void) close(ip);
		return (1);
	}

	reqsize = numifs * sizeof (struct ifreq);
	reqbuf = (struct ifreq *)smalloc(reqsize);

	ifconf.ifc_len = reqsize;
	ifconf.ifc_buf = (caddr_t)reqbuf;

	if (ioctl(ip, SIOCGIFCONF, &ifconf) < 0) {
		dhcpmsg(LOG_ERR,
		    "Error getting network interface information: %s\n",
		    strerror(errno));
		free(reqbuf);
		(void) close(ip);
		return (1);
	}

	/*
	 * Verify that user specified interfaces are valid.
	 */
	user_if = (char **)smalloc(numifs * sizeof (char *));
	if (interfaces != NULL) {
		for (i = 0; i < numifs; i++) {
			user_if[i] = strtok(interfaces, ",");
			if (user_if[i] == NULL)
				break;		/* we're done */
			interfaces = NULL; /* for next call to strtok() */

			for (found = B_FALSE, ifr = ifconf.ifc_req;
			    ifr < &ifconf.ifc_req[ifconf.ifc_len /
			    sizeof (struct ifreq)]; ifr++) {
				if (strcmp(user_if[i], ifr->ifr_name) == 0) {
					found = B_TRUE;
					break;
				}
			}
			if (!found) {
				dhcpmsg(LOG_ERR,
				    "Invalid network interface:  %s\n",
				    user_if[i]);
				free(reqbuf);
				free(user_if);
				(void) close(ip);
				return (1);
			}
		}
		if (i < numifs)
			user_if[i] = NULL;
	} else
		user_if[0] = NULL;

	/*
	 * For each interface, build an interface structure. Ignore any
	 * LOOPBACK or down interfaces.
	 */
	if_tail = if_head = NULL;
	for (ifr = ifconf.ifc_req;
	    ifr < &ifconf.ifc_req[ifconf.ifc_len / sizeof (struct ifreq)];
	    ifr++) {
		if (ioctl(ip, SIOCGIFFLAGS, ifr) < 0) {
			dhcpmsg(LOG_ERR,
"Error encountered getting interface: %s flags: %s\n",
			    ifr->ifr_name, strerror(errno));
			continue;
		}
		if ((ifr->ifr_flags & IFF_LOOPBACK) ||
		    !(ifr->ifr_flags & IFF_UP))
			continue;

		num_interfaces++;	/* all possible interfaces counted */

		/*
		 * If the user specified a list of interfaces,
		 * we'll only consider the ones specified.
		 */
		if (user_if[0] != NULL) {
			for (i = 0; i < numifs; i++) {
				if (user_if[i] == NULL)
					break; /* skip this interface */
				if (strcmp(user_if[i], ifr->ifr_name) == 0)
					break;	/* user wants this one */
			}
			if (i == numifs || user_if[i] == NULL)
				continue;	/* skip this interface */
		} else if (strchr(ifr->ifr_name, ':') != NULL)
			continue;	/* skip virtual interfaces */

		ifp = (IF *)smalloc(sizeof (IF));
		(void) strcpy(ifp->nm, ifr->ifr_name);

		ifp->ifceno = if_nametoindex(ifp->nm);
		ifp->flags = ifr->ifr_flags;
		for (k = 0; k < DSRVR_NUM_DESC; k++)
			ifp->descs[k] = -1;

		/*
		 * Broadcast address. Not valid for POINTOPOINT
		 * connections.
		 */
		if ((ifp->flags & IFF_POINTOPOINT) == 0) {
			if (ifp->flags & IFF_BROADCAST) {
				if (ioctl(ip, SIOCGIFBRDADDR, ifr) < 0) {
					dhcpmsg(LOG_ERR, "Error encountered \
getting interface: %s broadcast address: %s\n", ifp->nm, strerror(errno));
					free(ifp);
					num_interfaces--;
					continue;
				}
				/* LINTED [alignment ok] */
				sin = (struct sockaddr_in *)&ifr->ifr_addr;
				ifp->bcast = sin->sin_addr;
			} else
				ifp->bcast.s_addr = htonl(INADDR_ANY);

			hecp = make_encode(DSYM_STANDARD, CD_BROADCASTADDR,
			    sizeof (struct in_addr), &ifp->bcast,
			    ENC_COPY);
			replace_encode(&ifp->ecp, hecp, ENC_DONT_COPY);
		}

		/* Subnet mask */
		if (ioctl(ip, SIOCGIFNETMASK, ifr) < 0) {
			dhcpmsg(LOG_ERR, "Error encountered getting \
interface: %s netmask: %s\n", ifp->nm, strerror(errno));
			free_encode_list(ifp->ecp);
			free(ifp);
			num_interfaces--;
			continue;
		}
		/* LINTED [alignment ok] */
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		ifp->mask = sin->sin_addr;
		hecp = make_encode(DSYM_STANDARD, CD_SUBNETMASK,
		    sizeof (struct in_addr), &ifp->mask, ENC_COPY);
		replace_encode(&ifp->ecp, hecp, ENC_DONT_COPY);

		/* Address */
		if (ioctl(ip, SIOCGIFADDR, ifr) < 0) {
			dhcpmsg(LOG_ERR, "Error encountered getting \
interface: %s address: %s\n", ifp->nm,  strerror(errno));
			free_encode_list(ifp->ecp);
			free(ifp);
			num_interfaces--;
			continue;
		}
		/* LINTED [alignment ok] */
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		ifp->addr = sin->sin_addr;

		/* MTU */
		if (ioctl(ip, SIOCGIFMTU, ifr) < 0) {
			dhcpmsg(LOG_ERR, "Error encountered getting \
interface: %s MTU: %s\n", ifp->nm, strerror(errno));
			free_encode_list(ifp->ecp);
			free(ifp);
			num_interfaces--;
			continue;
		}

		ifp->mtu = ifr->ifr_metric;
		mtu_tmp = htons(ifp->mtu);
		hecp = make_encode(DSYM_STANDARD, CD_MTU, 2,
		    &mtu_tmp, ENC_COPY);
		replace_encode(&ifp->ecp, hecp, ENC_DONT_COPY);

		/* Attach to interface list */
		if (!if_tail) {
			(void) mutex_init(&if_head_mtx, USYNC_THREAD, 0);
			(void) mutex_lock(&if_head_mtx);
			if_tail = if_head = ifp;
			(void) mutex_unlock(&if_head_mtx);
		} else {
			(void) mutex_lock(&if_head_mtx);
			if_tail->next = ifp;
			if_tail = ifp;
			(void) mutex_unlock(&if_head_mtx);
		}
	}

	free(reqbuf);
	free(user_if);
	(void) close(ip);

	if (if_head == NULL) {
		num_interfaces = 0;
		dhcpmsg(LOG_ERR, "Cannot find any valid interfaces.\n");
		(void) mutex_destroy(&if_head_mtx);
		return (EINVAL);
	}
	return (0);
}

/*
 * Destroy an *uninitialized* IF structure - returns next ifp.
 */
static IF *
zap_ifp(IF **ifp_prevpp, IF *ifp)
{
	IF	*tifp;

	assert(MUTEX_HELD(&if_head_mtx));

	if (*ifp_prevpp == ifp) {
		if_head = ifp->next;
		*ifp_prevpp = if_head;
	} else
		(*ifp_prevpp)->next = ifp->next;

	tifp = ifp->next;

	free(ifp);

	return (tifp);
}

/*
 * Monitor thread function. Poll on interface descriptors. Add valid BOOTP
 * packets to interfaces PKT_LIST.
 *
 * Because the buffer will potentially contain the ip/udp headers, we flag
 * this by setting the 'offset' field to the length of the two headers so that
 * free_plp() can "do the right thing"
 *
 * Monitor the given interface. Signals are handled by sig_client thread.
 *
 * We make some attempt to deal with marginal interfaces as follows. We
 * keep track of system errors (errors) and protocol errors (ifp->errors).
 * If we encounter more than DHCP_MON_SYSERRS in DHCP_MON_ERRINTVL,
 * then the interface thread will put itself to sleep for DHCP_MON_SLEEP
 * minutes.
 *
 * MT SAFE
 */
static void *
monitor_interface(void *argp)
{
	PKT_LIST		*plp, *tplp;
	IF			*ifp = (IF *)argp;
	int			errors, err, i;
	uint_t			verify_len;
	struct pollfd		pfd[DSRVR_NUM_DESC];
	struct strbuf		data;
	char 			cbuf[DN_MAX_CID_LEN], ntoab[INET_ADDRSTRLEN];
	time_t			err_interval;
	dn_rec_t		dn;
	dsvc_dnet_t		*pnd;
	dsvc_clnt_t		*pcd;
	struct in_addr		netaddr, subnetaddr;
	dsvc_pendclnt_t		*workp;
	int			open_ret;
	dsvc_thr_t		*freep;
	thread_t		tid;
	boolean_t		existing_allocation;

	if (debug) {
		dhcpmsg(LOG_DEBUG, "Monitor (%04d/%s) started...\n",
		    ifp->if_thread, ifp->nm);
	}

	if (verbose)
		disp_if(ifp);

	pfd[DSRVR_LBCAST].fd = ifp->descs[DSRVR_LBCAST];
	pfd[DSRVR_LBCAST].events = POLLIN | POLLPRI;
	pfd[DSRVR_DBCAST].fd = ifp->descs[DSRVR_DBCAST];
	pfd[DSRVR_DBCAST].events = POLLIN | POLLPRI;
	pfd[DSRVR_UCAST].fd = ifp->descs[DSRVR_UCAST];
	pfd[DSRVR_UCAST].events = POLLIN | POLLPRI;

	err_interval = time(NULL) + DHCP_MON_ERRINTVL;
	errors = 0;
	while (time_to_go == 0) {
		if (errors > DHCP_MON_SYSERRS) {
			if (time(NULL) < err_interval) {
				dhcpmsg(LOG_WARNING,
"Monitor (%04d/%s): Too many system errors (%d), pausing for %d minute(s)...\n",
				    ifp->if_thread, ifp->nm, errors,
				    DHCP_MON_SYSERRS);
				(void) sleep(DHCP_MON_SLEEP);
				err_interval = time(NULL) + DHCP_MON_ERRINTVL;
			}
			errors = 0;
		}
		pfd[DSRVR_LBCAST].revents = 0;
		pfd[DSRVR_DBCAST].revents = 0;
		pfd[DSRVR_UCAST].revents = 0;
		if (poll(&pfd[0], (nfds_t)DSRVR_NUM_DESC, INFTIM) < 0) {
			dhcpmsg(LOG_ERR,
			    "Monitor (%04d/%s) Polling error: (%s).\n",
			    ifp->if_thread, ifp->nm, strerror(errno));
			errors++;
			continue;
		}
		/*
		 * See if we are to exit. We can't be holding any locks...
		 */
		(void) mutex_lock(&ifp->ifp_mtx);
		if (ifp->thr_exit) {
			if (debug) {
				dhcpmsg(LOG_DEBUG,
				    "Monitor (%04d/%s): exiting.\n",
				    ifp->if_thread, ifp->nm);
			}
			(void) mutex_unlock(&ifp->ifp_mtx);
			break;
		}
		(void) mutex_unlock(&ifp->ifp_mtx);

		/* examine each socket for packets in turn */
		for (i = 0; i < DSRVR_NUM_DESC; i++) {
			if (pfd[i].revents == 0)
				continue;
			if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				dhcpmsg(LOG_ERR, "Network interface "
				    "error on device: %s(%s)\n", ifp->nm,
				    dsrvr_socktype(i));
				errors++;
				continue;
			}
			if (!(pfd[i].revents & (POLLIN | POLLRDNORM))) {
				dhcpmsg(LOG_INFO, "Unsupported event "
				    "on device %s(%s): %d\n", ifp->nm,
				    dsrvr_socktype(i),
				    pfd[i].revents);
				errors++;
				continue;
			}
			data.buf = smalloc(ifp->mtu);
			data.len = recv(ifp->descs[i], data.buf, ifp->mtu, 0);
			if (data.len < 0) {
				dhcpmsg(LOG_ERR, "Error: %s receiving UDP "
				    "datagrams on %s(%s)\n",
				    strerror(errno), ifp->nm,
				    dsrvr_socktype(i));
				free(data.buf);
				errors++;
				continue;
			} else
				verify_len = data.len;

			if (debug) {
				dhcpmsg(LOG_INFO,
				    "Datagram received on network device: "
				    "%s(%s)\n", ifp->nm, dsrvr_socktype(i));
			}

			(void) mutex_lock(&ifp->ifp_mtx);
			ifp->received++;
			(void) mutex_unlock(&ifp->ifp_mtx);

			if (verify_len < BASE_PKT_SIZE) {
				if (verbose) {
					dhcpmsg(LOG_INFO, "Short packet %d < "
					    "%d on %s(%s) ignored\n",
					    verify_len, sizeof (PKT),
					    ifp->nm, dsrvr_socktype(i));
				}
				free(data.buf);
				(void) mutex_lock(&ifp->ifp_mtx);
				ifp->errors++;
				(void) mutex_unlock(&ifp->ifp_mtx);
				continue;
			}

			plp = (PKT_LIST *)smalloc(sizeof (PKT_LIST));
			plp->offset = 0;
			plp->len = data.len;
			/* LINTED [alignment ok] */
			plp->pkt = (PKT *)data.buf;

			if (plp->pkt->hops >= max_hops + 1) {
				if (verbose) {
					dhcpmsg(LOG_INFO, "%s(%s): Packet "
					    "dropped: too many hops: %d\n",
					    ifp->nm, dsrvr_socktype(i),
					    plp->pkt->hops);
				}
				free_plp(plp);
				(void) mutex_lock(&ifp->ifp_mtx);
				ifp->errors++;
				(void) mutex_unlock(&ifp->ifp_mtx);
				continue;
			}

			/* validate hardware len */
			if (plp->pkt->hlen > sizeof (plp->pkt->chaddr))
				plp->pkt->hlen = sizeof (plp->pkt->chaddr);

			if (debug && plp->pkt->giaddr.s_addr != 0L &&
			    plp->pkt->giaddr.s_addr != ifp->addr.s_addr) {
				dhcpmsg(LOG_INFO, "%s(%s): Packet received "
				    "from relay agent: %s\n", ifp->nm,
				    dsrvr_socktype(i), inet_ntop(AF_INET,
				    &plp->pkt->giaddr, ntoab, sizeof (ntoab)));
			}

			if (!server_mode) {
				/*
				 * Relay agent mode. No further processing
				 * required ; we'll handle it here.
				 */
				(void) mutex_lock(&if_head_mtx);
				err = relay_agent(ifp, plp);
				(void) mutex_unlock(&if_head_mtx);
				if (err != 0) {
					dhcpmsg(LOG_ERR, "Relay agent mode "
					    "failed: %d (%s) on: %s(%s)\n",
					    err, (plp->pkt->op == BOOTREPLY) ?
					    "reply" : "request",  ifp->nm,
					    dsrvr_socktype(i));
					errors++; /* considered system error */
				} else {
					/* update statistics */
					(void) mutex_lock(&ifp->ifp_mtx);
					ifp->processed++;
					ifp->received++;
					(void) mutex_unlock(&ifp->ifp_mtx);
				}
				free_plp(plp);
				continue;
			}

/* ============ Packets destined for bootp and dhcp server modules ========== */

			/*
			 * Allow packets without RFC1048 magic cookies.
			 * Just don't do an options scan on them,
			 * thus we treat them as plain BOOTP packets.
			 * The BOOTP server can deal with requests of
			 * this type.
			 */
			if (memcmp(plp->pkt->cookie, magic_cookie,
			    sizeof (magic_cookie)) != 0) {
				if (verbose) {
					dhcpmsg(LOG_INFO, "%s(%s): Client: %s "
					    "using non-RFC1048 BOOTP cookie.\n",
					    ifp->nm, dsrvr_socktype(i),
					    disp_cid(plp, cbuf, sizeof (cbuf)));
				}
				plp->rfc1048 = B_FALSE;
			} else {
				/*
				 * Scan the options in the packet and fill in
				 * the opts and vs fields in the * clientlist
				 * structure.  If there's a DHCP message type
				 * in the packet then it's a DHCP packet;
				 * otherwise it's a BOOTP packet. Standard
				 * options are RFC1048 style.
				 */
				if (dhcp_options_scan(plp, B_FALSE) != 0) {
					dhcpmsg(LOG_ERR, "Garbled DHCP/BOOTP "
					    "packet received on: %s(%s)\n",
					    ifp->nm, dsrvr_socktype(i));
					free_plp(plp);
					(void) mutex_lock(&ifp->ifp_mtx);
					ifp->errors++;
					(void) mutex_unlock(&ifp->ifp_mtx);
					continue;
				}
				plp->rfc1048 = B_TRUE;
			}

			/*
			 * Link the new packet to the list of packets
			 * for this network/client. No need to lock plp,
			 * since it isn't visible outside this function yet.
			 */
			if (plp->pkt->op != BOOTREQUEST) {
				dhcpmsg(LOG_ERR, "Unexpected packet received "
				    "on %s(%s), BOOTP server port. Ignored.\n",
				    ifp->nm, dsrvr_socktype(i));
				free_plp(plp);
				(void) mutex_lock(&ifp->ifp_mtx);
				ifp->errors++;
				(void) mutex_unlock(&ifp->ifp_mtx);
				continue;
			}

			determine_network(ifp, plp, &netaddr, &subnetaddr);
			if ((err = open_dnet(&pnd, &netaddr, &subnetaddr)) !=
			    DSVC_SUCCESS) {
				if (verbose && err == DSVC_NO_TABLE) {
					netaddr.s_addr &= subnetaddr.s_addr;
					dhcpmsg(LOG_INFO, "%s(%s): There is no "
					    "%s dhcp-network table for DHCP "
					    "client's network.\n", ifp->nm,
					    dsrvr_socktype(i),
					    inet_ntop(AF_INET, &netaddr,
					    ntoab, sizeof (ntoab)));
				}
				free_plp(plp);
				continue;
			}

			/* Find client */
			get_clnt_id(plp, (uchar_t *)dn.dn_cid,
			    sizeof (dn.dn_cid), &dn.dn_cid_len);
			open_ret = open_clnt(pnd, &pcd, dn.dn_cid,
			    dn.dn_cid_len, B_FALSE);

			if (pcd == NULL) {
				free_plp(plp);
				close_dnet(pnd, B_FALSE);
				continue;
			}

			/*
			 * DOS via Packet flooding: ensure that each client's
			 * PKT_LIST never exceeds DHCP_MON_THRESHOLD pkts in
			 * length. If it does, we prune it from the head of
			 * the list, dropping sequential packets. Note that
			 * since DHCP is a multi-transaction protocol, we would
			 * like to be sure not to discard a REQUEST for an OFFER
			 * we've extended.
			 *
			 * TODO: we are still vulnerable to flooding attacks
			 * where bogus client ids are presented. This can be
			 * manually controlled via the MAX_CLIENTS and
			 * MAX_THREADS config file knobs.
			 */
			(void) mutex_lock(&pcd->pkt_mtx);
			if (pcd->pending > DHCP_MON_THRESHOLD) {
				if ((tplp = pcd->pkthead) != NULL) {
					detach_plp(pcd, tplp);
					free_plp(tplp);
					pcd->pending--;
				}
			}

			if (pcd->pkthead == NULL)
				pcd->pkthead = plp;
			else {
				pcd->pkttail->next = plp;
				plp->prev = pcd->pkttail;
			}
			pcd->pkttail = plp;
			pcd->pending++;
			(void) mutex_unlock(&pcd->pkt_mtx);

			/*
			 * Manage worker threads and deferred thread work list.
			 */
			(void) mutex_lock(&pcd->pcd_mtx);
			pcd->ifp = ifp;
			if (pcd->clnt_thread == NULL &&
			    (pcd->flags & DHCP_PCD_CLOSING) == 0) {
				existing_allocation = B_FALSE;
				(void) mutex_lock(&pnd->thr_mtx);
				if ((freep = pnd->thrhead) != NULL) {
					existing_allocation = B_TRUE;
					/*
					 * Restart a suspended thread.
					 */
					pnd->thrhead = freep->thr_next;
					if (pnd->thrhead == NULL)
						pnd->thrtail = NULL;
					(void) mutex_unlock(&pnd->thr_mtx);

					(void) mutex_lock(&freep->thr_mtx);
					freep->thr_flags &= ~DHCP_THR_LIST;
					freep->thr_next = NULL;
					freep->thr_pcd = pcd;
					(void) mutex_unlock(&freep->thr_mtx);
					pcd->clnt_thread = freep;
				} else if (max_threads != -1 &&
				    pnd->nthreads >= max_threads) {
					/*
					 * Add client once to deferred work
					 * list, to keep track of future work.
					 */
					if ((pcd->flags & DHCP_PCD_WORK) == 0) {
						pcd->flags |= DHCP_PCD_WORK;
						workp = (dsvc_pendclnt_t *)
						    smalloc(
						    sizeof (dsvc_pendclnt_t));
						get_clnt_id(plp,
						    (uchar_t *)workp->pnd_cid,
						    sizeof (workp->pnd_cid),
						    &workp->pnd_cid_len);
						if (pnd->workhead == NULL)
							pnd->workhead = workp;
						else {
							pnd->worktail->
							    pnd_next = workp;
						}
						pnd->worktail = workp;
					}
					(void) mutex_unlock(&pnd->thr_mtx);
					(void) mutex_unlock(&pcd->pcd_mtx);
					if (open_ret == DSVC_SUCCESS)
						close_clnt(pcd, B_FALSE);
					close_dnet(pnd, B_FALSE);
					continue;
				}
				if (pcd->clnt_thread == NULL) {
					pnd->nthreads++;
					(void) mutex_unlock(&pnd->thr_mtx);
					freep = pcd->clnt_thread =
					    (dsvc_thr_t *)
					    smalloc(sizeof (dsvc_thr_t));
					(void) mutex_init(&freep->thr_mtx,
					    USYNC_THREAD, 0);
					freep->thr_pcd = pcd;

					/* Fire up a client thread. */
					if (thr_create(NULL, 0, monitor_client,
					    freep, THR_BOUND | THR_SUSPENDED |
					    THR_DETACHED, &freep->thr_tid) !=
					    0) {
						dhcpmsg(LOG_ERR, "%s(%s): "
						    "Error %s starting client "
						    "monitor thread.\n",
						    ifp->nm, dsrvr_socktype(i),
						    strerror(errno));
						(void) mutex_lock(
						    &pnd->thr_mtx);
						pnd->nthreads--;
						(void) mutex_unlock(
						    &pnd->thr_mtx);
						free(freep);
						freep = pcd->clnt_thread = NULL;
					}
				}
				if (freep != NULL) {
					/*
					 * Continue the new or reused thread.
					 * Let it close the client.
					 */
					open_ret = DSVC_BUSY;
					tid = freep->thr_tid;
					(void) mutex_unlock(&pcd->pcd_mtx);
					pcd = NULL;
					if (existing_allocation) {
						(void) cond_signal(
						    &freep->thr_cv);
					} else {
						(void) thr_continue(tid);
					}
				}
			}
			if (pcd != NULL) {
				(void) mutex_unlock(&pcd->pcd_mtx);
				if (open_ret == DSVC_SUCCESS)
					close_clnt(pcd, B_FALSE);
			}
			close_dnet(pnd, B_FALSE);
		}
	}
	return (NULL);
}

/*
 * close interface sockets
 */
static void
close_sockets(IF *ifp) {
	int	i;

	for (i = 0; i < DSRVR_NUM_DESC; i++) {
		if (ifp->descs[i] == -1)
			continue;
		(void) close(ifp->descs[i]);
		ifp->descs[i] = -1;
	}
}

/*
 * initialize interface sockets.
 *
 * Returns: 0 for success, -1 otherwise.
 */
static int
init_sockets(IF *ifp)
{
	int			i, soptbuf = 1;
	struct sockaddr_in	sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons((short)IPPORT_BOOTPS + port_offset);

	ifp->descs[DSRVR_LBCAST] = -1;
	ifp->descs[DSRVR_DBCAST] = -1;
	ifp->descs[DSRVR_UCAST] = -1;

	for (i = 0; i < DSRVR_NUM_DESC; i++) {
		ifp->descs[i] = socket(AF_INET, SOCK_DGRAM, 0);
		if (ifp->descs[i] < 0) {
			dhcpmsg(LOG_ERR, "Error opening socket on %s(%s) for "
			    "receiving UDP datagrams: %s\n",
			    ifp->nm, dsrvr_socktype(i), strerror(errno));
			return (-1);
		}

		if (setsockopt(ifp->descs[i], SOL_SOCKET, SO_REUSEADDR,
		    &soptbuf, (int)sizeof (soptbuf)) < 0) {
			dhcpmsg(LOG_DEBUG, "Setting socket option on %s(%s) "
			    "to allow reuse on send descriptor failed: %s\n",
			    ifp->nm, dsrvr_socktype(i), strerror(errno));
			close_sockets(ifp);
			return (-1);
		}

		(void) setsockopt(ifp->descs[i], SOL_SOCKET, SO_RCVBUF,
		    &socksize, sizeof (socksize));
		(void) setsockopt(ifp->descs[i], SOL_SOCKET, SO_SNDBUF,
		    &socksize, sizeof (socksize));

		switch (i) {
			case DSRVR_LBCAST:
				if (setsockopt(ifp->descs[i], IPPROTO_IP,
				    IP_BOUND_IF, &ifp->ifceno,
				    (int)sizeof (char *)) < 0) {
					dhcpmsg(LOG_ERR,
					    "Bind to index failed on %s: %s\n",
					    ifp->nm, strerror(errno));
					close_sockets(ifp);
					return (-1);
				}
				sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
				break;
			case DSRVR_DBCAST:
				sin.sin_addr.s_addr =
				    ifp->addr.s_addr & ifp->mask.s_addr;
				break;
			case DSRVR_UCAST:
				/* We send out the unicast socket */
				if (setsockopt(ifp->descs[i], SOL_SOCKET,
				    SO_BROADCAST, &soptbuf,
				    (int)sizeof (soptbuf)) < 0) {
					dhcpmsg(LOG_ERR, "Setting socket "
					    "option on %s to allow broadcast "
					    "on send descriptor failed: %s\n",
					    ifp->nm, strerror(errno));
					close_sockets(ifp);
					return (-1);
				}
				sin.sin_addr.s_addr = ifp->addr.s_addr;
				break;
		}
		if (bind(ifp->descs[i],
		    (struct sockaddr *)&sin, sizeof (sin)) < 0) {
			dhcpmsg(LOG_ERR,
			    "Error binding to UDP socket on %s(%s): %s\n",
			    ifp->nm, dsrvr_socktype(i), strerror(errno));
			close_sockets(ifp);
			return (-1);
		}
	}
	return (0);
}

/*
 * Based on the list generated by find_interfaces(), possibly modified by
 * user arguments, open a stream for each valid / requested interface.
 *
 * If:
 *
 *	1) Only one interface exists, open a standard bidirectional UDP
 *		socket. Note that this is different than if only ONE
 *		interface is requested (but more exist).
 *
 *	2) If more than one valid interface exists, then attach to the
 *		datalink layer, push on the packet filter and buffering
 *		modules, and wait for fragment 0 IP packets that contain
 *		UDP packets with port 67 (server port).
 *
 *	Comments:
 *		Using DLPI to identify the interface thru which BOOTP
 *		packets pass helps in providing the correct response.
 *		Note that I will open a socket for use in transmitting
 *		responses, suitably specifying the destination relay agent
 *		or host. Note that if I'm unicasting to the client (broadcast
 *		flag not set), that somehow I have to clue the IP layer about
 *		the client's hw address. The only way I can see doing this is
 *		making the appropriate ARP table entry.
 *
 *		The only remaining unknown is dealing with clients that
 *		require broadcasting, and multiple interfaces exist. I assume
 *		that if I specify the interface's source address when
 *		opening the socket, that a limited broadcast will be
 *		directed to the correct net, and only the correct net.
 *
 *	Returns: 0 for success, non-zero for failure.
 */
int
open_interfaces(void)
{
	int		inum, err = 0;
	IF		*ifp, *ifp_prevp;

	/* Uncover list of valid, user-selected interfaces to monitor */
	if ((err = find_interfaces()) != 0)
		return (err);

	(void) mutex_lock(&if_head_mtx);

	/*
	 * Setup valid interfaces.
	 */
	ifp = ifp_prevp = if_head;
	err = inum = 0;
	while (ifp != NULL) {
		if (init_sockets(ifp) < 0) {
			ifp = zap_ifp(&ifp_prevp, ifp);
			num_interfaces--;
			continue;
		}

		/* Accounting */
		ifp->transmit = ifp->received = 0;
		ifp->duplicate = ifp->dropped = 0;
		ifp->processed = 0;

		/* ifp structure lock */
		(void) mutex_init(&ifp->ifp_mtx, USYNC_THREAD, 0);
		ifp->thr_exit = 0;

		/* fire up monitor thread */
		if (thr_create(NULL, 0, monitor_interface, ifp,
		    THR_BOUND, &ifp->if_thread) != 0) {
			dhcpmsg(LOG_ERR,
"Interface: %s - Error %s starting monitor thread.\n", ifp->nm,
			    strerror(errno));
			close_sockets(ifp);
			(void) mutex_destroy(&ifp->ifp_mtx);
			ifp = zap_ifp(&ifp_prevp, ifp);
			num_interfaces--;
			continue;
		}
		inum++;
		ifp_prevp = ifp;
		ifp = ifp->next;
	}
	(void) mutex_unlock(&if_head_mtx);

	/*
	 * We must succeed in configuring at least one interface
	 * to be considered successful.
	 */
	if (num_interfaces == 0) {
		err = EINVAL;
		dhcpmsg(LOG_ERR, "Cannot configure any interfaces.\n");
	}
	return (err);
}

/*
 * Detach the referenced plp from the client list.
 */
void
detach_plp(dsvc_clnt_t *pcd, PKT_LIST *plp)
{
	assert(MUTEX_HELD(&pcd->pkt_mtx));

	if (plp->prev == NULL) {
		pcd->pkthead = plp->next;
		if (pcd->pkthead != NULL)
			pcd->pkthead->prev = NULL;
	} else
		plp->prev->next = plp->next;

	if (plp->next != NULL)
		plp->next->prev = plp->prev;
	else {
		pcd->pkttail = plp->prev;
		if (pcd->pkttail != NULL)
			pcd->pkttail->next = NULL;
	}
	plp->prev = plp->next = NULL;
}

/*
 * Write a packet to an interface.
 *
 * Returns 0 on success otherwise non-zero.
 */
int
write_interface(IF *ifp, PKT *clientp, int len, struct sockaddr_in *to)
{
	int err;

	to->sin_family = AF_INET;

	if ((err = sendto(ifp->descs[DSRVR_UCAST], clientp, len, 0,
	    (struct sockaddr *)to, sizeof (struct sockaddr))) < 0) {
		dhcpmsg(LOG_ERR, "SENDTO: %s.\n", strerror(errno));
		return (err);
	}

	(void) mutex_lock(&ifp->ifp_mtx);
	ifp->transmit++;
	(void) mutex_unlock(&ifp->ifp_mtx);

	return (0);
}

/*
 * Pop any packet filters, buffering modules, close stream, free encode
 * list, terminate monitor thread, free ifp. Return ifp next ptr.
 */
static IF *
close_interface(IF *ifp)
{
	int		err;
	IF		*tifp;

	assert(ifp != NULL);

	assert(MUTEX_HELD(&if_head_mtx));

	(void) mutex_lock(&ifp->ifp_mtx);
	ifp->thr_exit = 1;

	close_sockets(ifp);	/* thread will exit poll ... */
	(void) mutex_unlock(&ifp->ifp_mtx);

	/*
	 * Wait for the thread to exit. We release the if_head_mtx
	 * lock, since the monitor thread(s) need to acquire it to traverse
	 * the list - and we don't want to deadlock. Once the monitor thread
	 * notices the thr_exit flag, it'll be gone anyway. Note that if_head
	 * is changing (in close_interfaces()). At this point, only monitor
	 * threads that haven't been reaped could be walking the interface
	 * list. They will "see" the change in if_head.
	 */
	(void) mutex_unlock(&if_head_mtx);
	if ((err = thr_join(ifp->if_thread, NULL, NULL)) != 0) {
		dhcpmsg(LOG_ERR,
		    "Error %d while waiting for monitor %d of %s\n",
		    err, ifp->if_thread, ifp->nm);
	}
	(void) mutex_lock(&if_head_mtx);

	/*
	 * Note: clients and their associated packet lists are freed prior
	 * to interfaces being closed.
	 */

	/* free encode list */
	free_encode_list(ifp->ecp);

	/* display statistics */
	disp_if_stats(ifp);

	ifp->received = ifp->processed = 0;

	(void) mutex_unlock(&ifp->ifp_mtx);
	(void) mutex_destroy(&ifp->ifp_mtx);
	tifp = ifp->next;
	free(ifp);
	return (tifp);
}

/*
 * Close all interfaces, freeing up associated resources.
 * This should only be called from main() during final exit.
 */
void
close_interfaces(void)
{
	(void) mutex_lock(&if_head_mtx);
	for (; if_head != NULL; if_head = close_interface(if_head)) {
		if (verbose) {
			dhcpmsg(LOG_INFO, "Closing interface: %s\n",
			    if_head->nm);
		}
	}
	(void) mutex_unlock(&if_head_mtx);
	(void) mutex_destroy(&if_head_mtx);
}

/*
 * display IF info. Must be MT Safe - called from monitor threads.
 */
static void
disp_if(IF *ifp)
{
	char ntoab[INET_ADDRSTRLEN];

	dhcpmsg(LOG_INFO, "Thread Id: %04d - Monitoring Interface: %s *****\n",
	    ifp->if_thread, ifp->nm);
	dhcpmsg(LOG_INFO, "MTU: %d\tType: %s\n", ifp->mtu, "SOCKET");
	if ((ifp->flags & IFF_POINTOPOINT) == 0)
		dhcpmsg(LOG_INFO, "Broadcast: %s\n",
		    inet_ntop(AF_INET, &ifp->bcast, ntoab, sizeof (ntoab)));
	dhcpmsg(LOG_INFO, "Netmask: %s\n",
	    inet_ntop(AF_INET, &ifp->mask, ntoab, sizeof (ntoab)));
	dhcpmsg(LOG_INFO, "Address: %s\n",
	    inet_ntop(AF_INET, &ifp->addr, ntoab, sizeof (ntoab)));
}

/*
 * Display IF statistics.
 */
void
disp_if_stats(IF *ifp)
{
	dhcpmsg(LOG_INFO, "Interface statistics for: %s **************\n",
	    ifp->nm);

	dhcpmsg(LOG_INFO, "Pending DHCP offers: %d\n", ifp->offers);
	dhcpmsg(LOG_INFO, "Total Packets Transmitted: %d\n", ifp->transmit);
	dhcpmsg(LOG_INFO, "Total Packets Received: %d\n", ifp->received);
	dhcpmsg(LOG_INFO, "Total Packet Duplicates: %d\n", ifp->duplicate);
	dhcpmsg(LOG_INFO, "Total Packets Dropped: %d\n", ifp->dropped);
	dhcpmsg(LOG_INFO, "Total Packets Processed: %d\n", ifp->processed);
	dhcpmsg(LOG_INFO, "Total Protocol Errors: %d\n", ifp->errors);
}

/*
 * Setup the arp cache so that IP address 'ia' will be temporarily
 * bound to hardware address 'ha' of length 'len'. 'ia' is expected in
 * network order.
 *
 * Returns: 0 if the arp entry was made, 1 otherwise.
 */
int
set_arp(IF *ifp, struct in_addr *ia, uchar_t *ha, int len, uchar_t flags)
{
	struct sockaddr_in	*si;
	struct xarpreq		arpreq;
	int			err = 0;
	char			scratch[DHCP_SCRATCH];
	uint_t			scratch_len;
	char			ntoab[INET_ADDRSTRLEN];

	(void) memset((caddr_t)&arpreq, 0, sizeof (arpreq));

	arpreq.xarp_ha.sdl_family = AF_LINK;

	si = (struct sockaddr_in *)&arpreq.xarp_pa;
	si->sin_family = AF_INET;
	si->sin_addr = *ia;	/* struct copy */

	switch (flags) {
	case DHCP_ARP_ADD:
		if (debug) {
			scratch_len = sizeof (scratch);
			if (octet_to_hexascii(ha, len, scratch,
			    &scratch_len) != 0) {
				dhcpmsg(LOG_DEBUG, "Cannot convert ARP \
request to ASCII: %s: len: %d\n",
				    inet_ntop(AF_INET, ia,
				    ntoab, sizeof (ntoab)),
				    len);
			} else {
				dhcpmsg(LOG_DEBUG,
				    "Adding ARP entry: %s == %s\n",
				    inet_ntop(AF_INET, ia,
				    ntoab, sizeof (ntoab)),
				    scratch);
			}
		}
		arpreq.xarp_flags = ATF_INUSE | ATF_COM;
		(void) memcpy(LLADDR(&arpreq.xarp_ha), ha, len);
		arpreq.xarp_ha.sdl_alen = len;

		if (ioctl(ifp->descs[DSRVR_UCAST], SIOCSXARP, &arpreq) < 0) {
			dhcpmsg(LOG_ERR,
			    "ADD: Cannot modify ARP table to add: %s\n",
			    inet_ntop(AF_INET, ia, ntoab, sizeof (ntoab)));
			err = 1;
		}
		break;
	case DHCP_ARP_DEL:
		/* give it a good effort, but don't worry... */
		(void) ioctl(ifp->descs[DSRVR_UCAST], SIOCDXARP, &arpreq);
		break;
	default:
		err = 1;
		break;
	}

	return (err);
}

/*
 * Address and send a BOOTP reply packet appropriately. Does right thing
 * based on BROADCAST flag. Also checks if giaddr field is set, and
 * WE are the relay agent...
 *
 * Returns: 0 for success, nonzero otherwise (fatal)
 */
int
send_reply(IF *ifp, PKT *pp, int len, struct in_addr *dstp)
{
	int			local = B_FALSE;
	struct sockaddr_in	to;
	struct in_addr		if_in, cl_in;
	char			ntoab[INET_ADDRSTRLEN];

	if (pp->giaddr.s_addr != 0L && ifp->addr.s_addr !=
	    pp->giaddr.s_addr) {
		/* Going thru a relay agent */
		to.sin_addr.s_addr = pp->giaddr.s_addr;
		to.sin_port = htons(IPPORT_BOOTPS + port_offset);
	} else {
		to.sin_port = htons(IPPORT_BOOTPC + port_offset);

		if (ntohs(pp->flags) & BCAST_MASK) {
			/*
			 * TODO - what should we do if broadcast
			 * flag is set, but ptp connection?
			 */
			if (debug)
				dhcpmsg(LOG_INFO,
				    "Sending datagram to broadcast address.\n");
			to.sin_addr.s_addr = INADDR_BROADCAST;
		} else {
			/*
			 * By default, we assume unicast!
			 */
			to.sin_addr.s_addr = dstp->s_addr;

			if (debug) {
				dhcpmsg(LOG_INFO,
				    "Unicasting datagram to %s address.\n",
				    inet_ntop(AF_INET, dstp,
				    ntoab, sizeof (ntoab)));
			}
			if (ifp->addr.s_addr == pp->giaddr.s_addr) {
				/*
				 * No doubt a reply packet which we, as
				 * the relay agent, are supposed to deliver.
				 * Local Delivery!
				 */
				local = B_TRUE;
			} else {
				/*
				 * We can't use the giaddr field to
				 * determine whether the client is local
				 * or remote. Use the client's address,
				 * our interface's address,  and our
				 * interface's netmask to make this
				 * determination.
				 */
				if_in.s_addr = ntohl(ifp->addr.s_addr);
				if_in.s_addr &= ntohl(ifp->mask.s_addr);
				cl_in.s_addr = ntohl(dstp->s_addr);
				cl_in.s_addr &= ntohl(ifp->mask.s_addr);
				if (if_in.s_addr == cl_in.s_addr)
					local = B_TRUE;
			}

			if (local) {
				/*
				 * Local delivery. If we can make an
				 * ARP entry we'll unicast. But only in
				 * cases when we do have the chaddr handy.
				 * RFC2855 and IPoIB are cases that do not
				 * send chaddr and set hlen = 0. Identify
				 * such media by their htype, and rely on
				 * in-kernel ARP for them.
				 */
				if ((ifp->flags & IFF_NOARP) == 0 &&
				    ((pp->htype == ARPHRD_IB) ||
				    (set_arp(ifp, dstp, pp->chaddr, pp->hlen,
				    DHCP_ARP_ADD) == 0))) {
					to.sin_addr.s_addr = dstp->s_addr;
				} else {
					to.sin_addr.s_addr = INADDR_BROADCAST;
				}
			}
		}
	}
	return (write_interface(ifp, pp, len, &to));
}

/*
 * Free pkts
 */
void
free_pktlist(dsvc_clnt_t *pcd)
{
	PKT_LIST *plp, *plp_next;
	IF *ifp = pcd->ifp;

	assert(MUTEX_HELD(&pcd->pcd_mtx));

	plp = pcd->pkthead;
	while (plp != NULL) {
		plp_next = plp;
		plp = plp->next;
		free_plp(plp_next);
		ifp->dropped++;
		pcd->pending--;
	}
	pcd->pkthead = NULL;
}

/* Check if address is one of the addresses we are listening on */
boolean_t
is_our_address(in_addr_t addr)
{
	IF		*ifp;
	boolean_t	found = B_FALSE;

	(void) mutex_lock(&if_head_mtx);
	for (ifp = if_head; ifp != NULL; ifp = ifp->next) {
		if (ifp->addr.s_addr == addr) {
			found = B_TRUE;
			break;
		}
	}
	(void) mutex_unlock(&if_head_mtx);
	return (found);
}
