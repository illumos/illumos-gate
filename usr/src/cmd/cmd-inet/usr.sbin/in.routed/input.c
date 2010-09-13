/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/routed/input.c,v 1.9 2001/06/06 20:52:30 phk Exp $
 */

#include "defs.h"
#include <md5.h>

/*
 * The size of the control buffer passed to recvmsg() used to receive
 * ancillary data.
 */
#define	CONTROL_BUFSIZE	1024

static void input(struct sockaddr_in *, struct interface *, struct rip *, int);
static boolean_t ck_passwd(struct interface *, struct rip *, uint8_t *,
    in_addr_t, struct msg_limit *);


/*
 * Find the interface which received the given message.
 */
struct interface *
receiving_interface(struct msghdr *msg, boolean_t findremote)
{
	struct interface *ifp, *ifp1, *ifp2;
	struct sockaddr_in *from;
	void *opt;
	uint_t ifindex;

	from = (struct sockaddr_in *)msg->msg_name;

	/* First see if this packet came from a remote gateway. */
	if (findremote && ((ifp = findremoteif(from->sin_addr.s_addr)) != NULL))
		return (ifp);

	/*
	 * It did not come from a remote gateway.  Determine which
	 * physical interface this packet was received on by
	 * processing the message's ancillary data to find the
	 * IP_RECVIF option we requested.
	 */
	if ((opt = find_ancillary(msg, IP_RECVIF)) == NULL) {
		msglog("unable to retrieve IP_RECVIF");
	} else {
		ifindex = *(uint_t *)opt;
		if ((ifp = ifwithindex(ifindex, _B_TRUE)) != NULL) {
			/* Find the best match of the aliases */
			ifp2 = NULL;
			for (ifp1 = ifp; ifp1 != NULL;
			    ifp1 = ifp1->int_ilist.hl_next) {
				if (ifp1->int_addr == from->sin_addr.s_addr)
					return (ifp1);
				if ((ifp2 == NULL ||
				    (ifp2->int_state & IS_ALIAS)) &&
				    on_net(from->sin_addr.s_addr, ifp1->int_net,
				    ifp1->int_mask)) {
					ifp2 = ifp1;
				}
			}
			if (ifp2 != NULL)
				ifp = ifp2;
			return (ifp);
		}
	}

	/*
	 * As a last resort (for some reason, ip didn't give us the
	 * IP_RECVIF index we requested), try to deduce the receiving
	 * interface based on the source address of the packet.
	 */
	return (iflookup(from->sin_addr.s_addr));
}

/*
 * Process RIP input on rip_sock.  Returns 0 for success, -1 for failure.
 */
int
read_rip()
{
	struct sockaddr_in from;
	struct interface *ifp;
	int cc;
	union pkt_buf inbuf;
	struct msghdr msg;
	struct iovec iov;
	uint8_t ancillary_data[CONTROL_BUFSIZE];

	iov.iov_base = &inbuf;
	iov.iov_len = sizeof (inbuf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &from;
	msg.msg_control = &ancillary_data;

	for (;;) {
		msg.msg_namelen = sizeof (from);
		msg.msg_controllen = sizeof (ancillary_data);
		cc = recvmsg(rip_sock, &msg, 0);
		if (cc == 0)
			return (-1);
		if (cc < 0) {
			if (errno == EWOULDBLOCK || errno == EINTR)
				return (0);
			LOGERR("recvmsg(rip_sock)");
			return (-1);
		}

		/*
		 * ifp is the interface via which the packet arrived.
		 */
		ifp = receiving_interface(&msg, _B_TRUE);

		input(&from, ifp, &inbuf.rip, cc);
	}
}


/* Process a RIP packet */
static void
input(struct sockaddr_in *from,		/* received from this IP address */
    struct interface *ifp,		/* interface of incoming socket */
    struct rip *rip,
    int cc)
{
#define	FROM_NADDR from->sin_addr.s_addr
	static struct msg_limit use_auth, bad_len, bad_mask;
	static struct msg_limit unk_router, bad_router, bad_nhop;

	struct rt_entry *rt;
	struct rt_spare new;
	struct netinfo *n, *lim;
	struct interface *ifp1;
	in_addr_t gate, mask, v1_mask, dst, ddst_h = 0;
	struct auth *ap;
	struct tgate *tg = NULL;
	struct tgate_net *tn;
	int i, j;
	boolean_t poll_answer = _B_FALSE; /* Set to _B_TRUE if RIPCMD_POLL */
	uint16_t rt_state = 0;	/* Extra route state to pass to input_route() */
	uint8_t metric;

	(void) memset(&new, 0, sizeof (new));
	/* Notice when we hear from a remote gateway */
	if (ifp != NULL && (ifp->int_state & IS_REMOTE))
		ifp->int_act_time = now.tv_sec;

	trace_rip("Recv", "from", from, ifp, rip, cc);

	if (ifp != NULL && (ifp->int_if_flags & IFF_NORTEXCH)) {
		trace_misc("discard RIP packet received over %s (IFF_NORTEXCH)",
		    ifp->int_name);
		return;
	}

	gate = ntohl(FROM_NADDR);
	if (IN_CLASSD(gate) || (gate >> IN_CLASSA_NSHIFT) == 0) {
		msglim(&bad_router, FROM_NADDR, "source address %s unusable",
		    naddr_ntoa(FROM_NADDR));
		return;
	}

	if (rip->rip_vers == 0) {
		msglim(&bad_router, FROM_NADDR,
		    "RIP version 0, cmd %d, packet received from %s",
		    rip->rip_cmd, naddr_ntoa(FROM_NADDR));
		return;
	}

	if (rip->rip_vers > RIPv2) {
		msglim(&bad_router, FROM_NADDR,
		    "Treating RIP version %d packet received from %s as "
		    "version %d", rip->rip_vers, naddr_ntoa(FROM_NADDR),
		    RIPv2);
		rip->rip_vers = RIPv2;
	}

	if (cc > (int)OVER_MAXPACKETSIZE) {
		msglim(&bad_router, FROM_NADDR,
		    "packet at least %d bytes too long received from %s",
		    cc-MAXPACKETSIZE, naddr_ntoa(FROM_NADDR));
	}

	n = rip->rip_nets;
	lim = n + (cc - 4) / sizeof (struct netinfo);

	/*
	 * Notice authentication.
	 * As required by section 5.2 of RFC 2453, discard authenticated
	 * RIPv2 messages, but only if configured for that silliness.
	 *
	 * RIPv2 authentication is lame.  Why authenticate queries?
	 * Why should a RIPv2 implementation with authentication disabled
	 * not be able to listen to RIPv2 packets with authentication, while
	 * RIPv1 systems will listen?  Crazy!
	 */
	if (!auth_ok && rip->rip_vers == RIPv2 && n < lim &&
	    n->n_family == RIP_AF_AUTH) {
		msglim(&use_auth, FROM_NADDR,
		    "RIPv2 message with authentication from %s discarded",
		    naddr_ntoa(FROM_NADDR));
		return;
	}

	switch (rip->rip_cmd) {
	case RIPCMD_POLL:
		/*
		 * Similar to RIPCMD_REQUEST, this command is used to
		 * request either a full-table or a set of entries.  Both
		 * silent processes and routers can respond to this
		 * command.
		 */
		poll_answer = _B_TRUE;
		/* FALLTHRU */
	case RIPCMD_REQUEST:
		/* Are we talking to ourself or a remote gateway? */
		ifp1 = ifwithaddr(FROM_NADDR, _B_FALSE, _B_TRUE);
		if (ifp1 != NULL) {
			if (ifp1->int_state & IS_REMOTE) {
				/* remote gateway */
				ifp = ifp1;
				if (check_remote(ifp)) {
					ifp->int_act_time = now.tv_sec;
					if_ok(ifp, "remote ", _B_FALSE);
				}
			} else if (from->sin_port == htons(RIP_PORT)) {
				trace_pkt("    discard our own RIP request");
				return;
			}
		}

		/* did the request come from a router? */
		if (!poll_answer && (from->sin_port == htons(RIP_PORT))) {
			/*
			 * yes, ignore the request if RIP is off so that
			 * the router does not depend on us.
			 */
			if (ripout_interfaces == 0 ||
			    (ifp != NULL && (IS_RIP_OUT_OFF(ifp->int_state) ||
			    !IS_IFF_ROUTING(ifp->int_if_flags)))) {
				trace_pkt("    discard request while RIP off");
				return;
			}
		}

		/*
		 * According to RFC 2453 section 5.2, we should ignore
		 * unauthenticated queries when authentication is
		 * configured.  That is too silly to bother with.  Sheesh!
		 * Are forwarding tables supposed to be secret even though
		 * a bad guy can infer them with test traffic?  RIP is
		 * still the most common router-discovery protocol, so
		 * hosts need to send queries that will be answered.  What
		 * about `rtquery`?  Maybe on firewalls you'd care, but not
		 * enough to give up the diagnostic facilities of remote
		 * probing.
		 */

		if (n >= lim) {
			msglim(&bad_len, FROM_NADDR, "empty request from %s",
			    naddr_ntoa(FROM_NADDR));
			return;
		}
		if (cc%sizeof (*n) != sizeof (struct rip)%sizeof (*n)) {
			msglim(&bad_len, FROM_NADDR,
			    "request of bad length (%d) from %s",
			    cc, naddr_ntoa(FROM_NADDR));
		}

		if (rip->rip_vers == RIPv2 && (ifp == NULL ||
		    (ifp->int_state & IS_NO_RIPV1_OUT))) {
			v12buf.buf->rip_vers = RIPv2;
			/*
			 * If we have a secret but it is a cleartext secret,
			 * do not disclose our secret unless the other guy
			 * already knows it.
			 */
			ap = find_auth(ifp);
			if (ap != NULL &&
			    (ulong_t)ap->end < (ulong_t)clk.tv_sec) {
				/*
				 * Don't authenticate incoming packets
				 * using an expired key.
				 */
				msglim(&use_auth, FROM_NADDR,
				    "%s attempting to authenticate using "
				    "an expired password.",
				    naddr_ntoa(FROM_NADDR));
				ap = NULL;
			}
			if (ap != NULL && ap->type == RIP_AUTH_PW &&
			    (n->n_family != RIP_AF_AUTH ||
			    !ck_passwd(ifp, rip, (uint8_t *)lim, FROM_NADDR,
			    &use_auth)))
				ap = NULL;
		} else {
			v12buf.buf->rip_vers = RIPv1;
			ap = NULL;
		}
		clr_ws_buf(&v12buf, ap);

		do {
			n->n_metric = ntohl(n->n_metric);

			/*
			 * A single entry with family RIP_AF_UNSPEC and
			 * metric HOPCNT_INFINITY means "all routes".
			 * We respond to routers only if we are acting
			 * as a supplier, or to anyone other than a router
			 * (i.e. a query).
			 */
			if (n->n_family == RIP_AF_UNSPEC &&
			    n->n_metric == HOPCNT_INFINITY) {
				/*
				 * Answer a full-table query from a utility
				 * program with all we know.
				 */
				if (poll_answer ||
				    (from->sin_port != htons(RIP_PORT))) {
					supply(from, ifp, OUT_QUERY, 0,
					    rip->rip_vers, ap != NULL);
					return;
				}

				/*
				 * A router is trying to prime its tables.
				 * Filter the answer in the same way
				 * broadcasts are filtered.
				 *
				 * Only answer a router if we are a supplier
				 * to keep an unwary host that is just starting
				 * from picking us as a router.
				 */
				if (ifp == NULL) {
					trace_pkt("ignore distant router");
					return;
				}
				if (IS_RIP_OFF(ifp->int_state) ||
				    !should_supply(ifp)) {
					trace_pkt("ignore; not supplying");
					return;
				}

				/*
				 * Do not answer a RIPv1 router if
				 * we are sending RIPv2.  But do offer
				 * poor man's router discovery.
				 */
				if ((ifp->int_state & IS_NO_RIPV1_OUT) &&
				    rip->rip_vers == RIPv1) {
					if (!(ifp->int_state & IS_PM_RDISC)) {
						trace_pkt("ignore; sending "
						    "RIPv2");
						return;
					}

					v12buf.n->n_family = RIP_AF_INET;
					v12buf.n->n_dst = RIP_DEFAULT;
					metric = ifp->int_d_metric;
					if (NULL !=
					    (rt = rtget(RIP_DEFAULT, 0)))
						metric = MIN(metric,
						    (rt->rt_metric + 1));
					v12buf.n->n_metric = htonl(metric);
					v12buf.n++;
					break;
				}

				/*
				 * Respond with RIPv1 instead of RIPv2 if
				 * that is what we are broadcasting on the
				 * interface to keep the remote router from
				 * getting the wrong initial idea of the
				 * routes we send.
				 */
				supply(from, ifp, OUT_UNICAST, 0,
				    (ifp->int_state & IS_NO_RIPV1_OUT)
				    ? RIPv2 : RIPv1,
				    ap != NULL);
				return;
			}

			/* Ignore authentication */
			if (n->n_family == RIP_AF_AUTH)
				continue;

			if (n->n_family != RIP_AF_INET) {
				msglim(&bad_router, FROM_NADDR,
				    "request from %s for unsupported"
				    " (af %d) %s",
				    naddr_ntoa(FROM_NADDR),
				    ntohs(n->n_family),
				    naddr_ntoa(n->n_dst));
				return;
			}

			/* We are being asked about a specific destination. */
			v12buf.n->n_dst = dst = n->n_dst;
			v12buf.n->n_family = RIP_AF_INET;
			if (!check_dst(dst)) {
				msglim(&bad_router, FROM_NADDR,
				    "bad queried destination %s from %s",
				    naddr_ntoa(dst),
				    naddr_ntoa(FROM_NADDR));
				v12buf.n->n_metric = HOPCNT_INFINITY;
				goto rte_done;
			}

			/* decide what mask was intended */
			if (rip->rip_vers == RIPv1 ||
			    0 == (mask = ntohl(n->n_mask)) ||
			    0 != (ntohl(dst) & ~mask))
				mask = ripv1_mask_host(dst, ifp);

			/*
			 * Try to find the answer.  If we don't have an
			 * explicit route for the destination, use the best
			 * route to the destination.
			 */
			rt = rtget(dst, mask);
			if (rt == NULL && dst != RIP_DEFAULT)
				rt = rtfind(n->n_dst);

			if (v12buf.buf->rip_vers != RIPv1)
				v12buf.n->n_mask = htonl(mask);
			if (rt == NULL) {
				/* we do not have the answer */
				v12buf.n->n_metric = HOPCNT_INFINITY;
				goto rte_done;
			}

			/*
			 * we have the answer, so compute the right metric
			 * and next hop.
			 */
			v12buf.n->n_metric = rt->rt_metric + 1;
			if (v12buf.n->n_metric > HOPCNT_INFINITY)
				v12buf.n->n_metric = HOPCNT_INFINITY;
			if (v12buf.buf->rip_vers != RIPv1) {
				v12buf.n->n_tag = rt->rt_tag;
				if (ifp != NULL &&
				    on_net(rt->rt_gate, ifp->int_net,
				    ifp->int_mask) &&
				    rt->rt_gate != ifp->int_addr)
					v12buf.n->n_nhop = rt->rt_gate;
			}
rte_done:
			v12buf.n->n_metric = htonl(v12buf.n->n_metric);

			/*
			 * Stop paying attention if we fill the output buffer.
			 */
			if (++v12buf.n >= v12buf.lim)
				break;
		} while (++n < lim);

		/*
		 * If our response is authenticated with md5, complete the
		 * md5 computation.
		 */
		if (ap != NULL && ap->type == RIP_AUTH_MD5)
			end_md5_auth(&v12buf, ap);

		/*
		 * Diagnostic programs make specific requests
		 * from ports other than 520.  Log other types
		 * of specific requests as suspicious.
		 */
		if (!poll_answer && (from->sin_port == htons(RIP_PORT))) {
			writelog(LOG_WARNING,
			    "Received suspicious request from %s port %d",
			    naddr_ntoa(FROM_NADDR), RIP_PORT);
		}
		if (poll_answer || (from->sin_port != htons(RIP_PORT))) {
			/* query */
			(void) output(OUT_QUERY, from, ifp, v12buf.buf,
			    ((char *)v12buf.n - (char *)v12buf.buf));
		} else {
			(void) output(OUT_UNICAST, from, ifp,
			    v12buf.buf, ((char *)v12buf.n -
			    (char *)v12buf.buf));
		}
		return;

	case RIPCMD_TRACEON:
	case RIPCMD_TRACEOFF:
		/*
		 * Notice that trace messages are turned off for all possible
		 * abuse if PATH_TRACE is undefined in pathnames.h.
		 * Notice also that because of the way the trace file is
		 * handled in trace.c, no abuse is plausible even if
		 * PATH_TRACE is defined.
		 *
		 * First verify message came from a privileged port.
		 */
		if (ntohs(from->sin_port) > IPPORT_RESERVED) {
			trace_pkt("trace command from untrusted port %d on %s",
			    ntohs(from->sin_port), naddr_ntoa(FROM_NADDR));
			return;
		}
		if (ifp == NULL || !remote_address_ok(ifp, FROM_NADDR)) {
			/*
			 * Use a message here to warn about strange
			 * messages from remote systems.
			 */
			msglim(&bad_router, FROM_NADDR,
			    "trace command from non-local host %s",
			    naddr_ntoa(FROM_NADDR));
			return;
		}
		if (ifp->int_state & IS_DISTRUST) {
			tg = tgates;
			while (tg->tgate_addr != FROM_NADDR) {
				tg = tg->tgate_next;
				if (tg == NULL) {
					trace_pkt("trace command from "
					    "untrusted host %s",
					    naddr_ntoa(FROM_NADDR));
					return;
				}
			}
		}
		if (ifp->int_auth[0].type != RIP_AUTH_NONE) {
			/*
			 * Technically, it would be fairly easy to add
			 * standard authentication to the existing
			 * trace commands -- just bracket the payload
			 * with the authentication information.
			 * However, the tracing message behavior
			 * itself is marginal enough that we don't
			 * actually care.  Just discard if
			 * authentication is needed.
			 */
			trace_pkt("trace command unauthenticated from %s",
			    naddr_ntoa(FROM_NADDR));
			return;
		}
		if (rip->rip_cmd == RIPCMD_TRACEON) {
			rip->rip_tracefile[cc-4] = '\0';
			set_tracefile(rip->rip_tracefile,
			    "trace command: %s\n", 0);
		} else {
			trace_off("tracing turned off by %s",
			    naddr_ntoa(FROM_NADDR));
		}
		return;

	case RIPCMD_RESPONSE:
		if (ifp != NULL && (ifp->int_if_flags & IFF_NOXMIT)) {
			trace_misc("discard RIP response received over %s "
			    "(IFF_NOXMIT)", ifp->int_name);
			return;
		}

		if (cc%sizeof (*n) != sizeof (struct rip)%sizeof (*n)) {
			msglim(&bad_len, FROM_NADDR,
			    "response of bad length (%d) from %s",
			    cc, naddr_ntoa(FROM_NADDR));
		}

		if ((gate >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
		    IN_LINKLOCAL(gate)) {
			msglim(&bad_router, FROM_NADDR,
			    "discard RIP response from bad source address %s",
			    naddr_ntoa(FROM_NADDR));
			return;
		}

		/* verify message came from a router */
		if (from->sin_port != htons(RIP_PORT)) {
			msglim(&bad_router, FROM_NADDR,
			    "    discard RIP response from unknown port"
			    " %d on host %s", ntohs(from->sin_port),
			    naddr_ntoa(FROM_NADDR));
			return;
		}

		if (!rip_enabled) {
			trace_pkt("    discard response while RIP off");
			return;
		}

		/* Are we talking to ourself or a remote gateway? */
		ifp1 = ifwithaddr(FROM_NADDR, _B_FALSE, _B_TRUE);
		if (ifp1 != NULL) {
			if (ifp1->int_state & IS_REMOTE) {
				/* remote gateway */
				ifp = ifp1;
				if (check_remote(ifp)) {
					ifp->int_act_time = now.tv_sec;
					if_ok(ifp, "remote ", _B_FALSE);
				}
			} else {
				trace_pkt("    discard our own RIP response");
				return;
			}
		} else {
			/*
			 * If it's not a remote gateway, then the
			 * remote address *must* be directly
			 * connected.  Make sure that it is.
			 */
			if (ifp != NULL &&
			    !remote_address_ok(ifp, FROM_NADDR)) {
				msglim(&bad_router, FROM_NADDR,
				    "discard RIP response; source %s not on "
				    "interface %s", naddr_ntoa(FROM_NADDR),
				    ifp->int_name);
				return;
			}
		}

		/*
		 * Accept routing packets from routers directly connected
		 * via broadcast or point-to-point networks, and from
		 * those listed in /etc/gateways.
		 */
		if (ifp == NULL) {
			msglim(&unk_router, FROM_NADDR,
			    "   discard response from %s"
			    " via unexpected interface",
			    naddr_ntoa(FROM_NADDR));
			return;
		}

		if (IS_RIP_IN_OFF(ifp->int_state)) {
			trace_pkt("    discard RIPv%d response"
			    " via disabled interface %s",
			    rip->rip_vers, ifp->int_name);
			return;
		}

		if (n >= lim) {
			msglim(&bad_len, FROM_NADDR, "empty response from %s",
			    naddr_ntoa(FROM_NADDR));
			return;
		}

		if (((ifp->int_state & IS_NO_RIPV1_IN) &&
		    rip->rip_vers == RIPv1) ||
		    ((ifp->int_state & IS_NO_RIPV2_IN) &&
		    rip->rip_vers != RIPv1)) {
			trace_pkt("    discard RIPv%d response",
			    rip->rip_vers);
			return;
		}

		/*
		 * Continue to listen to routes via broken interfaces
		 * which might be declared IS_BROKE because of
		 * device-driver idiosyncracies, but might otherwise
		 * be perfectly healthy.
		 */
		if (ifp->int_state & IS_BROKE) {
			trace_pkt("response via broken interface %s",
			    ifp->int_name);
		}

		/*
		 * If the interface cares, ignore bad routers.
		 * Trace but do not log this problem, because where it
		 * happens, it happens frequently.
		 */
		if (ifp->int_state & IS_DISTRUST) {
			tg = tgates;
			while (tg->tgate_addr != FROM_NADDR) {
				tg = tg->tgate_next;
				if (tg == NULL) {
					trace_pkt("    discard RIP response"
					    " from untrusted router %s",
					    naddr_ntoa(FROM_NADDR));
					return;
				}
			}
		}

		/*
		 * Authenticate the packet if we have a secret.
		 * If we do not have any secrets, ignore the error in
		 * RFC 1723 and accept it regardless.
		 */
		if (ifp->int_auth[0].type != RIP_AUTH_NONE &&
		    rip->rip_vers != RIPv1 &&
		    !ck_passwd(ifp, rip, (uint8_t *)lim, FROM_NADDR, &use_auth))
			return;

		/*
		 * Do this only if we're supplying routes to *nobody*.
		 */
		if (!should_supply(NULL) && save_space) {
			/*
			 * "-S" option.  Instead of entering all routes,
			 * only enter a default route for the sender of
			 * this RESPONSE message
			 */

			/* Should we trust this route from this router? */
			if (tg != NULL && tg->tgate_nets->mask != 0) {
				trace_pkt("   ignored unauthorized %s",
				    addrname(RIP_DEFAULT, 0, 0));
				break;
			}

			new.rts_gate = FROM_NADDR;
			new.rts_router = FROM_NADDR;
			new.rts_metric = HOPCNT_INFINITY-1;
			new.rts_tag = n->n_tag;
			new.rts_time = now.tv_sec;
			new.rts_ifp = ifp;
			new.rts_de_ag = 0;
			new.rts_origin = RO_RIP;
			/*
			 * Add the newly generated default route, but don't
			 * propagate the madness.  Treat it the same way as
			 * default routes learned from Router Discovery.
			 */
			input_route(RIP_DEFAULT, 0, &new, n, RS_NOPROPAGATE);
			return;
		}

		if (!IS_IFF_ROUTING(ifp->int_if_flags)) {
			/*
			 * We don't want to propagate routes which would
			 * result in a black-hole.
			 */
			rt_state = RS_NOPROPAGATE;
		}

		do {
			if (n->n_family == RIP_AF_AUTH)
				continue;

			n->n_metric = ntohl(n->n_metric);
			dst = n->n_dst;
			if (n->n_family != RIP_AF_INET &&
			    (n->n_family != RIP_AF_UNSPEC ||
			    dst != RIP_DEFAULT)) {
				msglim(&bad_router, FROM_NADDR,
				    "route from %s to unsupported"
				    " address family=%d destination=%s",
				    naddr_ntoa(FROM_NADDR), n->n_family,
				    naddr_ntoa(dst));
				continue;
			}
			if (!check_dst(dst)) {
				msglim(&bad_router, FROM_NADDR,
				    "bad destination %s from %s",
				    naddr_ntoa(dst),
				    naddr_ntoa(FROM_NADDR));
				continue;
			}
			if (n->n_metric == 0 || n->n_metric > HOPCNT_INFINITY) {
				msglim(&bad_router, FROM_NADDR,
				    "bad metric %d from %s"
				    " for destination %s",
				    n->n_metric, naddr_ntoa(FROM_NADDR),
				    naddr_ntoa(dst));
				continue;
			}

			/*
			 * Notice the next-hop.
			 */
			gate = FROM_NADDR;
			if (n->n_nhop != 0) {
				if (rip->rip_vers == RIPv1) {
					n->n_nhop = 0;
				} else {
					/* Use it only if it is valid. */
					if (on_net(n->n_nhop,
					    ifp->int_net, ifp->int_mask) &&
					    check_dst(n->n_nhop)) {
						gate = n->n_nhop;
					} else {
						msglim(&bad_nhop,
						    FROM_NADDR,
						    "router %s to %s"
						    " has bad next hop %s",
						    naddr_ntoa(FROM_NADDR),
						    naddr_ntoa(dst),
						    naddr_ntoa(n->n_nhop));
						n->n_nhop = 0;
					}
				}
			}

			if (rip->rip_vers == RIPv1 ||
			    0 == (mask = ntohl(n->n_mask))) {
				mask = ripv1_mask_host(dst, ifp);
			} else if ((ntohl(dst) & ~mask) != 0) {
				msglim(&bad_mask, FROM_NADDR,
				    "router %s sent bad netmask %s with %s",
				    naddr_ntoa(FROM_NADDR),
				    naddr_ntoa(htonl(mask)),
				    naddr_ntoa(dst));
				continue;
			}

			if (mask == HOST_MASK &&
			    (ifp->int_state & IS_NO_HOST)) {
				trace_pkt("   ignored host route %s",
				    addrname(dst, mask, 0));
				continue;
			}

			if (rip->rip_vers == RIPv1)
				n->n_tag = 0;

			/*
			 * Adjust metric according to incoming interface cost.
			 * We intentionally don't drop incoming routes with
			 * metric 15 on the floor even though they will
			 * not be advertised to other routers.  We can use
			 * such routes locally, resulting in a network with
			 * a maximum width of 15 hops rather than 14.
			 */
			n->n_metric += ifp->int_metric;
			if (n->n_metric > HOPCNT_INFINITY)
				n->n_metric = HOPCNT_INFINITY;

			/*
			 * Should we trust this route from this router?
			 */
			if (tg != NULL && (tn = tg->tgate_nets)->mask != 0) {
				for (i = 0; i < MAX_TGATE_NETS; i++, tn++) {
					if (on_net(dst, tn->net, tn->mask) &&
					    tn->mask <= mask)
						break;
				}
				if (i >= MAX_TGATE_NETS || tn->mask == 0) {
					trace_pkt("   ignored unauthorized %s",
					    addrname(dst, mask, 0));
					continue;
				}
			}

			/*
			 * Recognize and ignore a default route we faked
			 * which is being sent back to us by a machine with
			 * broken split-horizon. Be a little more paranoid
			 * than that, and reject default routes with the
			 * same metric we advertised.
			 */
			if (ifp->int_d_metric != 0 && dst == RIP_DEFAULT &&
			    n->n_metric >= ifp->int_d_metric)
				continue;

			/*
			 * We can receive aggregated RIPv2 routes that must
			 * be broken down before they are transmitted by
			 * RIPv1 via an interface on a subnet. We might
			 * also receive the same routes aggregated via
			 * other RIPv2 interfaces.  This could cause
			 * duplicate routes to be sent on the RIPv1
			 * interfaces. "Longest matching variable length
			 * netmasks" lets RIPv2 listeners understand, but
			 * breaking down the aggregated routes for RIPv1
			 * listeners can produce duplicate routes.
			 *
			 * Breaking down aggregated routes here bloats the
			 * daemon table, but does not hurt the kernel
			 * table, since routes are always aggregated for
			 * the kernel.
			 *
			 * Notice that this does not break down network
			 * routes corresponding to subnets. This is part of
			 * the defense against RS_NET_SYN.
			 */
			if (have_ripv1_out &&
			    (((rt = rtget(dst, mask)) == NULL ||
			    !(rt->rt_state & RS_NET_SYN))) &&
			    (v1_mask = ripv1_mask_net(dst, 0)) > mask) {
				/* Get least significant set bit */
				ddst_h = v1_mask & -v1_mask;
				i = (v1_mask & ~mask)/ddst_h;
				/*
				 * If you're going to make 512 or more
				 * routes, then that's just too many.  The
				 * reason here is that breaking an old
				 * class B into /24 allocations is common
				 * enough that allowing for the creation of
				 * at least 256 deaggregated routes is
				 * good.  The next power of 2 is 512.
				 */
				if (i >= 511) {
					/*
					 * Punt if we would have to
					 * generate an unreasonable number
					 * of routes.
					 */
					if (TRACECONTENTS)
						trace_misc("accept %s-->%s as 1"
						    " instead of %d routes",
						    addrname(dst, mask, 0),
						    naddr_ntoa(FROM_NADDR),
						    i + 1);
					i = 0;
				} else {
					mask = v1_mask;
				}
			} else {
				i = 0;
			}

			new.rts_gate = gate;
			new.rts_router = FROM_NADDR;
			new.rts_metric = n->n_metric;
			new.rts_tag = n->n_tag;
			new.rts_time = now.tv_sec;
			new.rts_ifp = ifp;
			new.rts_de_ag = i;
			new.rts_origin = RO_RIP;
			j = 0;
			for (;;) {
				input_route(dst, mask, &new, n, rt_state);
				if (++j > i)
					break;
				dst = htonl(ntohl(dst) + ddst_h);
			}
		} while (++n < lim);
		return;
	case RIPCMD_POLLENTRY:
		/*
		 * With this command one can request a single entry.
		 * Both silent processes and routers can respond to this
		 * command
		 */

		if (n >= lim) {
			msglim(&bad_len, FROM_NADDR, "empty request from %s",
			    naddr_ntoa(FROM_NADDR));
			return;
		}
		if (cc%sizeof (*n) != sizeof (struct rip)%sizeof (*n)) {
			msglim(&bad_len, FROM_NADDR,
			    "request of bad length (%d) from %s",
			    cc, naddr_ntoa(FROM_NADDR));
		}

		if (rip->rip_vers == RIPv2 && (ifp == NULL ||
		    (ifp->int_state & IS_NO_RIPV1_OUT))) {
			v12buf.buf->rip_vers = RIPv2;
		} else {
			v12buf.buf->rip_vers = RIPv1;
		}
		/* Dont bother with md5 authentication with POLLENTRY */
		ap = NULL;
		clr_ws_buf(&v12buf, ap);

		n->n_metric = ntohl(n->n_metric);

		if (n->n_family != RIP_AF_INET) {
			msglim(&bad_router, FROM_NADDR,
			    "POLLENTRY request from %s for unsupported"
			    " (af %d) %s",
			    naddr_ntoa(FROM_NADDR),
			    ntohs(n->n_family),
			    naddr_ntoa(n->n_dst));
			return;
		}

		/* We are being asked about a specific destination. */
		v12buf.n->n_dst = dst = n->n_dst;
		v12buf.n->n_family = RIP_AF_INET;
		if (!check_dst(dst)) {
			msglim(&bad_router, FROM_NADDR,
			    "bad queried destination %s from %s",
			    naddr_ntoa(dst),
			    naddr_ntoa(FROM_NADDR));
			v12buf.n->n_metric = HOPCNT_INFINITY;
			goto pollentry_done;
		}

		/* decide what mask was intended */
		if (rip->rip_vers == RIPv1 ||
		    0 == (mask = ntohl(n->n_mask)) ||
		    0 != (ntohl(dst) & ~mask))
			mask = ripv1_mask_host(dst, ifp);

		/* try to find the answer */
		rt = rtget(dst, mask);
		if (rt == NULL && dst != RIP_DEFAULT)
			rt = rtfind(n->n_dst);

		if (v12buf.buf->rip_vers != RIPv1)
			v12buf.n->n_mask = htonl(mask);
		if (rt == NULL) {
			/* we do not have the answer */
			v12buf.n->n_metric = HOPCNT_INFINITY;
			goto pollentry_done;
		}


		/*
		 * we have the answer, so compute the right metric and next
		 * hop.
		 */
		v12buf.n->n_metric = rt->rt_metric + 1;
		if (v12buf.n->n_metric > HOPCNT_INFINITY)
			v12buf.n->n_metric = HOPCNT_INFINITY;
		if (v12buf.buf->rip_vers != RIPv1) {
			v12buf.n->n_tag = rt->rt_tag;
			if (ifp != NULL &&
			    on_net(rt->rt_gate, ifp->int_net, ifp->int_mask) &&
			    rt->rt_gate != ifp->int_addr)
				v12buf.n->n_nhop = rt->rt_gate;
		}
pollentry_done:
		v12buf.n->n_metric = htonl(v12buf.n->n_metric);

		/*
		 * Send the answer about specific routes.
		 */
		(void) output(OUT_QUERY, from, ifp, v12buf.buf,
		    ((char *)v12buf.n - (char *)v12buf.buf));
		break;
	}
#undef FROM_NADDR
}


/*
 * Process a single input route.
 */
void
input_route(in_addr_t dst,			/* network order */
    in_addr_t mask,
    struct rt_spare *new,
    struct netinfo *n,
    uint16_t rt_state)
{
	int i;
	struct rt_entry *rt;
	struct rt_spare *rts, *rts0;
	struct interface *ifp1;
	struct rt_spare *ptr;
	size_t ptrsize;

	/*
	 * See if we can already get there by a working interface.  Ignore
	 * if so.
	 */
	ifp1 = ifwithaddr(dst, _B_TRUE, _B_FALSE);
	if (ifp1 != NULL && (ifp1->int_state & IS_PASSIVE))
		return;

	/*
	 * Look for the route in our table.
	 */
	rt = rtget(dst, mask);

	/* Consider adding the route if we do not already have it. */
	if (rt == NULL) {
		/* Ignore unknown routes being poisoned. */
		if (new->rts_metric == HOPCNT_INFINITY)
			return;

		/* Ignore the route if it points to us */
		if (n != NULL && n->n_nhop != 0 &&
		    NULL != ifwithaddr(n->n_nhop, _B_TRUE, _B_FALSE))
			return;

		/*
		 * If something has not gone crazy and tried to fill
		 * our memory, accept the new route.
		 */
		rtadd(dst, mask, rt_state, new);
		return;
	}

	/*
	 * We already know about the route.  Consider this update.
	 *
	 * If (rt->rt_state & RS_NET_SYN), then this route
	 * is the same as a network route we have inferred
	 * for subnets we know, in order to tell RIPv1 routers
	 * about the subnets.
	 *
	 * It is impossible to tell if the route is coming
	 * from a distant RIPv2 router with the standard
	 * netmask because that router knows about the entire
	 * network, or if it is a round-about echo of a
	 * synthetic, RIPv1 network route of our own.
	 * The worst is that both kinds of routes might be
	 * received, and the bad one might have the smaller
	 * metric.  Partly solve this problem by never
	 * aggregating into such a route.  Also keep it
	 * around as long as the interface exists.
	 */

	rts0 = rt->rt_spares;
	for (rts = rts0, i = rt->rt_num_spares; i != 0; i--, rts++) {
		if (rts->rts_router == new->rts_router)
			break;
		/*
		 * Note the worst slot to reuse,
		 * other than the current slot.
		 */
		if (BETTER_LINK(rt, rts0, rts))
			rts0 = rts;
	}
	if (i != 0) {
		/*
		 * Found a route from the router already in the table.
		 */

		/*
		 * If the new route is a route broken down from an
		 * aggregated route, and if the previous route is either
		 * not a broken down route or was broken down from a finer
		 * netmask, and if the previous route is current,
		 * then forget this one.
		 */
		if (new->rts_de_ag > rts->rts_de_ag &&
		    now_stale <= rts->rts_time)
			return;

		/*
		 * Keep poisoned routes around only long enough to pass
		 * the poison on.  Use a new timestamp for good routes.
		 */
		if (rts->rts_metric == HOPCNT_INFINITY &&
		    new->rts_metric == HOPCNT_INFINITY)
			new->rts_time = rts->rts_time;

		/*
		 * If this is an update for the router we currently prefer,
		 * then note it.
		 */
		if (i == rt->rt_num_spares) {
			uint8_t old_metric = rts->rts_metric;

			rtchange(rt, rt->rt_state | rt_state, new, 0);
			/*
			 * If the route got worse, check for something better.
			 */
			if (new->rts_metric != old_metric)
				rtswitch(rt, 0);
			return;
		}

		/*
		 * This is an update for a spare route.
		 * Finished if the route is unchanged.
		 */
		if (rts->rts_gate == new->rts_gate &&
		    rts->rts_metric == new->rts_metric &&
		    rts->rts_tag == new->rts_tag) {
			if ((rt->rt_dst == RIP_DEFAULT) &&
			    (rts->rts_ifp != new->rts_ifp))
				trace_misc("input_route update for spare");
			trace_upslot(rt, rts, new);
			*rts = *new;
			return;
		}

		/*
		 * Forget it if it has gone bad.
		 */
		if (new->rts_metric == HOPCNT_INFINITY) {
			rts_delete(rt, rts);
			return;
		}

	} else {
		/*
		 * The update is for a route we know about,
		 * but not from a familiar router.
		 *
		 * Ignore the route if it points to us.
		 */
		if (n != NULL && n->n_nhop != 0 &&
		    NULL != ifwithaddr(n->n_nhop, _B_TRUE, _B_FALSE))
			return;

		/* the loop above set rts0=worst spare */
		if (rts0->rts_metric < HOPCNT_INFINITY) {
			ptrsize = (rt->rt_num_spares + SPARE_INC) *
			    sizeof (struct rt_spare);
			ptr = realloc(rt->rt_spares, ptrsize);
			if (ptr != NULL) {

				rt->rt_spares = ptr;
				rts0 = &rt->rt_spares[rt->rt_num_spares];
				(void) memset(rts0, 0,
				    SPARE_INC * sizeof (struct rt_spare));
				rt->rt_num_spares += SPARE_INC;
				for (rts = rts0, i = SPARE_INC;
				    i != 0; i--, rts++)
					rts->rts_metric = HOPCNT_INFINITY;
			}
		}
		rts = rts0;

		/*
		 * Save the route as a spare only if it has
		 * a better metric than our worst spare.
		 * This also ignores poisoned routes (those
		 * received with metric HOPCNT_INFINITY).
		 */
		if (new->rts_metric >= rts->rts_metric)
			return;
	}
	trace_upslot(rt, rts, new);
	*rts = *new;

	/* try to switch to a better route */
	rtswitch(rt, rts);
}

/*
 * Recorded information about peer's MD5 sequence numbers.  This is
 * used to validate that received sequence numbers are in
 * non-decreasing order as per the RFC.
 */
struct peer_hash {
	struct peer_hash *ph_next;
	in_addr_t ph_addr;
	time_t ph_heard;
	uint32_t ph_seqno;
};

static struct peer_hash **peer_hashes;
static int ph_index;
static int ph_num_peers;

/*
 * Get a peer_hash structure from the hash of known peers.  Create a
 * new one if not found.  Returns NULL on unrecoverable allocation
 * failure.
 */
static struct peer_hash *
get_peer_info(in_addr_t from)
{
	struct peer_hash *php;
	struct peer_hash *pnhp;
	struct peer_hash **ph_pp;
	struct peer_hash **ph2_pp;
	struct peer_hash **ph3_pp;
	int i;
	static uint_t failed_count;

	if (peer_hashes == NULL) {
		peer_hashes = calloc(hash_table_sizes[0],
		    sizeof (peer_hashes[0]));
		if (peer_hashes == NULL) {
			if (++failed_count % 100 == 1)
				msglog("no memory for peer hash");
			return (NULL);
		}
	}
	/* Search for peer in existing hash table */
	ph_pp = peer_hashes + (from % hash_table_sizes[ph_index]);
	for (php = ph_pp[0]; php != NULL; php = php->ph_next) {
		if (php->ph_addr == from)
			return (php);
	}
	/*
	 * Not found; we need to add this peer to the table.  If there
	 * are already too many peers, then try to expand the table
	 * first.  It's not a big deal if we can't expand the table
	 * right now due to memory constraints.  We'll try again
	 * later.
	 */
	if (ph_num_peers >= hash_table_sizes[ph_index] * 5 &&
	    hash_table_sizes[ph_index + 1] != 0 &&
	    (ph_pp = calloc(hash_table_sizes[ph_index + 1],
	    sizeof (peer_hashes[0]))) != NULL) {
		ph2_pp = peer_hashes;
		for (i = hash_table_sizes[ph_index] - 1; i >= 0; i--) {
			for (php = ph2_pp[i]; php != NULL; php = pnhp) {
				pnhp = php->ph_next;
				ph3_pp = ph_pp + (php->ph_addr %
				    hash_table_sizes[ph_index + 1]);
				php->ph_next = ph3_pp[0];
				ph3_pp[0] = php;
			}
		}
		ph_index++;
		free(peer_hashes);
		peer_hashes = ph_pp;
		ph_pp += from % hash_table_sizes[ph_index];
	}
	php = calloc(sizeof (*php), 1);
	if (php == NULL) {
		if (++failed_count % 100 == 1)
			msglog("no memory for peer hash entry");
	} else {
		php->ph_addr = from;
		php->ph_heard = now.tv_sec;
		php->ph_next = ph_pp[0];
		ph_pp[0] = php;
		ph_num_peers++;
	}
	return (php);
}

/*
 * Age out entries in the peer table.  This is called every time we do
 * a normal 30 second broadcast.
 */
void
age_peer_info(void)
{
	struct peer_hash *php;
	struct peer_hash *next_ph;
	struct peer_hash *prev_ph;
	struct peer_hash **ph_pp;
	int i;

	/*
	 * Scan through the list and remove peers that should not
	 * still have valid authenticated entries in the routing
	 * table.
	 */
	if ((ph_pp = peer_hashes) == NULL || ph_num_peers == 0)
		return;
	for (i = hash_table_sizes[ph_index] - 1; i >= 0; i--) {
		prev_ph = NULL;
		for (php = ph_pp[i]; php != NULL; php = next_ph) {
			next_ph = php->ph_next;
			if (php->ph_heard <= now_expire) {
				if (prev_ph == NULL)
					ph_pp[i] = next_ph;
				else
					prev_ph->ph_next = next_ph;
				free(php);
				if (--ph_num_peers == 0)
					return;
			} else {
				prev_ph = php;
			}
		}
	}
}

static boolean_t		/* _B_FALSE if bad, _B_TRUE if good */
ck_passwd(struct interface *aifp,
    struct rip *rip,
    uint8_t *lim,
    in_addr_t from,
    struct msg_limit *use_authp)
{
#define	NA (rip->rip_auths)
	struct netauth *na2;
	struct auth *ap;
	MD5_CTX md5_ctx;
	uchar_t hash[RIP_AUTH_PW_LEN];
	int i, len;
	struct peer_hash *php;
	uint32_t seqno;

	if ((uint8_t *)NA >= lim || NA->a_family != RIP_AF_AUTH) {
		msglim(use_authp, from, "missing auth data from %s",
		    naddr_ntoa(from));
		return (_B_FALSE);
	}

	/*
	 * Validate sequence number on RIPv2 responses using keyed MD5
	 * authentication per RFC 2082 section 3.2.2.  Note that if we
	 * can't locate the peer information (due to transient
	 * allocation problems), then we don't do the test.  Also note
	 * that we assume that all sequence numbers 0x80000000 or more
	 * away are "less than."
	 *
	 * We intentionally violate RFC 2082 with respect to one case:
	 * restablishing contact.  The RFC says that you should
	 * continue to ignore old sequence numbers in this case but
	 * make a special allowance for 0.  This is extremely foolish.
	 * The problem is that if the router has crashed, it's
	 * entirely possible that either we'll miss sequence zero (or
	 * that it might not even send it!) or that the peer doesn't
	 * remember what it last used for a sequence number.  In
	 * either case, we'll create a failure state that persists
	 * until the sequence number happens to advance past the last
	 * one we saw.  This is bad because it means that we may have
	 * to wait until the router has been up for at least as long
	 * as it was last time before we even pay attention to it.
	 * Meanwhile, other routers may listen to it if they hadn't
	 * seen it before (i.e., if they crashed in the meantime).
	 * This means -- perversely -- that stable systems that stay
	 * "up" for a long time pay a penalty for doing so.
	 */
	if (rip->rip_cmd == RIPCMD_RESPONSE && NA->a_type == RIP_AUTH_MD5 &&
	    (php = get_peer_info(from)) != NULL) {
		/*
		 * If the entry that we find has been updated
		 * recently enough that the routes are known
		 * to still be good, but the sequence number
		 * looks bad, then discard the packet.
		 */
		seqno = ntohl(NA->au.a_md5.md5_seqno);
		if (php->ph_heard > now_expire && php->ph_seqno != 0 &&
		    (seqno == 0 || ((seqno - php->ph_seqno) & 0x80000000ul))) {
			msglim(use_authp, from,
			    "discarding sequence %x (older than %x)",
			    (unsigned)seqno, (unsigned)php->ph_seqno);
			return (_B_FALSE);
		}
		php->ph_heard = now.tv_sec;
		php->ph_seqno = seqno;
	}

	/*
	 * accept any current (+/- 24 hours) password
	 */
	for (ap = aifp->int_auth, i = 0; i < MAX_AUTH_KEYS; i++, ap++) {
		if (ap->type != NA->a_type ||
		    (ulong_t)ap->start > (ulong_t)clk.tv_sec+DAY ||
		    (ulong_t)ap->end+DAY < (ulong_t)clk.tv_sec)
			continue;

		if (NA->a_type == RIP_AUTH_PW) {
			if (0 == memcmp(NA->au.au_pw, ap->key, RIP_AUTH_PW_LEN))
				return (_B_TRUE);

		} else {
			/*
			 * accept MD5 secret with the right key ID
			 */
			if (NA->au.a_md5.md5_keyid != ap->keyid)
				continue;

			len = ntohs(NA->au.a_md5.md5_pkt_len);
			if ((len - sizeof (*rip)) % sizeof (*NA) != 0 ||
			    len > (lim - (uint8_t *)rip - sizeof (*NA))) {
				msglim(use_authp, from,
				    "wrong MD5 RIPv2 packet length of %d"
				    " instead of %d from %s",
				    len, lim - (uint8_t *)rip - sizeof (*NA),
				    naddr_ntoa(from));
				return (_B_FALSE);
			}
			na2 = (struct netauth *)(rip->rip_nets +
			    (len - 4) / sizeof (struct netinfo));

			/*
			 * Given a good hash value, these are not security
			 * problems so be generous and accept the routes,
			 * after complaining.
			 */
			if (TRACEPACKETS) {
				if (NA->au.a_md5.md5_auth_len !=
				    RIP_AUTH_MD5_LEN)
					msglim(use_authp, from,
					    "unknown MD5 RIPv2 auth len %#x"
					    " instead of %#x from %s",
					    NA->au.a_md5.md5_auth_len,
					    RIP_AUTH_MD5_LEN,
					    naddr_ntoa(from));
				if (na2->a_family != RIP_AF_AUTH)
					msglim(use_authp, from,
					    "unknown MD5 RIPv2 family %#x"
					    " instead of %#x from %s",
					    na2->a_family, RIP_AF_AUTH,
					    naddr_ntoa(from));
				if (na2->a_type != RIP_AUTH_TRAILER)
					msglim(use_authp, from,
					    "MD5 RIPv2 hash has %#x"
					    " instead of %#x from %s",
					    ntohs(na2->a_type),
					    ntohs(RIP_AUTH_TRAILER),
					    naddr_ntoa(from));
			}

			MD5Init(&md5_ctx);
			/*
			 * len+4 to include auth trailer's family/type in
			 * MD5 sum
			 */
			MD5Update(&md5_ctx, (uchar_t *)rip, len + 4);
			MD5Update(&md5_ctx, ap->key, RIP_AUTH_MD5_LEN);
			MD5Final(hash, &md5_ctx);
			if (0 == memcmp(hash, na2->au.au_pw, sizeof (hash)))
				return (_B_TRUE);
		}
	}

	msglim(use_authp, from, "bad auth data from %s",
	    naddr_ntoa(from));
	return (_B_FALSE);
#undef NA
}
