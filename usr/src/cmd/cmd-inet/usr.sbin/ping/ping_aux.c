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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2015, Joyent, Inc.
 */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stropts.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <stdlib.h>

#include <libinetutil.h>
#include "ping.h"


/*
 * IPv4 source routing option.
 * In order to avoid padding for the alignment of IPv4 addresses, ipsr_addrs
 * is defined as a 2-D array of uint8_t, instead of 1-D array of struct in_addr.
 */
struct ip_sourceroute {
	uint8_t ipsr_code;
	uint8_t ipsr_len;
	uint8_t ipsr_ptr;
	/* up to 9 IPv4 addresses */
	uint8_t ipsr_addrs[1][sizeof (struct in_addr)];
};

void check_reply(struct addrinfo *, struct msghdr *, int, ushort_t);
extern void find_dstaddr(ushort_t, union any_in_addr *);
extern boolean_t is_a_target(struct addrinfo *, union any_in_addr *);
extern char *pr_name(char *, int);
static void pr_options(uchar_t *, int);
extern char *pr_protocol(int);
static void pr_rropt(uchar_t *, int, boolean_t);
static void pr_tsopt(uchar_t *, int);
static char *pr_type(int);
extern void schedule_sigalrm();
extern void send_scheduled_probe();
extern boolean_t seq_match(ushort_t, int, ushort_t);
extern void sigalrm_handler();
void set_IPv4_options(int, union any_in_addr *, int, struct in_addr *,
    struct in_addr *);
extern void tvsub(struct timeval *, struct timeval *);

/*
 * Set IPv4 options
 */
void
set_IPv4_options(int sock, union any_in_addr *gw_IP_list, int gw_count,
    struct in_addr *src, struct in_addr *dst)
{
	int req_size;
	char srr[ROUTE_SIZE + 1];
	char *bufp;
	int optsize = ROUTE_SIZE;
	struct ip_sourceroute *srp;
	struct ip_timestamp *tsp;
	int i;

	if (rr_option || ts_option || gw_count > 0) {
		bzero(srr, sizeof (srr));
		bufp = srr;

		if (gw_count > 0) {
			/* 3 = 1 (code) + 1 (len) + 1 (ptr) of src route opt. */
			req_size = 3 + (sizeof (struct in_addr)) * gw_count;

			if (optsize < req_size) {
				Fprintf(stderr, "%s: too many IPv4 gateways\n",
				    progname);
				exit(EXIT_FAILURE);
			}

			srp = (struct ip_sourceroute *)bufp;
			srp->ipsr_code = strict ? IPOPT_SSRR : IPOPT_LSRR;
			srp->ipsr_len = req_size;
			srp->ipsr_ptr = IPOPT_MINOFF;

			for (i = 0; i < gw_count; i++) {
				bcopy((char *)&gw_IP_list[i].addr,
				    &srp->ipsr_addrs[i],
				    sizeof (struct in_addr));
			}
			optsize -= srp->ipsr_len;
			bufp += srp->ipsr_len;
		}
		/* do we send a timestamp option? */
		if (ts_option) {
			if (optsize < IPOPT_MINOFF) {
				Fprintf(stderr,
				    "%s: no room for timestamp option\n",
				    progname);
				exit(EXIT_FAILURE);
			}
			/* LINTED */
			tsp = (struct ip_timestamp *)bufp;
			tsp->ipt_code = IPOPT_TS;
			tsp->ipt_len = optsize;
			tsp->ipt_ptr = IPOPT_MINOFF + 1;
			tsp->ipt_flg = ts_flag & 0x0f;

			if (tsp->ipt_flg > IPOPT_TS_TSANDADDR) {
				req_size = IPOPT_MINOFF +
				    2 * sizeof (struct ipt_ta);
				/*
				 * Note: BSD/4.X is broken in their check so we
				 * have to  bump up this number by at least one.
				 */
				req_size++;

				if (optsize < req_size) {
					Fprintf(stderr, "%s: no room for "
					    "timestamp option\n", progname);
					exit(EXIT_FAILURE);
				}

				bcopy((char *)dst,
				    &tsp->ipt_timestamp.ipt_ta[0].ipt_addr,
				    sizeof (struct in_addr));

				bcopy((char *)src,
				    &tsp->ipt_timestamp.ipt_ta[1].ipt_addr,
				    sizeof (struct in_addr));
				tsp->ipt_len = req_size;

			}
			optsize -= tsp->ipt_len;
			bufp += tsp->ipt_len;
		}
		/* do we send a record route option? */
		if (rr_option) {
			if (optsize < IPOPT_MINOFF) {
				Fprintf(stderr,
				    "%s: no room for record route option\n",
				    progname);
				exit(EXIT_FAILURE);

			}
			/*
			 * Format of record route option is same as source
			 * route option.
			 */
			srp = (struct ip_sourceroute *)bufp;
			srp->ipsr_code = IPOPT_RR;
			srp->ipsr_len = optsize;
			srp->ipsr_ptr = IPOPT_MINOFF;

			optsize -= srp->ipsr_len;
			bufp += srp->ipsr_len;
		}
		optsize = bufp - srr;
		/* Round up to 4 byte boundary */
		if (optsize & 0x3)
			optsize = (optsize & ~0x3) + 4;
		if (setsockopt(sock, IPPROTO_IP, IP_OPTIONS, srr, optsize) <
		    0) {
			Fprintf(stderr, "%s: setsockopt IP_OPTIONS %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

/*
 * Check out the packet to see if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void
check_reply(struct addrinfo *ai_dst, struct msghdr *msg, int cc,
    ushort_t udp_src_port)
{
	struct ip *ip;
	struct icmp *icp;
	struct udphdr *up;
	union any_in_addr dst_addr;
	uchar_t *buf;
	int32_t *intp;
	struct sockaddr_in *from;
	struct timeval *tp;
	struct timeval tv;
	int hlen, hlen1;
	int64_t triptime;
	boolean_t valid_reply = _B_FALSE;
	boolean_t reply_matched_current_target = _B_FALSE; /* Is the source */
						/* address of this reply same */
						/* as where we're sending */
						/* currently? */
	boolean_t last_reply_from_targetaddr = _B_FALSE; /* Is this stats, */
						/* probe all with npackets>0 */
						/* and we received reply for */
						/* the last probe sent to */
						/* targetaddr */
	int cc_left;
	char tmp_buf[INET6_ADDRSTRLEN];
	static char *unreach[] = {
	    "Net Unreachable",
	    "Host Unreachable",
	    "Protocol Unreachable",
	    "Port Unreachable",
	    "Fragmentation needed and DF set",
	    "Source Route Failed",
	    /* The following are from RFC1700 */
	    "Net Unknown",
	    "Host Unknown",
	    "Source Host Isolated",
	    "Dest Net Prohibited",
	    "Dest Host Prohibited",
	    "Net Unreachable for TOS",
	    "Host Unreachable for TOS",
	    "Communication Administratively Prohibited",
	    "Host Precedence Violation",
	    "Precedence Cutoff in Effect"
	};
	static char *redirect[] = {
	    "Net",
	    "Host",
	    "TOS Net",
	    "TOS Host"
	};
	static char *timexceed[] = {
	    "Time exceeded in transit",
	    "Time exceeded during reassembly"
	};
	boolean_t print_newline = _B_FALSE;
	int i;

	/* decompose msghdr into useful pieces */
	buf = (uchar_t *)msg->msg_iov->iov_base;
	from = (struct sockaddr_in *)msg->msg_name;

	/* LINTED */
	intp = (int32_t *)buf;

	ping_gettime(msg, &tv);

	/* LINTED */
	ip = (struct ip *)buf;
	hlen = ip->ip_hl << 2;

	if ((cc < sizeof (struct ip)) || (cc < hlen + ICMP_MINLEN)) {
		if (verbose) {
			Printf("packet too short (%d bytes) from %s\n", cc,
			    pr_name((char *)&from->sin_addr, AF_INET));
		}
		return;
	}

	cc -= hlen;
	/* LINTED */
	icp = (struct icmp *)(buf + hlen);

	if (ip->ip_p == 0) {
		/*
		 * Assume that we are running on a pre-4.3BSD system
		 * such as SunOS before 4.0
		 */
		/* LINTED */
		icp = (struct icmp *)buf;
	}
	cc_left = cc - ICMP_MINLEN;

	switch (icp->icmp_type) {
	case ICMP_UNREACH:
		ip = &icp->icmp_ip;
		hlen1 = ip->ip_hl << 2;

		/* check if we have enough of the packet to work on */
		if ((cc_left < sizeof (struct ip)) ||
		    (cc_left < hlen1 + sizeof (struct udphdr))) {
			if (verbose) {
				Printf("packet too short (%d bytes) from %s\n",
				    cc, pr_name((char *)&from->sin_addr,
				    AF_INET));
			}
			return;
		}

		/* get the UDP packet */
		cc_left -= hlen1 + sizeof (struct udphdr);
		/* LINTED */
		up = (struct udphdr *)((uchar_t *)ip + hlen1);

		/* check to see if this is what we sent */
		if (icp->icmp_code == ICMP_UNREACH_PORT &&
		    ip->ip_p == IPPROTO_UDP &&
		    udp_src_port == up->uh_sport &&
		    use_udp) {
			valid_reply = _B_TRUE;
		} else {
			valid_reply = _B_FALSE;
		}

		if (valid_reply) {
			/*
			 * For this valid reply, if we are still sending to
			 * this target IP address, we'd like to do some
			 * updates to targetaddr, so hold SIGALRMs.
			 */
			(void) sighold(SIGALRM);
			is_alive = _B_TRUE;
			nreceived++;
			reply_matched_current_target =
			    seq_match(current_targetaddr->starting_seq_num,
			    current_targetaddr->num_sent,
			    ntohs(up->uh_dport));
			if (reply_matched_current_target) {
				current_targetaddr->got_reply = _B_TRUE;
				nreceived_last_target++;
				/*
				 * Determine if stats, probe-all, and
				 * npackets != 0, and this is the reply for
				 * the last probe we sent to current target
				 * address.
				 */
				if (stats && probe_all && npackets > 0 &&
				    ((current_targetaddr->starting_seq_num +
				    current_targetaddr->num_probes - 1) %
				    (MAX_PORT + 1) == ntohs(up->uh_dport)) &&
				    (current_targetaddr->num_probes ==
				    current_targetaddr->num_sent))
					last_reply_from_targetaddr = _B_TRUE;
			} else {
				/*
				 * If it's just probe_all and we just received
				 * a reply from a target address we were
				 * probing and had timed out (now we are probing
				 * some other target address), we ignore
				 * this reply.
				 */
				if (probe_all && !stats) {
					valid_reply = _B_FALSE;
					/*
					 * Only if it's verbose, we get a
					 * message regarding this reply,
					 * otherwise we are done here.
					 */
					if (!verbose) {
						(void) sigrelse(SIGALRM);
						return;
					}
				}
			}
		}

		/* stats mode doesn't print 'alive' messages */
		if (valid_reply && !stats) {
			/*
			 * if we are still sending to the same target address,
			 * then stop it, because we know it's alive.
			 */
			if (reply_matched_current_target) {
				(void) alarm(0);	/* cancel alarm */
				(void) sigset(SIGALRM, SIG_IGN);
				current_targetaddr->probing_done = _B_TRUE;
			}
			(void) sigrelse(SIGALRM);

			if (!probe_all) {
				Printf("%s is alive\n", targethost);
			} else {
				(void) inet_ntop(AF_INET, (void *)&ip->ip_dst,
				    tmp_buf, sizeof (tmp_buf));

				if (nflag) {
					Printf("%s is alive\n", tmp_buf);
				} else {
					Printf("%s (%s) is alive\n",
					    targethost, tmp_buf);
				}
			}
			if (reply_matched_current_target) {
				/*
				 * Let's get things going again, but now
				 * ping will start sending to next target IP
				 * address.
				 */
				send_scheduled_probe();
				(void) sigset(SIGALRM, sigalrm_handler);
				schedule_sigalrm();
			}
			return;
		} else {
			/*
			 * If we are not moving to next targetaddr, let's
			 * release the SIGALRM now. We don't want to stall in
			 * the middle of probing a targetaddr if the pr_name()
			 * call (see below) takes longer.
			 */
			if (!last_reply_from_targetaddr)
				(void) sigrelse(SIGALRM);
			/* else, we'll release it later */
		}

		dst_addr.addr = ip->ip_dst;
		if (valid_reply) {
			Printf("%d bytes from %s: ", cc,
			    pr_name((char *)&from->sin_addr, AF_INET));
			Printf("udp_port=%d. ", ntohs(up->uh_dport));
			print_newline = _B_TRUE;
		} else if (is_a_target(ai_dst, &dst_addr) || verbose) {
			if (icp->icmp_code >= A_CNT(unreach)) {
				Printf("ICMP %d Unreachable from gateway %s\n",
				    icp->icmp_code,
				    pr_name((char *)&from->sin_addr, AF_INET));
			} else {
				Printf("ICMP %s from gateway %s\n",
				    unreach[icp->icmp_code],
				    pr_name((char *)&from->sin_addr, AF_INET));
			}
			Printf(" for %s from %s", pr_protocol(ip->ip_p),
			    pr_name((char *)&ip->ip_src, AF_INET));
			Printf(" to %s", pr_name((char *)&ip->ip_dst, AF_INET));
			if (ip->ip_p == IPPROTO_TCP ||
			    ip->ip_p == IPPROTO_UDP) {
				Printf(" port %d ", ntohs(up->uh_dport));
			}
			print_newline = _B_TRUE;
		}

		/* if we are timing and the reply has a timeval */
		if (valid_reply && datalen >= sizeof (struct timeval) &&
		    cc_left >= sizeof (struct timeval)) {
			/* LINTED */
			tp = (struct timeval *)((char *)up +
			    sizeof (struct udphdr));
			(void) tvsub(&tv, tp);
			triptime = (int64_t)tv.tv_sec * MICROSEC + tv.tv_usec;
			Printf("time=" TIMEFORMAT " ms", triptime/1000.0);
			tsum += triptime;
			tsum2 += triptime*triptime;
			if (triptime < tmin)
				tmin = triptime;
			if (triptime > tmax)
				tmax = triptime;
			print_newline = _B_TRUE;
		}
		if (print_newline)
			(void) putchar('\n');
		/*
		 * If it's stats, probe-all, npackets > 0, and we received reply
		 * for the last probe sent to this target address, then we
		 * don't need to wait anymore, let's move on to next target
		 * address, now!
		 */
		if (last_reply_from_targetaddr) {
			(void) alarm(0);	/* cancel alarm */
			current_targetaddr->probing_done = _B_TRUE;
			(void) sigrelse(SIGALRM);
			send_scheduled_probe();
			schedule_sigalrm();
		}
		break;

	case ICMP_REDIRECT:
		if (cc_left < sizeof (struct ip)) {
			if (verbose) {
				Printf("packet too short (%d bytes) from %s\n",
				    cc, pr_name((char *)&from->sin_addr,
				    AF_INET));
			}
			return;
		}

		ip = &icp->icmp_ip;
		dst_addr.addr = ip->ip_dst;
		if (is_a_target(ai_dst, &dst_addr) || verbose) {
			if (icp->icmp_code >= A_CNT(redirect)) {
				Printf("ICMP %d redirect from gateway %s\n",
				    icp->icmp_code,
				    pr_name((char *)&from->sin_addr, AF_INET));
			} else {
				Printf("ICMP %s redirect from gateway %s\n",
				    redirect[icp->icmp_code],
				    pr_name((char *)&from->sin_addr, AF_INET));
			}
			Printf(" to %s",
			    pr_name((char *)&icp->icmp_gwaddr, AF_INET));
			Printf(" for %s\n",
			    pr_name((char *)&ip->ip_dst, AF_INET));
		}
		break;

	case ICMP_ECHOREPLY:
		if (ntohs(icp->icmp_id) == ident) {
			if (!use_udp && !use_icmp_ts)
				valid_reply = _B_TRUE;
			else
				valid_reply = _B_FALSE;
		} else {
			return;
		}

		if (valid_reply) {
			/*
			 * For this valid reply, if we are still sending to
			 * this target IP address, we'd like to do some
			 * updates to targetaddr, so hold SIGALRMs.
			 */
			(void) sighold(SIGALRM);
			is_alive = _B_TRUE;
			nreceived++;
			reply_matched_current_target =
			    seq_match(current_targetaddr->starting_seq_num,
			    current_targetaddr->num_sent,
			    ntohs(icp->icmp_seq));
			if (reply_matched_current_target) {
				current_targetaddr->got_reply = _B_TRUE;
				nreceived_last_target++;
				/*
				 * Determine if stats, probe-all, and
				 * npackets != 0, and this is the reply for
				 * the last probe we sent to current target
				 * address.
				 */
				if (stats && probe_all && npackets > 0 &&
				    ((current_targetaddr->starting_seq_num +
				    current_targetaddr->num_probes - 1) %
				    (MAX_ICMP_SEQ + 1) ==
				    ntohs(icp->icmp_seq)) &&
				    (current_targetaddr->num_probes ==
				    current_targetaddr->num_sent))
					last_reply_from_targetaddr = _B_TRUE;
			} else {
				/*
				 * If it's just probe_all and we just received
				 * a reply from a target address we were
				 * probing and had timed out (now we are probing
				 * some other target address), we ignore
				 * this reply.
				 */
				if (probe_all && !stats) {
					valid_reply = _B_FALSE;
					/*
					 * Only if it's verbose, we get a
					 * message regarding this reply,
					 * otherwise we are done here.
					 */
					if (!verbose) {
						(void) sigrelse(SIGALRM);
						return;
					}
				}
			}
		}

		if (!stats && valid_reply) {
			/*
			 * if we are still sending to the same target address,
			 * then stop it, because we know it's alive.
			 */
			if (reply_matched_current_target) {
				(void) alarm(0);	/* cancel alarm */
				(void) sigset(SIGALRM, SIG_IGN);
				current_targetaddr->probing_done = _B_TRUE;
			}
			(void) sigrelse(SIGALRM);

			if (!probe_all) {
				Printf("%s is alive\n", targethost);
			} else {
				/*
				 * If we are using send_reply, the real
				 * target address is not the src address of the
				 * replies. Use icmp_seq to find out where this
				 * probe was sent to.
				 */
				if (send_reply) {
					(void) find_dstaddr(
					    ntohs(icp->icmp_seq), &dst_addr);
					(void) inet_ntop(AF_INET,
					    (void *)&dst_addr.addr,
					    tmp_buf, sizeof (tmp_buf));
				} else {
					(void) inet_ntop(AF_INET,
					    (void *)&from->sin_addr,
					    tmp_buf, sizeof (tmp_buf));
				}
				if (nflag) {
					Printf("%s is alive\n", tmp_buf);
				} else {
					Printf("%s (%s) is alive\n",
					    targethost, tmp_buf);
				}
			}
			if (reply_matched_current_target) {
				/*
				 * Let's get things going again, but now
				 * ping will start sending to next target IP
				 * address.
				 */
				send_scheduled_probe();
				(void) sigset(SIGALRM, sigalrm_handler);
				schedule_sigalrm();
			}
			return;
		} else {
			/*
			 * If we are not moving to next targetaddr, let's
			 * release the SIGALRM now. We don't want to stall in
			 * the middle of probing a targetaddr if the pr_name()
			 * call (see below) takes longer.
			 */
			if (!last_reply_from_targetaddr)
				(void) sigrelse(SIGALRM);
			/* else, we'll release it later */
		}
		/*
		 * If we are using send_reply, the real target address is
		 * not the src address of the replies. Use icmp_seq to find out
		 * where this probe was sent to.
		 */
		if (send_reply) {
			(void) find_dstaddr(ntohs(icp->icmp_seq), &dst_addr);
			Printf("%d bytes from %s: ", cc,
			    pr_name((char *)&dst_addr.addr,  AF_INET));
		} else {
			Printf("%d bytes from %s: ", cc,
			    pr_name((char *)&from->sin_addr, AF_INET));
		}
		Printf("icmp_seq=%d. ", ntohs(icp->icmp_seq));

		if (valid_reply && datalen >= sizeof (struct timeval) &&
		    cc_left >= sizeof (struct timeval)) {
			/* LINTED */
			tp = (struct timeval *)&icp->icmp_data[0];
			(void) tvsub(&tv, tp);
			triptime = (int64_t)tv.tv_sec * MICROSEC + tv.tv_usec;
			Printf("time=" TIMEFORMAT " ms", triptime/1000.0);
			tsum += triptime;
			tsum2 += triptime*triptime;
			if (triptime < tmin)
				tmin = triptime;
			if (triptime > tmax)
				tmax = triptime;
		}
		(void) putchar('\n');

		/*
		 * If it's stats, probe-all, npackets > 0, and we received reply
		 * for the last probe sent to this target address, then we
		 * don't need to wait anymore, let's move on to next target
		 * address, now!
		 */
		if (last_reply_from_targetaddr) {
			(void) alarm(0);	/* cancel alarm */
			current_targetaddr->probing_done = _B_TRUE;
			(void) sigrelse(SIGALRM);
			send_scheduled_probe();
			schedule_sigalrm();
		}
		break;

	case ICMP_SOURCEQUENCH:
		if (cc_left < sizeof (struct ip)) {
			if (verbose) {
				Printf("packet too short (%d bytes) from %s\n",
				    cc, pr_name((char *)&from->sin_addr,
				    AF_INET));
			}
			return;
		}
		ip = &icp->icmp_ip;
		hlen1 = ip->ip_hl << 2;
		dst_addr.addr = ip->ip_dst;
		if (is_a_target(ai_dst, &dst_addr) || verbose) {
			Printf("ICMP Source Quench from %s\n",
			    pr_name((char *)&from->sin_addr, AF_INET));
			Printf(" for %s from %s", pr_protocol(ip->ip_p),
			    pr_name((char *)&ip->ip_src, AF_INET));
			Printf(" to %s", pr_name((char *)&ip->ip_dst, AF_INET));

			/*
			 * if it's a UDP or TCP packet, we need at least first
			 * 4 bytes of it to see the src/dst ports
			 */
			if ((ip->ip_p == IPPROTO_TCP ||
			    ip->ip_p == IPPROTO_UDP) &&
			    (cc_left >= hlen1 + 4)) {
				/* LINTED */
				up = (struct udphdr *)((uchar_t *)ip + hlen1);
				Printf(" port %d", ntohs(up->uh_dport));
			}
			(void) putchar('\n');
		}
		break;

	case ICMP_PARAMPROB:
		if (cc_left < sizeof (struct ip)) {
			if (verbose) {
				Printf("packet too short (%d bytes) from %s\n",
				    cc, pr_name((char *)&from->sin_addr,
				    AF_INET));
			}
			return;
		}
		ip = &icp->icmp_ip;
		hlen1 = ip->ip_hl << 2;
		dst_addr.addr = ip->ip_dst;
		if (is_a_target(ai_dst, &dst_addr) || verbose) {
			switch (icp->icmp_code) {
			case ICMP_PARAMPROB_OPTABSENT:
				Printf("ICMP Missing a Required Option "
				    "parameter problem from %s\n",
				    pr_name((char *)&from->sin_addr, AF_INET));
				Printf(" option type = %d", icp->icmp_pptr);
				break;
			case ICMP_PARAMPROB_BADLENGTH:
				Printf("ICMP Bad Length parameter problem "
				    "from %s\n",
				    pr_name((char *)&from->sin_addr, AF_INET));
				Printf(" in byte %d", icp->icmp_pptr);
				if (icp->icmp_pptr <= hlen1) {
					Printf(" (value 0x%x)",
					    *((char *)ip + icp->icmp_pptr));
				}
				break;
			case 0:
			default:
				Printf("ICMP Parameter Problem from %s\n",
				    pr_name((char *)&from->sin_addr, AF_INET));
				Printf(" in byte %d", icp->icmp_pptr);
				if (icp->icmp_pptr <= hlen1) {
					Printf(" (value 0x%x)",
					    *((char *)ip + icp->icmp_pptr));
				}
				break;
			}

			Printf(" for %s from %s", pr_protocol(ip->ip_p),
			    pr_name((char *)&ip->ip_src, AF_INET));
			Printf(" to %s", pr_name((char *)&ip->ip_dst, AF_INET));

			/*
			 * if it's a UDP or TCP packet, we need at least first
			 * 4 bytes of it to see the src/dst ports
			 */
			if ((ip->ip_p == IPPROTO_TCP ||
			    ip->ip_p == IPPROTO_UDP) &&
			    (cc_left >= hlen1 + 4)) {
				/* LINTED */
				up = (struct udphdr *)((uchar_t *)ip + hlen1);
				Printf(" port %d", ntohs(up->uh_dport));
			}
			(void) putchar('\n');
		}
		break;

	case ICMP_TIMXCEED:
		if (cc_left < sizeof (struct ip)) {
			if (verbose) {
				Printf("packet too short (%d bytes) from %s\n",
				    cc, pr_name((char *)&from->sin_addr,
				    AF_INET));
			}
			return;
		}
		ip = &icp->icmp_ip;
		hlen1 = ip->ip_hl << 2;
		dst_addr.addr = ip->ip_dst;
		if (is_a_target(ai_dst, &dst_addr) || verbose) {
			if (icp->icmp_code >= A_CNT(timexceed)) {
				Printf("ICMP %d time exceeded from %s\n",
				    icp->icmp_code,
				    pr_name((char *)&from->sin_addr, AF_INET));
			} else {
				Printf("ICMP %s from %s\n",
				    timexceed[icp->icmp_code],
				    pr_name((char *)&from->sin_addr, AF_INET));
			}
			Printf(" for %s from %s", pr_protocol(ip->ip_p),
			    pr_name((char *)&ip->ip_src, AF_INET));
			Printf(" to %s", pr_name((char *)&ip->ip_dst, AF_INET));
			if ((ip->ip_p == IPPROTO_TCP ||
			    ip->ip_p == IPPROTO_UDP) &&
			    (cc_left >= hlen1 + 4)) {
				/* LINTED */
				up = (struct udphdr *)((uchar_t *)ip + hlen1);
				Printf(" port %d", ntohs(up->uh_dport));
			}
			(void) putchar('\n');
		}
		break;

	case ICMP_TSTAMPREPLY:
		/* the packet should have enough space to store timestamps */
		if (cc_left < sizeof (struct id_ts)) {
			if (verbose) {
				Printf("packet too short (%d bytes) from %s\n",
				    cc, pr_name((char *)&from->sin_addr,
				    AF_INET));
			}
			return;
		}

		if (ntohs(icp->icmp_id) == ident) {
			if (use_icmp_ts)
				valid_reply = _B_TRUE;
			else
				valid_reply = _B_FALSE;
		} else {
			return;
		}

		if (valid_reply) {
			/*
			 * For this valid reply, if we are still sending to
			 * this target IP address, we'd like to do some
			 * updates to targetaddr, so hold SIGALRMs.
			 */
			(void) sighold(SIGALRM);
			is_alive = _B_TRUE;
			nreceived++;
			reply_matched_current_target =
			    seq_match(current_targetaddr->starting_seq_num,
			    current_targetaddr->num_sent,
			    ntohs(icp->icmp_seq));
			if (reply_matched_current_target) {
				current_targetaddr->got_reply = _B_TRUE;
				nreceived_last_target++;
				/*
				 * Determine if stats, probe-all, and
				 * npackets != 0, and this is the reply for
				 * the last probe we sent to current target
				 * address.
				 */
				if (stats && probe_all && npackets > 0 &&
				    ((current_targetaddr->starting_seq_num +
				    current_targetaddr->num_probes - 1) %
				    (MAX_ICMP_SEQ + 1) ==
				    ntohs(icp->icmp_seq)) &&
				    (current_targetaddr->num_probes ==
				    current_targetaddr->num_sent))
					last_reply_from_targetaddr = _B_TRUE;
			} else {
				/*
				 * If it's just probe_all and we just received
				 * a reply from a target address we were
				 * probing and had timed out (now we are probing
				 * some other target address), we ignore
				 * this reply.
				 */
				if (probe_all && !stats) {
					valid_reply = _B_FALSE;
					/*
					 * Only if it's verbose, we get a
					 * message regarding this reply,
					 * otherwise we are done here.
					 */
					if (!verbose) {
						(void) sigrelse(SIGALRM);
						return;
					}
				}
			}
		}

		if (!stats && valid_reply) {
			/*
			 * if we are still sending to the same target address,
			 * then stop it, because we know it's alive.
			 */
			if (reply_matched_current_target) {
				(void) alarm(0);	/* cancel alarm */
				(void) sigset(SIGALRM, SIG_IGN);
				current_targetaddr->probing_done = _B_TRUE;
			}
			(void) sigrelse(SIGALRM);

			if (!probe_all) {
				Printf("%s is alive\n", targethost);
			} else {
				/*
				 * If we are using send_reply, the real
				 * target address is not the src address of the
				 * replies. Use icmp_seq to find out where this
				 * probe was sent to.
				 */
				if (send_reply) {
					(void) find_dstaddr(
					    ntohs(icp->icmp_seq), &dst_addr);
					(void) inet_ntop(AF_INET,
					    (void *)&dst_addr.addr,
					    tmp_buf, sizeof (tmp_buf));
				} else {
					(void) inet_ntop(AF_INET,
					    (void *)&from->sin_addr,
					    tmp_buf, sizeof (tmp_buf));
				}
				if (nflag) {
					Printf("%s is alive\n", tmp_buf);
				} else {
					Printf("%s (%s) is alive\n",
					    targethost, tmp_buf);
				}
			}
			if (reply_matched_current_target) {
				/*
				 * Let's get things going again, but now
				 * ping will start sending to next target IP
				 * address.
				 */
				send_scheduled_probe();
				(void) sigset(SIGALRM, sigalrm_handler);
				schedule_sigalrm();
			}
			return;
		} else {
			/*
			 * If we are not moving to next targetaddr, let's
			 * release the SIGALRM now. We don't want to stall in
			 * the middle of probing a targetaddr if the pr_name()
			 * call (see below) takes longer.
			 */
			if (!last_reply_from_targetaddr)
				(void) sigrelse(SIGALRM);
			/* else, we'll release it later */
		}

		/*
		 * If we are using send_reply, the real target address is
		 * not the src address of the replies. Use icmp_seq to find out
		 * where this probe was sent to.
		 */
		if (send_reply) {
			(void) find_dstaddr(ntohs(icp->icmp_seq), &dst_addr);
			Printf("%d bytes from %s: ", cc,
			    pr_name((char *)&dst_addr.addr,  AF_INET));
		} else {
			Printf("%d bytes from %s: ", cc,
			    pr_name((char *)&from->sin_addr, AF_INET));
		}
		Printf("icmp_seq=%d. ", ntohs(icp->icmp_seq));
		Printf("orig = %lu, recv = %lu, xmit = %lu ",
		    (ulong_t)ntohl(icp->icmp_otime),
		    (ulong_t)ntohl(icp->icmp_rtime),
		    (ulong_t)ntohl(icp->icmp_ttime));

		if (valid_reply) {
			/*
			 * icp->icmp_otime is the time passed since midnight.
			 * Therefore we need to adjust tv value, which is
			 * the time passed since Jan 1, 1970.
			 */
			triptime = (tv.tv_sec % (24LL * 60 * 60)) * MILLISEC +
			    (tv.tv_usec / (MICROSEC/MILLISEC));
			triptime -= ntohl(icp->icmp_otime);
			if (triptime < 0)
				triptime += 24LL * 60 * 60 * MILLISEC;

			Printf("time=%d. ms", (int)triptime);
			triptime *= (MICROSEC/MILLISEC);
			tsum += triptime;
			tsum2 += triptime*triptime;
			if (triptime < tmin)
				tmin = triptime;
			if (triptime > tmax)
				tmax = triptime;
		}
		(void) putchar('\n');
		/*
		 * If it's stats, probe-all, npackets > 0, and we received reply
		 * for the last probe sent to this target address, then we
		 * don't need to wait anymore, let's move on to next target
		 * address, now!
		 */
		if (last_reply_from_targetaddr) {
			(void) alarm(0);	/* cancel alarm */
			current_targetaddr->probing_done = _B_TRUE;
			(void) sigrelse(SIGALRM);
			send_scheduled_probe();
			schedule_sigalrm();
		}
		break;
	case ICMP_ROUTERADVERT:
	case ICMP_ROUTERSOLICIT:
		/* Router discovery messages */
		return;

	case ICMP_ECHO:
	case ICMP_TSTAMP:
	case ICMP_IREQ:
	case ICMP_MASKREQ:
		/* These were never passed out from the SunOS 4.X kernel. */
		return;

	case ICMP_IREQREPLY:
	case ICMP_MASKREPLY:
		/* Replies for information and address mask requests */
		return;

	default:
		if (verbose) {
			Printf("%d bytes from %s:\n", cc,
			    pr_name((char *)&from->sin_addr, AF_INET));
			Printf("icmp_type=%d (%s) ",
			    icp->icmp_type, pr_type(icp->icmp_type));
			Printf("icmp_code=%d\n", icp->icmp_code);
			for (i = 0; i < 12; i++) {
				Printf("x%2.2x: x%8.8x\n",
				    i * sizeof (int32_t), *intp++);
			}
		}
		break;
	}

	buf += sizeof (struct ip);
	hlen -= sizeof (struct ip);

	/* if verbose and there exists IP options */
	if (verbose && hlen > 0)
		pr_options((uchar_t *)buf, hlen);
}

/*
 * Print out the ip options.
 */
static void
pr_options(uchar_t *opt, int optlength)
{
	int curlength;

	Printf("  IP options: ");
	while (optlength > 0) {
		curlength = opt[1];
		switch (*opt) {
		case IPOPT_EOL:
			optlength = 0;
			break;

		case IPOPT_NOP:
			opt++;
			optlength--;
			continue;

		case IPOPT_RR:
			Printf(" <record route> ");
			pr_rropt(opt, curlength, _B_TRUE);
			break;

		case IPOPT_TS:
			Printf(" <time stamp> ");
			pr_tsopt(opt, curlength);
			break;

		case IPOPT_SECURITY:
			Printf(" <security>");
			break;

		case IPOPT_LSRR:
			Printf(" <loose source route> ");
			pr_rropt(opt, curlength, _B_FALSE);
			break;

		case IPOPT_SATID:
			Printf(" <stream id>");
			break;

		case IPOPT_SSRR:
			Printf(" <strict source route> ");
			pr_rropt(opt, curlength, _B_FALSE);
			break;

		default:
			Printf(" <option %d, len %d>", *opt, curlength);
			break;
		}
		/*
		 * Following most options comes a length field
		 */
		opt += curlength;
		optlength -= curlength;
	}
	(void) putchar('\n');
}

/*
 * Print out a recorded route option. If rrflag is _B_TRUE, it prints record
 * route option, otherwise LSRR/SSRR.
 */
static void
pr_rropt(uchar_t *opt, int length, boolean_t rrflag)
{
	struct ip_sourceroute *rrp;
	int sr_index = 0;
	struct in_addr addr;

	rrp = (struct ip_sourceroute *)opt;

	/* data starts at offset 3 */
	length -= 3;
	while (length > 0) {
		/*
		 * Let's see if we are examining the addr pointed by ipsr_ptr
		 */
		if ((rrp->ipsr_ptr == (sr_index + 1) * sizeof (addr)) &&
		    rrflag) {
			Printf(" (End of record)");
			break;
		}

		bcopy(&rrp->ipsr_addrs[sr_index], &addr, sizeof (addr));
		Printf("%s", pr_name((char *)&addr, AF_INET));

		if (rrp->ipsr_ptr == (sr_index + 1) * sizeof (addr)) {
			Printf("(Current)");
		}

		sr_index++;

		length -= sizeof (addr);
		if (length > 0)
			Printf(", ");
	}
}

/*
 * Print out a timestamp option.
 */
static void
pr_tsopt(uchar_t *opt, int length)
{
	boolean_t address_present;
	boolean_t rrflag;		/* End at current entry? */
	struct ip_timestamp *tsp;
	int ts_index = 0;
	struct in_addr addr;
	size_t data_len;
	int32_t time;

	/* LINTED */
	tsp = (struct ip_timestamp *)opt;

	switch (tsp->ipt_flg) {
	case IPOPT_TS_TSONLY:
		address_present = _B_FALSE;
		data_len = sizeof (tsp->ipt_timestamp.ipt_time[0]);
		rrflag = _B_TRUE;
		break;
	case IPOPT_TS_TSANDADDR:
		address_present = _B_TRUE;
		data_len = sizeof (tsp->ipt_timestamp.ipt_ta[0]);
		rrflag = _B_TRUE;
		break;
	case IPOPT_TS_PRESPEC:
	case 3:
		address_present = _B_TRUE;
		data_len = sizeof (tsp->ipt_timestamp.ipt_ta[0]);
		rrflag = _B_FALSE;
		break;
	default:
		Printf("(Bad flag value: 0x%x)", tsp->ipt_flg);
		return;
	}
	if (tsp->ipt_oflw > 0)
		Printf("(Overflow: %d) ", tsp->ipt_oflw);

	/* data starts at offset 4 */
	length -= 4;

	while (length > 0) {
		if (length < data_len)
			break;

		/* the minimum value of ipt_ptr is 5 */
		if ((tsp->ipt_ptr == ts_index * data_len + 5) && rrflag) {
			Printf(" (End of record)");
			break;
		}
		if (address_present) {
			bcopy(&tsp->ipt_timestamp.ipt_ta[ts_index].ipt_addr,
			    &addr, sizeof (addr));
			Printf("%s: ", pr_name((char *)&addr, AF_INET));
			bcopy(&tsp->ipt_timestamp.ipt_ta[ts_index].ipt_time,
			    &time, sizeof (time));
		} else {
			bcopy(&tsp->ipt_timestamp.ipt_time[ts_index],
			    &time, sizeof (time));
		}
		Printf("%d", ntohl(time));

		if (tsp->ipt_ptr == ts_index * data_len + 5)
			Printf("(Current)");

		ts_index++;
		length -= data_len;
		if (length > 0)
			Printf(", ");
	}
}

/*
 * Convert an ICMP "type" field to a printable string.
 */
static char *
pr_type(int icmp_type)
{
	static struct icmptype_table ttab[] = {
		{ICMP_ECHOREPLY,	"Echo Reply"},
		{1,			"ICMP 1"},
		{2,			"ICMP 2"},
		{ICMP_UNREACH,		"Dest Unreachable"},
		{ICMP_SOURCEQUENCH,	"Source Quench"},
		{ICMP_REDIRECT,		"Redirect"},
		{6,			"ICMP 6"},
		{7,			"ICMP 7"},
		{ICMP_ECHO,		"Echo"},
		{ICMP_ROUTERADVERT,	"Router Advertisement"},
		{ICMP_ROUTERSOLICIT,	"Router Solicitation"},
		{ICMP_TIMXCEED,		"Time Exceeded"},
		{ICMP_PARAMPROB,	"Parameter Problem"},
		{ICMP_TSTAMP,		"Timestamp"},
		{ICMP_TSTAMPREPLY,	"Timestamp Reply"},
		{ICMP_IREQ,		"Info Request"},
		{ICMP_IREQREPLY,	"Info Reply"},
		{ICMP_MASKREQ,		"Netmask Request"},
		{ICMP_MASKREPLY,	"Netmask Reply"}
	};
	int i;

	for (i = 0; i < A_CNT(ttab); i++) {
		if (ttab[i].type == icmp_type)
			return (ttab[i].message);
	}

	return ("OUT-OF-RANGE");
}
