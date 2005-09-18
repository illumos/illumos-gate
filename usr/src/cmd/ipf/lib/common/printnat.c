/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Added redirect stuff and a variety of bug fixes. (mcn@EnGarde.com)
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ipf.h"
#include "kmem.h"


#if !defined(lint)
static const char rcsid[] = "@(#)$Id: printnat.c,v 1.14 2003/04/13 06:39:16 darrenr Exp $";
#endif


void printactivenat(nat, opts)
nat_t *nat;
int opts;
{
	u_int hv1, hv2;

	printf("%s", getnattype(nat->nat_ptr));

	if (nat->nat_flags & SI_CLONE)
		printf(" CLONE");

	printf(" %-15s", inet_ntoa(nat->nat_inip));

	if ((nat->nat_flags & IPN_TCPUDP) != 0)
		printf(" %-5hu", ntohs(nat->nat_inport));

	printf(" <- -> %-15s",inet_ntoa(nat->nat_outip));

	if ((nat->nat_flags & IPN_TCPUDP) != 0)
		printf(" %-5hu", ntohs(nat->nat_outport));

	printf(" [%s", inet_ntoa(nat->nat_oip));
	if ((nat->nat_flags & IPN_TCPUDP) != 0)
		printf(" %hu", ntohs(nat->nat_oport));
	printf("]");

	if (opts & OPT_VERBOSE) {
		printf("\n\tage %lu use %hu sumd %s/",
			nat->nat_age, nat->nat_use, getsumd(nat->nat_sumd[0]));
                if ((nat->nat_flags & SI_WILDP) == 0) {
                        hv1 = NAT_HASH_FN(nat->nat_inip.s_addr,
                                        nat->nat_inport, 0xffffffff);
                        hv1 = NAT_HASH_FN(nat->nat_oip.s_addr,
                                        hv1 + nat->nat_oport, NAT_TABLE_SZ);
                        hv2 = NAT_HASH_FN(nat->nat_outip.s_addr,
                                        nat->nat_outport, 0xffffffff);
                        hv2 = NAT_HASH_FN(nat->nat_oip.s_addr,
                                        hv2 + nat->nat_oport, NAT_TABLE_SZ);
                } else {
                        hv1 = NAT_HASH_FN(nat->nat_inip.s_addr, 0,
                                        0xffffffff);
                        hv1 = NAT_HASH_FN(nat->nat_oip.s_addr, hv1,
                                        NAT_TABLE_SZ);
                        hv2 = NAT_HASH_FN(nat->nat_outip.s_addr, 0,
                                        0xffffffff);
                        hv2 = NAT_HASH_FN(nat->nat_oip.s_addr, hv2,
                                        NAT_TABLE_SZ);
                }
		printf("%s pr %u bkt %d/%d flags %x\n",
			getsumd(nat->nat_sumd[1]), nat->nat_p,
			hv1, hv2, nat->nat_flags);
		printf("\tifp %s", getifname(nat->nat_ifps[0]));
		printf(",%s ", getifname(nat->nat_ifps[1]));
#ifdef	USE_QUAD_T
		printf("bytes %qu/%qu pkts %qu/%qu",
			(unsigned long long)nat->nat_bytes[0],
			(unsigned long long)nat->nat_bytes[1],
			(unsigned long long)nat->nat_pkts[0],
			(unsigned long long)nat->nat_pkts[1]);
#else
		printf("bytes %lu/%lu pkts %lu/%lu", nat->nat_bytes[0],
			nat->nat_bytes[1], nat->nat_pkts[0], nat->nat_pkts[1]);
#endif
#if SOLARIS
		printf(" %lx", nat->nat_ipsumd);
#endif
	}

	putchar('\n');
	if (nat->nat_aps)
		printaps(nat->nat_aps, opts);
}


/*
 * Print out a NAT rule
 */
void printnat(np, opts)
ipnat_t *np;
int opts;
{
	struct	protoent	*pr;
	struct	servent	*sv;
	int	bits;

	pr = getprotobynumber(np->in_p);

	switch (np->in_redir)
	{
	case NAT_REDIRECT :
		printf("rdr");
		break;
	case NAT_MAP :
		printf("map");
		break;
	case NAT_MAPBLK :
		printf("map-block");
		break;
	case NAT_BIMAP :
		printf("bimap");
		break;
	default :
		fprintf(stderr, "unknown value for in_redir: %#x\n",
			np->in_redir);
		break;
	}

	printf(" %s", np->in_ifnames[0]);
	if ((np->in_ifnames[1][0] != '\0') &&
	    (strncmp(np->in_ifnames[0], np->in_ifnames[1], LIFNAMSIZ) != 0)) {
		printf(",%s ", np->in_ifnames[1]);
	}
	putchar(' ');

	if (np->in_flags & IPN_FILTER) {
		if (np->in_flags & IPN_NOTSRC)
			printf("! ");
		printf("from ");
		if (np->in_redir == NAT_REDIRECT) {
			printhostmask(4, (u_32_t *)&np->in_srcip,
				      (u_32_t *)&np->in_srcmsk);
		} else {
			printhostmask(4, (u_32_t *)&np->in_inip,
				      (u_32_t *)&np->in_inmsk);
		}
		if (np->in_scmp)
			printportcmp(np->in_p, &np->in_tuc.ftu_src);

		if (np->in_flags & IPN_NOTDST)
			printf(" !");
		printf(" to ");
		if (np->in_redir == NAT_REDIRECT) {
			printhostmask(4, (u_32_t *)&np->in_outip,
				      (u_32_t *)&np->in_outmsk);
		} else {
			printhostmask(4, (u_32_t *)&np->in_srcip,
				      (u_32_t *)&np->in_srcmsk);
		}
		if (np->in_dcmp)
			printportcmp(np->in_p, &np->in_tuc.ftu_dst);
	}

	if (np->in_redir == NAT_REDIRECT) {
		if (!(np->in_flags & IPN_FILTER)) {
			printf("%s", inet_ntoa(np->in_out[0].in4));
			bits = count4bits(np->in_outmsk);
			if (bits != -1)
				printf("/%d ", bits);
			else
				printf("/%s ", inet_ntoa(np->in_out[1].in4));
			printf("port %d", ntohs(np->in_pmin));
			if (np->in_pmax != np->in_pmin)
				printf("-%d", ntohs(np->in_pmax));
		}
		printf(" -> %s", inet_ntoa(np->in_in[0].in4));
		if (np->in_flags & IPN_SPLIT)
			printf(",%s", inet_ntoa(np->in_in[1].in4));
		if (np->in_inip == 0) {
			bits = count4bits(np->in_inmsk);
			printf("/%d", bits);
		}
		printf(" port %d", ntohs(np->in_pnext));
		if ((np->in_flags & IPN_TCPUDP) == IPN_TCPUDP)
			printf(" tcp/udp");
		else if ((np->in_flags & IPN_TCP) == IPN_TCP)
			printf(" tcp");
		else if ((np->in_flags & IPN_UDP) == IPN_UDP)
			printf(" udp");
		else if (np->in_p == 0)
			printf(" ip");
		else if (pr != NULL)
			printf(" %s", pr->p_name);
		else
			printf(" %d", np->in_p);
		if (np->in_flags & IPN_ROUNDR)
			printf(" round-robin");
		if (np->in_flags & IPN_FRAG)
			printf(" frag");
		if (np->in_age[0] != 0 || np->in_age[1] != 0) {
			printf(" age %d/%d", np->in_age[0], np->in_age[1]);
		}
		if (np->in_flags & IPN_STICKY)
			printf(" sticky");
		if (np->in_mssclamp != 0)
			printf(" mssclamp %d", np->in_mssclamp);
		if (*np->in_plabel != '\0') {
			printf(" proxy %.*s/", (int)sizeof(np->in_plabel),
				np->in_plabel);
			if (pr != NULL)
				fputs(pr->p_name, stdout);
			else
				printf("%d", np->in_p);
		}
		printf("\n");
		if (opts & OPT_DEBUG)
			printf("\tspc %lu flg %#x max %u use %d\n",
			       np->in_space, np->in_flags,
			       np->in_pmax, np->in_use);
	} else {
		if (!(np->in_flags & IPN_FILTER)) {
			printf("%s/", inet_ntoa(np->in_in[0].in4));
			bits = count4bits(np->in_inmsk);
			if (bits != -1)
				printf("%d", bits);
			else
				printf("%s", inet_ntoa(np->in_in[1].in4));
		}
		printf(" -> ");
		if (np->in_flags & IPN_IPRANGE) {
			printf("range %s-", inet_ntoa(np->in_out[0].in4));
			printf("%s", inet_ntoa(np->in_out[1].in4));
		} else {
			printf("%s/", inet_ntoa(np->in_out[0].in4));
			bits = count4bits(np->in_outmsk);
			if (bits != -1)
				printf("%d", bits);
			else
				printf("%s", inet_ntoa(np->in_out[1].in4));
		}
		if (*np->in_plabel != '\0') {
			printf(" proxy port");
			if (np->in_dcmp != 0)
				np->in_dport = htons(np->in_dport);
			if (np->in_dport != 0) {
				if (pr != NULL)
					sv = getservbyport(np->in_dport,
							   pr->p_name);
				else
					sv = getservbyport(np->in_dport, NULL);
				if (sv != NULL)
					printf(" %s", sv->s_name);
				else
					printf(" %hu", ntohs(np->in_dport));
			}
			printf(" %.*s/", (int)sizeof(np->in_plabel),
				np->in_plabel);
			if (pr != NULL)
				fputs(pr->p_name, stdout);
			else
				printf("%d", np->in_p);
		} else if (np->in_redir == NAT_MAPBLK) {
			if ((np->in_pmin == 0) &&
			    (np->in_flags & IPN_AUTOPORTMAP))
				printf(" ports auto");
			else
				printf(" ports %d", np->in_pmin);
			if (opts & OPT_DEBUG)
				printf("\n\tip modulous %d", np->in_pmax);
		} else if (np->in_pmin || np->in_pmax) {
			printf(" portmap");
			if ((np->in_flags & IPN_TCPUDP) == IPN_TCPUDP)
				printf(" tcp/udp");
			else if (np->in_flags & IPN_TCP)
				printf(" tcp");
			else if (np->in_flags & IPN_UDP)
				printf(" udp");
			if (np->in_flags & IPN_AUTOPORTMAP) {
				printf(" auto");
				if (opts & OPT_DEBUG)
					printf(" [%d:%d %d %d]",
					       ntohs(np->in_pmin),
					       ntohs(np->in_pmax),
					       np->in_ippip, np->in_ppip);
			} else {
				printf(" %d:%d", ntohs(np->in_pmin),
				       ntohs(np->in_pmax));
			}
		}
		if (np->in_flags & IPN_FRAG)
			printf(" frag");
		if (np->in_age[0] != 0 || np->in_age[1] != 0) {
			printf(" age %d/%d", np->in_age[0], np->in_age[1]);
		}
		if (np->in_mssclamp != 0)
			printf(" mssclamp %d", np->in_mssclamp);
		printf("\n");
		if (opts & OPT_DEBUG) {
			struct in_addr nip;

			nip.s_addr = htonl(np->in_nextip.s_addr);

			printf("\tspace %lu nextip %s pnext %d", np->in_space,
			       inet_ntoa(nip), np->in_pnext);
			printf(" flags %x use %u\n",
			       np->in_flags, np->in_use);
		}
	}
}
