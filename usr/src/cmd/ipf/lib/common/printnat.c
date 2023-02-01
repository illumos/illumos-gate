/*
 * Copyright (C) 2002-2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Added redirect stuff and a variety of bug fixes. (mcn@EnGarde.com)
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"
#include "kmem.h"


#if !defined(lint)
static const char rcsid[] = "@(#)$Id: printnat.c,v 1.22.2.9 2005/06/12 07:18:43 darrenr Exp $";
#endif

/*
 * Print out a NAT rule
 */
void printnat(np, opts)
ipnat_t *np;
int opts;
{
	struct	protoent	*pr;
	int	bits, af;
	char	ipbuf[INET6_ADDRSTRLEN];
	void	*ptr;

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
			printhostmask(np->in_v, (u_32_t *)&np->in_src[0],
				      (u_32_t *)&np->in_src[1]);
		} else {
			printhostmask(np->in_v, (u_32_t *)&np->in_in[0],
				      (u_32_t *)&np->in_in[1]);
		}
		if (np->in_scmp)
			printportcmp(np->in_p, &np->in_tuc.ftu_src);

		if (np->in_flags & IPN_NOTDST)
			printf(" !");
		printf(" to ");
		if (np->in_redir == NAT_REDIRECT) {
			printhostmask(np->in_v, (u_32_t *)&np->in_out[0],
				      (u_32_t *)&np->in_out[1]);
		} else {
			printhostmask(np->in_v, (u_32_t *)&np->in_src[0],
				      (u_32_t *)&np->in_src[1]);
		}
		if (np->in_dcmp)
			printportcmp(np->in_p, &np->in_tuc.ftu_dst);
	}

	if (np->in_v == 4)
		af = AF_INET;
	else if (np->in_v == 6)
		af = AF_INET6;
	else
		af = 0;

	if (np->in_redir == NAT_REDIRECT) {
		if (!(np->in_flags & IPN_FILTER)) {
			ptr = (void *)(u_32_t *)&np->in_out[0];
			printf("%s", inet_ntop(af, ptr, ipbuf, sizeof (ipbuf)));
			printmask(np->in_v, (u_32_t *)&np->in_out[1]);
			if (np->in_flags & IPN_TCPUDP) {
				printf(" port %d", ntohs(np->in_pmin));
				if (np->in_pmax != np->in_pmin)
					printf("-%d", ntohs(np->in_pmax));
			}
		}
		printf(" -> ");
		ptr = (void *)(u_32_t *)&np->in_in[0];
		printf("%s", inet_ntop(af, ptr, ipbuf, sizeof (ipbuf)));
		if (np->in_flags & IPN_SPLIT) {
			printf(",");
			ptr = (void *)(u_32_t *)&np->in_in[1];
			printf("%s", inet_ntop(af, ptr, ipbuf, sizeof (ipbuf)));
		}
		if (((np->in_v == 4) && (np->in_inip == 0)) ||
		    ((np->in_v == 6) && IP6_ISZERO(&np->in_in[0])))
			printmask(np->in_v, (u_32_t *)&np->in_in[1]);

		if (np->in_flags & IPN_TCPUDP) {
			if ((np->in_flags & IPN_FIXEDDPORT) != 0)
				printf(" port = %d", ntohs(np->in_pnext));
			else
				printf(" port %d", ntohs(np->in_pnext));
		}
		putchar(' ');
		printproto(pr, np->in_p, np);
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
		if (*np->in_plabel != '\0')
			printf(" proxy %.*s", (int)sizeof (np->in_plabel),
				np->in_plabel);
		if (np->in_tag.ipt_tag[0] != '\0')
			printf(" tag %-.*s", IPFTAG_LEN, np->in_tag.ipt_tag);
		printf("\n");
		if (opts & OPT_DEBUG)
			printf("\tpmax %u\n", np->in_pmax);
	} else {
		if (!(np->in_flags & IPN_FILTER)) {
			ptr = (void *)(u_32_t *)&np->in_in[0];
			printf("%s", inet_ntop(af, ptr, ipbuf, sizeof (ipbuf)));
			printmask(np->in_v, (u_32_t *)&np->in_in[1]);
		}
		printf(" -> ");
		if (np->in_flags & IPN_IPRANGE) {
			printf("range ");
			ptr = (void *)(u_32_t *)&np->in_out[0];
			printf("%s", inet_ntop(af, ptr, ipbuf, sizeof (ipbuf)));
			printf("-");
			ptr = (void *)(u_32_t *)&np->in_out[1];
			printf("%s", inet_ntop(af, ptr, ipbuf, sizeof (ipbuf)));
		} else {
			ptr = (void *)(u_32_t *)&np->in_out[0];
			printf("%s", inet_ntop(af, ptr, ipbuf, sizeof (ipbuf)));
			printmask(np->in_v, (u_32_t *)&np->in_out[1]);
		}
		if (*np->in_plabel != '\0') {
			printf(" proxy port ");
			if (np->in_dcmp != 0)
				np->in_dport = htons(np->in_dport);
			if (np->in_dport != 0) {
				char *s;

				s = portname(np->in_p, ntohs(np->in_dport));
				if (s != NULL)
					fputs(s, stdout);
				else
					fputs("???", stdout);
			}
			printf(" %.*s/", (int)sizeof (np->in_plabel),
				np->in_plabel);
			printproto(pr, np->in_p, NULL);
		} else if (np->in_redir == NAT_MAPBLK) {
			if ((np->in_pmin == 0) &&
			    (np->in_flags & IPN_AUTOPORTMAP))
				printf(" ports auto");
			else
				printf(" ports %d", np->in_pmin);
			if (opts & OPT_DEBUG)
				printf("\n\tip modulous %d", np->in_pmax);
		} else if (np->in_pmin || np->in_pmax) {
			if (np->in_flags & IPN_ICMPQUERY) {
				printf(" icmpidmap ");
			} else {
				printf(" portmap ");
			}
			printproto(pr, np->in_p, np);
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
		} else if (np->in_flags & IPN_TCPUDP || np->in_p) {
			putchar(' ');
			printproto(pr, np->in_p, np);
		}

		if (np->in_flags & IPN_FRAG)
			printf(" frag");
		if (np->in_age[0] != 0 || np->in_age[1] != 0) {
			printf(" age %d/%d", np->in_age[0], np->in_age[1]);
		}
		if (np->in_mssclamp != 0)
			printf(" mssclamp %d", np->in_mssclamp);
		if (np->in_tag.ipt_tag[0] != '\0')
			printf(" tag %s", np->in_tag.ipt_tag);
		if (np->in_flags & IPN_SEQUENTIAL)
			printf(" sequential");
		printf("\n");
		if (opts & OPT_DEBUG) {
			struct in_addr nip;

			nip.s_addr = htonl(np->in_nextip.s_addr);

			printf("\tnextip %s pnext %d\n",
			       inet_ntoa(nip), np->in_pnext);
		}
	}

	if (opts & OPT_DEBUG) {
		printf("\tspace %lu use %u hits %lu flags %#x proto %d hv %d\n",
			np->in_space, np->in_use, np->in_hits,
			np->in_flags, np->in_p, np->in_hv);
		printf("\tifp[0] %p ifp[1] %p apr %p\n",
			np->in_ifps[0], np->in_ifps[1], np->in_apr);
		printf("\ttqehead %p/%p comment %p\n",
			np->in_tqehead[0], np->in_tqehead[1], np->in_comment);
	}
}
