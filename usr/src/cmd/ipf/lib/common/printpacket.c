/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: printpacket.c,v 1.12 2002/11/02 13:27:29 darrenr Exp $
 */

#include "ipf.h"

#ifndef	IP_OFFMASK
# define	IP_OFFMASK	0x3fff
#endif


void printpacket(ip)
struct ip *ip;
{
	struct	tcphdr	*tcp;
	u_short len;

	if (IP_V(ip) == 6)
		len = ntohs(((u_short *)ip)[2]) + 40;
	else
		len = ntohs(ip->ip_len);

	if ((opts & OPT_HEX) == OPT_HEX) {
		u_char *s;
		int i;

		for (s = (u_char *)ip, i = 0; i < len; i++) {
			printf("%02x", *s++ & 0xff);
			if (len - i > 1) {
				i++;
				printf("%02x", *s++ & 0xff);
			}
			putchar(' ');
		}
		putchar('\n');
		return;
	}

	if (IP_V(ip) == 6) {
		printpacket6(ip);
		return;
	}

	tcp = (struct tcphdr *)((char *)ip + (IP_HL(ip) << 2));
	printf("ip %d(%d) %d", ntohs(ip->ip_len), IP_HL(ip) << 2, ip->ip_p);
	if (ip->ip_off & IP_OFFMASK)
		printf(" @%d", ip->ip_off << 3);
	printf(" %s", inet_ntoa(ip->ip_src));
	if (!(ip->ip_off & IP_OFFMASK))
		if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP)
			printf(",%d", ntohs(tcp->th_sport));
	printf(" > ");
	printf("%s", inet_ntoa(ip->ip_dst));
	if (!(ip->ip_off & IP_OFFMASK)) {
		if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP)
			printf(",%d", ntohs(tcp->th_dport));
		if ((ip->ip_p == IPPROTO_TCP) && (tcp->th_flags != 0)) {
			putchar(' ');
			if (tcp->th_flags & TH_FIN)
				putchar('F');
			if (tcp->th_flags & TH_SYN)
				putchar('S');
			if (tcp->th_flags & TH_RST)
				putchar('R');
			if (tcp->th_flags & TH_PUSH)
				putchar('P');
			if (tcp->th_flags & TH_ACK)
				putchar('A');
			if (tcp->th_flags & TH_URG)
				putchar('U');
			if (tcp->th_flags & TH_ECN)
				putchar('E');
			if (tcp->th_flags & TH_CWR)
				putchar('C');
		}
	}

	putchar('\n');
}
