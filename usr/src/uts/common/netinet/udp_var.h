/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * UDP kernel structures and variables.
 */

#ifndef	_NETINET_UDP_VAR_H
#define	_NETINET_UDP_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* udp_var.h 1.8 88/08/19 SMI; from UCB 7.1 6/5/86	*/

#ifdef	__cplusplus
extern "C" {
#endif

struct	udpiphdr {
	struct 	ipovly ui_i;		/* overlaid ip structure */
	struct	udphdr ui_u;		/* udp header */
};
#define	ui_next		ui_i.ih_next
#define	ui_prev		ui_i.ih_prev
#define	ui_x1		ui_i.ih_x1
#define	ui_pr		ui_i.ih_pr
#define	ui_len		ui_i.ih_len
#define	ui_src		ui_i.ih_src
#define	ui_dst		ui_i.ih_dst
#define	ui_sport	ui_u.uh_sport
#define	ui_dport	ui_u.uh_dport
#define	ui_ulen		ui_u.uh_ulen
#define	ui_sum		ui_u.uh_sum

struct	udpstat {
	int	udps_hdrops;
	int	udps_badsum;
	int	udps_badlen;
	int	udps_fullsock;
};

#define	UDP_TTL		30		/* time to live for UDP packets */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_UDP_VAR_H */
