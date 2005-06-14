/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NETINET_TCP_DEBUG_H
#define	_NETINET_TCP_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* tcp_debug.h 1.8 88/08/19 SMI; from UCB 7.1 6/5/86	*/

#ifdef	__cplusplus
extern "C" {
#endif

struct	tcp_debug {
	n_time	td_time;
	short	td_act;
	short	td_ostate;
	caddr_t	td_tcb;
	struct	tcpiphdr td_ti;
	short	td_req;
	struct	tcpcb td_cb;
};

#define	TA_INPUT 	0
#define	TA_OUTPUT	1
#define	TA_USER		2
#define	TA_RESPOND	3
#define	TA_DROP		4

#ifdef TANAMES
char	*tanames[] =
	{ "input", "output", "user", "respond", "drop" };
#endif

#define	TCP_NDEBUG 100

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_TCP_DEBUG_H */
