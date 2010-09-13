/*
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Common structure pcb for internet protocol implementation.
 * Here are stored pointers to local and foreign host table
 * entries, local and foreign socket numbers, and pointers
 * up (to a socket structure) and down (to a protocol-specific)
 * control block.
 */

#ifndef	_NETINET_IN_PCB_H
#define	_NETINET_IN_PCB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* in_pcb.h 1.7 88/08/19 SMI; from UCB 7.1 6/5/86	*/

#ifdef	__cplusplus
extern "C" {
#endif

struct inpcb {
	struct	inpcb *inp_next, *inp_prev;	/* pointers to other pcb's */
	struct	inpcb *inp_head;	/* pointer back to chain of inpcb's */
					/* for this protocol */
	struct	in_addr inp_faddr;	/* foreign host table entry */
	ushort_t inp_fport;		/* foreign port */
	struct	in_addr inp_laddr;	/* local host table entry */
	ushort_t inp_lport;		/* local port */
	struct	socket *inp_socket;	/* back pointer to socket */
	caddr_t	inp_ppcb;		/* pointer to per-protocol pcb */
	struct	route inp_route;	/* placeholder for routing entry */
	struct	mbuf *inp_options;	/* IP options */
};

#define	INPLOOKUP_WILDCARD	1
#define	INPLOOKUP_SETLOCAL	2

#define	sotoinpcb(so)	((struct inpcb *)(so)->so_pcb)

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IN_PCB_H */
