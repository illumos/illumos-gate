/*
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 1980, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NET_AF_H
#define	_NET_AF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* af.h 1.10 88/08/19 SMI; from UCB 7.1	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Address family routines,
 * used in handling generic sockaddr structures.
 *
 * Hash routine is called
 *	af_hash(addr, h);
 *	struct sockaddr *addr; struct afhash *h;
 * producing an afhash structure for addr.
 *
 * Netmatch routine is called
 *	af_netmatch(addr1, addr2);
 * where addr1 and addr2 are sockaddr *.  Returns 1 if network
 * values match, 0 otherwise.
 */
struct afswitch {
	int	(*af_hash)();
	int	(*af_netmatch)();
};

struct afhash {
	uint_t	afh_hosthash;
	uint_t	afh_nethash;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _NET_AF_H */
