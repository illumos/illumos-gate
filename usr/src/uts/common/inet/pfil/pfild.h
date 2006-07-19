/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

/*
 * STREAMS control messages used to communicate between pfild and pfil.
 * Messages are sent down to /dev/pfil as M_PROTO->M_DATA.
 * M_PROTO block contains uint32_t command code.
 * M_DATA block contains [an array of] the corresponding data structure.
 */

/*
 * Data structure used to pass interface configuration information from
 * pfild to the pfil kernel module.
 */
#define	PFILCMD_IFADDRS 1
struct pfil_ifaddrs {
	char name[LIFNAMSIZ];
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} localaddr;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} netmask;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} broadaddr;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} dstaddr;
	uint_t mtu;
};

/*
 * Data structure used to pass interface valid source address set information
 * from pfild to the pfil kernel module.
 */
#define	PFILCMD_IFADDRSET 2
struct pfil_ifaddrset {
	char name[LIFNAMSIZ];
	uint8_t af;
	uint32_t nspans;
};
struct pfil_v4span {
	uint32_t first, last;		/* in host byte order! */
};
struct pfil_v6span {
	struct in6_addr first, last;
};
