/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Variables related to this implementation
 * of the internet control message protocol.
 */

#ifndef	_NETINET_ICMP_VAR_H
#define	_NETINET_ICMP_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* icmp_var.h 1.10 88/08/19 SMI; from UCB 7.2 1/13/87	*/

#ifdef	__cplusplus
extern "C" {
#endif

struct	icmpstat {
/* statistics related to icmp packets generated */
	int	icps_error;		/* # of calls to icmp_error */
	int	icps_oldshort;		/* no error 'cuz old ip too short */
	int	icps_oldicmp;		/* no error 'cuz old was icmp */
	int	icps_outhist[ICMP_MAXTYPE + 1];
/* statistics related to input messages processed */
	int	icps_badcode;		/* icmp_code out of range */
	int	icps_tooshort;		/* packet < ICMP_MINLEN */
	int	icps_checksum;		/* bad checksum */
	int	icps_badlen;		/* calculated bound mismatch */
	int	icps_reflect;		/* number of responses */
	int	icps_inhist[ICMP_MAXTYPE + 1];
};

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_ICMP_VAR_H */
