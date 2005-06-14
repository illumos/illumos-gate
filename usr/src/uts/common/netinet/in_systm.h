/*
 * Copyright (c) 1997-1998, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NETINET_IN_SYSTM_H
#define	_NETINET_IN_SYSTM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* in_systm.h 1.8 88/08/19 SMI; from UCB 7.1 6/5/86	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Legacy "network types" -- these are provided for backwards compatibility
 * only; new code should use uint16_t and uint32_t instead.
 */
typedef uint16_t n_short;	/* short as received from the net */
typedef uint32_t n_long;	/* long as received from the net */
typedef uint32_t n_time;	/* ms since 00:00 GMT, byte rev */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IN_SYSTM_H */
