/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_IFCONFIG_H
#define	_IFCONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libdlpi.h>

/*
 * return values for (af_getaddr)() from in_getprefixlen()
 */
#define	BAD_ADDR	-1	/* prefix is invalid */
#define	NO_PREFIX	-2	/* no prefix was found */

#define	MAX_MODS	9	/* max modules that can be pushed on intr */

extern int	debug;
extern uid_t	euid;

extern void	Perror0(char *);
extern void	Perror0_exit(char *);
extern void	Perror2(char *, char *);
extern void	Perror2_exit(char *, char *);

extern int	doifrevarp(char *, struct sockaddr_in *);
extern int	getnetmaskbyaddr(struct in_addr, struct in_addr *);

extern int	dlpi_set_address(char *, uchar_t *, int);
extern void	dlpi_print_address(char *);

extern int	do_dad(char *, struct sockaddr_in6 *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IFCONFIG_H */
