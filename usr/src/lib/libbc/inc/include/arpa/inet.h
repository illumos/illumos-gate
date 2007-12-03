/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * External definitions for
 * functions in inet(3N)
 */

#ifndef	_arpa_inet_h
#define	_arpa_inet_h

unsigned long inet_addr();
char	*inet_ntoa();
/*
 * With the introduction of CIDR the following
 * routines are now considered to be Obsolete
 */
struct	in_addr inet_makeaddr();
unsigned long inet_network();

#endif	/* !_arpa_inet_h */
