/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_INET_PRIVATE_H
#define	_INET_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Functions defined by the ISC for BIND 8.2, but which do not appear
 * in RFC 2553 (hence, aren't suitable for inclusion in <inet.h>).
 */

#ifdef __STDC__
#ifndef __P
#define	__P(x)	x
#endif
#else
#ifndef __P
#define	__P(x)	()
#endif
#endif /* __STDC__ */

char *	inet_net_ntop __P((int, const void *, int, char *, size_t));
int	inet_net_pton __P((int, const char *, void *, size_t));
u_int	inet_nsap_addr __P((const char *, u_char *, int));
char *	inet_nsap_ntoa __P((int, const u_char *, char *));

#endif	/* _INET_PRIVATE_H */
