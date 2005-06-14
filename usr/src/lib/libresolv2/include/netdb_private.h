/*
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NETDB_PRIVATE_H
#define	_NETDB_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Constants defined by the ISC for BIND 8.2, but which do not appear
 * in RFC 2553 (hence, aren't suitable for inclusion in <netdb.h>).
 */

/*
 * Error return codes from getaddrinfo()
 */

#define		EAI_BADHINTS	12
#define		EAI_PROTOCOL	13
#define		EAI_MAX		14

/*
 * Flag values for getaddrinfo()
 */

#define		AI_MASK		0x00000007

/*
 * Scope delimit character
 */
#define	SCOPE_DELIMITER '%'

/*
 * XXX
 * Various data types (hostent_data, netent_data, protoent_data, servent_data)
 * only defined for __osf__ or __hpux => we don't need them ??
 */

#endif	/* _NETDB_PRIVATE_H */
