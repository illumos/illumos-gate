/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of California at Berkeley. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission.  This software
 * is provided ``as is'' without express or implied warranty.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ethernet.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>

/*
 * Store and retrieve local individual ethernet address.
 * This is typically initialized (called with 'hint' nonnull)
 * by the boot code.
 */

static kmutex_t localetheraddr_lock;   /* Perimeter lock for localetheraddr */

int
localetheraddr(struct ether_addr *hint, struct ether_addr *result)
{
	static int found = 0;
	static	struct	ether_addr	addr;

	mutex_enter(&localetheraddr_lock);
	if (!found) {
		if (hint == NULL) {
			mutex_exit(&localetheraddr_lock);
			return (0);
		}
		found = 1;
		addr = *hint;
		cmn_err(CE_CONT, "?Ethernet address = %s\n",
		    ether_sprintf(&addr));
	}
	if (result != NULL)
		*result = addr;
	mutex_exit(&localetheraddr_lock);
	return (1);
}

/*
 * Convert Ethernet address to printable (loggable) representation.
 *
 * XXX This is not MT-safe, but its only race is for the "etherbuf".
 */
char *
ether_sprintf(struct ether_addr *addr)
{
	static char etherbuf[18];

	(void) snprintf(etherbuf, sizeof (etherbuf), "%x:%x:%x:%x:%x:%x",
	    addr->ether_addr_octet[0], addr->ether_addr_octet[1],
	    addr->ether_addr_octet[2], addr->ether_addr_octet[3],
	    addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
	return (etherbuf);
}

static int
hexval(char dig)
{
	if ('0' <= dig && dig <= '9') {
		return (dig - '0');
	} else if ('a' <= dig && dig <= 'f') {
		return (dig - 'a' + 10);
	} else if ('A' <= dig && dig <= 'F') {
		return (dig - 'A' + 10);
	} else {
		return (-1);
	}
}

/*
 * Convert Ethernet address from ascii to binary form.
 * Return number of bytes written.
 */
int
ether_aton(char *addr, uchar_t *macaddr)
{
	int i = 0;
	uint_t val = 0;
	char *cp = addr;

	while (*cp != 0 && i < 6) {
		if (*cp == ':') {
			macaddr[i++] = val;
			val = 0;
			cp++;
			continue;
		}

		val = (val << 4) | hexval(*cp++);
	}
	macaddr[i] = val;
	return (i + 1);
}
