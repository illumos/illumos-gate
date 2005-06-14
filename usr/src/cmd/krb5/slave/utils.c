/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <k5-int.h>
#include <socket-utils.h>
#include <inet/ip.h>

/*
 * convert a sockaddr_storage address to a krb5_address
 * Returns address of krbap if success, NULL if error.
 */

krb5_address *
cvtkaddr(struct sockaddr_storage *ss, krb5_address *krbap)
{
	switch (ss->ss_family) {
		case AF_INET:
			krbap->contents = (krb5_octet *)
				    malloc(sizeof (ss2sin(ss)->sin_addr));
			if (krbap->contents == NULL)
				return (NULL);
			memcpy((char *)krbap->contents,
					(char *)&(ss2sin(ss)->sin_addr),
					sizeof (ss2sin(ss)->sin_addr));
			krbap->addrtype = ADDRTYPE_INET;
			krbap->length = sizeof (ss2sin(ss)->sin_addr);
			return (krbap);
		case AF_INET6:
			if (IN6_IS_ADDR_V4MAPPED(&ss2sin6(ss)->sin6_addr)) {
				/* coerce to IPv4 address */
				krbap->contents = (krb5_octet *)
					malloc(IPV4_ADDR_LEN);
				if (krbap->contents == NULL)
					return (NULL);
				IN6_V4MAPPED_TO_IPADDR(
					&(ss2sin6(ss)->sin6_addr),
					*(ipaddr_t *)(krbap->contents));
				krbap->addrtype = ADDRTYPE_INET;
				krbap->length = IPV4_ADDR_LEN;
			} else {
				krbap->contents = (krb5_octet *)
					malloc(sizeof (ss2sin6(ss)->sin6_addr));
				if (krbap->contents == NULL)
					return (NULL);
				memcpy((char *)krbap->contents,
					(char *)&ss2sin6(ss)->sin6_addr,
					sizeof (ss2sin6(ss)->sin6_addr));
				krbap->addrtype = ADDRTYPE_INET6;
				krbap->length = sizeof (ss2sin6(ss)->sin6_addr);
			}
			return (krbap);
		default:
			return (NULL);
	}
}
