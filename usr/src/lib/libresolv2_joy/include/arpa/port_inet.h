/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * All rights reserved.
 */

#ifndef _ARPA_PORT_INET_H
#define	_ARPA_PORT_INET_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * these are libresolv2 functions that were made local in previous versions
 * we rename them res_* because they conflict with libnsl or libsocket
 */

#define	inet_lnaof res_inet_lnaof  /* libsocket */
ulong_t inet_lnaof(struct in_addr in);

#define	inet_makeaddr res_inet_makeaddr  /* libsocket */
struct in_addr inet_makeaddr(ulong_t net, ulong_t host);

#define	inet_netof res_inet_netof  /* libnsl */
ulong_t inet_netof(struct in_addr in);

#define	inet_network res_inet_network  /* libsocket */
ulong_t inet_network(register const char *cp);

#ifdef	__cplusplus
}
#endif



#endif /* _ARPA_PORT_INET_H */
