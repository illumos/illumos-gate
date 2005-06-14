/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Socket-specific definitions
 */

#ifndef _SOCKET_INET_H
#define	_SOCKET_INET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Network configuration protocol definitions */
enum nc_type { NCT_BOOTP_DHCP, NCT_RARP_BOOTPARAMS, NCT_MANUAL };
struct nct_t {
	char		*p_name;
	enum nc_type	p_id;
};
#define	NCT_DEFAULT		NCT_RARP_BOOTPARAMS
#define	NCT_BUFSIZE		(64)
extern struct nct_t	nct[];
extern int		nct_entries;

/*
 * Dynamic/private ports can be allocated in the range of 49152-65535.
 * Source: IANA (www.iana.org) port numbers.
 */
#define	IPPORT_DYNAMIC_START	49152

extern int dontroute;

extern int socket_read(int, void *, size_t, int);
extern int socket_write(int, const void *, size_t, struct sockaddr_in *);
extern int socket_close(int);

extern int get_netconfig_strategy(void);
extern in_port_t get_source_port(boolean_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SOCKET_INET_H */
