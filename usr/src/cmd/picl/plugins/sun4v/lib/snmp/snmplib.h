/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SNMPLIB_H
#define	_SNMPLIB_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef USE_SOCKETS
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/*
 * Groups of OIDs are registered with the picl snmp library to provide
 * the library with a hint as to the set of OIDs to do GETBULK requests
 */
typedef struct oidgroup {
	struct oidgroup *next;
	char		*oidstrs;
	int		n_oids;
	int		is_volatile;
} oidgroup_t;

/*
 * Private (opaque to clients) handle to manage per-client snmp data
 */
struct picl_snmphdl {
	oidgroup_t	*group;
#ifdef USE_SOCKETS
	struct sockaddr_in	agent_addr;
#endif
	int		fd;
};

#define	MIBCACHE_BLK_SZ		256
#define	MIBCACHE_BLK_SHIFT	8
#define	REFRESHQ_BLK_SZ		256
#define	REFRESHQ_BLK_SHIFT	8

#define	HRTIME_SCALE		10LL	/* internal time in 10s of seconds */
#define	MAX_INCACHE_TIME	(300 / HRTIME_SCALE)
#define	MAX_INT_LEN		16	/* #chars to print */

#define	DS_SNMP_DRIVER   	"/devices/pseudo/ds_snmp@0:ds_snmp"

#ifdef	__cplusplus
}
#endif

#endif	/* _SNMPLIB_H */
