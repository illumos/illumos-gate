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
 */

#ifndef	UTIL_H
#define	UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <libinetutil.h>
#include <dhcpagent_ipc.h>

/*
 * general utility functions which have no better home.  see util.c
 * for documentation on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

struct ifslist;				/* forward declaration */

typedef int64_t monosec_t;		/* see README for details */

/* conversion functions */
const char	*pkt_type_to_string(uchar_t);
const char	*monosec_to_string(monosec_t);
time_t		monosec_to_time(monosec_t);
uchar_t		dlpi_to_arp(uchar_t);

/* shutdown handlers */
void		graceful_shutdown(int);
void		inactivity_shutdown(iu_tq_t *, void *);

/* acknak handlers */
int		register_acknak(struct ifslist *);
int		unregister_acknak(struct ifslist *);

/* ipc functions */
void		send_error_reply(dhcp_ipc_request_t *, int, int *);
void		send_ok_reply(dhcp_ipc_request_t *, int *);
void		send_data_reply(dhcp_ipc_request_t *, int *, int,
		    dhcp_data_type_t, void *, size_t);

/* miscellaneous */
int		add_default_route(const char *, struct in_addr *);
int		del_default_route(const char *, struct in_addr *);
int		daemonize(void);
monosec_t	monosec(void);
void		print_server_msg(struct ifslist *, DHCP_OPT *);
int		bind_sock(int, in_port_t, in_addr_t);
const char	*iffile_to_hostname(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* UTIL_H */
