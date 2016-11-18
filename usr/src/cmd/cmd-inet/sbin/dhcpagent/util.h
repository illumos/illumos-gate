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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 */

#ifndef	UTIL_H
#define	UTIL_H

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp6.h>
#include <libinetutil.h>
#include <dhcpagent_ipc.h>

#include "common.h"
#include "packet.h"

/*
 * general utility functions which have no better home.  see util.c
 * for documentation on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

struct dhcp_timer_s {
	iu_timer_id_t	dt_id;
	lease_t		dt_start;		/* Initial timer value */
};

/* conversion functions */
const char	*pkt_type_to_string(uchar_t, boolean_t);
const char	*monosec_to_string(monosec_t);
time_t		monosec_to_time(monosec_t);
monosec_t	hrtime_to_monosec(hrtime_t);

/* shutdown handlers */
void		graceful_shutdown(int);
void		inactivity_shutdown(iu_tq_t *, void *);

/* timer functions */
void		init_timer(dhcp_timer_t *, lease_t);
boolean_t	cancel_timer(dhcp_timer_t *);
boolean_t	schedule_timer(dhcp_timer_t *, iu_tq_callback_t *, void *);

/* miscellaneous */
boolean_t	add_default_route(uint32_t, struct in_addr *);
boolean_t	del_default_route(uint32_t, struct in_addr *);
int		daemonize(void);
monosec_t	monosec(void);
void		print_server_msg(dhcp_smach_t *, const char *, uint_t);
boolean_t	bind_sock(int, in_port_t, in_addr_t);
boolean_t	bind_sock_v6(int, in_port_t, const in6_addr_t *);
const char	*iffile_to_hostname(const char *);
int		dhcpv6_status_code(const dhcpv6_option_t *, uint_t,
    const char **, const char **, uint_t *);
void		write_lease_to_hostconf(dhcp_smach_t *);
boolean_t	dhcp_add_hostname_opt(dhcp_pkt_t *, dhcp_smach_t *);
boolean_t	dhcp_add_fqdn_opt(dhcp_pkt_t *, dhcp_smach_t *);
void		save_domainname(dhcp_smach_t *, PKT_LIST *);

#ifdef	__cplusplus
}
#endif

#endif	/* UTIL_H */
