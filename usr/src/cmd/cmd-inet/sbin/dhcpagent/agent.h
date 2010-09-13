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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	AGENT_H
#define	AGENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <libinetutil.h>
#include <dhcpagent_ipc.h>

/*
 * agent.h contains general symbols that should be available to all
 * source programs that are part of the agent.  in general, files
 * specific to a given collection of code (such as interface.h or
 * dhcpmsg.h) are to be preferred to this dumping ground.  use only
 * when necessary.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * global variables: `tq' and `eh' represent the global timer queue
 * and event handler, as described in the README. `class_id' is our
 * vendor class id set early on in main().  `inactivity_id' is the
 * timer id of the global inactivity timer, which shuts down the agent
 * if there are no state machines to manage for DHCP_INACTIVITY_WAIT
 * seconds. `grandparent' is the pid of the original process when in
 * adopt mode.  `rtsock_fd' is the global routing socket file descriptor.
 */

extern iu_tq_t		*tq;
extern iu_eh_t		*eh;
extern char		*class_id;
extern int		class_id_len;
extern iu_timer_id_t	inactivity_id;
extern pid_t		grandparent;
extern int		rtsock_fd;

boolean_t	drain_script(iu_eh_t *, void *);
boolean_t	check_cmd_allowed(DHCPSTATE, dhcp_ipc_type_t);

/*
 * global tunable parameters.  an `I' in the preceding comment indicates
 * an implementation artifact; a `R' in the preceding comment indicates
 * that the value was suggested (or required) by RFC2131.
 */

/* I: how many seconds to wait before restarting DHCP on an interface */
#define	DHCP_RESTART_WAIT	10

/*
 * I: the maximum number of milliseconds to wait before SELECTING on an
 * interface. RFC2131 recommends a random wait of between one and ten seconds,
 * to speed up DHCP at boot we wait between zero and two seconds.
 */
#define	DHCP_SELECT_WAIT	2000

/* R: how many seconds before lease expiration we give up trying to rebind */
#define	DHCP_REBIND_MIN		60

/* I: seconds to wait retrying dhcp_expire() if uncancellable async event */
#define	DHCP_EXPIRE_WAIT	10

/* R: approximate percentage of lease time to wait until RENEWING state */
#define	DHCP_T1_FACT		.5

/* R: approximate percentage of lease time to wait until REBINDING state */
#define	DHCP_T2_FACT		.875

/* I: number of REQUEST attempts before assuming something is awry */
#define	DHCP_MAX_REQUESTS	4

/* I: epsilon in seconds used to check if old and new lease times are same */
#define	DHCP_LEASE_EPS		30

/* I: if lease is not being extended, seconds left before alerting user */
#define	DHCP_LEASE_ERROR_THRESH	(60*60)	/* one hour */

/* I: how many seconds before bailing out if there's no work to do */
#define	DHCP_INACTIVITY_WAIT	(60*3)		/* three minutes */

/* I: the maximum amount of seconds we use an adopted lease */
#define	DHCP_ADOPT_LEASE_MAX	(60*60)		/* one hour */

/* I: number of seconds grandparent waits for child to finish adoption. */
#define	DHCP_ADOPT_SLEEP	30

/* I: the maximum amount of milliseconds to wait for an ipc request */
#define	DHCP_IPC_REQUEST_WAIT	(3*1000)	/* three seconds */

/*
 * DHCPv6 timer and retransmit values from RFC 3315.
 */
#define	DHCPV6_SOL_MAX_DELAY	1000	/* Max delay of first Solicit; 1s */
#define	DHCPV6_CNF_MAX_DELAY	1000	/* Max delay of first Confirm; 1s */
#define	DHCPV6_INF_MAX_DELAY	1000	/* Max delay of first Info-req; 1s */
#define	DHCPV6_SOL_TIMEOUT	1000	/* Initial Solicit timeout; 1s */
#define	DHCPV6_REQ_TIMEOUT	1000	/* Initial Request timeout; 1s */
#define	DHCPV6_CNF_TIMEOUT	1000	/* Initial Confirm timeout; 1s */
#define	DHCPV6_REN_TIMEOUT	10000	/* Initial Renew timeout; 10s */
#define	DHCPV6_REB_TIMEOUT	10000	/* Initial Rebind timeout; 10s */
#define	DHCPV6_INF_TIMEOUT	1000	/* Initial Info-req timeout; 1s */
#define	DHCPV6_REL_TIMEOUT	1000	/* Initial Release timeout; 1s */
#define	DHCPV6_DEC_TIMEOUT	1000	/* Initial Decline timeout; 1s */
#define	DHCPV6_SOL_MAX_RT	120000	/* Max Solicit timeout; 2m */
#define	DHCPV6_REQ_MAX_RT	30000	/* Max Request timeout; 30s */
#define	DHCPV6_CNF_MAX_RT	4000	/* Max Confirm timeout; 4s */
#define	DHCPV6_REN_MAX_RT	600000	/* Max Renew timeout; 5m */
#define	DHCPV6_REB_MAX_RT	600000	/* Max Rebind timeout; 5m */
#define	DHCPV6_INF_MAX_RT	120000	/* Max Info-req timeout; 2m */
#define	DHCPV6_CNF_MAX_RD	10000	/* Max Confirm duration; 10s */
#define	DHCPV6_REQ_MAX_RC	10	/* Max Request attempts */
#define	DHCPV6_REL_MAX_RC	5	/* Max Release attempts */
#define	DHCPV6_DEC_MAX_RC	5	/* Max Decline attempts */

/*
 * reasons for why iu_handle_events() returned
 */
enum { DHCP_REASON_INACTIVITY, DHCP_REASON_SIGNAL, DHCP_REASON_TERMINATE };

#ifdef	__cplusplus
}
#endif

#endif	/* AGENT_H */
