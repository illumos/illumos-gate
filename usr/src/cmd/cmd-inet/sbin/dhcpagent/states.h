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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 */

#ifndef	STATES_H
#define	STATES_H

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <libinetutil.h>

#include "common.h"
#include "ipc_action.h"
#include "async.h"
#include "packet.h"
#include "util.h"

/*
 * interfaces for state transition/action functions.  these functions
 * can be found in suitably named .c files, such as inform.c, select.c,
 * renew.c, etc.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DHCP state machine representation: includes all of the information used for
 * a state machine instance.  For IPv4, this represents a single logical
 * interface and (usually) a leased address.  For IPv6, it represents a
 * DUID+IAID combination.  Note that if multiple DUID+IAID instances are one
 * day allowed per interface, this will need to become a list.
 */
struct dhcp_smach_s {
	dhcp_smach_t	*dsm_next;	/* Note: must be first */
	dhcp_smach_t	*dsm_prev;

	/*
	 * The name of the state machine.  This is currently just a pointer to
	 * the controlling LIF's name, but could be otherwise.
	 */
	const char	*dsm_name;
	dhcp_lif_t	*dsm_lif;	/* Controlling LIF */
	uint_t		dsm_hold_count;	/* reference count */

	dhcp_lease_t	*dsm_leases;	/* List of leases */
	uint_t		dsm_lif_wait;	/* LIFs waiting on DAD */
	uint_t		dsm_lif_down;	/* LIFs failed */

	/*
	 * each state machine can have at most one pending asynchronous
	 * action, which is represented in a `struct async_action'.
	 * if that asynchronous action was a result of a user request,
	 * then the `struct ipc_action' is used to hold information
	 * about the user request.  these structures are opaque to
	 * users of the ifslist, and the functional interfaces
	 * provided in async.[ch] and ipc_action.[ch] should be used
	 * to maintain them.
	 */

	ipc_action_t	dsm_ia;
	async_action_t	dsm_async;

	uchar_t		*dsm_cid;	/* client id */
	uchar_t		dsm_cidlen;	/* client id len */

	/*
	 * current state of the machine
	 */

	DHCPSTATE	dsm_state;
	boolean_t	dsm_droprelease;  /* soon to call finished_smach */

	uint16_t	dsm_dflags;	/* DHCP_IF_* (shared with IPC) */

	uint16_t	*dsm_prl;	/* if non-NULL, param request list */
	uint_t		dsm_prllen;	/* param request list len */
	uint16_t	*dsm_pil;	/* if non-NULL, param ignore list */
	uint_t		dsm_pillen;	/* param ignore list len */

	uint_t		dsm_nrouters;	/* the number of default routers */
	struct in_addr	*dsm_routers;	/* an array of default routers */

	in6_addr_t	dsm_server;	/* our DHCP server */
	uchar_t		*dsm_serverid;	/* server DUID for v6 */
	uint_t		dsm_serveridlen; /* DUID length */

	/*
	 * We retain the very first ack obtained on the state machine to
	 * provide access to options which were originally assigned by
	 * the server but may not have been included in subsequent
	 * acks, as there are servers which do this and customers have
	 * had unsatisfactory results when using our agent with them.
	 * ipc_event() in agent.c provides a fallback to the original
	 * ack when the current ack doesn't have the information
	 * requested.
	 *
	 * Note that neither of these is actually a list of packets.  There's
	 * exactly one packet here, so use free_pkt_entry.
	 */
	PKT_LIST	*dsm_ack;
	PKT_LIST	*dsm_orig_ack;

	/*
	 * other miscellaneous variables set or needed in the process
	 * of acquiring a lease.
	 */

	int		dsm_offer_wait;	/* seconds between sending offers */
	iu_timer_id_t	dsm_offer_timer; /* timer associated with offer wait */

	/*
	 * time we sent the DISCOVER relative to dsm_neg_hrtime, so that the
	 * REQUEST can have the same pkt->secs.
	 */

	uint16_t	dsm_disc_secs;

	/*
	 * this is a chain of packets which have been received on this
	 * state machine over some interval of time.  the packets may have
	 * to meet some criteria in order to be put on this list.  in
	 * general, packets are put on this list through recv_pkt()
	 */

	PKT_LIST	*dsm_recv_pkt_list;

	/*
	 * these three fields are initially zero, and get incremented
	 * as the ifslist goes from INIT -> BOUND.  if and when the
	 * ifslist moves to the RENEWING state, these fields are
	 * reset, so they always either indicate the number of packets
	 * sent, received, and declined while obtaining the current
	 * lease (if BOUND), or the number of packets sent, received,
	 * and declined while attempting to obtain a future lease
	 * (if any other state).
	 */

	uint32_t	dsm_sent;
	uint32_t	dsm_received;
	uint32_t	dsm_bad_offers;

	/*
	 * dsm_send_pkt.pkt is dynamically allocated to be as big a
	 * packet as we can send out on this state machine.  the remainder
	 * of this information is needed to make it easy to handle
	 * retransmissions.  note that other than dsm_bad_offers, all
	 * of these fields are maintained internally in send_pkt(),
	 * and consequently should never need to be modified by any
	 * other functions.
	 */

	dhcp_pkt_t	dsm_send_pkt;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} dsm_send_dest;

	/*
	 * For v4, dsm_send_tcenter is used to track the central timer value in
	 * milliseconds (4000, 8000, 16000, 32000, 64000), and dsm_send_timeout
	 * is that value plus the +/- 1000 millisecond fuzz.
	 *
	 * For v6, dsm_send_tcenter is the MRT (maximum retransmit timer)
	 * value, and dsm_send_timeout must be set to the IRT (initial
	 * retransmit timer) value by the sender.
	 */
	uint_t		dsm_send_timeout;
	uint_t		dsm_send_tcenter;
	stop_func_t	*dsm_send_stop_func;
	uint32_t	dsm_packet_sent;
	iu_timer_id_t	dsm_retrans_timer;

	/*
	 * The host name we've been asked to request is remembered
	 * here between the DISCOVER and the REQUEST.  (v4 only)
	 */
	char		*dsm_reqhost;

	/*
	 * The host name we've been asked by IPC message (e.g.,
	 * `ipadm -T dhcp -h ...') to request is remembered here until it is
	 * reset by another external message.
	 */
	char		*dsm_msg_reqhost;

	/*
	 * The domain name returned for v4 DNSdmain is decoded here for use
	 * (if configured and needed) to determine an FQDN.
	 */
	char		*dsm_dhcp_domainname;

	/*
	 * V4 and V6 use slightly different timers.  For v4, we must count
	 * seconds from the point where we first try to configure the
	 * interface.  For v6, only seconds while performing a transaction
	 * matter.
	 *
	 * In v4, `dsm_neg_hrtime' represents the time since DHCP started
	 * configuring the interface, and is used for computing the pkt->secs
	 * field in v4.  In v6, it represents the time since the current
	 * transaction (if any) was started, and is used for the ELAPSED_TIME
	 * option.
	 *
	 * `dsm_newstart_monosec' represents the time the ACKed REQUEST was
	 * sent, which represents the start time of a new batch of leases.
	 * When the lease time actually begins (and thus becomes current),
	 * `dsm_curstart_monosec' is set to `dsm_newstart_monosec'.
	 */
	hrtime_t	dsm_neg_hrtime;
	monosec_t	dsm_newstart_monosec;
	monosec_t	dsm_curstart_monosec;

	int		dsm_script_fd;
	pid_t		dsm_script_pid;
	pid_t		dsm_script_helper_pid;
	const char	*dsm_script_event;
	iu_event_id_t	dsm_script_event_id;
	void		*dsm_callback_arg;
	script_callback_t *dsm_script_callback;

	iu_timer_id_t	dsm_start_timer;
};

#define	dsm_isv6	dsm_lif->lif_pif->pif_isv6
#define	dsm_hwtype	dsm_lif->lif_pif->pif_hwtype

struct dhcp_lease_s {
	dhcp_lease_t	*dl_next;	/* Note: must be first */
	dhcp_lease_t	*dl_prev;

	dhcp_smach_t	*dl_smach;	/* back pointer to state machine */
	dhcp_lif_t	*dl_lifs;	/* LIFs configured by this lease */
	uint_t		dl_nlifs;	/* Number of configured LIFs */
	uint_t		dl_hold_count;	/* reference counter */
	boolean_t	dl_removed;	/* Set if removed from list */
	boolean_t	dl_stale;	/* not updated by Renew/bind */

	/*
	 * the following fields are set when a lease is acquired, and
	 * may be updated over the lifetime of the lease.  they are
	 * all reset by reset_smach().
	 */

	dhcp_timer_t	dl_t1;		/* relative renewal start time, hbo */
	dhcp_timer_t	dl_t2;		/* relative rebinding start time, hbo */
};

/* The IU event callback functions */
iu_eh_callback_t	dhcp_acknak_global;
iu_eh_callback_t	dhcp_packet_lif;

/* Common state-machine related routines throughout dhcpagent */
boolean_t	dhcp_adopt(void);
void		dhcp_adopt_complete(dhcp_smach_t *);
boolean_t	dhcp_bound(dhcp_smach_t *, PKT_LIST *);
void		dhcp_bound_complete(dhcp_smach_t *);
int		dhcp_drop(dhcp_smach_t *, void *);
void		dhcp_deprecate(iu_tq_t *, void *);
void		dhcp_expire(iu_tq_t *, void *);
boolean_t	dhcp_extending(dhcp_smach_t *);
void		dhcp_inform(dhcp_smach_t *);
void		dhcp_init_reboot(dhcp_smach_t *);
void		dhcp_rebind(iu_tq_t *, void *);
int		dhcp_release(dhcp_smach_t *, void *);
void		dhcp_renew(iu_tq_t *, void *);
void		dhcp_requesting(iu_tq_t *, void *);
void		dhcp_restart(dhcp_smach_t *);
void		dhcp_selecting(dhcp_smach_t *);
boolean_t	set_start_timer(dhcp_smach_t *);
void		send_declines(dhcp_smach_t *);
void		send_v6_request(dhcp_smach_t *);
boolean_t	save_server_id(dhcp_smach_t *, PKT_LIST *);
void		server_unicast_option(dhcp_smach_t *, PKT_LIST *);

/* State machine support functions in states.c */
dhcp_smach_t	*insert_smach(dhcp_lif_t *, int *);
void		hold_smach(dhcp_smach_t *);
void		release_smach(dhcp_smach_t *);
void		remove_smach(dhcp_smach_t *);
dhcp_smach_t	*next_smach(dhcp_smach_t *, boolean_t);
dhcp_smach_t	*primary_smach(boolean_t);
dhcp_smach_t	*info_primary_smach(boolean_t);
void		make_primary(dhcp_smach_t *);
dhcp_smach_t	*lookup_smach(const char *, boolean_t);
dhcp_smach_t	*lookup_smach_by_uindex(uint16_t, dhcp_smach_t *, boolean_t);
dhcp_smach_t	*lookup_smach_by_xid(uint32_t, dhcp_smach_t *, boolean_t);
dhcp_smach_t	*lookup_smach_by_event(iu_event_id_t);
void		finished_smach(dhcp_smach_t *, int);
boolean_t	set_smach_state(dhcp_smach_t *, DHCPSTATE);
int		get_smach_cid(dhcp_smach_t *);
boolean_t	verify_smach(dhcp_smach_t *);
uint_t		smach_count(void);
void		reset_smach(dhcp_smach_t *);
void		refresh_smachs(iu_eh_t *, int, void *);
void		refresh_smach(dhcp_smach_t *);
void		nuke_smach_list(void);
boolean_t	schedule_smach_timer(dhcp_smach_t *, int, uint32_t,
		    iu_tq_callback_t *);
void		cancel_offer_timer(dhcp_smach_t *);
void		cancel_smach_timers(dhcp_smach_t *);
void		discard_default_routes(dhcp_smach_t *);
void		remove_default_routes(dhcp_smach_t *);
boolean_t	is_bound_state(DHCPSTATE);

/* Lease-related support functions in states.c */
dhcp_lease_t	*insert_lease(dhcp_smach_t *);
void		hold_lease(dhcp_lease_t *);
void		release_lease(dhcp_lease_t *);
void		remove_lease(dhcp_lease_t *);
void		deprecate_leases(dhcp_smach_t *);
void		cancel_lease_timers(dhcp_lease_t *);
boolean_t	schedule_lease_timer(dhcp_lease_t *, dhcp_timer_t *,
		    iu_tq_callback_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* STATES_H */
