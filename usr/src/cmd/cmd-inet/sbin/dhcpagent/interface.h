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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	INTERFACE_H
#define	INTERFACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * interface.[ch] encapsulate all of the agent's knowledge of network
 * interfaces from the DHCP agent's perspective.  see interface.c
 * for documentation on how to use the exported functions.  note that
 * there are not functional interfaces for manipulating all of the fields
 * in an ifslist -- please read the comments in the ifslist structure
 * definition below for the rules on accessing various fields.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>			/* IFNAMSIZ */
#include <sys/types.h>
#include <netinet/dhcp.h>
#include <dhcpagent_ipc.h>
#include <libinetutil.h>

#include "async.h"
#include "agent.h"
#include "dlpi_io.h"
#include "ipc_action.h"
#include "packet.h"
#include "util.h"

enum { DHCP_T1_TIMER, DHCP_T2_TIMER, DHCP_LEASE_TIMER };

typedef int script_callback_t (struct ifslist *, const char *);

struct ifslist {

	/*
	 * ifslist chain pointers, maintained by insert_ifs() /
	 * remove_ifs().
	 */

	struct ifslist		*next;
	struct ifslist		*prev;

	/*
	 * hold count on this ifslist, maintained by hold_ifs() /
	 * release_ifs() -- see below for a discussion of ifs memory
	 * management.
	 */

	uchar_t			if_hold_count;

	/*
	 * each interface can have at most one pending asynchronous
	 * action, which is represented in a `struct async_action'.
	 * if that asynchronous action was a result of a user request,
	 * then the `struct ipc_action' is used to hold information
	 * about the user request.  these structures are opaque to
	 * users of the ifslist, and the functional interfaces
	 * provided in async.[ch] and ipc_action.[ch] should be used
	 * to maintain them.
	 */

	struct ipc_action	if_ia;
	struct async_action	if_async;

	/*
	 * current state of the interface
	 */

	DHCPSTATE		if_state;

	/*
	 * flags specific to DHCP (see dhcpagent_ipc.h)
	 */

	uint16_t		if_dflags;

	/*
	 * general interface information -- this information is initialized
	 * in insert_ifs() and does not change over the lifetime of the
	 * interface.
	 */

	char		if_name[IFNAMSIZ];

	uint16_t	if_max;		/* largest DHCP packet on this if */
	uint16_t	if_min;		/* minimum mtu size on this if */
	uint16_t	if_opt;		/* amount of space for options in PKT */

	uchar_t		*if_hwaddr;	/* our link-layer address */
	uchar_t		if_hwlen;	/* our link-layer address len */
	uchar_t		if_hwtype;	/* type of link-layer */

	uchar_t		*if_cid;	/* client id, if set in defaults file */
	uchar_t		if_cidlen;	/* client id len */

	uchar_t		*if_prl;	/* if non-NULL, param request list */
	uchar_t		if_prllen;	/* param request list len */

		/*
		 * the destination address is the broadcast address of
		 * the interface, in DLPI terms (which means it
		 * includes both a link-layer broadcast address and a
		 * sap, and the order isn't consistent.)  fun, huh?
		 * blame AT&T.  we store it as a token like this
		 * because it's generally how we need to use it.  we
		 * can pull it apart using the saplen and sap_before
		 * fields below.
		 */

	uchar_t		*if_daddr;	/* our destination address */
	uchar_t		if_dlen;	/* our destination address len */

	uchar_t		if_saplen;	/* the SAP len */
	uchar_t		if_sap_before;	/* does SAP come before address? */

		/*
		 * network descriptors; one is used for the DLPI
		 * traffic before we have our IP address configured;
		 * the other two are used afterwards.  there have to
		 * be two socket descriptors since:
		 *
		 * o  we need one to be bound to IPPORT_BOOTPC and
		 *    and INADDR_BROADCAST, so it can receive all
		 *    broadcast traffic.  this is if_sock_fd.  it
		 *    is also used as a general descriptor to perform
		 *    socket-related ioctls on, like SIOCGIFFLAGS.
		 *
		 * o  we need another to be bound to IPPORT_BOOTPC and
		 *    the IP address given to us by the DHCP server,
		 *    so we can guarantee the IP address of outgoing
		 *    packets when multihomed. (the problem being that
		 *    if a packet goes out with the wrong IP address,
		 *    then the server's response will come back on the
		 *    wrong interface).  this is if_sock_ip_fd.
		 *
		 * note that if_sock_fd is created in init_ifs() but
		 * not bound until dhcp_bound(); this is because we
		 * cannot even bind to the broadcast address until we
		 * have an IP address.
		 *
		 * if_sock_ip_fd isn't created until dhcp_bound(),
		 * since we don't need it until then and we can't
		 * bind it until after we have an IP address anyway.
		 *
		 * both socket descriptors are closed in reset_ifs().
		 */

	int		if_dlpi_fd;
	int		if_sock_fd;
	int		if_sock_ip_fd;

	/*
	 * the following fields are set when a lease is acquired, and
	 * may be updated over the lifetime of the lease.  they are
	 * all reset by reset_ifs().
	 */

	iu_timer_id_t	if_timer[3];	/* T1, T2, and LEASE timers */

	lease_t		if_t1;		/* relative renewal start time, hbo */
	lease_t		if_t2;		/* relative rebinding start time, hbo */
	lease_t		if_lease;	/* relative expire time, hbo */

	unsigned int	if_nrouters;	/* the number of default routers */
	struct in_addr	*if_routers;	/* an array of default routers */
	struct in_addr	if_server;	/* our DHCP server, nbo */

	/*
	 * while in any states except ADOPTING, INIT, INFORMATION and
	 * INFORM_SENT, the following three fields are equal to what
	 * we believe the current address, netmask, and broadcast
	 * address on the interface to be.  this is so we can detect
	 * if the user changes them and abandon the interface.
	 */

	struct in_addr	if_addr;	/* our IP address, nbo */
	struct in_addr	if_netmask;	/* our netmask, nbo */
	struct in_addr	if_broadcast;	/* our broadcast address, nbo */

	PKT_LIST	*if_ack;	/* ACK from the server */

	/*
	 * We retain the very first ack obtained on the interface to
	 * provide access to options which were originally assigned by
	 * the server but may not have been included in subsequent
	 * acks, as there are servers which do this and customers have
	 * had unsatisfactory results when using our agent with them.
	 * ipc_event() in agent.c provides a fallback to the original
	 * ack when the current ack doesn't have the information
	 * requested.
	 */

	PKT_LIST	*if_orig_ack;

	/*
	 * other miscellaneous variables set or needed in the process
	 * of acquiring a lease.
	 */

	int		if_offer_wait;	/* seconds between sending offers */
	iu_timer_id_t	if_offer_timer;	/* timer associated with offer wait */
	iu_event_id_t	if_offer_id;	/* event offer id */
	iu_event_id_t	if_acknak_id;	/* event acknak id */
	iu_event_id_t	if_acknak_bcast_id;

		/*
		 * `if_neg_monosec' represents the time since lease
		 * acquisition or renewal began, and is used for
		 * computing the pkt->secs field.  `if_newstart_monosec'
		 * represents the time the ACKed REQUEST was sent,
		 * which represents the start time of a new lease.
		 * when the lease actually begins (and thus becomes
		 * current), `if_curstart_monosec' is set to
		 * `if_newstart_monosec'.
		 */

	monosec_t		if_neg_monosec;
	monosec_t		if_newstart_monosec;
	monosec_t		if_curstart_monosec;

		/*
		 * time we sent the DISCOVER relative to if_neg_monosec,
		 * so that the REQUEST can have the same pkt->secs.
		 */

	uint16_t		if_disc_secs;

		/*
		 * the host name we've been asked to request is remembered
		 * here between the DISCOVER and the REQUEST
		 */
	char			*if_reqhost;

	/*
	 * this is a chain of packets which have been received on this
	 * interface over some interval of time.  the packets may have
	 * to meet some criteria in order to be put on this list.  in
	 * general, packets are put on this list through recv_pkt()
	 */

	PKT_LIST		*if_recv_pkt_list;

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

	uint32_t		if_sent;
	uint32_t		if_received;
	uint32_t		if_bad_offers;

	/*
	 * if_send_pkt.pkt is dynamically allocated to be as big a
	 * packet as we can send out on this interface.  the remainder
	 * of this information is needed to make it easy to handle
	 * retransmissions.  note that other than if_bad_offers, all
	 * of these fields are maintained internally in send_pkt(),
	 * and consequently should never need to be modified by any
	 * other functions.
	 */

	dhcp_pkt_t		if_send_pkt;
	uint32_t		if_send_timeout;
	struct sockaddr_in	if_send_dest;
	stop_func_t		*if_send_stop_func;
	uint32_t		if_packet_sent;
	iu_timer_id_t		if_retrans_timer;

	int			if_script_fd;
	pid_t			if_script_pid;
	pid_t			if_script_helper_pid;
	const char		*if_script_event;
	iu_event_id_t		if_script_event_id;
	const char		*if_callback_msg;
	script_callback_t	*if_script_callback;
};

/*
 * a word on memory management and ifslists:
 *
 * since ifslists are often passed as context to callback functions,
 * they cannot be freed when the interface they represent is dropped
 * or released (or when those callbacks finally go off, they will be
 * hosed).  to handle this situation, ifslists are reference counted.
 * here are the rules for managing ifslists:
 *
 * an ifslist is created through insert_ifs().  along with
 * initializing the ifslist, this puts a hold on the ifslist through
 * hold_ifs().
 *
 * whenever an ifslist is released or dropped (implicitly or
 * explicitly), remove_ifs() is called, which sets the DHCP_IF_REMOVED
 * flag and removes the interface from the internal list of managed
 * interfaces.  lastly, remove_ifs() calls release_ifs() to remove the
 * hold acquired in insert_ifs().  if this decrements the hold count
 * on the interface to zero, then free_ifs() is called.  if there are
 * holds other than the hold acquired in insert_ifs(), the hold count
 * will still be > 0, and the interface will remain allocated (though
 * dormant).
 *
 * whenever a callback is scheduled against an ifslist, another hold
 * must be put on the ifslist through hold_ifs().
 *
 * whenever a callback is called back against an ifslist,
 * release_ifs() must be called to decrement the hold count, which may
 * end up freeing the ifslist if the hold count becomes zero.
 *
 * if release_ifs() returns 0, then there are no remaining holds
 * against this ifslist, and the ifslist in fact no longer exists.
 *
 * since some callbacks may take a long time to get called back (such
 * as timeout callbacks for lease expiration, etc), it is sometimes
 * more appropriate to cancel the callbacks and call release_ifs() if
 * the cancellation succeeds.  this is done in remove_ifs() for the
 * lease, t1, and t2 callbacks.
 *
 * in general, a callback should also call verify_ifs() when it gets
 * called back in addition to release_ifs(), to make sure that the
 * interface is still in fact under the dhcpagent's control.  to make
 * coding simpler, there is a third function, check_ifs(), which
 * performs both the release_ifs() and the verify_ifs().  in addition,
 * if check_ifs() detects that the callback has the last hold against
 * a given interface, it informs it instead of performing the final
 * release, and thus allows it to clean up appropriately before
 * performing the final release.
 */

int		canonize_ifs(struct ifslist *);
int		check_ifs(struct ifslist *);
void		hold_ifs(struct ifslist *);
struct ifslist *insert_ifs(const char *, boolean_t, int *);
struct ifslist *lookup_ifs(const char *);
struct ifslist *lookup_ifs_by_xid(uint32_t);
void		nuke_ifslist(boolean_t);
void		refresh_ifslist(iu_eh_t *, int, void *);
int		release_ifs(struct ifslist *);
void		remove_ifs(struct ifslist *);
void		reset_ifs(struct ifslist *);
int		verify_ifs(struct ifslist *);
unsigned int	ifs_count(void);
void		cancel_ifs_timers(struct ifslist *);
int		schedule_ifs_timer(struct ifslist *, int, uint32_t,
		    iu_tq_callback_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* INTERFACE_H */
