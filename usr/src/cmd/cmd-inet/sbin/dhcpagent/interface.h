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
 * Copyright 2019 Joshua M. Clulow <josh@sysmgr.org>
 */

#ifndef	INTERFACE_H
#define	INTERFACE_H

/*
 * Interface.[ch] encapsulate all of the agent's knowledge of network
 * interfaces from the DHCP agent's perspective.  See interface.c for
 * documentation on how to use the exported functions.  Note that there are not
 * functional interfaces for manipulating all of the fields in a PIF or LIF --
 * please read the comments in the structure definitions below for the rules on
 * accessing various fields.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <net/if.h>			/* IFNAMSIZ */
#include <sys/types.h>
#include <netinet/dhcp.h>
#include <dhcpagent_ipc.h>
#include <libinetutil.h>

#include "common.h"
#include "util.h"

#define	V4_PART_OF_V6(v6)	v6._S6_un._S6_u32[3]

struct dhcp_pif_s {
	dhcp_pif_t	*pif_next;	/* Note: must be first */
	dhcp_pif_t	*pif_prev;
	dhcp_lif_t	*pif_lifs;	/* pointer to logical interface list */
	uint32_t	pif_index;	/* interface index */
	uint_t		pif_mtu_orig;	/* Original interface MTU */
	uint_t		pif_mtu;	/* Current interface MTU */
	uchar_t		*pif_hwaddr;	/* our link-layer address */
	uchar_t		pif_hwlen;	/* our link-layer address len */
	uchar_t		pif_hwtype;	/* type of link-layer */
	boolean_t	pif_isv6;
	boolean_t	pif_running;	/* interface is running */
	uint_t		pif_hold_count;	/* reference count */
	char		pif_name[LIFNAMSIZ];
	char		pif_grifname[LIFNAMSIZ];
	uint32_t	pif_grindex;	/* interface index for pif_grifname */
	boolean_t	pif_under_ipmp;	/* is an ipmp underlying interface */
};

struct dhcp_lif_s {
	dhcp_lif_t	*lif_next;	/* Note: must be first */
	dhcp_lif_t	*lif_prev;
	dhcp_pif_t	*lif_pif;	/* backpointer to parent physical if */
	dhcp_smach_t	*lif_smachs;	/* pointer to list of state machines */
	dhcp_lease_t	*lif_lease;	/* backpointer to lease holding LIF */
	uint64_t	lif_flags;	/* Interface flags (IFF_*) */
	int		lif_sock_ip_fd;	/* Bound to addr.BOOTPC for src addr */
	iu_event_id_t	lif_packet_id;	/* event packet id */
	uint_t		lif_mtu;	/* Requested interface MTU */
	uint_t		lif_hold_count;	/* reference count */
	boolean_t	lif_dad_wait;	/* waiting for DAD resolution */
	boolean_t	lif_removed;	/* removed from list */
	boolean_t	lif_plumbed;	/* interface plumbed by dhcpagent */
	boolean_t	lif_expired;	/* lease has evaporated */
	const char	*lif_declined;	/* reason to refuse this address */
	uint32_t	lif_iaid;	/* unique and stable identifier */
	iu_event_id_t	lif_iaid_id;	/* for delayed writes to /etc */

	/*
	 * While in any states except ADOPTING, INIT, INFORMATION and
	 * INFORM_SENT, the following three fields are equal to what we believe
	 * the current address, netmask, and broadcast address on the interface
	 * to be.  This is so we can detect if the user changes them and
	 * abandon the interface.
	 */

	in6_addr_t	lif_v6addr;	/* our IP address */
	in6_addr_t	lif_v6mask;	/* our netmask */
	in6_addr_t	lif_v6peer;	/* our broadcast or peer address */

	dhcp_timer_t	lif_preferred;	/* lease preferred timer (v6 only) */
	dhcp_timer_t	lif_expire;	/* lease expire timer */

	char		lif_name[LIFNAMSIZ];
};
#define	lif_addr	V4_PART_OF_V6(lif_v6addr)
#define	lif_netmask	V4_PART_OF_V6(lif_v6mask)
#define	lif_peer	V4_PART_OF_V6(lif_v6peer)
#define	lif_broadcast	V4_PART_OF_V6(lif_v6peer)

/* used by expired_lif_state to express state of DHCP interfaces */
typedef enum dhcp_expire_e {
	DHCP_EXP_NOLIFS,
	DHCP_EXP_NOEXP,
	DHCP_EXP_ALLEXP,
	DHCP_EXP_SOMEEXP
} dhcp_expire_t;

/*
 * A word on memory management and LIFs and PIFs:
 *
 * Since LIFs are often passed as context to callback functions, they cannot be
 * freed when the interface they represent is dropped or released (or when
 * those callbacks finally go off, they will be hosed).  To handle this
 * situation, the structures are reference counted.  Here are the rules for
 * managing these counts:
 *
 * A PIF is created through insert_pif().  Along with initializing the PIF,
 * this puts a hold on the PIF.  A LIF is created through insert_lif().  This
 * also initializes the LIF and places a hold on it.  The caller's hold on the
 * underlying PIF is transferred to the LIF.
 *
 * Whenever a lease is released or dropped (implicitly or explicitly),
 * remove_lif() is called, which sets the lif_removed flag and removes the
 * interface from the internal list of managed interfaces.  Lastly,
 * remove_lif() calls release_lif() to remove the hold acquired in
 * insert_lif().  If this decrements the hold count on the interface to zero,
 * then free() is called and the hold on the PIF is dropped.  If there are
 * holds other than the hold acquired in insert_lif(), the hold count will
 * still be > 0, and the interface will remain allocated (though dormant).
 *
 * Whenever a callback is scheduled against a LIF, another hold must be put on
 * the ifslist through hold_lif().
 *
 * Whenever a callback is called back against a LIF, release_lif() must be
 * called to decrement the hold count, which may end up freeing the LIF if the
 * hold count becomes zero.
 *
 * Since some callbacks may take a long time to get called back (such as
 * timeout callbacks for lease expiration, etc), it is sometimes more
 * appropriate to cancel the callbacks and call release_lif() if the
 * cancellation succeeds.  This is done in remove_lif() for the lease preferred
 * and expire callbacks.
 *
 * In general, a callback may also call verify_lif() when it gets called back
 * in addition to release_lif(), to make sure that the interface is still in
 * fact under the dhcpagent's control.  To make coding simpler, there is a
 * third function, verify_smach(), which performs both the release_lif() and
 * the verify_lif() on all LIFs controlled by a state machine.
 */

extern dhcp_pif_t *v4root;
extern dhcp_pif_t *v6root;

dhcp_pif_t	*insert_pif(const char *, boolean_t, int *);
void		hold_pif(dhcp_pif_t *);
void		release_pif(dhcp_pif_t *);
dhcp_pif_t	*lookup_pif_by_uindex(uint16_t, dhcp_pif_t *, boolean_t);
dhcp_pif_t	*lookup_pif_by_name(const char *, boolean_t);
void		pif_status(dhcp_pif_t *, boolean_t);

dhcp_lif_t	*insert_lif(dhcp_pif_t *, const char *, int *);
void		hold_lif(dhcp_lif_t *);
void		release_lif(dhcp_lif_t *);
void		remove_lif(dhcp_lif_t *);
dhcp_lif_t	*lookup_lif_by_name(const char *, const dhcp_pif_t *);
boolean_t	verify_lif(const dhcp_lif_t *);
dhcp_lif_t	*plumb_lif(dhcp_pif_t *, const in6_addr_t *);
void		unplumb_lif(dhcp_lif_t *);
dhcp_lif_t	*attach_lif(const char *, boolean_t, int *);
int		set_lif_dhcp(dhcp_lif_t *);
void		set_lif_deprecated(dhcp_lif_t *);
boolean_t	clear_lif_deprecated(dhcp_lif_t *);
void		set_lif_mtu(dhcp_lif_t *, uint_t);
void		clear_lif_mtu(dhcp_lif_t *);
boolean_t	open_ip_lif(dhcp_lif_t *, in_addr_t, boolean_t);
void		close_ip_lif(dhcp_lif_t *);
void		lif_mark_decline(dhcp_lif_t *, const char *);
boolean_t	schedule_lif_timer(dhcp_lif_t *, dhcp_timer_t *,
		    iu_tq_callback_t *);
void		cancel_lif_timers(dhcp_lif_t *);
dhcp_expire_t	expired_lif_state(dhcp_smach_t *);
dhcp_lif_t	*find_expired_lif(dhcp_smach_t *);

uint_t		get_max_mtu(boolean_t);
void		remove_v6_strays(void);

#ifdef	__cplusplus
}
#endif

#endif	/* INTERFACE_H */
