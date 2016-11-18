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
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#ifndef	_PACKET_H
#define	_PACKET_H

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp6.h>
#include <dhcp_impl.h>

#include "common.h"

/*
 * packet.[ch] contain routines for manipulating, setting, and
 * transmitting DHCP/BOOTP packets.  see packet.c for descriptions on
 * how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * data type for recv_pkt().  needed because we may want to wait for
 * several kinds of packets at once, and the existing enumeration of
 * DHCP packet types does not provide a way to do that easily.  here,
 * we light a different bit in the enumeration for each type of packet
 * we want to receive.
 *
 * Note that for DHCPv6, types 4 (CONFIRM), 5 (RENEW), 6 (REBIND), 12
 * (RELAY-FORW, and 13 (RELAY-REPL) are not in the table.  They're never
 * received by a client, so there's no reason to process them.  (SOLICIT,
 * REQUEST, DECLINE, RELEASE, and INFORMATION-REQUEST are also never seen by
 * clients, but are included for consistency.)
 *
 * Note also that the symbols are named for the DHCPv4 message types, and that
 * DHCPv6 has analogous message types.
 */

typedef enum {

	DHCP_PUNTYPED	= 0x001,	/* untyped (BOOTP) message */
	DHCP_PDISCOVER	= 0x002,	/* in v6: SOLICIT (1) */
	DHCP_POFFER 	= 0x004,	/* in v6: ADVERTISE (2) */
	DHCP_PREQUEST	= 0x008,	/* in v6: REQUEST (3) */
	DHCP_PDECLINE	= 0x010,	/* in v6: DECLINE (9) */
	DHCP_PACK	= 0x020,	/* in v6: REPLY (7), status == 0 */
	DHCP_PNAK	= 0x040,	/* in v6: REPLY (7), status != 0 */
	DHCP_PRELEASE	= 0x080,	/* in v6: RELEASE (8) */
	DHCP_PINFORM	= 0x100,	/* in v6: INFORMATION-REQUEST (11) */
	DHCP_PRECONFIG	= 0x200		/* v6 only: RECONFIGURE (10) */

} dhcp_message_type_t;

/*
 * A dhcp_pkt_t is used by the output-side packet manipulation functions.
 * While the structure is not strictly necessary, it allows a better separation
 * of functionality since metadata about the packet (such as its current
 * length) is stored along with the packet.
 *
 * Note that 'pkt' points to a dhcpv6_message_t if the packet is IPv6.
 */

typedef struct dhcp_pkt_s {
	PKT		*pkt;		/* the real underlying packet */
	unsigned int	pkt_max_len; 	/* its maximum length */
	unsigned int	pkt_cur_len;	/* its current length */
	boolean_t	pkt_isv6;
} dhcp_pkt_t;

/*
 * a `stop_func_t' is used by parts of dhcpagent that use the
 * retransmission capability of send_pkt().  this makes it so the
 * callers of send_pkt() decide when to stop retransmitting, which
 * makes more sense than hardcoding their instance-specific cases into
 * packet.c
 */

typedef boolean_t stop_func_t(dhcp_smach_t *, unsigned int);

/*
 * Default I/O and interface control sockets.
 */
extern int v6_sock_fd;
extern int v4_sock_fd;

extern const in6_addr_t ipv6_all_dhcp_relay_and_servers;
extern const in6_addr_t my_in6addr_any;

PKT_LIST	*alloc_pkt_entry(size_t, boolean_t);
void		free_pkt_entry(PKT_LIST *);
void		free_pkt_list(PKT_LIST **);
uchar_t		pkt_recv_type(const PKT_LIST *);
uint_t		pkt_get_xid(const PKT *, boolean_t);
dhcp_pkt_t	*init_pkt(dhcp_smach_t *, uchar_t);
boolean_t	remove_pkt_opt(dhcp_pkt_t *, uint_t);
boolean_t	update_v6opt_len(dhcpv6_option_t *, int);
void		*add_pkt_opt(dhcp_pkt_t *, uint_t, const void *, uint_t);
size_t		encode_dhcp_opt(void *, boolean_t, uint_t, const void *,
			uint_t);
void		*add_pkt_subopt(dhcp_pkt_t *, dhcpv6_option_t *, uint_t,
		    const void *, uint_t);
void		*add_pkt_opt16(dhcp_pkt_t *, uint_t, uint16_t);
void		*add_pkt_opt32(dhcp_pkt_t *, uint_t, uint32_t);
void		*add_pkt_prl(dhcp_pkt_t *, dhcp_smach_t *);
boolean_t	add_pkt_lif(dhcp_pkt_t *, dhcp_lif_t *, int, const char *);
void		stop_pkt_retransmission(dhcp_smach_t *);
void		retransmit_now(dhcp_smach_t *);
PKT_LIST	*recv_pkt(int, int, boolean_t);
boolean_t	pkt_v4_match(uchar_t, dhcp_message_type_t);
void		pkt_smach_enqueue(dhcp_smach_t *, PKT_LIST *);
boolean_t	send_pkt(dhcp_smach_t *, dhcp_pkt_t *, in_addr_t,
		    stop_func_t *);
boolean_t	send_pkt_v6(dhcp_smach_t *, dhcp_pkt_t *, in6_addr_t,
		    stop_func_t *, uint_t, uint_t);
boolean_t	dhcp_ip_default(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _PACKET_H */
