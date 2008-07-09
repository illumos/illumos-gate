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

#ifndef	_INET_IPSEC_INFO_H
#define	_INET_IPSEC_INFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/crypto/common.h>

/*
 * IPsec informational messages.  These are M_CTL STREAMS messages, which
 * convey IPsec information between various IP and related modules.  The
 * messages come in a few flavors:
 *
 *	* IPSEC_{IN,OUT}  -  These show what IPsec action have been taken (for
 *	  inbound datagrams), or need to be taken (for outbound datagrams).
 *	  They flow between AH/ESP and IP.
 *
 *	* Keysock consumer interface  -  These messages are wrappers for
 *	  PF_KEY messages.  They flow between AH/ESP and keysock.
 *
 * Some of these messages include pointers such as a netstack_t pointer.
 * We do not explicitly reference count those with netstack_hold/rele,
 * since we depend on IP's ability to discard all of the IPSEC_{IN,OUT}
 * messages in order to handle the ipsa pointers.
 * We have special logic when doing asynch callouts to kEF for which we
 * verify netstack_t pointer using the netstackid_t.
 */

/*
 * The IPsec M_CTL value MUST be something that will not be even close
 * to an IPv4 or IPv6 header.  This means the first byte must not be
 * 0x40 - 0x4f or 0x60-0x6f.  For big-endian machines, this is fixable with
 * the IPSEC_M_CTL prefix.  For little-endian machines, the actual M_CTL
 * _type_ must not be in the aforementioned ranges.
 *
 * The reason for this avoidance is because M_CTL's with a real IPv4/IPv6
 * datagram get sent from to TCP or UDP when an ICMP datagram affects a
 * TCP/UDP session.
 */
#define	IPSEC_M_CTL	0x73706900

/*
 * M_CTL types for IPsec messages.  Remember, the values 0x40 - 0x4f and 0x60
 * - 0x6f are not to be used because of potential little-endian confusion.
 *
 * Offsets 1-25 (decimal) are in use, spread through this file.
 * Check for duplicates through the whole file before adding.
 */

/*
 * IPSEC_{IN,OUT} policy expressors.
 */
#define	IPSEC_IN	(IPSEC_M_CTL + 1)
#define	IPSEC_OUT	(IPSEC_M_CTL + 2)

/*
 * This is used for communication between IP and IPSEC (AH/ESP)
 * for Inbound datagrams. IPSEC_IN is allocated by IP before IPSEC
 * processing begins. On return spi fields are initialized so that
 * IP can locate the security associations later on for doing policy
 * checks. For loopback case, IPSEC processing is not done. But the
 * attributes of the security are reflected in <foo>_done fields below.
 * The code in policy check infers that it is a loopback case and
 * would not try to get the associations.
 *
 * The comment below (and for other netstack_t references) refers
 * to the fact that we only do netstack_hold in particular cases,
 * such as the references from open streams (ill_t and conn_t's
 * pointers). Internally within IP we rely on IP's ability to cleanup e.g.
 * ire_t's when an ill goes away.
 */
typedef struct ipsec_in_s {
	uint32_t ipsec_in_type;
	uint32_t ipsec_in_len;
	frtn_t ipsec_in_frtn;		/* for esballoc() callback */
	struct ipsa_s 	*ipsec_in_ah_sa;	/* SA for AH */
	struct ipsa_s 	*ipsec_in_esp_sa;	/* SA for ESP */

	struct ipsec_policy_head_s *ipsec_in_policy;
	struct ipsec_action_s *ipsec_in_action; /* how we made it in.. */
	unsigned int
		ipsec_in_secure : 1,	/* Is the message attached secure ? */
		ipsec_in_v4 : 1,	/* Is this an ipv4 packet ? */
		ipsec_in_loopback : 1,	/* Is this a loopback request ? */
		ipsec_in_dont_check : 1, /* Used by TCP to avoid policy check */

		ipsec_in_decaps : 1,	/* Was this packet decapsulated from */
					/* a matching inner packet? */
		ipsec_in_attach_if : 1,	/* Don't load spread this packet */
		ipsec_in_accelerated : 1, /* hardware accelerated packet */

		ipsec_in_icmp_loopback : 1, /* Looped-back ICMP packet, */
					    /* all should trust this. */
		ipsec_in_pad_bits : 24;

	int    ipsec_in_ill_index;	/* interface on which ipha_dst was */
					/* configured when pkt was recv'd  */
	int    ipsec_in_rill_index;	/* interface on which pkt was recv'd */
	uint32_t ipsec_in_esp_udp_ports;	/* For an ESP-in-UDP packet. */
	mblk_t *ipsec_in_da;		/* data attr. for accelerated pkts */

	/*
	 * For call to the kernel crypto framework. State needed during
	 * the execution of a crypto request. Storing these here
	 * allow us to avoid a separate allocation before calling the
	 * crypto framework.
	 */
	size_t ipsec_in_skip_len;		/* len to skip for AH auth */
	crypto_data_t ipsec_in_crypto_data;	/* single op crypto data */
	crypto_dual_data_t ipsec_in_crypto_dual_data; /* for dual ops */
	crypto_data_t ipsec_in_crypto_mac;	/* to store the MAC */

	zoneid_t ipsec_in_zoneid;	/* target zone for the datagram */
	netstack_t *ipsec_in_ns;	/* Does not have a netstack_hold */
	netstackid_t ipsec_in_stackid;	/* Used while waing for kEF callback */
} ipsec_in_t;

#define	IPSECOUT_MAX_ADDRLEN 4	/* Max addr len. (in 32-bit words) */
/*
 * This is used for communication between IP and IPSEC (AH/ESP)
 * for Outbound datagrams. IPSEC_OUT is allocated by IP before IPSEC
 * processing begins. On return SA fields are initialized so that
 * IP can locate the security associations later on for doing policy
 * checks.  The policy and the actions associated with this packet are
 * stored in the ipsec_out_policy and ipsec_out_act fields respectively.
 * IPSEC_OUT is also used to carry non-ipsec information when conn is
 * absent or the conn information is lost across the calls to ARP.
 * example: message from ARP or from ICMP error routines.
 */
typedef struct ipsec_out_s {
	uint32_t ipsec_out_type;
	uint32_t ipsec_out_len;
	frtn_t ipsec_out_frtn;		/* for esballoc() callback */
	struct ipsec_policy_head_s *ipsec_out_polhead;
	ipsec_latch_t		*ipsec_out_latch;
	struct ipsec_policy_s 	*ipsec_out_policy; /* why are we here? */
	struct ipsec_action_s	*ipsec_out_act;	/* what do we want? */
	struct ipsa_s	*ipsec_out_ah_sa; /* AH SA used for the packet */
	struct ipsa_s	*ipsec_out_esp_sa; /* ESP SA used for the packet */
	/*
	 * NOTE: "Source" and "Dest" are w.r.t. outbound datagrams.  Ports can
	 *	 be zero, and the protocol number is needed to make the ports
	 *	 significant.
	 */
	uint16_t ipsec_out_src_port;	/* Source port number of d-gram. */
	uint16_t ipsec_out_dst_port;	/* Destination port number of d-gram. */
	uint8_t  ipsec_out_icmp_type;	/* ICMP type of d-gram */
	uint8_t  ipsec_out_icmp_code;	/* ICMP code of d-gram */

	sa_family_t ipsec_out_inaf;	/* Inner address family */
	uint32_t ipsec_out_insrc[IPSECOUT_MAX_ADDRLEN];	/* Inner src address */
	uint32_t ipsec_out_indst[IPSECOUT_MAX_ADDRLEN];	/* Inner dest address */
	uint8_t  ipsec_out_insrcpfx;	/* Inner source prefix */
	uint8_t  ipsec_out_indstpfx;	/* Inner destination prefix */

	uint_t ipsec_out_ill_index;	/* ill index used for multicast etc. */
	uint8_t ipsec_out_proto;	/* IP protocol number for d-gram. */
	unsigned int
		ipsec_out_tunnel : 1,	/* Tunnel mode? */
		ipsec_out_use_global_policy : 1, /* Inherit global policy ? */
		ipsec_out_secure : 1,	/* Is this secure ? */
		ipsec_out_proc_begin : 1, /* IPSEC processing begun */
		/*
		 * Following five values reflects the values stored
		 * in conn.
		 */
		ipsec_out_multicast_loop : 1,
		ipsec_out_dontroute : 1,
		ipsec_out_reserved : 1,
		ipsec_out_v4 : 1,

		ipsec_out_attach_if : 1,
		ipsec_out_unspec_src : 1,	/* IPv6 ip6i_t info */
		ipsec_out_reachable : 1, 	/* NDP reachability info */
		ipsec_out_failed: 1,

		ipsec_out_se_done: 1,
		ipsec_out_esp_done: 1,
		ipsec_out_ah_done: 1,
		ipsec_out_need_policy: 1,

		/*
		 * To indicate that packet must be accelerated, i.e.
		 * ICV or encryption performed, by Provider.
		 */
		ipsec_out_accelerated : 1,
		/*
		 * Used by IP to tell IPsec that the outbound ill for this
		 * packet supports acceleration of the AH or ESP prototocol.
		 * If set, ipsec_out_capab_ill_index contains the
		 * index of the ill.
		 */
		ipsec_out_is_capab_ill : 1,
		/*
		 * Indicates ICMP message destined for self.  These
		 * messages are to be trusted by all receivers.
		 */
		ipsec_out_icmp_loopback: 1,
		ipsec_out_ip_nexthop : 1,	/* IP_NEXTHOP option is set */
		ipsec_out_pad_bits : 12;
	cred_t	*ipsec_out_cred;
	uint32_t ipsec_out_capab_ill_index;

	/*
	 * For call to the kernel crypto framework. State needed during
	 * the execution of a crypto request. Storing these here
	 * allow us to avoid a separate allocation before calling the
	 * crypto framework.
	 */
	size_t ipsec_out_skip_len;		/* len to skip for AH auth */
	crypto_data_t ipsec_out_crypto_data;	/* single op crypto data */
	crypto_dual_data_t ipsec_out_crypto_dual_data; /* for dual ops */
	crypto_data_t ipsec_out_crypto_mac;	/* to store the MAC */

	zoneid_t ipsec_out_zoneid;	/* source zone for the datagram */
	in6_addr_t ipsec_out_nexthop_v6;	/* nexthop IP address */
#define	ipsec_out_nexthop_addr V4_PART_OF_V6(ipsec_out_nexthop_v6)
	netstack_t *ipsec_out_ns;	/* Does not have a netstack_hold */
	netstackid_t ipsec_out_stackid;	/* Used while waing for kEF callback */
} ipsec_out_t;

/*
 * This is used to mark the ipsec_out_t *req* fields
 * when the operation is done without affecting the
 * requests.
 */
#define	IPSEC_REQ_DONE		0x80000000
/*
 * Operation could not be performed by the AH/ESP
 * module.
 */
#define	IPSEC_REQ_FAILED	0x40000000

/*
 * Keysock consumer interface.
 *
 * The driver/module keysock (which is a driver to PF_KEY sockets, but is
 * a module to 'consumers' like AH and ESP) uses keysock consumer interface
 * messages to pass on PF_KEY messages to consumers who process and act upon
 * them.
 */
#define	KEYSOCK_IN		(IPSEC_M_CTL + 3)
#define	KEYSOCK_OUT		(IPSEC_M_CTL + 4)
#define	KEYSOCK_OUT_ERR		(IPSEC_M_CTL + 5)
#define	KEYSOCK_HELLO		(IPSEC_M_CTL + 6)
#define	KEYSOCK_HELLO_ACK	(IPSEC_M_CTL + 7)

/*
 * KEYSOCK_HELLO is sent by keysock to a consumer when it is pushed on top
 * of one (i.e. opened as a module).
 *
 * NOTE: Keysock_hello is simply an ipsec_info_t
 */

/* TUN_HELLO is just like KEYSOCK_HELLO, except for tunnels to talk with IP. */
#define	TUN_HELLO		KEYSOCK_HELLO

/*
 * KEYSOCK_HELLO_ACK is sent by a consumer to acknowledge a KEYSOCK_HELLO.
 * It contains the PF_KEYv2 sa_type, so keysock can redirect PF_KEY messages
 * to the right consumer.
 */
typedef struct keysock_hello_ack_s {
	uint32_t ks_hello_type;
	uint32_t ks_hello_len;
	uint8_t ks_hello_satype;	/* PF_KEYv2 sa_type of ks client */
} keysock_hello_ack_t;

#define	KS_IN_ADDR_UNKNOWN 0
#define	KS_IN_ADDR_NOTTHERE 1
#define	KS_IN_ADDR_UNSPEC 2
#define	KS_IN_ADDR_ME 3
#define	KS_IN_ADDR_NOTME 4
#define	KS_IN_ADDR_MBCAST 5
#define	KS_IN_ADDR_DONTCARE 6

/*
 * KEYSOCK_IN is a PF_KEY message from a PF_KEY socket destined for a consumer.
 */
typedef struct keysock_in_s {
	uint32_t ks_in_type;
	uint32_t ks_in_len;
	/*
	 * NOTE:	These pointers MUST be into the M_DATA that follows
	 *		this M_CTL message.  If they aren't, weirdness
	 *		results.
	 */
	struct sadb_ext *ks_in_extv[SADB_EXT_MAX + 1];
	int ks_in_srctype;	/* Source address type. */
	int ks_in_dsttype;	/* Dest address type. */
	minor_t ks_in_serial;	/* Serial # of sending socket. */
} keysock_in_t;

/*
 * KEYSOCK_OUT is a PF_KEY message from a consumer destined for a PF_KEY
 * socket.
 */
typedef struct keysock_out_s {
	uint32_t ks_out_type;
	uint32_t ks_out_len;
	minor_t ks_out_serial;	/* Serial # of sending socket. */
} keysock_out_t;

/*
 * KEYSOCK_OUT_ERR is sent to a consumer from keysock if for some reason
 * keysock could not find a PF_KEY socket to deliver a consumer-originated
 * message (e.g. SADB_ACQUIRE).
 */
typedef struct keysock_out_err_s {
	uint32_t ks_err_type;
	uint32_t ks_err_len;
	minor_t ks_err_serial;
	int ks_err_errno;
	/*
	 * Other, richer error information may end up going here eventually.
	 */
} keysock_out_err_t;

/*
 * M_CTL message type for sending inbound pkt information between IP & ULP.
 * These are _not_ related to IPsec in any way, but are here so that there is
 * one place where all these values are defined which makes it easier to track.
 * The choice of this value has the same rationale as explained above.
 */
#define	IN_PKTINFO		(IPSEC_M_CTL + 24)


/*
 * IPSEC_CTL messages are used by IPsec to send control type requests
 * to IP. Such a control message is currently used by IPsec to request
 * that IP send the contents of an IPsec SA or the entire SADB to
 * every IPsec hardware acceleration capable provider.
 */

#define	IPSEC_CTL		(IPSEC_M_CTL + 25)

typedef struct ipsec_ctl_s {
	uint32_t ipsec_ctl_type;
	uint32_t ipsec_ctl_len;
	uint_t ipsec_ctl_sa_type;
	void *ipsec_ctl_sa;
} ipsec_ctl_t;


/*
 * All IPsec informational messages are placed into the ipsec_info_t
 * union, so that allocation can be done once, and IPsec informational
 * messages can be recycled.
 */
typedef union ipsec_info_u {
	struct {
		uint32_t ipsec_allu_type;
		uint32_t ipsec_allu_len;	/* In bytes */
	} ipsec_allu;
	ipsec_in_t ipsec_in;
	ipsec_out_t ipsec_out;
	keysock_hello_ack_t keysock_hello_ack;
	keysock_in_t keysock_in;
	keysock_out_t keysock_out;
	keysock_out_err_t keysock_out_err;
	ipsec_ctl_t ipsec_ctl;
} ipsec_info_t;
#define	ipsec_info_type ipsec_allu.ipsec_allu_type
#define	ipsec_info_len ipsec_allu.ipsec_allu_len

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPSEC_INFO_H */
