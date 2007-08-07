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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MIPAGENTSTAT_DOOR_H
#define	_MIPAGENTSTAT_DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This header defines constants and structures common to the
 * mipagentstat door client and server. That stat client
 * can retrieve and display information about mobile nodes
 * from mipagent by making enumeration RPCs to the stat server
 * in mipagent. Each door call effects a single enumeration
 * transaction, so the stat client is in effect a sliding
 * window across the registration tables in mipagent.
 *
 * The client / server protocol is defined by the DoorStatsArgs
 * structure. The same structure is used for both call and reply
 * information, and no memory needs to be allocated for the
 * IPC by either the client or server. All address information
 * about mobile nodes and agents is communicated via buffers
 * large enough to hold an IPv6 address, and each address is
 * tagged with an address family so that it can be processed
 * by the stat client.
 *
 * The client keeps track of all enumeration state by passing
 * an opaque state handle to the server for each enumeration
 * transaction. This state handle is the enum_state field in
 * DoorStatArgs. The server is stateless, and simply conducts
 * the enumeration operation based on the information in the
 * state handle and updates the handle each call before passing
 * it back to the client. The client indicates that it wishes to
 * start an enumeration setting the op field to FIRST_ENT; all
 * successive enumeration calls should set the op to NEXT_ENT.
 *
 * The stat client can enumerate either the home or foreign agent
 * tables. Which agent to get stats for is indicated by setting
 * the type field to either HOME_AGENT or FOREIGN_AGENT.
 *
 * The last two fields of DoorStatArgs are the time granted and
 * time remaining for the mobile node being displayed. These times
 * are absolute times, in seconds.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Stat door rendezvous point */
#define	MIPAGENTSTAT_DOOR	"/var/run/.mipagentstat_door"

/* Bits for tracking command-line arguments for HA / FA stats */
#define	DO_HA		0x01
#define	DO_FA		0x02
#define	DO_BOTH		0x03

/*
 * Enum describing which agent to get stats for, and if our output should be
 * be mn-centric, or mobility agent peer-centric.
 */
typedef enum { HOME_AGENT,
		FOREIGN_AGENT,
		HOME_AGENT_PEER,
		FOREIGN_AGENT_PEER } enum_stat_type;

/*
 * Define peer-flags so we know our place in the peer relationship.
 */
#define	HA_PEER	0x01	/* identifies this agent as an HA peer */
#define	FA_PEER	0x02	/* identifies this agent as an FA peer */

/* Enum describing which enumeration operation to do */
typedef enum { FIRST_ENT, NEXT_ENT } enum_op;

/* Call / reply buffer; defines the mipagentstat protocol */
typedef struct door_stat_args {
	/* control (call)  fields */
	enum_stat_type	type;		/* home agent or foreign agent */
	enum_op		op;		/* first or next entry */
	uint8_t		enum_state[16];	/* 128 bits of enumerator state */
	/* data (reply) fields */
	int		node_af;	/* mobile node addr address family */
	int		agent_af;	/* agent addr address family */
	uint8_t		node[sizeof (struct in6_addr)];
					/* mobile node address */
	uint8_t		agent[sizeof (struct in6_addr)];
					/* home/foreign agent name */
	uint32_t	granted;	/* time granted */
	uint32_t	expires;	/* time remaining */
	/* flags - indicate services, and security */
	uint8_t		service_flags;  /* special services for the mn */
} DoorStatArgs;

/* service flags - keep it tightly anologous to the registration */
#define	SERVICE_BIT_UNUSED		0x01 /* placeholder */
#define	SERVICE_REVERSE_TUNNEL		0x02 /* ReverseTunnel Service */
#define	SERVICE_VJ_COMPRESSION		0x04 /* VJ Compression Service */
#define	SERVICE_GRE_ENCAP		0x08 /* GRE Encapsulation Service */
#define	SERVICE_MIN_ENCAP		0x10 /* MIN Encapsulation Service */
#define	SERVICE_DECAPSULATION_BY_MN	0x20 /* MN is Colocated */
#define	SERVICE_FWD_BROADCASTS		0x40 /* [multi/broad]cast service */
#define	SERVICE_SIMULTANEOUS_BINDINGS	0x80 /* Simultaneous binding service */

/*
 * These should be indicated in the Flags column (of mipagentstat) by the flag
 * identifiers in the becon/registration for consistency (when supported):
 *
 * Simultaneous Bindings = S
 * Forwarding Broadcasts = B
 * Decapsulation by MN   = D
 * Minimim Encapsulation = M
 * Generic Encapsulation = G
 * Van Jacobson Compress = V
 * Reverse Tunneling     = T    - supported
 */

#ifdef __cplusplus
}
#endif

#endif /* _MIPAGENTSTAT_DOOR_H */
