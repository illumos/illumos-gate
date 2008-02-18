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

#ifndef _SMB_NETBIOS_H_
#define	_SMB_NETBIOS_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <synch.h>
#include <pthread.h>
#include <strings.h>
#include <netinet/in.h>

#include <smbsrv/libsmbns.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/netbios.h>

#define	QUEUE_INSERT_TAIL(q, e) \
	((e)->back) = (void *)((q)->back);	\
	((e)->forw) = (void *)(q);		\
	((q)->back->forw) = (void *)(e);	\
	((q)->back) = (void *)(e);

#define	QUEUE_CLIP(e) \
	(e)->forw->back = (e)->back;	\
	(e)->back->forw = (e)->forw;	\
	(e)->forw = 0;			\
	(e)->back = 0;

#define	NETBIOS_NAME_SVC_LAUNCHED	0x00001
#define	NETBIOS_NAME_SVC_RUNNING	0x00002
#define	NETBIOS_NAME_SVC_FAILED		0x00004

#define	NETBIOS_DATAGRAM_SVC_LAUNCHED	0x00010
#define	NETBIOS_DATAGRAM_SVC_RUNNING	0x00020
#define	NETBIOS_DATAGRAM_SVC_FAILED	0x00040

#define	NETBIOS_TIMER_LAUNCHED		0x00100
#define	NETBIOS_TIMER_RUNNING		0x00200
#define	NETBIOS_TIMER_FAILED		0x00400

#define	NETBIOS_BROWSER_LAUNCHED	0x01000
#define	NETBIOS_BROWSER_RUNNING		0x02000
#define	NETBIOS_BROWSER_FAILED		0x04000

#define	NETBIOS_SHUTTING_DOWN		0x10000
#define	NETBIOS_SHUT_DOWN		0x20000

char smb_node_type;

#define	SMB_NODETYPE_B	'B'
#define	SMB_NODETYPE_P	'P'
#define	SMB_NODETYPE_M	'M'
#define	SMB_NODETYPE_H	'H'

typedef struct {
	mutex_t mtx;
	cond_t cv;
	uint32_t state;
} netbios_status_t;
extern netbios_status_t nb_status;

/*
 * NAME service definitions
 */
#define	ADDR_FLAG_INVALID		0x0000
#define	ADDR_FLAG_VALID		0x0001

typedef struct addr_entry {
	struct addr_entry 	*forw;
	struct addr_entry 	*back;
	uint32_t		attributes;
	uint32_t		conflict_timer;
	uint32_t		refresh_ttl;
	uint32_t		ttl;
	struct sockaddr_in	sin;
	int			sinlen;
	uint32_t 		flags;
} addr_entry_t;

/*
 *   The NODE_NAME ARRAY is an array of zero or more NUM_NAMES entries
 *   of NODE_NAME records.  Each NODE_NAME entry represents an active
 *   name in the same NetBIOS scope as the requesting name in the
 *   local name table of the responder.  RR_NAME is the requesting
 *   name.
 *
 *   NODE_NAME Entry:
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +---                                                         ---+
 *   |                                                               |
 *   +---                    NETBIOS FORMAT NAME                  ---+
 *   |                                                               |
 *   +---                                                         ---+
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_FLAGS            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   The NAME_FLAGS field:
 *
 *                                             1   1   1   1   1   1
 *     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *   | G |  ONT  |DRG|CNF|ACT|PRM|          RESERVED                 |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 *   The NAME_FLAGS field is defined as:
 *
 *   Symbol     Bit(s)   Description:
 *
 *   RESERVED     7-15   Reserved for future use.  Must be zero (0).
 *   PRM             6   Permanent Name Flag.  If one (1) then entry
 *                       is for the permanent node name.  Flag is zero
 *                       (0) for all other names.
 *   ACT             5   Active Name Flag.  All entries have this flag
 *                       set to one (1).
 *   CNF             4   Conflict Flag.  If one (1) then name on this
 *                       node is in conflict.
 *   DRG             3   Deregister Flag.  If one (1) then this name
 *                       is in the process of being deleted.
 *   ONT           1,2   Owner Node Type:
 *                          00 = B node
 *                          01 = P node
 *                          10 = M node
 *                          11 = Reserved for future use
 *   G               0   Group Name Flag.
 *                       name.
 *                       If zero (0) then it is a UNIQUE NetBIOS name.
 */

typedef struct name_entry {
	struct name_entry 	*forw;
	struct name_entry 	*back;
	unsigned char		name[NETBIOS_NAME_SZ];
	unsigned char		scope[NETBIOS_DOMAIN_NAME_MAX];
	unsigned short		attributes;
	struct addr_entry	addr_list;
	mutex_t			mtx;
} name_entry_t;

struct name_question {
	struct name_entry 	*name;
	unsigned		question_type;
	unsigned		question_class;
};

struct resource_record {
	/*
	 * These two flags and address are contained within RDATA
	 * when rr_type==0x0020 (NB - NetBIOS general Name Service)
	 * and rr_class==0x01 (IN - Internet Class).
	 */

	struct name_entry *name;
	unsigned short rr_type;
	unsigned short rr_class;
	uint32_t ttl;
	unsigned short rdlength;
	unsigned char *rdata;
};

struct name_packet {
	unsigned short		name_trn_id;
	unsigned short		info;

	unsigned		qdcount;	/* question entries */
	unsigned		ancount;	/* answer recs */
	unsigned		nscount;	/* authority recs */
	unsigned		arcount;	/* additional recs */

	struct name_question 	*question;
	struct resource_record 	*answer;
	struct resource_record 	*authority;
	struct resource_record 	*additional;

	unsigned char			block_data[4];	/* begining of space */
};

#define	NAME_OPCODE_R		0x8000	/* RESPONSE flag: 1 bit */
#define	NAME_OPCODE_OPCODE_MASK	0x7800	/* OPCODE Field: 4 bits */
#define	NAME_OPCODE_QUERY	0x0000
#define	NAME_OPCODE_REGISTRATION	0x2800
#define	NAME_OPCODE_RELEASE	0x3000
#define	NAME_OPCODE_WACK	0x3800
#define	NAME_OPCODE_REFRESH	0x4000
#define	NAME_OPCODE_MULTIHOME	0x7800
#define	NAME_NM_FLAGS_AA	0x0400	/* Authoritative Answer:1 bit */
#define	NAME_NM_FLAGS_TC	0x0200	/* Truncation:		1 bit */
#define	NAME_NM_FLAGS_RD	0x0100	/* Recursion desired:	1 bit */
#define	NAME_NM_FLAGS_RA	0x0080	/* Recursion available:	1 bit */
#define	NAME_NM_FLAGS_x2	0x0040	/* reserved, mbz:	1 bit */
#define	NAME_NM_FLAGS_x1	0x0020	/* reserved, mbz:	1 bit */
#define	NAME_NM_FLAGS_B		0x0010	/* Broadcast:		1 bit */
#define	NAME_RCODE_MASK		0x000f	/* RCODE Field:		4 bits */
#define	RCODE_FMT_ERR		0x0001
#define	RCODE_SRV_ERR		0x0002
#define	RCODE_NAM_ERR		0x0003
#define	RCODE_IMP_ERR		0x0004
#define	RCODE_RFS_ERR		0x0005
#define	RCODE_ACT_ERR		0x0006
#define	RCODE_CFT_ERR		0x0007

#define	NM_FLAGS_UNICAST		0
#define	NM_FLAGS_BROADCAST		NAME_NM_FLAGS_B

#define	PACKET_TYPE(x)	((x) & (NAME_OPCODE_R | NAME_OPCODE_OPCODE_MASK | \
			NAME_NM_FLAGS_AA | NAME_NM_FLAGS_RD))

#define	RCODE(x)		((x) & NAME_RCODE_MASK)
#define	POSITIVE_RESPONSE(x)	(RCODE(x) == 0)
#define	NEGATIVE_RESPONSE(x)	(RCODE(x) != 0)

#define	END_NODE_CHALLENGE_REGISTRATION_REQUEST				\
	    (NAME_OPCODE_REGISTRATION | NAME_NM_FLAGS_AA | NAME_NM_FLAGS_RD)
#define	END_NODE_CHALLENGE_NAME_REGISTRATION_RESPONSE			\
	    (NAME_OPCODE_R | END_NODE_CHALLENGE_REGISTRATION_REQUEST)

#define	NAME_QUERY_REQUEST						\
	    (NAME_OPCODE_QUERY | NAME_NM_FLAGS_RD)
#define	NAME_QUERY_RESPONSE						\
	    (NAME_OPCODE_R | NAME_QUERY_REQUEST |			\
	    NAME_NM_FLAGS_AA | NAME_NM_FLAGS_RD)

#define	NODE_STATUS_REQUEST						\
	    (NAME_OPCODE_QUERY)
#define	NODE_STATUS_RESPONSE						\
	    (NAME_OPCODE_R | NODE_STATUS_REQUEST | NAME_NM_FLAGS_AA)

#define	REDIRECT_NAME_QUERY_RESPONSE					\
	    (NAME_OPCODE_R | NAME_QUERY_REQUEST | NAME_NM_FLAGS_RD)

#define	NAME_REFRESH_REQUEST						\
	    (NAME_OPCODE_REFRESH)
#define	NAME_REGISTRATION_REQUEST					\
	    (NAME_OPCODE_REGISTRATION | NAME_NM_FLAGS_RD)
#define	NAME_MULTIHOME_REGISTRATION_REQUEST				\
	    (NAME_OPCODE_MULTIHOME | NAME_NM_FLAGS_RD)
#define	NAME_REGISTRATION_RESPONSE					\
	    (NAME_OPCODE_R | NAME_REGISTRATION_REQUEST | NAME_NM_FLAGS_AA)

#define	NAME_RELEASE_REQUEST						\
	    (NAME_OPCODE_RELEASE)
#define	NAME_RELEASE_RESPONSE						\
	    (NAME_OPCODE_R | NAME_RELEASE_REQUEST | NAME_NM_FLAGS_AA)

#define	WACK_RESPONSE						\
	    (NAME_OPCODE_R | NAME_OPCODE_WACK | NAME_NM_FLAGS_AA)

#define	NAME_QUESTION_TYPE_NB		0x0020
#define	NAME_QUESTION_TYPE_NBSTAT	0x0021
#define	NAME_QUESTION_CLASS_IN		0x0001


#define	NAME_RR_TYPE_A			0x0001	/* IP Address */
#define	NAME_RR_TYPE_NS			0x0002	/* Name Server */
#define	NAME_RR_TYPE_NULL		0x000A	/* NULL */
#define	NAME_RR_TYPE_NB			0x0020	/* NetBIOS Name Service */
#define	NAME_RR_TYPE_NBSTAT		0x0021	/* NetBIOS Node Status */

#define	NAME_RR_CLASS_IN		0x0001	/* NetBIOS Node Status */

#define	NAME_NB_FLAGS_ONT_MASK		(3<<13)
#define	NAME_NB_FLAGS_ONT_B		(0<<13) /* B-node (broadcast) */
#define	NAME_NB_FLAGS_ONT_P		(1<<13)	/* P-node (point-to-point) */
#define	NAME_NB_FLAGS_ONT_M		(2<<13)	/* M-node (multicast) */
#define	NAME_NB_FLAGS_ONT_resv		(3<<13)
#define	NAME_NB_FLAGS_G			(1<<15)	/* Group Name */

#define	UNICAST				0
#define	BROADCAST			1
#define	POINTCAST			2

#define	NAME_ATTR_UNIQUE		0x0000
#define	NAME_ATTR_GROUP			0x8000
#define	NAME_ATTR_OWNER_NODE_TYPE	0x6000
#define	  NAME_ATTR_OWNER_TYPE_BNODE	  0x0000
#define	  NAME_ATTR_OWNER_TYPE_PNODE	  0x2000
#define	  NAME_ATTR_OWNER_TYPE_MNODE	  0x4000
#define	  NAME_ATTR_OWNER_TYPE_HNODE	  0x6000
#define	NAME_ATTR_DEREGISTER		0x1000
#define	NAME_ATTR_CONFLICT		0x0800
#define	NAME_ATTR_ACTIVE_NAME		0x0400
#define	NAME_ATTR_PERMANENT		0x0200
#define	NAME_ATTR_RESERVED		0x01FF
#define	NAME_ATTR_LOCAL			0x0001

#define	NODE_TYPE(x)		((x) & NAME_ATTR_OWNER_NODE_TYPE))
#define	IS_BNODE(x)		(NODE_TYPE(x) == NAME_ATTR_OWNER_TYPE_BNODE)
#define	IS_PNODE(x)		(NODE_TYPE(x) == NAME_ATTR_OWNER_TYPE_PNODE)
#define	IS_MNODE(x)		(NODE_TYPE(x) == NAME_ATTR_OWNER_TYPE_MNODE)
#define	IS_HNODE(x)		(NODE_TYPE(x) == NAME_ATTR_OWNER_TYPE_HNODE)

#define	IS_UNIQUE(x)		(((x) & NAME_ATTR_GROUP) == 0)
#define	IS_GROUP(x)		(((x) & NAME_ATTR_GROUP) != 0)
#define	IS_PERMANENT(x)		(((x) & NAME_ATTR_PERMANENT) != 0)
#define	IS_CONFLICTING(x)	(((x) & NAME_ATTR_CONFLICT) != 0)
#define	IS_ACTIVE(x)		(((x) & NAME_ATTR_ACTIVE) != 0)
#define	IS_DEGREGISTERED(x)	(((x) & NAME_ATTR_ACTIVE) != 0)

#define	IS_LOCAL(x)		(((x) & NAME_ATTR_LOCAL) != 0)
#define	IS_PUBLIC(x)		(((x) & NAME_ATTR_LOCAL) == 0)
#define	PUBLIC_BITS(x)		((x) & ~NAME_ATTR_RESERVED)

#define	SAME_SCOPE(scope, e)	(strcmp((scope), ((e)->scope)) == 0)

/*
 *   STATISTICS Field of the NODE STATUS RESPONSE:
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |               UNIT_ID (Unique unit ID)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       UNIT_ID,continued       |    JUMPERS    |  TEST_RESULT  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       VERSION_NUMBER          |      PERIOD_OF_STATISTICS     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       NUMBER_OF_CRCs          |     NUMBER_ALIGNMENT_ERRORS   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       NUMBER_OF_COLLISIONS    |        NUMBER_SEND_ABORTS     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       NUMBER_GOOD_SENDS                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      NUMBER_GOOD_RECEIVES                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       NUMBER_RETRANSMITS      | NUMBER_NO_RESOURCE_CONDITIONS |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  NUMBER_FREE_COMMAND_BLOCKS   |  TOTAL_NUMBER_COMMAND_BLOCKS  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |MAX_TOTAL_NUMBER_COMMAND_BLOCKS|    NUMBER_PENDING_SESSIONS    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  MAX_NUMBER_PENDING_SESSIONS  |  MAX_TOTAL_SESSIONS_POSSIBLE  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   SESSION_DATA_PACKET_SIZE    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct {
	unsigned char	unit_id[6];
	unsigned char	jumpers;
	unsigned char	test_result;
	unsigned short	version_number;
	unsigned short	statistical_period;
	unsigned short	crc_errors;
	unsigned short	alignment_errors;
	unsigned short	collisions;
	unsigned short	send_aborts;
	unsigned int	good_sends;
	unsigned int	good_receives;
	unsigned short	retransmits;
	unsigned short	no_resource_conditions;
	unsigned short	free_command_blocks;
	unsigned short	total_command_blocks;
	unsigned short	max_total_command_blocks;
	unsigned short	pending_sessions;
	unsigned short	max_pending_sessions;
	unsigned short	total_possible_sessions;
	unsigned short	session_data_packet_size;
} node_status_response;

/*
 * 4.4.1.  NetBIOS DATAGRAM HEADER
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           SOURCE_IP                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          SOURCE_PORT          |          DGM_LENGTH           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |         PACKET_OFFSET         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct {
	unsigned char	msg_type;
	unsigned char	flags;
	unsigned short	dgm_id;
	uint32_t	source_ip;
	unsigned short	source_port;
	unsigned short	dgm_length;
	unsigned short	packet_offset;
} datagram_header;

/*
 *    MSG_TYPE values (in hexidecimal):
 *
 *            10 -  DIRECT_UNIQUE DATAGRAM
 *            11 -  DIRECT_GROUP DATAGRAM
 *            12 -  BROADCAST DATAGRAM
 *            13 -  DATAGRAM ERROR
 *            14 -  DATAGRAM QUERY REQUEST
 *            15 -  DATAGRAM POSITIVE QUERY RESPONSE
 *            16 -  DATAGRAM NEGATIVE QUERY RESPONSE
 */
#define	DATAGRAM_TYPE_DIRECT_UNIQUE	0x10
#define	DATAGRAM_TYPE_DIRECT_GROUP	0x11
#define	DATAGRAM_TYPE_BROADCAST		0x12
#define	DATAGRAM_TYPE_ERROR_DATAGRAM	0x13
#define	DATAGRAM_TYPE_QUERY_REQUEST	0x14
#define	DATAGRAM_TYPE_POSITIVE_RESPONSE	0x15
#define	DATAGRAM_TYPE_NEGATIVE_RESPONSE	0x16


/*
 *    Bit definitions of the FLAGS field:
 *
 *      0   1   2   3   4   5   6   7
 *    +---+---+---+---+---+---+---+---+
 *    | 0 | 0 | 0 | 0 |  SNT  | F | M |
 *    +---+---+---+---+---+---+---+---+
 *
 *    Symbol     Bit(s)   Description
 *
 *    M               7   MORE flag, If set then more NetBIOS datagram
 *                        fragments follow.
 *
 *    F               6   FIRST packet flag,  If set then this is first
 *                        (and possibly only) fragment of NetBIOS
 *                        datagram
 *
 *    SNT           4,5   Source End-Node type:
 *                           00 = B node
 *                           01 = P node
 *                           10 = M node
 *                           11 = H node
 *    RESERVED      0-3   Reserved, must be zero (0)
 */
#define	DATAGRAM_FLAGS_MORE	0x01
#define	DATAGRAM_FLAGS_FIRST	0x02
#define	DATAGRAM_FLAGS_SRC_TYPE	0x0c
#define	DATAGRAM_FLAGS_B_NODE	  0x00
#define	DATAGRAM_FLAGS_P_NODE	  0x04
#define	DATAGRAM_FLAGS_M_NODE	  0x08
#define	DATAGRAM_FLAGS_H_NODE	  0x0C
#define	DATAGRAM_FLAGS_NBDD	  0x0c
#define	DATAGRAM_FLAGS_RESERVED	0xf0

/*
 * 4.4.2.  DIRECT_UNIQUE, DIRECT_GROUP, & BROADCAST DATAGRAM
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           SOURCE_IP                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          SOURCE_PORT          |          DGM_LENGTH           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |         PACKET_OFFSET         |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *    |                                                               |
 *    /                          SOURCE_NAME                          /
 *    /                                                               /
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    /                       DESTINATION_NAME                        /
 *    /                                                               /
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    /                           USER_DATA                           /
 *    /                                                               /
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct {
	datagram_header	header;
	unsigned char	*source_name;
	unsigned char	*destination_name;
	unsigned char	*user_data;
} datagram_packet;


/*
 *    4.4.3.  DATAGRAM ERROR PACKET
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           SOURCE_IP                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          SOURCE_PORT          |  ERROR_CODE   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    ERROR_CODE values (in hexidecimal):
 *
 *            82 -  DESTINATION NAME NOT PRESENT
 *            83 -  INVALID SOURCE NAME FORMAT
 *            84 -  INVALID DESTINATION NAME FORMAT
 */

typedef struct {
	unsigned char	msg_type;
	unsigned char	flags;
	unsigned short	dgm_id;
	uint32_t	source_ip;
	unsigned short	source_port;
	unsigned char	error;
} datagram_error_packet;

/*
 * 4.4.4.  DATAGRAM QUERY REQUEST
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           SOURCE_IP                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          SOURCE_PORT          |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                                                               |
 *    /                       DESTINATION_NAME                        /
 *    /                                                               /
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 4.4.5.  DATAGRAM POSITIVE AND NEGATIVE QUERY RESPONSE
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           SOURCE_IP                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          SOURCE_PORT          |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                                                               |
 *    /                       DESTINATION_NAME                        /
 *    /                                                               /
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct datagram_query_packet {
	unsigned char	msg_type;
	unsigned char	flags;
	unsigned short	dgm_id;
	uint32_t	source_ip;
	unsigned short	source_port;
	unsigned char	destination_name[MAX_NAME_LENGTH];
} datagram_query_packet;


typedef struct datagram {
	struct datagram 	*forw;
	struct datagram 	*back;
	struct addr_entry	inaddr;
	int			discard_timer;
	unsigned char		packet_type;
	unsigned char		flags;
	unsigned short		datagram_id;
	struct name_entry	src;
	struct name_entry	dest;
	unsigned short		offset;
	unsigned short		data_length;
	unsigned char 		*data;
	unsigned int		rawbytes;
	unsigned char		rawbuf[MAX_DATAGRAM_LENGTH];
} datagram;

typedef struct datagram_queue {
	struct datagram 	*forw;
	struct datagram 	*back;
} datagram_queue;

typedef struct name_queue {
	struct name_entry head;
	mutex_t mtx;
} name_queue_t;

typedef struct nbcache_iter {
	HT_ITERATOR		nbc_hti;
	struct name_entry	*nbc_entry;
} nbcache_iter_t;

#define	NETBIOS_EMPTY_NAME (unsigned char *)""

#define	NETBIOS_NAME_IS_STAR(name) \
	(bcmp(name, "*\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", NETBIOS_NAME_SZ) == 0)

void smb_netbios_chg_status(uint32_t status, int set);

/*
 * Name Cache Functions
 */
int  smb_netbios_cache_init(void);
void smb_netbios_cache_fini(void);
void smb_netbios_cache_dump(void);
int smb_netbios_cache_count(void);
void smb_netbios_cache_clean(void);
void smb_netbios_cache_reset_ttl(void);
void smb_netbios_cache_delete_locals(name_queue_t *);
void smb_netbios_cache_refresh(name_queue_t *);

int smb_netbios_cache_insert(struct name_entry *name);
int smb_netbios_cache_insert_list(struct name_entry *name);
void smb_netbios_cache_delete(struct name_entry *name);
int smb_netbios_cache_delete_addr(struct name_entry *name);
struct name_entry *smb_netbios_cache_lookup(struct name_entry *name);
struct name_entry *smb_netbios_cache_lookup_addr(struct name_entry *name);
void smb_netbios_cache_update_entry(struct name_entry *, struct name_entry *);
void smb_netbios_cache_unlock_entry(struct name_entry *);
unsigned char *smb_netbios_cache_status(unsigned char *, int, unsigned char *);
int smb_netbios_cache_getfirst(nbcache_iter_t *);
int smb_netbios_cache_getnext(nbcache_iter_t *);

void smb_netbios_name_dump(struct name_entry *entry);
void smb_netbios_name_logf(struct name_entry *entry);
void smb_netbios_name_freeaddrs(struct name_entry *entry);
struct name_entry *smb_netbios_name_dup(struct name_entry *, int);

/* Name service functions */
void *smb_netbios_name_service_daemon(void *);
void smb_init_name_struct(unsigned char *, char, unsigned char *, uint32_t,
    unsigned short, uint32_t, uint32_t, struct name_entry *);

struct name_entry *smb_name_find_name(struct name_entry *name);
int smb_name_add_name(struct name_entry *name);
int smb_name_delete_name(struct name_entry *name);
void smb_name_unlock_name(struct name_entry *name);

void smb_netbios_name_config(void);
void smb_netbios_name_unconfig(void);
void smb_netbios_name_tick(void);

int smb_first_level_name_encode(struct name_entry *, unsigned char *, int);
int smb_first_level_name_decode(unsigned char *, struct name_entry *);
void smb_encode_netbios_name(unsigned char *, char, unsigned char *,
    struct name_entry *);

/* Datagram service functions */
void *smb_netbios_datagram_service_daemon(void *);
int smb_netbios_datagram_send(struct name_entry *,
    struct name_entry *, unsigned char *, int);
void smb_netbios_datagram_tick(void);

/* browser functions */
void *smb_browser_dispatch(void *arg);
void *smb_browser_daemon(void *);
int smb_browser_load_transact_header(unsigned char *, int, int, int, char *);

/* Netlogon function */
void smb_netlogon_receive(struct datagram *, char *, unsigned char *, int);
void smb_netlogon_request(struct name_entry *, int, char *);

#endif /* _SMB_NETBIOS_H_ */
