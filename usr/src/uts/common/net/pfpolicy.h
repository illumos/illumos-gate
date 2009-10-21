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
 */

#ifndef	_NET_PFPOLICY_H
#define	_NET_PFPOLICY_H

/*
 * Definitions and structures for PF_POLICY version 1.
 *
 * This local protocol provides an interface allowing utilities to
 * manage a system's IPsec System Policy Database; see RFC2401 for a
 * conceptual overview of the SPD.
 * The basic encoding is modelled on PF_KEY version 2; see pfkeyv2.h
 * and RFC2367 for more information.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	PF_POLICY_V1		1
#define	PF_POLICY_REVISION	200304L

/*
 * Base PF_POLICY message header.  Each request/response starts with
 * one of these, followed by some number of extensions.  Each
 * extension type appears at most once in a message.  spd_msg_len
 * contains the total length of the message including header.
 */
typedef struct spd_msg
{
	uint8_t spd_msg_version;	/* PF_POLICY_V1 */
	uint8_t spd_msg_type;		/* ADD, DELETE, QUERY, ... */
	uint8_t spd_msg_errno;		/* Unix errno space; mbz on request */
	uint8_t spd_msg_spdid;		/* which policy db instance */
	uint16_t spd_msg_len;		/* in 64-bit words */
	uint16_t spd_msg_diagnostic;	/* additional error reason */
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint32_t spd_msg_useq;		/* set by sender */
			uint32_t spd_msg_upid;		/* set by sender */
		} spd_msg_actual;
		uint64_t spd_msg_alignment;
	} spd_msg_u;
#define	spd_msg_seq spd_msg_u.spd_msg_actual.spd_msg_useq
#define	spd_msg_pid spd_msg_u.spd_msg_actual.spd_msg_upid
} spd_msg_t;

/*
 * Command numbers, found in spd_msg_type.
 */
#define	SPD_RESERVED				0
#define	SPD_MIN					1
#define	SPD_FLUSH				1
#define	SPD_ADDRULE				2
#define	SPD_DELETERULE				3
#define	SPD_FLIP				4
#define	SPD_LOOKUP				5
#define	SPD_DUMP				6
#define	SPD_CLONE				7
#define	SPD_ALGLIST				8
#define	SPD_DUMPALGS				9
#define	SPD_UPDATEALGS				10
#define	SPD_MAX					10

/*
 * Well-known policy db instances, found in spd_msg_spdid
 */
#define	SPD_ACTIVE		0	/* The currently active instance */
#define	SPD_STANDBY		1 	/* "on deck" standby SPD */

/*
 * The spd_msg_t is followed by extensions, which start with the
 * following header; each extension structure includes the length and
 * type fields internally as an overlay to simplify parsing and
 * construction.
 */
typedef struct spd_ext
{
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t spd_ext_ulen;		/* in 64-bit words */
			uint16_t spd_ext_utype;		/* 0 is reserved */
		} spd_ext_actual;
		uint64_t spd_ext_alignment;
	} spd_ext_u;
#define	spd_ext_len spd_ext_u.spd_ext_actual.spd_ext_ulen
#define	spd_ext_type spd_ext_u.spd_ext_actual.spd_ext_utype
} spd_ext_t;

/*
 * Extension numbers, found in spd_ext_type.
 */

#define	SPD_EXT_LCLPORT				1
#define	SPD_EXT_REMPORT				2
#define	SPD_EXT_PROTO				3
#define	SPD_EXT_LCLADDR				4
#define	SPD_EXT_REMADDR				5

#define	SPD_EXT_ACTION				6
#define	SPD_EXT_RULE				7
#define	SPD_EXT_RULESET				8
#define	SPD_EXT_ICMP_TYPECODE  			9

#define	SPD_EXT_TUN_NAME			10

#define	SPD_EXT_MAX				10

/*
 * base policy rule (attributes which every rule has)
 *
 * spd_rule_index MBZ on a SPD_ADD, and is assigned by the kernel.
 * subsequent deletes can operate either by specifying selectors or by
 * specifying a non-zero rule index.
 */
struct spd_rule
{
	uint16_t spd_rule_len;
	uint16_t spd_rule_type;		/* SPD_EXT_RULE */
	uint32_t spd_rule_priority;
	uint32_t spd_rule_flags;	/* INBOUND, OUTBOUND, ... */
	uint32_t spd_rule_unused;
	uint64_t spd_rule_index;	/* unique rule identifier. */
};

/*
 * Flags for spd_rule.spd_rule_flags
 */
#define	SPD_RULE_FLAG_INBOUND		0x0001
#define	SPD_RULE_FLAG_OUTBOUND		0x0002
/* Only applies to tunnel policy heads. */
#define	SPD_RULE_FLAG_TUNNEL		0x0004

/*
 * Address selectors.   Different from PF_KEY because we want a
 * more precise format for wildcards on ports/protocol.
 */
typedef struct spd_address {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t spd_address_ulen;
			uint16_t spd_address_uexttype;	/* SRC, DST */
			uint8_t spd_address_uaf;	/* address family. */
			uint8_t spd_address_uprefixlen;	/* Prefix len (bits). */
			uint16_t spd_address_ureserved2; /* Padding */
		} spd_address_actual;
		uint64_t spd_address_alignment;
	} spd_address_u;
	/*
	 * .. followed by 4 bytes of IPv4 or 16 bytes of IPv6 address,
	 * padded up to next uint64_t
	 */
#define	spd_address_len	\
	spd_address_u.spd_address_actual.spd_address_ulen
#define	spd_address_exttype \
	spd_address_u.spd_address_actual.spd_address_uexttype
#define	spd_address_af \
	spd_address_u.spd_address_actual.spd_address_uaf
#define	spd_address_prefixlen \
	spd_address_u.spd_address_actual.spd_address_uprefixlen
#define	spd_address_reserved2 \
	spd_address_u.spd_address_actual.spd_address_ureserved2
} spd_address_t;

/*
 * Protocol selector
 */
struct spd_proto
{
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t spd_proto_ulen;
			uint16_t spd_proto_uexttype;		/* PROTO */
			uint8_t spd_proto_unumber;		/* IPPROTO_* */
			uint8_t	spd_proto_ureserved1;		 /* pad */
			uint16_t spd_proto_ureserved2;		 /* pad */
		} spd_proto_actual;
		uint64_t spd_proto_alignment;
	} spd_proto_u;
#define	spd_proto_len spd_proto_u.spd_proto_actual.spd_proto_ulen
#define	spd_proto_exttype spd_proto_u.spd_proto_actual.spd_proto_uexttype
#define	spd_proto_number spd_proto_u.spd_proto_actual.spd_proto_unumber
#define	spd_proto_reserved1 spd_proto_u.spd_proto_actual.spd_proto_ureserved1
#define	spd_proto_reserved2 spd_proto_u.spd_proto_actual.spd_proto_ureserved2
};

/*
 * Port selector.  We only support minport==maxport at present.
 */
struct spd_portrange
{
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t spd_ports_ulen;
			uint16_t spd_ports_uexttype;	/* LCLPORT, REMPORT */
			uint16_t spd_ports_uminport;	/* min port */
			uint16_t spd_ports_umaxport;	/* max port */
		} spd_ports_actual;
		uint64_t spd_ports_alignment;
	} spd_ports_u;
#define	spd_ports_len spd_ports_u.spd_ports_actual.spd_ports_ulen
#define	spd_ports_exttype spd_ports_u.spd_ports_actual.spd_ports_uexttype
#define	spd_ports_minport spd_ports_u.spd_ports_actual.spd_ports_uminport
#define	spd_ports_maxport spd_ports_u.spd_ports_actual.spd_ports_umaxport
};

/*
 * ICMP type selector.
 */
struct spd_typecode
{
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t spd_typecode_ulen;
			uint16_t spd_typecode_uexttype;	/* ICMP_TYPECODE */
			uint8_t  spd_typecode_utype;
			uint8_t  spd_typecode_utype_end;
			uint8_t  spd_typecode_ucode;
			uint8_t  spd_typecode_ucode_end;
		} spd_typecode_actual;
		uint64_t spd_typecode_alignment;
	} spd_typecode_u;
#define	spd_typecode_len	\
    spd_typecode_u.spd_typecode_actual.spd_typecode_ulen
#define	spd_typecode_exttype	\
    spd_typecode_u.spd_typecode_actual.spd_typecode_uexttype
#define	spd_typecode_type	\
    spd_typecode_u.spd_typecode_actual.spd_typecode_utype
#define	spd_typecode_type_end	\
    spd_typecode_u.spd_typecode_actual.spd_typecode_utype_end
#define	spd_typecode_code	\
    spd_typecode_u.spd_typecode_actual.spd_typecode_ucode
#define	spd_typecode_code_end	\
    spd_typecode_u.spd_typecode_actual.spd_typecode_ucode_end
};


/*
 * Actions, specifying what happens to packets which match selectors.
 * This extension is followed by some number of spd_attribute tag-value pairs
 * which encode one or more alternative policies; see below for
 * the encoding used.
 */
struct spd_ext_actions
{
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t spd_actions_ulen;
			uint16_t spd_actions_uexttype;	/* ACTION */
			uint16_t spd_actions_ucount;	/* # of alternatives */
			uint16_t spd_actions_ureserved;
		} spd_actions_actual;
		uint64_t spd_actions_alignment;
	} spd_actions_u;
#define	spd_actions_len \
	spd_actions_u.spd_actions_actual.spd_actions_ulen
#define	spd_actions_exttype \
	spd_actions_u.spd_actions_actual.spd_actions_uexttype
#define	spd_actions_count \
	spd_actions_u.spd_actions_actual.spd_actions_ucount
#define	spd_actions_reserved \
	spd_actions_u.spd_actions_actual.spd_actions_ureserved
};

/*
 * Extensible encoding for requested SA attributes.
 * To allow additional attributes to be added, we use a simple-to-interpret
 * (tag, value) encoding to fill in attributes in a list of alternatives.
 *
 * We fill in alternatives one at a time, starting with most-preferred,
 * proceeding to least-preferred.
 *
 * Conceptually, we are filling in attributes of a "template", and
 * then copying that template value into the list of alternatives when
 * we see a SPD_ATTR_END or SPD_ATTR_NEXT.
 *
 * The template is not changed by SPD_ATTR_NEXT, so that attributes common to
 * all alternatives need only be mentioned once.
 *
 * spd_actions_count is the maximum number of alternatives present; it
 * should be one greater than the number of SPD_ATTR_NEXT opcodes
 * present in the sequence.
 */

struct spd_attribute
{
	union {
		struct {
			uint32_t	spd_attr_utag;
			uint32_t	spd_attr_uvalue;
		} spd_attribute_actual;
		uint64_t spd_attribute_alignment;
	} spd_attribute_u;
#define	spd_attr_tag spd_attribute_u.spd_attribute_actual.spd_attr_utag
#define	spd_attr_value spd_attribute_u.spd_attribute_actual.spd_attr_uvalue
};

/*
 * These flags are used by the kernel algorithm structures and by ipsecalgs(1m).
 * ALG_FLAG_KERNELCHECKED is used by ipsecalgs(1m) to tag ipsecalgent_t as
 * kernel verified. ALG_FLAG_VALID is only meaningful if set by the kernel.
 */
#define	ALG_FLAG_VALID		0x01
#define	ALG_FLAG_COUNTERMODE	0x02
#define	ALG_FLAG_COMBINED	0x04
#define	ALG_FLAG_CCM		0x08
#define	ALG_FLAG_GCM		0x10
#define	ALG_FLAG_KERNELCHECKED	0x80000000

#define	SPD_ATTR_NOP	0x00000000	/* space filler */
#define	SPD_ATTR_END	0x00000001	/* end of description */
#define	SPD_ATTR_EMPTY	0x00000002	/* reset template to default */
#define	SPD_ATTR_NEXT	0x00000003	/* start filling next alternative */

#define	SPD_ATTR_TYPE			0x00000100
#define	SPD_ATTR_FLAGS			0x00000101
#define	SPD_ATTR_AH_AUTH		0x00000102
#define	SPD_ATTR_ESP_ENCR		0x00000103
#define	SPD_ATTR_ESP_AUTH		0x00000104
#define	SPD_ATTR_ENCR_MINBITS		0x00000105
#define	SPD_ATTR_ENCR_MAXBITS		0x00000106
#define	SPD_ATTR_AH_MINBITS		0x00000107
#define	SPD_ATTR_AH_MAXBITS		0x00000108
#define	SPD_ATTR_LIFE_SOFT_TIME		0x00000109
#define	SPD_ATTR_LIFE_HARD_TIME		0x0000010a
#define	SPD_ATTR_LIFE_SOFT_BYTES	0x0000010b
#define	SPD_ATTR_LIFE_HARD_BYTES	0x0000010c
#define	SPD_ATTR_KM_PROTO		0x0000010d
#define	SPD_ATTR_KM_COOKIE		0x0000010e
#define	SPD_ATTR_REPLAY_DEPTH		0x0000010f
#define	SPD_ATTR_ESPA_MINBITS		0x00000110
#define	SPD_ATTR_ESPA_MAXBITS		0x00000111
#define	SPD_ATTR_ENCR_DEFBITS		0x00000112
#define	SPD_ATTR_ENCR_INCRBITS		0x00000113
#define	SPD_ATTR_AH_DEFBITS		0x00000114
#define	SPD_ATTR_AH_INCRBITS		0x00000115
#define	SPD_ATTR_ESPA_DEFBITS		0x00000116
#define	SPD_ATTR_ESPA_INCRBITS		0x00000117
#define	SPD_ATTR_ALG_ID			0x00000118
#define	SPD_ATTR_ALG_PROTO		0x00000119
#define	SPD_ATTR_ALG_INCRBITS		0x0000011a
#define	SPD_ATTR_ALG_NKEYSIZES		0x0000011b
#define	SPD_ATTR_ALG_KEYSIZE		0x0000011c
#define	SPD_ATTR_ALG_NBLOCKSIZES	0x0000011d
#define	SPD_ATTR_ALG_BLOCKSIZE		0x0000011e
#define	SPD_ATTR_ALG_MECHNAME		0x0000011f
#define	SPD_ATTR_PROTO_ID		0x00000120
#define	SPD_ATTR_PROTO_EXEC_MODE	0x00000121
#define	SPD_ATTR_ALG_NPARAMS		0x00000122
#define	SPD_ATTR_ALG_PARAMS		0x00000123
#define	SPD_ATTR_ALG_FLAGS		0x00000124

/*
 * An interface extension identifies a network interface.
 * It is used for configuring Tunnel Mode policies on a tunnelling
 * interface for now.
 */
typedef struct spd_if_s {
	union {
		struct {
			uint16_t spd_if_ulen;
			uint16_t spd_if_uexttype;
			union {
				uint8_t spd_if_iuname[4];
				uint32_t spd_if_iuindex;
			} spd_if_iu;
		} spd_if_actual;
		uint64_t spd_if_alignment;
	} spd_if_u;
#define	spd_if_len spd_if_u.spd_if_actual.spd_if_ulen
#define	spd_if_exttype spd_if_u.spd_if_actual.spd_if_uexttype
#define	spd_if_name spd_if_u.spd_if_actual.spd_if_iu.spd_if_iuname
#define	spd_if_index spd_if_u.spd_if_actual.spd_if_iu.spd_if_iuindex
} spd_if_t;

/*
 * Minimum, maximum key lengths in bits.
 */
#define	SPD_MIN_MINBITS		0x0000
#define	SPD_MAX_MAXBITS		0xffff

/*
 * IPsec action types (in SPD_ATTR_TYPE attribute)
 */
#define	SPD_ACTTYPE_DROP	0x0001
#define	SPD_ACTTYPE_PASS	0x0002
#define	SPD_ACTTYPE_IPSEC	0x0003

/*
 * Action flags (in SPD_ATTR_FLAGS attribute)
 */
#define	SPD_APPLY_AH		0x0001
#define	SPD_APPLY_ESP		0x0002
#define	SPD_APPLY_SE		0x0004  /* self-encapsulation */
#define	SPD_APPLY_COMP		0x0008	/* compression; NYI */
#define	SPD_APPLY_UNIQUE	0x0010	/* unique per-flow SA */
#define	SPD_APPLY_BYPASS	0x0020	/* bypass policy */
#define	SPD_APPLY_ESPA		0x0040 	/* ESP authentication */

/*
 * SW crypto execution modes.
 */
#define	SPD_ALG_EXEC_MODE_SYNC		1	/* synchronous */
#define	SPD_ALG_EXEC_MODE_ASYNC		2	/* asynchronous */

/*
 * SPD_DUMP protocol:
 *
 * We do not want to force an stack to have to read-lock the entire
 * SPD for the duration of the dump, but we want management apps to be
 * able to get a consistent snapshot of the SPD.
 *
 * Therefore, we make optimistic locking assumptions.
 *
 * The response to a SPD_DUMP request consists of multiple spd_msg
 * records, all with spd_msg_type == SPD_DUMP and spd_msg_{seq,pid}
 * matching the request.
 *
 * There is one header, then a sequence of policy rule records (one
 * rule per record), then a trailer.
 *
 * The header and trailer both contain a single SPD_EXT_RULESET
 * containing a version number and rule count.  The dump was "good" if
 * header version == trailer version, and the number of rules read by
 * the application matches the rule count in the trailer.  The rule
 * count in the header is unused and should be set to zero.
 *
 * In between, each rule record contains a set of extensions which, if
 * used in an SPD_ADD request, would recreate an equivalent rule.
 *
 * If rules were added to the SPD during the dump, the dump may be
 * truncated or otherwise incomplete; the management application
 * should re-try the dump in this case.
 */

/*
 * Ruleset extension, used at the start and end of a SPD_DUMP.
 */
typedef struct spd_ruleset_ext
{
	uint16_t spd_ruleset_len;	/* 2 x 64 bits */
	uint16_t spd_ruleset_type;	/* SPD_EXT_RULESET */
	uint32_t spd_ruleset_count;	/* only valid in trailer */
	uint64_t spd_ruleset_version;	/* version number */
} spd_ruleset_ext_t;

/*
 * Diagnostic codes.  These supplement error messages.  Be sure to
 * update libipsecutil's spdsock_diag() if you change any of these.
 */
#define	SPD_DIAGNOSTIC_NONE			0
#define	SPD_DIAGNOSTIC_UNKNOWN_EXT		1
#define	SPD_DIAGNOSTIC_BAD_EXTLEN		2
#define	SPD_DIAGNOSTIC_NO_RULE_EXT		3
#define	SPD_DIAGNOSTIC_BAD_ADDR_LEN		4
#define	SPD_DIAGNOSTIC_MIXED_AF			5
#define	SPD_DIAGNOSTIC_ADD_NO_MEM		6
#define	SPD_DIAGNOSTIC_ADD_WRONG_ACT_COUNT	7
#define	SPD_DIAGNOSTIC_ADD_BAD_TYPE		8
#define	SPD_DIAGNOSTIC_ADD_BAD_FLAGS		9
#define	SPD_DIAGNOSTIC_ADD_INCON_FLAGS		10
#define	SPD_DIAGNOSTIC_MALFORMED_LCLPORT 	11
#define	SPD_DIAGNOSTIC_DUPLICATE_LCLPORT	12
#define	SPD_DIAGNOSTIC_MALFORMED_REMPORT	13
#define	SPD_DIAGNOSTIC_DUPLICATE_REMPORT	14
#define	SPD_DIAGNOSTIC_MALFORMED_PROTO		15
#define	SPD_DIAGNOSTIC_DUPLICATE_PROTO		16
#define	SPD_DIAGNOSTIC_MALFORMED_LCLADDR	17
#define	SPD_DIAGNOSTIC_DUPLICATE_LCLADDR	18
#define	SPD_DIAGNOSTIC_MALFORMED_REMADDR	19
#define	SPD_DIAGNOSTIC_DUPLICATE_REMADDR	20
#define	SPD_DIAGNOSTIC_MALFORMED_ACTION		21
#define	SPD_DIAGNOSTIC_DUPLICATE_ACTION		22
#define	SPD_DIAGNOSTIC_MALFORMED_RULE		23
#define	SPD_DIAGNOSTIC_DUPLICATE_RULE		24
#define	SPD_DIAGNOSTIC_MALFORMED_RULESET	25
#define	SPD_DIAGNOSTIC_DUPLICATE_RULESET	26
#define	SPD_DIAGNOSTIC_INVALID_RULE_INDEX	27
#define	SPD_DIAGNOSTIC_BAD_SPDID		28
#define	SPD_DIAGNOSTIC_BAD_MSG_TYPE		29
#define	SPD_DIAGNOSTIC_UNSUPP_AH_ALG		30
#define	SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_ALG	31
#define	SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_ALG	32
#define	SPD_DIAGNOSTIC_UNSUPP_AH_KEYSIZE	33
#define	SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_KEYSIZE	34
#define	SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_KEYSIZE	35
#define	SPD_DIAGNOSTIC_NO_ACTION_EXT		36
#define	SPD_DIAGNOSTIC_ALG_ID_RANGE		37
#define	SPD_DIAGNOSTIC_ALG_NUM_KEY_SIZES	38
#define	SPD_DIAGNOSTIC_ALG_NUM_BLOCK_SIZES	39
#define	SPD_DIAGNOSTIC_ALG_MECH_NAME_LEN	40
#define	SPD_DIAGNOSTIC_ALG_IPSEC_NOT_LOADED	41
#define	SPD_DIAGNOSTIC_MALFORMED_ICMP_TYPECODE	42
#define	SPD_DIAGNOSTIC_DUPLICATE_ICMP_TYPECODE	43
#define	SPD_DIAGNOSTIC_NOT_GLOBAL_OP		44
#define	SPD_DIAGNOSTIC_NO_TUNNEL_SELECTORS	45

/*
 * Helper macros.
 */
#define	SPD_64TO8(x)	((x) << 3)
#define	SPD_8TO64(x)	((x) >> 3)
#define	SPD_8TO1(x)	((x) << 3)
#define	SPD_1TO8(x)	((x) >> 3)

#ifdef	__cplusplus
}
#endif

#endif	/* _NET_PFPOLICY_H */
