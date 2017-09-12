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
 * Copyright (c) 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _INET_IPSEC_IMPL_H
#define	_INET_IPSEC_IMPL_H

#include <inet/ip.h>
#include <inet/ipdrop.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	IPSEC_CONF_SRC_ADDRESS	0	/* Source Address */
#define	IPSEC_CONF_SRC_PORT		1	/* Source Port */
#define	IPSEC_CONF_DST_ADDRESS	2	/* Dest Address */
#define	IPSEC_CONF_DST_PORT		3	/* Dest Port */
#define	IPSEC_CONF_SRC_MASK		4	/* Source Address Mask */
#define	IPSEC_CONF_DST_MASK		5	/* Destination Address Mask */
#define	IPSEC_CONF_ULP			6	/* Upper layer Port */
#define	IPSEC_CONF_IPSEC_PROT	7	/* AH or ESP or AH_ESP */
#define	IPSEC_CONF_IPSEC_AALGS	8	/* Auth Algorithms - MD5 etc. */
#define	IPSEC_CONF_IPSEC_EALGS	9	/* Encr Algorithms - DES etc. */
#define	IPSEC_CONF_IPSEC_EAALGS	10	/* Encr Algorithms - MD5 etc. */
#define	IPSEC_CONF_IPSEC_SA		11	/* Shared or unique SA */
#define	IPSEC_CONF_IPSEC_DIR 		12	/* Direction of traffic */
#define	IPSEC_CONF_ICMP_TYPE 		13	/* ICMP type */
#define	IPSEC_CONF_ICMP_CODE 		14	/* ICMP code */
#define	IPSEC_CONF_NEGOTIATE		15	/* Negotiation */
#define	IPSEC_CONF_TUNNEL		16	/* Tunnel */

/* Type of an entry */

#define	IPSEC_NTYPES			0x02
#define	IPSEC_TYPE_OUTBOUND		0x00
#define	IPSEC_TYPE_INBOUND		0x01

/* Policy */
#define	IPSEC_POLICY_APPLY	0x01
#define	IPSEC_POLICY_DISCARD	0x02
#define	IPSEC_POLICY_BYPASS	0x03

/* Shared or unique SA */
#define	IPSEC_SHARED_SA		0x01
#define	IPSEC_UNIQUE_SA		0x02

/* IPsec protocols and combinations */
#define	IPSEC_AH_ONLY		0x01
#define	IPSEC_ESP_ONLY		0x02
#define	IPSEC_AH_ESP		0x03

/*
 * Internally defined "any" algorithm.
 * Move to PF_KEY v3 when that RFC is released.
 */
#define	SADB_AALG_ANY 255

#ifdef _KERNEL

#include <inet/common.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/pfkeyv2.h>
#include <inet/ip.h>
#include <inet/sadb.h>
#include <inet/ipsecah.h>
#include <inet/ipsecesp.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/avl.h>

/*
 * Maximum number of authentication algorithms (can be indexed by one byte
 * per PF_KEY and the IKE IPsec DOI.
 */
#define	MAX_AALGS 256

/*
 * IPsec task queue constants.
 */
#define	IPSEC_TASKQ_MIN 10
#define	IPSEC_TASKQ_MAX 20

/*
 * So we can access IPsec global variables that live in keysock.c.
 */
extern boolean_t keysock_extended_reg(netstack_t *);
extern uint32_t keysock_next_seq(netstack_t *);

/* Common-code for spdsock and keysock. */
extern void keysock_spdsock_wput_iocdata(queue_t *, mblk_t *, sa_family_t);

/*
 * Locking for ipsec policy rules:
 *
 * policy heads: system policy is static; per-conn polheads are dynamic,
 * and refcounted (and inherited); use atomic refcounts and "don't let
 * go with both hands".
 *
 * policy: refcounted; references from polhead, ipsec_out
 *
 * actions: refcounted; referenced from: action hash table, policy, ipsec_out
 * selectors: refcounted; referenced from: selector hash table, policy.
 */

/*
 * the following are inspired by, but not directly based on,
 * some of the sys/queue.h type-safe pseudo-polymorphic macros
 * found in BSD.
 *
 * XXX If we use these more generally, we'll have to make the names
 * less generic (HASH_* will probably clobber other namespaces).
 */

#define	HASH_LOCK(table, hash) \
	mutex_enter(&(table)[hash].hash_lock)
#define	HASH_UNLOCK(table, hash) \
	mutex_exit(&(table)[hash].hash_lock)

#define	HASH_LOCKED(table, hash) \
	MUTEX_HELD(&(table)[hash].hash_lock)

#define	HASH_ITERATE(var, field, table, hash) 		\
	var = table[hash].hash_head; var != NULL; var = var->field.hash_next

#define	HASH_NEXT(var, field) 		\
	(var)->field.hash_next

#define	HASH_INSERT(var, field, table, hash)			\
{								\
	ASSERT(HASH_LOCKED(table, hash));			\
	(var)->field.hash_next = (table)[hash].hash_head;	\
	(var)->field.hash_pp = &(table)[hash].hash_head;	\
	(table)[hash].hash_head = var;				\
	if ((var)->field.hash_next != NULL)			\
		(var)->field.hash_next->field.hash_pp = 	\
			&((var)->field.hash_next); 		\
}


#define	HASH_UNCHAIN(var, field, table, hash)			\
{								\
	ASSERT(MUTEX_HELD(&(table)[hash].hash_lock));		\
	HASHLIST_UNCHAIN(var, field);				\
}

#define	HASHLIST_INSERT(var, field, head)			\
{								\
	(var)->field.hash_next = head;				\
	(var)->field.hash_pp = &(head);				\
	head = var;						\
	if ((var)->field.hash_next != NULL)			\
		(var)->field.hash_next->field.hash_pp = 	\
			&((var)->field.hash_next); 		\
}

#define	HASHLIST_UNCHAIN(var, field) 				\
{								\
	*var->field.hash_pp = var->field.hash_next;		\
	if (var->field.hash_next)				\
		var->field.hash_next->field.hash_pp = 		\
			var->field.hash_pp;			\
	HASH_NULL(var, field);					\
}


#define	HASH_NULL(var, field) 					\
{								\
	var->field.hash_next = NULL;				\
	var->field.hash_pp = NULL;				\
}

#define	HASH_LINK(fieldname, type)				\
	struct {						\
		type *hash_next;				\
		type **hash_pp;					\
	} fieldname


#define	HASH_HEAD(tag)						\
	struct {						\
		struct tag *hash_head;				\
		kmutex_t hash_lock;				\
	}


typedef struct ipsec_policy_s ipsec_policy_t;

typedef HASH_HEAD(ipsec_policy_s) ipsec_policy_hash_t;

/*
 * When adding new fields to ipsec_prot_t, make sure to update
 * ipsec_in_to_out_action() as well as other code in spd.c
 */

typedef struct ipsec_prot
{
	unsigned int
		ipp_use_ah : 1,
		ipp_use_esp : 1,
		ipp_use_se : 1,
		ipp_use_unique : 1,
		ipp_use_espa : 1,
		ipp_pad : 27;
	uint8_t		ipp_auth_alg;		 /* DOI number */
	uint8_t		ipp_encr_alg;		 /* DOI number */
	uint8_t		ipp_esp_auth_alg;	 /* DOI number */
	uint16_t 	ipp_ah_minbits;		 /* AH: min keylen */
	uint16_t 	ipp_ah_maxbits;		 /* AH: max keylen */
	uint16_t	ipp_espe_minbits;	 /* ESP encr: min keylen */
	uint16_t	ipp_espe_maxbits;	 /* ESP encr: max keylen */
	uint16_t	ipp_espa_minbits;	 /* ESP auth: min keylen */
	uint16_t	ipp_espa_maxbits;	 /* ESP auth: max keylen */
	uint32_t	ipp_km_proto;		 /* key mgmt protocol */
	uint64_t	ipp_km_cookie;		 /* key mgmt cookie */
	uint32_t	ipp_replay_depth;	 /* replay window */
	/* XXX add lifetimes */
} ipsec_prot_t;

#define	IPSEC_MAX_KEYBITS (0xffff)

/*
 * An individual policy action, possibly a member of a chain.
 *
 * Action chains may be shared between multiple policy rules.
 *
 * With one exception (IPSEC_POLICY_LOG), a chain consists of an
 * ordered list of alternative ways to handle a packet.
 *
 * All actions are also "interned" into a hash table (to allow
 * multiple rules with the same action chain to share one copy in
 * memory).
 */

typedef struct ipsec_act
{
	uint8_t		ipa_type;
	uint8_t		ipa_log;
	union
	{
		ipsec_prot_t	ipau_apply;
		uint8_t		ipau_reject_type;
		uint32_t	ipau_resolve_id; /* magic cookie */
		uint8_t		ipau_log_type;
	} ipa_u;
#define	ipa_apply ipa_u.ipau_apply
#define	ipa_reject_type ipa_u.ipau_reject_type
#define	ipa_log_type ipa_u.ipau_log_type
#define	ipa_resolve_type ipa_u.ipau_resolve_type
} ipsec_act_t;

#define	IPSEC_ACT_APPLY		0x01 /* match IPSEC_POLICY_APPLY */
#define	IPSEC_ACT_DISCARD	0x02 /* match IPSEC_POLICY_DISCARD */
#define	IPSEC_ACT_BYPASS	0x03 /* match IPSEC_POLICY_BYPASS */
#define	IPSEC_ACT_REJECT	0x04
#define	IPSEC_ACT_CLEAR		0x05

typedef struct ipsec_action_s
{
	HASH_LINK(ipa_hash, struct ipsec_action_s);
	struct ipsec_action_s	*ipa_next;	/* next alternative */
	uint32_t		ipa_refs;		/* refcount */
	ipsec_act_t		ipa_act;
	/*
	 * The following bits are equivalent to an OR of bits included in the
	 * ipau_apply fields of this and subsequent actions in an
	 * action chain; this is an optimization for the sake of
	 * ipsec_out_process() in ip.c and a few other places.
	 */
	unsigned int
		ipa_hval: 8,
		ipa_allow_clear:1,		/* rule allows cleartext? */
		ipa_want_ah:1,			/* an action wants ah */
		ipa_want_esp:1,			/* an action wants esp */
		ipa_want_se:1,			/* an action wants se */
		ipa_want_unique:1,		/* want unique sa's */
		ipa_pad:19;
	uint32_t		ipa_ovhd;	/* per-packet encap ovhd */
} ipsec_action_t;

#define	IPACT_REFHOLD(ipa) {			\
	atomic_inc_32(&(ipa)->ipa_refs);	\
	ASSERT((ipa)->ipa_refs != 0);	\
}
#define	IPACT_REFRELE(ipa) {					\
	ASSERT((ipa)->ipa_refs != 0);				\
	membar_exit();						\
	if (atomic_dec_32_nv(&(ipa)->ipa_refs) == 0)	\
		ipsec_action_free(ipa);				\
	(ipa) = 0;						\
}

/*
 * For now, use a trivially sized hash table for actions.
 * In the future we can add the structure canonicalization necessary
 * to get the hash function to behave correctly..
 */
#define	IPSEC_ACTION_HASH_SIZE 1

/*
 * Merged address structure, for cheezy address-family independent
 * matches in policy code.
 */

typedef union ipsec_addr
{
	in6_addr_t	ipsad_v6;
	in_addr_t	ipsad_v4;
} ipsec_addr_t;

/*
 * ipsec selector set, as used by the kernel policy structures.
 * Note that that we specify "local" and "remote"
 * rather than "source" and "destination", which allows the selectors
 * for symmetric policy rules to be shared between inbound and
 * outbound rules.
 *
 * "local" means "destination" on inbound, and "source" on outbound.
 * "remote" means "source" on inbound, and "destination" on outbound.
 * XXX if we add a fifth policy enforcement point for forwarded packets,
 * what do we do?
 *
 * The ipsl_valid mask is not done as a bitfield; this is so we
 * can use "ffs()" to find the "most interesting" valid tag.
 *
 * XXX should we have multiple types for space-conservation reasons?
 * (v4 vs v6?  prefix vs. range)?
 */

typedef struct ipsec_selkey
{
	uint32_t	ipsl_valid;		/* bitmask of valid entries */
#define	IPSL_REMOTE_ADDR		0x00000001
#define	IPSL_LOCAL_ADDR			0x00000002
#define	IPSL_REMOTE_PORT		0x00000004
#define	IPSL_LOCAL_PORT			0x00000008
#define	IPSL_PROTOCOL			0x00000010
#define	IPSL_ICMP_TYPE			0x00000020
#define	IPSL_ICMP_CODE			0x00000040
#define	IPSL_IPV6			0x00000080
#define	IPSL_IPV4			0x00000100

#define	IPSL_WILDCARD			0x0000007f

	ipsec_addr_t	ipsl_local;
	ipsec_addr_t	ipsl_remote;
	uint16_t	ipsl_lport;
	uint16_t	ipsl_rport;
	/*
	 * ICMP type and code selectors. Both have an end value to
	 * specify ranges, or * and *_end are equal for a single
	 * value
	 */
	uint8_t		ipsl_icmp_type;
	uint8_t		ipsl_icmp_type_end;
	uint8_t		ipsl_icmp_code;
	uint8_t		ipsl_icmp_code_end;

	uint8_t		ipsl_proto;		/* ip payload type */
	uint8_t		ipsl_local_pfxlen;	/* #bits of prefix */
	uint8_t		ipsl_remote_pfxlen;	/* #bits of prefix */
	uint8_t		ipsl_mbz;

	/* Insert new elements above this line */
	uint32_t	ipsl_pol_hval;
	uint32_t	ipsl_sel_hval;
} ipsec_selkey_t;

typedef struct ipsec_sel
{
	HASH_LINK(ipsl_hash, struct ipsec_sel);
	uint32_t	ipsl_refs;		/* # refs to this sel */
	ipsec_selkey_t	ipsl_key;		/* actual selector guts */
} ipsec_sel_t;

/*
 * One policy rule.  This will be linked into a single hash chain bucket in
 * the parent rule structure.  If the selector is simple enough to
 * allow hashing, it gets filed under ipsec_policy_root_t->ipr_hash.
 * Otherwise it goes onto a linked list in ipsec_policy_root_t->ipr_nonhash[af]
 *
 * In addition, we file the rule into an avl tree keyed by the rule index.
 * (Duplicate rules are permitted; the comparison function breaks ties).
 */
struct ipsec_policy_s
{
	HASH_LINK(ipsp_hash, struct ipsec_policy_s);
	avl_node_t		ipsp_byid;
	uint64_t		ipsp_index;	/* unique id */
	uint32_t		ipsp_prio; 	/* rule priority */
	uint32_t		ipsp_refs;
	ipsec_sel_t		*ipsp_sel;	/* selector set (shared) */
	ipsec_action_t		*ipsp_act; 	/* action (may be shared) */
	netstack_t		*ipsp_netstack;	/* No netstack_hold */
};

#define	IPPOL_REFHOLD(ipp) {			\
	atomic_inc_32(&(ipp)->ipsp_refs);	\
	ASSERT((ipp)->ipsp_refs != 0);		\
}
#define	IPPOL_REFRELE(ipp) {					\
	ASSERT((ipp)->ipsp_refs != 0);				\
	membar_exit();						\
	if (atomic_dec_32_nv(&(ipp)->ipsp_refs) == 0)	\
		ipsec_policy_free(ipp);				\
	(ipp) = 0;						\
}

#define	IPPOL_UNCHAIN(php, ip)					\
	HASHLIST_UNCHAIN((ip), ipsp_hash);			\
	avl_remove(&(php)->iph_rulebyid, (ip));			\
	IPPOL_REFRELE(ip);

/*
 * Policy ruleset.  One per (protocol * direction) for system policy.
 */

#define	IPSEC_AF_V4	0
#define	IPSEC_AF_V6	1
#define	IPSEC_NAF	2

typedef struct ipsec_policy_root_s
{
	ipsec_policy_t		*ipr_nonhash[IPSEC_NAF];
	int			ipr_nchains;
	ipsec_policy_hash_t 	*ipr_hash;
} ipsec_policy_root_t;

/*
 * Policy head.  One for system policy; there may also be one present
 * on ill_t's with interface-specific policy, as well as one present
 * for sockets with per-socket policy allocated.
 */

typedef struct ipsec_policy_head_s
{
	uint32_t	iph_refs;
	krwlock_t	iph_lock;
	uint64_t	iph_gen; /* generation number */
	ipsec_policy_root_t iph_root[IPSEC_NTYPES];
	avl_tree_t	iph_rulebyid;
} ipsec_policy_head_t;

#define	IPPH_REFHOLD(iph) {			\
	atomic_inc_32(&(iph)->iph_refs);	\
	ASSERT((iph)->iph_refs != 0);		\
}
#define	IPPH_REFRELE(iph, ns) {					\
	ASSERT((iph)->iph_refs != 0);				\
	membar_exit();						\
	if (atomic_dec_32_nv(&(iph)->iph_refs) == 0)	\
		ipsec_polhead_free(iph, ns);			\
	(iph) = 0;						\
}

/*
 * IPsec fragment related structures
 */

typedef struct ipsec_fragcache_entry {
	struct ipsec_fragcache_entry *itpfe_next;	/* hash list chain */
	mblk_t *itpfe_fraglist;			/* list of fragments */
	time_t itpfe_exp;			/* time when entry is stale */
	int itpfe_depth;			/* # of fragments in list */
	ipsec_addr_t itpfe_frag_src;
	ipsec_addr_t itpfe_frag_dst;
#define	itpfe_src itpfe_frag_src.ipsad_v4
#define	itpfe_src6 itpfe_frag_src.ipsad_v6
#define	itpfe_dst itpfe_frag_dst.ipsad_v4
#define	itpfe_dst6 itpfe_frag_dst.ipsad_v6
	uint32_t itpfe_id;			/* IP datagram ID */
	uint8_t itpfe_proto;			/* IP Protocol */
	uint8_t itpfe_last;			/* Last packet */
} ipsec_fragcache_entry_t;

typedef struct ipsec_fragcache {
	kmutex_t itpf_lock;
	struct ipsec_fragcache_entry **itpf_ptr;
	struct ipsec_fragcache_entry *itpf_freelist;
	time_t itpf_expire_hint;	/* time when oldest entry is stale */
} ipsec_fragcache_t;

/*
 * Tunnel policies.  We keep a minature of the transport-mode/global policy
 * per each tunnel instance.
 *
 * People who need both an itp held down AND one of its polheads need to
 * first lock the itp, THEN the polhead, otherwise deadlock WILL occur.
 */
typedef struct ipsec_tun_pol_s {
	avl_node_t itp_node;
	kmutex_t itp_lock;
	uint64_t itp_next_policy_index;
	ipsec_policy_head_t *itp_policy;
	ipsec_policy_head_t *itp_inactive;
	uint32_t itp_flags;
	uint32_t itp_refcnt;
	char itp_name[LIFNAMSIZ];
	ipsec_fragcache_t itp_fragcache;
} ipsec_tun_pol_t;
/* NOTE - Callers (tun code) synchronize their own instances for these flags. */
#define	ITPF_P_ACTIVE 0x1	/* Are we using IPsec right now? */
#define	ITPF_P_TUNNEL 0x2	/* Negotiate tunnel-mode */
/* Optimization -> Do we have per-port security entries in this polhead? */
#define	ITPF_P_PER_PORT_SECURITY 0x4
#define	ITPF_PFLAGS 0x7
#define	ITPF_SHIFT 3

#define	ITPF_I_ACTIVE 0x8	/* Is the inactive using IPsec right now? */
#define	ITPF_I_TUNNEL 0x10	/* Negotiate tunnel-mode (on inactive) */
/* Optimization -> Do we have per-port security entries in this polhead? */
#define	ITPF_I_PER_PORT_SECURITY 0x20
#define	ITPF_IFLAGS 0x38

/* NOTE:  f cannot be an expression. */
#define	ITPF_CLONE(f) (f) = (((f) & ITPF_PFLAGS) | \
	    (((f) & ITPF_PFLAGS) << ITPF_SHIFT));
#define	ITPF_SWAP(f) (f) = ((((f) & ITPF_PFLAGS) << ITPF_SHIFT) | \
	    (((f) & ITPF_IFLAGS) >> ITPF_SHIFT))

#define	ITP_P_ISACTIVE(itp, iph) ((itp)->itp_flags & \
	(((itp)->itp_policy == (iph)) ? ITPF_P_ACTIVE : ITPF_I_ACTIVE))

#define	ITP_P_ISTUNNEL(itp, iph) ((itp)->itp_flags & \
	(((itp)->itp_policy == (iph)) ? ITPF_P_TUNNEL : ITPF_I_TUNNEL))

#define	ITP_P_ISPERPORT(itp, iph) ((itp)->itp_flags & \
	(((itp)->itp_policy == (iph)) ? ITPF_P_PER_PORT_SECURITY : \
	ITPF_I_PER_PORT_SECURITY))

#define	ITP_REFHOLD(itp) { \
	atomic_inc_32(&((itp)->itp_refcnt));	\
	ASSERT((itp)->itp_refcnt != 0); \
}

#define	ITP_REFRELE(itp, ns) { \
	ASSERT((itp)->itp_refcnt != 0); \
	membar_exit(); \
	if (atomic_dec_32_nv(&((itp)->itp_refcnt)) == 0) \
		itp_free(itp, ns); \
}

/*
 * Certificate identity.
 */

typedef struct ipsid_s
{
	struct ipsid_s *ipsid_next;
	struct ipsid_s **ipsid_ptpn;
	uint32_t	ipsid_refcnt;
	int		ipsid_type;	/* id type */
	char 		*ipsid_cid;	/* certificate id string */
} ipsid_t;

/*
 * ipsid_t reference hold/release macros, just like ipsa versions.
 */

#define	IPSID_REFHOLD(ipsid) {			\
	atomic_inc_32(&(ipsid)->ipsid_refcnt);	\
	ASSERT((ipsid)->ipsid_refcnt != 0);	\
}

/*
 * Decrement the reference count on the ID.  Someone else will clean up
 * after us later.
 */

#define	IPSID_REFRELE(ipsid) {					\
	membar_exit();						\
	atomic_dec_32(&(ipsid)->ipsid_refcnt);		\
}

/*
 * Following are the estimates of what the maximum AH and ESP header size
 * would be. This is used to tell the upper layer the right value of MSS
 * it should use without consulting AH/ESP. If the size is something
 * different from this, ULP will learn the right one through
 * ICMP_FRAGMENTATION_NEEDED messages generated locally.
 *
 * AH : 12 bytes of constant header + 32 bytes of ICV checksum (SHA-512).
 */
#define	IPSEC_MAX_AH_HDR_SIZE   (44)

/*
 * ESP : Is a bit more complex...
 *
 * A system of one inequality and one equation MUST be solved for proper ESP
 * overhead.  The inequality is:
 *
 *    MTU - sizeof (IP header + options) >=
 *		sizeof (esph_t) + sizeof (IV or ctr) + data-size + 2 + ICV
 *
 * IV or counter is almost always the cipher's block size.  The equation is:
 *
 *    data-size % block-size = (block-size - 2)
 *
 * so we can put as much data into the datagram as possible.  If we are
 * pessimistic and include our largest overhead cipher (AES) and hash
 * (SHA-512), and assume 1500-byte MTU minus IPv4 overhead of 20 bytes, we get:
 *
 *    1480 >= 8 + 16 + data-size + 2 + 32
 *    1480 >= 58 + data-size
 *    1422 >= data-size,      1422 % 16 = 14, so 58 is the overhead!
 *
 * But, let's re-run the numbers with the same algorithms, but with an IPv6
 * header:
 *
 *    1460 >= 58 + data-size
 *    1402 >= data-size,     1402 % 16 = 10, meaning shrink to 1390 to get 14,
 *
 * which means the overhead is now 70.
 *
 * Hmmm... IPv4 headers can never be anything other than multiples of 4-bytes,
 * and IPv6 ones can never be anything other than multiples of 8-bytes.  We've
 * seen overheads of 58 and 70.  58 % 16 == 10, and 70 % 16 == 6.  IPv4 could
 * force us to have 62 ( % 16 == 14) or 66 ( % 16 == 2), or IPv6 could force us
 * to have 78 ( % 16 = 14).  Let's compute IPv6 + 8-bytes of options:
 *
 *    1452 >= 58 + data-size
 *    1394 >= data-size,     1394 % 16 = 2, meaning shrink to 1390 to get 14,
 *
 * Aha!  The "ESP overhead" shrinks to 62 (70 - 8).  This is good.  Let's try
 * IPv4 + 8 bytes of IPv4 options:
 *
 *    1472 >= 58 + data-size
 *    1414 >= data-size,      1414 % 16 = 6, meaning shrink to 1406,
 *
 * meaning 66 is the overhead.  Let's try 12 bytes:
 *
 *    1468 >= 58 + data-size
 *    1410 >= data-size,      1410 % 16 = 2, meaning also shrink to 1406,
 *
 * meaning 62 is the overhead.  How about 16 bytes?
 *
 *    1464 >= 58 + data-size
 *    1406 >= data-size,      1402 % 16 = 14, which is great!
 *
 * this means 58 is the overhead.  If I wrap and add 20 bytes, it looks just
 * like IPv6's 70 bytes.  If I add 24, we go back to 66 bytes.
 *
 * So picking 70 is a sensible, conservative default.  Optimal calculations
 * will depend on knowing pre-ESP header length (called "divpoint" in the ESP
 * code), which could be cached in the conn_t for connected endpoints, or
 * which must be computed on every datagram otherwise.
 */
#define	IPSEC_MAX_ESP_HDR_SIZE  (70)

/*
 * Alternate, when we know the crypto block size via the SA.  Assume an ICV on
 * the SA.  Use:
 *
 * sizeof (esph_t) + 2 * (sizeof (IV/counter)) - 2 + sizeof (ICV).  The "-2"
 * discounts the overhead of the pad + padlen that gets swallowed up by the
 * second (theoretically all-pad) cipher-block.  If you use our examples of
 * AES and SHA512, you get:
 *
 *    8 + 32 - 2 + 32 == 70.
 *
 * Which is our pre-computed maximum above.
 */
#include <inet/ipsecesp.h>
#define	IPSEC_BASE_ESP_HDR_SIZE(sa) \
	(sizeof (esph_t) + ((sa)->ipsa_iv_len << 1) - 2 + (sa)->ipsa_mac_len)

/*
 * Identity hash table.
 *
 * Identities are refcounted and "interned" into the hash table.
 * Only references coming from other objects (SA's, latching state)
 * are counted in ipsid_refcnt.
 *
 * Locking: IPSID_REFHOLD is safe only when (a) the object's hash bucket
 * is locked, (b) we know that the refcount must be > 0.
 *
 * The ipsid_next and ipsid_ptpn fields are only to be referenced or
 * modified when the bucket lock is held; in particular, we only
 * delete objects while holding the bucket lock, and we only increase
 * the refcount from 0 to 1 while the bucket lock is held.
 */

#define	IPSID_HASHSIZE 64

typedef struct ipsif_s
{
	ipsid_t *ipsif_head;
	kmutex_t ipsif_lock;
} ipsif_t;

/*
 * For call to the kernel crypto framework. State needed during
 * the execution of a crypto request.
 */
typedef struct ipsec_crypto_s {
	size_t		ic_skip_len;		/* len to skip for AH auth */
	crypto_data_t	ic_crypto_data;		/* single op crypto data */
	crypto_dual_data_t ic_crypto_dual_data; /* for dual ops */
	crypto_data_t	ic_crypto_mac;		/* to store the MAC */
	ipsa_cm_mech_t	ic_cmm;
} ipsec_crypto_t;

/*
 * IPsec stack instances
 */
struct ipsec_stack {
	netstack_t		*ipsec_netstack;	/* Common netstack */

	/* Packet dropper for IP IPsec processing failures */
	ipdropper_t		ipsec_dropper;

/* From spd.c */
	/*
	 * Policy rule index generator.  We assume this won't wrap in the
	 * lifetime of a system.  If we make 2^20 policy changes per second,
	 * this will last 2^44 seconds, or roughly 500,000 years, so we don't
	 * have to worry about reusing policy index values.
	 */
	uint64_t		ipsec_next_policy_index;

	HASH_HEAD(ipsec_action_s) ipsec_action_hash[IPSEC_ACTION_HASH_SIZE];
	HASH_HEAD(ipsec_sel)	  *ipsec_sel_hash;
	uint32_t		ipsec_spd_hashsize;

	ipsif_t			ipsec_ipsid_buckets[IPSID_HASHSIZE];

	/*
	 * Active & Inactive system policy roots
	 */
	ipsec_policy_head_t	ipsec_system_policy;
	ipsec_policy_head_t	ipsec_inactive_policy;

	/* Packet dropper for generic SPD drops. */
	ipdropper_t		ipsec_spd_dropper;

/* ipdrop.c */
	kstat_t			*ipsec_ip_drop_kstat;
	struct ip_dropstats	*ipsec_ip_drop_types;

/* spd.c */
	/*
	 * Have a counter for every possible policy message in
	 * ipsec_policy_failure_msgs
	 */
	uint32_t		ipsec_policy_failure_count[IPSEC_POLICY_MAX];
	/* Time since last ipsec policy failure that printed a message. */
	hrtime_t		ipsec_policy_failure_last;

/* ip_spd.c */
	/* stats */
	kstat_t			*ipsec_ksp;
	struct ipsec_kstats_s	*ipsec_kstats;

/* sadb.c */
	/* Packet dropper for generic SADB drops. */
	ipdropper_t		ipsec_sadb_dropper;

/* spd.c */
	boolean_t		ipsec_inbound_v4_policy_present;
	boolean_t		ipsec_outbound_v4_policy_present;
	boolean_t		ipsec_inbound_v6_policy_present;
	boolean_t		ipsec_outbound_v6_policy_present;

/* spd.c */
	/*
	 * Because policy needs to know what algorithms are supported, keep the
	 * lists of algorithms here.
	 */
	krwlock_t 		ipsec_alg_lock;

	uint8_t			ipsec_nalgs[IPSEC_NALGTYPES];
	ipsec_alginfo_t	*ipsec_alglists[IPSEC_NALGTYPES][IPSEC_MAX_ALGS];

	uint8_t		ipsec_sortlist[IPSEC_NALGTYPES][IPSEC_MAX_ALGS];

	int		ipsec_algs_exec_mode[IPSEC_NALGTYPES];

	uint32_t 	ipsec_tun_spd_hashsize;
	/*
	 * Tunnel policies - AVL tree indexed by tunnel name.
	 */
	krwlock_t 	ipsec_tunnel_policy_lock;
	uint64_t	ipsec_tunnel_policy_gen;
	avl_tree_t	ipsec_tunnel_policies;

/* ipsec_loader.c */
	kmutex_t	ipsec_loader_lock;
	int		ipsec_loader_state;
	int		ipsec_loader_sig;
	kt_did_t	ipsec_loader_tid;
	kcondvar_t	ipsec_loader_sig_cv;	/* For loader_sig conditions. */

};
typedef struct ipsec_stack ipsec_stack_t;

/* Handle the kstat_create in ip_drop_init() failing */
#define	DROPPER(_ipss, _dropper) \
	(((_ipss)->ipsec_ip_drop_types == NULL) ? NULL : \
	&((_ipss)->ipsec_ip_drop_types->_dropper))

/*
 * Loader states..
 */
#define	IPSEC_LOADER_WAIT	0
#define	IPSEC_LOADER_FAILED	-1
#define	IPSEC_LOADER_SUCCEEDED	1

/*
 * ipsec_loader entrypoints.
 */
extern void ipsec_loader_init(ipsec_stack_t *);
extern void ipsec_loader_start(ipsec_stack_t *);
extern void ipsec_loader_destroy(ipsec_stack_t *);
extern void ipsec_loader_loadnow(ipsec_stack_t *);
extern boolean_t ipsec_loader_wait(queue_t *q, ipsec_stack_t *);
extern boolean_t ipsec_loaded(ipsec_stack_t *);
extern boolean_t ipsec_failed(ipsec_stack_t *);

/*
 * ipsec policy entrypoints (spd.c)
 */

extern void ipsec_policy_g_destroy(void);
extern void ipsec_policy_g_init(void);

extern mblk_t	*ipsec_add_crypto_data(mblk_t *, ipsec_crypto_t **);
extern mblk_t	*ipsec_remove_crypto_data(mblk_t *, ipsec_crypto_t **);
extern mblk_t	*ipsec_free_crypto_data(mblk_t *);
extern int ipsec_alloc_table(ipsec_policy_head_t *, int, int, boolean_t,
    netstack_t *);
extern void ipsec_polhead_init(ipsec_policy_head_t *, int);
extern void ipsec_polhead_destroy(ipsec_policy_head_t *);
extern void ipsec_polhead_free_table(ipsec_policy_head_t *);
extern mblk_t *ipsec_check_global_policy(mblk_t *, conn_t *, ipha_t *,
    ip6_t *, ip_recv_attr_t *, netstack_t *ns);
extern mblk_t *ipsec_check_inbound_policy(mblk_t *, conn_t *, ipha_t *, ip6_t *,
    ip_recv_attr_t *);

extern boolean_t ipsec_in_to_out(ip_recv_attr_t *, ip_xmit_attr_t *,
    mblk_t *, ipha_t *, ip6_t *);
extern void ipsec_in_release_refs(ip_recv_attr_t *);
extern void ipsec_out_release_refs(ip_xmit_attr_t *);
extern void ipsec_log_policy_failure(int, char *, ipha_t *, ip6_t *, boolean_t,
    netstack_t *);
extern boolean_t ipsec_inbound_accept_clear(mblk_t *, ipha_t *, ip6_t *);
extern int ipsec_conn_cache_policy(conn_t *, boolean_t);
extern void ipsec_cache_outbound_policy(const conn_t *, const in6_addr_t *,
    const in6_addr_t *, in_port_t, ip_xmit_attr_t *);
extern boolean_t ipsec_outbound_policy_current(ip_xmit_attr_t *);
extern ipsec_action_t *ipsec_in_to_out_action(ip_recv_attr_t *);
extern void ipsec_latch_inbound(conn_t *connp, ip_recv_attr_t *ira);

extern void ipsec_policy_free(ipsec_policy_t *);
extern void ipsec_action_free(ipsec_action_t *);
extern void ipsec_polhead_free(ipsec_policy_head_t *, netstack_t *);
extern ipsec_policy_head_t *ipsec_polhead_split(ipsec_policy_head_t *,
    netstack_t *);
extern ipsec_policy_head_t *ipsec_polhead_create(void);
extern ipsec_policy_head_t *ipsec_system_policy(netstack_t *);
extern ipsec_policy_head_t *ipsec_inactive_policy(netstack_t *);
extern void ipsec_swap_policy(ipsec_policy_head_t *, ipsec_policy_head_t *,
    netstack_t *);
extern void ipsec_swap_global_policy(netstack_t *);

extern int ipsec_clone_system_policy(netstack_t *);
extern ipsec_policy_t *ipsec_policy_create(ipsec_selkey_t *,
    const ipsec_act_t *, int, int, uint64_t *, netstack_t *);
extern boolean_t ipsec_policy_delete(ipsec_policy_head_t *,
    ipsec_selkey_t *, int, netstack_t *);
extern int ipsec_policy_delete_index(ipsec_policy_head_t *, uint64_t,
    netstack_t *);
extern boolean_t ipsec_polhead_insert(ipsec_policy_head_t *, ipsec_act_t *,
    uint_t, int, int, netstack_t *);
extern void ipsec_polhead_flush(ipsec_policy_head_t *, netstack_t *);
extern int ipsec_copy_polhead(ipsec_policy_head_t *, ipsec_policy_head_t *,
    netstack_t *);
extern void ipsec_actvec_from_req(const ipsec_req_t *, ipsec_act_t **, uint_t *,
    netstack_t *);
extern void ipsec_actvec_free(ipsec_act_t *, uint_t);
extern int ipsec_req_from_head(ipsec_policy_head_t *, ipsec_req_t *, int);
extern mblk_t *ipsec_construct_inverse_acquire(sadb_msg_t *, sadb_ext_t **,
    netstack_t *);
extern ipsec_policy_t *ipsec_find_policy(int, const conn_t *,
    ipsec_selector_t *, netstack_t *);
extern ipsid_t *ipsid_lookup(int, char *, netstack_t *);
extern boolean_t ipsid_equal(ipsid_t *, ipsid_t *);
extern void ipsid_gc(netstack_t *);
extern void ipsec_latch_ids(ipsec_latch_t *, ipsid_t *, ipsid_t *);

extern void ipsec_config_flush(netstack_t *);
extern boolean_t ipsec_check_policy(ipsec_policy_head_t *, ipsec_policy_t *,
    int);
extern void ipsec_enter_policy(ipsec_policy_head_t *, ipsec_policy_t *, int,
    netstack_t *);
extern boolean_t ipsec_check_action(ipsec_act_t *, int *, netstack_t *);

extern void iplatch_free(ipsec_latch_t *);
extern ipsec_latch_t *iplatch_create(void);
extern int ipsec_set_req(cred_t *, conn_t *, ipsec_req_t *);

extern void ipsec_insert_always(avl_tree_t *tree, void *new_node);

extern int32_t ipsec_act_ovhd(const ipsec_act_t *act);
extern mblk_t *sadb_whack_label(mblk_t *, ipsa_t *, ip_xmit_attr_t *,
    kstat_named_t *, ipdropper_t *);
extern mblk_t *sadb_whack_label_v4(mblk_t *, ipsa_t *, kstat_named_t *,
    ipdropper_t *);
extern mblk_t *sadb_whack_label_v6(mblk_t *, ipsa_t *, kstat_named_t *,
    ipdropper_t *);
extern boolean_t update_iv(uint8_t *, queue_t *, ipsa_t *, ipsecesp_stack_t *);

/*
 * Tunnel-support SPD functions and variables.
 */
struct iptun_s;	/* Defined in inet/iptun/iptun_impl.h. */
extern mblk_t *ipsec_tun_inbound(ip_recv_attr_t *, mblk_t *,  ipsec_tun_pol_t *,
    ipha_t *, ip6_t *, ipha_t *, ip6_t *, int, netstack_t *);
extern mblk_t *ipsec_tun_outbound(mblk_t *, struct iptun_s *, ipha_t *,
    ip6_t *, ipha_t *, ip6_t *, int, ip_xmit_attr_t *);
extern void itp_free(ipsec_tun_pol_t *, netstack_t *);
extern ipsec_tun_pol_t *create_tunnel_policy(char *, int *, uint64_t *,
    netstack_t *);
extern ipsec_tun_pol_t *get_tunnel_policy(char *, netstack_t *);
extern void itp_unlink(ipsec_tun_pol_t *, netstack_t *);
extern void itp_walk(void (*)(ipsec_tun_pol_t *, void *, netstack_t *),
    void *, netstack_t *);

extern ipsec_tun_pol_t *itp_get_byaddr(uint32_t *, uint32_t *, int,
    ip_stack_t *);

/*
 * IPsec AH/ESP functions called from IP or the common SADB code in AH.
 */

extern void ipsecah_in_assocfailure(mblk_t *, char, ushort_t, char *,
    uint32_t, void *, int, ip_recv_attr_t *ira);
extern void ipsecesp_in_assocfailure(mblk_t *, char, ushort_t, char *,
    uint32_t, void *, int, ip_recv_attr_t *ira);
extern void ipsecesp_send_keepalive(ipsa_t *);

/*
 * Algorithm management helper functions.
 */
extern boolean_t ipsec_valid_key_size(uint16_t, ipsec_alginfo_t *);

/*
 * Per-socket policy, for now, takes precedence... this priority value
 * insures it.
 */
#define	IPSEC_PRIO_SOCKET		0x1000000

/* DDI initialization functions. */
extern	boolean_t    ipsecesp_ddi_init(void);
extern	boolean_t    ipsecah_ddi_init(void);
extern	boolean_t    keysock_ddi_init(void);
extern	boolean_t    spdsock_ddi_init(void);

extern	void    ipsecesp_ddi_destroy(void);
extern	void    ipsecah_ddi_destroy(void);
extern	void	keysock_ddi_destroy(void);
extern	void    spdsock_ddi_destroy(void);

/*
 * AH- and ESP-specific functions that are called directly by other modules.
 */
extern void ipsecah_fill_defs(struct sadb_x_ecomb *, netstack_t *);
extern void ipsecesp_fill_defs(struct sadb_x_ecomb *, netstack_t *);
extern void ipsecah_algs_changed(netstack_t *);
extern void ipsecesp_algs_changed(netstack_t *);
extern void ipsecesp_init_funcs(ipsa_t *);
extern void ipsecah_init_funcs(ipsa_t *);
extern mblk_t *ipsecah_icmp_error(mblk_t *, ip_recv_attr_t *);
extern mblk_t *ipsecesp_icmp_error(mblk_t *, ip_recv_attr_t *);

/*
 * spdsock functions that are called directly by IP.
 */
extern void spdsock_update_pending_algs(netstack_t *);

/*
 * IP functions that are called from AH and ESP.
 */
extern boolean_t ipsec_outbound_sa(mblk_t *, ip_xmit_attr_t *, uint_t);
extern mblk_t *ipsec_inbound_esp_sa(mblk_t *, ip_recv_attr_t *, esph_t **);
extern mblk_t *ipsec_inbound_ah_sa(mblk_t *, ip_recv_attr_t *, ah_t **);
extern ipsec_policy_t *ipsec_find_policy_head(ipsec_policy_t *,
    ipsec_policy_head_t *, int, ipsec_selector_t *);

/*
 * IP dropper init/destroy.
 */
void ip_drop_init(ipsec_stack_t *);
void ip_drop_destroy(ipsec_stack_t *);

/*
 * Common functions
 */
extern boolean_t ip_addr_match(uint8_t *, int, in6_addr_t *);
extern boolean_t ipsec_label_match(ts_label_t *, ts_label_t *);

/*
 * AH and ESP counters types.
 */
typedef uint32_t ah_counter;
typedef uint32_t esp_counter;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPSEC_IMPL_H */
