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

#ifndef _INET_IPSEC_IMPL_H
#define	_INET_IPSEC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/* IPSEC protocols and combinations */
#define	IPSEC_AH_ONLY		0x01
#define	IPSEC_ESP_ONLY		0x02
#define	IPSEC_AH_ESP		0x03

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
extern boolean_t keysock_extended_reg(void);
extern uint32_t keysock_next_seq(void);

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
	uint32_t	ipp_km_cookie;		 /* key mgmt cookie */
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
	atomic_add_32(&(ipa)->ipa_refs, 1);	\
	ASSERT((ipa)->ipa_refs != 0);	\
}
#define	IPACT_REFRELE(ipa) {					\
	ASSERT((ipa)->ipa_refs != 0);				\
	membar_exit();						\
	if (atomic_add_32_nv(&(ipa)->ipa_refs, -1) == 0)	\
		ipsec_action_free(ipa);				\
	(ipa) = 0;						\
}

/*
 * Merged address structure, for cheezy address-family independant
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

	uint32_t	ipsl_hval;
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
};

#define	IPPOL_REFHOLD(ipp) {			\
	atomic_add_32(&(ipp)->ipsp_refs, 1);	\
	ASSERT((ipp)->ipsp_refs != 0);		\
}
#define	IPPOL_REFRELE(ipp) {					\
	ASSERT((ipp)->ipsp_refs != 0);				\
	membar_exit();						\
	if (atomic_add_32_nv(&(ipp)->ipsp_refs, -1) == 0)	\
		ipsec_policy_free(ipp);				\
	(ipp) = 0;						\
}

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
	atomic_add_32(&(iph)->iph_refs, 1);	\
	ASSERT((iph)->iph_refs != 0);		\
}
#define	IPPH_REFRELE(iph) {					\
	ASSERT((iph)->iph_refs != 0);				\
	membar_exit();						\
	if (atomic_add_32_nv(&(iph)->iph_refs, -1) == 0)	\
		ipsec_polhead_free(iph);			\
	(iph) = 0;						\
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
	atomic_add_32(&(ipsid)->ipsid_refcnt, 1);	\
	ASSERT((ipsid)->ipsid_refcnt != 0);	\
}

/*
 * Decrement the reference count on the ID.  Someone else will clean up
 * after us later.
 */

#define	IPSID_REFRELE(ipsid) {					\
	membar_exit();						\
	atomic_add_32(&(ipsid)->ipsid_refcnt, -1);		\
}

extern boolean_t ipsec_inbound_v4_policy_present;
extern boolean_t ipsec_outbound_v4_policy_present;
extern boolean_t ipsec_inbound_v6_policy_present;
extern boolean_t ipsec_outbound_v6_policy_present;

struct ipsec_out_s;

/*
 * Following are the estimates of what the maximum AH and ESP header size
 * would be. This is used to tell the upper layer the right value of MSS
 * it should use without consulting AH/ESP. If the size is something
 * different from this, ULP will learn the right one through
 * ICMP_FRAGMENTATION_NEEDED messages generated locally.
 *
 * AH : 12 bytes of constant header + 12 bytes of ICV checksum (MD5/SHA1).
 *
 * ESP : 8 bytes of constant header + 16 bytes of IV + 12 bytes ICV +
 * 2 bytes of trailer + 15 bytes pad = 53
 *
 * Note that for ESP, this estimate is overly pessimistic; however, a
 * more accurate estimate needs to know the exact amount of space
 * which will be available to ESP so it can just leave 2 bytes free in
 * the last cipherblock for the ESP inner trailer, and that
 * information is not available at the right moment in the current
 * stack.
 */
#define	IPSEC_MAX_AH_HDR_SIZE   (24)
#define	IPSEC_MAX_ESP_HDR_SIZE  (53)

/* Alternate, when we know the crypto block size */
#define	IPSEC_BASE_ESP_HDR_SIZE(sa) (4 + 4 + 12 + 1 + 2 * (sa)->ipsa_iv_len)
#define	IPSEC_DEF_BLOCKSIZE	(8) /* safe default */

/*
 * Loader states..
 */
#define	IPSEC_LOADER_WAIT	0
#define	IPSEC_LOADER_FAILED	-1
#define	IPSEC_LOADER_SUCCEEDED	1

extern kmutex_t ipsec_loader_lock;
extern int ipsec_loader_state;

/*
 * ipsec_loader entrypoints.
 */
extern void ipsec_loader_init(void);
extern void ipsec_loader_start(void);
extern void ipsec_loader_destroy(void);
extern void ipsec_loader_loadnow(void);
extern boolean_t ipsec_loader_wait(queue_t *q);
extern boolean_t ipsec_loaded(void);
extern boolean_t ipsec_failed(void);

/*
 * callback from ipsec_loader to ip
 */
extern void ip_ipsec_load_complete();

/*
 * ipsec policy entrypoints (spd.c)
 */

extern void ipsec_policy_destroy(void);
extern void ipsec_policy_init(void);
extern boolean_t ipsec_inherit_global_policy(conn_t *, ipsec_req_t *,
    ipsec_selector_t *, boolean_t);
extern mblk_t *ipsec_check_global_policy(mblk_t *, conn_t *, ipha_t *,
		    ip6_t *, boolean_t);
extern mblk_t *ipsec_check_inbound_policy(mblk_t *, conn_t *, ipha_t *, ip6_t *,
    boolean_t);

extern boolean_t ipsec_in_to_out(mblk_t *, ipha_t *, ip6_t *);
extern void ipsec_log_policy_failure(queue_t *, int, char *, ipha_t *,
		    ip6_t *, boolean_t);
extern boolean_t ipsec_inbound_accept_clear(mblk_t *, ipha_t *, ip6_t *);
extern int ipsec_policy_alloc(conn_t *);
extern int ipsec_conn_cache_policy(conn_t *, boolean_t);
extern mblk_t *ipsec_alloc_ipsec_out(void);
extern mblk_t	*ipsec_attach_ipsec_out(mblk_t *, conn_t *, ipsec_policy_t *,
    uint8_t);
extern mblk_t	*ipsec_init_ipsec_out(mblk_t *, conn_t *, ipsec_policy_t *,
    uint8_t);
struct ipsec_in_s;
extern ipsec_action_t *ipsec_in_to_out_action(struct ipsec_in_s *);
extern boolean_t ipsec_check_ipsecin_latch(struct ipsec_in_s *, mblk_t *,
    struct ipsec_latch_s *, ipha_t *, ip6_t *, const char **, kstat_named_t **);
extern void ipsec_latch_inbound(ipsec_latch_t *ipl, struct ipsec_in_s *ii);

extern void ipsec_policy_free(ipsec_policy_t *);
extern void ipsec_action_free(ipsec_action_t *);
extern void ipsec_polhead_free(ipsec_policy_head_t *);
extern ipsec_policy_head_t *ipsec_polhead_split(ipsec_policy_head_t *);
extern ipsec_policy_head_t *ipsec_polhead_create(void);
extern ipsec_policy_head_t *ipsec_system_policy(void);
extern ipsec_policy_head_t *ipsec_inactive_policy(void);
extern void ipsec_swap_policy(void);

extern int ipsec_clone_system_policy(void);
extern ipsec_policy_t *ipsec_policy_create(ipsec_selkey_t *,
    const ipsec_act_t *, int, int);
extern boolean_t ipsec_policy_delete(ipsec_policy_head_t *,
    ipsec_selkey_t *, int);
extern int ipsec_policy_delete_index(ipsec_policy_head_t *, uint64_t);
extern void ipsec_polhead_flush(ipsec_policy_head_t *);
extern void ipsec_actvec_from_req(ipsec_req_t *, ipsec_act_t **, uint_t *);
extern void ipsec_actvec_free(ipsec_act_t *, uint_t);
extern mblk_t *ipsec_construct_inverse_acquire(sadb_msg_t *, sadb_ext_t **);
extern mblk_t *ip_wput_attach_policy(mblk_t *, ipha_t *, ip6_t *, ire_t *,
    conn_t *, boolean_t);
extern mblk_t	*ip_wput_ire_parse_ipsec_out(mblk_t *, ipha_t *, ip6_t *,
    ire_t *, conn_t *, boolean_t);
extern ipsec_policy_t *ipsec_find_policy(int, conn_t *,
    struct ipsec_out_s *, ipsec_selector_t *);
extern ipsid_t *ipsid_lookup(int, char *);
extern boolean_t ipsid_equal(ipsid_t *, ipsid_t *);
extern void ipsid_gc(void);
extern void ipsec_latch_ids(ipsec_latch_t *, ipsid_t *, ipsid_t *);

extern void ipsec_config_flush(void);
extern boolean_t ipsec_check_policy(ipsec_policy_head_t *, ipsec_policy_t *,
    int);
extern void ipsec_enter_policy(ipsec_policy_head_t *, ipsec_policy_t *, int);
extern boolean_t ipsec_check_action(ipsec_act_t *, int *);

extern void ipsec_config_list_compat(queue_t *, mblk_t *);
extern int ipsec_config_add_compat(mblk_t *);
extern int ipsec_config_delete_compat(mblk_t *);

extern mblk_t *ipsec_out_tag(mblk_t *, mblk_t *);
extern mblk_t *ipsec_in_tag(mblk_t *, mblk_t *);
extern mblk_t *ip_copymsg(mblk_t *mp);

extern void iplatch_free(ipsec_latch_t *);
extern ipsec_latch_t *iplatch_create(void);
extern int ipsec_set_req(cred_t *, conn_t *, ipsec_req_t *);

extern void ipsec_insert_always(avl_tree_t *tree, void *new_node);

/*
 * IPsec AH/ESP functions called from IP.
 */

extern void ipsecah_in_assocfailure(mblk_t *, char, ushort_t, char *,
    uint32_t, void *, int);
extern void ipsecesp_in_assocfailure(mblk_t *, char, ushort_t, char *,
    uint32_t, void *, int);

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
extern void ipsecah_fill_defs(struct sadb_x_ecomb *);
extern void ipsecesp_fill_defs(struct sadb_x_ecomb *);
extern void ipsecah_algs_changed(void);
extern void ipsecesp_algs_changed(void);
extern void ipsecesp_init_funcs(ipsa_t *);
extern void ipsecah_init_funcs(ipsa_t *);
extern ipsec_status_t ipsecah_icmp_error(mblk_t *);
extern ipsec_status_t ipsecesp_icmp_error(mblk_t *);

/*
 * Wrapper for putnext() to ipsec accelerated interface.
 */
extern void ipsec_hw_putnext(queue_t *, mblk_t *);

/*
 * spdsock functions that are called directly by IP.
 */
extern void spdsock_update_pending_algs(void);

/*
 * IP functions that are called from AH and ESP.
 */
extern boolean_t ipsec_outbound_sa(mblk_t *, uint_t);
extern esph_t *ipsec_inbound_esp_sa(mblk_t *);
extern ah_t *ipsec_inbound_ah_sa(mblk_t *);

/*
 * NAT-Traversal cleanup
 */
extern void nattymod_clean_ipif(ipif_t *);

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
