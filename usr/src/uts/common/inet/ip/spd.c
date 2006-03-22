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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IPsec Security Policy Database.
 *
 * This module maintains the SPD and provides routines used by ip and ip6
 * to apply IPsec policy to inbound and outbound datagrams.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strlog.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>

#include <sys/crypto/api.h>

#include <inet/common.h>
#include <inet/mi.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

#include <inet/ip.h>
#include <inet/ip6.h>

#include <net/pfkeyv2.h>
#include <net/pfpolicy.h>
#include <inet/ipsec_info.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/ipsecah.h>
#include <inet/ipsecesp.h>
#include <inet/ipdrop.h>
#include <inet/ipclassifier.h>

static void ipsec_update_present_flags();
static ipsec_act_t *ipsec_act_wildcard_expand(ipsec_act_t *, uint_t *);
static void ipsec_out_free(void *);
static void ipsec_in_free(void *);
static boolean_t ipsec_init_inbound_sel(ipsec_selector_t *, mblk_t *,
    ipha_t *, ip6_t *);
static mblk_t *ipsec_attach_global_policy(mblk_t *, conn_t *,
    ipsec_selector_t *);
static mblk_t *ipsec_apply_global_policy(mblk_t *, conn_t *,
    ipsec_selector_t *);
static mblk_t *ipsec_check_ipsecin_policy(queue_t *, mblk_t *,
    ipsec_policy_t *, ipha_t *, ip6_t *);
static void ipsec_in_release_refs(ipsec_in_t *);
static void ipsec_out_release_refs(ipsec_out_t *);
static void ipsec_action_reclaim(void *);
static void ipsid_init(void);
static void ipsid_fini(void);
static boolean_t ipsec_check_ipsecin_action(struct ipsec_in_s *, mblk_t *,
    struct ipsec_action_s *, ipha_t *ipha, ip6_t *ip6h, const char **,
    kstat_named_t **);
static int32_t ipsec_act_ovhd(const ipsec_act_t *act);
static void ipsec_unregister_prov_update(void);
static boolean_t ipsec_compare_action(ipsec_policy_t *, ipsec_policy_t *);
static uint32_t selector_hash(ipsec_selector_t *);

/*
 * Policy rule index generator.  We assume this won't wrap in the
 * lifetime of a system.  If we make 2^20 policy changes per second,
 * this will last 2^44 seconds, or roughly 500,000 years, so we don't
 * have to worry about reusing policy index values.
 *
 * Protected by ipsec_conf_lock.
 */
uint64_t	ipsec_next_policy_index = 1;

/*
 * Active & Inactive system policy roots
 */
static ipsec_policy_head_t system_policy;
static ipsec_policy_head_t inactive_policy;

/* Packet dropper for generic SPD drops. */
static ipdropper_t spd_dropper;

/*
 * For now, use a trivially sized hash table for actions.
 * In the future we can add the structure canonicalization necessary
 * to get the hash function to behave correctly..
 */
#define	IPSEC_ACTION_HASH_SIZE 1

/*
 * Selector hash table is statically sized at module load time.
 * we default to 251 buckets, which is the largest prime number under 255
 */

#define	IPSEC_SPDHASH_DEFAULT 251
uint32_t ipsec_spd_hashsize = 0;

#define	IPSEC_SEL_NOHASH ((uint32_t)(~0))

static HASH_HEAD(ipsec_action_s) ipsec_action_hash[IPSEC_ACTION_HASH_SIZE];
static HASH_HEAD(ipsec_sel) *ipsec_sel_hash;

static kmem_cache_t *ipsec_action_cache;
static kmem_cache_t *ipsec_sel_cache;
static kmem_cache_t *ipsec_pol_cache;
static kmem_cache_t *ipsec_info_cache;

boolean_t ipsec_inbound_v4_policy_present = B_FALSE;
boolean_t ipsec_outbound_v4_policy_present = B_FALSE;
boolean_t ipsec_inbound_v6_policy_present = B_FALSE;
boolean_t ipsec_outbound_v6_policy_present = B_FALSE;

/*
 * Because policy needs to know what algorithms are supported, keep the
 * lists of algorithms here.
 */

kmutex_t alg_lock;
uint8_t ipsec_nalgs[IPSEC_NALGTYPES];
ipsec_alginfo_t *ipsec_alglists[IPSEC_NALGTYPES][IPSEC_MAX_ALGS];
uint8_t ipsec_sortlist[IPSEC_NALGTYPES][IPSEC_MAX_ALGS];
ipsec_algs_exec_mode_t ipsec_algs_exec_mode[IPSEC_NALGTYPES];
static crypto_notify_handle_t prov_update_handle = NULL;

int ipsec_hdr_pullup_needed = 0;
int ipsec_weird_null_inbound_policy = 0;

#define	ALGBITS_ROUND_DOWN(x, align)	(((x)/(align))*(align))
#define	ALGBITS_ROUND_UP(x, align)	ALGBITS_ROUND_DOWN((x)+(align)-1, align)

/*
 * Inbound traffic should have matching identities for both SA's.
 */

#define	SA_IDS_MATCH(sa1, sa2) 						\
	(((sa1) == NULL) || ((sa2) == NULL) ||				\
	(((sa1)->ipsa_src_cid == (sa2)->ipsa_src_cid) &&		\
	    (((sa1)->ipsa_dst_cid == (sa2)->ipsa_dst_cid))))

#define	IPPOL_UNCHAIN(php, ip) 						\
	HASHLIST_UNCHAIN((ip), ipsp_hash);				\
	avl_remove(&(php)->iph_rulebyid, (ip));				\
	IPPOL_REFRELE(ip);

/*
 * Policy failure messages.
 */
static char *ipsec_policy_failure_msgs[] = {

	/* IPSEC_POLICY_NOT_NEEDED */
	"%s: Dropping the datagram because the incoming packet "
	"is %s, but the recipient expects clear; Source %s, "
	"Destination %s.\n",

	/* IPSEC_POLICY_MISMATCH */
	"%s: Policy Failure for the incoming packet (%s); Source %s, "
	"Destination %s.\n",

	/* IPSEC_POLICY_AUTH_NOT_NEEDED	*/
	"%s: Authentication present while not expected in the "
	"incoming %s packet; Source %s, Destination %s.\n",

	/* IPSEC_POLICY_ENCR_NOT_NEEDED */
	"%s: Encryption present while not expected in the "
	"incoming %s packet; Source %s, Destination %s.\n",

	/* IPSEC_POLICY_SE_NOT_NEEDED */
	"%s: Self-Encapsulation present while not expected in the "
	"incoming %s packet; Source %s, Destination %s.\n",
};
/*
 * Have a counter for every possible policy message in the previous array.
 */
static uint32_t ipsec_policy_failure_count[IPSEC_POLICY_MAX];
/* Time since last ipsec policy failure that printed a message. */
hrtime_t ipsec_policy_failure_last = 0;

/*
 * General overviews:
 *
 * Locking:
 *
 *	All of the system policy structures are protected by a single
 *	rwlock, ipsec_conf_lock.  These structures are threaded in a
 *	fairly complex fashion and are not expected to change on a
 *	regular basis, so this should not cause scaling/contention
 *	problems.  As a result, policy checks should (hopefully) be MT-hot.
 *
 * Allocation policy:
 *
 *	We use custom kmem cache types for the various
 *	bits & pieces of the policy data structures.  All allocations
 *	use KM_NOSLEEP instead of KM_SLEEP for policy allocation.  The
 *	policy table is of potentially unbounded size, so we don't
 *	want to provide a way to hog all system memory with policy
 *	entries..
 */


/*
 * AVL tree comparison function.
 * the in-kernel avl assumes unique keys for all objects.
 * Since sometimes policy will duplicate rules, we may insert
 * multiple rules with the same rule id, so we need a tie-breaker.
 */
static int
ipsec_policy_cmpbyid(const void *a, const void *b)
{
	const ipsec_policy_t *ipa, *ipb;
	uint64_t idxa, idxb;

	ipa = (const ipsec_policy_t *)a;
	ipb = (const ipsec_policy_t *)b;
	idxa = ipa->ipsp_index;
	idxb = ipb->ipsp_index;

	if (idxa < idxb)
		return (-1);
	if (idxa > idxb)
		return (1);
	/*
	 * Tie-breaker #1: All installed policy rules have a non-NULL
	 * ipsl_sel (selector set), so an entry with a NULL ipsp_sel is not
	 * actually in-tree but rather a template node being used in
	 * an avl_find query; see ipsec_policy_delete().  This gives us
	 * a placeholder in the ordering just before the the first entry with
	 * a key >= the one we're looking for, so we can walk forward from
	 * that point to get the remaining entries with the same id.
	 */
	if ((ipa->ipsp_sel == NULL) && (ipb->ipsp_sel != NULL))
		return (-1);
	if ((ipb->ipsp_sel == NULL) && (ipa->ipsp_sel != NULL))
		return (1);
	/*
	 * At most one of the arguments to the comparison should have a
	 * NULL selector pointer; if not, the tree is broken.
	 */
	ASSERT(ipa->ipsp_sel != NULL);
	ASSERT(ipb->ipsp_sel != NULL);
	/*
	 * Tie-breaker #2: use the virtual address of the policy node
	 * to arbitrarily break ties.  Since we use the new tree node in
	 * the avl_find() in ipsec_insert_always, the new node will be
	 * inserted into the tree in the right place in the sequence.
	 */
	if (ipa < ipb)
		return (-1);
	if (ipa > ipb)
		return (1);
	return (0);
}

static void
ipsec_polhead_free_table(ipsec_policy_head_t *iph)
{
	int dir, nchains;

	nchains = ipsec_spd_hashsize;

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &iph->iph_root[dir];

		if (ipr->ipr_hash == NULL)
			continue;

		kmem_free(ipr->ipr_hash, nchains *
		    sizeof (ipsec_policy_hash_t));
	}
}

static void
ipsec_polhead_destroy(ipsec_policy_head_t *iph)
{
	int dir;

	avl_destroy(&iph->iph_rulebyid);
	rw_destroy(&iph->iph_lock);

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &iph->iph_root[dir];
		int nchains = ipr->ipr_nchains;
		int chain;

		for (chain = 0; chain < nchains; chain++)
			mutex_destroy(&(ipr->ipr_hash[chain].hash_lock));

	}
	ipsec_polhead_free_table(iph);
}

/*
 * Module unload hook.
 */
void
ipsec_policy_destroy(void)
{
	int i;

	ip_drop_unregister(&spd_dropper);
	ip_drop_destroy();

	ipsec_polhead_destroy(&system_policy);
	ipsec_polhead_destroy(&inactive_policy);

	for (i = 0; i < IPSEC_ACTION_HASH_SIZE; i++)
		mutex_destroy(&(ipsec_action_hash[i].hash_lock));

	for (i = 0; i < ipsec_spd_hashsize; i++)
		mutex_destroy(&(ipsec_sel_hash[i].hash_lock));

	ipsec_unregister_prov_update();

	mutex_destroy(&alg_lock);

	kmem_cache_destroy(ipsec_action_cache);
	kmem_cache_destroy(ipsec_sel_cache);
	kmem_cache_destroy(ipsec_pol_cache);
	kmem_cache_destroy(ipsec_info_cache);
	ipsid_gc();
	ipsid_fini();
}


/*
 * Called when table allocation fails to free the table.
 */
static int
ipsec_alloc_tables_failed()
{
	if (ipsec_sel_hash != NULL) {
		kmem_free(ipsec_sel_hash, ipsec_spd_hashsize *
		    sizeof (*ipsec_sel_hash));
		ipsec_sel_hash = NULL;
	}
	ipsec_polhead_free_table(&system_policy);
	ipsec_polhead_free_table(&inactive_policy);

	return (ENOMEM);
}

/*
 * Attempt to allocate the tables in a single policy head.
 * Return nonzero on failure after cleaning up any work in progress.
 */
static int
ipsec_alloc_table(ipsec_policy_head_t *iph, int kmflag)
{
	int dir, nchains;

	nchains = ipsec_spd_hashsize;

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &iph->iph_root[dir];

		ipr->ipr_hash = kmem_zalloc(nchains *
		    sizeof (ipsec_policy_hash_t), kmflag);
		if (ipr->ipr_hash == NULL)
			return (ipsec_alloc_tables_failed());
	}
	return (0);
}

/*
 * Attempt to allocate the various tables.  Return nonzero on failure
 * after cleaning up any work in progress.
 */
static int
ipsec_alloc_tables(int kmflag)
{
	int error;

	error = ipsec_alloc_table(&system_policy, kmflag);
	if (error != 0)
		return (error);

	error = ipsec_alloc_table(&inactive_policy, kmflag);
	if (error != 0)
		return (error);

	ipsec_sel_hash = kmem_zalloc(ipsec_spd_hashsize *
	    sizeof (*ipsec_sel_hash), kmflag);

	if (ipsec_sel_hash == NULL)
		return (ipsec_alloc_tables_failed());

	return (0);
}

/*
 * After table allocation, initialize a policy head.
 */
static void
ipsec_polhead_init(ipsec_policy_head_t *iph)
{
	int dir, chain, nchains;

	nchains = ipsec_spd_hashsize;

	rw_init(&iph->iph_lock, NULL, RW_DEFAULT, NULL);
	avl_create(&iph->iph_rulebyid, ipsec_policy_cmpbyid,
	    sizeof (ipsec_policy_t), offsetof(ipsec_policy_t, ipsp_byid));

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &iph->iph_root[dir];
		ipr->ipr_nchains = nchains;

		for (chain = 0; chain < nchains; chain++) {
			mutex_init(&(ipr->ipr_hash[chain].hash_lock),
			    NULL, MUTEX_DEFAULT, NULL);
		}
	}
}

/*
 * Module load hook.
 */
void
ipsec_policy_init()
{
	int i;

	/*
	 * Make two attempts to allocate policy hash tables; try it at
	 * the "preferred" size (may be set in /etc/system) first,
	 * then fall back to the default size.
	 */
	if (ipsec_spd_hashsize == 0)
		ipsec_spd_hashsize = IPSEC_SPDHASH_DEFAULT;

	if (ipsec_alloc_tables(KM_NOSLEEP) != 0) {
		cmn_err(CE_WARN,
		    "Unable to allocate %d entry IPsec policy hash table",
		    ipsec_spd_hashsize);
		ipsec_spd_hashsize = IPSEC_SPDHASH_DEFAULT;
		cmn_err(CE_WARN, "Falling back to %d entries",
		    ipsec_spd_hashsize);
		(void) ipsec_alloc_tables(KM_SLEEP);
	}

	ipsid_init();
	ipsec_polhead_init(&system_policy);
	ipsec_polhead_init(&inactive_policy);

	for (i = 0; i < IPSEC_ACTION_HASH_SIZE; i++)
		mutex_init(&(ipsec_action_hash[i].hash_lock),
		    NULL, MUTEX_DEFAULT, NULL);

	for (i = 0; i < ipsec_spd_hashsize; i++)
		mutex_init(&(ipsec_sel_hash[i].hash_lock),
		    NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&alg_lock, NULL, MUTEX_DEFAULT, NULL);

	for (i = 0; i < IPSEC_NALGTYPES; i++)
		ipsec_nalgs[i] = 0;

	ipsec_action_cache = kmem_cache_create("ipsec_actions",
	    sizeof (ipsec_action_t), _POINTER_ALIGNMENT, NULL, NULL,
	    ipsec_action_reclaim, NULL, NULL, 0);
	ipsec_sel_cache = kmem_cache_create("ipsec_selectors",
	    sizeof (ipsec_sel_t), _POINTER_ALIGNMENT, NULL, NULL,
	    NULL, NULL, NULL, 0);
	ipsec_pol_cache = kmem_cache_create("ipsec_policy",
	    sizeof (ipsec_policy_t), _POINTER_ALIGNMENT, NULL, NULL,
	    NULL, NULL, NULL, 0);
	ipsec_info_cache = kmem_cache_create("ipsec_info",
	    sizeof (ipsec_info_t), _POINTER_ALIGNMENT, NULL, NULL,
	    NULL, NULL, NULL, 0);

	ip_drop_init();
	ip_drop_register(&spd_dropper, "IPsec SPD");
}

/*
 * Sort algorithm lists.
 *
 * I may need to split this based on
 * authentication/encryption, and I may wish to have an administrator
 * configure this list.  Hold on to some NDD variables...
 *
 * XXX For now, sort on minimum key size (GAG!).  While minimum key size is
 * not the ideal metric, it's the only quantifiable measure available.
 * We need a better metric for sorting algorithms by preference.
 */
static void
alg_insert_sortlist(enum ipsec_algtype at, uint8_t algid)
{
	ipsec_alginfo_t *ai = ipsec_alglists[at][algid];
	uint8_t holder, swap;
	uint_t i;
	uint_t count = ipsec_nalgs[at];
	ASSERT(ai != NULL);
	ASSERT(algid == ai->alg_id);

	ASSERT(MUTEX_HELD(&alg_lock));

	holder = algid;

	for (i = 0; i < count - 1; i++) {
		ipsec_alginfo_t *alt;

		alt = ipsec_alglists[at][ipsec_sortlist[at][i]];
		/*
		 * If you want to give precedence to newly added algs,
		 * add the = in the > comparison.
		 */
		if ((holder != algid) || (ai->alg_minbits > alt->alg_minbits)) {
			/* Swap sortlist[i] and holder. */
			swap = ipsec_sortlist[at][i];
			ipsec_sortlist[at][i] = holder;
			holder = swap;
			ai = alt;
		} /* Else just continue. */
	}

	/* Store holder in last slot. */
	ipsec_sortlist[at][i] = holder;
}

/*
 * Remove an algorithm from a sorted algorithm list.
 * This should be considerably easier, even with complex sorting.
 */
static void
alg_remove_sortlist(enum ipsec_algtype at, uint8_t algid)
{
	boolean_t copyback = B_FALSE;
	int i;
	int newcount = ipsec_nalgs[at];

	ASSERT(MUTEX_HELD(&alg_lock));

	for (i = 0; i <= newcount; i++) {
		if (copyback)
			ipsec_sortlist[at][i-1] = ipsec_sortlist[at][i];
		else if (ipsec_sortlist[at][i] == algid)
			copyback = B_TRUE;
	}
}

/*
 * Add the specified algorithm to the algorithm tables.
 * Must be called while holding the algorithm table writer lock.
 */
void
ipsec_alg_reg(ipsec_algtype_t algtype, ipsec_alginfo_t *alg)
{
	ASSERT(MUTEX_HELD(&alg_lock));

	ASSERT(ipsec_alglists[algtype][alg->alg_id] == NULL);
	ipsec_alg_fix_min_max(alg, algtype);
	ipsec_alglists[algtype][alg->alg_id] = alg;

	ipsec_nalgs[algtype]++;
	alg_insert_sortlist(algtype, alg->alg_id);
}

/*
 * Remove the specified algorithm from the algorithm tables.
 * Must be called while holding the algorithm table writer lock.
 */
void
ipsec_alg_unreg(ipsec_algtype_t algtype, uint8_t algid)
{
	ASSERT(MUTEX_HELD(&alg_lock));

	ASSERT(ipsec_alglists[algtype][algid] != NULL);
	ipsec_alg_free(ipsec_alglists[algtype][algid]);
	ipsec_alglists[algtype][algid] = NULL;

	ipsec_nalgs[algtype]--;
	alg_remove_sortlist(algtype, algid);
}

/*
 * Hooks for spdsock to get a grip on system policy.
 */

ipsec_policy_head_t *
ipsec_system_policy(void)
{
	ipsec_policy_head_t *h = &system_policy;
	IPPH_REFHOLD(h);
	return (h);
}

ipsec_policy_head_t *
ipsec_inactive_policy(void)
{
	ipsec_policy_head_t *h = &inactive_policy;
	IPPH_REFHOLD(h);
	return (h);
}

/*
 * Lock inactive policy, then active policy, then exchange policy root
 * pointers.
 */
void
ipsec_swap_policy(void)
{
	int af, dir;
	avl_tree_t r1, r2;

	rw_enter(&inactive_policy.iph_lock, RW_WRITER);
	rw_enter(&system_policy.iph_lock, RW_WRITER);

	r1 = system_policy.iph_rulebyid;
	r2 = inactive_policy.iph_rulebyid;
	system_policy.iph_rulebyid = r2;
	inactive_policy.iph_rulebyid = r1;

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_hash_t *h1, *h2;

		h1 = system_policy.iph_root[dir].ipr_hash;
		h2 = inactive_policy.iph_root[dir].ipr_hash;
		system_policy.iph_root[dir].ipr_hash = h2;
		inactive_policy.iph_root[dir].ipr_hash = h1;

		for (af = 0; af < IPSEC_NAF; af++) {
			ipsec_policy_t *t1, *t2;

			t1 = system_policy.iph_root[dir].ipr_nonhash[af];
			t2 = inactive_policy.iph_root[dir].ipr_nonhash[af];
			system_policy.iph_root[dir].ipr_nonhash[af] = t2;
			inactive_policy.iph_root[dir].ipr_nonhash[af] = t1;
			if (t1 != NULL) {
				t1->ipsp_hash.hash_pp =
				    &(inactive_policy.iph_root[dir].
				    ipr_nonhash[af]);
			}
			if (t2 != NULL) {
				t2->ipsp_hash.hash_pp =
				    &(system_policy.iph_root[dir].
				    ipr_nonhash[af]);
			}

		}
	}
	system_policy.iph_gen++;
	inactive_policy.iph_gen++;
	ipsec_update_present_flags();
	rw_exit(&system_policy.iph_lock);
	rw_exit(&inactive_policy.iph_lock);
}

/*
 * Clone one policy rule..
 */
static ipsec_policy_t *
ipsec_copy_policy(const ipsec_policy_t *src)
{
	ipsec_policy_t *dst = kmem_cache_alloc(ipsec_pol_cache, KM_NOSLEEP);

	if (dst == NULL)
		return (NULL);

	/*
	 * Adjust refcounts of cloned state.
	 */
	IPACT_REFHOLD(src->ipsp_act);
	src->ipsp_sel->ipsl_refs++;

	HASH_NULL(dst, ipsp_hash);
	dst->ipsp_refs = 1;
	dst->ipsp_sel = src->ipsp_sel;
	dst->ipsp_act = src->ipsp_act;
	dst->ipsp_prio = src->ipsp_prio;
	dst->ipsp_index = src->ipsp_index;

	return (dst);
}

void
ipsec_insert_always(avl_tree_t *tree, void *new_node)
{
	void *node;
	avl_index_t where;

	node = avl_find(tree, new_node, &where);
	ASSERT(node == NULL);
	avl_insert(tree, new_node, where);
}


static int
ipsec_copy_chain(ipsec_policy_head_t *dph, ipsec_policy_t *src,
    ipsec_policy_t **dstp)
{
	for (; src != NULL; src = src->ipsp_hash.hash_next) {
		ipsec_policy_t *dst = ipsec_copy_policy(src);
		if (dst == NULL)
			return (ENOMEM);

		HASHLIST_INSERT(dst, ipsp_hash, *dstp);
		ipsec_insert_always(&dph->iph_rulebyid, dst);
	}
	return (0);
}



/*
 * Make one policy head look exactly like another.
 *
 * As with ipsec_swap_policy, we lock the destination policy head first, then
 * the source policy head. Note that we only need to read-lock the source
 * policy head as we are not changing it.
 */
static int
ipsec_copy_polhead(ipsec_policy_head_t *sph, ipsec_policy_head_t *dph)
{
	int af, dir, chain, nchains;

	rw_enter(&dph->iph_lock, RW_WRITER);

	ipsec_polhead_flush(dph);

	rw_enter(&sph->iph_lock, RW_READER);

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *dpr = &dph->iph_root[dir];
		ipsec_policy_root_t *spr = &sph->iph_root[dir];
		nchains = dpr->ipr_nchains;

		ASSERT(dpr->ipr_nchains == spr->ipr_nchains);

		for (af = 0; af < IPSEC_NAF; af++) {
			if (ipsec_copy_chain(dph, spr->ipr_nonhash[af],
			    &dpr->ipr_nonhash[af]))
				goto abort_copy;
		}

		for (chain = 0; chain < nchains; chain++) {
			if (ipsec_copy_chain(dph,
			    spr->ipr_hash[chain].hash_head,
			    &dpr->ipr_hash[chain].hash_head))
				goto abort_copy;
		}
	}

	dph->iph_gen++;

	rw_exit(&sph->iph_lock);
	rw_exit(&dph->iph_lock);
	return (0);

abort_copy:
	ipsec_polhead_flush(dph);
	rw_exit(&sph->iph_lock);
	rw_exit(&dph->iph_lock);
	return (ENOMEM);
}

/*
 * Clone currently active policy to the inactive policy list.
 */
int
ipsec_clone_system_policy(void)
{
	return (ipsec_copy_polhead(&system_policy, &inactive_policy));
}


/*
 * Extract the string from ipsec_policy_failure_msgs[type] and
 * log it.
 *
 */
void
ipsec_log_policy_failure(queue_t *q, int type, char *func_name, ipha_t *ipha,
    ip6_t *ip6h, boolean_t secure)
{
	char	sbuf[INET6_ADDRSTRLEN];
	char	dbuf[INET6_ADDRSTRLEN];
	char	*s;
	char	*d;
	short mid = 0;

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	if (ipha != NULL) {
		s = inet_ntop(AF_INET, &ipha->ipha_src, sbuf, sizeof (sbuf));
		d = inet_ntop(AF_INET, &ipha->ipha_dst, dbuf, sizeof (dbuf));
	} else {
		s = inet_ntop(AF_INET6, &ip6h->ip6_src, sbuf, sizeof (sbuf));
		d = inet_ntop(AF_INET6, &ip6h->ip6_dst, dbuf, sizeof (dbuf));

	}

	/* Always bump the policy failure counter. */
	ipsec_policy_failure_count[type]++;

	if (q != NULL) {
		mid = q->q_qinfo->qi_minfo->mi_idnum;
	}
	ipsec_rl_strlog(mid, 0, 0, SL_ERROR|SL_WARN|SL_CONSOLE,
		ipsec_policy_failure_msgs[type],
		func_name,
		(secure ? "secure" : "not secure"), s, d);
}

/*
 * Rate-limiting front-end to strlog() for AH and ESP.	Uses the ndd variables
 * in /dev/ip and the same rate-limiting clock so that there's a single
 * knob to turn to throttle the rate of messages.
 */
void
ipsec_rl_strlog(short mid, short sid, char level, ushort_t sl, char *fmt, ...)
{
	va_list adx;
	hrtime_t current = gethrtime();

	sl |= SL_CONSOLE;
	/*
	 * Throttle logging to stop syslog from being swamped. If variable
	 * 'ipsec_policy_log_interval' is zero, don't log any messages at
	 * all, otherwise log only one message every 'ipsec_policy_log_interval'
	 * msec. Convert interval (in msec) to hrtime (in nsec).
	 */

	if (ipsec_policy_log_interval) {
		if (ipsec_policy_failure_last +
		    ((hrtime_t)ipsec_policy_log_interval * (hrtime_t)1000000) <=
		    current) {
			va_start(adx, fmt);
			(void) vstrlog(mid, sid, level, sl, fmt, adx);
			va_end(adx);
			ipsec_policy_failure_last = current;
		}
	}
}

void
ipsec_config_flush()
{
	rw_enter(&system_policy.iph_lock, RW_WRITER);
	ipsec_polhead_flush(&system_policy);
	ipsec_next_policy_index = 1;
	rw_exit(&system_policy.iph_lock);
	ipsec_action_reclaim(0);
}

/*
 * Clip a policy's min/max keybits vs. the capabilities of the
 * algorithm.
 */
static void
act_alg_adjust(uint_t algtype, uint_t algid,
    uint16_t *minbits, uint16_t *maxbits)
{
	ipsec_alginfo_t *algp = ipsec_alglists[algtype][algid];
	if (algp != NULL) {
		/*
		 * If passed-in minbits is zero, we assume the caller trusts
		 * us with setting the minimum key size.  We pick the
		 * algorithms DEFAULT key size for the minimum in this case.
		 */
		if (*minbits == 0) {
			*minbits = algp->alg_default_bits;
			ASSERT(*minbits >= algp->alg_minbits);
		} else {
			*minbits = MAX(*minbits, algp->alg_minbits);
		}
		if (*maxbits == 0)
			*maxbits = algp->alg_maxbits;
		else
			*maxbits = MIN(*maxbits, algp->alg_maxbits);
		ASSERT(*minbits <= *maxbits);
	} else {
		*minbits = 0;
		*maxbits = 0;
	}
}

/*
 * Check an action's requested algorithms against the algorithms currently
 * loaded in the system.
 */
boolean_t
ipsec_check_action(ipsec_act_t *act, int *diag)
{
	ipsec_prot_t *ipp;

	ipp = &act->ipa_apply;

	if (ipp->ipp_use_ah &&
	    ipsec_alglists[IPSEC_ALG_AUTH][ipp->ipp_auth_alg] == NULL) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_AH_ALG;
		return (B_FALSE);
	}
	if (ipp->ipp_use_espa &&
	    ipsec_alglists[IPSEC_ALG_AUTH][ipp->ipp_esp_auth_alg] == NULL) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_ALG;
		return (B_FALSE);
	}
	if (ipp->ipp_use_esp &&
	    ipsec_alglists[IPSEC_ALG_ENCR][ipp->ipp_encr_alg] == NULL) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_ALG;
		return (B_FALSE);
	}

	act_alg_adjust(IPSEC_ALG_AUTH, ipp->ipp_auth_alg,
	    &ipp->ipp_ah_minbits, &ipp->ipp_ah_maxbits);
	act_alg_adjust(IPSEC_ALG_AUTH, ipp->ipp_esp_auth_alg,
	    &ipp->ipp_espa_minbits, &ipp->ipp_espa_maxbits);
	act_alg_adjust(IPSEC_ALG_ENCR, ipp->ipp_encr_alg,
	    &ipp->ipp_espe_minbits, &ipp->ipp_espe_maxbits);

	if (ipp->ipp_ah_minbits > ipp->ipp_ah_maxbits) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_AH_KEYSIZE;
		return (B_FALSE);
	}
	if (ipp->ipp_espa_minbits > ipp->ipp_espa_maxbits) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_KEYSIZE;
		return (B_FALSE);
	}
	if (ipp->ipp_espe_minbits > ipp->ipp_espe_maxbits) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_KEYSIZE;
		return (B_FALSE);
	}
	/* TODO: sanity check lifetimes */
	return (B_TRUE);
}

/*
 * Set up a single action during wildcard expansion..
 */
static void
ipsec_setup_act(ipsec_act_t *outact, ipsec_act_t *act,
    uint_t auth_alg, uint_t encr_alg, uint_t eauth_alg)
{
	ipsec_prot_t *ipp;

	*outact = *act;
	ipp = &outact->ipa_apply;
	ipp->ipp_auth_alg = (uint8_t)auth_alg;
	ipp->ipp_encr_alg = (uint8_t)encr_alg;
	ipp->ipp_esp_auth_alg = (uint8_t)eauth_alg;

	act_alg_adjust(IPSEC_ALG_AUTH, auth_alg,
	    &ipp->ipp_ah_minbits, &ipp->ipp_ah_maxbits);
	act_alg_adjust(IPSEC_ALG_AUTH, eauth_alg,
	    &ipp->ipp_espa_minbits, &ipp->ipp_espa_maxbits);
	act_alg_adjust(IPSEC_ALG_ENCR, encr_alg,
	    &ipp->ipp_espe_minbits, &ipp->ipp_espe_maxbits);
}

/*
 * combinatoric expansion time: expand a wildcarded action into an
 * array of wildcarded actions; we return the exploded action list,
 * and return a count in *nact (output only).
 */
static ipsec_act_t *
ipsec_act_wildcard_expand(ipsec_act_t *act, uint_t *nact)
{
	boolean_t use_ah, use_esp, use_espa;
	boolean_t wild_auth, wild_encr, wild_eauth;
	uint_t	auth_alg, auth_idx, auth_min, auth_max;
	uint_t	eauth_alg, eauth_idx, eauth_min, eauth_max;
	uint_t  encr_alg, encr_idx, encr_min, encr_max;
	uint_t	action_count, ai;
	ipsec_act_t *outact;

	if (act->ipa_type != IPSEC_ACT_APPLY) {
		outact = kmem_alloc(sizeof (*act), KM_NOSLEEP);
		*nact = 1;
		if (outact != NULL)
			bcopy(act, outact, sizeof (*act));
		return (outact);
	}
	/*
	 * compute the combinatoric explosion..
	 *
	 * we assume a request for encr if esp_req is PREF_REQUIRED
	 * we assume a request for ah auth if ah_req is PREF_REQUIRED.
	 * we assume a request for esp auth if !ah and esp_req is PREF_REQUIRED
	 */

	use_ah = act->ipa_apply.ipp_use_ah;
	use_esp = act->ipa_apply.ipp_use_esp;
	use_espa = act->ipa_apply.ipp_use_espa;
	auth_alg = act->ipa_apply.ipp_auth_alg;
	eauth_alg = act->ipa_apply.ipp_esp_auth_alg;
	encr_alg = act->ipa_apply.ipp_encr_alg;

	wild_auth = use_ah && (auth_alg == 0);
	wild_eauth = use_espa && (eauth_alg == 0);
	wild_encr = use_esp && (encr_alg == 0);

	action_count = 1;
	auth_min = auth_max = auth_alg;
	eauth_min = eauth_max = eauth_alg;
	encr_min = encr_max = encr_alg;

	/*
	 * set up for explosion.. for each dimension, expand output
	 * size by the explosion factor.
	 *
	 * Don't include the "any" algorithms, if defined, as no
	 * kernel policies should be set for these algorithms.
	 */

#define	SET_EXP_MINMAX(type, wild, alg, min, max) if (wild) {	\
		int nalgs = ipsec_nalgs[type];			\
		if (ipsec_alglists[type][alg] != NULL)		\
			nalgs--;				\
		action_count *= nalgs;				\
		min = 0;					\
		max = ipsec_nalgs[type] - 1;			\
	}

	SET_EXP_MINMAX(IPSEC_ALG_AUTH, wild_auth, SADB_AALG_NONE,
	    auth_min, auth_max);
	SET_EXP_MINMAX(IPSEC_ALG_AUTH, wild_eauth, SADB_AALG_NONE,
	    eauth_min, eauth_max);
	SET_EXP_MINMAX(IPSEC_ALG_ENCR, wild_encr, SADB_EALG_NONE,
	    encr_min, encr_max);

#undef	SET_EXP_MINMAX

	/*
	 * ok, allocate the whole mess..
	 */

	outact = kmem_alloc(sizeof (*outact) * action_count, KM_NOSLEEP);
	if (outact == NULL)
		return (NULL);

	/*
	 * Now compute all combinations.  Note that non-wildcarded
	 * dimensions just get a single value from auth_min, while
	 * wildcarded dimensions indirect through the sortlist.
	 *
	 * We do encryption outermost since, at this time, there's
	 * greater difference in security and performance between
	 * encryption algorithms vs. authentication algorithms.
	 */

	ai = 0;

#define	WHICH_ALG(type, wild, idx) ((wild)?(ipsec_sortlist[type][idx]):(idx))

	for (encr_idx = encr_min; encr_idx <= encr_max; encr_idx++) {
		encr_alg = WHICH_ALG(IPSEC_ALG_ENCR, wild_encr, encr_idx);
		if (wild_encr && encr_alg == SADB_EALG_NONE)
			continue;
		for (auth_idx = auth_min; auth_idx <= auth_max; auth_idx++) {
			auth_alg = WHICH_ALG(IPSEC_ALG_AUTH, wild_auth,
			    auth_idx);
			if (wild_auth && auth_alg == SADB_AALG_NONE)
				continue;
			for (eauth_idx = eauth_min; eauth_idx <= eauth_max;
			    eauth_idx++) {
				eauth_alg = WHICH_ALG(IPSEC_ALG_AUTH,
				    wild_eauth, eauth_idx);
				if (wild_eauth && eauth_alg == SADB_AALG_NONE)
					continue;

				ipsec_setup_act(&outact[ai], act,
				    auth_alg, encr_alg, eauth_alg);
				ai++;
			}
		}
	}

#undef WHICH_ALG

	ASSERT(ai == action_count);
	*nact = action_count;
	return (outact);
}

/*
 * Extract the parts of an ipsec_prot_t from an old-style ipsec_req_t.
 */
static void
ipsec_prot_from_req(ipsec_req_t *req, ipsec_prot_t *ipp)
{
	bzero(ipp, sizeof (*ipp));
	/*
	 * ipp_use_* are bitfields.  Look at "!!" in the following as a
	 * "boolean canonicalization" operator.
	 */
	ipp->ipp_use_ah = !!(req->ipsr_ah_req & IPSEC_PREF_REQUIRED);
	ipp->ipp_use_esp = !!(req->ipsr_esp_req & IPSEC_PREF_REQUIRED);
	ipp->ipp_use_espa = !!(req->ipsr_esp_auth_alg) || !ipp->ipp_use_ah;
	ipp->ipp_use_se = !!(req->ipsr_self_encap_req & IPSEC_PREF_REQUIRED);
	ipp->ipp_use_unique = !!((req->ipsr_ah_req|req->ipsr_esp_req) &
	    IPSEC_PREF_UNIQUE);
	ipp->ipp_encr_alg = req->ipsr_esp_alg;
	ipp->ipp_auth_alg = req->ipsr_auth_alg;
	ipp->ipp_esp_auth_alg = req->ipsr_esp_auth_alg;
}

/*
 * Extract a new-style action from a request.
 */
void
ipsec_actvec_from_req(ipsec_req_t *req, ipsec_act_t **actp, uint_t *nactp)
{
	struct ipsec_act act;
	bzero(&act, sizeof (act));
	if ((req->ipsr_ah_req & IPSEC_PREF_NEVER) &&
	    (req->ipsr_esp_req & IPSEC_PREF_NEVER)) {
		act.ipa_type = IPSEC_ACT_BYPASS;
	} else {
		act.ipa_type = IPSEC_ACT_APPLY;
		ipsec_prot_from_req(req, &act.ipa_apply);
	}
	*actp = ipsec_act_wildcard_expand(&act, nactp);
}

/*
 * Convert a new-style "prot" back to an ipsec_req_t (more backwards compat).
 * We assume caller has already zero'ed *req for us.
 */
static int
ipsec_req_from_prot(ipsec_prot_t *ipp, ipsec_req_t *req)
{
	req->ipsr_esp_alg = ipp->ipp_encr_alg;
	req->ipsr_auth_alg = ipp->ipp_auth_alg;
	req->ipsr_esp_auth_alg = ipp->ipp_esp_auth_alg;

	if (ipp->ipp_use_unique) {
		req->ipsr_ah_req |= IPSEC_PREF_UNIQUE;
		req->ipsr_esp_req |= IPSEC_PREF_UNIQUE;
	}
	if (ipp->ipp_use_se)
		req->ipsr_self_encap_req |= IPSEC_PREF_REQUIRED;
	if (ipp->ipp_use_ah)
		req->ipsr_ah_req |= IPSEC_PREF_REQUIRED;
	if (ipp->ipp_use_esp)
		req->ipsr_esp_req |= IPSEC_PREF_REQUIRED;
	return (sizeof (*req));
}

/*
 * Convert a new-style action back to an ipsec_req_t (more backwards compat).
 * We assume caller has already zero'ed *req for us.
 */
static int
ipsec_req_from_act(ipsec_action_t *ap, ipsec_req_t *req)
{
	switch (ap->ipa_act.ipa_type) {
	case IPSEC_ACT_BYPASS:
		req->ipsr_ah_req = IPSEC_PREF_NEVER;
		req->ipsr_esp_req = IPSEC_PREF_NEVER;
		return (sizeof (*req));
	case IPSEC_ACT_APPLY:
		return (ipsec_req_from_prot(&ap->ipa_act.ipa_apply, req));
	}
	return (sizeof (*req));
}

/*
 * Convert a new-style action back to an ipsec_req_t (more backwards compat).
 * We assume caller has already zero'ed *req for us.
 */
static int
ipsec_req_from_head(ipsec_policy_head_t *ph, ipsec_req_t *req, int af)
{
	ipsec_policy_t *p;

	/*
	 * FULL-PERSOCK: consult hash table, too?
	 */
	for (p = ph->iph_root[IPSEC_INBOUND].ipr_nonhash[af];
	    p != NULL;
	    p = p->ipsp_hash.hash_next) {
		if ((p->ipsp_sel->ipsl_key.ipsl_valid&IPSL_WILDCARD) == 0)
			return (ipsec_req_from_act(p->ipsp_act, req));
	}
	return (sizeof (*req));
}

/*
 * Based on per-socket or latched policy, convert to an appropriate
 * IP_SEC_OPT ipsec_req_t for the socket option; return size so we can
 * be tail-called from ip.
 */
int
ipsec_req_from_conn(conn_t *connp, ipsec_req_t *req, int af)
{
	ipsec_latch_t *ipl;
	int rv = sizeof (ipsec_req_t);

	bzero(req, sizeof (*req));

	mutex_enter(&connp->conn_lock);
	ipl = connp->conn_latch;

	/*
	 * Find appropriate policy.  First choice is latched action;
	 * failing that, see latched policy; failing that,
	 * look at configured policy.
	 */
	if (ipl != NULL) {
		if (ipl->ipl_in_action != NULL) {
			rv = ipsec_req_from_act(ipl->ipl_in_action, req);
			goto done;
		}
		if (ipl->ipl_in_policy != NULL) {
			rv = ipsec_req_from_act(ipl->ipl_in_policy->ipsp_act,
			    req);
			goto done;
		}
	}
	if (connp->conn_policy != NULL)
		rv = ipsec_req_from_head(connp->conn_policy, req, af);
done:
	mutex_exit(&connp->conn_lock);
	return (rv);
}

void
ipsec_actvec_free(ipsec_act_t *act, uint_t nact)
{
	kmem_free(act, nact * sizeof (*act));
}

/*
 * When outbound policy is not cached, look it up the hard way and attach
 * an ipsec_out_t to the packet..
 */
static mblk_t *
ipsec_attach_global_policy(mblk_t *mp, conn_t *connp, ipsec_selector_t *sel)
{
	ipsec_policy_t *p;

	p = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, NULL, sel);

	if (p == NULL)
		return (NULL);
	return (ipsec_attach_ipsec_out(mp, connp, p, sel->ips_protocol));
}

/*
 * We have an ipsec_out already, but don't have cached policy; fill it in
 * with the right actions.
 */
static mblk_t *
ipsec_apply_global_policy(mblk_t *ipsec_mp, conn_t *connp,
    ipsec_selector_t *sel)
{
	ipsec_out_t *io;
	ipsec_policy_t *p;

	ASSERT(ipsec_mp->b_datap->db_type == M_CTL);
	ASSERT(ipsec_mp->b_cont->b_datap->db_type == M_DATA);

	io = (ipsec_out_t *)ipsec_mp->b_rptr;

	if (io->ipsec_out_policy == NULL) {
		p = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, io, sel);
		io->ipsec_out_policy = p;
	}
	return (ipsec_mp);
}


/* ARGSUSED */
/*
 * Consumes a reference to ipsp.
 */
static mblk_t *
ipsec_check_loopback_policy(queue_t *q, mblk_t *first_mp,
    boolean_t mctl_present, ipsec_policy_t *ipsp)
{
	mblk_t *ipsec_mp;
	ipsec_in_t *ii;

	if (!mctl_present)
		return (first_mp);

	ipsec_mp = first_mp;

	ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	ASSERT(ii->ipsec_in_loopback);
	IPPOL_REFRELE(ipsp);

	/*
	 * We should do an actual policy check here.  Revisit this
	 * when we revisit the IPsec API.
	 */

	return (first_mp);
}

/*
 * Check that packet's inbound ports & proto match the selectors
 * expected by the SAs it traversed on the way in.
 */
static boolean_t
ipsec_check_ipsecin_unique(ipsec_in_t *ii, mblk_t *mp,
    ipha_t *ipha, ip6_t *ip6h,
    const char **reason, kstat_named_t **counter)
{
	uint64_t pkt_unique, ah_mask, esp_mask;
	ipsa_t *ah_assoc;
	ipsa_t *esp_assoc;
	ipsec_selector_t sel;

	ASSERT(ii->ipsec_in_secure);
	ASSERT(!ii->ipsec_in_loopback);

	ah_assoc = ii->ipsec_in_ah_sa;
	esp_assoc = ii->ipsec_in_esp_sa;
	ASSERT((ah_assoc != NULL) || (esp_assoc != NULL));

	ah_mask = (ah_assoc != NULL) ? ah_assoc->ipsa_unique_mask : 0;
	esp_mask = (esp_assoc != NULL) ? esp_assoc->ipsa_unique_mask : 0;

	if ((ah_mask == 0) && (esp_mask == 0))
		return (B_TRUE);

	if (!ipsec_init_inbound_sel(&sel, mp, ipha, ip6h)) {
		/*
		 * Technically not a policy mismatch, but it is
		 * an internal failure.
		 */
		*reason = "ipsec_init_inbound_sel";
		*counter = &ipdrops_spd_nomem;
		return (B_FALSE);
	}

	pkt_unique = SA_UNIQUE_ID(sel.ips_remote_port, sel.ips_local_port,
	    sel.ips_protocol);

	if (ah_mask != 0) {
		if (ah_assoc->ipsa_unique_id != (pkt_unique & ah_mask)) {
			*reason = "AH inner header mismatch";
			*counter = &ipdrops_spd_ah_innermismatch;
			return (B_FALSE);
		}
	}
	if (esp_mask != 0) {
		if (esp_assoc->ipsa_unique_id != (pkt_unique & esp_mask)) {
			*reason = "ESP inner header mismatch";
			*counter = &ipdrops_spd_esp_innermismatch;
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

static boolean_t
ipsec_check_ipsecin_action(ipsec_in_t *ii, mblk_t *mp, ipsec_action_t *ap,
    ipha_t *ipha, ip6_t *ip6h, const char **reason, kstat_named_t **counter)
{
	boolean_t ret = B_TRUE;
	ipsec_prot_t *ipp;
	ipsa_t *ah_assoc;
	ipsa_t *esp_assoc;
	boolean_t decaps;

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	if (ii->ipsec_in_loopback) {
		/*
		 * Besides accepting pointer-equivalent actions, we also
		 * accept any ICMP errors we generated for ourselves,
		 * regardless of policy.  If we do not wish to make this
		 * assumption in the future, check here, and where
		 * icmp_loopback is initialized in ip.c and ip6.c.  (Look for
		 * ipsec_out_icmp_loopback.)
		 */
		if (ap == ii->ipsec_in_action || ii->ipsec_in_icmp_loopback)
			return (B_TRUE);

		/* Deep compare necessary here?? */
		*counter = &ipdrops_spd_loopback_mismatch;
		*reason = "loopback policy mismatch";
		return (B_FALSE);
	}
	ASSERT(!ii->ipsec_in_icmp_loopback);

	ah_assoc = ii->ipsec_in_ah_sa;
	esp_assoc = ii->ipsec_in_esp_sa;

	decaps = ii->ipsec_in_decaps;

	switch (ap->ipa_act.ipa_type) {
	case IPSEC_ACT_DISCARD:
	case IPSEC_ACT_REJECT:
		/* Should "fail hard" */
		*counter = &ipdrops_spd_explicit;
		*reason = "blocked by policy";
		return (B_FALSE);

	case IPSEC_ACT_BYPASS:
	case IPSEC_ACT_CLEAR:
		*counter = &ipdrops_spd_got_secure;
		*reason = "expected clear, got protected";
		return (B_FALSE);

	case IPSEC_ACT_APPLY:
		ipp = &ap->ipa_act.ipa_apply;
		/*
		 * As of now we do the simple checks of whether
		 * the datagram has gone through the required IPSEC
		 * protocol constraints or not. We might have more
		 * in the future like sensitive levels, key bits, etc.
		 * If it fails the constraints, check whether we would
		 * have accepted this if it had come in clear.
		 */
		if (ipp->ipp_use_ah) {
			if (ah_assoc == NULL) {
				ret = ipsec_inbound_accept_clear(mp, ipha,
				    ip6h);
				*counter = &ipdrops_spd_got_clear;
				*reason = "unprotected not accepted";
				break;
			}
			ASSERT(ah_assoc != NULL);
			ASSERT(ipp->ipp_auth_alg != 0);

			if (ah_assoc->ipsa_auth_alg !=
			    ipp->ipp_auth_alg) {
				*counter = &ipdrops_spd_bad_ahalg;
				*reason = "unacceptable ah alg";
				ret = B_FALSE;
				break;
			}
		} else if (ah_assoc != NULL) {
			/*
			 * Don't allow this. Check IPSEC NOTE above
			 * ip_fanout_proto().
			 */
			*counter = &ipdrops_spd_got_ah;
			*reason = "unexpected AH";
			ret = B_FALSE;
			break;
		}
		if (ipp->ipp_use_esp) {
			if (esp_assoc == NULL) {
				ret = ipsec_inbound_accept_clear(mp, ipha,
				    ip6h);
				*counter = &ipdrops_spd_got_clear;
				*reason = "unprotected not accepted";
				break;
			}
			ASSERT(esp_assoc != NULL);
			ASSERT(ipp->ipp_encr_alg != 0);

			if (esp_assoc->ipsa_encr_alg !=
			    ipp->ipp_encr_alg) {
				*counter = &ipdrops_spd_bad_espealg;
				*reason = "unacceptable esp alg";
				ret = B_FALSE;
				break;
			}
			/*
			 * If the client does not need authentication,
			 * we don't verify the alogrithm.
			 */
			if (ipp->ipp_use_espa) {
				if (esp_assoc->ipsa_auth_alg !=
				    ipp->ipp_esp_auth_alg) {
					*counter = &ipdrops_spd_bad_espaalg;
					*reason = "unacceptable esp auth alg";
					ret = B_FALSE;
					break;
				}
			}
		} else if (esp_assoc != NULL) {
				/*
				 * Don't allow this. Check IPSEC NOTE above
				 * ip_fanout_proto().
				 */
			*counter = &ipdrops_spd_got_esp;
			*reason = "unexpected ESP";
			ret = B_FALSE;
			break;
		}
		if (ipp->ipp_use_se) {
			if (!decaps) {
				ret = ipsec_inbound_accept_clear(mp, ipha,
				    ip6h);
				if (!ret) {
					/* XXX mutant? */
					*counter = &ipdrops_spd_bad_selfencap;
					*reason = "self encap not found";
					break;
				}
			}
		} else if (decaps) {
			/*
			 * XXX If the packet comes in tunneled and the
			 * recipient does not expect it to be tunneled, it
			 * is okay. But we drop to be consistent with the
			 * other cases.
			 */
			*counter = &ipdrops_spd_got_selfencap;
			*reason = "unexpected self encap";
			ret = B_FALSE;
			break;
		}
		if (ii->ipsec_in_action != NULL) {
			/*
			 * This can happen if we do a double policy-check on
			 * a packet
			 * XXX XXX should fix this case!
			 */
			IPACT_REFRELE(ii->ipsec_in_action);
		}
		ASSERT(ii->ipsec_in_action == NULL);
		IPACT_REFHOLD(ap);
		ii->ipsec_in_action = ap;
		break;	/* from switch */
	}
	return (ret);
}

static boolean_t
spd_match_inbound_ids(ipsec_latch_t *ipl, ipsa_t *sa)
{
	ASSERT(ipl->ipl_ids_latched == B_TRUE);
	return ipsid_equal(ipl->ipl_remote_cid, sa->ipsa_src_cid) &&
	    ipsid_equal(ipl->ipl_local_cid, sa->ipsa_dst_cid);
}

/*
 * Called to check policy on a latched connection, both from this file
 * and from tcp.c
 */
boolean_t
ipsec_check_ipsecin_latch(ipsec_in_t *ii, mblk_t *mp, ipsec_latch_t *ipl,
    ipha_t *ipha, ip6_t *ip6h, const char **reason, kstat_named_t **counter)
{
	ASSERT(ipl->ipl_ids_latched == B_TRUE);

	if (!ii->ipsec_in_loopback) {
		/*
		 * Over loopback, there aren't real security associations,
		 * so there are neither identities nor "unique" values
		 * for us to check the packet against.
		 */
		if ((ii->ipsec_in_ah_sa != NULL) &&
		    (!spd_match_inbound_ids(ipl, ii->ipsec_in_ah_sa))) {
			*counter = &ipdrops_spd_ah_badid;
			*reason = "AH identity mismatch";
			return (B_FALSE);
		}

		if ((ii->ipsec_in_esp_sa != NULL) &&
		    (!spd_match_inbound_ids(ipl, ii->ipsec_in_esp_sa))) {
			*counter = &ipdrops_spd_esp_badid;
			*reason = "ESP identity mismatch";
			return (B_FALSE);
		}

		if (!ipsec_check_ipsecin_unique(ii, mp, ipha, ip6h, reason,
		    counter)) {
			return (B_FALSE);
		}
	}

	return (ipsec_check_ipsecin_action(ii, mp, ipl->ipl_in_action,
	    ipha, ip6h, reason, counter));
}

/*
 * Check to see whether this secured datagram meets the policy
 * constraints specified in ipsp.
 *
 * Called from ipsec_check_global_policy, and ipsec_check_inbound_policy.
 *
 * Consumes a reference to ipsp.
 */
static mblk_t *
ipsec_check_ipsecin_policy(queue_t *q, mblk_t *first_mp, ipsec_policy_t *ipsp,
    ipha_t *ipha, ip6_t *ip6h)
{
	ipsec_in_t *ii;
	ipsec_action_t *ap;
	const char *reason = "no policy actions found";
	mblk_t *data_mp, *ipsec_mp;
	short mid = 0;
	kstat_named_t *counter = &ipdrops_spd_got_secure;

	data_mp = first_mp->b_cont;
	ipsec_mp = first_mp;

	ASSERT(ipsp != NULL);

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	ii = (ipsec_in_t *)ipsec_mp->b_rptr;

	if (ii->ipsec_in_loopback)
		return (ipsec_check_loopback_policy(q, first_mp, B_TRUE, ipsp));
	ASSERT(ii->ipsec_in_type == IPSEC_IN);
	ASSERT(ii->ipsec_in_secure);

	if (ii->ipsec_in_action != NULL) {
		/*
		 * this can happen if we do a double policy-check on a packet
		 * Would be nice to be able to delete this test..
		 */
		IPACT_REFRELE(ii->ipsec_in_action);
	}
	ASSERT(ii->ipsec_in_action == NULL);

	if (!SA_IDS_MATCH(ii->ipsec_in_ah_sa, ii->ipsec_in_esp_sa)) {
		reason = "inbound AH and ESP identities differ";
		counter = &ipdrops_spd_ahesp_diffid;
		goto drop;
	}

	if (!ipsec_check_ipsecin_unique(ii, data_mp, ipha, ip6h,
	    &reason, &counter))
		goto drop;

	/*
	 * Ok, now loop through the possible actions and see if any
	 * of them work for us.
	 */

	for (ap = ipsp->ipsp_act; ap != NULL; ap = ap->ipa_next) {
		if (ipsec_check_ipsecin_action(ii, data_mp, ap,
		    ipha, ip6h, &reason, &counter)) {
			BUMP_MIB(&ip_mib, ipsecInSucceeded);
			IPPOL_REFRELE(ipsp);
			return (first_mp);
		}
	}
drop:
	if (q != NULL) {
		mid = q->q_qinfo->qi_minfo->mi_idnum;
	}
	ipsec_rl_strlog(mid, 0, 0, SL_ERROR|SL_WARN|SL_CONSOLE,
	    "ipsec inbound policy mismatch: %s, packet dropped\n",
	    reason);
	IPPOL_REFRELE(ipsp);
	ASSERT(ii->ipsec_in_action == NULL);
	BUMP_MIB(&ip_mib, ipsecInFailed);
	ip_drop_packet(first_mp, B_TRUE, NULL, NULL, counter, &spd_dropper);
	return (NULL);
}

/*
 * sleazy prefix-length-based compare.
 * another inlining candidate..
 */
static boolean_t
ip_addr_match(uint8_t *addr1, int pfxlen, in6_addr_t *addr2p)
{
	int offset = pfxlen>>3;
	int bitsleft = pfxlen & 7;
	uint8_t *addr2 = (uint8_t *)addr2p;

	/*
	 * and there was much evil..
	 * XXX should inline-expand the bcmp here and do this 32 bits
	 * or 64 bits at a time..
	 */
	return ((bcmp(addr1, addr2, offset) == 0) &&
	    ((bitsleft == 0) ||
		(((addr1[offset] ^ addr2[offset]) &
		    (0xff<<(8-bitsleft))) == 0)));
}

static ipsec_policy_t *
ipsec_find_policy_chain(ipsec_policy_t *best, ipsec_policy_t *chain,
    ipsec_selector_t *sel, boolean_t is_icmp_inv_acq)
{
	ipsec_selkey_t *isel;
	ipsec_policy_t *p;
	int bpri = best ? best->ipsp_prio : 0;

	for (p = chain; p != NULL; p = p->ipsp_hash.hash_next) {
		uint32_t valid;

		if (p->ipsp_prio <= bpri)
			continue;
		isel = &p->ipsp_sel->ipsl_key;
		valid = isel->ipsl_valid;

		if ((valid & IPSL_PROTOCOL) &&
		    (isel->ipsl_proto != sel->ips_protocol))
			continue;

		if ((valid & IPSL_REMOTE_ADDR) &&
		    !ip_addr_match((uint8_t *)&isel->ipsl_remote,
			isel->ipsl_remote_pfxlen,
			&sel->ips_remote_addr_v6))
			continue;

		if ((valid & IPSL_LOCAL_ADDR) &&
		    !ip_addr_match((uint8_t *)&isel->ipsl_local,
			isel->ipsl_local_pfxlen,
			&sel->ips_local_addr_v6))
			continue;

		if ((valid & IPSL_REMOTE_PORT) &&
		    isel->ipsl_rport != sel->ips_remote_port)
			continue;

		if ((valid & IPSL_LOCAL_PORT) &&
		    isel->ipsl_lport != sel->ips_local_port)
			continue;

		if (!is_icmp_inv_acq) {
			if ((valid & IPSL_ICMP_TYPE) &&
			    (isel->ipsl_icmp_type > sel->ips_icmp_type ||
			    isel->ipsl_icmp_type_end < sel->ips_icmp_type)) {
				continue;
			}

			if ((valid & IPSL_ICMP_CODE) &&
			    (isel->ipsl_icmp_code > sel->ips_icmp_code ||
			    isel->ipsl_icmp_code_end <
			    sel->ips_icmp_code)) {
				continue;
			}
		} else {
			/*
			 * special case for icmp inverse acquire
			 * we only want policies that aren't drop/pass
			 */
			if (p->ipsp_act->ipa_act.ipa_type != IPSEC_ACT_APPLY)
				continue;
		}

		/* we matched all the packet-port-field selectors! */
		best = p;
		bpri = p->ipsp_prio;
	}

	return (best);
}

/*
 * Try to find and return the best policy entry under a given policy
 * root for a given set of selectors; the first parameter "best" is
 * the current best policy so far.  If "best" is non-null, we have a
 * reference to it.  We return a reference to a policy; if that policy
 * is not the original "best", we need to release that reference
 * before returning.
 */
static ipsec_policy_t *
ipsec_find_policy_head(ipsec_policy_t *best,
    ipsec_policy_head_t *head, int direction, ipsec_selector_t *sel,
    int selhash)
{
	ipsec_policy_t *curbest;
	ipsec_policy_root_t *root;
	uint8_t is_icmp_inv_acq = sel->ips_is_icmp_inv_acq;
	int af = sel->ips_isv4 ? IPSEC_AF_V4 : IPSEC_AF_V6;

	curbest = best;
	root = &head->iph_root[direction];

#ifdef DEBUG
	if (is_icmp_inv_acq) {
		if (sel->ips_isv4) {
			if (sel->ips_protocol != IPPROTO_ICMP) {
			    cmn_err(CE_WARN, "ipsec_find_policy_head:"
			    " expecting icmp, got %d", sel->ips_protocol);
			}
		} else {
			if (sel->ips_protocol != IPPROTO_ICMPV6) {
				cmn_err(CE_WARN, "ipsec_find_policy_head:"
				" expecting icmpv6, got %d", sel->ips_protocol);
			}
		}
	}
#endif

	rw_enter(&head->iph_lock, RW_READER);

	if (root->ipr_nchains > 0) {
		curbest = ipsec_find_policy_chain(curbest,
		    root->ipr_hash[selhash].hash_head, sel, is_icmp_inv_acq);
	}
	curbest = ipsec_find_policy_chain(curbest, root->ipr_nonhash[af], sel,
	    is_icmp_inv_acq);

	/*
	 * Adjust reference counts if we found anything new.
	 */
	if (curbest != best) {
		ASSERT(curbest != NULL);
		IPPOL_REFHOLD(curbest);

		if (best != NULL) {
			IPPOL_REFRELE(best);
		}
	}

	rw_exit(&head->iph_lock);

	return (curbest);
}

/*
 * Find the best system policy (either global or per-interface) which
 * applies to the given selector; look in all the relevant policy roots
 * to figure out which policy wins.
 *
 * Returns a reference to a policy; caller must release this
 * reference when done.
 */
ipsec_policy_t *
ipsec_find_policy(int direction, conn_t *connp, ipsec_out_t *io,
    ipsec_selector_t *sel)
{
	ipsec_policy_t *p;
	int selhash = selector_hash(sel);

	p = ipsec_find_policy_head(NULL, &system_policy, direction, sel,
	    selhash);
	if ((connp != NULL) && (connp->conn_policy != NULL)) {
		p = ipsec_find_policy_head(p, connp->conn_policy,
		    direction, sel, selhash);
	} else if ((io != NULL) && (io->ipsec_out_polhead != NULL)) {
		p = ipsec_find_policy_head(p, io->ipsec_out_polhead,
		    direction, sel, selhash);
	}

	return (p);
}

/*
 * Check with global policy and see whether this inbound
 * packet meets the policy constraints.
 *
 * Locate appropriate policy from global policy, supplemented by the
 * conn's configured and/or cached policy if the conn is supplied.
 *
 * Dispatch to ipsec_check_ipsecin_policy if we have policy and an
 * encrypted packet to see if they match.
 *
 * Otherwise, see if the policy allows cleartext; if not, drop it on the
 * floor.
 */
mblk_t *
ipsec_check_global_policy(mblk_t *first_mp, conn_t *connp,
    ipha_t *ipha, ip6_t *ip6h, boolean_t mctl_present)
{
	ipsec_policy_t *p;
	ipsec_selector_t sel;
	queue_t *q = NULL;
	mblk_t *data_mp, *ipsec_mp;
	boolean_t policy_present;
	kstat_named_t *counter;
	ipsec_in_t *ii = NULL;

	data_mp = mctl_present ? first_mp->b_cont : first_mp;
	ipsec_mp = mctl_present ? first_mp : NULL;

	sel.ips_is_icmp_inv_acq = 0;

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	if (ipha != NULL)
		policy_present = ipsec_inbound_v4_policy_present;
	else
		policy_present = ipsec_inbound_v6_policy_present;

	if (!policy_present && connp == NULL) {
		/*
		 * No global policy and no per-socket policy;
		 * just pass it back (but we shouldn't get here in that case)
		 */
		return (first_mp);
	}

	if (connp != NULL)
		q = CONNP_TO_WQ(connp);

	if (ipsec_mp != NULL) {
		ASSERT(ipsec_mp->b_datap->db_type == M_CTL);
		ii = (ipsec_in_t *)(ipsec_mp->b_rptr);
		ASSERT(ii->ipsec_in_type == IPSEC_IN);
	}

	/*
	 * If we have cached policy, use it.
	 * Otherwise consult system policy.
	 */
	if ((connp != NULL) && (connp->conn_latch != NULL)) {
		p = connp->conn_latch->ipl_in_policy;
		if (p != NULL) {
			IPPOL_REFHOLD(p);
		}
	} else {
		/* Initialize the ports in the selector */
		if (!ipsec_init_inbound_sel(&sel, data_mp, ipha, ip6h)) {
			/*
			 * Technically not a policy mismatch, but it is
			 * an internal failure.
			 */
			ipsec_log_policy_failure(q, IPSEC_POLICY_MISMATCH,
			    "ipsec_init_inbound_sel", ipha, ip6h, B_FALSE);
			counter = &ipdrops_spd_nomem;
			goto fail;
		}

		/*
		 * Find the policy which best applies.
		 *
		 * If we find global policy, we should look at both
		 * local policy and global policy and see which is
		 * stronger and match accordingly.
		 *
		 * If we don't find a global policy, check with
		 * local policy alone.
		 */

		p = ipsec_find_policy(IPSEC_TYPE_INBOUND, connp, NULL, &sel);
	}

	if (p == NULL) {
		if (ipsec_mp == NULL) {
			/*
			 * We have no policy; default to succeeding.
			 * XXX paranoid system design doesn't do this.
			 */
			BUMP_MIB(&ip_mib, ipsecInSucceeded);
			return (first_mp);
		} else {
			counter = &ipdrops_spd_got_secure;
			ipsec_log_policy_failure(q, IPSEC_POLICY_NOT_NEEDED,
			    "ipsec_check_global_policy", ipha, ip6h, B_TRUE);
			goto fail;
		}
	}
	if ((ii != NULL) && (ii->ipsec_in_secure))
		return (ipsec_check_ipsecin_policy(q, ipsec_mp, p, ipha, ip6h));
	if (p->ipsp_act->ipa_allow_clear) {
		BUMP_MIB(&ip_mib, ipsecInSucceeded);
		IPPOL_REFRELE(p);
		return (first_mp);
	}
	IPPOL_REFRELE(p);
	/*
	 * If we reach here, we will drop the packet because it failed the
	 * global policy check because the packet was cleartext, and it
	 * should not have been.
	 */
	ipsec_log_policy_failure(q, IPSEC_POLICY_MISMATCH,
	    "ipsec_check_global_policy", ipha, ip6h, B_FALSE);
	counter = &ipdrops_spd_got_clear;

fail:
	ip_drop_packet(first_mp, B_TRUE, NULL, NULL, counter, &spd_dropper);
	BUMP_MIB(&ip_mib, ipsecInFailed);
	return (NULL);
}

/*
 * We check whether an inbound datagram is a valid one
 * to accept in clear. If it is secure, it is the job
 * of IPSEC to log information appropriately if it
 * suspects that it may not be the real one.
 *
 * It is called only while fanning out to the ULP
 * where ULP accepts only secure data and the incoming
 * is clear. Usually we never accept clear datagrams in
 * such cases. ICMP is the only exception.
 *
 * NOTE : We don't call this function if the client (ULP)
 * is willing to accept things in clear.
 */
boolean_t
ipsec_inbound_accept_clear(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h)
{
	ushort_t iph_hdr_length;
	icmph_t *icmph;
	icmp6_t *icmp6;
	uint8_t *nexthdrp;

	ASSERT((ipha != NULL && ip6h == NULL) ||
	    (ipha == NULL && ip6h != NULL));

	if (ip6h != NULL) {
		iph_hdr_length = ip_hdr_length_v6(mp, ip6h);
		if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &iph_hdr_length,
		    &nexthdrp)) {
			return (B_FALSE);
		}
		if (*nexthdrp != IPPROTO_ICMPV6)
			return (B_FALSE);
		icmp6 = (icmp6_t *)(&mp->b_rptr[iph_hdr_length]);
		/* Match IPv6 ICMP policy as closely as IPv4 as possible. */
		switch (icmp6->icmp6_type) {
		case ICMP6_PARAM_PROB:
			/* Corresponds to port/proto unreach in IPv4. */
		case ICMP6_ECHO_REQUEST:
			/* Just like IPv4. */
			return (B_FALSE);

		case MLD_LISTENER_QUERY:
		case MLD_LISTENER_REPORT:
		case MLD_LISTENER_REDUCTION:
			/*
			 * XXX Seperate NDD in IPv4 what about here?
			 * Plus, mcast is important to ND.
			 */
		case ICMP6_DST_UNREACH:
			/* Corresponds to HOST/NET unreachable in IPv4. */
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_ECHO_REPLY:
			/* These are trusted in IPv4. */
		case ND_ROUTER_SOLICIT:
		case ND_ROUTER_ADVERT:
		case ND_NEIGHBOR_SOLICIT:
		case ND_NEIGHBOR_ADVERT:
		case ND_REDIRECT:
			/* Trust ND messages for now. */
		case ICMP6_TIME_EXCEEDED:
		default:
			return (B_TRUE);
		}
	} else {
		/*
		 * If it is not ICMP, fail this request.
		 */
		if (ipha->ipha_protocol != IPPROTO_ICMP)
			return (B_FALSE);
		iph_hdr_length = IPH_HDR_LENGTH(ipha);
		icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
		/*
		 * It is an insecure icmp message. Check to see whether we are
		 * willing to accept this one.
		 */

		switch (icmph->icmph_type) {
		case ICMP_ECHO_REPLY:
		case ICMP_TIME_STAMP_REPLY:
		case ICMP_INFO_REPLY:
		case ICMP_ROUTER_ADVERTISEMENT:
			/*
			 * We should not encourage clear replies if this
			 * client expects secure. If somebody is replying
			 * in clear some mailicious user watching both the
			 * request and reply, can do chosen-plain-text attacks.
			 * With global policy we might be just expecting secure
			 * but sending out clear. We don't know what the right
			 * thing is. We can't do much here as we can't control
			 * the sender here. Till we are sure of what to do,
			 * accept them.
			 */
			return (B_TRUE);
		case ICMP_ECHO_REQUEST:
		case ICMP_TIME_STAMP_REQUEST:
		case ICMP_INFO_REQUEST:
		case ICMP_ADDRESS_MASK_REQUEST:
		case ICMP_ROUTER_SOLICITATION:
		case ICMP_ADDRESS_MASK_REPLY:
			/*
			 * Don't accept this as somebody could be sending
			 * us plain text to get encrypted data. If we reply,
			 * it will lead to chosen plain text attack.
			 */
			return (B_FALSE);
		case ICMP_DEST_UNREACHABLE:
			switch (icmph->icmph_code) {
			case ICMP_FRAGMENTATION_NEEDED:
				/*
				 * Be in sync with icmp_inbound, where we have
				 * already set ire_max_frag.
				 */
				return (B_TRUE);
			case ICMP_HOST_UNREACHABLE:
			case ICMP_NET_UNREACHABLE:
				/*
				 * By accepting, we could reset a connection.
				 * How do we solve the problem of some
				 * intermediate router sending in-secure ICMP
				 * messages ?
				 */
				return (B_TRUE);
			case ICMP_PORT_UNREACHABLE:
			case ICMP_PROTOCOL_UNREACHABLE:
			default :
				return (B_FALSE);
			}
		case ICMP_SOURCE_QUENCH:
			/*
			 * If this is an attack, TCP will slow start
			 * because of this. Is it very harmful ?
			 */
			return (B_TRUE);
		case ICMP_PARAM_PROBLEM:
			return (B_FALSE);
		case ICMP_TIME_EXCEEDED:
			return (B_TRUE);
		case ICMP_REDIRECT:
			return (B_FALSE);
		default :
			return (B_FALSE);
		}
	}
}

void
ipsec_latch_ids(ipsec_latch_t *ipl, ipsid_t *local, ipsid_t *remote)
{
	mutex_enter(&ipl->ipl_lock);

	if (ipl->ipl_ids_latched) {
		/* I lost, someone else got here before me */
		mutex_exit(&ipl->ipl_lock);
		return;
	}

	if (local != NULL)
		IPSID_REFHOLD(local);
	if (remote != NULL)
		IPSID_REFHOLD(remote);

	ipl->ipl_local_cid = local;
	ipl->ipl_remote_cid = remote;
	ipl->ipl_ids_latched = B_TRUE;
	mutex_exit(&ipl->ipl_lock);
}

void
ipsec_latch_inbound(ipsec_latch_t *ipl, ipsec_in_t *ii)
{
	ipsa_t *sa;

	if (!ipl->ipl_ids_latched) {
		ipsid_t *local = NULL;
		ipsid_t *remote = NULL;

		if (!ii->ipsec_in_loopback) {
			if (ii->ipsec_in_esp_sa != NULL)
				sa = ii->ipsec_in_esp_sa;
			else
				sa = ii->ipsec_in_ah_sa;
			ASSERT(sa != NULL);
			local = sa->ipsa_dst_cid;
			remote = sa->ipsa_src_cid;
		}
		ipsec_latch_ids(ipl, local, remote);
	}
	ipl->ipl_in_action = ii->ipsec_in_action;
	IPACT_REFHOLD(ipl->ipl_in_action);
}

/*
 * Check whether the policy constraints are met either for an
 * inbound datagram; called from IP in numerous places.
 *
 * Note that this is not a chokepoint for inbound policy checks;
 * see also ipsec_check_ipsecin_latch() and ipsec_check_global_policy()
 */
mblk_t *
ipsec_check_inbound_policy(mblk_t *first_mp, conn_t *connp,
    ipha_t *ipha, ip6_t *ip6h, boolean_t mctl_present)
{
	ipsec_in_t *ii;
	boolean_t ret;
	queue_t *q;
	short mid = 0;
	mblk_t *mp = mctl_present ? first_mp->b_cont : first_mp;
	mblk_t *ipsec_mp = mctl_present ? first_mp : NULL;
	ipsec_latch_t *ipl;

	ASSERT(connp != NULL);
	ipl = connp->conn_latch;

	if (ipsec_mp == NULL) {
clear:
		/*
		 * This is the case where the incoming datagram is
		 * cleartext and we need to see whether this client
		 * would like to receive such untrustworthy things from
		 * the wire.
		 */
		ASSERT(mp != NULL);

		if (ipl != NULL) {
			/*
			 * Policy is cached in the conn.
			 */
			if ((ipl->ipl_in_policy != NULL) &&
			    (!ipl->ipl_in_policy->ipsp_act->ipa_allow_clear)) {
				ret = ipsec_inbound_accept_clear(mp,
				    ipha, ip6h);
				if (ret) {
					BUMP_MIB(&ip_mib, ipsecInSucceeded);
					return (first_mp);
				} else {
					ipsec_log_policy_failure(
					    CONNP_TO_WQ(connp),
					    IPSEC_POLICY_MISMATCH,
					    "ipsec_check_inbound_policy", ipha,
					    ip6h, B_FALSE);
					ip_drop_packet(first_mp, B_TRUE, NULL,
					    NULL, &ipdrops_spd_got_clear,
					    &spd_dropper);
					BUMP_MIB(&ip_mib, ipsecInFailed);
					return (NULL);
				}
			} else {
				BUMP_MIB(&ip_mib, ipsecInSucceeded);
				return (first_mp);
			}
		} else {
			/*
			 * As this is a non-hardbound connection we need
			 * to look at both per-socket policy and global
			 * policy. As this is cleartext, mark the mp as
			 * M_DATA in case if it is an ICMP error being
			 * reported before calling ipsec_check_global_policy
			 * so that it does not mistake it for IPSEC_IN.
			 */
			uchar_t db_type = mp->b_datap->db_type;
			mp->b_datap->db_type = M_DATA;
			first_mp = ipsec_check_global_policy(first_mp, connp,
			    ipha, ip6h, mctl_present);
			if (first_mp != NULL)
				mp->b_datap->db_type = db_type;
			return (first_mp);
		}
	}
	/*
	 * If it is inbound check whether the attached message
	 * is secure or not. We have a special case for ICMP,
	 * where we have a IPSEC_IN message and the attached
	 * message is not secure. See icmp_inbound_error_fanout
	 * for details.
	 */
	ASSERT(ipsec_mp != NULL);
	ASSERT(ipsec_mp->b_datap->db_type == M_CTL);
	ii = (ipsec_in_t *)ipsec_mp->b_rptr;

	if (!ii->ipsec_in_secure)
		goto clear;

	/*
	 * mp->b_cont could be either a M_CTL message
	 * for icmp errors being sent up or a M_DATA message.
	 */
	ASSERT(mp->b_datap->db_type == M_CTL ||
	    mp->b_datap->db_type == M_DATA);

	ASSERT(ii->ipsec_in_type == IPSEC_IN);

	if (ipl == NULL) {
		/*
		 * We don't have policies cached in the conn
		 * for this stream. So, look at the global
		 * policy. It will check against conn or global
		 * depending on whichever is stronger.
		 */
		return (ipsec_check_global_policy(first_mp, connp,
		    ipha, ip6h, mctl_present));
	}

	if (ipl->ipl_in_action != NULL) {
		/* Policy is cached & latched; fast(er) path */
		const char *reason;
		kstat_named_t *counter;
		if (ipsec_check_ipsecin_latch(ii, mp, ipl,
		    ipha, ip6h, &reason, &counter)) {
			BUMP_MIB(&ip_mib, ipsecInSucceeded);
			return (first_mp);
		}
		q = CONNP_TO_WQ(connp);
		if (q != NULL) {
			mid = q->q_qinfo->qi_minfo->mi_idnum;
		}
		ipsec_rl_strlog(mid, 0, 0, SL_ERROR|SL_WARN|SL_CONSOLE,
		    "ipsec inbound policy mismatch: %s, packet dropped\n",
		    reason);
		ip_drop_packet(first_mp, B_TRUE, NULL, NULL, counter,
		    &spd_dropper);
		BUMP_MIB(&ip_mib, ipsecInFailed);
		return (NULL);
	} else if (ipl->ipl_in_policy == NULL) {
		ipsec_weird_null_inbound_policy++;
		return (first_mp);
	}

	IPPOL_REFHOLD(ipl->ipl_in_policy);
	first_mp = ipsec_check_ipsecin_policy(CONNP_TO_WQ(connp), first_mp,
	    ipl->ipl_in_policy, ipha, ip6h);
	/*
	 * NOTE: ipsecIn{Failed,Succeeeded} bumped by
	 * ipsec_check_ipsecin_policy().
	 */
	if (first_mp != NULL)
		ipsec_latch_inbound(ipl, ii);
	return (first_mp);
}

boolean_t
ipsec_init_inbound_sel(ipsec_selector_t *sel, mblk_t *mp,
    ipha_t *ipha, ip6_t *ip6h)
{
	uint16_t *ports;
	ushort_t hdr_len;
	mblk_t *spare_mp = NULL;
	uint8_t *nexthdrp;
	uint8_t nexthdr;
	uint8_t *typecode;
	uint8_t check_proto;

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ipha != NULL && ip6h == NULL));

	if (ip6h != NULL) {
		check_proto = IPPROTO_ICMPV6;
		sel->ips_isv4 = B_FALSE;
		sel->ips_local_addr_v6 = ip6h->ip6_dst;
		sel->ips_remote_addr_v6 = ip6h->ip6_src;

		nexthdr = ip6h->ip6_nxt;
		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			/*
			 * Use ip_hdr_length_nexthdr_v6().  And have a spare
			 * mblk that's contiguous to feed it
			 */
			if ((spare_mp = msgpullup(mp, -1)) == NULL)
				return (B_FALSE);
			if (!ip_hdr_length_nexthdr_v6(spare_mp,
			    (ip6_t *)spare_mp->b_rptr, &hdr_len, &nexthdrp)) {
				/* Malformed packet - XXX ip_drop_packet()? */
				freemsg(spare_mp);
				return (B_FALSE);
			}
			nexthdr = *nexthdrp;
			/* We can just extract based on hdr_len now. */
			break;
		default:
			hdr_len = IPV6_HDR_LEN;
			break;
		}
	} else {
		check_proto = IPPROTO_ICMP;
		sel->ips_isv4 = B_TRUE;
		sel->ips_local_addr_v4 = ipha->ipha_dst;
		sel->ips_remote_addr_v4 = ipha->ipha_src;
		nexthdr = ipha->ipha_protocol;
		hdr_len = IPH_HDR_LENGTH(ipha);
	}
	sel->ips_protocol = nexthdr;

	if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP &&
	    nexthdr != IPPROTO_SCTP && nexthdr != check_proto) {
		sel->ips_remote_port = sel->ips_local_port = 0;
		freemsg(spare_mp);	/* Always works, even if NULL. */
		return (B_TRUE);
	}

	if (&mp->b_rptr[hdr_len] + 4 > mp->b_wptr) {
		/* If we didn't pullup a copy already, do so now. */
		/*
		 * XXX performance, will upper-layers frequently split TCP/UDP
		 * apart from IP or options?  If so, perhaps we should revisit
		 * the spare_mp strategy.
		 */
		ipsec_hdr_pullup_needed++;
		if (spare_mp == NULL &&
		    (spare_mp = msgpullup(mp, -1)) == NULL) {
			return (B_FALSE);
		}
		ports = (uint16_t *)&spare_mp->b_rptr[hdr_len];
	} else {
		ports = (uint16_t *)&mp->b_rptr[hdr_len];
	}

	if (nexthdr == check_proto) {
		typecode = (uint8_t *)ports;
		sel->ips_icmp_type = *typecode++;
		sel->ips_icmp_code = *typecode;
		sel->ips_remote_port = sel->ips_local_port = 0;
		freemsg(spare_mp);	/* Always works, even if NULL */
		return (B_TRUE);
	}

	sel->ips_remote_port = *ports++;
	sel->ips_local_port = *ports;
	freemsg(spare_mp);	/* Always works, even if NULL */
	return (B_TRUE);
}

static boolean_t
ipsec_init_outbound_ports(ipsec_selector_t *sel, mblk_t *mp, ipha_t *ipha,
    ip6_t *ip6h)
{
	/*
	 * XXX cut&paste shared with ipsec_init_inbound_sel
	 */
	uint16_t *ports;
	ushort_t hdr_len;
	mblk_t *spare_mp = NULL;
	uint8_t *nexthdrp;
	uint8_t nexthdr;
	uint8_t *typecode;
	uint8_t check_proto;

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ipha != NULL && ip6h == NULL));

	if (ip6h != NULL) {
		check_proto = IPPROTO_ICMPV6;
		nexthdr = ip6h->ip6_nxt;
		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			/*
			 * Use ip_hdr_length_nexthdr_v6().  And have a spare
			 * mblk that's contiguous to feed it
			 */
			spare_mp = msgpullup(mp, -1);
			if (spare_mp == NULL ||
			    !ip_hdr_length_nexthdr_v6(spare_mp,
				(ip6_t *)spare_mp->b_rptr, &hdr_len,
				&nexthdrp)) {
				/* Always works, even if NULL. */
				freemsg(spare_mp);
				freemsg(mp);
				return (B_FALSE);
			} else {
				nexthdr = *nexthdrp;
				/* We can just extract based on hdr_len now. */
			}
			break;
		default:
			hdr_len = IPV6_HDR_LEN;
			break;
		}
	} else {
		check_proto = IPPROTO_ICMP;
		hdr_len = IPH_HDR_LENGTH(ipha);
		nexthdr = ipha->ipha_protocol;
	}

	sel->ips_protocol = nexthdr;
	if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP &&
	    nexthdr != IPPROTO_SCTP && nexthdr != check_proto) {
		sel->ips_local_port = sel->ips_remote_port = 0;
		freemsg(spare_mp);  /* Always works, even if NULL. */
		return (B_TRUE);
	}

	if (&mp->b_rptr[hdr_len] + 4 > mp->b_wptr) {
		/* If we didn't pullup a copy already, do so now. */
		/*
		 * XXX performance, will upper-layers frequently split TCP/UDP
		 * apart from IP or options?  If so, perhaps we should revisit
		 * the spare_mp strategy.
		 *
		 * XXX should this be msgpullup(mp, hdr_len+4) ???
		 */
		if (spare_mp == NULL &&
		    (spare_mp = msgpullup(mp, -1)) == NULL) {
			freemsg(mp);
			return (B_FALSE);
		}
		ports = (uint16_t *)&spare_mp->b_rptr[hdr_len];
	} else {
		ports = (uint16_t *)&mp->b_rptr[hdr_len];
	}

	if (nexthdr == check_proto) {
		typecode = (uint8_t *)ports;
		sel->ips_icmp_type = *typecode++;
		sel->ips_icmp_code = *typecode;
		sel->ips_remote_port = sel->ips_local_port = 0;
		freemsg(spare_mp);	/* Always works, even if NULL */
		return (B_TRUE);
	}

	sel->ips_local_port = *ports++;
	sel->ips_remote_port = *ports;
	freemsg(spare_mp);	/* Always works, even if NULL */
	return (B_TRUE);
}

/*
 * Create an ipsec_action_t based on the way an inbound packet was protected.
 * Used to reflect traffic back to a sender.
 *
 * We don't bother interning the action into the hash table.
 */
ipsec_action_t *
ipsec_in_to_out_action(ipsec_in_t *ii)
{
	ipsa_t *ah_assoc, *esp_assoc;
	uint_t auth_alg = 0, encr_alg = 0, espa_alg = 0;
	ipsec_action_t *ap;
	boolean_t unique;

	ap = kmem_cache_alloc(ipsec_action_cache, KM_NOSLEEP);

	if (ap == NULL)
		return (NULL);

	bzero(ap, sizeof (*ap));
	HASH_NULL(ap, ipa_hash);
	ap->ipa_next = NULL;
	ap->ipa_refs = 1;

	/*
	 * Get the algorithms that were used for this packet.
	 */
	ap->ipa_act.ipa_type = IPSEC_ACT_APPLY;
	ap->ipa_act.ipa_log = 0;
	ah_assoc = ii->ipsec_in_ah_sa;
	ap->ipa_act.ipa_apply.ipp_use_ah = (ah_assoc != NULL);

	esp_assoc = ii->ipsec_in_esp_sa;
	ap->ipa_act.ipa_apply.ipp_use_esp = (esp_assoc != NULL);

	if (esp_assoc != NULL) {
		encr_alg = esp_assoc->ipsa_encr_alg;
		espa_alg = esp_assoc->ipsa_auth_alg;
		ap->ipa_act.ipa_apply.ipp_use_espa = (espa_alg != 0);
	}
	if (ah_assoc != NULL)
		auth_alg = ah_assoc->ipsa_auth_alg;

	ap->ipa_act.ipa_apply.ipp_encr_alg = (uint8_t)encr_alg;
	ap->ipa_act.ipa_apply.ipp_auth_alg = (uint8_t)auth_alg;
	ap->ipa_act.ipa_apply.ipp_esp_auth_alg = (uint8_t)espa_alg;
	ap->ipa_act.ipa_apply.ipp_use_se = ii->ipsec_in_decaps;
	unique = B_FALSE;

	if (esp_assoc != NULL) {
		ap->ipa_act.ipa_apply.ipp_espa_minbits =
		    esp_assoc->ipsa_authkeybits;
		ap->ipa_act.ipa_apply.ipp_espa_maxbits =
		    esp_assoc->ipsa_authkeybits;
		ap->ipa_act.ipa_apply.ipp_espe_minbits =
		    esp_assoc->ipsa_encrkeybits;
		ap->ipa_act.ipa_apply.ipp_espe_maxbits =
		    esp_assoc->ipsa_encrkeybits;
		ap->ipa_act.ipa_apply.ipp_km_proto = esp_assoc->ipsa_kmp;
		ap->ipa_act.ipa_apply.ipp_km_cookie = esp_assoc->ipsa_kmc;
		if (esp_assoc->ipsa_flags & IPSA_F_UNIQUE)
			unique = B_TRUE;
	}
	if (ah_assoc != NULL) {
		ap->ipa_act.ipa_apply.ipp_ah_minbits =
		    ah_assoc->ipsa_authkeybits;
		ap->ipa_act.ipa_apply.ipp_ah_maxbits =
		    ah_assoc->ipsa_authkeybits;
		ap->ipa_act.ipa_apply.ipp_km_proto = ah_assoc->ipsa_kmp;
		ap->ipa_act.ipa_apply.ipp_km_cookie = ah_assoc->ipsa_kmc;
		if (ah_assoc->ipsa_flags & IPSA_F_UNIQUE)
			unique = B_TRUE;
	}
	ap->ipa_act.ipa_apply.ipp_use_unique = unique;
	ap->ipa_want_unique = unique;
	ap->ipa_allow_clear = B_FALSE;
	ap->ipa_want_se = ii->ipsec_in_decaps;
	ap->ipa_want_ah = (ah_assoc != NULL);
	ap->ipa_want_esp = (esp_assoc != NULL);

	ap->ipa_ovhd = ipsec_act_ovhd(&ap->ipa_act);

	ap->ipa_act.ipa_apply.ipp_replay_depth = 0; /* don't care */

	return (ap);
}


/*
 * Compute the worst-case amount of extra space required by an action.
 * Note that, because of the ESP considerations listed below, this is
 * actually not the same as the best-case reduction in the MTU; in the
 * future, we should pass additional information to this function to
 * allow the actual MTU impact to be computed.
 *
 * AH: Revisit this if we implement algorithms with
 * a verifier size of more than 12 bytes.
 *
 * ESP: A more exact but more messy computation would take into
 * account the interaction between the cipher block size and the
 * effective MTU, yielding the inner payload size which reflects a
 * packet with *minimum* ESP padding..
 */
static int32_t
ipsec_act_ovhd(const ipsec_act_t *act)
{
	int32_t overhead = 0;

	if (act->ipa_type == IPSEC_ACT_APPLY) {
		const ipsec_prot_t *ipp = &act->ipa_apply;

		if (ipp->ipp_use_ah)
			overhead += IPSEC_MAX_AH_HDR_SIZE;
		if (ipp->ipp_use_esp) {
			overhead += IPSEC_MAX_ESP_HDR_SIZE;
			overhead += sizeof (struct udphdr);
		}
		if (ipp->ipp_use_se)
			overhead += IP_SIMPLE_HDR_LENGTH;
	}
	return (overhead);
}

/*
 * This hash function is used only when creating policies and thus is not
 * performance-critical for packet flows.
 *
 * Future work: canonicalize the structures hashed with this (i.e.,
 * zeroize padding) so the hash works correctly.
 */
/* ARGSUSED */
static uint32_t
policy_hash(int size, const void *start, const void *end)
{
	return (0);
}


/*
 * Hash function macros for each address type.
 *
 * The IPV6 hash function assumes that the low order 32-bits of the
 * address (typically containing the low order 24 bits of the mac
 * address) are reasonably well-distributed.  Revisit this if we run
 * into trouble from lots of collisions on ::1 addresses and the like
 * (seems unlikely).
 */
#define	IPSEC_IPV4_HASH(a) ((a) % ipsec_spd_hashsize)
#define	IPSEC_IPV6_HASH(a) ((a.s6_addr32[3]) % ipsec_spd_hashsize)

/*
 * These two hash functions should produce coordinated values
 * but have slightly different roles.
 */
static uint32_t
selkey_hash(const ipsec_selkey_t *selkey)
{
	uint32_t valid = selkey->ipsl_valid;

	if (!(valid & IPSL_REMOTE_ADDR))
		return (IPSEC_SEL_NOHASH);

	if (valid & IPSL_IPV4) {
		if (selkey->ipsl_remote_pfxlen == 32)
			return (IPSEC_IPV4_HASH(selkey->ipsl_remote.ipsad_v4));
	}
	if (valid & IPSL_IPV6) {
		if (selkey->ipsl_remote_pfxlen == 128)
			return (IPSEC_IPV6_HASH(selkey->ipsl_remote.ipsad_v6));
	}
	return (IPSEC_SEL_NOHASH);
}

static uint32_t
selector_hash(ipsec_selector_t *sel)
{
	if (sel->ips_isv4) {
		return (IPSEC_IPV4_HASH(sel->ips_remote_addr_v4));
	}
	return (IPSEC_IPV6_HASH(sel->ips_remote_addr_v6));
}

/*
 * Intern actions into the action hash table.
 */
ipsec_action_t *
ipsec_act_find(const ipsec_act_t *a, int n)
{
	int i;
	uint32_t hval;
	ipsec_action_t *ap;
	ipsec_action_t *prev = NULL;
	int32_t overhead, maxovhd = 0;
	boolean_t allow_clear = B_FALSE;
	boolean_t want_ah = B_FALSE;
	boolean_t want_esp = B_FALSE;
	boolean_t want_se = B_FALSE;
	boolean_t want_unique = B_FALSE;

	/*
	 * TODO: should canonicalize a[] (i.e., zeroize any padding)
	 * so we can use a non-trivial policy_hash function.
	 */
	for (i = n-1; i >= 0; i--) {
		hval = policy_hash(IPSEC_ACTION_HASH_SIZE, &a[i], &a[n]);

		HASH_LOCK(ipsec_action_hash, hval);

		for (HASH_ITERATE(ap, ipa_hash, ipsec_action_hash, hval)) {
			if (bcmp(&ap->ipa_act, &a[i], sizeof (*a)) != 0)
				continue;
			if (ap->ipa_next != prev)
				continue;
			break;
		}
		if (ap != NULL) {
			HASH_UNLOCK(ipsec_action_hash, hval);
			prev = ap;
			continue;
		}
		/*
		 * need to allocate a new one..
		 */
		ap = kmem_cache_alloc(ipsec_action_cache, KM_NOSLEEP);
		if (ap == NULL) {
			HASH_UNLOCK(ipsec_action_hash, hval);
			if (prev != NULL)
				ipsec_action_free(prev);
			return (NULL);
		}
		HASH_INSERT(ap, ipa_hash, ipsec_action_hash, hval);

		ap->ipa_next = prev;
		ap->ipa_act = a[i];

		overhead = ipsec_act_ovhd(&a[i]);
		if (maxovhd < overhead)
			maxovhd = overhead;

		if ((a[i].ipa_type == IPSEC_ACT_BYPASS) ||
		    (a[i].ipa_type == IPSEC_ACT_CLEAR))
			allow_clear = B_TRUE;
		if (a[i].ipa_type == IPSEC_ACT_APPLY) {
			const ipsec_prot_t *ipp = &a[i].ipa_apply;

			ASSERT(ipp->ipp_use_ah || ipp->ipp_use_esp);
			want_ah |= ipp->ipp_use_ah;
			want_esp |= ipp->ipp_use_esp;
			want_se |= ipp->ipp_use_se;
			want_unique |= ipp->ipp_use_unique;
		}
		ap->ipa_allow_clear = allow_clear;
		ap->ipa_want_ah = want_ah;
		ap->ipa_want_esp = want_esp;
		ap->ipa_want_se = want_se;
		ap->ipa_want_unique = want_unique;
		ap->ipa_refs = 1; /* from the hash table */
		ap->ipa_ovhd = maxovhd;
		if (prev)
			prev->ipa_refs++;
		prev = ap;
		HASH_UNLOCK(ipsec_action_hash, hval);
	}

	ap->ipa_refs++;		/* caller's reference */

	return (ap);
}

/*
 * Called when refcount goes to 0, indicating that all references to this
 * node are gone.
 *
 * This does not unchain the action from the hash table.
 */
void
ipsec_action_free(ipsec_action_t *ap)
{
	for (;;) {
		ipsec_action_t *np = ap->ipa_next;
		ASSERT(ap->ipa_refs == 0);
		ASSERT(ap->ipa_hash.hash_pp == NULL);
		kmem_cache_free(ipsec_action_cache, ap);
		ap = np;
		/* Inlined IPACT_REFRELE -- avoid recursion */
		if (ap == NULL)
			break;
		membar_exit();
		if (atomic_add_32_nv(&(ap)->ipa_refs, -1) != 0)
			break;
		/* End inlined IPACT_REFRELE */
	}
}

/*
 * Periodically sweep action hash table for actions with refcount==1, and
 * nuke them.  We cannot do this "on demand" (i.e., from IPACT_REFRELE)
 * because we can't close the race between another thread finding the action
 * in the hash table without holding the bucket lock during IPACT_REFRELE.
 * Instead, we run this function sporadically to clean up after ourselves;
 * we also set it as the "reclaim" function for the action kmem_cache.
 *
 * Note that it may take several passes of ipsec_action_gc() to free all
 * "stale" actions.
 */
/* ARGSUSED */
static void
ipsec_action_reclaim(void *dummy)
{
	int i;

	for (i = 0; i < IPSEC_ACTION_HASH_SIZE; i++) {
		ipsec_action_t *ap, *np;

		/* skip the lock if nobody home */
		if (ipsec_action_hash[i].hash_head == NULL)
			continue;

		HASH_LOCK(ipsec_action_hash, i);
		for (ap = ipsec_action_hash[i].hash_head;
		    ap != NULL; ap = np) {
			ASSERT(ap->ipa_refs > 0);
			np = ap->ipa_hash.hash_next;
			if (ap->ipa_refs > 1)
				continue;
			HASH_UNCHAIN(ap, ipa_hash, ipsec_action_hash, i);
			IPACT_REFRELE(ap);
		}
		HASH_UNLOCK(ipsec_action_hash, i);
	}
}

/*
 * Intern a selector set into the selector set hash table.
 * This is simpler than the actions case..
 */
static ipsec_sel_t *
ipsec_find_sel(ipsec_selkey_t *selkey)
{
	ipsec_sel_t *sp;
	uint32_t hval, bucket;

	/*
	 * Exactly one AF bit should be set in selkey.
	 */
	ASSERT(!(selkey->ipsl_valid & IPSL_IPV4) ^
	    !(selkey->ipsl_valid & IPSL_IPV6));

	hval = selkey_hash(selkey);
	selkey->ipsl_hval = hval;

	bucket = (hval == IPSEC_SEL_NOHASH) ? 0 : hval;

	ASSERT(!HASH_LOCKED(ipsec_sel_hash, bucket));
	HASH_LOCK(ipsec_sel_hash, bucket);

	for (HASH_ITERATE(sp, ipsl_hash, ipsec_sel_hash, bucket)) {
		if (bcmp(&sp->ipsl_key, selkey, sizeof (*selkey)) == 0)
			break;
	}
	if (sp != NULL) {
		sp->ipsl_refs++;

		HASH_UNLOCK(ipsec_sel_hash, bucket);
		return (sp);
	}

	sp = kmem_cache_alloc(ipsec_sel_cache, KM_NOSLEEP);
	if (sp == NULL) {
		HASH_UNLOCK(ipsec_sel_hash, bucket);
		return (NULL);
	}

	HASH_INSERT(sp, ipsl_hash, ipsec_sel_hash, bucket);
	sp->ipsl_refs = 2;	/* one for hash table, one for caller */
	sp->ipsl_key = *selkey;

	HASH_UNLOCK(ipsec_sel_hash, bucket);

	return (sp);
}

static void
ipsec_sel_rel(ipsec_sel_t **spp)
{
	ipsec_sel_t *sp = *spp;
	int hval = sp->ipsl_key.ipsl_hval;
	*spp = NULL;

	if (hval == IPSEC_SEL_NOHASH)
		hval = 0;

	ASSERT(!HASH_LOCKED(ipsec_sel_hash, hval));
	HASH_LOCK(ipsec_sel_hash, hval);
	if (--sp->ipsl_refs == 1) {
		HASH_UNCHAIN(sp, ipsl_hash, ipsec_sel_hash, hval);
		sp->ipsl_refs--;
		HASH_UNLOCK(ipsec_sel_hash, hval);
		ASSERT(sp->ipsl_refs == 0);
		kmem_cache_free(ipsec_sel_cache, sp);
		/* Caller unlocks */
		return;
	}

	HASH_UNLOCK(ipsec_sel_hash, hval);
}

/*
 * Free a policy rule which we know is no longer being referenced.
 */
void
ipsec_policy_free(ipsec_policy_t *ipp)
{
	ASSERT(ipp->ipsp_refs == 0);
	ASSERT(ipp->ipsp_sel != NULL);
	ASSERT(ipp->ipsp_act != NULL);
	ipsec_sel_rel(&ipp->ipsp_sel);
	IPACT_REFRELE(ipp->ipsp_act);
	kmem_cache_free(ipsec_pol_cache, ipp);
}

/*
 * Construction of new policy rules; construct a policy, and add it to
 * the appropriate tables.
 */
ipsec_policy_t *
ipsec_policy_create(ipsec_selkey_t *keys, const ipsec_act_t *a,
    int nacts, int prio)
{
	ipsec_action_t *ap;
	ipsec_sel_t *sp;
	ipsec_policy_t *ipp;

	ipp = kmem_cache_alloc(ipsec_pol_cache, KM_NOSLEEP);
	ap = ipsec_act_find(a, nacts);
	sp = ipsec_find_sel(keys);

	if ((ap == NULL) || (sp == NULL) || (ipp == NULL)) {
		if (ap != NULL) {
			IPACT_REFRELE(ap);
		}
		if (sp != NULL)
			ipsec_sel_rel(&sp);
		if (ipp != NULL)
			kmem_cache_free(ipsec_pol_cache, ipp);
		return (NULL);
	}

	HASH_NULL(ipp, ipsp_hash);

	ipp->ipsp_refs = 1;	/* caller's reference */
	ipp->ipsp_sel = sp;
	ipp->ipsp_act = ap;
	ipp->ipsp_prio = prio;	/* rule priority */
	ipp->ipsp_index = ipsec_next_policy_index++;

	return (ipp);
}

static void
ipsec_update_present_flags()
{
	boolean_t hashpol = (avl_numnodes(&system_policy.iph_rulebyid) > 0);

	if (hashpol) {
		ipsec_outbound_v4_policy_present = B_TRUE;
		ipsec_outbound_v6_policy_present = B_TRUE;
		ipsec_inbound_v4_policy_present = B_TRUE;
		ipsec_inbound_v6_policy_present = B_TRUE;
		return;
	}

	ipsec_outbound_v4_policy_present = (NULL !=
	    system_policy.iph_root[IPSEC_TYPE_OUTBOUND].
	    ipr_nonhash[IPSEC_AF_V4]);
	ipsec_outbound_v6_policy_present = (NULL !=
	    system_policy.iph_root[IPSEC_TYPE_OUTBOUND].
	    ipr_nonhash[IPSEC_AF_V6]);
	ipsec_inbound_v4_policy_present = (NULL !=
	    system_policy.iph_root[IPSEC_TYPE_INBOUND].
	    ipr_nonhash[IPSEC_AF_V4]);
	ipsec_inbound_v6_policy_present = (NULL !=
	    system_policy.iph_root[IPSEC_TYPE_INBOUND].
	    ipr_nonhash[IPSEC_AF_V6]);
}

boolean_t
ipsec_policy_delete(ipsec_policy_head_t *php, ipsec_selkey_t *keys, int dir)
{
	ipsec_sel_t *sp;
	ipsec_policy_t *ip, *nip, *head;
	int af;
	ipsec_policy_root_t *pr = &php->iph_root[dir];

	sp = ipsec_find_sel(keys);

	if (sp == NULL)
		return (B_FALSE);

	af = (sp->ipsl_key.ipsl_valid & IPSL_IPV4) ? IPSEC_AF_V4 : IPSEC_AF_V6;

	rw_enter(&php->iph_lock, RW_WRITER);

	if (keys->ipsl_hval == IPSEC_SEL_NOHASH) {
		head = pr->ipr_nonhash[af];
	} else {
		head = pr->ipr_hash[keys->ipsl_hval].hash_head;
	}

	for (ip = head; ip != NULL; ip = nip) {
		nip = ip->ipsp_hash.hash_next;
		if (ip->ipsp_sel != sp) {
			continue;
		}

		IPPOL_UNCHAIN(php, ip);

		php->iph_gen++;
		ipsec_update_present_flags();

		rw_exit(&php->iph_lock);

		ipsec_sel_rel(&sp);

		return (B_TRUE);
	}

	rw_exit(&php->iph_lock);
	ipsec_sel_rel(&sp);
	return (B_FALSE);
}

int
ipsec_policy_delete_index(ipsec_policy_head_t *php, uint64_t policy_index)
{
	boolean_t found = B_FALSE;
	ipsec_policy_t ipkey;
	ipsec_policy_t *ip;
	avl_index_t where;

	(void) memset(&ipkey, 0, sizeof (ipkey));
	ipkey.ipsp_index = policy_index;

	rw_enter(&php->iph_lock, RW_WRITER);

	/*
	 * We could be cleverer here about the walk.
	 * but well, (k+1)*log(N) will do for now (k==number of matches,
	 * N==number of table entries
	 */
	for (;;) {
		ip = (ipsec_policy_t *)avl_find(&php->iph_rulebyid,
		    (void *)&ipkey, &where);
		ASSERT(ip == NULL);

		ip = avl_nearest(&php->iph_rulebyid, where, AVL_AFTER);

		if (ip == NULL)
			break;

		if (ip->ipsp_index != policy_index) {
			ASSERT(ip->ipsp_index > policy_index);
			break;
		}

		IPPOL_UNCHAIN(php, ip);
		found = B_TRUE;
	}

	if (found) {
		php->iph_gen++;
		ipsec_update_present_flags();
	}

	rw_exit(&php->iph_lock);

	return (found ? 0 : ENOENT);
}

/*
 * Given a constructed ipsec_policy_t policy rule, see if it can be entered
 * into the correct policy ruleset.
 *
 * Returns B_TRUE if it can be entered, B_FALSE if it can't be (because a
 * duplicate policy exists with exactly the same selectors), or an icmp
 * rule exists with a different encryption/authentication action.
 */
boolean_t
ipsec_check_policy(ipsec_policy_head_t *php, ipsec_policy_t *ipp, int direction)
{
	ipsec_policy_root_t *pr = &php->iph_root[direction];
	int af = -1;
	ipsec_policy_t *p2, *head;
	uint8_t check_proto;
	ipsec_selkey_t *selkey = &ipp->ipsp_sel->ipsl_key;
	uint32_t	valid = selkey->ipsl_valid;

	if (valid & IPSL_IPV6) {
		ASSERT(!(valid & IPSL_IPV4));
		af = IPSEC_AF_V6;
		check_proto = IPPROTO_ICMPV6;
	} else {
		ASSERT(valid & IPSL_IPV4);
		af = IPSEC_AF_V4;
		check_proto = IPPROTO_ICMP;
	}

	ASSERT(RW_WRITE_HELD(&php->iph_lock));

	/*
	 * Double-check that we don't have any duplicate selectors here.
	 * Because selectors are interned below, we need only compare pointers
	 * for equality.
	 */
	if (selkey->ipsl_hval == IPSEC_SEL_NOHASH) {
		head = pr->ipr_nonhash[af];
	} else {
		head = pr->ipr_hash[selkey->ipsl_hval].hash_head;
	}

	for (p2 = head; p2 != NULL; p2 = p2->ipsp_hash.hash_next) {
		if (p2->ipsp_sel == ipp->ipsp_sel)
			return (B_FALSE);
	}

	/*
	 * If it's ICMP and not a drop or pass rule, run through the ICMP
	 * rules and make sure the action is either new or the same as any
	 * other actions.  We don't have to check the full chain because
	 * discard and bypass will override all other actions
	 */

	if (valid & IPSL_PROTOCOL &&
	    selkey->ipsl_proto == check_proto &&
	    (ipp->ipsp_act->ipa_act.ipa_type == IPSEC_ACT_APPLY)) {

		for (p2 = head; p2 != NULL; p2 = p2->ipsp_hash.hash_next) {

			if (p2->ipsp_sel->ipsl_key.ipsl_valid & IPSL_PROTOCOL &&
			    p2->ipsp_sel->ipsl_key.ipsl_proto == check_proto &&
			    (p2->ipsp_act->ipa_act.ipa_type ==
				IPSEC_ACT_APPLY)) {
				return (ipsec_compare_action(p2, ipp));
			}
		}
	}

	return (B_TRUE);
}

/*
 * compare the action chains of two policies for equality
 * B_TRUE -> effective equality
 */

static boolean_t
ipsec_compare_action(ipsec_policy_t *p1, ipsec_policy_t *p2)
{

	ipsec_action_t *act1, *act2;

	/* We have a valid rule. Let's compare the actions */
	if (p1->ipsp_act == p2->ipsp_act) {
		/* same action. We are good */
		return (B_TRUE);
	}

	/* we have to walk the chain */

	act1 = p1->ipsp_act;
	act2 = p2->ipsp_act;

	while (act1 != NULL && act2 != NULL) {

		/* otherwise, Are we close enough? */
		if (act1->ipa_allow_clear != act2->ipa_allow_clear ||
		    act1->ipa_want_ah != act2->ipa_want_ah ||
		    act1->ipa_want_esp != act2->ipa_want_esp ||
		    act1->ipa_want_se != act2->ipa_want_se) {
			/* Nope, we aren't */
			return (B_FALSE);
		}

		if (act1->ipa_want_ah) {
			if (act1->ipa_act.ipa_apply.ipp_auth_alg !=
			    act2->ipa_act.ipa_apply.ipp_auth_alg) {
				return (B_FALSE);
			}

			if (act1->ipa_act.ipa_apply.ipp_ah_minbits !=
			    act2->ipa_act.ipa_apply.ipp_ah_minbits ||
			    act1->ipa_act.ipa_apply.ipp_ah_maxbits !=
			    act2->ipa_act.ipa_apply.ipp_ah_maxbits) {
				return (B_FALSE);
			}
		}

		if (act1->ipa_want_esp) {
			if (act1->ipa_act.ipa_apply.ipp_use_esp !=
			    act2->ipa_act.ipa_apply.ipp_use_esp ||
			    act1->ipa_act.ipa_apply.ipp_use_espa !=
			    act2->ipa_act.ipa_apply.ipp_use_espa) {
				return (B_FALSE);
			}

			if (act1->ipa_act.ipa_apply.ipp_use_esp) {
				if (act1->ipa_act.ipa_apply.ipp_encr_alg !=
				    act2->ipa_act.ipa_apply.ipp_encr_alg) {
					return (B_FALSE);
				}

				if (act1->ipa_act.ipa_apply.ipp_espe_minbits !=
				    act2->ipa_act.ipa_apply.ipp_espe_minbits ||
				    act1->ipa_act.ipa_apply.ipp_espe_maxbits !=
				    act2->ipa_act.ipa_apply.ipp_espe_maxbits) {
					return (B_FALSE);
				}
			}

			if (act1->ipa_act.ipa_apply.ipp_use_espa) {
				if (act1->ipa_act.ipa_apply.ipp_esp_auth_alg !=
				    act2->ipa_act.ipa_apply.ipp_esp_auth_alg) {
					return (B_FALSE);
				}

				if (act1->ipa_act.ipa_apply.ipp_espa_minbits !=
				    act2->ipa_act.ipa_apply.ipp_espa_minbits ||
				    act1->ipa_act.ipa_apply.ipp_espa_maxbits !=
				    act2->ipa_act.ipa_apply.ipp_espa_maxbits) {
					return (B_FALSE);
				}
			}

		}

		act1 = act1->ipa_next;
		act2 = act2->ipa_next;
	}

	if (act1 != NULL || act2 != NULL) {
		return (B_FALSE);
	}

	return (B_TRUE);
}


/*
 * Given a constructed ipsec_policy_t policy rule, enter it into
 * the correct policy ruleset.
 *
 * ipsec_check_policy() is assumed to have succeeded first (to check for
 * duplicates).
 */
void
ipsec_enter_policy(ipsec_policy_head_t *php, ipsec_policy_t *ipp, int direction)
{
	ipsec_policy_root_t *pr = &php->iph_root[direction];
	ipsec_selkey_t *selkey = &ipp->ipsp_sel->ipsl_key;
	uint32_t valid = selkey->ipsl_valid;
	uint32_t hval = selkey->ipsl_hval;
	int af = -1;

	ASSERT(RW_WRITE_HELD(&php->iph_lock));

	if (valid & IPSL_IPV6) {
		ASSERT(!(valid & IPSL_IPV4));
		af = IPSEC_AF_V6;
	} else {
		ASSERT(valid & IPSL_IPV4);
		af = IPSEC_AF_V4;
	}

	php->iph_gen++;

	if (hval == IPSEC_SEL_NOHASH) {
		HASHLIST_INSERT(ipp, ipsp_hash, pr->ipr_nonhash[af]);
	} else {
		HASH_LOCK(pr->ipr_hash, hval);
		HASH_INSERT(ipp, ipsp_hash, pr->ipr_hash, hval);
		HASH_UNLOCK(pr->ipr_hash, hval);
	}

	ipsec_insert_always(&php->iph_rulebyid, ipp);

	ipsec_update_present_flags();
}

static void
ipsec_ipr_flush(ipsec_policy_head_t *php, ipsec_policy_root_t *ipr)
{
	ipsec_policy_t *ip, *nip;

	int af, chain, nchain;

	for (af = 0; af < IPSEC_NAF; af++) {
		for (ip = ipr->ipr_nonhash[af]; ip != NULL; ip = nip) {
			nip = ip->ipsp_hash.hash_next;
			IPPOL_UNCHAIN(php, ip);
		}
		ipr->ipr_nonhash[af] = NULL;
	}
	nchain = ipr->ipr_nchains;

	for (chain = 0; chain < nchain; chain++) {
		for (ip = ipr->ipr_hash[chain].hash_head; ip != NULL;
		    ip = nip) {
			nip = ip->ipsp_hash.hash_next;
			IPPOL_UNCHAIN(php, ip);
		}
		ipr->ipr_hash[chain].hash_head = NULL;
	}
}


void
ipsec_polhead_flush(ipsec_policy_head_t *php)
{
	int dir;

	ASSERT(RW_WRITE_HELD(&php->iph_lock));

	for (dir = 0; dir < IPSEC_NTYPES; dir++)
		ipsec_ipr_flush(php, &php->iph_root[dir]);

	ipsec_update_present_flags();
}

void
ipsec_polhead_free(ipsec_policy_head_t *php)
{
	ASSERT(php->iph_refs == 0);
	rw_enter(&php->iph_lock, RW_WRITER);
	ipsec_polhead_flush(php);
	rw_exit(&php->iph_lock);
	rw_destroy(&php->iph_lock);
	kmem_free(php, sizeof (*php));
}

static void
ipsec_ipr_init(ipsec_policy_root_t *ipr)
{
	int af;

	ipr->ipr_nchains = 0;
	ipr->ipr_hash = NULL;

	for (af = 0; af < IPSEC_NAF; af++) {
		ipr->ipr_nonhash[af] = NULL;
	}
}

extern ipsec_policy_head_t *
ipsec_polhead_create(void)
{
	ipsec_policy_head_t *php;

	php = kmem_alloc(sizeof (*php), KM_NOSLEEP);
	if (php == NULL)
		return (php);

	rw_init(&php->iph_lock, NULL, RW_DEFAULT, NULL);
	php->iph_refs = 1;
	php->iph_gen = 0;

	ipsec_ipr_init(&php->iph_root[IPSEC_TYPE_INBOUND]);
	ipsec_ipr_init(&php->iph_root[IPSEC_TYPE_OUTBOUND]);

	avl_create(&php->iph_rulebyid, ipsec_policy_cmpbyid,
	    sizeof (ipsec_policy_t), offsetof(ipsec_policy_t, ipsp_byid));

	return (php);
}

/*
 * Clone the policy head into a new polhead; release one reference to the
 * old one and return the only reference to the new one.
 * If the old one had a refcount of 1, just return it.
 */
extern ipsec_policy_head_t *
ipsec_polhead_split(ipsec_policy_head_t *php)
{
	ipsec_policy_head_t *nphp;

	if (php == NULL)
		return (ipsec_polhead_create());
	else if (php->iph_refs == 1)
		return (php);

	nphp = ipsec_polhead_create();
	if (nphp == NULL)
		return (NULL);

	if (ipsec_copy_polhead(php, nphp) != 0) {
		ipsec_polhead_free(nphp);
		return (NULL);
	}
	IPPH_REFRELE(php);
	return (nphp);
}

/*
 * When sending a response to a ICMP request or generating a RST
 * in the TCP case, the outbound packets need to go at the same level
 * of protection as the incoming ones i.e we associate our outbound
 * policy with how the packet came in. We call this after we have
 * accepted the incoming packet which may or may not have been in
 * clear and hence we are sending the reply back with the policy
 * matching the incoming datagram's policy.
 *
 * NOTE : This technology serves two purposes :
 *
 * 1) If we have multiple outbound policies, we send out a reply
 *    matching with how it came in rather than matching the outbound
 *    policy.
 *
 * 2) For assymetric policies, we want to make sure that incoming
 *    and outgoing has the same level of protection. Assymetric
 *    policies exist only with global policy where we may not have
 *    both outbound and inbound at the same time.
 *
 * NOTE2:	This function is called by cleartext cases, so it needs to be
 *		in IP proper.
 */
boolean_t
ipsec_in_to_out(mblk_t *ipsec_mp, ipha_t *ipha, ip6_t *ip6h)
{
	ipsec_in_t  *ii;
	ipsec_out_t  *io;
	boolean_t v4;
	mblk_t *mp;
	boolean_t secure, attach_if;
	uint_t ifindex;
	ipsec_selector_t sel;
	ipsec_action_t *reflect_action = NULL;
	zoneid_t zoneid;

	ASSERT(ipsec_mp->b_datap->db_type == M_CTL);

	bzero((void*)&sel, sizeof (sel));

	ii = (ipsec_in_t *)ipsec_mp->b_rptr;

	mp = ipsec_mp->b_cont;
	ASSERT(mp != NULL);

	if (ii->ipsec_in_action != NULL) {
		/* transfer reference.. */
		reflect_action = ii->ipsec_in_action;
		ii->ipsec_in_action = NULL;
	} else if (!ii->ipsec_in_loopback)
		reflect_action = ipsec_in_to_out_action(ii);
	secure = ii->ipsec_in_secure;
	attach_if = ii->ipsec_in_attach_if;
	ifindex = ii->ipsec_in_ill_index;
	zoneid = ii->ipsec_in_zoneid;
	v4 = ii->ipsec_in_v4;

	ipsec_in_release_refs(ii);

	/*
	 * The caller is going to send the datagram out which might
	 * go on the wire or delivered locally through ip_wput_local.
	 *
	 * 1) If it goes out on the wire, new associations will be
	 *    obtained.
	 * 2) If it is delivered locally, ip_wput_local will convert
	 *    this IPSEC_OUT to a IPSEC_IN looking at the requests.
	 */

	io = (ipsec_out_t *)ipsec_mp->b_rptr;
	bzero(io, sizeof (ipsec_out_t));
	io->ipsec_out_type = IPSEC_OUT;
	io->ipsec_out_len = sizeof (ipsec_out_t);
	io->ipsec_out_frtn.free_func = ipsec_out_free;
	io->ipsec_out_frtn.free_arg = (char *)io;
	io->ipsec_out_act = reflect_action;

	if (!ipsec_init_outbound_ports(&sel, mp, ipha, ip6h))
		return (B_FALSE);

	io->ipsec_out_src_port = sel.ips_local_port;
	io->ipsec_out_dst_port = sel.ips_remote_port;
	io->ipsec_out_proto = sel.ips_protocol;
	io->ipsec_out_icmp_type = sel.ips_icmp_type;
	io->ipsec_out_icmp_code = sel.ips_icmp_code;

	/*
	 * Don't use global policy for this, as we want
	 * to use the same protection that was applied to the inbound packet.
	 */
	io->ipsec_out_use_global_policy = B_FALSE;
	io->ipsec_out_proc_begin = B_FALSE;
	io->ipsec_out_secure = secure;
	io->ipsec_out_v4 = v4;
	io->ipsec_out_attach_if = attach_if;
	io->ipsec_out_ill_index = ifindex;
	io->ipsec_out_zoneid = zoneid;
	return (B_TRUE);
}

mblk_t *
ipsec_in_tag(mblk_t *mp, mblk_t *cont)
{
	ipsec_in_t *ii = (ipsec_in_t *)mp->b_rptr;
	ipsec_in_t *nii;
	mblk_t *nmp;
	frtn_t nfrtn;

	ASSERT(ii->ipsec_in_type == IPSEC_IN);
	ASSERT(ii->ipsec_in_len == sizeof (ipsec_in_t));

	nmp = ipsec_in_alloc(ii->ipsec_in_v4);

	ASSERT(nmp->b_datap->db_type == M_CTL);
	ASSERT(nmp->b_wptr == (nmp->b_rptr + sizeof (ipsec_info_t)));

	/*
	 * Bump refcounts.
	 */
	if (ii->ipsec_in_ah_sa != NULL)
		IPSA_REFHOLD(ii->ipsec_in_ah_sa);
	if (ii->ipsec_in_esp_sa != NULL)
		IPSA_REFHOLD(ii->ipsec_in_esp_sa);
	if (ii->ipsec_in_policy != NULL)
		IPPH_REFHOLD(ii->ipsec_in_policy);

	/*
	 * Copy everything, but preserve the free routine provided by
	 * ipsec_in_alloc().
	 */
	nii = (ipsec_in_t *)nmp->b_rptr;
	nfrtn = nii->ipsec_in_frtn;
	bcopy(ii, nii, sizeof (*ii));
	nii->ipsec_in_frtn = nfrtn;

	nmp->b_cont = cont;

	return (nmp);
}

mblk_t *
ipsec_out_tag(mblk_t *mp, mblk_t *cont)
{
	ipsec_out_t *io = (ipsec_out_t *)mp->b_rptr;
	ipsec_out_t *nio;
	mblk_t *nmp;
	frtn_t nfrtn;

	ASSERT(io->ipsec_out_type == IPSEC_OUT);
	ASSERT(io->ipsec_out_len == sizeof (ipsec_out_t));

	nmp = ipsec_alloc_ipsec_out();
	if (nmp == NULL) {
		freemsg(cont);	/* XXX ip_drop_packet() ? */
		return (NULL);
	}
	ASSERT(nmp->b_datap->db_type == M_CTL);
	ASSERT(nmp->b_wptr == (nmp->b_rptr + sizeof (ipsec_info_t)));

	/*
	 * Bump refcounts.
	 */
	if (io->ipsec_out_ah_sa != NULL)
		IPSA_REFHOLD(io->ipsec_out_ah_sa);
	if (io->ipsec_out_esp_sa != NULL)
		IPSA_REFHOLD(io->ipsec_out_esp_sa);
	if (io->ipsec_out_polhead != NULL)
		IPPH_REFHOLD(io->ipsec_out_polhead);
	if (io->ipsec_out_policy != NULL)
		IPPOL_REFHOLD(io->ipsec_out_policy);
	if (io->ipsec_out_act != NULL)
		IPACT_REFHOLD(io->ipsec_out_act);
	if (io->ipsec_out_latch != NULL)
		IPLATCH_REFHOLD(io->ipsec_out_latch);
	if (io->ipsec_out_cred != NULL)
		crhold(io->ipsec_out_cred);

	/*
	 * Copy everything, but preserve the free routine provided by
	 * ipsec_alloc_ipsec_out().
	 */
	nio = (ipsec_out_t *)nmp->b_rptr;
	nfrtn = nio->ipsec_out_frtn;
	bcopy(io, nio, sizeof (*io));
	nio->ipsec_out_frtn = nfrtn;

	nmp->b_cont = cont;

	return (nmp);
}

static void
ipsec_out_release_refs(ipsec_out_t *io)
{
	ASSERT(io->ipsec_out_type == IPSEC_OUT);
	ASSERT(io->ipsec_out_len == sizeof (ipsec_out_t));

	/* Note: IPSA_REFRELE is multi-line macro */
	if (io->ipsec_out_ah_sa != NULL)
		IPSA_REFRELE(io->ipsec_out_ah_sa);
	if (io->ipsec_out_esp_sa != NULL)
		IPSA_REFRELE(io->ipsec_out_esp_sa);
	if (io->ipsec_out_polhead != NULL)
		IPPH_REFRELE(io->ipsec_out_polhead);
	if (io->ipsec_out_policy != NULL)
		IPPOL_REFRELE(io->ipsec_out_policy);
	if (io->ipsec_out_act != NULL)
		IPACT_REFRELE(io->ipsec_out_act);
	if (io->ipsec_out_cred != NULL) {
		crfree(io->ipsec_out_cred);
		io->ipsec_out_cred = NULL;
	}
	if (io->ipsec_out_latch) {
		IPLATCH_REFRELE(io->ipsec_out_latch);
		io->ipsec_out_latch = NULL;
	}
}

static void
ipsec_out_free(void *arg)
{
	ipsec_out_t *io = (ipsec_out_t *)arg;
	ipsec_out_release_refs(io);
	kmem_cache_free(ipsec_info_cache, arg);
}

static void
ipsec_in_release_refs(ipsec_in_t *ii)
{
	/* Note: IPSA_REFRELE is multi-line macro */
	if (ii->ipsec_in_ah_sa != NULL)
		IPSA_REFRELE(ii->ipsec_in_ah_sa);
	if (ii->ipsec_in_esp_sa != NULL)
		IPSA_REFRELE(ii->ipsec_in_esp_sa);
	if (ii->ipsec_in_policy != NULL)
		IPPH_REFRELE(ii->ipsec_in_policy);
	if (ii->ipsec_in_da != NULL) {
		freeb(ii->ipsec_in_da);
		ii->ipsec_in_da = NULL;
	}
}

static void
ipsec_in_free(void *arg)
{
	ipsec_in_t *ii = (ipsec_in_t *)arg;
	ipsec_in_release_refs(ii);
	kmem_cache_free(ipsec_info_cache, arg);
}

/*
 * This is called only for outbound datagrams if the datagram needs to
 * go out secure.  A NULL mp can be passed to get an ipsec_out. This
 * facility is used by ip_unbind.
 *
 * NOTE : o As the data part could be modified by ipsec_out_process etc.
 *	    we can't make it fast by calling a dup.
 */
mblk_t *
ipsec_alloc_ipsec_out()
{
	mblk_t *ipsec_mp;

	ipsec_out_t *io = kmem_cache_alloc(ipsec_info_cache, KM_NOSLEEP);

	if (io == NULL)
		return (NULL);

	bzero(io, sizeof (ipsec_out_t));

	io->ipsec_out_type = IPSEC_OUT;
	io->ipsec_out_len = sizeof (ipsec_out_t);
	io->ipsec_out_frtn.free_func = ipsec_out_free;
	io->ipsec_out_frtn.free_arg = (char *)io;

	/*
	 * Set the zoneid to ALL_ZONES which is used as an invalid value. Code
	 * using ipsec_out_zoneid should assert that the zoneid has been set to
	 * a sane value.
	 */
	io->ipsec_out_zoneid = ALL_ZONES;

	ipsec_mp = desballoc((uint8_t *)io, sizeof (ipsec_info_t), BPRI_HI,
	    &io->ipsec_out_frtn);
	if (ipsec_mp == NULL) {
		ipsec_out_free(io);

		return (NULL);
	}
	ipsec_mp->b_datap->db_type = M_CTL;
	ipsec_mp->b_wptr = ipsec_mp->b_rptr + sizeof (ipsec_info_t);

	return (ipsec_mp);
}

/*
 * Attach an IPSEC_OUT; use pol for policy if it is non-null.
 * Otherwise initialize using conn.
 *
 * If pol is non-null, we consume a reference to it.
 */
mblk_t *
ipsec_attach_ipsec_out(mblk_t *mp, conn_t *connp, ipsec_policy_t *pol,
    uint8_t proto)
{
	mblk_t *ipsec_mp;
	queue_t *q;
	short mid = 0;

	ASSERT((pol != NULL) || (connp != NULL));

	ipsec_mp = ipsec_alloc_ipsec_out();
	if (ipsec_mp == NULL) {
		q = CONNP_TO_WQ(connp);
		if (q != NULL) {
			mid = q->q_qinfo->qi_minfo->mi_idnum;
		}
		ipsec_rl_strlog(mid, 0, 0, SL_ERROR|SL_NOTE,
		    "ipsec_attach_ipsec_out: Allocation failure\n");
		BUMP_MIB(&ip_mib, ipOutDiscards);
		ip_drop_packet(mp, B_FALSE, NULL, NULL, &ipdrops_spd_nomem,
		    &spd_dropper);
		return (NULL);
	}
	ipsec_mp->b_cont = mp;
	return (ipsec_init_ipsec_out(ipsec_mp, connp, pol, proto));
}

/*
 * Initialize the IPSEC_OUT (ipsec_mp) using pol if it is non-null.
 * Otherwise initialize using conn.
 *
 * If pol is non-null, we consume a reference to it.
 */
mblk_t *
ipsec_init_ipsec_out(mblk_t *ipsec_mp, conn_t *connp, ipsec_policy_t *pol,
    uint8_t proto)
{
	mblk_t *mp;
	ipsec_out_t *io;
	ipsec_policy_t *p;
	ipha_t *ipha;
	ip6_t *ip6h;

	ASSERT((pol != NULL) || (connp != NULL));

	/*
	 * If mp is NULL, we won't/should not be using it.
	 */
	mp = ipsec_mp->b_cont;

	ASSERT(ipsec_mp->b_datap->db_type == M_CTL);
	ASSERT(ipsec_mp->b_wptr == (ipsec_mp->b_rptr + sizeof (ipsec_info_t)));
	io = (ipsec_out_t *)ipsec_mp->b_rptr;
	ASSERT(io->ipsec_out_type == IPSEC_OUT);
	ASSERT(io->ipsec_out_len == sizeof (ipsec_out_t));
	io->ipsec_out_latch = NULL;
	/*
	 * Set the zoneid when we have the connp.
	 * Otherwise, we're called from ip_wput_attach_policy() who will take
	 * care of setting the zoneid.
	 */
	if (connp != NULL)
		io->ipsec_out_zoneid = connp->conn_zoneid;

	if (mp != NULL) {
		ipha = (ipha_t *)mp->b_rptr;
		if (IPH_HDR_VERSION(ipha) == IP_VERSION) {
			io->ipsec_out_v4 = B_TRUE;
			ip6h = NULL;
		} else {
			io->ipsec_out_v4 = B_FALSE;
			ip6h = (ip6_t *)ipha;
			ipha = NULL;
		}
	} else {
		ASSERT(connp != NULL && connp->conn_policy_cached);
		ip6h = NULL;
		ipha = NULL;
		io->ipsec_out_v4 = !connp->conn_pkt_isv6;
	}

	p = NULL;

	/*
	 * Take latched policies over global policy.  Check here again for
	 * this, in case we had conn_latch set while the packet was flying
	 * around in IP.
	 */
	if (connp != NULL && connp->conn_latch != NULL) {
		p = connp->conn_latch->ipl_out_policy;
		io->ipsec_out_latch = connp->conn_latch;
		IPLATCH_REFHOLD(connp->conn_latch);
		if (p != NULL) {
			IPPOL_REFHOLD(p);
		}
		io->ipsec_out_src_port = connp->conn_lport;
		io->ipsec_out_dst_port = connp->conn_fport;
		io->ipsec_out_icmp_type = io->ipsec_out_icmp_code = 0;
		if (pol != NULL)
			IPPOL_REFRELE(pol);
	} else if (pol != NULL) {
		ipsec_selector_t sel;

		bzero((void*)&sel, sizeof (sel));

		p = pol;
		/*
		 * conn does not have the port information. Get
		 * it from the packet.
		 */

		if (!ipsec_init_outbound_ports(&sel, mp, ipha, ip6h)) {
			/* XXX any cleanup required here?? */
			return (NULL);
		}
		io->ipsec_out_src_port = sel.ips_local_port;
		io->ipsec_out_dst_port = sel.ips_remote_port;
		io->ipsec_out_icmp_type = sel.ips_icmp_type;
		io->ipsec_out_icmp_code = sel.ips_icmp_code;
	}

	io->ipsec_out_proto = proto;
	io->ipsec_out_use_global_policy = B_TRUE;
	io->ipsec_out_secure = (p != NULL);
	io->ipsec_out_policy = p;

	if (p == NULL) {
		if (connp->conn_policy != NULL) {
			io->ipsec_out_secure = B_TRUE;
			ASSERT(io->ipsec_out_latch == NULL);
			ASSERT(io->ipsec_out_use_global_policy == B_TRUE);
			io->ipsec_out_need_policy = B_TRUE;
			ASSERT(io->ipsec_out_polhead == NULL);
			IPPH_REFHOLD(connp->conn_policy);
			io->ipsec_out_polhead = connp->conn_policy;
		}
	}
	return (ipsec_mp);
}

/*
 * Allocate an IPSEC_IN mblk.  This will be prepended to an inbound datagram
 * and keep track of what-if-any IPsec processing will be applied to the
 * datagram.
 */
mblk_t *
ipsec_in_alloc(boolean_t isv4)
{
	mblk_t *ipsec_in;
	ipsec_in_t *ii = kmem_cache_alloc(ipsec_info_cache, KM_NOSLEEP);

	if (ii == NULL)
		return (NULL);

	bzero(ii, sizeof (ipsec_info_t));
	ii->ipsec_in_type = IPSEC_IN;
	ii->ipsec_in_len = sizeof (ipsec_in_t);

	ii->ipsec_in_v4 = isv4;
	ii->ipsec_in_secure = B_TRUE;

	ii->ipsec_in_frtn.free_func = ipsec_in_free;
	ii->ipsec_in_frtn.free_arg = (char *)ii;

	ipsec_in = desballoc((uint8_t *)ii, sizeof (ipsec_info_t), BPRI_HI,
	    &ii->ipsec_in_frtn);
	if (ipsec_in == NULL) {
		ip1dbg(("ipsec_in_alloc: IPSEC_IN allocation failure.\n"));
		ipsec_in_free(ii);
		return (NULL);
	}

	ipsec_in->b_datap->db_type = M_CTL;
	ipsec_in->b_wptr += sizeof (ipsec_info_t);

	return (ipsec_in);
}

/*
 * This is called from ip_wput_local when a packet which needs
 * security is looped back, to convert the IPSEC_OUT to a IPSEC_IN
 * before fanout, where the policy check happens.  In most of the
 * cases, IPSEC processing has *never* been done.  There is one case
 * (ip_wput_ire_fragmentit -> ip_wput_frag -> icmp_frag_needed) where
 * the packet is destined for localhost, IPSEC processing has already
 * been done.
 *
 * Future: This could happen after SA selection has occurred for
 * outbound.. which will tell us who the src and dst identities are..
 * Then it's just a matter of splicing the ah/esp SA pointers from the
 * ipsec_out_t to the ipsec_in_t.
 */
void
ipsec_out_to_in(mblk_t *ipsec_mp)
{
	ipsec_in_t  *ii;
	ipsec_out_t *io;
	ipsec_policy_t *pol;
	ipsec_action_t *act;
	boolean_t v4, icmp_loopback;

	ASSERT(ipsec_mp->b_datap->db_type == M_CTL);

	io = (ipsec_out_t *)ipsec_mp->b_rptr;

	v4 = io->ipsec_out_v4;
	icmp_loopback = io->ipsec_out_icmp_loopback;

	act = io->ipsec_out_act;
	if (act == NULL) {
		pol = io->ipsec_out_policy;
		if (pol != NULL) {
			act = pol->ipsp_act;
			IPACT_REFHOLD(act);
		}
	}
	io->ipsec_out_act = NULL;

	ipsec_out_release_refs(io);

	ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	bzero(ii, sizeof (ipsec_in_t));
	ii->ipsec_in_type = IPSEC_IN;
	ii->ipsec_in_len = sizeof (ipsec_in_t);
	ii->ipsec_in_loopback = B_TRUE;
	ii->ipsec_in_frtn.free_func = ipsec_in_free;
	ii->ipsec_in_frtn.free_arg = (char *)ii;
	ii->ipsec_in_action = act;

	/*
	 * In most of the cases, we can't look at the ipsec_out_XXX_sa
	 * because this never went through IPSEC processing. So, look at
	 * the requests and infer whether it would have gone through
	 * IPSEC processing or not. Initialize the "done" fields with
	 * the requests. The possible values for "done" fields are :
	 *
	 * 1) zero, indicates that a particular preference was never
	 *    requested.
	 * 2) non-zero, indicates that it could be IPSEC_PREF_REQUIRED/
	 *    IPSEC_PREF_NEVER. If IPSEC_REQ_DONE is set, it means that
	 *    IPSEC processing has been completed.
	 */
	ii->ipsec_in_secure = B_TRUE;
	ii->ipsec_in_v4 = v4;
	ii->ipsec_in_icmp_loopback = icmp_loopback;
	ii->ipsec_in_attach_if = B_FALSE;
}

/*
 * Consults global policy to see whether this datagram should
 * go out secure. If so it attaches a ipsec_mp in front and
 * returns.
 */
mblk_t *
ip_wput_attach_policy(mblk_t *ipsec_mp, ipha_t *ipha, ip6_t *ip6h, ire_t *ire,
    conn_t *connp, boolean_t unspec_src)
{
	mblk_t *mp;
	ipsec_out_t *io = NULL;
	ipsec_selector_t sel;
	uint_t	ill_index;
	boolean_t conn_dontroutex;
	boolean_t conn_multicast_loopx;
	boolean_t policy_present;

	ASSERT((ipha != NULL && ip6h == NULL) ||
	    (ip6h != NULL && ipha == NULL));

	bzero((void*)&sel, sizeof (sel));

	if (ipha != NULL)
		policy_present = ipsec_outbound_v4_policy_present;
	else
		policy_present = ipsec_outbound_v6_policy_present;
	/*
	 * Fast Path to see if there is any policy.
	 */
	if (!policy_present) {
		if (ipsec_mp->b_datap->db_type == M_CTL) {
			io = (ipsec_out_t *)ipsec_mp->b_rptr;
			if (!io->ipsec_out_secure) {
				/*
				 * If there is no global policy and ip_wput
				 * or ip_wput_multicast has attached this mp
				 * for multicast case, free the ipsec_mp and
				 * return the original mp.
				 */
				mp = ipsec_mp->b_cont;
				freeb(ipsec_mp);
				ipsec_mp = mp;
				io = NULL;
			}
		}
		if (((io == NULL) || (io->ipsec_out_polhead == NULL)) &&
		    ((connp == NULL) || (connp->conn_policy == NULL)))
			return (ipsec_mp);
	}

	ill_index = 0;
	conn_multicast_loopx = conn_dontroutex = B_FALSE;
	mp = ipsec_mp;
	if (ipsec_mp->b_datap->db_type == M_CTL) {
		mp = ipsec_mp->b_cont;
		/*
		 * This is a connection where we have some per-socket
		 * policy or ip_wput has attached an ipsec_mp for
		 * the multicast datagram.
		 */
		io = (ipsec_out_t *)ipsec_mp->b_rptr;
		if (!io->ipsec_out_secure) {
			/*
			 * This ipsec_mp was allocated in ip_wput or
			 * ip_wput_multicast so that we will know the
			 * value of ill_index, conn_dontroute,
			 * conn_multicast_loop in the multicast case if
			 * we inherit global policy here.
			 */
			ill_index = io->ipsec_out_ill_index;
			conn_dontroutex = io->ipsec_out_dontroute;
			conn_multicast_loopx = io->ipsec_out_multicast_loop;
			freeb(ipsec_mp);
			ipsec_mp = mp;
			io = NULL;
		}
	}

	if (ipha != NULL) {
		sel.ips_local_addr_v4 = (ipha->ipha_src != 0 ?
		    ipha->ipha_src : ire->ire_src_addr);
		sel.ips_remote_addr_v4 = ip_get_dst(ipha);
		sel.ips_protocol = (uint8_t)ipha->ipha_protocol;
		sel.ips_isv4 = B_TRUE;
	} else {
		ushort_t hdr_len;
		uint8_t	*nexthdrp;
		boolean_t is_fragment;

		sel.ips_isv4 = B_FALSE;
		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src)) {
			if (!unspec_src)
				sel.ips_local_addr_v6 = ire->ire_src_addr_v6;
		} else {
			sel.ips_local_addr_v6 = ip6h->ip6_src;
		}

		sel.ips_remote_addr_v6 = ip_get_dst_v6(ip6h, &is_fragment);
		if (is_fragment) {
			/*
			 * It's a packet fragment for a packet that
			 * we have already processed (since IPsec processing
			 * is done before fragmentation), so we don't
			 * have to do policy checks again. Fragments can
			 * come back to us for processing if they have
			 * been queued up due to flow control.
			 */
			if (ipsec_mp->b_datap->db_type == M_CTL) {
				mp = ipsec_mp->b_cont;
				freeb(ipsec_mp);
				ipsec_mp = mp;
			}
			return (ipsec_mp);
		}

		/* IPv6 common-case. */
		sel.ips_protocol = ip6h->ip6_nxt;
		switch (ip6h->ip6_nxt) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
		case IPPROTO_ICMPV6:
			break;
		default:
			if (!ip_hdr_length_nexthdr_v6(mp, ip6h,
			    &hdr_len, &nexthdrp)) {
				BUMP_MIB(&ip6_mib, ipv6OutDiscards);
				freemsg(ipsec_mp); /* Not IPsec-related drop. */
				return (NULL);
			}
			sel.ips_protocol = *nexthdrp;
			break;
		}
	}

	if (!ipsec_init_outbound_ports(&sel, mp, ipha, ip6h)) {
		if (ipha != NULL) {
			BUMP_MIB(&ip_mib, ipOutDiscards);
		} else {
			BUMP_MIB(&ip6_mib, ipv6OutDiscards);
		}

		ip_drop_packet(ipsec_mp, B_FALSE, NULL, NULL,
		    &ipdrops_spd_nomem, &spd_dropper);
		return (NULL);
	}

	if (io != NULL) {
		/*
		 * We seem to have some local policy (we already have
		 * an ipsec_out).  Look at global policy and see
		 * whether we have to inherit or not.
		 */
		io->ipsec_out_need_policy = B_FALSE;
		ipsec_mp = ipsec_apply_global_policy(ipsec_mp, connp, &sel);
		ASSERT((io->ipsec_out_policy != NULL) ||
		    (io->ipsec_out_act != NULL));
		ASSERT(io->ipsec_out_need_policy == B_FALSE);
		return (ipsec_mp);
	}
	ipsec_mp = ipsec_attach_global_policy(mp, connp, &sel);
	if (ipsec_mp == NULL)
		return (mp);

	/*
	 * Copy the right port information.
	 */
	ASSERT(ipsec_mp->b_datap->db_type == M_CTL);
	io = (ipsec_out_t *)ipsec_mp->b_rptr;

	ASSERT(io->ipsec_out_need_policy == B_FALSE);
	ASSERT((io->ipsec_out_policy != NULL) ||
	    (io->ipsec_out_act != NULL));
	io->ipsec_out_src_port = sel.ips_local_port;
	io->ipsec_out_dst_port = sel.ips_remote_port;
	io->ipsec_out_icmp_type = sel.ips_icmp_type;
	io->ipsec_out_icmp_code = sel.ips_icmp_code;
	/*
	 * Set ill_index, conn_dontroute and conn_multicast_loop
	 * for multicast datagrams.
	 */
	io->ipsec_out_ill_index = ill_index;
	io->ipsec_out_dontroute = conn_dontroutex;
	io->ipsec_out_multicast_loop = conn_multicast_loopx;
	/*
	 * When conn is non-NULL, the zoneid is set by ipsec_init_ipsec_out().
	 * Otherwise set the zoneid based on the ire.
	 */
	if (connp == NULL)
		io->ipsec_out_zoneid = ire->ire_zoneid;
	return (ipsec_mp);
}

/*
 * When appropriate, this function caches inbound and outbound policy
 * for this connection.
 *
 * XXX need to work out more details about per-interface policy and
 * caching here!
 *
 * XXX may want to split inbound and outbound caching for ill..
 */
int
ipsec_conn_cache_policy(conn_t *connp, boolean_t isv4)
{
	boolean_t global_policy_present;

	/*
	 * There is no policy latching for ICMP sockets because we can't
	 * decide on which policy to use until we see the packet and get
	 * type/code selectors.
	 */
	if (connp->conn_ulp == IPPROTO_ICMP ||
	    connp->conn_ulp == IPPROTO_ICMPV6) {
		connp->conn_in_enforce_policy =
		    connp->conn_out_enforce_policy = B_TRUE;
		if (connp->conn_latch != NULL) {
			IPLATCH_REFRELE(connp->conn_latch);
			connp->conn_latch = NULL;
		}
		connp->conn_flags |= IPCL_CHECK_POLICY;
		return (0);
	}

	global_policy_present = isv4 ?
	    (ipsec_outbound_v4_policy_present ||
		ipsec_inbound_v4_policy_present) :
	    (ipsec_outbound_v6_policy_present ||
		ipsec_inbound_v6_policy_present);

	if ((connp->conn_policy != NULL) || global_policy_present) {
		ipsec_selector_t sel;
		ipsec_policy_t	*p;

		if (connp->conn_latch == NULL &&
		    (connp->conn_latch = iplatch_create()) == NULL) {
			return (ENOMEM);
		}

		sel.ips_protocol = connp->conn_ulp;
		sel.ips_local_port = connp->conn_lport;
		sel.ips_remote_port = connp->conn_fport;
		sel.ips_is_icmp_inv_acq = 0;
		sel.ips_isv4 = isv4;
		if (isv4) {
			sel.ips_local_addr_v4 = connp->conn_src;
			sel.ips_remote_addr_v4 = connp->conn_rem;
		} else {
			sel.ips_local_addr_v6 = connp->conn_srcv6;
			sel.ips_remote_addr_v6 = connp->conn_remv6;
		}

		p = ipsec_find_policy(IPSEC_TYPE_INBOUND, connp, NULL, &sel);
		if (connp->conn_latch->ipl_in_policy != NULL)
			IPPOL_REFRELE(connp->conn_latch->ipl_in_policy);
		connp->conn_latch->ipl_in_policy = p;
		connp->conn_in_enforce_policy = (p != NULL);

		p = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, NULL, &sel);
		if (connp->conn_latch->ipl_out_policy != NULL)
			IPPOL_REFRELE(connp->conn_latch->ipl_out_policy);
		connp->conn_latch->ipl_out_policy = p;
		connp->conn_out_enforce_policy = (p != NULL);

		/* Clear the latched actions too, in case we're recaching. */
		if (connp->conn_latch->ipl_out_action != NULL)
			IPACT_REFRELE(connp->conn_latch->ipl_out_action);
		if (connp->conn_latch->ipl_in_action != NULL)
			IPACT_REFRELE(connp->conn_latch->ipl_in_action);
	}

	/*
	 * We may or may not have policy for this endpoint.  We still set
	 * conn_policy_cached so that inbound datagrams don't have to look
	 * at global policy as policy is considered latched for these
	 * endpoints.  We should not set conn_policy_cached until the conn
	 * reflects the actual policy. If we *set* this before inheriting
	 * the policy there is a window where the check
	 * CONN_INBOUND_POLICY_PRESENT, will neither check with the policy
	 * on the conn (because we have not yet copied the policy on to
	 * conn and hence not set conn_in_enforce_policy) nor with the
	 * global policy (because conn_policy_cached is already set).
	 */
	connp->conn_policy_cached = B_TRUE;
	if (connp->conn_in_enforce_policy)
		connp->conn_flags |= IPCL_CHECK_POLICY;
	return (0);
}

void
iplatch_free(ipsec_latch_t *ipl)
{
	if (ipl->ipl_out_policy != NULL)
		IPPOL_REFRELE(ipl->ipl_out_policy);
	if (ipl->ipl_in_policy != NULL)
		IPPOL_REFRELE(ipl->ipl_in_policy);
	if (ipl->ipl_in_action != NULL)
		IPACT_REFRELE(ipl->ipl_in_action);
	if (ipl->ipl_out_action != NULL)
		IPACT_REFRELE(ipl->ipl_out_action);
	if (ipl->ipl_local_cid != NULL)
		IPSID_REFRELE(ipl->ipl_local_cid);
	if (ipl->ipl_remote_cid != NULL)
		IPSID_REFRELE(ipl->ipl_remote_cid);
	if (ipl->ipl_local_id != NULL)
		crfree(ipl->ipl_local_id);
	mutex_destroy(&ipl->ipl_lock);
	kmem_free(ipl, sizeof (*ipl));
}

ipsec_latch_t *
iplatch_create()
{
	ipsec_latch_t *ipl = kmem_alloc(sizeof (*ipl), KM_NOSLEEP);
	if (ipl == NULL)
		return (ipl);
	bzero(ipl, sizeof (*ipl));
	mutex_init(&ipl->ipl_lock, NULL, MUTEX_DEFAULT, NULL);
	ipl->ipl_refcnt = 1;
	return (ipl);
}

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

ipsif_t ipsid_buckets[IPSID_HASHSIZE];

/*
 * Hash function for ID hash table.
 */
static uint32_t
ipsid_hash(int idtype, char *idstring)
{
	uint32_t hval = idtype;
	unsigned char c;

	while ((c = *idstring++) != 0) {
		hval = (hval << 4) | (hval >> 28);
		hval ^= c;
	}
	hval = hval ^ (hval >> 16);
	return (hval & (IPSID_HASHSIZE-1));
}

/*
 * Look up identity string in hash table.  Return identity object
 * corresponding to the name -- either preexisting, or newly allocated.
 *
 * Return NULL if we need to allocate a new one and can't get memory.
 */
ipsid_t *
ipsid_lookup(int idtype, char *idstring)
{
	ipsid_t *retval;
	char *nstr;
	int idlen = strlen(idstring) + 1;

	ipsif_t *bucket = &ipsid_buckets[ipsid_hash(idtype, idstring)];

	mutex_enter(&bucket->ipsif_lock);

	for (retval = bucket->ipsif_head; retval != NULL;
	    retval = retval->ipsid_next) {
		if (idtype != retval->ipsid_type)
			continue;
		if (bcmp(idstring, retval->ipsid_cid, idlen) != 0)
			continue;

		IPSID_REFHOLD(retval);
		mutex_exit(&bucket->ipsif_lock);
		return (retval);
	}

	retval = kmem_alloc(sizeof (*retval), KM_NOSLEEP);
	if (!retval) {
		mutex_exit(&bucket->ipsif_lock);
		return (NULL);
	}

	nstr = kmem_alloc(idlen, KM_NOSLEEP);
	if (!nstr) {
		mutex_exit(&bucket->ipsif_lock);
		kmem_free(retval, sizeof (*retval));
		return (NULL);
	}

	retval->ipsid_refcnt = 1;
	retval->ipsid_next = bucket->ipsif_head;
	if (retval->ipsid_next != NULL)
		retval->ipsid_next->ipsid_ptpn = &retval->ipsid_next;
	retval->ipsid_ptpn = &bucket->ipsif_head;
	retval->ipsid_type = idtype;
	retval->ipsid_cid = nstr;
	bucket->ipsif_head = retval;
	bcopy(idstring, nstr, idlen);
	mutex_exit(&bucket->ipsif_lock);

	return (retval);
}

/*
 * Garbage collect the identity hash table.
 */
void
ipsid_gc()
{
	int i, len;
	ipsid_t *id, *nid;
	ipsif_t *bucket;

	for (i = 0; i < IPSID_HASHSIZE; i++) {
		bucket = &ipsid_buckets[i];
		mutex_enter(&bucket->ipsif_lock);
		for (id = bucket->ipsif_head; id != NULL; id = nid) {
			nid = id->ipsid_next;
			if (id->ipsid_refcnt == 0) {
				*id->ipsid_ptpn = nid;
				if (nid != NULL)
					nid->ipsid_ptpn = id->ipsid_ptpn;
				len = strlen(id->ipsid_cid) + 1;
				kmem_free(id->ipsid_cid, len);
				kmem_free(id, sizeof (*id));
			}
		}
		mutex_exit(&bucket->ipsif_lock);
	}
}

/*
 * Return true if two identities are the same.
 */
boolean_t
ipsid_equal(ipsid_t *id1, ipsid_t *id2)
{
	if (id1 == id2)
		return (B_TRUE);
#ifdef DEBUG
	if ((id1 == NULL) || (id2 == NULL))
		return (B_FALSE);
	/*
	 * test that we're interning id's correctly..
	 */
	ASSERT((strcmp(id1->ipsid_cid, id2->ipsid_cid) != 0) ||
	    (id1->ipsid_type != id2->ipsid_type));
#endif
	return (B_FALSE);
}

/*
 * Initialize identity table; called during module initialization.
 */
static void
ipsid_init()
{
	ipsif_t *bucket;
	int i;

	for (i = 0; i < IPSID_HASHSIZE; i++) {
		bucket = &ipsid_buckets[i];
		mutex_init(&bucket->ipsif_lock, NULL, MUTEX_DEFAULT, NULL);
	}
}

/*
 * Free identity table (preparatory to module unload)
 */
static void
ipsid_fini()
{
	ipsif_t *bucket;
	int i;

	for (i = 0; i < IPSID_HASHSIZE; i++) {
		bucket = &ipsid_buckets[i];
		mutex_destroy(&bucket->ipsif_lock);
	}
}

/*
 * Update the minimum and maximum supported key sizes for the
 * specified algorithm. Must be called while holding the algorithms lock.
 */
void
ipsec_alg_fix_min_max(ipsec_alginfo_t *alg, ipsec_algtype_t alg_type)
{
	size_t crypto_min = (size_t)-1, crypto_max = 0;
	size_t cur_crypto_min, cur_crypto_max;
	boolean_t is_valid;
	crypto_mechanism_info_t *mech_infos;
	uint_t nmech_infos;
	int crypto_rc, i;
	crypto_mech_usage_t mask;

	ASSERT(MUTEX_HELD(&alg_lock));

	/*
	 * Compute the min, max, and default key sizes (in number of
	 * increments to the default key size in bits) as defined
	 * by the algorithm mappings. This range of key sizes is used
	 * for policy related operations. The effective key sizes
	 * supported by the framework could be more limited than
	 * those defined for an algorithm.
	 */
	alg->alg_default_bits = alg->alg_key_sizes[0];
	if (alg->alg_increment != 0) {
		/* key sizes are defined by range & increment */
		alg->alg_minbits = alg->alg_key_sizes[1];
		alg->alg_maxbits = alg->alg_key_sizes[2];

		alg->alg_default = SADB_ALG_DEFAULT_INCR(alg->alg_minbits,
		    alg->alg_increment, alg->alg_default_bits);
	} else if (alg->alg_nkey_sizes == 0) {
		/* no specified key size for algorithm */
		alg->alg_minbits = alg->alg_maxbits = 0;
	} else {
		/* key sizes are defined by enumeration */
		alg->alg_minbits = (uint16_t)-1;
		alg->alg_maxbits = 0;

		for (i = 0; i < alg->alg_nkey_sizes; i++) {
			if (alg->alg_key_sizes[i] < alg->alg_minbits)
				alg->alg_minbits = alg->alg_key_sizes[i];
			if (alg->alg_key_sizes[i] > alg->alg_maxbits)
				alg->alg_maxbits = alg->alg_key_sizes[i];
		}
		alg->alg_default = 0;
	}

	if (!(alg->alg_flags & ALG_FLAG_VALID))
		return;

	/*
	 * Mechanisms do not apply to the NULL encryption
	 * algorithm, so simply return for this case.
	 */
	if (alg->alg_id == SADB_EALG_NULL)
		return;

	/*
	 * Find the min and max key sizes supported by the cryptographic
	 * framework providers.
	 */

	/* get the key sizes supported by the framework */
	crypto_rc = crypto_get_all_mech_info(alg->alg_mech_type,
	    &mech_infos, &nmech_infos, KM_SLEEP);
	if (crypto_rc != CRYPTO_SUCCESS || nmech_infos == 0) {
		alg->alg_flags &= ~ALG_FLAG_VALID;
		return;
	}

	/* min and max key sizes supported by framework */
	for (i = 0, is_valid = B_FALSE; i < nmech_infos; i++) {
		int unit_bits;

		/*
		 * Ignore entries that do not support the operations
		 * needed for the algorithm type.
		 */
		if (alg_type == IPSEC_ALG_AUTH)
			mask = CRYPTO_MECH_USAGE_MAC;
		else
			mask = CRYPTO_MECH_USAGE_ENCRYPT |
				CRYPTO_MECH_USAGE_DECRYPT;
		if ((mech_infos[i].mi_usage & mask) != mask)
			continue;

		unit_bits = (mech_infos[i].mi_keysize_unit ==
		    CRYPTO_KEYSIZE_UNIT_IN_BYTES)  ? 8 : 1;
		/* adjust min/max supported by framework */
		cur_crypto_min = mech_infos[i].mi_min_key_size * unit_bits;
		cur_crypto_max = mech_infos[i].mi_max_key_size * unit_bits;

		if (cur_crypto_min < crypto_min)
			crypto_min = cur_crypto_min;

		/*
		 * CRYPTO_EFFECTIVELY_INFINITE is a special value of
		 * the crypto framework which means "no upper limit".
		 */
		if (mech_infos[i].mi_max_key_size ==
		    CRYPTO_EFFECTIVELY_INFINITE)
			crypto_max = (size_t)-1;
		else if (cur_crypto_max > crypto_max)
			crypto_max = cur_crypto_max;

		is_valid = B_TRUE;
	}

	kmem_free(mech_infos, sizeof (crypto_mechanism_info_t) *
	    nmech_infos);

	if (!is_valid) {
		/* no key sizes supported by framework */
		alg->alg_flags &= ~ALG_FLAG_VALID;
		return;
	}

	/*
	 * Determine min and max key sizes from alg_key_sizes[].
	 * defined for the algorithm entry. Adjust key sizes based on
	 * those supported by the framework.
	 */
	alg->alg_ef_default_bits = alg->alg_key_sizes[0];
	if (alg->alg_increment != 0) {
		/* supported key sizes are defined by range  & increment */
		crypto_min = ALGBITS_ROUND_UP(crypto_min, alg->alg_increment);
		crypto_max = ALGBITS_ROUND_DOWN(crypto_max, alg->alg_increment);

		alg->alg_ef_minbits = MAX(alg->alg_minbits,
		    (uint16_t)crypto_min);
		alg->alg_ef_maxbits = MIN(alg->alg_maxbits,
		    (uint16_t)crypto_max);

		/*
		 * If the sizes supported by the framework are outside
		 * the range of sizes defined by the algorithm mappings,
		 * the algorithm cannot be used. Check for this
		 * condition here.
		 */
		if (alg->alg_ef_minbits > alg->alg_ef_maxbits) {
			alg->alg_flags &= ~ALG_FLAG_VALID;
			return;
		}

		if (alg->alg_ef_default_bits < alg->alg_ef_minbits)
		    alg->alg_ef_default_bits = alg->alg_ef_minbits;
		if (alg->alg_ef_default_bits > alg->alg_ef_maxbits)
		    alg->alg_ef_default_bits = alg->alg_ef_maxbits;

		alg->alg_ef_default = SADB_ALG_DEFAULT_INCR(alg->alg_ef_minbits,
		    alg->alg_increment, alg->alg_ef_default_bits);
	} else if (alg->alg_nkey_sizes == 0) {
		/* no specified key size for algorithm */
		alg->alg_ef_minbits = alg->alg_ef_maxbits = 0;
	} else {
		/* supported key sizes are defined by enumeration */
		alg->alg_ef_minbits = (uint16_t)-1;
		alg->alg_ef_maxbits = 0;

		for (i = 0, is_valid = B_FALSE; i < alg->alg_nkey_sizes; i++) {
			/*
			 * Ignore the current key size if it is not in the
			 * range of sizes supported by the framework.
			 */
			if (alg->alg_key_sizes[i] < crypto_min ||
			    alg->alg_key_sizes[i] > crypto_max)
				continue;
			if (alg->alg_key_sizes[i] < alg->alg_ef_minbits)
				alg->alg_ef_minbits = alg->alg_key_sizes[i];
			if (alg->alg_key_sizes[i] > alg->alg_ef_maxbits)
				alg->alg_ef_maxbits = alg->alg_key_sizes[i];
			is_valid = B_TRUE;
		}

		if (!is_valid) {
			alg->alg_flags &= ~ALG_FLAG_VALID;
			return;
		}
		alg->alg_ef_default = 0;
	}
}

/*
 * Free the memory used by the specified algorithm.
 */
void
ipsec_alg_free(ipsec_alginfo_t *alg)
{
	if (alg == NULL)
		return;

	if (alg->alg_key_sizes != NULL)
		kmem_free(alg->alg_key_sizes,
		    (alg->alg_nkey_sizes + 1) * sizeof (uint16_t));

	if (alg->alg_block_sizes != NULL)
		kmem_free(alg->alg_block_sizes,
		    (alg->alg_nblock_sizes + 1) * sizeof (uint16_t));

	kmem_free(alg, sizeof (*alg));
}

/*
 * Check the validity of the specified key size for an algorithm.
 * Returns B_TRUE if key size is valid, B_FALSE otherwise.
 */
boolean_t
ipsec_valid_key_size(uint16_t key_size, ipsec_alginfo_t *alg)
{
	if (key_size < alg->alg_ef_minbits || key_size > alg->alg_ef_maxbits)
		return (B_FALSE);

	if (alg->alg_increment == 0 && alg->alg_nkey_sizes != 0) {
		/*
		 * If the key sizes are defined by enumeration, the new
		 * key size must be equal to one of the supported values.
		 */
		int i;

		for (i = 0; i < alg->alg_nkey_sizes; i++)
			if (key_size == alg->alg_key_sizes[i])
				break;
		if (i == alg->alg_nkey_sizes)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Callback function invoked by the crypto framework when a provider
 * registers or unregisters. This callback updates the algorithms
 * tables when a crypto algorithm is no longer available or becomes
 * available, and triggers the freeing/creation of context templates
 * associated with existing SAs, if needed.
 */
void
ipsec_prov_update_callback(uint32_t event, void *event_arg)
{
	crypto_notify_event_change_t *prov_change =
	    (crypto_notify_event_change_t *)event_arg;
	uint_t algidx, algid, algtype, mech_count, mech_idx;
	ipsec_alginfo_t *alg;
	ipsec_alginfo_t oalg;
	crypto_mech_name_t *mechs;
	boolean_t alg_changed = B_FALSE;

	/* ignore events for which we didn't register */
	if (event != CRYPTO_EVENT_PROVIDERS_CHANGE) {
		ip1dbg(("ipsec_prov_update_callback: unexpected event 0x%x "
			" received from crypto framework\n", event));
		return;
	}

	mechs = crypto_get_mech_list(&mech_count, KM_SLEEP);
	if (mechs == NULL)
		return;

	/*
	 * Walk the list of currently defined IPsec algorithm. Update
	 * the algorithm valid flag and trigger an update of the
	 * SAs that depend on that algorithm.
	 */
	mutex_enter(&alg_lock);
	for (algtype = 0; algtype < IPSEC_NALGTYPES; algtype++) {
		for (algidx = 0; algidx < ipsec_nalgs[algtype]; algidx++) {

			algid = ipsec_sortlist[algtype][algidx];
			alg = ipsec_alglists[algtype][algid];
			ASSERT(alg != NULL);

			/*
			 * Skip the algorithms which do not map to the
			 * crypto framework provider being added or removed.
			 */
			if (strncmp(alg->alg_mech_name,
			    prov_change->ec_mech_name,
			    CRYPTO_MAX_MECH_NAME) != 0)
				continue;

			/*
			 * Determine if the mechanism is valid. If it
			 * is not, mark the algorithm as being invalid. If
			 * it is, mark the algorithm as being valid.
			 */
			for (mech_idx = 0; mech_idx < mech_count; mech_idx++)
				if (strncmp(alg->alg_mech_name,
				    mechs[mech_idx], CRYPTO_MAX_MECH_NAME) == 0)
					break;
			if (mech_idx == mech_count &&
			    alg->alg_flags & ALG_FLAG_VALID) {
				alg->alg_flags &= ~ALG_FLAG_VALID;
				alg_changed = B_TRUE;
			} else if (mech_idx < mech_count &&
			    !(alg->alg_flags & ALG_FLAG_VALID)) {
				alg->alg_flags |= ALG_FLAG_VALID;
				alg_changed = B_TRUE;
			}

			/*
			 * Update the supported key sizes, regardless
			 * of whether a crypto provider was added or
			 * removed.
			 */
			oalg = *alg;
			ipsec_alg_fix_min_max(alg, algtype);
			if (!alg_changed &&
			    alg->alg_ef_minbits != oalg.alg_ef_minbits ||
			    alg->alg_ef_maxbits != oalg.alg_ef_maxbits ||
			    alg->alg_ef_default != oalg.alg_ef_default ||
			    alg->alg_ef_default_bits !=
			    oalg.alg_ef_default_bits)
				alg_changed = B_TRUE;

			/*
			 * Update the affected SAs if a software provider is
			 * being added or removed.
			 */
			if (prov_change->ec_provider_type ==
			    CRYPTO_SW_PROVIDER)
				sadb_alg_update(algtype, alg->alg_id,
				    prov_change->ec_change ==
				    CRYPTO_EVENT_CHANGE_ADDED);
		}
	}
	mutex_exit(&alg_lock);
	crypto_free_mech_list(mechs, mech_count);

	if (alg_changed) {
		/*
		 * An algorithm has changed, i.e. it became valid or
		 * invalid, or its support key sizes have changed.
		 * Notify ipsecah and ipsecesp of this change so
		 * that they can send a SADB_REGISTER to their consumers.
		 */
		ipsecah_algs_changed();
		ipsecesp_algs_changed();
	}
}

/*
 * Registers with the crypto framework to be notified of crypto
 * providers changes. Used to update the algorithm tables and
 * to free or create context templates if needed. Invoked after IPsec
 * is loaded successfully.
 */
void
ipsec_register_prov_update(void)
{
	prov_update_handle = crypto_notify_events(
	    ipsec_prov_update_callback, CRYPTO_EVENT_PROVIDERS_CHANGE);
}

/*
 * Unregisters from the framework to be notified of crypto providers
 * changes. Called from ipsec_policy_destroy().
 */
static void
ipsec_unregister_prov_update(void)
{
	if (prov_update_handle != NULL)
		crypto_unnotify_events(prov_update_handle);
}
