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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <sys/strsun.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/ddi.h>

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
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>

#include <inet/ip_impl.h>	/* For IP_MOD_ID */

#include <inet/ipsecah.h>
#include <inet/ipsecesp.h>
#include <inet/ipdrop.h>
#include <inet/ipclassifier.h>
#include <inet/iptun.h>
#include <inet/iptun/iptun_impl.h>

static void ipsec_update_present_flags(ipsec_stack_t *);
static ipsec_act_t *ipsec_act_wildcard_expand(ipsec_act_t *, uint_t *,
    netstack_t *);
static mblk_t *ipsec_check_ipsecin_policy(mblk_t *, ipsec_policy_t *,
    ipha_t *, ip6_t *, uint64_t, ip_recv_attr_t *, netstack_t *);
static void ipsec_action_free_table(ipsec_action_t *);
static void ipsec_action_reclaim(void *);
static void ipsec_action_reclaim_stack(ipsec_stack_t *);
static void ipsid_init(netstack_t *);
static void ipsid_fini(netstack_t *);

/* sel_flags values for ipsec_init_inbound_sel(). */
#define	SEL_NONE	0x0000
#define	SEL_PORT_POLICY	0x0001
#define	SEL_IS_ICMP	0x0002
#define	SEL_TUNNEL_MODE	0x0004
#define	SEL_POST_FRAG	0x0008

/* Return values for ipsec_init_inbound_sel(). */
typedef enum { SELRET_NOMEM, SELRET_BADPKT, SELRET_SUCCESS, SELRET_TUNFRAG}
    selret_t;

static selret_t ipsec_init_inbound_sel(ipsec_selector_t *, mblk_t *,
    ipha_t *, ip6_t *, uint8_t);

static boolean_t ipsec_check_ipsecin_action(ip_recv_attr_t *, mblk_t *,
    struct ipsec_action_s *, ipha_t *ipha, ip6_t *ip6h, const char **,
    kstat_named_t **, netstack_t *);
static void ipsec_unregister_prov_update(void);
static void ipsec_prov_update_callback_stack(uint32_t, void *, netstack_t *);
static boolean_t ipsec_compare_action(ipsec_policy_t *, ipsec_policy_t *);
static uint32_t selector_hash(ipsec_selector_t *, ipsec_policy_root_t *);
static boolean_t ipsec_kstat_init(ipsec_stack_t *);
static void ipsec_kstat_destroy(ipsec_stack_t *);
static int ipsec_free_tables(ipsec_stack_t *);
static int tunnel_compare(const void *, const void *);
static void ipsec_freemsg_chain(mblk_t *);
static void ip_drop_packet_chain(mblk_t *, boolean_t, ill_t *,
    struct kstat_named *, ipdropper_t *);
static boolean_t ipsec_kstat_init(ipsec_stack_t *);
static void ipsec_kstat_destroy(ipsec_stack_t *);
static int ipsec_free_tables(ipsec_stack_t *);
static int tunnel_compare(const void *, const void *);
static void ipsec_freemsg_chain(mblk_t *);

/*
 * Selector hash table is statically sized at module load time.
 * we default to 251 buckets, which is the largest prime number under 255
 */

#define	IPSEC_SPDHASH_DEFAULT 251

/* SPD hash-size tunable per tunnel. */
#define	TUN_SPDHASH_DEFAULT 5

uint32_t ipsec_spd_hashsize;
uint32_t tun_spd_hashsize;

#define	IPSEC_SEL_NOHASH ((uint32_t)(~0))

/*
 * Handle global across all stack instances
 */
static crypto_notify_handle_t prov_update_handle = NULL;

static kmem_cache_t *ipsec_action_cache;
static kmem_cache_t *ipsec_sel_cache;
static kmem_cache_t *ipsec_pol_cache;

/* Frag cache prototypes */
static void ipsec_fragcache_clean(ipsec_fragcache_t *, ipsec_stack_t *);
static ipsec_fragcache_entry_t *fragcache_delentry(int,
    ipsec_fragcache_entry_t *, ipsec_fragcache_t *, ipsec_stack_t *);
boolean_t ipsec_fragcache_init(ipsec_fragcache_t *);
void ipsec_fragcache_uninit(ipsec_fragcache_t *, ipsec_stack_t *ipss);
mblk_t *ipsec_fragcache_add(ipsec_fragcache_t *, mblk_t *, mblk_t *,
    int, ipsec_stack_t *);

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

/*
 * IPv6 Fragments
 */
#define	IS_V6_FRAGMENT(ipp)	(ipp.ipp_fields & IPPF_FRAGHDR)

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
 * General overviews:
 *
 * Locking:
 *
 *	All of the system policy structures are protected by a single
 *	rwlock.  These structures are threaded in a
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

/* Convenient functions for freeing or dropping a b_next linked mblk chain */

/* Free all messages in an mblk chain */
static void
ipsec_freemsg_chain(mblk_t *mp)
{
	mblk_t *mpnext;
	while (mp != NULL) {
		ASSERT(mp->b_prev == NULL);
		mpnext = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
		mp = mpnext;
	}
}

/*
 * ip_drop all messages in an mblk chain
 * Can handle a b_next chain of ip_recv_attr_t mblks, or just a b_next chain
 * of data.
 */
static void
ip_drop_packet_chain(mblk_t *mp, boolean_t inbound, ill_t *ill,
    struct kstat_named *counter, ipdropper_t *who_called)
{
	mblk_t *mpnext;
	while (mp != NULL) {
		ASSERT(mp->b_prev == NULL);
		mpnext = mp->b_next;
		mp->b_next = NULL;
		if (ip_recv_attr_is_mblk(mp))
			mp = ip_recv_attr_free_mblk(mp);
		ip_drop_packet(mp, inbound, ill, counter, who_called);
		mp = mpnext;
	}
}

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
	 * a placeholder in the ordering just before the first entry with
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

/*
 * Free what ipsec_alloc_table allocated.
 */
void
ipsec_polhead_free_table(ipsec_policy_head_t *iph)
{
	int dir;
	int i;

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &iph->iph_root[dir];

		if (ipr->ipr_hash == NULL)
			continue;

		for (i = 0; i < ipr->ipr_nchains; i++) {
			ASSERT(ipr->ipr_hash[i].hash_head == NULL);
		}
		kmem_free(ipr->ipr_hash, ipr->ipr_nchains *
		    sizeof (ipsec_policy_hash_t));
		ipr->ipr_hash = NULL;
	}
}

void
ipsec_polhead_destroy(ipsec_policy_head_t *iph)
{
	int dir;

	avl_destroy(&iph->iph_rulebyid);
	rw_destroy(&iph->iph_lock);

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &iph->iph_root[dir];
		int chain;

		for (chain = 0; chain < ipr->ipr_nchains; chain++)
			mutex_destroy(&(ipr->ipr_hash[chain].hash_lock));

	}
	ipsec_polhead_free_table(iph);
}

/*
 * Free the IPsec stack instance.
 */
/* ARGSUSED */
static void
ipsec_stack_fini(netstackid_t stackid, void *arg)
{
	ipsec_stack_t	*ipss = (ipsec_stack_t *)arg;
	void *cookie;
	ipsec_tun_pol_t *node;
	netstack_t	*ns = ipss->ipsec_netstack;
	int		i;
	ipsec_algtype_t	algtype;

	ipsec_loader_destroy(ipss);

	rw_enter(&ipss->ipsec_tunnel_policy_lock, RW_WRITER);
	/*
	 * It's possible we can just ASSERT() the tree is empty.  After all,
	 * we aren't called until IP is ready to unload (and presumably all
	 * tunnels have been unplumbed).  But we'll play it safe for now, the
	 * loop will just exit immediately if it's empty.
	 */
	cookie = NULL;
	while ((node = (ipsec_tun_pol_t *)
	    avl_destroy_nodes(&ipss->ipsec_tunnel_policies,
	    &cookie)) != NULL) {
		ITP_REFRELE(node, ns);
	}
	avl_destroy(&ipss->ipsec_tunnel_policies);
	rw_exit(&ipss->ipsec_tunnel_policy_lock);
	rw_destroy(&ipss->ipsec_tunnel_policy_lock);

	ipsec_config_flush(ns);

	ipsec_kstat_destroy(ipss);

	ip_drop_unregister(&ipss->ipsec_dropper);

	ip_drop_unregister(&ipss->ipsec_spd_dropper);
	ip_drop_destroy(ipss);
	/*
	 * Globals start with ref == 1 to prevent IPPH_REFRELE() from
	 * attempting to free them, hence they should have 1 now.
	 */
	ipsec_polhead_destroy(&ipss->ipsec_system_policy);
	ASSERT(ipss->ipsec_system_policy.iph_refs == 1);
	ipsec_polhead_destroy(&ipss->ipsec_inactive_policy);
	ASSERT(ipss->ipsec_inactive_policy.iph_refs == 1);

	for (i = 0; i < IPSEC_ACTION_HASH_SIZE; i++) {
		ipsec_action_free_table(ipss->ipsec_action_hash[i].hash_head);
		ipss->ipsec_action_hash[i].hash_head = NULL;
		mutex_destroy(&(ipss->ipsec_action_hash[i].hash_lock));
	}

	for (i = 0; i < ipss->ipsec_spd_hashsize; i++) {
		ASSERT(ipss->ipsec_sel_hash[i].hash_head == NULL);
		mutex_destroy(&(ipss->ipsec_sel_hash[i].hash_lock));
	}

	mutex_enter(&ipss->ipsec_alg_lock);
	for (algtype = 0; algtype < IPSEC_NALGTYPES; algtype ++) {
		int nalgs = ipss->ipsec_nalgs[algtype];

		for (i = 0; i < nalgs; i++) {
			if (ipss->ipsec_alglists[algtype][i] != NULL)
				ipsec_alg_unreg(algtype, i, ns);
		}
	}
	mutex_exit(&ipss->ipsec_alg_lock);
	mutex_destroy(&ipss->ipsec_alg_lock);

	ipsid_gc(ns);
	ipsid_fini(ns);

	(void) ipsec_free_tables(ipss);
	kmem_free(ipss, sizeof (*ipss));
}

void
ipsec_policy_g_destroy(void)
{
	kmem_cache_destroy(ipsec_action_cache);
	kmem_cache_destroy(ipsec_sel_cache);
	kmem_cache_destroy(ipsec_pol_cache);

	ipsec_unregister_prov_update();

	netstack_unregister(NS_IPSEC);
}


/*
 * Free what ipsec_alloc_tables allocated.
 * Called when table allocation fails to free the table.
 */
static int
ipsec_free_tables(ipsec_stack_t *ipss)
{
	int i;

	if (ipss->ipsec_sel_hash != NULL) {
		for (i = 0; i < ipss->ipsec_spd_hashsize; i++) {
			ASSERT(ipss->ipsec_sel_hash[i].hash_head == NULL);
		}
		kmem_free(ipss->ipsec_sel_hash, ipss->ipsec_spd_hashsize *
		    sizeof (*ipss->ipsec_sel_hash));
		ipss->ipsec_sel_hash = NULL;
		ipss->ipsec_spd_hashsize = 0;
	}
	ipsec_polhead_free_table(&ipss->ipsec_system_policy);
	ipsec_polhead_free_table(&ipss->ipsec_inactive_policy);

	return (ENOMEM);
}

/*
 * Attempt to allocate the tables in a single policy head.
 * Return nonzero on failure after cleaning up any work in progress.
 */
int
ipsec_alloc_table(ipsec_policy_head_t *iph, int nchains, int kmflag,
    boolean_t global_cleanup, netstack_t *ns)
{
	int dir;

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &iph->iph_root[dir];

		ipr->ipr_nchains = nchains;
		ipr->ipr_hash = kmem_zalloc(nchains *
		    sizeof (ipsec_policy_hash_t), kmflag);
		if (ipr->ipr_hash == NULL)
			return (global_cleanup ?
			    ipsec_free_tables(ns->netstack_ipsec) :
			    ENOMEM);
	}
	return (0);
}

/*
 * Attempt to allocate the various tables.  Return nonzero on failure
 * after cleaning up any work in progress.
 */
static int
ipsec_alloc_tables(int kmflag, netstack_t *ns)
{
	int error;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	error = ipsec_alloc_table(&ipss->ipsec_system_policy,
	    ipss->ipsec_spd_hashsize, kmflag, B_TRUE, ns);
	if (error != 0)
		return (error);

	error = ipsec_alloc_table(&ipss->ipsec_inactive_policy,
	    ipss->ipsec_spd_hashsize, kmflag, B_TRUE, ns);
	if (error != 0)
		return (error);

	ipss->ipsec_sel_hash = kmem_zalloc(ipss->ipsec_spd_hashsize *
	    sizeof (*ipss->ipsec_sel_hash), kmflag);

	if (ipss->ipsec_sel_hash == NULL)
		return (ipsec_free_tables(ipss));

	return (0);
}

/*
 * After table allocation, initialize a policy head.
 */
void
ipsec_polhead_init(ipsec_policy_head_t *iph, int nchains)
{
	int dir, chain;

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

static boolean_t
ipsec_kstat_init(ipsec_stack_t *ipss)
{
	ipss->ipsec_ksp = kstat_create_netstack("ip", 0, "ipsec_stat", "net",
	    KSTAT_TYPE_NAMED, sizeof (ipsec_kstats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT, ipss->ipsec_netstack->netstack_stackid);

	if (ipss->ipsec_ksp == NULL || ipss->ipsec_ksp->ks_data == NULL)
		return (B_FALSE);

	ipss->ipsec_kstats = ipss->ipsec_ksp->ks_data;

#define	KI(x) kstat_named_init(&ipss->ipsec_kstats->x, #x, KSTAT_DATA_UINT64)
	KI(esp_stat_in_requests);
	KI(esp_stat_in_discards);
	KI(esp_stat_lookup_failure);
	KI(ah_stat_in_requests);
	KI(ah_stat_in_discards);
	KI(ah_stat_lookup_failure);
	KI(sadb_acquire_maxpackets);
	KI(sadb_acquire_qhiwater);
#undef KI

	kstat_install(ipss->ipsec_ksp);
	return (B_TRUE);
}

static void
ipsec_kstat_destroy(ipsec_stack_t *ipss)
{
	kstat_delete_netstack(ipss->ipsec_ksp,
	    ipss->ipsec_netstack->netstack_stackid);
	ipss->ipsec_kstats = NULL;

}

/*
 * Initialize the IPsec stack instance.
 */
/* ARGSUSED */
static void *
ipsec_stack_init(netstackid_t stackid, netstack_t *ns)
{
	ipsec_stack_t	*ipss;
	int i;

	ipss = (ipsec_stack_t *)kmem_zalloc(sizeof (*ipss), KM_SLEEP);
	ipss->ipsec_netstack = ns;

	/*
	 * FIXME: netstack_ipsec is used by some of the routines we call
	 * below, but it isn't set until this routine returns.
	 * Either we introduce optional xxx_stack_alloc() functions
	 * that will be called by the netstack framework before xxx_stack_init,
	 * or we switch spd.c and sadb.c to operate on ipsec_stack_t
	 * (latter has some include file order issues for sadb.h, but makes
	 * sense if we merge some of the ipsec related stack_t's together.
	 */
	ns->netstack_ipsec = ipss;

	/*
	 * Make two attempts to allocate policy hash tables; try it at
	 * the "preferred" size (may be set in /etc/system) first,
	 * then fall back to the default size.
	 */
	ipss->ipsec_spd_hashsize = (ipsec_spd_hashsize == 0) ?
	    IPSEC_SPDHASH_DEFAULT : ipsec_spd_hashsize;

	if (ipsec_alloc_tables(KM_NOSLEEP, ns) != 0) {
		cmn_err(CE_WARN,
		    "Unable to allocate %d entry IPsec policy hash table",
		    ipss->ipsec_spd_hashsize);
		ipss->ipsec_spd_hashsize = IPSEC_SPDHASH_DEFAULT;
		cmn_err(CE_WARN, "Falling back to %d entries",
		    ipss->ipsec_spd_hashsize);
		(void) ipsec_alloc_tables(KM_SLEEP, ns);
	}

	/* Just set a default for tunnels. */
	ipss->ipsec_tun_spd_hashsize = (tun_spd_hashsize == 0) ?
	    TUN_SPDHASH_DEFAULT : tun_spd_hashsize;

	ipsid_init(ns);
	/*
	 * Globals need ref == 1 to prevent IPPH_REFRELE() from attempting
	 * to free them.
	 */
	ipss->ipsec_system_policy.iph_refs = 1;
	ipss->ipsec_inactive_policy.iph_refs = 1;
	ipsec_polhead_init(&ipss->ipsec_system_policy,
	    ipss->ipsec_spd_hashsize);
	ipsec_polhead_init(&ipss->ipsec_inactive_policy,
	    ipss->ipsec_spd_hashsize);
	rw_init(&ipss->ipsec_tunnel_policy_lock, NULL, RW_DEFAULT, NULL);
	avl_create(&ipss->ipsec_tunnel_policies, tunnel_compare,
	    sizeof (ipsec_tun_pol_t), 0);

	ipss->ipsec_next_policy_index = 1;

	rw_init(&ipss->ipsec_system_policy.iph_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&ipss->ipsec_inactive_policy.iph_lock, NULL, RW_DEFAULT, NULL);

	for (i = 0; i < IPSEC_ACTION_HASH_SIZE; i++)
		mutex_init(&(ipss->ipsec_action_hash[i].hash_lock),
		    NULL, MUTEX_DEFAULT, NULL);

	for (i = 0; i < ipss->ipsec_spd_hashsize; i++)
		mutex_init(&(ipss->ipsec_sel_hash[i].hash_lock),
		    NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&ipss->ipsec_alg_lock, NULL, MUTEX_DEFAULT, NULL);
	for (i = 0; i < IPSEC_NALGTYPES; i++) {
		ipss->ipsec_nalgs[i] = 0;
	}

	ip_drop_init(ipss);
	ip_drop_register(&ipss->ipsec_spd_dropper, "IPsec SPD");

	/* IP's IPsec code calls the packet dropper */
	ip_drop_register(&ipss->ipsec_dropper, "IP IPsec processing");

	(void) ipsec_kstat_init(ipss);

	ipsec_loader_init(ipss);
	ipsec_loader_start(ipss);

	return (ipss);
}

/* Global across all stack instances */
void
ipsec_policy_g_init(void)
{
	ipsec_action_cache = kmem_cache_create("ipsec_actions",
	    sizeof (ipsec_action_t), _POINTER_ALIGNMENT, NULL, NULL,
	    ipsec_action_reclaim, NULL, NULL, 0);
	ipsec_sel_cache = kmem_cache_create("ipsec_selectors",
	    sizeof (ipsec_sel_t), _POINTER_ALIGNMENT, NULL, NULL,
	    NULL, NULL, NULL, 0);
	ipsec_pol_cache = kmem_cache_create("ipsec_policy",
	    sizeof (ipsec_policy_t), _POINTER_ALIGNMENT, NULL, NULL,
	    NULL, NULL, NULL, 0);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of ipsec_stack_t's.
	 */
	netstack_register(NS_IPSEC, ipsec_stack_init, NULL, ipsec_stack_fini);
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
alg_insert_sortlist(enum ipsec_algtype at, uint8_t algid, netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ipsec_alginfo_t *ai = ipss->ipsec_alglists[at][algid];
	uint8_t holder, swap;
	uint_t i;
	uint_t count = ipss->ipsec_nalgs[at];
	ASSERT(ai != NULL);
	ASSERT(algid == ai->alg_id);

	ASSERT(MUTEX_HELD(&ipss->ipsec_alg_lock));

	holder = algid;

	for (i = 0; i < count - 1; i++) {
		ipsec_alginfo_t *alt;

		alt = ipss->ipsec_alglists[at][ipss->ipsec_sortlist[at][i]];
		/*
		 * If you want to give precedence to newly added algs,
		 * add the = in the > comparison.
		 */
		if ((holder != algid) || (ai->alg_minbits > alt->alg_minbits)) {
			/* Swap sortlist[i] and holder. */
			swap = ipss->ipsec_sortlist[at][i];
			ipss->ipsec_sortlist[at][i] = holder;
			holder = swap;
			ai = alt;
		} /* Else just continue. */
	}

	/* Store holder in last slot. */
	ipss->ipsec_sortlist[at][i] = holder;
}

/*
 * Remove an algorithm from a sorted algorithm list.
 * This should be considerably easier, even with complex sorting.
 */
static void
alg_remove_sortlist(enum ipsec_algtype at, uint8_t algid, netstack_t *ns)
{
	boolean_t copyback = B_FALSE;
	int i;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	int newcount = ipss->ipsec_nalgs[at];

	ASSERT(MUTEX_HELD(&ipss->ipsec_alg_lock));

	for (i = 0; i <= newcount; i++) {
		if (copyback) {
			ipss->ipsec_sortlist[at][i-1] =
			    ipss->ipsec_sortlist[at][i];
		} else if (ipss->ipsec_sortlist[at][i] == algid) {
			copyback = B_TRUE;
		}
	}
}

/*
 * Add the specified algorithm to the algorithm tables.
 * Must be called while holding the algorithm table writer lock.
 */
void
ipsec_alg_reg(ipsec_algtype_t algtype, ipsec_alginfo_t *alg, netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(MUTEX_HELD(&ipss->ipsec_alg_lock));

	ASSERT(ipss->ipsec_alglists[algtype][alg->alg_id] == NULL);
	ipsec_alg_fix_min_max(alg, algtype, ns);
	ipss->ipsec_alglists[algtype][alg->alg_id] = alg;

	ipss->ipsec_nalgs[algtype]++;
	alg_insert_sortlist(algtype, alg->alg_id, ns);
}

/*
 * Remove the specified algorithm from the algorithm tables.
 * Must be called while holding the algorithm table writer lock.
 */
void
ipsec_alg_unreg(ipsec_algtype_t algtype, uint8_t algid, netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(MUTEX_HELD(&ipss->ipsec_alg_lock));

	ASSERT(ipss->ipsec_alglists[algtype][algid] != NULL);
	ipsec_alg_free(ipss->ipsec_alglists[algtype][algid]);
	ipss->ipsec_alglists[algtype][algid] = NULL;

	ipss->ipsec_nalgs[algtype]--;
	alg_remove_sortlist(algtype, algid, ns);
}

/*
 * Hooks for spdsock to get a grip on system policy.
 */

ipsec_policy_head_t *
ipsec_system_policy(netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ipsec_policy_head_t *h = &ipss->ipsec_system_policy;

	IPPH_REFHOLD(h);
	return (h);
}

ipsec_policy_head_t *
ipsec_inactive_policy(netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ipsec_policy_head_t *h = &ipss->ipsec_inactive_policy;

	IPPH_REFHOLD(h);
	return (h);
}

/*
 * Lock inactive policy, then active policy, then exchange policy root
 * pointers.
 */
void
ipsec_swap_policy(ipsec_policy_head_t *active, ipsec_policy_head_t *inactive,
    netstack_t *ns)
{
	int af, dir;
	avl_tree_t r1, r2;

	rw_enter(&inactive->iph_lock, RW_WRITER);
	rw_enter(&active->iph_lock, RW_WRITER);

	r1 = active->iph_rulebyid;
	r2 = inactive->iph_rulebyid;
	active->iph_rulebyid = r2;
	inactive->iph_rulebyid = r1;

	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_hash_t *h1, *h2;

		h1 = active->iph_root[dir].ipr_hash;
		h2 = inactive->iph_root[dir].ipr_hash;
		active->iph_root[dir].ipr_hash = h2;
		inactive->iph_root[dir].ipr_hash = h1;

		for (af = 0; af < IPSEC_NAF; af++) {
			ipsec_policy_t *t1, *t2;

			t1 = active->iph_root[dir].ipr_nonhash[af];
			t2 = inactive->iph_root[dir].ipr_nonhash[af];
			active->iph_root[dir].ipr_nonhash[af] = t2;
			inactive->iph_root[dir].ipr_nonhash[af] = t1;
			if (t1 != NULL) {
				t1->ipsp_hash.hash_pp =
				    &(inactive->iph_root[dir].ipr_nonhash[af]);
			}
			if (t2 != NULL) {
				t2->ipsp_hash.hash_pp =
				    &(active->iph_root[dir].ipr_nonhash[af]);
			}

		}
	}
	active->iph_gen++;
	inactive->iph_gen++;
	ipsec_update_present_flags(ns->netstack_ipsec);
	rw_exit(&active->iph_lock);
	rw_exit(&inactive->iph_lock);
}

/*
 * Swap global policy primary/secondary.
 */
void
ipsec_swap_global_policy(netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ipsec_swap_policy(&ipss->ipsec_system_policy,
	    &ipss->ipsec_inactive_policy, ns);
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
	dst->ipsp_netstack = src->ipsp_netstack;
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
int
ipsec_copy_polhead(ipsec_policy_head_t *sph, ipsec_policy_head_t *dph,
    netstack_t *ns)
{
	int af, dir, chain, nchains;

	rw_enter(&dph->iph_lock, RW_WRITER);

	ipsec_polhead_flush(dph, ns);

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
	ipsec_polhead_flush(dph, ns);
	rw_exit(&sph->iph_lock);
	rw_exit(&dph->iph_lock);
	return (ENOMEM);
}

/*
 * Clone currently active policy to the inactive policy list.
 */
int
ipsec_clone_system_policy(netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	return (ipsec_copy_polhead(&ipss->ipsec_system_policy,
	    &ipss->ipsec_inactive_policy, ns));
}

/*
 * Extract the string from ipsec_policy_failure_msgs[type] and
 * log it.
 *
 */
void
ipsec_log_policy_failure(int type, char *func_name, ipha_t *ipha, ip6_t *ip6h,
    boolean_t secure, netstack_t *ns)
{
	char	sbuf[INET6_ADDRSTRLEN];
	char	dbuf[INET6_ADDRSTRLEN];
	char	*s;
	char	*d;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

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
	ipss->ipsec_policy_failure_count[type]++;

	ipsec_rl_strlog(ns, IP_MOD_ID, 0, 0, SL_ERROR|SL_WARN|SL_CONSOLE,
	    ipsec_policy_failure_msgs[type], func_name,
	    (secure ? "secure" : "not secure"), s, d);
}

/*
 * Rate-limiting front-end to strlog() for AH and ESP.	Uses the ndd variables
 * in /dev/ip and the same rate-limiting clock so that there's a single
 * knob to turn to throttle the rate of messages.
 */
void
ipsec_rl_strlog(netstack_t *ns, short mid, short sid, char level, ushort_t sl,
    char *fmt, ...)
{
	va_list adx;
	hrtime_t current = gethrtime();
	ip_stack_t	*ipst = ns->netstack_ip;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	sl |= SL_CONSOLE;
	/*
	 * Throttle logging to stop syslog from being swamped. If variable
	 * 'ipsec_policy_log_interval' is zero, don't log any messages at
	 * all, otherwise log only one message every 'ipsec_policy_log_interval'
	 * msec. Convert interval (in msec) to hrtime (in nsec).
	 */

	if (ipst->ips_ipsec_policy_log_interval) {
		if (ipss->ipsec_policy_failure_last +
		    MSEC2NSEC(ipst->ips_ipsec_policy_log_interval) <= current) {
			va_start(adx, fmt);
			(void) vstrlog(mid, sid, level, sl, fmt, adx);
			va_end(adx);
			ipss->ipsec_policy_failure_last = current;
		}
	}
}

void
ipsec_config_flush(netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	rw_enter(&ipss->ipsec_system_policy.iph_lock, RW_WRITER);
	ipsec_polhead_flush(&ipss->ipsec_system_policy, ns);
	ipss->ipsec_next_policy_index = 1;
	rw_exit(&ipss->ipsec_system_policy.iph_lock);
	ipsec_action_reclaim_stack(ipss);
}

/*
 * Clip a policy's min/max keybits vs. the capabilities of the
 * algorithm.
 */
static void
act_alg_adjust(uint_t algtype, uint_t algid,
    uint16_t *minbits, uint16_t *maxbits, netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ipsec_alginfo_t *algp = ipss->ipsec_alglists[algtype][algid];

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
			*minbits = MAX(MIN(*minbits, algp->alg_maxbits),
			    algp->alg_minbits);
		}
		if (*maxbits == 0)
			*maxbits = algp->alg_maxbits;
		else
			*maxbits = MIN(MAX(*maxbits, algp->alg_minbits),
			    algp->alg_maxbits);
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
ipsec_check_action(ipsec_act_t *act, int *diag, netstack_t *ns)
{
	ipsec_prot_t *ipp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ipp = &act->ipa_apply;

	if (ipp->ipp_use_ah &&
	    ipss->ipsec_alglists[IPSEC_ALG_AUTH][ipp->ipp_auth_alg] == NULL) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_AH_ALG;
		return (B_FALSE);
	}
	if (ipp->ipp_use_espa &&
	    ipss->ipsec_alglists[IPSEC_ALG_AUTH][ipp->ipp_esp_auth_alg] ==
	    NULL) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_ALG;
		return (B_FALSE);
	}
	if (ipp->ipp_use_esp &&
	    ipss->ipsec_alglists[IPSEC_ALG_ENCR][ipp->ipp_encr_alg] == NULL) {
		*diag = SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_ALG;
		return (B_FALSE);
	}

	act_alg_adjust(IPSEC_ALG_AUTH, ipp->ipp_auth_alg,
	    &ipp->ipp_ah_minbits, &ipp->ipp_ah_maxbits, ns);
	act_alg_adjust(IPSEC_ALG_AUTH, ipp->ipp_esp_auth_alg,
	    &ipp->ipp_espa_minbits, &ipp->ipp_espa_maxbits, ns);
	act_alg_adjust(IPSEC_ALG_ENCR, ipp->ipp_encr_alg,
	    &ipp->ipp_espe_minbits, &ipp->ipp_espe_maxbits, ns);

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
    uint_t auth_alg, uint_t encr_alg, uint_t eauth_alg, netstack_t *ns)
{
	ipsec_prot_t *ipp;

	*outact = *act;
	ipp = &outact->ipa_apply;
	ipp->ipp_auth_alg = (uint8_t)auth_alg;
	ipp->ipp_encr_alg = (uint8_t)encr_alg;
	ipp->ipp_esp_auth_alg = (uint8_t)eauth_alg;

	act_alg_adjust(IPSEC_ALG_AUTH, auth_alg,
	    &ipp->ipp_ah_minbits, &ipp->ipp_ah_maxbits, ns);
	act_alg_adjust(IPSEC_ALG_AUTH, eauth_alg,
	    &ipp->ipp_espa_minbits, &ipp->ipp_espa_maxbits, ns);
	act_alg_adjust(IPSEC_ALG_ENCR, encr_alg,
	    &ipp->ipp_espe_minbits, &ipp->ipp_espe_maxbits, ns);
}

/*
 * combinatoric expansion time: expand a wildcarded action into an
 * array of wildcarded actions; we return the exploded action list,
 * and return a count in *nact (output only).
 */
static ipsec_act_t *
ipsec_act_wildcard_expand(ipsec_act_t *act, uint_t *nact, netstack_t *ns)
{
	boolean_t use_ah, use_esp, use_espa;
	boolean_t wild_auth, wild_encr, wild_eauth;
	uint_t	auth_alg, auth_idx, auth_min, auth_max;
	uint_t	eauth_alg, eauth_idx, eauth_min, eauth_max;
	uint_t  encr_alg, encr_idx, encr_min, encr_max;
	uint_t	action_count, ai;
	ipsec_act_t *outact;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

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

#define	SET_EXP_MINMAX(type, wild, alg, min, max, ipss)		\
	if (wild) {						\
		int nalgs = ipss->ipsec_nalgs[type];		\
		if (ipss->ipsec_alglists[type][alg] != NULL)	\
			nalgs--;				\
		action_count *= nalgs;				\
		min = 0;					\
		max = ipss->ipsec_nalgs[type] - 1;		\
	}

	SET_EXP_MINMAX(IPSEC_ALG_AUTH, wild_auth, SADB_AALG_NONE,
	    auth_min, auth_max, ipss);
	SET_EXP_MINMAX(IPSEC_ALG_AUTH, wild_eauth, SADB_AALG_NONE,
	    eauth_min, eauth_max, ipss);
	SET_EXP_MINMAX(IPSEC_ALG_ENCR, wild_encr, SADB_EALG_NONE,
	    encr_min, encr_max, ipss);

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

#define	WHICH_ALG(type, wild, idx, ipss) \
	((wild)?(ipss->ipsec_sortlist[type][idx]):(idx))

	for (encr_idx = encr_min; encr_idx <= encr_max; encr_idx++) {
		encr_alg = WHICH_ALG(IPSEC_ALG_ENCR, wild_encr, encr_idx, ipss);
		if (wild_encr && encr_alg == SADB_EALG_NONE)
			continue;
		for (auth_idx = auth_min; auth_idx <= auth_max; auth_idx++) {
			auth_alg = WHICH_ALG(IPSEC_ALG_AUTH, wild_auth,
			    auth_idx, ipss);
			if (wild_auth && auth_alg == SADB_AALG_NONE)
				continue;
			for (eauth_idx = eauth_min; eauth_idx <= eauth_max;
			    eauth_idx++) {
				eauth_alg = WHICH_ALG(IPSEC_ALG_AUTH,
				    wild_eauth, eauth_idx, ipss);
				if (wild_eauth && eauth_alg == SADB_AALG_NONE)
					continue;

				ipsec_setup_act(&outact[ai], act,
				    auth_alg, encr_alg, eauth_alg, ns);
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
ipsec_prot_from_req(const ipsec_req_t *req, ipsec_prot_t *ipp)
{
	bzero(ipp, sizeof (*ipp));
	/*
	 * ipp_use_* are bitfields.  Look at "!!" in the following as a
	 * "boolean canonicalization" operator.
	 */
	ipp->ipp_use_ah = !!(req->ipsr_ah_req & IPSEC_PREF_REQUIRED);
	ipp->ipp_use_esp = !!(req->ipsr_esp_req & IPSEC_PREF_REQUIRED);
	ipp->ipp_use_espa = !!(req->ipsr_esp_auth_alg);
	ipp->ipp_use_se = !!(req->ipsr_self_encap_req & IPSEC_PREF_REQUIRED);
	ipp->ipp_use_unique = !!((req->ipsr_ah_req|req->ipsr_esp_req) &
	    IPSEC_PREF_UNIQUE);
	ipp->ipp_encr_alg = req->ipsr_esp_alg;
	/*
	 * SADB_AALG_ANY is a placeholder to distinguish "any" from
	 * "none" above.  If auth is required, as determined above,
	 * SADB_AALG_ANY becomes 0, which is the representation
	 * of "any" and "none" in PF_KEY v2.
	 */
	ipp->ipp_auth_alg = (req->ipsr_auth_alg != SADB_AALG_ANY) ?
	    req->ipsr_auth_alg : 0;
	ipp->ipp_esp_auth_alg = (req->ipsr_esp_auth_alg != SADB_AALG_ANY) ?
	    req->ipsr_esp_auth_alg : 0;
}

/*
 * Extract a new-style action from a request.
 */
void
ipsec_actvec_from_req(const ipsec_req_t *req, ipsec_act_t **actp, uint_t *nactp,
    netstack_t *ns)
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
	*actp = ipsec_act_wildcard_expand(&act, nactp, ns);
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
int
ipsec_req_from_head(ipsec_policy_head_t *ph, ipsec_req_t *req, int af)
{
	ipsec_policy_t *p;

	/*
	 * FULL-PERSOCK: consult hash table, too?
	 */
	for (p = ph->iph_root[IPSEC_INBOUND].ipr_nonhash[af];
	    p != NULL;
	    p = p->ipsp_hash.hash_next) {
		if ((p->ipsp_sel->ipsl_key.ipsl_valid & IPSL_WILDCARD) == 0)
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

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ipl = connp->conn_latch;

	/*
	 * Find appropriate policy.  First choice is latched action;
	 * failing that, see latched policy; failing that,
	 * look at configured policy.
	 */
	if (ipl != NULL) {
		if (connp->conn_latch_in_action != NULL) {
			rv = ipsec_req_from_act(connp->conn_latch_in_action,
			    req);
			goto done;
		}
		if (connp->conn_latch_in_policy != NULL) {
			rv = ipsec_req_from_act(
			    connp->conn_latch_in_policy->ipsp_act, req);
			goto done;
		}
	}
	if (connp->conn_policy != NULL)
		rv = ipsec_req_from_head(connp->conn_policy, req, af);
done:
	return (rv);
}

void
ipsec_actvec_free(ipsec_act_t *act, uint_t nact)
{
	kmem_free(act, nact * sizeof (*act));
}

/*
 * Consumes a reference to ipsp.
 */
static mblk_t *
ipsec_check_loopback_policy(mblk_t *data_mp, ip_recv_attr_t *ira,
    ipsec_policy_t *ipsp)
{
	if (!(ira->ira_flags & IRAF_IPSEC_SECURE))
		return (data_mp);

	ASSERT(ira->ira_flags & IRAF_LOOPBACK);

	IPPOL_REFRELE(ipsp);

	/*
	 * We should do an actual policy check here.  Revisit this
	 * when we revisit the IPsec API.  (And pass a conn_t in when we
	 * get there.)
	 */

	return (data_mp);
}

/*
 * Check that packet's inbound ports & proto match the selectors
 * expected by the SAs it traversed on the way in.
 */
static boolean_t
ipsec_check_ipsecin_unique(ip_recv_attr_t *ira, const char **reason,
    kstat_named_t **counter, uint64_t pkt_unique, netstack_t *ns)
{
	uint64_t ah_mask, esp_mask;
	ipsa_t *ah_assoc;
	ipsa_t *esp_assoc;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
	ASSERT(!(ira->ira_flags & IRAF_LOOPBACK));

	ah_assoc = ira->ira_ipsec_ah_sa;
	esp_assoc = ira->ira_ipsec_esp_sa;
	ASSERT((ah_assoc != NULL) || (esp_assoc != NULL));

	ah_mask = (ah_assoc != NULL) ? ah_assoc->ipsa_unique_mask : 0;
	esp_mask = (esp_assoc != NULL) ? esp_assoc->ipsa_unique_mask : 0;

	if ((ah_mask == 0) && (esp_mask == 0))
		return (B_TRUE);

	/*
	 * The pkt_unique check will also check for tunnel mode on the SA
	 * vs. the tunneled_packet boolean.  "Be liberal in what you receive"
	 * should not apply in this case.  ;)
	 */

	if (ah_mask != 0 &&
	    ah_assoc->ipsa_unique_id != (pkt_unique & ah_mask)) {
		*reason = "AH inner header mismatch";
		*counter = DROPPER(ipss, ipds_spd_ah_innermismatch);
		return (B_FALSE);
	}
	if (esp_mask != 0 &&
	    esp_assoc->ipsa_unique_id != (pkt_unique & esp_mask)) {
		*reason = "ESP inner header mismatch";
		*counter = DROPPER(ipss, ipds_spd_esp_innermismatch);
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
ipsec_check_ipsecin_action(ip_recv_attr_t *ira, mblk_t *mp, ipsec_action_t *ap,
    ipha_t *ipha, ip6_t *ip6h, const char **reason, kstat_named_t **counter,
    netstack_t *ns)
{
	boolean_t ret = B_TRUE;
	ipsec_prot_t *ipp;
	ipsa_t *ah_assoc;
	ipsa_t *esp_assoc;
	boolean_t decaps;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	if (ira->ira_flags & IRAF_LOOPBACK) {
		/*
		 * Besides accepting pointer-equivalent actions, we also
		 * accept any ICMP errors we generated for ourselves,
		 * regardless of policy.  If we do not wish to make this
		 * assumption in the future, check here, and where
		 * IXAF_TRUSTED_ICMP is initialized in ip.c and ip6.c.
		 */
		if (ap == ira->ira_ipsec_action ||
		    (ira->ira_flags & IRAF_TRUSTED_ICMP))
			return (B_TRUE);

		/* Deep compare necessary here?? */
		*counter = DROPPER(ipss, ipds_spd_loopback_mismatch);
		*reason = "loopback policy mismatch";
		return (B_FALSE);
	}
	ASSERT(!(ira->ira_flags & IRAF_TRUSTED_ICMP));
	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);

	ah_assoc = ira->ira_ipsec_ah_sa;
	esp_assoc = ira->ira_ipsec_esp_sa;

	decaps = (ira->ira_flags & IRAF_IPSEC_DECAPS);

	switch (ap->ipa_act.ipa_type) {
	case IPSEC_ACT_DISCARD:
	case IPSEC_ACT_REJECT:
		/* Should "fail hard" */
		*counter = DROPPER(ipss, ipds_spd_explicit);
		*reason = "blocked by policy";
		return (B_FALSE);

	case IPSEC_ACT_BYPASS:
	case IPSEC_ACT_CLEAR:
		*counter = DROPPER(ipss, ipds_spd_got_secure);
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
				*counter = DROPPER(ipss, ipds_spd_got_clear);
				*reason = "unprotected not accepted";
				break;
			}
			ASSERT(ah_assoc != NULL);
			ASSERT(ipp->ipp_auth_alg != 0);

			if (ah_assoc->ipsa_auth_alg !=
			    ipp->ipp_auth_alg) {
				*counter = DROPPER(ipss, ipds_spd_bad_ahalg);
				*reason = "unacceptable ah alg";
				ret = B_FALSE;
				break;
			}
		} else if (ah_assoc != NULL) {
			/*
			 * Don't allow this. Check IPSEC NOTE above
			 * ip_fanout_proto().
			 */
			*counter = DROPPER(ipss, ipds_spd_got_ah);
			*reason = "unexpected AH";
			ret = B_FALSE;
			break;
		}
		if (ipp->ipp_use_esp) {
			if (esp_assoc == NULL) {
				ret = ipsec_inbound_accept_clear(mp, ipha,
				    ip6h);
				*counter = DROPPER(ipss, ipds_spd_got_clear);
				*reason = "unprotected not accepted";
				break;
			}
			ASSERT(esp_assoc != NULL);
			ASSERT(ipp->ipp_encr_alg != 0);

			if (esp_assoc->ipsa_encr_alg !=
			    ipp->ipp_encr_alg) {
				*counter = DROPPER(ipss, ipds_spd_bad_espealg);
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
					*counter = DROPPER(ipss,
					    ipds_spd_bad_espaalg);
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
			*counter = DROPPER(ipss, ipds_spd_got_esp);
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
					*counter = DROPPER(ipss,
					    ipds_spd_bad_selfencap);
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
			*counter = DROPPER(ipss, ipds_spd_got_selfencap);
			*reason = "unexpected self encap";
			ret = B_FALSE;
			break;
		}
		if (ira->ira_ipsec_action != NULL) {
			/*
			 * This can happen if we do a double policy-check on
			 * a packet
			 * XXX XXX should fix this case!
			 */
			IPACT_REFRELE(ira->ira_ipsec_action);
		}
		ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
		ASSERT(ira->ira_ipsec_action == NULL);
		IPACT_REFHOLD(ap);
		ira->ira_ipsec_action = ap;
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
 * Takes a latched conn and an inbound packet and returns a unique_id suitable
 * for SA comparisons.  Most of the time we will copy from the conn_t, but
 * there are cases when the conn_t is latched but it has wildcard selectors,
 * and then we need to fallback to scooping them out of the packet.
 *
 * Assume we'll never have 0 with a conn_t present, so use 0 as a failure.  We
 * can get away with this because we only have non-zero ports/proto for
 * latched conn_ts.
 *
 * Ideal candidate for an "inline" keyword, as we're JUST convoluted enough
 * to not be a nice macro.
 */
static uint64_t
conn_to_unique(conn_t *connp, mblk_t *data_mp, ipha_t *ipha, ip6_t *ip6h)
{
	ipsec_selector_t sel;
	uint8_t ulp = connp->conn_proto;

	ASSERT(connp->conn_latch_in_policy != NULL);

	if ((ulp == IPPROTO_TCP || ulp == IPPROTO_UDP || ulp == IPPROTO_SCTP) &&
	    (connp->conn_fport == 0 || connp->conn_lport == 0)) {
		/* Slow path - we gotta grab from the packet. */
		if (ipsec_init_inbound_sel(&sel, data_mp, ipha, ip6h,
		    SEL_NONE) != SELRET_SUCCESS) {
			/* Failure -> have caller free packet with ENOMEM. */
			return (0);
		}
		return (SA_UNIQUE_ID(sel.ips_remote_port, sel.ips_local_port,
		    sel.ips_protocol, 0));
	}

#ifdef DEBUG_NOT_UNTIL_6478464
	if (ipsec_init_inbound_sel(&sel, data_mp, ipha, ip6h, SEL_NONE) ==
	    SELRET_SUCCESS) {
		ASSERT(sel.ips_local_port == connp->conn_lport);
		ASSERT(sel.ips_remote_port == connp->conn_fport);
		ASSERT(sel.ips_protocol == connp->conn_proto);
	}
	ASSERT(connp->conn_proto != 0);
#endif

	return (SA_UNIQUE_ID(connp->conn_fport, connp->conn_lport, ulp, 0));
}

/*
 * Called to check policy on a latched connection.
 * Note that we don't dereference conn_latch or conn_ihere since the conn might
 * be closing. The caller passes a held ipsec_latch_t instead.
 */
static boolean_t
ipsec_check_ipsecin_latch(ip_recv_attr_t *ira, mblk_t *mp, ipsec_latch_t *ipl,
    ipsec_action_t *ap, ipha_t *ipha, ip6_t *ip6h, const char **reason,
    kstat_named_t **counter, conn_t *connp, netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(ipl->ipl_ids_latched == B_TRUE);
	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);

	if (!(ira->ira_flags & IRAF_LOOPBACK)) {
		/*
		 * Over loopback, there aren't real security associations,
		 * so there are neither identities nor "unique" values
		 * for us to check the packet against.
		 */
		if (ira->ira_ipsec_ah_sa != NULL) {
			if (!spd_match_inbound_ids(ipl,
			    ira->ira_ipsec_ah_sa)) {
				*counter = DROPPER(ipss, ipds_spd_ah_badid);
				*reason = "AH identity mismatch";
				return (B_FALSE);
			}
		}

		if (ira->ira_ipsec_esp_sa != NULL) {
			if (!spd_match_inbound_ids(ipl,
			    ira->ira_ipsec_esp_sa)) {
				*counter = DROPPER(ipss, ipds_spd_esp_badid);
				*reason = "ESP identity mismatch";
				return (B_FALSE);
			}
		}

		/*
		 * Can fudge pkt_unique from connp because we're latched.
		 * In DEBUG kernels (see conn_to_unique()'s implementation),
		 * verify this even if it REALLY slows things down.
		 */
		if (!ipsec_check_ipsecin_unique(ira, reason, counter,
		    conn_to_unique(connp, mp, ipha, ip6h), ns)) {
			return (B_FALSE);
		}
	}
	return (ipsec_check_ipsecin_action(ira, mp, ap, ipha, ip6h, reason,
	    counter, ns));
}

/*
 * Check to see whether this secured datagram meets the policy
 * constraints specified in ipsp.
 *
 * Called from ipsec_check_global_policy, and ipsec_check_inbound_policy.
 *
 * Consumes a reference to ipsp.
 * Returns the mblk if ok.
 */
static mblk_t *
ipsec_check_ipsecin_policy(mblk_t *data_mp, ipsec_policy_t *ipsp,
    ipha_t *ipha, ip6_t *ip6h, uint64_t pkt_unique, ip_recv_attr_t *ira,
    netstack_t *ns)
{
	ipsec_action_t *ap;
	const char *reason = "no policy actions found";
	ip_stack_t	*ipst = ns->netstack_ip;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	kstat_named_t *counter;

	counter = DROPPER(ipss, ipds_spd_got_secure);

	ASSERT(ipsp != NULL);

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	if (ira->ira_flags & IRAF_LOOPBACK)
		return (ipsec_check_loopback_policy(data_mp, ira, ipsp));

	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);

	if (ira->ira_ipsec_action != NULL) {
		/*
		 * this can happen if we do a double policy-check on a packet
		 * Would be nice to be able to delete this test..
		 */
		IPACT_REFRELE(ira->ira_ipsec_action);
	}
	ASSERT(ira->ira_ipsec_action == NULL);

	if (!SA_IDS_MATCH(ira->ira_ipsec_ah_sa, ira->ira_ipsec_esp_sa)) {
		reason = "inbound AH and ESP identities differ";
		counter = DROPPER(ipss, ipds_spd_ahesp_diffid);
		goto drop;
	}

	if (!ipsec_check_ipsecin_unique(ira, &reason, &counter, pkt_unique,
	    ns))
		goto drop;

	/*
	 * Ok, now loop through the possible actions and see if any
	 * of them work for us.
	 */

	for (ap = ipsp->ipsp_act; ap != NULL; ap = ap->ipa_next) {
		if (ipsec_check_ipsecin_action(ira, data_mp, ap,
		    ipha, ip6h, &reason, &counter, ns)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipsecInSucceeded);
			IPPOL_REFRELE(ipsp);
			return (data_mp);
		}
	}
drop:
	ipsec_rl_strlog(ns, IP_MOD_ID, 0, 0, SL_ERROR|SL_WARN|SL_CONSOLE,
	    "ipsec inbound policy mismatch: %s, packet dropped\n",
	    reason);
	IPPOL_REFRELE(ipsp);
	ASSERT(ira->ira_ipsec_action == NULL);
	BUMP_MIB(&ipst->ips_ip_mib, ipsecInFailed);
	ip_drop_packet(data_mp, B_TRUE, NULL, counter,
	    &ipss->ipsec_spd_dropper);
	return (NULL);
}

/*
 * sleazy prefix-length-based compare.
 * another inlining candidate..
 */
boolean_t
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
	    (((addr1[offset] ^ addr2[offset]) & (0xff<<(8-bitsleft))) == 0)));
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
		    isel->ipsl_remote_pfxlen, &sel->ips_remote_addr_v6))
			continue;

		if ((valid & IPSL_LOCAL_ADDR) &&
		    !ip_addr_match((uint8_t *)&isel->ipsl_local,
		    isel->ipsl_local_pfxlen, &sel->ips_local_addr_v6))
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
ipsec_policy_t *
ipsec_find_policy_head(ipsec_policy_t *best, ipsec_policy_head_t *head,
    int direction, ipsec_selector_t *sel)
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
				    " expecting icmp, got %d",
				    sel->ips_protocol);
			}
		} else {
			if (sel->ips_protocol != IPPROTO_ICMPV6) {
				cmn_err(CE_WARN, "ipsec_find_policy_head:"
				    " expecting icmpv6, got %d",
				    sel->ips_protocol);
			}
		}
	}
#endif

	rw_enter(&head->iph_lock, RW_READER);

	if (root->ipr_nchains > 0) {
		curbest = ipsec_find_policy_chain(curbest,
		    root->ipr_hash[selector_hash(sel, root)].hash_head, sel,
		    is_icmp_inv_acq);
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
ipsec_find_policy(int direction, const conn_t *connp, ipsec_selector_t *sel,
    netstack_t *ns)
{
	ipsec_policy_t *p;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	p = ipsec_find_policy_head(NULL, &ipss->ipsec_system_policy,
	    direction, sel);
	if ((connp != NULL) && (connp->conn_policy != NULL)) {
		p = ipsec_find_policy_head(p, connp->conn_policy,
		    direction, sel);
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
ipsec_check_global_policy(mblk_t *data_mp, conn_t *connp,
    ipha_t *ipha, ip6_t *ip6h, ip_recv_attr_t *ira, netstack_t *ns)
{
	ipsec_policy_t *p;
	ipsec_selector_t sel;
	boolean_t policy_present;
	kstat_named_t *counter;
	uint64_t pkt_unique;
	ip_stack_t	*ipst = ns->netstack_ip;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	sel.ips_is_icmp_inv_acq = 0;

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	if (ipha != NULL)
		policy_present = ipss->ipsec_inbound_v4_policy_present;
	else
		policy_present = ipss->ipsec_inbound_v6_policy_present;

	if (!policy_present && connp == NULL) {
		/*
		 * No global policy and no per-socket policy;
		 * just pass it back (but we shouldn't get here in that case)
		 */
		return (data_mp);
	}

	/*
	 * If we have cached policy, use it.
	 * Otherwise consult system policy.
	 */
	if ((connp != NULL) && (connp->conn_latch != NULL)) {
		p = connp->conn_latch_in_policy;
		if (p != NULL) {
			IPPOL_REFHOLD(p);
		}
		/*
		 * Fudge sel for UNIQUE_ID setting below.
		 */
		pkt_unique = conn_to_unique(connp, data_mp, ipha, ip6h);
	} else {
		/* Initialize the ports in the selector */
		if (ipsec_init_inbound_sel(&sel, data_mp, ipha, ip6h,
		    SEL_NONE) == SELRET_NOMEM) {
			/*
			 * Technically not a policy mismatch, but it is
			 * an internal failure.
			 */
			ipsec_log_policy_failure(IPSEC_POLICY_MISMATCH,
			    "ipsec_init_inbound_sel", ipha, ip6h, B_TRUE, ns);
			counter = DROPPER(ipss, ipds_spd_nomem);
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

		p = ipsec_find_policy(IPSEC_TYPE_INBOUND, connp, &sel, ns);
		pkt_unique = SA_UNIQUE_ID(sel.ips_remote_port,
		    sel.ips_local_port, sel.ips_protocol, 0);
	}

	if (p == NULL) {
		if (!(ira->ira_flags & IRAF_IPSEC_SECURE)) {
			/*
			 * We have no policy; default to succeeding.
			 * XXX paranoid system design doesn't do this.
			 */
			BUMP_MIB(&ipst->ips_ip_mib, ipsecInSucceeded);
			return (data_mp);
		} else {
			counter = DROPPER(ipss, ipds_spd_got_secure);
			ipsec_log_policy_failure(IPSEC_POLICY_NOT_NEEDED,
			    "ipsec_check_global_policy", ipha, ip6h, B_TRUE,
			    ns);
			goto fail;
		}
	}
	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		return (ipsec_check_ipsecin_policy(data_mp, p, ipha, ip6h,
		    pkt_unique, ira, ns));
	}
	if (p->ipsp_act->ipa_allow_clear) {
		BUMP_MIB(&ipst->ips_ip_mib, ipsecInSucceeded);
		IPPOL_REFRELE(p);
		return (data_mp);
	}
	IPPOL_REFRELE(p);
	/*
	 * If we reach here, we will drop the packet because it failed the
	 * global policy check because the packet was cleartext, and it
	 * should not have been.
	 */
	ipsec_log_policy_failure(IPSEC_POLICY_MISMATCH,
	    "ipsec_check_global_policy", ipha, ip6h, B_FALSE, ns);
	counter = DROPPER(ipss, ipds_spd_got_clear);

fail:
	ip_drop_packet(data_mp, B_TRUE, NULL, counter,
	    &ipss->ipsec_spd_dropper);
	BUMP_MIB(&ipst->ips_ip_mib, ipsecInFailed);
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
		if (ipha->ipha_protocol != IPPROTO_ICMP) {
#ifdef FRAGCACHE_DEBUG
			cmn_err(CE_WARN, "Dropping - ipha_proto = %d\n",
			    ipha->ipha_protocol);
#endif
			return (B_FALSE);
		}
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
				 * already set dce_pmtu
				 */
#ifdef FRAGCACHE_DEBUG
			cmn_err(CE_WARN, "ICMP frag needed\n");
#endif
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
ipsec_latch_inbound(conn_t *connp, ip_recv_attr_t *ira)
{
	ipsa_t *sa;
	ipsec_latch_t *ipl = connp->conn_latch;

	if (!ipl->ipl_ids_latched) {
		ipsid_t *local = NULL;
		ipsid_t *remote = NULL;

		if (!(ira->ira_flags & IRAF_LOOPBACK)) {
			ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
			if (ira->ira_ipsec_esp_sa != NULL)
				sa = ira->ira_ipsec_esp_sa;
			else
				sa = ira->ira_ipsec_ah_sa;
			ASSERT(sa != NULL);
			local = sa->ipsa_dst_cid;
			remote = sa->ipsa_src_cid;
		}
		ipsec_latch_ids(ipl, local, remote);
	}
	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		if (connp->conn_latch_in_action != NULL) {
			/*
			 * Previously cached action.  This is probably
			 * harmless, but in DEBUG kernels, check for
			 * action equality.
			 *
			 * Preserve the existing action to preserve latch
			 * invariance.
			 */
			ASSERT(connp->conn_latch_in_action ==
			    ira->ira_ipsec_action);
			return;
		}
		connp->conn_latch_in_action = ira->ira_ipsec_action;
		IPACT_REFHOLD(connp->conn_latch_in_action);
	}
}

/*
 * Check whether the policy constraints are met either for an
 * inbound datagram; called from IP in numerous places.
 *
 * Note that this is not a chokepoint for inbound policy checks;
 * see also ipsec_check_ipsecin_latch() and ipsec_check_global_policy()
 */
mblk_t *
ipsec_check_inbound_policy(mblk_t *mp, conn_t *connp,
    ipha_t *ipha, ip6_t *ip6h, ip_recv_attr_t *ira)
{
	boolean_t	ret;
	ipsec_latch_t	*ipl;
	ipsec_action_t	*ap;
	uint64_t	unique_id;
	ipsec_stack_t	*ipss;
	ip_stack_t	*ipst;
	netstack_t	*ns;
	ipsec_policy_head_t *policy_head;
	ipsec_policy_t	*p = NULL;

	ASSERT(connp != NULL);
	ns = connp->conn_netstack;
	ipss = ns->netstack_ipsec;
	ipst = ns->netstack_ip;

	if (!(ira->ira_flags & IRAF_IPSEC_SECURE)) {
		/*
		 * This is the case where the incoming datagram is
		 * cleartext and we need to see whether this client
		 * would like to receive such untrustworthy things from
		 * the wire.
		 */
		ASSERT(mp != NULL);

		mutex_enter(&connp->conn_lock);
		if (connp->conn_state_flags & CONN_CONDEMNED) {
			mutex_exit(&connp->conn_lock);
			ip_drop_packet(mp, B_TRUE, NULL,
			    DROPPER(ipss, ipds_spd_got_clear),
			    &ipss->ipsec_spd_dropper);
			BUMP_MIB(&ipst->ips_ip_mib, ipsecInFailed);
			return (NULL);
		}
		if (connp->conn_latch != NULL) {
			/* Hold a reference in case the conn is closing */
			p = connp->conn_latch_in_policy;
			if (p != NULL)
				IPPOL_REFHOLD(p);
			mutex_exit(&connp->conn_lock);
			/*
			 * Policy is cached in the conn.
			 */
			if (p != NULL && !p->ipsp_act->ipa_allow_clear) {
				ret = ipsec_inbound_accept_clear(mp,
				    ipha, ip6h);
				if (ret) {
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipsecInSucceeded);
					IPPOL_REFRELE(p);
					return (mp);
				} else {
					ipsec_log_policy_failure(
					    IPSEC_POLICY_MISMATCH,
					    "ipsec_check_inbound_policy", ipha,
					    ip6h, B_FALSE, ns);
					ip_drop_packet(mp, B_TRUE, NULL,
					    DROPPER(ipss, ipds_spd_got_clear),
					    &ipss->ipsec_spd_dropper);
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipsecInFailed);
					IPPOL_REFRELE(p);
					return (NULL);
				}
			} else {
				BUMP_MIB(&ipst->ips_ip_mib, ipsecInSucceeded);
				if (p != NULL)
					IPPOL_REFRELE(p);
				return (mp);
			}
		} else {
			policy_head = connp->conn_policy;

			/* Hold a reference in case the conn is closing */
			if (policy_head != NULL)
				IPPH_REFHOLD(policy_head);
			mutex_exit(&connp->conn_lock);
			/*
			 * As this is a non-hardbound connection we need
			 * to look at both per-socket policy and global
			 * policy.
			 */
			mp = ipsec_check_global_policy(mp, connp,
			    ipha, ip6h, ira, ns);
			if (policy_head != NULL)
				IPPH_REFRELE(policy_head, ns);
			return (mp);
		}
	}

	mutex_enter(&connp->conn_lock);
	/* Connection is closing */
	if (connp->conn_state_flags & CONN_CONDEMNED) {
		mutex_exit(&connp->conn_lock);
		ip_drop_packet(mp, B_TRUE, NULL,
		    DROPPER(ipss, ipds_spd_got_clear),
		    &ipss->ipsec_spd_dropper);
		BUMP_MIB(&ipst->ips_ip_mib, ipsecInFailed);
		return (NULL);
	}

	/*
	 * Once a connection is latched it remains so for life, the conn_latch
	 * pointer on the conn has not changed, simply initializing ipl here
	 * as the earlier initialization was done only in the cleartext case.
	 */
	if ((ipl = connp->conn_latch) == NULL) {
		mblk_t *retmp;
		policy_head = connp->conn_policy;

		/* Hold a reference in case the conn is closing */
		if (policy_head != NULL)
			IPPH_REFHOLD(policy_head);
		mutex_exit(&connp->conn_lock);
		/*
		 * We don't have policies cached in the conn
		 * for this stream. So, look at the global
		 * policy. It will check against conn or global
		 * depending on whichever is stronger.
		 */
		retmp = ipsec_check_global_policy(mp, connp,
		    ipha, ip6h, ira, ns);
		if (policy_head != NULL)
			IPPH_REFRELE(policy_head, ns);
		return (retmp);
	}

	IPLATCH_REFHOLD(ipl);
	/* Hold reference on conn_latch_in_action in case conn is closing */
	ap = connp->conn_latch_in_action;
	if (ap != NULL)
		IPACT_REFHOLD(ap);
	mutex_exit(&connp->conn_lock);

	if (ap != NULL) {
		/* Policy is cached & latched; fast(er) path */
		const char *reason;
		kstat_named_t *counter;

		if (ipsec_check_ipsecin_latch(ira, mp, ipl, ap,
		    ipha, ip6h, &reason, &counter, connp, ns)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipsecInSucceeded);
			IPLATCH_REFRELE(ipl);
			IPACT_REFRELE(ap);
			return (mp);
		}
		ipsec_rl_strlog(ns, IP_MOD_ID, 0, 0,
		    SL_ERROR|SL_WARN|SL_CONSOLE,
		    "ipsec inbound policy mismatch: %s, packet dropped\n",
		    reason);
		ip_drop_packet(mp, B_TRUE, NULL, counter,
		    &ipss->ipsec_spd_dropper);
		BUMP_MIB(&ipst->ips_ip_mib, ipsecInFailed);
		IPLATCH_REFRELE(ipl);
		IPACT_REFRELE(ap);
		return (NULL);
	}
	if ((p = connp->conn_latch_in_policy) == NULL) {
		ipsec_weird_null_inbound_policy++;
		IPLATCH_REFRELE(ipl);
		return (mp);
	}

	unique_id = conn_to_unique(connp, mp, ipha, ip6h);
	IPPOL_REFHOLD(p);
	mp = ipsec_check_ipsecin_policy(mp, p, ipha, ip6h, unique_id, ira, ns);
	/*
	 * NOTE: ipsecIn{Failed,Succeeeded} bumped by
	 * ipsec_check_ipsecin_policy().
	 */
	if (mp != NULL)
		ipsec_latch_inbound(connp, ira);
	IPLATCH_REFRELE(ipl);
	return (mp);
}

/*
 * Handle all sorts of cases like tunnel-mode and ICMP.
 */
static int
prepended_length(mblk_t *mp, uintptr_t hptr)
{
	int rc = 0;

	while (mp != NULL) {
		if (hptr >= (uintptr_t)mp->b_rptr && hptr <
		    (uintptr_t)mp->b_wptr) {
			rc += (int)(hptr - (uintptr_t)mp->b_rptr);
			break;	/* out of while loop */
		}
		rc += (int)MBLKL(mp);
		mp = mp->b_cont;
	}

	if (mp == NULL) {
		/*
		 * IF (big IF) we make it here by naturally exiting the loop,
		 * then ip6h isn't in the mblk chain "mp" at all.
		 *
		 * The only case where this happens is with a reversed IP
		 * header that gets passed up by inbound ICMP processing.
		 * This unfortunately triggers longstanding bug 6478464.  For
		 * now, just pass up 0 for the answer.
		 */
#ifdef DEBUG_NOT_UNTIL_6478464
		ASSERT(mp != NULL);
#endif
		rc = 0;
	}

	return (rc);
}

/*
 * Returns:
 *
 * SELRET_NOMEM --> msgpullup() needed to gather things failed.
 * SELRET_BADPKT --> If we're being called after tunnel-mode fragment
 *		     gathering, the initial fragment is too short for
 *		     useful data.  Only returned if SEL_TUNNEL_FIRSTFRAG is
 *		     set.
 * SELRET_SUCCESS --> "sel" now has initialized IPsec selector data.
 * SELRET_TUNFRAG --> This is a fragment in a tunnel-mode packet.  Caller
 *		      should put this packet in a fragment-gathering queue.
 *		      Only returned if SEL_TUNNEL_MODE and SEL_PORT_POLICY
 *		      is set.
 *
 * Note that ipha/ip6h can be in a different mblk (mp->b_cont) in the case
 * of tunneled packets.
 * Also, mp->b_rptr can be an ICMP error where ipha/ip6h is the packet in
 * error past the ICMP error.
 */
static selret_t
ipsec_init_inbound_sel(ipsec_selector_t *sel, mblk_t *mp, ipha_t *ipha,
    ip6_t *ip6h, uint8_t sel_flags)
{
	uint16_t *ports;
	int outer_hdr_len = 0;	/* For ICMP or tunnel-mode cases... */
	ushort_t hdr_len;
	mblk_t *spare_mp = NULL;
	uint8_t *nexthdrp, *transportp;
	uint8_t nexthdr;
	uint8_t icmp_proto;
	ip_pkt_t ipp;
	boolean_t port_policy_present = (sel_flags & SEL_PORT_POLICY);
	boolean_t is_icmp = (sel_flags & SEL_IS_ICMP);
	boolean_t tunnel_mode = (sel_flags & SEL_TUNNEL_MODE);
	boolean_t post_frag = (sel_flags & SEL_POST_FRAG);

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ipha != NULL && ip6h == NULL));

	if (ip6h != NULL) {
		outer_hdr_len = prepended_length(mp, (uintptr_t)ip6h);
		nexthdr = ip6h->ip6_nxt;
		icmp_proto = IPPROTO_ICMPV6;
		sel->ips_isv4 = B_FALSE;
		sel->ips_local_addr_v6 = ip6h->ip6_dst;
		sel->ips_remote_addr_v6 = ip6h->ip6_src;

		bzero(&ipp, sizeof (ipp));

		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		case IPPROTO_FRAGMENT:
			/*
			 * Use ip_hdr_length_nexthdr_v6().  And have a spare
			 * mblk that's contiguous to feed it
			 */
			if ((spare_mp = msgpullup(mp, -1)) == NULL)
				return (SELRET_NOMEM);
			if (!ip_hdr_length_nexthdr_v6(spare_mp,
			    (ip6_t *)(spare_mp->b_rptr + outer_hdr_len),
			    &hdr_len, &nexthdrp)) {
				/* Malformed packet - caller frees. */
				ipsec_freemsg_chain(spare_mp);
				return (SELRET_BADPKT);
			}
			/* Repopulate now that we have the whole packet */
			ip6h = (ip6_t *)(spare_mp->b_rptr + outer_hdr_len);
			(void) ip_find_hdr_v6(spare_mp, ip6h, B_FALSE, &ipp,
			    NULL);
			nexthdr = *nexthdrp;
			/* We can just extract based on hdr_len now. */
			break;
		default:
			(void) ip_find_hdr_v6(mp, ip6h, B_FALSE, &ipp, NULL);
			hdr_len = IPV6_HDR_LEN;
			break;
		}
		if (port_policy_present && IS_V6_FRAGMENT(ipp) && !is_icmp) {
			/* IPv6 Fragment */
			ipsec_freemsg_chain(spare_mp);
			return (SELRET_TUNFRAG);
		}
		transportp = (uint8_t *)ip6h + hdr_len;
	} else {
		outer_hdr_len = prepended_length(mp, (uintptr_t)ipha);
		icmp_proto = IPPROTO_ICMP;
		sel->ips_isv4 = B_TRUE;
		sel->ips_local_addr_v4 = ipha->ipha_dst;
		sel->ips_remote_addr_v4 = ipha->ipha_src;
		nexthdr = ipha->ipha_protocol;
		hdr_len = IPH_HDR_LENGTH(ipha);

		if (port_policy_present &&
		    IS_V4_FRAGMENT(ipha->ipha_fragment_offset_and_flags) &&
		    !is_icmp) {
			/* IPv4 Fragment */
			ipsec_freemsg_chain(spare_mp);
			return (SELRET_TUNFRAG);
		}
		transportp = (uint8_t *)ipha + hdr_len;
	}
	sel->ips_protocol = nexthdr;

	if ((nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP &&
	    nexthdr != IPPROTO_SCTP && nexthdr != icmp_proto) ||
	    (!port_policy_present && !post_frag && tunnel_mode)) {
		sel->ips_remote_port = sel->ips_local_port = 0;
		ipsec_freemsg_chain(spare_mp);
		return (SELRET_SUCCESS);
	}

	if (transportp + 4 > mp->b_wptr) {
		/* If we didn't pullup a copy already, do so now. */
		/*
		 * XXX performance, will upper-layers frequently split TCP/UDP
		 * apart from IP or options?  If so, perhaps we should revisit
		 * the spare_mp strategy.
		 */
		ipsec_hdr_pullup_needed++;
		if (spare_mp == NULL &&
		    (spare_mp = msgpullup(mp, -1)) == NULL) {
			return (SELRET_NOMEM);
		}
		transportp = &spare_mp->b_rptr[hdr_len + outer_hdr_len];
	}

	if (nexthdr == icmp_proto) {
		sel->ips_icmp_type = *transportp++;
		sel->ips_icmp_code = *transportp;
		sel->ips_remote_port = sel->ips_local_port = 0;
	} else {
		ports = (uint16_t *)transportp;
		sel->ips_remote_port = *ports++;
		sel->ips_local_port = *ports;
	}
	ipsec_freemsg_chain(spare_mp);
	return (SELRET_SUCCESS);
}

/*
 * This is called with a b_next chain of messages from the fragcache code,
 * hence it needs to discard a chain on error.
 */
static boolean_t
ipsec_init_outbound_ports(ipsec_selector_t *sel, mblk_t *mp, ipha_t *ipha,
    ip6_t *ip6h, int outer_hdr_len, ipsec_stack_t *ipss)
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
		case IPPROTO_FRAGMENT:
			/*
			 * Use ip_hdr_length_nexthdr_v6().  And have a spare
			 * mblk that's contiguous to feed it
			 */
			spare_mp = msgpullup(mp, -1);
			if (spare_mp == NULL ||
			    !ip_hdr_length_nexthdr_v6(spare_mp,
			    (ip6_t *)(spare_mp->b_rptr + outer_hdr_len),
			    &hdr_len, &nexthdrp)) {
				/* Always works, even if NULL. */
				ipsec_freemsg_chain(spare_mp);
				ip_drop_packet_chain(mp, B_FALSE, NULL,
				    DROPPER(ipss, ipds_spd_nomem),
				    &ipss->ipsec_spd_dropper);
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
		ipsec_freemsg_chain(spare_mp); /* Always works, even if NULL */
		return (B_TRUE);
	}

	if (&mp->b_rptr[hdr_len] + 4 + outer_hdr_len > mp->b_wptr) {
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
			ip_drop_packet_chain(mp, B_FALSE, NULL,
			    DROPPER(ipss, ipds_spd_nomem),
			    &ipss->ipsec_spd_dropper);
			return (B_FALSE);
		}
		ports = (uint16_t *)&spare_mp->b_rptr[hdr_len + outer_hdr_len];
	} else {
		ports = (uint16_t *)&mp->b_rptr[hdr_len + outer_hdr_len];
	}

	if (nexthdr == check_proto) {
		typecode = (uint8_t *)ports;
		sel->ips_icmp_type = *typecode++;
		sel->ips_icmp_code = *typecode;
		sel->ips_remote_port = sel->ips_local_port = 0;
	} else {
		sel->ips_local_port = *ports++;
		sel->ips_remote_port = *ports;
	}
	ipsec_freemsg_chain(spare_mp);	/* Always works, even if NULL */
	return (B_TRUE);
}

/*
 * Prepend an mblk with a ipsec_crypto_t to the message chain.
 * Frees the argument and returns NULL should the allocation fail.
 * Returns the pointer to the crypto data part.
 */
mblk_t *
ipsec_add_crypto_data(mblk_t *data_mp, ipsec_crypto_t **icp)
{
	mblk_t	*mp;

	mp = allocb(sizeof (ipsec_crypto_t), BPRI_MED);
	if (mp == NULL) {
		freemsg(data_mp);
		return (NULL);
	}
	bzero(mp->b_rptr, sizeof (ipsec_crypto_t));
	mp->b_wptr += sizeof (ipsec_crypto_t);
	mp->b_cont = data_mp;
	mp->b_datap->db_type = M_EVENT;	/* For ASSERT */
	*icp = (ipsec_crypto_t *)mp->b_rptr;
	return (mp);
}

/*
 * Remove what was prepended above. Return b_cont and a pointer to the
 * crypto data.
 * The caller must call ipsec_free_crypto_data for mblk once it is done
 * with the crypto data.
 */
mblk_t *
ipsec_remove_crypto_data(mblk_t *crypto_mp, ipsec_crypto_t **icp)
{
	ASSERT(crypto_mp->b_datap->db_type == M_EVENT);
	ASSERT(MBLKL(crypto_mp) == sizeof (ipsec_crypto_t));

	*icp = (ipsec_crypto_t *)crypto_mp->b_rptr;
	return (crypto_mp->b_cont);
}

/*
 * Free what was prepended above. Return b_cont.
 */
mblk_t *
ipsec_free_crypto_data(mblk_t *crypto_mp)
{
	mblk_t	*mp;

	ASSERT(crypto_mp->b_datap->db_type == M_EVENT);
	ASSERT(MBLKL(crypto_mp) == sizeof (ipsec_crypto_t));

	mp = crypto_mp->b_cont;
	freeb(crypto_mp);
	return (mp);
}

/*
 * Create an ipsec_action_t based on the way an inbound packet was protected.
 * Used to reflect traffic back to a sender.
 *
 * We don't bother interning the action into the hash table.
 */
ipsec_action_t *
ipsec_in_to_out_action(ip_recv_attr_t *ira)
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
	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);

	ah_assoc = ira->ira_ipsec_ah_sa;
	ap->ipa_act.ipa_apply.ipp_use_ah = (ah_assoc != NULL);

	esp_assoc = ira->ira_ipsec_esp_sa;
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
	ap->ipa_act.ipa_apply.ipp_use_se =
	    !!(ira->ira_flags & IRAF_IPSEC_DECAPS);
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
	ap->ipa_want_se = !!(ira->ira_flags & IRAF_IPSEC_DECAPS);
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
int32_t
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
#define	IPSEC_IPV4_HASH(a, n) ((a) % (n))
#define	IPSEC_IPV6_HASH(a, n) (((a).s6_addr32[3]) % (n))

/*
 * These two hash functions should produce coordinated values
 * but have slightly different roles.
 */
static uint32_t
selkey_hash(const ipsec_selkey_t *selkey, netstack_t *ns)
{
	uint32_t valid = selkey->ipsl_valid;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	if (!(valid & IPSL_REMOTE_ADDR))
		return (IPSEC_SEL_NOHASH);

	if (valid & IPSL_IPV4) {
		if (selkey->ipsl_remote_pfxlen == 32) {
			return (IPSEC_IPV4_HASH(selkey->ipsl_remote.ipsad_v4,
			    ipss->ipsec_spd_hashsize));
		}
	}
	if (valid & IPSL_IPV6) {
		if (selkey->ipsl_remote_pfxlen == 128) {
			return (IPSEC_IPV6_HASH(selkey->ipsl_remote.ipsad_v6,
			    ipss->ipsec_spd_hashsize));
		}
	}
	return (IPSEC_SEL_NOHASH);
}

static uint32_t
selector_hash(ipsec_selector_t *sel, ipsec_policy_root_t *root)
{
	if (sel->ips_isv4) {
		return (IPSEC_IPV4_HASH(sel->ips_remote_addr_v4,
		    root->ipr_nchains));
	}
	return (IPSEC_IPV6_HASH(sel->ips_remote_addr_v6, root->ipr_nchains));
}

/*
 * Intern actions into the action hash table.
 */
ipsec_action_t *
ipsec_act_find(const ipsec_act_t *a, int n, netstack_t *ns)
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
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	/*
	 * TODO: should canonicalize a[] (i.e., zeroize any padding)
	 * so we can use a non-trivial policy_hash function.
	 */
	for (i = n-1; i >= 0; i--) {
		hval = policy_hash(IPSEC_ACTION_HASH_SIZE, &a[i], &a[n]);

		HASH_LOCK(ipss->ipsec_action_hash, hval);

		for (HASH_ITERATE(ap, ipa_hash,
		    ipss->ipsec_action_hash, hval)) {
			if (bcmp(&ap->ipa_act, &a[i], sizeof (*a)) != 0)
				continue;
			if (ap->ipa_next != prev)
				continue;
			break;
		}
		if (ap != NULL) {
			HASH_UNLOCK(ipss->ipsec_action_hash, hval);
			prev = ap;
			continue;
		}
		/*
		 * need to allocate a new one..
		 */
		ap = kmem_cache_alloc(ipsec_action_cache, KM_NOSLEEP);
		if (ap == NULL) {
			HASH_UNLOCK(ipss->ipsec_action_hash, hval);
			if (prev != NULL)
				ipsec_action_free(prev);
			return (NULL);
		}
		HASH_INSERT(ap, ipa_hash, ipss->ipsec_action_hash, hval);

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
		HASH_UNLOCK(ipss->ipsec_action_hash, hval);
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
 * Called when the action hash table goes away.
 *
 * The actions can be queued on an mblk with ipsec_in or
 * ipsec_out, hence the actions might still be around.
 * But we decrement ipa_refs here since we no longer have
 * a reference to the action from the hash table.
 */
static void
ipsec_action_free_table(ipsec_action_t *ap)
{
	while (ap != NULL) {
		ipsec_action_t *np = ap->ipa_next;

		/* FIXME: remove? */
		(void) printf("ipsec_action_free_table(%p) ref %d\n",
		    (void *)ap, ap->ipa_refs);
		ASSERT(ap->ipa_refs > 0);
		IPACT_REFRELE(ap);
		ap = np;
	}
}

/*
 * Need to walk all stack instances since the reclaim function
 * is global for all instances
 */
/* ARGSUSED */
static void
ipsec_action_reclaim(void *arg)
{
	netstack_handle_t nh;
	netstack_t *ns;
	ipsec_stack_t *ipss;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		/*
		 * netstack_next() can return a netstack_t with a NULL
		 * netstack_ipsec at boot time.
		 */
		if ((ipss = ns->netstack_ipsec) == NULL) {
			netstack_rele(ns);
			continue;
		}
		ipsec_action_reclaim_stack(ipss);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
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
static void
ipsec_action_reclaim_stack(ipsec_stack_t *ipss)
{
	int i;

	for (i = 0; i < IPSEC_ACTION_HASH_SIZE; i++) {
		ipsec_action_t *ap, *np;

		/* skip the lock if nobody home */
		if (ipss->ipsec_action_hash[i].hash_head == NULL)
			continue;

		HASH_LOCK(ipss->ipsec_action_hash, i);
		for (ap = ipss->ipsec_action_hash[i].hash_head;
		    ap != NULL; ap = np) {
			ASSERT(ap->ipa_refs > 0);
			np = ap->ipa_hash.hash_next;
			if (ap->ipa_refs > 1)
				continue;
			HASH_UNCHAIN(ap, ipa_hash,
			    ipss->ipsec_action_hash, i);
			IPACT_REFRELE(ap);
		}
		HASH_UNLOCK(ipss->ipsec_action_hash, i);
	}
}

/*
 * Intern a selector set into the selector set hash table.
 * This is simpler than the actions case..
 */
static ipsec_sel_t *
ipsec_find_sel(ipsec_selkey_t *selkey, netstack_t *ns)
{
	ipsec_sel_t *sp;
	uint32_t hval, bucket;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	/*
	 * Exactly one AF bit should be set in selkey.
	 */
	ASSERT(!(selkey->ipsl_valid & IPSL_IPV4) ^
	    !(selkey->ipsl_valid & IPSL_IPV6));

	hval = selkey_hash(selkey, ns);
	/* Set pol_hval to uninitialized until we put it in a polhead. */
	selkey->ipsl_sel_hval = hval;

	bucket = (hval == IPSEC_SEL_NOHASH) ? 0 : hval;

	ASSERT(!HASH_LOCKED(ipss->ipsec_sel_hash, bucket));
	HASH_LOCK(ipss->ipsec_sel_hash, bucket);

	for (HASH_ITERATE(sp, ipsl_hash, ipss->ipsec_sel_hash, bucket)) {
		if (bcmp(&sp->ipsl_key, selkey,
		    offsetof(ipsec_selkey_t, ipsl_pol_hval)) == 0)
			break;
	}
	if (sp != NULL) {
		sp->ipsl_refs++;

		HASH_UNLOCK(ipss->ipsec_sel_hash, bucket);
		return (sp);
	}

	sp = kmem_cache_alloc(ipsec_sel_cache, KM_NOSLEEP);
	if (sp == NULL) {
		HASH_UNLOCK(ipss->ipsec_sel_hash, bucket);
		return (NULL);
	}

	HASH_INSERT(sp, ipsl_hash, ipss->ipsec_sel_hash, bucket);
	sp->ipsl_refs = 2;	/* one for hash table, one for caller */
	sp->ipsl_key = *selkey;
	/* Set to uninitalized and have insertion into polhead fix things. */
	if (selkey->ipsl_sel_hval != IPSEC_SEL_NOHASH)
		sp->ipsl_key.ipsl_pol_hval = 0;
	else
		sp->ipsl_key.ipsl_pol_hval = IPSEC_SEL_NOHASH;

	HASH_UNLOCK(ipss->ipsec_sel_hash, bucket);

	return (sp);
}

static void
ipsec_sel_rel(ipsec_sel_t **spp, netstack_t *ns)
{
	ipsec_sel_t *sp = *spp;
	int hval = sp->ipsl_key.ipsl_sel_hval;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	*spp = NULL;

	if (hval == IPSEC_SEL_NOHASH)
		hval = 0;

	ASSERT(!HASH_LOCKED(ipss->ipsec_sel_hash, hval));
	HASH_LOCK(ipss->ipsec_sel_hash, hval);
	if (--sp->ipsl_refs == 1) {
		HASH_UNCHAIN(sp, ipsl_hash, ipss->ipsec_sel_hash, hval);
		sp->ipsl_refs--;
		HASH_UNLOCK(ipss->ipsec_sel_hash, hval);
		ASSERT(sp->ipsl_refs == 0);
		kmem_cache_free(ipsec_sel_cache, sp);
		/* Caller unlocks */
		return;
	}

	HASH_UNLOCK(ipss->ipsec_sel_hash, hval);
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
	ASSERT(ipp->ipsp_netstack != NULL);

	ipsec_sel_rel(&ipp->ipsp_sel, ipp->ipsp_netstack);
	IPACT_REFRELE(ipp->ipsp_act);
	kmem_cache_free(ipsec_pol_cache, ipp);
}

/*
 * Construction of new policy rules; construct a policy, and add it to
 * the appropriate tables.
 */
ipsec_policy_t *
ipsec_policy_create(ipsec_selkey_t *keys, const ipsec_act_t *a,
    int nacts, int prio, uint64_t *index_ptr, netstack_t *ns)
{
	ipsec_action_t *ap;
	ipsec_sel_t *sp;
	ipsec_policy_t *ipp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	if (index_ptr == NULL)
		index_ptr = &ipss->ipsec_next_policy_index;

	ipp = kmem_cache_alloc(ipsec_pol_cache, KM_NOSLEEP);
	ap = ipsec_act_find(a, nacts, ns);
	sp = ipsec_find_sel(keys, ns);

	if ((ap == NULL) || (sp == NULL) || (ipp == NULL)) {
		if (ap != NULL) {
			IPACT_REFRELE(ap);
		}
		if (sp != NULL)
			ipsec_sel_rel(&sp, ns);
		if (ipp != NULL)
			kmem_cache_free(ipsec_pol_cache, ipp);
		return (NULL);
	}

	HASH_NULL(ipp, ipsp_hash);

	ipp->ipsp_netstack = ns;	/* Needed for ipsec_policy_free */
	ipp->ipsp_refs = 1;	/* caller's reference */
	ipp->ipsp_sel = sp;
	ipp->ipsp_act = ap;
	ipp->ipsp_prio = prio;	/* rule priority */
	ipp->ipsp_index = *index_ptr;
	(*index_ptr)++;

	return (ipp);
}

static void
ipsec_update_present_flags(ipsec_stack_t *ipss)
{
	boolean_t hashpol;

	hashpol = (avl_numnodes(&ipss->ipsec_system_policy.iph_rulebyid) > 0);

	if (hashpol) {
		ipss->ipsec_outbound_v4_policy_present = B_TRUE;
		ipss->ipsec_outbound_v6_policy_present = B_TRUE;
		ipss->ipsec_inbound_v4_policy_present = B_TRUE;
		ipss->ipsec_inbound_v6_policy_present = B_TRUE;
		return;
	}

	ipss->ipsec_outbound_v4_policy_present = (NULL !=
	    ipss->ipsec_system_policy.iph_root[IPSEC_TYPE_OUTBOUND].
	    ipr_nonhash[IPSEC_AF_V4]);
	ipss->ipsec_outbound_v6_policy_present = (NULL !=
	    ipss->ipsec_system_policy.iph_root[IPSEC_TYPE_OUTBOUND].
	    ipr_nonhash[IPSEC_AF_V6]);
	ipss->ipsec_inbound_v4_policy_present = (NULL !=
	    ipss->ipsec_system_policy.iph_root[IPSEC_TYPE_INBOUND].
	    ipr_nonhash[IPSEC_AF_V4]);
	ipss->ipsec_inbound_v6_policy_present = (NULL !=
	    ipss->ipsec_system_policy.iph_root[IPSEC_TYPE_INBOUND].
	    ipr_nonhash[IPSEC_AF_V6]);
}

boolean_t
ipsec_policy_delete(ipsec_policy_head_t *php, ipsec_selkey_t *keys, int dir,
	netstack_t *ns)
{
	ipsec_sel_t *sp;
	ipsec_policy_t *ip, *nip, *head;
	int af;
	ipsec_policy_root_t *pr = &php->iph_root[dir];

	sp = ipsec_find_sel(keys, ns);

	if (sp == NULL)
		return (B_FALSE);

	af = (sp->ipsl_key.ipsl_valid & IPSL_IPV4) ? IPSEC_AF_V4 : IPSEC_AF_V6;

	rw_enter(&php->iph_lock, RW_WRITER);

	if (sp->ipsl_key.ipsl_pol_hval == IPSEC_SEL_NOHASH) {
		head = pr->ipr_nonhash[af];
	} else {
		head = pr->ipr_hash[sp->ipsl_key.ipsl_pol_hval].hash_head;
	}

	for (ip = head; ip != NULL; ip = nip) {
		nip = ip->ipsp_hash.hash_next;
		if (ip->ipsp_sel != sp) {
			continue;
		}

		IPPOL_UNCHAIN(php, ip);

		php->iph_gen++;
		ipsec_update_present_flags(ns->netstack_ipsec);

		rw_exit(&php->iph_lock);

		ipsec_sel_rel(&sp, ns);

		return (B_TRUE);
	}

	rw_exit(&php->iph_lock);
	ipsec_sel_rel(&sp, ns);
	return (B_FALSE);
}

int
ipsec_policy_delete_index(ipsec_policy_head_t *php, uint64_t policy_index,
    netstack_t *ns)
{
	boolean_t found = B_FALSE;
	ipsec_policy_t ipkey;
	ipsec_policy_t *ip;
	avl_index_t where;

	bzero(&ipkey, sizeof (ipkey));
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
		ipsec_update_present_flags(ns->netstack_ipsec);
	}

	rw_exit(&php->iph_lock);

	return (found ? 0 : ENOENT);
}

/*
 * Given a constructed ipsec_policy_t policy rule, see if it can be entered
 * into the correct policy ruleset.  As a side-effect, it sets the hash
 * entries on "ipp"'s ipsp_pol_hval.
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
	if (selkey->ipsl_sel_hval == IPSEC_SEL_NOHASH) {
		head = pr->ipr_nonhash[af];
	} else {
		selkey->ipsl_pol_hval =
		    (selkey->ipsl_valid & IPSL_IPV4) ?
		    IPSEC_IPV4_HASH(selkey->ipsl_remote.ipsad_v4,
		    pr->ipr_nchains) :
		    IPSEC_IPV6_HASH(selkey->ipsl_remote.ipsad_v6,
		    pr->ipr_nchains);

		head = pr->ipr_hash[selkey->ipsl_pol_hval].hash_head;
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
ipsec_enter_policy(ipsec_policy_head_t *php, ipsec_policy_t *ipp, int direction,
    netstack_t *ns)
{
	ipsec_policy_root_t *pr = &php->iph_root[direction];
	ipsec_selkey_t *selkey = &ipp->ipsp_sel->ipsl_key;
	uint32_t valid = selkey->ipsl_valid;
	uint32_t hval = selkey->ipsl_pol_hval;
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

	ipsec_update_present_flags(ns->netstack_ipsec);
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

/*
 * Create and insert inbound or outbound policy associated with actp for the
 * address family fam into the policy head ph.  Returns B_TRUE if policy was
 * inserted, and B_FALSE otherwise.
 */
boolean_t
ipsec_polhead_insert(ipsec_policy_head_t *ph, ipsec_act_t *actp, uint_t nact,
    int fam, int ptype, netstack_t *ns)
{
	ipsec_selkey_t		sel;
	ipsec_policy_t		*pol;
	ipsec_policy_root_t	*pr;

	bzero(&sel, sizeof (sel));
	sel.ipsl_valid = (fam == IPSEC_AF_V4 ? IPSL_IPV4 : IPSL_IPV6);
	if ((pol = ipsec_policy_create(&sel, actp, nact, IPSEC_PRIO_SOCKET,
	    NULL, ns)) != NULL) {
		pr = &ph->iph_root[ptype];
		HASHLIST_INSERT(pol, ipsp_hash, pr->ipr_nonhash[fam]);
		ipsec_insert_always(&ph->iph_rulebyid, pol);
	}
	return (pol != NULL);
}

void
ipsec_polhead_flush(ipsec_policy_head_t *php, netstack_t *ns)
{
	int dir;

	ASSERT(RW_WRITE_HELD(&php->iph_lock));

	for (dir = 0; dir < IPSEC_NTYPES; dir++)
		ipsec_ipr_flush(php, &php->iph_root[dir]);

	php->iph_gen++;
	ipsec_update_present_flags(ns->netstack_ipsec);
}

void
ipsec_polhead_free(ipsec_policy_head_t *php, netstack_t *ns)
{
	int dir;

	ASSERT(php->iph_refs == 0);

	rw_enter(&php->iph_lock, RW_WRITER);
	ipsec_polhead_flush(php, ns);
	rw_exit(&php->iph_lock);
	rw_destroy(&php->iph_lock);
	for (dir = 0; dir < IPSEC_NTYPES; dir++) {
		ipsec_policy_root_t *ipr = &php->iph_root[dir];
		int chain;

		for (chain = 0; chain < ipr->ipr_nchains; chain++)
			mutex_destroy(&(ipr->ipr_hash[chain].hash_lock));

	}
	ipsec_polhead_free_table(php);
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

ipsec_policy_head_t *
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
ipsec_policy_head_t *
ipsec_polhead_split(ipsec_policy_head_t *php, netstack_t *ns)
{
	ipsec_policy_head_t *nphp;

	if (php == NULL)
		return (ipsec_polhead_create());
	else if (php->iph_refs == 1)
		return (php);

	nphp = ipsec_polhead_create();
	if (nphp == NULL)
		return (NULL);

	if (ipsec_copy_polhead(php, nphp, ns) != 0) {
		ipsec_polhead_free(nphp, ns);
		return (NULL);
	}
	IPPH_REFRELE(php, ns);
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
 *
 * Note: the caller has moved other parts of ira into ixa already.
 */
boolean_t
ipsec_in_to_out(ip_recv_attr_t *ira, ip_xmit_attr_t *ixa, mblk_t *data_mp,
    ipha_t *ipha, ip6_t *ip6h)
{
	ipsec_selector_t sel;
	ipsec_action_t	*reflect_action = NULL;
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;

	bzero((void*)&sel, sizeof (sel));

	if (ira->ira_ipsec_action != NULL) {
		/* transfer reference.. */
		reflect_action = ira->ira_ipsec_action;
		ira->ira_ipsec_action = NULL;
	} else if (!(ira->ira_flags & IRAF_LOOPBACK))
		reflect_action = ipsec_in_to_out_action(ira);

	/*
	 * The caller is going to send the datagram out which might
	 * go on the wire or delivered locally through ire_send_local.
	 *
	 * 1) If it goes out on the wire, new associations will be
	 *    obtained.
	 * 2) If it is delivered locally, ire_send_local will convert
	 *    this ip_xmit_attr_t back to a ip_recv_attr_t looking at the
	 *    requests.
	 */
	ixa->ixa_ipsec_action = reflect_action;

	if (!ipsec_init_outbound_ports(&sel, data_mp, ipha, ip6h, 0,
	    ns->netstack_ipsec)) {
		/* Note: data_mp already consumed and ip_drop_packet done */
		return (B_FALSE);
	}
	ixa->ixa_ipsec_src_port = sel.ips_local_port;
	ixa->ixa_ipsec_dst_port = sel.ips_remote_port;
	ixa->ixa_ipsec_proto = sel.ips_protocol;
	ixa->ixa_ipsec_icmp_type = sel.ips_icmp_type;
	ixa->ixa_ipsec_icmp_code = sel.ips_icmp_code;

	/*
	 * Don't use global policy for this, as we want
	 * to use the same protection that was applied to the inbound packet.
	 * Thus we set IXAF_NO_IPSEC is it arrived in the clear to make
	 * it be sent in the clear.
	 */
	if (ira->ira_flags & IRAF_IPSEC_SECURE)
		ixa->ixa_flags |= IXAF_IPSEC_SECURE;
	else
		ixa->ixa_flags |= IXAF_NO_IPSEC;

	return (B_TRUE);
}

void
ipsec_out_release_refs(ip_xmit_attr_t *ixa)
{
	if (!(ixa->ixa_flags & IXAF_IPSEC_SECURE))
		return;

	if (ixa->ixa_ipsec_ah_sa != NULL) {
		IPSA_REFRELE(ixa->ixa_ipsec_ah_sa);
		ixa->ixa_ipsec_ah_sa = NULL;
	}
	if (ixa->ixa_ipsec_esp_sa != NULL) {
		IPSA_REFRELE(ixa->ixa_ipsec_esp_sa);
		ixa->ixa_ipsec_esp_sa = NULL;
	}
	if (ixa->ixa_ipsec_policy != NULL) {
		IPPOL_REFRELE(ixa->ixa_ipsec_policy);
		ixa->ixa_ipsec_policy = NULL;
	}
	if (ixa->ixa_ipsec_action != NULL) {
		IPACT_REFRELE(ixa->ixa_ipsec_action);
		ixa->ixa_ipsec_action = NULL;
	}
	if (ixa->ixa_ipsec_latch) {
		IPLATCH_REFRELE(ixa->ixa_ipsec_latch);
		ixa->ixa_ipsec_latch = NULL;
	}
	/* Clear the soft references to the SAs */
	ixa->ixa_ipsec_ref[0].ipsr_sa = NULL;
	ixa->ixa_ipsec_ref[0].ipsr_bucket = NULL;
	ixa->ixa_ipsec_ref[0].ipsr_gen = 0;
	ixa->ixa_ipsec_ref[1].ipsr_sa = NULL;
	ixa->ixa_ipsec_ref[1].ipsr_bucket = NULL;
	ixa->ixa_ipsec_ref[1].ipsr_gen = 0;
	ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
}

void
ipsec_in_release_refs(ip_recv_attr_t *ira)
{
	if (!(ira->ira_flags & IRAF_IPSEC_SECURE))
		return;

	if (ira->ira_ipsec_ah_sa != NULL) {
		IPSA_REFRELE(ira->ira_ipsec_ah_sa);
		ira->ira_ipsec_ah_sa = NULL;
	}
	if (ira->ira_ipsec_esp_sa != NULL) {
		IPSA_REFRELE(ira->ira_ipsec_esp_sa);
		ira->ira_ipsec_esp_sa = NULL;
	}
	ira->ira_flags &= ~IRAF_IPSEC_SECURE;
}

/*
 * This is called from ire_send_local when a packet
 * is looped back. We setup the ip_recv_attr_t "borrowing" the references
 * held by the callers.
 * Note that we don't do any IPsec but we carry the actions and IPSEC flags
 * across so that the fanout policy checks see that IPsec was applied.
 *
 * The caller should do ipsec_in_release_refs() on the ira by calling
 * ira_cleanup().
 */
void
ipsec_out_to_in(ip_xmit_attr_t *ixa, ill_t *ill, ip_recv_attr_t *ira)
{
	ipsec_policy_t *pol;
	ipsec_action_t *act;

	/* Non-IPsec operations */
	ira->ira_free_flags = 0;
	ira->ira_zoneid = ixa->ixa_zoneid;
	ira->ira_cred = ixa->ixa_cred;
	ira->ira_cpid = ixa->ixa_cpid;
	ira->ira_tsl = ixa->ixa_tsl;
	ira->ira_ill = ira->ira_rill = ill;
	ira->ira_flags = ixa->ixa_flags & IAF_MASK;
	ira->ira_no_loop_zoneid = ixa->ixa_no_loop_zoneid;
	ira->ira_pktlen = ixa->ixa_pktlen;
	ira->ira_ip_hdr_length = ixa->ixa_ip_hdr_length;
	ira->ira_protocol = ixa->ixa_protocol;
	ira->ira_mhip = NULL;

	ira->ira_flags |= IRAF_LOOPBACK | IRAF_L2SRC_LOOPBACK;

	ira->ira_sqp = ixa->ixa_sqp;
	ira->ira_ring = NULL;

	ira->ira_ruifindex = ill->ill_phyint->phyint_ifindex;
	ira->ira_rifindex = ira->ira_ruifindex;

	if (!(ixa->ixa_flags & IXAF_IPSEC_SECURE))
		return;

	ira->ira_flags |= IRAF_IPSEC_SECURE;

	ira->ira_ipsec_ah_sa = NULL;
	ira->ira_ipsec_esp_sa = NULL;

	act = ixa->ixa_ipsec_action;
	if (act == NULL) {
		pol = ixa->ixa_ipsec_policy;
		if (pol != NULL) {
			act = pol->ipsp_act;
			IPACT_REFHOLD(act);
		}
	}
	ixa->ixa_ipsec_action = NULL;
	ira->ira_ipsec_action = act;
}

/*
 * Consults global policy and per-socket policy to see whether this datagram
 * should go out secure. If so it updates the ip_xmit_attr_t
 * Should not be used when connecting, since then we want to latch the policy.
 *
 * If connp is NULL we just look at the global policy.
 *
 * Returns NULL if the packet was dropped, in which case the MIB has
 * been incremented and ip_drop_packet done.
 */
mblk_t *
ip_output_attach_policy(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h,
    const conn_t *connp, ip_xmit_attr_t *ixa)
{
	ipsec_selector_t sel;
	boolean_t	policy_present;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	netstack_t	*ns = ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ipsec_policy_t	*p;

	ixa->ixa_ipsec_policy_gen = ipss->ipsec_system_policy.iph_gen;
	ASSERT((ipha != NULL && ip6h == NULL) ||
	    (ip6h != NULL && ipha == NULL));

	if (ipha != NULL)
		policy_present = ipss->ipsec_outbound_v4_policy_present;
	else
		policy_present = ipss->ipsec_outbound_v6_policy_present;

	if (!policy_present && (connp == NULL || connp->conn_policy == NULL))
		return (mp);

	bzero((void*)&sel, sizeof (sel));

	if (ipha != NULL) {
		sel.ips_local_addr_v4 = ipha->ipha_src;
		sel.ips_remote_addr_v4 = ip_get_dst(ipha);
		sel.ips_isv4 = B_TRUE;
	} else {
		sel.ips_isv4 = B_FALSE;
		sel.ips_local_addr_v6 = ip6h->ip6_src;
		sel.ips_remote_addr_v6 = ip_get_dst_v6(ip6h, mp, NULL);
	}
	sel.ips_protocol = ixa->ixa_protocol;

	if (!ipsec_init_outbound_ports(&sel, mp, ipha, ip6h, 0, ipss)) {
		if (ipha != NULL) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		} else {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutDiscards);
		}
		/* Note: mp already consumed and ip_drop_packet done */
		return (NULL);
	}

	ASSERT(ixa->ixa_ipsec_policy == NULL);
	p = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, &sel, ns);
	ixa->ixa_ipsec_policy = p;
	if (p != NULL) {
		ixa->ixa_flags |= IXAF_IPSEC_SECURE;
		if (connp == NULL || connp->conn_policy == NULL)
			ixa->ixa_flags |= IXAF_IPSEC_GLOBAL_POLICY;
	} else {
		ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
	}

	/*
	 * Copy the right port information.
	 */
	ixa->ixa_ipsec_src_port = sel.ips_local_port;
	ixa->ixa_ipsec_dst_port = sel.ips_remote_port;
	ixa->ixa_ipsec_icmp_type = sel.ips_icmp_type;
	ixa->ixa_ipsec_icmp_code = sel.ips_icmp_code;
	ixa->ixa_ipsec_proto = sel.ips_protocol;
	return (mp);
}

/*
 * When appropriate, this function caches inbound and outbound policy
 * for this connection. The outbound policy is stored in conn_ixa.
 * Note that it can not be used for SCTP since conn_faddr isn't set for SCTP.
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
	netstack_t	*ns = connp->conn_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	connp->conn_ixa->ixa_ipsec_policy_gen =
	    ipss->ipsec_system_policy.iph_gen;
	/*
	 * There is no policy latching for ICMP sockets because we can't
	 * decide on which policy to use until we see the packet and get
	 * type/code selectors.
	 */
	if (connp->conn_proto == IPPROTO_ICMP ||
	    connp->conn_proto == IPPROTO_ICMPV6) {
		connp->conn_in_enforce_policy =
		    connp->conn_out_enforce_policy = B_TRUE;
		if (connp->conn_latch != NULL) {
			IPLATCH_REFRELE(connp->conn_latch);
			connp->conn_latch = NULL;
		}
		if (connp->conn_latch_in_policy != NULL) {
			IPPOL_REFRELE(connp->conn_latch_in_policy);
			connp->conn_latch_in_policy = NULL;
		}
		if (connp->conn_latch_in_action != NULL) {
			IPACT_REFRELE(connp->conn_latch_in_action);
			connp->conn_latch_in_action = NULL;
		}
		if (connp->conn_ixa->ixa_ipsec_policy != NULL) {
			IPPOL_REFRELE(connp->conn_ixa->ixa_ipsec_policy);
			connp->conn_ixa->ixa_ipsec_policy = NULL;
		}
		if (connp->conn_ixa->ixa_ipsec_action != NULL) {
			IPACT_REFRELE(connp->conn_ixa->ixa_ipsec_action);
			connp->conn_ixa->ixa_ipsec_action = NULL;
		}
		connp->conn_ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
		return (0);
	}

	global_policy_present = isv4 ?
	    (ipss->ipsec_outbound_v4_policy_present ||
	    ipss->ipsec_inbound_v4_policy_present) :
	    (ipss->ipsec_outbound_v6_policy_present ||
	    ipss->ipsec_inbound_v6_policy_present);

	if ((connp->conn_policy != NULL) || global_policy_present) {
		ipsec_selector_t sel;
		ipsec_policy_t	*p;

		if (connp->conn_latch == NULL &&
		    (connp->conn_latch = iplatch_create()) == NULL) {
			return (ENOMEM);
		}

		bzero((void*)&sel, sizeof (sel));

		sel.ips_protocol = connp->conn_proto;
		sel.ips_local_port = connp->conn_lport;
		sel.ips_remote_port = connp->conn_fport;
		sel.ips_is_icmp_inv_acq = 0;
		sel.ips_isv4 = isv4;
		if (isv4) {
			sel.ips_local_addr_v4 = connp->conn_laddr_v4;
			sel.ips_remote_addr_v4 = connp->conn_faddr_v4;
		} else {
			sel.ips_local_addr_v6 = connp->conn_laddr_v6;
			sel.ips_remote_addr_v6 = connp->conn_faddr_v6;
		}

		p = ipsec_find_policy(IPSEC_TYPE_INBOUND, connp, &sel, ns);
		if (connp->conn_latch_in_policy != NULL)
			IPPOL_REFRELE(connp->conn_latch_in_policy);
		connp->conn_latch_in_policy = p;
		connp->conn_in_enforce_policy = (p != NULL);

		p = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, &sel, ns);
		if (connp->conn_ixa->ixa_ipsec_policy != NULL)
			IPPOL_REFRELE(connp->conn_ixa->ixa_ipsec_policy);
		connp->conn_ixa->ixa_ipsec_policy = p;
		connp->conn_out_enforce_policy = (p != NULL);
		if (p != NULL) {
			connp->conn_ixa->ixa_flags |= IXAF_IPSEC_SECURE;
			if (connp->conn_policy == NULL) {
				connp->conn_ixa->ixa_flags |=
				    IXAF_IPSEC_GLOBAL_POLICY;
			}
		} else {
			connp->conn_ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
		}
		/* Clear the latched actions too, in case we're recaching. */
		if (connp->conn_ixa->ixa_ipsec_action != NULL) {
			IPACT_REFRELE(connp->conn_ixa->ixa_ipsec_action);
			connp->conn_ixa->ixa_ipsec_action = NULL;
		}
		if (connp->conn_latch_in_action != NULL) {
			IPACT_REFRELE(connp->conn_latch_in_action);
			connp->conn_latch_in_action = NULL;
		}
		connp->conn_ixa->ixa_ipsec_src_port = sel.ips_local_port;
		connp->conn_ixa->ixa_ipsec_dst_port = sel.ips_remote_port;
		connp->conn_ixa->ixa_ipsec_icmp_type = sel.ips_icmp_type;
		connp->conn_ixa->ixa_ipsec_icmp_code = sel.ips_icmp_code;
		connp->conn_ixa->ixa_ipsec_proto = sel.ips_protocol;
	} else {
		connp->conn_ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
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
	return (0);
}

/*
 * When appropriate, this function caches outbound policy for faddr/fport.
 * It is used when we are not connected i.e., when we can not latch the
 * policy.
 */
void
ipsec_cache_outbound_policy(const conn_t *connp, const in6_addr_t *v6src,
    const in6_addr_t *v6dst, in_port_t dstport, ip_xmit_attr_t *ixa)
{
	boolean_t	isv4 = (ixa->ixa_flags & IXAF_IS_IPV4) != 0;
	boolean_t	global_policy_present;
	netstack_t	*ns = connp->conn_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ixa->ixa_ipsec_policy_gen = ipss->ipsec_system_policy.iph_gen;

	/*
	 * There is no policy caching for ICMP sockets because we can't
	 * decide on which policy to use until we see the packet and get
	 * type/code selectors.
	 */
	if (connp->conn_proto == IPPROTO_ICMP ||
	    connp->conn_proto == IPPROTO_ICMPV6) {
		ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
		if (ixa->ixa_ipsec_policy != NULL) {
			IPPOL_REFRELE(ixa->ixa_ipsec_policy);
			ixa->ixa_ipsec_policy = NULL;
		}
		if (ixa->ixa_ipsec_action != NULL) {
			IPACT_REFRELE(ixa->ixa_ipsec_action);
			ixa->ixa_ipsec_action = NULL;
		}
		return;
	}

	global_policy_present = isv4 ?
	    (ipss->ipsec_outbound_v4_policy_present ||
	    ipss->ipsec_inbound_v4_policy_present) :
	    (ipss->ipsec_outbound_v6_policy_present ||
	    ipss->ipsec_inbound_v6_policy_present);

	if ((connp->conn_policy != NULL) || global_policy_present) {
		ipsec_selector_t sel;
		ipsec_policy_t	*p;

		bzero((void*)&sel, sizeof (sel));

		sel.ips_protocol = connp->conn_proto;
		sel.ips_local_port = connp->conn_lport;
		sel.ips_remote_port = dstport;
		sel.ips_is_icmp_inv_acq = 0;
		sel.ips_isv4 = isv4;
		if (isv4) {
			IN6_V4MAPPED_TO_IPADDR(v6src, sel.ips_local_addr_v4);
			IN6_V4MAPPED_TO_IPADDR(v6dst, sel.ips_remote_addr_v4);
		} else {
			sel.ips_local_addr_v6 = *v6src;
			sel.ips_remote_addr_v6 = *v6dst;
		}

		p = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, &sel, ns);
		if (ixa->ixa_ipsec_policy != NULL)
			IPPOL_REFRELE(ixa->ixa_ipsec_policy);
		ixa->ixa_ipsec_policy = p;
		if (p != NULL) {
			ixa->ixa_flags |= IXAF_IPSEC_SECURE;
			if (connp->conn_policy == NULL)
				ixa->ixa_flags |= IXAF_IPSEC_GLOBAL_POLICY;
		} else {
			ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
		}
		/* Clear the latched actions too, in case we're recaching. */
		if (ixa->ixa_ipsec_action != NULL) {
			IPACT_REFRELE(ixa->ixa_ipsec_action);
			ixa->ixa_ipsec_action = NULL;
		}

		ixa->ixa_ipsec_src_port = sel.ips_local_port;
		ixa->ixa_ipsec_dst_port = sel.ips_remote_port;
		ixa->ixa_ipsec_icmp_type = sel.ips_icmp_type;
		ixa->ixa_ipsec_icmp_code = sel.ips_icmp_code;
		ixa->ixa_ipsec_proto = sel.ips_protocol;
	} else {
		ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
		if (ixa->ixa_ipsec_policy != NULL) {
			IPPOL_REFRELE(ixa->ixa_ipsec_policy);
			ixa->ixa_ipsec_policy = NULL;
		}
		if (ixa->ixa_ipsec_action != NULL) {
			IPACT_REFRELE(ixa->ixa_ipsec_action);
			ixa->ixa_ipsec_action = NULL;
		}
	}
}

/*
 * Returns B_FALSE if the policy has gone stale.
 */
boolean_t
ipsec_outbound_policy_current(ip_xmit_attr_t *ixa)
{
	ipsec_stack_t	*ipss = ixa->ixa_ipst->ips_netstack->netstack_ipsec;

	if (!(ixa->ixa_flags & IXAF_IPSEC_GLOBAL_POLICY))
		return (B_TRUE);

	return (ixa->ixa_ipsec_policy_gen == ipss->ipsec_system_policy.iph_gen);
}

void
iplatch_free(ipsec_latch_t *ipl)
{
	if (ipl->ipl_local_cid != NULL)
		IPSID_REFRELE(ipl->ipl_local_cid);
	if (ipl->ipl_remote_cid != NULL)
		IPSID_REFRELE(ipl->ipl_remote_cid);
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
ipsid_lookup(int idtype, char *idstring, netstack_t *ns)
{
	ipsid_t *retval;
	char *nstr;
	int idlen = strlen(idstring) + 1;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ipsif_t *bucket;

	bucket = &ipss->ipsec_ipsid_buckets[ipsid_hash(idtype, idstring)];

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
ipsid_gc(netstack_t *ns)
{
	int i, len;
	ipsid_t *id, *nid;
	ipsif_t *bucket;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	for (i = 0; i < IPSID_HASHSIZE; i++) {
		bucket = &ipss->ipsec_ipsid_buckets[i];
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
ipsid_init(netstack_t *ns)
{
	ipsif_t *bucket;
	int i;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	for (i = 0; i < IPSID_HASHSIZE; i++) {
		bucket = &ipss->ipsec_ipsid_buckets[i];
		mutex_init(&bucket->ipsif_lock, NULL, MUTEX_DEFAULT, NULL);
	}
}

/*
 * Free identity table (preparatory to module unload)
 */
static void
ipsid_fini(netstack_t *ns)
{
	ipsif_t *bucket;
	int i;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	for (i = 0; i < IPSID_HASHSIZE; i++) {
		bucket = &ipss->ipsec_ipsid_buckets[i];
		ASSERT(bucket->ipsif_head == NULL);
		mutex_destroy(&bucket->ipsif_lock);
	}
}

/*
 * Update the minimum and maximum supported key sizes for the
 * specified algorithm. Must be called while holding the algorithms lock.
 */
void
ipsec_alg_fix_min_max(ipsec_alginfo_t *alg, ipsec_algtype_t alg_type,
    netstack_t *ns)
{
	size_t crypto_min = (size_t)-1, crypto_max = 0;
	size_t cur_crypto_min, cur_crypto_max;
	boolean_t is_valid;
	crypto_mechanism_info_t *mech_infos;
	uint_t nmech_infos;
	int crypto_rc, i;
	crypto_mech_usage_t mask;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(MUTEX_HELD(&ipss->ipsec_alg_lock));

	/*
	 * Compute the min, max, and default key sizes (in number of
	 * increments to the default key size in bits) as defined
	 * by the algorithm mappings. This range of key sizes is used
	 * for policy related operations. The effective key sizes
	 * supported by the framework could be more limited than
	 * those defined for an algorithm.
	 */
	alg->alg_default_bits = alg->alg_key_sizes[0];
	alg->alg_default = 0;
	if (alg->alg_increment != 0) {
		/* key sizes are defined by range & increment */
		alg->alg_minbits = alg->alg_key_sizes[1];
		alg->alg_maxbits = alg->alg_key_sizes[2];
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
		if (alg_type == IPSEC_ALG_AUTH) {
			mask = CRYPTO_MECH_USAGE_MAC;
		} else {
			mask = CRYPTO_MECH_USAGE_ENCRYPT |
			    CRYPTO_MECH_USAGE_DECRYPT;
		}
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
		    CRYPTO_EFFECTIVELY_INFINITE) {
			crypto_max = (size_t)-1;
		} else if (cur_crypto_max > crypto_max) {
			crypto_max = cur_crypto_max;
		}

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

	/*
	 * For backwards compatability, assume that the IV length
	 * is the same as the data length.
	 */
	alg->alg_ivlen = alg->alg_datalen;

	/*
	 * Copy any algorithm parameters (if provided) into dedicated
	 * elements in the ipsec_alginfo_t structure.
	 * There may be a better place to put this code.
	 */
	for (i = 0; i < alg->alg_nparams; i++) {
		switch (i) {
		case 0:
			/* Initialisation Vector length (bytes) */
			alg->alg_ivlen =  alg->alg_params[0];
			break;
		case 1:
			/* Integrity Check Vector length (bytes) */
			alg->alg_icvlen = alg->alg_params[1];
			break;
		case 2:
			/* Salt length (bytes) */
			alg->alg_saltlen = (uint8_t)alg->alg_params[2];
			break;
		default:
			break;
		}
	}

	/* Default if the IV length is not specified. */
	if (alg_type == IPSEC_ALG_ENCR && alg->alg_ivlen == 0)
		alg->alg_ivlen = alg->alg_datalen;

	alg_flag_check(alg);

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
 * Sanity check parameters provided by ipsecalgs(1m). Assume that
 * the algoritm is marked as valid, there is a check at the top
 * of this function. If any of the checks below fail, the algorithm
 * entry is invalid.
 */
void
alg_flag_check(ipsec_alginfo_t *alg)
{
	alg->alg_flags &= ~ALG_FLAG_VALID;

	/*
	 * Can't have the algorithm marked as CCM and GCM.
	 * Check the ALG_FLAG_COMBINED and ALG_FLAG_COUNTERMODE
	 * flags are set for CCM & GCM.
	 */
	if ((alg->alg_flags & (ALG_FLAG_CCM|ALG_FLAG_GCM)) ==
	    (ALG_FLAG_CCM|ALG_FLAG_GCM))
		return;
	if (alg->alg_flags & (ALG_FLAG_CCM|ALG_FLAG_GCM)) {
		if (!(alg->alg_flags & ALG_FLAG_COUNTERMODE))
			return;
		if (!(alg->alg_flags & ALG_FLAG_COMBINED))
			return;
	}

	/*
	 * For ALG_FLAG_COUNTERMODE, check the parameters
	 * fit in the ipsec_nonce_t structure.
	 */
	if (alg->alg_flags & ALG_FLAG_COUNTERMODE) {
		if (alg->alg_ivlen != sizeof (((ipsec_nonce_t *)NULL)->iv))
			return;
		if (alg->alg_saltlen > sizeof (((ipsec_nonce_t *)NULL)->salt))
			return;
	}
	if ((alg->alg_flags & ALG_FLAG_COMBINED) &&
	    (alg->alg_icvlen == 0))
		return;

	/* all is well. */
	alg->alg_flags |= ALG_FLAG_VALID;
}

/*
 * Free the memory used by the specified algorithm.
 */
void
ipsec_alg_free(ipsec_alginfo_t *alg)
{
	if (alg == NULL)
		return;

	if (alg->alg_key_sizes != NULL) {
		kmem_free(alg->alg_key_sizes,
		    (alg->alg_nkey_sizes + 1) * sizeof (uint16_t));
		alg->alg_key_sizes = NULL;
	}
	if (alg->alg_block_sizes != NULL) {
		kmem_free(alg->alg_block_sizes,
		    (alg->alg_nblock_sizes + 1) * sizeof (uint16_t));
		alg->alg_block_sizes = NULL;
	}
	if (alg->alg_params != NULL) {
		kmem_free(alg->alg_params,
		    (alg->alg_nparams + 1) * sizeof (uint16_t));
		alg->alg_params = NULL;
	}
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
 *
 * Need to walk all stack instances since the callback is global
 * for all instances
 */
void
ipsec_prov_update_callback(uint32_t event, void *event_arg)
{
	netstack_handle_t nh;
	netstack_t *ns;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		ipsec_prov_update_callback_stack(event, event_arg, ns);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
}

static void
ipsec_prov_update_callback_stack(uint32_t event, void *event_arg,
    netstack_t *ns)
{
	crypto_notify_event_change_t *prov_change =
	    (crypto_notify_event_change_t *)event_arg;
	uint_t algidx, algid, algtype, mech_count, mech_idx;
	ipsec_alginfo_t *alg;
	ipsec_alginfo_t oalg;
	crypto_mech_name_t *mechs;
	boolean_t alg_changed = B_FALSE;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	/* ignore events for which we didn't register */
	if (event != CRYPTO_EVENT_MECHS_CHANGED) {
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
	mutex_enter(&ipss->ipsec_alg_lock);
	for (algtype = 0; algtype < IPSEC_NALGTYPES; algtype++) {
		for (algidx = 0; algidx < ipss->ipsec_nalgs[algtype];
		    algidx++) {

			algid = ipss->ipsec_sortlist[algtype][algidx];
			alg = ipss->ipsec_alglists[algtype][algid];
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
			ipsec_alg_fix_min_max(alg, algtype, ns);
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
				    CRYPTO_MECH_ADDED, ns);
		}
	}
	mutex_exit(&ipss->ipsec_alg_lock);
	crypto_free_mech_list(mechs, mech_count);

	if (alg_changed) {
		/*
		 * An algorithm has changed, i.e. it became valid or
		 * invalid, or its support key sizes have changed.
		 * Notify ipsecah and ipsecesp of this change so
		 * that they can send a SADB_REGISTER to their consumers.
		 */
		ipsecah_algs_changed(ns);
		ipsecesp_algs_changed(ns);
	}
}

/*
 * Registers with the crypto framework to be notified of crypto
 * providers changes. Used to update the algorithm tables and
 * to free or create context templates if needed. Invoked after IPsec
 * is loaded successfully.
 *
 * This is called separately for each IP instance, so we ensure we only
 * register once.
 */
void
ipsec_register_prov_update(void)
{
	if (prov_update_handle != NULL)
		return;

	prov_update_handle = crypto_notify_events(
	    ipsec_prov_update_callback, CRYPTO_EVENT_MECHS_CHANGED);
}

/*
 * Unregisters from the framework to be notified of crypto providers
 * changes. Called from ipsec_policy_g_destroy().
 */
static void
ipsec_unregister_prov_update(void)
{
	if (prov_update_handle != NULL)
		crypto_unnotify_events(prov_update_handle);
}

/*
 * Tunnel-mode support routines.
 */

/*
 * Returns an mblk chain suitable for putnext() if policies match and IPsec
 * SAs are available.  If there's no per-tunnel policy, or a match comes back
 * with no match, then still return the packet and have global policy take
 * a crack at it in IP.
 * This updates the ip_xmit_attr with the IPsec policy.
 *
 * Remember -> we can be forwarding packets.  Keep that in mind w.r.t.
 * inner-packet contents.
 */
mblk_t *
ipsec_tun_outbound(mblk_t *mp, iptun_t *iptun, ipha_t *inner_ipv4,
    ip6_t *inner_ipv6, ipha_t *outer_ipv4, ip6_t *outer_ipv6, int outer_hdr_len,
    ip_xmit_attr_t *ixa)
{
	ipsec_policy_head_t *polhead;
	ipsec_selector_t sel;
	mblk_t *nmp;
	boolean_t is_fragment;
	ipsec_policy_t *pol;
	ipsec_tun_pol_t *itp = iptun->iptun_itp;
	netstack_t *ns = iptun->iptun_ns;
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	ASSERT(outer_ipv6 != NULL && outer_ipv4 == NULL ||
	    outer_ipv4 != NULL && outer_ipv6 == NULL);
	/* We take care of inners in a bit. */

	/* Are the IPsec fields initialized at all? */
	if (!(ixa->ixa_flags & IXAF_IPSEC_SECURE)) {
		ASSERT(ixa->ixa_ipsec_policy == NULL);
		ASSERT(ixa->ixa_ipsec_latch == NULL);
		ASSERT(ixa->ixa_ipsec_action == NULL);
		ASSERT(ixa->ixa_ipsec_ah_sa == NULL);
		ASSERT(ixa->ixa_ipsec_esp_sa == NULL);
	}

	ASSERT(itp != NULL && (itp->itp_flags & ITPF_P_ACTIVE));
	polhead = itp->itp_policy;

	bzero(&sel, sizeof (sel));
	if (inner_ipv4 != NULL) {
		ASSERT(inner_ipv6 == NULL);
		sel.ips_isv4 = B_TRUE;
		sel.ips_local_addr_v4 = inner_ipv4->ipha_src;
		sel.ips_remote_addr_v4 = inner_ipv4->ipha_dst;
		sel.ips_protocol = (uint8_t)inner_ipv4->ipha_protocol;
	} else {
		ASSERT(inner_ipv6 != NULL);
		sel.ips_isv4 = B_FALSE;
		sel.ips_local_addr_v6 = inner_ipv6->ip6_src;
		/*
		 * We don't care about routing-header dests in the
		 * forwarding/tunnel path, so just grab ip6_dst.
		 */
		sel.ips_remote_addr_v6 = inner_ipv6->ip6_dst;
	}

	if (itp->itp_flags & ITPF_P_PER_PORT_SECURITY) {
		/*
		 * Caller can prepend the outer header, which means
		 * inner_ipv[46] may be stuck in the middle.  Pullup the whole
		 * mess now if need-be, for easier processing later.  Don't
		 * forget to rewire the outer header too.
		 */
		if (mp->b_cont != NULL) {
			nmp = msgpullup(mp, -1);
			if (nmp == NULL) {
				ip_drop_packet(mp, B_FALSE, NULL,
				    DROPPER(ipss, ipds_spd_nomem),
				    &ipss->ipsec_spd_dropper);
				return (NULL);
			}
			freemsg(mp);
			mp = nmp;
			if (outer_ipv4 != NULL)
				outer_ipv4 = (ipha_t *)mp->b_rptr;
			else
				outer_ipv6 = (ip6_t *)mp->b_rptr;
			if (inner_ipv4 != NULL) {
				inner_ipv4 =
				    (ipha_t *)(mp->b_rptr + outer_hdr_len);
			} else {
				inner_ipv6 =
				    (ip6_t *)(mp->b_rptr + outer_hdr_len);
			}
		}
		if (inner_ipv4 != NULL) {
			is_fragment = IS_V4_FRAGMENT(
			    inner_ipv4->ipha_fragment_offset_and_flags);
		} else {
			sel.ips_remote_addr_v6 = ip_get_dst_v6(inner_ipv6, mp,
			    &is_fragment);
		}

		if (is_fragment) {
			ipha_t *oiph;
			ipha_t *iph = NULL;
			ip6_t *ip6h = NULL;
			int hdr_len;
			uint16_t ip6_hdr_length;
			uint8_t v6_proto;
			uint8_t *v6_proto_p;

			/*
			 * We have a fragment we need to track!
			 */
			mp = ipsec_fragcache_add(&itp->itp_fragcache, NULL, mp,
			    outer_hdr_len, ipss);
			if (mp == NULL)
				return (NULL);
			ASSERT(mp->b_cont == NULL);

			/*
			 * If we get here, we have a full fragment chain
			 */

			oiph = (ipha_t *)mp->b_rptr;
			if (IPH_HDR_VERSION(oiph) == IPV4_VERSION) {
				hdr_len = ((outer_hdr_len != 0) ?
				    IPH_HDR_LENGTH(oiph) : 0);
				iph = (ipha_t *)(mp->b_rptr + hdr_len);
			} else {
				ASSERT(IPH_HDR_VERSION(oiph) == IPV6_VERSION);
				ip6h = (ip6_t *)mp->b_rptr;
				if (!ip_hdr_length_nexthdr_v6(mp, ip6h,
				    &ip6_hdr_length, &v6_proto_p)) {
					ip_drop_packet_chain(mp, B_FALSE, NULL,
					    DROPPER(ipss,
					    ipds_spd_malformed_packet),
					    &ipss->ipsec_spd_dropper);
					return (NULL);
				}
				hdr_len = ip6_hdr_length;
			}
			outer_hdr_len = hdr_len;

			if (sel.ips_isv4) {
				if (iph == NULL) {
					/* Was v6 outer */
					iph = (ipha_t *)(mp->b_rptr + hdr_len);
				}
				inner_ipv4 = iph;
				sel.ips_local_addr_v4 = inner_ipv4->ipha_src;
				sel.ips_remote_addr_v4 = inner_ipv4->ipha_dst;
				sel.ips_protocol =
				    (uint8_t)inner_ipv4->ipha_protocol;
			} else {
				inner_ipv6 = (ip6_t *)(mp->b_rptr +
				    hdr_len);
				sel.ips_local_addr_v6 = inner_ipv6->ip6_src;
				sel.ips_remote_addr_v6 = inner_ipv6->ip6_dst;
				if (!ip_hdr_length_nexthdr_v6(mp,
				    inner_ipv6, &ip6_hdr_length, &v6_proto_p)) {
					ip_drop_packet_chain(mp, B_FALSE, NULL,
					    DROPPER(ipss,
					    ipds_spd_malformed_frag),
					    &ipss->ipsec_spd_dropper);
					return (NULL);
				}
				v6_proto = *v6_proto_p;
				sel.ips_protocol = v6_proto;
#ifdef FRAGCACHE_DEBUG
				cmn_err(CE_WARN, "v6_sel.ips_protocol = %d\n",
				    sel.ips_protocol);
#endif
			}
			/* Ports are extracted below */
		}

		/* Get ports... */
		if (!ipsec_init_outbound_ports(&sel, mp,
		    inner_ipv4, inner_ipv6, outer_hdr_len, ipss)) {
			/* callee did ip_drop_packet_chain() on mp. */
			return (NULL);
		}
#ifdef FRAGCACHE_DEBUG
		if (inner_ipv4 != NULL)
			cmn_err(CE_WARN,
			    "(v4) sel.ips_protocol = %d, "
			    "sel.ips_local_port = %d, "
			    "sel.ips_remote_port = %d\n",
			    sel.ips_protocol, ntohs(sel.ips_local_port),
			    ntohs(sel.ips_remote_port));
		if (inner_ipv6 != NULL)
			cmn_err(CE_WARN,
			    "(v6) sel.ips_protocol = %d, "
			    "sel.ips_local_port = %d, "
			    "sel.ips_remote_port = %d\n",
			    sel.ips_protocol, ntohs(sel.ips_local_port),
			    ntohs(sel.ips_remote_port));
#endif
		/* Success so far! */
	}
	rw_enter(&polhead->iph_lock, RW_READER);
	pol = ipsec_find_policy_head(NULL, polhead, IPSEC_TYPE_OUTBOUND, &sel);
	rw_exit(&polhead->iph_lock);
	if (pol == NULL) {
		/*
		 * No matching policy on this tunnel, drop the packet.
		 *
		 * NOTE:  Tunnel-mode tunnels are different from the
		 * IP global transport mode policy head.  For a tunnel-mode
		 * tunnel, we drop the packet in lieu of passing it
		 * along accepted the way a global-policy miss would.
		 *
		 * NOTE2:  "negotiate transport" tunnels should match ALL
		 * inbound packets, but we do not uncomment the ASSERT()
		 * below because if/when we open PF_POLICY, a user can
		 * shoot him/her-self in the foot with a 0 priority.
		 */

		/* ASSERT(itp->itp_flags & ITPF_P_TUNNEL); */
#ifdef FRAGCACHE_DEBUG
		cmn_err(CE_WARN, "ipsec_tun_outbound(): No matching tunnel "
		    "per-port policy\n");
#endif
		ip_drop_packet_chain(mp, B_FALSE, NULL,
		    DROPPER(ipss, ipds_spd_explicit),
		    &ipss->ipsec_spd_dropper);
		return (NULL);
	}

#ifdef FRAGCACHE_DEBUG
	cmn_err(CE_WARN, "Having matching tunnel per-port policy\n");
#endif

	/*
	 * NOTE: ixa_cleanup() function will release pol references.
	 */
	ixa->ixa_ipsec_policy = pol;
	/*
	 * NOTE: There is a subtle difference between iptun_zoneid and
	 * iptun_connp->conn_zoneid explained in iptun_conn_create().  When
	 * interacting with the ip module, we must use conn_zoneid.
	 */
	ixa->ixa_zoneid = iptun->iptun_connp->conn_zoneid;

	ASSERT((outer_ipv4 != NULL) ? (ixa->ixa_flags & IXAF_IS_IPV4) :
	    !(ixa->ixa_flags & IXAF_IS_IPV4));
	ASSERT(ixa->ixa_ipsec_policy != NULL);
	ixa->ixa_flags |= IXAF_IPSEC_SECURE;

	if (!(itp->itp_flags & ITPF_P_TUNNEL)) {
		/* Set up transport mode for tunnelled packets. */
		ixa->ixa_ipsec_proto = (inner_ipv4 != NULL) ? IPPROTO_ENCAP :
		    IPPROTO_IPV6;
		return (mp);
	}

	/* Fill in tunnel-mode goodies here. */
	ixa->ixa_flags |= IXAF_IPSEC_TUNNEL;
	/* XXX Do I need to fill in all of the goodies here? */
	if (inner_ipv4) {
		ixa->ixa_ipsec_inaf = AF_INET;
		ixa->ixa_ipsec_insrc[0] =
		    pol->ipsp_sel->ipsl_key.ipsl_local.ipsad_v4;
		ixa->ixa_ipsec_indst[0] =
		    pol->ipsp_sel->ipsl_key.ipsl_remote.ipsad_v4;
	} else {
		ixa->ixa_ipsec_inaf = AF_INET6;
		ixa->ixa_ipsec_insrc[0] =
		    pol->ipsp_sel->ipsl_key.ipsl_local.ipsad_v6.s6_addr32[0];
		ixa->ixa_ipsec_insrc[1] =
		    pol->ipsp_sel->ipsl_key.ipsl_local.ipsad_v6.s6_addr32[1];
		ixa->ixa_ipsec_insrc[2] =
		    pol->ipsp_sel->ipsl_key.ipsl_local.ipsad_v6.s6_addr32[2];
		ixa->ixa_ipsec_insrc[3] =
		    pol->ipsp_sel->ipsl_key.ipsl_local.ipsad_v6.s6_addr32[3];
		ixa->ixa_ipsec_indst[0] =
		    pol->ipsp_sel->ipsl_key.ipsl_remote.ipsad_v6.s6_addr32[0];
		ixa->ixa_ipsec_indst[1] =
		    pol->ipsp_sel->ipsl_key.ipsl_remote.ipsad_v6.s6_addr32[1];
		ixa->ixa_ipsec_indst[2] =
		    pol->ipsp_sel->ipsl_key.ipsl_remote.ipsad_v6.s6_addr32[2];
		ixa->ixa_ipsec_indst[3] =
		    pol->ipsp_sel->ipsl_key.ipsl_remote.ipsad_v6.s6_addr32[3];
	}
	ixa->ixa_ipsec_insrcpfx = pol->ipsp_sel->ipsl_key.ipsl_local_pfxlen;
	ixa->ixa_ipsec_indstpfx = pol->ipsp_sel->ipsl_key.ipsl_remote_pfxlen;
	/* NOTE:  These are used for transport mode too. */
	ixa->ixa_ipsec_src_port = pol->ipsp_sel->ipsl_key.ipsl_lport;
	ixa->ixa_ipsec_dst_port = pol->ipsp_sel->ipsl_key.ipsl_rport;
	ixa->ixa_ipsec_proto = pol->ipsp_sel->ipsl_key.ipsl_proto;

	return (mp);
}

/*
 * NOTE: The following releases pol's reference and
 * calls ip_drop_packet() for me on NULL returns.
 */
mblk_t *
ipsec_check_ipsecin_policy_reasm(mblk_t *attr_mp, ipsec_policy_t *pol,
    ipha_t *inner_ipv4, ip6_t *inner_ipv6, uint64_t pkt_unique, netstack_t *ns)
{
	/* Assume attr_mp is a chain of b_next-linked ip_recv_attr mblk. */
	mblk_t *data_chain = NULL, *data_tail = NULL;
	mblk_t *next;
	mblk_t *data_mp;
	ip_recv_attr_t	iras;

	while (attr_mp != NULL) {
		ASSERT(ip_recv_attr_is_mblk(attr_mp));
		next = attr_mp->b_next;
		attr_mp->b_next = NULL;  /* No tripping asserts. */

		data_mp = attr_mp->b_cont;
		attr_mp->b_cont = NULL;
		if (!ip_recv_attr_from_mblk(attr_mp, &iras)) {
			/* The ill or ip_stack_t disappeared on us */
			freemsg(data_mp);	/* ip_drop_packet?? */
			ira_cleanup(&iras, B_TRUE);
			goto fail;
		}

		/*
		 * Need IPPOL_REFHOLD(pol) for extras because
		 * ipsecin_policy does the refrele.
		 */
		IPPOL_REFHOLD(pol);

		data_mp = ipsec_check_ipsecin_policy(data_mp, pol, inner_ipv4,
		    inner_ipv6, pkt_unique, &iras, ns);
		ira_cleanup(&iras, B_TRUE);

		if (data_mp == NULL)
			goto fail;

		if (data_tail == NULL) {
			/* First one */
			data_chain = data_tail = data_mp;
		} else {
			data_tail->b_next = data_mp;
			data_tail = data_mp;
		}
		attr_mp = next;
	}
	/*
	 * One last release because either the loop bumped it up, or we never
	 * called ipsec_check_ipsecin_policy().
	 */
	IPPOL_REFRELE(pol);

	/* data_chain is ready for return to tun module. */
	return (data_chain);

fail:
	/*
	 * Need to get rid of any extra pol
	 * references, and any remaining bits as well.
	 */
	IPPOL_REFRELE(pol);
	ipsec_freemsg_chain(data_chain);
	ipsec_freemsg_chain(next);	/* ipdrop stats? */
	return (NULL);
}

/*
 * Return a message if the inbound packet passed an IPsec policy check.  Returns
 * NULL if it failed or if it is a fragment needing its friends before a
 * policy check can be performed.
 *
 * Expects a non-NULL data_mp, and a non-NULL polhead.
 * The returned mblk may be a b_next chain of packets if fragments
 * neeeded to be collected for a proper policy check.
 *
 * This function calls ip_drop_packet() on data_mp if need be.
 *
 * NOTE:  outer_hdr_len is signed.  If it's a negative value, the caller
 * is inspecting an ICMP packet.
 */
mblk_t *
ipsec_tun_inbound(ip_recv_attr_t *ira, mblk_t *data_mp, ipsec_tun_pol_t *itp,
    ipha_t *inner_ipv4, ip6_t *inner_ipv6, ipha_t *outer_ipv4,
    ip6_t *outer_ipv6, int outer_hdr_len, netstack_t *ns)
{
	ipsec_policy_head_t *polhead;
	ipsec_selector_t sel;
	ipsec_policy_t *pol;
	uint16_t tmpport;
	selret_t rc;
	boolean_t port_policy_present, is_icmp, global_present;
	in6_addr_t tmpaddr;
	ipaddr_t tmp4;
	uint8_t flags, *inner_hdr;
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	sel.ips_is_icmp_inv_acq = 0;

	if (outer_ipv4 != NULL) {
		ASSERT(outer_ipv6 == NULL);
		global_present = ipss->ipsec_inbound_v4_policy_present;
	} else {
		ASSERT(outer_ipv6 != NULL);
		global_present = ipss->ipsec_inbound_v6_policy_present;
	}

	ASSERT(inner_ipv4 != NULL && inner_ipv6 == NULL ||
	    inner_ipv4 == NULL && inner_ipv6 != NULL);

	if (outer_hdr_len < 0) {
		outer_hdr_len = (-outer_hdr_len);
		is_icmp = B_TRUE;
	} else {
		is_icmp = B_FALSE;
	}

	if (itp != NULL && (itp->itp_flags & ITPF_P_ACTIVE)) {
		mblk_t *mp = data_mp;

		polhead = itp->itp_policy;
		/*
		 * We need to perform full Tunnel-Mode enforcement,
		 * and we need to have inner-header data for such enforcement.
		 *
		 * See ipsec_init_inbound_sel() for the 0x80000000 on inbound
		 * and on return.
		 */

		port_policy_present = ((itp->itp_flags &
		    ITPF_P_PER_PORT_SECURITY) ? B_TRUE : B_FALSE);
		/*
		 * NOTE:  Even if our policy is transport mode, set the
		 * SEL_TUNNEL_MODE flag so ipsec_init_inbound_sel() can
		 * do the right thing w.r.t. outer headers.
		 */
		flags = ((port_policy_present ? SEL_PORT_POLICY : SEL_NONE) |
		    (is_icmp ? SEL_IS_ICMP : SEL_NONE) | SEL_TUNNEL_MODE);

		rc = ipsec_init_inbound_sel(&sel, data_mp, inner_ipv4,
		    inner_ipv6, flags);

		switch (rc) {
		case SELRET_NOMEM:
			ip_drop_packet(data_mp, B_TRUE, NULL,
			    DROPPER(ipss, ipds_spd_nomem),
			    &ipss->ipsec_spd_dropper);
			return (NULL);
		case SELRET_TUNFRAG:
			/*
			 * At this point, if we're cleartext, we don't want
			 * to go there.
			 */
			if (!(ira->ira_flags & IRAF_IPSEC_SECURE)) {
				ip_drop_packet(data_mp, B_TRUE, NULL,
				    DROPPER(ipss, ipds_spd_got_clear),
				    &ipss->ipsec_spd_dropper);
				return (NULL);
			}

			/*
			 * Inner and outer headers may not be contiguous.
			 * Pullup the data_mp now to satisfy assumptions of
			 * ipsec_fragcache_add()
			 */
			if (data_mp->b_cont != NULL) {
				mblk_t *nmp;

				nmp = msgpullup(data_mp, -1);
				if (nmp == NULL) {
					ip_drop_packet(data_mp, B_TRUE, NULL,
					    DROPPER(ipss, ipds_spd_nomem),
					    &ipss->ipsec_spd_dropper);
					return (NULL);
				}
				freemsg(data_mp);
				data_mp = nmp;
				if (outer_ipv4 != NULL)
					outer_ipv4 =
					    (ipha_t *)data_mp->b_rptr;
				else
					outer_ipv6 =
					    (ip6_t *)data_mp->b_rptr;
				if (inner_ipv4 != NULL) {
					inner_ipv4 =
					    (ipha_t *)(data_mp->b_rptr +
					    outer_hdr_len);
				} else {
					inner_ipv6 =
					    (ip6_t *)(data_mp->b_rptr +
					    outer_hdr_len);
				}
			}

			/*
			 * If we need to queue the packet. First we
			 * get an mblk with the attributes. ipsec_fragcache_add
			 * will prepend that to the queued data and return
			 * a list of b_next messages each of which starts with
			 * the attribute mblk.
			 */
			mp = ip_recv_attr_to_mblk(ira);
			if (mp == NULL) {
				ip_drop_packet(data_mp, B_TRUE, NULL,
				    DROPPER(ipss, ipds_spd_nomem),
				    &ipss->ipsec_spd_dropper);
				return (NULL);
			}

			mp = ipsec_fragcache_add(&itp->itp_fragcache,
			    mp, data_mp, outer_hdr_len, ipss);

			if (mp == NULL) {
				/*
				 * Data is cached, fragment chain is not
				 * complete.
				 */
				return (NULL);
			}

			/*
			 * If we get here, we have a full fragment chain.
			 * Reacquire headers and selectors from first fragment.
			 */
			ASSERT(ip_recv_attr_is_mblk(mp));
			data_mp = mp->b_cont;
			inner_hdr = data_mp->b_rptr;
			if (outer_ipv4 != NULL) {
				inner_hdr += IPH_HDR_LENGTH(
				    (ipha_t *)data_mp->b_rptr);
			} else {
				inner_hdr += ip_hdr_length_v6(data_mp,
				    (ip6_t *)data_mp->b_rptr);
			}
			ASSERT(inner_hdr <= data_mp->b_wptr);

			if (inner_ipv4 != NULL) {
				inner_ipv4 = (ipha_t *)inner_hdr;
				inner_ipv6 = NULL;
			} else {
				inner_ipv6 = (ip6_t *)inner_hdr;
				inner_ipv4 = NULL;
			}

			/*
			 * Use SEL_TUNNEL_MODE to take into account the outer
			 * header.  Use SEL_POST_FRAG so we always get ports.
			 */
			rc = ipsec_init_inbound_sel(&sel, data_mp,
			    inner_ipv4, inner_ipv6,
			    SEL_TUNNEL_MODE | SEL_POST_FRAG);
			switch (rc) {
			case SELRET_SUCCESS:
				/*
				 * Get to same place as first caller's
				 * SELRET_SUCCESS case.
				 */
				break;
			case SELRET_NOMEM:
				ip_drop_packet_chain(mp, B_TRUE, NULL,
				    DROPPER(ipss, ipds_spd_nomem),
				    &ipss->ipsec_spd_dropper);
				return (NULL);
			case SELRET_BADPKT:
				ip_drop_packet_chain(mp, B_TRUE, NULL,
				    DROPPER(ipss, ipds_spd_malformed_frag),
				    &ipss->ipsec_spd_dropper);
				return (NULL);
			case SELRET_TUNFRAG:
				cmn_err(CE_WARN, "(TUNFRAG on 2nd call...)");
				/* FALLTHRU */
			default:
				cmn_err(CE_WARN, "ipsec_init_inbound_sel(mark2)"
				    " returns bizarro 0x%x", rc);
				/* Guaranteed panic! */
				ASSERT(rc == SELRET_NOMEM);
				return (NULL);
			}
			/* FALLTHRU */
		case SELRET_SUCCESS:
			/*
			 * Common case:
			 * No per-port policy or a non-fragment.  Keep going.
			 */
			break;
		case SELRET_BADPKT:
			/*
			 * We may receive ICMP (with IPv6 inner) packets that
			 * trigger this return value.  Send 'em in for
			 * enforcement checking.
			 */
			cmn_err(CE_NOTE, "ipsec_tun_inbound(): "
			    "sending 'bad packet' in for enforcement");
			break;
		default:
			cmn_err(CE_WARN,
			    "ipsec_init_inbound_sel() returns bizarro 0x%x",
			    rc);
			ASSERT(rc == SELRET_NOMEM);	/* Guaranteed panic! */
			return (NULL);
		}

		if (is_icmp) {
			/*
			 * Swap local/remote because this is an ICMP packet.
			 */
			tmpaddr = sel.ips_local_addr_v6;
			sel.ips_local_addr_v6 = sel.ips_remote_addr_v6;
			sel.ips_remote_addr_v6 = tmpaddr;
			tmpport = sel.ips_local_port;
			sel.ips_local_port = sel.ips_remote_port;
			sel.ips_remote_port = tmpport;
		}

		/* find_policy_head() */
		rw_enter(&polhead->iph_lock, RW_READER);
		pol = ipsec_find_policy_head(NULL, polhead, IPSEC_TYPE_INBOUND,
		    &sel);
		rw_exit(&polhead->iph_lock);
		if (pol != NULL) {
			uint64_t pkt_unique;

			if (!(ira->ira_flags & IRAF_IPSEC_SECURE)) {
				if (!pol->ipsp_act->ipa_allow_clear) {
					/*
					 * XXX should never get here with
					 * tunnel reassembled fragments?
					 */
					ASSERT(mp == data_mp);
					ip_drop_packet(data_mp, B_TRUE, NULL,
					    DROPPER(ipss, ipds_spd_got_clear),
					    &ipss->ipsec_spd_dropper);
					IPPOL_REFRELE(pol);
					return (NULL);
				} else {
					IPPOL_REFRELE(pol);
					return (mp);
				}
			}
			pkt_unique = SA_UNIQUE_ID(sel.ips_remote_port,
			    sel.ips_local_port,
			    (inner_ipv4 == NULL) ? IPPROTO_IPV6 :
			    IPPROTO_ENCAP, sel.ips_protocol);

			/*
			 * NOTE: The following releases pol's reference and
			 * calls ip_drop_packet() for me on NULL returns.
			 *
			 * "sel" is still good here, so let's use it!
			 */
			if (data_mp == mp) {
				/* A single packet without attributes */
				data_mp = ipsec_check_ipsecin_policy(data_mp,
				    pol, inner_ipv4, inner_ipv6, pkt_unique,
				    ira, ns);
			} else {
				/*
				 * We pass in the b_next chain of attr_mp's
				 * and get back a b_next chain of data_mp's.
				 */
				data_mp = ipsec_check_ipsecin_policy_reasm(mp,
				    pol, inner_ipv4, inner_ipv6, pkt_unique,
				    ns);
			}
			return (data_mp);
		}

		/*
		 * Else fallthru and check the global policy on the outer
		 * header(s) if this tunnel is an old-style transport-mode
		 * one.  Drop the packet explicitly (no policy entry) for
		 * a new-style tunnel-mode tunnel.
		 */
		if ((itp->itp_flags & ITPF_P_TUNNEL) && !is_icmp) {
			ip_drop_packet_chain(data_mp, B_TRUE, NULL,
			    DROPPER(ipss, ipds_spd_explicit),
			    &ipss->ipsec_spd_dropper);
			return (NULL);
		}
	}

	/*
	 * NOTE:  If we reach here, we will not have packet chains from
	 * fragcache_add(), because the only way I get chains is on a
	 * tunnel-mode tunnel, which either returns with a pass, or gets
	 * hit by the ip_drop_packet_chain() call right above here.
	 */
	ASSERT(data_mp->b_next == NULL);

	/* If no per-tunnel security, check global policy now. */
	if ((ira->ira_flags & IRAF_IPSEC_SECURE) && !global_present) {
		if (ira->ira_flags & IRAF_TRUSTED_ICMP) {
			/*
			 * This is an ICMP message that was geenrated locally.
			 * We should accept it.
			 */
			return (data_mp);
		}

		ip_drop_packet(data_mp, B_TRUE, NULL,
		    DROPPER(ipss, ipds_spd_got_secure),
		    &ipss->ipsec_spd_dropper);
		return (NULL);
	}

	if (is_icmp) {
		/*
		 * For ICMP packets, "outer_ipvN" is set to the outer header
		 * that is *INSIDE* the ICMP payload.  For global policy
		 * checking, we need to reverse src/dst on the payload in
		 * order to construct selectors appropriately.  See "ripha"
		 * constructions in ip.c.  To avoid a bug like 6478464 (see
		 * earlier in this file), we will actually exchange src/dst
		 * in the packet, and reverse if after the call to
		 * ipsec_check_global_policy().
		 */
		if (outer_ipv4 != NULL) {
			tmp4 = outer_ipv4->ipha_src;
			outer_ipv4->ipha_src = outer_ipv4->ipha_dst;
			outer_ipv4->ipha_dst = tmp4;
		} else {
			ASSERT(outer_ipv6 != NULL);
			tmpaddr = outer_ipv6->ip6_src;
			outer_ipv6->ip6_src = outer_ipv6->ip6_dst;
			outer_ipv6->ip6_dst = tmpaddr;
		}
	}

	data_mp = ipsec_check_global_policy(data_mp, NULL, outer_ipv4,
	    outer_ipv6, ira, ns);
	if (data_mp == NULL)
		return (NULL);

	if (is_icmp) {
		/* Set things back to normal. */
		if (outer_ipv4 != NULL) {
			tmp4 = outer_ipv4->ipha_src;
			outer_ipv4->ipha_src = outer_ipv4->ipha_dst;
			outer_ipv4->ipha_dst = tmp4;
		} else {
			/* No need for ASSERT()s now. */
			tmpaddr = outer_ipv6->ip6_src;
			outer_ipv6->ip6_src = outer_ipv6->ip6_dst;
			outer_ipv6->ip6_dst = tmpaddr;
		}
	}

	/*
	 * At this point, we pretend it's a cleartext accepted
	 * packet.
	 */
	return (data_mp);
}

/*
 * AVL comparison routine for our list of tunnel polheads.
 */
static int
tunnel_compare(const void *arg1, const void *arg2)
{
	ipsec_tun_pol_t *left, *right;
	int rc;

	left = (ipsec_tun_pol_t *)arg1;
	right = (ipsec_tun_pol_t *)arg2;

	rc = strncmp(left->itp_name, right->itp_name, LIFNAMSIZ);
	return (rc == 0 ? rc : (rc > 0 ? 1 : -1));
}

/*
 * Free a tunnel policy node.
 */
void
itp_free(ipsec_tun_pol_t *node, netstack_t *ns)
{
	if (node->itp_policy != NULL) {
		IPPH_REFRELE(node->itp_policy, ns);
		node->itp_policy = NULL;
	}
	if (node->itp_inactive != NULL) {
		IPPH_REFRELE(node->itp_inactive, ns);
		node->itp_inactive = NULL;
	}
	mutex_destroy(&node->itp_lock);
	kmem_free(node, sizeof (*node));
}

void
itp_unlink(ipsec_tun_pol_t *node, netstack_t *ns)
{
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	rw_enter(&ipss->ipsec_tunnel_policy_lock, RW_WRITER);
	ipss->ipsec_tunnel_policy_gen++;
	ipsec_fragcache_uninit(&node->itp_fragcache, ipss);
	avl_remove(&ipss->ipsec_tunnel_policies, node);
	rw_exit(&ipss->ipsec_tunnel_policy_lock);
	ITP_REFRELE(node, ns);
}

/*
 * Public interface to look up a tunnel security policy by name.  Used by
 * spdsock mostly.  Returns "node" with a bumped refcnt.
 */
ipsec_tun_pol_t *
get_tunnel_policy(char *name, netstack_t *ns)
{
	ipsec_tun_pol_t *node, lookup;
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	(void) strncpy(lookup.itp_name, name, LIFNAMSIZ);

	rw_enter(&ipss->ipsec_tunnel_policy_lock, RW_READER);
	node = (ipsec_tun_pol_t *)avl_find(&ipss->ipsec_tunnel_policies,
	    &lookup, NULL);
	if (node != NULL) {
		ITP_REFHOLD(node);
	}
	rw_exit(&ipss->ipsec_tunnel_policy_lock);

	return (node);
}

/*
 * Public interface to walk all tunnel security polcies.  Useful for spdsock
 * DUMP operations.  iterator() will not consume a reference.
 */
void
itp_walk(void (*iterator)(ipsec_tun_pol_t *, void *, netstack_t *),
    void *arg, netstack_t *ns)
{
	ipsec_tun_pol_t *node;
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	rw_enter(&ipss->ipsec_tunnel_policy_lock, RW_READER);
	for (node = avl_first(&ipss->ipsec_tunnel_policies); node != NULL;
	    node = AVL_NEXT(&ipss->ipsec_tunnel_policies, node)) {
		iterator(node, arg, ns);
	}
	rw_exit(&ipss->ipsec_tunnel_policy_lock);
}

/*
 * Initialize policy head.  This can only fail if there's a memory problem.
 */
static boolean_t
tunnel_polhead_init(ipsec_policy_head_t *iph, netstack_t *ns)
{
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	rw_init(&iph->iph_lock, NULL, RW_DEFAULT, NULL);
	iph->iph_refs = 1;
	iph->iph_gen = 0;
	if (ipsec_alloc_table(iph, ipss->ipsec_tun_spd_hashsize,
	    KM_SLEEP, B_FALSE, ns) != 0) {
		ipsec_polhead_free_table(iph);
		return (B_FALSE);
	}
	ipsec_polhead_init(iph, ipss->ipsec_tun_spd_hashsize);
	return (B_TRUE);
}

/*
 * Create a tunnel policy node with "name".  Set errno with
 * ENOMEM if there's a memory problem, and EEXIST if there's an existing
 * node.
 */
ipsec_tun_pol_t *
create_tunnel_policy(char *name, int *errno, uint64_t *gen, netstack_t *ns)
{
	ipsec_tun_pol_t *newbie, *existing;
	avl_index_t where;
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	newbie = kmem_zalloc(sizeof (*newbie), KM_NOSLEEP);
	if (newbie == NULL) {
		*errno = ENOMEM;
		return (NULL);
	}
	if (!ipsec_fragcache_init(&newbie->itp_fragcache)) {
		kmem_free(newbie, sizeof (*newbie));
		*errno = ENOMEM;
		return (NULL);
	}

	(void) strncpy(newbie->itp_name, name, LIFNAMSIZ);

	rw_enter(&ipss->ipsec_tunnel_policy_lock, RW_WRITER);
	existing = (ipsec_tun_pol_t *)avl_find(&ipss->ipsec_tunnel_policies,
	    newbie, &where);
	if (existing != NULL) {
		itp_free(newbie, ns);
		*errno = EEXIST;
		rw_exit(&ipss->ipsec_tunnel_policy_lock);
		return (NULL);
	}
	ipss->ipsec_tunnel_policy_gen++;
	*gen = ipss->ipsec_tunnel_policy_gen;
	newbie->itp_refcnt = 2;	/* One for the caller, one for the tree. */
	newbie->itp_next_policy_index = 1;
	avl_insert(&ipss->ipsec_tunnel_policies, newbie, where);
	mutex_init(&newbie->itp_lock, NULL, MUTEX_DEFAULT, NULL);
	newbie->itp_policy = kmem_zalloc(sizeof (ipsec_policy_head_t),
	    KM_NOSLEEP);
	if (newbie->itp_policy == NULL)
		goto nomem;
	newbie->itp_inactive = kmem_zalloc(sizeof (ipsec_policy_head_t),
	    KM_NOSLEEP);
	if (newbie->itp_inactive == NULL) {
		kmem_free(newbie->itp_policy, sizeof (ipsec_policy_head_t));
		goto nomem;
	}

	if (!tunnel_polhead_init(newbie->itp_policy, ns)) {
		kmem_free(newbie->itp_policy, sizeof (ipsec_policy_head_t));
		kmem_free(newbie->itp_inactive, sizeof (ipsec_policy_head_t));
		goto nomem;
	} else if (!tunnel_polhead_init(newbie->itp_inactive, ns)) {
		IPPH_REFRELE(newbie->itp_policy, ns);
		kmem_free(newbie->itp_inactive, sizeof (ipsec_policy_head_t));
		goto nomem;
	}
	rw_exit(&ipss->ipsec_tunnel_policy_lock);

	return (newbie);
nomem:
	*errno = ENOMEM;
	kmem_free(newbie, sizeof (*newbie));
	return (NULL);
}

/*
 * Given two addresses, find a tunnel instance's IPsec policy heads.
 * Returns NULL on failure.
 */
ipsec_tun_pol_t *
itp_get_byaddr(uint32_t *laddr, uint32_t *faddr, int af, ip_stack_t *ipst)
{
	conn_t *connp;
	iptun_t *iptun;
	ipsec_tun_pol_t *itp = NULL;

	/* Classifiers are used to "src" being foreign. */
	if (af == AF_INET) {
		connp = ipcl_iptun_classify_v4((ipaddr_t *)faddr,
		    (ipaddr_t *)laddr, ipst);
	} else {
		ASSERT(af == AF_INET6);
		ASSERT(!IN6_IS_ADDR_V4MAPPED((in6_addr_t *)laddr));
		ASSERT(!IN6_IS_ADDR_V4MAPPED((in6_addr_t *)faddr));
		connp = ipcl_iptun_classify_v6((in6_addr_t *)faddr,
		    (in6_addr_t *)laddr, ipst);
	}

	if (connp == NULL)
		return (NULL);

	if (IPCL_IS_IPTUN(connp)) {
		iptun = connp->conn_iptun;
		if (iptun != NULL) {
			itp = iptun->iptun_itp;
			if (itp != NULL) {
				/* Braces due to the macro's nature... */
				ITP_REFHOLD(itp);
			}
		}  /* Else itp is already NULL. */
	}

	CONN_DEC_REF(connp);
	return (itp);
}

/*
 * Frag cache code, based on SunScreen 3.2 source
 *	screen/kernel/common/screen_fragcache.c
 */

#define	IPSEC_FRAG_TTL_MAX	5
/*
 * Note that the following parameters create 256 hash buckets
 * with 1024 free entries to be distributed.  Things are cleaned
 * periodically and are attempted to be cleaned when there is no
 * free space, but this system errs on the side of dropping packets
 * over creating memory exhaustion.  We may decide to make hash
 * factor a tunable if this proves to be a bad decision.
 */
#define	IPSEC_FRAG_HASH_SLOTS	(1<<8)
#define	IPSEC_FRAG_HASH_FACTOR	4
#define	IPSEC_FRAG_HASH_SIZE	(IPSEC_FRAG_HASH_SLOTS * IPSEC_FRAG_HASH_FACTOR)

#define	IPSEC_FRAG_HASH_MASK		(IPSEC_FRAG_HASH_SLOTS - 1)
#define	IPSEC_FRAG_HASH_FUNC(id)	(((id) & IPSEC_FRAG_HASH_MASK) ^ \
					    (((id) / \
					    (ushort_t)IPSEC_FRAG_HASH_SLOTS) & \
					    IPSEC_FRAG_HASH_MASK))

/* Maximum fragments per packet.  48 bytes payload x 1366 packets > 64KB */
#define	IPSEC_MAX_FRAGS		1366

#define	V4_FRAG_OFFSET(ipha) ((ntohs(ipha->ipha_fragment_offset_and_flags) & \
				    IPH_OFFSET) << 3)
#define	V4_MORE_FRAGS(ipha) (ntohs(ipha->ipha_fragment_offset_and_flags) & \
		IPH_MF)

/*
 * Initialize an ipsec fragcache instance.
 * Returns B_FALSE if memory allocation fails.
 */
boolean_t
ipsec_fragcache_init(ipsec_fragcache_t *frag)
{
	ipsec_fragcache_entry_t *ftemp;
	int i;

	mutex_init(&frag->itpf_lock, NULL, MUTEX_DEFAULT, NULL);
	frag->itpf_ptr = (ipsec_fragcache_entry_t **)
	    kmem_zalloc(sizeof (ipsec_fragcache_entry_t *) *
	    IPSEC_FRAG_HASH_SLOTS, KM_NOSLEEP);
	if (frag->itpf_ptr == NULL)
		return (B_FALSE);

	ftemp = (ipsec_fragcache_entry_t *)
	    kmem_zalloc(sizeof (ipsec_fragcache_entry_t) *
	    IPSEC_FRAG_HASH_SIZE, KM_NOSLEEP);
	if (ftemp == NULL) {
		kmem_free(frag->itpf_ptr, sizeof (ipsec_fragcache_entry_t *) *
		    IPSEC_FRAG_HASH_SLOTS);
		return (B_FALSE);
	}

	frag->itpf_freelist = NULL;

	for (i = 0; i < IPSEC_FRAG_HASH_SIZE; i++) {
		ftemp->itpfe_next = frag->itpf_freelist;
		frag->itpf_freelist = ftemp;
		ftemp++;
	}

	frag->itpf_expire_hint = 0;

	return (B_TRUE);
}

void
ipsec_fragcache_uninit(ipsec_fragcache_t *frag, ipsec_stack_t *ipss)
{
	ipsec_fragcache_entry_t *fep;
	int i;

	mutex_enter(&frag->itpf_lock);
	if (frag->itpf_ptr) {
		/* Delete any existing fragcache entry chains */
		for (i = 0; i < IPSEC_FRAG_HASH_SLOTS; i++) {
			fep = (frag->itpf_ptr)[i];
			while (fep != NULL) {
				/* Returned fep is next in chain or NULL */
				fep = fragcache_delentry(i, fep, frag, ipss);
			}
		}
		/*
		 * Chase the pointers back to the beginning
		 * of the memory allocation and then
		 * get rid of the allocated freelist
		 */
		while (frag->itpf_freelist->itpfe_next != NULL)
			frag->itpf_freelist = frag->itpf_freelist->itpfe_next;
		/*
		 * XXX - If we ever dynamically grow the freelist
		 * then we'll have to free entries individually
		 * or determine how many entries or chunks we have
		 * grown since the initial allocation.
		 */
		kmem_free(frag->itpf_freelist,
		    sizeof (ipsec_fragcache_entry_t) *
		    IPSEC_FRAG_HASH_SIZE);
		/* Free the fragcache structure */
		kmem_free(frag->itpf_ptr,
		    sizeof (ipsec_fragcache_entry_t *) *
		    IPSEC_FRAG_HASH_SLOTS);
	}
	mutex_exit(&frag->itpf_lock);
	mutex_destroy(&frag->itpf_lock);
}

/*
 * Add a fragment to the fragment cache.   Consumes mp if NULL is returned.
 * Returns mp if a whole fragment has been assembled, NULL otherwise
 * The returned mp could be a b_next chain of fragments.
 *
 * The iramp argument is set on inbound; NULL if outbound.
 */
mblk_t *
ipsec_fragcache_add(ipsec_fragcache_t *frag, mblk_t *iramp, mblk_t *mp,
    int outer_hdr_len, ipsec_stack_t *ipss)
{
	boolean_t is_v4;
	time_t itpf_time;
	ipha_t *iph;
	ipha_t *oiph;
	ip6_t *ip6h = NULL;
	uint8_t v6_proto;
	uint8_t *v6_proto_p;
	uint16_t ip6_hdr_length;
	ip_pkt_t ipp;
	ip6_frag_t *fraghdr;
	ipsec_fragcache_entry_t *fep;
	int i;
	mblk_t *nmp, *prevmp;
	int firstbyte, lastbyte;
	int offset;
	int last;
	boolean_t inbound = (iramp != NULL);

#ifdef FRAGCACHE_DEBUG
	cmn_err(CE_WARN, "Fragcache: %s\n", inbound ? "INBOUND" : "OUTBOUND");
#endif
	/*
	 * You're on the slow path, so insure that every packet in the
	 * cache is a single-mblk one.
	 */
	if (mp->b_cont != NULL) {
		nmp = msgpullup(mp, -1);
		if (nmp == NULL) {
			ip_drop_packet(mp, inbound, NULL,
			    DROPPER(ipss, ipds_spd_nomem),
			    &ipss->ipsec_spd_dropper);
			if (inbound)
				(void) ip_recv_attr_free_mblk(iramp);
			return (NULL);
		}
		freemsg(mp);
		mp = nmp;
	}

	mutex_enter(&frag->itpf_lock);

	oiph  = (ipha_t *)mp->b_rptr;
	iph  = (ipha_t *)(mp->b_rptr + outer_hdr_len);

	if (IPH_HDR_VERSION(iph) == IPV4_VERSION) {
		is_v4 = B_TRUE;
	} else {
		ASSERT(IPH_HDR_VERSION(iph) == IPV6_VERSION);
		ip6h = (ip6_t *)(mp->b_rptr + outer_hdr_len);

		if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &ip6_hdr_length,
		    &v6_proto_p)) {
			/*
			 * Find upper layer protocol.
			 * If it fails we have a malformed packet
			 */
			mutex_exit(&frag->itpf_lock);
			ip_drop_packet(mp, inbound, NULL,
			    DROPPER(ipss, ipds_spd_malformed_packet),
			    &ipss->ipsec_spd_dropper);
			if (inbound)
				(void) ip_recv_attr_free_mblk(iramp);
			return (NULL);
		} else {
			v6_proto = *v6_proto_p;
		}


		bzero(&ipp, sizeof (ipp));
		(void) ip_find_hdr_v6(mp, ip6h, B_FALSE, &ipp, NULL);
		if (!(ipp.ipp_fields & IPPF_FRAGHDR)) {
			/*
			 * We think this is a fragment, but didn't find
			 * a fragment header.  Something is wrong.
			 */
			mutex_exit(&frag->itpf_lock);
			ip_drop_packet(mp, inbound, NULL,
			    DROPPER(ipss, ipds_spd_malformed_frag),
			    &ipss->ipsec_spd_dropper);
			if (inbound)
				(void) ip_recv_attr_free_mblk(iramp);
			return (NULL);
		}
		fraghdr = ipp.ipp_fraghdr;
		is_v4 = B_FALSE;
	}

	/* Anything to cleanup? */

	/*
	 * This cleanup call could be put in a timer loop
	 * but it may actually be just as reasonable a decision to
	 * leave it here.  The disadvantage is this only gets called when
	 * frags are added.  The advantage is that it is not
	 * susceptible to race conditions like a time-based cleanup
	 * may be.
	 */
	itpf_time = gethrestime_sec();
	if (itpf_time >= frag->itpf_expire_hint)
		ipsec_fragcache_clean(frag, ipss);

	/* Lookup to see if there is an existing entry */

	if (is_v4)
		i = IPSEC_FRAG_HASH_FUNC(iph->ipha_ident);
	else
		i = IPSEC_FRAG_HASH_FUNC(fraghdr->ip6f_ident);

	for (fep = (frag->itpf_ptr)[i]; fep; fep = fep->itpfe_next) {
		if (is_v4) {
			ASSERT(iph != NULL);
			if ((fep->itpfe_id == iph->ipha_ident) &&
			    (fep->itpfe_src == iph->ipha_src) &&
			    (fep->itpfe_dst == iph->ipha_dst) &&
			    (fep->itpfe_proto == iph->ipha_protocol))
				break;
		} else {
			ASSERT(fraghdr != NULL);
			ASSERT(fep != NULL);
			if ((fep->itpfe_id == fraghdr->ip6f_ident) &&
			    IN6_ARE_ADDR_EQUAL(&fep->itpfe_src6,
			    &ip6h->ip6_src) &&
			    IN6_ARE_ADDR_EQUAL(&fep->itpfe_dst6,
			    &ip6h->ip6_dst) && (fep->itpfe_proto == v6_proto))
				break;
		}
	}

	if (is_v4) {
		firstbyte = V4_FRAG_OFFSET(iph);
		lastbyte  = firstbyte + ntohs(iph->ipha_length) -
		    IPH_HDR_LENGTH(iph);
		last = (V4_MORE_FRAGS(iph) == 0);
#ifdef FRAGCACHE_DEBUG
		cmn_err(CE_WARN, "V4 fragcache: firstbyte = %d, lastbyte = %d, "
		    "is_last_frag = %d, id = %d, mp = %p\n", firstbyte,
		    lastbyte, last, iph->ipha_ident, mp);
#endif
	} else {
		firstbyte = ntohs(fraghdr->ip6f_offlg & IP6F_OFF_MASK);
		lastbyte  = firstbyte + ntohs(ip6h->ip6_plen) +
		    sizeof (ip6_t) - ip6_hdr_length;
		last = (fraghdr->ip6f_offlg & IP6F_MORE_FRAG) == 0;
#ifdef FRAGCACHE_DEBUG
		cmn_err(CE_WARN, "V6 fragcache: firstbyte = %d, lastbyte = %d, "
		    "is_last_frag = %d, id = %d, fraghdr = %p, mp = %p\n",
		    firstbyte, lastbyte, last, fraghdr->ip6f_ident, fraghdr,
		    mp);
#endif
	}

	/* check for bogus fragments and delete the entry */
	if (firstbyte > 0 && firstbyte <= 8) {
		if (fep != NULL)
			(void) fragcache_delentry(i, fep, frag, ipss);
		mutex_exit(&frag->itpf_lock);
		ip_drop_packet(mp, inbound, NULL,
		    DROPPER(ipss, ipds_spd_malformed_frag),
		    &ipss->ipsec_spd_dropper);
		if (inbound)
			(void) ip_recv_attr_free_mblk(iramp);
		return (NULL);
	}

	/* Not found, allocate a new entry */
	if (fep == NULL) {
		if (frag->itpf_freelist == NULL) {
			/* see if there is some space */
			ipsec_fragcache_clean(frag, ipss);
			if (frag->itpf_freelist == NULL) {
				mutex_exit(&frag->itpf_lock);
				ip_drop_packet(mp, inbound, NULL,
				    DROPPER(ipss, ipds_spd_nomem),
				    &ipss->ipsec_spd_dropper);
				if (inbound)
					(void) ip_recv_attr_free_mblk(iramp);
				return (NULL);
			}
		}

		fep = frag->itpf_freelist;
		frag->itpf_freelist = fep->itpfe_next;

		if (is_v4) {
			bcopy((caddr_t)&iph->ipha_src, (caddr_t)&fep->itpfe_src,
			    sizeof (struct in_addr));
			bcopy((caddr_t)&iph->ipha_dst, (caddr_t)&fep->itpfe_dst,
			    sizeof (struct in_addr));
			fep->itpfe_id = iph->ipha_ident;
			fep->itpfe_proto = iph->ipha_protocol;
			i = IPSEC_FRAG_HASH_FUNC(fep->itpfe_id);
		} else {
			bcopy((in6_addr_t *)&ip6h->ip6_src,
			    (in6_addr_t *)&fep->itpfe_src6,
			    sizeof (struct in6_addr));
			bcopy((in6_addr_t *)&ip6h->ip6_dst,
			    (in6_addr_t *)&fep->itpfe_dst6,
			    sizeof (struct in6_addr));
			fep->itpfe_id = fraghdr->ip6f_ident;
			fep->itpfe_proto = v6_proto;
			i = IPSEC_FRAG_HASH_FUNC(fep->itpfe_id);
		}
		itpf_time = gethrestime_sec();
		fep->itpfe_exp = itpf_time + IPSEC_FRAG_TTL_MAX + 1;
		fep->itpfe_last = 0;
		fep->itpfe_fraglist = NULL;
		fep->itpfe_depth = 0;
		fep->itpfe_next = (frag->itpf_ptr)[i];
		(frag->itpf_ptr)[i] = fep;

		if (frag->itpf_expire_hint > fep->itpfe_exp)
			frag->itpf_expire_hint = fep->itpfe_exp;

	}

	/* Insert it in the frag list */
	/* List is in order by starting offset of fragments */

	prevmp = NULL;
	for (nmp = fep->itpfe_fraglist; nmp; nmp = nmp->b_next) {
		ipha_t *niph;
		ipha_t *oniph;
		ip6_t *nip6h;
		ip_pkt_t nipp;
		ip6_frag_t *nfraghdr;
		uint16_t nip6_hdr_length;
		uint8_t *nv6_proto_p;
		int nfirstbyte, nlastbyte;
		char *data, *ndata;
		mblk_t *ndata_mp = (inbound ? nmp->b_cont : nmp);
		int hdr_len;

		oniph  = (ipha_t *)mp->b_rptr;
		nip6h = NULL;
		niph = NULL;

		/*
		 * Determine outer header type and length and set
		 * pointers appropriately
		 */

		if (IPH_HDR_VERSION(oniph) == IPV4_VERSION) {
			hdr_len = ((outer_hdr_len != 0) ?
			    IPH_HDR_LENGTH(oiph) : 0);
			niph = (ipha_t *)(ndata_mp->b_rptr + hdr_len);
		} else {
			ASSERT(IPH_HDR_VERSION(oniph) == IPV6_VERSION);
			ASSERT(ndata_mp->b_cont == NULL);
			nip6h = (ip6_t *)ndata_mp->b_rptr;
			(void) ip_hdr_length_nexthdr_v6(ndata_mp, nip6h,
			    &nip6_hdr_length, &v6_proto_p);
			hdr_len = ((outer_hdr_len != 0) ? nip6_hdr_length : 0);
		}

		/*
		 * Determine inner header type and length and set
		 * pointers appropriately
		 */

		if (is_v4) {
			if (niph == NULL) {
				/* Was v6 outer */
				niph = (ipha_t *)(ndata_mp->b_rptr + hdr_len);
			}
			nfirstbyte = V4_FRAG_OFFSET(niph);
			nlastbyte = nfirstbyte + ntohs(niph->ipha_length) -
			    IPH_HDR_LENGTH(niph);
		} else {
			ASSERT(ndata_mp->b_cont == NULL);
			nip6h = (ip6_t *)(ndata_mp->b_rptr + hdr_len);
			if (!ip_hdr_length_nexthdr_v6(ndata_mp, nip6h,
			    &nip6_hdr_length, &nv6_proto_p)) {
				mutex_exit(&frag->itpf_lock);
				ip_drop_packet_chain(nmp, inbound, NULL,
				    DROPPER(ipss, ipds_spd_malformed_frag),
				    &ipss->ipsec_spd_dropper);
				ipsec_freemsg_chain(ndata_mp);
				if (inbound)
					(void) ip_recv_attr_free_mblk(iramp);
				return (NULL);
			}
			bzero(&nipp, sizeof (nipp));
			(void) ip_find_hdr_v6(ndata_mp, nip6h, B_FALSE, &nipp,
			    NULL);
			nfraghdr = nipp.ipp_fraghdr;
			nfirstbyte = ntohs(nfraghdr->ip6f_offlg &
			    IP6F_OFF_MASK);
			nlastbyte  = nfirstbyte + ntohs(nip6h->ip6_plen) +
			    sizeof (ip6_t) - nip6_hdr_length;
		}

		/* Check for overlapping fragments */
		if (firstbyte >= nfirstbyte && firstbyte < nlastbyte) {
			/*
			 * Overlap Check:
			 *  ~~~~---------		# Check if the newly
			 * ~	ndata_mp|		# received fragment
			 *  ~~~~---------		# overlaps with the
			 *	 ---------~~~~~~	# current fragment.
			 *	|    mp		~
			 *	 ---------~~~~~~
			 */
			if (is_v4) {
				data  = (char *)iph  + IPH_HDR_LENGTH(iph) +
				    firstbyte - nfirstbyte;
				ndata = (char *)niph + IPH_HDR_LENGTH(niph);
			} else {
				data  = (char *)ip6h  +
				    nip6_hdr_length + firstbyte -
				    nfirstbyte;
				ndata = (char *)nip6h + nip6_hdr_length;
			}
			if (bcmp(data, ndata, MIN(lastbyte, nlastbyte) -
			    firstbyte)) {
				/* Overlapping data does not match */
				(void) fragcache_delentry(i, fep, frag, ipss);
				mutex_exit(&frag->itpf_lock);
				ip_drop_packet(mp, inbound, NULL,
				    DROPPER(ipss, ipds_spd_overlap_frag),
				    &ipss->ipsec_spd_dropper);
				if (inbound)
					(void) ip_recv_attr_free_mblk(iramp);
				return (NULL);
			}
			/* Part of defense for jolt2.c fragmentation attack */
			if (firstbyte >= nfirstbyte && lastbyte <= nlastbyte) {
				/*
				 * Check for identical or subset fragments:
				 *  ----------	    ~~~~--------~~~~~
				 * |    nmp   | or  ~	   nmp	    ~
				 *  ----------	    ~~~~--------~~~~~
				 *  ----------		  ------
				 * |	mp    |		 |  mp  |
				 *  ----------		  ------
				 */
				mutex_exit(&frag->itpf_lock);
				ip_drop_packet(mp, inbound, NULL,
				    DROPPER(ipss, ipds_spd_evil_frag),
				    &ipss->ipsec_spd_dropper);
				if (inbound)
					(void) ip_recv_attr_free_mblk(iramp);
				return (NULL);
			}

		}

		/* Correct location for this fragment? */
		if (firstbyte <= nfirstbyte) {
			/*
			 * Check if the tail end of the new fragment overlaps
			 * with the head of the current fragment.
			 *	  --------~~~~~~~
			 *	 |    nmp	~
			 *	  --------~~~~~~~
			 *  ~~~~~--------
			 *  ~	mp	 |
			 *  ~~~~~--------
			 */
			if (lastbyte > nfirstbyte) {
				/* Fragments overlap */
				data  = (char *)iph  + IPH_HDR_LENGTH(iph) +
				    firstbyte - nfirstbyte;
				ndata = (char *)niph + IPH_HDR_LENGTH(niph);
				if (is_v4) {
					data  = (char *)iph +
					    IPH_HDR_LENGTH(iph) + firstbyte -
					    nfirstbyte;
					ndata = (char *)niph +
					    IPH_HDR_LENGTH(niph);
				} else {
					data  = (char *)ip6h  +
					    nip6_hdr_length + firstbyte -
					    nfirstbyte;
					ndata = (char *)nip6h + nip6_hdr_length;
				}
				if (bcmp(data, ndata, MIN(lastbyte, nlastbyte)
				    - nfirstbyte)) {
					/* Overlap mismatch */
					(void) fragcache_delentry(i, fep, frag,
					    ipss);
					mutex_exit(&frag->itpf_lock);
					ip_drop_packet(mp, inbound, NULL,
					    DROPPER(ipss,
					    ipds_spd_overlap_frag),
					    &ipss->ipsec_spd_dropper);
					if (inbound) {
						(void) ip_recv_attr_free_mblk(
						    iramp);
					}
					return (NULL);
				}
			}

			/*
			 * Fragment does not illegally overlap and can now
			 * be inserted into the chain
			 */
			break;
		}

		prevmp = nmp;
	}
	/* Prepend the attributes before we link it in */
	if (iramp != NULL) {
		ASSERT(iramp->b_cont == NULL);
		iramp->b_cont = mp;
		mp = iramp;
		iramp = NULL;
	}
	mp->b_next = nmp;

	if (prevmp == NULL) {
		fep->itpfe_fraglist = mp;
	} else {
		prevmp->b_next = mp;
	}
	if (last)
		fep->itpfe_last = 1;

	/* Part of defense for jolt2.c fragmentation attack */
	if (++(fep->itpfe_depth) > IPSEC_MAX_FRAGS) {
		(void) fragcache_delentry(i, fep, frag, ipss);
		mutex_exit(&frag->itpf_lock);
		if (inbound)
			mp = ip_recv_attr_free_mblk(mp);

		ip_drop_packet(mp, inbound, NULL,
		    DROPPER(ipss, ipds_spd_max_frags),
		    &ipss->ipsec_spd_dropper);
		return (NULL);
	}

	/* Check for complete packet */

	if (!fep->itpfe_last) {
		mutex_exit(&frag->itpf_lock);
#ifdef FRAGCACHE_DEBUG
		cmn_err(CE_WARN, "Fragment cached, last not yet seen.\n");
#endif
		return (NULL);
	}

	offset = 0;
	for (mp = fep->itpfe_fraglist; mp; mp = mp->b_next) {
		mblk_t *data_mp = (inbound ? mp->b_cont : mp);
		int hdr_len;

		oiph  = (ipha_t *)data_mp->b_rptr;
		ip6h = NULL;
		iph = NULL;

		if (IPH_HDR_VERSION(oiph) == IPV4_VERSION) {
			hdr_len = ((outer_hdr_len != 0) ?
			    IPH_HDR_LENGTH(oiph) : 0);
			iph = (ipha_t *)(data_mp->b_rptr + hdr_len);
		} else {
			ASSERT(IPH_HDR_VERSION(oiph) == IPV6_VERSION);
			ASSERT(data_mp->b_cont == NULL);
			ip6h = (ip6_t *)data_mp->b_rptr;
			(void) ip_hdr_length_nexthdr_v6(data_mp, ip6h,
			    &ip6_hdr_length, &v6_proto_p);
			hdr_len = ((outer_hdr_len != 0) ? ip6_hdr_length : 0);
		}

		/* Calculate current fragment start/end */
		if (is_v4) {
			if (iph == NULL) {
				/* Was v6 outer */
				iph = (ipha_t *)(data_mp->b_rptr + hdr_len);
			}
			firstbyte = V4_FRAG_OFFSET(iph);
			lastbyte = firstbyte + ntohs(iph->ipha_length) -
			    IPH_HDR_LENGTH(iph);
		} else {
			ASSERT(data_mp->b_cont == NULL);
			ip6h = (ip6_t *)(data_mp->b_rptr + hdr_len);
			if (!ip_hdr_length_nexthdr_v6(data_mp, ip6h,
			    &ip6_hdr_length, &v6_proto_p)) {
				mutex_exit(&frag->itpf_lock);
				ip_drop_packet_chain(mp, inbound, NULL,
				    DROPPER(ipss, ipds_spd_malformed_frag),
				    &ipss->ipsec_spd_dropper);
				return (NULL);
			}
			v6_proto = *v6_proto_p;
			bzero(&ipp, sizeof (ipp));
			(void) ip_find_hdr_v6(data_mp, ip6h, B_FALSE, &ipp,
			    NULL);
			fraghdr = ipp.ipp_fraghdr;
			firstbyte = ntohs(fraghdr->ip6f_offlg &
			    IP6F_OFF_MASK);
			lastbyte  = firstbyte + ntohs(ip6h->ip6_plen) +
			    sizeof (ip6_t) - ip6_hdr_length;
		}

		/*
		 * If this fragment is greater than current offset,
		 * we have a missing fragment so return NULL
		 */
		if (firstbyte > offset) {
			mutex_exit(&frag->itpf_lock);
#ifdef FRAGCACHE_DEBUG
			/*
			 * Note, this can happen when the last frag
			 * gets sent through because it is smaller
			 * than the MTU.  It is not necessarily an
			 * error condition.
			 */
			cmn_err(CE_WARN, "Frag greater than offset! : "
			    "missing fragment: firstbyte = %d, offset = %d, "
			    "mp = %p\n", firstbyte, offset, mp);
#endif
			return (NULL);
		}
#ifdef FRAGCACHE_DEBUG
		cmn_err(CE_WARN, "Frag offsets : "
		    "firstbyte = %d, offset = %d, mp = %p\n",
		    firstbyte, offset, mp);
#endif

		/*
		 * If we are at the last fragment, we have the complete
		 * packet, so rechain things and return it to caller
		 * for processing
		 */

		if ((is_v4 && !V4_MORE_FRAGS(iph)) ||
		    (!is_v4 && !(fraghdr->ip6f_offlg & IP6F_MORE_FRAG))) {
			mp = fep->itpfe_fraglist;
			fep->itpfe_fraglist = NULL;
			(void) fragcache_delentry(i, fep, frag, ipss);
			mutex_exit(&frag->itpf_lock);

			if ((is_v4 && (firstbyte + ntohs(iph->ipha_length) >
			    65535)) || (!is_v4 && (firstbyte +
			    ntohs(ip6h->ip6_plen) > 65535))) {
				/* It is an invalid "ping-o-death" packet */
				/* Discard it */
				ip_drop_packet_chain(mp, inbound, NULL,
				    DROPPER(ipss, ipds_spd_evil_frag),
				    &ipss->ipsec_spd_dropper);
				return (NULL);
			}
#ifdef FRAGCACHE_DEBUG
			cmn_err(CE_WARN, "Fragcache returning mp = %p, "
			    "mp->b_next = %p", mp, mp->b_next);
#endif
			/*
			 * For inbound case, mp has attrmp b_next'd chain
			 * For outbound case, it is just data mp chain
			 */
			return (mp);
		}

		/*
		 * Update new ending offset if this
		 * fragment extends the packet
		 */
		if (offset < lastbyte)
			offset = lastbyte;
	}

	mutex_exit(&frag->itpf_lock);

	/* Didn't find last fragment, so return NULL */
	return (NULL);
}

static void
ipsec_fragcache_clean(ipsec_fragcache_t *frag, ipsec_stack_t *ipss)
{
	ipsec_fragcache_entry_t *fep;
	int i;
	ipsec_fragcache_entry_t *earlyfep = NULL;
	time_t itpf_time;
	int earlyexp;
	int earlyi = 0;

	ASSERT(MUTEX_HELD(&frag->itpf_lock));

	itpf_time = gethrestime_sec();
	earlyexp = itpf_time + 10000;

	for (i = 0; i < IPSEC_FRAG_HASH_SLOTS; i++) {
		fep = (frag->itpf_ptr)[i];
		while (fep) {
			if (fep->itpfe_exp < itpf_time) {
				/* found */
				fep = fragcache_delentry(i, fep, frag, ipss);
			} else {
				if (fep->itpfe_exp < earlyexp) {
					earlyfep = fep;
					earlyexp = fep->itpfe_exp;
					earlyi = i;
				}
				fep = fep->itpfe_next;
			}
		}
	}

	frag->itpf_expire_hint = earlyexp;

	/* if (!found) */
	if (frag->itpf_freelist == NULL)
		(void) fragcache_delentry(earlyi, earlyfep, frag, ipss);
}

static ipsec_fragcache_entry_t *
fragcache_delentry(int slot, ipsec_fragcache_entry_t *fep,
    ipsec_fragcache_t *frag, ipsec_stack_t *ipss)
{
	ipsec_fragcache_entry_t *targp;
	ipsec_fragcache_entry_t *nextp = fep->itpfe_next;

	ASSERT(MUTEX_HELD(&frag->itpf_lock));

	/* Free up any fragment list still in cache entry */
	if (fep->itpfe_fraglist != NULL) {
		ip_drop_packet_chain(fep->itpfe_fraglist,
		    ip_recv_attr_is_mblk(fep->itpfe_fraglist), NULL,
		    DROPPER(ipss, ipds_spd_expired_frags),
		    &ipss->ipsec_spd_dropper);
	}
	fep->itpfe_fraglist = NULL;

	targp = (frag->itpf_ptr)[slot];
	ASSERT(targp != 0);

	if (targp == fep) {
		/* unlink from head of hash chain */
		(frag->itpf_ptr)[slot] = nextp;
		/* link into free list */
		fep->itpfe_next = frag->itpf_freelist;
		frag->itpf_freelist = fep;
		return (nextp);
	}

	/* maybe should use double linked list to make update faster */
	/* must be past front of chain */
	while (targp) {
		if (targp->itpfe_next == fep) {
			/* unlink from hash chain */
			targp->itpfe_next = nextp;
			/* link into free list */
			fep->itpfe_next = frag->itpf_freelist;
			frag->itpf_freelist = fep;
			return (nextp);
		}
		targp = targp->itpfe_next;
		ASSERT(targp != 0);
	}
	/* NOTREACHED */
	return (NULL);
}
