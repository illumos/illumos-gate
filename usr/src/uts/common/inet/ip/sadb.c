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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/tihdr.h>
#include <sys/atomic.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/zone.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/pfkeyv2.h>
#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip6.h>
#include <inet/ipsec_info.h>
#include <inet/tcp.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/ipsecah.h>
#include <inet/ipsecesp.h>
#include <sys/random.h>
#include <sys/dlpi.h>
#include <sys/iphada.h>
#include <inet/ip_if.h>
#include <inet/ipdrop.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <inet/tun.h>

/*
 * This source file contains Security Association Database (SADB) common
 * routines.  They are linked in with the AH module.  Since AH has no chance
 * of falling under export control, it was safe to link it in there.
 */

static mblk_t *sadb_extended_acquire(ipsec_selector_t *, ipsec_policy_t *,
    ipsec_action_t *, boolean_t, uint32_t, uint32_t, netstack_t *);
static void sadb_ill_df(ill_t *, mblk_t *, isaf_t *, int, boolean_t);
static ipsa_t *sadb_torch_assoc(isaf_t *, ipsa_t *, boolean_t, mblk_t **);
static void sadb_drain_torchq(queue_t *, mblk_t *);
static void sadb_destroy_acqlist(iacqf_t **, uint_t, boolean_t,
			    netstack_t *);
static void sadb_destroy(sadb_t *, netstack_t *);
static mblk_t *sadb_sa2msg(ipsa_t *, sadb_msg_t *);

static time_t sadb_add_time(time_t, uint64_t);
static void lifetime_fuzz(ipsa_t *);
static void age_pair_peer_list(templist_t *, sadb_t *, boolean_t);

/*
 * ipsacq_maxpackets is defined here to make it tunable
 * from /etc/system.
 */
extern uint64_t ipsacq_maxpackets;

#define	SET_EXPIRE(sa, delta, exp) {				\
	if (((sa)->ipsa_ ## delta) != 0) {				\
		(sa)->ipsa_ ## exp = sadb_add_time((sa)->ipsa_addtime,	\
			(sa)->ipsa_ ## delta);				\
	}								\
}

#define	UPDATE_EXPIRE(sa, delta, exp) {					\
	if (((sa)->ipsa_ ## delta) != 0) {				\
		time_t tmp = sadb_add_time((sa)->ipsa_usetime,		\
			(sa)->ipsa_ ## delta);				\
		if (((sa)->ipsa_ ## exp) == 0)				\
			(sa)->ipsa_ ## exp = tmp;			\
		else							\
			(sa)->ipsa_ ## exp = 				\
			    MIN((sa)->ipsa_ ## exp, tmp); 		\
	}								\
}


/* wrap the macro so we can pass it as a function pointer */
void
sadb_sa_refrele(void *target)
{
	IPSA_REFRELE(((ipsa_t *)target));
}

/*
 * We presume that sizeof (long) == sizeof (time_t) and that time_t is
 * a signed type.
 */
#define	TIME_MAX LONG_MAX

/*
 * PF_KEY gives us lifetimes in uint64_t seconds.  We presume that
 * time_t is defined to be a signed type with the same range as
 * "long".  On ILP32 systems, we thus run the risk of wrapping around
 * at end of time, as well as "overwrapping" the clock back around
 * into a seemingly valid but incorrect future date earlier than the
 * desired expiration.
 *
 * In order to avoid odd behavior (either negative lifetimes or loss
 * of high order bits) when someone asks for bizarrely long SA
 * lifetimes, we do a saturating add for expire times.
 *
 * We presume that ILP32 systems will be past end of support life when
 * the 32-bit time_t overflows (a dangerous assumption, mind you..).
 *
 * On LP64, 2^64 seconds are about 5.8e11 years, at which point we
 * will hopefully have figured out clever ways to avoid the use of
 * fixed-sized integers in computation.
 */
static time_t
sadb_add_time(time_t base, uint64_t delta)
{
	time_t sum;

	/*
	 * Clip delta to the maximum possible time_t value to
	 * prevent "overwrapping" back into a shorter-than-desired
	 * future time.
	 */
	if (delta > TIME_MAX)
		delta = TIME_MAX;
	/*
	 * This sum may still overflow.
	 */
	sum = base + delta;

	/*
	 * .. so if the result is less than the base, we overflowed.
	 */
	if (sum < base)
		sum = TIME_MAX;

	return (sum);
}

/*
 * Callers of this function have already created a working security
 * association, and have found the appropriate table & hash chain.  All this
 * function does is check duplicates, and insert the SA.  The caller needs to
 * hold the hash bucket lock and increment the refcnt before insertion.
 *
 * Return 0 if success, EEXIST if collision.
 */
#define	SA_UNIQUE_MATCH(sa1, sa2) \
	(((sa1)->ipsa_unique_id & (sa1)->ipsa_unique_mask) == \
	((sa2)->ipsa_unique_id & (sa2)->ipsa_unique_mask))

int
sadb_insertassoc(ipsa_t *ipsa, isaf_t *bucket)
{
	ipsa_t **ptpn = NULL;
	ipsa_t *walker;
	boolean_t unspecsrc;

	ASSERT(MUTEX_HELD(&bucket->isaf_lock));

	unspecsrc = IPSA_IS_ADDR_UNSPEC(ipsa->ipsa_srcaddr, ipsa->ipsa_addrfam);

	walker = bucket->isaf_ipsa;
	ASSERT(walker == NULL || ipsa->ipsa_addrfam == walker->ipsa_addrfam);

	/*
	 * Find insertion point (pointed to with **ptpn).  Insert at the head
	 * of the list unless there's an unspecified source address, then
	 * insert it after the last SA with a specified source address.
	 *
	 * BTW, you'll have to walk the whole chain, matching on {DST, SPI}
	 * checking for collisions.
	 */

	while (walker != NULL) {
		if (IPSA_ARE_ADDR_EQUAL(walker->ipsa_dstaddr,
		    ipsa->ipsa_dstaddr, ipsa->ipsa_addrfam)) {
			if (walker->ipsa_spi == ipsa->ipsa_spi)
				return (EEXIST);

			mutex_enter(&walker->ipsa_lock);
			if (ipsa->ipsa_state == IPSA_STATE_MATURE &&
			    (walker->ipsa_flags & IPSA_F_USED) &&
			    SA_UNIQUE_MATCH(walker, ipsa)) {
				walker->ipsa_flags |= IPSA_F_CINVALID;
			}
			mutex_exit(&walker->ipsa_lock);
		}

		if (ptpn == NULL && unspecsrc) {
			if (IPSA_IS_ADDR_UNSPEC(walker->ipsa_srcaddr,
			    walker->ipsa_addrfam))
				ptpn = walker->ipsa_ptpn;
			else if (walker->ipsa_next == NULL)
				ptpn = &walker->ipsa_next;
		}

		walker = walker->ipsa_next;
	}

	if (ptpn == NULL)
		ptpn = &bucket->isaf_ipsa;
	ipsa->ipsa_next = *ptpn;
	ipsa->ipsa_ptpn = ptpn;
	if (ipsa->ipsa_next != NULL)
		ipsa->ipsa_next->ipsa_ptpn = &ipsa->ipsa_next;
	*ptpn = ipsa;
	ipsa->ipsa_linklock = &bucket->isaf_lock;

	return (0);
}
#undef SA_UNIQUE_MATCH

/*
 * Free a security association.  Its reference count is 0, which means
 * I must free it.  The SA must be unlocked and must not be linked into
 * any fanout list.
 */
static void
sadb_freeassoc(ipsa_t *ipsa)
{
	ipsec_stack_t	*ipss = ipsa->ipsa_netstack->netstack_ipsec;

	ASSERT(ipss != NULL);
	ASSERT(!MUTEX_HELD(&ipsa->ipsa_lock));
	ASSERT(ipsa->ipsa_refcnt == 0);
	ASSERT(ipsa->ipsa_next == NULL);
	ASSERT(ipsa->ipsa_ptpn == NULL);

	ip_drop_packet(sadb_clear_lpkt(ipsa), B_TRUE, NULL, NULL,
	    DROPPER(ipss, ipds_sadb_inlarval_timeout),
	    &ipss->ipsec_sadb_dropper);

	mutex_enter(&ipsa->ipsa_lock);
	ipsec_destroy_ctx_tmpl(ipsa, IPSEC_ALG_AUTH);
	ipsec_destroy_ctx_tmpl(ipsa, IPSEC_ALG_ENCR);
	mutex_exit(&ipsa->ipsa_lock);

	/* bzero() these fields for paranoia's sake. */
	if (ipsa->ipsa_authkey != NULL) {
		bzero(ipsa->ipsa_authkey, ipsa->ipsa_authkeylen);
		kmem_free(ipsa->ipsa_authkey, ipsa->ipsa_authkeylen);
	}
	if (ipsa->ipsa_encrkey != NULL) {
		bzero(ipsa->ipsa_encrkey, ipsa->ipsa_encrkeylen);
		kmem_free(ipsa->ipsa_encrkey, ipsa->ipsa_encrkeylen);
	}
	if (ipsa->ipsa_src_cid != NULL) {
		IPSID_REFRELE(ipsa->ipsa_src_cid);
	}
	if (ipsa->ipsa_dst_cid != NULL) {
		IPSID_REFRELE(ipsa->ipsa_dst_cid);
	}
	if (ipsa->ipsa_integ != NULL)
		kmem_free(ipsa->ipsa_integ, ipsa->ipsa_integlen);
	if (ipsa->ipsa_sens != NULL)
		kmem_free(ipsa->ipsa_sens, ipsa->ipsa_senslen);

	mutex_destroy(&ipsa->ipsa_lock);
	kmem_free(ipsa, sizeof (*ipsa));
}

/*
 * Unlink a security association from a hash bucket.  Assume the hash bucket
 * lock is held, but the association's lock is not.
 *
 * Note that we do not bump the bucket's generation number here because
 * we might not be making a visible change to the set of visible SA's.
 * All callers MUST bump the bucket's generation number before they unlock
 * the bucket if they use sadb_unlinkassoc to permanetly remove an SA which
 * was present in the bucket at the time it was locked.
 */
void
sadb_unlinkassoc(ipsa_t *ipsa)
{
	ASSERT(ipsa->ipsa_linklock != NULL);
	ASSERT(MUTEX_HELD(ipsa->ipsa_linklock));

	/* These fields are protected by the link lock. */
	*(ipsa->ipsa_ptpn) = ipsa->ipsa_next;
	if (ipsa->ipsa_next != NULL) {
		ipsa->ipsa_next->ipsa_ptpn = ipsa->ipsa_ptpn;
		ipsa->ipsa_next = NULL;
	}

	ipsa->ipsa_ptpn = NULL;

	/* This may destroy the SA. */
	IPSA_REFRELE(ipsa);
}

/*
 * Create a larval security association with the specified SPI.	 All other
 * fields are zeroed.
 */
static ipsa_t *
sadb_makelarvalassoc(uint32_t spi, uint32_t *src, uint32_t *dst, int addrfam,
    netstack_t *ns)
{
	ipsa_t *newbie;

	/*
	 * Allocate...
	 */

	newbie = (ipsa_t *)kmem_zalloc(sizeof (ipsa_t), KM_NOSLEEP);
	if (newbie == NULL) {
		/* Can't make new larval SA. */
		return (NULL);
	}

	/* Assigned requested SPI, assume caller does SPI allocation magic. */
	newbie->ipsa_spi = spi;
	newbie->ipsa_netstack = ns;	/* No netstack_hold */

	/*
	 * Copy addresses...
	 */

	IPSA_COPY_ADDR(newbie->ipsa_srcaddr, src, addrfam);
	IPSA_COPY_ADDR(newbie->ipsa_dstaddr, dst, addrfam);

	newbie->ipsa_addrfam = addrfam;

	/*
	 * Set common initialization values, including refcnt.
	 */
	mutex_init(&newbie->ipsa_lock, NULL, MUTEX_DEFAULT, NULL);
	newbie->ipsa_state = IPSA_STATE_LARVAL;
	newbie->ipsa_refcnt = 1;
	newbie->ipsa_freefunc = sadb_freeassoc;

	/*
	 * There aren't a lot of other common initialization values, as
	 * they are copied in from the PF_KEY message.
	 */

	return (newbie);
}

/*
 * Call me to initialize a security association fanout.
 */
static int
sadb_init_fanout(isaf_t **tablep, uint_t size, int kmflag)
{
	isaf_t *table;
	int i;

	table = (isaf_t *)kmem_alloc(size * sizeof (*table), kmflag);
	*tablep = table;

	if (table == NULL)
		return (ENOMEM);

	for (i = 0; i < size; i++) {
		mutex_init(&(table[i].isaf_lock), NULL, MUTEX_DEFAULT, NULL);
		table[i].isaf_ipsa = NULL;
		table[i].isaf_gen = 0;
	}

	return (0);
}

/*
 * Call me to initialize an acquire fanout
 */
static int
sadb_init_acfanout(iacqf_t **tablep, uint_t size, int kmflag)
{
	iacqf_t *table;
	int i;

	table = (iacqf_t *)kmem_alloc(size * sizeof (*table), kmflag);
	*tablep = table;

	if (table == NULL)
		return (ENOMEM);

	for (i = 0; i < size; i++) {
		mutex_init(&(table[i].iacqf_lock), NULL, MUTEX_DEFAULT, NULL);
		table[i].iacqf_ipsacq = NULL;
	}

	return (0);
}

/*
 * Attempt to initialize an SADB instance.  On failure, return ENOMEM;
 * caller must clean up partial allocations.
 */
static int
sadb_init_trial(sadb_t *sp, uint_t size, int kmflag)
{
	ASSERT(sp->sdb_of == NULL);
	ASSERT(sp->sdb_if == NULL);
	ASSERT(sp->sdb_acq == NULL);

	sp->sdb_hashsize = size;
	if (sadb_init_fanout(&sp->sdb_of, size, kmflag) != 0)
		return (ENOMEM);
	if (sadb_init_fanout(&sp->sdb_if, size, kmflag) != 0)
		return (ENOMEM);
	if (sadb_init_acfanout(&sp->sdb_acq, size, kmflag) != 0)
		return (ENOMEM);

	return (0);
}

/*
 * Call me to initialize an SADB instance; fall back to default size on failure.
 */
static void
sadb_init(const char *name, sadb_t *sp, uint_t size, uint_t ver,
    netstack_t *ns)
{
	ASSERT(sp->sdb_of == NULL);
	ASSERT(sp->sdb_if == NULL);
	ASSERT(sp->sdb_acq == NULL);

	if (size < IPSEC_DEFAULT_HASH_SIZE)
		size = IPSEC_DEFAULT_HASH_SIZE;

	if (sadb_init_trial(sp, size, KM_NOSLEEP) != 0) {

		cmn_err(CE_WARN,
		    "Unable to allocate %u entry IPv%u %s SADB hash table",
		    size, ver, name);

		sadb_destroy(sp, ns);
		size = IPSEC_DEFAULT_HASH_SIZE;
		cmn_err(CE_WARN, "Falling back to %d entries", size);
		(void) sadb_init_trial(sp, size, KM_SLEEP);
	}
}


/*
 * Initialize an SADB-pair.
 */
void
sadbp_init(const char *name, sadbp_t *sp, int type, int size, netstack_t *ns)
{
	sadb_init(name, &sp->s_v4, size, 4, ns);
	sadb_init(name, &sp->s_v6, size, 6, ns);

	sp->s_satype = type;

	ASSERT((type == SADB_SATYPE_AH) || (type == SADB_SATYPE_ESP));
	if (type == SADB_SATYPE_AH) {
		ipsec_stack_t	*ipss = ns->netstack_ipsec;

		ip_drop_register(&ipss->ipsec_sadb_dropper, "IPsec SADB");
		sp->s_addflags = AH_ADD_SETTABLE_FLAGS;
		sp->s_updateflags = AH_UPDATE_SETTABLE_FLAGS;
	} else {
		sp->s_addflags = ESP_ADD_SETTABLE_FLAGS;
		sp->s_updateflags = ESP_UPDATE_SETTABLE_FLAGS;
	}
}

/*
 * Deliver a single SADB_DUMP message representing a single SA.  This is
 * called many times by sadb_dump().
 *
 * If the return value of this is ENOBUFS (not the same as ENOMEM), then
 * the caller should take that as a hint that dupb() on the "original answer"
 * failed, and that perhaps the caller should try again with a copyb()ed
 * "original answer".
 */
static int
sadb_dump_deliver(queue_t *pfkey_q, mblk_t *original_answer, ipsa_t *ipsa,
    sadb_msg_t *samsg)
{
	mblk_t *answer;

	answer = dupb(original_answer);
	if (answer == NULL)
		return (ENOBUFS);
	answer->b_cont = sadb_sa2msg(ipsa, samsg);
	if (answer->b_cont == NULL) {
		freeb(answer);
		return (ENOMEM);
	}

	/* Just do a putnext, and let keysock deal with flow control. */
	putnext(pfkey_q, answer);
	return (0);
}

/*
 * Common function to allocate and prepare a keysock_out_t M_CTL message.
 */
mblk_t *
sadb_keysock_out(minor_t serial)
{
	mblk_t *mp;
	keysock_out_t *kso;

	mp = allocb(sizeof (ipsec_info_t), BPRI_HI);
	if (mp != NULL) {
		mp->b_datap->db_type = M_CTL;
		mp->b_wptr += sizeof (ipsec_info_t);
		kso = (keysock_out_t *)mp->b_rptr;
		kso->ks_out_type = KEYSOCK_OUT;
		kso->ks_out_len = sizeof (*kso);
		kso->ks_out_serial = serial;
	}

	return (mp);
}

/*
 * Perform an SADB_DUMP, spewing out every SA in an array of SA fanouts
 * to keysock.
 */
static int
sadb_dump_fanout(queue_t *pfkey_q, mblk_t *mp, minor_t serial, isaf_t *fanout,
    int num_entries, boolean_t do_peers)
{
	int i, error = 0;
	mblk_t *original_answer;
	ipsa_t *walker;
	sadb_msg_t *samsg;

	/*
	 * For each IPSA hash bucket do:
	 *	- Hold the mutex
	 *	- Walk each entry, doing an sadb_dump_deliver() on it.
	 */
	ASSERT(mp->b_cont != NULL);
	samsg = (sadb_msg_t *)mp->b_cont->b_rptr;

	original_answer = sadb_keysock_out(serial);
	if (original_answer == NULL)
		return (ENOMEM);

	for (i = 0; i < num_entries; i++) {
		mutex_enter(&fanout[i].isaf_lock);
		for (walker = fanout[i].isaf_ipsa; walker != NULL;
		    walker = walker->ipsa_next) {
			if (!do_peers && walker->ipsa_haspeer)
				continue;
			error = sadb_dump_deliver(pfkey_q, original_answer,
			    walker, samsg);
			if (error == ENOBUFS) {
				mblk_t *new_original_answer;

				/* Ran out of dupb's.  Try a copyb. */
				new_original_answer = copyb(original_answer);
				if (new_original_answer == NULL) {
					error = ENOMEM;
				} else {
					freeb(original_answer);
					original_answer = new_original_answer;
					error = sadb_dump_deliver(pfkey_q,
					    original_answer, walker, samsg);
				}
			}
			if (error != 0)
				break;	/* out of for loop. */
		}
		mutex_exit(&fanout[i].isaf_lock);
		if (error != 0)
			break;	/* out of for loop. */
	}

	freeb(original_answer);
	return (error);
}

/*
 * Dump an entire SADB; outbound first, then inbound.
 */

int
sadb_dump(queue_t *pfkey_q, mblk_t *mp, minor_t serial, sadb_t *sp)
{
	int error;

	/* Dump outbound */
	error = sadb_dump_fanout(pfkey_q, mp, serial, sp->sdb_of,
	    sp->sdb_hashsize, B_TRUE);
	if (error)
		return (error);

	/* Dump inbound */
	return sadb_dump_fanout(pfkey_q, mp, serial, sp->sdb_if,
	    sp->sdb_hashsize, B_FALSE);
}

/*
 * Generic sadb table walker.
 *
 * Call "walkfn" for each SA in each bucket in "table"; pass the
 * bucket, the entry and "cookie" to the callback function.
 * Take care to ensure that walkfn can delete the SA without screwing
 * up our traverse.
 *
 * The bucket is locked for the duration of the callback, both so that the
 * callback can just call sadb_unlinkassoc() when it wants to delete something,
 * and so that no new entries are added while we're walking the list.
 */
static void
sadb_walker(isaf_t *table, uint_t numentries,
    void (*walkfn)(isaf_t *head, ipsa_t *entry, void *cookie),
    void *cookie)
{
	int i;
	for (i = 0; i < numentries; i++) {
		ipsa_t *entry, *next;

		mutex_enter(&table[i].isaf_lock);

		for (entry = table[i].isaf_ipsa; entry != NULL;
		    entry = next) {
			next = entry->ipsa_next;
			(*walkfn)(&table[i], entry, cookie);
		}
		mutex_exit(&table[i].isaf_lock);
	}
}

/*
 * From the given SA, construct a dl_ct_ipsec_key and
 * a dl_ct_ipsec structures to be sent to the adapter as part
 * of a DL_CONTROL_REQ.
 *
 * ct_sa must point to the storage allocated for the key
 * structure and must be followed by storage allocated
 * for the SA information that must be sent to the driver
 * as part of the DL_CONTROL_REQ request.
 *
 * The is_inbound boolean indicates whether the specified
 * SA is part of an inbound SA table.
 *
 * Returns B_TRUE if the corresponding SA must be passed to
 * a provider, B_FALSE otherwise; frees *mp if it returns B_FALSE.
 */
static boolean_t
sadb_req_from_sa(ipsa_t *sa, mblk_t *mp, boolean_t is_inbound)
{
	dl_ct_ipsec_key_t *keyp;
	dl_ct_ipsec_t *sap;
	void *ct_sa = mp->b_wptr;

	ASSERT(MUTEX_HELD(&sa->ipsa_lock));

	keyp = (dl_ct_ipsec_key_t *)(ct_sa);
	sap = (dl_ct_ipsec_t *)(keyp + 1);

	IPSECHW_DEBUG(IPSECHW_CAPAB, ("sadb_req_from_sa: "
	    "is_inbound = %d\n", is_inbound));

	/* initialize flag */
	sap->sadb_sa_flags = 0;
	if (is_inbound) {
		sap->sadb_sa_flags |= DL_CT_IPSEC_INBOUND;
		/*
		 * If an inbound SA has a peer, then mark it has being
		 * an outbound SA as well.
		 */
		if (sa->ipsa_haspeer)
			sap->sadb_sa_flags |= DL_CT_IPSEC_OUTBOUND;
	} else {
		/*
		 * If an outbound SA has a peer, then don't send it,
		 * since we will send the copy from the inbound table.
		 */
		if (sa->ipsa_haspeer) {
			freemsg(mp);
			return (B_FALSE);
		}
		sap->sadb_sa_flags |= DL_CT_IPSEC_OUTBOUND;
	}

	keyp->dl_key_spi = sa->ipsa_spi;
	bcopy(sa->ipsa_dstaddr, keyp->dl_key_dest_addr,
	    DL_CTL_IPSEC_ADDR_LEN);
	keyp->dl_key_addr_family = sa->ipsa_addrfam;

	sap->sadb_sa_auth = sa->ipsa_auth_alg;
	sap->sadb_sa_encrypt = sa->ipsa_encr_alg;

	sap->sadb_key_len_a = sa->ipsa_authkeylen;
	sap->sadb_key_bits_a = sa->ipsa_authkeybits;
	bcopy(sa->ipsa_authkey,
	    sap->sadb_key_data_a, sap->sadb_key_len_a);

	sap->sadb_key_len_e = sa->ipsa_encrkeylen;
	sap->sadb_key_bits_e = sa->ipsa_encrkeybits;
	bcopy(sa->ipsa_encrkey,
	    sap->sadb_key_data_e, sap->sadb_key_len_e);

	mp->b_wptr += sizeof (dl_ct_ipsec_t) + sizeof (dl_ct_ipsec_key_t);
	return (B_TRUE);
}

/*
 * Called from AH or ESP to format a message which will be used to inform
 * IPsec-acceleration-capable ills of a SADB change.
 * (It is not possible to send the message to IP directly from this function
 * since the SA, if any, is locked during the call).
 *
 * dl_operation: DL_CONTROL_REQ operation (add, delete, update, etc)
 * sa_type: identifies whether the operation applies to AH or ESP
 *	(must be one of SADB_SATYPE_AH or SADB_SATYPE_ESP)
 * sa: Pointer to an SA.  Must be non-NULL and locked
 *	for ADD, DELETE, GET, and UPDATE operations.
 * This function returns an mblk chain that must be passed to IP
 * for forwarding to the IPsec capable providers.
 */
mblk_t *
sadb_fmt_sa_req(uint_t dl_operation, uint_t sa_type, ipsa_t *sa,
    boolean_t is_inbound)
{
	mblk_t *mp;
	dl_control_req_t *ctrl;
	boolean_t need_key = B_FALSE;
	mblk_t *ctl_mp = NULL;
	ipsec_ctl_t *ctl;

	/*
	 * 1 allocate and initialize DL_CONTROL_REQ M_PROTO
	 * 2 if a key is needed for the operation
	 *    2.1 initialize key
	 *    2.2 if a full SA is needed for the operation
	 *	2.2.1 initialize full SA info
	 * 3 return message; caller will call ill_ipsec_capab_send_all()
	 * to send the resulting message to IPsec capable ills.
	 */

	ASSERT(sa_type == SADB_SATYPE_AH || sa_type == SADB_SATYPE_ESP);

	/*
	 * Allocate DL_CONTROL_REQ M_PROTO
	 * We allocate room for the SA even if it's not needed
	 * by some of the operations (for example flush)
	 */
	mp = allocb(sizeof (dl_control_req_t) +
	    sizeof (dl_ct_ipsec_key_t) + sizeof (dl_ct_ipsec_t), BPRI_HI);
	if (mp == NULL)
		return (NULL);
	mp->b_datap->db_type = M_PROTO;

	/* initialize dl_control_req_t */
	ctrl = (dl_control_req_t *)mp->b_wptr;
	ctrl->dl_primitive = DL_CONTROL_REQ;
	ctrl->dl_operation = dl_operation;
	ctrl->dl_type = sa_type == SADB_SATYPE_AH ? DL_CT_IPSEC_AH :
	    DL_CT_IPSEC_ESP;
	ctrl->dl_key_offset = sizeof (dl_control_req_t);
	ctrl->dl_key_length = sizeof (dl_ct_ipsec_key_t);
	ctrl->dl_data_offset = sizeof (dl_control_req_t) +
	    sizeof (dl_ct_ipsec_key_t);
	ctrl->dl_data_length = sizeof (dl_ct_ipsec_t);
	mp->b_wptr += sizeof (dl_control_req_t);

	if ((dl_operation == DL_CO_SET) || (dl_operation == DL_CO_DELETE)) {
		ASSERT(sa != NULL);
		ASSERT(MUTEX_HELD(&sa->ipsa_lock));

		need_key = B_TRUE;

		/*
		 * Initialize key and SA data. Note that for some
		 * operations the SA data is ignored by the provider
		 * (delete, etc.)
		 */
		if (!sadb_req_from_sa(sa, mp, is_inbound))
			return (NULL);
	}

	/* construct control message */
	ctl_mp = allocb(sizeof (ipsec_ctl_t), BPRI_HI);
	if (ctl_mp == NULL) {
		cmn_err(CE_WARN, "sadb_fmt_sa_req: allocb failed\n");
		freemsg(mp);
		return (NULL);
	}

	ctl_mp->b_datap->db_type = M_CTL;
	ctl_mp->b_wptr += sizeof (ipsec_ctl_t);
	ctl_mp->b_cont = mp;

	ctl = (ipsec_ctl_t *)ctl_mp->b_rptr;
	ctl->ipsec_ctl_type = IPSEC_CTL;
	ctl->ipsec_ctl_len  = sizeof (ipsec_ctl_t);
	ctl->ipsec_ctl_sa_type = sa_type;

	if (need_key) {
		/*
		 * Keep an additional reference on SA, since it will be
		 * needed by IP to send control messages corresponding
		 * to that SA from its perimeter. IP will do a
		 * IPSA_REFRELE when done with the request.
		 */
		ASSERT(MUTEX_HELD(&sa->ipsa_lock));
		IPSA_REFHOLD(sa);
		ctl->ipsec_ctl_sa = sa;
	} else
		ctl->ipsec_ctl_sa = NULL;

	return (ctl_mp);
}


/*
 * Called by sadb_ill_download() to dump the entries for a specific
 * fanout table.  For each SA entry in the table passed as argument,
 * use mp as a template and constructs a full DL_CONTROL message, and
 * call ill_dlpi_send(), provided by IP, to send the resulting
 * messages to the ill.
 */
static void
sadb_ill_df(ill_t *ill, mblk_t *mp, isaf_t *fanout, int num_entries,
    boolean_t is_inbound)
{
	ipsa_t *walker;
	mblk_t *nmp, *salist;
	int i, error = 0;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;

	IPSECHW_DEBUG(IPSECHW_SADB, ("sadb_ill_df: fanout at 0x%p ne=%d\n",
	    (void *)fanout, num_entries));
	/*
	 * For each IPSA hash bucket do:
	 *	- Hold the mutex
	 *	- Walk each entry, sending a corresponding request to IP
	 *	  for it.
	 */
	ASSERT(mp->b_datap->db_type == M_PROTO);

	for (i = 0; i < num_entries; i++) {
		mutex_enter(&fanout[i].isaf_lock);
		salist = NULL;

		for (walker = fanout[i].isaf_ipsa; walker != NULL;
		    walker = walker->ipsa_next) {
			IPSECHW_DEBUG(IPSECHW_SADB,
			    ("sadb_ill_df: sending SA to ill via IP \n"));
			/*
			 * Duplicate the template mp passed and
			 * complete DL_CONTROL_REQ data.
			 * To be more memory efficient, we could use
			 * dupb() for the M_CTL and copyb() for the M_PROTO
			 * as the M_CTL, since the M_CTL is the same for
			 * every SA entry passed down to IP for the same ill.
			 *
			 * Note that copymsg/copyb ensure that the new mblk
			 * is at least as large as the source mblk even if it's
			 * not using all its storage -- therefore, nmp
			 * has trailing space for sadb_req_from_sa to add
			 * the SA-specific bits.
			 */
			mutex_enter(&walker->ipsa_lock);
			if (ipsec_capab_match(ill,
			    ill->ill_phyint->phyint_ifindex, ill->ill_isv6,
			    walker, ns)) {
				nmp = copymsg(mp);
				if (nmp == NULL) {
					IPSECHW_DEBUG(IPSECHW_SADB,
					    ("sadb_ill_df: alloc error\n"));
					error = ENOMEM;
					mutex_exit(&walker->ipsa_lock);
					break;
				}
				if (sadb_req_from_sa(walker, nmp, is_inbound)) {
					nmp->b_next = salist;
					salist = nmp;
				}
			}
			mutex_exit(&walker->ipsa_lock);
		}
		mutex_exit(&fanout[i].isaf_lock);
		while (salist != NULL) {
			nmp = salist;
			salist = nmp->b_next;
			nmp->b_next = NULL;
			ill_dlpi_send(ill, nmp);
		}
		if (error != 0)
			break;	/* out of for loop. */
	}
}

/*
 * Called by ill_ipsec_capab_add(). Sends a copy of the SADB of
 * the type specified by sa_type to the specified ill.
 *
 * We call for each fanout table defined by the SADB (one per
 * protocol). sadb_ill_df() finally calls ill_dlpi_send() for
 * each SADB entry in order to send a corresponding DL_CONTROL_REQ
 * message to the ill.
 */
void
sadb_ill_download(ill_t *ill, uint_t sa_type)
{
	mblk_t *protomp;	/* prototype message */
	dl_control_req_t *ctrl;
	sadbp_t *spp;
	sadb_t *sp;
	int dlt;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;

	ASSERT(sa_type == SADB_SATYPE_AH || sa_type == SADB_SATYPE_ESP);

	/*
	 * Allocate and initialize prototype answer. A duplicate for
	 * each SA is sent down to the interface.
	 */

	/* DL_CONTROL_REQ M_PROTO mblk_t */
	protomp = allocb(sizeof (dl_control_req_t) +
	    sizeof (dl_ct_ipsec_key_t) + sizeof (dl_ct_ipsec_t), BPRI_HI);
	if (protomp == NULL)
		return;
	protomp->b_datap->db_type = M_PROTO;

	dlt = (sa_type == SADB_SATYPE_AH) ? DL_CT_IPSEC_AH : DL_CT_IPSEC_ESP;
	if (sa_type == SADB_SATYPE_ESP) {
		ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;

		spp = &espstack->esp_sadb;
	} else {
		ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;

		spp = &ahstack->ah_sadb;
	}

	ctrl = (dl_control_req_t *)protomp->b_wptr;
	ctrl->dl_primitive = DL_CONTROL_REQ;
	ctrl->dl_operation = DL_CO_SET;
	ctrl->dl_type = dlt;
	ctrl->dl_key_offset = sizeof (dl_control_req_t);
	ctrl->dl_key_length = sizeof (dl_ct_ipsec_key_t);
	ctrl->dl_data_offset = sizeof (dl_control_req_t) +
	    sizeof (dl_ct_ipsec_key_t);
	ctrl->dl_data_length = sizeof (dl_ct_ipsec_t);
	protomp->b_wptr += sizeof (dl_control_req_t);

	/*
	 * then for each SADB entry, we fill out the dl_ct_ipsec_key_t
	 * and dl_ct_ipsec_t
	 */
	sp = ill->ill_isv6 ? &(spp->s_v6) : &(spp->s_v4);
	sadb_ill_df(ill, protomp, sp->sdb_of, sp->sdb_hashsize, B_FALSE);
	sadb_ill_df(ill, protomp, sp->sdb_if, sp->sdb_hashsize, B_TRUE);
	freemsg(protomp);
}

/*
 * Call me to free up a security association fanout.  Use the forever
 * variable to indicate freeing up the SAs (forever == B_FALSE, e.g.
 * an SADB_FLUSH message), or destroying everything (forever == B_TRUE,
 * when a module is unloaded).
 */
static void
sadb_destroyer(isaf_t **tablep, uint_t numentries, boolean_t forever)
{
	int i;
	isaf_t *table = *tablep;

	if (table == NULL)
		return;

	for (i = 0; i < numentries; i++) {
		mutex_enter(&table[i].isaf_lock);
		while (table[i].isaf_ipsa != NULL)
			sadb_unlinkassoc(table[i].isaf_ipsa);
		table[i].isaf_gen++;
		mutex_exit(&table[i].isaf_lock);
		if (forever)
			mutex_destroy(&(table[i].isaf_lock));
	}

	if (forever) {
		*tablep = NULL;
		kmem_free(table, numentries * sizeof (*table));
	}
}

/*
 * Entry points to sadb_destroyer().
 */
static void
sadb_flush(sadb_t *sp, netstack_t *ns)
{
	/*
	 * Flush out each bucket, one at a time.  Were it not for keysock's
	 * enforcement, there would be a subtlety where I could add on the
	 * heels of a flush.  With keysock's enforcement, however, this
	 * makes ESP's job easy.
	 */
	sadb_destroyer(&sp->sdb_of, sp->sdb_hashsize, B_FALSE);
	sadb_destroyer(&sp->sdb_if, sp->sdb_hashsize, B_FALSE);

	/* For each acquire, destroy it; leave the bucket mutex alone. */
	sadb_destroy_acqlist(&sp->sdb_acq, sp->sdb_hashsize, B_FALSE, ns);
}

static void
sadb_destroy(sadb_t *sp, netstack_t *ns)
{
	sadb_destroyer(&sp->sdb_of, sp->sdb_hashsize, B_TRUE);
	sadb_destroyer(&sp->sdb_if, sp->sdb_hashsize, B_TRUE);

	/* For each acquire, destroy it, including the bucket mutex. */
	sadb_destroy_acqlist(&sp->sdb_acq, sp->sdb_hashsize, B_TRUE, ns);

	ASSERT(sp->sdb_of == NULL);
	ASSERT(sp->sdb_if == NULL);
	ASSERT(sp->sdb_acq == NULL);
}

static void
sadb_send_flush_req(sadbp_t *spp)
{
	mblk_t *ctl_mp;

	/*
	 * we've been unplumbed, or never were plumbed; don't go there.
	 */
	if (spp->s_ip_q == NULL)
		return;

	/* have IP send a flush msg to the IPsec accelerators */
	ctl_mp = sadb_fmt_sa_req(DL_CO_FLUSH, spp->s_satype, NULL, B_TRUE);
	if (ctl_mp != NULL)
		putnext(spp->s_ip_q, ctl_mp);
}

void
sadbp_flush(sadbp_t *spp, netstack_t *ns)
{
	sadb_flush(&spp->s_v4, ns);
	sadb_flush(&spp->s_v6, ns);

	sadb_send_flush_req(spp);
}

void
sadbp_destroy(sadbp_t *spp, netstack_t *ns)
{
	sadb_destroy(&spp->s_v4, ns);
	sadb_destroy(&spp->s_v6, ns);

	sadb_send_flush_req(spp);
	if (spp->s_satype == SADB_SATYPE_AH) {
		ipsec_stack_t	*ipss = ns->netstack_ipsec;

		ip_drop_unregister(&ipss->ipsec_sadb_dropper);
	}
}


/*
 * Check hard vs. soft lifetimes.  If there's a reality mismatch (e.g.
 * soft lifetimes > hard lifetimes) return an appropriate diagnostic for
 * EINVAL.
 */
int
sadb_hardsoftchk(sadb_lifetime_t *hard, sadb_lifetime_t *soft)
{
	if (hard == NULL || soft == NULL)
		return (0);

	if (hard->sadb_lifetime_allocations != 0 &&
	    soft->sadb_lifetime_allocations != 0 &&
	    hard->sadb_lifetime_allocations < soft->sadb_lifetime_allocations)
		return (SADB_X_DIAGNOSTIC_ALLOC_HSERR);

	if (hard->sadb_lifetime_bytes != 0 &&
	    soft->sadb_lifetime_bytes != 0 &&
	    hard->sadb_lifetime_bytes < soft->sadb_lifetime_bytes)
		return (SADB_X_DIAGNOSTIC_BYTES_HSERR);

	if (hard->sadb_lifetime_addtime != 0 &&
	    soft->sadb_lifetime_addtime != 0 &&
	    hard->sadb_lifetime_addtime < soft->sadb_lifetime_addtime)
		return (SADB_X_DIAGNOSTIC_ADDTIME_HSERR);

	if (hard->sadb_lifetime_usetime != 0 &&
	    soft->sadb_lifetime_usetime != 0 &&
	    hard->sadb_lifetime_usetime < soft->sadb_lifetime_usetime)
		return (SADB_X_DIAGNOSTIC_USETIME_HSERR);

	return (0);
}

/*
 * Clone a security association for the purposes of inserting a single SA
 * into inbound and outbound tables respectively. This function should only
 * be called from sadb_common_add().
 */
static ipsa_t *
sadb_cloneassoc(ipsa_t *ipsa)
{
	ipsa_t *newbie;
	boolean_t error = B_FALSE;

	ASSERT(!MUTEX_HELD(&(ipsa->ipsa_lock)));

	newbie = kmem_alloc(sizeof (ipsa_t), KM_NOSLEEP);
	if (newbie == NULL)
		return (NULL);

	/* Copy over what we can. */
	*newbie = *ipsa;

	/* bzero and initialize locks, in case *_init() allocates... */
	mutex_init(&newbie->ipsa_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * While somewhat dain-bramaged, the most graceful way to
	 * recover from errors is to keep plowing through the
	 * allocations, and getting what I can.  It's easier to call
	 * sadb_freeassoc() on the stillborn clone when all the
	 * pointers aren't pointing to the parent's data.
	 */

	if (ipsa->ipsa_authkey != NULL) {
		newbie->ipsa_authkey = kmem_alloc(newbie->ipsa_authkeylen,
		    KM_NOSLEEP);
		if (newbie->ipsa_authkey == NULL) {
			error = B_TRUE;
		} else {
			bcopy(ipsa->ipsa_authkey, newbie->ipsa_authkey,
			    newbie->ipsa_authkeylen);

			newbie->ipsa_kcfauthkey.ck_data =
			    newbie->ipsa_authkey;
		}

		if (newbie->ipsa_amech.cm_param != NULL) {
			newbie->ipsa_amech.cm_param =
			    (char *)&newbie->ipsa_mac_len;
		}
	}

	if (ipsa->ipsa_encrkey != NULL) {
		newbie->ipsa_encrkey = kmem_alloc(newbie->ipsa_encrkeylen,
		    KM_NOSLEEP);
		if (newbie->ipsa_encrkey == NULL) {
			error = B_TRUE;
		} else {
			bcopy(ipsa->ipsa_encrkey, newbie->ipsa_encrkey,
			    newbie->ipsa_encrkeylen);

			newbie->ipsa_kcfencrkey.ck_data =
			    newbie->ipsa_encrkey;
		}
	}

	newbie->ipsa_authtmpl = NULL;
	newbie->ipsa_encrtmpl = NULL;
	newbie->ipsa_haspeer = B_TRUE;

	if (ipsa->ipsa_integ != NULL) {
		newbie->ipsa_integ = kmem_alloc(newbie->ipsa_integlen,
		    KM_NOSLEEP);
		if (newbie->ipsa_integ == NULL) {
			error = B_TRUE;
		} else {
			bcopy(ipsa->ipsa_integ, newbie->ipsa_integ,
			    newbie->ipsa_integlen);
		}
	}

	if (ipsa->ipsa_sens != NULL) {
		newbie->ipsa_sens = kmem_alloc(newbie->ipsa_senslen,
		    KM_NOSLEEP);
		if (newbie->ipsa_sens == NULL) {
			error = B_TRUE;
		} else {
			bcopy(ipsa->ipsa_sens, newbie->ipsa_sens,
			    newbie->ipsa_senslen);
		}
	}

	if (ipsa->ipsa_src_cid != NULL) {
		newbie->ipsa_src_cid = ipsa->ipsa_src_cid;
		IPSID_REFHOLD(ipsa->ipsa_src_cid);
	}

	if (ipsa->ipsa_dst_cid != NULL) {
		newbie->ipsa_dst_cid = ipsa->ipsa_dst_cid;
		IPSID_REFHOLD(ipsa->ipsa_dst_cid);
	}

	if (error) {
		sadb_freeassoc(newbie);
		return (NULL);
	}

	return (newbie);
}

/*
 * Initialize a SADB address extension at the address specified by addrext.
 * Return a pointer to the end of the new address extension.
 */
static uint8_t *
sadb_make_addr_ext(uint8_t *start, uint8_t *end, uint16_t exttype,
    sa_family_t af, uint32_t *addr, uint16_t port, uint8_t proto, int prefix)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint8_t *cur = start;
	int addrext_len;
	int sin_len;
	sadb_address_t *addrext	= (sadb_address_t *)cur;

	if (cur == NULL)
		return (NULL);

	cur += sizeof (*addrext);
	if (cur > end)
		return (NULL);

	addrext->sadb_address_proto = proto;
	addrext->sadb_address_prefixlen = prefix;
	addrext->sadb_address_reserved = 0;
	addrext->sadb_address_exttype = exttype;

	switch (af) {
	case AF_INET:
		sin = (struct sockaddr_in *)cur;
		sin_len = sizeof (*sin);
		cur += sin_len;
		if (cur > end)
			return (NULL);

		sin->sin_family = af;
		bzero(sin->sin_zero, sizeof (sin->sin_zero));
		sin->sin_port = port;
		IPSA_COPY_ADDR(&sin->sin_addr, addr, af);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)cur;
		sin_len = sizeof (*sin6);
		cur += sin_len;
		if (cur > end)
			return (NULL);

		bzero(sin6, sizeof (*sin6));
		sin6->sin6_family = af;
		sin6->sin6_port = port;
		IPSA_COPY_ADDR(&sin6->sin6_addr, addr, af);
		break;
	}

	addrext_len = roundup(cur - start, sizeof (uint64_t));
	addrext->sadb_address_len = SADB_8TO64(addrext_len);

	cur = start + addrext_len;
	if (cur > end)
		cur = NULL;

	return (cur);
}

/*
 * Construct a key management cookie extension.
 */

static uint8_t *
sadb_make_kmc_ext(uint8_t *cur, uint8_t *end, uint32_t kmp, uint32_t kmc)
{
	sadb_x_kmc_t *kmcext = (sadb_x_kmc_t *)cur;

	if (cur == NULL)
		return (NULL);

	cur += sizeof (*kmcext);

	if (cur > end)
		return (NULL);

	kmcext->sadb_x_kmc_len = SADB_8TO64(sizeof (*kmcext));
	kmcext->sadb_x_kmc_exttype = SADB_X_EXT_KM_COOKIE;
	kmcext->sadb_x_kmc_proto = kmp;
	kmcext->sadb_x_kmc_cookie = kmc;
	kmcext->sadb_x_kmc_reserved = 0;

	return (cur);
}

/*
 * Given an original message header with sufficient space following it, and an
 * SA, construct a full PF_KEY message with all of the relevant extensions.
 * This is mostly used for SADB_GET, and SADB_DUMP.
 */
static mblk_t *
sadb_sa2msg(ipsa_t *ipsa, sadb_msg_t *samsg)
{
	int alloclen, addrsize, paddrsize, authsize, encrsize;
	int srcidsize, dstidsize;
	sa_family_t fam, pfam;	/* Address family for SADB_EXT_ADDRESS */
				/* src/dst and proxy sockaddrs. */
	/*
	 * The following are pointers into the PF_KEY message this PF_KEY
	 * message creates.
	 */
	sadb_msg_t *newsamsg;
	sadb_sa_t *assoc;
	sadb_lifetime_t *lt;
	sadb_key_t *key;
	sadb_ident_t *ident;
	sadb_sens_t *sens;
	sadb_ext_t *walker;	/* For when we need a generic ext. pointer. */
	sadb_x_pair_t *pair_ext;

	mblk_t *mp;
	uint64_t *bitmap;
	uint8_t *cur, *end;
	/* These indicate the presence of the above extension fields. */
	boolean_t soft, hard, isrc, idst, auth, encr, sensinteg, srcid, dstid;
	boolean_t paired;
	uint32_t otherspi;

	/* First off, figure out the allocation length for this message. */

	/*
	 * Constant stuff.  This includes base, SA, address (src, dst),
	 * and lifetime (current).
	 */
	alloclen = sizeof (sadb_msg_t) + sizeof (sadb_sa_t) +
	    sizeof (sadb_lifetime_t);

	fam = ipsa->ipsa_addrfam;
	switch (fam) {
	case AF_INET:
		addrsize = roundup(sizeof (struct sockaddr_in) +
		    sizeof (sadb_address_t), sizeof (uint64_t));
		break;
	case AF_INET6:
		addrsize = roundup(sizeof (struct sockaddr_in6) +
		    sizeof (sadb_address_t), sizeof (uint64_t));
		break;
	default:
		return (NULL);
	}
	/*
	 * Allocate TWO address extensions, for source and destination.
	 * (Thus, the * 2.)
	 */
	alloclen += addrsize * 2;
	if (ipsa->ipsa_flags & IPSA_F_NATT_REM)
		alloclen += addrsize;
	if (ipsa->ipsa_flags & IPSA_F_NATT_LOC)
		alloclen += addrsize;

	if (ipsa->ipsa_flags & IPSA_F_PAIRED) {
		paired = B_TRUE;
		alloclen += sizeof (sadb_x_pair_t);
		otherspi = ipsa->ipsa_otherspi;
	} else {
		paired = B_FALSE;
	}

	/* How 'bout other lifetimes? */
	if (ipsa->ipsa_softaddlt != 0 || ipsa->ipsa_softuselt != 0 ||
	    ipsa->ipsa_softbyteslt != 0 || ipsa->ipsa_softalloc != 0) {
		alloclen += sizeof (sadb_lifetime_t);
		soft = B_TRUE;
	} else {
		soft = B_FALSE;
	}

	if (ipsa->ipsa_hardaddlt != 0 || ipsa->ipsa_harduselt != 0 ||
	    ipsa->ipsa_hardbyteslt != 0 || ipsa->ipsa_hardalloc != 0) {
		alloclen += sizeof (sadb_lifetime_t);
		hard = B_TRUE;
	} else {
		hard = B_FALSE;
	}

	/* Inner addresses. */
	if (ipsa->ipsa_innerfam == 0) {
		isrc = B_FALSE;
		idst = B_FALSE;
	} else {
		pfam = ipsa->ipsa_innerfam;
		switch (pfam) {
		case AF_INET6:
			paddrsize = roundup(sizeof (struct sockaddr_in6) +
			    sizeof (sadb_address_t), sizeof (uint64_t));
			break;
		case AF_INET:
			paddrsize = roundup(sizeof (struct sockaddr_in) +
			    sizeof (sadb_address_t), sizeof (uint64_t));
			break;
		default:
			cmn_err(CE_PANIC,
			    "IPsec SADB: Proxy length failure.\n");
			break;
		}
		isrc = B_TRUE;
		idst = B_TRUE;
		alloclen += 2 * paddrsize;
	}

	/* For the following fields, assume that length != 0 ==> stuff */
	if (ipsa->ipsa_authkeylen != 0) {
		authsize = roundup(sizeof (sadb_key_t) + ipsa->ipsa_authkeylen,
		    sizeof (uint64_t));
		alloclen += authsize;
		auth = B_TRUE;
	} else {
		auth = B_FALSE;
	}

	if (ipsa->ipsa_encrkeylen != 0) {
		encrsize = roundup(sizeof (sadb_key_t) + ipsa->ipsa_encrkeylen,
		    sizeof (uint64_t));
		alloclen += encrsize;
		encr = B_TRUE;
	} else {
		encr = B_FALSE;
	}

	/* No need for roundup on sens and integ. */
	if (ipsa->ipsa_integlen != 0 || ipsa->ipsa_senslen != 0) {
		alloclen += sizeof (sadb_key_t) + ipsa->ipsa_integlen +
		    ipsa->ipsa_senslen;
		sensinteg = B_TRUE;
	} else {
		sensinteg = B_FALSE;
	}

	/*
	 * Must use strlen() here for lengths.	Identities use NULL
	 * pointers to indicate their nonexistence.
	 */
	if (ipsa->ipsa_src_cid != NULL) {
		srcidsize = roundup(sizeof (sadb_ident_t) +
		    strlen(ipsa->ipsa_src_cid->ipsid_cid) + 1,
		    sizeof (uint64_t));
		alloclen += srcidsize;
		srcid = B_TRUE;
	} else {
		srcid = B_FALSE;
	}

	if (ipsa->ipsa_dst_cid != NULL) {
		dstidsize = roundup(sizeof (sadb_ident_t) +
		    strlen(ipsa->ipsa_dst_cid->ipsid_cid) + 1,
		    sizeof (uint64_t));
		alloclen += dstidsize;
		dstid = B_TRUE;
	} else {
		dstid = B_FALSE;
	}

	if ((ipsa->ipsa_kmp != 0) || (ipsa->ipsa_kmc != 0))
		alloclen += sizeof (sadb_x_kmc_t);

	/* Make sure the allocation length is a multiple of 8 bytes. */
	ASSERT((alloclen & 0x7) == 0);

	/* XXX Possibly make it esballoc, with a bzero-ing free_ftn. */
	mp = allocb(alloclen, BPRI_HI);
	if (mp == NULL)
		return (NULL);

	mp->b_wptr += alloclen;
	end = mp->b_wptr;
	newsamsg = (sadb_msg_t *)mp->b_rptr;
	*newsamsg = *samsg;
	newsamsg->sadb_msg_len = (uint16_t)SADB_8TO64(alloclen);

	mutex_enter(&ipsa->ipsa_lock);	/* Since I'm grabbing SA fields... */

	newsamsg->sadb_msg_satype = ipsa->ipsa_type;

	assoc = (sadb_sa_t *)(newsamsg + 1);
	assoc->sadb_sa_len = SADB_8TO64(sizeof (*assoc));
	assoc->sadb_sa_exttype = SADB_EXT_SA;
	assoc->sadb_sa_spi = ipsa->ipsa_spi;
	assoc->sadb_sa_replay = ipsa->ipsa_replay_wsize;
	assoc->sadb_sa_state = ipsa->ipsa_state;
	assoc->sadb_sa_auth = ipsa->ipsa_auth_alg;
	assoc->sadb_sa_encrypt = ipsa->ipsa_encr_alg;
	assoc->sadb_sa_flags = ipsa->ipsa_flags;

	lt = (sadb_lifetime_t *)(assoc + 1);
	lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	/* We do not support the concept. */
	lt->sadb_lifetime_allocations = 0;
	lt->sadb_lifetime_bytes = ipsa->ipsa_bytes;
	lt->sadb_lifetime_addtime = ipsa->ipsa_addtime;
	lt->sadb_lifetime_usetime = ipsa->ipsa_usetime;

	if (hard) {
		lt++;
		lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
		lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
		lt->sadb_lifetime_allocations = ipsa->ipsa_hardalloc;
		lt->sadb_lifetime_bytes = ipsa->ipsa_hardbyteslt;
		lt->sadb_lifetime_addtime = ipsa->ipsa_hardaddlt;
		lt->sadb_lifetime_usetime = ipsa->ipsa_harduselt;
	}

	if (soft) {
		lt++;
		lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
		lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
		lt->sadb_lifetime_allocations = ipsa->ipsa_softalloc;
		lt->sadb_lifetime_bytes = ipsa->ipsa_softbyteslt;
		lt->sadb_lifetime_addtime = ipsa->ipsa_softaddlt;
		lt->sadb_lifetime_usetime = ipsa->ipsa_softuselt;
	}

	cur = (uint8_t *)(lt + 1);

	/* NOTE:  Don't fill in ports here if we are a tunnel-mode SA. */
	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC, fam,
	    ipsa->ipsa_srcaddr, (!isrc && !idst) ? SA_SRCPORT(ipsa) : 0,
	    SA_PROTO(ipsa), 0);
	if (cur == NULL) {
		freemsg(mp);
		mp = NULL;
		goto bail;
	}

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST, fam,
	    ipsa->ipsa_dstaddr, (!isrc && !idst) ? SA_DSTPORT(ipsa) : 0,
	    SA_PROTO(ipsa), 0);
	if (cur == NULL) {
		freemsg(mp);
		mp = NULL;
		goto bail;
	}

	if (ipsa->ipsa_flags & IPSA_F_NATT_LOC) {
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_NATT_LOC,
		    fam, &ipsa->ipsa_natt_addr_loc, ipsa->ipsa_local_nat_port,
		    IPPROTO_UDP, 0);
		if (cur == NULL) {
			freemsg(mp);
			mp = NULL;
			goto bail;
		}
	}

	if (ipsa->ipsa_flags & IPSA_F_NATT_REM) {
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_NATT_REM,
		    fam, &ipsa->ipsa_natt_addr_rem, ipsa->ipsa_remote_nat_port,
		    IPPROTO_UDP, 0);
		if (cur == NULL) {
			freemsg(mp);
			mp = NULL;
			goto bail;
		}
	}

	/* If we are a tunnel-mode SA, fill in the inner-selectors. */
	if (isrc) {
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_INNER_SRC,
		    pfam, ipsa->ipsa_innersrc, SA_SRCPORT(ipsa),
		    SA_IPROTO(ipsa), ipsa->ipsa_innersrcpfx);
		if (cur == NULL) {
			freemsg(mp);
			mp = NULL;
			goto bail;
		}
	}

	if (idst) {
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_INNER_DST,
		    pfam, ipsa->ipsa_innerdst, SA_DSTPORT(ipsa),
		    SA_IPROTO(ipsa), ipsa->ipsa_innerdstpfx);
		if (cur == NULL) {
			freemsg(mp);
			mp = NULL;
			goto bail;
		}
	}

	if ((ipsa->ipsa_kmp != 0) || (ipsa->ipsa_kmc != 0)) {
		cur = sadb_make_kmc_ext(cur, end,
		    ipsa->ipsa_kmp, ipsa->ipsa_kmc);
		if (cur == NULL) {
			freemsg(mp);
			mp = NULL;
			goto bail;
		}
	}

	walker = (sadb_ext_t *)cur;
	if (auth) {
		key = (sadb_key_t *)walker;
		key->sadb_key_len = SADB_8TO64(authsize);
		key->sadb_key_exttype = SADB_EXT_KEY_AUTH;
		key->sadb_key_bits = ipsa->ipsa_authkeybits;
		key->sadb_key_reserved = 0;
		bcopy(ipsa->ipsa_authkey, key + 1, ipsa->ipsa_authkeylen);
		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}

	if (encr) {
		key = (sadb_key_t *)walker;
		key->sadb_key_len = SADB_8TO64(encrsize);
		key->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
		key->sadb_key_bits = ipsa->ipsa_encrkeybits;
		key->sadb_key_reserved = 0;
		bcopy(ipsa->ipsa_encrkey, key + 1, ipsa->ipsa_encrkeylen);
		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}

	if (srcid) {
		ident = (sadb_ident_t *)walker;
		ident->sadb_ident_len = SADB_8TO64(srcidsize);
		ident->sadb_ident_exttype = SADB_EXT_IDENTITY_SRC;
		ident->sadb_ident_type = ipsa->ipsa_src_cid->ipsid_type;
		ident->sadb_ident_id = 0;
		ident->sadb_ident_reserved = 0;
		(void) strcpy((char *)(ident + 1),
		    ipsa->ipsa_src_cid->ipsid_cid);
		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}

	if (dstid) {
		ident = (sadb_ident_t *)walker;
		ident->sadb_ident_len = SADB_8TO64(dstidsize);
		ident->sadb_ident_exttype = SADB_EXT_IDENTITY_DST;
		ident->sadb_ident_type = ipsa->ipsa_dst_cid->ipsid_type;
		ident->sadb_ident_id = 0;
		ident->sadb_ident_reserved = 0;
		(void) strcpy((char *)(ident + 1),
		    ipsa->ipsa_dst_cid->ipsid_cid);
		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}

	if (sensinteg) {
		sens = (sadb_sens_t *)walker;
		sens->sadb_sens_len = SADB_8TO64(sizeof (sadb_sens_t *) +
		    ipsa->ipsa_senslen + ipsa->ipsa_integlen);
		sens->sadb_sens_dpd = ipsa->ipsa_dpd;
		sens->sadb_sens_sens_level = ipsa->ipsa_senslevel;
		sens->sadb_sens_integ_level = ipsa->ipsa_integlevel;
		sens->sadb_sens_sens_len = SADB_8TO64(ipsa->ipsa_senslen);
		sens->sadb_sens_integ_len = SADB_8TO64(ipsa->ipsa_integlen);
		sens->sadb_sens_reserved = 0;
		bitmap = (uint64_t *)(sens + 1);
		if (ipsa->ipsa_sens != NULL) {
			bcopy(ipsa->ipsa_sens, bitmap, ipsa->ipsa_senslen);
			bitmap += sens->sadb_sens_sens_len;
		}
		if (ipsa->ipsa_integ != NULL)
			bcopy(ipsa->ipsa_integ, bitmap, ipsa->ipsa_integlen);
		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}

	if (paired) {
		pair_ext = (sadb_x_pair_t *)walker;

		pair_ext->sadb_x_pair_len = SADB_8TO64(sizeof (sadb_x_pair_t));
		pair_ext->sadb_x_pair_exttype = SADB_X_EXT_PAIR;
		pair_ext->sadb_x_pair_spi = otherspi;

		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}

bail:
	/* Pardon any delays... */
	mutex_exit(&ipsa->ipsa_lock);

	return (mp);
}

/*
 * Strip out key headers or unmarked headers (SADB_EXT_KEY_*, SADB_EXT_UNKNOWN)
 * and adjust base message accordingly.
 *
 * Assume message is pulled up in one piece of contiguous memory.
 *
 * Say if we start off with:
 *
 * +------+----+-------------+-----------+---------------+---------------+
 * | base | SA | source addr | dest addr | rsrvd. or key | soft lifetime |
 * +------+----+-------------+-----------+---------------+---------------+
 *
 * we will end up with
 *
 * +------+----+-------------+-----------+---------------+
 * | base | SA | source addr | dest addr | soft lifetime |
 * +------+----+-------------+-----------+---------------+
 */
static void
sadb_strip(sadb_msg_t *samsg)
{
	sadb_ext_t *ext;
	uint8_t *target = NULL;
	uint8_t *msgend;
	int sofar = SADB_8TO64(sizeof (*samsg));
	int copylen;

	ext = (sadb_ext_t *)(samsg + 1);
	msgend = (uint8_t *)samsg;
	msgend += SADB_64TO8(samsg->sadb_msg_len);
	while ((uint8_t *)ext < msgend) {
		if (ext->sadb_ext_type == SADB_EXT_RESERVED ||
		    ext->sadb_ext_type == SADB_EXT_KEY_AUTH ||
		    ext->sadb_ext_type == SADB_EXT_KEY_ENCRYPT) {
			/*
			 * Aha!	 I found a header to be erased.
			 */

			if (target != NULL) {
				/*
				 * If I had a previous header to be erased,
				 * copy over it.  I can get away with just
				 * copying backwards because the target will
				 * always be 8 bytes behind the source.
				 */
				copylen = ((uint8_t *)ext) - (target +
				    SADB_64TO8(
				    ((sadb_ext_t *)target)->sadb_ext_len));
				ovbcopy(((uint8_t *)ext - copylen), target,
				    copylen);
				target += copylen;
				((sadb_ext_t *)target)->sadb_ext_len =
				    SADB_8TO64(((uint8_t *)ext) - target +
				    SADB_64TO8(ext->sadb_ext_len));
			} else {
				target = (uint8_t *)ext;
			}
		} else {
			sofar += ext->sadb_ext_len;
		}

		ext = (sadb_ext_t *)(((uint64_t *)ext) + ext->sadb_ext_len);
	}

	ASSERT((uint8_t *)ext == msgend);

	if (target != NULL) {
		copylen = ((uint8_t *)ext) - (target +
		    SADB_64TO8(((sadb_ext_t *)target)->sadb_ext_len));
		if (copylen != 0)
			ovbcopy(((uint8_t *)ext - copylen), target, copylen);
	}

	/* Adjust samsg. */
	samsg->sadb_msg_len = (uint16_t)sofar;

	/* Assume all of the rest is cleared by caller in sadb_pfkey_echo(). */
}

/*
 * AH needs to send an error to PF_KEY.	 Assume mp points to an M_CTL
 * followed by an M_DATA with a PF_KEY message in it.  The serial of
 * the sending keysock instance is included.
 */
void
sadb_pfkey_error(queue_t *pfkey_q, mblk_t *mp, int error, int diagnostic,
    uint_t serial)
{
	mblk_t *msg = mp->b_cont;
	sadb_msg_t *samsg;
	keysock_out_t *kso;

	/*
	 * Enough functions call this to merit a NULL queue check.
	 */
	if (pfkey_q == NULL) {
		freemsg(mp);
		return;
	}

	ASSERT(msg != NULL);
	ASSERT((mp->b_wptr - mp->b_rptr) == sizeof (ipsec_info_t));
	ASSERT((msg->b_wptr - msg->b_rptr) >= sizeof (sadb_msg_t));
	samsg = (sadb_msg_t *)msg->b_rptr;
	kso = (keysock_out_t *)mp->b_rptr;

	kso->ks_out_type = KEYSOCK_OUT;
	kso->ks_out_len = sizeof (*kso);
	kso->ks_out_serial = serial;

	/*
	 * Only send the base message up in the event of an error.
	 * Don't worry about bzero()-ing, because it was probably bogus
	 * anyway.
	 */
	msg->b_wptr = msg->b_rptr + sizeof (*samsg);
	samsg = (sadb_msg_t *)msg->b_rptr;
	samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg));
	samsg->sadb_msg_errno = (uint8_t)error;
	if (diagnostic != SADB_X_DIAGNOSTIC_PRESET)
		samsg->sadb_x_msg_diagnostic = (uint16_t)diagnostic;

	putnext(pfkey_q, mp);
}

/*
 * Send a successful return packet back to keysock via the queue in pfkey_q.
 *
 * Often, an SA is associated with the reply message, it's passed in if needed,
 * and NULL if not.  BTW, that ipsa will have its refcnt appropriately held,
 * and the caller will release said refcnt.
 */
void
sadb_pfkey_echo(queue_t *pfkey_q, mblk_t *mp, sadb_msg_t *samsg,
    keysock_in_t *ksi, ipsa_t *ipsa)
{
	keysock_out_t *kso;
	mblk_t *mp1;
	sadb_msg_t *newsamsg;
	uint8_t *oldend;

	ASSERT((mp->b_cont != NULL) &&
	    ((void *)samsg == (void *)mp->b_cont->b_rptr) &&
	    ((void *)mp->b_rptr == (void *)ksi));

	switch (samsg->sadb_msg_type) {
	case SADB_ADD:
	case SADB_UPDATE:
	case SADB_X_UPDATEPAIR:
	case SADB_FLUSH:
	case SADB_DUMP:
		/*
		 * I have all of the message already.  I just need to strip
		 * out the keying material and echo the message back.
		 *
		 * NOTE: for SADB_DUMP, the function sadb_dump() did the
		 * work.  When DUMP reaches here, it should only be a base
		 * message.
		 */
	justecho:
		ASSERT(samsg->sadb_msg_type != SADB_DUMP ||
		    samsg->sadb_msg_len == SADB_8TO64(sizeof (sadb_msg_t)));

		if (ksi->ks_in_extv[SADB_EXT_KEY_AUTH] != NULL ||
		    ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT] != NULL) {
			sadb_strip(samsg);
			/* Assume PF_KEY message is contiguous. */
			ASSERT(mp->b_cont->b_cont == NULL);
			oldend = mp->b_cont->b_wptr;
			mp->b_cont->b_wptr = mp->b_cont->b_rptr +
			    SADB_64TO8(samsg->sadb_msg_len);
			bzero(mp->b_cont->b_wptr, oldend - mp->b_cont->b_wptr);
		}
		break;
	case SADB_GET:
		/*
		 * Do a lot of work here, because of the ipsa I just found.
		 * First construct the new PF_KEY message, then abandon
		 * the old one.
		 */
		mp1 = sadb_sa2msg(ipsa, samsg);
		if (mp1 == NULL) {
			sadb_pfkey_error(pfkey_q, mp, ENOMEM,
			    SADB_X_DIAGNOSTIC_NONE, ksi->ks_in_serial);
			return;
		}
		freemsg(mp->b_cont);
		mp->b_cont = mp1;
		break;
	case SADB_DELETE:
	case SADB_X_DELPAIR:
		if (ipsa == NULL)
			goto justecho;
		/*
		 * Because listening KMds may require more info, treat
		 * DELETE like a special case of GET.
		 */
		mp1 = sadb_sa2msg(ipsa, samsg);
		if (mp1 == NULL) {
			sadb_pfkey_error(pfkey_q, mp, ENOMEM,
			    SADB_X_DIAGNOSTIC_NONE, ksi->ks_in_serial);
			return;
		}
		newsamsg = (sadb_msg_t *)mp1->b_rptr;
		sadb_strip(newsamsg);
		oldend = mp1->b_wptr;
		mp1->b_wptr = mp1->b_rptr + SADB_64TO8(newsamsg->sadb_msg_len);
		bzero(mp1->b_wptr, oldend - mp1->b_wptr);
		freemsg(mp->b_cont);
		mp->b_cont = mp1;
		break;
	default:
		if (mp != NULL)
			freemsg(mp);
		return;
	}

	/* ksi is now null and void. */
	kso = (keysock_out_t *)ksi;
	kso->ks_out_type = KEYSOCK_OUT;
	kso->ks_out_len = sizeof (*kso);
	kso->ks_out_serial = ksi->ks_in_serial;
	/* We're ready to send... */
	putnext(pfkey_q, mp);
}

/*
 * Set up a global pfkey_q instance for AH, ESP, or some other consumer.
 */
void
sadb_keysock_hello(queue_t **pfkey_qp, queue_t *q, mblk_t *mp,
    void (*ager)(void *), void *agerarg, timeout_id_t *top, int satype)
{
	keysock_hello_ack_t *kha;
	queue_t *oldq;

	ASSERT(OTHERQ(q) != NULL);

	/*
	 * First, check atomically that I'm the first and only keysock
	 * instance.
	 *
	 * Use OTHERQ(q), because qreply(q, mp) == putnext(OTHERQ(q), mp),
	 * and I want this module to say putnext(*_pfkey_q, mp) for PF_KEY
	 * messages.
	 */

	oldq = casptr((void **)pfkey_qp, NULL, OTHERQ(q));
	if (oldq != NULL) {
		ASSERT(oldq != q);
		cmn_err(CE_WARN, "Danger!  Multiple keysocks on top of %s.\n",
		    (satype == SADB_SATYPE_ESP)? "ESP" : "AH or other");
		freemsg(mp);
		return;
	}

	kha = (keysock_hello_ack_t *)mp->b_rptr;
	kha->ks_hello_len = sizeof (keysock_hello_ack_t);
	kha->ks_hello_type = KEYSOCK_HELLO_ACK;
	kha->ks_hello_satype = (uint8_t)satype;

	/*
	 * If we made it past the casptr, then we have "exclusive" access
	 * to the timeout handle.  Fire it off in 4 seconds, because it
	 * just seems like a good interval.
	 */
	*top = qtimeout(*pfkey_qp, ager, agerarg, drv_usectohz(4000000));

	putnext(*pfkey_qp, mp);
}

/*
 * Normalize IPv4-mapped IPv6 addresses (and prefixes) as appropriate.
 *
 * Check addresses themselves for wildcard or multicast.
 * Check ire table for local/non-local/broadcast.
 */
int
sadb_addrcheck(queue_t *pfkey_q, mblk_t *mp, sadb_ext_t *ext, uint_t serial,
    netstack_t *ns)
{
	sadb_address_t *addr = (sadb_address_t *)ext;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	ire_t *ire;
	int diagnostic, type;
	boolean_t normalized = B_FALSE;

	ASSERT(ext != NULL);
	ASSERT((ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC) ||
	    (ext->sadb_ext_type == SADB_EXT_ADDRESS_DST) ||
	    (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_INNER_SRC) ||
	    (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_INNER_DST) ||
	    (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_NATT_LOC) ||
	    (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_NATT_REM));

	/* Assign both sockaddrs, the compiler will do the right thing. */
	sin = (struct sockaddr_in *)(addr + 1);
	sin6 = (struct sockaddr_in6 *)(addr + 1);

	if (sin6->sin6_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			/*
			 * Convert to an AF_INET sockaddr.  This means the
			 * return messages will have the extra space, but have
			 * AF_INET sockaddrs instead of AF_INET6.
			 *
			 * Yes, RFC 2367 isn't clear on what to do here w.r.t.
			 * mapped addresses, but since AF_INET6 ::ffff:<v4> is
			 * equal to AF_INET <v4>, it shouldnt be a huge
			 * problem.
			 */
			sin->sin_family = AF_INET;
			IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr,
			    &sin->sin_addr);
			bzero(&sin->sin_zero, sizeof (sin->sin_zero));
			normalized = B_TRUE;
		}
	} else if (sin->sin_family != AF_INET) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_ADDRESS_SRC:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_SRC_AF;
			break;
		case SADB_EXT_ADDRESS_DST:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_DST_AF;
			break;
		case SADB_X_EXT_ADDRESS_INNER_SRC:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_PROXY_AF;
			break;
		case SADB_X_EXT_ADDRESS_INNER_DST:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_INNER_DST_AF;
			break;
		case SADB_X_EXT_ADDRESS_NATT_LOC:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_NATT_LOC_AF;
			break;
		case SADB_X_EXT_ADDRESS_NATT_REM:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_NATT_REM_AF;
			break;
			/* There is no default, see above ASSERT. */
		}
bail:
		if (pfkey_q != NULL) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL, diagnostic,
			    serial);
		} else {
			/*
			 * Scribble in sadb_msg that we got passed in.
			 * Overload "mp" to be an sadb_msg pointer.
			 */
			sadb_msg_t *samsg = (sadb_msg_t *)mp;

			samsg->sadb_msg_errno = EINVAL;
			samsg->sadb_x_msg_diagnostic = diagnostic;
		}
		return (KS_IN_ADDR_UNKNOWN);
	}

	if (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_INNER_SRC ||
	    ext->sadb_ext_type == SADB_X_EXT_ADDRESS_INNER_DST) {
		/*
		 * We need only check for prefix issues.
		 */

		/* Set diagnostic now, in case we need it later. */
		diagnostic =
		    (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_INNER_SRC) ?
		    SADB_X_DIAGNOSTIC_PREFIX_INNER_SRC :
		    SADB_X_DIAGNOSTIC_PREFIX_INNER_DST;

		if (normalized)
			addr->sadb_address_prefixlen -= 96;

		/*
		 * Verify and mask out inner-addresses based on prefix length.
		 */
		if (sin->sin_family == AF_INET) {
			if (addr->sadb_address_prefixlen > 32)
				goto bail;
			sin->sin_addr.s_addr &=
			    ip_plen_to_mask(addr->sadb_address_prefixlen);
		} else {
			in6_addr_t mask;

			ASSERT(sin->sin_family == AF_INET6);
			/*
			 * ip_plen_to_mask_v6() returns NULL if the value in
			 * question is out of range.
			 */
			if (ip_plen_to_mask_v6(addr->sadb_address_prefixlen,
			    &mask) == NULL)
				goto bail;
			sin6->sin6_addr.s6_addr32[0] &= mask.s6_addr32[0];
			sin6->sin6_addr.s6_addr32[1] &= mask.s6_addr32[1];
			sin6->sin6_addr.s6_addr32[2] &= mask.s6_addr32[2];
			sin6->sin6_addr.s6_addr32[3] &= mask.s6_addr32[3];
		}

		/* We don't care in these cases. */
		return (KS_IN_ADDR_DONTCARE);
	}

	if (sin->sin_family == AF_INET6) {
		/* Check the easy ones now. */
		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			return (KS_IN_ADDR_MBCAST);
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			return (KS_IN_ADDR_UNSPEC);
		/*
		 * At this point, we're a unicast IPv6 address.
		 *
		 * A ctable lookup for local is sufficient here.  If we're
		 * local, return KS_IN_ADDR_ME, otherwise KS_IN_ADDR_NOTME.
		 *
		 * XXX Zones alert -> me/notme decision needs to be tempered
		 * by what zone we're in when we go to zone-aware IPsec.
		 */
		ire = ire_ctable_lookup_v6(&sin6->sin6_addr, NULL,
		    IRE_LOCAL, NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE,
		    ns->netstack_ip);
		if (ire != NULL) {
			/* Hey hey, it's local. */
			IRE_REFRELE(ire);
			return (KS_IN_ADDR_ME);
		}
	} else {
		ASSERT(sin->sin_family == AF_INET);
		if (sin->sin_addr.s_addr == INADDR_ANY)
			return (KS_IN_ADDR_UNSPEC);
		if (CLASSD(sin->sin_addr.s_addr))
			return (KS_IN_ADDR_MBCAST);
		/*
		 * At this point we're a unicast or broadcast IPv4 address.
		 *
		 * Lookup on the ctable for IRE_BROADCAST or IRE_LOCAL.
		 * A NULL return value is NOTME, otherwise, look at the
		 * returned ire for broadcast or not and return accordingly.
		 *
		 * XXX Zones alert -> me/notme decision needs to be tempered
		 * by what zone we're in when we go to zone-aware IPsec.
		 */
		ire = ire_ctable_lookup(sin->sin_addr.s_addr, 0,
		    IRE_LOCAL | IRE_BROADCAST, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_TYPE, ns->netstack_ip);
		if (ire != NULL) {
			/* Check for local or broadcast */
			type = ire->ire_type;
			IRE_REFRELE(ire);
			ASSERT(type == IRE_LOCAL || type == IRE_BROADCAST);
			return ((type == IRE_LOCAL) ? KS_IN_ADDR_ME :
			    KS_IN_ADDR_MBCAST);
		}
	}

	return (KS_IN_ADDR_NOTME);
}

/*
 * Address normalizations and reality checks for inbound PF_KEY messages.
 *
 * For the case of src == unspecified AF_INET6, and dst == AF_INET, convert
 * the source to AF_INET.  Do the same for the inner sources.
 */
boolean_t
sadb_addrfix(keysock_in_t *ksi, queue_t *pfkey_q, mblk_t *mp, netstack_t *ns)
{
	struct sockaddr_in *src, *isrc;
	struct sockaddr_in6 *dst, *idst;
	sadb_address_t *srcext, *dstext;
	uint16_t sport;
	sadb_ext_t **extv = ksi->ks_in_extv;
	int rc;

	if (extv[SADB_EXT_ADDRESS_SRC] != NULL) {
		rc = sadb_addrcheck(pfkey_q, mp, extv[SADB_EXT_ADDRESS_SRC],
		    ksi->ks_in_serial, ns);
		if (rc == KS_IN_ADDR_UNKNOWN)
			return (B_FALSE);
		if (rc == KS_IN_ADDR_MBCAST) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_BAD_SRC, ksi->ks_in_serial);
			return (B_FALSE);
		}
		ksi->ks_in_srctype = rc;
	}

	if (extv[SADB_EXT_ADDRESS_DST] != NULL) {
		rc = sadb_addrcheck(pfkey_q, mp, extv[SADB_EXT_ADDRESS_DST],
		    ksi->ks_in_serial, ns);
		if (rc == KS_IN_ADDR_UNKNOWN)
			return (B_FALSE);
		if (rc == KS_IN_ADDR_UNSPEC) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_BAD_DST, ksi->ks_in_serial);
			return (B_FALSE);
		}
		ksi->ks_in_dsttype = rc;
	}

	/*
	 * NAT-Traversal addrs are simple enough to not require all of
	 * the checks in sadb_addrcheck().  Just normalize or reject if not
	 * AF_INET.
	 */
	if (extv[SADB_X_EXT_ADDRESS_NATT_LOC] != NULL) {
		rc = sadb_addrcheck(pfkey_q, mp,
		    extv[SADB_X_EXT_ADDRESS_NATT_LOC], ksi->ks_in_serial, ns);

		/*
		 * Local NAT-T addresses never use an IRE_LOCAL, so it should
		 * always be NOTME, or UNSPEC (to handle both tunnel mode
		 * AND local-port flexibility).
		 */
		if (rc != KS_IN_ADDR_NOTME && rc != KS_IN_ADDR_UNSPEC) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_MALFORMED_NATT_LOC,
			    ksi->ks_in_serial);
			return (B_FALSE);
		}
		src = (struct sockaddr_in *)
		    (((sadb_address_t *)extv[SADB_X_EXT_ADDRESS_NATT_LOC]) + 1);
		if (src->sin_family != AF_INET) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_BAD_NATT_LOC_AF,
			    ksi->ks_in_serial);
			return (B_FALSE);
		}
	}

	if (extv[SADB_X_EXT_ADDRESS_NATT_REM] != NULL) {
		rc = sadb_addrcheck(pfkey_q, mp,
		    extv[SADB_X_EXT_ADDRESS_NATT_REM], ksi->ks_in_serial, ns);

		/*
		 * Remote NAT-T addresses never use an IRE_LOCAL, so it should
		 * always be NOTME, or UNSPEC if it's a tunnel-mode SA.
		 */
		if (rc != KS_IN_ADDR_NOTME &&
		    !(extv[SADB_X_EXT_ADDRESS_INNER_SRC] != NULL &&
		    rc == KS_IN_ADDR_UNSPEC)) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_MALFORMED_NATT_REM,
			    ksi->ks_in_serial);
			return (B_FALSE);
		}
		src = (struct sockaddr_in *)
		    (((sadb_address_t *)extv[SADB_X_EXT_ADDRESS_NATT_REM]) + 1);
		if (src->sin_family != AF_INET) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_BAD_NATT_REM_AF,
			    ksi->ks_in_serial);
			return (B_FALSE);
		}
	}

	if (extv[SADB_X_EXT_ADDRESS_INNER_SRC] != NULL) {
		if (extv[SADB_X_EXT_ADDRESS_INNER_DST] == NULL) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_MISSING_INNER_DST,
			    ksi->ks_in_serial);
			return (B_FALSE);
		}

		if (sadb_addrcheck(pfkey_q, mp,
		    extv[SADB_X_EXT_ADDRESS_INNER_DST], ksi->ks_in_serial, ns)
		    == KS_IN_ADDR_UNKNOWN ||
		    sadb_addrcheck(pfkey_q, mp,
		    extv[SADB_X_EXT_ADDRESS_INNER_SRC], ksi->ks_in_serial, ns)
		    == KS_IN_ADDR_UNKNOWN)
			return (B_FALSE);

		isrc = (struct sockaddr_in *)
		    (((sadb_address_t *)extv[SADB_X_EXT_ADDRESS_INNER_SRC]) +
		    1);
		idst = (struct sockaddr_in6 *)
		    (((sadb_address_t *)extv[SADB_X_EXT_ADDRESS_INNER_DST]) +
		    1);
		if (isrc->sin_family != idst->sin6_family) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_INNER_AF_MISMATCH,
			    ksi->ks_in_serial);
			return (B_FALSE);
		}
	} else if (extv[SADB_X_EXT_ADDRESS_INNER_DST] != NULL) {
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_MISSING_INNER_SRC,
			    ksi->ks_in_serial);
			return (B_FALSE);
	} else {
		isrc = NULL;	/* For inner/outer port check below. */
	}

	dstext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_DST];
	srcext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_SRC];

	if (dstext == NULL || srcext == NULL)
		return (B_TRUE);

	dst = (struct sockaddr_in6 *)(dstext + 1);
	src = (struct sockaddr_in *)(srcext + 1);

	if (isrc != NULL &&
	    (isrc->sin_port != 0 || idst->sin6_port != 0) &&
	    (src->sin_port != 0 || dst->sin6_port != 0)) {
		/* Can't set inner and outer ports in one SA. */
		sadb_pfkey_error(pfkey_q, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_DUAL_PORT_SETS,
		    ksi->ks_in_serial);
		return (B_FALSE);
	}

	if (dst->sin6_family == src->sin_family)
		return (B_TRUE);

	if (srcext->sadb_address_proto != dstext->sadb_address_proto) {
		if (srcext->sadb_address_proto == 0) {
			srcext->sadb_address_proto = dstext->sadb_address_proto;
		} else if (dstext->sadb_address_proto == 0) {
			dstext->sadb_address_proto = srcext->sadb_address_proto;
		} else {
			/* Inequal protocols, neither were 0.  Report error. */
			sadb_pfkey_error(pfkey_q, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_PROTO_MISMATCH,
			    ksi->ks_in_serial);
			return (B_FALSE);
		}
	}

	/*
	 * With the exception of an unspec IPv6 source and an IPv4
	 * destination, address families MUST me matched.
	 */
	if (src->sin_family == AF_INET ||
	    ksi->ks_in_srctype != KS_IN_ADDR_UNSPEC) {
		sadb_pfkey_error(pfkey_q, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_AF_MISMATCH, ksi->ks_in_serial);
		return (B_FALSE);
	}

	/*
	 * Convert "src" to AF_INET INADDR_ANY.  We rely on sin_port being
	 * in the same place for sockaddr_in and sockaddr_in6.
	 */
	sport = src->sin_port;
	bzero(src, sizeof (*src));
	src->sin_family = AF_INET;
	src->sin_port = sport;

	return (B_TRUE);
}

/*
 * Set the results in "addrtype", given an IRE as requested by
 * sadb_addrcheck().
 */
int
sadb_addrset(ire_t *ire)
{
	if ((ire->ire_type & IRE_BROADCAST) ||
	    (ire->ire_ipversion == IPV4_VERSION && CLASSD(ire->ire_addr)) ||
	    (ire->ire_ipversion == IPV6_VERSION &&
	    IN6_IS_ADDR_MULTICAST(&(ire->ire_addr_v6))))
		return (KS_IN_ADDR_MBCAST);
	if (ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK))
		return (KS_IN_ADDR_ME);
	return (KS_IN_ADDR_NOTME);
}


/*
 * Walker callback function to delete sa's based on src/dst address.
 * Assumes that we're called with *head locked, no other locks held;
 * Conveniently, and not coincidentally, this is both what sadb_walker
 * gives us and also what sadb_unlinkassoc expects.
 */

struct sadb_purge_state
{
	uint32_t *src;
	uint32_t *dst;
	sa_family_t af;
	boolean_t inbnd;
	char *sidstr;
	char *didstr;
	uint16_t sidtype;
	uint16_t didtype;
	uint32_t kmproto;
	mblk_t *mq;
};

static void
sadb_purge_cb(isaf_t *head, ipsa_t *entry, void *cookie)
{
	struct sadb_purge_state *ps = (struct sadb_purge_state *)cookie;

	ASSERT(MUTEX_HELD(&head->isaf_lock));

	mutex_enter(&entry->ipsa_lock);

	if ((entry->ipsa_state == IPSA_STATE_LARVAL) ||
	    (ps->src != NULL &&
	    !IPSA_ARE_ADDR_EQUAL(entry->ipsa_srcaddr, ps->src, ps->af)) ||
	    (ps->dst != NULL &&
	    !IPSA_ARE_ADDR_EQUAL(entry->ipsa_dstaddr, ps->dst, ps->af)) ||
	    (ps->didstr != NULL && (entry->ipsa_dst_cid != NULL) &&
	    !(ps->didtype == entry->ipsa_dst_cid->ipsid_type &&
	    strcmp(ps->didstr, entry->ipsa_dst_cid->ipsid_cid) == 0)) ||
	    (ps->sidstr != NULL && (entry->ipsa_src_cid != NULL) &&
	    !(ps->sidtype == entry->ipsa_src_cid->ipsid_type &&
	    strcmp(ps->sidstr, entry->ipsa_src_cid->ipsid_cid) == 0)) ||
	    (ps->kmproto <= SADB_X_KMP_MAX && ps->kmproto != entry->ipsa_kmp)) {
		mutex_exit(&entry->ipsa_lock);
		return;
	}

	entry->ipsa_state = IPSA_STATE_DEAD;
	(void) sadb_torch_assoc(head, entry, ps->inbnd, &ps->mq);
}

/*
 * Common code to purge an SA with a matching src or dst address.
 * Don't kill larval SA's in such a purge.
 */
int
sadb_purge_sa(mblk_t *mp, keysock_in_t *ksi, sadb_t *sp, queue_t *pfkey_q,
    queue_t *ip_q)
{
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_ident_t *dstid =
	    (sadb_ident_t *)ksi->ks_in_extv[SADB_EXT_IDENTITY_DST];
	sadb_ident_t *srcid =
	    (sadb_ident_t *)ksi->ks_in_extv[SADB_EXT_IDENTITY_SRC];
	sadb_x_kmc_t *kmc =
	    (sadb_x_kmc_t *)ksi->ks_in_extv[SADB_X_EXT_KM_COOKIE];
	struct sockaddr_in *src, *dst;
	struct sockaddr_in6 *src6, *dst6;
	struct sadb_purge_state ps;

	/*
	 * Don't worry about IPv6 v4-mapped addresses, sadb_addrcheck()
	 * takes care of them.
	 */

	/* enforced by caller */
	ASSERT((dstext != NULL) || (srcext != NULL));

	ps.src = NULL;
	ps.dst = NULL;
#ifdef DEBUG
	ps.af = (sa_family_t)-1;
#endif
	ps.mq = NULL;
	ps.sidstr = NULL;
	ps.didstr = NULL;
	ps.kmproto = SADB_X_KMP_MAX + 1;

	if (dstext != NULL) {
		dst = (struct sockaddr_in *)(dstext + 1);
		ps.af = dst->sin_family;
		if (dst->sin_family == AF_INET6) {
			dst6 = (struct sockaddr_in6 *)dst;
			ps.dst = (uint32_t *)&dst6->sin6_addr;
		} else {
			ps.dst = (uint32_t *)&dst->sin_addr;
		}
	}

	if (srcext != NULL) {
		src = (struct sockaddr_in *)(srcext + 1);
		ps.af = src->sin_family;
		if (src->sin_family == AF_INET6) {
			src6 = (struct sockaddr_in6 *)(srcext + 1);
			ps.src = (uint32_t *)&src6->sin6_addr;
		} else {
			ps.src = (uint32_t *)&src->sin_addr;
		}
		ASSERT(dstext == NULL || src->sin_family == dst->sin_family);
	}

	ASSERT(ps.af != (sa_family_t)-1);

	if (dstid != NULL) {
		/*
		 * NOTE:  May need to copy string in the future
		 * if the inbound keysock message disappears for some strange
		 * reason.
		 */
		ps.didstr = (char *)(dstid + 1);
		ps.didtype = dstid->sadb_ident_type;
	}

	if (srcid != NULL) {
		/*
		 * NOTE:  May need to copy string in the future
		 * if the inbound keysock message disappears for some strange
		 * reason.
		 */
		ps.sidstr = (char *)(srcid + 1);
		ps.sidtype = srcid->sadb_ident_type;
	}

	if (kmc != NULL)
		ps.kmproto = kmc->sadb_x_kmc_proto;

	/*
	 * This is simple, crude, and effective.
	 * Unimplemented optimizations (TBD):
	 * - we can limit how many places we search based on where we
	 * think the SA is filed.
	 * - if we get a dst address, we can hash based on dst addr to find
	 * the correct bucket in the outbound table.
	 */
	ps.inbnd = B_TRUE;
	sadb_walker(sp->sdb_if, sp->sdb_hashsize, sadb_purge_cb, &ps);
	ps.inbnd = B_FALSE;
	sadb_walker(sp->sdb_of, sp->sdb_hashsize, sadb_purge_cb, &ps);

	if (ps.mq != NULL)
		sadb_drain_torchq(ip_q, ps.mq);

	ASSERT(mp->b_cont != NULL);
	sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr, ksi,
	    NULL);
	return (0);
}

/*
 * Common code to delete/get an SA.
 */
int
sadb_delget_sa(mblk_t *mp, keysock_in_t *ksi, sadbp_t *spp,
    int *diagnostic, queue_t *pfkey_q, uint8_t sadb_msg_type)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	ipsa_t *echo_target = NULL;
	ipsap_t *ipsapp;
	mblk_t *torchq = NULL;
	uint_t	error = 0;

	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}
	if (assoc == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SA;
		return (EINVAL);
	}

	ipsapp = get_ipsa_pair(assoc, srcext, dstext, spp);
	if (ipsapp == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_SA_NOTFOUND;
		return (ESRCH);
	}

	echo_target = ipsapp->ipsap_sa_ptr;
	if (echo_target == NULL)
		echo_target = ipsapp->ipsap_psa_ptr;

	if (sadb_msg_type == SADB_DELETE || sadb_msg_type == SADB_X_DELPAIR) {
		/*
		 * Bucket locks will be required if SA is actually unlinked.
		 * get_ipsa_pair() returns valid hash bucket pointers even
		 * if it can't find a pair SA pointer.
		 */
		mutex_enter(&ipsapp->ipsap_bucket->isaf_lock);
		mutex_enter(&ipsapp->ipsap_pbucket->isaf_lock);

		if (ipsapp->ipsap_sa_ptr != NULL) {
			mutex_enter(&ipsapp->ipsap_sa_ptr->ipsa_lock);
			ipsapp->ipsap_sa_ptr->ipsa_state = IPSA_STATE_DEAD;
			(void) sadb_torch_assoc(ipsapp->ipsap_bucket,
			    ipsapp->ipsap_sa_ptr, B_FALSE, &torchq);
			/*
			 * sadb_torch_assoc() releases the ipsa_lock
			 * and calls sadb_unlinkassoc() which does a
			 * IPSA_REFRELE.
			 */
		}
		if (ipsapp->ipsap_psa_ptr != NULL) {
			mutex_enter(&ipsapp->ipsap_psa_ptr->ipsa_lock);
			if (sadb_msg_type == SADB_X_DELPAIR) {
				ipsapp->ipsap_psa_ptr->ipsa_state =
				    IPSA_STATE_DEAD;
				(void) sadb_torch_assoc(ipsapp->ipsap_pbucket,
				    ipsapp->ipsap_psa_ptr, B_FALSE, &torchq);
			} else {
				/*
				 * Only half of the "pair" has been deleted.
				 * Update the remaining SA and remove references
				 * to its pair SA, which is now gone.
				 */
				ipsapp->ipsap_psa_ptr->ipsa_otherspi = 0;
				ipsapp->ipsap_psa_ptr->ipsa_flags &=
				    ~IPSA_F_PAIRED;
				mutex_exit(&ipsapp->ipsap_psa_ptr->ipsa_lock);
			}
		} else if (sadb_msg_type == SADB_X_DELPAIR) {
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
			error = ESRCH;
		}
		mutex_exit(&ipsapp->ipsap_bucket->isaf_lock);
		mutex_exit(&ipsapp->ipsap_pbucket->isaf_lock);
	}

	if (torchq != NULL)
		sadb_drain_torchq(spp->s_ip_q, torchq);

	ASSERT(mp->b_cont != NULL);

	if (error == 0)
		sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)
		    mp->b_cont->b_rptr, ksi, echo_target);

	destroy_ipsa_pair(ipsapp);

	return (error);
}

/*
 * This function takes a sadb_sa_t and finds the ipsa_t structure
 * and the isaf_t (hash bucket) that its stored under. If the security
 * association has a peer, the ipsa_t structure and bucket for that security
 * association are also searched for. The "pair" of ipsa_t's and isaf_t's
 * are returned as a ipsap_t.
 *
 * Note that a "pair" is defined as one (but not both) of the following:
 *
 * A security association which has a soft reference to another security
 * association via its SPI.
 *
 * A security association that is not obviously "inbound" or "outbound" so
 * it appears in both hash tables, the "peer" being the same security
 * association in the other hash table.
 *
 * This function will return NULL if the ipsa_t can't be found in the
 * inbound or outbound  hash tables (not found). If only one ipsa_t is
 * found, the pair ipsa_t will be NULL. Both isaf_t values are valid
 * provided at least one ipsa_t is found.
 */
ipsap_t *
get_ipsa_pair(sadb_sa_t *assoc, sadb_address_t *srcext, sadb_address_t *dstext,
    sadbp_t *spp)
{
	struct sockaddr_in *src, *dst;
	struct sockaddr_in6 *src6, *dst6;
	sadb_t *sp;
	uint32_t *srcaddr, *dstaddr;
	isaf_t *outbound_bucket, *inbound_bucket;
	boolean_t in_inbound_table = B_FALSE;
	ipsap_t *ipsapp;
	sa_family_t af;

	uint32_t pair_srcaddr[IPSA_MAX_ADDRLEN];
	uint32_t pair_dstaddr[IPSA_MAX_ADDRLEN];
	uint32_t pair_spi;

	ipsapp = kmem_zalloc(sizeof (*ipsapp), KM_NOSLEEP);
	if (ipsapp == NULL)
		return (NULL);

	/*
	 * Don't worry about IPv6 v4-mapped addresses, sadb_addrcheck()
	 * takes care of them.
	 */

	dst = (struct sockaddr_in *)(dstext + 1);
	af = dst->sin_family;
	if (af == AF_INET6) {
		sp = &spp->s_v6;
		dst6 = (struct sockaddr_in6 *)dst;
		dstaddr = (uint32_t *)&dst6->sin6_addr;
		if (srcext != NULL) {
			src6 = (struct sockaddr_in6 *)(srcext + 1);
			srcaddr = (uint32_t *)&src6->sin6_addr;
			ASSERT(src6->sin6_family == af);
			ASSERT(src6->sin6_family == AF_INET6);
		} else {
			srcaddr = ALL_ZEROES_PTR;
		}
		outbound_bucket = OUTBOUND_BUCKET_V6(sp,
		    *(uint32_t *)dstaddr);
	} else {
		sp = &spp->s_v4;
		dstaddr = (uint32_t *)&dst->sin_addr;
		if (srcext != NULL) {
			src = (struct sockaddr_in *)(srcext + 1);
			srcaddr = (uint32_t *)&src->sin_addr;
			ASSERT(src->sin_family == af);
			ASSERT(src->sin_family == AF_INET);
		} else {
			srcaddr = ALL_ZEROES_PTR;
		}
		outbound_bucket = OUTBOUND_BUCKET_V4(sp,
		    *(uint32_t *)dstaddr);
	}

	inbound_bucket = INBOUND_BUCKET(sp, assoc->sadb_sa_spi);

	/* Lock down both buckets. */
	mutex_enter(&outbound_bucket->isaf_lock);
	mutex_enter(&inbound_bucket->isaf_lock);

	if (assoc->sadb_sa_flags & IPSA_F_INBOUND) {
		ipsapp->ipsap_sa_ptr = ipsec_getassocbyspi(inbound_bucket,
		    assoc->sadb_sa_spi, srcaddr, dstaddr, af);
		if (ipsapp->ipsap_sa_ptr != NULL) {
			ipsapp->ipsap_bucket = inbound_bucket;
			ipsapp->ipsap_pbucket = outbound_bucket;
			in_inbound_table = B_TRUE;
		} else {
			ipsapp->ipsap_sa_ptr =
			    ipsec_getassocbyspi(outbound_bucket,
			    assoc->sadb_sa_spi, srcaddr, dstaddr, af);
			ipsapp->ipsap_bucket = outbound_bucket;
			ipsapp->ipsap_pbucket = inbound_bucket;
		}
	} else {
		/* IPSA_F_OUTBOUND is set *or* no directions flags set. */
		ipsapp->ipsap_sa_ptr =
		    ipsec_getassocbyspi(outbound_bucket,
		    assoc->sadb_sa_spi, srcaddr, dstaddr, af);
		if (ipsapp->ipsap_sa_ptr != NULL) {
			ipsapp->ipsap_bucket = outbound_bucket;
			ipsapp->ipsap_pbucket = inbound_bucket;
		} else {
			ipsapp->ipsap_sa_ptr =
			    ipsec_getassocbyspi(inbound_bucket,
			    assoc->sadb_sa_spi, srcaddr, dstaddr, af);
			ipsapp->ipsap_bucket = inbound_bucket;
			ipsapp->ipsap_pbucket = outbound_bucket;
			if (ipsapp->ipsap_sa_ptr != NULL)
				in_inbound_table = B_TRUE;
		}
	}

	if (ipsapp->ipsap_sa_ptr == NULL) {
		mutex_exit(&outbound_bucket->isaf_lock);
		mutex_exit(&inbound_bucket->isaf_lock);
		kmem_free(ipsapp, sizeof (*ipsapp));
		return (NULL);
	}

	if ((ipsapp->ipsap_sa_ptr->ipsa_state == IPSA_STATE_LARVAL) &&
	    in_inbound_table) {
		mutex_exit(&outbound_bucket->isaf_lock);
		mutex_exit(&inbound_bucket->isaf_lock);
		return (ipsapp);
	}

	mutex_enter(&ipsapp->ipsap_sa_ptr->ipsa_lock);
	if (ipsapp->ipsap_sa_ptr->ipsa_haspeer) {
		/*
		 * haspeer implies no sa_pairing, look for same spi
		 * in other hashtable.
		 */
		ipsapp->ipsap_psa_ptr =
		    ipsec_getassocbyspi(ipsapp->ipsap_pbucket,
		    assoc->sadb_sa_spi, srcaddr, dstaddr, af);
		mutex_exit(&ipsapp->ipsap_sa_ptr->ipsa_lock);
		mutex_exit(&outbound_bucket->isaf_lock);
		mutex_exit(&inbound_bucket->isaf_lock);
		return (ipsapp);
	}
	pair_spi = ipsapp->ipsap_sa_ptr->ipsa_otherspi;
	IPSA_COPY_ADDR(&pair_srcaddr,
	    ipsapp->ipsap_sa_ptr->ipsa_srcaddr, af);
	IPSA_COPY_ADDR(&pair_dstaddr,
	    ipsapp->ipsap_sa_ptr->ipsa_dstaddr, af);
	mutex_exit(&ipsapp->ipsap_sa_ptr->ipsa_lock);
	mutex_exit(&outbound_bucket->isaf_lock);
	mutex_exit(&inbound_bucket->isaf_lock);

	if (pair_spi == 0) {
		ASSERT(ipsapp->ipsap_bucket != NULL);
		ASSERT(ipsapp->ipsap_pbucket != NULL);
		return (ipsapp);
	}

	/* found sa in outbound sadb, peer should be inbound */

	if (in_inbound_table) {
		/* Found SA in inbound table, pair will be in outbound. */
		if (af == AF_INET6) {
			ipsapp->ipsap_pbucket = OUTBOUND_BUCKET_V6(sp,
			    *(uint32_t *)pair_srcaddr);
		} else {
			ipsapp->ipsap_pbucket = OUTBOUND_BUCKET_V4(sp,
			    *(uint32_t *)pair_srcaddr);
		}
	} else {
		ipsapp->ipsap_pbucket = INBOUND_BUCKET(sp, pair_spi);
	}
	mutex_enter(&ipsapp->ipsap_pbucket->isaf_lock);
	ipsapp->ipsap_psa_ptr = ipsec_getassocbyspi(ipsapp->ipsap_pbucket,
	    pair_spi, pair_dstaddr, pair_srcaddr, af);
	mutex_exit(&ipsapp->ipsap_pbucket->isaf_lock);

	ASSERT(ipsapp->ipsap_bucket != NULL);
	ASSERT(ipsapp->ipsap_pbucket != NULL);
	return (ipsapp);
}

/*
 * Initialize the mechanism parameters associated with an SA.
 * These parameters can be shared by multiple packets, which saves
 * us from the overhead of consulting the algorithm table for
 * each packet.
 */
static void
sadb_init_alginfo(ipsa_t *sa)
{
	ipsec_alginfo_t *alg;
	ipsec_stack_t	*ipss = sa->ipsa_netstack->netstack_ipsec;

	mutex_enter(&ipss->ipsec_alg_lock);

	if (sa->ipsa_encrkey != NULL) {
		alg = ipss->ipsec_alglists[IPSEC_ALG_ENCR][sa->ipsa_encr_alg];
		if (alg != NULL && ALG_VALID(alg)) {
			sa->ipsa_emech.cm_type = alg->alg_mech_type;
			sa->ipsa_emech.cm_param = NULL;
			sa->ipsa_emech.cm_param_len = 0;
			sa->ipsa_iv_len = alg->alg_datalen;
		} else
			sa->ipsa_emech.cm_type = CRYPTO_MECHANISM_INVALID;
	}

	if (sa->ipsa_authkey != NULL) {
		alg = ipss->ipsec_alglists[IPSEC_ALG_AUTH][sa->ipsa_auth_alg];
		if (alg != NULL && ALG_VALID(alg)) {
			sa->ipsa_amech.cm_type = alg->alg_mech_type;
			sa->ipsa_amech.cm_param = (char *)&sa->ipsa_mac_len;
			sa->ipsa_amech.cm_param_len = sizeof (size_t);
			sa->ipsa_mac_len = (size_t)alg->alg_datalen;
		} else
			sa->ipsa_amech.cm_type = CRYPTO_MECHANISM_INVALID;
	}

	mutex_exit(&ipss->ipsec_alg_lock);
}

/*
 * Perform NAT-traversal cached checksum offset calculations here.
 */
static void
sadb_nat_calculations(ipsa_t *newbie, sadb_address_t *natt_loc_ext,
    sadb_address_t *natt_rem_ext, uint32_t *src_addr_ptr,
    uint32_t *dst_addr_ptr)
{
	struct sockaddr_in *natt_loc, *natt_rem;
	uint32_t *natt_loc_ptr = NULL, *natt_rem_ptr = NULL;
	uint32_t running_sum = 0;

#define	DOWN_SUM(x) (x) = ((x) & 0xFFFF) +	 ((x) >> 16)

	if (natt_rem_ext != NULL) {
		uint32_t l_src;
		uint32_t l_rem;

		natt_rem = (struct sockaddr_in *)(natt_rem_ext + 1);

		/* Ensured by sadb_addrfix(). */
		ASSERT(natt_rem->sin_family == AF_INET);

		natt_rem_ptr = (uint32_t *)(&natt_rem->sin_addr);
		newbie->ipsa_remote_nat_port = natt_rem->sin_port;
		l_src = *src_addr_ptr;
		l_rem = *natt_rem_ptr;

		/* Instead of IPSA_COPY_ADDR(), just copy first 32 bits. */
		newbie->ipsa_natt_addr_rem = *natt_rem_ptr;

		l_src = ntohl(l_src);
		DOWN_SUM(l_src);
		DOWN_SUM(l_src);
		l_rem = ntohl(l_rem);
		DOWN_SUM(l_rem);
		DOWN_SUM(l_rem);

		/*
		 * We're 1's complement for checksums, so check for wraparound
		 * here.
		 */
		if (l_rem > l_src)
			l_src--;

		running_sum += l_src - l_rem;

		DOWN_SUM(running_sum);
		DOWN_SUM(running_sum);
	}

	if (natt_loc_ext != NULL) {
		natt_loc = (struct sockaddr_in *)(natt_loc_ext + 1);

		/* Ensured by sadb_addrfix(). */
		ASSERT(natt_loc->sin_family == AF_INET);

		natt_loc_ptr = (uint32_t *)(&natt_loc->sin_addr);
		newbie->ipsa_local_nat_port = natt_loc->sin_port;

		/* Instead of IPSA_COPY_ADDR(), just copy first 32 bits. */
		newbie->ipsa_natt_addr_loc = *natt_loc_ptr;

		/*
		 * NAT-T port agility means we may have natt_loc_ext, but
		 * only for a local-port change.
		 */
		if (natt_loc->sin_addr.s_addr != INADDR_ANY) {
			uint32_t l_dst = ntohl(*dst_addr_ptr);
			uint32_t l_loc = ntohl(*natt_loc_ptr);

			DOWN_SUM(l_loc);
			DOWN_SUM(l_loc);
			DOWN_SUM(l_dst);
			DOWN_SUM(l_dst);

			/*
			 * We're 1's complement for checksums, so check for
			 * wraparound here.
			 */
			if (l_loc > l_dst)
				l_dst--;

			running_sum += l_dst - l_loc;
			DOWN_SUM(running_sum);
			DOWN_SUM(running_sum);
		}
	}

	newbie->ipsa_inbound_cksum = running_sum;
#undef DOWN_SUM
}

/*
 * This function is called from consumers that need to insert a fully-grown
 * security association into its tables.  This function takes into account that
 * SAs can be "inbound", "outbound", or "both".	 The "primary" and "secondary"
 * hash bucket parameters are set in order of what the SA will be most of the
 * time.  (For example, an SA with an unspecified source, and a multicast
 * destination will primarily be an outbound SA.  OTOH, if that destination
 * is unicast for this node, then the SA will primarily be inbound.)
 *
 * It takes a lot of parameters because even if clone is B_FALSE, this needs
 * to check both buckets for purposes of collision.
 *
 * Return 0 upon success.  Return various errnos (ENOMEM, EEXIST) for
 * various error conditions.  We may need to set samsg->sadb_x_msg_diagnostic
 * with additional diagnostic information because there is at least one EINVAL
 * case here.
 */
int
sadb_common_add(queue_t *ip_q, queue_t *pfkey_q, mblk_t *mp, sadb_msg_t *samsg,
    keysock_in_t *ksi, isaf_t *primary, isaf_t *secondary,
    ipsa_t *newbie, boolean_t clone, boolean_t is_inbound, int *diagnostic,
    netstack_t *ns, sadbp_t *spp)
{
	ipsa_t *newbie_clone = NULL, *scratch;
	ipsap_t *ipsapp = NULL;
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_address_t *isrcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_INNER_SRC];
	sadb_address_t *idstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_INNER_DST];
	sadb_x_kmc_t *kmcext =
	    (sadb_x_kmc_t *)ksi->ks_in_extv[SADB_X_EXT_KM_COOKIE];
	sadb_key_t *akey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_AUTH];
	sadb_key_t *ekey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT];
	sadb_x_pair_t *pair_ext =
	    (sadb_x_pair_t *)ksi->ks_in_extv[SADB_X_EXT_PAIR];
#if 0
	/*
	 * XXXMLS - When Trusted Solaris or Multi-Level Secure functionality
	 * comes to ON, examine these if 0'ed fragments.  Look for XXXMLS.
	 */
	sadb_sens_t *sens = (sadb_sens_t *);
#endif
	struct sockaddr_in *src, *dst, *isrc, *idst;
	struct sockaddr_in6 *src6, *dst6, *isrc6, *idst6;
	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];
	sa_family_t af;
	int error = 0;
	boolean_t isupdate = (newbie != NULL);
	uint32_t *src_addr_ptr, *dst_addr_ptr, *isrc_addr_ptr, *idst_addr_ptr;
	mblk_t *ctl_mp = NULL;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	if (srcext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return (EINVAL);
	}
	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}
	if (assoc == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SA;
		return (EINVAL);
	}

	src = (struct sockaddr_in *)(srcext + 1);
	src6 = (struct sockaddr_in6 *)(srcext + 1);
	dst = (struct sockaddr_in *)(dstext + 1);
	dst6 = (struct sockaddr_in6 *)(dstext + 1);
	if (isrcext != NULL) {
		isrc = (struct sockaddr_in *)(isrcext + 1);
		isrc6 = (struct sockaddr_in6 *)(isrcext + 1);
		ASSERT(idstext != NULL);
		idst = (struct sockaddr_in *)(idstext + 1);
		idst6 = (struct sockaddr_in6 *)(idstext + 1);
	} else {
		isrc = NULL;
		isrc6 = NULL;
	}

	af = src->sin_family;

	if (af == AF_INET) {
		src_addr_ptr = (uint32_t *)&src->sin_addr;
		dst_addr_ptr = (uint32_t *)&dst->sin_addr;
	} else {
		ASSERT(af == AF_INET6);
		src_addr_ptr = (uint32_t *)&src6->sin6_addr;
		dst_addr_ptr = (uint32_t *)&dst6->sin6_addr;
	}

	/*
	 * Check to see if the new SA will be cloned AND paired. The
	 * reason a SA will be cloned is the source or destination addresses
	 * are not specific enough to determine if the SA goes in the outbound
	 * or the inbound hash table, so its cloned and put in both. If
	 * the SA is paired, it's soft linked to another SA for the other
	 * direction. Keeping track and looking up SA's that are direction
	 * unspecific and linked is too hard.
	 */
	if (clone && (pair_ext != NULL)) {
		*diagnostic = SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE;
		return (EINVAL);
	}

	if (!isupdate) {
		newbie = sadb_makelarvalassoc(assoc->sadb_sa_spi,
		    src_addr_ptr, dst_addr_ptr, af, ns);
		if (newbie == NULL)
			return (ENOMEM);
	}

	mutex_enter(&newbie->ipsa_lock);

	if (isrc != NULL) {
		if (isrc->sin_family == AF_INET) {
			if (srcext->sadb_address_proto != IPPROTO_ENCAP) {
				if (srcext->sadb_address_proto != 0) {
					/*
					 * Mismatched outer-packet protocol
					 * and inner-packet address family.
					 */
					mutex_exit(&newbie->ipsa_lock);
					error = EPROTOTYPE;
					goto error;
				} else {
					/* Fill in with explicit protocol. */
					srcext->sadb_address_proto =
					    IPPROTO_ENCAP;
					dstext->sadb_address_proto =
					    IPPROTO_ENCAP;
				}
			}
			isrc_addr_ptr = (uint32_t *)&isrc->sin_addr;
			idst_addr_ptr = (uint32_t *)&idst->sin_addr;
		} else {
			ASSERT(isrc->sin_family == AF_INET6);
			if (srcext->sadb_address_proto != IPPROTO_IPV6) {
				if (srcext->sadb_address_proto != 0) {
					/*
					 * Mismatched outer-packet protocol
					 * and inner-packet address family.
					 */
					mutex_exit(&newbie->ipsa_lock);
					error = EPROTOTYPE;
					goto error;
				} else {
					/* Fill in with explicit protocol. */
					srcext->sadb_address_proto =
					    IPPROTO_IPV6;
					dstext->sadb_address_proto =
					    IPPROTO_IPV6;
				}
			}
			isrc_addr_ptr = (uint32_t *)&isrc6->sin6_addr;
			idst_addr_ptr = (uint32_t *)&idst6->sin6_addr;
		}
		newbie->ipsa_innerfam = isrc->sin_family;

		IPSA_COPY_ADDR(newbie->ipsa_innersrc, isrc_addr_ptr,
		    newbie->ipsa_innerfam);
		IPSA_COPY_ADDR(newbie->ipsa_innerdst, idst_addr_ptr,
		    newbie->ipsa_innerfam);
		newbie->ipsa_innersrcpfx = isrcext->sadb_address_prefixlen;
		newbie->ipsa_innerdstpfx = idstext->sadb_address_prefixlen;

		/* Unique value uses inner-ports for Tunnel Mode... */
		newbie->ipsa_unique_id = SA_UNIQUE_ID(isrc->sin_port,
		    idst->sin_port, dstext->sadb_address_proto,
		    idstext->sadb_address_proto);
		newbie->ipsa_unique_mask = SA_UNIQUE_MASK(isrc->sin_port,
		    idst->sin_port, dstext->sadb_address_proto,
		    idstext->sadb_address_proto);
	} else {
		/* ... and outer-ports for Transport Mode. */
		newbie->ipsa_unique_id = SA_UNIQUE_ID(src->sin_port,
		    dst->sin_port, dstext->sadb_address_proto, 0);
		newbie->ipsa_unique_mask = SA_UNIQUE_MASK(src->sin_port,
		    dst->sin_port, dstext->sadb_address_proto, 0);
	}
	if (newbie->ipsa_unique_mask != (uint64_t)0)
		newbie->ipsa_flags |= IPSA_F_UNIQUE;

	sadb_nat_calculations(newbie,
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_LOC],
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_REM],
	    src_addr_ptr, dst_addr_ptr);

	newbie->ipsa_type = samsg->sadb_msg_satype;
	ASSERT(assoc->sadb_sa_state == SADB_SASTATE_MATURE);
	newbie->ipsa_auth_alg = assoc->sadb_sa_auth;
	newbie->ipsa_encr_alg = assoc->sadb_sa_encrypt;

	newbie->ipsa_flags |= assoc->sadb_sa_flags;
	if ((newbie->ipsa_flags & SADB_X_SAFLAGS_NATT_LOC &&
	    ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_LOC] == NULL) ||
	    (newbie->ipsa_flags & SADB_X_SAFLAGS_NATT_REM &&
	    ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_REM] == NULL) ||
	    (newbie->ipsa_flags & SADB_X_SAFLAGS_TUNNEL &&
	    ksi->ks_in_extv[SADB_X_EXT_ADDRESS_INNER_SRC] == NULL)) {
		mutex_exit(&newbie->ipsa_lock);
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SAFLAGS;
		error = EINVAL;
		goto error;
	}
	/*
	 * If unspecified source address, force replay_wsize to 0.
	 * This is because an SA that has multiple sources of secure
	 * traffic cannot enforce a replay counter w/o synchronizing the
	 * senders.
	 */
	if (ksi->ks_in_srctype != KS_IN_ADDR_UNSPEC)
		newbie->ipsa_replay_wsize = assoc->sadb_sa_replay;
	else
		newbie->ipsa_replay_wsize = 0;

	newbie->ipsa_addtime = gethrestime_sec();

	if (kmcext != NULL) {
		newbie->ipsa_kmp = kmcext->sadb_x_kmc_proto;
		newbie->ipsa_kmc = kmcext->sadb_x_kmc_cookie;
	}

	/*
	 * XXX CURRENT lifetime checks MAY BE needed for an UPDATE.
	 * The spec says that one can update current lifetimes, but
	 * that seems impractical, especially in the larval-to-mature
	 * update that this function performs.
	 */
	if (soft != NULL) {
		newbie->ipsa_softaddlt = soft->sadb_lifetime_addtime;
		newbie->ipsa_softuselt = soft->sadb_lifetime_usetime;
		newbie->ipsa_softbyteslt = soft->sadb_lifetime_bytes;
		newbie->ipsa_softalloc = soft->sadb_lifetime_allocations;
		SET_EXPIRE(newbie, softaddlt, softexpiretime);
	}
	if (hard != NULL) {
		newbie->ipsa_hardaddlt = hard->sadb_lifetime_addtime;
		newbie->ipsa_harduselt = hard->sadb_lifetime_usetime;
		newbie->ipsa_hardbyteslt = hard->sadb_lifetime_bytes;
		newbie->ipsa_hardalloc = hard->sadb_lifetime_allocations;
		SET_EXPIRE(newbie, hardaddlt, hardexpiretime);
	}

	newbie->ipsa_authtmpl = NULL;
	newbie->ipsa_encrtmpl = NULL;

	if (akey != NULL) {
		newbie->ipsa_authkeybits = akey->sadb_key_bits;
		newbie->ipsa_authkeylen = SADB_1TO8(akey->sadb_key_bits);
		/* In case we have to round up to the next byte... */
		if ((akey->sadb_key_bits & 0x7) != 0)
			newbie->ipsa_authkeylen++;
		newbie->ipsa_authkey = kmem_alloc(newbie->ipsa_authkeylen,
		    KM_NOSLEEP);
		if (newbie->ipsa_authkey == NULL) {
			error = ENOMEM;
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
		bcopy(akey + 1, newbie->ipsa_authkey, newbie->ipsa_authkeylen);
		bzero(akey + 1, newbie->ipsa_authkeylen);

		/*
		 * Pre-initialize the kernel crypto framework key
		 * structure.
		 */
		newbie->ipsa_kcfauthkey.ck_format = CRYPTO_KEY_RAW;
		newbie->ipsa_kcfauthkey.ck_length = newbie->ipsa_authkeybits;
		newbie->ipsa_kcfauthkey.ck_data = newbie->ipsa_authkey;

		mutex_enter(&ipss->ipsec_alg_lock);
		error = ipsec_create_ctx_tmpl(newbie, IPSEC_ALG_AUTH);
		mutex_exit(&ipss->ipsec_alg_lock);
		if (error != 0) {
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
	}

	if (ekey != NULL) {
		newbie->ipsa_encrkeybits = ekey->sadb_key_bits;
		newbie->ipsa_encrkeylen = SADB_1TO8(ekey->sadb_key_bits);
		/* In case we have to round up to the next byte... */
		if ((ekey->sadb_key_bits & 0x7) != 0)
			newbie->ipsa_encrkeylen++;
		newbie->ipsa_encrkey = kmem_alloc(newbie->ipsa_encrkeylen,
		    KM_NOSLEEP);
		if (newbie->ipsa_encrkey == NULL) {
			error = ENOMEM;
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
		bcopy(ekey + 1, newbie->ipsa_encrkey, newbie->ipsa_encrkeylen);
		/* XXX is this safe w.r.t db_ref, etc? */
		bzero(ekey + 1, newbie->ipsa_encrkeylen);

		/*
		 * Pre-initialize the kernel crypto framework key
		 * structure.
		 */
		newbie->ipsa_kcfencrkey.ck_format = CRYPTO_KEY_RAW;
		newbie->ipsa_kcfencrkey.ck_length = newbie->ipsa_encrkeybits;
		newbie->ipsa_kcfencrkey.ck_data = newbie->ipsa_encrkey;

		mutex_enter(&ipss->ipsec_alg_lock);
		error = ipsec_create_ctx_tmpl(newbie, IPSEC_ALG_ENCR);
		mutex_exit(&ipss->ipsec_alg_lock);
		if (error != 0) {
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
	}

	sadb_init_alginfo(newbie);

	/*
	 * Ptrs to processing functions.
	 */
	if (newbie->ipsa_type == SADB_SATYPE_ESP)
		ipsecesp_init_funcs(newbie);
	else
		ipsecah_init_funcs(newbie);
	ASSERT(newbie->ipsa_output_func != NULL &&
	    newbie->ipsa_input_func != NULL);

	/*
	 * Certificate ID stuff.
	 */
	if (ksi->ks_in_extv[SADB_EXT_IDENTITY_SRC] != NULL) {
		sadb_ident_t *id =
		    (sadb_ident_t *)ksi->ks_in_extv[SADB_EXT_IDENTITY_SRC];

		/*
		 * Can assume strlen() will return okay because ext_check() in
		 * keysock.c prepares the string for us.
		 */
		newbie->ipsa_src_cid = ipsid_lookup(id->sadb_ident_type,
		    (char *)(id+1), ns);
		if (newbie->ipsa_src_cid == NULL) {
			error = ENOMEM;
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
	}

	if (ksi->ks_in_extv[SADB_EXT_IDENTITY_DST] != NULL) {
		sadb_ident_t *id =
		    (sadb_ident_t *)ksi->ks_in_extv[SADB_EXT_IDENTITY_DST];

		/*
		 * Can assume strlen() will return okay because ext_check() in
		 * keysock.c prepares the string for us.
		 */
		newbie->ipsa_dst_cid = ipsid_lookup(id->sadb_ident_type,
		    (char *)(id+1), ns);
		if (newbie->ipsa_dst_cid == NULL) {
			error = ENOMEM;
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
	}

#if 0
	/* XXXMLS  SENSITIVITY handling code. */
	if (sens != NULL) {
		int i;
		uint64_t *bitmap = (uint64_t *)(sens + 1);

		newbie->ipsa_dpd = sens->sadb_sens_dpd;
		newbie->ipsa_senslevel = sens->sadb_sens_sens_level;
		newbie->ipsa_integlevel = sens->sadb_sens_integ_level;
		newbie->ipsa_senslen = SADB_64TO8(sens->sadb_sens_sens_len);
		newbie->ipsa_integlen = SADB_64TO8(sens->sadb_sens_integ_len);
		newbie->ipsa_integ = kmem_alloc(newbie->ipsa_integlen,
		    KM_NOSLEEP);
		if (newbie->ipsa_integ == NULL) {
			error = ENOMEM;
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
		newbie->ipsa_sens = kmem_alloc(newbie->ipsa_senslen,
		    KM_NOSLEEP);
		if (newbie->ipsa_sens == NULL) {
			error = ENOMEM;
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
		for (i = 0; i < sens->sadb_sens_sens_len; i++) {
			newbie->ipsa_sens[i] = *bitmap;
			bitmap++;
		}
		for (i = 0; i < sens->sadb_sens_integ_len; i++) {
			newbie->ipsa_integ[i] = *bitmap;
			bitmap++;
		}
	}

#endif

	/* now that the SA has been updated, set its new state */
	newbie->ipsa_state = assoc->sadb_sa_state;

	if (clone) {
		newbie->ipsa_haspeer = B_TRUE;
	} else {
		if (!is_inbound) {
			lifetime_fuzz(newbie);
		}
	}
	/*
	 * The less locks I hold when doing an insertion and possible cloning,
	 * the better!
	 */
	mutex_exit(&newbie->ipsa_lock);

	if (clone) {
		newbie_clone = sadb_cloneassoc(newbie);

		if (newbie_clone == NULL) {
			error = ENOMEM;
			goto error;
		}
	}

	/*
	 * Enter the bucket locks.  The order of entry is outbound,
	 * inbound.  We map "primary" and "secondary" into outbound and inbound
	 * based on the destination address type.  If the destination address
	 * type is for a node that isn't mine (or potentially mine), the
	 * "primary" bucket is the outbound one.
	 */
	if (!is_inbound) {
		/* primary == outbound */
		mutex_enter(&primary->isaf_lock);
		mutex_enter(&secondary->isaf_lock);
	} else {
		/* primary == inbound */
		mutex_enter(&secondary->isaf_lock);
		mutex_enter(&primary->isaf_lock);
	}

	IPSECHW_DEBUG(IPSECHW_SADB, ("sadb_common_add: spi = 0x%x\n",
	    newbie->ipsa_spi));

	/*
	 * sadb_insertassoc() doesn't increment the reference
	 * count.  We therefore have to increment the
	 * reference count one more time to reflect the
	 * pointers of the table that reference this SA.
	 */
	IPSA_REFHOLD(newbie);

	if (isupdate) {
		/*
		 * Unlink from larval holding cell in the "inbound" fanout.
		 */
		ASSERT(newbie->ipsa_linklock == &primary->isaf_lock ||
		    newbie->ipsa_linklock == &secondary->isaf_lock);
		sadb_unlinkassoc(newbie);
	}

	mutex_enter(&newbie->ipsa_lock);
	error = sadb_insertassoc(newbie, primary);
	if (error == 0) {
		ctl_mp = sadb_fmt_sa_req(DL_CO_SET, newbie->ipsa_type, newbie,
		    is_inbound);
	}
	mutex_exit(&newbie->ipsa_lock);

	if (error != 0) {
		/*
		 * Since sadb_insertassoc() failed, we must decrement the
		 * refcount again so the cleanup code will actually free
		 * the offending SA.
		 */
		IPSA_REFRELE(newbie);
		goto error_unlock;
	}

	if (newbie_clone != NULL) {
		mutex_enter(&newbie_clone->ipsa_lock);
		error = sadb_insertassoc(newbie_clone, secondary);
		mutex_exit(&newbie_clone->ipsa_lock);
		if (error != 0) {
			/* Collision in secondary table. */
			sadb_unlinkassoc(newbie);  /* This does REFRELE. */
			goto error_unlock;
		}
		IPSA_REFHOLD(newbie_clone);
	} else {
		ASSERT(primary != secondary);
		scratch = ipsec_getassocbyspi(secondary, newbie->ipsa_spi,
		    ALL_ZEROES_PTR, newbie->ipsa_dstaddr, af);
		if (scratch != NULL) {
			/* Collision in secondary table. */
			sadb_unlinkassoc(newbie);  /* This does REFRELE. */
			/* Set the error, since ipsec_getassocbyspi() can't. */
			error = EEXIST;
			goto error_unlock;
		}
	}

	/* OKAY!  So let's do some reality check assertions. */

	ASSERT(!MUTEX_HELD(&newbie->ipsa_lock));
	ASSERT(newbie_clone == NULL || (!MUTEX_HELD(&newbie_clone->ipsa_lock)));
	/*
	 * If hardware acceleration could happen, send it.
	 */
	if (ctl_mp != NULL) {
		putnext(ip_q, ctl_mp);
		ctl_mp = NULL;
	}

error_unlock:

	/*
	 * We can exit the locks in any order.	Only entrance needs to
	 * follow any protocol.
	 */
	mutex_exit(&secondary->isaf_lock);
	mutex_exit(&primary->isaf_lock);

	if (pair_ext != NULL && error == 0) {
		/* update pair_spi if it exists. */
		ipsapp = get_ipsa_pair(assoc, srcext, dstext, spp);
		if (ipsapp == NULL) {
			error = ESRCH;
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
		} else if (ipsapp->ipsap_psa_ptr != NULL) {
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_ALREADY;
			error = EINVAL;
		} else {
			/* update_pairing() sets diagnostic */
			error = update_pairing(ipsapp, ksi, diagnostic, spp);
		}
	}
	/* Common error point for this routine. */
error:
	if (newbie != NULL) {
		if (error != 0) {
			/* This SA is broken, let the reaper clean up. */
			mutex_enter(&newbie->ipsa_lock);
			newbie->ipsa_state = IPSA_STATE_DEAD;
			newbie->ipsa_hardexpiretime = 1;
			mutex_exit(&newbie->ipsa_lock);
		}
		IPSA_REFRELE(newbie);
	}
	if (newbie_clone != NULL) {
		IPSA_REFRELE(newbie_clone);
	}
	if (ctl_mp != NULL)
		freemsg(ctl_mp);

	if (error == 0) {
		/*
		 * Construct favorable PF_KEY return message and send to
		 * keysock. Update the flags in the original keysock message
		 * to reflect the actual flags in the new SA.
		 *  (Q:  Do I need to pass "newbie"?  If I do,
		 * make sure to REFHOLD, call, then REFRELE.)
		 */
		assoc->sadb_sa_flags = newbie->ipsa_flags;
		sadb_pfkey_echo(pfkey_q, mp, samsg, ksi, NULL);
	}

	destroy_ipsa_pair(ipsapp);
	return (error);
}

/*
 * Set the time of first use for a security association.  Update any
 * expiration times as a result.
 */
void
sadb_set_usetime(ipsa_t *assoc)
{
	time_t snapshot = gethrestime_sec();

	mutex_enter(&assoc->ipsa_lock);
	assoc->ipsa_lastuse = snapshot;
	/*
	 * Caller does check usetime before calling me usually, and
	 * double-checking is better than a mutex_enter/exit hit.
	 */
	if (assoc->ipsa_usetime == 0) {
		/*
		 * This is redundant for outbound SA's, as
		 * ipsec_getassocbyconn() sets the IPSA_F_USED flag already.
		 * Inbound SAs, however, have no such protection.
		 */
		assoc->ipsa_flags |= IPSA_F_USED;
		assoc->ipsa_usetime = snapshot;

		/*
		 * After setting the use time, see if we have a use lifetime
		 * that would cause the actual SA expiration time to shorten.
		 */
		UPDATE_EXPIRE(assoc, softuselt, softexpiretime);
		UPDATE_EXPIRE(assoc, harduselt, hardexpiretime);
	}
	mutex_exit(&assoc->ipsa_lock);
}

/*
 * Send up a PF_KEY expire message for this association.
 */
static void
sadb_expire_assoc(queue_t *pfkey_q, ipsa_t *assoc)
{
	mblk_t *mp, *mp1;
	int alloclen, af;
	sadb_msg_t *samsg;
	sadb_lifetime_t *current, *expire;
	sadb_sa_t *saext;
	uint8_t *end;
	boolean_t tunnel_mode;

	ASSERT(MUTEX_HELD(&assoc->ipsa_lock));

	/* Don't bother sending if there's no queue. */
	if (pfkey_q == NULL)
		return;

	/* If the SA is one of a pair, only SOFT expire the OUTBOUND SA */
	if (assoc->ipsa_state == IPSA_STATE_DYING &&
	    (assoc->ipsa_flags & IPSA_F_PAIRED) &&
	    !(assoc->ipsa_flags & IPSA_F_OUTBOUND)) {
		return;
	}

	mp = sadb_keysock_out(0);
	if (mp == NULL) {
		/* cmn_err(CE_WARN, */
		/*	"sadb_expire_assoc: Can't allocate KEYSOCK_OUT.\n"); */
		return;
	}

	alloclen = sizeof (*samsg) + sizeof (*current) + sizeof (*expire) +
	    2 * sizeof (sadb_address_t) + sizeof (*saext);

	af = assoc->ipsa_addrfam;
	switch (af) {
	case AF_INET:
		alloclen += 2 * sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		alloclen += 2 * sizeof (struct sockaddr_in6);
		break;
	default:
		/* Won't happen unless there's a kernel bug. */
		freeb(mp);
		cmn_err(CE_WARN,
		    "sadb_expire_assoc: Unknown address length.\n");
		return;
	}

	tunnel_mode = (assoc->ipsa_flags & IPSA_F_TUNNEL);
	if (tunnel_mode) {
		alloclen += 2 * sizeof (sadb_address_t);
		switch (assoc->ipsa_innerfam) {
		case AF_INET:
			alloclen += 2 * sizeof (struct sockaddr_in);
			break;
		case AF_INET6:
			alloclen += 2 * sizeof (struct sockaddr_in6);
			break;
		default:
			/* Won't happen unless there's a kernel bug. */
			freeb(mp);
			cmn_err(CE_WARN, "sadb_expire_assoc: "
			    "Unknown inner address length.\n");
			return;
		}
	}

	mp->b_cont = allocb(alloclen, BPRI_HI);
	if (mp->b_cont == NULL) {
		freeb(mp);
		/* cmn_err(CE_WARN, */
		/*	"sadb_expire_assoc: Can't allocate message.\n"); */
		return;
	}

	mp1 = mp;
	mp = mp->b_cont;
	end = mp->b_wptr + alloclen;

	samsg = (sadb_msg_t *)mp->b_wptr;
	mp->b_wptr += sizeof (*samsg);
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_EXPIRE;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = assoc->ipsa_type;
	samsg->sadb_msg_len = SADB_8TO64(alloclen);
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = 0;
	samsg->sadb_msg_pid = 0;

	saext = (sadb_sa_t *)mp->b_wptr;
	mp->b_wptr += sizeof (*saext);
	saext->sadb_sa_len = SADB_8TO64(sizeof (*saext));
	saext->sadb_sa_exttype = SADB_EXT_SA;
	saext->sadb_sa_spi = assoc->ipsa_spi;
	saext->sadb_sa_replay = assoc->ipsa_replay_wsize;
	saext->sadb_sa_state = assoc->ipsa_state;
	saext->sadb_sa_auth = assoc->ipsa_auth_alg;
	saext->sadb_sa_encrypt = assoc->ipsa_encr_alg;
	saext->sadb_sa_flags = assoc->ipsa_flags;

	current = (sadb_lifetime_t *)mp->b_wptr;
	mp->b_wptr += sizeof (sadb_lifetime_t);
	current->sadb_lifetime_len = SADB_8TO64(sizeof (*current));
	current->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	/* We do not support the concept. */
	current->sadb_lifetime_allocations = 0;
	current->sadb_lifetime_bytes = assoc->ipsa_bytes;
	current->sadb_lifetime_addtime = assoc->ipsa_addtime;
	current->sadb_lifetime_usetime = assoc->ipsa_usetime;

	expire = (sadb_lifetime_t *)mp->b_wptr;
	mp->b_wptr += sizeof (*expire);
	expire->sadb_lifetime_len = SADB_8TO64(sizeof (*expire));

	if (assoc->ipsa_state == IPSA_STATE_DEAD) {
		expire->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
		expire->sadb_lifetime_allocations = assoc->ipsa_hardalloc;
		expire->sadb_lifetime_bytes = assoc->ipsa_hardbyteslt;
		expire->sadb_lifetime_addtime = assoc->ipsa_hardaddlt;
		expire->sadb_lifetime_usetime = assoc->ipsa_harduselt;
	} else {
		ASSERT(assoc->ipsa_state == IPSA_STATE_DYING);
		expire->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
		expire->sadb_lifetime_allocations = assoc->ipsa_softalloc;
		expire->sadb_lifetime_bytes = assoc->ipsa_softbyteslt;
		expire->sadb_lifetime_addtime = assoc->ipsa_softaddlt;
		expire->sadb_lifetime_usetime = assoc->ipsa_softuselt;
	}

	mp->b_wptr = sadb_make_addr_ext(mp->b_wptr, end, SADB_EXT_ADDRESS_SRC,
	    af, assoc->ipsa_srcaddr, tunnel_mode ? 0 : SA_SRCPORT(assoc),
	    SA_PROTO(assoc), 0);
	ASSERT(mp->b_wptr != NULL);

	mp->b_wptr = sadb_make_addr_ext(mp->b_wptr, end, SADB_EXT_ADDRESS_DST,
	    af, assoc->ipsa_dstaddr, tunnel_mode ? 0 : SA_DSTPORT(assoc),
	    SA_PROTO(assoc), 0);
	ASSERT(mp->b_wptr != NULL);

	if (tunnel_mode) {
		mp->b_wptr = sadb_make_addr_ext(mp->b_wptr, end,
		    SADB_X_EXT_ADDRESS_INNER_SRC, assoc->ipsa_innerfam,
		    assoc->ipsa_innersrc, SA_SRCPORT(assoc), SA_IPROTO(assoc),
		    assoc->ipsa_innersrcpfx);
		ASSERT(mp->b_wptr != NULL);
		mp->b_wptr = sadb_make_addr_ext(mp->b_wptr, end,
		    SADB_X_EXT_ADDRESS_INNER_DST, assoc->ipsa_innerfam,
		    assoc->ipsa_innerdst, SA_DSTPORT(assoc), SA_IPROTO(assoc),
		    assoc->ipsa_innerdstpfx);
		ASSERT(mp->b_wptr != NULL);
	}

	/* Can just putnext, we're ready to go! */
	putnext(pfkey_q, mp1);
}

/*
 * "Age" the SA with the number of bytes that was used to protect traffic.
 * Send an SADB_EXPIRE message if appropriate.	Return B_TRUE if there was
 * enough "charge" left in the SA to protect the data.	Return B_FALSE
 * otherwise.  (If B_FALSE is returned, the association either was, or became
 * DEAD.)
 */
boolean_t
sadb_age_bytes(queue_t *pfkey_q, ipsa_t *assoc, uint64_t bytes,
    boolean_t sendmsg)
{
	boolean_t rc = B_TRUE;
	uint64_t newtotal;

	mutex_enter(&assoc->ipsa_lock);
	newtotal = assoc->ipsa_bytes + bytes;
	if (assoc->ipsa_hardbyteslt != 0 &&
	    newtotal >= assoc->ipsa_hardbyteslt) {
		if (assoc->ipsa_state < IPSA_STATE_DEAD) {
			/*
			 * Send EXPIRE message to PF_KEY.  May wish to pawn
			 * this off on another non-interrupt thread.  Also
			 * unlink this SA immediately.
			 */
			assoc->ipsa_state = IPSA_STATE_DEAD;
			if (sendmsg)
				sadb_expire_assoc(pfkey_q, assoc);
			/*
			 * Set non-zero expiration time so sadb_age_assoc()
			 * will work when reaping.
			 */
			assoc->ipsa_hardexpiretime = (time_t)1;
		} /* Else someone beat me to it! */
		rc = B_FALSE;
	} else if (assoc->ipsa_softbyteslt != 0 &&
	    (newtotal >= assoc->ipsa_softbyteslt)) {
		if (assoc->ipsa_state < IPSA_STATE_DYING) {
			/*
			 * Send EXPIRE message to PF_KEY.  May wish to pawn
			 * this off on another non-interrupt thread.
			 */
			assoc->ipsa_state = IPSA_STATE_DYING;
			assoc->ipsa_bytes = newtotal;
			if (sendmsg)
				sadb_expire_assoc(pfkey_q, assoc);
		} /* Else someone beat me to it! */
	}
	if (rc == B_TRUE)
		assoc->ipsa_bytes = newtotal;
	mutex_exit(&assoc->ipsa_lock);
	return (rc);
}

/*
 * Push one or more DL_CO_DELETE messages queued up by
 * sadb_torch_assoc down to the underlying driver now that it's a
 * convenient time for it (i.e., ipsa bucket locks not held).
 */
static void
sadb_drain_torchq(queue_t *q, mblk_t *mp)
{
	while (mp != NULL) {
		mblk_t *next = mp->b_next;
		mp->b_next = NULL;
		if (q != NULL)
			putnext(q, mp);
		else
			freemsg(mp);
		mp = next;
	}
}

/*
 * "Torch" an individual SA.  Returns NULL, so it can be tail-called from
 *     sadb_age_assoc().
 *
 * If SA is hardware-accelerated, and we can't allocate the mblk
 * containing the DL_CO_DELETE, just return; it will remain in the
 * table and be swept up by sadb_ager() in a subsequent pass.
 */
static ipsa_t *
sadb_torch_assoc(isaf_t *head, ipsa_t *sa, boolean_t inbnd, mblk_t **mq)
{
	mblk_t *mp;

	ASSERT(MUTEX_HELD(&head->isaf_lock));
	ASSERT(MUTEX_HELD(&sa->ipsa_lock));
	ASSERT(sa->ipsa_state == IPSA_STATE_DEAD);

	/*
	 * Force cached SAs to be revalidated..
	 */
	head->isaf_gen++;

	if (sa->ipsa_flags & IPSA_F_HW) {
		mp = sadb_fmt_sa_req(DL_CO_DELETE, sa->ipsa_type, sa, inbnd);
		if (mp == NULL) {
			mutex_exit(&sa->ipsa_lock);
			return (NULL);
		}
		mp->b_next = *mq;
		*mq = mp;
	}
	mutex_exit(&sa->ipsa_lock);
	sadb_unlinkassoc(sa);

	return (NULL);
}

/*
 * Do various SA-is-idle activities depending on delta (the number of idle
 * seconds on the SA) and/or other properties of the SA.
 *
 * Return B_TRUE if I've sent a packet, because I have to drop the
 * association's mutex before sending a packet out the wire.
 */
/* ARGSUSED */
static boolean_t
sadb_idle_activities(ipsa_t *assoc, time_t delta, boolean_t inbound)
{
	ipsecesp_stack_t *espstack = assoc->ipsa_netstack->netstack_ipsecesp;
	int nat_t_interval = espstack->ipsecesp_nat_keepalive_interval;

	ASSERT(MUTEX_HELD(&assoc->ipsa_lock));

	if (!inbound && (assoc->ipsa_flags & IPSA_F_NATT_LOC) &&
	    delta >= nat_t_interval &&
	    gethrestime_sec() - assoc->ipsa_last_nat_t_ka >= nat_t_interval) {
		ASSERT(assoc->ipsa_type == SADB_SATYPE_ESP);
		assoc->ipsa_last_nat_t_ka = gethrestime_sec();
		mutex_exit(&assoc->ipsa_lock);
		ipsecesp_send_keepalive(assoc);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Return "assoc" if haspeer is true and I send an expire.  This allows
 * the consumers' aging functions to tidy up an expired SA's peer.
 */
static ipsa_t *
sadb_age_assoc(isaf_t *head, queue_t *pfkey_q, ipsa_t *assoc,
    time_t current, int reap_delay, boolean_t inbound, mblk_t **mq)
{
	ipsa_t *retval = NULL;
	boolean_t dropped_mutex = B_FALSE;

	ASSERT(MUTEX_HELD(&head->isaf_lock));

	mutex_enter(&assoc->ipsa_lock);

	if ((assoc->ipsa_state == IPSA_STATE_LARVAL) &&
	    (assoc->ipsa_hardexpiretime <= current)) {
		assoc->ipsa_state = IPSA_STATE_DEAD;
		return (sadb_torch_assoc(head, assoc, inbound, mq));
	}

	/*
	 * Check lifetimes.  Fortunately, SA setup is done
	 * such that there are only two times to look at,
	 * softexpiretime, and hardexpiretime.
	 *
	 * Check hard first.
	 */

	if (assoc->ipsa_hardexpiretime != 0 &&
	    assoc->ipsa_hardexpiretime <= current) {
		if (assoc->ipsa_state == IPSA_STATE_DEAD)
			return (sadb_torch_assoc(head, assoc, inbound, mq));

		/*
		 * Send SADB_EXPIRE with hard lifetime, delay for unlinking.
		 */
		assoc->ipsa_state = IPSA_STATE_DEAD;
		if (assoc->ipsa_haspeer || assoc->ipsa_otherspi != 0) {
			/*
			 * If the SA is paired or peered with another, put
			 * a copy on a list which can be processed later, the
			 * pair/peer SA needs to be updated so the both die
			 * at the same time.
			 *
			 * If I return assoc, I have to bump up its reference
			 * count to keep with the ipsa_t reference count
			 * semantics.
			 */
			IPSA_REFHOLD(assoc);
			retval = assoc;
		}
		sadb_expire_assoc(pfkey_q, assoc);
		assoc->ipsa_hardexpiretime = current + reap_delay;
	} else if (assoc->ipsa_softexpiretime != 0 &&
	    assoc->ipsa_softexpiretime <= current &&
	    assoc->ipsa_state < IPSA_STATE_DYING) {
		/*
		 * Send EXPIRE message to PF_KEY.  May wish to pawn
		 * this off on another non-interrupt thread.
		 */
		assoc->ipsa_state = IPSA_STATE_DYING;
		if (assoc->ipsa_haspeer) {
			/*
			 * If the SA has a peer, update the peer's state
			 * on SOFT_EXPIRE, this is mostly to prevent two
			 * expire messages from effectively the same SA.
			 *
			 * Don't care about paired SA's, then can (and should)
			 * be able to soft expire at different times.
			 *
			 * If I return assoc, I have to bump up its
			 * reference count to keep with the ipsa_t reference
			 * count semantics.
			 */
			IPSA_REFHOLD(assoc);
			retval = assoc;
		}
		sadb_expire_assoc(pfkey_q, assoc);
	} else {
		/* Check idle time activities. */
		dropped_mutex = sadb_idle_activities(assoc,
		    current - assoc->ipsa_lastuse, inbound);
	}

	if (!dropped_mutex)
		mutex_exit(&assoc->ipsa_lock);
	return (retval);
}

/*
 * Called by a consumer protocol to do ther dirty work of reaping dead
 * Security Associations.
 *
 * NOTE: sadb_age_assoc() marks expired SA's as DEAD but only removed
 * SA's that are already marked DEAD, so expired SA's are only reaped
 * the second time sadb_ager() runs.
 */
void
sadb_ager(sadb_t *sp, queue_t *pfkey_q, queue_t *ip_q, int reap_delay,
    netstack_t *ns)
{
	int i;
	isaf_t *bucket;
	ipsa_t *assoc, *spare;
	iacqf_t *acqlist;
	ipsacq_t *acqrec, *spareacq;
	templist_t *haspeerlist, *newbie;
	/* Snapshot current time now. */
	time_t current = gethrestime_sec();
	mblk_t *mq = NULL;
	haspeerlist = NULL;

	/*
	 * Do my dirty work.  This includes aging real entries, aging
	 * larvals, and aging outstanding ACQUIREs.
	 *
	 * I hope I don't tie up resources for too long.
	 */

	/* Age acquires. */

	for (i = 0; i < sp->sdb_hashsize; i++) {
		acqlist = &sp->sdb_acq[i];
		mutex_enter(&acqlist->iacqf_lock);
		for (acqrec = acqlist->iacqf_ipsacq; acqrec != NULL;
		    acqrec = spareacq) {
			spareacq = acqrec->ipsacq_next;
			if (current > acqrec->ipsacq_expire)
				sadb_destroy_acquire(acqrec, ns);
		}
		mutex_exit(&acqlist->iacqf_lock);
	}

	/* Age inbound associations. */
	for (i = 0; i < sp->sdb_hashsize; i++) {
		bucket = &(sp->sdb_if[i]);
		mutex_enter(&bucket->isaf_lock);
		for (assoc = bucket->isaf_ipsa; assoc != NULL;
		    assoc = spare) {
			spare = assoc->ipsa_next;
			if (sadb_age_assoc(bucket, pfkey_q, assoc, current,
			    reap_delay, B_TRUE, &mq) != NULL) {
				/*
				 * Put SA's which have a peer or SA's which
				 * are paired on a list for processing after
				 * all the hash tables have been walked.
				 *
				 * sadb_age_assoc() increments the refcnt,
				 * effectively doing an IPSA_REFHOLD().
				 */
				newbie = kmem_alloc(sizeof (*newbie),
				    KM_NOSLEEP);
				if (newbie == NULL) {
					/*
					 * Don't forget to REFRELE().
					 */
					IPSA_REFRELE(assoc);
					continue;	/* for loop... */
				}
				newbie->next = haspeerlist;
				newbie->ipsa = assoc;
				haspeerlist = newbie;
			}
		}
		mutex_exit(&bucket->isaf_lock);
	}

	if (mq != NULL) {
		sadb_drain_torchq(ip_q, mq);
		mq = NULL;
	}
	age_pair_peer_list(haspeerlist, sp, B_FALSE);
	haspeerlist = NULL;

	/* Age outbound associations. */
	for (i = 0; i < sp->sdb_hashsize; i++) {
		bucket = &(sp->sdb_of[i]);
		mutex_enter(&bucket->isaf_lock);
		for (assoc = bucket->isaf_ipsa; assoc != NULL;
		    assoc = spare) {
			spare = assoc->ipsa_next;
			if (sadb_age_assoc(bucket, pfkey_q, assoc, current,
			    reap_delay, B_FALSE, &mq) != NULL) {
				/*
				 * sadb_age_assoc() increments the refcnt,
				 * effectively doing an IPSA_REFHOLD().
				 */
				newbie = kmem_alloc(sizeof (*newbie),
				    KM_NOSLEEP);
				if (newbie == NULL) {
					/*
					 * Don't forget to REFRELE().
					 */
					IPSA_REFRELE(assoc);
					continue;	/* for loop... */
				}
				newbie->next = haspeerlist;
				newbie->ipsa = assoc;
				haspeerlist = newbie;
			}
		}
		mutex_exit(&bucket->isaf_lock);
	}
	if (mq != NULL) {
		sadb_drain_torchq(ip_q, mq);
		mq = NULL;
	}

	age_pair_peer_list(haspeerlist, sp, B_TRUE);

	/*
	 * Run a GC pass to clean out dead identities.
	 */
	ipsid_gc(ns);
}

/*
 * Figure out when to reschedule the ager.
 */
timeout_id_t
sadb_retimeout(hrtime_t begin, queue_t *pfkey_q, void (*ager)(void *),
    void *agerarg, uint_t *intp, uint_t intmax, short mid)
{
	hrtime_t end = gethrtime();
	uint_t interval = *intp;

	/*
	 * See how long this took.  If it took too long, increase the
	 * aging interval.
	 */
	if ((end - begin) > interval * 1000000) {
		if (interval >= intmax) {
			/* XXX Rate limit this?  Or recommend flush? */
			(void) strlog(mid, 0, 0, SL_ERROR | SL_WARN,
			    "Too many SA's to age out in %d msec.\n",
			    intmax);
		} else {
			/* Double by shifting by one bit. */
			interval <<= 1;
			interval = min(interval, intmax);
		}
	} else if ((end - begin) <= interval * 500000 &&
	    interval > SADB_AGE_INTERVAL_DEFAULT) {
		/*
		 * If I took less than half of the interval, then I should
		 * ratchet the interval back down.  Never automatically
		 * shift below the default aging interval.
		 *
		 * NOTE:This even overrides manual setting of the age
		 *	interval using NDD.
		 */
		/* Halve by shifting one bit. */
		interval >>= 1;
		interval = max(interval, SADB_AGE_INTERVAL_DEFAULT);
	}
	*intp = interval;
	return (qtimeout(pfkey_q, ager, agerarg,
	    interval * drv_usectohz(1000)));
}


/*
 * Update the lifetime values of an SA.	 This is the path an SADB_UPDATE
 * message takes when updating a MATURE or DYING SA.
 */
static void
sadb_update_lifetimes(ipsa_t *assoc, sadb_lifetime_t *hard,
    sadb_lifetime_t *soft, boolean_t outbound)
{
	mutex_enter(&assoc->ipsa_lock);

	/*
	 * XXX RFC 2367 mentions how an SADB_EXT_LIFETIME_CURRENT can be
	 * passed in during an update message.	We currently don't handle
	 * these.
	 */

	if (hard != NULL) {
		if (hard->sadb_lifetime_bytes != 0)
			assoc->ipsa_hardbyteslt = hard->sadb_lifetime_bytes;
		if (hard->sadb_lifetime_usetime != 0)
			assoc->ipsa_harduselt = hard->sadb_lifetime_usetime;
		if (hard->sadb_lifetime_addtime != 0)
			assoc->ipsa_hardaddlt = hard->sadb_lifetime_addtime;
		if (assoc->ipsa_hardaddlt != 0) {
			assoc->ipsa_hardexpiretime =
			    assoc->ipsa_addtime + assoc->ipsa_hardaddlt;
		}
		if (assoc->ipsa_harduselt != 0 &&
		    assoc->ipsa_flags & IPSA_F_USED) {
			UPDATE_EXPIRE(assoc, harduselt, hardexpiretime);
		}
		if (hard->sadb_lifetime_allocations != 0)
			assoc->ipsa_hardalloc = hard->sadb_lifetime_allocations;
	}

	if (soft != NULL) {
		if (soft->sadb_lifetime_bytes != 0) {
			if (soft->sadb_lifetime_bytes >
			    assoc->ipsa_hardbyteslt) {
				assoc->ipsa_softbyteslt =
				    assoc->ipsa_hardbyteslt;
			} else {
				assoc->ipsa_softbyteslt =
				    soft->sadb_lifetime_bytes;
			}
		}
		if (soft->sadb_lifetime_usetime != 0) {
			if (soft->sadb_lifetime_usetime >
			    assoc->ipsa_harduselt) {
				assoc->ipsa_softuselt =
				    assoc->ipsa_harduselt;
			} else {
				assoc->ipsa_softuselt =
				    soft->sadb_lifetime_usetime;
			}
		}
		if (soft->sadb_lifetime_addtime != 0) {
			if (soft->sadb_lifetime_addtime >
			    assoc->ipsa_hardexpiretime) {
				assoc->ipsa_softexpiretime =
				    assoc->ipsa_hardexpiretime;
			} else {
				assoc->ipsa_softaddlt =
				    soft->sadb_lifetime_addtime;
			}
		}
		if (assoc->ipsa_softaddlt != 0) {
			assoc->ipsa_softexpiretime =
			    assoc->ipsa_addtime + assoc->ipsa_softaddlt;
		}
		if (assoc->ipsa_softuselt != 0 &&
		    assoc->ipsa_flags & IPSA_F_USED) {
			UPDATE_EXPIRE(assoc, softuselt, softexpiretime);
		}
		if (outbound && assoc->ipsa_softexpiretime != 0) {
			if (assoc->ipsa_state == IPSA_STATE_MATURE)
				lifetime_fuzz(assoc);
		}

		if (soft->sadb_lifetime_allocations != 0)
			assoc->ipsa_softalloc = soft->sadb_lifetime_allocations;
	}
	mutex_exit(&assoc->ipsa_lock);
}

/*
 * Common code to update an SA.
 */

int
sadb_update_sa(mblk_t *mp, keysock_in_t *ksi,
    sadbp_t *spp, int *diagnostic, queue_t *pfkey_q,
    int (*add_sa_func)(mblk_t *, keysock_in_t *, int *, netstack_t *),
    netstack_t *ns, uint8_t sadb_msg_type)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_x_kmc_t *kmcext =
	    (sadb_x_kmc_t *)ksi->ks_in_extv[SADB_X_EXT_KM_COOKIE];
	sadb_key_t *akey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_AUTH];
	sadb_key_t *ekey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT];
	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];
	sadb_x_pair_t *pair_ext =
	    (sadb_x_pair_t *)ksi->ks_in_extv[SADB_X_EXT_PAIR];
	ipsa_t *echo_target = NULL;
	int error = 0;
	ipsap_t *ipsapp = NULL;
	uint32_t kmp = 0, kmc = 0;


	/* I need certain extensions present for either UPDATE message. */
	if (srcext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return (EINVAL);
	}
	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}
	if (assoc == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SA;
		return (EINVAL);
	}

	if (kmcext != NULL) {
		kmp = kmcext->sadb_x_kmc_proto;
		kmc = kmcext->sadb_x_kmc_cookie;
	}

	ipsapp = get_ipsa_pair(assoc, srcext, dstext, spp);
	if (ipsapp == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_SA_NOTFOUND;
		return (ESRCH);
	}

	if (ipsapp->ipsap_psa_ptr == NULL && ipsapp->ipsap_sa_ptr != NULL) {
		if (ipsapp->ipsap_sa_ptr->ipsa_state == IPSA_STATE_LARVAL) {
			/*
			 * REFRELE the target and let the add_sa_func()
			 * deal with updating a larval SA.
			 */
			destroy_ipsa_pair(ipsapp);
			return (add_sa_func(mp, ksi, diagnostic, ns));
		}
	}

	/*
	 * Reality checks for updates of active associations.
	 * Sundry first-pass UPDATE-specific reality checks.
	 * Have to do the checks here, because it's after the add_sa code.
	 * XXX STATS : logging/stats here?
	 */

	if (assoc->sadb_sa_state != SADB_SASTATE_MATURE) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
		error = EINVAL;
		goto bail;
	}

	if (assoc->sadb_sa_flags & ~spp->s_updateflags) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SAFLAGS;
		error = EINVAL;
		goto bail;
	}

	if (ksi->ks_in_extv[SADB_EXT_LIFETIME_CURRENT] != NULL) {
		error = EOPNOTSUPP;
		goto bail;
	}
	if ((*diagnostic = sadb_hardsoftchk(hard, soft)) != 0) {
		error = EINVAL;
		goto bail;
	}
	if (akey != NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_AKEY_PRESENT;
		error = EINVAL;
		goto bail;
	}
	if (ekey != NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_EKEY_PRESENT;
		error = EINVAL;
		goto bail;
	}

	if (ipsapp->ipsap_sa_ptr != NULL) {
		if (ipsapp->ipsap_sa_ptr->ipsa_state == IPSA_STATE_DEAD) {
			error = ESRCH;	/* DEAD == Not there, in this case. */
			*diagnostic = SADB_X_DIAGNOSTIC_SA_EXPIRED;
			goto bail;
		}
		if ((kmp != 0) &&
		    ((ipsapp->ipsap_sa_ptr->ipsa_kmp != 0) ||
		    (ipsapp->ipsap_sa_ptr->ipsa_kmp != kmp))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMP;
			error = EINVAL;
			goto bail;
		}
		if ((kmc != 0) &&
		    ((ipsapp->ipsap_sa_ptr->ipsa_kmc != 0) ||
		    (ipsapp->ipsap_sa_ptr->ipsa_kmc != kmc))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMC;
			error = EINVAL;
			goto bail;
		}
	}

	if (ipsapp->ipsap_psa_ptr != NULL) {
		if (ipsapp->ipsap_psa_ptr->ipsa_state == IPSA_STATE_DEAD) {
			*diagnostic = SADB_X_DIAGNOSTIC_SA_EXPIRED;
			error = ESRCH;	/* DEAD == Not there, in this case. */
			goto bail;
		}
		if ((kmp != 0) &&
		    ((ipsapp->ipsap_psa_ptr->ipsa_kmp != 0) ||
		    (ipsapp->ipsap_psa_ptr->ipsa_kmp != kmp))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMP;
			error = EINVAL;
			goto bail;
		}
		if ((kmc != 0) &&
		    ((ipsapp->ipsap_psa_ptr->ipsa_kmc != 0) ||
		    (ipsapp->ipsap_psa_ptr->ipsa_kmc != kmc))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMC;
			error = EINVAL;
			goto bail;
		}
	}

	if (ipsapp->ipsap_sa_ptr != NULL) {
		sadb_update_lifetimes(ipsapp->ipsap_sa_ptr, hard, soft, B_TRUE);
		if (kmp != 0)
			ipsapp->ipsap_sa_ptr->ipsa_kmp = kmp;
		if (kmc != 0)
			ipsapp->ipsap_sa_ptr->ipsa_kmc = kmc;
	}

	if (sadb_msg_type == SADB_X_UPDATEPAIR) {
		if (ipsapp->ipsap_psa_ptr != NULL) {
			sadb_update_lifetimes(ipsapp->ipsap_psa_ptr, hard, soft,
			    B_FALSE);
			if (kmp != 0)
				ipsapp->ipsap_psa_ptr->ipsa_kmp = kmp;
			if (kmc != 0)
				ipsapp->ipsap_psa_ptr->ipsa_kmc = kmc;
		} else {
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
			error = ESRCH;
			goto bail;
		}
	}

	if (pair_ext != NULL)
		error = update_pairing(ipsapp, ksi, diagnostic, spp);

	if (error == 0)
		sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr,
		    ksi, echo_target);
bail:

	destroy_ipsa_pair(ipsapp);

	return (error);
}


int
update_pairing(ipsap_t *ipsapp, keysock_in_t *ksi, int *diagnostic,
    sadbp_t *spp)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_x_pair_t *pair_ext =
	    (sadb_x_pair_t *)ksi->ks_in_extv[SADB_X_EXT_PAIR];
	int error = 0;
	ipsap_t *oipsapp = NULL;
	boolean_t undo_pair = B_FALSE;
	uint32_t ipsa_flags;

	if (pair_ext->sadb_x_pair_spi == 0 || pair_ext->sadb_x_pair_spi ==
	    assoc->sadb_sa_spi) {
		*diagnostic = SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE;
		return (EINVAL);
	}

	/*
	 * Assume for now that the spi value provided in the SADB_UPDATE
	 * message was valid, update the SA with its pair spi value.
	 * If the spi turns out to be bogus or the SA no longer exists
	 * then this will be detected when the reverse update is made
	 * below.
	 */
	mutex_enter(&ipsapp->ipsap_sa_ptr->ipsa_lock);
	ipsapp->ipsap_sa_ptr->ipsa_flags |= IPSA_F_PAIRED;
	ipsapp->ipsap_sa_ptr->ipsa_otherspi = pair_ext->sadb_x_pair_spi;
	mutex_exit(&ipsapp->ipsap_sa_ptr->ipsa_lock);

	/*
	 * After updating the ipsa_otherspi element of the SA, get_ipsa_pair()
	 * should now return pointers to the SA *AND* its pair, if this is not
	 * the case, the "otherspi" either did not exist or was deleted. Also
	 * check that "otherspi" is not already paired. If everything looks
	 * good, complete the update. IPSA_REFRELE the first pair_pointer
	 * after this update to ensure its not deleted until we are done.
	 */
	oipsapp = get_ipsa_pair(assoc, srcext, dstext, spp);
	if (oipsapp == NULL) {
		/*
		 * This should never happen, calling function still has
		 * IPSA_REFHELD on the SA we just updated.
		 */
		*diagnostic = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
		return (EINVAL);
	}

	if (oipsapp->ipsap_psa_ptr == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE;
		undo_pair = B_TRUE;
	} else {
		ipsa_flags = oipsapp->ipsap_psa_ptr->ipsa_flags;
		if (oipsapp->ipsap_psa_ptr->ipsa_state > IPSA_STATE_MATURE) {
			/* Its dead Jim! */
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE;
			undo_pair = B_TRUE;
		} else if ((ipsa_flags & (IPSA_F_OUTBOUND | IPSA_F_INBOUND)) ==
		    (IPSA_F_OUTBOUND | IPSA_F_INBOUND)) {
			/* This SA is in both hashtables. */
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE;
			undo_pair = B_TRUE;
		} else if (ipsa_flags & IPSA_F_PAIRED) {
			/* This SA is already paired with another. */
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_ALREADY;
			undo_pair = B_TRUE;
		}
	}

	if (undo_pair) {
		/* The pair SA does not exist. */
		mutex_enter(&ipsapp->ipsap_sa_ptr->ipsa_lock);
		ipsapp->ipsap_sa_ptr->ipsa_flags &= ~IPSA_F_PAIRED;
		ipsapp->ipsap_sa_ptr->ipsa_otherspi = 0;
		mutex_exit(&ipsapp->ipsap_sa_ptr->ipsa_lock);
		error = EINVAL;
	} else {
		mutex_enter(&oipsapp->ipsap_psa_ptr->ipsa_lock);
		oipsapp->ipsap_psa_ptr->ipsa_otherspi = assoc->sadb_sa_spi;
		oipsapp->ipsap_psa_ptr->ipsa_flags |= IPSA_F_PAIRED;
		mutex_exit(&oipsapp->ipsap_psa_ptr->ipsa_lock);
	}

	destroy_ipsa_pair(oipsapp);
	return (error);
}

/*
 * The following functions deal with ACQUIRE LISTS.  An ACQUIRE list is
 * a list of outstanding SADB_ACQUIRE messages.	 If ipsec_getassocbyconn() fails
 * for an outbound datagram, that datagram is queued up on an ACQUIRE record,
 * and an SADB_ACQUIRE message is sent up.  Presumably, a user-space key
 * management daemon will process the ACQUIRE, use a SADB_GETSPI to reserve
 * an SPI value and a larval SA, then SADB_UPDATE the larval SA, and ADD the
 * other direction's SA.
 */

/*
 * Check the ACQUIRE lists.  If there's an existing ACQUIRE record,
 * grab it, lock it, and return it.  Otherwise return NULL.
 */
static ipsacq_t *
sadb_checkacquire(iacqf_t *bucket, ipsec_action_t *ap, ipsec_policy_t *pp,
    uint32_t *src, uint32_t *dst, uint32_t *isrc, uint32_t *idst,
    uint64_t unique_id)
{
	ipsacq_t *walker;
	sa_family_t fam;
	uint32_t blank_address[4] = {0, 0, 0, 0};

	if (isrc == NULL) {
		ASSERT(idst == NULL);
		isrc = idst = blank_address;
	}

	/*
	 * Scan list for duplicates.  Check for UNIQUE, src/dest, policy.
	 *
	 * XXX May need search for duplicates based on other things too!
	 */
	for (walker = bucket->iacqf_ipsacq; walker != NULL;
	    walker = walker->ipsacq_next) {
		mutex_enter(&walker->ipsacq_lock);
		fam = walker->ipsacq_addrfam;
		if (IPSA_ARE_ADDR_EQUAL(dst, walker->ipsacq_dstaddr, fam) &&
		    IPSA_ARE_ADDR_EQUAL(src, walker->ipsacq_srcaddr, fam) &&
		    ip_addr_match((uint8_t *)isrc, walker->ipsacq_innersrcpfx,
		    (in6_addr_t *)walker->ipsacq_innersrc) &&
		    ip_addr_match((uint8_t *)idst, walker->ipsacq_innerdstpfx,
		    (in6_addr_t *)walker->ipsacq_innerdst) &&
		    (ap == walker->ipsacq_act) &&
		    (pp == walker->ipsacq_policy) &&
		    /* XXX do deep compares of ap/pp? */
		    (unique_id == walker->ipsacq_unique_id))
			break;			/* everything matched */
		mutex_exit(&walker->ipsacq_lock);
	}

	return (walker);
}

/*
 * For this mblk, insert a new acquire record.  Assume bucket contains addrs
 * of all of the same length.  Give up (and drop) if memory
 * cannot be allocated for a new one; otherwise, invoke callback to
 * send the acquire up..
 *
 * In cases where we need both AH and ESP, add the SA to the ESP ACQUIRE
 * list.  The ah_add_sa_finish() routines can look at the packet's ipsec_out_t
 * and handle this case specially.
 */
void
sadb_acquire(mblk_t *mp, ipsec_out_t *io, boolean_t need_ah, boolean_t need_esp)
{
	sadbp_t *spp;
	sadb_t *sp;
	ipsacq_t *newbie;
	iacqf_t *bucket;
	mblk_t *datamp = mp->b_cont;
	mblk_t *extended;
	ipha_t *ipha = (ipha_t *)datamp->b_rptr;
	ip6_t *ip6h = (ip6_t *)datamp->b_rptr;
	uint32_t *src, *dst, *isrc, *idst;
	ipsec_policy_t *pp = io->ipsec_out_policy;
	ipsec_action_t *ap = io->ipsec_out_act;
	sa_family_t af;
	int hashoffset;
	uint32_t seq;
	uint64_t unique_id = 0;
	ipsec_selector_t sel;
	boolean_t tunnel_mode = io->ipsec_out_tunnel;
	netstack_t	*ns = io->ipsec_out_ns;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT((pp != NULL) || (ap != NULL));

	ASSERT(need_ah != NULL || need_esp != NULL);
	/* Assign sadb pointers */
	if (need_esp) { /* ESP for AH+ESP */
		ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;

		spp = &espstack->esp_sadb;
	} else {
		ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;

		spp = &ahstack->ah_sadb;
	}
	sp = io->ipsec_out_v4 ? &spp->s_v4 : &spp->s_v6;

	if (ap == NULL)
		ap = pp->ipsp_act;

	ASSERT(ap != NULL);

	if (ap->ipa_act.ipa_apply.ipp_use_unique || tunnel_mode)
		unique_id = SA_FORM_UNIQUE_ID(io);

	/*
	 * Set up an ACQUIRE record.
	 *
	 * Immediately, make sure the ACQUIRE sequence number doesn't slip
	 * below the lowest point allowed in the kernel.  (In other words,
	 * make sure the high bit on the sequence number is set.)
	 */

	seq = keysock_next_seq(ns) | IACQF_LOWEST_SEQ;

	if (IPH_HDR_VERSION(ipha) == IP_VERSION) {
		src = (uint32_t *)&ipha->ipha_src;
		dst = (uint32_t *)&ipha->ipha_dst;
		af = AF_INET;
		hashoffset = OUTBOUND_HASH_V4(sp, ipha->ipha_dst);
		ASSERT(io->ipsec_out_v4 == B_TRUE);
	} else {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		src = (uint32_t *)&ip6h->ip6_src;
		dst = (uint32_t *)&ip6h->ip6_dst;
		af = AF_INET6;
		hashoffset = OUTBOUND_HASH_V6(sp, ip6h->ip6_dst);
		ASSERT(io->ipsec_out_v4 == B_FALSE);
	}

	if (tunnel_mode) {
		/* Snag inner addresses. */
		isrc = io->ipsec_out_insrc;
		idst = io->ipsec_out_indst;
	} else {
		isrc = idst = NULL;
	}

	/*
	 * Check buckets to see if there is an existing entry.  If so,
	 * grab it.  sadb_checkacquire locks newbie if found.
	 */
	bucket = &(sp->sdb_acq[hashoffset]);
	mutex_enter(&bucket->iacqf_lock);
	newbie = sadb_checkacquire(bucket, ap, pp, src, dst, isrc, idst,
	    unique_id);

	if (newbie == NULL) {
		/*
		 * Otherwise, allocate a new one.
		 */
		newbie = kmem_zalloc(sizeof (*newbie), KM_NOSLEEP);
		if (newbie == NULL) {
			mutex_exit(&bucket->iacqf_lock);
			ip_drop_packet(mp, B_FALSE, NULL, NULL,
			    DROPPER(ipss, ipds_sadb_acquire_nomem),
			    &ipss->ipsec_sadb_dropper);
			return;
		}
		newbie->ipsacq_policy = pp;
		if (pp != NULL) {
			IPPOL_REFHOLD(pp);
		}
		IPACT_REFHOLD(ap);
		newbie->ipsacq_act = ap;
		newbie->ipsacq_linklock = &bucket->iacqf_lock;
		newbie->ipsacq_next = bucket->iacqf_ipsacq;
		newbie->ipsacq_ptpn = &bucket->iacqf_ipsacq;
		if (newbie->ipsacq_next != NULL)
			newbie->ipsacq_next->ipsacq_ptpn = &newbie->ipsacq_next;
		bucket->iacqf_ipsacq = newbie;
		mutex_init(&newbie->ipsacq_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_enter(&newbie->ipsacq_lock);
	}

	mutex_exit(&bucket->iacqf_lock);

	/*
	 * This assert looks silly for now, but we may need to enter newbie's
	 * mutex during a search.
	 */
	ASSERT(MUTEX_HELD(&newbie->ipsacq_lock));

	mp->b_next = NULL;
	/* Queue up packet.  Use b_next. */
	if (newbie->ipsacq_numpackets == 0) {
		/* First one. */
		newbie->ipsacq_mp = mp;
		newbie->ipsacq_numpackets = 1;
		newbie->ipsacq_expire = gethrestime_sec();
		/*
		 * Extended ACQUIRE with both AH+ESP will use ESP's timeout
		 * value.
		 */
		newbie->ipsacq_expire += *spp->s_acquire_timeout;
		newbie->ipsacq_seq = seq;
		newbie->ipsacq_addrfam = af;

		newbie->ipsacq_srcport = io->ipsec_out_src_port;
		newbie->ipsacq_dstport = io->ipsec_out_dst_port;
		newbie->ipsacq_icmp_type = io->ipsec_out_icmp_type;
		newbie->ipsacq_icmp_code = io->ipsec_out_icmp_code;
		if (tunnel_mode) {
			newbie->ipsacq_inneraddrfam = io->ipsec_out_inaf;
			newbie->ipsacq_proto = io->ipsec_out_inaf == AF_INET6 ?
			    IPPROTO_IPV6 : IPPROTO_ENCAP;
			newbie->ipsacq_innersrcpfx = io->ipsec_out_insrcpfx;
			newbie->ipsacq_innerdstpfx = io->ipsec_out_indstpfx;
			IPSA_COPY_ADDR(newbie->ipsacq_innersrc,
			    io->ipsec_out_insrc, io->ipsec_out_inaf);
			IPSA_COPY_ADDR(newbie->ipsacq_innerdst,
			    io->ipsec_out_indst, io->ipsec_out_inaf);
		} else {
			newbie->ipsacq_proto = io->ipsec_out_proto;
		}
		newbie->ipsacq_unique_id = unique_id;
	} else {
		/* Scan to the end of the list & insert. */
		mblk_t *lastone = newbie->ipsacq_mp;

		while (lastone->b_next != NULL)
			lastone = lastone->b_next;
		lastone->b_next = mp;
		if (newbie->ipsacq_numpackets++ == ipsacq_maxpackets) {
			newbie->ipsacq_numpackets = ipsacq_maxpackets;
			lastone = newbie->ipsacq_mp;
			newbie->ipsacq_mp = lastone->b_next;
			lastone->b_next = NULL;
			ip_drop_packet(lastone, B_FALSE, NULL, NULL,
			    DROPPER(ipss, ipds_sadb_acquire_toofull),
			    &ipss->ipsec_sadb_dropper);
		} else {
			IP_ACQUIRE_STAT(ipss, qhiwater,
			    newbie->ipsacq_numpackets);
		}
	}

	/*
	 * Reset addresses.  Set them to the most recently added mblk chain,
	 * so that the address pointers in the acquire record will point
	 * at an mblk still attached to the acquire list.
	 */

	newbie->ipsacq_srcaddr = src;
	newbie->ipsacq_dstaddr = dst;

	/*
	 * If the acquire record has more than one queued packet, we've
	 * already sent an ACQUIRE, and don't need to repeat ourself.
	 */
	if (newbie->ipsacq_seq != seq || newbie->ipsacq_numpackets > 1) {
		/* I have an acquire outstanding already! */
		mutex_exit(&newbie->ipsacq_lock);
		return;
	}

	if (keysock_extended_reg(ns)) {
		/*
		 * Construct an extended ACQUIRE.  There are logging
		 * opportunities here in failure cases.
		 */

		(void) memset(&sel, 0, sizeof (sel));
		sel.ips_isv4 = io->ipsec_out_v4;
		if (tunnel_mode) {
			sel.ips_protocol = (io->ipsec_out_inaf == AF_INET) ?
			    IPPROTO_ENCAP : IPPROTO_IPV6;
		} else {
			sel.ips_protocol = io->ipsec_out_proto;
			sel.ips_local_port = io->ipsec_out_src_port;
			sel.ips_remote_port = io->ipsec_out_dst_port;
		}
		sel.ips_icmp_type = io->ipsec_out_icmp_type;
		sel.ips_icmp_code = io->ipsec_out_icmp_code;
		sel.ips_is_icmp_inv_acq = 0;
		if (af == AF_INET) {
			sel.ips_local_addr_v4 = ipha->ipha_src;
			sel.ips_remote_addr_v4 = ipha->ipha_dst;
		} else {
			sel.ips_local_addr_v6 = ip6h->ip6_src;
			sel.ips_remote_addr_v6 = ip6h->ip6_dst;
		}

		extended = sadb_keysock_out(0);
		if (extended != NULL) {
			extended->b_cont = sadb_extended_acquire(&sel, pp, ap,
			    tunnel_mode, seq, 0, ns);
			if (extended->b_cont == NULL) {
				freeb(extended);
				extended = NULL;
			}
		}
	} else
		extended = NULL;

	/*
	 * Send an ACQUIRE message (and possible an extended ACQUIRE) based on
	 * this new record.  The send-acquire callback assumes that acqrec is
	 * already locked.
	 */
	(*spp->s_acqfn)(newbie, extended, ns);
}

/*
 * Unlink and free an acquire record.
 */
void
sadb_destroy_acquire(ipsacq_t *acqrec, netstack_t *ns)
{
	mblk_t *mp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(MUTEX_HELD(acqrec->ipsacq_linklock));

	if (acqrec->ipsacq_policy != NULL) {
		IPPOL_REFRELE(acqrec->ipsacq_policy, ns);
	}
	if (acqrec->ipsacq_act != NULL) {
		IPACT_REFRELE(acqrec->ipsacq_act);
	}

	/* Unlink */
	*(acqrec->ipsacq_ptpn) = acqrec->ipsacq_next;
	if (acqrec->ipsacq_next != NULL)
		acqrec->ipsacq_next->ipsacq_ptpn = acqrec->ipsacq_ptpn;

	/*
	 * Free hanging mp's.
	 *
	 * XXX Instead of freemsg(), perhaps use IPSEC_REQ_FAILED.
	 */

	mutex_enter(&acqrec->ipsacq_lock);
	while (acqrec->ipsacq_mp != NULL) {
		mp = acqrec->ipsacq_mp;
		acqrec->ipsacq_mp = mp->b_next;
		mp->b_next = NULL;
		ip_drop_packet(mp, B_FALSE, NULL, NULL,
		    DROPPER(ipss, ipds_sadb_acquire_timeout),
		    &ipss->ipsec_sadb_dropper);
	}
	mutex_exit(&acqrec->ipsacq_lock);

	/* Free */
	mutex_destroy(&acqrec->ipsacq_lock);
	kmem_free(acqrec, sizeof (*acqrec));
}

/*
 * Destroy an acquire list fanout.
 */
static void
sadb_destroy_acqlist(iacqf_t **listp, uint_t numentries, boolean_t forever,
    netstack_t *ns)
{
	int i;
	iacqf_t *list = *listp;

	if (list == NULL)
		return;

	for (i = 0; i < numentries; i++) {
		mutex_enter(&(list[i].iacqf_lock));
		while (list[i].iacqf_ipsacq != NULL)
			sadb_destroy_acquire(list[i].iacqf_ipsacq, ns);
		mutex_exit(&(list[i].iacqf_lock));
		if (forever)
			mutex_destroy(&(list[i].iacqf_lock));
	}

	if (forever) {
		*listp = NULL;
		kmem_free(list, numentries * sizeof (*list));
	}
}

/*
 * Create an algorithm descriptor for an extended ACQUIRE.  Filter crypto
 * framework's view of reality vs. IPsec's.  EF's wins, BTW.
 */
static uint8_t *
sadb_new_algdesc(uint8_t *start, uint8_t *limit,
    sadb_x_ecomb_t *ecomb, uint8_t satype, uint8_t algtype,
    uint8_t alg, uint16_t minbits, uint16_t maxbits, ipsec_stack_t *ipss)
{
	uint8_t *cur = start;
	ipsec_alginfo_t *algp;
	sadb_x_algdesc_t *algdesc = (sadb_x_algdesc_t *)cur;

	cur += sizeof (*algdesc);
	if (cur >= limit)
		return (NULL);

	ecomb->sadb_x_ecomb_numalgs++;

	/*
	 * Normalize vs. crypto framework's limits.  This way, you can specify
	 * a stronger policy, and when the framework loads a stronger version,
	 * you can just keep plowing w/o rewhacking your SPD.
	 */
	mutex_enter(&ipss->ipsec_alg_lock);
	algp = ipss->ipsec_alglists[(algtype == SADB_X_ALGTYPE_AUTH) ?
	    IPSEC_ALG_AUTH : IPSEC_ALG_ENCR][alg];
	if (algp == NULL) {
		mutex_exit(&ipss->ipsec_alg_lock);
		return (NULL);	/* Algorithm doesn't exist.  Fail gracefully. */
	}
	if (minbits < algp->alg_ef_minbits)
		minbits = algp->alg_ef_minbits;
	if (maxbits > algp->alg_ef_maxbits)
		maxbits = algp->alg_ef_maxbits;
	mutex_exit(&ipss->ipsec_alg_lock);

	algdesc->sadb_x_algdesc_satype = satype;
	algdesc->sadb_x_algdesc_algtype = algtype;
	algdesc->sadb_x_algdesc_alg = alg;
	algdesc->sadb_x_algdesc_minbits = minbits;
	algdesc->sadb_x_algdesc_maxbits = maxbits;
	algdesc->sadb_x_algdesc_reserved = 0;
	return (cur);
}

/*
 * Convert the given ipsec_action_t into an ecomb starting at *ecomb
 * which must fit before *limit
 *
 * return NULL if we ran out of room or a pointer to the end of the ecomb.
 */
static uint8_t *
sadb_action_to_ecomb(uint8_t *start, uint8_t *limit, ipsec_action_t *act,
    netstack_t *ns)
{
	uint8_t *cur = start;
	sadb_x_ecomb_t *ecomb = (sadb_x_ecomb_t *)cur;
	ipsec_prot_t *ipp;
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	cur += sizeof (*ecomb);
	if (cur >= limit)
		return (NULL);

	ASSERT(act->ipa_act.ipa_type == IPSEC_ACT_APPLY);

	ipp = &act->ipa_act.ipa_apply;

	ecomb->sadb_x_ecomb_numalgs = 0;
	ecomb->sadb_x_ecomb_reserved = 0;
	ecomb->sadb_x_ecomb_reserved2 = 0;
	/*
	 * No limits on allocations, since we really don't support that
	 * concept currently.
	 */
	ecomb->sadb_x_ecomb_soft_allocations = 0;
	ecomb->sadb_x_ecomb_hard_allocations = 0;

	/*
	 * XXX TBD: Policy or global parameters will eventually be
	 * able to fill in some of these.
	 */
	ecomb->sadb_x_ecomb_flags = 0;
	ecomb->sadb_x_ecomb_soft_bytes = 0;
	ecomb->sadb_x_ecomb_hard_bytes = 0;
	ecomb->sadb_x_ecomb_soft_addtime = 0;
	ecomb->sadb_x_ecomb_hard_addtime = 0;
	ecomb->sadb_x_ecomb_soft_usetime = 0;
	ecomb->sadb_x_ecomb_hard_usetime = 0;

	if (ipp->ipp_use_ah) {
		cur = sadb_new_algdesc(cur, limit, ecomb,
		    SADB_SATYPE_AH, SADB_X_ALGTYPE_AUTH, ipp->ipp_auth_alg,
		    ipp->ipp_ah_minbits, ipp->ipp_ah_maxbits, ipss);
		if (cur == NULL)
			return (NULL);
		ipsecah_fill_defs(ecomb, ns);
	}

	if (ipp->ipp_use_esp) {
		if (ipp->ipp_use_espa) {
			cur = sadb_new_algdesc(cur, limit, ecomb,
			    SADB_SATYPE_ESP, SADB_X_ALGTYPE_AUTH,
			    ipp->ipp_esp_auth_alg,
			    ipp->ipp_espa_minbits,
			    ipp->ipp_espa_maxbits, ipss);
			if (cur == NULL)
				return (NULL);
		}

		cur = sadb_new_algdesc(cur, limit, ecomb,
		    SADB_SATYPE_ESP, SADB_X_ALGTYPE_CRYPT,
		    ipp->ipp_encr_alg,
		    ipp->ipp_espe_minbits,
		    ipp->ipp_espe_maxbits, ipss);
		if (cur == NULL)
			return (NULL);
		/* Fill in lifetimes if and only if AH didn't already... */
		if (!ipp->ipp_use_ah)
			ipsecesp_fill_defs(ecomb, ns);
	}

	return (cur);
}

/*
 * Construct an extended ACQUIRE message based on a selector and the resulting
 * IPsec action.
 *
 * NOTE: This is used by both inverse ACQUIRE and actual ACQUIRE
 * generation. As a consequence, expect this function to evolve
 * rapidly.
 */
static mblk_t *
sadb_extended_acquire(ipsec_selector_t *sel, ipsec_policy_t *pol,
    ipsec_action_t *act, boolean_t tunnel_mode, uint32_t seq, uint32_t pid,
    netstack_t *ns)
{
	mblk_t *mp;
	sadb_msg_t *samsg;
	uint8_t *start, *cur, *end;
	uint32_t *saddrptr, *daddrptr;
	sa_family_t af;
	sadb_prop_t *eprop;
	ipsec_action_t *ap, *an;
	ipsec_selkey_t *ipsl;
	uint8_t proto, pfxlen;
	uint16_t lport, rport;
	uint32_t kmp, kmc;

	/*
	 * Find the action we want sooner rather than later..
	 */
	an = NULL;
	if (pol == NULL) {
		ap = act;
	} else {
		ap = pol->ipsp_act;

		if (ap != NULL)
			an = ap->ipa_next;
	}

	/*
	 * Just take a swag for the allocation for now.	 We can always
	 * alter it later.
	 */
#define	SADB_EXTENDED_ACQUIRE_SIZE	4096
	mp = allocb(SADB_EXTENDED_ACQUIRE_SIZE, BPRI_HI);
	if (mp == NULL)
		return (NULL);

	start = mp->b_rptr;
	end = start + SADB_EXTENDED_ACQUIRE_SIZE;

	cur = start;

	samsg = (sadb_msg_t *)cur;
	cur += sizeof (*samsg);

	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_ACQUIRE;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_satype = 0;
	samsg->sadb_msg_seq = seq;
	samsg->sadb_msg_pid = pid;

	if (tunnel_mode) {
		/*
		 * Form inner address extensions based NOT on the inner
		 * selectors (i.e. the packet data), but on the policy's
		 * selector key (i.e. the policy's selector information).
		 *
		 * NOTE:  The position of IPv4 and IPv6 addresses is the
		 * same in ipsec_selkey_t (unless the compiler does very
		 * strange things with unions, consult your local C language
		 * lawyer for details).
		 */
		ipsl = &(pol->ipsp_sel->ipsl_key);
		if (ipsl->ipsl_valid & IPSL_IPV4) {
			af = AF_INET;
			ASSERT(sel->ips_protocol == IPPROTO_ENCAP);
			ASSERT(!(ipsl->ipsl_valid & IPSL_IPV6));
		} else {
			af = AF_INET6;
			ASSERT(sel->ips_protocol == IPPROTO_IPV6);
			ASSERT(ipsl->ipsl_valid & IPSL_IPV6);
		}

		if (ipsl->ipsl_valid & IPSL_LOCAL_ADDR) {
			saddrptr = (uint32_t *)(&ipsl->ipsl_local);
			pfxlen = ipsl->ipsl_local_pfxlen;
		} else {
			saddrptr = (uint32_t *)(&ipv6_all_zeros);
			pfxlen = 0;
		}
		/* XXX What about ICMP type/code? */
		lport = (ipsl->ipsl_valid & IPSL_LOCAL_PORT) ?
		    ipsl->ipsl_lport : 0;
		proto = (ipsl->ipsl_valid & IPSL_PROTOCOL) ?
		    ipsl->ipsl_proto : 0;

		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_INNER_SRC,
		    af, saddrptr, lport, proto, pfxlen);
		if (cur == NULL) {
			freeb(mp);
			return (NULL);
		}

		if (ipsl->ipsl_valid & IPSL_REMOTE_ADDR) {
			daddrptr = (uint32_t *)(&ipsl->ipsl_remote);
			pfxlen = ipsl->ipsl_remote_pfxlen;
		} else {
			daddrptr = (uint32_t *)(&ipv6_all_zeros);
			pfxlen = 0;
		}
		/* XXX What about ICMP type/code? */
		rport = (ipsl->ipsl_valid & IPSL_REMOTE_PORT) ?
		    ipsl->ipsl_rport : 0;

		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_INNER_DST,
		    af, daddrptr, rport, proto, pfxlen);
		if (cur == NULL) {
			freeb(mp);
			return (NULL);
		}
		/*
		 * TODO  - if we go to 3408's dream of transport mode IP-in-IP
		 * _with_ inner-packet address selectors, we'll need to further
		 * distinguish tunnel mode here.  For now, having inner
		 * addresses and/or ports is sufficient.
		 *
		 * Meanwhile, whack proto/ports to reflect IP-in-IP for the
		 * outer addresses.
		 */
		proto = sel->ips_protocol;	/* Either _ENCAP or _IPV6 */
		lport = rport = 0;
	} else if ((ap != NULL) && (!ap->ipa_want_unique)) {
		proto = 0;
		lport = 0;
		rport = 0;
		if (pol != NULL) {
			ipsl = &(pol->ipsp_sel->ipsl_key);
			if (ipsl->ipsl_valid & IPSL_PROTOCOL)
				proto = ipsl->ipsl_proto;
			if (ipsl->ipsl_valid & IPSL_REMOTE_PORT)
				rport = ipsl->ipsl_rport;
			if (ipsl->ipsl_valid & IPSL_LOCAL_PORT)
				lport = ipsl->ipsl_lport;
		}
	} else {
		proto = sel->ips_protocol;
		lport = sel->ips_local_port;
		rport = sel->ips_remote_port;
	}

	af = sel->ips_isv4 ? AF_INET : AF_INET6;

	/*
	 * NOTE:  The position of IPv4 and IPv6 addresses is the same in
	 * ipsec_selector_t.
	 */
	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC, af,
	    (uint32_t *)(&sel->ips_local_addr_v6), lport, proto, 0);

	if (cur == NULL) {
		freeb(mp);
		return (NULL);
	}

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST, af,
	    (uint32_t *)(&sel->ips_remote_addr_v6), rport, proto, 0);

	if (cur == NULL) {
		freeb(mp);
		return (NULL);
	}

	/*
	 * This section will change a lot as policy evolves.
	 * For now, it'll be relatively simple.
	 */
	eprop = (sadb_prop_t *)cur;
	cur += sizeof (*eprop);
	if (cur > end) {
		/* no space left */
		freeb(mp);
		return (NULL);
	}

	eprop->sadb_prop_exttype = SADB_X_EXT_EPROP;
	eprop->sadb_x_prop_ereserved = 0;
	eprop->sadb_x_prop_numecombs = 0;
	eprop->sadb_prop_replay = 32;	/* default */

	kmc = kmp = 0;

	for (; ap != NULL; ap = an) {
		an = (pol != NULL) ? ap->ipa_next : NULL;

		/*
		 * Skip non-IPsec policies
		 */
		if (ap->ipa_act.ipa_type != IPSEC_ACT_APPLY)
			continue;

		if (ap->ipa_act.ipa_apply.ipp_km_proto)
			kmp = ap->ipa_act.ipa_apply.ipp_km_proto;
		if (ap->ipa_act.ipa_apply.ipp_km_cookie)
			kmc = ap->ipa_act.ipa_apply.ipp_km_cookie;
		if (ap->ipa_act.ipa_apply.ipp_replay_depth) {
			eprop->sadb_prop_replay =
			    ap->ipa_act.ipa_apply.ipp_replay_depth;
		}

		cur = sadb_action_to_ecomb(cur, end, ap, ns);
		if (cur == NULL) { /* no space */
			freeb(mp);
			return (NULL);
		}
		eprop->sadb_x_prop_numecombs++;
	}

	if (eprop->sadb_x_prop_numecombs == 0) {
		/*
		 * This will happen if we fail to find a policy
		 * allowing for IPsec processing.
		 * Construct an error message.
		 */
		samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg));
		samsg->sadb_msg_errno = ENOENT;
		samsg->sadb_x_msg_diagnostic = 0;
		return (mp);
	}

	if ((kmp != 0) || (kmc != 0)) {
		cur = sadb_make_kmc_ext(cur, end, kmp, kmc);
		if (cur == NULL) {
			freeb(mp);
			return (NULL);
		}
	}

	eprop->sadb_prop_len = SADB_8TO64(cur - (uint8_t *)eprop);
	samsg->sadb_msg_len = SADB_8TO64(cur - start);
	mp->b_wptr = cur;

	return (mp);
}

/*
 * Generic setup of an RFC 2367 ACQUIRE message.  Caller sets satype.
 *
 * NOTE: This function acquires alg_lock as a side-effect if-and-only-if we
 * succeed (i.e. return non-NULL).  Caller MUST release it.  This is to
 * maximize code consolidation while preventing algorithm changes from messing
 * with the callers finishing touches on the ACQUIRE itself.
 */
mblk_t *
sadb_setup_acquire(ipsacq_t *acqrec, uint8_t satype, ipsec_stack_t *ipss)
{
	uint_t allocsize;
	mblk_t *pfkeymp, *msgmp;
	sa_family_t af;
	uint8_t *cur, *end;
	sadb_msg_t *samsg;
	uint16_t sport_typecode;
	uint16_t dport_typecode;
	uint8_t check_proto;
	boolean_t tunnel_mode = (acqrec->ipsacq_inneraddrfam != 0);

	ASSERT(MUTEX_HELD(&acqrec->ipsacq_lock));

	pfkeymp = sadb_keysock_out(0);
	if (pfkeymp == NULL)
		return (NULL);

	/*
	 * First, allocate a basic ACQUIRE message
	 */
	allocsize = sizeof (sadb_msg_t) + sizeof (sadb_address_t) +
	    sizeof (sadb_address_t) + sizeof (sadb_prop_t);

	/* Make sure there's enough to cover both AF_INET and AF_INET6. */
	allocsize += 2 * sizeof (struct sockaddr_in6);

	mutex_enter(&ipss->ipsec_alg_lock);
	/* NOTE:  The lock is now held through to this function's return. */
	allocsize += ipss->ipsec_nalgs[IPSEC_ALG_AUTH] *
	    ipss->ipsec_nalgs[IPSEC_ALG_ENCR] * sizeof (sadb_comb_t);

	if (tunnel_mode) {
		/* Tunnel mode! */
		allocsize += 2 * sizeof (sadb_address_t);
		/* Enough to cover both AF_INET and AF_INET6. */
		allocsize += 2 * sizeof (struct sockaddr_in6);
	}

	msgmp = allocb(allocsize, BPRI_HI);
	if (msgmp == NULL) {
		freeb(pfkeymp);
		mutex_exit(&ipss->ipsec_alg_lock);
		return (NULL);
	}

	pfkeymp->b_cont = msgmp;
	cur = msgmp->b_rptr;
	end = cur + allocsize;
	samsg = (sadb_msg_t *)cur;
	cur += sizeof (sadb_msg_t);

	af = acqrec->ipsacq_addrfam;
	switch (af) {
	case AF_INET:
		check_proto = IPPROTO_ICMP;
		break;
	case AF_INET6:
		check_proto = IPPROTO_ICMPV6;
		break;
	default:
		/* This should never happen unless we have kernel bugs. */
		cmn_err(CE_WARN,
		    "sadb_setup_acquire:  corrupt ACQUIRE record.\n");
		ASSERT(0);
		mutex_exit(&ipss->ipsec_alg_lock);
		return (NULL);
	}

	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_ACQUIRE;
	samsg->sadb_msg_satype = satype;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_pid = 0;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = acqrec->ipsacq_seq;

	ASSERT(MUTEX_HELD(&acqrec->ipsacq_lock));

	if ((acqrec->ipsacq_proto == check_proto) || tunnel_mode) {
		sport_typecode = dport_typecode = 0;
	} else {
		sport_typecode = acqrec->ipsacq_srcport;
		dport_typecode = acqrec->ipsacq_dstport;
	}

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC, af,
	    acqrec->ipsacq_srcaddr, sport_typecode, acqrec->ipsacq_proto, 0);

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST, af,
	    acqrec->ipsacq_dstaddr, dport_typecode, acqrec->ipsacq_proto, 0);

	if (tunnel_mode) {
		sport_typecode = acqrec->ipsacq_srcport;
		dport_typecode = acqrec->ipsacq_dstport;
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_INNER_SRC,
		    acqrec->ipsacq_inneraddrfam, acqrec->ipsacq_innersrc,
		    sport_typecode, acqrec->ipsacq_inner_proto,
		    acqrec->ipsacq_innersrcpfx);
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_INNER_DST,
		    acqrec->ipsacq_inneraddrfam, acqrec->ipsacq_innerdst,
		    dport_typecode, acqrec->ipsacq_inner_proto,
		    acqrec->ipsacq_innerdstpfx);
	}

	/* XXX Insert identity information here. */

	/* XXXMLS Insert sensitivity information here. */

	if (cur != NULL)
		samsg->sadb_msg_len = SADB_8TO64(cur - msgmp->b_rptr);
	else
		mutex_exit(&ipss->ipsec_alg_lock);

	return (pfkeymp);
}

/*
 * Given an SADB_GETSPI message, find an appropriately ranged SA and
 * allocate an SA.  If there are message improprieties, return (ipsa_t *)-1.
 * If there was a memory allocation error, return NULL.	 (Assume NULL !=
 * (ipsa_t *)-1).
 *
 * master_spi is passed in host order.
 */
ipsa_t *
sadb_getspi(keysock_in_t *ksi, uint32_t master_spi, int *diagnostic,
    netstack_t *ns)
{
	sadb_address_t *src =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC],
	    *dst = (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_spirange_t *range =
	    (sadb_spirange_t *)ksi->ks_in_extv[SADB_EXT_SPIRANGE];
	struct sockaddr_in *ssa, *dsa;
	struct sockaddr_in6 *ssa6, *dsa6;
	uint32_t *srcaddr, *dstaddr;
	sa_family_t af;
	uint32_t add, min, max;

	if (src == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return ((ipsa_t *)-1);
	}
	if (dst == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return ((ipsa_t *)-1);
	}
	if (range == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_RANGE;
		return ((ipsa_t *)-1);
	}

	min = ntohl(range->sadb_spirange_min);
	max = ntohl(range->sadb_spirange_max);
	dsa = (struct sockaddr_in *)(dst + 1);
	dsa6 = (struct sockaddr_in6 *)dsa;

	ssa = (struct sockaddr_in *)(src + 1);
	ssa6 = (struct sockaddr_in6 *)ssa;
	ASSERT(dsa->sin_family == ssa->sin_family);

	srcaddr = ALL_ZEROES_PTR;
	af = dsa->sin_family;
	switch (af) {
	case AF_INET:
		if (src != NULL)
			srcaddr = (uint32_t *)(&ssa->sin_addr);
		dstaddr = (uint32_t *)(&dsa->sin_addr);
		break;
	case AF_INET6:
		if (src != NULL)
			srcaddr = (uint32_t *)(&ssa6->sin6_addr);
		dstaddr = (uint32_t *)(&dsa6->sin6_addr);
		break;
	default:
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_DST_AF;
		return ((ipsa_t *)-1);
	}

	if (master_spi < min || master_spi > max) {
		/* Return a random value in the range. */
		(void) random_get_pseudo_bytes((uint8_t *)&add, sizeof (add));
		master_spi = min + (add % (max - min + 1));
	}

	/*
	 * Since master_spi is passed in host order, we need to htonl() it
	 * for the purposes of creating a new SA.
	 */
	return (sadb_makelarvalassoc(htonl(master_spi), srcaddr, dstaddr, af,
	    ns));
}

/*
 *
 * Locate an ACQUIRE and nuke it.  If I have an samsg that's larger than the
 * base header, just ignore it.	 Otherwise, lock down the whole ACQUIRE list
 * and scan for the sequence number in question.  I may wish to accept an
 * address pair with it, for easier searching.
 *
 * Caller frees the message, so we don't have to here.
 *
 * NOTE:	The ip_q parameter may be used in the future for ACQUIRE
 *		failures.
 */
/* ARGSUSED */
void
sadb_in_acquire(sadb_msg_t *samsg, sadbp_t *sp, queue_t *ip_q, netstack_t *ns)
{
	int i;
	ipsacq_t *acqrec;
	iacqf_t *bucket;

	/*
	 * I only accept the base header for this!
	 * Though to be honest, requiring the dst address would help
	 * immensely.
	 *
	 * XXX	There are already cases where I can get the dst address.
	 */
	if (samsg->sadb_msg_len > SADB_8TO64(sizeof (*samsg)))
		return;

	/*
	 * Using the samsg->sadb_msg_seq, find the ACQUIRE record, delete it,
	 * (and in the future send a message to IP with the appropriate error
	 * number).
	 *
	 * Q: Do I want to reject if pid != 0?
	 */

	for (i = 0; i < sp->s_v4.sdb_hashsize; i++) {
		bucket = &sp->s_v4.sdb_acq[i];
		mutex_enter(&bucket->iacqf_lock);
		for (acqrec = bucket->iacqf_ipsacq; acqrec != NULL;
		    acqrec = acqrec->ipsacq_next) {
			if (samsg->sadb_msg_seq == acqrec->ipsacq_seq)
				break;	/* for acqrec... loop. */
		}
		if (acqrec != NULL)
			break;	/* for i = 0... loop. */

		mutex_exit(&bucket->iacqf_lock);
	}

	if (acqrec == NULL) {
		for (i = 0; i < sp->s_v6.sdb_hashsize; i++) {
			bucket = &sp->s_v6.sdb_acq[i];
			mutex_enter(&bucket->iacqf_lock);
			for (acqrec = bucket->iacqf_ipsacq; acqrec != NULL;
			    acqrec = acqrec->ipsacq_next) {
				if (samsg->sadb_msg_seq == acqrec->ipsacq_seq)
					break;	/* for acqrec... loop. */
			}
			if (acqrec != NULL)
				break;	/* for i = 0... loop. */

			mutex_exit(&bucket->iacqf_lock);
		}
	}


	if (acqrec == NULL)
		return;

	/*
	 * What do I do with the errno and IP?	I may need mp's services a
	 * little more.	 See sadb_destroy_acquire() for future directions
	 * beyond free the mblk chain on the acquire record.
	 */

	ASSERT(&bucket->iacqf_lock == acqrec->ipsacq_linklock);
	sadb_destroy_acquire(acqrec, ns);
	/* Have to exit mutex here, because of breaking out of for loop. */
	mutex_exit(&bucket->iacqf_lock);
}

/*
 * The following functions work with the replay windows of an SA.  They assume
 * the ipsa->ipsa_replay_arr is an array of uint64_t, and that the bit vector
 * represents the highest sequence number packet received, and back
 * (ipsa->ipsa_replay_wsize) packets.
 */

/*
 * Is the replay bit set?
 */
static boolean_t
ipsa_is_replay_set(ipsa_t *ipsa, uint32_t offset)
{
	uint64_t bit = (uint64_t)1 << (uint64_t)(offset & 63);

	return ((bit & ipsa->ipsa_replay_arr[offset >> 6]) ? B_TRUE : B_FALSE);
}

/*
 * Shift the bits of the replay window over.
 */
static void
ipsa_shift_replay(ipsa_t *ipsa, uint32_t shift)
{
	int i;
	int jump = ((shift - 1) >> 6) + 1;

	if (shift == 0)
		return;

	for (i = (ipsa->ipsa_replay_wsize - 1) >> 6; i >= 0; i--) {
		if (i + jump <= (ipsa->ipsa_replay_wsize - 1) >> 6) {
			ipsa->ipsa_replay_arr[i + jump] |=
			    ipsa->ipsa_replay_arr[i] >> (64 - (shift & 63));
		}
		ipsa->ipsa_replay_arr[i] <<= shift;
	}
}

/*
 * Set a bit in the bit vector.
 */
static void
ipsa_set_replay(ipsa_t *ipsa, uint32_t offset)
{
	uint64_t bit = (uint64_t)1 << (uint64_t)(offset & 63);

	ipsa->ipsa_replay_arr[offset >> 6] |= bit;
}

#define	SADB_MAX_REPLAY_VALUE 0xffffffff

/*
 * Assume caller has NOT done ntohl() already on seq.  Check to see
 * if replay sequence number "seq" has been seen already.
 */
boolean_t
sadb_replay_check(ipsa_t *ipsa, uint32_t seq)
{
	boolean_t rc;
	uint32_t diff;

	if (ipsa->ipsa_replay_wsize == 0)
		return (B_TRUE);

	/*
	 * NOTE:  I've already checked for 0 on the wire in sadb_replay_peek().
	 */

	/* Convert sequence number into host order before holding the mutex. */
	seq = ntohl(seq);

	mutex_enter(&ipsa->ipsa_lock);

	/* Initialize inbound SA's ipsa_replay field to last one received. */
	if (ipsa->ipsa_replay == 0)
		ipsa->ipsa_replay = 1;

	if (seq > ipsa->ipsa_replay) {
		/*
		 * I have received a new "highest value received".  Shift
		 * the replay window over.
		 */
		diff = seq - ipsa->ipsa_replay;
		if (diff < ipsa->ipsa_replay_wsize) {
			/* In replay window, shift bits over. */
			ipsa_shift_replay(ipsa, diff);
		} else {
			/* WAY FAR AHEAD, clear bits and start again. */
			bzero(ipsa->ipsa_replay_arr,
			    sizeof (ipsa->ipsa_replay_arr));
		}
		ipsa_set_replay(ipsa, 0);
		ipsa->ipsa_replay = seq;
		rc = B_TRUE;
		goto done;
	}
	diff = ipsa->ipsa_replay - seq;
	if (diff >= ipsa->ipsa_replay_wsize || ipsa_is_replay_set(ipsa, diff)) {
		rc = B_FALSE;
		goto done;
	}
	/* Set this packet as seen. */
	ipsa_set_replay(ipsa, diff);

	rc = B_TRUE;
done:
	mutex_exit(&ipsa->ipsa_lock);
	return (rc);
}

/*
 * "Peek" and see if we should even bother going through the effort of
 * running an authentication check on the sequence number passed in.
 * this takes into account packets that are below the replay window,
 * and collisions with already replayed packets.  Return B_TRUE if it
 * is okay to proceed, B_FALSE if this packet should be dropped immediately.
 * Assume same byte-ordering as sadb_replay_check.
 */
boolean_t
sadb_replay_peek(ipsa_t *ipsa, uint32_t seq)
{
	boolean_t rc = B_FALSE;
	uint32_t diff;

	if (ipsa->ipsa_replay_wsize == 0)
		return (B_TRUE);

	/*
	 * 0 is 0, regardless of byte order... :)
	 *
	 * If I get 0 on the wire (and there is a replay window) then the
	 * sender most likely wrapped.	This ipsa may need to be marked or
	 * something.
	 */
	if (seq == 0)
		return (B_FALSE);

	seq = ntohl(seq);
	mutex_enter(&ipsa->ipsa_lock);
	if (seq < ipsa->ipsa_replay - ipsa->ipsa_replay_wsize &&
	    ipsa->ipsa_replay >= ipsa->ipsa_replay_wsize)
		goto done;

	/*
	 * If I've hit 0xffffffff, then quite honestly, I don't need to
	 * bother with formalities.  I'm not accepting any more packets
	 * on this SA.
	 */
	if (ipsa->ipsa_replay == SADB_MAX_REPLAY_VALUE) {
		/*
		 * Since we're already holding the lock, update the
		 * expire time ala. sadb_replay_delete() and return.
		 */
		ipsa->ipsa_hardexpiretime = (time_t)1;
		goto done;
	}

	if (seq <= ipsa->ipsa_replay) {
		/*
		 * This seq is in the replay window.  I'm not below it,
		 * because I already checked for that above!
		 */
		diff = ipsa->ipsa_replay - seq;
		if (ipsa_is_replay_set(ipsa, diff))
			goto done;
	}
	/* Else return B_TRUE, I'm going to advance the window. */

	rc = B_TRUE;
done:
	mutex_exit(&ipsa->ipsa_lock);
	return (rc);
}

/*
 * Delete a single SA.
 *
 * For now, use the quick-and-dirty trick of making the association's
 * hard-expire lifetime (time_t)1, ensuring deletion by the *_ager().
 */
void
sadb_replay_delete(ipsa_t *assoc)
{
	mutex_enter(&assoc->ipsa_lock);
	assoc->ipsa_hardexpiretime = (time_t)1;
	mutex_exit(&assoc->ipsa_lock);
}

/*
 * Given a queue that presumably points to IP, send a T_BIND_REQ for _proto_
 * down.  The caller will handle the T_BIND_ACK locally.
 */
boolean_t
sadb_t_bind_req(queue_t *q, int proto)
{
	struct T_bind_req *tbr;
	mblk_t *mp;

	mp = allocb(sizeof (struct T_bind_req) + 1, BPRI_HI);
	if (mp == NULL) {
		/* cmn_err(CE_WARN, */
		/* "sadb_t_bind_req(%d): couldn't allocate mblk\n", proto); */
		return (B_FALSE);
	}
	mp->b_datap->db_type = M_PCPROTO;
	tbr = (struct T_bind_req *)mp->b_rptr;
	mp->b_wptr += sizeof (struct T_bind_req);
	tbr->PRIM_type = T_BIND_REQ;
	tbr->ADDR_length = 0;
	tbr->ADDR_offset = 0;
	tbr->CONIND_number = 0;
	*mp->b_wptr = (uint8_t)proto;
	mp->b_wptr++;

	putnext(q, mp);
	return (B_TRUE);
}

/*
 * Special front-end to ipsec_rl_strlog() dealing with SA failure.
 * this is designed to take only a format string with "* %x * %s *", so
 * that "spi" is printed first, then "addr" is converted using inet_pton().
 *
 * This is abstracted out to save the stack space for only when inet_pton()
 * is called.  Make sure "spi" is in network order; it usually is when this
 * would get called.
 */
void
ipsec_assocfailure(short mid, short sid, char level, ushort_t sl, char *fmt,
    uint32_t spi, void *addr, int af, netstack_t *ns)
{
	char buf[INET6_ADDRSTRLEN];

	ASSERT(af == AF_INET6 || af == AF_INET);

	ipsec_rl_strlog(ns, mid, sid, level, sl, fmt, ntohl(spi),
	    inet_ntop(af, addr, buf, sizeof (buf)));
}

/*
 * Fills in a reference to the policy, if any, from the conn, in *ppp
 * Releases a reference to the passed conn_t.
 */
static void
ipsec_conn_pol(ipsec_selector_t *sel, conn_t *connp, ipsec_policy_t **ppp)
{
	ipsec_policy_t	*pp;
	ipsec_latch_t	*ipl = connp->conn_latch;

	if ((ipl != NULL) && (ipl->ipl_out_policy != NULL)) {
		pp = ipl->ipl_out_policy;
		IPPOL_REFHOLD(pp);
	} else {
		pp = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, NULL, sel,
		    connp->conn_netstack);
	}
	*ppp = pp;
	CONN_DEC_REF(connp);
}

/*
 * The following functions scan through active conn_t structures
 * and return a reference to the best-matching policy it can find.
 * Caller must release the reference.
 */
static void
ipsec_udp_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp, ip_stack_t *ipst)
{
	connf_t *connfp;
	conn_t *connp = NULL;
	ipsec_selector_t portonly;

	bzero((void*)&portonly, sizeof (portonly));

	if (sel->ips_local_port == 0)
		return;

	connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(sel->ips_local_port,
	    ipst)];
	mutex_enter(&connfp->connf_lock);

	if (sel->ips_isv4) {
		connp = connfp->connf_head;
		while (connp != NULL) {
			if (IPCL_UDP_MATCH(connp, sel->ips_local_port,
			    sel->ips_local_addr_v4, sel->ips_remote_port,
			    sel->ips_remote_addr_v4))
				break;
			connp = connp->conn_next;
		}

		if (connp == NULL) {
			/* Try port-only match in IPv6. */
			portonly.ips_local_port = sel->ips_local_port;
			sel = &portonly;
		}
	}

	if (connp == NULL) {
		connp = connfp->connf_head;
		while (connp != NULL) {
			if (IPCL_UDP_MATCH_V6(connp, sel->ips_local_port,
			    sel->ips_local_addr_v6, sel->ips_remote_port,
			    sel->ips_remote_addr_v6))
				break;
			connp = connp->conn_next;
		}

		if (connp == NULL) {
			mutex_exit(&connfp->connf_lock);
			return;
		}
	}

	CONN_INC_REF(connp);
	mutex_exit(&connfp->connf_lock);

	ipsec_conn_pol(sel, connp, ppp);
}

static conn_t *
ipsec_find_listen_conn(uint16_t *pptr, ipsec_selector_t *sel, ip_stack_t *ipst)
{
	connf_t *connfp;
	conn_t *connp = NULL;
	const in6_addr_t *v6addrmatch = &sel->ips_local_addr_v6;

	if (sel->ips_local_port == 0)
		return (NULL);

	connfp = &ipst->ips_ipcl_bind_fanout[
	    IPCL_BIND_HASH(sel->ips_local_port, ipst)];
	mutex_enter(&connfp->connf_lock);

	if (sel->ips_isv4) {
		connp = connfp->connf_head;
		while (connp != NULL) {
			if (IPCL_BIND_MATCH(connp, IPPROTO_TCP,
			    sel->ips_local_addr_v4, pptr[1]))
				break;
			connp = connp->conn_next;
		}

		if (connp == NULL) {
			/* Match to all-zeroes. */
			v6addrmatch = &ipv6_all_zeros;
		}
	}

	if (connp == NULL) {
		connp = connfp->connf_head;
		while (connp != NULL) {
			if (IPCL_BIND_MATCH_V6(connp, IPPROTO_TCP,
			    *v6addrmatch, pptr[1]))
				break;
			connp = connp->conn_next;
		}

		if (connp == NULL) {
			mutex_exit(&connfp->connf_lock);
			return (NULL);
		}
	}

	CONN_INC_REF(connp);
	mutex_exit(&connfp->connf_lock);
	return (connp);
}

static void
ipsec_tcp_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp, ip_stack_t *ipst)
{
	connf_t 	*connfp;
	conn_t		*connp;
	uint32_t	ports;
	uint16_t	*pptr = (uint16_t *)&ports;

	/*
	 * Find TCP state in the following order:
	 * 1.) Connected conns.
	 * 2.) Listeners.
	 *
	 * Even though #2 will be the common case for inbound traffic, only
	 * following this order insures correctness.
	 */

	if (sel->ips_local_port == 0)
		return;

	/*
	 * 0 should be fport, 1 should be lport.  SRC is the local one here.
	 * See ipsec_construct_inverse_acquire() for details.
	 */
	pptr[0] = sel->ips_remote_port;
	pptr[1] = sel->ips_local_port;

	connfp = &ipst->ips_ipcl_conn_fanout[
	    IPCL_CONN_HASH(sel->ips_remote_addr_v4, ports, ipst)];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;

	if (sel->ips_isv4) {
		while (connp != NULL) {
			if (IPCL_CONN_MATCH(connp, IPPROTO_TCP,
			    sel->ips_remote_addr_v4, sel->ips_local_addr_v4,
			    ports))
				break;
			connp = connp->conn_next;
		}
	} else {
		while (connp != NULL) {
			if (IPCL_CONN_MATCH_V6(connp, IPPROTO_TCP,
			    sel->ips_remote_addr_v6, sel->ips_local_addr_v6,
			    ports))
				break;
			connp = connp->conn_next;
		}
	}

	if (connp != NULL) {
		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
	} else {
		mutex_exit(&connfp->connf_lock);

		/* Try the listen hash. */
		if ((connp = ipsec_find_listen_conn(pptr, sel, ipst)) == NULL)
			return;
	}

	ipsec_conn_pol(sel, connp, ppp);
}

static void
ipsec_sctp_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp,
    ip_stack_t *ipst)
{
	conn_t		*connp;
	uint32_t	ports;
	uint16_t	*pptr = (uint16_t *)&ports;

	/*
	 * Find SCP state in the following order:
	 * 1.) Connected conns.
	 * 2.) Listeners.
	 *
	 * Even though #2 will be the common case for inbound traffic, only
	 * following this order insures correctness.
	 */

	if (sel->ips_local_port == 0)
		return;

	/*
	 * 0 should be fport, 1 should be lport.  SRC is the local one here.
	 * See ipsec_construct_inverse_acquire() for details.
	 */
	pptr[0] = sel->ips_remote_port;
	pptr[1] = sel->ips_local_port;

	if (sel->ips_isv4) {
		in6_addr_t	src, dst;

		IN6_IPADDR_TO_V4MAPPED(sel->ips_remote_addr_v4, &dst);
		IN6_IPADDR_TO_V4MAPPED(sel->ips_local_addr_v4, &src);
		connp = sctp_find_conn(&dst, &src, ports, ALL_ZONES,
		    ipst->ips_netstack->netstack_sctp);
	} else {
		connp = sctp_find_conn(&sel->ips_remote_addr_v6,
		    &sel->ips_local_addr_v6, ports, ALL_ZONES,
		    ipst->ips_netstack->netstack_sctp);
	}
	if (connp == NULL)
		return;
	ipsec_conn_pol(sel, connp, ppp);
}

/*
 * Fill in a query for the SPD (in "sel") using two PF_KEY address extensions.
 * Returns 0 or errno, and always sets *diagnostic to something appropriate
 * to PF_KEY.
 *
 * NOTE:  For right now, this function (and ipsec_selector_t for that matter),
 * ignore prefix lengths in the address extension.  Since we match on first-
 * entered policies, this shouldn't matter.  Also, since we normalize prefix-
 * set addresses to mask out the lower bits, we should get a suitable search
 * key for the SPD anyway.  This is the function to change if the assumption
 * about suitable search keys is wrong.
 */
static int
ipsec_get_inverse_acquire_sel(ipsec_selector_t *sel, sadb_address_t *srcext,
    sadb_address_t *dstext, int *diagnostic)
{
	struct sockaddr_in *src, *dst;
	struct sockaddr_in6 *src6, *dst6;

	*diagnostic = 0;

	bzero(sel, sizeof (*sel));
	sel->ips_protocol = srcext->sadb_address_proto;
	dst = (struct sockaddr_in *)(dstext + 1);
	if (dst->sin_family == AF_INET6) {
		dst6 = (struct sockaddr_in6 *)dst;
		src6 = (struct sockaddr_in6 *)(srcext + 1);
		if (src6->sin6_family != AF_INET6) {
			*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
			return (EINVAL);
		}
		sel->ips_remote_addr_v6 = dst6->sin6_addr;
		sel->ips_local_addr_v6 = src6->sin6_addr;
		if (sel->ips_protocol == IPPROTO_ICMPV6) {
			sel->ips_is_icmp_inv_acq = 1;
		} else {
			sel->ips_remote_port = dst6->sin6_port;
			sel->ips_local_port = src6->sin6_port;
		}
		sel->ips_isv4 = B_FALSE;
	} else {
		src = (struct sockaddr_in *)(srcext + 1);
		if (src->sin_family != AF_INET) {
			*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
			return (EINVAL);
		}
		sel->ips_remote_addr_v4 = dst->sin_addr.s_addr;
		sel->ips_local_addr_v4 = src->sin_addr.s_addr;
		if (sel->ips_protocol == IPPROTO_ICMP) {
			sel->ips_is_icmp_inv_acq = 1;
		} else {
			sel->ips_remote_port = dst->sin_port;
			sel->ips_local_port = src->sin_port;
		}
		sel->ips_isv4 = B_TRUE;
	}
	return (0);
}

/*
 * We have encapsulation.
 * - Lookup tun_t by address and look for an associated
 *   tunnel policy
 * - If there are inner selectors
 *   - check ITPF_P_TUNNEL and ITPF_P_ACTIVE
 *   - Look up tunnel policy based on selectors
 * - Else
 *   - Sanity check the negotation
 *   - If appropriate, fall through to global policy
 */
static int
ipsec_tun_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp,
    sadb_address_t *innsrcext, sadb_address_t *inndstext, ipsec_tun_pol_t *itp,
    int *diagnostic, netstack_t *ns)
{
	int err;
	ipsec_policy_head_t *polhead;

	/* Check for inner selectors and act appropriately */

	if (innsrcext != NULL) {
		/* Inner selectors present */
		ASSERT(inndstext != NULL);
		if ((itp == NULL) ||
		    (itp->itp_flags & (ITPF_P_ACTIVE | ITPF_P_TUNNEL)) !=
		    (ITPF_P_ACTIVE | ITPF_P_TUNNEL)) {
			/*
			 * If inner packet selectors, we must have negotiate
			 * tunnel and active policy.  If the tunnel has
			 * transport-mode policy set on it, or has no policy,
			 * fail.
			 */
			return (ENOENT);
		} else {
			/*
			 * Reset "sel" to indicate inner selectors.  Pass
			 * inner PF_KEY address extensions for this to happen.
			 */
			err = ipsec_get_inverse_acquire_sel(sel,
			    innsrcext, inndstext, diagnostic);
			if (err != 0) {
				ITP_REFRELE(itp, ns);
				return (err);
			}
			/*
			 * Now look for a tunnel policy based on those inner
			 * selectors.  (Common code is below.)
			 */
		}
	} else {
		/* No inner selectors present */
		if ((itp == NULL) || !(itp->itp_flags & ITPF_P_ACTIVE)) {
			/*
			 * Transport mode negotiation with no tunnel policy
			 * configured - return to indicate a global policy
			 * check is needed.
			 */
			if (itp != NULL) {
				ITP_REFRELE(itp, ns);
			}
			return (0);
		} else if (itp->itp_flags & ITPF_P_TUNNEL) {
			/* Tunnel mode set with no inner selectors. */
			ITP_REFRELE(itp, ns);
			return (ENOENT);
		}
		/*
		 * Else, this is a tunnel policy configured with ifconfig(1m)
		 * or "negotiate transport" with ipsecconf(1m).  We have an
		 * itp with policy set based on any match, so don't bother
		 * changing fields in "sel".
		 */
	}

	ASSERT(itp != NULL);
	polhead = itp->itp_policy;
	ASSERT(polhead != NULL);
	rw_enter(&polhead->iph_lock, RW_READER);
	*ppp = ipsec_find_policy_head(NULL, polhead,
	    IPSEC_TYPE_INBOUND, sel, ns);
	rw_exit(&polhead->iph_lock);
	ITP_REFRELE(itp, ns);

	/*
	 * Don't default to global if we didn't find a matching policy entry.
	 * Instead, send ENOENT, just like if we hit a transport-mode tunnel.
	 */
	if (*ppp == NULL)
		return (ENOENT);

	return (0);
}

static void
ipsec_oth_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp,
    ip_stack_t *ipst)
{
	boolean_t	isv4 = sel->ips_isv4;
	connf_t		*connfp;
	conn_t		*connp;

	if (isv4) {
		connfp = &ipst->ips_ipcl_proto_fanout[sel->ips_protocol];
	} else {
		connfp = &ipst->ips_ipcl_proto_fanout_v6[sel->ips_protocol];
	}

	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		if (!((isv4 && !((connp->conn_src == 0 ||
		    connp->conn_src == sel->ips_local_addr_v4) &&
		    (connp->conn_rem == 0 ||
		    connp->conn_rem == sel->ips_remote_addr_v4))) ||
		    (!isv4 && !((IN6_IS_ADDR_UNSPECIFIED(&connp->conn_srcv6) ||
		    IN6_ARE_ADDR_EQUAL(&connp->conn_srcv6,
		    &sel->ips_local_addr_v6)) &&
		    (IN6_IS_ADDR_UNSPECIFIED(&connp->conn_remv6) ||
		    IN6_ARE_ADDR_EQUAL(&connp->conn_remv6,
		    &sel->ips_remote_addr_v6)))))) {
			break;
		}
	}
	if (connp == NULL) {
		mutex_exit(&connfp->connf_lock);
		return;
	}

	CONN_INC_REF(connp);
	mutex_exit(&connfp->connf_lock);

	ipsec_conn_pol(sel, connp, ppp);
}

/*
 * Construct an inverse ACQUIRE reply based on:
 *
 * 1.) Current global policy.
 * 2.) An conn_t match depending on what all was passed in the extv[].
 * 3.) A tunnel's policy head.
 * ...
 * N.) Other stuff TBD (e.g. identities)
 *
 * If there is an error, set sadb_msg_errno and sadb_x_msg_diagnostic
 * in this function so the caller can extract them where appropriately.
 *
 * The SRC address is the local one - just like an outbound ACQUIRE message.
 */
mblk_t *
ipsec_construct_inverse_acquire(sadb_msg_t *samsg, sadb_ext_t *extv[],
    netstack_t *ns)
{
	int err;
	int diagnostic;
	sadb_address_t *srcext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_SRC],
	    *dstext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_DST],
	    *innsrcext = (sadb_address_t *)extv[SADB_X_EXT_ADDRESS_INNER_SRC],
	    *inndstext = (sadb_address_t *)extv[SADB_X_EXT_ADDRESS_INNER_DST];
	struct sockaddr_in6 *src, *dst;
	struct sockaddr_in6 *isrc, *idst;
	ipsec_tun_pol_t *itp = NULL;
	ipsec_policy_t *pp = NULL;
	ipsec_selector_t sel, isel;
	mblk_t *retmp;
	ip_stack_t	*ipst = ns->netstack_ip;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	/* Normalize addresses */
	if (sadb_addrcheck(NULL, (mblk_t *)samsg, (sadb_ext_t *)srcext, 0, ns)
	    == KS_IN_ADDR_UNKNOWN) {
		err = EINVAL;
		diagnostic = SADB_X_DIAGNOSTIC_BAD_SRC;
		goto bail;
	}
	src = (struct sockaddr_in6 *)(srcext + 1);
	if (sadb_addrcheck(NULL, (mblk_t *)samsg, (sadb_ext_t *)dstext, 0, ns)
	    == KS_IN_ADDR_UNKNOWN) {
		err = EINVAL;
		diagnostic = SADB_X_DIAGNOSTIC_BAD_DST;
		goto bail;
	}
	dst = (struct sockaddr_in6 *)(dstext + 1);
	if (src->sin6_family != dst->sin6_family) {
		err = EINVAL;
		diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
		goto bail;
	}

	/* Check for tunnel mode and act appropriately */
	if (innsrcext != NULL) {
		if (inndstext == NULL) {
			err = EINVAL;
			diagnostic = SADB_X_DIAGNOSTIC_MISSING_INNER_DST;
			goto bail;
		}
		if (sadb_addrcheck(NULL, (mblk_t *)samsg,
		    (sadb_ext_t *)innsrcext, 0, ns) == KS_IN_ADDR_UNKNOWN) {
			err = EINVAL;
			diagnostic = SADB_X_DIAGNOSTIC_MALFORMED_INNER_SRC;
			goto bail;
		}
		isrc = (struct sockaddr_in6 *)(innsrcext + 1);
		if (sadb_addrcheck(NULL, (mblk_t *)samsg,
		    (sadb_ext_t *)inndstext, 0, ns) == KS_IN_ADDR_UNKNOWN) {
			err = EINVAL;
			diagnostic = SADB_X_DIAGNOSTIC_MALFORMED_INNER_DST;
			goto bail;
		}
		idst = (struct sockaddr_in6 *)(inndstext + 1);
		if (isrc->sin6_family != idst->sin6_family) {
			err = EINVAL;
			diagnostic = SADB_X_DIAGNOSTIC_INNER_AF_MISMATCH;
			goto bail;
		}
		if (isrc->sin6_family != AF_INET &&
		    isrc->sin6_family != AF_INET6) {
			err = EINVAL;
			diagnostic = SADB_X_DIAGNOSTIC_BAD_INNER_SRC_AF;
			goto bail;
		}
	} else if (inndstext != NULL) {
		err = EINVAL;
		diagnostic = SADB_X_DIAGNOSTIC_MISSING_INNER_SRC;
		goto bail;
	}

	/* Get selectors first, based on outer addresses */
	err = ipsec_get_inverse_acquire_sel(&sel, srcext, dstext, &diagnostic);
	if (err != 0)
		goto bail;

	/* Check for tunnel mode mismatches. */
	if (innsrcext != NULL &&
	    ((isrc->sin6_family == AF_INET &&
	    sel.ips_protocol != IPPROTO_ENCAP && sel.ips_protocol != 0) ||
	    (isrc->sin6_family == AF_INET6 &&
	    sel.ips_protocol != IPPROTO_IPV6 && sel.ips_protocol != 0))) {
		err = EPROTOTYPE;
		goto bail;
	}

	/*
	 * Okay, we have the addresses and other selector information.
	 * Let's first find a conn...
	 */
	pp = NULL;
	switch (sel.ips_protocol) {
	case IPPROTO_TCP:
		ipsec_tcp_pol(&sel, &pp, ipst);
		break;
	case IPPROTO_UDP:
		ipsec_udp_pol(&sel, &pp, ipst);
		break;
	case IPPROTO_SCTP:
		ipsec_sctp_pol(&sel, &pp, ipst);
		break;
	case IPPROTO_ENCAP:
	case IPPROTO_IPV6:
		rw_enter(&ipss->ipsec_itp_get_byaddr_rw_lock, RW_READER);
		/*
		 * Assume sel.ips_remote_addr_* has the right address at
		 * that exact position.
		 */
		itp = ipss->ipsec_itp_get_byaddr(
		    (uint32_t *)(&sel.ips_local_addr_v6),
		    (uint32_t *)(&sel.ips_remote_addr_v6),
		    src->sin6_family, ns);
		rw_exit(&ipss->ipsec_itp_get_byaddr_rw_lock);
		if (innsrcext == NULL) {
			/*
			 * Transport-mode tunnel, make sure we fake out isel
			 * to contain something based on the outer protocol.
			 */
			bzero(&isel, sizeof (isel));
			isel.ips_isv4 = (sel.ips_protocol == IPPROTO_ENCAP);
		} /* Else isel is initialized by ipsec_tun_pol(). */
		err = ipsec_tun_pol(&isel, &pp, innsrcext, inndstext, itp,
		    &diagnostic, ns);
		/*
		 * NOTE:  isel isn't used for now, but in RFC 430x IPsec, it
		 * may be.
		 */
		if (err != 0)
			goto bail;
		break;
	default:
		ipsec_oth_pol(&sel, &pp, ipst);
		break;
	}

	/*
	 * If we didn't find a matching conn_t or other policy head, take a
	 * look in the global policy.
	 */
	if (pp == NULL) {
		pp = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, NULL, NULL, &sel,
		    ns);
		if (pp == NULL) {
			/* There's no global policy. */
			err = ENOENT;
			diagnostic = 0;
			goto bail;
		}
	}

	/*
	 * Now that we have a policy entry/widget, construct an ACQUIRE
	 * message based on that, fix fields where appropriate,
	 * and return the message.
	 */
	retmp = sadb_extended_acquire(&sel, pp, NULL,
	    (itp != NULL && (itp->itp_flags & ITPF_P_TUNNEL)),
	    samsg->sadb_msg_seq, samsg->sadb_msg_pid, ns);
	if (pp != NULL) {
		IPPOL_REFRELE(pp, ns);
	}
	if (retmp != NULL) {
		return (retmp);
	} else {
		err = ENOMEM;
		diagnostic = 0;
	}
bail:
	samsg->sadb_msg_errno = (uint8_t)err;
	samsg->sadb_x_msg_diagnostic = (uint16_t)diagnostic;
	return (NULL);
}

/*
 * ipsa_lpkt is a one-element queue, only manipulated by casptr within
 * the next two functions.
 *
 * These functions loop calling casptr() until the swap "happens",
 * turning a compare-and-swap op into an atomic swap operation.
 */

/*
 * sadb_set_lpkt: Atomically swap in a value to ipsa->ipsa_lpkt and
 * freemsg the previous value.  free clue: freemsg(NULL) is safe.
 */

void
sadb_set_lpkt(ipsa_t *ipsa, mblk_t *npkt, netstack_t *ns)
{
	mblk_t *opkt;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	membar_producer();
	do {
		opkt = ipsa->ipsa_lpkt;
	} while (casptr(&ipsa->ipsa_lpkt, opkt, npkt) != opkt);

	ip_drop_packet(opkt, B_TRUE, NULL, NULL,
	    DROPPER(ipss, ipds_sadb_inlarval_replace),
	    &ipss->ipsec_sadb_dropper);
}

/*
 * sadb_clear_lpkt: Atomically clear ipsa->ipsa_lpkt and return the
 * previous value.
 */

mblk_t *
sadb_clear_lpkt(ipsa_t *ipsa)
{
	mblk_t *opkt;

	do {
		opkt = ipsa->ipsa_lpkt;
	} while (casptr(&ipsa->ipsa_lpkt, opkt, NULL) != opkt);

	return (opkt);
}

/*
 * Walker callback used by sadb_alg_update() to free/create crypto
 * context template when a crypto software provider is removed or
 * added.
 */

struct sadb_update_alg_state {
	ipsec_algtype_t alg_type;
	uint8_t alg_id;
	boolean_t is_added;
};

static void
sadb_alg_update_cb(isaf_t *head, ipsa_t *entry, void *cookie)
{
	struct sadb_update_alg_state *update_state =
	    (struct sadb_update_alg_state *)cookie;
	crypto_ctx_template_t *ctx_tmpl = NULL;

	ASSERT(MUTEX_HELD(&head->isaf_lock));

	if (entry->ipsa_state == IPSA_STATE_LARVAL)
		return;

	mutex_enter(&entry->ipsa_lock);

	switch (update_state->alg_type) {
	case IPSEC_ALG_AUTH:
		if (entry->ipsa_auth_alg == update_state->alg_id)
			ctx_tmpl = &entry->ipsa_authtmpl;
		break;
	case IPSEC_ALG_ENCR:
		if (entry->ipsa_encr_alg == update_state->alg_id)
			ctx_tmpl = &entry->ipsa_encrtmpl;
		break;
	default:
		ctx_tmpl = NULL;
	}

	if (ctx_tmpl == NULL) {
		mutex_exit(&entry->ipsa_lock);
		return;
	}

	/*
	 * The context template of the SA may be affected by the change
	 * of crypto provider.
	 */
	if (update_state->is_added) {
		/* create the context template if not already done */
		if (*ctx_tmpl == NULL) {
			(void) ipsec_create_ctx_tmpl(entry,
			    update_state->alg_type);
		}
	} else {
		/*
		 * The crypto provider was removed. If the context template
		 * exists but it is no longer valid, free it.
		 */
		if (*ctx_tmpl != NULL)
			ipsec_destroy_ctx_tmpl(entry, update_state->alg_type);
	}

	mutex_exit(&entry->ipsa_lock);
}

/*
 * Invoked by IP when an software crypto provider has been updated.
 * The type and id of the corresponding algorithm is passed as argument.
 * is_added is B_TRUE if the provider was added, B_FALSE if it was
 * removed. The function updates the SADB and free/creates the
 * context templates associated with SAs if needed.
 */

#define	SADB_ALG_UPDATE_WALK(sadb, table) \
    sadb_walker((sadb).table, (sadb).sdb_hashsize, sadb_alg_update_cb, \
	&update_state)

void
sadb_alg_update(ipsec_algtype_t alg_type, uint8_t alg_id, boolean_t is_added,
    netstack_t *ns)
{
	struct sadb_update_alg_state update_state;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsecesp_stack_t	*espstack = ns->netstack_ipsecesp;

	update_state.alg_type = alg_type;
	update_state.alg_id = alg_id;
	update_state.is_added = is_added;

	if (alg_type == IPSEC_ALG_AUTH) {
		/* walk the AH tables only for auth. algorithm changes */
		SADB_ALG_UPDATE_WALK(ahstack->ah_sadb.s_v4, sdb_of);
		SADB_ALG_UPDATE_WALK(ahstack->ah_sadb.s_v4, sdb_if);
		SADB_ALG_UPDATE_WALK(ahstack->ah_sadb.s_v6, sdb_of);
		SADB_ALG_UPDATE_WALK(ahstack->ah_sadb.s_v6, sdb_if);
	}

	/* walk the ESP tables */
	SADB_ALG_UPDATE_WALK(espstack->esp_sadb.s_v4, sdb_of);
	SADB_ALG_UPDATE_WALK(espstack->esp_sadb.s_v4, sdb_if);
	SADB_ALG_UPDATE_WALK(espstack->esp_sadb.s_v6, sdb_of);
	SADB_ALG_UPDATE_WALK(espstack->esp_sadb.s_v6, sdb_if);
}

/*
 * Creates a context template for the specified SA. This function
 * is called when an SA is created and when a context template needs
 * to be created due to a change of software provider.
 */
int
ipsec_create_ctx_tmpl(ipsa_t *sa, ipsec_algtype_t alg_type)
{
	ipsec_alginfo_t *alg;
	crypto_mechanism_t mech;
	crypto_key_t *key;
	crypto_ctx_template_t *sa_tmpl;
	int rv;
	ipsec_stack_t	*ipss = sa->ipsa_netstack->netstack_ipsec;

	ASSERT(MUTEX_HELD(&ipss->ipsec_alg_lock));
	ASSERT(MUTEX_HELD(&sa->ipsa_lock));

	/* get pointers to the algorithm info, context template, and key */
	switch (alg_type) {
	case IPSEC_ALG_AUTH:
		key = &sa->ipsa_kcfauthkey;
		sa_tmpl = &sa->ipsa_authtmpl;
		alg = ipss->ipsec_alglists[alg_type][sa->ipsa_auth_alg];
		break;
	case IPSEC_ALG_ENCR:
		key = &sa->ipsa_kcfencrkey;
		sa_tmpl = &sa->ipsa_encrtmpl;
		alg = ipss->ipsec_alglists[alg_type][sa->ipsa_encr_alg];
		break;
	default:
		alg = NULL;
	}

	if (alg == NULL || !ALG_VALID(alg))
		return (EINVAL);

	/* initialize the mech info structure for the framework */
	ASSERT(alg->alg_mech_type != CRYPTO_MECHANISM_INVALID);
	mech.cm_type = alg->alg_mech_type;
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* create a new context template */
	rv = crypto_create_ctx_template(&mech, key, sa_tmpl, KM_NOSLEEP);

	/*
	 * CRYPTO_MECH_NOT_SUPPORTED can be returned if only hardware
	 * providers are available for that mechanism. In that case
	 * we don't fail, and will generate the context template from
	 * the framework callback when a software provider for that
	 * mechanism registers.
	 *
	 * The context template is assigned the special value
	 * IPSEC_CTX_TMPL_ALLOC if the allocation failed due to a
	 * lack of memory. No attempt will be made to use
	 * the context template if it is set to this value.
	 */
	if (rv == CRYPTO_HOST_MEMORY) {
		*sa_tmpl = IPSEC_CTX_TMPL_ALLOC;
	} else if (rv != CRYPTO_SUCCESS) {
		*sa_tmpl = NULL;
		if (rv != CRYPTO_MECH_NOT_SUPPORTED)
			return (EINVAL);
	}

	return (0);
}

/*
 * Destroy the context template of the specified algorithm type
 * of the specified SA. Must be called while holding the SA lock.
 */
void
ipsec_destroy_ctx_tmpl(ipsa_t *sa, ipsec_algtype_t alg_type)
{
	ASSERT(MUTEX_HELD(&sa->ipsa_lock));

	if (alg_type == IPSEC_ALG_AUTH) {
		if (sa->ipsa_authtmpl == IPSEC_CTX_TMPL_ALLOC)
			sa->ipsa_authtmpl = NULL;
		else if (sa->ipsa_authtmpl != NULL) {
			crypto_destroy_ctx_template(sa->ipsa_authtmpl);
			sa->ipsa_authtmpl = NULL;
		}
	} else {
		ASSERT(alg_type == IPSEC_ALG_ENCR);
		if (sa->ipsa_encrtmpl == IPSEC_CTX_TMPL_ALLOC)
			sa->ipsa_encrtmpl = NULL;
		else if (sa->ipsa_encrtmpl != NULL) {
			crypto_destroy_ctx_template(sa->ipsa_encrtmpl);
			sa->ipsa_encrtmpl = NULL;
		}
	}
}

/*
 * Use the kernel crypto framework to check the validity of a key received
 * via keysock. Returns 0 if the key is OK, -1 otherwise.
 */
int
ipsec_check_key(crypto_mech_type_t mech_type, sadb_key_t *sadb_key,
    boolean_t is_auth, int *diag)
{
	crypto_mechanism_t mech;
	crypto_key_t crypto_key;
	int crypto_rc;

	mech.cm_type = mech_type;
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	crypto_key.ck_format = CRYPTO_KEY_RAW;
	crypto_key.ck_data = sadb_key + 1;
	crypto_key.ck_length = sadb_key->sadb_key_bits;

	crypto_rc = crypto_key_check(&mech, &crypto_key);

	switch (crypto_rc) {
	case CRYPTO_SUCCESS:
		return (0);
	case CRYPTO_MECHANISM_INVALID:
	case CRYPTO_MECH_NOT_SUPPORTED:
		*diag = is_auth ? SADB_X_DIAGNOSTIC_BAD_AALG :
		    SADB_X_DIAGNOSTIC_BAD_EALG;
		break;
	case CRYPTO_KEY_SIZE_RANGE:
		*diag = is_auth ? SADB_X_DIAGNOSTIC_BAD_AKEYBITS :
		    SADB_X_DIAGNOSTIC_BAD_EKEYBITS;
		break;
	case CRYPTO_WEAK_KEY:
		*diag = is_auth ? SADB_X_DIAGNOSTIC_WEAK_AKEY :
		    SADB_X_DIAGNOSTIC_WEAK_EKEY;
		break;
	}

	return (-1);
}
/*
 * If this is an outgoing SA then add some fuzz to the
 * SOFT EXPIRE time. The reason for this is to stop
 * peers trying to renegotiate SOFT expiring SA's at
 * the same time. The amount of fuzz needs to be at
 * least 10 seconds which is the typical interval
 * sadb_ager(), although this is only a guide as it
 * selftunes.
 */
void
lifetime_fuzz(ipsa_t *assoc)
{
	uint8_t rnd;

	if (assoc->ipsa_softaddlt == 0)
		return;

	(void) random_get_pseudo_bytes(&rnd, sizeof (rnd));
	rnd = (rnd & 0xF) + 10;
	assoc->ipsa_softexpiretime -= rnd;
	assoc->ipsa_softaddlt -= rnd;
}
void
destroy_ipsa_pair(ipsap_t *ipsapp)
{
	if (ipsapp == NULL)
		return;

	/*
	 * Because of the multi-line macro nature of IPSA_REFRELE, keep
	 * them in { }.
	 */
	if (ipsapp->ipsap_sa_ptr != NULL) {
		IPSA_REFRELE(ipsapp->ipsap_sa_ptr);
	}
	if (ipsapp->ipsap_psa_ptr != NULL) {
		IPSA_REFRELE(ipsapp->ipsap_psa_ptr);
	}

	kmem_free(ipsapp, sizeof (*ipsapp));
}

/*
 * The sadb_ager() function walks through the hash tables of SA's and ages
 * them, if the SA expires as a result, its marked as DEAD and will be reaped
 * the next time sadb_ager() runs. SA's which are paired or have a peer (same
 * SA appears in both the inbound and outbound tables because its not possible
 * to determine its direction) are placed on a list when they expire. This is
 * to ensure that pair/peer SA's are reaped at the same time, even if they
 * expire at different times.
 *
 * This function is called twice by sadb_ager(), one after processing the
 * inbound table, then again after processing the outbound table.
 */
void
age_pair_peer_list(templist_t *haspeerlist, sadb_t *sp, boolean_t outbound)
{
	templist_t *listptr;
	int outhash;
	isaf_t *bucket;
	boolean_t haspeer;
	ipsa_t *peer_assoc, *dying;
	/*
	 * Haspeer cases will contain both IPv4 and IPv6.  This code
	 * is address independent.
	 */
	while (haspeerlist != NULL) {
		/* "dying" contains the SA that has a peer. */
		dying = haspeerlist->ipsa;
		haspeer = (dying->ipsa_haspeer);
		listptr = haspeerlist;
		haspeerlist = listptr->next;
		kmem_free(listptr, sizeof (*listptr));
		/*
		 * Pick peer bucket based on addrfam.
		 */
		if (outbound) {
			if (haspeer)
				bucket = INBOUND_BUCKET(sp, dying->ipsa_spi);
			else
				bucket = INBOUND_BUCKET(sp,
				    dying->ipsa_otherspi);
		} else { /* inbound */
			if (haspeer) {
				if (dying->ipsa_addrfam == AF_INET6) {
					outhash = OUTBOUND_HASH_V6(sp,
					    *((in6_addr_t *)&dying->
					    ipsa_dstaddr));
				} else {
					outhash = OUTBOUND_HASH_V4(sp,
					    *((ipaddr_t *)&dying->
					    ipsa_dstaddr));
				}
			} else if (dying->ipsa_addrfam == AF_INET6) {
				outhash = OUTBOUND_HASH_V6(sp,
				    *((in6_addr_t *)&dying->
				    ipsa_srcaddr));
			} else {
				outhash = OUTBOUND_HASH_V4(sp,
				    *((ipaddr_t *)&dying->
				    ipsa_srcaddr));
			}
		bucket = &(sp->sdb_of[outhash]);
		}

		mutex_enter(&bucket->isaf_lock);
		/*
		 * "haspeer" SA's have the same src/dst address ordering,
		 * "paired" SA's have the src/dst addresses reversed.
		 */
		if (haspeer) {
			peer_assoc = ipsec_getassocbyspi(bucket,
			    dying->ipsa_spi, dying->ipsa_srcaddr,
			    dying->ipsa_dstaddr, dying->ipsa_addrfam);
		} else {
			peer_assoc = ipsec_getassocbyspi(bucket,
			    dying->ipsa_otherspi, dying->ipsa_dstaddr,
			    dying->ipsa_srcaddr, dying->ipsa_addrfam);
		}

		mutex_exit(&bucket->isaf_lock);
		if (peer_assoc != NULL) {
			mutex_enter(&peer_assoc->ipsa_lock);
			mutex_enter(&dying->ipsa_lock);
			if (!haspeer) {
				/*
				 * Only SA's which have a "peer" or are
				 * "paired" end up on this list, so this
				 * must be a "paired" SA, update the flags
				 * to break the pair.
				 */
				peer_assoc->ipsa_otherspi = 0;
				peer_assoc->ipsa_flags &= ~IPSA_F_PAIRED;
				dying->ipsa_otherspi = 0;
				dying->ipsa_flags &= ~IPSA_F_PAIRED;
			}
			if (haspeer || outbound) {
				/*
				 * Update the state of the "inbound" SA when
				 * the "outbound" SA has expired. Don't update
				 * the "outbound" SA when the "inbound" SA
				 * SA expires because setting the hard_addtime
				 * below will cause this to happen.
				 */
				peer_assoc->ipsa_state = dying->ipsa_state;
			}
			if (dying->ipsa_state == IPSA_STATE_DEAD)
				peer_assoc->ipsa_hardexpiretime = 1;

			mutex_exit(&dying->ipsa_lock);
			mutex_exit(&peer_assoc->ipsa_lock);
			IPSA_REFRELE(peer_assoc);
		}
		IPSA_REFRELE(dying);
	}
}
