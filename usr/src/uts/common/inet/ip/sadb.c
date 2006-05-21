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

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
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
#include <inet/ip6.h>
#include <inet/ipsec_info.h>
#include <inet/ipsec_impl.h>
#include <inet/tcp.h>
#include <inet/sadb.h>
#include <inet/ipsecah.h>
#include <inet/ipsecesp.h>
#include <sys/random.h>
#include <sys/dlpi.h>
#include <sys/iphada.h>
#include <inet/ip_if.h>
#include <inet/ipdrop.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>

/*
 * This source file contains Security Association Database (SADB) common
 * routines.  They are linked in with the AH module.  Since AH has no chance
 * of falling under export control, it was safe to link it in there.
 */

/* Packet dropper for generic SADB drops. */
static ipdropper_t sadb_dropper;

static mblk_t *sadb_extended_acquire(ipsec_selector_t *, ipsec_policy_t *,
    ipsec_action_t *, uint32_t, uint32_t);
static void sadb_ill_df(ill_t *, mblk_t *, isaf_t *, int, boolean_t);
static ipsa_t *sadb_torch_assoc(isaf_t *, ipsa_t *, boolean_t, mblk_t **);
static void sadb_drain_torchq(queue_t *q, mblk_t *);
static void sadb_destroy_acqlist(iacqf_t **, uint_t, boolean_t);
static void sadb_destroy(sadb_t *sp);

static time_t sadb_add_time(time_t base, uint64_t delta);

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
			    ((walker->ipsa_unique_id &
				walker->ipsa_unique_mask) ==
				(ipsa->ipsa_unique_id &
				    ipsa->ipsa_unique_mask))) {
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

/*
 * Free a security association.  Its reference count is 0, which means
 * I must free it.  The SA must be unlocked and must not be linked into
 * any fanout list.
 */
static void
sadb_freeassoc(ipsa_t *ipsa)
{
	ASSERT(!MUTEX_HELD(&ipsa->ipsa_lock));
	ASSERT(ipsa->ipsa_refcnt == 0);
	ASSERT(ipsa->ipsa_next == NULL);
	ASSERT(ipsa->ipsa_ptpn == NULL);

	ip_drop_packet(sadb_clear_lpkt(ipsa), B_TRUE, NULL, NULL,
	    &ipdrops_sadb_inlarval_timeout, &sadb_dropper);

	mutex_enter(&ipsa->ipsa_lock);

	if (ipsa->ipsa_natt_ka_timer != 0)
		(void) quntimeout(ipsa->ipsa_natt_q, ipsa->ipsa_natt_ka_timer);

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
	if (ipsa->ipsa_proxy_cid != NULL) {
		IPSID_REFRELE(ipsa->ipsa_proxy_cid);
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
sadb_makelarvalassoc(uint32_t spi, uint32_t *src, uint32_t *dst, int addrfam)
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
sadb_init(const char *name, sadb_t *sp, uint_t size, uint_t ver)
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

		sadb_destroy(sp);
		size = IPSEC_DEFAULT_HASH_SIZE;
		cmn_err(CE_WARN, "Falling back to %d entries", size);
		(void) sadb_init_trial(sp, size, KM_SLEEP);
	}
}


/*
 * Initialize an SADB-pair.
 */
void
sadbp_init(const char *name, sadbp_t *sp, int type, int size)
{
	sadb_init(name, &sp->s_v4, size, 4);
	sadb_init(name, &sp->s_v6, size, 6);

	sp->s_satype = type;

	ASSERT((type == SADB_SATYPE_AH) || (type == SADB_SATYPE_ESP));
	if (type == SADB_SATYPE_AH)
		ip_drop_register(&sadb_dropper, "IPsec SADB");
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
			    walker)) {
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
	spp = (sa_type == SADB_SATYPE_ESP) ? &esp_sadb : &ah_sadb;

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
sadb_flush(sadb_t *sp)
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
	sadb_destroy_acqlist(&sp->sdb_acq, sp->sdb_hashsize, B_FALSE);
}

static void
sadb_destroy(sadb_t *sp)
{
	sadb_destroyer(&sp->sdb_of, sp->sdb_hashsize, B_TRUE);
	sadb_destroyer(&sp->sdb_if, sp->sdb_hashsize, B_TRUE);

	/* For each acquire, destroy it, including the bucket mutex. */
	sadb_destroy_acqlist(&sp->sdb_acq, sp->sdb_hashsize, B_TRUE);

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
sadbp_flush(sadbp_t *spp)
{
	sadb_flush(&spp->s_v4);
	sadb_flush(&spp->s_v6);

	sadb_send_flush_req(spp);
}

void
sadbp_destroy(sadbp_t *spp)
{
	sadb_destroy(&spp->s_v4);
	sadb_destroy(&spp->s_v6);

	sadb_send_flush_req(spp);
	if (spp->s_satype == SADB_SATYPE_AH)
		ip_drop_unregister(&sadb_dropper);
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
 * into inbound and outbound tables respectively.
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

#if 0 /* XXX PROXY  - Proxy identities not supported yet. */
	if (ipsa->ipsa_proxy_cid != NULL) {
		newbie->ipsa_proxy_cid = ipsa->ipsa_proxy_cid;
		IPSID_REFHOLD(ipsa->ipsa_proxy_cid);
	}
#endif /* XXX PROXY */

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
    sa_family_t af, uint32_t *addr, uint16_t port, uint8_t proto)
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
	addrext->sadb_address_prefixlen = 0;
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
mblk_t *
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
	mblk_t *mp;
	uint64_t *bitmap;
	uint8_t *cur, *end;
	/* These indicate the presence of the above extension fields. */
	boolean_t soft, hard, proxy, auth, encr, sensinteg, srcid, dstid;
#if 0 /* XXX PROXY see below... */
	boolean_t proxyid, iv;
	int proxyidsize, ivsize;
#endif /* XXX PROXY */

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

	/* Proxy address? */
	if (!IPSA_IS_ADDR_UNSPEC(ipsa->ipsa_proxysrc, ipsa->ipsa_proxyfam)) {
		pfam = ipsa->ipsa_proxyfam;
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
		proxy = B_TRUE;
		alloclen += paddrsize;
	} else {
		proxy = B_FALSE;
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

#if 0 /* XXX PROXY not yet. */
	if (ipsa->ipsa_proxy_cid != NULL) {
		proxyidsize = roundup(sizeof (sadb_ident_t) +
		    strlen(ipsa->ipsa_proxy_cid->ipsid_cid) + 1,
		    sizeof (uint64_t));
		alloclen += proxyidsize;
		proxyid = B_TRUE;
	} else {
		proxyid = B_FALSE;
	}
#endif /* XXX PROXY */
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
	lt->sadb_lifetime_allocations = ipsa->ipsa_alloc;
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

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC, fam,
	    ipsa->ipsa_srcaddr, SA_SRCPORT(ipsa), SA_PROTO(ipsa));
	if (cur == NULL) {
		freemsg(mp);
		mp = NULL;
		goto bail;
	}

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST, fam,
	    ipsa->ipsa_dstaddr, SA_DSTPORT(ipsa), SA_PROTO(ipsa));
	if (cur == NULL) {
		freemsg(mp);
		mp = NULL;
		goto bail;
	}

	if (ipsa->ipsa_flags & IPSA_F_NATT_LOC) {
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_NATT_LOC,
		    fam, ipsa->ipsa_natt_addr_loc, 0, 0);
		if (cur == NULL) {
			freemsg(mp);
			mp = NULL;
			goto bail;
		}
	}

	if (ipsa->ipsa_flags & IPSA_F_NATT_REM) {
		cur = sadb_make_addr_ext(cur, end, SADB_X_EXT_ADDRESS_NATT_REM,
		    fam, ipsa->ipsa_natt_addr_rem, ipsa->ipsa_remote_port,
		    IPPROTO_UDP);
		if (cur == NULL) {
			freemsg(mp);
			mp = NULL;
			goto bail;
		}
	}

	if (proxy) {
		/*
		 * XXX PROXY When we expand the definition of proxy to include
		 * both inner and outer IP addresses, this will have to
		 * be expanded.
		 */
		cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_PROXY,
		    pfam, ipsa->ipsa_proxysrc, 0, 0);
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

#if 0 /* XXX PROXY not yet */
	if (proxyid) {
		ident = (sadb_ident_t *)walker;
		ident->sadb_ident_len = SADB_8TO64(proxyidsize);
		ident->sadb_ident_exttype = SADB_EXT_IDENTITY_PROXY;
		ident->sadb_ident_type = ipsa->ipsa_pcid_type;
		ident->sadb_ident_id = 0;
		ident->sadb_ident_reserved = 0;
		(void) strcpy((char *)(ident + 1), ipsa->ipsa_proxy_cid);
		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}
#endif /* XXX PROXY */

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
		 * First abandon the PF_KEY message, then construct
		 * the new one.
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
    void (*ager)(void *), timeout_id_t *top, int satype)
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
	*top = qtimeout(*pfkey_qp, ager, NULL, drv_usectohz(4000000));

	putnext(*pfkey_qp, mp);
}

/*
 * Send IRE_DB_REQ down to IP to get properties of address.
 * If I can determine the address, return the proper type.  If an error
 * occurs, or if I have to send down an IRE_DB_REQ, return UNKNOWN, and
 * the caller will just let go of mp w/o freeing it.
 *
 * To handle the compatible IPv6 addresses (i.e. ::FFFF:<v4-address>),
 * this function will also convert such AF_INET6 addresses into AF_INET
 * addresses.
 *
 * Whomever called the function will handle the return message that IP sends
 * in response to the message this function generates.
 */
int
sadb_addrcheck(queue_t *ip_q, queue_t *pfkey_q, mblk_t *mp, sadb_ext_t *ext,
    uint_t serial)
{
	sadb_address_t *addr = (sadb_address_t *)ext;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	mblk_t *ire_db_req_mp;
	ire_t *ire;
	int diagnostic;

	ASSERT(ext != NULL);
	ASSERT((ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC) ||
	    (ext->sadb_ext_type == SADB_EXT_ADDRESS_DST) ||
	    (ext->sadb_ext_type == SADB_EXT_ADDRESS_PROXY));

	ire_db_req_mp = allocb(sizeof (ire_t), BPRI_HI);
	if (ire_db_req_mp == NULL) {
		/* cmn_err(CE_WARN, "sadb_addrcheck: allocb() failed.\n"); */
		sadb_pfkey_error(pfkey_q, mp, ENOMEM, SADB_X_DIAGNOSTIC_NONE,
		    serial);
		return (KS_IN_ADDR_UNKNOWN);
	}

	ire_db_req_mp->b_datap->db_type = IRE_DB_REQ_TYPE;
	ire_db_req_mp->b_wptr += sizeof (ire_t);
	ire = (ire_t *)ire_db_req_mp->b_rptr;

	/* Assign both sockaddrs, the compiler will do the right thing. */
	sin = (struct sockaddr_in *)(addr + 1);
	sin6 = (struct sockaddr_in6 *)(addr + 1);

	switch (sin->sin_family) {
	case AF_INET6:
		/* Because of the longer IPv6 addrs, do check first. */
		if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
				freemsg(ire_db_req_mp);
				return (KS_IN_ADDR_MBCAST);
			}
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
				freemsg(ire_db_req_mp);
				return (KS_IN_ADDR_UNSPEC);
			}
			ire->ire_ipversion = IPV6_VERSION;
			ire->ire_addr_v6 = sin6->sin6_addr;
			break;	/* Out of switch. */
		}
		/*
		 * Convert to an AF_INET sockaddr.  This means
		 * the return messages will have the extra space, but
		 * have AF_INET sockaddrs instead of AF_INET6.
		 *
		 * Yes, RFC 2367 isn't clear on what to do here w.r.t.
		 * mapped addresses, but since AF_INET6 ::ffff:<v4> is
		 * equal to AF_INET <v4>, it shouldnt be a huge
		 * problem.
		 */
		ASSERT(&sin->sin_port == &sin6->sin6_port);
		sin->sin_family = AF_INET;
		IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr, &sin->sin_addr);
		bzero(&sin->sin_zero, sizeof (sin->sin_zero));
		/* FALLTHRU */
	case AF_INET:
		ire->ire_ipversion = IPV4_VERSION;
		ire->ire_addr = sin->sin_addr.s_addr;
		if (ire->ire_addr == INADDR_ANY) {
			freemsg(ire_db_req_mp);
			return (KS_IN_ADDR_UNSPEC);
		}
		if (CLASSD(ire->ire_addr)) {
			freemsg(ire_db_req_mp);
			return (KS_IN_ADDR_MBCAST);
		}
		break;
	default:
		freemsg(ire_db_req_mp);

		switch (ext->sadb_ext_type) {
		case SADB_EXT_ADDRESS_SRC:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_SRC_AF;
			break;
		case SADB_EXT_ADDRESS_DST:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_DST_AF;
			break;
		case SADB_EXT_ADDRESS_PROXY:
			diagnostic = SADB_X_DIAGNOSTIC_BAD_PROXY_AF;
			break;
			/* There is no default, see above ASSERT. */
		}

		sadb_pfkey_error(pfkey_q, mp, EINVAL, diagnostic, serial);
		return (KS_IN_ADDR_UNKNOWN);
	}
	ire_db_req_mp->b_cont = mp;

	ASSERT(ip_q != NULL);
	putnext(ip_q, ire_db_req_mp);
	return (KS_IN_ADDR_UNKNOWN);
}

/*
 * For the case of src == unspecified AF_INET6, and dst == AF_INET, convert
 * the source to AF_INET.
 */
void
sadb_srcaddrfix(keysock_in_t *ksi)
{
	struct sockaddr_in *src;
	struct sockaddr_in6 *dst;
	sadb_address_t *srcext, *dstext;
	uint16_t sport;

	if (ksi->ks_in_srctype != KS_IN_ADDR_UNSPEC ||
	    ksi->ks_in_dsttype == KS_IN_ADDR_NOTTHERE)
		return;

	dstext = (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	dst = (struct sockaddr_in6 *)(dstext + 1);
	srcext = (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	src = (struct sockaddr_in *)(srcext + 1);

	/*
	 * If unspecified IPv4 source, but an IPv6 dest, don't bother
	 * fixing, as it should be an error.
	 */
	if (dst->sin6_family == src->sin_family ||
	    src->sin_family == AF_INET)
		return;

	/*
	 * Convert "src" to AF_INET INADDR_ANY.  We rely on sin_port being
	 * in the same place for sockaddr_in and sockaddr_in6.
	 */
	sport = src->sin_port;
	bzero(src, sizeof (*src));
	src->sin_family = AF_INET;
	src->sin_port = sport;
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
	    (ps->didstr != NULL &&
		(entry->ipsa_dst_cid != NULL) &&
		!(ps->didtype == entry->ipsa_dst_cid->ipsid_type &&
		    strcmp(ps->didstr, entry->ipsa_dst_cid->ipsid_cid) == 0)) ||
	    (ps->sidstr != NULL &&
		(entry->ipsa_src_cid != NULL) &&
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
sadb_purge_sa(mblk_t *mp, keysock_in_t *ksi, sadb_t *sp,
    int *diagnostic, queue_t *pfkey_q, queue_t *ip_q)
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

		if (dstext != NULL) {
			if (src->sin_family != dst->sin_family) {
				*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
				return (EINVAL);
			}
		}
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
    int *diagnostic, queue_t *pfkey_q, boolean_t delete)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	struct sockaddr_in *src, *dst;
	struct sockaddr_in6 *src6, *dst6;
	sadb_t *sp;
	ipsa_t *outbound_target, *inbound_target;
	isaf_t *inbound, *outbound;
	uint32_t *srcaddr, *dstaddr;
	mblk_t *torchq = NULL;
	sa_family_t af;

	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}
	if (assoc == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SA;
		return (EINVAL);
	}

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
			if (src6->sin6_family != AF_INET6) {
				*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
				return (EINVAL);
			}
		} else {
			srcaddr = ALL_ZEROES_PTR;
		}

		outbound = OUTBOUND_BUCKET_V6(sp, *(uint32_t *)dstaddr);
	} else {
		sp = &spp->s_v4;
		dstaddr = (uint32_t *)&dst->sin_addr;
		if (srcext != NULL) {
			src = (struct sockaddr_in *)(srcext + 1);
			srcaddr = (uint32_t *)&src->sin_addr;
			if (src->sin_family != AF_INET) {
				*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
				return (EINVAL);
			}
		} else {
			srcaddr = ALL_ZEROES_PTR;
		}
		outbound = OUTBOUND_BUCKET_V4(sp, *(uint32_t *)dstaddr);
	}

	inbound = INBOUND_BUCKET(sp, assoc->sadb_sa_spi);

	/* Lock down both buckets. */
	mutex_enter(&outbound->isaf_lock);
	mutex_enter(&inbound->isaf_lock);

	/* Try outbound first. */
	outbound_target = ipsec_getassocbyspi(outbound, assoc->sadb_sa_spi,
	    srcaddr, dstaddr, af);

	if (outbound_target == NULL || outbound_target->ipsa_haspeer) {
		inbound_target = ipsec_getassocbyspi(inbound,
		    assoc->sadb_sa_spi, srcaddr, dstaddr, af);
	} else {
		inbound_target = NULL;
	}

	if (outbound_target == NULL && inbound_target == NULL) {
		mutex_exit(&inbound->isaf_lock);
		mutex_exit(&outbound->isaf_lock);
		return (ESRCH);
	}

	if (delete) {
		/* At this point, I have one or two SAs to be deleted. */
		if (outbound_target != NULL) {
			mutex_enter(&outbound_target->ipsa_lock);
			outbound_target->ipsa_state = IPSA_STATE_DEAD;
			(void) sadb_torch_assoc(outbound, outbound_target,
			    B_FALSE, &torchq);
		}

		if (inbound_target != NULL) {
			mutex_enter(&inbound_target->ipsa_lock);
			inbound_target->ipsa_state = IPSA_STATE_DEAD;
			(void) sadb_torch_assoc(inbound, inbound_target,
			    B_TRUE, &torchq);
		}
	}

	mutex_exit(&inbound->isaf_lock);
	mutex_exit(&outbound->isaf_lock);

	if (torchq != NULL)
		sadb_drain_torchq(spp->s_ip_q, torchq);

	/*
	 * Because of the multi-line macro nature of IPSA_REFRELE, keep
	 * them in { }.
	 */
	ASSERT(mp->b_cont != NULL);
	sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr, ksi,
	    (outbound_target != NULL ? outbound_target : inbound_target));

	if (outbound_target != NULL) {
		IPSA_REFRELE(outbound_target);
	}
	if (inbound_target != NULL) {
		IPSA_REFRELE(inbound_target);
	}

	return (0);
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

	mutex_enter(&alg_lock);

	if (sa->ipsa_encrkey != NULL) {
		alg = ipsec_alglists[IPSEC_ALG_ENCR][sa->ipsa_encr_alg];
		if (alg != NULL && ALG_VALID(alg)) {
			sa->ipsa_emech.cm_type = alg->alg_mech_type;
			sa->ipsa_emech.cm_param = NULL;
			sa->ipsa_emech.cm_param_len = 0;
			sa->ipsa_iv_len = alg->alg_datalen;
		} else
			sa->ipsa_emech.cm_type = CRYPTO_MECHANISM_INVALID;
	}

	if (sa->ipsa_authkey != NULL) {
		alg = ipsec_alglists[IPSEC_ALG_AUTH][sa->ipsa_auth_alg];
		if (alg != NULL && ALG_VALID(alg)) {
			sa->ipsa_amech.cm_type = alg->alg_mech_type;
			sa->ipsa_amech.cm_param = (char *)&sa->ipsa_mac_len;
			sa->ipsa_amech.cm_param_len = sizeof (size_t);
			sa->ipsa_mac_len = (size_t)alg->alg_datalen;
		} else
			sa->ipsa_amech.cm_type = CRYPTO_MECHANISM_INVALID;
	}

	mutex_exit(&alg_lock);
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
 * various error conditions.  No need to set samsg->sadb_x_msg_diagnostic with
 * additional diagnostic information because ENOMEM and EEXIST are self-
 * explanitory.
 */
int
sadb_common_add(queue_t *ip_q, queue_t *pfkey_q, mblk_t *mp, sadb_msg_t *samsg,
    keysock_in_t *ksi, isaf_t *primary, isaf_t *secondary,
    ipsa_t *newbie, boolean_t clone, boolean_t is_inbound)
{
	ipsa_t *newbie_clone = NULL, *scratch;
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_address_t *proxyext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_PROXY];
	sadb_address_t *natt_loc_ext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_LOC];
	sadb_address_t *natt_rem_ext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_REM];
	sadb_x_kmc_t *kmcext =
	    (sadb_x_kmc_t *)ksi->ks_in_extv[SADB_X_EXT_KM_COOKIE];
	sadb_key_t *akey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_AUTH];
	sadb_key_t *ekey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT];
#if 0
	/*
	 * XXXMLS - When Trusted Solaris or Multi-Level Secure functionality
	 * comes to ON, examine these if 0'ed fragments.  Look for XXXMLS.
	 */
	sadb_sens_t *sens = (sadb_sens_t *);
#endif
	struct sockaddr_in *src, *dst, *proxy, *natt_loc, *natt_rem;
	struct sockaddr_in6 *src6, *dst6, *proxy6, *natt_loc6, *natt_rem6;
	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];
	sa_family_t af;
	int error = 0;
	boolean_t isupdate = (newbie != NULL);
	uint32_t *src_addr_ptr, *dst_addr_ptr, *proxy_addr_ptr;
	uint32_t *natt_loc_ptr = NULL, *natt_rem_ptr = NULL;
	uint32_t running_sum = 0;
	mblk_t *ctl_mp = NULL;

	src = (struct sockaddr_in *)(srcext + 1);
	src6 = (struct sockaddr_in6 *)(srcext + 1);
	dst = (struct sockaddr_in *)(dstext + 1);
	dst6 = (struct sockaddr_in6 *)(dstext + 1);
	if (proxyext != NULL) {
		proxy = (struct sockaddr_in *)(proxyext + 1);
		proxy6 = (struct sockaddr_in6 *)(proxyext + 1);
	} else {
		proxy = NULL;
		proxy6 = NULL;
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

	if (!isupdate) {
		newbie = sadb_makelarvalassoc(assoc->sadb_sa_spi,
		    src_addr_ptr, dst_addr_ptr, af);
		if (newbie == NULL)
			return (ENOMEM);
	}

	mutex_enter(&newbie->ipsa_lock);

	if (proxy != NULL) {
		if (proxy->sin_family == AF_INET) {
			proxy_addr_ptr = (uint32_t *)&proxy->sin_addr;
		} else {
			ASSERT(proxy->sin_family == AF_INET6);
			proxy_addr_ptr = (uint32_t *)&proxy6->sin6_addr;
		}
		newbie->ipsa_proxyfam = proxy->sin_family;

		IPSA_COPY_ADDR(newbie->ipsa_proxysrc, proxy_addr_ptr,
		    newbie->ipsa_proxyfam);
	}

#define	DOWN_SUM(x) (x) = ((x) & 0xFFFF) +	 ((x) >> 16)


	if (natt_rem_ext != NULL) {
		uint32_t l_src;
		uint32_t l_rem;

		natt_rem = (struct sockaddr_in *)(natt_rem_ext + 1);
		natt_rem6 = (struct sockaddr_in6 *)(natt_rem_ext + 1);

		if (natt_rem->sin_family == AF_INET) {
			natt_rem_ptr = (uint32_t *)(&natt_rem->sin_addr);
			newbie->ipsa_remote_port = natt_rem->sin_port;
			l_src = *src_addr_ptr;
			l_rem = *natt_rem_ptr;
		} else {
			if (!IN6_IS_ADDR_V4MAPPED(&natt_rem6->sin6_addr)) {
				goto error;
			}
			ASSERT(natt_rem->sin_family == AF_INET6);

			natt_rem_ptr = ((uint32_t *)
			    (&natt_rem6->sin6_addr)) + 3;
			newbie->ipsa_remote_port = natt_rem6->sin6_port;
			l_src = *src_addr_ptr;
			l_rem = *natt_rem_ptr;
		}
		IPSA_COPY_ADDR(newbie->ipsa_natt_addr_rem, natt_rem_ptr, af);

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
		uint32_t l_dst;
		uint32_t l_loc;

		natt_loc = (struct sockaddr_in *)(natt_loc_ext + 1);
		natt_loc6 = (struct sockaddr_in6 *)(natt_loc_ext + 1);

		if (natt_loc->sin_family == AF_INET) {
			natt_loc_ptr = (uint32_t *)&natt_loc->sin_addr;
			l_dst = *dst_addr_ptr;
			l_loc = *natt_loc_ptr;

		} else {
			if (!IN6_IS_ADDR_V4MAPPED(&natt_loc6->sin6_addr)) {
				goto error;
			}
			ASSERT(natt_loc->sin_family == AF_INET6);
			natt_loc_ptr = ((uint32_t *)&natt_loc6->sin6_addr) + 3;
			l_dst = *dst_addr_ptr;
			l_loc = *natt_loc_ptr;

		}
		IPSA_COPY_ADDR(newbie->ipsa_natt_addr_loc, natt_loc_ptr, af);

		l_loc = ntohl(l_loc);
		DOWN_SUM(l_loc);
		DOWN_SUM(l_loc);
		l_dst = ntohl(l_dst);
		DOWN_SUM(l_dst);
		DOWN_SUM(l_dst);

		/*
		 * We're 1's complement for checksums, so check for wraparound
		 * here.
		 */
		if (l_loc > l_dst)
			l_dst--;

		running_sum += l_dst - l_loc;
		DOWN_SUM(running_sum);
		DOWN_SUM(running_sum);
	}

	newbie->ipsa_inbound_cksum = running_sum;
#undef DOWN_SUM

	newbie->ipsa_type = samsg->sadb_msg_satype;
	ASSERT(assoc->sadb_sa_state == SADB_SASTATE_MATURE);
	newbie->ipsa_auth_alg = assoc->sadb_sa_auth;
	newbie->ipsa_encr_alg = assoc->sadb_sa_encrypt;
	newbie->ipsa_flags = assoc->sadb_sa_flags;
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

	(void) drv_getparm(TIME, &newbie->ipsa_addtime);

	/* Set unique value */
	newbie->ipsa_unique_id = SA_UNIQUE_ID((uint16_t)src->sin_port,
	    (uint16_t)dst->sin_port, dstext->sadb_address_proto);
	newbie->ipsa_unique_mask = SA_UNIQUE_MASK((uint16_t)src->sin_port,
	    (uint16_t)dst->sin_port, dstext->sadb_address_proto);

	if (newbie->ipsa_unique_mask != 0)
		newbie->ipsa_flags |= IPSA_F_UNIQUE;

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

		mutex_enter(&alg_lock);
		error = ipsec_create_ctx_tmpl(newbie, IPSEC_ALG_AUTH);
		mutex_exit(&alg_lock);
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

		mutex_enter(&alg_lock);
		error = ipsec_create_ctx_tmpl(newbie, IPSEC_ALG_ENCR);
		mutex_exit(&alg_lock);
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
		    (char *)(id+1));
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
		    (char *)(id+1));
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
		newbie->ipsa_haspeer = B_TRUE;
		newbie_clone->ipsa_haspeer = B_TRUE;
	}

	/*
	 * Enter the bucket locks.  The order of entry is outbound,
	 * inbound.  We map "primary" and "secondary" into outbound and inbound
	 * based on the destination address type.  If the destination address
	 * type is for a node that isn't mine (or potentially mine), the
	 * "primary" bucket is the outbound one.
	 */
	if (ksi->ks_in_dsttype == KS_IN_ADDR_NOTME) {
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

	/* Common error point for this routine. */
error:
	if (newbie != NULL) {
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
		 * keysock.  (Q:  Do I need to pass "newbie"?  If I do,
		 * make sure to REFHOLD, call, then REFRELE.)
		 */
		sadb_pfkey_echo(pfkey_q, mp, samsg, ksi, NULL);
	}

	return (error);
}

/*
 * Set the time of first use for a security association.  Update any
 * expiration times as a result.
 */
void
sadb_set_usetime(ipsa_t *assoc)
{
	mutex_enter(&assoc->ipsa_lock);
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

		(void) drv_getparm(TIME, &assoc->ipsa_usetime);

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

	ASSERT(MUTEX_HELD(&assoc->ipsa_lock));

	/* Don't bother sending if there's no queue. */
	if (pfkey_q == NULL)
		return;

	mp = sadb_keysock_out(0);
	if (mp == NULL) {
		/* cmn_err(CE_WARN, */
		/*	"sadb_expire_assoc: Can't allocate KEYSOCK_OUT.\n"); */
		return;
	}

	alloclen = sizeof (*samsg) + sizeof (*current) + sizeof (*expire) +
	    2*sizeof (sadb_address_t) + sizeof (*saext);

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
	current->sadb_lifetime_allocations = assoc->ipsa_alloc;
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
	    af, assoc->ipsa_srcaddr, SA_SRCPORT(assoc), SA_PROTO(assoc));
	ASSERT(mp->b_wptr != NULL);

	mp->b_wptr = sadb_make_addr_ext(mp->b_wptr, end, SADB_EXT_ADDRESS_DST,
	    af, assoc->ipsa_dstaddr, SA_DSTPORT(assoc), SA_PROTO(assoc));
	ASSERT(mp->b_wptr != NULL);

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
 * Return "assoc" iff haspeer is true and I send an expire.  This allows
 * the consumers' aging functions to tidy up an expired SA's peer.
 */
static ipsa_t *
sadb_age_assoc(isaf_t *head, queue_t *pfkey_q, ipsa_t *assoc,
    time_t current, int reap_delay, boolean_t inbnd, mblk_t **mq)
{
	ipsa_t *retval = NULL;

	ASSERT(MUTEX_HELD(&head->isaf_lock));

	mutex_enter(&assoc->ipsa_lock);

	if ((assoc->ipsa_state == IPSA_STATE_LARVAL) &&
	    (assoc->ipsa_hardexpiretime <= current)) {
		assoc->ipsa_state = IPSA_STATE_DEAD;
		return (sadb_torch_assoc(head, assoc, inbnd, mq));
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
			return (sadb_torch_assoc(head, assoc, inbnd, mq));

		/*
		 * Send SADB_EXPIRE with hard lifetime, delay for unlinking.
		 */
		assoc->ipsa_state = IPSA_STATE_DEAD;
		if (assoc->ipsa_haspeer) {
			/*
			 * If I return assoc, I have to bump up its
			 * reference count to keep with the ipsa_t reference
			 * count semantics.
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
			 * If I return assoc, I have to bump up its
			 * reference count to keep with the ipsa_t reference
			 * count semantics.
			 */
			IPSA_REFHOLD(assoc);
			retval = assoc;
		}
		sadb_expire_assoc(pfkey_q, assoc);
	}

	mutex_exit(&assoc->ipsa_lock);
	return (retval);
}

/*
 * Called by a consumer protocol to do ther dirty work of reaping dead
 * Security Associations.
 */
void
sadb_ager(sadb_t *sp, queue_t *pfkey_q, queue_t *ip_q, int reap_delay)
{
	int i;
	isaf_t *bucket;
	ipsa_t *assoc, *spare;
	iacqf_t *acqlist;
	ipsacq_t *acqrec, *spareacq;
	struct templist {
		ipsa_t *ipsa;
		struct templist *next;
	} *haspeerlist = NULL, *newbie;
	time_t current;
	int outhash;
	mblk_t *mq = NULL;

	/*
	 * Do my dirty work.  This includes aging real entries, aging
	 * larvals, and aging outstanding ACQUIREs.
	 *
	 * I hope I don't tie up resources for too long.
	 */

	/* Snapshot current time now. */
	(void) drv_getparm(TIME, &current);

	/* Age acquires. */

	for (i = 0; i < sp->sdb_hashsize; i++) {
		acqlist = &sp->sdb_acq[i];
		mutex_enter(&acqlist->iacqf_lock);
		for (acqrec = acqlist->iacqf_ipsacq; acqrec != NULL;
		    acqrec = spareacq) {
			spareacq = acqrec->ipsacq_next;
			if (current > acqrec->ipsacq_expire)
				sadb_destroy_acquire(acqrec);
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
	/*
	 * Haspeer cases will contain both IPv4 and IPv6.  This code
	 * is address independent.
	 */
	while (haspeerlist != NULL) {
		/* "spare" contains the SA that has a peer. */
		spare = haspeerlist->ipsa;
		newbie = haspeerlist;
		haspeerlist = newbie->next;
		kmem_free(newbie, sizeof (*newbie));
		/*
		 * Pick peer bucket based on addrfam.
		 */
		if (spare->ipsa_addrfam == AF_INET6) {
			outhash = OUTBOUND_HASH_V6(sp,
			    *((in6_addr_t *)&spare->ipsa_dstaddr));
		} else {
			outhash = OUTBOUND_HASH_V4(sp,
			    *((ipaddr_t *)&spare->ipsa_dstaddr));
		}
		bucket = &(sp->sdb_of[outhash]);

		mutex_enter(&bucket->isaf_lock);
		assoc = ipsec_getassocbyspi(bucket, spare->ipsa_spi,
		    spare->ipsa_srcaddr, spare->ipsa_dstaddr,
		    spare->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (assoc != NULL) {
			mutex_enter(&assoc->ipsa_lock);
			mutex_enter(&spare->ipsa_lock);
			assoc->ipsa_state = spare->ipsa_state;
			if (assoc->ipsa_state == IPSA_STATE_DEAD)
				assoc->ipsa_hardexpiretime = 1;
			mutex_exit(&spare->ipsa_lock);
			mutex_exit(&assoc->ipsa_lock);
			IPSA_REFRELE(assoc);
		}
		IPSA_REFRELE(spare);
	}

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
	/*
	 * Haspeer cases will contain both IPv4 and IPv6.  This code
	 * is address independent.
	 */
	while (haspeerlist != NULL) {
		/* "spare" contains the SA that has a peer. */
		spare = haspeerlist->ipsa;
		newbie = haspeerlist;
		haspeerlist = newbie->next;
		kmem_free(newbie, sizeof (*newbie));
		/*
		 * Pick peer bucket based on addrfam.
		 */
		bucket = INBOUND_BUCKET(sp, spare->ipsa_spi);
		mutex_enter(&bucket->isaf_lock);
		assoc = ipsec_getassocbyspi(bucket, spare->ipsa_spi,
		    spare->ipsa_srcaddr, spare->ipsa_dstaddr,
		    spare->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (assoc != NULL) {
			mutex_enter(&assoc->ipsa_lock);
			mutex_enter(&spare->ipsa_lock);
			assoc->ipsa_state = spare->ipsa_state;
			if (assoc->ipsa_state == IPSA_STATE_DEAD)
				assoc->ipsa_hardexpiretime = 1;
			mutex_exit(&spare->ipsa_lock);
			mutex_exit(&assoc->ipsa_lock);
			IPSA_REFRELE(assoc);
		}
		IPSA_REFRELE(spare);
	}
	/*
	 * Run a GC pass to clean out dead identities.
	 */
	ipsid_gc();
}

/*
 * Figure out when to reschedule the ager.
 */
timeout_id_t
sadb_retimeout(hrtime_t begin, queue_t *pfkey_q, void (*ager)(void *),
    uint_t *intp, uint_t intmax, short mid)
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
	return (qtimeout(pfkey_q, ager, NULL, interval * drv_usectohz(1000)));
}


/*
 * Update the lifetime values of an SA.	 This is the path an SADB_UPDATE
 * message takes when updating a MATURE or DYING SA.
 */
static void
sadb_update_lifetimes(ipsa_t *assoc, sadb_lifetime_t *hard,
    sadb_lifetime_t *soft)
{
	mutex_enter(&assoc->ipsa_lock);

	assoc->ipsa_state = IPSA_STATE_MATURE;

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
		if (assoc->ipsa_harduselt != 0) {
			if (assoc->ipsa_hardexpiretime != 0) {
				assoc->ipsa_hardexpiretime =
				    min(assoc->ipsa_hardexpiretime,
					assoc->ipsa_usetime +
					assoc->ipsa_harduselt);
			} else {
				assoc->ipsa_hardexpiretime =
				    assoc->ipsa_usetime + assoc->ipsa_harduselt;
			}
		}

		if (hard->sadb_lifetime_allocations != 0)
			assoc->ipsa_hardalloc = hard->sadb_lifetime_allocations;
	}

	if (soft != NULL) {
		if (soft->sadb_lifetime_bytes != 0)
			assoc->ipsa_softbyteslt = soft->sadb_lifetime_bytes;
		if (soft->sadb_lifetime_usetime != 0)
			assoc->ipsa_softuselt = soft->sadb_lifetime_usetime;
		if (soft->sadb_lifetime_addtime != 0)
			assoc->ipsa_softaddlt = soft->sadb_lifetime_addtime;
		if (assoc->ipsa_softaddlt != 0) {
			assoc->ipsa_softexpiretime =
			    assoc->ipsa_addtime + assoc->ipsa_softaddlt;
		}
		if (assoc->ipsa_softuselt != 0) {
			if (assoc->ipsa_softexpiretime != 0) {
				assoc->ipsa_softexpiretime =
				    min(assoc->ipsa_softexpiretime,
					assoc->ipsa_usetime +
					assoc->ipsa_softuselt);
			} else {
				assoc->ipsa_softexpiretime =
				    assoc->ipsa_usetime + assoc->ipsa_softuselt;
			}
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
    sadb_t *sp, int *diagnostic, queue_t *pfkey_q,
    int (*add_sa_func)(mblk_t *, keysock_in_t *, int *))
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
	struct sockaddr_in *src, *dst;
	struct sockaddr_in6 *src6, *dst6;
	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];
	isaf_t *inbound, *outbound;
	ipsa_t *outbound_target = NULL, *inbound_target = NULL;
	int error = 0;
	uint32_t *srcaddr, *dstaddr;
	sa_family_t af;
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

	dst = (struct sockaddr_in *)(dstext + 1);
	src = (struct sockaddr_in *)(srcext + 1);
	af = dst->sin_family;
	if (af == AF_INET6) {
		dst6 = (struct sockaddr_in6 *)dst;
		src6 = (struct sockaddr_in6 *)src;

		srcaddr = (uint32_t *)&src6->sin6_addr;
		dstaddr = (uint32_t *)&dst6->sin6_addr;
		outbound = OUTBOUND_BUCKET_V6(sp, *(uint32_t *)dstaddr);
#if 0
		/* Not used for now... */
		if (proxyext != NULL)
			proxy6 = (struct sockaddr_in6 *)(proxyext + 1);
#endif
	} else {
		srcaddr = (uint32_t *)&src->sin_addr;
		dstaddr = (uint32_t *)&dst->sin_addr;
		outbound = OUTBOUND_BUCKET_V4(sp, *(uint32_t *)dstaddr);
	}
	inbound = INBOUND_BUCKET(sp, assoc->sadb_sa_spi);

	/* Lock down both buckets. */
	mutex_enter(&outbound->isaf_lock);
	mutex_enter(&inbound->isaf_lock);

	/* Try outbound first. */
	outbound_target = ipsec_getassocbyspi(outbound, assoc->sadb_sa_spi,
	    srcaddr, dstaddr, af);
	inbound_target = ipsec_getassocbyspi(inbound, assoc->sadb_sa_spi,
	    srcaddr, dstaddr, af);

	mutex_exit(&inbound->isaf_lock);
	mutex_exit(&outbound->isaf_lock);

	if (outbound_target == NULL) {
		if (inbound_target == NULL) {
			return (ESRCH);
		} else if (inbound_target->ipsa_state == IPSA_STATE_LARVAL) {
			/*
			 * REFRELE the target and let the add_sa_func()
			 * deal with updating a larval SA.
			 */
			IPSA_REFRELE(inbound_target);
			return (add_sa_func(mp, ksi, diagnostic));
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
	if (assoc->sadb_sa_flags & ~(SADB_SAFLAGS_NOREPLAY |
		SADB_X_SAFLAGS_NATT_LOC | SADB_X_SAFLAGS_NATT_REM)) {
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
	if (src->sin_family != dst->sin_family) {
		*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
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

	if (outbound_target != NULL) {
		if (outbound_target->ipsa_state == IPSA_STATE_DEAD) {
			error = ESRCH;	/* DEAD == Not there, in this case. */
			goto bail;
		}
		if ((kmp != 0) &&
		    ((outbound_target->ipsa_kmp != 0) ||
			(outbound_target->ipsa_kmp != kmp))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMP;
			error = EINVAL;
			goto bail;
		}
		if ((kmc != 0) &&
		    ((outbound_target->ipsa_kmc != 0) ||
			(outbound_target->ipsa_kmc != kmc))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMC;
			error = EINVAL;
			goto bail;
		}
	}

	if (inbound_target != NULL) {
		if (inbound_target->ipsa_state == IPSA_STATE_DEAD) {
			error = ESRCH;	/* DEAD == Not there, in this case. */
			goto bail;
		}
		if ((kmp != 0) &&
		    ((inbound_target->ipsa_kmp != 0) ||
			(inbound_target->ipsa_kmp != kmp))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMP;
			error = EINVAL;
			goto bail;
		}
		if ((kmc != 0) &&
		    ((inbound_target->ipsa_kmc != 0) ||
			(inbound_target->ipsa_kmc != kmc))) {
			*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMC;
			error = EINVAL;
			goto bail;
		}
	}

	if (outbound_target != NULL) {
		sadb_update_lifetimes(outbound_target, hard, soft);
		if (kmp != 0)
			outbound_target->ipsa_kmp = kmp;
		if (kmc != 0)
			outbound_target->ipsa_kmc = kmc;
	}

	if (inbound_target != NULL) {
		sadb_update_lifetimes(inbound_target, hard, soft);
		if (kmp != 0)
			inbound_target->ipsa_kmp = kmp;
		if (kmc != 0)
			inbound_target->ipsa_kmc = kmc;
	}

	sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr,
	    ksi, (outbound_target == NULL) ? inbound_target : outbound_target);

bail:
	/*
	 * Because of the multi-line macro nature of IPSA_REFRELE, keep
	 * them in { }.
	 */
	if (outbound_target != NULL) {
		IPSA_REFRELE(outbound_target);
	}
	if (inbound_target != NULL) {
		IPSA_REFRELE(inbound_target);
	}

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
    uint32_t *src, uint32_t *dst, uint64_t unique_id)
{
	ipsacq_t *walker;
	sa_family_t fam;

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
		    /* XXX PROXY should check for proxy addr here */
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
	uint32_t *src, *dst;
	ipsec_policy_t *pp = io->ipsec_out_policy;
	ipsec_action_t *ap = io->ipsec_out_act;
	sa_family_t af;
	int hashoffset;
	uint32_t seq;
	uint64_t unique_id = 0;
	ipsec_selector_t sel;

	ASSERT((pp != NULL) || (ap != NULL));

	ASSERT(need_ah != NULL || need_esp != NULL);
	/* Assign sadb pointers */
	spp = need_esp ? &esp_sadb : &ah_sadb; /* ESP for AH+ESP */
	sp = io->ipsec_out_v4 ? &spp->s_v4 : &spp->s_v6;

	if (ap == NULL)
		ap = pp->ipsp_act;

	ASSERT(ap != NULL);

	if (ap->ipa_act.ipa_apply.ipp_use_unique)
		unique_id = SA_FORM_UNIQUE_ID(io);

	/*
	 * Set up an ACQUIRE record.
	 *
	 * Will eventually want to pull the PROXY source address from
	 * either the inner IP header, or from a future extension to the
	 * IPSEC_OUT message.
	 *
	 * Actually, we'll also want to check for duplicates.
	 *
	 * Immediately, make sure the ACQUIRE sequence number doesn't slip
	 * below the lowest point allowed in the kernel.  (In other words,
	 * make sure the high bit on the sequence number is set.)
	 */

	seq = keysock_next_seq() | IACQF_LOWEST_SEQ;

	sel.ips_isv4 = io->ipsec_out_v4;
	sel.ips_protocol = io->ipsec_out_proto;
	sel.ips_local_port = io->ipsec_out_src_port;
	sel.ips_remote_port = io->ipsec_out_dst_port;
	sel.ips_icmp_type = io->ipsec_out_icmp_type;
	sel.ips_icmp_code = io->ipsec_out_icmp_code;
	sel.ips_is_icmp_inv_acq = 0;
	if (IPH_HDR_VERSION(ipha) == IP_VERSION) {
		src = (uint32_t *)&ipha->ipha_src;
		dst = (uint32_t *)&ipha->ipha_dst;
		/* No compiler dain-bramage (4438087) for IPv4 addresses. */
		sel.ips_local_addr_v4 = ipha->ipha_src;
		sel.ips_remote_addr_v4 = ipha->ipha_dst;
		af = AF_INET;
		hashoffset = OUTBOUND_HASH_V4(sp, ipha->ipha_dst);
		ASSERT(io->ipsec_out_v4 == B_TRUE);
	} else {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		src = (uint32_t *)&ip6h->ip6_src;
		dst = (uint32_t *)&ip6h->ip6_dst;
		sel.ips_local_addr_v6 = ip6h->ip6_src;
		sel.ips_remote_addr_v6 = ip6h->ip6_dst;
		af = AF_INET6;
		hashoffset = OUTBOUND_HASH_V6(sp, ip6h->ip6_dst);
		ASSERT(io->ipsec_out_v4 == B_FALSE);
	}

	/*
	 * Check buckets to see if there is an existing entry.  If so,
	 * grab it.  sadb_checkacquire locks newbie if found.
	 */
	bucket = &(sp->sdb_acq[hashoffset]);
	mutex_enter(&bucket->iacqf_lock);
	newbie = sadb_checkacquire(bucket, ap, pp, src, dst, unique_id);

	if (newbie == NULL) {
		/*
		 * Otherwise, allocate a new one.
		 */
		newbie = kmem_zalloc(sizeof (*newbie), KM_NOSLEEP);
		if (newbie == NULL) {
			mutex_exit(&bucket->iacqf_lock);
			ip_drop_packet(mp, B_FALSE, NULL, NULL,
			    &ipdrops_sadb_acquire_nomem, &sadb_dropper);
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
		(void) drv_getparm(TIME, &newbie->ipsacq_expire);
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
		newbie->ipsacq_proto = io->ipsec_out_proto;
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
			    &ipdrops_sadb_acquire_toofull, &sadb_dropper);
		} else {
			IP_ACQUIRE_STAT(qhiwater, newbie->ipsacq_numpackets);
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

	if (keysock_extended_reg()) {
		/*
		 * Construct an extended ACQUIRE.  There are logging
		 * opportunities here in failure cases.
		 */

		extended = sadb_keysock_out(0);
		if (extended != NULL) {
			extended->b_cont = sadb_extended_acquire(&sel, pp, ap,
			    seq, 0);
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
	(*spp->s_acqfn)(newbie, extended);
}

/*
 * Unlink and free an acquire record.
 */
void
sadb_destroy_acquire(ipsacq_t *acqrec)
{
	mblk_t *mp;

	ASSERT(MUTEX_HELD(acqrec->ipsacq_linklock));

	if (acqrec->ipsacq_policy != NULL) {
		IPPOL_REFRELE(acqrec->ipsacq_policy);
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
		    &ipdrops_sadb_acquire_timeout, &sadb_dropper);
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
sadb_destroy_acqlist(iacqf_t **listp, uint_t numentries, boolean_t forever)
{
	int i;
	iacqf_t *list = *listp;

	if (list == NULL)
		return;

	for (i = 0; i < numentries; i++) {
		mutex_enter(&(list[i].iacqf_lock));
		while (list[i].iacqf_ipsacq != NULL)
			sadb_destroy_acquire(list[i].iacqf_ipsacq);
		mutex_exit(&(list[i].iacqf_lock));
		if (forever)
			mutex_destroy(&(list[i].iacqf_lock));
	}

	if (forever) {
		*listp = NULL;
		kmem_free(list, numentries * sizeof (*list));
	}
}

static uint8_t *
sadb_new_algdesc(uint8_t *start, uint8_t *limit,
    sadb_x_ecomb_t *ecomb, uint8_t satype, uint8_t algtype,
    uint8_t alg, uint16_t minbits, uint16_t maxbits)
{
	uint8_t *cur = start;

	sadb_x_algdesc_t *algdesc = (sadb_x_algdesc_t *)cur;
	cur += sizeof (*algdesc);
	if (cur >= limit)
		return (NULL);

	ecomb->sadb_x_ecomb_numalgs++;

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
sadb_action_to_ecomb(uint8_t *start, uint8_t *limit, ipsec_action_t *act)
{
	uint8_t *cur = start;
	sadb_x_ecomb_t *ecomb = (sadb_x_ecomb_t *)cur;
	ipsec_prot_t *ipp;

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
		    ipp->ipp_ah_minbits, ipp->ipp_ah_maxbits);
		if (cur == NULL)
			return (NULL);
		ipsecah_fill_defs(ecomb);
	}

	if (ipp->ipp_use_esp) {
		if (ipp->ipp_use_espa) {
			cur = sadb_new_algdesc(cur, limit, ecomb,
			    SADB_SATYPE_ESP, SADB_X_ALGTYPE_AUTH,
			    ipp->ipp_esp_auth_alg,
			    ipp->ipp_espa_minbits,
			    ipp->ipp_espa_maxbits);
			if (cur == NULL)
				return (NULL);
		}

		cur = sadb_new_algdesc(cur, limit, ecomb,
		    SADB_SATYPE_ESP, SADB_X_ALGTYPE_CRYPT,
		    ipp->ipp_encr_alg,
		    ipp->ipp_espe_minbits,
		    ipp->ipp_espe_maxbits);
		if (cur == NULL)
			return (NULL);
		/* Fill in lifetimes if and only if AH didn't already... */
		if (!ipp->ipp_use_ah)
			ipsecesp_fill_defs(ecomb);
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
    ipsec_action_t *act, uint32_t seq, uint32_t pid)
{
	mblk_t *mp;
	sadb_msg_t *samsg;
	uint8_t *start, *cur, *end;
	uint32_t *saddrptr, *daddrptr;
	sa_family_t af;
	sadb_prop_t *eprop;
	ipsec_action_t *ap, *an;
	uint8_t proto;
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
#define	SADB_EXTENDED_ACQUIRE_SIZE	2048
	mp = allocb(SADB_EXTENDED_ACQUIRE_SIZE, BPRI_HI);
	if (mp == NULL)
		return (NULL);
	if (sel->ips_isv4) {
		af = AF_INET;
		saddrptr = (uint32_t *)(&sel->ips_local_addr_v4);
		daddrptr = (uint32_t *)(&sel->ips_remote_addr_v4);
	} else {
		af = AF_INET6;
		saddrptr = (uint32_t *)(&sel->ips_local_addr_v6);
		daddrptr = (uint32_t *)(&sel->ips_remote_addr_v6);
	}

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

	proto = sel->ips_protocol;
	lport = sel->ips_local_port;
	rport = sel->ips_remote_port;

	/*
	 * Unless our policy says "sa unique", drop port/proto
	 * selectors, then add them back if policy rule includes them..
	 */

	if ((ap != NULL) && (!ap->ipa_want_unique)) {
		proto = 0;
		lport = 0;
		rport = 0;
		if (pol != NULL) {
			ipsec_selkey_t *psel = &pol->ipsp_sel->ipsl_key;
			if (psel->ipsl_valid & IPSL_PROTOCOL)
				proto = psel->ipsl_proto;
			if (psel->ipsl_valid & IPSL_REMOTE_PORT)
				rport = psel->ipsl_rport;
			if (psel->ipsl_valid & IPSL_LOCAL_PORT)
				lport = psel->ipsl_lport;
		}
	}

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC, af,
	    saddrptr, lport, proto);

	if (cur == NULL) {
		freeb(mp);
		return (NULL);
	}

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST, af,
	    daddrptr, rport, proto);

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

		cur = sadb_action_to_ecomb(cur, end, ap);
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
	samsg->sadb_msg_len = SADB_8TO64(cur-start);
	mp->b_wptr = cur;

	return (mp);
}

/*
 * Generic setup of an ACQUIRE message.	 Caller sets satype.
 */
uint8_t *
sadb_setup_acquire(uint8_t *start, uint8_t *end, ipsacq_t *acqrec)
{
	sa_family_t af;
	uint8_t *cur = start;
	sadb_msg_t *samsg = (sadb_msg_t *)cur;
	uint16_t sport_typecode;
	uint16_t dport_typecode;
	uint8_t check_proto;

	cur += sizeof (sadb_msg_t);
	if (cur > end)
		return (NULL);

	/* use the address length to find the address family */
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
		return (NULL);
	}

	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_ACQUIRE;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_pid = 0;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = acqrec->ipsacq_seq;

	ASSERT(MUTEX_HELD(&acqrec->ipsacq_lock));

	if (acqrec->ipsacq_proto == check_proto) {
		sport_typecode = dport_typecode = 0;
	} else {
		sport_typecode = acqrec->ipsacq_srcport;
		dport_typecode = acqrec->ipsacq_dstport;
	}

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC, af,
	    acqrec->ipsacq_srcaddr, sport_typecode, acqrec->ipsacq_proto);

	cur = sadb_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST, af,
	    acqrec->ipsacq_dstaddr, dport_typecode, acqrec->ipsacq_proto);

	if (cur != NULL)
		samsg->sadb_msg_len = SADB_8TO64(cur - start);

	return (cur);
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
sadb_getspi(keysock_in_t *ksi, uint32_t master_spi, int *diagnostic)
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
	if (dsa->sin_family != ssa->sin_family) {
		*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
		return ((ipsa_t *)-1);
	}

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
	return (sadb_makelarvalassoc(htonl(master_spi), srcaddr, dstaddr, af));
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
sadb_in_acquire(sadb_msg_t *samsg, sadbp_t *sp, queue_t *ip_q)
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
	sadb_destroy_acquire(acqrec);
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
 * is okay to proceed, B_FALSE if this packet should be dropped immeidately.
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
    uint32_t spi, void *addr, int af)
{
	char buf[INET6_ADDRSTRLEN];

	ASSERT(af == AF_INET6 || af == AF_INET);

	ipsec_rl_strlog(mid, sid, level, sl, fmt, ntohl(spi),
	    inet_ntop(af, addr, buf, sizeof (buf)));
}

/*
 * Fills in a reference to the policy, if any, from the conn, in *ppp
 * Releases a reference to the passed conn_t.
 */

/* ARGSUSED */
static void
ipsec_conn_pol(ipsec_selector_t *sel, conn_t *connp, ipsec_policy_t **ppp,
    ipsec_action_t **app)
{
	ipsec_policy_t	*pp;
	ipsec_latch_t	*ipl = connp->conn_latch;

	if ((ipl != NULL) && (ipl->ipl_out_policy != NULL)) {
		pp = ipl->ipl_out_policy;
		IPPOL_REFHOLD(pp);
	} else {
		pp = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, NULL, sel);
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
ipsec_udp_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp, ipsec_action_t **app)
{
	connf_t *connfp;
	conn_t *connp = NULL;
	ipsec_selector_t portonly;

	bzero((void*)&portonly, sizeof (portonly));

	if (sel->ips_local_port == 0)
		return;

	connfp = &ipcl_udp_fanout[IPCL_UDP_HASH(sel->ips_local_port)];
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

	ipsec_conn_pol(sel, connp, ppp, app);
}

static conn_t *
ipsec_find_listen_conn(uint16_t *pptr, ipsec_selector_t *sel)
{
	connf_t *connfp;
	conn_t *connp = NULL;
	const in6_addr_t *v6addrmatch = &sel->ips_local_addr_v6;

	if (sel->ips_local_port == 0)
		return (NULL);

	connfp = &ipcl_bind_fanout[IPCL_BIND_HASH(sel->ips_local_port)];
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
ipsec_tcp_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp, ipsec_action_t **app)
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

	connfp = &ipcl_conn_fanout[IPCL_CONN_HASH(sel->ips_remote_addr_v4,
	    ports)];
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
		if ((connp = ipsec_find_listen_conn(pptr, sel)) == NULL)
			return;
	}

	ipsec_conn_pol(sel, connp, ppp, app);
}

static void
ipsec_sctp_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp,
    ipsec_action_t **app)
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
		connp = sctp_find_conn(&dst, &src, ports, 0, ALL_ZONES);
	} else {
		connp = sctp_find_conn(&sel->ips_remote_addr_v6,
		    &sel->ips_local_addr_v6, ports, 0, ALL_ZONES);
	}
	if (connp == NULL)
		return;
	ipsec_conn_pol(sel, connp, ppp, app);
}

static void
ipsec_oth_pol(ipsec_selector_t *sel,
    ipsec_policy_t **ppp, ipsec_action_t **app)
{
	boolean_t	isv4 = sel->ips_isv4;
	connf_t		*connfp;
	conn_t		*connp;

	if (isv4) {
		connfp = &ipcl_proto_fanout[sel->ips_protocol];
	} else {
		connfp = &ipcl_proto_fanout_v6[sel->ips_protocol];
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

	ipsec_conn_pol(sel, connp, ppp, app);
}

/*
 * Construct an inverse ACQUIRE reply based on:
 *
 * 1.) Current global policy.
 * 2.) An conn_t match depending on what all was passed in the extv[].
 * ...
 * N.) Other stuff TBD (e.g. identities)
 *
 * If there is an error, set sadb_msg_errno and sadb_x_msg_diagnostic
 * in this function so the caller can extract them where appropriately.
 *
 * The SRC address is the local one - just like an outbound ACQUIRE message.
 */
mblk_t *
ipsec_construct_inverse_acquire(sadb_msg_t *samsg, sadb_ext_t *extv[])
{
	int err;
	int diagnostic;
	sadb_address_t *srcext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_SRC],
	    *dstext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_DST];
	struct sockaddr_in *src, *dst;
	struct sockaddr_in6 *src6, *dst6;
	ipsec_policy_t *pp;
	ipsec_action_t *ap;
	ipsec_selector_t sel;
	mblk_t *retmp;

	bzero(&sel, sizeof (sel));
	sel.ips_protocol = srcext->sadb_address_proto;
	dst = (struct sockaddr_in *)(dstext + 1);
	if (dst->sin_family == AF_INET6) {
		dst6 = (struct sockaddr_in6 *)dst;
		src6 = (struct sockaddr_in6 *)(srcext + 1);
		if (src6->sin6_family != AF_INET6) {
			diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
			err = EINVAL;
			goto bail;
		}
		sel.ips_remote_addr_v6 = dst6->sin6_addr;
		sel.ips_local_addr_v6 = src6->sin6_addr;
		if (sel.ips_protocol == IPPROTO_ICMPV6) {
			sel.ips_is_icmp_inv_acq = 1;
		} else {
			sel.ips_remote_port = dst6->sin6_port;
			sel.ips_local_port = src6->sin6_port;
		}
		sel.ips_isv4 = B_FALSE;
	} else {
		src = (struct sockaddr_in *)(srcext + 1);
		if (src->sin_family != AF_INET) {
			diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
			err = EINVAL;
			goto bail;
		}
		sel.ips_remote_addr_v4 = dst->sin_addr.s_addr;
		sel.ips_local_addr_v4 = src->sin_addr.s_addr;
		if (sel.ips_protocol == IPPROTO_ICMP) {
			sel.ips_is_icmp_inv_acq = 1;
		} else {
			sel.ips_remote_port = dst->sin_port;
			sel.ips_local_port = src->sin_port;
		}
		sel.ips_isv4 = B_TRUE;
	}

	/*
	 * Okay, we have the addresses and other selector information.
	 * Let's first find a conn...
	 */
	pp = NULL; ap = NULL;
	switch (sel.ips_protocol) {
	case IPPROTO_TCP:
		ipsec_tcp_pol(&sel, &pp, &ap);
		break;
	case IPPROTO_UDP:
		ipsec_udp_pol(&sel, &pp, &ap);
		break;
	case IPPROTO_SCTP:
		ipsec_sctp_pol(&sel, &pp, &ap);
		break;
	default:
		ipsec_oth_pol(&sel, &pp, &ap);
		break;
	}

	/*
	 * If we didn't find a matching conn_t, take a look in the global
	 * policy.
	 */
	if ((pp == NULL) && (ap == NULL)) {
		pp = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, NULL, NULL, &sel);
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
	retmp = sadb_extended_acquire(&sel, pp, ap, samsg->sadb_msg_seq,
	    samsg->sadb_msg_pid);
	if (pp != NULL) {
		IPPOL_REFRELE(pp);
	}
	if (ap != NULL) {
		IPACT_REFRELE(ap);
	}
	if (retmp != NULL) {
		return (retmp);
	} else {
		err = ENOMEM;
		diagnostic = 0;
	bail:
		samsg->sadb_msg_errno = (uint8_t)err;
		samsg->sadb_x_msg_diagnostic = (uint16_t)diagnostic;
		return (NULL);
	}
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
sadb_set_lpkt(ipsa_t *ipsa, mblk_t *npkt)
{
	mblk_t *opkt;

	membar_producer();
	do
		opkt = ipsa->ipsa_lpkt;
	while (casptr(&ipsa->ipsa_lpkt, opkt, npkt) != opkt);

	ip_drop_packet(opkt, B_TRUE, NULL, NULL, &ipdrops_sadb_inlarval_replace,
	    &sadb_dropper);
}

/*
 * sadb_clear_lpkt: Atomically clear ipsa->ipsa_lpkt and return the
 * previous value.
 */

mblk_t *
sadb_clear_lpkt(ipsa_t *ipsa)
{
	mblk_t *opkt;

	do
		opkt = ipsa->ipsa_lpkt;
	while (casptr(&ipsa->ipsa_lpkt, opkt, NULL) != opkt);

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
sadb_alg_update(ipsec_algtype_t alg_type, uint8_t alg_id, boolean_t is_added)
{
	struct sadb_update_alg_state update_state;

	update_state.alg_type = alg_type;
	update_state.alg_id = alg_id;
	update_state.is_added = is_added;

	if (alg_type == IPSEC_ALG_AUTH) {
		/* walk the AH tables only for auth. algorithm changes */
		SADB_ALG_UPDATE_WALK(ah_sadb.s_v4, sdb_of);
		SADB_ALG_UPDATE_WALK(ah_sadb.s_v4, sdb_if);
		SADB_ALG_UPDATE_WALK(ah_sadb.s_v6, sdb_of);
		SADB_ALG_UPDATE_WALK(ah_sadb.s_v6, sdb_if);
	}

	/* walk the ESP tables */
	SADB_ALG_UPDATE_WALK(esp_sadb.s_v4, sdb_of);
	SADB_ALG_UPDATE_WALK(esp_sadb.s_v4, sdb_if);
	SADB_ALG_UPDATE_WALK(esp_sadb.s_v6, sdb_of);
	SADB_ALG_UPDATE_WALK(esp_sadb.s_v6, sdb_if);
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

	ASSERT(MUTEX_HELD(&alg_lock));
	ASSERT(MUTEX_HELD(&sa->ipsa_lock));

	/* get pointers to the algorithm info, context template, and key */
	switch (alg_type) {
	case IPSEC_ALG_AUTH:
		key = &sa->ipsa_kcfauthkey;
		sa_tmpl = &sa->ipsa_authtmpl;
		alg = ipsec_alglists[alg_type][sa->ipsa_auth_alg];
		break;
	case IPSEC_ALG_ENCR:
		key = &sa->ipsa_kcfencrkey;
		sa_tmpl = &sa->ipsa_encrtmpl;
		alg = ipsec_alglists[alg_type][sa->ipsa_encr_alg];
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

/* ARGSUSED */
static void
sadb_clear_timeouts_walker(isaf_t *head, ipsa_t *ipsa, void *q)
{
	if (!(ipsa->ipsa_flags & IPSA_F_NATT))
		return;

	mutex_enter(&ipsa->ipsa_lock);
	if (ipsa->ipsa_natt_q != q) {
		mutex_exit(&ipsa->ipsa_lock);
		return;
	}

	(void) quntimeout(ipsa->ipsa_natt_q, ipsa->ipsa_natt_ka_timer);

	ipsa->ipsa_natt_ka_timer = 0;
	ipsa->ipsa_natt_q = NULL;
	mutex_exit(&ipsa->ipsa_lock);
}

void
sadb_clear_timeouts(queue_t *q)
{
	sadb_t *sp = &esp_sadb.s_v4;

	sadb_walker(sp->sdb_if, sp->sdb_hashsize,
	    sadb_clear_timeouts_walker, q);
}
