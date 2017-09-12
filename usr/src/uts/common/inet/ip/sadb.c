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
 * Copyright (c) 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
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
#include <net/pfpolicy.h>
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
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <inet/ip_if.h>
#include <inet/ipdrop.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <sys/tsol/tnet.h>

/*
 * This source file contains Security Association Database (SADB) common
 * routines.  They are linked in with the AH module.  Since AH has no chance
 * of falling under export control, it was safe to link it in there.
 */

static uint8_t *sadb_action_to_ecomb(uint8_t *, uint8_t *, ipsec_action_t *,
    netstack_t *);
static ipsa_t *sadb_torch_assoc(isaf_t *, ipsa_t *);
static void sadb_destroy_acqlist(iacqf_t **, uint_t, boolean_t,
			    netstack_t *);
static void sadb_destroy(sadb_t *, netstack_t *);
static mblk_t *sadb_sa2msg(ipsa_t *, sadb_msg_t *);
static ts_label_t *sadb_label_from_sens(sadb_sens_t *, uint64_t *);

static time_t sadb_add_time(time_t, uint64_t);
static void lifetime_fuzz(ipsa_t *);
static void age_pair_peer_list(templist_t *, sadb_t *, boolean_t);
static int get_ipsa_pair(ipsa_query_t *, ipsap_t *, int *);
static void init_ipsa_pair(ipsap_t *);
static void destroy_ipsa_pair(ipsap_t *);
static int update_pairing(ipsap_t *, ipsa_query_t *, keysock_in_t *, int *);
static void ipsa_set_replay(ipsa_t *ipsa, uint32_t offset);

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
	mblk_t		*asyncmp, *mp;

	ASSERT(ipss != NULL);
	ASSERT(MUTEX_NOT_HELD(&ipsa->ipsa_lock));
	ASSERT(ipsa->ipsa_refcnt == 0);
	ASSERT(ipsa->ipsa_next == NULL);
	ASSERT(ipsa->ipsa_ptpn == NULL);


	asyncmp = sadb_clear_lpkt(ipsa);
	if (asyncmp != NULL) {
		mp = ip_recv_attr_free_mblk(asyncmp);
		ip_drop_packet(mp, B_TRUE, NULL,
		    DROPPER(ipss, ipds_sadb_inlarval_timeout),
		    &ipss->ipsec_sadb_dropper);
	}
	mutex_enter(&ipsa->ipsa_lock);

	if (ipsa->ipsa_tsl != NULL) {
		label_rele(ipsa->ipsa_tsl);
		ipsa->ipsa_tsl = NULL;
	}

	if (ipsa->ipsa_otsl != NULL) {
		label_rele(ipsa->ipsa_otsl);
		ipsa->ipsa_otsl = NULL;
	}

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
	if (ipsa->ipsa_nonce_buf != NULL) {
		bzero(ipsa->ipsa_nonce_buf, sizeof (ipsec_nonce_t));
		kmem_free(ipsa->ipsa_nonce_buf, sizeof (ipsec_nonce_t));
	}
	if (ipsa->ipsa_src_cid != NULL) {
		IPSID_REFRELE(ipsa->ipsa_src_cid);
	}
	if (ipsa->ipsa_dst_cid != NULL) {
		IPSID_REFRELE(ipsa->ipsa_dst_cid);
	}
	if (ipsa->ipsa_emech.cm_param != NULL)
		kmem_free(ipsa->ipsa_emech.cm_param,
		    ipsa->ipsa_emech.cm_param_len);

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

void
sadb_delete_cluster(ipsa_t *assoc)
{
	uint8_t protocol;

	if (cl_inet_deletespi &&
	    ((assoc->ipsa_state == IPSA_STATE_LARVAL) ||
	    (assoc->ipsa_state == IPSA_STATE_MATURE))) {
		protocol = (assoc->ipsa_type == SADB_SATYPE_AH) ?
		    IPPROTO_AH : IPPROTO_ESP;
		cl_inet_deletespi(assoc->ipsa_netstack->netstack_stackid,
		    protocol, assoc->ipsa_spi, NULL);
	}
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
    int num_entries, boolean_t do_peers, time_t active_time)
{
	int i, error = 0;
	mblk_t *original_answer;
	ipsa_t *walker;
	sadb_msg_t *samsg;
	time_t	current;

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

	current = gethrestime_sec();
	for (i = 0; i < num_entries; i++) {
		mutex_enter(&fanout[i].isaf_lock);
		for (walker = fanout[i].isaf_ipsa; walker != NULL;
		    walker = walker->ipsa_next) {
			if (!do_peers && walker->ipsa_haspeer)
				continue;
			if ((active_time != 0) &&
			    ((current - walker->ipsa_lastuse) > active_time))
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
sadb_dump(queue_t *pfkey_q, mblk_t *mp, keysock_in_t *ksi, sadb_t *sp)
{
	int error;
	time_t	active_time = 0;
	sadb_x_edump_t	*edump =
	    (sadb_x_edump_t *)ksi->ks_in_extv[SADB_X_EXT_EDUMP];

	if (edump != NULL) {
		active_time = edump->sadb_x_edump_timeout;
	}

	/* Dump outbound */
	error = sadb_dump_fanout(pfkey_q, mp, ksi->ks_in_serial, sp->sdb_of,
	    sp->sdb_hashsize, B_TRUE, active_time);
	if (error)
		return (error);

	/* Dump inbound */
	return sadb_dump_fanout(pfkey_q, mp, ksi->ks_in_serial, sp->sdb_if,
	    sp->sdb_hashsize, B_FALSE, active_time);
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
 * Call me to free up a security association fanout.  Use the forever
 * variable to indicate freeing up the SAs (forever == B_FALSE, e.g.
 * an SADB_FLUSH message), or destroying everything (forever == B_TRUE,
 * when a module is unloaded).
 */
static void
sadb_destroyer(isaf_t **tablep, uint_t numentries, boolean_t forever,
    boolean_t inbound)
{
	int i;
	isaf_t *table = *tablep;
	uint8_t protocol;
	ipsa_t *sa;
	netstackid_t sid;

	if (table == NULL)
		return;

	for (i = 0; i < numentries; i++) {
		mutex_enter(&table[i].isaf_lock);
		while ((sa = table[i].isaf_ipsa) != NULL) {
			if (inbound && cl_inet_deletespi &&
			    (sa->ipsa_state != IPSA_STATE_ACTIVE_ELSEWHERE) &&
			    (sa->ipsa_state != IPSA_STATE_IDLE)) {
				protocol = (sa->ipsa_type == SADB_SATYPE_AH) ?
				    IPPROTO_AH : IPPROTO_ESP;
				sid = sa->ipsa_netstack->netstack_stackid;
				cl_inet_deletespi(sid, protocol, sa->ipsa_spi,
				    NULL);
			}
			sadb_unlinkassoc(sa);
		}
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
	sadb_destroyer(&sp->sdb_of, sp->sdb_hashsize, B_FALSE, B_FALSE);
	sadb_destroyer(&sp->sdb_if, sp->sdb_hashsize, B_FALSE, B_TRUE);

	/* For each acquire, destroy it; leave the bucket mutex alone. */
	sadb_destroy_acqlist(&sp->sdb_acq, sp->sdb_hashsize, B_FALSE, ns);
}

static void
sadb_destroy(sadb_t *sp, netstack_t *ns)
{
	sadb_destroyer(&sp->sdb_of, sp->sdb_hashsize, B_TRUE, B_FALSE);
	sadb_destroyer(&sp->sdb_if, sp->sdb_hashsize, B_TRUE, B_TRUE);

	/* For each acquire, destroy it, including the bucket mutex. */
	sadb_destroy_acqlist(&sp->sdb_acq, sp->sdb_hashsize, B_TRUE, ns);

	ASSERT(sp->sdb_of == NULL);
	ASSERT(sp->sdb_if == NULL);
	ASSERT(sp->sdb_acq == NULL);
}

void
sadbp_flush(sadbp_t *spp, netstack_t *ns)
{
	sadb_flush(&spp->s_v4, ns);
	sadb_flush(&spp->s_v6, ns);
}

void
sadbp_destroy(sadbp_t *spp, netstack_t *ns)
{
	sadb_destroy(&spp->s_v4, ns);
	sadb_destroy(&spp->s_v6, ns);

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
sadb_hardsoftchk(sadb_lifetime_t *hard, sadb_lifetime_t *soft,
    sadb_lifetime_t *idle)
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

	if (idle != NULL) {
		if (hard->sadb_lifetime_addtime != 0 &&
		    idle->sadb_lifetime_addtime != 0 &&
		    hard->sadb_lifetime_addtime < idle->sadb_lifetime_addtime)
			return (SADB_X_DIAGNOSTIC_ADDTIME_HSERR);

		if (soft->sadb_lifetime_addtime != 0 &&
		    idle->sadb_lifetime_addtime != 0 &&
		    soft->sadb_lifetime_addtime < idle->sadb_lifetime_addtime)
			return (SADB_X_DIAGNOSTIC_ADDTIME_HSERR);

		if (hard->sadb_lifetime_usetime != 0 &&
		    idle->sadb_lifetime_usetime != 0 &&
		    hard->sadb_lifetime_usetime < idle->sadb_lifetime_usetime)
			return (SADB_X_DIAGNOSTIC_USETIME_HSERR);

		if (soft->sadb_lifetime_usetime != 0 &&
		    idle->sadb_lifetime_usetime != 0 &&
		    soft->sadb_lifetime_usetime < idle->sadb_lifetime_usetime)
			return (SADB_X_DIAGNOSTIC_USETIME_HSERR);
	}

	return (0);
}

/*
 * Sanity check sensitivity labels.
 *
 * For now, just reject labels on unlabeled systems.
 */
int
sadb_labelchk(keysock_in_t *ksi)
{
	if (!is_system_labeled()) {
		if (ksi->ks_in_extv[SADB_EXT_SENSITIVITY] != NULL)
			return (SADB_X_DIAGNOSTIC_BAD_LABEL);

		if (ksi->ks_in_extv[SADB_X_EXT_OUTER_SENS] != NULL)
			return (SADB_X_DIAGNOSTIC_BAD_LABEL);
	}

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

	ASSERT(MUTEX_NOT_HELD(&(ipsa->ipsa_lock)));

	newbie = kmem_alloc(sizeof (ipsa_t), KM_NOSLEEP);
	if (newbie == NULL)
		return (NULL);

	/* Copy over what we can. */
	*newbie = *ipsa;

	/* bzero and initialize locks, in case *_init() allocates... */
	mutex_init(&newbie->ipsa_lock, NULL, MUTEX_DEFAULT, NULL);

	if (newbie->ipsa_tsl != NULL)
		label_hold(newbie->ipsa_tsl);

	if (newbie->ipsa_otsl != NULL)
		label_hold(newbie->ipsa_otsl);

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
sadb_make_kmc_ext(uint8_t *cur, uint8_t *end, uint32_t kmp, uint64_t kmc)
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
	kmcext->sadb_x_kmc_cookie64 = kmc;

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
	int srcidsize, dstidsize, senslen, osenslen;
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
	sadb_x_replay_ctr_t *repl_ctr;
	sadb_x_pair_t *pair_ext;

	mblk_t *mp;
	uint8_t *cur, *end;
	/* These indicate the presence of the above extension fields. */
	boolean_t soft = B_FALSE, hard = B_FALSE;
	boolean_t isrc = B_FALSE, idst = B_FALSE;
	boolean_t auth = B_FALSE, encr = B_FALSE;
	boolean_t sensinteg = B_FALSE, osensinteg = B_FALSE;
	boolean_t srcid = B_FALSE, dstid = B_FALSE;
	boolean_t idle;
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
	}

	if (ipsa->ipsa_hardaddlt != 0 || ipsa->ipsa_harduselt != 0 ||
	    ipsa->ipsa_hardbyteslt != 0 || ipsa->ipsa_hardalloc != 0) {
		alloclen += sizeof (sadb_lifetime_t);
		hard = B_TRUE;
	}

	if (ipsa->ipsa_idleaddlt != 0 || ipsa->ipsa_idleuselt != 0) {
		alloclen += sizeof (sadb_lifetime_t);
		idle = B_TRUE;
	} else {
		idle = B_FALSE;
	}

	/* Inner addresses. */
	if (ipsa->ipsa_innerfam != 0) {
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
	}

	if (ipsa->ipsa_encrkeylen != 0) {
		encrsize = roundup(sizeof (sadb_key_t) + ipsa->ipsa_encrkeylen +
		    ipsa->ipsa_nonce_len, sizeof (uint64_t));
		alloclen += encrsize;
		encr = B_TRUE;
	} else {
		encr = B_FALSE;
	}

	if (ipsa->ipsa_tsl != NULL) {
		senslen = sadb_sens_len_from_label(ipsa->ipsa_tsl);
		alloclen += senslen;
		sensinteg = B_TRUE;
	}

	if (ipsa->ipsa_otsl != NULL) {
		osenslen = sadb_sens_len_from_label(ipsa->ipsa_otsl);
		alloclen += osenslen;
		osensinteg = B_TRUE;
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
	}

	if (ipsa->ipsa_dst_cid != NULL) {
		dstidsize = roundup(sizeof (sadb_ident_t) +
		    strlen(ipsa->ipsa_dst_cid->ipsid_cid) + 1,
		    sizeof (uint64_t));
		alloclen += dstidsize;
		dstid = B_TRUE;
	}

	if ((ipsa->ipsa_kmp != 0) || (ipsa->ipsa_kmc != 0))
		alloclen += sizeof (sadb_x_kmc_t);

	if (ipsa->ipsa_replay != 0) {
		alloclen += sizeof (sadb_x_replay_ctr_t);
	}

	/* Make sure the allocation length is a multiple of 8 bytes. */
	ASSERT((alloclen & 0x7) == 0);

	/* XXX Possibly make it esballoc, with a bzero-ing free_ftn. */
	mp = allocb(alloclen, BPRI_HI);
	if (mp == NULL)
		return (NULL);
	bzero(mp->b_rptr, alloclen);

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

	if (idle) {
		lt++;
		lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
		lt->sadb_lifetime_exttype = SADB_X_EXT_LIFETIME_IDLE;
		lt->sadb_lifetime_addtime = ipsa->ipsa_idleaddlt;
		lt->sadb_lifetime_usetime = ipsa->ipsa_idleuselt;
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
		uint8_t *buf_ptr;
		key = (sadb_key_t *)walker;
		key->sadb_key_len = SADB_8TO64(encrsize);
		key->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
		key->sadb_key_bits = ipsa->ipsa_encrkeybits;
		key->sadb_key_reserved = ipsa->ipsa_saltbits;
		buf_ptr = (uint8_t *)(key + 1);
		bcopy(ipsa->ipsa_encrkey, buf_ptr, ipsa->ipsa_encrkeylen);
		if (ipsa->ipsa_salt != NULL) {
			buf_ptr += ipsa->ipsa_encrkeylen;
			bcopy(ipsa->ipsa_salt, buf_ptr, ipsa->ipsa_saltlen);
		}
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
		sadb_sens_from_label(sens, SADB_EXT_SENSITIVITY,
		    ipsa->ipsa_tsl, senslen);

		walker = (sadb_ext_t *)((uint64_t *)walker +
		    walker->sadb_ext_len);
	}

	if (osensinteg) {
		sens = (sadb_sens_t *)walker;

		sadb_sens_from_label(sens, SADB_X_EXT_OUTER_SENS,
		    ipsa->ipsa_otsl, osenslen);
		if (ipsa->ipsa_mac_exempt)
			sens->sadb_x_sens_flags = SADB_X_SENS_IMPLICIT;

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

	if (ipsa->ipsa_replay != 0) {
		repl_ctr = (sadb_x_replay_ctr_t *)walker;
		repl_ctr->sadb_x_rc_len = SADB_8TO64(sizeof (*repl_ctr));
		repl_ctr->sadb_x_rc_exttype = SADB_X_EXT_REPLAY_VALUE;
		repl_ctr->sadb_x_rc_replay32 = ipsa->ipsa_replay;
		repl_ctr->sadb_x_rc_replay64 = 0;
		walker = (sadb_ext_t *)(repl_ctr + 1);
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
		    ext->sadb_ext_type == SADB_X_EXT_EDUMP ||
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
	case SADB_X_DELPAIR_STATE:
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
		if (ksi->ks_in_extv[SADB_EXT_KEY_AUTH] != NULL ||
		    ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT] != NULL ||
		    ksi->ks_in_extv[SADB_X_EXT_EDUMP] != NULL) {
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

	oldq = atomic_cas_ptr((void **)pfkey_qp, NULL, OTHERQ(q));
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
	 * If we made it past the atomic_cas_ptr, then we have "exclusive"
	 * access to the timeout handle.  Fire it off after the default ager
	 * interval.
	 */
	*top = qtimeout(*pfkey_qp, ager, agerarg,
	    drv_usectohz(SADB_AGE_INTERVAL_DEFAULT * 1000));

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
		 * XXX Zones alert -> me/notme decision needs to be tempered
		 * by what zone we're in when we go to zone-aware IPsec.
		 */
		if (ip_type_v6(&sin6->sin6_addr, ns->netstack_ip) ==
		    IRE_LOCAL) {
			/* Hey hey, it's local. */
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
		 * Check if the address is IRE_BROADCAST or IRE_LOCAL.
		 *
		 * XXX Zones alert -> me/notme decision needs to be tempered
		 * by what zone we're in when we go to zone-aware IPsec.
		 */
		type = ip_type_v4(sin->sin_addr.s_addr, ns->netstack_ip);
		switch (type) {
		case IRE_LOCAL:
			return (KS_IN_ADDR_ME);
		case IRE_BROADCAST:
			return (KS_IN_ADDR_MBCAST);
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
 * Match primitives..
 * !!! TODO: short term: inner selectors
 *		ipv6 scope id (ifindex)
 * longer term:  zone id.  sensitivity label. uid.
 */
boolean_t
sadb_match_spi(ipsa_query_t *sq, ipsa_t *sa)
{
	return (sq->spi == sa->ipsa_spi);
}

boolean_t
sadb_match_dst_v6(ipsa_query_t *sq, ipsa_t *sa)
{
	return (IPSA_ARE_ADDR_EQUAL(sa->ipsa_dstaddr, sq->dstaddr, AF_INET6));
}

boolean_t
sadb_match_src_v6(ipsa_query_t *sq, ipsa_t *sa)
{
	return (IPSA_ARE_ADDR_EQUAL(sa->ipsa_srcaddr, sq->srcaddr, AF_INET6));
}

boolean_t
sadb_match_dst_v4(ipsa_query_t *sq, ipsa_t *sa)
{
	return (sq->dstaddr[0] == sa->ipsa_dstaddr[0]);
}

boolean_t
sadb_match_src_v4(ipsa_query_t *sq, ipsa_t *sa)
{
	return (sq->srcaddr[0] == sa->ipsa_srcaddr[0]);
}

boolean_t
sadb_match_dstid(ipsa_query_t *sq, ipsa_t *sa)
{
	return ((sa->ipsa_dst_cid != NULL) &&
	    (sq->didtype == sa->ipsa_dst_cid->ipsid_type) &&
	    (strcmp(sq->didstr, sa->ipsa_dst_cid->ipsid_cid) == 0));

}
boolean_t
sadb_match_srcid(ipsa_query_t *sq, ipsa_t *sa)
{
	return ((sa->ipsa_src_cid != NULL) &&
	    (sq->sidtype == sa->ipsa_src_cid->ipsid_type) &&
	    (strcmp(sq->sidstr, sa->ipsa_src_cid->ipsid_cid) == 0));
}

boolean_t
sadb_match_kmc(ipsa_query_t *sq, ipsa_t *sa)
{
#define	M(a, b) (((a) == 0) || ((b) == 0) || ((a) == (b)))

	return (M(sq->kmc, sa->ipsa_kmc) && M(sq->kmp, sa->ipsa_kmp));

#undef M
}

/*
 * Common function which extracts several PF_KEY extensions for ease of
 * SADB matching.
 *
 * XXX TODO: weed out ipsa_query_t fields not used during matching
 * or afterwards?
 */
int
sadb_form_query(keysock_in_t *ksi, uint32_t req, uint32_t match,
    ipsa_query_t *sq, int *diagnostic)
{
	int i;
	ipsa_match_fn_t *mfpp = &(sq->matchers[0]);

	for (i = 0; i < IPSA_NMATCH; i++)
		sq->matchers[i] = NULL;

	ASSERT((req & ~match) == 0);

	sq->req = req;
	sq->dstext = (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sq->srcext = (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sq->assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];

	if ((req & IPSA_Q_DST) && (sq->dstext == NULL)) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}
	if ((req & IPSA_Q_SRC) && (sq->srcext == NULL)) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return (EINVAL);
	}
	if ((req & IPSA_Q_SA) && (sq->assoc == NULL)) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SA;
		return (EINVAL);
	}

	if (match & IPSA_Q_SA) {
		*mfpp++ = sadb_match_spi;
		sq->spi = sq->assoc->sadb_sa_spi;
	}

	if (sq->dstext != NULL)
		sq->dst = (struct sockaddr_in *)(sq->dstext + 1);
	else {
		sq->dst = NULL;
		sq->dst6 = NULL;
		sq->dstaddr = NULL;
	}

	if (sq->srcext != NULL)
		sq->src = (struct sockaddr_in *)(sq->srcext + 1);
	else {
		sq->src = NULL;
		sq->src6 = NULL;
		sq->srcaddr = NULL;
	}

	if (sq->dst != NULL)
		sq->af = sq->dst->sin_family;
	else if (sq->src != NULL)
		sq->af = sq->src->sin_family;
	else
		sq->af = AF_INET;

	if (sq->af == AF_INET6) {
		if ((match & IPSA_Q_DST) && (sq->dstext != NULL)) {
			*mfpp++ = sadb_match_dst_v6;
			sq->dst6 = (struct sockaddr_in6 *)sq->dst;
			sq->dstaddr = (uint32_t *)&(sq->dst6->sin6_addr);
		} else {
			match &= ~IPSA_Q_DST;
			sq->dstaddr = ALL_ZEROES_PTR;
		}

		if ((match & IPSA_Q_SRC) && (sq->srcext != NULL)) {
			sq->src6 = (struct sockaddr_in6 *)(sq->srcext + 1);
			sq->srcaddr = (uint32_t *)&sq->src6->sin6_addr;
			if (sq->src6->sin6_family != AF_INET6) {
				*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
				return (EINVAL);
			}
			*mfpp++ = sadb_match_src_v6;
		} else {
			match &= ~IPSA_Q_SRC;
			sq->srcaddr = ALL_ZEROES_PTR;
		}
	} else {
		sq->src6 = sq->dst6 = NULL;
		if ((match & IPSA_Q_DST) && (sq->dstext != NULL)) {
			*mfpp++ = sadb_match_dst_v4;
			sq->dstaddr = (uint32_t *)&sq->dst->sin_addr;
		} else {
			match &= ~IPSA_Q_DST;
			sq->dstaddr = ALL_ZEROES_PTR;
		}
		if ((match & IPSA_Q_SRC) && (sq->srcext != NULL)) {
			sq->srcaddr = (uint32_t *)&sq->src->sin_addr;
			if (sq->src->sin_family != AF_INET) {
				*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
				return (EINVAL);
			}
			*mfpp++ = sadb_match_src_v4;
		} else {
			match &= ~IPSA_Q_SRC;
			sq->srcaddr = ALL_ZEROES_PTR;
		}
	}

	sq->dstid = (sadb_ident_t *)ksi->ks_in_extv[SADB_EXT_IDENTITY_DST];
	if ((match & IPSA_Q_DSTID) && (sq->dstid != NULL)) {
		sq->didstr = (char *)(sq->dstid + 1);
		sq->didtype = sq->dstid->sadb_ident_type;
		*mfpp++ = sadb_match_dstid;
	}

	sq->srcid = (sadb_ident_t *)ksi->ks_in_extv[SADB_EXT_IDENTITY_SRC];

	if ((match & IPSA_Q_SRCID) && (sq->srcid != NULL)) {
		sq->sidstr = (char *)(sq->srcid + 1);
		sq->sidtype = sq->srcid->sadb_ident_type;
		*mfpp++ = sadb_match_srcid;
	}

	sq->kmcext = (sadb_x_kmc_t *)ksi->ks_in_extv[SADB_X_EXT_KM_COOKIE];
	sq->kmc = 0;
	sq->kmp = 0;

	if ((match & IPSA_Q_KMC) && (sq->kmcext)) {
		sq->kmp = sq->kmcext->sadb_x_kmc_proto;
		/*
		 * Be liberal in what we receive.  Special-case the IKEv1
		 * cookie, which closed-source in.iked assumes is 32 bits.
		 * Now that we store all 64 bits, we should pre-zero the
		 * reserved field on behalf of closed-source in.iked.
		 */
		if (sq->kmp == SADB_X_KMP_IKE) {
			/* Just in case in.iked is misbehaving... */
			sq->kmcext->sadb_x_kmc_reserved = 0;
		}
		sq->kmc = sq->kmcext->sadb_x_kmc_cookie64;
		*mfpp++ = sadb_match_kmc;
	}

	if (match & (IPSA_Q_INBOUND|IPSA_Q_OUTBOUND)) {
		if (sq->af == AF_INET6)
			sq->sp = &sq->spp->s_v6;
		else
			sq->sp = &sq->spp->s_v4;
	} else {
		sq->sp = NULL;
	}

	if (match & IPSA_Q_INBOUND) {
		sq->inhash = INBOUND_HASH(sq->sp, sq->assoc->sadb_sa_spi);
		sq->inbound = &sq->sp->sdb_if[sq->inhash];
	} else {
		sq->inhash = 0;
		sq->inbound = NULL;
	}

	if (match & IPSA_Q_OUTBOUND) {
		if (sq->af == AF_INET6) {
			sq->outhash = OUTBOUND_HASH_V6(sq->sp, *(sq->dstaddr));
		} else {
			sq->outhash = OUTBOUND_HASH_V4(sq->sp, *(sq->dstaddr));
		}
		sq->outbound = &sq->sp->sdb_of[sq->outhash];
	} else {
		sq->outhash = 0;
		sq->outbound = NULL;
	}
	sq->match = match;
	return (0);
}

/*
 * Match an initialized query structure with a security association;
 * return B_TRUE on a match, B_FALSE on a miss.
 * Applies match functions set up by sadb_form_query() until one returns false.
 */
boolean_t
sadb_match_query(ipsa_query_t *sq, ipsa_t *sa)
{
	ipsa_match_fn_t *mfpp = &(sq->matchers[0]);
	ipsa_match_fn_t mfp;

	for (mfp = *mfpp++; mfp != NULL; mfp = *mfpp++) {
		if (!mfp(sq, sa))
			return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Walker callback function to delete sa's based on src/dst address.
 * Assumes that we're called with *head locked, no other locks held;
 * Conveniently, and not coincidentally, this is both what sadb_walker
 * gives us and also what sadb_unlinkassoc expects.
 */
struct sadb_purge_state
{
	ipsa_query_t sq;
	boolean_t inbnd;
	uint8_t sadb_sa_state;
};

static void
sadb_purge_cb(isaf_t *head, ipsa_t *entry, void *cookie)
{
	struct sadb_purge_state *ps = (struct sadb_purge_state *)cookie;

	ASSERT(MUTEX_HELD(&head->isaf_lock));

	mutex_enter(&entry->ipsa_lock);

	if (entry->ipsa_state == IPSA_STATE_LARVAL ||
	    !sadb_match_query(&ps->sq, entry)) {
		mutex_exit(&entry->ipsa_lock);
		return;
	}

	if (ps->inbnd) {
		sadb_delete_cluster(entry);
	}
	entry->ipsa_state = IPSA_STATE_DEAD;
	(void) sadb_torch_assoc(head, entry);
}

/*
 * Common code to purge an SA with a matching src or dst address.
 * Don't kill larval SA's in such a purge.
 */
int
sadb_purge_sa(mblk_t *mp, keysock_in_t *ksi, sadb_t *sp,
    int *diagnostic, queue_t *pfkey_q)
{
	struct sadb_purge_state ps;
	int error = sadb_form_query(ksi, 0,
	    IPSA_Q_SRC|IPSA_Q_DST|IPSA_Q_SRCID|IPSA_Q_DSTID|IPSA_Q_KMC,
	    &ps.sq, diagnostic);

	if (error != 0)
		return (error);

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

	ASSERT(mp->b_cont != NULL);
	sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr, ksi,
	    NULL);
	return (0);
}

static void
sadb_delpair_state_one(isaf_t *head, ipsa_t *entry, void *cookie)
{
	struct sadb_purge_state *ps = (struct sadb_purge_state *)cookie;
	isaf_t  *inbound_bucket;
	ipsa_t *peer_assoc;
	ipsa_query_t *sq = &ps->sq;

	ASSERT(MUTEX_HELD(&head->isaf_lock));

	mutex_enter(&entry->ipsa_lock);

	if ((entry->ipsa_state != ps->sadb_sa_state) ||
	    ((sq->srcaddr != NULL) &&
	    !IPSA_ARE_ADDR_EQUAL(entry->ipsa_srcaddr, sq->srcaddr, sq->af))) {
		mutex_exit(&entry->ipsa_lock);
		return;
	}

	/*
	 * The isaf_t *, which is passed in , is always an outbound bucket,
	 * and we are preserving the outbound-then-inbound hash-bucket lock
	 * ordering. The sadb_walker() which triggers this function is called
	 * only on the outbound fanout, and the corresponding inbound bucket
	 * lock is safe to acquire here.
	 */

	if (entry->ipsa_haspeer) {
		inbound_bucket = INBOUND_BUCKET(sq->sp, entry->ipsa_spi);
		mutex_enter(&inbound_bucket->isaf_lock);
		peer_assoc = ipsec_getassocbyspi(inbound_bucket,
		    entry->ipsa_spi, entry->ipsa_srcaddr,
		    entry->ipsa_dstaddr, entry->ipsa_addrfam);
	} else {
		inbound_bucket = INBOUND_BUCKET(sq->sp, entry->ipsa_otherspi);
		mutex_enter(&inbound_bucket->isaf_lock);
		peer_assoc = ipsec_getassocbyspi(inbound_bucket,
		    entry->ipsa_otherspi, entry->ipsa_dstaddr,
		    entry->ipsa_srcaddr, entry->ipsa_addrfam);
	}

	entry->ipsa_state = IPSA_STATE_DEAD;
	(void) sadb_torch_assoc(head, entry);
	if (peer_assoc != NULL) {
		mutex_enter(&peer_assoc->ipsa_lock);
		peer_assoc->ipsa_state = IPSA_STATE_DEAD;
		(void) sadb_torch_assoc(inbound_bucket, peer_assoc);
	}
	mutex_exit(&inbound_bucket->isaf_lock);
}

static int
sadb_delpair_state(mblk_t *mp, keysock_in_t *ksi, sadbp_t *spp,
    int *diagnostic, queue_t *pfkey_q)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	struct sadb_purge_state ps;
	int error;

	ps.sq.spp = spp;		/* XXX param */

	error = sadb_form_query(ksi, IPSA_Q_DST|IPSA_Q_SRC,
	    IPSA_Q_SRC|IPSA_Q_DST|IPSA_Q_SRCID|IPSA_Q_DSTID|IPSA_Q_KMC,
	    &ps.sq, diagnostic);
	if (error != 0)
		return (error);

	ps.inbnd = B_FALSE;
	ps.sadb_sa_state = assoc->sadb_sa_state;
	sadb_walker(ps.sq.sp->sdb_of, ps.sq.sp->sdb_hashsize,
	    sadb_delpair_state_one, &ps);

	ASSERT(mp->b_cont != NULL);
	sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr,
	    ksi, NULL);
	return (0);
}

/*
 * Common code to delete/get an SA.
 */
int
sadb_delget_sa(mblk_t *mp, keysock_in_t *ksi, sadbp_t *spp,
    int *diagnostic, queue_t *pfkey_q, uint8_t sadb_msg_type)
{
	ipsa_query_t sq;
	ipsa_t *echo_target = NULL;
	ipsap_t ipsapp;
	uint_t	error = 0;

	if (sadb_msg_type == SADB_X_DELPAIR_STATE)
		return (sadb_delpair_state(mp, ksi, spp, diagnostic, pfkey_q));

	sq.spp = spp;		/* XXX param */
	error = sadb_form_query(ksi, IPSA_Q_DST|IPSA_Q_SA,
	    IPSA_Q_SRC|IPSA_Q_DST|IPSA_Q_SA|IPSA_Q_INBOUND|IPSA_Q_OUTBOUND,
	    &sq, diagnostic);
	if (error != 0)
		return (error);

	error = get_ipsa_pair(&sq, &ipsapp, diagnostic);
	if (error != 0) {
		return (error);
	}

	echo_target = ipsapp.ipsap_sa_ptr;
	if (echo_target == NULL)
		echo_target = ipsapp.ipsap_psa_ptr;

	if (sadb_msg_type == SADB_DELETE || sadb_msg_type == SADB_X_DELPAIR) {
		/*
		 * Bucket locks will be required if SA is actually unlinked.
		 * get_ipsa_pair() returns valid hash bucket pointers even
		 * if it can't find a pair SA pointer. To prevent a potential
		 * deadlock, always lock the outbound bucket before the inbound.
		 */
		if (ipsapp.in_inbound_table) {
			mutex_enter(&ipsapp.ipsap_pbucket->isaf_lock);
			mutex_enter(&ipsapp.ipsap_bucket->isaf_lock);
		} else {
			mutex_enter(&ipsapp.ipsap_bucket->isaf_lock);
			mutex_enter(&ipsapp.ipsap_pbucket->isaf_lock);
		}

		if (ipsapp.ipsap_sa_ptr != NULL) {
			mutex_enter(&ipsapp.ipsap_sa_ptr->ipsa_lock);
			if (ipsapp.ipsap_sa_ptr->ipsa_flags & IPSA_F_INBOUND) {
				sadb_delete_cluster(ipsapp.ipsap_sa_ptr);
			}
			ipsapp.ipsap_sa_ptr->ipsa_state = IPSA_STATE_DEAD;
			(void) sadb_torch_assoc(ipsapp.ipsap_bucket,
			    ipsapp.ipsap_sa_ptr);
			/*
			 * sadb_torch_assoc() releases the ipsa_lock
			 * and calls sadb_unlinkassoc() which does a
			 * IPSA_REFRELE.
			 */
		}
		if (ipsapp.ipsap_psa_ptr != NULL) {
			mutex_enter(&ipsapp.ipsap_psa_ptr->ipsa_lock);
			if (sadb_msg_type == SADB_X_DELPAIR ||
			    ipsapp.ipsap_psa_ptr->ipsa_haspeer) {
				if (ipsapp.ipsap_psa_ptr->ipsa_flags &
				    IPSA_F_INBOUND) {
					sadb_delete_cluster
					    (ipsapp.ipsap_psa_ptr);
				}
				ipsapp.ipsap_psa_ptr->ipsa_state =
				    IPSA_STATE_DEAD;
				(void) sadb_torch_assoc(ipsapp.ipsap_pbucket,
				    ipsapp.ipsap_psa_ptr);
			} else {
				/*
				 * Only half of the "pair" has been deleted.
				 * Update the remaining SA and remove references
				 * to its pair SA, which is now gone.
				 */
				ipsapp.ipsap_psa_ptr->ipsa_otherspi = 0;
				ipsapp.ipsap_psa_ptr->ipsa_flags &=
				    ~IPSA_F_PAIRED;
				mutex_exit(&ipsapp.ipsap_psa_ptr->ipsa_lock);
			}
		} else if (sadb_msg_type == SADB_X_DELPAIR) {
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
			error = ESRCH;
		}
		mutex_exit(&ipsapp.ipsap_bucket->isaf_lock);
		mutex_exit(&ipsapp.ipsap_pbucket->isaf_lock);
	}

	ASSERT(mp->b_cont != NULL);

	if (error == 0)
		sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)
		    mp->b_cont->b_rptr, ksi, echo_target);

	destroy_ipsa_pair(&ipsapp);

	return (error);
}

/*
 * This function takes a sadb_sa_t and finds the ipsa_t structure
 * and the isaf_t (hash bucket) that its stored under. If the security
 * association has a peer, the ipsa_t structure and bucket for that security
 * association are also searched for. The "pair" of ipsa_t's and isaf_t's
 * are returned as a ipsap_t.
 *
 * The hash buckets are returned for convenience, if the calling function
 * needs to use the hash bucket locks, say to remove the SA's, it should
 * take care to observe the convention of locking outbound bucket then
 * inbound bucket. The flag in_inbound_table provides direction.
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
static int
get_ipsa_pair(ipsa_query_t *sq, ipsap_t *ipsapp, int *diagnostic)
{
	uint32_t pair_srcaddr[IPSA_MAX_ADDRLEN];
	uint32_t pair_dstaddr[IPSA_MAX_ADDRLEN];
	uint32_t pair_spi;

	init_ipsa_pair(ipsapp);

	ipsapp->in_inbound_table = B_FALSE;

	/* Lock down both buckets. */
	mutex_enter(&sq->outbound->isaf_lock);
	mutex_enter(&sq->inbound->isaf_lock);

	if (sq->assoc->sadb_sa_flags & IPSA_F_INBOUND) {
		ipsapp->ipsap_sa_ptr = ipsec_getassocbyspi(sq->inbound,
		    sq->assoc->sadb_sa_spi, sq->srcaddr, sq->dstaddr, sq->af);
		if (ipsapp->ipsap_sa_ptr != NULL) {
			ipsapp->ipsap_bucket = sq->inbound;
			ipsapp->ipsap_pbucket = sq->outbound;
			ipsapp->in_inbound_table = B_TRUE;
		} else {
			ipsapp->ipsap_sa_ptr = ipsec_getassocbyspi(sq->outbound,
			    sq->assoc->sadb_sa_spi, sq->srcaddr, sq->dstaddr,
			    sq->af);
			ipsapp->ipsap_bucket = sq->outbound;
			ipsapp->ipsap_pbucket = sq->inbound;
		}
	} else {
		/* IPSA_F_OUTBOUND is set *or* no directions flags set. */
		ipsapp->ipsap_sa_ptr =
		    ipsec_getassocbyspi(sq->outbound,
		    sq->assoc->sadb_sa_spi, sq->srcaddr, sq->dstaddr, sq->af);
		if (ipsapp->ipsap_sa_ptr != NULL) {
			ipsapp->ipsap_bucket = sq->outbound;
			ipsapp->ipsap_pbucket = sq->inbound;
		} else {
			ipsapp->ipsap_sa_ptr = ipsec_getassocbyspi(sq->inbound,
			    sq->assoc->sadb_sa_spi, sq->srcaddr, sq->dstaddr,
			    sq->af);
			ipsapp->ipsap_bucket = sq->inbound;
			ipsapp->ipsap_pbucket = sq->outbound;
			if (ipsapp->ipsap_sa_ptr != NULL)
				ipsapp->in_inbound_table = B_TRUE;
		}
	}

	if (ipsapp->ipsap_sa_ptr == NULL) {
		mutex_exit(&sq->outbound->isaf_lock);
		mutex_exit(&sq->inbound->isaf_lock);
		*diagnostic = SADB_X_DIAGNOSTIC_SA_NOTFOUND;
		return (ESRCH);
	}

	if ((ipsapp->ipsap_sa_ptr->ipsa_state == IPSA_STATE_LARVAL) &&
	    ipsapp->in_inbound_table) {
		mutex_exit(&sq->outbound->isaf_lock);
		mutex_exit(&sq->inbound->isaf_lock);
		return (0);
	}

	mutex_enter(&ipsapp->ipsap_sa_ptr->ipsa_lock);
	if (ipsapp->ipsap_sa_ptr->ipsa_haspeer) {
		/*
		 * haspeer implies no sa_pairing, look for same spi
		 * in other hashtable.
		 */
		ipsapp->ipsap_psa_ptr =
		    ipsec_getassocbyspi(ipsapp->ipsap_pbucket,
		    sq->assoc->sadb_sa_spi, sq->srcaddr, sq->dstaddr, sq->af);
		mutex_exit(&ipsapp->ipsap_sa_ptr->ipsa_lock);
		mutex_exit(&sq->outbound->isaf_lock);
		mutex_exit(&sq->inbound->isaf_lock);
		return (0);
	}
	pair_spi = ipsapp->ipsap_sa_ptr->ipsa_otherspi;
	IPSA_COPY_ADDR(&pair_srcaddr,
	    ipsapp->ipsap_sa_ptr->ipsa_srcaddr, sq->af);
	IPSA_COPY_ADDR(&pair_dstaddr,
	    ipsapp->ipsap_sa_ptr->ipsa_dstaddr, sq->af);
	mutex_exit(&ipsapp->ipsap_sa_ptr->ipsa_lock);
	mutex_exit(&sq->inbound->isaf_lock);
	mutex_exit(&sq->outbound->isaf_lock);

	if (pair_spi == 0) {
		ASSERT(ipsapp->ipsap_bucket != NULL);
		ASSERT(ipsapp->ipsap_pbucket != NULL);
		return (0);
	}

	/* found sa in outbound sadb, peer should be inbound */

	if (ipsapp->in_inbound_table) {
		/* Found SA in inbound table, pair will be in outbound. */
		if (sq->af == AF_INET6) {
			ipsapp->ipsap_pbucket = OUTBOUND_BUCKET_V6(sq->sp,
			    *(uint32_t *)pair_srcaddr);
		} else {
			ipsapp->ipsap_pbucket = OUTBOUND_BUCKET_V4(sq->sp,
			    *(uint32_t *)pair_srcaddr);
		}
	} else {
		ipsapp->ipsap_pbucket = INBOUND_BUCKET(sq->sp, pair_spi);
	}
	mutex_enter(&ipsapp->ipsap_pbucket->isaf_lock);
	ipsapp->ipsap_psa_ptr = ipsec_getassocbyspi(ipsapp->ipsap_pbucket,
	    pair_spi, pair_dstaddr, pair_srcaddr, sq->af);
	mutex_exit(&ipsapp->ipsap_pbucket->isaf_lock);
	ASSERT(ipsapp->ipsap_bucket != NULL);
	ASSERT(ipsapp->ipsap_pbucket != NULL);
	return (0);
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
sadb_common_add(queue_t *pfkey_q, mblk_t *mp, sadb_msg_t *samsg,
    keysock_in_t *ksi, isaf_t *primary, isaf_t *secondary,
    ipsa_t *newbie, boolean_t clone, boolean_t is_inbound, int *diagnostic,
    netstack_t *ns, sadbp_t *spp)
{
	ipsa_t *newbie_clone = NULL, *scratch;
	ipsap_t ipsapp;
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
	sadb_sens_t *sens =
	    (sadb_sens_t *)ksi->ks_in_extv[SADB_EXT_SENSITIVITY];
	sadb_sens_t *osens =
	    (sadb_sens_t *)ksi->ks_in_extv[SADB_X_EXT_OUTER_SENS];
	sadb_x_pair_t *pair_ext =
	    (sadb_x_pair_t *)ksi->ks_in_extv[SADB_X_EXT_PAIR];
	sadb_x_replay_ctr_t *replayext =
	    (sadb_x_replay_ctr_t *)ksi->ks_in_extv[SADB_X_EXT_REPLAY_VALUE];
	uint8_t protocol =
	    (samsg->sadb_msg_satype == SADB_SATYPE_AH) ? IPPROTO_AH:IPPROTO_ESP;
	int salt_offset;
	uint8_t *buf_ptr;
	struct sockaddr_in *src, *dst, *isrc, *idst;
	struct sockaddr_in6 *src6, *dst6, *isrc6, *idst6;
	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];
	sadb_lifetime_t	*idle =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_X_EXT_LIFETIME_IDLE];
	sa_family_t af;
	int error = 0;
	boolean_t isupdate = (newbie != NULL);
	uint32_t *src_addr_ptr, *dst_addr_ptr, *isrc_addr_ptr, *idst_addr_ptr;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ip_stack_t 	*ipst = ns->netstack_ip;
	ipsec_alginfo_t *alg;
	int		rcode;
	boolean_t	async = B_FALSE;

	init_ipsa_pair(&ipsapp);

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

	if (!isupdate && (clone == B_TRUE || is_inbound == B_TRUE) &&
	    cl_inet_checkspi &&
	    (assoc->sadb_sa_state != SADB_X_SASTATE_ACTIVE_ELSEWHERE)) {
		rcode = cl_inet_checkspi(ns->netstack_stackid, protocol,
		    assoc->sadb_sa_spi, NULL);
		if (rcode == -1) {
			return (EEXIST);
		}
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
					*diagnostic =
					    SADB_X_DIAGNOSTIC_INNER_AF_MISMATCH;
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
					*diagnostic =
					    SADB_X_DIAGNOSTIC_INNER_AF_MISMATCH;
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

	ASSERT((assoc->sadb_sa_state == SADB_SASTATE_MATURE) ||
	    (assoc->sadb_sa_state == SADB_X_SASTATE_ACTIVE_ELSEWHERE));
	newbie->ipsa_auth_alg = assoc->sadb_sa_auth;
	newbie->ipsa_encr_alg = assoc->sadb_sa_encrypt;

	newbie->ipsa_flags |= assoc->sadb_sa_flags;
	if (newbie->ipsa_flags & SADB_X_SAFLAGS_NATT_LOC &&
	    ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_LOC] == NULL) {
		mutex_exit(&newbie->ipsa_lock);
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_NATT_LOC;
		error = EINVAL;
		goto error;
	}
	if (newbie->ipsa_flags & SADB_X_SAFLAGS_NATT_REM &&
	    ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_REM] == NULL) {
		mutex_exit(&newbie->ipsa_lock);
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_NATT_REM;
		error = EINVAL;
		goto error;
	}
	if (newbie->ipsa_flags & SADB_X_SAFLAGS_TUNNEL &&
	    ksi->ks_in_extv[SADB_X_EXT_ADDRESS_INNER_SRC] == NULL) {
		mutex_exit(&newbie->ipsa_lock);
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_INNER_SRC;
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
		/*
		 * Be liberal in what we receive.  Special-case the IKEv1
		 * cookie, which closed-source in.iked assumes is 32 bits.
		 * Now that we store all 64 bits, we should pre-zero the
		 * reserved field on behalf of closed-source in.iked.
		 */
		if (newbie->ipsa_kmp == SADB_X_KMP_IKE) {
			/* Just in case in.iked is misbehaving... */
			kmcext->sadb_x_kmc_reserved = 0;
		}
		newbie->ipsa_kmc = kmcext->sadb_x_kmc_cookie64;
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
	if (idle != NULL) {
		newbie->ipsa_idleaddlt = idle->sadb_lifetime_addtime;
		newbie->ipsa_idleuselt = idle->sadb_lifetime_usetime;
		newbie->ipsa_idleexpiretime = newbie->ipsa_addtime +
		    newbie->ipsa_idleaddlt;
		newbie->ipsa_idletime = newbie->ipsa_idleaddlt;
	}

	newbie->ipsa_authtmpl = NULL;
	newbie->ipsa_encrtmpl = NULL;

#ifdef IPSEC_LATENCY_TEST
	if (akey != NULL && newbie->ipsa_auth_alg != SADB_AALG_NONE) {
#else
	if (akey != NULL) {
#endif
		async = (ipss->ipsec_algs_exec_mode[IPSEC_ALG_AUTH] ==
		    IPSEC_ALGS_EXEC_ASYNC);

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

		rw_enter(&ipss->ipsec_alg_lock, RW_READER);
		alg = ipss->ipsec_alglists[IPSEC_ALG_AUTH]
		    [newbie->ipsa_auth_alg];
		if (alg != NULL && ALG_VALID(alg)) {
			newbie->ipsa_amech.cm_type = alg->alg_mech_type;
			newbie->ipsa_amech.cm_param =
			    (char *)&newbie->ipsa_mac_len;
			newbie->ipsa_amech.cm_param_len = sizeof (size_t);
			newbie->ipsa_mac_len = (size_t)alg->alg_datalen;
		} else {
			newbie->ipsa_amech.cm_type = CRYPTO_MECHANISM_INVALID;
		}
		error = ipsec_create_ctx_tmpl(newbie, IPSEC_ALG_AUTH);
		rw_exit(&ipss->ipsec_alg_lock);
		if (error != 0) {
			mutex_exit(&newbie->ipsa_lock);
			/*
			 * An error here indicates that alg is the wrong type
			 * (IE: not authentication) or its not in the alg tables
			 * created by ipsecalgs(1m), or Kcf does not like the
			 * parameters passed in with this algorithm, which is
			 * probably a coding error!
			 */
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_CTX;

			goto error;
		}
	}

	if (ekey != NULL) {
		rw_enter(&ipss->ipsec_alg_lock, RW_READER);
		async = async || (ipss->ipsec_algs_exec_mode[IPSEC_ALG_ENCR] ==
		    IPSEC_ALGS_EXEC_ASYNC);
		alg = ipss->ipsec_alglists[IPSEC_ALG_ENCR]
		    [newbie->ipsa_encr_alg];

		if (alg != NULL && ALG_VALID(alg)) {
			newbie->ipsa_emech.cm_type = alg->alg_mech_type;
			newbie->ipsa_datalen = alg->alg_datalen;
			if (alg->alg_flags & ALG_FLAG_COUNTERMODE)
				newbie->ipsa_flags |= IPSA_F_COUNTERMODE;

			if (alg->alg_flags & ALG_FLAG_COMBINED) {
				newbie->ipsa_flags |= IPSA_F_COMBINED;
				newbie->ipsa_mac_len =  alg->alg_icvlen;
			}

			if (alg->alg_flags & ALG_FLAG_CCM)
				newbie->ipsa_noncefunc = ccm_params_init;
			else if (alg->alg_flags & ALG_FLAG_GCM)
				newbie->ipsa_noncefunc = gcm_params_init;
			else newbie->ipsa_noncefunc = cbc_params_init;

			newbie->ipsa_saltlen = alg->alg_saltlen;
			newbie->ipsa_saltbits = SADB_8TO1(newbie->ipsa_saltlen);
			newbie->ipsa_iv_len = alg->alg_ivlen;
			newbie->ipsa_nonce_len = newbie->ipsa_saltlen +
			    newbie->ipsa_iv_len;
			newbie->ipsa_emech.cm_param = NULL;
			newbie->ipsa_emech.cm_param_len = 0;
		} else {
			newbie->ipsa_emech.cm_type = CRYPTO_MECHANISM_INVALID;
		}
		rw_exit(&ipss->ipsec_alg_lock);

		/*
		 * The byte stream following the sadb_key_t is made up of:
		 * key bytes, [salt bytes], [IV initial value]
		 * All of these have variable length. The IV is typically
		 * randomly generated by this function and not passed in.
		 * By supporting the injection of a known IV, the whole
		 * IPsec subsystem and the underlying crypto subsystem
		 * can be tested with known test vectors.
		 *
		 * The keying material has been checked by ext_check()
		 * and ipsec_valid_key_size(), after removing salt/IV
		 * bits, whats left is the encryption key. If this is too
		 * short, ipsec_create_ctx_tmpl() will fail and the SA
		 * won't get created.
		 *
		 * set ipsa_encrkeylen to length of key only.
		 */
		newbie->ipsa_encrkeybits = ekey->sadb_key_bits;
		newbie->ipsa_encrkeybits -= ekey->sadb_key_reserved;
		newbie->ipsa_encrkeybits -= newbie->ipsa_saltbits;
		newbie->ipsa_encrkeylen = SADB_1TO8(newbie->ipsa_encrkeybits);

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

		buf_ptr = (uint8_t *)(ekey + 1);
		bcopy(buf_ptr, newbie->ipsa_encrkey, newbie->ipsa_encrkeylen);

		if (newbie->ipsa_flags & IPSA_F_COMBINED) {
			/*
			 * Combined mode algs need a nonce. Copy the salt and
			 * IV into a buffer. The ipsa_nonce is a pointer into
			 * this buffer, some bytes at the start of the buffer
			 * may be unused, depends on the salt length. The IV
			 * is 64 bit aligned so it can be incremented as a
			 * uint64_t. Zero out key in samsg_t before freeing.
			 */

			newbie->ipsa_nonce_buf = kmem_alloc(
			    sizeof (ipsec_nonce_t), KM_NOSLEEP);
			if (newbie->ipsa_nonce_buf == NULL) {
				error = ENOMEM;
				mutex_exit(&newbie->ipsa_lock);
				goto error;
			}
			/*
			 * Initialize nonce and salt pointers to point
			 * to the nonce buffer. This is just in case we get
			 * bad data, the pointers will be valid, the data
			 * won't be.
			 *
			 * See sadb.h for layout of nonce.
			 */
			newbie->ipsa_iv = &newbie->ipsa_nonce_buf->iv;
			newbie->ipsa_salt = (uint8_t *)newbie->ipsa_nonce_buf;
			newbie->ipsa_nonce = newbie->ipsa_salt;
			if (newbie->ipsa_saltlen != 0) {
				salt_offset = MAXSALTSIZE -
				    newbie->ipsa_saltlen;
				newbie->ipsa_salt = (uint8_t *)
				    &newbie->ipsa_nonce_buf->salt[salt_offset];
				newbie->ipsa_nonce = newbie->ipsa_salt;
				buf_ptr += newbie->ipsa_encrkeylen;
				bcopy(buf_ptr, newbie->ipsa_salt,
				    newbie->ipsa_saltlen);
			}
			/*
			 * The IV for CCM/GCM mode increments, it should not
			 * repeat. Get a random value for the IV, make a
			 * copy, the SA will expire when/if the IV ever
			 * wraps back to the initial value. If an Initial IV
			 * is passed in via PF_KEY, save this in the SA.
			 * Initialising IV for inbound is pointless as its
			 * taken from the inbound packet.
			 */
			if (!is_inbound) {
				if (ekey->sadb_key_reserved != 0) {
					buf_ptr += newbie->ipsa_saltlen;
					bcopy(buf_ptr, (uint8_t *)newbie->
					    ipsa_iv, SADB_1TO8(ekey->
					    sadb_key_reserved));
				} else {
					(void) random_get_pseudo_bytes(
					    (uint8_t *)newbie->ipsa_iv,
					    newbie->ipsa_iv_len);
				}
				newbie->ipsa_iv_softexpire =
				    (*newbie->ipsa_iv) << 9;
				newbie->ipsa_iv_hardexpire = *newbie->ipsa_iv;
			}
		}
		bzero((ekey + 1), SADB_1TO8(ekey->sadb_key_bits));

		/*
		 * Pre-initialize the kernel crypto framework key
		 * structure.
		 */
		newbie->ipsa_kcfencrkey.ck_format = CRYPTO_KEY_RAW;
		newbie->ipsa_kcfencrkey.ck_length = newbie->ipsa_encrkeybits;
		newbie->ipsa_kcfencrkey.ck_data = newbie->ipsa_encrkey;

		rw_enter(&ipss->ipsec_alg_lock, RW_READER);
		error = ipsec_create_ctx_tmpl(newbie, IPSEC_ALG_ENCR);
		rw_exit(&ipss->ipsec_alg_lock);
		if (error != 0) {
			mutex_exit(&newbie->ipsa_lock);
			/* See above for error explanation. */
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_CTX;
			goto error;
		}
	}

	if (async)
		newbie->ipsa_flags |= IPSA_F_ASYNC;

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

	/*
	 * sensitivity label handling code:
	 * Convert sens + bitmap into cred_t, and associate it
	 * with the new SA.
	 */
	if (sens != NULL) {
		uint64_t *bitmap = (uint64_t *)(sens + 1);

		newbie->ipsa_tsl = sadb_label_from_sens(sens, bitmap);
	}

	/*
	 * Likewise for outer sensitivity.
	 */
	if (osens != NULL) {
		uint64_t *bitmap = (uint64_t *)(osens + 1);
		ts_label_t *tsl, *effective_tsl;
		uint32_t *peer_addr_ptr;
		zoneid_t zoneid = GLOBAL_ZONEID;
		zone_t *zone;

		peer_addr_ptr = is_inbound ? src_addr_ptr : dst_addr_ptr;

		tsl = sadb_label_from_sens(osens, bitmap);
		newbie->ipsa_mac_exempt = CONN_MAC_DEFAULT;

		if (osens->sadb_x_sens_flags & SADB_X_SENS_IMPLICIT) {
			newbie->ipsa_mac_exempt = CONN_MAC_IMPLICIT;
		}

		error = tsol_check_dest(tsl, peer_addr_ptr,
		    (af == AF_INET6)?IPV6_VERSION:IPV4_VERSION,
		    newbie->ipsa_mac_exempt, B_TRUE, &effective_tsl);
		if (error != 0) {
			label_rele(tsl);
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}

		if (effective_tsl != NULL) {
			label_rele(tsl);
			tsl = effective_tsl;
		}

		newbie->ipsa_otsl = tsl;

		zone = zone_find_by_label(tsl);
		if (zone != NULL) {
			zoneid = zone->zone_id;
			zone_rele(zone);
		}
		/*
		 * For exclusive stacks we set the zoneid to zero to operate
		 * as if in the global zone for tsol_compute_label_v4/v6
		 */
		if (ipst->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID)
			zoneid = GLOBAL_ZONEID;

		if (af == AF_INET6) {
			error = tsol_compute_label_v6(tsl, zoneid,
			    (in6_addr_t *)peer_addr_ptr,
			    newbie->ipsa_opt_storage, ipst);
		} else {
			error = tsol_compute_label_v4(tsl, zoneid,
			    *peer_addr_ptr, newbie->ipsa_opt_storage, ipst);
		}
		if (error != 0) {
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
	}


	if (replayext != NULL) {
		if ((replayext->sadb_x_rc_replay32 == 0) &&
		    (replayext->sadb_x_rc_replay64 != 0)) {
			error = EOPNOTSUPP;
			*diagnostic = SADB_X_DIAGNOSTIC_INVALID_REPLAY;
			mutex_exit(&newbie->ipsa_lock);
			goto error;
		}
		newbie->ipsa_replay = replayext->sadb_x_rc_replay32;
	}

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

	ASSERT(MUTEX_NOT_HELD(&newbie->ipsa_lock));
	ASSERT(newbie_clone == NULL ||
	    (MUTEX_NOT_HELD(&newbie_clone->ipsa_lock)));

error_unlock:

	/*
	 * We can exit the locks in any order.	Only entrance needs to
	 * follow any protocol.
	 */
	mutex_exit(&secondary->isaf_lock);
	mutex_exit(&primary->isaf_lock);

	if (pair_ext != NULL && error == 0) {
		/* update pair_spi if it exists. */
		ipsa_query_t sq;

		sq.spp = spp;		/* XXX param */
		error = sadb_form_query(ksi, IPSA_Q_DST, IPSA_Q_SRC|IPSA_Q_DST|
		    IPSA_Q_SA|IPSA_Q_INBOUND|IPSA_Q_OUTBOUND, &sq, diagnostic);
		if (error)
			return (error);

		error = get_ipsa_pair(&sq, &ipsapp, diagnostic);

		if (error != 0)
			goto error;

		if (ipsapp.ipsap_psa_ptr != NULL) {
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_ALREADY;
			error = EINVAL;
		} else {
			/* update_pairing() sets diagnostic */
			error = update_pairing(&ipsapp, &sq, ksi, diagnostic);
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

	destroy_ipsa_pair(&ipsapp);
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
	assoc->ipsa_idleexpiretime = snapshot + assoc->ipsa_idletime;

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
	} else if (assoc->ipsa_state == IPSA_STATE_DYING) {
		expire->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
		expire->sadb_lifetime_allocations = assoc->ipsa_softalloc;
		expire->sadb_lifetime_bytes = assoc->ipsa_softbyteslt;
		expire->sadb_lifetime_addtime = assoc->ipsa_softaddlt;
		expire->sadb_lifetime_usetime = assoc->ipsa_softuselt;
	} else {
		ASSERT(assoc->ipsa_state == IPSA_STATE_MATURE);
		expire->sadb_lifetime_exttype = SADB_X_EXT_LIFETIME_IDLE;
		expire->sadb_lifetime_allocations = 0;
		expire->sadb_lifetime_bytes = 0;
		expire->sadb_lifetime_addtime = assoc->ipsa_idleaddlt;
		expire->sadb_lifetime_usetime = assoc->ipsa_idleuselt;
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
		if (assoc->ipsa_state != IPSA_STATE_DEAD) {
			sadb_delete_cluster(assoc);
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
 * "Torch" an individual SA.  Returns NULL, so it can be tail-called from
 *     sadb_age_assoc().
 */
static ipsa_t *
sadb_torch_assoc(isaf_t *head, ipsa_t *sa)
{
	ASSERT(MUTEX_HELD(&head->isaf_lock));
	ASSERT(MUTEX_HELD(&sa->ipsa_lock));
	ASSERT(sa->ipsa_state == IPSA_STATE_DEAD);

	/*
	 * Force cached SAs to be revalidated..
	 */
	head->isaf_gen++;

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
    time_t current, int reap_delay, boolean_t inbound)
{
	ipsa_t *retval = NULL;
	boolean_t dropped_mutex = B_FALSE;

	ASSERT(MUTEX_HELD(&head->isaf_lock));

	mutex_enter(&assoc->ipsa_lock);

	if (((assoc->ipsa_state == IPSA_STATE_LARVAL) ||
	    ((assoc->ipsa_state == IPSA_STATE_IDLE) ||
	    (assoc->ipsa_state == IPSA_STATE_ACTIVE_ELSEWHERE) &&
	    (assoc->ipsa_hardexpiretime != 0))) &&
	    (assoc->ipsa_hardexpiretime <= current)) {
		assoc->ipsa_state = IPSA_STATE_DEAD;
		return (sadb_torch_assoc(head, assoc));
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
			return (sadb_torch_assoc(head, assoc));

		if (inbound) {
			sadb_delete_cluster(assoc);
		}

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
	} else if (assoc->ipsa_idletime != 0 &&
	    assoc->ipsa_idleexpiretime <= current) {
		if (assoc->ipsa_state == IPSA_STATE_ACTIVE_ELSEWHERE) {
			assoc->ipsa_state = IPSA_STATE_IDLE;
		}

		/*
		 * Need to handle Mature case
		 */
		if (assoc->ipsa_state == IPSA_STATE_MATURE) {
			sadb_expire_assoc(pfkey_q, assoc);
		}
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
sadb_ager(sadb_t *sp, queue_t *pfkey_q, int reap_delay, netstack_t *ns)
{
	int i;
	isaf_t *bucket;
	ipsa_t *assoc, *spare;
	iacqf_t *acqlist;
	ipsacq_t *acqrec, *spareacq;
	templist_t *haspeerlist, *newbie;
	/* Snapshot current time now. */
	time_t current = gethrestime_sec();
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
			    reap_delay, B_TRUE) != NULL) {
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
			    reap_delay, B_FALSE) != NULL) {
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
	uint_t interval = *intp;	/* "interval" is in ms. */

	/*
	 * See how long this took.  If it took too long, increase the
	 * aging interval.
	 */
	if ((end - begin) > MSEC2NSEC(interval)) {
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
	} else if ((end - begin) <= (MSEC2NSEC(interval) / 2) &&
	    interval > SADB_AGE_INTERVAL_DEFAULT) {
		/*
		 * If I took less than half of the interval, then I should
		 * ratchet the interval back down.  Never automatically
		 * shift below the default aging interval.
		 *
		 * NOTE:This even overrides manual setting of the age
		 *	interval using NDD to lower the setting past the
		 *	default.  In other words, if you set the interval
		 *	lower than the default, and your SADB gets too big,
		 *	the interval will only self-lower back to the default.
		 */
		/* Halve by shifting one bit. */
		interval >>= 1;
		interval = max(interval, SADB_AGE_INTERVAL_DEFAULT);
	}
	*intp = interval;
	return (qtimeout(pfkey_q, ager, agerarg,
	    drv_usectohz(interval * (MICROSEC / MILLISEC))));
}


/*
 * Update the lifetime values of an SA.	 This is the path an SADB_UPDATE
 * message takes when updating a MATURE or DYING SA.
 */
static void
sadb_update_lifetimes(ipsa_t *assoc, sadb_lifetime_t *hard,
    sadb_lifetime_t *soft, sadb_lifetime_t *idle, boolean_t outbound)
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

	if (idle != NULL) {
		time_t current = gethrestime_sec();
		if ((assoc->ipsa_idleexpiretime <= current) &&
		    (assoc->ipsa_idleaddlt == idle->sadb_lifetime_addtime)) {
			assoc->ipsa_idleexpiretime =
			    current + assoc->ipsa_idleaddlt;
		}
		if (idle->sadb_lifetime_addtime != 0)
			assoc->ipsa_idleaddlt = idle->sadb_lifetime_addtime;
		if (idle->sadb_lifetime_usetime != 0)
			assoc->ipsa_idleuselt = idle->sadb_lifetime_usetime;
		if (assoc->ipsa_idleaddlt != 0) {
			assoc->ipsa_idleexpiretime =
			    current + idle->sadb_lifetime_addtime;
			assoc->ipsa_idletime = idle->sadb_lifetime_addtime;
		}
		if (assoc->ipsa_idleuselt != 0) {
			if (assoc->ipsa_idletime != 0) {
				assoc->ipsa_idletime = min(assoc->ipsa_idletime,
				    assoc->ipsa_idleuselt);
			assoc->ipsa_idleexpiretime =
			    current + assoc->ipsa_idletime;
			} else {
				assoc->ipsa_idleexpiretime =
				    current + assoc->ipsa_idleuselt;
				assoc->ipsa_idletime = assoc->ipsa_idleuselt;
			}
		}
	}
	mutex_exit(&assoc->ipsa_lock);
}

static int
sadb_update_state(ipsa_t *assoc, uint_t new_state, mblk_t **ipkt_lst)
{
	int rcode = 0;
	time_t current = gethrestime_sec();

	mutex_enter(&assoc->ipsa_lock);

	switch (new_state) {
	case SADB_X_SASTATE_ACTIVE_ELSEWHERE:
		if (assoc->ipsa_state == SADB_X_SASTATE_IDLE) {
			assoc->ipsa_state = IPSA_STATE_ACTIVE_ELSEWHERE;
			assoc->ipsa_idleexpiretime =
			    current + assoc->ipsa_idletime;
		}
		break;
	case SADB_X_SASTATE_IDLE:
		if (assoc->ipsa_state == SADB_X_SASTATE_ACTIVE_ELSEWHERE) {
			assoc->ipsa_state = IPSA_STATE_IDLE;
			assoc->ipsa_idleexpiretime =
			    current + assoc->ipsa_idletime;
		} else {
			rcode = EINVAL;
		}
		break;

	case SADB_X_SASTATE_ACTIVE:
		if (assoc->ipsa_state != SADB_X_SASTATE_IDLE) {
			rcode = EINVAL;
			break;
		}
		assoc->ipsa_state = IPSA_STATE_MATURE;
		assoc->ipsa_idleexpiretime = current + assoc->ipsa_idletime;

		if (ipkt_lst == NULL) {
			break;
		}

		if (assoc->ipsa_bpkt_head != NULL) {
			*ipkt_lst = assoc->ipsa_bpkt_head;
			assoc->ipsa_bpkt_head = assoc->ipsa_bpkt_tail = NULL;
			assoc->ipsa_mblkcnt = 0;
		} else {
			*ipkt_lst = NULL;
		}
		break;
	default:
		rcode = EINVAL;
		break;
	}

	mutex_exit(&assoc->ipsa_lock);
	return (rcode);
}

/*
 * Check a proposed KMC update for sanity.
 */
static int
sadb_check_kmc(ipsa_query_t *sq, ipsa_t *sa, int *diagnostic)
{
	uint32_t kmp = sq->kmp;
	uint64_t kmc = sq->kmc;

	if (sa == NULL)
		return (0);

	if (sa->ipsa_state == IPSA_STATE_DEAD)
		return (ESRCH);	/* DEAD == Not there, in this case. */

	if ((kmp != 0) && (sa->ipsa_kmp != 0) && (sa->ipsa_kmp != kmp)) {
		*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMP;
		return (EINVAL);
	}

	if ((kmc != 0) && (sa->ipsa_kmc != 0) && (sa->ipsa_kmc != kmc)) {
		*diagnostic = SADB_X_DIAGNOSTIC_DUPLICATE_KMC;
		return (EINVAL);
	}

	return (0);
}

/*
 * Actually update the KMC info.
 */
static void
sadb_update_kmc(ipsa_query_t *sq, ipsa_t *sa)
{
	uint32_t kmp = sq->kmp;
	uint64_t kmc = sq->kmc;

	if (kmp != 0)
		sa->ipsa_kmp = kmp;
	if (kmc != 0)
		sa->ipsa_kmc = kmc;
}

/*
 * Common code to update an SA.
 */

int
sadb_update_sa(mblk_t *mp, keysock_in_t *ksi, mblk_t **ipkt_lst,
    sadbp_t *spp, int *diagnostic, queue_t *pfkey_q,
    int (*add_sa_func)(mblk_t *, keysock_in_t *, int *, netstack_t *),
    netstack_t *ns, uint8_t sadb_msg_type)
{
	sadb_key_t *akey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_AUTH];
	sadb_key_t *ekey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT];
	sadb_x_replay_ctr_t *replext =
	    (sadb_x_replay_ctr_t *)ksi->ks_in_extv[SADB_X_EXT_REPLAY_VALUE];
	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];
	sadb_lifetime_t *idle =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_X_EXT_LIFETIME_IDLE];
	sadb_x_pair_t *pair_ext =
	    (sadb_x_pair_t *)ksi->ks_in_extv[SADB_X_EXT_PAIR];
	ipsa_t *echo_target = NULL;
	ipsap_t ipsapp;
	ipsa_query_t sq;
	time_t current = gethrestime_sec();

	sq.spp = spp;		/* XXX param */
	int error = sadb_form_query(ksi, IPSA_Q_SRC|IPSA_Q_DST|IPSA_Q_SA,
	    IPSA_Q_SRC|IPSA_Q_DST|IPSA_Q_SA|IPSA_Q_INBOUND|IPSA_Q_OUTBOUND|
	    IPSA_Q_KMC,
	    &sq, diagnostic);

	if (error != 0)
		return (error);

	error = get_ipsa_pair(&sq, &ipsapp, diagnostic);
	if (error != 0)
		return (error);

	if (ipsapp.ipsap_psa_ptr == NULL && ipsapp.ipsap_sa_ptr != NULL) {
		if (ipsapp.ipsap_sa_ptr->ipsa_state == IPSA_STATE_LARVAL) {
			/*
			 * REFRELE the target and let the add_sa_func()
			 * deal with updating a larval SA.
			 */
			destroy_ipsa_pair(&ipsapp);
			return (add_sa_func(mp, ksi, diagnostic, ns));
		}
	}

	/*
	 * At this point we have an UPDATE to a MATURE SA. There should
	 * not be any keying material present.
	 */
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

	if (sq.assoc->sadb_sa_state == SADB_X_SASTATE_ACTIVE_ELSEWHERE) {
		if (ipsapp.ipsap_sa_ptr != NULL &&
		    ipsapp.ipsap_sa_ptr->ipsa_state == IPSA_STATE_IDLE) {
			if ((error = sadb_update_state(ipsapp.ipsap_sa_ptr,
			    sq.assoc->sadb_sa_state, NULL)) != 0) {
				*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
				goto bail;
			}
		}
		if (ipsapp.ipsap_psa_ptr != NULL &&
		    ipsapp.ipsap_psa_ptr->ipsa_state == IPSA_STATE_IDLE) {
			if ((error = sadb_update_state(ipsapp.ipsap_psa_ptr,
			    sq.assoc->sadb_sa_state, NULL)) != 0) {
				*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
				goto bail;
			}
		}
	}
	if (sq.assoc->sadb_sa_state == SADB_X_SASTATE_ACTIVE) {
		if (ipsapp.ipsap_sa_ptr != NULL) {
			error = sadb_update_state(ipsapp.ipsap_sa_ptr,
			    sq.assoc->sadb_sa_state,
			    (ipsapp.ipsap_sa_ptr->ipsa_flags &
			    IPSA_F_INBOUND) ? ipkt_lst : NULL);
			if (error) {
				*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
				goto bail;
			}
		}
		if (ipsapp.ipsap_psa_ptr != NULL) {
			error = sadb_update_state(ipsapp.ipsap_psa_ptr,
			    sq.assoc->sadb_sa_state,
			    (ipsapp.ipsap_psa_ptr->ipsa_flags &
			    IPSA_F_INBOUND) ? ipkt_lst : NULL);
			if (error) {
				*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
				goto bail;
			}
		}
		sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr,
		    ksi, echo_target);
		goto bail;
	}

	/*
	 * Reality checks for updates of active associations.
	 * Sundry first-pass UPDATE-specific reality checks.
	 * Have to do the checks here, because it's after the add_sa code.
	 * XXX STATS : logging/stats here?
	 */

	if (!((sq.assoc->sadb_sa_state == SADB_SASTATE_MATURE) ||
	    (sq.assoc->sadb_sa_state == SADB_X_SASTATE_ACTIVE_ELSEWHERE))) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
		error = EINVAL;
		goto bail;
	}
	if (sq.assoc->sadb_sa_flags & ~spp->s_updateflags) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SAFLAGS;
		error = EINVAL;
		goto bail;
	}
	if (ksi->ks_in_extv[SADB_EXT_LIFETIME_CURRENT] != NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_LIFETIME;
		error = EOPNOTSUPP;
		goto bail;
	}

	if ((*diagnostic = sadb_hardsoftchk(hard, soft, idle)) != 0) {
		error = EINVAL;
		goto bail;
	}

	if ((*diagnostic = sadb_labelchk(ksi)) != 0)
		return (EINVAL);

	error = sadb_check_kmc(&sq, ipsapp.ipsap_sa_ptr, diagnostic);
	if (error != 0)
		goto bail;

	error = sadb_check_kmc(&sq, ipsapp.ipsap_psa_ptr, diagnostic);
	if (error != 0)
		goto bail;


	if (ipsapp.ipsap_sa_ptr != NULL) {
		/*
		 * Do not allow replay value change for MATURE or LARVAL SA.
		 */

		if ((replext != NULL) &&
		    ((ipsapp.ipsap_sa_ptr->ipsa_state == IPSA_STATE_LARVAL) ||
		    (ipsapp.ipsap_sa_ptr->ipsa_state == IPSA_STATE_MATURE))) {
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
			error = EINVAL;
			goto bail;
		}
	}


	if (ipsapp.ipsap_sa_ptr != NULL) {
		sadb_update_lifetimes(ipsapp.ipsap_sa_ptr, hard, soft,
		    idle, B_TRUE);
		sadb_update_kmc(&sq, ipsapp.ipsap_sa_ptr);
		if ((replext != NULL) &&
		    (ipsapp.ipsap_sa_ptr->ipsa_replay_wsize != 0)) {
			/*
			 * If an inbound SA, update the replay counter
			 * and check off all the other sequence number
			 */
			if (ksi->ks_in_dsttype == KS_IN_ADDR_ME) {
				if (!sadb_replay_check(ipsapp.ipsap_sa_ptr,
				    replext->sadb_x_rc_replay32)) {
					*diagnostic =
					    SADB_X_DIAGNOSTIC_INVALID_REPLAY;
					error = EINVAL;
					goto bail;
				}
				mutex_enter(&ipsapp.ipsap_sa_ptr->ipsa_lock);
				ipsapp.ipsap_sa_ptr->ipsa_idleexpiretime =
				    current +
				    ipsapp.ipsap_sa_ptr->ipsa_idletime;
				mutex_exit(&ipsapp.ipsap_sa_ptr->ipsa_lock);
			} else {
				mutex_enter(&ipsapp.ipsap_sa_ptr->ipsa_lock);
				ipsapp.ipsap_sa_ptr->ipsa_replay =
				    replext->sadb_x_rc_replay32;
				ipsapp.ipsap_sa_ptr->ipsa_idleexpiretime =
				    current +
				    ipsapp.ipsap_sa_ptr->ipsa_idletime;
				mutex_exit(&ipsapp.ipsap_sa_ptr->ipsa_lock);
			}
		}
	}

	if (sadb_msg_type == SADB_X_UPDATEPAIR) {
		if (ipsapp.ipsap_psa_ptr != NULL) {
			sadb_update_lifetimes(ipsapp.ipsap_psa_ptr, hard, soft,
			    idle, B_FALSE);
			sadb_update_kmc(&sq, ipsapp.ipsap_psa_ptr);
		} else {
			*diagnostic = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
			error = ESRCH;
			goto bail;
		}
	}

	if (pair_ext != NULL)
		error = update_pairing(&ipsapp, &sq, ksi, diagnostic);

	if (error == 0)
		sadb_pfkey_echo(pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr,
		    ksi, echo_target);
bail:

	destroy_ipsa_pair(&ipsapp);

	return (error);
}


static int
update_pairing(ipsap_t *ipsapp, ipsa_query_t *sq, keysock_in_t *ksi,
    int *diagnostic)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_x_pair_t *pair_ext =
	    (sadb_x_pair_t *)ksi->ks_in_extv[SADB_X_EXT_PAIR];
	int error = 0;
	ipsap_t oipsapp;
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
	error = get_ipsa_pair(sq, &oipsapp, diagnostic);
	if (error != 0) {
		/*
		 * This should never happen, calling function still has
		 * IPSA_REFHELD on the SA we just updated.
		 */
		return (error);	/* XXX EINVAL instead of ESRCH? */
	}

	if (oipsapp.ipsap_psa_ptr == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE;
		error = EINVAL;
		undo_pair = B_TRUE;
	} else {
		ipsa_flags = oipsapp.ipsap_psa_ptr->ipsa_flags;
		if ((oipsapp.ipsap_psa_ptr->ipsa_state == IPSA_STATE_DEAD) ||
		    (oipsapp.ipsap_psa_ptr->ipsa_state == IPSA_STATE_DYING)) {
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
	} else {
		mutex_enter(&oipsapp.ipsap_psa_ptr->ipsa_lock);
		oipsapp.ipsap_psa_ptr->ipsa_otherspi = assoc->sadb_sa_spi;
		oipsapp.ipsap_psa_ptr->ipsa_flags |= IPSA_F_PAIRED;
		mutex_exit(&oipsapp.ipsap_psa_ptr->ipsa_lock);
	}

	destroy_ipsa_pair(&oipsapp);
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
 *
 * XXX MLS number of arguments getting unwieldy here
 */
static ipsacq_t *
sadb_checkacquire(iacqf_t *bucket, ipsec_action_t *ap, ipsec_policy_t *pp,
    uint32_t *src, uint32_t *dst, uint32_t *isrc, uint32_t *idst,
    uint64_t unique_id, ts_label_t *tsl)
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
		    (unique_id == walker->ipsacq_unique_id) &&
		    (ipsec_label_match(tsl, walker->ipsacq_tsl)))
			break;			/* everything matched */
		mutex_exit(&walker->ipsacq_lock);
	}

	return (walker);
}

/*
 * Generate an SADB_ACQUIRE base message mblk, including KEYSOCK_OUT metadata.
 * In other words, this will return, upon success, a two-mblk chain.
 */
static inline mblk_t *
sadb_acquire_msg_base(minor_t serial, uint8_t satype, uint32_t seq, pid_t pid)
{
	mblk_t *mp;
	sadb_msg_t *samsg;

	mp = sadb_keysock_out(serial);
	if (mp == NULL)
		return (NULL);
	mp->b_cont = allocb(sizeof (sadb_msg_t), BPRI_HI);
	if (mp->b_cont == NULL) {
		freeb(mp);
		return (NULL);
	}

	samsg = (sadb_msg_t *)mp->b_cont->b_rptr;
	mp->b_cont->b_wptr += sizeof (*samsg);
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_ACQUIRE;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_satype = satype;
	samsg->sadb_msg_seq = seq;
	samsg->sadb_msg_pid = pid;

	return (mp);
}

/*
 * Generate address and TX/MLS sensitivity label PF_KEY extensions that are
 * common to both regular and extended ACQUIREs.
 */
static mblk_t *
sadb_acquire_msg_common(ipsec_selector_t *sel, ipsec_policy_t *pp,
    ipsec_action_t *ap, boolean_t tunnel_mode, ts_label_t *tsl,
    sadb_sens_t *sens)
{
	size_t len;
	mblk_t *mp;
	uint8_t *start, *cur, *end;
	uint32_t *saddrptr, *daddrptr;
	sa_family_t af;
	ipsec_action_t *oldap;
	ipsec_selkey_t *ipsl;
	uint8_t proto, pfxlen;
	uint16_t lport, rport;
	int senslen = 0;

	/*
	 * Get action pointer set if it isn't already.
	 */
	oldap = ap;
	if (pp != NULL) {
		ap = pp->ipsp_act;
		if (ap == NULL)
			ap = oldap;
	}

	/*
	 * Biggest-case scenario:
	 * 4x (sadb_address_t + struct sockaddr_in6)
	 *	(src, dst, isrc, idst)
	 *	(COMING SOON, 6x, because of triggering-packet contents.)
	 * sadb_x_kmc_t
	 * sadb_sens_t
	 * And wiggle room for label bitvectors.  Luckily there are
	 * programmatic ways to find it.
	 */
	len = 4 * (sizeof (sadb_address_t) + sizeof (struct sockaddr_in6));

	/* Figure out full and proper length of sensitivity labels. */
	if (sens != NULL) {
		ASSERT(tsl == NULL);
		senslen = SADB_64TO8(sens->sadb_sens_len);
	} else if (tsl != NULL) {
		senslen = sadb_sens_len_from_label(tsl);
	}
#ifdef DEBUG
	else {
		ASSERT(senslen == 0);
	}
#endif /* DEBUG */
	len += senslen;

	mp = allocb(len, BPRI_HI);
	if (mp == NULL)
		return (NULL);

	start = mp->b_rptr;
	end = start + len;
	cur = start;

	/*
	 * Address extensions first, from most-recently-defined to least.
	 * (This should immediately trigger surprise or verify robustness on
	 * older apps, like in.iked.)
	 */
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
		ASSERT(pp != NULL);

		ipsl = &(pp->ipsp_sel->ipsl_key);
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
		 * TODO  - if we go to 3884's dream of transport mode IP-in-IP
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
		/*
		 * For cases when the policy calls out specific ports (or not).
		 */
		proto = 0;
		lport = 0;
		rport = 0;
		if (pp != NULL) {
			ipsl = &(pp->ipsp_sel->ipsl_key);
			if (ipsl->ipsl_valid & IPSL_PROTOCOL)
				proto = ipsl->ipsl_proto;
			if (ipsl->ipsl_valid & IPSL_REMOTE_PORT)
				rport = ipsl->ipsl_rport;
			if (ipsl->ipsl_valid & IPSL_LOCAL_PORT)
				lport = ipsl->ipsl_lport;
		}
	} else {
		/*
		 * For require-unique-SA policies.
		 */
		proto = sel->ips_protocol;
		lport = sel->ips_local_port;
		rport = sel->ips_remote_port;
	}

	/*
	 * Regular addresses.  These are outer-packet ones for tunnel mode.
	 * Or for transport mode, the regulard address & port information.
	 */
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
	 * If present, generate a sensitivity label.
	 */
	if (cur + senslen > end) {
		freeb(mp);
		return (NULL);
	}
	if (sens != NULL) {
		/* Explicit sadb_sens_t, usually from inverse-ACQUIRE. */
		bcopy(sens, cur, senslen);
	} else if (tsl != NULL) {
		/* Generate sadb_sens_t from ACQUIRE source. */
		sadb_sens_from_label((sadb_sens_t *)cur, SADB_EXT_SENSITIVITY,
		    tsl, senslen);
	}
#ifdef DEBUG
	else {
		ASSERT(senslen == 0);
	}
#endif /* DEBUG */
	cur += senslen;
	mp->b_wptr = cur;

	return (mp);
}

/*
 * Generate a regular ACQUIRE's proposal extension and KMC information..
 */
static mblk_t *
sadb_acquire_prop(ipsec_action_t *ap, netstack_t *ns, boolean_t do_esp)
{
	ipsec_stack_t *ipss = ns->netstack_ipsec;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsecah_stack_t *ahstack = ns->netstack_ipsecah;
	mblk_t *mp = NULL;
	sadb_prop_t *prop;
	sadb_comb_t *comb;
	ipsec_action_t *walker;
	int ncombs, allocsize, ealgid, aalgid, aminbits, amaxbits, eminbits,
	    emaxbits, replay;
	uint64_t softbytes, hardbytes, softaddtime, hardaddtime, softusetime,
	    hardusetime;
	uint64_t kmc = 0;
	uint32_t kmp = 0;

	/*
	 * Since it's an rwlock read, AND writing to the IPsec algorithms is
	 * rare, just acquire it once up top, and drop it upon return.
	 */
	rw_enter(&ipss->ipsec_alg_lock, RW_READER);
	if (do_esp) {
		uint64_t num_aalgs, num_ealgs;

		if (espstack->esp_kstats == NULL)
			goto bail;

		num_aalgs = ipss->ipsec_nalgs[IPSEC_ALG_AUTH];
		num_ealgs = ipss->ipsec_nalgs[IPSEC_ALG_ENCR];
		if (num_ealgs == 0)
			goto bail;	/* IPsec not loaded yet, apparently. */
		num_aalgs++;	/* No-auth or self-auth-crypto ESP. */

		/* Use netstack's maximum loaded algorithms... */
		ncombs = num_ealgs * num_aalgs;
		replay =  espstack->ipsecesp_replay_size;
	} else {
		if (ahstack->ah_kstats == NULL)
			goto bail;

		ncombs = ipss->ipsec_nalgs[IPSEC_ALG_AUTH];

		if (ncombs == 0)
			goto bail;	/* IPsec not loaded yet, apparently. */
		replay =  ahstack->ipsecah_replay_size;
	}

	allocsize = sizeof (*prop) + ncombs * sizeof (*comb) +
	    sizeof (sadb_x_kmc_t);
	mp = allocb(allocsize, BPRI_HI);
	if (mp == NULL)
		goto bail;
	prop = (sadb_prop_t *)mp->b_rptr;
	mp->b_wptr += sizeof (*prop);
	comb = (sadb_comb_t *)mp->b_wptr;
	/* Decrement allocsize, if it goes to or below 0, stop. */
	allocsize -= sizeof (*prop);
	prop->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	prop->sadb_prop_len = SADB_8TO64(sizeof (*prop));
	*(uint32_t *)(&prop->sadb_prop_replay) = 0;	/* Quick zero-out! */
	prop->sadb_prop_replay = replay;

	/*
	 * Based upon algorithm properties, and what-not, prioritize a
	 * proposal, based on the ordering of the ESP algorithms in the
	 * alternatives in the policy rule or socket that was placed
	 * in the acquire record.
	 *
	 * For each action in policy list
	 *   Add combination.
	 *   I should not hit it, but if I've hit limit, return.
	 */

	for (walker = ap; walker != NULL; walker = walker->ipa_next) {
		ipsec_alginfo_t *ealg, *aalg;
		ipsec_prot_t *prot;

		if (walker->ipa_act.ipa_type != IPSEC_POLICY_APPLY)
			continue;

		prot = &walker->ipa_act.ipa_apply;
		if (walker->ipa_act.ipa_apply.ipp_km_proto != 0)
			kmp = walker->ipa_act.ipa_apply.ipp_km_proto;
		if (walker->ipa_act.ipa_apply.ipp_km_cookie != 0)
			kmc = walker->ipa_act.ipa_apply.ipp_km_cookie;
		if (walker->ipa_act.ipa_apply.ipp_replay_depth) {
			prop->sadb_prop_replay =
			    walker->ipa_act.ipa_apply.ipp_replay_depth;
		}

		if (do_esp) {
			if (!prot->ipp_use_esp)
				continue;

			if (prot->ipp_esp_auth_alg != 0) {
				aalg = ipss->ipsec_alglists[IPSEC_ALG_AUTH]
				    [prot->ipp_esp_auth_alg];
				if (aalg == NULL || !ALG_VALID(aalg))
					continue;
			} else
				aalg = NULL;

			ASSERT(prot->ipp_encr_alg > 0);
			ealg = ipss->ipsec_alglists[IPSEC_ALG_ENCR]
			    [prot->ipp_encr_alg];
			if (ealg == NULL || !ALG_VALID(ealg))
				continue;

			/*
			 * These may want to come from policy rule..
			 */
			softbytes = espstack->ipsecesp_default_soft_bytes;
			hardbytes = espstack->ipsecesp_default_hard_bytes;
			softaddtime = espstack->ipsecesp_default_soft_addtime;
			hardaddtime = espstack->ipsecesp_default_hard_addtime;
			softusetime = espstack->ipsecesp_default_soft_usetime;
			hardusetime = espstack->ipsecesp_default_hard_usetime;
		} else {
			if (!prot->ipp_use_ah)
				continue;
			ealg = NULL;
			aalg = ipss->ipsec_alglists[IPSEC_ALG_AUTH]
			    [prot->ipp_auth_alg];
			if (aalg == NULL || !ALG_VALID(aalg))
				continue;

			/*
			 * These may want to come from policy rule..
			 */
			softbytes = ahstack->ipsecah_default_soft_bytes;
			hardbytes = ahstack->ipsecah_default_hard_bytes;
			softaddtime = ahstack->ipsecah_default_soft_addtime;
			hardaddtime = ahstack->ipsecah_default_hard_addtime;
			softusetime = ahstack->ipsecah_default_soft_usetime;
			hardusetime = ahstack->ipsecah_default_hard_usetime;
		}

		if (ealg == NULL) {
			ealgid = eminbits = emaxbits = 0;
		} else {
			ealgid = ealg->alg_id;
			eminbits =
			    MAX(prot->ipp_espe_minbits, ealg->alg_ef_minbits);
			emaxbits =
			    MIN(prot->ipp_espe_maxbits, ealg->alg_ef_maxbits);
		}

		if (aalg == NULL) {
			aalgid = aminbits = amaxbits = 0;
		} else {
			aalgid = aalg->alg_id;
			aminbits = MAX(prot->ipp_espa_minbits,
			    aalg->alg_ef_minbits);
			amaxbits = MIN(prot->ipp_espa_maxbits,
			    aalg->alg_ef_maxbits);
		}

		comb->sadb_comb_flags = 0;
		comb->sadb_comb_reserved = 0;
		comb->sadb_comb_encrypt = ealgid;
		comb->sadb_comb_encrypt_minbits = eminbits;
		comb->sadb_comb_encrypt_maxbits = emaxbits;
		comb->sadb_comb_auth = aalgid;
		comb->sadb_comb_auth_minbits = aminbits;
		comb->sadb_comb_auth_maxbits = amaxbits;
		comb->sadb_comb_soft_allocations = 0;
		comb->sadb_comb_hard_allocations = 0;
		comb->sadb_comb_soft_bytes = softbytes;
		comb->sadb_comb_hard_bytes = hardbytes;
		comb->sadb_comb_soft_addtime = softaddtime;
		comb->sadb_comb_hard_addtime = hardaddtime;
		comb->sadb_comb_soft_usetime = softusetime;
		comb->sadb_comb_hard_usetime = hardusetime;

		prop->sadb_prop_len += SADB_8TO64(sizeof (*comb));
		mp->b_wptr += sizeof (*comb);
		allocsize -= sizeof (*comb);
		/* Should never dip BELOW sizeof (KM cookie extension). */
		ASSERT3S(allocsize, >=, sizeof (sadb_x_kmc_t));
		if (allocsize <= sizeof (sadb_x_kmc_t))
			break;	/* out of space.. */
		comb++;
	}

	/* Don't include KMC extension if there's no room. */
	if (((kmp != 0) || (kmc != 0)) && allocsize >= sizeof (sadb_x_kmc_t)) {
		if (sadb_make_kmc_ext(mp->b_wptr,
		    mp->b_wptr + sizeof (sadb_x_kmc_t), kmp, kmc) == NULL) {
			freeb(mp);
			mp = NULL;
			goto bail;
		}
		mp->b_wptr += sizeof (sadb_x_kmc_t);
		prop->sadb_prop_len += SADB_8TO64(sizeof (sadb_x_kmc_t));
	}

bail:
	rw_exit(&ipss->ipsec_alg_lock);
	return (mp);
}

/*
 * Generate an extended ACQUIRE's extended-proposal extension.
 */
static mblk_t *
sadb_acquire_extended_prop(ipsec_action_t *ap, netstack_t *ns)
{
	sadb_prop_t *eprop;
	uint8_t *cur, *end;
	mblk_t *mp;
	int allocsize, numecombs = 0, numalgdescs = 0;
	uint32_t kmp = 0, replay = 0;
	uint64_t kmc = 0;
	ipsec_action_t *walker;

	allocsize = sizeof (*eprop);

	/*
	 * Going to walk through the action list twice.  Once for allocation
	 * measurement, and once for actual construction.
	 */
	for (walker = ap; walker != NULL; walker = walker->ipa_next) {
		ipsec_prot_t *ipp;

		/*
		 * Skip non-IPsec policies
		 */
		if (walker->ipa_act.ipa_type != IPSEC_ACT_APPLY)
			continue;

		ipp = &walker->ipa_act.ipa_apply;

		if (walker->ipa_act.ipa_apply.ipp_km_proto)
			kmp = ipp->ipp_km_proto;
		if (walker->ipa_act.ipa_apply.ipp_km_cookie)
			kmc = ipp->ipp_km_cookie;
		if (walker->ipa_act.ipa_apply.ipp_replay_depth)
			replay = ipp->ipp_replay_depth;

		if (ipp->ipp_use_ah)
			numalgdescs++;
		if (ipp->ipp_use_esp) {
			numalgdescs++;
			if (ipp->ipp_use_espa)
				numalgdescs++;
		}

		numecombs++;
	}
	ASSERT(numecombs > 0);

	allocsize += numecombs * sizeof (sadb_x_ecomb_t) +
	    numalgdescs * sizeof (sadb_x_algdesc_t) + sizeof (sadb_x_kmc_t);
	mp = allocb(allocsize, BPRI_HI);
	if (mp == NULL)
		return (NULL);
	eprop = (sadb_prop_t *)mp->b_rptr;
	end = mp->b_rptr + allocsize;
	cur = mp->b_rptr + sizeof (*eprop);

	eprop->sadb_prop_exttype = SADB_X_EXT_EPROP;
	eprop->sadb_x_prop_ereserved = 0;
	eprop->sadb_x_prop_numecombs = 0;
	*(uint32_t *)(&eprop->sadb_prop_replay) = 0;	/* Quick zero-out! */
	/* Pick ESP's replay default if need be. */
	eprop->sadb_prop_replay = (replay == 0) ?
	    ns->netstack_ipsecesp->ipsecesp_replay_size : replay;

	/* This time, walk through and actually allocate. */
	for (walker = ap; walker != NULL; walker = walker->ipa_next) {
		/*
		 * Skip non-IPsec policies
		 */
		if (walker->ipa_act.ipa_type != IPSEC_ACT_APPLY)
			continue;
		cur = sadb_action_to_ecomb(cur, end, walker, ns);
		if (cur == NULL) {
			/* NOTE: inverse-ACQUIRE should note this as ENOMEM. */
			freeb(mp);
			return (NULL);
		}
		eprop->sadb_x_prop_numecombs++;
	}

	ASSERT(end - cur >= sizeof (sadb_x_kmc_t));
	if ((kmp != 0) || (kmc != 0)) {
		cur = sadb_make_kmc_ext(cur, end, kmp, kmc);
		if (cur == NULL) {
			freeb(mp);
			return (NULL);
		}
	}
	mp->b_wptr = cur;
	eprop->sadb_prop_len = SADB_8TO64(cur - mp->b_rptr);

	return (mp);
}

/*
 * For this mblk, insert a new acquire record.  Assume bucket contains addrs
 * of all of the same length.  Give up (and drop) if memory
 * cannot be allocated for a new one; otherwise, invoke callback to
 * send the acquire up..
 *
 * In cases where we need both AH and ESP, add the SA to the ESP ACQUIRE
 * list.  The ah_add_sa_finish() routines can look at the packet's attached
 * attributes and handle this case specially.
 */
void
sadb_acquire(mblk_t *datamp, ip_xmit_attr_t *ixa, boolean_t need_ah,
    boolean_t need_esp)
{
	mblk_t	*asyncmp, *regular, *extended, *common, *prop, *eprop;
	sadbp_t *spp;
	sadb_t *sp;
	ipsacq_t *newbie;
	iacqf_t *bucket;
	ipha_t *ipha = (ipha_t *)datamp->b_rptr;
	ip6_t *ip6h = (ip6_t *)datamp->b_rptr;
	uint32_t *src, *dst, *isrc, *idst;
	ipsec_policy_t *pp = ixa->ixa_ipsec_policy;
	ipsec_action_t *ap = ixa->ixa_ipsec_action;
	sa_family_t af;
	int hashoffset;
	uint32_t seq;
	uint64_t unique_id = 0;
	boolean_t tunnel_mode = (ixa->ixa_flags & IXAF_IPSEC_TUNNEL) != 0;
	ts_label_t 	*tsl;
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsec_selector_t sel;
	queue_t *q;

	ASSERT((pp != NULL) || (ap != NULL));

	ASSERT(need_ah || need_esp);

	/* Assign sadb pointers */
	if (need_esp) {
		/*
		 * ESP happens first if we need both AH and ESP.
		 */
		spp = &espstack->esp_sadb;
	} else {
		spp = &ahstack->ah_sadb;
	}
	sp = (ixa->ixa_flags & IXAF_IS_IPV4) ? &spp->s_v4 : &spp->s_v6;

	if (is_system_labeled())
		tsl = ixa->ixa_tsl;
	else
		tsl = NULL;

	if (ap == NULL)
		ap = pp->ipsp_act;
	ASSERT(ap != NULL);

	if (ap->ipa_act.ipa_apply.ipp_use_unique || tunnel_mode)
		unique_id = SA_FORM_UNIQUE_ID(ixa);

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
		ASSERT(ixa->ixa_flags & IXAF_IS_IPV4);
	} else {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		src = (uint32_t *)&ip6h->ip6_src;
		dst = (uint32_t *)&ip6h->ip6_dst;
		af = AF_INET6;
		hashoffset = OUTBOUND_HASH_V6(sp, ip6h->ip6_dst);
		ASSERT(!(ixa->ixa_flags & IXAF_IS_IPV4));
	}

	if (tunnel_mode) {
		if (pp == NULL) {
			/*
			 * Tunnel mode with no policy pointer means this is a
			 * reflected ICMP (like a ECHO REQUEST) that came in
			 * with self-encapsulated protection.  Until we better
			 * support this, drop the packet.
			 */
			ip_drop_packet(datamp, B_FALSE, NULL,
			    DROPPER(ipss, ipds_spd_got_selfencap),
			    &ipss->ipsec_spd_dropper);
			return;
		}
		/* Snag inner addresses. */
		isrc = ixa->ixa_ipsec_insrc;
		idst = ixa->ixa_ipsec_indst;
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
	    unique_id, tsl);

	if (newbie == NULL) {
		/*
		 * Otherwise, allocate a new one.
		 */
		newbie = kmem_zalloc(sizeof (*newbie), KM_NOSLEEP);
		if (newbie == NULL) {
			mutex_exit(&bucket->iacqf_lock);
			ip_drop_packet(datamp, B_FALSE, NULL,
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

	/*
	 * XXX MLS does it actually help us to drop the bucket lock here?
	 * we have inserted a half-built, locked acquire record into the
	 * bucket.  any competing thread will now be able to lock the bucket
	 * to scan it, but will immediately pile up on the new acquire
	 * record's lock; I don't think we gain anything here other than to
	 * disperse blame for lock contention.
	 *
	 * we might be able to dispense with acquire record locks entirely..
	 * just use the bucket locks..
	 */

	mutex_exit(&bucket->iacqf_lock);

	/*
	 * This assert looks silly for now, but we may need to enter newbie's
	 * mutex during a search.
	 */
	ASSERT(MUTEX_HELD(&newbie->ipsacq_lock));

	/*
	 * Make the ip_xmit_attr_t into something we can queue.
	 * If no memory it frees datamp.
	 */
	asyncmp = ip_xmit_attr_to_mblk(ixa);
	if (asyncmp != NULL)
		linkb(asyncmp, datamp);

	/* Queue up packet.  Use b_next. */

	if (asyncmp == NULL) {
		/* Statistics for allocation failure */
		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			BUMP_MIB(&ixa->ixa_ipst->ips_ip_mib,
			    ipIfStatsOutDiscards);
		} else {
			BUMP_MIB(&ixa->ixa_ipst->ips_ip6_mib,
			    ipIfStatsOutDiscards);
		}
		ip_drop_output("No memory for asyncmp", datamp, NULL);
		freemsg(datamp);
		/*
		 * The acquire record will be freed quickly if it's new
		 * (ipsacq_expire == 0), and will proceed as if no packet
		 * showed up if not.
		 */
		mutex_exit(&newbie->ipsacq_lock);
		return;
	} else if (newbie->ipsacq_numpackets == 0) {
		/* First one. */
		newbie->ipsacq_mp = asyncmp;
		newbie->ipsacq_numpackets = 1;
		newbie->ipsacq_expire = gethrestime_sec();
		/*
		 * Extended ACQUIRE with both AH+ESP will use ESP's timeout
		 * value.
		 */
		newbie->ipsacq_expire += *spp->s_acquire_timeout;
		newbie->ipsacq_seq = seq;
		newbie->ipsacq_addrfam = af;

		newbie->ipsacq_srcport = ixa->ixa_ipsec_src_port;
		newbie->ipsacq_dstport = ixa->ixa_ipsec_dst_port;
		newbie->ipsacq_icmp_type = ixa->ixa_ipsec_icmp_type;
		newbie->ipsacq_icmp_code = ixa->ixa_ipsec_icmp_code;
		if (tunnel_mode) {
			newbie->ipsacq_inneraddrfam = ixa->ixa_ipsec_inaf;
			newbie->ipsacq_proto = ixa->ixa_ipsec_inaf == AF_INET6 ?
			    IPPROTO_IPV6 : IPPROTO_ENCAP;
			newbie->ipsacq_innersrcpfx = ixa->ixa_ipsec_insrcpfx;
			newbie->ipsacq_innerdstpfx = ixa->ixa_ipsec_indstpfx;
			IPSA_COPY_ADDR(newbie->ipsacq_innersrc,
			    ixa->ixa_ipsec_insrc, ixa->ixa_ipsec_inaf);
			IPSA_COPY_ADDR(newbie->ipsacq_innerdst,
			    ixa->ixa_ipsec_indst, ixa->ixa_ipsec_inaf);
		} else {
			newbie->ipsacq_proto = ixa->ixa_ipsec_proto;
		}
		newbie->ipsacq_unique_id = unique_id;

		if (tsl != NULL) {
			label_hold(tsl);
			newbie->ipsacq_tsl = tsl;
		}
	} else {
		/* Scan to the end of the list & insert. */
		mblk_t *lastone = newbie->ipsacq_mp;

		while (lastone->b_next != NULL)
			lastone = lastone->b_next;
		lastone->b_next = asyncmp;
		if (newbie->ipsacq_numpackets++ == ipsacq_maxpackets) {
			newbie->ipsacq_numpackets = ipsacq_maxpackets;
			lastone = newbie->ipsacq_mp;
			newbie->ipsacq_mp = lastone->b_next;
			lastone->b_next = NULL;

			/* Freeing the async message */
			lastone = ip_xmit_attr_free_mblk(lastone);
			ip_drop_packet(lastone, B_FALSE, NULL,
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

	if (need_esp) {
		ESP_BUMP_STAT(espstack, acquire_requests);
		q = espstack->esp_pfkey_q;
	} else {
		/*
		 * Two cases get us here:
		 * 1.) AH-only policy.
		 *
		 * 2.) A continuation of an AH+ESP policy, and this is the
		 * post-ESP, AH-needs-to-send-a-regular-ACQUIRE case.
		 * (i.e. called from esp_do_outbound_ah().)
		 */
		AH_BUMP_STAT(ahstack, acquire_requests);
		q = ahstack->ah_pfkey_q;
	}

	/*
	 * Get selectors and other policy-expression bits needed for an
	 * ACQUIRE.
	 */
	bzero(&sel, sizeof (sel));
	sel.ips_isv4 = (ixa->ixa_flags & IXAF_IS_IPV4) != 0;
	if (tunnel_mode) {
		sel.ips_protocol = (ixa->ixa_ipsec_inaf == AF_INET) ?
		    IPPROTO_ENCAP : IPPROTO_IPV6;
	} else {
		sel.ips_protocol = ixa->ixa_ipsec_proto;
		sel.ips_local_port = ixa->ixa_ipsec_src_port;
		sel.ips_remote_port = ixa->ixa_ipsec_dst_port;
	}
	sel.ips_icmp_type = ixa->ixa_ipsec_icmp_type;
	sel.ips_icmp_code = ixa->ixa_ipsec_icmp_code;
	sel.ips_is_icmp_inv_acq = 0;
	if (af == AF_INET) {
		sel.ips_local_addr_v4 = ipha->ipha_src;
		sel.ips_remote_addr_v4 = ipha->ipha_dst;
	} else {
		sel.ips_local_addr_v6 = ip6h->ip6_src;
		sel.ips_remote_addr_v6 = ip6h->ip6_dst;
	}


	/*
	 * 1. Generate addresses, kmc, and sensitivity.  These are "common"
	 * and should be an mblk pointed to by common. TBD -- eventually it
	 * will include triggering packet contents as more address extensions.
	 *
	 * 2. Generate ACQUIRE & KEYSOCK_OUT and single-protocol proposal.
	 * These are "regular" and "prop".  String regular->b_cont->b_cont =
	 * common, common->b_cont = prop.
	 *
	 * 3. If extended register got turned on, generate EXT_ACQUIRE &
	 * KEYSOCK_OUT and multi-protocol eprop. These are "extended" and
	 * "eprop".  String extended->b_cont->b_cont = dupb(common) and
	 * extended->b_cont->b_cont->b_cont = prop.
	 *
	 * 4. Deliver:  putnext(q, regular) and if there, putnext(q, extended).
	 */

	regular = extended = prop = eprop = NULL;

	common = sadb_acquire_msg_common(&sel, pp, ap, tunnel_mode, tsl, NULL);
	if (common == NULL)
		goto bail;

	regular = sadb_acquire_msg_base(0, (need_esp ?
	    SADB_SATYPE_ESP : SADB_SATYPE_AH), newbie->ipsacq_seq, 0);
	if (regular == NULL)
		goto bail;

	/*
	 * Pardon the boolean cleverness. At least one of need_* must be true.
	 * If they are equal, it's an AH & ESP policy and ESP needs to go
	 * first.  If they aren't, just check the contents of need_esp.
	 */
	prop = sadb_acquire_prop(ap, ns, need_esp);
	if (prop == NULL)
		goto bail;

	/* Link the parts together. */
	regular->b_cont->b_cont = common;
	common->b_cont = prop;
	/*
	 * Prop is now linked, so don't freemsg() it if the extended
	 * construction goes off the rails.
	 */
	prop = NULL;

	((sadb_msg_t *)(regular->b_cont->b_rptr))->sadb_msg_len =
	    SADB_8TO64(msgsize(regular->b_cont));

	/*
	 * If we need an extended ACQUIRE, build it here.
	 */
	if (keysock_extended_reg(ns)) {
		/* NOTE: "common" still points to what we need. */
		extended = sadb_acquire_msg_base(0, 0, newbie->ipsacq_seq, 0);
		if (extended == NULL) {
			common = NULL;
			goto bail;
		}

		extended->b_cont->b_cont = dupb(common);
		common = NULL;
		if (extended->b_cont->b_cont == NULL)
			goto bail;

		eprop = sadb_acquire_extended_prop(ap, ns);
		if (eprop == NULL)
			goto bail;
		extended->b_cont->b_cont->b_cont = eprop;

		((sadb_msg_t *)(extended->b_cont->b_rptr))->sadb_msg_len =
		    SADB_8TO64(msgsize(extended->b_cont));
	}

	/* So we don't hold a lock across putnext()... */
	mutex_exit(&newbie->ipsacq_lock);

	if (extended != NULL)
		putnext(q, extended);
	ASSERT(regular != NULL);
	putnext(q, regular);
	return;

bail:
	/* Make this acquire record go away quickly... */
	newbie->ipsacq_expire = 0;
	/* Exploit freemsg(NULL) being legal for fun & profit. */
	freemsg(common);
	freemsg(prop);
	freemsg(extended);
	freemsg(regular);
	mutex_exit(&newbie->ipsacq_lock);
}

/*
 * Unlink and free an acquire record.
 */
void
sadb_destroy_acquire(ipsacq_t *acqrec, netstack_t *ns)
{
	mblk_t		*mp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

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

	if (acqrec->ipsacq_tsl != NULL) {
		label_rele(acqrec->ipsacq_tsl);
		acqrec->ipsacq_tsl = NULL;
	}

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
		/* Freeing the async message */
		mp = ip_xmit_attr_free_mblk(mp);
		ip_drop_packet(mp, B_FALSE, NULL,
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
	rw_enter(&ipss->ipsec_alg_lock, RW_READER);
	algp = ipss->ipsec_alglists[(algtype == SADB_X_ALGTYPE_AUTH) ?
	    IPSEC_ALG_AUTH : IPSEC_ALG_ENCR][alg];
	if (algp == NULL) {
		rw_exit(&ipss->ipsec_alg_lock);
		return (NULL);	/* Algorithm doesn't exist.  Fail gracefully. */
	}
	if (minbits < algp->alg_ef_minbits)
		minbits = algp->alg_ef_minbits;
	if (maxbits > algp->alg_ef_maxbits)
		maxbits = algp->alg_ef_maxbits;
	rw_exit(&ipss->ipsec_alg_lock);

	algdesc->sadb_x_algdesc_reserved = SADB_8TO1(algp->alg_saltlen);
	algdesc->sadb_x_algdesc_satype = satype;
	algdesc->sadb_x_algdesc_algtype = algtype;
	algdesc->sadb_x_algdesc_alg = alg;
	algdesc->sadb_x_algdesc_minbits = minbits;
	algdesc->sadb_x_algdesc_maxbits = maxbits;

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

#include <sys/tsol/label_macro.h> /* XXX should not need this */

/*
 * From a cred_t, construct a sensitivity label extension
 *
 * We send up a fixed-size sensitivity label bitmap, and are perhaps
 * overly chummy with the underlying data structures here.
 */

/* ARGSUSED */
int
sadb_sens_len_from_label(ts_label_t *tsl)
{
	int baselen = sizeof (sadb_sens_t) + _C_LEN * 4;
	return (roundup(baselen, sizeof (uint64_t)));
}

void
sadb_sens_from_label(sadb_sens_t *sens, int exttype, ts_label_t *tsl,
    int senslen)
{
	uint8_t *bitmap;
	bslabel_t *sl;

	/* LINTED */
	ASSERT((_C_LEN & 1) == 0);
	ASSERT((senslen & 7) == 0);

	sl = label2bslabel(tsl);

	sens->sadb_sens_exttype = exttype;
	sens->sadb_sens_len = SADB_8TO64(senslen);

	sens->sadb_sens_dpd = tsl->tsl_doi;
	sens->sadb_sens_sens_level = LCLASS(sl);
	sens->sadb_sens_integ_level = 0; /* TBD */
	sens->sadb_sens_sens_len = _C_LEN >> 1;
	sens->sadb_sens_integ_len = 0; /* TBD */
	sens->sadb_x_sens_flags = 0;

	bitmap = (uint8_t *)(sens + 1);
	bcopy(&(((_bslabel_impl_t *)sl)->compartments), bitmap, _C_LEN * 4);
}

/*
 * Okay, how do we report errors/invalid labels from this?
 * With a special designated "not a label" cred_t ?
 */
/* ARGSUSED */
ts_label_t *
sadb_label_from_sens(sadb_sens_t *sens, uint64_t *bitmap)
{
	int bitmap_len = SADB_64TO8(sens->sadb_sens_sens_len);
	bslabel_t sl;
	ts_label_t *tsl;

	if (sens->sadb_sens_integ_level != 0)
		return (NULL);
	if (sens->sadb_sens_integ_len != 0)
		return (NULL);
	if (bitmap_len > _C_LEN * 4)
		return (NULL);

	bsllow(&sl);
	LCLASS_SET((_bslabel_impl_t *)&sl, sens->sadb_sens_sens_level);
	bcopy(bitmap, &((_bslabel_impl_t *)&sl)->compartments,
	    bitmap_len);

	tsl = labelalloc(&sl, sens->sadb_sens_dpd, KM_NOSLEEP);
	if (tsl == NULL)
		return (NULL);

	if (sens->sadb_x_sens_flags & SADB_X_SENS_UNLABELED)
		tsl->tsl_flags |= TSLF_UNLABELED;
	return (tsl);
}

/* End XXX label-library-leakage */

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
    netstack_t *ns, uint_t sa_type)
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
	uint8_t protocol =
	    (sa_type == SADB_SATYPE_AH) ? IPPROTO_AH : IPPROTO_ESP;

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
		if (cl_inet_getspi) {
			cl_inet_getspi(ns->netstack_stackid, protocol,
			    (uint8_t *)&add, sizeof (add), NULL);
		} else {
			(void) random_get_pseudo_bytes((uint8_t *)&add,
			    sizeof (add));
		}
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
 * NOTE:	The pfkey_q parameter may be used in the future for ACQUIRE
 *		failures.
 */
/* ARGSUSED */
void
sadb_in_acquire(sadb_msg_t *samsg, sadbp_t *sp, queue_t *pfkey_q,
    netstack_t *ns)
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
 */
static void
ipsec_conn_pol(ipsec_selector_t *sel, conn_t *connp, ipsec_policy_t **ppp)
{
	ipsec_policy_t	*pp;
	ipsec_latch_t	*ipl = connp->conn_latch;

	if ((ipl != NULL) && (connp->conn_ixa->ixa_ipsec_policy != NULL)) {
		pp = connp->conn_ixa->ixa_ipsec_policy;
		IPPOL_REFHOLD(pp);
	} else {
		pp = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, connp, sel,
		    connp->conn_netstack);
	}
	*ppp = pp;
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

	bzero((void *)&portonly, sizeof (portonly));

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
	CONN_DEC_REF(connp);
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
	CONN_DEC_REF(connp);
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

	/*
	 * For labeled systems, there's no need to check the
	 * label here.  It's known to be good as we checked
	 * before allowing the connection to become bound.
	 */
	if (sel->ips_isv4) {
		in6_addr_t	src, dst;

		IN6_IPADDR_TO_V4MAPPED(sel->ips_remote_addr_v4, &dst);
		IN6_IPADDR_TO_V4MAPPED(sel->ips_local_addr_v4, &src);
		connp = sctp_find_conn(&dst, &src, ports, ALL_ZONES,
		    0, ipst->ips_netstack->netstack_sctp);
	} else {
		connp = sctp_find_conn(&sel->ips_remote_addr_v6,
		    &sel->ips_local_addr_v6, ports, ALL_ZONES,
		    0, ipst->ips_netstack->netstack_sctp);
	}
	if (connp == NULL)
		return;
	ipsec_conn_pol(sel, connp, ppp);
	CONN_DEC_REF(connp);
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
    int *diagnostic)
{
	int err;
	ipsec_policy_head_t *polhead;

	*diagnostic = 0;

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
			if ((err = ipsec_get_inverse_acquire_sel(sel,
			    innsrcext, inndstext, diagnostic)) != 0)
				return (err);
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
			return (0);
		} else if (itp->itp_flags & ITPF_P_TUNNEL) {
			/* Tunnel mode set with no inner selectors. */
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
	*ppp = ipsec_find_policy_head(NULL, polhead, IPSEC_TYPE_INBOUND, sel);
	rw_exit(&polhead->iph_lock);

	/*
	 * Don't default to global if we didn't find a matching policy entry.
	 * Instead, send ENOENT, just like if we hit a transport-mode tunnel.
	 */
	if (*ppp == NULL)
		return (ENOENT);

	return (0);
}

/*
 * For sctp conn_faddr is the primary address, hence this is of limited
 * use for sctp.
 */
static void
ipsec_oth_pol(ipsec_selector_t *sel, ipsec_policy_t **ppp,
    ip_stack_t *ipst)
{
	boolean_t	isv4 = sel->ips_isv4;
	connf_t		*connfp;
	conn_t		*connp;

	if (isv4) {
		connfp = &ipst->ips_ipcl_proto_fanout_v4[sel->ips_protocol];
	} else {
		connfp = &ipst->ips_ipcl_proto_fanout_v6[sel->ips_protocol];
	}

	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		if (isv4) {
			if ((connp->conn_laddr_v4 == INADDR_ANY ||
			    connp->conn_laddr_v4 == sel->ips_local_addr_v4) &&
			    (connp->conn_faddr_v4 == INADDR_ANY ||
			    connp->conn_faddr_v4 == sel->ips_remote_addr_v4))
				break;
		} else {
			if ((IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6) ||
			    IN6_ARE_ADDR_EQUAL(&connp->conn_laddr_v6,
			    &sel->ips_local_addr_v6)) &&
			    (IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6) ||
			    IN6_ARE_ADDR_EQUAL(&connp->conn_faddr_v6,
			    &sel->ips_remote_addr_v6)))
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
	CONN_DEC_REF(connp);
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
 *
 * XXX MLS: key management supplies a label which we just reflect back up
 * again.  clearly we need to involve the label in the rest of the checks.
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
	sadb_sens_t *sens = (sadb_sens_t *)extv[SADB_EXT_SENSITIVITY];
	struct sockaddr_in6 *src, *dst;
	struct sockaddr_in6 *isrc, *idst;
	ipsec_tun_pol_t *itp = NULL;
	ipsec_policy_t *pp = NULL;
	ipsec_selector_t sel, isel;
	mblk_t *retmp = NULL;
	ip_stack_t	*ipst = ns->netstack_ip;


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
		/*
		 * Assume sel.ips_remote_addr_* has the right address at
		 * that exact position.
		 */
		itp = itp_get_byaddr((uint32_t *)(&sel.ips_local_addr_v6),
		    (uint32_t *)(&sel.ips_remote_addr_v6), src->sin6_family,
		    ipst);

		if (innsrcext == NULL) {
			/*
			 * Transport-mode tunnel, make sure we fake out isel
			 * to contain something based on the outer protocol.
			 */
			bzero(&isel, sizeof (isel));
			isel.ips_isv4 = (sel.ips_protocol == IPPROTO_ENCAP);
		} /* Else isel is initialized by ipsec_tun_pol(). */
		err = ipsec_tun_pol(&isel, &pp, innsrcext, inndstext, itp,
		    &diagnostic);
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
		pp = ipsec_find_policy(IPSEC_TYPE_OUTBOUND, NULL, &sel, ns);
		if (pp == NULL) {
			/* There's no global policy. */
			err = ENOENT;
			diagnostic = 0;
			goto bail;
		}
	}

	ASSERT(pp != NULL);
	retmp = sadb_acquire_msg_base(0, 0, samsg->sadb_msg_seq,
	    samsg->sadb_msg_pid);
	if (retmp != NULL) {
		/* Remove KEYSOCK_OUT, because caller constructs it instead. */
		mblk_t *kso = retmp;

		retmp = retmp->b_cont;
		freeb(kso);
		/* Append addresses... */
		retmp->b_cont = sadb_acquire_msg_common(&sel, pp, NULL,
		    (itp != NULL && (itp->itp_flags & ITPF_P_TUNNEL)), NULL,
		    sens);
		if (retmp->b_cont == NULL) {
			freemsg(retmp);
			retmp = NULL;
		}
		/* And the policy result. */
		retmp->b_cont->b_cont =
		    sadb_acquire_extended_prop(pp->ipsp_act, ns);
		if (retmp->b_cont->b_cont == NULL) {
			freemsg(retmp);
			retmp = NULL;
		}
		((sadb_msg_t *)retmp->b_rptr)->sadb_msg_len =
		    SADB_8TO64(msgsize(retmp));
	}

	if (pp != NULL) {
		IPPOL_REFRELE(pp);
	}
	ASSERT(err == 0 && diagnostic == 0);
	if (retmp == NULL)
		err = ENOMEM;
bail:
	if (itp != NULL) {
		ITP_REFRELE(itp, ns);
	}
	samsg->sadb_msg_errno = (uint8_t)err;
	samsg->sadb_x_msg_diagnostic = (uint16_t)diagnostic;
	return (retmp);
}

/*
 * ipsa_lpkt is a one-element queue, only manipulated by the next two
 * functions.  They have to hold the ipsa_lock because of potential races
 * between key management using SADB_UPDATE, and inbound packets that may
 * queue up on the larval SA (hence the 'l' in "lpkt").
 */

/*
 * sadb_set_lpkt:
 *
 * Returns the passed-in packet if the SA is no longer larval.
 *
 * Returns NULL if the SA is larval, and needs to be swapped into the SA for
 * processing after an SADB_UPDATE.
 */
mblk_t *
sadb_set_lpkt(ipsa_t *ipsa, mblk_t *npkt, ip_recv_attr_t *ira)
{
	mblk_t		*opkt;

	mutex_enter(&ipsa->ipsa_lock);
	opkt = ipsa->ipsa_lpkt;
	if (ipsa->ipsa_state == IPSA_STATE_LARVAL) {
		/*
		 * Consume npkt and place it in the LARVAL SA's inbound
		 * packet slot.
		 */
		mblk_t	*attrmp;

		attrmp = ip_recv_attr_to_mblk(ira);
		if (attrmp == NULL) {
			ill_t *ill = ira->ira_ill;

			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", npkt, ill);
			freemsg(npkt);
			opkt = NULL;
		} else {
			ASSERT(attrmp->b_cont == NULL);
			attrmp->b_cont = npkt;
			ipsa->ipsa_lpkt = attrmp;
		}
		npkt = NULL;
	} else {
		/*
		 * If not larval, we lost the race.  NOTE: ipsa_lpkt may still
		 * have been non-NULL in the non-larval case, because of
		 * inbound packets arriving prior to sadb_common_add()
		 * transferring the SA completely out of larval state, but
		 * after lpkt was grabbed by the AH/ESP-specific add routines.
		 * We should clear the old ipsa_lpkt in this case to make sure
		 * that it doesn't linger on the now-MATURE IPsec SA, or get
		 * picked up as an out-of-order packet.
		 */
		ipsa->ipsa_lpkt = NULL;
	}
	mutex_exit(&ipsa->ipsa_lock);

	if (opkt != NULL) {
		ipsec_stack_t	*ipss;

		ipss = ira->ira_ill->ill_ipst->ips_netstack->netstack_ipsec;
		opkt = ip_recv_attr_free_mblk(opkt);
		ip_drop_packet(opkt, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_sadb_inlarval_replace),
		    &ipss->ipsec_sadb_dropper);
	}
	return (npkt);
}

/*
 * sadb_clear_lpkt: Atomically clear ipsa->ipsa_lpkt and return the
 * previous value.
 */
mblk_t *
sadb_clear_lpkt(ipsa_t *ipsa)
{
	mblk_t *opkt;

	mutex_enter(&ipsa->ipsa_lock);
	opkt = ipsa->ipsa_lpkt;
	ipsa->ipsa_lpkt = NULL;
	mutex_exit(&ipsa->ipsa_lock);
	return (opkt);
}

/*
 * Buffer a packet that's in IDLE state as set by Solaris Clustering.
 */
void
sadb_buf_pkt(ipsa_t *ipsa, mblk_t *bpkt, ip_recv_attr_t *ira)
{
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsec_stack_t   *ipss = ns->netstack_ipsec;
	in6_addr_t *srcaddr = (in6_addr_t *)(&ipsa->ipsa_srcaddr);
	in6_addr_t *dstaddr = (in6_addr_t *)(&ipsa->ipsa_dstaddr);
	mblk_t		*mp;

	ASSERT(ipsa->ipsa_state == IPSA_STATE_IDLE);

	if (cl_inet_idlesa == NULL) {
		ip_drop_packet(bpkt, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_sadb_inidle_overflow),
		    &ipss->ipsec_sadb_dropper);
		return;
	}

	cl_inet_idlesa(ns->netstack_stackid,
	    (ipsa->ipsa_type == SADB_SATYPE_AH) ? IPPROTO_AH : IPPROTO_ESP,
	    ipsa->ipsa_spi, ipsa->ipsa_addrfam, *srcaddr, *dstaddr, NULL);

	mp = ip_recv_attr_to_mblk(ira);
	if (mp == NULL) {
		ip_drop_packet(bpkt, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_sadb_inidle_overflow),
		    &ipss->ipsec_sadb_dropper);
		return;
	}
	linkb(mp, bpkt);

	mutex_enter(&ipsa->ipsa_lock);
	ipsa->ipsa_mblkcnt++;
	if (ipsa->ipsa_bpkt_head == NULL) {
		ipsa->ipsa_bpkt_head = ipsa->ipsa_bpkt_tail = bpkt;
	} else {
		ipsa->ipsa_bpkt_tail->b_next = bpkt;
		ipsa->ipsa_bpkt_tail = bpkt;
		if (ipsa->ipsa_mblkcnt > SADB_MAX_IDLEPKTS) {
			mblk_t *tmp;

			tmp = ipsa->ipsa_bpkt_head;
			ipsa->ipsa_bpkt_head = ipsa->ipsa_bpkt_head->b_next;
			tmp = ip_recv_attr_free_mblk(tmp);
			ip_drop_packet(tmp, B_TRUE, NULL,
			    DROPPER(ipss, ipds_sadb_inidle_overflow),
			    &ipss->ipsec_sadb_dropper);
			ipsa->ipsa_mblkcnt --;
		}
	}
	mutex_exit(&ipsa->ipsa_lock);
}

/*
 * Stub function that taskq_dispatch() invokes to take the mblk (in arg)
 * and put into STREAMS again.
 */
void
sadb_clear_buf_pkt(void *ipkt)
{
	mblk_t	*tmp, *buf_pkt;
	ip_recv_attr_t	iras;

	buf_pkt = (mblk_t *)ipkt;

	while (buf_pkt != NULL) {
		mblk_t *data_mp;

		tmp = buf_pkt->b_next;
		buf_pkt->b_next = NULL;

		data_mp = buf_pkt->b_cont;
		buf_pkt->b_cont = NULL;
		if (!ip_recv_attr_from_mblk(buf_pkt, &iras)) {
			/* The ill or ip_stack_t disappeared on us. */
			ip_drop_input("ip_recv_attr_from_mblk", data_mp, NULL);
			freemsg(data_mp);
		} else {
			ip_input_post_ipsec(data_mp, &iras);
		}
		ira_cleanup(&iras, B_TRUE);
		buf_pkt = tmp;
	}
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
	boolean_t async_auth;
	boolean_t async_encr;
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

	if ((entry->ipsa_encr_alg != SADB_EALG_NONE && entry->ipsa_encr_alg !=
	    SADB_EALG_NULL && update_state->async_encr) ||
	    (entry->ipsa_auth_alg != SADB_AALG_NONE &&
	    update_state->async_auth)) {
		entry->ipsa_flags |= IPSA_F_ASYNC;
	} else {
		entry->ipsa_flags &= ~IPSA_F_ASYNC;
	}

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
 * Invoked by IP when an software crypto provider has been updated, or if
 * the crypto synchrony changes.  The type and id of the corresponding
 * algorithm is passed as argument.  The type is set to ALL in the case of
 * a synchrony change.
 *
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
	ipsec_stack_t *ipss = ns->netstack_ipsec;

	update_state.alg_type = alg_type;
	update_state.alg_id = alg_id;
	update_state.is_added = is_added;
	update_state.async_auth = ipss->ipsec_algs_exec_mode[IPSEC_ALG_AUTH] ==
	    IPSEC_ALGS_EXEC_ASYNC;
	update_state.async_encr = ipss->ipsec_algs_exec_mode[IPSEC_ALG_ENCR] ==
	    IPSEC_ALGS_EXEC_ASYNC;

	if (alg_type == IPSEC_ALG_AUTH || alg_type == IPSEC_ALG_ALL) {
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

	ASSERT(RW_READ_HELD(&ipss->ipsec_alg_lock));
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
 * Whack options in the outer IP header when ipsec changes the outer label
 *
 * This is inelegant and really could use refactoring.
 */
mblk_t *
sadb_whack_label_v4(mblk_t *mp, ipsa_t *assoc, kstat_named_t *counter,
    ipdropper_t *dropper)
{
	int delta;
	int plen;
	dblk_t *db;
	int hlen;
	uint8_t *opt_storage = assoc->ipsa_opt_storage;
	ipha_t *ipha = (ipha_t *)mp->b_rptr;

	plen = ntohs(ipha->ipha_length);

	delta = tsol_remove_secopt(ipha, MBLKL(mp));
	mp->b_wptr += delta;
	plen += delta;

	/* XXX XXX code copied from tsol_check_label */

	/* Make sure we have room for the worst-case addition */
	hlen = IPH_HDR_LENGTH(ipha) + opt_storage[IPOPT_OLEN];
	hlen = (hlen + 3) & ~3;
	if (hlen > IP_MAX_HDR_LENGTH)
		hlen = IP_MAX_HDR_LENGTH;
	hlen -= IPH_HDR_LENGTH(ipha);

	db = mp->b_datap;
	if ((db->db_ref != 1) || (mp->b_wptr + hlen > db->db_lim)) {
		int copylen;
		mblk_t *new_mp;

		/* allocate enough to be meaningful, but not *too* much */
		copylen = MBLKL(mp);
		if (copylen > 256)
			copylen = 256;
		new_mp = allocb_tmpl(hlen + copylen +
		    (mp->b_rptr - mp->b_datap->db_base), mp);

		if (new_mp == NULL) {
			ip_drop_packet(mp, B_FALSE, NULL, counter,  dropper);
			return (NULL);
		}

		/* keep the bias */
		new_mp->b_rptr += mp->b_rptr - mp->b_datap->db_base;
		new_mp->b_wptr = new_mp->b_rptr + copylen;
		bcopy(mp->b_rptr, new_mp->b_rptr, copylen);
		new_mp->b_cont = mp;
		if ((mp->b_rptr += copylen) >= mp->b_wptr) {
			new_mp->b_cont = mp->b_cont;
			freeb(mp);
		}
		mp = new_mp;
		ipha = (ipha_t *)mp->b_rptr;
	}

	delta = tsol_prepend_option(assoc->ipsa_opt_storage, ipha, MBLKL(mp));

	ASSERT(delta != -1);

	plen += delta;
	mp->b_wptr += delta;

	/*
	 * Paranoia
	 */
	db = mp->b_datap;

	ASSERT3P(mp->b_wptr, <=, db->db_lim);
	ASSERT3P(mp->b_rptr, <=, db->db_lim);

	ASSERT3P(mp->b_wptr, >=, db->db_base);
	ASSERT3P(mp->b_rptr, >=, db->db_base);
	/* End paranoia */

	ipha->ipha_length = htons(plen);

	return (mp);
}

mblk_t *
sadb_whack_label_v6(mblk_t *mp, ipsa_t *assoc, kstat_named_t *counter,
    ipdropper_t *dropper)
{
	int delta;
	int plen;
	dblk_t *db;
	int hlen;
	uint8_t *opt_storage = assoc->ipsa_opt_storage;
	uint_t sec_opt_len; /* label option length not including type, len */
	ip6_t *ip6h = (ip6_t *)mp->b_rptr;

	plen = ntohs(ip6h->ip6_plen);

	delta = tsol_remove_secopt_v6(ip6h, MBLKL(mp));
	mp->b_wptr += delta;
	plen += delta;

	/* XXX XXX code copied from tsol_check_label_v6 */
	/*
	 * Make sure we have room for the worst-case addition. Add 2 bytes for
	 * the hop-by-hop ext header's next header and length fields. Add
	 * another 2 bytes for the label option type, len and then round
	 * up to the next 8-byte multiple.
	 */
	sec_opt_len = opt_storage[1];

	db = mp->b_datap;
	hlen = (4 + sec_opt_len + 7) & ~7;

	if ((db->db_ref != 1) || (mp->b_wptr + hlen > db->db_lim)) {
		int copylen;
		mblk_t *new_mp;
		uint16_t hdr_len;

		hdr_len = ip_hdr_length_v6(mp, ip6h);
		/*
		 * Allocate enough to be meaningful, but not *too* much.
		 * Also all the IPv6 extension headers must be in the same mblk
		 */
		copylen = MBLKL(mp);
		if (copylen > 256)
			copylen = 256;
		if (copylen < hdr_len)
			copylen = hdr_len;
		new_mp = allocb_tmpl(hlen + copylen +
		    (mp->b_rptr - mp->b_datap->db_base), mp);
		if (new_mp == NULL) {
			ip_drop_packet(mp, B_FALSE, NULL, counter,  dropper);
			return (NULL);
		}

		/* keep the bias */
		new_mp->b_rptr += mp->b_rptr - mp->b_datap->db_base;
		new_mp->b_wptr = new_mp->b_rptr + copylen;
		bcopy(mp->b_rptr, new_mp->b_rptr, copylen);
		new_mp->b_cont = mp;
		if ((mp->b_rptr += copylen) >= mp->b_wptr) {
			new_mp->b_cont = mp->b_cont;
			freeb(mp);
		}
		mp = new_mp;
		ip6h = (ip6_t *)mp->b_rptr;
	}

	delta = tsol_prepend_option_v6(assoc->ipsa_opt_storage,
	    ip6h, MBLKL(mp));

	ASSERT(delta != -1);

	plen += delta;
	mp->b_wptr += delta;

	/*
	 * Paranoia
	 */
	db = mp->b_datap;

	ASSERT3P(mp->b_wptr, <=, db->db_lim);
	ASSERT3P(mp->b_rptr, <=, db->db_lim);

	ASSERT3P(mp->b_wptr, >=, db->db_base);
	ASSERT3P(mp->b_rptr, >=, db->db_base);
	/* End paranoia */

	ip6h->ip6_plen = htons(plen);

	return (mp);
}

/* Whack the labels and update ip_xmit_attr_t as needed */
mblk_t *
sadb_whack_label(mblk_t *mp, ipsa_t *assoc, ip_xmit_attr_t *ixa,
    kstat_named_t *counter, ipdropper_t *dropper)
{
	int adjust;
	int iplen;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t		*ipha = (ipha_t *)mp->b_rptr;

		ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);
		iplen = ntohs(ipha->ipha_length);
		mp = sadb_whack_label_v4(mp, assoc, counter, dropper);
		if (mp == NULL)
			return (NULL);

		ipha = (ipha_t *)mp->b_rptr;
		ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);
		adjust = (int)ntohs(ipha->ipha_length) - iplen;
	} else {
		ip6_t		*ip6h = (ip6_t *)mp->b_rptr;

		ASSERT(IPH_HDR_VERSION(ip6h) == IPV6_VERSION);
		iplen = ntohs(ip6h->ip6_plen);
		mp = sadb_whack_label_v6(mp, assoc, counter, dropper);
		if (mp == NULL)
			return (NULL);

		ip6h = (ip6_t *)mp->b_rptr;
		ASSERT(IPH_HDR_VERSION(ip6h) == IPV6_VERSION);
		adjust = (int)ntohs(ip6h->ip6_plen) - iplen;
	}
	ixa->ixa_pktlen += adjust;
	ixa->ixa_ip_hdr_length += adjust;
	return (mp);
}

/*
 * If this is an outgoing SA then add some fuzz to the
 * SOFT EXPIRE time. The reason for this is to stop
 * peers trying to renegotiate SOFT expiring SA's at
 * the same time. The amount of fuzz needs to be at
 * least 8 seconds which is the typical interval
 * sadb_ager(), although this is only a guide as it
 * selftunes.
 */
static void
lifetime_fuzz(ipsa_t *assoc)
{
	uint8_t rnd;

	if (assoc->ipsa_softaddlt == 0)
		return;

	(void) random_get_pseudo_bytes(&rnd, sizeof (rnd));
	rnd = (rnd & 0xF) + 8;
	assoc->ipsa_softexpiretime -= rnd;
	assoc->ipsa_softaddlt -= rnd;
}

static void
destroy_ipsa_pair(ipsap_t *ipsapp)
{
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
	init_ipsa_pair(ipsapp);
}

static void
init_ipsa_pair(ipsap_t *ipsapp)
{
	ipsapp->ipsap_bucket = NULL;
	ipsapp->ipsap_sa_ptr = NULL;
	ipsapp->ipsap_pbucket = NULL;
	ipsapp->ipsap_psa_ptr = NULL;
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

/*
 * Ensure that the IV used for CCM mode never repeats. The IV should
 * only be updated by this function. Also check to see if the IV
 * is about to wrap and generate a SOFT Expire. This function is only
 * called for outgoing packets, the IV for incomming packets is taken
 * from the wire. If the outgoing SA needs to be expired, update
 * the matching incomming SA.
 */
boolean_t
update_iv(uint8_t *iv_ptr, queue_t *pfkey_q, ipsa_t *assoc,
    ipsecesp_stack_t *espstack)
{
	boolean_t rc = B_TRUE;
	isaf_t *inbound_bucket;
	sadb_t *sp;
	ipsa_t *pair_sa = NULL;
	int sa_new_state = 0;

	/* For non counter modes, the IV is random data. */
	if (!(assoc->ipsa_flags & IPSA_F_COUNTERMODE)) {
		(void) random_get_pseudo_bytes(iv_ptr, assoc->ipsa_iv_len);
		return (rc);
	}

	mutex_enter(&assoc->ipsa_lock);

	(*assoc->ipsa_iv)++;

	if (*assoc->ipsa_iv == assoc->ipsa_iv_hardexpire) {
		sa_new_state = IPSA_STATE_DEAD;
		rc = B_FALSE;
	} else if (*assoc->ipsa_iv == assoc->ipsa_iv_softexpire) {
		if (assoc->ipsa_state != IPSA_STATE_DYING) {
			/*
			 * This SA may have already been expired when its
			 * PAIR_SA expired.
			 */
			sa_new_state = IPSA_STATE_DYING;
		}
	}
	if (sa_new_state) {
		/*
		 * If there is a state change, we need to update this SA
		 * and its "pair", we can find the bucket for the "pair" SA
		 * while holding the ipsa_t mutex, but we won't actually
		 * update anything untill the ipsa_t mutex has been released
		 * for _this_ SA.
		 */
		assoc->ipsa_state = sa_new_state;
		if (assoc->ipsa_addrfam == AF_INET6) {
			sp = &espstack->esp_sadb.s_v6;
		} else {
			sp = &espstack->esp_sadb.s_v4;
		}
		inbound_bucket = INBOUND_BUCKET(sp, assoc->ipsa_otherspi);
		sadb_expire_assoc(pfkey_q, assoc);
	}
	if (rc == B_TRUE)
		bcopy(assoc->ipsa_iv, iv_ptr, assoc->ipsa_iv_len);

	mutex_exit(&assoc->ipsa_lock);

	if (sa_new_state) {
		/* Find the inbound SA, need to lock hash bucket. */
		mutex_enter(&inbound_bucket->isaf_lock);
		pair_sa = ipsec_getassocbyspi(inbound_bucket,
		    assoc->ipsa_otherspi, assoc->ipsa_dstaddr,
		    assoc->ipsa_srcaddr, assoc->ipsa_addrfam);
		mutex_exit(&inbound_bucket->isaf_lock);
		if (pair_sa != NULL) {
			mutex_enter(&pair_sa->ipsa_lock);
			pair_sa->ipsa_state = sa_new_state;
			mutex_exit(&pair_sa->ipsa_lock);
			IPSA_REFRELE(pair_sa);
		}
	}

	return (rc);
}

void
ccm_params_init(ipsa_t *assoc, uchar_t *esph, uint_t data_len, uchar_t *iv_ptr,
    ipsa_cm_mech_t *cm_mech, crypto_data_t *crypto_data)
{
	uchar_t *nonce;
	crypto_mechanism_t *combined_mech;
	CK_AES_CCM_PARAMS *params;

	combined_mech = (crypto_mechanism_t *)cm_mech;
	params = (CK_AES_CCM_PARAMS *)(combined_mech + 1);
	nonce = (uchar_t *)(params + 1);
	params->ulMACSize = assoc->ipsa_mac_len;
	params->ulNonceSize = assoc->ipsa_nonce_len;
	params->ulAuthDataSize = sizeof (esph_t);
	params->ulDataSize = data_len;
	params->nonce = nonce;
	params->authData = esph;

	cm_mech->combined_mech.cm_type = assoc->ipsa_emech.cm_type;
	cm_mech->combined_mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	cm_mech->combined_mech.cm_param = (caddr_t)params;
	/* See gcm_params_init() for comments. */
	bcopy(assoc->ipsa_nonce, nonce, assoc->ipsa_saltlen);
	nonce += assoc->ipsa_saltlen;
	bcopy(iv_ptr, nonce, assoc->ipsa_iv_len);
	crypto_data->cd_miscdata = NULL;
}

/* ARGSUSED */
void
cbc_params_init(ipsa_t *assoc, uchar_t *esph, uint_t data_len, uchar_t *iv_ptr,
    ipsa_cm_mech_t *cm_mech, crypto_data_t *crypto_data)
{
	cm_mech->combined_mech.cm_type = assoc->ipsa_emech.cm_type;
	cm_mech->combined_mech.cm_param_len = 0;
	cm_mech->combined_mech.cm_param = NULL;
	crypto_data->cd_miscdata = (char *)iv_ptr;
}

/* ARGSUSED */
void
gcm_params_init(ipsa_t *assoc, uchar_t *esph, uint_t data_len, uchar_t *iv_ptr,
    ipsa_cm_mech_t *cm_mech, crypto_data_t *crypto_data)
{
	uchar_t *nonce;
	crypto_mechanism_t *combined_mech;
	CK_AES_GCM_PARAMS *params;

	combined_mech = (crypto_mechanism_t *)cm_mech;
	params = (CK_AES_GCM_PARAMS *)(combined_mech + 1);
	nonce = (uchar_t *)(params + 1);

	params->pIv = nonce;
	params->ulIvLen = assoc->ipsa_nonce_len;
	params->ulIvBits = SADB_8TO1(assoc->ipsa_nonce_len);
	params->pAAD = esph;
	params->ulAADLen = sizeof (esph_t);
	params->ulTagBits = SADB_8TO1(assoc->ipsa_mac_len);

	cm_mech->combined_mech.cm_type = assoc->ipsa_emech.cm_type;
	cm_mech->combined_mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	cm_mech->combined_mech.cm_param = (caddr_t)params;
	/*
	 * Create the nonce, which is made up of the salt and the IV.
	 * Copy the salt from the SA and the IV from the packet.
	 * For inbound packets we copy the IV from the packet because it
	 * was set by the sending system, for outbound packets we copy the IV
	 * from the packet because the IV in the SA may be changed by another
	 * thread, the IV in the packet was created while holding a mutex.
	 */
	bcopy(assoc->ipsa_nonce, nonce, assoc->ipsa_saltlen);
	nonce += assoc->ipsa_saltlen;
	bcopy(iv_ptr, nonce, assoc->ipsa_iv_len);
	crypto_data->cd_miscdata = NULL;
}
