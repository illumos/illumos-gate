/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 * RFC 2385 TCP MD5 Signature Option
 *
 * A security option commonly used to enhance security for BGP sessions. When a
 * TCP socket has its TCP_MD5SIG option enabled, an additional TCP option is
 * added to the header containing an MD5 digest calculated across the pseudo IP
 * header, part of the TCP header, the data in the segment and a shared secret.
 * The option is large (18 bytes plus 2 more for padding to a word boundary),
 * and often /just/ fits in the TCP header -- particularly with SYN packets due
 * to their additional options such as MSS.
 *
 * The socket option is boolean, and it is also necessary to have configured a
 * security association (SA) to match the traffic that should be signed, and to
 * provide the signing key. These SAs are configured from userland via
 * tcpkey(8), use source and destination addresses and ports as criteria, and
 * are maintained in a per-netstack linked list. The SAs pertaining to a
 * particular TCP connection, one for each direction, are cached in the
 * connection's TCP state after the first packet has been processed, and so
 * using a single list is not a significant overhead, particularly as it is
 * expected to be short.
 *
 * Enabling the socket option has a number of side effects:
 *
 *  - TCP fast path is disabled;
 *  - TCP Fusion is disabled;
 *  - Outbound packets for which a matching SA cannot be found are silently
 *    discarded.
 *  - Inbound packets that DO NOT contain an MD5 option in their TCP header are
 *    silently discarded.
 *  - Inbound packets that DO contain an MD5 option but for which the digest
 *    does not match the locally calculated one are silently discarded.
 *
 * An SA is bound to a TCP stream once the first packet is sent or received
 * following the TCP_MD5SIG socket option being enabled. Typically an
 * application will enable the socket option immediately after creating the
 * socket, and before moving on to calling connect() or bind() but it is
 * necessary to wait for the first packet as that is the point at which the
 * source and destination addresses and ports are all known, and we need these
 * to find the SA. Note that if no matching SA is present in the database when
 * the first packet is sent or received, it will be silently dropped. Due to
 * the reference counting and tombstone logic, an SA that has been bound to one
 * or more streams will persist until all of those streams have been torn down.
 * It is not possible to change the SA for an active connection.
 *
 * -------------
 * Lock Ordering
 * -------------
 *
 * In order to ensure that we don't deadlock, if both are required, the RW lock
 * across the SADB must be taken before acquiring an individual SA's lock. That
 * is, locks must be taken in the following order (and released in the opposite
 * order):
 *
 * 0) <tcpstack>->tcps_sigdb->td_lock
 * 1) <tcpstack>->tcps_sigdb->td_sa.list-><entry>->ts_lock
 *
 * The lock at <tcpstack>->tcps_sigdb_lock is independent and used to
 * synchronize lazy initialization of the database.
 */

#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/list.h>
#include <sys/md5.h>
#include <sys/stdbool.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <net/pfkeyv2.h>
#include <net/pfpolicy.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/tcp_stats.h>
#include <inet/keysock.h>
#include <inet/sadb.h>
#include <inet/tcp_sig.h>

static void tcpsig_sa_free(tcpsig_sa_t *);

void
tcpsig_init(tcp_stack_t *tcps)
{
	mutex_init(&tcps->tcps_sigdb_lock, NULL, MUTEX_DEFAULT, NULL);
}

void
tcpsig_fini(tcp_stack_t *tcps)
{
	tcpsig_db_t *db;

	if ((db = tcps->tcps_sigdb) != NULL) {
		tcpsig_sa_t *sa;

		rw_destroy(&db->td_lock);
		while ((sa = list_remove_head(&db->td_salist)) != NULL)
			tcpsig_sa_free(sa);
		list_destroy(&db->td_salist);
		kmem_free(tcps->tcps_sigdb, sizeof (tcpsig_db_t));
		tcps->tcps_sigdb = NULL;
	}
	mutex_destroy(&tcps->tcps_sigdb_lock);
}

static tcpsig_db_t *
tcpsig_db(tcp_stack_t *tcps)
{
	mutex_enter(&tcps->tcps_sigdb_lock);
	if (tcps->tcps_sigdb == NULL) {
		tcpsig_db_t *db = kmem_alloc(sizeof (tcpsig_db_t), KM_SLEEP);

		rw_init(&db->td_lock, NULL, RW_DEFAULT, 0);
		list_create(&db->td_salist, sizeof (tcpsig_sa_t),
		    offsetof(tcpsig_sa_t, ts_link));

		tcps->tcps_sigdb = db;
	}
	mutex_exit(&tcps->tcps_sigdb_lock);

	return ((tcpsig_db_t *)tcps->tcps_sigdb);
}

static uint8_t *
tcpsig_make_sa_ext(uint8_t *start, const uint8_t * const end,
    const tcpsig_sa_t *sa)
{
	sadb_sa_t *assoc;

	ASSERT3P(end, >, start);

	if (start == NULL || end - start < sizeof (*assoc))
		return (NULL);

	assoc = (sadb_sa_t *)start;
	assoc->sadb_sa_exttype = SADB_EXT_SA;
	assoc->sadb_sa_len = SADB_8TO64(sizeof (*assoc));
	assoc->sadb_sa_auth = sa->ts_key.sak_algid;
	assoc->sadb_sa_flags = SADB_X_SAFLAGS_TCPSIG;
	assoc->sadb_sa_state = sa->ts_state;

	return ((uint8_t *)(assoc + 1));
}

static size_t
tcpsig_addr_extsize(const tcpsig_sa_t *sa)
{
	size_t addrsize = 0;

	switch (sa->ts_family) {
	case AF_INET:
		addrsize = roundup(sizeof (sin_t) +
		    sizeof (sadb_address_t), sizeof (uint64_t));
		break;
	case AF_INET6:
		addrsize = roundup(sizeof (sin6_t) +
		    sizeof (sadb_address_t), sizeof (uint64_t));
		break;
	}
	return (addrsize);
}

static uint8_t *
tcpsig_make_addr_ext(uint8_t *start, const uint8_t * const end,
    uint16_t exttype, sa_family_t af, const struct sockaddr_storage *addr)
{
	uint8_t *cur = start;
	unsigned int addrext_len;
	sadb_address_t *addrext;

	ASSERT(af == AF_INET || af == AF_INET6);
	ASSERT3P(end, >, start);

	if (cur == NULL)
		return (NULL);

	if (end - cur < sizeof (*addrext))
		return (NULL);

	addrext = (sadb_address_t *)cur;
	addrext->sadb_address_proto = IPPROTO_TCP;
	addrext->sadb_address_reserved = 0;
	addrext->sadb_address_prefixlen = 0;
	addrext->sadb_address_exttype = exttype;
	cur = (uint8_t *)(addrext + 1);

	if (af == AF_INET) {
		sin_t *sin;

		if (end - cur < sizeof (*sin))
			return (NULL);
		sin = (sin_t *)cur;

		*sin = sin_null;
		bcopy(addr, sin, sizeof (*sin));
		cur = (uint8_t *)(sin + 1);
	} else {
		sin6_t *sin6;

		if (end - cur < sizeof (*sin6))
			return (NULL);
		sin6 = (sin6_t *)cur;

		*sin6 = sin6_null;
		bcopy(addr, sin6, sizeof (*sin6));
		cur = (uint8_t *)(sin6 + 1);
	}

	addrext_len = roundup(cur - start, sizeof (uint64_t));
	addrext->sadb_address_len = SADB_8TO64(addrext_len);

	if (end - start < addrext_len)
		return (NULL);
	return (start + addrext_len);
}

#define	SET_EXPIRE(sa, delta, exp) do {					\
	if (((sa)->ts_ ## delta) != 0) {				\
		(sa)->ts_ ## exp = tcpsig_add_time((sa)->ts_addtime,	\
			(sa)->ts_ ## delta);				\
	}								\
} while (0)

#define	UPDATE_EXPIRE(sa, delta, exp) do {				\
	if (((sa)->ts_ ## delta) != 0) {				\
		time_t tmp = tcpsig_add_time((sa)->ts_usetime,		\
		    (sa)->ts_ ## delta);				\
		if (((sa)->ts_ ## exp) == 0)				\
			(sa)->ts_ ## exp = tmp;				\
		else							\
			(sa)->ts_ ## exp = MIN((sa)->ts_ ## exp, tmp);	\
	}								\
} while (0)

#define	EXPIRED(sa, exp, now)						\
	((sa)->ts_ ## exp != 0 && sa->ts_ ## exp < (now))

/*
 * PF_KEY gives us lifetimes in uint64_t seconds. In order to avoid odd
 * behaviour (either negative lifetimes or loss of high order bits) when
 * someone asks for bizarrely long SA lifetimes, we do a saturating add for
 * expire times.
 */
#define	TIME_MAX	INT64_MAX
static time_t
tcpsig_add_time(time_t base, uint64_t delta)
{
	if (delta > TIME_MAX)
		delta = TIME_MAX;

	if (base > 0) {
		if (TIME_MAX - base < delta)
			return (TIME_MAX);
	}

	return (base + delta);
}

/*
 * Check hard/soft liftimes and return an appropriate error.
 */
static int
tcpsig_check_lifetimes(sadb_lifetime_t *hard, sadb_lifetime_t *soft)
{
	if (hard == NULL || soft == NULL)
		return (SADB_X_DIAGNOSTIC_NONE);

	if (hard->sadb_lifetime_addtime != 0 &&
	    soft->sadb_lifetime_addtime != 0 &&
	    hard->sadb_lifetime_addtime < soft->sadb_lifetime_addtime) {
		return (SADB_X_DIAGNOSTIC_ADDTIME_HSERR);
	}

	if (hard->sadb_lifetime_usetime != 0 &&
	    soft->sadb_lifetime_usetime != 0 &&
	    hard->sadb_lifetime_usetime < soft->sadb_lifetime_usetime) {
		return (SADB_X_DIAGNOSTIC_USETIME_HSERR);
	}

	return (SADB_X_DIAGNOSTIC_NONE);
}

/*
 * Update the lifetime values of an SA.
 * If the updated lifetimes mean that a previously dying or dead SA should be
 * promoted back to mature, then do that too. However, if they would mean that
 * the SA is immediately expired, then that will be handled on the next
 * aging run.
 */
static void
tcpsig_update_lifetimes(tcpsig_sa_t *sa, sadb_lifetime_t *hard,
    sadb_lifetime_t *soft)
{
	const time_t now = gethrestime_sec();

	mutex_enter(&sa->ts_lock);

	if (hard != NULL) {
		if (hard->sadb_lifetime_usetime != 0)
			sa->ts_harduselt = hard->sadb_lifetime_usetime;
		if (hard->sadb_lifetime_addtime != 0)
			sa->ts_hardaddlt = hard->sadb_lifetime_addtime;
		if (sa->ts_hardaddlt != 0)
			SET_EXPIRE(sa, hardaddlt, hardexpiretime);
		if (sa->ts_harduselt != 0 && sa->ts_usetime != 0)
			UPDATE_EXPIRE(sa, harduselt, hardexpiretime);
		if (sa->ts_state == SADB_SASTATE_DEAD &&
		    !EXPIRED(sa, hardexpiretime, now)) {
			sa->ts_state = SADB_SASTATE_MATURE;
		}
	}

	if (soft != NULL) {
		if (soft->sadb_lifetime_usetime != 0) {
			sa->ts_softuselt = MIN(sa->ts_harduselt,
			    soft->sadb_lifetime_usetime);
		}
		if (soft->sadb_lifetime_addtime != 0) {
			sa->ts_softaddlt = MIN(sa->ts_hardaddlt,
			    soft->sadb_lifetime_addtime);
		}
		if (sa->ts_softaddlt != 0)
			SET_EXPIRE(sa, softaddlt, softexpiretime);
		if (sa->ts_softuselt != 0 && sa->ts_usetime != 0)
			UPDATE_EXPIRE(sa, softuselt, softexpiretime);
		if (sa->ts_state == SADB_SASTATE_DYING &&
		    !EXPIRED(sa, softexpiretime, now)) {
			sa->ts_state = SADB_SASTATE_MATURE;
		}
	}

	mutex_exit(&sa->ts_lock);
}

static void
tcpsig_sa_touch(tcpsig_sa_t *sa)
{
	const time_t now = gethrestime_sec();

	mutex_enter(&sa->ts_lock);
	sa->ts_lastuse = now;

	if (sa->ts_usetime == 0) {
		sa->ts_usetime = now;
		/* Update expiry times following the first use */
		UPDATE_EXPIRE(sa, softuselt, softexpiretime);
		UPDATE_EXPIRE(sa, harduselt, hardexpiretime);
	}
	mutex_exit(&sa->ts_lock);
}

static void
tcpsig_sa_expiremsg(keysock_t *ks, const tcpsig_sa_t *sa, int ltt)
{
	size_t alloclen;
	sadb_sa_t *assoc;
	sadb_msg_t *samsg;
	sadb_lifetime_t *lt;
	uint8_t *cur, *end;
	mblk_t *mp;

	alloclen = sizeof (sadb_msg_t) + sizeof (sadb_sa_t) +
	    2 * sizeof (sadb_lifetime_t) + 2 * tcpsig_addr_extsize(sa);

	mp = allocb(alloclen, BPRI_HI);
	if (mp == NULL)
		return;

	bzero(mp->b_rptr, alloclen);
	mp->b_wptr += alloclen;
	end = mp->b_wptr;

	samsg = (sadb_msg_t *)mp->b_rptr;
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_EXPIRE;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = SADB_X_SATYPE_TCPSIG;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = 0;
	samsg->sadb_msg_pid = 0;
	samsg->sadb_msg_len = (uint16_t)SADB_8TO64(alloclen);

	cur = (uint8_t *)(samsg + 1);
	cur = tcpsig_make_sa_ext(cur, end, sa);
	cur = tcpsig_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC,
	    sa->ts_family, &sa->ts_src);
	cur = tcpsig_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST,
	    sa->ts_family, &sa->ts_dst);

	if (cur == NULL) {
		freeb(mp);
		return;
	}

	lt = (sadb_lifetime_t *)cur;
	lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	lt->sadb_lifetime_allocations = 0;
	lt->sadb_lifetime_bytes = 0;
	lt->sadb_lifetime_addtime = sa->ts_addtime;
	lt->sadb_lifetime_usetime = sa->ts_usetime;

	lt++;
	lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
	lt->sadb_lifetime_exttype = ltt;
	lt->sadb_lifetime_allocations = 0;
	lt->sadb_lifetime_bytes = 0;
	lt->sadb_lifetime_addtime = sa->ts_hardaddlt;
	lt->sadb_lifetime_usetime = sa->ts_harduselt;

	keysock_passup(mp, (sadb_msg_t *)mp->b_rptr,
	    0, NULL, B_TRUE, ks->keysock_keystack);
}

static void
tcpsig_sa_age(keysock_t *ks, tcp_stack_t *tcps)
{
	tcpsig_db_t *db = tcpsig_db(tcps);
	tcpsig_sa_t *nextsa;
	const time_t now = gethrestime_sec();

	rw_enter(&db->td_lock, RW_WRITER);
	nextsa = list_head(&db->td_salist);
	while (nextsa != NULL) {
		tcpsig_sa_t *sa = nextsa;

		nextsa = list_next(&db->td_salist, sa);

		mutex_enter(&sa->ts_lock);

		if (sa->ts_tombstoned) {
			mutex_exit(&sa->ts_lock);
			continue;
		}

		if (EXPIRED(sa, hardexpiretime, now)) {
			sa->ts_state = IPSA_STATE_DEAD;
			tcpsig_sa_expiremsg(ks, sa, SADB_EXT_LIFETIME_HARD);
			if (sa->ts_refcnt > 0) {
				sa->ts_tombstoned = true;
				mutex_exit(&sa->ts_lock);
			} else {
				list_remove(&db->td_salist, sa);
				mutex_exit(&sa->ts_lock);
				tcpsig_sa_free(sa);
			}
			continue;
		}

		if (EXPIRED(sa, softexpiretime, now) &&
		    sa->ts_state == IPSA_STATE_MATURE) {
			sa->ts_state = IPSA_STATE_DYING;
			tcpsig_sa_expiremsg(ks, sa, SADB_EXT_LIFETIME_SOFT);
		}

		mutex_exit(&sa->ts_lock);
	}

	rw_exit(&db->td_lock);
}

static void
tcpsig_sa_free(tcpsig_sa_t *sa)
{
	ASSERT0(sa->ts_refcnt);
	mutex_destroy(&sa->ts_lock);
	kmem_free(sa->ts_key.sak_key, sa->ts_key.sak_keylen);
	kmem_free(sa, sizeof (*sa));
}

void
tcpsig_sa_rele(tcpsig_sa_t *sa)
{
	mutex_enter(&sa->ts_lock);
	VERIFY3U(sa->ts_refcnt, >, 0);
	sa->ts_refcnt--;
	/*
	 * If we are tombstoned (have been marked as deleted) and the reference
	 * count has now dropped to zero, then we can go ahead and finally
	 * remove this SA from the database.
	 */
	if (sa->ts_tombstoned && sa->ts_refcnt == 0) {
		tcpsig_db_t *db = tcpsig_db(sa->ts_stack);

		/*
		 * To maintain the required lock ordering, we need to drop the
		 * lock on the SA while acquiring the RW lock on the list. Take
		 * an additional hold before doing this dance and drop it once
		 * we have re-gained the lock.
		 */
		sa->ts_refcnt++;
		mutex_exit(&sa->ts_lock);
		rw_enter(&db->td_lock, RW_WRITER);
		mutex_enter(&sa->ts_lock);
		sa->ts_refcnt--;
		mutex_exit(&sa->ts_lock);

		list_remove(&db->td_salist, sa);

		rw_exit(&db->td_lock);
		tcpsig_sa_free(sa);
	} else {
		mutex_exit(&sa->ts_lock);
	}
}

static bool
tcpsig_sa_match4(tcpsig_sa_t *sa, struct sockaddr_storage *src_s,
    struct sockaddr_storage *dst_s)
{
	sin_t msrc, mdst, *src, *dst, *sasrc, *sadst;

	if (src_s->ss_family != AF_INET)
		return (false);

	src = (sin_t *)src_s;
	dst = (sin_t *)dst_s;

	if (sa->ts_family == AF_INET6) {
		sin6_t *sasrc6 = (sin6_t *)&sa->ts_src;
		sin6_t *sadst6 = (sin6_t *)&sa->ts_dst;

		if (!IN6_IS_ADDR_V4MAPPED(&sasrc6->sin6_addr) ||
		    !IN6_IS_ADDR_V4MAPPED(&sadst6->sin6_addr)) {
			return (false);
		}

		msrc = sin_null;
		msrc.sin_family = AF_INET;
		msrc.sin_port = sasrc6->sin6_port;
		IN6_V4MAPPED_TO_INADDR(&sasrc6->sin6_addr, &msrc.sin_addr);
		sasrc = &msrc;

		mdst = sin_null;
		mdst.sin_family = AF_INET;
		mdst.sin_port = sadst6->sin6_port;
		IN6_V4MAPPED_TO_INADDR(&sadst6->sin6_addr, &mdst.sin_addr);
		sadst = &mdst;
	} else {
		sasrc = (sin_t *)&sa->ts_src;
		sadst = (sin_t *)&sa->ts_dst;
	}

	if (sasrc->sin_port != 0 && sasrc->sin_port != src->sin_port)
		return (false);
	if (sadst->sin_port != 0 && sadst->sin_port != dst->sin_port)
		return (false);

	if (sasrc->sin_addr.s_addr != src->sin_addr.s_addr)
		return (false);
	if (sadst->sin_addr.s_addr != dst->sin_addr.s_addr)
		return (false);

	return (true);
}

static bool
tcpsig_sa_match6(tcpsig_sa_t *sa, struct sockaddr_storage *src_s,
    struct sockaddr_storage *dst_s)
{
	sin6_t *src, *dst, *sasrc, *sadst;

	if (src_s->ss_family != AF_INET6 || sa->ts_src.ss_family != AF_INET6)
		return (false);

	src = (sin6_t *)src_s;
	dst = (sin6_t *)dst_s;

	sasrc = (sin6_t *)&sa->ts_src;
	sadst = (sin6_t *)&sa->ts_dst;

	if (sasrc->sin6_port != 0 && sasrc->sin6_port != src->sin6_port)
		return (false);
	if (sadst->sin6_port != 0 && sadst->sin6_port != dst->sin6_port)
		return (false);

	if (!IN6_ARE_ADDR_EQUAL(&sasrc->sin6_addr, &src->sin6_addr))
		return (false);
	if (!IN6_ARE_ADDR_EQUAL(&sadst->sin6_addr, &dst->sin6_addr))
		return (false);

	return (true);
}

static tcpsig_sa_t *
tcpsig_sa_find_held(struct sockaddr_storage *src, struct sockaddr_storage *dst,
    tcp_stack_t *tcps)
{
	tcpsig_db_t *db = tcpsig_db(tcps);
	tcpsig_sa_t *sa = NULL;
	const time_t now = gethrestime_sec();

	ASSERT(RW_LOCK_HELD(&db->td_lock));

	if (src->ss_family != dst->ss_family)
		return (NULL);

	for (sa = list_head(&db->td_salist); sa != NULL;
	    sa = list_next(&db->td_salist, sa)) {
		mutex_enter(&sa->ts_lock);
		/*
		 * We don't consider tombstoned or hard expired entries as a
		 * possible match.
		 */
		if (sa->ts_tombstoned || EXPIRED(sa, hardexpiretime, now)) {
			mutex_exit(&sa->ts_lock);
			continue;
		}
		if (tcpsig_sa_match4(sa, src, dst) ||
		    tcpsig_sa_match6(sa, src, dst)) {
			sa->ts_refcnt++;
			mutex_exit(&sa->ts_lock);
			break;
		}
		mutex_exit(&sa->ts_lock);
	}

	return (sa);
}

static tcpsig_sa_t *
tcpsig_sa_find(struct sockaddr_storage *src, struct sockaddr_storage *dst,
    tcp_stack_t *tcps)
{
	tcpsig_db_t *db = tcpsig_db(tcps);
	tcpsig_sa_t *sa;

	rw_enter(&db->td_lock, RW_READER);
	sa = tcpsig_sa_find_held(src, dst, tcps);
	rw_exit(&db->td_lock);

	return (sa);
}

static int
tcpsig_sa_flush(keysock_t *ks, tcp_stack_t *tcps, int *diagp)
{
	tcpsig_db_t *db = tcpsig_db(tcps);
	tcpsig_sa_t *nextsa;

	rw_enter(&db->td_lock, RW_WRITER);
	nextsa = list_head(&db->td_salist);
	while (nextsa != NULL) {
		tcpsig_sa_t *sa = nextsa;

		nextsa = list_next(&db->td_salist, sa);

		mutex_enter(&sa->ts_lock);
		if (sa->ts_refcnt > 0) {
			sa->ts_tombstoned = true;
			mutex_exit(&sa->ts_lock);
			continue;
		}

		list_remove(&db->td_salist, sa);

		mutex_exit(&sa->ts_lock);
		tcpsig_sa_free(sa);
	}

	rw_exit(&db->td_lock);

	return (0);
}

static int
tcpsig_sa_add(keysock_t *ks, tcp_stack_t *tcps, keysock_in_t *ksi,
    sadb_ext_t **extv, int *diagp)
{
	tcpsig_db_t *db;
	sadb_address_t *srcext, *dstext;
	sadb_lifetime_t *soft, *hard;
	sadb_sa_t *assoc;
	struct sockaddr_storage *src, *dst;
	sadb_key_t *key;
	tcpsig_sa_t *sa, *dupsa;
	int ret = 0;

	assoc = (sadb_sa_t *)extv[SADB_EXT_SA];
	srcext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_SRC];
	dstext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_DST];
	key = (sadb_key_t *)extv[SADB_X_EXT_STR_AUTH];
	soft = (sadb_lifetime_t *)extv[SADB_EXT_LIFETIME_SOFT];
	hard = (sadb_lifetime_t *)extv[SADB_EXT_LIFETIME_HARD];

	if (assoc == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_SA;
		return (EINVAL);
	}

	if (srcext == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return (EINVAL);
	}

	if (dstext == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}

	if (key == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_ASTR;
		return (EINVAL);
	}

	if ((*diagp = tcpsig_check_lifetimes(hard, soft)) !=
	    SADB_X_DIAGNOSTIC_NONE) {
		return (EINVAL);
	}

	src = (struct sockaddr_storage *)(srcext + 1);
	dst = (struct sockaddr_storage *)(dstext + 1);

	if (src->ss_family != dst->ss_family) {
		*diagp = SADB_X_DIAGNOSTIC_AF_MISMATCH;
		return (EINVAL);
	}

	if (src->ss_family != AF_INET && src->ss_family != AF_INET6) {
		*diagp = SADB_X_DIAGNOSTIC_BAD_SRC_AF;
		return (EINVAL);
	}

	/* We only support MD5 */
	if (assoc->sadb_sa_auth != SADB_AALG_MD5) {
		*diagp = SADB_X_DIAGNOSTIC_BAD_AALG;
		return (EINVAL);
	}

	/* The authentication key length must be a multiple of whole bytes */
	if ((key->sadb_key_bits & 0x7) != 0) {
		*diagp = SADB_X_DIAGNOSTIC_MALFORMED_AKEY;
		return (EINVAL);
	}

	db = tcpsig_db(tcps);

	sa = kmem_zalloc(sizeof (*sa), KM_NOSLEEP_LAZY);
	if (sa == NULL)
		return (ENOMEM);

	sa->ts_stack = tcps;
	sa->ts_family = src->ss_family;
	if (sa->ts_family == AF_INET6) {
		bcopy(src, (sin6_t *)&sa->ts_src, sizeof (sin6_t));
		bcopy(dst, (sin6_t *)&sa->ts_dst, sizeof (sin6_t));
	} else {
		bcopy(src, (sin_t *)&sa->ts_src, sizeof (sin_t));
		bcopy(dst, (sin_t *)&sa->ts_dst, sizeof (sin_t));
	}

	sa->ts_key.sak_algid = assoc->sadb_sa_auth;
	sa->ts_key.sak_keylen = SADB_1TO8(key->sadb_key_bits);
	sa->ts_key.sak_keybits = key->sadb_key_bits;

	sa->ts_key.sak_key = kmem_alloc(sa->ts_key.sak_keylen,
	    KM_NOSLEEP_LAZY);
	if (sa->ts_key.sak_key == NULL) {
		kmem_free(sa, sizeof (*sa));
		return (ENOMEM);
	}
	bcopy(key + 1, sa->ts_key.sak_key, sa->ts_key.sak_keylen);
	bzero(key + 1, sa->ts_key.sak_keylen);

	mutex_init(&sa->ts_lock, NULL, MUTEX_DEFAULT, NULL);

	sa->ts_state = SADB_SASTATE_MATURE;
	sa->ts_addtime = gethrestime_sec();
	sa->ts_usetime = 0;
	if (soft != NULL) {
		sa->ts_softaddlt = soft->sadb_lifetime_addtime;
		sa->ts_softuselt = soft->sadb_lifetime_usetime;
		SET_EXPIRE(sa, softaddlt, softexpiretime);
	}

	if (hard != NULL) {
		sa->ts_hardaddlt = hard->sadb_lifetime_addtime;
		sa->ts_harduselt = hard->sadb_lifetime_usetime;
		SET_EXPIRE(sa, hardaddlt, hardexpiretime);
	}

	sa->ts_refcnt = 0;
	sa->ts_tombstoned = false;

	rw_enter(&db->td_lock, RW_WRITER);
	if ((dupsa = tcpsig_sa_find_held(src, dst, tcps)) != NULL) {
		rw_exit(&db->td_lock);
		tcpsig_sa_rele(dupsa);
		tcpsig_sa_free(sa);
		*diagp = SADB_X_DIAGNOSTIC_DUPLICATE_SA;
		ret = EEXIST;
	} else {
		list_insert_tail(&db->td_salist, sa);
		rw_exit(&db->td_lock);
	}

	return (ret);
}

/*
 * Handle an UPDATE message. We only support updating lifetimes.
 */
static int
tcpsig_sa_update(keysock_t *ks, tcp_stack_t *tcps, keysock_in_t *ksi,
    sadb_ext_t **extv, int *diagp)
{
	tcpsig_db_t *db;
	sadb_address_t *srcext, *dstext;
	sadb_lifetime_t *soft, *hard;
	struct sockaddr_storage *src, *dst;
	tcpsig_sa_t *sa;

	srcext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_SRC];
	dstext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_DST];
	soft = (sadb_lifetime_t *)extv[SADB_EXT_LIFETIME_SOFT];
	hard = (sadb_lifetime_t *)extv[SADB_EXT_LIFETIME_HARD];

	if (srcext == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return (EINVAL);
	}

	if (dstext == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}


	if ((*diagp = tcpsig_check_lifetimes(hard, soft)) !=
	    SADB_X_DIAGNOSTIC_NONE) {
		return (EINVAL);
	}

	src = (struct sockaddr_storage *)(srcext + 1);
	dst = (struct sockaddr_storage *)(dstext + 1);

	sa = tcpsig_sa_find(src, dst, tcps);

	if (sa == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
		return (ESRCH);
	}

	tcpsig_update_lifetimes(sa, hard, soft);
	tcpsig_sa_rele(sa);

	/*
	 * Run an aging pass in case updating the SA lifetimes has resulted in
	 * the SA now being aged out.
	 */
	tcpsig_sa_age(ks, tcps);

	return (0);
}

static mblk_t *
tcpsig_dump_one(const tcpsig_sa_t *sa, sadb_msg_t *samsg)
{
	size_t alloclen, keysize;
	sadb_sa_t *assoc;
	sadb_msg_t *newsamsg;
	uint8_t *cur, *end;
	sadb_key_t *key;
	mblk_t *mp;
	bool soft = false, hard = false;

	ASSERT(MUTEX_HELD(&sa->ts_lock));

	alloclen = sizeof (sadb_msg_t) + sizeof (sadb_sa_t) +
	    2 * tcpsig_addr_extsize(sa);

	if (sa->ts_softaddlt != 0 || sa->ts_softuselt != 0) {
		alloclen += sizeof (sadb_lifetime_t);
		soft = true;
	}

	if (sa->ts_hardaddlt != 0 || sa->ts_harduselt != 0) {
		alloclen += sizeof (sadb_lifetime_t);
		hard = true;
	}

	/* Add space for LIFETIME_CURRENT */
	if (soft || hard)
		alloclen += sizeof (sadb_lifetime_t);

	keysize = roundup(sizeof (sadb_key_t) + sa->ts_key.sak_keylen,
	    sizeof (uint64_t));

	alloclen += keysize;

	mp = allocb(alloclen, BPRI_HI);
	if (mp == NULL)
		return (NULL);

	bzero(mp->b_rptr, alloclen);
	mp->b_wptr += alloclen;
	end = mp->b_wptr;

	newsamsg = (sadb_msg_t *)mp->b_rptr;
	*newsamsg = *samsg;
	newsamsg->sadb_msg_len = (uint16_t)SADB_8TO64(alloclen);

	cur = (uint8_t *)(newsamsg + 1);
	cur = tcpsig_make_sa_ext(cur, end, sa);
	cur = tcpsig_make_addr_ext(cur, end, SADB_EXT_ADDRESS_SRC,
	    sa->ts_family, &sa->ts_src);
	cur = tcpsig_make_addr_ext(cur, end, SADB_EXT_ADDRESS_DST,
	    sa->ts_family, &sa->ts_dst);

	if (cur == NULL) {
		freeb(mp);
		return (NULL);
	}

	if (soft || hard) {
		sadb_lifetime_t *lt = (sadb_lifetime_t *)cur;

		lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
		lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
		lt->sadb_lifetime_allocations = 0;
		lt->sadb_lifetime_bytes = 0;
		lt->sadb_lifetime_addtime = sa->ts_addtime;
		lt->sadb_lifetime_usetime = sa->ts_usetime;
		lt++;

		if (soft) {
			lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
			lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
			lt->sadb_lifetime_allocations = 0;
			lt->sadb_lifetime_bytes = 0;
			lt->sadb_lifetime_addtime = sa->ts_softaddlt;
			lt->sadb_lifetime_usetime = sa->ts_softuselt;
			lt++;
		}
		if (hard) {
			lt->sadb_lifetime_len = SADB_8TO64(sizeof (*lt));
			lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
			lt->sadb_lifetime_allocations = 0;
			lt->sadb_lifetime_bytes = 0;
			lt->sadb_lifetime_addtime = sa->ts_hardaddlt;
			lt->sadb_lifetime_usetime = sa->ts_harduselt;
			lt++;
		}

		cur = (uint8_t *)lt;
	}

	key = (sadb_key_t *)cur;
	key->sadb_key_exttype = SADB_X_EXT_STR_AUTH;
	key->sadb_key_len = SADB_8TO64(keysize);
	key->sadb_key_bits = sa->ts_key.sak_keybits;
	key->sadb_key_reserved = 0;
	bcopy(sa->ts_key.sak_key, (uint8_t *)(key + 1), sa->ts_key.sak_keylen);

	return (mp);
}

static int
tcpsig_sa_dump(keysock_t *ks, tcp_stack_t *tcps, sadb_msg_t *samsg, int *diag)
{
	tcpsig_db_t *db;
	tcpsig_sa_t *sa;

	db = tcpsig_db(tcps);
	rw_enter(&db->td_lock, RW_READER);

	for (sa = list_head(&db->td_salist); sa != NULL;
	    sa = list_next(&db->td_salist, sa)) {
		mblk_t *mp;

		mutex_enter(&sa->ts_lock);
		if (sa->ts_tombstoned) {
			mutex_exit(&sa->ts_lock);
			continue;
		}
		mp = tcpsig_dump_one(sa, samsg);
		mutex_exit(&sa->ts_lock);

		if (mp == NULL) {
			rw_exit(&db->td_lock);
			return (ENOMEM);
		}
		keysock_passup(mp, (sadb_msg_t *)mp->b_rptr,
		    ks->keysock_serial, NULL, B_TRUE, ks->keysock_keystack);
	}

	rw_exit(&db->td_lock);

	/* A sequence number of 0 indicates the end of the list */
	samsg->sadb_msg_seq = 0;

	return (0);
}

static int
tcpsig_sa_delget(keysock_t *ks, tcp_stack_t *tcps, sadb_msg_t *samsg,
    sadb_ext_t **extv, int *diagp)
{
	sadb_address_t *srcext, *dstext;
	struct sockaddr_storage *src, *dst;
	tcpsig_sa_t *sa;
	mblk_t *mp;

	srcext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_SRC];
	dstext = (sadb_address_t *)extv[SADB_EXT_ADDRESS_DST];

	if (srcext == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return (EINVAL);
	}

	if (dstext == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}

	src = (struct sockaddr_storage *)(srcext + 1);
	dst = (struct sockaddr_storage *)(dstext + 1);

	sa = tcpsig_sa_find(src, dst, tcps);

	if (sa == NULL) {
		*diagp = SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND;
		return (ESRCH);
	}

	if (samsg->sadb_msg_type == SADB_GET) {
		mutex_enter(&sa->ts_lock);
		mp = tcpsig_dump_one(sa, samsg);
		mutex_exit(&sa->ts_lock);

		if (mp == NULL) {
			tcpsig_sa_rele(sa);
			return (ENOMEM);
		}
		keysock_passup(mp, (sadb_msg_t *)mp->b_rptr,
		    ks->keysock_serial, NULL, B_TRUE, ks->keysock_keystack);
		tcpsig_sa_rele(sa);

		return (0);
	}

	/*
	 * Delete the entry.
	 * At this point we still have a hold on the entry from the find call
	 * above, so mark it as tombstoned and then release the hold. If
	 * that causes the reference count to become 0, the entry will be
	 * removed from the database.
	 */

	mutex_enter(&sa->ts_lock);
	sa->ts_tombstoned = true;
	mutex_exit(&sa->ts_lock);
	tcpsig_sa_rele(sa);

	return (0);
}

void
tcpsig_sa_handler(keysock_t *ks, mblk_t *mp, sadb_msg_t *samsg,
    sadb_ext_t **extv)
{
	keysock_stack_t *keystack = ks->keysock_keystack;
	netstack_t *nst = keystack->keystack_netstack;
	tcp_stack_t *tcps = nst->netstack_tcp;
	keysock_in_t *ksi = (keysock_in_t *)mp->b_rptr;
	int diag = SADB_X_DIAGNOSTIC_NONE;
	int error;

	tcpsig_sa_age(ks, tcps);

	switch (samsg->sadb_msg_type) {
	case SADB_ADD:
		error = tcpsig_sa_add(ks, tcps, ksi, extv, &diag);
		keysock_error(ks, mp, error, diag);
		break;
	case SADB_UPDATE:
		error = tcpsig_sa_update(ks, tcps, ksi, extv, &diag);
		keysock_error(ks, mp, error, diag);
		break;
	case SADB_GET:
	case SADB_DELETE:
		error = tcpsig_sa_delget(ks, tcps, samsg, extv, &diag);
		keysock_error(ks, mp, error, diag);
		break;
	case SADB_FLUSH:
		error = tcpsig_sa_flush(ks, tcps, &diag);
		keysock_error(ks, mp, error, diag);
		break;
	case SADB_DUMP:
		error = tcpsig_sa_dump(ks, tcps, samsg, &diag);
		keysock_error(ks, mp, error, diag);
		break;
	default:
		keysock_error(ks, mp, EOPNOTSUPP, diag);
		break;
	}
}

bool
tcpsig_sa_exists(tcp_t *tcp, bool inbound, tcpsig_sa_t **sap)
{
	tcp_stack_t *tcps = tcp->tcp_tcps;
	conn_t *connp = tcp->tcp_connp;
	struct sockaddr_storage src, dst;
	tcpsig_sa_t *sa;

	bzero(&src, sizeof (src));
	bzero(&dst, sizeof (dst));

	if (connp->conn_ipversion == IPV6_VERSION) {
		sin6_t *sin6;

		sin6 = (sin6_t *)&src;
		sin6->sin6_family = AF_INET6;
		if (inbound) {
			sin6->sin6_addr = connp->conn_faddr_v6;
			sin6->sin6_port = connp->conn_fport;
		} else {
			sin6->sin6_addr = connp->conn_saddr_v6;
			sin6->sin6_port = connp->conn_lport;
		}

		sin6 = (sin6_t *)&dst;
		sin6->sin6_family = AF_INET6;
		if (inbound) {
			sin6->sin6_addr = connp->conn_saddr_v6;
			sin6->sin6_port = connp->conn_lport;
		} else {
			sin6->sin6_addr = connp->conn_faddr_v6;
			sin6->sin6_port = connp->conn_fport;
		}
	} else {
		sin_t *sin;

		sin = (sin_t *)&src;
		sin->sin_family = AF_INET;
		if (inbound) {
			sin->sin_addr.s_addr = connp->conn_faddr_v4;
			sin->sin_port = connp->conn_fport;
		} else {
			sin->sin_addr.s_addr = connp->conn_saddr_v4;
			sin->sin_port = connp->conn_lport;
		}

		sin = (sin_t *)&dst;
		sin->sin_family = AF_INET;
		if (inbound) {
			sin->sin_addr.s_addr = connp->conn_saddr_v4;
			sin->sin_port = connp->conn_lport;
		} else {
			sin->sin_addr.s_addr = connp->conn_faddr_v4;
			sin->sin_port = connp->conn_fport;
		}
	}

	sa = tcpsig_sa_find(&src, &dst, tcps);

	if (sa == NULL)
		return (false);

	if (sap != NULL)
		*sap = sa;
	else
		tcpsig_sa_rele(sa);

	return (true);
}

static void
tcpsig_pseudo_compute4(tcp_t *tcp, int tcplen, MD5_CTX *ctx, bool inbound)
{
	struct ip_pseudo {
		struct in_addr	ipp_src;
		struct in_addr	ipp_dst;
		uint8_t		ipp_pad;
		uint8_t		ipp_proto;
		uint16_t	ipp_len;
	} ipp;
	conn_t *connp = tcp->tcp_connp;

	if (inbound) {
		ipp.ipp_src.s_addr = connp->conn_faddr_v4;
		ipp.ipp_dst.s_addr = connp->conn_saddr_v4;
	} else {
		ipp.ipp_src.s_addr = connp->conn_saddr_v4;
		ipp.ipp_dst.s_addr = connp->conn_faddr_v4;
	}
	ipp.ipp_pad = 0;
	ipp.ipp_proto = IPPROTO_TCP;
	ipp.ipp_len = htons(tcplen);

	DTRACE_PROBE1(ipp4, struct ip_pseudo *, &ipp);

	MD5Update(ctx, (char *)&ipp, sizeof (ipp));
}

static void
tcpsig_pseudo_compute6(tcp_t *tcp, int tcplen, MD5_CTX *ctx, bool inbound)
{
	struct ip6_pseudo {
		struct in6_addr	ipp_src;
		struct in6_addr ipp_dst;
		uint32_t	ipp_len;
		uint32_t	ipp_nxt;
	} ip6p;
	conn_t *connp = tcp->tcp_connp;

	if (inbound) {
		ip6p.ipp_src = connp->conn_faddr_v6;
		ip6p.ipp_dst = connp->conn_saddr_v6;
	} else {
		ip6p.ipp_src = connp->conn_saddr_v6;
		ip6p.ipp_dst = connp->conn_faddr_v6;
	}
	ip6p.ipp_len = htonl(tcplen);
	ip6p.ipp_nxt = htonl(IPPROTO_TCP);

	DTRACE_PROBE1(ipp6, struct ip6_pseudo *, &ip6p);

	MD5Update(ctx, (char *)&ip6p, sizeof (ip6p));
}

bool
tcpsig_signature(mblk_t *mp, tcp_t *tcp, tcpha_t *tcpha, int tcplen,
    uint8_t *digest, bool inbound)
{
	tcp_stack_t *tcps = tcp->tcp_tcps;
	conn_t *connp = tcp->tcp_connp;
	tcpsig_sa_t *sa;
	MD5_CTX context;

	/*
	 * The TCP_MD5SIG option is 20 bytes, including padding, which adds 5
	 * 32-bit words to the header's 4-bit field. Check that it can fit in
	 * the current packet.
	 */
	if (!inbound && (tcpha->tha_offset_and_reserved >> 4) > 10) {
		TCP_STAT(tcps, tcp_sig_no_space);
		return (false);
	}

	sa = inbound ? tcp->tcp_sig_sa_in : tcp->tcp_sig_sa_out;
	if (sa == NULL) {
		if (!tcpsig_sa_exists(tcp, inbound, &sa)) {
			TCP_STAT(tcps, tcp_sig_match_failed);
			return (false);
		}

		/*
		 * tcpsig_sa_exists() returns a held SA, so we don't need to
		 * take another hold before adding it to tcp.
		 */
		if (inbound)
			tcp->tcp_sig_sa_in = sa;
		else
			tcp->tcp_sig_sa_out = sa;
	}

	tcpsig_sa_touch(sa);

	VERIFY3U(sa->ts_key.sak_algid, ==, SADB_AALG_MD5);

	/* We have a key for this connection, generate the hash */
	MD5Init(&context);

	/* TCP pseudo-header */
	if (connp->conn_ipversion == IPV6_VERSION)
		tcpsig_pseudo_compute6(tcp, tcplen, &context, inbound);
	else
		tcpsig_pseudo_compute4(tcp, tcplen, &context, inbound);

	/* TCP header, excluding options and with a zero checksum */
	uint16_t offset = tcpha->tha_offset_and_reserved;
	uint16_t sum = tcpha->tha_sum;

	if (!inbound) {
		/* Account for the MD5 option we are going to add */
		tcpha->tha_offset_and_reserved += (5 << 4);
	}
	tcpha->tha_sum = 0;
	MD5Update(&context, tcpha, sizeof (*tcpha));
	tcpha->tha_offset_and_reserved = offset;
	tcpha->tha_sum = sum;

	/* TCP segment data */
	for (; mp != NULL; mp = mp->b_cont)
		MD5Update(&context, mp->b_rptr, mp->b_wptr - mp->b_rptr);

	/* Connection-specific key */
	MD5Update(&context, sa->ts_key.sak_key, sa->ts_key.sak_keylen);

	MD5Final(digest, &context);

	return (true);
}

bool
tcpsig_verify(mblk_t *mp, tcp_t *tcp, tcpha_t *tcpha, ip_recv_attr_t *ira,
    uint8_t *digest)
{
	uint8_t calc_digest[MD5_DIGEST_LENGTH];

	if (!tcpsig_signature(mp, tcp, tcpha,
	    ira->ira_pktlen - ira->ira_ip_hdr_length, calc_digest, true)) {
		/* The appropriate stat will already have been bumped */
		return (false);
	}

	if (bcmp(digest, calc_digest, sizeof (calc_digest)) != 0) {
		TCP_STAT(tcp->tcp_tcps, tcp_sig_verify_failed);
		return (false);
	}

	return (true);
}
