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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>
#include <sys/condvar_impl.h>
#include <sys/sendfile.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>
#include <fs/sockfs/socktpi_impl.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/led.h>
#include <inet/mi.h>

#include <inet/nca/ncadoorhdr.h>
#include <inet/nca/ncalogd.h>
#include <inet/nca/ncandd.h>

#include <sys/promif.h>

/*
 * Some externs:
 */

extern boolean_t	nl7c_logd_enabled;
extern void		nl7c_logd_log(uri_desc_t *, uri_desc_t *,
			    time_t, ipaddr_t);
extern boolean_t	nl7c_close_addr(struct sonode *);
extern struct sonode	*nl7c_addr2portso(void *);
extern uri_desc_t	*nl7c_http_cond(uri_desc_t *, uri_desc_t *);

/*
 * Various global tuneables:
 */

clock_t		nl7c_uri_ttl = -1;	/* TTL in seconds (-1 == infinite) */

boolean_t	nl7c_use_kmem = B_FALSE; /* Force use of kmem (no segmap) */

uint64_t	nl7c_file_prefetch = 1; /* File cache prefetch pages */

uint64_t	nl7c_uri_max = 0;	/* Maximum bytes (0 == infinite) */
uint64_t	nl7c_uri_bytes = 0;	/* Bytes of kmem used by URIs */

/*
 * Locals:
 */

static int	uri_rd_response(struct sonode *, uri_desc_t *,
		    uri_rd_t *, boolean_t);
static int	uri_response(struct sonode *, uri_desc_t *);

/*
 * HTTP scheme functions called from nl7chttp.c:
 */

boolean_t nl7c_http_request(char **, char *, uri_desc_t *, struct sonode *);
boolean_t nl7c_http_response(char **, char *, uri_desc_t *, struct sonode *);
boolean_t nl7c_http_cmp(void *, void *);
mblk_t *nl7c_http_persist(struct sonode *);
void nl7c_http_free(void *arg);
void nl7c_http_init(void);

/*
 * Counters that need to move to kstat and/or be removed:
 */

volatile uint64_t nl7c_uri_request = 0;
volatile uint64_t nl7c_uri_hit = 0;
volatile uint64_t nl7c_uri_pass = 0;
volatile uint64_t nl7c_uri_miss = 0;
volatile uint64_t nl7c_uri_temp = 0;
volatile uint64_t nl7c_uri_more = 0;
volatile uint64_t nl7c_uri_data = 0;
volatile uint64_t nl7c_uri_sendfilev = 0;
volatile uint64_t nl7c_uri_reclaim_calls = 0;
volatile uint64_t nl7c_uri_reclaim_cnt = 0;
volatile uint64_t nl7c_uri_pass_urifail = 0;
volatile uint64_t nl7c_uri_pass_dupbfail = 0;
volatile uint64_t nl7c_uri_more_get = 0;
volatile uint64_t nl7c_uri_pass_method = 0;
volatile uint64_t nl7c_uri_pass_option = 0;
volatile uint64_t nl7c_uri_more_eol = 0;
volatile uint64_t nl7c_uri_more_http = 0;
volatile uint64_t nl7c_uri_pass_http = 0;
volatile uint64_t nl7c_uri_pass_addfail = 0;
volatile uint64_t nl7c_uri_pass_temp = 0;
volatile uint64_t nl7c_uri_expire = 0;
volatile uint64_t nl7c_uri_purge = 0;
volatile uint64_t nl7c_uri_NULL1 = 0;
volatile uint64_t nl7c_uri_NULL2 = 0;
volatile uint64_t nl7c_uri_close = 0;
volatile uint64_t nl7c_uri_temp_close = 0;
volatile uint64_t nl7c_uri_free = 0;
volatile uint64_t nl7c_uri_temp_free = 0;
volatile uint64_t nl7c_uri_temp_mk = 0;
volatile uint64_t nl7c_uri_rd_EAGAIN = 0;

/*
 * Various kmem_cache_t's:
 */

kmem_cache_t *nl7c_uri_kmc;
kmem_cache_t *nl7c_uri_rd_kmc;
static kmem_cache_t *uri_desb_kmc;
static kmem_cache_t *uri_segmap_kmc;

static void uri_kmc_reclaim(void *);

static void nl7c_uri_reclaim(void);

/*
 * The URI hash is a dynamically sized A/B bucket hash, when the current
 * hash's average bucket chain length exceeds URI_HASH_AVRG a new hash of
 * the next P2Ps[] size is created.
 *
 * All lookups are done in the current hash then the new hash (if any),
 * if there is a new has then when a current hash bucket chain is examined
 * any uri_desc_t members will be migrated to the new hash and when the
 * last uri_desc_t has been migrated then the new hash will become the
 * current and the previous current hash will be freed leaving a single
 * hash.
 *
 * uri_hash_t - hash bucket (chain) type, contained in the uri_hash_ab[]
 * and can be accessed only after aquiring the uri_hash_access lock (for
 * READER or WRITER) then acquiring the lock uri_hash_t.lock, the uri_hash_t
 * and all linked uri_desc_t.hash members are protected. Note, a REF_HOLD()
 * is placed on all uri_desc_t uri_hash_t list members.
 *
 * uri_hash_access - rwlock for all uri_hash_* variables, READER for read
 * access and WRITER for write access. Note, WRITER is only required for
 * hash geometry changes.
 *
 * uri_hash_which - which uri_hash_ab[] is the current hash.
 *
 * uri_hash_n[] - the P2Ps[] index for each uri_hash_ab[].
 *
 * uri_hash_sz[] - the size for each uri_hash_ab[].
 *
 * uri_hash_cnt[] - the total uri_desc_t members for each uri_hash_ab[].
 *
 * uri_hash_overflow[] - the uri_hash_cnt[] for each uri_hash_ab[] when
 * a new uri_hash_ab[] needs to be created.
 *
 * uri_hash_ab[] - the uri_hash_t entries.
 *
 * uri_hash_lru[] - the last uri_hash_ab[] walked for lru reclaim.
 */

typedef struct uri_hash_s {
	struct uri_desc_s	*list;		/* List of uri_t(s) */
	kmutex_t		lock;
} uri_hash_t;

#define	URI_HASH_AVRG	5	/* Desired average hash chain length */
#define	URI_HASH_N_INIT	9	/* P2Ps[] initial index */

static krwlock_t	uri_hash_access;
static uint32_t		uri_hash_which = 0;
static uint32_t		uri_hash_n[2] = {URI_HASH_N_INIT, 0};
static uint32_t		uri_hash_sz[2] = {0, 0};
static uint32_t		uri_hash_cnt[2] = {0, 0};
static uint32_t		uri_hash_overflow[2] = {0, 0};
static uri_hash_t	*uri_hash_ab[2] = {NULL, NULL};
static uri_hash_t	*uri_hash_lru[2] = {NULL, NULL};

/*
 * Primes for N of 3 - 24 where P is first prime less then (2^(N-1))+(2^(N-2))
 * these primes have been foud to be useful for prime sized hash tables.
 */

static const int P2Ps[] = {
	0, 0, 0, 5, 11, 23, 47, 89, 191, 383, 761, 1531, 3067,
	6143, 12281, 24571, 49139, 98299, 196597, 393209,
	786431, 1572853, 3145721, 6291449, 12582893, 0};

/*
 * Hash macros:
 *
 *    H2A(char *cp, char *ep, char c) - convert the escaped octet (ASCII)
 *    hex multichar of the format "%HH" pointeded to by *cp to a char and
 *    return in c, *ep points to past end of (char *), on return *cp will
 *    point to the last char consumed.
 *
 *    URI_HASH(unsigned hix, char *cp, char *ep) - hash the char(s) from
 *    *cp to *ep to the unsigned hix, cp nor ep are modified.
 *
 *    URI_HASH_IX(unsigned hix, int which) - convert the hash value hix to
 *    a hash index 0 - (uri_hash_sz[which] - 1).
 *
 *    URI_HASH_MIGRATE(from, hp, to) - migrate the uri_hash_t *hp list
 *    uri_desc_t members from hash from to hash to.
 *
 *    URI_HASH_UNLINK(cur, new, hp, puri, uri) - unlink the uri_desc_t
 *    *uri which is a member of the uri_hash_t *hp list with a previous
 *    list member of *puri for the uri_hash_ab[] cur. After unlinking
 *    check for cur hash empty, if so make new cur. Note, as this macro
 *    can change a hash chain it needs to be run under hash_access as
 *    RW_WRITER, futher as it can change the new hash to cur any access
 *    to the hash state must be done after either dropping locks and
 *    starting over or making sure the global state is consistent after
 *    as before.
 */

#define	H2A(cp, ep, c) {						\
	int	_h = 2;							\
	int	_n = 0;							\
	char	_hc;							\
									\
	while (_h > 0 && ++(cp) < (ep)) {				\
		if (_h == 1)						\
			_n *= 0x10;					\
		_hc = *(cp);						\
		if (_hc >= '0' && _hc <= '9')				\
			_n += _hc - '0';				\
		else if (_hc >= 'a' || _hc <= 'f')			\
			_n += _hc - 'W';				\
		else if (_hc >= 'A' || _hc <= 'F')			\
			_n += _hc - '7';				\
		_h--;							\
	}								\
	(c) = _n;							\
}

#define	URI_HASH(hv, cp, ep) {						\
	char	*_s = (cp);						\
	char	_c;							\
									\
	while (_s < (ep)) {						\
		if ((_c = *_s) == '%') {				\
			H2A(_s, (ep), _c);				\
		}							\
		CHASH(hv, _c);						\
		_s++;							\
	}								\
}

#define	URI_HASH_IX(hix, which) (hix) = (hix) % (uri_hash_sz[(which)])

#define	URI_HASH_MIGRATE(from, hp, to) {				\
	uri_desc_t	*_nuri;						\
	uint32_t	_nhix;						\
	uri_hash_t	*_nhp;						\
									\
	mutex_enter(&(hp)->lock);					\
	while ((_nuri = (hp)->list) != NULL) {				\
		(hp)->list = _nuri->hash;				\
		atomic_dec_32(&uri_hash_cnt[(from)]);		\
		atomic_inc_32(&uri_hash_cnt[(to)]);			\
		_nhix = _nuri->hvalue;					\
		URI_HASH_IX(_nhix, to);					\
		_nhp = &uri_hash_ab[(to)][_nhix];			\
		mutex_enter(&_nhp->lock);				\
		_nuri->hash = _nhp->list;				\
		_nhp->list = _nuri;					\
		_nuri->hit = 0;						\
		mutex_exit(&_nhp->lock);				\
	}								\
	mutex_exit(&(hp)->lock);					\
}

#define	URI_HASH_UNLINK(cur, new, hp, puri, uri) {			\
	if ((puri) != NULL) {						\
		(puri)->hash = (uri)->hash;				\
	} else {							\
		(hp)->list = (uri)->hash;				\
	}								\
	if (atomic_dec_32_nv(&uri_hash_cnt[(cur)]) == 0 &&		\
	    uri_hash_ab[(new)] != NULL) {				\
		kmem_free(uri_hash_ab[cur],				\
		    sizeof (uri_hash_t) * uri_hash_sz[cur]);		\
		uri_hash_ab[(cur)] = NULL;				\
		uri_hash_lru[(cur)] = NULL;				\
		uri_hash_which = (new);					\
	} else {							\
		uri_hash_lru[(cur)] = (hp);				\
	}								\
}

void
nl7c_uri_init(void)
{
	uint32_t	cur = uri_hash_which;

	rw_init(&uri_hash_access, NULL, RW_DEFAULT, NULL);

	uri_hash_sz[cur] = P2Ps[URI_HASH_N_INIT];
	uri_hash_overflow[cur] = P2Ps[URI_HASH_N_INIT] * URI_HASH_AVRG;
	uri_hash_ab[cur] = kmem_zalloc(sizeof (uri_hash_t) * uri_hash_sz[cur],
	    KM_SLEEP);
	uri_hash_lru[cur] = uri_hash_ab[cur];

	nl7c_uri_kmc = kmem_cache_create("NL7C_uri_kmc", sizeof (uri_desc_t),
	    0, NULL, NULL, uri_kmc_reclaim, NULL, NULL, 0);

	nl7c_uri_rd_kmc = kmem_cache_create("NL7C_uri_rd_kmc",
	    sizeof (uri_rd_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	uri_desb_kmc = kmem_cache_create("NL7C_uri_desb_kmc",
	    sizeof (uri_desb_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	uri_segmap_kmc = kmem_cache_create("NL7C_uri_segmap_kmc",
	    sizeof (uri_segmap_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	nl7c_http_init();
}

#define	CV_SZ	16

void
nl7c_mi_report_hash(mblk_t *mp)
{
	uri_hash_t	*hp, *pend;
	uri_desc_t	*uri;
	uint32_t	cur;
	uint32_t	new;
	int		n, nz, tot;
	uint32_t	cv[CV_SZ + 1];

	rw_enter(&uri_hash_access, RW_READER);
	cur = uri_hash_which;
	new = cur ? 0 : 1;
next:
	for (n = 0; n <= CV_SZ; n++)
		cv[n] = 0;
	nz = 0;
	tot = 0;
	hp = &uri_hash_ab[cur][0];
	pend = &uri_hash_ab[cur][uri_hash_sz[cur]];
	while (hp < pend) {
		n = 0;
		for (uri = hp->list; uri != NULL; uri = uri->hash) {
			n++;
		}
		tot += n;
		if (n > 0)
			nz++;
		if (n > CV_SZ)
			n = CV_SZ;
		cv[n]++;
		hp++;
	}

	(void) mi_mpprintf(mp, "\nHash=%s, Buckets=%d, "
	    "Avrg=%d\nCount by bucket:", cur != new ? "CUR" : "NEW",
	    uri_hash_sz[cur], nz != 0 ? ((tot * 10 + 5) / nz) / 10 : 0);
	(void) mi_mpprintf(mp, "Free=%d", cv[0]);
	for (n = 1; n < CV_SZ; n++) {
		int	pn = 0;
		char	pv[5];
		char	*pp = pv;

		for (pn = n; pn < 1000; pn *= 10)
			*pp++ = ' ';
		*pp = 0;
		(void) mi_mpprintf(mp, "%s%d=%d", pv, n, cv[n]);
	}
	(void) mi_mpprintf(mp, "Long=%d", cv[CV_SZ]);

	if (cur != new && uri_hash_ab[new] != NULL) {
		cur = new;
		goto next;
	}
	rw_exit(&uri_hash_access);
}

void
nl7c_mi_report_uri(mblk_t *mp)
{
	uri_hash_t	*hp;
	uri_desc_t	*uri;
	uint32_t	cur;
	uint32_t	new;
	int		ix;
	int		ret;
	char		sc;

	rw_enter(&uri_hash_access, RW_READER);
	cur = uri_hash_which;
	new = cur ? 0 : 1;
next:
	for (ix = 0; ix < uri_hash_sz[cur]; ix++) {
		hp = &uri_hash_ab[cur][ix];
		mutex_enter(&hp->lock);
		uri = hp->list;
		while (uri != NULL) {
			sc = *(uri->path.ep);
			*(uri->path.ep) = 0;
			ret = mi_mpprintf(mp, "%s: %d %d %d",
			    uri->path.cp, (int)uri->resplen,
			    (int)uri->respclen, (int)uri->count);
			*(uri->path.ep) = sc;
			if (ret == -1) break;
			uri = uri->hash;
		}
		mutex_exit(&hp->lock);
		if (ret == -1) break;
	}
	if (ret != -1 && cur != new && uri_hash_ab[new] != NULL) {
		cur = new;
		goto next;
	}
	rw_exit(&uri_hash_access);
}

/*
 * The uri_desc_t ref_t inactive function called on the last REF_RELE(),
 * free all resources contained in the uri_desc_t. Note, the uri_desc_t
 * will be freed by REF_RELE() on return.
 */

void
nl7c_uri_inactive(uri_desc_t *uri)
{
	int64_t	 bytes = 0;

	if (uri->tail) {
		uri_rd_t *rdp = &uri->response;
		uri_rd_t *free = NULL;

		while (rdp) {
			if (rdp->off == -1) {
				bytes += rdp->sz;
				kmem_free(rdp->data.kmem, rdp->sz);
			} else {
				VN_RELE(rdp->data.vnode);
			}
			rdp = rdp->next;
			if (free != NULL) {
				kmem_cache_free(nl7c_uri_rd_kmc, free);
			}
			free = rdp;
		}
	}
	if (bytes) {
		atomic_add_64(&nl7c_uri_bytes, -bytes);
	}
	if (uri->scheme != NULL) {
		nl7c_http_free(uri->scheme);
	}
	if (uri->reqmp) {
		freeb(uri->reqmp);
	}
}

/*
 * The reclaim is called by the kmem subsystem when kmem is running
 * low. More work is needed to determine the best reclaim policy, for
 * now we just manipulate the nl7c_uri_max global maximum bytes threshold
 * value using a simple arithmetic backoff of the value every time this
 * function is called then call uri_reclaim() to enforce it.
 *
 * Note, this value remains in place and enforced for all subsequent
 * URI request/response processing.
 *
 * Note, nl7c_uri_max is currently initialized to 0 or infinite such that
 * the first call here set it to the current uri_bytes value then backoff
 * from there.
 *
 * XXX how do we determine when to increase nl7c_uri_max ???
 */

/*ARGSUSED*/
static void
uri_kmc_reclaim(void *arg)
{
	uint64_t new_max;

	if ((new_max = nl7c_uri_max) == 0) {
		/* Currently infinite, initialize to current bytes used */
		nl7c_uri_max = nl7c_uri_bytes;
		new_max = nl7c_uri_bytes;
	}
	if (new_max > 1) {
		/* Lower max_bytes to 93% of current value */
		new_max >>= 1;			/* 50% */
		new_max += (new_max >> 1);	/* 75% */
		new_max += (new_max >> 2);	/* 93% */
		if (new_max < nl7c_uri_max)
			nl7c_uri_max = new_max;
		else
			nl7c_uri_max = 1;
	}
	nl7c_uri_reclaim();
}

/*
 * Delete a uri_desc_t from the URI hash.
 */

static void
uri_delete(uri_desc_t *del)
{
	uint32_t	hix;
	uri_hash_t	*hp;
	uri_desc_t	*uri;
	uri_desc_t	*puri;
	uint32_t	cur;
	uint32_t	new;

	ASSERT(del->hash != URI_TEMP);
	rw_enter(&uri_hash_access, RW_WRITER);
	cur = uri_hash_which;
	new = cur ? 0 : 1;
next:
	puri = NULL;
	hix = del->hvalue;
	URI_HASH_IX(hix, cur);
	hp = &uri_hash_ab[cur][hix];
	for (uri = hp->list; uri != NULL; uri = uri->hash) {
		if (uri != del) {
			puri = uri;
			continue;
		}
		/*
		 * Found the URI, unlink from the hash chain,
		 * drop locks, ref release it.
		 */
		URI_HASH_UNLINK(cur, new, hp, puri, uri);
		rw_exit(&uri_hash_access);
		REF_RELE(uri);
		return;
	}
	if (cur != new && uri_hash_ab[new] != NULL) {
		/*
		 * Not found in current hash and have a new hash so
		 * check the new hash next.
		 */
		cur = new;
		goto next;
	}
	rw_exit(&uri_hash_access);
}

/*
 * Add a uri_desc_t to the URI hash.
 */

static void
uri_add(uri_desc_t *uri, krw_t rwlock, boolean_t nonblocking)
{
	uint32_t	hix;
	uri_hash_t	*hp;
	uint32_t	cur = uri_hash_which;
	uint32_t	new = cur ? 0 : 1;

	/*
	 * Caller of uri_add() must hold the uri_hash_access rwlock.
	 */
	ASSERT((rwlock == RW_READER && RW_READ_HELD(&uri_hash_access)) ||
	    (rwlock == RW_WRITER && RW_WRITE_HELD(&uri_hash_access)));
	/*
	 * uri_add() always succeeds so add a hash ref to the URI now.
	 */
	REF_HOLD(uri);
again:
	hix = uri->hvalue;
	URI_HASH_IX(hix, cur);
	if (uri_hash_ab[new] == NULL &&
	    uri_hash_cnt[cur] < uri_hash_overflow[cur]) {
		/*
		 * Easy case, no new hash and current hasn't overflowed,
		 * add URI to current hash and return.
		 *
		 * Note, the check for uri_hash_cnt[] above aren't done
		 * atomictally, i.e. multiple threads can be in this code
		 * as RW_READER and update the cnt[], this isn't a problem
		 * as the check is only advisory.
		 */
	fast:
		atomic_inc_32(&uri_hash_cnt[cur]);
		hp = &uri_hash_ab[cur][hix];
		mutex_enter(&hp->lock);
		uri->hash = hp->list;
		hp->list = uri;
		mutex_exit(&hp->lock);
		rw_exit(&uri_hash_access);
		return;
	}
	if (uri_hash_ab[new] == NULL) {
		/*
		 * Need a new a or b hash, if not already RW_WRITER
		 * try to upgrade our lock to writer.
		 */
		if (rwlock != RW_WRITER && ! rw_tryupgrade(&uri_hash_access)) {
			/*
			 * Upgrade failed, we can't simple exit and reenter
			 * the lock as after the exit and before the reenter
			 * the whole world can change so just wait for writer
			 * then do everything again.
			 */
			if (nonblocking) {
				/*
				 * Can't block, use fast-path above.
				 *
				 * XXX should have a background thread to
				 * handle new ab[] in this case so as to
				 * not overflow the cur hash to much.
				 */
				goto fast;
			}
			rw_exit(&uri_hash_access);
			rwlock = RW_WRITER;
			rw_enter(&uri_hash_access, rwlock);
			cur = uri_hash_which;
			new = cur ? 0 : 1;
			goto again;
		}
		rwlock = RW_WRITER;
		if (uri_hash_ab[new] == NULL) {
			/*
			 * Still need a new hash, allocate and initialize
			 * the new hash.
			 */
			uri_hash_n[new] = uri_hash_n[cur] + 1;
			if (uri_hash_n[new] == 0) {
				/*
				 * No larger P2Ps[] value so use current,
				 * i.e. 2 of the largest are better than 1 ?
				 */
				uri_hash_n[new] = uri_hash_n[cur];
				cmn_err(CE_NOTE, "NL7C: hash index overflow");
			}
			uri_hash_sz[new] = P2Ps[uri_hash_n[new]];
			ASSERT(uri_hash_cnt[new] == 0);
			uri_hash_overflow[new] = uri_hash_sz[new] *
			    URI_HASH_AVRG;
			uri_hash_ab[new] = kmem_zalloc(sizeof (uri_hash_t) *
			    uri_hash_sz[new], nonblocking ? KM_NOSLEEP :
			    KM_SLEEP);
			if (uri_hash_ab[new] == NULL) {
				/*
				 * Alloc failed, use fast-path above.
				 *
				 * XXX should have a background thread to
				 * handle new ab[] in this case so as to
				 * not overflow the cur hash to much.
				 */
				goto fast;
			}
			uri_hash_lru[new] = uri_hash_ab[new];
		}
	}
	/*
	 * Hashed against current hash so migrate any current hash chain
	 * members, if any.
	 *
	 * Note, the hash chain list can be checked for a non empty list
	 * outside of the hash chain list lock as the hash chain struct
	 * can't be destroyed while in the uri_hash_access rwlock, worst
	 * case is that a non empty list is found and after acquiring the
	 * lock another thread beats us to it (i.e. migrated the list).
	 */
	hp = &uri_hash_ab[cur][hix];
	if (hp->list != NULL) {
		URI_HASH_MIGRATE(cur, hp, new);
	}
	/*
	 * If new hash has overflowed before current hash has been
	 * completely migrated then walk all current hash chains and
	 * migrate list members now.
	 */
	if (atomic_inc_32_nv(&uri_hash_cnt[new]) >= uri_hash_overflow[new]) {
		for (hix = 0; hix < uri_hash_sz[cur]; hix++) {
			hp = &uri_hash_ab[cur][hix];
			if (hp->list != NULL) {
				URI_HASH_MIGRATE(cur, hp, new);
			}
		}
	}
	/*
	 * Add URI to new hash.
	 */
	hix = uri->hvalue;
	URI_HASH_IX(hix, new);
	hp = &uri_hash_ab[new][hix];
	mutex_enter(&hp->lock);
	uri->hash = hp->list;
	hp->list = uri;
	mutex_exit(&hp->lock);
	/*
	 * Last, check to see if last cur hash chain has been
	 * migrated, if so free cur hash and make new hash cur.
	 */
	if (uri_hash_cnt[cur] == 0) {
		/*
		 * If we don't already hold the uri_hash_access rwlock for
		 * RW_WRITE try to upgrade to RW_WRITE and if successful
		 * check again and to see if still need to do the free.
		 */
		if ((rwlock == RW_WRITER || rw_tryupgrade(&uri_hash_access)) &&
		    uri_hash_cnt[cur] == 0 && uri_hash_ab[new] != 0) {
			kmem_free(uri_hash_ab[cur],
			    sizeof (uri_hash_t) * uri_hash_sz[cur]);
			uri_hash_ab[cur] = NULL;
			uri_hash_lru[cur] = NULL;
			uri_hash_which = new;
		}
	}
	rw_exit(&uri_hash_access);
}

/*
 * Lookup a uri_desc_t in the URI hash, if found free the request uri_desc_t
 * and return the found uri_desc_t with a REF_HOLD() placed on it. Else, if
 * add B_TRUE use the request URI to create a new hash entry. Else if add
 * B_FALSE ...
 */

static uri_desc_t *
uri_lookup(uri_desc_t *ruri, boolean_t add, boolean_t nonblocking)
{
	uint32_t	hix;
	uri_hash_t	*hp;
	uri_desc_t	*uri;
	uri_desc_t	*puri;
	uint32_t	cur;
	uint32_t	new;
	char		*rcp = ruri->path.cp;
	char		*rep = ruri->path.ep;

again:
	rw_enter(&uri_hash_access, RW_READER);
	cur = uri_hash_which;
	new = cur ? 0 : 1;
nexthash:
	puri = NULL;
	hix = ruri->hvalue;
	URI_HASH_IX(hix, cur);
	hp = &uri_hash_ab[cur][hix];
	mutex_enter(&hp->lock);
	for (uri = hp->list; uri != NULL; uri = uri->hash) {
		char	*ap = uri->path.cp;
		char	*bp = rcp;
		char	a, b;

		/* Compare paths */
		while (bp < rep && ap < uri->path.ep) {
			if ((a = *ap) == '%') {
				/* Escaped hex multichar, convert it */
				H2A(ap, uri->path.ep, a);
			}
			if ((b = *bp) == '%') {
				/* Escaped hex multichar, convert it */
				H2A(bp, rep, b);
			}
			if (a != b) {
				/* Char's don't match */
				goto nexturi;
			}
			ap++;
			bp++;
		}
		if (bp != rep || ap != uri->path.ep) {
			/* Not same length */
			goto nexturi;
		}
		ap = uri->auth.cp;
		bp = ruri->auth.cp;
		if (ap != NULL) {
			if (bp == NULL) {
				/* URI has auth request URI doesn't */
				goto nexturi;
			}
			while (bp < ruri->auth.ep && ap < uri->auth.ep) {
				if ((a = *ap) == '%') {
					/* Escaped hex multichar, convert it */
					H2A(ap, uri->path.ep, a);
				}
				if ((b = *bp) == '%') {
					/* Escaped hex multichar, convert it */
					H2A(bp, rep, b);
				}
				if (a != b) {
					/* Char's don't match */
					goto nexturi;
				}
				ap++;
				bp++;
			}
			if (bp != ruri->auth.ep || ap != uri->auth.ep) {
				/* Not same length */
				goto nexturi;
			}
		} else if (bp != NULL) {
			/* URI doesn't have auth and request URI does */
			goto nexturi;
		}
		/*
		 * Have a path/auth match so before any other processing
		 * of requested URI, check for expire or request no cache
		 * purge.
		 */
		if (uri->expire >= 0 && uri->expire <= ddi_get_lbolt() ||
		    ruri->nocache) {
			/*
			 * URI has expired or request specified to not use
			 * the cached version, unlink the URI from the hash
			 * chain, release all locks, release the hash ref
			 * on the URI, and last look it up again.
			 *
			 * Note, this will cause all variants of the named
			 * URI to be purged.
			 */
			if (puri != NULL) {
				puri->hash = uri->hash;
			} else {
				hp->list = uri->hash;
			}
			mutex_exit(&hp->lock);
			atomic_dec_32(&uri_hash_cnt[cur]);
			rw_exit(&uri_hash_access);
			if (ruri->nocache)
				nl7c_uri_purge++;
			else
				nl7c_uri_expire++;
			REF_RELE(uri);
			goto again;
		}
		if (uri->scheme != NULL) {
			/*
			 * URI has scheme private qualifier(s), if request
			 * URI doesn't or if no match skip this URI.
			 */
			if (ruri->scheme == NULL ||
			    ! nl7c_http_cmp(uri->scheme, ruri->scheme))
				goto nexturi;
		} else if (ruri->scheme != NULL) {
			/*
			 * URI doesn't have scheme private qualifiers but
			 * request URI does, no match, skip this URI.
			 */
			goto nexturi;
		}
		/*
		 * Have a match, ready URI for return, first put a reference
		 * hold on the URI, if this URI is currently being processed
		 * then have to wait for the processing to be completed and
		 * redo the lookup, else return it.
		 */
		REF_HOLD(uri);
		mutex_enter(&uri->proclock);
		if (uri->proc != NULL) {
			/* The URI is being processed, wait for completion */
			mutex_exit(&hp->lock);
			rw_exit(&uri_hash_access);
			if (! nonblocking &&
			    cv_wait_sig(&uri->waiting, &uri->proclock)) {
				/*
				 * URI has been processed but things may
				 * have changed while we were away so do
				 * most everything again.
				 */
				mutex_exit(&uri->proclock);
				REF_RELE(uri);
				goto again;
			} else {
				/*
				 * A nonblocking socket or an interrupted
				 * cv_wait_sig() in the first case can't
				 * block waiting for the processing of the
				 * uri hash hit uri to complete, in both
				 * cases just return failure to lookup.
				 */
				mutex_exit(&uri->proclock);
				REF_RELE(uri);
				return (NULL);
			}
		}
		mutex_exit(&uri->proclock);
		uri->hit++;
		mutex_exit(&hp->lock);
		rw_exit(&uri_hash_access);
		return (uri);
	nexturi:
		puri = uri;
	}
	mutex_exit(&hp->lock);
	if (cur != new && uri_hash_ab[new] != NULL) {
		/*
		 * Not found in current hash and have a new hash so
		 * check the new hash next.
		 */
		cur = new;
		goto nexthash;
	}
add:
	if (! add) {
		/* Lookup only so return failure */
		rw_exit(&uri_hash_access);
		return (NULL);
	}
	/*
	 * URI not hashed, finish intialization of the
	 * request URI, add it to the hash, return it.
	 */
	ruri->hit = 0;
	ruri->expire = -1;
	ruri->response.sz = 0;
	ruri->proc = (struct sonode *)~NULL;
	cv_init(&ruri->waiting, NULL, CV_DEFAULT, NULL);
	mutex_init(&ruri->proclock, NULL, MUTEX_DEFAULT, NULL);
	uri_add(ruri, RW_READER, nonblocking);
	/* uri_add() has done rw_exit(&uri_hash_access) */
	return (ruri);
}

/*
 * Reclaim URIs until max cache size threshold has been reached.
 *
 * A CLOCK based reclaim modified with a history (hit counter) counter.
 */

static void
nl7c_uri_reclaim(void)
{
	uri_hash_t	*hp, *start, *pend;
	uri_desc_t	*uri;
	uri_desc_t	*puri;
	uint32_t	cur;
	uint32_t	new;

	nl7c_uri_reclaim_calls++;
again:
	rw_enter(&uri_hash_access, RW_WRITER);
	cur = uri_hash_which;
	new = cur ? 0 : 1;
next:
	hp = uri_hash_lru[cur];
	start = hp;
	pend = &uri_hash_ab[cur][uri_hash_sz[cur]];
	while (nl7c_uri_bytes > nl7c_uri_max) {
		puri = NULL;
		for (uri = hp->list; uri != NULL; uri = uri->hash) {
			if (uri->hit != 0) {
				/*
				 * Decrement URI activity counter and skip.
				 */
				uri->hit--;
				puri = uri;
				continue;
			}
			if (uri->proc != NULL) {
				/*
				 * Currently being processed by a socket, skip.
				 */
				continue;
			}
			/*
			 * Found a candidate, no hit(s) since added or last
			 * reclaim pass, unlink from it's hash chain, update
			 * lru scan pointer, drop lock, ref release it.
			 */
			URI_HASH_UNLINK(cur, new, hp, puri, uri);
			if (cur == uri_hash_which) {
				if (++hp == pend) {
					/* Wrap pointer */
					hp = uri_hash_ab[cur];
				}
				uri_hash_lru[cur] = hp;
			}
			rw_exit(&uri_hash_access);
			REF_RELE(uri);
			nl7c_uri_reclaim_cnt++;
			goto again;
		}
		if (++hp == pend) {
			/* Wrap pointer */
			hp = uri_hash_ab[cur];
		}
		if (hp == start) {
			if (cur != new && uri_hash_ab[new] != NULL) {
				/*
				 * Done with the current hash and have a
				 * new hash so check the new hash next.
				 */
				cur = new;
				goto next;
			}
		}
	}
	rw_exit(&uri_hash_access);
}

/*
 * Called for a socket which is being freed prior to close, e.g. errored.
 */

void
nl7c_urifree(struct sonode *so)
{
	sotpi_info_t *sti = SOTOTPI(so);
	uri_desc_t *uri = (uri_desc_t *)sti->sti_nl7c_uri;

	sti->sti_nl7c_uri = NULL;
	if (uri->hash != URI_TEMP) {
		uri_delete(uri);
		mutex_enter(&uri->proclock);
		uri->proc = NULL;
		if (CV_HAS_WAITERS(&uri->waiting)) {
			cv_broadcast(&uri->waiting);
		}
		mutex_exit(&uri->proclock);
		nl7c_uri_free++;
	} else {
		/* No proclock as uri exclusively owned by so */
		uri->proc = NULL;
		nl7c_uri_temp_free++;
	}
	REF_RELE(uri);
}

/*
 * ...
 *
 *	< 0	need more data
 *
 *	  0	parse complete
 *
 *	> 0	parse error
 */

volatile uint64_t nl7c_resp_pfail = 0;
volatile uint64_t nl7c_resp_ntemp = 0;
volatile uint64_t nl7c_resp_pass = 0;

static int
nl7c_resp_parse(struct sonode *so, uri_desc_t *uri, char *data, int sz)
{
	if (! nl7c_http_response(&data, &data[sz], uri, so)) {
		if (data == NULL) {
			/* Parse fail */
			goto pfail;
		}
		/* More data */
		data = NULL;
	} else if (data == NULL) {
		goto pass;
	}
	if (uri->hash != URI_TEMP && uri->nocache) {
		/*
		 * After response parse now no cache,
		 * delete it from cache, wakeup any
		 * waiters on this URI, make URI_TEMP.
		 */
		uri_delete(uri);
		mutex_enter(&uri->proclock);
		if (CV_HAS_WAITERS(&uri->waiting)) {
			cv_broadcast(&uri->waiting);
		}
		mutex_exit(&uri->proclock);
		uri->hash = URI_TEMP;
		nl7c_uri_temp_mk++;
	}
	if (data == NULL) {
		/* More data needed */
		return (-1);
	}
	/* Success */
	return (0);

pfail:
	nl7c_resp_pfail++;
	return (EINVAL);

pass:
	nl7c_resp_pass++;
	return (ENOTSUP);
}

/*
 * Called to sink application response data, the processing of the data
 * is the same for a cached or temp URI (i.e. a URI for which we aren't
 * going to cache the URI but want to parse it for detecting response
 * data end such that for a persistent connection we can parse the next
 * request).
 *
 * On return 0 is returned for sink success, > 0 on error, and < 0 on
 * no so URI (note, data not sinked).
 */

int
nl7c_data(struct sonode *so, uio_t *uio)
{
	sotpi_info_t	*sti = SOTOTPI(so);
	uri_desc_t	*uri = (uri_desc_t *)sti->sti_nl7c_uri;
	iovec_t		*iov;
	int		cnt;
	int		sz = uio->uio_resid;
	char		*data, *alloc;
	char		*bp;
	uri_rd_t	*rdp;
	boolean_t	first;
	int		error, perror;

	nl7c_uri_data++;

	if (uri == NULL) {
		/* Socket & NL7C out of sync, disable NL7C */
		sti->sti_nl7c_flags = 0;
		nl7c_uri_NULL1++;
		return (-1);
	}

	if (sti->sti_nl7c_flags & NL7C_WAITWRITE) {
		sti->sti_nl7c_flags &= ~NL7C_WAITWRITE;
		first = B_TRUE;
	} else {
		first = B_FALSE;
	}

	alloc = kmem_alloc(sz, KM_SLEEP);
	URI_RD_ADD(uri, rdp, sz, -1);
	if (rdp == NULL) {
		error = ENOMEM;
		goto fail;
	}

	if (uri->hash != URI_TEMP && uri->count > nca_max_cache_size) {
		uri_delete(uri);
		uri->hash = URI_TEMP;
	}
	data = alloc;
	alloc = NULL;
	rdp->data.kmem = data;
	atomic_add_64(&nl7c_uri_bytes, sz);

	bp = data;
	while (uio->uio_resid > 0) {
		iov = uio->uio_iov;
		if ((cnt = iov->iov_len) == 0) {
			goto next;
		}
		cnt = MIN(cnt, uio->uio_resid);
		error = xcopyin(iov->iov_base, bp, cnt);
		if (error)
			goto fail;

		iov->iov_base += cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_loffset += cnt;
		bp += cnt;
	next:
		uio->uio_iov++;
		uio->uio_iovcnt--;
	}

	/* Successfull sink of data, response parse the data */
	perror = nl7c_resp_parse(so, uri, data, sz);

	/* Send the data out the connection */
	error = uri_rd_response(so, uri, rdp, first);
	if (error)
		goto fail;

	/* Success */
	if (perror == 0 &&
	    ((uri->respclen == URI_LEN_NOVALUE &&
	    uri->resplen == URI_LEN_NOVALUE) ||
	    uri->count >= uri->resplen)) {
		/*
		 * No more data needed and no pending response
		 * data or current data count >= response length
		 * so close the URI processing for this so.
		 */
		nl7c_close(so);
		if (! (sti->sti_nl7c_flags & NL7C_SOPERSIST)) {
			/* Not a persistent connection */
			sti->sti_nl7c_flags = 0;
		}
	}

	return (0);

fail:
	if (alloc != NULL) {
		kmem_free(alloc, sz);
	}
	sti->sti_nl7c_flags = 0;
	nl7c_urifree(so);

	return (error);
}

/*
 * Called to read data from file "*fp" at offset "*off" of length "*len"
 * for a maximum of "*max_rem" bytes.
 *
 * On success a pointer to the kmem_alloc()ed file data is returned, "*off"
 * and "*len" are updated for the acutal number of bytes read and "*max_rem"
 * is updated with the number of bytes remaining to be read.
 *
 * Else, "NULL" is returned.
 */

static char *
nl7c_readfile(file_t *fp, u_offset_t *off, int *len, int max, int *ret)
{
	vnode_t	*vp = fp->f_vnode;
	int	flg = 0;
	size_t	size = MIN(*len, max);
	char	*data;
	int	error;
	uio_t	uio;
	iovec_t	iov;

	(void) VOP_RWLOCK(vp, flg, NULL);

	if (*off > MAXOFFSET_T) {
		VOP_RWUNLOCK(vp, flg, NULL);
		*ret = EFBIG;
		return (NULL);
	}

	if (*off + size > MAXOFFSET_T)
		size = (ssize32_t)(MAXOFFSET_T - *off);

	data = kmem_alloc(size, KM_SLEEP);

	iov.iov_base = data;
	iov.iov_len = size;
	uio.uio_loffset = *off;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = size;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_llimit = MAXOFFSET_T;
	uio.uio_fmode = fp->f_flag;

	error = VOP_READ(vp, &uio, fp->f_flag, fp->f_cred, NULL);
	VOP_RWUNLOCK(vp, flg, NULL);
	*ret = error;
	if (error) {
		kmem_free(data, size);
		return (NULL);
	}
	*len = size;
	*off += size;
	return (data);
}

/*
 * Called to sink application response sendfilev, as with nl7c_data() above
 * all the data will be processed by NL7C unless there's an error.
 */

int
nl7c_sendfilev(struct sonode *so, u_offset_t *fileoff, sendfilevec_t *sfvp,
	int sfvc, ssize_t *xfer)
{
	sotpi_info_t	*sti = SOTOTPI(so);
	uri_desc_t	*uri = (uri_desc_t *)sti->sti_nl7c_uri;
	file_t		*fp = NULL;
	vnode_t		*vp = NULL;
	char		*data = NULL;
	u_offset_t	off;
	int		len;
	int		cnt;
	int		total_count = 0;
	char		*alloc;
	uri_rd_t	*rdp;
	int		max;
	int		perror;
	int		error = 0;
	boolean_t	first = B_TRUE;

	nl7c_uri_sendfilev++;

	if (uri == NULL) {
		/* Socket & NL7C out of sync, disable NL7C */
		sti->sti_nl7c_flags = 0;
		nl7c_uri_NULL2++;
		return (0);
	}

	if (sti->sti_nl7c_flags & NL7C_WAITWRITE)
		sti->sti_nl7c_flags &= ~NL7C_WAITWRITE;

	while (sfvc-- > 0) {
		/*
		 * off - the current sfv read file offset or user address.
		 *
		 * len - the current sfv length in bytes.
		 *
		 * cnt - number of bytes kmem_alloc()ed.
		 *
		 * alloc - the kmem_alloc()ed buffer of size "cnt".
		 *
		 * data - copy of "alloc" used for post alloc references.
		 *
		 * fp - the current sfv file_t pointer.
		 *
		 * vp - the current "*vp" vnode_t pointer.
		 *
		 * Note, for "data" and "fp" and "vp" a NULL value is used
		 * when not allocated such that the common failure path "fail"
		 * is used.
		 */
		off = sfvp->sfv_off;
		len = sfvp->sfv_len;
		cnt = len;

		if (len == 0) {
			sfvp++;
			continue;
		}

		if (sfvp->sfv_fd == SFV_FD_SELF) {
			/*
			 * User memory, copyin() all the bytes.
			 */
			alloc = kmem_alloc(cnt, KM_SLEEP);
			error = xcopyin((caddr_t)(uintptr_t)off, alloc, cnt);
			if (error)
				goto fail;
		} else {
			/*
			 * File descriptor, prefetch some bytes.
			 */
			if ((fp = getf(sfvp->sfv_fd)) == NULL) {
				error = EBADF;
				goto fail;
			}
			if ((fp->f_flag & FREAD) == 0) {
				error = EACCES;
				goto fail;
			}
			vp = fp->f_vnode;
			if (vp->v_type != VREG) {
				error = EINVAL;
				goto fail;
			}
			VN_HOLD(vp);

			/* Read max_rem bytes from file for prefetch */
			if (nl7c_use_kmem) {
				max = cnt;
			} else {
				max = MAXBSIZE * nl7c_file_prefetch;
			}
			alloc = nl7c_readfile(fp, &off, &cnt, max, &error);
			if (alloc == NULL)
				goto fail;

			releasef(sfvp->sfv_fd);
			fp = NULL;
		}
		URI_RD_ADD(uri, rdp, cnt, -1);
		if (rdp == NULL) {
			error = ENOMEM;
			goto fail;
		}
		data = alloc;
		alloc = NULL;
		rdp->data.kmem = data;
		total_count += cnt;
		if (uri->hash != URI_TEMP && total_count > nca_max_cache_size) {
			uri_delete(uri);
			uri->hash = URI_TEMP;
		}

		/* Response parse */
		perror = nl7c_resp_parse(so, uri, data, len);

		/* Send kmem data out the connection */
		error = uri_rd_response(so, uri, rdp, first);

		if (error)
			goto fail;

		if (sfvp->sfv_fd != SFV_FD_SELF) {
			/*
			 * File descriptor, if any bytes left save vnode_t.
			 */
			if (len > cnt) {
				/* More file data so add it */
				URI_RD_ADD(uri, rdp, len - cnt, off);
				if (rdp == NULL) {
					error = ENOMEM;
					goto fail;
				}
				rdp->data.vnode = vp;

				/* Send vnode data out the connection */
				error = uri_rd_response(so, uri, rdp, first);
			} else {
				/* All file data fit in the prefetch */
				VN_RELE(vp);
			}
			*fileoff += len;
			vp = NULL;
		}
		*xfer += len;
		sfvp++;

		if (first)
			first = B_FALSE;
	}
	if (total_count > 0) {
		atomic_add_64(&nl7c_uri_bytes, total_count);
	}
	if (perror == 0 &&
	    ((uri->respclen == URI_LEN_NOVALUE &&
	    uri->resplen == URI_LEN_NOVALUE) ||
	    uri->count >= uri->resplen)) {
		/*
		 * No more data needed and no pending response
		 * data or current data count >= response length
		 * so close the URI processing for this so.
		 */
		nl7c_close(so);
		if (! (sti->sti_nl7c_flags & NL7C_SOPERSIST)) {
			/* Not a persistent connection */
			sti->sti_nl7c_flags = 0;
		}
	}

	return (0);

fail:
	if (error == EPIPE)
		tsignal(curthread, SIGPIPE);

	if (alloc != NULL)
		kmem_free(data, len);

	if (vp != NULL)
		VN_RELE(vp);

	if (fp != NULL)
		releasef(sfvp->sfv_fd);

	if (total_count > 0) {
		atomic_add_64(&nl7c_uri_bytes, total_count);
	}

	sti->sti_nl7c_flags = 0;
	nl7c_urifree(so);

	return (error);
}

/*
 * Called for a socket which is closing or when an application has
 * completed sending all the response data (i.e. for a persistent
 * connection called once for each completed application response).
 */

void
nl7c_close(struct sonode *so)
{
	sotpi_info_t	*sti = SOTOTPI(so);
	uri_desc_t 	*uri = (uri_desc_t *)sti->sti_nl7c_uri;

	if (uri == NULL) {
		/*
		 * No URI being processed so might be a listen()er
		 * if so do any cleanup, else nothing more to do.
		 */
		if (so->so_state & SS_ACCEPTCONN) {
			(void) nl7c_close_addr(so);
		}
		return;
	}
	sti->sti_nl7c_uri = NULL;
	if (uri->hash != URI_TEMP) {
		mutex_enter(&uri->proclock);
		uri->proc = NULL;
		if (CV_HAS_WAITERS(&uri->waiting)) {
			cv_broadcast(&uri->waiting);
		}
		mutex_exit(&uri->proclock);
		nl7c_uri_close++;
	} else {
		/* No proclock as uri exclusively owned by so */
		uri->proc = NULL;
		nl7c_uri_temp_close++;
	}
	REF_RELE(uri);
	if (nl7c_uri_max > 0 && nl7c_uri_bytes > nl7c_uri_max) {
		nl7c_uri_reclaim();
	}
}

/*
 * The uri_segmap_t ref_t inactive function called on the last REF_RELE(),
 * release the segmap mapping. Note, the uri_segmap_t will be freed by
 * REF_RELE() on return.
 */

void
uri_segmap_inactive(uri_segmap_t *smp)
{
	if (!segmap_kpm) {
		(void) segmap_fault(kas.a_hat, segkmap, smp->base,
		    smp->len, F_SOFTUNLOCK, S_OTHER);
	}
	(void) segmap_release(segkmap, smp->base, SM_DONTNEED);
	VN_RELE(smp->vp);
}

/*
 * The call-back for desballoc()ed mblk_t's, if a segmap mapped mblk_t
 * release the reference, one per desballoc() of a segmap page, if a rd_t
 * mapped mblk_t release the reference, one per desballoc() of a uri_desc_t,
 * last kmem free the uri_desb_t.
 */

static void
uri_desb_free(uri_desb_t *desb)
{
	if (desb->segmap != NULL) {
		REF_RELE(desb->segmap);
	}
	REF_RELE(desb->uri);
	kmem_cache_free(uri_desb_kmc, desb);
}

/*
 * Segmap map up to a page of a uri_rd_t file descriptor.
 */

uri_segmap_t *
uri_segmap_map(uri_rd_t *rdp, int bytes)
{
	uri_segmap_t	*segmap = kmem_cache_alloc(uri_segmap_kmc, KM_SLEEP);
	int		len = MIN(rdp->sz, MAXBSIZE);

	if (len > bytes)
		len = bytes;

	REF_INIT(segmap, 1, uri_segmap_inactive, uri_segmap_kmc);
	segmap->len = len;
	VN_HOLD(rdp->data.vnode);
	segmap->vp = rdp->data.vnode;

	segmap->base = segmap_getmapflt(segkmap, segmap->vp, rdp->off, len,
	    segmap_kpm ? SM_FAULT : 0, S_READ);

	if (segmap_fault(kas.a_hat, segkmap, segmap->base, len,
	    F_SOFTLOCK, S_READ) != 0) {
		REF_RELE(segmap);
		return (NULL);
	}
	return (segmap);
}

/*
 * Chop up the kernel virtual memory area *data of size *sz bytes for
 * a maximum of *bytes bytes into an besballoc()ed mblk_t chain using
 * the given template uri_desb_t *temp of max_mblk bytes per.
 *
 * The values of *data, *sz, and *bytes are updated on return, the
 * mblk_t chain is returned.
 */

static mblk_t *
uri_desb_chop(
	char 		**data,
	size_t		*sz,
	int 		*bytes,
	uri_desb_t 	*temp,
	int		max_mblk,
	char		*eoh,
	mblk_t		*persist
)
{
	char		*ldata = *data;
	size_t		lsz = *sz;
	int		lbytes = bytes ? *bytes : lsz;
	uri_desb_t	*desb;
	mblk_t		*mp = NULL;
	mblk_t		*nmp, *pmp = NULL;
	int		msz;

	if (lbytes == 0 && lsz == 0)
		return (NULL);

	while (lbytes > 0 && lsz > 0) {
		msz = MIN(lbytes, max_mblk);
		msz = MIN(msz, lsz);
		if (persist && eoh >= ldata && eoh < &ldata[msz]) {
			msz = (eoh - ldata);
			pmp = persist;
			persist = NULL;
			if (msz == 0) {
				nmp = pmp;
				pmp = NULL;
				goto zero;
			}
		}
		desb = kmem_cache_alloc(uri_desb_kmc, KM_SLEEP);
		REF_HOLD(temp->uri);
		if (temp->segmap) {
			REF_HOLD(temp->segmap);
		}
		bcopy(temp, desb, sizeof (*desb));
		desb->frtn.free_arg = (caddr_t)desb;
		nmp = desballoc((uchar_t *)ldata, msz, BPRI_HI, &desb->frtn);
		if (nmp == NULL) {
			if (temp->segmap) {
				REF_RELE(temp->segmap);
			}
			REF_RELE(temp->uri);
			if (mp != NULL) {
				mp->b_next = NULL;
				freemsg(mp);
			}
			if (persist != NULL) {
				freeb(persist);
			}
			return (NULL);
		}
		nmp->b_wptr += msz;
	zero:
		if (mp != NULL) {
			mp->b_next->b_cont = nmp;
		} else {
			mp = nmp;
		}
		if (pmp != NULL) {
			nmp->b_cont = pmp;
			nmp = pmp;
			pmp = NULL;
		}
		mp->b_next = nmp;
		ldata += msz;
		lsz -= msz;
		lbytes -= msz;
	}
	*data = ldata;
	*sz = lsz;
	if (bytes)
		*bytes = lbytes;
	return (mp);
}

/*
 * Experimential noqwait (i.e. no canput()/qwait() checks), just send
 * the entire mblk_t chain down without flow-control checks.
 */

static int
kstrwritempnoqwait(struct vnode *vp, mblk_t *mp)
{
	struct stdata *stp;
	int error = 0;

	ASSERT(vp->v_stream);
	stp = vp->v_stream;

	/* Fast check of flags before acquiring the lock */
	if (stp->sd_flag & (STWRERR|STRHUP|STPLEX)) {
		mutex_enter(&stp->sd_lock);
		error = strgeterr(stp, STWRERR|STRHUP|STPLEX, 0);
		mutex_exit(&stp->sd_lock);
		if (error != 0) {
			if (!(stp->sd_flag & STPLEX) &&
			    (stp->sd_wput_opt & SW_SIGPIPE)) {
				error = EPIPE;
			}
			return (error);
		}
	}
	putnext(stp->sd_wrq, mp);
	return (0);
}

/*
 * Send the URI uri_desc_t *uri response uri_rd_t *rdp out the socket_t *so.
 */

static int
uri_rd_response(struct sonode *so,
    uri_desc_t *uri,
    uri_rd_t *rdp,
    boolean_t first)
{
	vnode_t		*vp = SOTOV(so);
	int		max_mblk = (int)vp->v_stream->sd_maxblk;
	int		wsz;
	mblk_t		*mp, *wmp, *persist;
	int		write_bytes;
	uri_rd_t	rd;
	uri_desb_t	desb;
	uri_segmap_t	*segmap = NULL;
	char		*segmap_data;
	size_t		segmap_sz;
	int		error;
	int		fflg = ((so->so_state & SS_NDELAY) ? FNDELAY : 0) |
	    ((so->so_state & SS_NONBLOCK) ? FNONBLOCK : 0);


	/* Initialize template uri_desb_t */
	desb.frtn.free_func = uri_desb_free;
	desb.frtn.free_arg = NULL;
	desb.uri = uri;

	/* Get a local copy of the rd_t */
	bcopy(rdp, &rd, sizeof (rd));
	do {
		if (first) {
			/*
			 * For first kstrwrite() enough data to get
			 * things going, note non blocking version of
			 * kstrwrite() will be used below.
			 */
			write_bytes = P2ROUNDUP((max_mblk * 4),
			    MAXBSIZE * nl7c_file_prefetch);
		} else {
			if ((write_bytes = so->so_sndbuf) == 0)
				write_bytes = vp->v_stream->sd_qn_maxpsz;
			ASSERT(write_bytes > 0);
			write_bytes = P2ROUNDUP(write_bytes, MAXBSIZE);
		}
		/*
		 * Chop up to a write_bytes worth of data.
		 */
		wmp = NULL;
		wsz = write_bytes;
		do {
			if (rd.sz == 0)
				break;
			if (rd.off == -1) {
				if (uri->eoh >= rd.data.kmem &&
				    uri->eoh < &rd.data.kmem[rd.sz]) {
					persist = nl7c_http_persist(so);
				} else {
					persist = NULL;
				}
				desb.segmap = NULL;
				mp = uri_desb_chop(&rd.data.kmem, &rd.sz,
				    &wsz, &desb, max_mblk, uri->eoh, persist);
				if (mp == NULL) {
					error = ENOMEM;
					goto invalidate;
				}
			} else {
				if (segmap == NULL) {
					segmap = uri_segmap_map(&rd,
					    write_bytes);
					if (segmap == NULL) {
						error = ENOMEM;
						goto invalidate;
					}
					desb.segmap = segmap;
					segmap_data = segmap->base;
					segmap_sz = segmap->len;
				}
				mp = uri_desb_chop(&segmap_data, &segmap_sz,
				    &wsz, &desb, max_mblk, NULL, NULL);
				if (mp == NULL) {
					error = ENOMEM;
					goto invalidate;
				}
				if (segmap_sz == 0) {
					rd.sz -= segmap->len;
					rd.off += segmap->len;
					REF_RELE(segmap);
					segmap = NULL;
				}
			}
			if (wmp == NULL) {
				wmp = mp;
			} else {
				wmp->b_next->b_cont = mp;
				wmp->b_next = mp->b_next;
				mp->b_next = NULL;
			}
		} while (wsz > 0 && rd.sz > 0);

		wmp->b_next = NULL;
		if (first) {
			/* First kstrwrite(), use noqwait */
			if ((error = kstrwritempnoqwait(vp, wmp)) != 0)
				goto invalidate;
			/*
			 * For the rest of the kstrwrite()s use SO_SNDBUF
			 * worth of data at a time, note these kstrwrite()s
			 * may (will) block one or more times.
			 */
			first = B_FALSE;
		} else {
			if ((error = kstrwritemp(vp, wmp, fflg)) != 0) {
				if (error == EAGAIN) {
					nl7c_uri_rd_EAGAIN++;
					if ((error =
					    kstrwritempnoqwait(vp, wmp)) != 0)
						goto invalidate;
				} else
					goto invalidate;
			}
		}
	} while (rd.sz > 0);

	return (0);

invalidate:
	if (segmap) {
		REF_RELE(segmap);
	}
	if (wmp)
		freemsg(wmp);

	return (error);
}

/*
 * Send the URI uri_desc_t *uri response out the socket_t *so.
 */

static int
uri_response(struct sonode *so, uri_desc_t *uri)
{
	uri_rd_t	*rdp = &uri->response;
	boolean_t	first = B_TRUE;
	int		error;

	while (rdp != NULL) {
		error = uri_rd_response(so, uri, rdp, first);
		if (error != 0) {
			goto invalidate;
		}
		first = B_FALSE;
		rdp = rdp->next;
	}
	return (0);

invalidate:
	if (uri->hash != URI_TEMP)
		uri_delete(uri);
	return (error);
}

/*
 * The pchars[] array is indexed by a char to determine if it's a
 * valid URI path component chararcter where:
 *
 *    pchar       = unreserved | escaped |
 *                  ":" | "@" | "&" | "=" | "+" | "$" | ","
 *
 *    unreserved  = alphanum | mark
 *
 *    alphanum    = alpha | digit
 *
 *    alpha       = lowalpha | upalpha
 *
 *    lowalpha    = "a" | "b" | "c" | "d" | "e" | "f" | "g" | "h" |
 *                  "i" | "j" | "k" | "l" | "m" | "n" | "o" | "p" |
 *                  "q" | "r" | "s" | "t" | "u" | "v" | "w" | "x" |
 *                  "y" | "z"
 *
 *    upalpha     = "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H" |
 *                  "I" | "J" | "K" | "L" | "M" | "N" | "O" | "P" |
 *                  "Q" | "R" | "S" | "T" | "U" | "V" | "W" | "X" |
 *                  "Y" | "Z"
 *
 *    digit       = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" |
 *                  "8" | "9"
 *
 *    mark        = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
 *
 *    escaped     = "%" hex hex
 *    hex         = digit | "A" | "B" | "C" | "D" | "E" | "F" |
 *                  "a" | "b" | "c" | "d" | "e" | "f"
 */

static char pchars[] = {
    0, 0, 0, 0, 0, 0, 0, 0,	/* 0x00 - 0x07 */
    0, 0, 0, 0, 0, 0, 0, 0,	/* 0x08 - 0x0F */
    0, 0, 0, 0, 0, 0, 0, 0,	/* 0x10 - 0x17 */
    0, 0, 0, 0, 0, 0, 0, 0,	/* 0x18 - 0x1F */
    0, 1, 0, 0, 1, 1, 1, 1,	/* 0x20 - 0x27 */
    0, 0, 1, 1, 1, 1, 1, 1,	/* 0x28 - 0x2F */
    1, 1, 1, 1, 1, 1, 1, 1,	/* 0x30 - 0x37 */
    1, 1, 1, 0, 0, 1, 0, 0,	/* 0x38 - 0x3F */
    1, 1, 1, 1, 1, 1, 1, 1,	/* 0x40 - 0x47 */
    1, 1, 1, 1, 1, 1, 1, 1,	/* 0x48 - 0x4F */
    1, 1, 1, 1, 1, 1, 1, 1,	/* 0x50 - 0x57 */
    1, 1, 1, 0, 0, 0, 0, 1,	/* 0x58 - 0x5F */
    0, 1, 1, 1, 1, 1, 1, 1,	/* 0x60 - 0x67 */
    1, 1, 1, 1, 1, 1, 1, 1,	/* 0x68 - 0x6F */
    1, 1, 1, 1, 1, 1, 1, 1,	/* 0x70 - 0x77 */
    1, 1, 1, 0, 0, 0, 1, 0	/* 0x78 - 0x7F */
};

#define	PCHARS_MASK 0x7F

/*
 * This is the main L7 request message parse, we are called each time
 * new data is availble for a socket, each time a single buffer of the
 * entire message to date is given.
 *
 * Here we parse the request looking for the URI, parse it, and if a
 * supported scheme call the scheme parser to commplete the parse of any
 * headers which may further qualify the identity of the requested object
 * then lookup it up in the URI hash.
 *
 * Return B_TRUE for more processing.
 *
 * Note, at this time the parser supports the generic message format as
 * specified in RFC 822 with potentional limitations as specified in RFC
 * 2616 for HTTP messages.
 *
 * Note, the caller supports an mblk_t chain, for now the parser(s)
 * require the complete header in a single mblk_t. This is the common
 * case and certainly for high performance environments, if at a future
 * date mblk_t chains are important the parse can be reved to process
 * mblk_t chains.
 */

boolean_t
nl7c_parse(struct sonode *so, boolean_t nonblocking, boolean_t *ret)
{
	sotpi_info_t *sti = SOTOTPI(so);
	char	*cp = (char *)sti->sti_nl7c_rcv_mp->b_rptr;
	char	*ep = (char *)sti->sti_nl7c_rcv_mp->b_wptr;
	char	*get = "GET ";
	char	*post = "POST ";
	char	c;
	char	*uris;
	uri_desc_t *uri = NULL;
	uri_desc_t *ruri = NULL;
	mblk_t	*reqmp;
	uint32_t hv = 0;

	if ((reqmp = dupb(sti->sti_nl7c_rcv_mp)) == NULL) {
		nl7c_uri_pass_dupbfail++;
		goto pass;
	}
	/*
	 * Allocate and initialize minimumal state for the request
	 * uri_desc_t, in the cache hit case this uri_desc_t will
	 * be freed.
	 */
	uri = kmem_cache_alloc(nl7c_uri_kmc, KM_SLEEP);
	REF_INIT(uri, 1, nl7c_uri_inactive, nl7c_uri_kmc);
	uri->hash = NULL;
	uri->tail = NULL;
	uri->scheme = NULL;
	uri->count = 0;
	uri->reqmp = reqmp;

	/*
	 * Set request time to current time.
	 */
	sti->sti_nl7c_rtime = gethrestime_sec();

	/*
	 * Parse the Request-Line for the URI.
	 *
	 * For backwards HTTP version compatable reasons skip any leading
	 * CRLF (or CR or LF) line terminator(s) preceding Request-Line.
	 */
	while (cp < ep && (*cp == '\r' || *cp == '\n')) {
		cp++;
	}
	while (cp < ep && *get == *cp) {
		get++;
		cp++;
	}
	if (*get != 0) {
		/* Note a "GET", check for "POST" */
		while (cp < ep && *post == *cp) {
			post++;
			cp++;
		}
		if (*post != 0) {
			if (cp == ep) {
				nl7c_uri_more_get++;
				goto more;
			}
			/* Not a "GET" or a "POST", just pass */
			nl7c_uri_pass_method++;
			goto pass;
		}
		/* "POST", don't cache but still may want to parse */
		uri->hash = URI_TEMP;
	}
	/*
	 * Skip over URI path char(s) and save start and past end pointers.
	 */
	uris = cp;
	while (cp < ep && (c = *cp) != ' ' && c != '\r') {
		if (c == '?') {
			/* Don't cache but still may want to parse */
			uri->hash = URI_TEMP;
		}
		CHASH(hv, c);
		cp++;
	}
	if (c != '\r' && cp == ep) {
		nl7c_uri_more_eol++;
		goto more;
	}
	/*
	 * Request-Line URI parsed, pass the rest of the request on
	 * to the the http scheme parse.
	 */
	uri->path.cp = uris;
	uri->path.ep = cp;
	uri->hvalue = hv;
	if (! nl7c_http_request(&cp, ep, uri, so) || cp == NULL) {
		/*
		 * Parse not successful or pass on request, the pointer
		 * to the parse pointer "cp" is overloaded such that ! NULL
		 * for more data and NULL for bad parse of request or pass.
		 */
		if (cp != NULL) {
			nl7c_uri_more_http++;
			goto more;
		}
		nl7c_uri_pass_http++;
		goto pass;
	}
	if (uri->nocache) {
		uri->hash = URI_TEMP;
		(void) uri_lookup(uri, B_FALSE, nonblocking);
	} else if (uri->hash == URI_TEMP) {
		uri->nocache = B_TRUE;
		(void) uri_lookup(uri, B_FALSE, nonblocking);
	}

	if (uri->hash == URI_TEMP) {
		if (sti->sti_nl7c_flags & NL7C_SOPERSIST) {
			/* Temporary URI so skip hash processing */
			nl7c_uri_request++;
			nl7c_uri_temp++;
			goto temp;
		}
		/* Not persistent so not interested in the response */
		nl7c_uri_pass_temp++;
		goto pass;
	}
	/*
	 * Check the URI hash for a cached response, save the request
	 * uri in case we need it below.
	 */
	ruri = uri;
	if ((uri = uri_lookup(uri, B_TRUE, nonblocking)) == NULL) {
		/*
		 * Failed to lookup due to nonblocking wait required,
		 * interrupted cv_wait_sig(), KM_NOSLEEP memory alloc
		 * failure, ... Just pass on this request.
		 */
		nl7c_uri_pass_addfail++;
		goto pass;
	}
	nl7c_uri_request++;
	if (uri->response.sz > 0) {
		/*
		 * We have the response cached, update recv mblk rptr
		 * to reflect the data consumed in parse.
		 */
		mblk_t	*mp = sti->sti_nl7c_rcv_mp;

		if (cp == (char *)mp->b_wptr) {
			sti->sti_nl7c_rcv_mp = mp->b_cont;
			mp->b_cont = NULL;
			freeb(mp);
		} else {
			mp->b_rptr = (unsigned char *)cp;
		}
		nl7c_uri_hit++;
		/* If logging enabled log request */
		if (nl7c_logd_enabled) {
			ipaddr_t faddr;

			if (so->so_family == AF_INET) {
				/* Only support IPv4 addrs */
				faddr = ((struct sockaddr_in *)
				    sti->sti_faddr_sa) ->sin_addr.s_addr;
			} else {
				faddr = 0;
			}
			/* XXX need to pass response type, e.g. 200, 304 */
			nl7c_logd_log(ruri, uri, sti->sti_nl7c_rtime, faddr);
		}

		/* If conditional request check for substitute response */
		if (ruri->conditional) {
			uri = nl7c_http_cond(ruri, uri);
		}

		/*
		 * Release reference on request URI, send the response out
		 * the socket, release reference on response uri, set the
		 * *ret value to B_TRUE to indicate request was consumed
		 * then return B_FALSE to indcate no more data needed.
		 */
		REF_RELE(ruri);
		(void) uri_response(so, uri);
		REF_RELE(uri);
		*ret = B_TRUE;
		return (B_FALSE);
	}
	/*
	 * Miss the cache, the request URI is in the cache waiting for
	 * application write-side data to fill it.
	 */
	nl7c_uri_miss++;
temp:
	/*
	 * A miss or temp URI for which response data is needed, link
	 * uri to so and so to uri, set WAITWRITE in the so such that
	 * read-side processing is suspended (so the next read() gets
	 * the request data) until a write() is processed by NL7C.
	 *
	 * Note, sti->sti_nl7c_uri now owns the REF_INIT() ref.
	 */
	uri->proc = so;
	sti->sti_nl7c_uri = uri;
	sti->sti_nl7c_flags |= NL7C_WAITWRITE;
	*ret = B_FALSE;
	return (B_FALSE);

more:
	/* More data is needed, note fragmented recv not supported */
	nl7c_uri_more++;

pass:
	/* Pass on this request */
	nl7c_uri_pass++;
	nl7c_uri_request++;
	if (ruri != NULL) {
		REF_RELE(ruri);
	}
	if (uri) {
		REF_RELE(uri);
	}
	sti->sti_nl7c_flags = 0;
	*ret = B_FALSE;
	return (B_FALSE);
}
