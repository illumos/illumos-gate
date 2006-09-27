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
#include <sys/errno.h>
#include <sys/strlog.h>
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/strsun.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <net/pfkeyv2.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/sadb.h>
#include <inet/ipsec_info.h>
#include <inet/ipsec_impl.h>
#include <inet/ipsecesp.h>
#include <inet/ipdrop.h>
#include <inet/tcp.h>
#include <sys/kstat.h>
#include <sys/policy.h>
#include <sys/strsun.h>
#include <inet/udp_impl.h>
#include <sys/taskq.h>

#include <sys/iphada.h>

/* Packet dropper for ESP drops. */
static ipdropper_t esp_dropper;

static kmutex_t ipsecesp_param_lock; /* Protects ipsecesp_param_arr[] below. */
/*
 * Table of ND variables supported by ipsecesp. These are loaded into
 * ipsecesp_g_nd in ipsecesp_init_nd.
 * All of these are alterable, within the min/max values given, at run time.
 */
static	ipsecespparam_t	ipsecesp_param_arr[] = {
	/* min	max			value	name */
	{ 0,	3,			0,	"ipsecesp_debug"},
	{ 125,	32000, SADB_AGE_INTERVAL_DEFAULT, "ipsecesp_age_interval"},
	{ 1,	10,			1,	"ipsecesp_reap_delay"},
	{ 1,	SADB_MAX_REPLAY,	64,	"ipsecesp_replay_size"},
	{ 1,	300,			15,	"ipsecesp_acquire_timeout"},
	{ 1,	1800,			90,	"ipsecesp_larval_timeout"},
	/* Default lifetime values for ACQUIRE messages. */
	{ 0,	0xffffffffU,	0,	"ipsecesp_default_soft_bytes"},
	{ 0,	0xffffffffU,	0,	"ipsecesp_default_hard_bytes"},
	{ 0,	0xffffffffU,	24000,	"ipsecesp_default_soft_addtime"},
	{ 0,	0xffffffffU,	28800,	"ipsecesp_default_hard_addtime"},
	{ 0,	0xffffffffU,	0,	"ipsecesp_default_soft_usetime"},
	{ 0,	0xffffffffU,	0,	"ipsecesp_default_hard_usetime"},
	{ 0,	1,		0,	"ipsecesp_log_unknown_spi"},
	{ 0,	2,		1,	"ipsecesp_padding_check"},
};
#define	ipsecesp_debug		ipsecesp_param_arr[0].ipsecesp_param_value
#define	ipsecesp_age_interval	ipsecesp_param_arr[1].ipsecesp_param_value
#define	ipsecesp_age_int_max	ipsecesp_param_arr[1].ipsecesp_param_max
#define	ipsecesp_reap_delay	ipsecesp_param_arr[2].ipsecesp_param_value
#define	ipsecesp_replay_size	ipsecesp_param_arr[3].ipsecesp_param_value
#define	ipsecesp_acquire_timeout ipsecesp_param_arr[4].ipsecesp_param_value
#define	ipsecesp_larval_timeout ipsecesp_param_arr[5].ipsecesp_param_value
#define	ipsecesp_default_soft_bytes \
	ipsecesp_param_arr[6].ipsecesp_param_value
#define	ipsecesp_default_hard_bytes \
	ipsecesp_param_arr[7].ipsecesp_param_value
#define	ipsecesp_default_soft_addtime \
	ipsecesp_param_arr[8].ipsecesp_param_value
#define	ipsecesp_default_hard_addtime \
	ipsecesp_param_arr[9].ipsecesp_param_value
#define	ipsecesp_default_soft_usetime \
	ipsecesp_param_arr[10].ipsecesp_param_value
#define	ipsecesp_default_hard_usetime \
	ipsecesp_param_arr[11].ipsecesp_param_value
#define	ipsecesp_log_unknown_spi \
	ipsecesp_param_arr[12].ipsecesp_param_value
#define	ipsecesp_padding_check \
	ipsecesp_param_arr[13].ipsecesp_param_value

#define	esp0dbg(a)	printf a
/* NOTE:  != 0 instead of > 0 so lint doesn't complain. */
#define	esp1dbg(a)	if (ipsecesp_debug != 0) printf a
#define	esp2dbg(a)	if (ipsecesp_debug > 1) printf a
#define	esp3dbg(a)	if (ipsecesp_debug > 2) printf a

static IDP ipsecesp_g_nd;

static int ipsecesp_open(queue_t *, dev_t *, int, int, cred_t *);
static int ipsecesp_close(queue_t *);
static void ipsecesp_rput(queue_t *, mblk_t *);
static void ipsecesp_wput(queue_t *, mblk_t *);
static void esp_send_acquire(ipsacq_t *, mblk_t *);

static ipsec_status_t esp_outbound_accelerated(mblk_t *, uint_t);
static ipsec_status_t esp_inbound_accelerated(mblk_t *, mblk_t *,
    boolean_t, ipsa_t *);

static boolean_t esp_register_out(uint32_t, uint32_t, uint_t);
static boolean_t esp_strip_header(mblk_t *, boolean_t, uint32_t,
    kstat_named_t **);
static ipsec_status_t esp_submit_req_inbound(mblk_t *, ipsa_t *, uint_t);
static ipsec_status_t esp_submit_req_outbound(mblk_t *, ipsa_t *, uchar_t *,
    uint_t);

static struct module_info info = {
	5137, "ipsecesp", 0, INFPSZ, 65536, 1024
};

static struct qinit rinit = {
	(pfi_t)ipsecesp_rput, NULL, ipsecesp_open, ipsecesp_close, NULL, &info,
	NULL
};

static struct qinit winit = {
	(pfi_t)ipsecesp_wput, NULL, ipsecesp_open, ipsecesp_close, NULL, &info,
	NULL
};

struct streamtab ipsecespinfo = {
	&rinit, &winit, NULL, NULL
};

/*
 * Keysock instance of ESP.  "There can be only one." :)
 * Use casptr() on this because I don't set it until KEYSOCK_HELLO comes down.
 * Paired up with the esp_pfkey_q is the esp_event, which will age SAs.
 */
static queue_t *esp_pfkey_q;
static timeout_id_t esp_event;
static taskq_t *esp_taskq;

/*
 * OTOH, this one is set at open/close, and I'm D_MTQPAIR for now.
 *
 * Question:	Do I need this, given that all instance's esps->esps_wq point
 *		to IP?
 *
 * Answer:	Yes, because I need to know which queue is BOUND to
 *		IPPROTO_ESP
 */
static mblk_t *esp_ip_unbind;

/*
 * Stats.  This may eventually become a full-blown SNMP MIB once that spec
 * stabilizes.
 */

typedef struct {
	kstat_named_t esp_stat_num_aalgs;
	kstat_named_t esp_stat_good_auth;
	kstat_named_t esp_stat_bad_auth;
	kstat_named_t esp_stat_bad_padding;
	kstat_named_t esp_stat_replay_failures;
	kstat_named_t esp_stat_replay_early_failures;
	kstat_named_t esp_stat_keysock_in;
	kstat_named_t esp_stat_out_requests;
	kstat_named_t esp_stat_acquire_requests;
	kstat_named_t esp_stat_bytes_expired;
	kstat_named_t esp_stat_out_discards;
	kstat_named_t esp_stat_in_accelerated;
	kstat_named_t esp_stat_out_accelerated;
	kstat_named_t esp_stat_noaccel;
	kstat_named_t esp_stat_crypto_sync;
	kstat_named_t esp_stat_crypto_async;
	kstat_named_t esp_stat_crypto_failures;
	kstat_named_t esp_stat_num_ealgs;
	kstat_named_t esp_stat_bad_decrypt;
} esp_kstats_t;

uint32_t esp_hash_size = IPSEC_DEFAULT_HASH_SIZE;
#define	ESP_BUMP_STAT(x) (esp_kstats->esp_stat_ ## x).value.ui64++
#define	ESP_DEBUMP_STAT(x) (esp_kstats->esp_stat_ ## x).value.ui64--

static kstat_t *esp_ksp;
static esp_kstats_t *esp_kstats;

static int	esp_kstat_update(kstat_t *, int);

static boolean_t
esp_kstat_init(void)
{
	esp_ksp = kstat_create("ipsecesp", 0, "esp_stat", "net",
	    KSTAT_TYPE_NAMED, sizeof (*esp_kstats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT);

	if (esp_ksp == NULL)
		return (B_FALSE);

	esp_kstats = esp_ksp->ks_data;

	esp_ksp->ks_update = esp_kstat_update;

#define	K64 KSTAT_DATA_UINT64
#define	KI(x) kstat_named_init(&(esp_kstats->esp_stat_##x), #x, K64)

	KI(num_aalgs);
	KI(num_ealgs);
	KI(good_auth);
	KI(bad_auth);
	KI(bad_padding);
	KI(replay_failures);
	KI(replay_early_failures);
	KI(keysock_in);
	KI(out_requests);
	KI(acquire_requests);
	KI(bytes_expired);
	KI(out_discards);
	KI(in_accelerated);
	KI(out_accelerated);
	KI(noaccel);
	KI(crypto_sync);
	KI(crypto_async);
	KI(crypto_failures);
	KI(bad_decrypt);

#undef KI
#undef K64

	kstat_install(esp_ksp);

	return (B_TRUE);
}

static int
esp_kstat_update(kstat_t *kp, int rw)
{
	esp_kstats_t *ekp;

	if ((kp == NULL) || (kp->ks_data == NULL))
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ASSERT(kp == esp_ksp);
	ekp = (esp_kstats_t *)kp->ks_data;
	ASSERT(ekp == esp_kstats);

	mutex_enter(&alg_lock);
	ekp->esp_stat_num_aalgs.value.ui64 = ipsec_nalgs[IPSEC_ALG_AUTH];
	ekp->esp_stat_num_ealgs.value.ui64 = ipsec_nalgs[IPSEC_ALG_ENCR];
	mutex_exit(&alg_lock);

	return (0);
}

#ifdef DEBUG
/*
 * Debug routine, useful to see pre-encryption data.
 */
static char *
dump_msg(mblk_t *mp)
{
	char tmp_str[3], tmp_line[256];

	while (mp != NULL) {
		unsigned char *ptr;

		printf("mblk address 0x%p, length %ld, db_ref %d "
		    "type %d, base 0x%p, lim 0x%p\n",
		    (void *) mp, (long)(mp->b_wptr - mp->b_rptr),
		    mp->b_datap->db_ref, mp->b_datap->db_type,
		    (void *)mp->b_datap->db_base, (void *)mp->b_datap->db_lim);
		ptr = mp->b_rptr;

		tmp_line[0] = '\0';
		while (ptr < mp->b_wptr) {
			uint_t diff;

			diff = (ptr - mp->b_rptr);
			if (!(diff & 0x1f)) {
				if (strlen(tmp_line) > 0) {
					printf("bytes: %s\n", tmp_line);
					tmp_line[0] = '\0';
				}
			}
			if (!(diff & 0x3))
				(void) strcat(tmp_line, " ");
			(void) sprintf(tmp_str, "%02x", *ptr);
			(void) strcat(tmp_line, tmp_str);
			ptr++;
		}
		if (strlen(tmp_line) > 0)
			printf("bytes: %s\n", tmp_line);

		mp = mp->b_cont;
	}

	return ("\n");
}

#else /* DEBUG */
static char *
dump_msg(mblk_t *mp)
{
	printf("Find value of mp %p.\n", mp);
	return ("\n");
}
#endif /* DEBUG */

/*
 * Don't have to lock age_interval, as only one thread will access it at
 * a time, because I control the one function that does with timeout().
 */
/* ARGSUSED */
static void
esp_ager(void *ignoreme)
{
	hrtime_t begin = gethrtime();

	sadb_ager(&esp_sadb.s_v4, esp_pfkey_q, esp_sadb.s_ip_q,
	    ipsecesp_reap_delay);
	sadb_ager(&esp_sadb.s_v6, esp_pfkey_q, esp_sadb.s_ip_q,
	    ipsecesp_reap_delay);

	esp_event = sadb_retimeout(begin, esp_pfkey_q, esp_ager,
	    &(ipsecesp_age_interval), ipsecesp_age_int_max, info.mi_idnum);
}

/*
 * Get an ESP NDD parameter.
 */
/* ARGSUSED */
static int
ipsecesp_param_get(q, mp, cp, cr)
	queue_t	*q;
	mblk_t	*mp;
	caddr_t	cp;
	cred_t *cr;
{
	ipsecespparam_t	*ipsecesppa = (ipsecespparam_t *)cp;
	uint_t value;

	mutex_enter(&ipsecesp_param_lock);
	value = ipsecesppa->ipsecesp_param_value;
	mutex_exit(&ipsecesp_param_lock);

	(void) mi_mpprintf(mp, "%u", value);
	return (0);
}

/*
 * This routine sets an NDD variable in a ipsecespparam_t structure.
 */
/* ARGSUSED */
static int
ipsecesp_param_set(q, mp, value, cp, cr)
	queue_t	*q;
	mblk_t	*mp;
	char	*value;
	caddr_t	cp;
	cred_t *cr;
{
	ulong_t	new_value;
	ipsecespparam_t	*ipsecesppa = (ipsecespparam_t *)cp;

	/*
	 * Fail the request if the new value does not lie within the
	 * required bounds.
	 */
	if (ddi_strtoul(value, NULL, 10, &new_value) != 0 ||
	    new_value < ipsecesppa->ipsecesp_param_min ||
	    new_value > ipsecesppa->ipsecesp_param_max) {
		return (EINVAL);
	}

	/* Set the new value */
	mutex_enter(&ipsecesp_param_lock);
	ipsecesppa->ipsecesp_param_value = new_value;
	mutex_exit(&ipsecesp_param_lock);
	return (0);
}

/*
 * Using lifetime NDD variables, fill in an extended combination's
 * lifetime information.
 */
void
ipsecesp_fill_defs(sadb_x_ecomb_t *ecomb)
{
	ecomb->sadb_x_ecomb_soft_bytes = ipsecesp_default_soft_bytes;
	ecomb->sadb_x_ecomb_hard_bytes = ipsecesp_default_hard_bytes;
	ecomb->sadb_x_ecomb_soft_addtime = ipsecesp_default_soft_addtime;
	ecomb->sadb_x_ecomb_hard_addtime = ipsecesp_default_hard_addtime;
	ecomb->sadb_x_ecomb_soft_usetime = ipsecesp_default_soft_usetime;
	ecomb->sadb_x_ecomb_hard_usetime = ipsecesp_default_hard_usetime;
}

/*
 * Initialize things for ESP at module load time.
 */
boolean_t
ipsecesp_ddi_init(void)
{
	int count;
	ipsecespparam_t *espp = ipsecesp_param_arr;

	for (count = A_CNT(ipsecesp_param_arr); count-- > 0; espp++) {
		if (espp->ipsecesp_param_name != NULL &&
		    espp->ipsecesp_param_name[0]) {
			if (!nd_load(&ipsecesp_g_nd, espp->ipsecesp_param_name,
			    ipsecesp_param_get, ipsecesp_param_set,
			    (caddr_t)espp)) {
				nd_free(&ipsecesp_g_nd);
				return (B_FALSE);
			}
		}
	}

	if (!esp_kstat_init()) {
		nd_free(&ipsecesp_g_nd);
		return (B_FALSE);
	}

	esp_sadb.s_acquire_timeout = &ipsecesp_acquire_timeout;
	esp_sadb.s_acqfn = esp_send_acquire;
	sadbp_init("ESP", &esp_sadb, SADB_SATYPE_ESP, esp_hash_size);

	esp_taskq = taskq_create("esp_taskq", 1, minclsyspri,
	    IPSEC_TASKQ_MIN, IPSEC_TASKQ_MAX, 0);

	mutex_init(&ipsecesp_param_lock, NULL, MUTEX_DEFAULT, 0);

	ip_drop_register(&esp_dropper, "IPsec ESP");

	return (B_TRUE);
}

/*
 * Destroy things for ESP at module unload time.
 */
void
ipsecesp_ddi_destroy(void)
{
	esp1dbg(("In ipsecesp_ddi_destroy.\n"));

	sadbp_destroy(&esp_sadb);
	ip_drop_unregister(&esp_dropper);
	taskq_destroy(esp_taskq);
	mutex_destroy(&ipsecesp_param_lock);
	nd_free(&ipsecesp_g_nd);
	kstat_delete(esp_ksp);
}

/*
 * ESP module open routine.
 */
/* ARGSUSED */
static int
ipsecesp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	if (secpolicy_net_config(credp, B_FALSE) != 0) {
		esp1dbg(("Non-privileged user trying to open ipsecesp.\n"));
		return (EPERM);
	}

	if (q->q_ptr != NULL)
		return (0);  /* Re-open of an already open instance. */

	if (sflag != MODOPEN)
		return (EINVAL);

	/*
	 * ASSUMPTIONS (because I'm MT_OCEXCL):
	 *
	 *	* I'm being pushed on top of IP for all my opens (incl. #1).
	 *	* Only ipsecesp_open() can write into esp_sadb.s_ip_q.
	 *	* Because of this, I can check lazily for esp_sadb.s_ip_q.
	 *
	 *  If these assumptions are wrong, I'm in BIG trouble...
	 */

	q->q_ptr = q; /* just so I know I'm open */

	if (esp_sadb.s_ip_q == NULL) {
		struct T_unbind_req *tur;

		esp_sadb.s_ip_q = WR(q);
		/* Allocate an unbind... */
		esp_ip_unbind = allocb(sizeof (struct T_unbind_req), BPRI_HI);

		/*
		 * Send down T_BIND_REQ to bind IPPROTO_ESP.
		 * Handle the ACK here in ESP.
		 */
		qprocson(q);
		if (esp_ip_unbind == NULL ||
		    !sadb_t_bind_req(esp_sadb.s_ip_q, IPPROTO_ESP)) {
			if (esp_ip_unbind != NULL) {
				freeb(esp_ip_unbind);
				esp_ip_unbind = NULL;
			}
			q->q_ptr = NULL;
			return (ENOMEM);
		}

		esp_ip_unbind->b_datap->db_type = M_PROTO;
		tur = (struct T_unbind_req *)esp_ip_unbind->b_rptr;
		tur->PRIM_type = T_UNBIND_REQ;
	} else {
		qprocson(q);
	}

	/*
	 * For now, there's not much I can do.  I'll be getting a message
	 * passed down to me from keysock (in my wput), and a T_BIND_ACK
	 * up from IP (in my rput).
	 */

	return (0);
}

/*
 * ESP module close routine.
 */
static int
ipsecesp_close(queue_t *q)
{
	/*
	 * If esp_sadb.s_ip_q is attached to this instance, send a
	 * T_UNBIND_REQ to IP for the instance before doing
	 * a qprocsoff().
	 */
	if (WR(q) == esp_sadb.s_ip_q && esp_ip_unbind != NULL) {
		putnext(WR(q), esp_ip_unbind);
		esp_ip_unbind = NULL;
	}

	/*
	 * Clean up q_ptr, if needed.
	 */
	qprocsoff(q);

	/* Keysock queue check is safe, because of OCEXCL perimeter. */

	if (q == esp_pfkey_q) {
		esp0dbg(("ipsecesp_close:  Ummm... keysock is closing ESP.\n"));
		esp_pfkey_q = NULL;
		/* Detach qtimeouts. */
		(void) quntimeout(q, esp_event);
	}

	if (WR(q) == esp_sadb.s_ip_q) {
		/*
		 * If the esp_sadb.s_ip_q is attached to this instance, find
		 * another.  The OCEXCL outer perimeter helps us here.
		 */
		esp_sadb.s_ip_q = NULL;

		/*
		 * Find a replacement queue for esp_sadb.s_ip_q.
		 */
		if (esp_pfkey_q != NULL && esp_pfkey_q != RD(q)) {
			/*
			 * See if we can use the pfkey_q.
			 */
			esp_sadb.s_ip_q = WR(esp_pfkey_q);
		}

		if (esp_sadb.s_ip_q == NULL ||
		    !sadb_t_bind_req(esp_sadb.s_ip_q, IPPROTO_ESP)) {
			esp1dbg(("ipsecesp: Can't reassign ip_q.\n"));
			esp_sadb.s_ip_q = NULL;
		} else {
			esp_ip_unbind = allocb(sizeof (struct T_unbind_req),
			    BPRI_HI);

			if (esp_ip_unbind != NULL) {
				struct T_unbind_req *tur;

				esp_ip_unbind->b_datap->db_type = M_PROTO;
				tur = (struct T_unbind_req *)
				    esp_ip_unbind->b_rptr;
				tur->PRIM_type = T_UNBIND_REQ;
			}
			/* If it's NULL, I can't do much here. */
		}
	}

	return (0);
}

/*
 * Add a number of bytes to what the SA has protected so far.  Return
 * B_TRUE if the SA can still protect that many bytes.
 *
 * Caller must REFRELE the passed-in assoc.  This function must REFRELE
 * any obtained peer SA.
 */
static boolean_t
esp_age_bytes(ipsa_t *assoc, uint64_t bytes, boolean_t inbound)
{
	ipsa_t *inassoc, *outassoc;
	isaf_t *bucket;
	boolean_t inrc, outrc, isv6;
	sadb_t *sp;
	int outhash;

	/* No peer?  No problem! */
	if (!assoc->ipsa_haspeer) {
		return (sadb_age_bytes(esp_pfkey_q, assoc, bytes,
		    B_TRUE));
	}

	/*
	 * Otherwise, we want to grab both the original assoc and its peer.
	 * There might be a race for this, but if it's a real race, two
	 * expire messages may occur.  We limit this by only sending the
	 * expire message on one of the peers, we'll pick the inbound
	 * arbitrarily.
	 *
	 * If we need tight synchronization on the peer SA, then we need to
	 * reconsider.
	 */

	/* Use address length to select IPv6/IPv4 */
	isv6 = (assoc->ipsa_addrfam == AF_INET6);
	sp = isv6 ? &esp_sadb.s_v6 : &esp_sadb.s_v4;

	if (inbound) {
		inassoc = assoc;
		if (isv6) {
			outhash = OUTBOUND_HASH_V6(sp, *((in6_addr_t *)
			    &inassoc->ipsa_dstaddr));
		} else {
			outhash = OUTBOUND_HASH_V4(sp, *((ipaddr_t *)
				&inassoc->ipsa_dstaddr));
		}
		bucket = &sp->sdb_of[outhash];
		mutex_enter(&bucket->isaf_lock);
		outassoc = ipsec_getassocbyspi(bucket, inassoc->ipsa_spi,
		    inassoc->ipsa_srcaddr, inassoc->ipsa_dstaddr,
		    inassoc->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (outassoc == NULL) {
			/* Q: Do we wish to set haspeer == B_FALSE? */
			esp0dbg(("esp_age_bytes: "
			    "can't find peer for inbound.\n"));
			return (sadb_age_bytes(esp_pfkey_q, inassoc,
			    bytes, B_TRUE));
		}
	} else {
		outassoc = assoc;
		bucket = INBOUND_BUCKET(sp, outassoc->ipsa_spi);
		mutex_enter(&bucket->isaf_lock);
		inassoc = ipsec_getassocbyspi(bucket, outassoc->ipsa_spi,
		    outassoc->ipsa_srcaddr, outassoc->ipsa_dstaddr,
		    outassoc->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (inassoc == NULL) {
			/* Q: Do we wish to set haspeer == B_FALSE? */
			esp0dbg(("esp_age_bytes: "
			    "can't find peer for outbound.\n"));
			return (sadb_age_bytes(esp_pfkey_q, outassoc,
			    bytes, B_TRUE));
		}
	}

	inrc = sadb_age_bytes(esp_pfkey_q, inassoc, bytes, B_TRUE);
	outrc = sadb_age_bytes(esp_pfkey_q, outassoc, bytes, B_FALSE);

	/*
	 * REFRELE any peer SA.
	 *
	 * Because of the multi-line macro nature of IPSA_REFRELE, keep
	 * them in { }.
	 */
	if (inbound) {
		IPSA_REFRELE(outassoc);
	} else {
		IPSA_REFRELE(inassoc);
	}

	return (inrc && outrc);
}

/*
 * Do incoming NAT-T manipulations for packet.
 */
static ipsec_status_t
esp_fix_natt_checksums(mblk_t *data_mp, ipsa_t *assoc)
{
	ipha_t *ipha = (ipha_t *)data_mp->b_rptr;
	tcpha_t *tcph;
	udpha_t *udpha;
	/* Initialize to our inbound cksum adjustment... */
	uint32_t sum = assoc->ipsa_inbound_cksum;

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP:
		tcph = (tcpha_t *)(data_mp->b_rptr +
		    IPH_HDR_LENGTH(ipha));

#define	DOWN_SUM(x) (x) = ((x) & 0xFFFF) +	 ((x) >> 16)
		sum += ~ntohs(tcph->tha_sum) & 0xFFFF;
		DOWN_SUM(sum);
		DOWN_SUM(sum);
		tcph->tha_sum = ~htons(sum);
		break;
	case IPPROTO_UDP:
		udpha = (udpha_t *)(data_mp->b_rptr + IPH_HDR_LENGTH(ipha));

		if (udpha->uha_checksum != 0) {
			/* Adujst if the inbound one was not zero. */
			sum += ~ntohs(udpha->uha_checksum) & 0xFFFF;
			DOWN_SUM(sum);
			DOWN_SUM(sum);
			udpha->uha_checksum = ~htons(sum);
			if (udpha->uha_checksum == 0)
				udpha->uha_checksum = 0xFFFF;
		}
#undef DOWN_SUM
		break;
	case IPPROTO_IP:
		/*
		 * This case is only an issue for self-encapsulated
		 * packets.  So for now, fall through.
		 */
		break;
	}
	return (IPSEC_STATUS_SUCCESS);
}


/*
 * Strip ESP header and fix IP header
 * Returns B_TRUE on success, B_FALSE if an error occured.
 */
static boolean_t
esp_strip_header(mblk_t *data_mp, boolean_t isv4, uint32_t ivlen,
    kstat_named_t **counter)
{
	ipha_t *ipha;
	ip6_t *ip6h;
	uint_t divpoint;
	mblk_t *scratch;
	uint8_t nexthdr, padlen;
	uint8_t lastpad;

	/*
	 * Strip ESP data and fix IP header.
	 *
	 * XXX In case the beginning of esp_inbound() changes to not do a
	 * pullup, this part of the code can remain unchanged.
	 */
	if (isv4) {
		ASSERT((data_mp->b_wptr - data_mp->b_rptr) >= sizeof (ipha_t));
		ipha = (ipha_t *)data_mp->b_rptr;
		ASSERT((data_mp->b_wptr - data_mp->b_rptr) >= sizeof (esph_t) +
		    IPH_HDR_LENGTH(ipha));
		divpoint = IPH_HDR_LENGTH(ipha);
	} else {
		ASSERT((data_mp->b_wptr - data_mp->b_rptr) >= sizeof (ip6_t));
		ip6h = (ip6_t *)data_mp->b_rptr;
		divpoint = ip_hdr_length_v6(data_mp, ip6h);
	}

	scratch = data_mp;
	while (scratch->b_cont != NULL)
		scratch = scratch->b_cont;

	ASSERT((scratch->b_wptr - scratch->b_rptr) >= 3);

	/*
	 * "Next header" and padding length are the last two bytes in the
	 * ESP-protected datagram, thus the explicit - 1 and - 2.
	 * lastpad is the last byte of the padding, which can be used for
	 * a quick check to see if the padding is correct.
	 */
	nexthdr = *(scratch->b_wptr - 1);
	padlen = *(scratch->b_wptr - 2);
	lastpad = *(scratch->b_wptr - 3);

	if (isv4) {
		/* Fix part of the IP header. */
		ipha->ipha_protocol = nexthdr;
		/*
		 * Reality check the padlen.  The explicit - 2 is for the
		 * padding length and the next-header bytes.
		 */
		if (padlen >= ntohs(ipha->ipha_length) - sizeof (ipha_t) - 2 -
		    sizeof (esph_t) - ivlen) {
			ESP_BUMP_STAT(bad_decrypt);
			ipsec_rl_strlog(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
			    "Possibly corrupt ESP packet.");
			esp1dbg(("padlen (%d) is greater than:\n", padlen));
			esp1dbg(("pkt len(%d) - ip hdr - esp hdr - ivlen(%d) "
			    "= %d.\n", ntohs(ipha->ipha_length), ivlen,
			    (int)(ntohs(ipha->ipha_length) - sizeof (ipha_t) -
				2 - sizeof (esph_t) - ivlen)));
			*counter = &ipdrops_esp_bad_padlen;
			return (B_FALSE);
		}

		/*
		 * Fix the rest of the header.  The explicit - 2 is for the
		 * padding length and the next-header bytes.
		 */
		ipha->ipha_length = htons(ntohs(ipha->ipha_length) - padlen -
		    2 - sizeof (esph_t) - ivlen);
		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = (uint16_t)ip_csum_hdr(ipha);
	} else {
		if (ip6h->ip6_nxt == IPPROTO_ESP) {
			ip6h->ip6_nxt = nexthdr;
		} else {
			ip6_pkt_t ipp;

			bzero(&ipp, sizeof (ipp));
			(void) ip_find_hdr_v6(data_mp, ip6h, &ipp, NULL);
			if (ipp.ipp_dstopts != NULL) {
				ipp.ipp_dstopts->ip6d_nxt = nexthdr;
			} else if (ipp.ipp_rthdr != NULL) {
				ipp.ipp_rthdr->ip6r_nxt = nexthdr;
			} else if (ipp.ipp_hopopts != NULL) {
				ipp.ipp_hopopts->ip6h_nxt = nexthdr;
			} else {
				/* Panic a DEBUG kernel. */
				ASSERT(ipp.ipp_hopopts != NULL);
				/* Otherwise, pretend it's IP + ESP. */
				cmn_err(CE_WARN, "ESP IPv6 headers wrong.\n");
				ip6h->ip6_nxt = nexthdr;
			}
		}

		if (padlen >= ntohs(ip6h->ip6_plen) - 2 - sizeof (esph_t) -
		    ivlen) {
			ESP_BUMP_STAT(bad_decrypt);
			ipsec_rl_strlog(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
			    "Possibly corrupt ESP packet.");
			esp1dbg(("padlen (%d) is greater than:\n", padlen));
			esp1dbg(("pkt len(%u) - ip hdr - esp hdr - ivlen(%d)"
			    " = %u.\n", (unsigned)(ntohs(ip6h->ip6_plen)
				+ sizeof (ip6_t)), ivlen,
			    (unsigned)(ntohs(ip6h->ip6_plen) - 2 -
				sizeof (esph_t) - ivlen)));
			*counter = &ipdrops_esp_bad_padlen;
			return (B_FALSE);
		}


		/*
		 * Fix the rest of the header.  The explicit - 2 is for the
		 * padding length and the next-header bytes.  IPv6 is nice,
		 * because there's no hdr checksum!
		 */
		ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) - padlen -
		    2 - sizeof (esph_t) - ivlen);
	}

	if (ipsecesp_padding_check > 0 &&
		padlen != lastpad && padlen != 0) {
		ipsec_rl_strlog(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
		    "Possibly corrupt ESP packet.");
		esp1dbg(("lastpad (%d) not equal to padlen (%d):\n",
		    lastpad, padlen));
		ESP_BUMP_STAT(bad_padding);
		*counter = &ipdrops_esp_bad_padding;
		return (B_FALSE);
	}

	if (ipsecesp_padding_check > 1) {
		uint8_t *last = (uint8_t *)(scratch->b_wptr - 3);
		uint8_t lastval = *last;

		/*
		 * this assert may have to become an if
		 * and a pullup if we start accepting
		 * multi-dblk mblks. Any packet here will
		 * have been pulled up in esp_inbound.
		 */
		ASSERT(MBLKL(scratch) >= lastval + 3);

		while (lastval != 0) {
			if (lastval != *last) {
				ipsec_rl_strlog(info.mi_idnum, 0, 0,
				    SL_ERROR | SL_WARN,
				    "Possibly corrupt ESP packet.");
				esp1dbg(("padding not in correct"
				    " format:\n"));
				ESP_BUMP_STAT(bad_padding);
				*counter = &ipdrops_esp_bad_padding;
				return (B_FALSE);
			}
			lastval--; last--;
		}
	}

	/* Trim off the padding. */
	ASSERT(data_mp->b_cont == NULL);
	data_mp->b_wptr -= (padlen + 2);

	/*
	 * Remove the ESP header.
	 *
	 * The above assertions about data_mp's size will make this work.
	 *
	 * XXX  Question:  If I send up and get back a contiguous mblk,
	 * would it be quicker to bcopy over, or keep doing the dupb stuff?
	 * I go with copying for now.
	 */

	if (IS_P2ALIGNED(data_mp->b_rptr, sizeof (uint32_t)) &&
	    IS_P2ALIGNED(ivlen, sizeof (uint32_t))) {
		uint8_t *start = data_mp->b_rptr;
		uint32_t *src, *dst;

		src = (uint32_t *)(start + divpoint);
		dst = (uint32_t *)(start + divpoint + sizeof (esph_t) + ivlen);

		ASSERT(IS_P2ALIGNED(dst, sizeof (uint32_t)) &&
		    IS_P2ALIGNED(src, sizeof (uint32_t)));

		do {
			src--;
			dst--;
			*dst = *src;
		} while (src != (uint32_t *)start);

		data_mp->b_rptr = (uchar_t *)dst;
	} else {
		uint8_t *start = data_mp->b_rptr;
		uint8_t *src, *dst;

		src = start + divpoint;
		dst = src + sizeof (esph_t) + ivlen;

		do {
			src--;
			dst--;
			*dst = *src;
		} while (src != start);

		data_mp->b_rptr = dst;
	}

	esp2dbg(("data_mp after inbound ESP adjustment:\n"));
	esp2dbg((dump_msg(data_mp)));

	return (B_TRUE);
}

/*
 * Updating use times can be tricky business if the ipsa_haspeer flag is
 * set.  This function is called once in an SA's lifetime.
 *
 * Caller has to REFRELE "assoc" which is passed in.  This function has
 * to REFRELE any peer SA that is obtained.
 */
static void
esp_set_usetime(ipsa_t *assoc, boolean_t inbound)
{
	ipsa_t *inassoc, *outassoc;
	isaf_t *bucket;
	sadb_t *sp;
	int outhash;
	boolean_t isv6;

	/* No peer?  No problem! */
	if (!assoc->ipsa_haspeer) {
		sadb_set_usetime(assoc);
		return;
	}

	/*
	 * Otherwise, we want to grab both the original assoc and its peer.
	 * There might be a race for this, but if it's a real race, the times
	 * will be out-of-synch by at most a second, and since our time
	 * granularity is a second, this won't be a problem.
	 *
	 * If we need tight synchronization on the peer SA, then we need to
	 * reconsider.
	 */

	/* Use address length to select IPv6/IPv4 */
	isv6 = (assoc->ipsa_addrfam == AF_INET6);
	sp = isv6 ? &esp_sadb.s_v6 : &esp_sadb.s_v4;

	if (inbound) {
		inassoc = assoc;
		if (isv6) {
			outhash = OUTBOUND_HASH_V6(sp, *((in6_addr_t *)
			    &inassoc->ipsa_dstaddr));
		} else {
			outhash = OUTBOUND_HASH_V4(sp, *((ipaddr_t *)
				&inassoc->ipsa_dstaddr));
		}
		bucket = &sp->sdb_of[outhash];
		mutex_enter(&bucket->isaf_lock);
		outassoc = ipsec_getassocbyspi(bucket, inassoc->ipsa_spi,
		    inassoc->ipsa_srcaddr, inassoc->ipsa_dstaddr,
		    inassoc->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (outassoc == NULL) {
			/* Q: Do we wish to set haspeer == B_FALSE? */
			esp0dbg(("esp_set_usetime: "
			    "can't find peer for inbound.\n"));
			sadb_set_usetime(inassoc);
			return;
		}
	} else {
		outassoc = assoc;
		bucket = INBOUND_BUCKET(sp, outassoc->ipsa_spi);
		mutex_enter(&bucket->isaf_lock);
		inassoc = ipsec_getassocbyspi(bucket, outassoc->ipsa_spi,
		    outassoc->ipsa_srcaddr, outassoc->ipsa_dstaddr,
		    outassoc->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (inassoc == NULL) {
			/* Q: Do we wish to set haspeer == B_FALSE? */
			esp0dbg(("esp_set_usetime: "
			    "can't find peer for outbound.\n"));
			sadb_set_usetime(outassoc);
			return;
		}
	}

	/* Update usetime on both. */
	sadb_set_usetime(inassoc);
	sadb_set_usetime(outassoc);

	/*
	 * REFRELE any peer SA.
	 *
	 * Because of the multi-line macro nature of IPSA_REFRELE, keep
	 * them in { }.
	 */
	if (inbound) {
		IPSA_REFRELE(outassoc);
	} else {
		IPSA_REFRELE(inassoc);
	}
}

/*
 * Handle ESP inbound data for IPv4 and IPv6.
 * On success returns B_TRUE, on failure returns B_FALSE and frees the
 * mblk chain ipsec_in_mp.
 */
ipsec_status_t
esp_inbound(mblk_t *ipsec_in_mp, void *arg)
{
	mblk_t *data_mp = ipsec_in_mp->b_cont;
	ipsec_in_t *ii = (ipsec_in_t *)ipsec_in_mp->b_rptr;
	esph_t *esph = (esph_t *)arg;
	ipsa_t *ipsa = ii->ipsec_in_esp_sa;

	if (ipsa->ipsa_usetime == 0)
		esp_set_usetime(ipsa, B_TRUE);

	/*
	 * We may wish to check replay in-range-only here as an optimization.
	 * Include the reality check of ipsa->ipsa_replay >
	 * ipsa->ipsa_replay_wsize for times when it's the first N packets,
	 * where N == ipsa->ipsa_replay_wsize.
	 *
	 * Another check that may come here later is the "collision" check.
	 * If legitimate packets flow quickly enough, this won't be a problem,
	 * but collisions may cause authentication algorithm crunching to
	 * take place when it doesn't need to.
	 */
	if (!sadb_replay_peek(ipsa, esph->esph_replay)) {
		ESP_BUMP_STAT(replay_early_failures);
		IP_ESP_BUMP_STAT(in_discards);
		/*
		 * TODO: Extract inbound interface from the IPSEC_IN
		 * message's ii->ipsec_in_rill_index.
		 */
		ip_drop_packet(ipsec_in_mp, B_TRUE, NULL, NULL,
		    &ipdrops_esp_early_replay, &esp_dropper);
		return (IPSEC_STATUS_FAILED);
	}

	/*
	 * Has this packet already been processed by a hardware
	 * IPsec accelerator?
	 */
	if (ii->ipsec_in_accelerated) {
		ipsec_status_t rv;
		esp3dbg(("esp_inbound: pkt processed by ill=%d isv6=%d\n",
		    ii->ipsec_in_ill_index, !ii->ipsec_in_v4));
		rv = esp_inbound_accelerated(ipsec_in_mp,
		    data_mp, ii->ipsec_in_v4, ipsa);
		return (rv);
	}
	ESP_BUMP_STAT(noaccel);

	/*
	 * Adjust the IP header's payload length to reflect the removal
	 * of the ICV.
	 */
	if (!ii->ipsec_in_v4) {
		ip6_t *ip6h = (ip6_t *)data_mp->b_rptr;
		ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) -
		    ipsa->ipsa_mac_len);
	} else {
		ipha_t *ipha = (ipha_t *)data_mp->b_rptr;
		ipha->ipha_length = htons(ntohs(ipha->ipha_length) -
		    ipsa->ipsa_mac_len);
	}

	/* submit the request to the crypto framework */
	return (esp_submit_req_inbound(ipsec_in_mp, ipsa,
	    (uint8_t *)esph - data_mp->b_rptr));
}

/*
 * Perform the really difficult work of inserting the proposed situation.
 * Called while holding the algorithm lock.
 */
static void
esp_insert_prop(sadb_prop_t *prop, ipsacq_t *acqrec, uint_t combs)
{
	sadb_comb_t *comb = (sadb_comb_t *)(prop + 1);
	ipsec_out_t *io;
	ipsec_action_t *ap;
	ipsec_prot_t *prot;

	ASSERT(MUTEX_HELD(&alg_lock));
	io = (ipsec_out_t *)acqrec->ipsacq_mp->b_rptr;
	ASSERT(io->ipsec_out_type == IPSEC_OUT);

	prop->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	prop->sadb_prop_len = SADB_8TO64(sizeof (sadb_prop_t));
	*(uint32_t *)(&prop->sadb_prop_replay) = 0;	/* Quick zero-out! */

	prop->sadb_prop_replay = ipsecesp_replay_size;

	/*
	 * Based upon algorithm properties, and what-not, prioritize
	 * a proposal.  If the IPSEC_OUT message has an algorithm specified,
	 * use it first and foremost.
	 *
	 * For each action in policy list
	 *   Add combination.  If I've hit limit, return.
	 */

	for (ap = acqrec->ipsacq_act; ap != NULL;
	    ap = ap->ipa_next) {
		ipsec_alginfo_t *ealg = NULL;
		ipsec_alginfo_t *aalg = NULL;

		if (ap->ipa_act.ipa_type != IPSEC_POLICY_APPLY)
			continue;

		prot = &ap->ipa_act.ipa_apply;

		if (!(prot->ipp_use_esp))
			continue;

		if (prot->ipp_esp_auth_alg != 0) {
			aalg = ipsec_alglists[IPSEC_ALG_AUTH]
			    [prot->ipp_esp_auth_alg];
			if (aalg == NULL || !ALG_VALID(aalg))
				continue;
		}

		ASSERT(prot->ipp_encr_alg > 0);
		ealg = ipsec_alglists[IPSEC_ALG_ENCR][prot->ipp_encr_alg];
		if (ealg == NULL || !ALG_VALID(ealg))
			continue;

		comb->sadb_comb_flags = 0;
		comb->sadb_comb_reserved = 0;
		comb->sadb_comb_encrypt = ealg->alg_id;
		comb->sadb_comb_encrypt_minbits =
		    MAX(prot->ipp_espe_minbits, ealg->alg_ef_minbits);
		comb->sadb_comb_encrypt_maxbits =
		    MIN(prot->ipp_espe_maxbits, ealg->alg_ef_maxbits);
		if (aalg == NULL) {
			comb->sadb_comb_auth = 0;
			comb->sadb_comb_auth_minbits = 0;
			comb->sadb_comb_auth_maxbits = 0;
		} else {
			comb->sadb_comb_auth = aalg->alg_id;
			comb->sadb_comb_auth_minbits =
			    MAX(prot->ipp_espa_minbits, aalg->alg_ef_minbits);
			comb->sadb_comb_auth_maxbits =
			    MIN(prot->ipp_espa_maxbits, aalg->alg_ef_maxbits);
		}

		/*
		 * The following may be based on algorithm
		 * properties, but in the meantime, we just pick
		 * some good, sensible numbers.  Key mgmt. can
		 * (and perhaps should) be the place to finalize
		 * such decisions.
		 */

		/*
		 * No limits on allocations, since we really don't
		 * support that concept currently.
		 */
		comb->sadb_comb_soft_allocations = 0;
		comb->sadb_comb_hard_allocations = 0;

		/*
		 * These may want to come from policy rule..
		 */
		comb->sadb_comb_soft_bytes = ipsecesp_default_soft_bytes;
		comb->sadb_comb_hard_bytes = ipsecesp_default_hard_bytes;
		comb->sadb_comb_soft_addtime = ipsecesp_default_soft_addtime;
		comb->sadb_comb_hard_addtime = ipsecesp_default_hard_addtime;
		comb->sadb_comb_soft_usetime = ipsecesp_default_soft_usetime;
		comb->sadb_comb_hard_usetime = ipsecesp_default_hard_usetime;

		prop->sadb_prop_len += SADB_8TO64(sizeof (*comb));
		if (--combs == 0)
			break;	/* out of space.. */
		comb++;
	}
}

/*
 * Prepare and actually send the SADB_ACQUIRE message to PF_KEY.
 */
static void
esp_send_acquire(ipsacq_t *acqrec, mblk_t *extended)
{
	mblk_t *pfkeymp, *msgmp;
	uint_t allocsize, combs;
	sadb_msg_t *samsg;
	sadb_prop_t *prop;
	uint8_t *cur, *end;

	ESP_BUMP_STAT(acquire_requests);

	ASSERT(MUTEX_HELD(&acqrec->ipsacq_lock));

	pfkeymp = sadb_keysock_out(0);
	if (pfkeymp == NULL) {
		esp0dbg(("esp_send_acquire: 1st allocb() failed.\n"));
		/* Just bail. */
		goto done;
	}

	/*
	 * First, allocate a basic ACQUIRE message.  Beyond that,
	 * you need to extract certificate info from
	 */
	allocsize = sizeof (sadb_msg_t) + sizeof (sadb_address_t) +
	    sizeof (sadb_address_t) + sizeof (sadb_prop_t);

	switch (acqrec->ipsacq_addrfam) {
	case AF_INET:
		allocsize += 2 * sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		allocsize += 2 * sizeof (struct sockaddr_in6);
		break;
	}

	mutex_enter(&alg_lock);

	combs = ipsec_nalgs[IPSEC_ALG_AUTH] * ipsec_nalgs[IPSEC_ALG_ENCR];

	allocsize += combs * sizeof (sadb_comb_t);

	/*
	 * XXX If there are:
	 *	certificate IDs
	 *	proxy address
	 *	<Others>
	 * add additional allocation size.
	 */

	msgmp = allocb(allocsize, BPRI_HI);
	if (msgmp == NULL) {
		esp0dbg(("esp_send_acquire: 2nd allocb() failed.\n"));
		/* Just bail. */
		freemsg(pfkeymp);
		pfkeymp = NULL;
		goto done;
	}

	cur = msgmp->b_rptr;
	end = cur + allocsize;
	samsg = (sadb_msg_t *)cur;
	pfkeymp->b_cont = msgmp;

	/* Set up ACQUIRE. */
	cur = sadb_setup_acquire(cur, end, acqrec);
	if (cur == NULL) {
		esp0dbg(("sadb_setup_acquire failed.\n"));
		/* Just bail. */
		freemsg(pfkeymp);
		pfkeymp = NULL;
		goto done;
	}
	samsg->sadb_msg_satype = SADB_SATYPE_ESP;

	/* XXX Insert proxy address information here. */

	/* XXX Insert identity information here. */

	/* XXXMLS Insert sensitivity information here. */

	/* Insert proposal here. */

	prop = (sadb_prop_t *)(((uint64_t *)samsg) + samsg->sadb_msg_len);
	esp_insert_prop(prop, acqrec, combs);
	samsg->sadb_msg_len += prop->sadb_prop_len;
	msgmp->b_wptr += SADB_64TO8(samsg->sadb_msg_len);

done:
	mutex_exit(&alg_lock);

	/*
	 * Must mutex_exit() before sending PF_KEY message up, in
	 * order to avoid recursive mutex_enter() if there are no registered
	 * listeners.
	 *
	 * Once I've sent the message, I'm cool anyway.
	 */
	mutex_exit(&acqrec->ipsacq_lock);
	if (esp_pfkey_q != NULL && pfkeymp != NULL) {
		if (extended != NULL) {
			putnext(esp_pfkey_q, extended);
		}
		putnext(esp_pfkey_q, pfkeymp);
		return;
	}
	/* XXX freemsg() works for extended == NULL. */
	freemsg(extended);
	freemsg(pfkeymp);
}

/*
 * Handle the SADB_GETSPI message.  Create a larval SA.
 */
static void
esp_getspi(mblk_t *mp, keysock_in_t *ksi)
{
	ipsa_t *newbie, *target;
	isaf_t *outbound, *inbound;
	int rc, diagnostic;
	sadb_sa_t *assoc;
	keysock_out_t *kso;
	uint32_t newspi;

	/*
	 * Randomly generate a proposed SPI value
	 */
	(void) random_get_pseudo_bytes((uint8_t *)&newspi, sizeof (uint32_t));
	newbie = sadb_getspi(ksi, newspi, &diagnostic);

	if (newbie == NULL) {
		sadb_pfkey_error(esp_pfkey_q, mp, ENOMEM, diagnostic,
		    ksi->ks_in_serial);
		return;
	} else if (newbie == (ipsa_t *)-1) {
		sadb_pfkey_error(esp_pfkey_q, mp, EINVAL, diagnostic,
		    ksi->ks_in_serial);
		return;
	}

	/*
	 * XXX - We may randomly collide.  We really should recover from this.
	 *	 Unfortunately, that could require spending way-too-much-time
	 *	 in here.  For now, let the user retry.
	 */

	if (newbie->ipsa_addrfam == AF_INET6) {
		outbound = OUTBOUND_BUCKET_V6(&esp_sadb.s_v6,
		    *(uint32_t *)(newbie->ipsa_dstaddr));
		inbound = INBOUND_BUCKET(&esp_sadb.s_v6, newbie->ipsa_spi);
	} else {
		ASSERT(newbie->ipsa_addrfam == AF_INET);
		outbound = OUTBOUND_BUCKET_V4(&esp_sadb.s_v4,
		    *(uint32_t *)(newbie->ipsa_dstaddr));
		inbound = INBOUND_BUCKET(&esp_sadb.s_v4, newbie->ipsa_spi);
	}

	mutex_enter(&outbound->isaf_lock);
	mutex_enter(&inbound->isaf_lock);

	/*
	 * Check for collisions (i.e. did sadb_getspi() return with something
	 * that already exists?).
	 *
	 * Try outbound first.  Even though SADB_GETSPI is traditionally
	 * for inbound SAs, you never know what a user might do.
	 */
	target = ipsec_getassocbyspi(outbound, newbie->ipsa_spi,
	    newbie->ipsa_srcaddr, newbie->ipsa_dstaddr, newbie->ipsa_addrfam);
	if (target == NULL) {
		target = ipsec_getassocbyspi(inbound, newbie->ipsa_spi,
		    newbie->ipsa_srcaddr, newbie->ipsa_dstaddr,
		    newbie->ipsa_addrfam);
	}

	/*
	 * I don't have collisions elsewhere!
	 * (Nor will I because I'm still holding inbound/outbound locks.)
	 */

	if (target != NULL) {
		rc = EEXIST;
		IPSA_REFRELE(target);
	} else {
		/*
		 * sadb_insertassoc() also checks for collisions, so
		 * if there's a colliding entry, rc will be set
		 * to EEXIST.
		 */
		rc = sadb_insertassoc(newbie, inbound);
		(void) drv_getparm(TIME, &newbie->ipsa_hardexpiretime);
		newbie->ipsa_hardexpiretime += ipsecesp_larval_timeout;
	}

	/*
	 * Can exit outbound mutex.  Hold inbound until we're done
	 * with newbie.
	 */
	mutex_exit(&outbound->isaf_lock);

	if (rc != 0) {
		mutex_exit(&inbound->isaf_lock);
		IPSA_REFRELE(newbie);
		sadb_pfkey_error(esp_pfkey_q, mp, rc, SADB_X_DIAGNOSTIC_NONE,
		    ksi->ks_in_serial);
		return;
	}


	/* Can write here because I'm still holding the bucket lock. */
	newbie->ipsa_type = SADB_SATYPE_ESP;

	/*
	 * Construct successful return message.  We have one thing going
	 * for us in PF_KEY v2.  That's the fact that
	 *	sizeof (sadb_spirange_t) == sizeof (sadb_sa_t)
	 */
	assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SPIRANGE];
	assoc->sadb_sa_exttype = SADB_EXT_SA;
	assoc->sadb_sa_spi = newbie->ipsa_spi;
	*((uint64_t *)(&assoc->sadb_sa_replay)) = 0;
	mutex_exit(&inbound->isaf_lock);

	/* Convert KEYSOCK_IN to KEYSOCK_OUT. */
	kso = (keysock_out_t *)ksi;
	kso->ks_out_len = sizeof (*kso);
	kso->ks_out_serial = ksi->ks_in_serial;
	kso->ks_out_type = KEYSOCK_OUT;

	/*
	 * Can safely putnext() to esp_pfkey_q, because this is a turnaround
	 * from the esp_pfkey_q.
	 */
	putnext(esp_pfkey_q, mp);
}

/*
 * Insert the ESP header into a packet.  Duplicate an mblk, and insert a newly
 * allocated mblk with the ESP header in between the two.
 */
static boolean_t
esp_insert_esp(mblk_t *mp, mblk_t *esp_mp, uint_t divpoint)
{
	mblk_t *split_mp = mp;
	uint_t wheretodiv = divpoint;

	while ((split_mp->b_wptr - split_mp->b_rptr) < wheretodiv) {
		wheretodiv -= (split_mp->b_wptr - split_mp->b_rptr);
		split_mp = split_mp->b_cont;
		ASSERT(split_mp != NULL);
	}

	if (split_mp->b_wptr - split_mp->b_rptr != wheretodiv) {
		mblk_t *scratch;

		/* "scratch" is the 2nd half, split_mp is the first. */
		scratch = dupb(split_mp);
		if (scratch == NULL) {
			esp1dbg(("esp_insert_esp: can't allocate scratch.\n"));
			return (B_FALSE);
		}
		/* NOTE:  dupb() doesn't set b_cont appropriately. */
		scratch->b_cont = split_mp->b_cont;
		scratch->b_rptr += wheretodiv;
		split_mp->b_wptr = split_mp->b_rptr + wheretodiv;
		split_mp->b_cont = scratch;
	}
	/*
	 * At this point, split_mp is exactly "wheretodiv" bytes long, and
	 * holds the end of the pre-ESP part of the datagram.
	 */
	esp_mp->b_cont = split_mp->b_cont;
	split_mp->b_cont = esp_mp;

	return (B_TRUE);
}

/*
 * Finish processing of an inbound ESP packet after processing by the
 * crypto framework.
 * - Remove the ESP header.
 * - Send packet back to IP.
 * If authentication was performed on the packet, this function is called
 * only if the authentication succeeded.
 * On success returns B_TRUE, on failure returns B_FALSE and frees the
 * mblk chain ipsec_in_mp.
 */
static ipsec_status_t
esp_in_done(mblk_t *ipsec_in_mp)
{
	ipsec_in_t *ii = (ipsec_in_t *)ipsec_in_mp->b_rptr;
	mblk_t *data_mp;
	ipsa_t *assoc;
	uint_t espstart;
	uint32_t ivlen = 0;
	uint_t processed_len;
	esph_t *esph;
	kstat_named_t *counter;
	boolean_t is_natt;

	assoc = ii->ipsec_in_esp_sa;
	ASSERT(assoc != NULL);

	is_natt = ((assoc->ipsa_flags & IPSA_F_NATT) != 0);

	/* get the pointer to the ESP header */
	if (assoc->ipsa_encr_alg == SADB_EALG_NULL) {
		/* authentication-only ESP */
		espstart = ii->ipsec_in_crypto_data.cd_offset;
		processed_len = ii->ipsec_in_crypto_data.cd_length;
	} else {
		/* encryption present */
		ivlen = assoc->ipsa_iv_len;
		if (assoc->ipsa_auth_alg == SADB_AALG_NONE) {
			/* encryption-only ESP */
			espstart = ii->ipsec_in_crypto_data.cd_offset -
				sizeof (esph_t) - assoc->ipsa_iv_len;
			processed_len = ii->ipsec_in_crypto_data.cd_length +
				ivlen;
		} else {
			/* encryption with authentication */
			espstart = ii->ipsec_in_crypto_dual_data.dd_offset1;
			processed_len = ii->ipsec_in_crypto_dual_data.dd_len2 +
			    ivlen;
		}
	}

	data_mp = ipsec_in_mp->b_cont;
	esph = (esph_t *)(data_mp->b_rptr + espstart);

	if (assoc->ipsa_auth_alg != IPSA_AALG_NONE) {
		/* authentication passed if we reach this point */
		ESP_BUMP_STAT(good_auth);
		data_mp->b_wptr -= assoc->ipsa_mac_len;

		/*
		 * Check replay window here!
		 * For right now, assume keysock will set the replay window
		 * size to zero for SAs that have an unspecified sender.
		 * This may change...
		 */

		if (!sadb_replay_check(assoc, esph->esph_replay)) {
			/*
			 * Log the event. As of now we print out an event.
			 * Do not print the replay failure number, or else
			 * syslog cannot collate the error messages.  Printing
			 * the replay number that failed opens a denial-of-
			 * service attack.
			 */
			ipsec_assocfailure(info.mi_idnum, 0, 0,
			    SL_ERROR | SL_WARN,
			    "Replay failed for ESP spi 0x%x, dst %s.\n",
			    assoc->ipsa_spi, assoc->ipsa_dstaddr,
			    assoc->ipsa_addrfam);
			ESP_BUMP_STAT(replay_failures);
			counter = &ipdrops_esp_replay;
			goto drop_and_bail;
		}
	}

	if (!esp_age_bytes(assoc, processed_len, B_TRUE)) {
		/* The ipsa has hit hard expiration, LOG and AUDIT. */
		ipsec_assocfailure(info.mi_idnum, 0, 0,
		    SL_ERROR | SL_WARN,
		    "ESP association 0x%x, dst %s had bytes expire.\n",
		    assoc->ipsa_spi, assoc->ipsa_dstaddr, assoc->ipsa_addrfam);
		ESP_BUMP_STAT(bytes_expired);
		counter = &ipdrops_esp_bytes_expire;
		goto drop_and_bail;
	}

	/*
	 * Remove ESP header and padding from packet.  I hope the compiler
	 * spews "branch, predict taken" code for this.
	 */

	if (esp_strip_header(data_mp, ii->ipsec_in_v4, ivlen, &counter)) {
		if (is_natt)
			return (esp_fix_natt_checksums(data_mp, assoc));
		return (IPSEC_STATUS_SUCCESS);
	}

	esp1dbg(("esp_in_done: esp_strip_header() failed\n"));
drop_and_bail:
	IP_ESP_BUMP_STAT(in_discards);
	/*
	 * TODO: Extract inbound interface from the IPSEC_IN message's
	 * ii->ipsec_in_rill_index.
	 */
	ip_drop_packet(ipsec_in_mp, B_TRUE, NULL, NULL, counter, &esp_dropper);
	return (IPSEC_STATUS_FAILED);
}

/*
 * Called upon failing the inbound ICV check. The message passed as
 * argument is freed.
 */
static void
esp_log_bad_auth(mblk_t *ipsec_in)
{
	ipsec_in_t *ii = (ipsec_in_t *)ipsec_in->b_rptr;
	ipsa_t *assoc = ii->ipsec_in_esp_sa;

	/*
	 * Log the event. Don't print to the console, block
	 * potential denial-of-service attack.
	 */
	ESP_BUMP_STAT(bad_auth);

	ipsec_assocfailure(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
	    "ESP Authentication failed for spi 0x%x, dst %s.\n",
	    assoc->ipsa_spi, assoc->ipsa_dstaddr, assoc->ipsa_addrfam);

	IP_ESP_BUMP_STAT(in_discards);
	/*
	 * TODO: Extract inbound interface from the IPSEC_IN
	 * message's ii->ipsec_in_rill_index.
	 */
	ip_drop_packet(ipsec_in, B_TRUE, NULL, NULL, &ipdrops_esp_bad_auth,
	    &esp_dropper);
}


/*
 * Invoked for outbound packets after ESP processing. If the packet
 * also requires AH, performs the AH SA selection and AH processing.
 * Returns B_TRUE if the AH processing was not needed or if it was
 * performed successfully. Returns B_FALSE and consumes the passed mblk
 * if AH processing was required but could not be performed.
 */
static boolean_t
esp_do_outbound_ah(mblk_t *ipsec_mp)
{
	ipsec_out_t *io = (ipsec_out_t *)ipsec_mp->b_rptr;
	ipsec_status_t ipsec_rc;
	ipsec_action_t *ap;

	ap = io->ipsec_out_act;
	if (ap == NULL) {
		ipsec_policy_t *pp = io->ipsec_out_policy;
		ap = pp->ipsp_act;
	}

	if (!ap->ipa_want_ah)
		return (B_TRUE);

	ASSERT(io->ipsec_out_ah_done == B_FALSE);

	if (io->ipsec_out_ah_sa == NULL) {
		if (!ipsec_outbound_sa(ipsec_mp, IPPROTO_AH)) {
			sadb_acquire(ipsec_mp, io, B_TRUE, B_FALSE);
			return (B_FALSE);
		}
	}
	ASSERT(io->ipsec_out_ah_sa != NULL);

	io->ipsec_out_ah_done = B_TRUE;
	ipsec_rc = io->ipsec_out_ah_sa->ipsa_output_func(ipsec_mp);
	return (ipsec_rc == IPSEC_STATUS_SUCCESS);
}


/*
 * Kernel crypto framework callback invoked after completion of async
 * crypto requests.
 */
static void
esp_kcf_callback(void *arg, int status)
{
	mblk_t *ipsec_mp = (mblk_t *)arg;
	ipsec_in_t *ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	boolean_t is_inbound = (ii->ipsec_in_type == IPSEC_IN);

	ASSERT(ipsec_mp->b_cont != NULL);

	if (status == CRYPTO_SUCCESS) {
		if (is_inbound) {
			if (esp_in_done(ipsec_mp) != IPSEC_STATUS_SUCCESS)
				return;

			/* finish IPsec processing */
			ip_fanout_proto_again(ipsec_mp, NULL, NULL, NULL);
		} else {
			/*
			 * If a ICV was computed, it was stored by the
			 * crypto framework at the end of the packet.
			 */
			ipha_t *ipha = (ipha_t *)ipsec_mp->b_cont->b_rptr;

			/* do AH processing if needed */
			if (!esp_do_outbound_ah(ipsec_mp))
				return;

			/* finish IPsec processing */
			if (IPH_HDR_VERSION(ipha) == IP_VERSION) {
				ip_wput_ipsec_out(NULL, ipsec_mp, ipha, NULL,
				    NULL);
			} else {
				ip6_t *ip6h = (ip6_t *)ipha;
				ip_wput_ipsec_out_v6(NULL, ipsec_mp, ip6h,
				    NULL, NULL);
			}
		}

	} else if (status == CRYPTO_INVALID_MAC) {
		esp_log_bad_auth(ipsec_mp);

	} else {
		esp1dbg(("esp_kcf_callback: crypto failed with 0x%x\n",
		    status));
		ESP_BUMP_STAT(crypto_failures);
		if (is_inbound)
			IP_ESP_BUMP_STAT(in_discards);
		else
			ESP_BUMP_STAT(out_discards);
		ip_drop_packet(ipsec_mp, is_inbound, NULL, NULL,
		    &ipdrops_esp_crypto_failed, &esp_dropper);
	}
}

/*
 * Invoked on crypto framework failure during inbound and outbound processing.
 */
static void
esp_crypto_failed(mblk_t *mp, boolean_t is_inbound, int kef_rc)
{
	esp1dbg(("crypto failed for %s ESP with 0x%x\n",
	    is_inbound ? "inbound" : "outbound", kef_rc));
	ip_drop_packet(mp, is_inbound, NULL, NULL, &ipdrops_esp_crypto_failed,
	    &esp_dropper);
	ESP_BUMP_STAT(crypto_failures);
	if (is_inbound)
		IP_ESP_BUMP_STAT(in_discards);
	else
		ESP_BUMP_STAT(out_discards);
}

#define	ESP_INIT_CALLREQ(_cr) {						\
	(_cr)->cr_flag = CRYPTO_SKIP_REQID|CRYPTO_RESTRICTED;		\
	(_cr)->cr_callback_arg = ipsec_mp;				\
	(_cr)->cr_callback_func = esp_kcf_callback;			\
}

#define	ESP_INIT_CRYPTO_MAC(mac, icvlen, icvbuf) {			\
	(mac)->cd_format = CRYPTO_DATA_RAW;				\
	(mac)->cd_offset = 0;						\
	(mac)->cd_length = icvlen;					\
	(mac)->cd_raw.iov_base = (char *)icvbuf;			\
	(mac)->cd_raw.iov_len = icvlen;					\
}

#define	ESP_INIT_CRYPTO_DATA(data, mp, off, len) {			\
	if (MBLKL(mp) >= (len) + (off)) {				\
		(data)->cd_format = CRYPTO_DATA_RAW;			\
		(data)->cd_raw.iov_base = (char *)(mp)->b_rptr;		\
		(data)->cd_raw.iov_len = MBLKL(mp);			\
		(data)->cd_offset = off;				\
	} else {							\
		(data)->cd_format = CRYPTO_DATA_MBLK;			\
		(data)->cd_mp = mp;			       		\
		(data)->cd_offset = off;				\
	}								\
	(data)->cd_length = len;					\
}

#define	ESP_INIT_CRYPTO_DUAL_DATA(data, mp, off1, len1, off2, len2) {	\
	(data)->dd_format = CRYPTO_DATA_MBLK;				\
	(data)->dd_mp = mp;						\
	(data)->dd_len1 = len1;						\
	(data)->dd_offset1 = off1;					\
	(data)->dd_len2 = len2;						\
	(data)->dd_offset2 = off2;					\
}

static ipsec_status_t
esp_submit_req_inbound(mblk_t *ipsec_mp, ipsa_t *assoc, uint_t esph_offset)
{
	ipsec_in_t *ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	boolean_t do_auth;
	uint_t auth_offset, msg_len, auth_len;
	crypto_call_req_t call_req;
	mblk_t *esp_mp;
	int kef_rc = CRYPTO_FAILED;
	uint_t icv_len = assoc->ipsa_mac_len;
	crypto_ctx_template_t auth_ctx_tmpl;
	boolean_t do_encr;
	uint_t encr_offset, encr_len;
	uint_t iv_len = assoc->ipsa_iv_len;
	crypto_ctx_template_t encr_ctx_tmpl;

	ASSERT(ii->ipsec_in_type == IPSEC_IN);

	do_auth = assoc->ipsa_auth_alg != SADB_AALG_NONE;
	do_encr = assoc->ipsa_encr_alg != SADB_EALG_NULL;

	/*
	 * An inbound packet is of the form:
	 * IPSEC_IN -> [IP,options,ESP,IV,data,ICV,pad]
	 */
	esp_mp = ipsec_mp->b_cont;
	msg_len = MBLKL(esp_mp);

	ESP_INIT_CALLREQ(&call_req);

	if (do_auth) {
		/* force asynchronous processing? */
		if (ipsec_algs_exec_mode[IPSEC_ALG_AUTH] ==
		    IPSEC_ALGS_EXEC_ASYNC)
			call_req.cr_flag |= CRYPTO_ALWAYS_QUEUE;

		/* authentication context template */
		IPSEC_CTX_TMPL(assoc, ipsa_authtmpl, IPSEC_ALG_AUTH,
		    auth_ctx_tmpl);

		/* ICV to be verified */
		ESP_INIT_CRYPTO_MAC(&ii->ipsec_in_crypto_mac,
		    icv_len, esp_mp->b_wptr - icv_len);

		/* authentication starts at the ESP header */
		auth_offset = esph_offset;
		auth_len = msg_len - auth_offset - icv_len;
		if (!do_encr) {
			/* authentication only */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&ii->ipsec_in_crypto_data,
			    esp_mp, auth_offset, auth_len);

			/* call the crypto framework */
			kef_rc = crypto_mac_verify(&assoc->ipsa_amech,
			    &ii->ipsec_in_crypto_data,
			    &assoc->ipsa_kcfauthkey, auth_ctx_tmpl,
			    &ii->ipsec_in_crypto_mac, &call_req);
		}
	}

	if (do_encr) {
		/* force asynchronous processing? */
		if (ipsec_algs_exec_mode[IPSEC_ALG_ENCR] ==
		    IPSEC_ALGS_EXEC_ASYNC)
			call_req.cr_flag |= CRYPTO_ALWAYS_QUEUE;

		/* encryption template */
		IPSEC_CTX_TMPL(assoc, ipsa_encrtmpl, IPSEC_ALG_ENCR,
		    encr_ctx_tmpl);

		/* skip IV, since it is passed separately */
		encr_offset = esph_offset + sizeof (esph_t) + iv_len;
		encr_len = msg_len - encr_offset;

		if (!do_auth) {
			/* decryption only */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&ii->ipsec_in_crypto_data,
			    esp_mp, encr_offset, encr_len);

			/* specify IV */
			ii->ipsec_in_crypto_data.cd_miscdata =
			    (char *)esp_mp->b_rptr + sizeof (esph_t) +
			    esph_offset;

			/* call the crypto framework */
			kef_rc = crypto_decrypt(&assoc->ipsa_emech,
			    &ii->ipsec_in_crypto_data,
			    &assoc->ipsa_kcfencrkey, encr_ctx_tmpl,
			    NULL, &call_req);
		}
	}

	if (do_auth && do_encr) {
		/* dual operation */
		/* initialize input data argument */
		ESP_INIT_CRYPTO_DUAL_DATA(&ii->ipsec_in_crypto_dual_data,
		    esp_mp, auth_offset, auth_len,
		    encr_offset, encr_len - icv_len);

		/* specify IV */
		ii->ipsec_in_crypto_dual_data.dd_miscdata =
		    (char *)esp_mp->b_rptr + sizeof (esph_t) + esph_offset;

		/* call the framework */
		kef_rc = crypto_mac_verify_decrypt(&assoc->ipsa_amech,
		    &assoc->ipsa_emech, &ii->ipsec_in_crypto_dual_data,
		    &assoc->ipsa_kcfauthkey, &assoc->ipsa_kcfencrkey,
		    auth_ctx_tmpl, encr_ctx_tmpl, &ii->ipsec_in_crypto_mac,
		    NULL, &call_req);
	}

	switch (kef_rc) {
	case CRYPTO_SUCCESS:
		ESP_BUMP_STAT(crypto_sync);
		return (esp_in_done(ipsec_mp));
	case CRYPTO_QUEUED:
		/* esp_kcf_callback() will be invoked on completion */
		ESP_BUMP_STAT(crypto_async);
		return (IPSEC_STATUS_PENDING);
	case CRYPTO_INVALID_MAC:
		ESP_BUMP_STAT(crypto_sync);
		esp_log_bad_auth(ipsec_mp);
		return (IPSEC_STATUS_FAILED);
	}

	esp_crypto_failed(ipsec_mp, B_TRUE, kef_rc);
	return (IPSEC_STATUS_FAILED);
}

static ipsec_status_t
esp_submit_req_outbound(mblk_t *ipsec_mp, ipsa_t *assoc, uchar_t *icv_buf,
    uint_t payload_len)
{
	ipsec_out_t *io = (ipsec_out_t *)ipsec_mp->b_rptr;
	uint_t auth_len;
	crypto_call_req_t call_req;
	mblk_t *esp_mp;
	int kef_rc = CRYPTO_FAILED;
	uint_t icv_len = assoc->ipsa_mac_len;
	crypto_ctx_template_t auth_ctx_tmpl;
	boolean_t do_auth;
	boolean_t do_encr;
	uint_t iv_len = assoc->ipsa_iv_len;
	crypto_ctx_template_t encr_ctx_tmpl;
	boolean_t is_natt = ((assoc->ipsa_flags & IPSA_F_NATT) != 0);
	size_t esph_offset = (is_natt ? UDPH_SIZE : 0);

	esp3dbg(("esp_submit_req_outbound:%s", is_natt ? "natt" : "not natt"));

	ASSERT(io->ipsec_out_type == IPSEC_OUT);

	do_encr = assoc->ipsa_encr_alg != SADB_EALG_NULL;
	do_auth = assoc->ipsa_auth_alg != SADB_AALG_NONE;

	/*
	 * Outbound IPsec packets are of the form:
	 * IPSEC_OUT -> [IP,options] -> [ESP,IV] -> [data] -> [pad,ICV]
	 * unless it's NATT, then it's
	 * IPSEC_OUT -> [IP,options] -> [udp][ESP,IV] -> [data] -> [pad,ICV]
	 * Get a pointer to the mblk containing the ESP header.
	 */
	ASSERT(ipsec_mp->b_cont != NULL && ipsec_mp->b_cont->b_cont != NULL);
	esp_mp = ipsec_mp->b_cont->b_cont;

	ESP_INIT_CALLREQ(&call_req);

	if (do_auth) {
		/* force asynchronous processing? */
		if (ipsec_algs_exec_mode[IPSEC_ALG_AUTH] ==
		    IPSEC_ALGS_EXEC_ASYNC)
			call_req.cr_flag |= CRYPTO_ALWAYS_QUEUE;

		/* authentication context template */
		IPSEC_CTX_TMPL(assoc, ipsa_authtmpl, IPSEC_ALG_AUTH,
		    auth_ctx_tmpl);

		/* where to store the computed mac */
		ESP_INIT_CRYPTO_MAC(&io->ipsec_out_crypto_mac,
		    icv_len, icv_buf);

		/* authentication starts at the ESP header */
		auth_len = payload_len + iv_len + sizeof (esph_t);
		if (!do_encr) {
			/* authentication only */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&io->ipsec_out_crypto_data,
			    esp_mp, esph_offset, auth_len);

			/* call the crypto framework */
			kef_rc = crypto_mac(&assoc->ipsa_amech,
			    &io->ipsec_out_crypto_data,
			    &assoc->ipsa_kcfauthkey, auth_ctx_tmpl,
			    &io->ipsec_out_crypto_mac, &call_req);
		}
	}

	if (do_encr) {
		/* force asynchronous processing? */
		if (ipsec_algs_exec_mode[IPSEC_ALG_ENCR] ==
		    IPSEC_ALGS_EXEC_ASYNC)
			call_req.cr_flag |= CRYPTO_ALWAYS_QUEUE;

		/* encryption context template */
		IPSEC_CTX_TMPL(assoc, ipsa_encrtmpl, IPSEC_ALG_ENCR,
		    encr_ctx_tmpl);

		if (!do_auth) {
			/* encryption only, skip mblk that contains ESP hdr */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&io->ipsec_out_crypto_data,
			    esp_mp->b_cont, 0, payload_len);

			/* specify IV */
			io->ipsec_out_crypto_data.cd_miscdata =
			    (char *)esp_mp->b_rptr + sizeof (esph_t) +
			    esph_offset;

			/* call the crypto framework */
			kef_rc = crypto_encrypt(&assoc->ipsa_emech,
			    &io->ipsec_out_crypto_data,
			    &assoc->ipsa_kcfencrkey, encr_ctx_tmpl,
			    NULL, &call_req);
		}
	}

	if (do_auth && do_encr) {
		/*
		 * Encryption and authentication:
		 * Pass the pointer to the mblk chain starting at the ESP
		 * header to the framework. Skip the ESP header mblk
		 * for encryption, which is reflected by an encryption
		 * offset equal to the length of that mblk. Start
		 * the authentication at the ESP header, i.e. use an
		 * authentication offset of zero.
		 */
		ESP_INIT_CRYPTO_DUAL_DATA(&io->ipsec_out_crypto_dual_data,
		    esp_mp, MBLKL(esp_mp), payload_len, esph_offset, auth_len);

		/* specify IV */
		io->ipsec_out_crypto_dual_data.dd_miscdata =
		    (char *)esp_mp->b_rptr + sizeof (esph_t) + esph_offset;

		/* call the framework */
		kef_rc = crypto_encrypt_mac(&assoc->ipsa_emech,
		    &assoc->ipsa_amech, NULL,
		    &assoc->ipsa_kcfencrkey, &assoc->ipsa_kcfauthkey,
		    encr_ctx_tmpl, auth_ctx_tmpl,
		    &io->ipsec_out_crypto_dual_data,
		    &io->ipsec_out_crypto_mac, &call_req);
	}

	switch (kef_rc) {
	case CRYPTO_SUCCESS:
		ESP_BUMP_STAT(crypto_sync);
		return (IPSEC_STATUS_SUCCESS);
	case CRYPTO_QUEUED:
		/* esp_kcf_callback() will be invoked on completion */
		ESP_BUMP_STAT(crypto_async);
		return (IPSEC_STATUS_PENDING);
	}

	esp_crypto_failed(ipsec_mp, B_TRUE, kef_rc);
	return (IPSEC_STATUS_FAILED);
}

/*
 * Handle outbound IPsec processing for IPv4 and IPv6
 * On success returns B_TRUE, on failure returns B_FALSE and frees the
 * mblk chain ipsec_in_mp.
 */
static ipsec_status_t
esp_outbound(mblk_t *mp)
{
	mblk_t *ipsec_out_mp, *data_mp, *espmp, *tailmp;
	ipsec_out_t *io;
	ipha_t *ipha;
	ip6_t *ip6h;
	esph_t *esph;
	uint_t af;
	uint8_t *nhp;
	uintptr_t divpoint, datalen, adj, padlen, i, alloclen;
	uintptr_t esplen = sizeof (esph_t);
	uint8_t protocol;
	ipsa_t *assoc;
	uint_t iv_len = 0, mac_len = 0;
	uchar_t *icv_buf;
	udpha_t *udpha;
	boolean_t is_natt = B_FALSE;

	ESP_BUMP_STAT(out_requests);

	ipsec_out_mp = mp;
	data_mp = ipsec_out_mp->b_cont;

	/*
	 * <sigh> We have to copy the message here, because TCP (for example)
	 * keeps a dupb() of the message lying around for retransmission.
	 * Since ESP changes the whole of the datagram, we have to create our
	 * own copy lest we clobber TCP's data.  Since we have to copy anyway,
	 * we might as well make use of msgpullup() and get the mblk into one
	 * contiguous piece!
	 */
	ipsec_out_mp->b_cont = msgpullup(data_mp, -1);
	if (ipsec_out_mp->b_cont == NULL) {
		esp0dbg(("esp_outbound: msgpullup() failed, "
		    "dropping packet.\n"));
		ipsec_out_mp->b_cont = data_mp;
		/*
		 * TODO:  Find the outbound IRE for this packet and
		 * pass it to ip_drop_packet().
		 */
		ip_drop_packet(ipsec_out_mp, B_FALSE, NULL, NULL,
		    &ipdrops_esp_nomem, &esp_dropper);
		return (IPSEC_STATUS_FAILED);
	} else {
		freemsg(data_mp);
		data_mp = ipsec_out_mp->b_cont;
	}

	io = (ipsec_out_t *)ipsec_out_mp->b_rptr;

	/*
	 * Reality check....
	 */

	ipha = (ipha_t *)data_mp->b_rptr;  /* So we can call esp_acquire(). */

	if (io->ipsec_out_v4) {
		af = AF_INET;
		divpoint = IPH_HDR_LENGTH(ipha);
		datalen = ntohs(ipha->ipha_length) - divpoint;
		nhp = (uint8_t *)&ipha->ipha_protocol;
	} else {
		ip6_pkt_t ipp;

		af = AF_INET6;
		ip6h = (ip6_t *)ipha;
		bzero(&ipp, sizeof (ipp));
		divpoint = ip_find_hdr_v6(data_mp, ip6h, &ipp, NULL);
		if (ipp.ipp_dstopts != NULL &&
		    ipp.ipp_dstopts->ip6d_nxt != IPPROTO_ROUTING) {
			/*
			 * Destination options are tricky.  If we get in here,
			 * then we have a terminal header following the
			 * destination options.  We need to adjust backwards
			 * so we insert ESP BEFORE the destination options
			 * bag.  (So that the dstopts get encrypted!)
			 *
			 * Since this is for outbound packets only, we know
			 * that non-terminal destination options only precede
			 * routing headers.
			 */
			divpoint -= ipp.ipp_dstoptslen;
		}
		datalen = ntohs(ip6h->ip6_plen) + sizeof (ip6_t) - divpoint;

		if (ipp.ipp_rthdr != NULL) {
			nhp = &ipp.ipp_rthdr->ip6r_nxt;
		} else if (ipp.ipp_hopopts != NULL) {
			nhp = &ipp.ipp_hopopts->ip6h_nxt;
		} else {
			ASSERT(divpoint == sizeof (ip6_t));
			/* It's probably IP + ESP. */
			nhp = &ip6h->ip6_nxt;
		}
	}
	assoc = io->ipsec_out_esp_sa;
	ASSERT(assoc != NULL);

	if (assoc->ipsa_usetime == 0)
		esp_set_usetime(assoc, B_FALSE);

	if (assoc->ipsa_auth_alg != SADB_AALG_NONE)
		mac_len = assoc->ipsa_mac_len;

	if (assoc->ipsa_flags & IPSA_F_NATT) {
		/* wedge in fake UDP */
		is_natt = B_TRUE;
		esplen += UDPH_SIZE;
	}

	if (assoc->ipsa_encr_alg != SADB_EALG_NULL)
		iv_len = assoc->ipsa_iv_len;

	/*
	 * Set up ESP header and encryption padding for ENCR PI request.
	 */

	/*
	 * Determine the padding length.   Pad to 4-bytes.
	 *
	 * Include the two additional bytes (hence the - 2) for the padding
	 * length and the next header.  Take this into account when
	 * calculating the actual length of the padding.
	 */

	if (assoc->ipsa_encr_alg != SADB_EALG_NULL) {
		padlen = ((unsigned)(iv_len - datalen - 2)) % iv_len;
	} else {
		padlen = ((unsigned)(sizeof (uint32_t) - datalen - 2)) %
		    sizeof (uint32_t);
	}

	/* Allocate ESP header and IV. */
	esplen += iv_len;

	/*
	 * Update association byte-count lifetimes.  Don't forget to take
	 * into account the padding length and next-header (hence the + 2).
	 *
	 * Use the amount of data fed into the "encryption algorithm".  This
	 * is the IV, the data length, the padding length, and the final two
	 * bytes (padlen, and next-header).
	 *
	 */

	if (!esp_age_bytes(assoc, datalen + padlen + iv_len + 2, B_FALSE)) {
		/*
		 * TODO:  Find the outbound IRE for this packet and
		 * pass it to ip_drop_packet().
		 */
		ip_drop_packet(mp, B_FALSE, NULL, NULL,
		    &ipdrops_esp_bytes_expire, &esp_dropper);
		return (IPSEC_STATUS_FAILED);
	}

	espmp = allocb(esplen, BPRI_HI);
	if (espmp == NULL) {
		ESP_BUMP_STAT(out_discards);
		esp1dbg(("esp_outbound: can't allocate espmp.\n"));
		/*
		 * TODO:  Find the outbound IRE for this packet and
		 * pass it to ip_drop_packet().
		 */
		ip_drop_packet(mp, B_FALSE, NULL, NULL, &ipdrops_esp_nomem,
		    &esp_dropper);
		return (IPSEC_STATUS_FAILED);
	}
	espmp->b_wptr += esplen;
	esph = (esph_t *)espmp->b_rptr;

	if (is_natt) {
		esp3dbg(("esp_outbound: NATT"));

		udpha = (udpha_t *)espmp->b_rptr;
		udpha->uha_src_port = htons(IPPORT_IKE_NATT);
		if (assoc->ipsa_remote_port != 0)
			udpha->uha_dst_port = assoc->ipsa_remote_port;
		else
			udpha->uha_dst_port = htons(IPPORT_IKE_NATT);
		/*
		 * Set the checksum to 0, so that the ip_wput_ipsec_out()
		 * can do the right thing.
		 */
		udpha->uha_checksum = 0;
		esph = (esph_t *)(udpha + 1);
	}

	esph->esph_spi = assoc->ipsa_spi;

	esph->esph_replay = htonl(atomic_add_32_nv(&assoc->ipsa_replay, 1));
	if (esph->esph_replay == 0 && assoc->ipsa_replay_wsize != 0) {
		/*
		 * XXX We have replay counter wrapping.
		 * We probably want to nuke this SA (and its peer).
		 */
		ipsec_assocfailure(info.mi_idnum, 0, 0,
		    SL_ERROR | SL_CONSOLE | SL_WARN,
		    "Outbound ESP SA (0x%x, %s) has wrapped sequence.\n",
		    esph->esph_spi, assoc->ipsa_dstaddr, af);

		ESP_BUMP_STAT(out_discards);
		sadb_replay_delete(assoc);
		/*
		 * TODO:  Find the outbound IRE for this packet and
		 * pass it to ip_drop_packet().
		 */
		ip_drop_packet(mp, B_FALSE, NULL, NULL, &ipdrops_esp_replay,
		    &esp_dropper);
		return (IPSEC_STATUS_FAILED);
	}

	/*
	 * Set the IV to a random quantity.  We do not require the
	 * highest quality random bits, but for best security with CBC
	 * mode ciphers, the value must be unlikely to repeat and also
	 * must not be known in advance to an adversary capable of
	 * influencing the plaintext.
	 */
	(void) random_get_pseudo_bytes((uint8_t *)(esph + 1), iv_len);

	/* Fix the IP header. */
	alloclen = padlen + 2 + mac_len;
	adj = alloclen + (espmp->b_wptr - espmp->b_rptr);

	protocol = *nhp;

	if (io->ipsec_out_v4) {
		ipha->ipha_length = htons(ntohs(ipha->ipha_length) + adj);
		if (is_natt) {
			*nhp = IPPROTO_UDP;
			udpha->uha_length = htons(ntohs(ipha->ipha_length) -
			    IPH_HDR_LENGTH(ipha));
		} else {
			*nhp = IPPROTO_ESP;
		}
		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = (uint16_t)ip_csum_hdr(ipha);
	} else {
		ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) + adj);
		*nhp = IPPROTO_ESP;
	}

	/* I've got the two ESP mblks, now insert them. */

	esp2dbg(("data_mp before outbound ESP adjustment:\n"));
	esp2dbg((dump_msg(data_mp)));

	if (!esp_insert_esp(data_mp, espmp, divpoint)) {
		ESP_BUMP_STAT(out_discards);
		/* NOTE:  esp_insert_esp() only fails if there's no memory. */
		/*
		 * TODO:  Find the outbound IRE for this packet and
		 * pass it to ip_drop_packet().
		 */
		ip_drop_packet(mp, B_FALSE, NULL, NULL, &ipdrops_esp_nomem,
		    &esp_dropper);
		freeb(espmp);
		return (IPSEC_STATUS_FAILED);
	}

	/* Append padding (and leave room for ICV). */
	for (tailmp = data_mp; tailmp->b_cont != NULL; tailmp = tailmp->b_cont)
		;
	if (tailmp->b_wptr + alloclen > tailmp->b_datap->db_lim) {
		tailmp->b_cont = allocb(alloclen, BPRI_HI);
		if (tailmp->b_cont == NULL) {
			ESP_BUMP_STAT(out_discards);
			esp0dbg(("esp_outbound:  Can't allocate tailmp.\n"));
			/*
			 * TODO:  Find the outbound IRE for this packet and
			 * pass it to ip_drop_packet().
			 */
			ip_drop_packet(mp, B_FALSE, NULL, NULL,
			    &ipdrops_esp_nomem, &esp_dropper);
			return (IPSEC_STATUS_FAILED);
		}
		tailmp = tailmp->b_cont;
	}

	/*
	 * If there's padding, N bytes of padding must be of the form 0x1,
	 * 0x2, 0x3... 0xN.
	 */
	for (i = 0; i < padlen; ) {
		i++;
		*tailmp->b_wptr++ = i;
	}
	*tailmp->b_wptr++ = i;
	*tailmp->b_wptr++ = protocol;

	esp2dbg(("data_Mp before encryption:\n"));
	esp2dbg((dump_msg(data_mp)));

	/*
	 * The packet is eligible for hardware acceleration if the
	 * following conditions are satisfied:
	 *
	 * 1. the packet will not be fragmented
	 * 2. the provider supports the algorithms specified by SA
	 * 3. there is no pending control message being exchanged
	 * 4. snoop is not attached
	 * 5. the destination address is not a multicast address
	 *
	 * All five of these conditions are checked by IP prior to
	 * sending the packet to ESP.
	 *
	 * But We, and We Alone, can, nay MUST check if the packet
	 * is over NATT, and then disqualify it from hardware
	 * acceleration.
	 */

	if (io->ipsec_out_is_capab_ill && !(assoc->ipsa_flags & IPSA_F_NATT)) {
		return (esp_outbound_accelerated(ipsec_out_mp, mac_len));
	}
	ESP_BUMP_STAT(noaccel);

	/*
	 * Okay.  I've set up the pre-encryption ESP.  Let's do it!
	 */

	if (mac_len > 0) {
		ASSERT(tailmp->b_wptr + mac_len <= tailmp->b_datap->db_lim);
		icv_buf = tailmp->b_wptr;
		tailmp->b_wptr += mac_len;
	} else {
		icv_buf = NULL;
	}

	return (esp_submit_req_outbound(ipsec_out_mp, assoc, icv_buf,
	    datalen + padlen + 2));
}

/*
 * IP calls this to validate the ICMP errors that
 * we got from the network.
 */
ipsec_status_t
ipsecesp_icmp_error(mblk_t *ipsec_mp)
{
	/*
	 * Unless we get an entire packet back, this function is useless.
	 * Why?
	 *
	 * 1.)	Partial packets are useless, because the "next header"
	 *	is at the end of the decrypted ESP packet.  Without the
	 *	whole packet, this is useless.
	 *
	 * 2.)	If we every use a stateful cipher, such as a stream or a
	 *	one-time pad, we can't do anything.
	 *
	 * Since the chances of us getting an entire packet back are very
	 * very small, we discard here.
	 */
	IP_ESP_BUMP_STAT(in_discards);
	ip_drop_packet(ipsec_mp, B_TRUE, NULL, NULL, &ipdrops_esp_icmp,
	    &esp_dropper);
	return (IPSEC_STATUS_FAILED);
}

/*
 * ESP module read put routine.
 */
/* ARGSUSED */
static void
ipsecesp_rput(queue_t *q, mblk_t *mp)
{
	keysock_in_t *ksi;
	int *addrtype;
	ire_t *ire;
	mblk_t *ire_mp, *last_mp;

	switch (mp->b_datap->db_type) {
	case M_CTL:
		/*
		 * IPsec request of some variety from IP.  IPSEC_{IN,OUT}
		 * are the common cases, but even ICMP error messages from IP
		 * may rise up here.
		 *
		 * Ummmm, actually, this can also be the reflected KEYSOCK_IN
		 * message, with an IRE_DB_TYPE hung off at the end.
		 */
		switch (((ipsec_info_t *)(mp->b_rptr))->ipsec_info_type) {
		case KEYSOCK_IN:
			last_mp = mp;
			while (last_mp->b_cont != NULL &&
			    last_mp->b_cont->b_datap->db_type != IRE_DB_TYPE)
				last_mp = last_mp->b_cont;

			if (last_mp->b_cont == NULL) {
				freemsg(mp);
				break;	/* Out of switch. */
			}

			ire_mp = last_mp->b_cont;
			last_mp->b_cont = NULL;

			ksi = (keysock_in_t *)mp->b_rptr;

			if (ksi->ks_in_srctype == KS_IN_ADDR_UNKNOWN)
				addrtype = &ksi->ks_in_srctype;
			else if (ksi->ks_in_dsttype == KS_IN_ADDR_UNKNOWN)
				addrtype = &ksi->ks_in_dsttype;
			else if (ksi->ks_in_proxytype == KS_IN_ADDR_UNKNOWN)
				addrtype = &ksi->ks_in_proxytype;

			ire = (ire_t *)ire_mp->b_rptr;

			*addrtype = sadb_addrset(ire);

			freemsg(ire_mp);
			if (esp_pfkey_q != NULL) {
				/*
				 * Decrement counter to make up for
				 * auto-increment in ipsecesp_wput().
				 * I'm running all MT-hot through here, so
				 * don't worry about perimeters and lateral
				 * puts.
				 */
				ESP_DEBUMP_STAT(keysock_in);
				ipsecesp_wput(WR(esp_pfkey_q), mp);
			} else {
				freemsg(mp);
			}
			break;
		default:
			freemsg(mp);
			break;
		}
		break;
	case M_PROTO:
	case M_PCPROTO:
		/* TPI message of some sort. */
		switch (*((t_scalar_t *)mp->b_rptr)) {
		case T_BIND_ACK:
			esp3dbg(("Thank you IP from ESP for T_BIND_ACK\n"));
			break;
		case T_ERROR_ACK:
			cmn_err(CE_WARN,
			    "ipsecesp:  ESP received T_ERROR_ACK from IP.");
			/*
			 * Make esp_sadb.s_ip_q NULL, and in the
			 * future, perhaps try again.
			 */
			esp_sadb.s_ip_q = NULL;
			break;
		case T_OK_ACK:
			/* Probably from a (rarely sent) T_UNBIND_REQ. */
			break;
		default:
			esp0dbg(("Unknown M_{,PC}PROTO message.\n"));
		}
		freemsg(mp);
		break;
	default:
		/* For now, passthru message. */
		esp2dbg(("ESP got unknown mblk type %d.\n",
		    mp->b_datap->db_type));
		putnext(q, mp);
	}
}

/*
 * Construct an SADB_REGISTER message with the current algorithms.
 */
static boolean_t
esp_register_out(uint32_t sequence, uint32_t pid, uint_t serial)
{
	mblk_t *pfkey_msg_mp, *keysock_out_mp;
	sadb_msg_t *samsg;
	sadb_supported_t *sasupp_auth = NULL;
	sadb_supported_t *sasupp_encr = NULL;
	sadb_alg_t *saalg;
	uint_t allocsize = sizeof (*samsg);
	uint_t i, numalgs_snap;
	int current_aalgs;
	ipsec_alginfo_t **authalgs;
	uint_t num_aalgs;
	int current_ealgs;
	ipsec_alginfo_t **encralgs;
	uint_t num_ealgs;

	/* Allocate the KEYSOCK_OUT. */
	keysock_out_mp = sadb_keysock_out(serial);
	if (keysock_out_mp == NULL) {
		esp0dbg(("esp_register_out: couldn't allocate mblk.\n"));
		return (B_FALSE);
	}

	/*
	 * Allocate the PF_KEY message that follows KEYSOCK_OUT.
	 */

	mutex_enter(&alg_lock);

	/*
	 * Fill SADB_REGISTER message's algorithm descriptors.  Hold
	 * down the lock while filling it.
	 *
	 * Return only valid algorithms, so the number of algorithms
	 * to send up may be less than the number of algorithm entries
	 * in the table.
	 */
	authalgs = ipsec_alglists[IPSEC_ALG_AUTH];
	for (num_aalgs = 0, i = 0; i < IPSEC_MAX_ALGS; i++)
		if (authalgs[i] != NULL && ALG_VALID(authalgs[i]))
			num_aalgs++;

	if (num_aalgs != 0) {
		allocsize += (num_aalgs * sizeof (*saalg));
		allocsize += sizeof (*sasupp_auth);
	}
	encralgs = ipsec_alglists[IPSEC_ALG_ENCR];
	for (num_ealgs = 0, i = 0; i < IPSEC_MAX_ALGS; i++)
		if (encralgs[i] != NULL && ALG_VALID(encralgs[i]))
			num_ealgs++;

	if (num_ealgs != 0) {
		allocsize += (num_ealgs * sizeof (*saalg));
		allocsize += sizeof (*sasupp_encr);
	}
	keysock_out_mp->b_cont = allocb(allocsize, BPRI_HI);
	if (keysock_out_mp->b_cont == NULL) {
		mutex_exit(&alg_lock);
		freemsg(keysock_out_mp);
		return (B_FALSE);
	}

	pfkey_msg_mp = keysock_out_mp->b_cont;
	pfkey_msg_mp->b_wptr += allocsize;
	if (num_aalgs != 0) {
		sasupp_auth = (sadb_supported_t *)
		    (pfkey_msg_mp->b_rptr + sizeof (*samsg));
		saalg = (sadb_alg_t *)(sasupp_auth + 1);

		ASSERT(((ulong_t)saalg & 0x7) == 0);

		numalgs_snap = 0;
		for (i = 0;
		    ((i < IPSEC_MAX_ALGS) && (numalgs_snap < num_aalgs)); i++) {
			if (authalgs[i] == NULL || !ALG_VALID(authalgs[i]))
				continue;

			saalg->sadb_alg_id = authalgs[i]->alg_id;
			saalg->sadb_alg_ivlen = 0;
			saalg->sadb_alg_minbits	= authalgs[i]->alg_ef_minbits;
			saalg->sadb_alg_maxbits	= authalgs[i]->alg_ef_maxbits;
			saalg->sadb_x_alg_defincr = authalgs[i]->alg_ef_default;
			saalg->sadb_x_alg_increment =
			    authalgs[i]->alg_increment;
			numalgs_snap++;
			saalg++;
		}
		ASSERT(numalgs_snap == num_aalgs);
#ifdef DEBUG
		/*
		 * Reality check to make sure I snagged all of the
		 * algorithms.
		 */
		for (; i < IPSEC_MAX_ALGS; i++) {
			if (authalgs[i] != NULL && ALG_VALID(authalgs[i])) {
				cmn_err(CE_PANIC, "esp_register_out()! "
				    "Missed aalg #%d.\n", i);
			}
		}
#endif /* DEBUG */
	} else {
		saalg = (sadb_alg_t *)(pfkey_msg_mp->b_rptr + sizeof (*samsg));
	}

	if (num_ealgs != 0) {
		sasupp_encr = (sadb_supported_t *)saalg;
		saalg = (sadb_alg_t *)(sasupp_encr + 1);

		numalgs_snap = 0;
		for (i = 0;
		    ((i < IPSEC_MAX_ALGS) && (numalgs_snap < num_ealgs)); i++) {
			if (encralgs[i] == NULL || !ALG_VALID(encralgs[i]))
				continue;
			saalg->sadb_alg_id = encralgs[i]->alg_id;
			saalg->sadb_alg_ivlen = encralgs[i]->alg_datalen;
			saalg->sadb_alg_minbits	= encralgs[i]->alg_ef_minbits;
			saalg->sadb_alg_maxbits	= encralgs[i]->alg_ef_maxbits;
			saalg->sadb_x_alg_defincr = encralgs[i]->alg_ef_default;
			saalg->sadb_x_alg_increment =
			    encralgs[i]->alg_increment;
			numalgs_snap++;
			saalg++;
		}
		ASSERT(numalgs_snap == num_ealgs);
#ifdef DEBUG
		/*
		 * Reality check to make sure I snagged all of the
		 * algorithms.
		 */
		for (; i < IPSEC_MAX_ALGS; i++) {
			if (encralgs[i] != NULL && ALG_VALID(encralgs[i])) {
				cmn_err(CE_PANIC, "esp_register_out()! "
				    "Missed ealg #%d.\n", i);
			}
		}
#endif /* DEBUG */
	}

	current_aalgs = num_aalgs;
	current_ealgs = num_ealgs;

	mutex_exit(&alg_lock);

	/* Now fill the rest of the SADB_REGISTER message. */

	samsg = (sadb_msg_t *)pfkey_msg_mp->b_rptr;
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_REGISTER;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = SADB_SATYPE_ESP;
	samsg->sadb_msg_len = SADB_8TO64(allocsize);
	samsg->sadb_msg_reserved = 0;
	/*
	 * Assume caller has sufficient sequence/pid number info.  If it's one
	 * from me over a new alg., I could give two hoots about sequence.
	 */
	samsg->sadb_msg_seq = sequence;
	samsg->sadb_msg_pid = pid;

	if (sasupp_auth != NULL) {
		sasupp_auth->sadb_supported_len =
		    SADB_8TO64(sizeof (*sasupp_auth) +
			sizeof (*saalg) * current_aalgs);
		sasupp_auth->sadb_supported_exttype = SADB_EXT_SUPPORTED_AUTH;
		sasupp_auth->sadb_supported_reserved = 0;
	}

	if (sasupp_encr != NULL) {
		sasupp_encr->sadb_supported_len =
		    SADB_8TO64(sizeof (*sasupp_encr) +
			sizeof (*saalg) * current_ealgs);
		sasupp_encr->sadb_supported_exttype =
		    SADB_EXT_SUPPORTED_ENCRYPT;
		sasupp_encr->sadb_supported_reserved = 0;
	}

	if (esp_pfkey_q != NULL)
		putnext(esp_pfkey_q, keysock_out_mp);
	else {
		freemsg(keysock_out_mp);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Invoked when the algorithm table changes. Causes SADB_REGISTER
 * messages continaining the current list of algorithms to be
 * sent up to the ESP listeners.
 */
void
ipsecesp_algs_changed(void)
{
	/*
	 * Time to send a PF_KEY SADB_REGISTER message to ESP listeners
	 * everywhere.  (The function itself checks for NULL esp_pfkey_q.)
	 */
	(void) esp_register_out(0, 0, 0);
}

/*
 * taskq_dispatch handler.
 */
static void
inbound_task(void *arg)
{
	esph_t *esph;
	mblk_t *mp = (mblk_t *)arg;
	ipsec_in_t *ii = (ipsec_in_t *)mp->b_rptr;
	int ipsec_rc;

	esp2dbg(("in ESP inbound_task"));

	esph = ipsec_inbound_esp_sa(mp);
	if (esph == NULL)
		return;
	ASSERT(ii->ipsec_in_esp_sa != NULL);
	ipsec_rc = ii->ipsec_in_esp_sa->ipsa_input_func(mp, esph);
	if (ipsec_rc != IPSEC_STATUS_SUCCESS)
		return;
	ip_fanout_proto_again(mp, NULL, NULL, NULL);
}

/*
 * Now that weak-key passed, actually ADD the security association, and
 * send back a reply ADD message.
 */
static int
esp_add_sa_finish(mblk_t *mp, sadb_msg_t *samsg, keysock_in_t *ksi)
{
	isaf_t *primary, *secondary, *inbound, *outbound;
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	struct sockaddr_in *dst;
	struct sockaddr_in6 *dst6;
	boolean_t is_ipv4, clone = B_FALSE, is_inbound = B_FALSE;
	uint32_t *dstaddr;
	ipsa_t *larval = NULL;
	ipsacq_t *acqrec;
	iacqf_t *acq_bucket;
	mblk_t *acq_msgs = NULL;
	int rc;
	sadb_t *sp;
	int outhash;
	mblk_t *lpkt;

	/*
	 * Locate the appropriate table(s).
	 */

	dst = (struct sockaddr_in *)(dstext + 1);
	dst6 = (struct sockaddr_in6 *)dst;
	is_ipv4 = (dst->sin_family == AF_INET);
	if (is_ipv4) {
		sp = &esp_sadb.s_v4;
		dstaddr = (uint32_t *)(&dst->sin_addr);
		outhash = OUTBOUND_HASH_V4(sp, *(ipaddr_t *)dstaddr);
	} else {
		sp = &esp_sadb.s_v6;
		dstaddr = (uint32_t *)(&dst6->sin6_addr);
		outhash = OUTBOUND_HASH_V6(sp, *(in6_addr_t *)dstaddr);
	}

	inbound = INBOUND_BUCKET(sp, assoc->sadb_sa_spi);
	outbound = &sp->sdb_of[outhash];

	switch (ksi->ks_in_dsttype) {
	case KS_IN_ADDR_MBCAST:
		clone = B_TRUE;	/* All mcast SAs can be bidirectional */
		/* FALLTHRU */
	case KS_IN_ADDR_ME:
		primary = inbound;
		secondary = outbound;
		/*
		 * If the source address is either one of mine, or unspecified
		 * (which is best summed up by saying "not 'not mine'"),
		 * then the association is potentially bi-directional,
		 * in that it can be used for inbound traffic and outbound
		 * traffic.  The best example of such an SA is a multicast
		 * SA (which allows me to receive the outbound traffic).
		 */
		if (ksi->ks_in_srctype != KS_IN_ADDR_NOTME)
			clone = B_TRUE;
		is_inbound = B_TRUE;
		break;
	case KS_IN_ADDR_NOTME:
		primary = outbound;
		secondary = inbound;
		/*
		 * If the source address literally not mine (either
		 * unspecified or not mine), then this SA may have an
		 * address that WILL be mine after some configuration.
		 * We pay the price for this by making it a bi-directional
		 * SA.
		 */
		if (ksi->ks_in_srctype != KS_IN_ADDR_ME)
			clone = B_TRUE;
		break;
	default:
		samsg->sadb_x_msg_diagnostic = SADB_X_DIAGNOSTIC_BAD_DST;
		return (EINVAL);
	}

	/*
	 * Find a ACQUIRE list entry if possible.  If we've added an SA that
	 * suits the needs of an ACQUIRE list entry, we can eliminate the
	 * ACQUIRE list entry and transmit the enqueued packets.  Use the
	 * high-bit of the sequence number to queue it.  Key off destination
	 * addr, and change acqrec's state.
	 */

	if (samsg->sadb_msg_seq & IACQF_LOWEST_SEQ) {
		acq_bucket = &sp->sdb_acq[outhash];
		mutex_enter(&acq_bucket->iacqf_lock);
		for (acqrec = acq_bucket->iacqf_ipsacq; acqrec != NULL;
		    acqrec = acqrec->ipsacq_next) {
			mutex_enter(&acqrec->ipsacq_lock);
			/*
			 * Q:  I only check sequence.  Should I check dst?
			 * A: Yes, check dest because those are the packets
			 *    that are queued up.
			 */
			if (acqrec->ipsacq_seq == samsg->sadb_msg_seq &&
			    IPSA_ARE_ADDR_EQUAL(dstaddr,
				acqrec->ipsacq_dstaddr, acqrec->ipsacq_addrfam))
				break;
			mutex_exit(&acqrec->ipsacq_lock);
		}
		if (acqrec != NULL) {
			/*
			 * AHA!  I found an ACQUIRE record for this SA.
			 * Grab the msg list, and free the acquire record.
			 * I already am holding the lock for this record,
			 * so all I have to do is free it.
			 */
			acq_msgs = acqrec->ipsacq_mp;
			acqrec->ipsacq_mp = NULL;
			mutex_exit(&acqrec->ipsacq_lock);
			sadb_destroy_acquire(acqrec);
		}
		mutex_exit(&acq_bucket->iacqf_lock);
	}

	/*
	 * Find PF_KEY message, and see if I'm an update.  If so, find entry
	 * in larval list (if there).
	 */

	if (samsg->sadb_msg_type == SADB_UPDATE) {
		mutex_enter(&inbound->isaf_lock);
		larval = ipsec_getassocbyspi(inbound, assoc->sadb_sa_spi,
		    ALL_ZEROES_PTR, dstaddr, dst->sin_family);
		mutex_exit(&inbound->isaf_lock);

		if (larval == NULL) {
			esp0dbg(("Larval update, but larval disappeared.\n"));
			return (ESRCH);
		} /* Else sadb_common_add unlinks it for me! */
	}

	lpkt = NULL;
	if (larval != NULL)
		lpkt = sadb_clear_lpkt(larval);

	rc = sadb_common_add(esp_sadb.s_ip_q, esp_pfkey_q, mp, samsg, ksi,
	    primary, secondary, larval, clone, is_inbound);

	if (rc == 0 && lpkt != NULL) {
		rc = !taskq_dispatch(esp_taskq, inbound_task,
			    (void *) lpkt, TQ_NOSLEEP);
	}

	if (rc != 0) {
		ip_drop_packet(lpkt, B_TRUE, NULL, NULL,
		    &ipdrops_sadb_inlarval_timeout, &esp_dropper);
	}

	/*
	 * How much more stack will I create with all of these
	 * esp_outbound() calls?
	 */

	while (acq_msgs != NULL) {
		mblk_t *mp = acq_msgs;

		acq_msgs = acq_msgs->b_next;
		mp->b_next = NULL;
		if (rc == 0) {
			if (ipsec_outbound_sa(mp, IPPROTO_ESP)) {
				((ipsec_out_t *)(mp->b_rptr))->
				    ipsec_out_esp_done = B_TRUE;
				if (esp_outbound(mp) == IPSEC_STATUS_SUCCESS) {
					ipha_t *ipha = (ipha_t *)
					    mp->b_cont->b_rptr;

					/* do AH processing if needed */
					if (!esp_do_outbound_ah(mp))
						continue;

					/* finish IPsec processing */
					if (is_ipv4) {
						ip_wput_ipsec_out(NULL, mp,
						    ipha, NULL, NULL);
					} else {
						ip6_t *ip6h = (ip6_t *)ipha;
						ip_wput_ipsec_out_v6(NULL,
						    mp, ip6h, NULL, NULL);
					}
				}
				continue;
			}
		}
		ESP_BUMP_STAT(out_discards);
		ip_drop_packet(mp, B_FALSE, NULL, NULL,
		    &ipdrops_sadb_acquire_timeout, &esp_dropper);
	}

	return (rc);
}

/*
 * Add new ESP security association.  This may become a generic AH/ESP
 * routine eventually.
 */
static int
esp_add_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_address_t *nttext_loc =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_LOC];
	sadb_address_t *nttext_rem =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_NATT_REM];
	sadb_key_t *akey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_AUTH];
	sadb_key_t *ekey = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT];
	struct sockaddr_in *src, *dst;
	struct sockaddr_in *natt_loc, *natt_rem;
	struct sockaddr_in6 *natt_loc6, *natt_rem6;

	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];

	/* I need certain extensions present for an ADD message. */
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
	if (ekey == NULL && assoc->sadb_sa_encrypt != SADB_EALG_NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_EKEY;
		return (EINVAL);
	}

	src = (struct sockaddr_in *)(srcext + 1);
	dst = (struct sockaddr_in *)(dstext + 1);
	natt_loc = (struct sockaddr_in *)(nttext_loc + 1);
	natt_loc6 = (struct sockaddr_in6 *)(nttext_loc + 1);
	natt_rem = (struct sockaddr_in *)(nttext_rem + 1);
	natt_rem6 = (struct sockaddr_in6 *)(nttext_rem + 1);

	/* Sundry ADD-specific reality checks. */
	/* XXX STATS :  Logging/stats here? */
	if (assoc->sadb_sa_state != SADB_SASTATE_MATURE) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
		return (EINVAL);
	}
	if (assoc->sadb_sa_encrypt == SADB_EALG_NONE) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_EALG;
		return (EINVAL);
	}

	if (assoc->sadb_sa_encrypt == SADB_EALG_NULL &&
	    assoc->sadb_sa_auth == SADB_AALG_NONE) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_AALG;
		return (EINVAL);
	}

	if (assoc->sadb_sa_flags & ~(SADB_SAFLAGS_NOREPLAY |
	    SADB_X_SAFLAGS_NATT_LOC | SADB_X_SAFLAGS_NATT_REM)) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SAFLAGS;
		return (EINVAL);
	}

	if ((*diagnostic = sadb_hardsoftchk(hard, soft)) != 0) {
		return (EINVAL);
	}
	if (src->sin_family != dst->sin_family) {
		*diagnostic = SADB_X_DIAGNOSTIC_AF_MISMATCH;
		return (EINVAL);
	}


	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_NATT_LOC) {
		if (nttext_loc == NULL) {
			*diagnostic = SADB_X_DIAGNOSTIC_MISSING_NATT_LOC;
			return (EINVAL);
		}

		if (natt_loc->sin_family == AF_INET6 &&
		    !IN6_IS_ADDR_V4MAPPED(&natt_loc6->sin6_addr)) {
			*diagnostic = SADB_X_DIAGNOSTIC_MALFORMED_NATT_LOC;
			return (EINVAL);
		}
	}

	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_NATT_REM) {
		if (nttext_rem == NULL) {
			*diagnostic = SADB_X_DIAGNOSTIC_MISSING_NATT_REM;
			return (EINVAL);
		}
		if (natt_rem->sin_family == AF_INET6 &&
		    !IN6_IS_ADDR_V4MAPPED(&natt_rem6->sin6_addr)) {
			*diagnostic = SADB_X_DIAGNOSTIC_MALFORMED_NATT_REM;
			return (EINVAL);
		}
	}


	/* Stuff I don't support, for now.  XXX Diagnostic? */
	if (ksi->ks_in_extv[SADB_EXT_LIFETIME_CURRENT] != NULL ||
	    ksi->ks_in_extv[SADB_EXT_SENSITIVITY] != NULL)
		return (EOPNOTSUPP);

	/*
	 * XXX Policy :  I'm not checking identities or sensitivity
	 * labels at this time, but if I did, I'd do them here, before I sent
	 * the weak key check up to the algorithm.
	 */

	mutex_enter(&alg_lock);

	/*
	 * First locate the authentication algorithm.
	 */
	if (akey != NULL) {
		ipsec_alginfo_t *aalg;

		aalg = ipsec_alglists[IPSEC_ALG_AUTH][assoc->sadb_sa_auth];
		if (aalg == NULL || !ALG_VALID(aalg)) {
			mutex_exit(&alg_lock);
			esp1dbg(("Couldn't find auth alg #%d.\n",
			    assoc->sadb_sa_auth));
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_AALG;
			return (EINVAL);
		}

		/*
		 * Sanity check key sizes.
		 * Note: It's not possible to use SADB_AALG_NONE because
		 * this auth_alg is not defined with ALG_FLAG_VALID. If this
		 * ever changes, the same check for SADB_AALG_NONE and
		 * a auth_key != NULL should be made here ( see below).
		 */
		if (!ipsec_valid_key_size(akey->sadb_key_bits, aalg)) {
			mutex_exit(&alg_lock);
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_AKEYBITS;
			return (EINVAL);
		}
		ASSERT(aalg->alg_mech_type != CRYPTO_MECHANISM_INVALID);

		/* check key and fix parity if needed */
		if (ipsec_check_key(aalg->alg_mech_type, akey, B_TRUE,
		    diagnostic) != 0) {
			mutex_exit(&alg_lock);
			return (EINVAL);
		}
	}

	/*
	 * Then locate the encryption algorithm.
	 */
	if (ekey != NULL) {
		ipsec_alginfo_t *ealg;

		ealg = ipsec_alglists[IPSEC_ALG_ENCR][assoc->sadb_sa_encrypt];
		if (ealg == NULL || !ALG_VALID(ealg)) {
			mutex_exit(&alg_lock);
			esp1dbg(("Couldn't find encr alg #%d.\n",
			    assoc->sadb_sa_encrypt));
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_EALG;
			return (EINVAL);
		}

		/*
		 * Sanity check key sizes. If the encryption algorithm is
		 * SADB_EALG_NULL but the encryption key is NOT
		 * NULL then complain.
		 */
		if ((assoc->sadb_sa_encrypt == SADB_EALG_NULL) ||
		    (!ipsec_valid_key_size(ekey->sadb_key_bits, ealg))) {
			mutex_exit(&alg_lock);
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_EKEYBITS;
			return (EINVAL);
		}
		ASSERT(ealg->alg_mech_type != CRYPTO_MECHANISM_INVALID);

		/* check key */
		if (ipsec_check_key(ealg->alg_mech_type, ekey, B_FALSE,
		    diagnostic) != 0) {
			mutex_exit(&alg_lock);
			return (EINVAL);
		}
	}
	mutex_exit(&alg_lock);

	return (esp_add_sa_finish(mp, (sadb_msg_t *)mp->b_cont->b_rptr, ksi));
}

/*
 * Update a security association.  Updates come in two varieties.  The first
 * is an update of lifetimes on a non-larval SA.  The second is an update of
 * a larval SA, which ends up looking a lot more like an add.
 */
static int
esp_update_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic)
{
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	struct sockaddr_in *sin;

	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}

	sin = (struct sockaddr_in *)(dstext + 1);
	return (sadb_update_sa(mp, ksi,
	    (sin->sin_family == AF_INET6) ? &esp_sadb.s_v6 : &esp_sadb.s_v4,
	    diagnostic, esp_pfkey_q, esp_add_sa));
}

/*
 * Delete a security association.  This is REALLY likely to be code common to
 * both AH and ESP.  Find the association, then unlink it.
 */
static int
esp_del_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	struct sockaddr_in *sin;

	if (assoc == NULL) {
		if (dstext != NULL) {
			sin = (struct sockaddr_in *)(dstext + 1);
		} else if (srcext != NULL) {
			sin = (struct sockaddr_in *)(srcext + 1);
		} else {
			*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SA;
			return (EINVAL);
		}
		return sadb_purge_sa(mp, ksi,
		    (sin->sin_family == AF_INET6) ? &esp_sadb.s_v6 :
		    &esp_sadb.s_v4,
		    diagnostic, esp_pfkey_q, esp_sadb.s_ip_q);
	}

	return (sadb_del_sa(mp, ksi, &esp_sadb, diagnostic, esp_pfkey_q));
}

/*
 * Convert the entire contents of all of ESP's SA tables into PF_KEY SADB_DUMP
 * messages.
 */
static void
esp_dump(mblk_t *mp, keysock_in_t *ksi)
{
	int error;
	sadb_msg_t *samsg;

	/*
	 * Dump each fanout, bailing if error is non-zero.
	 */

	error = sadb_dump(esp_pfkey_q, mp, ksi->ks_in_serial, &esp_sadb.s_v4);
	if (error != 0)
		goto bail;

	error = sadb_dump(esp_pfkey_q, mp, ksi->ks_in_serial, &esp_sadb.s_v6);
bail:
	ASSERT(mp->b_cont != NULL);
	samsg = (sadb_msg_t *)mp->b_cont->b_rptr;
	samsg->sadb_msg_errno = (uint8_t)error;
	sadb_pfkey_echo(esp_pfkey_q, mp, (sadb_msg_t *)mp->b_cont->b_rptr, ksi,
	    NULL);
}

/*
 * ESP parsing of PF_KEY messages.  Keysock did most of the really silly
 * error cases.  What I receive is a fully-formed, syntactically legal
 * PF_KEY message.  I then need to check semantics...
 *
 * This code may become common to AH and ESP.  Stay tuned.
 *
 * I also make the assumption that db_ref's are cool.  If this assumption
 * is wrong, this means that someone other than keysock or me has been
 * mucking with PF_KEY messages.
 */
static void
esp_parse_pfkey(mblk_t *mp)
{
	mblk_t *msg = mp->b_cont;
	sadb_msg_t *samsg;
	keysock_in_t *ksi;
	int error;
	int diagnostic = SADB_X_DIAGNOSTIC_NONE;

	ASSERT(msg != NULL);
	samsg = (sadb_msg_t *)msg->b_rptr;
	ksi = (keysock_in_t *)mp->b_rptr;

	/*
	 * If applicable, convert unspecified AF_INET6 to unspecified
	 * AF_INET.
	 */
	sadb_srcaddrfix(ksi);

	switch (samsg->sadb_msg_type) {
	case SADB_ADD:
		error = esp_add_sa(mp, ksi, &diagnostic);
		if (error != 0) {
			sadb_pfkey_error(esp_pfkey_q, mp, error, diagnostic,
			    ksi->ks_in_serial);
		}
		/* else esp_add_sa() took care of things. */
		break;
	case SADB_DELETE:
		error = esp_del_sa(mp, ksi, &diagnostic);
		if (error != 0) {
			sadb_pfkey_error(esp_pfkey_q, mp, error, diagnostic,
			    ksi->ks_in_serial);
		}
		/* Else esp_del_sa() took care of things. */
		break;
	case SADB_GET:
		error = sadb_get_sa(mp, ksi, &esp_sadb, &diagnostic,
		    esp_pfkey_q);
		if (error != 0) {
			sadb_pfkey_error(esp_pfkey_q, mp, error, diagnostic,
			    ksi->ks_in_serial);
		}
		/* Else sadb_get_sa() took care of things. */
		break;
	case SADB_FLUSH:
		sadbp_flush(&esp_sadb);
		sadb_pfkey_echo(esp_pfkey_q, mp, samsg, ksi, NULL);
		break;
	case SADB_REGISTER:
		/*
		 * Hmmm, let's do it!  Check for extensions (there should
		 * be none), extract the fields, call esp_register_out(),
		 * then either free or report an error.
		 *
		 * Keysock takes care of the PF_KEY bookkeeping for this.
		 */
		if (esp_register_out(samsg->sadb_msg_seq, samsg->sadb_msg_pid,
		    ksi->ks_in_serial)) {
			freemsg(mp);
		} else {
			/*
			 * Only way this path hits is if there is a memory
			 * failure.  It will not return B_FALSE because of
			 * lack of esp_pfkey_q if I am in wput().
			 */
			sadb_pfkey_error(esp_pfkey_q, mp, ENOMEM, diagnostic,
			    ksi->ks_in_serial);
		}
		break;
	case SADB_UPDATE:
		/*
		 * Find a larval, if not there, find a full one and get
		 * strict.
		 */
		error = esp_update_sa(mp, ksi, &diagnostic);
		if (error != 0) {
			sadb_pfkey_error(esp_pfkey_q, mp, error, diagnostic,
			    ksi->ks_in_serial);
		}
		/* else esp_update_sa() took care of things. */
		break;
	case SADB_GETSPI:
		/*
		 * Reserve a new larval entry.
		 */
		esp_getspi(mp, ksi);
		break;
	case SADB_ACQUIRE:
		/*
		 * Find larval and/or ACQUIRE record and kill it (them), I'm
		 * most likely an error.  Inbound ACQUIRE messages should only
		 * have the base header.
		 */
		sadb_in_acquire(samsg, &esp_sadb, esp_pfkey_q);
		freemsg(mp);
		break;
	case SADB_DUMP:
		/*
		 * Dump all entries.
		 */
		esp_dump(mp, ksi);
		/* esp_dump will take care of the return message, etc. */
		break;
	case SADB_EXPIRE:
		/* Should never reach me. */
		sadb_pfkey_error(esp_pfkey_q, mp, EOPNOTSUPP, diagnostic,
		    ksi->ks_in_serial);
		break;
	default:
		sadb_pfkey_error(esp_pfkey_q, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_UNKNOWN_MSG, ksi->ks_in_serial);
		break;
	}
}

/*
 * Handle case where PF_KEY says it can't find a keysock for one of my
 * ACQUIRE messages.
 */
static void
esp_keysock_no_socket(mblk_t *mp)
{
	sadb_msg_t *samsg;
	keysock_out_err_t *kse = (keysock_out_err_t *)mp->b_rptr;

	if (mp->b_cont == NULL) {
		freemsg(mp);
		return;
	}
	samsg = (sadb_msg_t *)mp->b_cont->b_rptr;

	/*
	 * If keysock can't find any registered, delete the acquire record
	 * immediately, and handle errors.
	 */
	if (samsg->sadb_msg_type == SADB_ACQUIRE) {
		samsg->sadb_msg_errno = kse->ks_err_errno;
		samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg));
		/*
		 * Use the write-side of the esp_pfkey_q, in case there is
		 * no esp_sadb.s_ip_q.
		 */
		sadb_in_acquire(samsg, &esp_sadb, WR(esp_pfkey_q));
	}

	freemsg(mp);
}

/*
 * First-cut reality check for an inbound PF_KEY message.
 */
static boolean_t
esp_pfkey_reality_failures(mblk_t *mp, keysock_in_t *ksi)
{
	int diagnostic;

	if (ksi->ks_in_extv[SADB_EXT_PROPOSAL] != NULL) {
		diagnostic = SADB_X_DIAGNOSTIC_PROP_PRESENT;
		goto badmsg;
	}
	if (ksi->ks_in_extv[SADB_EXT_SUPPORTED_AUTH] != NULL ||
	    ksi->ks_in_extv[SADB_EXT_SUPPORTED_ENCRYPT] != NULL) {
		diagnostic = SADB_X_DIAGNOSTIC_SUPP_PRESENT;
		goto badmsg;
	}
	if (ksi->ks_in_srctype == KS_IN_ADDR_MBCAST) {
		diagnostic = SADB_X_DIAGNOSTIC_BAD_SRC;
		goto badmsg;
	}
	if (ksi->ks_in_dsttype == KS_IN_ADDR_UNSPEC) {
		diagnostic = SADB_X_DIAGNOSTIC_BAD_DST;
		goto badmsg;
	}

	return (B_FALSE);	/* False ==> no failures */

badmsg:
	sadb_pfkey_error(esp_pfkey_q, mp, EINVAL, diagnostic,
	    ksi->ks_in_serial);
	return (B_TRUE);	/* True ==> failures */
}

/*
 * ESP module write put routine.
 */
static void
ipsecesp_wput(queue_t *q, mblk_t *mp)
{
	ipsec_info_t *ii;
	keysock_in_t *ksi;
	int rc;
	struct iocblk *iocp;

	esp3dbg(("In esp_wput().\n"));

	/* NOTE: Each case must take care of freeing or passing mp. */
	switch (mp->b_datap->db_type) {
	case M_CTL:
		if ((mp->b_wptr - mp->b_rptr) < sizeof (ipsec_info_t)) {
			/* Not big enough message. */
			freemsg(mp);
			break;
		}
		ii = (ipsec_info_t *)mp->b_rptr;

		switch (ii->ipsec_info_type) {
		case KEYSOCK_OUT_ERR:
			esp1dbg(("Got KEYSOCK_OUT_ERR message.\n"));
			esp_keysock_no_socket(mp);
			break;
		case KEYSOCK_IN:
			ESP_BUMP_STAT(keysock_in);
			esp3dbg(("Got KEYSOCK_IN message.\n"));
			ksi = (keysock_in_t *)ii;
			/*
			 * Some common reality checks.
			 */

			if (esp_pfkey_reality_failures(mp, ksi))
				return;

			/*
			 * Use 'q' instead of esp_sadb.s_ip_q, since
			 * it's the write side already, and it'll go
			 * down to IP.  Use esp_pfkey_q because we
			 * wouldn't get here if that weren't set, and
			 * the RD(q) has been done already.
			 */
			if (ksi->ks_in_srctype == KS_IN_ADDR_UNKNOWN) {
				rc = sadb_addrcheck(q, esp_pfkey_q, mp,
				    ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC],
				    ksi->ks_in_serial);
				if (rc == KS_IN_ADDR_UNKNOWN)
					return;
				else
					ksi->ks_in_srctype = rc;
			}
			if (ksi->ks_in_dsttype == KS_IN_ADDR_UNKNOWN) {
				rc = sadb_addrcheck(q, esp_pfkey_q, mp,
				    ksi->ks_in_extv[SADB_EXT_ADDRESS_DST],
				    ksi->ks_in_serial);
				if (rc == KS_IN_ADDR_UNKNOWN)
					return;
				else
					ksi->ks_in_dsttype = rc;
			}
			/*
			 * XXX Proxy may be a different address family.
			 */
			if (ksi->ks_in_proxytype == KS_IN_ADDR_UNKNOWN) {
				rc = sadb_addrcheck(q, esp_pfkey_q, mp,
				    ksi->ks_in_extv[SADB_EXT_ADDRESS_PROXY],
				    ksi->ks_in_serial);
				if (rc == KS_IN_ADDR_UNKNOWN)
					return;
				else
					ksi->ks_in_proxytype = rc;
			}
			esp_parse_pfkey(mp);
			break;
		case KEYSOCK_HELLO:
			sadb_keysock_hello(&esp_pfkey_q, q, mp,
			    esp_ager, &esp_event, SADB_SATYPE_ESP);
			break;
		default:
			esp2dbg(("Got M_CTL from above of 0x%x.\n",
			    ii->ipsec_info_type));
			freemsg(mp);
			break;
		}
		break;
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case ND_SET:
		case ND_GET:
			if (nd_getset(q, ipsecesp_g_nd, mp)) {
				qreply(q, mp);
				return;
			} else {
				iocp->ioc_error = ENOENT;
			}
			/* FALLTHRU */
		default:
			/* We really don't support any other ioctls, do we? */

			/* Return EINVAL */
			if (iocp->ioc_error != ENOENT)
				iocp->ioc_error = EINVAL;
			iocp->ioc_count = 0;
			mp->b_datap->db_type = M_IOCACK;
			qreply(q, mp);
			return;
		}
	default:
		esp3dbg(("Got default message, type %d, passing to IP.\n",
		    mp->b_datap->db_type));
		putnext(q, mp);
	}
}

/*
 * Process an outbound ESP packet that can be accelerated by a IPsec
 * hardware acceleration capable Provider.
 * The caller already inserted and initialized the ESP header.
 * This function allocates a tagging M_CTL, and adds room at the end
 * of the packet to hold the ICV if authentication is needed.
 *
 * On success returns B_TRUE, on failure returns B_FALSE and frees the
 * mblk chain ipsec_out.
 */
static ipsec_status_t
esp_outbound_accelerated(mblk_t *ipsec_out, uint_t icv_len)
{
	ipsec_out_t *io;
	mblk_t *lastmp;

	ESP_BUMP_STAT(out_accelerated);

	io = (ipsec_out_t *)ipsec_out->b_rptr;

	/* mark packet as being accelerated in IPSEC_OUT */
	ASSERT(io->ipsec_out_accelerated == B_FALSE);
	io->ipsec_out_accelerated = B_TRUE;

	/*
	 * add room at the end of the packet for the ICV if needed
	 */
	if (icv_len > 0) {
		/* go to last mblk */
		lastmp = ipsec_out;	/* For following while loop. */
		do {
			lastmp = lastmp->b_cont;
		} while (lastmp->b_cont != NULL);

		/* if not enough available room, allocate new mblk */
		if ((lastmp->b_wptr + icv_len) > lastmp->b_datap->db_lim) {
			lastmp->b_cont = allocb(icv_len, BPRI_HI);
			if (lastmp->b_cont == NULL) {
				ESP_BUMP_STAT(out_discards);
				ip_drop_packet(ipsec_out, B_FALSE, NULL, NULL,
				    &ipdrops_esp_nomem, &esp_dropper);
				return (IPSEC_STATUS_FAILED);
			}
			lastmp = lastmp->b_cont;
		}
		lastmp->b_wptr += icv_len;
	}

	return (IPSEC_STATUS_SUCCESS);
}

/*
 * Process an inbound accelerated ESP packet.
 * On success returns B_TRUE, on failure returns B_FALSE and frees the
 * mblk chain ipsec_in.
 */
static ipsec_status_t
esp_inbound_accelerated(mblk_t *ipsec_in, mblk_t *data_mp, boolean_t isv4,
    ipsa_t *assoc)
{
	ipsec_in_t *ii;
	mblk_t *hada_mp;
	uint32_t icv_len = 0;
	da_ipsec_t *hada;
	ipha_t *ipha;
	ip6_t *ip6h;
	kstat_named_t *counter;

	ESP_BUMP_STAT(in_accelerated);

	ii = (ipsec_in_t *)ipsec_in->b_rptr;
	hada_mp = ii->ipsec_in_da;
	ASSERT(hada_mp != NULL);
	hada = (da_ipsec_t *)hada_mp->b_rptr;

	/*
	 * We only support one level of decapsulation in hardware, so
	 * nuke the pointer.
	 */
	ii->ipsec_in_da = NULL;
	ii->ipsec_in_accelerated = B_FALSE;

	if (assoc->ipsa_auth_alg != IPSA_AALG_NONE) {
		/*
		 * ESP with authentication. We expect the Provider to have
		 * computed the ICV and placed it in the hardware acceleration
		 * data attributes.
		 *
		 * Extract ICV length from attributes M_CTL and sanity check
		 * its value. We allow the mblk to be smaller than da_ipsec_t
		 * for a small ICV, as long as the entire ICV fits within the
		 * mblk.
		 *
		 * Also ensures that the ICV length computed by Provider
		 * corresponds to the ICV length of the agorithm specified by
		 * the SA.
		 */
		icv_len = hada->da_icv_len;
		if ((icv_len != assoc->ipsa_mac_len) ||
		    (icv_len > DA_ICV_MAX_LEN) || (MBLKL(hada_mp) <
			(sizeof (da_ipsec_t) - DA_ICV_MAX_LEN + icv_len))) {
			esp0dbg(("esp_inbound_accelerated: "
			    "ICV len (%u) incorrect or mblk too small (%u)\n",
			    icv_len, (uint32_t)(MBLKL(hada_mp))));
			counter = &ipdrops_esp_bad_auth;
			goto esp_in_discard;
		}
	}

	/* get pointers to IP header */
	if (isv4) {
		ipha = (ipha_t *)data_mp->b_rptr;
	} else {
		ip6h = (ip6_t *)data_mp->b_rptr;
	}

	/*
	 * Compare ICV in ESP packet vs ICV computed by adapter.
	 * We also remove the ICV from the end of the packet since
	 * it will no longer be needed.
	 *
	 * Assume that esp_inbound() already ensured that the pkt
	 * was in one mblk.
	 */
	ASSERT(data_mp->b_cont == NULL);
	data_mp->b_wptr -= icv_len;
	/* adjust IP header */
	if (isv4)
		ipha->ipha_length = htons(ntohs(ipha->ipha_length) - icv_len);
	else
		ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) - icv_len);
	if (icv_len && bcmp(hada->da_icv, data_mp->b_wptr, icv_len)) {
		int af;
		void *addr;

		if (isv4) {
			addr = &ipha->ipha_dst;
			af = AF_INET;
		} else {
			addr = &ip6h->ip6_dst;
			af = AF_INET6;
		}

		/*
		 * Log the event. Don't print to the console, block
		 * potential denial-of-service attack.
		 */
		ESP_BUMP_STAT(bad_auth);
		ipsec_assocfailure(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
		    "ESP Authentication failed spi %x, dst_addr %s",
		    assoc->ipsa_spi, addr, af);
		counter = &ipdrops_esp_bad_auth;
		goto esp_in_discard;
	}

	esp3dbg(("esp_inbound_accelerated: ESP authentication succeeded, "
	    "checking replay\n"));

	ipsec_in->b_cont = data_mp;

	/*
	 * Remove ESP header and padding from packet.
	 */
	if (!esp_strip_header(data_mp, ii->ipsec_in_v4, assoc->ipsa_iv_len,
		&counter)) {
		esp1dbg(("esp_inbound_accelerated: "
		    "esp_strip_header() failed\n"));
		goto esp_in_discard;
	}

	freeb(hada_mp);

	/*
	 * Account for usage..
	 */
	if (!esp_age_bytes(assoc, msgdsize(data_mp), B_TRUE)) {
		/* The ipsa has hit hard expiration, LOG and AUDIT. */
		ESP_BUMP_STAT(bytes_expired);
		IP_ESP_BUMP_STAT(in_discards);
		ipsec_assocfailure(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
		    "ESP association 0x%x, dst %s had bytes expire.\n",
		    assoc->ipsa_spi, assoc->ipsa_dstaddr, assoc->ipsa_addrfam);
		ip_drop_packet(ipsec_in, B_TRUE, NULL, NULL,
		    &ipdrops_esp_bytes_expire, &esp_dropper);
		return (IPSEC_STATUS_FAILED);
	}

	/* done processing the packet */
	return (IPSEC_STATUS_SUCCESS);

esp_in_discard:
	IP_ESP_BUMP_STAT(in_discards);
	freeb(hada_mp);

	ipsec_in->b_cont = data_mp;	/* For ip_drop_packet()'s sake... */
	ip_drop_packet(ipsec_in, B_TRUE, NULL, NULL, counter, &esp_dropper);

	return (IPSEC_STATUS_FAILED);
}

/*
 * Wrapper to allow IP to trigger an ESP association failure message
 * during inbound SA selection.
 */
void
ipsecesp_in_assocfailure(mblk_t *mp, char level, ushort_t sl, char *fmt,
    uint32_t spi, void *addr, int af)
{
	if (ipsecesp_log_unknown_spi) {
		ipsec_assocfailure(info.mi_idnum, 0, level, sl, fmt, spi,
		    addr, af);
	}

	ip_drop_packet(mp, B_TRUE, NULL, NULL, &ipdrops_esp_no_sa,
	    &esp_dropper);
}

/*
 * Initialize the ESP input and output processing functions.
 */
void
ipsecesp_init_funcs(ipsa_t *sa)
{
	if (sa->ipsa_output_func == NULL)
		sa->ipsa_output_func = esp_outbound;
	if (sa->ipsa_input_func == NULL)
		sa->ipsa_input_func = esp_inbound;
}
