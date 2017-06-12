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
#include <sys/errno.h>
#include <sys/strlog.h>
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/zone.h>
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
#include <net/pfpolicy.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ndp.h>
#include <inet/sadb.h>
#include <inet/ipsec_info.h>
#include <inet/ipsec_impl.h>
#include <inet/ipsecesp.h>
#include <inet/ipdrop.h>
#include <inet/tcp.h>
#include <sys/kstat.h>
#include <sys/policy.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <inet/udp_impl.h>
#include <sys/taskq.h>
#include <sys/note.h>

#include <sys/tsol/tnet.h>

/*
 * Table of ND variables supported by ipsecesp. These are loaded into
 * ipsecesp_g_nd in ipsecesp_init_nd.
 * All of these are alterable, within the min/max values given, at run time.
 */
static	ipsecespparam_t	lcl_param_arr[] = {
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
	{ 0,	600,		20,	"ipsecesp_nat_keepalive_interval"},
};
/* For ipsecesp_nat_keepalive_interval, see ipsecesp.h. */

#define	esp0dbg(a)	printf a
/* NOTE:  != 0 instead of > 0 so lint doesn't complain. */
#define	esp1dbg(espstack, a)	if (espstack->ipsecesp_debug != 0) printf a
#define	esp2dbg(espstack, a)	if (espstack->ipsecesp_debug > 1) printf a
#define	esp3dbg(espstack, a)	if (espstack->ipsecesp_debug > 2) printf a

static int ipsecesp_open(queue_t *, dev_t *, int, int, cred_t *);
static int ipsecesp_close(queue_t *);
static void ipsecesp_wput(queue_t *, mblk_t *);
static void	*ipsecesp_stack_init(netstackid_t stackid, netstack_t *ns);
static void	ipsecesp_stack_fini(netstackid_t stackid, void *arg);

static void esp_prepare_udp(netstack_t *, mblk_t *, ipha_t *);
static void esp_outbound_finish(mblk_t *, ip_xmit_attr_t *);
static void esp_inbound_restart(mblk_t *, ip_recv_attr_t *);

static boolean_t esp_register_out(uint32_t, uint32_t, uint_t,
    ipsecesp_stack_t *, cred_t *);
static boolean_t esp_strip_header(mblk_t *, boolean_t, uint32_t,
    kstat_named_t **, ipsecesp_stack_t *);
static mblk_t *esp_submit_req_inbound(mblk_t *, ip_recv_attr_t *,
    ipsa_t *, uint_t);
static mblk_t *esp_submit_req_outbound(mblk_t *, ip_xmit_attr_t *,
    ipsa_t *, uchar_t *, uint_t);

/* Setable in /etc/system */
uint32_t esp_hash_size = IPSEC_DEFAULT_HASH_SIZE;

static struct module_info info = {
	5137, "ipsecesp", 0, INFPSZ, 65536, 1024
};

static struct qinit rinit = {
	(pfi_t)putnext, NULL, ipsecesp_open, ipsecesp_close, NULL, &info,
	NULL
};

static struct qinit winit = {
	(pfi_t)ipsecesp_wput, NULL, ipsecesp_open, ipsecesp_close, NULL, &info,
	NULL
};

struct streamtab ipsecespinfo = {
	&rinit, &winit, NULL, NULL
};

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

static int	esp_kstat_update(kstat_t *, int);

static boolean_t
esp_kstat_init(ipsecesp_stack_t *espstack, netstackid_t stackid)
{
	espstack->esp_ksp = kstat_create_netstack("ipsecesp", 0, "esp_stat",
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (esp_kstats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT, stackid);

	if (espstack->esp_ksp == NULL || espstack->esp_ksp->ks_data == NULL)
		return (B_FALSE);

	espstack->esp_kstats = espstack->esp_ksp->ks_data;

	espstack->esp_ksp->ks_update = esp_kstat_update;
	espstack->esp_ksp->ks_private = (void *)(uintptr_t)stackid;

#define	K64 KSTAT_DATA_UINT64
#define	KI(x) kstat_named_init(&(espstack->esp_kstats->esp_stat_##x), #x, K64)

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
	KI(crypto_sync);
	KI(crypto_async);
	KI(crypto_failures);
	KI(bad_decrypt);
	KI(sa_port_renumbers);

#undef KI
#undef K64

	kstat_install(espstack->esp_ksp);

	return (B_TRUE);
}

static int
esp_kstat_update(kstat_t *kp, int rw)
{
	esp_kstats_t *ekp;
	netstackid_t	stackid = (zoneid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	ipsec_stack_t	*ipss;

	if ((kp == NULL) || (kp->ks_data == NULL))
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	ipss = ns->netstack_ipsec;
	if (ipss == NULL) {
		netstack_rele(ns);
		return (-1);
	}
	ekp = (esp_kstats_t *)kp->ks_data;

	rw_enter(&ipss->ipsec_alg_lock, RW_READER);
	ekp->esp_stat_num_aalgs.value.ui64 =
	    ipss->ipsec_nalgs[IPSEC_ALG_AUTH];
	ekp->esp_stat_num_ealgs.value.ui64 =
	    ipss->ipsec_nalgs[IPSEC_ALG_ENCR];
	rw_exit(&ipss->ipsec_alg_lock);

	netstack_rele(ns);
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
static void
esp_ager(void *arg)
{
	ipsecesp_stack_t *espstack = (ipsecesp_stack_t *)arg;
	netstack_t	*ns = espstack->ipsecesp_netstack;
	hrtime_t begin = gethrtime();

	sadb_ager(&espstack->esp_sadb.s_v4, espstack->esp_pfkey_q,
	    espstack->ipsecesp_reap_delay, ns);
	sadb_ager(&espstack->esp_sadb.s_v6, espstack->esp_pfkey_q,
	    espstack->ipsecesp_reap_delay, ns);

	espstack->esp_event = sadb_retimeout(begin, espstack->esp_pfkey_q,
	    esp_ager, espstack,
	    &espstack->ipsecesp_age_interval, espstack->ipsecesp_age_int_max,
	    info.mi_idnum);
}

/*
 * Get an ESP NDD parameter.
 */
/* ARGSUSED */
static int
ipsecesp_param_get(
    queue_t	*q,
    mblk_t	*mp,
    caddr_t	cp,
    cred_t *cr)
{
	ipsecespparam_t	*ipsecesppa = (ipsecespparam_t *)cp;
	uint_t value;
	ipsecesp_stack_t	*espstack = (ipsecesp_stack_t *)q->q_ptr;

	mutex_enter(&espstack->ipsecesp_param_lock);
	value = ipsecesppa->ipsecesp_param_value;
	mutex_exit(&espstack->ipsecesp_param_lock);

	(void) mi_mpprintf(mp, "%u", value);
	return (0);
}

/*
 * This routine sets an NDD variable in a ipsecespparam_t structure.
 */
/* ARGSUSED */
static int
ipsecesp_param_set(
    queue_t	*q,
    mblk_t	*mp,
    char	*value,
    caddr_t	cp,
    cred_t *cr)
{
	ulong_t	new_value;
	ipsecespparam_t	*ipsecesppa = (ipsecespparam_t *)cp;
	ipsecesp_stack_t	*espstack = (ipsecesp_stack_t *)q->q_ptr;

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
	mutex_enter(&espstack->ipsecesp_param_lock);
	ipsecesppa->ipsecesp_param_value = new_value;
	mutex_exit(&espstack->ipsecesp_param_lock);
	return (0);
}

/*
 * Using lifetime NDD variables, fill in an extended combination's
 * lifetime information.
 */
void
ipsecesp_fill_defs(sadb_x_ecomb_t *ecomb, netstack_t *ns)
{
	ipsecesp_stack_t	*espstack = ns->netstack_ipsecesp;

	ecomb->sadb_x_ecomb_soft_bytes = espstack->ipsecesp_default_soft_bytes;
	ecomb->sadb_x_ecomb_hard_bytes = espstack->ipsecesp_default_hard_bytes;
	ecomb->sadb_x_ecomb_soft_addtime =
	    espstack->ipsecesp_default_soft_addtime;
	ecomb->sadb_x_ecomb_hard_addtime =
	    espstack->ipsecesp_default_hard_addtime;
	ecomb->sadb_x_ecomb_soft_usetime =
	    espstack->ipsecesp_default_soft_usetime;
	ecomb->sadb_x_ecomb_hard_usetime =
	    espstack->ipsecesp_default_hard_usetime;
}

/*
 * Initialize things for ESP at module load time.
 */
boolean_t
ipsecesp_ddi_init(void)
{
	esp_taskq = taskq_create("esp_taskq", 1, minclsyspri,
	    IPSEC_TASKQ_MIN, IPSEC_TASKQ_MAX, 0);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of ipsecesp_stack_t's.
	 */
	netstack_register(NS_IPSECESP, ipsecesp_stack_init, NULL,
	    ipsecesp_stack_fini);

	return (B_TRUE);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch handler.
 */
static boolean_t
ipsecesp_param_register(IDP *ndp, ipsecespparam_t *espp, int cnt)
{
	for (; cnt-- > 0; espp++) {
		if (espp->ipsecesp_param_name != NULL &&
		    espp->ipsecesp_param_name[0]) {
			if (!nd_load(ndp,
			    espp->ipsecesp_param_name,
			    ipsecesp_param_get, ipsecesp_param_set,
			    (caddr_t)espp)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}
	return (B_TRUE);
}

/*
 * Initialize things for ESP for each stack instance
 */
static void *
ipsecesp_stack_init(netstackid_t stackid, netstack_t *ns)
{
	ipsecesp_stack_t	*espstack;
	ipsecespparam_t		*espp;

	espstack = (ipsecesp_stack_t *)kmem_zalloc(sizeof (*espstack),
	    KM_SLEEP);
	espstack->ipsecesp_netstack = ns;

	espp = (ipsecespparam_t *)kmem_alloc(sizeof (lcl_param_arr), KM_SLEEP);
	espstack->ipsecesp_params = espp;
	bcopy(lcl_param_arr, espp, sizeof (lcl_param_arr));

	(void) ipsecesp_param_register(&espstack->ipsecesp_g_nd, espp,
	    A_CNT(lcl_param_arr));

	(void) esp_kstat_init(espstack, stackid);

	espstack->esp_sadb.s_acquire_timeout =
	    &espstack->ipsecesp_acquire_timeout;
	sadbp_init("ESP", &espstack->esp_sadb, SADB_SATYPE_ESP, esp_hash_size,
	    espstack->ipsecesp_netstack);

	mutex_init(&espstack->ipsecesp_param_lock, NULL, MUTEX_DEFAULT, 0);

	ip_drop_register(&espstack->esp_dropper, "IPsec ESP");
	return (espstack);
}

/*
 * Destroy things for ESP at module unload time.
 */
void
ipsecesp_ddi_destroy(void)
{
	netstack_unregister(NS_IPSECESP);
	taskq_destroy(esp_taskq);
}

/*
 * Destroy things for ESP for one stack instance
 */
static void
ipsecesp_stack_fini(netstackid_t stackid, void *arg)
{
	ipsecesp_stack_t *espstack = (ipsecesp_stack_t *)arg;

	if (espstack->esp_pfkey_q != NULL) {
		(void) quntimeout(espstack->esp_pfkey_q, espstack->esp_event);
	}
	espstack->esp_sadb.s_acquire_timeout = NULL;
	sadbp_destroy(&espstack->esp_sadb, espstack->ipsecesp_netstack);
	ip_drop_unregister(&espstack->esp_dropper);
	mutex_destroy(&espstack->ipsecesp_param_lock);
	nd_free(&espstack->ipsecesp_g_nd);

	kmem_free(espstack->ipsecesp_params, sizeof (lcl_param_arr));
	espstack->ipsecesp_params = NULL;
	kstat_delete_netstack(espstack->esp_ksp, stackid);
	espstack->esp_ksp = NULL;
	espstack->esp_kstats = NULL;
	kmem_free(espstack, sizeof (*espstack));
}

/*
 * ESP module open routine, which is here for keysock plumbing.
 * Keysock is pushed over {AH,ESP} which is an artifact from the Bad Old
 * Days of export control, and fears that ESP would not be allowed
 * to be shipped at all by default.  Eventually, keysock should
 * either access AH and ESP via modstubs or krtld dependencies, or
 * perhaps be folded in with AH and ESP into a single IPsec/netsec
 * module ("netsec" if PF_KEY provides more than AH/ESP keying tables).
 */
/* ARGSUSED */
static int
ipsecesp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	netstack_t		*ns;
	ipsecesp_stack_t	*espstack;

	if (secpolicy_ip_config(credp, B_FALSE) != 0)
		return (EPERM);

	if (q->q_ptr != NULL)
		return (0);  /* Re-open of an already open instance. */

	if (sflag != MODOPEN)
		return (EINVAL);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	espstack = ns->netstack_ipsecesp;
	ASSERT(espstack != NULL);

	q->q_ptr = espstack;
	WR(q)->q_ptr = q->q_ptr;

	qprocson(q);
	return (0);
}

/*
 * ESP module close routine.
 */
static int
ipsecesp_close(queue_t *q)
{
	ipsecesp_stack_t	*espstack = (ipsecesp_stack_t *)q->q_ptr;

	/*
	 * Clean up q_ptr, if needed.
	 */
	qprocsoff(q);

	/* Keysock queue check is safe, because of OCEXCL perimeter. */

	if (q == espstack->esp_pfkey_q) {
		esp1dbg(espstack,
		    ("ipsecesp_close:  Ummm... keysock is closing ESP.\n"));
		espstack->esp_pfkey_q = NULL;
		/* Detach qtimeouts. */
		(void) quntimeout(q, espstack->esp_event);
	}

	netstack_rele(espstack->ipsecesp_netstack);
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
	netstack_t		*ns = assoc->ipsa_netstack;
	ipsecesp_stack_t	*espstack = ns->netstack_ipsecesp;

	/* No peer?  No problem! */
	if (!assoc->ipsa_haspeer) {
		return (sadb_age_bytes(espstack->esp_pfkey_q, assoc, bytes,
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
	sp = isv6 ? &espstack->esp_sadb.s_v6 : &espstack->esp_sadb.s_v4;

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
			return (sadb_age_bytes(espstack->esp_pfkey_q, inassoc,
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
			return (sadb_age_bytes(espstack->esp_pfkey_q, outassoc,
			    bytes, B_TRUE));
		}
	}

	inrc = sadb_age_bytes(espstack->esp_pfkey_q, inassoc, bytes, B_TRUE);
	outrc = sadb_age_bytes(espstack->esp_pfkey_q, outassoc, bytes, B_FALSE);

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
 * Returns NULL if the mblk chain is consumed.
 */
static mblk_t *
esp_fix_natt_checksums(mblk_t *data_mp, ipsa_t *assoc)
{
	ipha_t *ipha = (ipha_t *)data_mp->b_rptr;
	tcpha_t *tcpha;
	udpha_t *udpha;
	/* Initialize to our inbound cksum adjustment... */
	uint32_t sum = assoc->ipsa_inbound_cksum;

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP:
		tcpha = (tcpha_t *)(data_mp->b_rptr +
		    IPH_HDR_LENGTH(ipha));

#define	DOWN_SUM(x) (x) = ((x) & 0xFFFF) +	 ((x) >> 16)
		sum += ~ntohs(tcpha->tha_sum) & 0xFFFF;
		DOWN_SUM(sum);
		DOWN_SUM(sum);
		tcpha->tha_sum = ~htons(sum);
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
	return (data_mp);
}


/*
 * Strip ESP header, check padding, and fix IP header.
 * Returns B_TRUE on success, B_FALSE if an error occured.
 */
static boolean_t
esp_strip_header(mblk_t *data_mp, boolean_t isv4, uint32_t ivlen,
    kstat_named_t **counter, ipsecesp_stack_t *espstack)
{
	ipha_t *ipha;
	ip6_t *ip6h;
	uint_t divpoint;
	mblk_t *scratch;
	uint8_t nexthdr, padlen;
	uint8_t lastpad;
	ipsec_stack_t	*ipss = espstack->ipsecesp_netstack->netstack_ipsec;
	uint8_t *lastbyte;

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
	lastbyte = scratch->b_wptr - 1;
	nexthdr = *lastbyte--;
	padlen = *lastbyte--;

	if (isv4) {
		/* Fix part of the IP header. */
		ipha->ipha_protocol = nexthdr;
		/*
		 * Reality check the padlen.  The explicit - 2 is for the
		 * padding length and the next-header bytes.
		 */
		if (padlen >= ntohs(ipha->ipha_length) - sizeof (ipha_t) - 2 -
		    sizeof (esph_t) - ivlen) {
			ESP_BUMP_STAT(espstack, bad_decrypt);
			ipsec_rl_strlog(espstack->ipsecesp_netstack,
			    info.mi_idnum, 0, 0,
			    SL_ERROR | SL_WARN,
			    "Corrupt ESP packet (padlen too big).\n");
			esp1dbg(espstack, ("padlen (%d) is greater than:\n",
			    padlen));
			esp1dbg(espstack, ("pkt len(%d) - ip hdr - esp "
			    "hdr - ivlen(%d) = %d.\n",
			    ntohs(ipha->ipha_length), ivlen,
			    (int)(ntohs(ipha->ipha_length) - sizeof (ipha_t) -
			    2 - sizeof (esph_t) - ivlen)));
			*counter = DROPPER(ipss, ipds_esp_bad_padlen);
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
			ip_pkt_t ipp;

			bzero(&ipp, sizeof (ipp));
			(void) ip_find_hdr_v6(data_mp, ip6h, B_FALSE, &ipp,
			    NULL);
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
			ESP_BUMP_STAT(espstack, bad_decrypt);
			ipsec_rl_strlog(espstack->ipsecesp_netstack,
			    info.mi_idnum, 0, 0,
			    SL_ERROR | SL_WARN,
			    "Corrupt ESP packet (v6 padlen too big).\n");
			esp1dbg(espstack, ("padlen (%d) is greater than:\n",
			    padlen));
			esp1dbg(espstack,
			    ("pkt len(%u) - ip hdr - esp hdr - ivlen(%d) = "
			    "%u.\n", (unsigned)(ntohs(ip6h->ip6_plen)
			    + sizeof (ip6_t)), ivlen,
			    (unsigned)(ntohs(ip6h->ip6_plen) - 2 -
			    sizeof (esph_t) - ivlen)));
			*counter = DROPPER(ipss, ipds_esp_bad_padlen);
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

	if (espstack->ipsecesp_padding_check > 0 && padlen > 0) {
		/*
		 * Weak padding check: compare last-byte to length, they
		 * should be equal.
		 */
		lastpad = *lastbyte--;

		if (padlen != lastpad) {
			ipsec_rl_strlog(espstack->ipsecesp_netstack,
			    info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
			    "Corrupt ESP packet (lastpad != padlen).\n");
			esp1dbg(espstack,
			    ("lastpad (%d) not equal to padlen (%d):\n",
			    lastpad, padlen));
			ESP_BUMP_STAT(espstack, bad_padding);
			*counter = DROPPER(ipss, ipds_esp_bad_padding);
			return (B_FALSE);
		}

		/*
		 * Strong padding check: Check all pad bytes to see that
		 * they're ascending.  Go backwards using a descending counter
		 * to verify.  padlen == 1 is checked by previous block, so
		 * only bother if we've more than 1 byte of padding.
		 * Consequently, start the check one byte before the location
		 * of "lastpad".
		 */
		if (espstack->ipsecesp_padding_check > 1) {
			/*
			 * This assert may have to become an if and a pullup
			 * if we start accepting multi-dblk mblks. For now,
			 * though, any packet here will have been pulled up in
			 * esp_inbound.
			 */
			ASSERT(MBLKL(scratch) >= lastpad + 3);

			/*
			 * Use "--lastpad" because we already checked the very
			 * last pad byte previously.
			 */
			while (--lastpad != 0) {
				if (lastpad != *lastbyte) {
					ipsec_rl_strlog(
					    espstack->ipsecesp_netstack,
					    info.mi_idnum, 0, 0,
					    SL_ERROR | SL_WARN, "Corrupt ESP "
					    "packet (bad padding).\n");
					esp1dbg(espstack,
					    ("padding not in correct"
					    " format:\n"));
					ESP_BUMP_STAT(espstack, bad_padding);
					*counter = DROPPER(ipss,
					    ipds_esp_bad_padding);
					return (B_FALSE);
				}
				lastbyte--;
			}
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

	esp2dbg(espstack, ("data_mp after inbound ESP adjustment:\n"));
	esp2dbg(espstack, (dump_msg(data_mp)));

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
	netstack_t		*ns = assoc->ipsa_netstack;
	ipsecesp_stack_t	*espstack = ns->netstack_ipsecesp;

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
	sp = isv6 ? &espstack->esp_sadb.s_v6 : &espstack->esp_sadb.s_v4;

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
 * mblk chain data_mp.
 */
mblk_t *
esp_inbound(mblk_t *data_mp, void *arg, ip_recv_attr_t *ira)
{
	esph_t *esph = (esph_t *)arg;
	ipsa_t *ipsa = ira->ira_ipsec_esp_sa;
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

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
		ESP_BUMP_STAT(espstack, replay_early_failures);
		IP_ESP_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(data_mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_esp_early_replay),
		    &espstack->esp_dropper);
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		return (NULL);
	}

	/*
	 * Adjust the IP header's payload length to reflect the removal
	 * of the ICV.
	 */
	if (!(ira->ira_flags & IRAF_IS_IPV4)) {
		ip6_t *ip6h = (ip6_t *)data_mp->b_rptr;
		ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) -
		    ipsa->ipsa_mac_len);
	} else {
		ipha_t *ipha = (ipha_t *)data_mp->b_rptr;
		ipha->ipha_length = htons(ntohs(ipha->ipha_length) -
		    ipsa->ipsa_mac_len);
	}

	/* submit the request to the crypto framework */
	return (esp_submit_req_inbound(data_mp, ira, ipsa,
	    (uint8_t *)esph - data_mp->b_rptr));
}

/* XXX refactor me */
/*
 * Handle the SADB_GETSPI message.  Create a larval SA.
 */
static void
esp_getspi(mblk_t *mp, keysock_in_t *ksi, ipsecesp_stack_t *espstack)
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
	if (cl_inet_getspi != NULL) {
		cl_inet_getspi(espstack->ipsecesp_netstack->netstack_stackid,
		    IPPROTO_ESP, (uint8_t *)&newspi, sizeof (uint32_t), NULL);
	} else {
		(void) random_get_pseudo_bytes((uint8_t *)&newspi,
		    sizeof (uint32_t));
	}
	newbie = sadb_getspi(ksi, newspi, &diagnostic,
	    espstack->ipsecesp_netstack, IPPROTO_ESP);

	if (newbie == NULL) {
		sadb_pfkey_error(espstack->esp_pfkey_q, mp, ENOMEM, diagnostic,
		    ksi->ks_in_serial);
		return;
	} else if (newbie == (ipsa_t *)-1) {
		sadb_pfkey_error(espstack->esp_pfkey_q, mp, EINVAL, diagnostic,
		    ksi->ks_in_serial);
		return;
	}

	/*
	 * XXX - We may randomly collide.  We really should recover from this.
	 *	 Unfortunately, that could require spending way-too-much-time
	 *	 in here.  For now, let the user retry.
	 */

	if (newbie->ipsa_addrfam == AF_INET6) {
		outbound = OUTBOUND_BUCKET_V6(&espstack->esp_sadb.s_v6,
		    *(uint32_t *)(newbie->ipsa_dstaddr));
		inbound = INBOUND_BUCKET(&espstack->esp_sadb.s_v6,
		    newbie->ipsa_spi);
	} else {
		ASSERT(newbie->ipsa_addrfam == AF_INET);
		outbound = OUTBOUND_BUCKET_V4(&espstack->esp_sadb.s_v4,
		    *(uint32_t *)(newbie->ipsa_dstaddr));
		inbound = INBOUND_BUCKET(&espstack->esp_sadb.s_v4,
		    newbie->ipsa_spi);
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
		newbie->ipsa_hardexpiretime = gethrestime_sec();
		newbie->ipsa_hardexpiretime +=
		    espstack->ipsecesp_larval_timeout;
	}

	/*
	 * Can exit outbound mutex.  Hold inbound until we're done
	 * with newbie.
	 */
	mutex_exit(&outbound->isaf_lock);

	if (rc != 0) {
		mutex_exit(&inbound->isaf_lock);
		IPSA_REFRELE(newbie);
		sadb_pfkey_error(espstack->esp_pfkey_q, mp, rc,
		    SADB_X_DIAGNOSTIC_NONE, ksi->ks_in_serial);
		return;
	}


	/* Can write here because I'm still holding the bucket lock. */
	newbie->ipsa_type = SADB_SATYPE_ESP;

	/*
	 * Construct successful return message. We have one thing going
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
	putnext(espstack->esp_pfkey_q, mp);
}

/*
 * Insert the ESP header into a packet.  Duplicate an mblk, and insert a newly
 * allocated mblk with the ESP header in between the two.
 */
static boolean_t
esp_insert_esp(mblk_t *mp, mblk_t *esp_mp, uint_t divpoint,
    ipsecesp_stack_t *espstack)
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
			esp1dbg(espstack,
			    ("esp_insert_esp: can't allocate scratch.\n"));
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
 * Section 7 of RFC 3947 says:
 *
 * 7.  Recovering from the Expiring NAT Mappings
 *
 *    There are cases where NAT box decides to remove mappings that are still
 *    alive (for example, when the keepalive interval is too long, or when the
 *    NAT box is rebooted).  To recover from this, ends that are NOT behind
 *    NAT SHOULD use the last valid UDP encapsulated IKE or IPsec packet from
 *    the other end to determine which IP and port addresses should be used.
 *    The host behind dynamic NAT MUST NOT do this, as otherwise it opens a
 *    DoS attack possibility because the IP address or port of the other host
 *    will not change (it is not behind NAT).
 *
 *    Keepalives cannot be used for these purposes, as they are not
 *    authenticated, but any IKE authenticated IKE packet or ESP packet can be
 *    used to detect whether the IP address or the port has changed.
 *
 * The following function will check an SA and its explicitly-set pair to see
 * if the NAT-T remote port matches the received packet (which must have
 * passed ESP authentication, see esp_in_done() for the caller context).  If
 * there is a mismatch, the SAs are updated.  It is not important if we race
 * with a transmitting thread, as if there is a transmitting thread, it will
 * merely emit a packet that will most-likely be dropped.
 *
 * "ports" are ordered src,dst, and assoc is an inbound SA, where src should
 * match ipsa_remote_nat_port and dst should match ipsa_local_nat_port.
 */
#ifdef _LITTLE_ENDIAN
#define	FIRST_16(x) ((x) & 0xFFFF)
#define	NEXT_16(x) (((x) >> 16) & 0xFFFF)
#else
#define	FIRST_16(x) (((x) >> 16) & 0xFFFF)
#define	NEXT_16(x) ((x) & 0xFFFF)
#endif
static void
esp_port_freshness(uint32_t ports, ipsa_t *assoc)
{
	uint16_t remote = FIRST_16(ports);
	uint16_t local = NEXT_16(ports);
	ipsa_t *outbound_peer;
	isaf_t *bucket;
	ipsecesp_stack_t *espstack = assoc->ipsa_netstack->netstack_ipsecesp;

	/* We found a conn_t, therefore local != 0. */
	ASSERT(local != 0);
	/* Assume an IPv4 SA. */
	ASSERT(assoc->ipsa_addrfam == AF_INET);

	/*
	 * On-the-wire rport == 0 means something's very wrong.
	 * An unpaired SA is also useless to us.
	 * If we are behind the NAT, don't bother.
	 * A zero local NAT port defaults to 4500, so check that too.
	 * And, of course, if the ports already match, we don't need to
	 * bother.
	 */
	if (remote == 0 || assoc->ipsa_otherspi == 0 ||
	    (assoc->ipsa_flags & IPSA_F_BEHIND_NAT) ||
	    (assoc->ipsa_remote_nat_port == 0 &&
	    remote == htons(IPPORT_IKE_NATT)) ||
	    remote == assoc->ipsa_remote_nat_port)
		return;

	/* Try and snag the peer.   NOTE:  Assume IPv4 for now. */
	bucket = OUTBOUND_BUCKET_V4(&(espstack->esp_sadb.s_v4),
	    assoc->ipsa_srcaddr[0]);
	mutex_enter(&bucket->isaf_lock);
	outbound_peer = ipsec_getassocbyspi(bucket, assoc->ipsa_otherspi,
	    assoc->ipsa_dstaddr, assoc->ipsa_srcaddr, AF_INET);
	mutex_exit(&bucket->isaf_lock);

	/* We probably lost a race to a deleting or expiring thread. */
	if (outbound_peer == NULL)
		return;

	/*
	 * Hold the mutexes for both SAs so we don't race another inbound
	 * thread.  A lock-entry order shouldn't matter, since all other
	 * per-ipsa locks are individually held-then-released.
	 *
	 * Luckily, this has nothing to do with the remote-NAT address,
	 * so we don't have to re-scribble the cached-checksum differential.
	 */
	mutex_enter(&outbound_peer->ipsa_lock);
	mutex_enter(&assoc->ipsa_lock);
	outbound_peer->ipsa_remote_nat_port = assoc->ipsa_remote_nat_port =
	    remote;
	mutex_exit(&assoc->ipsa_lock);
	mutex_exit(&outbound_peer->ipsa_lock);
	IPSA_REFRELE(outbound_peer);
	ESP_BUMP_STAT(espstack, sa_port_renumbers);
}
/*
 * Finish processing of an inbound ESP packet after processing by the
 * crypto framework.
 * - Remove the ESP header.
 * - Send packet back to IP.
 * If authentication was performed on the packet, this function is called
 * only if the authentication succeeded.
 * On success returns B_TRUE, on failure returns B_FALSE and frees the
 * mblk chain data_mp.
 */
static mblk_t *
esp_in_done(mblk_t *data_mp, ip_recv_attr_t *ira, ipsec_crypto_t *ic)
{
	ipsa_t *assoc;
	uint_t espstart;
	uint32_t ivlen = 0;
	uint_t processed_len;
	esph_t *esph;
	kstat_named_t *counter;
	boolean_t is_natt;
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	assoc = ira->ira_ipsec_esp_sa;
	ASSERT(assoc != NULL);

	is_natt = ((assoc->ipsa_flags & IPSA_F_NATT) != 0);

	/* get the pointer to the ESP header */
	if (assoc->ipsa_encr_alg == SADB_EALG_NULL) {
		/* authentication-only ESP */
		espstart = ic->ic_crypto_data.cd_offset;
		processed_len = ic->ic_crypto_data.cd_length;
	} else {
		/* encryption present */
		ivlen = assoc->ipsa_iv_len;
		if (assoc->ipsa_auth_alg == SADB_AALG_NONE) {
			/* encryption-only ESP */
			espstart = ic->ic_crypto_data.cd_offset -
			    sizeof (esph_t) - assoc->ipsa_iv_len;
			processed_len = ic->ic_crypto_data.cd_length +
			    ivlen;
		} else {
			/* encryption with authentication */
			espstart = ic->ic_crypto_dual_data.dd_offset1;
			processed_len = ic->ic_crypto_dual_data.dd_len2 +
			    ivlen;
		}
	}

	esph = (esph_t *)(data_mp->b_rptr + espstart);

	if (assoc->ipsa_auth_alg != IPSA_AALG_NONE ||
	    (assoc->ipsa_flags & IPSA_F_COMBINED)) {
		/*
		 * Authentication passed if we reach this point.
		 * Packets with authentication will have the ICV
		 * after the crypto data. Adjust b_wptr before
		 * making padlen checks.
		 */
		ESP_BUMP_STAT(espstack, good_auth);
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
			    assoc->ipsa_addrfam, espstack->ipsecesp_netstack);
			ESP_BUMP_STAT(espstack, replay_failures);
			counter = DROPPER(ipss, ipds_esp_replay);
			goto drop_and_bail;
		}

		if (is_natt) {
			ASSERT(ira->ira_flags & IRAF_ESP_UDP_PORTS);
			ASSERT(ira->ira_esp_udp_ports != 0);
			esp_port_freshness(ira->ira_esp_udp_ports, assoc);
		}
	}

	esp_set_usetime(assoc, B_TRUE);

	if (!esp_age_bytes(assoc, processed_len, B_TRUE)) {
		/* The ipsa has hit hard expiration, LOG and AUDIT. */
		ipsec_assocfailure(info.mi_idnum, 0, 0,
		    SL_ERROR | SL_WARN,
		    "ESP association 0x%x, dst %s had bytes expire.\n",
		    assoc->ipsa_spi, assoc->ipsa_dstaddr, assoc->ipsa_addrfam,
		    espstack->ipsecesp_netstack);
		ESP_BUMP_STAT(espstack, bytes_expired);
		counter = DROPPER(ipss, ipds_esp_bytes_expire);
		goto drop_and_bail;
	}

	/*
	 * Remove ESP header and padding from packet.  I hope the compiler
	 * spews "branch, predict taken" code for this.
	 */

	if (esp_strip_header(data_mp, (ira->ira_flags & IRAF_IS_IPV4),
	    ivlen, &counter, espstack)) {

		if (is_system_labeled() && assoc->ipsa_tsl != NULL) {
			if (!ip_recv_attr_replace_label(ira, assoc->ipsa_tsl)) {
				ip_drop_packet(data_mp, B_TRUE, ira->ira_ill,
				    DROPPER(ipss, ipds_ah_nomem),
				    &espstack->esp_dropper);
				BUMP_MIB(ira->ira_ill->ill_ip_mib,
				    ipIfStatsInDiscards);
				return (NULL);
			}
		}
		if (is_natt)
			return (esp_fix_natt_checksums(data_mp, assoc));

		if (assoc->ipsa_state == IPSA_STATE_IDLE) {
			/*
			 * Cluster buffering case.  Tell caller that we're
			 * handling the packet.
			 */
			sadb_buf_pkt(assoc, data_mp, ira);
			return (NULL);
		}

		return (data_mp);
	}

	esp1dbg(espstack, ("esp_in_done: esp_strip_header() failed\n"));
drop_and_bail:
	IP_ESP_BUMP_STAT(ipss, in_discards);
	ip_drop_packet(data_mp, B_TRUE, ira->ira_ill, counter,
	    &espstack->esp_dropper);
	BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
	return (NULL);
}

/*
 * Called upon failing the inbound ICV check. The message passed as
 * argument is freed.
 */
static void
esp_log_bad_auth(mblk_t *mp, ip_recv_attr_t *ira)
{
	ipsa_t		*assoc = ira->ira_ipsec_esp_sa;
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	/*
	 * Log the event. Don't print to the console, block
	 * potential denial-of-service attack.
	 */
	ESP_BUMP_STAT(espstack, bad_auth);

	ipsec_assocfailure(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
	    "ESP Authentication failed for spi 0x%x, dst %s.\n",
	    assoc->ipsa_spi, assoc->ipsa_dstaddr, assoc->ipsa_addrfam,
	    espstack->ipsecesp_netstack);

	IP_ESP_BUMP_STAT(ipss, in_discards);
	ip_drop_packet(mp, B_TRUE, ira->ira_ill,
	    DROPPER(ipss, ipds_esp_bad_auth),
	    &espstack->esp_dropper);
}


/*
 * Invoked for outbound packets after ESP processing. If the packet
 * also requires AH, performs the AH SA selection and AH processing.
 *
 * Returns data_mp (possibly with AH added) unless data_mp was consumed
 * due to an error, or queued due to async. crypto or an ACQUIRE trigger.
 */
static mblk_t *
esp_do_outbound_ah(mblk_t *data_mp, ip_xmit_attr_t *ixa)
{
	ipsec_action_t *ap;

	ap = ixa->ixa_ipsec_action;
	if (ap == NULL) {
		ipsec_policy_t *pp = ixa->ixa_ipsec_policy;
		ap = pp->ipsp_act;
	}

	if (!ap->ipa_want_ah)
		return (data_mp);

	/*
	 * Normally the AH SA would have already been put in place
	 * but it could have been flushed so we need to look for it.
	 */
	if (ixa->ixa_ipsec_ah_sa == NULL) {
		if (!ipsec_outbound_sa(data_mp, ixa, IPPROTO_AH)) {
			sadb_acquire(data_mp, ixa, B_TRUE, B_FALSE);
			return (NULL);
		}
	}
	ASSERT(ixa->ixa_ipsec_ah_sa != NULL);

	data_mp = ixa->ixa_ipsec_ah_sa->ipsa_output_func(data_mp, ixa);
	return (data_mp);
}


/*
 * Kernel crypto framework callback invoked after completion of async
 * crypto requests for outbound packets.
 */
static void
esp_kcf_callback_outbound(void *arg, int status)
{
	mblk_t		*mp = (mblk_t *)arg;
	mblk_t		*async_mp;
	netstack_t	*ns;
	ipsec_stack_t	*ipss;
	ipsecesp_stack_t *espstack;
	mblk_t		*data_mp;
	ip_xmit_attr_t	ixas;
	ipsec_crypto_t	*ic;
	ill_t		*ill;

	/*
	 * First remove the ipsec_crypto_t mblk
	 * Note that we need to ipsec_free_crypto_data(mp) once done with ic.
	 */
	async_mp = ipsec_remove_crypto_data(mp, &ic);
	ASSERT(async_mp != NULL);

	/*
	 * Extract the ip_xmit_attr_t from the first mblk.
	 * Verifies that the netstack and ill is still around; could
	 * have vanished while kEf was doing its work.
	 * On succesful return we have a nce_t and the ill/ipst can't
	 * disappear until we do the nce_refrele in ixa_cleanup.
	 */
	data_mp = async_mp->b_cont;
	async_mp->b_cont = NULL;
	if (!ip_xmit_attr_from_mblk(async_mp, &ixas)) {
		/* Disappeared on us - no ill/ipst for MIB */
		/* We have nowhere to do stats since ixa_ipst could be NULL */
		if (ixas.ixa_nce != NULL) {
			ill = ixas.ixa_nce->nce_ill;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", data_mp, ill);
		}
		freemsg(data_mp);
		goto done;
	}
	ns = ixas.ixa_ipst->ips_netstack;
	espstack = ns->netstack_ipsecesp;
	ipss = ns->netstack_ipsec;
	ill = ixas.ixa_nce->nce_ill;

	if (status == CRYPTO_SUCCESS) {
		/*
		 * If a ICV was computed, it was stored by the
		 * crypto framework at the end of the packet.
		 */
		ipha_t *ipha = (ipha_t *)data_mp->b_rptr;

		esp_set_usetime(ixas.ixa_ipsec_esp_sa, B_FALSE);
		/* NAT-T packet. */
		if (IPH_HDR_VERSION(ipha) == IP_VERSION &&
		    ipha->ipha_protocol == IPPROTO_UDP)
			esp_prepare_udp(ns, data_mp, ipha);

		/* do AH processing if needed */
		data_mp = esp_do_outbound_ah(data_mp, &ixas);
		if (data_mp == NULL)
			goto done;

		(void) ip_output_post_ipsec(data_mp, &ixas);
	} else {
		/* Outbound shouldn't see invalid MAC */
		ASSERT(status != CRYPTO_INVALID_MAC);

		esp1dbg(espstack,
		    ("esp_kcf_callback_outbound: crypto failed with 0x%x\n",
		    status));
		ESP_BUMP_STAT(espstack, crypto_failures);
		ESP_BUMP_STAT(espstack, out_discards);
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_esp_crypto_failed),
		    &espstack->esp_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
	}
done:
	ixa_cleanup(&ixas);
	(void) ipsec_free_crypto_data(mp);
}

/*
 * Kernel crypto framework callback invoked after completion of async
 * crypto requests for inbound packets.
 */
static void
esp_kcf_callback_inbound(void *arg, int status)
{
	mblk_t		*mp = (mblk_t *)arg;
	mblk_t		*async_mp;
	netstack_t	*ns;
	ipsecesp_stack_t *espstack;
	ipsec_stack_t	*ipss;
	mblk_t		*data_mp;
	ip_recv_attr_t	iras;
	ipsec_crypto_t	*ic;

	/*
	 * First remove the ipsec_crypto_t mblk
	 * Note that we need to ipsec_free_crypto_data(mp) once done with ic.
	 */
	async_mp = ipsec_remove_crypto_data(mp, &ic);
	ASSERT(async_mp != NULL);

	/*
	 * Extract the ip_recv_attr_t from the first mblk.
	 * Verifies that the netstack and ill is still around; could
	 * have vanished while kEf was doing its work.
	 */
	data_mp = async_mp->b_cont;
	async_mp->b_cont = NULL;
	if (!ip_recv_attr_from_mblk(async_mp, &iras)) {
		/* The ill or ip_stack_t disappeared on us */
		ip_drop_input("ip_recv_attr_from_mblk", data_mp, NULL);
		freemsg(data_mp);
		goto done;
	}

	ns = iras.ira_ill->ill_ipst->ips_netstack;
	espstack = ns->netstack_ipsecesp;
	ipss = ns->netstack_ipsec;

	if (status == CRYPTO_SUCCESS) {
		data_mp = esp_in_done(data_mp, &iras, ic);
		if (data_mp == NULL)
			goto done;

		/* finish IPsec processing */
		ip_input_post_ipsec(data_mp, &iras);
	} else if (status == CRYPTO_INVALID_MAC) {
		esp_log_bad_auth(data_mp, &iras);
	} else {
		esp1dbg(espstack,
		    ("esp_kcf_callback: crypto failed with 0x%x\n",
		    status));
		ESP_BUMP_STAT(espstack, crypto_failures);
		IP_ESP_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(data_mp, B_TRUE, iras.ira_ill,
		    DROPPER(ipss, ipds_esp_crypto_failed),
		    &espstack->esp_dropper);
		BUMP_MIB(iras.ira_ill->ill_ip_mib, ipIfStatsInDiscards);
	}
done:
	ira_cleanup(&iras, B_TRUE);
	(void) ipsec_free_crypto_data(mp);
}

/*
 * Invoked on crypto framework failure during inbound and outbound processing.
 */
static void
esp_crypto_failed(mblk_t *data_mp, boolean_t is_inbound, int kef_rc,
    ill_t *ill, ipsecesp_stack_t *espstack)
{
	ipsec_stack_t	*ipss = espstack->ipsecesp_netstack->netstack_ipsec;

	esp1dbg(espstack, ("crypto failed for %s ESP with 0x%x\n",
	    is_inbound ? "inbound" : "outbound", kef_rc));
	ip_drop_packet(data_mp, is_inbound, ill,
	    DROPPER(ipss, ipds_esp_crypto_failed),
	    &espstack->esp_dropper);
	ESP_BUMP_STAT(espstack, crypto_failures);
	if (is_inbound)
		IP_ESP_BUMP_STAT(ipss, in_discards);
	else
		ESP_BUMP_STAT(espstack, out_discards);
}

/*
 * A statement-equivalent macro, _cr MUST point to a modifiable
 * crypto_call_req_t.
 */
#define	ESP_INIT_CALLREQ(_cr, _mp, _callback)				\
	(_cr)->cr_flag = CRYPTO_SKIP_REQID|CRYPTO_ALWAYS_QUEUE;	\
	(_cr)->cr_callback_arg = (_mp);				\
	(_cr)->cr_callback_func = (_callback)

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

/*
 * Returns data_mp if successfully completed the request. Returns
 * NULL if it failed (and increments InDiscards) or if it is pending.
 */
static mblk_t *
esp_submit_req_inbound(mblk_t *esp_mp, ip_recv_attr_t *ira,
    ipsa_t *assoc, uint_t esph_offset)
{
	uint_t auth_offset, msg_len, auth_len;
	crypto_call_req_t call_req, *callrp;
	mblk_t *mp;
	esph_t *esph_ptr;
	int kef_rc;
	uint_t icv_len = assoc->ipsa_mac_len;
	crypto_ctx_template_t auth_ctx_tmpl;
	boolean_t do_auth, do_encr, force;
	uint_t encr_offset, encr_len;
	uint_t iv_len = assoc->ipsa_iv_len;
	crypto_ctx_template_t encr_ctx_tmpl;
	ipsec_crypto_t	*ic, icstack;
	uchar_t *iv_ptr;
	netstack_t *ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsec_stack_t *ipss = ns->netstack_ipsec;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;

	do_auth = assoc->ipsa_auth_alg != SADB_AALG_NONE;
	do_encr = assoc->ipsa_encr_alg != SADB_EALG_NULL;
	force = (assoc->ipsa_flags & IPSA_F_ASYNC);

#ifdef IPSEC_LATENCY_TEST
	kef_rc = CRYPTO_SUCCESS;
#else
	kef_rc = CRYPTO_FAILED;
#endif

	/*
	 * An inbound packet is of the form:
	 * [IP,options,ESP,IV,data,ICV,pad]
	 */
	esph_ptr = (esph_t *)(esp_mp->b_rptr + esph_offset);
	iv_ptr = (uchar_t *)(esph_ptr + 1);
	/* Packet length starting at IP header ending after ESP ICV. */
	msg_len = MBLKL(esp_mp);

	encr_offset = esph_offset + sizeof (esph_t) + iv_len;
	encr_len = msg_len - encr_offset;

	/*
	 * Counter mode algs need a nonce. This is setup in sadb_common_add().
	 * If for some reason we are using a SA which does not have a nonce
	 * then we must fail here.
	 */
	if ((assoc->ipsa_flags & IPSA_F_COUNTERMODE) &&
	    (assoc->ipsa_nonce == NULL)) {
		ip_drop_packet(esp_mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_esp_nomem), &espstack->esp_dropper);
		return (NULL);
	}

	if (force) {
		/* We are doing asynch; allocate mblks to hold state */
		if ((mp = ip_recv_attr_to_mblk(ira)) == NULL ||
		    (mp = ipsec_add_crypto_data(mp, &ic)) == NULL) {
			BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", esp_mp,
			    ira->ira_ill);
			return (NULL);
		}
		linkb(mp, esp_mp);
		callrp = &call_req;
		ESP_INIT_CALLREQ(callrp, mp, esp_kcf_callback_inbound);
	} else {
		/*
		 * If we know we are going to do sync then ipsec_crypto_t
		 * should be on the stack.
		 */
		ic = &icstack;
		bzero(ic, sizeof (*ic));
		callrp = NULL;
	}

	if (do_auth) {
		/* authentication context template */
		IPSEC_CTX_TMPL(assoc, ipsa_authtmpl, IPSEC_ALG_AUTH,
		    auth_ctx_tmpl);

		/* ICV to be verified */
		ESP_INIT_CRYPTO_MAC(&ic->ic_crypto_mac,
		    icv_len, esp_mp->b_wptr - icv_len);

		/* authentication starts at the ESP header */
		auth_offset = esph_offset;
		auth_len = msg_len - auth_offset - icv_len;
		if (!do_encr) {
			/* authentication only */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&ic->ic_crypto_data,
			    esp_mp, auth_offset, auth_len);

			/* call the crypto framework */
			kef_rc = crypto_mac_verify(&assoc->ipsa_amech,
			    &ic->ic_crypto_data,
			    &assoc->ipsa_kcfauthkey, auth_ctx_tmpl,
			    &ic->ic_crypto_mac, callrp);
		}
	}

	if (do_encr) {
		/* encryption template */
		IPSEC_CTX_TMPL(assoc, ipsa_encrtmpl, IPSEC_ALG_ENCR,
		    encr_ctx_tmpl);

		/* Call the nonce update function. Also passes in IV */
		(assoc->ipsa_noncefunc)(assoc, (uchar_t *)esph_ptr, encr_len,
		    iv_ptr, &ic->ic_cmm, &ic->ic_crypto_data);

		if (!do_auth) {
			/* decryption only */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&ic->ic_crypto_data,
			    esp_mp, encr_offset, encr_len);

			/* call the crypto framework */
			kef_rc = crypto_decrypt((crypto_mechanism_t *)
			    &ic->ic_cmm, &ic->ic_crypto_data,
			    &assoc->ipsa_kcfencrkey, encr_ctx_tmpl,
			    NULL, callrp);
		}
	}

	if (do_auth && do_encr) {
		/* dual operation */
		/* initialize input data argument */
		ESP_INIT_CRYPTO_DUAL_DATA(&ic->ic_crypto_dual_data,
		    esp_mp, auth_offset, auth_len,
		    encr_offset, encr_len - icv_len);

		/* specify IV */
		ic->ic_crypto_dual_data.dd_miscdata = (char *)iv_ptr;

		/* call the framework */
		kef_rc = crypto_mac_verify_decrypt(&assoc->ipsa_amech,
		    &assoc->ipsa_emech, &ic->ic_crypto_dual_data,
		    &assoc->ipsa_kcfauthkey, &assoc->ipsa_kcfencrkey,
		    auth_ctx_tmpl, encr_ctx_tmpl, &ic->ic_crypto_mac,
		    NULL, callrp);
	}

	switch (kef_rc) {
	case CRYPTO_SUCCESS:
		ESP_BUMP_STAT(espstack, crypto_sync);
		esp_mp = esp_in_done(esp_mp, ira, ic);
		if (force) {
			/* Free mp after we are done with ic */
			mp = ipsec_free_crypto_data(mp);
			(void) ip_recv_attr_free_mblk(mp);
		}
		return (esp_mp);
	case CRYPTO_QUEUED:
		/* esp_kcf_callback_inbound() will be invoked on completion */
		ESP_BUMP_STAT(espstack, crypto_async);
		return (NULL);
	case CRYPTO_INVALID_MAC:
		if (force) {
			mp = ipsec_free_crypto_data(mp);
			esp_mp = ip_recv_attr_free_mblk(mp);
		}
		ESP_BUMP_STAT(espstack, crypto_sync);
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		esp_log_bad_auth(esp_mp, ira);
		/* esp_mp was passed to ip_drop_packet */
		return (NULL);
	}

	if (force) {
		mp = ipsec_free_crypto_data(mp);
		esp_mp = ip_recv_attr_free_mblk(mp);
	}
	BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
	esp_crypto_failed(esp_mp, B_TRUE, kef_rc, ira->ira_ill, espstack);
	/* esp_mp was passed to ip_drop_packet */
	return (NULL);
}

/*
 * Compute the IP and UDP checksums -- common code for both keepalives and
 * actual ESP-in-UDP packets.  Be flexible with multiple mblks because ESP
 * uses mblk-insertion to insert the UDP header.
 * TODO - If there is an easy way to prep a packet for HW checksums, make
 * it happen here.
 * Note that this is used before both before calling ip_output_simple and
 * in the esp datapath. The former could use IXAF_SET_ULP_CKSUM but not the
 * latter.
 */
static void
esp_prepare_udp(netstack_t *ns, mblk_t *mp, ipha_t *ipha)
{
	int offset;
	uint32_t cksum;
	uint16_t *arr;
	mblk_t *udpmp = mp;
	uint_t hlen = IPH_HDR_LENGTH(ipha);

	ASSERT(MBLKL(mp) >= sizeof (ipha_t));

	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

	if (ns->netstack_udp->us_do_checksum) {
		ASSERT(MBLKL(udpmp) >= sizeof (udpha_t));
		/* arr points to the IP header. */
		arr = (uint16_t *)ipha;
		IP_STAT(ns->netstack_ip, ip_out_sw_cksum);
		IP_STAT_UPDATE(ns->netstack_ip, ip_out_sw_cksum_bytes,
		    ntohs(htons(ipha->ipha_length) - hlen));
		/* arr[6-9] are the IP addresses. */
		cksum = IP_UDP_CSUM_COMP + arr[6] + arr[7] + arr[8] + arr[9] +
		    ntohs(htons(ipha->ipha_length) - hlen);
		cksum = IP_CSUM(mp, hlen, cksum);
		offset = hlen + UDP_CHECKSUM_OFFSET;
		while (offset >= MBLKL(udpmp)) {
			offset -= MBLKL(udpmp);
			udpmp = udpmp->b_cont;
		}
		/* arr points to the UDP header's checksum field. */
		arr = (uint16_t *)(udpmp->b_rptr + offset);
		*arr = cksum;
	}
}

/*
 * taskq handler so we can send the NAT-T keepalive on a separate thread.
 */
static void
actually_send_keepalive(void *arg)
{
	mblk_t *mp = (mblk_t *)arg;
	ip_xmit_attr_t ixas;
	netstack_t	*ns;
	netstackid_t	stackid;

	stackid = (netstackid_t)(uintptr_t)mp->b_prev;
	mp->b_prev = NULL;
	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL) {
		/* Disappeared */
		ip_drop_output("ipIfStatsOutDiscards", mp, NULL);
		freemsg(mp);
		return;
	}

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_zoneid = ALL_ZONES;
	ixas.ixa_cred = kcred;
	ixas.ixa_cpid = NOPID;
	ixas.ixa_tsl = NULL;
	ixas.ixa_ipst = ns->netstack_ip;
	/* No ULP checksum; done by esp_prepare_udp */
	ixas.ixa_flags = (IXAF_IS_IPV4 | IXAF_NO_IPSEC | IXAF_VERIFY_SOURCE);

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);
	netstack_rele(ns);
}

/*
 * Send a one-byte UDP NAT-T keepalive.
 */
void
ipsecesp_send_keepalive(ipsa_t *assoc)
{
	mblk_t		*mp;
	ipha_t		*ipha;
	udpha_t		*udpha;
	netstack_t	*ns = assoc->ipsa_netstack;

	ASSERT(MUTEX_NOT_HELD(&assoc->ipsa_lock));

	mp = allocb(sizeof (ipha_t) + sizeof (udpha_t) + 1, BPRI_HI);
	if (mp == NULL)
		return;
	ipha = (ipha_t *)mp->b_rptr;
	ipha->ipha_version_and_hdr_length = IP_SIMPLE_HDR_VERSION;
	ipha->ipha_type_of_service = 0;
	ipha->ipha_length = htons(sizeof (ipha_t) + sizeof (udpha_t) + 1);
	/* Use the low-16 of the SPI so we have some clue where it came from. */
	ipha->ipha_ident = *(((uint16_t *)(&assoc->ipsa_spi)) + 1);
	ipha->ipha_fragment_offset_and_flags = 0;  /* Too small to fragment! */
	ipha->ipha_ttl = 0xFF;
	ipha->ipha_protocol = IPPROTO_UDP;
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_src = assoc->ipsa_srcaddr[0];
	ipha->ipha_dst = assoc->ipsa_dstaddr[0];
	udpha = (udpha_t *)(ipha + 1);
	udpha->uha_src_port = (assoc->ipsa_local_nat_port != 0) ?
	    assoc->ipsa_local_nat_port : htons(IPPORT_IKE_NATT);
	udpha->uha_dst_port = (assoc->ipsa_remote_nat_port != 0) ?
	    assoc->ipsa_remote_nat_port : htons(IPPORT_IKE_NATT);
	udpha->uha_length = htons(sizeof (udpha_t) + 1);
	udpha->uha_checksum = 0;
	mp->b_wptr = (uint8_t *)(udpha + 1);
	*(mp->b_wptr++) = 0xFF;

	esp_prepare_udp(ns, mp, ipha);

	/*
	 * We're holding an isaf_t bucket lock, so pawn off the actual
	 * packet transmission to another thread.  Just in case syncq
	 * processing causes a same-bucket packet to be processed.
	 */
	mp->b_prev = (mblk_t *)(uintptr_t)ns->netstack_stackid;

	if (taskq_dispatch(esp_taskq, actually_send_keepalive, mp,
	    TQ_NOSLEEP) == 0) {
		/* Assume no memory if taskq_dispatch() fails. */
		mp->b_prev = NULL;
		ip_drop_packet(mp, B_FALSE, NULL,
		    DROPPER(ns->netstack_ipsec, ipds_esp_nomem),
		    &ns->netstack_ipsecesp->esp_dropper);
	}
}

/*
 * Returns mp if successfully completed the request. Returns
 * NULL if it failed (and increments InDiscards) or if it is pending.
 */
static mblk_t *
esp_submit_req_outbound(mblk_t *data_mp, ip_xmit_attr_t *ixa, ipsa_t *assoc,
    uchar_t *icv_buf, uint_t payload_len)
{
	uint_t auth_len;
	crypto_call_req_t call_req, *callrp;
	mblk_t *esp_mp;
	esph_t *esph_ptr;
	mblk_t *mp;
	int kef_rc = CRYPTO_FAILED;
	uint_t icv_len = assoc->ipsa_mac_len;
	crypto_ctx_template_t auth_ctx_tmpl;
	boolean_t do_auth, do_encr, force;
	uint_t iv_len = assoc->ipsa_iv_len;
	crypto_ctx_template_t encr_ctx_tmpl;
	boolean_t is_natt = ((assoc->ipsa_flags & IPSA_F_NATT) != 0);
	size_t esph_offset = (is_natt ? UDPH_SIZE : 0);
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_crypto_t	*ic, icstack;
	uchar_t		*iv_ptr;
	crypto_data_t	*cd_ptr = NULL;
	ill_t		*ill = ixa->ixa_nce->nce_ill;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	esp3dbg(espstack, ("esp_submit_req_outbound:%s",
	    is_natt ? "natt" : "not natt"));

	do_encr = assoc->ipsa_encr_alg != SADB_EALG_NULL;
	do_auth = assoc->ipsa_auth_alg != SADB_AALG_NONE;
	force = (assoc->ipsa_flags & IPSA_F_ASYNC);

#ifdef IPSEC_LATENCY_TEST
	kef_rc = CRYPTO_SUCCESS;
#else
	kef_rc = CRYPTO_FAILED;
#endif

	/*
	 * Outbound IPsec packets are of the form:
	 * [IP,options] -> [ESP,IV] -> [data] -> [pad,ICV]
	 * unless it's NATT, then it's
	 * [IP,options] -> [udp][ESP,IV] -> [data] -> [pad,ICV]
	 * Get a pointer to the mblk containing the ESP header.
	 */
	ASSERT(data_mp->b_cont != NULL);
	esp_mp = data_mp->b_cont;
	esph_ptr = (esph_t *)(esp_mp->b_rptr + esph_offset);
	iv_ptr = (uchar_t *)(esph_ptr + 1);

	/*
	 * Combined mode algs need a nonce. This is setup in sadb_common_add().
	 * If for some reason we are using a SA which does not have a nonce
	 * then we must fail here.
	 */
	if ((assoc->ipsa_flags & IPSA_F_COUNTERMODE) &&
	    (assoc->ipsa_nonce == NULL)) {
		ip_drop_packet(data_mp, B_FALSE, NULL,
		    DROPPER(ipss, ipds_esp_nomem), &espstack->esp_dropper);
		return (NULL);
	}

	if (force) {
		/* We are doing asynch; allocate mblks to hold state */
		if ((mp = ip_xmit_attr_to_mblk(ixa)) == NULL ||
		    (mp = ipsec_add_crypto_data(mp, &ic)) == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", data_mp, ill);
			freemsg(data_mp);
			return (NULL);
		}

		linkb(mp, data_mp);
		callrp = &call_req;
		ESP_INIT_CALLREQ(callrp, mp, esp_kcf_callback_outbound);
	} else {
		/*
		 * If we know we are going to do sync then ipsec_crypto_t
		 * should be on the stack.
		 */
		ic = &icstack;
		bzero(ic, sizeof (*ic));
		callrp = NULL;
	}


	if (do_auth) {
		/* authentication context template */
		IPSEC_CTX_TMPL(assoc, ipsa_authtmpl, IPSEC_ALG_AUTH,
		    auth_ctx_tmpl);

		/* where to store the computed mac */
		ESP_INIT_CRYPTO_MAC(&ic->ic_crypto_mac,
		    icv_len, icv_buf);

		/* authentication starts at the ESP header */
		auth_len = payload_len + iv_len + sizeof (esph_t);
		if (!do_encr) {
			/* authentication only */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&ic->ic_crypto_data,
			    esp_mp, esph_offset, auth_len);

			/* call the crypto framework */
			kef_rc = crypto_mac(&assoc->ipsa_amech,
			    &ic->ic_crypto_data,
			    &assoc->ipsa_kcfauthkey, auth_ctx_tmpl,
			    &ic->ic_crypto_mac, callrp);
		}
	}

	if (do_encr) {
		/* encryption context template */
		IPSEC_CTX_TMPL(assoc, ipsa_encrtmpl, IPSEC_ALG_ENCR,
		    encr_ctx_tmpl);
		/* Call the nonce update function. */
		(assoc->ipsa_noncefunc)(assoc, (uchar_t *)esph_ptr, payload_len,
		    iv_ptr, &ic->ic_cmm, &ic->ic_crypto_data);

		if (!do_auth) {
			/* encryption only, skip mblk that contains ESP hdr */
			/* initialize input data argument */
			ESP_INIT_CRYPTO_DATA(&ic->ic_crypto_data,
			    esp_mp->b_cont, 0, payload_len);

			/*
			 * For combined mode ciphers, the ciphertext is the same
			 * size as the clear text, the ICV should follow the
			 * ciphertext. To convince the kcf to allow in-line
			 * encryption, with an ICV, use ipsec_out_crypto_mac
			 * to point to the same buffer as the data. The calling
			 * function need to ensure the buffer is large enough to
			 * include the ICV.
			 *
			 * The IV is already written to the packet buffer, the
			 * nonce setup function copied it to the params struct
			 * for the cipher to use.
			 */
			if (assoc->ipsa_flags & IPSA_F_COMBINED) {
				bcopy(&ic->ic_crypto_data,
				    &ic->ic_crypto_mac,
				    sizeof (crypto_data_t));
				ic->ic_crypto_mac.cd_length =
				    payload_len + icv_len;
				cd_ptr = &ic->ic_crypto_mac;
			}

			/* call the crypto framework */
			kef_rc = crypto_encrypt((crypto_mechanism_t *)
			    &ic->ic_cmm, &ic->ic_crypto_data,
			    &assoc->ipsa_kcfencrkey, encr_ctx_tmpl,
			    cd_ptr, callrp);

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
		ESP_INIT_CRYPTO_DUAL_DATA(&ic->ic_crypto_dual_data,
		    esp_mp, MBLKL(esp_mp), payload_len, esph_offset, auth_len);

		/* specify IV */
		ic->ic_crypto_dual_data.dd_miscdata = (char *)iv_ptr;

		/* call the framework */
		kef_rc = crypto_encrypt_mac(&assoc->ipsa_emech,
		    &assoc->ipsa_amech, NULL,
		    &assoc->ipsa_kcfencrkey, &assoc->ipsa_kcfauthkey,
		    encr_ctx_tmpl, auth_ctx_tmpl,
		    &ic->ic_crypto_dual_data,
		    &ic->ic_crypto_mac, callrp);
	}

	switch (kef_rc) {
	case CRYPTO_SUCCESS:
		ESP_BUMP_STAT(espstack, crypto_sync);
		esp_set_usetime(assoc, B_FALSE);
		if (force) {
			mp = ipsec_free_crypto_data(mp);
			data_mp = ip_xmit_attr_free_mblk(mp);
		}
		if (is_natt)
			esp_prepare_udp(ns, data_mp, (ipha_t *)data_mp->b_rptr);
		return (data_mp);
	case CRYPTO_QUEUED:
		/* esp_kcf_callback_outbound() will be invoked on completion */
		ESP_BUMP_STAT(espstack, crypto_async);
		return (NULL);
	}

	if (force) {
		mp = ipsec_free_crypto_data(mp);
		data_mp = ip_xmit_attr_free_mblk(mp);
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
	esp_crypto_failed(data_mp, B_FALSE, kef_rc, NULL, espstack);
	/* data_mp was passed to ip_drop_packet */
	return (NULL);
}

/*
 * Handle outbound IPsec processing for IPv4 and IPv6
 *
 * Returns data_mp if successfully completed the request. Returns
 * NULL if it failed (and increments InDiscards) or if it is pending.
 */
static mblk_t *
esp_outbound(mblk_t *data_mp, ip_xmit_attr_t *ixa)
{
	mblk_t *espmp, *tailmp;
	ipha_t *ipha;
	ip6_t *ip6h;
	esph_t *esph_ptr, *iv_ptr;
	uint_t af;
	uint8_t *nhp;
	uintptr_t divpoint, datalen, adj, padlen, i, alloclen;
	uintptr_t esplen = sizeof (esph_t);
	uint8_t protocol;
	ipsa_t *assoc;
	uint_t iv_len, block_size, mac_len = 0;
	uchar_t *icv_buf;
	udpha_t *udpha;
	boolean_t is_natt = B_FALSE;
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ill_t		*ill = ixa->ixa_nce->nce_ill;
	boolean_t	need_refrele = B_FALSE;

	ESP_BUMP_STAT(espstack, out_requests);

	/*
	 * <sigh> We have to copy the message here, because TCP (for example)
	 * keeps a dupb() of the message lying around for retransmission.
	 * Since ESP changes the whole of the datagram, we have to create our
	 * own copy lest we clobber TCP's data.  Since we have to copy anyway,
	 * we might as well make use of msgpullup() and get the mblk into one
	 * contiguous piece!
	 */
	tailmp = msgpullup(data_mp, -1);
	if (tailmp == NULL) {
		esp0dbg(("esp_outbound: msgpullup() failed, "
		    "dropping packet.\n"));
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_esp_nomem),
		    &espstack->esp_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		return (NULL);
	}
	freemsg(data_mp);
	data_mp = tailmp;

	assoc = ixa->ixa_ipsec_esp_sa;
	ASSERT(assoc != NULL);

	/*
	 * Get the outer IP header in shape to escape this system..
	 */
	if (is_system_labeled() && (assoc->ipsa_otsl != NULL)) {
		/*
		 * Need to update packet with any CIPSO option and update
		 * ixa_tsl to capture the new label.
		 * We allocate a separate ixa for that purpose.
		 */
		ixa = ip_xmit_attr_duplicate(ixa);
		if (ixa == NULL) {
			ip_drop_packet(data_mp, B_FALSE, ill,
			    DROPPER(ipss, ipds_esp_nomem),
			    &espstack->esp_dropper);
			return (NULL);
		}
		need_refrele = B_TRUE;

		label_hold(assoc->ipsa_otsl);
		ip_xmit_attr_replace_tsl(ixa, assoc->ipsa_otsl);

		data_mp = sadb_whack_label(data_mp, assoc, ixa,
		    DROPPER(ipss, ipds_esp_nomem), &espstack->esp_dropper);
		if (data_mp == NULL) {
			/* Packet dropped by sadb_whack_label */
			ixa_refrele(ixa);
			return (NULL);
		}
	}

	/*
	 * Reality check....
	 */
	ipha = (ipha_t *)data_mp->b_rptr;  /* So we can call esp_acquire(). */

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);

		af = AF_INET;
		divpoint = IPH_HDR_LENGTH(ipha);
		datalen = ntohs(ipha->ipha_length) - divpoint;
		nhp = (uint8_t *)&ipha->ipha_protocol;
	} else {
		ip_pkt_t ipp;

		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);

		af = AF_INET6;
		ip6h = (ip6_t *)ipha;
		bzero(&ipp, sizeof (ipp));
		divpoint = ip_find_hdr_v6(data_mp, ip6h, B_FALSE, &ipp, NULL);
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

	mac_len = assoc->ipsa_mac_len;

	if (assoc->ipsa_flags & IPSA_F_NATT) {
		/* wedge in UDP header */
		is_natt = B_TRUE;
		esplen += UDPH_SIZE;
	}

	/*
	 * Set up ESP header and encryption padding for ENCR PI request.
	 */

	/* Determine the padding length.  Pad to 4-bytes for no-encryption. */
	if (assoc->ipsa_encr_alg != SADB_EALG_NULL) {
		iv_len = assoc->ipsa_iv_len;
		block_size = assoc->ipsa_datalen;

		/*
		 * Pad the data to the length of the cipher block size.
		 * Include the two additional bytes (hence the - 2) for the
		 * padding length and the next header.  Take this into account
		 * when calculating the actual length of the padding.
		 */
		ASSERT(ISP2(iv_len));
		padlen = ((unsigned)(block_size - datalen - 2)) &
		    (block_size - 1);
	} else {
		iv_len = 0;
		padlen = ((unsigned)(sizeof (uint32_t) - datalen - 2)) &
		    (sizeof (uint32_t) - 1);
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
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_esp_bytes_expire),
		    &espstack->esp_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		if (need_refrele)
			ixa_refrele(ixa);
		return (NULL);
	}

	espmp = allocb(esplen, BPRI_HI);
	if (espmp == NULL) {
		ESP_BUMP_STAT(espstack, out_discards);
		esp1dbg(espstack, ("esp_outbound: can't allocate espmp.\n"));
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_esp_nomem),
		    &espstack->esp_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		if (need_refrele)
			ixa_refrele(ixa);
		return (NULL);
	}
	espmp->b_wptr += esplen;
	esph_ptr = (esph_t *)espmp->b_rptr;

	if (is_natt) {
		esp3dbg(espstack, ("esp_outbound: NATT"));

		udpha = (udpha_t *)espmp->b_rptr;
		udpha->uha_src_port = (assoc->ipsa_local_nat_port != 0) ?
		    assoc->ipsa_local_nat_port : htons(IPPORT_IKE_NATT);
		udpha->uha_dst_port = (assoc->ipsa_remote_nat_port != 0) ?
		    assoc->ipsa_remote_nat_port : htons(IPPORT_IKE_NATT);
		/*
		 * Set the checksum to 0, so that the esp_prepare_udp() call
		 * can do the right thing.
		 */
		udpha->uha_checksum = 0;
		esph_ptr = (esph_t *)(udpha + 1);
	}

	esph_ptr->esph_spi = assoc->ipsa_spi;

	esph_ptr->esph_replay = htonl(atomic_inc_32_nv(&assoc->ipsa_replay));
	if (esph_ptr->esph_replay == 0 && assoc->ipsa_replay_wsize != 0) {
		/*
		 * XXX We have replay counter wrapping.
		 * We probably want to nuke this SA (and its peer).
		 */
		ipsec_assocfailure(info.mi_idnum, 0, 0,
		    SL_ERROR | SL_CONSOLE | SL_WARN,
		    "Outbound ESP SA (0x%x, %s) has wrapped sequence.\n",
		    esph_ptr->esph_spi, assoc->ipsa_dstaddr, af,
		    espstack->ipsecesp_netstack);

		ESP_BUMP_STAT(espstack, out_discards);
		sadb_replay_delete(assoc);
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_esp_replay),
		    &espstack->esp_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		if (need_refrele)
			ixa_refrele(ixa);
		return (NULL);
	}

	iv_ptr = (esph_ptr + 1);
	/*
	 * iv_ptr points to the mblk which will contain the IV once we have
	 * written it there. This mblk will be part of a mblk chain that
	 * will make up the packet.
	 *
	 * For counter mode algorithms, the IV is a 64 bit quantity, it
	 * must NEVER repeat in the lifetime of the SA, otherwise an
	 * attacker who had recorded enough packets might be able to
	 * determine some clear text.
	 *
	 * To ensure this does not happen, the IV is stored in the SA and
	 * incremented for each packet, the IV is then copied into the
	 * "packet" for transmission to the receiving system. The IV will
	 * also be copied into the nonce, when the packet is encrypted.
	 *
	 * CBC mode algorithms use a random IV for each packet. We do not
	 * require the highest quality random bits, but for best security
	 * with CBC mode ciphers, the value must be unlikely to repeat and
	 * must not be known in advance to an adversary capable of influencing
	 * the clear text.
	 */
	if (!update_iv((uint8_t *)iv_ptr, espstack->esp_pfkey_q, assoc,
	    espstack)) {
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_esp_iv_wrap), &espstack->esp_dropper);
		if (need_refrele)
			ixa_refrele(ixa);
		return (NULL);
	}

	/* Fix the IP header. */
	alloclen = padlen + 2 + mac_len;
	adj = alloclen + (espmp->b_wptr - espmp->b_rptr);

	protocol = *nhp;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
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

	esp2dbg(espstack, ("data_mp before outbound ESP adjustment:\n"));
	esp2dbg(espstack, (dump_msg(data_mp)));

	if (!esp_insert_esp(data_mp, espmp, divpoint, espstack)) {
		ESP_BUMP_STAT(espstack, out_discards);
		/* NOTE:  esp_insert_esp() only fails if there's no memory. */
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_esp_nomem),
		    &espstack->esp_dropper);
		freeb(espmp);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		if (need_refrele)
			ixa_refrele(ixa);
		return (NULL);
	}

	/* Append padding (and leave room for ICV). */
	for (tailmp = data_mp; tailmp->b_cont != NULL; tailmp = tailmp->b_cont)
		;
	if (tailmp->b_wptr + alloclen > tailmp->b_datap->db_lim) {
		tailmp->b_cont = allocb(alloclen, BPRI_HI);
		if (tailmp->b_cont == NULL) {
			ESP_BUMP_STAT(espstack, out_discards);
			esp0dbg(("esp_outbound:  Can't allocate tailmp.\n"));
			ip_drop_packet(data_mp, B_FALSE, ill,
			    DROPPER(ipss, ipds_esp_nomem),
			    &espstack->esp_dropper);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			if (need_refrele)
				ixa_refrele(ixa);
			return (NULL);
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

	esp2dbg(espstack, ("data_Mp before encryption:\n"));
	esp2dbg(espstack, (dump_msg(data_mp)));

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

	data_mp = esp_submit_req_outbound(data_mp, ixa, assoc, icv_buf,
	    datalen + padlen + 2);
	if (need_refrele)
		ixa_refrele(ixa);
	return (data_mp);
}

/*
 * IP calls this to validate the ICMP errors that
 * we got from the network.
 */
mblk_t *
ipsecesp_icmp_error(mblk_t *data_mp, ip_recv_attr_t *ira)
{
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

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
	IP_ESP_BUMP_STAT(ipss, in_discards);
	ip_drop_packet(data_mp, B_TRUE, ira->ira_ill,
	    DROPPER(ipss, ipds_esp_icmp),
	    &espstack->esp_dropper);
	return (NULL);
}

/*
 * Construct an SADB_REGISTER message with the current algorithms.
 * This function gets called when 'ipsecalgs -s' is run or when
 * in.iked (or other KMD) starts.
 */
static boolean_t
esp_register_out(uint32_t sequence, uint32_t pid, uint_t serial,
    ipsecesp_stack_t *espstack, cred_t *cr)
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
	ipsec_stack_t	*ipss = espstack->ipsecesp_netstack->netstack_ipsec;
	sadb_sens_t *sens;
	size_t sens_len = 0;
	sadb_ext_t *nextext;
	ts_label_t *sens_tsl = NULL;

	/* Allocate the KEYSOCK_OUT. */
	keysock_out_mp = sadb_keysock_out(serial);
	if (keysock_out_mp == NULL) {
		esp0dbg(("esp_register_out: couldn't allocate mblk.\n"));
		return (B_FALSE);
	}

	if (is_system_labeled() && (cr != NULL)) {
		sens_tsl = crgetlabel(cr);
		if (sens_tsl != NULL) {
			sens_len = sadb_sens_len_from_label(sens_tsl);
			allocsize += sens_len;
		}
	}

	/*
	 * Allocate the PF_KEY message that follows KEYSOCK_OUT.
	 */

	rw_enter(&ipss->ipsec_alg_lock, RW_READER);
	/*
	 * Fill SADB_REGISTER message's algorithm descriptors.  Hold
	 * down the lock while filling it.
	 *
	 * Return only valid algorithms, so the number of algorithms
	 * to send up may be less than the number of algorithm entries
	 * in the table.
	 */
	authalgs = ipss->ipsec_alglists[IPSEC_ALG_AUTH];
	for (num_aalgs = 0, i = 0; i < IPSEC_MAX_ALGS; i++)
		if (authalgs[i] != NULL && ALG_VALID(authalgs[i]))
			num_aalgs++;

	if (num_aalgs != 0) {
		allocsize += (num_aalgs * sizeof (*saalg));
		allocsize += sizeof (*sasupp_auth);
	}
	encralgs = ipss->ipsec_alglists[IPSEC_ALG_ENCR];
	for (num_ealgs = 0, i = 0; i < IPSEC_MAX_ALGS; i++)
		if (encralgs[i] != NULL && ALG_VALID(encralgs[i]))
			num_ealgs++;

	if (num_ealgs != 0) {
		allocsize += (num_ealgs * sizeof (*saalg));
		allocsize += sizeof (*sasupp_encr);
	}
	keysock_out_mp->b_cont = allocb(allocsize, BPRI_HI);
	if (keysock_out_mp->b_cont == NULL) {
		rw_exit(&ipss->ipsec_alg_lock);
		freemsg(keysock_out_mp);
		return (B_FALSE);
	}
	pfkey_msg_mp = keysock_out_mp->b_cont;
	pfkey_msg_mp->b_wptr += allocsize;

	nextext = (sadb_ext_t *)(pfkey_msg_mp->b_rptr + sizeof (*samsg));

	if (num_aalgs != 0) {
		sasupp_auth = (sadb_supported_t *)nextext;
		saalg = (sadb_alg_t *)(sasupp_auth + 1);

		ASSERT(((ulong_t)saalg & 0x7) == 0);

		numalgs_snap = 0;
		for (i = 0;
		    ((i < IPSEC_MAX_ALGS) && (numalgs_snap < num_aalgs));
		    i++) {
			if (authalgs[i] == NULL || !ALG_VALID(authalgs[i]))
				continue;

			saalg->sadb_alg_id = authalgs[i]->alg_id;
			saalg->sadb_alg_ivlen = 0;
			saalg->sadb_alg_minbits	= authalgs[i]->alg_ef_minbits;
			saalg->sadb_alg_maxbits	= authalgs[i]->alg_ef_maxbits;
			saalg->sadb_x_alg_increment =
			    authalgs[i]->alg_increment;
			saalg->sadb_x_alg_saltbits = SADB_8TO1(
			    authalgs[i]->alg_saltlen);
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
		nextext = (sadb_ext_t *)saalg;
	}

	if (num_ealgs != 0) {
		sasupp_encr = (sadb_supported_t *)nextext;
		saalg = (sadb_alg_t *)(sasupp_encr + 1);

		numalgs_snap = 0;
		for (i = 0;
		    ((i < IPSEC_MAX_ALGS) && (numalgs_snap < num_ealgs)); i++) {
			if (encralgs[i] == NULL || !ALG_VALID(encralgs[i]))
				continue;
			saalg->sadb_alg_id = encralgs[i]->alg_id;
			saalg->sadb_alg_ivlen = encralgs[i]->alg_ivlen;
			saalg->sadb_alg_minbits	= encralgs[i]->alg_ef_minbits;
			saalg->sadb_alg_maxbits	= encralgs[i]->alg_ef_maxbits;
			/*
			 * We could advertise the ICV length, except there
			 * is not a value in sadb_x_algb to do this.
			 * saalg->sadb_alg_maclen = encralgs[i]->alg_maclen;
			 */
			saalg->sadb_x_alg_increment =
			    encralgs[i]->alg_increment;
			saalg->sadb_x_alg_saltbits =
			    SADB_8TO1(encralgs[i]->alg_saltlen);

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
		nextext = (sadb_ext_t *)saalg;
	}

	current_aalgs = num_aalgs;
	current_ealgs = num_ealgs;

	rw_exit(&ipss->ipsec_alg_lock);

	if (sens_tsl != NULL) {
		sens = (sadb_sens_t *)nextext;
		sadb_sens_from_label(sens, SADB_EXT_SENSITIVITY,
		    sens_tsl, sens_len);

		nextext = (sadb_ext_t *)(((uint8_t *)sens) + sens_len);
	}

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
		sasupp_auth->sadb_supported_len = SADB_8TO64(
		    sizeof (*sasupp_auth) + sizeof (*saalg) * current_aalgs);
		sasupp_auth->sadb_supported_exttype = SADB_EXT_SUPPORTED_AUTH;
		sasupp_auth->sadb_supported_reserved = 0;
	}

	if (sasupp_encr != NULL) {
		sasupp_encr->sadb_supported_len = SADB_8TO64(
		    sizeof (*sasupp_encr) + sizeof (*saalg) * current_ealgs);
		sasupp_encr->sadb_supported_exttype =
		    SADB_EXT_SUPPORTED_ENCRYPT;
		sasupp_encr->sadb_supported_reserved = 0;
	}

	if (espstack->esp_pfkey_q != NULL)
		putnext(espstack->esp_pfkey_q, keysock_out_mp);
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
ipsecesp_algs_changed(netstack_t *ns)
{
	ipsecesp_stack_t	*espstack = ns->netstack_ipsecesp;

	/*
	 * Time to send a PF_KEY SADB_REGISTER message to ESP listeners
	 * everywhere.  (The function itself checks for NULL esp_pfkey_q.)
	 */
	(void) esp_register_out(0, 0, 0, espstack, NULL);
}

/*
 * Stub function that taskq_dispatch() invokes to take the mblk (in arg)
 * and send() it into ESP and IP again.
 */
static void
inbound_task(void *arg)
{
	mblk_t		*mp = (mblk_t *)arg;
	mblk_t		*async_mp;
	ip_recv_attr_t	iras;

	async_mp = mp;
	mp = async_mp->b_cont;
	async_mp->b_cont = NULL;
	if (!ip_recv_attr_from_mblk(async_mp, &iras)) {
		/* The ill or ip_stack_t disappeared on us */
		ip_drop_input("ip_recv_attr_from_mblk", mp, NULL);
		freemsg(mp);
		goto done;
	}

	esp_inbound_restart(mp, &iras);
done:
	ira_cleanup(&iras, B_TRUE);
}

/*
 * Restart ESP after the SA has been added.
 */
static void
esp_inbound_restart(mblk_t *mp, ip_recv_attr_t *ira)
{
	esph_t		*esph;
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;

	esp2dbg(espstack, ("in ESP inbound_task"));
	ASSERT(espstack != NULL);

	mp = ipsec_inbound_esp_sa(mp, ira, &esph);
	if (mp == NULL)
		return;

	ASSERT(esph != NULL);
	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
	ASSERT(ira->ira_ipsec_esp_sa != NULL);

	mp = ira->ira_ipsec_esp_sa->ipsa_input_func(mp, esph, ira);
	if (mp == NULL) {
		/*
		 * Either it failed or is pending. In the former case
		 * ipIfStatsInDiscards was increased.
		 */
		return;
	}

	ip_input_post_ipsec(mp, ira);
}

/*
 * Now that weak-key passed, actually ADD the security association, and
 * send back a reply ADD message.
 */
static int
esp_add_sa_finish(mblk_t *mp, sadb_msg_t *samsg, keysock_in_t *ksi,
    int *diagnostic, ipsecesp_stack_t *espstack)
{
	isaf_t *primary = NULL, *secondary;
	boolean_t clone = B_FALSE, is_inbound = B_FALSE;
	ipsa_t *larval = NULL;
	ipsacq_t *acqrec;
	iacqf_t *acq_bucket;
	mblk_t *acq_msgs = NULL;
	int rc;
	mblk_t *lpkt;
	int error;
	ipsa_query_t sq;
	ipsec_stack_t	*ipss = espstack->ipsecesp_netstack->netstack_ipsec;

	/*
	 * Locate the appropriate table(s).
	 */
	sq.spp = &espstack->esp_sadb;	/* XXX */
	error = sadb_form_query(ksi, IPSA_Q_SA|IPSA_Q_DST,
	    IPSA_Q_SA|IPSA_Q_DST|IPSA_Q_INBOUND|IPSA_Q_OUTBOUND,
	    &sq, diagnostic);
	if (error)
		return (error);

	/*
	 * Use the direction flags provided by the KMD to determine
	 * if the inbound or outbound table should be the primary
	 * for this SA. If these flags were absent then make this
	 * decision based on the addresses.
	 */
	if (sq.assoc->sadb_sa_flags & IPSA_F_INBOUND) {
		primary = sq.inbound;
		secondary = sq.outbound;
		is_inbound = B_TRUE;
		if (sq.assoc->sadb_sa_flags & IPSA_F_OUTBOUND)
			clone = B_TRUE;
	} else if (sq.assoc->sadb_sa_flags & IPSA_F_OUTBOUND) {
		primary = sq.outbound;
		secondary = sq.inbound;
	}

	if (primary == NULL) {
		/*
		 * The KMD did not set a direction flag, determine which
		 * table to insert the SA into based on addresses.
		 */
		switch (ksi->ks_in_dsttype) {
		case KS_IN_ADDR_MBCAST:
			clone = B_TRUE;	/* All mcast SAs can be bidirectional */
			sq.assoc->sadb_sa_flags |= IPSA_F_OUTBOUND;
			/* FALLTHRU */
		/*
		 * If the source address is either one of mine, or unspecified
		 * (which is best summed up by saying "not 'not mine'"),
		 * then the association is potentially bi-directional,
		 * in that it can be used for inbound traffic and outbound
		 * traffic.  The best example of such an SA is a multicast
		 * SA (which allows me to receive the outbound traffic).
		 */
		case KS_IN_ADDR_ME:
			sq.assoc->sadb_sa_flags |= IPSA_F_INBOUND;
			primary = sq.inbound;
			secondary = sq.outbound;
			if (ksi->ks_in_srctype != KS_IN_ADDR_NOTME)
				clone = B_TRUE;
			is_inbound = B_TRUE;
			break;
		/*
		 * If the source address literally not mine (either
		 * unspecified or not mine), then this SA may have an
		 * address that WILL be mine after some configuration.
		 * We pay the price for this by making it a bi-directional
		 * SA.
		 */
		case KS_IN_ADDR_NOTME:
			sq.assoc->sadb_sa_flags |= IPSA_F_OUTBOUND;
			primary = sq.outbound;
			secondary = sq.inbound;
			if (ksi->ks_in_srctype != KS_IN_ADDR_ME) {
				sq.assoc->sadb_sa_flags |= IPSA_F_INBOUND;
				clone = B_TRUE;
			}
			break;
		default:
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_DST;
			return (EINVAL);
		}
	}

	/*
	 * Find a ACQUIRE list entry if possible.  If we've added an SA that
	 * suits the needs of an ACQUIRE list entry, we can eliminate the
	 * ACQUIRE list entry and transmit the enqueued packets.  Use the
	 * high-bit of the sequence number to queue it.  Key off destination
	 * addr, and change acqrec's state.
	 */

	if (samsg->sadb_msg_seq & IACQF_LOWEST_SEQ) {
		acq_bucket = &(sq.sp->sdb_acq[sq.outhash]);
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
			    IPSA_ARE_ADDR_EQUAL(sq.dstaddr,
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
			sadb_destroy_acquire(acqrec,
			    espstack->ipsecesp_netstack);
		}
		mutex_exit(&acq_bucket->iacqf_lock);
	}

	/*
	 * Find PF_KEY message, and see if I'm an update.  If so, find entry
	 * in larval list (if there).
	 */
	if (samsg->sadb_msg_type == SADB_UPDATE) {
		mutex_enter(&sq.inbound->isaf_lock);
		larval = ipsec_getassocbyspi(sq.inbound, sq.assoc->sadb_sa_spi,
		    ALL_ZEROES_PTR, sq.dstaddr, sq.dst->sin_family);
		mutex_exit(&sq.inbound->isaf_lock);

		if ((larval == NULL) ||
		    (larval->ipsa_state != IPSA_STATE_LARVAL)) {
			*diagnostic = SADB_X_DIAGNOSTIC_SA_NOTFOUND;
			if (larval != NULL) {
				IPSA_REFRELE(larval);
			}
			esp0dbg(("Larval update, but larval disappeared.\n"));
			return (ESRCH);
		} /* Else sadb_common_add unlinks it for me! */
	}

	if (larval != NULL) {
		/*
		 * Hold again, because sadb_common_add() consumes a reference,
		 * and we don't want to clear_lpkt() without a reference.
		 */
		IPSA_REFHOLD(larval);
	}

	rc = sadb_common_add(espstack->esp_pfkey_q,
	    mp, samsg, ksi, primary, secondary, larval, clone, is_inbound,
	    diagnostic, espstack->ipsecesp_netstack, &espstack->esp_sadb);

	if (larval != NULL) {
		if (rc == 0) {
			lpkt = sadb_clear_lpkt(larval);
			if (lpkt != NULL) {
				rc = !taskq_dispatch(esp_taskq, inbound_task,
				    lpkt, TQ_NOSLEEP);
			}
		}
		IPSA_REFRELE(larval);
	}

	/*
	 * How much more stack will I create with all of these
	 * esp_outbound() calls?
	 */

	/* Handle the packets queued waiting for the SA */
	while (acq_msgs != NULL) {
		mblk_t		*asyncmp;
		mblk_t		*data_mp;
		ip_xmit_attr_t	ixas;
		ill_t		*ill;

		asyncmp = acq_msgs;
		acq_msgs = acq_msgs->b_next;
		asyncmp->b_next = NULL;

		/*
		 * Extract the ip_xmit_attr_t from the first mblk.
		 * Verifies that the netstack and ill is still around; could
		 * have vanished while iked was doing its work.
		 * On succesful return we have a nce_t and the ill/ipst can't
		 * disappear until we do the nce_refrele in ixa_cleanup.
		 */
		data_mp = asyncmp->b_cont;
		asyncmp->b_cont = NULL;
		if (!ip_xmit_attr_from_mblk(asyncmp, &ixas)) {
			ESP_BUMP_STAT(espstack, out_discards);
			ip_drop_packet(data_mp, B_FALSE, NULL,
			    DROPPER(ipss, ipds_sadb_acquire_timeout),
			    &espstack->esp_dropper);
		} else if (rc != 0) {
			ill = ixas.ixa_nce->nce_ill;
			ESP_BUMP_STAT(espstack, out_discards);
			ip_drop_packet(data_mp, B_FALSE, ill,
			    DROPPER(ipss, ipds_sadb_acquire_timeout),
			    &espstack->esp_dropper);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		} else {
			esp_outbound_finish(data_mp, &ixas);
		}
		ixa_cleanup(&ixas);
	}

	return (rc);
}

/*
 * Process one of the queued messages (from ipsacq_mp) once the SA
 * has been added.
 */
static void
esp_outbound_finish(mblk_t *data_mp, ip_xmit_attr_t *ixa)
{
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ill_t		*ill = ixa->ixa_nce->nce_ill;

	if (!ipsec_outbound_sa(data_mp, ixa, IPPROTO_ESP)) {
		ESP_BUMP_STAT(espstack, out_discards);
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_sadb_acquire_timeout),
		    &espstack->esp_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		return;
	}

	data_mp = esp_outbound(data_mp, ixa);
	if (data_mp == NULL)
		return;

	/* do AH processing if needed */
	data_mp = esp_do_outbound_ah(data_mp, ixa);
	if (data_mp == NULL)
		return;

	(void) ip_output_post_ipsec(data_mp, ixa);
}

/*
 * Add new ESP security association.  This may become a generic AH/ESP
 * routine eventually.
 */
static int
esp_add_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic, netstack_t *ns)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_address_t *isrcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_INNER_SRC];
	sadb_address_t *idstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_X_EXT_ADDRESS_INNER_DST];
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
	sadb_lifetime_t *idle =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_X_EXT_LIFETIME_IDLE];
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;



	/* I need certain extensions present for an ADD message. */
	if (srcext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SRC;
		return (EINVAL);
	}
	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}
	if (isrcext == NULL && idstext != NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_INNER_SRC;
		return (EINVAL);
	}
	if (isrcext != NULL && idstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_INNER_DST;
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

	if ((assoc->sadb_sa_state != SADB_SASTATE_MATURE) &&
	    (assoc->sadb_sa_state != SADB_X_SASTATE_ACTIVE_ELSEWHERE)) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
		return (EINVAL);
	}
	if (assoc->sadb_sa_encrypt == SADB_EALG_NONE) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_EALG;
		return (EINVAL);
	}

#ifndef IPSEC_LATENCY_TEST
	if (assoc->sadb_sa_encrypt == SADB_EALG_NULL &&
	    assoc->sadb_sa_auth == SADB_AALG_NONE) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_AALG;
		return (EINVAL);
	}
#endif

	if (assoc->sadb_sa_flags & ~espstack->esp_sadb.s_addflags) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SAFLAGS;
		return (EINVAL);
	}

	if ((*diagnostic = sadb_hardsoftchk(hard, soft, idle)) != 0) {
		return (EINVAL);
	}
	ASSERT(src->sin_family == dst->sin_family);

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
	if (ksi->ks_in_extv[SADB_EXT_LIFETIME_CURRENT] != NULL)
		return (EOPNOTSUPP);

	if ((*diagnostic = sadb_labelchk(ksi)) != 0)
		return (EINVAL);

	/*
	 * XXX Policy :  I'm not checking identities at this time,
	 * but if I did, I'd do them here, before I sent
	 * the weak key check up to the algorithm.
	 */

	rw_enter(&ipss->ipsec_alg_lock, RW_READER);

	/*
	 * First locate the authentication algorithm.
	 */
#ifdef IPSEC_LATENCY_TEST
	if (akey != NULL && assoc->sadb_sa_auth != SADB_AALG_NONE) {
#else
	if (akey != NULL) {
#endif
		ipsec_alginfo_t *aalg;

		aalg = ipss->ipsec_alglists[IPSEC_ALG_AUTH]
		    [assoc->sadb_sa_auth];
		if (aalg == NULL || !ALG_VALID(aalg)) {
			rw_exit(&ipss->ipsec_alg_lock);
			esp1dbg(espstack, ("Couldn't find auth alg #%d.\n",
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
			rw_exit(&ipss->ipsec_alg_lock);
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_AKEYBITS;
			return (EINVAL);
		}
		ASSERT(aalg->alg_mech_type != CRYPTO_MECHANISM_INVALID);

		/* check key and fix parity if needed */
		if (ipsec_check_key(aalg->alg_mech_type, akey, B_TRUE,
		    diagnostic) != 0) {
			rw_exit(&ipss->ipsec_alg_lock);
			return (EINVAL);
		}
	}

	/*
	 * Then locate the encryption algorithm.
	 */
	if (ekey != NULL) {
		uint_t keybits;
		ipsec_alginfo_t *ealg;

		ealg = ipss->ipsec_alglists[IPSEC_ALG_ENCR]
		    [assoc->sadb_sa_encrypt];
		if (ealg == NULL || !ALG_VALID(ealg)) {
			rw_exit(&ipss->ipsec_alg_lock);
			esp1dbg(espstack, ("Couldn't find encr alg #%d.\n",
			    assoc->sadb_sa_encrypt));
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_EALG;
			return (EINVAL);
		}

		/*
		 * Sanity check key sizes. If the encryption algorithm is
		 * SADB_EALG_NULL but the encryption key is NOT
		 * NULL then complain.
		 *
		 * The keying material includes salt bits if required by
		 * algorithm and optionally the Initial IV, check the
		 * length of whats left.
		 */
		keybits = ekey->sadb_key_bits;
		keybits -= ekey->sadb_key_reserved;
		keybits -= SADB_8TO1(ealg->alg_saltlen);
		if ((assoc->sadb_sa_encrypt == SADB_EALG_NULL) ||
		    (!ipsec_valid_key_size(keybits, ealg))) {
			rw_exit(&ipss->ipsec_alg_lock);
			*diagnostic = SADB_X_DIAGNOSTIC_BAD_EKEYBITS;
			return (EINVAL);
		}
		ASSERT(ealg->alg_mech_type != CRYPTO_MECHANISM_INVALID);

		/* check key */
		if (ipsec_check_key(ealg->alg_mech_type, ekey, B_FALSE,
		    diagnostic) != 0) {
			rw_exit(&ipss->ipsec_alg_lock);
			return (EINVAL);
		}
	}
	rw_exit(&ipss->ipsec_alg_lock);

	return (esp_add_sa_finish(mp, (sadb_msg_t *)mp->b_cont->b_rptr, ksi,
	    diagnostic, espstack));
}

/*
 * Update a security association.  Updates come in two varieties.  The first
 * is an update of lifetimes on a non-larval SA.  The second is an update of
 * a larval SA, which ends up looking a lot more like an add.
 */
static int
esp_update_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic,
    ipsecesp_stack_t *espstack, uint8_t sadb_msg_type)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	mblk_t    *buf_pkt;
	int rcode;

	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];

	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}

	rcode = sadb_update_sa(mp, ksi, &buf_pkt, &espstack->esp_sadb,
	    diagnostic, espstack->esp_pfkey_q, esp_add_sa,
	    espstack->ipsecesp_netstack, sadb_msg_type);

	if ((assoc->sadb_sa_state != SADB_X_SASTATE_ACTIVE) ||
	    (rcode != 0)) {
		return (rcode);
	}

	HANDLE_BUF_PKT(esp_taskq, espstack->ipsecesp_netstack->netstack_ipsec,
	    espstack->esp_dropper, buf_pkt);

	return (rcode);
}

/* XXX refactor me */
/*
 * Delete a security association.  This is REALLY likely to be code common to
 * both AH and ESP.  Find the association, then unlink it.
 */
static int
esp_del_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic,
    ipsecesp_stack_t *espstack, uint8_t sadb_msg_type)
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
		return (sadb_purge_sa(mp, ksi,
		    (sin->sin_family == AF_INET6) ? &espstack->esp_sadb.s_v6 :
		    &espstack->esp_sadb.s_v4, diagnostic,
		    espstack->esp_pfkey_q));
	}

	return (sadb_delget_sa(mp, ksi, &espstack->esp_sadb, diagnostic,
	    espstack->esp_pfkey_q, sadb_msg_type));
}

/* XXX refactor me */
/*
 * Convert the entire contents of all of ESP's SA tables into PF_KEY SADB_DUMP
 * messages.
 */
static void
esp_dump(mblk_t *mp, keysock_in_t *ksi, ipsecesp_stack_t *espstack)
{
	int error;
	sadb_msg_t *samsg;

	/*
	 * Dump each fanout, bailing if error is non-zero.
	 */

	error = sadb_dump(espstack->esp_pfkey_q, mp, ksi,
	    &espstack->esp_sadb.s_v4);
	if (error != 0)
		goto bail;

	error = sadb_dump(espstack->esp_pfkey_q, mp, ksi,
	    &espstack->esp_sadb.s_v6);
bail:
	ASSERT(mp->b_cont != NULL);
	samsg = (sadb_msg_t *)mp->b_cont->b_rptr;
	samsg->sadb_msg_errno = (uint8_t)error;
	sadb_pfkey_echo(espstack->esp_pfkey_q, mp,
	    (sadb_msg_t *)mp->b_cont->b_rptr, ksi, NULL);
}

/*
 * First-cut reality check for an inbound PF_KEY message.
 */
static boolean_t
esp_pfkey_reality_failures(mblk_t *mp, keysock_in_t *ksi,
    ipsecesp_stack_t *espstack)
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
	return (B_FALSE);	/* False ==> no failures */

badmsg:
	sadb_pfkey_error(espstack->esp_pfkey_q, mp, EINVAL, diagnostic,
	    ksi->ks_in_serial);
	return (B_TRUE);	/* True ==> failures */
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
esp_parse_pfkey(mblk_t *mp, ipsecesp_stack_t *espstack)
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
	 * AF_INET.  And do other address reality checks.
	 */
	if (!sadb_addrfix(ksi, espstack->esp_pfkey_q, mp,
	    espstack->ipsecesp_netstack) ||
	    esp_pfkey_reality_failures(mp, ksi, espstack)) {
		return;
	}

	switch (samsg->sadb_msg_type) {
	case SADB_ADD:
		error = esp_add_sa(mp, ksi, &diagnostic,
		    espstack->ipsecesp_netstack);
		if (error != 0) {
			sadb_pfkey_error(espstack->esp_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* else esp_add_sa() took care of things. */
		break;
	case SADB_DELETE:
	case SADB_X_DELPAIR:
	case SADB_X_DELPAIR_STATE:
		error = esp_del_sa(mp, ksi, &diagnostic, espstack,
		    samsg->sadb_msg_type);
		if (error != 0) {
			sadb_pfkey_error(espstack->esp_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* Else esp_del_sa() took care of things. */
		break;
	case SADB_GET:
		error = sadb_delget_sa(mp, ksi, &espstack->esp_sadb,
		    &diagnostic, espstack->esp_pfkey_q, samsg->sadb_msg_type);
		if (error != 0) {
			sadb_pfkey_error(espstack->esp_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* Else sadb_get_sa() took care of things. */
		break;
	case SADB_FLUSH:
		sadbp_flush(&espstack->esp_sadb, espstack->ipsecesp_netstack);
		sadb_pfkey_echo(espstack->esp_pfkey_q, mp, samsg, ksi, NULL);
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
		    ksi->ks_in_serial, espstack, msg_getcred(mp, NULL))) {
			freemsg(mp);
		} else {
			/*
			 * Only way this path hits is if there is a memory
			 * failure.  It will not return B_FALSE because of
			 * lack of esp_pfkey_q if I am in wput().
			 */
			sadb_pfkey_error(espstack->esp_pfkey_q, mp, ENOMEM,
			    diagnostic, ksi->ks_in_serial);
		}
		break;
	case SADB_UPDATE:
	case SADB_X_UPDATEPAIR:
		/*
		 * Find a larval, if not there, find a full one and get
		 * strict.
		 */
		error = esp_update_sa(mp, ksi, &diagnostic, espstack,
		    samsg->sadb_msg_type);
		if (error != 0) {
			sadb_pfkey_error(espstack->esp_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* else esp_update_sa() took care of things. */
		break;
	case SADB_GETSPI:
		/*
		 * Reserve a new larval entry.
		 */
		esp_getspi(mp, ksi, espstack);
		break;
	case SADB_ACQUIRE:
		/*
		 * Find larval and/or ACQUIRE record and kill it (them), I'm
		 * most likely an error.  Inbound ACQUIRE messages should only
		 * have the base header.
		 */
		sadb_in_acquire(samsg, &espstack->esp_sadb,
		    espstack->esp_pfkey_q, espstack->ipsecesp_netstack);
		freemsg(mp);
		break;
	case SADB_DUMP:
		/*
		 * Dump all entries.
		 */
		esp_dump(mp, ksi, espstack);
		/* esp_dump will take care of the return message, etc. */
		break;
	case SADB_EXPIRE:
		/* Should never reach me. */
		sadb_pfkey_error(espstack->esp_pfkey_q, mp, EOPNOTSUPP,
		    diagnostic, ksi->ks_in_serial);
		break;
	default:
		sadb_pfkey_error(espstack->esp_pfkey_q, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_UNKNOWN_MSG, ksi->ks_in_serial);
		break;
	}
}

/*
 * Handle case where PF_KEY says it can't find a keysock for one of my
 * ACQUIRE messages.
 */
static void
esp_keysock_no_socket(mblk_t *mp, ipsecesp_stack_t *espstack)
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
		 * Use the write-side of the esp_pfkey_q
		 */
		sadb_in_acquire(samsg, &espstack->esp_sadb,
		    WR(espstack->esp_pfkey_q), espstack->ipsecesp_netstack);
	}

	freemsg(mp);
}

/*
 * ESP module write put routine.
 */
static void
ipsecesp_wput(queue_t *q, mblk_t *mp)
{
	ipsec_info_t *ii;
	struct iocblk *iocp;
	ipsecesp_stack_t	*espstack = (ipsecesp_stack_t *)q->q_ptr;

	esp3dbg(espstack, ("In esp_wput().\n"));

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
			esp1dbg(espstack, ("Got KEYSOCK_OUT_ERR message.\n"));
			esp_keysock_no_socket(mp, espstack);
			break;
		case KEYSOCK_IN:
			ESP_BUMP_STAT(espstack, keysock_in);
			esp3dbg(espstack, ("Got KEYSOCK_IN message.\n"));

			/* Parse the message. */
			esp_parse_pfkey(mp, espstack);
			break;
		case KEYSOCK_HELLO:
			sadb_keysock_hello(&espstack->esp_pfkey_q, q, mp,
			    esp_ager, (void *)espstack, &espstack->esp_event,
			    SADB_SATYPE_ESP);
			break;
		default:
			esp2dbg(espstack, ("Got M_CTL from above of 0x%x.\n",
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
			if (nd_getset(q, espstack->ipsecesp_g_nd, mp)) {
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
		esp3dbg(espstack,
		    ("Got default message, type %d, passing to IP.\n",
		    mp->b_datap->db_type));
		putnext(q, mp);
	}
}

/*
 * Wrapper to allow IP to trigger an ESP association failure message
 * during inbound SA selection.
 */
void
ipsecesp_in_assocfailure(mblk_t *mp, char level, ushort_t sl, char *fmt,
    uint32_t spi, void *addr, int af, ip_recv_attr_t *ira)
{
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	if (espstack->ipsecesp_log_unknown_spi) {
		ipsec_assocfailure(info.mi_idnum, 0, level, sl, fmt, spi,
		    addr, af, espstack->ipsecesp_netstack);
	}

	ip_drop_packet(mp, B_TRUE, ira->ira_ill,
	    DROPPER(ipss, ipds_esp_no_sa),
	    &espstack->esp_dropper);
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
