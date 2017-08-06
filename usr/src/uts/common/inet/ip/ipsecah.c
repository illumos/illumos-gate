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
#include <sys/mkdev.h>
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
#include <netinet/icmp6.h>
#include <net/pfkeyv2.h>
#include <net/pfpolicy.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/nd.h>
#include <inet/ip_if.h>
#include <inet/ip_ndp.h>
#include <inet/ipsec_info.h>
#include <inet/ipsec_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecah.h>
#include <inet/ipsec_impl.h>
#include <inet/ipdrop.h>
#include <sys/taskq.h>
#include <sys/policy.h>
#include <sys/strsun.h>

#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/kstat.h>
#include <sys/strsubr.h>

#include <sys/tsol/tnet.h>

/*
 * Table of ND variables supported by ipsecah. These are loaded into
 * ipsecah_g_nd in ipsecah_init_nd.
 * All of these are alterable, within the min/max values given, at run time.
 */
static	ipsecahparam_t	lcl_param_arr[] = {
	/* min	max			value	name */
	{ 0,	3,			0,	"ipsecah_debug"},
	{ 125,	32000, SADB_AGE_INTERVAL_DEFAULT,	"ipsecah_age_interval"},
	{ 1,	10,			1,	"ipsecah_reap_delay"},
	{ 1,	SADB_MAX_REPLAY,	64,	"ipsecah_replay_size"},
	{ 1,	300,			15,	"ipsecah_acquire_timeout"},
	{ 1,	1800,			90,	"ipsecah_larval_timeout"},
	/* Default lifetime values for ACQUIRE messages. */
	{ 0,	0xffffffffU,		0,	"ipsecah_default_soft_bytes"},
	{ 0,	0xffffffffU,		0,	"ipsecah_default_hard_bytes"},
	{ 0,	0xffffffffU,		24000,	"ipsecah_default_soft_addtime"},
	{ 0,	0xffffffffU,		28800,	"ipsecah_default_hard_addtime"},
	{ 0,	0xffffffffU,		0,	"ipsecah_default_soft_usetime"},
	{ 0,	0xffffffffU,		0,	"ipsecah_default_hard_usetime"},
	{ 0,	1,			0,	"ipsecah_log_unknown_spi"},
};

#define	ah0dbg(a)	printf a
/* NOTE:  != 0 instead of > 0 so lint doesn't complain. */
#define	ah1dbg(ahstack, a)	if (ahstack->ipsecah_debug != 0) printf a
#define	ah2dbg(ahstack, a)	if (ahstack->ipsecah_debug > 1) printf a
#define	ah3dbg(ahstack, a)	if (ahstack->ipsecah_debug > 2) printf a

/*
 * XXX This is broken. Padding should be determined dynamically
 * depending on the ICV size and IP version number so that the
 * total AH header size is a multiple of 32 bits or 64 bits
 * for V4 and V6 respectively. For 96bit ICVs we have no problems.
 * Anything different from that, we need to fix our code.
 */
#define	IPV4_PADDING_ALIGN	0x04	/* Multiple of 32 bits */
#define	IPV6_PADDING_ALIGN	0x04	/* Multiple of 32 bits */

/*
 * Helper macro. Avoids a call to msgdsize if there is only one
 * mblk in the chain.
 */
#define	AH_MSGSIZE(mp) ((mp)->b_cont != NULL ? msgdsize(mp) : MBLKL(mp))


static mblk_t *ah_auth_out_done(mblk_t *, ip_xmit_attr_t *, ipsec_crypto_t *);
static mblk_t *ah_auth_in_done(mblk_t *, ip_recv_attr_t *, ipsec_crypto_t *);
static mblk_t *ah_process_ip_options_v4(mblk_t *, ipsa_t *, int *, uint_t,
    boolean_t, ipsecah_stack_t *);
static mblk_t *ah_process_ip_options_v6(mblk_t *, ipsa_t *, int *, uint_t,
    boolean_t, ipsecah_stack_t *);
static void ah_getspi(mblk_t *, keysock_in_t *, ipsecah_stack_t *);
static void ah_inbound_restart(mblk_t *, ip_recv_attr_t *);

static mblk_t *ah_outbound(mblk_t *, ip_xmit_attr_t *);
static void ah_outbound_finish(mblk_t *, ip_xmit_attr_t *);

static int ipsecah_open(queue_t *, dev_t *, int, int, cred_t *);
static int ipsecah_close(queue_t *);
static void ipsecah_wput(queue_t *, mblk_t *);
static boolean_t ah_register_out(uint32_t, uint32_t, uint_t, ipsecah_stack_t *,
    cred_t *);
static void	*ipsecah_stack_init(netstackid_t stackid, netstack_t *ns);
static void	ipsecah_stack_fini(netstackid_t stackid, void *arg);

/* Setable in /etc/system */
uint32_t ah_hash_size = IPSEC_DEFAULT_HASH_SIZE;

static taskq_t *ah_taskq;

static struct module_info info = {
	5136, "ipsecah", 0, INFPSZ, 65536, 1024
};

static struct qinit rinit = {
	(pfi_t)putnext, NULL, ipsecah_open, ipsecah_close, NULL, &info,
	NULL
};

static struct qinit winit = {
	(pfi_t)ipsecah_wput, NULL, ipsecah_open, ipsecah_close, NULL, &info,
	NULL
};

struct streamtab ipsecahinfo = {
	&rinit, &winit, NULL, NULL
};

static int ah_kstat_update(kstat_t *, int);

uint64_t ipsacq_maxpackets = IPSACQ_MAXPACKETS;

static boolean_t
ah_kstat_init(ipsecah_stack_t *ahstack, netstackid_t stackid)
{
	ipsec_stack_t	*ipss = ahstack->ipsecah_netstack->netstack_ipsec;

	ahstack->ah_ksp = kstat_create_netstack("ipsecah", 0, "ah_stat", "net",
	    KSTAT_TYPE_NAMED, sizeof (ah_kstats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT, stackid);

	if (ahstack->ah_ksp == NULL || ahstack->ah_ksp->ks_data == NULL)
		return (B_FALSE);

	ahstack->ah_kstats = ahstack->ah_ksp->ks_data;

	ahstack->ah_ksp->ks_update = ah_kstat_update;
	ahstack->ah_ksp->ks_private = (void *)(uintptr_t)stackid;

#define	K64 KSTAT_DATA_UINT64
#define	KI(x) kstat_named_init(&(ahstack->ah_kstats->ah_stat_##x), #x, K64)

	KI(num_aalgs);
	KI(good_auth);
	KI(bad_auth);
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

#undef KI
#undef K64

	kstat_install(ahstack->ah_ksp);
	IP_ACQUIRE_STAT(ipss, maxpackets, ipsacq_maxpackets);
	return (B_TRUE);
}

static int
ah_kstat_update(kstat_t *kp, int rw)
{
	ah_kstats_t	*ekp;
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
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
	ekp = (ah_kstats_t *)kp->ks_data;

	rw_enter(&ipss->ipsec_alg_lock, RW_READER);
	ekp->ah_stat_num_aalgs.value.ui64 = ipss->ipsec_nalgs[IPSEC_ALG_AUTH];
	rw_exit(&ipss->ipsec_alg_lock);

	netstack_rele(ns);
	return (0);
}

/*
 * Don't have to lock ipsec_age_interval, as only one thread will access it at
 * a time, because I control the one function that does a qtimeout() on
 * ah_pfkey_q.
 */
static void
ah_ager(void *arg)
{
	ipsecah_stack_t *ahstack = (ipsecah_stack_t *)arg;
	netstack_t	*ns = ahstack->ipsecah_netstack;
	hrtime_t begin = gethrtime();

	sadb_ager(&ahstack->ah_sadb.s_v4, ahstack->ah_pfkey_q,
	    ahstack->ipsecah_reap_delay, ns);
	sadb_ager(&ahstack->ah_sadb.s_v6, ahstack->ah_pfkey_q,
	    ahstack->ipsecah_reap_delay, ns);

	ahstack->ah_event = sadb_retimeout(begin, ahstack->ah_pfkey_q,
	    ah_ager, ahstack,
	    &ahstack->ipsecah_age_interval, ahstack->ipsecah_age_int_max,
	    info.mi_idnum);
}

/*
 * Get an AH NDD parameter.
 */
/* ARGSUSED */
static int
ipsecah_param_get(
    queue_t	*q,
    mblk_t	*mp,
    caddr_t	cp,
    cred_t *cr)
{
	ipsecahparam_t	*ipsecahpa = (ipsecahparam_t *)cp;
	uint_t value;
	ipsecah_stack_t	*ahstack = (ipsecah_stack_t *)q->q_ptr;

	mutex_enter(&ahstack->ipsecah_param_lock);
	value = ipsecahpa->ipsecah_param_value;
	mutex_exit(&ahstack->ipsecah_param_lock);

	(void) mi_mpprintf(mp, "%u", value);
	return (0);
}

/*
 * This routine sets an NDD variable in a ipsecahparam_t structure.
 */
/* ARGSUSED */
static int
ipsecah_param_set(
    queue_t	*q,
    mblk_t	*mp,
    char	*value,
    caddr_t	cp,
    cred_t *cr)
{
	ulong_t	new_value;
	ipsecahparam_t	*ipsecahpa = (ipsecahparam_t *)cp;
	ipsecah_stack_t	*ahstack = (ipsecah_stack_t *)q->q_ptr;

	/*
	 * Fail the request if the new value does not lie within the
	 * required bounds.
	 */
	if (ddi_strtoul(value, NULL, 10, &new_value) != 0 ||
	    new_value < ipsecahpa->ipsecah_param_min ||
	    new_value > ipsecahpa->ipsecah_param_max) {
		return (EINVAL);
	}

	/* Set the new value */
	mutex_enter(&ahstack->ipsecah_param_lock);
	ipsecahpa->ipsecah_param_value = new_value;
	mutex_exit(&ahstack->ipsecah_param_lock);
	return (0);
}

/*
 * Using lifetime NDD variables, fill in an extended combination's
 * lifetime information.
 */
void
ipsecah_fill_defs(sadb_x_ecomb_t *ecomb, netstack_t *ns)
{
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;

	ecomb->sadb_x_ecomb_soft_bytes = ahstack->ipsecah_default_soft_bytes;
	ecomb->sadb_x_ecomb_hard_bytes = ahstack->ipsecah_default_hard_bytes;
	ecomb->sadb_x_ecomb_soft_addtime =
	    ahstack->ipsecah_default_soft_addtime;
	ecomb->sadb_x_ecomb_hard_addtime =
	    ahstack->ipsecah_default_hard_addtime;
	ecomb->sadb_x_ecomb_soft_usetime =
	    ahstack->ipsecah_default_soft_usetime;
	ecomb->sadb_x_ecomb_hard_usetime =
	    ahstack->ipsecah_default_hard_usetime;
}

/*
 * Initialize things for AH at module load time.
 */
boolean_t
ipsecah_ddi_init(void)
{
	ah_taskq = taskq_create("ah_taskq", 1, minclsyspri,
	    IPSEC_TASKQ_MIN, IPSEC_TASKQ_MAX, 0);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of ipsecah_stack_t's.
	 */
	netstack_register(NS_IPSECAH, ipsecah_stack_init, NULL,
	    ipsecah_stack_fini);

	return (B_TRUE);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch handler.
 */
static boolean_t
ipsecah_param_register(IDP *ndp, ipsecahparam_t *ahp, int cnt)
{
	for (; cnt-- > 0; ahp++) {
		if (ahp->ipsecah_param_name != NULL &&
		    ahp->ipsecah_param_name[0]) {
			if (!nd_load(ndp,
			    ahp->ipsecah_param_name,
			    ipsecah_param_get, ipsecah_param_set,
			    (caddr_t)ahp)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}
	return (B_TRUE);
}

/*
 * Initialize things for AH for each stack instance
 */
static void *
ipsecah_stack_init(netstackid_t stackid, netstack_t *ns)
{
	ipsecah_stack_t	*ahstack;
	ipsecahparam_t	*ahp;

	ahstack = (ipsecah_stack_t *)kmem_zalloc(sizeof (*ahstack), KM_SLEEP);
	ahstack->ipsecah_netstack = ns;

	ahp = (ipsecahparam_t *)kmem_alloc(sizeof (lcl_param_arr), KM_SLEEP);
	ahstack->ipsecah_params = ahp;
	bcopy(lcl_param_arr, ahp, sizeof (lcl_param_arr));

	(void) ipsecah_param_register(&ahstack->ipsecah_g_nd, ahp,
	    A_CNT(lcl_param_arr));

	(void) ah_kstat_init(ahstack, stackid);

	ahstack->ah_sadb.s_acquire_timeout = &ahstack->ipsecah_acquire_timeout;
	sadbp_init("AH", &ahstack->ah_sadb, SADB_SATYPE_AH, ah_hash_size,
	    ahstack->ipsecah_netstack);

	mutex_init(&ahstack->ipsecah_param_lock, NULL, MUTEX_DEFAULT, 0);

	ip_drop_register(&ahstack->ah_dropper, "IPsec AH");
	return (ahstack);
}

/*
 * Destroy things for AH at module unload time.
 */
void
ipsecah_ddi_destroy(void)
{
	netstack_unregister(NS_IPSECAH);
	taskq_destroy(ah_taskq);
}

/*
 * Destroy things for AH for one stack... Never called?
 */
static void
ipsecah_stack_fini(netstackid_t stackid, void *arg)
{
	ipsecah_stack_t *ahstack = (ipsecah_stack_t *)arg;

	if (ahstack->ah_pfkey_q != NULL) {
		(void) quntimeout(ahstack->ah_pfkey_q, ahstack->ah_event);
	}
	ahstack->ah_sadb.s_acquire_timeout = NULL;
	sadbp_destroy(&ahstack->ah_sadb, ahstack->ipsecah_netstack);
	ip_drop_unregister(&ahstack->ah_dropper);
	mutex_destroy(&ahstack->ipsecah_param_lock);
	nd_free(&ahstack->ipsecah_g_nd);

	kmem_free(ahstack->ipsecah_params, sizeof (lcl_param_arr));
	ahstack->ipsecah_params = NULL;
	kstat_delete_netstack(ahstack->ah_ksp, stackid);
	ahstack->ah_ksp = NULL;
	ahstack->ah_kstats = NULL;

	kmem_free(ahstack, sizeof (*ahstack));
}

/*
 * AH module open routine, which is here for keysock plumbing.
 * Keysock is pushed over {AH,ESP} which is an artifact from the Bad Old
 * Days of export control, and fears that ESP would not be allowed
 * to be shipped at all by default.  Eventually, keysock should
 * either access AH and ESP via modstubs or krtld dependencies, or
 * perhaps be folded in with AH and ESP into a single IPsec/netsec
 * module ("netsec" if PF_KEY provides more than AH/ESP keying tables).
 */
/* ARGSUSED */
static int
ipsecah_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	netstack_t	*ns;
	ipsecah_stack_t	*ahstack;

	if (secpolicy_ip_config(credp, B_FALSE) != 0)
		return (EPERM);

	if (q->q_ptr != NULL)
		return (0);  /* Re-open of an already open instance. */

	if (sflag != MODOPEN)
		return (EINVAL);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	ahstack = ns->netstack_ipsecah;
	ASSERT(ahstack != NULL);

	q->q_ptr = ahstack;
	WR(q)->q_ptr = q->q_ptr;

	qprocson(q);
	return (0);
}

/*
 * AH module close routine.
 */
static int
ipsecah_close(queue_t *q)
{
	ipsecah_stack_t	*ahstack = (ipsecah_stack_t *)q->q_ptr;

	/*
	 * Clean up q_ptr, if needed.
	 */
	qprocsoff(q);

	/* Keysock queue check is safe, because of OCEXCL perimeter. */

	if (q == ahstack->ah_pfkey_q) {
		ah1dbg(ahstack,
		    ("ipsecah_close:  Ummm... keysock is closing AH.\n"));
		ahstack->ah_pfkey_q = NULL;
		/* Detach qtimeouts. */
		(void) quntimeout(q, ahstack->ah_event);
	}

	netstack_rele(ahstack->ipsecah_netstack);
	return (0);
}

/*
 * Construct an SADB_REGISTER message with the current algorithms.
 */
static boolean_t
ah_register_out(uint32_t sequence, uint32_t pid, uint_t serial,
    ipsecah_stack_t *ahstack, cred_t *cr)
{
	mblk_t *mp;
	boolean_t rc = B_TRUE;
	sadb_msg_t *samsg;
	sadb_supported_t *sasupp;
	sadb_alg_t *saalg;
	uint_t allocsize = sizeof (*samsg);
	uint_t i, numalgs_snap;
	ipsec_alginfo_t **authalgs;
	uint_t num_aalgs;
	ipsec_stack_t	*ipss = ahstack->ipsecah_netstack->netstack_ipsec;
	sadb_sens_t *sens;
	size_t sens_len = 0;
	sadb_ext_t *nextext;
	ts_label_t *sens_tsl = NULL;

	/* Allocate the KEYSOCK_OUT. */
	mp = sadb_keysock_out(serial);
	if (mp == NULL) {
		ah0dbg(("ah_register_out: couldn't allocate mblk.\n"));
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
	 * The alg reader lock needs to be held while allocating
	 * the variable part (i.e. the algorithms) of the message.
	 */

	rw_enter(&ipss->ipsec_alg_lock, RW_READER);

	/*
	 * Return only valid algorithms, so the number of algorithms
	 * to send up may be less than the number of algorithm entries
	 * in the table.
	 */
	authalgs = ipss->ipsec_alglists[IPSEC_ALG_AUTH];
	for (num_aalgs = 0, i = 0; i < IPSEC_MAX_ALGS; i++)
		if (authalgs[i] != NULL && ALG_VALID(authalgs[i]))
			num_aalgs++;

	/*
	 * Fill SADB_REGISTER message's algorithm descriptors.  Hold
	 * down the lock while filling it.
	 */
	if (num_aalgs != 0) {
		allocsize += (num_aalgs * sizeof (*saalg));
		allocsize += sizeof (*sasupp);
	}
	mp->b_cont = allocb(allocsize, BPRI_HI);
	if (mp->b_cont == NULL) {
		rw_exit(&ipss->ipsec_alg_lock);
		freemsg(mp);
		return (B_FALSE);
	}

	mp->b_cont->b_wptr += allocsize;
	nextext = (sadb_ext_t *)(mp->b_cont->b_rptr + sizeof (*samsg));

	if (num_aalgs != 0) {

		saalg = (sadb_alg_t *)(((uint8_t *)nextext) + sizeof (*sasupp));
		ASSERT(((ulong_t)saalg & 0x7) == 0);

		numalgs_snap = 0;
		for (i = 0;
		    ((i < IPSEC_MAX_ALGS) && (numalgs_snap < num_aalgs));
		    i++) {
			if (authalgs[i] == NULL || !ALG_VALID(authalgs[i]))
				continue;

			saalg->sadb_alg_id = authalgs[i]->alg_id;
			saalg->sadb_alg_ivlen = 0;
			saalg->sadb_alg_minbits = authalgs[i]->alg_ef_minbits;
			saalg->sadb_alg_maxbits = authalgs[i]->alg_ef_maxbits;
			saalg->sadb_x_alg_increment =
			    authalgs[i]->alg_increment;
			/* For now, salt is meaningless in AH. */
			ASSERT(authalgs[i]->alg_saltlen == 0);
			saalg->sadb_x_alg_saltbits =
			    SADB_8TO1(authalgs[i]->alg_saltlen);
			numalgs_snap++;
			saalg++;
		}
		ASSERT(numalgs_snap == num_aalgs);
#ifdef DEBUG
		/*
		 * Reality check to make sure I snagged all of the
		 * algorithms.
		 */
		for (; i < IPSEC_MAX_ALGS; i++)
			if (authalgs[i] != NULL && ALG_VALID(authalgs[i]))
				cmn_err(CE_PANIC,
				    "ah_register_out()!  Missed #%d.\n", i);
#endif /* DEBUG */
		nextext = (sadb_ext_t *)saalg;
	}

	rw_exit(&ipss->ipsec_alg_lock);

	if (sens_tsl != NULL) {
		sens = (sadb_sens_t *)nextext;
		sadb_sens_from_label(sens, SADB_EXT_SENSITIVITY,
		    sens_tsl, sens_len);

		nextext = (sadb_ext_t *)(((uint8_t *)sens) + sens_len);
	}

	/* Now fill the restof the SADB_REGISTER message. */

	samsg = (sadb_msg_t *)mp->b_cont->b_rptr;
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_REGISTER;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = SADB_SATYPE_AH;
	samsg->sadb_msg_len = SADB_8TO64(allocsize);
	samsg->sadb_msg_reserved = 0;
	/*
	 * Assume caller has sufficient sequence/pid number info.  If it's one
	 * from me over a new alg., I could give two hoots about sequence.
	 */
	samsg->sadb_msg_seq = sequence;
	samsg->sadb_msg_pid = pid;

	if (num_aalgs != 0) {
		sasupp = (sadb_supported_t *)(samsg + 1);
		sasupp->sadb_supported_len = SADB_8TO64(
		    sizeof (*sasupp) + sizeof (*saalg) * num_aalgs);
		sasupp->sadb_supported_exttype = SADB_EXT_SUPPORTED_AUTH;
		sasupp->sadb_supported_reserved = 0;
	}

	if (ahstack->ah_pfkey_q != NULL)
		putnext(ahstack->ah_pfkey_q, mp);
	else {
		rc = B_FALSE;
		freemsg(mp);
	}

	return (rc);
}

/*
 * Invoked when the algorithm table changes. Causes SADB_REGISTER
 * messages continaining the current list of algorithms to be
 * sent up to the AH listeners.
 */
void
ipsecah_algs_changed(netstack_t *ns)
{
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;

	/*
	 * Time to send a PF_KEY SADB_REGISTER message to AH listeners
	 * everywhere.  (The function itself checks for NULL ah_pfkey_q.)
	 */
	(void) ah_register_out(0, 0, 0, ahstack, NULL);
}

/*
 * Stub function that taskq_dispatch() invokes to take the mblk (in arg)
 * and send it into AH and IP again.
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

	ah_inbound_restart(mp, &iras);
done:
	ira_cleanup(&iras, B_TRUE);
}

/*
 * Restart ESP after the SA has been added.
 */
static void
ah_inbound_restart(mblk_t *mp, ip_recv_attr_t *ira)
{
	ah_t		*ah;
	netstack_t	*ns;
	ipsecah_stack_t	*ahstack;

	ns = ira->ira_ill->ill_ipst->ips_netstack;
	ahstack = ns->netstack_ipsecah;

	ASSERT(ahstack != NULL);
	mp = ipsec_inbound_ah_sa(mp, ira, &ah);
	if (mp == NULL)
		return;

	ASSERT(ah != NULL);
	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
	ASSERT(ira->ira_ipsec_ah_sa != NULL);

	mp = ira->ira_ipsec_ah_sa->ipsa_input_func(mp, ah, ira);
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
ah_add_sa_finish(mblk_t *mp, sadb_msg_t *samsg, keysock_in_t *ksi,
    int *diagnostic, ipsecah_stack_t *ahstack)
{
	isaf_t *primary = NULL, *secondary;
	boolean_t clone = B_FALSE, is_inbound = B_FALSE;
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	ipsa_t *larval;
	ipsacq_t *acqrec;
	iacqf_t *acq_bucket;
	mblk_t *acq_msgs = NULL;
	mblk_t *lpkt;
	int rc;
	ipsa_query_t sq;
	int error;
	netstack_t	*ns = ahstack->ipsecah_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	/*
	 * Locate the appropriate table(s).
	 */

	sq.spp = &ahstack->ah_sadb;
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
	if (assoc->sadb_sa_flags & IPSA_F_INBOUND) {
		primary = sq.inbound;
		secondary = sq.outbound;
		is_inbound = B_TRUE;
		if (assoc->sadb_sa_flags & IPSA_F_OUTBOUND)
			clone = B_TRUE;
	} else {
		if (assoc->sadb_sa_flags & IPSA_F_OUTBOUND) {
			primary = sq.outbound;
			secondary = sq.inbound;
		}
	}
	if (primary == NULL) {
		/*
		 * The KMD did not set a direction flag, determine which
		 * table to insert the SA into based on addresses.
		 */
		switch (ksi->ks_in_dsttype) {
		case KS_IN_ADDR_MBCAST:
			clone = B_TRUE;	/* All mcast SAs can be bidirectional */
			assoc->sadb_sa_flags |= IPSA_F_OUTBOUND;
			/* FALLTHRU */
		/*
		 * If the source address is either one of mine, or unspecified
		 * (which is best summed up by saying "not 'not mine'"),
		 * then the association is potentially bi-directional,
		 * in that it can be used for inbound traffic and outbound
		 * traffic.  The best example of such and SA is a multicast
		 * SA (which allows me to receive the outbound traffic).
		 */
		case KS_IN_ADDR_ME:
			assoc->sadb_sa_flags |= IPSA_F_INBOUND;
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
			assoc->sadb_sa_flags |= IPSA_F_OUTBOUND;
			primary = sq.outbound;
			secondary = sq.inbound;
			if (ksi->ks_in_srctype != KS_IN_ADDR_ME) {
				assoc->sadb_sa_flags |= IPSA_F_INBOUND;
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
			sadb_destroy_acquire(acqrec, ns);
		}
		mutex_exit(&acq_bucket->iacqf_lock);
	}

	/*
	 * Find PF_KEY message, and see if I'm an update.  If so, find entry
	 * in larval list (if there).
	 */

	larval = NULL;

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
			ah0dbg(("Larval update, but larval disappeared.\n"));
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

	rc = sadb_common_add(ahstack->ah_pfkey_q, mp,
	    samsg, ksi, primary, secondary, larval, clone, is_inbound,
	    diagnostic, ns, &ahstack->ah_sadb);

	if (larval != NULL) {
		if (rc == 0) {
			lpkt = sadb_clear_lpkt(larval);
			if (lpkt != NULL) {
				rc = !taskq_dispatch(ah_taskq, inbound_task,
				    lpkt, TQ_NOSLEEP);
			}
		}
		IPSA_REFRELE(larval);
	}

	/*
	 * How much more stack will I create with all of these
	 * ah_outbound_*() calls?
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
			AH_BUMP_STAT(ahstack, out_discards);
			ip_drop_packet(data_mp, B_FALSE, NULL,
			    DROPPER(ipss, ipds_sadb_acquire_timeout),
			    &ahstack->ah_dropper);
		} else if (rc != 0) {
			ill = ixas.ixa_nce->nce_ill;
			AH_BUMP_STAT(ahstack, out_discards);
			ip_drop_packet(data_mp, B_FALSE, ill,
			    DROPPER(ipss, ipds_sadb_acquire_timeout),
			    &ahstack->ah_dropper);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		} else {
			ah_outbound_finish(data_mp, &ixas);
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
ah_outbound_finish(mblk_t *data_mp, ip_xmit_attr_t *ixa)
{
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;
	ipsecah_stack_t *ahstack = ns->netstack_ipsecah;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ill_t		*ill = ixa->ixa_nce->nce_ill;

	if (!ipsec_outbound_sa(data_mp, ixa, IPPROTO_AH)) {
		AH_BUMP_STAT(ahstack, out_discards);
		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_sadb_acquire_timeout),
		    &ahstack->ah_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		return;
	}

	data_mp = ah_outbound(data_mp, ixa);
	if (data_mp == NULL)
		return;

	(void) ip_output_post_ipsec(data_mp, ixa);
}

/*
 * Add new AH security association.  This may become a generic AH/ESP
 * routine eventually.
 */
static int
ah_add_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic, netstack_t *ns)
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
	sadb_key_t *key = (sadb_key_t *)ksi->ks_in_extv[SADB_EXT_KEY_AUTH];
	struct sockaddr_in *src, *dst;
	/* We don't need sockaddr_in6 for now. */
	sadb_lifetime_t *soft =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_SOFT];
	sadb_lifetime_t *hard =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_EXT_LIFETIME_HARD];
	sadb_lifetime_t *idle =
	    (sadb_lifetime_t *)ksi->ks_in_extv[SADB_X_EXT_LIFETIME_IDLE];
	ipsec_alginfo_t *aalg;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
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
	if (key == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_AKEY;
		return (EINVAL);
	}

	src = (struct sockaddr_in *)(srcext + 1);
	dst = (struct sockaddr_in *)(dstext + 1);

	/* Sundry ADD-specific reality checks. */
	/* XXX STATS : Logging/stats here? */

	if ((assoc->sadb_sa_state != SADB_SASTATE_MATURE) &&
	    (assoc->sadb_sa_state != SADB_X_SASTATE_ACTIVE_ELSEWHERE)) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SASTATE;
		return (EINVAL);
	}
	if (assoc->sadb_sa_encrypt != SADB_EALG_NONE) {
		*diagnostic = SADB_X_DIAGNOSTIC_ENCR_NOTSUPP;
		return (EINVAL);
	}
	if (assoc->sadb_sa_flags & ~ahstack->ah_sadb.s_addflags) {
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_SAFLAGS;
		return (EINVAL);
	}
	if ((*diagnostic = sadb_hardsoftchk(hard, soft, idle)) != 0)
		return (EINVAL);

	ASSERT(src->sin_family == dst->sin_family);

	/* Stuff I don't support, for now.  XXX Diagnostic? */
	if (ksi->ks_in_extv[SADB_EXT_LIFETIME_CURRENT] != NULL)
		return (EOPNOTSUPP);

	if (ksi->ks_in_extv[SADB_EXT_SENSITIVITY] != NULL) {
		if (!is_system_labeled())
			return (EOPNOTSUPP);
	}

	if (ksi->ks_in_extv[SADB_X_EXT_OUTER_SENS] != NULL) {
		if (!is_system_labeled())
			return (EOPNOTSUPP);
	}
	/*
	 * XXX Policy : I'm not checking identities at this time, but
	 * if I did, I'd do them here, before I sent the weak key
	 * check up to the algorithm.
	 */

	/* verify that there is a mapping for the specified algorithm */
	rw_enter(&ipss->ipsec_alg_lock, RW_READER);
	aalg = ipss->ipsec_alglists[IPSEC_ALG_AUTH][assoc->sadb_sa_auth];
	if (aalg == NULL || !ALG_VALID(aalg)) {
		rw_exit(&ipss->ipsec_alg_lock);
		ah1dbg(ahstack, ("Couldn't find auth alg #%d.\n",
		    assoc->sadb_sa_auth));
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_AALG;
		return (EINVAL);
	}
	ASSERT(aalg->alg_mech_type != CRYPTO_MECHANISM_INVALID);

	/* sanity check key sizes */
	if (!ipsec_valid_key_size(key->sadb_key_bits, aalg)) {
		rw_exit(&ipss->ipsec_alg_lock);
		*diagnostic = SADB_X_DIAGNOSTIC_BAD_AKEYBITS;
		return (EINVAL);
	}

	/* check key and fix parity if needed */
	if (ipsec_check_key(aalg->alg_mech_type, key, B_TRUE,
	    diagnostic) != 0) {
		rw_exit(&ipss->ipsec_alg_lock);
		return (EINVAL);
	}

	rw_exit(&ipss->ipsec_alg_lock);

	return (ah_add_sa_finish(mp, (sadb_msg_t *)mp->b_cont->b_rptr, ksi,
	    diagnostic, ahstack));
}

/* Refactor me */
/*
 * Update a security association.  Updates come in two varieties.  The first
 * is an update of lifetimes on a non-larval SA.  The second is an update of
 * a larval SA, which ends up looking a lot more like an add.
 */
static int
ah_update_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic,
    ipsecah_stack_t *ahstack, uint8_t sadb_msg_type)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	mblk_t	*buf_pkt;
	int rcode;

	if (dstext == NULL) {
		*diagnostic = SADB_X_DIAGNOSTIC_MISSING_DST;
		return (EINVAL);
	}

	rcode = sadb_update_sa(mp, ksi, &buf_pkt, &ahstack->ah_sadb,
	    diagnostic, ahstack->ah_pfkey_q, ah_add_sa,
	    ahstack->ipsecah_netstack, sadb_msg_type);

	if ((assoc->sadb_sa_state != SADB_X_SASTATE_ACTIVE) ||
	    (rcode != 0)) {
		return (rcode);
	}

	HANDLE_BUF_PKT(ah_taskq, ahstack->ipsecah_netstack->netstack_ipsec,
	    ahstack->ah_dropper, buf_pkt);

	return (rcode);
}

/* Refactor me */
/*
 * Delete a security association.  This is REALLY likely to be code common to
 * both AH and ESP.  Find the association, then unlink it.
 */
static int
ah_del_sa(mblk_t *mp, keysock_in_t *ksi, int *diagnostic,
    ipsecah_stack_t *ahstack, uint8_t sadb_msg_type)
{
	sadb_sa_t *assoc = (sadb_sa_t *)ksi->ks_in_extv[SADB_EXT_SA];
	sadb_address_t *dstext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_DST];
	sadb_address_t *srcext =
	    (sadb_address_t *)ksi->ks_in_extv[SADB_EXT_ADDRESS_SRC];
	struct sockaddr_in *sin;

	if (assoc == NULL) {
		if (dstext != NULL)
			sin = (struct sockaddr_in *)(dstext + 1);
		else if (srcext != NULL)
			sin = (struct sockaddr_in *)(srcext + 1);
		else {
			*diagnostic = SADB_X_DIAGNOSTIC_MISSING_SA;
			return (EINVAL);
		}
		return (sadb_purge_sa(mp, ksi,
		    (sin->sin_family == AF_INET6) ? &ahstack->ah_sadb.s_v6 :
		    &ahstack->ah_sadb.s_v4, diagnostic, ahstack->ah_pfkey_q));
	}

	return (sadb_delget_sa(mp, ksi, &ahstack->ah_sadb, diagnostic,
	    ahstack->ah_pfkey_q, sadb_msg_type));
}

/* Refactor me */
/*
 * Convert the entire contents of all of AH's SA tables into PF_KEY SADB_DUMP
 * messages.
 */
static void
ah_dump(mblk_t *mp, keysock_in_t *ksi, ipsecah_stack_t *ahstack)
{
	int error;
	sadb_msg_t *samsg;

	/*
	 * Dump each fanout, bailing if error is non-zero.
	 */

	error = sadb_dump(ahstack->ah_pfkey_q, mp, ksi, &ahstack->ah_sadb.s_v4);
	if (error != 0)
		goto bail;

	error = sadb_dump(ahstack->ah_pfkey_q, mp, ksi, &ahstack->ah_sadb.s_v6);
bail:
	ASSERT(mp->b_cont != NULL);
	samsg = (sadb_msg_t *)mp->b_cont->b_rptr;
	samsg->sadb_msg_errno = (uint8_t)error;
	sadb_pfkey_echo(ahstack->ah_pfkey_q, mp,
	    (sadb_msg_t *)mp->b_cont->b_rptr, ksi, NULL);
}

/*
 * First-cut reality check for an inbound PF_KEY message.
 */
static boolean_t
ah_pfkey_reality_failures(mblk_t *mp, keysock_in_t *ksi,
    ipsecah_stack_t *ahstack)
{
	int diagnostic;

	if (mp->b_cont == NULL) {
		freemsg(mp);
		return (B_TRUE);
	}

	if (ksi->ks_in_extv[SADB_EXT_KEY_ENCRYPT] != NULL) {
		diagnostic = SADB_X_DIAGNOSTIC_EKEY_PRESENT;
		goto badmsg;
	}
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
	sadb_pfkey_error(ahstack->ah_pfkey_q, mp, EINVAL,
	    diagnostic, ksi->ks_in_serial);
	return (B_TRUE);	/* True ==> failures */
}

/*
 * AH parsing of PF_KEY messages.  Keysock did most of the really silly
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
ah_parse_pfkey(mblk_t *mp, ipsecah_stack_t *ahstack)
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
	if (!sadb_addrfix(ksi, ahstack->ah_pfkey_q, mp,
	    ahstack->ipsecah_netstack) ||
	    ah_pfkey_reality_failures(mp, ksi, ahstack)) {
		return;
	}

	switch (samsg->sadb_msg_type) {
	case SADB_ADD:
		error = ah_add_sa(mp, ksi, &diagnostic,
		    ahstack->ipsecah_netstack);
		if (error != 0) {
			sadb_pfkey_error(ahstack->ah_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* else ah_add_sa() took care of things. */
		break;
	case SADB_DELETE:
	case SADB_X_DELPAIR:
	case SADB_X_DELPAIR_STATE:
		error = ah_del_sa(mp, ksi, &diagnostic, ahstack,
		    samsg->sadb_msg_type);
		if (error != 0) {
			sadb_pfkey_error(ahstack->ah_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* Else ah_del_sa() took care of things. */
		break;
	case SADB_GET:
		error = sadb_delget_sa(mp, ksi, &ahstack->ah_sadb, &diagnostic,
		    ahstack->ah_pfkey_q, samsg->sadb_msg_type);
		if (error != 0) {
			sadb_pfkey_error(ahstack->ah_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* Else sadb_get_sa() took care of things. */
		break;
	case SADB_FLUSH:
		sadbp_flush(&ahstack->ah_sadb, ahstack->ipsecah_netstack);
		sadb_pfkey_echo(ahstack->ah_pfkey_q, mp, samsg, ksi, NULL);
		break;
	case SADB_REGISTER:
		/*
		 * Hmmm, let's do it!  Check for extensions (there should
		 * be none), extract the fields, call ah_register_out(),
		 * then either free or report an error.
		 *
		 * Keysock takes care of the PF_KEY bookkeeping for this.
		 */
		if (ah_register_out(samsg->sadb_msg_seq, samsg->sadb_msg_pid,
		    ksi->ks_in_serial, ahstack, msg_getcred(mp, NULL))) {
			freemsg(mp);
		} else {
			/*
			 * Only way this path hits is if there is a memory
			 * failure.  It will not return B_FALSE because of
			 * lack of ah_pfkey_q if I am in wput().
			 */
			sadb_pfkey_error(ahstack->ah_pfkey_q, mp, ENOMEM,
			    diagnostic, ksi->ks_in_serial);
		}
		break;
	case SADB_UPDATE:
	case SADB_X_UPDATEPAIR:
		/*
		 * Find a larval, if not there, find a full one and get
		 * strict.
		 */
		error = ah_update_sa(mp, ksi, &diagnostic, ahstack,
		    samsg->sadb_msg_type);
		if (error != 0) {
			sadb_pfkey_error(ahstack->ah_pfkey_q, mp, error,
			    diagnostic, ksi->ks_in_serial);
		}
		/* else ah_update_sa() took care of things. */
		break;
	case SADB_GETSPI:
		/*
		 * Reserve a new larval entry.
		 */
		ah_getspi(mp, ksi, ahstack);
		break;
	case SADB_ACQUIRE:
		/*
		 * Find larval and/or ACQUIRE record and kill it (them), I'm
		 * most likely an error.  Inbound ACQUIRE messages should only
		 * have the base header.
		 */
		sadb_in_acquire(samsg, &ahstack->ah_sadb, ahstack->ah_pfkey_q,
		    ahstack->ipsecah_netstack);
		freemsg(mp);
		break;
	case SADB_DUMP:
		/*
		 * Dump all entries.
		 */
		ah_dump(mp, ksi, ahstack);
		/* ah_dump will take care of the return message, etc. */
		break;
	case SADB_EXPIRE:
		/* Should never reach me. */
		sadb_pfkey_error(ahstack->ah_pfkey_q, mp, EOPNOTSUPP,
		    diagnostic, ksi->ks_in_serial);
		break;
	default:
		sadb_pfkey_error(ahstack->ah_pfkey_q, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_UNKNOWN_MSG, ksi->ks_in_serial);
		break;
	}
}

/*
 * Handle case where PF_KEY says it can't find a keysock for one of my
 * ACQUIRE messages.
 */
static void
ah_keysock_no_socket(mblk_t *mp, ipsecah_stack_t *ahstack)
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
		 * Use the write-side of the ah_pfkey_q
		 */
		sadb_in_acquire(samsg, &ahstack->ah_sadb,
		    WR(ahstack->ah_pfkey_q), ahstack->ipsecah_netstack);
	}

	freemsg(mp);
}

/*
 * AH module write put routine.
 */
static void
ipsecah_wput(queue_t *q, mblk_t *mp)
{
	ipsec_info_t *ii;
	struct iocblk *iocp;
	ipsecah_stack_t	*ahstack = (ipsecah_stack_t *)q->q_ptr;

	ah3dbg(ahstack, ("In ah_wput().\n"));

	/* NOTE:  Each case must take care of freeing or passing mp. */
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
			ah1dbg(ahstack, ("Got KEYSOCK_OUT_ERR message.\n"));
			ah_keysock_no_socket(mp, ahstack);
			break;
		case KEYSOCK_IN:
			AH_BUMP_STAT(ahstack, keysock_in);
			ah3dbg(ahstack, ("Got KEYSOCK_IN message.\n"));

			/* Parse the message. */
			ah_parse_pfkey(mp, ahstack);
			break;
		case KEYSOCK_HELLO:
			sadb_keysock_hello(&ahstack->ah_pfkey_q, q, mp,
			    ah_ager, (void *)ahstack, &ahstack->ah_event,
			    SADB_SATYPE_AH);
			break;
		default:
			ah1dbg(ahstack, ("Got M_CTL from above of 0x%x.\n",
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
			if (nd_getset(q, ahstack->ipsecah_g_nd, mp)) {
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
		ah3dbg(ahstack,
		    ("Got default message, type %d, passing to IP.\n",
		    mp->b_datap->db_type));
		putnext(q, mp);
	}
}

/* Refactor me */
/*
 * Updating use times can be tricky business if the ipsa_haspeer flag is
 * set.  This function is called once in an SA's lifetime.
 *
 * Caller has to REFRELE "assoc" which is passed in.  This function has
 * to REFRELE any peer SA that is obtained.
 */
static void
ah_set_usetime(ipsa_t *assoc, boolean_t inbound)
{
	ipsa_t *inassoc, *outassoc;
	isaf_t *bucket;
	sadb_t *sp;
	int outhash;
	boolean_t isv6;
	netstack_t	*ns = assoc->ipsa_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;

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

	/* Use address family to select IPv6/IPv4 */
	isv6 = (assoc->ipsa_addrfam == AF_INET6);
	if (isv6) {
		sp = &ahstack->ah_sadb.s_v6;
	} else {
		sp = &ahstack->ah_sadb.s_v4;
		ASSERT(assoc->ipsa_addrfam == AF_INET);
	}
	if (inbound) {
		inassoc = assoc;
		if (isv6)
			outhash = OUTBOUND_HASH_V6(sp,
			    *((in6_addr_t *)&inassoc->ipsa_dstaddr));
		else
			outhash = OUTBOUND_HASH_V4(sp,
			    *((ipaddr_t *)&inassoc->ipsa_dstaddr));
		bucket = &sp->sdb_of[outhash];

		mutex_enter(&bucket->isaf_lock);
		outassoc = ipsec_getassocbyspi(bucket, inassoc->ipsa_spi,
		    inassoc->ipsa_srcaddr, inassoc->ipsa_dstaddr,
		    inassoc->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (outassoc == NULL) {
			/* Q: Do we wish to set haspeer == B_FALSE? */
			ah0dbg(("ah_set_usetime: "
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
			ah0dbg(("ah_set_usetime: "
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

/* Refactor me */
/*
 * Add a number of bytes to what the SA has protected so far.  Return
 * B_TRUE if the SA can still protect that many bytes.
 *
 * Caller must REFRELE the passed-in assoc.  This function must REFRELE
 * any obtained peer SA.
 */
static boolean_t
ah_age_bytes(ipsa_t *assoc, uint64_t bytes, boolean_t inbound)
{
	ipsa_t *inassoc, *outassoc;
	isaf_t *bucket;
	boolean_t inrc, outrc, isv6;
	sadb_t *sp;
	int outhash;
	netstack_t	*ns = assoc->ipsa_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;

	/* No peer?  No problem! */
	if (!assoc->ipsa_haspeer) {
		return (sadb_age_bytes(ahstack->ah_pfkey_q, assoc, bytes,
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

	/* Pick v4/v6 bucket based on addrfam. */
	isv6 = (assoc->ipsa_addrfam == AF_INET6);
	if (isv6) {
		sp = &ahstack->ah_sadb.s_v6;
	} else {
		sp = &ahstack->ah_sadb.s_v4;
		ASSERT(assoc->ipsa_addrfam == AF_INET);
	}
	if (inbound) {
		inassoc = assoc;
		if (isv6)
			outhash = OUTBOUND_HASH_V6(sp,
			    *((in6_addr_t *)&inassoc->ipsa_dstaddr));
		else
			outhash = OUTBOUND_HASH_V4(sp,
			    *((ipaddr_t *)&inassoc->ipsa_dstaddr));
		bucket = &sp->sdb_of[outhash];
		mutex_enter(&bucket->isaf_lock);
		outassoc = ipsec_getassocbyspi(bucket, inassoc->ipsa_spi,
		    inassoc->ipsa_srcaddr, inassoc->ipsa_dstaddr,
		    inassoc->ipsa_addrfam);
		mutex_exit(&bucket->isaf_lock);
		if (outassoc == NULL) {
			/* Q: Do we wish to set haspeer == B_FALSE? */
			ah0dbg(("ah_age_bytes: "
			    "can't find peer for inbound.\n"));
			return (sadb_age_bytes(ahstack->ah_pfkey_q, inassoc,
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
			ah0dbg(("ah_age_bytes: "
			    "can't find peer for outbound.\n"));
			return (sadb_age_bytes(ahstack->ah_pfkey_q, outassoc,
			    bytes, B_TRUE));
		}
	}

	inrc = sadb_age_bytes(ahstack->ah_pfkey_q, inassoc, bytes, B_TRUE);
	outrc = sadb_age_bytes(ahstack->ah_pfkey_q, outassoc, bytes, B_FALSE);

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

/* Refactor me */
/*
 * Handle the SADB_GETSPI message.  Create a larval SA.
 */
static void
ah_getspi(mblk_t *mp, keysock_in_t *ksi, ipsecah_stack_t *ahstack)
{
	ipsa_t *newbie, *target;
	isaf_t *outbound, *inbound;
	int rc, diagnostic;
	sadb_sa_t *assoc;
	keysock_out_t *kso;
	uint32_t newspi;

	/*
	 * Randomly generate a proposed SPI value.
	 */
	if (cl_inet_getspi != NULL) {
		cl_inet_getspi(ahstack->ipsecah_netstack->netstack_stackid,
		    IPPROTO_AH, (uint8_t *)&newspi, sizeof (uint32_t), NULL);
	} else {
		(void) random_get_pseudo_bytes((uint8_t *)&newspi,
		    sizeof (uint32_t));
	}
	newbie = sadb_getspi(ksi, newspi, &diagnostic,
	    ahstack->ipsecah_netstack, IPPROTO_AH);

	if (newbie == NULL) {
		sadb_pfkey_error(ahstack->ah_pfkey_q, mp, ENOMEM, diagnostic,
		    ksi->ks_in_serial);
		return;
	} else if (newbie == (ipsa_t *)-1) {
		sadb_pfkey_error(ahstack->ah_pfkey_q, mp, EINVAL, diagnostic,
		    ksi->ks_in_serial);
		return;
	}

	/*
	 * XXX - We may randomly collide.  We really should recover from this.
	 *	 Unfortunately, that could require spending way-too-much-time
	 *	 in here.  For now, let the user retry.
	 */

	if (newbie->ipsa_addrfam == AF_INET6) {
		outbound = OUTBOUND_BUCKET_V6(&ahstack->ah_sadb.s_v6,
		    *(uint32_t *)(newbie->ipsa_dstaddr));
		inbound = INBOUND_BUCKET(&ahstack->ah_sadb.s_v6,
		    newbie->ipsa_spi);
	} else {
		outbound = OUTBOUND_BUCKET_V4(&ahstack->ah_sadb.s_v4,
		    *(uint32_t *)(newbie->ipsa_dstaddr));
		inbound = INBOUND_BUCKET(&ahstack->ah_sadb.s_v4,
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
		 * if there's a colliding larval entry, rc will be set
		 * to EEXIST.
		 */
		rc = sadb_insertassoc(newbie, inbound);
		newbie->ipsa_hardexpiretime = gethrestime_sec();
		newbie->ipsa_hardexpiretime += ahstack->ipsecah_larval_timeout;
	}

	/*
	 * Can exit outbound mutex.  Hold inbound until we're done with
	 * newbie.
	 */
	mutex_exit(&outbound->isaf_lock);

	if (rc != 0) {
		mutex_exit(&inbound->isaf_lock);
		IPSA_REFRELE(newbie);
		sadb_pfkey_error(ahstack->ah_pfkey_q, mp, rc,
		    SADB_X_DIAGNOSTIC_NONE, ksi->ks_in_serial);
		return;
	}

	/* Can write here because I'm still holding the bucket lock. */
	newbie->ipsa_type = SADB_SATYPE_AH;

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
	 * Can safely putnext() to ah_pfkey_q, because this is a turnaround
	 * from the ah_pfkey_q.
	 */
	putnext(ahstack->ah_pfkey_q, mp);
}

/*
 * IPv6 sends up the ICMP errors for validation and the removal of the AH
 * header.
 * If succesful, the mp has been modified to not include the AH header so
 * that the caller can fanout to the ULP's icmp error handler.
 */
static mblk_t *
ah_icmp_error_v6(mblk_t *mp, ip_recv_attr_t *ira, ipsecah_stack_t *ahstack)
{
	ip6_t *ip6h, *oip6h;
	uint16_t hdr_length, ah_length;
	uint8_t *nexthdrp;
	ah_t *ah;
	icmp6_t *icmp6;
	isaf_t *isaf;
	ipsa_t *assoc;
	uint8_t *post_ah_ptr;
	ipsec_stack_t	*ipss = ahstack->ipsecah_netstack->netstack_ipsec;

	/*
	 * Eat the cost of a pullupmsg() for now.  It makes the rest of this
	 * code far less convoluted.
	 */
	if (!pullupmsg(mp, -1) ||
	    !ip_hdr_length_nexthdr_v6(mp, (ip6_t *)mp->b_rptr, &hdr_length,
	    &nexthdrp) ||
	    mp->b_rptr + hdr_length + sizeof (icmp6_t) + sizeof (ip6_t) +
	    sizeof (ah_t) > mp->b_wptr) {
		IP_AH_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_nomem),
		    &ahstack->ah_dropper);
		return (NULL);
	}

	oip6h = (ip6_t *)mp->b_rptr;
	icmp6 = (icmp6_t *)((uint8_t *)oip6h + hdr_length);
	ip6h = (ip6_t *)(icmp6 + 1);
	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &hdr_length, &nexthdrp)) {
		IP_AH_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_bad_v6_hdrs),
		    &ahstack->ah_dropper);
		return (NULL);
	}
	ah = (ah_t *)((uint8_t *)ip6h + hdr_length);

	isaf = OUTBOUND_BUCKET_V6(&ahstack->ah_sadb.s_v6, ip6h->ip6_dst);
	mutex_enter(&isaf->isaf_lock);
	assoc = ipsec_getassocbyspi(isaf, ah->ah_spi,
	    (uint32_t *)&ip6h->ip6_src, (uint32_t *)&ip6h->ip6_dst, AF_INET6);
	mutex_exit(&isaf->isaf_lock);

	if (assoc == NULL) {
		IP_AH_BUMP_STAT(ipss, lookup_failure);
		IP_AH_BUMP_STAT(ipss, in_discards);
		if (ahstack->ipsecah_log_unknown_spi) {
			ipsec_assocfailure(info.mi_idnum, 0, 0,
			    SL_CONSOLE | SL_WARN | SL_ERROR,
			    "Bad ICMP message - No association for the "
			    "attached AH header whose spi is 0x%x, "
			    "sender is 0x%x\n",
			    ah->ah_spi, &oip6h->ip6_src, AF_INET6,
			    ahstack->ipsecah_netstack);
		}
		ip_drop_packet(mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_no_sa),
		    &ahstack->ah_dropper);
		return (NULL);
	}

	IPSA_REFRELE(assoc);

	/*
	 * There seems to be a valid association. If there is enough of AH
	 * header remove it, otherwise bail.  One could check whether it has
	 * complete AH header plus 8 bytes but it does not make sense if an
	 * icmp error is returned for ICMP messages e.g ICMP time exceeded,
	 * that are being sent up. Let the caller figure out.
	 *
	 * NOTE: ah_length is the number of 32 bit words minus 2.
	 */
	ah_length = (ah->ah_length << 2) + 8;
	post_ah_ptr = (uint8_t *)ah + ah_length;

	if (post_ah_ptr > mp->b_wptr) {
		IP_AH_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_bad_length),
		    &ahstack->ah_dropper);
		return (NULL);
	}

	ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) - ah_length);
	*nexthdrp = ah->ah_nexthdr;
	ovbcopy(post_ah_ptr, ah,
	    (size_t)((uintptr_t)mp->b_wptr - (uintptr_t)post_ah_ptr));
	mp->b_wptr -= ah_length;

	return (mp);
}

/*
 * IP sends up the ICMP errors for validation and the removal of
 * the AH header.
 * If succesful, the mp has been modified to not include the AH header so
 * that the caller can fanout to the ULP's icmp error handler.
 */
static mblk_t *
ah_icmp_error_v4(mblk_t *mp, ip_recv_attr_t *ira, ipsecah_stack_t *ahstack)
{
	mblk_t *mp1;
	icmph_t *icmph;
	int iph_hdr_length;
	int hdr_length;
	isaf_t *hptr;
	ipsa_t *assoc;
	int ah_length;
	ipha_t *ipha;
	ipha_t *oipha;
	ah_t *ah;
	uint32_t length;
	int alloc_size;
	uint8_t nexthdr;
	ipsec_stack_t	*ipss = ahstack->ipsecah_netstack->netstack_ipsec;

	oipha = ipha = (ipha_t *)mp->b_rptr;
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];

	ipha = (ipha_t *)&icmph[1];
	hdr_length = IPH_HDR_LENGTH(ipha);

	/*
	 * See if we have enough to locate the SPI
	 */
	if ((uchar_t *)ipha + hdr_length + 8 > mp->b_wptr) {
		if (!pullupmsg(mp, (uchar_t *)ipha + hdr_length + 8 -
		    mp->b_rptr)) {
			ipsec_rl_strlog(ahstack->ipsecah_netstack,
			    info.mi_idnum, 0, 0,
			    SL_WARN | SL_ERROR,
			    "ICMP error: Small AH header\n");
			IP_AH_BUMP_STAT(ipss, in_discards);
			ip_drop_packet(mp, B_TRUE, ira->ira_ill,
			    DROPPER(ipss, ipds_ah_bad_length),
			    &ahstack->ah_dropper);
			return (NULL);
		}
		icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
		ipha = (ipha_t *)&icmph[1];
	}

	ah = (ah_t *)((uint8_t *)ipha + hdr_length);
	nexthdr = ah->ah_nexthdr;

	hptr = OUTBOUND_BUCKET_V4(&ahstack->ah_sadb.s_v4, ipha->ipha_dst);
	mutex_enter(&hptr->isaf_lock);
	assoc = ipsec_getassocbyspi(hptr, ah->ah_spi,
	    (uint32_t *)&ipha->ipha_src, (uint32_t *)&ipha->ipha_dst, AF_INET);
	mutex_exit(&hptr->isaf_lock);

	if (assoc == NULL) {
		IP_AH_BUMP_STAT(ipss, lookup_failure);
		IP_AH_BUMP_STAT(ipss, in_discards);
		if (ahstack->ipsecah_log_unknown_spi) {
			ipsec_assocfailure(info.mi_idnum, 0, 0,
			    SL_CONSOLE | SL_WARN | SL_ERROR,
			    "Bad ICMP message - No association for the "
			    "attached AH header whose spi is 0x%x, "
			    "sender is 0x%x\n",
			    ah->ah_spi, &oipha->ipha_src, AF_INET,
			    ahstack->ipsecah_netstack);
		}
		ip_drop_packet(mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_no_sa),
		    &ahstack->ah_dropper);
		return (NULL);
	}

	IPSA_REFRELE(assoc);
	/*
	 * There seems to be a valid association. If there
	 * is enough of AH header remove it, otherwise remove
	 * as much as possible and send it back. One could check
	 * whether it has complete AH header plus 8 bytes but it
	 * does not make sense if an icmp error is returned for
	 * ICMP messages e.g ICMP time exceeded, that are being
	 * sent up. Let the caller figure out.
	 *
	 * NOTE: ah_length is the number of 32 bit words minus 2.
	 */
	ah_length = (ah->ah_length << 2) + 8;

	if ((uchar_t *)ipha + hdr_length + ah_length > mp->b_wptr) {
		if (mp->b_cont == NULL) {
			/*
			 * There is nothing to pullup. Just remove as
			 * much as possible. This is a common case for
			 * IPV4.
			 */
			ah_length = (mp->b_wptr - ((uchar_t *)ipha +
			    hdr_length));
			goto done;
		}
		/* Pullup the full ah header */
		if (!pullupmsg(mp, (uchar_t *)ah + ah_length - mp->b_rptr)) {
			/*
			 * pullupmsg could have failed if there was not
			 * enough to pullup or memory allocation failed.
			 * We tried hard, give up now.
			 */
			IP_AH_BUMP_STAT(ipss, in_discards);
			ip_drop_packet(mp, B_TRUE, ira->ira_ill,
			    DROPPER(ipss, ipds_ah_nomem),
			    &ahstack->ah_dropper);
			return (NULL);
		}
		icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
		ipha = (ipha_t *)&icmph[1];
	}
done:
	/*
	 * Remove the AH header and change the protocol.
	 * Don't update the spi fields in the ip_recv_attr_t
	 * as we are called just to validate the
	 * message attached to the ICMP message.
	 *
	 * If we never pulled up since all of the message
	 * is in one single mblk, we can't remove the AH header
	 * by just setting the b_wptr to the beginning of the
	 * AH header. We need to allocate a mblk that can hold
	 * up until the inner IP header and copy them.
	 */
	alloc_size = iph_hdr_length + sizeof (icmph_t) + hdr_length;

	if ((mp1 = allocb(alloc_size, BPRI_LO)) == NULL) {
		IP_AH_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_nomem),
		    &ahstack->ah_dropper);
		return (NULL);
	}
	bcopy(mp->b_rptr, mp1->b_rptr, alloc_size);
	mp1->b_wptr += alloc_size;

	/*
	 * Skip whatever we have copied and as much of AH header
	 * possible. If we still have something left in the original
	 * message, tag on.
	 */
	mp->b_rptr = (uchar_t *)ipha + hdr_length + ah_length;

	if (mp->b_rptr != mp->b_wptr) {
		mp1->b_cont = mp;
	} else {
		if (mp->b_cont != NULL)
			mp1->b_cont = mp->b_cont;
		freeb(mp);
	}

	ipha = (ipha_t *)(mp1->b_rptr + iph_hdr_length + sizeof (icmph_t));
	ipha->ipha_protocol = nexthdr;
	length = ntohs(ipha->ipha_length);
	length -= ah_length;
	ipha->ipha_length = htons((uint16_t)length);
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = (uint16_t)ip_csum_hdr(ipha);

	return (mp1);
}

/*
 * IP calls this to validate the ICMP errors that
 * we got from the network.
 */
mblk_t *
ipsecah_icmp_error(mblk_t *data_mp, ip_recv_attr_t *ira)
{
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;

	if (ira->ira_flags & IRAF_IS_IPV4)
		return (ah_icmp_error_v4(data_mp, ira, ahstack));
	else
		return (ah_icmp_error_v6(data_mp, ira, ahstack));
}

static int
ah_fix_tlv_options_v6(uint8_t *oi_opt, uint8_t *pi_opt, uint_t ehdrlen,
    uint8_t hdr_type, boolean_t copy_always)
{
	uint8_t opt_type;
	uint_t optlen;

	ASSERT(hdr_type == IPPROTO_DSTOPTS || hdr_type == IPPROTO_HOPOPTS);

	/*
	 * Copy the next header and hdr ext. len of the HOP-by-HOP
	 * and Destination option.
	 */
	*pi_opt++ = *oi_opt++;
	*pi_opt++ = *oi_opt++;
	ehdrlen -= 2;

	/*
	 * Now handle all the TLV encoded options.
	 */
	while (ehdrlen != 0) {
		opt_type = *oi_opt;

		if (opt_type == IP6OPT_PAD1) {
			optlen = 1;
		} else {
			if (ehdrlen < 2)
				goto bad_opt;
			optlen = 2 + oi_opt[1];
			if (optlen > ehdrlen)
				goto bad_opt;
		}
		if (copy_always || !(opt_type & IP6OPT_MUTABLE)) {
			bcopy(oi_opt, pi_opt, optlen);
		} else {
			if (optlen == 1) {
				*pi_opt = 0;
			} else {
				/*
				 * Copy the type and data length fields.
				 * Zero the option data by skipping
				 * option type and option data len
				 * fields.
				 */
				*pi_opt = *oi_opt;
				*(pi_opt + 1) = *(oi_opt + 1);
				bzero(pi_opt + 2, optlen - 2);
			}
		}
		ehdrlen -= optlen;
		oi_opt += optlen;
		pi_opt += optlen;
	}
	return (0);
bad_opt:
	return (-1);
}

/*
 * Construct a pseudo header for AH, processing all the options.
 *
 * oip6h is the IPv6 header of the incoming or outgoing packet.
 * ip6h is the pointer to the pseudo headers IPV6 header. All
 * the space needed for the options have been allocated including
 * the AH header.
 *
 * If copy_always is set, all the options that appear before AH are copied
 * blindly without checking for IP6OPT_MUTABLE. This is used by
 * ah_auth_out_done().  Please refer to that function for details.
 *
 * NOTE :
 *
 * *  AH header is never copied in this function even if copy_always
 *    is set. It just returns the ah_offset - offset of the AH header
 *    and the caller needs to do the copying. This is done so that we
 *    don't have pass extra arguments e.g. SA etc. and also,
 *    it is not needed when ah_auth_out_done is calling this function.
 */
static uint_t
ah_fix_phdr_v6(ip6_t *ip6h, ip6_t *oip6h, boolean_t outbound,
    boolean_t copy_always)
{
	uint8_t	*oi_opt;
	uint8_t	*pi_opt;
	uint8_t nexthdr;
	uint8_t *prev_nexthdr;
	ip6_hbh_t *hbhhdr;
	ip6_dest_t *dsthdr = NULL;
	ip6_rthdr0_t *rthdr;
	int ehdrlen;
	ah_t *ah;
	int ret;

	/*
	 * In the outbound case for source route, ULP has already moved
	 * the first hop, which is now in ip6_dst. We need to re-arrange
	 * the header to make it look like how it would appear in the
	 * receiver i.e
	 *
	 * Because of ip_massage_options_v6 the header looks like
	 * this :
	 *
	 * ip6_src = S, ip6_dst = I1. followed by I2,I3,D.
	 *
	 * When it reaches the receiver, it would look like
	 *
	 * ip6_src = S, ip6_dst = D. followed by I1,I2,I3.
	 *
	 * NOTE : We assume that there are no problems with the options
	 * as IP should have already checked this.
	 */

	oi_opt = (uchar_t *)&oip6h[1];
	pi_opt = (uchar_t *)&ip6h[1];

	/*
	 * We set the prev_nexthdr properly in the pseudo header.
	 * After we finish authentication and come back from the
	 * algorithm module, pseudo header will become the real
	 * IP header.
	 */
	prev_nexthdr = (uint8_t *)&ip6h->ip6_nxt;
	nexthdr = oip6h->ip6_nxt;
	/* Assume IP has already stripped it */
	ASSERT(nexthdr != IPPROTO_FRAGMENT);
	ah = NULL;
	dsthdr = NULL;
	for (;;) {
		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
			hbhhdr = (ip6_hbh_t *)oi_opt;
			nexthdr = hbhhdr->ip6h_nxt;
			ehdrlen = 8 * (hbhhdr->ip6h_len + 1);
			ret = ah_fix_tlv_options_v6(oi_opt, pi_opt, ehdrlen,
			    IPPROTO_HOPOPTS, copy_always);
			/*
			 * Return a zero offset indicating error if there
			 * was error.
			 */
			if (ret == -1)
				return (0);
			hbhhdr = (ip6_hbh_t *)pi_opt;
			prev_nexthdr = (uint8_t *)&hbhhdr->ip6h_nxt;
			break;
		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr0_t *)oi_opt;
			nexthdr = rthdr->ip6r0_nxt;
			ehdrlen = 8 * (rthdr->ip6r0_len + 1);
			if (!copy_always && outbound) {
				int i, left;
				ip6_rthdr0_t *prthdr;
				in6_addr_t *ap, *pap;

				left = rthdr->ip6r0_segleft;
				prthdr = (ip6_rthdr0_t *)pi_opt;
				pap = (in6_addr_t *)(prthdr + 1);
				ap = (in6_addr_t *)(rthdr + 1);
				/*
				 * First eight bytes except seg_left
				 * does not change en route.
				 */
				bcopy(oi_opt, pi_opt, 8);
				prthdr->ip6r0_segleft = 0;
				/*
				 * First address has been moved to
				 * the destination address of the
				 * ip header by ip_massage_options_v6.
				 * And the real destination address is
				 * in the last address part of the
				 * option.
				 */
				*pap = oip6h->ip6_dst;
				for (i = 1; i < left - 1; i++)
					pap[i] = ap[i - 1];
				ip6h->ip6_dst = *(ap + left - 1);
			} else {
				bcopy(oi_opt, pi_opt, ehdrlen);
			}
			rthdr = (ip6_rthdr0_t *)pi_opt;
			prev_nexthdr = (uint8_t *)&rthdr->ip6r0_nxt;
			break;
		case IPPROTO_DSTOPTS:
			/*
			 * Destination options are tricky.  If there is
			 * a terminal (e.g. non-IPv6-extension) header
			 * following the destination options, don't
			 * reset prev_nexthdr or advance the AH insertion
			 * point and just treat this as a terminal header.
			 *
			 * If this is an inbound packet, just deal with
			 * it as is.
			 */
			dsthdr = (ip6_dest_t *)oi_opt;
			/*
			 * XXX I hope common-subexpression elimination
			 * saves us the double-evaluate.
			 */
			if (outbound && dsthdr->ip6d_nxt != IPPROTO_ROUTING &&
			    dsthdr->ip6d_nxt != IPPROTO_HOPOPTS)
				goto terminal_hdr;
			nexthdr = dsthdr->ip6d_nxt;
			ehdrlen = 8 * (dsthdr->ip6d_len + 1);
			ret = ah_fix_tlv_options_v6(oi_opt, pi_opt, ehdrlen,
			    IPPROTO_DSTOPTS, copy_always);
			/*
			 * Return a zero offset indicating error if there
			 * was error.
			 */
			if (ret == -1)
				return (0);
			break;
		case IPPROTO_AH:
			/*
			 * Be conservative in what you send.  We shouldn't
			 * see two same-scoped AH's in one packet.
			 * (Inner-IP-scoped AH will be hit by terminal
			 * header of IP or IPv6.)
			 */
			ASSERT(!outbound);
			return ((uint_t)(pi_opt - (uint8_t *)ip6h));
		default:
			ASSERT(outbound);
terminal_hdr:
			*prev_nexthdr = IPPROTO_AH;
			ah = (ah_t *)pi_opt;
			ah->ah_nexthdr = nexthdr;
			return ((uint_t)(pi_opt - (uint8_t *)ip6h));
		}
		pi_opt += ehdrlen;
		oi_opt += ehdrlen;
	}
	/* NOTREACHED */
}

static boolean_t
ah_finish_up(ah_t *phdr_ah, ah_t *inbound_ah, ipsa_t *assoc,
    int ah_data_sz, int ah_align_sz, ipsecah_stack_t *ahstack)
{
	int i;

	/*
	 * Padding :
	 *
	 * 1) Authentication data may have to be padded
	 * before ICV calculation if ICV is not a multiple
	 * of 64 bits. This padding is arbitrary and transmitted
	 * with the packet at the end of the authentication data.
	 * Payload length should include the padding bytes.
	 *
	 * 2) Explicit padding of the whole datagram may be
	 * required by the algorithm which need not be
	 * transmitted. It is assumed that this will be taken
	 * care by the algorithm module.
	 */
	bzero(phdr_ah + 1, ah_data_sz);	/* Zero out ICV for pseudo-hdr. */

	if (inbound_ah == NULL) {
		/* Outbound AH datagram. */

		phdr_ah->ah_length = (ah_align_sz >> 2) + 1;
		phdr_ah->ah_reserved = 0;
		phdr_ah->ah_spi = assoc->ipsa_spi;

		phdr_ah->ah_replay =
		    htonl(atomic_inc_32_nv(&assoc->ipsa_replay));
		if (phdr_ah->ah_replay == 0 && assoc->ipsa_replay_wsize != 0) {
			/*
			 * XXX We have replay counter wrapping.  We probably
			 * want to nuke this SA (and its peer).
			 */
			ipsec_assocfailure(info.mi_idnum, 0, 0,
			    SL_ERROR | SL_CONSOLE | SL_WARN,
			    "Outbound AH SA (0x%x), dst %s has wrapped "
			    "sequence.\n", phdr_ah->ah_spi,
			    assoc->ipsa_dstaddr, assoc->ipsa_addrfam,
			    ahstack->ipsecah_netstack);

			sadb_replay_delete(assoc);
			/* Caller will free phdr_mp and return NULL. */
			return (B_FALSE);
		}

		if (ah_data_sz != ah_align_sz) {
			uchar_t *pad = ((uchar_t *)phdr_ah + sizeof (ah_t) +
			    ah_data_sz);

			for (i = 0; i < (ah_align_sz - ah_data_sz); i++) {
				pad[i] = (uchar_t)i;	/* Fill the padding */
			}
		}
	} else {
		/* Inbound AH datagram. */
		phdr_ah->ah_nexthdr = inbound_ah->ah_nexthdr;
		phdr_ah->ah_length = inbound_ah->ah_length;
		phdr_ah->ah_reserved = 0;
		ASSERT(inbound_ah->ah_spi == assoc->ipsa_spi);
		phdr_ah->ah_spi = inbound_ah->ah_spi;
		phdr_ah->ah_replay = inbound_ah->ah_replay;

		if (ah_data_sz != ah_align_sz) {
			uchar_t *opad = ((uchar_t *)inbound_ah +
			    sizeof (ah_t) + ah_data_sz);
			uchar_t *pad = ((uchar_t *)phdr_ah + sizeof (ah_t) +
			    ah_data_sz);

			for (i = 0; i < (ah_align_sz - ah_data_sz); i++) {
				pad[i] = opad[i];	/* Copy the padding */
			}
		}
	}

	return (B_TRUE);
}

/*
 * Called upon failing the inbound ICV check. The message passed as
 * argument is freed.
 */
static void
ah_log_bad_auth(mblk_t *mp, ip_recv_attr_t *ira, ipsec_crypto_t *ic)
{
	boolean_t	isv4 = (ira->ira_flags & IRAF_IS_IPV4);
	ipsa_t		*assoc = ira->ira_ipsec_ah_sa;
	int		af;
	void		*addr;
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(mp->b_datap->db_type == M_DATA);

	mp->b_rptr -= ic->ic_skip_len;

	if (isv4) {
		ipha_t *ipha = (ipha_t *)mp->b_rptr;
		addr = &ipha->ipha_dst;
		af = AF_INET;
	} else {
		ip6_t *ip6h = (ip6_t *)mp->b_rptr;
		addr = &ip6h->ip6_dst;
		af = AF_INET6;
	}

	/*
	 * Log the event. Don't print to the console, block
	 * potential denial-of-service attack.
	 */
	AH_BUMP_STAT(ahstack, bad_auth);

	ipsec_assocfailure(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
	    "AH Authentication failed spi %x, dst_addr %s",
	    assoc->ipsa_spi, addr, af, ahstack->ipsecah_netstack);

	IP_AH_BUMP_STAT(ipss, in_discards);
	ip_drop_packet(mp, B_TRUE, ira->ira_ill,
	    DROPPER(ipss, ipds_ah_bad_auth),
	    &ahstack->ah_dropper);
}

/*
 * Kernel crypto framework callback invoked after completion of async
 * crypto requests for outbound packets.
 */
static void
ah_kcf_callback_outbound(void *arg, int status)
{
	mblk_t		*mp = (mblk_t *)arg;
	mblk_t		*async_mp;
	netstack_t	*ns;
	ipsec_stack_t	*ipss;
	ipsecah_stack_t	*ahstack;
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
		if (ixas.ixa_nce != NULL) {
			ill = ixas.ixa_nce->nce_ill;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", data_mp, ill);
		}
		freemsg(data_mp);
		goto done;
	}
	ns = ixas.ixa_ipst->ips_netstack;
	ahstack = ns->netstack_ipsecah;
	ipss = ns->netstack_ipsec;
	ill = ixas.ixa_nce->nce_ill;

	if (status == CRYPTO_SUCCESS) {
		data_mp = ah_auth_out_done(data_mp, &ixas, ic);
		if (data_mp == NULL)
			goto done;

		(void) ip_output_post_ipsec(data_mp, &ixas);
	} else {
		/* Outbound shouldn't see invalid MAC */
		ASSERT(status != CRYPTO_INVALID_MAC);

		ah1dbg(ahstack,
		    ("ah_kcf_callback_outbound: crypto failed with 0x%x\n",
		    status));
		AH_BUMP_STAT(ahstack, crypto_failures);
		AH_BUMP_STAT(ahstack, out_discards);

		ip_drop_packet(data_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_ah_crypto_failed),
		    &ahstack->ah_dropper);
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
ah_kcf_callback_inbound(void *arg, int status)
{
	mblk_t		*mp = (mblk_t *)arg;
	mblk_t		*async_mp;
	netstack_t	*ns;
	ipsec_stack_t	*ipss;
	ipsecah_stack_t	*ahstack;
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
	 * Extract the ip_xmit_attr_t from the first mblk.
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
	ahstack = ns->netstack_ipsecah;
	ipss = ns->netstack_ipsec;

	if (status == CRYPTO_SUCCESS) {
		data_mp = ah_auth_in_done(data_mp, &iras, ic);
		if (data_mp == NULL)
			goto done;

		/* finish IPsec processing */
		ip_input_post_ipsec(data_mp, &iras);

	} else if (status == CRYPTO_INVALID_MAC) {
		ah_log_bad_auth(data_mp, &iras, ic);
	} else {
		ah1dbg(ahstack,
		    ("ah_kcf_callback_inbound: crypto failed with 0x%x\n",
		    status));
		AH_BUMP_STAT(ahstack, crypto_failures);
		IP_AH_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(data_mp, B_TRUE, iras.ira_ill,
		    DROPPER(ipss, ipds_ah_crypto_failed),
		    &ahstack->ah_dropper);
		BUMP_MIB(iras.ira_ill->ill_ip_mib, ipIfStatsInDiscards);
	}
done:
	ira_cleanup(&iras, B_TRUE);
	(void) ipsec_free_crypto_data(mp);
}

/*
 * Invoked on kernel crypto failure during inbound and outbound processing.
 */
static void
ah_crypto_failed(mblk_t *data_mp, boolean_t is_inbound, int kef_rc,
    ill_t *ill, ipsecah_stack_t *ahstack)
{
	ipsec_stack_t	*ipss = ahstack->ipsecah_netstack->netstack_ipsec;

	ah1dbg(ahstack, ("crypto failed for %s AH with 0x%x\n",
	    is_inbound ? "inbound" : "outbound", kef_rc));
	ip_drop_packet(data_mp, is_inbound, ill,
	    DROPPER(ipss, ipds_ah_crypto_failed),
	    &ahstack->ah_dropper);
	AH_BUMP_STAT(ahstack, crypto_failures);
	if (is_inbound)
		IP_AH_BUMP_STAT(ipss, in_discards);
	else
		AH_BUMP_STAT(ahstack, out_discards);
}

/*
 * Helper macros for the ah_submit_req_{inbound,outbound}() functions.
 */

/*
 * A statement-equivalent macro, _cr MUST point to a modifiable
 * crypto_call_req_t.
 */
#define	AH_INIT_CALLREQ(_cr, _mp, _callback)		\
	(_cr)->cr_flag = CRYPTO_SKIP_REQID|CRYPTO_ALWAYS_QUEUE;	\
	(_cr)->cr_callback_arg = (_mp);				\
	(_cr)->cr_callback_func = (_callback)

#define	AH_INIT_CRYPTO_DATA(data, msglen, mblk) {			\
	(data)->cd_format = CRYPTO_DATA_MBLK;				\
	(data)->cd_mp = mblk;						\
	(data)->cd_offset = 0;						\
	(data)->cd_length = msglen;					\
}

#define	AH_INIT_CRYPTO_MAC(mac, icvlen, icvbuf) {			\
	(mac)->cd_format = CRYPTO_DATA_RAW;				\
	(mac)->cd_offset = 0;						\
	(mac)->cd_length = icvlen;					\
	(mac)->cd_raw.iov_base = icvbuf;				\
	(mac)->cd_raw.iov_len = icvlen;					\
}

/*
 * Submit an inbound packet for processing by the crypto framework.
 */
static mblk_t *
ah_submit_req_inbound(mblk_t *phdr_mp, ip_recv_attr_t *ira,
    size_t skip_len, uint32_t ah_offset, ipsa_t *assoc)
{
	int kef_rc;
	mblk_t *mp;
	crypto_call_req_t call_req, *callrp;
	uint_t icv_len = assoc->ipsa_mac_len;
	crypto_ctx_template_t ctx_tmpl;
	ipsecah_stack_t	*ahstack;
	ipsec_crypto_t	*ic, icstack;
	boolean_t force = (assoc->ipsa_flags & IPSA_F_ASYNC);

	ahstack = ira->ira_ill->ill_ipst->ips_netstack->netstack_ipsecah;

	ASSERT(phdr_mp != NULL);
	ASSERT(phdr_mp->b_datap->db_type == M_DATA);

	if (force) {
		/* We are doing asynch; allocate mblks to hold state */
		if ((mp = ip_recv_attr_to_mblk(ira)) == NULL ||
		    (mp = ipsec_add_crypto_data(mp, &ic)) == NULL) {
			BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", phdr_mp,
			    ira->ira_ill);
			freemsg(phdr_mp);
			return (NULL);
		}

		linkb(mp, phdr_mp);
		callrp = &call_req;
		AH_INIT_CALLREQ(callrp, mp, ah_kcf_callback_inbound);
	} else {
		/*
		 * If we know we are going to do sync then ipsec_crypto_t
		 * should be on the stack.
		 */
		ic = &icstack;
		bzero(ic, sizeof (*ic));
		callrp = NULL;
	}

	/* init arguments for the crypto framework */
	AH_INIT_CRYPTO_DATA(&ic->ic_crypto_data, AH_MSGSIZE(phdr_mp),
	    phdr_mp);

	AH_INIT_CRYPTO_MAC(&ic->ic_crypto_mac, icv_len,
	    (char *)phdr_mp->b_cont->b_rptr - skip_len + ah_offset +
	    sizeof (ah_t));

	ic->ic_skip_len = skip_len;

	IPSEC_CTX_TMPL(assoc, ipsa_authtmpl, IPSEC_ALG_AUTH, ctx_tmpl);

	/* call KEF to do the MAC operation */
	kef_rc = crypto_mac_verify(&assoc->ipsa_amech,
	    &ic->ic_crypto_data, &assoc->ipsa_kcfauthkey, ctx_tmpl,
	    &ic->ic_crypto_mac, callrp);

	switch (kef_rc) {
	case CRYPTO_SUCCESS:
		AH_BUMP_STAT(ahstack, crypto_sync);
		phdr_mp = ah_auth_in_done(phdr_mp, ira, ic);
		if (force) {
			/* Free mp after we are done with ic */
			mp = ipsec_free_crypto_data(mp);
			(void) ip_recv_attr_free_mblk(mp);
		}
		return (phdr_mp);
	case CRYPTO_QUEUED:
		/* ah_kcf_callback_inbound() will be invoked on completion */
		AH_BUMP_STAT(ahstack, crypto_async);
		return (NULL);
	case CRYPTO_INVALID_MAC:
		/* Free mp after we are done with ic */
		AH_BUMP_STAT(ahstack, crypto_sync);
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		ah_log_bad_auth(phdr_mp, ira, ic);
		/* phdr_mp was passed to ip_drop_packet */
		if (force) {
			mp = ipsec_free_crypto_data(mp);
			(void) ip_recv_attr_free_mblk(mp);
		}
		return (NULL);
	}

	if (force) {
		mp = ipsec_free_crypto_data(mp);
		phdr_mp = ip_recv_attr_free_mblk(mp);
	}
	BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
	ah_crypto_failed(phdr_mp, B_TRUE, kef_rc, ira->ira_ill, ahstack);
	/* phdr_mp was passed to ip_drop_packet */
	return (NULL);
}

/*
 * Submit an outbound packet for processing by the crypto framework.
 */
static mblk_t *
ah_submit_req_outbound(mblk_t *phdr_mp, ip_xmit_attr_t *ixa,
    size_t skip_len, ipsa_t *assoc)
{
	int kef_rc;
	mblk_t *mp;
	crypto_call_req_t call_req, *callrp;
	uint_t icv_len = assoc->ipsa_mac_len;
	ipsecah_stack_t	*ahstack;
	ipsec_crypto_t	*ic, icstack;
	ill_t		*ill = ixa->ixa_nce->nce_ill;
	boolean_t force = (assoc->ipsa_flags & IPSA_F_ASYNC);

	ahstack = ill->ill_ipst->ips_netstack->netstack_ipsecah;

	ASSERT(phdr_mp != NULL);
	ASSERT(phdr_mp->b_datap->db_type == M_DATA);

	if (force) {
		/* We are doing asynch; allocate mblks to hold state */
		if ((mp = ip_xmit_attr_to_mblk(ixa)) == NULL ||
		    (mp = ipsec_add_crypto_data(mp, &ic)) == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", phdr_mp, ill);
			freemsg(phdr_mp);
			return (NULL);
		}
		linkb(mp, phdr_mp);
		callrp = &call_req;
		AH_INIT_CALLREQ(callrp, mp, ah_kcf_callback_outbound);
	} else {
		/*
		 * If we know we are going to do sync then ipsec_crypto_t
		 * should be on the stack.
		 */
		ic = &icstack;
		bzero(ic, sizeof (*ic));
		callrp = NULL;
	}

	/* init arguments for the crypto framework */
	AH_INIT_CRYPTO_DATA(&ic->ic_crypto_data, AH_MSGSIZE(phdr_mp),
	    phdr_mp);

	AH_INIT_CRYPTO_MAC(&ic->ic_crypto_mac, icv_len,
	    (char *)phdr_mp->b_wptr);

	ic->ic_skip_len = skip_len;

	ASSERT(ixa->ixa_ipsec_ah_sa != NULL);

	/* call KEF to do the MAC operation */
	kef_rc = crypto_mac(&assoc->ipsa_amech, &ic->ic_crypto_data,
	    &assoc->ipsa_kcfauthkey, assoc->ipsa_authtmpl,
	    &ic->ic_crypto_mac, callrp);

	switch (kef_rc) {
	case CRYPTO_SUCCESS:
		AH_BUMP_STAT(ahstack, crypto_sync);
		phdr_mp = ah_auth_out_done(phdr_mp, ixa, ic);
		if (force) {
			/* Free mp after we are done with ic */
			mp = ipsec_free_crypto_data(mp);
			(void) ip_xmit_attr_free_mblk(mp);
		}
		return (phdr_mp);
	case CRYPTO_QUEUED:
		/* ah_kcf_callback_outbound() will be invoked on completion */
		AH_BUMP_STAT(ahstack, crypto_async);
		return (NULL);
	}

	if (force) {
		mp = ipsec_free_crypto_data(mp);
		phdr_mp = ip_xmit_attr_free_mblk(mp);
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
	ah_crypto_failed(phdr_mp, B_FALSE, kef_rc, NULL, ahstack);
	/* phdr_mp was passed to ip_drop_packet */
	return (NULL);
}

/*
 * This function constructs a pseudo header by looking at the IP header
 * and options if any. This is called for both outbound and inbound,
 * before computing the ICV.
 */
static mblk_t *
ah_process_ip_options_v6(mblk_t *mp, ipsa_t *assoc, int *length_to_skip,
    uint_t ah_data_sz, boolean_t outbound, ipsecah_stack_t *ahstack)
{
	ip6_t	*ip6h;
	ip6_t	*oip6h;
	mblk_t 	*phdr_mp;
	int option_length;
	uint_t	ah_align_sz;
	uint_t ah_offset;
	int hdr_size;

	/*
	 * Allocate space for the authentication data also. It is
	 * useful both during the ICV calculation where we need to
	 * feed in zeroes and while sending the datagram back to IP
	 * where we will be using the same space.
	 *
	 * We need to allocate space for padding bytes if it is not
	 * a multiple of IPV6_PADDING_ALIGN.
	 *
	 * In addition, we allocate space for the ICV computed by
	 * the kernel crypto framework, saving us a separate kmem
	 * allocation down the road.
	 */

	ah_align_sz = P2ALIGN(ah_data_sz + IPV6_PADDING_ALIGN - 1,
	    IPV6_PADDING_ALIGN);

	ASSERT(ah_align_sz >= ah_data_sz);

	hdr_size = ipsec_ah_get_hdr_size_v6(mp, B_FALSE);
	option_length = hdr_size - IPV6_HDR_LEN;

	/* This was not included in ipsec_ah_get_hdr_size_v6() */
	hdr_size += (sizeof (ah_t) + ah_align_sz);

	if (!outbound && (MBLKL(mp) < hdr_size)) {
		/*
		 * We have post-AH header options in a separate mblk,
		 * a pullup is required.
		 */
		if (!pullupmsg(mp, hdr_size))
			return (NULL);
	}

	if ((phdr_mp = allocb_tmpl(hdr_size + ah_data_sz, mp)) == NULL) {
		return (NULL);
	}

	oip6h = (ip6_t *)mp->b_rptr;

	/*
	 * Form the basic IP header first. Zero out the header
	 * so that the mutable fields are zeroed out.
	 */
	ip6h = (ip6_t *)phdr_mp->b_rptr;
	bzero(ip6h, sizeof (ip6_t));
	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;

	if (outbound) {
		/*
		 * Include the size of AH and authentication data.
		 * This is how our recipient would compute the
		 * authentication data. Look at what we do in the
		 * inbound case below.
		 */
		ip6h->ip6_plen = htons(ntohs(oip6h->ip6_plen) +
		    sizeof (ah_t) + ah_align_sz);
	} else {
		ip6h->ip6_plen = oip6h->ip6_plen;
	}

	ip6h->ip6_src = oip6h->ip6_src;
	ip6h->ip6_dst = oip6h->ip6_dst;

	*length_to_skip = IPV6_HDR_LEN;
	if (option_length == 0) {
		/* Form the AH header */
		ip6h->ip6_nxt = IPPROTO_AH;
		((ah_t *)(ip6h + 1))->ah_nexthdr = oip6h->ip6_nxt;
		ah_offset = *length_to_skip;
	} else {
		ip6h->ip6_nxt = oip6h->ip6_nxt;
		/* option_length does not include the AH header's size */
		*length_to_skip += option_length;

		ah_offset = ah_fix_phdr_v6(ip6h, oip6h, outbound, B_FALSE);
		if (ah_offset == 0) {
			return (NULL);
		}
	}

	if (!ah_finish_up(((ah_t *)((uint8_t *)ip6h + ah_offset)),
	    (outbound ? NULL : ((ah_t *)((uint8_t *)oip6h + ah_offset))),
	    assoc, ah_data_sz, ah_align_sz, ahstack)) {
		freeb(phdr_mp);
		/*
		 * Returning NULL will tell the caller to
		 * IPSA_REFELE(), free the memory, etc.
		 */
		return (NULL);
	}

	phdr_mp->b_wptr = ((uint8_t *)ip6h + ah_offset + sizeof (ah_t) +
	    ah_align_sz);
	if (!outbound)
		*length_to_skip += sizeof (ah_t) + ah_align_sz;
	return (phdr_mp);
}

/*
 * This function constructs a pseudo header by looking at the IP header
 * and options if any. This is called for both outbound and inbound,
 * before computing the ICV.
 */
static mblk_t *
ah_process_ip_options_v4(mblk_t *mp, ipsa_t *assoc, int *length_to_skip,
    uint_t ah_data_sz, boolean_t outbound, ipsecah_stack_t *ahstack)
{
	ipoptp_t opts;
	uint32_t option_length;
	ipha_t	*ipha;
	ipha_t	*oipha;
	mblk_t 	*phdr_mp;
	int	 size;
	uchar_t	*optptr;
	uint8_t optval;
	uint8_t optlen;
	ipaddr_t dst;
	uint32_t v_hlen_tos_len;
	int ip_hdr_length;
	uint_t	ah_align_sz;
	uint32_t off;

#ifdef	_BIG_ENDIAN
#define	V_HLEN	(v_hlen_tos_len >> 24)
#else
#define	V_HLEN	(v_hlen_tos_len & 0xFF)
#endif

	oipha = (ipha_t *)mp->b_rptr;
	v_hlen_tos_len = ((uint32_t *)oipha)[0];

	/*
	 * Allocate space for the authentication data also. It is
	 * useful both during the ICV calculation where we need to
	 * feed in zeroes and while sending the datagram back to IP
	 * where we will be using the same space.
	 *
	 * We need to allocate space for padding bytes if it is not
	 * a multiple of IPV4_PADDING_ALIGN.
	 *
	 * In addition, we allocate space for the ICV computed by
	 * the kernel crypto framework, saving us a separate kmem
	 * allocation down the road.
	 */

	ah_align_sz = P2ALIGN(ah_data_sz + IPV4_PADDING_ALIGN - 1,
	    IPV4_PADDING_ALIGN);

	ASSERT(ah_align_sz >= ah_data_sz);

	size = IP_SIMPLE_HDR_LENGTH + sizeof (ah_t) + ah_align_sz +
	    ah_data_sz;

	if (V_HLEN != IP_SIMPLE_HDR_VERSION) {
		option_length = oipha->ipha_version_and_hdr_length -
		    (uint8_t)((IP_VERSION << 4) +
		    IP_SIMPLE_HDR_LENGTH_IN_WORDS);
		option_length <<= 2;
		size += option_length;
	}

	if ((phdr_mp = allocb_tmpl(size, mp)) == NULL) {
		return (NULL);
	}

	/*
	 * Form the basic IP header first.
	 */
	ipha = (ipha_t *)phdr_mp->b_rptr;
	ipha->ipha_version_and_hdr_length = oipha->ipha_version_and_hdr_length;
	ipha->ipha_type_of_service = 0;

	if (outbound) {
		/*
		 * Include the size of AH and authentication data.
		 * This is how our recipient would compute the
		 * authentication data. Look at what we do in the
		 * inbound case below.
		 */
		ipha->ipha_length = ntohs(htons(oipha->ipha_length) +
		    sizeof (ah_t) + ah_align_sz);
	} else {
		ipha->ipha_length = oipha->ipha_length;
	}

	ipha->ipha_ident = oipha->ipha_ident;
	ipha->ipha_fragment_offset_and_flags = 0;
	ipha->ipha_ttl = 0;
	ipha->ipha_protocol = IPPROTO_AH;
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_src = oipha->ipha_src;
	ipha->ipha_dst = dst = oipha->ipha_dst;

	/*
	 * If there is no option to process return now.
	 */
	ip_hdr_length = IP_SIMPLE_HDR_LENGTH;

	if (V_HLEN == IP_SIMPLE_HDR_VERSION) {
		/* Form the AH header */
		goto ah_hdr;
	}

	ip_hdr_length += option_length;

	/*
	 * We have options. In the outbound case for source route,
	 * ULP has already moved the first hop, which is now in
	 * ipha_dst. We need the final destination for the calculation
	 * of authentication data. And also make sure that mutable
	 * and experimental fields are zeroed out in the IP options.
	 */

	bcopy(&oipha[1], &ipha[1], option_length);

	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		optptr = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		switch (optval) {
		case IPOPT_EXTSEC:
		case IPOPT_COMSEC:
		case IPOPT_RA:
		case IPOPT_SDMDD:
		case IPOPT_SECURITY:
			/*
			 * These options are Immutable, leave them as-is.
			 * Note that IPOPT_NOP is also Immutable, but it
			 * was skipped by ipoptp_next() and thus remains
			 * intact in the header.
			 */
			break;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0)
				goto bad_ipv4opt;
			/*
			 * These two are mutable and will be zeroed, but
			 * first get the final destination.
			 */
			off = optptr[IPOPT_OFFSET];
			/*
			 * If one of the conditions is true, it means
			 * end of options and dst already has the right
			 * value. So, just fall through.
			 */
			if (!(optlen < IP_ADDR_LEN || off > optlen - 3)) {
				off = optlen - IP_ADDR_LEN;
				bcopy(&optptr[off], &dst, IP_ADDR_LEN);
			}
			/* FALLTHRU */
		case IPOPT_RR:
		case IPOPT_TS:
		case IPOPT_SATID:
		default:
			/*
			 * optlen should include from the beginning of an
			 * option.
			 * NOTE : Stream Identifier Option (SID): RFC 791
			 * shows the bit pattern of optlen as 2 and documents
			 * the length as 4. We assume it to be 2 here.
			 */
			bzero(optptr, optlen);
			break;
		}
	}

	if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
bad_ipv4opt:
		ah1dbg(ahstack, ("AH : bad IPv4 option"));
		freeb(phdr_mp);
		return (NULL);
	}

	/*
	 * Don't change ipha_dst for an inbound datagram as it points
	 * to the right value. Only for the outbound with LSRR/SSRR,
	 * because of ip_massage_options called by the ULP, ipha_dst
	 * points to the first hop and we need to use the final
	 * destination for computing the ICV.
	 */

	if (outbound)
		ipha->ipha_dst = dst;
ah_hdr:
	((ah_t *)((uint8_t *)ipha + ip_hdr_length))->ah_nexthdr =
	    oipha->ipha_protocol;
	if (!ah_finish_up(((ah_t *)((uint8_t *)ipha + ip_hdr_length)),
	    (outbound ? NULL : ((ah_t *)((uint8_t *)oipha + ip_hdr_length))),
	    assoc, ah_data_sz, ah_align_sz, ahstack)) {
		freeb(phdr_mp);
		/*
		 * Returning NULL will tell the caller to IPSA_REFELE(), free
		 * the memory, etc.
		 */
		return (NULL);
	}

	phdr_mp->b_wptr = ((uchar_t *)ipha + ip_hdr_length +
	    sizeof (ah_t) + ah_align_sz);

	ASSERT(phdr_mp->b_wptr <= phdr_mp->b_datap->db_lim);
	if (outbound)
		*length_to_skip = ip_hdr_length;
	else
		*length_to_skip = ip_hdr_length + sizeof (ah_t) + ah_align_sz;
	return (phdr_mp);
}

/*
 * Authenticate an outbound datagram. This function is called
 * whenever IP sends an outbound datagram that needs authentication.
 * Returns a modified packet if done. Returns NULL if error or queued.
 * If error return then ipIfStatsOutDiscards has been increased.
 */
static mblk_t *
ah_outbound(mblk_t *data_mp, ip_xmit_attr_t *ixa)
{
	mblk_t *phdr_mp;
	ipsa_t *assoc;
	int length_to_skip;
	uint_t ah_align_sz;
	uint_t age_bytes;
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ill_t		*ill = ixa->ixa_nce->nce_ill;
	boolean_t	need_refrele = B_FALSE;

	/*
	 * Construct the chain of mblks
	 *
	 * PSEUDO_HDR->DATA
	 *
	 * one by one.
	 */

	AH_BUMP_STAT(ahstack, out_requests);

	ASSERT(data_mp->b_datap->db_type == M_DATA);

	assoc = ixa->ixa_ipsec_ah_sa;
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
			    DROPPER(ipss, ipds_ah_nomem),
			    &ahstack->ah_dropper);
			return (NULL);
		}
		need_refrele = B_TRUE;

		label_hold(assoc->ipsa_otsl);
		ip_xmit_attr_replace_tsl(ixa, assoc->ipsa_otsl);

		data_mp = sadb_whack_label(data_mp, assoc, ixa,
		    DROPPER(ipss, ipds_ah_nomem), &ahstack->ah_dropper);
		if (data_mp == NULL) {
			/* Packet dropped by sadb_whack_label */
			ixa_refrele(ixa);
			return (NULL);
		}
	}

	/*
	 * Age SA according to number of bytes that will be sent after
	 * adding the AH header, ICV, and padding to the packet.
	 */

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t *ipha = (ipha_t *)data_mp->b_rptr;
		ah_align_sz = P2ALIGN(assoc->ipsa_mac_len +
		    IPV4_PADDING_ALIGN - 1, IPV4_PADDING_ALIGN);
		age_bytes = ntohs(ipha->ipha_length) + sizeof (ah_t) +
		    ah_align_sz;
	} else {
		ip6_t *ip6h = (ip6_t *)data_mp->b_rptr;
		ah_align_sz = P2ALIGN(assoc->ipsa_mac_len +
		    IPV6_PADDING_ALIGN - 1, IPV6_PADDING_ALIGN);
		age_bytes = sizeof (ip6_t) + ntohs(ip6h->ip6_plen) +
		    sizeof (ah_t) + ah_align_sz;
	}

	if (!ah_age_bytes(assoc, age_bytes, B_FALSE)) {
		/* rig things as if ipsec_getassocbyconn() failed */
		ipsec_assocfailure(info.mi_idnum, 0, 0, SL_ERROR | SL_WARN,
		    "AH association 0x%x, dst %s had bytes expire.\n",
		    ntohl(assoc->ipsa_spi), assoc->ipsa_dstaddr, AF_INET,
		    ahstack->ipsecah_netstack);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards", data_mp, ill);
		freemsg(data_mp);
		if (need_refrele)
			ixa_refrele(ixa);
		return (NULL);
	}

	/*
	 * XXX We need to have fixed up the outer label before we get here.
	 * (AH is computing the checksum over the outer label).
	 */

	/*
	 * Insert pseudo header:
	 * [IP, ULP] => [IP, AH, ICV] -> ULP
	 */

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		phdr_mp = ah_process_ip_options_v4(data_mp, assoc,
		    &length_to_skip, assoc->ipsa_mac_len, B_TRUE, ahstack);
	} else {
		phdr_mp = ah_process_ip_options_v6(data_mp, assoc,
		    &length_to_skip, assoc->ipsa_mac_len, B_TRUE, ahstack);
	}

	if (phdr_mp == NULL) {
		AH_BUMP_STAT(ahstack, out_discards);
		ip_drop_packet(data_mp, B_FALSE, ixa->ixa_nce->nce_ill,
		    DROPPER(ipss, ipds_ah_bad_v4_opts),
		    &ahstack->ah_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		if (need_refrele)
			ixa_refrele(ixa);
		return (NULL);
	}

	phdr_mp->b_cont = data_mp;
	data_mp->b_rptr += length_to_skip;
	data_mp = phdr_mp;

	/*
	 * At this point data_mp points to
	 * an mblk containing the pseudo header (IP header,
	 * AH header, and ICV with mutable fields zero'ed out).
	 * mp points to the mblk containing the ULP data. The original
	 * IP header is kept before the ULP data in data_mp.
	 */

	/* submit MAC request to KCF */
	data_mp = ah_submit_req_outbound(data_mp, ixa, length_to_skip, assoc);
	if (need_refrele)
		ixa_refrele(ixa);
	return (data_mp);
}

static mblk_t *
ah_inbound(mblk_t *data_mp, void *arg, ip_recv_attr_t *ira)
{
	ah_t		*ah = (ah_t *)arg;
	ipsa_t		*assoc = ira->ira_ipsec_ah_sa;
	int		length_to_skip;
	int		ah_length;
	mblk_t		*phdr_mp;
	uint32_t	ah_offset;
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT(assoc != NULL);

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
	if (!sadb_replay_peek(assoc, ah->ah_replay)) {
		AH_BUMP_STAT(ahstack, replay_early_failures);
		IP_AH_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(data_mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_early_replay),
		    &ahstack->ah_dropper);
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		return (NULL);
	}

	/*
	 * The offset of the AH header can be computed from its pointer
	 * within the data mblk, which was pulled up until the AH header
	 * by ipsec_inbound_ah_sa() during SA selection.
	 */
	ah_offset = (uchar_t *)ah - data_mp->b_rptr;

	/*
	 * We need to pullup until the ICV before we call
	 * ah_process_ip_options_v6.
	 */
	ah_length = (ah->ah_length << 2) + 8;

	/*
	 * NOTE : If we want to use any field of IP/AH header, you need
	 * to re-assign following the pullup.
	 */
	if (((uchar_t *)ah + ah_length) > data_mp->b_wptr) {
		if (!pullupmsg(data_mp, (uchar_t *)ah + ah_length -
		    data_mp->b_rptr)) {
			(void) ipsec_rl_strlog(ns, info.mi_idnum, 0, 0,
			    SL_WARN | SL_ERROR,
			    "ah_inbound: Small AH header\n");
			IP_AH_BUMP_STAT(ipss, in_discards);
			ip_drop_packet(data_mp, B_TRUE, ira->ira_ill,
			    DROPPER(ipss, ipds_ah_nomem),
			    &ahstack->ah_dropper);
			BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
			return (NULL);
		}
	}

	/*
	 * Insert pseudo header:
	 * [IP, ULP] => [IP, AH, ICV] -> ULP
	 */
	if (ira->ira_flags & IRAF_IS_IPV4) {
		phdr_mp = ah_process_ip_options_v4(data_mp, assoc,
		    &length_to_skip, assoc->ipsa_mac_len, B_FALSE, ahstack);
	} else {
		phdr_mp = ah_process_ip_options_v6(data_mp, assoc,
		    &length_to_skip, assoc->ipsa_mac_len, B_FALSE, ahstack);
	}

	if (phdr_mp == NULL) {
		IP_AH_BUMP_STAT(ipss, in_discards);
		ip_drop_packet(data_mp, B_TRUE, ira->ira_ill,
		    ((ira->ira_flags & IRAF_IS_IPV4) ?
		    DROPPER(ipss, ipds_ah_bad_v4_opts) :
		    DROPPER(ipss, ipds_ah_bad_v6_hdrs)),
		    &ahstack->ah_dropper);
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		return (NULL);
	}

	phdr_mp->b_cont = data_mp;
	data_mp->b_rptr += length_to_skip;
	data_mp = phdr_mp;

	/* submit request to KCF */
	return (ah_submit_req_inbound(data_mp, ira, length_to_skip, ah_offset,
	    assoc));
}

/*
 * Invoked after processing of an inbound packet by the
 * kernel crypto framework. Called by ah_submit_req() for a sync request,
 * or by the kcf callback for an async request.
 * Returns NULL if the mblk chain is consumed.
 */
static mblk_t *
ah_auth_in_done(mblk_t *phdr_mp, ip_recv_attr_t *ira, ipsec_crypto_t *ic)
{
	ipha_t *ipha;
	uint_t ah_offset = 0;
	mblk_t *mp;
	int align_len, newpos;
	ah_t *ah;
	uint32_t length;
	uint32_t *dest32;
	uint8_t *dest;
	boolean_t isv4;
	ip6_t *ip6h;
	uint_t icv_len;
	ipsa_t *assoc;
	kstat_named_t *counter;
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	isv4 = (ira->ira_flags & IRAF_IS_IPV4);
	assoc = ira->ira_ipsec_ah_sa;
	icv_len = (uint_t)ic->ic_crypto_mac.cd_raw.iov_len;

	if (phdr_mp == NULL) {
		ip_drop_packet(phdr_mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_nomem),
		    &ahstack->ah_dropper);
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		return (NULL);
	}

	mp = phdr_mp->b_cont;
	if (mp == NULL) {
		ip_drop_packet(phdr_mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_ah_nomem),
		    &ahstack->ah_dropper);
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		return (NULL);
	}
	mp->b_rptr -= ic->ic_skip_len;

	ah_set_usetime(assoc, B_TRUE);

	if (isv4) {
		ipha = (ipha_t *)mp->b_rptr;
		ah_offset = ipha->ipha_version_and_hdr_length -
		    (uint8_t)((IP_VERSION << 4));
		ah_offset <<= 2;
		align_len = P2ALIGN(icv_len + IPV4_PADDING_ALIGN - 1,
		    IPV4_PADDING_ALIGN);
	} else {
		ip6h = (ip6_t *)mp->b_rptr;
		ah_offset = ipsec_ah_get_hdr_size_v6(mp, B_TRUE);
		ASSERT((mp->b_wptr - mp->b_rptr) >= ah_offset);
		align_len = P2ALIGN(icv_len + IPV6_PADDING_ALIGN - 1,
		    IPV6_PADDING_ALIGN);
	}

	ah = (ah_t *)(mp->b_rptr + ah_offset);
	newpos = sizeof (ah_t) + align_len;

	/*
	 * We get here only when authentication passed.
	 */

	ah3dbg(ahstack, ("AH succeeded, checking replay\n"));
	AH_BUMP_STAT(ahstack, good_auth);

	if (!sadb_replay_check(assoc, ah->ah_replay)) {
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
		 * Log the event. As of now we print out an event.
		 * Do not print the replay failure number, or else
		 * syslog cannot collate the error messages.  Printing
		 * the replay number that failed (or printing to the
		 * console) opens a denial-of-service attack.
		 */
		AH_BUMP_STAT(ahstack, replay_failures);
		ipsec_assocfailure(info.mi_idnum, 0, 0,
		    SL_ERROR | SL_WARN,
		    "Replay failed for AH spi %x, dst_addr %s",
		    assoc->ipsa_spi, addr, af, ahstack->ipsecah_netstack);
		counter = DROPPER(ipss, ipds_ah_replay);
		goto ah_in_discard;
	}

	/*
	 * We need to remove the AH header from the original
	 * datagram. Best way to do this is to move the pre-AH headers
	 * forward in the (relatively simple) IPv4 case.  In IPv6, it's
	 * a bit more complicated because of IPv6's next-header chaining,
	 * but it's doable.
	 */
	if (isv4) {
		/*
		 * Assign the right protocol, adjust the length as we
		 * are removing the AH header and adjust the checksum to
		 * account for the protocol and length.
		 */
		length = ntohs(ipha->ipha_length);
		if (!ah_age_bytes(assoc, length, B_TRUE)) {
			/* The ipsa has hit hard expiration, LOG and AUDIT. */
			ipsec_assocfailure(info.mi_idnum, 0, 0,
			    SL_ERROR | SL_WARN,
			    "AH Association 0x%x, dst %s had bytes expire.\n",
			    assoc->ipsa_spi, assoc->ipsa_dstaddr,
			    AF_INET, ahstack->ipsecah_netstack);
			AH_BUMP_STAT(ahstack, bytes_expired);
			counter = DROPPER(ipss, ipds_ah_bytes_expire);
			goto ah_in_discard;
		}
		ipha->ipha_protocol = ah->ah_nexthdr;
		length -= newpos;

		ipha->ipha_length = htons((uint16_t)length);
		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = (uint16_t)ip_csum_hdr(ipha);
	} else {
		uchar_t *whereptr;
		int hdrlen;
		uint8_t *nexthdr;
		ip6_hbh_t *hbhhdr;
		ip6_dest_t *dsthdr;
		ip6_rthdr0_t *rthdr;

		/*
		 * Make phdr_mp hold until the AH header and make
		 * mp hold everything past AH header.
		 */
		length = ntohs(ip6h->ip6_plen);
		if (!ah_age_bytes(assoc, length + sizeof (ip6_t), B_TRUE)) {
			/* The ipsa has hit hard expiration, LOG and AUDIT. */
			ipsec_assocfailure(info.mi_idnum, 0, 0,
			    SL_ERROR | SL_WARN,
			    "AH Association 0x%x, dst %s had bytes "
			    "expire.\n", assoc->ipsa_spi, &ip6h->ip6_dst,
			    AF_INET6, ahstack->ipsecah_netstack);
			AH_BUMP_STAT(ahstack, bytes_expired);
			counter = DROPPER(ipss, ipds_ah_bytes_expire);
			goto ah_in_discard;
		}

		/*
		 * Update the next header field of the header preceding
		 * AH with the next header field of AH. Start with the
		 * IPv6 header and proceed with the extension headers
		 * until we find what we're looking for.
		 */
		nexthdr = &ip6h->ip6_nxt;
		whereptr =  (uchar_t *)ip6h;
		hdrlen = sizeof (ip6_t);

		while (*nexthdr != IPPROTO_AH) {
			whereptr += hdrlen;
			/* Assume IP has already stripped it */
			ASSERT(*nexthdr != IPPROTO_FRAGMENT);
			switch (*nexthdr) {
			case IPPROTO_HOPOPTS:
				hbhhdr = (ip6_hbh_t *)whereptr;
				nexthdr = &hbhhdr->ip6h_nxt;
				hdrlen = 8 * (hbhhdr->ip6h_len + 1);
				break;
			case IPPROTO_DSTOPTS:
				dsthdr = (ip6_dest_t *)whereptr;
				nexthdr = &dsthdr->ip6d_nxt;
				hdrlen = 8 * (dsthdr->ip6d_len + 1);
				break;
			case IPPROTO_ROUTING:
				rthdr = (ip6_rthdr0_t *)whereptr;
				nexthdr = &rthdr->ip6r0_nxt;
				hdrlen = 8 * (rthdr->ip6r0_len + 1);
				break;
			}
		}
		*nexthdr = ah->ah_nexthdr;
		length -= newpos;
		ip6h->ip6_plen = htons((uint16_t)length);
	}

	/* Now that we've fixed the IP header, move it forward. */
	mp->b_rptr += newpos;
	if (IS_P2ALIGNED(mp->b_rptr, sizeof (uint32_t))) {
		dest32 = (uint32_t *)(mp->b_rptr + ah_offset);
		while (--dest32 >= (uint32_t *)mp->b_rptr)
			*dest32 = *(dest32 - (newpos >> 2));
	} else {
		dest = mp->b_rptr + ah_offset;
		while (--dest >= mp->b_rptr)
			*dest = *(dest - newpos);
	}
	freeb(phdr_mp);

	/*
	 * If SA is labelled, use its label, else inherit the label
	 */
	if (is_system_labeled() && (assoc->ipsa_tsl != NULL)) {
		if (!ip_recv_attr_replace_label(ira, assoc->ipsa_tsl)) {
			ip_drop_packet(mp, B_TRUE, ira->ira_ill,
			    DROPPER(ipss, ipds_ah_nomem), &ahstack->ah_dropper);
			BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
			return (NULL);
		}
	}

	if (assoc->ipsa_state == IPSA_STATE_IDLE) {
		/*
		 * Cluster buffering case.  Tell caller that we're
		 * handling the packet.
		 */
		sadb_buf_pkt(assoc, mp, ira);
		return (NULL);
	}

	return (mp);

ah_in_discard:
	IP_AH_BUMP_STAT(ipss, in_discards);
	ip_drop_packet(phdr_mp, B_TRUE, ira->ira_ill, counter,
	    &ahstack->ah_dropper);
	BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
	return (NULL);
}

/*
 * Invoked after processing of an outbound packet by the
 * kernel crypto framework, either by ah_submit_req() for a request
 * executed syncrhonously, or by the KEF callback for a request
 * executed asynchronously.
 */
static mblk_t *
ah_auth_out_done(mblk_t *phdr_mp, ip_xmit_attr_t *ixa, ipsec_crypto_t *ic)
{
	mblk_t *mp;
	int align_len;
	uint32_t hdrs_length;
	uchar_t *ptr;
	uint32_t length;
	boolean_t isv4;
	size_t icv_len;
	netstack_t	*ns = ixa->ixa_ipst->ips_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ill_t		*ill = ixa->ixa_nce->nce_ill;

	isv4 = (ixa->ixa_flags & IXAF_IS_IPV4);
	icv_len = ic->ic_crypto_mac.cd_raw.iov_len;

	mp = phdr_mp->b_cont;
	if (mp == NULL) {
		ip_drop_packet(phdr_mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_ah_nomem),
		    &ahstack->ah_dropper);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		return (NULL);
	}
	mp->b_rptr -= ic->ic_skip_len;

	ASSERT(ixa->ixa_flags & IXAF_IPSEC_SECURE);
	ASSERT(ixa->ixa_ipsec_ah_sa != NULL);
	ah_set_usetime(ixa->ixa_ipsec_ah_sa, B_FALSE);

	if (isv4) {
		ipha_t *ipha;
		ipha_t *nipha;

		ipha = (ipha_t *)mp->b_rptr;
		hdrs_length = ipha->ipha_version_and_hdr_length -
		    (uint8_t)((IP_VERSION << 4));
		hdrs_length <<= 2;
		align_len = P2ALIGN(icv_len + IPV4_PADDING_ALIGN - 1,
		    IPV4_PADDING_ALIGN);
		/*
		 * phdr_mp must have the right amount of space for the
		 * combined IP and AH header. Copy the IP header and
		 * the ack_data onto AH. Note that the AH header was
		 * already formed before the ICV calculation and hence
		 * you don't have to copy it here.
		 */
		bcopy(mp->b_rptr, phdr_mp->b_rptr, hdrs_length);

		ptr = phdr_mp->b_rptr + hdrs_length + sizeof (ah_t);
		bcopy(phdr_mp->b_wptr, ptr, icv_len);

		/*
		 * Compute the new header checksum as we are assigning
		 * IPPROTO_AH and adjusting the length here.
		 */
		nipha = (ipha_t *)phdr_mp->b_rptr;

		nipha->ipha_protocol = IPPROTO_AH;
		length = ntohs(nipha->ipha_length);
		length += (sizeof (ah_t) + align_len);
		nipha->ipha_length = htons((uint16_t)length);
		nipha->ipha_hdr_checksum = 0;
		nipha->ipha_hdr_checksum = (uint16_t)ip_csum_hdr(nipha);
	} else {
		ip6_t *ip6h;
		ip6_t *nip6h;
		uint_t ah_offset;

		ip6h = (ip6_t *)mp->b_rptr;
		nip6h = (ip6_t *)phdr_mp->b_rptr;
		align_len = P2ALIGN(icv_len + IPV6_PADDING_ALIGN - 1,
		    IPV6_PADDING_ALIGN);
		/*
		 * phdr_mp must have the right amount of space for the
		 * combined IP and AH header. Copy the IP header with
		 * options into the pseudo header. When we constructed
		 * a pseudo header, we did not copy some of the mutable
		 * fields. We do it now by calling ah_fix_phdr_v6()
		 * with the last argument B_TRUE. It returns the
		 * ah_offset into the pseudo header.
		 */

		bcopy(ip6h, nip6h, IPV6_HDR_LEN);
		ah_offset = ah_fix_phdr_v6(nip6h, ip6h, B_TRUE, B_TRUE);
		ASSERT(ah_offset != 0);
		/*
		 * phdr_mp can hold exactly the whole IP header with options
		 * plus the AH header also. Thus subtracting the AH header's
		 * size should give exactly how much of the original header
		 * should be skipped.
		 */
		hdrs_length = (phdr_mp->b_wptr - phdr_mp->b_rptr) -
		    sizeof (ah_t) - icv_len;
		bcopy(phdr_mp->b_wptr, ((uint8_t *)nip6h + ah_offset +
		    sizeof (ah_t)), icv_len);
		length = ntohs(nip6h->ip6_plen);
		length += (sizeof (ah_t) + align_len);
		nip6h->ip6_plen = htons((uint16_t)length);
	}

	/* Skip the original IP header */
	mp->b_rptr += hdrs_length;
	if (mp->b_rptr == mp->b_wptr) {
		phdr_mp->b_cont = mp->b_cont;
		freeb(mp);
	}

	return (phdr_mp);
}

/* Refactor me */
/*
 * Wrapper to allow IP to trigger an AH association failure message
 * during SA inbound selection.
 */
void
ipsecah_in_assocfailure(mblk_t *mp, char level, ushort_t sl, char *fmt,
    uint32_t spi, void *addr, int af, ip_recv_attr_t *ira)
{
	netstack_t	*ns = ira->ira_ill->ill_ipst->ips_netstack;
	ipsecah_stack_t	*ahstack = ns->netstack_ipsecah;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	if (ahstack->ipsecah_log_unknown_spi) {
		ipsec_assocfailure(info.mi_idnum, 0, level, sl, fmt, spi,
		    addr, af, ahstack->ipsecah_netstack);
	}

	ip_drop_packet(mp, B_TRUE, ira->ira_ill,
	    DROPPER(ipss, ipds_ah_no_sa),
	    &ahstack->ah_dropper);
}

/*
 * Initialize the AH input and output processing functions.
 */
void
ipsecah_init_funcs(ipsa_t *sa)
{
	if (sa->ipsa_output_func == NULL)
		sa->ipsa_output_func = ah_outbound;
	if (sa->ipsa_input_func == NULL)
		sa->ipsa_input_func = ah_inbound;
}
