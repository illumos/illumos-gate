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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/vnode.h>
#include <sys/zone.h>
#include <sys/strlog.h>
#include <sys/sysmacros.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/file.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/proc.h>
#include <sys/suntpi.h>
#include <sys/atomic.h>
#include <sys/mkdev.h>
#include <sys/policy.h>
#include <sys/disp.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/pfkeyv2.h>

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/proto_set.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/ipsec_info.h>
#include <inet/ipsec_impl.h>
#include <inet/keysock.h>

#include <sys/isa_defs.h>

/*
 * This is a transport provider for the PF_KEY key mangement socket.
 * (See RFC 2367 for details.)
 * Downstream messages are wrapped in a keysock consumer interface KEYSOCK_IN
 * messages (see ipsec_info.h), and passed to the appropriate consumer.
 * Upstream messages are generated for all open PF_KEY sockets, when
 * appropriate, as well as the sender (as long as SO_USELOOPBACK is enabled)
 * in reply to downstream messages.
 *
 * Upstream messages must be created asynchronously for the following
 * situations:
 *
 *	1.) A keysock consumer requires an SA, and there is currently none.
 *	2.) An SA expires, either hard or soft lifetime.
 *	3.) Other events a consumer deems fit.
 *
 * The MT model of this is PERMOD, with shared put procedures.  Two types of
 * messages, SADB_FLUSH and SADB_DUMP, need to lock down the perimeter to send
 * down the *multiple* messages they create.
 */

static vmem_t *keysock_vmem;		/* for minor numbers. */

#define	KEYSOCK_MAX_CONSUMERS 256

/* Default structure copied into T_INFO_ACK messages (from rts.c...) */
static struct T_info_ack keysock_g_t_info_ack = {
	T_INFO_ACK,
	T_INFINITE,	/* TSDU_size. Maximum size messages. */
	T_INVALID,	/* ETSDU_size. No expedited data. */
	T_INVALID,	/* CDATA_size. No connect data. */
	T_INVALID,	/* DDATA_size. No disconnect data. */
	0,		/* ADDR_size. */
	0,		/* OPT_size. No user-settable options */
	64 * 1024,	/* TIDU_size. keysock allows maximum size messages. */
	T_COTS,		/* SERV_type. keysock supports connection oriented. */
	TS_UNBND,	/* CURRENT_state. This is set from keysock_state. */
	(XPG4_1)	/* Provider flags */
};

/* Named Dispatch Parameter Management Structure */
typedef struct keysockparam_s {
	uint_t	keysock_param_min;
	uint_t	keysock_param_max;
	uint_t	keysock_param_value;
	char	*keysock_param_name;
} keysockparam_t;

/*
 * Table of NDD variables supported by keysock. These are loaded into
 * keysock_g_nd in keysock_init_nd.
 * All of these are alterable, within the min/max values given, at run time.
 */
static	keysockparam_t	lcl_param_arr[] = {
	/* min	max	value	name */
	{ 4096, 65536,	8192,	"keysock_xmit_hiwat"},
	{ 0,	65536,	1024,	"keysock_xmit_lowat"},
	{ 4096, 65536,	8192,	"keysock_recv_hiwat"},
	{ 65536, 1024*1024*1024, 256*1024,	"keysock_max_buf"},
	{ 0,	3,	0,	"keysock_debug"},
};
#define	keystack_xmit_hiwat	keystack_params[0].keysock_param_value
#define	keystack_xmit_lowat	keystack_params[1].keysock_param_value
#define	keystack_recv_hiwat	keystack_params[2].keysock_param_value
#define	keystack_max_buf	keystack_params[3].keysock_param_value
#define	keystack_debug	keystack_params[4].keysock_param_value

#define	ks0dbg(a)	printf a
/* NOTE:  != 0 instead of > 0 so lint doesn't complain. */
#define	ks1dbg(keystack, a)	if (keystack->keystack_debug != 0) printf a
#define	ks2dbg(keystack, a)	if (keystack->keystack_debug > 1) printf a
#define	ks3dbg(keystack, a)	if (keystack->keystack_debug > 2) printf a

static int keysock_close(queue_t *);
static int keysock_open(queue_t *, dev_t *, int, int, cred_t *);
static void keysock_wput(queue_t *, mblk_t *);
static void keysock_rput(queue_t *, mblk_t *);
static void keysock_rsrv(queue_t *);
static void keysock_passup(mblk_t *, sadb_msg_t *, minor_t,
    keysock_consumer_t *, boolean_t, keysock_stack_t *);
static void *keysock_stack_init(netstackid_t stackid, netstack_t *ns);
static void keysock_stack_fini(netstackid_t stackid, void *arg);

static struct module_info info = {
	5138, "keysock", 1, INFPSZ, 512, 128
};

static struct qinit rinit = {
	(pfi_t)keysock_rput, (pfi_t)keysock_rsrv, keysock_open, keysock_close,
	NULL, &info
};

static struct qinit winit = {
	(pfi_t)keysock_wput, NULL, NULL, NULL, NULL, &info
};

struct streamtab keysockinfo = {
	&rinit, &winit
};

extern struct modlinkage *keysock_modlp;

/*
 * Plumb IPsec.
 *
 * NOTE:  New "default" modules will need to be loaded here if needed before
 *	  boot time.
 */

/* Keep these in global space to keep the lint from complaining. */
static char *IPSECESP = "ipsecesp";
static char *IPSECESPDEV = "/devices/pseudo/ipsecesp@0:ipsecesp";
static char *IPSECAH = "ipsecah";
static char *IPSECAHDEV = "/devices/pseudo/ipsecah@0:ipsecah";
static char *IP6DEV = "/devices/pseudo/ip6@0:ip6";
static char *KEYSOCK = "keysock";
static char *STRMOD = "strmod";

/*
 * Load the other ipsec modules and plumb them together.
 */
int
keysock_plumb_ipsec(netstack_t *ns)
{
	ldi_handle_t	lh, ip6_lh = NULL;
	ldi_ident_t	li = NULL;
	int		err = 0;
	int		muxid, rval;
	boolean_t	esp_present = B_TRUE;
	cred_t		*cr;
	keysock_stack_t *keystack = ns->netstack_keysock;

#ifdef NS_DEBUG
	(void) printf("keysock_plumb_ipsec(%d)\n",
	    ns->netstack_stackid);
#endif

	keystack->keystack_plumbed = 0;	/* we're trying again.. */

	cr = zone_get_kcred(netstackid_to_zoneid(
	    keystack->keystack_netstack->netstack_stackid));
	ASSERT(cr != NULL);
	/*
	 * Load up the drivers (AH/ESP).
	 *
	 * I do this separately from the actual plumbing in case this function
	 * ever gets called from a diskless boot before the root filesystem is
	 * up.  I don't have to worry about "keysock" because, well, if I'm
	 * here, keysock must've loaded successfully.
	 */
	if (i_ddi_attach_pseudo_node(IPSECAH) == NULL) {
		ks0dbg(("IPsec:  AH failed to attach.\n"));
		goto bail;
	}
	if (i_ddi_attach_pseudo_node(IPSECESP) == NULL) {
		ks0dbg(("IPsec:  ESP failed to attach.\n"));
		esp_present = B_FALSE;
	}

	/*
	 * Set up the IP streams for AH and ESP, as well as tacking keysock
	 * on top of them.  Assume keysock has set the autopushes up already.
	 */

	/* Open IP. */
	err = ldi_ident_from_mod(keysock_modlp, &li);
	if (err) {
		ks0dbg(("IPsec:  lid_ident_from_mod failed (err %d).\n",
		    err));
		goto bail;
	}

	err = ldi_open_by_name(IP6DEV, FREAD|FWRITE, cr, &ip6_lh, li);
	if (err) {
		ks0dbg(("IPsec:  Open of IP6 failed (err %d).\n", err));
		goto bail;
	}

	/* PLINK KEYSOCK/AH */
	err = ldi_open_by_name(IPSECAHDEV, FREAD|FWRITE, cr, &lh, li);
	if (err) {
		ks0dbg(("IPsec:  Open of AH failed (err %d).\n", err));
		goto bail;
	}
	err = ldi_ioctl(lh,
	    I_PUSH, (intptr_t)KEYSOCK, FKIOCTL, cr, &rval);
	if (err) {
		ks0dbg(("IPsec:  Push of KEYSOCK onto AH failed (err %d).\n",
		    err));
		(void) ldi_close(lh, FREAD|FWRITE, cr);
		goto bail;
	}
	err = ldi_ioctl(ip6_lh, I_PLINK, (intptr_t)lh,
	    FREAD+FWRITE+FNOCTTY+FKIOCTL, cr, &muxid);
	if (err) {
		ks0dbg(("IPsec:  PLINK of KEYSOCK/AH failed (err %d).\n", err));
		(void) ldi_close(lh, FREAD|FWRITE, cr);
		goto bail;
	}
	(void) ldi_close(lh, FREAD|FWRITE, cr);

	/* PLINK KEYSOCK/ESP */
	if (esp_present) {
		err = ldi_open_by_name(IPSECESPDEV,
		    FREAD|FWRITE, cr, &lh, li);
		if (err) {
			ks0dbg(("IPsec:  Open of ESP failed (err %d).\n", err));
			goto bail;
		}
		err = ldi_ioctl(lh,
		    I_PUSH, (intptr_t)KEYSOCK, FKIOCTL, cr, &rval);
		if (err) {
			ks0dbg(("IPsec:  "
			    "Push of KEYSOCK onto ESP failed (err %d).\n",
			    err));
			(void) ldi_close(lh, FREAD|FWRITE, cr);
			goto bail;
		}
		err = ldi_ioctl(ip6_lh, I_PLINK, (intptr_t)lh,
		    FREAD+FWRITE+FNOCTTY+FKIOCTL, cr, &muxid);
		if (err) {
			ks0dbg(("IPsec:  "
			    "PLINK of KEYSOCK/ESP failed (err %d).\n", err));
			(void) ldi_close(lh, FREAD|FWRITE, cr);
			goto bail;
		}
		(void) ldi_close(lh, FREAD|FWRITE, cr);
	}

bail:
	keystack->keystack_plumbed = (err == 0) ? 1 : -1;
	if (ip6_lh != NULL) {
		(void) ldi_close(ip6_lh, FREAD|FWRITE, cr);
	}
	if (li != NULL)
		ldi_ident_release(li);
#ifdef NS_DEBUG
	(void) printf("keysock_plumb_ipsec -> %d\n",
	    keystack->keystack_plumbed);
#endif
	crfree(cr);
	return (err);
}

/* ARGSUSED */
static int
keysock_param_get(q, mp, cp, cr)
	queue_t	*q;
	mblk_t	*mp;
	caddr_t	cp;
	cred_t *cr;
{
	keysockparam_t	*keysockpa = (keysockparam_t *)cp;
	uint_t value;
	keysock_t *ks = (keysock_t *)q->q_ptr;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	mutex_enter(&keystack->keystack_param_lock);
	value = keysockpa->keysock_param_value;
	mutex_exit(&keystack->keystack_param_lock);

	(void) mi_mpprintf(mp, "%u", value);
	return (0);
}

/* This routine sets an NDD variable in a keysockparam_t structure. */
/* ARGSUSED */
static int
keysock_param_set(q, mp, value, cp, cr)
	queue_t	*q;
	mblk_t	*mp;
	char	*value;
	caddr_t	cp;
	cred_t *cr;
{
	ulong_t	new_value;
	keysockparam_t	*keysockpa = (keysockparam_t *)cp;
	keysock_t *ks = (keysock_t *)q->q_ptr;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	/* Convert the value from a string into a long integer. */
	if (ddi_strtoul(value, NULL, 10, &new_value) != 0)
		return (EINVAL);

	mutex_enter(&keystack->keystack_param_lock);
	/*
	 * Fail the request if the new value does not lie within the
	 * required bounds.
	 */
	if (new_value < keysockpa->keysock_param_min ||
	    new_value > keysockpa->keysock_param_max) {
		mutex_exit(&keystack->keystack_param_lock);
		return (EINVAL);
	}

	/* Set the new value */
	keysockpa->keysock_param_value = new_value;
	mutex_exit(&keystack->keystack_param_lock);

	return (0);
}

/*
 * Initialize keysock at module load time
 */
boolean_t
keysock_ddi_init(void)
{
	keysock_max_optsize = optcom_max_optsize(
	    keysock_opt_obj.odb_opt_des_arr, keysock_opt_obj.odb_opt_arr_cnt);

	keysock_vmem = vmem_create("keysock", (void *)1, MAXMIN, 1,
	    NULL, NULL, NULL, 1, VM_SLEEP | VMC_IDENTIFIER);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of keysock_stack_t's.
	 */
	netstack_register(NS_KEYSOCK, keysock_stack_init, NULL,
	    keysock_stack_fini);

	return (B_TRUE);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch handler.
 */
static boolean_t
keysock_param_register(IDP *ndp, keysockparam_t *ksp, int cnt)
{
	for (; cnt-- > 0; ksp++) {
		if (ksp->keysock_param_name != NULL &&
		    ksp->keysock_param_name[0]) {
			if (!nd_load(ndp,
			    ksp->keysock_param_name,
			    keysock_param_get, keysock_param_set,
			    (caddr_t)ksp)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}
	return (B_TRUE);
}

/*
 * Initialize keysock for one stack instance
 */
/* ARGSUSED */
static void *
keysock_stack_init(netstackid_t stackid, netstack_t *ns)
{
	keysock_stack_t	*keystack;
	keysockparam_t *ksp;

	keystack = (keysock_stack_t *)kmem_zalloc(sizeof (*keystack), KM_SLEEP);
	keystack->keystack_netstack = ns;

	keystack->keystack_acquire_seq = 0xffffffff;

	ksp = (keysockparam_t *)kmem_alloc(sizeof (lcl_param_arr), KM_SLEEP);
	keystack->keystack_params = ksp;
	bcopy(lcl_param_arr, ksp, sizeof (lcl_param_arr));

	(void) keysock_param_register(&keystack->keystack_g_nd, ksp,
	    A_CNT(lcl_param_arr));

	mutex_init(&keystack->keystack_list_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&keystack->keystack_consumers_lock,
	    NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&keystack->keystack_param_lock, NULL, MUTEX_DEFAULT, NULL);
	return (keystack);
}

/*
 * Free NDD variable space, and other destructors, for keysock.
 */
void
keysock_ddi_destroy(void)
{
	netstack_unregister(NS_KEYSOCK);
	vmem_destroy(keysock_vmem);
}

/*
 * Remove one stack instance from keysock
 */
/* ARGSUSED */
static void
keysock_stack_fini(netstackid_t stackid, void *arg)
{
	keysock_stack_t *keystack = (keysock_stack_t *)arg;

	nd_free(&keystack->keystack_g_nd);
	kmem_free(keystack->keystack_params, sizeof (lcl_param_arr));
	keystack->keystack_params = NULL;

	mutex_destroy(&keystack->keystack_list_lock);
	mutex_destroy(&keystack->keystack_consumers_lock);
	mutex_destroy(&keystack->keystack_param_lock);

	kmem_free(keystack, sizeof (*keystack));
}

/*
 * Close routine for keysock.
 */
static int
keysock_close(queue_t *q)
{
	keysock_t *ks;
	keysock_consumer_t *kc;
	void *ptr = q->q_ptr;
	int size;
	keysock_stack_t	*keystack;


	qprocsoff(q);

	/* Safe assumption. */
	ASSERT(ptr != NULL);

	if (WR(q)->q_next) {
		kc = (keysock_consumer_t *)ptr;
		keystack = kc->kc_keystack;

		ks1dbg(keystack, ("Module close, removing a consumer (%d).\n",
		    kc->kc_sa_type));
		/*
		 * Because of PERMOD open/close exclusive perimeter, I
		 * can inspect KC_FLUSHING w/o locking down kc->kc_lock.
		 */
		if (kc->kc_flags & KC_FLUSHING) {
			/*
			 * If this decrement was the last one, send
			 * down the next pending one, if any.
			 *
			 * With a PERMOD perimeter, the mutexes ops aren't
			 * really necessary, but if we ever loosen up, we will
			 * have this bit covered already.
			 */
			keystack->keystack_flushdump--;
			if (keystack->keystack_flushdump == 0) {
				/*
				 * The flush/dump terminated by having a
				 * consumer go away.  I need to send up to the
				 * appropriate keysock all of the relevant
				 * information.  Unfortunately, I don't
				 * have that handy.
				 */
				ks0dbg(("Consumer went away while flushing or"
				    " dumping.\n"));
			}
		}
		size = sizeof (keysock_consumer_t);
		mutex_enter(&keystack->keystack_consumers_lock);
		keystack->keystack_consumers[kc->kc_sa_type] = NULL;
		mutex_exit(&keystack->keystack_consumers_lock);
		mutex_destroy(&kc->kc_lock);
		netstack_rele(kc->kc_keystack->keystack_netstack);
	} else {
		ks = (keysock_t *)ptr;
		keystack = ks->keysock_keystack;

		ks3dbg(keystack,
		    ("Driver close, PF_KEY socket is going away.\n"));
		if ((ks->keysock_flags & KEYSOCK_EXTENDED) != 0)
			atomic_dec_32(&keystack->keystack_num_extended);
		size = sizeof (keysock_t);
		mutex_enter(&keystack->keystack_list_lock);
		*(ks->keysock_ptpn) = ks->keysock_next;
		if (ks->keysock_next != NULL)
			ks->keysock_next->keysock_ptpn = ks->keysock_ptpn;
		mutex_exit(&keystack->keystack_list_lock);
		mutex_destroy(&ks->keysock_lock);
		vmem_free(keysock_vmem, (void *)(uintptr_t)ks->keysock_serial,
		    1);
		netstack_rele(ks->keysock_keystack->keystack_netstack);
	}

	/* Now I'm free. */
	kmem_free(ptr, size);
	return (0);
}
/*
 * Open routine for keysock.
 */
/* ARGSUSED */
static int
keysock_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	keysock_t *ks;
	keysock_consumer_t *kc;
	mblk_t *mp;
	ipsec_info_t *ii;
	netstack_t *ns;
	keysock_stack_t *keystack;

	if (secpolicy_ip_config(credp, B_FALSE) != 0) {
		/* Privilege debugging will log the error */
		return (EPERM);
	}

	if (q->q_ptr != NULL)
		return (0);  /* Re-open of an already open instance. */

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	keystack = ns->netstack_keysock;
	ASSERT(keystack != NULL);

	ks3dbg(keystack, ("Entering keysock open.\n"));

	if (keystack->keystack_plumbed < 1) {
		netstack_t *ns = keystack->keystack_netstack;

		keystack->keystack_plumbed = 0;
#ifdef NS_DEBUG
		printf("keysock_open(%d) - plumb\n",
		    keystack->keystack_netstack->netstack_stackid);
#endif
		/*
		 * Don't worry about ipsec_failure being true here.
		 * (See ip.c).  An open of keysock should try and force
		 * the issue.  Maybe it was a transient failure.
		 */
		ipsec_loader_loadnow(ns->netstack_ipsec);
	}

	if (sflag & MODOPEN) {
		/* Initialize keysock_consumer state here. */
		kc = kmem_zalloc(sizeof (keysock_consumer_t), KM_NOSLEEP);
		if (kc == NULL) {
			netstack_rele(keystack->keystack_netstack);
			return (ENOMEM);
		}
		mutex_init(&kc->kc_lock, NULL, MUTEX_DEFAULT, 0);
		kc->kc_rq = q;
		kc->kc_wq = WR(q);

		q->q_ptr = kc;
		WR(q)->q_ptr = kc;

		kc->kc_keystack = keystack;
		qprocson(q);

		/*
		 * Send down initial message to whatever I was pushed on top
		 * of asking for its consumer type.  The reply will set it.
		 */

		/* Allocate it. */
		mp = allocb(sizeof (ipsec_info_t), BPRI_HI);
		if (mp == NULL) {
			ks1dbg(keystack, (
			    "keysock_open:  Cannot allocate KEYSOCK_HELLO.\n"));
			/* Do I need to set these to null? */
			q->q_ptr = NULL;
			WR(q)->q_ptr = NULL;
			mutex_destroy(&kc->kc_lock);
			kmem_free(kc, sizeof (*kc));
			netstack_rele(keystack->keystack_netstack);
			return (ENOMEM);
		}

		/* If I allocated okay, putnext to what I was pushed atop. */
		mp->b_wptr += sizeof (ipsec_info_t);
		mp->b_datap->db_type = M_CTL;
		ii = (ipsec_info_t *)mp->b_rptr;
		ii->ipsec_info_type = KEYSOCK_HELLO;
		/* Length only of type/len. */
		ii->ipsec_info_len = sizeof (ii->ipsec_allu);
		ks2dbg(keystack, ("Ready to putnext KEYSOCK_HELLO.\n"));
		putnext(kc->kc_wq, mp);
	} else {
		minor_t ksminor;

		/* Initialize keysock state. */

		ks2dbg(keystack, ("Made it into PF_KEY socket open.\n"));

		ksminor = (minor_t)(uintptr_t)
		    vmem_alloc(keysock_vmem, 1, VM_NOSLEEP);
		if (ksminor == 0) {
			netstack_rele(keystack->keystack_netstack);
			return (ENOMEM);
		}
		ks = kmem_zalloc(sizeof (keysock_t), KM_NOSLEEP);
		if (ks == NULL) {
			vmem_free(keysock_vmem, (void *)(uintptr_t)ksminor, 1);
			netstack_rele(keystack->keystack_netstack);
			return (ENOMEM);
		}

		mutex_init(&ks->keysock_lock, NULL, MUTEX_DEFAULT, 0);
		ks->keysock_rq = q;
		ks->keysock_wq = WR(q);
		ks->keysock_state = TS_UNBND;
		ks->keysock_serial = ksminor;

		q->q_ptr = ks;
		WR(q)->q_ptr = ks;
		ks->keysock_keystack = keystack;

		/*
		 * The receive hiwat is only looked at on the stream head
		 * queue.  Store in q_hiwat in order to return on SO_RCVBUF
		 * getsockopts.
		 */

		q->q_hiwat = keystack->keystack_recv_hiwat;

		/*
		 * The transmit hiwat/lowat is only looked at on IP's queue.
		 * Store in q_hiwat/q_lowat in order to return on
		 * SO_SNDBUF/SO_SNDLOWAT getsockopts.
		 */

		WR(q)->q_hiwat = keystack->keystack_xmit_hiwat;
		WR(q)->q_lowat = keystack->keystack_xmit_lowat;

		*devp = makedevice(getmajor(*devp), ksminor);

		/*
		 * Thread keysock into the global keysock list.
		 */
		mutex_enter(&keystack->keystack_list_lock);
		ks->keysock_next = keystack->keystack_list;
		ks->keysock_ptpn = &keystack->keystack_list;
		if (keystack->keystack_list != NULL) {
			keystack->keystack_list->keysock_ptpn =
			    &ks->keysock_next;
		}
		keystack->keystack_list = ks;
		mutex_exit(&keystack->keystack_list_lock);

		qprocson(q);
		(void) proto_set_rx_hiwat(q, NULL,
		    keystack->keystack_recv_hiwat);
		/*
		 * Wait outside the keysock module perimeter for IPsec
		 * plumbing to be completed.  If it fails, keysock_close()
		 * undoes everything we just did.
		 */
		if (!ipsec_loader_wait(q,
		    keystack->keystack_netstack->netstack_ipsec)) {
			(void) keysock_close(q);
			return (EPFNOSUPPORT);
		}
	}

	return (0);
}

/* BELOW THIS LINE ARE ROUTINES INCLUDING AND RELATED TO keysock_wput(). */

/*
 * Copy relevant state bits.
 */
static void
keysock_copy_info(struct T_info_ack *tap, keysock_t *ks)
{
	*tap = keysock_g_t_info_ack;
	tap->CURRENT_state = ks->keysock_state;
	tap->OPT_size = keysock_max_optsize;
}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * keysock_wput.  Much of the T_CAPABILITY_ACK information is copied from
 * keysock_g_t_info_ack.  The current state of the stream is copied from
 * keysock_state.
 */
static void
keysock_capability_req(queue_t *q, mblk_t *mp)
{
	keysock_t *ks = (keysock_t *)q->q_ptr;
	t_uscalar_t cap_bits1;
	struct T_capability_ack	*tcap;

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (mp == NULL)
		return;

	tcap = (struct T_capability_ack *)mp->b_rptr;
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		keysock_copy_info(&tcap->INFO_ack, ks);
		tcap->CAP_bits1 |= TC1_INFO;
	}

	qreply(q, mp);
}

/*
 * This routine responds to T_INFO_REQ messages. It is called by
 * keysock_wput_other.
 * Most of the T_INFO_ACK information is copied from keysock_g_t_info_ack.
 * The current state of the stream is copied from keysock_state.
 */
static void
keysock_info_req(q, mp)
	queue_t	*q;
	mblk_t	*mp;
{
	mp = tpi_ack_alloc(mp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (mp == NULL)
		return;
	keysock_copy_info((struct T_info_ack *)mp->b_rptr,
	    (keysock_t *)q->q_ptr);
	qreply(q, mp);
}

/*
 * keysock_err_ack. This routine creates a
 * T_ERROR_ACK message and passes it
 * upstream.
 */
static void
keysock_err_ack(q, mp, t_error, sys_error)
	queue_t	*q;
	mblk_t	*mp;
	int	t_error;
	int	sys_error;
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		qreply(q, mp);
}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved.
 */
/* ARGSUSED */
int
keysock_opt_get(queue_t *q, int level, int name, uchar_t *ptr)
{
	int *i1 = (int *)ptr;
	keysock_t *ks = (keysock_t *)q->q_ptr;

	switch (level) {
	case SOL_SOCKET:
		mutex_enter(&ks->keysock_lock);
		switch (name) {
		case SO_TYPE:
			*i1 = SOCK_RAW;
			break;
		case SO_USELOOPBACK:
			*i1 = (int)(!((ks->keysock_flags & KEYSOCK_NOLOOP) ==
			    KEYSOCK_NOLOOP));
			break;
		/*
		 * The following two items can be manipulated,
		 * but changing them should do nothing.
		 */
		case SO_SNDBUF:
			*i1 = (int)q->q_hiwat;
			break;
		case SO_RCVBUF:
			*i1 = (int)(RD(q)->q_hiwat);
			break;
		}
		mutex_exit(&ks->keysock_lock);
		break;
	default:
		return (0);
	}
	return (sizeof (int));
}

/*
 * This routine sets socket options.
 */
/* ARGSUSED */
int
keysock_opt_set(queue_t *q, uint_t mgmt_flags, int level,
    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr)
{
	int *i1 = (int *)invalp, errno = 0;
	keysock_t *ks = (keysock_t *)q->q_ptr;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	switch (level) {
	case SOL_SOCKET:
		mutex_enter(&ks->keysock_lock);
		switch (name) {
		case SO_USELOOPBACK:
			if (!(*i1))
				ks->keysock_flags |= KEYSOCK_NOLOOP;
			else ks->keysock_flags &= ~KEYSOCK_NOLOOP;
			break;
		case SO_SNDBUF:
			if (*i1 > keystack->keystack_max_buf)
				errno = ENOBUFS;
			else q->q_hiwat = *i1;
			break;
		case SO_RCVBUF:
			if (*i1 > keystack->keystack_max_buf) {
				errno = ENOBUFS;
			} else {
				RD(q)->q_hiwat = *i1;
				(void) proto_set_rx_hiwat(RD(q), NULL, *i1);
			}
			break;
		default:
			errno = EINVAL;
		}
		mutex_exit(&ks->keysock_lock);
		break;
	default:
		errno = EINVAL;
	}
	return (errno);
}

/*
 * Handle STREAMS messages.
 */
static void
keysock_wput_other(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	int error;
	keysock_t *ks = (keysock_t *)q->q_ptr;
	keysock_stack_t	*keystack = ks->keysock_keystack;
	cred_t		*cr;

	switch (mp->b_datap->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		if ((mp->b_wptr - mp->b_rptr) < sizeof (long)) {
			ks3dbg(keystack, (
			    "keysock_wput_other: Not big enough M_PROTO\n"));
			freemsg(mp);
			return;
		}
		switch (((union T_primitives *)mp->b_rptr)->type) {
		case T_CAPABILITY_REQ:
			keysock_capability_req(q, mp);
			break;
		case T_INFO_REQ:
			keysock_info_req(q, mp);
			break;
		case T_SVR4_OPTMGMT_REQ:
		case T_OPTMGMT_REQ:
			/*
			 * All Solaris components should pass a db_credp
			 * for this TPI message, hence we ASSERT.
			 * But in case there is some other M_PROTO that looks
			 * like a TPI message sent by some other kernel
			 * component, we check and return an error.
			 */
			cr = msg_getcred(mp, NULL);
			ASSERT(cr != NULL);
			if (cr == NULL) {
				keysock_err_ack(q, mp, TSYSERR, EINVAL);
				return;
			}
			if (((union T_primitives *)mp->b_rptr)->type ==
			    T_SVR4_OPTMGMT_REQ) {
				svr4_optcom_req(q, mp, cr, &keysock_opt_obj);
			} else {
				tpi_optcom_req(q, mp, cr, &keysock_opt_obj);
			}
			break;
		case T_DATA_REQ:
		case T_EXDATA_REQ:
		case T_ORDREL_REQ:
			/* Illegal for keysock. */
			freemsg(mp);
			(void) putnextctl1(RD(q), M_ERROR, EPROTO);
			break;
		default:
			/* Not supported by keysock. */
			keysock_err_ack(q, mp, TNOTSUPPORT, 0);
			break;
		}
		return;
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		error = EINVAL;

		switch (iocp->ioc_cmd) {
		case ND_SET:
		case ND_GET:
			if (nd_getset(q, keystack->keystack_g_nd, mp)) {
				qreply(q, mp);
				return;
			} else
				error = ENOENT;
			/* FALLTHRU */
		default:
			miocnak(q, mp, 0, error);
			return;
		}
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			qreply(q, mp);
			return;
		}
		/* Else FALLTHRU */
	}

	/* If fell through, just black-hole the message. */
	freemsg(mp);
}

/*
 * Transmit a PF_KEY error message to the instance either pointed to
 * by ks, the instance with serial number serial, or more, depending.
 *
 * The faulty message (or a reasonable facsimile thereof) is in mp.
 * This function will free mp or recycle it for delivery, thereby causing
 * the stream head to free it.
 */
static void
keysock_error(keysock_t *ks, mblk_t *mp, int error, int diagnostic)
{
	sadb_msg_t *samsg = (sadb_msg_t *)mp->b_rptr;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	ASSERT(mp->b_datap->db_type == M_DATA);

	if (samsg->sadb_msg_type < SADB_GETSPI ||
	    samsg->sadb_msg_type > SADB_MAX)
		samsg->sadb_msg_type = SADB_RESERVED;

	/*
	 * Strip out extension headers.
	 */
	ASSERT(mp->b_rptr + sizeof (*samsg) <= mp->b_datap->db_lim);
	mp->b_wptr = mp->b_rptr + sizeof (*samsg);
	samsg->sadb_msg_len = SADB_8TO64(sizeof (sadb_msg_t));
	samsg->sadb_msg_errno = (uint8_t)error;
	samsg->sadb_x_msg_diagnostic = (uint16_t)diagnostic;

	keysock_passup(mp, samsg, ks->keysock_serial, NULL, B_FALSE, keystack);
}

/*
 * Pass down a message to a consumer.  Wrap it in KEYSOCK_IN, and copy
 * in the extv if passed in.
 */
static void
keysock_passdown(keysock_t *ks, mblk_t *mp, uint8_t satype, sadb_ext_t *extv[],
    boolean_t flushmsg)
{
	keysock_consumer_t *kc;
	mblk_t *wrapper;
	keysock_in_t *ksi;
	int i;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	wrapper = allocb(sizeof (ipsec_info_t), BPRI_HI);
	if (wrapper == NULL) {
		ks3dbg(keystack, ("keysock_passdown: allocb failed.\n"));
		if (extv[SADB_EXT_KEY_ENCRYPT] != NULL)
			bzero(extv[SADB_EXT_KEY_ENCRYPT],
			    SADB_64TO8(
			    extv[SADB_EXT_KEY_ENCRYPT]->sadb_ext_len));
		if (extv[SADB_EXT_KEY_AUTH] != NULL)
			bzero(extv[SADB_EXT_KEY_AUTH],
			    SADB_64TO8(
			    extv[SADB_EXT_KEY_AUTH]->sadb_ext_len));
		if (flushmsg) {
			ks0dbg((
			    "keysock: Downwards flush/dump message failed!\n"));
			/* If this is true, I hold the perimeter. */
			keystack->keystack_flushdump--;
		}
		freemsg(mp);
		return;
	}

	wrapper->b_datap->db_type = M_CTL;
	ksi = (keysock_in_t *)wrapper->b_rptr;
	ksi->ks_in_type = KEYSOCK_IN;
	ksi->ks_in_len = sizeof (keysock_in_t);
	if (extv[SADB_EXT_ADDRESS_SRC] != NULL)
		ksi->ks_in_srctype = KS_IN_ADDR_UNKNOWN;
	else ksi->ks_in_srctype = KS_IN_ADDR_NOTTHERE;
	if (extv[SADB_EXT_ADDRESS_DST] != NULL)
		ksi->ks_in_dsttype = KS_IN_ADDR_UNKNOWN;
	else ksi->ks_in_dsttype = KS_IN_ADDR_NOTTHERE;
	for (i = 0; i <= SADB_EXT_MAX; i++)
		ksi->ks_in_extv[i] = extv[i];
	ksi->ks_in_serial = ks->keysock_serial;
	wrapper->b_wptr += sizeof (ipsec_info_t);
	wrapper->b_cont = mp;

	/*
	 * Find the appropriate consumer where the message is passed down.
	 */
	kc = keystack->keystack_consumers[satype];
	if (kc == NULL) {
		freeb(wrapper);
		keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_UNKNOWN_SATYPE);
		if (flushmsg) {
			ks0dbg((
			    "keysock: Downwards flush/dump message failed!\n"));
			/* If this is true, I hold the perimeter. */
			keystack->keystack_flushdump--;
		}
		return;
	}

	/*
	 * NOTE: There used to be code in here to spin while a flush or
	 *	 dump finished.  Keysock now assumes that consumers have enough
	 *	 MT-savviness to deal with that.
	 */

	/*
	 * Current consumers (AH and ESP) are guaranteed to return a
	 * FLUSH or DUMP message back, so when we reach here, we don't
	 * have to worry about keysock_flushdumps.
	 */

	putnext(kc->kc_wq, wrapper);
}

/*
 * High-level reality checking of extensions.
 */
static boolean_t
ext_check(sadb_ext_t *ext, keysock_stack_t *keystack)
{
	int i;
	uint64_t *lp;
	sadb_ident_t *id;
	char *idstr;

	switch (ext->sadb_ext_type) {
	case SADB_EXT_ADDRESS_SRC:
	case SADB_EXT_ADDRESS_DST:
	case SADB_X_EXT_ADDRESS_INNER_SRC:
	case SADB_X_EXT_ADDRESS_INNER_DST:
		/* Check for at least enough addtl length for a sockaddr. */
		if (ext->sadb_ext_len <= SADB_8TO64(sizeof (sadb_address_t)))
			return (B_FALSE);
		break;
	case SADB_EXT_LIFETIME_HARD:
	case SADB_EXT_LIFETIME_SOFT:
	case SADB_EXT_LIFETIME_CURRENT:
		if (ext->sadb_ext_len != SADB_8TO64(sizeof (sadb_lifetime_t)))
			return (B_FALSE);
		break;
	case SADB_EXT_SPIRANGE:
		/* See if the SPI range is legit. */
		if (htonl(((sadb_spirange_t *)ext)->sadb_spirange_min) >
		    htonl(((sadb_spirange_t *)ext)->sadb_spirange_max))
			return (B_FALSE);
		break;
	case SADB_EXT_KEY_AUTH:
	case SADB_EXT_KEY_ENCRYPT:
		/* Key length check. */
		if (((sadb_key_t *)ext)->sadb_key_bits == 0)
			return (B_FALSE);
		/*
		 * Check to see if the key length (in bits) is less than the
		 * extension length (in 8-bits words).
		 */
		if ((roundup(SADB_1TO8(((sadb_key_t *)ext)->sadb_key_bits), 8) +
		    sizeof (sadb_key_t)) != SADB_64TO8(ext->sadb_ext_len)) {
			ks1dbg(keystack, (
			    "ext_check:  Key bits/length inconsistent.\n"));
			ks1dbg(keystack, ("%d bits, len is %d bytes.\n",
			    ((sadb_key_t *)ext)->sadb_key_bits,
			    SADB_64TO8(ext->sadb_ext_len)));
			return (B_FALSE);
		}

		/* All-zeroes key check. */
		lp = (uint64_t *)(((char *)ext) + sizeof (sadb_key_t));
		for (i = 0;
		    i < (ext->sadb_ext_len - SADB_8TO64(sizeof (sadb_key_t)));
		    i++)
			if (lp[i] != 0)
				break;	/* Out of for loop. */
		/* If finished the loop naturally, it's an all zero key. */
		if (lp[i] == 0)
			return (B_FALSE);
		break;
	case SADB_EXT_IDENTITY_SRC:
	case SADB_EXT_IDENTITY_DST:
		/*
		 * Make sure the strings in these identities are
		 * null-terminated.  RFC 2367 underspecified how to handle
		 * such a case.  I "proactively" null-terminate the string
		 * at the last byte if it's not terminated sooner.
		 */
		id = (sadb_ident_t *)ext;
		i = SADB_64TO8(id->sadb_ident_len);
		i -= sizeof (sadb_ident_t);
		idstr = (char *)(id + 1);
		while (*idstr != '\0' && i > 0) {
			i--;
			idstr++;
		}
		if (i == 0) {
			/*
			 * I.e., if the bozo user didn't NULL-terminate the
			 * string...
			 */
			idstr--;
			*idstr = '\0';
		}
		break;
	}
	return (B_TRUE);	/* For now... */
}

/* Return values for keysock_get_ext(). */
#define	KGE_OK	0
#define	KGE_DUP	1
#define	KGE_UNK	2
#define	KGE_LEN	3
#define	KGE_CHK	4

/*
 * Parse basic extension headers and return in the passed-in pointer vector.
 * Return values include:
 *
 *	KGE_OK	Everything's nice and parsed out.
 *		If there are no extensions, place NULL in extv[0].
 *	KGE_DUP	There is a duplicate extension.
 *		First instance in appropriate bin.  First duplicate in
 *		extv[0].
 *	KGE_UNK	Unknown extension type encountered.  extv[0] contains
 *		unknown header.
 *	KGE_LEN	Extension length error.
 *	KGE_CHK	High-level reality check failed on specific extension.
 *
 * My apologies for some of the pointer arithmetic in here.  I'm thinking
 * like an assembly programmer, yet trying to make the compiler happy.
 */
static int
keysock_get_ext(sadb_ext_t *extv[], sadb_msg_t *basehdr, uint_t msgsize,
    keysock_stack_t *keystack)
{
	bzero(extv, sizeof (sadb_ext_t *) * (SADB_EXT_MAX + 1));

	/* Use extv[0] as the "current working pointer". */

	extv[0] = (sadb_ext_t *)(basehdr + 1);

	while (extv[0] < (sadb_ext_t *)(((uint8_t *)basehdr) + msgsize)) {
		/* Check for unknown headers. */
		if (extv[0]->sadb_ext_type == 0 ||
		    extv[0]->sadb_ext_type > SADB_EXT_MAX)
			return (KGE_UNK);

		/*
		 * Check length.  Use uint64_t because extlen is in units
		 * of 64-bit words.  If length goes beyond the msgsize,
		 * return an error.  (Zero length also qualifies here.)
		 */
		if (extv[0]->sadb_ext_len == 0 ||
		    (void *)((uint64_t *)extv[0] + extv[0]->sadb_ext_len) >
		    (void *)((uint8_t *)basehdr + msgsize))
			return (KGE_LEN);

		/* Check for redundant headers. */
		if (extv[extv[0]->sadb_ext_type] != NULL)
			return (KGE_DUP);

		/*
		 * Reality check the extension if possible at the keysock
		 * level.
		 */
		if (!ext_check(extv[0], keystack))
			return (KGE_CHK);

		/* If I make it here, assign the appropriate bin. */
		extv[extv[0]->sadb_ext_type] = extv[0];

		/* Advance pointer (See above for uint64_t ptr reasoning.) */
		extv[0] = (sadb_ext_t *)
		    ((uint64_t *)extv[0] + extv[0]->sadb_ext_len);
	}

	/* Everything's cool. */

	/*
	 * If extv[0] == NULL, then there are no extension headers in this
	 * message.  Ensure that this is the case.
	 */
	if (extv[0] == (sadb_ext_t *)(basehdr + 1))
		extv[0] = NULL;

	return (KGE_OK);
}

/*
 * qwriter() callback to handle flushes and dumps.  This routine will hold
 * the inner perimeter.
 */
void
keysock_do_flushdump(queue_t *q, mblk_t *mp)
{
	int i, start, finish;
	mblk_t *mp1 = NULL;
	keysock_t *ks = (keysock_t *)q->q_ptr;
	sadb_ext_t *extv[SADB_EXT_MAX + 1];
	sadb_msg_t *samsg = (sadb_msg_t *)mp->b_rptr;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	/*
	 * I am guaranteed this will work.  I did the work in keysock_parse()
	 * already.
	 */
	(void) keysock_get_ext(extv, samsg, SADB_64TO8(samsg->sadb_msg_len),
	    keystack);

	/*
	 * I hold the perimeter, therefore I don't need to use atomic ops.
	 */
	if (keystack->keystack_flushdump != 0) {
		/* XXX Should I instead use EBUSY? */
		/* XXX Or is there a way to queue these up? */
		keysock_error(ks, mp, ENOMEM, SADB_X_DIAGNOSTIC_NONE);
		return;
	}

	if (samsg->sadb_msg_satype == SADB_SATYPE_UNSPEC) {
		start = 0;
		finish = KEYSOCK_MAX_CONSUMERS - 1;
	} else {
		start = samsg->sadb_msg_satype;
		finish = samsg->sadb_msg_satype;
	}

	/*
	 * Fill up keysock_flushdump with the number of outstanding dumps
	 * and/or flushes.
	 */

	keystack->keystack_flushdump_errno = 0;

	/*
	 * Okay, I hold the perimeter.  Eventually keysock_flushdump will
	 * contain the number of consumers with outstanding flush operations.
	 *
	 * SO, here's the plan:
	 *	* For each relevant consumer (Might be one, might be all)
	 *		* Twiddle on the FLUSHING flag.
	 *		* Pass down the FLUSH/DUMP message.
	 *
	 * When I see upbound FLUSH/DUMP messages, I will decrement the
	 * keysock_flushdump.  When I decrement it to 0, I will pass the
	 * FLUSH/DUMP message back up to the PF_KEY sockets.  Because I will
	 * pass down the right SA type to the consumer (either its own, or
	 * that of UNSPEC), the right one will be reflected from each consumer,
	 * and accordingly back to the socket.
	 */

	mutex_enter(&keystack->keystack_consumers_lock);
	for (i = start; i <= finish; i++) {
		if (keystack->keystack_consumers[i] != NULL) {
			mp1 = copymsg(mp);
			if (mp1 == NULL) {
				ks0dbg(("SADB_FLUSH copymsg() failed.\n"));
				/*
				 * Error?  And what about outstanding
				 * flushes?  Oh, yeah, they get sucked up and
				 * the counter is decremented.  Consumers
				 * (see keysock_passdown()) are guaranteed
				 * to deliver back a flush request, even if
				 * it's an error.
				 */
				keysock_error(ks, mp, ENOMEM,
				    SADB_X_DIAGNOSTIC_NONE);
				return;
			}
			/*
			 * Because my entry conditions are met above, the
			 * following assertion should hold true.
			 */
			mutex_enter(&keystack->keystack_consumers[i]->kc_lock);
			ASSERT((keystack->keystack_consumers[i]->kc_flags &
			    KC_FLUSHING) == 0);
			keystack->keystack_consumers[i]->kc_flags |=
			    KC_FLUSHING;
			mutex_exit(&(keystack->keystack_consumers[i]->kc_lock));
			/* Always increment the number of flushes... */
			keystack->keystack_flushdump++;
			/* Guaranteed to return a message. */
			keysock_passdown(ks, mp1, i, extv, B_TRUE);
		} else if (start == finish) {
			/*
			 * In case where start == finish, and there's no
			 * consumer, should we force an error?  Yes.
			 */
			mutex_exit(&keystack->keystack_consumers_lock);
			keysock_error(ks, mp, EINVAL,
			    SADB_X_DIAGNOSTIC_UNKNOWN_SATYPE);
			return;
		}
	}
	mutex_exit(&keystack->keystack_consumers_lock);

	if (keystack->keystack_flushdump == 0) {
		/*
		 * There were no consumers at all for this message.
		 * XXX For now return ESRCH.
		 */
		keysock_error(ks, mp, ESRCH, SADB_X_DIAGNOSTIC_NO_SADBS);
	} else {
		/* Otherwise, free the original message. */
		freemsg(mp);
	}
}

/*
 * Get the right diagnostic for a duplicate.  Should probably use a static
 * table lookup.
 */
int
keysock_duplicate(int ext_type)
{
	int rc = 0;

	switch (ext_type) {
	case SADB_EXT_ADDRESS_SRC:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_SRC;
		break;
	case SADB_EXT_ADDRESS_DST:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_DST;
		break;
	case SADB_X_EXT_ADDRESS_INNER_SRC:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_INNER_SRC;
		break;
	case SADB_X_EXT_ADDRESS_INNER_DST:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_INNER_DST;
		break;
	case SADB_EXT_SA:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_SA;
		break;
	case SADB_EXT_SPIRANGE:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_RANGE;
		break;
	case SADB_EXT_KEY_AUTH:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_AKEY;
		break;
	case SADB_EXT_KEY_ENCRYPT:
		rc = SADB_X_DIAGNOSTIC_DUPLICATE_EKEY;
		break;
	}
	return (rc);
}

/*
 * Get the right diagnostic for a reality check failure.  Should probably use
 * a static table lookup.
 */
int
keysock_malformed(int ext_type)
{
	int rc = 0;

	switch (ext_type) {
	case SADB_EXT_ADDRESS_SRC:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_SRC;
		break;
	case SADB_EXT_ADDRESS_DST:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_DST;
		break;
	case SADB_X_EXT_ADDRESS_INNER_SRC:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_INNER_SRC;
		break;
	case SADB_X_EXT_ADDRESS_INNER_DST:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_INNER_DST;
		break;
	case SADB_EXT_SA:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_SA;
		break;
	case SADB_EXT_SPIRANGE:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_RANGE;
		break;
	case SADB_EXT_KEY_AUTH:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_AKEY;
		break;
	case SADB_EXT_KEY_ENCRYPT:
		rc = SADB_X_DIAGNOSTIC_MALFORMED_EKEY;
		break;
	}
	return (rc);
}

/*
 * Keysock massaging of an inverse ACQUIRE.  Consult policy,
 * and construct an appropriate response.
 */
static void
keysock_inverse_acquire(mblk_t *mp, sadb_msg_t *samsg, sadb_ext_t *extv[],
    keysock_t *ks)
{
	mblk_t *reply_mp;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	/*
	 * Reality check things...
	 */
	if (extv[SADB_EXT_ADDRESS_SRC] == NULL) {
		keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_MISSING_SRC);
		return;
	}
	if (extv[SADB_EXT_ADDRESS_DST] == NULL) {
		keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_MISSING_DST);
		return;
	}

	if (extv[SADB_X_EXT_ADDRESS_INNER_SRC] != NULL &&
	    extv[SADB_X_EXT_ADDRESS_INNER_DST] == NULL) {
		keysock_error(ks, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_MISSING_INNER_DST);
		return;
	}

	if (extv[SADB_X_EXT_ADDRESS_INNER_SRC] == NULL &&
	    extv[SADB_X_EXT_ADDRESS_INNER_DST] != NULL) {
		keysock_error(ks, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_MISSING_INNER_SRC);
		return;
	}

	reply_mp = ipsec_construct_inverse_acquire(samsg, extv,
	    keystack->keystack_netstack);

	if (reply_mp != NULL) {
		freemsg(mp);
		keysock_passup(reply_mp, (sadb_msg_t *)reply_mp->b_rptr,
		    ks->keysock_serial, NULL, B_FALSE, keystack);
	} else {
		keysock_error(ks, mp, samsg->sadb_msg_errno,
		    samsg->sadb_x_msg_diagnostic);
	}
}

/*
 * Spew an extended REGISTER down to the relevant consumers.
 */
static void
keysock_extended_register(keysock_t *ks, mblk_t *mp, sadb_ext_t *extv[])
{
	sadb_x_ereg_t *ereg = (sadb_x_ereg_t *)extv[SADB_X_EXT_EREG];
	uint8_t *satypes, *fencepost;
	mblk_t *downmp;
	sadb_ext_t *downextv[SADB_EXT_MAX + 1];
	keysock_stack_t	*keystack = ks->keysock_keystack;

	if (ks->keysock_registered[0] != 0 || ks->keysock_registered[1] != 0 ||
	    ks->keysock_registered[2] != 0 || ks->keysock_registered[3] != 0) {
		keysock_error(ks, mp, EBUSY, 0);
	}

	ks->keysock_flags |= KEYSOCK_EXTENDED;
	if (ereg == NULL) {
		keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_SATYPE_NEEDED);
	} else {
		ASSERT(mp->b_rptr + msgdsize(mp) == mp->b_wptr);
		fencepost = (uint8_t *)mp->b_wptr;
		satypes = ereg->sadb_x_ereg_satypes;
		while (*satypes != SADB_SATYPE_UNSPEC && satypes != fencepost) {
			downmp = copymsg(mp);
			if (downmp == NULL) {
				keysock_error(ks, mp, ENOMEM, 0);
				return;
			}
			/*
			 * Since we've made it here, keysock_get_ext will work!
			 */
			(void) keysock_get_ext(downextv,
			    (sadb_msg_t *)downmp->b_rptr, msgdsize(downmp),
			    keystack);
			keysock_passdown(ks, downmp, *satypes, downextv,
			    B_FALSE);
			++satypes;
		}
		freemsg(mp);
	}

	/*
	 * Set global to indicate we prefer an extended ACQUIRE.
	 */
	atomic_inc_32(&keystack->keystack_num_extended);
}

static void
keysock_delpair_all(keysock_t *ks, mblk_t *mp, sadb_ext_t *extv[])
{
	int i, start, finish;
	mblk_t *mp1 = NULL;
	keysock_stack_t *keystack = ks->keysock_keystack;

	start = 0;
	finish = KEYSOCK_MAX_CONSUMERS - 1;

	for (i = start; i <= finish; i++) {
		if (keystack->keystack_consumers[i] != NULL) {
			mp1 = copymsg(mp);
			if (mp1 == NULL) {
				keysock_error(ks, mp, ENOMEM,
				    SADB_X_DIAGNOSTIC_NONE);
				return;
			}
			keysock_passdown(ks, mp1, i, extv, B_FALSE);
		}
	}
}

/*
 * Handle PF_KEY messages.
 */
static void
keysock_parse(queue_t *q, mblk_t *mp)
{
	sadb_msg_t *samsg;
	sadb_ext_t *extv[SADB_EXT_MAX + 1];
	keysock_t *ks = (keysock_t *)q->q_ptr;
	uint_t msgsize;
	uint8_t satype;
	keysock_stack_t	*keystack = ks->keysock_keystack;

	/* Make sure I'm a PF_KEY socket.  (i.e. nothing's below me) */
	ASSERT(WR(q)->q_next == NULL);

	samsg = (sadb_msg_t *)mp->b_rptr;
	ks2dbg(keystack, ("Received possible PF_KEY message, type %d.\n",
	    samsg->sadb_msg_type));

	msgsize = SADB_64TO8(samsg->sadb_msg_len);

	if (msgdsize(mp) != msgsize) {
		/*
		 * Message len incorrect w.r.t. actual size.  Send an error
		 * (EMSGSIZE).	It may be necessary to massage things a
		 * bit.	 For example, if the sadb_msg_type is hosed,
		 * I need to set it to SADB_RESERVED to get delivery to
		 * do the right thing.	Then again, maybe just letting
		 * the error delivery do the right thing.
		 */
		ks2dbg(keystack,
		    ("mblk (%lu) and base (%d) message sizes don't jibe.\n",
		    msgdsize(mp), msgsize));
		keysock_error(ks, mp, EMSGSIZE, SADB_X_DIAGNOSTIC_NONE);
		return;
	}

	if (msgsize > (uint_t)(mp->b_wptr - mp->b_rptr)) {
		/* Get all message into one mblk. */
		if (pullupmsg(mp, -1) == 0) {
			/*
			 * Something screwy happened.
			 */
			ks3dbg(keystack,
			    ("keysock_parse: pullupmsg() failed.\n"));
			return;
		} else {
			samsg = (sadb_msg_t *)mp->b_rptr;
		}
	}

	switch (keysock_get_ext(extv, samsg, msgsize, keystack)) {
	case KGE_DUP:
		/* Handle duplicate extension. */
		ks1dbg(keystack, ("Got duplicate extension of type %d.\n",
		    extv[0]->sadb_ext_type));
		keysock_error(ks, mp, EINVAL,
		    keysock_duplicate(extv[0]->sadb_ext_type));
		return;
	case KGE_UNK:
		/* Handle unknown extension. */
		ks1dbg(keystack, ("Got unknown extension of type %d.\n",
		    extv[0]->sadb_ext_type));
		keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_UNKNOWN_EXT);
		return;
	case KGE_LEN:
		/* Length error. */
		ks1dbg(keystack,
		    ("Length %d on extension type %d overrun or 0.\n",
		    extv[0]->sadb_ext_len, extv[0]->sadb_ext_type));
		keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_BAD_EXTLEN);
		return;
	case KGE_CHK:
		/* Reality check failed. */
		ks1dbg(keystack,
		    ("Reality check failed on extension type %d.\n",
		    extv[0]->sadb_ext_type));
		keysock_error(ks, mp, EINVAL,
		    keysock_malformed(extv[0]->sadb_ext_type));
		return;
	default:
		/* Default case is no errors. */
		break;
	}

	switch (samsg->sadb_msg_type) {
	case SADB_REGISTER:
		/*
		 * There's a semantic weirdness in that a message OTHER than
		 * the return REGISTER message may be passed up if I set the
		 * registered bit BEFORE I pass it down.
		 *
		 * SOOOO, I'll not twiddle any registered bits until I see
		 * the upbound REGISTER (with a serial number in it).
		 */
		if (samsg->sadb_msg_satype == SADB_SATYPE_UNSPEC) {
			/* Handle extended register here. */
			keysock_extended_register(ks, mp, extv);
			return;
		} else if (ks->keysock_flags & KEYSOCK_EXTENDED) {
			keysock_error(ks, mp, EBUSY, 0);
			return;
		}
		/* FALLTHRU */
	case SADB_GETSPI:
	case SADB_ADD:
	case SADB_UPDATE:
	case SADB_X_UPDATEPAIR:
	case SADB_DELETE:
	case SADB_X_DELPAIR:
	case SADB_GET:
		/*
		 * Pass down to appropriate consumer.
		 */
		if (samsg->sadb_msg_satype != SADB_SATYPE_UNSPEC)
			keysock_passdown(ks, mp, samsg->sadb_msg_satype, extv,
			    B_FALSE);
		else keysock_error(ks, mp, EINVAL,
		    SADB_X_DIAGNOSTIC_SATYPE_NEEDED);
		return;
	case SADB_X_DELPAIR_STATE:
		if (samsg->sadb_msg_satype == SADB_SATYPE_UNSPEC) {
			keysock_delpair_all(ks, mp, extv);
		} else {
			keysock_passdown(ks, mp, samsg->sadb_msg_satype, extv,
			    B_FALSE);
		}
		return;
	case SADB_ACQUIRE:
		/*
		 * If I _receive_ an acquire, this means I should spread it
		 * out to registered sockets.  Unless there's an errno...
		 *
		 * Need ADDRESS, may have ID, SENS, and PROP, unless errno,
		 * in which case there should be NO extensions.
		 *
		 * Return to registered.
		 */
		if (samsg->sadb_msg_errno != 0) {
			satype = samsg->sadb_msg_satype;
			if (satype == SADB_SATYPE_UNSPEC) {
				if (!(ks->keysock_flags & KEYSOCK_EXTENDED)) {
					keysock_error(ks, mp, EINVAL,
					    SADB_X_DIAGNOSTIC_SATYPE_NEEDED);
					return;
				}
				/*
				 * Reassign satype based on the first
				 * flags that KEYSOCK_SETREG says.
				 */
				while (satype <= SADB_SATYPE_MAX) {
					if (KEYSOCK_ISREG(ks, satype))
						break;
					satype++;
				}
				if (satype > SADB_SATYPE_MAX) {
					keysock_error(ks, mp, EBUSY, 0);
					return;
				}
			}
			keysock_passdown(ks, mp, satype, extv, B_FALSE);
		} else {
			if (samsg->sadb_msg_satype == SADB_SATYPE_UNSPEC) {
				keysock_error(ks, mp, EINVAL,
				    SADB_X_DIAGNOSTIC_SATYPE_NEEDED);
			} else {
				keysock_passup(mp, samsg, 0, NULL, B_FALSE,
				    keystack);
			}
		}
		return;
	case SADB_EXPIRE:
		/*
		 * If someone sends this in, then send out to all senders.
		 * (Save maybe ESP or AH, I have to be careful here.)
		 *
		 * Need ADDRESS, may have ID and SENS.
		 *
		 * XXX for now this is unsupported.
		 */
		break;
	case SADB_FLUSH:
		/*
		 * Nuke all SAs.
		 *
		 * No extensions at all.  Return to all listeners.
		 *
		 * Question:	Should I hold a lock here to prevent
		 *		additions/deletions while flushing?
		 * Answer:	No.  (See keysock_passdown() for details.)
		 */
		if (extv[0] != NULL) {
			/*
			 * FLUSH messages shouldn't have extensions.
			 * Return EINVAL.
			 */
			ks2dbg(keystack, ("FLUSH message with extension.\n"));
			keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_NO_EXT);
			return;
		}

		/* Passing down of DUMP/FLUSH messages are special. */
		qwriter(q, mp, keysock_do_flushdump, PERIM_INNER);
		return;
	case SADB_DUMP:	 /* not used by normal applications */
		if ((extv[0] != NULL) &&
		    ((msgsize >
		    (sizeof (sadb_msg_t) + sizeof (sadb_x_edump_t))) ||
		    (extv[SADB_X_EXT_EDUMP] == NULL))) {
				keysock_error(ks, mp, EINVAL,
				    SADB_X_DIAGNOSTIC_NO_EXT);
				return;
		}
		qwriter(q, mp, keysock_do_flushdump, PERIM_INNER);
		return;
	case SADB_X_PROMISC:
		/*
		 * Promiscuous processing message.
		 */
		if (samsg->sadb_msg_satype == 0)
			ks->keysock_flags &= ~KEYSOCK_PROMISC;
		else
			ks->keysock_flags |= KEYSOCK_PROMISC;
		keysock_passup(mp, samsg, ks->keysock_serial, NULL, B_FALSE,
		    keystack);
		return;
	case SADB_X_INVERSE_ACQUIRE:
		keysock_inverse_acquire(mp, samsg, extv, ks);
		return;
	default:
		ks2dbg(keystack, ("Got unknown message type %d.\n",
		    samsg->sadb_msg_type));
		keysock_error(ks, mp, EINVAL, SADB_X_DIAGNOSTIC_UNKNOWN_MSG);
		return;
	}

	/* As a placeholder... */
	ks0dbg(("keysock_parse():  Hit EOPNOTSUPP\n"));
	keysock_error(ks, mp, EOPNOTSUPP, SADB_X_DIAGNOSTIC_NONE);
}

/*
 * wput routing for PF_KEY/keysock/whatever.  Unlike the routing socket,
 * I don't convert to ioctl()'s for IP.  I am the end-all driver as far
 * as PF_KEY sockets are concerned.  I do some conversion, but not as much
 * as IP/rts does.
 */
static void
keysock_wput(queue_t *q, mblk_t *mp)
{
	uchar_t *rptr = mp->b_rptr;
	mblk_t *mp1;
	keysock_t *ks;
	keysock_stack_t	*keystack;

	if (WR(q)->q_next) {
		keysock_consumer_t *kc = (keysock_consumer_t *)q->q_ptr;
		keystack = kc->kc_keystack;

		ks3dbg(keystack, ("In keysock_wput\n"));

		/*
		 * We shouldn't get writes on a consumer instance.
		 * But for now, just passthru.
		 */
		ks1dbg(keystack, ("Huh?  wput for an consumer instance (%d)?\n",
		    kc->kc_sa_type));
		putnext(q, mp);
		return;
	}
	ks = (keysock_t *)q->q_ptr;
	keystack = ks->keysock_keystack;

	ks3dbg(keystack, ("In keysock_wput\n"));

	switch (mp->b_datap->db_type) {
	case M_DATA:
		/*
		 * Silently discard.
		 */
		ks2dbg(keystack, ("raw M_DATA in keysock.\n"));
		freemsg(mp);
		return;
	case M_PROTO:
	case M_PCPROTO:
		if ((mp->b_wptr - rptr) >= sizeof (struct T_data_req)) {
			if (((union T_primitives *)rptr)->type == T_DATA_REQ) {
				if ((mp1 = mp->b_cont) == NULL) {
					/* No data after T_DATA_REQ. */
					ks2dbg(keystack,
					    ("No data after DATA_REQ.\n"));
					freemsg(mp);
					return;
				}
				freeb(mp);
				mp = mp1;
				ks2dbg(keystack, ("T_DATA_REQ\n"));
				break;	/* Out of switch. */
			}
		}
		/* FALLTHRU */
	default:
		ks3dbg(keystack, ("In default wput case (%d %d).\n",
		    mp->b_datap->db_type, ((union T_primitives *)rptr)->type));
		keysock_wput_other(q, mp);
		return;
	}

	/* I now have a PF_KEY message in an M_DATA block, pointed to by mp. */
	keysock_parse(q, mp);
}

/* BELOW THIS LINE ARE ROUTINES INCLUDING AND RELATED TO keysock_rput(). */

/*
 * Called upon receipt of a KEYSOCK_HELLO_ACK to set up the appropriate
 * state vectors.
 */
static void
keysock_link_consumer(uint8_t satype, keysock_consumer_t *kc)
{
	keysock_t *ks;
	keysock_stack_t	*keystack = kc->kc_keystack;

	mutex_enter(&keystack->keystack_consumers_lock);
	mutex_enter(&kc->kc_lock);
	if (keystack->keystack_consumers[satype] != NULL) {
		ks0dbg((
		    "Hmmmm, someone closed %d before the HELLO_ACK happened.\n",
		    satype));
		/*
		 * Perhaps updating the new below-me consumer with what I have
		 * so far would work too?
		 */
		mutex_exit(&kc->kc_lock);
		mutex_exit(&keystack->keystack_consumers_lock);
	} else {
		/* Add new below-me consumer. */
		keystack->keystack_consumers[satype] = kc;

		kc->kc_flags = 0;
		kc->kc_sa_type = satype;
		mutex_exit(&kc->kc_lock);
		mutex_exit(&keystack->keystack_consumers_lock);

		/* Scan the keysock list. */
		mutex_enter(&keystack->keystack_list_lock);
		for (ks = keystack->keystack_list; ks != NULL;
		    ks = ks->keysock_next) {
			if (KEYSOCK_ISREG(ks, satype)) {
				/*
				 * XXX Perhaps send an SADB_REGISTER down on
				 * the socket's behalf.
				 */
				ks1dbg(keystack,
				    ("Socket %u registered already for "
				    "new consumer.\n", ks->keysock_serial));
			}
		}
		mutex_exit(&keystack->keystack_list_lock);
	}
}

/*
 * Generate a KEYSOCK_OUT_ERR message for my consumer.
 */
static void
keysock_out_err(keysock_consumer_t *kc, int ks_errno, mblk_t *mp)
{
	keysock_out_err_t *kse;
	mblk_t *imp;
	keysock_stack_t	*keystack = kc->kc_keystack;

	imp = allocb(sizeof (ipsec_info_t), BPRI_HI);
	if (imp == NULL) {
		ks1dbg(keystack, ("keysock_out_err:  Can't alloc message.\n"));
		return;
	}

	imp->b_datap->db_type = M_CTL;
	imp->b_wptr += sizeof (ipsec_info_t);

	kse = (keysock_out_err_t *)imp->b_rptr;
	imp->b_cont = mp;
	kse->ks_err_type = KEYSOCK_OUT_ERR;
	kse->ks_err_len = sizeof (*kse);
	/* Is serial necessary? */
	kse->ks_err_serial = 0;
	kse->ks_err_errno = ks_errno;

	/*
	 * XXX What else do I need to do here w.r.t. information
	 * to tell the consumer what caused this error?
	 *
	 * I believe the answer is the PF_KEY ACQUIRE (or other) message
	 * attached in mp, which is appended at the end.  I believe the
	 * db_ref won't matter here, because the PF_KEY message is only read
	 * for KEYSOCK_OUT_ERR.
	 */

	putnext(kc->kc_wq, imp);
}

/* XXX this is a hack errno. */
#define	EIPSECNOSA 255

/*
 * Route message (pointed by mp, header in samsg) toward appropriate
 * sockets.  Assume the message's creator did its job correctly.
 *
 * This should be a function that is followed by a return in its caller.
 * The compiler _should_ be able to use tail-call optimizations to make the
 * large ## of parameters not a huge deal.
 */
static void
keysock_passup(mblk_t *mp, sadb_msg_t *samsg, minor_t serial,
    keysock_consumer_t *kc, boolean_t persistent, keysock_stack_t *keystack)
{
	keysock_t *ks;
	uint8_t satype = samsg->sadb_msg_satype;
	boolean_t toall = B_FALSE, allreg = B_FALSE, allereg = B_FALSE,
	    setalg = B_FALSE;
	mblk_t *mp1;
	int err = EIPSECNOSA;

	/* Convert mp, which is M_DATA, into an M_PROTO of type T_DATA_IND */
	mp1 = allocb(sizeof (struct T_data_req), BPRI_HI);
	if (mp1 == NULL) {
		err = ENOMEM;
		goto error;
	}
	mp1->b_wptr += sizeof (struct T_data_req);
	((struct T_data_ind *)mp1->b_rptr)->PRIM_type = T_DATA_IND;
	((struct T_data_ind *)mp1->b_rptr)->MORE_flag = 0;
	mp1->b_datap->db_type = M_PROTO;
	mp1->b_cont = mp;
	mp = mp1;

	switch (samsg->sadb_msg_type) {
	case SADB_FLUSH:
	case SADB_GETSPI:
	case SADB_UPDATE:
	case SADB_X_UPDATEPAIR:
	case SADB_ADD:
	case SADB_DELETE:
	case SADB_X_DELPAIR:
	case SADB_EXPIRE:
		/*
		 * These are most likely replies.  Don't worry about
		 * KEYSOCK_OUT_ERR handling.  Deliver to all sockets.
		 */
		ks3dbg(keystack,
		    ("Delivering normal message (%d) to all sockets.\n",
		    samsg->sadb_msg_type));
		toall = B_TRUE;
		break;
	case SADB_REGISTER:
		/*
		 * REGISTERs come up for one of three reasons:
		 *
		 *	1.) In response to a normal SADB_REGISTER
		 *		(samsg->sadb_msg_satype != SADB_SATYPE_UNSPEC &&
		 *		    serial != 0)
		 *		Deliver to normal SADB_REGISTERed sockets.
		 *	2.) In response to an extended REGISTER
		 *		(samsg->sadb_msg_satype == SADB_SATYPE_UNSPEC)
		 *		Deliver to extended REGISTERed socket.
		 *	3.) Spontaneous algorithm changes
		 *		(samsg->sadb_msg_satype != SADB_SATYPE_UNSPEC &&
		 *		    serial == 0)
		 *		Deliver to REGISTERed sockets of all sorts.
		 */
		if (kc == NULL) {
			/* Here because of keysock_error() call. */
			ASSERT(samsg->sadb_msg_errno != 0);
			break;	/* Out of switch. */
		}
		ks3dbg(keystack, ("Delivering REGISTER.\n"));
		if (satype == SADB_SATYPE_UNSPEC) {
			/* REGISTER Reason #2 */
			allereg = B_TRUE;
			/*
			 * Rewhack SA type so PF_KEY socket holder knows what
			 * consumer generated this algorithm list.
			 */
			satype = kc->kc_sa_type;
			samsg->sadb_msg_satype = satype;
			setalg = B_TRUE;
		} else if (serial == 0) {
			/* REGISTER Reason #3 */
			allreg = B_TRUE;
			allereg = B_TRUE;
		} else {
			/* REGISTER Reason #1 */
			allreg = B_TRUE;
			setalg = B_TRUE;
		}
		break;
	case SADB_ACQUIRE:
		/*
		 * ACQUIREs are either extended (sadb_msg_satype == 0) or
		 * regular (sadb_msg_satype != 0).  And we're guaranteed
		 * that serial == 0 for an ACQUIRE.
		 */
		ks3dbg(keystack, ("Delivering ACQUIRE.\n"));
		allereg = (satype == SADB_SATYPE_UNSPEC);
		allreg = !allereg;
		/*
		 * Corner case - if we send a regular ACQUIRE and there's
		 * extended ones registered, don't send an error down to
		 * consumers if nobody's listening and prematurely destroy
		 * their ACQUIRE record.  This might be too hackish of a
		 * solution.
		 */
		if (allreg && keystack->keystack_num_extended > 0)
			err = 0;
		break;
	case SADB_X_PROMISC:
	case SADB_X_INVERSE_ACQUIRE:
	case SADB_DUMP:
	case SADB_GET:
	default:
		/*
		 * Deliver to the sender and promiscuous only.
		 */
		ks3dbg(keystack, ("Delivering sender/promisc only (%d).\n",
		    samsg->sadb_msg_type));
		break;
	}

	mutex_enter(&keystack->keystack_list_lock);
	for (ks = keystack->keystack_list; ks != NULL; ks = ks->keysock_next) {
		/* Delivery loop. */

		/*
		 * Check special keysock-setting cases (REGISTER replies)
		 * here.
		 */
		if (setalg && serial == ks->keysock_serial) {
			ASSERT(kc != NULL);
			ASSERT(kc->kc_sa_type == satype);
			KEYSOCK_SETREG(ks, satype);
		}

		/*
		 * NOLOOP takes precedence over PROMISC.  So if you've set
		 * !SO_USELOOPBACK, don't expect to see any data...
		 */
		if (ks->keysock_flags & KEYSOCK_NOLOOP)
			continue;

		/*
		 * Messages to all, or promiscuous sockets just GET the
		 * message.  Perform rules-type checking iff it's not for all
		 * listeners or the socket is in promiscuous mode.
		 *
		 * NOTE:Because of the (kc != NULL && ISREG()), make sure
		 *	extended ACQUIREs arrive off a consumer that is
		 *	part of the extended REGISTER set of consumers.
		 */
		if (serial != ks->keysock_serial &&
		    !toall &&
		    !(ks->keysock_flags & KEYSOCK_PROMISC) &&
		    !((ks->keysock_flags & KEYSOCK_EXTENDED) ?
		    allereg : allreg && kc != NULL &&
		    KEYSOCK_ISREG(ks, kc->kc_sa_type)))
			continue;

		mp1 = dupmsg(mp);
		if (mp1 == NULL) {
			ks2dbg(keystack, (
			    "keysock_passup():  dupmsg() failed.\n"));
			mp1 = mp;
			mp = NULL;
			err = ENOMEM;
		}

		/*
		 * At this point, we can deliver or attempt to deliver
		 * this message.  We're free of obligation to report
		 * no listening PF_KEY sockets.  So set err to 0.
		 */
		err = 0;

		/*
		 * See if we canputnext(), as well as see if the message
		 * needs to be queued if we can't.
		 */
		if (!canputnext(ks->keysock_rq)) {
			if (persistent) {
				if (putq(ks->keysock_rq, mp1) == 0) {
					ks1dbg(keystack, (
					    "keysock_passup: putq failed.\n"));
				} else {
					continue;
				}
			}
			freemsg(mp1);
			continue;
		}

		ks3dbg(keystack,
		    ("Putting to serial %d.\n", ks->keysock_serial));
		/*
		 * Unlike the specific keysock instance case, this
		 * will only hit for listeners, so we will only
		 * putnext() if we can.
		 */
		putnext(ks->keysock_rq, mp1);
		if (mp == NULL)
			break;	/* out of for loop. */
	}
	mutex_exit(&keystack->keystack_list_lock);

error:
	if ((err != 0) && (kc != NULL)) {
		/*
		 * Generate KEYSOCK_OUT_ERR for consumer.
		 * Basically, I send this back if I have not been able to
		 * transmit (for whatever reason)
		 */
		ks1dbg(keystack,
		    ("keysock_passup():  No registered of type %d.\n",
		    satype));
		if (mp != NULL) {
			if (mp->b_datap->db_type == M_PROTO) {
				mp1 = mp;
				mp = mp->b_cont;
				freeb(mp1);
			}
			/*
			 * Do a copymsg() because people who get
			 * KEYSOCK_OUT_ERR may alter the message contents.
			 */
			mp1 = copymsg(mp);
			if (mp1 == NULL) {
				ks2dbg(keystack,
				    ("keysock_passup: copymsg() failed.\n"));
				mp1 = mp;
				mp = NULL;
			}
			keysock_out_err(kc, err, mp1);
		}
	}

	/*
	 * XXX Blank the message somehow.  This is difficult because we don't
	 * know at this point if the message has db_ref > 1, etc.
	 *
	 * Optimally, keysock messages containing actual keying material would
	 * be allocated with esballoc(), with a zeroing free function.
	 */
	if (mp != NULL)
		freemsg(mp);
}

/*
 * Keysock's read service procedure is there only for PF_KEY reply
 * messages that really need to reach the top.
 */
static void
keysock_rsrv(queue_t *q)
{
	mblk_t *mp;

	while ((mp = getq(q)) != NULL) {
		if (canputnext(q)) {
			putnext(q, mp);
		} else {
			(void) putbq(q, mp);
			return;
		}
	}
}

/*
 * The read procedure should only be invoked by a keysock consumer, like
 * ESP, AH, etc.  I should only see KEYSOCK_OUT and KEYSOCK_HELLO_ACK
 * messages on my read queues.
 */
static void
keysock_rput(queue_t *q, mblk_t *mp)
{
	keysock_consumer_t *kc = (keysock_consumer_t *)q->q_ptr;
	ipsec_info_t *ii;
	keysock_hello_ack_t *ksa;
	minor_t serial;
	mblk_t *mp1;
	sadb_msg_t *samsg;
	keysock_stack_t	*keystack = kc->kc_keystack;

	/* Make sure I'm a consumer instance.  (i.e. something's below me) */
	ASSERT(WR(q)->q_next != NULL);

	if (mp->b_datap->db_type != M_CTL) {
		/*
		 * Keysock should only see keysock consumer interface
		 * messages (see ipsec_info.h) on its read procedure.
		 * To be robust, however, putnext() up so the STREAM head can
		 * deal with it appropriately.
		 */
		ks1dbg(keystack,
		    ("Hmmm, a non M_CTL (%d, 0x%x) on keysock_rput.\n",
		    mp->b_datap->db_type, mp->b_datap->db_type));
		putnext(q, mp);
		return;
	}

	ii = (ipsec_info_t *)mp->b_rptr;

	switch (ii->ipsec_info_type) {
	case KEYSOCK_OUT:
		/*
		 * A consumer needs to pass a response message or an ACQUIRE
		 * UP.  I assume that the consumer has done the right
		 * thing w.r.t. message creation, etc.
		 */
		serial = ((keysock_out_t *)mp->b_rptr)->ks_out_serial;
		mp1 = mp->b_cont;	/* Get M_DATA portion. */
		freeb(mp);
		samsg = (sadb_msg_t *)mp1->b_rptr;
		if (samsg->sadb_msg_type == SADB_FLUSH ||
		    (samsg->sadb_msg_type == SADB_DUMP &&
		    samsg->sadb_msg_len == SADB_8TO64(sizeof (*samsg)))) {
			/*
			 * If I'm an end-of-FLUSH or an end-of-DUMP marker...
			 */
			ASSERT(keystack->keystack_flushdump != 0);
						/* Am I flushing? */

			mutex_enter(&kc->kc_lock);
			kc->kc_flags &= ~KC_FLUSHING;
			mutex_exit(&kc->kc_lock);

			if (samsg->sadb_msg_errno != 0)
				keystack->keystack_flushdump_errno =
				    samsg->sadb_msg_errno;

			/*
			 * Lower the atomic "flushing" count.  If it's
			 * the last one, send up the end-of-{FLUSH,DUMP} to
			 * the appropriate PF_KEY socket.
			 */
			if (atomic_dec_32_nv(&keystack->keystack_flushdump) !=
			    0) {
				ks1dbg(keystack,
				    ("One flush/dump message back from %d,"
				    " more to go.\n", samsg->sadb_msg_satype));
				freemsg(mp1);
				return;
			}

			samsg->sadb_msg_errno =
			    (uint8_t)keystack->keystack_flushdump_errno;
			if (samsg->sadb_msg_type == SADB_DUMP) {
				samsg->sadb_msg_seq = 0;
			}
		}
		keysock_passup(mp1, samsg, serial, kc,
		    (samsg->sadb_msg_type == SADB_DUMP), keystack);
		return;
	case KEYSOCK_HELLO_ACK:
		/* Aha, now we can link in the consumer! */
		ksa = (keysock_hello_ack_t *)ii;
		keysock_link_consumer(ksa->ks_hello_satype, kc);
		freemsg(mp);
		return;
	default:
		ks1dbg(keystack, ("Hmmm, an IPsec info I'm not used to, 0x%x\n",
		    ii->ipsec_info_type));
		putnext(q, mp);
	}
}

/*
 * So we can avoid external linking problems....
 */
boolean_t
keysock_extended_reg(netstack_t *ns)
{
	keysock_stack_t	*keystack = ns->netstack_keysock;

	return (keystack->keystack_num_extended != 0);
}

uint32_t
keysock_next_seq(netstack_t *ns)
{
	keysock_stack_t	*keystack = ns->netstack_keysock;

	return (atomic_dec_32_nv(&keystack->keystack_acquire_seq));
}
