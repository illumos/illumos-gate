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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * This module implements a STREAMS driver that provides layer-two (Ethernet)
 * bridging functionality.  The STREAMS interface is used to provide
 * observability (snoop/wireshark) and control, but not for interface plumbing.
 */

#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/errno.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/note.h>
#include <sys/param.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/dlpi.h>
#include <sys/dls.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_impl.h>
#include <sys/vlan.h>
#include <net/bridge.h>
#include <net/bridge_impl.h>
#include <net/trill.h>
#include <sys/dld_ioc.h>

/*
 * Locks and reference counts: object lifetime and design.
 *
 * bridge_mac_t
 *   Bridge mac (snoop) instances are in bmac_list, which is protected by
 *   bmac_rwlock.  They're allocated by bmac_alloc and freed by bridge_timer().
 *   Every bridge_inst_t has a single bridge_mac_t, but when bridge_inst_t goes
 *   away, the bridge_mac_t remains until either all of the users go away
 *   (detected by a timer) or until the instance is picked up again by the same
 *   bridge starting back up.
 *
 * bridge_inst_t
 *   Bridge instances are in inst_list, which is protected by inst_lock.
 *   They're allocated by inst_alloc() and freed by inst_free().  After
 *   allocation, an instance is placed in inst_list, and the reference count is
 *   incremented to represent this.  That reference is decremented when the
 *   BIF_SHUTDOWN flag is set, and no new increments may occur.  When the last
 *   reference is freed, the instance is removed from the list.
 *
 *   Bridge instances have lists of links and an AVL tree of forwarding
 *   entries.  Each of these structures holds one reference on the bridge
 *   instance.  These lists and tree are protected by bi_rwlock.
 *
 * bridge_stream_t
 *   Bridge streams are allocated by stream_alloc() and freed by stream_free().
 *   These streams are created when "bridged" opens /dev/bridgectl, and are
 *   used to create new bridge instances (via BRIOC_NEWBRIDGE) and control the
 *   links on the bridge.  When a stream closes, the bridge instance created is
 *   destroyed.  There's at most one bridge instance for a given control
 *   stream.
 *
 * bridge_link_t
 *   Links are allocated by bridge_add_link() and freed by link_free().  The
 *   bi_links list holds a reference to the link.  When the BLF_DELETED flag is
 *   set, that reference is dropped.  The link isn't removed from the list
 *   until the last reference drops.  Each forwarding entry that uses a given
 *   link holds a reference, as does each thread transmitting a packet via the
 *   link.  The MAC layer calls in via bridge_ref_cb() to hold a reference on
 *   a link when transmitting.
 *
 *   It's important that once BLF_DELETED is set, there's no way for the
 *   reference count to increase again.  If it can, then the link may be
 *   double-freed.  The BLF_FREED flag is intended for use with assertions to
 *   guard against this in testing.
 *
 * bridge_fwd_t
 *   Bridge forwarding entries are allocated by bridge_recv_cb() and freed by
 *   fwd_free().  The bi_fwd AVL tree holds one reference to the entry.  Unlike
 *   other data structures, the reference is dropped when the entry is removed
 *   from the tree by fwd_delete(), and the BFF_INTREE flag is removed.  Each
 *   thread that's forwarding a packet to a known destination holds a reference
 *   to a forwarding entry.
 *
 * TRILL notes:
 *
 *   The TRILL module does all of its I/O through bridging.  It uses references
 *   on the bridge_inst_t and bridge_link_t structures, and has seven entry
 *   points and four callbacks.  One entry point is for setting the callbacks
 *   (bridge_trill_register_cb).  There are four entry points for taking bridge
 *   and link references (bridge_trill_{br,ln}{ref,unref}).  The final two
 *   entry points are for decapsulated packets from TRILL (bridge_trill_decaps)
 *   that need to be bridged locally, and for TRILL-encapsulated output packets
 *   (bridge_trill_output).
 *
 *   The four callbacks comprise two notification functions for bridges and
 *   links being deleted, one function for raw received TRILL packets, and one
 *   for bridge output to non-local TRILL destinations (tunnel entry).
 */

/*
 * Ethernet reserved multicast addresses for TRILL; used also in TRILL module.
 */
const uint8_t all_isis_rbridges[] = ALL_ISIS_RBRIDGES;
static const uint8_t all_esadi_rbridges[] = ALL_ESADI_RBRIDGES;
const uint8_t bridge_group_address[] = BRIDGE_GROUP_ADDRESS;

static const char *inst_kstats_list[] = { KSINST_NAMES };
static const char *link_kstats_list[] = { KSLINK_NAMES };

#define	KREF(p, m, vn)	p->m.vn.value.ui64
#define	KINCR(p, m, vn)	++KREF(p, m, vn)
#define	KDECR(p, m, vn)	--KREF(p, m, vn)

#define	KIPINCR(p, vn)	KINCR(p, bi_kstats, vn)
#define	KIPDECR(p, vn)	KDECR(p, bi_kstats, vn)
#define	KLPINCR(p, vn)	KINCR(p, bl_kstats, vn)

#define	KIINCR(vn)	KIPINCR(bip, vn)
#define	KIDECR(vn)	KIPDECR(bip, vn)
#define	KLINCR(vn)	KLPINCR(blp, vn)

#define	Dim(x)		(sizeof (x) / sizeof (*(x)))

/* Amount of overhead added when encapsulating with VLAN headers */
#define	VLAN_INCR	(sizeof (struct ether_vlan_header) -	\
			sizeof (struct ether_header))

static dev_info_t *bridge_dev_info;
static major_t bridge_major;
static ddi_taskq_t *bridge_taskq;

/*
 * These are the bridge instance management data structures.  The mutex lock
 * protects the list of bridge instances.  A reference count is then used on
 * each instance to determine when to free it.  We use mac_minor_hold() to
 * allocate minor_t values, which are used both for self-cloning /dev/net/
 * device nodes as well as client streams.  Minor node 0 is reserved for the
 * allocation control node.
 */
static list_t inst_list;
static kcondvar_t inst_cv;		/* Allows us to wait for shutdown */
static kmutex_t inst_lock;

static krwlock_t bmac_rwlock;
static list_t bmac_list;

/* Wait for taskq entries that use STREAMS */
static kcondvar_t stream_ref_cv;
static kmutex_t stream_ref_lock;

static timeout_id_t bridge_timerid;
static clock_t bridge_scan_interval;
static clock_t bridge_fwd_age;

static bridge_inst_t *bridge_find_name(const char *);
static void bridge_timer(void *);
static void bridge_unref(bridge_inst_t *);

static const uint8_t zero_addr[ETHERADDRL] = { 0 };

/* Global TRILL linkage */
static trill_recv_pkt_t trill_recv_fn;
static trill_encap_pkt_t trill_encap_fn;
static trill_br_dstr_t trill_brdstr_fn;
static trill_ln_dstr_t trill_lndstr_fn;

/* special settings to accommodate DLD flow control; see dld_str.c */
static struct module_info bridge_dld_modinfo = {
	0,			/* mi_idnum */
	BRIDGE_DEV_NAME,	/* mi_idname */
	0,			/* mi_minpsz */
	INFPSZ,			/* mi_maxpsz */
	1,			/* mi_hiwat */
	0			/* mi_lowat */
};

static struct qinit bridge_dld_rinit = {
	NULL,			/* qi_putp */
	NULL,			/* qi_srvp */
	dld_open,		/* qi_qopen */
	dld_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&bridge_dld_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit bridge_dld_winit = {
	(int (*)())dld_wput,	/* qi_putp */
	(int (*)())dld_wsrv,	/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&bridge_dld_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static int bridge_ioc_listfwd(void *, intptr_t, int, cred_t *, int *);

/* GLDv3 control ioctls used by Bridging */
static dld_ioc_info_t bridge_ioc_list[] = {
	{BRIDGE_IOC_LISTFWD, DLDCOPYINOUT, sizeof (bridge_listfwd_t),
	    bridge_ioc_listfwd, NULL},
};

/*
 * Given a bridge mac pointer, get a ref-held pointer to the corresponding
 * bridge instance, if any.  We must hold the global bmac_rwlock so that
 * bm_inst doesn't slide out from under us.
 */
static bridge_inst_t *
mac_to_inst(const bridge_mac_t *bmp)
{
	bridge_inst_t *bip;

	rw_enter(&bmac_rwlock, RW_READER);
	if ((bip = bmp->bm_inst) != NULL)
		atomic_inc_uint(&bip->bi_refs);
	rw_exit(&bmac_rwlock);
	return (bip);
}

static void
link_sdu_fail(bridge_link_t *blp, boolean_t failed, mblk_t **mlist)
{
	mblk_t *mp;
	bridge_ctl_t *bcp;
	bridge_link_t *blcmp;
	bridge_inst_t *bip;
	bridge_mac_t *bmp;

	if (failed) {
		if (blp->bl_flags & BLF_SDUFAIL)
			return;
		blp->bl_flags |= BLF_SDUFAIL;
	} else {
		if (!(blp->bl_flags & BLF_SDUFAIL))
			return;
		blp->bl_flags &= ~BLF_SDUFAIL;
	}

	/*
	 * If this link is otherwise up, then check if there are any other
	 * non-failed non-down links.  If not, then we control the state of the
	 * whole bridge.
	 */
	bip = blp->bl_inst;
	bmp = bip->bi_mac;
	if (blp->bl_linkstate != LINK_STATE_DOWN) {
		for (blcmp = list_head(&bip->bi_links); blcmp != NULL;
		    blcmp = list_next(&bip->bi_links, blcmp)) {
			if (blp != blcmp &&
			    !(blcmp->bl_flags & (BLF_DELETED|BLF_SDUFAIL)) &&
			    blcmp->bl_linkstate != LINK_STATE_DOWN)
				break;
		}
		if (blcmp == NULL) {
			bmp->bm_linkstate = failed ? LINK_STATE_DOWN :
			    LINK_STATE_UP;
			mac_link_redo(bmp->bm_mh, bmp->bm_linkstate);
		}
	}

	/*
	 * If we're becoming failed, then the link's current true state needs
	 * to be reflected upwards to this link's clients.  If we're becoming
	 * unfailed, then we get the state of the bridge instead on all
	 * clients.
	 */
	if (failed) {
		if (bmp->bm_linkstate != blp->bl_linkstate)
			mac_link_redo(blp->bl_mh, blp->bl_linkstate);
	} else {
		mac_link_redo(blp->bl_mh, bmp->bm_linkstate);
	}

	/* get the current mblk we're going to send up */
	if ((mp = blp->bl_lfailmp) == NULL &&
	    (mp = allocb(sizeof (bridge_ctl_t), BPRI_MED)) == NULL)
		return;

	/* get a new one for next time */
	blp->bl_lfailmp = allocb(sizeof (bridge_ctl_t), BPRI_MED);

	/* if none for next time, then report only failures */
	if (blp->bl_lfailmp == NULL && !failed) {
		blp->bl_lfailmp = mp;
		return;
	}

	/* LINTED: alignment */
	bcp = (bridge_ctl_t *)mp->b_rptr;
	bcp->bc_linkid = blp->bl_linkid;
	bcp->bc_failed = failed;
	mp->b_wptr = (uchar_t *)(bcp + 1);
	mp->b_next = *mlist;
	*mlist = mp;
}

/*
 * Send control messages (link SDU changes) using the stream to the
 * bridge instance daemon.
 */
static void
send_up_messages(bridge_inst_t *bip, mblk_t *mp)
{
	mblk_t *mnext;
	queue_t *rq;

	rq = bip->bi_control->bs_wq;
	rq = OTHERQ(rq);
	while (mp != NULL) {
		mnext = mp->b_next;
		mp->b_next = NULL;
		putnext(rq, mp);
		mp = mnext;
	}
}

/* ARGSUSED */
static int
bridge_m_getstat(void *arg, uint_t stat, uint64_t *val)
{
	return (ENOTSUP);
}

static int
bridge_m_start(void *arg)
{
	bridge_mac_t *bmp = arg;

	bmp->bm_flags |= BMF_STARTED;
	return (0);
}

static void
bridge_m_stop(void *arg)
{
	bridge_mac_t *bmp = arg;

	bmp->bm_flags &= ~BMF_STARTED;
}

/* ARGSUSED */
static int
bridge_m_setpromisc(void *arg, boolean_t on)
{
	return (0);
}

/* ARGSUSED */
static int
bridge_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (0);
}

/* ARGSUSED */
static int
bridge_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (ENOTSUP);
}

static mblk_t *
bridge_m_tx(void *arg, mblk_t *mp)
{
	_NOTE(ARGUNUSED(arg));
	freemsgchain(mp);
	return (NULL);
}

/* ARGSUSED */
static int
bridge_ioc_listfwd(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	bridge_listfwd_t *blf = karg;
	bridge_inst_t *bip;
	bridge_fwd_t *bfp, match;
	avl_index_t where;

	bip = bridge_find_name(blf->blf_name);
	if (bip == NULL)
		return (ENOENT);

	bcopy(blf->blf_dest, match.bf_dest, ETHERADDRL);
	match.bf_flags |= BFF_VLANLOCAL;
	rw_enter(&bip->bi_rwlock, RW_READER);
	if ((bfp = avl_find(&bip->bi_fwd, &match, &where)) == NULL)
		bfp = avl_nearest(&bip->bi_fwd, where, AVL_AFTER);
	else
		bfp = AVL_NEXT(&bip->bi_fwd, bfp);
	if (bfp == NULL) {
		bzero(blf, sizeof (*blf));
	} else {
		bcopy(bfp->bf_dest, blf->blf_dest, ETHERADDRL);
		blf->blf_trill_nick = bfp->bf_trill_nick;
		blf->blf_ms_age =
		    drv_hztousec(ddi_get_lbolt() - bfp->bf_lastheard) / 1000;
		blf->blf_is_local =
		    (bfp->bf_flags & BFF_LOCALADDR) != 0;
		blf->blf_linkid = bfp->bf_links[0]->bl_linkid;
	}
	rw_exit(&bip->bi_rwlock);
	bridge_unref(bip);
	return (0);
}

static int
bridge_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	bridge_mac_t *bmp = arg;
	bridge_inst_t *bip;
	bridge_link_t *blp;
	int err;
	uint_t maxsdu;
	mblk_t *mlist;

	_NOTE(ARGUNUSED(pr_name));
	switch (pr_num) {
	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (bmp->bm_maxsdu)) {
			err = EINVAL;
			break;
		}
		(void) bcopy(pr_val, &maxsdu, sizeof (maxsdu));
		if (maxsdu == bmp->bm_maxsdu) {
			err = 0;
		} else if ((bip = mac_to_inst(bmp)) == NULL) {
			err = ENXIO;
		} else {
			rw_enter(&bip->bi_rwlock, RW_WRITER);
			mlist = NULL;
			for (blp = list_head(&bip->bi_links); blp != NULL;
			    blp = list_next(&bip->bi_links, blp)) {
				if (blp->bl_flags & BLF_DELETED)
					continue;
				if (blp->bl_maxsdu == maxsdu)
					link_sdu_fail(blp, B_FALSE, &mlist);
				else if (blp->bl_maxsdu == bmp->bm_maxsdu)
					link_sdu_fail(blp, B_TRUE, &mlist);
			}
			rw_exit(&bip->bi_rwlock);
			bmp->bm_maxsdu = maxsdu;
			(void) mac_maxsdu_update(bmp->bm_mh, maxsdu);
			send_up_messages(bip, mlist);
			bridge_unref(bip);
			err = 0;
		}
		break;

	default:
		err = ENOTSUP;
		break;
	}
	return (err);
}

static int
bridge_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	bridge_mac_t *bmp = arg;
	int err = 0;

	_NOTE(ARGUNUSED(pr_name));
	switch (pr_num) {
	case MAC_PROP_STATUS:
		ASSERT(pr_valsize >= sizeof (bmp->bm_linkstate));
		bcopy(&bmp->bm_linkstate, pr_val, sizeof (&bmp->bm_linkstate));
		break;

	default:
		err = ENOTSUP;
		break;
	}
	return (err);
}

static void
bridge_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	bridge_mac_t *bmp = arg;

	_NOTE(ARGUNUSED(pr_name));

	switch (pr_num) {
	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh, bmp->bm_maxsdu,
		    bmp->bm_maxsdu);
		break;
	case MAC_PROP_STATUS:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;
	}
}

static mac_callbacks_t bridge_m_callbacks = {
	MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	bridge_m_getstat,
	bridge_m_start,
	bridge_m_stop,
	bridge_m_setpromisc,
	bridge_m_multicst,
	bridge_m_unicst,
	bridge_m_tx,
	NULL,	/* reserved */
	NULL,	/* ioctl */
	NULL,	/* getcapab */
	NULL,	/* open */
	NULL,	/* close */
	bridge_m_setprop,
	bridge_m_getprop,
	bridge_m_propinfo
};

/*
 * Create kstats from a list.
 */
static kstat_t *
kstat_setup(kstat_named_t *knt, const char **names, int nstat,
    const char *unitname)
{
	kstat_t *ksp;
	int i;

	for (i = 0; i < nstat; i++)
		kstat_named_init(&knt[i], names[i], KSTAT_DATA_UINT64);

	ksp = kstat_create_zone(BRIDGE_DEV_NAME, 0, unitname, "net",
	    KSTAT_TYPE_NAMED, nstat, KSTAT_FLAG_VIRTUAL, GLOBAL_ZONEID);
	if (ksp != NULL) {
		ksp->ks_data = knt;
		kstat_install(ksp);
	}
	return (ksp);
}

/*
 * Find an existing bridge_mac_t structure or allocate a new one for the given
 * bridge instance.  This creates the mac driver instance that snoop can use.
 */
static int
bmac_alloc(bridge_inst_t *bip, bridge_mac_t **bmacp)
{
	bridge_mac_t *bmp, *bnew;
	mac_register_t *mac;
	int err;

	*bmacp = NULL;
	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (EINVAL);

	bnew = kmem_zalloc(sizeof (*bnew), KM_SLEEP);

	rw_enter(&bmac_rwlock, RW_WRITER);
	for (bmp = list_head(&bmac_list); bmp != NULL;
	    bmp = list_next(&bmac_list, bmp)) {
		if (strcmp(bip->bi_name, bmp->bm_name) == 0) {
			ASSERT(bmp->bm_inst == NULL);
			bmp->bm_inst = bip;
			rw_exit(&bmac_rwlock);
			kmem_free(bnew, sizeof (*bnew));
			mac_free(mac);
			*bmacp = bmp;
			return (0);
		}
	}

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = bnew;
	mac->m_dip = bridge_dev_info;
	mac->m_instance = (uint_t)-1;
	mac->m_src_addr = (uint8_t *)zero_addr;
	mac->m_callbacks = &bridge_m_callbacks;

	/*
	 * Note that the SDU limits are irrelevant, as nobody transmits on the
	 * bridge node itself.  It's mainly for monitoring but we allow
	 * setting the bridge MTU for quick transition of all links part of the
	 * bridge to a new MTU.
	 */
	mac->m_min_sdu = 1;
	mac->m_max_sdu = 1500;
	err = mac_register(mac, &bnew->bm_mh);
	mac_free(mac);
	if (err != 0) {
		rw_exit(&bmac_rwlock);
		kmem_free(bnew, sizeof (*bnew));
		return (err);
	}

	bnew->bm_inst = bip;
	(void) strcpy(bnew->bm_name, bip->bi_name);
	if (list_is_empty(&bmac_list)) {
		bridge_timerid = timeout(bridge_timer, NULL,
		    bridge_scan_interval);
	}
	list_insert_tail(&bmac_list, bnew);
	rw_exit(&bmac_rwlock);

	/*
	 * Mark the MAC as unable to go "active" so that only passive clients
	 * (such as snoop) can bind to it.
	 */
	mac_no_active(bnew->bm_mh);
	*bmacp = bnew;
	return (0);
}

/*
 * Disconnect the given bridge_mac_t from its bridge instance.  The bridge
 * instance is going away.  The mac instance can't go away until the clients
 * are gone (see bridge_timer).
 */
static void
bmac_disconnect(bridge_mac_t *bmp)
{
	bridge_inst_t *bip;

	bmp->bm_linkstate = LINK_STATE_DOWN;
	mac_link_redo(bmp->bm_mh, LINK_STATE_DOWN);

	rw_enter(&bmac_rwlock, RW_READER);
	bip = bmp->bm_inst;
	bip->bi_mac = NULL;
	bmp->bm_inst = NULL;
	rw_exit(&bmac_rwlock);
}

/* This is used by the avl trees to sort forwarding table entries */
static int
fwd_compare(const void *addr1, const void *addr2)
{
	const bridge_fwd_t *fwd1 = addr1;
	const bridge_fwd_t *fwd2 = addr2;
	int diff = memcmp(fwd1->bf_dest, fwd2->bf_dest, ETHERADDRL);

	if (diff != 0)
		return (diff > 0 ? 1 : -1);

	if ((fwd1->bf_flags ^ fwd2->bf_flags) & BFF_VLANLOCAL) {
		if (fwd1->bf_vlanid > fwd2->bf_vlanid)
			return (1);
		else if (fwd1->bf_vlanid < fwd2->bf_vlanid)
			return (-1);
	}
	return (0);
}

static void
inst_free(bridge_inst_t *bip)
{
	ASSERT(bip->bi_mac == NULL);
	rw_destroy(&bip->bi_rwlock);
	list_destroy(&bip->bi_links);
	cv_destroy(&bip->bi_linkwait);
	avl_destroy(&bip->bi_fwd);
	if (bip->bi_ksp != NULL)
		kstat_delete(bip->bi_ksp);
	kmem_free(bip, sizeof (*bip));
}

static bridge_inst_t *
inst_alloc(const char *bridge)
{
	bridge_inst_t *bip;

	bip = kmem_zalloc(sizeof (*bip), KM_SLEEP);
	bip->bi_refs = 1;
	(void) strcpy(bip->bi_name, bridge);
	rw_init(&bip->bi_rwlock, NULL, RW_DRIVER, NULL);
	list_create(&bip->bi_links, sizeof (bridge_link_t),
	    offsetof(bridge_link_t, bl_node));
	cv_init(&bip->bi_linkwait, NULL, CV_DRIVER, NULL);
	avl_create(&bip->bi_fwd, fwd_compare, sizeof (bridge_fwd_t),
	    offsetof(bridge_fwd_t, bf_node));
	return (bip);
}

static bridge_inst_t *
bridge_find_name(const char *bridge)
{
	bridge_inst_t *bip;

	mutex_enter(&inst_lock);
	for (bip = list_head(&inst_list); bip != NULL;
	    bip = list_next(&inst_list, bip)) {
		if (!(bip->bi_flags & BIF_SHUTDOWN) &&
		    strcmp(bridge, bip->bi_name) == 0) {
			atomic_inc_uint(&bip->bi_refs);
			break;
		}
	}
	mutex_exit(&inst_lock);

	return (bip);
}

static int
bridge_create(datalink_id_t linkid, const char *bridge, bridge_inst_t **bipc,
    cred_t *cred)
{
	bridge_inst_t *bip, *bipnew;
	bridge_mac_t *bmp = NULL;
	int err;

	*bipc = NULL;
	bipnew = inst_alloc(bridge);

	mutex_enter(&inst_lock);
lookup_retry:
	for (bip = list_head(&inst_list); bip != NULL;
	    bip = list_next(&inst_list, bip)) {
		if (strcmp(bridge, bip->bi_name) == 0)
			break;
	}

	/* This should not take long; if it does, we've got a design problem */
	if (bip != NULL && (bip->bi_flags & BIF_SHUTDOWN)) {
		cv_wait(&inst_cv, &inst_lock);
		goto lookup_retry;
	}

	if (bip == NULL) {
		bip = bipnew;
		bipnew = NULL;
		list_insert_tail(&inst_list, bip);
	}

	mutex_exit(&inst_lock);
	if (bipnew != NULL) {
		inst_free(bipnew);
		return (EEXIST);
	}

	bip->bi_ksp = kstat_setup((kstat_named_t *)&bip->bi_kstats,
	    inst_kstats_list, Dim(inst_kstats_list), bip->bi_name);

	err = bmac_alloc(bip, &bmp);
	if ((bip->bi_mac = bmp) == NULL)
		goto fail_create;

	/*
	 * bm_inst is set, so the timer cannot yank the DLS rug from under us.
	 * No extra locking is needed here.
	 */
	if (!(bmp->bm_flags & BMF_DLS)) {
		err = dls_devnet_create(bmp->bm_mh, linkid, crgetzoneid(cred));
		if (err != 0)
			goto fail_create;
		bmp->bm_flags |= BMF_DLS;
	}

	bip->bi_dev = makedevice(bridge_major, mac_minor(bmp->bm_mh));
	*bipc = bip;
	return (0);

fail_create:
	ASSERT(bip->bi_trilldata == NULL);
	bip->bi_flags |= BIF_SHUTDOWN;
	bridge_unref(bip);
	return (err);
}

static void
bridge_unref(bridge_inst_t *bip)
{
	if (atomic_dec_uint_nv(&bip->bi_refs) == 0) {
		ASSERT(bip->bi_flags & BIF_SHUTDOWN);
		/* free up mac for reuse before leaving global list */
		if (bip->bi_mac != NULL)
			bmac_disconnect(bip->bi_mac);
		mutex_enter(&inst_lock);
		list_remove(&inst_list, bip);
		cv_broadcast(&inst_cv);
		mutex_exit(&inst_lock);
		inst_free(bip);
	}
}

/*
 * Stream instances are used only for allocating bridges and serving as a
 * control node.  They serve no data-handling function.
 */
static bridge_stream_t *
stream_alloc(void)
{
	bridge_stream_t *bsp;
	minor_t mn;

	if ((mn = mac_minor_hold(B_FALSE)) == 0)
		return (NULL);
	bsp = kmem_zalloc(sizeof (*bsp), KM_SLEEP);
	bsp->bs_minor = mn;
	return (bsp);
}

static void
stream_free(bridge_stream_t *bsp)
{
	mac_minor_rele(bsp->bs_minor);
	kmem_free(bsp, sizeof (*bsp));
}

/* Reference hold/release functions for STREAMS-related taskq */
static void
stream_ref(bridge_stream_t *bsp)
{
	mutex_enter(&stream_ref_lock);
	bsp->bs_taskq_cnt++;
	mutex_exit(&stream_ref_lock);
}

static void
stream_unref(bridge_stream_t *bsp)
{
	mutex_enter(&stream_ref_lock);
	if (--bsp->bs_taskq_cnt == 0)
		cv_broadcast(&stream_ref_cv);
	mutex_exit(&stream_ref_lock);
}

static void
link_free(bridge_link_t *blp)
{
	bridge_inst_t *bip = blp->bl_inst;

	ASSERT(!(blp->bl_flags & BLF_FREED));
	blp->bl_flags |= BLF_FREED;
	if (blp->bl_ksp != NULL)
		kstat_delete(blp->bl_ksp);
	if (blp->bl_lfailmp != NULL)
		freeb(blp->bl_lfailmp);
	cv_destroy(&blp->bl_trillwait);
	mutex_destroy(&blp->bl_trilllock);
	kmem_free(blp, sizeof (*blp));
	/* Don't unreference the bridge until the MAC is closed */
	bridge_unref(bip);
}

static void
link_unref(bridge_link_t *blp)
{
	if (atomic_dec_uint_nv(&blp->bl_refs) == 0) {
		bridge_inst_t *bip = blp->bl_inst;

		ASSERT(blp->bl_flags & BLF_DELETED);
		rw_enter(&bip->bi_rwlock, RW_WRITER);
		if (blp->bl_flags & BLF_LINK_ADDED)
			list_remove(&bip->bi_links, blp);
		rw_exit(&bip->bi_rwlock);
		if (bip->bi_trilldata != NULL && list_is_empty(&bip->bi_links))
			cv_broadcast(&bip->bi_linkwait);
		link_free(blp);
	}
}

static bridge_fwd_t *
fwd_alloc(const uint8_t *addr, uint_t nlinks, uint16_t nick)
{
	bridge_fwd_t *bfp;

	bfp = kmem_zalloc(sizeof (*bfp) + (nlinks * sizeof (bridge_link_t *)),
	    KM_NOSLEEP);
	if (bfp != NULL) {
		bcopy(addr, bfp->bf_dest, ETHERADDRL);
		bfp->bf_lastheard = ddi_get_lbolt();
		bfp->bf_maxlinks = nlinks;
		bfp->bf_links = (bridge_link_t **)(bfp + 1);
		bfp->bf_trill_nick = nick;
	}
	return (bfp);
}

static bridge_fwd_t *
fwd_find(bridge_inst_t *bip, const uint8_t *addr, uint16_t vlanid)
{
	bridge_fwd_t *bfp, *vbfp;
	bridge_fwd_t match;

	bcopy(addr, match.bf_dest, ETHERADDRL);
	match.bf_flags = 0;
	rw_enter(&bip->bi_rwlock, RW_READER);
	if ((bfp = avl_find(&bip->bi_fwd, &match, NULL)) != NULL) {
		if (bfp->bf_vlanid != vlanid && bfp->bf_vcnt > 0) {
			match.bf_vlanid = vlanid;
			match.bf_flags = BFF_VLANLOCAL;
			vbfp = avl_find(&bip->bi_fwd, &match, NULL);
			if (vbfp != NULL)
				bfp = vbfp;
		}
		atomic_inc_uint(&bfp->bf_refs);
	}
	rw_exit(&bip->bi_rwlock);
	return (bfp);
}

static void
fwd_free(bridge_fwd_t *bfp)
{
	uint_t i;
	bridge_inst_t *bip = bfp->bf_links[0]->bl_inst;

	KIDECR(bki_count);
	for (i = 0; i < bfp->bf_nlinks; i++)
		link_unref(bfp->bf_links[i]);
	kmem_free(bfp,
	    sizeof (*bfp) + bfp->bf_maxlinks * sizeof (bridge_link_t *));
}

static void
fwd_unref(bridge_fwd_t *bfp)
{
	if (atomic_dec_uint_nv(&bfp->bf_refs) == 0) {
		ASSERT(!(bfp->bf_flags & BFF_INTREE));
		fwd_free(bfp);
	}
}

static void
fwd_delete(bridge_fwd_t *bfp)
{
	bridge_inst_t *bip;
	bridge_fwd_t *bfpzero;

	if (bfp->bf_flags & BFF_INTREE) {
		ASSERT(bfp->bf_nlinks > 0);
		bip = bfp->bf_links[0]->bl_inst;
		rw_enter(&bip->bi_rwlock, RW_WRITER);
		/* Another thread could beat us to this */
		if (bfp->bf_flags & BFF_INTREE) {
			avl_remove(&bip->bi_fwd, bfp);
			bfp->bf_flags &= ~BFF_INTREE;
			if (bfp->bf_flags & BFF_VLANLOCAL) {
				bfp->bf_flags &= ~BFF_VLANLOCAL;
				bfpzero = avl_find(&bip->bi_fwd, bfp, NULL);
				if (bfpzero != NULL && bfpzero->bf_vcnt > 0)
					bfpzero->bf_vcnt--;
			}
			rw_exit(&bip->bi_rwlock);
			fwd_unref(bfp);		/* no longer in avl tree */
		} else {
			rw_exit(&bip->bi_rwlock);
		}
	}
}

static boolean_t
fwd_insert(bridge_inst_t *bip, bridge_fwd_t *bfp)
{
	avl_index_t idx;
	boolean_t retv;

	rw_enter(&bip->bi_rwlock, RW_WRITER);
	if (!(bip->bi_flags & BIF_SHUTDOWN) &&
	    avl_numnodes(&bip->bi_fwd) < bip->bi_tablemax &&
	    avl_find(&bip->bi_fwd, bfp, &idx) == NULL) {
		avl_insert(&bip->bi_fwd, bfp, idx);
		bfp->bf_flags |= BFF_INTREE;
		atomic_inc_uint(&bfp->bf_refs);	/* avl entry */
		retv = B_TRUE;
	} else {
		retv = B_FALSE;
	}
	rw_exit(&bip->bi_rwlock);
	return (retv);
}

static void
fwd_update_local(bridge_link_t *blp, const uint8_t *oldaddr,
    const uint8_t *newaddr)
{
	bridge_inst_t *bip = blp->bl_inst;
	bridge_fwd_t *bfp, *bfnew;
	bridge_fwd_t match;
	avl_index_t idx;
	boolean_t drop_ref = B_FALSE;

	if (bcmp(oldaddr, newaddr, ETHERADDRL) == 0)
		return;

	if (bcmp(oldaddr, zero_addr, ETHERADDRL) == 0)
		goto no_old_addr;

	/*
	 * Find the previous entry, and remove our link from it.
	 */
	bcopy(oldaddr, match.bf_dest, ETHERADDRL);
	rw_enter(&bip->bi_rwlock, RW_WRITER);
	if ((bfp = avl_find(&bip->bi_fwd, &match, NULL)) != NULL) {
		int i;

		/*
		 * See if we're in the list, and remove if so.
		 */
		for (i = 0; i < bfp->bf_nlinks; i++) {
			if (bfp->bf_links[i] == blp) {
				/*
				 * We assume writes are atomic, so no special
				 * MT handling is needed.  The list length is
				 * decremented first, and then we remove
				 * entries.
				 */
				bfp->bf_nlinks--;
				for (; i < bfp->bf_nlinks; i++)
					bfp->bf_links[i] = bfp->bf_links[i + 1];
				drop_ref = B_TRUE;
				break;
			}
		}
		/* If no more links, then remove and free up */
		if (bfp->bf_nlinks == 0) {
			avl_remove(&bip->bi_fwd, bfp);
			bfp->bf_flags &= ~BFF_INTREE;
		} else {
			bfp = NULL;
		}
	}
	rw_exit(&bip->bi_rwlock);
	if (bfp != NULL)
		fwd_unref(bfp);		/* no longer in avl tree */

	/*
	 * Now get the new link address and add this link to the list.  The
	 * list should be of length 1 unless the user has configured multiple
	 * NICs with the same address.  (That's an incorrect configuration, but
	 * we support it anyway.)
	 */
no_old_addr:
	bfp = NULL;
	if ((bip->bi_flags & BIF_SHUTDOWN) ||
	    bcmp(newaddr, zero_addr, ETHERADDRL) == 0)
		goto no_new_addr;

	bcopy(newaddr, match.bf_dest, ETHERADDRL);
	rw_enter(&bip->bi_rwlock, RW_WRITER);
	if ((bfp = avl_find(&bip->bi_fwd, &match, &idx)) == NULL) {
		bfnew = fwd_alloc(newaddr, 1, RBRIDGE_NICKNAME_NONE);
		if (bfnew != NULL)
			KIINCR(bki_count);
	} else if (bfp->bf_nlinks < bfp->bf_maxlinks) {
		/* special case: link fits in existing entry */
		bfnew = bfp;
	} else {
		bfnew = fwd_alloc(newaddr, bfp->bf_nlinks + 1,
		    RBRIDGE_NICKNAME_NONE);
		if (bfnew != NULL) {
			KIINCR(bki_count);
			avl_remove(&bip->bi_fwd, bfp);
			bfp->bf_flags &= ~BFF_INTREE;
			bfnew->bf_nlinks = bfp->bf_nlinks;
			bcopy(bfp->bf_links, bfnew->bf_links,
			    bfp->bf_nlinks * sizeof (bfp));
			/* reset the idx value due to removal above */
			(void) avl_find(&bip->bi_fwd, &match, &idx);
		}
	}

	if (bfnew != NULL) {
		bfnew->bf_links[bfnew->bf_nlinks++] = blp;
		if (drop_ref)
			drop_ref = B_FALSE;
		else
			atomic_inc_uint(&blp->bl_refs);	/* bf_links entry */

		if (bfnew != bfp) {
			/* local addresses are not subject to table limits */
			avl_insert(&bip->bi_fwd, bfnew, idx);
			bfnew->bf_flags |= (BFF_INTREE | BFF_LOCALADDR);
			atomic_inc_uint(&bfnew->bf_refs);	/* avl entry */
		}
	}
	rw_exit(&bip->bi_rwlock);

no_new_addr:
	/*
	 * If we found an existing entry and we replaced it with a new one,
	 * then drop the table reference from the old one.  We removed it from
	 * the AVL tree above.
	 */
	if (bfnew != NULL && bfp != NULL && bfnew != bfp)
		fwd_unref(bfp);

	/* Account for removed entry. */
	if (drop_ref)
		link_unref(blp);
}

static void
bridge_new_unicst(bridge_link_t *blp)
{
	uint8_t new_mac[ETHERADDRL];

	mac_unicast_primary_get(blp->bl_mh, new_mac);
	fwd_update_local(blp, blp->bl_local_mac, new_mac);
	bcopy(new_mac, blp->bl_local_mac, ETHERADDRL);
}

/*
 * We must shut down a link prior to freeing it, and doing that requires
 * blocking to wait for running MAC threads while holding a reference.  This is
 * run from a taskq to accomplish proper link shutdown followed by reference
 * drop.
 */
static void
link_shutdown(void *arg)
{
	bridge_link_t *blp = arg;
	mac_handle_t mh = blp->bl_mh;
	bridge_inst_t *bip;
	bridge_fwd_t *bfp, *bfnext;
	avl_tree_t fwd_scavenge;
	int i;

	/*
	 * This link is being destroyed.  Notify TRILL now that it's no longer
	 * possible to send packets.  Data packets may still arrive until TRILL
	 * calls bridge_trill_lnunref.
	 */
	if (blp->bl_trilldata != NULL)
		trill_lndstr_fn(blp->bl_trilldata, blp);

	if (blp->bl_flags & BLF_PROM_ADDED)
		(void) mac_promisc_remove(blp->bl_mphp);

	if (blp->bl_flags & BLF_SET_BRIDGE)
		mac_bridge_clear(mh, (mac_handle_t)blp);

	if (blp->bl_flags & BLF_MARGIN_ADDED) {
		(void) mac_notify_remove(blp->bl_mnh, B_TRUE);
		(void) mac_margin_remove(mh, blp->bl_margin);
	}

	/* Tell the clients the real link state when we leave */
	mac_link_redo(blp->bl_mh,
	    mac_stat_get(blp->bl_mh, MAC_STAT_LOWLINK_STATE));

	/* Destroy all of the forwarding entries related to this link */
	avl_create(&fwd_scavenge, fwd_compare, sizeof (bridge_fwd_t),
	    offsetof(bridge_fwd_t, bf_node));
	bip = blp->bl_inst;
	rw_enter(&bip->bi_rwlock, RW_WRITER);
	bfnext = avl_first(&bip->bi_fwd);
	while ((bfp = bfnext) != NULL) {
		bfnext = AVL_NEXT(&bip->bi_fwd, bfp);
		for (i = 0; i < bfp->bf_nlinks; i++) {
			if (bfp->bf_links[i] == blp)
				break;
		}
		if (i >= bfp->bf_nlinks)
			continue;
		if (bfp->bf_nlinks > 1) {
			/* note that this can't be the last reference */
			link_unref(blp);
			bfp->bf_nlinks--;
			for (; i < bfp->bf_nlinks; i++)
				bfp->bf_links[i] = bfp->bf_links[i + 1];
		} else {
			ASSERT(bfp->bf_flags & BFF_INTREE);
			avl_remove(&bip->bi_fwd, bfp);
			bfp->bf_flags &= ~BFF_INTREE;
			avl_add(&fwd_scavenge, bfp);
		}
	}
	rw_exit(&bip->bi_rwlock);
	bfnext = avl_first(&fwd_scavenge);
	while ((bfp = bfnext) != NULL) {
		bfnext = AVL_NEXT(&fwd_scavenge, bfp);
		avl_remove(&fwd_scavenge, bfp);
		fwd_unref(bfp);
	}
	avl_destroy(&fwd_scavenge);

	if (blp->bl_flags & BLF_CLIENT_OPEN)
		mac_client_close(blp->bl_mch, 0);

	mac_close(mh);

	/*
	 * We are now completely removed from the active list, so drop the
	 * reference (see bridge_add_link).
	 */
	link_unref(blp);
}

static void
shutdown_inst(bridge_inst_t *bip)
{
	bridge_link_t *blp, *blnext;
	bridge_fwd_t *bfp;

	mutex_enter(&inst_lock);
	if (bip->bi_flags & BIF_SHUTDOWN) {
		mutex_exit(&inst_lock);
		return;
	}

	/*
	 * Once on the inst_list, the bridge instance must not leave that list
	 * without having the shutdown flag set first.  When the shutdown flag
	 * is set, we own the list reference, so we must drop it before
	 * returning.
	 */
	bip->bi_flags |= BIF_SHUTDOWN;
	mutex_exit(&inst_lock);

	bip->bi_control = NULL;

	rw_enter(&bip->bi_rwlock, RW_READER);
	blnext = list_head(&bip->bi_links);
	while ((blp = blnext) != NULL) {
		blnext = list_next(&bip->bi_links, blp);
		if (!(blp->bl_flags & BLF_DELETED)) {
			blp->bl_flags |= BLF_DELETED;
			(void) ddi_taskq_dispatch(bridge_taskq, link_shutdown,
			    blp, DDI_SLEEP);
		}
	}
	while ((bfp = avl_first(&bip->bi_fwd)) != NULL) {
		atomic_inc_uint(&bfp->bf_refs);
		rw_exit(&bip->bi_rwlock);
		fwd_delete(bfp);
		fwd_unref(bfp);
		rw_enter(&bip->bi_rwlock, RW_READER);
	}
	rw_exit(&bip->bi_rwlock);

	/*
	 * This bridge is being destroyed.  Notify TRILL once all of the
	 * links are all gone.
	 */
	mutex_enter(&inst_lock);
	while (bip->bi_trilldata != NULL && !list_is_empty(&bip->bi_links))
		cv_wait(&bip->bi_linkwait, &inst_lock);
	mutex_exit(&inst_lock);
	if (bip->bi_trilldata != NULL)
		trill_brdstr_fn(bip->bi_trilldata, bip);

	bridge_unref(bip);
}

/*
 * This is called once by the TRILL module when it starts up.  It just sets the
 * global TRILL callback function pointers -- data transmit/receive and bridge
 * and link destroy notification.  There's only one TRILL module, so only one
 * registration is needed.
 *
 * TRILL should call this function with NULL pointers before unloading.  It
 * must not do so before dropping all references to bridges and links.  We
 * assert that this is true on debug builds.
 */
void
bridge_trill_register_cb(trill_recv_pkt_t recv_fn, trill_encap_pkt_t encap_fn,
    trill_br_dstr_t brdstr_fn, trill_ln_dstr_t lndstr_fn)
{
#ifdef DEBUG
	if (recv_fn == NULL && trill_recv_fn != NULL) {
		bridge_inst_t *bip;
		bridge_link_t *blp;

		mutex_enter(&inst_lock);
		for (bip = list_head(&inst_list); bip != NULL;
		    bip = list_next(&inst_list, bip)) {
			ASSERT(bip->bi_trilldata == NULL);
			rw_enter(&bip->bi_rwlock, RW_READER);
			for (blp = list_head(&bip->bi_links); blp != NULL;
			    blp = list_next(&bip->bi_links, blp)) {
				ASSERT(blp->bl_trilldata == NULL);
			}
			rw_exit(&bip->bi_rwlock);
		}
		mutex_exit(&inst_lock);
	}
#endif
	trill_recv_fn = recv_fn;
	trill_encap_fn = encap_fn;
	trill_brdstr_fn = brdstr_fn;
	trill_lndstr_fn = lndstr_fn;
}

/*
 * This registers the TRILL instance pointer with a bridge.  Before this
 * pointer is set, the forwarding, TRILL receive, and bridge destructor
 * functions won't be called.
 *
 * TRILL holds a reference on a bridge with this call.  It must free the
 * reference by calling the unregister function below.
 */
bridge_inst_t *
bridge_trill_brref(const char *bname, void *ptr)
{
	char bridge[MAXLINKNAMELEN];
	bridge_inst_t *bip;

	(void) snprintf(bridge, MAXLINKNAMELEN, "%s0", bname);
	bip = bridge_find_name(bridge);
	if (bip != NULL) {
		ASSERT(bip->bi_trilldata == NULL && ptr != NULL);
		bip->bi_trilldata = ptr;
	}
	return (bip);
}

void
bridge_trill_brunref(bridge_inst_t *bip)
{
	ASSERT(bip->bi_trilldata != NULL);
	bip->bi_trilldata = NULL;
	bridge_unref(bip);
}

/*
 * TRILL calls this function when referencing a particular link on a bridge.
 *
 * It holds a reference on the link, so TRILL must clear out the reference when
 * it's done with the link (on unbinding).
 */
bridge_link_t *
bridge_trill_lnref(bridge_inst_t *bip, datalink_id_t linkid, void *ptr)
{
	bridge_link_t *blp;

	ASSERT(ptr != NULL);
	rw_enter(&bip->bi_rwlock, RW_READER);
	for (blp = list_head(&bip->bi_links); blp != NULL;
	    blp = list_next(&bip->bi_links, blp)) {
		if (!(blp->bl_flags & BLF_DELETED) &&
		    blp->bl_linkid == linkid && blp->bl_trilldata == NULL) {
			blp->bl_trilldata = ptr;
			blp->bl_flags &= ~BLF_TRILLACTIVE;
			(void) memset(blp->bl_afs, 0, sizeof (blp->bl_afs));
			atomic_inc_uint(&blp->bl_refs);
			break;
		}
	}
	rw_exit(&bip->bi_rwlock);
	return (blp);
}

void
bridge_trill_lnunref(bridge_link_t *blp)
{
	mutex_enter(&blp->bl_trilllock);
	ASSERT(blp->bl_trilldata != NULL);
	blp->bl_trilldata = NULL;
	blp->bl_flags &= ~BLF_TRILLACTIVE;
	while (blp->bl_trillthreads > 0)
		cv_wait(&blp->bl_trillwait, &blp->bl_trilllock);
	mutex_exit(&blp->bl_trilllock);
	(void) memset(blp->bl_afs, 0xff, sizeof (blp->bl_afs));
	link_unref(blp);
}

/*
 * This periodic timer performs three functions:
 *  1. It scans the list of learned forwarding entries, and removes ones that
 *     haven't been heard from in a while.  The time limit is backed down if
 *     we're above the configured table limit.
 *  2. It walks the links and decays away the bl_learns counter.
 *  3. It scans the observability node entries looking for ones that can be
 *     freed up.
 */
/* ARGSUSED */
static void
bridge_timer(void *arg)
{
	bridge_inst_t *bip;
	bridge_fwd_t *bfp, *bfnext;
	bridge_mac_t *bmp, *bmnext;
	bridge_link_t *blp;
	int err;
	datalink_id_t tmpid;
	avl_tree_t fwd_scavenge;
	clock_t age_limit;
	uint32_t ldecay;

	avl_create(&fwd_scavenge, fwd_compare, sizeof (bridge_fwd_t),
	    offsetof(bridge_fwd_t, bf_node));
	mutex_enter(&inst_lock);
	for (bip = list_head(&inst_list); bip != NULL;
	    bip = list_next(&inst_list, bip)) {
		if (bip->bi_flags & BIF_SHUTDOWN)
			continue;
		rw_enter(&bip->bi_rwlock, RW_WRITER);
		/* compute scaled maximum age based on table limit */
		if (avl_numnodes(&bip->bi_fwd) > bip->bi_tablemax)
			bip->bi_tshift++;
		else
			bip->bi_tshift = 0;
		if ((age_limit = bridge_fwd_age >> bip->bi_tshift) == 0) {
			if (bip->bi_tshift != 0)
				bip->bi_tshift--;
			age_limit = 1;
		}
		bfnext = avl_first(&bip->bi_fwd);
		while ((bfp = bfnext) != NULL) {
			bfnext = AVL_NEXT(&bip->bi_fwd, bfp);
			if (!(bfp->bf_flags & BFF_LOCALADDR) &&
			    (ddi_get_lbolt() - bfp->bf_lastheard) > age_limit) {
				ASSERT(bfp->bf_flags & BFF_INTREE);
				avl_remove(&bip->bi_fwd, bfp);
				bfp->bf_flags &= ~BFF_INTREE;
				avl_add(&fwd_scavenge, bfp);
			}
		}
		for (blp = list_head(&bip->bi_links); blp != NULL;
		    blp = list_next(&bip->bi_links, blp)) {
			ldecay = mac_get_ldecay(blp->bl_mh);
			if (ldecay >= blp->bl_learns)
				blp->bl_learns = 0;
			else
				atomic_add_int(&blp->bl_learns, -(int)ldecay);
		}
		rw_exit(&bip->bi_rwlock);
		bfnext = avl_first(&fwd_scavenge);
		while ((bfp = bfnext) != NULL) {
			bfnext = AVL_NEXT(&fwd_scavenge, bfp);
			avl_remove(&fwd_scavenge, bfp);
			KIINCR(bki_expire);
			fwd_unref(bfp);	/* drop tree reference */
		}
	}
	mutex_exit(&inst_lock);
	avl_destroy(&fwd_scavenge);

	/*
	 * Scan the bridge_mac_t entries and try to free up the ones that are
	 * no longer active.  This must be done by polling, as neither DLS nor
	 * MAC provides a driver any sort of positive control over clients.
	 */
	rw_enter(&bmac_rwlock, RW_WRITER);
	bmnext = list_head(&bmac_list);
	while ((bmp = bmnext) != NULL) {
		bmnext = list_next(&bmac_list, bmp);

		/* ignore active bridges */
		if (bmp->bm_inst != NULL)
			continue;

		if (bmp->bm_flags & BMF_DLS) {
			err = dls_devnet_destroy(bmp->bm_mh, &tmpid, B_FALSE);
			ASSERT(err == 0 || err == EBUSY);
			if (err == 0)
				bmp->bm_flags &= ~BMF_DLS;
		}

		if (!(bmp->bm_flags & BMF_DLS)) {
			err = mac_unregister(bmp->bm_mh);
			ASSERT(err == 0 || err == EBUSY);
			if (err == 0) {
				list_remove(&bmac_list, bmp);
				kmem_free(bmp, sizeof (*bmp));
			}
		}
	}
	if (list_is_empty(&bmac_list)) {
		bridge_timerid = 0;
	} else {
		bridge_timerid = timeout(bridge_timer, NULL,
		    bridge_scan_interval);
	}
	rw_exit(&bmac_rwlock);
}

static int
bridge_open(queue_t *rq, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	bridge_stream_t	*bsp;

	if (rq->q_ptr != NULL)
		return (0);

	if (sflag & MODOPEN)
		return (EINVAL);

	/*
	 * Check the minor node number being opened.  This tells us which
	 * bridge instance the user wants.
	 */
	if (getminor(*devp) != 0) {
		/*
		 * This is a regular DLPI stream for snoop or the like.
		 * Redirect it through DLD.
		 */
		rq->q_qinfo = &bridge_dld_rinit;
		OTHERQ(rq)->q_qinfo = &bridge_dld_winit;
		return (dld_open(rq, devp, oflag, sflag, credp));
	} else {
		/*
		 * Allocate the bridge control stream structure.
		 */
		if ((bsp = stream_alloc()) == NULL)
			return (ENOSR);
		rq->q_ptr = WR(rq)->q_ptr = (caddr_t)bsp;
		bsp->bs_wq = WR(rq);
		*devp = makedevice(getmajor(*devp), bsp->bs_minor);
		qprocson(rq);
		return (0);
	}
}

/*
 * This is used only for bridge control streams.  DLPI goes through dld
 * instead.
 */
static int
bridge_close(queue_t *rq)
{
	bridge_stream_t	*bsp = rq->q_ptr;
	bridge_inst_t *bip;

	/*
	 * Wait for any stray taskq (add/delete link) entries related to this
	 * stream to leave the system.
	 */
	mutex_enter(&stream_ref_lock);
	while (bsp->bs_taskq_cnt != 0)
		cv_wait(&stream_ref_cv, &stream_ref_lock);
	mutex_exit(&stream_ref_lock);

	qprocsoff(rq);
	if ((bip = bsp->bs_inst) != NULL)
		shutdown_inst(bip);
	rq->q_ptr = WR(rq)->q_ptr = NULL;
	stream_free(bsp);
	if (bip != NULL)
		bridge_unref(bip);

	return (0);
}

static void
bridge_learn(bridge_link_t *blp, const uint8_t *saddr, uint16_t ingress_nick,
    uint16_t vlanid)
{
	bridge_inst_t *bip = blp->bl_inst;
	bridge_fwd_t *bfp, *bfpnew;
	int i;
	boolean_t replaced = B_FALSE;

	/* Ignore multi-destination address used as source; it's nonsense. */
	if (*saddr & 1)
		return;

	/*
	 * If the source is known, then check whether it belongs on this link.
	 * If not, and this isn't a fixed local address, then we've detected a
	 * move.  If it's not known, learn it.
	 */
	if ((bfp = fwd_find(bip, saddr, vlanid)) != NULL) {
		/*
		 * If the packet has a fixed local source address, then there's
		 * nothing we can learn.  We must quit.  If this was a received
		 * packet, then the sender has stolen our address, but there's
		 * nothing we can do.  If it's a transmitted packet, then
		 * that's the normal case.
		 */
		if (bfp->bf_flags & BFF_LOCALADDR) {
			fwd_unref(bfp);
			return;
		}

		/*
		 * Check if the link (and TRILL sender, if any) being used is
		 * among the ones registered for this address.  If so, then
		 * this is information that we already know.
		 */
		if (bfp->bf_trill_nick == ingress_nick) {
			for (i = 0; i < bfp->bf_nlinks; i++) {
				if (bfp->bf_links[i] == blp) {
					bfp->bf_lastheard = ddi_get_lbolt();
					fwd_unref(bfp);
					return;
				}
			}
		}
	}

	/*
	 * Note that we intentionally "unlearn" things that appear to be under
	 * attack on this link.  The forwarding cache is a negative thing for
	 * security -- it disables reachability as a performance optimization
	 * -- so leaving out entries optimizes for success and defends against
	 * the attack.  Thus, the bare increment without a check in the delete
	 * code above is right.  (And it's ok if we skid over the limit a
	 * little, so there's no syncronization needed on the test.)
	 */
	if (blp->bl_learns >= mac_get_llimit(blp->bl_mh)) {
		if (bfp != NULL) {
			if (bfp->bf_vcnt == 0)
				fwd_delete(bfp);
			fwd_unref(bfp);
		}
		return;
	}

	atomic_inc_uint(&blp->bl_learns);

	if ((bfpnew = fwd_alloc(saddr, 1, ingress_nick)) == NULL) {
		if (bfp != NULL)
			fwd_unref(bfp);
		return;
	}
	KIINCR(bki_count);

	if (bfp != NULL) {
		/*
		 * If this is a new destination for the same VLAN, then delete
		 * so that we can update.  If it's a different VLAN, then we're
		 * not going to delete the original.  Split off instead into an
		 * IVL entry.
		 */
		if (bfp->bf_vlanid == vlanid) {
			/* save the count of IVL duplicates */
			bfpnew->bf_vcnt = bfp->bf_vcnt;

			/* entry deletes count as learning events */
			atomic_inc_uint(&blp->bl_learns);

			/* destroy and create anew; node moved */
			fwd_delete(bfp);
			replaced = B_TRUE;
			KIINCR(bki_moved);
		} else {
			bfp->bf_vcnt++;
			bfpnew->bf_flags |= BFF_VLANLOCAL;
		}
		fwd_unref(bfp);
	}
	bfpnew->bf_links[0] = blp;
	bfpnew->bf_nlinks = 1;
	atomic_inc_uint(&blp->bl_refs);	/* bf_links entry */
	if (!fwd_insert(bip, bfpnew))
		fwd_free(bfpnew);
	else if (!replaced)
		KIINCR(bki_source);
}

/*
 * Process the VLAN headers for output on a given link.  There are several
 * cases (noting that we don't map VLANs):
 *   1. The input packet is good as it is; either
 *	a. It has no tag, and output has same PVID
 *	b. It has a non-zero priority-only tag for PVID, and b_band is same
 *	c. It has a tag with VLAN different from PVID, and b_band is same
 *   2. The tag must change: non-zero b_band is different from tag priority
 *   3. The packet has a tag and should not (VLAN same as PVID, b_band zero)
 *   4. The packet has no tag and needs one:
 *      a. VLAN ID same as PVID, but b_band is non-zero
 *      b. VLAN ID different from PVID
 * We exclude case 1 first, then modify the packet.  Note that output packets
 * get a priority set by the mblk, not by the header, because QoS in bridging
 * requires priority recalculation at each node.
 *
 * The passed-in tci is the "impossible" value 0xFFFF when no tag is present.
 */
static mblk_t *
reform_vlan_header(mblk_t *mp, uint16_t vlanid, uint16_t tci, uint16_t pvid)
{
	boolean_t source_has_tag = (tci != 0xFFFF);
	mblk_t *mpcopy;
	size_t mlen, minlen;
	struct ether_vlan_header *evh;
	int pri;

	/* This helps centralize error handling in the caller. */
	if (mp == NULL)
		return (mp);

	/* No forwarded packet can have hardware checksum enabled */
	DB_CKSUMFLAGS(mp) = 0;

	/* Get the no-modification cases out of the way first */
	if (!source_has_tag && vlanid == pvid)		/* 1a */
		return (mp);

	pri = VLAN_PRI(tci);
	if (source_has_tag && mp->b_band == pri) {
		if (vlanid != pvid)			/* 1c */
			return (mp);
		if (pri != 0 && VLAN_ID(tci) == 0)	/* 1b */
			return (mp);
	}

	/*
	 * We now know that we must modify the packet.  Prepare for that.  Note
	 * that if a tag is present, the caller has already done a pullup for
	 * the VLAN header, so we're good to go.
	 */
	if (MBLKL(mp) < sizeof (struct ether_header)) {
		mpcopy = msgpullup(mp, sizeof (struct ether_header));
		if (mpcopy == NULL) {
			freemsg(mp);
			return (NULL);
		}
		mp = mpcopy;
	}
	if (DB_REF(mp) > 1 || !IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)) ||
	    (!source_has_tag && MBLKTAIL(mp) < VLAN_INCR)) {
		minlen = mlen = MBLKL(mp);
		if (!source_has_tag)
			minlen += VLAN_INCR;
		ASSERT(minlen >= sizeof (struct ether_vlan_header));
		/*
		 * We're willing to copy some data to avoid fragmentation, but
		 * not a lot.
		 */
		if (minlen > 256)
			minlen = sizeof (struct ether_vlan_header);
		mpcopy = allocb(minlen, BPRI_MED);
		if (mpcopy == NULL) {
			freemsg(mp);
			return (NULL);
		}
		if (mlen <= minlen) {
			/* We toss the first mblk when we can. */
			bcopy(mp->b_rptr, mpcopy->b_rptr, mlen);
			mpcopy->b_wptr += mlen;
			mpcopy->b_cont = mp->b_cont;
			freeb(mp);
		} else {
			/* If not, then just copy what we need */
			if (!source_has_tag)
				minlen = sizeof (struct ether_header);
			bcopy(mp->b_rptr, mpcopy->b_rptr, minlen);
			mpcopy->b_wptr += minlen;
			mpcopy->b_cont = mp;
			mp->b_rptr += minlen;
		}
		mp = mpcopy;
	}

	/* LINTED: pointer alignment */
	evh = (struct ether_vlan_header *)mp->b_rptr;
	if (source_has_tag) {
		if (mp->b_band == 0 && vlanid == pvid) {	/* 3 */
			evh->ether_tpid = evh->ether_type;
			mlen = MBLKL(mp);
			if (mlen > sizeof (struct ether_vlan_header))
				ovbcopy(mp->b_rptr +
				    sizeof (struct ether_vlan_header),
				    mp->b_rptr + sizeof (struct ether_header),
				    mlen - sizeof (struct ether_vlan_header));
			mp->b_wptr -= VLAN_INCR;
		} else {					/* 2 */
			if (vlanid == pvid)
				vlanid = VLAN_ID_NONE;
			tci = VLAN_TCI(mp->b_band, ETHER_CFI, vlanid);
			evh->ether_tci = htons(tci);
		}
	} else {
		/* case 4: no header present, but one is needed */
		mlen = MBLKL(mp);
		if (mlen > sizeof (struct ether_header))
			ovbcopy(mp->b_rptr + sizeof (struct ether_header),
			    mp->b_rptr + sizeof (struct ether_vlan_header),
			    mlen - sizeof (struct ether_header));
		mp->b_wptr += VLAN_INCR;
		ASSERT(mp->b_wptr <= DB_LIM(mp));
		if (vlanid == pvid)
			vlanid = VLAN_ID_NONE;
		tci = VLAN_TCI(mp->b_band, ETHER_CFI, vlanid);
		evh->ether_type = evh->ether_tpid;
		evh->ether_tpid = htons(ETHERTYPE_VLAN);
		evh->ether_tci = htons(tci);
	}
	return (mp);
}

/* Record VLAN information and strip header if requested . */
static void
update_header(mblk_t *mp, mac_header_info_t *hdr_info, boolean_t striphdr)
{
	if (hdr_info->mhi_bindsap == ETHERTYPE_VLAN) {
		struct ether_vlan_header *evhp;
		uint16_t ether_type;

		/* LINTED: alignment */
		evhp = (struct ether_vlan_header *)mp->b_rptr;
		hdr_info->mhi_istagged = B_TRUE;
		hdr_info->mhi_tci = ntohs(evhp->ether_tci);
		if (striphdr) {
			/*
			 * For VLAN tagged frames update the ether_type
			 * in hdr_info before stripping the header.
			 */
			ether_type = ntohs(evhp->ether_type);
			hdr_info->mhi_origsap = ether_type;
			hdr_info->mhi_bindsap = (ether_type > ETHERMTU) ?
			    ether_type : DLS_SAP_LLC;
			mp->b_rptr = (uchar_t *)(evhp + 1);
		}
	} else {
		hdr_info->mhi_istagged = B_FALSE;
		hdr_info->mhi_tci = VLAN_ID_NONE;
		if (striphdr)
			mp->b_rptr += sizeof (struct ether_header);
	}
}

/*
 * Return B_TRUE if we're allowed to send on this link with the given VLAN ID.
 */
static boolean_t
bridge_can_send(bridge_link_t *blp, uint16_t vlanid)
{
	ASSERT(vlanid != VLAN_ID_NONE);
	if (blp->bl_flags & BLF_DELETED)
		return (B_FALSE);
	if (blp->bl_trilldata == NULL && blp->bl_state != BLS_FORWARDING)
		return (B_FALSE);
	return (BRIDGE_VLAN_ISSET(blp, vlanid) && BRIDGE_AF_ISSET(blp, vlanid));
}

/*
 * This function scans the bridge forwarding tables in order to forward a given
 * packet.  If the packet either doesn't need forwarding (the current link is
 * correct) or the current link needs a copy as well, then the packet is
 * returned to the caller.
 *
 * If a packet has been decapsulated from TRILL, then it must *NOT* reenter a
 * TRILL tunnel.  If the destination points there, then drop instead.
 */
static mblk_t *
bridge_forward(bridge_link_t *blp, mac_header_info_t *hdr_info, mblk_t *mp,
    uint16_t vlanid, uint16_t tci, boolean_t from_trill, boolean_t is_xmit)
{
	mblk_t *mpsend, *mpcopy;
	bridge_inst_t *bip = blp->bl_inst;
	bridge_link_t *blpsend, *blpnext;
	bridge_fwd_t *bfp;
	uint_t i;
	boolean_t selfseen = B_FALSE;
	void *tdp;
	const uint8_t *daddr = hdr_info->mhi_daddr;

	/*
	 * Check for the IEEE "reserved" multicast addresses.  Messages sent to
	 * these addresses are used for link-local control (STP and pause), and
	 * are never forwarded or redirected.
	 */
	if (daddr[0] == 1 && daddr[1] == 0x80 && daddr[2] == 0xc2 &&
	    daddr[3] == 0 && daddr[4] == 0 && (daddr[5] & 0xf0) == 0) {
		if (from_trill) {
			freemsg(mp);
			mp = NULL;
		}
		return (mp);
	}

	if ((bfp = fwd_find(bip, daddr, vlanid)) != NULL) {

		/*
		 * If trill indicates a destination for this node, then it's
		 * clearly not intended for local delivery.  We must tell TRILL
		 * to encapsulate, as long as we didn't just decapsulate it.
		 */
		if (bfp->bf_trill_nick != RBRIDGE_NICKNAME_NONE) {
			/*
			 * Error case: can't reencapsulate if the protocols are
			 * working correctly.
			 */
			if (from_trill) {
				freemsg(mp);
				return (NULL);
			}
			mutex_enter(&blp->bl_trilllock);
			if ((tdp = blp->bl_trilldata) != NULL) {
				blp->bl_trillthreads++;
				mutex_exit(&blp->bl_trilllock);
				update_header(mp, hdr_info, B_FALSE);
				if (is_xmit)
					mp = mac_fix_cksum(mp);
				/* all trill data frames have Inner.VLAN */
				mp = reform_vlan_header(mp, vlanid, tci, 0);
				if (mp == NULL) {
					KIINCR(bki_drops);
					fwd_unref(bfp);
					return (NULL);
				}
				trill_encap_fn(tdp, blp, hdr_info, mp,
				    bfp->bf_trill_nick);
				mutex_enter(&blp->bl_trilllock);
				if (--blp->bl_trillthreads == 0 &&
				    blp->bl_trilldata == NULL)
					cv_broadcast(&blp->bl_trillwait);
			}
			mutex_exit(&blp->bl_trilllock);

			/* if TRILL has been disabled, then kill this stray */
			if (tdp == NULL) {
				freemsg(mp);
				fwd_delete(bfp);
			}
			fwd_unref(bfp);
			return (NULL);
		}

		/* find first link we can send on */
		for (i = 0; i < bfp->bf_nlinks; i++) {
			blpsend = bfp->bf_links[i];
			if (blpsend == blp)
				selfseen = B_TRUE;
			else if (bridge_can_send(blpsend, vlanid))
				break;
		}

		while (i < bfp->bf_nlinks) {
			blpsend = bfp->bf_links[i];
			for (i++; i < bfp->bf_nlinks; i++) {
				blpnext = bfp->bf_links[i];
				if (blpnext == blp)
					selfseen = B_TRUE;
				else if (bridge_can_send(blpnext, vlanid))
					break;
			}
			if (i == bfp->bf_nlinks && !selfseen) {
				mpsend = mp;
				mp = NULL;
			} else {
				mpsend = copymsg(mp);
			}

			if (!from_trill && is_xmit)
				mpsend = mac_fix_cksum(mpsend);

			mpsend = reform_vlan_header(mpsend, vlanid, tci,
			    blpsend->bl_pvid);
			if (mpsend == NULL) {
				KIINCR(bki_drops);
				continue;
			}

			KIINCR(bki_forwards);
			/*
			 * No need to bump up the link reference count, as
			 * the forwarding entry itself holds a reference to
			 * the link.
			 */
			if (bfp->bf_flags & BFF_LOCALADDR) {
				mac_rx_common(blpsend->bl_mh, NULL, mpsend);
			} else {
				KLPINCR(blpsend, bkl_xmit);
				MAC_RING_TX(blpsend->bl_mh, NULL, mpsend,
				    mpsend);
				freemsg(mpsend);
			}
		}
		/*
		 * Handle a special case: if we're transmitting to the original
		 * link, then check whether the localaddr flag is set.  If it
		 * is, then receive instead.  This doesn't happen with ordinary
		 * bridging, but does happen often with TRILL decapsulation.
		 */
		if (mp != NULL && is_xmit && (bfp->bf_flags & BFF_LOCALADDR)) {
			mac_rx_common(blp->bl_mh, NULL, mp);
			mp = NULL;
		}
		fwd_unref(bfp);
	} else {
		/*
		 * TRILL has two cases to handle.  If the packet is off the
		 * wire (not from TRILL), then we need to send up into the
		 * TRILL module to have the distribution tree computed.  If the
		 * packet is from TRILL (decapsulated), then we're part of the
		 * distribution tree, and we need to copy the packet on member
		 * interfaces.
		 *
		 * Thus, the from TRILL case is identical to the STP case.
		 */
		if (!from_trill && blp->bl_trilldata != NULL) {
			mutex_enter(&blp->bl_trilllock);
			if ((tdp = blp->bl_trilldata) != NULL) {
				blp->bl_trillthreads++;
				mutex_exit(&blp->bl_trilllock);
				if ((mpsend = copymsg(mp)) != NULL) {
					update_header(mpsend,
					    hdr_info, B_FALSE);
					/*
					 * all trill data frames have
					 * Inner.VLAN
					 */
					mpsend = reform_vlan_header(mpsend,
					    vlanid, tci, 0);
					if (mpsend == NULL) {
						KIINCR(bki_drops);
					} else {
						trill_encap_fn(tdp, blp,
						    hdr_info, mpsend,
						    RBRIDGE_NICKNAME_NONE);
					}
				}
				mutex_enter(&blp->bl_trilllock);
				if (--blp->bl_trillthreads == 0 &&
				    blp->bl_trilldata == NULL)
					cv_broadcast(&blp->bl_trillwait);
			}
			mutex_exit(&blp->bl_trilllock);
		}

		/*
		 * This is an unknown destination, so flood.
		 */
		rw_enter(&bip->bi_rwlock, RW_READER);
		for (blpnext = list_head(&bip->bi_links); blpnext != NULL;
		    blpnext = list_next(&bip->bi_links, blpnext)) {
			if (blpnext == blp)
				selfseen = B_TRUE;
			else if (bridge_can_send(blpnext, vlanid))
				break;
		}
		if (blpnext != NULL)
			atomic_inc_uint(&blpnext->bl_refs);
		rw_exit(&bip->bi_rwlock);
		while ((blpsend = blpnext) != NULL) {
			rw_enter(&bip->bi_rwlock, RW_READER);
			for (blpnext = list_next(&bip->bi_links, blpsend);
			    blpnext != NULL;
			    blpnext = list_next(&bip->bi_links, blpnext)) {
				if (blpnext == blp)
					selfseen = B_TRUE;
				else if (bridge_can_send(blpnext, vlanid))
					break;
			}
			if (blpnext != NULL)
				atomic_inc_uint(&blpnext->bl_refs);
			rw_exit(&bip->bi_rwlock);
			if (blpnext == NULL && !selfseen) {
				mpsend = mp;
				mp = NULL;
			} else {
				mpsend = copymsg(mp);
			}

			if (!from_trill && is_xmit)
				mpsend = mac_fix_cksum(mpsend);

			mpsend = reform_vlan_header(mpsend, vlanid, tci,
			    blpsend->bl_pvid);
			if (mpsend == NULL) {
				KIINCR(bki_drops);
				continue;
			}

			if (hdr_info->mhi_dsttype == MAC_ADDRTYPE_UNICAST)
				KIINCR(bki_unknown);
			else
				KIINCR(bki_mbcast);
			KLPINCR(blpsend, bkl_xmit);
			if ((mpcopy = copymsg(mpsend)) != NULL)
				mac_rx_common(blpsend->bl_mh, NULL, mpcopy);
			MAC_RING_TX(blpsend->bl_mh, NULL, mpsend, mpsend);
			freemsg(mpsend);
			link_unref(blpsend);
		}
	}

	/*
	 * At this point, if np is non-NULL, it means that the caller needs to
	 * continue on the selected link.
	 */
	return (mp);
}

/*
 * Extract and validate the VLAN information for a given packet.  This checks
 * conformance with the rules for use of the PVID on the link, and for the
 * allowed (configured) VLAN set.
 *
 * Returns B_TRUE if the packet passes, B_FALSE if it fails.
 */
static boolean_t
bridge_get_vlan(bridge_link_t *blp, mac_header_info_t *hdr_info, mblk_t *mp,
    uint16_t *vlanidp, uint16_t *tcip)
{
	uint16_t tci, vlanid;

	if (hdr_info->mhi_bindsap == ETHERTYPE_VLAN) {
		ptrdiff_t tpos = offsetof(struct ether_vlan_header, ether_tci);
		ptrdiff_t mlen;

		/*
		 * Extract the VLAN ID information, regardless of alignment,
		 * and without a pullup.  This isn't attractive, but we do this
		 * to avoid having to deal with the pointers stashed in
		 * hdr_info moving around or having the caller deal with a new
		 * mblk_t pointer.
		 */
		while (mp != NULL) {
			mlen = MBLKL(mp);
			if (mlen > tpos && mlen > 0)
				break;
			tpos -= mlen;
			mp = mp->b_cont;
		}
		if (mp == NULL)
			return (B_FALSE);
		tci = mp->b_rptr[tpos] << 8;
		if (++tpos >= mlen) {
			do {
				mp = mp->b_cont;
			} while (mp != NULL && MBLKL(mp) == 0);
			if (mp == NULL)
				return (B_FALSE);
			tpos = 0;
		}
		tci |= mp->b_rptr[tpos];

		vlanid = VLAN_ID(tci);
		if (VLAN_CFI(tci) != ETHER_CFI || vlanid > VLAN_ID_MAX)
			return (B_FALSE);
		if (vlanid == VLAN_ID_NONE || vlanid == blp->bl_pvid)
			goto input_no_vlan;
		if (!BRIDGE_VLAN_ISSET(blp, vlanid))
			return (B_FALSE);
	} else {
		tci = 0xFFFF;
input_no_vlan:
		/*
		 * If PVID is set to zero, then untagged traffic is not
		 * supported here.  Do not learn or forward.
		 */
		if ((vlanid = blp->bl_pvid) == VLAN_ID_NONE)
			return (B_FALSE);
	}

	*tcip = tci;
	*vlanidp = vlanid;
	return (B_TRUE);
}

/*
 * Handle MAC notifications.
 */
static void
bridge_notify_cb(void *arg, mac_notify_type_t note_type)
{
	bridge_link_t *blp = arg;

	switch (note_type) {
	case MAC_NOTE_UNICST:
		bridge_new_unicst(blp);
		break;

	case MAC_NOTE_SDU_SIZE: {
		uint_t maxsdu;
		bridge_inst_t *bip = blp->bl_inst;
		bridge_mac_t *bmp = bip->bi_mac;
		boolean_t notify = B_FALSE;
		mblk_t *mlist = NULL;

		mac_sdu_get(blp->bl_mh, NULL, &maxsdu);
		rw_enter(&bip->bi_rwlock, RW_READER);
		if (list_prev(&bip->bi_links, blp) == NULL &&
		    list_next(&bip->bi_links, blp) == NULL) {
			notify = (maxsdu != bmp->bm_maxsdu);
			bmp->bm_maxsdu = maxsdu;
		}
		blp->bl_maxsdu = maxsdu;
		if (maxsdu != bmp->bm_maxsdu)
			link_sdu_fail(blp, B_TRUE, &mlist);
		else if (notify)
			(void) mac_maxsdu_update(bmp->bm_mh, maxsdu);
		rw_exit(&bip->bi_rwlock);
		send_up_messages(bip, mlist);
		break;
	}
	}
}

/*
 * This is called by the MAC layer.  As with the transmit side, we're right in
 * the data path for all I/O on this port, so if we don't need to forward this
 * packet anywhere, we have to send it upwards via mac_rx_common.
 */
static void
bridge_recv_cb(mac_handle_t mh, mac_resource_handle_t rsrc, mblk_t *mpnext)
{
	mblk_t *mp, *mpcopy;
	bridge_link_t *blp = (bridge_link_t *)mh;
	bridge_inst_t *bip = blp->bl_inst;
	bridge_mac_t *bmp = bip->bi_mac;
	mac_header_info_t hdr_info;
	uint16_t vlanid, tci;
	boolean_t trillmode = B_FALSE;

	KIINCR(bki_recv);
	KLINCR(bkl_recv);

	/*
	 * Regardless of state, check for inbound TRILL packets when TRILL is
	 * active.  These are pulled out of band and sent for TRILL handling.
	 */
	if (blp->bl_trilldata != NULL) {
		void *tdp;
		mblk_t *newhead;
		mblk_t *tail = NULL;

		mutex_enter(&blp->bl_trilllock);
		if ((tdp = blp->bl_trilldata) != NULL) {
			blp->bl_trillthreads++;
			mutex_exit(&blp->bl_trilllock);
			trillmode = B_TRUE;
			newhead = mpnext;
			while ((mp = mpnext) != NULL) {
				boolean_t raw_isis, bridge_group;

				mpnext = mp->b_next;

				/*
				 * If the header isn't readable, then leave on
				 * the list and continue.
				 */
				if (mac_header_info(blp->bl_mh, mp,
				    &hdr_info) != 0) {
					tail = mp;
					continue;
				}

				/*
				 * The TRILL document specifies that, on
				 * Ethernet alone, IS-IS packets arrive with
				 * LLC rather than Ethertype, and using a
				 * specific destination address.  We must check
				 * for that here.  Also, we need to give BPDUs
				 * to TRILL for processing.
				 */
				raw_isis = bridge_group = B_FALSE;
				if (hdr_info.mhi_dsttype ==
				    MAC_ADDRTYPE_MULTICAST) {
					if (memcmp(hdr_info.mhi_daddr,
					    all_isis_rbridges, ETHERADDRL) == 0)
						raw_isis = B_TRUE;
					else if (memcmp(hdr_info.mhi_daddr,
					    bridge_group_address, ETHERADDRL) ==
					    0)
						bridge_group = B_TRUE;
				}
				if (!raw_isis && !bridge_group &&
				    hdr_info.mhi_bindsap != ETHERTYPE_TRILL &&
				    (hdr_info.mhi_bindsap != ETHERTYPE_VLAN ||
				    /* LINTED: alignment */
				    ((struct ether_vlan_header *)mp->b_rptr)->
				    ether_type != htons(ETHERTYPE_TRILL))) {
					tail = mp;
					continue;
				}

				/*
				 * We've got TRILL input.  Remove from the list
				 * and send up through the TRILL module.  (Send
				 * a copy through promiscuous receive just to
				 * support snooping on TRILL.  Order isn't
				 * preserved strictly, but that doesn't matter
				 * here.)
				 */
				if (tail != NULL)
					tail->b_next = mpnext;
				mp->b_next = NULL;
				if (mp == newhead)
					newhead = mpnext;
				mac_trill_snoop(blp->bl_mh, mp);
				update_header(mp, &hdr_info, B_TRUE);
				/*
				 * On raw IS-IS and BPDU frames, we have to
				 * make sure that the length is trimmed
				 * properly.  We use origsap in order to cope
				 * with jumbograms for IS-IS.  (Regular mac
				 * can't.)
				 */
				if (raw_isis || bridge_group) {
					size_t msglen = msgdsize(mp);

					if (msglen > hdr_info.mhi_origsap) {
						(void) adjmsg(mp,
						    hdr_info.mhi_origsap -
						    msglen);
					} else if (msglen <
					    hdr_info.mhi_origsap) {
						freemsg(mp);
						continue;
					}
				}
				trill_recv_fn(tdp, blp, rsrc, mp, &hdr_info);
			}
			mpnext = newhead;
			mutex_enter(&blp->bl_trilllock);
			if (--blp->bl_trillthreads == 0 &&
			    blp->bl_trilldata == NULL)
				cv_broadcast(&blp->bl_trillwait);
		}
		mutex_exit(&blp->bl_trilllock);
		if (mpnext == NULL)
			return;
	}

	/*
	 * If this is a TRILL RBridge, then just check whether this link is
	 * used at all for forwarding.  If not, then we're done.
	 */
	if (trillmode) {
		if (!(blp->bl_flags & BLF_TRILLACTIVE) ||
		    (blp->bl_flags & BLF_SDUFAIL)) {
			mac_rx_common(blp->bl_mh, rsrc, mpnext);
			return;
		}
	} else {
		/*
		 * For regular (STP) bridges, if we're in blocking or listening
		 * state, then do nothing.  We don't learn or forward until
		 * told to do so.
		 */
		if (blp->bl_state == BLS_BLOCKLISTEN) {
			mac_rx_common(blp->bl_mh, rsrc, mpnext);
			return;
		}
	}

	/*
	 * Send a copy of the message chain up to the observability node users.
	 * For TRILL, we must obey the VLAN AF rules, so we go packet-by-
	 * packet.
	 */
	if (!trillmode && blp->bl_state == BLS_FORWARDING &&
	    (bmp->bm_flags & BMF_STARTED) &&
	    (mp = copymsgchain(mpnext)) != NULL) {
		mac_rx(bmp->bm_mh, NULL, mp);
	}

	/*
	 * We must be in learning or forwarding state, or using TRILL on a link
	 * with one or more VLANs active.  For each packet in the list, process
	 * the source address, and then attempt to forward.
	 */
	while ((mp = mpnext) != NULL) {
		mpnext = mp->b_next;
		mp->b_next = NULL;

		/*
		 * If we can't decode the header or if the header specifies a
		 * multicast source address (impossible!), then don't bother
		 * learning or forwarding, but go ahead and forward up the
		 * stack for subsequent processing.
		 */
		if (mac_header_info(blp->bl_mh, mp, &hdr_info) != 0 ||
		    (hdr_info.mhi_saddr[0] & 1) != 0) {
			KIINCR(bki_drops);
			KLINCR(bkl_drops);
			mac_rx_common(blp->bl_mh, rsrc, mp);
			continue;
		}

		/*
		 * Extract and validate the VLAN ID for this packet.
		 */
		if (!bridge_get_vlan(blp, &hdr_info, mp, &vlanid, &tci) ||
		    !BRIDGE_AF_ISSET(blp, vlanid)) {
			mac_rx_common(blp->bl_mh, rsrc, mp);
			continue;
		}

		if (trillmode) {
			/*
			 * Special test required by TRILL document: must
			 * discard frames with outer address set to ESADI.
			 */
			if (memcmp(hdr_info.mhi_daddr, all_esadi_rbridges,
			    ETHERADDRL) == 0) {
				mac_rx_common(blp->bl_mh, rsrc, mp);
				continue;
			}

			/*
			 * If we're in TRILL mode, then the call above to get
			 * the VLAN ID has also checked that we're the
			 * appointed forwarder, so report that we're handling
			 * this packet to any observability node users.
			 */
			if ((bmp->bm_flags & BMF_STARTED) &&
			    (mpcopy = copymsg(mp)) != NULL)
				mac_rx(bmp->bm_mh, NULL, mpcopy);
		}

		/*
		 * First process the source address and learn from it.  For
		 * TRILL, we learn only if we're the appointed forwarder.
		 */
		bridge_learn(blp, hdr_info.mhi_saddr, RBRIDGE_NICKNAME_NONE,
		    vlanid);

		/*
		 * Now check whether we're forwarding and look up the
		 * destination.  If we can forward, do so.
		 */
		if (trillmode || blp->bl_state == BLS_FORWARDING) {
			mp = bridge_forward(blp, &hdr_info, mp, vlanid, tci,
			    B_FALSE, B_FALSE);
		}
		if (mp != NULL)
			mac_rx_common(blp->bl_mh, rsrc, mp);
	}
}


/* ARGSUSED */
static mblk_t *
bridge_xmit_cb(mac_handle_t mh, mac_ring_handle_t rh, mblk_t *mpnext)
{
	bridge_link_t *blp = (bridge_link_t *)mh;
	bridge_inst_t *bip = blp->bl_inst;
	bridge_mac_t *bmp = bip->bi_mac;
	mac_header_info_t hdr_info;
	uint16_t vlanid, tci;
	mblk_t *mp, *mpcopy;
	boolean_t trillmode;

	trillmode = blp->bl_trilldata != NULL;

	/*
	 * If we're using STP and we're in blocking or listening state, or if
	 * we're using TRILL and no VLANs are active, then behave as though the
	 * bridge isn't here at all, and send on the local link alone.
	 */
	if ((!trillmode && blp->bl_state == BLS_BLOCKLISTEN) ||
	    (trillmode &&
	    (!(blp->bl_flags & BLF_TRILLACTIVE) ||
	    (blp->bl_flags & BLF_SDUFAIL)))) {
		KIINCR(bki_sent);
		KLINCR(bkl_xmit);
		MAC_RING_TX(blp->bl_mh, rh, mpnext, mp);
		return (mp);
	}

	/*
	 * Send a copy of the message up to the observability node users.
	 * TRILL needs to check on a packet-by-packet basis.
	 */
	if (!trillmode && blp->bl_state == BLS_FORWARDING &&
	    (bmp->bm_flags & BMF_STARTED) &&
	    (mp = copymsgchain(mpnext)) != NULL) {
		mac_rx(bmp->bm_mh, NULL, mp);
	}

	while ((mp = mpnext) != NULL) {
		mpnext = mp->b_next;
		mp->b_next = NULL;

		if (mac_header_info(blp->bl_mh, mp, &hdr_info) != 0) {
			freemsg(mp);
			continue;
		}

		/*
		 * Extract and validate the VLAN ID for this packet.
		 */
		if (!bridge_get_vlan(blp, &hdr_info, mp, &vlanid, &tci) ||
		    !BRIDGE_AF_ISSET(blp, vlanid)) {
			freemsg(mp);
			continue;
		}

		/*
		 * If we're using TRILL, then we've now validated that we're
		 * the forwarder for this VLAN, so go ahead and let
		 * observability node users know about the packet.
		 */
		if (trillmode && (bmp->bm_flags & BMF_STARTED) &&
		    (mpcopy = copymsg(mp)) != NULL) {
			mac_rx(bmp->bm_mh, NULL, mpcopy);
		}

		/*
		 * We have to learn from our own transmitted packets, because
		 * there may be a Solaris DLPI raw sender (which can specify its
		 * own source address) using promiscuous mode for receive.  The
		 * mac layer information won't (and can't) tell us everything
		 * we need to know.
		 */
		bridge_learn(blp, hdr_info.mhi_saddr, RBRIDGE_NICKNAME_NONE,
		    vlanid);

		/* attempt forwarding */
		if (trillmode || blp->bl_state == BLS_FORWARDING) {
			mp = bridge_forward(blp, &hdr_info, mp, vlanid, tci,
			    B_FALSE, B_TRUE);
		}
		if (mp != NULL) {
			MAC_RING_TX(blp->bl_mh, rh, mp, mp);
			if (mp == NULL) {
				KIINCR(bki_sent);
				KLINCR(bkl_xmit);
			}
		}
		/*
		 * If we get stuck, then stop.  Don't let the user's output
		 * packets get out of order.  (More importantly: don't try to
		 * bridge the same packet multiple times if flow control is
		 * asserted.)
		 */
		if (mp != NULL) {
			mp->b_next = mpnext;
			break;
		}
	}
	return (mp);
}

/*
 * This is called by TRILL when it decapsulates an packet, and we must forward
 * locally.  On failure, we just drop.
 *
 * Note that the ingress_nick reported by TRILL must not represent this local
 * node.
 */
void
bridge_trill_decaps(bridge_link_t *blp, mblk_t *mp, uint16_t ingress_nick)
{
	mac_header_info_t hdr_info;
	uint16_t vlanid, tci;
	bridge_inst_t *bip = blp->bl_inst;	/* used by macros */
	mblk_t *mpcopy;

	if (mac_header_info(blp->bl_mh, mp, &hdr_info) != 0) {
		freemsg(mp);
		return;
	}

	/* Extract VLAN ID for this packet. */
	if (hdr_info.mhi_bindsap == ETHERTYPE_VLAN) {
		struct ether_vlan_header *evhp;

		/* LINTED: alignment */
		evhp = (struct ether_vlan_header *)mp->b_rptr;
		tci = ntohs(evhp->ether_tci);
		vlanid = VLAN_ID(tci);
	} else {
		/* Inner VLAN headers are required in TRILL data packets */
		DTRACE_PROBE3(bridge__trill__decaps__novlan, bridge_link_t *,
		    blp, mblk_t *, mp, uint16_t, ingress_nick);
		freemsg(mp);
		return;
	}

	/* Learn the location of this sender in the RBridge network */
	bridge_learn(blp, hdr_info.mhi_saddr, ingress_nick, vlanid);

	/* attempt forwarding */
	mp = bridge_forward(blp, &hdr_info, mp, vlanid, tci, B_TRUE, B_TRUE);
	if (mp != NULL) {
		if (bridge_can_send(blp, vlanid)) {
			/* Deliver a copy locally as well */
			if ((mpcopy = copymsg(mp)) != NULL)
				mac_rx_common(blp->bl_mh, NULL, mpcopy);
			MAC_RING_TX(blp->bl_mh, NULL, mp, mp);
		}
		if (mp == NULL) {
			KIINCR(bki_sent);
			KLINCR(bkl_xmit);
		} else {
			freemsg(mp);
		}
	}
}

/*
 * This function is used by TRILL _only_ to transmit TRILL-encapsulated
 * packets.  It sends on a single underlying link and does not bridge.
 */
mblk_t *
bridge_trill_output(bridge_link_t *blp, mblk_t *mp)
{
	bridge_inst_t *bip = blp->bl_inst;	/* used by macros */

	mac_trill_snoop(blp->bl_mh, mp);
	MAC_RING_TX(blp->bl_mh, NULL, mp, mp);
	if (mp == NULL) {
		KIINCR(bki_sent);
		KLINCR(bkl_xmit);
	}
	return (mp);
}

/*
 * Set the "appointed forwarder" flag array for this link.  TRILL controls
 * forwarding on a VLAN basis.  The "trillactive" flag is an optimization for
 * the forwarder.
 */
void
bridge_trill_setvlans(bridge_link_t *blp, const uint8_t *arr)
{
	int i;
	uint_t newflags = 0;

	for (i = 0; i < BRIDGE_VLAN_ARR_SIZE; i++) {
		if ((blp->bl_afs[i] = arr[i]) != 0)
			newflags = BLF_TRILLACTIVE;
	}
	blp->bl_flags = (blp->bl_flags & ~BLF_TRILLACTIVE) | newflags;
}

void
bridge_trill_flush(bridge_link_t *blp, uint16_t vlan, boolean_t dotrill)
{
	bridge_inst_t *bip = blp->bl_inst;
	bridge_fwd_t *bfp, *bfnext;
	avl_tree_t fwd_scavenge;
	int i;

	_NOTE(ARGUNUSED(vlan));

	avl_create(&fwd_scavenge, fwd_compare, sizeof (bridge_fwd_t),
	    offsetof(bridge_fwd_t, bf_node));
	rw_enter(&bip->bi_rwlock, RW_WRITER);
	bfnext = avl_first(&bip->bi_fwd);
	while ((bfp = bfnext) != NULL) {
		bfnext = AVL_NEXT(&bip->bi_fwd, bfp);
		if (bfp->bf_flags & BFF_LOCALADDR)
			continue;
		if (dotrill) {
			/* port doesn't matter if we're flushing TRILL */
			if (bfp->bf_trill_nick == RBRIDGE_NICKNAME_NONE)
				continue;
		} else {
			if (bfp->bf_trill_nick != RBRIDGE_NICKNAME_NONE)
				continue;
			for (i = 0; i < bfp->bf_nlinks; i++) {
				if (bfp->bf_links[i] == blp)
					break;
			}
			if (i >= bfp->bf_nlinks)
				continue;
		}
		ASSERT(bfp->bf_flags & BFF_INTREE);
		avl_remove(&bip->bi_fwd, bfp);
		bfp->bf_flags &= ~BFF_INTREE;
		avl_add(&fwd_scavenge, bfp);
	}
	rw_exit(&bip->bi_rwlock);
	bfnext = avl_first(&fwd_scavenge);
	while ((bfp = bfnext) != NULL) {
		bfnext = AVL_NEXT(&fwd_scavenge, bfp);
		avl_remove(&fwd_scavenge, bfp);
		fwd_unref(bfp);
	}
	avl_destroy(&fwd_scavenge);
}

/*
 * Let the mac module take or drop a reference to a bridge link.  When this is
 * called, the mac module is holding the mi_bridge_lock, so the link cannot be
 * in the process of entering or leaving a bridge.
 */
static void
bridge_ref_cb(mac_handle_t mh, boolean_t hold)
{
	bridge_link_t *blp = (bridge_link_t *)mh;

	if (hold)
		atomic_inc_uint(&blp->bl_refs);
	else
		link_unref(blp);
}

/*
 * Handle link state changes reported by the mac layer.  This acts as a filter
 * for link state changes: if a link is reporting down, but there are other
 * links still up on the bridge, then the state is changed to "up."  When the
 * last link goes down, all are marked down, and when the first link goes up,
 * all are marked up.  (Recursion is avoided by the use of the "redo" function.)
 *
 * We treat unknown as equivalent to "up."
 */
static link_state_t
bridge_ls_cb(mac_handle_t mh, link_state_t newls)
{
	bridge_link_t *blp = (bridge_link_t *)mh;
	bridge_link_t *blcmp;
	bridge_inst_t *bip;
	bridge_mac_t *bmp;

	if (newls != LINK_STATE_DOWN && blp->bl_linkstate != LINK_STATE_DOWN ||
	    (blp->bl_flags & (BLF_DELETED|BLF_SDUFAIL))) {
		blp->bl_linkstate = newls;
		return (newls);
	}

	/*
	 * Scan first to see if there are any other non-down links.  If there
	 * are, then we're done.  Otherwise, if all others are down, then the
	 * state of this link is the state of the bridge.
	 */
	bip = blp->bl_inst;
	rw_enter(&bip->bi_rwlock, RW_WRITER);
	for (blcmp = list_head(&bip->bi_links); blcmp != NULL;
	    blcmp = list_next(&bip->bi_links, blcmp)) {
		if (blcmp != blp &&
		    !(blcmp->bl_flags & (BLF_DELETED|BLF_SDUFAIL)) &&
		    blcmp->bl_linkstate != LINK_STATE_DOWN)
			break;
	}

	if (blcmp != NULL) {
		/*
		 * If there are other links that are considered up, then tell
		 * the caller that the link is actually still up, regardless of
		 * this link's underlying state.
		 */
		blp->bl_linkstate = newls;
		newls = LINK_STATE_UP;
	} else if (blp->bl_linkstate != newls) {
		/*
		 * If we've found no other 'up' links, and this link has
		 * changed state, then report the new state of the bridge to
		 * all other clients.
		 */
		blp->bl_linkstate = newls;
		for (blcmp = list_head(&bip->bi_links); blcmp != NULL;
		    blcmp = list_next(&bip->bi_links, blcmp)) {
			if (blcmp != blp && !(blcmp->bl_flags & BLF_DELETED))
				mac_link_redo(blcmp->bl_mh, newls);
		}
		bmp = bip->bi_mac;
		if ((bmp->bm_linkstate = newls) != LINK_STATE_DOWN)
			bmp->bm_linkstate = LINK_STATE_UP;
		mac_link_redo(bmp->bm_mh, bmp->bm_linkstate);
	}
	rw_exit(&bip->bi_rwlock);
	return (newls);
}

static void
bridge_add_link(void *arg)
{
	mblk_t *mp = arg;
	bridge_stream_t *bsp;
	bridge_inst_t *bip, *bipt;
	bridge_mac_t *bmp;
	datalink_id_t linkid;
	int err;
	mac_handle_t mh;
	uint_t maxsdu;
	bridge_link_t *blp = NULL, *blpt;
	const mac_info_t *mip;
	boolean_t macopen = B_FALSE;
	char linkname[MAXLINKNAMELEN];
	char kstatname[KSTAT_STRLEN];
	int i;
	link_state_t linkstate;
	mblk_t *mlist;

	bsp = (bridge_stream_t *)mp->b_next;
	mp->b_next = NULL;
	bip = bsp->bs_inst;
	/* LINTED: alignment */
	linkid = *(datalink_id_t *)mp->b_cont->b_rptr;

	/*
	 * First make sure that there is no other bridge that has this link.
	 * We don't want to overlap operations from two bridges; the MAC layer
	 * supports only one bridge on a given MAC at a time.
	 *
	 * We rely on the fact that there's just one taskq thread for the
	 * bridging module: once we've checked for a duplicate, we can drop the
	 * lock, because no other thread could possibly be adding another link
	 * until we're done.
	 */
	mutex_enter(&inst_lock);
	for (bipt = list_head(&inst_list); bipt != NULL;
	    bipt = list_next(&inst_list, bipt)) {
		rw_enter(&bipt->bi_rwlock, RW_READER);
		for (blpt = list_head(&bipt->bi_links); blpt != NULL;
		    blpt = list_next(&bipt->bi_links, blpt)) {
			if (linkid == blpt->bl_linkid)
				break;
		}
		rw_exit(&bipt->bi_rwlock);
		if (blpt != NULL)
			break;
	}
	mutex_exit(&inst_lock);
	if (bipt != NULL) {
		err = EBUSY;
		goto fail;
	}

	if ((err = mac_open_by_linkid(linkid, &mh)) != 0)
		goto fail;
	macopen = B_TRUE;

	/* we bridge only Ethernet */
	mip = mac_info(mh);
	if (mip->mi_media != DL_ETHER) {
		err = ENOTSUP;
		goto fail;
	}

	/*
	 * Get the current maximum SDU on this interface.  If there are other
	 * links on the bridge, then this one must match, or it errors out.
	 * Otherwise, the first link becomes the standard for the new bridge.
	 */
	mac_sdu_get(mh, NULL, &maxsdu);
	bmp = bip->bi_mac;
	if (list_is_empty(&bip->bi_links)) {
		bmp->bm_maxsdu = maxsdu;
		(void) mac_maxsdu_update(bmp->bm_mh, maxsdu);
	}

	/* figure the kstat name; also used as the mac client name */
	i = MBLKL(mp->b_cont) - sizeof (datalink_id_t);
	if (i < 0 || i >= MAXLINKNAMELEN)
		i = MAXLINKNAMELEN - 1;
	bcopy(mp->b_cont->b_rptr + sizeof (datalink_id_t), linkname, i);
	linkname[i] = '\0';
	(void) snprintf(kstatname, sizeof (kstatname), "%s-%s", bip->bi_name,
	    linkname);

	if ((blp = kmem_zalloc(sizeof (*blp), KM_NOSLEEP)) == NULL) {
		err = ENOMEM;
		goto fail;
	}
	blp->bl_lfailmp = allocb(sizeof (bridge_ctl_t), BPRI_MED);
	if (blp->bl_lfailmp == NULL) {
		kmem_free(blp, sizeof (*blp));
		blp = NULL;
		err = ENOMEM;
		goto fail;
	}

	blp->bl_refs = 1;
	atomic_inc_uint(&bip->bi_refs);
	blp->bl_inst = bip;
	blp->bl_mh = mh;
	blp->bl_linkid = linkid;
	blp->bl_maxsdu = maxsdu;
	cv_init(&blp->bl_trillwait, NULL, CV_DRIVER, NULL);
	mutex_init(&blp->bl_trilllock, NULL, MUTEX_DRIVER, NULL);
	(void) memset(blp->bl_afs, 0xff, sizeof (blp->bl_afs));

	err = mac_client_open(mh, &blp->bl_mch, kstatname, 0);
	if (err != 0)
		goto fail;
	blp->bl_flags |= BLF_CLIENT_OPEN;

	err = mac_margin_add(mh, &blp->bl_margin, B_TRUE);
	if (err != 0)
		goto fail;
	blp->bl_flags |= BLF_MARGIN_ADDED;

	blp->bl_mnh = mac_notify_add(mh, bridge_notify_cb, blp);

	/* Enable Bridging on the link */
	err = mac_bridge_set(mh, (mac_handle_t)blp);
	if (err != 0)
		goto fail;
	blp->bl_flags |= BLF_SET_BRIDGE;

	err = mac_promisc_add(blp->bl_mch, MAC_CLIENT_PROMISC_ALL, NULL,
	    blp, &blp->bl_mphp, MAC_PROMISC_FLAGS_NO_TX_LOOP);
	if (err != 0)
		goto fail;
	blp->bl_flags |= BLF_PROM_ADDED;

	bridge_new_unicst(blp);

	blp->bl_ksp = kstat_setup((kstat_named_t *)&blp->bl_kstats,
	    link_kstats_list, Dim(link_kstats_list), kstatname);

	/*
	 * The link holds a reference to the bridge instance, so that the
	 * instance can't go away before the link is freed.  The insertion into
	 * bi_links holds a reference on the link (reference set to 1 above).
	 * When marking as removed from bi_links (BLF_DELETED), drop the
	 * reference on the link. When freeing the link, drop the reference on
	 * the instance. BLF_LINK_ADDED tracks link insertion in bi_links list.
	 */
	rw_enter(&bip->bi_rwlock, RW_WRITER);
	list_insert_tail(&bip->bi_links, blp);
	blp->bl_flags |= BLF_LINK_ADDED;

	/*
	 * If the new link is no good on this bridge, then let the daemon know
	 * about the problem.
	 */
	mlist = NULL;
	if (maxsdu != bmp->bm_maxsdu)
		link_sdu_fail(blp, B_TRUE, &mlist);
	rw_exit(&bip->bi_rwlock);
	send_up_messages(bip, mlist);

	/*
	 * Trigger a link state update so that if this link is the first one
	 * "up" in the bridge, then we notify everyone.  This triggers a trip
	 * through bridge_ls_cb.
	 */
	linkstate = mac_stat_get(mh, MAC_STAT_LOWLINK_STATE);
	blp->bl_linkstate = LINK_STATE_DOWN;
	mac_link_update(mh, linkstate);

	/*
	 * We now need to report back to the stream that invoked us, and then
	 * drop the reference on the stream that we're holding.
	 */
	miocack(bsp->bs_wq, mp, 0, 0);
	stream_unref(bsp);
	return;

fail:
	if (blp == NULL) {
		if (macopen)
			mac_close(mh);
	} else {
		link_shutdown(blp);
	}
	miocnak(bsp->bs_wq, mp, 0, err);
	stream_unref(bsp);
}

static void
bridge_rem_link(void *arg)
{
	mblk_t *mp = arg;
	bridge_stream_t *bsp;
	bridge_inst_t *bip;
	bridge_mac_t *bmp;
	datalink_id_t linkid;
	bridge_link_t *blp, *blsave;
	boolean_t found;
	mblk_t *mlist;

	bsp = (bridge_stream_t *)mp->b_next;
	mp->b_next = NULL;
	bip = bsp->bs_inst;
	/* LINTED: alignment */
	linkid = *(datalink_id_t *)mp->b_cont->b_rptr;

	/*
	 * We become reader here so that we can loop over the other links and
	 * deliver link up/down notification.
	 */
	rw_enter(&bip->bi_rwlock, RW_READER);
	found = B_FALSE;
	for (blp = list_head(&bip->bi_links); blp != NULL;
	    blp = list_next(&bip->bi_links, blp)) {
		if (blp->bl_linkid == linkid &&
		    !(blp->bl_flags & BLF_DELETED)) {
			blp->bl_flags |= BLF_DELETED;
			(void) ddi_taskq_dispatch(bridge_taskq, link_shutdown,
			    blp, DDI_SLEEP);
			found = B_TRUE;
			break;
		}
	}

	/*
	 * Check if this link is up and the remainder of the links are all
	 * down.
	 */
	if (blp != NULL && blp->bl_linkstate != LINK_STATE_DOWN) {
		for (blp = list_head(&bip->bi_links); blp != NULL;
		    blp = list_next(&bip->bi_links, blp)) {
			if (blp->bl_linkstate != LINK_STATE_DOWN &&
			    !(blp->bl_flags & (BLF_DELETED|BLF_SDUFAIL)))
				break;
		}
		if (blp == NULL) {
			for (blp = list_head(&bip->bi_links); blp != NULL;
			    blp = list_next(&bip->bi_links, blp)) {
				if (!(blp->bl_flags & BLF_DELETED))
					mac_link_redo(blp->bl_mh,
					    LINK_STATE_DOWN);
			}
			bmp = bip->bi_mac;
			bmp->bm_linkstate = LINK_STATE_DOWN;
			mac_link_redo(bmp->bm_mh, LINK_STATE_DOWN);
		}
	}

	/*
	 * Check if there's just one working link left on the bridge.  If so,
	 * then that link is now authoritative for bridge MTU.
	 */
	blsave = NULL;
	for (blp = list_head(&bip->bi_links); blp != NULL;
	    blp = list_next(&bip->bi_links, blp)) {
		if (!(blp->bl_flags & BLF_DELETED)) {
			if (blsave == NULL)
				blsave = blp;
			else
				break;
		}
	}
	mlist = NULL;
	bmp = bip->bi_mac;
	if (blsave != NULL && blp == NULL &&
	    blsave->bl_maxsdu != bmp->bm_maxsdu) {
		bmp->bm_maxsdu = blsave->bl_maxsdu;
		(void) mac_maxsdu_update(bmp->bm_mh, blsave->bl_maxsdu);
		link_sdu_fail(blsave, B_FALSE, &mlist);
	}
	rw_exit(&bip->bi_rwlock);
	send_up_messages(bip, mlist);

	if (found)
		miocack(bsp->bs_wq, mp, 0, 0);
	else
		miocnak(bsp->bs_wq, mp, 0, ENOENT);
	stream_unref(bsp);
}

/*
 * This function intentionally returns with bi_rwlock held; it is intended for
 * quick checks and updates.
 */
static bridge_link_t *
enter_link(bridge_inst_t *bip, datalink_id_t linkid)
{
	bridge_link_t *blp;

	rw_enter(&bip->bi_rwlock, RW_READER);
	for (blp = list_head(&bip->bi_links); blp != NULL;
	    blp = list_next(&bip->bi_links, blp)) {
		if (blp->bl_linkid == linkid && !(blp->bl_flags & BLF_DELETED))
			break;
	}
	return (blp);
}

static void
bridge_ioctl(queue_t *wq, mblk_t *mp)
{
	bridge_stream_t *bsp = wq->q_ptr;
	bridge_inst_t *bip;
	struct iocblk *iop;
	int rc = EINVAL;
	int len = 0;
	bridge_link_t *blp;
	cred_t *cr;

	/* LINTED: alignment */
	iop = (struct iocblk *)mp->b_rptr;

	/*
	 * For now, all of the bridge ioctls are privileged.
	 */
	if ((cr = msg_getcred(mp, NULL)) == NULL)
		cr = iop->ioc_cr;
	if (cr != NULL && secpolicy_net_config(cr, B_FALSE) != 0) {
		miocnak(wq, mp, 0, EPERM);
		return;
	}

	switch (iop->ioc_cmd) {
	case BRIOC_NEWBRIDGE: {
		bridge_newbridge_t *bnb;

		if (bsp->bs_inst != NULL ||
		    (rc = miocpullup(mp, sizeof (bridge_newbridge_t))) != 0)
			break;
		/* LINTED: alignment */
		bnb = (bridge_newbridge_t *)mp->b_cont->b_rptr;
		bnb->bnb_name[MAXNAMELEN-1] = '\0';
		rc = bridge_create(bnb->bnb_linkid, bnb->bnb_name, &bip, cr);
		if (rc != 0)
			break;

		rw_enter(&bip->bi_rwlock, RW_WRITER);
		if (bip->bi_control != NULL) {
			rw_exit(&bip->bi_rwlock);
			bridge_unref(bip);
			rc = EBUSY;
		} else {
			atomic_inc_uint(&bip->bi_refs);
			bsp->bs_inst = bip;	/* stream holds reference */
			bip->bi_control = bsp;
			rw_exit(&bip->bi_rwlock);
			rc = 0;
		}
		break;
	}

	case BRIOC_ADDLINK:
		if ((bip = bsp->bs_inst) == NULL ||
		    (rc = miocpullup(mp, sizeof (datalink_id_t))) != 0)
			break;
		/*
		 * We cannot perform the action in this thread, because we're
		 * not in process context, and we may already be holding
		 * MAC-related locks.  Place the request on taskq.
		 */
		mp->b_next = (mblk_t *)bsp;
		stream_ref(bsp);
		(void) ddi_taskq_dispatch(bridge_taskq, bridge_add_link, mp,
		    DDI_SLEEP);
		return;

	case BRIOC_REMLINK:
		if ((bip = bsp->bs_inst) == NULL ||
		    (rc = miocpullup(mp, sizeof (datalink_id_t))) != 0)
			break;
		/*
		 * We cannot perform the action in this thread, because we're
		 * not in process context, and we may already be holding
		 * MAC-related locks.  Place the request on taskq.
		 */
		mp->b_next = (mblk_t *)bsp;
		stream_ref(bsp);
		(void) ddi_taskq_dispatch(bridge_taskq, bridge_rem_link, mp,
		    DDI_SLEEP);
		return;

	case BRIOC_SETSTATE: {
		bridge_setstate_t *bss;

		if ((bip = bsp->bs_inst) == NULL ||
		    (rc = miocpullup(mp, sizeof (*bss))) != 0)
			break;
		/* LINTED: alignment */
		bss = (bridge_setstate_t *)mp->b_cont->b_rptr;
		if ((blp = enter_link(bip, bss->bss_linkid)) == NULL) {
			rc = ENOENT;
		} else {
			rc = 0;
			blp->bl_state = bss->bss_state;
		}
		rw_exit(&bip->bi_rwlock);
		break;
	}

	case BRIOC_SETPVID: {
		bridge_setpvid_t *bsv;

		if ((bip = bsp->bs_inst) == NULL ||
		    (rc = miocpullup(mp, sizeof (*bsv))) != 0)
			break;
		/* LINTED: alignment */
		bsv = (bridge_setpvid_t *)mp->b_cont->b_rptr;
		if (bsv->bsv_vlan > VLAN_ID_MAX)
			break;
		if ((blp = enter_link(bip, bsv->bsv_linkid)) == NULL) {
			rc = ENOENT;
		} else if (blp->bl_pvid == bsv->bsv_vlan) {
			rc = 0;
		} else {
			rc = 0;
			BRIDGE_VLAN_CLR(blp, blp->bl_pvid);
			blp->bl_pvid = bsv->bsv_vlan;
			if (blp->bl_pvid != 0)
				BRIDGE_VLAN_SET(blp, blp->bl_pvid);
		}
		rw_exit(&bip->bi_rwlock);
		break;
	}

	case BRIOC_VLANENAB: {
		bridge_vlanenab_t *bve;

		if ((bip = bsp->bs_inst) == NULL ||
		    (rc = miocpullup(mp, sizeof (*bve))) != 0)
			break;
		/* LINTED: alignment */
		bve = (bridge_vlanenab_t *)mp->b_cont->b_rptr;
		if (bve->bve_vlan > VLAN_ID_MAX)
			break;
		if ((blp = enter_link(bip, bve->bve_linkid)) == NULL) {
			rc = ENOENT;
		} else {
			rc = 0;
			/* special case: vlan 0 means "all" */
			if (bve->bve_vlan == 0) {
				(void) memset(blp->bl_vlans,
				    bve->bve_onoff ? ~0 : 0,
				    sizeof (blp->bl_vlans));
				BRIDGE_VLAN_CLR(blp, 0);
				if (blp->bl_pvid != 0)
					BRIDGE_VLAN_SET(blp, blp->bl_pvid);
			} else if (bve->bve_vlan == blp->bl_pvid) {
				rc = EINVAL;
			} else if (bve->bve_onoff) {
				BRIDGE_VLAN_SET(blp, bve->bve_vlan);
			} else {
				BRIDGE_VLAN_CLR(blp, bve->bve_vlan);
			}
		}
		rw_exit(&bip->bi_rwlock);
		break;
	}

	case BRIOC_FLUSHFWD: {
		bridge_flushfwd_t *bff;
		bridge_fwd_t *bfp, *bfnext;
		avl_tree_t fwd_scavenge;
		int i;

		if ((bip = bsp->bs_inst) == NULL ||
		    (rc = miocpullup(mp, sizeof (*bff))) != 0)
			break;
		/* LINTED: alignment */
		bff = (bridge_flushfwd_t *)mp->b_cont->b_rptr;
		rw_enter(&bip->bi_rwlock, RW_WRITER);
		/* This case means "all" */
		if (bff->bff_linkid == DATALINK_INVALID_LINKID) {
			blp = NULL;
		} else {
			for (blp = list_head(&bip->bi_links); blp != NULL;
			    blp = list_next(&bip->bi_links, blp)) {
				if (blp->bl_linkid == bff->bff_linkid &&
				    !(blp->bl_flags & BLF_DELETED))
					break;
			}
			if (blp == NULL) {
				rc = ENOENT;
				rw_exit(&bip->bi_rwlock);
				break;
			}
		}
		avl_create(&fwd_scavenge, fwd_compare, sizeof (bridge_fwd_t),
		    offsetof(bridge_fwd_t, bf_node));
		bfnext = avl_first(&bip->bi_fwd);
		while ((bfp = bfnext) != NULL) {
			bfnext = AVL_NEXT(&bip->bi_fwd, bfp);
			if (bfp->bf_flags & BFF_LOCALADDR)
				continue;
			if (blp != NULL) {
				for (i = 0; i < bfp->bf_maxlinks; i++) {
					if (bfp->bf_links[i] == blp)
						break;
				}
				/*
				 * If the link is there and we're excluding,
				 * then skip.  If the link is not there and
				 * we're doing only that link, then skip.
				 */
				if ((i < bfp->bf_maxlinks) == bff->bff_exclude)
					continue;
			}
			ASSERT(bfp->bf_flags & BFF_INTREE);
			avl_remove(&bip->bi_fwd, bfp);
			bfp->bf_flags &= ~BFF_INTREE;
			avl_add(&fwd_scavenge, bfp);
		}
		rw_exit(&bip->bi_rwlock);
		bfnext = avl_first(&fwd_scavenge);
		while ((bfp = bfnext) != NULL) {
			bfnext = AVL_NEXT(&fwd_scavenge, bfp);
			avl_remove(&fwd_scavenge, bfp);
			fwd_unref(bfp);	/* drop tree reference */
		}
		avl_destroy(&fwd_scavenge);
		break;
	}

	case BRIOC_TABLEMAX:
		if ((bip = bsp->bs_inst) == NULL ||
		    (rc = miocpullup(mp, sizeof (uint32_t))) != 0)
			break;
		/* LINTED: alignment */
		bip->bi_tablemax = *(uint32_t *)mp->b_cont->b_rptr;
		break;
	}

	if (rc == 0)
		miocack(wq, mp, len, 0);
	else
		miocnak(wq, mp, 0, rc);
}

static void
bridge_wput(queue_t *wq, mblk_t *mp)
{
	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		bridge_ioctl(wq, mp);
		break;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			*mp->b_rptr &= ~FLUSHW;
		if (*mp->b_rptr & FLUSHR)
			qreply(wq, mp);
		else
			freemsg(mp);
		break;
	default:
		freemsg(mp);
		break;
	}
}

/*
 * This function allocates the main data structures for the bridge driver and
 * connects us into devfs.
 */
static void
bridge_inst_init(void)
{
	bridge_scan_interval = 5 * drv_usectohz(1000000);
	bridge_fwd_age = 25 * drv_usectohz(1000000);

	rw_init(&bmac_rwlock, NULL, RW_DRIVER, NULL);
	list_create(&bmac_list, sizeof (bridge_mac_t),
	    offsetof(bridge_mac_t, bm_node));
	list_create(&inst_list, sizeof (bridge_inst_t),
	    offsetof(bridge_inst_t, bi_node));
	cv_init(&inst_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&inst_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&stream_ref_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&stream_ref_lock, NULL, MUTEX_DRIVER, NULL);

	mac_bridge_vectors(bridge_xmit_cb, bridge_recv_cb, bridge_ref_cb,
	    bridge_ls_cb);
}

/*
 * This function disconnects from devfs and destroys all data structures in
 * preparation for unload.  It's assumed that there are no active bridge
 * references left at this point.
 */
static void
bridge_inst_fini(void)
{
	mac_bridge_vectors(NULL, NULL, NULL, NULL);
	if (bridge_timerid != 0)
		(void) untimeout(bridge_timerid);
	rw_destroy(&bmac_rwlock);
	list_destroy(&bmac_list);
	list_destroy(&inst_list);
	cv_destroy(&inst_cv);
	mutex_destroy(&inst_lock);
	cv_destroy(&stream_ref_cv);
	mutex_destroy(&stream_ref_lock);
}

/*
 * bridge_attach()
 *
 * Description:
 *    Attach bridge driver to the system.
 */
static int
bridge_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, BRIDGE_CTL, S_IFCHR, 0, DDI_PSEUDO,
	    CLONE_DEV) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	if (dld_ioc_register(BRIDGE_IOC, bridge_ioc_list,
	    DLDIOCCNT(bridge_ioc_list)) != 0) {
		ddi_remove_minor_node(dip, BRIDGE_CTL);
		return (DDI_FAILURE);
	}

	bridge_dev_info = dip;
	bridge_major = ddi_driver_major(dip);
	bridge_taskq = ddi_taskq_create(dip, BRIDGE_DEV_NAME, 1,
	    TASKQ_DEFAULTPRI, 0);
	return (DDI_SUCCESS);
}

/*
 * bridge_detach()
 *
 * Description:
 *    Detach an interface to the system.
 */
static int
bridge_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);
	ddi_taskq_destroy(bridge_taskq);
	bridge_dev_info = NULL;
	return (DDI_SUCCESS);
}

/*
 * bridge_info()
 *
 * Description:
 *    Translate "dev_t" to a pointer to the associated "dev_info_t".
 */
/* ARGSUSED */
static int
bridge_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
	void **result)
{
	int	rc;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (bridge_dev_info == NULL) {
			rc = DDI_FAILURE;
		} else {
			*result = (void *)bridge_dev_info;
			rc = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		rc = DDI_SUCCESS;
		break;
	default:
		rc = DDI_FAILURE;
		break;
	}
	return (rc);
}

static struct module_info bridge_modinfo = {
	2105,			/* mi_idnum */
	BRIDGE_DEV_NAME,	/* mi_idname */
	0,			/* mi_minpsz */
	16384,			/* mi_maxpsz */
	65536,			/* mi_hiwat */
	128			/* mi_lowat */
};

static struct qinit bridge_rinit = {
	NULL,			/* qi_putp */
	NULL,			/* qi_srvp */
	bridge_open,		/* qi_qopen */
	bridge_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&bridge_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit bridge_winit = {
	(int (*)())bridge_wput, /* qi_putp */
	NULL,			/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&bridge_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab bridge_tab = {
	&bridge_rinit,	/* st_rdinit */
	&bridge_winit	/* st_wrinit */
};

/* No STREAMS perimeters; we do all our own locking */
DDI_DEFINE_STREAM_OPS(bridge_ops, nulldev, nulldev, bridge_attach,
    bridge_detach, nodev, bridge_info, D_NEW | D_MP, &bridge_tab,
    ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops,
	"bridging driver",
	&bridge_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int retv;

	mac_init_ops(NULL, BRIDGE_DEV_NAME);
	bridge_inst_init();
	if ((retv = mod_install(&modlinkage)) != 0)
		bridge_inst_fini();
	return (retv);
}

int
_fini(void)
{
	int retv;

	rw_enter(&bmac_rwlock, RW_READER);
	retv = list_is_empty(&bmac_list) ? 0 : EBUSY;
	rw_exit(&bmac_rwlock);
	if (retv == 0 &&
	    (retv = mod_remove(&modlinkage)) == 0)
		bridge_inst_fini();
	return (retv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
