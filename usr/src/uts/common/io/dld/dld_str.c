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

/*
 * Data-Link Driver
 */

#include	<inet/common.h>
#include	<sys/strsubr.h>
#include	<sys/stropts.h>
#include	<sys/strsun.h>
#include	<sys/vlan.h>
#include	<sys/dld_impl.h>
#include	<sys/cpuvar.h>
#include	<sys/callb.h>
#include	<sys/list.h>
#include	<sys/mac_client.h>
#include	<sys/mac_client_priv.h>
#include	<sys/mac_flow.h>

static int	str_constructor(void *, void *, int);
static void	str_destructor(void *, void *);
static mblk_t	*str_unitdata_ind(dld_str_t *, mblk_t *, boolean_t);
static void	str_notify_promisc_on_phys(dld_str_t *);
static void	str_notify_promisc_off_phys(dld_str_t *);
static void	str_notify_phys_addr(dld_str_t *, uint_t, const uint8_t *);
static void	str_notify_link_up(dld_str_t *);
static void	str_notify_link_down(dld_str_t *);
static void	str_notify_capab_reneg(dld_str_t *);
static void	str_notify_speed(dld_str_t *, uint32_t);

static void	ioc_native(dld_str_t *,  mblk_t *);
static void	ioc_margin(dld_str_t *, mblk_t *);
static void	ioc_raw(dld_str_t *, mblk_t *);
static void	ioc_fast(dld_str_t *,  mblk_t *);
static void	ioc_lowlink(dld_str_t *,  mblk_t *);
static void	ioc(dld_str_t *, mblk_t *);
static void	dld_ioc(dld_str_t *, mblk_t *);
static void	dld_wput_nondata(dld_str_t *, mblk_t *);

static void	str_mdata_raw_put(dld_str_t *, mblk_t *);
static mblk_t	*i_dld_ether_header_update_tag(mblk_t *, uint_t, uint16_t,
    link_tagmode_t);
static mblk_t	*i_dld_ether_header_strip_tag(mblk_t *, boolean_t);

static uint32_t		str_count;
static kmem_cache_t	*str_cachep;
static mod_hash_t	*str_hashp;

#define	STR_HASHSZ		64
#define	STR_HASH_KEY(key)	((mod_hash_key_t)(uintptr_t)(key))

#define	dld_taskq	system_taskq

static kmutex_t		dld_taskq_lock;
static kcondvar_t	dld_taskq_cv;
static list_t		dld_taskq_list;		/* List of dld_str_t */
boolean_t		dld_taskq_quit;
boolean_t		dld_taskq_done;

static void		dld_taskq_dispatch(void);

/*
 * Some notes on entry points, flow-control, queueing.
 *
 * This driver exports the traditional STREAMS put entry point as well as
 * the non-STREAMS fast-path transmit routine which is provided to IP via
 * the DL_CAPAB_POLL negotiation.  The put procedure handles all control
 * and data operations, while the fast-path routine deals only with M_DATA
 * fast-path packets.  Regardless of the entry point, all outbound packets
 * will end up in DLD_TX(), where they will be delivered to the MAC layer.
 *
 * The transmit logic operates in the following way: All packets coming
 * into DLD will be sent to the MAC layer through DLD_TX(). Flow-control
 * happens when the MAC layer indicates the packets couldn't be
 * transmitted due to 1) lack of resources (e.g. running out of
 * descriptors),  or 2) reaching the allowed bandwidth limit for this
 * particular flow. The indication comes in the form of a Tx cookie that
 * identifies the blocked ring. In such case, DLD will place a
 * dummy message on its write-side STREAMS queue so that the queue is
 * marked as "full". Any subsequent packets arriving at the driver will
 * still be sent to the MAC layer where it either gets queued in the Tx
 * SRS or discarded it if queue limit is exceeded. The write-side STREAMS
 * queue gets enabled when MAC layer notifies DLD through MAC_NOTE_TX.
 * When the write service procedure runs, it will remove the dummy
 * message from the write-side STREAMS queue; in effect this will trigger
 * backenabling. The sizes of q_hiwat and q_lowat are set to 1 and 0,
 * respectively, due to the above reasons.
 *
 * All non-data operations, both DLPI and ioctls are single threaded on a per
 * dld_str_t endpoint. This is done using a taskq so that the control operation
 * has kernel context and can cv_wait for resources. In addition all set type
 * operations that involve mac level state modification are serialized on a
 * per mac end point using the perimeter mechanism provided by the mac layer.
 * This serializes all mac clients trying to modify a single mac end point over
 * the entire sequence of mac calls made by that client as an atomic unit. The
 * mac framework locking is described in mac.c. A critical element is that
 * DLD/DLS does not hold any locks across the mac perimeter.
 *
 * dld_finddevinfo() returns the dev_info_t * corresponding to a particular
 * dev_t. It searches str_hashp (a table of dld_str_t's) for streams that
 * match dev_t. If a stream is found and it is attached, its dev_info_t *
 * is returned. If the mac handle is non-null, it can be safely accessed
 * below. The mac handle won't be freed until the mac_unregister which
 * won't happen until the driver detaches. The DDI framework ensures that
 * the detach won't happen while a getinfo is in progress.
 */
typedef struct i_dld_str_state_s {
	major_t		ds_major;
	minor_t		ds_minor;
	int		ds_instance;
	dev_info_t	*ds_dip;
} i_dld_str_state_t;

/* ARGSUSED */
static uint_t
i_dld_str_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	i_dld_str_state_t	*statep = arg;
	dld_str_t		*dsp = (dld_str_t *)val;
	mac_handle_t		mh;

	if (statep->ds_major != dsp->ds_major)
		return (MH_WALK_CONTINUE);

	ASSERT(statep->ds_minor != 0);
	mh = dsp->ds_mh;

	if (statep->ds_minor == dsp->ds_minor) {
		/*
		 * Clone: a clone minor is unique. we can terminate the
		 * walk if we find a matching stream -- even if we fail
		 * to obtain the devinfo.
		 */
		if (mh != NULL) {
			statep->ds_dip = mac_devinfo_get(mh);
			statep->ds_instance = DLS_MINOR2INST(mac_minor(mh));
		}
		return (MH_WALK_TERMINATE);
	}
	return (MH_WALK_CONTINUE);
}

static dev_info_t *
dld_finddevinfo(dev_t dev)
{
	dev_info_t		*dip;
	i_dld_str_state_t	state;

	if (getminor(dev) == 0)
		return (NULL);

	/*
	 * See if it's a minor node of a link
	 */
	if ((dip = dls_link_devinfo(dev)) != NULL)
		return (dip);

	state.ds_minor = getminor(dev);
	state.ds_major = getmajor(dev);
	state.ds_dip = NULL;
	state.ds_instance = -1;

	mod_hash_walk(str_hashp, i_dld_str_walker, &state);
	return (state.ds_dip);
}

int
dld_devt_to_instance(dev_t dev)
{
	minor_t			minor;
	i_dld_str_state_t	state;

	/*
	 * GLDv3 numbers DLPI style 1 node as the instance number + 1.
	 * Minor number 0 is reserved for the DLPI style 2 unattached
	 * node.
	 */

	if ((minor = getminor(dev)) == 0)
		return (-1);

	/*
	 * Check for unopened style 1 node.
	 * Note that this doesn't *necessarily* work for legacy
	 * devices, but this code is only called within the
	 * getinfo(9e) implementation for true GLDv3 devices, so it
	 * doesn't matter.
	 */
	if (minor > 0 && minor <= DLS_MAX_MINOR) {
		return (DLS_MINOR2INST(minor));
	}

	state.ds_minor = getminor(dev);
	state.ds_major = getmajor(dev);
	state.ds_dip = NULL;
	state.ds_instance = -1;

	mod_hash_walk(str_hashp, i_dld_str_walker, &state);
	return (state.ds_instance);
}

/*
 * devo_getinfo: getinfo(9e)
 *
 * NB: This may be called for a provider before the provider's
 * instances are attached.  Hence, if a particular provider needs a
 * special mapping (the mac instance != ddi_get_instance()), then it
 * may need to provide its own implmentation using the
 * mac_devt_to_instance() function, and translating the returned mac
 * instance to a devinfo instance.  For dev_t's where the minor number
 * is too large (i.e. > MAC_MAX_MINOR), the provider can call this
 * function indirectly via the mac_getinfo() function.
 */
/*ARGSUSED*/
int
dld_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	dev_info_t	*devinfo;
	minor_t		minor = getminor((dev_t)arg);
	int		rc = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((devinfo = dld_finddevinfo((dev_t)arg)) != NULL) {
			*(dev_info_t **)resp = devinfo;
			rc = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		if (minor > 0 && minor <= DLS_MAX_MINOR) {
			*resp = (void *)(uintptr_t)DLS_MINOR2INST(minor);
			rc = DDI_SUCCESS;
		} else if (minor > DLS_MAX_MINOR &&
		    (devinfo = dld_finddevinfo((dev_t)arg)) != NULL) {
			*resp = (void *)(uintptr_t)ddi_get_instance(devinfo);
			rc = DDI_SUCCESS;
		}
		break;
	}
	return (rc);
}

void *
dld_str_private(queue_t *q)
{
	return (((dld_str_t *)(q->q_ptr))->ds_private);
}

int
dld_str_open(queue_t *rq, dev_t *devp, void *private)
{
	dld_str_t	*dsp;
	major_t		major;
	minor_t		minor;
	int		err;

	major = getmajor(*devp);
	minor = getminor(*devp);

	/*
	 * Create a new dld_str_t for the stream. This will grab a new minor
	 * number that will be handed back in the cloned dev_t.  Creation may
	 * fail if we can't allocate the dummy mblk used for flow-control.
	 */
	dsp = dld_str_create(rq, DLD_DLPI, major,
	    ((minor == 0) ? DL_STYLE2 : DL_STYLE1));
	if (dsp == NULL)
		return (ENOSR);

	ASSERT(dsp->ds_dlstate == DL_UNATTACHED);
	dsp->ds_private = private;
	if (minor != 0) {
		/*
		 * Style 1 open
		 */
		if ((err = dld_str_attach(dsp, (t_uscalar_t)minor - 1)) != 0)
			goto failed;

		ASSERT(dsp->ds_dlstate == DL_UNBOUND);
	} else {
		(void) qassociate(rq, -1);
	}

	/*
	 * Enable the queue srv(9e) routine.
	 */
	qprocson(rq);

	/*
	 * Construct a cloned dev_t to hand back.
	 */
	*devp = makedevice(getmajor(*devp), dsp->ds_minor);
	return (0);

failed:
	dld_str_destroy(dsp);
	return (err);
}

int
dld_str_close(queue_t *rq)
{
	dld_str_t	*dsp = rq->q_ptr;

	/*
	 * All modules on top have been popped off. So there can't be any
	 * threads from the top.
	 */
	ASSERT(dsp->ds_datathr_cnt == 0);

	/*
	 * Wait until pending DLPI requests are processed.
	 */
	mutex_enter(&dsp->ds_lock);
	while (dsp->ds_dlpi_pending)
		cv_wait(&dsp->ds_dlpi_pending_cv, &dsp->ds_lock);
	mutex_exit(&dsp->ds_lock);


	/*
	 * This stream was open to a provider node. Check to see
	 * if it has been cleanly shut down.
	 */
	if (dsp->ds_dlstate != DL_UNATTACHED) {
		/*
		 * The stream is either open to a style 1 provider or
		 * this is not clean shutdown. Detach from the PPA.
		 * (This is still ok even in the style 1 case).
		 */
		dld_str_detach(dsp);
	}

	dld_str_destroy(dsp);
	return (0);
}

/*
 * qi_qopen: open(9e)
 */
/*ARGSUSED*/
int
dld_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	if (sflag == MODOPEN)
		return (ENOTSUP);

	/*
	 * This is a cloning driver and therefore each queue should only
	 * ever get opened once.
	 */
	if (rq->q_ptr != NULL)
		return (EBUSY);

	return (dld_str_open(rq, devp, NULL));
}

/*
 * qi_qclose: close(9e)
 */
int
dld_close(queue_t *rq)
{
	/*
	 * Disable the queue srv(9e) routine.
	 */
	qprocsoff(rq);

	return (dld_str_close(rq));
}

/*
 * qi_qputp: put(9e)
 */
void
dld_wput(queue_t *wq, mblk_t *mp)
{
	dld_str_t *dsp = (dld_str_t *)wq->q_ptr;
	dld_str_mode_t	mode;

	switch (DB_TYPE(mp)) {
	case M_DATA:
		mutex_enter(&dsp->ds_lock);
		mode = dsp->ds_mode;
		if ((dsp->ds_dlstate != DL_IDLE) ||
		    (mode != DLD_FASTPATH && mode != DLD_RAW)) {
			mutex_exit(&dsp->ds_lock);
			freemsg(mp);
			break;
		}

		DLD_DATATHR_INC(dsp);
		mutex_exit(&dsp->ds_lock);
		if (mode == DLD_FASTPATH) {
			if (dsp->ds_mip->mi_media == DL_ETHER &&
			    (MBLKL(mp) < sizeof (struct ether_header))) {
				freemsg(mp);
			} else {
				(void) str_mdata_fastpath_put(dsp, mp, 0, 0);
			}
		} else {
			str_mdata_raw_put(dsp, mp);
		}
		DLD_DATATHR_DCR(dsp);
		break;
	case M_PROTO:
	case M_PCPROTO: {
		t_uscalar_t	prim;

		if (MBLKL(mp) < sizeof (t_uscalar_t))
			break;

		prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;

		if (prim == DL_UNITDATA_REQ) {
			proto_unitdata_req(dsp, mp);
		} else {
			dld_wput_nondata(dsp, mp);
		}
		break;
	}

	case M_IOCTL:
		dld_wput_nondata(dsp, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			DLD_CLRQFULL(dsp);
			*mp->b_rptr &= ~FLUSHW;
		}

		if (*mp->b_rptr & FLUSHR) {
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		break;

	default:
		freemsg(mp);
		break;
	}
}

/*
 * qi_srvp: srv(9e)
 */
void
dld_wsrv(queue_t *wq)
{
	dld_str_t	*dsp = wq->q_ptr;

	DLD_CLRQFULL(dsp);
}

void
dld_init_ops(struct dev_ops *ops, const char *name)
{
	struct streamtab *stream;
	struct qinit *rq, *wq;
	struct module_info *modinfo;

	modinfo = kmem_zalloc(sizeof (struct module_info), KM_SLEEP);
	modinfo->mi_idname = kmem_zalloc(FMNAMESZ, KM_SLEEP);
	(void) snprintf(modinfo->mi_idname, FMNAMESZ, "%s", name);
	modinfo->mi_minpsz = 0;
	modinfo->mi_maxpsz = 64*1024;
	modinfo->mi_hiwat  = 1;
	modinfo->mi_lowat = 0;

	rq = kmem_zalloc(sizeof (struct qinit), KM_SLEEP);
	rq->qi_qopen = dld_open;
	rq->qi_qclose = dld_close;
	rq->qi_minfo = modinfo;

	wq = kmem_zalloc(sizeof (struct qinit), KM_SLEEP);
	wq->qi_putp = (pfi_t)dld_wput;
	wq->qi_srvp = (pfi_t)dld_wsrv;
	wq->qi_minfo = modinfo;

	stream = kmem_zalloc(sizeof (struct streamtab), KM_SLEEP);
	stream->st_rdinit = rq;
	stream->st_wrinit = wq;
	ops->devo_cb_ops->cb_str = stream;

	if (ops->devo_getinfo == NULL)
		ops->devo_getinfo = &dld_getinfo;
}

void
dld_fini_ops(struct dev_ops *ops)
{
	struct streamtab *stream;
	struct qinit *rq, *wq;
	struct module_info *modinfo;

	stream = ops->devo_cb_ops->cb_str;
	rq = stream->st_rdinit;
	wq = stream->st_wrinit;
	modinfo = rq->qi_minfo;
	ASSERT(wq->qi_minfo == modinfo);

	kmem_free(stream, sizeof (struct streamtab));
	kmem_free(wq, sizeof (struct qinit));
	kmem_free(rq, sizeof (struct qinit));
	kmem_free(modinfo->mi_idname, FMNAMESZ);
	kmem_free(modinfo, sizeof (struct module_info));
}

/*
 * Initialize this module's data structures.
 */
void
dld_str_init(void)
{
	/*
	 * Create dld_str_t object cache.
	 */
	str_cachep = kmem_cache_create("dld_str_cache", sizeof (dld_str_t),
	    0, str_constructor, str_destructor, NULL, NULL, NULL, 0);
	ASSERT(str_cachep != NULL);

	/*
	 * Create a hash table for maintaining dld_str_t's.
	 * The ds_minor field (the clone minor number) of a dld_str_t
	 * is used as a key for this hash table because this number is
	 * globally unique (allocated from "dls_minor_arena").
	 */
	str_hashp = mod_hash_create_idhash("dld_str_hash", STR_HASHSZ,
	    mod_hash_null_valdtor);

	mutex_init(&dld_taskq_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dld_taskq_cv, NULL, CV_DRIVER, NULL);

	dld_taskq_quit = B_FALSE;
	dld_taskq_done = B_FALSE;
	list_create(&dld_taskq_list, sizeof (dld_str_t),
	    offsetof(dld_str_t, ds_tqlist));
	(void) thread_create(NULL, 0, dld_taskq_dispatch, NULL, 0,
	    &p0, TS_RUN, minclsyspri);
}

/*
 * Tear down this module's data structures.
 */
int
dld_str_fini(void)
{
	/*
	 * Make sure that there are no objects in use.
	 */
	if (str_count != 0)
		return (EBUSY);

	/*
	 * Ask the dld_taskq thread to quit and wait for it to be done
	 */
	mutex_enter(&dld_taskq_lock);
	dld_taskq_quit = B_TRUE;
	cv_signal(&dld_taskq_cv);
	while (!dld_taskq_done)
		cv_wait(&dld_taskq_cv, &dld_taskq_lock);
	mutex_exit(&dld_taskq_lock);
	list_destroy(&dld_taskq_list);
	/*
	 * Destroy object cache.
	 */
	kmem_cache_destroy(str_cachep);
	mod_hash_destroy_idhash(str_hashp);
	return (0);
}

/*
 * Create a new dld_str_t object.
 */
dld_str_t *
dld_str_create(queue_t *rq, uint_t type, major_t major, t_uscalar_t style)
{
	dld_str_t	*dsp;
	int		err;

	/*
	 * Allocate an object from the cache.
	 */
	atomic_inc_32(&str_count);
	dsp = kmem_cache_alloc(str_cachep, KM_SLEEP);

	/*
	 * Allocate the dummy mblk for flow-control.
	 */
	dsp->ds_tx_flow_mp = allocb(1, BPRI_HI);
	if (dsp->ds_tx_flow_mp == NULL) {
		kmem_cache_free(str_cachep, dsp);
		atomic_dec_32(&str_count);
		return (NULL);
	}
	dsp->ds_type = type;
	dsp->ds_major = major;
	dsp->ds_style = style;

	/*
	 * Initialize the queue pointers.
	 */
	ASSERT(RD(rq) == rq);
	dsp->ds_rq = rq;
	dsp->ds_wq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (void *)dsp;

	/*
	 * We want explicit control over our write-side STREAMS queue
	 * where the dummy mblk gets added/removed for flow-control.
	 */
	noenable(WR(rq));

	err = mod_hash_insert(str_hashp, STR_HASH_KEY(dsp->ds_minor),
	    (mod_hash_val_t)dsp);
	ASSERT(err == 0);
	return (dsp);
}

/*
 * Destroy a dld_str_t object.
 */
void
dld_str_destroy(dld_str_t *dsp)
{
	queue_t		*rq;
	queue_t		*wq;
	mod_hash_val_t	val;

	/*
	 * Clear the queue pointers.
	 */
	rq = dsp->ds_rq;
	wq = dsp->ds_wq;
	ASSERT(wq == WR(rq));
	rq->q_ptr = wq->q_ptr = NULL;
	dsp->ds_rq = dsp->ds_wq = NULL;

	ASSERT(dsp->ds_dlstate == DL_UNATTACHED);
	ASSERT(dsp->ds_sap == 0);
	ASSERT(dsp->ds_mh == NULL);
	ASSERT(dsp->ds_mch == NULL);
	ASSERT(dsp->ds_promisc == 0);
	ASSERT(dsp->ds_mph == NULL);
	ASSERT(dsp->ds_mip == NULL);
	ASSERT(dsp->ds_mnh == NULL);

	ASSERT(dsp->ds_polling == B_FALSE);
	ASSERT(dsp->ds_direct == B_FALSE);
	ASSERT(dsp->ds_lso == B_FALSE);
	ASSERT(dsp->ds_lso_max == 0);
	ASSERT(dsp->ds_passivestate != DLD_ACTIVE);

	/*
	 * Reinitialize all the flags.
	 */
	dsp->ds_notifications = 0;
	dsp->ds_passivestate = DLD_UNINITIALIZED;
	dsp->ds_mode = DLD_UNITDATA;
	dsp->ds_native = B_FALSE;
	dsp->ds_nonip = B_FALSE;

	ASSERT(dsp->ds_datathr_cnt == 0);
	ASSERT(dsp->ds_pending_head == NULL);
	ASSERT(dsp->ds_pending_tail == NULL);
	ASSERT(!dsp->ds_dlpi_pending);

	ASSERT(dsp->ds_dlp == NULL);
	ASSERT(dsp->ds_dmap == NULL);
	ASSERT(dsp->ds_rx == NULL);
	ASSERT(dsp->ds_rx_arg == NULL);
	ASSERT(dsp->ds_next == NULL);
	ASSERT(dsp->ds_head == NULL);

	/*
	 * Free the dummy mblk if exists.
	 */
	if (dsp->ds_tx_flow_mp != NULL) {
		freeb(dsp->ds_tx_flow_mp);
		dsp->ds_tx_flow_mp = NULL;
	}

	(void) mod_hash_remove(str_hashp, STR_HASH_KEY(dsp->ds_minor), &val);
	ASSERT(dsp == (dld_str_t *)val);

	/*
	 * Free the object back to the cache.
	 */
	kmem_cache_free(str_cachep, dsp);
	atomic_dec_32(&str_count);
}

/*
 * kmem_cache contructor function: see kmem_cache_create(9f).
 */
/*ARGSUSED*/
static int
str_constructor(void *buf, void *cdrarg, int kmflags)
{
	dld_str_t	*dsp = buf;

	bzero(buf, sizeof (dld_str_t));

	/*
	 * Allocate a new minor number.
	 */
	if ((dsp->ds_minor = mac_minor_hold(kmflags == KM_SLEEP)) == 0)
		return (-1);

	/*
	 * Initialize the DLPI state machine.
	 */
	dsp->ds_dlstate = DL_UNATTACHED;

	mutex_init(&dsp->ds_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dsp->ds_datathr_cv, NULL, CV_DRIVER, NULL);
	cv_init(&dsp->ds_dlpi_pending_cv, NULL, CV_DRIVER, NULL);

	return (0);
}

/*
 * kmem_cache destructor function.
 */
/*ARGSUSED*/
static void
str_destructor(void *buf, void *cdrarg)
{
	dld_str_t	*dsp = buf;

	/*
	 * Release the minor number.
	 */
	mac_minor_rele(dsp->ds_minor);

	ASSERT(dsp->ds_tx_flow_mp == NULL);

	mutex_destroy(&dsp->ds_lock);
	cv_destroy(&dsp->ds_datathr_cv);
	cv_destroy(&dsp->ds_dlpi_pending_cv);
}

/*
 * Update the priority bits and VID (may need to insert tag if mp points
 * to an untagged packet.
 * If vid is VLAN_ID_NONE, use the VID encoded in the packet.
 */
static mblk_t *
i_dld_ether_header_update_tag(mblk_t *mp, uint_t pri, uint16_t vid,
    link_tagmode_t tagmode)
{
	mblk_t *hmp;
	struct ether_vlan_header *evhp;
	struct ether_header *ehp;
	uint16_t old_tci = 0;
	size_t len;

	ASSERT(pri != 0 || vid != VLAN_ID_NONE);

	evhp = (struct ether_vlan_header *)mp->b_rptr;
	if (ntohs(evhp->ether_tpid) == ETHERTYPE_VLAN) {
		/*
		 * Tagged packet, update the priority bits.
		 */
		len = sizeof (struct ether_vlan_header);

		if ((DB_REF(mp) > 1) || (MBLKL(mp) < len)) {
			/*
			 * In case some drivers only check the db_ref
			 * count of the first mblk, we pullup the
			 * message into a single mblk.
			 */
			hmp = msgpullup(mp, -1);
			if ((hmp == NULL) || (MBLKL(hmp) < len)) {
				freemsg(hmp);
				return (NULL);
			} else {
				freemsg(mp);
				mp = hmp;
			}
		}

		evhp = (struct ether_vlan_header *)mp->b_rptr;
		old_tci = ntohs(evhp->ether_tci);
	} else {
		/*
		 * Untagged packet.  Two factors will cause us to insert a
		 * VLAN header:
		 * - This is a VLAN link (vid is specified)
		 * - The link supports user priority tagging and the priority
		 *   is non-zero.
		 */
		if (vid == VLAN_ID_NONE && tagmode == LINK_TAGMODE_VLANONLY)
			return (mp);

		hmp = allocb(sizeof (struct ether_vlan_header), BPRI_MED);
		if (hmp == NULL)
			return (NULL);

		evhp = (struct ether_vlan_header *)hmp->b_rptr;
		ehp = (struct ether_header *)mp->b_rptr;

		/*
		 * Copy the MAC addresses and typelen
		 */
		bcopy(ehp, evhp, (ETHERADDRL * 2));
		evhp->ether_type = ehp->ether_type;
		evhp->ether_tpid = htons(ETHERTYPE_VLAN);

		hmp->b_wptr += sizeof (struct ether_vlan_header);
		mp->b_rptr += sizeof (struct ether_header);

		/*
		 * Free the original message if it's now empty. Link the
		 * rest of the messages to the header message.
		 */
		if (MBLKL(mp) == 0) {
			hmp->b_cont = mp->b_cont;
			freeb(mp);
		} else {
			hmp->b_cont = mp;
		}
		mp = hmp;
	}

	if (pri == 0)
		pri = VLAN_PRI(old_tci);
	if (vid == VLAN_ID_NONE)
		vid = VLAN_ID(old_tci);
	evhp->ether_tci = htons(VLAN_TCI(pri, VLAN_CFI(old_tci), vid));
	return (mp);
}

static boolean_t
i_dld_raw_ether_check(dld_str_t *dsp, mac_header_info_t *mhip, mblk_t **mpp)
{
	mblk_t *mp = *mpp;
	mblk_t *newmp;
	uint_t pri, vid, dvid;

	dvid = mac_client_vid(dsp->ds_mch);

	/*
	 * Discard the packet if this is a VLAN stream but the VID in
	 * the packet is not correct.
	 */
	vid = VLAN_ID(mhip->mhi_tci);
	if ((dvid != VLAN_ID_NONE) && (vid != VLAN_ID_NONE))
		return (B_FALSE);

	/*
	 * Discard the packet if this packet is a tagged packet
	 * but both pri and VID are 0.
	 */
	pri = VLAN_PRI(mhip->mhi_tci);
	if (mhip->mhi_istagged && !mhip->mhi_ispvid && pri == 0 &&
	    vid == VLAN_ID_NONE)
		return (B_FALSE);

	/*
	 * Update the priority bits to the per-stream priority if
	 * priority is not set in the packet. Update the VID for
	 * packets on a VLAN stream.
	 */
	pri = (pri == 0) ? dsp->ds_pri : 0;
	if ((pri != 0) || (dvid != VLAN_ID_NONE)) {
		if ((newmp = i_dld_ether_header_update_tag(mp, pri,
		    dvid, dsp->ds_dlp->dl_tagmode)) == NULL) {
			return (B_FALSE);
		}
		*mpp = newmp;
	}

	return (B_TRUE);
}

mac_tx_cookie_t
str_mdata_raw_fastpath_put(dld_str_t *dsp, mblk_t *mp, uintptr_t f_hint,
    uint16_t flag)
{
	boolean_t is_ethernet = (dsp->ds_mip->mi_media == DL_ETHER);
	mac_header_info_t mhi;
	mac_tx_cookie_t cookie;

	if (mac_vlan_header_info(dsp->ds_mh, mp, &mhi) != 0)
		goto discard;

	if (is_ethernet) {
		if (i_dld_raw_ether_check(dsp, &mhi, &mp) == B_FALSE)
			goto discard;
	}

	if ((cookie = DLD_TX(dsp, mp, f_hint, flag)) != NULL) {
		DLD_SETQFULL(dsp);
	}
	return (cookie);
discard:
	/* TODO: bump kstat? */
	freemsg(mp);
	return (NULL);
}



/*
 * M_DATA put (IP fast-path mode)
 */
mac_tx_cookie_t
str_mdata_fastpath_put(dld_str_t *dsp, mblk_t *mp, uintptr_t f_hint,
    uint16_t flag)
{
	boolean_t is_ethernet = (dsp->ds_mip->mi_media == DL_ETHER);
	mblk_t *newmp;
	uint_t pri;
	mac_tx_cookie_t cookie;

	if (is_ethernet) {
		/*
		 * Update the priority bits to the assigned priority.
		 */
		pri = (VLAN_MBLKPRI(mp) == 0) ? dsp->ds_pri : VLAN_MBLKPRI(mp);

		if (pri != 0) {
			newmp = i_dld_ether_header_update_tag(mp, pri,
			    VLAN_ID_NONE, dsp->ds_dlp->dl_tagmode);
			if (newmp == NULL)
				goto discard;
			mp = newmp;
		}
	}

	if ((cookie = DLD_TX(dsp, mp, f_hint, flag)) != NULL) {
		DLD_SETQFULL(dsp);
	}
	return (cookie);

discard:
	/* TODO: bump kstat? */
	freemsg(mp);
	return (NULL);
}

/*
 * M_DATA put (DLIOCRAW mode)
 */
static void
str_mdata_raw_put(dld_str_t *dsp, mblk_t *mp)
{
	boolean_t is_ethernet = (dsp->ds_mip->mi_media == DL_ETHER);
	mblk_t *bp, *newmp;
	size_t size;
	mac_header_info_t mhi;
	uint_t max_sdu;

	/*
	 * Certain MAC type plugins provide an illusion for raw DLPI
	 * consumers.  They pretend that the MAC layer is something that
	 * it's not for the benefit of observability tools.  For example,
	 * mac_wifi pretends that it's Ethernet for such consumers.
	 * Here, unless native mode is enabled, we call into the MAC layer so
	 * that this illusion can be maintained.  The plugin will optionally
	 * transform the MAC header here into something that can be passed
	 * down.  The header goes from raw mode to "cooked" mode.
	 */
	if (!dsp->ds_native) {
		if ((newmp = mac_header_cook(dsp->ds_mh, mp)) == NULL)
			goto discard;
		mp = newmp;
	}

	size = MBLKL(mp);

	/*
	 * Check the packet is not too big and that any remaining
	 * fragment list is composed entirely of M_DATA messages. (We
	 * know the first fragment was M_DATA otherwise we could not
	 * have got here).
	 */
	for (bp = mp->b_cont; bp != NULL; bp = bp->b_cont) {
		if (DB_TYPE(bp) != M_DATA)
			goto discard;
		size += MBLKL(bp);
	}

	if (mac_vlan_header_info(dsp->ds_mh, mp, &mhi) != 0)
		goto discard;

	mac_sdu_get(dsp->ds_mh, NULL, &max_sdu);
	/*
	 * If LSO is enabled, check the size against lso_max. Otherwise,
	 * compare the packet size with max_sdu.
	 */
	max_sdu = dsp->ds_lso ? dsp->ds_lso_max : max_sdu;
	if (size > max_sdu + mhi.mhi_hdrsize)
		goto discard;

	if (is_ethernet) {
		if (i_dld_raw_ether_check(dsp, &mhi, &mp) == B_FALSE)
			goto discard;
	}

	if (DLD_TX(dsp, mp, 0, 0) != NULL) {
		/* Turn on flow-control for dld */
		DLD_SETQFULL(dsp);
	}
	return;

discard:
	/* TODO: bump kstat? */
	freemsg(mp);
}

/*
 * Process DL_ATTACH_REQ (style 2) or open(2) (style 1).
 */
int
dld_str_attach(dld_str_t *dsp, t_uscalar_t ppa)
{
	dev_t			dev;
	int			err;
	const char		*drvname;
	mac_perim_handle_t	mph = NULL;
	boolean_t		qassociated = B_FALSE;
	dls_link_t		*dlp = NULL;
	dls_dl_handle_t		ddp = NULL;

	if ((drvname = ddi_major_to_name(dsp->ds_major)) == NULL)
		return (EINVAL);

	if (dsp->ds_style == DL_STYLE2 && ppa > DLS_MAX_PPA)
		return (ENOTSUP);

	/*
	 * /dev node access. This will still be supported for backward
	 * compatibility reason.
	 */
	if ((dsp->ds_style == DL_STYLE2) && (strcmp(drvname, "aggr") != 0) &&
	    (strcmp(drvname, "vnic") != 0)) {
		if (qassociate(dsp->ds_wq, DLS_PPA2INST(ppa)) != 0)
			return (EINVAL);
		qassociated = B_TRUE;
	}

	dev = makedevice(dsp->ds_major, (minor_t)ppa + 1);
	if ((err = dls_devnet_hold_by_dev(dev, &ddp)) != 0)
		goto failed;

	if ((err = mac_perim_enter_by_macname(dls_devnet_mac(ddp), &mph)) != 0)
		goto failed;

	/*
	 * Open a channel.
	 */
	if ((err = dls_link_hold(dls_devnet_mac(ddp), &dlp)) != 0)
		goto failed;

	if ((err = dls_open(dlp, ddp, dsp)) != 0)
		goto failed;

	/*
	 * Set the default packet priority.
	 */
	dsp->ds_pri = 0;

	/*
	 * Add a notify function so that the we get updates from the MAC.
	 */
	dsp->ds_mnh = mac_notify_add(dsp->ds_mh, str_notify, dsp);
	dsp->ds_dlstate = DL_UNBOUND;
	mac_perim_exit(mph);
	return (0);

failed:
	if (dlp != NULL)
		dls_link_rele(dlp);
	if (mph != NULL)
		mac_perim_exit(mph);
	if (ddp != NULL)
		dls_devnet_rele(ddp);
	if (qassociated)
		(void) qassociate(dsp->ds_wq, -1);

	return (err);
}

/*
 * Process DL_DETACH_REQ (style 2) or close(2) (style 1). Can also be called
 * from close(2) for style 2.
 */
void
dld_str_detach(dld_str_t *dsp)
{
	mac_perim_handle_t	mph;
	int			err;

	ASSERT(dsp->ds_datathr_cnt == 0);

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);
	/*
	 * Remove the notify function.
	 *
	 * Note that we cannot wait for the notification callback to be removed
	 * since it could cause the deadlock with str_notify() since they both
	 * need the mac perimeter. Continue if we cannot remove the
	 * notification callback right now and wait after we leave the
	 * perimeter.
	 */
	err = mac_notify_remove(dsp->ds_mnh, B_FALSE);
	dsp->ds_mnh = NULL;

	/*
	 * Disable the capabilities
	 */
	dld_capabilities_disable(dsp);

	/*
	 * Clear LSO flags.
	 */
	dsp->ds_lso = B_FALSE;
	dsp->ds_lso_max = 0;

	dls_close(dsp);
	mac_perim_exit(mph);

	/*
	 * Now we leave the mac perimeter. If mac_notify_remove() failed
	 * because the notification callback was in progress, wait for
	 * it to finish before we proceed.
	 */
	if (err != 0)
		mac_notify_remove_wait(dsp->ds_mh);

	/*
	 * An unreferenced tagged (non-persistent) vlan gets destroyed
	 * automatically in the call to dls_devnet_rele.
	 */
	dls_devnet_rele(dsp->ds_ddh);

	dsp->ds_sap = 0;
	dsp->ds_mh = NULL;
	dsp->ds_mch = NULL;
	dsp->ds_mip = NULL;

	if (dsp->ds_style == DL_STYLE2)
		(void) qassociate(dsp->ds_wq, -1);

	/*
	 * Re-initialize the DLPI state machine.
	 */
	dsp->ds_dlstate = DL_UNATTACHED;
}

/*
 * This function is only called for VLAN streams. In raw mode, we strip VLAN
 * tags before sending packets up to the DLS clients, with the exception of
 * special priority tagged packets, in that case, we set the VID to 0.
 * mp must be a VLAN tagged packet.
 */
static mblk_t *
i_dld_ether_header_strip_tag(mblk_t *mp, boolean_t keep_pri)
{
	mblk_t *newmp;
	struct ether_vlan_header *evhp;
	uint16_t tci, new_tci;

	ASSERT(MBLKL(mp) >= sizeof (struct ether_vlan_header));
	if (DB_REF(mp) > 1) {
		newmp = copymsg(mp);
		if (newmp == NULL)
			return (NULL);
		freemsg(mp);
		mp = newmp;
	}
	evhp = (struct ether_vlan_header *)mp->b_rptr;

	tci = ntohs(evhp->ether_tci);
	if (VLAN_PRI(tci) == 0 || !keep_pri) {
		/*
		 * Priority is 0, strip the tag.
		 */
		ovbcopy(mp->b_rptr, mp->b_rptr + VLAN_TAGSZ, 2 * ETHERADDRL);
		mp->b_rptr += VLAN_TAGSZ;
	} else {
		/*
		 * Priority is not 0, update the VID to 0.
		 */
		new_tci = VLAN_TCI(VLAN_PRI(tci), VLAN_CFI(tci), VLAN_ID_NONE);
		evhp->ether_tci = htons(new_tci);
	}
	return (mp);
}

/*
 * Raw mode receive function.
 */
/*ARGSUSED*/
void
dld_str_rx_raw(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    mac_header_info_t *mhip)
{
	dld_str_t *dsp = (dld_str_t *)arg;
	boolean_t is_ethernet = (dsp->ds_mip->mi_media == DL_ETHER);
	mblk_t *next, *newmp;

	ASSERT(mp != NULL);
	do {
		/*
		 * Get the pointer to the next packet in the chain and then
		 * clear b_next before the packet gets passed on.
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Wind back b_rptr to point at the MAC header.
		 */
		ASSERT(mp->b_rptr >= DB_BASE(mp) + mhip->mhi_hdrsize);
		mp->b_rptr -= mhip->mhi_hdrsize;

		/*
		 * Certain MAC type plugins provide an illusion for raw
		 * DLPI consumers.  They pretend that the MAC layer is
		 * something that it's not for the benefit of observability
		 * tools.  For example, mac_wifi pretends that it's Ethernet
		 * for such consumers.	Here, unless native mode is enabled,
		 * we call into the MAC layer so that this illusion can be
		 * maintained.	The plugin will optionally transform the MAC
		 * header here into something that can be passed up to raw
		 * consumers.  The header goes from "cooked" mode to raw mode.
		 */
		if (!dsp->ds_native) {
			newmp = mac_header_uncook(dsp->ds_mh, mp);
			if (newmp == NULL) {
				freemsg(mp);
				goto next;
			}
			mp = newmp;
		}

		/*
		 * Strip the VLAN tag for VLAN streams.
		 */
		if (is_ethernet &&
		    mac_client_vid(dsp->ds_mch) != VLAN_ID_NONE) {
			/*
			 * The priority should be kept only for VLAN
			 * data-links.
			 */
			newmp = i_dld_ether_header_strip_tag(mp,
			    mac_client_is_vlan_vnic(dsp->ds_mch));
			if (newmp == NULL) {
				freemsg(mp);
				goto next;
			}
			mp = newmp;
		}

		/*
		 * Pass the packet on.
		 */
		if (canputnext(dsp->ds_rq))
			putnext(dsp->ds_rq, mp);
		else
			freemsg(mp);

next:
		/*
		 * Move on to the next packet in the chain.
		 */
		mp = next;
	} while (mp != NULL);
}

/*
 * Fast-path receive function.
 */
/*ARGSUSED*/
void
dld_str_rx_fastpath(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    mac_header_info_t *mhip)
{
	dld_str_t *dsp = (dld_str_t *)arg;
	mblk_t *next;
	size_t offset = 0;

	/*
	 * MAC header stripping rules:
	 *    - Tagged packets:
	 *	a. VLAN streams. Strip the whole VLAN header including the tag.
	 *	b. Physical streams
	 *	- VLAN packets (non-zero VID). The stream must be either a
	 *	  DL_PROMISC_SAP listener or a ETHERTYPE_VLAN listener.
	 *	  Strip the Ethernet header but keep the VLAN header.
	 *	- Special tagged packets (zero VID)
	 *	  * The stream is either a DL_PROMISC_SAP listener or a
	 *	    ETHERTYPE_VLAN listener, strip the Ethernet header but
	 *	    keep the VLAN header.
	 *	  * Otherwise, strip the whole VLAN header.
	 *    - Untagged packets. Strip the whole MAC header.
	 */
	if (mhip->mhi_istagged &&
	    (mac_client_vid(dsp->ds_mch) == VLAN_ID_NONE) &&
	    ((dsp->ds_sap == ETHERTYPE_VLAN) ||
	    (dsp->ds_promisc & DLS_PROMISC_SAP))) {
		offset = VLAN_TAGSZ;
	}

	ASSERT(mp != NULL);
	do {
		/*
		 * Get the pointer to the next packet in the chain and then
		 * clear b_next before the packet gets passed on.
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Wind back b_rptr to point at the VLAN header.
		 */
		ASSERT(mp->b_rptr >= DB_BASE(mp) + offset);
		mp->b_rptr -= offset;

		/*
		 * Pass the packet on.
		 */
		if (canputnext(dsp->ds_rq))
			putnext(dsp->ds_rq, mp);
		else
			freemsg(mp);
		/*
		 * Move on to the next packet in the chain.
		 */
		mp = next;
	} while (mp != NULL);
}

/*
 * Default receive function (send DL_UNITDATA_IND messages).
 */
/*ARGSUSED*/
void
dld_str_rx_unitdata(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    mac_header_info_t *mhip)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	mblk_t			*ud_mp;
	mblk_t			*next;
	size_t			offset = 0;
	boolean_t		strip_vlan = B_TRUE;

	/*
	 * See MAC header stripping rules in the dld_str_rx_fastpath() function.
	 */
	if (mhip->mhi_istagged &&
	    (mac_client_vid(dsp->ds_mch) == VLAN_ID_NONE) &&
	    ((dsp->ds_sap == ETHERTYPE_VLAN) ||
	    (dsp->ds_promisc & DLS_PROMISC_SAP))) {
		offset = VLAN_TAGSZ;
		strip_vlan = B_FALSE;
	}

	ASSERT(mp != NULL);
	do {
		/*
		 * Get the pointer to the next packet in the chain and then
		 * clear b_next before the packet gets passed on.
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Wind back b_rptr to point at the MAC header.
		 */
		ASSERT(mp->b_rptr >= DB_BASE(mp) + mhip->mhi_hdrsize);
		mp->b_rptr -= mhip->mhi_hdrsize;

		/*
		 * Create the DL_UNITDATA_IND M_PROTO.
		 */
		if ((ud_mp = str_unitdata_ind(dsp, mp, strip_vlan)) == NULL) {
			freemsgchain(mp);
			return;
		}

		/*
		 * Advance b_rptr to point at the payload (or the VLAN header).
		 */
		mp->b_rptr += (mhip->mhi_hdrsize - offset);

		/*
		 * Prepend the DL_UNITDATA_IND.
		 */
		ud_mp->b_cont = mp;

		/*
		 * Send the message.
		 */
		if (canputnext(dsp->ds_rq))
			putnext(dsp->ds_rq, ud_mp);
		else
			freemsg(ud_mp);

		/*
		 * Move on to the next packet in the chain.
		 */
		mp = next;
	} while (mp != NULL);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_SDU_SIZE
 */
static void
str_notify_sdu_size(dld_str_t *dsp, uint_t max_sdu, uint_t multicast_sdu)
{
	mblk_t		*mp;
	dl_notify_ind_t *dlip;

	if (!(dsp->ds_notifications & (DL_NOTE_SDU_SIZE|DL_NOTE_SDU_SIZE2)))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	if (dsp->ds_notifications & DL_NOTE_SDU_SIZE2) {
		dlip->dl_notification = DL_NOTE_SDU_SIZE2;
		dlip->dl_data1 = max_sdu;
		dlip->dl_data2 = multicast_sdu;
	} else {
		dlip->dl_notification = DL_NOTE_SDU_SIZE;
		dlip->dl_data = max_sdu;
	}

	qreply(dsp->ds_wq, mp);
}

/*
 * Generate DL_NOTIFY_IND messages to notify the DLPI consumer of the
 * current state of the interface.
 */
void
dld_str_notify_ind(dld_str_t *dsp)
{
	mac_notify_type_t	type;

	for (type = 0; type < MAC_NNOTE; type++)
		str_notify(dsp, type);
}

typedef struct dl_unitdata_ind_wrapper {
	dl_unitdata_ind_t	dl_unitdata;
	uint8_t			dl_dest_addr[MAXMACADDRLEN + sizeof (uint16_t)];
	uint8_t			dl_src_addr[MAXMACADDRLEN + sizeof (uint16_t)];
} dl_unitdata_ind_wrapper_t;

/*
 * Create a DL_UNITDATA_IND M_PROTO message.
 */
static mblk_t *
str_unitdata_ind(dld_str_t *dsp, mblk_t *mp, boolean_t strip_vlan)
{
	mblk_t				*nmp;
	dl_unitdata_ind_wrapper_t	*dlwp;
	dl_unitdata_ind_t		*dlp;
	mac_header_info_t		mhi;
	uint_t				addr_length;
	uint8_t				*daddr;
	uint8_t				*saddr;

	/*
	 * Get the packet header information.
	 */
	if (mac_vlan_header_info(dsp->ds_mh, mp, &mhi) != 0)
		return (NULL);

	/*
	 * Allocate a message large enough to contain the wrapper structure
	 * defined above.
	 */
	if ((nmp = mexchange(dsp->ds_wq, NULL,
	    sizeof (dl_unitdata_ind_wrapper_t), M_PROTO,
	    DL_UNITDATA_IND)) == NULL)
		return (NULL);

	dlwp = (dl_unitdata_ind_wrapper_t *)nmp->b_rptr;

	dlp = &(dlwp->dl_unitdata);
	ASSERT(dlp == (dl_unitdata_ind_t *)nmp->b_rptr);
	ASSERT(dlp->dl_primitive == DL_UNITDATA_IND);

	/*
	 * Copy in the destination address.
	 */
	addr_length = dsp->ds_mip->mi_addr_length;
	daddr = dlwp->dl_dest_addr;
	dlp->dl_dest_addr_offset = (uintptr_t)daddr - (uintptr_t)dlp;
	bcopy(mhi.mhi_daddr, daddr, addr_length);

	/*
	 * Set the destination DLSAP to the SAP value encoded in the packet.
	 */
	if (mhi.mhi_istagged && !strip_vlan)
		*(uint16_t *)(daddr + addr_length) = ETHERTYPE_VLAN;
	else
		*(uint16_t *)(daddr + addr_length) = mhi.mhi_bindsap;
	dlp->dl_dest_addr_length = addr_length + sizeof (uint16_t);

	/*
	 * If the destination address was multicast or broadcast then the
	 * dl_group_address field should be non-zero.
	 */
	dlp->dl_group_address = (mhi.mhi_dsttype == MAC_ADDRTYPE_MULTICAST) ||
	    (mhi.mhi_dsttype == MAC_ADDRTYPE_BROADCAST);

	/*
	 * Copy in the source address if one exists.  Some MAC types (DL_IB
	 * for example) may not have access to source information.
	 */
	if (mhi.mhi_saddr == NULL) {
		dlp->dl_src_addr_offset = dlp->dl_src_addr_length = 0;
	} else {
		saddr = dlwp->dl_src_addr;
		dlp->dl_src_addr_offset = (uintptr_t)saddr - (uintptr_t)dlp;
		bcopy(mhi.mhi_saddr, saddr, addr_length);

		/*
		 * Set the source DLSAP to the packet ethertype.
		 */
		*(uint16_t *)(saddr + addr_length) = mhi.mhi_origsap;
		dlp->dl_src_addr_length = addr_length + sizeof (uint16_t);
	}

	return (nmp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_PROMISC_ON_PHYS
 */
static void
str_notify_promisc_on_phys(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_PROMISC_ON_PHYS))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_PROMISC_ON_PHYS;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_PROMISC_OFF_PHYS
 */
static void
str_notify_promisc_off_phys(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_PROMISC_OFF_PHYS))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_PROMISC_OFF_PHYS;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_PHYS_ADDR
 */
static void
str_notify_phys_addr(dld_str_t *dsp, uint_t addr_type, const uint8_t *addr)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;
	uint_t		addr_length;
	uint16_t	ethertype;

	if (!(dsp->ds_notifications & DL_NOTE_PHYS_ADDR))
		return;

	addr_length = dsp->ds_mip->mi_addr_length;
	if ((mp = mexchange(dsp->ds_wq, NULL,
	    sizeof (dl_notify_ind_t) + addr_length + sizeof (uint16_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_PHYS_ADDR;
	dlip->dl_data = addr_type;
	dlip->dl_addr_offset = sizeof (dl_notify_ind_t);
	dlip->dl_addr_length = addr_length + sizeof (uint16_t);

	bcopy(addr, &dlip[1], addr_length);

	ethertype = (dsp->ds_sap < ETHERTYPE_802_MIN) ? 0 : dsp->ds_sap;
	*(uint16_t *)((uchar_t *)(dlip + 1) + addr_length) = ethertype;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_LINK_UP
 */
static void
str_notify_link_up(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_LINK_UP))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_LINK_UP;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_LINK_DOWN
 */
static void
str_notify_link_down(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_LINK_DOWN))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_LINK_DOWN;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_SPEED
 */
static void
str_notify_speed(dld_str_t *dsp, uint32_t speed)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_SPEED))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_SPEED;
	dlip->dl_data = speed;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_CAPAB_RENEG
 */
static void
str_notify_capab_reneg(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_CAPAB_RENEG))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_CAPAB_RENEG;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_FASTPATH_FLUSH
 */
static void
str_notify_fastpath_flush(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_FASTPATH_FLUSH))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_FASTPATH_FLUSH;

	qreply(dsp->ds_wq, mp);
}

static void
str_notify_allowed_ips(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;
	size_t		mp_size;
	mac_protect_t	*mrp;

	if (!(dsp->ds_notifications & DL_NOTE_ALLOWED_IPS))
		return;

	mp_size = sizeof (mac_protect_t) + sizeof (dl_notify_ind_t);
	if ((mp = mexchange(dsp->ds_wq, NULL, mp_size, M_PROTO, 0)) == NULL)
		return;

	mrp = mac_protect_get(dsp->ds_mh);
	bzero(mp->b_rptr, mp_size);
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_ALLOWED_IPS;
	dlip->dl_data = 0;
	dlip->dl_addr_offset = sizeof (dl_notify_ind_t);
	dlip->dl_addr_length = sizeof (mac_protect_t);
	bcopy(mrp, mp->b_rptr + sizeof (dl_notify_ind_t),
	    sizeof (mac_protect_t));

	qreply(dsp->ds_wq, mp);
}

/*
 * MAC notification callback.
 */
void
str_notify(void *arg, mac_notify_type_t type)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	queue_t			*q = dsp->ds_wq;
	mac_handle_t		mh = dsp->ds_mh;
	mac_client_handle_t	mch = dsp->ds_mch;
	uint8_t			addr[MAXMACADDRLEN];

	switch (type) {
	case MAC_NOTE_TX:
		qenable(q);
		break;

	case MAC_NOTE_DEVPROMISC:
		/*
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		if (mac_promisc_get(mh))
			str_notify_promisc_on_phys(dsp);
		else
			str_notify_promisc_off_phys(dsp);
		break;

	case MAC_NOTE_UNICST:
		/*
		 * This notification is sent whenever the MAC unicast
		 * address changes.
		 */
		mac_unicast_primary_get(mh, addr);

		/*
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		str_notify_phys_addr(dsp, DL_CURR_PHYS_ADDR, addr);
		break;

	case MAC_NOTE_DEST:
		/*
		 * Only send up DL_NOTE_DEST_ADDR if the link has a
		 * destination address.
		 */
		if (mac_dst_get(dsp->ds_mh, addr))
			str_notify_phys_addr(dsp, DL_CURR_DEST_ADDR, addr);
		break;

	case MAC_NOTE_LOWLINK:
	case MAC_NOTE_LINK:
		/*
		 * LOWLINK refers to the actual link status. For links that
		 * are not part of a bridge instance LOWLINK and LINK state
		 * are the same. But for a link part of a bridge instance
		 * LINK state refers to the aggregate link status: "up" when
		 * at least one link part of the bridge is up and is "down"
		 * when all links part of the bridge are down.
		 *
		 * Clients can request to be notified of the LOWLINK state
		 * using the DLIOCLOWLINK ioctl. Clients such as the bridge
		 * daemon request lowlink state changes and upper layer clients
		 * receive notifications of the aggregate link state changes
		 * which is the default when requesting LINK UP/DOWN state
		 * notifications.
		 */

		/*
		 * Check that the notification type matches the one that we
		 * want.  If we want lower-level link notifications, and this
		 * is upper, or if we want upper and this is lower, then
		 * ignore.
		 */
		if ((type == MAC_NOTE_LOWLINK) != dsp->ds_lowlink)
			break;
		/*
		 * This notification is sent every time the MAC driver
		 * updates the link state.
		 */
		switch (mac_client_stat_get(mch, dsp->ds_lowlink ?
		    MAC_STAT_LOWLINK_STATE : MAC_STAT_LINK_STATE)) {
		case LINK_STATE_UP: {
			uint64_t speed;
			/*
			 * The link is up so send the appropriate
			 * DL_NOTIFY_IND.
			 */
			str_notify_link_up(dsp);

			speed = mac_stat_get(mh, MAC_STAT_IFSPEED);
			str_notify_speed(dsp, (uint32_t)(speed / 1000ull));
			break;
		}
		case LINK_STATE_DOWN:
			/*
			 * The link is down so send the appropriate
			 * DL_NOTIFY_IND.
			 */
			str_notify_link_down(dsp);
			break;

		default:
			break;
		}
		break;

	case MAC_NOTE_CAPAB_CHG:
		/*
		 * This notification is sent whenever the MAC resources
		 * change or capabilities change. We need to renegotiate
		 * the capabilities. Send the appropriate DL_NOTIFY_IND.
		 */
		str_notify_capab_reneg(dsp);
		break;

	case MAC_NOTE_SDU_SIZE: {
		uint_t  max_sdu;
		uint_t	multicast_sdu;
		mac_sdu_get2(dsp->ds_mh, NULL, &max_sdu, &multicast_sdu);
		str_notify_sdu_size(dsp, max_sdu, multicast_sdu);
		break;
	}

	case MAC_NOTE_FASTPATH_FLUSH:
		str_notify_fastpath_flush(dsp);
		break;

	/* Unused notifications */
	case MAC_NOTE_MARGIN:
		break;

	case MAC_NOTE_ALLOWED_IPS:
		str_notify_allowed_ips(dsp);
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}
}

/*
 * This function is called via a taskq mechansim to process all control
 * messages on a per 'dsp' end point.
 */
static void
dld_wput_nondata_task(void *arg)
{
	dld_str_t	*dsp = arg;
	mblk_t		*mp;

	mutex_enter(&dsp->ds_lock);
	while (dsp->ds_pending_head != NULL) {
		mp = dsp->ds_pending_head;
		dsp->ds_pending_head = mp->b_next;
		mp->b_next = NULL;
		if (dsp->ds_pending_head == NULL)
			dsp->ds_pending_tail = NULL;
		mutex_exit(&dsp->ds_lock);

		switch (DB_TYPE(mp)) {
		case M_PROTO:
		case M_PCPROTO:
			dld_proto(dsp, mp);
			break;
		case M_IOCTL:
			dld_ioc(dsp, mp);
			break;
		default:
			ASSERT(0);
		}

		mutex_enter(&dsp->ds_lock);
	}
	ASSERT(dsp->ds_pending_tail == NULL);
	dsp->ds_dlpi_pending = 0;
	cv_broadcast(&dsp->ds_dlpi_pending_cv);
	mutex_exit(&dsp->ds_lock);
}

/*
 * Kernel thread to handle taskq dispatch failures in dld_wput_data. This
 * thread is started at boot time.
 */
static void
dld_taskq_dispatch(void)
{
	callb_cpr_t	cprinfo;
	dld_str_t	*dsp;

	CALLB_CPR_INIT(&cprinfo, &dld_taskq_lock, callb_generic_cpr,
	    "dld_taskq_dispatch");
	mutex_enter(&dld_taskq_lock);

	while (!dld_taskq_quit) {
		dsp = list_head(&dld_taskq_list);
		while (dsp != NULL) {
			list_remove(&dld_taskq_list, dsp);
			mutex_exit(&dld_taskq_lock);
			VERIFY(taskq_dispatch(dld_taskq, dld_wput_nondata_task,
			    dsp, TQ_SLEEP) != 0);
			mutex_enter(&dld_taskq_lock);
			dsp = list_head(&dld_taskq_list);
		}

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&dld_taskq_cv, &dld_taskq_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &dld_taskq_lock);
	}

	dld_taskq_done = B_TRUE;
	cv_signal(&dld_taskq_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * All control operations are serialized on the 'dsp' and are also funneled
 * through a taskq mechanism to ensure that subsequent processing has kernel
 * context and can safely use cv_wait.
 *
 * Mechanisms to handle taskq dispatch failures
 *
 * The only way to be sure that taskq dispatch does not fail is to either
 * specify TQ_SLEEP or to use a static taskq and prepopulate it with
 * some number of entries and make sure that the number of outstanding requests
 * are less than that number. We can't use TQ_SLEEP since we don't know the
 * context. Nor can we bound the total number of 'dsp' end points. So we are
 * unable to use either of the above schemes, and are forced to deal with
 * taskq dispatch failures. Note that even dynamic taskq could fail in
 * dispatch if TQ_NOSLEEP is specified, since this flag is translated
 * eventually to KM_NOSLEEP and kmem allocations could fail in the taskq
 * framework.
 *
 * We maintain a queue of 'dsp's that encountered taskq dispatch failure.
 * We also have a single global thread to retry the taskq dispatch. This
 * thread loops in 'dld_taskq_dispatch' and retries the taskq dispatch, but
 * uses TQ_SLEEP to ensure eventual success of the dispatch operation.
 */
static void
dld_wput_nondata(dld_str_t *dsp, mblk_t *mp)
{
	ASSERT(mp->b_next == NULL);
	mutex_enter(&dsp->ds_lock);
	if (dsp->ds_pending_head != NULL) {
		ASSERT(dsp->ds_dlpi_pending);
		dsp->ds_pending_tail->b_next = mp;
		dsp->ds_pending_tail = mp;
		mutex_exit(&dsp->ds_lock);
		return;
	}
	ASSERT(dsp->ds_pending_tail == NULL);
	dsp->ds_pending_head = dsp->ds_pending_tail = mp;
	/*
	 * At this point if ds_dlpi_pending is set, it implies that the taskq
	 * thread is still active and is processing the last message, though
	 * the pending queue has been emptied.
	 */
	if (dsp->ds_dlpi_pending) {
		mutex_exit(&dsp->ds_lock);
		return;
	}

	dsp->ds_dlpi_pending = 1;
	mutex_exit(&dsp->ds_lock);

	if (taskq_dispatch(dld_taskq, dld_wput_nondata_task, dsp,
	    TQ_NOSLEEP) != 0)
		return;

	mutex_enter(&dld_taskq_lock);
	list_insert_tail(&dld_taskq_list, dsp);
	cv_signal(&dld_taskq_cv);
	mutex_exit(&dld_taskq_lock);
}

/*
 * Process an M_IOCTL message.
 */
static void
dld_ioc(dld_str_t *dsp, mblk_t *mp)
{
	uint_t			cmd;

	cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
	ASSERT(dsp->ds_type == DLD_DLPI);

	switch (cmd) {
	case DLIOCNATIVE:
		ioc_native(dsp, mp);
		break;
	case DLIOCMARGININFO:
		ioc_margin(dsp, mp);
		break;
	case DLIOCRAW:
		ioc_raw(dsp, mp);
		break;
	case DLIOCHDRINFO:
		ioc_fast(dsp, mp);
		break;
	case DLIOCLOWLINK:
		ioc_lowlink(dsp, mp);
		break;
	default:
		ioc(dsp, mp);
	}
}

/*
 * DLIOCNATIVE
 */
static void
ioc_native(dld_str_t *dsp, mblk_t *mp)
{
	queue_t *q = dsp->ds_wq;
	const mac_info_t *mip = dsp->ds_mip;

	/*
	 * Native mode can be enabled if it's disabled and if the
	 * native media type is different.
	 */
	if (!dsp->ds_native && mip->mi_media != mip->mi_nativemedia)
		dsp->ds_native = B_TRUE;

	if (dsp->ds_native)
		miocack(q, mp, 0, mip->mi_nativemedia);
	else
		miocnak(q, mp, 0, ENOTSUP);
}

/*
 * DLIOCMARGININFO
 */
static void
ioc_margin(dld_str_t *dsp, mblk_t *mp)
{
	queue_t *q = dsp->ds_wq;
	uint32_t margin;
	int err;

	if (dsp->ds_dlstate == DL_UNATTACHED) {
		err = EINVAL;
		goto failed;
	}
	if ((err = miocpullup(mp, sizeof (uint32_t))) != 0)
		goto failed;

	mac_margin_get(dsp->ds_mh, &margin);
	*((uint32_t *)mp->b_cont->b_rptr) = margin;
	miocack(q, mp, sizeof (uint32_t), 0);
	return;

failed:
	miocnak(q, mp, 0, err);
}

/*
 * DLIOCRAW
 */
static void
ioc_raw(dld_str_t *dsp, mblk_t *mp)
{
	queue_t *q = dsp->ds_wq;
	mac_perim_handle_t	mph;

	if (dsp->ds_mh == NULL) {
		dsp->ds_mode = DLD_RAW;
		miocack(q, mp, 0, 0);
		return;
	}

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);
	if (dsp->ds_polling || dsp->ds_direct) {
		mac_perim_exit(mph);
		miocnak(q, mp, 0, EPROTO);
		return;
	}

	if (dsp->ds_mode != DLD_RAW && dsp->ds_dlstate == DL_IDLE) {
		/*
		 * Set the receive callback.
		 */
		dls_rx_set(dsp, dld_str_rx_raw, dsp);
	}

	/*
	 * Note that raw mode is enabled.
	 */
	dsp->ds_mode = DLD_RAW;
	mac_perim_exit(mph);

	miocack(q, mp, 0, 0);
}

/*
 * DLIOCHDRINFO
 */
static void
ioc_fast(dld_str_t *dsp, mblk_t *mp)
{
	dl_unitdata_req_t *dlp;
	off_t		off;
	size_t		len;
	const uint8_t	*addr;
	uint16_t	sap;
	mblk_t		*nmp;
	mblk_t		*hmp;
	uint_t		addr_length;
	queue_t		*q = dsp->ds_wq;
	int		err;
	mac_perim_handle_t	mph;

	if (dld_opt & DLD_OPT_NO_FASTPATH) {
		err = ENOTSUP;
		goto failed;
	}

	/*
	 * DLIOCHDRINFO should only come from IP. The one initiated from
	 * user-land should not be allowed.
	 */
	if (((struct iocblk *)mp->b_rptr)->ioc_cr != kcred) {
		err = EINVAL;
		goto failed;
	}

	nmp = mp->b_cont;
	if (nmp == NULL || MBLKL(nmp) < sizeof (dl_unitdata_req_t) ||
	    (dlp = (dl_unitdata_req_t *)nmp->b_rptr,
	    dlp->dl_primitive != DL_UNITDATA_REQ)) {
		err = EINVAL;
		goto failed;
	}

	off = dlp->dl_dest_addr_offset;
	len = dlp->dl_dest_addr_length;

	if (!MBLKIN(nmp, off, len)) {
		err = EINVAL;
		goto failed;
	}

	if (dsp->ds_dlstate != DL_IDLE) {
		err = ENOTSUP;
		goto failed;
	}

	addr_length = dsp->ds_mip->mi_addr_length;
	if (len != addr_length + sizeof (uint16_t)) {
		err = EINVAL;
		goto failed;
	}

	addr = nmp->b_rptr + off;
	sap = *(uint16_t *)(nmp->b_rptr + off + addr_length);

	if ((hmp = dls_header(dsp, addr, sap, 0, NULL)) == NULL) {
		err = ENOMEM;
		goto failed;
	}

	/*
	 * This ioctl might happen concurrently with a direct call to dld_capab
	 * that tries to enable direct and/or poll capabilities. Since the
	 * stack does not serialize them, we do so here to avoid mixing
	 * the callbacks.
	 */
	mac_perim_enter_by_mh(dsp->ds_mh, &mph);
	if (dsp->ds_mode != DLD_FASTPATH) {
		/*
		 * Set the receive callback (unless polling is enabled).
		 */
		if (!dsp->ds_polling && !dsp->ds_direct)
			dls_rx_set(dsp, dld_str_rx_fastpath, dsp);

		/*
		 * Note that fast-path mode is enabled.
		 */
		dsp->ds_mode = DLD_FASTPATH;
	}
	mac_perim_exit(mph);

	freemsg(nmp->b_cont);
	nmp->b_cont = hmp;

	miocack(q, mp, MBLKL(nmp) + MBLKL(hmp), 0);
	return;
failed:
	miocnak(q, mp, 0, err);
}

/*
 * DLIOCLOWLINK: request actual link state changes. When the
 * link is part of a bridge instance the client receives actual
 * link state changes and not the aggregate link status. Used by
 * the bridging daemon (bridged) for proper RSTP operation.
 */
static void
ioc_lowlink(dld_str_t *dsp, mblk_t *mp)
{
	queue_t *q = dsp->ds_wq;
	int err;

	if ((err = miocpullup(mp, sizeof (int))) != 0) {
		miocnak(q, mp, 0, err);
	} else {
		/* LINTED: alignment */
		dsp->ds_lowlink = *(boolean_t *)mp->b_cont->b_rptr;
		miocack(q, mp, 0, 0);
	}
}

/*
 * Catch-all handler.
 */
static void
ioc(dld_str_t *dsp, mblk_t *mp)
{
	queue_t	*q = dsp->ds_wq;

	if (dsp->ds_dlstate == DL_UNATTACHED) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}
	mac_ioctl(dsp->ds_mh, q, mp);
}
