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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Data-Link Driver
 */

#include	<sys/stropts.h>
#include	<sys/strsun.h>
#include	<sys/strsubr.h>
#include	<sys/atomic.h>
#include	<sys/disp.h>
#include	<sys/callb.h>
#include	<sys/vlan.h>
#include	<sys/dld.h>
#include	<sys/dld_impl.h>
#include	<sys/dls_impl.h>
#include	<inet/common.h>

static int	str_constructor(void *, void *, int);
static void	str_destructor(void *, void *);
static mblk_t	*str_unitdata_ind(dld_str_t *, mblk_t *, boolean_t);
static void	str_notify_promisc_on_phys(dld_str_t *);
static void	str_notify_promisc_off_phys(dld_str_t *);
static void	str_notify_phys_addr(dld_str_t *, const uint8_t *);
static void	str_notify_link_up(dld_str_t *);
static void	str_notify_link_down(dld_str_t *);
static void	str_notify_capab_reneg(dld_str_t *);
static void	str_notify_speed(dld_str_t *, uint32_t);
static void	str_notify(void *, mac_notify_type_t);

static void	ioc_native(dld_str_t *,  mblk_t *);
static void	ioc_margin(dld_str_t *, mblk_t *);
static void	ioc_raw(dld_str_t *, mblk_t *);
static void	ioc_fast(dld_str_t *,  mblk_t *);
static void	ioc(dld_str_t *, mblk_t *);
static void	dld_tx_enqueue(dld_str_t *, mblk_t *, mblk_t *, boolean_t,
		    uint_t, uint_t);
static void	dld_wput_nondata(dld_str_t *, mblk_t *);
static void	dld_wput_nondata_task(void *);
static void	dld_flush_nondata(dld_str_t *);
static mblk_t	*i_dld_ether_header_update_tag(mblk_t *, uint_t, uint16_t);
static mblk_t	*i_dld_ether_header_strip_tag(mblk_t *);

static uint32_t		str_count;
static kmem_cache_t	*str_cachep;
static taskq_t		*dld_disp_taskq = NULL;
static mod_hash_t	*str_hashp;

#define	STR_HASHSZ		64
#define	STR_HASH_KEY(key)	((mod_hash_key_t)(uintptr_t)(key))

static inline uint_t	mp_getsize(mblk_t *);

/*
 * Interval to count the TX queued depth. Default is 1s (1000000us).
 * Count the queue depth immediately (not by timeout) if this is set to 0.
 * See more details above dld_tx_enqueue().
 */
uint_t tx_qdepth_interval = 1000000;

/*
 * Some notes on entry points, flow-control, queueing and locking:
 *
 * This driver exports the traditional STREAMS put entry point as well as
 * the non-STREAMS fast-path transmit routine which is provided to IP via
 * the DL_CAPAB_POLL negotiation.  The put procedure handles all control
 * and data operations, while the fast-path routine deals only with M_DATA
 * fast-path packets.  Regardless of the entry point, all outbound packets
 * will end up in dld_tx_single(), where they will be delivered to the MAC
 * driver.
 *
 * The transmit logic operates in two modes: a "not busy" mode where the
 * packets will be delivered to the MAC for a send attempt, or "busy" mode
 * where they will be enqueued in the internal queue because of flow-control.
 * Flow-control happens when the MAC driver indicates the packets couldn't
 * be transmitted due to lack of resources (e.g. running out of descriptors).
 * In such case, the driver will place a dummy message on its write-side
 * STREAMS queue so that the queue is marked as "full".  Any subsequent
 * packets arriving at the driver will be enqueued in the internal queue,
 * which is drained in the context of the service thread that gets scheduled
 * whenever the driver is in the "busy" mode.  When all packets have been
 * successfully delivered by MAC and the internal queue is empty, it will
 * transition to the "not busy" mode by removing the dummy message from the
 * write-side STREAMS queue; in effect this will trigger backenabling.
 * The sizes of q_hiwat and q_lowat are set to 1 and 0, respectively, due
 * to the above reasons.
 *
 * The driver implements an internal transmit queue independent of STREAMS.
 * This allows for flexibility and provides a fast enqueue/dequeue mechanism
 * compared to the putq() and get() STREAMS interfaces.  The only putq() and
 * getq() operations done by the driver are those related to placing and
 * removing the dummy message to/from the write-side STREAMS queue for flow-
 * control purposes.
 *
 * Locking is done independent of STREAMS due to the driver being fully MT.
 * Threads entering the driver (either from put or service entry points)
 * will most likely be readers, with the exception of a few writer cases
 * such those handling DLPI attach/detach/bind/unbind/etc. or any of the
 * DLD-related ioctl requests.  The DLPI detach case is special, because
 * it involves freeing resources and therefore must be single-threaded.
 * Unfortunately the readers/writers lock can't be used to protect against
 * it, because the lock is dropped prior to the driver calling places where
 * putnext() may be invoked, and such places may depend on those resources
 * to exist.  Because of this, the driver always completes the DLPI detach
 * process when there are no other threads running in the driver.  This is
 * done by keeping track of the number of threads, such that the the last
 * thread leaving the driver will finish the pending DLPI detach operation.
 */

/*
 * dld_max_q_count is the queue depth threshold used to limit the number of
 * outstanding packets or bytes allowed in the queue; once this limit is
 * reached the driver will free any incoming ones until the queue depth
 * drops below the threshold.
 *
 * This buffering is provided to accomodate clients which do not employ
 * their own buffering scheme, and to handle occasional packet bursts.
 * Clients which handle their own buffering will receive positive feedback
 * from this driver as soon as it transitions into the "busy" state, i.e.
 * when the queue is initially filled up; they will get backenabled once
 * the queue is empty.
 *
 * The value chosen here is rather arbitrary; in future some intelligent
 * heuristics may be involved which could take into account the hardware's
 * transmit ring size, etc.
 */
uint_t dld_max_q_count = (16 * 1024 *1024);

/*
 * dld_finddevinfo() returns the dev_info_t * corresponding to a particular
 * dev_t. It searches str_hashp (a table of dld_str_t's) for streams that
 * match dev_t. If a stream is found and it is attached, its dev_info_t *
 * is returned.
 */
typedef struct i_dld_str_state_s {
	major_t		ds_major;
	minor_t		ds_minor;
	dev_info_t	*ds_dip;
} i_dld_str_state_t;

/* ARGSUSED */
static uint_t
i_dld_str_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	i_dld_str_state_t	*statep = arg;
	dld_str_t		*dsp = (dld_str_t *)val;

	if (statep->ds_major != dsp->ds_major)
		return (MH_WALK_CONTINUE);

	ASSERT(statep->ds_minor != 0);

	/*
	 * Access to ds_mh needs to be protected by ds_lock.
	 */
	rw_enter(&dsp->ds_lock, RW_READER);
	if (statep->ds_minor == dsp->ds_minor) {
		/*
		 * Clone: a clone minor is unique. we can terminate the
		 * walk if we find a matching stream -- even if we fail
		 * to obtain the devinfo.
		 */
		if (dsp->ds_mh != NULL)
			statep->ds_dip = mac_devinfo_get(dsp->ds_mh);
		rw_exit(&dsp->ds_lock);
		return (MH_WALK_TERMINATE);
	}
	rw_exit(&dsp->ds_lock);
	return (MH_WALK_CONTINUE);
}

static dev_info_t *
dld_finddevinfo(dev_t dev)
{
	dev_info_t	*dip;
	i_dld_str_state_t	state;

	if (getminor(dev) == 0)
		return (NULL);

	/*
	 * See if it's a minor node of a link
	 */
	if ((dip = dls_finddevinfo(dev)) != NULL)
		return (dip);

	state.ds_minor = getminor(dev);
	state.ds_major = getmajor(dev);
	state.ds_dip = NULL;

	mod_hash_walk(str_hashp, i_dld_str_walker, &state);
	return (state.ds_dip);
}

/*
 * devo_getinfo: getinfo(9e)
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

/*
 * qi_qopen: open(9e)
 */
/*ARGSUSED*/
int
dld_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	dld_str_t	*dsp;
	major_t		major;
	minor_t		minor;
	int		err;

	if (sflag == MODOPEN)
		return (ENOTSUP);

	/*
	 * This is a cloning driver and therefore each queue should only
	 * ever get opened once.
	 */
	if (rq->q_ptr != NULL)
		return (EBUSY);

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

/*
 * qi_qclose: close(9e)
 */
int
dld_close(queue_t *rq)
{
	dld_str_t	*dsp = rq->q_ptr;

	/*
	 * Disable the queue srv(9e) routine.
	 */
	qprocsoff(rq);

	dld_finish_pending_task(dsp);

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
 * qi_qputp: put(9e)
 */
void
dld_wput(queue_t *wq, mblk_t *mp)
{
	dld_str_t	*dsp = wq->q_ptr;

	switch (DB_TYPE(mp)) {
	case M_DATA: {
		dld_tx_t tx;

		DLD_TX_ENTER(dsp);
		if ((tx = dsp->ds_tx) != NULL)
			tx(dsp, mp);
		else
			freemsg(mp);
		DLD_TX_EXIT(dsp);
		break;
	}
	case M_PROTO:
	case M_PCPROTO: {
		t_uscalar_t	prim;
		dld_tx_t	tx;

		if (MBLKL(mp) < sizeof (t_uscalar_t)) {
			freemsg(mp);
			return;
		}

		prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;
		if (prim != DL_UNITDATA_REQ) {
			/* Control path */
			dld_wput_nondata(dsp, mp);
			break;
		}

		/* Data path */
		DLD_TX_ENTER(dsp);
		if ((tx = dsp->ds_unitdata_tx) != NULL)
			tx(dsp, mp);
		else
			dlerrorack(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		DLD_TX_EXIT(dsp);
		break;
	}
	case M_IOCTL:
	case M_IOCDATA:
		/* Control path */
		dld_wput_nondata(dsp, mp);
		break;
	case M_FLUSH:
		/*
		 * Flush both the data messages and the control messages.
		 */
		if (*mp->b_rptr & FLUSHW) {
			dld_flush_nondata(dsp);
			dld_tx_flush(dsp);
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
 * Called by GLDv3 control node to process the ioctls. It will start
 * a taskq to allow the ioctl processing to block. This is a temporary
 * solution, and will be replaced by a more graceful approach afterwards.
 */
void
dld_ioctl(queue_t *wq, mblk_t *mp)
{
	dld_wput_nondata(wq->q_ptr, mp);
}

/*
 * qi_srvp: srv(9e)
 */
void
dld_wsrv(queue_t *wq)
{
	mblk_t		*mp, *head, *tail;
	dld_str_t	*dsp = wq->q_ptr;
	uint_t		cnt, msgcnt;
	timeout_id_t	tid = 0;

	rw_enter(&dsp->ds_lock, RW_READER);
	/*
	 * Grab all packets (chained via b_next) off our transmit queue
	 * and try to send them all to the MAC layer.  Since the queue
	 * is independent of streams, we are able to dequeue all messages
	 * at once without looping through getq() and manually chaining
	 * them.  Note that the queue size parameters (byte and message
	 * counts) are cleared as well, but we postpone the backenabling
	 * until after the MAC transmit since some packets may end up
	 * back at our transmit queue.
	 */
	mutex_enter(&dsp->ds_tx_list_lock);
	if ((mp = dsp->ds_tx_list_head) == NULL) {
		ASSERT(!dsp->ds_tx_qbusy);
		ASSERT(dsp->ds_tx_flow_mp != NULL);
		ASSERT(dsp->ds_tx_list_head == NULL);
		ASSERT(dsp->ds_tx_list_tail == NULL);
		ASSERT(dsp->ds_tx_cnt == 0);
		ASSERT(dsp->ds_tx_msgcnt == 0);
		mutex_exit(&dsp->ds_tx_list_lock);
		rw_exit(&dsp->ds_lock);
		return;
	}
	head = mp;
	tail = dsp->ds_tx_list_tail;
	dsp->ds_tx_list_head = dsp->ds_tx_list_tail = NULL;
	cnt = dsp->ds_tx_cnt;
	msgcnt = dsp->ds_tx_msgcnt;
	dsp->ds_tx_cnt = dsp->ds_tx_msgcnt = 0;
	mutex_exit(&dsp->ds_tx_list_lock);

	/*
	 * Discard packets unless we are attached and bound; note that
	 * the driver mode (fastpath/raw/unitdata) is irrelevant here,
	 * because regardless of the mode all transmit will end up in
	 * dld_tx_single() where the packets may be queued.
	 */
	ASSERT((DB_TYPE(mp) == M_DATA) || (DB_TYPE(mp) == M_MULTIDATA));
	if (dsp->ds_dlstate != DL_IDLE) {
		freemsgchain(mp);
		goto done;
	}

	/*
	 * Attempt to transmit one or more packets.  If the MAC can't
	 * send them all, re-queue the packet(s) at the beginning of
	 * the transmit queue to avoid any re-ordering.
	 */
	mp = dls_tx(dsp->ds_dc, mp);
	if (mp == head) {
		/*
		 * No message was sent out. Take the saved the queue depth
		 * as the input, so that dld_tx_enqueue() need not to
		 * calculate it again.
		 */
		dld_tx_enqueue(dsp, mp, tail, B_TRUE, msgcnt, cnt);
	} else if (mp != NULL) {
		/*
		 * Some but not all messages were sent out. dld_tx_enqueue()
		 * needs to start the timer to calculate the queue depth if
		 * timer has not been started.
		 *
		 * Note that a timer is used to calculate the queue depth
		 * to improve network performance, especially for TCP, in
		 * which case packets are sent without canput() being checked,
		 * and mostly end up in dld_tx_enqueue() under heavy load.
		 */
		dld_tx_enqueue(dsp, mp, tail, B_TRUE, 0, 0);
	}

done:
	/*
	 * Grab the list lock again and check if the transmit queue is
	 * really empty; if so, lift up flow-control and backenable any
	 * writer queues.  If the queue is not empty, schedule service
	 * thread to drain it.
	 */
	mutex_enter(&dsp->ds_tx_list_lock);
	if (dsp->ds_tx_list_head == NULL) {
		dsp->ds_tx_flow_mp = getq(wq);
		ASSERT(dsp->ds_tx_flow_mp != NULL);
		dsp->ds_tx_qbusy = B_FALSE;
		if ((tid = dsp->ds_tx_qdepth_tid) != 0)
			dsp->ds_tx_qdepth_tid = 0;
	}
	mutex_exit(&dsp->ds_tx_list_lock);

	/*
	 * Note that ds_tx_list_lock (which is acquired by the timeout
	 * callback routine) cannot be held across the call to untimeout().
	 */
	if (tid != 0)
		(void) untimeout(tid);

	rw_exit(&dsp->ds_lock);
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
	 * Create taskq to process DLPI requests.
	 */
	dld_disp_taskq = taskq_create("dld_disp_taskq", 1024, MINCLSYSPRI, 2,
	    INT_MAX, TASKQ_DYNAMIC | TASKQ_PREPOPULATE);

	/*
	 * Create a hash table for maintaining dld_str_t's.
	 * The ds_minor field (the clone minor number) of a dld_str_t
	 * is used as a key for this hash table because this number is
	 * globally unique (allocated from "dls_minor_arena").
	 */
	str_hashp = mod_hash_create_idhash("dld_str_hash", STR_HASHSZ,
	    mod_hash_null_valdtor);
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

	ASSERT(dld_disp_taskq != NULL);
	taskq_destroy(dld_disp_taskq);
	dld_disp_taskq = NULL;

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
	atomic_add_32(&str_count, 1);
	dsp = kmem_cache_alloc(str_cachep, KM_SLEEP);

	/*
	 * Allocate the dummy mblk for flow-control.
	 */
	dsp->ds_tx_flow_mp = allocb(1, BPRI_HI);
	if (dsp->ds_tx_flow_mp == NULL) {
		kmem_cache_free(str_cachep, dsp);
		atomic_add_32(&str_count, -1);
		return (NULL);
	}
	dsp->ds_type = type;
	dsp->ds_major = major;
	dsp->ds_style = style;
	dsp->ds_tx = dsp->ds_unitdata_tx = NULL;

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

void
dld_finish_pending_task(dld_str_t *dsp)
{
	/*
	 * Wait until the pending requests are processed by the worker thread.
	 */
	mutex_enter(&dsp->ds_disp_lock);
	dsp->ds_closing = B_TRUE;
	while (dsp->ds_tid != NULL)
		cv_wait(&dsp->ds_disp_cv, &dsp->ds_disp_lock);
	dsp->ds_closing = B_FALSE;
	mutex_exit(&dsp->ds_disp_lock);
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

	ASSERT(!RW_LOCK_HELD(&dsp->ds_lock));
	ASSERT(MUTEX_NOT_HELD(&dsp->ds_tx_list_lock));
	ASSERT(dsp->ds_tx_list_head == NULL);
	ASSERT(dsp->ds_tx_list_tail == NULL);
	ASSERT(dsp->ds_tx_cnt == 0);
	ASSERT(dsp->ds_tx_msgcnt == 0);
	ASSERT(dsp->ds_tx_qdepth_tid == 0);
	ASSERT(!dsp->ds_tx_qbusy);

	ASSERT(MUTEX_NOT_HELD(&dsp->ds_disp_lock));
	ASSERT(dsp->ds_pending_head == NULL);
	ASSERT(dsp->ds_pending_tail == NULL);
	ASSERT(dsp->ds_tx == NULL);
	ASSERT(dsp->ds_unitdata_tx == NULL);

	/*
	 * Reinitialize all the flags.
	 */
	dsp->ds_notifications = 0;
	dsp->ds_passivestate = DLD_UNINITIALIZED;
	dsp->ds_mode = DLD_UNITDATA;
	dsp->ds_native = B_FALSE;

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
	atomic_add_32(&str_count, -1);
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

	rw_init(&dsp->ds_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&dsp->ds_tx_list_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dsp->ds_disp_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dsp->ds_disp_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&dsp->ds_tx_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dsp->ds_tx_cv, NULL, CV_DRIVER, NULL);

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
	 * Make sure the DLPI state machine was reset.
	 */
	ASSERT(dsp->ds_dlstate == DL_UNATTACHED);

	/*
	 * Make sure the data-link interface was closed.
	 */
	ASSERT(dsp->ds_mh == NULL);
	ASSERT(dsp->ds_dc == NULL);
	ASSERT(dsp->ds_tx == NULL);
	ASSERT(dsp->ds_unitdata_tx == NULL);
	ASSERT(dsp->ds_intx_cnt == 0);
	ASSERT(dsp->ds_detaching == B_FALSE);

	/*
	 * Make sure enabled notifications are cleared.
	 */
	ASSERT(dsp->ds_notifications == 0);

	/*
	 * Make sure polling is disabled.
	 */
	ASSERT(!dsp->ds_polling);

	/*
	 * Release the minor number.
	 */
	mac_minor_rele(dsp->ds_minor);

	ASSERT(!RW_LOCK_HELD(&dsp->ds_lock));
	rw_destroy(&dsp->ds_lock);

	ASSERT(MUTEX_NOT_HELD(&dsp->ds_tx_list_lock));
	mutex_destroy(&dsp->ds_tx_list_lock);
	ASSERT(dsp->ds_tx_flow_mp == NULL);
	ASSERT(dsp->ds_pending_head == NULL);
	ASSERT(dsp->ds_pending_tail == NULL);
	ASSERT(!dsp->ds_closing);

	ASSERT(MUTEX_NOT_HELD(&dsp->ds_disp_lock));
	mutex_destroy(&dsp->ds_disp_lock);
	cv_destroy(&dsp->ds_disp_cv);

	ASSERT(MUTEX_NOT_HELD(&dsp->ds_tx_lock));
	mutex_destroy(&dsp->ds_tx_lock);
	cv_destroy(&dsp->ds_tx_cv);
}

void
dld_tx_single(dld_str_t *dsp, mblk_t *mp)
{
	/*
	 * If we are busy enqueue the packet and return.
	 * Otherwise hand them over to the MAC driver for transmission.
	 * If the message didn't get sent it will be queued.
	 *
	 * Note here that we don't grab the list lock prior to checking
	 * the busy flag.  This is okay, because a missed transition
	 * will not cause any packet reordering for any particular TCP
	 * connection (which is single-threaded).  The enqueue routine
	 * will atomically set the busy flag and schedule the service
	 * thread to run; the flag is only cleared by the service thread
	 * when there is no more packet to be transmitted.
	 */

	if (dsp->ds_tx_qbusy || ((mp = dls_tx(dsp->ds_dc, mp)) != NULL))
		dld_tx_enqueue(dsp, mp, mp, B_FALSE, 1, mp_getsize(mp));
}

/*
 * Update the priority bits and VID (may need to insert tag if mp points
 * to an untagged packet).
 * If vid is VLAN_ID_NONE, use the VID encoded in the packet.
 */
static mblk_t *
i_dld_ether_header_update_tag(mblk_t *mp, uint_t pri, uint16_t vid)
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
		old_tci = ntohs(evhp->ether_tci);
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
	} else {
		/*
		 * Untagged packet. Insert the special priority tag.
		 * First allocate a header mblk.
		 */
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

/*
 * M_DATA put
 *
 * The poll callback function for DLS clients which are not in the per-stream
 * mode. This function is called from an upper layer protocol (currently only
 * tcp and udp).
 */
void
str_mdata_fastpath_put(dld_str_t *dsp, mblk_t *mp)
{
	boolean_t is_ethernet = (dsp->ds_mip->mi_media == DL_ETHER);
	mblk_t *newmp;
	uint_t pri;

	if (is_ethernet) {
		/*
		 * Update the priority bits to the assigned priority.
		 */
		pri = (VLAN_MBLKPRI(mp) == 0) ? dsp->ds_pri : VLAN_MBLKPRI(mp);

		if (pri != 0) {
			newmp = i_dld_ether_header_update_tag(mp, pri,
			    VLAN_ID_NONE);
			if (newmp == NULL)
				goto discard;
			mp = newmp;
		}
	}

	dld_tx_single(dsp, mp);
	return;

discard:
	/* TODO: bump kstat? */
	freemsg(mp);
}

/*
 * M_DATA put (DLIOCRAW mode).
 */
void
str_mdata_raw_put(dld_str_t *dsp, mblk_t *mp)
{
	boolean_t is_ethernet = (dsp->ds_mip->mi_media == DL_ETHER);
	mblk_t *bp, *newmp;
	size_t size;
	mac_header_info_t mhi;
	uint_t pri, vid;
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

	if (dls_header_info(dsp->ds_dc, mp, &mhi) != 0)
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
		/*
		 * Discard the packet if this is a VLAN stream but the VID in
		 * the packet is not correct.
		 */
		vid = VLAN_ID(mhi.mhi_tci);
		if ((dsp->ds_vid != VLAN_ID_NONE) && (vid != VLAN_ID_NONE))
			goto discard;

		/*
		 * Discard the packet if this packet is a tagged packet
		 * but both pri and VID are 0.
		 */
		pri = VLAN_PRI(mhi.mhi_tci);
		if (mhi.mhi_istagged && (pri == 0) && (vid == VLAN_ID_NONE))
			goto discard;

		/*
		 * Update the priority bits to the per-stream priority if
		 * priority is not set in the packet. Update the VID for
		 * packets on a VLAN stream.
		 */
		pri = (pri == 0) ? dsp->ds_pri : 0;
		if ((pri != 0) || (dsp->ds_vid != VLAN_ID_NONE)) {
			if ((newmp = i_dld_ether_header_update_tag(mp,
			    pri, dsp->ds_vid)) == NULL) {
				goto discard;
			}
			mp = newmp;
		}
	}

	dld_tx_single(dsp, mp);
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
	dev_t				dev;
	int				err;
	const char			*drvname;
	dls_channel_t			dc;
	uint_t				addr_length;
	boolean_t			qassociated = B_FALSE;

	ASSERT(dsp->ds_dc == NULL);

	if ((drvname = ddi_major_to_name(dsp->ds_major)) == NULL)
		return (EINVAL);

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

	/*
	 * Open a channel.
	 */
	if (dsp->ds_style == DL_STYLE2 && ppa > DLS_MAX_PPA) {
		/*
		 * style-2 VLAN open, this is a /dev VLAN ppa open
		 * which might result in a newly created dls_vlan_t.
		 */
		err = dls_open_style2_vlan(dsp->ds_major, ppa, &dc);
		if (err != 0) {
			if (qassociated)
				(void) qassociate(dsp->ds_wq, -1);
			return (err);
		}
	} else {
		dev = makedevice(dsp->ds_major, (minor_t)ppa + 1);
		if ((err = dls_open_by_dev(dev, &dc)) != 0) {
			if (qassociated)
				(void) qassociate(dsp->ds_wq, -1);
			return (err);
		}
	}

	/*
	 * Cache the MAC interface handle, a pointer to the immutable MAC
	 * information and the current and 'factory' MAC address.
	 */
	dsp->ds_mh = dls_mac(dc);
	dsp->ds_mip = mac_info(dsp->ds_mh);

	mac_unicst_get(dsp->ds_mh, dsp->ds_curr_addr);

	addr_length = dsp->ds_mip->mi_addr_length;
	bcopy(dsp->ds_mip->mi_unicst_addr, dsp->ds_fact_addr, addr_length);

	/*
	 * Cache the interface VLAN identifier. (This will be VLAN_ID_NONE for
	 * a non-VLAN interface).
	 */
	dsp->ds_vid = dls_vid(dc);

	/*
	 * Set the default packet priority.
	 */
	dsp->ds_pri = 0;

	/*
	 * Add a notify function so that the we get updates from the MAC.
	 */
	dsp->ds_mnh = mac_notify_add(dsp->ds_mh, str_notify, (void *)dsp);

	dsp->ds_dc = dc;
	dsp->ds_dlstate = DL_UNBOUND;

	return (0);
}

/*
 * Process DL_DETACH_REQ (style 2) or close(2) (style 1). Can also be called
 * from close(2) for style 2.
 */
void
dld_str_detach(dld_str_t *dsp)
{
	/*
	 * Remove the notify function.
	 */
	mac_notify_remove(dsp->ds_mh, dsp->ds_mnh);

	/*
	 * Disable the capabilities and clear the promisc flag.
	 */
	ASSERT(!dsp->ds_polling);
	ASSERT(!dsp->ds_soft_ring);
	dld_capabilities_disable(dsp);
	dsp->ds_promisc = 0;

	DLD_TX_QUIESCE(dsp);

	/*
	 * Flush all pending packets which are sitting in the transmit queue.
	 */
	dld_tx_flush(dsp);

	/*
	 * Clear LSO flags.
	 */
	dsp->ds_lso = B_FALSE;
	dsp->ds_lso_max = 0;

	dls_close(dsp->ds_dc);
	dsp->ds_dc = NULL;
	dsp->ds_mh = NULL;

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
i_dld_ether_header_strip_tag(mblk_t *mp)
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
	if (VLAN_PRI(tci) == 0) {
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
		if (is_ethernet && dsp->ds_vid != VLAN_ID_NONE) {
			newmp = i_dld_ether_header_strip_tag(mp);
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
	if (mhip->mhi_istagged && (dsp->ds_vid == VLAN_ID_NONE) &&
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
	if (mhip->mhi_istagged && (dsp->ds_vid == VLAN_ID_NONE) &&
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
str_notify_sdu_size(dld_str_t *dsp, uint_t max_sdu)
{
	mblk_t		*mp;
	dl_notify_ind_t *dlip;

	if (!(dsp->ds_notifications & DL_NOTE_SDU_SIZE))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_SDU_SIZE;
	dlip->dl_data = max_sdu;

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
	if (dls_header_info(dsp->ds_dc, mp, &mhi) != 0)
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
str_notify_phys_addr(dld_str_t *dsp, const uint8_t *addr)
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
	dlip->dl_data = DL_CURR_PHYS_ADDR;
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

/*
 * MAC notification callback.
 */
static void
str_notify(void *arg, mac_notify_type_t type)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	queue_t			*q = dsp->ds_wq;

	switch (type) {
	case MAC_NOTE_TX:
		qenable(q);
		break;

	case MAC_NOTE_DEVPROMISC:
		/*
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		if (mac_promisc_get(dsp->ds_mh, MAC_DEVPROMISC))
			str_notify_promisc_on_phys(dsp);
		else
			str_notify_promisc_off_phys(dsp);
		break;

	case MAC_NOTE_PROMISC:
		break;

	case MAC_NOTE_UNICST:
		/*
		 * This notification is sent whenever the MAC unicast address
		 * changes. We need to re-cache the address.
		 */
		mac_unicst_get(dsp->ds_mh, dsp->ds_curr_addr);

		/*
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		str_notify_phys_addr(dsp, dsp->ds_curr_addr);
		break;

	case MAC_NOTE_LINK:
		/*
		 * This notification is sent every time the MAC driver
		 * updates the link state.
		 */
		switch (mac_link_get(dsp->ds_mh)) {
		case LINK_STATE_UP: {
			uint64_t speed;
			/*
			 * The link is up so send the appropriate
			 * DL_NOTIFY_IND.
			 */
			str_notify_link_up(dsp);

			speed = mac_stat_get(dsp->ds_mh, MAC_STAT_IFSPEED);
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

	case MAC_NOTE_RESOURCE:
	case MAC_NOTE_VNIC:
		/*
		 * This notification is sent whenever the MAC resources
		 * change or capabilities change. We need to renegotiate
		 * the capabilities. Send the appropriate DL_NOTIFY_IND.
		 */
		str_notify_capab_reneg(dsp);
		break;

	case MAC_NOTE_SDU_SIZE: {
		uint_t  max_sdu;
		mac_sdu_get(dsp->ds_mh, NULL, &max_sdu);
		str_notify_sdu_size(dsp, max_sdu);
		break;
	}

	case MAC_NOTE_FASTPATH_FLUSH:
		str_notify_fastpath_flush(dsp);
		break;

	case MAC_NOTE_MARGIN:
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}
}

static inline uint_t
mp_getsize(mblk_t *mp)
{
	ASSERT(DB_TYPE(mp) == M_DATA);
	return ((mp->b_cont == NULL) ? MBLKL(mp) : msgdsize(mp));
}

/*
 * Calculate the dld queue depth, free the messages that exceed the threshold.
 */
static void
dld_tx_qdepth_timer(void *arg)
{
	dld_str_t *dsp = (dld_str_t *)arg;
	mblk_t *prev, *mp;
	uint_t cnt, msgcnt, size;

	mutex_enter(&dsp->ds_tx_list_lock);

	/* Calculate total size and count of the packet(s) */
	cnt = msgcnt = 0;
	for (prev = NULL, mp = dsp->ds_tx_list_head; mp != NULL;
	    prev = mp, mp = mp->b_next) {
		size = mp_getsize(mp);
		cnt += size;
		msgcnt++;
		if (cnt >= dld_max_q_count || msgcnt >= dld_max_q_count) {
			ASSERT(dsp->ds_tx_qbusy);
			dsp->ds_tx_list_tail = prev;
			if (prev == NULL)
				dsp->ds_tx_list_head = NULL;
			else
				prev->b_next = NULL;
			freemsgchain(mp);
			cnt -= size;
			msgcnt--;
			break;
		}
	}
	dsp->ds_tx_cnt = cnt;
	dsp->ds_tx_msgcnt = msgcnt;
	dsp->ds_tx_qdepth_tid = 0;
	mutex_exit(&dsp->ds_tx_list_lock);
}

/*
 * Enqueue one or more messages on the transmit queue. Caller specifies:
 *  - the insertion position (head/tail).
 *  - the message count and the total message size of messages to be queued
 *    if they are known to the caller; or 0 if they are not known.
 *
 * If the caller does not know the message size information, this usually
 * means that dld_wsrv() managed to send some but not all of the queued
 * messages. For performance reasons, we do not calculate the queue depth
 * every time. Instead, a timer is started to calculate the queue depth
 * every 1 second (can be changed by tx_qdepth_interval).
 */
static void
dld_tx_enqueue(dld_str_t *dsp, mblk_t *mp, mblk_t *tail, boolean_t head_insert,
    uint_t msgcnt, uint_t cnt)
{
	queue_t *q = dsp->ds_wq;
	uint_t tot_cnt, tot_msgcnt;
	mblk_t *next;

	mutex_enter(&dsp->ds_tx_list_lock);

	/*
	 * Simply enqueue the message and calculate the queue depth via
	 * timer if:
	 *
	 * - the current queue depth is incorrect, and the timer is already
	 *   started; or
	 *
	 * - the given message size is unknown and it is allowed to start the
	 *   timer;
	 */
	if ((dsp->ds_tx_qdepth_tid != 0) ||
	    (msgcnt == 0 && tx_qdepth_interval != 0)) {
		goto enqueue;
	}

	/*
	 * The timer is not allowed, so calculate the message size now.
	 */
	if (msgcnt == 0) {
		for (next = mp; next != NULL; next = next->b_next) {
			cnt += mp_getsize(next);
			msgcnt++;
		}
	}

	/*
	 * Grow the queue depth using the input messesge size.
	 *
	 * If the queue depth would exceed the allowed threshold, drop
	 * new packet(s) and drain those already in the queue.
	 */
	tot_cnt = dsp->ds_tx_cnt + cnt;
	tot_msgcnt = dsp->ds_tx_msgcnt + msgcnt;

	if (!head_insert && (tot_cnt >= dld_max_q_count ||
	    tot_msgcnt >= dld_max_q_count)) {
		ASSERT(dsp->ds_tx_qbusy);
		mutex_exit(&dsp->ds_tx_list_lock);
		freemsgchain(mp);
		goto done;
	}
	/* Update the queue size parameters */
	dsp->ds_tx_cnt = tot_cnt;
	dsp->ds_tx_msgcnt = tot_msgcnt;

enqueue:
	/*
	 * If the transmit queue is currently empty and we are
	 * about to deposit the packet(s) there, switch mode to
	 * "busy" and raise flow-control condition.
	 */
	if (!dsp->ds_tx_qbusy) {
		dsp->ds_tx_qbusy = B_TRUE;
		ASSERT(dsp->ds_tx_flow_mp != NULL);
		(void) putq(q, dsp->ds_tx_flow_mp);
		dsp->ds_tx_flow_mp = NULL;
	}

	if (!head_insert) {
		/* Tail insertion */
		if (dsp->ds_tx_list_head == NULL)
			dsp->ds_tx_list_head = mp;
		else
			dsp->ds_tx_list_tail->b_next = mp;
		dsp->ds_tx_list_tail = tail;
	} else {
		/* Head insertion */
		tail->b_next = dsp->ds_tx_list_head;
		if (dsp->ds_tx_list_head == NULL)
			dsp->ds_tx_list_tail = tail;
		dsp->ds_tx_list_head = mp;
	}

	if (msgcnt == 0 && dsp->ds_tx_qdepth_tid == 0 &&
	    tx_qdepth_interval != 0) {
		/*
		 * The message size is not given so that we need to start
		 * the timer to calculate the queue depth.
		 */
		dsp->ds_tx_qdepth_tid = timeout(dld_tx_qdepth_timer, dsp,
		    drv_usectohz(tx_qdepth_interval));
		ASSERT(dsp->ds_tx_qdepth_tid != NULL);
	}
	mutex_exit(&dsp->ds_tx_list_lock);
done:
	/* Schedule service thread to drain the transmit queue */
	if (!head_insert)
		qenable(q);
}

void
dld_tx_flush(dld_str_t *dsp)
{
	timeout_id_t	tid = 0;

	mutex_enter(&dsp->ds_tx_list_lock);
	if (dsp->ds_tx_list_head != NULL) {
		freemsgchain(dsp->ds_tx_list_head);
		dsp->ds_tx_list_head = dsp->ds_tx_list_tail = NULL;
		dsp->ds_tx_cnt = dsp->ds_tx_msgcnt = 0;
		if (dsp->ds_tx_qbusy) {
			dsp->ds_tx_flow_mp = getq(dsp->ds_wq);
			ASSERT(dsp->ds_tx_flow_mp != NULL);
			dsp->ds_tx_qbusy = B_FALSE;
		}
		if ((tid = dsp->ds_tx_qdepth_tid) != 0)
			dsp->ds_tx_qdepth_tid = 0;
	}
	mutex_exit(&dsp->ds_tx_list_lock);

	/*
	 * Note that ds_tx_list_lock (which is acquired by the timeout
	 * callback routine) cannot be held across the call to untimeout().
	 */
	if (tid != 0)
		(void) untimeout(tid);
}

/*
 * Process a non-data message.
 */
static void
dld_wput_nondata(dld_str_t *dsp, mblk_t *mp)
{
	ASSERT((dsp->ds_type == DLD_DLPI && dsp->ds_ioctl == NULL) ||
	    (dsp->ds_type == DLD_CONTROL && dsp->ds_ioctl != NULL));

	mutex_enter(&dsp->ds_disp_lock);

	/*
	 * The processing of the message might block. Enqueue the
	 * message for later processing.
	 */
	if (dsp->ds_pending_head == NULL) {
		dsp->ds_pending_head = dsp->ds_pending_tail = mp;
	} else {
		dsp->ds_pending_tail->b_next = mp;
		dsp->ds_pending_tail = mp;
	}

	/*
	 * If there is no task pending, kick off the task.
	 */
	if (dsp->ds_tid == NULL) {
		dsp->ds_tid = taskq_dispatch(dld_disp_taskq,
		    dld_wput_nondata_task, dsp, TQ_SLEEP);
		ASSERT(dsp->ds_tid != NULL);
	}
	mutex_exit(&dsp->ds_disp_lock);
}

/*
 * The worker thread which processes non-data messages. Note we only process
 * one message at one time in order to be able to "flush" the queued message
 * and serialize the processing.
 */
static void
dld_wput_nondata_task(void *arg)
{
	dld_str_t	*dsp = (dld_str_t *)arg;
	mblk_t		*mp;

	mutex_enter(&dsp->ds_disp_lock);
	ASSERT(dsp->ds_pending_head != NULL);
	ASSERT(dsp->ds_tid != NULL);

	if (dsp->ds_closing)
		goto closing;

	mp = dsp->ds_pending_head;
	if ((dsp->ds_pending_head = mp->b_next) == NULL)
		dsp->ds_pending_tail = NULL;
	mp->b_next = NULL;

	mutex_exit(&dsp->ds_disp_lock);

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO:
		ASSERT(dsp->ds_type == DLD_DLPI);
		dld_wput_proto_nondata(dsp, mp);
		break;
	case M_IOCTL: {
		uint_t cmd;

		if (dsp->ds_type == DLD_CONTROL) {
			ASSERT(dsp->ds_ioctl != NULL);
			dsp->ds_ioctl(dsp->ds_wq, mp);
			break;
		}

		cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;

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
		default:
			ioc(dsp, mp);
			break;
		}
		break;
	}
	case M_IOCDATA:
		ASSERT(dsp->ds_type == DLD_DLPI);
		ioc(dsp, mp);
		break;
	}

	mutex_enter(&dsp->ds_disp_lock);

	if (dsp->ds_closing)
		goto closing;

	if (dsp->ds_pending_head != NULL) {
		dsp->ds_tid = taskq_dispatch(dld_disp_taskq,
		    dld_wput_nondata_task, dsp, TQ_SLEEP);
		ASSERT(dsp->ds_tid != NULL);
	} else {
		dsp->ds_tid = NULL;
	}
	mutex_exit(&dsp->ds_disp_lock);
	return;

	/*
	 * If the stream is closing, flush all queued messages and inform
	 * the stream once it is done.
	 */
closing:
	freemsgchain(dsp->ds_pending_head);
	dsp->ds_pending_head = dsp->ds_pending_tail = NULL;
	dsp->ds_tid = NULL;
	cv_signal(&dsp->ds_disp_cv);
	mutex_exit(&dsp->ds_disp_lock);
}

/*
 * Flush queued non-data messages.
 */
static void
dld_flush_nondata(dld_str_t *dsp)
{
	mutex_enter(&dsp->ds_disp_lock);
	freemsgchain(dsp->ds_pending_head);
	dsp->ds_pending_head = dsp->ds_pending_tail = NULL;
	mutex_exit(&dsp->ds_disp_lock);
}

/*
 * DLIOCNATIVE
 */
static void
ioc_native(dld_str_t *dsp, mblk_t *mp)
{
	queue_t *q = dsp->ds_wq;
	const mac_info_t *mip = dsp->ds_mip;

	rw_enter(&dsp->ds_lock, RW_WRITER);

	/*
	 * Native mode can be enabled if it's disabled and if the
	 * native media type is different.
	 */
	if (!dsp->ds_native && mip->mi_media != mip->mi_nativemedia)
		dsp->ds_native = B_TRUE;

	rw_exit(&dsp->ds_lock);

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

	if (dsp->ds_polling || dsp->ds_soft_ring) {
		miocnak(q, mp, 0, EPROTO);
		return;
	}

	rw_enter(&dsp->ds_lock, RW_WRITER);
	if ((dsp->ds_mode != DLD_RAW) && (dsp->ds_dlstate == DL_IDLE)) {
		/*
		 * Set the receive callback.
		 */
		dls_rx_set(dsp->ds_dc, dld_str_rx_raw, dsp);
		dsp->ds_tx = str_mdata_raw_put;
	}
	dsp->ds_mode = DLD_RAW;
	rw_exit(&dsp->ds_lock);
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

	/*
	 * We don't need to hold any locks to access ds_dlstate, because
	 * control message prossessing (which updates this field) is
	 * serialized.
	 */
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

	if ((hmp = dls_header(dsp->ds_dc, addr, sap, 0, NULL)) == NULL) {
		err = ENOMEM;
		goto failed;
	}

	rw_enter(&dsp->ds_lock, RW_WRITER);
	ASSERT(dsp->ds_dlstate == DL_IDLE);
	if (dsp->ds_mode != DLD_FASTPATH) {
		/*
		 * Set the receive callback (unless polling or
		 * soft-ring is enabled).
		 */
		dsp->ds_mode = DLD_FASTPATH;
		if (!dsp->ds_polling && !dsp->ds_soft_ring)
			dls_rx_set(dsp->ds_dc, dld_str_rx_fastpath, dsp);
		dsp->ds_tx = str_mdata_fastpath_put;
	}
	rw_exit(&dsp->ds_lock);

	freemsg(nmp->b_cont);
	nmp->b_cont = hmp;

	miocack(q, mp, MBLKL(nmp) + MBLKL(hmp), 0);
	return;
failed:
	miocnak(q, mp, 0, err);
}

static void
ioc(dld_str_t *dsp, mblk_t *mp)
{
	queue_t	*q = dsp->ds_wq;
	mac_handle_t mh;

	if (dsp->ds_dlstate == DL_UNATTACHED) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}
	mh = dsp->ds_mh;
	ASSERT(mh != NULL);
	mac_ioctl(mh, q, mp);
}
