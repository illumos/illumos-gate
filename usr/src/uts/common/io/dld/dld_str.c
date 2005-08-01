/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver
 */

#include	<sys/stropts.h>
#include	<sys/strsun.h>
#include	<sys/strsubr.h>
#include	<sys/atomic.h>
#include	<sys/mkdev.h>
#include	<sys/vlan.h>
#include	<sys/dld.h>
#include	<sys/dld_impl.h>
#include	<sys/dls_impl.h>
#include	<inet/common.h>

static int	str_constructor(void *, void *, int);
static void	str_destructor(void *, void *);
static mblk_t	*str_unitdata_ind(dld_str_t *, mblk_t *);
static void	str_notify_promisc_on_phys(dld_str_t *);
static void	str_notify_promisc_off_phys(dld_str_t *);
static void	str_notify_phys_addr(dld_str_t *, const uint8_t *);
static void	str_notify_link_up(dld_str_t *);
static void	str_notify_link_down(dld_str_t *);
static void	str_notify_capab_reneg(dld_str_t *);
static void	str_notify_speed(dld_str_t *, uint32_t);
static void	str_notify(void *, mac_notify_type_t);

static void	ioc_raw(dld_str_t *, mblk_t *);
static void	ioc_fast(dld_str_t *,  mblk_t *);
static void	ioc(dld_str_t *, mblk_t *);
static void	dld_ioc(dld_str_t *, mblk_t *);
static minor_t	dld_minor_hold(boolean_t);
static void	dld_minor_rele(minor_t);

static uint32_t		str_count;
static kmem_cache_t	*str_cachep;
static vmem_t		*minor_arenap;
static uint32_t		minor_count;

#define	MINOR_TO_PTR(minor)	((void *)(uintptr_t)(minor))
#define	PTR_TO_MINOR(ptr)	((minor_t)(uintptr_t)(ptr))

/*
 * Some notes on entry points, flow-control, queueing and locking:
 *
 * This driver exports the traditional STREAMS put entry point as well as
 * the non-STREAMS fast-path transmit routine which is provided to IP via
 * the DL_CAPAB_POLL negotiation.  The put procedure handles all control
 * and data operations, while the fast-path routine deals only with M_DATA
 * fast-path packets.  Regardless of the entry point, all outbound packets
 * will end up in str_mdata_fastpath_put(), where they will be delivered to
 * the MAC driver.
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

static dev_info_t *
dld_finddevinfo(dev_t dev)
{
	minor_t		minor = getminor(dev);
	char		*drvname = ddi_major_to_name(getmajor(dev));
	char		name[MAXNAMELEN];
	dls_vlan_t	*dvp = NULL;
	dev_info_t	*dip = NULL;

	if (drvname == NULL || minor == 0 || minor > DLD_MAX_PPA + 1)
		return (NULL);

	(void) snprintf(name, MAXNAMELEN, "%s%d", drvname, (int)minor - 1);
	if (dls_vlan_hold(name, &dvp, B_FALSE) != 0)
		return (NULL);

	dip = mac_devinfo_get(dvp->dv_dlp->dl_mh);
	dls_vlan_rele(dvp);
	return (dip);
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
		if (minor > 0 && minor <= DLD_MAX_PPA + 1) {
			*(int *)resp = (int)minor - 1;
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
	if (minor > DLD_MAX_MINOR)
		return (ENODEV);

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

	/*
	 * At this point we can not be entered by any threads via STREAMS
	 * or the direct call interface, which is available only to IP.
	 * After the interface is unplumbed, IP wouldn't have any reference
	 * to this instance, and therefore we are now effectively single
	 * threaded and don't require any lock protection.  Flush all
	 * pending packets which are sitting in the transmit queue.
	 */
	ASSERT(dsp->ds_thr == 0);
	dld_tx_flush(dsp);

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
	dld_str_t *dsp = (dld_str_t *)wq->q_ptr;

	DLD_ENTER(dsp);

	switch (DB_TYPE(mp)) {
	case M_DATA:
		rw_enter(&dsp->ds_lock, RW_READER);
		if (dsp->ds_dlstate != DL_IDLE ||
		    dsp->ds_mode == DLD_UNITDATA) {
			freemsg(mp);
		} else if (dsp->ds_mode == DLD_FASTPATH) {
			str_mdata_fastpath_put(dsp, mp);
		} else if (dsp->ds_mode == DLD_RAW) {
			str_mdata_raw_put(dsp, mp);
		}
		rw_exit(&dsp->ds_lock);
		break;
	case M_PROTO:
	case M_PCPROTO:
		dld_proto(dsp, mp);
		break;
	case M_IOCTL:
		dld_ioc(dsp, mp);
		break;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
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

	DLD_EXIT(dsp);
}

/*
 * qi_srvp: srv(9e)
 */
void
dld_wsrv(queue_t *wq)
{
	mblk_t		*mp;
	dld_str_t	*dsp = wq->q_ptr;

	DLD_ENTER(dsp);
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
		goto done;
	}
	dsp->ds_tx_list_head = dsp->ds_tx_list_tail = NULL;
	dsp->ds_tx_cnt = dsp->ds_tx_msgcnt = 0;
	mutex_exit(&dsp->ds_tx_list_lock);

	/*
	 * Discard packets unless we are attached and bound; note that
	 * the driver mode (fastpath/raw/unitdata) is irrelevant here,
	 * because regardless of the mode all transmit will end up in
	 * str_mdata_fastpath_put() where the packets may be queued.
	 */
	ASSERT(DB_TYPE(mp) == M_DATA);
	if (dsp->ds_dlstate != DL_IDLE) {
		freemsgchain(mp);
		goto done;
	}

	/*
	 * Attempt to transmit one or more packets.  If the MAC can't
	 * send them all, re-queue the packet(s) at the beginning of
	 * the transmit queue to avoid any re-ordering.
	 */
	if ((mp = dls_tx(dsp->ds_dc, mp)) != NULL)
		dld_tx_enqueue(dsp, mp, B_TRUE);

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
	}
	mutex_exit(&dsp->ds_tx_list_lock);
done:
	rw_exit(&dsp->ds_lock);
	DLD_EXIT(dsp);
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
	 * Allocate a vmem arena to manage minor numbers. The range of the
	 * arena will be from DLD_MAX_MINOR + 1 to MAXMIN (maximum legal
	 * minor number).
	 */
	minor_arenap = vmem_create("dld_minor_arena",
	    MINOR_TO_PTR(DLD_MAX_MINOR + 1), MAXMIN, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);
	ASSERT(minor_arenap != NULL);
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
	 * Check to see if there are any minor numbers still in use.
	 */
	if (minor_count != 0)
		return (EBUSY);

	/*
	 * Destroy object cache.
	 */
	kmem_cache_destroy(str_cachep);
	vmem_destroy(minor_arenap);
	return (0);
}

/*
 * Create a new dld_str_t object.
 */
dld_str_t *
dld_str_create(queue_t *rq, uint_t type, major_t major, t_uscalar_t style)
{
	dld_str_t	*dsp;

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
	ASSERT(!dsp->ds_tx_qbusy);

	ASSERT(MUTEX_NOT_HELD(&dsp->ds_thr_lock));
	ASSERT(dsp->ds_thr == 0);
	ASSERT(dsp->ds_detach_req == NULL);

	/*
	 * Reinitialize all the flags.
	 */
	dsp->ds_notifications = 0;
	dsp->ds_passivestate = DLD_UNINITIALIZED;
	dsp->ds_mode = DLD_UNITDATA;

	/*
	 * Free the dummy mblk if exists.
	 */
	if (dsp->ds_tx_flow_mp != NULL) {
		freeb(dsp->ds_tx_flow_mp);
		dsp->ds_tx_flow_mp = NULL;
	}
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
	if ((dsp->ds_minor = dld_minor_hold(kmflags == KM_SLEEP)) == 0)
		return (-1);

	/*
	 * Initialize the DLPI state machine.
	 */
	dsp->ds_dlstate = DL_UNATTACHED;

	mutex_init(&dsp->ds_thr_lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&dsp->ds_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&dsp->ds_tx_list_lock, NULL, MUTEX_DRIVER, NULL);

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
	dld_minor_rele(dsp->ds_minor);

	ASSERT(!RW_LOCK_HELD(&dsp->ds_lock));
	rw_destroy(&dsp->ds_lock);

	ASSERT(MUTEX_NOT_HELD(&dsp->ds_tx_list_lock));
	mutex_destroy(&dsp->ds_tx_list_lock);
	ASSERT(dsp->ds_tx_flow_mp == NULL);

	ASSERT(MUTEX_NOT_HELD(&dsp->ds_thr_lock));
	mutex_destroy(&dsp->ds_thr_lock);
	ASSERT(dsp->ds_detach_req == NULL);
}

/*
 * M_DATA put (IP fast-path mode)
 */
void
str_mdata_fastpath_put(dld_str_t *dsp, mblk_t *mp)
{
	/*
	 * We get here either as a result of putnext() from above or
	 * because IP has called us directly.  If we are in the busy
	 * mode enqueue the packet(s) and return.  Otherwise hand them
	 * over to the MAC driver for transmission; any remaining one(s)
	 * which didn't get sent will be queued.
	 *
	 * Note here that we don't grab the list lock prior to checking
	 * the busy flag.  This is okay, because a missed transition
	 * will not cause any packet reordering for any particular TCP
	 * connection (which is single-threaded).  The enqueue routine
	 * will atomically set the busy flag and schedule the service
	 * thread to run; the flag is only cleared by the service thread
	 * when there is no more packet to be transmitted.
	 */
	if (dsp->ds_tx_qbusy || (mp = dls_tx(dsp->ds_dc, mp)) != NULL)
		dld_tx_enqueue(dsp, mp, B_FALSE);
}

/*
 * M_DATA put (raw mode)
 */
void
str_mdata_raw_put(dld_str_t *dsp, mblk_t *mp)
{
	struct ether_header	*ehp;
	mblk_t			*bp;
	size_t			size;
	size_t			hdrlen;

	size = MBLKL(mp);
	if (size < sizeof (struct ether_header))
		goto discard;

	hdrlen = sizeof (struct ether_header);

	ehp = (struct ether_header *)mp->b_rptr;
	if (ntohs(ehp->ether_type) == VLAN_TPID) {
		struct ether_vlan_header	*evhp;

		if (size < sizeof (struct ether_vlan_header))
			goto discard;

		/*
		 * Replace vtag with our own
		 */
		evhp = (struct ether_vlan_header *)ehp;
		evhp->ether_tci = htons(VLAN_TCI(dsp->ds_pri,
		    ETHER_CFI, dsp->ds_vid));
		hdrlen = sizeof (struct ether_vlan_header);
	}

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

	if (size > dsp->ds_mip->mi_sdu_max + hdrlen)
		goto discard;

	str_mdata_fastpath_put(dsp, mp);
	return;

discard:
	freemsg(mp);
}

/*
 * Process DL_ATTACH_REQ (style 2) or open(2) (style 1).
 */
int
dld_str_attach(dld_str_t *dsp, t_uscalar_t ppa)
{
	int			err;
	const char		*drvname;
	char			name[MAXNAMELEN];
	dls_channel_t		dc;
	uint_t			addr_length;

	ASSERT(dsp->ds_dc == NULL);

	if ((drvname = ddi_major_to_name(dsp->ds_major)) == NULL)
		return (EINVAL);

	(void) snprintf(name, MAXNAMELEN, "%s%u", drvname, ppa);

	if (strcmp(drvname, "aggr") != 0 &&
	    qassociate(dsp->ds_wq, DLS_PPA2INST(ppa)) != 0)
		return (EINVAL);

	/*
	 * Open a channel.
	 */
	if ((err = dls_open(name, &dc)) != 0) {
		(void) qassociate(dsp->ds_wq, -1);
		return (err);
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
	ASSERT(dsp->ds_thr == 0);

	/*
	 * Remove the notify function.
	 */
	mac_notify_remove(dsp->ds_mh, dsp->ds_mnh);

	/*
	 * Re-initialize the DLPI state machine.
	 */
	dsp->ds_dlstate = DL_UNATTACHED;

	/*
	 * Clear the polling and promisc flags.
	 */
	dsp->ds_polling = B_FALSE;
	dsp->ds_promisc = 0;

	/*
	 * Close the channel.
	 */
	dls_close(dsp->ds_dc);
	dsp->ds_dc = NULL;
	dsp->ds_mh = NULL;

	(void) qassociate(dsp->ds_wq, -1);
}

/*
 * Raw mode receive function.
 */
/*ARGSUSED*/
void
dld_str_rx_raw(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    size_t header_length)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	mblk_t			*next;

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
		ASSERT(mp->b_rptr >= DB_BASE(mp) + header_length);
		mp->b_rptr -= header_length;
		if (header_length == sizeof (struct ether_vlan_header)) {
			/*
			 * Strip off the vtag
			 */
			ovbcopy(mp->b_rptr, mp->b_rptr + VLAN_TAGSZ,
			    2 * ETHERADDRL);
			mp->b_rptr += VLAN_TAGSZ;
		}

		/*
		 * Pass the packet on.
		 */
		putnext(dsp->ds_rq, mp);

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
    size_t header_length)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	mblk_t			*next;

	ASSERT(mp != NULL);
	do {
		/*
		 * Get the pointer to the next packet in the chain and then
		 * clear b_next before the packet gets passed on.
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Pass the packet on.
		 */
		putnext(dsp->ds_rq, mp);

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
    size_t header_length)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	mblk_t			*ud_mp;
	mblk_t			*next;

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
		ASSERT(mp->b_rptr >= DB_BASE(mp) + header_length);
		mp->b_rptr -= header_length;

		/*
		 * Create the DL_UNITDATA_IND M_PROTO.
		 */
		if ((ud_mp = str_unitdata_ind(dsp, mp)) == NULL) {
			freemsgchain(mp);
			return;
		}

		/*
		 * Advance b_rptr to point at the payload again.
		 */
		mp->b_rptr += header_length;

		/*
		 * Prepend the DL_UNITDATA_IND.
		 */
		ud_mp->b_cont = mp;

		/*
		 * Send the message.
		 */
		putnext(dsp->ds_rq, ud_mp);

		/*
		 * Move on to the next packet in the chain.
		 */
		mp = next;
	} while (mp != NULL);
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
	uint8_t			dl_dest_addr[MAXADDRLEN + sizeof (uint16_t)];
	uint8_t			dl_src_addr[MAXADDRLEN + sizeof (uint16_t)];
} dl_unitdata_ind_wrapper_t;

/*
 * Create a DL_UNITDATA_IND M_PROTO message.
 */
static mblk_t *
str_unitdata_ind(dld_str_t *dsp, mblk_t *mp)
{
	mblk_t				*nmp;
	dl_unitdata_ind_wrapper_t	*dlwp;
	dl_unitdata_ind_t		*dlp;
	dls_header_info_t		dhi;
	uint_t				addr_length;
	uint8_t				*daddr;
	uint8_t				*saddr;

	/*
	 * Get the packet header information.
	 */
	dls_header_info(dsp->ds_dc, mp, &dhi);

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
	bcopy(dhi.dhi_daddr, daddr, addr_length);

	/*
	 * Set the destination DLSAP to our bound DLSAP value.
	 */
	*(uint16_t *)(daddr + addr_length) = dsp->ds_sap;
	dlp->dl_dest_addr_length = addr_length + sizeof (uint16_t);

	/*
	 * If the destination address was a group address then
	 * dl_group_address field should be non-zero.
	 */
	dlp->dl_group_address = dhi.dhi_isgroup;

	/*
	 * Copy in the source address.
	 */
	saddr = dlwp->dl_src_addr;
	dlp->dl_src_addr_offset = (uintptr_t)saddr - (uintptr_t)dlp;
	bcopy(dhi.dhi_saddr, saddr, addr_length);

	/*
	 * Set the source DLSAP to the packet ethertype.
	 */
	*(uint16_t *)(saddr + addr_length) = dhi.dhi_ethertype;
	dlp->dl_src_addr_length = addr_length + sizeof (uint16_t);

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
	*(uint16_t *)((uchar_t *)(dlip + 1) + addr_length) =
		ethertype;

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
		case LINK_STATE_UP:
			/*
			 * The link is up so send the appropriate
			 * DL_NOTIFY_IND.
			 */
			str_notify_link_up(dsp);

			/*
			 * If we can find the link speed then send a
			 * DL_NOTIFY_IND for that too.
			 */
			if (dsp->ds_mip->mi_stat[MAC_STAT_IFSPEED]) {
				uint64_t	val;

				val = mac_stat_get(dsp->ds_mh,
				    MAC_STAT_IFSPEED);
				str_notify_speed(dsp,
				    (uint32_t)(val / 1000ull));
			}
			break;

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
		/*
		 * This notification is sent whenever the MAC resources
		 * change. We need to renegotiate the capabilities.
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		str_notify_capab_reneg(dsp);
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}
}

/*
 * Enqueue one or more messages to the transmit queue.
 * Caller specifies the insertion position (head/tail).
 */
void
dld_tx_enqueue(dld_str_t *dsp, mblk_t *mp, boolean_t head_insert)
{
	mblk_t	*tail;
	queue_t *q = dsp->ds_wq;
	uint_t	cnt, msgcnt;
	uint_t	tot_cnt, tot_msgcnt;

	ASSERT(DB_TYPE(mp) == M_DATA);
	/* Calculate total size and count of the packet(s) */
	for (tail = mp, cnt = msgdsize(mp), msgcnt = 1;
	    tail->b_next != NULL; tail = tail->b_next) {
		ASSERT(DB_TYPE(tail) == M_DATA);
		cnt += msgdsize(tail);
		msgcnt++;
	}

	mutex_enter(&dsp->ds_tx_list_lock);
	/*
	 * If the queue depth would exceed the allowed threshold, drop
	 * new packet(s) and drain those already in the queue.
	 */
	tot_cnt = dsp->ds_tx_cnt + cnt;
	tot_msgcnt = dsp->ds_tx_msgcnt + msgcnt;

	if (!head_insert &&
	    (tot_cnt >= dld_max_q_count || tot_msgcnt >= dld_max_q_count)) {
		ASSERT(dsp->ds_tx_qbusy);
		mutex_exit(&dsp->ds_tx_list_lock);
		freemsgchain(mp);
		goto done;
	}

	/* Update the queue size parameters */
	dsp->ds_tx_cnt = tot_cnt;
	dsp->ds_tx_msgcnt = tot_msgcnt;

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
	mutex_exit(&dsp->ds_tx_list_lock);
done:
	/* Schedule service thread to drain the transmit queue */
	qenable(q);
}

void
dld_tx_flush(dld_str_t *dsp)
{
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
	}
	mutex_exit(&dsp->ds_tx_list_lock);
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
	case DLIOCRAW:
		ioc_raw(dsp, mp);
		break;
	case DLIOCHDRINFO:
		ioc_fast(dsp, mp);
		break;
	default:
		ioc(dsp, mp);
	}
}

/*
 * DLIOCRAW
 */
static void
ioc_raw(dld_str_t *dsp, mblk_t *mp)
{
	queue_t *q = dsp->ds_wq;

	rw_enter(&dsp->ds_lock, RW_WRITER);
	if (dsp->ds_polling) {
		rw_exit(&dsp->ds_lock);
		miocnak(q, mp, 0, EPROTO);
		return;
	}

	if (dsp->ds_mode != DLD_RAW && dsp->ds_dlstate == DL_IDLE) {
		/*
		 * Set the receive callback.
		 */
		dls_rx_set(dsp->ds_dc, dld_str_rx_raw, (void *)dsp);

		/*
		 * Note that raw mode is enabled.
		 */
		dsp->ds_mode = DLD_RAW;
	}

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
	dls_channel_t	dc;

	if (dld_opt & DLD_OPT_NO_FASTPATH) {
		err = ENOTSUP;
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

	rw_enter(&dsp->ds_lock, RW_READER);
	if (dsp->ds_dlstate != DL_IDLE) {
		rw_exit(&dsp->ds_lock);
		err = ENOTSUP;
		goto failed;
	}

	addr_length = dsp->ds_mip->mi_addr_length;
	if (len != addr_length + sizeof (uint16_t)) {
		rw_exit(&dsp->ds_lock);
		err = EINVAL;
		goto failed;
	}

	addr = nmp->b_rptr + off;
	sap = *(uint16_t *)(nmp->b_rptr + off + addr_length);
	dc = dsp->ds_dc;

	if ((hmp = dls_header(dc, addr, sap, dsp->ds_pri)) == NULL) {
		rw_exit(&dsp->ds_lock);
		err = ENOMEM;
		goto failed;
	}

	/*
	 * This is a performance optimization.  We originally entered
	 * as reader and only become writer upon transitioning into
	 * the DLD_FASTPATH mode for the first time.  Otherwise we
	 * stay as reader and return the fast-path header to IP.
	 */
	if (dsp->ds_mode != DLD_FASTPATH) {
		if (!rw_tryupgrade(&dsp->ds_lock)) {
			rw_exit(&dsp->ds_lock);
			rw_enter(&dsp->ds_lock, RW_WRITER);

			/*
			 * State may have changed before we re-acquired
			 * the writer lock in case the upgrade failed.
			 */
			if (dsp->ds_dlstate != DL_IDLE) {
				rw_exit(&dsp->ds_lock);
				err = ENOTSUP;
				goto failed;
			}
		}

		/*
		 * Set the receive callback (unless polling is enabled).
		 */
		if (!dsp->ds_polling)
			dls_rx_set(dc, dld_str_rx_fastpath, (void *)dsp);

		/*
		 * Note that fast-path mode is enabled.
		 */
		dsp->ds_mode = DLD_FASTPATH;
	}
	rw_exit(&dsp->ds_lock);

	freemsg(nmp->b_cont);
	nmp->b_cont = hmp;

	miocack(q, mp, MBLKL(nmp) + MBLKL(hmp), 0);
	return;
failed:
	miocnak(q, mp, 0, err);
}

/*
 * Catch-all handler.
 */
static void
ioc(dld_str_t *dsp, mblk_t *mp)
{
	queue_t	*q = dsp->ds_wq;
	mac_handle_t mh;

	rw_enter(&dsp->ds_lock, RW_READER);
	if (dsp->ds_dlstate == DL_UNATTACHED) {
		rw_exit(&dsp->ds_lock);
		miocnak(q, mp, 0, EINVAL);
		return;
	}
	mh = dsp->ds_mh;
	ASSERT(mh != NULL);
	rw_exit(&dsp->ds_lock);
	mac_ioctl(mh, q, mp);
}

/*
 * Allocate a new minor number.
 */
static minor_t
dld_minor_hold(boolean_t sleep)
{
	minor_t		minor;

	/*
	 * Grab a value from the arena.
	 */
	atomic_add_32(&minor_count, 1);
	if ((minor = PTR_TO_MINOR(vmem_alloc(minor_arenap, 1,
	    (sleep) ? VM_SLEEP : VM_NOSLEEP))) == 0) {
		atomic_add_32(&minor_count, -1);
		return (0);
	}

	return (minor);
}

/*
 * Release a previously allocated minor number.
 */
static void
dld_minor_rele(minor_t minor)
{
	/*
	 * Return the value to the arena.
	 */
	vmem_free(minor_arenap, MINOR_TO_PTR(minor), 1);

	atomic_add_32(&minor_count, -1);
}
