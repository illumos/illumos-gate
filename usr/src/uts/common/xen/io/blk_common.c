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


#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/ddidevmap.h>
#include <sys/xendev.h>
#include <public/io/protocols.h>
#include <xen/io/blkif_impl.h>

#include "blk_common.h"


/* blk interface status */
enum blk_if_state {
	/*
	 * initial state
	 */
	BLK_IF_UNKNOWN = 0,
	/*
	 * frontend xenbus state changed to XenbusStateConnected,
	 * we finally connect
	 */
	BLK_IF_CONNECTED,
	/*
	 * frontend xenbus state changed to XenbusStateClosed,
	 * interface disconnected
	 */
	BLK_IF_DISCONNECTED
};

/* backend device status */
enum blk_be_state {
	/* initial state */
	BLK_BE_UNKNOWN = 0,
	/* backend device is ready (hotplug script finishes successfully) */
	BLK_BE_READY
};

/* frontend status */
enum blk_fe_state {
	/* initial state */
	BLK_FE_UNKNOWN = 0,
	/*
	 * frontend's xenbus state has changed to
	 * XenbusStateInitialised, is ready for connecting
	 */
	BLK_FE_READY
};

typedef struct blk_ring_state_s {
	kmutex_t		rs_mutex;
	boolean_t		rs_sleeping_on_ring;
	boolean_t		rs_ring_up;
	kcondvar_t		rs_cv;
} blk_ring_state_t;

/* Disk Statistics */
static char *blk_stats[] = {
	"rd_reqs",
	"wr_reqs",
	"br_reqs",
	"fl_reqs",
	"oo_reqs"
};

typedef struct blk_stats_s {
	uint64_t bs_req_reads;
	uint64_t bs_req_writes;
	uint64_t bs_req_barriers;
	uint64_t bs_req_flushes;
} blk_stats_t;

struct blk_ring_s {
	kmutex_t		ri_mutex;
	dev_info_t		*ri_dip;

	kstat_t			*ri_kstats;
	blk_stats_t		ri_stats;

	blk_intr_t		ri_intr;
	caddr_t			ri_intr_arg;
	blk_ring_cb_t		ri_ringup;
	caddr_t			ri_ringup_arg;
	blk_ring_cb_t		ri_ringdown;
	caddr_t			ri_ringdown_arg;

	/* blk interface, backend, and frontend status */
	enum blk_if_state	ri_if_status;
	enum blk_be_state	ri_be_status;
	enum blk_fe_state	ri_fe_status;

	domid_t			ri_fe;

	enum blkif_protocol	ri_protocol;
	size_t			ri_nentry;
	size_t			ri_entrysize;

	xendev_ring_t		*ri_ring;
	blk_ring_state_t	ri_state;
};


static void blk_oe_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data);
static void blk_hp_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data);
static int blk_check_state_transition(blk_ring_t ring, XenbusState oestate);
static int blk_start_connect(blk_ring_t ring);
static void blk_start_disconnect(blk_ring_t ring);
static void blk_ring_close(blk_ring_t ring);
static int blk_bindto_frontend(blk_ring_t ring);
static void blk_unbindfrom_frontend(blk_ring_t ring);
static uint_t blk_intr(caddr_t arg);

static int blk_kstat_init(blk_ring_t ring);
static void blk_kstat_fini(blk_ring_t ring);
static int blk_kstat_update(kstat_t *ksp, int flag);

static void blk_ring_request_32(blkif_request_t *dst,
    blkif_x86_32_request_t *src);
static void blk_ring_request_64(blkif_request_t *dst,
    blkif_x86_64_request_t *src);

static void blk_ring_response_32(blkif_x86_32_response_t *dst,
    blkif_response_t *src);
static void blk_ring_response_64(blkif_x86_64_response_t *dst,
    blkif_response_t *src);


/*
 * blk_ring_init()
 */
int
blk_ring_init(blk_ringinit_args_t *args, blk_ring_t *ringp)
{
	blk_ring_t ring;
	int e;


	ring = kmem_zalloc(sizeof (struct blk_ring_s), KM_SLEEP);
	mutex_init(&ring->ri_mutex, NULL, MUTEX_DRIVER, NULL);
	ring->ri_dip = args->ar_dip;
	ring->ri_intr = args->ar_intr;
	ring->ri_intr_arg = args->ar_intr_arg;
	ring->ri_ringup = args->ar_ringup;
	ring->ri_ringup_arg = args->ar_ringup_arg;
	ring->ri_ringdown = args->ar_ringdown;
	ring->ri_ringdown_arg = args->ar_ringdown_arg;

	ring->ri_if_status = BLK_IF_UNKNOWN;
	ring->ri_be_status = BLK_BE_UNKNOWN;
	ring->ri_fe_status = BLK_FE_UNKNOWN;
	ring->ri_state.rs_sleeping_on_ring = B_FALSE;
	ring->ri_state.rs_ring_up = B_FALSE;

	mutex_init(&ring->ri_state.rs_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ring->ri_state.rs_cv, NULL, CV_DRIVER, NULL);

	e = blk_kstat_init(ring);
	if (e != DDI_SUCCESS) {
		goto ringinitfail_kstat;
	}

	/* Watch frontend and hotplug state change */
	if (xvdi_add_event_handler(ring->ri_dip, XS_OE_STATE,
	    blk_oe_state_change, ring) != DDI_SUCCESS) {
		goto ringinitfail_oestate;
	}
	if (xvdi_add_event_handler(ring->ri_dip, XS_HP_STATE,
	    blk_hp_state_change, ring) != DDI_SUCCESS) {
		goto ringinitfail_hpstate;
	}

	/*
	 * Kick-off hotplug script
	 */
	if (xvdi_post_event(ring->ri_dip, XEN_HP_ADD) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "blk@%s: failed to start hotplug script",
		    ddi_get_name_addr(ring->ri_dip));
		goto ringinitfail_postevent;
	}

	/*
	 * start waiting for hotplug event and otherend state event
	 * mainly for debugging, frontend will not take any op seeing this
	 */
	(void) xvdi_switch_state(ring->ri_dip, XBT_NULL, XenbusStateInitWait);

	*ringp = ring;
	return (DDI_SUCCESS);

ringinitfail_postevent:
	xvdi_remove_event_handler(ring->ri_dip, XS_HP_STATE);
ringinitfail_hpstate:
	xvdi_remove_event_handler(ring->ri_dip, XS_OE_STATE);
ringinitfail_oestate:
	blk_kstat_fini(ring);
ringinitfail_kstat:
	cv_destroy(&ring->ri_state.rs_cv);
	mutex_destroy(&ring->ri_state.rs_mutex);
	mutex_destroy(&ring->ri_mutex);
	kmem_free(ring, sizeof (struct blk_ring_s));
	return (DDI_FAILURE);
}


/*
 * blk_ring_fini()
 */
void
blk_ring_fini(blk_ring_t *ringp)
{
	blk_ring_t ring;


	ring = *ringp;

	mutex_enter(&ring->ri_mutex);
	if (ring->ri_if_status != BLK_IF_DISCONNECTED) {
		blk_ring_close(ring);
	}
	mutex_exit(&ring->ri_mutex);

	xvdi_remove_event_handler(ring->ri_dip, NULL);
	blk_kstat_fini(ring);
	cv_destroy(&ring->ri_state.rs_cv);
	mutex_destroy(&ring->ri_state.rs_mutex);
	mutex_destroy(&ring->ri_mutex);
	kmem_free(ring, sizeof (struct blk_ring_s));

	*ringp = NULL;
}


/*
 * blk_kstat_init()
 */
static int
blk_kstat_init(blk_ring_t ring)
{
	int nstat = sizeof (blk_stats) / sizeof (blk_stats[0]);
	char **cp = blk_stats;
	kstat_named_t *knp;

	ring->ri_kstats = kstat_create(ddi_get_name(ring->ri_dip),
	    ddi_get_instance(ring->ri_dip), "req_statistics", "block",
	    KSTAT_TYPE_NAMED, nstat, 0);
	if (ring->ri_kstats == NULL) {
		return (DDI_FAILURE);
	}

	ring->ri_kstats->ks_private = ring;
	ring->ri_kstats->ks_update = blk_kstat_update;

	knp = ring->ri_kstats->ks_data;
	while (nstat > 0) {
		kstat_named_init(knp, *cp, KSTAT_DATA_UINT64);
		knp++;
		cp++;
		nstat--;
	}

	kstat_install(ring->ri_kstats);

	return (DDI_SUCCESS);
}


/*
 * blk_kstat_fini()
 */
static void
blk_kstat_fini(blk_ring_t ring)
{
	kstat_delete(ring->ri_kstats);
}


/*
 * blk_kstat_update()
 */
static int
blk_kstat_update(kstat_t *ksp, int flag)
{
	kstat_named_t *knp;
	blk_stats_t *stats;
	blk_ring_t ring;


	if (flag != KSTAT_READ) {
		return (EACCES);
	}

	ring = ksp->ks_private;
	stats = &ring->ri_stats;
	knp = ksp->ks_data;

	/*
	 * Assignment order should match that of the names in
	 * blk_stats.
	 */
	(knp++)->value.ui64 = stats->bs_req_reads;
	(knp++)->value.ui64 = stats->bs_req_writes;
	(knp++)->value.ui64 = stats->bs_req_barriers;
	(knp++)->value.ui64 = stats->bs_req_flushes;
	(knp++)->value.ui64 = 0; /* oo_req */

	return (0);
}


/*
 * blk_oe_state_change()
 */
/*ARGSUSED*/
static void
blk_oe_state_change(dev_info_t *dip, ddi_eventcookie_t id, void *arg,
    void *impl_data)
{
	XenbusState new_state;
	blk_ring_t ring;


	ring = (blk_ring_t)arg;
	new_state = *(XenbusState *)impl_data;

	mutex_enter(&ring->ri_mutex);

	if (blk_check_state_transition(ring, new_state) == DDI_FAILURE) {
		mutex_exit(&ring->ri_mutex);
		return;
	}

	switch (new_state) {
	case XenbusStateInitialised:
		ASSERT(ring->ri_if_status == BLK_IF_UNKNOWN);

		/* frontend is ready for connecting */
		ring->ri_fe_status = BLK_FE_READY;

		if (ring->ri_be_status == BLK_BE_READY) {
			mutex_exit(&ring->ri_mutex);
			if (blk_start_connect(ring) != DDI_SUCCESS)
				(void) blk_start_disconnect(ring);
			mutex_enter(&ring->ri_mutex);
		}
		break;
	case XenbusStateClosing:
		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosing);
		break;
	case XenbusStateClosed:
		/* clean up */
		(void) xvdi_post_event(ring->ri_dip, XEN_HP_REMOVE);
		if (ring->ri_ringdown != NULL) {
			(*(ring->ri_ringdown))(ring->ri_ringdown_arg);
		}
		blk_ring_close(ring);

		/* reset state in case of reconnect */
		ring->ri_if_status = BLK_IF_UNKNOWN;
		ring->ri_be_status = BLK_BE_UNKNOWN;
		ring->ri_fe_status = BLK_FE_UNKNOWN;
		ring->ri_state.rs_sleeping_on_ring = B_FALSE;
		ring->ri_state.rs_ring_up = B_FALSE;

		break;
	default:
		ASSERT(0);
	}

	mutex_exit(&ring->ri_mutex);
}


/*
 * blk_hp_state_change()
 */
/*ARGSUSED*/
static void
blk_hp_state_change(dev_info_t *dip, ddi_eventcookie_t id, void *arg,
    void *impl_data)
{
	xendev_hotplug_state_t hpstate;
	blk_ring_t ring;


	ring = (blk_ring_t)arg;
	hpstate = *(xendev_hotplug_state_t *)impl_data;

	mutex_enter(&ring->ri_mutex);
	if (hpstate == Connected) {
		/* Hotplug script has completed successfully */
		if (ring->ri_be_status == BLK_BE_UNKNOWN) {
			ring->ri_be_status = BLK_BE_READY;
			if (ring->ri_fe_status == BLK_FE_READY) {
				mutex_exit(&ring->ri_mutex);
				/* try to connect to frontend */
				if (blk_start_connect(ring) != DDI_SUCCESS)
					(void) blk_start_disconnect(ring);
				mutex_enter(&ring->ri_mutex);
			}
		}
	}
	mutex_exit(&ring->ri_mutex);
}


/*
 * blk_check_state_transition()
 *    check the XenbusState change to see if the change is a valid transition
 *    or not. The new state is written by frontend domain, or by running
 *    xenstore-write to change it manually in dom0.
 */
static int
blk_check_state_transition(blk_ring_t ring, XenbusState oestate)
{
	switch (ring->ri_if_status) {
	case BLK_IF_UNKNOWN:
		if (ring->ri_fe_status == BLK_FE_UNKNOWN) {
			if ((oestate == XenbusStateUnknown)		||
			    (oestate == XenbusStateConnected))
				goto statechkfail_bug;
			else if ((oestate == XenbusStateInitialising)	||
			    (oestate == XenbusStateInitWait))
				goto statechkfail_nop;
		} else {
			if ((oestate == XenbusStateUnknown)		||
			    (oestate == XenbusStateInitialising)	||
			    (oestate == XenbusStateInitWait)		||
			    (oestate == XenbusStateConnected))
				goto statechkfail_bug;
			else if (oestate == XenbusStateInitialised)
				goto statechkfail_nop;
		}
		break;

	case BLK_IF_CONNECTED:
		if ((oestate == XenbusStateUnknown)		||
		    (oestate == XenbusStateInitialising)	||
		    (oestate == XenbusStateInitWait)		||
		    (oestate == XenbusStateInitialised))
			goto statechkfail_bug;
		else if (oestate == XenbusStateConnected)
			goto statechkfail_nop;
		break;

	case BLK_IF_DISCONNECTED:
	default:
		goto statechkfail_bug;
	}

	return (DDI_SUCCESS);

statechkfail_bug:
	cmn_err(CE_NOTE, "blk@%s: unexpected otherend "
	    "state change to %d!, when status is %d",
	    ddi_get_name_addr(ring->ri_dip), oestate,
	    ring->ri_if_status);

statechkfail_nop:
	return (DDI_FAILURE);
}


/*
 * blk_start_connect()
 *    Kick-off connect process
 *    If ri_fe_status == BLK_FE_READY and ri_be_status == BLK_BE_READY
 *    the ri_if_status will be changed to BLK_IF_CONNECTED on success,
 *    otherwise, ri_if_status will not be changed
 */
static int
blk_start_connect(blk_ring_t ring)
{
	xenbus_transaction_t xbt;
	dev_info_t *dip;
	char *barrier;
	char *xsnode;
	uint_t len;
	int e;


	dip = ring->ri_dip;

	/*
	 * Start connect to frontend only when backend device are ready
	 * and frontend has moved to XenbusStateInitialised, which means
	 * ready to connect
	 */
	ASSERT(ring->ri_fe_status == BLK_FE_READY);
	ASSERT(ring->ri_be_status == BLK_BE_READY);

	xsnode = xvdi_get_xsname(dip);
	if (xsnode == NULL) {
		goto startconnectfail_get_xsname;
	}

	ring->ri_fe = xvdi_get_oeid(dip);
	if (ring->ri_fe == (domid_t)-1) {
		goto startconnectfail_get_oeid;
	}

	e =  xvdi_switch_state(dip, XBT_NULL, XenbusStateInitialised);
	if (e > 0) {
		goto startconnectfail_switch_init;
	}

	e = blk_bindto_frontend(ring);
	if (e != DDI_SUCCESS) {
		goto startconnectfail_bindto_frontend;
	}
	ring->ri_if_status = BLK_IF_CONNECTED;

	e = ddi_add_intr(dip, 0, NULL, NULL, blk_intr, (caddr_t)ring);
	if (e != DDI_SUCCESS) {
		goto startconnectfail_add_intr;
	}

trans_retry:
	e = xenbus_transaction_start(&xbt);
	if (e != 0) {
		xvdi_fatal_error(dip, e, "transaction start");
		goto startconnectfail_transaction_start;
	}

	/* If feature-barrier isn't present in xenstore, add it */
	e = xenbus_read(xbt, xsnode, "feature-barrier", (void **)&barrier,
	    &len);
	if (e != 0) {
		e = xenbus_printf(xbt, xsnode, "feature-barrier", "%d", 1);
		if (e != 0) {
			cmn_err(CE_WARN, "xdb@%s: failed to write "
			    "'feature-barrier'", ddi_get_name_addr(dip));
			xvdi_fatal_error(dip, e, "writing 'feature-barrier'");
			(void) xenbus_transaction_end(xbt, 1);
			goto startconnectfail_xenbus_printf;
		}
	} else {
		kmem_free(barrier, len);
	}

	e = xvdi_switch_state(dip, xbt, XenbusStateConnected);
	if (e > 0) {
		xvdi_fatal_error(dip, e, "writing 'state'");
		(void) xenbus_transaction_end(xbt, 1);
		goto startconnectfail_switch_connected;
	}

	e = xenbus_transaction_end(xbt, 0);
	if (e != 0) {
		if (e == EAGAIN) {
			/* transaction is ended, don't need to abort it */
			goto trans_retry;
		}
		xvdi_fatal_error(dip, e, "completing transaction");
		goto startconnectfail_transaction_end;
	}

	mutex_enter(&ring->ri_state.rs_mutex);
	ring->ri_state.rs_ring_up = B_TRUE;
	if (ring->ri_state.rs_sleeping_on_ring) {
		ring->ri_state.rs_sleeping_on_ring = B_FALSE;
		cv_signal(&ring->ri_state.rs_cv);
	}
	mutex_exit(&ring->ri_state.rs_mutex);

	if (ring->ri_ringup != NULL) {
		(*(ring->ri_ringup))(ring->ri_ringup_arg);
	}

	return (DDI_SUCCESS);


startconnectfail_transaction_end:
startconnectfail_switch_connected:
startconnectfail_xenbus_printf:
startconnectfail_transaction_start:
	ddi_remove_intr(dip, 0, NULL);
startconnectfail_add_intr:
	blk_unbindfrom_frontend(ring);
	ring->ri_fe = (domid_t)-1;
startconnectfail_bindto_frontend:
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosed);
startconnectfail_switch_init:
startconnectfail_get_oeid:
startconnectfail_get_xsname:
	return (DDI_FAILURE);
}


/*
 * blk_start_disconnect()
 *    Kick-off disconnect process. ri_if_status will not be changed
 */
static void
blk_start_disconnect(blk_ring_t ring)
{
	/* Kick-off disconnect process */
	(void) xvdi_switch_state(ring->ri_dip, XBT_NULL, XenbusStateClosing);
}


/*
 * blk_ring_close()
 *    Disconnect from frontend and close backend device
 *    ifstatus will be changed to BLK_DISCONNECTED
 *    Xenbus state will be changed to XenbusStateClosed
 */
static void
blk_ring_close(blk_ring_t ring)
{
	dev_info_t *dip;


	/* mutex protect ri_if_status only here */
	ASSERT(MUTEX_HELD(&ring->ri_mutex));

	dip = ring->ri_dip;

	if (ring->ri_if_status != BLK_IF_CONNECTED) {
		return;
	}

	ring->ri_if_status = BLK_IF_DISCONNECTED;
	mutex_exit(&ring->ri_mutex);

	/* stop accepting I/O request from frontend */
	ddi_remove_intr(dip, 0, NULL);

	blk_unbindfrom_frontend(ring);
	ring->ri_fe = (domid_t)-1;
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosed);
	mutex_enter(&ring->ri_mutex);
}


/*
 * blk_bindto_frontend()
 */
static int
blk_bindto_frontend(blk_ring_t ring)
{
	evtchn_port_t evtchn;
	char protocol[64];
	grant_ref_t gref;
	dev_info_t *dip;
	char *oename;
	int e;


	dip = ring->ri_dip;
	protocol[0] = 0x0;

	/*
	 * Gather info from frontend
	 */
	oename = xvdi_get_oename(dip);
	if (oename == NULL) {
		return (DDI_FAILURE);
	}

	e = xenbus_gather(XBT_NULL, oename, "ring-ref", "%lu", &gref,
	    "event-channel", "%u", &evtchn, NULL);
	if (e != 0) {
		xvdi_fatal_error(dip, e,
		    "Getting ring-ref and evtchn from frontend");
		return (DDI_FAILURE);
	}

	e = xenbus_gather(XBT_NULL, oename, "protocol", "%63s",
	    protocol, NULL);
	if (e != 0) {
		(void) strcpy(protocol, "unspecified, assuming native");
	} else if (strcmp(protocol, XEN_IO_PROTO_ABI_NATIVE) == 0) {
		ring->ri_protocol = BLKIF_PROTOCOL_NATIVE;
		ring->ri_nentry = BLKIF_RING_SIZE;
		ring->ri_entrysize = sizeof (union blkif_sring_entry);
	} else if (strcmp(protocol, XEN_IO_PROTO_ABI_X86_32) == 0) {
		ring->ri_protocol = BLKIF_PROTOCOL_X86_32;
		ring->ri_nentry = BLKIF_X86_32_RING_SIZE;
		ring->ri_entrysize = sizeof (union blkif_x86_32_sring_entry);
	} else if (strcmp(protocol, XEN_IO_PROTO_ABI_X86_64) == 0) {
		ring->ri_protocol = BLKIF_PROTOCOL_X86_64;
		ring->ri_nentry = BLKIF_X86_64_RING_SIZE;
		ring->ri_entrysize = sizeof (union blkif_x86_64_sring_entry);
	} else {
		xvdi_fatal_error(dip, e, "unknown fe protocol");
		return (DDI_FAILURE);
	}

	/*
	 * map and init ring
	 */
	e = xvdi_map_ring(dip, ring->ri_nentry, ring->ri_entrysize, gref,
	    &ring->ri_ring);
	if (e != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * bind event channel
	 */
	e = xvdi_bind_evtchn(dip, evtchn);
	if (e != DDI_SUCCESS) {
		xvdi_unmap_ring(ring->ri_ring);
		return (DDI_FAILURE);
	}


	return (DDI_SUCCESS);
}


/*
 * blk_unbindfrom_frontend()
 */
static void
blk_unbindfrom_frontend(blk_ring_t ring)
{
	xvdi_free_evtchn(ring->ri_dip);
	xvdi_unmap_ring(ring->ri_ring);
}


/*
 * blk_intr()
 */
static uint_t
blk_intr(caddr_t arg)
{
	blk_ring_t ring;

	ring = (blk_ring_t)arg;
	if (ring->ri_if_status != BLK_IF_CONNECTED) {
		return (DDI_INTR_CLAIMED);
	}

	(void) (*ring->ri_intr)(ring->ri_intr_arg);
	return (DDI_INTR_CLAIMED);
}


/*
 * blk_ring_request_get()
 */
boolean_t
blk_ring_request_get(blk_ring_t ring, blkif_request_t *req)
{
	blkif_request_t *src;
	blk_stats_t *stats;


	mutex_enter(&ring->ri_mutex);
	src = xvdi_ring_get_request(ring->ri_ring);
	if (src == NULL) {
		mutex_exit(&ring->ri_mutex);
		return (B_FALSE);
	}

	switch (ring->ri_protocol) {
	case BLKIF_PROTOCOL_NATIVE:
		bcopy(src, req, sizeof (*req));
		break;
	case BLKIF_PROTOCOL_X86_32:
		blk_ring_request_32(req, (blkif_x86_32_request_t *)src);
		break;
	case BLKIF_PROTOCOL_X86_64:
		blk_ring_request_64(req, (blkif_x86_64_request_t *)src);
		break;
	default:
		cmn_err(CE_WARN, "blkif@%s: unrecognised protocol: %d",
		    ddi_get_name_addr(ring->ri_dip),
		    ring->ri_protocol);
	}
	mutex_exit(&ring->ri_mutex);

	stats = &ring->ri_stats;
	switch (req->operation) {
	case BLKIF_OP_READ:
		stats->bs_req_reads++;
		break;
	case BLKIF_OP_WRITE:
		stats->bs_req_writes++;
		break;
	case BLKIF_OP_WRITE_BARRIER:
		stats->bs_req_barriers++;
		break;
	case BLKIF_OP_FLUSH_DISKCACHE:
		stats->bs_req_flushes++;
		break;
	}

	return (B_TRUE);
}


/*
 * blk_ring_request_requeue()
 *    if a request is requeued, caller will have to poll for request
 *    later.
 */
void
blk_ring_request_requeue(blk_ring_t ring)
{
	ring->ri_ring->xr_sring.br.req_cons--;
}


/*
 * blk_ring_response_put()
 */
void
blk_ring_response_put(blk_ring_t ring, blkif_response_t *src)
{
	blkif_response_t *rsp = xvdi_ring_get_response(ring->ri_ring);
	int e;

	ASSERT(rsp);

	switch (ring->ri_protocol) {
	case BLKIF_PROTOCOL_NATIVE:
		bcopy(src, rsp, sizeof (*rsp));
		break;
	case BLKIF_PROTOCOL_X86_32:
		blk_ring_response_32((blkif_x86_32_response_t *)rsp, src);
		break;
	case BLKIF_PROTOCOL_X86_64:
		blk_ring_response_64((blkif_x86_64_response_t *)rsp, src);
		break;
	default:
		cmn_err(CE_WARN, "blk@%s: unrecognised protocol: %d",
		    ddi_get_name_addr(ring->ri_dip),
		    ring->ri_protocol);
	}

	e = xvdi_ring_push_response(ring->ri_ring);
	if (e != 0) {
		xvdi_notify_oe(ring->ri_dip);
	}
}


/*
 * blk_ring_request_32()
 */
static void
blk_ring_request_32(blkif_request_t *dst, blkif_x86_32_request_t *src)
{
	int i, n = BLKIF_MAX_SEGMENTS_PER_REQUEST;
	dst->operation = src->operation;
	dst->nr_segments = src->nr_segments;
	dst->handle = src->handle;
	dst->id = src->id;
	dst->sector_number = src->sector_number;
	if (n > src->nr_segments)
		n = src->nr_segments;
	for (i = 0; i < n; i++)
		dst->seg[i] = src->seg[i];
}


/*
 * blk_ring_request_64()
 */
static void
blk_ring_request_64(blkif_request_t *dst, blkif_x86_64_request_t *src)
{
	int i, n = BLKIF_MAX_SEGMENTS_PER_REQUEST;
	dst->operation = src->operation;
	dst->nr_segments = src->nr_segments;
	dst->handle = src->handle;
	dst->id = src->id;
	dst->sector_number = src->sector_number;
	if (n > src->nr_segments)
		n = src->nr_segments;
	for (i = 0; i < n; i++)
		dst->seg[i] = src->seg[i];
}


/*
 * blk_ring_response_32()
 */
static void
blk_ring_response_32(blkif_x86_32_response_t *dst, blkif_response_t *src)
{
	dst->id = src->id;
	dst->operation = src->operation;
	dst->status = src->status;
}


/*
 * blk_ring_response_64()
 */
static void
blk_ring_response_64(blkif_x86_64_response_t *dst, blkif_response_t *src)
{
	dst->id = src->id;
	dst->operation = src->operation;
	dst->status = src->status;
}


/*
 * blk_ring_request_dump()
 */
void
blk_ring_request_dump(blkif_request_t *req)
{
	int i;

	/*
	 * Exploit the public interface definitions for BLKIF_OP_READ
	 * etc..
	 */
	char *op_name[] = { "read", "write", "barrier", "flush" };

	cmn_err(CE_NOTE, "   op=%s", op_name[req->operation]);
	cmn_err(CE_NOTE, "   num of segments=%d", req->nr_segments);
	cmn_err(CE_NOTE, "   handle=%d", req->handle);
	cmn_err(CE_NOTE, "   id=0x%llx", (unsigned long long)req->id);
	cmn_err(CE_NOTE, "   start sector=%llu",
	    (unsigned long long)req->sector_number);
	for (i = 0; i < req->nr_segments; i++) {
		cmn_err(CE_NOTE, "   gref=%d, first sec=%d,"
		    "last sec=%d", req->seg[i].gref, req->seg[i].first_sect,
		    req->seg[i].last_sect);
	}
}


/*
 * blk_ring_response_dump()
 */
void
blk_ring_response_dump(blkif_response_t *resp)
{
	/*
	 * Exploit the public interface definitions for BLKIF_OP_READ
	 * etc..
	 */
	char *op_name[] = { "read", "write", "barrier", "flush" };

	cmn_err(CE_NOTE, "   op=%d:%s", resp->operation,
	    op_name[resp->operation]);
	cmn_err(CE_NOTE, "   op=%d", resp->operation);
	cmn_err(CE_NOTE, "   status=%d", resp->status);
}
