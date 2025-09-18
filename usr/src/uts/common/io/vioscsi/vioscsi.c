/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 * Copyright 2025 Oxide Computer Company
 * Copyright 2026 Hans Rosenfeld
 */

#include "vioscsi.h"

static char vioscsi_ident[] = "VIRTIO SCSI driver";

static uint_t vioscsi_ctl_handler(caddr_t arg1, caddr_t arg2);
static uint_t vioscsi_evt_handler(caddr_t arg1, caddr_t arg2);
static uint_t vioscsi_cmd_handler(caddr_t arg1, caddr_t arg2);

static int vioscsi_tran_getcap(struct scsi_address *, char *, int);
static int vioscsi_tran_setcap(struct scsi_address *, char *, int, int);
static int vioscsi_tran_reset(struct scsi_address *, int);

static int vioscsi_tran_start(struct scsi_address *, struct scsi_pkt *);
static int vioscsi_tran_abort(struct scsi_address *, struct scsi_pkt *);

static int vioscsi_iport_attach(dev_info_t *);
static int vioscsi_iport_detach(dev_info_t *);

static int vioscsi_req_init(vioscsi_softc_t *, vioscsi_request_t *,
    virtio_queue_t *, int);
static void vioscsi_req_fini(vioscsi_request_t *);
static boolean_t vioscsi_req_abort(vioscsi_softc_t *, vioscsi_request_t *);
static void vioscsi_lun_changed(vioscsi_softc_t *sc, uint8_t target);
static void vioscsi_discover(void *);

static void *vioscsi_state;

/*
 * DMA attributes. We support a linked list, but most of our uses require a
 * single aligned buffer.  The HBA buffers will use a copy of this adjusted for
 * the actual virtio limits.
 */
static ddi_dma_attr_t virtio_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =		0x00000000FFFFFFFFull,
	.dma_attr_align =		1,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0xFFFFFFFFull,
	.dma_attr_seg =			0xFFFFFFFFFFFFFFFFull,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		1,
	.dma_attr_flags =		0,
};

/*
 * this avoids calls to drv_usectohz that might be expensive:
 */
static clock_t vioscsi_hz;

static boolean_t
vioscsi_poll_until(vioscsi_softc_t *sc, vioscsi_request_t *req,
    ddi_intr_handler_t func, clock_t until)
{
	until *= 1000000; /* convert to usec */
	while (until > 0) {
		(void) func((caddr_t)sc, NULL);
		if (req->vr_done) {
			return (B_TRUE);
		}
		drv_usecwait(10);
		until -= 10;
	}
	atomic_or_8(&req->vr_expired, 1);
	return (B_FALSE);
}

static boolean_t
vioscsi_tmf(vioscsi_softc_t *sc, uint32_t func, uint8_t target, uint16_t lun,
    vioscsi_request_t *task)
{
	vioscsi_request_t req;
	vioscsi_tmf_res_t *res;
	vioscsi_tmf_req_t *tmf;

	bzero(&req, sizeof (req));

	if (vioscsi_req_init(sc, &req, sc->vs_ctl_vq, KM_NOSLEEP) != 0) {
		return (B_FALSE);
	}

	tmf = &req.vr_req->tmf;
	res = &req.vr_res->tmf;

	tmf->type = VIRTIO_SCSI_T_TMF;
	tmf->subtype = func;
	tmf->lun[0] = 1;
	tmf->lun[1] = target;
	tmf->lun[2] = 0x40 | (lun >> 8);
	tmf->lun[3] = lun & 0xff;
	tmf->tag = (uint64_t)task;

	virtio_chain_clear(req.vr_vic);
	if (virtio_chain_append(req.vr_vic, req.vr_req_pa, sizeof (*tmf),
	    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		virtio_chain_clear(req.vr_vic);
		return (B_FALSE);
	}

	if (virtio_chain_append(req.vr_vic, req.vr_res_pa, sizeof (*res),
	    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		virtio_chain_clear(req.vr_vic);
		return (B_FALSE);
	}

	/*
	 * Make sure the device can see our request:
	 */
	virtio_dma_sync(req.vr_dma, DDI_DMA_SYNC_FORDEV);

	/*
	 * Push chain into the queue:
	 */
	virtio_chain_submit(req.vr_vic, B_TRUE);

	/*
	 * Wait for it to complete -- these should always complete in a tiny
	 * amount of time.  Give it 5 seconds to be sure.
	 */
	if (!vioscsi_poll_until(sc, &req,  vioscsi_ctl_handler, 5)) {
		/*
		 * We timed out -- this should *NEVER* happen!
		 * There is no safe way to deal with this if it occurs, so we
		 * just warn and leak the resources.  Plan for a reboot soon.
		 */
		dev_err(sc->vs_dip, CE_WARN,
		    "task mgmt timeout! (target %d lun %d)", target, lun);
		return (B_FALSE);
	}

	vioscsi_req_fini(&req);

	switch (res->response) {
	case VIRTIO_SCSI_S_OK:
	case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
		break;
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
vioscsi_lun_reset(vioscsi_softc_t *sc, uint8_t target, uint16_t lun)
{
	return (vioscsi_tmf(sc, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET,
	    target, lun, NULL));
}

static boolean_t
vioscsi_target_reset(vioscsi_softc_t *sc, uint8_t target)
{
	return (vioscsi_tmf(sc, VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET,
	    target, 0, NULL));
}

static boolean_t
vioscsi_req_abort(vioscsi_softc_t *sc, vioscsi_request_t *req)
{
	return (vioscsi_tmf(sc, VIRTIO_SCSI_T_TMF_ABORT_TASK,
	    req->vr_target, req->vr_lun, req));
}

static void
vioscsi_dev_abort(vioscsi_dev_t *vd)
{
	vioscsi_request_t *req;
	list_t *l = &vd->vd_reqs;

	mutex_enter(&vd->vd_lock);
	for (req = list_head(l); req != NULL; req = list_next(l, req)) {
		(void) vioscsi_tmf(vd->vd_sc, VIRTIO_SCSI_T_TMF_ABORT_TASK,
		    req->vr_target, req->vr_lun, req);
	}
	mutex_exit(&vd->vd_lock);
}

static void
vioscsi_dev_timeout(void *arg)
{
	vioscsi_dev_t *vd = arg;
	vioscsi_softc_t *sc = vd->vd_sc;
	vioscsi_request_t *req;
	timeout_id_t tid;
	clock_t now;
	list_t *l;

	mutex_enter(&vd->vd_lock);
	if ((tid = vd->vd_timeout) == 0) {
		/*
		 * We are shutting down, stop and do not reschedule.
		 */
		mutex_exit(&vd->vd_lock);
		return;
	}
	vd->vd_timeout = 0;

	now = ddi_get_lbolt();
	l = &vd->vd_reqs;

	for (req = list_head(l); req != NULL; req = list_next(l, req)) {
		/*
		 * The list is sorted by expiration time, so if we reach an
		 * item that hasn't expired yet, we're done.
		 */
		if (now < req->vr_expire) {
			break;
		}
		atomic_or_8(&req->vr_expired, 1);

		/*
		 * This command timed out, so send an abort.
		 */
		dev_err(sc->vs_dip, CE_WARN, "cmd timed out (%ds)",
		    (int)req->vr_time);
		(void) vioscsi_req_abort(sc, req);
	}

	if (!list_is_empty(l)) {
		/*
		 * Check again in a second.
		 * If these wake ups are too expensive, we could
		 * calculate other timeouts, but that would require
		 * doing untimeout if we want to wake up earlier.
		 * This is probably cheaper, and certainly simpler.
		 */
		vd->vd_timeout = timeout(vioscsi_dev_timeout, vd, vioscsi_hz);
	}
	mutex_exit(&vd->vd_lock);
}

static void
vioscsi_poll(vioscsi_softc_t *sc, vioscsi_request_t *req)
{
	if (vioscsi_poll_until(sc, req, vioscsi_cmd_handler, req->vr_time)) {
		return;
	}

	/*
	 * Try a "gentle" task abort -- timeouts may be quasi-normal for some
	 * types of requests and devices.
	 */
	if (vioscsi_req_abort(sc, req) &&
	    vioscsi_poll_until(sc, req, vioscsi_cmd_handler, 1)) {
		return;
	}

	/*
	 * A little more forceful with a lun reset:
	 */
	if (vioscsi_lun_reset(sc, req->vr_target, req->vr_lun) &&
	    vioscsi_poll_until(sc, req, vioscsi_cmd_handler, 1)) {
		return;
	}

	/*
	 * If all else fails, reset the target, and keep trying.
	 * This can wind up blocking forever, but if it does it means we are in
	 * a very bad situation (and the virtio device is busted).
	 * We may also be leaking request structures at this point, but only at
	 * the maximum rate of one per minute.
	 */
	for (;;) {
		dev_err(sc->vs_dip, CE_WARN, "request stuck, resetting target");
		(void) vioscsi_target_reset(sc, req->vr_target);
		if (vioscsi_poll_until(sc, req, vioscsi_cmd_handler, 60)) {
			return;
		}
	}
}

static void
vioscsi_start(vioscsi_softc_t *sc, vioscsi_request_t *req)
{
	vioscsi_cmd_req_t *cmd = &req->vr_req->cmd;

	req->vr_done = 0;
	req->vr_expired = 0;
	cmd->lun[0] = 1;
	cmd->lun[1] = req->vr_target;
	cmd->lun[2] = 0x40 | ((req->vr_lun >> 8) & 0xff);
	cmd->lun[3] = req->vr_lun & 0xff;
	cmd->lun[4] = 0;
	cmd->lun[5] = 0;
	cmd->lun[6] = 0;
	cmd->lun[7] = 0;
	cmd->tag = (uint64_t)req;
	cmd->prio = 0;
	cmd->crn = 0;
	cmd->task_attr = req->vr_task_attr;

	/*
	 * Make sure the device can see our CDB data:
	 */
	virtio_dma_sync(req->vr_dma, DDI_DMA_SYNC_FORDEV);

	/*
	 * Determine whether we expect to poll before submitting (because we
	 * cannot touch the request after submission if we are not polling).
	 */
	if (req->vr_poll) {
		/*
		 * Push chain into the queue:
		 */
		virtio_chain_submit(req->vr_vic, B_TRUE);

		/*
		 * NB: Interrupts may be enabled, or might not be.  It is fine
		 * either way.
		 */
		vioscsi_poll(sc, req);
	} else {
		/*
		 * Push chain into the queue:
		 */
		virtio_chain_submit(req->vr_vic, B_TRUE);
	}
}

static int
vioscsi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct scsi_device *sd = scsi_address_device(ap);
	vioscsi_dev_t *vd = scsi_device_hba_private_get(sd);
	vioscsi_request_t *req = pkt->pkt_ha_private;
	virtio_chain_t *vic = req->vr_vic;
	vioscsi_cmd_req_t *cmd = &req->vr_req->cmd;
	vioscsi_cmd_res_t *res = &req->vr_res->cmd;

	if (pkt->pkt_cdbp == NULL) {
		return (TRAN_BADPKT);
	}

	bzero(cmd, sizeof (*cmd));
	bcopy(pkt->pkt_cdbp, cmd->cdb, pkt->pkt_cdblen);

	/*
	 * Default expiration is 10 seconds, clip at an hour.
	 * (order of operations here is to avoid wrapping, if run in a 32-bit
	 * kernel)
	 */
	req->vr_time = min(pkt->pkt_time ? pkt->pkt_time : 10, 3600);
	req->vr_dev = vd;
	req->vr_poll = ((pkt->pkt_flags & FLAG_NOINTR) != 0);
	req->vr_target = vd->vd_target;
	req->vr_lun = vd->vd_lun;
	req->vr_start = ddi_get_lbolt();
	req->vr_expire = req->vr_start + req->vr_time * vioscsi_hz;

	/*
	 * Configure task queuing behavior:
	 */
	if (pkt->pkt_flags & (FLAG_HTAG|FLAG_HEAD)) {
		req->vr_task_attr = VIRTIO_SCSI_S_HEAD;
	} else if (pkt->pkt_flags & FLAG_OTAG) {
		req->vr_task_attr = VIRTIO_SCSI_S_ORDERED;
	} else if (pkt->pkt_flags & FLAG_SENSING) {
		req->vr_task_attr = VIRTIO_SCSI_S_ACA;
	} else { /* FLAG_STAG is also our default */
		req->vr_task_attr = VIRTIO_SCSI_S_SIMPLE;
	}

	/*
	 * Make sure we start with a clear chain:
	 */
	virtio_chain_clear(vic);

	/*
	 * The KVM SCSI emulation requires that all outgoing buffers are added
	 * first with the request header being the first entry.  After the
	 * outgoing have been added then the incoming buffers with the response
	 * buffer being the first of the incoming.  This requirement is
	 * independent of using chained ring entries or one ring entry with
	 * indirect buffers.
	 */

	/*
	 * Add request header:
	 */
	if (virtio_chain_append(vic, req->vr_req_pa, sizeof (*cmd),
	    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS)
		goto busy;

	/*
	 * Add write buffers:
	 */
	if (pkt->pkt_dma_flags & DDI_DMA_WRITE) {
		for (int i = 0; i < pkt->pkt_numcookies; i++) {
			if (virtio_chain_append(vic,
			    pkt->pkt_cookies[i].dmac_laddress,
			    pkt->pkt_cookies[i].dmac_size,
			    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS)
				goto busy;
		}
	}

	/*
	 * Add response header:
	 */
	if (virtio_chain_append(vic, req->vr_res_pa, sizeof (*res),
	    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS)
		goto busy;

	/*
	 * Add read buffers:
	 */
	if (pkt->pkt_dma_flags & DDI_DMA_READ) {
		for (int i = 0; i < pkt->pkt_numcookies; i++) {
			if (virtio_chain_append(vic,
			    pkt->pkt_cookies[i].dmac_laddress,
			    pkt->pkt_cookies[i].dmac_size,
			    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS)
				goto busy;
		}
	}

	/*
	 * Check for queue depth, and add to the timeout list:
	 */
	mutex_enter(&vd->vd_lock);
	if (vd->vd_num_cmd >= vd->vd_max_cmd) {
		mutex_exit(&vd->vd_lock);
		goto busy;
	}

	vd->vd_num_cmd++;

	if (!req->vr_poll) {
		/*
		 * Add the request to the timeout list.
		 *
		 * In order to minimize the work done during timeout handling,
		 * we keep requests sorted.  This assumes that requests mostly
		 * have the same timeout, and requests with long timeouts are
		 * infrequent.
		 */
		list_t *l = &vd->vd_reqs;
		vioscsi_request_t *r;

		for (r = list_tail(l); r != NULL; r = list_prev(l, r)) {
			/*
			 * Avoids wrapping lbolt:
			 */
			if ((req->vr_expire - r->vr_expire) >= 0) {
				list_insert_after(l, r, req);
				break;
			}
		}
		if (r == NULL) {
			/*
			 * List empty, or this one expires before others:
			 */
			list_insert_head(l, req);
		}
		if (vd->vd_timeout == 0) {
			vd->vd_timeout = timeout(vioscsi_dev_timeout, vd,
			    vioscsi_hz);
		}
	}

	mutex_exit(&vd->vd_lock);

	vioscsi_start(vd->vd_sc, req);
	return (TRAN_ACCEPT);

busy:
	virtio_chain_clear(vic);
	return (TRAN_BUSY);
}

static int
vioscsi_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct scsi_device *sd;
	vioscsi_dev_t *vd;
	vioscsi_request_t *req;

	if ((ap == NULL) ||
	    ((sd = scsi_address_device(ap)) == NULL) ||
	    ((vd = scsi_device_hba_private_get(sd)) == NULL)) {
		return (0);
	}
	if (pkt == NULL) {
		/*
		 * Abort all requests for the LUN.
		 */
		vioscsi_dev_abort(vd);
		return (1);
	}
	if ((req = pkt->pkt_ha_private) != NULL) {
		return (vioscsi_req_abort(vd->vd_sc, req) ? 1 : 0);
	}

	return (0);
}

static void
vioscsi_req_fini(vioscsi_request_t *req)
{
	if (req->vr_dma != NULL) {
		virtio_dma_free(req->vr_dma);
		req->vr_dma = NULL;
	}
	if (req->vr_vic != NULL) {
		virtio_chain_free(req->vr_vic);
		req->vr_vic = NULL;
	}
}

static int
vioscsi_req_init(vioscsi_softc_t *sc, vioscsi_request_t *req,
    virtio_queue_t *vq, int sleep)
{
	uint64_t pa;

	bzero(req, sizeof (*req));
	list_link_init(&req->vr_node);
	req->vr_vq = vq;
	req->vr_dma = virtio_dma_alloc(sc->vs_virtio, sizeof (vioscsi_op_t),
	    &virtio_dma_attr, DDI_DMA_STREAMING | DDI_DMA_READ | DDI_DMA_WRITE,
	    sleep);
	req->vr_vic = virtio_chain_alloc(vq, sleep);
	if ((req->vr_dma == NULL) || (req->vr_vic == NULL)) {
		return (-1);
	}
	virtio_chain_data_set(req->vr_vic, req);
	req->vr_req = virtio_dma_va(req->vr_dma, VIOSCSI_REQ_OFFSET);
	req->vr_res = virtio_dma_va(req->vr_dma, VIOSCSI_RES_OFFSET);
	pa = virtio_dma_cookie_pa(req->vr_dma, 0);
	req->vr_req_pa = pa + VIOSCSI_REQ_OFFSET;
	req->vr_res_pa = pa + VIOSCSI_RES_OFFSET;
	return (0);
}

static void
vioscsi_tran_pkt_destructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran)
{
	vioscsi_request_t *req = pkt->pkt_ha_private;

	vioscsi_req_fini(req);
}

static int
vioscsi_tran_pkt_constructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran,
    int sleep)
{
	vioscsi_softc_t *sc = tran->tran_hba_private;
	vioscsi_request_t *req = pkt->pkt_ha_private;

	if (vioscsi_req_init(sc, req, sc->vs_cmd_vq, sleep) != 0) {
		vioscsi_req_fini(req);
		return (-1);
	}
	req->vr_pkt = pkt;
	return (0);
}

static int
vioscsi_tran_setup_pkt(struct scsi_pkt *pkt, int (*cb)(caddr_t), caddr_t arg)
{
	if ((pkt->pkt_dma_flags & DDI_DMA_RDWR) == DDI_DMA_RDWR) {
		/*
		 * We can do read, or write, but not both.
		 */
		return (-1);
	}

	return (0);
}

static void
vioscsi_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	vioscsi_request_t *req = pkt->pkt_ha_private;
	virtio_chain_t *vic = req->vr_vic;

	virtio_chain_clear(vic);
}

static int
vioscsi_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int rval = 0;
	vioscsi_softc_t *sc = ap->a_hba_tran->tran_hba_private;

	if (cap == NULL)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_CDB_LEN:
		rval = sc->vs_cdb_size;
		break;

	case SCSI_CAP_DMA_MAX:
		rval = sc->vs_tran->tran_dma_attr.dma_attr_maxxfer;
		break;

	case SCSI_CAP_INTERCONNECT_TYPE:
		rval = sc->vs_tran->tran_interconnect_type;
		break;

	case SCSI_CAP_ARQ:
	case SCSI_CAP_LUN_RESET:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
		rval = 1;
		break;

	default:
		rval = -1;
	}
	return (rval);
}

static int
vioscsi_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int rval = 1;

	if (cap == NULL || whom == 0) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	default:
		rval = 1;
	}
	return (rval);
}

static int
vioscsi_tran_reset(struct scsi_address *ap, int level)
{
	struct scsi_device *sd;
	vioscsi_dev_t *vd;

	if ((ap == NULL) ||
	    ((sd = scsi_address_device(ap)) == NULL) ||
	    ((vd = scsi_device_hba_private_get(sd)) == NULL)) {
		return (0);
	}

	switch (level) {
	case RESET_LUN:
		if (vioscsi_lun_reset(vd->vd_sc, vd->vd_target, vd->vd_lun)) {
			return (1);
		}
		break;
	case RESET_TARGET:
		if (vioscsi_target_reset(vd->vd_sc, vd->vd_target)) {
			return (1);
		}
		break;
	case RESET_ALL:
	default:
		break;
	}
	return (0);
}

static boolean_t
vioscsi_parse_unit_address(const char *ua, int *tgt, int *lun)
{
	long num;
	char *end;

	if ((ddi_strtol(ua, &end, 16, &num) != 0) ||
	    ((*end != ',') && (*end != 0))) {
		return (B_FALSE);
	}
	*tgt = (int)num;
	if (*end == 0) {
		*lun = 0;
		return (B_TRUE);
	}
	end++; /* skip comma */
	if ((ddi_strtol(end, &end, 16, &num) != 0) || (*end != 0)) {
		return (B_FALSE);
	}
	*lun = (int)num;
	return (B_TRUE);
}

uint_t
vioscsi_ctl_handler(caddr_t arg1, caddr_t arg2)
{
	vioscsi_softc_t *sc = (vioscsi_softc_t *)arg1;
	virtio_chain_t *vic;

	while ((vic = virtio_queue_poll(sc->vs_ctl_vq)) != NULL) {
		vioscsi_request_t *req;

		if ((req = virtio_chain_data(vic)) == NULL) {
			dev_err(sc->vs_dip, CE_WARN, "missing ctl chain data");
			continue;
		}
		atomic_or_8(&req->vr_done, 1);
	}
	return (DDI_INTR_CLAIMED);
}

uint_t
vioscsi_evt_handler(caddr_t arg1, caddr_t arg2)
{
	vioscsi_softc_t *sc = (vioscsi_softc_t *)arg1;
	virtio_chain_t *vic;
	boolean_t missed = B_FALSE;

	while ((vic = virtio_queue_poll(sc->vs_evt_vq)) != NULL) {
		vioscsi_evt_t *evt;
		vioscsi_event_t *ve;
		uint8_t target;

		if ((ve = virtio_chain_data(vic)) == NULL) {
			/*
			 * This should never occur, it's a bug if it does.
			 */
			dev_err(sc->vs_dip, CE_WARN, "missing evt chain data");
			continue;
		}
		evt = ve->ve_evt;

		virtio_dma_sync(ve->ve_dma, DDI_DMA_SYNC_FORKERNEL);

		target = evt->lun[1];
		switch (evt->event & 0x7FFFFFFF) {
		case VIRTIO_SCSI_T_TRANSPORT_RESET:
			switch (evt->reason) {
			case VIRTIO_SCSI_EVT_RESET_HARD:
				/*
				 * We could reset-notify, but this doesn't seem
				 * to get fired for targets initiated from
				 * host.
				 */
				break;
			case VIRTIO_SCSI_EVT_RESET_REMOVED:
			case VIRTIO_SCSI_EVT_RESET_RESCAN:
				/*
				 * We can treat these the same for the target,
				 * and not worry about the actual LUN id here.
				 */
				vioscsi_lun_changed(sc, target);
				break;
			default:
				/*
				 * Some other event we don't know about.
				 */
				break;
			}
			break;
		case VIRTIO_SCSI_T_NO_EVENT:
			/*
			 * If this happens, we missed some event(s).
			 */
			missed = B_TRUE;
			break;
		case VIRTIO_SCSI_T_ASYNC_NOTIFY:
			/*
			 * We don't register for these, so we don't expect
			 * them.
			 */
			break;
		}

		if (evt->event & VIRTIO_SCSI_T_EVENTS_MISSED) {
			missed = B_TRUE;
		}

		/*
		 * Resubmit the chain for the next event.
		 */
		virtio_chain_submit(vic, B_TRUE);
	}

	if (missed) {
		(void) ddi_taskq_dispatch(sc->vs_tq, vioscsi_discover, sc,
		    DDI_NOSLEEP);
	}

	return (DDI_INTR_CLAIMED);
}

uint_t
vioscsi_cmd_handler(caddr_t arg1, caddr_t arg2)
{
	vioscsi_softc_t *sc = (vioscsi_softc_t *)arg1;
	virtio_chain_t *vic;

	while ((vic = virtio_queue_poll(sc->vs_cmd_vq)) != NULL) {

		vioscsi_request_t *req;
		vioscsi_dev_t *vd;
		struct scsi_pkt *pkt;
		struct virtio_scsi_cmd_resp *res;

		virtio_chain_clear(vic);

		if ((req = virtio_chain_data(vic)) == NULL) {
			/*
			 * This should never occur, it's a bug if it does.
			 */
			dev_err(sc->vs_dip, CE_WARN, "missing cmd chain data");
			continue;
		}

		virtio_dma_sync(req->vr_dma, DDI_DMA_SYNC_FORKERNEL);
		res = &req->vr_res->cmd;
		pkt = req->vr_pkt;

		if (pkt == NULL) {
			/*
			 * This is an internal request (from discovery), and
			 * doesn't have an associated SCSI pkt structure.  In
			 * this case, the notification we've done is
			 * sufficient, and the submitter will examine the
			 * response field directly.
			 */
			if (req->vr_poll) {
				atomic_or_8(&req->vr_done, 1);
			}
			continue;
		}

		if ((vd = req->vr_dev) != NULL) {
			mutex_enter(&vd->vd_lock);
			vd->vd_num_cmd--;
			list_remove(&vd->vd_reqs, req);
			mutex_exit(&vd->vd_lock);
		}

		pkt->pkt_state = STATE_GOT_BUS;

		switch (res->response) {

		case VIRTIO_SCSI_S_OK:
			/*
			 * Request processed successfully, check SCSI status.
			 */
			pkt->pkt_scbp[0] = res->status;
			pkt->pkt_resid = 0;
			pkt->pkt_reason = CMD_CMPLT;
			pkt->pkt_state |= STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_GOT_STATUS;
			if ((pkt->pkt_numcookies > 0) &&
			    (pkt->pkt_cookies[0].dmac_size > 0)) {
				pkt->pkt_state |= STATE_XFERRED_DATA;
			}

			/*
			 * For CHECK_CONDITION, fill out the ARQ details:
			 */
			if (res->status == STATUS_CHECK) {
				/*
				 * ARQ status and arq structure:
				 */
				pkt->pkt_state |= STATE_ARQ_DONE;
				pkt->pkt_scbp[1] = STATUS_GOOD;
				struct scsi_arq_status *ars =
				    (void *)pkt->pkt_scbp;
				ars->sts_rqpkt_reason = CMD_CMPLT;
				ars->sts_rqpkt_resid = 0;
				ars->sts_rqpkt_state =
				    STATE_GOT_BUS | STATE_GOT_TARGET |
				    STATE_GOT_STATUS | STATE_SENT_CMD |
				    STATE_XFERRED_DATA;
				bcopy(res->sense, &ars->sts_sensedata,
				    MIN(sizeof (ars->sts_sensedata),
				    MIN(sc->vs_sense_size, res->sense_len)));
			}
			break;

		case VIRTIO_SCSI_S_BAD_TARGET:
		case VIRTIO_SCSI_S_INCORRECT_LUN:
		case VIRTIO_SCSI_S_TRANSPORT_FAILURE:
		case VIRTIO_SCSI_S_TARGET_FAILURE:
			pkt->pkt_reason = CMD_DEV_GONE;
			break;

		case VIRTIO_SCSI_S_OVERRUN:
			dev_err(sc->vs_dip, CE_WARN, "OVERRUN");
			pkt->pkt_reason = CMD_DATA_OVR;
			pkt->pkt_state |= STATE_GOT_TARGET | STATE_SENT_CMD;
			break;

		case VIRTIO_SCSI_S_RESET:
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_state |= STATE_GOT_TARGET | STATE_SENT_CMD;
			pkt->pkt_statistics |= STAT_DEV_RESET;
			break;

		case VIRTIO_SCSI_S_ABORTED:
			pkt->pkt_state |= STATE_GOT_TARGET | STATE_SENT_CMD;
			if (req->vr_expired) {
				pkt->pkt_statistics |= STAT_TIMEOUT;
				pkt->pkt_reason = CMD_TIMEOUT;
			} else {
				pkt->pkt_reason = CMD_ABORTED;
				pkt->pkt_statistics |= STAT_ABORTED;
			}
			break;

		case VIRTIO_SCSI_S_BUSY:
			/*
			 * Busy, should have been caught at submission:
			 */
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case VIRTIO_SCSI_S_NEXUS_FAILURE:
		case VIRTIO_SCSI_S_FAILURE:
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		default:
			dev_err(sc->vs_dip, CE_WARN, "Unknown response: 0x%x",
			    res->response);
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}

		if (!req->vr_poll) {
			scsi_hba_pkt_comp(pkt);
		} else {
			atomic_or_8(&req->vr_done, 1);
		}
	}
	return (DDI_INTR_CLAIMED);
}

static int
vioscsi_tran_tgt_init(dev_info_t *hdip, dev_info_t *tdip, scsi_hba_tran_t *tran,
    struct scsi_device *sd)
{
	const char *ua;
	vioscsi_softc_t *sc;
	int target;
	int lun;
	vioscsi_dev_t *vd;

	if (scsi_hba_iport_unit_address(hdip) == NULL) {
		return (DDI_FAILURE); /* only iport has targets */
	}
	if ((sc = tran->tran_hba_private) == NULL) {
		return (DDI_FAILURE);
	}

	if (((ua = scsi_device_unit_address(sd)) == NULL) ||
	    (!vioscsi_parse_unit_address(ua, &target, &lun))) {
		return (DDI_FAILURE);
	}

	vd = kmem_zalloc(sizeof (*vd), KM_SLEEP);
	list_create(&vd->vd_reqs, sizeof (vioscsi_request_t),
	    offsetof(vioscsi_request_t, vr_node));
	mutex_init(&vd->vd_lock, NULL, MUTEX_DRIVER,
	    virtio_intr_pri(sc->vs_virtio));

	vd->vd_target = (uint8_t)target;
	vd->vd_lun = (uint16_t)lun;
	vd->vd_sc = sc;
	vd->vd_sd = sd;
	vd->vd_max_cmd = sc->vs_cmd_per_lun;
	vd->vd_num_cmd = 0;

	scsi_device_hba_private_set(sd, vd);

	mutex_enter(&sc->vs_lock);
	list_insert_tail(&sc->vs_devs, vd);
	mutex_exit(&sc->vs_lock);

	return (DDI_SUCCESS);
}

static void
vioscsi_tran_tgt_free(dev_info_t *hdip, dev_info_t *tdip, scsi_hba_tran_t *tran,
    struct scsi_device *sd)
{
	vioscsi_dev_t *vd = scsi_device_hba_private_get(sd);
	vioscsi_softc_t *sc = vd->vd_sc;
	timeout_id_t tid;

	scsi_device_hba_private_set(sd, NULL);

	mutex_enter(&vd->vd_lock);
	tid = vd->vd_timeout;
	vd->vd_timeout = 0;
	mutex_exit(&vd->vd_lock);

	if (tid != 0) {
		(void) untimeout(tid);
	}

	mutex_enter(&sc->vs_lock);
	list_remove(&sc->vs_devs, vd);
	mutex_exit(&sc->vs_lock);

	list_destroy(&vd->vd_reqs);
	mutex_destroy(&vd->vd_lock);
	kmem_free(vd, sizeof (*vd));
}

/*
 * vioscsi_probe_target probes for existence of a valid target (LUN 0).
 * It utilizes the supplied request, and sends TEST UNIT READY.
 * (This command is used because it requires no data.)
 * It returns 1 if the target is found, 0 if not, and -1 on error.
 * It is expected additional LUNs will be discovered by the HBA framework using
 * REPORT LUNS on LUN 0.
 */
static int
vioscsi_probe_target(vioscsi_softc_t *sc, vioscsi_request_t *req,
    uint8_t target)
{
	struct virtio_scsi_cmd_req *cmd = &req->vr_req->cmd;
	struct virtio_scsi_cmd_resp *res = &req->vr_res->cmd;

	bzero(cmd, sizeof (*cmd));
	cmd->cdb[0] = SCMD_TEST_UNIT_READY;

	virtio_chain_clear(req->vr_vic);
	if (virtio_chain_append(req->vr_vic, req->vr_req_pa,
	    sizeof (*cmd), VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		return (-1);
	}
	if (virtio_chain_append(req->vr_vic, req->vr_res_pa,
	    sizeof (*res), VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		return (-1);
	}
	req->vr_poll = B_TRUE;
	req->vr_start = ddi_get_lbolt();
	req->vr_time = 10; /* seconds */
	req->vr_target = target;
	req->vr_lun = 0;
	req->vr_task_attr = VIRTIO_SCSI_S_HEAD;
	vioscsi_start(sc, req);
	switch (res->response) {
	case VIRTIO_SCSI_S_OK:
		return (1);
	case VIRTIO_SCSI_S_INCORRECT_LUN:
	case VIRTIO_SCSI_S_BAD_TARGET:
		return (0);
	default:
		return (-1);
	}
}

static void
vioscsi_rescan_luns(void *arg)
{
	vioscsi_softc_t		*sc = arg;
	vioscsi_dev_t		*vd;
	scsi_hba_tgtmap_t	*tm = sc->vs_tgtmap;
	list_t			*l;
	char			addr[16];

	l = &sc->vs_devs;
	mutex_enter(&sc->vs_lock);
	for (vd = list_head(l); vd != NULL; vd = list_next(l, vd)) {
		if (!vd->vd_rescan) {
			continue;
		}

		vd->vd_rescan = B_FALSE;
		(void) snprintf(addr, sizeof (addr), "%x", vd->vd_target);
		scsi_hba_tgtmap_scan_luns(tm, addr);
	}
	mutex_exit(&sc->vs_lock);
}

static void
vioscsi_lun_changed(vioscsi_softc_t *sc, uint8_t target)
{
	vioscsi_dev_t *vd;
	list_t *l = &sc->vs_devs;
	boolean_t found = B_FALSE;

	mutex_enter(&sc->vs_lock);
	for (vd = list_head(l); vd != NULL; vd = list_next(l, vd)) {
		if ((vd->vd_target == target) && (vd->vd_lun == 0)) {
			vd->vd_rescan = B_TRUE;
			found = B_TRUE;
			break;
		}
	}
	mutex_exit(&sc->vs_lock);

	if (found) {
		/*
		 * We have lun 0 already, so report luns changed:
		 */
		(void) ddi_taskq_dispatch(sc->vs_tq, vioscsi_rescan_luns,
		    sc, DDI_NOSLEEP);
	} else {
		/*
		 * We didn't find lun 0, so issue a new discovery:
		 */
		(void) ddi_taskq_dispatch(sc->vs_tq, vioscsi_discover,
		    sc, DDI_NOSLEEP);
	}
}

/*
 * vioscsi_discover is our task function for performing target and lun
 * discovery.  This is done using active SCSI probes.
 */
static void
vioscsi_discover(void *arg)
{
	vioscsi_softc_t *sc = arg;
	scsi_hba_tgtmap_t *tm = sc->vs_tgtmap;
	vioscsi_request_t req;
	uint32_t target;

	if (vioscsi_req_init(sc, &req, sc->vs_cmd_vq, KM_SLEEP) != 0) {
		vioscsi_req_fini(&req);
		return;
	}

	if (scsi_hba_tgtmap_set_begin(tm) != DDI_SUCCESS) {
		vioscsi_req_fini(&req);
		return;
	}
	for (target = 0;
	    target <= sc->vs_max_target && target < VIOSCSI_MAX_TARGET;
	    target++) {
		char ua[10];
		switch (vioscsi_probe_target(sc, &req, target)) {
		case 1:
			(void) snprintf(ua, sizeof (ua), "%x", target);
			if (scsi_hba_tgtmap_set_add(tm, SCSI_TGT_SCSI_DEVICE,
			    ua, NULL) != DDI_SUCCESS) {
				(void) scsi_hba_tgtmap_set_flush(tm);
				vioscsi_req_fini(&req);
				return;
			}
			break;
		case 0:
			continue;
		case -1:
			(void) scsi_hba_tgtmap_set_flush(tm);
			vioscsi_req_fini(&req);
			return;
		}
	}
	(void) scsi_hba_tgtmap_set_end(tm, 0);
	vioscsi_req_fini(&req);
}

static void
vioscsi_teardown(vioscsi_softc_t *sc, boolean_t failed)
{
	int instance = ddi_get_instance(sc->vs_dip);

	/*
	 * Free up the event resources:
	 */
	for (int i = 0; i < VIOSCSI_NUM_EVENTS; i++) {
		vioscsi_event_t *ve = &sc->vs_events[i];
		if (ve->ve_vic != NULL) {
			virtio_chain_free(ve->ve_vic);
		}
		if (ve->ve_dma != NULL) {
			virtio_dma_free(ve->ve_dma);
		}
	}

	if (sc->vs_virtio != NULL) {
		virtio_fini(sc->vs_virtio, failed);
	}

	if (sc->vs_tran != NULL) {
		scsi_hba_tran_free(sc->vs_tran);
	}
	if (sc->vs_tq != NULL) {
		ddi_taskq_destroy(sc->vs_tq);
	}
	if (sc->vs_intr_pri != NULL) {
		mutex_destroy(&sc->vs_lock);
	}
	ddi_soft_state_free(vioscsi_state, instance);
}

static int
vioscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	scsi_hba_tran_t *tran = NULL;
	vioscsi_softc_t *sc;
	virtio_t *vio;
	ddi_dma_attr_t attr;
	int instance;

	if (cmd != DDI_ATTACH) { /* no suspend/resume support */
		return (DDI_FAILURE);
	}

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (vioscsi_iport_attach(dip));
	}

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(vioscsi_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	sc = ddi_get_soft_state(vioscsi_state, instance);
	sc->vs_dip = dip;

	list_create(&sc->vs_devs, sizeof (vioscsi_dev_t),
	    offsetof(vioscsi_dev_t, vd_node));

	tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);
	sc->vs_tran = tran;

	tran->tran_hba_len = sizeof (vioscsi_request_t);
	tran->tran_hba_private = sc;

	/*
	 * We don't use WWN addressing, so advertise parallel.  The underlying
	 * device might still be using a different transport, even in a
	 * pass-through, but we cannot discriminate that at this layer.
	 */
	tran->tran_interconnect_type = INTERCONNECT_PARALLEL;

	tran->tran_start = vioscsi_tran_start;
	tran->tran_abort = vioscsi_tran_abort;
	tran->tran_reset = vioscsi_tran_reset;
	tran->tran_getcap = vioscsi_tran_getcap;
	tran->tran_setcap = vioscsi_tran_setcap;

	tran->tran_tgt_init = vioscsi_tran_tgt_init;
	tran->tran_tgt_free = vioscsi_tran_tgt_free;

	tran->tran_setup_pkt = vioscsi_tran_setup_pkt;
	tran->tran_teardown_pkt = vioscsi_tran_teardown_pkt;
	tran->tran_pkt_constructor = vioscsi_tran_pkt_constructor;
	tran->tran_pkt_destructor = vioscsi_tran_pkt_destructor;

	/*
	 * We need to determine some device settings here, so we initialize the
	 * virtio in order to access those values.  The rest of the setup we do
	 * in the iport attach.  Note that this driver cannot support
	 * reattaching a child iport once it is removed -- the entire driver
	 * will need to be reset for that.
	 */
	vio = virtio_init(dip);
	if ((sc->vs_virtio = vio) == NULL) {
		dev_err(dip, CE_WARN, "failed to init virtio");
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}
	if (!virtio_init_features(vio, VIOSCSI_WANTED_FEATURES, B_TRUE)) {
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}

	if (!virtio_features_present(vio, VIOSCSI_NEEDED_FEATURES)) {
		dev_err(dip, CE_WARN, "need features %b, have %b",
		    VIOSCSI_NEEDED_FEATURES, VIOSCSI_FEATURE_FORMAT,
		    virtio_features(vio), VIOSCSI_FEATURE_FORMAT);
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}
	/*
	 * Get virtio parameters:
	 */
	sc->vs_num_queues = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_NUM_QUEUES);
	sc->vs_seg_max = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_SEG_MAX);
	sc->vs_max_sectors = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_MAX_SECTORS);
	sc->vs_cmd_per_lun = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_CMD_PER_LUN);
	sc->vs_evi_size = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_EVI_SIZE);
	sc->vs_sense_size = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_SENSE_SIZE);
	sc->vs_cdb_size = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_CDB_SIZE);
	sc->vs_max_channel = virtio_dev_get16(vio, VIRTIO_SCSI_CFG_MAX_CHANNEL);
	sc->vs_max_target = virtio_dev_get16(vio, VIRTIO_SCSI_CFG_MAX_TARGET);
	sc->vs_max_lun = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_MAX_LUN);

	/*
	 * Check virtio parameter sanity.
	 */
#define	VIOSCSI_CHECK(var, op, val)					\
	do {								\
		if (!(sc->vs_ ##var op val)) {				\
			dev_err(dip, CE_WARN,				\
			    "!device config error: "#var" = %lx "	\
			    "(want "#op" %lx)", (uint64_t)sc->vs_ ##var,\
			    (uint64_t)val);				\
			sc->vs_ ##var = val;				\
		}							\
	} while (0)

	/*
	 * max_sectors determines the maxxfer size of our DMA attributes.
	 * This needs to be at least PAGESIZE. The virtio spec doesn't spell
	 * it out explicitly, but max_sectors is in units of 512 bytes.
	 */
	VIOSCSI_CHECK(max_sectors, >=, 1 << (PAGESHIFT - 9));

	/*
	 * seg_max is the maximum number of data segments (aka SGL entries)
	 * the device can handle in a single command. (If we supported INOUT,
	 * each command can have seg_max input segments and seg_max output
	 * segments, but we don't.)
	 *
	 * We cap this at VIOSCSI_MAX_SEGS just in case.
	 *
	 * This does not include the 2 segments needed for input and output
	 * headers, hence we add 2 in the call to virtio_queue_alloc() below.
	 */
	VIOSCSI_CHECK(seg_max, >=, VIOSCSI_MIN_SEGS);
	VIOSCSI_CHECK(seg_max, <=, VIOSCSI_MAX_SEGS);
	VIOSCSI_CHECK(cmd_per_lun, >=, 1);
	VIOSCSI_CHECK(evi_size, <=, sizeof (vioscsi_evt_t));
	VIOSCSI_CHECK(cdb_size, ==, VIRTIO_SCSI_CDB_SIZE);
	VIOSCSI_CHECK(sense_size, ==, VIRTIO_SCSI_SENSE_SIZE);
	VIOSCSI_CHECK(max_channel, ==, 0);
	VIOSCSI_CHECK(max_target, <=, VIOSCSI_MAX_TARGET - 1);
	VIOSCSI_CHECK(max_lun, <=, VIOSCSI_MAX_LUN - 1);
#undef	VIOSCSI_CHECK

	/*
	 * Allocate queues
	 */
	sc->vs_ctl_vq = virtio_queue_alloc(vio, 0, "ctl",
	    vioscsi_ctl_handler, sc, B_FALSE, sc->vs_seg_max + 2);
	sc->vs_evt_vq = virtio_queue_alloc(vio, 1, "evt",
	    vioscsi_evt_handler, sc, B_FALSE, sc->vs_seg_max + 2);
	sc->vs_cmd_vq = virtio_queue_alloc(vio, 2, "cmd",
	    vioscsi_cmd_handler, sc, B_FALSE, sc->vs_seg_max + 2);

	if ((sc->vs_ctl_vq == NULL) || (sc->vs_evt_vq == NULL) ||
	    (sc->vs_cmd_vq == NULL)) {
		dev_err(dip, CE_WARN, "failed allocating queue(s)");
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}

	if (virtio_init_complete(vio, VIRTIO_ANY_INTR_TYPE) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "virtio_init_complete failed");
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}

	/*
	 * We cannot initialize this mutex before virtio_init_complete:
	 */
	sc->vs_intr_pri = virtio_intr_pri(vio);
	mutex_init(&sc->vs_lock, NULL, MUTEX_DRIVER, sc->vs_intr_pri);

	/*
	 * Allocate events, but do not submit yet:
	 */
	for (int i = 0; i < VIOSCSI_NUM_EVENTS; i++) {
		vioscsi_event_t *ve = &sc->vs_events[i];
		ve->ve_vic = virtio_chain_alloc(sc->vs_evt_vq, KM_SLEEP);
		ve->ve_dma = virtio_dma_alloc(sc->vs_virtio,
		    sizeof (vioscsi_evt_t), &virtio_dma_attr,
		    DDI_DMA_STREAMING | DDI_DMA_READ, KM_SLEEP);
		if ((ve->ve_vic == NULL) || (ve->ve_dma == NULL)) {
			vioscsi_teardown(sc, B_TRUE);
			return (DDI_FAILURE);
		}
		if (virtio_chain_append(ve->ve_vic,
		    virtio_dma_cookie_pa(ve->ve_dma, 0), sizeof (*ve->ve_evt),
		    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
			vioscsi_teardown(sc, B_TRUE);
			return (DDI_FAILURE);
		}
		ve->ve_evt = virtio_dma_va(ve->ve_dma, 0);
		virtio_chain_data_set(ve->ve_vic, ve);
	}

	sc->vs_tq = ddi_taskq_create(dip, "task", 1, TASKQ_DEFAULTPRI, 0);
	if (sc->vs_tq == NULL) {
		dev_err(dip, CE_WARN, "failed to create taskq");
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}

	/* Adjust DMA limits. */
	attr = virtio_dma_attr;
	attr.dma_attr_sgllen = sc->vs_seg_max;
	attr.dma_attr_maxxfer = (uint64_t)sc->vs_max_sectors << 9;

	if (scsi_hba_attach_setup(dip, &attr, tran,
	    SCSI_HBA_ADDR_COMPLEX | SCSI_HBA_HBA |
	    SCSI_HBA_TRAN_CDB | SCSI_HBA_TRAN_SCB) !=
	    DDI_SUCCESS) {
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}

	if (scsi_hba_iport_register(dip, "iport0") != DDI_SUCCESS) {
		vioscsi_teardown(sc, B_TRUE);
		return (DDI_FAILURE);
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static void
vioscsi_iport_teardown(vioscsi_softc_t *sc)
{
	/*
	 * Stop the taskq -- ensures we don't try to access resources from a
	 * task while we are tearing down.
	 */
	ddi_taskq_suspend(sc->vs_tq);
	ddi_taskq_wait(sc->vs_tq);

	/*
	 * Shutdown all interrupts and device transfers:
	 */
	virtio_interrupts_disable(sc->vs_virtio);
	virtio_shutdown(sc->vs_virtio);

	/*
	 * Common resources:
	 */
	if (sc->vs_tgtmap != NULL) {
		scsi_hba_tgtmap_destroy(sc->vs_tgtmap);
		sc->vs_tgtmap = NULL;
	}
}

/*
 * vioscsi_iport_attach implements the attach of the iport.  We do the final
 * set up of interrupts, and posting of event buffers here, as we do not want
 * any activity unless the iport is attached.  This matches detach, and makes
 * teardown safer.
 */
static int
vioscsi_iport_attach(dev_info_t *dip)
{
	const char *ua = scsi_hba_iport_unit_address(dip);
	scsi_hba_tran_t *tran;
	vioscsi_softc_t *sc;

	/*
	 * We only support a single iport -- all disks are virtual and all
	 * disks use target/lun addresses.
	 */
	if ((ua == NULL) || (strcmp(ua, "iport0") != 0)) {
		return (DDI_FAILURE);
	}

	/*
	 * Get our parent's tran, and look up the sc from that:
	 */
	tran = ddi_get_driver_private(ddi_get_parent(dip));
	if ((tran == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}

	/*
	 * Save a copy of the soft state in our tran private area.
	 * (The framework clears this after cloning from parent.)
	 */
	tran = ddi_get_driver_private(dip);
	tran->tran_hba_private = sc;

	/*
	 * We don't want interrupts on the control queue -- strictly polled
	 * (however if this handler is called from an interrupt, it should
	 * still be absolutely fine).
	 */
	virtio_queue_no_interrupt(sc->vs_ctl_vq, B_TRUE);

	if (scsi_hba_tgtmap_create(dip, SCSI_TM_FULLSET, MICROSEC,
	    2 * MICROSEC, sc, NULL, NULL, &sc->vs_tgtmap) != DDI_SUCCESS) {
		vioscsi_iport_teardown(sc);
		return (DDI_FAILURE);
	}

	/*
	 * Post events:
	 */
	for (int i = 0; i < VIOSCSI_NUM_EVENTS; i++) {
		virtio_chain_submit(sc->vs_events[i].ve_vic, B_FALSE);
	}
	virtio_queue_flush(sc->vs_evt_vq);

	/*
	 * Start interrupts going now:
	 */
	if (virtio_interrupts_enable(sc->vs_virtio) != DDI_SUCCESS) {
		vioscsi_iport_teardown(sc);
		return (DDI_FAILURE);
	}

	/*
	 * Start a discovery:
	 */
	(void) ddi_taskq_dispatch(sc->vs_tq, vioscsi_discover, sc, DDI_SLEEP);

	return (DDI_SUCCESS);
}

static int
vioscsi_quiesce(dev_info_t *dip)
{
	vioscsi_softc_t *sc;
	scsi_hba_tran_t *tran;

	if (((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}
	if (sc->vs_virtio == NULL) {
		return (DDI_SUCCESS); /* not initialized yet */
	}

	return (virtio_quiesce(sc->vs_virtio));
}

/*
 * vioscsi_iport_detach is used to perform the detach of the iport.  It
 * disables interrupts and the device, but does not free resources, other than
 * the target map.  Note that due to lack of a way to start virtio after
 * virtio_shutdown(), it is not possible to reattach the iport after this is
 * called, unless the underlying HBA is also detached and then re-attached.
 */
static int
vioscsi_iport_detach(dev_info_t *dip)
{
	const char *ua = scsi_hba_iport_unit_address(dip);
	vioscsi_softc_t *sc;
	scsi_hba_tran_t *tran;

	if ((ua == NULL) || (strcmp(ua, "iport0") != 0)) {
		return (DDI_FAILURE);
	}

	if (((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}

	mutex_enter(&sc->vs_lock);
	if (!list_is_empty(&sc->vs_devs)) {
		/*
		 * Cannot detach while we have target children.
		 */
		mutex_exit(&sc->vs_lock);
		return (DDI_FAILURE);
	}

	vioscsi_iport_teardown(sc);

	return (DDI_SUCCESS);
}

static int
vioscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vioscsi_softc_t *sc;
	scsi_hba_tran_t *tran;

	if (cmd != DDI_DETACH)  {
		return (DDI_FAILURE);
	}

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (vioscsi_iport_detach(dip));
	}

	if (((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}

	if (scsi_hba_detach(dip) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	vioscsi_teardown(sc, B_FALSE);

	return (DDI_SUCCESS);
}

static struct dev_ops vioscsi_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		nodev,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		vioscsi_attach,
	.devo_detach =		vioscsi_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		NULL,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		vioscsi_quiesce,
};

static struct modldrv modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		vioscsi_ident,
	.drv_dev_ops =		&vioscsi_dev_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &modldrv, NULL, },
};


int
_init(void)
{
	int err;

	/*
	 * Initialize this unconditionally:
	 */
	vioscsi_hz = drv_usectohz(1000000);

	err = ddi_soft_state_init(&vioscsi_state, sizeof (vioscsi_softc_t), 1);
	if (err != DDI_SUCCESS)
		return (err);

	if ((err = scsi_hba_init(&modlinkage)) != 0) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		scsi_hba_fini(&modlinkage);
		return (err);
	}

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0) {
		return (err);
	}

	scsi_hba_fini(&modlinkage);
	ddi_soft_state_fini(&vioscsi_state);

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
