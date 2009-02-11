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

/*
 * 1394 mass storage SBP-2 driver routines
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/targets/scsa1394/impl.h>
#include <sys/1394/targets/scsa1394/cmd.h>
#include <sys/sbp2/bus.h>
#include <sys/sbp2/driver.h>

static void	scsa1394_sbp2_detect_symbios(scsa1394_state_t *);
static void	scsa1394_sbp2_worker_thread(void *);
static void	scsa1394_sbp2_status_cb(void *, sbp2_task_t *);
static void	scsa1394_sbp2_seg2pt_default(scsa1394_lun_t *,
		scsa1394_cmd_t *);
static void	scsa1394_sbp2_seg2pt_symbios(scsa1394_lun_t *,
		scsa1394_cmd_t *);
static void	scsa1394_sbp2_req_status(scsa1394_lun_t *);
static void	scsa1394_sbp2_status_proc(scsa1394_lun_t *, scsa1394_cmd_t *,
		scsa1394_status_t *);
static int	scsa1394_sbp2_conv_status(scsa1394_cmd_t *,
		scsa1394_status_t *);
static void	scsa1394_sbp2_reset_proc(scsa1394_lun_t *, int,
		scsa1394_cmd_t *);
static boolean_t scsa1394_sbp2_logged_in(scsa1394_lun_t *);

extern sbp2_bus_t scsa1394_sbp2_bus;

/* tunables */
uint_t scsa1394_sbp2_max_payload_sub = 2;
extern int scsa1394_symbios_size_max;
extern int scsa1394_symbios_page_size;
extern int scsa1394_wrka_symbios;

/* symbios workaround will be applied unless device is on this list */
scsa1394_bw_list_t scsa1394_sbp2_symbios_whitelist[] = {
	{ SCSA1394_BW_ONE, 0x0a27 },		/* Apple */
	{ SCSA1394_BW_ONE, 0xd04b }		/* LaCie */
};

/*
 *
 * --- SBP-2 routines
 *
 */
int
scsa1394_sbp2_attach(scsa1394_state_t *sp)
{
	sbp2_tgt_t	*tp;
	scsa1394_lun_t	*lp;
	int		i;

	/*
	 * target
	 */
	if (sbp2_tgt_init(sp, &scsa1394_sbp2_bus, NLUNS_PER_TARGET,
	    &sp->s_tgt) != SBP2_SUCCESS) {
		return (DDI_FAILURE);
	}
	tp = sp->s_tgt;

	/*
	 * luns
	 */
	sp->s_nluns = tp->t_nluns;
	sp->s_lun = kmem_zalloc(sp->s_nluns * sizeof (scsa1394_lun_t),
	    KM_SLEEP);

	for (i = 0; i < sp->s_nluns; i++) {
		lp = &sp->s_lun[i];

		mutex_init(&lp->l_mutex, NULL, MUTEX_DRIVER,
		    sp->s_attachinfo.iblock_cookie);

		lp->l_rmb_orig = -1;
		lp->l_lun = &tp->t_lun[i];
		lp->l_sp = sp;
		lp->l_lba_size = DEV_BSIZE;
	}

	scsa1394_sbp2_detect_symbios(sp);

	return (DDI_SUCCESS);
}

void
scsa1394_sbp2_detach(scsa1394_state_t *sp)
{
	int		i;
	scsa1394_lun_t	*lp;

	for (i = 0; i < sp->s_nluns; i++) {
		lp = &sp->s_lun[i];
		if (lp->l_sp != NULL) {
			mutex_destroy(&lp->l_mutex);
		}
	}

	kmem_free(sp->s_lun, sp->s_nluns * sizeof (scsa1394_lun_t));
	sbp2_tgt_fini(sp->s_tgt);
}

static void
scsa1394_sbp2_detect_symbios(scsa1394_state_t *sp)
{
	sbp2_cfgrom_ent_t *root = &sp->s_tgt->t_cfgrom.cr_root;
	sbp2_cfgrom_ent_t *ent;
	scsa1394_bw_list_t *wl;
	int	vid;
	int	i;


	if (!scsa1394_wrka_symbios) {
		sp->s_symbios = B_FALSE;
		return;
	} else {
		sp->s_symbios = B_TRUE;
	}

	/* get device's vendor ID */
	if ((ent = sbp2_cfgrom_ent_by_key(root, IEEE1212_IMMEDIATE_TYPE,
	    IEEE1212_MODULE_VENDOR_ID, 0)) == NULL) {
		return;
	}
	vid = ent->ce_data.imm;

	/* find a match in the whitelist */
	for (i = 0; i < NELEM(scsa1394_sbp2_symbios_whitelist); i++) {
		wl = &scsa1394_sbp2_symbios_whitelist[i];
		if ((wl->vid_match == SCSA1394_BW_ONE) && (wl->vid == vid)) {
			sp->s_symbios = B_FALSE;
			break;
		}
	}
}


/*
 * functional equivalent of ddi_rep_get32() with big endian access handle
 */
static void
bcopy_swap32(uint32_t *from, uint32_t *to, int count)
{
	int		i;
	uint32_t	data;

	ASSERT((uintptr_t)to % 4 == 0);

	for (i = 0; i < count; i++) {
		data = *from++;
		*to++ = SBP2_SWAP32(data);
	}
}

/*
 * Build an inquiry for a given device that doesn't like inquiry commands.
 */
void
scsa1394_sbp2_fake_inquiry(scsa1394_state_t *sp, struct scsi_inquiry *inq)
{
	sbp2_cfgrom_ent_t *r = &sp->s_tgt->t_cfgrom.cr_root;
	sbp2_cfgrom_ent_t *e, *eref, *evid;
	int	i, len;

	bzero(inq, sizeof (struct scsi_inquiry));

	inq->inq_dtype = DTYPE_DIRECT;
	inq->inq_rmb = 1;
	inq->inq_ansi = 2;
	inq->inq_rdf = RDF_SCSI2;
	inq->inq_len = sizeof (struct scsi_inquiry) - 4;

	(void) memset(inq->inq_vid, ' ', sizeof (inq->inq_vid));
	(void) memset(inq->inq_pid, ' ', sizeof (inq->inq_pid));
	(void) memset(inq->inq_revision, ' ', sizeof (inq->inq_revision));

	/*
	 * vid/pid/rev can be derived from Config ROM textual descriptors
	 */
	for (i = 0; i < 256; i++) {
		if ((e = sbp2_cfgrom_ent_by_key(r, IEEE1212_LEAF_TYPE,
		    IEEE1212_TEXTUAL_DESCRIPTOR, i)) == NULL) {
			break;
		}
		eref = e->ce_ref;
		if ((eref == NULL) || (eref->ce_len < 3) &&
		    (eref->ce_kt != IEEE1212_IMMEDIATE_TYPE)) {
			continue;
		}

		len = e->ce_len - 2;
		if (eref->ce_kv == IEEE1212_MODULE_VENDOR_ID) {
			evid = e;
			bcopy_swap32(&e->ce_data.leaf[2],
			    (uint32_t *)inq->inq_vid,
			    min(sizeof (inq->inq_vid) / 4, len));
		} else if (eref->ce_kv == 0x17) {
			bcopy_swap32(&e->ce_data.leaf[2],
			    (uint32_t *)inq->inq_pid,
			    min(sizeof (inq->inq_pid) / 4, len));
		} else if ((eref->ce_kv == IEEE1212_MODULE_HW_VERSION) ||
		    (eref == evid)) {
			bcopy_swap32(&e->ce_data.leaf[2],
			    (uint32_t *)inq->inq_revision,
			    min(sizeof (inq->inq_revision) / 4, len));
		}
	}
}

int
scsa1394_sbp2_threads_init(scsa1394_state_t *sp)
{
	scsa1394_lun_t		*lp;
	scsa1394_thread_t	*thr;
	int			i;

	for (i = 0; i < sp->s_nluns; i++) {
		lp = &sp->s_lun[i];
		thr = &lp->l_worker_thread;

		thr->thr_func = scsa1394_sbp2_worker_thread;
		thr->thr_arg = thr;
		thr->thr_state = SCSA1394_THR_INIT;
		cv_init(&thr->thr_cv, NULL, CV_DRIVER, NULL);
		thr->thr_lun = lp;
		thr->thr_req = 0;

		mutex_enter(&lp->l_mutex);
		if (scsa1394_thr_dispatch(thr) != DDI_SUCCESS) {
			mutex_exit(&lp->l_mutex);
			scsa1394_sbp2_threads_fini(sp);
			return (DDI_FAILURE);
		}
		mutex_exit(&lp->l_mutex);
	}

	return (DDI_SUCCESS);
}

void
scsa1394_sbp2_threads_fini(scsa1394_state_t *sp)
{
	scsa1394_lun_t		*lp;
	scsa1394_thread_t	*thr;
	int			i;

	for (i = 0; i < sp->s_nluns; i++) {
		lp = &sp->s_lun[i];
		thr = &lp->l_worker_thread;

		/* if thread wasn't initialized, thr_lun will be NULL */
		if (thr->thr_lun == lp) {
			mutex_enter(&lp->l_mutex);
			scsa1394_thr_cancel(thr);
			mutex_exit(&lp->l_mutex);
			ASSERT(thr->thr_state != SCSA1394_THR_RUN);
			cv_destroy(&thr->thr_cv);
		}
	}
}

int
scsa1394_sbp2_get_lun_type(scsa1394_lun_t *lp)
{
	return (lp->l_lun->l_type);
}

int
scsa1394_sbp2_login(scsa1394_state_t *sp, int lun)
{
	scsa1394_lun_t	*lp = &sp->s_lun[lun];
	int		berr;

	if (sbp2_lun_login(lp->l_lun, &lp->l_ses,
	    scsa1394_sbp2_status_cb, lp, &berr) != SBP2_SUCCESS) {
		return (DDI_FAILURE);
	}
	ASSERT(lp->l_ses != NULL);
	return (DDI_SUCCESS);
}

void
scsa1394_sbp2_logout(scsa1394_state_t *sp, int lun, boolean_t phys)
{
	scsa1394_lun_t	*lp = &sp->s_lun[lun];
	int		berr;

	if (scsa1394_sbp2_logged_in(lp)) {
		(void) sbp2_lun_logout(lp->l_lun, &lp->l_ses, &berr, phys);
	}
}

void
scsa1394_sbp2_req(scsa1394_state_t *sp, int lun, int req)
{
	scsa1394_lun_t	*lp = &sp->s_lun[lun];

	if (lp != NULL) {
		mutex_enter(&lp->l_mutex);
		scsa1394_thr_wake(&lp->l_worker_thread, req);
		mutex_exit(&lp->l_mutex);
	}
}

void
scsa1394_sbp2_req_bus_reset(scsa1394_lun_t *lp)
{
	scsa1394_state_t	*sp = lp->l_sp;
	int			berr = 0;

	if (t1394_get_targetinfo(sp->s_t1394_hdl, SCSA1394_BUSGEN(sp), 0,
	    &sp->s_targetinfo) != DDI_SUCCESS) {
		goto disconnect;
	}

	if (sp->s_targetinfo.target_nodeID == T1394_INVALID_NODEID) {
		goto disconnect;
	}

	if (!scsa1394_sbp2_logged_in(lp)) {
		/* reconnect procedure is only for logged in hosts */
		return;
	}

	/*
	 * Try SBP-2 RECONNECT procedure first. Note that we're passing
	 * local Node ID, which might have changed during bus reset.
	 * sbp2_ses_reconnect() will use it to update the ORBs.
	 */
	if (sbp2_ses_reconnect(lp->l_ses, &berr,
	    SCSA1394_NODEID(sp)) == SBP2_SUCCESS) {
		mutex_enter(&sp->s_mutex);
		sp->s_dev_state = SCSA1394_DEV_ONLINE;
		mutex_exit(&sp->s_mutex);

		/* resume task processing */
		scsa1394_sbp2_nudge(lp);

		return;
	}

	if (berr == CMD1394_EDEVICE_REMOVED) {
		goto disconnect;
	}

	/* reconnect failed, try to logout and login again */
	scsa1394_sbp2_flush_cmds(lp, CMD_TRAN_ERR, 0, STAT_BUS_RESET);
	(void) sbp2_lun_logout(lp->l_lun, &lp->l_ses, &berr, B_FALSE);

	if (scsa1394_sbp2_login(sp, 0) != SBP2_SUCCESS) {
		goto disconnect;
	}

	mutex_enter(&sp->s_mutex);
	sp->s_dev_state = SCSA1394_DEV_ONLINE;
	mutex_exit(&sp->s_mutex);

	return;

disconnect:
	mutex_enter(&sp->s_mutex);
	sp->s_dev_state = SCSA1394_DEV_DISCONNECTED;
	mutex_exit(&sp->s_mutex);
	if (scsa1394_sbp2_logged_in(lp)) {
		scsa1394_sbp2_flush_cmds(lp, CMD_DEV_GONE, 0, STAT_BUS_RESET);
		(void) sbp2_lun_logout(lp->l_lun, &lp->l_ses, &berr, B_FALSE);
	}
}

/*ARGSUSED*/
void
scsa1394_sbp2_req_reconnect(scsa1394_lun_t *lp)
{
	scsa1394_state_t	*sp = lp->l_sp;

	if (t1394_get_targetinfo(sp->s_t1394_hdl, SCSA1394_BUSGEN(sp), 0,
	    &sp->s_targetinfo) != DDI_SUCCESS) {
		return;
	}

	mutex_enter(&sp->s_mutex);
	sp->s_dev_state = SCSA1394_DEV_ONLINE;
	mutex_exit(&sp->s_mutex);

	if (sbp2_tgt_reconnect(sp->s_tgt) != SBP2_SUCCESS) {
		goto disconnect;
	}

	if (scsa1394_sbp2_login(sp, 0) != SBP2_SUCCESS) {
		goto disconnect;
	}

	cmn_err(CE_WARN, "scsa1394(%d): "
	    "Reinserted device is accessible again.\n", sp->s_instance);

	return;

disconnect:
	mutex_enter(&sp->s_mutex);
	sp->s_dev_state = SCSA1394_DEV_DISCONNECTED;
	mutex_exit(&sp->s_mutex);
}

void
scsa1394_sbp2_disconnect(scsa1394_state_t *sp)
{
	scsa1394_lun_t	*lp = &sp->s_lun[0];
	int		berr;

	scsa1394_sbp2_flush_cmds(lp, CMD_DEV_GONE, 0, STAT_BUS_RESET);
	if (scsa1394_sbp2_logged_in(lp)) {
		(void) sbp2_lun_logout(lp->l_lun, &lp->l_ses, &berr, B_FALSE);
	}
	sbp2_tgt_disconnect(sp->s_tgt);
}

/*
 * convert segment array into DMA-mapped SBP-2 page table
 */
void
scsa1394_sbp2_seg2pt(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	scsa1394_state_t	*sp = lp->l_sp;

	ASSERT(cmd->sc_flags & SCSA1394_CMD_DMA_BUF_PT_VALID);

	if (sp->s_symbios) {
		scsa1394_sbp2_seg2pt_symbios(lp, cmd);
	} else {
		scsa1394_sbp2_seg2pt_default(lp, cmd);
	}
}

/*ARGSUSED*/
static void
scsa1394_sbp2_seg2pt_default(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	sbp2_pt_unrestricted_t *pt;
	scsa1394_cmd_seg_t *seg;
	int		i;

	pt = (sbp2_pt_unrestricted_t *)cmd->sc_pt_kaddr;
	seg = &cmd->sc_buf_seg[0];
	for (i = 0; i < cmd->sc_buf_nsegs; i++) {
		pt->pt_seg_len = SBP2_SWAP16(seg->ss_len);
		pt->pt_seg_base_hi = SBP2_SWAP16(seg->ss_baddr >> 32);
		pt->pt_seg_base_lo = SBP2_SWAP32(seg->ss_baddr & 0xFFFFFFFF);

		pt++;
		seg++;
	}
	(void) ddi_dma_sync(cmd->sc_pt_dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	cmd->sc_pt_cmd_size = cmd->sc_buf_nsegs;
}

/*
 * fill page table for Symbios workaround
 */
/*ARGSUSED*/
static void
scsa1394_sbp2_seg2pt_symbios(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	sbp2_pt_unrestricted_t *pt;
	scsa1394_cmd_seg_t *seg;
	int		nsegs;
	size_t		resid, skiplen, dataoff, segoff, seglen;
	uint64_t	baddr;

	/* data offset within command */
	if (cmd->sc_flags & SCSA1394_CMD_SYMBIOS_BREAKUP) {
		dataoff = (cmd->sc_total_blks - cmd->sc_resid_blks) *
		    cmd->sc_blk_size;
	} else {
		dataoff = 0;
	}

	/* skip dataoff bytes */
	seg = &cmd->sc_buf_seg[0];
	skiplen = 0;
	while (skiplen + seg->ss_len <= dataoff) {
		skiplen += seg->ss_len;
		seg++;
	}
	segoff = dataoff - skiplen; /* offset within segment */

	pt = (sbp2_pt_unrestricted_t *)cmd->sc_pt_kaddr;
	resid = cmd->sc_xfer_bytes;
	nsegs = 0;
	while (resid > 0) {
		ASSERT(seg->ss_len <= scsa1394_symbios_page_size);

		seglen = min(seg->ss_len, resid) - segoff;
		baddr = seg->ss_baddr + segoff;

		pt->pt_seg_len = SBP2_SWAP16(seglen);
		pt->pt_seg_base_hi = SBP2_SWAP16(baddr >> 32);
		pt->pt_seg_base_lo = SBP2_SWAP32(baddr & 0xFFFFFFFF);

		segoff = 0;
		resid -= seglen;
		nsegs++;
		pt++;
		seg++;
	}
	(void) ddi_dma_sync(cmd->sc_pt_dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	cmd->sc_pt_cmd_size = nsegs;
}

/*
 * convert command into DMA-mapped SBP-2 ORB
 */
void
scsa1394_sbp2_cmd2orb(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	scsa1394_state_t *sp = lp->l_sp;
	scsa1394_cmd_orb_t *orb = sbp2_task_orb_kaddr(&cmd->sc_task);

	mutex_enter(&lp->l_mutex);

	lp->l_stat.stat_cmd_cnt++;

	bzero(orb->co_cdb, sizeof (orb->co_cdb));

	/* CDB */
	bcopy(cmd->sc_cdb, orb->co_cdb, cmd->sc_cdb_actual_len);

	/*
	 * ORB parameters
	 *
	 * use max speed and max payload for this speed.
	 * max async data transfer for a given speed is 512<<speed
	 * SBP-2 defines (see 5.1.2) max data transfer as 2^(max_payload+2),
	 * hence max_payload = 7 + speed
	 */
	orb->co_params = SBP2_ORB_NOTIFY | SBP2_ORB_RQ_FMT_SBP2 |
	    (sp->s_targetinfo.current_max_speed << SBP2_ORB_CMD_SPD_SHIFT) |
	    ((7 + sp->s_targetinfo.current_max_speed -
	    scsa1394_sbp2_max_payload_sub) << SBP2_ORB_CMD_MAX_PAYLOAD_SHIFT);

	/* direction: initiator's read is target's write (and vice versa) */
	if (cmd->sc_flags & SCSA1394_CMD_READ) {
		orb->co_params |= SBP2_ORB_CMD_DIR;
	}

	/*
	 * data_size and data_descriptor
	 */
	if (cmd->sc_buf_nsegs == 0) {
		/* no data */
		orb->co_data_size = 0;
		SCSA1394_ADDR_SET(sp, orb->co_data_descr, 0);
	} else if (cmd->sc_buf_nsegs == 1) {
		/* contiguous buffer - use direct addressing */
		ASSERT(cmd->sc_buf_seg[0].ss_len != 0);
		orb->co_data_size = SBP2_SWAP16(cmd->sc_buf_seg[0].ss_len);
		SCSA1394_ADDR_SET(sp, orb->co_data_descr,
		    cmd->sc_buf_seg[0].ss_baddr);
	} else {
		/* non-contiguous s/g list - page table */
		ASSERT(cmd->sc_pt_cmd_size > 0);
		orb->co_params |= SBP2_ORB_CMD_PT;
		orb->co_data_size = SBP2_SWAP16(cmd->sc_pt_cmd_size);
		SCSA1394_ADDR_SET(sp, orb->co_data_descr, cmd->sc_pt_baddr);
	}

	SBP2_SWAP16_1(orb->co_params);

	SBP2_ORBP_SET(orb->co_next_orb, SBP2_ORBP_NULL);

	mutex_exit(&lp->l_mutex);

	sbp2_task_orb_sync(lp->l_lun, &cmd->sc_task, DDI_DMA_SYNC_FORDEV);
}


/*ARGSUSED*/
int
scsa1394_sbp2_start(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	sbp2_task_t	*task = CMD2TASK(cmd);
	int		ret;

	ASSERT(lp->l_ses != NULL);

	task->ts_timeout = cmd->sc_timeout;
	task->ts_error = SBP2_TASK_ERR_NONE;
	task->ts_bus_error = 0;
	task->ts_state = SBP2_TASK_INIT;

	ret = sbp2_ses_submit_task(lp->l_ses, task);

	if ((ret == SBP2_SUCCESS) || (ret == SBP2_ECONTEXT)) {
		return (TRAN_ACCEPT);
	} if (task->ts_error == SBP2_TASK_ERR_BUS) {
		if (task->ts_bus_error == CMD1394_EDEVICE_BUSY) {
			return (TRAN_BUSY);
		} else {
			return (TRAN_FATAL_ERROR);
		}
	} else {
		return (TRAN_FATAL_ERROR);
	}
}

/*
 * This function is called by SBP-2 layer when task status is received,
 * typically from interrupt handler. Just wake the thread to do the actual work.
 */
/*ARGSUSED*/
static void
scsa1394_sbp2_status_cb(void *arg, sbp2_task_t *task)
{
	scsa1394_lun_t		*lp = (scsa1394_lun_t *)arg;

	mutex_enter(&lp->l_mutex);
	scsa1394_thr_wake(&lp->l_worker_thread, SCSA1394_THREQ_TASK_STATUS);
	mutex_exit(&lp->l_mutex);
}

void
scsa1394_sbp2_nudge(scsa1394_lun_t *lp)
{
	mutex_enter(&lp->l_mutex);
	scsa1394_thr_wake(&lp->l_worker_thread, SCSA1394_THREQ_NUDGE);
	mutex_exit(&lp->l_mutex);
}

/*
 * worker thread
 */
static void
scsa1394_sbp2_worker_thread(void *arg)
{
	scsa1394_thread_t	*thr = (scsa1394_thread_t *)arg;
	scsa1394_lun_t		*lp = thr->thr_lun;

	mutex_enter(&lp->l_mutex);
	for (;;) {
		while (thr->thr_req == 0) {
			cv_wait(&thr->thr_cv, &lp->l_mutex);
		}
		if (thr->thr_req & SCSA1394_THREQ_EXIT) {
			break;
		}
		if (thr->thr_req & SCSA1394_THREQ_BUS_RESET) {
			thr->thr_req &= ~SCSA1394_THREQ_BUS_RESET;
			mutex_exit(&lp->l_mutex);
			scsa1394_sbp2_req_bus_reset(lp);
			mutex_enter(&lp->l_mutex);
			continue;
		}
		if (thr->thr_req & SCSA1394_THREQ_RECONNECT) {
			thr->thr_req &= ~SCSA1394_THREQ_RECONNECT;
			mutex_exit(&lp->l_mutex);
			scsa1394_sbp2_req_reconnect(lp);
			mutex_enter(&lp->l_mutex);
			continue;
		}
		if (thr->thr_req & SCSA1394_THREQ_TASK_STATUS) {
			thr->thr_req &= ~SCSA1394_THREQ_TASK_STATUS;
			mutex_exit(&lp->l_mutex);
			scsa1394_sbp2_req_status(lp);
			mutex_enter(&lp->l_mutex);
			continue;
		}
		if (thr->thr_req & SCSA1394_THREQ_NUDGE) {
			thr->thr_req &= ~SCSA1394_THREQ_NUDGE;
			mutex_exit(&lp->l_mutex);
			if (scsa1394_sbp2_logged_in(lp)) {
				sbp2_ses_nudge(lp->l_ses);
			}
			mutex_enter(&lp->l_mutex);
			continue;
		}
	}
	thr->thr_state = SCSA1394_THR_EXIT;
	cv_signal(&thr->thr_cv);
	mutex_exit(&lp->l_mutex);
}

/*
 * task status handler
 */
static void
scsa1394_sbp2_req_status(scsa1394_lun_t *lp)
{
	sbp2_ses_t		*sp = lp->l_ses;
	sbp2_task_t		*task;

	if (sp == NULL) {
		return;
	}

	/*
	 * Process all tasks that received status.
	 * This algorithm preserves callback order.
	 */
	while ((task = sbp2_ses_remove_first_task_state(sp, SBP2_TASK_COMP)) !=
	    NULL) {
		sbp2_ses_nudge(sp);

		ASSERT(task->ts_state == SBP2_TASK_COMP);
		task->ts_state = SBP2_TASK_PROC;
		scsa1394_sbp2_status_proc(lp, TASK2CMD(task),
		    (scsa1394_status_t *)&task->ts_status);
	}
	sbp2_ses_nudge(sp);	/* submit next task */
}

static void
scsa1394_sbp2_status_proc(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd,
    scsa1394_status_t *st)
{
	sbp2_task_t		*task = CMD2TASK(cmd);
	struct scsi_pkt		*pkt = CMD2PKT(cmd);
	uint64_t		*p;

	if (cmd->sc_flags & SCSA1394_CMD_READ) {
		(void) ddi_dma_sync(cmd->sc_buf_dma_hdl, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	if (task->ts_error != SBP2_TASK_ERR_NONE) {
		pkt->pkt_state |= STATE_GOT_BUS;
		switch (task->ts_error) {
		case SBP2_TASK_ERR_ABORT:
			pkt->pkt_state |= STATE_GOT_TARGET;
			pkt->pkt_reason = CMD_ABORTED;
			break;
		case SBP2_TASK_ERR_LUN_RESET:
			pkt->pkt_state |= STATE_GOT_TARGET;
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_DEV_RESET;
			break;
		case SBP2_TASK_ERR_TGT_RESET:
			pkt->pkt_state |= STATE_GOT_TARGET;
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_DEV_RESET;
			break;
		case SBP2_TASK_ERR_TIMEOUT:
			(void) scsa1394_sbp2_reset(lp, RESET_TARGET, cmd);
			return;
		case SBP2_TASK_ERR_DEAD:
		case SBP2_TASK_ERR_BUS:
		default:
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}
	} else if ((st->st_param & SBP2_ST_RESP) == SBP2_ST_RESP_COMPLETE) {
		/*
		 * SBP-2 status block has been received, now look at sbp_status.
		 *
		 * Note: ANSI NCITS 325-1998 B.2 requires that when status is
		 * GOOD, length must be one, but some devices do not comply
		 */
		if (st->st_sbp_status == SBP2_ST_SBP_DUMMY_ORB) {
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET);
			pkt->pkt_reason = CMD_ABORTED;
			pkt->pkt_statistics |= STAT_DEV_RESET;
		} else if ((st->st_status & SCSA1394_ST_STATUS) ==
		    STATUS_GOOD) {
			/* request complete */
			*(pkt->pkt_scbp) = STATUS_GOOD;
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_XFERRED_DATA |
			    STATE_GOT_STATUS);
			pkt->pkt_reason = CMD_CMPLT;
		} else if (scsa1394_sbp2_conv_status(cmd, st) == DDI_SUCCESS) {
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_XFERRED_DATA |
			    STATE_GOT_STATUS | STATE_ARQ_DONE);
			pkt->pkt_reason = CMD_TRAN_ERR;
		} else {
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_XFERRED_DATA |
			    STATE_GOT_STATUS);
			pkt->pkt_reason = CMD_TRAN_ERR;
			lp->l_stat.stat_err_status_conv++;
		}
	} else {
		/* transport or serial bus failure */
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET);
		pkt->pkt_reason = CMD_TRAN_ERR;
		lp->l_stat.stat_err_status_resp++;
	}

	if (pkt->pkt_reason == CMD_TRAN_ERR) {
		lp->l_stat.stat_err_status_tran_err++;

		/* save the command */
		p = &lp->l_stat.stat_cmd_last_fail[
		    lp->l_stat.stat_cmd_last_fail_idx][0];
		bcopy(&pkt->pkt_cdbp[0], p, min(cmd->sc_cdb_len, 16));
		*(clock_t *)&p[2] = ddi_get_lbolt();
		lp->l_stat.stat_cmd_last_fail_idx =
		    (lp->l_stat.stat_cmd_last_fail_idx + 1) %
		    SCSA1394_STAT_NCMD_LAST;
	}

	/* generic HBA status processing */
	scsa1394_cmd_status_proc(lp, cmd);
}


/*
 * Convert SBP-2 status block into SCSA status.
 *
 * Note: (ref: B.2) "SBP-2 permits the return of a status block between two
 *	and quadlets in length. When a truncated status block is stored, the
 *	omitted quadlets shall be interpreted as if zero values were stored."
 * 	We expect the sbp2 layer to do the zeroing for us.
 */
static int
scsa1394_sbp2_conv_status(scsa1394_cmd_t *cmd, scsa1394_status_t *st)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
	uint8_t		status = st->st_status;
	uint8_t		bits = st->st_sense_bits;
	struct scsi_arq_status *arqp = (struct scsi_arq_status *)pkt->pkt_scbp;
	struct scsi_extended_sense *esp = &arqp->sts_sensedata;

	*(pkt->pkt_scbp) = (status & SCSA1394_ST_STATUS);
	*(uint8_t *)&arqp->sts_rqpkt_status = STATUS_GOOD;
	arqp->sts_rqpkt_reason = CMD_CMPLT;
	arqp->sts_rqpkt_resid = 0;
	arqp->sts_rqpkt_state |= STATE_XFERRED_DATA;
	arqp->sts_rqpkt_statistics = 0;

	esp->es_valid = (bits & SCSA1394_ST_VALID) >> SCSA1394_ST_VALID_SHIFT;
	esp->es_class = CLASS_EXTENDED_SENSE;
	esp->es_code = (status & SCSA1394_ST_SFMT) >> SCSA1394_ST_SFMT_SHIFT;

	esp->es_segnum = 0;

	esp->es_filmk = (bits & SCSA1394_ST_MARK) >> SCSA1394_ST_MARK_SHIFT;
	esp->es_eom = (bits & SCSA1394_ST_EOM) >> SCSA1394_ST_EOM_SHIFT;
	esp->es_ili = (bits & SCSA1394_ST_ILI) >> SCSA1394_ST_ILI_SHIFT;
	esp->es_key = (bits & SCSA1394_ST_SENSE_KEY);

	esp->es_info_1 = st->st_info[0];
	esp->es_info_2 = st->st_info[1];
	esp->es_info_3 = st->st_info[2];
	esp->es_info_4 = st->st_info[3];
	esp->es_add_len = 4;

	esp->es_cmd_info[0] = st->st_cdb[0];
	esp->es_cmd_info[1] = st->st_cdb[1];
	esp->es_cmd_info[2] = st->st_cdb[2];
	esp->es_cmd_info[3] = st->st_cdb[3];
	esp->es_add_code = st->st_sense_code;
	esp->es_qual_code = st->st_sense_qual;
	esp->es_fru_code = st->st_fru;
	esp->es_skey_specific[0] = st->st_sks[0];
	esp->es_skey_specific[1] = st->st_sks[1];
	esp->es_skey_specific[2] = st->st_sks[2];

	esp->es_add_info[0] = esp->es_add_info[1] = 0;

	return (DDI_SUCCESS);
}

/*
 * Sends appropriate reset command to the target. LUN reset is optional, so it
 * can fail, in which case the SCSA target driver will use RESET_TARGET/ALL.
 * Target reset support is mandatory in SBP-2, if it fails, it means something's
 * terribly wrong with the device - blow away outstanding tasks in that case.
 */
int
scsa1394_sbp2_reset(scsa1394_lun_t *lp, int level, scsa1394_cmd_t *cmd)
{
	scsa1394_state_t	*sp = lp->l_sp;
	sbp2_task_t		*task;
	int			berr;
	int			ret = DDI_FAILURE;

	if (scsa1394_dev_is_online(sp)) {
		switch (level) {
		case RESET_LUN:
			ret = sbp2_lun_reset(lp->l_lun, &berr);
			if (ret != SBP2_SUCCESS) {
				return (ret);
			}
			break;
		case RESET_TARGET:
		case RESET_ALL:
			ret = sbp2_tgt_reset(sp->s_tgt, &berr);
			break;
		}
	}

	if (cmd != NULL) {
		scsa1394_sbp2_reset_proc(lp, level, cmd);
	}
	if (scsa1394_sbp2_logged_in(lp)) {
		while ((task = sbp2_ses_cancel_first_task(lp->l_ses)) != NULL) {
			ASSERT(task->ts_state < SBP2_TASK_PROC);
			scsa1394_sbp2_reset_proc(lp, level, TASK2CMD(task));
		}
	}

	return (ret);
}

static void
scsa1394_sbp2_reset_proc(scsa1394_lun_t *lp, int level, scsa1394_cmd_t *cmd)
{
	sbp2_task_t		*task = CMD2TASK(cmd);
	struct scsi_pkt		*pkt = CMD2PKT(cmd);
	int			ts_error;

	pkt->pkt_reason = CMD_RESET;
	if (level == RESET_LUN) {
		if (task->ts_state == SBP2_TASK_PEND) {
			pkt->pkt_statistics |= STAT_DEV_RESET;
		} else {
			pkt->pkt_statistics |= STAT_ABORTED;
		}
		ts_error = SBP2_TASK_ERR_LUN_RESET;
	} else {
		pkt->pkt_statistics |= STAT_BUS_RESET;
		ts_error = SBP2_TASK_ERR_TGT_RESET;
	}
	task->ts_error = ts_error;
	task->ts_state = SBP2_TASK_PROC;
	scsa1394_cmd_status_proc(lp, cmd);
}

/*
 * Cancel commands immediately.
 *
 * Caller's responsibility to set device state such that no new tasks are added.
 */
void
scsa1394_sbp2_flush_cmds(scsa1394_lun_t *lp, int reason, int state,
    int statistics)
{
	scsa1394_cmd_t	*cmd;
	struct scsi_pkt	*pkt;
	sbp2_ses_t	*sp = lp->l_ses;
	sbp2_task_t	*task;

	if (sp == NULL) {
		return;
	}

	while ((task = sbp2_ses_cancel_first_task(sp)) != NULL) {
		ASSERT(task->ts_state < SBP2_TASK_PROC);
		cmd = TASK2CMD(task);
		pkt = CMD2PKT(cmd);

		pkt->pkt_reason = reason;
		pkt->pkt_state |= state;
		pkt->pkt_statistics |= statistics;
		task->ts_state = SBP2_TASK_PROC;
		scsa1394_cmd_status_proc(lp, cmd);
	}

	scsa1394_thr_clear_req(&lp->l_worker_thread,
	    SCSA1394_THREQ_TASK_STATUS | SCSA1394_THREQ_NUDGE);
}

static boolean_t
scsa1394_sbp2_logged_in(scsa1394_lun_t *lp)
{
	return (lp->l_ses != NULL);
}
