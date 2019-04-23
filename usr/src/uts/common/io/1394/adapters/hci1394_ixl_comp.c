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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hci1394_ixl_comp.c
 *    Isochronous IXL Compiler.
 *    The compiler converts the general hardware independent IXL command
 *    blocks into OpenHCI DMA descriptors.
 */

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/tnf_probe.h>

#include <sys/1394/h1394.h>
#include <sys/1394/ixl1394.h>
#include <sys/1394/adapters/hci1394.h>

/* compiler allocation size for DMA descriptors. 8000 is 500 descriptors */
#define	HCI1394_IXL_PAGESIZE	8000

/* invalid opcode */
#define	IXL1394_OP_INVALID  (0 | IXL1394_OPTY_OTHER)

/*
 * maximum number of interrupts permitted for a single context in which
 * the context does not advance to the next DMA descriptor.  Interrupts are
 * triggered by 1) hardware completing a DMA descriptor block which has the
 * interrupt (i) bits set, 2) a cycle_inconsistent interrupt, or 3) a cycle_lost
 * interrupt.  Once the max is reached, the HCI1394_IXL_INTR_NOADV error is
 * returned.
 */
int hci1394_ixl_max_noadv_intrs = 8;


static void hci1394_compile_ixl_init(hci1394_comp_ixl_vars_t *wvp,
    hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    ixl1394_command_t *ixlp);
static void hci1394_compile_ixl_endup(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_parse_ixl(hci1394_comp_ixl_vars_t *wvp,
    ixl1394_command_t *ixlp);
static void hci1394_finalize_all_xfer_desc(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_finalize_cur_xfer_desc(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_bld_recv_pkt_desc(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_bld_recv_buf_ppb_desc(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_bld_recv_buf_fill_desc(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_bld_xmit_pkt_desc(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_bld_xmit_buf_desc(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_bld_xmit_hdronly_nopkt_desc(hci1394_comp_ixl_vars_t *wvp);
static int hci1394_bld_dma_mem_desc_blk(hci1394_comp_ixl_vars_t *wvp,
    caddr_t *dma_descpp, uint32_t *dma_desc_bound);
static void hci1394_set_xmit_pkt_hdr(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_set_xmit_skip_mode(hci1394_comp_ixl_vars_t *wvp);
static void hci1394_set_xmit_storevalue_desc(hci1394_comp_ixl_vars_t *wvp);
static int hci1394_set_next_xfer_buf(hci1394_comp_ixl_vars_t *wvp,
    uint32_t bufp, uint16_t size);
static int hci1394_flush_end_desc_check(hci1394_comp_ixl_vars_t *wvp,
    uint32_t count);
static int hci1394_flush_hci_cache(hci1394_comp_ixl_vars_t *wvp);
static uint32_t hci1394_alloc_storevalue_dma_mem(hci1394_comp_ixl_vars_t *wvp);
static hci1394_xfer_ctl_t *hci1394_alloc_xfer_ctl(hci1394_comp_ixl_vars_t *wvp,
    uint32_t dmacnt);
static void *hci1394_alloc_dma_mem(hci1394_comp_ixl_vars_t *wvp,
    uint32_t size, uint32_t *dma_bound);
static boolean_t hci1394_is_opcode_valid(uint16_t ixlopcode);


/*
 * FULL LIST OF ACCEPTED IXL COMMAND OPCOCDES:
 * Receive Only:			Transmit Only:
 *    IXL1394_OP_RECV_PKT_ST		    IXL1394_OP_SEND_PKT_WHDR_ST
 *    IXL1394_OP_RECV_PKT		    IXL1394_OP_SEND_PKT_ST
 *    IXL1394_OP_RECV_BUF		    IXL1394_OP_SEND_PKT
 *    IXL1394_OP_SET_SYNCWAIT		    IXL1394_OP_SEND_BUF
 *					    IXL1394_OP_SEND_HDR_ONLY
 * Receive or Transmit:			    IXL1394_OP_SEND_NO_PKT
 *    IXL1394_OP_CALLBACK		    IXL1394_OP_SET_TAGSYNC
 *    IXL1394_OP_LABEL			    IXL1394_OP_SET_SKIPMODE
 *    IXL1394_OP_JUMP			    IXL1394_OP_STORE_TIMESTAMP
 */

/*
 * hci1394_compile_ixl()
 *    Top level ixl compiler entry point.  Scans ixl and builds openHCI 1.0
 *    descriptor blocks in dma memory.
 */
int
hci1394_compile_ixl(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    ixl1394_command_t *ixlp, int *resultp)
{
	hci1394_comp_ixl_vars_t wv;	/* working variables used throughout */

	ASSERT(soft_statep != NULL);
	ASSERT(ctxtp != NULL);
	TNF_PROBE_0_DEBUG(hci1394_compile_ixl_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* Initialize compiler working variables */
	hci1394_compile_ixl_init(&wv, soft_statep, ctxtp, ixlp);

	/*
	 * First pass:
	 *    Parse ixl commands, building desc blocks, until end of IXL
	 *    linked list.
	 */
	hci1394_parse_ixl(&wv, ixlp);

	/*
	 * Second pass:
	 *    Resolve all generated descriptor block jump and skip addresses.
	 *    Set interrupt enable in descriptor blocks which have callback
	 *    operations in their execution scope. (Previously store_timesamp
	 *    operations were counted also.) Set interrupt enable in descriptor
	 *    blocks which were introduced by an ixl label command.
	 */
	if (wv.dma_bld_error == 0) {
		hci1394_finalize_all_xfer_desc(&wv);
	}

	/* Endup: finalize and cleanup ixl compile, return result */
	hci1394_compile_ixl_endup(&wv);

	*resultp = wv.dma_bld_error;
	if (*resultp != 0) {
		TNF_PROBE_0_DEBUG(hci1394_compile_ixl_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	} else {
		TNF_PROBE_0_DEBUG(hci1394_compile_ixl_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_SUCCESS);
	}
}

/*
 * hci1394_compile_ixl_init()
 *    Initialize the isoch context structure associated with the IXL
 *    program, and initialize the temporary working variables structure.
 */
static void
hci1394_compile_ixl_init(hci1394_comp_ixl_vars_t *wvp,
    hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    ixl1394_command_t *ixlp)
{
	TNF_PROBE_0_DEBUG(hci1394_compile_ixl_init_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* initialize common recv/xmit compile values */
	wvp->soft_statep = soft_statep;
	wvp->ctxtp = ctxtp;

	/* init/clear ctxtp values */
	ctxtp->dma_mem_execp = 0;
	ctxtp->dma_firstp = NULL;
	ctxtp->dma_last_time = 0;
	ctxtp->xcs_firstp = NULL;
	ctxtp->ixl_exec_depth = 0;
	ctxtp->ixl_execp = NULL;
	ctxtp->ixl_firstp = ixlp;
	ctxtp->default_skipxferp = NULL;

	/*
	 * the context's max_noadv_intrs is set here instead of in isoch init
	 * because the default is patchable and would only be picked up this way
	 */
	ctxtp->max_noadv_intrs = hci1394_ixl_max_noadv_intrs;

	/* init working variables */
	wvp->xcs_firstp = NULL;
	wvp->xcs_currentp = NULL;

	wvp->dma_firstp = NULL;
	wvp->dma_currentp = NULL;
	wvp->dma_bld_error = 0;

	wvp->ixl_io_mode = ctxtp->ctxt_flags;
	wvp->ixl_cur_cmdp = NULL;
	wvp->ixl_cur_xfer_stp = NULL;
	wvp->ixl_cur_labelp = NULL;

	wvp->ixl_xfer_st_cnt = 0;	/* count of xfer start commands found */
	wvp->xfer_state = XFER_NONE;	/* none, pkt, buf, skip, hdronly */
	wvp->xfer_hci_flush = 0;	/* updateable - xfer, jump, set */
	wvp->xfer_pktlen = 0;
	wvp->xfer_bufcnt = 0;
	wvp->descriptors = 0;

	/* START RECV ONLY SECTION */
	wvp->ixl_setsyncwait_cnt = 0;

	/* START XMIT ONLY SECTION */
	wvp->ixl_settagsync_cmdp = NULL;
	wvp->ixl_setskipmode_cmdp = NULL;
	wvp->default_skipmode = ctxtp->default_skipmode; /* nxt,self,stop,jmp */
	wvp->default_skiplabelp = ctxtp->default_skiplabelp;
	wvp->default_skipxferp = NULL;
	wvp->skipmode = ctxtp->default_skipmode;
	wvp->skiplabelp = NULL;
	wvp->skipxferp = NULL;
	wvp->default_tag = ctxtp->default_tag;
	wvp->default_sync = ctxtp->default_sync;
	wvp->storevalue_bufp = hci1394_alloc_storevalue_dma_mem(wvp);
	wvp->storevalue_data = 0;
	wvp->xmit_pkthdr1 = 0;
	wvp->xmit_pkthdr2 = 0;
	/* END XMIT ONLY SECTION */

	TNF_PROBE_0_DEBUG(hci1394_compile_ixl_init_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_compile_ixl_endup()
 *    This routine is called just before the main hci1394_compile_ixl() exits.
 *    It checks for errors and performs the appropriate cleanup, or it rolls any
 *    relevant info from the working variables struct into the context structure
 */
static void
hci1394_compile_ixl_endup(hci1394_comp_ixl_vars_t *wvp)
{
	ixl1394_command_t *ixl_exec_stp;
	hci1394_idma_desc_mem_t *dma_nextp;
	int err;

	TNF_PROBE_0_DEBUG(hci1394_compile_ixl_endup_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* error if no descriptor blocks found in ixl & created in dma memory */
	if ((wvp->dma_bld_error == 0) && (wvp->ixl_xfer_st_cnt == 0)) {
		TNF_PROBE_1(hci1394_compile_ixl_endup_nodata_error,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_ENO_DATA_PKTS: prog has no data packets");

		wvp->dma_bld_error = IXL1394_ENO_DATA_PKTS;
	}

	/* if no errors yet, find the first IXL command that's a transfer cmd */
	if (wvp->dma_bld_error == 0) {
		err = hci1394_ixl_find_next_exec_xfer(wvp->ctxtp->ixl_firstp,
		    NULL, &ixl_exec_stp);

		/* error if a label<->jump loop, or no xfer */
		if ((err == DDI_FAILURE) || (ixl_exec_stp == NULL)) {
			TNF_PROBE_1(hci1394_compile_ixl_endup_error,
			    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
			    "IXL1394_ENO_DATA_PKTS: loop or no xfer detected");

			wvp->dma_bld_error = IXL1394_ENO_DATA_PKTS;
		}
	}

	/* Sync all the DMA descriptor buffers */
	dma_nextp = wvp->ctxtp->dma_firstp;
	while (dma_nextp != NULL) {
		err = ddi_dma_sync(dma_nextp->mem.bi_dma_handle,
		    (off_t)dma_nextp->mem.bi_kaddr, dma_nextp->mem.bi_length,
		    DDI_DMA_SYNC_FORDEV);
		if (err != DDI_SUCCESS) {
			wvp->dma_bld_error = IXL1394_EINTERNAL_ERROR;

			TNF_PROBE_1(hci1394_compile_ixl_endup_error,
			    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
			    "IXL1394_INTERNAL_ERROR: dma_sync() failed");
			break;
		}

		/* advance to next dma memory descriptor */
		dma_nextp = dma_nextp->dma_nextp;
	}

	/*
	 * If error, cleanup and return. delete all allocated xfer_ctl structs
	 * and all dma descriptor page memory and its dma memory blocks too.
	 */
	if (wvp->dma_bld_error != 0) {
		wvp->ctxtp->xcs_firstp = (void *)wvp->xcs_firstp;
		wvp->ctxtp->dma_firstp = wvp->dma_firstp;
		hci1394_ixl_cleanup(wvp->soft_statep, wvp->ctxtp);

		TNF_PROBE_0_DEBUG(hci1394_compile_ixl_endup_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/* can only get to here if the first ixl transfer command is found */

	/* set required processing vars into ctxtp struct */
	wvp->ctxtp->default_skipxferp = wvp->default_skipxferp;
	wvp->ctxtp->dma_mem_execp = 0;

	/*
	 * the transfer command's compiler private xfer_ctl structure has the
	 * appropriate bound address
	 */
	wvp->ctxtp->dma_mem_execp = (uint32_t)((hci1394_xfer_ctl_t *)
	    ixl_exec_stp->compiler_privatep)->dma[0].dma_bound;
	wvp->ctxtp->xcs_firstp = (void *)wvp->xcs_firstp;
	wvp->ctxtp->dma_firstp = wvp->dma_firstp;
	wvp->ctxtp->dma_last_time = 0;
	wvp->ctxtp->ixl_exec_depth = 0;
	wvp->ctxtp->ixl_execp = NULL;

	/* compile done */
	TNF_PROBE_0_DEBUG(hci1394_compile_ixl_endup_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_parse_ixl()
 *    Scan IXL program and build ohci DMA descriptor blocks in dma memory.
 *
 *    Parse/process succeeding ixl commands until end of IXL linked list is
 *    reached. Evaluate ixl syntax and build (xmit or recv) descriptor
 *    blocks.  To aid execution time evaluation of current location, enable
 *    status recording on each descriptor block built.
 *    On xmit, set sync & tag bits. On recv, optionally set wait for sync bit.
 */
static void
hci1394_parse_ixl(hci1394_comp_ixl_vars_t *wvp, ixl1394_command_t *ixlp)
{
	ixl1394_command_t *ixlnextp = ixlp;	/* addr of next ixl cmd */
	ixl1394_command_t *ixlcurp = NULL;	/* addr of current ixl cmd */
	uint16_t ixlopcode = 0;			/* opcode of currnt ixl cmd */

	uint32_t pktsize;
	uint32_t pktcnt;

	TNF_PROBE_0_DEBUG(hci1394_parse_ixl_enter, HCI1394_TNF_HAL_STACK_ISOCH,
	    "");

	/* follow ixl links until reach end or find error */
	while ((ixlnextp != NULL) && (wvp->dma_bld_error == 0)) {

		/* set this command as the current ixl command */
		wvp->ixl_cur_cmdp = ixlcurp = ixlnextp;
		ixlnextp = ixlcurp->next_ixlp;

		ixlopcode = ixlcurp->ixl_opcode;

		/* init compiler controlled values in current ixl command */
		ixlcurp->compiler_privatep = NULL;
		ixlcurp->compiler_resv = 0;

		/* error if xmit/recv mode not appropriate for current cmd */
		if ((((wvp->ixl_io_mode & HCI1394_ISO_CTXT_RECV) != 0) &&
		    ((ixlopcode & IXL1394_OPF_ONRECV) == 0)) ||
		    (((wvp->ixl_io_mode & HCI1394_ISO_CTXT_RECV) == 0) &&
		    ((ixlopcode & IXL1394_OPF_ONXMIT) == 0))) {

			/* check if command op failed because it was invalid */
			if (hci1394_is_opcode_valid(ixlopcode) != B_TRUE) {
				TNF_PROBE_3(hci1394_parse_ixl_bad_opcode_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_BAD_IXL_OPCODE",
				    tnf_opaque, ixl_commandp, ixlcurp,
				    tnf_opaque, ixl_opcode, ixlopcode);

				wvp->dma_bld_error = IXL1394_EBAD_IXL_OPCODE;
			} else {
				TNF_PROBE_3(hci1394_parse_ixl_mode_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EWRONG_XR_CMD_MODE: "
				    "invalid ixlop in mode", tnf_uint, io_mode,
				    wvp->ixl_io_mode, tnf_opaque, ixl_opcode,
				    ixlopcode);

				wvp->dma_bld_error = IXL1394_EWRONG_XR_CMD_MODE;
			}
			continue;
		}

		/*
		 * if ends xfer flag set, finalize current xfer descriptor
		 * block build
		 */
		if ((ixlopcode & IXL1394_OPF_ENDSXFER) != 0) {
			/* finalize any descriptor block build in progress */
			hci1394_finalize_cur_xfer_desc(wvp);

			if (wvp->dma_bld_error != 0) {
				continue;
			}
		}

		/*
		 * now process based on specific opcode value
		 */
		switch (ixlopcode) {

		case IXL1394_OP_RECV_BUF:
		case IXL1394_OP_RECV_BUF_U: {
			ixl1394_xfer_buf_t *cur_xfer_buf_ixlp;

			cur_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)ixlcurp;

			/*
			 * In packet-per-buffer mode:
			 *    This ixl command builds a collection of xfer
			 *    descriptor blocks (size/pkt_size of them) each to
			 *    recv a packet whose buffer size is pkt_size and
			 *    whose buffer ptr is (pktcur*pkt_size + bufp)
			 *
			 * In buffer fill mode:
			 *    This ixl command builds a single xfer descriptor
			 *    block to recv as many packets or parts of packets
			 *    as can fit into the buffer size specified
			 *    (pkt_size is not used).
			 */

			/* set xfer_state for new descriptor block build */
			wvp->xfer_state = XFER_BUF;

			/* set this ixl command as current xferstart command */
			wvp->ixl_cur_xfer_stp = ixlcurp;

			/*
			 * perform packet-per-buffer checks
			 * (no checks needed when in buffer fill mode)
			 */
			if ((wvp->ixl_io_mode & HCI1394_ISO_CTXT_BFFILL) == 0) {

				/* the packets must use the buffer exactly */
				pktsize = cur_xfer_buf_ixlp->pkt_size;
				pktcnt = 0;
				if (pktsize != 0) {
					pktcnt = cur_xfer_buf_ixlp->size /
					    pktsize;
				}
				if ((pktcnt == 0) || ((pktsize * pktcnt) !=
				    cur_xfer_buf_ixlp->size)) {

					TNF_PROBE_3(hci1394_parse_ixl_rat_error,
					    HCI1394_TNF_HAL_ERROR_ISOCH, "",
					    tnf_string, errmsg,
					    "IXL1394_EPKTSIZE_RATIO", tnf_int,
					    buf_size, cur_xfer_buf_ixlp->size,
					    tnf_int, pkt_size, pktsize);

					wvp->dma_bld_error =
					    IXL1394_EPKTSIZE_RATIO;
					continue;
				}
			}

			/*
			 * set buffer pointer & size into first xfer_bufp
			 * and xfer_size
			 */
			if (hci1394_set_next_xfer_buf(wvp,
			    cur_xfer_buf_ixlp->ixl_buf.ixldmac_addr,
			    cur_xfer_buf_ixlp->size) != DDI_SUCCESS) {

				/* wvp->dma_bld_error is set by above call */
				continue;
			}
			break;
		}

		case IXL1394_OP_RECV_PKT_ST:
		case IXL1394_OP_RECV_PKT_ST_U: {
			ixl1394_xfer_pkt_t *cur_xfer_pkt_ixlp;

			cur_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)ixlcurp;

			/* error if in buffer fill mode */
			if ((wvp->ixl_io_mode & HCI1394_ISO_CTXT_BFFILL) != 0) {
				TNF_PROBE_1(hci1394_parse_ixl_mode_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EWRONG_XR_CMD_MODE: "
				    "RECV_PKT_ST used in BFFILL mode");

				wvp->dma_bld_error = IXL1394_EWRONG_XR_CMD_MODE;
				continue;
			}

			/* set xfer_state for new descriptor block build */
			/* set this ixl command as current xferstart command */
			wvp->xfer_state = XFER_PKT;
			wvp->ixl_cur_xfer_stp = ixlcurp;

			/*
			 * set buffer pointer & size into first xfer_bufp
			 * and xfer_size
			 */
			if (hci1394_set_next_xfer_buf(wvp,
			    cur_xfer_pkt_ixlp->ixl_buf.ixldmac_addr,
			    cur_xfer_pkt_ixlp->size) != DDI_SUCCESS) {

				/* wvp->dma_bld_error is set by above call */
				continue;
			}
			break;
		}

		case IXL1394_OP_RECV_PKT:
		case IXL1394_OP_RECV_PKT_U: {
			ixl1394_xfer_pkt_t *cur_xfer_pkt_ixlp;

			cur_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)ixlcurp;

			/* error if in buffer fill mode */
			if ((wvp->ixl_io_mode & HCI1394_ISO_CTXT_BFFILL) != 0) {
				TNF_PROBE_1(hci1394_parse_ixl_mode_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EWRONG_XR_CMD_MODE: "
				    "RECV_PKT_ST used in BFFILL mode");

				wvp->dma_bld_error = IXL1394_EWRONG_XR_CMD_MODE;
				continue;
			}

			/* error if xfer_state not xfer pkt */
			if (wvp->xfer_state != XFER_PKT) {
				TNF_PROBE_1(hci1394_parse_ixl_misplacercv_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EMISPLACED_RECV: "
				    "RECV_PKT without RECV_PKT_ST");

				wvp->dma_bld_error = IXL1394_EMISPLACED_RECV;
				continue;
			}

			/*
			 * save xfer start cmd ixl ptr in compiler_privatep
			 * field of this cmd
			 */
			ixlcurp->compiler_privatep = (void *)
			    wvp->ixl_cur_xfer_stp;

			/*
			 * save pkt index [1-n] in compiler_resv field of
			 * this cmd
			 */
			ixlcurp->compiler_resv = wvp->xfer_bufcnt;

			/*
			 * set buffer pointer & size into next xfer_bufp
			 * and xfer_size
			 */
			if (hci1394_set_next_xfer_buf(wvp,
			    cur_xfer_pkt_ixlp->ixl_buf.ixldmac_addr,
			    cur_xfer_pkt_ixlp->size) != DDI_SUCCESS) {

				/* wvp->dma_bld_error is set by above call */
				continue;
			}

			/*
			 * set updateable xfer cache flush eval flag if
			 * updateable opcode
			 */
			if ((ixlopcode & IXL1394_OPF_UPDATE) != 0) {
				wvp->xfer_hci_flush |= UPDATEABLE_XFER;
			}
			break;
		}

		case IXL1394_OP_SEND_BUF:
		case IXL1394_OP_SEND_BUF_U: {
			ixl1394_xfer_buf_t *cur_xfer_buf_ixlp;

			cur_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)ixlcurp;

			/*
			 * These send_buf commands build a collection of xmit
			 * descriptor blocks (size/pkt_size of them) each to
			 * xfer a packet whose buffer size is pkt_size and whose
			 * buffer pt is (pktcur*pkt_size + bufp). (ptr and size
			 * are adjusted if they have header form of ixl cmd)
			 */

			/* set xfer_state for new descriptor block build */
			wvp->xfer_state = XFER_BUF;

			/* set this ixl command as current xferstart command */
			wvp->ixl_cur_xfer_stp = ixlcurp;

			/* the packets must use the buffer exactly,else error */
			pktsize = cur_xfer_buf_ixlp->pkt_size;
			pktcnt = 0;
			if (pktsize != 0) {
				pktcnt = cur_xfer_buf_ixlp->size / pktsize;
			}
			if ((pktcnt == 0) || ((pktsize * pktcnt) !=
			    cur_xfer_buf_ixlp->size)) {

				TNF_PROBE_3(hci1394_parse_ixl_rat_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EPKTSIZE_RATIO", tnf_int,
				    buf_size, cur_xfer_buf_ixlp->size, tnf_int,
				    pkt_size, pktsize);

				wvp->dma_bld_error = IXL1394_EPKTSIZE_RATIO;
				continue;
			}

			/* set buf ptr & size into 1st xfer_bufp & xfer_size */
			if (hci1394_set_next_xfer_buf(wvp,
			    cur_xfer_buf_ixlp->ixl_buf.ixldmac_addr,
			    cur_xfer_buf_ixlp->size) != DDI_SUCCESS) {

				/* wvp->dma_bld_error is set by above call */
				continue;
			}
			break;
		}

		case IXL1394_OP_SEND_PKT_ST:
		case IXL1394_OP_SEND_PKT_ST_U: {
			ixl1394_xfer_pkt_t *cur_xfer_pkt_ixlp;

			cur_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)ixlcurp;

			/* set xfer_state for new descriptor block build */
			/* set this ixl command as current xferstart command */
			wvp->xfer_state = XFER_PKT;
			wvp->ixl_cur_xfer_stp = ixlcurp;

			/*
			 * set buffer pointer & size into first xfer_bufp and
			 * xfer_size
			 */
			if (hci1394_set_next_xfer_buf(wvp,
			    cur_xfer_pkt_ixlp->ixl_buf.ixldmac_addr,
			    cur_xfer_pkt_ixlp->size) != DDI_SUCCESS) {

				/* wvp->dma_bld_error is set by above call */
				continue;
			}
			break;
		}

		case IXL1394_OP_SEND_PKT_WHDR_ST:
		case IXL1394_OP_SEND_PKT_WHDR_ST_U: {
			ixl1394_xfer_pkt_t *cur_xfer_pkt_ixlp;

			cur_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)ixlcurp;

			/* set xfer_state for new descriptor block build */
			/* set this ixl command as current xferstart command */
			wvp->xfer_state = XFER_PKT;
			wvp->ixl_cur_xfer_stp = ixlcurp;

			/*
			 * buffer size must be at least 4 (must include header),
			 * else error
			 */
			if (cur_xfer_pkt_ixlp->size < 4) {
				TNF_PROBE_2(hci1394_parse_ixl_hdr_missing_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EPKT_HDR_MISSING", tnf_int,
				    pkt_size, cur_xfer_pkt_ixlp->size);

				wvp->dma_bld_error = IXL1394_EPKT_HDR_MISSING;
				continue;
			}

			/*
			 * set buffer and size(excluding header) into first
			 * xfer_bufp and xfer_size
			 */
			if (hci1394_set_next_xfer_buf(wvp,
			    cur_xfer_pkt_ixlp->ixl_buf.ixldmac_addr + 4,
			    cur_xfer_pkt_ixlp->size - 4) != DDI_SUCCESS) {

				/* wvp->dma_bld_error is set by above call */
				continue;
			}
			break;
		}

		case IXL1394_OP_SEND_PKT:
		case IXL1394_OP_SEND_PKT_U: {
			ixl1394_xfer_pkt_t *cur_xfer_pkt_ixlp;

			cur_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)ixlcurp;

			/* error if xfer_state not xfer pkt */
			if (wvp->xfer_state != XFER_PKT) {
				TNF_PROBE_1(hci1394_parse_ixl_misplacesnd_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EMISPLACED_SEND: SEND_PKT "
				    "without SEND_PKT_ST");

				wvp->dma_bld_error = IXL1394_EMISPLACED_SEND;
				continue;
			}

			/*
			 * save xfer start cmd ixl ptr in compiler_privatep
			 * field of this cmd
			 */
			ixlcurp->compiler_privatep = (void *)
			    wvp->ixl_cur_xfer_stp;

			/*
			 * save pkt index [1-n] in compiler_resv field of this
			 * cmd
			 */
			ixlcurp->compiler_resv = wvp->xfer_bufcnt;

			/*
			 * set buffer pointer & size into next xfer_bufp
			 * and xfer_size
			 */
			if (hci1394_set_next_xfer_buf(wvp,
			    cur_xfer_pkt_ixlp->ixl_buf.ixldmac_addr,
			    cur_xfer_pkt_ixlp->size) != DDI_SUCCESS) {

				/* wvp->dma_bld_error is set by above call */
				continue;
			}

			/*
			 * set updateable xfer cache flush eval flag if
			 * updateable opcode
			 */
			if ((ixlopcode & IXL1394_OPF_UPDATE) != 0) {
				wvp->xfer_hci_flush |= UPDATEABLE_XFER;
			}
			break;
		}

		case IXL1394_OP_SEND_HDR_ONLY:
			/* set xfer_state for new descriptor block build */
			wvp->xfer_state = XMIT_HDRONLY;

			/* set this ixl command as current xferstart command */
			wvp->ixl_cur_xfer_stp = ixlcurp;
			break;

		case IXL1394_OP_SEND_NO_PKT:
			/* set xfer_state for new descriptor block build */
			wvp->xfer_state = XMIT_NOPKT;

			/* set this ixl command as current xferstart command */
			wvp->ixl_cur_xfer_stp = ixlcurp;
			break;

		case IXL1394_OP_JUMP:
		case IXL1394_OP_JUMP_U: {
			ixl1394_jump_t *cur_jump_ixlp;

			cur_jump_ixlp = (ixl1394_jump_t *)ixlcurp;

			/*
			 * verify label indicated by IXL1394_OP_JUMP is
			 * actually an IXL1394_OP_LABEL or NULL
			 */
			if ((cur_jump_ixlp->label != NULL) &&
			    (cur_jump_ixlp->label->ixl_opcode !=
			    IXL1394_OP_LABEL)) {
				TNF_PROBE_3(hci1394_parse_ixl_jumplabel_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EJUMP_NOT_TO_LABEL",
				    tnf_opaque, jumpixl_commandp, ixlcurp,
				    tnf_opaque, jumpto_ixl,
				    cur_jump_ixlp->label);

				wvp->dma_bld_error = IXL1394_EJUMP_NOT_TO_LABEL;
				continue;
			}
			break;
		}

		case IXL1394_OP_LABEL:
			/*
			 * save current ixl label command for xfer cmd
			 * finalize processing
			 */
			wvp->ixl_cur_labelp = ixlcurp;

			/* set initiating label flag to cause cache flush */
			wvp->xfer_hci_flush |= INITIATING_LBL;
			break;

		case IXL1394_OP_CALLBACK:
		case IXL1394_OP_CALLBACK_U:
		case IXL1394_OP_STORE_TIMESTAMP:
			/*
			 * these commands are accepted during compile,
			 * processed during execution (interrupt handling)
			 * No further processing is needed here.
			 */
			break;

		case IXL1394_OP_SET_SKIPMODE:
		case IXL1394_OP_SET_SKIPMODE_U:
			/*
			 * Error if already have a set skipmode cmd for
			 * this xfer
			 */
			if (wvp->ixl_setskipmode_cmdp != NULL) {
				TNF_PROBE_2(hci1394_parse_ixl_dup_set_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EDUPLICATE_SET_CMD:"
				    " duplicate set skipmode", tnf_opaque,
				    ixl_commandp, ixlcurp);

				wvp->dma_bld_error = IXL1394_EDUPLICATE_SET_CMD;
				continue;
			}

			/* save skip mode ixl command and verify skipmode */
			wvp->ixl_setskipmode_cmdp = (ixl1394_set_skipmode_t *)
			    ixlcurp;

			if ((wvp->ixl_setskipmode_cmdp->skipmode !=
			    IXL1394_SKIP_TO_NEXT) &&
			    (wvp->ixl_setskipmode_cmdp->skipmode !=
			    IXL1394_SKIP_TO_SELF) &&
			    (wvp->ixl_setskipmode_cmdp->skipmode !=
			    IXL1394_SKIP_TO_STOP) &&
			    (wvp->ixl_setskipmode_cmdp->skipmode !=
			    IXL1394_SKIP_TO_LABEL)) {

				TNF_PROBE_3(hci1394_parse_ixl_dup_set_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL EBAD_SKIPMODE", tnf_opaque,
				    ixl_commandp, ixlcurp, tnf_int, skip,
				    wvp->ixl_setskipmode_cmdp->skipmode);

				wvp->dma_bld_error = IXL1394_EBAD_SKIPMODE;
				continue;
			}

			/*
			 * if mode is IXL1394_SKIP_TO_LABEL, verify label
			 * references an IXL1394_OP_LABEL
			 */
			if ((wvp->ixl_setskipmode_cmdp->skipmode ==
			    IXL1394_SKIP_TO_LABEL) &&
			    ((wvp->ixl_setskipmode_cmdp->label == NULL) ||
			    (wvp->ixl_setskipmode_cmdp->label->ixl_opcode !=
			    IXL1394_OP_LABEL))) {

				TNF_PROBE_3(hci1394_parse_ixl_jump_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EJUMP_NOT_TO_LABEL",
				    tnf_opaque, jumpixl_commandp, ixlcurp,
				    tnf_opaque, jumpto_ixl,
				    wvp->ixl_setskipmode_cmdp->label);

				wvp->dma_bld_error = IXL1394_EJUMP_NOT_TO_LABEL;
				continue;
			}
			/*
			 * set updateable set cmd cache flush eval flag if
			 * updateable opcode
			 */
			if ((ixlopcode & IXL1394_OPF_UPDATE) != 0) {
				wvp->xfer_hci_flush |= UPDATEABLE_SET;
			}
			break;

		case IXL1394_OP_SET_TAGSYNC:
		case IXL1394_OP_SET_TAGSYNC_U:
			/*
			 * is an error if already have a set tag and sync cmd
			 * for this xfer
			 */
			if (wvp->ixl_settagsync_cmdp != NULL) {
				TNF_PROBE_2(hci1394_parse_ixl_dup_set_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_EDUPLICATE_SET_CMD:"
				    " duplicate set tagsync", tnf_opaque,
				    ixl_commandp, ixlcurp);

				wvp->dma_bld_error = IXL1394_EDUPLICATE_SET_CMD;
				continue;
			}

			/* save ixl command containing tag and sync values */
			wvp->ixl_settagsync_cmdp =
			    (ixl1394_set_tagsync_t *)ixlcurp;

			/*
			 * set updateable set cmd cache flush eval flag if
			 * updateable opcode
			 */
			if ((ixlopcode & IXL1394_OPF_UPDATE) != 0) {
				wvp->xfer_hci_flush |= UPDATEABLE_SET;
			}
			break;

		case IXL1394_OP_SET_SYNCWAIT:
			/*
			 * count ixl wait-for-sync commands since last
			 * finalize ignore multiple occurrences for same xfer
			 * command
			 */
			wvp->ixl_setsyncwait_cnt++;
			break;

		default:
			/* error - unknown/unimplemented ixl command */
			TNF_PROBE_3(hci1394_parse_ixl_bad_opcode_error,
			    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
			    "IXL1394_BAD_IXL_OPCODE", tnf_opaque, ixl_commandp,
			    ixlcurp, tnf_opaque, ixl_opcode, ixlopcode);

			wvp->dma_bld_error = IXL1394_EBAD_IXL_OPCODE;
			continue;
		}
	} /* while */

	/* finalize any last descriptor block build */
	wvp->ixl_cur_cmdp = NULL;
	if (wvp->dma_bld_error == 0) {
		hci1394_finalize_cur_xfer_desc(wvp);
	}

	TNF_PROBE_0_DEBUG(hci1394_parse_ixl_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_finalize_all_xfer_desc()
 *    Pass 2: Scan IXL resolving all dma descriptor jump and skip addresses.
 *
 *    Set interrupt enable on first descriptor block associated with current
 *    xfer IXL command if current IXL xfer was introduced by an IXL label cmnd.
 *
 *    Set interrupt enable on last descriptor block associated with current xfer
 *    IXL command if any callback ixl commands are found on the execution path
 *    between the current and the next xfer ixl command.  (Previously, this
 *    applied to store timestamp ixl commands, as well.)
 */
static void
hci1394_finalize_all_xfer_desc(hci1394_comp_ixl_vars_t *wvp)
{
	ixl1394_command_t *ixlcurp;		/* current ixl command */
	ixl1394_command_t *ixlnextp;		/* next ixl command */
	ixl1394_command_t *ixlexecnext;
	hci1394_xfer_ctl_t	*xferctl_curp;
	hci1394_xfer_ctl_t	*xferctl_nxtp;
	hci1394_desc_t		*hcidescp;
	ddi_acc_handle_t	acc_hdl;
	uint32_t	temp;
	uint32_t	dma_execnext_addr;
	uint32_t	dma_skiplabel_addr;
	uint32_t	dma_skip_addr;
	uint32_t	callback_cnt;
	uint16_t	repcnt;
	uint16_t	ixlopcode;
	int		ii;
	int		err;

	TNF_PROBE_0_DEBUG(hci1394_finalize_all_xfer_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/*
	 * If xmit mode and if default skipmode is skip to label -
	 * follow exec path starting at default skipmode label until
	 * find the first ixl xfer command which is to be executed.
	 * Set its address into default_skipxferp.
	 */
	if (((wvp->ixl_io_mode & HCI1394_ISO_CTXT_RECV) == 0) &&
	    (wvp->ctxtp->default_skipmode == IXL1394_SKIP_TO_LABEL)) {

		err = hci1394_ixl_find_next_exec_xfer(wvp->default_skiplabelp,
		    NULL, &wvp->default_skipxferp);
		if (err == DDI_FAILURE) {
			TNF_PROBE_2(hci1394_finalize_all_xfer_desc_error,
			    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
			    "IXL1394_ENO_DATA_PKTS: label<->jump loop detected "
			    "for skiplabel default w/no xfers", tnf_opaque,
			    skipixl_cmdp, wvp->default_skiplabelp);
			TNF_PROBE_0_DEBUG(hci1394_finalize_all_xfer_desc_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");

			wvp->dma_bld_error = IXL1394_ENO_DATA_PKTS;
			return;
		}
	}

	/* set first ixl cmd */
	ixlnextp = wvp->ctxtp->ixl_firstp;

	/* follow ixl links until reach end or find error */
	while ((ixlnextp != NULL) && (wvp->dma_bld_error == 0)) {

		/* set this command as the current ixl command */
		ixlcurp = ixlnextp;
		ixlnextp = ixlcurp->next_ixlp;

		/* get command opcode removing unneeded update flag */
		ixlopcode = ixlcurp->ixl_opcode & ~IXL1394_OPF_UPDATE;

		/*
		 * Scan for next ixl xfer start command (including this one),
		 * along ixl link path. Once xfer command found, find next IXL
		 * xfer cmd along execution path and fill in branch address of
		 * current xfer command. If is composite ixl xfer command, first
		 * link forward branch dma addresses of each descriptor block in
		 * composite, until reach final one then set its branch address
		 * to next execution path xfer found.  Next determine skip mode
		 * and fill in skip address(es) appropriately.
		 */
		/* skip to next if not xfer start ixl command */
		if (((ixlopcode & IXL1394_OPF_ISXFER) == 0) ||
		    ((ixlopcode & IXL1394_OPTY_MASK) == 0)) {
			continue;
		}

		/*
		 * get xfer_ctl structure and composite repeat count for current
		 * IXL xfer cmd
		 */
		xferctl_curp = (hci1394_xfer_ctl_t *)ixlcurp->compiler_privatep;
		repcnt = xferctl_curp->cnt;

		/*
		 * if initiated by an IXL label command, set interrupt enable
		 * flag into last component of first descriptor block of
		 * current IXL xfer cmd
		 */
		if ((xferctl_curp->ctl_flags & XCTL_LABELLED) != 0) {
			hcidescp = (hci1394_desc_t *)
			    xferctl_curp->dma[0].dma_descp;
			acc_hdl = xferctl_curp->dma[0].dma_buf->bi_handle;
			temp = ddi_get32(acc_hdl, &hcidescp->hdr);
			temp |= DESC_INTR_ENBL;
			ddi_put32(acc_hdl, &hcidescp->hdr, temp);
		}

		/* find next xfer IXL cmd by following execution path */
		err = hci1394_ixl_find_next_exec_xfer(ixlcurp->next_ixlp,
		    &callback_cnt, &ixlexecnext);

		/* if label<->jump loop detected, return error */
		if (err == DDI_FAILURE) {
			wvp->dma_bld_error = IXL1394_ENO_DATA_PKTS;

			TNF_PROBE_2(hci1394_finalize_all_xfer_desc_error,
			    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
			    "IXL1394_ENO_DATA_PKTS: label<->jump loop detected "
			    "w/no xfers", tnf_opaque, ixl_cmdp,
			    ixlcurp->next_ixlp);
			continue;
		}

		/* link current IXL's xfer_ctl to next xfer IXL on exec path */
		xferctl_curp->execp = ixlexecnext;

		/*
		 * if callbacks have been seen during execution path scan,
		 * set interrupt enable flag into last descriptor of last
		 * descriptor block of current IXL xfer cmd
		 */
		if (callback_cnt != 0) {
			hcidescp = (hci1394_desc_t *)
			    xferctl_curp->dma[repcnt - 1].dma_descp;
			acc_hdl =
			    xferctl_curp->dma[repcnt - 1].dma_buf->bi_handle;
			temp = ddi_get32(acc_hdl, &hcidescp->hdr);
			temp |= DESC_INTR_ENBL;
			ddi_put32(acc_hdl, &hcidescp->hdr, temp);
		}

		/*
		 * obtain dma bound addr of next exec path IXL xfer command,
		 * if any
		 */
		dma_execnext_addr = 0;

		if (ixlexecnext != NULL) {
			xferctl_nxtp = (hci1394_xfer_ctl_t *)
			    ixlexecnext->compiler_privatep;
			dma_execnext_addr = xferctl_nxtp->dma[0].dma_bound;
		} else {
			/*
			 * If this is last descriptor (next == NULL), then
			 * make sure the interrupt bit is enabled.  This
			 * way we can ensure that we are notified when the
			 * descriptor chain processing has come to an end.
			 */
			hcidescp = (hci1394_desc_t *)
			    xferctl_curp->dma[repcnt - 1].dma_descp;
			acc_hdl =
			    xferctl_curp->dma[repcnt - 1].dma_buf->bi_handle;
			temp = ddi_get32(acc_hdl, &hcidescp->hdr);
			temp |= DESC_INTR_ENBL;
			ddi_put32(acc_hdl, &hcidescp->hdr, temp);
		}

		/*
		 * set jump address of final cur IXL xfer cmd to addr next
		 * IXL xfer cmd
		 */
		hcidescp = (hci1394_desc_t *)
		    xferctl_curp->dma[repcnt - 1].dma_descp;
		acc_hdl = xferctl_curp->dma[repcnt - 1].dma_buf->bi_handle;
		ddi_put32(acc_hdl, &hcidescp->branch, dma_execnext_addr);

		/*
		 * if a composite object, forward link initial jump
		 * dma addresses
		 */
		for (ii = 0; ii < repcnt - 1; ii++) {
			hcidescp = (hci1394_desc_t *)
			    xferctl_curp->dma[ii].dma_descp;
			acc_hdl	 = xferctl_curp->dma[ii].dma_buf->bi_handle;
			ddi_put32(acc_hdl, &hcidescp->branch,
			    xferctl_curp->dma[ii + 1].dma_bound);
		}

		/*
		 * fill in skip address(es) for all descriptor blocks belonging
		 * to current IXL xfer command; note:skip addresses apply only
		 * to xmit mode commands
		 */
		if ((ixlopcode & IXL1394_OPF_ONXMIT) != 0) {

			/* first obtain and set skip mode information */
			wvp->ixl_setskipmode_cmdp = xferctl_curp->skipmodep;
			hci1394_set_xmit_skip_mode(wvp);

			/*
			 * if skip to label,init dma bound addr to be
			 * 1st xfer cmd after label
			 */
			dma_skiplabel_addr = 0;
			if ((wvp->skipmode == IXL1394_SKIP_TO_LABEL) &&
			    (wvp->skipxferp != NULL)) {
				xferctl_nxtp = (hci1394_xfer_ctl_t *)
				    wvp->skipxferp->compiler_privatep;
				dma_skiplabel_addr =
				    xferctl_nxtp->dma[0].dma_bound;
			}

			/*
			 * set skip addrs for each descriptor blk at this
			 * xfer start IXL cmd
			 */
			for (ii = 0; ii < repcnt; ii++) {
				switch (wvp->skipmode) {

				case IXL1394_SKIP_TO_LABEL:
					/* set dma bound address - label */
					dma_skip_addr = dma_skiplabel_addr;
					break;

				case IXL1394_SKIP_TO_NEXT:
					/* set dma bound address - next */
					if (ii < repcnt - 1) {
						dma_skip_addr = xferctl_curp->
						    dma[ii + 1].dma_bound;
					} else {
						dma_skip_addr =
						    dma_execnext_addr;
					}
					break;

				case IXL1394_SKIP_TO_SELF:
					/* set dma bound address - self */
					dma_skip_addr =
					    xferctl_curp->dma[ii].dma_bound;
					break;

				case IXL1394_SKIP_TO_STOP:
				default:
					/* set dma bound address - stop */
					dma_skip_addr = 0;
					break;
				}

				/*
				 * determine address of first descriptor of
				 * current descriptor block by adjusting addr of
				 * last descriptor of current descriptor block
				 */
				hcidescp = ((hci1394_desc_t *)
				    xferctl_curp->dma[ii].dma_descp);
				acc_hdl =
				    xferctl_curp->dma[ii].dma_buf->bi_handle;

				/*
				 * adjust by count of descriptors in this desc
				 * block not including the last one (size of
				 * descriptor)
				 */
				hcidescp -= ((xferctl_curp->dma[ii].dma_bound &
				    DESC_Z_MASK) - 1);

				/*
				 * adjust further if the last descriptor is
				 * double sized
				 */
				if (ixlopcode == IXL1394_OP_SEND_HDR_ONLY) {
					hcidescp++;
				}
				/*
				 * now set skip address into first descriptor
				 * of descriptor block
				 */
				ddi_put32(acc_hdl, &hcidescp->branch,
				    dma_skip_addr);
			} /* for */
		} /* if */
	} /* while */

	TNF_PROBE_0_DEBUG(hci1394_finalize_all_xfer_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_finalize_cur_xfer_desc()
 *    Build the openHCI descriptor for a packet or buffer based on info
 *    currently collected into the working vars struct (wvp).  After some
 *    checks, this routine dispatches to the appropriate descriptor block
 *    build (bld) routine for the packet or buf type.
 */
static void
hci1394_finalize_cur_xfer_desc(hci1394_comp_ixl_vars_t *wvp)
{
	uint16_t ixlopcode;
	uint16_t ixlopraw;

	TNF_PROBE_0_DEBUG(hci1394_finalize_cur_xfer_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* extract opcode from current IXL cmd (if any) */
	if (wvp->ixl_cur_cmdp != NULL) {
		ixlopcode = wvp->ixl_cur_cmdp->ixl_opcode;
		ixlopraw = ixlopcode & ~IXL1394_OPF_UPDATE;
	} else {
		ixlopcode = ixlopraw = IXL1394_OP_INVALID;
	}

	/*
	 * if no xfer descriptor block being built, perform validity checks
	 */
	if (wvp->xfer_state == XFER_NONE) {
		/*
		 * error if being finalized by IXL1394_OP_LABEL or
		 * IXL1394_OP_JUMP or if at end, and have an unapplied
		 * IXL1394_OP_SET_TAGSYNC, IXL1394_OP_SET_SKIPMODE or
		 * IXL1394_OP_SET_SYNCWAIT
		 */
		if ((ixlopraw == IXL1394_OP_JUMP) ||
		    (ixlopraw == IXL1394_OP_LABEL) ||
		    (wvp->ixl_cur_cmdp == NULL) ||
		    (wvp->ixl_cur_cmdp->next_ixlp == NULL)) {
			if ((wvp->ixl_settagsync_cmdp != NULL) ||
			    (wvp->ixl_setskipmode_cmdp != NULL) ||
			    (wvp->ixl_setsyncwait_cnt != 0)) {

				wvp->dma_bld_error = IXL1394_EUNAPPLIED_SET_CMD;

				TNF_PROBE_2(
				    hci1394_finalize_cur_xfer_desc_set_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_UNAPPLIED_SET_CMD: "
				    "orphaned set (no associated packet)",
				    tnf_opaque, ixl_commandp,
				    wvp->ixl_cur_cmdp);
				TNF_PROBE_0_DEBUG(
				    hci1394_finalize_cur_xfer_desc_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return;
			}
		}

		/* error if finalize is due to updateable jump cmd */
		if (ixlopcode == IXL1394_OP_JUMP_U) {

			wvp->dma_bld_error = IXL1394_EUPDATE_DISALLOWED;

			TNF_PROBE_2(hci1394_finalize_cur_xfer_desc_upd_error,
			    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
			    "IXL1394_EUPDATE_DISALLOWED: jumpU w/out pkt",
			    tnf_opaque, ixl_commandp, wvp->ixl_cur_cmdp);
			TNF_PROBE_0_DEBUG(hci1394_finalize_cur_xfer_desc_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return;
		}

		TNF_PROBE_0_DEBUG(hci1394_finalize_cur_xfer_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* no error, no xfer */
		return;
	}

	/*
	 * finalize current xfer descriptor block being built
	 */

	/* count IXL xfer start command for descriptor block being built */
	wvp->ixl_xfer_st_cnt++;

	/*
	 * complete setting of cache flush evaluation flags; flags will already
	 * have been set by updateable set cmds and non-start xfer pkt cmds
	 */
	/* now set cache flush flag if current xfer start cmnd is updateable */
	if ((wvp->ixl_cur_xfer_stp->ixl_opcode & IXL1394_OPF_UPDATE) != 0) {
		wvp->xfer_hci_flush |= UPDATEABLE_XFER;
	}
	/*
	 * also set cache flush flag if xfer being finalized by
	 * updateable jump cmd
	 */
	if ((ixlopcode == IXL1394_OP_JUMP_U) != 0) {
		wvp->xfer_hci_flush |= UPDATEABLE_JUMP;
	}

	/*
	 * Determine if cache flush required before building next descriptor
	 * block. If xfer pkt command and any cache flush flags are set,
	 * hci flush needed.
	 * If buffer or special xfer command and xfer command is updateable or
	 * an associated set command is updateable, hci flush is required now.
	 * If a single-xfer buffer or special xfer command is finalized by
	 * updateable jump command, hci flush is required now.
	 * Note: a cache flush will be required later, before the last
	 * descriptor block of a multi-xfer set of descriptor blocks is built,
	 * if this (non-pkt) xfer is finalized by an updateable jump command.
	 */
	if (wvp->xfer_hci_flush != 0) {
		if (((wvp->ixl_cur_xfer_stp->ixl_opcode &
		    IXL1394_OPTY_XFER_PKT_ST) != 0) || ((wvp->xfer_hci_flush &
		    (UPDATEABLE_XFER | UPDATEABLE_SET | INITIATING_LBL)) !=
		    0)) {

			if (hci1394_flush_hci_cache(wvp) != DDI_SUCCESS) {
				TNF_PROBE_0_DEBUG(
				    hci1394_finalize_cur_xfer_desc_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");

				/* wvp->dma_bld_error is set by above call */
				return;
			}
		}
	}

	/*
	 * determine which kind of descriptor block to build based on
	 * xfer state - hdr only, skip cycle, pkt or buf.
	 */
	switch (wvp->xfer_state) {

	case XFER_PKT:
		if ((wvp->ixl_io_mode & HCI1394_ISO_CTXT_RECV) != 0) {
			hci1394_bld_recv_pkt_desc(wvp);
		} else {
			hci1394_bld_xmit_pkt_desc(wvp);
		}
		break;

	case XFER_BUF:
		if ((wvp->ixl_io_mode & HCI1394_ISO_CTXT_RECV) != 0) {
			if ((wvp->ixl_io_mode & HCI1394_ISO_CTXT_BFFILL) != 0) {
				hci1394_bld_recv_buf_fill_desc(wvp);
			} else {
				hci1394_bld_recv_buf_ppb_desc(wvp);
			}
		} else {
			hci1394_bld_xmit_buf_desc(wvp);
		}
		break;

	case XMIT_HDRONLY:
	case XMIT_NOPKT:
		hci1394_bld_xmit_hdronly_nopkt_desc(wvp);
		break;

	default:
		/* internal compiler error */
		TNF_PROBE_2(hci1394_finalize_cur_xfer_desc_internal_error,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_INTERNAL_ERROR: invalid state", tnf_opaque,
		    ixl_commandp, wvp->ixl_cur_cmdp);
		wvp->dma_bld_error = IXL1394_EINTERNAL_ERROR;
	}

	/* return if error */
	if (wvp->dma_bld_error != 0) {
		TNF_PROBE_0_DEBUG(hci1394_finalize_cur_xfer_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* wvp->dma_bld_error is set by above call */
		return;
	}

	/*
	 * if was finalizing IXL jump cmd, set compiler_privatep to
	 * cur xfer IXL cmd
	 */
	if (ixlopraw == IXL1394_OP_JUMP) {
		wvp->ixl_cur_cmdp->compiler_privatep =
		    (void *)wvp->ixl_cur_xfer_stp;
	}

	/* if cur xfer IXL initiated by IXL label cmd, set flag in xfer_ctl */
	if (wvp->ixl_cur_labelp != NULL) {
		((hci1394_xfer_ctl_t *)
		    (wvp->ixl_cur_xfer_stp->compiler_privatep))->ctl_flags |=
		    XCTL_LABELLED;
		wvp->ixl_cur_labelp = NULL;
	}

	/*
	 * set any associated IXL set skipmode cmd into xfer_ctl of
	 * cur xfer IXL cmd
	 */
	if (wvp->ixl_setskipmode_cmdp != NULL) {
		((hci1394_xfer_ctl_t *)
		    (wvp->ixl_cur_xfer_stp->compiler_privatep))->skipmodep =
		    wvp->ixl_setskipmode_cmdp;
	}

	/* set no current xfer start cmd */
	wvp->ixl_cur_xfer_stp = NULL;

	/* set no current set tag&sync, set skipmode or set syncwait commands */
	wvp->ixl_settagsync_cmdp = NULL;
	wvp->ixl_setskipmode_cmdp = NULL;
	wvp->ixl_setsyncwait_cnt = 0;

	/* set no currently active descriptor blocks */
	wvp->descriptors = 0;

	/* reset total packet length and buffers count */
	wvp->xfer_pktlen = 0;
	wvp->xfer_bufcnt = 0;

	/* reset flush cache evaluation flags */
	wvp->xfer_hci_flush = 0;

	/* set no xmit descriptor block being built */
	wvp->xfer_state = XFER_NONE;

	TNF_PROBE_0_DEBUG(hci1394_finalize_cur_xfer_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_bld_recv_pkt_desc()
 *    Used to create the openHCI dma descriptor block(s) for a receive packet.
 */
static void
hci1394_bld_recv_pkt_desc(hci1394_comp_ixl_vars_t *wvp)
{
	hci1394_xfer_ctl_t	*xctlp;
	caddr_t			dma_descp;
	uint32_t		dma_desc_bound;
	uint32_t		wait_for_sync;
	uint32_t		ii;
	hci1394_desc_t		*wv_descp;	/* shorthand to local descrpt */

	TNF_PROBE_0_DEBUG(hci1394_bld_recv_pkt_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/*
	 * is error if number of descriptors to be built exceeds maximum
	 * descriptors allowed in a descriptor block.
	 */
	if ((wvp->descriptors + wvp->xfer_bufcnt) > HCI1394_DESC_MAX_Z) {

		wvp->dma_bld_error = IXL1394_EFRAGMENT_OFLO;

		TNF_PROBE_3(hci1394_bld_recv_pkt_desc_fragment_oflo_error,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EFRAGMENT_OFLO", tnf_opaque, ixl_commandp,
		    wvp->ixl_cur_xfer_stp, tnf_int, frag_count,
		    wvp->descriptors + wvp->xfer_bufcnt);
		TNF_PROBE_0_DEBUG(hci1394_bld_recv_pkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/* allocate an xfer_ctl struct, including 1 xfer_ctl_dma struct */
	if ((xctlp = hci1394_alloc_xfer_ctl(wvp, 1)) == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_2(hci1394_bld_recv_pkt_desc_mem_alloc_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: for xfer_ctl", tnf_opaque,
		    ixl_commandp, wvp->ixl_cur_xfer_stp);
		TNF_PROBE_0_DEBUG(hci1394_bld_recv_pkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/*
	 * save xfer_ctl struct addr in compiler_privatep of
	 * current IXL xfer cmd
	 */
	wvp->ixl_cur_xfer_stp->compiler_privatep = (void *)xctlp;

	/*
	 * if enabled, set wait for sync flag in first descriptor of
	 * descriptor block
	 */
	if (wvp->ixl_setsyncwait_cnt > 0) {
		wvp->ixl_setsyncwait_cnt = 1;
		wait_for_sync = DESC_W_ENBL;
	} else {
		wait_for_sync = DESC_W_DSABL;
	}

	/* create descriptor block for this recv packet (xfer status enabled) */
	for (ii = 0; ii < wvp->xfer_bufcnt; ii++) {
		wv_descp = &wvp->descriptor_block[wvp->descriptors];

		if (ii == (wvp->xfer_bufcnt - 1)) {
			HCI1394_INIT_IR_PPB_ILAST(wv_descp, DESC_HDR_STAT_ENBL,
			    DESC_INTR_DSABL, wait_for_sync, wvp->xfer_size[ii]);
		} else {
			HCI1394_INIT_IR_PPB_IMORE(wv_descp, wait_for_sync,
			    wvp->xfer_size[ii]);
		}
		wv_descp->data_addr = wvp->xfer_bufp[ii];
		wv_descp->branch = 0;
		wv_descp->status = (wvp->xfer_size[ii] <<
		    DESC_ST_RESCOUNT_SHIFT) & DESC_ST_RESCOUNT_MASK;
		wvp->descriptors++;
	}

	/* allocate and copy descriptor block to dma memory */
	if (hci1394_bld_dma_mem_desc_blk(wvp, &dma_descp, &dma_desc_bound) !=
	    DDI_SUCCESS) {
		TNF_PROBE_0_DEBUG(hci1394_bld_recv_pkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* wvp->dma_bld_error is set by above function call */
		return;
	}

	/*
	 * set dma addrs into xfer_ctl structure (unbound addr (kernel virtual)
	 * is last component)
	 */
	xctlp->dma[0].dma_bound = dma_desc_bound;
	xctlp->dma[0].dma_descp =
	    dma_descp + (wvp->xfer_bufcnt - 1) * sizeof (hci1394_desc_t);
	xctlp->dma[0].dma_buf	= &wvp->dma_currentp->mem;

	TNF_PROBE_0_DEBUG(hci1394_bld_recv_pkt_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_bld_recv_buf_ppb_desc()
 *    Used to create the openHCI dma descriptor block(s) for a receive buf
 *    in packet per buffer mode.
 */
static void
hci1394_bld_recv_buf_ppb_desc(hci1394_comp_ixl_vars_t *wvp)
{
	hci1394_xfer_ctl_t	*xctlp;
	ixl1394_xfer_buf_t	*local_ixl_cur_xfer_stp;
	caddr_t		dma_descp;
	uint32_t	dma_desc_bound;
	uint32_t	pktsize;
	uint32_t	pktcnt;
	uint32_t	wait_for_sync;
	uint32_t	ii;
	hci1394_desc_t	*wv_descp;	/* shorthand to local descriptor */

	TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_ppb_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	local_ixl_cur_xfer_stp = (ixl1394_xfer_buf_t *)wvp->ixl_cur_xfer_stp;

	/* determine number and size of pkt desc blocks to create */
	pktsize = local_ixl_cur_xfer_stp->pkt_size;
	pktcnt = local_ixl_cur_xfer_stp->size / pktsize;

	/* allocate an xfer_ctl struct including pktcnt xfer_ctl_dma structs */
	if ((xctlp = hci1394_alloc_xfer_ctl(wvp, pktcnt)) == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_2(hci1394_bld_recv_buf_ppb_desc_mem_alloc_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: for xfer_ctl", tnf_opaque,
		    ixl_commandp, wvp->ixl_cur_xfer_stp);
		TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_ppb_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/*
	 * save xfer_ctl struct addr in compiler_privatep of
	 * current IXL xfer cmd
	 */
	local_ixl_cur_xfer_stp->compiler_privatep = (void *)xctlp;

	/*
	 * if enabled, set wait for sync flag in first descriptor in
	 * descriptor block
	 */
	if (wvp->ixl_setsyncwait_cnt > 0) {
		wvp->ixl_setsyncwait_cnt = 1;
		wait_for_sync = DESC_W_ENBL;
	} else {
		wait_for_sync = DESC_W_DSABL;
	}

	/* create first descriptor block for this recv packet */
	/* consists of one descriptor and xfer status is enabled */
	wv_descp = &wvp->descriptor_block[wvp->descriptors];
	HCI1394_INIT_IR_PPB_ILAST(wv_descp, DESC_HDR_STAT_ENBL, DESC_INTR_DSABL,
	    wait_for_sync, pktsize);
	wv_descp->data_addr = local_ixl_cur_xfer_stp->ixl_buf.ixldmac_addr;
	wv_descp->branch = 0;
	wv_descp->status = (pktsize << DESC_ST_RESCOUNT_SHIFT) &
	    DESC_ST_RESCOUNT_MASK;
	wvp->descriptors++;

	/* useful debug trace info - IXL command, and packet count and size */
	TNF_PROBE_3_DEBUG(hci1394_bld_recv_buf_ppb_desc_recv_buf_info,
	    HCI1394_TNF_HAL_INFO_ISOCH, "", tnf_opaque, ixl_commandp,
	    wvp->ixl_cur_xfer_stp, tnf_int, pkt_count, pktcnt, tnf_int,
	    pkt_size, pktsize);

	/*
	 * generate as many contiguous descriptor blocks as there are
	 * recv pkts
	 */
	for (ii = 0; ii < pktcnt; ii++) {

		/* if about to create last descriptor block */
		if (ii == (pktcnt - 1)) {
			/* check and perform any required hci cache flush */
			if (hci1394_flush_end_desc_check(wvp, ii) !=
			    DDI_SUCCESS) {
				TNF_PROBE_1_DEBUG(
				    hci1394_bld_recv_buf_ppb_desc_fl_error,
				    HCI1394_TNF_HAL_INFO_ISOCH, "", tnf_int,
				    for_ii, ii);
				TNF_PROBE_0_DEBUG(
				    hci1394_bld_recv_buf_ppb_desc_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");

				/* wvp->dma_bld_error is set by above call */
				return;
			}
		}

		/* allocate and copy descriptor block to dma memory */
		if (hci1394_bld_dma_mem_desc_blk(wvp, &dma_descp,
		    &dma_desc_bound) != DDI_SUCCESS) {

			TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_ppb_desc_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");

			/* wvp->dma_bld_error is set by above call */
			return;
		}

		/*
		 * set dma addrs into xfer_ctl struct (unbound addr (kernel
		 * virtual) is last component (descriptor))
		 */
		xctlp->dma[ii].dma_bound = dma_desc_bound;
		xctlp->dma[ii].dma_descp = dma_descp;
		xctlp->dma[ii].dma_buf	 = &wvp->dma_currentp->mem;

		/* advance buffer ptr by pktsize in descriptor block */
		wvp->descriptor_block[wvp->descriptors - 1].data_addr +=
		    pktsize;
	}
	TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_ppb_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_bld_recv_buf_fill_desc()
 *    Used to create the openHCI dma descriptor block(s) for a receive buf
 *    in buffer fill mode.
 */
static void
hci1394_bld_recv_buf_fill_desc(hci1394_comp_ixl_vars_t *wvp)
{
	hci1394_xfer_ctl_t	*xctlp;
	caddr_t			dma_descp;
	uint32_t		dma_desc_bound;
	uint32_t		wait_for_sync;
	ixl1394_xfer_buf_t	*local_ixl_cur_xfer_stp;

	TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_fill_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	local_ixl_cur_xfer_stp = (ixl1394_xfer_buf_t *)wvp->ixl_cur_xfer_stp;


	/* allocate an xfer_ctl struct including 1 xfer_ctl_dma structs */
	if ((xctlp = hci1394_alloc_xfer_ctl(wvp, 1)) == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_2(hci1394_bld_recv_buf_fill_desc_mem_alloc_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: xfer_ctl", tnf_opaque,
		    ixl_commandp, wvp->ixl_cur_xfer_stp);
		TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_fill_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/*
	 * save xfer_ctl struct addr in compiler_privatep of
	 * current IXL xfer cmd
	 */
	local_ixl_cur_xfer_stp->compiler_privatep = (void *)xctlp;

	/*
	 * if enabled, set wait for sync flag in first descriptor of
	 * descriptor block
	 */
	if (wvp->ixl_setsyncwait_cnt > 0) {
		wvp->ixl_setsyncwait_cnt = 1;
		wait_for_sync = DESC_W_ENBL;
	} else {
		wait_for_sync = DESC_W_DSABL;
	}

	/*
	 * create descriptor block for this buffer fill mode recv command which
	 * consists of one descriptor with xfer status enabled
	 */
	HCI1394_INIT_IR_BF_IMORE(&wvp->descriptor_block[wvp->descriptors],
	    DESC_INTR_DSABL, wait_for_sync, local_ixl_cur_xfer_stp->size);

	wvp->descriptor_block[wvp->descriptors].data_addr =
	    local_ixl_cur_xfer_stp->ixl_buf.ixldmac_addr;
	wvp->descriptor_block[wvp->descriptors].branch = 0;
	wvp->descriptor_block[wvp->descriptors].status =
	    (local_ixl_cur_xfer_stp->size << DESC_ST_RESCOUNT_SHIFT) &
	    DESC_ST_RESCOUNT_MASK;
	wvp->descriptors++;

	/* check and perform any required hci cache flush */
	if (hci1394_flush_end_desc_check(wvp, 0) != DDI_SUCCESS) {
		TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_fill_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* wvp->dma_bld_error is set by above call */
		return;
	}

	/* allocate and copy descriptor block to dma memory */
	if (hci1394_bld_dma_mem_desc_blk(wvp, &dma_descp, &dma_desc_bound)
	    != DDI_SUCCESS) {
		TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_fill_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* wvp->dma_bld_error is set by above call */
		return;
	}

	/*
	 * set dma addrs into xfer_ctl structure (unbound addr (kernel virtual)
	 * is last component.
	 */
	xctlp->dma[0].dma_bound = dma_desc_bound;
	xctlp->dma[0].dma_descp = dma_descp;
	xctlp->dma[0].dma_buf	= &wvp->dma_currentp->mem;

	TNF_PROBE_0_DEBUG(hci1394_bld_recv_buf_fill_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_bld_xmit_pkt_desc()
 *    Used to create the openHCI dma descriptor block(s) for a transmit packet.
 */
static void
hci1394_bld_xmit_pkt_desc(hci1394_comp_ixl_vars_t *wvp)
{
	hci1394_xfer_ctl_t *xctlp;
	hci1394_output_more_imm_t *wv_omi_descp; /* shorthand to local descrp */
	hci1394_desc_t	*wv_descp;	/* shorthand to local descriptor */
	caddr_t		dma_descp;	/* dma bound memory for descriptor */
	uint32_t	dma_desc_bound;
	uint32_t	ii;

	TNF_PROBE_0_DEBUG(hci1394_bld_xmit_pkt_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/*
	 * is error if number of descriptors to be built exceeds maximum
	 * descriptors allowed in a descriptor block. Add 2 for the overhead
	 * of the OMORE-Immediate.
	 */
	if ((wvp->descriptors + 2 + wvp->xfer_bufcnt) > HCI1394_DESC_MAX_Z) {

		wvp->dma_bld_error = IXL1394_EFRAGMENT_OFLO;

		TNF_PROBE_3(hci1394_bld_xmit_pkt_desc_fragment_oflo_error,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EFRAGMENT_OFLO", tnf_opaque, ixl_commandp,
		    wvp->ixl_cur_xfer_stp, tnf_int, frag_count,
		    wvp->descriptors + 2 + wvp->xfer_bufcnt);
		TNF_PROBE_0_DEBUG(hci1394_bld_xmit_pkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/* is error if total packet length exceeds 0xFFFF */
	if (wvp->xfer_pktlen > 0xFFFF) {

		wvp->dma_bld_error = IXL1394_EPKTSIZE_MAX_OFLO;

		TNF_PROBE_3(hci1394_bld_xmit_pkt_desc_packet_oflo_error,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EPKTSIZE_MAX_OFLO", tnf_opaque, ixl_commandp,
		    wvp->ixl_cur_xfer_stp, tnf_int, total_pktlen,
		    wvp->xfer_pktlen);
		TNF_PROBE_0_DEBUG(hci1394_bld_xmit_pkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/* allocate an xfer_ctl struct, including 1 xfer_ctl_dma struct */
	if ((xctlp = hci1394_alloc_xfer_ctl(wvp, 1)) == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_2(hci1394_bld_xmit_pkt_desc_mem_alloc_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: for xfer_ctl", tnf_opaque,
		    ixl_commandp, wvp->ixl_cur_cmdp);
		TNF_PROBE_0_DEBUG(hci1394_bld_xmit_pkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/*
	 * save xfer_ctl struct addr in compiler_privatep of
	 * current IXL xfer cmd
	 */
	wvp->ixl_cur_xfer_stp->compiler_privatep = (void *)xctlp;

	/* generate values for the xmit pkt hdrs */
	hci1394_set_xmit_pkt_hdr(wvp);

	/*
	 * xmit pkt starts with an output more immediate,
	 * a double sized hci1394_desc
	 */
	wv_omi_descp = (hci1394_output_more_imm_t *)
	    (&wvp->descriptor_block[wvp->descriptors]);
	HCI1394_INIT_IT_OMORE_IMM(wv_omi_descp);

	wv_omi_descp->data_addr = 0;
	wv_omi_descp->branch = 0;
	wv_omi_descp->status = 0;
	wv_omi_descp->q1 = wvp->xmit_pkthdr1;
	wv_omi_descp->q2 = wvp->xmit_pkthdr2;
	wv_omi_descp->q3 = 0;
	wv_omi_descp->q4 = 0;

	wvp->descriptors += 2;

	/*
	 * create the required output more hci1394_desc descriptor, then create
	 * an output last hci1394_desc descriptor with xfer status enabled
	 */
	for (ii = 0; ii < wvp->xfer_bufcnt; ii++) {
		wv_descp = &wvp->descriptor_block[wvp->descriptors];

		if (ii == (wvp->xfer_bufcnt - 1)) {
			HCI1394_INIT_IT_OLAST(wv_descp, DESC_HDR_STAT_ENBL,
			    DESC_INTR_DSABL, wvp->xfer_size[ii]);
		} else {
			HCI1394_INIT_IT_OMORE(wv_descp, wvp->xfer_size[ii]);
		}
		wv_descp->data_addr = wvp->xfer_bufp[ii];
		wv_descp->branch = 0;
		wv_descp->status = 0;
		wvp->descriptors++;
	}

	/* allocate and copy descriptor block to dma memory */
	if (hci1394_bld_dma_mem_desc_blk(wvp, &dma_descp, &dma_desc_bound) !=
	    DDI_SUCCESS) {
		TNF_PROBE_0_DEBUG(hci1394_bld_xmit_pkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* wvp->dma_bld_error is set by above call */
		return;
	}

	/*
	 * set dma addrs into xfer_ctl structure (unbound addr (kernel virtual)
	 * is last component (descriptor))
	 */
	xctlp->dma[0].dma_bound = dma_desc_bound;
	xctlp->dma[0].dma_descp =
	    dma_descp + (wvp->xfer_bufcnt + 1) * sizeof (hci1394_desc_t);
	xctlp->dma[0].dma_buf	= &wvp->dma_currentp->mem;

	TNF_PROBE_0_DEBUG(hci1394_bld_xmit_pkt_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_bld_xmit_buf_desc()
 *    Used to create the openHCI dma descriptor blocks for a transmit buffer.
 */
static void
hci1394_bld_xmit_buf_desc(hci1394_comp_ixl_vars_t *wvp)
{
	hci1394_xfer_ctl_t	*xctlp;
	ixl1394_xfer_buf_t	*local_ixl_cur_xfer_stp;
	hci1394_output_more_imm_t *wv_omi_descp; /* shorthand to local descrp */
	hci1394_desc_t	*wv_descp;	/* shorthand to local descriptor */
	caddr_t		dma_descp;
	uint32_t	dma_desc_bound;
	uint32_t	pktsize;
	uint32_t	pktcnt;
	uint32_t	ii;

	TNF_PROBE_0_DEBUG(hci1394_bld_xmit_buf_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	local_ixl_cur_xfer_stp = (ixl1394_xfer_buf_t *)wvp->ixl_cur_xfer_stp;

	/* determine number and size of pkt desc blocks to create */
	pktsize = local_ixl_cur_xfer_stp->pkt_size;
	pktcnt = local_ixl_cur_xfer_stp->size / pktsize;

	/* allocate an xfer_ctl struct including pktcnt xfer_ctl_dma structs */
	if ((xctlp = hci1394_alloc_xfer_ctl(wvp, pktcnt)) == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_2(hci1394_bld_xmit_buf_desc_mem_alloc_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: for xfer_ctl", tnf_opaque,
		    ixl_commandp, wvp->ixl_cur_cmdp);
		TNF_PROBE_0_DEBUG(hci1394_bld_xmit_buf_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/*
	 * save xfer_ctl struct addr in compiler_privatep of
	 * current IXL xfer cmd
	 */
	local_ixl_cur_xfer_stp->compiler_privatep = (void *)xctlp;

	/* generate values for the xmit pkt hdrs */
	wvp->xfer_pktlen = pktsize;
	hci1394_set_xmit_pkt_hdr(wvp);

	/*
	 * xmit pkt starts with an output more immediate,
	 * a double sized hci1394_desc
	 */
	wv_omi_descp = (hci1394_output_more_imm_t *)
	    &wvp->descriptor_block[wvp->descriptors];

	HCI1394_INIT_IT_OMORE_IMM(wv_omi_descp);

	wv_omi_descp->data_addr = 0;
	wv_omi_descp->branch = 0;
	wv_omi_descp->status = 0;
	wv_omi_descp->q1 = wvp->xmit_pkthdr1;
	wv_omi_descp->q2 = wvp->xmit_pkthdr2;
	wv_omi_descp->q3 = 0;
	wv_omi_descp->q4 = 0;

	wvp->descriptors += 2;

	/* follow with a single output last descriptor w/status enabled */
	wv_descp = &wvp->descriptor_block[wvp->descriptors];
	HCI1394_INIT_IT_OLAST(wv_descp, DESC_HDR_STAT_ENBL, DESC_INTR_DSABL,
	    pktsize);
	wv_descp->data_addr = local_ixl_cur_xfer_stp->ixl_buf.ixldmac_addr;
	wv_descp->branch = 0;
	wv_descp->status = 0;
	wvp->descriptors++;

	/*
	 * generate as many contiguous descriptor blocks as there are
	 * xmit packets
	 */
	for (ii = 0; ii < pktcnt; ii++) {

		/* if about to create last descriptor block */
		if (ii == (pktcnt - 1)) {
			/* check and perform any required hci cache flush */
			if (hci1394_flush_end_desc_check(wvp, ii) !=
			    DDI_SUCCESS) {
				TNF_PROBE_0_DEBUG(
				    hci1394_bld_xmit_buf_desc_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");

				/* wvp->dma_bld_error is set by above call */
				return;
			}
		}

		/* allocate and copy descriptor block to dma memory */
		if (hci1394_bld_dma_mem_desc_blk(wvp, &dma_descp,
		    &dma_desc_bound) != DDI_SUCCESS) {
			TNF_PROBE_0_DEBUG(hci1394_bld_xmit_buf_desc_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");

			/* wvp->dma_bld_error is set by above call */
			return;
		}

		/*
		 * set dma addrs into xfer_ctl structure (unbound addr
		 * (kernel virtual) is last component (descriptor))
		 */
		xctlp->dma[ii].dma_bound = dma_desc_bound;
		xctlp->dma[ii].dma_descp = dma_descp + 2 *
		    sizeof (hci1394_desc_t);
		xctlp->dma[ii].dma_buf	 = &wvp->dma_currentp->mem;

		/* advance buffer ptr by pktsize in descriptor block */
		wvp->descriptor_block[wvp->descriptors - 1].data_addr +=
		    pktsize;
	}
	TNF_PROBE_0_DEBUG(hci1394_bld_xmit_buf_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_bld_xmit_hdronly_nopkt_desc()
 *    Used to create the openHCI dma descriptor blocks for transmitting
 *    a packet consisting of an isochronous header with no data payload,
 *    or for not sending a packet at all for a cycle.
 *
 *    A Store_Value openhci descriptor is built at the start of each
 *    IXL1394_OP_SEND_HDR_ONLY and IXL1394_OP_SEND_NO_PKT command's dma
 *    descriptor block (to allow for skip cycle specification and set skipmode
 *    processing for these commands).
 */
static void
hci1394_bld_xmit_hdronly_nopkt_desc(hci1394_comp_ixl_vars_t *wvp)
{
	hci1394_xfer_ctl_t	*xctlp;
	hci1394_output_last_t	*wv_ol_descp; /* shorthand to local descrp */
	hci1394_output_last_imm_t *wv_oli_descp; /* shorthand to local descrp */
	caddr_t		dma_descp;
	uint32_t	dma_desc_bound;
	uint32_t	repcnt;
	uint32_t	ii;

	TNF_PROBE_0_DEBUG(hci1394_bld_xmit_hdronly_nopkt_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* determine # of instances of output hdronly/nopkt to generate */
	repcnt = ((ixl1394_xmit_special_t *)wvp->ixl_cur_xfer_stp)->count;

	/*
	 * allocate an xfer_ctl structure which includes repcnt
	 * xfer_ctl_dma structs
	 */
	if ((xctlp = hci1394_alloc_xfer_ctl(wvp, repcnt)) == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_2(hci1394_bld_xmit_hdronly_nopkt_desc_mem_alloc_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL EMEM_ALLOC_FAIL: for xfer_ctl", tnf_opaque,
		    ixl_commandp, wvp->ixl_cur_cmdp);
		TNF_PROBE_0_DEBUG(hci1394_bld_xmit_hdronly_nopkt_desc_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return;
	}

	/*
	 * save xfer_ctl struct addr in compiler_privatep of
	 * current IXL xfer command
	 */
	wvp->ixl_cur_xfer_stp->compiler_privatep = (void *)xctlp;

	/*
	 * create a storevalue descriptor
	 * (will be used for skip vs jump processing)
	 */
	hci1394_set_xmit_storevalue_desc(wvp);

	/*
	 * processing now based on opcode:
	 * IXL1394_OP_SEND_HDR_ONLY or IXL1394_OP_SEND_NO_PKT
	 */
	if ((wvp->ixl_cur_xfer_stp->ixl_opcode & ~IXL1394_OPF_UPDATE) ==
	    IXL1394_OP_SEND_HDR_ONLY) {

		/* for header only, generate values for the xmit pkt hdrs */
		hci1394_set_xmit_pkt_hdr(wvp);

		/*
		 * create an output last immediate (double sized) descriptor
		 * xfer status enabled
		 */
		wv_oli_descp = (hci1394_output_last_imm_t *)
		    &wvp->descriptor_block[wvp->descriptors];

		HCI1394_INIT_IT_OLAST_IMM(wv_oli_descp, DESC_HDR_STAT_ENBL,
		    DESC_INTR_DSABL);

		wv_oli_descp->data_addr = 0;
		wv_oli_descp->branch = 0;
		wv_oli_descp->status = 0;
		wv_oli_descp->q1 = wvp->xmit_pkthdr1;
		wv_oli_descp->q2 = wvp->xmit_pkthdr2;
		wv_oli_descp->q3 = 0;
		wv_oli_descp->q4 = 0;
		wvp->descriptors += 2;
	} else {
		/*
		 * for skip cycle, create a single output last descriptor
		 * with xfer status enabled
		 */
		wv_ol_descp = &wvp->descriptor_block[wvp->descriptors];
		HCI1394_INIT_IT_OLAST(wv_ol_descp, DESC_HDR_STAT_ENBL,
		    DESC_INTR_DSABL, 0);
		wv_ol_descp->data_addr = 0;
		wv_ol_descp->branch = 0;
		wv_ol_descp->status = 0;
		wvp->descriptors++;
	}

	/*
	 * generate as many contiguous descriptor blocks as repeat count
	 * indicates
	 */
	for (ii = 0; ii < repcnt; ii++) {

		/* if about to create last descriptor block */
		if (ii == (repcnt - 1)) {
			/* check and perform any required hci cache flush */
			if (hci1394_flush_end_desc_check(wvp, ii) !=
			    DDI_SUCCESS) {
				TNF_PROBE_0_DEBUG(
				    hci1394_bld_xmit_hdronly_nopkt_desc_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");

				/* wvp->dma_bld_error is set by above call */
				return;
			}
		}

		/* allocate and copy descriptor block to dma memory */
		if (hci1394_bld_dma_mem_desc_blk(wvp, &dma_descp,
		    &dma_desc_bound) != DDI_SUCCESS) {
			TNF_PROBE_0_DEBUG(
			    hci1394_bld_xmit_hdronly_nopkt_desc_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");

			/* wvp->dma_bld_error is set by above call */
			return;
		}

		/*
		 * set dma addrs into xfer_ctl structure (unbound addr
		 * (kernel virtual) is last component (descriptor)
		 */
		xctlp->dma[ii].dma_bound = dma_desc_bound;
		xctlp->dma[ii].dma_descp = dma_descp + sizeof (hci1394_desc_t);
		xctlp->dma[ii].dma_buf	 = &wvp->dma_currentp->mem;
	}
	TNF_PROBE_0_DEBUG(hci1394_bld_xmit_hdronly_nopkt_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_bld_dma_mem_desc_blk()
 *    Used to put a given OpenHCI descriptor block into dma bound memory.
 */
static int
hci1394_bld_dma_mem_desc_blk(hci1394_comp_ixl_vars_t *wvp, caddr_t *dma_descpp,
    uint32_t *dma_desc_bound)
{
	uint32_t	dma_bound;

	TNF_PROBE_0_DEBUG(hci1394_bld_dma_mem_desc_blk_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* set internal error if no descriptor blocks to build */
	if (wvp->descriptors == 0) {

		wvp->dma_bld_error = IXL1394_EINTERNAL_ERROR;

		TNF_PROBE_1(hci1394_bld_dma_mem_desc_blk_error,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_INTERNAL_ERROR: no descriptors to build");
		TNF_PROBE_0_DEBUG(hci1394_bld_dma_mem_desc_blk_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	/* allocate dma memory and move this descriptor block to it */
	*dma_descpp = (caddr_t)hci1394_alloc_dma_mem(wvp, wvp->descriptors *
	    sizeof (hci1394_desc_t), &dma_bound);

	if (*dma_descpp == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_1(hci1394_bld_dma_mem_desc_blk_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: for descriptors");
		TNF_PROBE_0_DEBUG(hci1394_bld_dma_mem_desc_blk_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}
#ifdef _KERNEL
	ddi_rep_put32(wvp->dma_currentp->mem.bi_handle,
	    (uint_t *)wvp->descriptor_block, (uint_t *)*dma_descpp,
	    wvp->descriptors * (sizeof (hci1394_desc_t) >> 2),
	    DDI_DEV_AUTOINCR);
#else
	bcopy(wvp->descriptor_block, *dma_descpp,
	    wvp->descriptors * sizeof (hci1394_desc_t));
#endif
	/*
	 * convert allocated block's memory address to bus address space
	 * include properly set Z bits (descriptor count).
	 */
	*dma_desc_bound = (dma_bound & ~DESC_Z_MASK) | wvp->descriptors;

	TNF_PROBE_0_DEBUG(hci1394_bld_dma_mem_desc_blk_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	return (DDI_SUCCESS);
}

/*
 * hci1394_set_xmit_pkt_hdr()
 *    Compose the 2 quadlets for the xmit packet header.
 */
static void
hci1394_set_xmit_pkt_hdr(hci1394_comp_ixl_vars_t *wvp)
{
	uint16_t tag;
	uint16_t sync;

	TNF_PROBE_0_DEBUG(hci1394_set_xmit_pkt_hdr_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/*
	 * choose tag and sync bits for header either from default values or
	 * from currently active set tag and sync IXL command
	 * (clear command after use)
	 */
	if (wvp->ixl_settagsync_cmdp == NULL) {
		tag = wvp->default_tag;
		sync = wvp->default_sync;
	} else {
		tag = wvp->ixl_settagsync_cmdp->tag;
		sync = wvp->ixl_settagsync_cmdp->sync;
		wvp->ixl_settagsync_cmdp = NULL;
	}
	tag &= (DESC_PKT_TAG_MASK >> DESC_PKT_TAG_SHIFT);
	sync &= (DESC_PKT_SY_MASK >> DESC_PKT_SY_SHIFT);

	/*
	 * build xmit pkt header -
	 * hdr1 has speed, tag, channel number and sync bits
	 * hdr2 has the packet length.
	 */
	wvp->xmit_pkthdr1 = (wvp->ctxtp->isospd << DESC_PKT_SPD_SHIFT) |
	    (tag << DESC_PKT_TAG_SHIFT) | (wvp->ctxtp->isochan <<
	    DESC_PKT_CHAN_SHIFT) | (IEEE1394_TCODE_ISOCH <<
	    DESC_PKT_TCODE_SHIFT) | (sync << DESC_PKT_SY_SHIFT);

	wvp->xmit_pkthdr2 = wvp->xfer_pktlen << DESC_PKT_DATALEN_SHIFT;

	TNF_PROBE_0_DEBUG(hci1394_set_xmit_pkt_hdr_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_set_xmit_skip_mode()
 *    Set current skip mode from default or from currently active command.
 *    If non-default skip mode command's skip mode is skip to label, find
 *    and set xfer start IXL command which follows skip to label into
 *    compiler_privatep of set skipmode IXL command.
 */
static void
hci1394_set_xmit_skip_mode(hci1394_comp_ixl_vars_t *wvp)
{
	int err;

	TNF_PROBE_0_DEBUG(hci1394_set_xmit_skip_mode_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	if (wvp->ixl_setskipmode_cmdp == NULL) {
		wvp->skipmode = wvp->default_skipmode;
		wvp->skiplabelp = wvp->default_skiplabelp;
		wvp->skipxferp = wvp->default_skipxferp;
	} else {
		wvp->skipmode = wvp->ixl_setskipmode_cmdp->skipmode;
		wvp->skiplabelp = wvp->ixl_setskipmode_cmdp->label;
		wvp->skipxferp = NULL;
		if (wvp->skipmode == IXL1394_SKIP_TO_LABEL) {
			err = hci1394_ixl_find_next_exec_xfer(wvp->skiplabelp,
			    NULL, &wvp->skipxferp);
			if (err == DDI_FAILURE) {
				TNF_PROBE_2(hci1394_set_xmit_skip_mode_error,
				    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string,
				    errmsg, "IXL1394_ENO_DATA_PKTS: "
				    "label<->jump loop detected for skiplabel "
				    "w/no xfers", tnf_opaque, setskip_cmdp,
				    wvp->ixl_setskipmode_cmdp);
				wvp->skipxferp = NULL;
				wvp->dma_bld_error = IXL1394_ENO_DATA_PKTS;
			}
		}
		wvp->ixl_setskipmode_cmdp->compiler_privatep =
		    (void *)wvp->skipxferp;
	}
	TNF_PROBE_0_DEBUG(hci1394_set_xmit_skip_mode_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_set_xmit_storevalue_desc()
 *    Set up store_value DMA descriptor.
 *    XMIT_HDRONLY or XMIT_NOPKT xfer states use a store value as first
 *    descriptor in the descriptor block (to handle skip mode processing)
 */
static void
hci1394_set_xmit_storevalue_desc(hci1394_comp_ixl_vars_t *wvp)
{
	TNF_PROBE_0_DEBUG(hci1394_set_xmit_storevalue_desc_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	wvp->descriptors++;

	HCI1394_INIT_IT_STORE(&wvp->descriptor_block[wvp->descriptors - 1],
	    wvp->storevalue_data);
	wvp->descriptor_block[wvp->descriptors - 1].data_addr =
	    wvp->storevalue_bufp;
	wvp->descriptor_block[wvp->descriptors - 1].branch = 0;
	wvp->descriptor_block[wvp->descriptors - 1].status = 0;

	TNF_PROBE_0_DEBUG(hci1394_set_xmit_storevalue_desc_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}

/*
 * hci1394_set_next_xfer_buf()
 *    This routine adds the data buffer to the current wvp list.
 *    Returns DDI_SUCCESS or DDI_FAILURE. If DDI_FAILURE, wvp->dma_bld_error
 *    contains the error code.
 */
static int
hci1394_set_next_xfer_buf(hci1394_comp_ixl_vars_t *wvp, uint32_t bufp,
    uint16_t size)
{
	TNF_PROBE_0_DEBUG(hci1394_set_next_xfer_buf_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* error if buffer pointer is null (size may be 0) */
	if (bufp == 0) {

		wvp->dma_bld_error = IXL1394_ENULL_BUFFER_ADDR;

		TNF_PROBE_0_DEBUG(hci1394_set_next_xfer_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	/* count new xfer buffer */
	wvp->xfer_bufcnt++;

	/* error if exceeds maximum xfer buffer components allowed */
	if (wvp->xfer_bufcnt > HCI1394_DESC_MAX_Z) {

		wvp->dma_bld_error = IXL1394_EFRAGMENT_OFLO;

		TNF_PROBE_2(hci1394_set_next_xfer_buf_error,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EFRAGMENT_OFLO", tnf_int, frag_count,
		    wvp->xfer_bufcnt);
		TNF_PROBE_0_DEBUG(hci1394_set_next_xfer_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	/* save xmit buffer and size */
	wvp->xfer_bufp[wvp->xfer_bufcnt - 1] = bufp;
	wvp->xfer_size[wvp->xfer_bufcnt - 1] = size;

	/* accumulate total packet length */
	wvp->xfer_pktlen += size;

	TNF_PROBE_0_DEBUG(hci1394_set_next_xfer_buf_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (DDI_SUCCESS);
}

/*
 * hci1394_flush_end_desc_check()
 *    Check if flush required before last descriptor block of a
 *    non-unary set generated by an xfer buff or xmit special command
 *    or a unary set provided no other flush has already been done.
 *
 *    hci flush is required if xfer is finalized by an updateable
 *    jump command.
 *
 *    Returns DDI_SUCCESS or DDI_FAILURE. If DDI_FAILURE, wvp->dma_bld_error
 *    will contain the error code.
 */
static int
hci1394_flush_end_desc_check(hci1394_comp_ixl_vars_t *wvp, uint32_t count)
{
	TNF_PROBE_0_DEBUG(hci1394_flush_end_desc_check_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	if ((count != 0) ||
	    ((wvp->xfer_hci_flush & (UPDATEABLE_XFER | UPDATEABLE_SET |
	    INITIATING_LBL)) == 0)) {

		if (wvp->xfer_hci_flush & UPDATEABLE_JUMP) {
			if (hci1394_flush_hci_cache(wvp) != DDI_SUCCESS) {

				TNF_PROBE_0_DEBUG(
				    hci1394_flush_end_desc_check_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");

				/* wvp->dma_bld_error is set by above call */
				return (DDI_FAILURE);
			}
		}
	}

	TNF_PROBE_0_DEBUG(hci1394_flush_end_desc_check_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (DDI_SUCCESS);
}

/*
 * hci1394_flush_hci_cache()
 *    Sun hci controller (RIO) implementation specific processing!
 *
 *    Allocate dma memory for 1 hci descriptor block which will be left unused.
 *    During execution this will cause a break in the contiguous address space
 *    processing required by Sun's RIO implementation of the ohci controller and
 *    will require the controller to refetch the next descriptor block from
 *    host memory.
 *
 *    General rules for cache flush preceeding a descriptor block in dma memory:
 *    1. Current IXL Xfer Command Updateable Rule:
 *	    Cache flush of IXL xfer command is required if it, or any of the
 *	    non-start IXL packet xfer commands associated with it, is flagged
 *	    updateable.
 *    2. Next IXL Xfer Command Indeterminate Rule:
 *	    Cache flush of IXL xfer command is required if an IXL jump command
 *	    which is flagged updateable has finalized the current IXL xfer
 *	    command.
 *    3. Updateable IXL Set Command Rule:
 *	    Cache flush of an IXL xfer command is required if any of the IXL
 *	    "Set" commands (IXL1394_OP_SET_*) associated with the IXL xfer
 *	    command (i.e. immediately preceeding it), is flagged updateable.
 *    4. Label Initiating Xfer Command Rule:
 *	    Cache flush of IXL xfer command is required if it is initiated by a
 *	    label IXL command.  (This is to allow both a flush of the cache and
 *	    an interrupt to be generated easily and in close proximity to each
 *	    other.  This can make possible simpler more successful reset of
 *	    descriptor statuses, especially under circumstances where the cycle
 *	    of hci commands is short and/or there are no callbacks distributed
 *	    through the span of xfers, etc...  This is especially important for
 *	    input where statuses must be reset before execution cycles back
 *	    again.
 *
 *    Application of above rules:
 *    Packet mode IXL xfer commands:
 *	    If any of the above flush rules apply, flush cache should be done
 *	    immediately preceeding the generation of the dma descriptor block
 *	    for the packet xfer.
 *    Non-packet mode IXL xfer commands (including IXL1394_OP_*BUF*,
 *    SEND_HDR_ONLY, and SEND_NO_PKT):
 *	    If Rules #1, #3 or #4 applies, a flush cache should be done
 *	    immediately before the first generated dma descriptor block of the
 *	    non-packet xfer.
 *	    If Rule #2 applies, a flush cache should be done immediately before
 *	    the last generated dma descriptor block of the non-packet xfer.
 *
 *    Note: The flush cache should be done at most once in each location that is
 *    required to be flushed no matter how many rules apply (i.e. only once
 *    before the first descriptor block and/or only once before the last
 *    descriptor block generated).  If more than one place requires a flush,
 *    then both flush operations must be performed.  This is determined by
 *    taking all rules that apply into account.
 *
 *    Returns DDI_SUCCESS or DDI_FAILURE. If DDI_FAILURE, wvp->dma_bld_error
 *    will contain the error code.
 */
static int
hci1394_flush_hci_cache(hci1394_comp_ixl_vars_t *wvp)
{
	uint32_t	dma_bound;

	TNF_PROBE_0_DEBUG(hci1394_flush_hci_cache_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	if (hci1394_alloc_dma_mem(wvp, sizeof (hci1394_desc_t), &dma_bound) ==
	    NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_1(hci1394_flush_hci_cache_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: for flush_hci_cache");
		TNF_PROBE_0_DEBUG(hci1394_flush_hci_cache_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_flush_hci_cache_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (DDI_SUCCESS);
}

/*
 * hci1394_alloc_storevalue_dma_mem()
 *    Allocate dma memory for a 1 hci component descriptor block
 *    which will be used as the dma memory location that ixl
 *    compiler generated storevalue descriptor commands will
 *    specify as location to store their data value.
 *
 *    Returns 32-bit bound address of allocated mem, or NULL.
 */
static uint32_t
hci1394_alloc_storevalue_dma_mem(hci1394_comp_ixl_vars_t *wvp)
{
	uint32_t	dma_bound;

	TNF_PROBE_0_DEBUG(hci1394_alloc_storevalue_dma_mem_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	if (hci1394_alloc_dma_mem(wvp, sizeof (hci1394_desc_t),
	    &dma_bound) == NULL) {

		wvp->dma_bld_error = IXL1394_EMEM_ALLOC_FAIL;

		TNF_PROBE_2(hci1394_bld_alloc_storevalue_dma_mem_alloc_fail,
		    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, errmsg,
		    "IXL1394_EMEM_ALLOC_FAIL: for storevalue dma",
		    tnf_opaque, ixl_commandp, wvp->ixl_cur_cmdp);
		TNF_PROBE_0_DEBUG(hci1394_alloc_storevalue_dma_mem_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (0);
	}

	TNF_PROBE_0_DEBUG(hci1394_alloc_storevalue_dma_mem_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* return bound address of allocated memory */
	return (dma_bound);
}


/*
 * hci1394_alloc_xfer_ctl()
 *    Allocate an xfer_ctl structure.
 */
static hci1394_xfer_ctl_t *
hci1394_alloc_xfer_ctl(hci1394_comp_ixl_vars_t *wvp, uint32_t dmacnt)
{
	hci1394_xfer_ctl_t *xcsp;

	TNF_PROBE_0_DEBUG(hci1394_alloc_xfer_ctl_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/*
	 * allocate an xfer_ctl struct which includes dmacnt of
	 * xfer_ctl_dma structs
	 */
#ifdef _KERNEL
	if ((xcsp = (hci1394_xfer_ctl_t *)kmem_zalloc(
	    (sizeof (hci1394_xfer_ctl_t) + (dmacnt - 1) *
	    sizeof (hci1394_xfer_ctl_dma_t)), KM_NOSLEEP)) == NULL) {

		TNF_PROBE_0_DEBUG(hci1394_alloc_xfer_ctl_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (NULL);
	}
#else
	/*
	 * This section makes it possible to easily run and test the compiler in
	 * user mode.
	 */
	if ((xcsp = (hci1394_xfer_ctl_t *)calloc(1,
	    sizeof (hci1394_xfer_ctl_t) + (dmacnt - 1) *
	    sizeof (hci1394_xfer_ctl_dma_t))) == NULL) {

		TNF_PROBE_0_DEBUG(hci1394_alloc_xfer_ctl_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (NULL);
	}
#endif
	/*
	 * set dma structure count into allocated xfer_ctl struct for
	 * later deletion.
	 */
	xcsp->cnt = dmacnt;

	/* link it to previously allocated xfer_ctl structs or set as first */
	if (wvp->xcs_firstp == NULL) {
		wvp->xcs_firstp = wvp->xcs_currentp = xcsp;
	} else {
		wvp->xcs_currentp->ctl_nextp = xcsp;
		wvp->xcs_currentp = xcsp;
	}

	TNF_PROBE_0_DEBUG(hci1394_alloc_xfer_ctl_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* return allocated xfer_ctl structure */
	return (xcsp);
}

/*
 * hci1394_alloc_dma_mem()
 *	Allocates and binds memory for openHCI DMA descriptors as needed.
 */
static void *
hci1394_alloc_dma_mem(hci1394_comp_ixl_vars_t *wvp, uint32_t size,
    uint32_t *dma_bound)
{
	hci1394_idma_desc_mem_t *dma_new;
	hci1394_buf_parms_t parms;
	hci1394_buf_info_t *memp;
	void	*dma_mem_ret;
	int	ret;

	TNF_PROBE_0_DEBUG(hci1394_alloc_dma_mem_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/*
	 * if no dma has been allocated or current request exceeds
	 * remaining memory
	 */
	if ((wvp->dma_currentp == NULL) ||
	    (size > (wvp->dma_currentp->mem.bi_cookie.dmac_size -
	    wvp->dma_currentp->used))) {
#ifdef _KERNEL
		/* kernel-mode memory allocation for driver */

		/* allocate struct to track more dma descriptor memory */
		if ((dma_new = (hci1394_idma_desc_mem_t *)
		    kmem_zalloc(sizeof (hci1394_idma_desc_mem_t),
		    KM_NOSLEEP)) == NULL) {

			TNF_PROBE_0_DEBUG(hci1394_alloc_dma_mem_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (NULL);
		}

		/*
		 * if more cookies available from the current mem, try to find
		 * one of suitable size. Cookies that are too small will be
		 * skipped and unused. Given that cookie size is always at least
		 * 1 page long and HCI1394_DESC_MAX_Z is much smaller than that,
		 * it's a small price to pay for code simplicity.
		 */
		if (wvp->dma_currentp != NULL) {
			/* new struct is derived from current */
			memp = &wvp->dma_currentp->mem;
			dma_new->mem = *memp;
			dma_new->offset = wvp->dma_currentp->offset +
			    memp->bi_cookie.dmac_size;

			for (; memp->bi_cookie_count > 1;
			    memp->bi_cookie_count--) {
				ddi_dma_nextcookie(memp->bi_dma_handle,
				    &dma_new->mem.bi_cookie);

				if (dma_new->mem.bi_cookie.dmac_size >= size) {
					dma_new->mem_handle =
					    wvp->dma_currentp->mem_handle;
					wvp->dma_currentp->mem_handle = NULL;
					dma_new->mem.bi_cookie_count--;
					break;
				}
				dma_new->offset +=
				    dma_new->mem.bi_cookie.dmac_size;
			}
		}

		/* if no luck with current buffer, allocate a new one */
		if (dma_new->mem_handle == NULL) {
			parms.bp_length = HCI1394_IXL_PAGESIZE;
			parms.bp_max_cookies = OHCI_MAX_COOKIE;
			parms.bp_alignment = 16;
			ret = hci1394_buf_alloc(&wvp->soft_statep->drvinfo,
			    &parms, &dma_new->mem, &dma_new->mem_handle);
			if (ret != DDI_SUCCESS) {
				kmem_free(dma_new,
				    sizeof (hci1394_idma_desc_mem_t));

				TNF_PROBE_0_DEBUG(hci1394_alloc_dma_mem_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (NULL);
			}

			/* paranoia: this is not supposed to happen */
			if (dma_new->mem.bi_cookie.dmac_size < size) {
				hci1394_buf_free(&dma_new->mem_handle);
				kmem_free(dma_new,
				    sizeof (hci1394_idma_desc_mem_t));

				TNF_PROBE_0_DEBUG(hci1394_alloc_dma_mem_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (NULL);
			}
			dma_new->offset = 0;
		}
#else
		/* user-mode memory allocation for user mode compiler tests */
		/* allocate another dma_desc_mem struct */
		if ((dma_new = (hci1394_idma_desc_mem_t *)
		    calloc(1, sizeof (hci1394_idma_desc_mem_t))) == NULL) {
			TNF_PROBE_0_DEBUG(hci1394_alloc_dma_mem_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (NULL);
		}
		dma_new->mem.bi_dma_handle = NULL;
		dma_new->mem.bi_handle = NULL;
		if ((dma_new->mem.bi_kaddr = (caddr_t)calloc(1,
		    HCI1394_IXL_PAGESIZE)) == NULL) {
			TNF_PROBE_0_DEBUG(hci1394_alloc_dma_mem_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (NULL);
		}
		dma_new->mem.bi_cookie.dmac_address =
		    (unsigned long)dma_new->mem.bi_kaddr;
		dma_new->mem.bi_real_length = HCI1394_IXL_PAGESIZE;
		dma_new->mem.bi_cookie_count = 1;
#endif

		/* if this is not first dma_desc_mem, link last one to it */
		if (wvp->dma_currentp != NULL) {
			wvp->dma_currentp->dma_nextp = dma_new;
			wvp->dma_currentp = dma_new;
		} else {
			/* else set it as first one */
			wvp->dma_currentp = wvp->dma_firstp = dma_new;
		}
	}

	/* now allocate requested memory from current block */
	dma_mem_ret = wvp->dma_currentp->mem.bi_kaddr +
	    wvp->dma_currentp->offset + wvp->dma_currentp->used;
	*dma_bound = wvp->dma_currentp->mem.bi_cookie.dmac_address +
	    wvp->dma_currentp->used;
	wvp->dma_currentp->used += size;

	TNF_PROBE_0_DEBUG(hci1394_alloc_dma_mem_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (dma_mem_ret);
}


/*
 * hci1394_is_opcode_valid()
 *    given an ixl opcode, this routine returns B_TRUE if it is a
 *    recognized opcode and B_FALSE if it is not recognized.
 *    Note that the FULL 16 bits of the opcode are checked which includes
 *    various flags and not just the low order 8 bits of unique code.
 */
static boolean_t
hci1394_is_opcode_valid(uint16_t ixlopcode)
{
	TNF_PROBE_0_DEBUG(hci1394_is_opcode_bad_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* if it's not one we know about, then it's bad */
	switch (ixlopcode) {
	case IXL1394_OP_LABEL:
	case IXL1394_OP_JUMP:
	case IXL1394_OP_CALLBACK:
	case IXL1394_OP_RECV_PKT:
	case IXL1394_OP_RECV_PKT_ST:
	case IXL1394_OP_RECV_BUF:
	case IXL1394_OP_SEND_PKT:
	case IXL1394_OP_SEND_PKT_ST:
	case IXL1394_OP_SEND_PKT_WHDR_ST:
	case IXL1394_OP_SEND_BUF:
	case IXL1394_OP_SEND_HDR_ONLY:
	case IXL1394_OP_SEND_NO_PKT:
	case IXL1394_OP_STORE_TIMESTAMP:
	case IXL1394_OP_SET_TAGSYNC:
	case IXL1394_OP_SET_SKIPMODE:
	case IXL1394_OP_SET_SYNCWAIT:
	case IXL1394_OP_JUMP_U:
	case IXL1394_OP_CALLBACK_U:
	case IXL1394_OP_RECV_PKT_U:
	case IXL1394_OP_RECV_PKT_ST_U:
	case IXL1394_OP_RECV_BUF_U:
	case IXL1394_OP_SEND_PKT_U:
	case IXL1394_OP_SEND_PKT_ST_U:
	case IXL1394_OP_SEND_PKT_WHDR_ST_U:
	case IXL1394_OP_SEND_BUF_U:
	case IXL1394_OP_SET_TAGSYNC_U:
	case IXL1394_OP_SET_SKIPMODE_U:
		TNF_PROBE_1_DEBUG(hci1394_is_opcode_valid_enter,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, msg,
		    "ixl opcode is valid");
		TNF_PROBE_0_DEBUG(hci1394_is_opcode_bad_enter,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (B_TRUE);
	default:
		TNF_PROBE_2(hci1394_is_opcode_valid_enter,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, msg,
		    "ixl opcode is NOT valid", tnf_opaque, ixl_opcode,
		    ixlopcode);
		TNF_PROBE_0_DEBUG(hci1394_is_opcode_valid_enter,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (B_FALSE);
	}
}
