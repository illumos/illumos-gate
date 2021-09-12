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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hci1394_ixl_misc.c
 *    Isochronous IXL miscellaneous routines.
 *    Contains common routines used by the ixl compiler, interrupt handler and
 *    dynamic update.
 */

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ixl1394.h>
#include <sys/1394/adapters/hci1394.h>


/* local routines */
static void hci1394_delete_dma_desc_mem(hci1394_state_t *soft_statep,
    hci1394_idma_desc_mem_t *);
static void hci1394_delete_xfer_ctl(hci1394_xfer_ctl_t *);


/*
 * hci1394_ixl_set_start()
 *    Set up the context structure with the first ixl command to process
 *    and the first hci descriptor to execute.
 *
 *    This function assumes the current context is stopped!
 *
 *    If ixlstp IS NOT null AND is not the first compiled ixl command and
 *    is not an ixl label command, returns an error.
 *    If ixlstp IS null, uses the first compiled ixl command (ixl_firstp)
 *    in place of ixlstp.
 *
 *    If no executeable xfer found along exec path from ixlstp, returns error.
 */
int
hci1394_ixl_set_start(hci1394_iso_ctxt_t *ctxtp, ixl1394_command_t *ixlstp)
{

	ixl1394_command_t  *ixl_exec_startp;

	/* if ixl start command is null, use first compiled ixl command */
	if (ixlstp == NULL) {
		ixlstp = ctxtp->ixl_firstp;
	}

	/*
	 * if ixl start command is not first ixl compiled and is not a label,
	 * error
	 */
	if ((ixlstp != ctxtp->ixl_firstp) && (ixlstp->ixl_opcode !=
	    IXL1394_OP_LABEL)) {
		return (-1);
	}

	/* follow exec path to find first ixl command that's an xfer command */
	(void) hci1394_ixl_find_next_exec_xfer(ixlstp, NULL, &ixl_exec_startp);

	/*
	 * if there was one, then in it's compiler private, its
	 * hci1394_xfer_ctl structure has the appropriate bound address
	 */
	if (ixl_exec_startp != NULL) {

		/* set up for start of context and return done */
		ctxtp->dma_mem_execp = (uint32_t)((hci1394_xfer_ctl_t *)
			ixl_exec_startp->compiler_privatep)->dma[0].dma_bound;

		ctxtp->dma_last_time = 0;
		ctxtp->ixl_exec_depth = 0;
		ctxtp->ixl_execp = ixlstp;
		ctxtp->rem_noadv_intrs = ctxtp->max_noadv_intrs;

		return (0);
	}

	/* else no executeable xfer command found, return error */
	return (1);
}
#ifdef _KERNEL
/*
 * hci1394_ixl_reset_status()
 * Reset all statuses in all hci descriptor blocks associated with the
 * current linked list of compiled ixl commands.
 *
 * This function assumes the current context is stopped!
 */
void
hci1394_ixl_reset_status(hci1394_iso_ctxt_t *ctxtp)
{
	ixl1394_command_t	*ixlcur;
	ixl1394_command_t	*ixlnext;
	hci1394_xfer_ctl_t	*xferctlp;
	uint_t			ixldepth;
	uint16_t		timestamp;

	ixlnext = ctxtp->ixl_firstp;

	/*
	 * Scan for next ixl xfer start command along ixl link path.
	 * Once xfer command found, clear its hci descriptor block's
	 * status. If is composite ixl xfer command, clear statuses
	 * in each of its hci descriptor blocks.
	 */
	while (ixlnext != NULL) {

		/* set current and next ixl command */
		ixlcur = ixlnext;
		ixlnext = ixlcur->next_ixlp;

		/* skip to examine next if this is not xfer start ixl command */
		if (((ixlcur->ixl_opcode & IXL1394_OPF_ISXFER) == 0) ||
		    ((ixlcur->ixl_opcode & IXL1394_OPTY_MASK) == 0)) {
			continue;
		}

		/* get control struct for this xfer start ixl command */
		xferctlp = (hci1394_xfer_ctl_t *)ixlcur->compiler_privatep;

		/* clear status in each hci descriptor block for this ixl cmd */
		ixldepth = 0;
		while (ixldepth < xferctlp->cnt) {
			(void) hci1394_ixl_check_status(
			    &xferctlp->dma[ixldepth], ixlcur->ixl_opcode,
			    &timestamp, B_TRUE);
			ixldepth++;
		}
	}
}
#endif
/*
 * hci1394_ixl_find_next_exec_xfer()
 *    Follows execution path of ixl linked list until finds next xfer start IXL
 *    command, including the current IXL command or finds end of IXL linked
 *    list. Counts callback commands found along the way. (Previously, counted
 *    store timestamp commands, as well.)
 *
 *    To detect an infinite loop of label<->jump without an intervening xfer,
 *    a tolerance level of HCI1394_IXL_MAX_SEQ_JUMPS is used.  Once this
 *    number of jumps is traversed, the IXL prog is assumed to have a loop.
 *
 *    Returns DDI_SUCCESS or DDI_FAILURE.  DDI_FAILURE, indicates an infinite
 *    loop of labels & jumps was detected without any intervening xfers.
 *    DDI_SUCCESS indicates the next_exec_ixlpp contains the next xfer ixlp
 *    address, or NULL indicating the end of the list was reached.  Note that
 *    DDI_FAILURE can only be returned during the IXL compilation phase, and
 *    not during ixl_update processing.
 */
int
hci1394_ixl_find_next_exec_xfer(ixl1394_command_t *ixl_start,
    uint_t *callback_cnt, ixl1394_command_t **next_exec_ixlpp)
{
	uint16_t ixlopcode;
	boolean_t xferfound;
	ixl1394_command_t *ixlp;
	int ii;

	ixlp = ixl_start;
	xferfound = B_FALSE;
	ii = HCI1394_IXL_MAX_SEQ_JUMPS;
	if (callback_cnt != NULL) {
		*callback_cnt = 0;
	}

	/* continue until xfer start ixl cmd or end of ixl list found */
	while ((xferfound == B_FALSE) && (ixlp != NULL) && (ii > 0)) {

		/* get current ixl cmd opcode without update flag */
		ixlopcode = ixlp->ixl_opcode & ~IXL1394_OPF_UPDATE;

		/* if found an xfer start ixl command, are done */
		if (((ixlopcode & IXL1394_OPF_ISXFER) != 0) &&
		    ((ixlopcode & IXL1394_OPTY_MASK) != 0)) {
			xferfound = B_TRUE;
			continue;
		}

		/* if found jump command, adjust to follow its path */
		if (ixlopcode == IXL1394_OP_JUMP) {
			ixlp = (ixl1394_command_t *)
			    ((ixl1394_jump_t *)ixlp)->label;
			ii--;

			/* if exceeded tolerance, give up */
			if (ii == 0) {
				return (DDI_FAILURE);
			}
			continue;
		}

		/* if current ixl command is a callback, count it */
		if ((ixlopcode == IXL1394_OP_CALLBACK) &&
		    (callback_cnt != NULL)) {
			(*callback_cnt)++;
		}

		/* advance to next linked ixl command */
		ixlp = ixlp->next_ixlp;
	}

	/* return ixl xfer start command found, if any */
	*next_exec_ixlpp = ixlp;

	return (DDI_SUCCESS);
}
#ifdef _KERNEL
/*
 * hci1394_ixl_check_status()
 *    Read the descriptor status and hdrs, clear as appropriate.
 */
int32_t
hci1394_ixl_check_status(hci1394_xfer_ctl_dma_t *dma, uint16_t ixlopcode,
    uint16_t *timestamp, boolean_t do_status_reset)
{
	uint16_t	bufsiz;
	uint16_t	hcicnt;
	uint16_t	hcirecvcnt;
	hci1394_desc_t	*hcidescp;
	off_t		hcidesc_off;
	ddi_acc_handle_t	acc_hdl;
	ddi_dma_handle_t	dma_hdl;
	uint32_t		desc_status;
	uint32_t		desc_hdr;

	/* last dma descriptor in descriptor block from dma structure */
	hcidescp = (hci1394_desc_t *)(dma->dma_descp);
	hcidesc_off = (off_t)hcidescp - (off_t)dma->dma_buf->bi_kaddr;
	acc_hdl  = dma->dma_buf->bi_handle;
	dma_hdl  = dma->dma_buf->bi_dma_handle;

	/* if current ixl command opcode is xmit */
	if ((ixlopcode & IXL1394_OPF_ONXMIT) != 0) {

		/* Sync the descriptor before we get the status */
		(void) ddi_dma_sync(dma_hdl, hcidesc_off,
		    sizeof (hci1394_desc_t), DDI_DMA_SYNC_FORCPU);
		desc_status = ddi_get32(acc_hdl, &hcidescp->status);

		/* check if status is set in last dma descriptor in block */
		if ((desc_status & DESC_XFER_ACTIVE_MASK) != 0) {
			/*
			 * dma descriptor status set - I/O done.
			 * if not to reset status, just return; else extract
			 * timestamp, reset desc status and return dma
			 * descriptor block status set
			 */
			if (do_status_reset == B_FALSE) {
				return (1);
			}
			*timestamp = (uint16_t)
			    ((desc_status & DESC_ST_TIMESTAMP_MASK) >>
			    DESC_ST_TIMESTAMP_SHIFT);
			ddi_put32(acc_hdl, &hcidescp->status, 0);

			/* Sync descriptor for device (status was cleared) */
			(void) ddi_dma_sync(dma_hdl, hcidesc_off,
			    sizeof (hci1394_desc_t), DDI_DMA_SYNC_FORDEV);

			return (1);
		}
		/* else, return dma descriptor block status not set */
		return (0);
	}

	/* else current ixl opcode is recv */
	hcirecvcnt = 0;

	/* get count of descriptors in current dma descriptor block */
	hcicnt = dma->dma_bound & DESC_Z_MASK;
	hcidescp -= (hcicnt - 1);
	hcidesc_off = (off_t)hcidescp - (off_t)dma->dma_buf->bi_kaddr;

	/* iterate fwd through hci descriptors until end or find status set */
	while (hcicnt-- != 0) {

		/* Sync the descriptor before we get the status */
		(void) ddi_dma_sync(dma_hdl, hcidesc_off,
		    hcicnt * sizeof (hci1394_desc_t), DDI_DMA_SYNC_FORCPU);

		desc_hdr = ddi_get32(acc_hdl, &hcidescp->hdr);

		/* get cur buffer size & accumulate potential buffr usage */
		bufsiz = (desc_hdr & DESC_HDR_REQCOUNT_MASK) >>
		    DESC_HDR_REQCOUNT_SHIFT;
		hcirecvcnt += bufsiz;

		desc_status = ddi_get32(acc_hdl, &hcidescp->status);

		/* check if status set on this descriptor block descriptor */
		if ((desc_status & DESC_XFER_ACTIVE_MASK) != 0) {
			/*
			 * dma descriptor status set - I/O done.
			 * if not to reset status, just return; else extract
			 * buffer space used, reset desc status and return dma
			 * descriptor block status set
			 */
			if (do_status_reset == B_FALSE) {
				return (1);
			}

			hcirecvcnt -= (desc_status & DESC_ST_RESCOUNT_MASK) >>
			    DESC_ST_RESCOUNT_SHIFT;
			*timestamp = hcirecvcnt;
			desc_status = (bufsiz << DESC_ST_RESCOUNT_SHIFT) &
			    DESC_ST_RESCOUNT_MASK;
			ddi_put32(acc_hdl, &hcidescp->status, desc_status);

			/* Sync descriptor for device (status was cleared) */
			(void) ddi_dma_sync(dma_hdl, hcidesc_off,
			    sizeof (hci1394_desc_t), DDI_DMA_SYNC_FORDEV);

			return (1);
		} else {
			/* else, set to evaluate next descriptor. */
			hcidescp++;
			hcidesc_off = (off_t)hcidescp -
			    (off_t)dma->dma_buf->bi_kaddr;
		}
	}

	/* return input not complete status */
	return (0);
}
#endif
/*
 * hci1394_ixl_cleanup()
 *    Delete all memory that has earlier been allocated for a context's IXL prog
 */
void
hci1394_ixl_cleanup(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp)
{
	hci1394_delete_xfer_ctl((hci1394_xfer_ctl_t *)ctxtp->xcs_firstp);
	hci1394_delete_dma_desc_mem(soft_statep, ctxtp->dma_firstp);
}

/*
 * hci1394_delete_dma_desc_mem()
 *    Iterate through linked list of dma memory descriptors, deleting
 *    allocated dma memory blocks, then deleting the dma memory
 *    descriptor after advancing to next one
 */
static void
/* ARGSUSED */
hci1394_delete_dma_desc_mem(hci1394_state_t *soft_statep,
    hci1394_idma_desc_mem_t *dma_firstp)
{
	hci1394_idma_desc_mem_t *dma_next;

	while (dma_firstp != NULL) {
		dma_next = dma_firstp->dma_nextp;
#ifdef _KERNEL
		/*
		 * if this dma descriptor memory block has the handles, then
		 * free the memory.  (Note that valid handles are kept only with
		 * the most recently acquired cookie, and that each cookie is in
		 * it's own idma_desc_mem_t struct.)
		 */
		if (dma_firstp->mem_handle != NULL) {
			hci1394_buf_free(&dma_firstp->mem_handle);
		}

		/* free current dma memory descriptor */
		kmem_free(dma_firstp, sizeof (hci1394_idma_desc_mem_t));
#else
		/* user mode free */
		/* free dma memory block and current dma mem descriptor */
		free(dma_firstp->mem.bi_kaddr);
		free(dma_firstp);
#endif
		/* advance to next dma memory descriptor */
		dma_firstp = dma_next;
	}
}

/*
 * hci1394_delete_xfer_ctl()
 *    Iterate thru linked list of xfer_ctl structs, deleting allocated memory.
 */
void
hci1394_delete_xfer_ctl(hci1394_xfer_ctl_t *xcsp)
{
	hci1394_xfer_ctl_t *delp;

	while ((delp = xcsp) != NULL) {
		/* advance ptr to next xfer_ctl struct */
		xcsp = xcsp->ctl_nextp;

		/*
		 * delete current xfer_ctl struct and included
		 * xfer_ctl_dma structs
		 */
#ifdef _KERNEL
		kmem_free(delp,
		    sizeof (hci1394_xfer_ctl_t) +
		    sizeof (hci1394_xfer_ctl_dma_t) * (delp->cnt - 1));
#else
		free(delp);
#endif
	}
}
