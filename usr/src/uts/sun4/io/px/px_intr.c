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
 * PX nexus interrupt handling:
 *	PX device interrupt handler wrapper
 *	PIL lookup routine
 *	PX device interrupt related initchild code
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/machsystm.h>	/* e_ddi_nodeid_to_dip() */
#include <sys/ddi_impldefs.h>
#include <sys/sdt.h>
#include <sys/atomic.h>
#include "px_obj.h"
#include <sys/ontrap.h>
#include <sys/membar.h>
#include <sys/clock.h>

/*
 * interrupt jabber:
 *
 * When an interrupt line is jabbering, every time the state machine for the
 * associated ino is idled, a new mondo will be sent and the ino will go into
 * the pending state again. The mondo will cause a new call to
 * px_intr_wrapper() which normally idles the ino's state machine which would
 * precipitate another trip round the loop.
 *
 * The loop can be broken by preventing the ino's state machine from being
 * idled when an interrupt line is jabbering. See the comment at the
 * beginning of px_intr_wrapper() explaining how the 'interrupt jabber
 * protection' code does this.
 */

/*LINTLIBRARY*/

/*
 * If the unclaimed interrupt count has reached the limit set by
 * pci_unclaimed_intr_max within the time limit, then all interrupts
 * on this ino is blocked by not idling the interrupt state machine.
 */
static int
px_spurintr(px_ino_pil_t *ipil_p)
{
	px_ino_t	*ino_p = ipil_p->ipil_ino_p;
	px_ih_t		*ih_p = ipil_p->ipil_ih_start;
	px_t		*px_p = ino_p->ino_ib_p->ib_px_p;
	char		*err_fmt_str;
	boolean_t	blocked = B_FALSE;
	int		i;

	if (ino_p->ino_unclaimed_intrs > px_unclaimed_intr_max)
		return (DDI_INTR_CLAIMED);

	if (!ino_p->ino_unclaimed_intrs)
		ino_p->ino_spurintr_begin = ddi_get_lbolt();

	ino_p->ino_unclaimed_intrs++;

	if (ino_p->ino_unclaimed_intrs <= px_unclaimed_intr_max)
		goto clear;

	if (drv_hztousec(ddi_get_lbolt() - ino_p->ino_spurintr_begin)
	    > px_spurintr_duration) {
		ino_p->ino_unclaimed_intrs = 0;
		goto clear;
	}
	err_fmt_str = "%s%d: ino 0x%x blocked";
	blocked = B_TRUE;
	goto warn;
clear:
	err_fmt_str = "!%s%d: spurious interrupt from ino 0x%x";
warn:
	cmn_err(CE_WARN, err_fmt_str, NAMEINST(px_p->px_dip), ino_p->ino_ino);
	for (i = 0; i < ipil_p->ipil_ih_size; i++, ih_p = ih_p->ih_next)
		cmn_err(CE_CONT, "!%s-%d#%x ", NAMEINST(ih_p->ih_dip),
		    ih_p->ih_inum);
	cmn_err(CE_CONT, "!\n");

	/* Clear the pending state */
	if (blocked == B_FALSE) {
		if (px_lib_intr_setstate(px_p->px_dip, ino_p->ino_sysino,
		    INTR_IDLE_STATE) != DDI_SUCCESS)
			return (DDI_INTR_UNCLAIMED);
	}

	return (DDI_INTR_CLAIMED);
}

extern uint64_t intr_get_time(void);

/*
 * px_intx_intr (INTx or legacy interrupt handler)
 *
 * This routine is used as wrapper around interrupt handlers installed by child
 * device drivers.  This routine invokes the driver interrupt handlers and
 * examines the return codes.
 *
 * There is a count of unclaimed interrupts kept on a per-ino basis. If at
 * least one handler claims the interrupt then the counter is halved and the
 * interrupt state machine is idled. If no handler claims the interrupt then
 * the counter is incremented by one and the state machine is idled.
 * If the count ever reaches the limit value set by pci_unclaimed_intr_max
 * then the interrupt state machine is not idled thus preventing any further
 * interrupts on that ino. The state machine will only be idled again if a
 * handler is subsequently added or removed.
 *
 * return value: DDI_INTR_CLAIMED if any handlers claimed the interrupt,
 * DDI_INTR_UNCLAIMED otherwise.
 */
uint_t
px_intx_intr(caddr_t arg)
{
	px_ino_pil_t	*ipil_p = (px_ino_pil_t *)arg;
	px_ino_t	*ino_p = ipil_p->ipil_ino_p;
	px_t		*px_p = ino_p->ino_ib_p->ib_px_p;
	px_ih_t		*ih_p = ipil_p->ipil_ih_start;
	ushort_t	pil = ipil_p->ipil_pil;
	uint_t		result = 0, r = DDI_INTR_UNCLAIMED;
	int		i;

	DBG(DBG_INTX_INTR, px_p->px_dip, "px_intx_intr:"
	    "ino=%x sysino=%llx pil=%x ih_size=%x ih_lst=%x\n",
	    ino_p->ino_ino, ino_p->ino_sysino, ipil_p->ipil_pil,
	    ipil_p->ipil_ih_size, ipil_p->ipil_ih_head);

	for (i = 0; i < ipil_p->ipil_ih_size; i++, ih_p = ih_p->ih_next) {
		dev_info_t *dip = ih_p->ih_dip;
		uint_t (*handler)() = ih_p->ih_handler;
		caddr_t arg1 = ih_p->ih_handler_arg1;
		caddr_t arg2 = ih_p->ih_handler_arg2;

		if (ih_p->ih_intr_state == PX_INTR_STATE_DISABLE) {
			DBG(DBG_INTX_INTR, px_p->px_dip,
			    "px_intx_intr: %s%d interrupt %d is disabled\n",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    ino_p->ino_ino);

			continue;
		}

		DBG(DBG_INTX_INTR, px_p->px_dip, "px_intx_intr:"
		    "ino=%x handler=%p arg1 =%p arg2 = %p\n",
		    ino_p->ino_ino, handler, arg1, arg2);

		DTRACE_PROBE4(interrupt__start, dev_info_t, dip,
		    void *, handler, caddr_t, arg1, caddr_t, arg2);

		r = (*handler)(arg1, arg2);

		/*
		 * Account for time used by this interrupt. Protect against
		 * conflicting writes to ih_ticks from ib_intr_dist_all() by
		 * using atomic ops.
		 */

		if (pil <= LOCK_LEVEL)
			atomic_add_64(&ih_p->ih_ticks, intr_get_time());

		DTRACE_PROBE4(interrupt__complete, dev_info_t, dip,
		    void *, handler, caddr_t, arg1, int, r);

		result += r;

		if (px_check_all_handlers)
			continue;
		if (result)
			break;
	}

	if (result)
		ino_p->ino_claimed |= (1 << pil);

	/* Interrupt can only be cleared after all pil levels are handled */
	if (pil != ino_p->ino_lopil)
		return (DDI_INTR_CLAIMED);

	if (!ino_p->ino_claimed) {
		if (px_unclaimed_intr_block)
			return (px_spurintr(ipil_p));
	}

	ino_p->ino_unclaimed_intrs = 0;
	ino_p->ino_claimed = 0;

	/* Clear the pending state */
	if (px_lib_intr_setstate(px_p->px_dip,
	    ino_p->ino_sysino, INTR_IDLE_STATE) != DDI_SUCCESS)
		return (DDI_INTR_UNCLAIMED);

	return (DDI_INTR_CLAIMED);
}

/*
 * px_msiq_intr (MSI/X or PCIe MSG interrupt handler)
 *
 * This routine is used as wrapper around interrupt handlers installed by child
 * device drivers.  This routine invokes the driver interrupt handlers and
 * examines the return codes.
 *
 * There is a count of unclaimed interrupts kept on a per-ino basis. If at
 * least one handler claims the interrupt then the counter is halved and the
 * interrupt state machine is idled. If no handler claims the interrupt then
 * the counter is incremented by one and the state machine is idled.
 * If the count ever reaches the limit value set by pci_unclaimed_intr_max
 * then the interrupt state machine is not idled thus preventing any further
 * interrupts on that ino. The state machine will only be idled again if a
 * handler is subsequently added or removed.
 *
 * return value: DDI_INTR_CLAIMED if any handlers claimed the interrupt,
 * DDI_INTR_UNCLAIMED otherwise.
 */
uint_t
px_msiq_intr(caddr_t arg)
{
	px_ino_pil_t	*ipil_p = (px_ino_pil_t *)arg;
	px_ino_t	*ino_p = ipil_p->ipil_ino_p;
	px_t		*px_p = ino_p->ino_ib_p->ib_px_p;
	px_msiq_state_t	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	px_msiq_t	*msiq_p = ino_p->ino_msiq_p;
	dev_info_t	*dip = px_p->px_dip;
	ushort_t	pil = ipil_p->ipil_pil;
	msiq_rec_t	msiq_rec, *msiq_rec_p = &msiq_rec;
	msiqhead_t	*curr_head_p;
	msiqtail_t	curr_tail_index;
	msgcode_t	msg_code;
	px_ih_t		*ih_p;
	uint_t		ret = DDI_INTR_UNCLAIMED;
	int		i, j;

	DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: msiq_id =%x ino=%x pil=%x "
	    "ih_size=%x ih_lst=%x\n", msiq_p->msiq_id, ino_p->ino_ino,
	    ipil_p->ipil_pil, ipil_p->ipil_ih_size, ipil_p->ipil_ih_head);

	/*
	 * The px_msiq_intr() handles multiple interrupt priorities and it
	 * will set msiq->msiq_rec2process to the number of MSIQ records to
	 * process while handling the highest priority interrupt. Subsequent
	 * lower priority interrupts will just process any unprocessed MSIQ
	 * records or will just return immediately.
	 */
	if (msiq_p->msiq_recs2process == 0) {
		/* Read current MSIQ tail index */
		px_lib_msiq_gettail(dip, msiq_p->msiq_id, &curr_tail_index);
		msiq_p->msiq_new_head_index = msiq_p->msiq_curr_head_index;

		if (curr_tail_index < msiq_p->msiq_curr_head_index)
			curr_tail_index += msiq_state_p->msiq_rec_cnt;

		msiq_p->msiq_recs2process = curr_tail_index -
		    msiq_p->msiq_curr_head_index;
	}

	DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: curr_head %x new_head %x "
	    "rec2process %x\n", msiq_p->msiq_curr_head_index,
	    msiq_p->msiq_new_head_index, msiq_p->msiq_recs2process);

	/* If all MSIQ records are already processed, just return immediately */
	if ((msiq_p->msiq_new_head_index - msiq_p->msiq_curr_head_index)
	    == msiq_p->msiq_recs2process)
		goto intr_done;

	curr_head_p = (msiqhead_t *)((caddr_t)msiq_p->msiq_base_p +
	    (msiq_p->msiq_curr_head_index * sizeof (msiq_rec_t)));

	/*
	 * Calculate the number of recs to process by taking the difference
	 * between the head and tail pointers. For all records we always
	 * verify that we have a valid record type before we do any processing.
	 * If triggered, we should always have at least one valid record.
	 */
	for (i = 0; i < msiq_p->msiq_recs2process; i++) {
		/* Read next MSIQ record */
		px_lib_get_msiq_rec(dip, curr_head_p, msiq_rec_p);

		DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: MSIQ RECORD, "
		    "msiq_rec_type 0x%llx msiq_rec_rid 0x%llx\n",
		    msiq_rec_p->msiq_rec_type, msiq_rec_p->msiq_rec_rid);

		if (!msiq_rec_p->msiq_rec_type)
			goto next_rec;

		/* Check MSIQ record type */
		switch (msiq_rec_p->msiq_rec_type) {
		case MSG_REC:
			msg_code = msiq_rec_p->msiq_rec_data.msg.msg_code;
			DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: PCIE MSG "
			    "record, msg type 0x%x\n", msg_code);
			break;
		case MSI32_REC:
		case MSI64_REC:
			msg_code = msiq_rec_p->msiq_rec_data.msi.msi_data;
			DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: MSI record, "
			    "msi 0x%x\n", msg_code);

			/* Clear MSI state */
			px_lib_msi_setstate(dip, (msinum_t)msg_code,
			    PCI_MSI_STATE_IDLE);
			break;
		default:
			msg_code = 0;
			cmn_err(CE_WARN, "%s%d: px_msiq_intr: 0x%x MSIQ "
			    "record type is not supported",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    msiq_rec_p->msiq_rec_type);

			goto next_rec;
		}

		/*
		 * Scan through px_ih_t linked list, searching for the
		 * right px_ih_t, matching MSIQ record data.
		 */
		for (j = 0, ih_p = ipil_p->ipil_ih_start;
		    ih_p && (j < ipil_p->ipil_ih_size) &&
		    ((ih_p->ih_msg_code != msg_code) ||
		    (ih_p->ih_rec_type != msiq_rec_p->msiq_rec_type));
		    ih_p = ih_p->ih_next, j++)
			;

		if ((ih_p->ih_msg_code == msg_code) &&
		    (ih_p->ih_rec_type == msiq_rec_p->msiq_rec_type)) {
			dev_info_t *dip = ih_p->ih_dip;
			uint_t (*handler)() = ih_p->ih_handler;
			caddr_t arg1 = ih_p->ih_handler_arg1;
			caddr_t arg2 = ih_p->ih_handler_arg2;

			DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: ino=%x data=%x "
			    "handler=%p arg1 =%p arg2=%p\n", ino_p->ino_ino,
			    msg_code, handler, arg1, arg2);

			DTRACE_PROBE4(interrupt__start, dev_info_t, dip,
			    void *, handler, caddr_t, arg1, caddr_t, arg2);

			/*
			 * Special case for PCIE Error Messages.
			 * The current frame work doesn't fit PCIE Err Msgs
			 * This should be fixed when PCIE MESSAGES as a whole
			 * is architected correctly.
			 */
			if ((msg_code == PCIE_MSG_CODE_ERR_COR) ||
			    (msg_code == PCIE_MSG_CODE_ERR_NONFATAL) ||
			    (msg_code == PCIE_MSG_CODE_ERR_FATAL)) {
				ret = px_err_fabric_intr(px_p, msg_code,
				    msiq_rec_p->msiq_rec_rid);
			} else
				ret = (*handler)(arg1, arg2);

			/*
			 * Account for time used by this interrupt. Protect
			 * against conflicting writes to ih_ticks from
			 * ib_intr_dist_all() by using atomic ops.
			 */

			if (pil <= LOCK_LEVEL)
				atomic_add_64(&ih_p->ih_ticks, intr_get_time());

			DTRACE_PROBE4(interrupt__complete, dev_info_t, dip,
			    void *, handler, caddr_t, arg1, int, ret);

			msiq_p->msiq_new_head_index++;
			px_lib_clr_msiq_rec(dip, curr_head_p);
		} else {
			DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr:"
			    "No matching MSIQ record found\n");
		}
next_rec:
		/* Get the pointer next EQ record */
		curr_head_p = (msiqhead_t *)
		    ((caddr_t)curr_head_p + sizeof (msiq_rec_t));

		/* Check for overflow condition */
		if (curr_head_p >= (msiqhead_t *)((caddr_t)msiq_p->msiq_base_p
		    + (msiq_state_p->msiq_rec_cnt * sizeof (msiq_rec_t))))
			curr_head_p = (msiqhead_t *)msiq_p->msiq_base_p;
	}

	DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: No of MSIQ recs processed %x\n",
	    (msiq_p->msiq_new_head_index - msiq_p->msiq_curr_head_index));

	DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: curr_head %x new_head %x "
	    "rec2process %x\n", msiq_p->msiq_curr_head_index,
	    msiq_p->msiq_new_head_index, msiq_p->msiq_recs2process);

	/* ino_claimed used just for debugging purpose */
	if (ret)
		ino_p->ino_claimed |= (1 << pil);

intr_done:
	/* Interrupt can only be cleared after all pil levels are handled */
	if (pil != ino_p->ino_lopil)
		return (DDI_INTR_CLAIMED);

	if (msiq_p->msiq_new_head_index <= msiq_p->msiq_curr_head_index)  {
		if (px_unclaimed_intr_block)
			return (px_spurintr(ipil_p));
	}

	/*  Update MSIQ head index with no of MSIQ records processed */
	if (msiq_p->msiq_new_head_index >= msiq_state_p->msiq_rec_cnt)
		msiq_p->msiq_new_head_index -= msiq_state_p->msiq_rec_cnt;

	msiq_p->msiq_curr_head_index = msiq_p->msiq_new_head_index;
	px_lib_msiq_sethead(dip, msiq_p->msiq_id, msiq_p->msiq_new_head_index);

	msiq_p->msiq_new_head_index = 0;
	msiq_p->msiq_recs2process = 0;
	ino_p->ino_claimed = 0;

	/* Clear the pending state */
	if (px_lib_intr_setstate(dip, ino_p->ino_sysino,
	    INTR_IDLE_STATE) != DDI_SUCCESS)
		return (DDI_INTR_UNCLAIMED);

	return (DDI_INTR_CLAIMED);
}

dev_info_t *
px_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t	*cdip = rdip;

	for (; ddi_get_parent(cdip) != dip; cdip = ddi_get_parent(cdip))
		;

	return (cdip);
}

/* ARGSUSED */
int
px_intx_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	int	ret = DDI_SUCCESS;

	DBG(DBG_INTROPS, dip, "px_intx_ops: dip=%x rdip=%x intr_op=%x "
	    "handle=%p\n", dip, rdip, intr_op, hdlp);

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		ret = pci_intx_get_cap(rdip, (int *)result);
		break;
	case DDI_INTROP_SETCAP:
		DBG(DBG_INTROPS, dip, "px_intx_ops: SetCap is not supported\n");
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		*(int *)result = hdlp->ih_pri ?
		    hdlp->ih_pri : pci_class_to_pil(rdip);
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		ret = px_add_intx_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		ret = px_rem_intx_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
		ret = px_ib_update_intr_state(px_p, rdip, hdlp->ih_inum,
		    hdlp->ih_vector, hdlp->ih_pri, PX_INTR_STATE_ENABLE, 0, 0);
		break;
	case DDI_INTROP_DISABLE:
		ret = px_ib_update_intr_state(px_p, rdip, hdlp->ih_inum,
		    hdlp->ih_vector, hdlp->ih_pri, PX_INTR_STATE_DISABLE, 0, 0);
		break;
	case DDI_INTROP_SETMASK:
		ret = pci_intx_set_mask(rdip);
		break;
	case DDI_INTROP_CLRMASK:
		ret = pci_intx_clr_mask(rdip);
		break;
	case DDI_INTROP_GETPENDING:
		ret = pci_intx_get_pending(rdip, (int *)result);
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

/* ARGSUSED */
int
px_msix_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	px_t			*px_p = DIP_TO_STATE(dip);
	px_msi_state_t		*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	msiq_rec_type_t		msiq_rec_type;
	msi_type_t		msi_type;
	uint64_t		msi_addr;
	msinum_t		msi_num;
	msiqid_t		msiq_id;
	uint_t			nintrs;
	int			i, ret = DDI_SUCCESS;

	DBG(DBG_INTROPS, dip, "px_msix_ops: dip=%x rdip=%x intr_op=%x "
	    "handle=%p\n", dip, rdip, intr_op, hdlp);

	/* Check for MSI64 support */
	if ((hdlp->ih_cap & DDI_INTR_FLAG_MSI64) && msi_state_p->msi_addr64) {
		msiq_rec_type = MSI64_REC;
		msi_type = MSI64_TYPE;
		msi_addr = msi_state_p->msi_addr64;
	} else {
		msiq_rec_type = MSI32_REC;
		msi_type = MSI32_TYPE;
		msi_addr = msi_state_p->msi_addr32;
	}

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		ret = pci_msi_get_cap(rdip, hdlp->ih_type, (int *)result);
		break;
	case DDI_INTROP_SETCAP:
		DBG(DBG_INTROPS, dip, "px_msix_ops: SetCap is not supported\n");
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_ALLOC:
		/*
		 * We need to restrict this allocation in future
		 * based on Resource Management policies.
		 */
		if ((ret = px_msi_alloc(px_p, rdip, hdlp->ih_type,
		    hdlp->ih_inum, hdlp->ih_scratch1,
		    (uintptr_t)hdlp->ih_scratch2,
		    (int *)result)) != DDI_SUCCESS) {
			DBG(DBG_INTROPS, dip, "px_msix_ops: allocation "
			    "failed, rdip 0x%p type 0x%d inum 0x%x "
			    "count 0x%x\n", rdip, hdlp->ih_type, hdlp->ih_inum,
			    hdlp->ih_scratch1);

			return (ret);
		}

		if ((hdlp->ih_type == DDI_INTR_TYPE_MSIX) &&
		    (i_ddi_get_msix(rdip) == NULL)) {
			ddi_intr_msix_t		*msix_p;

			if (msix_p = pci_msix_init(rdip)) {
				i_ddi_set_msix(rdip, msix_p);
				break;
			}

			DBG(DBG_INTROPS, dip, "px_msix_ops: MSI-X allocation "
			    "failed, rdip 0x%p inum 0x%x\n", rdip,
			    hdlp->ih_inum);

			(void) px_msi_free(px_p, rdip, hdlp->ih_inum,
			    hdlp->ih_scratch1);

			return (DDI_FAILURE);
		}

		break;
	case DDI_INTROP_FREE:
		(void) pci_msi_disable_mode(rdip, hdlp->ih_type, NULL);
		(void) pci_msi_unconfigure(rdip, hdlp->ih_type, hdlp->ih_inum);

		if (hdlp->ih_type == DDI_INTR_TYPE_MSI)
			goto msi_free;

		if (hdlp->ih_flags & DDI_INTR_MSIX_DUP)
			break;

		if (((i_ddi_intr_get_current_nintrs(hdlp->ih_dip) - 1) == 0) &&
		    (i_ddi_get_msix(rdip))) {
			pci_msix_fini(i_ddi_get_msix(rdip));
			i_ddi_set_msix(rdip, NULL);
		}
msi_free:
		(void) px_msi_free(px_p, rdip, hdlp->ih_inum,
		    hdlp->ih_scratch1);
		break;
	case DDI_INTROP_GETPRI:
		*(int *)result = hdlp->ih_pri ?
		    hdlp->ih_pri : pci_class_to_pil(rdip);
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		if ((ret = px_msi_get_msinum(px_p, hdlp->ih_dip,
		    hdlp->ih_inum, &msi_num)) != DDI_SUCCESS)
			return (ret);

		if ((ret = px_add_msiq_intr(dip, rdip, hdlp,
		    msiq_rec_type, msi_num, &msiq_id)) != DDI_SUCCESS) {
			DBG(DBG_INTROPS, dip, "px_msix_ops: Add MSI handler "
			    "failed, rdip 0x%p msi 0x%x\n", rdip, msi_num);
			return (ret);
		}

		DBG(DBG_INTROPS, dip, "px_msix_ops: msiq used 0x%x\n", msiq_id);

		if ((ret = px_lib_msi_setmsiq(dip, msi_num,
		    msiq_id, msi_type)) != DDI_SUCCESS) {
			(void) px_rem_msiq_intr(dip, rdip,
			    hdlp, msiq_rec_type, msi_num, msiq_id);
			return (ret);
		}

		if ((ret = px_lib_msi_setstate(dip, msi_num,
		    PCI_MSI_STATE_IDLE)) != DDI_SUCCESS) {
			(void) px_rem_msiq_intr(dip, rdip,
			    hdlp, msiq_rec_type, msi_num, msiq_id);
			return (ret);
		}

		hdlp->ih_vector = msi_num;
		break;
	case DDI_INTROP_DUPVEC:
		DBG(DBG_INTROPS, dip, "px_msix_ops: dupisr - inum: %x, "
		    "new_vector: %x\n", hdlp->ih_inum, hdlp->ih_scratch1);

		ret = pci_msix_dup(hdlp->ih_dip, hdlp->ih_inum,
		    hdlp->ih_scratch1);
		break;
	case DDI_INTROP_REMISR:
		msi_num = hdlp->ih_vector;

		if ((ret = px_lib_msi_getmsiq(dip, msi_num,
		    &msiq_id)) != DDI_SUCCESS)
			return (ret);

		if ((ret = px_lib_msi_setstate(dip, msi_num,
		    PCI_MSI_STATE_IDLE)) != DDI_SUCCESS)
			return (ret);

		ret = px_rem_msiq_intr(dip, rdip,
		    hdlp, msiq_rec_type, msi_num, msiq_id);

		hdlp->ih_vector = 0;
		break;
	case DDI_INTROP_ENABLE:
		msi_num = hdlp->ih_vector;

		if ((ret = px_lib_msi_setvalid(dip, msi_num,
		    PCI_MSI_VALID)) != DDI_SUCCESS)
			return (ret);

		if ((pci_is_msi_enabled(rdip, hdlp->ih_type) != DDI_SUCCESS) ||
		    (hdlp->ih_type == DDI_INTR_TYPE_MSIX)) {
			nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);

			if ((ret = pci_msi_configure(rdip, hdlp->ih_type,
			    nintrs, hdlp->ih_inum, msi_addr,
			    hdlp->ih_type == DDI_INTR_TYPE_MSIX ?
			    msi_num : msi_num & ~(nintrs - 1))) != DDI_SUCCESS)
				return (ret);

			if ((ret = pci_msi_enable_mode(rdip, hdlp->ih_type))
			    != DDI_SUCCESS)
				return (ret);
		}

		if ((ret = pci_msi_clr_mask(rdip, hdlp->ih_type,
		    hdlp->ih_inum)) != DDI_SUCCESS)
			return (ret);

		if (hdlp->ih_flags & DDI_INTR_MSIX_DUP)
			break;

		if ((ret = px_lib_msi_getmsiq(dip, msi_num,
		    &msiq_id)) != DDI_SUCCESS)
			return (ret);

		ret = px_ib_update_intr_state(px_p, rdip, hdlp->ih_inum,
		    px_msiqid_to_devino(px_p, msiq_id), hdlp->ih_pri,
		    PX_INTR_STATE_ENABLE, msiq_rec_type, msi_num);

		break;
	case DDI_INTROP_DISABLE:
		msi_num = hdlp->ih_vector;

		if ((ret = pci_msi_set_mask(rdip, hdlp->ih_type,
		    hdlp->ih_inum)) != DDI_SUCCESS)
			return (ret);

		if ((ret = px_lib_msi_setvalid(dip, msi_num,
		    PCI_MSI_INVALID)) != DDI_SUCCESS)
			return (ret);

		if (hdlp->ih_flags & DDI_INTR_MSIX_DUP)
			break;

		if ((ret = px_lib_msi_getmsiq(dip, msi_num,
		    &msiq_id)) != DDI_SUCCESS)
			return (ret);

		ret = px_ib_update_intr_state(px_p, rdip,
		    hdlp->ih_inum, px_msiqid_to_devino(px_p, msiq_id),
		    hdlp->ih_pri, PX_INTR_STATE_DISABLE, msiq_rec_type,
		    msi_num);

		break;
	case DDI_INTROP_BLOCKENABLE:
		nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);
		msi_num = hdlp->ih_vector;

		if ((ret = pci_msi_configure(rdip, hdlp->ih_type,
		    nintrs, hdlp->ih_inum, msi_addr,
		    msi_num & ~(nintrs - 1))) != DDI_SUCCESS)
			return (ret);

		for (i = 0; i < nintrs; i++, msi_num++) {
			if ((ret = px_lib_msi_setvalid(dip, msi_num,
			    PCI_MSI_VALID)) != DDI_SUCCESS)
				return (ret);

			if ((ret = px_lib_msi_getmsiq(dip, msi_num,
			    &msiq_id)) != DDI_SUCCESS)
				return (ret);

			if ((ret = px_ib_update_intr_state(px_p, rdip,
			    hdlp->ih_inum + i, px_msiqid_to_devino(px_p,
			    msiq_id), hdlp->ih_pri, PX_INTR_STATE_ENABLE,
			    msiq_rec_type, msi_num)) != DDI_SUCCESS)
				return (ret);
		}

		ret = pci_msi_enable_mode(rdip, hdlp->ih_type);
		break;
	case DDI_INTROP_BLOCKDISABLE:
		nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);
		msi_num = hdlp->ih_vector;

		if ((ret = pci_msi_disable_mode(rdip, hdlp->ih_type,
		    hdlp->ih_cap & DDI_INTR_FLAG_BLOCK)) != DDI_SUCCESS)
			return (ret);

		for (i = 0; i < nintrs; i++, msi_num++) {
			if ((ret = px_lib_msi_setvalid(dip, msi_num,
			    PCI_MSI_INVALID)) != DDI_SUCCESS)
				return (ret);

			if ((ret = px_lib_msi_getmsiq(dip, msi_num,
			    &msiq_id)) != DDI_SUCCESS)
				return (ret);

			if ((ret = px_ib_update_intr_state(px_p, rdip,
			    hdlp->ih_inum + i, px_msiqid_to_devino(px_p,
			    msiq_id), hdlp->ih_pri, PX_INTR_STATE_DISABLE,
			    msiq_rec_type, msi_num)) != DDI_SUCCESS)
				return (ret);
		}

		break;
	case DDI_INTROP_SETMASK:
		ret = pci_msi_set_mask(rdip, hdlp->ih_type, hdlp->ih_inum);
		break;
	case DDI_INTROP_CLRMASK:
		ret = pci_msi_clr_mask(rdip, hdlp->ih_type, hdlp->ih_inum);
		break;
	case DDI_INTROP_GETPENDING:
		ret = pci_msi_get_pending(rdip, hdlp->ih_type,
		    hdlp->ih_inum, (int *)result);
		break;
	case DDI_INTROP_NINTRS:
		ret = pci_msi_get_nintrs(rdip, hdlp->ih_type, (int *)result);
		break;
	case DDI_INTROP_NAVAIL:
		/* XXX - a new interface may be needed */
		ret = pci_msi_get_nintrs(rdip, hdlp->ih_type, (int *)result);
		break;
	case DDI_INTROP_GETPOOL:
		if (msi_state_p->msi_pool_p == NULL) {
			*(ddi_irm_pool_t **)result = NULL;
			return (DDI_ENOTSUP);
		}
		*(ddi_irm_pool_t **)result = msi_state_p->msi_pool_p;
		ret = DDI_SUCCESS;
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

static struct {
	kstat_named_t pxintr_ks_name;
	kstat_named_t pxintr_ks_type;
	kstat_named_t pxintr_ks_cpu;
	kstat_named_t pxintr_ks_pil;
	kstat_named_t pxintr_ks_time;
	kstat_named_t pxintr_ks_ino;
	kstat_named_t pxintr_ks_cookie;
	kstat_named_t pxintr_ks_devpath;
	kstat_named_t pxintr_ks_buspath;
} pxintr_ks_template = {
	{ "name",	KSTAT_DATA_CHAR },
	{ "type",	KSTAT_DATA_CHAR },
	{ "cpu",	KSTAT_DATA_UINT64 },
	{ "pil",	KSTAT_DATA_UINT64 },
	{ "time",	KSTAT_DATA_UINT64 },
	{ "ino",	KSTAT_DATA_UINT64 },
	{ "cookie",	KSTAT_DATA_UINT64 },
	{ "devpath",	KSTAT_DATA_STRING },
	{ "buspath",	KSTAT_DATA_STRING },
};

static uint32_t pxintr_ks_instance;
static char ih_devpath[MAXPATHLEN];
static char ih_buspath[MAXPATHLEN];
kmutex_t pxintr_ks_template_lock;

int
px_ks_update(kstat_t *ksp, int rw)
{
	px_ih_t *ih_p = ksp->ks_private;
	int maxlen = sizeof (pxintr_ks_template.pxintr_ks_name.value.c);
	px_ino_pil_t *ipil_p = ih_p->ih_ipil_p;
	px_ino_t *ino_p = ipil_p->ipil_ino_p;
	px_t *px_p = ino_p->ino_ib_p->ib_px_p;
	devino_t ino;
	sysino_t sysino;

	ino = ino_p->ino_ino;
	if (px_lib_intr_devino_to_sysino(px_p->px_dip, ino, &sysino) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "px_ks_update: px_lib_intr_devino_to_sysino "
		    "failed");
	}

	(void) snprintf(pxintr_ks_template.pxintr_ks_name.value.c, maxlen,
	    "%s%d", ddi_driver_name(ih_p->ih_dip),
	    ddi_get_instance(ih_p->ih_dip));

	(void) ddi_pathname(ih_p->ih_dip, ih_devpath);
	(void) ddi_pathname(px_p->px_dip, ih_buspath);
	kstat_named_setstr(&pxintr_ks_template.pxintr_ks_devpath, ih_devpath);
	kstat_named_setstr(&pxintr_ks_template.pxintr_ks_buspath, ih_buspath);

	if (ih_p->ih_intr_state == PX_INTR_STATE_ENABLE) {

		switch (i_ddi_intr_get_current_type(ih_p->ih_dip)) {
		case DDI_INTR_TYPE_MSI:
			(void) strcpy(pxintr_ks_template.pxintr_ks_type.value.c,
			    "msi");
			break;
		case DDI_INTR_TYPE_MSIX:
			(void) strcpy(pxintr_ks_template.pxintr_ks_type.value.c,
			    "msix");
			break;
		default:
			(void) strcpy(pxintr_ks_template.pxintr_ks_type.value.c,
			    "fixed");
			break;
		}

		pxintr_ks_template.pxintr_ks_cpu.value.ui64 = ino_p->ino_cpuid;
		pxintr_ks_template.pxintr_ks_pil.value.ui64 = ipil_p->ipil_pil;
		pxintr_ks_template.pxintr_ks_time.value.ui64 = ih_p->ih_nsec +
		    (uint64_t)tick2ns((hrtime_t)ih_p->ih_ticks,
		    ino_p->ino_cpuid);
		pxintr_ks_template.pxintr_ks_ino.value.ui64 = ino;
		pxintr_ks_template.pxintr_ks_cookie.value.ui64 = sysino;
	} else {
		(void) strcpy(pxintr_ks_template.pxintr_ks_type.value.c,
		    "disabled");
		pxintr_ks_template.pxintr_ks_cpu.value.ui64 = 0;
		pxintr_ks_template.pxintr_ks_pil.value.ui64 = 0;
		pxintr_ks_template.pxintr_ks_time.value.ui64 = 0;
		pxintr_ks_template.pxintr_ks_ino.value.ui64 = 0;
		pxintr_ks_template.pxintr_ks_cookie.value.ui64 = 0;
	}
	return (0);
}

void
px_create_intr_kstats(px_ih_t *ih_p)
{
	msiq_rec_type_t rec_type = ih_p->ih_rec_type;

	ASSERT(ih_p->ih_ksp == NULL);

	/*
	 * Create pci_intrs::: kstats for all ih types except messages,
	 * which represent unusual conditions and don't need to be tracked.
	 */
	if (rec_type == 0 || rec_type == MSI32_REC || rec_type == MSI64_REC) {
		ih_p->ih_ksp = kstat_create("pci_intrs",
		    atomic_inc_32_nv(&pxintr_ks_instance), "config",
		    "interrupts", KSTAT_TYPE_NAMED,
		    sizeof (pxintr_ks_template) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL);
	}
	if (ih_p->ih_ksp != NULL) {
		ih_p->ih_ksp->ks_data_size += MAXPATHLEN * 2;
		ih_p->ih_ksp->ks_lock = &pxintr_ks_template_lock;
		ih_p->ih_ksp->ks_data = &pxintr_ks_template;
		ih_p->ih_ksp->ks_private = ih_p;
		ih_p->ih_ksp->ks_update = px_ks_update;
	}
}

/*
 * px_add_intx_intr:
 *
 * This function is called to register INTx and legacy hardware
 * interrupt pins interrupts.
 */
int
px_add_intx_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	px_t		*px_p = INST_TO_STATE(ddi_get_instance(dip));
	px_ib_t		*ib_p = px_p->px_ib_p;
	devino_t	ino;
	px_ih_t		*ih_p;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p, *ipil_list;
	int32_t		weight;
	int		ret = DDI_SUCCESS;

	ino = hdlp->ih_vector;

	DBG(DBG_A_INTX, dip, "px_add_intx_intr: rdip=%s%d ino=%x "
	    "handler=%x arg1=%x arg2=%x\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), ino, hdlp->ih_cb_func,
	    hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);

	ih_p = px_ib_alloc_ih(rdip, hdlp->ih_inum,
	    hdlp->ih_cb_func, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2, 0, 0);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, ino);
	ipil_list = ino_p ? ino_p->ino_ipil_p : NULL;

	/* Sharing ino */
	if (ino_p && (ipil_p = px_ib_ino_locate_ipil(ino_p, hdlp->ih_pri))) {
		if (px_ib_intr_locate_ih(ipil_p, rdip, hdlp->ih_inum, 0, 0)) {
			DBG(DBG_A_INTX, dip, "px_add_intx_intr: "
			    "dup intr #%d\n", hdlp->ih_inum);

			ret = DDI_FAILURE;
			goto fail1;
		}

		/* Save mondo value in hdlp */
		hdlp->ih_vector = ino_p->ino_sysino;

		if ((ret = px_ib_ino_add_intr(px_p, ipil_p,
		    ih_p)) != DDI_SUCCESS)
			goto fail1;

		goto ino_done;
	}

	if (hdlp->ih_pri == 0)
		hdlp->ih_pri = pci_class_to_pil(rdip);

	ipil_p = px_ib_new_ino_pil(ib_p, ino, hdlp->ih_pri, ih_p);
	ino_p = ipil_p->ipil_ino_p;

	/* Save mondo value in hdlp */
	hdlp->ih_vector = ino_p->ino_sysino;

	DBG(DBG_A_INTX, dip, "px_add_intx_intr: pil=0x%x mondo=0x%x\n",
	    hdlp->ih_pri, hdlp->ih_vector);

	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
	    (ddi_intr_handler_t *)px_intx_intr, (caddr_t)ipil_p, NULL);

	ret = i_ddi_add_ivintr(hdlp);

	/*
	 * Restore original interrupt handler
	 * and arguments in interrupt handle.
	 */
	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp, ih_p->ih_handler,
	    ih_p->ih_handler_arg1, ih_p->ih_handler_arg2);

	if (ret != DDI_SUCCESS)
		goto fail2;

	/* Save the pil for this ino */
	ipil_p->ipil_pil = hdlp->ih_pri;

	/* Select cpu, saving it for sharing and removal */
	if (ipil_list == NULL) {
		ino_p->ino_cpuid = intr_dist_cpuid();

		/* Enable interrupt */
		px_ib_intr_enable(px_p, ino_p->ino_cpuid, ino);
	}

ino_done:
	/* Add weight to the cpu that we are already targeting */
	weight = pci_class_to_intr_weight(rdip);
	intr_dist_cpuid_add_device_weight(ino_p->ino_cpuid, rdip, weight);

	ih_p->ih_ipil_p = ipil_p;
	px_create_intr_kstats(ih_p);
	if (ih_p->ih_ksp)
		kstat_install(ih_p->ih_ksp);
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	DBG(DBG_A_INTX, dip, "px_add_intx_intr: done! Interrupt 0x%x pil=%x\n",
	    ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
fail2:
	px_ib_delete_ino_pil(ib_p, ipil_p);
fail1:
	if (ih_p->ih_config_handle)
		pci_config_teardown(&ih_p->ih_config_handle);

	mutex_exit(&ib_p->ib_ino_lst_mutex);
	kmem_free(ih_p, sizeof (px_ih_t));

	DBG(DBG_A_INTX, dip, "px_add_intx_intr: Failed! Interrupt 0x%x "
	    "pil=%x\n", ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
}

/*
 * px_rem_intx_intr:
 *
 * This function is called to unregister INTx and legacy hardware
 * interrupt pins interrupts.
 */
int
px_rem_intx_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	px_t		*px_p = INST_TO_STATE(ddi_get_instance(dip));
	px_ib_t		*ib_p = px_p->px_ib_p;
	devino_t	ino;
	cpuid_t		curr_cpu;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p;
	px_ih_t		*ih_p;
	int		ret = DDI_SUCCESS;

	ino = hdlp->ih_vector;

	DBG(DBG_R_INTX, dip, "px_rem_intx_intr: rdip=%s%d ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), ino);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, ino);
	ipil_p = px_ib_ino_locate_ipil(ino_p, hdlp->ih_pri);
	ih_p = px_ib_intr_locate_ih(ipil_p, rdip, hdlp->ih_inum, 0, 0);

	/* Get the current cpu */
	if ((ret = px_lib_intr_gettarget(px_p->px_dip, ino_p->ino_sysino,
	    &curr_cpu)) != DDI_SUCCESS)
		goto fail;

	if ((ret = px_ib_ino_rem_intr(px_p, ipil_p, ih_p)) != DDI_SUCCESS)
		goto fail;

	intr_dist_cpuid_rem_device_weight(ino_p->ino_cpuid, rdip);

	if (ipil_p->ipil_ih_size == 0) {
		hdlp->ih_vector = ino_p->ino_sysino;
		i_ddi_rem_ivintr(hdlp);

		px_ib_delete_ino_pil(ib_p, ipil_p);
	}

	if (ino_p->ino_ipil_size == 0) {
		kmem_free(ino_p, sizeof (px_ino_t));
	} else {
		/* Re-enable interrupt only if mapping register still shared */
		PX_INTR_ENABLE(px_p->px_dip, ino_p->ino_sysino, curr_cpu);
	}

fail:
	mutex_exit(&ib_p->ib_ino_lst_mutex);
	return (ret);
}

/*
 * px_add_msiq_intr:
 *
 * This function is called to register MSI/Xs and PCIe message interrupts.
 */
int
px_add_msiq_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, msiq_rec_type_t rec_type,
    msgcode_t msg_code, msiqid_t *msiq_id_p)
{
	px_t		*px_p = INST_TO_STATE(ddi_get_instance(dip));
	px_ib_t		*ib_p = px_p->px_ib_p;
	px_msiq_state_t	*msiq_state_p = &ib_p->ib_msiq_state;
	devino_t	ino;
	px_ih_t		*ih_p;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p, *ipil_list;
	int32_t		weight;
	int		ret = DDI_SUCCESS;

	DBG(DBG_MSIQ, dip, "px_add_msiq_intr: rdip=%s%d handler=%x "
	    "arg1=%x arg2=%x\n", ddi_driver_name(rdip), ddi_get_instance(rdip),
	    hdlp->ih_cb_func, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);

	if ((ret = px_msiq_alloc(px_p, rec_type, msiq_id_p)) != DDI_SUCCESS) {
		DBG(DBG_MSIQ, dip, "px_add_msiq_intr: "
		    "msiq allocation failed\n");
		return (ret);
	}

	ino = px_msiqid_to_devino(px_p, *msiq_id_p);

	ih_p = px_ib_alloc_ih(rdip, hdlp->ih_inum, hdlp->ih_cb_func,
	    hdlp->ih_cb_arg1, hdlp->ih_cb_arg2, rec_type, msg_code);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, ino);
	ipil_list = ino_p ? ino_p->ino_ipil_p : NULL;

	/* Sharing ino */
	if (ino_p && (ipil_p = px_ib_ino_locate_ipil(ino_p, hdlp->ih_pri))) {
		if (px_ib_intr_locate_ih(ipil_p, rdip,
		    hdlp->ih_inum, rec_type, msg_code)) {
			DBG(DBG_MSIQ, dip, "px_add_msiq_intr: "
			    "dup intr #%d\n", hdlp->ih_inum);

			ret = DDI_FAILURE;
			goto fail1;
		}

		/* Save mondo value in hdlp */
		hdlp->ih_vector = ino_p->ino_sysino;

		if ((ret = px_ib_ino_add_intr(px_p, ipil_p,
		    ih_p)) != DDI_SUCCESS)
			goto fail1;

		goto ino_done;
	}

	if (hdlp->ih_pri == 0)
		hdlp->ih_pri = pci_class_to_pil(rdip);

	ipil_p = px_ib_new_ino_pil(ib_p, ino, hdlp->ih_pri, ih_p);
	ino_p = ipil_p->ipil_ino_p;

	ino_p->ino_msiq_p = msiq_state_p->msiq_p +
	    (*msiq_id_p - msiq_state_p->msiq_1st_msiq_id);

	/* Save mondo value in hdlp */
	hdlp->ih_vector = ino_p->ino_sysino;

	DBG(DBG_MSIQ, dip, "px_add_msiq_intr: pil=0x%x mondo=0x%x\n",
	    hdlp->ih_pri, hdlp->ih_vector);

	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
	    (ddi_intr_handler_t *)px_msiq_intr, (caddr_t)ipil_p, NULL);

	ret = i_ddi_add_ivintr(hdlp);

	/*
	 * Restore original interrupt handler
	 * and arguments in interrupt handle.
	 */
	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp, ih_p->ih_handler,
	    ih_p->ih_handler_arg1, ih_p->ih_handler_arg2);

	if (ret != DDI_SUCCESS)
		goto fail2;

	/* Save the pil for this ino */
	ipil_p->ipil_pil = hdlp->ih_pri;

	/* Select cpu, saving it for sharing and removal */
	if (ipil_list == NULL) {
		ino_p->ino_cpuid = intr_dist_cpuid();

		/* Enable MSIQ */
		px_lib_msiq_setstate(dip, *msiq_id_p, PCI_MSIQ_STATE_IDLE);
		px_lib_msiq_setvalid(dip, *msiq_id_p, PCI_MSIQ_VALID);

		/* Enable interrupt */
		px_ib_intr_enable(px_p, ino_p->ino_cpuid, ino);
	}

ino_done:
	/* Add weight to the cpu that we are already targeting */
	weight = pci_class_to_intr_weight(rdip);
	intr_dist_cpuid_add_device_weight(ino_p->ino_cpuid, rdip, weight);

	ih_p->ih_ipil_p = ipil_p;
	px_create_intr_kstats(ih_p);
	if (ih_p->ih_ksp)
		kstat_install(ih_p->ih_ksp);
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	DBG(DBG_MSIQ, dip, "px_add_msiq_intr: done! Interrupt 0x%x pil=%x\n",
	    ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
fail2:
	px_ib_delete_ino_pil(ib_p, ipil_p);
fail1:
	if (ih_p->ih_config_handle)
		pci_config_teardown(&ih_p->ih_config_handle);

	mutex_exit(&ib_p->ib_ino_lst_mutex);
	kmem_free(ih_p, sizeof (px_ih_t));

	DBG(DBG_MSIQ, dip, "px_add_msiq_intr: Failed! Interrupt 0x%x pil=%x\n",
	    ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
}

/*
 * px_rem_msiq_intr:
 *
 * This function is called to unregister MSI/Xs and PCIe message interrupts.
 */
int
px_rem_msiq_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, msiq_rec_type_t rec_type,
    msgcode_t msg_code, msiqid_t msiq_id)
{
	px_t		*px_p = INST_TO_STATE(ddi_get_instance(dip));
	px_ib_t		*ib_p = px_p->px_ib_p;
	devino_t	ino = px_msiqid_to_devino(px_p, msiq_id);
	cpuid_t		curr_cpu;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p;
	px_ih_t		*ih_p;
	int		ret = DDI_SUCCESS;

	DBG(DBG_MSIQ, dip, "px_rem_msiq_intr: rdip=%s%d msiq_id=%x ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), msiq_id, ino);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, ino);
	ipil_p = px_ib_ino_locate_ipil(ino_p, hdlp->ih_pri);
	ih_p = px_ib_intr_locate_ih(ipil_p, rdip, hdlp->ih_inum, rec_type,
	    msg_code);

	/* Get the current cpu */
	if ((ret = px_lib_intr_gettarget(px_p->px_dip, ino_p->ino_sysino,
	    &curr_cpu)) != DDI_SUCCESS)
		goto fail;

	if ((ret = px_ib_ino_rem_intr(px_p, ipil_p, ih_p)) != DDI_SUCCESS)
		goto fail;

	intr_dist_cpuid_rem_device_weight(ino_p->ino_cpuid, rdip);

	if (ipil_p->ipil_ih_size == 0) {
		hdlp->ih_vector = ino_p->ino_sysino;
		i_ddi_rem_ivintr(hdlp);

		px_ib_delete_ino_pil(ib_p, ipil_p);

		if (ino_p->ino_ipil_size == 0)
			px_lib_msiq_setvalid(dip,
			    px_devino_to_msiqid(px_p, ino), PCI_MSIQ_INVALID);

		(void) px_msiq_free(px_p, msiq_id);
	}

	if (ino_p->ino_ipil_size == 0) {
		kmem_free(ino_p, sizeof (px_ino_t));
	} else {
		/* Re-enable interrupt only if mapping register still shared */
		PX_INTR_ENABLE(px_p->px_dip, ino_p->ino_sysino, curr_cpu);
	}

fail:
	mutex_exit(&ib_p->ib_ino_lst_mutex);
	return (ret);
}
