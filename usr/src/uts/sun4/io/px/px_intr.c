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
#include <sys/machsystm.h>	/* e_ddi_nodeid_to_dip() */
#include <sys/ddi_impldefs.h>
#include <sys/sdt.h>
#include <sys/atomic.h>
#include "px_obj.h"

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
px_spurintr(px_ib_ino_info_t *ino_p)
{
	px_ih_t	*ih_p = ino_p->ino_ih_start;
	px_t	*px_p = ino_p->ino_ib_p->ib_px_p;
	char	*err_fmt_str;
	int	i;

	if (ino_p->ino_unclaimed > px_unclaimed_intr_max)
		return (DDI_INTR_CLAIMED);

	if (!ino_p->ino_unclaimed)
		ino_p->ino_spurintr_begin = ddi_get_lbolt();

	ino_p->ino_unclaimed++;

	if (ino_p->ino_unclaimed <= px_unclaimed_intr_max)
		goto clear;

	if (drv_hztousec(ddi_get_lbolt() - ino_p->ino_spurintr_begin)
	    > px_spurintr_duration) {
		ino_p->ino_unclaimed = 0;
		goto clear;
	}
	err_fmt_str = "%s%d: ino 0x%x blocked";
	goto warn;
clear:
	/* Clear the pending state */
	if (px_lib_intr_setstate(px_p->px_dip, ino_p->ino_sysino,
	    INTR_IDLE_STATE) != DDI_SUCCESS)
		return (DDI_INTR_UNCLAIMED);

	err_fmt_str = "!%s%d: spurious interrupt from ino 0x%x";
warn:
	cmn_err(CE_WARN, err_fmt_str, NAMEINST(px_p->px_dip), ino_p->ino_ino);
	for (i = 0; i < ino_p->ino_ih_size; i++, ih_p = ih_p->ih_next)
		cmn_err(CE_CONT, "!%s-%d#%x ", NAMEINST(ih_p->ih_dip),
		    ih_p->ih_inum);
	cmn_err(CE_CONT, "!\n");
	return (DDI_INTR_CLAIMED);
}


extern uint64_t intr_get_time(void);

/*
 * px_intx_intr (legacy or intx interrupt handler)
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
	px_ib_ino_info_t *ino_p = (px_ib_ino_info_t *)arg;
	px_t		*px_p = ino_p->ino_ib_p->ib_px_p;
	px_ih_t		*ih_p = ino_p->ino_ih_start;
	uint_t		result = 0, r;
	int		i;

	DBG(DBG_INTX_INTR, px_p->px_dip, "px_intx_intr:"
	    "ino=%x sysino=%llx pil=%x ih_size=%x ih_lst=%x\n",
	    ino_p->ino_ino, ino_p->ino_sysino, ino_p->ino_pil,
	    ino_p->ino_ih_size, ino_p->ino_ih_head);

	for (i = 0; i < ino_p->ino_ih_size; i++, ih_p = ih_p->ih_next) {
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

		if (ino_p->ino_pil <= LOCK_LEVEL)
			atomic_add_64(&ih_p->ih_ticks, intr_get_time());

		DTRACE_PROBE4(interrupt__complete, dev_info_t, dip,
		    void *, handler, caddr_t, arg1, int, r);

		result += r;

		if (px_check_all_handlers)
			continue;
		if (result)
			break;
	}

	if (!result && px_unclaimed_intr_block)
		return (px_spurintr(ino_p));

	ino_p->ino_unclaimed = 0;

	/* Clear the pending state */
	if (px_lib_intr_setstate(ino_p->ino_ib_p->ib_px_p->px_dip,
	    ino_p->ino_sysino, INTR_IDLE_STATE) != DDI_SUCCESS)
		return (DDI_INTR_UNCLAIMED);

	return (DDI_INTR_CLAIMED);
}

/*
 * px_msiq_intr (MSI/MSIX/MSG interrupt handler)
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
	px_ib_ino_info_t	*ino_p = (px_ib_ino_info_t *)arg;
	px_t		*px_p = ino_p->ino_ib_p->ib_px_p;
	px_msiq_state_t	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	px_msiq_t	*msiq_p = ino_p->ino_msiq_p;
	dev_info_t	*dip = px_p->px_dip;
	msiq_rec_t	msiq_rec, *msiq_rec_p = &msiq_rec;
	msiqhead_t	curr_msiq_rec_cnt, new_msiq_rec_cnt;
	msgcode_t	msg_code;
	px_ih_t		*ih_p;
	int		ret;

	DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: msiq_id =%x ino=%x pil=%x "
	    "ih_size=%x ih_lst=%x\n", msiq_p->msiq_id, ino_p->ino_ino,
	    ino_p->ino_pil, ino_p->ino_ih_size, ino_p->ino_ih_head);

	/* Read current MSIQ head index */
	px_lib_msiq_gethead(dip, msiq_p->msiq_id, &curr_msiq_rec_cnt);
	msiq_p->msiq_curr = (uint64_t)((caddr_t)msiq_p->msiq_base +
	    curr_msiq_rec_cnt * sizeof (msiq_rec_t));
	new_msiq_rec_cnt = curr_msiq_rec_cnt;

	/* Read next MSIQ record */
	px_lib_get_msiq_rec(dip, msiq_p, msiq_rec_p);

	/*
	 * Process current MSIQ record as long as request id
	 * field is non-zero.
	 */
	while (msiq_rec_p->msiq_rec_rid) {
		DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: MSIQ RECORD, "
		    "msiq_rec_type 0x%llx msiq_rec_rid 0x%llx\n",
		    msiq_rec_p->msiq_rec_type, msiq_rec_p->msiq_rec_rid);

		/* Get the pointer next EQ record */
		msiq_p->msiq_curr = (uint64_t)
		    ((caddr_t)msiq_p->msiq_curr + sizeof (msiq_rec_t));

		/* Check for overflow condition */
		if (msiq_p->msiq_curr >= (uint64_t)((caddr_t)msiq_p->msiq_base +
		    msiq_state_p->msiq_rec_cnt * sizeof (msiq_rec_t)))
			msiq_p->msiq_curr = msiq_p->msiq_base;

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

		ih_p = ino_p->ino_ih_start;

		/*
		 * Scan through px_ih_t linked list, searching for the
		 * right px_ih_t, matching MSIQ record data.
		 */
		while ((ih_p) && (ih_p->ih_msg_code != msg_code) &&
		    (ih_p->ih_rec_type != msiq_rec_p->msiq_rec_type))
			ih_p = ih_p->ih_next;

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

			if (msiq_rec_p->msiq_rec_type == MSG_REC)
				px_p->px_pec_p->pec_msiq_rec_p = msiq_rec_p;

			ret = (*handler)(arg1, arg2);

			/*
			 * Account for time used by this interrupt. Protect
			 * against conflicting writes to ih_ticks from
			 * ib_intr_dist_all() by using atomic ops.
			 */

			if (ino_p->ino_pil <= LOCK_LEVEL)
				atomic_add_64(&ih_p->ih_ticks, intr_get_time());

			DTRACE_PROBE4(interrupt__complete, dev_info_t, dip,
			    void *, handler, caddr_t, arg1, int, ret);
		} else {
			DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr:"
			    "Not found matching MSIQ record\n");

			/* px_spurintr(ino_p); */
			ino_p->ino_unclaimed++;
		}

next_rec:
		new_msiq_rec_cnt++;

		/* Zero out msiq_rec_rid field */
		msiq_rec_p->msiq_rec_rid = 0;

		/* Read next MSIQ record */
		px_lib_get_msiq_rec(dip, msiq_p, msiq_rec_p);
	}

	DBG(DBG_MSIQ_INTR, dip, "px_msiq_intr: No of MSIQ recs processed %x\n",
	    (new_msiq_rec_cnt - curr_msiq_rec_cnt));

	/*  Update MSIQ head index with no of MSIQ records processed */
	if (new_msiq_rec_cnt > curr_msiq_rec_cnt)  {
		if (new_msiq_rec_cnt >= msiq_state_p->msiq_rec_cnt)
			new_msiq_rec_cnt -= msiq_state_p->msiq_rec_cnt;

		px_lib_msiq_sethead(dip, msiq_p->msiq_id, new_msiq_rec_cnt);
	}

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

/* Default class to pil value mapping */
px_class_val_t px_default_pil [] = {
	{0x000000, 0xff0000, 0x1},	/* Class code for pre-2.0 devices */
	{0x010000, 0xff0000, 0x4},	/* Mass Storage Controller */
	{0x020000, 0xff0000, 0x6},	/* Network Controller */
	{0x030000, 0xff0000, 0x9},	/* Display Controller */
	{0x040000, 0xff0000, 0x9},	/* Multimedia Controller */
	{0x050000, 0xff0000, 0xb},	/* Memory Controller */
	{0x060000, 0xff0000, 0xb},	/* Bridge Controller */
	{0x0c0000, 0xffff00, 0x9},	/* Serial Bus, FireWire (IEEE 1394) */
	{0x0c0100, 0xffff00, 0x4},	/* Serial Bus, ACCESS.bus */
	{0x0c0200, 0xffff00, 0x4},	/* Serial Bus, SSA */
	{0x0c0300, 0xffff00, 0x9},	/* Serial Bus Universal Serial Bus */
	{0x0c0400, 0xffff00, 0x6},	/* Serial Bus, Fibre Channel */
	{0x0c0600, 0xffff00, 0x6}	/* Serial Bus, Infiniband */
};

/*
 * Default class to intr_weight value mapping (% of CPU).  A driver.conf
 * entry on or above the pci node like
 *
 *	pci-class-intr-weights= 0x020000, 0xff0000, 30;
 *
 * can be used to augment or override entries in the default table below.
 *
 * NB: The values below give NICs preference on redistribution, and provide
 * NICs some isolation from other interrupt sources. We need better interfaces
 * that allow the NIC driver to identify a specific NIC instance as high
 * bandwidth, and thus deserving of separation from other low bandwidth
 * NICs additional isolation from other interrupt sources.
 *
 * NB: We treat Infiniband like a NIC.
 */
px_class_val_t px_default_intr_weight [] = {
	{0x020000, 0xff0000, 35},	/* Network Controller */
	{0x010000, 0xff0000, 10},	/* Mass Storage Controller */
	{0x0c0400, 0xffff00, 10},	/* Serial Bus, Fibre Channel */
	{0x0c0600, 0xffff00, 50}	/* Serial Bus, Infiniband */
};

static uint32_t
px_match_class_val(uint32_t key, px_class_val_t *rec_p, int nrec,
    uint32_t default_val)
{
	int	i;

	for (i = 0; i < nrec; rec_p++, i++) {
		if ((rec_p->class_code & rec_p->class_mask) ==
		    (key & rec_p->class_mask))
			return (rec_p->class_val);
	}

	return (default_val);
}

/*
 * px_class_to_val
 *
 * Return the configuration value, based on class code and sub class code,
 * from the specified property based or default px_class_val_t table.
 */
uint32_t
px_class_to_val(dev_info_t *rdip, char *property_name, px_class_val_t *rec_p,
    int nrec, uint32_t default_val)
{
	int property_len;
	uint32_t class_code;
	px_class_val_t *conf;
	uint32_t val = default_val;

	/*
	 * Use the "class-code" property to get the base and sub class
	 * codes for the requesting device.
	 */
	class_code = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "class-code", -1);

	if (class_code == -1)
		return (val);

	/* look up the val from the default table */
	val = px_match_class_val(class_code, rec_p, nrec, val);

	/* see if there is a more specific property specified value */
	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_NOTPROM,
	    property_name, (caddr_t)&conf, &property_len))
		return (val);

	if ((property_len % sizeof (px_class_val_t)) == 0)
		val = px_match_class_val(class_code, conf,
		    property_len / sizeof (px_class_val_t), val);
	kmem_free(conf, property_len);
	return (val);
}


/* px_class_to_pil: return the pil for a given device. */
uint32_t
px_class_to_pil(dev_info_t *rdip)
{
	uint32_t pil;

	/* default pil is 0 (uninitialized) */
	pil = px_class_to_val(rdip,
	    "pci-class-priorities", px_default_pil,
	    sizeof (px_default_pil) / sizeof (px_class_val_t), 0);

	/* range check the result */
	if (pil >= 0xf)
		pil = 0;

	return (pil);
}


/* px_class_to_intr_weight: return the intr_weight for a given device. */
static int32_t
px_class_to_intr_weight(dev_info_t *rdip)
{
	int32_t intr_weight;

	/* default weight is 0% */
	intr_weight = px_class_to_val(rdip,
	    "pci-class-intr-weights", px_default_intr_weight,
	    sizeof (px_default_intr_weight) / sizeof (px_class_val_t), 0);

	/* range check the result */
	if (intr_weight < 0)
		intr_weight = 0;
	if (intr_weight > 1000)
		intr_weight = 1000;

	return (intr_weight);
}


/* ARGSUSED */
int
px_intx_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	ddi_ispec_t	*ip = (ddi_ispec_t *)hdlp->ih_private;
	int		ret = DDI_SUCCESS;

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
		*(int *)result = ip->is_pil ?
		    ip->is_pil : px_class_to_pil(rdip);
		break;
	case DDI_INTROP_SETPRI:
		ip->is_pil = (*(int *)result);
		break;
	case DDI_INTROP_ADDISR:
		hdlp->ih_vector = *ip->is_intr;

		ret = px_add_intx_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		hdlp->ih_vector = *ip->is_intr;

		ret = px_rem_intx_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
		ret = px_ib_update_intr_state(px_p, rdip, hdlp->ih_inum,
		    *ip->is_intr, PX_INTR_STATE_ENABLE);
		break;
	case DDI_INTROP_DISABLE:
		ret = px_ib_update_intr_state(px_p, rdip, hdlp->ih_inum,
		    *ip->is_intr, PX_INTR_STATE_DISABLE);
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
		*(int *)result = i_ddi_get_nintrs(rdip);
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		*(int *)result = DDI_INTR_TYPE_FIXED;
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
	msinum_t		msi_num;
	msiqid_t		msiq_id;
	uint_t			nintrs;
	int			i, ret = DDI_SUCCESS;

	DBG(DBG_INTROPS, dip, "px_msix_ops: dip=%x rdip=%x intr_op=%x "
	    "handle=%p\n", dip, rdip, intr_op, hdlp);

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
		if ((ret = px_msi_alloc(px_p, rdip, hdlp->ih_inum,
		    hdlp->ih_scratch1, hdlp->ih_scratch2, &msi_num,
		    (int *)result)) != DDI_SUCCESS) {
			DBG(DBG_INTROPS, dip, "px_msix_ops: MSI allocation "
			    "failed, rdip 0x%p inum 0x%x count 0x%x\n",
			    rdip, hdlp->ih_inum, hdlp->ih_scratch1);

			return (ret);
		}

		break;
	case DDI_INTROP_FREE:
		(void) pci_msi_disable_mode(rdip, hdlp->ih_type, hdlp->ih_inum);
		(void) pci_msi_unconfigure(rdip, hdlp->ih_type, hdlp->ih_inum);
		(void) px_msi_free(px_p, rdip, hdlp->ih_inum,
		    hdlp->ih_scratch1);
		break;
	case DDI_INTROP_GETPRI:
		*(int *)result = hdlp->ih_pri ?
		    hdlp->ih_pri : px_class_to_pil(rdip);
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		if ((ret = px_msi_get_msinum(px_p, hdlp->ih_dip,
		    hdlp->ih_inum, &msi_num)) != DDI_SUCCESS)
			return (ret);

		if ((ret = px_add_msiq_intr(dip, rdip, hdlp,
		    MSI32_REC, msi_num, &msiq_id)) != DDI_SUCCESS) {
			DBG(DBG_INTROPS, dip, "px_msix_ops: Add MSI handler "
			    "failed, rdip 0x%p msi 0x%x\n", rdip, msi_num);
			return (ret);
		}

		DBG(DBG_INTROPS, dip, "px_msix_ops: msiq used 0x%x\n", msiq_id);

		if ((ret = px_lib_msi_setmsiq(dip, msi_num,
		    msiq_id, MSI32_TYPE)) != DDI_SUCCESS) {
			(void) px_rem_msiq_intr(dip, rdip,
			    hdlp, MSI32_REC, msi_num, msiq_id);
			return (ret);
		}

		if ((ret = px_lib_msi_setstate(dip, msi_num,
		    PCI_MSI_STATE_IDLE)) != DDI_SUCCESS) {
			(void) px_rem_msiq_intr(dip, rdip,
			    hdlp, MSI32_REC, msi_num, msiq_id);
			return (ret);
		}

		hdlp->ih_vector = msi_num;
		break;
	case DDI_INTROP_DUPVEC:
		DBG(DBG_INTROPS, dip, "px_msix_ops: DupIsr is not supported\n");
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_REMISR:
		msi_num = hdlp->ih_vector;

		if ((ret = px_lib_msi_getmsiq(dip, msi_num,
		    &msiq_id)) != DDI_SUCCESS)
			return (ret);

		if ((ret = px_lib_msi_setstate(dip, msi_num,
		    PCI_MSI_STATE_DELIVERED)) != DDI_SUCCESS)
			return (ret);

		ret = px_rem_msiq_intr(dip, rdip,
		    hdlp, MSI32_REC, msi_num, msiq_id);

		hdlp->ih_vector = 0;
		break;
	case DDI_INTROP_ENABLE:
		msi_num = hdlp->ih_vector;

		if ((ret = px_lib_msi_setvalid(dip, msi_num,
		    PCI_MSI_VALID)) != DDI_SUCCESS)
			return (ret);

		if (pci_is_msi_enabled(rdip, hdlp->ih_type) != DDI_SUCCESS) {
			nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);

			if ((ret = pci_msi_configure(rdip, hdlp->ih_type,
			    nintrs, hdlp->ih_inum, msi_state_p->msi_addr32,
			    msi_num & ~(nintrs - 1))) != DDI_SUCCESS)
				return (ret);

			if ((ret = pci_msi_enable_mode(rdip, hdlp->ih_type,
			    hdlp->ih_inum)) != DDI_SUCCESS)
				return (ret);
		}

		ret = pci_msi_clr_mask(rdip, hdlp->ih_type, hdlp->ih_inum);

		break;
	case DDI_INTROP_DISABLE:
		msi_num = hdlp->ih_vector;

		if ((ret = pci_msi_set_mask(rdip, hdlp->ih_type,
		    hdlp->ih_inum)) != DDI_SUCCESS)
			return (ret);

		ret = px_lib_msi_setvalid(dip, msi_num, PCI_MSI_INVALID);
		break;
	case DDI_INTROP_BLOCKENABLE:
		nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);
		msi_num = hdlp->ih_vector;

		if ((ret = pci_msi_configure(rdip, hdlp->ih_type,
		    nintrs, hdlp->ih_inum, msi_state_p->msi_addr32,
		    msi_num & ~(nintrs - 1))) != DDI_SUCCESS)
			return (ret);

		for (i = 0; i < nintrs; i++, msi_num++) {
			if ((ret = px_lib_msi_setvalid(dip, msi_num,
			    PCI_MSI_VALID)) != DDI_SUCCESS)
				return (ret);
		}

		ret = pci_msi_enable_mode(rdip, hdlp->ih_type, hdlp->ih_inum);
		break;
	case DDI_INTROP_BLOCKDISABLE:
		nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);
		msi_num = hdlp->ih_vector;

		if ((ret = pci_msi_disable_mode(rdip, hdlp->ih_type,
		    hdlp->ih_inum)) != DDI_SUCCESS)
			return (ret);

		for (i = 0; i < nintrs; i++, msi_num++) {
			if ((ret = px_lib_msi_setvalid(dip, msi_num,
			    PCI_MSI_INVALID)) != DDI_SUCCESS)
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
	case DDI_INTROP_SUPPORTED_TYPES:
		ret = pci_msi_get_supported_type(rdip, (int *)result);
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

int
px_add_intx_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	px_t		*px_p = INST_TO_STATE(ddi_get_instance(dip));
	px_ib_t		*ib_p = px_p->px_ib_p;
	devino_t	ino;
	px_ih_t		*ih_p;
	px_ib_ino_info_t *ino_p;
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

	if (ino_p = px_ib_locate_ino(ib_p, ino)) {	/* sharing ino */
		uint32_t intr_index = hdlp->ih_inum;
		if (px_ib_ino_locate_intr(ino_p, rdip, intr_index, 0, 0)) {
			DBG(DBG_A_INTX, dip, "px_add_intx_intr: "
			    "dup intr #%d\n", intr_index);

			ret = DDI_FAILURE;
			goto fail1;
		}

		/* Save mondo value in hdlp */
		hdlp->ih_vector = ino_p->ino_sysino;

		if ((ret = px_ib_ino_add_intr(px_p, ino_p, ih_p))
		    != DDI_SUCCESS)
			goto fail1;
	} else {
		ino_p = px_ib_new_ino(ib_p, ino, ih_p);

		if (hdlp->ih_pri == 0)
			hdlp->ih_pri = px_class_to_pil(rdip);

		/* Save mondo value in hdlp */
		hdlp->ih_vector = ino_p->ino_sysino;

		DBG(DBG_A_INTX, dip, "px_add_intx_intr: pil=0x%x mondo=0x%x\n",
		    hdlp->ih_pri, hdlp->ih_vector);

		DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
		    (ddi_intr_handler_t *)px_intx_intr, (caddr_t)ino_p, NULL);

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
		ino_p->ino_pil = hdlp->ih_pri;

		/* select cpu, saving it for sharing and removal */
		ino_p->ino_cpuid = intr_dist_cpuid();

		/* Enable interrupt */
		px_ib_intr_enable(px_p, ino_p->ino_cpuid, ino);
	}

	/* add weight to the cpu that we are already targeting */
	weight = px_class_to_intr_weight(rdip);
	intr_dist_cpuid_add_device_weight(ino_p->ino_cpuid, rdip, weight);

	ih_p->ih_ino_p = ino_p;
	if (ih_p->ih_ksp)
		kstat_install(ih_p->ih_ksp);
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	DBG(DBG_A_INTX, dip, "px_add_intx_intr: done! Interrupt 0x%x pil=%x\n",
	    ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
fail2:
	px_ib_delete_ino(ib_p, ino_p);
fail1:
	if (ih_p->ih_config_handle)
		pci_config_teardown(&ih_p->ih_config_handle);

	mutex_exit(&ib_p->ib_ino_lst_mutex);
	kmem_free(ih_p, sizeof (px_ih_t));

	DBG(DBG_A_INTX, dip, "px_add_intx_intr: Failed! Interrupt 0x%x "
	    "pil=%x\n", ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
}

int
px_rem_intx_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	px_t		*px_p = INST_TO_STATE(ddi_get_instance(dip));
	px_ib_t		*ib_p = px_p->px_ib_p;
	devino_t	ino;
	cpuid_t		curr_cpu;
	px_ib_ino_info_t	*ino_p;
	px_ih_t		*ih_p;
	int		ret = DDI_SUCCESS;

	ino = hdlp->ih_vector;

	DBG(DBG_R_INTX, dip, "px_rem_intx_intr: rdip=%s%d ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), ino);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, ino);
	ih_p = px_ib_ino_locate_intr(ino_p, rdip, hdlp->ih_inum, 0, 0);

	/* Get the current cpu */
	if ((ret = px_lib_intr_gettarget(px_p->px_dip, ino_p->ino_sysino,
	    &curr_cpu)) != DDI_SUCCESS)
		goto fail;

	if ((ret = px_ib_ino_rem_intr(px_p, ino_p, ih_p)) != DDI_SUCCESS)
		goto fail;

	intr_dist_cpuid_rem_device_weight(ino_p->ino_cpuid, rdip);

	if (ino_p->ino_ih_size == 0) {
		if ((ret = px_lib_intr_setstate(px_p->px_dip, ino_p->ino_sysino,
		    INTR_DELIVERED_STATE)) != DDI_SUCCESS)
			goto fail;

		hdlp->ih_vector = ino_p->ino_sysino;
		i_ddi_rem_ivintr(hdlp);

		px_ib_delete_ino(ib_p, ino_p);
		kmem_free(ino_p, sizeof (px_ib_ino_info_t));
	} else {
		/* Re-enable interrupt only if mapping regsiter still shared */
		if ((ret = px_lib_intr_settarget(px_p->px_dip,
			    ino_p->ino_sysino, curr_cpu)) != DDI_SUCCESS)
			goto fail;

		ret = px_lib_intr_setvalid(px_p->px_dip, ino_p->ino_sysino,
		    INTR_VALID);
	}

fail:
	mutex_exit(&ib_p->ib_ino_lst_mutex);
	return (ret);
}

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
	px_ib_ino_info_t	*ino_p;
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

	if (ino_p = px_ib_locate_ino(ib_p, ino)) {	/* sharing ino */
		uint32_t intr_index = hdlp->ih_inum;
		if (px_ib_ino_locate_intr(ino_p, rdip,
		    intr_index, rec_type, msg_code)) {
			DBG(DBG_MSIQ, dip, "px_add_msiq_intr: "
			    "dup intr #%d\n", intr_index);

			ret = DDI_FAILURE;
			goto fail1;
		}

		if ((ret = px_ib_ino_add_intr(px_p, ino_p, ih_p))
		    != DDI_SUCCESS)
			goto fail1;
	} else {
		ino_p = px_ib_new_ino(ib_p, ino, ih_p);

		ino_p->ino_msiq_p = msiq_state_p->msiq_p +
		    (*msiq_id_p - msiq_state_p->msiq_1st_msiq_id);

		if (hdlp->ih_pri == 0)
			hdlp->ih_pri = px_class_to_pil(rdip);

		/* Save mondo value in hdlp */
		hdlp->ih_vector = ino_p->ino_sysino;

		DBG(DBG_MSIQ, dip, "px_add_msiq_intr: pil=0x%x mondo=0x%x\n",
		    hdlp->ih_pri, hdlp->ih_vector);

		DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
		    (ddi_intr_handler_t *)px_msiq_intr, (caddr_t)ino_p, NULL);

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
		ino_p->ino_pil = hdlp->ih_pri;

		/* Enable MSIQ */
		px_lib_msiq_setstate(dip, *msiq_id_p, PCI_MSIQ_STATE_IDLE);
		px_lib_msiq_setvalid(dip, *msiq_id_p, PCI_MSIQ_VALID);

		/* select cpu, saving it for sharing and removal */
		ino_p->ino_cpuid = intr_dist_cpuid();

		/* Enable interrupt */
		px_ib_intr_enable(px_p, ino_p->ino_cpuid, ino_p->ino_ino);
	}

	/* add weight to the cpu that we are already targeting */
	weight = px_class_to_intr_weight(rdip);
	intr_dist_cpuid_add_device_weight(ino_p->ino_cpuid, rdip, weight);

	ih_p->ih_ino_p = ino_p;
	if (ih_p->ih_ksp)
		kstat_install(ih_p->ih_ksp);
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	DBG(DBG_MSIQ, dip, "px_add_msiq_intr: done! Interrupt 0x%x pil=%x\n",
	    ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
fail2:
	px_ib_delete_ino(ib_p, ino_p);
fail1:
	if (ih_p->ih_config_handle)
		pci_config_teardown(&ih_p->ih_config_handle);

	mutex_exit(&ib_p->ib_ino_lst_mutex);
	kmem_free(ih_p, sizeof (px_ih_t));

	DBG(DBG_MSIQ, dip, "px_add_msiq_intr: Failed! Interrupt 0x%x pil=%x\n",
	    ino_p->ino_sysino, hdlp->ih_pri);

	return (ret);
}

int
px_rem_msiq_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, msiq_rec_type_t rec_type,
    msgcode_t msg_code, msiqid_t msiq_id)
{
	px_t		*px_p = INST_TO_STATE(ddi_get_instance(dip));
	px_ib_t		*ib_p = px_p->px_ib_p;
	devino_t	ino = px_msiqid_to_devino(px_p, msiq_id);
	cpuid_t		curr_cpu;
	px_ib_ino_info_t *ino_p;
	px_ih_t		*ih_p;
	int		ret = DDI_SUCCESS;

	DBG(DBG_MSIQ, dip, "px_rem_msiq_intr: rdip=%s%d msiq_id=%x ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), msiq_id, ino);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, ino);
	ih_p = px_ib_ino_locate_intr(ino_p, rdip, hdlp->ih_inum,
	    rec_type, msg_code);

	/* Get the current cpu */
	if ((ret = px_lib_intr_gettarget(px_p->px_dip, ino_p->ino_sysino,
	    &curr_cpu)) != DDI_SUCCESS)
		goto fail;

	if ((ret = px_ib_ino_rem_intr(px_p, ino_p, ih_p)) != DDI_SUCCESS)
		goto fail;

	intr_dist_cpuid_rem_device_weight(ino_p->ino_cpuid, rdip);

	if (ino_p->ino_ih_size == 0) {
		if ((ret = px_lib_intr_setstate(px_p->px_dip, ino_p->ino_sysino,
		    INTR_DELIVERED_STATE)) != DDI_SUCCESS)
			goto fail;

		px_lib_msiq_setvalid(dip, px_devino_to_msiqid(px_p, ino),
		    PCI_MSIQ_INVALID);

		hdlp->ih_vector = ino_p->ino_sysino;
		i_ddi_rem_ivintr(hdlp);

		px_ib_delete_ino(ib_p, ino_p);

		(void) px_msiq_free(px_p, msiq_id);
		kmem_free(ino_p, sizeof (px_ib_ino_info_t));
	} else {
		/* Re-enable interrupt only if mapping regsiter still shared */
		if ((ret = px_lib_intr_settarget(px_p->px_dip,
			    ino_p->ino_sysino, curr_cpu)) != DDI_SUCCESS)
			goto fail;

		ret = px_lib_intr_setvalid(px_p->px_dip, ino_p->ino_sysino,
		    INTR_VALID);
	}

fail:
	mutex_exit(&ib_p->ib_ino_lst_mutex);
	return (ret);
}
