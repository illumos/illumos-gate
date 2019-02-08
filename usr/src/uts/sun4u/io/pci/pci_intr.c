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
 * Copyright 2019 Peter Tribble.
 */

/*
 * PCI nexus interrupt handling:
 *	PCI device interrupt handler wrapper
 *	pil lookup routine
 *	PCI device interrupt related initchild code
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>	/* e_ddi_nodeid_to_dip() */
#include <sys/ddi_impldefs.h>
#include <sys/pci/pci_obj.h>
#include <sys/sdt.h>
#include <sys/clock.h>

/*
 * interrupt jabber:
 *
 * When an interrupt line is jabbering, every time the state machine for the
 * associated ino is idled, a new mondo will be sent and the ino will go into
 * the pending state again. The mondo will cause a new call to
 * pci_intr_wrapper() which normally idles the ino's state machine which would
 * precipitate another trip round the loop.
 * The loop can be broken by preventing the ino's state machine from being
 * idled when an interrupt line is jabbering. See the comment at the
 * beginning of pci_intr_wrapper() explaining how the 'interrupt jabber
 * protection' code does this.
 */

/*LINTLIBRARY*/

#ifdef NOT_DEFINED
/*
 * This array is used to determine the sparc PIL at the which the
 * handler for a given INO will execute.  This table is for onboard
 * devices only.  A different scheme will be used for plug-in cards.
 */

uint_t ino_to_pil[] = {

	/* pil */		/* ino */

	0, 0, 0, 0,  		/* 0x00 - 0x03: bus A slot 0 int#A, B, C, D */
	0, 0, 0, 0,		/* 0x04 - 0x07: bus A slot 1 int#A, B, C, D */
	0, 0, 0, 0,  		/* 0x08 - 0x0B: unused */
	0, 0, 0, 0,		/* 0x0C - 0x0F: unused */

	0, 0, 0, 0,  		/* 0x10 - 0x13: bus B slot 0 int#A, B, C, D */
	0, 0, 0, 0,		/* 0x14 - 0x17: bus B slot 1 int#A, B, C, D */
	0, 0, 0, 0,  		/* 0x18 - 0x1B: bus B slot 2 int#A, B, C, D */
	4, 0, 0, 0,		/* 0x1C - 0x1F: bus B slot 3 int#A, B, C, D */

	4,			/* 0x20: SCSI */
	6,			/* 0x21: ethernet */
	3,			/* 0x22: parallel port */
	9,			/* 0x23: audio record */
	9,			/* 0x24: audio playback */
	14,			/* 0x25: power fail */
	4,			/* 0x26: 2nd SCSI */
	8,			/* 0x27: floppy */
	14,			/* 0x28: thermal warning */
	12,			/* 0x29: keyboard */
	12,			/* 0x2A: mouse */
	12,			/* 0x2B: serial */
	0,			/* 0x2C: timer/counter 0 */
	0,			/* 0x2D: timer/counter 1 */
	14,			/* 0x2E: uncorrectable ECC errors */
	14,			/* 0x2F: correctable ECC errors */
	14,			/* 0x30: PCI bus A error */
	14,			/* 0x31: PCI bus B error */
	14,			/* 0x32: power management wakeup */
	14,			/* 0x33 */
	14,			/* 0x34 */
	14,			/* 0x35 */
	14,			/* 0x36 */
	14,			/* 0x37 */
	14,			/* 0x38 */
	14,			/* 0x39 */
	14,			/* 0x3a */
	14,			/* 0x3b */
	14,			/* 0x3c */
	14,			/* 0x3d */
	14,			/* 0x3e */
	14,			/* 0x3f */
	14			/* 0x40 */
};
#endif /* NOT_DEFINED */


#define	PCI_SIMBA_VENID		0x108e	/* vendor id for simba */
#define	PCI_SIMBA_DEVID		0x5000	/* device id for simba */

/*
 * map_pcidev_cfg_reg - create mapping to pci device configuration registers
 *			if we have a simba AND a pci to pci bridge along the
 *			device path.
 *			Called with corresponding mutexes held!!
 *
 * XXX	  XXX	XXX	The purpose of this routine is to overcome a hardware
 *			defect in Sabre CPU and Simba bridge configuration
 *			which does not drain DMA write data stalled in
 *			PCI to PCI bridges (such as the DEC bridge) beyond
 *			Simba. This routine will setup the data structures
 *			to allow the pci_intr_wrapper to perform a manual
 *			drain data operation before passing the control to
 *			interrupt handlers of device drivers.
 * return value:
 * DDI_SUCCESS
 * DDI_FAILURE		if unable to create mapping
 */
static int
map_pcidev_cfg_reg(dev_info_t *dip, dev_info_t *rdip, ddi_acc_handle_t *hdl_p)
{
	dev_info_t *cdip;
	dev_info_t *pci_dip = NULL;
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	int simba_found = 0, pci_bridge_found = 0;

	for (cdip = rdip; cdip && cdip != dip; cdip = ddi_get_parent(cdip)) {
		ddi_acc_handle_t config_handle;
		uint32_t vendor_id = ddi_getprop(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "vendor-id", 0xffff);

		DEBUG4(DBG_A_INTX, pci_p->pci_dip,
		    "map dev cfg reg for %s%d: @%s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(cdip), ddi_get_instance(cdip));

		if (ddi_prop_exists(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "no-dma-interrupt-sync"))
			continue;

		/* continue to search up-stream if not a PCI device */
		if (vendor_id == 0xffff)
			continue;

		/* record the deepest pci device */
		if (!pci_dip)
			pci_dip = cdip;

		/* look for simba */
		if (vendor_id == PCI_SIMBA_VENID) {
			uint32_t device_id = ddi_getprop(DDI_DEV_T_ANY,
			    cdip, DDI_PROP_DONTPASS, "device-id", -1);
			if (device_id == PCI_SIMBA_DEVID) {
				simba_found = 1;
				DEBUG0(DBG_A_INTX, pci_p->pci_dip,
				    "\tFound simba\n");
				continue; /* do not check bridge if simba */
			}
		}

		/* look for pci to pci bridge */
		if (pci_config_setup(cdip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s%d: can't get brdg cfg space for %s%d\n",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    ddi_driver_name(cdip), ddi_get_instance(cdip));
			return (DDI_FAILURE);
		}
		if (pci_config_get8(config_handle, PCI_CONF_BASCLASS)
		    == PCI_CLASS_BRIDGE) {
			DEBUG0(DBG_A_INTX, pci_p->pci_dip,
			    "\tFound PCI to xBus bridge\n");
			pci_bridge_found = 1;
		}
		pci_config_teardown(&config_handle);
	}

	if (!pci_bridge_found)
		return (DDI_SUCCESS);
	if (!simba_found && (CHIP_TYPE(pci_p) < PCI_CHIP_SCHIZO))
		return (DDI_SUCCESS);
	if (pci_config_setup(pci_dip, hdl_p) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: can not get config space for %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    ddi_driver_name(cdip), ddi_get_instance(cdip));
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * If the unclaimed interrupt count has reached the limit set by
 * pci_unclaimed_intr_max within the time limit, then all interrupts
 * on this ino is blocked by not idling the interrupt state machine.
 */
static int
pci_spurintr(ib_ino_pil_t *ipil_p) {
	ib_ino_info_t	*ino_p = ipil_p->ipil_ino_p;
	ih_t		*ih_p = ipil_p->ipil_ih_start;
	pci_t		*pci_p = ino_p->ino_ib_p->ib_pci_p;
	char		*err_fmt_str;
	boolean_t	blocked = B_FALSE;
	int		i;

	if (ino_p->ino_unclaimed_intrs > pci_unclaimed_intr_max)
		return (DDI_INTR_CLAIMED);

	if (!ino_p->ino_unclaimed_intrs)
		ino_p->ino_spurintr_begin = ddi_get_lbolt();

	ino_p->ino_unclaimed_intrs++;

	if (ino_p->ino_unclaimed_intrs <= pci_unclaimed_intr_max)
		goto clear;

	if (drv_hztousec(ddi_get_lbolt() - ino_p->ino_spurintr_begin)
	    > pci_spurintr_duration) {
		ino_p->ino_unclaimed_intrs = 0;
		goto clear;
	}
	err_fmt_str = "%s%d: ino 0x%x blocked";
	blocked = B_TRUE;
	goto warn;
clear:
	if (!pci_spurintr_msgs) { /* tomatillo errata #71 spurious mondo */
		/* clear the pending state */
		IB_INO_INTR_CLEAR(ino_p->ino_clr_reg);
		return (DDI_INTR_CLAIMED);
	}

	err_fmt_str = "!%s%d: spurious interrupt from ino 0x%x";
warn:
	cmn_err(CE_WARN, err_fmt_str, NAMEINST(pci_p->pci_dip), ino_p->ino_ino);
	for (i = 0; i < ipil_p->ipil_ih_size; i++, ih_p = ih_p->ih_next)
		cmn_err(CE_CONT, "!%s-%d#%x ", NAMEINST(ih_p->ih_dip),
		    ih_p->ih_inum);
	cmn_err(CE_CONT, "!\n");
	if (blocked == B_FALSE)  /* clear the pending state */
		IB_INO_INTR_CLEAR(ino_p->ino_clr_reg);

	return (DDI_INTR_CLAIMED);
}

/*
 * pci_intr_wrapper
 *
 * This routine is used as wrapper around interrupt handlers installed by child
 * device drivers.  This routine invokes the driver interrupt handlers and
 * examines the return codes.
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

extern uint64_t intr_get_time(void);

uint_t
pci_intr_wrapper(caddr_t arg)
{
	ib_ino_pil_t	*ipil_p = (ib_ino_pil_t *)arg;
	ib_ino_info_t	*ino_p = ipil_p->ipil_ino_p;
	uint_t		result = 0, r = DDI_INTR_UNCLAIMED;
	pci_t		*pci_p = ino_p->ino_ib_p->ib_pci_p;
	pbm_t		*pbm_p = pci_p->pci_pbm_p;
	ih_t		*ih_p = ipil_p->ipil_ih_start;
	int		i;

	for (i = 0; i < ipil_p->ipil_ih_size; i++, ih_p = ih_p->ih_next) {
		dev_info_t *dip = ih_p->ih_dip;
		uint_t (*handler)() = ih_p->ih_handler;
		caddr_t arg1 = ih_p->ih_handler_arg1;
		caddr_t arg2 = ih_p->ih_handler_arg2;
		ddi_acc_handle_t cfg_hdl = ih_p->ih_config_handle;

		if (pci_intr_dma_sync && cfg_hdl && pbm_p->pbm_sync_reg_pa) {
			(void) pci_config_get16(cfg_hdl, PCI_CONF_VENID);
			pci_pbm_dma_sync(pbm_p, ino_p->ino_ino);
		}

		if (ih_p->ih_intr_state == PCI_INTR_STATE_DISABLE) {
			DEBUG3(DBG_INTR, pci_p->pci_dip,
			    "pci_intr_wrapper: %s%d interrupt %d is disabled\n",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    ino_p->ino_ino);

			continue;
		}

		DTRACE_PROBE4(interrupt__start, dev_info_t, dip,
		    void *, handler, caddr_t, arg1, caddr_t, arg2);

		r = (*handler)(arg1, arg2);

		/*
		 * Account for time used by this interrupt. Protect against
		 * conflicting writes to ih_ticks from ib_intr_dist_all() by
		 * using atomic ops.
		 */

		if (ipil_p->ipil_pil <= LOCK_LEVEL)
			atomic_add_64(&ih_p->ih_ticks, intr_get_time());

		DTRACE_PROBE4(interrupt__complete, dev_info_t, dip,
		    void *, handler, caddr_t, arg1, int, r);

		result += r;

		if (pci_check_all_handlers)
			continue;
		if (result)
			break;
	}

	if (result)
		ino_p->ino_claimed |= (1 << ipil_p->ipil_pil);

	/* Interrupt can only be cleared after all pil levels are handled */
	if (ipil_p->ipil_pil != ino_p->ino_lopil)
		return (DDI_INTR_CLAIMED);

	if (!ino_p->ino_claimed)
		return (pci_spurintr(ipil_p));

	ino_p->ino_unclaimed_intrs = 0;
	ino_p->ino_claimed = 0;

	/* Clear the pending state */
	IB_INO_INTR_CLEAR(ino_p->ino_clr_reg);

	return (DDI_INTR_CLAIMED);
}

dev_info_t *
get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip = rdip;

	for (; ddi_get_parent(cdip) != dip; cdip = ddi_get_parent(cdip))
		;

	return (cdip);
}

static struct {
	kstat_named_t pciintr_ks_name;
	kstat_named_t pciintr_ks_type;
	kstat_named_t pciintr_ks_cpu;
	kstat_named_t pciintr_ks_pil;
	kstat_named_t pciintr_ks_time;
	kstat_named_t pciintr_ks_ino;
	kstat_named_t pciintr_ks_cookie;
	kstat_named_t pciintr_ks_devpath;
	kstat_named_t pciintr_ks_buspath;
} pciintr_ks_template = {
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
static uint32_t pciintr_ks_instance;
static char ih_devpath[MAXPATHLEN];
static char ih_buspath[MAXPATHLEN];

kmutex_t pciintr_ks_template_lock;

int
pci_ks_update(kstat_t *ksp, int rw)
{
	ih_t		*ih_p = ksp->ks_private;
	int	maxlen = sizeof (pciintr_ks_template.pciintr_ks_name.value.c);
	ib_ino_pil_t	*ipil_p = ih_p->ih_ipil_p;
	ib_ino_info_t	*ino_p = ipil_p->ipil_ino_p;
	ib_t		*ib_p = ino_p->ino_ib_p;
	pci_t		*pci_p = ib_p->ib_pci_p;
	ib_ino_t	ino;

	ino = ino_p->ino_ino;

	(void) snprintf(pciintr_ks_template.pciintr_ks_name.value.c, maxlen,
	    "%s%d", ddi_driver_name(ih_p->ih_dip),
	    ddi_get_instance(ih_p->ih_dip));

	(void) ddi_pathname(ih_p->ih_dip, ih_devpath);
	(void) ddi_pathname(pci_p->pci_dip, ih_buspath);
	kstat_named_setstr(&pciintr_ks_template.pciintr_ks_devpath, ih_devpath);
	kstat_named_setstr(&pciintr_ks_template.pciintr_ks_buspath, ih_buspath);

	if (ih_p->ih_intr_state == PCI_INTR_STATE_ENABLE) {
		(void) strcpy(pciintr_ks_template.pciintr_ks_type.value.c,
		    "fixed");
		pciintr_ks_template.pciintr_ks_cpu.value.ui64 =
		    ino_p->ino_cpuid;
		pciintr_ks_template.pciintr_ks_pil.value.ui64 =
		    ipil_p->ipil_pil;
		pciintr_ks_template.pciintr_ks_time.value.ui64 = ih_p->ih_nsec +
		    (uint64_t)tick2ns((hrtime_t)ih_p->ih_ticks,
		    ino_p->ino_cpuid);
		pciintr_ks_template.pciintr_ks_ino.value.ui64 = ino;
		pciintr_ks_template.pciintr_ks_cookie.value.ui64 =
		    IB_INO_TO_MONDO(ib_p, ino);
	} else {
		(void) strcpy(pciintr_ks_template.pciintr_ks_type.value.c,
		    "disabled");
		pciintr_ks_template.pciintr_ks_cpu.value.ui64 = 0;
		pciintr_ks_template.pciintr_ks_pil.value.ui64 = 0;
		pciintr_ks_template.pciintr_ks_time.value.ui64 = 0;
		pciintr_ks_template.pciintr_ks_ino.value.ui64 = 0;
		pciintr_ks_template.pciintr_ks_cookie.value.ui64 = 0;
	}

	return (0);
}

int
pci_add_intr(dev_info_t *dip, dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp)
{
	pci_t		*pci_p = get_pci_soft_state(ddi_get_instance(dip));
	ib_t		*ib_p = pci_p->pci_ib_p;
	cb_t		*cb_p = pci_p->pci_cb_p;
	ih_t		*ih_p;
	ib_ino_t	ino;
	ib_ino_info_t	*ino_p;	/* pulse interrupts have no ino */
	ib_ino_pil_t	*ipil_p, *ipil_list;
	ib_mondo_t	mondo;
	uint32_t	cpu_id;
	int		ret;
	int32_t		weight;

	ino = IB_MONDO_TO_INO(hdlp->ih_vector);

	DEBUG3(DBG_A_INTX, dip, "pci_add_intr: rdip=%s%d ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), ino);

	if (ino > ib_p->ib_max_ino) {
		DEBUG1(DBG_A_INTX, dip, "ino %x is invalid\n", ino);
		return (DDI_INTR_NOTFOUND);
	}

	if (hdlp->ih_vector & PCI_PULSE_INO) {
		volatile uint64_t *map_reg_addr;
		map_reg_addr = ib_intr_map_reg_addr(ib_p, ino);

		mondo = pci_xlate_intr(dip, rdip, ib_p, ino);
		if (mondo == 0)
			goto fail1;

		hdlp->ih_vector = CB_MONDO_TO_XMONDO(cb_p, mondo);

		if (i_ddi_add_ivintr(hdlp) != DDI_SUCCESS)
			goto fail1;

		/*
		 * Select cpu and program.
		 *
		 * Since there is no good way to always derive cpuid in
		 * pci_remove_intr for PCI_PULSE_INO (esp. for STARFIRE), we
		 * don't add (or remove) device weight for pulsed interrupt
		 * sources.
		 */
		mutex_enter(&ib_p->ib_intr_lock);
		cpu_id = intr_dist_cpuid();
		*map_reg_addr = ib_get_map_reg(mondo, cpu_id);
		mutex_exit(&ib_p->ib_intr_lock);
		*map_reg_addr;	/* flush previous write */
		goto done;
	}

	if ((mondo = pci_xlate_intr(dip, rdip, pci_p->pci_ib_p, ino)) == 0)
		goto fail1;

	ino = IB_MONDO_TO_INO(mondo);

	mutex_enter(&ib_p->ib_ino_lst_mutex);
	ih_p = ib_alloc_ih(rdip, hdlp->ih_inum,
	    hdlp->ih_cb_func, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);
	if (map_pcidev_cfg_reg(dip, rdip, &ih_p->ih_config_handle))
		goto fail2;

	ino_p = ib_locate_ino(ib_p, ino);
	ipil_list = ino_p ? ino_p->ino_ipil_p:NULL;

	/* Sharing ino */
	if (ino_p && (ipil_p = ib_ino_locate_ipil(ino_p, hdlp->ih_pri))) {
		if (ib_intr_locate_ih(ipil_p, rdip, hdlp->ih_inum)) {
			DEBUG1(DBG_A_INTX, dip, "dup intr #%d\n",
			    hdlp->ih_inum);
			goto fail3;
		}

		/* add weight to the cpu that we are already targeting */
		cpu_id = ino_p->ino_cpuid;
		weight = pci_class_to_intr_weight(rdip);
		intr_dist_cpuid_add_device_weight(cpu_id, rdip, weight);

		ib_ino_add_intr(pci_p, ipil_p, ih_p);
		goto ino_done;
	}

	if (hdlp->ih_pri == 0)
		hdlp->ih_pri = pci_class_to_pil(rdip);

	ipil_p = ib_new_ino_pil(ib_p, ino, hdlp->ih_pri, ih_p);
	ino_p = ipil_p->ipil_ino_p;

	hdlp->ih_vector = CB_MONDO_TO_XMONDO(cb_p, mondo);

	/* Store this global mondo */
	ino_p->ino_mondo = hdlp->ih_vector;

	DEBUG2(DBG_A_INTX, dip, "pci_add_intr:  pil=0x%x mondo=0x%x\n",
	    hdlp->ih_pri, hdlp->ih_vector);

	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
	    (ddi_intr_handler_t *)pci_intr_wrapper, (caddr_t)ipil_p, NULL);

	ret = i_ddi_add_ivintr(hdlp);

	/*
	 * Restore original interrupt handler
	 * and arguments in interrupt handle.
	 */
	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp, ih_p->ih_handler,
	    ih_p->ih_handler_arg1, ih_p->ih_handler_arg2);

	if (ret != DDI_SUCCESS)
		goto fail4;

	/* Save the pil for this ino */
	ipil_p->ipil_pil = hdlp->ih_pri;

	/* clear and enable interrupt */
	IB_INO_INTR_CLEAR(ino_p->ino_clr_reg);

	/*
	 * Select cpu and compute weight, saving both for sharing and removal.
	 */
	if (ipil_list == NULL)
		ino_p->ino_cpuid = pci_intr_dist_cpuid(ib_p, ino_p);

	cpu_id = ino_p->ino_cpuid;
	ino_p->ino_established = 1;
	weight = pci_class_to_intr_weight(rdip);
	intr_dist_cpuid_add_device_weight(cpu_id, rdip, weight);

	if (!ipil_list) {
		*ino_p->ino_map_reg = ib_get_map_reg(mondo, cpu_id);
		*ino_p->ino_map_reg;
	}
ino_done:
	hdlp->ih_target = ino_p->ino_cpuid;
	ih_p->ih_ipil_p = ipil_p;
	ih_p->ih_ksp = kstat_create("pci_intrs",
	    atomic_inc_32_nv(&pciintr_ks_instance), "config", "interrupts",
	    KSTAT_TYPE_NAMED,
	    sizeof (pciintr_ks_template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (ih_p->ih_ksp != NULL) {
		ih_p->ih_ksp->ks_data_size += MAXPATHLEN * 2;
		ih_p->ih_ksp->ks_lock = &pciintr_ks_template_lock;
		ih_p->ih_ksp->ks_data = &pciintr_ks_template;
		ih_p->ih_ksp->ks_private = ih_p;
		ih_p->ih_ksp->ks_update = pci_ks_update;
		kstat_install(ih_p->ih_ksp);
	}
	ib_ino_map_reg_share(ib_p, ino, ino_p);
	mutex_exit(&ib_p->ib_ino_lst_mutex);
done:
	DEBUG2(DBG_A_INTX, dip, "done! Interrupt 0x%x pil=%x\n",
	    hdlp->ih_vector, hdlp->ih_pri);
	return (DDI_SUCCESS);
fail4:
	ib_delete_ino_pil(ib_p, ipil_p);
fail3:
	if (ih_p->ih_config_handle)
		pci_config_teardown(&ih_p->ih_config_handle);
fail2:
	mutex_exit(&ib_p->ib_ino_lst_mutex);
	kmem_free(ih_p, sizeof (ih_t));
fail1:
	DEBUG2(DBG_A_INTX, dip, "Failed! Interrupt 0x%x pil=%x\n",
	    hdlp->ih_vector, hdlp->ih_pri);
	return (DDI_FAILURE);
}

int
pci_remove_intr(dev_info_t *dip, dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp)
{
	pci_t		*pci_p = get_pci_soft_state(ddi_get_instance(dip));
	ib_t		*ib_p = pci_p->pci_ib_p;
	cb_t		*cb_p = pci_p->pci_cb_p;
	ib_ino_t	ino;
	ib_mondo_t	mondo;
	ib_ino_info_t	*ino_p;	/* non-pulse only */
	ib_ino_pil_t	*ipil_p; /* non-pulse only */
	ih_t		*ih_p;	/* non-pulse only */

	ino = IB_MONDO_TO_INO(hdlp->ih_vector);

	DEBUG3(DBG_R_INTX, dip, "pci_rem_intr: rdip=%s%d ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), ino);

	if (hdlp->ih_vector & PCI_PULSE_INO) { /* pulse interrupt */
		volatile uint64_t *map_reg_addr;

		/*
		 * No weight was added by pci_add_intr for PCI_PULSE_INO
		 * because it is difficult to determine cpuid here.
		 */
		map_reg_addr = ib_intr_map_reg_addr(ib_p, ino);
		IB_INO_INTR_RESET(map_reg_addr);	/* disable intr */
		*map_reg_addr;

		mondo = pci_xlate_intr(dip, rdip, ib_p, ino);
		if (mondo == 0) {
			DEBUG1(DBG_R_INTX, dip,
			    "can't get mondo for ino %x\n", ino);
			return (DDI_FAILURE);
		}

		if (hdlp->ih_pri == 0)
			hdlp->ih_pri = pci_class_to_pil(rdip);

		hdlp->ih_vector = CB_MONDO_TO_XMONDO(cb_p, mondo);

		DEBUG2(DBG_R_INTX, dip, "pci_rem_intr: pil=0x%x mondo=0x%x\n",
		    hdlp->ih_pri, hdlp->ih_vector);

		i_ddi_rem_ivintr(hdlp);

		DEBUG2(DBG_R_INTX, dip, "pulse success mondo=%x reg=%p\n",
		    mondo, map_reg_addr);
		return (DDI_SUCCESS);
	}

	/* Translate the interrupt property */
	mondo = pci_xlate_intr(dip, rdip, pci_p->pci_ib_p, ino);
	if (mondo == 0) {
		DEBUG1(DBG_R_INTX, dip, "can't get mondo for ino %x\n", ino);
		return (DDI_FAILURE);
	}
	ino = IB_MONDO_TO_INO(mondo);

	mutex_enter(&ib_p->ib_ino_lst_mutex);
	ino_p = ib_locate_ino(ib_p, ino);
	if (!ino_p) {
		int r = cb_remove_xintr(pci_p, dip, rdip, ino, mondo);
		if (r != DDI_SUCCESS)
			cmn_err(CE_WARN, "%s%d-xintr: ino %x is invalid",
			    ddi_driver_name(dip), ddi_get_instance(dip), ino);
		mutex_exit(&ib_p->ib_ino_lst_mutex);
		return (r);
	}

	ipil_p = ib_ino_locate_ipil(ino_p, hdlp->ih_pri);
	ih_p = ib_intr_locate_ih(ipil_p, rdip, hdlp->ih_inum);
	ib_ino_rem_intr(pci_p, ipil_p, ih_p);
	intr_dist_cpuid_rem_device_weight(ino_p->ino_cpuid, rdip);
	if (ipil_p->ipil_ih_size == 0) {
		IB_INO_INTR_PEND(ib_clear_intr_reg_addr(ib_p, ino));
		hdlp->ih_vector = CB_MONDO_TO_XMONDO(cb_p, mondo);

		i_ddi_rem_ivintr(hdlp);
		ib_delete_ino_pil(ib_p, ipil_p);
	}

	/* re-enable interrupt only if mapping register still shared */
	if (ib_ino_map_reg_unshare(ib_p, ino, ino_p) || ino_p->ino_ipil_size) {
		IB_INO_INTR_ON(ino_p->ino_map_reg);
		*ino_p->ino_map_reg;
	}
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	if (ino_p->ino_ipil_size == 0)
		kmem_free(ino_p, sizeof (ib_ino_info_t));

	DEBUG1(DBG_R_INTX, dip, "success! mondo=%x\n", mondo);
	return (DDI_SUCCESS);
}

/*
 * free the pci_inos array allocated during pci_intr_setup. the actual
 * interrupts are torn down by their respective block destroy routines:
 * cb_destroy, pbm_destroy, and ib_destroy.
 */
void
pci_intr_teardown(pci_t *pci_p)
{
	kmem_free(pci_p->pci_inos, pci_p->pci_inos_len);
	pci_p->pci_inos = NULL;
	pci_p->pci_inos_len = 0;
}
