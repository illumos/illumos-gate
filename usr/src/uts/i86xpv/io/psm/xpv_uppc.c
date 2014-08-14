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

#define	PSMI_1_7

#include <sys/mutex.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/clock.h>
#include <sys/machlock.h>
#include <sys/smp_impldefs.h>
#include <sys/uadmin.h>
#include <sys/promif.h>
#include <sys/psm.h>
#include <sys/psm_common.h>
#include <sys/atomic.h>
#include <sys/archsystm.h>
#include <sys/mach_intr.h>
#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#include <sys/modctl.h>
#include <sys/trap.h>
#include <sys/panic.h>

#include <xen/public/vcpu.h>
#include <xen/public/physdev.h>


/*
 * Global Data
 */
int xen_uppc_use_acpi = 1;	/* Use ACPI by default */
int xen_uppc_enable_acpi = 0;

static int xen_clock_irq = -1;

/*
 * For interrupt link devices, if xen_uppc_unconditional_srs is set, an irq
 * resource will be assigned (via _SRS). If it is not set, use the current
 * irq setting (via _CRS), but only if that irq is in the set of possible
 * irqs (returned by _PRS) for the device.
 */
int xen_uppc_unconditional_srs = 1;

/*
 * For interrupt link devices, if xen_uppc_prefer_crs is set when we are
 * assigning an IRQ resource to a device, prefer the current IRQ setting
 * over other possible irq settings under same conditions.
 */
int xen_uppc_prefer_crs = 1;

int xen_uppc_verbose = 0;

/* flag definitions for xen_uppc_verbose */
#define	XEN_UPPC_VERBOSE_IRQ_FLAG		0x00000001
#define	XEN_UPPC_VERBOSE_POWEROFF_FLAG		0x00000002
#define	XEN_UPPC_VERBOSE_POWEROFF_PAUSE_FLAG	0x00000004

#define	XEN_UPPC_VERBOSE_IRQ(fmt) \
	if (xen_uppc_verbose & XEN_UPPC_VERBOSE_IRQ_FLAG) \
		cmn_err fmt;

#define	XEN_UPPC_VERBOSE_POWEROFF(fmt) \
	if (xen_uppc_verbose & XEN_UPPC_VERBOSE_POWEROFF_FLAG) \
		prom_printf fmt;

uchar_t xen_uppc_reserved_irqlist[MAX_ISA_IRQ + 1];

static uint16_t xen_uppc_irq_shared_table[MAX_ISA_IRQ + 1];

/*
 * Contains SCI irqno from FADT after initialization
 */
static int xen_uppc_sci = -1;

static struct psm_info xen_uppc_info;

/*
 * Local support routines
 */

static int
xen_uppc_init_acpi(void)
{
	int verboseflags = 0;
	int	sci;
	iflag_t sci_flags;

	/*
	 * Process SCI configuration here; this may return
	 * an error if acpi-user-options has specified
	 * legacy mode (use ACPI without ACPI mode or SCI)
	 */
	if (acpica_get_sci(&sci, &sci_flags) != AE_OK)
		sci = -1;

	/*
	 * Initialize sub-system - if error is returns, ACPI is not
	 * used.
	 */
	if (acpica_init() != AE_OK)
		return (0);

	/*
	 * uppc implies system is in PIC mode; set edge/level
	 * via ELCR based on return value from get_sci; this
	 * will default to level/low if no override present,
	 * as recommended by Intel ACPI CA team.
	 */
	if (sci >= 0) {
		ASSERT((sci_flags.intr_el == INTR_EL_LEVEL) ||
		    (sci_flags.intr_el == INTR_EL_EDGE));

		psm_set_elcr(sci, sci_flags.intr_el == INTR_EL_LEVEL);
	}

	/*
	 * Remember SCI for later use
	 */
	xen_uppc_sci = sci;

	if (xen_uppc_verbose & XEN_UPPC_VERBOSE_IRQ_FLAG)
		verboseflags |= PSM_VERBOSE_IRQ_FLAG;

	if (xen_uppc_verbose & XEN_UPPC_VERBOSE_POWEROFF_FLAG)
		verboseflags |= PSM_VERBOSE_POWEROFF_FLAG;

	if (xen_uppc_verbose & XEN_UPPC_VERBOSE_POWEROFF_PAUSE_FLAG)
		verboseflags |= PSM_VERBOSE_POWEROFF_PAUSE_FLAG;

	if (acpi_psm_init(xen_uppc_info.p_mach_idstring, verboseflags) ==
	    ACPI_PSM_FAILURE) {
		return (0);
	}

	return (1);
}

/*
 * Autoconfiguration Routines
 */

static int
xen_uppc_probe(void)
{

	return (PSM_SUCCESS);
}

static void
xen_uppc_softinit(void)
{
	int i;

	/* LINTED logical expression always true: op "||" */
	ASSERT((1 << EVTCHN_SHIFT) == NBBY * sizeof (ulong_t));
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		if (xen_uppc_use_acpi && xen_uppc_init_acpi()) {
			build_reserved_irqlist((uchar_t *)
			    xen_uppc_reserved_irqlist);
			for (i = 0; i <= MAX_ISA_IRQ; i++)
				xen_uppc_irq_shared_table[i] = 0;
			xen_uppc_enable_acpi = 1;
		}
	}
}


#define	XEN_NSEC_PER_TICK	10 /* XXX - assume we have a 100 Mhz clock */

/*ARGSUSED*/
static int
xen_uppc_clkinit(int hertz)
{
	extern enum tod_fault_type tod_fault(enum tod_fault_type, int);
	extern int dosynctodr;

	/*
	 * domU cannot set the TOD hardware, fault the TOD clock now to
	 * indicate that and turn off attempts to sync TOD hardware
	 * with the hires timer.
	 */
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		mutex_enter(&tod_lock);
		(void) tod_fault(TOD_RDONLY, 0);
		dosynctodr = 0;
		mutex_exit(&tod_lock);
	}
	/*
	 * The hypervisor provides a timer based on the local APIC timer.
	 * The interface supports requests of nanosecond resolution.
	 * A common frequency of the apic clock is 100 Mhz which
	 * gives a resolution of 10 nsec per tick.  What we would really like
	 * is a way to get the ns per tick value from xen.
	 * XXPV - This is an assumption that needs checking and may change
	 */
	return (XEN_NSEC_PER_TICK);
}

static void
xen_uppc_picinit()
{
	int irqno;

	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
#if 0
		/* hypervisor initializes the 8259, don't mess with it */
		picsetup();	 /* initialise the 8259 */
#endif
		/*
		 * We never called xen_uppc_addspl() when the SCI
		 * interrupt was added because that happened before the
		 * PSM module was loaded.  Fix that up here by doing
		 * any missed operations (e.g. bind to CPU)
		 */
		if ((irqno = xen_uppc_sci) >= 0) {
			ec_enable_irq(irqno);
		}
	}
}


/*ARGSUSED*/
static int
xen_uppc_addspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	int ret = PSM_SUCCESS;
	cpuset_t cpus;

	if (irqno >= 0 && irqno <= MAX_ISA_IRQ)
		atomic_inc_16(&xen_uppc_irq_shared_table[irqno]);

	/*
	 * We are called at splhi() so we can't call anything that might end
	 * up trying to context switch.
	 */
	if (irqno >= PIRQ_BASE && irqno < NR_PIRQS &&
	    DOMAIN_IS_INITDOMAIN(xen_info)) {
		CPUSET_ZERO(cpus);
		CPUSET_ADD(cpus, 0);
		ec_setup_pirq(irqno, ipl, &cpus);
	} else {
		/*
		 * Set priority/affinity/enable for non PIRQs
		 */
		ret = ec_set_irq_priority(irqno, ipl);
		ASSERT(ret == 0);
		CPUSET_ZERO(cpus);
		CPUSET_ADD(cpus, 0);
		ec_set_irq_affinity(irqno, cpus);
		ec_enable_irq(irqno);
	}

	return (ret);
}

/*ARGSUSED*/
static int
xen_uppc_delspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	int err = PSM_SUCCESS;

	if (irqno >= 0 && irqno <= MAX_ISA_IRQ)
		atomic_dec_16(&xen_uppc_irq_shared_table[irqno]);

	if (irqno >= PIRQ_BASE && irqno < NR_PIRQS &&
	    DOMAIN_IS_INITDOMAIN(xen_info)) {
		if (max_ipl == PSM_INVALID_IPL) {
			/*
			 * unbind if no more sharers of this irq/evtchn
			 */
			(void) ec_block_irq(irqno);
			ec_unbind_irq(irqno);
		} else {
			/*
			 * If still in use reset priority
			 */
			err = ec_set_irq_priority(irqno, max_ipl);
		}
	} else {
		(void) ec_block_irq(irqno);
		ec_unbind_irq(irqno);
	}
	return (err);
}

static processorid_t
xen_uppc_get_next_processorid(processorid_t id)
{
	if (id == -1)
		return (0);
	return (-1);
}

/*ARGSUSED*/
static int
xen_uppc_get_clockirq(int ipl)
{
	if (xen_clock_irq != -1)
		return (xen_clock_irq);

	xen_clock_irq = ec_bind_virq_to_irq(VIRQ_TIMER, 0);
	return (xen_clock_irq);
}

/*ARGSUSED*/
static void
xen_uppc_shutdown(int cmd, int fcn)
{
	XEN_UPPC_VERBOSE_POWEROFF(("xen_uppc_shutdown(%d,%d);\n", cmd, fcn));

	switch (cmd) {
	case A_SHUTDOWN:
		switch (fcn) {
		case AD_BOOT:
		case AD_IBOOT:
			(void) HYPERVISOR_shutdown(SHUTDOWN_reboot);
			break;
		case AD_POWEROFF:
			/* fall through if domU or if poweroff fails */
			if (DOMAIN_IS_INITDOMAIN(xen_info))
				if (xen_uppc_enable_acpi)
					(void) acpi_poweroff();
			/* FALLTHRU */
		case AD_HALT:
		default:
			(void) HYPERVISOR_shutdown(SHUTDOWN_poweroff);
			break;
		}
		break;
	case A_REBOOT:
		(void) HYPERVISOR_shutdown(SHUTDOWN_reboot);
		break;
	default:
		return;
	}
}


/*
 * This function will reprogram the timer.
 *
 * When in oneshot mode the argument is the absolute time in future at which to
 * generate the interrupt.
 *
 * When in periodic mode, the argument is the interval at which the
 * interrupts should be generated. There is no need to support the periodic
 * mode timer change at this time.
 *
 * Note that we must be careful to convert from hrtime to Xen system time (see
 * xpv_timestamp.c).
 */
static void
xen_uppc_timer_reprogram(hrtime_t timer_req)
{
	hrtime_t now, timer_new, time_delta, xen_time;
	ulong_t flags;

	flags = intr_clear();
	/*
	 * We should be called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */

	now = xpv_gethrtime();
	xen_time = xpv_getsystime();
	if (timer_req <= now) {
		/*
		 * requested to generate an interrupt in the past
		 * generate an interrupt as soon as possible
		 */
		time_delta = XEN_NSEC_PER_TICK;
	} else
		time_delta = timer_req - now;

	timer_new = xen_time + time_delta;
	if (HYPERVISOR_set_timer_op(timer_new) != 0)
		panic("can't set hypervisor timer?");
	intr_restore(flags);
}

/*
 * This function will enable timer interrupts.
 */
static void
xen_uppc_timer_enable(void)
{
	ec_unmask_irq(xen_clock_irq);
}

/*
 * This function will disable timer interrupts on the current cpu.
 */
static void
xen_uppc_timer_disable(void)
{
	(void) ec_block_irq(xen_clock_irq);
	/*
	 * If the clock irq is pending on this cpu then we need to
	 * clear the pending interrupt.
	 */
	ec_unpend_irq(xen_clock_irq);
}


/*
 * Configures the irq for the interrupt link device identified by
 * acpipsmlnkp.
 *
 * Gets the current and the list of possible irq settings for the
 * device. If xen_uppc_unconditional_srs is not set, and the current
 * resource setting is in the list of possible irq settings,
 * current irq resource setting is passed to the caller.
 *
 * Otherwise, picks an irq number from the list of possible irq
 * settings, and sets the irq of the device to this value.
 * If prefer_crs is set, among a set of irq numbers in the list that have
 * the least number of devices sharing the interrupt, we pick current irq
 * resource setting if it is a member of this set.
 *
 * Passes the irq number in the value pointed to by pci_irqp, and
 * polarity and sensitivity in the structure pointed to by dipintrflagp
 * to the caller.
 *
 * Note that if setting the irq resource failed, but successfuly obtained
 * the current irq resource settings, passes the current irq resources
 * and considers it a success.
 *
 * Returns:
 * ACPI_PSM_SUCCESS on success.
 *
 * ACPI_PSM_FAILURE if an error occured during the configuration or
 * if a suitable irq was not found for this device, or if setting the
 * irq resource and obtaining the current resource fails.
 *
 */
static int
xen_uppc_acpi_irq_configure(acpi_psm_lnk_t *acpipsmlnkp, dev_info_t *dip,
    int *pci_irqp, iflag_t *dipintr_flagp)
{
	int i, min_share, foundnow, done = 0;
	int32_t irq;
	int32_t share_irq = -1;
	int32_t chosen_irq = -1;
	int cur_irq = -1;
	acpi_irqlist_t *irqlistp;
	acpi_irqlist_t *irqlistent;

	if ((acpi_get_possible_irq_resources(acpipsmlnkp, &irqlistp))
	    == ACPI_PSM_FAILURE) {
		XEN_UPPC_VERBOSE_IRQ((CE_WARN, "!xVM_uppc: Unable to determine "
		    "or assign IRQ for device %s, instance #%d: The system was "
		    "unable to get the list of potential IRQs from ACPI.",
		    ddi_get_name(dip), ddi_get_instance(dip)));

		return (ACPI_PSM_FAILURE);
	}

	if ((acpi_get_current_irq_resource(acpipsmlnkp, &cur_irq,
	    dipintr_flagp) == ACPI_PSM_SUCCESS) &&
	    (!xen_uppc_unconditional_srs) &&
	    (cur_irq > 0)) {

		if (acpi_irqlist_find_irq(irqlistp, cur_irq, NULL)
		    == ACPI_PSM_SUCCESS) {

			acpi_free_irqlist(irqlistp);
			ASSERT(pci_irqp != NULL);
			*pci_irqp = cur_irq;
			return (ACPI_PSM_SUCCESS);
		}
		XEN_UPPC_VERBOSE_IRQ((CE_WARN, "!xVM_uppc: Could not find the "
		    "current irq %d for device %s, instance #%d in ACPI's "
		    "list of possible irqs for this device. Picking one from "
		    " the latter list.", cur_irq, ddi_get_name(dip),
		    ddi_get_instance(dip)));

	}

	irqlistent = irqlistp;
	min_share = 255;

	while (irqlistent != NULL) {

		for (foundnow = 0, i = 0; i < irqlistent->num_irqs; i++) {

			irq = irqlistp->irqs[i];

			if ((irq > MAX_ISA_IRQ) ||
			    (irqlistent->intr_flags.intr_el == INTR_EL_EDGE) ||
			    (irq == 0))
				continue;

			if (xen_uppc_reserved_irqlist[irq])
				continue;

			if (xen_uppc_irq_shared_table[irq] == 0) {
				chosen_irq = irq;
				foundnow = 1;
				if (!(xen_uppc_prefer_crs) ||
				    (irq == cur_irq)) {
					done = 1;
					break;
				}
			}

			if ((xen_uppc_irq_shared_table[irq] < min_share) ||
			    ((xen_uppc_irq_shared_table[irq] == min_share) &&
			    (cur_irq == irq) && (xen_uppc_prefer_crs))) {
				min_share = xen_uppc_irq_shared_table[irq];
				share_irq = irq;
				foundnow = 1;
			}
		}

		/* If we found an IRQ in the inner loop, save the details */
		if (foundnow && ((chosen_irq != -1) || (share_irq != -1))) {
			/*
			 * Copy the acpi_prs_private_t and flags from this
			 * irq list entry, since we found an irq from this
			 * entry.
			 */
			acpipsmlnkp->acpi_prs_prv = irqlistent->acpi_prs_prv;
			*dipintr_flagp = irqlistent->intr_flags;
		}

		if (done)
			break;

		/* Load the next entry in the irqlist */
		irqlistent = irqlistent->next;
	}

	acpi_free_irqlist(irqlistp);

	if (chosen_irq != -1)
		irq = chosen_irq;
	else if (share_irq != -1)
		irq = share_irq;
	else {
		XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: Could not find a "
		    "suitable irq from the list of possible irqs for device "
		    "%s, instance #%d in ACPI's list of possible\n",
		    ddi_get_name(dip), ddi_get_instance(dip)));

		return (ACPI_PSM_FAILURE);
	}


	XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: Setting irq %d "
	    "for device %s instance #%d\n", irq, ddi_get_name(dip),
	    ddi_get_instance(dip)));

	if ((acpi_set_irq_resource(acpipsmlnkp, irq)) == ACPI_PSM_SUCCESS) {
		/*
		 * setting irq was successful, check to make sure CRS
		 * reflects that. If CRS does not agree with what we
		 * set, return the irq that was set.
		 */

		if (acpi_get_current_irq_resource(acpipsmlnkp, &cur_irq,
		    dipintr_flagp) == ACPI_PSM_SUCCESS) {

			if (cur_irq != irq)
				XEN_UPPC_VERBOSE_IRQ((CE_WARN, "!xVM_uppc: "
				    "IRQ resource set (irqno %d) for device %s "
				    "instance #%d, differs from current "
				    "setting irqno %d",
				    irq, ddi_get_name(dip),
				    ddi_get_instance(dip), cur_irq));
		}
		/*
		 * return the irq that was set, and not what CRS reports,
		 * since CRS has been seen to be bogus on some systems
		 */
		cur_irq = irq;
	} else {
		XEN_UPPC_VERBOSE_IRQ((CE_WARN, "!xVM_uppc: set resource irq %d "
		    "failed for device %s instance #%d",
		    irq, ddi_get_name(dip), ddi_get_instance(dip)));
		if (cur_irq == -1)
			return (ACPI_PSM_FAILURE);
	}

	ASSERT(pci_irqp != NULL);
	*pci_irqp = cur_irq;
	return (ACPI_PSM_SUCCESS);
}


static int
xen_uppc_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp)
{
	int status;
	acpi_psm_lnk_t acpipsmlnk;

	if ((status = acpi_get_irq_cache_ent(busid, devid, ipin, pci_irqp,
	    intr_flagp)) == ACPI_PSM_SUCCESS) {
		XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: Found irqno %d "
		    "from cache for device %s, instance #%d\n", *pci_irqp,
		    ddi_get_name(dip), ddi_get_instance(dip)));
		return (status);
	}

	bzero(&acpipsmlnk, sizeof (acpi_psm_lnk_t));

	if ((status = acpi_translate_pci_irq(dip, ipin, pci_irqp,
	    intr_flagp, &acpipsmlnk)) == ACPI_PSM_FAILURE) {
		XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: "
		    " acpi_translate_pci_irq failed for device %s, instance"
		    " #%d\n", ddi_get_name(dip), ddi_get_instance(dip)));

		return (status);
	}

	if (status == ACPI_PSM_PARTIAL && acpipsmlnk.lnkobj != NULL) {
		status = xen_uppc_acpi_irq_configure(&acpipsmlnk, dip, pci_irqp,
		    intr_flagp);
		if (status != ACPI_PSM_SUCCESS) {
			status = acpi_get_current_irq_resource(&acpipsmlnk,
			    pci_irqp, intr_flagp);
		}
	}

	if (status == ACPI_PSM_SUCCESS) {
		acpi_new_irq_cache_ent(busid, devid, ipin, *pci_irqp,
		    intr_flagp, &acpipsmlnk);
		psm_set_elcr(*pci_irqp, 1); 	/* set IRQ to PCI mode */

		XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: [ACPI] "
		    "new irq %d for device %s, instance #%d\n",
		    *pci_irqp, ddi_get_name(dip), ddi_get_instance(dip)));
	}

	return (status);
}


/*ARGSUSED*/
static int
xen_uppc_translate_irq(dev_info_t *dip, int irqno)
{
	char dev_type[16];
	int dev_len, pci_irq, devid, busid;
	ddi_acc_handle_t cfg_handle;
	uchar_t ipin, iline;
	iflag_t intr_flag;

	if (dip == NULL) {
		XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: irqno = %d"
		    " dip = NULL\n", irqno));
		return (irqno);
	}

	if (!xen_uppc_enable_acpi) {
		return (irqno);
	}

	dev_len = sizeof (dev_type);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device_type", (caddr_t)dev_type,
	    &dev_len) != DDI_PROP_SUCCESS) {
		XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: irqno %d"
		    " device %s instance %d no device_type\n", irqno,
		    ddi_get_name(dip), ddi_get_instance(dip)));
		return (irqno);
	}

	if ((strcmp(dev_type, "pci") == 0) ||
	    (strcmp(dev_type, "pciex") == 0)) {

		/* pci device */
		if (acpica_get_bdf(dip, &busid, &devid, NULL) != 0)
			return (irqno);

		if (pci_config_setup(dip, &cfg_handle) != DDI_SUCCESS)
			return (irqno);

		ipin = pci_config_get8(cfg_handle, PCI_CONF_IPIN) - PCI_INTA;
		iline = pci_config_get8(cfg_handle, PCI_CONF_ILINE);
		if (xen_uppc_acpi_translate_pci_irq(dip, busid, devid,
		    ipin, &pci_irq, &intr_flag) == ACPI_PSM_SUCCESS) {

			XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: [ACPI] "
			    "new irq %d old irq %d device %s, instance %d\n",
			    pci_irq, irqno, ddi_get_name(dip),
			    ddi_get_instance(dip)));

			/*
			 * Make sure pci_irq is within range.
			 * Otherwise, fall through and return irqno.
			 */
			if (pci_irq <= MAX_ISA_IRQ) {
				if (iline != pci_irq) {
					/*
					 * Update the device's ILINE byte,
					 * in case uppc_acpi_translate_pci_irq
					 * has choosen a different pci_irq
					 * than the BIOS has configured.
					 * Some chipsets use the value in
					 * ILINE to control interrupt routing,
					 * in conflict with the PCI spec.
					 */
					pci_config_put8(cfg_handle,
					    PCI_CONF_ILINE, pci_irq);
				}
				pci_config_teardown(&cfg_handle);
				return (pci_irq);
			}
		}
		pci_config_teardown(&cfg_handle);

		/* FALLTHRU to common case - returning irqno */
	} else {
		/* non-PCI; assumes ISA-style edge-triggered */
		psm_set_elcr(irqno, 0); 	/* set IRQ to ISA mode */

		XEN_UPPC_VERBOSE_IRQ((CE_CONT, "!xVM_uppc: non-pci,"
		    "irqno %d device %s instance %d\n", irqno,
		    ddi_get_name(dip), ddi_get_instance(dip)));
	}

	return (irqno);
}

/*
 * xen_uppc_intr_enter() acks the event that triggered the interrupt and
 * returns the new priority level,
 */
/*ARGSUSED*/
static int
xen_uppc_intr_enter(int ipl, int *vector)
{
	int newipl;
	uint_t intno;
	cpu_t *cpu = CPU;

	intno = (*vector);

	ASSERT(intno < NR_IRQS);
	ASSERT(cpu->cpu_m.mcpu_vcpu_info->evtchn_upcall_mask != 0);

	ec_clear_irq(intno);

	newipl = autovect[intno].avh_hi_pri;
	if (newipl == 0) {
		/*
		 * (newipl == 0) means we have no service routines for this
		 * vector.  We will treat this as a spurious interrupt.
		 * We have cleared the pending bit already, clear the event
		 * mask and return a spurious interrupt.  This case can happen
		 * when an interrupt delivery is racing with the removal of
		 * of the service routine for that interrupt.
		 */
		ec_unmask_irq(intno);
		newipl = -1;	/* flag spurious interrupt */
	} else if (newipl <= cpu->cpu_pri) {
		/*
		 * (newipl <= cpu->cpu_pri) means that we must be trying to
		 * service a vector that was shared with a higher priority
		 * isr.  The higher priority handler has been removed and
		 * we need to service this int.  We can't return a lower
		 * priority than current cpu priority.  Just synthesize a
		 * priority to return that should be acceptable.
		 */
		newipl = cpu->cpu_pri + 1;	/* synthetic priority */
	}
	return (newipl);
}


static void xen_uppc_setspl(int);

/*
 * xen_uppc_intr_exit() restores the old interrupt
 * priority level after processing an interrupt.
 * It is called with interrupts disabled, and does not enable interrupts.
 */
/* ARGSUSED */
static void
xen_uppc_intr_exit(int ipl, int vector)
{
	ec_try_unmask_irq(vector);
	xen_uppc_setspl(ipl);
}

intr_exit_fn_t
psm_intr_exit_fn(void)
{
	return (xen_uppc_intr_exit);
}

/*
 * Check if new ipl level allows delivery of previously unserviced events
 */
static void
xen_uppc_setspl(int ipl)
{
	struct cpu *cpu = CPU;
	volatile vcpu_info_t *vci = cpu->cpu_m.mcpu_vcpu_info;
	uint16_t pending;

	ASSERT(vci->evtchn_upcall_mask != 0);

	/*
	 * If new ipl level will enable any pending interrupts, setup so the
	 * upcoming sti will cause us to get an upcall.
	 */
	pending = cpu->cpu_m.mcpu_intr_pending & ~((1 << (ipl + 1)) - 1);
	if (pending) {
		int i;
		ulong_t pending_sels = 0;
		volatile ulong_t *selp;
		struct xen_evt_data *cpe = cpu->cpu_m.mcpu_evt_pend;

		for (i = bsrw_insn(pending); i > ipl; i--)
			pending_sels |= cpe->pending_sel[i];
		ASSERT(pending_sels);
		selp = (volatile ulong_t *)&vci->evtchn_pending_sel;
		atomic_or_ulong(selp, pending_sels);
		vci->evtchn_upcall_pending = 1;
	}
}

/*
 * The rest of the file is just generic psm module boilerplate
 */

static struct psm_ops xen_uppc_ops = {
	xen_uppc_probe,				/* psm_probe		*/

	xen_uppc_softinit,			/* psm_init		*/
	xen_uppc_picinit,			/* psm_picinit		*/
	xen_uppc_intr_enter,			/* psm_intr_enter	*/
	xen_uppc_intr_exit,			/* psm_intr_exit	*/
	xen_uppc_setspl,			/* psm_setspl		*/
	xen_uppc_addspl,			/* psm_addspl		*/
	xen_uppc_delspl,			/* psm_delspl		*/
	(int (*)(processorid_t))NULL,		/* psm_disable_intr	*/
	(void (*)(processorid_t))NULL,		/* psm_enable_intr	*/
	(int (*)(int))NULL,			/* psm_softlvl_to_irq	*/
	(void (*)(int))NULL,			/* psm_set_softintr	*/
	(void (*)(processorid_t))NULL,		/* psm_set_idlecpu	*/
	(void (*)(processorid_t))NULL,		/* psm_unset_idlecpu	*/

	xen_uppc_clkinit,			/* psm_clkinit		*/
	xen_uppc_get_clockirq,			/* psm_get_clockirq	*/
	(void (*)(void))NULL,			/* psm_hrtimeinit	*/
	xpv_gethrtime,				/* psm_gethrtime	*/

	xen_uppc_get_next_processorid,		/* psm_get_next_processorid */
	(int (*)(processorid_t, caddr_t))NULL,	/* psm_cpu_start	*/
	(int (*)(void))NULL,			/* psm_post_cpu_start	*/
	xen_uppc_shutdown,			/* psm_shutdown		*/
	(int (*)(int, int))NULL,		/* psm_get_ipivect	*/
	(void (*)(processorid_t, int))NULL,	/* psm_send_ipi		*/

	xen_uppc_translate_irq,			/* psm_translate_irq	*/

	(void (*)(int, char *))NULL,		/* psm_notify_error	*/
	(void (*)(int msg))NULL,		/* psm_notify_func	*/
	xen_uppc_timer_reprogram,		/* psm_timer_reprogram	*/
	xen_uppc_timer_enable,			/* psm_timer_enable	*/
	xen_uppc_timer_disable,			/* psm_timer_disable	*/
	(void (*)(void *arg))NULL,		/* psm_post_cyclic_setup */
	(void (*)(int, int))NULL,		/* psm_preshutdown	*/

	(int (*)(dev_info_t *, ddi_intr_handle_impl_t *,
	    psm_intr_op_t, int *))NULL,		/* psm_intr_ops		*/
	(int (*)(psm_state_request_t *))NULL,	/* psm_state		*/
	(int (*)(psm_cpu_request_t *))NULL	/* psm_cpu_ops		*/
};

static struct psm_info xen_uppc_info = {
	PSM_INFO_VER01_5,	/* version				*/
	PSM_OWN_SYS_DEFAULT,	/* ownership				*/
	&xen_uppc_ops,		/* operation				*/
	"xVM_uppc",		/* machine name				*/
	"UniProcessor PC"	/* machine descriptions			*/
};

static void *xen_uppc_hdlp;

int
_init(void)
{
	return (psm_mod_init(&xen_uppc_hdlp, &xen_uppc_info));
}

int
_fini(void)
{
	return (psm_mod_fini(&xen_uppc_hdlp, &xen_uppc_info));
}

int
_info(struct modinfo *modinfop)
{
	return (psm_mod_info(&xen_uppc_hdlp, &xen_uppc_info, modinfop));
}
