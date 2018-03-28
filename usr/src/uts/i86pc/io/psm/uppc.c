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
 * Copyright 2018 Joyent, Inc.
 */

#define	PSMI_1_7

#include <sys/mutex.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/machlock.h>
#include <sys/smp_impldefs.h>
#include <sys/uadmin.h>
#include <sys/promif.h>
#include <sys/psm.h>
#include <sys/pit.h>
#include <sys/apic.h>
#include <sys/psm_common.h>
#include <sys/atomic.h>
#include <sys/archsystm.h>

#define	NSEC_IN_SEC		1000000000

/*
 * Local Function Prototypes
 */
static void uppc_softinit(void);
static void uppc_picinit();
static int uppc_post_cpu_start(void);
static int uppc_clkinit(int);
static int uppc_addspl(int irqno, int ipl, int min_ipl, int max_ipl);
static int uppc_delspl(int irqno, int ipl, int min_ipl, int max_ipl);
static processorid_t uppc_get_next_processorid(processorid_t cpu_id);
static int uppc_get_clockirq(int ipl);
static int uppc_probe(void);
static int uppc_translate_irq(dev_info_t *dip, int irqno);
static void uppc_shutdown(int cmd, int fcn);
static void uppc_preshutdown(int cmd, int fcn);
static int uppc_state(psm_state_request_t *request);
static int uppc_init_acpi(void);
static void uppc_setspl(int);
static int uppc_intr_enter(int, int *);
static void uppc_intr_exit(int, int);
static hrtime_t uppc_gethrtime();

static int uppc_acpi_irq_configure(acpi_psm_lnk_t *acpipsmlnkp, dev_info_t *dip,
    int *pci_irqp, iflag_t *intr_flagp);

/*
 * Global Data
 */
static struct standard_pic pics0;
int uppc_use_acpi = 1;	/* Use ACPI by default */
int uppc_enable_acpi = 0;


/*
 * For interrupt link devices, if uppc_unconditional_srs is set, an irq resource
 * will be assigned (via _SRS). If it is not set, use the current
 * irq setting (via _CRS), but only if that irq is in the set of possible
 * irqs (returned by _PRS) for the device.
 */
int uppc_unconditional_srs = 1;

/*
 * For interrupt link devices, if uppc_prefer_crs is set when we are
 * assigning an IRQ resource to a device, prefer the current IRQ setting
 * over other possible irq settings under same conditions.
 */
int uppc_prefer_crs = 1;

int uppc_verbose = 0;

/* flag definitions for uppc_verbose */
#define	UPPC_VERBOSE_IRQ_FLAG			0x00000001
#define	UPPC_VERBOSE_POWEROFF_FLAG		0x00000002
#define	UPPC_VERBOSE_POWEROFF_PAUSE_FLAG	0x00000004


#define	UPPC_VERBOSE_IRQ(fmt) \
	if (uppc_verbose & UPPC_VERBOSE_IRQ_FLAG) \
		cmn_err fmt;

#define	UPPC_VERBOSE_POWEROFF(fmt) \
	if (uppc_verbose & UPPC_VERBOSE_POWEROFF_FLAG) \
		prom_printf fmt;

uchar_t uppc_reserved_irqlist[MAX_ISA_IRQ + 1];

static uint16_t uppc_irq_shared_table[MAX_ISA_IRQ + 1];

/*
 * Contains SCI irqno from FADT after initialization
 */
static int uppc_sci = -1;

/*
 * Local Static Data
 */

static lock_t uppc_gethrtime_lock;
static hrtime_t uppc_lasthrtime;


#ifdef UPPC_DEBUG
#define	DENT	0x0001

static int	uppc_debug = 0;


#endif


static struct	psm_ops uppc_ops = {
	uppc_probe,				/* psm_probe		*/

	uppc_softinit,				/* psm_init		*/
	uppc_picinit,				/* psm_picinit		*/
	uppc_intr_enter,			/* psm_intr_enter	*/
	uppc_intr_exit,				/* psm_intr_exit	*/
	uppc_setspl,				/* psm_setspl		*/
	uppc_addspl,				/* psm_addspl		*/
	uppc_delspl,				/* psm_delspl		*/
	(int (*)(processorid_t))NULL,		/* psm_disable_intr	*/
	(void (*)(processorid_t))NULL,		/* psm_enable_intr	*/
	(int (*)(int))NULL,			/* psm_softlvl_to_irq	*/
	(void (*)(int))NULL,			/* psm_set_softintr	*/
	(void (*)(processorid_t))NULL,		/* psm_set_idlecpu	*/
	(void (*)(processorid_t))NULL,		/* psm_unset_idlecpu	*/

	uppc_clkinit,				/* psm_clkinit		*/
	uppc_get_clockirq,			/* psm_get_clockirq	*/
	(void (*)(void))NULL,			/* psm_hrtimeinit	*/
	uppc_gethrtime,				/* psm_gethrtime	*/

	uppc_get_next_processorid,		/* psm_get_next_processorid */
	(int (*)(processorid_t, caddr_t))NULL,	/* psm_cpu_start	*/
	uppc_post_cpu_start,			/* psm_post_cpu_start	*/
	uppc_shutdown,				/* psm_shutdown		*/
	(int (*)(int, int))NULL,		/* psm_get_ipivect	*/
	(void (*)(processorid_t, int))NULL,	/* psm_send_ipi		*/

	uppc_translate_irq,			/* psm_translate_irq	*/

	(void (*)(int, char *))NULL,		/* psm_notify_error	*/
	(void (*)(int msg))NULL,		/* psm_notify_func	*/
	(void (*)(hrtime_t time))NULL,		/* psm_timer_reprogram	*/
	(void (*)(void))NULL,			/* psm_timer_enable	*/
	(void (*)(void))NULL,			/* psm_timer_disable	*/
	(void (*)(void *arg))NULL,		/* psm_post_cyclic_setup */
	uppc_preshutdown,			/* psm_preshutdown	*/

	(int (*)(dev_info_t *, ddi_intr_handle_impl_t *,
	    psm_intr_op_t, int *))NULL,		/* psm_intr_ops		*/

	uppc_state,				/* psm_state		*/
	(int (*)(psm_cpu_request_t *))NULL,	/* psm_cpu_ops		*/

	(int (*)(void))NULL,			/* psm_get_pir_ipivect	*/
	(void (*)(processorid_t))NULL,		/* psm_send_pir_ipi	*/
};


static struct	psm_info uppc_info = {
	PSM_INFO_VER01_7,	/* version				*/
	PSM_OWN_SYS_DEFAULT,	/* ownership				*/
	(struct psm_ops *)&uppc_ops, /* operation			*/
	"uppc",			/* machine name				*/
	"UniProcessor PC",	/* machine descriptions			*/
};

/*
 * Configuration Data
 */

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

static void *uppc_hdlp;

int
_init(void)
{
	return (psm_mod_init(&uppc_hdlp, &uppc_info));
}

int
_fini(void)
{
	return (psm_mod_fini(&uppc_hdlp, &uppc_info));
}

int
_info(struct modinfo *modinfop)
{
	return (psm_mod_info(&uppc_hdlp, &uppc_info, modinfop));
}

/*
 * Autoconfiguration Routines
 */

static int
uppc_probe(void)
{


	return (PSM_SUCCESS);
}

static void
uppc_softinit(void)
{
	struct standard_pic *pp;
	int i;

	pp = &pics0;


	if (uppc_use_acpi && uppc_init_acpi()) {
		build_reserved_irqlist((uchar_t *)uppc_reserved_irqlist);
		for (i = 0; i <= MAX_ISA_IRQ; i++)
			uppc_irq_shared_table[i] = 0;
		uppc_enable_acpi = 1;
	}

	/*
	 * initialize the ipl mask
	 */
	for (i = 0; i < (MAXIPL << 1); i += 2) {
		/* enable slave lines on master */
		pp->c_iplmask[i] = 0xff;
		pp->c_iplmask[i+1] = (0xff & ~(1 << MASTERLINE));
	}
}

/*ARGSUSED*/
static int
uppc_clkinit(int hertz)
{
	ulong_t clkticks = PIT_HZ / hz;

	if (hertz == 0)
		return (0);	/* One shot mode not supported */

	/*
	 * program timer 0
	 */
	outb(PITCTL_PORT, (PIT_C0|PIT_NDIVMODE|PIT_READMODE));
	outb(PITCTR0_PORT, (uchar_t)clkticks);
	outb(PITCTR0_PORT, (uchar_t)(clkticks>>8));

	return (NSEC_IN_SEC / hertz);
}

static void
uppc_picinit()
{
	picsetup();

	/*
	 * If a valid SCI is present, manually addspl()
	 * since we're not set-up early enough in boot
	 * to do it "conventionally" (via add_avintr)
	 */
	if (uppc_sci >= 0)
		(void) uppc_addspl(uppc_sci, SCI_IPL, SCI_IPL, SCI_IPL);
}

static int
uppc_post_cpu_start(void)
{
	/*
	 * On uppc machines psm_post_cpu_start is called during S3 resume
	 * on the boot cpu from assembly, using the ap_mlsetup vector.
	 */

	/*
	 * Init master and slave pic
	 */
	picsetup();

	/*
	 * program timer 0
	 */
	(void) uppc_clkinit(hz);

	return (PSM_SUCCESS);
}

/*ARGSUSED3*/
static int
uppc_addspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	struct standard_pic *pp;
	int i;
	int startidx;
	uchar_t	vectmask;

	if (irqno <= MAX_ISA_IRQ)
		atomic_inc_16(&uppc_irq_shared_table[irqno]);

	if (ipl != min_ipl)
		return (0);

	if (irqno > 7) {
		vectmask = 1 << (irqno - 8);
		startidx = (ipl << 1);
	} else {
		vectmask = 1 << irqno;
		startidx = (ipl << 1) + 1;
	}

	/*
	 * mask intr same or above ipl
	 * level MAXIPL has all intr off as init. default
	 */
	pp = &pics0;
	for (i = startidx; i < (MAXIPL << 1); i += 2) {
		if (pp->c_iplmask[i] & vectmask)
			break;
		pp->c_iplmask[i] |= vectmask;
	}

	/*
	 * unmask intr below ipl
	 */
	for (i = startidx-2; i >= 0; i -= 2) {
		if (!(pp->c_iplmask[i] & vectmask))
			break;
		pp->c_iplmask[i] &= ~vectmask;
	}
	return (0);
}

static int
uppc_delspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	struct standard_pic *pp;
	int i;
	uchar_t	vectmask;

	if (irqno <= MAX_ISA_IRQ)
		atomic_dec_16(&uppc_irq_shared_table[irqno]);

	/*
	 * skip if we are not deleting the last handler
	 * and the ipl is higher than minimum
	 */
	if ((max_ipl != PSM_INVALID_IPL) && (ipl >= min_ipl))
		return (0);

	if (irqno > 7) {
		vectmask = 1 << (irqno - 8);
		i = 0;
	} else {
		vectmask = 1 << irqno;
		i = 1;
	}

	pp = &pics0;

	/*
	 * check any handlers left for this irqno
	 */
	if (max_ipl != PSM_INVALID_IPL) {
		/*
		 * unmasks all levels below the lowest priority
		 */
		i += ((min_ipl - 1) << 1);
		for (; i >= 0; i -= 2) {
			if (!(pp->c_iplmask[i] & vectmask))
				break;
			pp->c_iplmask[i] &= ~vectmask;
		}
	} else {
		/*
		 * set mask to all levels
		 */
		for (; i < (MAXIPL << 1); i += 2) {
			if (pp->c_iplmask[i] & vectmask)
				break;
			pp->c_iplmask[i] |= vectmask;
		}
	}
	return (0);
}

static processorid_t
uppc_get_next_processorid(processorid_t cpu_id)
{
	if (cpu_id == -1)
		return (0);
	return (-1);
}

/*ARGSUSED*/
static int
uppc_get_clockirq(int ipl)
{
	return (CLOCK_VECTOR);
}


static int
uppc_init_acpi(void)
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
	uppc_sci = sci;

	if (uppc_verbose & UPPC_VERBOSE_IRQ_FLAG)
		verboseflags |= PSM_VERBOSE_IRQ_FLAG;

	if (uppc_verbose & UPPC_VERBOSE_POWEROFF_FLAG)
		verboseflags |= PSM_VERBOSE_POWEROFF_FLAG;

	if (uppc_verbose & UPPC_VERBOSE_POWEROFF_PAUSE_FLAG)
		verboseflags |= PSM_VERBOSE_POWEROFF_PAUSE_FLAG;

	if (acpi_psm_init(uppc_info.p_mach_idstring, verboseflags) ==
	    ACPI_PSM_FAILURE) {
		return (0);
	}

	return (1);
}


static void
uppc_preshutdown(int cmd, int fcn)
{
	UPPC_VERBOSE_POWEROFF(("uppc_preshutdown(%d,%d);\n", cmd, fcn));

}

static void
uppc_shutdown(int cmd, int fcn)
{
	UPPC_VERBOSE_POWEROFF(("uppc_shutdown(%d,%d);\n", cmd, fcn));

	/*
	 * Return if passed a command other than A_SHUTDOWN or
	 * if we're not using ACPI.
	 */
	if ((cmd != A_SHUTDOWN) || (!uppc_enable_acpi))
		return;

	/*
	 * Switch system back into Legacy-Mode if using ACPI and
	 * not powering-off.  Some BIOSes need to remain in ACPI-mode
	 * for power-off to succeed (Dell Dimension 4600)
	 */
	if (fcn != AD_POWEROFF) {
		(void) AcpiDisable();
		return;
	}

	(void) acpi_poweroff();
}


static int
uppc_acpi_enter_picmode(void)
{
	ACPI_OBJECT_LIST	arglist;
	ACPI_OBJECT		arg;
	ACPI_STATUS		status;

	/* Setup parameter object */
	arglist.Count = 1;
	arglist.Pointer = &arg;
	arg.Type = ACPI_TYPE_INTEGER;
	arg.Integer.Value = ACPI_PIC_MODE;

	status = AcpiEvaluateObject(NULL, "\\_PIC", &arglist, NULL);
	if (ACPI_FAILURE(status))
		return (PSM_FAILURE);
	else
		return (PSM_SUCCESS);
}


struct pic_state {
	int8_t		mmask;
	int8_t		smask;
	uint16_t	elcr;
};


static void
pic_save_state(struct pic_state *sp)
{
	struct standard_pic *pp;
	int	vecno;

	/*
	 * Only the PIC masks and the ELCR can be saved;
	 * other 8259 state is write-only
	 */

	/*
	 * save current master and slave interrupt mask
	 */
	pp = &pics0;
	sp->smask = pp->c_curmask[0];
	sp->mmask = pp->c_curmask[1];

	/*
	 * save edge/level configuration for isa interrupts
	 */
	sp->elcr = 0;
	for (vecno = 0; vecno <= MAX_ISA_IRQ; vecno++)
		sp->elcr |= psm_get_elcr(vecno) << vecno;
}

static void
pic_restore_state(struct pic_state *sp)
{
	int	vecno;

	/* Restore master and slave interrupt masks */
	outb(SIMR_PORT, sp->smask);
	outb(MIMR_PORT, sp->mmask);

	/* Read master to allow pics to settle */
	(void) inb(MIMR_PORT);

	/* Restore edge/level configuration for isa interupts */
	for (vecno = 0; vecno <= MAX_ISA_IRQ; vecno++)
		psm_set_elcr(vecno, sp->elcr & (1 << vecno));

	/* Reenter PIC mode before restoring LNK devices */
	(void) uppc_acpi_enter_picmode();

	/* Restore ACPI link device mappings */
	acpi_restore_link_devices();
}

static int
uppc_state(psm_state_request_t *rp)
{
	switch (rp->psr_cmd) {
	case PSM_STATE_ALLOC:
		rp->req.psm_state_req.psr_state =
		    kmem_zalloc(sizeof (struct pic_state), KM_NOSLEEP);
		if (rp->req.psm_state_req.psr_state == NULL)
			return (ENOMEM);
		rp->req.psm_state_req.psr_state_size =
		    sizeof (struct pic_state);
		return (0);
	case PSM_STATE_FREE:
		kmem_free(rp->req.psm_state_req.psr_state,
		    rp->req.psm_state_req.psr_state_size);
		return (0);
	case PSM_STATE_SAVE:
		pic_save_state(rp->req.psm_state_req.psr_state);
		return (0);
	case PSM_STATE_RESTORE:
		pic_restore_state(rp->req.psm_state_req.psr_state);
		return (0);
	default:
		return (EINVAL);
	}
}


static int
uppc_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp)
{
	int status;
	acpi_psm_lnk_t acpipsmlnk;

	if ((status = acpi_get_irq_cache_ent(busid, devid, ipin, pci_irqp,
	    intr_flagp)) == ACPI_PSM_SUCCESS) {
		UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: Found irqno %d "
		    "from cache for device %s, instance #%d\n", *pci_irqp,
		    ddi_get_name(dip), ddi_get_instance(dip)));
		return (status);
	}

	bzero(&acpipsmlnk, sizeof (acpi_psm_lnk_t));

	if ((status = acpi_translate_pci_irq(dip, ipin, pci_irqp,
	    intr_flagp, &acpipsmlnk)) == ACPI_PSM_FAILURE) {
		UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: "
		    " acpi_translate_pci_irq failed for device %s, instance"
		    " #%d\n", ddi_get_name(dip), ddi_get_instance(dip)));

		return (status);
	}

	if (status == ACPI_PSM_PARTIAL && acpipsmlnk.lnkobj != NULL) {
		status = uppc_acpi_irq_configure(&acpipsmlnk, dip, pci_irqp,
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

		UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: [ACPI] "
		    "new irq %d for device %s, instance #%d\n",
		    *pci_irqp, ddi_get_name(dip), ddi_get_instance(dip)));
	}

	return (status);
}

/*
 * Configures the irq for the interrupt link device identified by
 * acpipsmlnkp.
 *
 * Gets the current and the list of possible irq settings for the
 * device. If uppc_unconditional_srs is not set, and the current
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
uppc_acpi_irq_configure(acpi_psm_lnk_t *acpipsmlnkp, dev_info_t *dip,
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
		UPPC_VERBOSE_IRQ((CE_WARN, "!uppc: Unable to determine "
		    "or assign IRQ for device %s, instance #%d: The system was "
		    "unable to get the list of potential IRQs from ACPI.",
		    ddi_get_name(dip), ddi_get_instance(dip)));

		return (ACPI_PSM_FAILURE);
	}

	if ((acpi_get_current_irq_resource(acpipsmlnkp, &cur_irq,
	    dipintr_flagp) == ACPI_PSM_SUCCESS) && (!uppc_unconditional_srs) &&
	    (cur_irq > 0)) {

		if (acpi_irqlist_find_irq(irqlistp, cur_irq, NULL)
		    == ACPI_PSM_SUCCESS) {

			acpi_free_irqlist(irqlistp);
			ASSERT(pci_irqp != NULL);
			*pci_irqp = cur_irq;
			return (ACPI_PSM_SUCCESS);
		}
		UPPC_VERBOSE_IRQ((CE_WARN, "!uppc: Could not find the "
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

			if (uppc_reserved_irqlist[irq])
				continue;

			if (uppc_irq_shared_table[irq] == 0) {
				chosen_irq = irq;
				foundnow = 1;
				if (!(uppc_prefer_crs) || (irq == cur_irq)) {
					done = 1;
					break;
				}
			}

			if ((uppc_irq_shared_table[irq] < min_share) ||
			    ((uppc_irq_shared_table[irq] == min_share) &&
			    (cur_irq == irq) && (uppc_prefer_crs))) {
				min_share = uppc_irq_shared_table[irq];
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
		UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: Could not find a "
		    "suitable irq from the list of possible irqs for device "
		    "%s, instance #%d in ACPI's list of possible\n",
		    ddi_get_name(dip), ddi_get_instance(dip)));

		return (ACPI_PSM_FAILURE);
	}


	UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: Setting irq %d for device %s "
	    "instance #%d\n", irq, ddi_get_name(dip), ddi_get_instance(dip)));

	if ((acpi_set_irq_resource(acpipsmlnkp, irq)) == ACPI_PSM_SUCCESS) {
		/*
		 * setting irq was successful, check to make sure CRS
		 * reflects that. If CRS does not agree with what we
		 * set, return the irq that was set.
		 */

		if (acpi_get_current_irq_resource(acpipsmlnkp, &cur_irq,
		    dipintr_flagp) == ACPI_PSM_SUCCESS) {

			if (cur_irq != irq)
				UPPC_VERBOSE_IRQ((CE_WARN, "!uppc: "
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
		UPPC_VERBOSE_IRQ((CE_WARN, "!uppc: set resource irq %d "
		    "failed for device %s instance #%d",
		    irq, ddi_get_name(dip), ddi_get_instance(dip)));
		if (cur_irq == -1)
			return (ACPI_PSM_FAILURE);
	}

	ASSERT(pci_irqp != NULL);
	*pci_irqp = cur_irq;
	return (ACPI_PSM_SUCCESS);
}


/*ARGSUSED*/
static int
uppc_translate_irq(dev_info_t *dip, int irqno)
{
	char dev_type[16];
	int dev_len, pci_irq, devid, busid;
	ddi_acc_handle_t cfg_handle;
	uchar_t ipin, iline;
	iflag_t intr_flag;

	if (dip == NULL) {
		UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: irqno = %d"
		    " dip = NULL\n", irqno));
		return (irqno);
	}

	if (!uppc_enable_acpi) {
		return (irqno);
	}

	dev_len = sizeof (dev_type);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device_type", (caddr_t)dev_type,
	    &dev_len) != DDI_PROP_SUCCESS) {
		UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: irqno %d"
		    "device %s instance %d no device_type\n", irqno,
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
		if (uppc_acpi_translate_pci_irq(dip, busid, devid,
		    ipin, &pci_irq, &intr_flag) == ACPI_PSM_SUCCESS) {

			UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: [ACPI] new irq "
			    "%d old irq %d device %s, instance %d\n", pci_irq,
			    irqno, ddi_get_name(dip), ddi_get_instance(dip)));

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

		UPPC_VERBOSE_IRQ((CE_CONT, "!uppc: non-pci,"
		    "irqno %d device %s instance %d\n", irqno,
		    ddi_get_name(dip), ddi_get_instance(dip)));
	}

	return (irqno);
}

/*
 * uppc_intr_enter() raises the ipl to the level of the current interrupt,
 * and sends EOI to the pics.
 * If interrupt is 7 or 15 and not spurious interrupt, send specific EOI
 * else send non-specific EOI
 * uppc_intr_enter() returns the new priority level,
 * or -1 for spurious interrupt
 */
static int
uppc_intr_enter(int ipl, int *vector)
{
	int newipl;
	int intno;

	intno = (*vector);

	ASSERT(intno < 256);

	newipl = autovect[intno].avh_hi_pri;

	/*
	 * During wait_till_seen() periods when interrupt vector is being
	 * removed in remove_av(), the removed hardware interrupt could
	 * trigger and got here with newipl 0.  It has to send EOI
	 * as usual but no need to call setspl and returns -1 like spurious.
	 */
	if ((intno & 7) != 7) {
		if (newipl)
			uppc_setspl(newipl);
		outb(MCMD_PORT, PIC_NSEOI);
		if (intno >= 8) {
			outb(SCMD_PORT, PIC_NSEOI);
		}
	} else { /* int was 7 or 15 */
		if (newipl && newipl <= ipl) { /* Check for spurious int */
			if (intno != 7)
				outb(MCMD_PORT, PIC_NSEOI);
			return (-1); /* Spurious int */
		} else {
			if (newipl)
				uppc_setspl(newipl);
			if (intno != 7) {
				outb(MCMD_PORT, PIC_NSEOI);
				outb(SCMD_PORT, PIC_SEOI_LVL7);
			} else  {
				outb(MCMD_PORT, PIC_SEOI_LVL7);
			}
		}
	}

	if (newipl)
		return (newipl);
	else
		return (-1); /* not real spurious int */
}

/*
 * uppc_intr_exit() restores the old interrupt
 * priority level after processing an interrupt.
 * It is called with interrupts disabled, and does not enable interrupts.
 */
/* ARGSUSED */
static void
uppc_intr_exit(int ipl, int vector)
{
	uppc_setspl(ipl);
}

/*
 * uppc_setspl() loads new interrupt masks into the pics
 * based on input ipl.
 */
/* ARGSUSED */
static void
uppc_setspl(int ipl)
{
	struct standard_pic *pp;
	uint8_t smask, mmask;
	uint8_t cursmask, curmmask;

	pp = &pics0;
	smask = pp->c_iplmask[ipl * 2];
	mmask = pp->c_iplmask[ipl * 2 + 1];
	cursmask = pp->c_curmask[0];
	curmmask = pp->c_curmask[1];
	if (cursmask == smask && curmmask == mmask)
		return;
	pp->c_curmask[0] = smask;
	pp->c_curmask[1] = mmask;

	if (cursmask != smask) {
		/*
		 * program new slave pic mask
		 */
		outb(SIMR_PORT, smask);
	}
	if (curmmask != mmask) {
		/*
		 * program new master pic mask
		 */
		outb(MIMR_PORT, mmask);
	}
	/*
	 * read master to allow pics to settle
	 */
	(void) inb(MIMR_PORT);
}

/*
 * uppc_gethrtime() returns high resolution timer value
 */
static hrtime_t
uppc_gethrtime()
{
	hrtime_t timeval, temp;
	unsigned int ctr0;
	ulong_t oflags;

	oflags = intr_clear(); /* disable ints */
	lock_set(&uppc_gethrtime_lock);
retry:
	temp = hrtime_base;
	outb(PITCTL_PORT, 0);	/* latch counter 0 */
	/*
	 * read counter 0
	 */
	ctr0 = inb(PITCTR0_PORT);
	ctr0 |= inb(PITCTR0_PORT) << 8;
	timeval = (hrtime_t)ctr0 * (NANOSEC / PIT_HZ);
	if (temp != hrtime_base)
		goto retry;
	timeval -= temp;
	if (timeval < uppc_lasthrtime)
		timeval = uppc_lasthrtime;
	uppc_lasthrtime = timeval;
	lock_clear(&uppc_gethrtime_lock);
	intr_restore(oflags);
	return (timeval);
}
