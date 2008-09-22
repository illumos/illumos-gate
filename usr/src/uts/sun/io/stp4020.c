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


/*
 * DRT device/interrupt handler
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddidmareq.h>
#include <sys/kstat.h>
#include <sys/kmem.h>

#include <sys/pctypes.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>

#include <sys/stp4020_reg.h>
#include <sys/stp4020_var.h>
#include <sys/spl.h>


struct stpramap *stpra_freelist = NULL;



char _depends_on[] = "misc/pcmcia";

#define	OUTB(a, b)	outb(a, b)
#define	INB(a)		inb(a)

int drt_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int drt_attach(dev_info_t *, ddi_attach_cmd_t);
static int drt_detach(dev_info_t *, ddi_detach_cmd_t);

static void drt_ll_reset(drt_dev_t *, int);
static void drt_stop_intr(drt_dev_t *, int);
static void drt_cpr(drt_dev_t *, int);
static void drt_new_card(drt_dev_t *, int);
static void drt_fixprops(dev_info_t *);
static int drt_inquire_adapter(dev_info_t *, inquire_adapter_t *);

static struct stpramap *stpra_alloc_map();
static void stpra_free_map(struct stpramap *);
static void stpra_free(struct stpramap **, uint32_t, uint32_t);
static int stpra_alloc(struct stpramap **, stpra_request_t *, stpra_return_t *);
static uint32_t stpra_fix_pow2(uint32_t);


static kmutex_t stpra_lock;

static
struct bus_ops pcmciabus_ops = {
	BUSO_REV,
	i_ddi_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_no_dma_mctl,
	pcmcia_ctlops,
	pcmcia_prop_op,
	NULL,			/* (*bus_get_eventcookie)();	*/
	NULL,			/* (*bus_add_eventcall)();	*/
	NULL,			/* (*bus_remove_eventcall)();	*/
	NULL,			/* (*bus_post_event)();		*/
	NULL,			/* (*bus_intr_ctl)();		*/
	NULL,			/* (*bus_config)(); 		*/
	NULL,			/* (*bus_unconfig)(); 		*/
	NULL,			/* (*bus_fm_init)(); 		*/
	NULL,			/* (*bus_fm_fini)(); 		*/
	NULL,			/* (*bus_enter)()		*/
	NULL,			/* (*bus_exit)()		*/
	NULL,			/* (*bus_power)()		*/
	pcmcia_intr_ops		/* (*bus_intr_op)(); 		*/
};

static struct dev_ops drt_devops = {
	DEVO_REV,
	0,
	drt_getinfo,
	nulldev,
	nulldev,
	drt_attach,
	drt_detach,
	nulldev,
	NULL,
	&pcmciabus_ops,
	ddi_power,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

#if defined(DEBUG)
#define	DRT_DEBUG
#endif
#if defined(DRT_DEBUG)
static void drt_dmp_regs(stp4020_socket_csr_t *);
int drt_debug = 0;
#endif

/* bit patterns to select voltage levels */
int drt_vpp_levels[13] = {
	0, 0, 0, 0, 0,
	1,			/* 5V */
	0, 0, 0, 0, 0, 0,
	2			/* 12V */
};
struct power_entry drt_power[DRT_NUM_POWER] = {
	{
		0,		/* off */
		VCC|VPP1|VPP2
	},
	{
		5*10,		/* 5Volt */
		VCC|VPP1|VPP2
	},
	{
		12*10,		/* 12Volt */
		VPP1|VPP2
	},
};

drt_dev_t *drt_get_driver_private(dev_info_t *);
uint32_t drt_hi_intr(caddr_t);
uint32_t drt_lo_intr(caddr_t);

static int drt_callback(dev_info_t *, int (*)(), int);
static int drt_inquire_adapter(dev_info_t *, inquire_adapter_t *);
static int drt_get_adapter(dev_info_t *, get_adapter_t *);
static int drt_get_page(dev_info_t *, get_page_t *);
static int drt_get_socket(dev_info_t *, get_socket_t *);
static int drt_get_status(dev_info_t *, get_ss_status_t *);
static int drt_get_window(dev_info_t *, get_window_t *);
static int drt_inquire_socket(dev_info_t *, inquire_socket_t *);
static int drt_inquire_window(dev_info_t *, inquire_window_t *);
static int drt_reset_socket(dev_info_t *, int, int);
static int drt_set_page(dev_info_t *, set_page_t *);
static int drt_set_window(dev_info_t *, set_window_t *);
static int drt_set_socket(dev_info_t *, set_socket_t *);
static int drt_set_interrupt(dev_info_t *, set_irq_handler_t *);
static int drt_clear_interrupt(dev_info_t *, clear_irq_handler_t *);
void drt_socket_card_id(drt_dev_t *, drt_socket_t *, int);

/*
 * pcmcia interface operations structure
 * this is the private interface that is exported to the nexus
 */
pcmcia_if_t drt_if_ops = {
	PCIF_MAGIC,
	PCIF_VERSION,
	drt_callback,
	drt_get_adapter,
	drt_get_page,
	drt_get_socket,
	drt_get_status,
	drt_get_window,
	drt_inquire_adapter,
	drt_inquire_socket,
	drt_inquire_window,
	drt_reset_socket,
	drt_set_page,
	drt_set_window,
	drt_set_socket,
	drt_set_interrupt,
	drt_clear_interrupt,
	NULL,
};

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"STP4020 (SUNW,pcmcia) adapter driver", /* Name of the module. */
	&drt_devops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init()
{
	int ret;

	mutex_init(&stpra_lock, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)__ipltospl(SPL7 - 1));
	if ((ret = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&stpra_lock);
	}
	return (ret);
}

int
_fini()
{
	int ret;
	struct stpramap *next;

	if ((ret = mod_remove(&modlinkage)) == 0) {

		mutex_enter(&stpra_lock);
		while (stpra_freelist != NULL) {
			next = stpra_freelist->ra_next;
			kmem_free((caddr_t)stpra_freelist,
			    sizeof (struct stpramap));
			stpra_freelist = next;
		}
		mutex_exit(&stpra_lock);

		mutex_destroy(&stpra_lock);
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * drt_getinfo()
 *	provide instance/device information about driver
 */
int
drt_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error = DDI_SUCCESS;
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		/* should make independent of SUNW,pcmcia */
		dip = ddi_find_devinfo("SUNW,pcmcia", getminor((dev_t)arg), 1);
		*result = dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

/*
 * drt_attach()
 *	attach the DRT (SPARC STP4020) driver
 *	to the system.  This is a child of "sysbus" since that is where
 *	the hardware lives, but it provides services to the "pcmcia"
 *	nexus driver.  It gives a pointer back via its private data
 *	structure which contains both the dip and socket services entry
 *	points
 */
static int
drt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	drt_dev_t *drt;
	struct pcmcia_adapter_nexus_private *drt_nexus;
	int i;
	ddi_device_acc_attr_t dev_attr;
	int regs[24];
	int err;

#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "drt_attach(%d): entered\n", cmd);
	}
#endif
	switch (cmd) {
	default:
		return (DDI_FAILURE);
	case DDI_RESUME:
		drt_nexus = ddi_get_driver_private(dip);
		drt = (drt_dev_t *)drt_get_driver_private(dip);
#if defined(DRT_DEBUG)
		if (drt_debug) {
			cmn_err(CE_CONT, "drt_attach: DDI_RESUME\n");
		}
#endif
		if (drt != NULL && drt->pc_flags & PCF_SUSPENDED) {
			/* XXX - why would drt be NULL?? */
			int sn;
			for (sn = 0; sn < DRSOCKETS; sn++) {
				drt_socket_t *sockp = &drt->pc_sockets[sn];

			    /* Restore adapter hardware state */
				mutex_enter(&drt->pc_lock);
				drt_cpr(drt, DRT_RESTORE_HW_STATE);
				drt_new_card(drt, sn);
				drt_socket_card_id(drt, sockp,
				    drt->pc_csr->socket[sn].stat0);
				mutex_exit(&drt->pc_lock);

			} /* for (sn) */
			mutex_enter(&drt->pc_lock);
			drt->pc_flags &= ~PCF_SUSPENDED;
			mutex_exit(&drt->pc_lock);
			/* do we want to do anything here??? */

			/* this code should do PC Card Standard form */
			(void) pcmcia_begin_resume(dip);
			/*
			 * this will do the CARD_INSERTION
			 * due to needing time for threads to
			 * run, it must be delayed for a short amount
			 * of time.  pcmcia_wait_insert checks for all
			 * children to be removed and then triggers insert.
			 */
			(void) pcmcia_wait_insert(dip);
			/*
			 * for complete implementation need END_RESUME (later)
			 */
			return (DDI_SUCCESS);
		}
		return (DDI_FAILURE);
	case DDI_ATTACH:
		break;
	}

	drt = (drt_dev_t *)kmem_zalloc(sizeof (drt_dev_t), KM_NOSLEEP);
	if (drt == NULL) {
		return (DDI_FAILURE);
	}

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_attach: drt=%p\n", (void *)drt);
#endif
	drt_nexus = (struct pcmcia_adapter_nexus_private *)
	    kmem_zalloc(sizeof (struct pcmcia_adapter_nexus_private),
	    KM_NOSLEEP);
	if (drt_nexus == NULL) {
		kmem_free(drt, sizeof (drt_dev_t));
		return (DDI_FAILURE);
	}
	/* map everything in we will ultimately need */
	drt->pc_devinfo = dip;
	drt->pc_csr = 0;
	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	if (ddi_regs_map_setup(dip, DRMAP_ASIC_CSRS, (caddr_t *)&drt->pc_csr,
	    (off_t)0, sizeof (stp4020_socket_csr_t),
	    &dev_attr, &drt->pc_handle) != 0) {
		kmem_free(drt, sizeof (drt_dev_t));
		kmem_free(drt_nexus,
		    sizeof (struct pcmcia_adapter_nexus_private *));
		return (DDI_FAILURE);
	}
#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "drt_attach: %x->%p\n", DRMAP_ASIC_CSRS,
		    (void *)drt->pc_csr);
	}
#endif

	i = sizeof (regs);
	if ((err = ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP, "reg",
	    (caddr_t)regs, &i)) != DDI_SUCCESS) {

		kmem_free(drt, sizeof (drt_dev_t));
		kmem_free(drt_nexus,
		    sizeof (struct pcmcia_adapter_nexus_private));
		return (DDI_FAILURE);
	}


	drt_nexus->an_dip = dip;
	drt_nexus->an_if = &drt_if_ops;
	drt_nexus->an_private = drt;

	drt->pc_numpower = DRT_NUM_POWER;
	drt->pc_power = drt_power;

	drt->pc_numsockets = DRSOCKETS;
	drt->pc_flags |= PCF_ATTACHING;

	ddi_set_driver_private(dip, drt_nexus);

	/* allow property to override audio */
	if (ddi_getprop(DDI_DEV_T_NONE, dip,
	    DDI_PROP_DONTPASS, "disable-audio", -1) == -1)
		drt->pc_flags |= PCF_AUDIO;

	/* now enable both interrupt handlers */
	if (ddi_add_intr(dip, 1, &drt->pc_icookie_hi, &drt->pc_dcookie_hi,
	    drt_hi_intr, (caddr_t)dip) != DDI_SUCCESS) {
		/* if it fails, unwind everything */
		ddi_regs_map_free(&drt->pc_handle);
		kmem_free((caddr_t)drt, sizeof (drt_dev_t));
		kmem_free((caddr_t)drt_nexus, sizeof (*drt_nexus));
		return (DDI_FAILURE);
	}

#if 0
	if (ddi_add_intr(dip, 0, &drt->pc_icookie_lo, &drt->pc_dcookie_lo,
	    drt_lo_intr, (caddr_t)dip) != DDI_SUCCESS) {
		/* if it fails, unwind everything */
		ddi_remove_intr(dip, 0, &drt->pc_icookie_hi);
		ddi_regs_map_free(&drt->pc_handle);
		kmem_free((caddr_t)drt, sizeof (drt_dev_t));
		kmem_free((caddr_t)drt_nexus, sizeof (*drt_nexus));
		return (DDI_FAILURE);
	}
#endif
	mutex_init(&drt->pc_lock, NULL, MUTEX_DRIVER, drt->pc_icookie_hi);
	mutex_init(&drt->pc_intr, NULL, MUTEX_DRIVER, drt->pc_icookie_hi);

	drt_nexus->an_iblock = &drt->pc_icookie_hi;
	drt_nexus->an_idev = &drt->pc_dcookie_hi;

	mutex_enter(&drt->pc_lock);

	for (i = 0; i < DRSOCKETS; i++) {
		struct stpramap *map;

		drt->pc_csr->socket[i].ctl1 = 0; /* turn things off */
		drt->pc_csr->socket[i].ctl0 = 0; /* before we touch anything */

		/* work around for false status bugs */
		drt->pc_csr->socket[i].stat1 = 0x3FFF;
		drt->pc_csr->socket[i].stat0 = 0x3FFF;

		/*
		 * enable the socket as well
		 * want status change interrupts for all possible events
		 * We do this even though CS hasn't asked.  The system
		 * wants to manage these and will only tell CS of those
		 * it asks for
		 */
		/* identify current state of card */
		drt_socket_card_id(drt, &drt->pc_sockets[i],
		    drt->pc_csr->socket[i].stat0);

		/* finally, turn it on */
		drt->pc_csr->socket[i].ctl0 = DRT_CHANGE_DEFAULT;

		/* now we need per-socket I/O space allocation */
		map = drt->pc_sockets[i].drt_iomap = stpra_alloc_map();
		map->ra_base = 0;
		map->ra_len = 0xffffff;	/* 1MB */
	}

	drt_fixprops(dip);

	/*
	 * now that the adapter is fully operational
	 * it is time to pull in the PCMCIA framework
	 * and let it know we exist and are "ready"
	 */
	mutex_exit(&drt->pc_lock);
	err = pcmcia_attach(dip, drt_nexus);

	return (err);
}

/*
 * drt_detach()
 *	request to detach from the system
 */
static int
drt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int i;
	drt_dev_t *drt = (drt_dev_t *)drt_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		if (drt != NULL) {
			/* turn everything off for all sockets and chips */
			for (i = 0; i < drt->pc_numsockets; i++) {
				drt->pc_csr->socket[i].ctl0 = 0;
				drt->pc_csr->socket[i].ctl1 = 0;
			}
			stpra_free_map(drt->pc_sockets[i].drt_iomap);
			ddi_regs_map_free(&drt->pc_handle);
			ddi_remove_intr(dip, 0, drt->pc_icookie_lo);
			ddi_remove_intr(dip, 1, drt->pc_icookie_hi);
			drt->pc_flags = 0;
			mutex_destroy(&drt->pc_lock);
			return (DDI_SUCCESS);
		}
		break;

	case DDI_PM_SUSPEND:
#if defined(DRT_DEBUG)
		if (drt_debug) {
			cmn_err(CE_WARN, "stp4020: DDI_PM_SUSPEND\n");
		}
#endif
						/*FALLTHROUGH*/
	case DDI_SUSPEND:
#if defined(DRT_DEBUG)
		if (drt_debug) {
			cmn_err(CE_CONT, "drt_detach: DDI_SUSPEND\n");
		}
#endif
		if (drt != NULL) {
			/* XXX - why is this test necessary here? */
			int sn;
			mutex_enter(&drt->pc_lock);
			drt->pc_flags |= PCF_SUSPENDED;
			mutex_exit(&drt->pc_lock);
			for (sn = 0; sn < DRSOCKETS; sn++) {
			    /* drt_stop_intr(drt, sn); XXX ?? */
				mutex_enter(&drt->pc_lock);
				/* clears sockp->drt_flags */
				drt_new_card(drt, sn);
				mutex_exit(&drt->pc_lock);
			}
			/*
			 * Save the adapter's hardware state here
			 */
			mutex_enter(&drt->pc_lock);
			drt_cpr(drt, DRT_SAVE_HW_STATE);
			mutex_exit(&drt->pc_lock);
			return (DDI_SUCCESS);
		} /* if (drt) */
	} /* switch */
	return (DDI_FAILURE);
}

drt_dev_t *
drt_get_driver_private(dev_info_t *dip)
{
	struct pcmcia_adapter_nexus_private *nexus;
	nexus = ddi_get_driver_private(dip);
	return ((drt_dev_t *)nexus->an_private);
}

/*
 * drt_inquire_adapter()
 *	SocketServices InquireAdapter function
 *	get characteristics of the physical adapter
 */
static int
drt_inquire_adapter(dev_info_t *dip, inquire_adapter_t *config)
{
	drt_dev_t *drt = drt_get_driver_private(dip);
#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_inquire_adapter\n");
#endif
	config->NumSockets = drt->pc_numsockets;
	config->NumWindows = DRT_NUMWINDOWS;
	config->NumEDCs = 0;
	config->AdpCaps = 0;
	config->ActiveHigh = 3;
	config->ActiveLow = 0;
	config->NumPower = drt->pc_numpower;
	config->power_entry = drt->pc_power; /* until we resolve this */
	config->ResourceFlags = RES_OWN_IRQ | RES_OWN_IO | RES_OWN_MEM |
	    RES_IRQ_NEXUS | RES_IRQ_SHAREABLE;
	return (SUCCESS);
}

/*
 * drt_callback()
 *	The PCMCIA nexus calls us via this function
 *	in order to set the callback function we are
 *	to call the nexus with
 */
static int
drt_callback(dev_info_t *dip, int (*handler)(), int arg)
{
	drt_dev_t *drt = (drt_dev_t *)drt_get_driver_private(dip);
#if defined(DRT_DEBUG)
	if (drt_debug) {
#ifdef	XXX
		cmn_err(CE_CONT, "drt_callback: drt=%x, lock=%x\n",
		    (int)drt, (int)drt->pc_lock);
#endif
		cmn_err(CE_CONT, "\thandler=%p, arg=%x\n", (void *)handler,
		    arg);
	}
#endif
	if (handler != NULL) {
		drt->pc_callback = handler;
		drt->pc_cb_arg  = arg;
		drt->pc_flags |= PCF_CALLBACK;
	} else {
		drt->pc_callback = NULL;
		drt->pc_cb_arg = 0;
		drt->pc_flags &= ~PCF_CALLBACK;
	}
	/*
	 * we're now registered with the nexus
	 * it is acceptable to do callbacks at this point.
	 * don't call back from here though since it could block
	 */

	return (PC_SUCCESS);
}

/*
 * drt_calc_speed()
 *	determine the bit pattern for speeds to be put in the control register
 */

static int
drt_calc_speed(int speed)
{
	int length;
	int delay;
	/*
	 * the documented speed determination (25MHZ) is
	 * 250 + (CMDLNG - 4) * 40 < speed <= 250 + (CMDLNG - 3) * 40
	 * The value of CMDLNG is roughly determined by
	 * CMDLNG == ((speed - 250) / 40) + [3|4]
	 * the calculation is very approximate.
	 * for speeds <= 250ns, use simple formula
	 *
	 * this should really be based on processor speed.
	 */

	if (speed <= 250) {
		if (speed < 100)
			speed = 100;
		length = (speed - 100) / 50;
		if (speed <= 100)
			delay = 1;
		else
			delay = 2;
	} else {
		length = ((speed - 250) / 40);
		if ((250 + (length - 3) * 40) == speed)
			length += 3;
		else
			length += 4;
		delay = 2;
	}

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_calc_speed: speed=%d, length=%x, "
		    "delay=%x, ret=%x\n",
		    speed, length, delay,
		    (SET_DRWIN_CMDDLY(delay) | SET_DRWIN_CMDLNG(length)));
#endif
	return (SET_DRWIN_CMDDLY(delay) | SET_DRWIN_CMDLNG(length));
}

/*
 * drt_set_window
 *	essentially the same as the Socket Services specification
 *	We use socket and not adapter since they are identifiable
 *	but the rest is the same
 *
 *	dip	drt driver's device information
 *	window	parameters for the request
 */
static int
drt_set_window(dev_info_t *dip, set_window_t *window)
{
	int prevstate;
	int which, win;
	drt_dev_t *drt = drt_get_driver_private(dip);
	drt_socket_t *sockp;
	struct drt_window *winp;
	stp4020_socket_csr_t *csrp;
	int windex;

#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "drt_set_window: entered\n");
		cmn_err(CE_CONT,
		    "\twindow=%d, socket=%d, WindowSize=%d, speed=%d\n",
		    window->window, window->socket, window->WindowSize,
		    window->speed);
		cmn_err(CE_CONT,
		    "\tbase=%x, state=%x\n", (int)window->base,
		    window->state);
	}
#endif


	/*
	 * do some basic sanity checking on what we support
	 * we don't do paged mode
	 */
	if (window->state & WS_PAGED)
		return (BAD_ATTRIBUTE);

	/*
	 * make sure we use the correct internal socket/window
	 * combination
	 */
	win = window->window % DRWINDOWS;
	if (window->socket != (window->window / DRWINDOWS)) {
		return (BAD_SOCKET);
	}

	if (!(window->state & WS_IO) && (window->WindowSize != DRWINSIZE &&
	    !(window->state & WS_EXACT_MAPIN)) ||
	    window->WindowSize > DRWINSIZE) {
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "\tBAD SIZE\n");
#endif
		return (BAD_SIZE);
	}

	sockp = &drt->pc_sockets[window->socket];

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT,
		    "\tusing window/socket %d/%d\n", win, window->socket);
#endif

	/*
	 * we don't care about previous mappings.
	 * Card Services will deal with that so don't
	 * even check
	 */

	winp = &sockp->drt_windows[win];
	csrp = &drt->pc_csr->socket[window->socket];

	mutex_enter(&drt->pc_lock); /* protect the registers */
	prevstate = winp->drtw_flags;
	which = 0;		/* no error */

	/* disable current settings */
	csrp->window[win].ctl0 = 0;

	/*
	 * disable current mapping
	 * this will handle the case of WS_ENABLED not being set
	 */
#ifdef notdef
	if ((window->state & (WS_IO|WS_EXACT_MAPIN)) ==
	    (WS_IO|WS_EXACT_MAPIN)) {
		if (window->base.base != 0) {
			/* compensate for having to start at 0 */
			window->WindowSize += (uint32_t)window->base.base;
		}
	}
#endif

	if (window->socket == 0)
		windex = DRMAP_CARD0_WIN0 + win;
	else
		windex = DRMAP_CARD1_WIN0 + win;

	if ((prevstate & DRW_MAPPED) &&
	    (window->WindowSize != winp->drtw_len)) {
		mutex_exit(&drt->pc_lock);
		ddi_regs_map_free(&winp->drtw_handle);
		mutex_enter(&drt->pc_lock);
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT,
			    "\tunmapped: base being set to NULL\n");
#endif
		winp->drtw_flags &= ~(DRW_MAPPED|DRW_ENABLED);
		if (prevstate & DRW_IO) {
			stpra_free(&sockp->drt_iomap,
			    (uint32_t)(uintptr_t)winp->drtw_reqaddr,
			    (uint32_t)winp->drtw_len);
		}
		winp->drtw_base = NULL;
	}

	if (window->state & WS_ENABLED) {
		if (winp->drtw_base == NULL) {
			if (window->state & WS_IO) {
				stpra_request_t req;
				stpra_return_t ret;
				bzero((caddr_t)&req, sizeof (req));
				bzero((caddr_t)&ret, sizeof (ret));
				req.ra_flags = STP_RA_ALLOC_POW2 |
				    STP_RA_ALIGN_SIZE;
				req.ra_len = window->WindowSize;
				req.ra_addr_lo = window->base;

				if (window->base != 0)
					req.ra_flags |= STP_RA_ALLOC_SPECIFIED;

				if (stpra_alloc(&sockp->drt_iomap,
				    &req, &ret) != DDI_SUCCESS) {
					mutex_exit(&drt->pc_lock);
					return (BAD_BASE);
				}
				/* now use the resultant address */
				window->base = ret.ra_addr_lo;
			}
			mutex_exit(&drt->pc_lock);
			which = ddi_regs_map_setup(drt->pc_devinfo,
			    windex,
			    &winp->drtw_base,
			    (offset_t)window->base,
			    window->WindowSize,
			    &window->attr,
			    &winp->drtw_handle);
			mutex_enter(&drt->pc_lock);
			if (which != DDI_SUCCESS) {
				mutex_exit(&drt->pc_lock);
				return (BAD_SIZE);
			}
#if defined(DRT_DEBUG)
			if (drt_debug)
				cmn_err(CE_CONT,
				    "\tmapped: handle = 0x%p base = %p, "
				    "len=%x\n",
				    (void *)winp->drtw_handle,
				    (void *)winp->drtw_base,
				    (int)window->WindowSize);
#endif
		}
		winp->drtw_reqaddr = (caddr_t)(uintptr_t)window->base;
		winp->drtw_flags |= DRW_MAPPED | DRW_ENABLED;

		if (!(window->state & WS_IO)) {
			winp->drtw_speed = window->speed;
			winp->drtw_ctl0 = drt_calc_speed(window->speed);
			winp->drtw_ctl0 |= DRWIN_ASPSEL_CM;
			winp->drtw_flags &= ~DRW_IO;
		} else {
			winp->drtw_flags |= DRW_IO;
			winp->drtw_ctl0 = DRWIN_ASPSEL_IO |
			    drt_calc_speed(window->speed);
			winp->drtw_modhandle.ah_addr +=	(int)window->base;
		}
		window->handle = winp->drtw_handle;
		csrp->window[win].ctl0 = winp->drtw_ctl0;
		csrp->window[win].ctl1 = SET_DRWIN_WAITREQ(1) |
		    SET_DRWIN_WAITDLY(0);
		winp->drtw_len = window->WindowSize;
	} else {
		if (winp->drtw_flags & DRW_ENABLED) {
			winp->drtw_flags &= ~DRW_ENABLED;
			csrp->window[win].ctl0 = 0; /* force off */
#ifdef	XXX
			if (prevstate & DRW_IO) {
				stpra_free(&sockp->drt_iomap,
				    (uint32_t)winp->drtw_reqaddr,
				    (uint32_t)winp->drtw_len);
			}
#endif	/* XXX */
		}
		winp->drtw_base = NULL;
	}

#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT,
		    "\tbase now set to %p (->%p), csrp=%p, winreg=%p"
		    ", len=%x\n",
		    (void *)window->handle,
		    (void *)winp->drtw_base, (void *)csrp,
		    (void *)&csrp->window[win].ctl0,
		    (int)window->WindowSize);
		cmn_err(CE_CONT,
		    "\twindow type is now %s\n", window->state & WS_IO ?
		    "I/O" : "memory");
		if (drt_debug > 1)
			drt_dmp_regs(csrp);
	}
#endif

	mutex_exit(&drt->pc_lock);

	return (SUCCESS);
}

/*
 * drt_card_state()
 *	compute the instantaneous Card State information
 */
int
drt_card_state(drt_dev_t *drt, int socket)
{
	int value, result;

	mutex_enter(&drt->pc_lock); /* protect the registers */

	value = drt->pc_csr->socket[socket].stat0;
#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "drt_card_state: socket=%d, *lock=%p\n",
		    socket, (void *)&drt->pc_lock);
		cmn_err(CE_CONT, "\tcsr@%p\n", (void *)drt->pc_csr);

		cmn_err(CE_CONT, "\tstat0=%b\n", value,
		    "\020\1PWRON\2WAIT\3WP\4RDYBSY\5BVD1\6BVD2\7CD1"
		    "\10CD2\011ACCTO\012WPC\013RBC\014BVD1C\015BVD2C"
		    "\016CDSC\017STAT");
		cmn_err(CE_CONT,
		    "\tstat1=%x\n",
		    (int)drt->pc_csr->socket[socket].stat1);
		cmn_err(CE_CONT, "\t&stat0=%p, &stat1=%p\n",
		    (void *)&drt->pc_csr->socket[socket].stat0,
		    (void *)&drt->pc_csr->socket[socket].stat1);
	}
#endif

	if (value & DRSTAT_WPST)
		result = SBM_WP;
	else
		result = 0;

	switch (value & DRSTAT_BVDST) {
	case DRSTAT_BATT_LOW:
		result |= SBM_BVD2;
		break;
	case DRSTAT_BATT_OK:
		break;
	default:
		/* battery dead */
		result |= SBM_BVD1;
		break;
	}

	if (value & DRSTAT_RDYST)
		result |= SBM_RDYBSY;
	if ((value & (DRSTAT_CD1ST|DRSTAT_CD2ST)) ==
	    (DRSTAT_CD1ST|DRSTAT_CD2ST))
		result |= SBM_CD;

	mutex_exit(&drt->pc_lock);

	return (result);
}

/*
 * drt_set_page()
 *	SocketServices SetPage function
 *	set the page of PC Card memory that should be in the mapped
 *	window
 */

int
drt_set_page(dev_info_t *dip, set_page_t *page)
{
	int which, socket, win;
	drt_dev_t *drt = drt_get_driver_private(dip);
	drt_socket_t *sockp;
	struct drt_window *winp;
	stp4020_socket_csr_t *csrp;

	if (page->window >= DRT_NUMWINDOWS) {
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "drt_set_page: window=%d (%d)\n",
			    page->window, DRWINDOWS);
#endif
		return (BAD_WINDOW);
	}

	win = page->window % DRWINDOWS;
	socket = page->window / DRWINDOWS;

	sockp = &drt->pc_sockets[socket];

#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT,
		    "drt_set_page: window=%d, socket=%d, page=%d\n",
		    win, socket, page->page);
	}
#endif

	/* only one page supported (fixed at 1MB) */
#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "\tpage=%d\n", page->page);
#endif
	winp = &sockp->drt_windows[win];
	csrp = &drt->pc_csr->socket[socket];

	if (winp->drtw_flags & DRW_IO) {
		return (BAD_WINDOW);
	}

	if (page->page != 0) {
		return (BAD_PAGE);
	}

	mutex_enter(&drt->pc_lock); /* protect the registers */

	/*
	 * now map the card's memory pages - we start with page 0
	 */

	if (page->state & PS_ATTRIBUTE) {
		which = SET_DRWIN_CMDDLY(2) | SET_DRWIN_CMDLNG(4);
		winp->drtw_flags |= DRW_ATTRIBUTE;
	} else {
		which = winp->drtw_ctl0 & (DRWIN_CMDLNG_M|DRWIN_CMDDLY_M);
		winp->drtw_flags &= ~DRW_ATTRIBUTE;
	}

	which |= (page->state & PS_ATTRIBUTE) ?
	    DRWIN_ASPSEL_AM : DRWIN_ASPSEL_CM;

	/* if card says Write Protect, enforce it */
	/* but we don't have hardware support to do it */

	/* The actual PC Card address mapping */
#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "\ta2p=%x, base=%x, csrp=%p\n",
		    (int)ADDR2PAGE(page->offset),
		    SET_DRWIN_BASE(ADDR2PAGE(page->offset)),
		    (void *)csrp);
#endif
	which |= SET_DRWIN_BASE(ADDR2PAGE(page->offset));
	winp->drtw_addr = (caddr_t)page->offset;

	/* now set the register */
#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "\tset ctl0=%x\n", which);
#endif

	csrp->window[win].ctl0 = (ushort_t)which;
	csrp->window[win].ctl1 = SET_DRWIN_WAITREQ(1) | SET_DRWIN_WAITDLY(0);

	/* now  */

#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "\tmemory type = %s\n",
		    (which & DRWIN_ASPSEL_CM) ? "common" : "attribute");
	}
#endif


#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT,
		    "\tpage offset=%x, base=%p (PC addr=%p, sockets=%d)\n",
		    (int)page->offset, (void *)winp->drtw_base,
		    (void *)winp->drtw_addr, drt->pc_numsockets);
		cmn_err(CE_CONT, "\t*base=%x, win reg=%p\n",
		    *(ushort_t *)winp->drtw_base,
		    (void *)&csrp->window[win].ctl0);
		if (drt_debug > 1)
			drt_dmp_regs(csrp);
	}
#endif
	mutex_exit(&drt->pc_lock);

	return (SUCCESS);
}

/*
 * drt_set_socket()
 *	Socket Services SetSocket call
 *	sets basic socket configuration
 */
static int
drt_set_socket(dev_info_t *dip, set_socket_t *socket)
{
	int value, sock;
	drt_dev_t *drt = drt_get_driver_private(dip);
	drt_socket_t *sockp = &drt->pc_sockets[socket->socket];
	int irq = 0;
	int powerlevel = 0;
	int ind;

	sock = socket->socket;

#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "drt_set_socket: entered (socket=%d)\n", sock);
	}
#endif
	/*
	 * check VccLevel, etc. before setting mutex
	 * if this is zero, power is being turned off
	 * if it is non-zero, power is being turned on.
	 * the default case is to assume Vcc only.
	 */

	/* this appears to be very implementation specific */

	if (socket->VccLevel == 0) {
		powerlevel = 0;
	} else  if (socket->VccLevel < drt->pc_numpower &&
	    drt_power[socket->VccLevel].ValidSignals & VCC) {
		/* enable Vcc */
		powerlevel = DRCTL_MSTPWR|DRCTL_PCIFOE;
		sockp->drt_vcc = socket->VccLevel;
	} else {
		return (BAD_VCC);
	}
#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "\tVccLevel=%d, Vpp1Level=%d, Vpp2Level=%d\n",
		    socket->VccLevel,
		    socket->Vpp1Level, socket->Vpp2Level);
	}
#endif
	ind = 0;		/* default index to 0 power */
	if (socket->Vpp1Level >= 0 && socket->Vpp1Level < drt->pc_numpower) {
		if (!(drt_power[socket->Vpp1Level].ValidSignals & VPP1)) {
			return (BAD_VPP);
		}
		ind = drt_power[socket->Vpp1Level].PowerLevel/10;
		powerlevel |= drt_vpp_levels[ind] << 2;
		sockp->drt_vpp1 = socket->Vpp1Level;
	}
	if (socket->Vpp2Level >= 0 && socket->Vpp2Level < drt->pc_numpower) {
		if (!(drt_power[socket->Vpp2Level].ValidSignals & VPP2)) {
			return (BAD_VPP);
		}
		ind = drt_power[socket->Vpp2Level].PowerLevel/10;
		powerlevel |= (drt_vpp_levels[ind] << 4);
		sockp->drt_vpp2 = socket->Vpp2Level;
	}

#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "\tpowerlevel=%x, ind=%x\n", powerlevel, ind);
	}
#endif
	mutex_enter(&drt->pc_lock); /* protect the registers */

	/* make sure not still in RESET */
	value = drt->pc_csr->socket[sock].ctl0;
	drt->pc_csr->socket[sock].ctl0 = value & ~DRCTL_RESET;
	/*
	 * ctlind processing -- we can ignore this
	 * there aren't any outputs on the chip for this
	 * the GUI will display what it thinks is correct
	 */


	/* handle event mask */
	sockp->drt_intmask = socket->SCIntMask;
	value = (drt->pc_csr->socket[sock].ctl0 & ~DRT_CHANGE_MASK) |
	    DRT_CHANGE_DEFAULT; /* always want CD */

	if (socket->SCIntMask & SBM_CD)
		value |= DRCTL_CDIE;
	if (socket->SCIntMask & SBM_BVD1)
		value |= DRCTL_BVD1IE;
	if (socket->SCIntMask & SBM_BVD2)
		value |= DRCTL_BVD2IE;
	if (socket->SCIntMask & SBM_WP)
		value |= DRCTL_WPIE;
	if (socket->SCIntMask & SBM_RDYBSY)
		value |= DRCTL_RDYIE;
	/* irq processing */
	if (socket->IFType == IF_IO) {
				/* IRQ only for I/O */
		irq = socket->IREQRouting & 0xF;
		if (socket->IREQRouting & IRQ_ENABLE) {
			irq = DRCTL_IOIE;
#if 0
			if (socket->IREQRouting & IRQ_PRIORITY) {
				irq |= DRCTL_IOILVL_SB1;
				sockp->drt_flags |= DRT_INTR_HIPRI;
			} else {
				irq |= DRCTL_IOILVL_SB0;
			}
#else
			irq |= DRCTL_IOILVL_SB1;
			sockp->drt_flags |= DRT_INTR_HIPRI;
#endif
			sockp->drt_flags |= DRT_INTR_ENABLED;
		} else {
			irq = 0; /* no interrupts */
			sockp->drt_flags &= ~(DRT_INTR_ENABLED|DRT_INTR_HIPRI);
		}
		sockp->drt_irq = socket->IREQRouting;

#if defined(DRT_DEBUG)
		if (drt_debug) {
			cmn_err(CE_CONT,
			    "\tsocket type is I/O and irq %x is %s\n", irq,
			    (socket->IREQRouting & IRQ_ENABLE) ?
			    "enabled" : "not enabled");
		}
#endif
		sockp->drt_flags |= DRT_SOCKET_IO;
		if (drt->pc_flags & PCF_AUDIO)
			value |= DRCTL_IFTYPE_IO | irq | DRCTL_SPKREN;
		else
			value |= DRCTL_IFTYPE_IO | irq;
	} else {
		/* enforce memory mode */
		value &= ~(DRCTL_IFTYPE_IO | DRCTL_SPKREN |
		    DRCTL_IOILVL_SB1 | DRCTL_IOILVL_SB0 |
		    DRCTL_IOIE);
		sockp->drt_flags &= ~(DRT_INTR_ENABLED|DRT_SOCKET_IO);
	}
	drt->pc_csr->socket[sock].ctl0 = (ushort_t)value;

	/*
	 * set power to socket
	 * note that the powerlevel was calculated earlier
	 */

	drt->pc_csr->socket[sock].ctl1 = (ushort_t)powerlevel;
#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT,
		    "\tpowerlevel (socket->ctl1) = %x\n", powerlevel);
		if (drt_debug > 1)
			drt_dmp_regs(&drt->pc_csr->socket[sock]);
	}
#endif
	sockp->drt_state &= ~socket->State;
	mutex_exit(&drt->pc_lock);
	return (SUCCESS);
}

/*
 * drt_inquire_socket()
 *	SocketServices InquireSocket function
 *	returns basic characteristics of the socket
 */
static int
drt_inquire_socket(dev_info_t *dip, inquire_socket_t *socket)
{
	int value;
	drt_dev_t *drt = drt_get_driver_private(dip);

	socket->SCIntCaps = DRT_DEFAULT_INT_CAPS;
	socket->SCRptCaps = DRT_DEFAULT_RPT_CAPS;
	socket->CtlIndCaps = DRT_DEFAULT_CTL_CAPS;
	value = drt->pc_sockets[socket->socket].drt_flags;
	socket->SocketCaps = IF_IO | IF_MEMORY;
	socket->ActiveHigh = 3;	/* 0 and 1 */
	socket->ActiveLow = 0;

#ifdef	lint
	if (value > 0)
		panic("lint panic");
#endif

	return (SUCCESS);
}

/*
 * drt_inquire_window()
 *	SocketServices InquireWindow function
 *	returns detailed characteristics of the window
 *	this is where windows get tied to sockets
 */
static int
drt_inquire_window(dev_info_t *dip, inquire_window_t *window)
{
	int socket, win;
	drt_dev_t *drt = drt_get_driver_private(dip);
	struct drt_window *winp;
	iowin_char_t *io;
	mem_win_char_t *mem;

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT,
		    "drt_inquire_window: win=%d\n", window->window);
#endif
	window->WndCaps = WC_COMMON|WC_ATTRIBUTE|WC_WAIT|WC_IO;

	/* get correct socket */
	socket = window->window / DRWINDOWS;
	win = window->window % DRWINDOWS;
	winp = &drt->pc_sockets[socket].drt_windows[win];
	/* initialize the socket map - one socket per window */
	PR_ZERO(window->Sockets);
	PR_SET(window->Sockets, socket);

	io = &window->iowin_char;
	io->IOWndCaps = WC_CALIGN|WC_IO_RANGE_PER_WINDOW|WC_WENABLE|
	    WC_8BIT|WC_16BIT|WC_SIZE;
	io->FirstByte = (baseaddr_t)winp->drtw_base;
	io->LastByte = (baseaddr_t)winp->drtw_base + DRWINSIZE;
	io->MinSize = 1;
	io->MaxSize = DRWINSIZE;
	io->ReqGran = ddi_ptob(dip, 1);
	io->AddrLines = DRADDRLINES;
	io->EISASlot = 0;

	mem = &window->mem_win_char;
	mem->MemWndCaps = WC_CALIGN|WC_WENABLE|WC_8BIT|WC_16BIT;
	mem->FirstByte = (baseaddr_t)winp->drtw_base;
	mem->LastByte = (baseaddr_t)winp->drtw_base + DRWINSIZE;
#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "\tFirstByte=%p, LastByte=%p\n",
		    (void *)mem->FirstByte, (void *)mem->LastByte);
	}
#endif
	mem->MinSize = DRWINSIZE;
	mem->MaxSize = DRWINSIZE;
	mem->ReqGran = ddi_ptob(dip, 1L);
	mem->ReqBase = 0;
	mem->ReqOffset = DRWINSIZE;
	mem->Slowest = MEM_SPEED_MAX;
	mem->Fastest = MEM_SPEED_MIN;

	return (SUCCESS);
}

/*
 * drt_get_adapter()
 *	SocketServices GetAdapter function
 *	this is nearly a no-op.
 */
static int
drt_get_adapter(dev_info_t *dip, get_adapter_t *adapt)
{
	drt_dev_t *drt = drt_get_driver_private(dip);

	if (drt->pc_flags & PCF_INTRENAB)
		adapt->SCRouting = IRQ_ENABLE;
	adapt->state = 0;
	return (SUCCESS);
}

/*
 * drt_get_page()
 *	SocketServices GetPage function
 *	returns info about the window
 */
static int
drt_get_page(dev_info_t *dip, get_page_t *page)
{
	int socket, window;
	drt_dev_t *drt = drt_get_driver_private(dip);
	struct drt_window *winp;

	window = page->window % DRWINDOWS;
	socket = page->window / DRWINDOWS;

	winp = &drt->pc_sockets[socket].drt_windows[window];

	if (page->page > 0)
		return (BAD_PAGE);

	page->state = 0;

	if (winp->drtw_flags & DRW_IO)
		page->state |= PS_IO;

	if (winp->drtw_flags & DRW_ENABLED)
		page->state |= PS_ENABLED;

	if (winp->drtw_flags & DRW_ATTRIBUTE)
		page->state |= PS_ATTRIBUTE;

	page->offset = (off_t)winp->drtw_addr;

	return (SUCCESS);
}

/*
 * drt_get_socket()
 *	SocketServices GetSocket
 *	returns information about the current socket settings
 */
static int
drt_get_socket(dev_info_t *dip, get_socket_t *socket)
{
	int socknum, irq_enabled;
	drt_socket_t *sockp;
	drt_dev_t *drt = drt_get_driver_private(dip);

	socknum = socket->socket;
	sockp = &drt->pc_sockets[socknum];

	socket->SCIntMask = sockp->drt_intmask;
	socket->state = sockp->drt_state;
	socket->VccLevel = sockp->drt_vcc;
	socket->Vpp1Level = sockp->drt_vpp1;
	socket->Vpp2Level = sockp->drt_vpp2;
	socket->CtlInd = 0;	/* no indicators */
	irq_enabled = (sockp->drt_flags & DRT_INTR_ENABLED) ? IRQ_ENABLE : 0;
#if 0
	irq_enabled |= (sockp->drt_flags & DRT_INTR_HIPRI) ? IRQ_HIGH : 0;
#endif
	socket->IRQRouting = sockp->drt_irq | irq_enabled;
	socket->IFType = (sockp->drt_flags & DRT_SOCKET_IO) ? IF_IO : IF_MEMORY;
	return (SUCCESS);
}

/*
 * drt_get_status()
 *	SocketServices GetStatus
 *	returns status information about the PC Card in
 *	the selected socket
 */
static int
drt_get_status(dev_info_t *dip, get_ss_status_t *status)
{
	int socknum, irq_enabled;
	drt_socket_t *sockp;
	drt_dev_t *drt = drt_get_driver_private(dip);
#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT, "drt_get_status: drt=%p\n", (void *)drt);
	}
#endif

	if (drt == NULL) {
		return (BAD_ADAPTER);
	}

	socknum = status->socket;
	sockp = &drt->pc_sockets[socknum];

	status->CardState = drt_card_state(drt, socknum);
	status->SocketState = sockp->drt_state;
	status->CtlInd = 0;	/* no indicators */
	irq_enabled = (sockp->drt_flags & DRT_INTR_ENABLED) ? IRQ_ENABLE : 0;
	status->IRQRouting = sockp->drt_irq | irq_enabled;
	status->IFType = (sockp->drt_flags & DRT_SOCKET_IO) ?
	    IF_IO : IF_MEMORY;
	return (SUCCESS);
}

/*
 * drt_get_window()
 *	SocketServices GetWindow function
 *	returns state information about the specified window
 */
static int
drt_get_window(dev_info_t *dip, get_window_t *window)
{
	int socket, win;
	drt_socket_t *sockp;
	drt_dev_t *drt = drt_get_driver_private(dip);
	struct drt_window *winp;

	if (window->window >= DRT_NUMWINDOWS) {
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "drt_get_window: failed\n");
#endif
		return (BAD_WINDOW);
	}
	socket = window->window / DRWINDOWS;
	win = window->window % DRWINDOWS;
	window->socket = socket;
	sockp = &drt->pc_sockets[socket];
	winp = &sockp->drt_windows[win];

	window->size = winp->drtw_len;
	window->speed = winp->drtw_speed;
	window->base = (uint32_t)(uintptr_t)winp->drtw_reqaddr;
	window->handle = winp->drtw_handle;
	window->state = 0;

	if (winp->drtw_flags & DRW_IO)
		window->state |= WS_IO;

	if (winp->drtw_flags & DRW_ENABLED)
		window->state |= WS_ENABLED;
#if defined(DRT_DEBUG)
	if (drt_debug) {
		cmn_err(CE_CONT,
		    "drt_get_window: socket=%d, window=%d\n", socket, win);
		cmn_err(CE_CONT,
		    "\tsize=%d, speed=%d, base=%x, state=%x\n",
		    window->size, (int)window->speed,
		    (int)window->base,
		    window->state);
	}
#endif

	return (SUCCESS);
}

/*
 * drt_ll_reset - This function handles the socket RESET signal timing and
 *			control.
 *
 *	There are two variables that control the RESET timing:
 *		drt_prereset_time - time in mS before asserting RESET
 *		drt_reset_time - time in mS to assert RESET
 *
 * XXX - need to rethink RESET timing delays to avoid using drv_usecwait
 */
int drt_prereset_time = 1;
int drt_reset_time = 5;

static void
drt_ll_reset(drt_dev_t *drt, int socket)
{
	uint32_t value;

	value = drt->pc_csr->socket[socket].ctl0;

	if (drt_prereset_time > 0)
		drv_usecwait(drt_prereset_time * 1000);

	/* turn reset on then off again */
	drt->pc_csr->socket[socket].ctl0 = value | DRCTL_RESET;

	if (drt_reset_time > 0)
		drv_usecwait(drt_reset_time * 1000);

	drt->pc_csr->socket[socket].ctl0 = value & ~DRCTL_RESET;

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_ll_reset: socket=%d, ctl0=%x, ctl1=%x\n",
		    socket,
		    drt->pc_csr->socket[socket].ctl0,
		    drt->pc_csr->socket[socket].ctl1);
#endif
}

/*
 * drt_new_card()
 *	put socket into known state on card insertion
 */
static void
drt_new_card(drt_dev_t *drt, int socket)
{
	drt->pc_csr->socket[socket].ctl0 = 0; /* off */
	drt->pc_csr->socket[socket].ctl0 = DRT_CHANGE_DEFAULT; /* on */
	drt->pc_csr->socket[socket].ctl1 = 0;
	drt->pc_sockets[socket].drt_state = 0;
	drt->pc_sockets[socket].drt_flags = 0;
}

/*
 * drt_reset_socket()
 *	SocketServices ResetSocket function
 *	puts the PC Card in the socket into the RESET state
 *	and then takes it out after the the cycle time
 *	The socket is back to initial state when done
 */
static int
drt_reset_socket(dev_info_t *dip, int socket, int mode)
{
	drt_dev_t *drt = drt_get_driver_private(dip);
	int window;
	drt_socket_t *sockp;

	mutex_enter(&drt->pc_lock); /* protect the registers */

	drt_ll_reset(drt, socket);

	if (mode == RESET_MODE_FULL) {
		/* need to unmap windows, etc. */

		drt->pc_sockets[socket].drt_state = 0;

		for (window = 0, sockp = &drt->pc_sockets[socket];
		    window < DRT_NUMWINDOWS; window++) {
			sockp->drt_windows[window].drtw_flags &= ~DRW_ENABLED;
		}
	}

	mutex_exit(&drt->pc_lock);
	return (SUCCESS);
}

/*
 * drt_set_interrupt()
 *	SocketServices SetInterrupt function
 */
static int
drt_set_interrupt(dev_info_t *dip, set_irq_handler_t *handler)
{
	inthandler_t *intr;
	drt_dev_t *drt = drt_get_driver_private(dip);

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_set_interrupt(%p, %p) pc_handlers=%p\n",
		    (void *)dip, (void *)handler, (void *)drt->pc_handlers);
#endif

	intr = (inthandler_t *)kmem_zalloc(sizeof (inthandler_t),
	    KM_NOSLEEP);
	if (intr == NULL) {
		return (BAD_IRQ);
	}

	intr->intr = (uint32_t (*)())handler->handler;
	intr->handler_id = handler->handler_id;
	intr->arg1 = handler->arg1;
	intr->arg2 = handler->arg2;
	intr->socket = handler->socket;
	intr->irq = handler->irq;
	mutex_enter(&drt->pc_intr);
	mutex_enter(&drt->pc_lock); /* protect the registers and structures */

	if (drt->pc_handlers == NULL) {
		drt->pc_handlers = intr;
		intr->next = intr;
		intr->prev = intr;
	} else {
		insque(intr, drt->pc_handlers);
	}

	/* interrupt handlers for both interrupts already done in attach */

	/*
	 * need to fill in cookies in event of multiple high priority
	 * interrupt handlers on same IRQ
	 */
	intr->iblk_cookie = drt->pc_icookie_hi;
	intr->idev_cookie = drt->pc_dcookie_hi;
	mutex_exit(&drt->pc_lock);
	mutex_exit(&drt->pc_intr);

	handler->iblk_cookie = &intr->iblk_cookie;
	handler->idev_cookie = &intr->idev_cookie;

	return (SUCCESS);
}

/*
 * drt_clear_interrupt()
 *	SocketServices ClearInterrupt function
 *	"What  controls the socket interrupt?"
 */
static int
drt_clear_interrupt(dev_info_t *dip, clear_irq_handler_t *handler)
{
	int i = 0;
	drt_dev_t *drt = drt_get_driver_private(dip);
	inthandler_t *intr, *done;

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_clear_interrupt(%p, %p) "
		    "pc_handlers = %p\n",
		    (void *)dip, (void *)handler, (void *)drt->pc_handlers);
#endif

	mutex_enter(&drt->pc_lock); /* protect the registers */

	for (intr = drt->pc_handlers, done = drt->pc_handlers;
	    done != NULL; /* empty */) {

		if (intr->handler_id == handler->handler_id) {
			/* Check if there is only one handler left */
			if ((intr->next == intr) && (intr->prev == intr)) {
				drt->pc_handlers = NULL;
			} else {
				if (drt->pc_handlers == intr) {
					drt->pc_handlers = intr->next;
				}
				remque(intr);
			}
			kmem_free((caddr_t)intr, sizeof (inthandler_t));
			break;
		}
		intr = intr->next;
		if (intr == done)
			done = NULL;
	}

	mutex_exit(&drt->pc_lock);

#ifdef	lint
	if (i > 0)
		panic("lint panic");
#endif

	return (SUCCESS);
}

static void
drt_stop_intr(drt_dev_t *drt, int socket)
{
	inthandler_t *intr;
	int done;

	mutex_enter(&drt->pc_intr);
	for (intr = drt->pc_handlers, done = 0; !done && intr != NULL;
	    intr = intr->next) {
		if (socket == intr->socket) {
			intr->socket |= 0x8000;	/* make an illegal socket */
		}
		if (intr->next == drt->pc_handlers)
			done++;
	}
	mutex_exit(&drt->pc_intr);
}

/*ARGSUSED*/
int
drt_do_intr(drt_dev_t *drt, int socket, int priority)
{
	inthandler_t *intr, *done;
	int result = 0;

	mutex_enter(&drt->pc_intr);

#if defined(DRT_DEBUG)
	if (drt_debug > 2)
		cmn_err(CE_CONT, "drt_do_intr(%p, %d, %d)\n",
		    (void *)drt, socket, priority);
#endif

	/*
	 * If we're suspended, then we don't need to process
	 *	any more interrupts. We have already (or will
	 *	shortly) be disabling all interrupts on the
	 *	adapter, but we still need to ACK any that
	 *	we receive and that the adapter has generated.
	 * XXX - do we really want to do this here, or does it
	 *	make more sense to let the clients receive any
	 *	interrupts even as we're in the process of
	 *	suspending?
	 */
	if (drt->pc_flags & PCF_SUSPENDED) {
		mutex_exit(&drt->pc_intr);
		return (DDI_INTR_CLAIMED);
	}

#if defined(DRT_DEBUG)
	if (drt_debug && drt->pc_handlers == NULL)
		cmn_err(CE_CONT, "drt_do_intr: pc_handlers == NULL\n");
#endif
	for (intr = drt->pc_handlers, done = drt->pc_handlers;
	    done != NULL && intr != NULL; intr = intr->next) {
#if defined(DRT_DEBUG)
		if (drt_debug > 2)
			cmn_err(CE_CONT,
			    "\tintr-> socket=%d, priority=%d, intr=%p,"
			    "arg1=%p arg2=%p (drt_flags=%x:%s)\n",
			    intr->socket, intr->priority,
			    (void *)intr->intr, intr->arg1, intr->arg2,
			    drt->pc_sockets[socket].drt_flags,
			    (drt->pc_sockets[socket].drt_flags &
			    DRT_INTR_ENABLED) ?
			    "true":"false");
#endif
#if 0
		/* may need to rethink the priority stuff */
		if (socket == intr->socket &&
		    (priority ^ (intr->priority < 10)) &&
		    drt->pc_sockets[socket].drt_flags & DRT_INTR_ENABLED) {
			result |= (*intr->intr)(intr->arg);
		}
#else
		result |= (*intr->intr)(intr->arg1, intr->arg2);
#endif
		if (done == intr->next)
			done = NULL;
	}
	/* do a round robin adjust */
	if (drt->pc_handlers != NULL)
		drt->pc_handlers = drt->pc_handlers->next;
	mutex_exit(&drt->pc_intr);
	return (result);
}

uint32_t
drt_hi_intr(caddr_t arg)
{
	drt_dev_t *drt = drt_get_driver_private((dev_info_t *)arg);
	int i, intr_sockets = 0;
	int result, changes;

	mutex_enter(&drt->pc_lock);

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_hi_intr: entered\n");
#endif

	/*
	 * need to change to only ACK and touch the slot that
	 * actually caused the interrupt.  Currently everything
	 * is acked
	 *
	 * we need to look at all known sockets to determine
	 * what might have happened, so step through the list
	 * of them
	 */
	result = 0;

	for (i = 0; i < DRSOCKETS; i++) {
		int card_type;
		int x = drt->pc_cb_arg;
		drt_socket_t *sockp;

		sockp = &drt->pc_sockets[i];

		if (drt->pc_csr->socket[i].ctl0 & DRCTL_IFTYPE)
			card_type = IF_IO;
		else
			card_type = IF_MEMORY;

		changes = drt->pc_csr->socket[i].stat0;
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "\tstat0=%x, type=%s\n",
			    changes, card_type == IF_IO ? "IO":"MEM");
#endif
		/* ack the interrupts we see */
		drt->pc_csr->socket[i].stat0 = (ushort_t)changes;

		if (changes & DRSTAT_SCINT) {
#if defined(DRT_DEBUG)
			if (drt_debug)
				cmn_err(CE_CONT,
				    "\tcard status change interrupt"
				    " on socket %d\n", i);
#endif
			/*
			 * We set the result here mainly for IF_MEMORY cases.
			 * The drt_do_intr() call at the end of this for loop
			 * will not be called for IF_MEMORY cases since
			 * intr_sockets are set ONLY for IF_IO cases.
			 */
			result |= DDI_INTR_CLAIMED;

			/* there was a valid interrupt on status change  */
			if (drt->pc_callback == NULL) {
				/* nothing to do */
				continue;
			}
			if (changes & DRSTAT_CDCHG) {
				if ((sockp->drt_flags &
				    DRT_CARD_PRESENT) &&
				    (changes & DRSTAT_CD_MASK) !=
				    DRSTAT_PRESENT_OK) {
					sockp->drt_flags &=
					    ~DRT_CARD_PRESENT;
					/*
					 * stop interrupt handler
					 * then do the callback
					 */
					drt_stop_intr(drt, i);
					/*
					 * XXX - note that drt_new_card will
					 *	clear sockp->drt_flags
					 */
					drt_new_card(drt, i); /* paranoia */
					PC_CALLBACK(drt, arg, x,
					    PCE_CARD_REMOVAL, i);
					continue;
				} else {
					if ((changes & DRSTAT_CD_MASK) ==
					    DRSTAT_PRESENT_OK &&
					    !(sockp->drt_flags &
					    DRT_CARD_PRESENT)) {
						drt_new_card(drt, i);
						drt_ll_reset(drt, i);
						sockp->drt_state |= SBM_CD;
						drt_socket_card_id(drt,
						    sockp,
						    changes);
						PC_CALLBACK(drt, arg, x,
						    PCE_CARD_INSERT,
						    i);
						continue;
					}
				}
				/*
				 * since other events may be the result of
				 * "bounce", don't check them on this pass.
				 * The insert code will check them anyway.
				 */
				continue;
			}

			/* Ready/Change Detect */
#if defined(DRT_DEBUG)
			if (drt_debug && changes & DRSTAT_RDYCHG)
				cmn_err(CE_CONT, "\trdychg: stat=%x, type=%s\n",
				    changes,
				    card_type == IF_MEMORY ?
				    "memory" : "I/O");
#endif
			if (card_type == IF_MEMORY &&
			    changes & DRSTAT_RDYCHG &&
			    changes & DRSTAT_RDYST) {
				sockp->drt_state |= SBM_RDYBSY;
				PC_CALLBACK(drt, arg, x, PCE_CARD_READY, i);
			}

			/* write protect switch moved */
			if (card_type == IF_MEMORY && changes & DRSTAT_WPCHG) {
				if (changes & DRSTAT_WPST)
					sockp->drt_state |= SBM_WP;
				else
					sockp->drt_state &= ~SBM_WP;
				PC_CALLBACK(drt, arg, x,
				    PCE_CARD_WRITE_PROTECT, i);
			}

			if (card_type == IF_MEMORY &&
			    changes & DRSTAT_BVDCHG) {
				/*
				 * there was a change in battery state.
				 * this could be a false alarm at
				 * card insertion but could be real.
				 * The individual change bits aren't
				 * meaningful so look at the live
				 * status and latch that
				 */
				switch (changes & DRSTAT_BVDST) {
				case DRSTAT_BATT_LOW:
					if (!(sockp->drt_flags &
					    DRT_BATTERY_LOW)) {
						sockp->drt_flags |=
						    DRT_BATTERY_LOW;
						sockp->drt_state |= SBM_BVD2;
						sockp->drt_state &= ~SBM_BVD1;
						PC_CALLBACK(drt, arg, x,
						    PCE_CARD_BATTERY_WARN,
						    i);
					}
					break;
				case DRSTAT_BATT_OK:
					sockp->drt_state &=
					    ~(DRT_BATTERY_LOW|
					    DRT_BATTERY_DEAD);
					sockp->drt_state &=
					    ~(SBM_BVD1|SBM_BVD2);
					break;
				default: /* battery failed */
					if (!(sockp->drt_flags &
					    DRT_BATTERY_DEAD)) {
						/* so we only see one of them */
						sockp->drt_flags |=
						    DRT_BATTERY_DEAD;
						sockp->drt_flags &=
						    DRT_BATTERY_LOW;
						sockp->drt_state |= SBM_BVD1;
						PC_CALLBACK(drt, arg, x,
						    PCE_CARD_BATTERY_DEAD,
						    i);
					}
				}
			}
			if (card_type == IF_IO &&
			    !(changes & DRSTAT_BVD1ST)) {
				/*
				 * Disable status change interrupts. We
				 *	will enable them again later after
				 *	Card Services has processed this
				 *	event.
				 */
				drt->pc_csr->socket[i].ctl0 &=
				    ~DRCTL_BVD1IE;

				/* we have an I/O status change */
				PC_CALLBACK(drt, arg, x,
				    PCE_CARD_STATUS_CHANGE,
				    i);
			}
#if 0
			/*
			 * need to reexamine this section to see what really
			 * needs to be done
			 */
			/* Battery Warn Detect */
			if (changes & DRSTAT_BVD2CHG) {
				if (card_type == IF_MEMORY &&
				    !(sockp->drt_flags & DRT_BATTERY_LOW)) {
					sockp->drt_flags |= DRT_BATTERY_LOW;
					sockp->drt_state |= SBM_BVD2;
					PC_CALLBACK(drt, arg, x,
					    PCE_CARD_BATTERY_WARN,
					    i);
				} else if (card_type == IF_IO) {
					PC_CALLBACK(drt, arg, x,
					    PCE_CARD_STATUS_CHANGE,
					    i);
				}
			}

			/* Battery Fail Detect */
			if (card_type == IF_MEMORY &&
			    changes & DRSTAT_BVD1CHG &&
			    !(sockp->drt_flags & DRT_BATTERY_DEAD)) {
				/* so we only see one of them */
				sockp->drt_flags |= DRT_BATTERY_DEAD;
				sockp->drt_state |= SBM_BVD1;
				PC_CALLBACK(drt, arg, x,
				    PCE_CARD_BATTERY_DEAD, i);
			}
#endif
		}
		/* now flag any PC Card interrupts */
		if (card_type == IF_IO && changes & DRSTAT_IOINT) {
			intr_sockets |= 1 << i;
		}
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "\tsocket %d: ctl0=%x, ctl1=%x\n",
			    i,
			    drt->pc_csr->socket[i].ctl0,
			    drt->pc_csr->socket[i].ctl1);
#endif
	}

	mutex_exit(&drt->pc_lock);

	for (i = 0; i < DRSOCKETS; i++) {
		if (intr_sockets & (1 << i))
			result |= drt_do_intr(drt, i, 1);
	}

	if (changes & DRSTAT_SCINT || result || intr_sockets)
		return (DDI_INTR_CLAIMED);
	if (drt->pc_flags & PCF_ATTACHING) {
		drt->pc_flags &= ~PCF_ATTACHING;
		return (DDI_INTR_CLAIMED);
	}

	return (DDI_INTR_UNCLAIMED);
}

uint32_t
drt_lo_intr(caddr_t arg)
{
	drt_dev_t *drt = drt_get_driver_private((dev_info_t *)arg);
	int i, result;

#if defined(DRT_DEBUG)
	if (drt_debug)
		cmn_err(CE_CONT, "drt_lo_intr(%p)\n", (void *)arg);
#endif
	/*
	 * we need to look at all known sockets to determine
	 * what might have happened, so step through the list
	 * of them
	 */

	/* XXX is this the lost interrupt problem?? XXX */
	for (i = 0, result = 0; i < drt->pc_numsockets; i++) {
		if (drt->pc_csr->socket[i].stat0 & DRSTAT_IOINT) {
#if defined(DRT_DEBUG)
			if (drt_debug)
				cmn_err(CE_CONT, "\tsocket=%x, stat0=%x\n",
				    i, drt->pc_csr->socket[i].stat0);
#endif
			result |= drt_do_intr(drt, i, 0);
			drt->pc_csr->socket[i].stat0 |= DRSTAT_IOINT;
		}
	}
	if (result)
		return (DDI_INTR_CLAIMED);
	return (DDI_INTR_UNCLAIMED);
}

/*
 * drt_socket_card_id()
 *	figure out current status of card in socket
 *	this is used to prevent callbacks at card insertion
 */
/* ARGSUSED */
void
drt_socket_card_id(drt_dev_t *drt, drt_socket_t *socket, int status)
{

	/* need to record if a card is present to init state */
	if ((status & DRSTAT_CD_MASK) == DRSTAT_PRESENT_OK)
		socket->drt_flags |= DRT_CARD_PRESENT;

	/* check battery state to avoid callbacks */
	switch (status & DRSTAT_BVDST) {
	case DRSTAT_BATT_LOW:
		socket->drt_flags |= DRT_BATTERY_LOW;
		socket->drt_flags &= ~DRT_BATTERY_DEAD;
		socket->drt_state |= SBM_BVD2;
		socket->drt_state &= ~SBM_BVD1;
		break;
	case DRSTAT_BATT_OK:
		socket->drt_flags &= ~(DRT_BATTERY_LOW|DRT_BATTERY_DEAD);
		socket->drt_state &= ~(SBM_BVD1|SBM_BVD2);
		break;
	default:
				/* battery dead */
		socket->drt_flags |= DRT_BATTERY_DEAD;
		socket->drt_state |= SBM_BVD1;
		break;
	}

	/* check write protect status */
	if (status & DRSTAT_WPST)
		socket->drt_state |= SBM_WP;
	else
		socket->drt_state &= ~SBM_WP;

	/* and ready/busy */
	if (status & DRSTAT_RDYST)
		socket->drt_state |= SBM_RDYBSY;
	else
		socket->drt_state &= ~SBM_RDYBSY;
}

#if defined(DRT_DEBUG)
static void
drt_dmp_regs(stp4020_socket_csr_t *csrp)
{
	int i;

	cmn_err(CE_CONT, "drt_dmp_regs (%p):\n", (void *)csrp);
	cmn_err(CE_CONT, "\tctl0: %b\n", csrp->ctl0,
	    "\020\1IFTYPE\2SFTRST\3SPKREN\4IOILVL\5IOIE\6RSVD"
	    "\7CTOIE\010WPIE\011RDYIE\012BVD1IE\013BVD2IE\014CDIE"
	    "\015SCILVL\016PROMEN\017RSVDX");
	cmn_err(CE_CONT,
	    "\tctl1: %b\n", csrp->ctl1,
	    "\020\1PCIFOE\1MSTPWR\7APWREN"
	    "\10RSVD\11DIAGEN\12WAITDB\13WPDB\14RDYDB\15BVD1DB\16BVD2DB"
	    "\17CD1DB\20LPBKEN");
	cmn_err(CE_CONT,
	    "\tstat0: %b\n", csrp->stat0,
	    "\020\1PWRON\2WAITST\3WPST"
	    "\4RDYST\5BVD1ST\6BVD2ST\7CD1ST\10CD2ST\11PCTO\12WPCHG"
	    "\13RDCHG\14BVD1CHG\15BVD2CHG\16CDCHG\17SCINT\20IOINT");
	cmn_err(CE_CONT,
	    "\tstat1: types=%x, rev=%x\n",
	    (int)(csrp->stat1 & DRSTAT_PCTYS_M),
	    csrp->stat1 & DRSTAT_REV_M);
	for (i = 0; i < 3; i++) {
		cmn_err(CE_CONT, "\twin%d:\tctl0: cmdlng=%x, cmddly=%x, "
		    "aspsel=%x, base=%x\n", i,
		    GET_DRWIN_CMDLNG(csrp->window[i].ctl0),
		    GET_DRWIN_CMDDLY(csrp->window[i].ctl0),
		    csrp->window[i].ctl0 & DRWIN_ASPSEL_M,
		    GET_DRWIN_BASE(csrp->window[i].ctl0));
		cmn_err(CE_CONT, "\t\tctl1: %x\n", csrp->window[i].ctl1);
	}
}

#endif

/*
 * drt_cpr - save/restore the adapter's hardware state
 */
static void
drt_cpr(drt_dev_t *drt, int cmd)
{
	int sn, wn;

	switch (cmd) {
		case DRT_SAVE_HW_STATE:
		for (sn = 0; sn < DRSOCKETS; sn++) {
			stp4020_socket_csr_t *drs = &drt->pc_csr->socket[sn];
			for (wn = 0; wn < DRWINDOWS; wn++) {
				drt->saved_socket[sn].window[wn].ctl0 =
				    drs->window[wn].ctl0;
				drt->saved_socket[sn].window[wn].ctl1 =
				    drs->window[wn].ctl1;
			}
			drt->saved_socket[sn].ctl0 = drs->ctl0;
			drt->saved_socket[sn].ctl1 = drs->ctl1;
		}
		break;
		case DRT_RESTORE_HW_STATE:
		for (sn = 0; sn < DRSOCKETS; sn++) {
			stp4020_socket_csr_t *drs = &drt->pc_csr->socket[sn];
			for (wn = 0; wn < DRWINDOWS; wn++) {
				drs->window[wn].ctl0 =
				    drt->saved_socket[sn].window[wn].ctl0;
				drs->window[wn].ctl1 =
				    drt->saved_socket[sn].window[wn].ctl1;
			}

			/* work around for false status bugs */
			/* XXX - why 0x3FFF and not 0xFFFF?? */
			drs->stat0 = 0x3FFF;
			drs->stat1 = 0x3FFF;

			drs->ctl0 = drt->saved_socket[sn].ctl0;
			drs->ctl1 = drt->saved_socket[sn].ctl1;
		}
		break;
	} /* switch */

}

/*
 * drt_fixprops(dip)
 *	if the adapter predates 1275 properties, add them.
 *	We do this by checking presence of the property
 *	and adding what we know if properties not present
 */
/* ARGSUSED */
static void
drt_fixprops(dev_info_t *dip)
{

	/*
	 * note that there are a number of properties that
	 * should be added here if not present
	 */

}




/*
 * stpra_alloc_map()
 *	allocate an stpramap structure.
 */

struct stpramap *
stpra_alloc_map()
{
	struct stpramap *new;
	mutex_enter(&stpra_lock);
	new = NULL;
	if (stpra_freelist != NULL) {
		new = stpra_freelist;
		stpra_freelist = new->ra_next;
	}
	mutex_exit(&stpra_lock);
	if (new == NULL) {
		new = (struct stpramap *)kmem_zalloc(sizeof (struct stpramap),
		    KM_SLEEP);
	} else {
		bzero((caddr_t)new, sizeof (struct stpramap));
	}
	return (new);
}

/*
 * stpra_free_map(map)
 *	return a used map to the freelist.
 *	Should probably check to see if above
 *	some threshold and kmem_free() any excess
 */
void
stpra_free_map(struct stpramap *map)
{
	if (map != NULL) {
		mutex_enter(&stpra_lock);
		map->ra_next = stpra_freelist;
		stpra_freelist = map;
		mutex_exit(&stpra_lock);
	}
}


/*
 * stpra_free(map, base, len)
 *	return the specified range (base to base+len)
 *	to the specified map
 */

void
stpra_free(struct stpramap **map, uint32_t base, uint32_t len)
{
	struct stpramap *newmap, *oldmap = NULL;
	struct stpramap *mapp, *backp;
	uint32_t newbase, mapend;

	/*
	 * always allocate a map entry so we can manipulate
	 * things without blocking inside our lock
	 */
	newmap = stpra_alloc_map();
	ASSERT(newmap);

	mutex_enter(&stpra_lock);

	mapp = *map;
	backp = (struct stpramap *)map;

	/* now find where range lies and fix things up */
	newbase = base + len;
	for (; mapp != NULL; backp = mapp, mapp = mapp->ra_next) {
		mapend = mapp->ra_base + mapp->ra_len;
		if (mapend == 0) {
			/*
			 * special case: sum is larger than 32bit
			 */
			mapend = mapp->ra_len;
		}
		if (newbase == mapp->ra_base) {
			/* simple - on front */
			mapp->ra_base = base;
			mapp->ra_len += len;
			/*
			 * don't need to check if it merges with
			 * previous since that would match on on end
			 */
			break;
		} else if (newbase == mapend) {
			/* simple - on end */
			mapp->ra_len += len;
			if (mapp->ra_next && newbase ==
			    mapp->ra_next->ra_base) {
				/* merge with next node */
				oldmap = mapp->ra_next;
				mapp->ra_len += oldmap->ra_len;
				mapp->ra_next = oldmap->ra_next;
			}
			break;
		} else if (base < mapp->ra_base) {
			/* somewhere in between so just an insert */
			newmap->ra_base = base;
			newmap->ra_len = len;
			newmap->ra_next = mapp;
			backp->ra_next = newmap;
			newmap = NULL;
			break;
		}
		/* else haven't found the spot yet */
	}
	if (mapp == NULL) {
		/* special case of running off the end - stick on end */
		newmap->ra_base = base;
		newmap->ra_len = len;
		backp->ra_next = newmap;
		newmap = NULL;
	}
	mutex_exit(&stpra_lock);
	if (newmap != NULL)
		stpra_free_map(newmap);
	if (oldmap != NULL)
		stpra_free_map(oldmap);
}

/*
 * stpra_alloc(map, reqest, return)
 *	Allocate a memory-like resource (physical memory, I/O space)
 *	subject to the constraints defined in the request structure.
 */

int
stpra_alloc(struct stpramap **map, stpra_request_t *req, stpra_return_t *ret)
{
	struct stpramap *mapp, *backp;
	struct stpramap *newmap, *old = NULL;
	int type = 0, len;
	uint32_t mask = 0;
	int newlen, rval = DDI_FAILURE;
	uint32_t base, lower, upper;

	if (req->ra_flags & STP_RA_ALLOC_SPECIFIED)
		type = STP_RA_ALLOC_SPECIFIED;
	else
		type = 0;

	if (req->ra_flags & (STP_RA_ALLOC_POW2|STP_RA_ALIGN_SIZE)) {
		if (req->ra_len != stpra_fix_pow2(req->ra_len)) {
#if defined(DRT_DEBUG)
			if (drt_debug)
				cmn_err(CE_WARN, "ra: bad length (pow2) %d\n",
				    req->ra_len);
#endif
			ret->ra_addr_hi = 0;
			ret->ra_addr_lo = 0;
			ret->ra_len = 0;
			return (DDI_FAILURE);
		}
	}
	mask = req->ra_align;
	if (req->ra_flags & STP_RA_ALIGN_SIZE) {
		len = stpra_fix_pow2(req->ra_len);
		mask = len - 1;
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "len=%d, mask=%x\n", len, mask);
#endif
	}

	newmap = stpra_alloc_map(); /* just in case */

	mutex_enter(&stpra_lock);

	mapp = *map;
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "stpra_alloc: mapp = %p\n",
			    (void *)mapp);
#endif

	backp = (struct stpramap *)map;

	len = req->ra_len;

	lower = 0;
	upper = ~(uint32_t)0;



	if (type != STP_RA_ALLOC_SPECIFIED) {
		/* first fit - not user specified */
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "stpra_alloc(unspecified request)"
			    "lower=%x, upper=%x\n", lower, upper);
#endif
		for (; mapp != NULL; backp = mapp, mapp = mapp->ra_next) {
#if defined(DRT_DEBUG)
		if (drt_debug)
			cmn_err(CE_CONT, "stpra_alloc: ra_len = %x, len = %x",
			    mapp->ra_len, len);
#endif

			if (mapp->ra_len >= len) {
				/* a candidate -- apply constraints */
				base = mapp->ra_base;
				if (base < lower &&
				    (base + mapp->ra_len) < (lower + len)) {
					if (((base + mapp->ra_len) != 0) ||
					    ((base + mapp->ra_len) >
					    mapp->ra_len))
					    /* same as the above case */
						continue;
				}
				if (base < lower)
					base = lower;
#if defined(DRT_DEBUG)
				if (drt_debug)
					cmn_err(CE_CONT,
					    "\tbase=%x, ra_base=%x,"
					    "mask=%x\n",
					    base, mapp->ra_base, mask);
#endif
				if ((mapp->ra_base & mask) != 0) {
					/*
					 * failed a critical constraint
					 * adjust and see if it still fits
					 */
					base = mapp->ra_base & ~mask;
					base += (mask + 1);
#if defined(DRT_DEBUG)
					if (drt_debug)
						cmn_err(CE_CONT,
						    "\tnew base=%x\n",
						    base);
#endif
					if (len > (mapp->ra_len -
					    (base - mapp->ra_base)))
						continue;
				}
				/* we have a fit */
#if defined(DRT_DEBUG)
				if (drt_debug)
					cmn_err(CE_CONT, "\thave a fit\n");
#endif
#ifdef lint
				upper = upper; /* need to check upper bound */
#endif
				if (base != mapp->ra_base) {
					/* in the middle or end */
					newlen = base - mapp->ra_base;
					if ((mapp->ra_len - newlen) == len) {
						/* on the end */
						mapp->ra_len = newlen;
					} else {
						newmap->ra_next = mapp->ra_next;
						newmap->ra_base = base + len;
						newmap->ra_len = mapp->ra_len -
						    (len + newlen);
						mapp->ra_len = newlen;
						mapp->ra_next = newmap;
						newmap = NULL;
					}

				} else {
					/* at the beginning */
					mapp->ra_base += len;
					mapp->ra_len -= len;
					if (mapp->ra_len == 0) {
						/* remove the whole node */
						backp->ra_next = mapp->ra_next;
						old = mapp;
					}
				}
				rval = DDI_SUCCESS;
				break;
			}
		}
	} else {
		/* want an exact value/fit */
		base = req->ra_addr_lo;
		len = req->ra_len;
		for (; mapp != NULL; backp = mapp, mapp = mapp->ra_next) {
			if (base >= mapp->ra_base &&
			    base < (mapp->ra_base + mapp->ra_len)) {
			    /* this is the node */
				if ((base + len) >
				    (mapp->ra_base + mapp->ra_len)) {
				    /* no match */
					base = 0;
				} else {
				    /* this is the one */
					if (base == mapp->ra_base) {
					    /* at the front */
						mapp->ra_base += len;
						mapp->ra_len -= len;
						if (mapp->ra_len == 0) {
						    /* used it up */
							old = mapp;
							backp->ra_next =
							    mapp->ra_next;
						}
					} else {
					    /* on the end or in middle */
						if ((base + len) ==
						    (mapp->ra_base +
						    mapp->ra_len)) {
						    /* on end */
							mapp->ra_len -= len;
						} else {
							uint32_t
							    newbase, newlen;
							/* in the middle */
							newbase = base + len;
							newlen =
							    (mapp->ra_base +
							    mapp->ra_len) -
							    newbase;
							newmap->ra_base =
							    newbase;
							newmap->ra_len = newlen;
							newmap->ra_next =
							    mapp->ra_next;
							mapp->ra_next = newmap;
							mapp->ra_len -=
							    newlen + len;
							newmap = NULL;
						}
					}
				}
				rval = DDI_SUCCESS;
				break;
			}
		}
	}

	mutex_exit(&stpra_lock);

	if (old)
		stpra_free_map(old);
	if (newmap)
		stpra_free_map(newmap);


	if (rval == DDI_SUCCESS) {
		ret->ra_addr_hi = 0;
		ret->ra_addr_lo = base;
		ret->ra_len = req->ra_len;
	}
	return (rval);
}




/*
 * stpra_fix_pow2(value)
 *	a utility function which rounds up to the
 *	nearest power of two value.
 */

uint32_t
stpra_fix_pow2(uint32_t value)
{
	int i;

	if (ddi_ffs(value) == ddi_fls(value))
		return (value);
	/* not a power of two so round up */
	i = ddi_fls(value);
	/* this works since ffs/fls is plus 1 */
#if defined(DRT_DEBUG)
	if (drt_debug)  {
		cmn_err(CE_CONT, "stpra_fix_pow2(%x)->%x:%x\n", value, i,
		    1 << i);
		cmn_err(CE_CONT,
		    "\tffs=%d, fls=%d\n", ddi_ffs(value), ddi_fls(value));
	}
#endif
	return (1 << i);
}
