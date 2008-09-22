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
 *	Source code for the bidirectional parallel port
 *	driver for the Zebra SBus card, and the parallel
 *	port in the DMA2P and MACHIO.
 *
 * For any questions/problems, contact deborah@eng.
 */

/*		#includes below			*/
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/dmaga.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/kstat.h>

#include <sys/bpp_io.h>
#include <sys/bpp_reg.h>
#include <sys/bpp_var.h>

/*		structure definitions below			*/

static struct	bpp_transfer_parms	bpp_default_transfer_parms = {
	BPP_ACK_BUSY_HS,		/* read_handshake */
	1000,				/* read_setup_time - 1 us */
	1000,				/* read_strobe_width - 1 us */
	60,				/* read_timeout - 1 minute */
	BPP_ACK_HS,			/* write_handshake */
	1000,				/* write_setup_time - 1 us */
	1000,				/* write_strobe_width - 1 us */
	60,				/* write_timeout - 1 minute */
};

static struct bpp_pins		bpp_default_pins = {
	0,				/* output pins	*/
	0,				/* input pins	*/
};

static struct bpp_error_status	bpp_default_error_stat = {
	0,				/* no timeout		*/
	0,				/* no bus error		*/
	0,				/* no pin status set	*/
};


/*		static variable declarations below		*/

					/* array of pointers to unit structs */
static	int	sbus_clock	= 0;	/* sbus clock freq prop in MHz */
static	int	sbus_cycle	= 0;	/* sbus clock prop period in nsec */
static	void *bpp_state_head;		/* opaque handle top of state structs */


static ddi_dma_attr_t	bpp_dma_attr = {
	DMA_ATTR_V0,		/* version */
	0x00000000ull,		/* dlim_addr_lo */
	0xffffffffull,		/* dlim_addr_hi */
	((1<<24)-1),		/* inclusive upper bound of */
				/* bpp dma address counter  */
				/* lower 24 bits are a counter, */
				/* upper 8 bits are registered */
	1,			/* DMA address alignment */
	DEFAULT_BURSTSIZE,	/* encoded burstsizes */
	0x1,			/* min effective DMA size */
	0x7fffffff,		/* max DMA xfer size */
	0x00ffffff,		/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA flags */
};

static ddi_device_acc_attr_t bpp_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_BE_ACC,
	DDI_STRICTORDER_ACC
};

#define	KIOIP	KSTAT_INTR_PTR(bpp_p->intrstats)

#define	getsoftc(unit) \
	((struct bpp_unit *)ddi_get_soft_state(bpp_state_head, (unit)))

#ifndef BPP_DEBUG
#define	BPP_DEBUG 0
#endif	/* BPP_DEBUG */


#if	BPP_DEBUG > 0
static	int bpp_debug = BPP_DEBUG;
#define	BPP_PRINT(level, args)	_STMT(if (bpp_debug >= (level)) \
					cmn_err args; /* space */)
#else
#define	BPP_PRINT(level, args)	/* nothing */
#endif	/* BPP_DEBUG */

/*		private procedure declarations below		*/
/* Autoconfig Declarations */
static	int	bpp_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result);
static	int	bpp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);

/* Driver function Declarations */
static	int	bpp_open(dev_t *dev, int openflags, int otyp, cred_t *credp);
static	int	bpp_close(dev_t dev, int openflags, int otyp, cred_t *credp);
static	int	bpp_read(dev_t dev, struct uio *uiop, cred_t *credp);
static	int	bpp_write(dev_t dev, struct uio *uiop, cred_t *credp);
static	int	bpp_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
			cred_t *credp, int *rvalp);
static	uint_t	bpp_intr();
static	int	bpp_strategy(register struct buf *bp);
static	void	bpp_minphys(struct buf *bp);

/* Utility Function Declarations */
static	int	check_bpp_registers(int unit_no);
static	void	set_dss_dsw(int unit_no, int read_mode);
static	ushort_t check_write_params(struct  bpp_transfer_parms *parms_p,
		int unit, int flags);
static	ushort_t check_read_params(struct  bpp_transfer_parms *parms_p,
		uint_t unit, int flags);
static	ushort_t check_read_pins(struct  bpp_pins *pins_p,
		int flags, uint_t unit, register enum handshake_t handshake);
static	ushort_t check_write_pins(struct  bpp_pins *pins_p,
		int flags, uint_t unit, register enum handshake_t handshake);
static	void	read_outpins(int unit_no, int flags,
			register enum   handshake_t handshake);
static	void	check_for_active_pins(int unit_no);
static	int	bpp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static	void 	bpp_transfer_timeout(void *unit_no_arg);
static	void	bpp_transfer_failed(int unit_no);

/*
 * The bpp_cb_ops struct enables the kernel to find the
 * rest of the driver entry points.
 */
static struct cb_ops	bpp_cb_ops = {
	bpp_open,		/* driver open routine		*/
	bpp_close,		/* driver close routine		*/
	nulldev,		/* driver strategy routine - block devs only */
	nodev,			/* driver print routine		*/
	nodev,			/* driver dump routine		*/
	bpp_read,		/* driver read routine		*/
	bpp_write,		/* driver write routine		*/
	bpp_ioctl,		/* driver ioctl routine		*/
	nodev,			/* driver devmap routine	*/
	nulldev,		/* driver mmap routine		*/
	nulldev,		/* driver segmap routine	*/
	nochpoll,		/* driver chpoll routine	*/
	ddi_prop_op,		/* driver prop_op routine	*/
	0,			/* driver cb_str - STREAMS only */
	D_NEW | D_MP		/* driver compatibility flag	*/
};

/*
 * The bpp_ops struct enables the kernel to find the
 * bpp loadable module routines.
 */
static struct dev_ops bpp_ops =
{
	DEVO_REV,			/* revision number		*/
	0,				/* device reference count	*/
	bpp_getinfo,			/* driver get_dev_info routine	*/
	nulldev,			/* confirm device ID		*/
	nulldev,			/* device probe for non-self-id */
	bpp_attach,			/* attach routine of driver	*/
	bpp_detach,			/* device detach routine	*/
	nodev,				/* device reset routine		*/
	&bpp_cb_ops,			/* device operations struct	*/
	(struct bus_ops *)0,		/* bus operations		*/
	NULL,				/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


/*
 * The bpp_drv structure provides the linkage between the vd driver
 * (for loadable drivers) and the dev_ops structure for this driver
 * (bpp_ops).
 */
static	struct modldrv modldrv = {
	&mod_driverops,				/* type of module - driver */
	"pport driver: bpp",			/* name of module  */
	&bpp_ops				/* *Drv_dev_ops		*/
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/* Autoconfig Support Functions */

/*
 *	bpp_attach()
 *
 * Allocate unit structures.
 * Map the bpp device registers into kernel virtual memory.
 * Add the bpp driver to the level 2 interrupt chain.
 * Initialize the bpp portion of the zebra card.
 * Turn on the interrupts.
 */
static int
bpp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		unit_no;	/* attaching unit's number */
	int	sbus_frequency;		/* sbus clock frequency (in cycles) */
	int	burst_sizes;		/* sbus burst sizes, encoded */
	char name[16];			/* name to pass to minor node */

	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	volatile struct bpp_regs	*bpp_regs_p;


	unit_no = ddi_get_instance(dip);
	BPP_PRINT(2, (CE_CONT, "Entering bpp_attach, unit %d\n", unit_no));

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((bpp_p = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);
		mutex_enter(&bpp_p->bpp_mutex);
		if (!(bpp_p->flags & BPP_SUSPENDED)) {
			mutex_exit(&bpp_p->bpp_mutex);
			return (DDI_FAILURE);
		}
		bpp_p->flags &= ~BPP_SUSPENDED;
		mutex_exit(&bpp_p->bpp_mutex);
		bpp_regs_p = bpp_p->bpp_regs_p;
		goto initialise;

	default:
			return (DDI_FAILURE);
	}

	/* Make sure we're not in a slave-only slot */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		cmn_err(CE_NOTE,
		    "bpp unit %d: NOT used - SBus slot is slave only.",
		    unit_no);
		return (DDI_FAILURE);
	}


	/*
	 * Allocate a unit structure for this unit.
	 * Each bpp_unit struct is allocated as zeroed memory.
	 * Store away its address for future use.
	 */
	BPP_PRINT(5, (CE_CONT, "Allocating unit struct for unit %d.\n",
	    unit_no));
	if (ddi_soft_state_zalloc(bpp_state_head, unit_no) != 0)
		return (DDI_FAILURE);
	/* assign a pointer to this unit's state struct */
	bpp_p = getsoftc(unit_no);
	ddi_set_driver_private(dip, bpp_p);

	/*
	 * Initialize the unit structures. The unit structure for
	 * each unit is initialized when bpp_attach is called for that unit.
	 */

	/*
	 * For devices that issue interrupts, the driver must install
	 * itself on the interrupt chain for each level that the hardware
	 * can interrupt at.
	 * This must be done before expecting to receive any interrupts.
	 */
	if (ddi_add_intr(dip, 0, &bpp_p->bpp_block_cookie,
	    (ddi_idevice_cookie_t *)0, bpp_intr,
	    (caddr_t)(uintptr_t)unit_no) != DDI_SUCCESS) {
		cmn_err(CE_NOTE,
		    "bpp_attach unit %d: cannot add interrupt!", unit_no);
		ddi_soft_state_free(bpp_state_head, unit_no);
		return (DDI_FAILURE);
	}
	BPP_PRINT(5, (CE_CONT, "Installed bpp_poll: unit %d\n", unit_no));

	cv_init(&bpp_p->wr_cv, NULL, CV_DRIVER, NULL);

	/*
	 * Initialize the bpp mutex.
	 * This mutex is used for all operations outside of attach.
	 */
	mutex_init(&bpp_p->bpp_mutex, NULL, MUTEX_DRIVER,
	    (void *)bpp_p->bpp_block_cookie);

	/*
	 * Save the devinfo pointer for this unit.
	 * Initialize the interupt cookie.
	 * Inhibit opens on this unit until initialization is successful.
	 */
	bpp_p->dip = dip;

	/*
	 * Initialize the transfer parameters structure for this unit.
	 */
	bpp_p->transfer_parms = bpp_default_transfer_parms;

	/*
	 * Initialize the control pins structure for this unit.
	 */
	bpp_p->pins = bpp_default_pins;

	/*
	 * Initialize the error status structure for this unit.
	 * Initialize the timeout status byte for this unit.
	 * Initialize the timeout idents for this unit.
	 */
	bpp_p->error_stat = bpp_default_error_stat;
	bpp_p->timeouts = NO_TIMEOUTS;
	BPP_PRINT(5, (CE_CONT, "Timeout block is 0x%x.\n", bpp_p->timeouts));
	bpp_p->bpp_transfer_timeout_ident = 0;
	bpp_p->bpp_fakeout_timeout_ident = 0;

	/*
	 * Check that the clock-frequency property is in
	 * a sensible range. If it isn't, the math used when setting
	 * the transfer parameters strobe and width times will
	 * fail. Flag the future problem here rather than in the ioctl.
	 */

	sbus_frequency = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	"clock-frequency", 1000000);
	BPP_PRINT(5, (CE_CONT,
	    "clock-frequency prop is:    %d\n", sbus_frequency));
	sbus_clock = sbus_frequency/1000000;
	if (sbus_clock >= 10 && sbus_clock <= 25) {
		BPP_PRINT(5, (CE_CONT, "SBus clock is %d MHz.\n", sbus_clock));
		/* calculate clock period (in nsec) */
		sbus_cycle = (1000 / sbus_clock);
		bpp_p->sbus_clock_cycle = sbus_cycle;
	} else {
		cmn_err(CE_NOTE, "SBus clock frequency out of range.");
		ddi_remove_intr(bpp_p->dip, 0, bpp_p->bpp_block_cookie);
		ddi_soft_state_free(bpp_state_head, unit_no);
		return (DDI_FAILURE);
	}
	BPP_PRINT(5, (CE_CONT, "SBus Clock period is %d nsec.\n",
	    bpp_p->sbus_clock_cycle));


	/*
	 * Map in any device registers. The zebra parallel section
	 * has only one register area.
	 */
	/*
	 * Map the structure into kernel virtual space.
	 */
	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&(bpp_p->bpp_regs_p),
	    0, sizeof (struct bpp_regs),
	    &bpp_acc_attr, &bpp_p->bpp_acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_NOTE,
		    "bpp_attach unit %d: regs_map_setup failed!", unit_no);
		cv_destroy(&bpp_p->wr_cv);
		mutex_destroy(&bpp_p->bpp_mutex);
		ddi_remove_intr(bpp_p->dip, 0, bpp_p->bpp_block_cookie);
		ddi_soft_state_free(bpp_state_head, unit_no);
		return (DDI_FAILURE);
	}
	bpp_regs_p = bpp_p->bpp_regs_p;

	if (check_bpp_registers(unit_no)) {	/* registers don't seem right */
		cmn_err(CE_NOTE,
		    "bpp_attach unit %d: register check failed!", unit_no);
		ddi_regs_map_free(&bpp_p->bpp_acc_handle);
		cv_destroy(&bpp_p->wr_cv);
		mutex_destroy(&bpp_p->bpp_mutex);
		ddi_remove_intr(bpp_p->dip, 0, bpp_p->bpp_block_cookie);
		ddi_soft_state_free(bpp_state_head, unit_no);
		return (DDI_FAILURE);
	}

	if (ddi_dma_alloc_handle(dip, &bpp_dma_attr, DDI_DMA_DONTWAIT, NULL,
	    &bpp_p->bpp_dma_handle) != DDI_SUCCESS) {
		cmn_err(CE_NOTE,
		    "bpp_attach unit %d: dma_alloc_handle failed!",
		    unit_no);
		ddi_regs_map_free(&bpp_p->bpp_acc_handle);
		cv_destroy(&bpp_p->wr_cv);
		mutex_destroy(&bpp_p->bpp_mutex);
		ddi_remove_intr(bpp_p->dip, 0, bpp_p->bpp_block_cookie);
		ddi_soft_state_free(bpp_state_head, unit_no);
		return (DDI_FAILURE);
	}

	/* The driver is now commited - all sanity checks done */

	(void) sprintf(name, "bpp%d", unit_no);
	if (ddi_create_minor_node(dip, name, S_IFCHR,
	    unit_no, DDI_NT_PRINTER, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		cmn_err(CE_NOTE, "ddi_create_minor_node failed for unit %d",
		    unit_no);
		ddi_dma_free_handle(&bpp_p->bpp_dma_handle);
		ddi_regs_map_free(&bpp_p->bpp_acc_handle);
		cv_destroy(&bpp_p->wr_cv);
		mutex_destroy(&bpp_p->bpp_mutex);
		ddi_remove_intr(bpp_p->dip, 0, bpp_p->bpp_block_cookie);
		ddi_soft_state_free(bpp_state_head, unit_no);
		return (DDI_FAILURE);
	}

	ddi_report_dev(dip);

	(void) sprintf(name, "bppc%d", unit_no);
	bpp_p->intrstats = kstat_create("bpp", unit_no, name, "controller",
	    KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT);
	if (bpp_p->intrstats) {
		kstat_install(bpp_p->intrstats);
	}

initialise:
	/*
	 * The burst-sizes property encodes which SBus burst sizes this
	 * cpu will support. Each binary digit represents a power of
	 * two. Thus 0x37 would indicate 1,2,4,16, and 32-byte bursts
	 * are supported.
	 * Use this info to program the P_BURST_SIZE bits of the
	 * P_CSR.
	 */
	burst_sizes = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "burst-sizes", -1);
	BPP_PRINT(5, (CE_CONT,
	    "^burst-sizes prop is:    0x%x\n", burst_sizes));

	/*
	 * Starting with the DMA2P, the bpp lives with a DMA controller
	 * which can support different burst sizes. Determine the
	 * SBus burst size and program the register.
	 * Be sure to always look for largest-possible burst-size first.
	 * On an HIOD (zebra card) there is no active register at that
	 * location.
	 */

#if	BPP_DEBUG
	if ((bpp_regs_p->dma_csr & BPP_DEVICE_ID_MASK) == BPP_HIOD_DEVID) {
		/*
		 * HIOD DMA engine only supports 4-word (default) bursts, no
		 * programmable register.
		 */
		BPP_PRINT(5, (CE_CONT,
		    "bpp_attach: devid field indicates HIOD bpp DMA\n"));
		/* no register, so do nothing here */
	} else
#endif /* BPP_DEBUG */
	if ((bpp_regs_p->dma_csr & BPP_DEVICE_ID_MASK) == BPP_DMA2P_DEVID) {
		BPP_PRINT(5, (CE_CONT,
		    "bpp_attach: devid field indicates DMA2P bpp DMA\n"));
		if ((burst_sizes == 0xff) ||
		    (!((burst_sizes & BURST16) ||
		    (burst_sizes & BURST32)))) {
			BPP_PRINT(5, (CE_CONT,
			    "bad burst-sizes 0x%x, setting to %x\n",
			    burst_sizes, BPP_BURST_DEFAULT));
			bpp_regs_p->dma_csr |= BPP_BURST_DEFAULT;
		} else if (burst_sizes & BURST32) {	/* largest possible */
			BPP_PRINT(5, (CE_CONT,
			    "Setting P_BURST_SIZE for 8-word bursts\n"));
			bpp_regs_p->dma_csr |= BPP_BURST_8WORD;
		} else if (burst_sizes & BURST16) {
			BPP_PRINT(5, (CE_CONT,
			    "Setting P_BURST_SIZE for 4-word bursts\n"));
			bpp_regs_p->dma_csr |= BPP_BURST_4WORD;
		}
	} else if ((bpp_regs_p->dma_csr & BPP_DEVICE_ID_MASK) !=
	    BPP_HIOD_DEVID) {
		BPP_PRINT(5, (CE_CONT,
		    "bpp_attach: undefined bpp DMA"));
		BPP_PRINT(5, (CE_CONT,
		    "using 0x%x for bursts.\n", BPP_BURST_DEFAULT));
		bpp_regs_p->dma_csr |= BPP_BURST_DEFAULT;
	}

	/*
	 * Perform device initialization.
	 */

	bpp_regs_p->dma_csr  |= BPP_RESET_BPP;
	bpp_regs_p->dma_csr  &= ~BPP_RESET_BPP;
	bpp_regs_p->dma_csr  |= BPP_TC_INTR_DISABLE;

	/*
	 * Set up the polarities for the ERR, SLCT PE, and BUSY interrupts.
	 * Changing the polarities could cause a stray interrupt,
	 * so clear them here.
	 * These polarities are handshake dependent.
	 * This setup corresponds to the default handshakes.
	 */
	BPP_PRINT(5, (CE_CONT, "Before setting polarities, int_cntl = 0x%x\n",
	    bpp_regs_p->int_cntl));
	bpp_regs_p->int_cntl |= BPP_ERR_IRP;	/* ERR rising edge */
	bpp_regs_p->int_cntl |= BPP_SLCT_IRP;	/* SLCT rising edge */
						/* SLCT+ means off-line */
	bpp_regs_p->int_cntl &= ~BPP_PE_IRP;	/* PE falling edge */
	bpp_regs_p->int_cntl |= BPP_BUSY_IRP;	/* BUSY rising edge */
	/* clear any stray interrupts */
	bpp_regs_p->int_cntl |= BPP_ALL_IRQS;
	BPP_PRINT(5, (CE_CONT, "After setting polarities, int_cntl = 0x%x\n",
	    bpp_regs_p->int_cntl));

	/* Turn on interrupts */
	bpp_p->bpp_regs_p->dma_csr |= BPP_INT_EN;

	if (bpp_p->bpp_regs_p->op_config
	    & BPP_VERSATEC_INTERLOCK) {	/* versatec connector absent */
		/* block versatec handshake modes */
		bpp_p->flags &= ~BPP_VERSATEC;
		BPP_PRINT(5, (CE_CONT, "Versatec connector absent.\n"));
	} else {
		/* allow versatec handshake modes */
		bpp_p->flags |= BPP_VERSATEC;
		BPP_PRINT(5, (CE_CONT, "Versatec connector present.\n"));
	}

	BPP_PRINT(2, (CE_CONT, "Leaving bpp_attach: unit %d\n", unit_no));

	BPP_PRINT(2, (CE_CONT, "ATTACH SUCCEEDED.\n"));
	return (DDI_SUCCESS);
}

/*
 * xx_getinfo is called from the framework to determine the devinfo pointer
 * or instance number corresponding to a given dev_info_t.
 */
/*ARGSUSED*/
static int
bpp_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;
	register struct	bpp_unit *bpp_p;

	BPP_PRINT(2, (CE_CONT, "Entering bpp_getinfo, cmd %x\n", infocmd));

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((bpp_p = getsoftc((dev_t)arg)) == NULL) {
			*result = NULL;
			error = DDI_FAILURE;
		} else {
			mutex_enter(&bpp_p->bpp_mutex);
			*result = bpp_p->dip;
			mutex_exit(&bpp_p->bpp_mutex);
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}

	BPP_PRINT(2, (CE_CONT, "Leaving bpp_getinfo, result %x\n", error));
	return (error);
}


/*
 * _init is called by the autoloading code when the special file is
 * first opened, or by modload().
 */
int
_init(void)
{
	register int	error;
	if ((error = ddi_soft_state_init(&bpp_state_head,
	    sizeof (struct bpp_unit), 1)) != 0) {
		return (error);
	}
	if ((error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&bpp_state_head);
	return (error);
}

/*
 * _info is called by modinfo().
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * _fini is called by
 * modunload() just before the driver is unloaded from system memory.
 */
int
_fini(void)
{
	int status;

	if ((status = mod_remove(&modlinkage)) != 0)
		return (status);
	ddi_soft_state_fini(&bpp_state_head);
	return (status);
}


/*
 * Turn off interrupts, remove registration of all interrupt vectors,
 * and release all memory.
 * This routine does the reverse of the attach routine.
 *
 */
static int
bpp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	volatile struct bpp_regs	*bpp_regs_p;
	int		unit_no;

	unit_no = ddi_get_instance(dip);
	BPP_PRINT(2, (CE_CONT, "Entering bpp_detach, unit %d\n", unit_no));

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		if ((bpp_p = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);
		mutex_enter(&bpp_p->bpp_mutex);
		if (bpp_p->flags & BPP_SUSPENDED) {
				mutex_exit(&bpp_p->bpp_mutex);
				return (DDI_FAILURE);
			}
		bpp_p->flags |= BPP_SUSPENDED;
		mutex_exit(&bpp_p->bpp_mutex);
		/* XXX - Need to Wait for pending ops to finish */
		while (bpp_p->timeouts) {
			}		/* Yuck! */
		return (DDI_SUCCESS);

	default:
		BPP_PRINT(3, (CE_CONT,
		    "Invalid detach cmd 0x%x in bpp_detach\n", cmd));
		goto detach_failed;
	}

	bpp_p = getsoftc(unit_no);
	bpp_regs_p = bpp_p->bpp_regs_p;

	/* Turn off interrupts for this unit. */
	if (bpp_regs_p->dma_csr & BPP_ENABLE_DMA) {
		/* was transferring */
		cmn_err(CE_NOTE,
		"ERROR: bpp unload of unit %d while DMA active!",
		    unit_no);
		/* turn off DMA  and byte count */
		bpp_regs_p->dma_csr &= ~BPP_ENABLE_DMA;
		bpp_regs_p->dma_csr &= ~BPP_ENABLE_BCNT;
		/* Reset PP state machine */
		bpp_regs_p->op_config |= BPP_SRST;
		bpp_regs_p->op_config &= ~BPP_SRST;
		/* flush the cache */
		bpp_regs_p->dma_csr |= BPP_FLUSH;
	}
	/*
	 * Disable the TC interrupts.
	 * Mask the error interrupts too.
	 * These shouldn't be on if we weren't transferring
	 * at the time, but it's safest to just turn
	 * them off anyway.
	 */
	bpp_regs_p->dma_csr |= BPP_TC_INTR_DISABLE;
	bpp_regs_p->int_cntl &=
	    ~(BPP_ERR_IRQ_EN | BPP_SLCT_IRQ_EN | BPP_PE_IRQ_EN);
	bpp_p->bpp_regs_p->dma_csr &= ~BPP_INT_EN;
	/*
	 * XXX	This comment no longer applies to 5.x
	 *
	 * To be safer, I really should free the buf which
	 * was being used to do the transfer, and wait on
	 * a semaphore that tells me that bpp_read or
	 * bpp_write have returned the partial error.
	 */

	/* Remove the minor node created in attach */
	ddi_remove_minor_node(dip, NULL);

	/* Free DMA handle */
	ddi_dma_free_handle(&bpp_p->bpp_dma_handle);

	/*
	 * Unmap register area from kernel memory.
	 */
	dip = bpp_p->dip;
	ddi_regs_map_free(&bpp_p->bpp_acc_handle);

	/*
	 * Remove interrupt registry
	 */
	BPP_PRINT(5, (CE_CONT, "Removing bpp from interrupt chains.\n"));
	ddi_remove_intr(bpp_p->dip, 0, bpp_p->bpp_block_cookie);

	if (bpp_p->intrstats) {
		kstat_delete(bpp_p->intrstats);
	}
	bpp_p->intrstats = NULL;

	/* Destroy the per-unit cv and mutex. */
	cv_destroy(&bpp_p->wr_cv);
	mutex_destroy(&bpp_p->bpp_mutex);

	/* Free the memory allocated for this unit's state struct */
	ddi_soft_state_free(bpp_state_head, unit_no);

	BPP_PRINT(2, (CE_CONT, "Leaving bpp_detach.\n"));
	return (DDI_SUCCESS);

detach_failed:
	BPP_PRINT(2, (CE_CONT, "DETACH FAILED.\n"));
	return (DDI_FAILURE);
}

/* Normal Device Driver routines	*/

/*
 * Open the device.
 */
/*ARGSUSED*/
static	int
bpp_open(dev_t *dev, int openflags, int otyp, cred_t *credp)
{
	int	unit_no;
	ushort_t retval = 0;	/* return value (errno) for system call */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	unit_no = BPP_UNIT(dev);
	bpp_p = getsoftc(unit_no);
	BPP_PRINT(2, (CE_CONT,
	    "bpp%d: Entering bpp_open, flags %d.\n", unit_no, openflags));
	/*
	 * Assure that the device is being opened as a character device.
	 */
	if (otyp != OTYP_CHR) {
		cmn_err(CE_NOTE,
		    "bpp%d attempted open as non-character device!",
		    unit_no);
		retval = EINVAL;
		goto out;
	}


	/*
	 * Check for allocation of unit structures.
	 */
	if (bpp_p == NULL) {
		cmn_err(CE_NOTE,
		    "bpp%d unit pointer is NULL!", unit_no);
		retval = ENXIO;			/* attach failed ?? */
		goto out;
	}

	mutex_enter(&bpp_p->bpp_mutex);
	/*
	 * Only allow a single open. If this device has
	 * already been opened, return an error.
	 */
	if (bpp_p->flags & BPP_ISOPEN) {
		BPP_PRINT(1, (CE_CONT, "bpp%d already opened.\n", unit_no));
		retval = EBUSY;
		mutex_exit(&bpp_p->bpp_mutex);
		goto out;
	}


	/*
	 * Mark the bpp as opened.
	 */
	bpp_p->flags |= BPP_ISOPEN;

	/*
	 * Initialize the transfer parameters structure
	 * and initialize the control pins structure
	 * for this unit.
	 */
	bpp_p->transfer_parms = bpp_default_transfer_parms;
	bpp_p->pins = bpp_default_pins;
	bpp_p->openflags = openflags;	/* record the open mode */
	mutex_exit(&bpp_p->bpp_mutex);

out:
	BPP_PRINT(2, (CE_CONT, "Leaving bpp_open, unit %d: errno %d.\n",
	    unit_no, retval));
	return (retval);
}

/*
 * Close the device.
 */
/*ARGSUSED*/
static	int
bpp_close(dev_t dev, int openflags, int otyp, cred_t *credp)
{

	int	unit_no;
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	timeout_id_t	tid = 0;

	unit_no = BPP_UNIT(&dev);
	bpp_p = getsoftc(unit_no);
	BPP_PRINT(2, (CE_CONT,
	    "Entering bpp_close, unit number %d.\n", unit_no));

	BPP_PRINT(5, (CE_CONT, "In bpp_close, Timeout block is 0x%x.\n",
	    bpp_p->timeouts));
	mutex_enter(&bpp_p->bpp_mutex);
	if (bpp_p->timeouts) {			 /* any timeouts pending? */
		BPP_PRINT(5, (CE_CONT, "Some timeouts still pending.\n"));
		if (bpp_p->timeouts & TRANSFER_TIMEOUT) {
			BPP_PRINT(5, (CE_CONT, "Clearing transfer timeout.\n"));
			tid = bpp_p->bpp_transfer_timeout_ident;
			bpp_p->bpp_transfer_timeout_ident = 0;
		}
		if (bpp_p->timeouts & FAKEOUT_TIMEOUT) {
			cmn_err(CE_CONT, "BOGUS fakeout timeout.\n");
		}
	}

	bpp_p->timeouts = NO_TIMEOUTS;
	BPP_PRINT(5, (CE_CONT, "At end of  bpp_close, Timeout block is 0x%x.\n",
	    bpp_p->timeouts));

	/*
	 * Mark unit closed.
	 */
	bpp_p->flags &= ~BPP_ISOPEN;
	mutex_exit(&bpp_p->bpp_mutex);

	if (tid)
		(void) untimeout(tid);

	BPP_PRINT(2, (CE_CONT, "Leaving bpp_close, unit %d:\n", unit_no));
	return (0);
}

/*
 * Read system call.
 */
/*ARGSUSED*/
static	int
bpp_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int	unit_no;
	ushort_t retval = 0;	/* return value (errno) for system call */
	volatile struct bpp_regs	*bpp_regs_p;
	struct	bpp_transfer_parms	*bpp_transfer_parms_p;
	static	int	scan_turnaround = 1000; /* time to allow the scanner */
						/* to change from data sink */
						/* to source */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	unit_no = BPP_UNIT(&dev);
	bpp_p = getsoftc(unit_no);
	BPP_PRINT(2, (CE_CONT, "Entering bpp_read, unit number %d.\n",
	    unit_no));

	mutex_enter(&bpp_p->bpp_mutex);

	while (bpp_p->flags & BPP_BUSY)
		if (!cv_wait_sig(&bpp_p->wr_cv, &bpp_p->bpp_mutex)) {
			mutex_exit(&bpp_p->bpp_mutex);
			return (EINTR);
		}

	bpp_p->flags |= BPP_BUSY;

	bpp_regs_p = bpp_p->bpp_regs_p;
	bpp_transfer_parms_p = &bpp_p->transfer_parms;

	/*
	 * delay to allow for scanning write/read turnaround
	 */

	if (bpp_p->last_trans == write_trans) {
		mutex_exit(&bpp_p->bpp_mutex);
		drv_usecwait(scan_turnaround);
		mutex_enter(&bpp_p->bpp_mutex);
	}

	/*
	 * Set the handshake bits
	 */

	/*
	 * make sure the memory clear operation is turned off
	 */
	bpp_regs_p->op_config &= ~BPP_EN_MEM_CLR;

	switch (bpp_transfer_parms_p->read_handshake) {
	case BPP_NO_HS:
		BPP_PRINT(5, (CE_CONT, "BPP_NO_HS case\n"));
		bpp_regs_p->op_config &= ~(BPP_ACK_OP | BPP_BUSY_OP);
		bpp_regs_p->op_config |= (BPP_DS_BIDIR | BPP_BUSY_BIDIR);
		break;
	case BPP_ACK_HS:
		BPP_PRINT(5, (CE_CONT, "BPP_ACK_HS case\n"));
		bpp_regs_p->op_config &= ~BPP_BUSY_OP;
		bpp_regs_p->op_config |= BPP_ACK_OP;
		bpp_regs_p->op_config |=
		    (BPP_DS_BIDIR | BPP_ACK_BIDIR | BPP_BUSY_BIDIR);
		break;
	case BPP_BUSY_HS:
	case BPP_HSCAN_HS:
		BPP_PRINT(5, (CE_CONT, "BPP_BUSY_HS case\n"));
		bpp_regs_p->op_config |= BPP_BUSY_OP;
		bpp_regs_p->op_config &= ~BPP_ACK_OP;
		bpp_regs_p->op_config |= (BPP_DS_BIDIR | BPP_BUSY_BIDIR);
		break;
	case BPP_ACK_BUSY_HS:
		BPP_PRINT(5, (CE_CONT, "BPP_ACK_BUSY_HS case\n"));
		bpp_regs_p->op_config |= (BPP_BUSY_OP | BPP_ACK_OP);
		bpp_regs_p->op_config |=
		    (BPP_DS_BIDIR | BPP_ACK_BIDIR | BPP_BUSY_BIDIR);
		break;
	case BPP_XSCAN_HS:
		/*
		 * reads with the Xerox use ACK handshake
		 * and unidirectional operation
		 */
		BPP_PRINT(5, (CE_CONT, "BPP_XSCAN_HS case\n"));
		bpp_regs_p->op_config &= ~BPP_BUSY_OP;
		bpp_regs_p->op_config |= BPP_ACK_OP;
		bpp_regs_p->op_config &=
		    ~(BPP_DS_BIDIR | BPP_BUSY_BIDIR | BPP_ACK_BIDIR);
		break;
	case BPP_CLEAR_MEM:
		BPP_PRINT(5, (CE_CONT, "BPP_CLEAR_MEM case\n"));
		bpp_regs_p->op_config &= ~BPP_DMA_DATA;
		bpp_regs_p->op_config |= BPP_EN_MEM_CLR;
		break;
	case BPP_SET_MEM:
		BPP_PRINT(5, (CE_CONT, "BPP_SET_MEM case\n"));
		bpp_regs_p->op_config |= BPP_DMA_DATA;
		bpp_regs_p->op_config |= BPP_EN_MEM_CLR;
		break;
	}
	/*
	 * The direction should not be marked until after the handshake
	 * bits have been set.
	 */
	bpp_regs_p->trans_cntl |= BPP_DIRECTION;

	/* set the dss and dsw values */
	set_dss_dsw(unit_no, 1);

	/*
	 * If we're opened for read/write,
	 * toggle the scan/print line for scanning
	 */
	if ((bpp_p->openflags & FREAD) &&
	    (bpp_p->openflags & FWRITE)) {
		if (bpp_transfer_parms_p->read_handshake == BPP_HSCAN_HS) {
			/* The HP Scanjet uses AFX */
			bpp_regs_p->out_pins |= BPP_AFX_PIN;
		} else {
			bpp_regs_p->out_pins |= BPP_SLCTIN_PIN;
		}
	}
	bpp_p->last_trans = read_trans;
	mutex_exit(&bpp_p->bpp_mutex);
	BPP_PRINT(5, (CE_CONT, "bpp_read, calling physio\n"));
	retval = physio(bpp_strategy, (struct buf *)0, dev,
	    B_READ, bpp_minphys, uiop);

	mutex_enter(&bpp_p->bpp_mutex);
	bpp_p->flags &= ~BPP_BUSY;
	cv_signal(&bpp_p->wr_cv);
	mutex_exit(&bpp_p->bpp_mutex);

	BPP_PRINT(2, (CE_CONT,
	    "Leaving bpp_read, unit %d: errno %d.\n",
	    unit_no, retval));
	return (retval);
}

/*
 * Write system call.
 */
/*ARGSUSED*/
static	int
bpp_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int	unit_no;
	ushort_t retval = 0;	/* return value (errno) for system call */
	register volatile struct bpp_regs	*bpp_regs_p;
	register struct	bpp_transfer_parms	*bpp_transfer_parms_p;

	register struct bpp_error_status *bpp_errorstat_p; /* error stat */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	unit_no = BPP_UNIT(&dev);
	BPP_PRINT(2, (CE_CONT,
	    "Entering bpp_write, unit number %d.\n", unit_no));

	bpp_p = getsoftc(unit_no);

	mutex_enter(&bpp_p->bpp_mutex);

	while (bpp_p->flags & BPP_BUSY)
		if (!cv_wait_sig(&bpp_p->wr_cv, &bpp_p->bpp_mutex)) {
			mutex_exit(&bpp_p->bpp_mutex);
			return (EINTR);
		}

	bpp_p->flags |= BPP_BUSY;

	bpp_regs_p = bpp_p->bpp_regs_p;
	bpp_transfer_parms_p = &bpp_p->transfer_parms;
	bpp_errorstat_p = &bpp_p->error_stat;

	/* clear any old error status */
	*bpp_errorstat_p = bpp_default_error_stat;

	/*
	 * Set up the polarities for the ERR, SLCT PE, and BUSY interrupts.
	 * Changing the polarities could cause a stray interrupt,
	 * so clear them here.
	 * These polarities are handshake dependent.
	 * This setup corresponds to the default handshakes.
	 */
	BPP_PRINT(5, (CE_CONT, "Before setting polarities, int_cntl = 0x%x\n",
	    bpp_regs_p->int_cntl));
	bpp_regs_p->int_cntl |= BPP_ERR_IRP;	/* ERR rising edge */
	bpp_regs_p->int_cntl |= BPP_SLCT_IRP;	/* SLCT rising edge */
						/* SLCT+ is off-line */
	bpp_regs_p->int_cntl &= ~BPP_PE_IRP;	/* PE falling edge */

	bpp_regs_p->int_cntl |= (BPP_ERR_IRQ | BPP_SLCT_IRQ | BPP_PE_IRQ);

	BPP_PRINT(5, (CE_CONT, "After setting polarities, int_cntl = 0x%x\n",
	    bpp_regs_p->int_cntl));

	check_for_active_pins(unit_no);

	/*
	 * if any active pins were found, don't attempt the transfer,
	 * unless we're in scanner mode (read-write), scanners use the PE line
	 * to get the host's attention.
	 */
	if ((bpp_p->openflags & (FREAD | FWRITE)) == (FREAD | FWRITE)) {
		/*
		 * Toggle the scan/print line for scanning
		 */
		if (bpp_transfer_parms_p->read_handshake == BPP_HSCAN_HS) {
			/* The HP Scanjet uses AFX */
			bpp_regs_p->out_pins &= ~BPP_AFX_PIN;
		} else {
			bpp_regs_p->out_pins &= ~BPP_SLCTIN_PIN;
		}
	} else {
		if ((bpp_errorstat_p->pin_status &
		    (BPP_ERR_ERR | BPP_SLCT_ERR | BPP_PE_ERR))) {
			/* printer error - no transfer allowed */
			BPP_PRINT(5, (CE_CONT,
			    "In bpp_write, pending error pin condition\n"));
			retval = ENXIO;
			mutex_exit(&bpp_p->bpp_mutex);
			goto out;
		}
	}

	/* mark the transfer direction in the hardware */
	bpp_regs_p->trans_cntl &= ~BPP_DIRECTION;

	/*
	 * make sure the memory clear operation is turned off
	 */
	bpp_regs_p->op_config &= ~BPP_EN_MEM_CLR;

	/*
	 * Set the handshake bits
	 */
	if (bpp_transfer_parms_p->write_handshake == BPP_NO_HS) {
		BPP_PRINT(5, (CE_CONT, "BPP_NO_HS case\n"));
		bpp_regs_p->op_config &= ~(BPP_ACK_OP | BPP_BUSY_OP);
	} else if (bpp_transfer_parms_p->write_handshake == BPP_ACK_HS) {
		BPP_PRINT(5, (CE_CONT, "BPP_ACK_HS case\n"));
		bpp_regs_p->op_config &= ~BPP_BUSY_OP;
		bpp_regs_p->op_config |= BPP_ACK_OP;
	} else if (bpp_transfer_parms_p->write_handshake == BPP_BUSY_HS) {
		BPP_PRINT(5, (CE_CONT, "BPP_BUSY_HS case\n"));
		bpp_regs_p->op_config |= BPP_BUSY_OP;
		bpp_regs_p->op_config &= ~BPP_ACK_OP;
	}

	/* Make sure that ACK and BUSY are unidirectional */
	bpp_regs_p->op_config &= ~(BPP_ACK_BIDIR | BPP_BUSY_BIDIR);

	/* set the dss and dsw values */
	set_dss_dsw(unit_no, 0);

	bpp_p->last_trans = write_trans;
	mutex_exit(&bpp_p->bpp_mutex);

	BPP_PRINT(5, (CE_CONT, "bpp_write, calling physio\n"));
	retval = physio(bpp_strategy, (struct buf *)0, dev,
	    B_WRITE, bpp_minphys, uiop);

out:
	mutex_enter(&bpp_p->bpp_mutex);
	bpp_p->flags &= ~BPP_BUSY;
	cv_signal(&bpp_p->wr_cv);
	mutex_exit(&bpp_p->bpp_mutex);

	BPP_PRINT(2, (CE_CONT,
	    "Leaving bpp_write, unit %d: errno %d.\n", unit_no, retval));
	return (retval);
}

/*
 * Limit transfer size to the smaller of
 *	- system minphys size
 *	- 16 MB limit in HIOD address register
 */
static void
bpp_minphys(struct buf *bp)
{
	minphys(bp);
	if (bp->b_bcount > BPP_MAX_DMA)
		bp->b_bcount = BPP_MAX_DMA;
}

/*
 * Check to see if any of the control pins are active.
 */
static void
check_for_active_pins(int unit_no)
{
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	register volatile struct bpp_regs	*bpp_regs_p;
	register struct bpp_error_status *bpp_errorstat_p; /* error stat */

	bpp_p = getsoftc(unit_no);
	bpp_regs_p = bpp_p->bpp_regs_p;
	bpp_errorstat_p = &bpp_p->error_stat;

	BPP_PRINT(2, (CE_CONT,
	    "Entering check_for_active_pins, unit number %d.\n", unit_no));
	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));
	/*
	 * Check that there are no pending ERR, SLCT or PE error
	 * conditions. If there are, do not attempt the transfer.
	 */
	BPP_PRINT(5, (CE_CONT, "check_active_pins: in_pins = 0x%x\n",
	    bpp_regs_p->in_pins));
	BPP_PRINT(5, (CE_CONT, "check_active_pins: int_cntl = 0x%x\n",
	    bpp_regs_p->int_cntl));

	if (((bpp_regs_p->in_pins & BPP_ERR_PIN) &&
	    (bpp_regs_p->int_cntl & BPP_ERR_IRP)) ||
	    ((~bpp_regs_p->in_pins & BPP_ERR_PIN)&&
	    (~bpp_regs_p->int_cntl & BPP_ERR_IRP))) { /* ERR active */
			BPP_PRINT(5, (CE_CONT,
			    "In ck_active_pins, pending ERR condition\n"));
			bpp_errorstat_p->pin_status |= BPP_ERR_ERR;
	}

	if (((bpp_regs_p->in_pins & BPP_SLCT_PIN) &&
	    (bpp_regs_p->int_cntl & BPP_SLCT_IRP)) ||
	    ((~bpp_regs_p->in_pins & BPP_SLCT_PIN)&&
	    (~bpp_regs_p->int_cntl & BPP_SLCT_IRP))) { /* SLCT active */
			BPP_PRINT(5, (CE_CONT,
			    "In ck_active_pins, pending SLCT condition\n"));
			bpp_errorstat_p->pin_status |= BPP_SLCT_ERR;
	}

	if (((bpp_regs_p->in_pins & BPP_PE_PIN) &&
	    (bpp_regs_p->int_cntl & BPP_PE_IRP)) ||
	    ((~bpp_regs_p->in_pins & BPP_PE_PIN)&&
	    (~bpp_regs_p->int_cntl & BPP_PE_IRP))) { /* PE active */
			BPP_PRINT(5, (CE_CONT,
			    "In check_active_pins, pending PE condition\n"));
			bpp_errorstat_p->pin_status |= BPP_PE_ERR;
	}
	BPP_PRINT(2, (CE_CONT,
	    "Leaving check_for_active_pins, unit number %d.\n", unit_no));
}

/*
 * Setup and start a transfer on the device.
 */
/*ARGSUSED*/
static int
bpp_strategy(register struct buf *bp)
{
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	int		unit_no;
	int	timeout_value;		/* read or write timeout in secs */
	uint_t	start_address;		/* kernel virt. DVMA start address */
	size_t	size;			/* size of DVMA transfer */
	register struct	bpp_transfer_parms	*bpp_transfer_parms_p;
	register volatile struct bpp_regs	*bpp_regs_p;
	int	flags;			/* flags to use for DMA mapping */
	ddi_dma_cookie_t	dma_cookie;
	uint_t			dma_cookie_cnt;


	unit_no = BPP_UNIT(&(bp->b_edev));
	BPP_PRINT(2, (CE_CONT,
	    "bpp%d:Entering bpp_strategy: length 0x%x.\n",
	    unit_no, bp->b_bcount));

	/*
	 * Use the unit number to locate our data structures.
	 */
	bpp_p = getsoftc(unit_no);
	bpp_regs_p = bpp_p->bpp_regs_p;
	bpp_transfer_parms_p = &bpp_p->transfer_parms;

	mutex_enter(&bpp_p->bpp_mutex);
	if (bpp_p->flags & BPP_SUSPENDED) {
		mutex_exit(&bpp_p->bpp_mutex);
		(void) ddi_dev_is_needed(bpp_p->dip, 0, 1);
		mutex_enter(&bpp_p->bpp_mutex);
	}
	bpp_p->bpp_buffer = bp;		/* bpp_intr needs this */

	/* Clear the unit error status struct */
	bpp_p->error_stat = bpp_default_error_stat;

	/* Set DMA request flags based on struct buf flags */
	if (bp->b_flags & B_READ)
		flags = DDI_DMA_READ;
	else if (bp->b_flags & B_WRITE)
		flags = DDI_DMA_WRITE;

	BPP_PRINT(5, (CE_CONT,
	    "Before dma_buf_bind, b_addr = 0x%p, b_bcount = 0x%x\n",
	    (void *)bp->b_un.b_addr, bp->b_bcount));
	/*
	 * Get dvma bus resource, sleeping if necessary.
	 */
	if (ddi_dma_buf_bind_handle(bpp_p->bpp_dma_handle, bp,
	    flags | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &dma_cookie, &dma_cookie_cnt) != DDI_DMA_MAPPED) {
		cmn_err(CE_NOTE,
		    "ERROR: bpp%d: dma_buf_bind failed mapping",
		    unit_no);
		bioerror(bp, ENOMEM);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}
	ASSERT(dma_cookie_cnt == 1);

	BPP_PRINT(5, (CE_CONT,
	    "After dma_buf_bind, b_addr = 0x%p, b_bcount = 0x%x\n",
	    (void *)bp->b_un.b_addr, bp->b_bcount));

	start_address = dma_cookie.dmac_address;
	BPP_PRINT(5, (CE_CONT,
	    "start_address = 0x%x\n", start_address));

	size = bp->b_bcount;

	/*
	 * Write the dma start address to the hardware.
	 * Write the transfer byte count to the hardware.
	 */
	BPP_PRINT(5, (CE_CONT, "writing start_address 0x%x, size %d to regs\n",
	    start_address, size));

	bpp_regs_p->dma_addr = start_address;
	bpp_regs_p->dma_bcnt = (uint_t)size;

	BPP_PRINT(5, (CE_CONT,
	    "bpp_strategy: Transfer %d bytes starting at 0x%x.\n",
	    bpp_regs_p->dma_bcnt, bpp_regs_p->dma_addr));
	BPP_PRINT(5, (CE_CONT,
	    "before enabling interrupts, dma csr=0x%x, int_cntl=0x%x.\n",
	    bpp_regs_p->dma_csr, bpp_regs_p->int_cntl));

	/*
	 * Enable byte-counter during DVMA.
	 * Enable TC interrupts so we will know when the DVMA is done.
	 * Start the DVMA.
	 * Enable the peripheral error interrupts.
	 */
	/*
	 * Do not close critical section until timeouts have been
	 * enabled, otherwise we might get an untimeout before
	 * the timeout has been set!
	 */
	bpp_regs_p->dma_csr |= BPP_ENABLE_BCNT;
	bpp_regs_p->dma_csr &= ~BPP_TC_INTR_DISABLE;
	bpp_regs_p->dma_csr |= BPP_ENABLE_DMA;

	if (bp->b_flags & B_READ) {
		BPP_PRINT(5, (CE_CONT,
		    "bp->b_flags indicates READ mode\n"));
		timeout_value = bpp_transfer_parms_p->read_timeout;
	} else {
		BPP_PRINT(5, (CE_CONT,
		    "bp->b_flags indicates WRITE mode\n"));
		if (!(bpp_p->openflags & FREAD &&
		    bpp_p->openflags & FWRITE)) {
			bpp_regs_p->int_cntl |= (BPP_ERR_IRQ_EN |
			    BPP_SLCT_IRQ_EN | BPP_PE_IRQ_EN);
		}
		BPP_PRINT(5, (CE_CONT,
		    "after enable error int. int cntl contains 0x%x.\n",
		    bpp_regs_p->int_cntl));
		timeout_value = bpp_transfer_parms_p->write_timeout;
	}

	BPP_PRINT(5, (CE_CONT,
	"after enabling interrupts, dma csr = 0x%x, int_cntl = 0x%x.\n",
	    bpp_regs_p->dma_csr, bpp_regs_p->int_cntl));
	BPP_PRINT(5, (CE_CONT,
	    "Setting timeout to call bpp_transfer_timeout in %d sec\n",
	    timeout_value));
	bpp_p->bpp_transfer_timeout_ident =
	    timeout(bpp_transfer_timeout, (void *)(uintptr_t)unit_no,
	    drv_usectohz(timeout_value * 1000000));
	bpp_p->timeouts |= TRANSFER_TIMEOUT;
	BPP_PRINT(5, (CE_CONT, "In bpp_strategy, Timeout block is 0x%x.\n",
	    bpp_p->timeouts));
	mutex_exit(&bpp_p->bpp_mutex);

	BPP_PRINT(2, (CE_CONT, "Leaving bpp_strategy.\n"));
	return (0);
}

/*
 * Handle special control requests
 */
/*ARGSUSED*/
static	int
bpp_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
	cred_t *credp, int *rvalp)
{
	int	unit_no;
	ushort_t retval = 0;	/* return value (errno) for system call */
	ushort_t	read_retval = 0;
	ushort_t	write_retval = 0;
	struct	bpp_unit	*bpp_p;	/* will point to this */
					/* unit's state struct */
	volatile struct bpp_regs	*bpp_regs_p;
	struct	bpp_transfer_parms	*bpp_transfer_parms_p;
	struct	bpp_transfer_parms	temp_parms;
	struct bpp_error_status *bpp_errorstat_p; /* error stat */
	struct bpp_pins 	*bpp_pins_p; /* error stat */
	struct	bpp_pins		temp_pins;

	register enum	handshake_t	write_handshake;
	register enum	handshake_t	read_handshake;

	unit_no = BPP_UNIT(&dev);
	bpp_p = getsoftc(unit_no);
	bpp_regs_p = bpp_p->bpp_regs_p;
	bpp_transfer_parms_p = &bpp_p->transfer_parms;
	bpp_errorstat_p = &bpp_p->error_stat;
	bpp_pins_p = &bpp_p->pins;

	write_handshake = bpp_transfer_parms_p->write_handshake;
	read_handshake = bpp_transfer_parms_p->read_handshake;

	BPP_PRINT(2, (CE_CONT,
	    "Entering bpp_ioctl, unit number %d.\n", unit_no));
	mutex_enter(&bpp_p->bpp_mutex);
	if (bpp_p->flags & BPP_SUSPENDED) {
		mutex_exit(&bpp_p->bpp_mutex);
		(void) ddi_dev_is_needed(bpp_p->dip, 0, 1);
		mutex_enter(&bpp_p->bpp_mutex);
	}

	switch (cmd) {
	case BPPIOC_SETPARMS:	/* set transfer parameters */
		BPP_PRINT(5, (CE_CONT, "BPPIOC_SETPARMS case.\n"));
		/* copy passed parms to temporary storage */
		(void) copyin((caddr_t)arg, &temp_parms, sizeof (temp_parms));
		bpp_transfer_parms_p = &temp_parms;
		if (flag & FREAD) {
			BPP_PRINT(5, (CE_CONT,
			    "Checking read parameters.\n"));
			read_retval = check_read_params(bpp_transfer_parms_p,
			    unit_no, flag);
		}
		if (flag & FWRITE) {
			BPP_PRINT(5, (CE_CONT,
			    "Checking write parameters.\n"));
			write_retval = check_write_params(bpp_transfer_parms_p,
			    unit_no, flag);
		}
		if (read_retval || write_retval) {
			retval = EINVAL;
		} else {	/* valid parameters */
			bpp_p->transfer_parms = temp_parms;
		}
		break;
	case BPPIOC_GETPARMS:	/* get transfer parameters */
		BPP_PRINT(5, (CE_CONT, "BPPIOC_GETPARMS case.\n"));
		(void) copyout(&bpp_p->transfer_parms,
		    (caddr_t)arg, sizeof (struct bpp_transfer_parms));
		retval = 0;
		break;
	case BPPIOC_SETOUTPINS:	/* set output pins */
		BPP_PRINT(5, (CE_CONT, "BPPIOC_SETOUTPINS case.\n"));
		/* copy passed parms to temporary storage */
		(void) copyin((caddr_t)arg, &temp_pins,
		    sizeof (struct bpp_pins));
		bpp_pins_p = &temp_pins;
		if (flag & FREAD) {
			BPP_PRINT(5, (CE_CONT,
			    "Checking read pins.\n"));
			read_retval = check_read_pins(bpp_pins_p,
			    flag, unit_no,  read_handshake);
			if (read_retval == 0) {	/* valid pins */
				bpp_p->pins = temp_pins;
			}
		}
		if (flag & FWRITE) {
			BPP_PRINT(5, (CE_CONT,
			    "Checking write pins.\n"));
			write_retval = check_write_pins(bpp_pins_p,
			    flag, unit_no, write_handshake);
			if (write_retval == 0) { /* valid pins */
				bpp_p->pins = temp_pins;
			}
		}
		if (read_retval || write_retval) {
			retval = EINVAL;
		} else {	/* All is well, write the registers */
			bpp_regs_p->out_pins =
			    bpp_p->pins.output_reg_pins;
				/* the previous line will not cstyle */
			bpp_regs_p->in_pins =
			    bpp_p->pins.input_reg_pins;
		}
		break;
	case BPPIOC_GETOUTPINS:	/* get output pins */
		BPP_PRINT(5, (CE_CONT, "BPPIOC_GETOUTPINS case.\n"));
		(void) copyout(&bpp_p->pins,
		    (caddr_t)arg, sizeof (struct bpp_pins));
		/* read the current pin state into the struct */
		read_outpins(unit_no, flag, write_handshake);
		retval = 0;
		break;
	case BPPIOC_GETERR:	/* get error block status */
		BPP_PRINT(5, (CE_CONT, "BPPIOC_GETERR case.\n"));
		(void) copyout(&bpp_p->error_stat,
		    (caddr_t)arg, sizeof (struct bpp_error_status));
		retval = 0;
		break;
	case BPPIOC_TESTIO:	/* test transfer readiness */
		BPP_PRINT(5, (CE_CONT, "BPPIOC_TESTIO case.\n"));
		bpp_errorstat_p = &bpp_p->error_stat;
		retval = 0;
		/* clear any old error status */
		*bpp_errorstat_p = bpp_default_error_stat;
		check_for_active_pins(unit_no);
		/* if any active pins were found, return -1 */
		if (bpp_errorstat_p->pin_status &
		    (BPP_ERR_ERR | BPP_SLCT_ERR | BPP_PE_ERR)) {
			BPP_PRINT(5, (CE_CONT,
			    "In TESTIO, found error pin condition\n"));
			retval = EIO;
		} else
			retval = 0;
		break;
		/* TEST - request partial fake transfer */
	case BPPIOC_SETBC:
		BPP_PRINT(5, (CE_CONT, "BPPIOC_SETBC case.\n"));
		retval = ENOTTY;
		break;
		/* TEST - get DMA_BCNT from last data transfer */
	case BPPIOC_GETBC:
		BPP_PRINT(5, (CE_CONT, "BPPIOC_GETBC case.\n"));
		retval = ENOTTY;
		break;
		/* TEST - get contents of device registers */
	case BPPIOC_GETREGS:
		BPP_PRINT(5, (CE_CONT, "BPPIOC_GETREGS case.\n"));
		retval = ENOTTY;
		break;
		/* TEST - set special fakeout error code to simulate errs */
	case BPPIOC_SETERRCODE:
		BPP_PRINT(5, (CE_CONT, "BPPIOC_SETERRCODE case.\n"));
		retval = ENOTTY;
		break;
		/* TEST - get pointer to fakeout transferred data */
	case BPPIOC_GETFAKEBUF:
		BPP_PRINT(5, (CE_CONT, "BPPIOC_GETFAKEBUF case.\n"));
		retval = ENOTTY;
		break;
	default:
		BPP_PRINT(1, (CE_CONT, "Error in bpp_ioctl switch!\n"));
		retval = ENOTTY;
		break;
	}

	mutex_exit(&bpp_p->bpp_mutex);

	BPP_PRINT(2, (CE_CONT, "Leaving bpp_ioctl, unit %d: errno %d.\n",
	    unit_no, retval));
	return (retval);
}


/*
 * Handle an interrupt or interrupts that may or may not be from
 * one or more of the bpp units.
 */
static uint_t
bpp_intr(caddr_t unit_no)
{
	int	bpp_unit_no;
	timeout_id_t tid;
	uint_t	int_serviced = DDI_INTR_UNCLAIMED;
	register struct buf		*bp;
	register volatile struct bpp_regs	*bpp_regs_p;
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	register struct bpp_error_status *bpp_errorstat_p; /* error stat */

	BPP_PRINT(2, (CE_CONT, "Entering bpp_intr, unit number %d\n", unit_no));
	bpp_unit_no = (int)(uintptr_t)unit_no;

	/*
	 * Check that this unit is indeed interrupting.
	 */
	bpp_p = getsoftc(bpp_unit_no);
	bpp_regs_p = bpp_p->bpp_regs_p;
	bpp_errorstat_p = &bpp_p->error_stat;
	mutex_enter(&bpp_p->bpp_mutex);
	if ((bpp_regs_p->dma_csr & BPP_INT_PEND) ||
	    (bpp_regs_p->dma_csr & BPP_ERR_PEND)) {
		BPP_PRINT(5, (CE_CONT, "Interrupt found, unit #%d.\n",
		    bpp_unit_no));
		/*
		 * Mark that we found an interrupting device.
		 * Call the interrupt service routine.
		 */
		int_serviced = DDI_INTR_CLAIMED;
		if (bpp_p->intrstats) {
			KIOIP->intrs[KSTAT_INTR_HARD]++;
		}

		/*
		 * The bpp hardware can interrupt for errors, or
		 * for several transfer conditions. These can happen
		 * at the same time.
		 * I process any errors first, checking to see
		 * if a transfer was in process.
		 * In the future, I may want to count how many times I've
		 * tried to flush the cache, and eventually give up and
		 * reset the hardware.
		 * Then I process "normal" conditions.
		 */

		bp = bpp_p->bpp_buffer;		/* saved in bpp_strategy */
		/*
		 * Check for an error, recover if possible.
		 */
		if (bpp_regs_p->dma_csr & BPP_ERR_PEND) {
#if	BPP_DEBUG
			BPP_PRINT(5, (CE_CONT, "Error interrupt detected\n"));
			if (bpp_regs_p->dma_csr & BPP_SLAVE_ERR) {
				BPP_PRINT(5,
				    (CE_CONT, "Slave error detected\n"));
			}
#endif	/* BPP_DEBUG */
			if (bpp_regs_p->dma_csr & BPP_ENABLE_DMA) {
				/* was transferring */
				/*
				 * The transfer has failed. Notify the
				 * application how many bytes got out,
				 * and that there was an IO error,
				 * and turn off the transfer.
				 */
				bpp_transfer_failed(bpp_unit_no);
				mutex_exit(&bpp_p->bpp_mutex);
				return (DDI_INTR_CLAIMED);
			} else {
				/* will make return value -1 */
				bp->b_flags |= B_ERROR;
				bp->b_resid = bp->b_bcount;
			}
			/*
			 * capture the error status in the error_stat struct
			 * so the application can get it with the GETERR
			 * ioctl later.
			 */
			bpp_errorstat_p->bus_error = 1;

			/* Mark the error.  */
			bp->b_error = EIO;

			/* clear the error interrupt */
			while (bp->b_flags & B_READ)
				;
				/* wait here */
				/* cannot assert FLUSH till cache drains */
				/* spin on draining bit */
			bpp_regs_p->dma_csr |= BPP_FLUSH;
		}
		if (bpp_regs_p->dma_csr & BPP_INT_PEND) {
			BPP_PRINT(5, (CE_CONT, "Interrupt pending found.\n"));
			BPP_PRINT(5, (CE_CONT, "dma csr contains 0x%x.\n",
			    bpp_regs_p->dma_csr));
			BPP_PRINT(5, (CE_CONT, "int cntl contains 0x%x.\n",
			    bpp_regs_p->int_cntl));
			/* TC case - terminal count */
			if (bpp_regs_p->dma_csr & BPP_TERMINAL_CNT &&
			    ((bpp_regs_p->dma_csr & BPP_TC_INTR_DISABLE) ==
			    0)) {
				BPP_PRINT(5, (CE_CONT,
				    "Terminal count interrupt found.\n"));
				/* mask this interrupt */
				bpp_regs_p->dma_csr |= BPP_TC_INTR_DISABLE;
				bpp_regs_p->dma_csr &= ~BPP_ENABLE_BCNT;
				/* and clear the interrupting condition */
				bpp_regs_p->dma_csr |= BPP_TERMINAL_CNT;
				bpp_regs_p->dma_csr &= ~BPP_ENABLE_DMA;
				bp->b_resid = bpp_p->transfer_remainder;
				/* Mask the error interrupt conditions */
				bpp_regs_p->int_cntl &=
				    ~(BPP_ERR_IRQ_EN | BPP_SLCT_IRQ_EN |
				    BPP_PE_IRQ_EN);
				BPP_PRINT(5, (CE_CONT, "dma csr 0x%x.\n",
				    bpp_regs_p->dma_csr));
				BPP_PRINT(5, (CE_CONT, "int cntl 0x%x.\n",
				    bpp_regs_p->int_cntl));
			}
			/* ERR_IRQ case - error pin interrupt */
			if ((bpp_regs_p->int_cntl & BPP_ERR_IRQ) &&
			    (bpp_regs_p->int_cntl & BPP_ERR_IRQ_EN)) {
				BPP_PRINT(5, (CE_CONT,
				"Error pin interrupt found.\n"));
				bpp_errorstat_p->pin_status |= BPP_ERR_ERR;
				if (bpp_regs_p->dma_csr & BPP_ENABLE_DMA) {
					/* was transferring */
					bpp_transfer_failed(bpp_unit_no);
				}
				/* clear interrupting condition */
				bpp_regs_p->int_cntl |= BPP_ERR_IRQ;
			}
			/* SLCT_IRQ case - select pin interrupt */
			if ((bpp_regs_p->int_cntl & BPP_SLCT_IRQ) &&
			    (bpp_regs_p->int_cntl & BPP_SLCT_IRQ_EN)) {
				BPP_PRINT(5, (CE_CONT,
				"Select pin interrupt found.\n"));
				bpp_errorstat_p->pin_status |= BPP_SLCT_ERR;
				if (bpp_regs_p->dma_csr & BPP_ENABLE_DMA) {
					/* was transferring */
					bpp_transfer_failed(bpp_unit_no);
				}
				/* clear interrupting condition */
				bpp_regs_p->int_cntl |= BPP_SLCT_IRQ;
			}
			/* PE_IRQ case - paper error pin interrupt */
			if ((bpp_regs_p->int_cntl & BPP_PE_IRQ) &&
			    (bpp_regs_p->int_cntl & BPP_PE_IRQ_EN)) {
				BPP_PRINT(5, (CE_CONT,
				"Paper error pin interrupt found.\n"));
				bpp_errorstat_p->pin_status |= BPP_PE_ERR;
				if (bpp_regs_p->dma_csr & BPP_ENABLE_DMA) {
					/* was transferring */
					bpp_transfer_failed(bpp_unit_no);
				}
				/* clear interrupting condition */
				bpp_regs_p->int_cntl |= BPP_PE_IRQ;
			}
		/*
		 * The interrupts below (BUSY, ACK, and DS)
		 * are available in the hardware, but are not
		 * being used for anything now.
		 */
			/* BUSY_IRQ case - busy pin interrupt */
			if ((bpp_regs_p->int_cntl & BPP_BUSY_IRQ) &&
			    (bpp_regs_p->int_cntl & BPP_BUSY_IRQ_EN)) {
				BPP_PRINT(5, (CE_CONT,
				"Busy pin interrupt found.\n"));
				/* for pio only */
				/* clear interrupting condition */
				bpp_regs_p->int_cntl |= BPP_BUSY_IRQ;
			}
			/* ACK_IRQ case - acknowledge pin interrupt */
			if ((bpp_regs_p->int_cntl & BPP_ACK_IRQ) &&
			    (bpp_regs_p->int_cntl & BPP_ACK_IRQ_EN)) {
				BPP_PRINT(5, (CE_CONT,
				"Acknowledge pin interrupt found.\n"));
				/* for pio only */
				/* clear interrupting condition */
				bpp_regs_p->int_cntl |= BPP_ACK_IRQ;
			}
			/* DS_IRQ case - data strobe pin interrupt */
			if ((bpp_regs_p->int_cntl & BPP_DS_IRQ) &&
			    (bpp_regs_p->int_cntl & BPP_DS_IRQ_EN)) {
				BPP_PRINT(5, (CE_CONT,
				"Data strobe pin interrupt found.\n"));
				/*  for pio only */
				/* clear interrupting condition */
				bpp_regs_p->int_cntl |= BPP_DS_IRQ;
			}
		}		/* end of INT_PEND check */

		BPP_PRINT(5, (CE_CONT,
		    "dma csr 0x%x.\n", bpp_regs_p->dma_csr));
		BPP_PRINT(5, (CE_CONT,
		    "int cntl 0x%x.\n", bpp_regs_p->int_cntl));

		/* Clear the transfer timeout */
		BPP_PRINT(5, (CE_CONT,
		    "In bpp_intr, Clearing transfer timeout.\n"));
		tid = bpp_p->bpp_transfer_timeout_ident;
		bpp_p->bpp_transfer_timeout_ident = 0;
		bpp_p->timeouts &= ~TRANSFER_TIMEOUT;
		BPP_PRINT(5, (CE_CONT, "In bpp_intr, Timeout block is 0x%x.\n",
		    bpp_p->timeouts));
		/*
		 * Release the dvma bus resource.
		 */

		(void) ddi_dma_unbind_handle(bpp_p->bpp_dma_handle);

		BPP_PRINT(5, (CE_CONT,
		    "bpp_intr, unit %d, Calling biodone.\n", unit_no));
		/*
		 * Mark the io on the buf as finished, with the side effect
		 * of waking up others who want to use the buf.
		 */
		mutex_exit(&bpp_p->bpp_mutex);
		if (tid)
			(void) untimeout(tid);
		(void) biodone(bp);
	} else {
		if (bpp_p->intrstats) {
			KIOIP->intrs[KSTAT_INTR_SPURIOUS]++;
		}
		mutex_exit(&bpp_p->bpp_mutex);
	}
	BPP_PRINT(2, (CE_CONT, "Leaving bpp_intr, int_serviced = 0x%x.\n",
	    int_serviced));
	return (int_serviced);
}


/*
 * A transfer has failed for some reason.
 * Mark the bp struct to indicate how much happened,
 * and turn off the transfer and its interrupts.
 */
static void
bpp_transfer_failed(int unit_no)
{
	struct buf		*bp;
	register volatile struct bpp_regs	*bpp_regs_p;
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	bpp_p = getsoftc(unit_no);
	bp = bpp_p->bpp_buffer;		/* saved in bpp_strategy */
	bpp_regs_p = bpp_p->bpp_regs_p;

	BPP_PRINT(2, (CE_CONT, "Entering bpp_transfer_failed.\n"));
	BPP_PRINT(1, (CE_CONT, "ERROR: bpp%d transfer failed!\n", unit_no));

	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));
	/*
	 * The transfer has failed. Notify the application
	 * how many bytes got out, and turn off the transfer.
	 * NOTE: don't set B_ERROR in b_flags else the return from
	 * write() will be -1. See syscall().
	 * NOTE: the kernel ignores the the b_error field
	 * in the short-write case - errno is always set to zero.
	 */
	/* Disable the DMA first for safety */
	bpp_regs_p->dma_csr &= ~BPP_ENABLE_DMA;


	/* If the DMA state machines are not idle, reset them. */
	if (!(bpp_regs_p->op_config & BPP_IDLE)) {
		BPP_PRINT(1, (CE_CONT, "Warning: DMA is not IDLE!\n"));
		bpp_regs_p->dma_csr &= ~BPP_ENABLE_BCNT;
		BPP_PRINT(1, (CE_CONT,
		    "In bpp_strategy, resetting PP state machine\n"));
		bpp_regs_p->op_config |= BPP_SRST;
		bpp_regs_p->op_config &= ~BPP_SRST;

		/*
		 * we have not received the acknowledge for the last
		 * byte transferred, so the byte counter was never
		 * decremented for it.
		 */
		bp->b_resid = ((bpp_regs_p->dma_bcnt - 1) +
		    bpp_p->transfer_remainder);
	} else {
		bpp_regs_p->dma_csr &= ~BPP_ENABLE_BCNT;
		bp->b_resid = (bpp_regs_p->dma_bcnt +
		    bpp_p->transfer_remainder);
	}
	/* flush the local cache */
	bpp_regs_p->dma_csr |= BPP_FLUSH;

	BPP_PRINT(5, (CE_CONT,
	    "In bpp_transfer_failed, Residual is %d.\n", bp->b_resid));

	/* make sure the DMA doesn't start again. */
	bpp_regs_p->dma_bcnt = 0;
	/*
	 * Disable the TC interrupts.
	 * Mask the error interrupts too.
	 */
	bpp_regs_p->dma_csr |= BPP_TC_INTR_DISABLE;
	bpp_regs_p->int_cntl &=
	    ~(BPP_ERR_IRQ_EN | BPP_SLCT_IRQ_EN | BPP_PE_IRQ_EN);

	/* Check for any of the input pins active */
	check_for_active_pins(unit_no);
	BPP_PRINT(2, (CE_CONT, "Leaving bpp_transfer_failed.\n"));
}


/*
 * This routine is called when the DVMA does not complete
 * and generate a TC interrupt.
 * I mark the bp struct to indicate that the transfer failed,
 * and turn off the transfer. I then call biodone to wake up strategy.
 */
static void
bpp_transfer_timeout(void *unit_no_arg)
{
	int unit_no = (int)(uintptr_t)unit_no_arg;
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	register struct buf		*bp;
	register volatile struct bpp_regs	*bpp_regs_p;

	BPP_PRINT(2, (CE_CONT, "Entering bpp_transfer_timeout, unit #%d.\n",
	    unit_no));

	bpp_p = getsoftc(unit_no);
	BPP_PRINT(5, (CE_CONT,
	    "In bpp_transfer_timeout, Timeout block is 0x%x.\n",
	    bpp_p->timeouts));
	mutex_enter(&bpp_p->bpp_mutex);
	if (bpp_p->bpp_transfer_timeout_ident == 0) {
		mutex_exit(&bpp_p->bpp_mutex);
		return;
	}

	ASSERT(bpp_p->timeouts != 0);

	/*
	 * Use the unit number to locate our data structures.
	 */
	bp = bpp_p->bpp_buffer;		/* saved in bpp_strategy */
	bpp_regs_p = bpp_p->bpp_regs_p;

	/*
	 * If we're talking to the
	 * Ricoh scanner, handle it's special "hold busy"
	 * protocol -- Toggle the print/scan (PR/SC) bit and
	 * reset the parallel port
	 */
	BPP_PRINT(5, (CE_CONT, "byte count is %d.\n", bpp_regs_p->dma_bcnt));
	BPP_PRINT(5, (CE_CONT, "write_timeout is %d.\n",
	    bpp_p->transfer_parms.write_timeout));
	if (bpp_regs_p->trans_cntl & BPP_DIRECTION) {
		/* read mode - partial reads will time out */
		BPP_PRINT(5, (CE_CONT, "read timeout, clearing registers.\n"));
		bp->b_resid = (bpp_regs_p->dma_bcnt +
		    bpp_p->transfer_remainder);
		/* make sure the DMA doesn't start again. */
		bpp_regs_p->dma_bcnt = 0;
		/*
		 * Disable the byte counting, and the TC interrupts.
		 * Mask the error interrupts too.
		 */
		bpp_regs_p->dma_csr |= BPP_TC_INTR_DISABLE;
		bpp_regs_p->dma_csr &= ~BPP_ENABLE_BCNT;
		bpp_regs_p->dma_csr &= ~BPP_ENABLE_DMA;
		bpp_regs_p->int_cntl &= ~(BPP_ERR_IRQ_EN | BPP_SLCT_IRQ_EN
		    | BPP_PE_IRQ_EN);
	} else if ((bpp_regs_p->trans_cntl & BPP_DIRECTION) == 0) {
		/* other write cases (read can time out w/no error) */
		bpp_transfer_failed(unit_no);
		/* Mark the error.  */
		/*
		 * bp->b_resid will be set to indicate the number
		 * of bytes actually transferred by bpp_transfer_failed().
		 * If no bytes were transferred, set B_ERROR
		 * so that -1 is returned, and set the b_error value.
		 */
		if (!(bp->b_resid)) {	/* not a partial transfer */
			bp->b_flags |= B_ERROR;
			bp->b_error = EIO;
		}
	}

	/* mark this timeout as no longer pending */
	bpp_p->bpp_transfer_timeout_ident = 0;
	bpp_p->timeouts &= ~TRANSFER_TIMEOUT;
	/* mark the error status structure */
	bpp_p->error_stat.timeout_occurred = 1;
	BPP_PRINT(5, (CE_CONT,
	    "In bpp_transfer_timeout, Timeout blk is 0x%x.\n",
	    bpp_p->timeouts));

	/*
	 * Release the dvma bus resource.
	 */
	(void) ddi_dma_unbind_handle(bpp_p->bpp_dma_handle);

	BPP_PRINT(5, (CE_CONT,
	    "bpp_transfer_timeout, unit %d, Calling biodone.\n", unit_no));
	mutex_exit(&bpp_p->bpp_mutex);
	(void) biodone(bp);
	BPP_PRINT(2, (CE_CONT, "Leaving bpp_transfer_timeout, unit #%d.\n",
	    unit_no));
}


/*	Utility Functions				*/


/*
 * The values of read_setup_time and read_strobe_width
 * have already been bounds-checked. Convert the requested times
 * (in nanoseconds) to SBus clock cycles for the dss and dsw registers.
 * Always round the requested setup time up to the next clock
 * cycle boundary.
 */
static	void
set_dss_dsw(int unit_no, int read_mode)
{
	int	dss_temp;		/* tentative dss value */
	int	dsw_temp;		/* tentative dsw value */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	register struct	bpp_transfer_parms	*bpp_transfer_parms_p;

	BPP_PRINT(2, (CE_CONT,
	    "Entering set_dss_dsw, unit:%d, read_mode = %x.\n",
	    unit_no, read_mode));
	bpp_p = getsoftc(unit_no);
	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));

	bpp_transfer_parms_p = &bpp_p->transfer_parms;

	if (read_mode) {
		dss_temp =
		    bpp_transfer_parms_p->read_setup_time /
		    bpp_p->sbus_clock_cycle;
		if (bpp_transfer_parms_p->read_setup_time %
		    bpp_p->sbus_clock_cycle)
			dss_temp ++;	/* round up */
		dsw_temp =
		    bpp_transfer_parms_p->read_strobe_width /
		    bpp_p->sbus_clock_cycle;
		if (bpp_transfer_parms_p->read_strobe_width %
		    bpp_p->sbus_clock_cycle)
			dsw_temp ++;	/* round up */
	} else {
		dss_temp =
		    bpp_transfer_parms_p->write_setup_time /
		    bpp_p->sbus_clock_cycle;
		if (bpp_transfer_parms_p->write_setup_time %
		    bpp_p->sbus_clock_cycle)
			dss_temp ++;	/* round up */
		dsw_temp =
		    bpp_transfer_parms_p->write_strobe_width /
		    bpp_p->sbus_clock_cycle;
		if (bpp_transfer_parms_p->write_strobe_width %
		    bpp_p->sbus_clock_cycle)
			dsw_temp ++;	/* round up */
	}

	BPP_PRINT(5, (CE_CONT, "dss = 0x%x, dsw = 0x%x\n", dss_temp, dsw_temp));
	bpp_p->bpp_regs_p->hw_config =
	    ((((uchar_t)dsw_temp) << 8) | ((uchar_t)dss_temp));
	BPP_PRINT(2, (CE_CONT,
	    "Leaving set_dss_dsw, unit:%d.\n", unit_no));
}
/*
 * Check the values of the write parameters in the passed bpp_transfer_parms
 * structure. If all the parameters are in range, 0 is returned.
 * If there is an out-of-range parameter, EINVAL is returned.
 */
/*ARGSUSED*/
static	ushort_t
check_write_params(struct  bpp_transfer_parms *parms_p, int unit, int flags)
{
	ushort_t retval = 0;	/* return value (errno) for system call */
	static int max_setup = 0;	/* maximum setup time allowed (ns) */
	static int max_width = 0;	/* maximum width time allowed (ns) */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	bpp_p = getsoftc(unit);
	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));
	retval = 0;
	BPP_PRINT(2, (CE_CONT,
	    "Entering check_write_params, parms_p = %x.\n", parms_p));
	BPP_PRINT(5, (CE_CONT, "write_hs %d, write_time %d, \n",
	    parms_p->write_handshake, parms_p->write_setup_time));
	BPP_PRINT(5, (CE_CONT, "write_width %d, timeout %d.\n",
	    parms_p->write_strobe_width, parms_p->write_timeout));
#ifndef	lint
	/* better rangechecking will be added later */
	/* check for legal range */
	if ((parms_p->write_handshake < BPP_NO_HS) ||
	    (parms_p->write_handshake > BPP_VPLOT_HS)) {
		BPP_PRINT(1, (CE_CONT, "Handshake out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}
	/* the handshake values overlap. Check for read handshakes */
	if ((parms_p->write_handshake > BPP_BUSY_HS) &&
	    (parms_p->write_handshake < BPP_VPRINT_HS)) {
		BPP_PRINT(1, (CE_CONT,
		    "Handshake out of legal write range!\n"));
		retval = EINVAL;
		goto out;
	}
	/* versatec handshakes illegal in read-write mode */
	if ((flags & FREAD) && (parms_p->write_handshake > BPP_BUSY_HS)) {
		BPP_PRINT(1, (CE_CONT, "No versatec handshakes in read md!\n"));
		retval = EINVAL;
		goto out;
	}
	/*
	 * Originally there was a plan to support a versatec mode.
	 * The decision was made not to support it in software.
	 * However, the hooks are still there in the hardware.
	 * I leave the versatec fragments in case the decision is ever
	 * reversed.
	 */
	/* versatec handshakes not implemented in current code */
	if ((parms_p->write_handshake > BPP_BUSY_HS)) {
		BPP_PRINT(1, (CE_CONT,
		    "No versatec handshakes allowed yet!\n"));
		retval = EINVAL;
		goto out;
	}
#endif	/* lint */
	/* check range of setup time and strobe width here */
	max_setup = BPP_DSS_SIZE * bpp_p->sbus_clock_cycle;
	max_width = BPP_DSW_SIZE * bpp_p->sbus_clock_cycle;

	if ((parms_p->write_setup_time < 0) ||
	    (parms_p->write_setup_time > max_setup)) {
		BPP_PRINT(1, (CE_CONT,
		    "Write setup time out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}
	if ((parms_p->write_strobe_width < 0) ||
	    (parms_p->write_strobe_width > max_width)) {
		BPP_PRINT(1, (CE_CONT,
		    "Write strobe width out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}

	/* check range of write timeout */
	if ((parms_p->write_timeout < 0) ||
	    (parms_p->write_timeout > MAX_TIMEOUT)) {
		BPP_PRINT(1, (CE_CONT,
		    "Write timeout out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}

out:
	BPP_PRINT(2, (CE_CONT,
	    "Leaving check_write_params, retval = %d.\n", retval));
	return (retval);
}

/*
 * Check the values of the read parameters in the passed bpp_transfer_parms
 * structure. If all the parameters are in range, 0 is returned.
 * If there is an out-of-range parameter, EINVAL is returned.
 */
/*ARGSUSED*/
static	ushort_t
check_read_params(struct  bpp_transfer_parms *parms_p, uint_t unit, int flags)
{
	ushort_t retval = 0;	/* return value (errno) for system call */
	static int max_setup = 0;	/* maximum setup time allowed (ns) */
	static int max_width = 0;	/* maximum width time allowed (ns) */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	bpp_p = getsoftc(unit);
	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));
	retval = 0;
	BPP_PRINT(2, (CE_CONT,
	    "Entering check_read_params, parms_p = %x.\n", parms_p));
	BPP_PRINT(5, (CE_CONT,
	    "read_hs %d, read_time %d, read_width %d, timeout %d.\n",
	    parms_p->read_handshake, parms_p->read_setup_time,
	    parms_p->read_strobe_width, parms_p->read_timeout));
#ifndef	lint
	/* check for legal range */
	if ((parms_p->read_handshake < BPP_NO_HS) ||
	    (parms_p->read_handshake > BPP_SET_MEM)) {
		BPP_PRINT(1, (CE_CONT, "Handshake out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}
#endif	/* lint */
	/* check range of setup time and strobe width here */
	max_setup = BPP_DSS_SIZE * bpp_p->sbus_clock_cycle;
	max_width = BPP_DSW_SIZE * bpp_p->sbus_clock_cycle;

	if ((parms_p->read_setup_time < 0) ||
	    (parms_p->read_setup_time > max_setup)) {
		BPP_PRINT(1, (CE_CONT,
		    "Read setup time out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}
	if ((parms_p->read_strobe_width < 0) ||
	    (parms_p->read_strobe_width > max_width)) {
		BPP_PRINT(1, (CE_CONT,
		    "Read strobe width out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}

	/* check range of read timeout */
	if ((parms_p->read_timeout < 0) ||
	    (parms_p->read_timeout > MAX_TIMEOUT)) {
		BPP_PRINT(1, (CE_CONT,
		    "Read timeout out of legal range!\n"));
		retval = EINVAL;
		goto out;
	}

out:
	BPP_PRINT(2, (CE_CONT,
	    "Leaving check_read_params, retval = %d.\n", retval));
	return (retval);
}

/*ARGSUSED*/
static	ushort_t
check_read_pins(struct  bpp_pins *pins_p, int flags, uint_t unit,
		register enum handshake_t handshake)
{
	ushort_t retval = 0;	/* return value (errno) for system call */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	bpp_p = getsoftc(unit);
	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));
	BPP_PRINT(2, (CE_CONT,
	    "Entering check_read_pins, pins_p = 0x%x \n", pins_p));
	BPP_PRINT(5, (CE_CONT,
	    "outpins = 0x%x, inpins = 0x%x.\n", pins_p->output_reg_pins,
	    pins_p->input_reg_pins));
	/* check for bogus bits turned on */
	if ((pins_p->output_reg_pins & ~BPP_ALL_OUT_PINS) ||
	    (pins_p->input_reg_pins  & ~BPP_ALL_IN_PINS)) {
		BPP_PRINT(1, (CE_CONT,
		    "Check pins : Bogus bit in bpp pins structure!\n"));
		retval = EINVAL;
		goto out;
	}
out:
	BPP_PRINT(2, (CE_CONT,
	    "Leaving check_read_pins, retval = %d.\n", retval));
	return (retval);
}

/*ARGSUSED*/
static	ushort_t
check_write_pins(struct  bpp_pins *pins_p, int flags, uint_t unit,
		register enum handshake_t handshake)
{
	ushort_t retval = 0;	/* return value (errno) for system call */
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */

	bpp_p = getsoftc(unit);
	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));
	BPP_PRINT(2, (CE_CONT,
	    "Entering check_write_pins, pins_p = 0x%x, \n", pins_p));
	BPP_PRINT(5, (CE_CONT, "outpins = 0x%x, inpins = 0x%x.\n",
	    pins_p->output_reg_pins, pins_p->input_reg_pins));
	/* check for bogus bits turned on */
	if ((pins_p->output_reg_pins & ~BPP_ALL_OUT_PINS) ||
	    (pins_p->input_reg_pins  & ~BPP_ALL_IN_PINS)) {
		BPP_PRINT(1, (CE_CONT,
		    "Check pins : Bogus bit in bpp pins structure!\n"));
		retval = EINVAL;
		goto out;
	}
	/*
	 * Originally there was a plan to support a versatec mode.
	 * The decision was made not to support it in software.
	 * However, the hooks are still there in the hardware.
	 * I leave the versatec fragments in case the decision is ever
	 * reversed.
	 */
#ifndef	lint
	/* versatec handshakes not implemented in current code */
	if ((handshake > BPP_BUSY_HS)) {
		BPP_PRINT(1, (CE_CONT,
		    "No versatec handshakes allowed yet!\n"));
		/*
		 * really, need to check for one bit only of remote
		 * pins set.
		 */
		retval = EINVAL;
		goto out;
	}
#endif	/* lint */
out:
	BPP_PRINT(2, (CE_CONT,
	    "Leaving check_write_pins, retval = %d.\n", retval));
	return (retval);
}

/* ARGSUSED */
static void
read_outpins(int unit_no, int flags, register enum   handshake_t handshake)
{
	register struct	bpp_unit	*bpp_p;	/* will point to this */
						/* unit's state struct */
	uchar_t	temppins;
	BPP_PRINT(2, (CE_CONT,
	    "Entering read_outpins, unit = %d, flags = 0x%x, \n",
	    unit_no, flags));
	bpp_p = getsoftc(unit_no);
	ASSERT(MUTEX_HELD(&bpp_p->bpp_mutex));

	BPP_PRINT(5, (CE_CONT, "handshake = %d.\n", handshake));
	if (flags & FWRITE) {

#if BPP_DEBUG > 0
		if (handshake > BPP_BUSY_HS) {
			BPP_PRINT(1, (CE_CONT,
			    "No versatec handshakes allowed yet!\n"));
		}
#endif /* BPP_DEBUG */

		temppins = bpp_p->bpp_regs_p->out_pins &
		    (BPP_SLCTIN_PIN | BPP_AFX_PIN | BPP_INIT_PIN);
		bpp_p->pins.output_reg_pins |= temppins;
	}

	BPP_PRINT(2, (CE_CONT, "Leaving read_outpins.\n"));
}

/*
 * Peek at the bpp registers to make sure that they really
 * exist. Also check initial conditions. If any of this
 * fails, return a non-zero value.
 */
static	int
check_bpp_registers(int unit_no)
{
	volatile uint32_t *l_reg_addr;		/* address of a 32-bit reg */
	volatile uint32_t l_reg_contents;	/* contents of a 32-bit reg */
	volatile ushort_t *s_reg_addr;		/* address of a 16-bit reg */
	volatile ushort_t s_reg_contents;	/* contents of a 16-bit reg */
	volatile uchar_t *c_reg_addr;		/* address of a 8-bit reg */
	volatile uchar_t c_reg_contents;	/* contents of a 8-bit reg */
	register struct	bpp_unit *bpp_p;	/* will point to this */
						/* unit's state struct */

	BPP_PRINT(2, (CE_CONT, "Entering check_bpp_registers, unit %d.\n",
	    unit_no));
	bpp_p = getsoftc(unit_no);
	/* check the 32-bit dma registers */
	/* dma csr */
	l_reg_addr = &(bpp_p->bpp_regs_p->dma_csr);
	if (ddi_peek32(bpp_p->dip,
	    (int32_t *)l_reg_addr, (int32_t *)&l_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed dma csr, address %x\n",
		    l_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "dma_csr contains %x\n", l_reg_contents));

	/* dma addr */
	l_reg_addr = &(bpp_p->bpp_regs_p->dma_addr);
	if (ddi_peek32(bpp_p->dip,
	    (int32_t *)l_reg_addr, (int32_t *)&l_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed dma addr, address %x\n",
		    l_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "dma_addr contains %x\n", l_reg_contents));

	/* dma bcnt */
	l_reg_addr = &(bpp_p->bpp_regs_p->dma_bcnt);
	if (ddi_peek32(bpp_p->dip,
	    (int32_t *)l_reg_addr, (int32_t *)&l_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed dma bcnt, address %x\n",
		    l_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "dma_bcnt contains %x\n", l_reg_contents));

/* short hardware registers */
	/* hw_config */
	s_reg_addr = &(bpp_p->bpp_regs_p->hw_config);
	if (ddi_peek16(bpp_p->dip,
	    (int16_t *)s_reg_addr, (int16_t *)&s_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed hw_config, address %x\n",
		    s_reg_addr));
		return (1);
	}
	if (ddi_poke16(bpp_p->dip,
	    (short *)s_reg_addr, s_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: poke failed hw_config, address %x\n",
		    s_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "hw_config contains %x\n", s_reg_contents));

	/* op_config */
	s_reg_addr = &(bpp_p->bpp_regs_p->op_config);
	if (ddi_peek16(bpp_p->dip,
	    (short *)s_reg_addr, (short *)&s_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed op_config, address %x\n",
		    s_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "op_config contains %x\n", s_reg_contents));

	/* int_cntl */
	s_reg_addr = &(bpp_p->bpp_regs_p->int_cntl);
	if (ddi_peek16(bpp_p->dip,
	    (short *)s_reg_addr, (short *)&s_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed int_cntl, address %x\n",
		    s_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "int_cntl contains %x\n", s_reg_contents));

/* char hardware registers */
	/* data */
	c_reg_addr = &(bpp_p->bpp_regs_p->data);
	if (ddi_peek8(bpp_p->dip,
	    (char *)c_reg_addr, (char *)&c_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed data, address %x\n",
		    c_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "data contains %x\n", c_reg_contents));

	/* trans_cntl */
	c_reg_addr = &(bpp_p->bpp_regs_p->trans_cntl);
	if (ddi_peek8(bpp_p->dip,
	    (char *)c_reg_addr, (char *)&c_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers:peek failed trans_cntl, address %x\n",
		    c_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "trans_cntl contains %x\n", c_reg_contents));

	/* out_pins */
	c_reg_addr = &(bpp_p->bpp_regs_p->out_pins);
	if (ddi_peek8(bpp_p->dip,
	    (char *)c_reg_addr, (char *)&c_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed out_pins, address %x\n",
		    c_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "out_pins contains %x\n", c_reg_contents));

	/* in_pins */
	c_reg_addr = &(bpp_p->bpp_regs_p->in_pins);
	if (ddi_peek8(bpp_p->dip,
	    (char *)c_reg_addr, (char *)&c_reg_contents) != DDI_SUCCESS) {
		BPP_PRINT(1, (CE_CONT,
		    "ck_bpp_registers: peek failed in_pins, address %x\n",
		    c_reg_addr));
		return (1);
	}
	BPP_PRINT(5, (CE_CONT, "in_pins contains %x\n", c_reg_contents));
	BPP_PRINT(5, (CE_CONT,
	    "Leaving check_bpp_registers, unit %d.\n", unit_no));
	return (0);
}
