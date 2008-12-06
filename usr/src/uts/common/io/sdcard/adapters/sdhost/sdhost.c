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

#include "sdhost.h"

typedef	struct sdslot	sdslot_t;
typedef	struct sdhost	sdhost_t;

/*
 * Per slot state.
 */
struct sdslot {
	sda_host_t		*ss_host;
	int			ss_num;
	ddi_acc_handle_t	ss_acch;
	caddr_t 		ss_regva;
	kmutex_t		ss_lock;
	uint32_t		ss_capab;
	uint32_t		ss_baseclk;	/* Hz */
	uint32_t		ss_cardclk;	/* Hz */
	uint8_t			ss_tmoutclk;
	uint32_t		ss_tmusecs;	/* timeout units in usecs */
	uint32_t		ss_ocr;		/* OCR formatted voltages */
	uint16_t		ss_mode;
	boolean_t		ss_suspended;

	/*
	 * Command in progress
	 */
	uint8_t			*ss_kvaddr;
	ddi_dma_cookie_t	*ss_dmacs;
	uint_t			ss_ndmac;
	int			ss_blksz;
	uint16_t		ss_resid;	/* in blocks */

	/* scratch buffer, to receive extra PIO data */
	uint32_t		ss_bounce[2048 / 4];
};

/*
 * Per controller state.
 */
struct sdhost {
	int			sh_numslots;
	ddi_dma_attr_t		sh_dmaattr;
	sdslot_t		sh_slots[SDHOST_MAXSLOTS];
	sda_host_t		*sh_host;

	/*
	 * Interrupt related information.
	 */
	ddi_intr_handle_t	sh_ihandle;
	int			sh_icap;
	uint_t			sh_ipri;
};


static int sdhost_attach(dev_info_t *, ddi_attach_cmd_t);
static int sdhost_detach(dev_info_t *, ddi_detach_cmd_t);
static int sdhost_quiesce(dev_info_t *);
static int sdhost_suspend(dev_info_t *);
static int sdhost_resume(dev_info_t *);

static void sdhost_enable_interrupts(sdslot_t *);
static void sdhost_disable_interrupts(sdslot_t *);
static int sdhost_setup_intr(dev_info_t *, sdhost_t *);
static uint_t sdhost_intr(caddr_t, caddr_t);
static int sdhost_init_slot(dev_info_t *, sdhost_t *, int, int);
static void sdhost_uninit_slot(sdhost_t *, int);
static sda_err_t sdhost_soft_reset(sdslot_t *, uint8_t);
static sda_err_t sdhost_set_clock(sdslot_t *, uint32_t);
static void sdhost_xfer_done(sdslot_t *, sda_err_t);
static sda_err_t sdhost_wait_cmd(sdslot_t *, sda_cmd_t *);
static uint_t sdhost_slot_intr(sdslot_t *);

static sda_err_t sdhost_cmd(void *, sda_cmd_t *);
static sda_err_t sdhost_getprop(void *, sda_prop_t, uint32_t *);
static sda_err_t sdhost_setprop(void *, sda_prop_t, uint32_t);
static sda_err_t sdhost_poll(void *);
static sda_err_t sdhost_reset(void *);
static sda_err_t sdhost_halt(void *);

static struct dev_ops sdhost_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	ddi_no_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	sdhost_attach,			/* devo_attach */
	sdhost_detach,			/* devo_detach */
	nodev,				/* devo_reset */
	NULL,				/* devo_cb_ops */
	NULL,				/* devo_bus_ops */
	NULL,				/* devo_power */
	sdhost_quiesce,			/* devo_quiesce */
};

static struct modldrv sdhost_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Standard SD Host Controller",	/* drv_linkinfo */
	&sdhost_dev_ops			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev */
	{ &sdhost_modldrv, NULL }	/* ml_linkage */
};

static struct sda_ops sdhost_ops = {
	SDA_OPS_VERSION,
	sdhost_cmd,			/* so_cmd */
	sdhost_getprop,			/* so_getprop */
	sdhost_setprop,			/* so_setprop */
	sdhost_poll,			/* so_poll */
	sdhost_reset,			/* so_reset */
	sdhost_halt,			/* so_halt */
};

static ddi_device_acc_attr_t sdhost_regattr = {
	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_STRUCTURE_LE_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC,	/* devacc_attr_dataorder */
	DDI_DEFAULT_ACC,	/* devacc_attr_access */
};

#define	GET16(ss, reg)	\
	ddi_get16(ss->ss_acch, (void *)(ss->ss_regva + reg))
#define	PUT16(ss, reg, val)	\
	ddi_put16(ss->ss_acch, (void *)(ss->ss_regva + reg), val)
#define	GET32(ss, reg)	\
	ddi_get32(ss->ss_acch, (void *)(ss->ss_regva + reg))
#define	PUT32(ss, reg, val)	\
	ddi_put32(ss->ss_acch, (void *)(ss->ss_regva + reg), val)
#define	GET64(ss, reg)	\
	ddi_get64(ss->ss_acch, (void *)(ss->ss_regva + reg))

#define	GET8(ss, reg)	\
	ddi_get8(ss->ss_acch, (void *)(ss->ss_regva + reg))
#define	PUT8(ss, reg, val)	\
	ddi_put8(ss->ss_acch, (void *)(ss->ss_regva + reg), val)

#define	CLR8(ss, reg, mask)	PUT8(ss, reg, GET8(ss, reg) & ~(mask))
#define	SET8(ss, reg, mask)	PUT8(ss, reg, GET8(ss, reg) | (mask))

/*
 * If ever anyone uses PIO on SPARC, we have to endian-swap.  But we
 * think that SD Host Controllers are likely to be uncommon on SPARC,
 * and hopefully when they exist at all they will be able to use DMA.
 */
#ifdef	_BIG_ENDIAN
#define	sw32(x)		ddi_swap32(x)
#define	sw16(x)		ddi_swap16(x)
#else
#define	sw32(x)		(x)
#define	sw16(x)		(x)
#endif

#define	GETDATA32(ss)		sw32(GET32(ss, REG_DATA))
#define	GETDATA16(ss)		sw16(GET16(ss, REG_DATA))
#define	GETDATA8(ss)		GET8(ss, REG_DATA)

#define	PUTDATA32(ss, val)	PUT32(ss, REG_DATA, sw32(val))
#define	PUTDATA16(ss, val)	PUT16(ss, REG_DATA, sw16(val))
#define	PUTDATA8(ss, val)	PUT8(ss, REG_DATA, val)

#define	CHECK_STATE(ss, nm)	\
	((GET32(ss, REG_PRS) & PRS_ ## nm) != 0)

int
_init(void)
{
	int	rv;

	sda_host_init_ops(&sdhost_dev_ops);

	if ((rv = mod_install(&modlinkage)) != 0) {
		sda_host_fini_ops(&sdhost_dev_ops);
	}

	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		sda_host_fini_ops(&sdhost_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
sdhost_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sdhost_t		*shp;
	ddi_acc_handle_t	pcih;
	uint8_t			slotinfo;
	uint8_t			bar;
	int			i;
	int			rv;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (sdhost_resume(dip));

	default:
		return (DDI_FAILURE);
	}

	/*
	 * Soft state allocation.
	 */
	shp = kmem_zalloc(sizeof (*shp), KM_SLEEP);
	ddi_set_driver_private(dip, shp);

	/*
	 * Initialize DMA attributes.  For now we initialize as for
	 * SDMA.  If we add ADMA support we can improve this.
	 */
	shp->sh_dmaattr.dma_attr_version = DMA_ATTR_V0;
	shp->sh_dmaattr.dma_attr_addr_lo = 0;
	shp->sh_dmaattr.dma_attr_addr_hi = 0xffffffffU;
	shp->sh_dmaattr.dma_attr_count_max = 0xffffffffU;
	shp->sh_dmaattr.dma_attr_align = 1;
	shp->sh_dmaattr.dma_attr_burstsizes = 0;	/* for now! */
	shp->sh_dmaattr.dma_attr_minxfer = 1;
	shp->sh_dmaattr.dma_attr_maxxfer = 0xffffffffU;
	shp->sh_dmaattr.dma_attr_sgllen = -1;		/* unlimited! */
	shp->sh_dmaattr.dma_attr_seg = 0xfff;		/* 4K segments */
	shp->sh_dmaattr.dma_attr_granular = 1;
	shp->sh_dmaattr.dma_attr_flags = 0;

	/*
	 * PCI configuration access to figure out number of slots present.
	 */
	if (pci_config_setup(dip, &pcih) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pci_config_setup failed");
		goto failed;
	}

	slotinfo = pci_config_get8(pcih, SLOTINFO);
	shp->sh_numslots = SLOTINFO_NSLOT(slotinfo);

	if (shp->sh_numslots > SDHOST_MAXSLOTS) {
		cmn_err(CE_WARN, "Host reports to have too many slots: %d",
		    shp->sh_numslots);
		goto failed;
	}

	/*
	 * Enable master accesses and DMA.
	 */
	pci_config_put16(pcih, PCI_CONF_COMM,
	    pci_config_get16(pcih, PCI_CONF_COMM) |
	    PCI_COMM_MAE | PCI_COMM_ME);

	/*
	 * Figure out which BAR to use.  Note that we number BARs from
	 * 1, although PCI and SD Host numbers from 0.  (We number
	 * from 1, because register number 0 means PCI configuration
	 * space in Solaris.)
	 */
	bar = SLOTINFO_BAR(slotinfo) + 1;

	pci_config_teardown(&pcih);

	/*
	 * Setup interrupts ... supports the new DDI interrupt API.  This
	 * will support MSI or MSI-X interrupts if a device is found to
	 * support it.
	 */
	if (sdhost_setup_intr(dip, shp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to setup interrupts");
		goto failed;
	}

	shp->sh_host = sda_host_alloc(dip, shp->sh_numslots, &sdhost_ops,
	    &shp->sh_dmaattr);
	if (shp->sh_host == NULL) {
		cmn_err(CE_WARN, "Failed allocating SD host structure");
		goto failed;
	}

	/*
	 * Configure slots, this also maps registers, enables
	 * interrupts, etc.  Most of the hardware setup is done here.
	 */
	for (i = 0; i < shp->sh_numslots; i++) {
		if (sdhost_init_slot(dip, shp, i, bar + i) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed initializing slot %d", i);
			goto failed;
		}
	}

	ddi_report_dev(dip);

	/*
	 * Enable device interrupts at the DDI layer.
	 */
	if (shp->sh_icap & DDI_INTR_FLAG_BLOCK) {
		rv = ddi_intr_block_enable(&shp->sh_ihandle, 1);
	} else {
		rv = ddi_intr_enable(shp->sh_ihandle);
	}
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed enabling interrupts");
		goto failed;
	}

	/*
	 * Mark the slots online with the framework.  This will cause
	 * the framework to probe them for the presence of cards.
	 */
	if (sda_host_attach(shp->sh_host) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed attaching to SDA framework");
		if (shp->sh_icap & DDI_INTR_FLAG_BLOCK) {
			(void) ddi_intr_block_disable(&shp->sh_ihandle, 1);
		} else {
			(void) ddi_intr_disable(shp->sh_ihandle);
		}
		goto failed;
	}

	return (DDI_SUCCESS);

failed:
	if (shp->sh_ihandle != NULL) {
		(void) ddi_intr_remove_handler(shp->sh_ihandle);
		(void) ddi_intr_free(shp->sh_ihandle);
	}
	for (i = 0; i < shp->sh_numslots; i++)
		sdhost_uninit_slot(shp, i);
	kmem_free(shp, sizeof (*shp));

	return (DDI_FAILURE);
}

int
sdhost_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sdhost_t	*shp;
	int		i;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (sdhost_suspend(dip));

	default:
		return (DDI_FAILURE);
	}

	shp = ddi_get_driver_private(dip);

	/*
	 * Take host offline with the framework.
	 */
	sda_host_detach(shp->sh_host);

	/*
	 * Tear down interrupts.
	 */
	if (shp->sh_ihandle != NULL) {
		if (shp->sh_icap & DDI_INTR_FLAG_BLOCK) {
			(void) ddi_intr_block_disable(&shp->sh_ihandle, 1);
		} else {
			(void) ddi_intr_disable(shp->sh_ihandle);
		}
		(void) ddi_intr_remove_handler(shp->sh_ihandle);
		(void) ddi_intr_free(shp->sh_ihandle);
	}

	/*
	 * Tear down register mappings, etc.
	 */
	for (i = 0; i < shp->sh_numslots; i++)
		sdhost_uninit_slot(shp, i);
	kmem_free(shp, sizeof (*shp));

	return (DDI_SUCCESS);
}

int
sdhost_quiesce(dev_info_t *dip)
{
	sdhost_t	*shp;
	sdslot_t	*ss;

	shp = ddi_get_driver_private(dip);

	/* reset each slot separately */
	for (int i = 0; i < shp->sh_numslots; i++) {
		ss = &shp->sh_slots[i];
		if (ss->ss_acch == NULL)
			continue;

		(void) sdhost_soft_reset(ss, SOFT_RESET_ALL);
	}
	return (DDI_SUCCESS);
}

int
sdhost_suspend(dev_info_t *dip)
{
	sdhost_t	*shp;
	sdslot_t	*ss;
	int		i;

	shp = ddi_get_driver_private(dip);

	sda_host_suspend(shp->sh_host);

	for (i = 0; i < shp->sh_numslots; i++) {
		ss = &shp->sh_slots[i];
		mutex_enter(&ss->ss_lock);
		ss->ss_suspended = B_TRUE;
		sdhost_disable_interrupts(ss);
		(void) sdhost_soft_reset(ss, SOFT_RESET_ALL);
		mutex_exit(&ss->ss_lock);
	}
	return (DDI_SUCCESS);
}

int
sdhost_resume(dev_info_t *dip)
{
	sdhost_t	*shp;
	sdslot_t	*ss;
	int		i;

	shp = ddi_get_driver_private(dip);

	for (i = 0; i < shp->sh_numslots; i++) {
		ss = &shp->sh_slots[i];
		mutex_enter(&ss->ss_lock);
		ss->ss_suspended = B_FALSE;
		(void) sdhost_soft_reset(ss, SOFT_RESET_ALL);
		sdhost_enable_interrupts(ss);
		mutex_exit(&ss->ss_lock);
	}

	sda_host_resume(shp->sh_host);

	return (DDI_SUCCESS);
}

sda_err_t
sdhost_set_clock(sdslot_t *ss, uint32_t hz)
{
	uint16_t	div;
	uint32_t	val;
	uint32_t	clk;
	int		count;

	/*
	 * Shut off the clock to begin.
	 */
	ss->ss_cardclk = 0;
	PUT16(ss, REG_CLOCK_CONTROL, 0);
	if (hz == 0) {
		return (SDA_EOK);
	}

	if (ss->ss_baseclk == 0) {
		sda_host_log(ss->ss_host, ss->ss_num,
		    "Base clock frequency not established.");
		return (SDA_EINVAL);
	}

	if ((hz > 25000000) && ((ss->ss_capab & CAPAB_HIGH_SPEED) != 0)) {
		/* this clock requires high speed timings! */
		SET8(ss, REG_HOST_CONTROL, HOST_CONTROL_HIGH_SPEED_EN);
	} else {
		/* don't allow clock to run faster than 25MHz */
		hz = min(hz, 25000000);
		CLR8(ss, REG_HOST_CONTROL, HOST_CONTROL_HIGH_SPEED_EN);
	}

	/* figure out the divider */
	clk = ss->ss_baseclk;
	div  = 1;
	while (clk > hz) {
		if (div > 0x80)
			break;
		clk >>= 1;	/* divide clock by two */
		div <<= 1;	/* divider goes up by one */
	}
	div >>= 1;	/* 0 == divide by 1, 1 = divide by 2 */

	/*
	 * Set the internal clock divider first, without enabling the
	 * card clock yet.
	 */
	PUT16(ss, REG_CLOCK_CONTROL,
	    (div << CLOCK_CONTROL_FREQ_SHIFT) | CLOCK_CONTROL_INT_CLOCK_EN);

	/*
	 * Wait up to 100 msec for the internal clock to stabilize.
	 * (The spec does not seem to indicate a maximum timeout, but
	 * it also suggests that an infinite loop be used, which is
	 * not appropriate for hardened Solaris drivers.)
	 */
	for (count = 100000; count; count -= 10) {

		val = GET16(ss, REG_CLOCK_CONTROL);

		if (val & CLOCK_CONTROL_INT_CLOCK_STABLE) {
			/* if clock is stable, enable the SD clock pin */
			PUT16(ss, REG_CLOCK_CONTROL, val |
			    CLOCK_CONTROL_SD_CLOCK_EN);

			ss->ss_cardclk = clk;
			return (SDA_EOK);
		}

		drv_usecwait(10);
	}

	return (SDA_ETIME);
}

sda_err_t
sdhost_soft_reset(sdslot_t *ss, uint8_t bits)
{
	int	count;

	/*
	 * There appears to be a bug where Ricoh hosts might have a
	 * problem if the host frequency is not set.  If the card
	 * isn't present, or we are doing a master reset, just enable
	 * the internal clock at its native speed.  (No dividers, and
	 * not exposed to card.).
	 */
	if ((bits == SOFT_RESET_ALL) || !(CHECK_STATE(ss, CARD_INSERTED))) {
		PUT16(ss, REG_CLOCK_CONTROL, CLOCK_CONTROL_INT_CLOCK_EN);
		/* simple 1msec wait, don't wait for clock to stabilize */
		drv_usecwait(1000);
	}

	PUT8(ss, REG_SOFT_RESET, bits);
	for (count = 100000; count != 0; count -= 10) {
		if ((GET8(ss, REG_SOFT_RESET) & bits) == 0) {
			return (SDA_EOK);
		}
		drv_usecwait(10);
	}

	return (SDA_ETIME);
}

void
sdhost_disable_interrupts(sdslot_t *ss)
{
	/* disable slot interrupts for card insert and remove */
	PUT16(ss, REG_INT_MASK, 0);
	PUT16(ss, REG_INT_EN, 0);

	/* disable error interrupts */
	PUT16(ss, REG_ERR_MASK, 0);
	PUT16(ss, REG_ERR_EN, 0);
}

void
sdhost_enable_interrupts(sdslot_t *ss)
{
	/*
	 * Note that we want to enable reading of the CMD related
	 * bits, but we do not want them to generate an interrupt.
	 * (The busy wait for typical CMD stuff will normally be less
	 * than 10usec, so its simpler/easier to just poll.  Even in
	 * the worst case of 100 kHz, the poll is at worst 2 msec.)
	 */

	/* enable slot interrupts for card insert and remove */
	PUT16(ss, REG_INT_MASK, INT_MASK);
	PUT16(ss, REG_INT_EN, INT_ENAB);

	/* enable error interrupts */
	PUT16(ss, REG_ERR_MASK, ERR_MASK);
	PUT16(ss, REG_ERR_EN, ERR_ENAB);
}

int
sdhost_setup_intr(dev_info_t *dip, sdhost_t *shp)
{
	int		itypes;
	int		itype;

	/*
	 * Set up interrupt handler.
	 */
	if (ddi_intr_get_supported_types(dip, &itypes) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_intr_get_supported_types failed");
		return (DDI_FAILURE);
	}

	/*
	 * Interrupt types are bits in a mask.  We know about these ones:
	 * FIXED = 1
	 * MSI = 2
	 * MSIX = 4
	 */
	for (itype = DDI_INTR_TYPE_MSIX; itype != 0; itype >>= 1) {

		int			count;

		if ((itypes & itype) == 0) {
			/* this type is not supported on this device! */
			continue;
		}

		if ((ddi_intr_get_nintrs(dip, itype, &count) != DDI_SUCCESS) ||
		    (count == 0)) {
			cmn_err(CE_WARN, "ddi_intr_get_nintrs failed");
			continue;
		}

		/*
		 * We have not seen a host device with multiple
		 * interrupts (one per slot?), and the spec does not
		 * indicate that they exist.  But if one ever occurs,
		 * we spew a warning to help future debugging/support
		 * efforts.
		 */
		if (count > 1) {
			cmn_err(CE_WARN, "Controller offers %d interrupts, "
			    "but driver only supports one", count);
			continue;
		}

		if ((ddi_intr_alloc(dip, &shp->sh_ihandle, itype, 0, 1,
		    &count, DDI_INTR_ALLOC_NORMAL) != DDI_SUCCESS) ||
		    (count != 1)) {
			cmn_err(CE_WARN, "ddi_intr_alloc failed");
			continue;
		}

		if (ddi_intr_get_pri(shp->sh_ihandle, &shp->sh_ipri) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "ddi_intr_get_pri failed");
			(void) ddi_intr_free(shp->sh_ihandle);
			shp->sh_ihandle = NULL;
			continue;
		}

		if (shp->sh_ipri >= ddi_intr_get_hilevel_pri()) {
			cmn_err(CE_WARN, "Hi level interrupt not supported");
			(void) ddi_intr_free(shp->sh_ihandle);
			shp->sh_ihandle = NULL;
			continue;
		}

		if (ddi_intr_get_cap(shp->sh_ihandle, &shp->sh_icap) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "ddi_intr_get_cap failed");
			(void) ddi_intr_free(shp->sh_ihandle);
			shp->sh_ihandle = NULL;
			continue;
		}

		if (ddi_intr_add_handler(shp->sh_ihandle, sdhost_intr,
		    shp, NULL) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "ddi_intr_add_handler failed");
			(void) ddi_intr_free(shp->sh_ihandle);
			shp->sh_ihandle = NULL;
			continue;
		}

		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

void
sdhost_xfer_done(sdslot_t *ss, sda_err_t errno)
{
	if ((errno == SDA_EOK) && (ss->ss_resid != 0)) {
		/* an unexpected partial transfer was found */
		errno = SDA_ERESID;
	}
	ss->ss_blksz = 0;
	ss->ss_resid = 0;

	if (errno != SDA_EOK) {
		(void) sdhost_soft_reset(ss, SOFT_RESET_CMD);
		(void) sdhost_soft_reset(ss, SOFT_RESET_DAT);

		/* send a STOP command if necessary */
		if (ss->ss_mode & XFR_MODE_AUTO_CMD12) {
			PUT32(ss, REG_ARGUMENT, 0);
			PUT16(ss, REG_COMMAND,
			    (CMD_STOP_TRANSMIT << 8) |
			    COMMAND_TYPE_NORM | COMMAND_INDEX_CHECK_EN |
			    COMMAND_CRC_CHECK_EN | COMMAND_RESP_48_BUSY);
		}
	}

	sda_host_transfer(ss->ss_host, ss->ss_num, errno);
}

uint_t
sdhost_slot_intr(sdslot_t *ss)
{
	uint16_t	intr;
	uint16_t	errs;
	uint8_t		*data;
	int		count;

	mutex_enter(&ss->ss_lock);

	if (ss->ss_suspended) {
		mutex_exit(&ss->ss_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	intr = GET16(ss, REG_INT_STAT);
	if (intr == 0) {
		mutex_exit(&ss->ss_lock);
		return (DDI_INTR_UNCLAIMED);
	}
	errs = GET16(ss, REG_ERR_STAT);

	if (intr & (INT_REM | INT_INS)) {

		PUT16(ss, REG_INT_STAT, intr);
		mutex_exit(&ss->ss_lock);

		sda_host_detect(ss->ss_host, ss->ss_num);
		/* no further interrupt processing this cycle */
		return (DDI_INTR_CLAIMED);
	}

	if (intr & INT_DMA) {
		/*
		 * We have crossed a DMA/page boundary.  Cope with it.
		 */
		if (ss->ss_ndmac) {
			ss->ss_ndmac--;
			ss->ss_dmacs++;
			PUT16(ss, REG_INT_STAT, INT_DMA);
			PUT32(ss, REG_SDMA_ADDR, ss->ss_dmacs->dmac_address);

		} else {
			/*
			 * Apparently some sdhost controllers issue a
			 * final DMA interrupt if the DMA completes on
			 * a boundary, even though there is no further
			 * data to transfer.
			 *
			 * There might be a risk here of the
			 * controller continuing to access the same
			 * data over and over again, but we accept the
			 * risk.
			 */
			PUT16(ss, REG_INT_STAT, INT_DMA);
		}
	}

	if (intr & INT_RD) {
		/*
		 * PIO read!  PIO is quite suboptimal, but we expect
		 * performance critical applications to use DMA
		 * whenever possible.  We have to stage this through
		 * the bounce buffer to meet alignment considerations.
		 */

		PUT16(ss, REG_INT_STAT, INT_RD);

		while ((ss->ss_resid > 0) && CHECK_STATE(ss, BUF_RD_EN)) {

			data = (void *)ss->ss_bounce;
			count = ss->ss_blksz;

			ASSERT(count > 0);
			ASSERT(ss->ss_kvaddr != NULL);

			while (count >= sizeof (uint32_t)) {
				*(uint32_t *)(void *)data = GETDATA32(ss);
				data += sizeof (uint32_t);
				count -= sizeof (uint32_t);
			}
			while (count >= sizeof (uint16_t)) {
				*(uint16_t *)(void *)data = GETDATA16(ss);
				data += sizeof (uint16_t);
				count -= sizeof (uint16_t);
			}
			while (count >= sizeof (uint8_t)) {
				*(uint8_t *)data = GETDATA8(ss);
				data += sizeof (uint8_t);
				count -= sizeof (uint8_t);
			}

			bcopy(ss->ss_bounce, ss->ss_kvaddr, ss->ss_blksz);
			ss->ss_kvaddr += ss->ss_blksz;
			ss->ss_resid--;
		}
	}

	if (intr & INT_WR) {
		/*
		 * PIO write!  PIO is quite suboptimal, but we expect
		 * performance critical applications to use DMA
		 * whenever possible.  We have to stage this trhough
		 * the bounce buffer to meet alignment considerations.
		 */

		PUT16(ss, REG_INT_STAT, INT_WR);

		while ((ss->ss_resid > 0) && CHECK_STATE(ss, BUF_WR_EN)) {

			data = (void *)ss->ss_bounce;
			count = ss->ss_blksz;

			ASSERT(count > 0);
			ASSERT(ss->ss_kvaddr != NULL);

			bcopy(ss->ss_kvaddr, data, count);
			while (count >= sizeof (uint32_t)) {
				PUTDATA32(ss, *(uint32_t *)(void *)data);
				data += sizeof (uint32_t);
				count -= sizeof (uint32_t);
			}
			while (count >= sizeof (uint16_t)) {
				PUTDATA16(ss, *(uint16_t *)(void *)data);
				data += sizeof (uint16_t);
				count -= sizeof (uint16_t);
			}
			while (count >= sizeof (uint8_t)) {
				PUTDATA8(ss, *(uint8_t *)data);
				data += sizeof (uint8_t);
				count -= sizeof (uint8_t);
			}

			ss->ss_kvaddr += ss->ss_blksz;
			ss->ss_resid--;
		}
	}

	if (intr & INT_XFR) {
		PUT16(ss, REG_INT_STAT, INT_XFR);

		sdhost_xfer_done(ss, SDA_EOK);
	}

	if (intr & INT_ERR) {
		PUT16(ss, REG_ERR_STAT, errs);
		PUT16(ss, REG_INT_STAT, INT_ERR);

		if (errs & ERR_DAT) {
			if ((errs & ERR_DAT_END) == ERR_DAT_END) {
				sdhost_xfer_done(ss, SDA_EPROTO);
			} else if ((errs & ERR_DAT_CRC) == ERR_DAT_CRC) {
				sdhost_xfer_done(ss, SDA_ECRC7);
			} else {
				sdhost_xfer_done(ss, SDA_ETIME);
			}

		} else if (errs & ERR_ACMD12) {
			/*
			 * Generally, this is bad news.  we need a full
			 * reset to recover properly.
			 */
			sdhost_xfer_done(ss, SDA_ECMD12);
		}

		/*
		 * This asynchronous error leaves the slot more or less
		 * useless.  Report it to the framework.
		 */
		if (errs & ERR_CURRENT) {
			sda_host_fault(ss->ss_host, ss->ss_num,
			    SDA_FAULT_CURRENT);
		}
	}

	mutex_exit(&ss->ss_lock);

	return (DDI_INTR_CLAIMED);
}

/*ARGSUSED1*/
uint_t
sdhost_intr(caddr_t arg1, caddr_t arg2)
{
	sdhost_t	*shp = (void *)arg1;
	int		rv = DDI_INTR_UNCLAIMED;
	int		num;

	/* interrupt for each of the slots present in the system */
	for (num = 0; num < shp->sh_numslots; num++) {
		if (sdhost_slot_intr(&shp->sh_slots[num]) ==
		    DDI_INTR_CLAIMED) {
			rv = DDI_INTR_CLAIMED;
		}
	}
	return (rv);
}

int
sdhost_init_slot(dev_info_t *dip, sdhost_t *shp, int num, int bar)
{
	sdslot_t	*ss;
	uint32_t	capab;
	uint32_t	clk;

	/*
	 * Register the private state.
	 */
	ss = &shp->sh_slots[num];
	ss->ss_host = shp->sh_host;
	ss->ss_num = num;
	sda_host_set_private(shp->sh_host, num, ss);

	/*
	 * Initialize core data structure, locks, etc.
	 */
	mutex_init(&ss->ss_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(shp->sh_ipri));

	if (ddi_regs_map_setup(dip, bar, &ss->ss_regva, 0, 0, &sdhost_regattr,
	    &ss->ss_acch) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to map registers!");
		return (DDI_FAILURE);
	}

	/* reset before reading capabilities */
	if (sdhost_soft_reset(ss, SOFT_RESET_ALL) != SDA_EOK)
		return (DDI_FAILURE);

	capab = GET64(ss, REG_CAPAB) & 0xffffffffU; /* upper bits reserved */
	ss->ss_capab = capab;

	/* host voltages in OCR format */
	ss->ss_ocr = 0;
	if (capab & CAPAB_18V)
		ss->ss_ocr |= OCR_18_19V;	/* 1.8V */
	if (capab & CAPAB_30V)
		ss->ss_ocr |= OCR_30_31V;
	if (capab & CAPAB_33V)
		ss->ss_ocr |= OCR_32_33V;

	/* base clock */
	ss->ss_baseclk =
	    ((capab & CAPAB_BASE_FREQ_MASK) >> CAPAB_BASE_FREQ_SHIFT);
	ss->ss_baseclk *= 1000000;

	/*
	 * Timeout clock.  We can calculate this using the following
	 * formula:
	 *
	 * (1000000 usec/1sec) * (1sec/tmoutclk) * base factor = clock time
	 *
	 * Clock time is the length of the base clock in usecs.
	 *
	 * Our base factor is 2^13, which is the shortest clock we
	 * can count.
	 *
	 * To simplify the math and avoid overflow, we cancel out the
	 * zeros for kHz or MHz.  Since we want to wait more clocks, not
	 * less, on error, we truncate the result rather than rounding
	 * up.
	 */
	clk = ((capab & CAPAB_TIMEOUT_FREQ_MASK) >> CAPAB_TIMEOUT_FREQ_SHIFT);
	if ((ss->ss_baseclk == 0) || (clk == 0)) {
		cmn_err(CE_WARN, "Unable to determine clock frequencies");
		return (DDI_FAILURE);
	}

	if (capab & CAPAB_TIMEOUT_UNITS) {
		/* MHz */
		ss->ss_tmusecs = (1 << 13) / clk;
		clk *= 1000000;
	} else {
		/* kHz */
		ss->ss_tmusecs = (1000 * (1 << 13)) / clk;
		clk *= 1000;
	}

	/*
	 * Calculation of the timeout.
	 *
	 * SDIO cards use a 1sec timeout, and SDHC cards use fixed
	 * 100msec for read and 250 msec for write.
	 *
	 * Legacy cards running at 375kHz have a worst case of about
	 * 15 seconds.  Running at 25MHz (the standard speed) it is
	 * about 100msec for read, and about 3.2 sec for write.
	 * Typical values are 1/100th that, or about 1msec for read,
	 * and 32 msec for write.
	 *
	 * No transaction at full speed should ever take more than 4
	 * seconds.  (Some slow legacy cards might have trouble, but
	 * we'll worry about them if they ever are seen.  Nobody wants
	 * to wait 4 seconds to access a single block anyway!)
	 *
	 * To get to 4 seconds, we continuously double usec until we
	 * get to the maximum value, or a timeout greater than 4
	 * seconds.
	 *
	 * Note that for high-speed timeout clocks, we might not be
	 * able to get to the full 4 seconds.  E.g. with a 48MHz
	 * timeout clock, we can only get to about 2.8 seconds.  Its
	 * possible that there could be some slow MMC cards that will
	 * timeout at this clock rate, but it seems unlikely.  (The
	 * device would have to be pressing the very worst times,
	 * against the 100-fold "permissive" window allowed, and
	 * running at only 12.5MHz.)
	 *
	 * XXX: this could easily be a tunable.  Someone dealing with only
	 * reasonable cards could set this to just 1 second.
	 */
	for (ss->ss_tmoutclk = 0; ss->ss_tmoutclk < 14; ss->ss_tmoutclk++) {
		if ((ss->ss_tmusecs * (1 << ss->ss_tmoutclk)) >= 4000000) {
			break;
		}
	}

	/*
	 * Enable slot interrupts.
	 */
	sdhost_enable_interrupts(ss);

	return (DDI_SUCCESS);
}

void
sdhost_uninit_slot(sdhost_t *shp, int num)
{
	sdslot_t	*ss;

	ss = &shp->sh_slots[num];
	if (ss->ss_acch == NULL)
		return;

	(void) sdhost_soft_reset(ss, SOFT_RESET_ALL);

	ddi_regs_map_free(&ss->ss_acch);
	mutex_destroy(&ss->ss_lock);
}

void
sdhost_get_response(sdslot_t *ss, sda_cmd_t *cmdp)
{
	uint32_t	*resp = cmdp->sc_response;
	int		i;

	resp[0] = GET32(ss, REG_RESP1);
	resp[1] = GET32(ss, REG_RESP2);
	resp[2] = GET32(ss, REG_RESP3);
	resp[3] = GET32(ss, REG_RESP4);

	/*
	 * Response 2 is goofy because the host drops the low
	 * order CRC bits.  This makes it a bit awkward, so we
	 * have to shift the bits to make it work out right.
	 *
	 * Note that the framework expects the 32 bit
	 * words to be ordered in LE fashion.  (The
	 * bits within the words are in native order).
	 */
	if (cmdp->sc_rtype == R2) {
		for (i = 3; i > 0; i--) {
			resp[i] <<= 8;
			resp[i] |= (resp[i - 1] >> 24);
		}
		resp[0] <<= 8;
	}
}

sda_err_t
sdhost_wait_cmd(sdslot_t *ss, sda_cmd_t *cmdp)
{
	int		i;
	uint16_t	errs;
	sda_err_t	rv;

	/*
	 * Worst case for 100kHz timeout is 2msec (200 clocks), we add
	 * a tiny bit for safety.  (Generally timeout will be far, far
	 * less than that.)
	 *
	 * Note that at more typical 12MHz (and normally it will be
	 * even faster than that!) that the device timeout is only
	 * 16.67 usec.  We could be smarter and reduce the delay time,
	 * but that would require putting more intelligence into the
	 * code, and we don't expect CMD timeout to normally occur
	 * except during initialization.  (At which time we need the
	 * full timeout anyway.)
	 *
	 * Checking the ERR_STAT will normally cause the timeout to
	 * terminate to finish early if the device is healthy, anyway.
	 */

	for (i = 3000; i > 0; i -= 5) {
		if (GET16(ss, REG_INT_STAT) & INT_CMD) {

			PUT16(ss, REG_INT_STAT, INT_CMD);

			/* command completed */
			sdhost_get_response(ss, cmdp);
			return (SDA_EOK);
		}

		if ((errs = (GET16(ss, REG_ERR_STAT) & ERR_CMD)) != 0) {
			PUT16(ss, REG_ERR_STAT, errs);

			/* command timeout isn't a host failure */
			if ((errs & ERR_CMD_TMO) == ERR_CMD_TMO) {
				rv = SDA_ETIME;
			} else if ((errs & ERR_CMD_CRC) == ERR_CMD_CRC) {
				rv = SDA_ECRC7;
			} else {
				rv = SDA_EPROTO;
			}
			goto error;
		}

		drv_usecwait(5);
	}

	rv = SDA_ETIME;

error:
	/*
	 * NB: We need to soft reset the CMD and DAT
	 * lines after a failure of this sort.
	 */
	(void) sdhost_soft_reset(ss, SOFT_RESET_CMD);
	(void) sdhost_soft_reset(ss, SOFT_RESET_DAT);

	return (rv);
}

sda_err_t
sdhost_poll(void *arg)
{
	sdslot_t	*ss = arg;

	(void) sdhost_slot_intr(ss);
	return (SDA_EOK);
}

sda_err_t
sdhost_cmd(void *arg, sda_cmd_t *cmdp)
{
	sdslot_t	*ss = arg;
	uint16_t	command;
	uint16_t	mode;
	sda_err_t	rv;

	/*
	 * Command register:
	 * bit 13-8	= command index
	 * bit 7-6	= command type (always zero for us!)
	 * bit 5	= data present select
	 * bit 4	= command index check (always on!)
	 * bit 3	= command CRC check enable
	 * bit 2	= reserved
	 * bit 1-0	= response type
	 */

	command = ((uint16_t)cmdp->sc_index << 8);
	command |= COMMAND_TYPE_NORM |
	    COMMAND_INDEX_CHECK_EN | COMMAND_CRC_CHECK_EN;

	switch (cmdp->sc_rtype) {
	case R0:
		command |= COMMAND_RESP_NONE;
		break;
	case R1:
	case R5:
	case R6:
	case R7:
		command |= COMMAND_RESP_48;
		break;
	case R1b:
	case R5b:
		command |= COMMAND_RESP_48_BUSY;
		break;
	case R2:
		command |= COMMAND_RESP_136;
		command &= ~(COMMAND_INDEX_CHECK_EN | COMMAND_CRC_CHECK_EN);
		break;
	case R3:
	case R4:
		command |= COMMAND_RESP_48;
		command &= ~COMMAND_CRC_CHECK_EN;
		command &= ~COMMAND_INDEX_CHECK_EN;
		break;
	default:
		return (SDA_EINVAL);
	}

	mutex_enter(&ss->ss_lock);
	if (ss->ss_suspended) {
		mutex_exit(&ss->ss_lock);
		return (SDA_ESUSPENDED);
	}

	if (cmdp->sc_nblks != 0) {
		uint16_t	blksz;
		uint16_t	nblks;

		blksz = cmdp->sc_blksz;
		nblks = cmdp->sc_nblks;

		/*
		 * Ensure that we have good data.
		 */
		if ((blksz < 1) || (blksz > 2048)) {
			mutex_exit(&ss->ss_lock);
			return (SDA_EINVAL);
		}
		command |= COMMAND_DATA_PRESENT;

		ss->ss_blksz = blksz;

		/*
		 * Only SDMA for now.  We can investigate ADMA2 later.
		 * (Right now we don't have ADMA2 capable hardware.)
		 */
		if (((ss->ss_capab & CAPAB_SDMA) != 0) &&
		    (cmdp->sc_ndmac != 0)) {
			ddi_dma_cookie_t	*dmacs = cmdp->sc_dmacs;

			ASSERT(dmacs != NULL);

			ss->ss_kvaddr = NULL;
			ss->ss_resid = 0;
			ss->ss_dmacs = dmacs;
			ss->ss_ndmac = cmdp->sc_ndmac - 1;

			PUT32(ss, REG_SDMA_ADDR, dmacs->dmac_address);
			mode = XFR_MODE_DMA_EN;
			PUT16(ss, REG_BLKSZ, blksz);

		} else {
			ss->ss_kvaddr = (void *)cmdp->sc_kvaddr;
			ss->ss_resid = nblks;
			ss->ss_dmacs = NULL;
			ss->ss_ndmac = 0;
			mode = 0;
			PUT16(ss, REG_BLKSZ, blksz);
		}

		if (nblks > 1) {
			mode |= XFR_MODE_MULTI | XFR_MODE_COUNT;
			if (cmdp->sc_flags & SDA_CMDF_AUTO_CMD12)
				mode |= XFR_MODE_AUTO_CMD12;
		}
		if ((cmdp->sc_flags & SDA_CMDF_READ) != 0) {
			mode |= XFR_MODE_READ;
		}

		ss->ss_mode = mode;

		PUT8(ss, REG_TIMEOUT_CONTROL, ss->ss_tmoutclk);
		PUT16(ss, REG_BLOCK_COUNT, nblks);
		PUT16(ss, REG_XFR_MODE, mode);
	}

	PUT32(ss, REG_ARGUMENT, cmdp->sc_argument);
	PUT16(ss, REG_COMMAND, command);

	rv = sdhost_wait_cmd(ss, cmdp);

	mutex_exit(&ss->ss_lock);

	return (rv);
}

sda_err_t
sdhost_getprop(void *arg, sda_prop_t prop, uint32_t *val)
{
	sdslot_t	*ss = arg;
	sda_err_t	rv = 0;

	mutex_enter(&ss->ss_lock);

	if (ss->ss_suspended) {
		mutex_exit(&ss->ss_lock);
		return (SDA_ESUSPENDED);
	}
	switch (prop) {
	case SDA_PROP_INSERTED:
		if (CHECK_STATE(ss, CARD_INSERTED)) {
			*val = B_TRUE;
		} else {
			*val = B_FALSE;
		}
		break;

	case SDA_PROP_WPROTECT:
		if (CHECK_STATE(ss, WRITE_ENABLE)) {
			*val = B_FALSE;
		} else {
			*val = B_TRUE;
		}
		break;

	case SDA_PROP_OCR:
		*val = ss->ss_ocr;
		break;

	case SDA_PROP_CLOCK:
		*val = ss->ss_cardclk;
		break;

	case SDA_PROP_CAP_HISPEED:
		if ((ss->ss_capab & CAPAB_HIGH_SPEED) != 0) {
			*val = B_TRUE;
		} else {
			*val = B_FALSE;
		}
		break;

	case SDA_PROP_CAP_4BITS:
		*val = B_TRUE;
		break;

	case SDA_PROP_CAP_NOPIO:
		if ((ss->ss_capab & CAPAB_SDMA) != 0) {
			*val = B_TRUE;
		} else {
			*val = B_FALSE;
		}
		break;

	case SDA_PROP_CAP_INTR:
	case SDA_PROP_CAP_8BITS:
		*val = B_FALSE;
		break;

	default:
		rv = SDA_ENOTSUP;
		break;
	}
	mutex_exit(&ss->ss_lock);

	return (rv);
}

sda_err_t
sdhost_setprop(void *arg, sda_prop_t prop, uint32_t val)
{
	sdslot_t	*ss = arg;
	sda_err_t	rv = SDA_EOK;

	mutex_enter(&ss->ss_lock);

	if (ss->ss_suspended) {
		mutex_exit(&ss->ss_lock);
		return (SDA_ESUSPENDED);
	}

	switch (prop) {
	case SDA_PROP_LED:
		if (val) {
			SET8(ss, REG_HOST_CONTROL, HOST_CONTROL_LED_ON);
		} else {
			CLR8(ss, REG_HOST_CONTROL, HOST_CONTROL_LED_ON);
		}
		break;

	case SDA_PROP_CLOCK:
		rv = sdhost_set_clock(arg, val);
		break;

	case SDA_PROP_BUSWIDTH:
		switch (val) {
		case 1:
			CLR8(ss, REG_HOST_CONTROL, HOST_CONTROL_DATA_WIDTH);
			break;
		case 4:
			SET8(ss, REG_HOST_CONTROL, HOST_CONTROL_DATA_WIDTH);
			break;
		default:
			rv = SDA_EINVAL;
		}
		break;

	case SDA_PROP_OCR:
		val &= ss->ss_ocr;

		if (val & OCR_17_18V) {
			PUT8(ss, REG_POWER_CONTROL, POWER_CONTROL_18V);
			PUT8(ss, REG_POWER_CONTROL, POWER_CONTROL_18V |
			    POWER_CONTROL_BUS_POWER);
		} else if (val & OCR_29_30V) {
			PUT8(ss, REG_POWER_CONTROL, POWER_CONTROL_30V);
			PUT8(ss, REG_POWER_CONTROL, POWER_CONTROL_30V |
			    POWER_CONTROL_BUS_POWER);
		} else if (val & OCR_32_33V) {
			PUT8(ss, REG_POWER_CONTROL, POWER_CONTROL_33V);
			PUT8(ss, REG_POWER_CONTROL, POWER_CONTROL_33V |
			    POWER_CONTROL_BUS_POWER);
		} else if (val == 0) {
			/* turn off power */
			PUT8(ss, REG_POWER_CONTROL, 0);
		} else {
			rv = SDA_EINVAL;
		}
		break;

	case SDA_PROP_HISPEED:
		if (val) {
			SET8(ss, REG_HOST_CONTROL, HOST_CONTROL_HIGH_SPEED_EN);
		} else {
			CLR8(ss, REG_HOST_CONTROL, HOST_CONTROL_HIGH_SPEED_EN);
		}
		/* give clocks time to settle */
		drv_usecwait(10);
		break;

	default:
		rv = SDA_ENOTSUP;
		break;
	}

	/*
	 * Apparently some controllers (ENE) have issues with changing
	 * certain parameters (bus width seems to be one), requiring
	 * a reset of the DAT and CMD lines.
	 */
	if (rv == SDA_EOK) {
		(void) sdhost_soft_reset(ss, SOFT_RESET_CMD);
		(void) sdhost_soft_reset(ss, SOFT_RESET_DAT);
	}
	mutex_exit(&ss->ss_lock);
	return (rv);
}

sda_err_t
sdhost_reset(void *arg)
{
	sdslot_t	*ss = arg;

	mutex_enter(&ss->ss_lock);
	if (!ss->ss_suspended) {
		if (sdhost_soft_reset(ss, SOFT_RESET_ALL) != SDA_EOK) {
			mutex_exit(&ss->ss_lock);
			return (SDA_ETIME);
		}
		sdhost_enable_interrupts(ss);
	}
	mutex_exit(&ss->ss_lock);
	return (SDA_EOK);
}

sda_err_t
sdhost_halt(void *arg)
{
	sdslot_t	*ss = arg;

	mutex_enter(&ss->ss_lock);
	if (!ss->ss_suspended) {
		sdhost_disable_interrupts(ss);
		/* this has the side effect of removing power from the card */
		if (sdhost_soft_reset(ss, SOFT_RESET_ALL) != SDA_EOK) {
			mutex_exit(&ss->ss_lock);
			return (SDA_ETIME);
		}
	}
	mutex_exit(&ss->ss_lock);
	return (SDA_EOK);
}
