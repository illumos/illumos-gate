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
 *
 * IEEE 1284 Parallel Port Device Driver
 *
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/debug.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/modctl.h>		/* for modldrv */
#include <sys/stat.h>		/* ddi_create_minor_node S_IFCHR */
#include <sys/open.h>
#include <sys/ddi_impldefs.h>
#include <sys/kstat.h>

#include <sys/prnio.h>
#include <sys/ecppreg.h>	/* hw description */
#include <sys/ecppio.h>		/* ioctl description */
#include <sys/ecppvar.h>	/* driver description */
#include <sys/dma_engine.h>
#include <sys/dma_i8237A.h>

/*
 * Background
 * ==========
 * IEEE 1284-1994 standard defines "a signalling method for asynchronous,
 * fully interlocked, bidirectional parallel communications between hosts
 * and printers or other peripherals." (1.1) The standard defines 5 modes
 * of operation - Compatibility, Nibble, Byte, ECP and EPP - which differ
 * in direction, bandwidth, pins assignment, DMA capability, etc.
 *
 * Negotiation is a mechanism for moving between modes. Compatibility mode
 * is a default mode, from which negotiations to other modes occur and
 * to which both host and peripheral break in case of interface errors.
 * Compatibility mode provides a unidirectional (forward) channel for
 * communicating with old pre-1284 peripherals.
 *
 * Each mode has a number of phases. [Mode, phase] pair represents the
 * interface state. Host initiates all transfers, though peripheral can
 * request backchannel transfer by asserting nErr pin.
 *
 * Ecpp driver implements an IEEE 1284-compliant host using a combination
 * of hardware and software. Hardware part is represented by a controller,
 * which is a part of the SuperIO chip. Ecpp supports the following SuperIOs:
 * PC82332/PC82336 (U5/U10/U60), PC97317 (U100), M1553 (Grover).
 * Struct ecpp_hw describes each SuperIO and is determined in ecpp_attach().
 *
 * Negotiation is performed in software. Transfer may be performed either
 * in software by driving output pins for each byte (PIO method), or with
 * hardware assistance - SuperIO has a 16-byte FIFO, which is filled by
 * the driver (normally using DMA), while the chip performs the actual xfer.
 * PIO is used for Nibble and Compat, DMA is used for ECP and Compat modes.
 *
 * Driver currently supports the following modes:
 *
 * - Compatibility mode: byte-wide forward channel ~50KB/sec;
 *   pp->io_mode defines PIO or DMA method of transfer;
 * - Nibble mode: nibble-wide (4-bit) reverse channel ~30KB/sec;
 * - ECP mode: byte-wide bidirectional channel (~1MB/sec);
 *
 * Theory of operation
 * ===================
 * The manner in which ecpp drives 1284 interface is that of a state machine.
 * State is a combination of 1284 mode {ECPP_*_MODE}, 1284 phase {ECPP_PHASE_*}
 * and transfer method {PIO, DMA}. State is a function of application actions
 * {write(2), ioctl(2)} and peripheral reaction.
 *
 * 1284 interface state is described by the following variables:
 *   pp->current_mode  -- 1284 mode used for forward transfers;
 *   pp->backchannel   -- 1284 mode used for backward transfers;
 *   pp->curent_phase  -- 1284 phase;
 *
 * Bidirectional operation in Compatibility mode is provided by a combination:
 * pp->current_mode == ECPP_COMPAT_MODE && pp->backchannel == ECPP_NIBBLE_MODE
 * ECPP_CENTRONICS means no backchannel
 *
 * Driver internal state is defined by pp->e_busy as follows:
 *   ECPP_IDLE	-- idle, no active transfers;
 *   ECPP_BUSY	-- transfer is in progress;
 *   ECPP_ERR	-- have data to transfer, but peripheral can`t receive data;
 *   ECPP_FLUSH	-- flushing the queues;
 *
 * When opened, driver is in ECPP_IDLE state, current mode is ECPP_CENTRONICS
 * Default negotiation tries to negotiate to the best mode supported by printer,
 * sets pp->current_mode and pp->backchannel accordingly.
 *
 * When output data arrives in M_DATA mblks ecpp_wput() puts them on the queue
 * to let ecpp_wsrv() concatenate small blocks into one big transfer
 * by copying them into pp->ioblock. If first the mblk data is bigger than
 * pp->ioblock, then it is used instead of i/o block (pointed by pp->msg)
 *
 * Before starting the transfer the driver will check if peripheral is ready
 * by calling ecpp_check_status() and if it is not, driver goes ECPP_ERR state
 * and schedules ecpp_wsrv_timer() which would qenable() the wq, effectively
 * rechecking the peripheral readiness and restarting itself until it is ready.
 * The transfer is then started by calling ecpp_start(), driver goes ECPP_BUSY
 *
 * While transfer is in progress all arriving messages will be queued up.
 * Transfer can end up in either of two ways:
 * - interrupt occurs, ecpp_isr() checks if all the data was transferred, if so
 *   cleanup and go ECPP_IDLE, otherwise putback untransferred and qenable();
 * - ecpp_xfer_timeout() cancels the transfer and puts back untransferred data;
 *
 * PIO transfer method is very CPU intensive: for each sent byte the peripheral
 * state is checked, then the byte is transfered and driver waits for an nAck
 * interrupt; ecpp_isr() will then look if there is more data and if so
 * triggers the soft interrupt, which transfers the next byte. PIO method
 * is needed only for legacy printers which are sensitive to strobe problem
 * (Bugid 4192788).
 *
 * ecpp_wsrv() is responsible for both starting transfers (ecpp_start()) and
 * going idle (ecpp_idle_phase()). Many routines qenable() the write queue,
 * meaning "check if there are pending requests, process them and go idle".
 *
 * In it`s idle state the driver will always try to listen to the backchannel
 * (as advised by 1284).
 *
 * The mechanism for handling backchannel requests is as follows:
 * - when the peripheral has data to send it asserts nErr pin
 *   (and also nAck in Nibble Mode) which results in an interrupt on the host;
 * - ISR creates M_CTL message containing an ECPP_BACKCHANNEL byte and
 *   puts it back on the write queue;
 * - ecpp_wsrv() gets M_CTL and calls ecpp_peripheral2host(), which kicks off
 *   the transfer;
 *
 * This way Nibble and ECP mode backchannel are implemented.
 * If the read queue gets full, backchannel request is rejected.
 * As the application reads data and queue size falls below the low watermark,
 * ecpp_rsrv() gets called and enables the backchannel again.
 *
 * Future enhancements
 * ===================
 *
 * Support new modes: Byte and EPP.
 */

#ifndef ECPP_DEBUG
#define	ECPP_DEBUG 0
#endif	/* ECPP_DEBUG */
int ecpp_debug = ECPP_DEBUG;

int noecp = 0;	/* flag not to use ECP mode */

/* driver entry point fn definitions */
static int	ecpp_open(queue_t *, dev_t *, int, int, cred_t *);
static int	ecpp_close(queue_t *, int, cred_t *);
static uint_t	ecpp_isr(caddr_t);
static uint_t	ecpp_softintr(caddr_t);

/* configuration entry point fn definitions */
static int	ecpp_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	ecpp_attach(dev_info_t *, ddi_attach_cmd_t);
static int	ecpp_detach(dev_info_t *, ddi_detach_cmd_t);
static struct ecpp_hw_bind *ecpp_determine_sio_type(struct ecppunit *);

/* isr support routines */
static uint_t	ecpp_nErr_ihdlr(struct ecppunit *);
static uint_t	ecpp_pio_ihdlr(struct ecppunit *);
static uint_t	ecpp_dma_ihdlr(struct ecppunit *);
static uint_t	ecpp_M1553_intr(struct ecppunit *);

/* configuration support routines */
static void	ecpp_get_props(struct ecppunit *);

/* Streams Routines */
static int	ecpp_wput(queue_t *, mblk_t *);
static int	ecpp_wsrv(queue_t *);
static int	ecpp_rsrv(queue_t *);
static void	ecpp_flush(struct ecppunit *, int);
static void	ecpp_start(struct ecppunit *, caddr_t, size_t);

/* ioctl handling */
static void	ecpp_putioc(queue_t *, mblk_t *);
static void	ecpp_srvioc(queue_t *, mblk_t *);
static void	ecpp_wput_iocdata_devid(queue_t *, mblk_t *, uintptr_t);
static void	ecpp_putioc_copyout(queue_t *, mblk_t *, void *, int);
static void	ecpp_putioc_stateful_copyin(queue_t *, mblk_t *, size_t);
static void	ecpp_srvioc_devid(queue_t *, mblk_t *,
				struct ecpp_device_id *, int *);
static void	ecpp_srvioc_prnif(queue_t *, mblk_t *);
static void	ecpp_ack_ioctl(queue_t *, mblk_t *);
static void	ecpp_nack_ioctl(queue_t *, mblk_t *, int);

/* kstat routines */
static void	ecpp_kstat_init(struct ecppunit *);
static int	ecpp_kstat_update(kstat_t *, int);
static int	ecpp_kstatintr_update(kstat_t *, int);

/* dma routines */
static void	ecpp_putback_untransfered(struct ecppunit *, void *, uint_t);
static uint8_t	ecpp_setup_dma_resources(struct ecppunit *, caddr_t, size_t);
static uint8_t	ecpp_init_dma_xfer(struct ecppunit *, caddr_t, size_t);

/* pio routines */
static void	ecpp_pio_writeb(struct ecppunit *);
static void	ecpp_xfer_cleanup(struct ecppunit *);
static uint8_t	ecpp_prep_pio_xfer(struct ecppunit *, caddr_t, size_t);

/* misc */
static uchar_t	ecpp_reset_port_regs(struct ecppunit *);
static void	ecpp_xfer_timeout(void *);
static void	ecpp_fifo_timer(void *);
static void	ecpp_wsrv_timer(void *);
static uchar_t	dcr_write(struct ecppunit *, uint8_t);
static uchar_t	ecr_write(struct ecppunit *, uint8_t);
static uchar_t	ecpp_check_status(struct ecppunit *);
static int	ecpp_backchan_req(struct ecppunit *);
static void	ecpp_untimeout_unblock(struct ecppunit *, timeout_id_t *);
static uint_t	ecpp_get_prn_ifcap(struct ecppunit *);

/* stubs */
static void	empty_config_mode(struct ecppunit *);
static void	empty_mask_intr(struct ecppunit *);

/* PC87332 support */
static int	pc87332_map_regs(struct ecppunit *);
static void	pc87332_unmap_regs(struct ecppunit *);
static int	pc87332_config_chip(struct ecppunit *);
static void	pc87332_config_mode(struct ecppunit *);
static uint8_t	pc87332_read_config_reg(struct ecppunit *, uint8_t);
static void	pc87332_write_config_reg(struct ecppunit *, uint8_t, uint8_t);
static void	cheerio_mask_intr(struct ecppunit *);
static void	cheerio_unmask_intr(struct ecppunit *);
static int	cheerio_dma_start(struct ecppunit *);
static int	cheerio_dma_stop(struct ecppunit *, size_t *);
static size_t	cheerio_getcnt(struct ecppunit *);
static void	cheerio_reset_dcsr(struct ecppunit *);

/* PC97317 support */
static int	pc97317_map_regs(struct ecppunit *);
static void	pc97317_unmap_regs(struct ecppunit *);
static int	pc97317_config_chip(struct ecppunit *);
static void	pc97317_config_mode(struct ecppunit *);

/* M1553 Southbridge support */
static int	m1553_map_regs(struct ecppunit *pp);
static void	m1553_unmap_regs(struct ecppunit *pp);
static int	m1553_config_chip(struct ecppunit *);
static uint8_t	m1553_read_config_reg(struct ecppunit *, uint8_t);
static void	m1553_write_config_reg(struct ecppunit *, uint8_t, uint8_t);

/* M1553 Southbridge DMAC 8237 support routines */
static int	dma8237_dma_start(struct ecppunit *);
static int	dma8237_dma_stop(struct ecppunit *, size_t *);
static size_t	dma8237_getcnt(struct ecppunit *);
static void	dma8237_write_addr(struct ecppunit *, uint32_t);
static void	dma8237_write_count(struct ecppunit *, uint32_t);
static uint32_t	dma8237_read_count(struct ecppunit *);
static void	dma8237_write(struct ecppunit *, int, uint8_t);
static uint8_t	dma8237_read(struct ecppunit *, int);
#ifdef INCLUDE_DMA8237_READ_ADDR
static uint32_t	dma8237_read_addr(struct ecppunit *);
#endif

/* i86 PC support rountines */

#if defined(__x86)
static int	x86_dma_start(struct ecppunit *);
static int	x86_dma_stop(struct ecppunit *, size_t *);
static int	x86_map_regs(struct ecppunit *);
static void	x86_unmap_regs(struct ecppunit *);
static int	x86_config_chip(struct ecppunit *);
static size_t	x86_getcnt(struct ecppunit *);
#endif

/* IEEE 1284 phase transitions */
static void	ecpp_1284_init_interface(struct ecppunit *);
static int	ecpp_1284_termination(struct ecppunit *);
static uchar_t	ecpp_idle_phase(struct ecppunit *);
static int	ecp_forward2reverse(struct ecppunit *);
static int	ecp_reverse2forward(struct ecppunit *);
static int	read_nibble_backchan(struct ecppunit *);

/* reverse transfers */
static uint_t	ecpp_peripheral2host(struct ecppunit *);
static uchar_t	ecp_peripheral2host(struct ecppunit *);
static uchar_t	nibble_peripheral2host(struct ecppunit *pp, uint8_t *);
static int	ecpp_getdevid(struct ecppunit *, uint8_t *, int *, int);
static void	ecpp_ecp_read_timeout(void *);
static void	ecpp_ecp_read_completion(struct ecppunit *);

/* IEEE 1284 mode transitions */
static void	ecpp_default_negotiation(struct ecppunit *);
static int	ecpp_mode_negotiation(struct ecppunit *, uchar_t);
static int	ecpp_1284_negotiation(struct ecppunit *, uint8_t, uint8_t *);
static int	ecp_negotiation(struct ecppunit *);
static int	nibble_negotiation(struct ecppunit *);
static int	devidnib_negotiation(struct ecppunit *);

/* IEEE 1284 utility routines */
static int	wait_dsr(struct ecppunit *, uint8_t, uint8_t, int);

/* debugging functions */
static void	ecpp_error(dev_info_t *, char *, ...);
static uchar_t	ecpp_get_error_status(uchar_t);

/*
 * Chip-dependent structures
 */
static ddi_dma_attr_t cheerio_dma_attr = {
	DMA_ATTR_VERSION,	/* version */
	0x00000000ull,		/* dlim_addr_lo */
	0xfffffffeull,		/* dlim_addr_hi */
	0xffffff,		/* DMA counter register */
	1,			/* DMA address alignment */
	0x74,			/* burst sizes */
	0x0001,			/* min effective DMA size */
	0xffff,			/* maximum transfer size */
	0xffff,			/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA flags */
};

static struct ecpp_hw pc87332 = {
	pc87332_map_regs,
	pc87332_unmap_regs,
	pc87332_config_chip,
	pc87332_config_mode,
	cheerio_mask_intr,
	cheerio_unmask_intr,
	cheerio_dma_start,
	cheerio_dma_stop,
	cheerio_getcnt,
	&cheerio_dma_attr
};

static struct ecpp_hw pc97317 = {
	pc97317_map_regs,
	pc97317_unmap_regs,
	pc97317_config_chip,
	pc97317_config_mode,
	cheerio_mask_intr,
	cheerio_unmask_intr,
	cheerio_dma_start,
	cheerio_dma_stop,
	cheerio_getcnt,
	&cheerio_dma_attr
};

static ddi_dma_attr_t i8237_dma_attr = {
	DMA_ATTR_VERSION,	/* version */
	0x00000000ull,		/* dlim_addr_lo */
	0xfffffffeull,		/* dlim_addr_hi */
	0xffff,			/* DMA counter register */
	1,			/* DMA address alignment */
	0x01,			/* burst sizes */
	0x0001,			/* min effective DMA size */
	0xffff,			/* maximum transfer size */
	0x7fff,			/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA flags */
};

static struct ecpp_hw m1553 = {
	m1553_map_regs,
	m1553_unmap_regs,
	m1553_config_chip,
	empty_config_mode,	/* no config_mode */
	empty_mask_intr,	/* no mask_intr */
	empty_mask_intr,	/* no unmask_intr */
	dma8237_dma_start,
	dma8237_dma_stop,
	dma8237_getcnt,
	&i8237_dma_attr
};

#if defined(__x86)
static ddi_dma_attr_t sb_dma_attr = {
	DMA_ATTR_VERSION,	/* version */
	0x00000000ull,		/* dlim_addr_lo */
	0xffffff,		/* dlim_addr_hi */
	0xffff,			/* DMA counter register */
	1,			/* DMA address alignment */
	0x01,			/* burst sizes */
	0x0001,			/* min effective DMA size */
	0xffffffff,		/* maximum transfer size */
	0xffff,			/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA flags */
};

static struct ecpp_hw x86 = {
	x86_map_regs,
	x86_unmap_regs,
	x86_config_chip,
	empty_config_mode,	/* no config_mode */
	empty_mask_intr,	/* no mask_intr */
	empty_mask_intr,	/* no unmask_intr */
	x86_dma_start,
	x86_dma_stop,
	x86_getcnt,
	&sb_dma_attr
};
#endif

/*
 * list of supported devices
 */
struct ecpp_hw_bind ecpp_hw_bind[] = {
	{ "ns87317-ecpp",	&pc97317,	"PC97317" },
	{ "pnpALI,1533,3",	&m1553,		"M1553" },
	{ "ecpp",		&pc87332,	"PC87332" },
#if defined(__x86)
	{ "lp",			&x86,		"i86pc"},
#endif
};

static ddi_device_acc_attr_t acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static struct ecpp_transfer_parms default_xfer_parms = {
	FWD_TIMEOUT_DEFAULT,	/* write timeout in seconds */
	ECPP_CENTRONICS		/* supported mode */
};

/* prnio interface info string */
static const char prn_ifinfo[] = PRN_PARALLEL;

/* prnio timeouts */
static const struct prn_timeouts prn_timeouts_default = {
	FWD_TIMEOUT_DEFAULT,	/* forward timeout */
	REV_TIMEOUT_DEFAULT	/* reverse timeout */
};

static int ecpp_isr_max_delay = ECPP_ISR_MAX_DELAY;
static int ecpp_def_timeout = 90;  /* left in for 2.7 compatibility */

static void    *ecppsoft_statep;

/*
 * STREAMS framework manages locks for these structures
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", datab))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", msgb))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", queue))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", copyreq))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", stroptions))

struct module_info ecppinfo = {
	/* id, name, min pkt siz, max pkt siz, hi water, low water */
	42, "ecpp", 0, IO_BLOCK_SZ, ECPPHIWAT, ECPPLOWAT
};

static struct qinit ecpp_rinit = {
	putq, ecpp_rsrv, ecpp_open, ecpp_close, NULL, &ecppinfo, NULL
};

static struct qinit ecpp_wint = {
	ecpp_wput, ecpp_wsrv, ecpp_open, ecpp_close, NULL, &ecppinfo, NULL
};

struct streamtab ecpp_str_info = {
	&ecpp_rinit, &ecpp_wint, NULL, NULL
};

static struct cb_ops ecpp_cb_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&ecpp_str_info,		/* cb_stream */
	(D_NEW | D_MP | D_MTPERQ)	/* cb_flag */
};

/*
 * Declare ops vectors for auto configuration.
 */
struct dev_ops  ecpp_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ecpp_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ecpp_attach,		/* devo_attach */
	ecpp_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ecpp_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv ecppmodldrv = {
	&mod_driverops,		/* type of module - driver */
	"parallel port driver",
	&ecpp_ops,
};

static struct modlinkage ecppmodlinkage = {
	MODREV_1,
	&ecppmodldrv,
	0
};


/*
 *
 * DDI/DKI entry points and supplementary routines
 *
 */


int
_init(void)
{
	int    error;

	if ((error = mod_install(&ecppmodlinkage)) == 0) {
		(void) ddi_soft_state_init(&ecppsoft_statep,
		    sizeof (struct ecppunit), 1);
	}

	return (error);
}

int
_fini(void)
{
	int    error;

	if ((error = mod_remove(&ecppmodlinkage)) == 0) {
		ddi_soft_state_fini(&ecppsoft_statep);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ecppmodlinkage, modinfop));
}

static int
ecpp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	char			name[16];
	struct ecppunit		*pp;
	struct ecpp_hw_bind	*hw_bind;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if (!(pp = ddi_get_soft_state(ecppsoft_statep, instance))) {
			return (DDI_FAILURE);
		}

		mutex_enter(&pp->umutex);

		pp->suspended = FALSE;

		/*
		 * Initialize the chip and restore current mode if needed
		 */
		(void) ECPP_CONFIG_CHIP(pp);
		(void) ecpp_reset_port_regs(pp);

		if (pp->oflag == TRUE) {
			int current_mode = pp->current_mode;

			(void) ecpp_1284_termination(pp);
			(void) ecpp_mode_negotiation(pp, current_mode);
		}

		mutex_exit(&pp->umutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(ecppsoft_statep, instance) != 0) {
		ecpp_error(dip, "ddi_soft_state_zalloc failed\n");
		goto fail;
	}

	pp = ddi_get_soft_state(ecppsoft_statep, instance);

	pp->dip = dip;
	pp->suspended = FALSE;

	/*
	 * Determine SuperIO type and set chip-dependent variables
	 */
	hw_bind = ecpp_determine_sio_type(pp);

	if (hw_bind == NULL) {
		cmn_err(CE_NOTE, "parallel port controller not supported");
		goto fail_sio;
	} else {
		pp->hw = hw_bind->hw;
		ecpp_error(pp->dip, "SuperIO type: %s\n", hw_bind->info);
	}

	/*
	 * Map registers
	 */
	if (ECPP_MAP_REGS(pp) != SUCCESS) {
		goto fail_map;
	}

	if (ddi_dma_alloc_handle(dip, pp->hw->attr, DDI_DMA_DONTWAIT,
	    NULL, &pp->dma_handle) != DDI_SUCCESS) {
		ecpp_error(dip, "ecpp_attach: failed ddi_dma_alloc_handle\n");
		goto fail_dma;
	}

	if (ddi_get_iblock_cookie(dip, 0,
	    &pp->ecpp_trap_cookie) != DDI_SUCCESS) {
		ecpp_error(dip, "ecpp_attach: failed ddi_get_iblock_cookie\n");
		goto fail_ibc;
	}

	mutex_init(&pp->umutex, NULL, MUTEX_DRIVER,
	    (void *)pp->ecpp_trap_cookie);

	cv_init(&pp->pport_cv, NULL, CV_DRIVER, NULL);

	if (ddi_add_intr(dip, 0, &pp->ecpp_trap_cookie, NULL, ecpp_isr,
	    (caddr_t)pp) != DDI_SUCCESS) {
		ecpp_error(dip, "ecpp_attach: failed to add hard intr\n");
		goto fail_intr;
	}

	if (ddi_add_softintr(dip, DDI_SOFTINT_LOW,
	    &pp->softintr_id, 0, 0, ecpp_softintr,
	    (caddr_t)pp) != DDI_SUCCESS) {
		ecpp_error(dip, "ecpp_attach: failed to add soft intr\n");
		goto fail_softintr;
	}

	(void) sprintf(name, "ecpp%d", instance);

	if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    DDI_NT_PRINTER, 0) == DDI_FAILURE) {
		ecpp_error(dip, "ecpp_attach: create_minor_node failed\n");
		goto fail_minor;
	}

	pp->ioblock = (caddr_t)kmem_alloc(IO_BLOCK_SZ, KM_SLEEP);
	if (pp->ioblock == NULL) {
		ecpp_error(dip, "ecpp_attach: kmem_alloc failed\n");
		goto fail_iob;
	} else {
		ecpp_error(pp->dip, "ecpp_attach: ioblock=0x%x\n", pp->ioblock);
	}

	ecpp_get_props(pp);
#if defined(__x86)
	if (pp->hw == &x86 && pp->uh.x86.chn != 0xff) {
		if (ddi_dmae_alloc(dip, pp->uh.x86.chn,
		    DDI_DMA_DONTWAIT, NULL) == DDI_SUCCESS)
			ecpp_error(pp->dip, "dmae_alloc success!\n");
	}
#endif
	if (ECPP_CONFIG_CHIP(pp) == FAILURE) {
		ecpp_error(pp->dip, "config_chip failed.\n");
		goto fail_config;
	}

	ecpp_kstat_init(pp);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail_config:
	ddi_prop_remove_all(dip);
	kmem_free(pp->ioblock, IO_BLOCK_SZ);
fail_iob:
	ddi_remove_minor_node(dip, NULL);
fail_minor:
	ddi_remove_softintr(pp->softintr_id);
fail_softintr:
	ddi_remove_intr(dip, (uint_t)0, pp->ecpp_trap_cookie);
fail_intr:
	mutex_destroy(&pp->umutex);
	cv_destroy(&pp->pport_cv);
fail_ibc:
	ddi_dma_free_handle(&pp->dma_handle);
fail_dma:
	ECPP_UNMAP_REGS(pp);
fail_map:
fail_sio:
	ddi_soft_state_free(ecppsoft_statep, instance);
fail:
	ecpp_error(dip, "ecpp_attach: failed.\n");

	return (DDI_FAILURE);
}

static int
ecpp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	struct ecppunit *pp;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		if (!(pp = ddi_get_soft_state(ecppsoft_statep, instance))) {
			return (DDI_FAILURE);
		}

		mutex_enter(&pp->umutex);
		ASSERT(pp->suspended == FALSE);

		pp->suspended = TRUE;	/* prevent new transfers */

		/*
		 * Wait if there's any activity on the port
		 */
		if ((pp->e_busy == ECPP_BUSY) || (pp->e_busy == ECPP_FLUSH)) {
			(void) cv_reltimedwait(&pp->pport_cv, &pp->umutex,
			    SUSPEND_TOUT * drv_usectohz(1000000),
			    TR_CLOCK_TICK);
			if ((pp->e_busy == ECPP_BUSY) ||
			    (pp->e_busy == ECPP_FLUSH)) {
				pp->suspended = FALSE;
				mutex_exit(&pp->umutex);
				ecpp_error(pp->dip,
				    "ecpp_detach: suspend timeout\n");
				return (DDI_FAILURE);
			}
		}

		mutex_exit(&pp->umutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	pp = ddi_get_soft_state(ecppsoft_statep, instance);
#if defined(__x86)
	if (pp->hw == &x86 && pp->uh.x86.chn != 0xff)
		(void) ddi_dmae_release(pp->dip, pp->uh.x86.chn);
#endif
	if (pp->dma_handle != NULL)
		ddi_dma_free_handle(&pp->dma_handle);

	ddi_remove_minor_node(dip, NULL);

	ddi_remove_softintr(pp->softintr_id);

	ddi_remove_intr(dip, (uint_t)0, pp->ecpp_trap_cookie);

	if (pp->ksp) {
		kstat_delete(pp->ksp);
	}
	if (pp->intrstats) {
		kstat_delete(pp->intrstats);
	}

	cv_destroy(&pp->pport_cv);

	mutex_destroy(&pp->umutex);

	ECPP_UNMAP_REGS(pp);

	kmem_free(pp->ioblock, IO_BLOCK_SZ);

	ddi_prop_remove_all(dip);

	ddi_soft_state_free(ecppsoft_statep, instance);

	return (DDI_SUCCESS);

}

/*
 * ecpp_get_props() reads ecpp.conf for user defineable tuneables.
 * If the file or a particular variable is not there, a default value
 * is assigned.
 */

static void
ecpp_get_props(struct ecppunit *pp)
{
	char	*prop;
#if defined(__x86)
	int	len;
	int	value;
#endif
	/*
	 * If fast_centronics is TRUE, non-compliant IEEE 1284
	 * peripherals ( Centronics peripherals) will operate in DMA mode.
	 * Transfers betwee main memory and the device will be via DMA;
	 * peripheral handshaking will be conducted by superio logic.
	 * If ecpp can not read the variable correctly fast_centronics will
	 * be set to FALSE.  In this case, transfers and handshaking
	 * will be conducted by PIO for Centronics devices.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pp->dip, 0,
	    "fast-centronics", &prop) == DDI_PROP_SUCCESS) {
		pp->fast_centronics =
		    (strcmp(prop, "true") == 0) ? TRUE : FALSE;
		ddi_prop_free(prop);
	} else {
		pp->fast_centronics = FALSE;
	}

	/*
	 * If fast-1284-compatible is set to TRUE, when ecpp communicates
	 * with IEEE 1284 compliant peripherals, data transfers between
	 * main memory and the parallel port will be conducted by DMA.
	 * Handshaking between the port and peripheral will be conducted
	 * by superio logic.  This is the default characteristic.  If
	 * fast-1284-compatible is set to FALSE, transfers and handshaking
	 * will be conducted by PIO.
	 */

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pp->dip, 0,
	    "fast-1284-compatible", &prop) == DDI_PROP_SUCCESS) {
		pp->fast_compat = (strcmp(prop, "true") == 0) ? TRUE : FALSE;
		ddi_prop_free(prop);
	} else {
		pp->fast_compat = TRUE;
	}

	/*
	 * Some centronics peripherals require the nInit signal to be
	 * toggled to reset the device.  If centronics_init_seq is set
	 * to TRUE, ecpp will toggle the nInit signal upon every ecpp_open().
	 * Applications have the opportunity to toggle the nInit signal
	 * with ioctl(2) calls as well.  The default is to set it to FALSE.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pp->dip, 0,
	    "centronics-init-seq", &prop) == DDI_PROP_SUCCESS) {
		pp->init_seq = (strcmp(prop, "true") == 0) ? TRUE : FALSE;
		ddi_prop_free(prop);
	} else {
		pp->init_seq = FALSE;
	}

	/*
	 * If one of the centronics status signals are in an erroneous
	 * state, ecpp_wsrv() will be reinvoked centronics-retry ms to
	 * check if the status is ok to transfer.  If the property is not
	 * found, wsrv_retry will be set to CENTRONICS_RETRY ms.
	 */
	pp->wsrv_retry = ddi_prop_get_int(DDI_DEV_T_ANY, pp->dip, 0,
	    "centronics-retry", CENTRONICS_RETRY);

	/*
	 * In PIO mode, ecpp_isr() will loop for wait for the busy signal
	 * to be deasserted before transferring the next byte. wait_for_busy
	 * is specificied in microseconds.  If the property is not found
	 * ecpp_isr() will wait for a maximum of WAIT_FOR_BUSY us.
	 */
	pp->wait_for_busy = ddi_prop_get_int(DDI_DEV_T_ANY, pp->dip, 0,
	    "centronics-wait-for-busy", WAIT_FOR_BUSY);

	/*
	 * In PIO mode, centronics transfers must hold the data signals
	 * for a data_setup_time milliseconds before the strobe is asserted.
	 */
	pp->data_setup_time = ddi_prop_get_int(DDI_DEV_T_ANY, pp->dip, 0,
	    "centronics-data-setup-time", DATA_SETUP_TIME);

	/*
	 * In PIO mode, centronics transfers asserts the strobe signal
	 * for a period of strobe_pulse_width milliseconds.
	 */
	pp->strobe_pulse_width = ddi_prop_get_int(DDI_DEV_T_ANY, pp->dip, 0,
	    "centronics-strobe-pulse-width", STROBE_PULSE_WIDTH);

	/*
	 * Upon a transfer the peripheral, ecpp waits write_timeout seconds
	 * for the transmission to complete.
	 */
	default_xfer_parms.write_timeout = ddi_prop_get_int(DDI_DEV_T_ANY,
	    pp->dip, 0, "ecpp-transfer-timeout", ecpp_def_timeout);

	pp->xfer_parms = default_xfer_parms;

	/*
	 * Get dma channel for M1553
	 */
	if (pp->hw == &m1553) {
		pp->uh.m1553.chn = ddi_prop_get_int(DDI_DEV_T_ANY,
		    pp->dip, 0, "dma-channel", 0x1);
		ecpp_error(pp->dip, "ecpp_get_prop:chn=%x\n", pp->uh.m1553.chn);
	}
#if defined(__x86)
	len = sizeof (value);
	/* Get dma channel for i86 pc */
	if (pp->hw == &x86) {
		if (ddi_prop_op(DDI_DEV_T_ANY, pp->dip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "dma-channels", (caddr_t)&value, &len)
		    != DDI_PROP_SUCCESS) {
			ecpp_error(pp->dip, "No dma channel found\n");
			pp->uh.x86.chn = 0xff;
			pp->fast_compat = FALSE;
			pp->noecpregs = TRUE;
		} else
			pp->uh.x86.chn = (uint8_t)value;
	}
#endif
	/*
	 * these properties are not yet public
	 */
	pp->ecp_rev_speed = ddi_prop_get_int(DDI_DEV_T_ANY, pp->dip, 0,
	    "ecp-rev-speed", ECP_REV_SPEED);

	pp->rev_watchdog = ddi_prop_get_int(DDI_DEV_T_ANY, pp->dip, 0,
	    "rev-watchdog", REV_WATCHDOG);

	ecpp_error(pp->dip,
	    "ecpp_get_prop: fast_centronics=%x, fast-1284=%x\n"
	    "ecpp_get_prop: wsrv_retry=%d, wait_for_busy=%d\n"
	    "ecpp_get_prop: data_setup=%d, strobe_pulse=%d\n"
	    "ecpp_get_prop: transfer-timeout=%d\n",
	    pp->fast_centronics, pp->fast_compat,
	    pp->wsrv_retry, pp->wait_for_busy,
	    pp->data_setup_time, pp->strobe_pulse_width,
	    pp->xfer_parms.write_timeout);
}

/*ARGSUSED*/
int
ecpp_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev = (dev_t)arg;
	struct ecppunit *pp;
	int	instance, ret;

	instance = getminor(dev);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		pp = ddi_get_soft_state(ecppsoft_statep, instance);
		if (pp != NULL) {
			*result = pp->dip;
			ret = DDI_SUCCESS;
		} else {
			ret = DDI_FAILURE;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		ret = DDI_SUCCESS;
		break;

	default:
		ret = DDI_FAILURE;
		break;
	}

	return (ret);
}

/*ARGSUSED2*/
static int
ecpp_open(queue_t *q, dev_t *dev, int flag, int sflag, cred_t *credp)
{
	struct ecppunit *pp;
	int		instance;
	struct stroptions *sop;
	mblk_t		*mop;

	instance = getminor(*dev);

	if (instance < 0) {
		return (ENXIO);
	}

	pp = (struct ecppunit *)ddi_get_soft_state(ecppsoft_statep, instance);

	if (pp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&pp->umutex);

	/*
	 * Parallel port is an exclusive-use device
	 * thus providing print job integrity
	 */
	if (pp->oflag == TRUE) {
		ecpp_error(pp->dip, "ecpp open failed");
		mutex_exit(&pp->umutex);
		return (EBUSY);
	}

	pp->oflag = TRUE;

	/* initialize state variables */
	pp->prn_timeouts = prn_timeouts_default;
	pp->xfer_parms = default_xfer_parms;
	pp->current_mode = ECPP_CENTRONICS;
	pp->backchannel = ECPP_CENTRONICS;
	pp->current_phase = ECPP_PHASE_PO;
	pp->port = ECPP_PORT_DMA;
	pp->instance = instance;
	pp->timeout_error = 0;
	pp->saved_dsr = DSR_READ(pp);
	pp->ecpp_drain_counter = 0;
	pp->dma_cancelled = FALSE;
	pp->io_mode = ECPP_DMA;
	pp->joblen = 0;
	pp->tfifo_intr = 0;
	pp->softintr_pending = 0;
	pp->nread = 0;

	/* clear the state flag */
	pp->e_busy = ECPP_IDLE;

	pp->readq = RD(q);
	pp->writeq = WR(q);
	pp->msg = NULL;

	RD(q)->q_ptr = WR(q)->q_ptr = (caddr_t)pp;

	/*
	 * Get ready: check host/peripheral, negotiate into default mode
	 */
	if (ecpp_reset_port_regs(pp) == FAILURE) {
		mutex_exit(&pp->umutex);
		return (EIO);
	}

	mutex_exit(&pp->umutex);

	/*
	 * Configure the Stream head and enable the Stream
	 */
	if (!(mop = allocb(sizeof (struct stroptions), BPRI_MED))) {
		return (EAGAIN);
	}

	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);

	/*
	 * if device is open with O_NONBLOCK flag set, let read(2) return 0
	 * if no data waiting to be read.  Writes will block on flow control.
	 */
	sop = (struct stroptions *)mop->b_rptr;
	sop->so_flags = SO_HIWAT | SO_LOWAT | SO_NDELON | SO_MREADON;
	sop->so_hiwat = ECPPHIWAT;
	sop->so_lowat = ECPPLOWAT;

	/* enable the stream */
	qprocson(q);

	putnext(q, mop);

	mutex_enter(&pp->umutex);

	ecpp_default_negotiation(pp);

	/* go revidle */
	(void) ecpp_idle_phase(pp);

	ecpp_error(pp->dip,
	    "ecpp_open: mode=%x, phase=%x ecr=%x, dsr=%x, dcr=%x\n",
	    pp->current_mode, pp->current_phase,
	    ECR_READ(pp), DSR_READ(pp), DCR_READ(pp));

	mutex_exit(&pp->umutex);

	return (0);
}

/*ARGSUSED1*/
static int
ecpp_close(queue_t *q, int flag, cred_t *cred_p)
{
	struct ecppunit *pp;
	timeout_id_t	timeout_id, fifo_timer_id, wsrv_timer_id;

	pp = (struct ecppunit *)q->q_ptr;

	ecpp_error(pp->dip, "ecpp_close: entering ...\n");

	mutex_enter(&pp->umutex);

	/*
	 * ecpp_close() will continue to loop until the
	 * queue has been drained or if the thread
	 * has received a SIG.  Typically, when the queue
	 * has data, the port will be ECPP_BUSY.  However,
	 * after a dma completes and before the wsrv
	 * starts the next transfer, the port may be IDLE.
	 * In this case, ecpp_close() will loop within this
	 * while(qsize) segment.  Since, ecpp_wsrv() runs
	 * at software interupt level, this shouldn't loop
	 * very long.
	 */
	while (pp->e_busy != ECPP_IDLE || qsize(WR(q))) {
		if (!cv_wait_sig(&pp->pport_cv, &pp->umutex)) {
			ecpp_error(pp->dip, "ecpp_close:B: received SIG\n");
			/*
			 * Returning from a signal such as
			 * SIGTERM or SIGKILL
			 */
			ecpp_flush(pp, FWRITE);
			break;
		} else {
			ecpp_error(pp->dip, "ecpp_close:rcvd cv-sig\n");
		}
	}

	ecpp_error(pp->dip, "ecpp_close: joblen=%d, ctx_cf=%d, "
	    "qsize(WR(q))=%d, qsize(RD(q))=%d\n",
	    pp->joblen, pp->ctx_cf, qsize(pp->writeq), qsize(q));

	/*
	 * Cancel all timeouts, disable interrupts
	 *
	 * Note that we can`t call untimeout(9F) with mutex held:
	 * callout may be blocked on the same mutex, and untimeout() will
	 * cv_wait() while callout is executing, thus creating a deadlock
	 * So we zero the timeout id's inside mutex and call untimeout later
	 */
	timeout_id = pp->timeout_id;
	fifo_timer_id = pp->fifo_timer_id;
	wsrv_timer_id = pp->wsrv_timer_id;

	pp->timeout_id = pp->fifo_timer_id = pp->wsrv_timer_id = 0;

	pp->softintr_pending = 0;
	pp->dma_cancelled = TRUE;
	ECPP_MASK_INTR(pp);

	mutex_exit(&pp->umutex);

	qprocsoff(q);

	if (timeout_id) {
		(void) untimeout(timeout_id);
	}
	if (fifo_timer_id) {
		(void) untimeout(fifo_timer_id);
	}
	if (wsrv_timer_id) {
		(void) untimeout(wsrv_timer_id);
	}

	mutex_enter(&pp->umutex);

	/* set link to Compatible mode */
	if ((pp->current_mode == ECPP_ECP_MODE) &&
	    (pp->current_phase != ECPP_PHASE_ECP_FWD_IDLE)) {
		(void) ecp_reverse2forward(pp);
	}

	(void) ecpp_1284_termination(pp);

	pp->oflag = FALSE;
	q->q_ptr = WR(q)->q_ptr = NULL;
	pp->readq = pp->writeq = NULL;
	pp->msg = NULL;

	ecpp_error(pp->dip, "ecpp_close: ecr=%x, dsr=%x, dcr=%x\n",
	    ECR_READ(pp), DSR_READ(pp), DCR_READ(pp));

	mutex_exit(&pp->umutex);

	return (0);
}

/*
 * standard put procedure for ecpp
 */
static int
ecpp_wput(queue_t *q, mblk_t *mp)
{
	struct msgb *nmp;
	struct ecppunit *pp;

	pp = (struct ecppunit *)q->q_ptr;

	if (!mp) {
		return (0);
	}

	if ((mp->b_wptr - mp->b_rptr) <= 0) {
		ecpp_error(pp->dip,
		    "ecpp_wput:bogus packet recieved mp=%x\n", mp);
		freemsg(mp);
		return (0);
	}

	switch (DB_TYPE(mp)) {
	case M_DATA:
		/*
		 * This is a quick fix for multiple message block problem,
		 * it will be changed later with better performance code.
		 */
		if (mp->b_cont) {
			/*
			 * mblk has scattered data ... do msgpullup
			 * if it fails, continue with the current mblk
			 */
			if ((nmp = msgpullup(mp, -1)) != NULL) {
				freemsg(mp);
				mp = nmp;
				ecpp_error(pp->dip,
				    "ecpp_wput:msgpullup: mp=%p len=%d\n",
				    mp, mp->b_wptr - mp->b_rptr);
			}
		}

		/* let ecpp_wsrv() concatenate small blocks */
		(void) putq(q, mp);

		break;

	case M_CTL:
		(void) putq(q, mp);

		break;

	case M_IOCTL: {
		struct iocblk *iocbp;

		iocbp = (struct iocblk *)mp->b_rptr;

		ecpp_error(pp->dip, "ecpp_wput:M_IOCTL %x\n", iocbp->ioc_cmd);

		mutex_enter(&pp->umutex);

		/* TESTIO and GET_STATUS can be used during transfer */
		if ((pp->e_busy == ECPP_BUSY) &&
		    (iocbp->ioc_cmd != BPPIOC_TESTIO) &&
		    (iocbp->ioc_cmd != PRNIOC_GET_STATUS)) {
			mutex_exit(&pp->umutex);
			(void) putq(q, mp);
		} else {
			mutex_exit(&pp->umutex);
			ecpp_putioc(q, mp);
		}

		break;
	}

	case M_IOCDATA: {
		struct copyresp *csp;

		ecpp_error(pp->dip, "ecpp_wput:M_IOCDATA\n");

		csp = (struct copyresp *)mp->b_rptr;

		/*
		 * If copy request failed, quit now
		 */
		if (csp->cp_rval != 0) {
			freemsg(mp);
			return (0);
		}

		switch (csp->cp_cmd) {
		case ECPPIOC_SETPARMS:
		case ECPPIOC_SETREGS:
		case ECPPIOC_SETPORT:
		case ECPPIOC_SETDATA:
		case PRNIOC_SET_IFCAP:
		case PRNIOC_SET_TIMEOUTS:
			/*
			 * need to retrieve and use the data, but if the
			 * device is busy, wait.
			 */
			(void) putq(q, mp);
			break;

		case ECPPIOC_GETPARMS:
		case ECPPIOC_GETREGS:
		case ECPPIOC_GETPORT:
		case ECPPIOC_GETDATA:
		case BPPIOC_GETERR:
		case BPPIOC_TESTIO:
		case PRNIOC_GET_IFCAP:
		case PRNIOC_GET_STATUS:
		case PRNIOC_GET_1284_STATUS:
		case PRNIOC_GET_TIMEOUTS:
			/* data transfered to user space okay */
			ecpp_ack_ioctl(q, mp);
			break;

		case ECPPIOC_GETDEVID:
			ecpp_wput_iocdata_devid(q, mp,
			    offsetof(struct ecpp_device_id, rlen));
			break;

		case PRNIOC_GET_1284_DEVID:
			ecpp_wput_iocdata_devid(q, mp,
			    offsetof(struct prn_1284_device_id, id_rlen));
			break;

		case PRNIOC_GET_IFINFO:
			ecpp_wput_iocdata_devid(q, mp,
			    offsetof(struct prn_interface_info, if_rlen));
			break;

		default:
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		break;
	}

	case M_FLUSH:
		ecpp_error(pp->dip, "ecpp_wput:M_FLUSH\n");

		if (*mp->b_rptr & FLUSHW) {
			mutex_enter(&pp->umutex);
			ecpp_flush(pp, FWRITE);
			mutex_exit(&pp->umutex);
		}

		if (*mp->b_rptr & FLUSHR) {
			mutex_enter(&pp->umutex);
			ecpp_flush(pp, FREAD);
			mutex_exit(&pp->umutex);
			qreply(q, mp);
		} else {
			freemsg(mp);
		}

		break;

	case M_READ:
		/*
		 * When the user calls read(2), M_READ message is sent to us,
		 * first byte of which is the number of requested bytes
		 * We add up user requests and use resulting number
		 * to calculate the reverse transfer block size
		 */
		mutex_enter(&pp->umutex);
		if (pp->e_busy == ECPP_IDLE) {
			pp->nread += *(size_t *)mp->b_rptr;
			ecpp_error(pp->dip, "ecpp_wput: M_READ %d", pp->nread);
			freemsg(mp);
		} else {
			ecpp_error(pp->dip, "ecpp_wput: M_READ queueing");
			(void) putq(q, mp);
		}
		mutex_exit(&pp->umutex);
		break;

	default:
		ecpp_error(pp->dip, "ecpp_wput: bad messagetype 0x%x\n",
		    DB_TYPE(mp));
		freemsg(mp);
		break;
	}

	return (0);
}

/*
 * Process ECPPIOC_GETDEVID-like ioctls
 */
static void
ecpp_wput_iocdata_devid(queue_t *q, mblk_t *mp, uintptr_t rlen_offset)
{
	struct copyresp		*csp;
	struct ecpp_copystate	*stp;
	mblk_t			*datamp;

	csp = (struct copyresp *)mp->b_rptr;
	stp = (struct ecpp_copystate *)csp->cp_private->b_rptr;

	/* determine the state of copyin/copyout process */
	switch (stp->state) {
	case ECPP_STRUCTIN:
		/* user structure has arrived */
		(void) putq(q, mp);
		break;

	case ECPP_ADDROUT:
		/*
		 * data transfered to user space okay
		 * now update user structure
		 */
		datamp = allocb(sizeof (int), BPRI_MED);
		if (datamp == NULL) {
			ecpp_nack_ioctl(q, mp, ENOSR);
			break;
		}

		*(int *)datamp->b_rptr =
		    *(int *)((char *)&stp->un + rlen_offset);
		stp->state = ECPP_STRUCTOUT;

		mcopyout(mp, csp->cp_private, sizeof (int),
		    (char *)stp->uaddr + rlen_offset, datamp);
		qreply(q, mp);
		break;

	case ECPP_STRUCTOUT:
		/* user structure was updated okay */
		freemsg(csp->cp_private);
		ecpp_ack_ioctl(q, mp);
		break;

	default:
		ecpp_nack_ioctl(q, mp, EINVAL);
		break;
	}
}

static uchar_t
ecpp_get_error_status(uchar_t status)
{
	uchar_t pin_status = 0;

	if (!(status & ECPP_nERR)) {
		pin_status |= BPP_ERR_ERR;
	}

	if (status & ECPP_PE) {
		pin_status |= BPP_PE_ERR;
	}

	if (!(status & ECPP_SLCT)) {
		pin_status |= BPP_SLCT_ERR;
	}

	if (!(status & ECPP_nBUSY)) {
		pin_status |= BPP_SLCT_ERR;
	}

	return (pin_status);
}

/*
 * ioctl handler for output PUT procedure.
 */
static void
ecpp_putioc(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocbp;
	struct ecppunit *pp;

	pp = (struct ecppunit *)q->q_ptr;

	iocbp = (struct iocblk *)mp->b_rptr;

	/* I_STR ioctls are invalid */
	if (iocbp->ioc_count != TRANSPARENT) {
		ecpp_nack_ioctl(q, mp, EINVAL);
		return;
	}

	switch (iocbp->ioc_cmd) {
	case ECPPIOC_SETPARMS: {
		mcopyin(mp, NULL, sizeof (struct ecpp_transfer_parms), NULL);
		qreply(q, mp);
		break;
	}

	case ECPPIOC_GETPARMS: {
		struct ecpp_transfer_parms xfer_parms;

		mutex_enter(&pp->umutex);

		pp->xfer_parms.mode = pp->current_mode;
		xfer_parms = pp->xfer_parms;

		mutex_exit(&pp->umutex);

		ecpp_putioc_copyout(q, mp, &xfer_parms, sizeof (xfer_parms));
		break;
	}

	case ECPPIOC_SETREGS: {
		mutex_enter(&pp->umutex);
		if (pp->current_mode != ECPP_DIAG_MODE) {
			mutex_exit(&pp->umutex);
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}
		mutex_exit(&pp->umutex);

		mcopyin(mp, NULL, sizeof (struct ecpp_regs), NULL);
		qreply(q, mp);
		break;
	}

	case ECPPIOC_GETREGS: {
		struct ecpp_regs rg;

		mutex_enter(&pp->umutex);

		if (pp->current_mode != ECPP_DIAG_MODE) {
			mutex_exit(&pp->umutex);
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		rg.dsr = DSR_READ(pp);
		rg.dcr = DCR_READ(pp);

		mutex_exit(&pp->umutex);

		ecpp_error(pp->dip, "ECPPIOC_GETREGS: dsr=%x,dcr=%x\n",
		    rg.dsr, rg.dcr);

		/* these bits must be 1 */
		rg.dsr |= ECPP_SETREGS_DSR_MASK;
		rg.dcr |= ECPP_SETREGS_DCR_MASK;

		ecpp_putioc_copyout(q, mp, &rg, sizeof (rg));
		break;
	}

	case ECPPIOC_SETPORT:
	case ECPPIOC_SETDATA: {
		mutex_enter(&pp->umutex);
		if (pp->current_mode != ECPP_DIAG_MODE) {
			mutex_exit(&pp->umutex);
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}
		mutex_exit(&pp->umutex);

		/*
		 * each of the commands fetches a byte quantity.
		 */
		mcopyin(mp, NULL, sizeof (uchar_t), NULL);
		qreply(q, mp);
		break;
	}

	case ECPPIOC_GETDATA:
	case ECPPIOC_GETPORT: {
		uchar_t	byte;

		mutex_enter(&pp->umutex);

		/* must be in diagnostic mode for these commands to work */
		if (pp->current_mode != ECPP_DIAG_MODE) {
			mutex_exit(&pp->umutex);
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		if (iocbp->ioc_cmd == ECPPIOC_GETPORT) {
			byte = pp->port;
		} else if (iocbp->ioc_cmd == ECPPIOC_GETDATA) {
			switch (pp->port) {
			case ECPP_PORT_PIO:
				byte = DATAR_READ(pp);
				break;
			case ECPP_PORT_TDMA:
				byte = TFIFO_READ(pp);
				ecpp_error(pp->dip, "GETDATA=0x%x\n", byte);
				break;
			default:
				ecpp_nack_ioctl(q, mp, EINVAL);
				break;
			}
		} else {
			mutex_exit(&pp->umutex);
			ecpp_error(pp->dip, "weird command");
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		mutex_exit(&pp->umutex);

		ecpp_putioc_copyout(q, mp, &byte, sizeof (byte));

		break;
	}

	case BPPIOC_GETERR: {
		struct bpp_error_status bpp_status;

		mutex_enter(&pp->umutex);

		bpp_status.timeout_occurred = pp->timeout_error;
		bpp_status.bus_error = 0;	/* not used */
		bpp_status.pin_status = ecpp_get_error_status(pp->saved_dsr);

		mutex_exit(&pp->umutex);

		ecpp_putioc_copyout(q, mp, &bpp_status, sizeof (bpp_status));

		break;
	}

	case BPPIOC_TESTIO: {
		mutex_enter(&pp->umutex);

		if (!((pp->current_mode == ECPP_CENTRONICS) ||
		    (pp->current_mode == ECPP_COMPAT_MODE))) {
			ecpp_nack_ioctl(q, mp, EINVAL);
		} else {
			pp->saved_dsr = DSR_READ(pp);

			if ((pp->saved_dsr & ECPP_PE) ||
			    !(pp->saved_dsr & ECPP_SLCT) ||
			    !(pp->saved_dsr & ECPP_nERR)) {
				ecpp_nack_ioctl(q, mp, EIO);
			} else {
				ecpp_ack_ioctl(q, mp);
			}
		}

		mutex_exit(&pp->umutex);

		break;
	}

	case PRNIOC_RESET:
		/*
		 * Initialize interface only if no transfer is in progress
		 */
		mutex_enter(&pp->umutex);
		if (pp->e_busy == ECPP_BUSY) {
			mutex_exit(&pp->umutex);
			ecpp_nack_ioctl(q, mp, EIO);
		} else {
			(void) ecpp_mode_negotiation(pp, ECPP_CENTRONICS);

			DCR_WRITE(pp, ECPP_SLCTIN);
			drv_usecwait(2);
			DCR_WRITE(pp, ECPP_SLCTIN | ECPP_nINIT);

			ecpp_default_negotiation(pp);

			mutex_exit(&pp->umutex);
			ecpp_ack_ioctl(q, mp);
		}
		break;

	case PRNIOC_GET_IFCAP: {
		uint_t		ifcap;

		mutex_enter(&pp->umutex);

		ifcap = ecpp_get_prn_ifcap(pp);

		mutex_exit(&pp->umutex);

		ecpp_putioc_copyout(q, mp, &ifcap, sizeof (ifcap));
		break;
	}

	case PRNIOC_SET_IFCAP: {
		mcopyin(mp, NULL, sizeof (uint_t), NULL);
		qreply(q, mp);
		break;
	}

	case PRNIOC_GET_TIMEOUTS: {
		struct prn_timeouts timeouts;

		mutex_enter(&pp->umutex);
		timeouts = pp->prn_timeouts;
		mutex_exit(&pp->umutex);

		ecpp_putioc_copyout(q, mp, &timeouts, sizeof (timeouts));

		break;
	}

	case PRNIOC_SET_TIMEOUTS:
		mcopyin(mp, NULL, sizeof (struct prn_timeouts),
		    *(caddr_t *)(void *)mp->b_cont->b_rptr);
		qreply(q, mp);
		break;

	case PRNIOC_GET_STATUS: {
		uint8_t	dsr;
		uint_t	status;

		mutex_enter(&pp->umutex);

		/* DSR only makes sense in Centronics & Compat mode */
		if (pp->current_mode == ECPP_CENTRONICS ||
		    pp->current_mode == ECPP_COMPAT_MODE) {
			dsr = DSR_READ(pp);
			if ((dsr & ECPP_PE) ||
			    !(dsr & ECPP_SLCT) || !(dsr & ECPP_nERR)) {
				status = PRN_ONLINE;
			} else {
				status = PRN_ONLINE | PRN_READY;
			}
		} else {
			status = PRN_ONLINE | PRN_READY;
		}

		mutex_exit(&pp->umutex);

		ecpp_putioc_copyout(q, mp, &status, sizeof (status));
		break;
	}

	case PRNIOC_GET_1284_STATUS: {
		uint8_t	dsr;
		uchar_t	status;

		mutex_enter(&pp->umutex);

		/* status only makes sense in Centronics & Compat mode */
		if (pp->current_mode != ECPP_COMPAT_MODE &&
		    pp->current_mode != ECPP_CENTRONICS) {
			mutex_exit(&pp->umutex);
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		dsr = DSR_READ(pp);		/* read status */

		mutex_exit(&pp->umutex);

		ecpp_error(pp->dip, "PRNIOC_GET_STATUS: %x\n", dsr);

		status = (dsr & (ECPP_SLCT | ECPP_PE | ECPP_nERR)) |
		    (~dsr & ECPP_nBUSY);

		ecpp_putioc_copyout(q, mp, &status, sizeof (status));
		break;
	}

	case ECPPIOC_GETDEVID:
		ecpp_putioc_stateful_copyin(q, mp,
		    sizeof (struct ecpp_device_id));
		break;

	case PRNIOC_GET_1284_DEVID:
		ecpp_putioc_stateful_copyin(q, mp,
		    sizeof (struct prn_1284_device_id));
		break;

	case PRNIOC_GET_IFINFO:
		ecpp_putioc_stateful_copyin(q, mp,
		    sizeof (struct prn_interface_info));
		break;

	default:
		ecpp_error(pp->dip, "putioc: unknown IOCTL: %x\n",
		    iocbp->ioc_cmd);
		ecpp_nack_ioctl(q, mp, EINVAL);
		break;
	}
}

/*
 * allocate mblk and copyout the requested number of bytes
 */
static void
ecpp_putioc_copyout(queue_t *q, mblk_t *mp, void *buf, int len)
{
	mblk_t	*tmp;

	if ((tmp = allocb(len, BPRI_MED)) == NULL) {
		ecpp_nack_ioctl(q, mp, ENOSR);
		return;
	}

	bcopy(buf, tmp->b_wptr, len);

	mcopyout(mp, NULL, len, NULL, tmp);
	qreply(q, mp);
}

/*
 * copyin the structure using struct ecpp_copystate
 */
static void
ecpp_putioc_stateful_copyin(queue_t *q, mblk_t *mp, size_t size)
{
	mblk_t *tmp;
	struct ecpp_copystate *stp;

	if ((tmp = allocb(sizeof (struct ecpp_copystate), BPRI_MED)) == NULL) {
		ecpp_nack_ioctl(q, mp, EAGAIN);
		return;
	}

	stp = (struct ecpp_copystate *)tmp->b_rptr;
	stp->state = ECPP_STRUCTIN;
	stp->uaddr = *(caddr_t *)mp->b_cont->b_rptr;

	tmp->b_wptr += sizeof (struct ecpp_copystate);

	mcopyin(mp, tmp, size, stp->uaddr);
	qreply(q, mp);
}

/*
 * read queue is only used when the peripheral sends data faster,
 * then the application consumes it;
 * once the low water mark is reached, this routine will be scheduled
 */
static int
ecpp_rsrv(queue_t *q)
{
	struct msgb	*mp;

	/*
	 * send data upstream until next queue is full or the queue is empty
	 */
	while (canputnext(q) && (mp = getq(q))) {
		putnext(q, mp);
	}

	/*
	 * if there is still space on the queue, enable backchannel
	 */
	if (canputnext(q)) {
		struct ecppunit	*pp = (struct ecppunit *)q->q_ptr;

		mutex_enter(&pp->umutex);

		if (pp->e_busy == ECPP_IDLE) {
			(void) ecpp_idle_phase(pp);
			cv_signal(&pp->pport_cv);  /* signal ecpp_close() */
		}

		mutex_exit(&pp->umutex);
	}

	return (0);
}

static int
ecpp_wsrv(queue_t *q)
{
	struct ecppunit	*pp = (struct ecppunit *)q->q_ptr;
	struct msgb	*mp;
	size_t		len, total_len;
	size_t		my_ioblock_sz;
	caddr_t		my_ioblock;
	caddr_t		start_addr;

	mutex_enter(&pp->umutex);

	ecpp_error(pp->dip, "ecpp_wsrv: e_busy=%x\n", pp->e_busy);

	/* if channel is actively doing work, wait till completed */
	if (pp->e_busy == ECPP_BUSY || pp->e_busy == ECPP_FLUSH) {
		mutex_exit(&pp->umutex);
		return (0);
	} else if (pp->suspended == TRUE) {
		/*
		 * if the system is about to suspend and ecpp_detach()
		 * is blocked due to active transfers, wake it up and exit
		 */
		cv_signal(&pp->pport_cv);
		mutex_exit(&pp->umutex);
		return (0);
	}

	/* peripheral status should be okay before starting transfer */
	if (pp->e_busy == ECPP_ERR) {
		if (ecpp_check_status(pp) == FAILURE) {
			if (pp->wsrv_timer_id == 0) {
				ecpp_error(pp->dip, "wsrv: start wrsv_timer\n");
				pp->wsrv_timer_id = timeout(ecpp_wsrv_timer,
				    (caddr_t)pp,
				    drv_usectohz(pp->wsrv_retry * 1000));
			} else {
				ecpp_error(pp->dip,
				    "ecpp_wsrv: wrsv_timer is active\n");
			}

			mutex_exit(&pp->umutex);
			return (0);
		} else {
			pp->e_busy = ECPP_IDLE;
		}
	}

	my_ioblock = pp->ioblock;
	my_ioblock_sz = IO_BLOCK_SZ;

	/*
	 * it`s important to null pp->msg here,
	 * cleaning up from the previous transfer attempts
	 */
	pp->msg = NULL;

	start_addr = NULL;
	len = total_len = 0;
	/*
	 * The following loop is implemented to gather the
	 * many small writes that the lp subsystem makes and
	 * compile them into one large dma transfer. The len and
	 * total_len variables are a running count of the number of
	 * bytes that have been gathered. They are bcopied to the
	 * ioblock buffer. The pp->e_busy is set to E_BUSY as soon as
	 * we start gathering packets to indicate the following transfer.
	 */
	while (mp = getq(q)) {
		switch (DB_TYPE(mp)) {
		case M_DATA:
			pp->e_busy = ECPP_BUSY;
			len = mp->b_wptr - mp->b_rptr;

			if ((total_len == 0) && (len >= my_ioblock_sz)) {
				/*
				 * if the first M_DATA is bigger than ioblock,
				 * just use this mblk and start the transfer
				 */
				total_len = len;
				start_addr = (caddr_t)mp->b_rptr;
				pp->msg = mp;
				goto breakout;
			} else if (total_len + len > my_ioblock_sz) {
				/*
				 * current M_DATA does not fit in ioblock,
				 * put it back and start the transfer
				 */
				(void) putbq(q, mp);
				goto breakout;
			} else {
				/*
				 * otherwise add data to ioblock and free mblk
				 */
				bcopy(mp->b_rptr, my_ioblock, len);
				my_ioblock += len;
				total_len += len;
				start_addr = (caddr_t)pp->ioblock;
				freemsg(mp);
			}
			break;

		case M_IOCTL:
			/*
			 * Assume a simple loopback test: an application
			 * writes data into the TFIFO, reads it using
			 * ECPPIOC_GETDATA and compares. If the transfer
			 * times out (which is only possible on Grover),
			 * the ioctl might be processed before the data
			 * got to the TFIFO, which leads to miscompare.
			 * So if we met ioctl, postpone it until after xfer.
			 */
			if (total_len > 0) {
				(void) putbq(q, mp);
				goto breakout;
			}

			ecpp_error(pp->dip, "M_IOCTL.\n");

			mutex_exit(&pp->umutex);

			ecpp_putioc(q, mp);

			mutex_enter(&pp->umutex);

			break;

		case M_IOCDATA: {
			struct copyresp *csp = (struct copyresp *)mp->b_rptr;

			ecpp_error(pp->dip, "M_IOCDATA\n");

			/*
			 * If copy request failed, quit now
			 */
			if (csp->cp_rval != 0) {
				freemsg(mp);
				break;
			}

			switch (csp->cp_cmd) {
			case ECPPIOC_SETPARMS:
			case ECPPIOC_SETREGS:
			case ECPPIOC_SETPORT:
			case ECPPIOC_SETDATA:
			case ECPPIOC_GETDEVID:
			case PRNIOC_SET_IFCAP:
			case PRNIOC_GET_1284_DEVID:
			case PRNIOC_SET_TIMEOUTS:
			case PRNIOC_GET_IFINFO:
				ecpp_srvioc(q, mp);
				break;

			default:
				ecpp_nack_ioctl(q, mp, EINVAL);
				break;
			}

			break;
		}

		case M_CTL:
			if (pp->e_busy != ECPP_IDLE) {
				ecpp_error(pp->dip, "wsrv: M_CTL postponed\n");
				(void) putbq(q, mp);
				goto breakout;
			} else {
				ecpp_error(pp->dip, "wsrv: M_CTL\n");
			}

			/* sanity check */
			if ((mp->b_wptr - mp->b_rptr != sizeof (int)) ||
			    (*(int *)mp->b_rptr != ECPP_BACKCHANNEL)) {
				ecpp_error(pp->dip, "wsrv: bogus M_CTL");
				freemsg(mp);
				break;
			} else {
				freemsg(mp);
			}

			/* This was a backchannel request */
			(void) ecpp_peripheral2host(pp);

			/* exit if transfer have been initiated */
			if (pp->e_busy == ECPP_BUSY) {
				goto breakout;
			}
			break;

		case M_READ:
			pp->nread += *(size_t *)mp->b_rptr;
			freemsg(mp);
			ecpp_error(pp->dip, "wsrv: M_READ %d", pp->nread);
			break;

		default:
			ecpp_error(pp->dip, "wsrv: should never get here\n");
			freemsg(mp);
			break;
		}
	}
breakout:
	/*
	 * If total_len > 0 then start the transfer, otherwise goto idle state
	 */
	if (total_len > 0) {
		ecpp_error(pp->dip, "wsrv:starting: total_len=%d\n", total_len);
		pp->e_busy = ECPP_BUSY;
		ecpp_start(pp, start_addr, total_len);
	} else {
		ecpp_error(pp->dip, "wsrv:finishing: ebusy=%x\n", pp->e_busy);

		/* IDLE if xfer_timeout, or FIFO_EMPTY */
		if (pp->e_busy == ECPP_IDLE) {
			(void) ecpp_idle_phase(pp);
			cv_signal(&pp->pport_cv);  /* signal ecpp_close() */
		}
	}

	mutex_exit(&pp->umutex);
	return (1);
}

/*
 * Ioctl processor for queued ioctl data transfer messages.
 */
static void
ecpp_srvioc(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocbp;
	struct ecppunit *pp;

	iocbp = (struct iocblk *)mp->b_rptr;
	pp = (struct ecppunit *)q->q_ptr;

	switch (iocbp->ioc_cmd) {
	case ECPPIOC_SETPARMS: {
		struct ecpp_transfer_parms *xferp;

		xferp = (struct ecpp_transfer_parms *)mp->b_cont->b_rptr;

		if (xferp->write_timeout <= 0 ||
		    xferp->write_timeout >= ECPP_MAX_TIMEOUT) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		if (!((xferp->mode == ECPP_CENTRONICS) ||
		    (xferp->mode == ECPP_COMPAT_MODE) ||
		    (xferp->mode == ECPP_NIBBLE_MODE) ||
		    (xferp->mode == ECPP_ECP_MODE) ||
		    (xferp->mode == ECPP_DIAG_MODE))) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		pp->xfer_parms = *xferp;
		pp->prn_timeouts.tmo_forward = pp->xfer_parms.write_timeout;

		ecpp_error(pp->dip, "srvioc: current_mode =%x new mode=%x\n",
		    pp->current_mode, pp->xfer_parms.mode);

		if (ecpp_mode_negotiation(pp, pp->xfer_parms.mode) == FAILURE) {
			ecpp_nack_ioctl(q, mp, EPROTONOSUPPORT);
		} else {
			/*
			 * mode nego was a success.  If nibble mode check
			 * back channel and set into REVIDLE.
			 */
			if ((pp->current_mode == ECPP_NIBBLE_MODE) &&
			    (read_nibble_backchan(pp) == FAILURE)) {
				/*
				 * problems reading the backchannel
				 * returned to centronics;
				 * ioctl fails.
				 */
				ecpp_nack_ioctl(q, mp, EPROTONOSUPPORT);
				break;
			}

			ecpp_ack_ioctl(q, mp);
		}
		if (pp->current_mode != ECPP_DIAG_MODE) {
			pp->port = ECPP_PORT_DMA;
		} else {
			pp->port = ECPP_PORT_PIO;
		}

		pp->xfer_parms.mode = pp->current_mode;

		break;
	}

	case ECPPIOC_SETREGS: {
		struct ecpp_regs *rg;
		uint8_t dcr;

		rg = (struct ecpp_regs *)mp->b_cont->b_rptr;

		/* must be in diagnostic mode for these commands to work */
		if (pp->current_mode != ECPP_DIAG_MODE) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		/* bits 4-7 must be 1 or return EINVAL */
		if ((rg->dcr & ECPP_SETREGS_DCR_MASK) !=
		    ECPP_SETREGS_DCR_MASK) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		/* get the old dcr */
		dcr = DCR_READ(pp) & ~ECPP_REV_DIR;
		/* get the new dcr */
		dcr = (dcr & ECPP_SETREGS_DCR_MASK) |
		    (rg->dcr & ~ECPP_SETREGS_DCR_MASK);
		DCR_WRITE(pp, dcr);
		ecpp_error(pp->dip, "ECPPIOC_SETREGS:dcr=%x\n", dcr);
		ecpp_ack_ioctl(q, mp);
		break;
	}

	case ECPPIOC_SETPORT: {
		uchar_t *port;

		port = (uchar_t *)mp->b_cont->b_rptr;

		/* must be in diagnostic mode for these commands to work */
		if (pp->current_mode != ECPP_DIAG_MODE) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		switch (*port) {
		case ECPP_PORT_PIO:
			/* put superio into PIO mode */
			ECR_WRITE(pp,
			    ECR_mode_001 | ECPP_INTR_MASK | ECPP_INTR_SRV);
			pp->port = *port;
			ecpp_ack_ioctl(q, mp);
			break;

		case ECPP_PORT_TDMA:
			ecpp_error(pp->dip, "SETPORT: to TDMA\n");
			pp->tfifo_intr = 1;
			/* change to mode 110 */
			ECR_WRITE(pp,
			    ECR_mode_110 | ECPP_INTR_MASK | ECPP_INTR_SRV);
			pp->port = *port;
			ecpp_ack_ioctl(q, mp);
			break;

		default:
			ecpp_nack_ioctl(q, mp, EINVAL);
		}

		break;
	}

	case ECPPIOC_SETDATA: {
		uchar_t *data;

		data = (uchar_t *)mp->b_cont->b_rptr;

		/* must be in diagnostic mode for these commands to work */
		if (pp->current_mode != ECPP_DIAG_MODE) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		switch (pp->port) {
		case ECPP_PORT_PIO:
			DATAR_WRITE(pp, *data);
			ecpp_ack_ioctl(q, mp);
			break;

		case ECPP_PORT_TDMA:
			TFIFO_WRITE(pp, *data);
			ecpp_ack_ioctl(q, mp);
			break;

		default:
			ecpp_nack_ioctl(q, mp, EINVAL);
		}

		break;
	}

	case ECPPIOC_GETDEVID: {
		struct copyresp		*csp;
		struct ecpp_copystate	*stp;
		struct ecpp_device_id	*dp;
		struct ecpp_device_id	id;

		csp = (struct copyresp *)mp->b_rptr;
		stp = (struct ecpp_copystate *)csp->cp_private->b_rptr;
		dp = (struct ecpp_device_id *)mp->b_cont->b_rptr;

#ifdef _MULTI_DATAMODEL
		if (IOC_CONVERT_FROM(iocbp) == IOC_ILP32) {
			struct ecpp_device_id32 *dp32;

			dp32 = (struct ecpp_device_id32 *)dp;
			id.mode = dp32->mode;
			id.len = dp32->len;
			id.addr = (char *)(uintptr_t)dp32->addr;
		} else {
#endif /* _MULTI_DATAMODEL */
			id = *dp;
#ifdef _MULTI_DATAMODEL
		}
#endif /* _MULTI_DATAMODEL */

		ecpp_srvioc_devid(q, mp, &id, &stp->un.devid.rlen);
		break;
	}

	case PRNIOC_GET_1284_DEVID: {
		struct copyresp			*csp;
		struct ecpp_copystate		*stp;
		struct prn_1284_device_id	*dp;
		struct ecpp_device_id		id;

		csp = (struct copyresp *)mp->b_rptr;
		stp = (struct ecpp_copystate *)csp->cp_private->b_rptr;
		dp = (struct prn_1284_device_id *)mp->b_cont->b_rptr;

		/* imitate struct ecpp_device_id */
		id.mode = ECPP_NIBBLE_MODE;

#ifdef _MULTI_DATAMODEL
		if (IOC_CONVERT_FROM(iocbp) == IOC_ILP32) {
			struct prn_1284_device_id32 *dp32;

			dp32 = (struct prn_1284_device_id32 *)dp;
			id.len = dp32->id_len;
			id.addr = (char *)(uintptr_t)dp32->id_data;
		} else {
#endif /* _MULTI_DATAMODEL */
			id.len = dp->id_len;
			id.addr = (char *)dp->id_data;
#ifdef _MULTI_DATAMODEL
		}
#endif /* _MULTI_DATAMODEL */

		ecpp_srvioc_devid(q, mp, &id,
		    (int *)&stp->un.prn_devid.id_rlen);
		break;
	}

	case PRNIOC_SET_IFCAP: {
		uint_t	ifcap, new_ifcap;

		ifcap = ecpp_get_prn_ifcap(pp);
		new_ifcap = *(uint_t *)mp->b_cont->b_rptr;

		if (ifcap == new_ifcap) {
			ecpp_ack_ioctl(q, mp);
			break;
		}

		/* only changing PRN_BIDI is supported */
		if ((ifcap ^ new_ifcap) & ~PRN_BIDI) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		if (new_ifcap & PRN_BIDI) {	/* go bidirectional */
			ecpp_default_negotiation(pp);
		} else {			/* go unidirectional */
			(void) ecpp_mode_negotiation(pp, ECPP_CENTRONICS);
		}

		ecpp_ack_ioctl(q, mp);
		break;
	}

	case PRNIOC_SET_TIMEOUTS: {
		struct prn_timeouts	*prn_timeouts;

		prn_timeouts = (struct prn_timeouts *)mp->b_cont->b_rptr;

		if (prn_timeouts->tmo_forward > ECPP_MAX_TIMEOUT) {
			ecpp_nack_ioctl(q, mp, EINVAL);
			break;
		}

		pp->prn_timeouts = *prn_timeouts;
		pp->xfer_parms.write_timeout = (int)prn_timeouts->tmo_forward;

		ecpp_ack_ioctl(q, mp);
		break;
	}

	case PRNIOC_GET_IFINFO:
		ecpp_srvioc_prnif(q, mp);
		break;

	default:		/* unexpected ioctl type */
		ecpp_nack_ioctl(q, mp, EINVAL);
		break;
	}
}

static void
ecpp_srvioc_devid(queue_t *q, mblk_t *mp, struct ecpp_device_id *id, int *rlen)
{
	struct ecppunit		*pp;
	struct copyresp		*csp;
	struct ecpp_copystate	*stp;
	int			error;
	int			len;
	int			mode;
	mblk_t			*datamp;

	pp = (struct ecppunit *)q->q_ptr;
	csp = (struct copyresp *)mp->b_rptr;
	stp = (struct ecpp_copystate *)csp->cp_private->b_rptr;
	mode = id->mode;

	/* check arguments */
	if ((mode < ECPP_CENTRONICS) || (mode > ECPP_ECP_MODE)) {
		ecpp_error(pp->dip, "ecpp_srvioc_devid: mode=%x, len=%x\n",
		    mode, id->len);
		ecpp_nack_ioctl(q, mp, EINVAL);
		return;
	}

	/* Currently only Nibble mode is supported */
	if (mode != ECPP_NIBBLE_MODE) {
		ecpp_nack_ioctl(q, mp, EPROTONOSUPPORT);
		return;
	}

	if ((id->addr == NULL) && (id->len != 0)) {
		ecpp_nack_ioctl(q, mp, EFAULT);
		return;
	}

	/* read device ID length */
	if (error = ecpp_getdevid(pp, NULL, &len, mode)) {
		ecpp_nack_ioctl(q, mp, error);
		goto breakout;
	}

	/* don't take into account two length bytes */
	len -= 2;
	*rlen = len;

	/* limit transfer to user buffer length */
	if (id->len < len) {
		len = id->len;
	}

	if (len == 0) {
		/* just return rlen */
		stp->state = ECPP_ADDROUT;
		ecpp_wput_iocdata_devid(q, mp,
		    (uintptr_t)rlen - (uintptr_t)&stp->un);
		goto breakout;
	}

	if ((datamp = allocb(len, BPRI_MED)) == NULL) {
		ecpp_nack_ioctl(q, mp, ENOSR);
		goto breakout;
	}

	/* read ID string */
	error = ecpp_getdevid(pp, datamp->b_rptr, &len, mode);
	if (error) {
		freemsg(datamp);
		ecpp_nack_ioctl(q, mp, error);
		goto breakout;
	} else {
		datamp->b_wptr += len;

		stp->state = ECPP_ADDROUT;
		mcopyout(mp, csp->cp_private, len, id->addr, datamp);
		qreply(q, mp);
	}

	return;

breakout:
	(void) ecpp_1284_termination(pp);
}

/*
 * PRNIOC_GET_IFINFO: return prnio interface info string
 */
static void
ecpp_srvioc_prnif(queue_t *q, mblk_t *mp)
{
	struct copyresp			*csp;
	struct ecpp_copystate		*stp;
	uint_t				len;
	struct prn_interface_info	*ip;
	struct prn_interface_info	info;
	mblk_t				*datamp;
#ifdef _MULTI_DATAMODEL
	struct iocblk		*iocbp = (struct iocblk *)mp->b_rptr;
#endif

	csp = (struct copyresp *)mp->b_rptr;
	stp = (struct ecpp_copystate *)csp->cp_private->b_rptr;
	ip = (struct prn_interface_info *)mp->b_cont->b_rptr;

#ifdef _MULTI_DATAMODEL
	if (IOC_CONVERT_FROM(iocbp) == IOC_ILP32) {
		struct prn_interface_info32 *ip32;

		ip32 = (struct prn_interface_info32 *)ip;
		info.if_len = ip32->if_len;
		info.if_data = (char *)(uintptr_t)ip32->if_data;
	} else {
#endif /* _MULTI_DATAMODEL */
		info = *ip;
#ifdef _MULTI_DATAMODEL
	}
#endif /* _MULTI_DATAMODEL */

	len = strlen(prn_ifinfo);
	stp->un.prn_if.if_rlen = len;
	stp->state = ECPP_ADDROUT;

	/* check arguments */
	if ((info.if_data == NULL) && (info.if_len != 0)) {
		ecpp_nack_ioctl(q, mp, EFAULT);
		return;
	}

	if (info.if_len == 0) {
		/* just copyout rlen */
		ecpp_wput_iocdata_devid(q, mp,
		    offsetof(struct prn_interface_info, if_rlen));
		return;
	}

	/* if needed, trim to the buffer size */
	if (len > info.if_len) {
		len = info.if_len;
	}

	if ((datamp = allocb(len, BPRI_MED)) == NULL) {
		ecpp_nack_ioctl(q, mp, ENOSR);
		return;
	}

	bcopy(&prn_ifinfo[0], datamp->b_wptr, len);
	datamp->b_wptr += len;

	mcopyout(mp, csp->cp_private, len, info.if_data, datamp);
	qreply(q, mp);
}

static void
ecpp_flush(struct ecppunit *pp, int cmd)
{
	queue_t		*q;
	uint8_t		ecr, dcr;
	timeout_id_t	timeout_id, fifo_timer_id, wsrv_timer_id;

	ASSERT(mutex_owned(&pp->umutex));

	if (!(cmd & FWRITE)) {
		return;
	}

	q = pp->writeq;
	timeout_id = fifo_timer_id = wsrv_timer_id = 0;

	ecpp_error(pp->dip, "ecpp_flush e_busy=%x\n", pp->e_busy);

	/* if there is an ongoing DMA, it needs to be turned off. */
	switch (pp->e_busy) {
	case ECPP_BUSY:
		/*
		 * Change the port status to ECPP_FLUSH to
		 * indicate to ecpp_wsrv that the wq is being flushed.
		 */
		pp->e_busy = ECPP_FLUSH;

		/*
		 * dma_cancelled indicates to ecpp_isr() that we have
		 * turned off the DMA.  Since the mutex is held, ecpp_isr()
		 * may be blocked.  Once ecpp_flush() finishes and ecpp_isr()
		 * gains the mutex, ecpp_isr() will have a _reset_ DMAC.  Most
		 * significantly, the DMAC will be reset after ecpp_isr() was
		 * invoked.  Therefore we need to have a flag "dma_cancelled"
		 * to signify when the described condition has occured.  If
		 * ecpp_isr() notes a dma_cancelled, it will ignore the DMAC csr
		 * and simply claim the interupt.
		 */

		pp->dma_cancelled = TRUE;

		/* either DMA or PIO transfer */
		if (COMPAT_DMA(pp) ||
		    (pp->current_mode == ECPP_ECP_MODE) ||
		    (pp->current_mode == ECPP_DIAG_MODE)) {
			/*
			 * if the bcr is zero, then DMA is complete and
			 * we are waiting for the fifo to drain.  Therefore,
			 * turn off dma.
			 */
			if (ECPP_DMA_STOP(pp, NULL) == FAILURE) {
				ecpp_error(pp->dip,
				    "ecpp_flush: dma_stop failed.\n");
			}

			/*
			 * If the status of the port is ECPP_BUSY,
			 * the DMA is stopped by either explicitly above, or by
			 * ecpp_isr() but the FIFO hasn't drained yet. In either
			 * case, we need to unbind the dma mappings.
			 */
			if (ddi_dma_unbind_handle(
			    pp->dma_handle) != DDI_SUCCESS)
				ecpp_error(pp->dip,
				    "ecpp_flush: unbind failed.\n");

			if (pp->msg != NULL) {
				freemsg(pp->msg);
				pp->msg = NULL;
			}
		} else {
			/*
			 * PIO transfer: disable nAck interrups
			 */
			dcr = DCR_READ(pp);
			dcr &= ~(ECPP_REV_DIR | ECPP_INTR_EN);
			DCR_WRITE(pp, dcr);
			ECPP_MASK_INTR(pp);
		}

		/*
		 * The transfer is cleaned up.  There may or may not be data
		 * in the fifo.  We don't care at this point.  Ie. SuperIO may
		 * transfer the remaining bytes in the fifo or not. it doesn't
		 * matter.  All that is important at this stage is that no more
		 * fifo timers are started.
		 */

		timeout_id = pp->timeout_id;
		fifo_timer_id = pp->fifo_timer_id;
		pp->timeout_id = pp->fifo_timer_id = 0;
		pp->softintr_pending = 0;

		break;

	case ECPP_ERR:
		/*
		 * Change the port status to ECPP_FLUSH to
		 * indicate to ecpp_wsrv that the wq is being flushed.
		 */
		pp->e_busy = ECPP_FLUSH;

		/*
		 *  Most likely there are mblks in the queue,
		 *  but the driver can not transmit because
		 *  of the bad port status.  In this case,
		 *  ecpp_flush() should make sure ecpp_wsrv_timer()
		 *  is turned off.
		 */
		wsrv_timer_id = pp->wsrv_timer_id;
		pp->wsrv_timer_id = 0;

		break;

	case ECPP_IDLE:
		/* No work to do. Ready to flush */
		break;

	default:
		ecpp_error(pp->dip,
		    "ecpp_flush: illegal state %x\n", pp->e_busy);
	}

	/* in DIAG mode clear TFIFO if needed */
	if (pp->current_mode == ECPP_DIAG_MODE) {
		ecr = ECR_READ(pp);
		if (!(ecr & ECPP_FIFO_EMPTY)) {
			ECR_WRITE(pp,
			    ECPP_INTR_SRV | ECPP_INTR_MASK | ECR_mode_001);
			ECR_WRITE(pp, ecr);
		}
	}

	/* Discard all messages on the output queue. */
	flushq(q, FLUSHDATA);

	/* The port is no longer flushing or dma'ing for that matter. */
	pp->e_busy = ECPP_IDLE;

	/* Set the right phase */
	if (pp->current_mode == ECPP_ECP_MODE) {
		if (pp->current_phase == ECPP_PHASE_ECP_REV_XFER) {
			pp->current_phase = ECPP_PHASE_ECP_REV_IDLE;
		} else {
			pp->current_phase = ECPP_PHASE_ECP_FWD_IDLE;
		}
	}

	/* cancel timeouts if any */
	mutex_exit(&pp->umutex);

	if (timeout_id) {
		(void) untimeout(timeout_id);
	}
	if (fifo_timer_id) {
		(void) untimeout(fifo_timer_id);
	}
	if (wsrv_timer_id) {
		(void) untimeout(wsrv_timer_id);
	}

	mutex_enter(&pp->umutex);

	cv_signal(&pp->pport_cv);	/* wake up ecpp_close() */
}

static void
ecpp_start(struct ecppunit *pp, caddr_t addr, size_t len)
{
	ASSERT(mutex_owned(&pp->umutex));
	ASSERT(pp->e_busy == ECPP_BUSY);

	ecpp_error(pp->dip,
	    "ecpp_start:current_mode=%x,current_phase=%x,ecr=%x,len=%d\n",
	    pp->current_mode, pp->current_phase, ECR_READ(pp), len);

	pp->dma_dir = DDI_DMA_WRITE;	/* this is a forward transfer */

	switch (pp->current_mode) {
	case ECPP_NIBBLE_MODE:
		(void) ecpp_1284_termination(pp);

		/* After termination we are either Compatible or Centronics */

		/* FALLTHRU */

	case ECPP_CENTRONICS:
	case ECPP_COMPAT_MODE:
		if (pp->io_mode == ECPP_DMA) {
			if (ecpp_init_dma_xfer(pp, addr, len) == FAILURE) {
				return;
			}
		} else {
			/* PIO mode */
			if (ecpp_prep_pio_xfer(pp, addr, len) == FAILURE) {
				return;
			}
			(void) ecpp_pio_writeb(pp);
		}
		break;

	case ECPP_DIAG_MODE: {
		int	oldlen;

		/* put superio into TFIFO mode, if not already */
		ECR_WRITE(pp, ECPP_INTR_SRV | ECPP_INTR_MASK | ECR_mode_110);
		/*
		 * DMA would block if the TFIFO is not empty
		 * if by this moment nobody read these bytes, they`re gone
		 */
		drv_usecwait(1);
		if (!(ECR_READ(pp) & ECPP_FIFO_EMPTY)) {
			ecpp_error(pp->dip,
			    "ecpp_start: TFIFO not empty, clearing\n");
			ECR_WRITE(pp,
			    ECPP_INTR_SRV | ECPP_INTR_MASK | ECR_mode_001);
			ECR_WRITE(pp,
			    ECPP_INTR_SRV | ECPP_INTR_MASK | ECR_mode_110);
		}

		/* we can DMA at most 16 bytes into TFIFO */
		oldlen = len;
		if (len > ECPP_FIFO_SZ) {
			len = ECPP_FIFO_SZ;
		}

		if (ecpp_init_dma_xfer(pp, addr, len) == FAILURE) {
			return;
		}

		/* put the rest of data back on the queue */
		if (oldlen > len) {
			ecpp_putback_untransfered(pp, addr + len, oldlen - len);
		}

		break;
	}

	case ECPP_ECP_MODE:
		ASSERT(pp->current_phase == ECPP_PHASE_ECP_FWD_IDLE ||
		    pp->current_phase == ECPP_PHASE_ECP_REV_IDLE);

		/* if in Reverse Phase negotiate to Forward */
		if (pp->current_phase == ECPP_PHASE_ECP_REV_IDLE) {
			if (ecp_reverse2forward(pp) == FAILURE) {
				if (pp->msg) {
					(void) putbq(pp->writeq, pp->msg);
				} else {
					ecpp_putback_untransfered(pp,
					    addr, len);
				}
			}
		}

		if (ecpp_init_dma_xfer(pp, addr, len) == FAILURE) {
			return;
		}

		break;
	}

	/* schedule transfer timeout */
	pp->timeout_id = timeout(ecpp_xfer_timeout, (caddr_t)pp,
	    pp->xfer_parms.write_timeout * drv_usectohz(1000000));
}

/*
 * Transfer a PIO "block" a byte at a time.
 * The block is starts at addr and ends at pp->last_byte
 */
static uint8_t
ecpp_prep_pio_xfer(struct ecppunit *pp, caddr_t addr, size_t len)
{
	pp->next_byte = addr;
	pp->last_byte = (caddr_t)((ulong_t)addr + len);

	if (ecpp_check_status(pp) == FAILURE) {
		/*
		 * if status signals are bad, do not start PIO,
		 * put everything back on the queue.
		 */
		ecpp_error(pp->dip,
		    "ecpp_prep_pio_xfer:suspend PIO len=%d\n", len);

		if (pp->msg != NULL) {
			/*
			 * this circumstance we want to copy the
			 * untransfered section of msg to a new mblk,
			 * then free the orignal one.
			 */
			ecpp_putback_untransfered(pp,
			    (void *)pp->msg->b_rptr, len);
			ecpp_error(pp->dip,
			    "ecpp_prep_pio_xfer: len1=%d\n", len);

			freemsg(pp->msg);
			pp->msg = NULL;
		} else {
			ecpp_putback_untransfered(pp, pp->ioblock, len);
			ecpp_error(pp->dip,
			    "ecpp_prep_pio_xfer: len2=%d\n", len);
		}
		qenable(pp->writeq);

		return (FAILURE);
	}

	pp->dma_cancelled = FALSE;

	/* pport must be in PIO mode */
	if (ecr_write(pp, ECR_mode_001 |
	    ECPP_INTR_MASK | ECPP_INTR_SRV) != SUCCESS) {
		ecpp_error(pp->dip, "ecpp_prep_pio_xfer: failed w/ECR.\n");
	}

	ecpp_error(pp->dip, "ecpp_prep_pio_xfer: dcr=%x ecr=%x\n",
	    DCR_READ(pp), ECR_READ(pp));

	return (SUCCESS);
}

static uint8_t
ecpp_init_dma_xfer(struct ecppunit *pp, caddr_t addr, size_t len)
{
	uint8_t ecr_mode[] = {
		0,
		ECR_mode_010,	/* Centronix */
		ECR_mode_010,	/* Compat */
		0,		/* Byte */
		0,		/* Nibble */
		ECR_mode_011,	/* ECP */
		0,		/* Failure */
		ECR_mode_110,	/* Diag */
	};
	uint8_t	ecr;

	ASSERT((pp->current_mode <= ECPP_DIAG_MODE) &&
	    (ecr_mode[pp->current_mode] != 0));

	if (ecpp_setup_dma_resources(pp, addr, len) == FAILURE) {
		qenable(pp->writeq);
		return (FAILURE);
	}

	if (ecpp_check_status(pp) == FAILURE) {
		/*
		 * if status signals are bad, do not start DMA, but
		 * rather put everything back on the queue.
		 */
		ecpp_error(pp->dip,
		    "ecpp_init_dma_xfer: suspending DMA len=%d\n",
		    pp->dma_cookie.dmac_size);

		if (pp->msg != NULL) {
			/*
			 * this circumstance we want to copy the
			 * untransfered section of msg to a new mblk,
			 * then free the orignal one.
			 */
			ecpp_putback_untransfered(pp,
			    (void *)pp->msg->b_rptr, len);
			ecpp_error(pp->dip,
			    "ecpp_init_dma_xfer:a:len=%d\n", len);

			freemsg(pp->msg);
			pp->msg = NULL;
		} else {
			ecpp_putback_untransfered(pp, pp->ioblock, len);
			ecpp_error(pp->dip,
			    "ecpp_init_dma_xfer:b:len=%d\n", len);
		}

		if (ddi_dma_unbind_handle(pp->dma_handle) != DDI_SUCCESS) {
			ecpp_error(pp->dip,
			    "ecpp_init_dma_xfer: unbind FAILURE.\n");
		}
		qenable(pp->writeq);
		return (FAILURE);
	}

	pp->xfercnt = pp->resid = len;
	pp->dma_cancelled = FALSE;
	pp->tfifo_intr = 0;

	/* set the right ECR mode and disable DMA */
	ecr = ecr_mode[pp->current_mode];
	(void) ecr_write(pp, ecr | ECPP_INTR_SRV | ECPP_INTR_MASK);

	/* prepare DMAC for a transfer */
	if (ECPP_DMA_START(pp) == FAILURE) {
		ecpp_error(pp->dip, "ecpp_init_dma_xfer: dma_start FAILED.\n");
		return (FAILURE);
	}

	/* GO! */
	(void) ecr_write(pp, ecr | ECPP_DMA_ENABLE | ECPP_INTR_MASK);

	return (SUCCESS);
}

static uint8_t
ecpp_setup_dma_resources(struct ecppunit *pp, caddr_t addr, size_t len)
{
	int	err;
	off_t	woff;
	size_t	wlen;

	ASSERT(pp->dma_dir == DDI_DMA_READ || pp->dma_dir == DDI_DMA_WRITE);

	err = ddi_dma_addr_bind_handle(pp->dma_handle, NULL,
	    addr, len, pp->dma_dir | DDI_DMA_PARTIAL,
	    DDI_DMA_DONTWAIT, NULL,
	    &pp->dma_cookie, &pp->dma_cookie_count);

	switch (err) {
	case DDI_DMA_MAPPED:
		ecpp_error(pp->dip, "ecpp_setup_dma: DMA_MAPPED\n");

		pp->dma_nwin = 1;
		pp->dma_curwin = 1;
		break;

	case DDI_DMA_PARTIAL_MAP: {
		ecpp_error(pp->dip, "ecpp_setup_dma: DMA_PARTIAL_MAP\n");

		if (ddi_dma_numwin(pp->dma_handle,
		    &pp->dma_nwin) != DDI_SUCCESS) {
			(void) ddi_dma_unbind_handle(pp->dma_handle);
			return (FAILURE);
		}
		pp->dma_curwin = 1;

		/*
		 * The very first window is returned by bind_handle,
		 * but we must do this explicitly here, otherwise
		 * next getwin would return wrong cookie dmac_size
		 */
		if (ddi_dma_getwin(pp->dma_handle, 0, &woff, &wlen,
		    &pp->dma_cookie, &pp->dma_cookie_count) != DDI_SUCCESS) {
			ecpp_error(pp->dip,
			    "ecpp_setup_dma: ddi_dma_getwin failed!");
			(void) ddi_dma_unbind_handle(pp->dma_handle);
			return (FAILURE);
		}

		ecpp_error(pp->dip,
		    "ecpp_setup_dma: cookies=%d, windows=%d"
		    " addr=%lx len=%d\n",
		    pp->dma_cookie_count, pp->dma_nwin,
		    pp->dma_cookie.dmac_address, pp->dma_cookie.dmac_size);

		break;
	}

	default:
		ecpp_error(pp->dip, "ecpp_setup_dma: err=%x\n", err);
		return (FAILURE);
	}

	return (SUCCESS);
}

static void
ecpp_ack_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk  *iocbp;

	mp->b_datap->db_type = M_IOCACK;
	mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);

	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	iocbp = (struct iocblk *)mp->b_rptr;
	iocbp->ioc_error = 0;
	iocbp->ioc_count = 0;
	iocbp->ioc_rval = 0;

	qreply(q, mp);
}

static void
ecpp_nack_ioctl(queue_t *q, mblk_t *mp, int err)
{
	struct iocblk  *iocbp;

	mp->b_datap->db_type = M_IOCNAK;
	mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
	iocbp = (struct iocblk *)mp->b_rptr;
	iocbp->ioc_error = err;

	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	qreply(q, mp);
}

uint_t
ecpp_isr(caddr_t arg)
{
	struct ecppunit *pp = (struct ecppunit *)(void *)arg;
	uint32_t	dcsr;
	uint8_t		dsr;
	int		cheerio_pend_counter;
	int		retval = DDI_INTR_UNCLAIMED;
	hrtime_t	now;

	mutex_enter(&pp->umutex);
	/*
	 * interrupt may occur while other thread is holding the lock
	 * and cancels DMA transfer (e.g. ecpp_flush())
	 * since it cannot cancel the interrupt thread,
	 * it just sets dma_cancelled to TRUE,
	 * telling interrupt handler to exit immediately
	 */
	if (pp->dma_cancelled == TRUE) {
		ecpp_error(pp->dip, "dma-cancel isr\n");

		pp->intr_hard++;
		pp->dma_cancelled = FALSE;

		mutex_exit(&pp->umutex);
		return (DDI_INTR_CLAIMED);
	}

	/* Southbridge interrupts are handled separately */
#if defined(__x86)
	if (pp->hw == &x86)
#else
	if (pp->hw == &m1553)
#endif
	{
		retval = ecpp_M1553_intr(pp);
		if (retval == DDI_INTR_UNCLAIMED) {
			goto unexpected;
		}
		mutex_exit(&pp->umutex);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * the intr is through the motherboard. it is faster than PCI route.
	 * sometimes ecpp_isr() is invoked before cheerio csr is updated.
	 */
	cheerio_pend_counter = ecpp_isr_max_delay;
	dcsr = GET_DMAC_CSR(pp);

	while (!(dcsr & DCSR_INT_PEND) && cheerio_pend_counter-- > 0) {
		drv_usecwait(1);
		dcsr = GET_DMAC_CSR(pp);
	}

	/*
	 * This is a workaround for what seems to be a timing problem
	 * with the delivery of interrupts and CSR updating with the
	 * ebus2 csr, superio and the n_ERR pin from the peripheral.
	 *
	 * delay is not needed for PIO mode
	 */
	if (!COMPAT_PIO(pp)) {
		drv_usecwait(100);
		dcsr = GET_DMAC_CSR(pp);
	}

	/* on 97317 in Extended mode IRQ_ST of DSR is deasserted when read */
	dsr = DSR_READ(pp);

	/*
	 * check if interrupt is for this device:
	 * it should be reflected either in cheerio DCSR register
	 * or in IRQ_ST bit of DSR on 97317
	 */
	if ((dcsr & DCSR_INT_PEND) == 0) {
		if (pp->hw != &pc97317) {
			goto unclaimed;
		}
		/*
		 * on Excalibur, reading DSR will deassert SuperIO IRQx line
		 * RIO's DCSR_INT_PEND seems to follow IRQx transitions,
		 * so if DSR is read after interrupt occured, but before
		 * we get here, IRQx and hence INT_PEND will be deasserted
		 * as a result, we can miss a service interrupt in PIO mode
		 *
		 * malicious DSR reader is BPPIOC_TESTIO, which is called
		 * by LP in between data blocks to check printer status
		 * this workaround lets us not to miss an interrupt
		 *
		 * also, nErr interrupt (ECP mode) not always reflected in DCSR
		 */
		if (((dsr & ECPP_IRQ_ST) == 0) ||
		    ((COMPAT_PIO(pp)) && (pp->e_busy == ECPP_BUSY)) ||
		    (((dsr & ECPP_nERR) == 0) &&
		    (pp->current_mode == ECPP_ECP_MODE))) {
			dcsr = 0;
		} else {
			goto unclaimed;
		}
	}

	pp->intr_hard++;

	/* the intr is for us - check all possible interrupt sources */
	if (dcsr & DCSR_ERR_PEND) {
		size_t	bcr;

		/* we are expecting a data transfer interrupt */
		ASSERT(pp->e_busy == ECPP_BUSY);

		/*
		 * some kind of DMA error
		 */
		if (ECPP_DMA_STOP(pp, &bcr) == FAILURE) {
			ecpp_error(pp->dip, "ecpp_isr: dma_stop failed\n");
		}

		ecpp_error(pp->dip, "ecpp_isr: DMAC ERROR bcr=%d\n", bcr);

		ecpp_xfer_cleanup(pp);

		if (ddi_dma_unbind_handle(pp->dma_handle) != DDI_SUCCESS) {
			ecpp_error(pp->dip, "ecpp_isr(e): unbind failed\n");
		}

		mutex_exit(&pp->umutex);
		return (DDI_INTR_CLAIMED);
	}

	if (dcsr & DCSR_TC) {
		retval = ecpp_dma_ihdlr(pp);
		mutex_exit(&pp->umutex);
		return (DDI_INTR_CLAIMED);
	}

	if (COMPAT_PIO(pp)) {
		retval = ecpp_pio_ihdlr(pp);
		mutex_exit(&pp->umutex);
		return (DDI_INTR_CLAIMED);
	}

	/* does peripheral need attention? */
	if ((dsr & ECPP_nERR) == 0) {
		retval = ecpp_nErr_ihdlr(pp);
		mutex_exit(&pp->umutex);
		return (DDI_INTR_CLAIMED);
	}

	pp->intr_hard--;

unexpected:

	pp->intr_spurious++;

	/*
	 * The following procedure tries to prevent soft hangs
	 * in event of peripheral/superio misbehaviour:
	 * if number of unexpected interrupts in the last SPUR_PERIOD ns
	 * exceeded SPUR_CRITICAL, then shut up interrupts
	 */
	now = gethrtime();
	if (pp->lastspur == 0 || now - pp->lastspur > SPUR_PERIOD) {
		/* last unexpected interrupt was long ago */
		pp->lastspur = now;
		pp->nspur = 1;
	} else {
		/* last unexpected interrupt was recently */
		pp->nspur++;
	}

	if (pp->nspur >= SPUR_CRITICAL) {
		ECPP_MASK_INTR(pp);
		ECR_WRITE(pp, ECR_READ(pp) | ECPP_INTR_MASK | ECPP_INTR_SRV);
		pp->nspur = 0;
		cmn_err(CE_NOTE, "%s%d: too many interrupt requests",
		    ddi_get_name(pp->dip), ddi_get_instance(pp->dip));
	} else {
		ECR_WRITE(pp, ECR_READ(pp) | ECPP_INTR_SRV | ECPP_INTR_MASK);
	}

	ecpp_error(pp->dip,
	    "isr:unknown: dcsr=%x ecr=%x dsr=%x dcr=%x\nmode=%x phase=%x\n",
	    dcsr, ECR_READ(pp), dsr, DCR_READ(pp),
	    pp->current_mode, pp->current_phase);

	mutex_exit(&pp->umutex);
	return (DDI_INTR_CLAIMED);

unclaimed:

	pp->intr_spurious++;

	ecpp_error(pp->dip,
	    "isr:UNCL: dcsr=%x ecr=%x dsr=%x dcr=%x\nmode=%x phase=%x\n",
	    dcsr, ECR_READ(pp), DSR_READ(pp), DCR_READ(pp),
	    pp->current_mode, pp->current_phase);

	mutex_exit(&pp->umutex);
	return (DDI_INTR_UNCLAIMED);
}

/*
 * M1553 intr handler
 */
static uint_t
ecpp_M1553_intr(struct ecppunit *pp)
{
	int retval = DDI_INTR_UNCLAIMED;

	pp->intr_hard++;

	if (pp->e_busy == ECPP_BUSY) {
		/* Centronics or Compat PIO transfer */
		if (COMPAT_PIO(pp)) {
			return (ecpp_pio_ihdlr(pp));
		}

		/* Centronics or Compat DMA transfer */
		if (COMPAT_DMA(pp) ||
		    (pp->current_mode == ECPP_ECP_MODE) ||
		    (pp->current_mode == ECPP_DIAG_MODE)) {
			return (ecpp_dma_ihdlr(pp));
		}
	}

	/* Nibble or ECP backchannel request? */
	if ((DSR_READ(pp) & ECPP_nERR) == 0) {
		return (ecpp_nErr_ihdlr(pp));
	}

	return (retval);
}

/*
 * DMA completion interrupt handler
 */
static uint_t
ecpp_dma_ihdlr(struct ecppunit *pp)
{
	clock_t	tm;

	ecpp_error(pp->dip, "ecpp_dma_ihdlr(%x): ecr=%x, dsr=%x, dcr=%x\n",
	    pp->current_mode, ECR_READ(pp), DSR_READ(pp), DCR_READ(pp));

	/* we are expecting a data transfer interrupt */
	ASSERT(pp->e_busy == ECPP_BUSY);

	/* Intr generated while invoking TFIFO mode. Exit */
	if (pp->tfifo_intr == 1) {
		pp->tfifo_intr = 0;
		ecpp_error(pp->dip, "ecpp_dma_ihdlr: tfifo_intr is 1\n");
		return (DDI_INTR_CLAIMED);
	}

	if (ECPP_DMA_STOP(pp, NULL) == FAILURE) {
		ecpp_error(pp->dip, "ecpp_dma_ihdlr: dma_stop failed\n");
	}

	if (pp->current_mode == ECPP_ECP_MODE &&
	    pp->current_phase == ECPP_PHASE_ECP_REV_XFER) {
		ecpp_ecp_read_completion(pp);
	} else {
		/*
		 * fifo_timer() will do the cleanup when the FIFO drains
		 */
		if ((ECR_READ(pp) & ECPP_FIFO_EMPTY) ||
		    (pp->current_mode == ECPP_DIAG_MODE)) {
			tm = 0;	/* no use in waiting if FIFO is already empty */
		} else {
			tm = drv_usectohz(FIFO_DRAIN_PERIOD);
		}
		pp->fifo_timer_id = timeout(ecpp_fifo_timer, (caddr_t)pp, tm);
	}

	/*
	 * Stop the DMA transfer timeout timer
	 * this operation will temporarily give up the mutex,
	 * so we do it in the end of the handler to avoid races
	 */
	ecpp_untimeout_unblock(pp, &pp->timeout_id);

	return (DDI_INTR_CLAIMED);
}

/*
 * ecpp_pio_ihdlr() is a PIO interrupt processing routine
 * It masks interrupts, updates statistics and initiates next byte transfer
 */
static uint_t
ecpp_pio_ihdlr(struct ecppunit *pp)
{
	ASSERT(mutex_owned(&pp->umutex));
	ASSERT(pp->e_busy == ECPP_BUSY);

	/* update statistics */
	pp->joblen++;
	pp->ctxpio_obytes++;

	/* disable nAck interrups */
	ECPP_MASK_INTR(pp);
	DCR_WRITE(pp, DCR_READ(pp) & ~(ECPP_REV_DIR | ECPP_INTR_EN));

	/*
	 * If it was the last byte of the data block cleanup,
	 * otherwise trigger a soft interrupt to send the next byte
	 */
	if (pp->next_byte >= pp->last_byte) {
		ecpp_xfer_cleanup(pp);
		ecpp_error(pp->dip,
		    "ecpp_pio_ihdlr: pp->joblen=%d,pp->ctx_cf=%d,\n",
		    pp->joblen, pp->ctx_cf);
	} else {
		if (pp->softintr_pending) {
			ecpp_error(pp->dip,
			    "ecpp_pio_ihdlr:E: next byte in progress\n");
		} else {
			pp->softintr_flags = ECPP_SOFTINTR_PIONEXT;
			pp->softintr_pending = 1;
			ddi_trigger_softintr(pp->softintr_id);
		}
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * ecpp_pio_writeb() sends a byte using Centronics handshake
 */
static void
ecpp_pio_writeb(struct ecppunit *pp)
{
	uint8_t	dcr;

	dcr = DCR_READ(pp) & ~ECPP_REV_DIR;
	dcr |= ECPP_INTR_EN;

	/* send the next byte */
	DATAR_WRITE(pp, *(pp->next_byte++));

	drv_usecwait(pp->data_setup_time);

	/* Now Assert (neg logic) nStrobe */
	if (dcr_write(pp, dcr | ECPP_STB) == FAILURE) {
		ecpp_error(pp->dip, "ecpp_pio_writeb:1: failed w/DCR\n");
	}

	/* Enable nAck interrupts */
	(void) DSR_READ(pp);	/* ensure IRQ_ST is armed */
	ECPP_UNMASK_INTR(pp);

	drv_usecwait(pp->strobe_pulse_width);

	if (dcr_write(pp, dcr & ~ECPP_STB) == FAILURE) {
		ecpp_error(pp->dip, "ecpp_pio_writeb:2: failed w/DCR\n");
	}
}

/*
 * Backchannel request interrupt handler
 */
static uint_t
ecpp_nErr_ihdlr(struct ecppunit *pp)
{
	ecpp_error(pp->dip, "ecpp_nErr_ihdlr: mode=%x, phase=%x\n",
	    pp->current_mode, pp->current_phase);

	if (pp->oflag != TRUE) {
		ecpp_error(pp->dip, "ecpp_nErr_ihdlr: not open!\n");
		return (DDI_INTR_UNCLAIMED);
	}

	if (pp->e_busy == ECPP_BUSY) {
		ecpp_error(pp->dip, "ecpp_nErr_ihdlr: busy\n");
		ECR_WRITE(pp, ECR_READ(pp) | ECPP_INTR_MASK);
		return (DDI_INTR_CLAIMED);
	}

	/* mask nErr & nAck interrupts */
	ECPP_MASK_INTR(pp);
	DCR_WRITE(pp, DCR_READ(pp) & ~(ECPP_INTR_EN | ECPP_REV_DIR));
	ECR_WRITE(pp, ECR_READ(pp) | ECPP_INTR_MASK);

	/* going reverse */
	switch (pp->current_mode) {
	case ECPP_ECP_MODE:
		/*
		 * Peripheral asserts nPeriphRequest (nFault)
		 */
		break;
	case ECPP_NIBBLE_MODE:
		/*
		 * Event 18: Periph asserts nErr to indicate data avail
		 * Event 19: After waiting minimum pulse width,
		 *   periph sets nAck high to generate an interrupt
		 *
		 * Interface is in Interrupt Phase
		 */
		pp->current_phase = ECPP_PHASE_NIBT_REVINTR;

		break;
	default:
		ecpp_error(pp->dip, "ecpp_nErr_ihdlr: wrong mode!\n");
		return (DDI_INTR_UNCLAIMED);
	}

	(void) ecpp_backchan_req(pp);	/* put backchannel request on the wq */

	return (DDI_INTR_CLAIMED);
}

/*
 * Softintr handler does work according to softintr_flags:
 * in case of ECPP_SOFTINTR_PIONEXT it sends next byte of PIO transfer
 */
static uint_t
ecpp_softintr(caddr_t arg)
{
	struct ecppunit *pp = (struct ecppunit *)arg;
	uint32_t unx_len, ecpp_reattempts = 0;

	mutex_enter(&pp->umutex);

	pp->intr_soft++;

	if (!pp->softintr_pending) {
		mutex_exit(&pp->umutex);
		return (DDI_INTR_CLAIMED);
	} else {
		pp->softintr_pending = 0;
	}

	if (pp->softintr_flags & ECPP_SOFTINTR_PIONEXT) {
		pp->softintr_flags &= ~ECPP_SOFTINTR_PIONEXT;
		/*
		 * Sent next byte in PIO mode
		 */
		ecpp_reattempts = 0;
		do {
			if (ecpp_check_status(pp) == SUCCESS) {
				pp->e_busy = ECPP_BUSY;
				break;
			}
			drv_usecwait(1);
			if (pp->isr_reattempt_high < ecpp_reattempts) {
				pp->isr_reattempt_high = ecpp_reattempts;
			}
		} while (++ecpp_reattempts < pp->wait_for_busy);

		/* if the peripheral still not recovered suspend the transfer */
		if (pp->e_busy == ECPP_ERR) {
			++pp->ctx_cf; /* check status fail */
			ecpp_error(pp->dip, "ecpp_softintr:check_status:F: "
			    "dsr=%x jl=%d cf_isr=%d\n",
			    DSR_READ(pp), pp->joblen, pp->ctx_cf);

			/*
			 * if status signals are bad,
			 * put everything back on the wq.
			 */
			unx_len = pp->last_byte - pp->next_byte;
			if (pp->msg != NULL) {
				ecpp_putback_untransfered(pp,
				    (void *)pp->msg->b_rptr, unx_len);
				ecpp_error(pp->dip,
				    "ecpp_softintr:e1:unx_len=%d\n", unx_len);

				freemsg(pp->msg);
				pp->msg = NULL;
			} else {
				ecpp_putback_untransfered(pp,
				    pp->next_byte, unx_len);
				ecpp_error(pp->dip,
				    "ecpp_softintr:e2:unx_len=%d\n", unx_len);
			}

			ecpp_xfer_cleanup(pp);
			pp->e_busy = ECPP_ERR;
			qenable(pp->writeq);
		} else {
			/* send the next one */
			pp->e_busy = ECPP_BUSY;
			(void) ecpp_pio_writeb(pp);
		}
	}

	mutex_exit(&pp->umutex);
	return (DDI_INTR_CLAIMED);
}


/*
 * Transfer clean-up:
 *	shut down the DMAC
 *	stop the transfer timer
 *	enable write queue
 */
static void
ecpp_xfer_cleanup(struct ecppunit *pp)
{
	ASSERT(mutex_owned(&pp->umutex));

	/*
	 * if we did not use the ioblock, the mblk that
	 * was used should be freed.
	 */
	if (pp->msg != NULL) {
		freemsg(pp->msg);
		pp->msg = NULL;
	}

	/* The port is no longer active */
	pp->e_busy = ECPP_IDLE;

	/* Stop the transfer timeout timer */
	ecpp_untimeout_unblock(pp, &pp->timeout_id);

	qenable(pp->writeq);
}

/*VARARGS*/
static void
ecpp_error(dev_info_t *dip, char *fmt, ...)
{
	static	long	last;
	static	char	*lastfmt;
	char		msg_buffer[255];
	va_list	ap;
	time_t	now;

	if (!ecpp_debug) {
		return;
	}

	/*
	 * This function is supposed to be a quick non-blockable
	 * wrapper for cmn_err(9F), which provides a sensible degree
	 * of debug message throttling.  Not using any type of lock
	 * is a requirement, but this also leaves two static variables
	 * - last and lastfmt - unprotected. However, this will not do
	 * any harm to driver functionality, it can only weaken throttling.
	 * The following directive asks warlock to not worry about these
	 * variables.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(last, lastfmt))

	/*
	 * Don't print same error message too often.
	 */
	now = gethrestime_sec();
	if ((last == (now & ~1)) && (lastfmt == fmt))
		return;

	last = now & ~1;
	lastfmt = fmt;

	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);
	cmn_err(CE_CONT, "%s%d: %s", ddi_get_name(dip),
	    ddi_get_instance(dip), msg_buffer);
	va_end(ap);
}

/*
 * Forward transfer timeout
 */
static void
ecpp_xfer_timeout(void *arg)
{
	struct ecppunit	*pp = arg;
	void		*unx_addr;
	size_t		unx_len, xferd;
	uint8_t		dcr;
	timeout_id_t	fifo_timer_id;

	mutex_enter(&pp->umutex);

	if (pp->timeout_id == 0) {
		mutex_exit(&pp->umutex);
		return;
	} else {
		pp->timeout_id = 0;
	}

	pp->xfer_tout++;

	pp->dma_cancelled = TRUE;	/* prevent race with isr() */

	if (COMPAT_PIO(pp)) {
		/*
		 * PIO mode timeout
		 */

		/* turn off nAck interrupts */
		dcr = DCR_READ(pp);
		(void) dcr_write(pp, dcr & ~(ECPP_REV_DIR | ECPP_INTR_EN));
		ECPP_MASK_INTR(pp);

		pp->softintr_pending = 0;
		unx_len = pp->last_byte - pp->next_byte;
		ecpp_error(pp->dip, "xfer_timeout: unx_len=%d\n", unx_len);

		if (unx_len > 0) {
			unx_addr = pp->next_byte;
		} else {
			ecpp_xfer_cleanup(pp);
			qenable(pp->writeq);
			mutex_exit(&pp->umutex);
			return;
		}
	} else {
		/*
		 * DMA mode timeout
		 *
		 * If DMAC fails to shut off, continue anyways and attempt
		 * to put untransfered data back on queue.
		 */
		if (ECPP_DMA_STOP(pp, &unx_len) == FAILURE) {
			ecpp_error(pp->dip,
			    "ecpp_xfer_timeout: failed dma_stop\n");
		}

		ecpp_error(pp->dip, "xfer_timeout: unx_len=%d\n", unx_len);

		if (ddi_dma_unbind_handle(pp->dma_handle) == DDI_FAILURE) {
			ecpp_error(pp->dip,
			    "ecpp_xfer_timeout: failed unbind\n");
		}

		/*
		 * if the bcr is zero, then DMA is complete and
		 * we are waiting for the fifo to drain.  So let
		 * ecpp_fifo_timer() look after the clean up.
		 */
		if (unx_len == 0) {
			qenable(pp->writeq);
			mutex_exit(&pp->umutex);
			return;
		} else {
			xferd = pp->dma_cookie.dmac_size - unx_len;
			pp->resid -= xferd;
			unx_len = pp->resid;

			/* update statistics */
			pp->obytes[pp->current_mode] += xferd;
			pp->joblen += xferd;

			if (pp->msg != NULL) {
				unx_addr = (caddr_t)pp->msg->b_wptr - unx_len;
			} else {
				unx_addr = pp->ioblock +
				    (pp->xfercnt - unx_len);
			}
		}
	}

	/* Following code is common for PIO and DMA modes */

	ecpp_putback_untransfered(pp, (caddr_t)unx_addr, unx_len);

	if (pp->msg != NULL) {
		freemsg(pp->msg);
		pp->msg = NULL;
	}

	/* mark the error status structure */
	pp->timeout_error = 1;
	pp->e_busy = ECPP_ERR;
	fifo_timer_id = pp->fifo_timer_id;
	pp->fifo_timer_id = 0;

	qenable(pp->writeq);

	mutex_exit(&pp->umutex);

	if (fifo_timer_id) {
		(void) untimeout(fifo_timer_id);
	}
}

static void
ecpp_putback_untransfered(struct ecppunit *pp, void *startp, uint_t len)
{
	mblk_t *new_mp;

	ecpp_error(pp->dip, "ecpp_putback_untrans=%d\n", len);

	if (len == 0) {
		return;
	}

	new_mp = allocb(len, BPRI_MED);
	if (new_mp == NULL) {
		ecpp_error(pp->dip,
		    "ecpp_putback_untransfered: allocb FAILURE.\n");
		return;
	}

	bcopy(startp, new_mp->b_rptr, len);
	new_mp->b_wptr = new_mp->b_rptr + len;

	if (!putbq(pp->writeq, new_mp)) {
		freemsg(new_mp);
	}
}

static uchar_t
ecr_write(struct ecppunit *pp, uint8_t ecr_byte)
{
	int i, current_ecr;

	for (i = ECPP_REG_WRITE_MAX_LOOP; i > 0; i--) {
		ECR_WRITE(pp, ecr_byte);

		current_ecr = ECR_READ(pp);

		/* mask off the lower two read-only bits */
		if ((ecr_byte & 0xFC) == (current_ecr & 0xFC))
			return (SUCCESS);
	}
	return (FAILURE);
}

static uchar_t
dcr_write(struct ecppunit *pp, uint8_t dcr_byte)
{
	uint8_t current_dcr;
	int i;

	for (i = ECPP_REG_WRITE_MAX_LOOP; i > 0; i--) {
		DCR_WRITE(pp, dcr_byte);

		current_dcr = DCR_READ(pp);

		/* compare only bits 0-4 (direction bit return 1) */
		if ((dcr_byte & 0x1F) == (current_dcr & 0x1F))
			return (SUCCESS);
	}
	ecpp_error(pp->dip,
	    "(%d)dcr_write: dcr written =%x, dcr readback =%x\n",
	    i, dcr_byte, current_dcr);

	return (FAILURE);
}

static uchar_t
ecpp_reset_port_regs(struct ecppunit *pp)
{
	DCR_WRITE(pp, ECPP_SLCTIN | ECPP_nINIT);
	ECR_WRITE(pp, ECR_mode_001 | ECPP_INTR_MASK | ECPP_INTR_SRV);
	return (SUCCESS);
}

/*
 * The data transferred by the DMA engine goes through the FIFO,
 * so that when the DMA counter reaches zero (and an interrupt occurs)
 * the FIFO can still contain data. If this is the case, the ISR will
 * schedule this callback to wait until the FIFO drains or a timeout occurs.
 */
static void
ecpp_fifo_timer(void *arg)
{
	struct ecppunit *pp = arg;
	uint8_t	ecr;
	timeout_id_t	timeout_id;

	mutex_enter(&pp->umutex);

	/*
	 * If the FIFO timer has been turned off, exit.
	 */
	if (pp->fifo_timer_id == 0) {
		ecpp_error(pp->dip, "ecpp_fifo_timer: untimedout\n");
		mutex_exit(&pp->umutex);
		return;
	} else {
		pp->fifo_timer_id = 0;
	}

	/*
	 * If the FIFO is not empty restart timer.  Wait FIFO_DRAIN_PERIOD
	 * (250 ms) and check FIFO_EMPTY bit again. Repeat until FIFO is
	 * empty or until 10 * FIFO_DRAIN_PERIOD expires.
	 */
	ecr = ECR_READ(pp);

	if ((pp->current_mode != ECPP_DIAG_MODE) &&
	    (((ecr & ECPP_FIFO_EMPTY) == 0) &&
	    (pp->ecpp_drain_counter < 10))) {

		ecpp_error(pp->dip,
		    "ecpp_fifo_timer(%d):FIFO not empty:ecr=%x\n",
		    pp->ecpp_drain_counter, ecr);

		pp->fifo_timer_id = timeout(ecpp_fifo_timer,
		    (caddr_t)pp, drv_usectohz(FIFO_DRAIN_PERIOD));
		++pp->ecpp_drain_counter;

		mutex_exit(&pp->umutex);
		return;
	}

	if (pp->current_mode != ECPP_DIAG_MODE) {
		/*
		 * If the FIFO won't drain after 10 FIFO_DRAIN_PERIODs
		 * then don't wait any longer.  Simply clean up the transfer.
		 */
		if (pp->ecpp_drain_counter >= 10) {
			ecpp_error(pp->dip, "ecpp_fifo_timer(%d):"
			    " clearing FIFO,can't wait:ecr=%x\n",
			    pp->ecpp_drain_counter, ecr);
		} else {
			ecpp_error(pp->dip,
			    "ecpp_fifo_timer(%d):FIFO empty:ecr=%x\n",
			    pp->ecpp_drain_counter, ecr);
		}

		pp->ecpp_drain_counter = 0;
	}

	/*
	 * Main section of routine:
	 *  - stop the DMA transfer timer
	 *  - program DMA with next cookie/window or unbind the DMA mapping
	 *  - update stats
	 *  - if last mblk in queue, signal to close() & return to idle state
	 */

	/* Stop the DMA transfer timeout timer */
	timeout_id = pp->timeout_id;
	pp->timeout_id = 0;

	/* data has drained from fifo, it is ok to free dma resource */
	if (pp->current_mode == ECPP_ECP_MODE ||
	    pp->current_mode == ECPP_DIAG_MODE ||
	    COMPAT_DMA(pp)) {
		off_t	off;
		size_t	len;

		/* update residual */
		pp->resid -= pp->dma_cookie.dmac_size;

		/* update statistics */
		pp->joblen += pp->dma_cookie.dmac_size;
		if (pp->dma_dir == DDI_DMA_WRITE) {
			pp->obytes[pp->current_mode] +=
			    pp->dma_cookie.dmac_size;
		} else {
			pp->ibytes[pp->current_mode] +=
			    pp->dma_cookie.dmac_size;
		}

		/*
		 * Look if any cookies/windows left
		 */
		if (--pp->dma_cookie_count > 0) {
			/* process the next cookie */
			ddi_dma_nextcookie(pp->dma_handle,
			    &pp->dma_cookie);
		} else if (pp->dma_curwin < pp->dma_nwin) {
			/* process the next window */
			if (ddi_dma_getwin(pp->dma_handle,
			    pp->dma_curwin, &off, &len,
			    &pp->dma_cookie,
			    &pp->dma_cookie_count) != DDI_SUCCESS) {
				ecpp_error(pp->dip,
				    "ecpp_fifo_timer: ddi_dma_getwin failed\n");
				goto dma_done;
			}

			pp->dma_curwin++;
		} else {
			goto dma_done;
		}

		ecpp_error(pp->dip, "ecpp_fifo_timer: next addr=%llx len=%d\n",
		    pp->dma_cookie.dmac_address,
		    pp->dma_cookie.dmac_size);

		/* kick off new transfer */
		if (ECPP_DMA_START(pp) != SUCCESS) {
			ecpp_error(pp->dip,
			    "ecpp_fifo_timer: dma_start failed\n");
			goto dma_done;
		}

		(void) ecr_write(pp, (ecr & 0xe0) |
		    ECPP_DMA_ENABLE | ECPP_INTR_MASK);

		mutex_exit(&pp->umutex);

		if (timeout_id) {
			(void) untimeout(timeout_id);
		}
		return;

	dma_done:
		if (ddi_dma_unbind_handle(pp->dma_handle) != DDI_SUCCESS) {
			ecpp_error(pp->dip, "ecpp_fifo_timer: unbind failed\n");
		} else {
			ecpp_error(pp->dip, "ecpp_fifo_timer: unbind ok\n");
		}
	}

	/*
	 * if we did not use the dmablock, the mblk that
	 * was used should be freed.
	 */
	if (pp->msg != NULL) {
		freemsg(pp->msg);
		pp->msg = NULL;
	}

	/* The port is no longer active */
	pp->e_busy = ECPP_IDLE;

	qenable(pp->writeq);

	mutex_exit(&pp->umutex);

	if (timeout_id) {
		(void) untimeout(timeout_id);
	}
}

/*
 * In Compatibility mode, check if the peripheral is ready to accept data
 */
static uint8_t
ecpp_check_status(struct ecppunit *pp)
{
	uint8_t	dsr;
	uint8_t statmask;

	if (pp->current_mode == ECPP_ECP_MODE ||
	    pp->current_mode == ECPP_DIAG_MODE)
		return (SUCCESS);

	statmask = ECPP_nERR | ECPP_SLCT | ECPP_nBUSY | ECPP_nACK;

	dsr = DSR_READ(pp);
	if ((dsr & ECPP_PE) || ((dsr & statmask) != statmask)) {
		pp->e_busy = ECPP_ERR;
		return (FAILURE);
	} else {
		return (SUCCESS);
	}
}

/*
 * if the peripheral is not ready to accept data, write service routine
 * periodically reschedules itself to recheck peripheral status
 * and start data transfer as soon as possible
 */
static void
ecpp_wsrv_timer(void *arg)
{
	struct ecppunit *pp = arg;

	ecpp_error(pp->dip, "ecpp_wsrv_timer: starting\n");

	mutex_enter(&pp->umutex);

	if (pp->wsrv_timer_id == 0) {
		mutex_exit(&pp->umutex);
		return;
	} else {
		pp->wsrv_timer_id = 0;
	}

	ecpp_error(pp->dip, "ecpp_wsrv_timer: qenabling...\n");

	qenable(pp->writeq);

	mutex_exit(&pp->umutex);
}

/*
 * Allocate a message indicating a backchannel request
 * and put it on the write queue
 */
static int
ecpp_backchan_req(struct ecppunit *pp)
{
	mblk_t	*mp;

	if ((mp = allocb(sizeof (int), BPRI_MED)) == NULL) {
		ecpp_error(pp->dip, "ecpp_backchan_req: allocb failed\n");
		return (FAILURE);
	} else {
		mp->b_datap->db_type = M_CTL;
		*(int *)mp->b_rptr = ECPP_BACKCHANNEL;
		mp->b_wptr = mp->b_rptr + sizeof (int);
		if (!putbq(pp->writeq, mp)) {
			ecpp_error(pp->dip, "ecpp_backchan_req:putbq failed\n");
			freemsg(mp);
			return (FAILURE);
		}
		return (SUCCESS);
	}
}

/*
 * Cancel the function scheduled with timeout(9F)
 * This function is to be called with the mutex held
 */
static void
ecpp_untimeout_unblock(struct ecppunit *pp, timeout_id_t *id)
{
	timeout_id_t	saved_id;

	ASSERT(mutex_owned(&pp->umutex));

	if (*id) {
		saved_id = *id;
		*id = 0;
		mutex_exit(&pp->umutex);
		(void) untimeout(saved_id);
		mutex_enter(&pp->umutex);
	}
}

/*
 * get prnio interface capabilities
 */
static uint_t
ecpp_get_prn_ifcap(struct ecppunit *pp)
{
	uint_t	ifcap;

	ifcap = PRN_1284_DEVID | PRN_TIMEOUTS | PRN_STREAMS;

	/* status (DSR) only makes sense in Centronics & Compat modes */
	if (pp->current_mode == ECPP_CENTRONICS ||
	    pp->current_mode == ECPP_COMPAT_MODE) {
		ifcap |= PRN_1284_STATUS;
	} else if (pp->current_mode == ECPP_NIBBLE_MODE ||
	    pp->current_mode == ECPP_ECP_MODE) {
		ifcap |= PRN_BIDI;
	}

	return (ifcap);
}

/*
 * Determine SuperI/O type
 */
static struct ecpp_hw_bind *
ecpp_determine_sio_type(struct ecppunit *pp)
{
	struct ecpp_hw_bind	*hw_bind;
	char			*name;
	int			i;

	name = ddi_binding_name(pp->dip);

	for (hw_bind = NULL, i = 0; i < NELEM(ecpp_hw_bind); i++) {
		if (strcmp(name, ecpp_hw_bind[i].name) == 0) {
			hw_bind = &ecpp_hw_bind[i];
			break;
		}
	}

	return (hw_bind);
}


/*
 *
 * IEEE 1284 support routines:
 *	negotiation and termination;
 *	phase transitions;
 *	device ID;
 *
 */

/*
 * Interface initialization, abnormal termination into Compatibility mode
 *
 * Peripheral may be non-1284, so we set current mode to ECPP_CENTRONICS
 */
static void
ecpp_1284_init_interface(struct ecppunit *pp)
{
	ECR_WRITE(pp, ECPP_INTR_SRV | ECPP_INTR_MASK | ECR_mode_001);

	/*
	 * Toggle the nInit signal if configured in ecpp.conf
	 * for most peripherals it is not needed
	 */
	if (pp->init_seq == TRUE) {
		DCR_WRITE(pp, ECPP_SLCTIN);
		drv_usecwait(50);	/* T(ER) = 50us */
	}

	DCR_WRITE(pp, ECPP_nINIT | ECPP_SLCTIN);

	pp->current_mode = pp->backchannel = ECPP_CENTRONICS;
	pp->current_phase = ECPP_PHASE_C_IDLE;
	ECPP_CONFIG_MODE(pp);
	pp->to_mode[pp->current_mode]++;

	ecpp_error(pp->dip, "ecpp_1284_init_interface: ok\n");
}

/*
 * ECP mode negotiation
 */
static int
ecp_negotiation(struct ecppunit *pp)
{
	uint8_t dsr;

	/* ECP mode negotiation */

	if (ecpp_1284_negotiation(pp, ECPP_XREQ_ECP, &dsr) == FAILURE)
		return (FAILURE);

	/* Event 5: peripheral deasserts PError and Busy, asserts Select */
	if ((dsr & (ECPP_PE | ECPP_nBUSY | ECPP_SLCT)) !=
	    (ECPP_nBUSY | ECPP_SLCT)) {
		ecpp_error(pp->dip,
		    "ecp_negotiation: failed event 5 %x\n", DSR_READ(pp));
		(void) ecpp_1284_termination(pp);
		return (FAILURE);
	}

	/* entered Setup Phase */
	pp->current_phase = ECPP_PHASE_ECP_SETUP;

	/* Event 30: host asserts nAutoFd */
	DCR_WRITE(pp, ECPP_nINIT | ECPP_AFX);

	/* Event 31: peripheral asserts PError */
	if (wait_dsr(pp, ECPP_PE, ECPP_PE, 35000) < 0) {
		ecpp_error(pp->dip,
		    "ecp_negotiation: failed event 31 %x\n", DSR_READ(pp));
		(void) ecpp_1284_termination(pp);
		return (FAILURE);
	}

	/* entered Forward Idle Phase */
	pp->current_phase = ECPP_PHASE_ECP_FWD_IDLE;

	/* successful negotiation into ECP mode */
	pp->current_mode = ECPP_ECP_MODE;
	pp->backchannel = ECPP_ECP_MODE;

	ecpp_error(pp->dip, "ecp_negotiation: ok\n");

	return (SUCCESS);
}

/*
 * Nibble mode negotiation
 */
static int
nibble_negotiation(struct ecppunit *pp)
{
	uint8_t	dsr;

	if (ecpp_1284_negotiation(pp, ECPP_XREQ_NIBBLE, &dsr) == FAILURE) {
		return (FAILURE);
	}

	/*
	 * If peripheral has data available, PE and nErr will
	 * be set low at Event 5 & 6.
	 */
	if ((dsr & (ECPP_PE | ECPP_nERR)) == 0) {
		pp->current_phase = ECPP_PHASE_NIBT_AVAIL;
	} else {
		pp->current_phase = ECPP_PHASE_NIBT_NAVAIL;
	}

	/* successful negotiation into Nibble mode */
	pp->current_mode = ECPP_NIBBLE_MODE;
	pp->backchannel = ECPP_NIBBLE_MODE;

	ecpp_error(pp->dip, "nibble_negotiation: ok (phase=%x)\n",
	    pp->current_phase);

	return (SUCCESS);

}

/*
 * Wait ptimeout usec for periph to set 'mask' bits to 'val' state
 *
 * return value < 0 indicates timeout
 */
static int
wait_dsr(struct ecppunit *pp, uint8_t mask, uint8_t val, int ptimeout)
{
	while (((DSR_READ(pp) & mask) != val) && ptimeout--) {
		drv_usecwait(1);
	}

	return (ptimeout);
}

/*
 * 1284 negotiation Events 0..6
 * required mode is indicated by extensibility request value
 *
 * After successful negotiation SUCCESS is returned and
 * current mode is set according to xreq,
 * otherwise FAILURE is returned and current mode is set to
 * either COMPAT (1284 periph) or CENTRONICS (non-1284 periph)
 *
 * Current phase must be set by the caller (mode-specific negotiation)
 *
 * If rdsr is not NULL, DSR value after Event 6 is stored here
 */
static int
ecpp_1284_negotiation(struct ecppunit *pp, uint8_t xreq, uint8_t *rdsr)
{
	int xflag;

	ecpp_error(pp->dip, "nego(%x): entering...\n", xreq);

	/* negotiation should start in Compatibility mode */
	(void) ecpp_1284_termination(pp);

	/* Set host into Compat mode */
	ECR_WRITE(pp, ECPP_INTR_SRV | ECPP_INTR_MASK | ECR_mode_001);

	pp->current_phase = ECPP_PHASE_NEGO;

	/* Event 0: host sets extensibility request on data lines */
	DATAR_WRITE(pp, xreq);

	/* Event 1: host deassert nSelectin and assert nAutoFd */
	DCR_WRITE(pp, ECPP_nINIT | ECPP_AFX);

	drv_usecwait(1);	/* Tp(ecp) == 0.5us */

	/*
	 * Event 2: peripheral asserts nAck, deasserts nFault,
	 *			asserts Select, asserts PError
	 */
	if (wait_dsr(pp, ECPP_nERR | ECPP_SLCT | ECPP_PE | ECPP_nACK,
	    ECPP_nERR | ECPP_SLCT | ECPP_PE, 35000) < 0) {
		/* peripheral is not 1284-compliant */
		ecpp_error(pp->dip,
		    "nego(%x): failed event 2 %x\n", xreq, DSR_READ(pp));
		(void) ecpp_1284_termination(pp);
		return (FAILURE);
	}

	/*
	 * Event 3: host asserts nStrobe, latching extensibility value into
	 * peripherals input latch.
	 */
	DCR_WRITE(pp, ECPP_nINIT | ECPP_AFX | ECPP_STB);

	drv_usecwait(2);	/* Tp(ecp) = 0.5us */

	/*
	 * Event 4: hosts deasserts nStrobe and nAutoFD to acknowledge that
	 * it has recognized an 1284 compatible peripheral
	 */
	DCR_WRITE(pp, ECPP_nINIT);

	/*
	 * Event 5: Peripheral confirms it supports requested extension
	 * For Nibble mode Xflag must be low, otherwise it must be high
	 */
	xflag = (xreq == ECPP_XREQ_NIBBLE) ? 0 : ECPP_SLCT;

	/*
	 * Event 6: Peripheral sets nAck high
	 * indicating that status lines are valid
	 */
	if (wait_dsr(pp, ECPP_nACK, ECPP_nACK, 35000) < 0) {
		/* Something wrong with peripheral */
		ecpp_error(pp->dip,
		    "nego(%x): failed event 6 %x\n", xreq, DSR_READ(pp));
		(void) ecpp_1284_termination(pp);
		return (FAILURE);
	}

	if ((DSR_READ(pp) & ECPP_SLCT) != xflag) {
		/* Extensibility value is not supported */
		ecpp_error(pp->dip,
		    "nego(%x): failed event 5 %x\n", xreq, DSR_READ(pp));
		(void) ecpp_1284_termination(pp);
		return (FAILURE);
	}

	if (rdsr) {
		*rdsr = DSR_READ(pp);
	}

	return (SUCCESS);
}

/*
 * 1284 Termination: Events 22..28 - set link to Compatibility mode
 *
 * This routine is not designed for Immediate termination,
 * caller must take care of waiting for a valid state,
 * (in particular, in ECP mode current phase must be Forward Idle)
 * otherwise interface will be reinitialized
 *
 * In case of Valid state termination SUCCESS is returned and
 * current_mode is ECPP_COMPAT_MODE, current phase is ECPP_PHASE_C_IDLE
 * Otherwise interface is reinitialized, FAILURE is returned and
 * current mode is ECPP_CENTRONICS, current phase is ECPP_PHASE_C_IDLE
 */
static int
ecpp_1284_termination(struct ecppunit *pp)
{
	int	previous_mode = pp->current_mode;

	if (((pp->current_mode == ECPP_COMPAT_MODE ||
	    pp->current_mode == ECPP_CENTRONICS) &&
	    pp->current_phase == ECPP_PHASE_C_IDLE) ||
	    pp->current_mode == ECPP_DIAG_MODE) {
		ecpp_error(pp->dip, "termination: not needed\n");
		return (SUCCESS);
	}

	/* Set host into Compat mode, interrupts disabled */
	ECPP_MASK_INTR(pp);
	ECR_WRITE(pp, ECPP_INTR_SRV | ECPP_INTR_MASK | ECR_mode_001);

	pp->current_mode = ECPP_COMPAT_MODE;	/* needed by next function */

	ECPP_CONFIG_MODE(pp);

	/*
	 * EPP mode uses simple nInit pulse for termination
	 */
	if (previous_mode == ECPP_EPP_MODE) {
		/* Event 68: host sets nInit low */
		DCR_WRITE(pp, 0);

		drv_usecwait(55);	/* T(ER) = 50us */

		/* Event 69: host sets nInit high */
		DCR_WRITE(pp, ECPP_nINIT | ECPP_SLCTIN);

		goto endterm;
	}

	/* terminate peripheral to Compat mode */
	pp->current_phase = ECPP_PHASE_TERM;

	/* Event 22: hosts sets nSelectIn low and nAutoFd high */
	DCR_WRITE(pp, ECPP_nINIT | ECPP_SLCTIN);

	/* Event 23: peripheral deasserts nFault and nBusy */
	/* Event 24: peripheral asserts nAck */
	if (wait_dsr(pp, ECPP_nERR | ECPP_nBUSY | ECPP_nACK,
	    ECPP_nERR, 35000) < 0) {
		ecpp_error(pp->dip,
		    "termination: failed events 23,24 %x\n", DSR_READ(pp));
		ecpp_1284_init_interface(pp);
		return (FAILURE);
	}

	drv_usecwait(1);	/* Tp = 0.5us */

	/* Event 25: hosts sets nAutoFd low */
	DCR_WRITE(pp, ECPP_nINIT | ECPP_SLCTIN | ECPP_AFX);

	/* Event 26: the peripheral puts itself in Compatible mode */

	/* Event 27: peripheral deasserts nAck */
	if (wait_dsr(pp, ECPP_nACK, ECPP_nACK, 35000) < 0) {
		ecpp_error(pp->dip,
		    "termination: failed event 27 %x\n", DSR_READ(pp));
		ecpp_1284_init_interface(pp);
		return (FAILURE);
	}

	drv_usecwait(1);	/* Tp = 0.5us */

	/* Event 28: hosts deasserts nAutoFd */
	DCR_WRITE(pp, ECPP_nINIT | ECPP_SLCTIN);

	drv_usecwait(1);	/* Tp = 0.5us */

endterm:
	/* Compatible mode Idle Phase */
	pp->current_phase = ECPP_PHASE_C_IDLE;

	ecpp_error(pp->dip, "termination: completed %x %x\n",
	    DSR_READ(pp), DCR_READ(pp));

	return (SUCCESS);
}

/*
 * Initiate ECP backchannel DMA transfer
 */
static uchar_t
ecp_peripheral2host(struct ecppunit *pp)
{
	mblk_t		*mp = NULL;
	size_t		len;
	uint32_t	xfer_time;

	ASSERT(pp->current_mode == ECPP_ECP_MODE &&
	    pp->current_phase == ECPP_PHASE_ECP_REV_IDLE);

	/*
	 * hardware generates cycles to receive data from the peripheral
	 * we only need to read from FIFO
	 */

	/*
	 * If user issued read(2) of rev_resid bytes, xfer exactly this amount
	 * unless it exceeds ECP_REV_BLKSZ_MAX; otherwise try to read
	 * ECP_REV_BLKSZ_MAX or at least ECP_REV_BLKSZ bytes
	 */
	if (pp->nread > 0) {
		len = min(pp->nread, ECP_REV_BLKSZ_MAX);
	} else {
		len = ECP_REV_BLKSZ_MAX;
	}

	pp->nread = 0;	/* clear after use */

	/*
	 * Allocate mblk for data, make max 2 attepmts:
	 * if len bytes block fails, try our block size
	 */
	while ((mp = allocb(len, BPRI_MED)) == NULL) {
		ecpp_error(pp->dip,
		    "ecp_periph2host: failed allocb(%d)\n", len);
		if (len > ECP_REV_BLKSZ) {
			len = ECP_REV_BLKSZ;
		} else {
			break;
		}
	}

	if (mp == NULL) {
		goto fail;
	}

	pp->msg = mp;
	pp->e_busy = ECPP_BUSY;
	pp->dma_dir = DDI_DMA_READ;
	pp->current_phase = ECPP_PHASE_ECP_REV_XFER;

	if (ecpp_init_dma_xfer(pp, (caddr_t)mp->b_rptr, len) == FAILURE) {
		goto fail;
	}

	/*
	 * there are two problems with defining ECP backchannel xfer timeout
	 *
	 * a) IEEE 1284 allows infinite time between backchannel bytes,
	 *    but we must stop at some point to send the data upstream,
	 *    look if any forward transfer requests are pending, etc;
	 *    all that done, we can continue with backchannel data;
	 *
	 * b) we don`t know how much data peripheral has;
	 *    DMA counter is set to our buffer size, which can be bigger
	 *    than needed - in this case a timeout must detect this;
	 *
	 * The timeout we schedule here serves as both the transfer timeout
	 * and a means of detecting backchannel stalls; in fact, there are
	 * two timeouts in one:
	 *
	 * - transfer timeout is based on the ECP bandwidth of ~1MB/sec and
	 *   equals the time needed to transfer the whole buffer
	 *   (but not less than ECP_REV_MINTOUT ms); if it occurs,
	 *   DMA is stopped and the data is sent upstream;
	 *
	 * - backchannel watchdog, which would look at DMA counter
	 *   every rev_watchdog ms and stop the transfer only
	 *   if the counter hasn`t changed since the last time;
	 *   otherwise it would save DMA counter value and restart itself;
	 *
	 * transfer timeout is a multiple of rev_watchdog
	 * and implemented as a downward counter
	 *
	 * on Grover, we can`t access DMAC registers while DMA is in flight,
	 * so we can`t have watchdog on Grover, only timeout
	 */

	/* calculate number of watchdog invocations equal to the xfer timeout */
	xfer_time = max((1000 * len) / pp->ecp_rev_speed, ECP_REV_MINTOUT);
#if defined(__x86)
	pp->rev_timeout_cnt = (pp->hw == &x86) ? 1 :
	    max(xfer_time / pp->rev_watchdog, 1);
#else
	pp->rev_timeout_cnt = (pp->hw == &m1553) ? 1 :
	    max(xfer_time / pp->rev_watchdog, 1);
#endif

	pp->last_dmacnt = len;	/* nothing xferred yet */

	pp->timeout_id = timeout(ecpp_ecp_read_timeout, (caddr_t)pp,
	    drv_usectohz(pp->rev_watchdog * 1000));

	ecpp_error(pp->dip, "ecp_periph2host: DMA started len=%d\n"
	    "xfer_time=%d wdog=%d cnt=%d\n",
	    len, xfer_time, pp->rev_watchdog, pp->rev_timeout_cnt);

	return (SUCCESS);

fail:
	if (mp) {
		freemsg(mp);
	}
	pp->e_busy = ECPP_IDLE;
	pp->current_phase = ECPP_PHASE_ECP_REV_IDLE;

	return (FAILURE);
}

/*
 * ECP backchannel read timeout
 * implements both backchannel watchdog and transfer timeout in ECP mode
 * if the transfer is still in progress, reschedule itself,
 * otherwise call completion routine
 */
static void
ecpp_ecp_read_timeout(void *arg)
{
	struct ecppunit	*pp = arg;
	size_t		dmacnt;

	mutex_enter(&pp->umutex);

	if (pp->timeout_id == 0) {
		mutex_exit(&pp->umutex);
		return;
	} else {
		pp->timeout_id = 0;
	}

	if (--pp->rev_timeout_cnt == 0) {
		/*
		 * Transfer timed out
		 */
		ecpp_error(pp->dip, "ecp_read_timeout: timeout\n");
		pp->xfer_tout++;
		ecpp_ecp_read_completion(pp);
	} else {
		/*
		 * Backchannel watchdog:
		 * look if DMA made any progress from the last time
		 */
		dmacnt = ECPP_DMA_GETCNT(pp);
		if (dmacnt - pp->last_dmacnt == 0) {
			/*
			 * No progress - stop the transfer and send
			 * whatever has been read so far up the stream
			 */
			ecpp_error(pp->dip, "ecp_read_timeout: no progress\n");
			pp->xfer_tout++;
			ecpp_ecp_read_completion(pp);
		} else {
			/*
			 * Something was transferred - restart ourselves
			 */
			ecpp_error(pp->dip, "ecp_read_timeout: restarting\n");
			pp->last_dmacnt = dmacnt;
			pp->timeout_id = timeout(ecpp_ecp_read_timeout,
			    (caddr_t)pp,
			    drv_usectohz(pp->rev_watchdog * 1000));
		}
	}

	mutex_exit(&pp->umutex);
}

/*
 * ECP backchannel read completion:
 * stop the DMA, free DMA resources and send read data upstream
 */
static void
ecpp_ecp_read_completion(struct ecppunit *pp)
{
	size_t	xfer_len, unx_len;
	mblk_t	*mp;

	ASSERT(mutex_owned(&pp->umutex));
	ASSERT(pp->current_mode == ECPP_ECP_MODE &&
	    pp->current_phase == ECPP_PHASE_ECP_REV_XFER);
	ASSERT(pp->msg != NULL);

	/*
	 * Stop the transfer and unbind DMA handle
	 */
	if (ECPP_DMA_STOP(pp, &unx_len) == FAILURE) {
		unx_len = pp->resid;
		ecpp_error(pp->dip, "ecp_read_completion: failed dma_stop\n");
	}

	mp = pp->msg;
	xfer_len = pp->resid - unx_len;	/* how much data was transferred */

	if (ddi_dma_unbind_handle(pp->dma_handle) != DDI_SUCCESS) {
		ecpp_error(pp->dip, "ecp_read_completion: unbind failed.\n");
	}

	ecpp_error(pp->dip, "ecp_read_completion: xfered %d bytes of %d\n",
	    xfer_len, pp->resid);

	/* clean up and update statistics */
	pp->msg = NULL;
	pp->resid -= xfer_len;
	pp->ibytes[pp->current_mode] += xfer_len;
	pp->e_busy = ECPP_IDLE;
	pp->current_phase = ECPP_PHASE_ECP_REV_IDLE;

	/*
	 * Send the read data up the stream
	 */
	mp->b_wptr += xfer_len;
	if (canputnext(pp->readq)) {
		mutex_exit(&pp->umutex);
		putnext(pp->readq, mp);
		mutex_enter(&pp->umutex);
	} else {
		ecpp_error(pp->dip, "ecp_read_completion: fail canputnext\n");
		if (!putq(pp->readq, mp)) {
			freemsg(mp);
		}
	}

	/* if bytes left in the FIFO another transfer is needed */
	if (!(ECR_READ(pp) & ECPP_FIFO_EMPTY)) {
		(void) ecpp_backchan_req(pp);
	}

	qenable(pp->writeq);
}

/*
 * Read one byte in the Nibble mode
 */
static uchar_t
nibble_peripheral2host(struct ecppunit *pp, uint8_t *byte)
{
	uint8_t	n[2];	/* two nibbles */
	int	i;

	/*
	 * One byte is made of two nibbles
	 */
	for (i = 0; i < 2; i++) {
		/* Event 7, 12: host asserts nAutoFd to move to read a nibble */
		DCR_WRITE(pp, ECPP_nINIT | ECPP_AFX);

		/* Event 8: peripheral puts data on the status lines */

		/* Event 9: peripheral asserts nAck, data available */
		if (wait_dsr(pp, ECPP_nACK, 0, 35000) < 0) {
			ecpp_error(pp->dip,
			    "nibble_periph2host(%d): failed event 9 %x\n",
			    i + 1, DSR_READ(pp));
			(void) ecpp_1284_termination(pp);
			return (FAILURE);
		}

		n[i] = DSR_READ(pp);	/* get a nibble */

		/* Event 10: host deasserts nAutoFd to say it grabbed data */
		DCR_WRITE(pp, ECPP_nINIT);

		/* (2) Event 13: peripheral asserts PE - end of data phase */

		/* Event 11: peripheral deasserts nAck to finish handshake */
		if (wait_dsr(pp, ECPP_nACK, ECPP_nACK, 35000) < 0) {
			ecpp_error(pp->dip,
			    "nibble_periph2host(%d): failed event 11 %x\n",
			    i + 1, DSR_READ(pp));
			(void) ecpp_1284_termination(pp);
			return (FAILURE);
		}
	}

	/* extract data byte from two nibbles - optimized formula */
	*byte = ((((n[1] & ~ECPP_nACK) << 1) | (~n[1] & ECPP_nBUSY)) & 0xf0) |
	    ((((n[0] & ~ECPP_nACK) >> 3) | ((~n[0] & ECPP_nBUSY) >> 4)) & 0x0f);

	pp->ibytes[ECPP_NIBBLE_MODE]++;
	return (SUCCESS);
}

/*
 * process data transfers requested by the peripheral
 */
static uint_t
ecpp_peripheral2host(struct ecppunit *pp)
{
	if (!canputnext(pp->readq)) {
		ecpp_error(pp->dip, "ecpp_peripheral2host: readq full\n");
		return (SUCCESS);
	}

	switch (pp->backchannel) {
	case ECPP_CENTRONICS:
		/* no backchannel */
		return (SUCCESS);

	case ECPP_NIBBLE_MODE:
		ASSERT(pp->current_mode == ECPP_NIBBLE_MODE);

		/*
		 * Event 20: Host sets nAutoFd high to ack request
		 */
		DCR_WRITE(pp, ECPP_nINIT);

		/* Event 21: Periph sets PError low to ack host */
		if (wait_dsr(pp, ECPP_PE, 0, 35000) < 0) {
			ecpp_error(pp->dip,
			    "ecpp_periph2host: failed event 21 %x\n",
			    DSR_READ(pp));
			(void) ecpp_1284_termination(pp);
			return (FAILURE);
		}

		pp->current_phase = ECPP_PHASE_NIBT_AVAIL;

		/* this routine will read the data in Nibble mode */
		return (ecpp_idle_phase(pp));

	case ECPP_ECP_MODE:
		if ((pp->current_phase == ECPP_PHASE_ECP_FWD_IDLE) &&
		    (ecp_forward2reverse(pp) == FAILURE)) {
			return (FAILURE);
		}

		return (ecp_peripheral2host(pp));	/* start the transfer */

	case ECPP_DIAG_MODE: {
		mblk_t		*mp;
		int		i;

		if (ECR_READ(pp) & ECPP_FIFO_EMPTY) {
			ecpp_error(pp->dip, "ecpp_periph2host: fifo empty\n");
			return (SUCCESS);
		}

		/* allocate the FIFO size */
		if ((mp = allocb(ECPP_FIFO_SZ, BPRI_MED)) == NULL) {
			ecpp_error(pp->dip,
			    "ecpp_periph2host: allocb FAILURE.\n");
			return (FAILURE);
		}

		/*
		 * For the time being just read it byte by byte
		 */
		i = ECPP_FIFO_SZ;
		while (i-- && (!(ECR_READ(pp) & ECPP_FIFO_EMPTY))) {
			*mp->b_wptr++ = TFIFO_READ(pp);
			drv_usecwait(1); /* ECR is sometimes slow to update */
		}

		if (canputnext(pp->readq)) {
			mutex_exit(&pp->umutex);
			mp->b_datap->db_type = M_DATA;
			ecpp_error(pp->dip,
			    "ecpp_periph2host: sending %d bytes\n",
			    mp->b_wptr - mp->b_rptr);
			putnext(pp->readq, mp);
			mutex_enter(&pp->umutex);
			return (SUCCESS);
		} else {
			ecpp_error(pp->dip,
			    "ecpp_periph2host: !canputnext data lost\n");
			freemsg(mp);
			return (FAILURE);
		}
	}

	default:
		ecpp_error(pp->dip, "ecpp_peripheraltohost: illegal back");
		return (FAILURE);
	}
}

/*
 * Negotiate from ECP Forward Idle to Reverse Idle Phase
 *
 * (manipulations with dcr/ecr are according to ECP Specification)
 */
static int
ecp_forward2reverse(struct ecppunit *pp)
{
	ASSERT(pp->current_mode == ECPP_ECP_MODE &&
	    pp->current_phase == ECPP_PHASE_ECP_FWD_IDLE);

	/* place port into PS2 mode */
	ECR_WRITE(pp, ECR_mode_001 | ECPP_INTR_SRV | ECPP_INTR_MASK);

	/* set direction bit (DCR3-0 must be 0100 - National) */
	DCR_WRITE(pp, ECPP_REV_DIR | ECPP_nINIT);

	/* enable hardware assist */
	ECR_WRITE(pp, ECR_mode_011 | ECPP_INTR_SRV | ECPP_INTR_MASK);

	drv_usecwait(1);	/* Tp(ecp) = 0.5us */

	/* Event 39: host sets nInit low */
	DCR_WRITE(pp, ECPP_REV_DIR);

	/* Event 40: peripheral sets PError low */

	pp->current_phase = ECPP_PHASE_ECP_REV_IDLE;

	ecpp_error(pp->dip, "ecp_forward2reverse ok\n");

	return (SUCCESS);
}

/*
 * Negotiate from ECP Reverse Idle to Forward Idle Phase
 *
 * (manipulations with dcr/ecr are according to ECP Specification)
 */
static int
ecp_reverse2forward(struct ecppunit *pp)
{
	ASSERT(pp->current_mode == ECPP_ECP_MODE &&
	    pp->current_phase == ECPP_PHASE_ECP_REV_IDLE);

	/* Event 47: host deasserts nInit */
	DCR_WRITE(pp, ECPP_REV_DIR | ECPP_nINIT);

	/*
	 * Event 48: peripheral deasserts nAck
	 * Event 49: peripheral asserts PError
	 */
	if (wait_dsr(pp, ECPP_PE, ECPP_PE, 35000) < 0) {
		ecpp_error(pp->dip,
		    "ecp_reverse2forward: failed event 49 %x\n", DSR_READ(pp));
		(void) ecpp_1284_termination(pp);
		return (FAILURE);
	}

	/* place port into PS2 mode */
	ECR_WRITE(pp, ECR_mode_001 | ECPP_INTR_SRV | ECPP_INTR_MASK);

	/* clear direction bit */
	DCR_WRITE(pp, ECPP_nINIT);

	/* reenable hardware assist */
	ECR_WRITE(pp, ECR_mode_011 | ECPP_INTR_SRV | ECPP_INTR_MASK);

	pp->current_phase = ECPP_PHASE_ECP_FWD_IDLE;

	ecpp_error(pp->dip, "ecp_reverse2forward ok\n");

	return (SUCCESS);
}

/*
 * Default negotiation chooses the best mode supported by peripheral
 * Note that backchannel mode may be different from forward mode
 */
static void
ecpp_default_negotiation(struct ecppunit *pp)
{
	if (!noecp && (ecpp_mode_negotiation(pp, ECPP_ECP_MODE) == SUCCESS)) {
		/* 1284 compatible device */
		pp->io_mode = (pp->fast_compat == TRUE) ? ECPP_DMA : ECPP_PIO;
		return;
	} else if (ecpp_mode_negotiation(pp, ECPP_NIBBLE_MODE) == SUCCESS) {
		/* 1284 compatible device */
		pp->io_mode = (pp->fast_compat == TRUE) ? ECPP_DMA : ECPP_PIO;
	} else {
		/* Centronics device */
		pp->io_mode =
		    (pp->fast_centronics == TRUE) ? ECPP_DMA : ECPP_PIO;
	}
	ECPP_CONFIG_MODE(pp);
}

/*
 * Negotiate to the mode indicated by newmode
 */
static int
ecpp_mode_negotiation(struct ecppunit *pp, uchar_t newmode)
{
	/* any other mode is impossible */
	ASSERT(pp->current_mode == ECPP_CENTRONICS ||
	    pp->current_mode == ECPP_COMPAT_MODE ||
	    pp->current_mode == ECPP_NIBBLE_MODE ||
	    pp->current_mode == ECPP_ECP_MODE ||
	    pp->current_mode == ECPP_DIAG_MODE);

	if (pp->current_mode == newmode) {
		return (SUCCESS);
	}

	/* termination from ECP is only allowed from the Forward Idle Phase */
	if ((pp->current_mode == ECPP_ECP_MODE) &&
	    (pp->current_phase != ECPP_PHASE_ECP_FWD_IDLE)) {
		/* this may break into Centronics */
		(void) ecp_reverse2forward(pp);
	}

	switch (newmode) {
	case ECPP_CENTRONICS:
		(void) ecpp_1284_termination(pp);

		/* put superio into PIO mode */
		ECR_WRITE(pp, ECR_mode_001 | ECPP_INTR_MASK | ECPP_INTR_SRV);

		pp->current_mode = ECPP_CENTRONICS;
		pp->backchannel = ECPP_CENTRONICS;
		ECPP_CONFIG_MODE(pp);

		pp->to_mode[pp->current_mode]++;
		return (SUCCESS);

	case ECPP_COMPAT_MODE:
		/* ECPP_COMPAT_MODE should support Nibble as a backchannel */
		if (pp->current_mode == ECPP_NIBBLE_MODE) {
			if (ecpp_1284_termination(pp) == SUCCESS) {
				pp->current_mode = ECPP_COMPAT_MODE;
				pp->backchannel = ECPP_NIBBLE_MODE;
				ECPP_CONFIG_MODE(pp);
				pp->to_mode[pp->current_mode]++;
				return (SUCCESS);
			} else {
				return (FAILURE);
			}
		}

		if ((nibble_negotiation(pp) == SUCCESS) &&
		    (ecpp_1284_termination(pp) == SUCCESS)) {
			pp->backchannel = ECPP_NIBBLE_MODE;
			pp->current_mode = ECPP_COMPAT_MODE;
			ECPP_CONFIG_MODE(pp);
			pp->to_mode[pp->current_mode]++;
			return (SUCCESS);
		} else {
			return (FAILURE);
		}

	case ECPP_NIBBLE_MODE:
		if (nibble_negotiation(pp) == FAILURE) {
			return (FAILURE);
		}

		pp->backchannel = ECPP_NIBBLE_MODE;
		ECPP_CONFIG_MODE(pp);
		pp->to_mode[pp->current_mode]++;

		return (SUCCESS);

	case ECPP_ECP_MODE:
		if (pp->noecpregs)
			return (FAILURE);
		if (ecp_negotiation(pp) == FAILURE) {
			return (FAILURE);
		}

		/*
		 * National says CTR[3:0] should be 0100b before moving to 011
		 */
		DCR_WRITE(pp, ECPP_nINIT);

		if (ecr_write(pp, ECR_mode_011 |
		    ECPP_INTR_MASK | ECPP_INTR_SRV) == FAILURE) {
			ecpp_error(pp->dip, "mode_nego:ECP: failed w/ecr\n");
			return (FAILURE);
		}

		ECPP_CONFIG_MODE(pp);
		pp->to_mode[pp->current_mode]++;

		return (SUCCESS);

	case ECPP_DIAG_MODE:
		/*
		 * In DIAG mode application can do nasty things(e.g drive pins)
		 * To keep peripheral sane, terminate to Compatibility mode
		 */
		(void) ecpp_1284_termination(pp);

		/* put superio into TFIFO mode */
		if (ecr_write(pp, ECR_mode_001 |
		    ECPP_INTR_MASK | ECPP_INTR_SRV) == FAILURE) {
			ecpp_error(pp->dip, "put to TFIFO: failed w/ecr\n");
			return (FAILURE);
		}

		pp->current_mode = ECPP_DIAG_MODE;
		pp->backchannel = ECPP_DIAG_MODE;
		ECPP_CONFIG_MODE(pp);
		pp->to_mode[pp->current_mode]++;

		return (SUCCESS);

	default:
		ecpp_error(pp->dip,
		    "ecpp_mode_negotiation: mode %d not supported\n", newmode);
		return (FAILURE);
	}
}

/*
 * Standard (9.1): Peripheral data is available only when the host places
 * the interface in a mode capable of peripheral-to-host data transfer.
 * This requires the host periodically to place the interface in such a mode.
 * Polling can be eliminated by leaving the interface in an 1284 idle phase.
 */
static uchar_t
ecpp_idle_phase(struct ecppunit *pp)
{
	uchar_t		rval = FAILURE;

	/*
	 * If there is no space on the read queue, do not reverse channel
	 */
	if (!canputnext(pp->readq)) {
		ecpp_error(pp->dip, "ecpp_idle_phase: readq full\n");
		return (SUCCESS);
	}

	switch (pp->backchannel) {
	case ECPP_CENTRONICS:
	case ECPP_COMPAT_MODE:
	case ECPP_DIAG_MODE:
		/* nothing */
		ecpp_error(pp->dip, "ecpp_idle_phase: compat idle\n");
		return (SUCCESS);

	case ECPP_NIBBLE_MODE:
		/*
		 * read as much data as possible, ending up in either
		 * Reverse Idle or Host Busy Data Available phase
		 */
		ecpp_error(pp->dip, "ecpp_idle_phase: nibble backchannel\n");
		if ((pp->current_mode != ECPP_NIBBLE_MODE) &&
		    (ecpp_mode_negotiation(pp, ECPP_NIBBLE_MODE) == FAILURE)) {
			break;
		}

		rval = read_nibble_backchan(pp);

		/* put interface into Reverse Idle phase */
		if (pp->current_phase == ECPP_PHASE_NIBT_NAVAIL &&
		    canputnext(pp->readq)) {
			ecpp_error(pp->dip, "ecpp_idle_phase: going revidle\n");

			/*
			 * Event 7: host asserts nAutoFd
			 * enable nAck interrupt to get a backchannel request
			 */
			DCR_WRITE(pp, ECPP_nINIT | ECPP_AFX | ECPP_INTR_EN);

			ECPP_UNMASK_INTR(pp);
		}

		break;

	case ECPP_ECP_MODE:
		/*
		 * if data is already available, request the backchannel xfer
		 * otherwise stay in Forward Idle and enable nErr interrupts
		 */
		ecpp_error(pp->dip, "ecpp_idle_phase: ECP forward\n");

		ASSERT(pp->current_phase == ECPP_PHASE_ECP_FWD_IDLE ||
		    pp->current_phase == ECPP_PHASE_ECP_REV_IDLE);

		/* put interface into Forward Idle phase */
		if ((pp->current_phase == ECPP_PHASE_ECP_REV_IDLE) &&
		    (ecp_reverse2forward(pp) == FAILURE)) {
			return (FAILURE);
		}

		/*
		 * if data already available, put backchannel request on the wq
		 * otherwise enable nErr interrupts
		 */
		if ((DSR_READ(pp) & ECPP_nERR) == 0) {
			(void) ecpp_backchan_req(pp);
		} else {
			ECR_WRITE(pp,
			    ECR_READ(pp) & ~ECPP_INTR_MASK | ECPP_INTR_SRV);

			ECPP_UNMASK_INTR(pp);
		}

		return (SUCCESS);

	default:
		ecpp_error(pp->dip, "ecpp_idle_phase: illegal backchannel");
	}

	return (rval);
}

/*
 * This routine will leave the port in ECPP_PHASE_NIBT_REVIDLE
 * Due to flow control, though, it may stop at ECPP_PHASE_NIBT_AVAIL,
 * and continue later as the user consumes data from the read queue
 *
 * The current phase should be NIBT_AVAIL or NIBT_NAVAIL
 * If some events fail during transfer, termination puts link
 * to Compatibility mode and FAILURE is returned
 */
static int
read_nibble_backchan(struct ecppunit *pp)
{
	mblk_t		*mp;
	int		i;
	int		rval = SUCCESS;

	ASSERT(pp->current_mode == ECPP_NIBBLE_MODE);

	pp->current_phase = (DSR_READ(pp) & (ECPP_nERR | ECPP_PE))
	    ? ECPP_PHASE_NIBT_NAVAIL : ECPP_PHASE_NIBT_AVAIL;

	ecpp_error(pp->dip, "read_nibble_backchan: %x\n", DSR_READ(pp));

	/*
	 * While data is available, read it in NIBBLE_REV_BLKSZ byte chunks
	 * and send up the stream
	 */
	while (pp->current_phase == ECPP_PHASE_NIBT_AVAIL && rval == SUCCESS) {
		/* see if there's space on the queue */
		if (!canputnext(pp->readq)) {
			ecpp_error(pp->dip,
			    "read_nibble_backchan: canputnext failed\n");
			return (SUCCESS);
		}

		if ((mp = allocb(NIBBLE_REV_BLKSZ, BPRI_MED)) == NULL) {
			ecpp_error(pp->dip,
			    "read_nibble_backchan: allocb failed\n");
			return (SUCCESS);
		}

		/* read a chunk of data from the peripheral byte by byte */
		i = NIBBLE_REV_BLKSZ;
		while (i-- && !(DSR_READ(pp) & ECPP_nERR)) {
			if (nibble_peripheral2host(pp, mp->b_wptr) != SUCCESS) {
				rval = FAILURE;
				break;
			}
			mp->b_wptr++;
		}

		pp->current_phase = (DSR_READ(pp) & (ECPP_nERR | ECPP_PE))
		    ? ECPP_PHASE_NIBT_NAVAIL
		    : ECPP_PHASE_NIBT_AVAIL;

		if (mp->b_wptr - mp->b_rptr > 0) {
			ecpp_error(pp->dip,
			    "read_nibble_backchan: sending %d bytes\n",
			    mp->b_wptr - mp->b_rptr);
			pp->nread = 0;
			mutex_exit(&pp->umutex);
			putnext(pp->readq, mp);
			mutex_enter(&pp->umutex);
		} else {
			freemsg(mp);
		}
	}

	return (rval);
}

/*
 * 'Request Device ID using nibble mode' negotiation
 */
static int
devidnib_negotiation(struct ecppunit *pp)
{
	uint8_t dsr;

	if (ecpp_1284_negotiation(pp,
	    ECPP_XREQ_NIBBLE | ECPP_XREQ_ID, &dsr) == FAILURE) {
		return (FAILURE);
	}

	/*
	 * If peripheral has data available, PE and nErr will
	 * be set low at Event 5 & 6.
	 */
	if ((dsr & (ECPP_PE | ECPP_nERR)) == 0) {
		pp->current_phase = ECPP_PHASE_NIBT_AVAIL;
	} else {
		pp->current_phase = ECPP_PHASE_NIBT_NAVAIL;
	}

	ecpp_error(pp->dip, "ecpp_devidnib_nego: current_phase=%x\n",
	    pp->current_phase);

	/* successful negotiation into Nibble mode */
	pp->current_mode = ECPP_NIBBLE_MODE;
	pp->backchannel = ECPP_NIBBLE_MODE;

	ecpp_error(pp->dip, "ecpp_devidnib_nego: ok\n");

	return (SUCCESS);
}

/*
 * Read 1284 device ID sequence
 *
 * This function should be called two times:
 * 1) ecpp_getdevid(pp, NULL, &len) - to retrieve ID length;
 * 2) ecpp_getdevid(pp, buffer, &len) - to read len bytes into buffer
 *
 * After 2) port is in Compatible mode
 * If the caller fails to make second call, it must reset port to Centronics
 *
 */
static int
ecpp_getdevid(struct ecppunit *pp, uint8_t *id, int *lenp, int mode)
{
	uint8_t lenhi, lenlo;
	uint8_t dsr;
	int i;

	switch (mode) {
	case ECPP_NIBBLE_MODE:
		/* negotiate only if neccessary */
		if ((pp->current_mode != mode) || (id == NULL)) {
			if (devidnib_negotiation(pp) == FAILURE) {
				return (EIO);
			}
		}

		if (pp->current_phase != ECPP_PHASE_NIBT_AVAIL) {
			return (EIO);
		}

		/*
		 * Event 14: Host tristates data bus, peripheral
		 * asserts nERR if data available, usually the
		 * status bits (7-0) and requires two reads since
		 * only nibbles are transfered.
		 */
		dsr = DSR_READ(pp);

		if (id == NULL) {
			/*
			 * first two bytes are the length of the sequence
			 * (incl. these bytes)
			 * first byte is MSB
			 */
			if ((dsr & ECPP_nERR) ||
			    (nibble_peripheral2host(pp, &lenhi) == FAILURE) ||
			    (dsr & ECPP_nERR) ||
			    (nibble_peripheral2host(pp, &lenlo) == FAILURE)) {
				ecpp_error(pp->dip,
				    "ecpp_getdevid: id length read error\n");
				return (EIO);
			}

			*lenp = (lenhi << 8) | (lenlo);

			ecpp_error(pp->dip,
			    "ecpp_getdevid: id length = %d\n", *lenp);

			if (*lenp < 2) {
				return (EIO);
			}
		} else {
			/*
			 * read the rest of the data
			 */
			i = *lenp;
			while (i && ((dsr & ECPP_nERR) == 0)) {
				if (nibble_peripheral2host(pp, id++) == FAILURE)
					break;

				i--;
				dsr = DSR_READ(pp);
			}
			ecpp_error(pp->dip,
			    "ecpp_getdevid: read %d bytes\n", *lenp - i);

			/*
			 * 1284: After receiving the sequence, the host is
			 * required to return the link to the Compatibility mode
			 */
			(void) ecpp_1284_termination(pp);
		}

		break;

	/* Other modes are not yet supported */
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * Various hardware support
 *
 * First define some stubs for functions that do nothing
 */

/*ARGSUSED*/
static void
empty_config_mode(struct ecppunit *pp)
{
}

/*ARGSUSED*/
static void
empty_mask_intr(struct ecppunit *pp)
{
}

#if defined(__x86)
static size_t
x86_getcnt(struct ecppunit *pp)
{
	int count;

	(void) ddi_dmae_getcnt(pp->dip, pp->uh.x86.chn, &count);
	return (count);
}
#endif

/*
 *
 * National PC87332 and PC97317 SuperIOs support routines
 * These chips are used in PCI-based Darwin, Quark, Quasar, Excalibur
 * and use EBus DMA facilities (Cheerio or RIO)
 *
 */

static int
pc87332_map_regs(struct ecppunit *pp)
{
	if (ddi_regs_map_setup(pp->dip, 1, (caddr_t *)&pp->uh.ebus.c_reg, 0,
	    sizeof (struct config_reg), &acc_attr,
	    &pp->uh.ebus.c_handle) != DDI_SUCCESS) {
		ecpp_error(pp->dip, "pc87332_map_regs: failed c_reg\n");
		goto fail;
	}

	if (ddi_regs_map_setup(pp->dip, 0, (caddr_t *)&pp->i_reg, 0,
	    sizeof (struct info_reg), &acc_attr, &pp->i_handle)
	    != DDI_SUCCESS) {
		ecpp_error(pp->dip, "pc87332_map_regs: failed i_reg\n");
		goto fail;
	}

	if (ddi_regs_map_setup(pp->dip, 0, (caddr_t *)&pp->f_reg, 0x400,
	    sizeof (struct fifo_reg), &acc_attr, &pp->f_handle)
	    != DDI_SUCCESS) {
		ecpp_error(pp->dip, "pc87332_map_regs: failed f_reg\n");
		goto fail;
	}

	if (ddi_regs_map_setup(pp->dip, 2, (caddr_t *)&pp->uh.ebus.dmac, 0,
	    sizeof (struct cheerio_dma_reg), &acc_attr,
	    &pp->uh.ebus.d_handle) != DDI_SUCCESS) {
		ecpp_error(pp->dip, "pc87332_map_regs: failed dmac\n");
		goto fail;
	}

	return (SUCCESS);

fail:
	pc87332_unmap_regs(pp);
	return (FAILURE);
}

static void
pc87332_unmap_regs(struct ecppunit *pp)
{
	if (pp->uh.ebus.c_handle) {
		ddi_regs_map_free(&pp->uh.ebus.c_handle);
	}
	if (pp->uh.ebus.d_handle) {
		ddi_regs_map_free(&pp->uh.ebus.d_handle);
	}
	if (pp->i_handle) {
		ddi_regs_map_free(&pp->i_handle);
	}
	if (pp->f_handle) {
		ddi_regs_map_free(&pp->f_handle);
	}
}

static uint8_t
pc87332_read_config_reg(struct ecppunit *pp, uint8_t reg_num)
{
	uint8_t retval;

	PP_PUTB(pp->uh.ebus.c_handle, &pp->uh.ebus.c_reg->index, reg_num);
	retval = PP_GETB(pp->uh.ebus.c_handle, &pp->uh.ebus.c_reg->data);

	return (retval);
}

static void
pc87332_write_config_reg(struct ecppunit *pp, uint8_t reg_num, uint8_t val)
{
	PP_PUTB(pp->uh.ebus.c_handle, &pp->uh.ebus.c_reg->index, reg_num);
	PP_PUTB(pp->uh.ebus.c_handle, &pp->uh.ebus.c_reg->data, val);

	/*
	 * second write to this register is needed.  the register behaves as
	 * a fifo.  the first value written goes to the data register.  the
	 * second write pushes the initial value to the register indexed.
	 */

	PP_PUTB(pp->uh.ebus.c_handle, &pp->uh.ebus.c_reg->data, val);
}

static int
pc87332_config_chip(struct ecppunit *pp)
{
	uint8_t pmc, fcr;

	pp->current_phase = ECPP_PHASE_INIT;

	/* ECP DMA configuration bit (PMC4) must be set */
	pmc = pc87332_read_config_reg(pp, PMC);
	if (!(pmc & PC87332_PMC_ECP_DMA_CONFIG)) {
		pc87332_write_config_reg(pp, PMC,
		    pmc | PC87332_PMC_ECP_DMA_CONFIG);
	}

	/*
	 * The Parallel Port Multiplexor pins must be driven.
	 * Check to see if FCR3 is zero, if not clear FCR3.
	 */
	fcr = pc87332_read_config_reg(pp, FCR);
	if (fcr & PC87332_FCR_PPM_FLOAT_CTL) {
		pc87332_write_config_reg(pp, FCR,
		    fcr & ~PC87332_FCR_PPM_FLOAT_CTL);
	}

	/*
	 * clear bits 3-0 in CTR (aka DCR) prior to enabling ECP mode
	 * CTR5 can not be cleared in SPP mode, CTR5 will return 1.
	 * "FAILURE" in this case is ok.  Better to use dcr_write()
	 * to ensure reliable writing to DCR.
	 */
	if (dcr_write(pp, ECPP_DCR_SET | ECPP_nINIT) == FAILURE) {
		ecpp_error(pp->dip, "ecpp_config_87332: DCR config\n");
	}

	/* enable ECP mode, level intr (note that DCR bits 3-0 == 0x0) */
	pc87332_write_config_reg(pp, PCR,
	    PC87332_PCR_INTR_LEVL | PC87332_PCR_ECP_EN);

	/* put SuperIO in initial state */
	if (ecr_write(pp, ECR_mode_001 |
	    ECPP_INTR_MASK | ECPP_INTR_SRV) == FAILURE) {
		ecpp_error(pp->dip, "ecpp_config_87332: ECR\n");
	}

	if (dcr_write(pp, ECPP_DCR_SET | ECPP_SLCTIN | ECPP_nINIT) == FAILURE) {
		ecpp_error(pp->dip, "ecpp_config_87332: w/DCR failed2.\n");
		return (FAILURE);

	}
	/* we are in centronic mode */
	pp->current_mode = ECPP_CENTRONICS;

	/* in compatible mode with no data transfer in progress */
	pp->current_phase = ECPP_PHASE_C_IDLE;

	return (SUCCESS);
}

/*
 * A new mode was set, do some mode specific reconfiguration
 * in this case - set interrupt characteristic
 */
static void
pc87332_config_mode(struct ecppunit *pp)
{
	if (COMPAT_PIO(pp)) {
		pc87332_write_config_reg(pp, PCR, 0x04);
	} else {
		pc87332_write_config_reg(pp, PCR, 0x14);
	}
}

static int
pc97317_map_regs(struct ecppunit *pp)
{
	if (pc87332_map_regs(pp) != SUCCESS) {
		return (FAILURE);
	}

	if (ddi_regs_map_setup(pp->dip, 0, (caddr_t *)&pp->uh.ebus.c2_reg,
	    0x403, sizeof (struct config2_reg), &acc_attr,
	    &pp->uh.ebus.c2_handle) != DDI_SUCCESS) {
		ecpp_error(pp->dip, "pc97317_map_regs: failed c2_reg\n");
		pc87332_unmap_regs(pp);
		return (FAILURE);
	} else {
		return (SUCCESS);
	}
}

static void
pc97317_unmap_regs(struct ecppunit *pp)
{
	if (pp->uh.ebus.c2_handle) {
		ddi_regs_map_free(&pp->uh.ebus.c2_handle);
	}

	pc87332_unmap_regs(pp);
}

/*
 * OBP should configure the PC97317 such that it does not need further
 * configuration.  Upon sustaining, it may be necessary to examine
 * or change the configuration registers.  This routine is left in
 * the file for that purpose.
 */
static int
pc97317_config_chip(struct ecppunit *pp)
{
	uint8_t conreg;

	/* set the logical device name */
	pc87332_write_config_reg(pp, PC97317_CONFIG_DEV_NO, 0x4);

	/* SPP Compatibility */
	PP_PUTB(pp->uh.ebus.c2_handle,
	    &pp->uh.ebus.c2_reg->eir, PC97317_CONFIG2_CONTROL2);
	PP_PUTB(pp->uh.ebus.c2_handle, &pp->uh.ebus.c2_reg->edr, 0x80);

	/* low interrupt polarity */
	pc87332_write_config_reg(pp, PC97317_CONFIG_INTR_TYPE, 0x00);

	/* ECP mode */
	pc87332_write_config_reg(pp, PC97317_CONFIG_PP_CONFIG, 0xf2);

	if (dcr_write(pp, ECPP_SLCTIN | ECPP_nINIT) == FAILURE) {
		ecpp_error(pp->dip, "pc97317_config_chip: failed w/DCR\n");
	}

	if (ecr_write(pp, ECR_mode_001 |
	    ECPP_INTR_MASK | ECPP_INTR_SRV) == FAILURE) {
		ecpp_error(pp->dip, "pc97317_config_chip: failed w/ECR\n");
	}

#ifdef DEBUG
	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_DEV_NO);
	ecpp_error(pp->dip, "97317:conreg7(logical dev)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_BASE_ADDR_MSB);
	ecpp_error(pp->dip, "97317:conreg60(addrHi)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_BASE_ADDR_LSB);
	ecpp_error(pp->dip, "97317:conreg61(addrLo)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_INTR_SEL);
	ecpp_error(pp->dip, "97317:conreg70(IRQL)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_INTR_TYPE);
	ecpp_error(pp->dip, "97317:conreg71(intr type)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_ACTIVATE);
	ecpp_error(pp->dip, "97317:conreg30(Active)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_IO_RANGE);
	ecpp_error(pp->dip, "97317:conreg31(IO Range Check)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_DMA0_CHAN);
	ecpp_error(pp->dip, "97317:conreg74(DMA0 Chan)=%x\n", conreg);
	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_DMA1_CHAN);
	ecpp_error(pp->dip, "97317:conreg75(DMA1 Chan)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_PP_CONFIG);
	ecpp_error(pp->dip, "97317:conregFO(pport conf)=%x\n", conreg);

	conreg = pc87332_read_config_reg(pp, PC97317_CONFIG_PP_CONFIG);
	ecpp_error(pp->dip, "97317:conregFO(pport conf)=%x\n", conreg);
#endif /* DEBUG */

	return (SUCCESS);
}

/*
 * A new mode was set, do some mode specific reconfiguration
 * in this case - set interrupt polarity
 */
static void
pc97317_config_mode(struct ecppunit *pp)
{
	/* set the logical device name */
	pc87332_write_config_reg(pp, PC97317_CONFIG_DEV_NO, 0x4);

	if (COMPAT_PIO(pp) || pp->current_mode == ECPP_NIBBLE_MODE) {
		pc87332_write_config_reg(pp, PC97317_CONFIG_INTR_TYPE, 0x02);
	} else {
		pc87332_write_config_reg(pp, PC97317_CONFIG_INTR_TYPE, 0x00);
	}
}

static void
cheerio_mask_intr(struct ecppunit *pp)
{
	/* mask Cheerio interrupts */
	AND_SET_LONG_R(pp->uh.ebus.d_handle,
	    &pp->uh.ebus.dmac->csr, ~DCSR_INT_EN);
}

static void
cheerio_unmask_intr(struct ecppunit *pp)
{
	/* unmask Cheerio interrupts */
	OR_SET_LONG_R(pp->uh.ebus.d_handle,
	    &pp->uh.ebus.dmac->csr, DCSR_INT_EN | DCSR_TCI_DIS);
}

static int
cheerio_dma_start(struct ecppunit *pp)
{
	cheerio_reset_dcsr(pp);
	SET_DMAC_BCR(pp, pp->dma_cookie.dmac_size);
	SET_DMAC_ACR(pp, pp->dma_cookie.dmac_address);

	if (pp->dma_dir == DDI_DMA_READ) {
		SET_DMAC_CSR(pp, DCSR_INT_EN | DCSR_EN_CNT | DCSR_EN_DMA |
		    DCSR_CSR_DRAIN | DCSR_BURST_1 | DCSR_BURST_0 | DCSR_WRITE);
	} else {
		SET_DMAC_CSR(pp, DCSR_INT_EN | DCSR_EN_CNT | DCSR_EN_DMA |
		    DCSR_CSR_DRAIN | DCSR_BURST_1 | DCSR_BURST_0);
	}

	return (SUCCESS);
}

/*
 * Note: BCR is reset to 0, so counter should always be read before dma_stop
 */
static int
cheerio_dma_stop(struct ecppunit *pp, size_t *countp)
{
	uint8_t ecr;

	/* disable DMA and byte counter */
	AND_SET_LONG_R(pp->uh.ebus.d_handle, &pp->uh.ebus.dmac->csr,
	    ~(DCSR_EN_DMA | DCSR_EN_CNT| DCSR_INT_EN));

	/* ACK and disable the TC interrupt */
	OR_SET_LONG_R(pp->uh.ebus.d_handle, &pp->uh.ebus.dmac->csr,
	    DCSR_TC | DCSR_TCI_DIS);

	/* read DMA count if requested */
	if (countp) {
		*countp = cheerio_getcnt(pp);
	}

	cheerio_reset_dcsr(pp);
	SET_DMAC_BCR(pp, 0);

	/* turn off SuperIO's DMA */
	ecr = ECR_READ(pp);
	if (ecr_write(pp, ecr & ~ECPP_DMA_ENABLE) == FAILURE) {
		return (FAILURE);
	}

	/* Disable SuperIO interrupts and DMA */
	ecr = ECR_READ(pp);

	return (ecr_write(pp, ecr | ECPP_INTR_SRV));
}

static size_t
cheerio_getcnt(struct ecppunit *pp)
{
	return (GET_DMAC_BCR(pp));
}

/*
 * Reset the DCSR by first setting the RESET bit to 1.  Poll the
 * DCSR_CYC_PEND bit to make sure there are no more pending DMA cycles.
 * If there are no more pending cycles, clear the RESET bit.
 */
static void
cheerio_reset_dcsr(struct ecppunit *pp)
{
	int	timeout = DMAC_RESET_TIMEOUT;

	SET_DMAC_CSR(pp, DCSR_RESET);

	while (GET_DMAC_CSR(pp) & DCSR_CYC_PEND) {
		if (timeout == 0) {
			ecpp_error(pp->dip, "cheerio_reset_dcsr: timeout\n");
			break;
		} else {
			drv_usecwait(1);
			timeout--;
		}
	}

	SET_DMAC_CSR(pp, 0);
}

/*
 *
 * Grover Southbridge (M1553) support routines
 * Southbridge contains an Intel 8237 DMAC onboard which is used
 * to transport data to/from PCI space to superio parallel port
 *
 */


static int
m1553_map_regs(struct ecppunit *pp)
{
	if (ddi_regs_map_setup(pp->dip, 1, (caddr_t *)&pp->uh.m1553.isa_space,
	    0, sizeof (struct isaspace), &acc_attr,
	    &pp->uh.m1553.d_handle) != DDI_SUCCESS) {
		ecpp_error(pp->dip, "m1553_map_regs: failed isa space\n");
		goto fail;
	}

	if (ddi_regs_map_setup(pp->dip, 0, (caddr_t *)&pp->i_reg, 0,
	    sizeof (struct info_reg), &acc_attr, &pp->i_handle)
	    != DDI_SUCCESS) {
		ecpp_error(pp->dip, "m1553_map_regs: failed i_reg\n");
		goto fail;
	}

	if (ddi_regs_map_setup(pp->dip, 0, (caddr_t *)&pp->f_reg, 0x400,
	    sizeof (struct fifo_reg), &acc_attr, &pp->f_handle)
	    != DDI_SUCCESS) {
		ecpp_error(pp->dip, "m1553_map_regs: failed f_reg\n");
		goto fail;
	}

	return (SUCCESS);

fail:
	m1553_unmap_regs(pp);
	return (FAILURE);
}

static void
m1553_unmap_regs(struct ecppunit *pp)
{
	if (pp->uh.m1553.d_handle) {
		ddi_regs_map_free(&pp->uh.m1553.d_handle);
	}
	if (pp->i_handle) {
		ddi_regs_map_free(&pp->i_handle);
	}
	if (pp->f_handle) {
		ddi_regs_map_free(&pp->f_handle);
	}
}

#if defined(__x86)
static int
x86_map_regs(struct ecppunit *pp)
{
	int nregs = 0;

	if (ddi_regs_map_setup(pp->dip, 0, (caddr_t *)&pp->i_reg, 0,
	    sizeof (struct info_reg), &acc_attr, &pp->i_handle)
	    != DDI_SUCCESS) {
		ecpp_error(pp->dip, "x86_map_regs: failed i_reg\n");
		goto fail;
	}
	if (ddi_dev_nregs(pp->dip, &nregs) == DDI_SUCCESS && nregs == 2) {
		if (ddi_regs_map_setup(pp->dip, 1, (caddr_t *)&pp->f_reg, 0,
		    sizeof (struct fifo_reg), &acc_attr, &pp->f_handle)
		    != DDI_SUCCESS) {
			ecpp_error(pp->dip, "x86_map_regs: failed f_reg\n");
			goto fail;
		} else
			pp->noecpregs = FALSE;
	} else {
		pp->noecpregs = TRUE;
	}
	return (SUCCESS);
fail:
	x86_unmap_regs(pp);
	return (FAILURE);
}

static void
x86_unmap_regs(struct ecppunit *pp)
{
	if (pp->i_handle) {
		ddi_regs_map_free(&pp->i_handle);
	}
	if (pp->f_handle) {
		ddi_regs_map_free(&pp->f_handle);
	}
}
#endif

static uint8_t
m1553_read_config_reg(struct ecppunit *pp, uint8_t reg_num)
{
	uint8_t retval;

	dma8237_write(pp, 0x3F0, reg_num);
	retval = dma8237_read(pp, 0x3F1);

	return (retval);
}

static void
m1553_write_config_reg(struct ecppunit *pp, uint8_t reg_num, uint8_t val)
{
	dma8237_write(pp, 0x3F0, reg_num);
	dma8237_write(pp, 0x3F1, val);
}

static int
m1553_config_chip(struct ecppunit *pp)
{
	uint8_t conreg;

	/* Unlock configuration regs with "key sequence" */
	dma8237_write(pp, 0x3F0, 0x51);
	dma8237_write(pp, 0x3F0, 0x23);

	m1553_write_config_reg(pp, PnP_CONFIG_DEV_NO, 0x3);
	conreg = m1553_read_config_reg(pp, PnP_CONFIG_DEV_NO);
	ecpp_error(pp->dip, "M1553:conreg7(logical dev)=%x\n", conreg);

	conreg = m1553_read_config_reg(pp, PnP_CONFIG_ACTIVATE);
	ecpp_error(pp->dip, "M1553:conreg30(Active)=%x\n", conreg);

	conreg = m1553_read_config_reg(pp, PnP_CONFIG_BASE_ADDR_MSB);
	ecpp_error(pp->dip, "M1553:conreg60(addrHi)=%x\n", conreg);
	conreg = m1553_read_config_reg(pp, PnP_CONFIG_BASE_ADDR_LSB);
	ecpp_error(pp->dip, "M1553:conreg61(addrLo)=%x\n", conreg);

	conreg = m1553_read_config_reg(pp, PnP_CONFIG_INTR_SEL);
	ecpp_error(pp->dip, "M1553:conreg70(IRQL)=%x\n", conreg);

	conreg = m1553_read_config_reg(pp, PnP_CONFIG_DMA0_CHAN);
	ecpp_error(pp->dip, "M1553:conreg74(DMA0 Chan)=%x\n", conreg);

	/* set FIFO threshold 1 and ECP mode, preserve bit 7 (IRQ polarity) */
	conreg = m1553_read_config_reg(pp, PnP_CONFIG_PP_CONFIG0);
	conreg = (conreg & ~0x7F) | 0x0A;
	m1553_write_config_reg(pp, PnP_CONFIG_PP_CONFIG0, conreg);
	conreg = m1553_read_config_reg(pp, PnP_CONFIG_PP_CONFIG0);
	ecpp_error(pp->dip, "M1553:conregFO(pport conf)=%x\n", conreg);

	m1553_write_config_reg(pp, PnP_CONFIG_PP_CONFIG1, 0x04);
	conreg = m1553_read_config_reg(pp, PnP_CONFIG_PP_CONFIG1);
	ecpp_error(pp->dip, "M1553:conregF1(outconf)=%x\n", conreg);

	/* lock configuration regs with key */
	dma8237_write(pp, 0x3F0, 0xBB);

	/* Set ECR, DCR in known state */
	ECR_WRITE(pp, ECR_mode_001 | ECPP_INTR_MASK | ECPP_INTR_SRV);
	DCR_WRITE(pp, ECPP_SLCTIN | ECPP_nINIT);

	ecpp_error(pp->dip, "m1553_config_chip: ecr=%x, dsr=%x, dcr=%x\n",
	    ECR_READ(pp), DSR_READ(pp), DCR_READ(pp));

	return (SUCCESS);
}

#if defined(__x86)
static int
x86_config_chip(struct ecppunit *pp)
{
	if (ecr_write(pp, ECR_mode_001 |
	    ECPP_INTR_MASK | ECPP_INTR_SRV) == FAILURE) {
		ecpp_error(pp->dip, "config chip: failed w/ecr\n");
		pp->noecpregs = TRUE;
	}
	if (pp->noecpregs)
		pp->fast_compat = FALSE;
	DCR_WRITE(pp, ECPP_SLCTIN | ECPP_nINIT);
	ecpp_error(pp->dip, "x86_config_chip: ecr=%x, dsr=%x, dcr=%x\n",
	    ECR_READ(pp), DSR_READ(pp), DCR_READ(pp));
	return (SUCCESS);
}
#endif

/*
 * dma8237_dma_start() programs the selected 8 bit channel
 * of DMAC1 with the dma cookie.  pp->dma_cookie must
 * be set before this routine is called.
 */
static int
dma8237_dma_start(struct ecppunit *pp)
{
	uint8_t chn;

	chn = pp->uh.m1553.chn;

	ASSERT(chn <= DMAE_CH3 &&
	    pp->dma_cookie.dmac_size != 0 &&
	    pp->dma_cookie.dmac_address != 0);

	/* At this point Southbridge has not yet asserted DREQ */

	/* set mode to read-from-memory. */
	dma8237_write(pp, DMAC2_MODE, DMAMODE_CASC);
	if (pp->dma_dir == DDI_DMA_READ) {
		dma8237_write(pp, DMAC1_MODE, DMAMODE_SINGLE |
		    DMAMODE_READ | chn);
	} else {
		dma8237_write(pp, DMAC1_MODE, DMAMODE_SINGLE |
		    DMAMODE_WRITE | chn);
	}

	dma8237_write_addr(pp, pp->dma_cookie.dmac_address);
	dma8237_write_count(pp, pp->dma_cookie.dmac_size - 1);

	/*
	 * M1553 chip does not permit to access DMA register banks
	 * while DMA is in flight. As a result, ecpp and floppy drivers
	 * can potentially corrupt each other's DMA. The interlocking mechanism
	 * is provided by a parent nexus driver (isadma), which is enabled
	 * indirectly through a DMAC1_ALLMASK register access:
	 *
	 * writing a non-zero value to this register enters a lock,
	 * writing zero releases the lock.
	 *
	 * DMA transfer must only occur after entering a lock.
	 * If the lock is already owned by other driver, we will block.
	 *
	 * The following operation unmasks our channel and masks all others
	 */
	dma8237_write(pp, DMAC1_ALLMASK, ~(1 << chn));
	pp->uh.m1553.isadma_entered = 1;

	return (SUCCESS);
}

static int
dma8237_dma_stop(struct ecppunit *pp, size_t *countp)
{
	uint8_t ecr;

	/* stop DMA */
	ecr = (ECR_READ(pp) & 0xe0) | ECPP_INTR_MASK | ECPP_INTR_SRV;
	(void) ecr_write(pp, ecr);

	if (pp->uh.m1553.isadma_entered) {
		/* reset the channel mask so we can issue PIO's to our device */
		dma8237_write(pp, DMAC1_ALLMASK, 0);
		pp->uh.m1553.isadma_entered = 0;

	}

	/* read DMA count if requested */
	if (countp) {
		*countp = dma8237_getcnt(pp);
		if (pp->dma_dir == DDI_DMA_READ && *countp > 0) {
			(*countp)++;	/* need correction for reverse xfers */
		}
	}
	return (SUCCESS);
}
#if defined(__x86)
static int
x86_dma_start(struct ecppunit *pp)
{
	uint8_t chn;
	struct ddi_dmae_req dmaereq;

	chn = pp->uh.x86.chn;
	ASSERT(chn <= DMAE_CH3 &&
	    pp->dma_cookie.dmac_size != 0 &&
	    pp->dma_cookie.dmac_address != 0);
	bzero(&dmaereq, sizeof (struct ddi_dmae_req));
	dmaereq.der_command =
	    (pp->dma_dir & DDI_DMA_READ) ? DMAE_CMD_READ : DMAE_CMD_WRITE;
	if (ddi_dmae_prog(pp->dip, &dmaereq, &pp->dma_cookie, chn)
	    != DDI_SUCCESS)
		ecpp_error(pp->dip, "prog failed !!!\n");
	ecpp_error(pp->dip, "dma_started..\n");
	return (SUCCESS);
}

static int
x86_dma_stop(struct ecppunit *pp, size_t *countp)
{
	uint8_t ecr;

	/* stop DMA */
	if (pp->uh.x86.chn == 0xff)
		return (FAILURE);
	ecr = (ECR_READ(pp) & 0xe0) | ECPP_INTR_MASK | ECPP_INTR_SRV;
	(void) ecr_write(pp, ecr);
	ecpp_error(pp->dip, "dma_stop\n");

	/* read DMA count if requested */
	if (countp) {
		*countp = x86_getcnt(pp);
	}
	ecpp_error(pp->dip, "dma_stoped..\n");
	return (SUCCESS);
}
#endif

/* channel must be masked */
static void
dma8237_write_addr(struct ecppunit *pp, uint32_t addr)
{
	uint8_t c_addr, c_lpage;
	uint16_t c_hpage, *p;

	switch (pp->uh.m1553.chn) {
	case DMAE_CH0:
		c_addr = DMA_0ADR;
		c_lpage = DMA_0PAGE;
		c_hpage = DMA_0HPG;
		break;

	case DMAE_CH1:
		c_addr = DMA_1ADR;
		c_lpage = DMA_1PAGE;
		c_hpage = DMA_1HPG;
		break;

	case DMAE_CH2:
		c_addr = DMA_2ADR;
		c_lpage = DMA_2PAGE;
		c_hpage = DMA_2HPG;
		break;

	case DMAE_CH3:
		c_addr = DMA_3ADR;
		c_lpage = DMA_3PAGE;
		c_hpage = DMA_3HPG;
		break;

	default:
		return;
	}

	p = (uint16_t *)&pp->uh.m1553.isa_space->isa_reg[c_addr];
	ddi_put16(pp->uh.m1553.d_handle, p, addr & 0xFFFF);

	dma8237_write(pp, c_lpage, (addr & 0xFF0000) >> 16);
	dma8237_write(pp, c_hpage, (addr & 0xFF000000) >> 24);

}

/*
 * This function may be useful during debugging,
 * so we leave it in, but do not include in the binary
 */
#ifdef INCLUDE_DMA8237_READ_ADDR
static uint32_t
dma8237_read_addr(struct ecppunit *pp)
{
	uint8_t rval3, rval4;
	uint16_t rval16;
	uint32_t rval;
	uint8_t c_addr, c_lpage;
	uint16_t c_hpage, *p;

	switch (pp->uh.m1553.chn) {
	case DMAE_CH0:
		c_addr = DMA_0ADR;
		c_lpage = DMA_0PAGE;
		c_hpage = DMA_0HPG;
		break;

	case DMAE_CH1:
		c_addr = DMA_1ADR;
		c_lpage = DMA_1PAGE;
		c_hpage = DMA_1HPG;
		break;

	case DMAE_CH2:
		c_addr = DMA_2ADR;
		c_lpage = DMA_2PAGE;
		c_hpage = DMA_2HPG;
		break;

	case DMAE_CH3:
		c_addr = DMA_3ADR;
		c_lpage = DMA_3PAGE;
		c_hpage = DMA_3HPG;
		break;

	default:
		return (NULL);
	}

	p = (uint16_t *)&pp->uh.m1553.isa_space->isa_reg[c_addr];
	rval16 = ddi_get16(pp->uh.m1553.d_handle, p);

	rval3 = dma8237_read(pp, c_lpage);
	rval4 = dma8237_read(pp, c_hpage);

	rval = rval16 | (rval3 << 16) | (rval4 <<24);

	return (rval);
}
#endif

static void
dma8237_write_count(struct ecppunit *pp, uint32_t count)
{
	uint8_t c_wcnt;
	uint16_t *p;

	switch (pp->uh.m1553.chn) {
	case DMAE_CH0:
		c_wcnt = DMA_0WCNT;
		break;

	case DMAE_CH1:
		c_wcnt = DMA_1WCNT;
		break;

	case DMAE_CH2:
		c_wcnt = DMA_2WCNT;
		break;

	case DMAE_CH3:
		c_wcnt = DMA_3WCNT;
		break;

	default:
		return;
	}

	p = (uint16_t *)&pp->uh.m1553.isa_space->isa_reg[c_wcnt];
	ddi_put16(pp->uh.m1553.d_handle, p, count & 0xFFFF);

}

static uint32_t
dma8237_read_count(struct ecppunit *pp)
{
	uint8_t c_wcnt;
	uint16_t *p;

	switch (pp->uh.m1553.chn) {
	case DMAE_CH0:
		c_wcnt = DMA_0WCNT;
		break;

	case DMAE_CH1:
		c_wcnt = DMA_1WCNT;
		break;

	case DMAE_CH2:
		c_wcnt = DMA_2WCNT;
		break;

	case DMAE_CH3:
		c_wcnt = DMA_3WCNT;
		break;

	default:
		return (0);
	}

	p = (uint16_t *)&pp->uh.m1553.isa_space->isa_reg[c_wcnt];
	return (ddi_get16(pp->uh.m1553.d_handle, p));

}

static void
dma8237_write(struct ecppunit *pp, int reg_num, uint8_t val)
{
	ddi_put8(pp->uh.m1553.d_handle,
	    &pp->uh.m1553.isa_space->isa_reg[reg_num], val);
}

static uint8_t
dma8237_read(struct ecppunit *pp, int reg_num)
{
	return (ddi_get8(pp->uh.m1553.d_handle,
	    &pp->uh.m1553.isa_space->isa_reg[reg_num]));
}

static size_t
dma8237_getcnt(struct ecppunit *pp)
{
	uint32_t cnt;

	if ((cnt = dma8237_read_count(pp)) == 0xffff)
		cnt = 0;
	else
		cnt++;
	return (cnt);
}


/*
 *
 * Kstat support routines
 *
 */
static void
ecpp_kstat_init(struct ecppunit *pp)
{
	struct ecppkstat *ekp;
	char buf[16];

	/*
	 * Allocate, initialize and install interrupt counter kstat
	 */
	(void) sprintf(buf, "ecppc%d", pp->instance);
	pp->intrstats = kstat_create("ecpp", pp->instance, buf, "controller",
	    KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT);
	if (pp->intrstats == NULL) {
		ecpp_error(pp->dip, "ecpp_kstat_init:1: kstat_create failed");
	} else {
		pp->intrstats->ks_update = ecpp_kstatintr_update;
		pp->intrstats->ks_private = (void *) pp;
		kstat_install(pp->intrstats);
	}

	/*
	 * Allocate, initialize and install misc stats kstat
	 */
	pp->ksp = kstat_create("ecpp", pp->instance, NULL, "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (struct ecppkstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT);
	if (pp->ksp == NULL) {
		ecpp_error(pp->dip, "ecpp_kstat_init:2: kstat_create failed");
		return;
	}

	ekp = (struct ecppkstat *)pp->ksp->ks_data;

#define	EK_NAMED_INIT(name) \
	kstat_named_init(&ekp->ek_##name, #name, KSTAT_DATA_UINT32)

	EK_NAMED_INIT(ctx_obytes);
	EK_NAMED_INIT(ctxpio_obytes);
	EK_NAMED_INIT(nib_ibytes);
	EK_NAMED_INIT(ecp_obytes);
	EK_NAMED_INIT(ecp_ibytes);
	EK_NAMED_INIT(epp_obytes);
	EK_NAMED_INIT(epp_ibytes);
	EK_NAMED_INIT(diag_obytes);
	EK_NAMED_INIT(to_ctx);
	EK_NAMED_INIT(to_nib);
	EK_NAMED_INIT(to_ecp);
	EK_NAMED_INIT(to_epp);
	EK_NAMED_INIT(to_diag);
	EK_NAMED_INIT(xfer_tout);
	EK_NAMED_INIT(ctx_cf);
	EK_NAMED_INIT(joblen);
	EK_NAMED_INIT(isr_reattempt_high);
	EK_NAMED_INIT(mode);
	EK_NAMED_INIT(phase);
	EK_NAMED_INIT(backchan);
	EK_NAMED_INIT(iomode);
	EK_NAMED_INIT(state);

	pp->ksp->ks_update = ecpp_kstat_update;
	pp->ksp->ks_private = (void *) pp;
	kstat_install(pp->ksp);
}

static int
ecpp_kstat_update(kstat_t *ksp, int rw)
{
	struct ecppunit *pp;
	struct ecppkstat *ekp;

	/*
	 * For the time being there is no point
	 * in supporting writable kstats
	 */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	pp = (struct ecppunit *)ksp->ks_private;
	ekp = (struct ecppkstat *)ksp->ks_data;

	mutex_enter(&pp->umutex);

	ekp->ek_ctx_obytes.value.ui32	= pp->obytes[ECPP_CENTRONICS] +
	    pp->obytes[ECPP_COMPAT_MODE];
	ekp->ek_ctxpio_obytes.value.ui32 = pp->ctxpio_obytes;
	ekp->ek_nib_ibytes.value.ui32	= pp->ibytes[ECPP_NIBBLE_MODE];
	ekp->ek_ecp_obytes.value.ui32	= pp->obytes[ECPP_ECP_MODE];
	ekp->ek_ecp_ibytes.value.ui32	= pp->ibytes[ECPP_ECP_MODE];
	ekp->ek_epp_obytes.value.ui32	= pp->obytes[ECPP_EPP_MODE];
	ekp->ek_epp_ibytes.value.ui32	= pp->ibytes[ECPP_EPP_MODE];
	ekp->ek_diag_obytes.value.ui32	= pp->obytes[ECPP_DIAG_MODE];
	ekp->ek_to_ctx.value.ui32	= pp->to_mode[ECPP_CENTRONICS] +
	    pp->to_mode[ECPP_COMPAT_MODE];
	ekp->ek_to_nib.value.ui32	= pp->to_mode[ECPP_NIBBLE_MODE];
	ekp->ek_to_ecp.value.ui32	= pp->to_mode[ECPP_ECP_MODE];
	ekp->ek_to_epp.value.ui32	= pp->to_mode[ECPP_EPP_MODE];
	ekp->ek_to_diag.value.ui32	= pp->to_mode[ECPP_DIAG_MODE];
	ekp->ek_xfer_tout.value.ui32	= pp->xfer_tout;
	ekp->ek_ctx_cf.value.ui32	= pp->ctx_cf;
	ekp->ek_joblen.value.ui32	= pp->joblen;
	ekp->ek_isr_reattempt_high.value.ui32	= pp->isr_reattempt_high;
	ekp->ek_mode.value.ui32		= pp->current_mode;
	ekp->ek_phase.value.ui32	= pp->current_phase;
	ekp->ek_backchan.value.ui32	= pp->backchannel;
	ekp->ek_iomode.value.ui32	= pp->io_mode;
	ekp->ek_state.value.ui32	= pp->e_busy;

	mutex_exit(&pp->umutex);

	return (0);
}

static int
ecpp_kstatintr_update(kstat_t *ksp, int rw)
{
	struct ecppunit *pp;

	/*
	 * For the time being there is no point
	 * in supporting writable kstats
	 */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	pp = (struct ecppunit *)ksp->ks_private;

	mutex_enter(&pp->umutex);

	KSTAT_INTR_PTR(ksp)->intrs[KSTAT_INTR_HARD] = pp->intr_hard;
	KSTAT_INTR_PTR(ksp)->intrs[KSTAT_INTR_SPURIOUS] = pp->intr_spurious;
	KSTAT_INTR_PTR(ksp)->intrs[KSTAT_INTR_SOFT] = pp->intr_soft;

	mutex_exit(&pp->umutex);

	return (0);
}
