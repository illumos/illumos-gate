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
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 * socal - Serial Optical Channel Arbitrated Loop host adapter driver.
 */

#include <sys/types.h>
#include <sys/note.h>
#include <sys/devops.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/fcntl.h>

#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/kmem.h>

#include <sys/errno.h>
#include <sys/open.h>
#include <sys/varargs.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/debug.h>
#include <sys/cpu.h>
#include <sys/autoconf.h>
#include <sys/conf.h>
#include <sys/stat.h>

#include <sys/file.h>
#include <sys/syslog.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ksynch.h>
#include <sys/ddidmareq.h>
#include <sys/dditypes.h>
#include <sys/ethernet.h>
#include <sys/socalreg.h>
#include <sys/socalmap.h>
#include <sys/fc4/fcal.h>
#include <sys/socal_cq_defs.h>
#include <sys/fc4/fcal_linkapp.h>
#include <sys/fc4/fcal_transport.h>
#include <sys/socalio.h>
#include <sys/socalvar.h>

/*
 * Local Macros
 */

#ifdef DEBUG
#define	SOCAL_DEBUG 1
#else
#define	SOCAL_DEBUG 0
#endif
static uchar_t	socal_xrambuf[0x40000];
static int	socal_core = SOCAL_TAKE_CORE;
#if SOCAL_DEBUG > 0 && !defined(lint)
static	int soc_debug = SOCAL_DEBUG;
static  int socal_read_stale_data = 0;
#define	DEBUGF(level, args) \
	if (soc_debug >= (level)) cmn_err args;
#define	SOCALDEBUG(level, args) \
	if (soc_debug >= level) args;
#else
#define	DEBUGF(level, args)	/* Nothing */
#define	SOCALDEBUG(level, args)	/* Nothing */
#endif


/* defines for properties */
#define	SOCAL_PORT_NO_PROP		"socal_port"
#define	SOCAL_ALT_PORT_NO_PROP		"port#"

/* for socal_force_reset() */
#define	RESET_PORT			1
#define	DONT_RESET_PORT			0

/*
 * Driver Entry points.
 */
static int socal_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int socal_bus_ctl(dev_info_t *dip, dev_info_t *rip,
	ddi_ctl_enum_t op, void *a, void *v);
static int socal_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int socal_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result);
static unsigned int socal_intr(caddr_t arg);
static unsigned int socal_dummy_intr(caddr_t arg);
static int socal_open(dev_t *devp, int flag, int otyp,
	cred_t *cred_p);
static int socal_close(dev_t dev, int flag, int otyp,
	cred_t *cred_p);
static int socal_ioctl(dev_t dev, int cmd, intptr_t arg,
	int mode, cred_t *cred_p, int *rval_p);

/*
 * FC_AL transport functions.
 */
static uint_t socal_transport(fcal_packet_t *, fcal_sleep_t, int);
static uint_t socal_transport_poll(fcal_packet_t *, uint_t, int);
static uint_t socal_lilp_map(void *, uint_t, uint32_t, uint_t);
static uint_t socal_force_lip(void *, uint_t, uint_t, uint_t);
static uint_t socal_force_offline(void *, uint_t, uint_t);
static uint_t socal_abort_cmd(void *, uint_t, fcal_packet_t *, uint_t);
static uint_t socal_doit(fcal_packet_t *, socal_port_t *, int,
    void (*)(), int, int, uint_t *);
static uint_t socal_els(void *, uint_t, uint_t, uint_t,
	void (*callback)(), void *, caddr_t, caddr_t *, uint_t);
static uint_t socal_bypass_dev(void *, uint_t, uint_t);
static void socal_force_reset(void *, uint_t, uint_t);
static void socal_add_ulp(void *, uint_t, uchar_t, void (*)(),
	void (*)(), void (*)(), void *);
static void socal_remove_ulp(void *, uint_t, uchar_t, void *);
static void socal_take_core(void *);

/*
 * Driver internal functions.
 */
static void socal_intr_solicited(socal_state_t *, uint32_t srq);
static void socal_intr_unsolicited(socal_state_t *, uint32_t urq);
static void socal_lilp_map_done(fcal_packet_t *);
static void socal_force_lip_done(fcal_packet_t *);
static void socal_force_offline_done(fcal_packet_t *);
static void socal_abort_done(fcal_packet_t *);
static void socal_bypass_dev_done(fcal_packet_t *);
static fcal_packet_t *socal_packet_alloc(socal_state_t *, fcal_sleep_t);
static void socal_packet_free(fcal_packet_t *);
static void socal_disable(socal_state_t *socalp);
static void socal_init_transport_interface(socal_state_t *socalp);
static int socal_cqalloc_init(socal_state_t *socalp, uint32_t index);
static void socal_cqinit(socal_state_t *socalp, uint32_t index);
static int socal_start(socal_state_t *socalp);
static void socal_doreset(socal_state_t *socalp);
static int socal_dodetach(dev_info_t *dip);
static int socal_diag_request(socal_state_t *socalp, uint32_t port,
	uint_t *diagcode, uint32_t cmd);
static void socal_download_ucode(socal_state_t *socalp);
static void socal_init_cq_desc(socal_state_t *socalp);
static void socal_init_wwn(socal_state_t *socalp);
static void socal_enable(socal_state_t *socalp);
static int socal_establish_pool(socal_state_t *socalp, uint32_t poolid);
static int socal_add_pool_buffer(socal_state_t *socalp, uint32_t poolid);
static int socal_issue_adisc(socal_state_t *socalp, uint32_t port, uint32_t
	dest, la_els_adisc_t *adisc_pl, uint32_t polled);
static int socal_issue_lbf(socal_state_t *socalp, uint32_t port,
	uchar_t *flb_pl, size_t length, uint32_t polled);
static int socal_issue_rls(socal_state_t *socalp, uint32_t port, uint32_t
	dest, la_els_rls_reply_t *rls_pl, uint32_t polled);
static void socal_us_els(socal_state_t *, cqe_t *, caddr_t);
static fcal_packet_t *socal_els_alloc(socal_state_t *, uint32_t, uint32_t,
	uint32_t, uint32_t, caddr_t *, uint32_t);
static fcal_packet_t *socal_lbf_alloc(socal_state_t *, uint32_t,
	uint32_t, uint32_t, caddr_t *, uint32_t);
static void socal_els_free(socal_priv_cmd_t *);
static void socal_lbf_free(socal_priv_cmd_t *);
static int socal_getmap(socal_state_t *socalp, uint32_t port, caddr_t arg,
	uint32_t polled, int);
static void socal_flush_overflowq(socal_state_t *, int, int);
static void socal_deferred_intr(void *);
static void socal_fix_harda(socal_state_t *socalp, int port);

/*
 * SOC+ Circular Queue Management routines.
 */
static int socal_cq_enque(socal_state_t *, socal_port_t *, cqe_t *, int,
	fcal_sleep_t, fcal_packet_t *, int);

/*
 * Utility functions
 */
static void socal_disp_err(socal_state_t *, uint_t level, char *mid, char *msg);
static void socal_wcopy(uint_t *, uint_t *, int);

/*
 *  Set this bit to enable 64-bit sus mode
 */
static	int socal_64bitsbus = 1;

/*
 * Default soc dma limits
 */

static ddi_dma_lim_t default_socallim = {
	(ulong_t)0, (ulong_t)0xffffffff, (uint_t)0xffffffff,
	DEFAULT_BURSTSIZE | BURST32 | BURST64, 1, (25*1024)
};

static struct ddi_dma_attr socal_dma_attr = {
	DMA_ATTR_V0,			/* version */
	(unsigned long long)0,		/* addr_lo */
	(unsigned long long)0xffffffff,	/* addr_hi */
	(unsigned long long)0xffffffff,	/* count max */
	(unsigned long long)4,		/* align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* burst size */
	1,				/* minxfer */
	(unsigned long long)0xffffffff,	/* maxxfer */
	(unsigned long long)0xffffffff,	/* seg */
	1,				/* sgllen */
	4,				/* granularity */
	0				/* flags */
};

static struct ddi_device_acc_attr socal_acc_attr = {
	(ushort_t)DDI_DEVICE_ATTR_V0,	/* version */
	(uchar_t)DDI_STRUCTURE_BE_ACC,	/* endian flags */
	(uchar_t)DDI_STRICTORDER_ACC	/* data order */
};

static struct fcal_transport_ops socal_transport_ops = {
	socal_transport,
	socal_transport_poll,
	socal_lilp_map,
	socal_force_lip,
	socal_abort_cmd,
	socal_els,
	socal_bypass_dev,
	socal_force_reset,
	socal_add_ulp,
	socal_remove_ulp,
	socal_take_core
};

/*
 * Table used for setting the burst size in the soc+ config register
 */
static int socal_burst32_table[] = {
	SOCAL_CR_BURST_4,
	SOCAL_CR_BURST_4,
	SOCAL_CR_BURST_4,
	SOCAL_CR_BURST_4,
	SOCAL_CR_BURST_16,
	SOCAL_CR_BURST_32,
	SOCAL_CR_BURST_64
};

/*
 * Table for setting the burst size for 64-bit sbus mode in soc+'s CR
 */
static int socal_burst64_table[] = {
	(SOCAL_CR_BURST_8 << 8),
	(SOCAL_CR_BURST_8 << 8),
	(SOCAL_CR_BURST_8 << 8),
	(SOCAL_CR_BURST_8 << 8),
	(SOCAL_CR_BURST_8 << 8),
	(SOCAL_CR_BURST_32 << 8),
	(SOCAL_CR_BURST_64 << 8),
	(SOCAL_CR_BURST_128 << 8)
};

/*
 * Tables used to define the sizes of the Circular Queues
 *
 * To conserve DVMA/IOPB space, we make some of these queues small...
 */
static int socal_req_entries[] = {
	SOCAL_SMALL_CQ_ENTRIES,		/* Error (reset, lip) requests */
	SOCAL_MAX_CQ_ENTRIES,		/* Most commands */
	0,				/* Not currently used */
	0				/* Not currently used */
};

static int socal_rsp_entries[] = {
	SOCAL_MAX_CQ_ENTRIES,		/* Solicited  "SOC_OK" responses */
	SOCAL_SMALL_CQ_ENTRIES,		/* Solicited error responses */
	0,			/* Unsolicited responses */
	0				/* Not currently used */
};

/*
 * Bus ops vector
 */

static struct bus_ops socal_bus_ops = {
	BUSO_REV,		/* rev */
	nullbusmap,		/* int (*bus_map)() */
	0,			/* ddi_intrspec_t (*bus_get_intrspec)(); */
	0,			/* int (*bus_add_intrspec)(); */
	0,			/* void	(*bus_remove_intrspec)(); */
	i_ddi_map_fault,	/* int (*bus_map_fault)() */
	0,			/* int (*bus_dma_map)() */
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,		/* int (*bus_dma_ctl)() */
	socal_bus_ctl,		/* int (*bus_ctl)() */
	ddi_bus_prop_op,	/* int (*bus_prop_op*)() */
};

static struct cb_ops socal_cb_ops = {
	socal_open,		/* int (*cb_open)() */
	socal_close,		/* int (*cb_close)() */
	nodev,			/* int (*cb_strategy)() */
	nodev,			/* int (*cb_print)() */
	nodev,			/* int (*cb_dump)() */
	nodev,			/* int (*cb_read)() */
	nodev,			/* int (*cb_write)() */
	socal_ioctl,		/* int (*cb_ioctl)() */
	nodev,			/* int (*cb_devmap)() */
	nodev,			/* int (*cb_mmap)() */
	nodev,			/* int (*cb_segmap)() */
	nochpoll,		/* int (*cb_chpoll)() */
	ddi_prop_op,		/* int (*cb_prop_op)() */
	0,			/* struct streamtab *cb_str */
	D_MP|D_NEW|D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

/*
 * Soc driver ops structure.
 */

static struct dev_ops socal_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt */
	socal_getinfo,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	socal_attach,		/* attach */
	socal_detach,		/* detach */
	nodev,			/* reset */
	&socal_cb_ops,		/* driver operations */
	&socal_bus_ops,		/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* quiesce */
};

/*
 * Driver private variables.
 */

static void *socal_soft_state_p = NULL;
static ddi_dma_lim_t *socallim = NULL;

static uchar_t socal_switch_to_alpa[] = {
	0xef, 0xe8, 0xe4, 0xe2, 0xe1, 0xe0, 0xdc, 0xda, 0xd9, 0xd6,
	0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xce, 0xcd, 0xcc, 0xcb, 0xca,
	0xc9, 0xc7, 0xc6, 0xc5, 0xc3, 0xbc, 0xba, 0xb9, 0xb6, 0xb5,
	0xb4, 0xb3, 0xb2, 0xb1, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9,
	0xa7, 0xa6, 0xa5, 0xa3, 0x9f, 0x9e, 0x9d, 0x9b, 0x98, 0x97,
	0x90, 0x8f, 0x88, 0x84, 0x82, 0x81, 0x80, 0x7c, 0x7a, 0x79,
	0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x6e, 0x6d, 0x6c, 0x6b,
	0x6a, 0x69, 0x67, 0x66, 0x65, 0x63, 0x5c, 0x5a, 0x59, 0x56,
	0x55, 0x54, 0x53, 0x52, 0x51, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a,
	0x49, 0x47, 0x46, 0x45, 0x43, 0x3c, 0x3a, 0x39, 0x36, 0x35,
	0x34, 0x33, 0x32, 0x31, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29,
	0x27, 0x26, 0x25, 0x23, 0x1f, 0x1e, 0x1d, 0x1b, 0x18, 0x17,
	0x10, 0x0f, 0x08, 0x04, 0x02, 0x01, 0x00
};

/*
 * Firmware related externs
 */
extern uint32_t socal_ucode[];
extern size_t socal_ucode_size;

/*
 * This is the loadable module wrapper: "module configuration section".
 */

#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

/*
 * Module linkage information for the kernel.
 */
#define	SOCAL_NAME "SOC+ FC-AL Host Adapter Driver"
static	char	socal_version[] = "1.62 08/19/2008";
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	SOCAL_NAME,
	&socal_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * This is the module initialization/completion routines
 */

#if !defined(lint)
static char socal_initmsg[] = "socal _init: socal.c\t1.62\t08/19/2008\n";
#endif

int
_init(void)
{
	int stat;

	DEBUGF(4, (CE_CONT, socal_initmsg));

	/* Allocate soft state.  */
	stat = ddi_soft_state_init(&socal_soft_state_p,
	    sizeof (socal_state_t), SOCAL_INIT_ITEMS);
	if (stat != 0)
		return (stat);

	/* Install the module */
	stat = mod_install(&modlinkage);
	if (stat != 0)
		ddi_soft_state_fini(&socal_soft_state_p);

	DEBUGF(4, (CE_CONT, "socal: _init: return=%d\n", stat));
	return (stat);
}

int
_fini(void)
{
	int stat;

	if ((stat = mod_remove(&modlinkage)) != 0)
		return (stat);

	DEBUGF(4, (CE_CONT, "socal: _fini: \n"));

	ddi_soft_state_fini(&socal_soft_state_p);

	DEBUGF(4, (CE_CONT, "socal: _fini: return=%d\n", stat));
	return (stat);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


int
socal_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	socal_state_t		*socalp;
	struct ether_addr	ourmacaddr;
	socal_port_t		*porta, *portb;
	char			buf[MAXPATHLEN];
	char			*cptr, *wwn;
	int			y;
	int			i, j;
	int			burstsize;
	short			s;
	int			loop_id;

	int			rval;


	instance = ddi_get_instance(dip);

	DEBUGF(4, (CE_CONT, "socal%d entering attach: cmd=%x\n", instance,
	    cmd));

	if (cmd == DDI_RESUME) {
		if ((socalp = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		if (!socalp->socal_shutdown) {
			/* our work is already done */
			return (DDI_SUCCESS);
		}
		if (socal_start(socalp) != FCAL_SUCCESS) {
			return	(DDI_FAILURE);
		}
		DEBUGF(4, (CE_CONT, "socal%d resumed\n", instance));
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_dev_is_sid(dip) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "socal%d probe: Not self-identifying",
		    instance);
		return (DDI_FAILURE);
	}

	/* If we are in a slave-slot, then we can't be used. */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "socal%d attach failed: device in slave-only slot",
		    instance);
		return (DDI_FAILURE);
	}

	if (ddi_intr_hilevel(dip, 0)) {
		/*
		 * Interrupt number '0' is a high-level interrupt.
		 * At this point you either add a special interrupt
		 * handler that triggers a soft interrupt at a lower level,
		 * or - more simply and appropriately here - you just
		 * fail the attach.
		 */
		cmn_err(CE_WARN,
		"socal%d attach failed: hilevel interrupt unsupported",
		    instance);
		return (DDI_FAILURE);
	}

	/* Allocate soft state. */
	if (ddi_soft_state_zalloc(socal_soft_state_p, instance)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "socal%d attach failed: alloc soft state",
		    instance);
		return (DDI_FAILURE);
	}
	DEBUGF(4, (CE_CONT, "socal%d attach: allocated soft state\n",
	    instance));

	/*
	 * Initialize the state structure.
	 */
	socalp = ddi_get_soft_state(socal_soft_state_p, instance);
	if (socalp == (socal_state_t *)NULL) {
		cmn_err(CE_WARN, "socal%d attach failed: bad soft state",
		    instance);
		return (DDI_FAILURE);
	}
	DEBUGF(4, (CE_CONT, "socal%d: attach: soc soft state ptr=0x%p\n",
	    instance, socalp));

	socalp->dip = dip;
	socallim = &default_socallim;
	porta = &socalp->port_state[0];
	portb = &socalp->port_state[1];

	/* Get the full path name for displaying error messages */
	cptr = ddi_pathname(dip, buf);
	(void) strcpy(socalp->socal_name, cptr);

	porta->sp_unsol_cb = NULL;
	portb->sp_unsol_cb = NULL;
	porta->sp_port = 0;
	portb->sp_port = 1;
	porta->sp_board = socalp;
	portb->sp_board = socalp;

	porta->sp_lilpmap_valid = 0;
	portb->sp_lilpmap_valid = 0;

	/*
	 * If an hard loop-id property is present, then the port is going
	 * to be used in target-mode so set the target-mode flag.
	 */
	loop_id = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "port0-loop-id", 127);
	if (loop_id >= 0 && loop_id <= 126) {
		porta->sp_status |= PORT_TARGET_MODE;
		porta->sp_hard_alpa = socal_switch_to_alpa[loop_id];
	} else porta->sp_hard_alpa = 0xfe;

	loop_id = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "port1-loop-id", 127);
	if (loop_id >= 0 && loop_id <= 126) {
		portb->sp_status |= PORT_TARGET_MODE;
		portb->sp_hard_alpa = socal_switch_to_alpa[loop_id];
	} else portb->sp_hard_alpa = 0xfe;

	/* Get out Node wwn and calculate port wwns */
	rval = ddi_prop_op(DDI_DEV_T_ANY, dip,
	    PROP_LEN_AND_VAL_ALLOC, DDI_PROP_DONTPASS |
	    DDI_PROP_CANSLEEP, "wwn", (caddr_t)&wwn, &i);

	if ((rval != DDI_PROP_SUCCESS) || (i < FC_WWN_SIZE) ||
	    (bcmp(wwn, "00000000", FC_WWN_SIZE) == 0)) {
		(void) localetheraddr((struct ether_addr *)NULL, &ourmacaddr);

		bcopy((caddr_t)&ourmacaddr, (caddr_t)&s, sizeof (short));
		socalp->socal_n_wwn.w.wwn_hi = s;
		bcopy((caddr_t)&ourmacaddr+2,
		    (caddr_t)&socalp->socal_n_wwn.w.wwn_lo,
		    sizeof (uint_t));
		socalp->socal_n_wwn.w.naa_id = NAA_ID_IEEE;
		socalp->socal_n_wwn.w.nport_id = 0;
	} else {
		bcopy((caddr_t)wwn, (caddr_t)&socalp->socal_n_wwn, FC_WWN_SIZE);
	}

	if (rval == DDI_SUCCESS)
		kmem_free((void *)wwn, i);

	for (i = 0; i < FC_WWN_SIZE; i++) {
		(void) sprintf(&socalp->socal_stats.node_wwn[i << 1],
		    "%02x", socalp->socal_n_wwn.raw_wwn[i]);
	}
	DEBUGF(4, (CE_CONT, "socal%d attach: node wwn: %s\n",
	    instance, socalp->socal_stats.node_wwn));

	bcopy((caddr_t)&socalp->socal_n_wwn, (caddr_t)&porta->sp_p_wwn,
	    sizeof (la_wwn_t));
	bcopy((caddr_t)&socalp->socal_n_wwn, (caddr_t)&portb->sp_p_wwn,
	    sizeof (la_wwn_t));
	porta->sp_p_wwn.w.naa_id = NAA_ID_IEEE_EXTENDED;
	portb->sp_p_wwn.w.naa_id = NAA_ID_IEEE_EXTENDED;
	porta->sp_p_wwn.w.nport_id = instance*2;
	portb->sp_p_wwn.w.nport_id = instance*2+1;

	for (i = 0; i < FC_WWN_SIZE; i++) {
		(void) sprintf(&socalp->socal_stats.port_wwn[0][i << 1],
		    "%02x", porta->sp_p_wwn.raw_wwn[i]);
		(void) sprintf(&socalp->socal_stats.port_wwn[1][i << 1],
		    "%02x", portb->sp_p_wwn.raw_wwn[i]);
	}
	DEBUGF(4, (CE_CONT, "socal%d attach: porta wwn: %s\n",
	    instance, socalp->socal_stats.port_wwn[0]));
	DEBUGF(4, (CE_CONT, "socal%d attach: portb wwn: %s\n",
	    instance, socalp->socal_stats.port_wwn[1]));

	if ((porta->sp_transport = (fcal_transport_t *)
	    kmem_zalloc(sizeof (fcal_transport_t), KM_SLEEP)) == NULL) {
		socal_disp_err(socalp, CE_WARN, "attach.4011",
		    "attach failed: unable to alloc xport struct");
		goto fail;
	}

	if ((portb->sp_transport = (fcal_transport_t *)
	    kmem_zalloc(sizeof (fcal_transport_t), KM_SLEEP)) == NULL) {
		socal_disp_err(socalp, CE_WARN, "attach.4012",
		    "attach failed: unable to alloc xport struct");
		goto fail;
	}
	DEBUGF(4, (CE_CONT, "socal%d attach: allocated transport structs\n",
	    instance));

	/*
	 * Map the external ram and registers for SOC+.
	 * Note: Soc+ sbus host adapter provides 3 register definition
	 * but on-board Soc+'s  may have only one register definition.
	 */
	if ((ddi_dev_nregs(dip, &i) == DDI_SUCCESS) && (i == 1)) {
		/* Map XRAM */
		if (ddi_map_regs(dip, 0, &socalp->socal_xrp, 0, 0)
		    != DDI_SUCCESS) {
			socalp->socal_xrp = NULL;
			socal_disp_err(socalp, CE_WARN, "attach.4020",
			    "attach failed: unable to map XRAM");
			goto fail;
		}
		/* Map registers */
		socalp->socal_rp = (socal_reg_t *)(socalp->socal_xrp +
		    SOCAL_XRAM_SIZE);
	} else {
		/* Map EEPROM */
		if (ddi_map_regs(dip, 0, &socalp->socal_eeprom, 0, 0) !=
		    DDI_SUCCESS) {
			socalp->socal_eeprom = NULL;
			socal_disp_err(socalp, CE_WARN, "attach.4010",
			    "attach failed: unable to map eeprom");
			goto fail;
		}
	DEBUGF(4, (CE_CONT, "socal%d attach: mapped eeprom 0x%p\n",
	    instance, socalp->socal_eeprom));
		/* Map XRAM */
		if (ddi_map_regs(dip, 1, &socalp->socal_xrp, 0, 0) !=
		    DDI_SUCCESS) {
			socalp->socal_xrp = NULL;
			socal_disp_err(socalp, CE_WARN, "attach.4020",
			    "attach failed: unable to map XRAM");
			goto fail;
		}
	DEBUGF(4, (CE_CONT, "socal%d attach: mapped xram 0x%p\n",
	    instance, socalp->socal_xrp));
		/* Map registers */
		if (ddi_map_regs(dip, 2, (caddr_t *)&socalp->socal_rp, 0, 0) !=
		    DDI_SUCCESS) {
			socalp->socal_rp = NULL;
			socal_disp_err(socalp, CE_WARN, "attach.4030",
			    "attach failed: unable to map registers");
			goto fail;
		}
	DEBUGF(4, (CE_CONT, "socal%d attach: mapped regs 0x%p\n",
	    instance, socalp->socal_rp));
	}
	/*
	 * Check to see we really have a SOC+ Host Adapter card installed
	 */
	if (ddi_peek32(dip, (int32_t *)&socalp->socal_rp->socal_csr.w,
	    (int32_t *)NULL) != DDI_SUCCESS) {
		socal_disp_err(socalp, CE_WARN, "attach.4040",
		    "attach failed: unable to access status register");
		goto fail;
	}
	/* now that we have our registers mapped make sure soc+ reset */
	socal_disable(socalp);

	/* try defacing a spot in XRAM */
	if (ddi_poke32(dip, (int32_t *)(socalp->socal_xrp + SOCAL_XRAM_UCODE),
	    0xdefaced) != DDI_SUCCESS) {
		socal_disp_err(socalp, CE_WARN, "attach.4050",
		    "attach failed: unable to write host adapter XRAM");
		goto fail;
	}

	/* see if it stayed defaced */
	if (ddi_peek32(dip, (int32_t *)(socalp->socal_xrp + SOCAL_XRAM_UCODE),
	    (int32_t *)&y)
	    != DDI_SUCCESS) {
		socal_disp_err(socalp, CE_WARN, "attach.4051",
		    "attach failed: unable to access host adapter XRAM");
		goto fail;
	}

#ifdef DEBUG
	for (i = 0; i < 4; i++) {
		socalp->socal_rp->socal_cr.w &=
		    ~SOCAL_CR_EXTERNAL_RAM_BANK_MASK;
		socalp->socal_rp->socal_cr.w |= i<<24;
		cptr = (char *)(socal_xrambuf + (i*0x10000));
		bcopy((caddr_t)socalp->socal_xrp, (caddr_t)cptr, 0x10000);
	}
	socalp->socal_rp->socal_cr.w &= ~SOCAL_CR_EXTERNAL_RAM_BANK_MASK;
#endif

	DEBUGF(4, (CE_CONT, "socal%d attach: read xram\n", instance));

	if (y != 0xdefaced) {
		socal_disp_err(socalp, CE_WARN, "attach.4052",
		    "attach failed: read/write mismatch in XRAM");
		goto fail;
	}

	/* Point to the SOC XRAM CQ Descriptor locations. */
	socalp->xram_reqp = (soc_cq_t *)(socalp->socal_xrp +
	    SOCAL_XRAM_REQ_DESC);
	socalp->xram_rspp = (soc_cq_t *)(socalp->socal_xrp +
	    SOCAL_XRAM_RSP_DESC);

	if ((socalp->socal_ksp = kstat_create("socal", instance, "statistics",
	    "controller", KSTAT_TYPE_RAW, sizeof (struct socal_stats),
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		socal_disp_err(socalp, CE_WARN, "attach.4053",
		    "unable to create kstats");
	} else {
		socalp->socal_stats.version = 2;
		(void) sprintf(socalp->socal_stats.drvr_name,
		    "%s: %s", SOCAL_NAME, socal_version);
		socalp->socal_stats.pstats[0].port = 0;
		socalp->socal_stats.pstats[1].port = 1;
		socalp->socal_ksp->ks_data = (void *)&socalp->socal_stats;
		kstat_install(socalp->socal_ksp);
	}

	/*
	 * Install a dummy interrupt routine.
	 */
	if (ddi_add_intr(dip,
	    (uint_t)0,
	    &socalp->iblkc,
	    &socalp->idevc,
	    socal_dummy_intr,
	    (caddr_t)socalp) != DDI_SUCCESS) {
			socal_disp_err(socalp, CE_WARN, "attach.4060",
			"attach failed: unable to install interrupt handler");
			goto fail;
	}

	ddi_set_driver_private(dip, socalp);

	/* initialize the interrupt mutex */
	mutex_init(&socalp->k_imr_mtx, NULL, MUTEX_DRIVER,
	    (void *)socalp->iblkc);

	mutex_init(&socalp->board_mtx, NULL, MUTEX_DRIVER,
	    (void *)socalp->iblkc);
	mutex_init(&socalp->ioctl_mtx, NULL, MUTEX_DRIVER,
	    (void *)socalp->iblkc);

	/* initialize the abort mutex */
	mutex_init(&socalp->abort_mtx, NULL, MUTEX_DRIVER,
	    (void *)socalp->iblkc);

	cv_init(&socalp->board_cv, NULL, CV_DRIVER, NULL);
	DEBUGF(4, (CE_CONT,
	    "socal%d: attach: inited imr mutex, board mutex, board cv\n",
	    instance));

	/* init the port mutexes */
	mutex_init(&porta->sp_mtx, NULL, MUTEX_DRIVER, socalp->iblkc);
	cv_init(&porta->sp_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&portb->sp_mtx, NULL, MUTEX_DRIVER, socalp->iblkc);
	cv_init(&portb->sp_cv, NULL, CV_DRIVER, NULL);
	DEBUGF(4, (CE_CONT, "socal%d: attach: inited port mutexes and cvs\n",
	    instance));

	/* get local copy of service params */
	socal_wcopy((uint_t *)socalp->socal_xrp + SOCAL_XRAM_SERV_PARAMS,
	    (uint_t *)socalp->socal_service_params, SOCAL_SVC_LENGTH);
	DEBUGF(4, (CE_CONT, "socal%d: attach: got service params\n", instance));
	/*
	 * Initailize the FCAL transport interface.
	 */
	socal_init_transport_interface(socalp);
	DEBUGF(4, (CE_CONT, "socal%d: attach: initalized transport interface\n",
	    instance));

	/*
	 * Allocate request and response queues and init their mutexs.
	 */
	for (i = 0; i < SOCAL_N_CQS; i++) {
		if (socal_cqalloc_init(socalp, i) != FCAL_SUCCESS) {
			goto fail;
		}
	}
	DEBUGF(4, (CE_CONT, "socal%d: attach: allocated cqs\n", instance));

	/*
	 * Adjust the burst size we'll use.
	 */
	burstsize = ddi_dma_burstsizes(socalp->request[0].skc_dhandle);
	DEBUGF(4, (CE_CONT, "socal%d: attach: burstsize = 0x%x\n",
	    instance, burstsize));
	j = burstsize & BURSTSIZE_MASK;
	for (i = 0; socal_burst32_table[i] != SOCAL_CR_BURST_64; i++)
		if (!(j >>= 1)) break;

	socalp->socal_cfg = (socalp->socal_cfg & ~SOCAL_CR_SBUS_BURST_SIZE_MASK)
	    | socal_burst32_table[i];

	if (socal_64bitsbus) {
		if (ddi_dma_set_sbus64(socalp->request[0].skc_dhandle,
		    socal_dma_attr.dma_attr_burstsizes | BURST128) ==
		    DDI_SUCCESS) {
			DEBUGF(4, (CE_CONT, "socal%d: enabled 64 bit sbus\n",
			    instance));
			socalp->socal_cfg |= SOCAL_CR_SBUS_ENHANCED;
			burstsize = ddi_dma_burstsizes(socalp->request[0].
			    skc_dhandle);
		DEBUGF(4, (CE_CONT, "socal%d: attach: 64bit burstsize = 0x%x\n",
		    instance, burstsize));
			j = burstsize & BURSTSIZE_MASK;
			for (i = 0; socal_burst64_table[i] !=
			    (SOCAL_CR_BURST_128 << 8); i++)
				if (!(j >>= 1))
					break;

			socalp->socal_cfg = (socalp->socal_cfg &
			    ~SOCAL_CR_SBUS_BURST_SIZE_64BIT_MASK) |
			    socal_burst64_table[i];
		}
	}

	ddi_remove_intr(dip, 0, socalp->iblkc);
	socalp->iblkc = (void *)NULL;
	/*
	 * Install the interrupt routine.
	 */
	if (ddi_add_intr(dip,
	    (uint_t)0,
	    &socalp->iblkc,
	    &socalp->idevc,
	    socal_intr,
	    (caddr_t)socalp) != DDI_SUCCESS) {
			socal_disp_err(socalp, CE_WARN, "attach.4060",
			"attach failed: unable to install interrupt handler");
			goto fail;
	}

	DEBUGF(4, (CE_CONT, "socal%d: attach: set config reg %x\n",
	    instance, socalp->socal_cfg));

	if (ddi_create_minor_node(dip, SOCAL_PORTA_NAME, S_IFCHR,
	    instance*N_SOCAL_NPORTS, SOCAL_NT_PORT, 0) != DDI_SUCCESS)
		goto fail;
	if (ddi_create_minor_node(dip, SOCAL_PORTB_NAME, S_IFCHR,
	    instance*N_SOCAL_NPORTS+1, SOCAL_NT_PORT, 0) != DDI_SUCCESS)
		goto fail;

	if (socal_start(socalp) != FCAL_SUCCESS)
		goto fail;
	DEBUGF(4, (CE_CONT, "socal%d: attach: soc+ started\n", instance));

	ddi_report_dev(dip);

	DEBUGF(2, (CE_CONT, "socal%d: attach O.K.\n\n", instance));

	return (DDI_SUCCESS);

fail:
	DEBUGF(4, (CE_CONT, "socal%d: attach: DDI_FAILURE\n", instance));

	/* Make sure soc reset */
	socal_disable(socalp);

	/* let detach do the dirty work */
	(void) socal_dodetach(dip);

	return (DDI_FAILURE);
}

static int
socal_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		resp;
	socal_state_t	*socalp;
	int		i;


	switch (cmd) {

	case DDI_SUSPEND:
		DEBUGF(4, (CE_CONT, "socal: suspend called\n"));

		if ((socalp = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		/*
		 * If any of the ports are in target-mode, don't suspend
		 */
		for (i = 0; i < N_SOCAL_NPORTS; i++) {
			if (socalp->port_state[i].sp_status & PORT_TARGET_MODE)
				return (DDI_FAILURE);
		}

		/* do not restart socal after reset */
		socal_force_reset((void *)socalp, 0, DONT_RESET_PORT);

		return (DDI_SUCCESS);

	case DDI_DETACH:
		DEBUGF(4, (CE_CONT, "socal: detach called\n"));
		resp = socal_dodetach(dip);
		if (resp == DDI_SUCCESS)
			ddi_set_driver_private(dip, NULL);
		return (resp);

	default:
		return (DDI_FAILURE);
	}
}

static int
socal_dodetach(dev_info_t *dip)
{

	int		instance = ddi_get_instance(dip);
	int		i;
	socal_state_t	*socalp;
	socal_port_t	*portp;
	socal_unsol_cb_t	*cb, *cbn = NULL;

	/* Get the soft state struct. */
	if ((socalp = ddi_get_soft_state(socal_soft_state_p, instance)) == 0) {
		return (DDI_FAILURE);
	}

	/*
	 * If somebody is still attached to us from above fail
	 * detach.
	 */
	mutex_enter(&socalp->board_mtx);
	if (socalp->socal_busy > 0) {
		mutex_exit(&socalp->board_mtx);
		return (DDI_FAILURE);
	}
	/* mark socal_busy = -1 to disallow sftm attach */
	socalp->socal_busy = -1;
	mutex_exit(&socalp->board_mtx);

	/* Make sure soc+ reset */
	mutex_enter(&socalp->k_imr_mtx);
	socal_disable(socalp);
	mutex_exit(&socalp->k_imr_mtx);

	/* remove soc+ interrupt */
	if (socalp->iblkc != (void *)NULL) {
		ddi_remove_intr(dip, (uint_t)0, socalp->iblkc);
		DEBUGF(2, (CE_CONT,
		    "socal%d: detach: Removed SOC+ interrupt from ddi\n",
		    instance));
	}

	for (i = 0; i < N_SOCAL_NPORTS; i++) {
		portp = &socalp->port_state[i];
		mutex_destroy(&portp->sp_mtx);
		cv_destroy(&portp->sp_cv);
		mutex_destroy(&portp->sp_transport->fcal_mtx);
		cv_destroy(&portp->sp_transport->fcal_cv);
		kmem_free((void *)portp->sp_transport,
		    sizeof (fcal_transport_t));
		for (cb = portp->sp_unsol_cb; cb != (socal_unsol_cb_t *)NULL;
		    cb = cbn) {
			cbn = cb->next;
			kmem_free((void *)cb, sizeof (socal_unsol_cb_t));
		}
		portp->sp_unsol_cb = (socal_unsol_cb_t *)NULL;
	}

	/*
	 * Free request queues, if allocated
	 */
	for (i = 0; i < SOCAL_N_CQS; i++) {
		/* Free the queues and destroy their mutexes. */
		mutex_destroy(&socalp->request[i].skc_mtx);
		mutex_destroy(&socalp->response[i].skc_mtx);
		cv_destroy(&socalp->request[i].skc_cv);
		cv_destroy(&socalp->response[i].skc_cv);

		if (socalp->request[i].skc_dhandle) {
			(void) ddi_dma_unbind_handle(socalp->
			    request[i].skc_dhandle);
			ddi_dma_free_handle(&socalp->request[i].skc_dhandle);
		}
		if (socalp->request[i].skc_cq_raw) {
			ddi_dma_mem_free(&socalp->request[i].skc_acchandle);
			socalp->request[i].skc_cq_raw = NULL;
			socalp->request[i].skc_cq = NULL;
		}
		if (socalp->response[i].skc_dhandle) {
			(void) ddi_dma_unbind_handle(socalp->
			    response[i].skc_dhandle);
			ddi_dma_free_handle(&socalp->response[i].skc_dhandle);
		}
		if (socalp->response[i].skc_cq_raw) {
			ddi_dma_mem_free(&socalp->response[i].skc_acchandle);
			socalp->response[i].skc_cq_raw = NULL;
			socalp->response[i].skc_cq = NULL;
		}
		if (socalp->request[i].deferred_intr_timeoutid) {
			(void) untimeout(socalp->
			    request[i].deferred_intr_timeoutid);
		}
		if (socalp->response[i].deferred_intr_timeoutid) {
			(void) untimeout(socalp->
			    response[i].deferred_intr_timeoutid);
		}
	}

	mutex_destroy(&socalp->abort_mtx);
	mutex_destroy(&socalp->board_mtx);
	mutex_destroy(&socalp->ioctl_mtx);
	cv_destroy(&socalp->board_cv);

	/*
	 * Free soc data buffer pool
	 */
	if (socalp->pool_dhandle) {
		(void) ddi_dma_unbind_handle(socalp->pool_dhandle);
		ddi_dma_free_handle(&socalp->pool_dhandle);
	}
	if (socalp->pool) {
		ddi_dma_mem_free(&socalp->pool_acchandle);
	}

	/* release register maps */
	/* Unmap EEPROM */
	if (socalp->socal_eeprom != NULL) {
		ddi_unmap_regs(dip, 0, &socalp->socal_eeprom, 0, 0);
	}

	/* Unmap XRAM */
	if (socalp->socal_xrp != NULL) {
		ddi_unmap_regs(dip, 1, &socalp->socal_xrp, 0, 0);
	}

	/* Unmap registers */
	if (socalp->socal_rp != NULL) {
		ddi_unmap_regs(dip, 2, (caddr_t *)&socalp->socal_rp, 0, 0);
	}

	if (socalp->socal_ksp != NULL)
		kstat_delete(socalp->socal_ksp);

	mutex_destroy(&socalp->k_imr_mtx);

	ddi_remove_minor_node(dip, NULL);

	ddi_soft_state_free(socal_soft_state_p, instance);

	return (DDI_SUCCESS);
}


int
socal_bus_ctl(dev_info_t *dip, dev_info_t *rip, ddi_ctl_enum_t op,
    void *a, void *v)
{
	int		port;


	switch (op) {
	case DDI_CTLOPS_REPORTDEV:
		port = ddi_getprop(DDI_DEV_T_ANY, rip, DDI_PROP_DONTPASS,
		    SOCAL_PORT_NO_PROP, -1);
		if ((port < 0) || (port > 1)) {
			port = ddi_getprop(DDI_DEV_T_ANY, rip,
			    DDI_PROP_DONTPASS, SOCAL_ALT_PORT_NO_PROP, -1);
		}
		/* log text identifying this driver (d) & its child (r) */
		cmn_err(CE_CONT, "?%s%d at %s%d: socal_port %d\n",
		    ddi_driver_name(rip), ddi_get_instance(rip),
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    port);
		break;

	case DDI_CTLOPS_INITCHILD: {
		dev_info_t	*child_dip = (dev_info_t *)a;
		char		name[MAXNAMELEN];
		socal_state_t	*socalp;

		if ((socalp = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		port = ddi_getprop(DDI_DEV_T_ANY, child_dip,
		    DDI_PROP_DONTPASS, SOCAL_PORT_NO_PROP, -1);

		if ((port < 0) || (port > 1)) {
			port = ddi_getprop(DDI_DEV_T_ANY, child_dip,
			    DDI_PROP_DONTPASS, SOCAL_ALT_PORT_NO_PROP, -1);
			if ((port < 0) || (port > 1)) {
				return (DDI_NOT_WELL_FORMED);
			}
		}
		mutex_enter(&socalp->board_mtx);
		mutex_enter(&socalp->port_state[port].sp_mtx);
		if (socalp->port_state[port].sp_status &
		    (PORT_CHILD_INIT | PORT_TARGET_MODE)) {
			mutex_exit(&socalp->port_state[port].sp_mtx);
			mutex_exit(&socalp->board_mtx);
			return (DDI_FAILURE);
		}
		socalp->socal_busy++;
		socalp->port_state[port].sp_status |= PORT_CHILD_INIT;
		mutex_exit(&socalp->port_state[port].sp_mtx);
		mutex_exit(&socalp->board_mtx);
		ddi_set_parent_data(child_dip,
		    socalp->port_state[port].sp_transport);
		(void) sprintf((char *)name, "%x,0", port);
		ddi_set_name_addr(child_dip, name);
		break;
	}

	case DDI_CTLOPS_UNINITCHILD: {
		dev_info_t	*child_dip = (dev_info_t *)a;
		socal_state_t	*socalp;

		socalp = ddi_get_driver_private(dip);
		port = ddi_getprop(DDI_DEV_T_ANY, child_dip,
		    DDI_PROP_DONTPASS, SOCAL_PORT_NO_PROP, -1);

		if ((port < 0) || (port > 1)) {
			port = ddi_getprop(DDI_DEV_T_ANY, child_dip,
			    DDI_PROP_DONTPASS, SOCAL_ALT_PORT_NO_PROP, -1);
			if ((port < 0) || (port > 1)) {
				return (DDI_NOT_WELL_FORMED);
			}
		}

		ddi_set_parent_data(child_dip, NULL);
		(void) ddi_set_name_addr(child_dip, NULL);
		mutex_enter(&socalp->board_mtx);
		mutex_enter(&socalp->port_state[port].sp_mtx);
		socalp->socal_busy--;
		socalp->port_state[port].sp_status &= ~PORT_CHILD_INIT;
		mutex_exit(&socalp->port_state[port].sp_mtx);
		mutex_exit(&socalp->board_mtx);

		break;
	}

	case DDI_CTLOPS_IOMIN: {
		int val;

		val = *((int *)v);
		val = maxbit(val, socallim->dlim_minxfer);
		/*
		 * The 'arg' value of nonzero indicates 'streaming' mode.
		 * If in streaming mode, pick the largest of our burstsizes
		 * available and say that that is our minimum value (modulo
		 * what minxfer is).
		 */
		if ((int)(uintptr_t)a) {
			val = maxbit(val,
			    1<<(ddi_fls(socallim->dlim_burstsizes)-1));
		} else {
			val = maxbit(val,
			    1<<(ddi_ffs(socallim->dlim_burstsizes)-1));
		}

		*((int *)v) = val;
		return (ddi_ctlops(dip, rip, op, a, v));
	}

	/*
	 * These ops are not available on this nexus.
	 */

	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		return (DDI_FAILURE);

	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_REPORTINT:
	default:
		/*
		 * Remaining requests get passed up to our parent
		 */
		DEBUGF(2, (CE_CONT, "%s%d: op (%d) from %s%d\n",
		    ddi_get_name(dip), ddi_get_instance(dip),
		    op, ddi_get_name(rip), ddi_get_instance(rip)));
		return (ddi_ctlops(dip, rip, op, a, v));
	}

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
/*
 * int
 * socal_getinfo() - Given the device number, return the devinfo
 *	pointer or the instance number.  Note: this routine must be
 *	successful on DDI_INFO_DEVT2INSTANCE even before attach.
 */
int
socal_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result)
{
	int instance;
	socal_state_t *socalp;

	instance = getminor((dev_t)arg) / 2;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		socalp = ddi_get_soft_state(socal_soft_state_p, instance);
		if (socalp)
			*result = socalp->dip;
		else
			*result = NULL;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
socal_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	int	instance = getminor(*devp) / 2;
	socal_state_t	*socalp =
	    ddi_get_soft_state(socal_soft_state_p, instance);
	socal_port_t	*port_statep;
	int		port;

	if (socalp == NULL)
		return (ENXIO);

	port = getminor(*devp)%2;
	port_statep = &socalp->port_state[port];

	mutex_enter(&port_statep->sp_mtx);
	port_statep->sp_status |= PORT_OPEN;
	mutex_exit(&port_statep->sp_mtx);
	DEBUGF(2, (CE_CONT,
	    "socal%d: open of port %d\n", instance, port));
	return (0);
}

/*ARGSUSED*/
int
socal_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	int	instance = getminor(dev) / 2;
	socal_state_t	*socalp =
	    ddi_get_soft_state(socal_soft_state_p, instance);
	socal_port_t	*port_statep;
	int		port;

	port = getminor(dev)%2;
	port_statep = &socalp->port_state[port];

	mutex_enter(&port_statep->sp_mtx);
	port_statep->sp_status &= ~PORT_OPEN;
	mutex_exit(&port_statep->sp_mtx);
	DEBUGF(2, (CE_CONT,
	    "socal%d: clsoe of port %d\n", instance, port));
	return (0);
}

/*ARGSUSED*/
int
socal_ioctl(dev_t dev,
    int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	int	instance = getminor(dev) / 2;
	socal_state_t	*socalp =
	    ddi_get_soft_state(socal_soft_state_p, instance);
	int		port;
	socal_port_t	*port_statep;
	int		i;
	uint_t		r;
	int		offset;
	int		retval = FCAL_SUCCESS;
	la_els_adisc_t		*adisc_pl;
	la_els_rls_reply_t	*rls_pl;
	dev_info_t	*dip;
	char		*buffer, tmp[10];
	struct socal_fm_version ver;
#ifdef _MULTI_DATAMODEL
	struct socal_fm_version32 {
		uint_t	fcode_ver_len;
		uint_t	mcode_ver_len;
		uint_t	prom_ver_len;
		caddr32_t	fcode_ver;
		caddr32_t	mcode_ver;
		caddr32_t	prom_ver;
	} ver32;
	uint_t		dm32 = 0;
#endif

	uchar_t		*flb_pl;
	flb_hdr_t	*flb_hdr;
	uint_t		flb_size;

	if (socalp == NULL)
		return (ENXIO);

	DEBUGF(4, (CE_CONT, "socal%d ioctl: got command %x\n", instance, cmd));
	port = getminor(dev)%2;

	switch (cmd) {
	case FCIO_FCODE_MCODE_VERSION:
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
			case DDI_MODEL_ILP32:
				dm32 = 1;
				if (ddi_copyin((caddr_t)arg,
				    (caddr_t)&ver32, sizeof (ver32),
				    mode) == -1)
					return (EFAULT);
				ver.fcode_ver_len =
				    ver32.fcode_ver_len;
				ver.mcode_ver_len =
				    ver32.mcode_ver_len;
				ver.prom_ver_len =
				    ver32.prom_ver_len;
				ver.fcode_ver =
				    (caddr_t)(uintptr_t)ver32.fcode_ver;
				ver.mcode_ver =
				    (caddr_t)(uintptr_t)ver32.mcode_ver;
				ver.prom_ver =
				    (caddr_t)(uintptr_t)ver32.prom_ver;
				break;
			case DDI_MODEL_NONE:
				if (ddi_copyin((caddr_t)arg,
				    (caddr_t)&ver, sizeof (ver),
				    mode) == -1)
					return (EFAULT);
		}
#else /* _MULTI_DATAMODEL */
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ver,
		    sizeof (ver), mode) == -1)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		dip = socalp->dip;
		if (ddi_prop_op(DDI_DEV_T_ANY, dip,
		    PROP_LEN_AND_VAL_ALLOC, DDI_PROP_DONTPASS |
		    DDI_PROP_CANSLEEP, "version", (caddr_t)&buffer,
		    &i) != DDI_PROP_SUCCESS)
			return (EIO);
		if (i < ver.fcode_ver_len)
			ver.fcode_ver_len = i;
		if (ddi_copyout((caddr_t)buffer,
		    (caddr_t)ver.fcode_ver, ver.fcode_ver_len,
		    mode) == -1) {
			kmem_free((caddr_t)buffer, i);
			return (EFAULT);
		}
		kmem_free((caddr_t)buffer, i);
		if (socalp->socal_eeprom) {
			for (i = 0; i < SOCAL_N_CQS; i++) {
				mutex_enter(
				    &socalp->request[i].skc_mtx);
				mutex_enter(
				    &socalp->response[i].skc_mtx);
			}
			i = socalp->socal_rp->socal_cr.w;
			socalp->socal_rp->socal_cr.w &=
			    ~SOCAL_CR_EEPROM_BANK_MASK;
			socalp->socal_rp->socal_cr.w |= 3 << 16;
			if (ver.prom_ver_len > 10)
				ver.prom_ver_len = 10;
			bcopy((caddr_t)socalp->socal_eeprom + (unsigned)
			    0xfff6, tmp, 10);
			socalp->socal_rp->socal_cr.w  = i;
			for (i = SOCAL_N_CQS-1; i >= 0; i--) {
				mutex_exit(&socalp->request[i].skc_mtx);
				mutex_exit(
				    &socalp->response[i].skc_mtx);
			}
			if (ddi_copyout((caddr_t)tmp,
			    (caddr_t)ver.prom_ver,
			    ver.prom_ver_len, mode) == -1)
				return (EFAULT);
		} else {
			ver.prom_ver_len = 0;
		}
		ver.mcode_ver_len = 0;
#ifdef _MULTI_DATAMODEL
		if (dm32) {
			ver32.fcode_ver_len = ver.fcode_ver_len;
			ver32.mcode_ver_len = ver.mcode_ver_len;
			ver32.prom_ver_len = ver.prom_ver_len;
			ver32.fcode_ver = (caddr32_t)(uintptr_t)
			    ver.fcode_ver;
			ver32.mcode_ver = (caddr32_t)(uintptr_t)
			    ver.mcode_ver;
			ver32.prom_ver = (caddr32_t)(uintptr_t)
			    ver.prom_ver;
			if (ddi_copyout((caddr_t)&ver32,
			    (caddr_t)arg, sizeof (ver32),
			    mode) == -1)
				return (EFAULT);
		} else
#endif /* _MULTI_DATAMODEL */
		if (ddi_copyout((caddr_t)&ver, (caddr_t)arg,
		    sizeof (struct socal_fm_version), mode) == -1)
			return (EFAULT);
		break;
	case FCIO_LOADUCODE:
		mutex_enter(&socalp->k_imr_mtx);
		socal_disable(socalp);
		mutex_exit(&socalp->k_imr_mtx);
		if (copyin((caddr_t)arg, (caddr_t)socal_ucode, 0x10000)
		    == -1)
			return (EFAULT);
		/* restart socal after resetting */
		(void) socal_force_reset((void *)socalp, 0,
		    RESET_PORT);
		break;
	case FCIO_DUMPXRAM:
		for (i = 0; i < SOCAL_N_CQS; i++) {
			mutex_enter(&socalp->request[i].skc_mtx);
			mutex_enter(&socalp->response[i].skc_mtx);
		}
		for (i = 0; i < 4; i++) {
			offset = arg+(0x10000 * i);
			socalp->socal_rp->socal_cr.w &=
			    ~SOCAL_CR_EXTERNAL_RAM_BANK_MASK;
			socalp->socal_rp->socal_cr.w |= i<<24;
			(void) copyout((caddr_t)socalp->socal_xrp,
			    (caddr_t)(uintptr_t)offset, 0x10000);
		}
		socalp->socal_rp->socal_cr.w &=
		    ~SOCAL_CR_EXTERNAL_RAM_BANK_MASK;
		for (i = SOCAL_N_CQS-1; i >= 0; i--) {
			mutex_exit(&socalp->request[i].skc_mtx);
			mutex_exit(&socalp->response[i].skc_mtx);
		}
		break;
#ifdef DEBUG
	case FCIO_DUMPXRAMBUF:
		(void) copyout((caddr_t)socal_xrambuf, (caddr_t)arg,
		    0x40000);
		break;
#endif
	case FCIO_GETMAP:
		mutex_enter(&socalp->ioctl_mtx);
		if (socal_getmap(socalp, port, (caddr_t)arg, 0, 0) ==
		    -1)
			retval = FCAL_ALLOC_FAILED;
		mutex_exit(&socalp->ioctl_mtx);
		break;
	case FCIO_BYPASS_DEV:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_bypass_dev((void *)socalp, port, arg);
		mutex_exit(&socalp->ioctl_mtx);
		break;
	case FCIO_FORCE_LIP:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_force_lip((void *)socalp, port, 0,
		    FCAL_FORCE_LIP);
		mutex_exit(&socalp->ioctl_mtx);
		break;
	case FCIO_FORCE_OFFLINE:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_force_offline((void *)socalp, port, 0);
		mutex_exit(&socalp->ioctl_mtx);
		break;
	case FCIO_ADISC_ELS:
	{
		if ((adisc_pl =
		    (la_els_adisc_t *)kmem_zalloc(
		    sizeof (la_els_adisc_t),
		    KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		if (copyin((caddr_t)arg, (caddr_t)adisc_pl,
		    sizeof (la_els_adisc_t)) == -1) {
			kmem_free((void *)adisc_pl,
			    sizeof (la_els_adisc_t));
			return (EFAULT);
		}
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_issue_adisc(socalp, port,
		    adisc_pl->nport_id,
		    adisc_pl, 0);
		mutex_exit(&socalp->ioctl_mtx);

		if (retval == FCAL_SUCCESS) {
		if (copyout((caddr_t)adisc_pl, (caddr_t)arg,
		    sizeof (la_els_adisc_t)) == -1) {
			kmem_free((void *)adisc_pl,
			    sizeof (la_els_adisc_t));
			return (EFAULT);
		}
		}

		kmem_free((void *)adisc_pl, sizeof (la_els_adisc_t));
		break;
	}
	case FCIO_LINKSTATUS:
	{
		int dest;
		if ((rls_pl =
		    (la_els_rls_reply_t *)
		    kmem_zalloc(sizeof (la_els_rls_reply_t),
		    KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		if (copyin((caddr_t)arg, (caddr_t)rls_pl,
		    sizeof (la_els_rls_reply_t)) == -1) {
			kmem_free((void *)rls_pl,
			    sizeof (la_els_rls_reply_t));
		return (EFAULT);
		}
		dest = (rls_pl->mbz[0] << 16) + (rls_pl->mbz[1] << 8) +
		    rls_pl->mbz[2];
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_issue_rls(socalp, port, dest,
		    rls_pl, 0);
		mutex_exit(&socalp->ioctl_mtx);

		if (retval == FCAL_SUCCESS) {
		if (copyout((caddr_t)rls_pl, (caddr_t)arg,
		    sizeof (la_els_rls_reply_t)) == -1) {
			kmem_free((void *)rls_pl,
			    sizeof (la_els_rls_reply_t));
			return (EFAULT);
		}
		}
		kmem_free((void *)rls_pl, sizeof (la_els_rls_reply_t));
		break;
	}
	case FCIO_LOOPBACK_INTERNAL:
		/*
		 * If userland doesn't provide a location for a return
		 * value the driver will permanently offline the port,
		 * ignoring any checks for devices on the loop.
		 */
		mutex_enter(&socalp->ioctl_mtx);
		if (arg == 0) {
			port_statep = &socalp->port_state[port];
			mutex_enter(&port_statep->sp_mtx);
			if (port_statep->sp_status & PORT_DISABLED) {
				/* Already disabled */
				mutex_exit(&port_statep->sp_mtx);
				mutex_exit(&socalp->ioctl_mtx);
				return (EALREADY);
			}
			port_statep->sp_status |= PORT_DISABLED;
			mutex_exit(&port_statep->sp_mtx);
		}
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_INT_LOOP);
		mutex_exit(&socalp->ioctl_mtx);
		if (arg == 0) break;
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_LOOPBACK_MANUAL:
		mutex_enter(&socalp->ioctl_mtx);
		port_statep = &socalp->port_state[port];
		mutex_enter(&port_statep->sp_mtx);
		if (port_statep->sp_status & PORT_DISABLED) {
			mutex_exit(&port_statep->sp_mtx);
			mutex_exit(&socalp->ioctl_mtx);
			return (EBUSY);
		}
		mutex_exit(&port_statep->sp_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_EXT_LOOP);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_NO_LOOPBACK:
		mutex_enter(&socalp->ioctl_mtx);
		port_statep = &socalp->port_state[port];
		mutex_enter(&port_statep->sp_mtx);
		/* Do not allow online if we're disabled */
		if (port_statep->sp_status & PORT_DISABLED) {
			if (arg != 0) {
				mutex_exit(&port_statep->sp_mtx);
				mutex_exit(&socalp->ioctl_mtx);
				/*
				 * It's permanently disabled -- Need to
				 * enable it first
				 */
				return (EBUSY);
			}
			/* This was a request to online. */
			port_statep->sp_status &= ~PORT_DISABLED;
		}
		mutex_exit(&port_statep->sp_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_REM_LOOP);
		mutex_exit(&socalp->ioctl_mtx);
		if (arg == 0) break;
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_NOP:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_NOP);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_XRAM:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_XRAM_TEST);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_SOC:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_SOC_TEST);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_HCB:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_HCB_TEST);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_SOCLB:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_SOCLB_TEST);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_SRDSLB:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_SRDSLB_TEST);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_EXTLB:
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    SOC_DIAG_EXTOE_TEST);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_DIAG_RAW:
		if (copyin((caddr_t)arg, (caddr_t)&i, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_diag_request((void *)socalp, port, &r,
		    (uint_t)i);
		mutex_exit(&socalp->ioctl_mtx);
		if (copyout((caddr_t)&r, (caddr_t)arg, sizeof (uint_t))
		    == -1)
			return (EFAULT);
		break;
	case FCIO_LOOPBACK_FRAME:
		if ((flb_hdr = (flb_hdr_t *)kmem_zalloc(sizeof (flb_hdr_t),
		    KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		if (copyin((caddr_t)arg,
		    (caddr_t)flb_hdr, sizeof (flb_hdr_t)) == -1) {
		kmem_free((void *)flb_hdr, sizeof (flb_hdr_t));
		return (EFAULT);
		}

		flb_size = flb_hdr->length;

		if ((flb_pl =
		    (uchar_t *)kmem_zalloc(flb_size, KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		if (copyin((caddr_t)(arg + sizeof (flb_hdr_t)),
		    (caddr_t)flb_pl, flb_size) == -1) {
			kmem_free((void *)flb_pl, flb_size);
			return (EFAULT);
		}
		mutex_enter(&socalp->ioctl_mtx);
		retval = socal_issue_lbf(socalp, port, flb_pl,
		    flb_size, 1);
		mutex_exit(&socalp->ioctl_mtx);

		if (retval == FCAL_SUCCESS) {
		if (copyout((caddr_t)flb_pl,
		    (caddr_t)(arg + sizeof (flb_hdr_t) +
		    flb_hdr->max_length), flb_size) == -1) {
			kmem_free((void *)flb_pl, flb_size);
			kmem_free((void *)flb_hdr, sizeof (flb_hdr_t));
			return (EFAULT);
		}
		}

		kmem_free((void *)flb_pl, flb_size);
		kmem_free((void *)flb_hdr, sizeof (flb_hdr_t));
		break;
	default:
		return (ENOTTY);

	}
	switch (retval) {
		case FCAL_SUCCESS:
			return (0);
		case FCAL_ALLOC_FAILED:
			return (ENOMEM);
		case FCAL_STATUS_DIAG_BUSY:
			return (EALREADY);
		case FCAL_STATUS_DIAG_INVALID:
			return (EINVAL);
		default:
			return (EIO);
	}

}

/*
 * Function name : socal_disable()
 *
 * Return Values :  none
 *
 * Description	 : Reset the soc+
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 *
 * Note:  before calling this, the interface should be locked down
 * so that it is guaranteed that no other threads are accessing
 * the hardware.
 */
static	void
socal_disable(socal_state_t *socalp)
{
#if !defined(lint)
	int i;
#endif
	/* Don't touch the hardware if the registers aren't mapped */
	if (!socalp->socal_rp)
		return;

	socalp->socal_rp->socal_imr = socalp->socal_k_imr = 0;
	socalp->socal_rp->socal_csr.w = SOCAL_CSR_SOFT_RESET;
#if !defined(lint)
	i = socalp->socal_rp->socal_csr.w;
#endif
	DEBUGF(9, (CE_CONT, "csr.w = %x\n", i));
}

/*
 * Function name : socal_init_transport_interface()
 *
 * Return Values :  none
 *
 * Description	 : Fill up the fcal_tranpsort struct for ULPs
 *
 *
 * Note:  Only called during attach, so no protection
 */
static void
socal_init_transport_interface(socal_state_t *socalp)
{
	int			i;
	fcal_transport_t	*xport;

	for (i = 0; i < N_SOCAL_NPORTS; i++) {
		xport = socalp->port_state[i].sp_transport;
		mutex_init(&xport->fcal_mtx, NULL, MUTEX_DRIVER,
		    (void *)(socalp->iblkc));

		cv_init(&xport->fcal_cv, NULL, CV_DRIVER, NULL);

		xport->fcal_handle = (void *)socalp;
		xport->fcal_dmalimp = socallim;
		xport->fcal_iblock = socalp->iblkc;
		xport->fcal_dmaattr = &socal_dma_attr;
		xport->fcal_accattr = &socal_acc_attr;
		xport->fcal_loginparms = socalp->socal_service_params;
		bcopy((caddr_t)&socalp->socal_n_wwn,
		    (caddr_t)&xport->fcal_n_wwn, sizeof (la_wwn_t));
		bcopy((caddr_t)&socalp->port_state[i].sp_p_wwn,
		    (caddr_t)&xport->fcal_p_wwn, sizeof (la_wwn_t));
		xport->fcal_portno = i;
		xport->fcal_cmdmax = SOCAL_MAX_XCHG;
		xport->fcal_ops = &socal_transport_ops;
	}
}

/*
 * static int
 * socal_cqalloc_init() - Inialize the circular queue tables.
 *	Also, init the locks that are associated with the tables.
 *
 *	Returns:	FCAL_SUCCESS, if able to init properly.
 *			FCAL_FAILURE, if unable to init properly.
 */

static int
socal_cqalloc_init(socal_state_t *socalp, uint32_t index)
{
	uint32_t cq_size;
	size_t real_len;
	uint_t ccount;
	socal_kcq_t *cqp;
	int	req_bound = 0, rsp_bound = 0;

	/*
	 * Initialize the Request and Response Queue locks.
	 */

	mutex_init(&socalp->request[index].skc_mtx, NULL, MUTEX_DRIVER,
	    (void *)socalp->iblkc);
	mutex_init(&socalp->response[index].skc_mtx, NULL, MUTEX_DRIVER,
	    (void *)socalp->iblkc);
	cv_init(&socalp->request[index].skc_cv, NULL, CV_DRIVER, NULL);
	cv_init(&socalp->response[index].skc_cv, NULL, CV_DRIVER, NULL);

	/* Allocate DVMA resources for the Request Queue. */
	cq_size = socal_req_entries[index] * sizeof (cqe_t);
	if (cq_size) {
		cqp = &socalp->request[index];

		if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
		    DDI_DMA_DONTWAIT, NULL,
		    &cqp->skc_dhandle) != DDI_SUCCESS) {
			socal_disp_err(socalp, CE_WARN, "driver.4020",
			    "!alloc of dma handle failed");
			goto fail;
		}

		if (ddi_dma_mem_alloc(cqp->skc_dhandle,
		    cq_size + SOCAL_CQ_ALIGN, &socal_acc_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    (caddr_t *)&cqp->skc_cq_raw, &real_len,
		    &cqp->skc_acchandle) != DDI_SUCCESS) {
			socal_disp_err(socalp, CE_WARN, "driver.4030",
			    "!alloc of dma space failed");
				goto fail;
		}

		if (real_len < (cq_size + SOCAL_CQ_ALIGN)) {
			socal_disp_err(socalp, CE_WARN, "driver.4035",
			    "!alloc of dma space failed");
			goto fail;
		}
		cqp->skc_cq = (cqe_t *)(((uintptr_t)cqp->skc_cq_raw +
		    (uintptr_t)SOCAL_CQ_ALIGN - 1) &
		    ((uintptr_t)(~(SOCAL_CQ_ALIGN-1))));

		if (ddi_dma_addr_bind_handle(cqp->skc_dhandle,
		    (struct as *)NULL, (caddr_t)cqp->skc_cq, cq_size,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
		    NULL, &cqp->skc_dcookie, &ccount) != DDI_DMA_MAPPED) {
			socal_disp_err(socalp, CE_WARN, "driver.4040",
			    "!bind of dma handle failed");
			goto fail;
		}

		req_bound = 1;
		if (ccount != 1) {
			socal_disp_err(socalp, CE_WARN, "driver.4045",
			    "!bind of dma handle failed");
			goto fail;
		}

	} else {
		socalp->request[index].skc_cq_raw = NULL;
		socalp->request[index].skc_cq = (cqe_t *)NULL;
		socalp->request[index].skc_dhandle = 0;
	}

	/* Allocate DVMA resources for the response Queue. */
	cq_size = socal_rsp_entries[index] * sizeof (cqe_t);
	if (cq_size) {
		cqp = &socalp->response[index];

		if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
		    DDI_DMA_DONTWAIT, NULL,
		    &cqp->skc_dhandle) != DDI_SUCCESS) {
			socal_disp_err(socalp, CE_WARN, "driver.4050",
			    "!alloc of dma handle failed");
			goto fail;
		}

		if (ddi_dma_mem_alloc(cqp->skc_dhandle,
		    cq_size + SOCAL_CQ_ALIGN, &socal_acc_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    (caddr_t *)&cqp->skc_cq_raw, &real_len,
		    &cqp->skc_acchandle) != DDI_SUCCESS) {
			socal_disp_err(socalp, CE_WARN, "driver.4060",
			    "!alloc of dma space failed");
				goto fail;
		}

		if (real_len < (cq_size + SOCAL_CQ_ALIGN)) {
			socal_disp_err(socalp, CE_WARN, "driver.4065",
			    "!alloc of dma space failed");
			goto fail;
		}

		cqp->skc_cq = (cqe_t *)(((uintptr_t)cqp->skc_cq_raw +
		    (uintptr_t)SOCAL_CQ_ALIGN - 1) &
		    ((uintptr_t)(~(SOCAL_CQ_ALIGN-1))));

		if (ddi_dma_addr_bind_handle(cqp->skc_dhandle,
		    (struct as *)NULL, (caddr_t)cqp->skc_cq, cq_size,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
		    NULL, &cqp->skc_dcookie, &ccount) != DDI_DMA_MAPPED) {
			socal_disp_err(socalp, CE_WARN, "driver.4070",
			    "!bind of dma handle failed");
			goto fail;
		}

		rsp_bound = 1;
		if (ccount != 1) {
			socal_disp_err(socalp, CE_WARN, "driver.4075",
			    "!bind of dma handle failed");
			goto fail;
		}

	} else {
		socalp->response[index].skc_cq_raw = NULL;
		socalp->response[index].skc_cq = (cqe_t *)NULL;
		socalp->response[index].skc_dhandle = 0;
	}

	/*
	 * Initialize the queue pointers
	 */
	socal_cqinit(socalp, index);

	return (FCAL_SUCCESS);
fail:
	if (socalp->request[index].skc_dhandle) {
		if (req_bound)
			(void) ddi_dma_unbind_handle(socalp->
			    request[index].skc_dhandle);
		ddi_dma_free_handle(&socalp->request[index].skc_dhandle);
	}
	if (socalp->request[index].skc_cq_raw)
		ddi_dma_mem_free(&socalp->request[index].skc_acchandle);

	if (socalp->response[index].skc_dhandle) {
		if (rsp_bound)
			(void) ddi_dma_unbind_handle(socalp->
			    response[index].skc_dhandle);
		ddi_dma_free_handle(&socalp->response[index].skc_dhandle);
	}
	if (socalp->response[index].skc_cq_raw)
		ddi_dma_mem_free(&socalp->response[index].skc_acchandle);

	socalp->request[index].skc_dhandle = NULL;
	socalp->response[index].skc_dhandle = NULL;
	socalp->request[index].skc_cq_raw = NULL;
	socalp->request[index].skc_cq = NULL;
	socalp->response[index].skc_cq_raw = NULL;
	socalp->response[index].skc_cq = NULL;
	mutex_destroy(&socalp->request[index].skc_mtx);
	mutex_destroy(&socalp->response[index].skc_mtx);
	cv_destroy(&socalp->request[index].skc_cv);
	cv_destroy(&socalp->response[index].skc_cv);
	return (FCAL_FAILURE);

}

/*
 * socal_cqinit() - initializes the driver's circular queue pointers, etc.
 */

static void
socal_cqinit(socal_state_t *socalp, uint32_t index)
{
	socal_kcq_t *kcq_req = &socalp->request[index];
	socal_kcq_t *kcq_rsp = &socalp->response[index];

	/*
	 * Initialize the Request and Response Queue pointers
	 */
	kcq_req->skc_seqno = 1;
	kcq_rsp->skc_seqno = 1;
	kcq_req->skc_in = 0;
	kcq_rsp->skc_in = 0;
	kcq_req->skc_out = 0;
	kcq_rsp->skc_out = 0;
	kcq_req->skc_last_index = socal_req_entries[index] - 1;
	kcq_rsp->skc_last_index = socal_rsp_entries[index] - 1;
	kcq_req->skc_full = 0;
	kcq_rsp->deferred_intr_timeoutid = 0;
	kcq_req->skc_socalp = socalp;
	kcq_rsp->skc_socalp = socalp;

	kcq_req->skc_xram_cqdesc =
	    (socalp->xram_reqp + (index * sizeof (struct cq))/8);
	kcq_rsp->skc_xram_cqdesc =
	    (socalp->xram_rspp + (index * sizeof (struct cq))/8);

	/*  Clear out memory we have allocated */
	if (kcq_req->skc_cq != NULL)
		bzero((caddr_t)kcq_req->skc_cq,
		    socal_req_entries[index] * sizeof (cqe_t));
	if (kcq_rsp->skc_cq != NULL)
		bzero((caddr_t)kcq_rsp->skc_cq,
		    socal_rsp_entries[index] * sizeof (cqe_t));
}


static int
socal_start(socal_state_t *socalp)
{
	uint_t r;

	if (!socalp)
		return (FCAL_FAILURE);

	socal_download_ucode(socalp);
	socal_init_cq_desc(socalp);
	socal_init_wwn(socalp);

	mutex_enter(&socalp->port_state[0].sp_mtx);
	socalp->port_state[0].sp_status
	    &= (PORT_OPEN|PORT_CHILD_INIT|PORT_DISABLED|PORT_TARGET_MODE);
	socalp->port_state[0].sp_status |= PORT_OFFLINE;
	mutex_exit(&socalp->port_state[0].sp_mtx);

	mutex_enter(&socalp->port_state[1].sp_mtx);
	socalp->port_state[1].sp_status
	    &= (PORT_OPEN|PORT_CHILD_INIT|PORT_DISABLED|PORT_TARGET_MODE);
	socalp->port_state[1].sp_status |= PORT_OFFLINE;
	mutex_exit(&socalp->port_state[1].sp_mtx);

	socal_enable(socalp);
	/* Make sure disabled ports stay disabled. */
	if (socalp->port_state[0].sp_status & PORT_DISABLED)
		(void) socal_diag_request((void *)socalp, 0, &r,
		    SOC_DIAG_INT_LOOP);
	if (socalp->port_state[1].sp_status & PORT_DISABLED)
		(void) socal_diag_request((void *)socalp, 1, &r,
		    SOC_DIAG_INT_LOOP);

	mutex_enter(&socalp->k_imr_mtx);
	socalp->socal_shutdown = 0;
	mutex_exit(&socalp->k_imr_mtx);

	mutex_enter(&socalp->board_mtx);
	if (socal_establish_pool(socalp, 1) != FCAL_SUCCESS) {
		mutex_exit(&socalp->board_mtx);
		return (FCAL_FAILURE);
	}
	if (socal_add_pool_buffer(socalp, 1) != FCAL_SUCCESS) {
		mutex_exit(&socalp->board_mtx);
		return (FCAL_FAILURE);
	}

	mutex_exit(&socalp->board_mtx);
	return (FCAL_SUCCESS);
}

static void
socal_doreset(socal_state_t *socalp)
{
	int		i;
	socal_port_t	*port_statep;
	socal_unsol_cb_t *scbp;

	for (i = 0; i < SOCAL_N_CQS; i++) {
		mutex_enter(&socalp->request[i].skc_mtx);
		mutex_enter(&socalp->response[i].skc_mtx);
	}

	mutex_enter(&socalp->k_imr_mtx);
	socal_disable(socalp);

	if (socalp->pool_dhandle) {
		(void) ddi_dma_unbind_handle(socalp->pool_dhandle);
		ddi_dma_free_handle(&socalp->pool_dhandle);
	}

	if (socalp->pool)
		ddi_dma_mem_free(&socalp->pool_acchandle);

	socalp->pool_dhandle = NULL;
	socalp->pool = NULL;

	for (i = 0; i < SOCAL_N_CQS; i++)
		socal_cqinit(socalp, i);

	for (i = 0; i < N_SOCAL_NPORTS; i++) {
		port_statep = &socalp->port_state[i];

		mutex_enter(&port_statep->sp_mtx);
		port_statep->sp_status &= ~ (PORT_STATUS_MASK |
		    PORT_LILP_PENDING | PORT_LIP_PENDING |
		    PORT_ABORT_PENDING | PORT_BYPASS_PENDING |
		    PORT_ELS_PENDING);
		mutex_exit(&port_statep->sp_mtx);
	}

	mutex_exit(&socalp->k_imr_mtx);

	for (i = SOCAL_N_CQS-1; i >= 0; i--) {
		mutex_exit(&socalp->request[i].skc_mtx);
		mutex_exit(&socalp->response[i].skc_mtx);
	}

	for (i = 0; i < N_SOCAL_NPORTS; i++) {
		for (scbp = socalp->port_state[i].sp_unsol_cb; scbp;
		    scbp = scbp->next)
			(scbp->statec_cb)(scbp->arg, FCAL_STATE_RESET);
	}

	for (i = 0; i < SOCAL_N_CQS; i++) {
		mutex_enter(&socalp->request[i].skc_mtx);
		mutex_enter(&socalp->response[i].skc_mtx);
	}


	for (i = 0; i < SOCAL_N_CQS; i++) {
		socalp->request[i].skc_overflowh = NULL;
		if (socalp->request[i].skc_full & SOCAL_SKC_SLEEP)
			cv_broadcast(&socalp->request[i].skc_cv);
	}

	for (i = SOCAL_N_CQS-1; i >= 0; i--) {
		mutex_exit(&socalp->request[i].skc_mtx);
		mutex_exit(&socalp->response[i].skc_mtx);
	}

}


/*
 * Function name : socal_download_ucode ()
 *
 * Return Values :
 *
 * Description	 : Copies firmware from code that has been linked into
 *		   the socal module into the soc+'s XRAM.  Prints the date
 *		   string
 *
 */
static void
socal_download_ucode(socal_state_t *socalp)
{
	uint_t	fw_len = 0;
	uint_t	date_str[16];
	auto	char buf[256];

	fw_len = (uint_t)socal_ucode_size;

	/* Copy the firmware image */
	socal_wcopy((uint_t *)&socal_ucode,
	    (uint_t *)socalp->socal_xrp, fw_len);

	socal_fix_harda(socalp, 0);
	socal_fix_harda(socalp, 1);

	/* Get the date string from the firmware image */
	socal_wcopy((uint_t *)(socalp->socal_xrp+SOCAL_XRAM_FW_DATE_STR),
	    date_str, sizeof (date_str));
	date_str[sizeof (date_str) / sizeof (uint_t) - 1] = 0;

	if (*(caddr_t)date_str != '\0') {
		(void) sprintf(buf,
		    "!Downloading host adapter, fw date code: %s\n",
		    (caddr_t)date_str);
		socal_disp_err(socalp, CE_CONT, "driver.1010", buf);
		(void) strcpy(socalp->socal_stats.fw_revision,
		    (char *)date_str);
	} else {
		(void) sprintf(buf,
		    "!Downloading host adapter fw, "
		    "date code: <not available>\n");
		socal_disp_err(socalp, CE_CONT, "driver.3010", buf);
		(void) strcpy(socalp->socal_stats.fw_revision,
		    "<Not Available>");
	}
}

/*
 * Function name : socal_disp_err()
 *
 * Return Values : none
 *
 * Description   : displays an error message on the system console
 *		   with the full device pathname displayed
 */
static void
socal_disp_err(
	socal_state_t	*socalp,
	uint_t		level,
	char		*mid,
	char		*msg)
{
	char c;
	int instance;

	instance = ddi_get_instance(socalp->dip);

	c = *msg;

	if (c == '!')		/* log only */
		cmn_err(level,
		"!ID[SUNWssa.socal.%s] socal%d: %s", mid, instance, msg+1);
	else if (c == '?')	/* boot message - log && maybe console */
		cmn_err(level,
		"?ID[SUNWssa.socal.%s] socal%d: %s", mid, instance, msg+1);
	else if (c == '^')	/* console only */
		cmn_err(level, "^socal%d: %s", instance, msg+1);
	else	{		/* log and console */
		cmn_err(level, "^socal%d: %s", instance, msg);
		cmn_err(level, "!ID[SUNWssa.socal.%s] socal%d: %s", mid,
		    instance, msg);
	}
}

/*
 * Function name : socal_init_cq_desc()
 *
 * Return Values : none
 *
 * Description	 : Initializes the request and response queue
 *		   descriptors in the SOC+'s XRAM
 *
 * Context	 : Should only be called during initialiation when
 *		   the SOC+ is reset.
 */
static void
socal_init_cq_desc(socal_state_t *socalp)
{
	soc_cq_t	que_desc[SOCAL_N_CQS];
	uint32_t	i;

	/*
	 * Finish CQ table initialization and give the descriptor
	 * table to the soc+.  Note that we don't use all of the queues
	 * provided by the hardware, but we make sure we initialize the
	 * quantities in the unused fields in the hardware to zeroes.
	 */

	/*
	 * Do request queues
	 */
	for (i = 0; i < SOCAL_N_CQS; i++) {
		if (socal_req_entries[i]) {
			que_desc[i].cq_address =
			    (uint32_t)socalp->request[i].
			    skc_dcookie.dmac_address;
			que_desc[i].cq_last_index = socal_req_entries[i] - 1;
		} else {
			que_desc[i].cq_address = (uint32_t)0;
			que_desc[i].cq_last_index = 0;
		}
		que_desc[i].cq_in = 0;
		que_desc[i].cq_out = 0;
		que_desc[i].cq_seqno = 1; /* required by SOC+ microcode */
	}

	/* copy to XRAM */
	socal_wcopy((uint_t *)que_desc,		/* pointer to kernel copy */
	    (uint_t *)socalp->xram_reqp,	/* pointer to xram location */
	    SOCAL_N_CQS * sizeof (soc_cq_t));

	/*
	 * Do response queues
	 */
	for (i = 0; i < SOCAL_N_CQS; i++) {
		if (socal_rsp_entries[i]) {
			que_desc[i].cq_last_index = socal_rsp_entries[i] - 1;
			que_desc[i].cq_address =
			    (uint32_t)socalp->response[i].
			    skc_dcookie.dmac_address;

		} else {
			que_desc[i].cq_address = 0;
			que_desc[i].cq_last_index = 0;
		}
	}

	/* copy to XRAM */
	socal_wcopy((uint_t *)que_desc,		/* pointer to kernel copy */
	    (uint_t *)socalp->xram_rspp,	/* pointer to xram location */
	    SOCAL_N_CQS * sizeof (soc_cq_t));
}

static void
socal_init_wwn(socal_state_t *socalp)
{
	/* copy the node wwn to xram */
	socal_wcopy((uint_t *)&socalp->socal_n_wwn,
	    (uint_t *)(socalp->socal_xrp +
	    SOCAL_XRAM_NODE_WWN), sizeof (la_wwn_t));

	/* copy port a's wwn to xram */
	socal_wcopy((uint_t *)&socalp->port_state[0].sp_p_wwn,
	    (uint_t *)(socalp->socal_xrp + SOCAL_XRAM_PORTA_WWN),
	    sizeof (la_wwn_t));

	/* copy port b's wwn to xram */
	socal_wcopy((uint_t *)&socalp->port_state[1].sp_p_wwn,
	    (uint_t *)(socalp->socal_xrp + SOCAL_XRAM_PORTB_WWN),
	    sizeof (la_wwn_t));

	/*
	 * need to avoid deadlock by assuring no other thread grabs both of
	 * these at once
	 */
	mutex_enter(&socalp->port_state[0].sp_transport->fcal_mtx);
	mutex_enter(&socalp->port_state[1].sp_transport->fcal_mtx);

	socal_wcopy((uint_t *)(socalp->socal_xrp + SOCAL_XRAM_SERV_PARAMS),
	    (uint_t *)&socalp->socal_service_params, SOCAL_SVC_LENGTH);
	mutex_exit(&socalp->port_state[1].sp_transport->fcal_mtx);
	mutex_exit(&socalp->port_state[0].sp_transport->fcal_mtx);
}

static void
socal_enable(socal_state_t *socalp)
{
	DEBUGF(2, (CE_CONT, "socal%d: enable:\n",
	    ddi_get_instance(socalp->dip)));

	socalp->socal_rp->socal_cr.w = socalp->socal_cfg;
	socalp->socal_rp->socal_csr.w = SOCAL_CSR_SOCAL_TO_HOST;

	socalp->socal_k_imr = (uint32_t)SOCAL_CSR_SOCAL_TO_HOST |
	    SOCAL_CSR_SLV_ACC_ERR;
	socalp->socal_rp->socal_imr = (uint32_t)socalp->socal_k_imr;
}

/*
 * static int
 * socal_establish_pool() - this routine tells the SOC+ of a buffer pool
 *	to place LINK ctl application data as it arrives.
 *
 *	Returns:
 *		FCAL_SUCCESS, upon establishing the pool.
 *		FCAL_FAILURE, if unable to establish the pool.
 */

static int
socal_establish_pool(socal_state_t *socalp, uint32_t poolid)
{
	soc_pool_request_t	*prq;
	int			result;

	if ((prq =
	    (soc_pool_request_t *)kmem_zalloc(sizeof (soc_pool_request_t),
	    KM_NOSLEEP)) == NULL)
			return (FCAL_FAILURE);
	/*
	 * Fill in the request structure.
	 */
	prq->spr_soc_hdr.sh_request_token = 1;
	prq->spr_soc_hdr.sh_flags = SOC_FC_HEADER | SOC_UNSOLICITED |
	    SOC_NO_RESPONSE;
	prq->spr_soc_hdr.sh_class = 0;
	prq->spr_soc_hdr.sh_seg_cnt = 1;
	prq->spr_soc_hdr.sh_byte_cnt = 0;

	prq->spr_pool_id = poolid;
	prq->spr_header_mask = SOCPR_MASK_RCTL;
	prq->spr_buf_size = SOCAL_POOL_SIZE;
	prq->spr_n_entries = 0;

	prq->spr_fc_frame_hdr.r_ctl = R_CTL_ELS_REQ;
	prq->spr_fc_frame_hdr.d_id = 0;
	prq->spr_fc_frame_hdr.s_id = 0;
	prq->spr_fc_frame_hdr.type = 0;
	prq->spr_fc_frame_hdr.f_ctl = 0;
	prq->spr_fc_frame_hdr.seq_id = 0;
	prq->spr_fc_frame_hdr.df_ctl = 0;
	prq->spr_fc_frame_hdr.seq_cnt = 0;
	prq->spr_fc_frame_hdr.ox_id = 0;
	prq->spr_fc_frame_hdr.rx_id = 0;
	prq->spr_fc_frame_hdr.ro = 0;

	prq->spr_cqhdr.cq_hdr_count = 1;
	prq->spr_cqhdr.cq_hdr_type = CQ_TYPE_ADD_POOL;
	prq->spr_cqhdr.cq_hdr_flags = 0;
	prq->spr_cqhdr.cq_hdr_seqno = 0;

	/* Enque the request. */
	result = socal_cq_enque(socalp, NULL, (cqe_t *)prq, CQ_REQUEST_1,
	    FCAL_NOSLEEP, NULL, 0);
	kmem_free((void *)prq, sizeof (soc_pool_request_t));
	return (result);

}


/*
 * static int
 * soc_add_pool_buffer() - this routine tells the SOC+ to add one buffer
 *	to an established pool of buffers
 *
 *	Returns:
 *		DDI_SUCCESS, upon establishing the pool.
 *		DDI_FAILURE, if unable to establish the pool.
 */

static int
socal_add_pool_buffer(socal_state_t *socalp, uint32_t poolid)
{
	soc_data_request_t	*drq;
	int			result;
	size_t			real_len;
	int			bound = 0;
	uint_t			ccount;

	if ((drq =
	    (soc_data_request_t *)kmem_zalloc(sizeof (soc_data_request_t),
	    KM_NOSLEEP)) == NULL)
			return (FCAL_FAILURE);

	/* Allocate DVMA resources for the buffer pool */
	if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &socalp->pool_dhandle) != DDI_SUCCESS)
		goto fail;

	if (ddi_dma_mem_alloc(socalp->pool_dhandle, SOCAL_POOL_SIZE,
	    &socal_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    (caddr_t *)&socalp->pool, &real_len, &socalp->pool_acchandle)
	    != DDI_SUCCESS)
		goto fail;

	if (real_len < SOCAL_POOL_SIZE)
		goto fail;

	if (ddi_dma_addr_bind_handle(socalp->pool_dhandle, (struct as *)NULL,
	    (caddr_t)socalp->pool, SOCAL_POOL_SIZE,
	    DDI_DMA_READ | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
	    NULL, &socalp->pool_dcookie, &ccount) != DDI_DMA_MAPPED)
		goto fail;

	bound = 1;
	if (ccount != 1)
		goto fail;

	/*
	 * Fill in the request structure.
	 */
	drq->sdr_soc_hdr.sh_request_token = poolid;
	drq->sdr_soc_hdr.sh_flags = SOC_UNSOLICITED | SOC_NO_RESPONSE;
	drq->sdr_soc_hdr.sh_class = 0;
	drq->sdr_soc_hdr.sh_seg_cnt = 1;
	drq->sdr_soc_hdr.sh_byte_cnt = 0;

	drq->sdr_dataseg[0].fc_base =
	    (uint32_t)socalp->pool_dcookie.dmac_address;
	drq->sdr_dataseg[0].fc_count = SOCAL_POOL_SIZE;
	drq->sdr_dataseg[1].fc_base = 0;
	drq->sdr_dataseg[1].fc_count = 0;
	drq->sdr_dataseg[2].fc_base = 0;
	drq->sdr_dataseg[2].fc_count = 0;
	drq->sdr_dataseg[3].fc_base = 0;
	drq->sdr_dataseg[3].fc_count = 0;
	drq->sdr_dataseg[4].fc_base = 0;
	drq->sdr_dataseg[4].fc_count = 0;
	drq->sdr_dataseg[5].fc_base = 0;
	drq->sdr_dataseg[5].fc_count = 0;

	drq->sdr_cqhdr.cq_hdr_count = 1;
	drq->sdr_cqhdr.cq_hdr_type = CQ_TYPE_ADD_BUFFER;
	drq->sdr_cqhdr.cq_hdr_flags = 0;
	drq->sdr_cqhdr.cq_hdr_seqno = 0;

	/* Transport the request. */
	result = socal_cq_enque(socalp, NULL, (cqe_t *)drq, CQ_REQUEST_1,
	    FCAL_NOSLEEP, NULL, 0);
	kmem_free((void *)drq, sizeof (soc_data_request_t));
	return (result);

fail:
	socal_disp_err(socalp, CE_WARN, "driver.4110",
	    "!Buffer pool DVMA alloc failed");
	if (socalp->pool_dhandle) {
		if (bound)
			(void) ddi_dma_unbind_handle(socalp->pool_dhandle);
		ddi_dma_free_handle(&socalp->pool_dhandle);
	}
	if (socalp->pool)
		ddi_dma_mem_free(&socalp->pool_acchandle);
	socalp->pool_dhandle = NULL;
	return (FCAL_FAILURE);
}

static uint_t
socal_transport(fcal_packet_t *fcalpkt, fcal_sleep_t sleep, int req_q_no)
{
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;
	socal_port_t	*port_statep;
#if defined(DEBUG) && !defined(lint)
	int		instance = ddi_get_instance(socalp->dip);
#endif
	int		port;
	soc_request_t	*sp = (soc_request_t *)&fcalpkt->fcal_socal_request;

	if (sp->sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	port_statep = &socalp->port_state[port];

	DEBUGF(4, (CE_CONT, "socal%d: transport: packet, sleep = %p, %d\n",
	    instance, fcalpkt, sleep));

	fcalpkt->fcal_cmd_state = 0;
	fcalpkt->fcal_pkt_flags &= ~(FCFLAG_COMPLETE | FCFLAG_ABORTING);

	return (socal_cq_enque(socalp, port_statep, (cqe_t *)sp,
	    req_q_no, sleep, fcalpkt, 0));
}

/*
 * Function name : socal_cq_enque()
 *
 * Return Values :
 *		FCAL_TRANSPORT_SUCCESS, if able to que the entry.
 *		FCAL_TRANSPORT_QFULL, if queue full & sleep not set
 *		FCAL_TRANSPORT_UNAVAIL if this port down
 *
 * Description	 : Enqueues an entry into the solicited request
 *		   queue
 *
 * Context	:
 */

/*ARGSUSED*/
static int
socal_cq_enque(socal_state_t *socalp, socal_port_t *port_statep, cqe_t *cqe,
    int rqix, fcal_sleep_t sleep, fcal_packet_t *to_queue,
    int mtxheld)
{
#if defined(DEBUG) && !defined(lint)
	int		instance = ddi_get_instance(socalp->dip);
#endif
	socal_kcq_t	*kcq;
	cqe_t		*sp;
	uint_t		bitmask, wmask;
	uchar_t		out;
	uchar_t		s_out;
	longlong_t	*p, *q;

	kcq = &socalp->request[rqix];

	bitmask = SOCAL_CSR_1ST_H_TO_S << rqix;
	wmask = SOCAL_CSR_SOCAL_TO_HOST | bitmask;
	p = (longlong_t *)cqe;

	/*
	 * Since we're only reading we don't need a mutex.
	 */
	if (socalp->socal_shutdown) {
		return (FCAL_TRANSPORT_UNAVAIL);
	}
	/*
	 * Get a token early.  That way we won't sleep
	 * in id32_alloc() with a mutex held.
	 */
	if (to_queue) {
		if ((to_queue->fcal_socal_request.sr_soc_hdr.sh_request_token =
		    SOCAL_ID_GET(to_queue, mtxheld ? FCAL_NOSLEEP :
		    sleep)) == 0) {
			return (FCAL_TRANSPORT_QFULL);
		}
	}
	/*
	 * Grab lock for request queue.
	 */

	if (!mtxheld)
		mutex_enter(&kcq->skc_mtx);

	/*
	 * Determine if the queue is full
	 */

	do {

		if (kcq->skc_full) {
		/*
		 * If soc's queue full, then we wait for an interrupt
		 * telling us we are not full.
		 */

			if (to_queue) {
			to_queue->fcal_pkt_next = NULL;
			if (!kcq->skc_overflowh) {
				DEBUGF(2, (CE_CONT,
				    "socal%d: cq_enque: request "
				    "que %d is full\n",
				    instance, rqix));
				kcq->skc_overflowh = to_queue;
				socalp->socal_stats.qfulls++;
			} else
				kcq->skc_overflowt->fcal_pkt_next = to_queue;
			kcq->skc_overflowt = to_queue;

			mutex_enter(&socalp->k_imr_mtx);
			socalp->socal_rp->socal_imr =
			    (socalp->socal_k_imr |= bitmask);
			mutex_exit(&socalp->k_imr_mtx);
			to_queue->fcal_cmd_state |= FCAL_CMD_IN_TRANSPORT;
			if (!mtxheld)
				mutex_exit(&kcq->skc_mtx);
			return (FCAL_TRANSPORT_SUCCESS);
			}

			if (!mtxheld)
			mutex_exit(&kcq->skc_mtx);
			return (FCAL_TRANSPORT_QFULL);
		}

		if (((kcq->skc_in + 1) & kcq->skc_last_index)
		    == (out = kcq->skc_out)) {
		/*
		 * get SOC+'s copy of out to update our copy of out
		 */
		s_out =
		    SOCAL_REQUESTQ_INDEX(rqix, socalp->socal_rp->socal_reqp.w);
		DEBUGF(2, (CE_CONT,
		    "socal%d: cq_enque: &XRAM cq_in: 0x%p s_out.out 0x%x\n",
		    instance, &kcq->skc_xram_cqdesc->cq_in, s_out));

		kcq->skc_out = out = s_out;
		/* if soc+'s que still full set flag */
		kcq->skc_full = ((((kcq->skc_in + 1) &
		    kcq->skc_last_index) == out)) ? SOCAL_SKC_FULL : 0;
		}

	} while (kcq->skc_full);

	/* Now enque the entry. */
	sp = &(kcq->skc_cq[kcq->skc_in]);
	cqe->cqe_hdr.cq_hdr_seqno = kcq->skc_seqno;

	/* Give the entry to the SOC. */
	q = (longlong_t *)sp;
	*q++ = *p++;
	*q++ = *p++;
	*q++ = *p++;
	*q++ = *p++;
	*q++ = *p++;
	*q++ = *p++;
	*q++ = *p++;
	*q = *p;
	(void) ddi_dma_sync(kcq->skc_dhandle, (int)((caddr_t)sp -
	    (caddr_t)kcq->skc_cq), sizeof (cqe_t), DDI_DMA_SYNC_FORDEV);
	if (to_queue)
		to_queue->fcal_cmd_state |= FCAL_CMD_IN_TRANSPORT;

	/*
	 * Update circular queue and ring SOC's doorbell.
	 */
	kcq->skc_in++;
	if ((kcq->skc_in & kcq->skc_last_index) == 0) {
		kcq->skc_in = 0;
		kcq->skc_seqno++;
	}

	socalp->socal_rp->socal_csr.w = wmask | (kcq->skc_in << 24);
	/* Let lock go for request queue. */
	if (!mtxheld)
		mutex_exit(&kcq->skc_mtx);

	return (FCAL_TRANSPORT_SUCCESS);
}

static uint_t
socal_transport_poll(fcal_packet_t *fcalpkt, uint_t timeout, int req_q_no)
{
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;
	register volatile socal_reg_t *socalreg = socalp->socal_rp;
	uint_t			csr;
	socal_port_t	*port_statep;
	int		port;
	soc_request_t	*sp = (soc_request_t *)&fcalpkt->fcal_socal_request;
	uint32_t	retval;
	clock_t		ticker, t;

	/* make the timeout meaningful */
	timeout = drv_usectohz(timeout);
	if (sp->sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	port_statep = &socalp->port_state[port];

	fcalpkt->fcal_cmd_state = 0;
	fcalpkt->fcal_pkt_flags &= ~(FCFLAG_COMPLETE | FCFLAG_ABORTING);

	ticker = ddi_get_lbolt();

	if ((retval = socal_cq_enque(socalp, port_statep, (cqe_t *)sp,
	    req_q_no, FCAL_NOSLEEP, fcalpkt, 0)) != FCAL_TRANSPORT_SUCCESS) {
		return (retval);
	} else {
		while (!(fcalpkt->fcal_cmd_state & FCAL_CMD_COMPLETE)) {
			drv_usecwait(SOCAL_NOINTR_POLL_DELAY_TIME);
			t = ddi_get_lbolt();
			if ((ticker + timeout) < t)
				return (FCAL_TRANSPORT_TIMEOUT);
			csr = socalreg->socal_csr.w;
			if ((SOCAL_INTR_CAUSE(socalp, csr)) &
			    SOCAL_CSR_RSP_QUE_0) {
				socal_intr_solicited(socalp, 0);
			}
		}
	}
	return (FCAL_TRANSPORT_SUCCESS);
}

static uint_t
socal_doit(fcal_packet_t *fcalpkt, socal_port_t *port_statep, int polled,
    void (*func)(), int timo, int flag, uint_t *diagcode)
{
	clock_t lb;
	uint32_t retval, status;
	socal_state_t   *socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;

	if (polled) {
		fcalpkt->fcal_pkt_comp = NULL;
		status = socal_transport_poll(fcalpkt, timo, CQ_REQUEST_0);
	} else {
		fcalpkt->fcal_pkt_comp = func;
		mutex_enter(&port_statep->sp_mtx);
		port_statep->sp_status |= flag;
		if ((status = socal_transport(fcalpkt, FCAL_NOSLEEP,
		    CQ_REQUEST_0)) == FCAL_TRANSPORT_SUCCESS) {
			lb = ddi_get_lbolt();
			while (!(fcalpkt->fcal_cmd_state & FCAL_CMD_COMPLETE)) {
			if ((retval = cv_timedwait(&port_statep->sp_cv,
			    &port_statep->sp_mtx,
			    lb+drv_usectohz(timo))) == -1) {
				status = FCAL_TRANSPORT_TIMEOUT;
				break;
			}
			}
		}
		port_statep->sp_status &= ~flag;
		mutex_exit(&port_statep->sp_mtx);
	}

	switch (status) {
		case FCAL_TRANSPORT_SUCCESS:
			status = fcalpkt->fcal_pkt_status;
			if (diagcode)
				*diagcode = fcalpkt->fcal_diag_status;
			switch (status) {
				case FCAL_STATUS_ABORT_FAILED:
					if (flag == PORT_ABORT_PENDING)
						retval = FCAL_ABORT_FAILED;
					break;
				case FCAL_STATUS_OK:
					if (flag == PORT_ABORT_PENDING)
						retval = FCAL_ABORT_FAILED;
					else
						retval = FCAL_SUCCESS;
					break;
				case FCAL_STATUS_OLD_PORT:
					retval = FCAL_OLD_PORT;
					break;
				case FCAL_STATUS_ERR_OFFLINE:
					retval = FCAL_OFFLINE;
					break;
				case FCAL_STATUS_ABORTED:
					retval = FCAL_ABORTED;
					port_statep->sp_board->
					    socal_stats.pstats[port_statep
					    ->sp_port].abts_ok++;
					break;
				case FCAL_STATUS_BAD_XID:
					retval = FCAL_BAD_ABORT;
					break;
				case FCAL_STATUS_BAD_DID:
					retval = FCAL_BAD_PARAMS;
					break;
				case FCAL_STATUS_DIAG_BUSY:
				case FCAL_STATUS_DIAG_INVALID:
					retval = status;
					break;
				default:
					retval = FCAL_LINK_ERROR;
			}
			break;
		case FCAL_TRANSPORT_TIMEOUT:
			if (flag == PORT_LIP_PENDING ||
			    flag == PORT_LILP_PENDING) {
				if (socal_core &&
				    (socal_core & SOCAL_FAILED_LIP)) {
					socal_core = 0;
					socal_take_core(socalp);
				}
				socal_disp_err(socalp, CE_WARN, "link.6040",
				"SOCAL:Forcing SOC+ reset as LIP timed out\n");
				/* restart socal after resetting */
				(void) socal_force_reset(port_statep->sp_board,
				    polled, RESET_PORT);
			}
			else
				(void) socal_force_lip(port_statep->sp_board,
				    port_statep->sp_port, polled,
				    FCAL_FORCE_LIP);
			retval = FCAL_TIMEOUT;
			break;
		case FCAL_TRANSPORT_FAILURE:
		case FCAL_BAD_PACKET:
		case FCAL_TRANSPORT_UNAVAIL:
		case FCAL_TRANSPORT_QFULL:
			retval = status;
			break;
		default:
			retval = FCAL_LINK_ERROR;
	}
	socal_packet_free(fcalpkt);
	return (retval);
}

static uint_t
socal_lilp_map(void *ssp, uint_t port, uint32_t bufid, uint_t polled)
{
	fcal_packet_t		*fcalpkt;
	soc_data_request_t	*sdr;
	socal_state_t		*socalp = (socal_state_t *)ssp;
	socal_port_t		*port_statep = &socalp->port_state[port];

	if ((fcalpkt =
	    socal_packet_alloc(socalp, polled ? FCAL_NOSLEEP : FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	sdr = (soc_data_request_t *)&fcalpkt->fcal_socal_request;
	if (port)
		sdr->sdr_soc_hdr.sh_flags = SOC_PORT_B;
	sdr->sdr_soc_hdr.sh_seg_cnt = 1;
	sdr->sdr_soc_hdr.sh_byte_cnt = 132;
	sdr->sdr_dataseg[0].fc_base = bufid;
	sdr->sdr_dataseg[0].fc_count = 132;
	sdr->sdr_cqhdr.cq_hdr_count = 1;
	sdr->sdr_cqhdr.cq_hdr_type = CQ_TYPE_REPORT_MAP;
	fcalpkt->fcal_pkt_cookie = (void *)socalp;

	return (socal_doit(fcalpkt, port_statep, polled, socal_lilp_map_done,
	    SOCAL_LILP_TIMEOUT, PORT_LILP_PENDING, NULL));
}

static uint_t
socal_force_lip(void *ssp, uint_t port, uint_t polled, uint_t lip_req)
{
	fcal_packet_t		*fcalpkt;
	soc_cmdonly_request_t	*scr;
	socal_state_t		*socalp = (socal_state_t *)ssp;
	socal_port_t		*port_statep = &socalp->port_state[port];


	if (lip_req == FCAL_NO_LIP) {
		mutex_enter(&port_statep->sp_mtx);
		if ((port_statep->sp_status & PORT_ONLINE_LOOP) &&
		    (port_statep->sp_unsol_cb->statec_cb != NULL)) {
				mutex_exit(&port_statep->sp_mtx);
				(*port_statep->sp_unsol_cb->statec_cb)
				    (port_statep->sp_unsol_cb->arg,
				    FCAL_STATUS_LOOP_ONLINE);
			return (FCAL_SUCCESS);

		} else
			mutex_exit(&port_statep->sp_mtx);
	}
	socalp->socal_stats.pstats[port].lips++;
	if ((fcalpkt =
	    socal_packet_alloc(socalp, polled ? FCAL_NOSLEEP : FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	scr = (soc_cmdonly_request_t *)&fcalpkt->fcal_socal_request;
	if (port)
		scr->scr_soc_hdr.sh_flags = SOC_PORT_B;
	scr->scr_cqhdr.cq_hdr_count = 1;
	scr->scr_cqhdr.cq_hdr_type = CQ_TYPE_REQUEST_LIP;

	fcalpkt->fcal_pkt_cookie = (void *)socalp;
	return (socal_doit(fcalpkt, port_statep, polled, socal_force_lip_done,
	    SOCAL_LIP_TIMEOUT, PORT_LIP_PENDING, NULL));
}

static uint_t
socal_abort_cmd(void *ssp, uint_t port, fcal_packet_t *fcalpkt, uint_t polled)
{
	fcal_packet_t		*fcalpkt2, *fpkt;
	soc_cmdonly_request_t	*scr, *tscr;
	socal_state_t		*socalp = (socal_state_t *)ssp;
	socal_port_t		*port_statep = &socalp->port_state[port];
	socal_kcq_t		*kcq;

	socalp->socal_stats.pstats[port].abts++;
	kcq = &socalp->request[CQ_REQUEST_1];
	mutex_enter(&kcq->skc_mtx);
	fcalpkt2 = kcq->skc_overflowh;
	fpkt = NULL;
	while (fcalpkt2 != NULL) {
		if (fcalpkt2 == fcalpkt) {
			if (fpkt == NULL)
				kcq->skc_overflowh = fcalpkt->fcal_pkt_next;
			else {
				fpkt->fcal_pkt_next = fcalpkt->fcal_pkt_next;
				if (kcq->skc_overflowt == fcalpkt)
					kcq->skc_overflowt = fpkt;
			}
			mutex_exit(&kcq->skc_mtx);
			socalp->socal_stats.pstats[port].abts_ok++;
			SOCAL_ID_FREE(fcalpkt->fcal_socal_request.
			    sr_soc_hdr.sh_request_token);
			return (FCAL_ABORTED);
		} else {
			fpkt = fcalpkt2;
			fcalpkt2 = fcalpkt2->fcal_pkt_next;
		}
	}
	mutex_exit(&kcq->skc_mtx);
	if ((fcalpkt2 =
	    socal_packet_alloc(socalp, polled ? FCAL_NOSLEEP : FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	mutex_enter(&socalp->abort_mtx);
	/* Too late? */
	if (fcalpkt->fcal_pkt_flags & FCFLAG_COMPLETE) {
		socal_packet_free(fcalpkt2);
		mutex_exit(&socalp->abort_mtx);
		return (FCAL_ABORTED);
		/* I lied.  So shoot me. */
	}
	/* Mark packet as being aborted and put it in the abort pending list. */
	fcalpkt->fcal_pkt_flags |= FCFLAG_ABORTING;

	scr = (soc_cmdonly_request_t *)&fcalpkt2->fcal_socal_request;
	tscr = (soc_cmdonly_request_t *)&fcalpkt->fcal_socal_request;
	scr->scr_soc_hdr.sh_byte_cnt = tscr->scr_soc_hdr.sh_request_token;
	scr->scr_cqhdr.cq_hdr_count = 1;
	scr->scr_cqhdr.cq_hdr_type = CQ_TYPE_REQUEST_ABORT;
	if (port)
		scr->scr_soc_hdr.sh_flags = SOC_PORT_B;
	fcalpkt2->fcal_pkt_cookie = (void *)socalp;
	mutex_exit(&socalp->abort_mtx);

	return (socal_doit(fcalpkt2, port_statep, polled, socal_abort_done,
	    SOCAL_ABORT_TIMEOUT, PORT_ABORT_PENDING, NULL));
}

/*ARGSUSED*/
static uint_t
socal_els(void *ssp, uint_t port, uint_t elscode, uint_t dest,
    void (*callback)(), void *arg, caddr_t reqpl, caddr_t *rsppl,
    uint_t sleep)
{
	return (FCAL_TRANSPORT_FAILURE);
}

static uint_t
socal_bypass_dev(void *ssp, uint_t port, uint_t dest)
{
	fcal_packet_t		*fcalpkt;
	soc_cmdonly_request_t	*scr;
	socal_state_t		*socalp = (socal_state_t *)ssp;
	socal_port_t		*port_statep = &socalp->port_state[port];

	if ((fcalpkt =
	    socal_packet_alloc(socalp, FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	scr = (soc_cmdonly_request_t *)&fcalpkt->fcal_socal_request;
	if (port)
		scr->scr_soc_hdr.sh_flags = SOC_PORT_B;
	scr->scr_soc_hdr.sh_byte_cnt = dest;
	scr->scr_cqhdr.cq_hdr_count = 1;
	scr->scr_cqhdr.cq_hdr_type = CQ_TYPE_BYPASS_DEV;
	return (socal_doit(fcalpkt, port_statep, 0, socal_bypass_dev_done,
	    SOCAL_BYPASS_TIMEOUT, PORT_BYPASS_PENDING, NULL));
}


/*ARGSUSED*/
static void
socal_force_reset(void *ssp, uint_t port, uint_t restart)
{
	socal_state_t	*socalp = (socal_state_t *)ssp;

	mutex_enter(&socalp->k_imr_mtx);
	if (socalp->socal_shutdown) {
		mutex_exit(&socalp->k_imr_mtx);
		return;
	} else {
		socalp->socal_shutdown = 1;
		mutex_exit(&socalp->k_imr_mtx);
	}
	socalp->socal_stats.resets++;
	socal_doreset(socalp);
	if (restart) {
		if (socal_start(socalp) != FCAL_SUCCESS) {
			cmn_err(CE_WARN, "socal: start failed.\n");
		}
	}
}


static void
socal_add_ulp(void *ssp, uint_t port, uchar_t type,
    void (*ulp_statec_callback)(), void (*ulp_els_callback)(),
    void (*ulp_data_callback)(), void *arg)
{
	socal_state_t	*socalp = (socal_state_t *)ssp;
	socal_port_t	*port_statep = &socalp->port_state[port];
	socal_unsol_cb_t *cbentry;

	mutex_enter(&port_statep->sp_mtx);
	for (cbentry = port_statep->sp_unsol_cb; cbentry;
	    cbentry = cbentry->next) {
		if (cbentry->type == type) {
			cbentry->statec_cb = ulp_statec_callback;
			cbentry->els_cb = ulp_els_callback;
			cbentry->data_cb = ulp_data_callback;
			cbentry->arg = arg;
			mutex_exit(&port_statep->sp_mtx);
			return;
		}
	}
	mutex_exit(&port_statep->sp_mtx);
	if ((cbentry =
	    (socal_unsol_cb_t *)kmem_zalloc(sizeof (socal_unsol_cb_t),
	    KM_SLEEP)) == (socal_unsol_cb_t *)NULL) {
		return;
	}
	mutex_enter(&port_statep->sp_mtx);
	cbentry->statec_cb = ulp_statec_callback;
	cbentry->els_cb = ulp_els_callback;
	cbentry->data_cb = ulp_data_callback;
	cbentry->arg = arg;
	cbentry->type = type;

	cbentry->next = port_statep->sp_unsol_cb;
	port_statep->sp_unsol_cb = cbentry;
	mutex_exit(&port_statep->sp_mtx);
}


/*
 * remove a ULP with matching type and arg
 */
static void
socal_remove_ulp(void *ssp, uint_t port, uchar_t type, void *arg)
{
	socal_state_t		*socalp = (socal_state_t *)ssp;
	socal_port_t		*port_statep;
	socal_unsol_cb_t	*cbentry;
	socal_unsol_cb_t	*p_cbentry;


	ASSERT(ssp != NULL);
	port_statep = &socalp->port_state[port];
	ASSERT(port_statep != NULL);

	/* scan the list of unsolicited callback entries */
	mutex_enter(&port_statep->sp_mtx);
	p_cbentry = NULL;
	for (cbentry = port_statep->sp_unsol_cb;
	    cbentry != NULL;
	    p_cbentry = cbentry, cbentry = cbentry->next) {
		if ((cbentry->type != type) || (cbentry->arg != arg)) {
			continue;	/* this entry  doesn't match */
		}
		/* found entry to remove */
		if (port_statep->sp_unsol_cb == cbentry) {
			/* remove first entry in list */
			port_statep->sp_unsol_cb = cbentry->next;
		} else {
			/* remove other entry in list */
			if (p_cbentry)
				p_cbentry->next = cbentry->next;
		}
		kmem_free((void *)cbentry, sizeof (socal_unsol_cb_t));
		DEBUGF(2, (CE_CONT, "socal port %d ULP removed\n", port));
		break;
	}
	mutex_exit(&port_statep->sp_mtx);
}


/*
 * static unsigned int
 * socal_intr() - this is the interrupt routine for the SOC. Process all
 *	possible incoming interrupts from the soc device.
 */

static unsigned int
socal_intr(caddr_t arg)
{
	socal_state_t *socalp = (socal_state_t *)arg;
	register volatile socal_reg_t *socalreg = socalp->socal_rp;
	unsigned csr;
	int cause = 0;
#if !defined(lint)
	int instance = ddi_get_instance(socalp->dip);
#endif
	int i, j, request;
	char full;
	struct fcal_packet *fpkt, *nfpkt;

	csr = socalreg->socal_csr.w;
	cause = (int)SOCAL_INTR_CAUSE(socalp, csr);

	DEBUGF(2, (CE_CONT,
	    "socal%d: intr: csr: 0x%x cause: 0x%x\n",
	    instance, csr, cause));

	if (!cause) {
		socalp->socal_on_intr = 0;
		return (DDI_INTR_UNCLAIMED);
	}

	socalp->socal_on_intr = 1;

	while (cause) {

	/*
	 * Process the unsolicited messages first in case there are some
	 * high priority async events that we should act on.
	 *
	 */

		if (cause & SOCAL_CSR_RSP_QUE_1) {
			socal_intr_unsolicited(socalp, 1);
	DEBUGF(4, (CE_CONT, "socal%d intr: did unsolicited\n", instance));
		}

		if (cause & SOCAL_CSR_RSP_QUE_0) {
			socal_intr_solicited(socalp, 0);
	DEBUGF(4, (CE_CONT, "socal%d intr: did solicited\n", instance));
		}

	/*
	 * for use with token-only response queues in the future
	 * if (cause & SOCAL_CSR_RSP_QUE_0) {
	 *	socal_intr_solicited(socalp, 0);
	 * }
	 */


	/*
	 * Process any request interrupts
	 * We only allow request interrupts when the request
	 * queue is full and we are waiting so we can enque
	 * another command.
	 */
		if ((request = (cause & SOCAL_CSR_HOST_TO_SOCAL)) != 0) {
		socalp->socal_stats.reqq_intrs++;
		for (i = SOCAL_CSR_1ST_H_TO_S, j = 0; j < SOCAL_N_CQS;
		    j++, i <<= 1) {
			if (request & i) {
			socal_kcq_t *kcq = &socalp->request[j];

			if (kcq->skc_full) {
				mutex_enter(&kcq->skc_mtx);
				full = kcq->skc_full;
				kcq->skc_full = 0;
				while ((fpkt = kcq->skc_overflowh) != NULL) {
				nfpkt = fpkt->fcal_pkt_next;
				fpkt->fcal_pkt_next = NULL;
				kcq->skc_overflowh = nfpkt;
				if (socal_cq_enque(socalp, (socal_port_t *)
				    fpkt->fcal_pkt_cookie,
				    (cqe_t *)&fpkt->fcal_socal_request,
				    j, FCAL_NOSLEEP, NULL, 1) !=
				    FCAL_TRANSPORT_SUCCESS) {
					break;
				}
				}
				if (!kcq->skc_overflowh) {
				if (full & SOCAL_SKC_SLEEP)
					cv_broadcast(&kcq->skc_cv);

			    /* Disable this queue's intrs */
				DEBUGF(2, (CE_CONT,
				    "socal%d: req que %d overflow cleared\n",
				    instance, j));
				mutex_enter(&socalp->k_imr_mtx);
				socalp->socal_rp->socal_imr =
				    (socalp->socal_k_imr &= ~i);
				mutex_exit(&socalp->k_imr_mtx);
				}
				mutex_exit(&kcq->skc_mtx);
			}
			}
		}
		}
		csr = socalreg->socal_csr.w;
		cause = (int)SOCAL_INTR_CAUSE(socalp, csr);
	DEBUGF(4, (CE_CONT, "socal%d intr: did request queues\n", instance));

	}

	socalp->socal_on_intr = 0;
	return (DDI_INTR_CLAIMED);
}

static void
socal_intr_solicited(socal_state_t *socalp, uint32_t srq)
{
	socal_kcq_t		*kcq;
	volatile socal_kcq_t	*kcqv;
	soc_response_t		*srp;
	cqe_t			*cqe;
	uint_t			status, i;
	fcal_packet_t		*fcalpkt = NULL;
	soc_header_t		*shp;
	register volatile socal_reg_t *socalreg = socalp->socal_rp;
	caddr_t			src, dst;
	uchar_t			index_in;
	cq_hdr_t		*cq_hdr;
	char			val;
	int			port;

#if defined(DEBUG) && !defined(lint)
	int instance = ddi_get_instance(socalp->dip);
#endif
	auto char buf[80];

	kcq = &socalp->response[srq];
	kcqv = (volatile socal_kcq_t *)kcq;
	DEBUGF(4, (CE_CONT, "socal%d intr_sol: entered \n", instance));

	/*
	 * Grab lock for request queue.
	 */
	mutex_enter(&kcq->skc_mtx);

	/*
	 * Process as many response queue entries as we can.
	 */
	cqe = &(kcq->skc_cq[kcqv->skc_out]);

	index_in = SOCAL_RESPONSEQ_INDEX(srq, socalreg->socal_rspp.w);

	if (index_in == kcqv->skc_out) {
		socalreg->socal_csr.w = ((kcqv->skc_out << 24) |
		    (SOCAL_CSR_SOCAL_TO_HOST & ~SOCAL_CSR_RSP_QUE_0));

		/* make sure the write completed */
		i = socalreg->socal_csr.w;

		index_in = SOCAL_RESPONSEQ_INDEX(srq, socalreg->socal_rspp.w);
	}

	kcqv->skc_in = index_in;

	while (kcqv->skc_out != index_in) {
		/* Find out where the newest entry lives in the queue */
		(void) ddi_dma_sync(kcq->skc_dhandle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);

		srp = (soc_response_t *)cqe;
		port = srp->sr_soc_hdr.sh_flags & SOC_PORT_B;
		shp = &srp->sr_soc_hdr;
		cq_hdr = &srp->sr_cqhdr;
		/*
		 * It turns out that on faster CPU's we have a problem where
		 * the soc interrupts us before the response has been DMA'ed
		 * in. This should not happen but does !!. So to workaround
		 * the problem for now, check the sequence # of the response.
		 * If it does not match with what we have, we must be
		 * reading stale data
		 */
		if (cq_hdr->cq_hdr_seqno != kcqv->skc_seqno) {
#if defined(DEBUG) && !defined(lint)
			socal_read_stale_data++;
#endif
			if (kcq->deferred_intr_timeoutid) {
				mutex_exit(&kcq->skc_mtx);
				return;
			} else {
				kcq->skc_saved_out = kcqv->skc_out;
				kcq->skc_saved_seqno = kcqv->skc_seqno;
				kcq->deferred_intr_timeoutid = timeout(
				    socal_deferred_intr, (caddr_t)kcq,
				    drv_usectohz(10000));
				mutex_exit(&kcq->skc_mtx);
				return;
			}
		}

		fcalpkt = (fcal_packet_t *)
		    SOCAL_ID_LOOKUP(shp->sh_request_token);

		if ((socal_core & SOCAL_TAKE_CORE) && ddi_peek8(socalp->dip,
		    (char *)fcalpkt, &val) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "bad token = %p\n", (void *)fcalpkt);
			mutex_exit(&kcq->skc_mtx);
			socal_take_core(socalp);
		}

		if ((fcalpkt == (fcal_packet_t *)NULL) ||
		    (fcalpkt->fcal_magic != FCALP_MAGIC)) {
			(void) sprintf(buf, "!invalid FC packet; \n\
			    in, out, seqno = 0x%x, 0x%x, 0x%x\n",
			    kcqv->skc_in, kcqv->skc_out, kcqv->skc_seqno);
			socal_disp_err(socalp, CE_WARN, "link.4060", buf);
			DEBUGF(4, (CE_CONT,
			    "\tsoc CR: 0x%x SAE: 0x%x CSR: 0x%x IMR: 0x%x\n",
			    socalreg->socal_cr.w,
			    socalreg->socal_sae.w,
			    socalreg->socal_csr.w,
			    socalreg->socal_imr));
		/*
		 * Update response queue ptrs and soc registers.
		 */
			kcqv->skc_out++;
			if ((kcqv->skc_out & kcq->skc_last_index) == 0) {
				kcqv->skc_out = 0;
				kcqv->skc_seqno++;
			}

		} else {

			DEBUGF(2, (CE_CONT, "packet 0x%p complete\n",
			    fcalpkt));
			status = srp->sr_soc_status;
			fcalpkt->fcal_pkt_status = status;
			DEBUGF(2, (CE_CONT, "SOC status: 0x%x\n", status));
			/*
			 * map soc status codes to
			 * transport status codes
			 */

			ASSERT((fcalpkt->fcal_cmd_state & FCAL_CMD_COMPLETE)
			    == 0);
			mutex_enter(&socalp->abort_mtx);
			fcalpkt->fcal_pkt_flags |= FCFLAG_COMPLETE;
			mutex_exit(&socalp->abort_mtx);

			/*
			 * Copy the response frame header (if there is one)
			 * so that the upper levels can use it.  Note that,
			 * for now, we'll copy the header only if there was
			 * some sort of non-OK status, to save the PIO reads
			 * required to get the header from the host adapter's
			 * xRAM.
			 */
			if (((status != FCAL_STATUS_OK) ||
			    (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags
			    & SOC_RESP_HEADER)) &&
			    (srp->sr_soc_hdr.sh_flags & SOC_FC_HEADER)) {
				src = (caddr_t)&srp->sr_fc_frame_hdr;
				dst = (caddr_t)&fcalpkt->fcal_resp_hdr;
				bcopy(src, dst, sizeof (fc_frame_header_t));
				fcalpkt->fcal_pkt_flags |= FCFLAG_RESP_HEADER;
				i = srp->sr_soc_hdr.sh_flags & SOC_PORT_B ?
				    1 : 0;
				if ((status != FCAL_STATUS_OK) &&
				    (status <= FCAL_STATUS_MAX_STATUS)) {
					socalp->socal_stats.pstats[i].
					    resp_status[status]++;
				} else {
					socalp->socal_stats.pstats[i].
					    resp_status[FCAL_STATUS_ERROR]++;
				}
			} else if (status == FCAL_STATUS_OK) {
				fcalpkt->fcal_socal_request.
				    sr_soc_hdr.sh_byte_cnt =
				    shp->sh_byte_cnt;
			}
			fcalpkt->fcal_diag_status =
			    (uint32_t)srp->sr_dataseg.fc_base;
			fcalpkt->fcal_ncmds = srp->sr_ncmds;

			/*
			 * Update response queue ptrs and soc registers.
			 */
			kcqv->skc_out++;
			if ((kcqv->skc_out & kcq->skc_last_index) == 0) {
				kcqv->skc_out = 0;
				kcqv->skc_seqno++;
			}

			/* For incmplt DMA offline loop by loopback */
			if (fcalpkt->fcal_pkt_status ==
			    FCAL_STATUS_INCOMPLETE_DMA_ERR) {
				socal_port_t	*port_statep;
				uint_t		r;

				/*
				 * Give up the mutex to avoid a deadlock
				 * with the loopback routine.
				 */
				mutex_exit(&kcq->skc_mtx);

				port_statep = &socalp->port_state[port];
				mutex_enter(&port_statep->sp_mtx);
				if (port_statep->sp_status &
				    PORT_DISABLED) {
					/* Already disabled */
					mutex_exit(&port_statep->sp_mtx);
				} else {
					port_statep->sp_status |=
					    PORT_DISABLED;
					mutex_exit(&port_statep->sp_mtx);
					(void) socal_diag_request(
					    (void *)socalp, port,
					    &r, SOC_DIAG_INT_LOOP);
				}
				/* reacquire mutex */
				mutex_enter(&kcq->skc_mtx);
			}

			/*
			 * Complete the packet *ONLY* if it not being aborted
			 * or the abort has already completed.  Otherwise it is
			 * not safe to free the ID.
			 */
			mutex_enter(&socalp->abort_mtx);
			if (!(fcalpkt->fcal_pkt_flags & FCFLAG_ABORTING)) {
				/*
				 * Call the completion routine
				 */
				SOCAL_ID_FREE(shp->sh_request_token);
				if (fcalpkt->fcal_pkt_comp != NULL) {
					fcalpkt->fcal_cmd_state |=
					    FCAL_CMD_COMPLETE;

					/*
					 * Give up the mutex to avoid a
					 * deadlock with the callback routine.
					 */
					mutex_exit(&socalp->abort_mtx);
					mutex_exit(&kcq->skc_mtx);

					/* callback */
					(*fcalpkt->fcal_pkt_comp)(fcalpkt);

					/* reacquire mutex */
					mutex_enter(&kcq->skc_mtx);
				} else {
					fcalpkt->fcal_cmd_state |=
					    FCAL_CMD_COMPLETE;
					mutex_exit(&socalp->abort_mtx);
				}
			} else {
				mutex_exit(&socalp->abort_mtx);
			}
		}


		if (kcq->skc_cq == NULL)
			/*
			 * This action averts a potential PANIC scenario
			 * where the SUSPEND code flow grabbed the kcq->skc_mtx
			 * when we let it go, to call our completion routine,
			 * and "initialized" the response queue.  We exit our
			 * processing loop here, thereby averting a PANIC due
			 * to a NULL de-reference from the response queue.
			 *
			 * Note that this is an interim measure that needs
			 * to be revisited when this driver is next revised
			 * for enhanced performance.
			 */
			break;

		/*
		 * We need to re-read the input and output pointers in
		 * case a polling routine should process some entries
		 * from the response queue while we're doing a callback
		 * routine with the response queue mutex dropped.
		 */
		cqe = &(kcq->skc_cq[kcqv->skc_out]);
		index_in = SOCAL_RESPONSEQ_INDEX(srq, socalreg->socal_rspp.w);

		/*
		 * Mess around with the hardware if we think we've run out
		 * of entries in the queue, just to make sure we've read
		 * all entries that are available.
		 */

		socalreg->socal_csr.w = ((kcqv->skc_out << 24) |
		    (SOCAL_CSR_SOCAL_TO_HOST & ~SOCAL_CSR_RSP_QUE_0));

		/* Make sure the csr write has completed */
		i = socalreg->socal_csr.w;
		DEBUGF(9, (CE_CONT, "csr.w = %x\n", i));

		/*
		 * Update our idea of where the host adapter has placed
		 * the most recent entry in the response queue and resync
		 * the response queue
		 */
		index_in = SOCAL_RESPONSEQ_INDEX(srq, socalreg->socal_rspp.w);

		kcqv->skc_in = index_in;
	}

	/* Drop lock for request queue. */
	mutex_exit(&kcq->skc_mtx);
}

/*
 * Function name : socal_intr_unsolicited()
 *
 * Return Values : none
 *
 * Description	 : Processes entries in the unsolicited response
 *		   queue
 *
 *	The SOC+ will give us an unsolicited response
 *	whenever its status changes: OFFLINE, ONLINE,
 *	or in response to a packet arriving from an originator.
 *
 *	When message requests come in they will be placed in our
 *	buffer queue or in the next "inline" packet by the SOC hardware.
 *
 * Context	: Unsolicited interrupts must be masked
 */

static void
socal_intr_unsolicited(socal_state_t *socalp, uint32_t urq)
{
	socal_kcq_t		*kcq;
	volatile socal_kcq_t	*kcqv;
	soc_response_t		*srp;
	volatile cqe_t		*cqe;
	int			port;
	register uchar_t		t_index, t_seqno;
	register volatile socal_reg_t *socalreg = socalp->socal_rp;
	volatile cqe_t		*cqe_cont = NULL;
	uint_t			i;
	int			hdr_count;
	int			status;
	ushort_t		flags;
	auto char		buf[256];
	socal_port_t		*port_statep;
#if defined(DEBUG) && !defined(lint)
	int			instance = ddi_get_instance(socalp->dip);
#endif
	uchar_t			index_in;
	socal_unsol_cb_t	*cblist;

	kcq = &socalp->response[urq];
	kcqv = (volatile socal_kcq_t *)kcq;

	/*
	 * Grab lock for response queue.
	 */
	mutex_enter(&kcq->skc_mtx);

	cqe = (volatile cqe_t *)&(kcq->skc_cq[kcqv->skc_out]);

	index_in = SOCAL_RESPONSEQ_INDEX(urq, socalreg->socal_rspp.w);

	kcqv->skc_in = index_in;

	while (kcqv->skc_out != index_in) {
		(void) ddi_dma_sync(kcq->skc_dhandle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);

		/* Check for continuation entries */
		if ((hdr_count = cqe->cqe_hdr.cq_hdr_count) != 1) {

			t_seqno = kcqv->skc_seqno;
			t_index = kcqv->skc_out + hdr_count;

			i = index_in;
			if (kcqv->skc_out > index_in)
			i += kcq->skc_last_index + 1;

		/*
		 * If we think the continuation entries haven't yet
		 * arrived, try once more before giving up
		 */
			if (i < t_index) {

			socalreg->socal_csr.w =
			    ((kcqv->skc_out << 24) |
			    (SOCAL_CSR_SOCAL_TO_HOST & ~SOCAL_CSR_RSP_QUE_1));

			/* Make sure the csr write has completed */
			i = socalreg->socal_csr.w;

			/*
			 * Update our idea of where the host adapter has placed
			 * the most recent entry in the response queue
			 */
			i = index_in = SOCAL_RESPONSEQ_INDEX(urq,
			    socalreg->socal_rspp.w);
			if (kcqv->skc_out > index_in)
				i += kcq->skc_last_index + 1;

			/*
			 * Exit if the continuation entries haven't yet
			 * arrived
			 */
			if (i < t_index)
				break;
			}

			if (t_index > kcq->skc_last_index) {
			t_seqno++;
			t_index &= kcq->skc_last_index;
			}

			cqe_cont = (volatile cqe_t *)
			    &(kcq->skc_cq[t_index ? t_index - 1 :
			    kcq->skc_last_index]);


		    /* A cq_hdr_count > 2 is illegal; throw away the response */

		/*
		 * XXX - should probably throw out as many entries as the
		 * hdr_cout tells us there are
		 */
			if (hdr_count != 2) {
			socal_disp_err(socalp, CE_WARN, "driver.4030",
			    "!too many continuation entries");
			DEBUGF(4, (CE_CONT,
			    "socal%d: soc+ unsolicited entry count = %d\n",
			    instance, cqe->cqe_hdr.cq_hdr_count));

			if ((++t_index & kcq->skc_last_index) == 0) {
				t_index = 0;
				t_seqno++;
			}
			kcqv->skc_out = t_index;
			kcqv->skc_seqno = t_seqno;

			cqe = &(kcq->skc_cq[kcqv->skc_out]);
			cqe_cont = NULL;
			continue;
			}
		}

		/*
		 * Update unsolicited response queue ptrs
		 */
		kcqv->skc_out++;
		if ((kcqv->skc_out & kcq->skc_last_index) == 0) {
			kcqv->skc_out = 0;
			kcqv->skc_seqno++;
		}

		if (cqe_cont != NULL) {
			kcqv->skc_out++;
			if ((kcqv->skc_out & kcq->skc_last_index) == 0) {
				kcqv->skc_out = 0;
				kcqv->skc_seqno++;
			}
		}

		if (index_in == kcqv->skc_out) {
			socalreg->socal_csr.w = ((kcqv->skc_out << 24) |
			    (SOCAL_CSR_SOCAL_TO_HOST & ~SOCAL_CSR_RSP_QUE_1));

		/* Make sure the csr write has completed */
			i = socalreg->socal_csr.w;
		}

		srp = (soc_response_t *)cqe;
		flags = srp->sr_soc_hdr.sh_flags;
		port = flags & SOC_PORT_B;
		port_statep = &socalp->port_state[port];

		/*
		 * XXX need to deal buffer pool entries here
		 */
		switch (flags & ~SOC_PORT_B) {
		case SOC_UNSOLICITED | SOC_FC_HEADER:

			srp = (soc_response_t *)cqe;

			switch (srp->sr_fc_frame_hdr.r_ctl & R_CTL_ROUTING) {
			case R_CTL_EXTENDED_SVC:
			/*
			 * Extended Link Services frame received
			 */
			socalp->socal_stats.pstats[port].els_rcvd++;
			socal_us_els(socalp, (cqe_t *)cqe, (caddr_t)cqe_cont);

			/* do callbacks to any interested ULPs */
			mutex_enter(&port_statep->sp_mtx);
			for (cblist = port_statep->sp_unsol_cb; cblist;
			    cblist = cblist->next) {
				if (cblist->els_cb) {
					mutex_exit(&port_statep->sp_mtx);
					mutex_exit(&kcq->skc_mtx);
					cblist->els_cb(cblist->arg,
					    (cqe_t *)cqe,
					    (caddr_t)cqe_cont);
					mutex_enter(&kcq->skc_mtx);
					mutex_enter(&port_statep->sp_mtx);
				}
			}
			mutex_exit(&port_statep->sp_mtx);
			break;
			case R_CTL_BASIC_SVC:
			(void) sprintf(buf,
			    "!unsupported Link Service command: 0x%x",
			    srp->sr_fc_frame_hdr.type);
			socal_disp_err(socalp, CE_WARN, "link.4020", buf);
			break;
			case R_CTL_DEVICE_DATA:
			switch (srp->sr_fc_frame_hdr.type) {
			default:
				mutex_enter(&port_statep->sp_mtx);
				status = 1;
				for (cblist = port_statep->sp_unsol_cb; cblist;
				    cblist = cblist->next) {
				if (cblist->data_cb &&
				    (cblist->type ==
				    srp->sr_fc_frame_hdr.type)) {
					mutex_exit(&port_statep->sp_mtx);
					mutex_exit(&kcq->skc_mtx);
					cblist->data_cb(cblist->arg,
					    (cqe_t *)cqe, (caddr_t)cqe_cont);
					mutex_enter(&kcq->skc_mtx);
					mutex_enter(&port_statep->sp_mtx);
					status = 0;
				}
				}
				mutex_exit(&port_statep->sp_mtx);

				if (status == 0)
				break;

				(void) sprintf(buf,
				    "!unknown FC-4 command: 0x%x",
				    srp->sr_fc_frame_hdr.type);
				socal_disp_err(socalp, CE_WARN,
				    "link.4030", buf);
				break;
			}
			break;
			default:
			(void) sprintf(buf, "!unsupported FC frame R_CTL: 0x%x",
			    srp->sr_fc_frame_hdr.r_ctl);
			socal_disp_err(socalp, CE_WARN, "link.4040", buf);
			break;
			}
			break;

		case SOC_STATUS: {

			/*
			 * Note that only the lsbyte of the status has
			 * interesting information...
			 */
			status = srp->sr_soc_status;

			switch (status) {

			case FCAL_STATUS_ONLINE:
				(void) sprintf(buf,
				"!port %d: Fibre Channel is ONLINE\n", port);
				socal_disp_err(socalp, CE_CONT, "link.6010",
				    buf);
				mutex_enter(&port_statep->sp_mtx);
				port_statep->sp_status &= ~PORT_STATUS_MASK;
				port_statep->sp_status |= PORT_ONLINE;
				mutex_exit(&port_statep->sp_mtx);
				socalp->socal_stats.pstats[port].onlines++;
				DEBUGF(4, (CE_CONT,
				    "socal%d intr_unsol: ONLINE intr\n",
				    instance));
				break;

			case FCAL_STATUS_LOOP_ONLINE:
				(void) sprintf(buf,
				"!port %d: Fibre Channel Loop is ONLINE\n",
				    port);
				socal_disp_err(socalp, CE_CONT, "link.6010",
				    buf);
				mutex_enter(&port_statep->sp_mtx);
				port_statep->sp_status &= ~PORT_STATUS_MASK;
				port_statep->sp_status |= PORT_ONLINE_LOOP;
				mutex_exit(&port_statep->sp_mtx);
				socalp->socal_stats.pstats[port].online_loops++;
				DEBUGF(4, (CE_CONT,
				    "socal%d intr_unsol: ONLINE-LOOP intr\n",
				    instance));
				break;

			case FCAL_STATUS_ERR_OFFLINE:
				/*
				 * SOC and Responder will both flush
				 * all active commands.
				 * So I don't have to do anything
				 * until it comes back online.
				 */
				(void) sprintf(buf,
				"!port %d: Fibre Channel is OFFLINE\n", port);
				socal_disp_err(socalp, CE_CONT, "link.5010",
				    buf);

				mutex_enter(&port_statep->sp_mtx);
				port_statep->sp_status &= ~PORT_STATUS_MASK;
				port_statep->sp_status |= PORT_OFFLINE;
				port_statep->sp_lilpmap_valid = 0;
				mutex_exit(&port_statep->sp_mtx);
				socalp->socal_stats.pstats[port].offlines++;
				DEBUGF(4, (CE_CONT,
				    "socal%d intr_unsol: OFFLINE intr\n",
				    instance));

				break;
			default:
				(void) sprintf(buf, "!unknown status: 0x%x\n",
				    status);
				socal_disp_err(socalp, CE_WARN, "link.3020",
				    buf);
			}
			mutex_exit(&kcq->skc_mtx);
			mutex_enter(&port_statep->sp_mtx);
			for (cblist = port_statep->sp_unsol_cb; cblist;
			    cblist = cblist->next) {
				if (cblist->statec_cb) {
					mutex_exit(&port_statep->sp_mtx);
					(*cblist->statec_cb)(cblist->arg,
					    status);
					mutex_enter(&port_statep->sp_mtx);
				}
			}
			mutex_exit(&port_statep->sp_mtx);
			if (status == FCAL_STATUS_ERR_OFFLINE) {
				socal_flush_overflowq(socalp, port,
				    CQ_REQUEST_0);
				socal_flush_overflowq(socalp, port,
				    CQ_REQUEST_1);
			}
			mutex_enter(&kcq->skc_mtx);
			break;
		}
		default:
			(void) sprintf(buf, "!unexpected state: flags: 0x%x\n",
			    flags);
			socal_disp_err(socalp, CE_WARN, "link.4050", buf);
			DEBUGF(4, (CE_CONT,
			    "\tsoc CR: 0x%x SAE: 0x%x CSR: 0x%x IMR: 0x%x\n",
			    socalp->socal_rp->socal_cr.w,
			    socalp->socal_rp->socal_sae.w,
			    socalp->socal_rp->socal_csr.w,
			    socalp->socal_rp->socal_imr));
		}


		if (kcq->skc_cq == NULL)
			/*
			 * This action averts a potential PANIC scenario
			 * where the SUSPEND code flow grabbed the kcq->skc_mtx
			 * when we let it go, to call our completion routine,
			 * and "initialized" the response queue.  We exit our
			 * processing loop here, thereby averting a PANIC due
			 * to a NULL de-reference from the response queue.
			 *
			 * Note that this is an interim measure that needs
			 * to be revisited when this driver is next revised
			 * for enhanced performance.
			 */
			break;

		/*
		 * We need to re-read the input and output pointers in
		 * case a polling routine should process some entries
		 * from the response queue while we're doing a callback
		 * routine with the response queue mutex dropped.
		 */
		cqe = &(kcq->skc_cq[kcqv->skc_out]);
		index_in = SOCAL_RESPONSEQ_INDEX(urq, socalreg->socal_rspp.w);
		cqe_cont = NULL;

		/*
		 * Mess around with the hardware if we think we've run out
		 * of entries in the queue, just to make sure we've read
		 * all entries that are available.
		 */
		if (index_in == kcqv->skc_out) {

			socalreg->socal_csr.w =
			    ((kcqv->skc_out << 24) |
			    (SOCAL_CSR_SOCAL_TO_HOST & ~SOCAL_CSR_RSP_QUE_1));

		/* Make sure the csr write has completed */
			i = socalreg->socal_csr.w;

		/*
		 * Update our idea of where the host adapter has placed
		 * the most recent entry in the response queue
		 */
			index_in =
			    SOCAL_RESPONSEQ_INDEX(urq, socalreg->socal_rspp.w);
		}

		socalp->socal_stats.pstats[port].unsol_resps++;

		kcqv->skc_in = index_in;

	}

	/* Release lock for response queue. */
	mutex_exit(&kcq->skc_mtx);
}

/*
 * socal_us_els() - This function handles unsolicited extended link
 *	service responses received from the soc.
 */
static void
socal_us_els(socal_state_t *socalp, cqe_t *cqe, caddr_t payload)
{
	soc_response_t	*srp = (soc_response_t *)cqe;
	els_payload_t	*els = (els_payload_t *)payload;
	int	i;
	char   *bp;
	auto	char buf[256];

	/*
	 * There should be a CQE continuation entry for all
	 * extended link services
	 */
	if ((els == NULL) || ((i = srp->sr_soc_hdr.sh_byte_cnt) == 0)) {
		socal_disp_err(socalp, CE_WARN, "link.4010",
		"!incomplete continuation entry");
		return;
	}

	/* Quietly impose a maximum byte count */
	if (i > SOC_CQE_PAYLOAD)
		i = SOC_CQE_PAYLOAD;
	i -= sizeof (union els_cmd_u);

	/*
	 * Decode the LS_Command code
	 */
	switch (els->els_cmd.c.ls_command) {
		case LA_ELS_DISPLAY:
		els->els_data[i] = '\0';	/* terminate the string */
		for (bp = (char *)&(els->els_data[0]); *bp; bp++) {
			/* squash newlines */
			if (*bp == '\n') *bp = ' ';
		}
		(void) sprintf(buf, "!message: %s\n", els->els_data);
		socal_disp_err(socalp, CE_CONT, "link.1010", buf);
		break;

		default:
		DEBUGF(3, (CE_CONT, "!unknown LS_Command, %x\n",
		    els->els_cmd.i));
		break;
	}

}

/*ARGSUSED*/
static fcal_packet_t *
socal_packet_alloc(socal_state_t *socalp, fcal_sleep_t sleep)
{
	int flag;
	fcal_packet_t *pkt;

	if (sleep == FCAL_SLEEP)
		flag = KM_SLEEP;
	else
		flag = KM_NOSLEEP;

	pkt = (fcal_packet_t *)kmem_zalloc(sizeof (fcal_packet_t), flag);

	if (pkt != (fcal_packet_t *)NULL)
		pkt->fcal_magic = FCALP_MAGIC;

	return (pkt);
}

static void
socal_packet_free(fcal_packet_t *fcalpkt)
{
	kmem_free((void *)fcalpkt, sizeof (fcal_packet_t));
}

static void
socal_lilp_map_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;

	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_LILP_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

static void
socal_force_lip_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;

	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_LIP_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

static void
socal_adisc_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;

	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_ADISC_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

static void
socal_lbf_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;

	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_LBF_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

static void
socal_rls_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;

	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_RLS_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

static void
socal_force_offline_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;

	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_OFFLINE_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

static void
socal_abort_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;
	soc_header_t	*shp =
	    (soc_header_t *)&fcalpkt->fcal_socal_request.sr_soc_hdr;
	fcal_packet_t	*target = (fcal_packet_t *)
	    SOCAL_ID_LOOKUP(shp->sh_request_token);

	mutex_enter(&socalp->abort_mtx);
	ASSERT(target->fcal_pkt_flags & FCFLAG_ABORTING);
	if (!(target->fcal_pkt_flags & FCFLAG_COMPLETE)) {
		SOCAL_ID_FREE(shp->sh_request_token);
	}
	mutex_exit(&socalp->abort_mtx);
	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_ABORT_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

static void
socal_bypass_dev_done(fcal_packet_t *fcalpkt)
{
	uint32_t	port;
	socal_state_t	*socalp = (socal_state_t *)fcalpkt->fcal_pkt_cookie;
	if (fcalpkt->fcal_socal_request.sr_soc_hdr.sh_flags & SOC_PORT_B)
		port = 1;
	else
		port = 0;
	mutex_enter(&socalp->port_state[port].sp_mtx);
	socalp->port_state[port].sp_status &= ~PORT_BYPASS_PENDING;
	cv_broadcast(&socalp->port_state[port].sp_cv);
	mutex_exit(&socalp->port_state[port].sp_mtx);
}

/*ARGSUSED*/
static unsigned int
socal_dummy_intr(caddr_t arg)
{
	return (DDI_INTR_UNCLAIMED);
}

static int
socal_diag_request(socal_state_t *socalp, uint32_t port, uint_t *diagcode,
    uint32_t cmd)
{
	fcal_packet_t		*fcalpkt;
	soc_diag_request_t	*sdr;
	socal_port_t		*port_statep = &socalp->port_state[port];
	struct fcal_lilp_map	map;

	/* Grabbing the state mutex is totally unnecessary.... */
	if (!(port_statep->sp_status & PORT_DISABLED)) {
		if (socal_getmap(socalp, port, (caddr_t)&map, 0, FKIOCTL)
		    != -1) {
			if (map.lilp_length != 1 && ((port_statep->sp_status &
			    PORT_ONLINE_LOOP) && cmd != SOC_DIAG_REM_LOOP))
				return (FCAL_TRANSPORT_UNAVAIL);
		}
	}
	if ((fcalpkt = socal_packet_alloc(socalp, FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);
	sdr = (soc_diag_request_t *)&fcalpkt->fcal_socal_request;
	if (port)
		sdr->sdr_soc_hdr.sh_flags = SOC_PORT_B;
	sdr->sdr_diag_cmd = cmd;
	sdr->sdr_cqhdr.cq_hdr_count = 1;
	sdr->sdr_cqhdr.cq_hdr_type = CQ_TYPE_DIAGNOSTIC;
	fcalpkt->fcal_pkt_cookie = (void *)socalp;
	return (socal_doit(fcalpkt, port_statep, 1, NULL,
	    SOCAL_DIAG_TIMEOUT, 0, diagcode));
}

static uint_t
socal_force_offline(void *ssp, uint_t port, uint_t polled)
{
	fcal_packet_t		*fcalpkt;
	soc_cmdonly_request_t	*scr;
	socal_state_t		*socalp = (socal_state_t *)ssp;
	socal_port_t		*port_statep = &socalp->port_state[port];

	if ((fcalpkt =
	    socal_packet_alloc(socalp, polled ? FCAL_NOSLEEP : FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	scr = (soc_cmdonly_request_t *)&fcalpkt->fcal_socal_request;
	if (port)
		scr->scr_soc_hdr.sh_flags = SOC_PORT_B;
	scr->scr_cqhdr.cq_hdr_count = 1;
	scr->scr_cqhdr.cq_hdr_type = CQ_TYPE_OFFLINE;
	fcalpkt->fcal_pkt_cookie = (void *)socalp;
	return (socal_doit(fcalpkt, port_statep, 0, socal_force_offline_done,
	    SOCAL_OFFLINE_TIMEOUT, PORT_OFFLINE_PENDING, NULL));
}

static int
socal_issue_adisc(socal_state_t *socalp, uint32_t port, uint32_t dest,
    la_els_adisc_t *payload, uint32_t polled)
{
	int			retval;
	la_els_adisc_t		*buf;
	fcal_packet_t		*fcalpkt;
	socal_port_t		*port_statep;
	socal_priv_cmd_t	*privp;

	port_statep = &socalp->port_state[port];

	if ((fcalpkt =
	    socal_els_alloc(socalp, port, dest, sizeof (la_els_adisc_t),
	    sizeof (la_els_adisc_t), (caddr_t *)&privp, polled))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	privp = (socal_priv_cmd_t *)fcalpkt->fcal_pkt_private;
	buf = (la_els_adisc_t *)privp->cmd;
	buf->ls_code = LA_ELS_ADISC;
	buf->mbz[0] = 0;
	buf->mbz[1] = 0;
	buf->mbz[2] = 0;
	buf->hard_address = 0;
	bcopy((caddr_t)&port_statep->sp_p_wwn,
	    (caddr_t)&buf->port_wwn, sizeof (buf->port_wwn));
	bcopy((caddr_t)&socalp->socal_n_wwn,
	    (caddr_t)&buf->node_wwn, sizeof (buf->node_wwn));
	buf->nport_id = fcalpkt->fcal_socal_request.sr_fc_frame_hdr.s_id;
	(void) ddi_dma_sync(privp->cmd_handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	retval = socal_doit(fcalpkt, port_statep, 0, socal_adisc_done,
	    SOCAL_ADISC_TIMEOUT, PORT_ADISC_PENDING, NULL);
	if (retval == FCAL_SUCCESS) {
		(void) ddi_dma_sync(privp->rsp_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		bcopy(privp->rsp, (caddr_t)payload, sizeof (la_els_adisc_t));
	}
	privp->fapktp = NULL;
	socal_els_free(privp);
	return (retval);
}

static int
socal_issue_lbf(socal_state_t *socalp, uint32_t port,
    uchar_t *payload, size_t length, uint32_t polled)
{
	int			retval;
	fcal_packet_t		*fcalpkt;
	socal_port_t		*port_statep;
	socal_priv_cmd_t	*privp;

	port_statep = &socalp->port_state[port];

	if ((fcalpkt = socal_lbf_alloc(socalp, port, length, length,
	    (caddr_t *)&privp, polled)) == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	privp = (socal_priv_cmd_t *)fcalpkt->fcal_pkt_private;
	bcopy((caddr_t)payload, privp->cmd, length);
	(void) ddi_dma_sync(privp->cmd_handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	retval = socal_doit(fcalpkt, port_statep, polled, socal_lbf_done,
	    SOCAL_LBF_TIMEOUT, PORT_LBF_PENDING, NULL);

	if (retval == FCAL_SUCCESS) {
		(void) ddi_dma_sync(privp->rsp_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		bcopy(privp->rsp, (caddr_t)payload, length);
	}
	privp->fapktp = NULL;
	socal_lbf_free(privp);
	return (retval);
}

static int
socal_issue_rls(socal_state_t *socalp, uint32_t port, uint32_t dest,
    la_els_rls_reply_t *payload, uint32_t polled)
{
	int	retval;
	la_els_rls_t		*buf;
	fcal_packet_t		*fcalpkt;
	socal_port_t		*port_statep;
	socal_priv_cmd_t	*privp;
	uint32_t		arg;

	port_statep = &socalp->port_state[port];

	if (dest == socal_getmap(socalp, port, NULL, 0, 0)) {
		/* load up the the struct with the local lesb */
		struct la_els_rjt *rsp = (struct la_els_rjt *)payload;

		rsp->ls_code = LA_ELS_RJT;
		rsp->mbz[0] = 0;
		rsp->mbz[1] = 0;
		rsp->mbz[2] = 0;
		rsp->reason_code = RJT_UNSUPPORTED;
		rsp->reserved = 0;
		rsp->explanation = 0;
		rsp->vendor = 0;
		return (FCAL_SUCCESS);
	}

	if ((fcalpkt =
	    socal_els_alloc(socalp, port, dest, sizeof (la_els_rls_t),
	    sizeof (la_els_rls_reply_t), (caddr_t *)&privp, polled))
	    == (fcal_packet_t *)NULL)
		return (FCAL_ALLOC_FAILED);

	privp = (socal_priv_cmd_t *)fcalpkt->fcal_pkt_private;

	if (payload->link_failure & 0xff000000)
		arg = payload->link_failure;
	else
		arg = dest;

	buf = (la_els_rls_t *)privp->cmd;
	buf->ls_code = LA_ELS_RLS;
	buf->mbz[0] = 0;
	buf->mbz[1] = 0;
	buf->mbz[2] = 0;
	buf->reserved = 0;
	buf->nport_id[0] = (arg >> 16) & 0xff;
	buf->nport_id[1] = (arg >> 8) & 0xff;
	buf->nport_id[2] = arg & 0xff;
	(void) ddi_dma_sync(privp->cmd_handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	retval = socal_doit(fcalpkt, port_statep, 0, socal_rls_done,
	    SOCAL_RLS_TIMEOUT, PORT_RLS_PENDING, NULL);
	if (retval == FCAL_SUCCESS) {
		(void) ddi_dma_sync(privp->rsp_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		bcopy(privp->rsp, (caddr_t)payload,
		    sizeof (la_els_rls_reply_t));
	}
	privp->fapktp = NULL;
	socal_els_free(privp);
	return (retval);
}

fcal_packet_t *
socal_els_alloc(socal_state_t *socalp, uint32_t port, uint32_t dest,
    uint32_t cmd_size, uint32_t rsp_size, caddr_t *rprivp, uint32_t polled)
{
	struct fcal_packet	*fcalpkt;
	ddi_dma_cookie_t	ccookie;
	ddi_dma_cookie_t	rcookie;
	socal_priv_cmd_t	*privp;
	ddi_dma_handle_t	chandle = NULL;
	ddi_dma_handle_t	rhandle = NULL;
	ddi_acc_handle_t	cacchandle;
	ddi_acc_handle_t	racchandle;
	soc_request_t		*srp;
	fc_frame_header_t	*fhp;
	uint_t			ccount, cmd_bound = 0, rsp_bound = 0;
	size_t			real_len;
	caddr_t			cmd;
	caddr_t			rsp;
	uint32_t		ouralpa;

	if ((fcalpkt =
	    socal_packet_alloc(socalp, polled ? FCAL_NOSLEEP : FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (NULL);

	if ((privp =
	    (socal_priv_cmd_t *)kmem_zalloc(sizeof (socal_priv_cmd_t),
	    polled ? KM_NOSLEEP : KM_SLEEP)) == (socal_priv_cmd_t *)NULL) {
		goto fail;
	}

	rprivp = (caddr_t *)&privp;

	fcalpkt->fcal_pkt_private = (caddr_t)privp;
	privp->fapktp = (void *)fcalpkt;

	if ((ouralpa = socal_getmap(socalp, port, NULL, 0, 0)) == -1)
		goto fail;

	if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &chandle) != DDI_SUCCESS)
		goto fail;
	privp->cmd_handle = chandle;

	if (ddi_dma_mem_alloc(chandle, cmd_size, &socal_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    (caddr_t *)&cmd, &real_len, &cacchandle) != DDI_SUCCESS)
		goto fail;
	privp->cmd = cmd;
	privp->cmd_acchandle = cacchandle;

	if (real_len < cmd_size)
		goto fail;

	if (ddi_dma_addr_bind_handle(chandle, (struct as *)NULL,
	    (caddr_t)cmd, cmd_size,
	    DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &ccookie, &ccount)
	    != DDI_DMA_MAPPED)
		goto fail;
	cmd_bound = 1;
	if (ccount != 1)
		goto fail;

	if (rsp_size) {
		if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
		    DDI_DMA_DONTWAIT, NULL, &rhandle) != DDI_SUCCESS)
		goto fail;

		privp->rsp_handle = rhandle;
		if (ddi_dma_mem_alloc(rhandle, rsp_size, &socal_acc_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    &rsp, &real_len, &racchandle) != DDI_SUCCESS)
			goto fail;
		privp->rsp = rsp;
		privp->rsp_acchandle = racchandle;
		if (real_len < rsp_size)
		goto fail;

		if (ddi_dma_addr_bind_handle(rhandle, (struct as *)NULL,
		    rsp, rsp_size,
		    DDI_DMA_READ | DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, NULL, &rcookie, &ccount)
		    != DDI_DMA_MAPPED)
		goto fail;

		rsp_bound = 1;
		if (ccount != 1)
		goto fail;
	}

	srp = (soc_request_t *)&fcalpkt->fcal_socal_request;
	srp->sr_soc_hdr.sh_flags = SOC_FC_HEADER;
	if (port)
		srp->sr_soc_hdr.sh_flags |= SOC_PORT_B;
	srp->sr_soc_hdr.sh_class = 3;
	srp->sr_soc_hdr.sh_byte_cnt = cmd_size;
	srp->sr_dataseg[0].fc_base = (uint32_t)ccookie.dmac_address;
	srp->sr_dataseg[0].fc_count = cmd_size;
	if (rsp_size == 0) {
		srp->sr_soc_hdr.sh_seg_cnt = 1;
	} else {
		srp->sr_soc_hdr.sh_seg_cnt = 2;
		srp->sr_dataseg[1].fc_base = (uint32_t)rcookie.dmac_address;
		srp->sr_dataseg[1].fc_count = rsp_size;
	}
	srp->sr_cqhdr.cq_hdr_count = 1;
	/* this will potentially be overwritten by the calling function */
	srp->sr_cqhdr.cq_hdr_type = CQ_TYPE_SIMPLE;

	fcalpkt->fcal_pkt_cookie = (void *)socalp;

	/* Fill in the Fabric Channel Header */
	fhp = &srp->sr_fc_frame_hdr;
	fhp->r_ctl = R_CTL_ELS_REQ;
	fhp->d_id = dest;
	fhp->s_id = ouralpa;
	fhp->type = TYPE_EXTENDED_LS;
	fhp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	fhp->seq_id = 0;
	fhp->df_ctl  = 0;
	fhp->seq_cnt = 0;
	fhp->ox_id = 0xffff;
	fhp->rx_id = 0xffff;
	fhp->ro = 0;
	return (fcalpkt);
fail:
	socal_packet_free(fcalpkt);
	if (privp) {
		if (privp->cmd_handle) {
			if (cmd_bound)
				(void) ddi_dma_unbind_handle(privp->cmd_handle);
			ddi_dma_free_handle(&privp->cmd_handle);
		}
		if (privp->cmd)
			ddi_dma_mem_free(&privp->cmd_acchandle);
		if (privp->rsp_handle) {
			if (rsp_bound)
				(void) ddi_dma_unbind_handle(privp->rsp_handle);
			ddi_dma_free_handle(&privp->rsp_handle);
		}
		if (privp->rsp)
			ddi_dma_mem_free(&privp->rsp_acchandle);

		kmem_free(privp, sizeof (*privp));
	}
	return (NULL);
}

fcal_packet_t *
socal_lbf_alloc(socal_state_t *socalp, uint32_t port,
    uint32_t cmd_size, uint32_t rsp_size, caddr_t *rprivp,
    uint32_t polled)
{
	struct fcal_packet	*fcalpkt;
	ddi_dma_cookie_t	ccookie;
	ddi_dma_cookie_t	rcookie;
	socal_priv_cmd_t	*privp;
	ddi_dma_handle_t	chandle = NULL;
	ddi_dma_handle_t	rhandle = NULL;
	ddi_acc_handle_t	cacchandle;
	ddi_acc_handle_t	racchandle;
	soc_request_t		*srp;
	fc_frame_header_t	*fhp;
	uint_t			ccount, cmd_bound = 0, rsp_bound = 0;
	size_t			real_len;
	caddr_t			cmd;
	caddr_t			rsp;

	if ((fcalpkt =
	    socal_packet_alloc(socalp, polled ? FCAL_NOSLEEP : FCAL_SLEEP))
	    == (fcal_packet_t *)NULL)
		return (NULL);

	if ((privp =
	    (socal_priv_cmd_t *)kmem_zalloc(sizeof (socal_priv_cmd_t),
	    polled ? KM_NOSLEEP : KM_SLEEP)) == (socal_priv_cmd_t *)NULL) {
		goto fail;
	}

	rprivp = (caddr_t *)&privp;

	fcalpkt->fcal_pkt_private = (caddr_t)privp;
	privp->fapktp = (void *)fcalpkt;

	if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &chandle) != DDI_SUCCESS)
		goto fail;
	privp->cmd_handle = chandle;

	if (ddi_dma_mem_alloc(chandle, cmd_size, &socal_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    (caddr_t *)&cmd, &real_len, &cacchandle) != DDI_SUCCESS)
		goto fail;
	privp->cmd = cmd;
	privp->cmd_acchandle = cacchandle;

	if (real_len < cmd_size)
		goto fail;

	if (ddi_dma_addr_bind_handle(chandle, (struct as *)NULL,
	    (caddr_t)cmd, cmd_size,
	    DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &ccookie, &ccount)
	    != DDI_DMA_MAPPED)
		goto fail;
	cmd_bound = 1;
	if (ccount != 1)
		goto fail;

	if (rsp_size) {
		if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
		    DDI_DMA_DONTWAIT, NULL, &rhandle) != DDI_SUCCESS)
		goto fail;

		privp->rsp_handle = rhandle;
		if (ddi_dma_mem_alloc(rhandle, rsp_size, &socal_acc_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    &rsp, &real_len, &racchandle) != DDI_SUCCESS)
			goto fail;

		privp->rsp = rsp;
		privp->rsp_acchandle = racchandle;
		if (real_len < rsp_size)
		goto fail;

		if (ddi_dma_addr_bind_handle(rhandle, (struct as *)NULL,
		    rsp, rsp_size,
		    DDI_DMA_READ | DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, NULL, &rcookie, &ccount)
		    != DDI_DMA_MAPPED)
			goto fail;

		rsp_bound = 1;
		if (ccount != 1)
		goto fail;
	}

	srp = (soc_request_t *)&fcalpkt->fcal_socal_request;
	srp->sr_soc_hdr.sh_flags = SOC_FC_HEADER;
	if (port)
		srp->sr_soc_hdr.sh_flags |= SOC_PORT_B;
	srp->sr_soc_hdr.sh_class = 3;
	srp->sr_soc_hdr.sh_byte_cnt = cmd_size;
	srp->sr_dataseg[0].fc_base = (uint32_t)ccookie.dmac_address;
	srp->sr_dataseg[0].fc_count = cmd_size;
	if (rsp_size == 0) {
		srp->sr_soc_hdr.sh_seg_cnt = 1;
	} else {
		srp->sr_soc_hdr.sh_seg_cnt = 2;
		srp->sr_dataseg[1].fc_base = (uint32_t)rcookie.dmac_address;
		srp->sr_dataseg[1].fc_count = rsp_size;
	}
	srp->sr_cqhdr.cq_hdr_count = 1;
	/* this will potentially be overwritten by the calling function */
	srp->sr_cqhdr.cq_hdr_type = CQ_TYPE_SIMPLE;

	fcalpkt->fcal_pkt_cookie = (void *)socalp;

	/* Fill in the Fabric Channel Header */
	fhp = &srp->sr_fc_frame_hdr;
	fhp->r_ctl = R_CTL_SOLICITED_DATA;
	fhp->d_id = socalp->port_state[port].sp_src_id;
	fhp->s_id = socalp->port_state[port].sp_src_id;
	fhp->type = TYPE_SCSI_FCP;
	fhp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ | F_CTL_LAST_SEQ;
	fhp->seq_id = 0;
	fhp->df_ctl  = 0;
	fhp->seq_cnt = 0;
	fhp->ox_id = 0xffff;
	fhp->rx_id = 0xffff;
	fhp->ro = 0;
	return (fcalpkt);
fail:
	socal_packet_free(fcalpkt);
	if (privp) {
		if (privp->cmd_handle) {
			if (cmd_bound)
				(void) ddi_dma_unbind_handle(privp->cmd_handle);
			ddi_dma_free_handle(&privp->cmd_handle);
		}
		if (privp->cmd)
			ddi_dma_mem_free(&privp->cmd_acchandle);
		if (privp->rsp_handle) {
			if (rsp_bound)
				(void) ddi_dma_unbind_handle(privp->rsp_handle);
			ddi_dma_free_handle(&privp->rsp_handle);
		}
		if (privp->rsp)
			ddi_dma_mem_free(&privp->rsp_acchandle);

		kmem_free(privp, sizeof (*privp));
	}
	return (NULL);
}

void
socal_els_free(socal_priv_cmd_t *privp)
{
	fcal_packet_t		*fcalpkt;

	if (privp)
		fcalpkt = (fcal_packet_t *)privp->fapktp;
	else
		return;

	(void) ddi_dma_unbind_handle(privp->cmd_handle);
	ddi_dma_free_handle(&privp->cmd_handle);
	ddi_dma_mem_free(&privp->cmd_acchandle);

	if (privp->rsp_handle) {
		(void) ddi_dma_unbind_handle(privp->rsp_handle);
		ddi_dma_free_handle(&privp->rsp_handle);
	}
	if (privp->rsp)
		ddi_dma_mem_free(&privp->rsp_acchandle);

	kmem_free(privp, sizeof (*privp));
	if (fcalpkt != NULL)
		socal_packet_free(fcalpkt);
}

void
socal_lbf_free(socal_priv_cmd_t *privp)
{
	fcal_packet_t		*fcalpkt;

	if (privp)
		fcalpkt = (fcal_packet_t *)privp->fapktp;
	else
		return;

	(void) ddi_dma_unbind_handle(privp->cmd_handle);
	ddi_dma_free_handle(&privp->cmd_handle);
	ddi_dma_mem_free(&privp->cmd_acchandle);

	if (privp->rsp_handle) {
		(void) ddi_dma_unbind_handle(privp->rsp_handle);
		ddi_dma_free_handle(&privp->rsp_handle);
	}

	if (privp->rsp)
		ddi_dma_mem_free(&privp->rsp_acchandle);

	kmem_free(privp, sizeof (*privp));
	if (fcalpkt != NULL)
		socal_packet_free(fcalpkt);
}

static int
socal_getmap(socal_state_t *socalp, uint32_t port, caddr_t arg,
    uint32_t polled, int flags)
{
	ddi_dma_cookie_t	dcookie;
	ddi_dma_handle_t	dhandle = NULL;
	ddi_acc_handle_t	acchandle;
	size_t			real_len, i;
	uint_t			ccount;
	fcal_lilp_map_t		*buf = NULL;
	int			retval, bound = 0;
	socal_port_t		*port_statep;

	port_statep = &socalp->port_state[port];

	if (port_statep->sp_lilpmap_valid) {

		buf = &port_statep->sp_lilpmap; /* give from cache */

		if (arg) {
		if (ddi_copyout(buf, (caddr_t)arg,
		    sizeof (struct lilpmap), flags) == -1)
			return (-1);
		}

		return (buf->lilp_myalpa);
	}

	if (ddi_dma_alloc_handle(socalp->dip, &socal_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &dhandle) != DDI_SUCCESS)
		goto getmap_fail;

	i = sizeof (struct fcal_lilp_map);

	if (ddi_dma_mem_alloc(dhandle, i, &socal_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    (caddr_t *)&buf, &real_len, &acchandle) != DDI_SUCCESS)
		goto getmap_fail;

	if (real_len < i)
		goto getmap_fail;

	if (ddi_dma_addr_bind_handle(dhandle, (struct as *)NULL,
	    (caddr_t)buf, i, DDI_DMA_READ | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &dcookie, &ccount) != DDI_DMA_MAPPED)
		goto getmap_fail;

	bound = 1;
	if (ccount != 1)
		goto getmap_fail;

	retval = socal_lilp_map((void *)socalp, port,
	    (uint32_t)dcookie.dmac_address, polled);

	(void) ddi_dma_sync(dhandle, 0, 0, DDI_DMA_SYNC_FORKERNEL);

	if (retval == FCAL_SUCCESS) {
		bcopy(buf, &port_statep->sp_lilpmap, sizeof (fcal_lilp_map_t));

		mutex_enter(&port_statep->sp_mtx);
		port_statep->sp_src_id = buf->lilp_myalpa;
		port_statep->sp_lilpmap_valid = 1; /* cached */
		mutex_exit(&port_statep->sp_mtx);

		if (arg) {
		if (ddi_copyout(buf, (caddr_t)arg,
		    sizeof (struct lilpmap), flags) == -1)
			goto getmap_fail;
		}

		retval = buf->lilp_myalpa;
	}
	else
		retval = -1;

	(void) ddi_dma_unbind_handle(dhandle);
	ddi_dma_mem_free(&acchandle);
	ddi_dma_free_handle(&dhandle);
	return (retval);

getmap_fail:
	if (dhandle) {
		if (bound)
			(void) ddi_dma_unbind_handle(dhandle);
		ddi_dma_free_handle(&dhandle);
	}
	if (buf)
		ddi_dma_mem_free(&acchandle);
	return (-1);
}

static	void
socal_wcopy(uint_t *h_src, uint_t *h_dest, int len)
{
	int	i;

	len /= 4;
	for (i = 0; i < len; i++) {
		*h_dest++ = *h_src++;
	}
}

static void
socal_flush_overflowq(socal_state_t *socalp, int port, int q_no)
{
	socal_kcq_t	*kcq;
	fcal_packet_t	*fpkt1, *fpkt2, *head = NULL, *tmp;

	kcq = &socalp->request[q_no];
	mutex_enter(&kcq->skc_mtx);
	fpkt2 = kcq->skc_overflowh;
	fpkt1 = NULL;
	while (fpkt2 != NULL) {
		if ((((soc_request_t *)&fpkt2->fcal_socal_request)
		    ->sr_soc_hdr.sh_flags & SOC_PORT_B) == port) {
			if (fpkt1 == NULL)
				kcq->skc_overflowh = fpkt2->fcal_pkt_next;
			else {
				fpkt1->fcal_pkt_next = fpkt2->fcal_pkt_next;
				if (kcq->skc_overflowt == fpkt2)
					kcq->skc_overflowt = fpkt1;
			}
			tmp = fpkt2->fcal_pkt_next;
			fpkt2->fcal_pkt_next = head;
			head = fpkt2;
			fpkt2 = tmp;
			SOCAL_ID_FREE(head->fcal_socal_request.
			    sr_soc_hdr.sh_request_token);
		} else {
			fpkt1 = fpkt2;
			fpkt2 = fpkt2->fcal_pkt_next;
		}
	}
	mutex_exit(&kcq->skc_mtx);
	fpkt2 = head;
	while (fpkt2 != NULL) {
		fpkt2->fcal_pkt_status = FCAL_STATUS_ERR_OFFLINE;
		fpkt2->fcal_cmd_state |= FCAL_CMD_COMPLETE;
		fpkt2->fcal_pkt_flags |= FCFLAG_COMPLETE;
		tmp = fpkt2->fcal_pkt_next;
		if (fpkt2->fcal_pkt_comp != NULL)
			(*fpkt2->fcal_pkt_comp)(fpkt2);
		fpkt2 = tmp;
	}
}

static void
socal_deferred_intr(void *arg)
{
	socal_kcq_t	*kcq = (socal_kcq_t *)arg;
	socal_state_t	*socalp = kcq->skc_socalp;

	ASSERT((socalp != NULL));

	mutex_enter(&kcq->skc_mtx);

	if ((kcq->skc_out != kcq->skc_saved_out) ||
	    (kcq->skc_seqno != kcq->skc_saved_seqno)) {
		kcq->deferred_intr_timeoutid = 0;
		mutex_exit(&kcq->skc_mtx);
		return;
	}

	if (socalp->socal_on_intr) {
		mutex_exit(&kcq->skc_mtx);
		kcq->deferred_intr_timeoutid = timeout(socal_deferred_intr,
		    (caddr_t)kcq, drv_usectohz(10000));
		return;
	}

	kcq->deferred_intr_timeoutid = 0;
	mutex_exit(&kcq->skc_mtx);
	socal_intr_solicited(socalp, 0);
}

static void
socal_take_core(void *arg)
{
	socal_state_t	*socalp = (socal_state_t *)arg;
	int i, instance;

	socal_disable(socalp);
	for (i = 0; i < SOCAL_N_CQS; i++) {
		mutex_enter(&socalp->request[i].skc_mtx);
		mutex_enter(&socalp->response[i].skc_mtx);
	}
	for (i = 0; i < 4; i++) {
		socalp->socal_rp->socal_cr.w &=
		    ~SOCAL_CR_EXTERNAL_RAM_BANK_MASK;
		socalp->socal_rp->socal_cr.w |= i<<24;
		(void) bcopy((caddr_t)socalp->socal_xrp,
		    (caddr_t)&socal_xrambuf[i*0x10000], 0x10000);
	}
	for (i = 3; i >= 0; i--) {
		mutex_exit(&socalp->request[i].skc_mtx);
		mutex_exit(&socalp->response[i].skc_mtx);
	}
	instance = ddi_get_instance(socalp->dip);
	cmn_err(CE_PANIC,
	    "socal take core (socal instance %d)", instance);
}

/*
 * Preset AL_PA in hardware, if is told.
 */
static void
socal_fix_harda(socal_state_t *socalp, int port)
{
	socal_port_t	*portp = &socalp->port_state[port];
	uint_t		*xrp = (uint_t *)socalp->socal_xrp;
	uint_t		accum, harda;

	harda = portp->sp_hard_alpa;
	accum = xrp[SOCAL_XRAM_PORTA_HRDA/4];
	if (port == 0) {
		accum &= 0x00FFFFFF;
		accum |= ((harda & 0xFF) << 24);
	} else {
		accum &= 0xFF00FFFF;
		accum |= ((harda & 0xFF) << 16);
	}
	xrp[SOCAL_XRAM_PORTA_HRDA/4] = accum;
}

/*
 * Target-Mode attach function
 */
fcal_transport_t *
socal_sftm_attach(dev_t dev, int loop_id)
{
	int		instance = getminor(dev) / 2;
	int		port = getminor(dev) % 2;
	int		hard_alpa;
	char		*name;
	socal_state_t	*socalp;

	/*
	 * If the device is not a "socal" device, return
	 */
	if ((name = ddi_major_to_name(getmajor(dev))) == NULL ||
	    strcmp(name, "socal") != 0)
		return (NULL);

	/*
	 * If no soft state structure, return
	 */
	socalp = ddi_get_soft_state(socal_soft_state_p, instance);
	if (socalp == NULL)
		return (NULL);

	/*
	 * If the port is already attached, return
	 */
	if (socalp->port_state[port].sp_status & PORT_CHILD_INIT)
		return (NULL);

	if (loop_id < 0 || loop_id > 126)
		return (NULL);

	/* if this instance is detaching, don't attach */
	mutex_enter(&socalp->board_mtx);
	mutex_enter(&socalp->port_state[port].sp_mtx);
	if (socalp->socal_busy < 0) {
		mutex_exit(&socalp->port_state[port].sp_mtx);
		mutex_exit(&socalp->board_mtx);
		return (NULL);
	}
	socalp->socal_busy++;
	socalp->port_state[port].sp_status |= PORT_CHILD_INIT;
	mutex_exit(&socalp->port_state[port].sp_mtx);
	mutex_exit(&socalp->board_mtx);

	/*
	 * Since we keep the Hard Loop-id in two config files, warn the
	 * user if they don't match.
	 */
	hard_alpa = socal_switch_to_alpa[loop_id];
	if (hard_alpa != socalp->port_state[port].sp_hard_alpa) {
		socalp->port_state[port].sp_hard_alpa = hard_alpa;
		cmn_err(CE_WARN, "socal%d: Hard Loop-id mismatch - "
		    "using Loop-id %d",
		    instance, loop_id);
	}

	return (socalp->port_state[port].sp_transport);
}


/*
 * Target-Mode detach function
 */
int
socal_sftm_detach(socal_state_t *socalp, int port)
{
	mutex_enter(&socalp->board_mtx);
	socalp->socal_busy--;
	socalp->port_state[port].sp_status &= ~PORT_CHILD_INIT;
	mutex_exit(&socalp->board_mtx);

	return (0);
}
