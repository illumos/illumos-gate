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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ECPPVAR_H
#define	_SYS_ECPPVAR_H

#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct ecppunit;

/*
 * Hardware-abstraction structure
 */
struct ecpp_hw {
	int	(*map_regs)(struct ecppunit *);		/* map registers */
	void	(*unmap_regs)(struct ecppunit *);	/* unmap registers */
	int	(*config_chip)(struct ecppunit *);	/* configure SuperIO */
	void	(*config_mode)(struct ecppunit *);	/* config new mode */
	void	(*mask_intr)(struct ecppunit *);	/* mask interrupts */
	void	(*unmask_intr)(struct ecppunit *);	/* unmask interrupts */
	int	(*dma_start)(struct ecppunit *);	/* start DMA transfer */
	int	(*dma_stop)(struct ecppunit *, size_t *); /* stop DMA xfer */
	size_t	(*dma_getcnt)(struct ecppunit *);	/* get DMA counter */
	ddi_dma_attr_t	*attr;				/* DMA attributes */
};

#define	ECPP_MAP_REGS(pp)		(pp)->hw->map_regs(pp)
#define	ECPP_UNMAP_REGS(pp)		(pp)->hw->unmap_regs(pp)
#define	ECPP_CONFIG_CHIP(pp)		(pp)->hw->config_chip(pp)
#define	ECPP_CONFIG_MODE(pp)		(pp)->hw->config_mode(pp)
#define	ECPP_MASK_INTR(pp)		(pp)->hw->mask_intr(pp)
#define	ECPP_UNMASK_INTR(pp)		(pp)->hw->unmask_intr(pp)
#define	ECPP_DMA_START(pp)		(pp)->hw->dma_start(pp)
#define	ECPP_DMA_STOP(pp, cnt)		(pp)->hw->dma_stop(pp, cnt)
#define	ECPP_DMA_GETCNT(pp)		(pp)->hw->dma_getcnt(pp)

/* NSC 87332/97317 and EBus DMAC */
struct ecpp_ebus {
	struct config_reg	*c_reg; 	/* configuration registers */
	ddi_acc_handle_t	c_handle;	/* handle for conf regs */
	struct cheerio_dma_reg	*dmac;		/* ebus dmac registers */
	ddi_acc_handle_t	d_handle;	/* handle for dmac registers */
	struct config2_reg	*c2_reg; 	/* 97317 2nd level conf regs */
	ddi_acc_handle_t	c2_handle;	/* handle for c2_reg */
};

/* Southbridge SuperIO and 8237 DMAC */
struct ecpp_m1553 {
	struct isaspace		*isa_space;	/* all of isa space */
	ddi_acc_handle_t	d_handle;	/* handle for isa space */
	uint8_t			chn;		/* 8237 dma channel */
	int			isadma_entered;	/* Southbridge DMA workaround */
};

#if defined(__x86)
struct ecpp_x86 {
	uint8_t			chn;
};
#endif

/*
 * Hardware binding structure
 */
struct ecpp_hw_bind {
	char		*name;		/* binding name */
	struct ecpp_hw	*hw;		/* hw description */
	char		*info;		/* info string */
};

/* ecpp e_busy states */
typedef enum {
	ECPP_IDLE = 1,	/* No ongoing transfers */
	ECPP_BUSY = 2,	/* Ongoing transfers on the cable */
	ECPP_DATA = 3,	/* Not used */
	ECPP_ERR = 4,	/* Bad status in Centronics mode */
	ECPP_FLUSH = 5	/* Currently flushing the q */
} ecpp_busy_t;

/*
 * ecpp soft state structure
 */
struct ecppunit {
	kmutex_t	umutex;		/* lock for this structure */
	int		instance;	/* instance number */
	dev_info_t	*dip;		/* device information */
	ddi_iblock_cookie_t ecpp_trap_cookie;	/* interrupt cookie */
	ecpp_busy_t	e_busy;		/* ecpp busy flag */
	kcondvar_t	pport_cv;	/* cv to signal idle state */
	/*
	 * common SuperIO registers
	 */
	struct info_reg		*i_reg; 	/* info registers */
	struct fifo_reg		*f_reg; 	/* fifo register */
	ddi_acc_handle_t	i_handle;
	ddi_acc_handle_t	f_handle;
	/*
	 * DMA support
	 */
	ddi_dma_handle_t	dma_handle;	/* DMA handle */
	ddi_dma_cookie_t	dma_cookie;	/* current cookie */
	uint_t			dma_cookie_count;	/* # of cookies */
	uint_t			dma_nwin;	/* # of DMA windows */
	uint_t			dma_curwin;	/* current window number */
	uint_t			dma_dir;	/* transfer direction */
	/*
	 * hardware-dependent stuff
	 */
	struct ecpp_hw	*hw;		/* operations/attributes */
	union {				/* hw-dependent data */
		struct ecpp_ebus	ebus;
		struct ecpp_m1553	m1553;
#if defined(__x86)
		struct ecpp_x86 	x86;
#endif
	} uh;
	/*
	 * DDI/STREAMS stuff
	 */
	boolean_t	oflag;		/* instance open flag */
	queue_t		*readq;		/* pointer to readq */
	queue_t		*writeq;	/* pointer to writeq */
	mblk_t		*msg;		/* current message block */
	boolean_t	suspended;	/* driver suspended status */
	/*
	 * Modes of operation
	 */
	int		current_mode;	/* 1284 mode */
	uchar_t		current_phase;	/* 1284 phase */
	uchar_t		backchannel;	/* backchannel mode supported */
	uchar_t		io_mode;	/* transfer mode: PIO/DMA */
	/*
	 * Ioctls support
	 */
	struct ecpp_transfer_parms xfer_parms;	/* transfer parameters */
	struct ecpp_regs regs;		/* control/status registers */
	uint8_t		saved_dsr;	/* store the dsr returned from TESTIO */
	boolean_t	timeout_error;	/* store the timeout for GETERR */
	uchar_t		port;		/* xfer type: dma/pio/tfifo */
	struct prn_timeouts prn_timeouts; /* prnio timeouts */
	/*
	 * ecpp.conf parameters
	 */
	uchar_t		init_seq;	/* centronics init seq */
	uint32_t	wsrv_retry;	/* delay (ms) before next wsrv */
	uint32_t	wait_for_busy;	/* wait for BUSY to deassert */
	uint32_t	data_setup_time; /* pio centronics handshake */
	uint32_t	strobe_pulse_width; /* pio centronics handshake */
	uint8_t		fast_centronics; /* DMA/PIO centronics */
	uint8_t		fast_compat;	/* DMA/PIO 1284 compatible mode */
	uint32_t	ecp_rev_speed;	/* rev xfer speed in ECP, bytes/sec */
	uint32_t	rev_watchdog;	/* rev xfer watchdog period, ms */
	/*
	 * Timeouts
	 */
	timeout_id_t	timeout_id;	/* io transfers timer */
	timeout_id_t	fifo_timer_id;	/* drain SuperIO FIFO */
	timeout_id_t	wsrv_timer_id;	/* wsrv timeout */
	/*
	 * Softintr data
	 */
	ddi_softintr_t	softintr_id;
	int		softintr_flags;	/* flags indicating softintr task */
	uint8_t		softintr_pending;
	/*
	 * Misc stuff
	 */
	caddr_t		ioblock;	/* transfer buffer block */
	size_t		xfercnt;	/* # of bytes to transfer */
	size_t		resid;		/* # of bytes not transferred */
	caddr_t		next_byte;	/* next byte for PIO transfer */
	caddr_t		last_byte;	/* last byte for PIO transfer */
	uint32_t	ecpp_drain_counter;	/* allows fifo to drain */
	uchar_t		dma_cancelled;	/* flushed while dma'ing */
	uint8_t		tfifo_intr;	/* TFIFO switch interrupt workaround */
	size_t		nread;		/* requested read */
	size_t		last_dmacnt;	/* DMA counter value for rev watchdog */
	uint32_t	rev_timeout_cnt; /* number of watchdog invocations */
	/*
	 * Spurious interrupt detection
	 */
	hrtime_t	lastspur;	/* last time spurious intrs started */
	long		nspur;		/* spurious intrs counter */
	/*
	 * Statistics
	 */
	kstat_t		*ksp;		/* kstat pointer */
	kstat_t		*intrstats;	/* kstat interrupt counter */
	/*
	 * number of bytes, transferred in and out in each mode
	 */
	uint32_t	ctxpio_obytes;
	uint32_t	obytes[ECPP_EPP_MODE+1];
	uint32_t	ibytes[ECPP_EPP_MODE+1];
	/*
	 * other stats
	 */
	uint32_t	to_mode[ECPP_EPP_MODE+1]; /* # transitions to mode */
	uint32_t	xfer_tout;	/* # transfer timeouts */
	uint32_t	ctx_cf;		/* # periph check failures */
	uint32_t	joblen;		/* of bytes xfer'd since open */
	uint32_t	isr_reattempt_high;	/* max times isr has looped */
	/*
	 * interrupt stats
	 */
	uint_t		intr_hard;
	uint_t		intr_spurious;
	uint_t		intr_soft;
	/*
	 * identify second register set for ecp mode on Sx86
	 */
	int		noecpregs;
};

_NOTE(MUTEX_PROTECTS_DATA(ecppunit::umutex, ecppunit))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::i_reg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::f_reg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::i_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::f_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::ecpp_trap_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::readq))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ecppunit::writeq))

/*
 * current_phase values
 */
#define	ECPP_PHASE_INIT		0x00	/* initialization */
#define	ECPP_PHASE_NEGO		0x01	/* negotiation */
#define	ECPP_PHASE_TERM		0x02	/* termination */
#define	ECPP_PHASE_PO		0x03	/* power-on */

#define	ECPP_PHASE_C_FWD_DMA	0x10	/* cntrx/compat fwd dma xfer */
#define	ECPP_PHASE_C_FWD_PIO	0x11	/* cntrx/compat fwd PIO xfer */
#define	ECPP_PHASE_C_IDLE	0x12	/* cntrx/compat idle */

#define	ECPP_PHASE_NIBT_REVDATA	0x20	/* nibble/byte reverse data */
#define	ECPP_PHASE_NIBT_AVAIL	0x21	/* nibble/byte reverse data available */
#define	ECPP_PHASE_NIBT_NAVAIL	0x22	/* nibble/byte reverse data not avail */
#define	ECPP_PHASE_NIBT_REVIDLE	0x22	/* nibble/byte reverse idle */
#define	ECPP_PHASE_NIBT_REVINTR	0x23	/* nibble/byte reverse interrupt */

#define	ECPP_PHASE_ECP_SETUP	0x30	/* ecp setup */
#define	ECPP_PHASE_ECP_FWD_XFER	0x31	/* ecp forward transfer */
#define	ECPP_PHASE_ECP_FWD_IDLE	0x32	/* ecp forward idle */
#define	ECPP_PHASE_ECP_FWD_REV	0x33	/* ecp forward to reverse */
#define	ECPP_PHASE_ECP_REV_XFER	0x34	/* ecp reverse transfer */
#define	ECPP_PHASE_ECP_REV_IDLE	0x35	/* ecp reverse idle */
#define	ECPP_PHASE_ECP_REV_FWD	0x36	/* ecp reverse to forward */

#define	ECPP_PHASE_EPP_INIT_IDLE 0x40	/* epp init phase */
#define	ECPP_PHASE_EPP_IDLE	0x41	/* epp all-round phase */

#define	FAILURE_PHASE		0x80
#define	UNDEFINED_PHASE		0x81

/* ecpp return values */
#define	SUCCESS		1
#define	FAILURE		2

#define	TRUE		1
#define	FALSE		0

/* message type */
#define	ECPP_BACKCHANNEL	0x45

/* transfer modes */
#define	ECPP_DMA		0x1
#define	ECPP_PIO		0x2

/* tuneable timing defaults */
#define	CENTRONICS_RETRY	750	/* 750 milliseconds */
#define	WAIT_FOR_BUSY		1000	/* 1000 microseconds */
#define	SUSPEND_TOUT		10	/* # seconds before suspend fails */

/* Centronics hanshaking defaults */
#define	DATA_SETUP_TIME		2	/* 2 uSec Data Setup Time (2x min) */
#define	STROBE_PULSE_WIDTH	2	/* 2 uSec Strobe Pulse (2x min) */

/* 1284 Extensibility Request values */
#define	ECPP_XREQ_NIBBLE	0x00    /* Nibble Mode Rev Channel Transfer */
#define	ECPP_XREQ_BYTE		0x01    /* Byte Mode Rev Channel Transfer */
#define	ECPP_XREQ_ID		0x04    /* Request Device ID */
#define	ECPP_XREQ_ECP		0x10    /* Request ECP Mode */
#define	ECPP_XREQ_ECPRLE	0x30    /* Request ECP Mode with RLE */
#define	ECPP_XREQ_EPP		0x40	/* Request EPP Mode */
#define	ECPP_XREQ_XLINK		0x80    /* Request Extensibility Link */

/* softintr flags */
#define	ECPP_SOFTINTR_PIONEXT	0x1	/* write next byte in PIO mode */

/* Stream  defaults */
#define	IO_BLOCK_SZ	1024 * 128	/* transfer buffer size */
#define	ECPPHIWAT	32 * 1024  * 6
#define	ECPPLOWAT	32 * 1024  * 4

/* Loop timers */
#define	ECPP_REG_WRITE_MAX_LOOP	100	/* cpu is faster than superio */
#define	ECPP_ISR_MAX_DELAY	30	/* DMAC slow PENDING status */

/* misc constants */
#define	ECPP_FIFO_SZ		16	/* FIFO size */
#define	FIFO_DRAIN_PERIOD	250000	/* max FIFO drain period in usec */
#define	NIBBLE_REV_BLKSZ	1024	/* send up to # bytes at a time */
#define	FWD_TIMEOUT_DEFAULT	90	/* forward xfer timeout in seconds */
#define	REV_TIMEOUT_DEFAULT	0	/* reverse xfer timeout in seconds */

/* ECP mode constants */
#define	ECP_REV_BLKSZ		1024	/* send up to # bytes at a time */
#define	ECP_REV_BLKSZ_MAX	(4 * 1024)	/* maximum of # bytes */
#define	ECP_REV_SPEED		(1 * 1024 * 1024)	/* bytes/sec */
#define	ECP_REV_MINTOUT		5	/* min ECP rev xfer timeout in ms */
#define	REV_WATCHDOG		100	/* poll DMA counter every # ms */

/* spurious interrupt detection */
#define	SPUR_CRITICAL		100	/* number of interrupts... */
#define	SPUR_PERIOD		1000000000 /* in # ns */

/*
 * Copyin/copyout states
 */
#define	ECPP_STRUCTIN		0
#define	ECPP_STRUCTOUT		1
#define	ECPP_ADDRIN 		2
#define	ECPP_ADDROUT		3

/*
 * As other ioctls require the same structure, put inner struct's into union
 */
struct ecpp_copystate {
	int	state;		/* see above */
	void	*uaddr;		/* user address of the following structure */
	union {
		struct ecpp_device_id		devid;
		struct prn_1284_device_id	prn_devid;
		struct prn_interface_info	prn_if;
	} un;
};

/*
 * The structure is dynamically created for each M_IOCTL and is bound to mblk
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", ecpp_copystate))

/* kstat structure */
struct ecppkstat {
	/*
	 * number of bytes, transferred in and out in each mode
	 */
	struct kstat_named	ek_ctx_obytes;
	struct kstat_named	ek_ctxpio_obytes;
	struct kstat_named	ek_nib_ibytes;
	struct kstat_named	ek_ecp_obytes;
	struct kstat_named	ek_ecp_ibytes;
	struct kstat_named	ek_epp_obytes;
	struct kstat_named	ek_epp_ibytes;
	struct kstat_named	ek_diag_obytes;
	/*
	 * number of transitions to particular mode
	 */
	struct kstat_named	ek_to_ctx;
	struct kstat_named	ek_to_nib;
	struct kstat_named	ek_to_ecp;
	struct kstat_named	ek_to_epp;
	struct kstat_named	ek_to_diag;
	/*
	 * other stats
	 */
	struct kstat_named	ek_xfer_tout;	/* # transfer timeouts */
	struct kstat_named	ek_ctx_cf;	/* # periph check failures */
	struct kstat_named	ek_joblen;	/* # bytes xfer'd since open */
	struct kstat_named	ek_isr_reattempt_high;	/* max # times */
							/* isr has looped */
	struct kstat_named	ek_mode;	/* 1284 mode */
	struct kstat_named	ek_phase;	/* 1284 ECP phase */
	struct kstat_named	ek_backchan;	/* backchannel mode supported */
	struct kstat_named	ek_iomode;	/* transfer mode: pio/dma */
	struct kstat_named	ek_state;	/* ecpp busy flag */
};

/* Macros for superio programming */
#define	PP_PUTB(x, y, z)  	ddi_put8(x, y, z)
#define	PP_GETB(x, y)		ddi_get8(x, y)

#define	DSR_READ(pp)		PP_GETB((pp)->i_handle, &(pp)->i_reg->dsr)
#define	DCR_READ(pp)		PP_GETB((pp)->i_handle, &(pp)->i_reg->dcr)
#define	ECR_READ(pp)		\
	(pp->noecpregs) ? 0xff : PP_GETB((pp)->f_handle, &(pp)->f_reg->ecr)
#define	DATAR_READ(pp)		PP_GETB((pp)->i_handle, &(pp)->i_reg->ir.datar)
#define	DFIFO_READ(pp)		\
	(pp->noecpregs) ? 0xff : PP_GETB((pp)->f_handle, &(pp)->f_reg->fr.dfifo)
#define	TFIFO_READ(pp)		\
	(pp->noecpregs) ? 0xff : PP_GETB((pp)->f_handle, &(pp)->f_reg->fr.tfifo)

#define	DCR_WRITE(pp, val)	PP_PUTB((pp)->i_handle, &(pp)->i_reg->dcr, val)
#define	ECR_WRITE(pp, val)	\
	if (!pp->noecpregs) PP_PUTB((pp)->f_handle, &(pp)->f_reg->ecr, val)
#define	DATAR_WRITE(pp, val)	\
			PP_PUTB((pp)->i_handle, &(pp)->i_reg->ir.datar, val)
#define	DFIFO_WRITE(pp, val)	\
	if (!pp->noecpregs) PP_PUTB((pp)->f_handle, &(pp)->f_reg->fr.dfifo, val)
#define	TFIFO_WRITE(pp, val)	\
	if (!pp->noecpregs) PP_PUTB((pp)->f_handle, &(pp)->f_reg->fr.tfifo, val)

/*
 * Macros to manipulate register bits
 */
#define	OR_SET_BYTE_R(handle, addr, val) \
{		\
	uint8_t tmpval;					\
	tmpval = ddi_get8(handle, (uint8_t *)addr);	\
	tmpval |= val;					\
	ddi_put8(handle, (uint8_t *)addr, tmpval);	\
}

#define	OR_SET_LONG_R(handle, addr, val) \
{		\
	uint32_t tmpval;				\
	tmpval = ddi_get32(handle, (uint32_t *)addr);	\
	tmpval |= val;					\
	ddi_put32(handle, (uint32_t *)addr, tmpval);	\
}

#define	AND_SET_BYTE_R(handle, addr, val) \
{		\
	uint8_t tmpval;					\
	tmpval = ddi_get8(handle, (uint8_t *)addr);	\
	tmpval &= val; 					\
	ddi_put8(handle, (uint8_t *)addr, tmpval);	\
}

#define	AND_SET_LONG_R(handle, addr, val) \
{		\
	uint32_t tmpval;				\
	tmpval = ddi_get32(handle, (uint32_t *)addr);	\
	tmpval &= val; 					\
	ddi_put32(handle, (uint32_t *)addr, tmpval);	\
}

#define	NOR_SET_LONG_R(handle, addr, val, mask) \
{		\
	uint32_t tmpval;				\
	tmpval = ddi_get32(handle, (uint32_t *)addr);	\
	tmpval &= ~(mask);				\
	tmpval |= val;					\
	ddi_put32(handle, (uint32_t *)addr, tmpval);	\
}

/*
 * Macros for Cheerio/RIO DMAC programming
 */
#define	SET_DMAC_CSR(pp, val)	ddi_put32(pp->uh.ebus.d_handle, \
				((uint32_t *)&pp->uh.ebus.dmac->csr), \
				((uint32_t)val))
#define	GET_DMAC_CSR(pp)	ddi_get32(pp->uh.ebus.d_handle, \
				(uint32_t *)&(pp->uh.ebus.dmac->csr))

#define	SET_DMAC_ACR(pp, val)	ddi_put32(pp->uh.ebus.d_handle, \
				((uint32_t *)&pp->uh.ebus.dmac->acr), \
				((uint32_t)val))

#define	GET_DMAC_ACR(pp)	ddi_get32(pp->uh.ebus.d_handle, \
				(uint32_t *)&pp->uh.ebus.dmac->acr)

#define	SET_DMAC_BCR(pp, val)	ddi_put32(pp->uh.ebus.d_handle, \
				((uint32_t *)&pp->uh.ebus.dmac->bcr), \
				((uint32_t)val))

#define	GET_DMAC_BCR(pp)	ddi_get32(pp->uh.ebus.d_handle, \
				((uint32_t *)&pp->uh.ebus.dmac->bcr))

#define	DMAC_RESET_TIMEOUT	10000	/* in usec */

/*
 * Macros to distinguish between PIO and DMA Compatibility mode
 */
#define	COMPAT_PIO(pp) (((pp)->io_mode == ECPP_PIO) &&		\
		    ((pp)->current_mode == ECPP_CENTRONICS ||	\
		    (pp)->current_mode == ECPP_COMPAT_MODE))

#define	COMPAT_DMA(pp) (((pp)->io_mode == ECPP_DMA) &&		\
		    ((pp)->current_mode == ECPP_CENTRONICS ||	\
		    (pp)->current_mode == ECPP_COMPAT_MODE))

/*
 * Other useful macros
 */
#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))
#define	offsetof(s, m)	((size_t)(&(((s *)0)->m)))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ECPPVAR_H */
