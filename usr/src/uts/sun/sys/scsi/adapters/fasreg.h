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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SCSI_ADAPTERS_FASREG_H
#define	_SYS_SCSI_ADAPTERS_FASREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * FAS register	definitions.
 */

/*
 * All current Sun implementations use the following layout.
 * That	is, the	FAS registers are always byte-wide, but	are
 * accessed longwords apart. Notice also that the byte-ordering
 * is big-endian.
 */

struct fasreg {
	uint8_t	fas_xcnt_lo;		/* RW: transfer	counter	(low byte) */
					uint8_t _pad1, _pad2, _pad3;

	uint8_t	fas_xcnt_mid;		/* RW: transfer	counter	(mid byte) */
					uint8_t _pad5, _pad6, _pad7;

	uint8_t	fas_fifo_data;		/* RW: fifo data buffer	*/
					uint8_t _pad9, _pad10, _pad11;

	uint8_t	fas_cmd;		/* RW: command register	*/
					uint8_t _pad13, _pad14, _pad15;

	uint8_t	fas_stat;		/* R: status register */
#define	fas_busid	fas_stat	/* W: bus id for sel/resel */
					uint8_t _pad17, _pad18, _pad19;


	uint8_t	fas_intr;		/* R: interrupt	status register	*/
#define	fas_timeout	fas_intr	/* W: sel/resel	timeout	*/
					uint8_t _pad21, _pad22, _pad23;


	uint8_t	fas_step;		/* R: sequence step register */
#define	fas_sync_period	fas_step	/* W: synchronous period */
					uint8_t _pad25, _pad26, _pad27;


	uint8_t	fas_fifo_flag;		/* R: fifo flag	register */
#define	fas_sync_offset	fas_fifo_flag	/* W: synchronous offset */
					uint8_t _pad29, _pad30, _pad31;


	uint8_t	fas_conf;		/* RW: configuration register */
					uint8_t _pad33, _pad34, _pad35;


	uint8_t	fas_clock_conv;		/* W: clock conversion register	*/
					uint8_t _pad37, _pad38, _pad39;
#define	fas_stat2	fas_clock_conv


	uint8_t	fas_test;		/* RW: test register */
					uint8_t _pad41, _pad42, _pad43;
#define	fas_conf4	fas_test


	uint8_t	fas_conf2;		/* FAS-II configuration	register */
					uint8_t _pad45, _pad46, _pad47;


	uint8_t	fas_conf3;		/* FAS-III configuration register */
					uint8_t _pad49, _pad50, _pad51;
					uint8_t _pad_reserved[4];

	uint8_t	fas_recmd_lo;		/* RW: fifo recmd counter lo */
#define	fas_id_code fas_recmd_lo	/* R: part-unique id code */
					uint8_t _pad52, _pad53, _pad54;

	uint8_t	fas_recmd_hi;		/* RW: fifo recmd counter lo */
					uint8_t _pad55, _pad56, _pad57;
};


/*
 * FAS command register	definitions
 */

/*
 * These commands may be used at any time with the FAS chip.
 * None	generate an interrupt, per se, although	if you have
 * enabled detection of	SCSI reset in setting the configuration
 * register, a CMD_RESET_SCSI will generate an interrupt.
 * Therefore, it is recommended	that if	you use	the CMD_RESET_SCSI
 * command, you	at least temporarily disable recognition of
 * SCSI	reset in the configuration register.
 */
#define	CMD_NOP		0x0
#define	CMD_FLUSH	0x1
#define	CMD_RESET_FAS	0x2
#define	CMD_RESET_SCSI	0x3

/*
 * These commands will only work if the	FAS is in the
 * 'disconnected' state:
 */
#define	CMD_RESEL_SEQ	0x40
#define	CMD_SEL_NOATN	0x41
#define	CMD_SEL_ATN	0x42
#define	CMD_SEL_STOP	0x43
#define	CMD_EN_RESEL	0x44	/* (no interrupt generated) */
#define	CMD_DIS_RESEL	0x45
#define	CMD_SEL_ATN3	0x46

/*
 * These commands will only work if the	FAS is connected as
 * an initiator	to a target:
 */
#define	CMD_TRAN_INFO	0x10
#define	CMD_COMP_SEQ	0x11
#define	CMD_MSG_ACPT	0x12
#define	CMD_TRAN_PAD	0x18
#define	CMD_SET_ATN	0x1a	/* (no interrupt generated) */
#define	CMD_CLR_ATN	0x1b	/* (no interrupt generated) */

/*
 * These commands will only work if the	FAS is connected as
 * a target to an initiator:
 */
#define	CMD_DISCONNECT	0x27	/* (no interrupt generated) */

/*
 * DMA enable bit
 */
#define	CMD_DMA		0x80

/*
 * FAS fifo register definitions (read only)
 */
#define	FIFOSIZE		16
#define	MAX_FIFO_FLAG		(FIFOSIZE-1)
#define	FAS_FIFO_ONZ		0x20
#define	FIFO_CNT_MASK		0x1f

/*
 * FAS status register definitions (read only)
 */
#define	FAS_STAT_IPEND	0x80	/* interrupt pending */
#define	FAS_STAT_GERR	0x40	/* gross error */
#define	FAS_STAT_PERR	0x20	/* parity error	*/
#define	FAS_STAT_XZERO	0x10	/* transfer counter zero */
#define	FAS_STAT_XCMP	0x8	/* transfer completed (target mode only) */
#define	FAS_STAT_MSG	0x4	/* scsi	phase bit: MSG */
#define	FAS_STAT_CD	0x2	/* scsi	phase bit: CD */
#define	FAS_STAT_IO	0x1	/* scsi	phase bit: IO */

#define	FAS_STAT_BITS	\
	"\20\10IPND\07GERR\06PERR\05XZERO\04XCMP\03MSG\02CD\01IO"

/*
 * settings of status to reflect different information transfer	phases
 */
#define	FAS_PHASE_MASK		(FAS_STAT_MSG |	FAS_STAT_CD | FAS_STAT_IO)
#define	FAS_PHASE_DATA_OUT	0
#define	FAS_PHASE_DATA_IN	(FAS_STAT_IO)
#define	FAS_PHASE_COMMAND	(FAS_STAT_CD)
#define	FAS_PHASE_STATUS	(FAS_STAT_CD | FAS_STAT_IO)
#define	FAS_PHASE_MSG_OUT	(FAS_STAT_MSG |	FAS_STAT_CD)
#define	FAS_PHASE_MSG_IN	(FAS_STAT_MSG |	FAS_STAT_CD | FAS_STAT_IO)

/*
 * FAS interrupt status	register definitions (read only)
 */

#define	FAS_INT_RESET	0x80	/* SCSI	reset detected */
#define	FAS_INT_ILLEGAL	0x40	/* illegal cmd */
#define	FAS_INT_DISCON	0x20	/* disconnect */
#define	FAS_INT_BUS	0x10	/* bus service */
#define	FAS_INT_FCMP	0x8	/* function completed */
#define	FAS_INT_RESEL	0x4	/* reselected */
#define	FAS_INT_SELATN	0x2	/* selected with ATN */
#define	FAS_INT_SEL	0x1	/* selected without ATN	*/

#define	FAS_INT_BITS	\
	"\20\10RST\07ILL\06DISC\05BUS\04FCMP\03RESEL\02SATN\01SEL"

/*
 * FAS step register- only the least significant 3 bits	are valid
 */
#define	FAS_STEP_MASK	0x7

#define	FAS_STEP_ARBSEL	0	/* Arbitration and select completed. */
				/* Not MESSAGE OUT phase. ATN* asserted. */

#define	FAS_STEP_SENTID	1	/* Sent	one message byte. ATN* asserted. */
				/* (SELECT AND STOP command only). */

#define	FAS_STEP_NOTCMD	2	/* For SELECT WITH ATN command:	*/
				/*	Sent one message byte. ATN* off. */
				/*	Not COMMAND phase. */
				/* For SELECT WITHOUT ATN command: */
				/*	Not COMMAND phase. */
				/* For SELECT WITH ATN3	command: */
				/*	Sent one to three message bytes. */
				/*	Stopped	due to unexpected phase	*/
				/*	change.	If third message byte */
				/*	not sent, ATN* asserted.  */

#define	FAS_STEP_PCMD	3	/* Not all of command bytes transferred	*/
				/* due to premature phase change. */

#define	FAS_STEP_DONE	4	/* Complete sequence. */

/*
 * FAS configuration register definitions (read/write)
 */
#define	FAS_CONF_SLOWMODE	0x80	/* slow	cable mode */
#define	FAS_CONF_DISRINT	0x40	/* disable reset int */
#define	FAS_CONF_PARTEST	0x20	/* parity test mode */
#define	FAS_CONF_PAREN		0x10	/* enable parity */
#define	FAS_CONF_CHIPTEST	0x8	/* chip	test mode */
#define	FAS_CONF_BUSID		0x7	/* last	3 bits to be host id */

#define	DEFAULT_HOSTID		7

/*
 * FAS test register definitions (read/write)
 */
#define	FAS_TEST_TGT		0x1	/* target test mode */
#define	FAS_TEST_INI		0x2	/* initiator test mode */
#define	FAS_TEST_TRI		0x4	/* tristate test mode */

/*
 * FAS configuration register #2 definitions (read/write)
 */
#define	FAS_CONF2_XL32		0x80
#define	FAS_CONF2_MKDONE	0x40
#define	FAS_CONF2_PAUSE_INTR_DISABLE 0x20
#define	FAS_CONF2_FENABLE	0x10	/* Features Enable */
#define	FAS_CONF2_SCSI2		0x8	/* SCSI-2 mode (target mode only) */
#define	FAS_CONF2_TGT_BAD_PRTY_ABORT 0x4
#define	FAS_CONF2_DMA_PRTY_ENABLE    0x1

/*
 * FAS configuration #3	register definitions (read/write)
 */
#define	FAS_CONF3_ODDBYTE_AUTO	0x80	/* auto push an odd-byte to dma */
#define	FAS_CONF3_WIDE		0x40	/* enables wide	*/
#define	FAS_CONF3_IDBIT3	0x20	/* extends scsi	bus ID to 4 bits */
#define	FAS_CONF3_IDRESCHK	0x10	/* ID message checking */
#define	FAS_CONF3_QUENB		0x8	/* 3-byte msg support */
#define	FAS_CONF3_CDB10		0x4	/* group 2 scsi-2 support */
#define	FAS_CONF3_FASTSCSI	0x2	/* 10 MB/S fast	scsi mode */
#define	FAS_CONF3_FASTCLK	0x1	/* fast	clock mode */

/*
 * FAS configuration #4 register definitions
 */
#define	FAS_CONF4_PADMSGS	0x20

/*
 * FAS part-unique id code definitions (read only)
 */
#define	FAS_REV_MASK		0x7	/* revision level mask */
#define	FAS_FCODE_MASK		0xf8	/* revision family code	mask */

/*
 * Macros to get/set an	integer	word into the 4 8-bit
 * registers that constitute the FAS's counter register.
 */
#define	SET_FAS_COUNT(fasreg, val) {	\
	fas_reg_write(fas, &fasreg->fas_xcnt_lo, (uint8_t)val); \
	fas_reg_write(fas, &fasreg->fas_xcnt_mid, \
		(uint8_t)(val >>	8)); \
	fas_reg_write(fas, &fasreg->fas_recmd_lo, \
		((uint8_t)(val >> 16)));	\
	fas_reg_write(fas, &fasreg->fas_recmd_hi, 0); \
}

/*
 * to save time, read back 3 registers
 */
#define	GET_FAS_COUNT(fasreg, val) {	\
	uint8_t lo, mid, r_lo; \
	lo = fas_reg_read(fas, &fasreg->fas_xcnt_lo); \
	mid = fas_reg_read(fas,	&fasreg->fas_xcnt_mid);	\
	r_lo = fas_reg_read(fas, &fasreg->fas_recmd_lo); \
	(val) =	(uint32_t)(lo | (mid << 8) | ((r_lo) << 16)); \
}



/*
 * FAS Clock constants
 */

/*
 * The probe routine will select amongst these values
 * and stuff it	into the tag f_clock_conv in the private host
 * adapter structure (see below) (as well as the the register fas_clock_conv
 * on the chip)
 */
#define	CLOCK_10MHZ		2
#define	CLOCK_15MHZ		3
#define	CLOCK_20MHZ		4
#define	CLOCK_25MHZ		5
#define	CLOCK_30MHZ		6
#define	CLOCK_35MHZ		7
#define	CLOCK_40MHZ		8	/* really 0 */
#define	CLOCK_MASK		0x7

/*
 * This	yields nanoseconds per input clock tick
 */

#define	CLOCK_PERIOD(mhz)	(1000 *	MEG) / (mhz / 1000)
#define	CONVERT_PERIOD(time)	((time) + 3) >> 2

/*
 * Formula to compute the select/reselect timeout register value:
 *
 *	Time_unit = 7682 * CCF * Input_Clock_Period
 *
 * where Time_unit && Input_Clock_Period should	be in the same units.
 * CCF = Clock Conversion Factor from CLOCK_XMHZ above.
 * Desired_Timeout_Period = 250	ms.
 *
 */
#define	FAS_CLOCK_DELAY	7682
#define	FAS_CLOCK_TICK(fas)	\
	((uint_t)FAS_CLOCK_DELAY * (uint_t)(fas)->f_clock_conv * \
	(uint_t)(fas)->f_clock_cycle) / (uint_t)1000
#define	FAS_SEL_TIMEOUT	(250 * MEG)
#define	FAS_CLOCK_TIMEOUT(tick,	selection_timeout) \
	(((selection_timeout) *	MEG) + (tick) -	1) / (tick)

/*
 * Max/Min number of clock cycles for synchronous period
 */
#define	MIN_SYNC_FAST(fas)	4
#define	MIN_SYNC_SLOW(fas)	\
	(((fas)->e_fasconf & FAS_CONF_SLOWMODE) ? 6 : 5)
#define	MIN_SYNC(fas)		(MIN_SYNC_FAST((fas)))
#define	MAX_SYNC(fas)		35
#define	SYNC_PERIOD_MASK	0x1F

/*
 * Max/Min time	(in nanoseconds) between successive Req/Ack
 */
#define	MIN_SYNC_TIME(fas)	\
	((uint_t)MIN_SYNC((fas)) * (uint_t)((fas)->f_clock_cycle)) / \
	    (uint_t)1000
#define	MAX_SYNC_TIME(fas)	\
	((uint_t)MAX_SYNC((fas)) * (uint_t)((fas)->f_clock_cycle)) / \
	    (uint_t)1000

/*
 * Max/Min Period values (appropriate for SYNCHRONOUS message).
 * We round up here to make sure that we are always slower
 * (longer time	period).
 */
#define	MIN_SYNC_PERIOD(fas)	(CONVERT_PERIOD(MIN_SYNC_TIME((fas))))
#define	MAX_SYNC_PERIOD(fas)	(CONVERT_PERIOD(MAX_SYNC_TIME((fas))))

/*
 * According to	the Emulex application notes for this part,
 * the ability to receive synchronous data is independent
 * of the FAS chip's input clock rate, and is fixed at
 * a maximum 5.6 mb/s (180 ns/byte).
 *
 * Therefore, we could tell targets that we can	*receive*
 * synchronous data this fast.
 * However, the	rest of	the transfer is	still at 5.0 MB/sec so to keep it
 * simple, we negotiate	200 ns
 * On a	c2,  a period of 45 and	50 result in the same register value (8) and
 * consequently	5 MB/sec.
 */
#define	DEFAULT_SYNC_PERIOD		200		/* 5.0 MB/s */
#define	DEFAULT_FASTSYNC_PERIOD		100		/* 10.0	MB/s */
#define	FASTSCSI_THRESHOLD		50		/* 5.0 MB/s */

/*
 * Short hand macro convert parameter in
 * nanoseconds/byte into k-bytes/second.
 */
#define	FAS_SYNC_KBPS(ns)	((((1000 * MEG) / (ns)) + 999) / 1000)

/*
 * Default Synchronous offset.
 * (max	# of allowable outstanding REQ)
 * IBS allows only 11 bytes offset
 */
#define	DEFAULT_OFFSET	15

/*
 * Chip	type defines &&	macros
 */
#define	FAS366		0
#define	FAST		5

/* status register #2 definitions (read	only) */
#define	FAS_STAT2_SEQCNT   0x01	   /* Sequence counter bit 7-3 enabled */
#define	FAS_STAT2_FLATCHED 0x02	   /* FIFO flags register latched */
#define	FAS_STAT2_CLATCHED 0x04	   /* Xfer cntr	& recommand ctr	latched */
#define	FAS_STAT2_CACTIVE  0x08	   /* Command register is active */
#define	FAS_STAT2_SCSI16   0x10	   /* SCSI interface is	wide */
#define	FAS_STAT2_ISHUTTLE 0x20	   /* FIFO Top register	contains 1 byte */
#define	FAS_STAT2_OSHUTTLE 0x40	   /* next byte	from FIFO is MSB */
#define	FAS_STAT2_EMPTY	   0x80	   /* FIFO is empty */

/*
 * select/reselect bus id register
 */
#define	FAS_BUSID_ENCODID	0x10	/* encode reselection ID */
#define	FAS_BUSID_32BIT_COUNTER	0x40	/* xfer	counter	is 32 bit */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_FASREG_H */
