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

#ifndef _SYS_SCSI_ADAPTERS_ESPREG_H
#define	_SYS_SCSI_ADAPTERS_ESPREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Hardware definitions for ESP (Enhanced SCSI Processor) generation chips.
 */

/*
 * Include definition of DMA, DMA+, and ESC gate arrays
 */

#include <sys/dmaga.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ESP register definitions.
 */

/*
 * All current Sun implementations use the following layout.
 * That is, the ESP registers are always byte-wide, but are
 * accessed 32-bit words apart. Notice also that the byte-ordering
 * is big-endian.
 */

struct espreg {
	uint8_t	esp_xcnt_lo;		/* RW: transfer counter (low byte) */
					uint8_t _pad1, _pad2, _pad3;

	uint8_t	esp_xcnt_mid;		/* RW: transfer counter (mid byte) */
					uint8_t _pad5, _pad6, _pad7;

	uint8_t	esp_fifo_data;		/* RW: fifo data buffer */
					uint8_t _pad9, _pad10, _pad11;

	uint8_t	esp_cmd;		/* RW: command register */
					uint8_t _pad13, _pad14, _pad15;

	uint8_t	esp_stat;		/* R: status register */
#define	esp_busid	esp_stat	/* W: bus id for sel/resel */
					uint8_t _pad17, _pad18, _pad19;


	uint8_t	esp_intr;		/* R: interrupt status register */
#define	esp_timeout	esp_intr	/* W: sel/resel timeout */
					uint8_t _pad21, _pad22, _pad23;


	uint8_t	esp_step;		/* R: sequence step register */
#define	esp_sync_period esp_step	/* W: synchronous period */
					uint8_t _pad25, _pad26, _pad27;


	uint8_t	esp_fifo_flag;		/* R: fifo flag register */
#define	esp_sync_offset esp_fifo_flag	/* W: synchronous offset */
					uint8_t _pad29, _pad30, _pad31;


	uint8_t	esp_conf;		/* RW: configuration register */
					uint8_t _pad33, _pad34, _pad35;


	uint8_t	esp_clock_conv;		/* W: clock conversion register */
					uint8_t _pad37, _pad38, _pad39;


	uint8_t	esp_test;		/* RW: test register */
					uint8_t _pad41, _pad42, _pad43;


	uint8_t	esp_conf2;		/* ESP-II configuration register */
					uint8_t _pad45, _pad46, _pad47;

	uint8_t	esp_conf3;		/* ESP-III configuration register */
					uint8_t _pad49, _pad50, _pad51;

					uint8_t _pad52, _pad53, _pad54, _pad55;

	uint8_t	esp_xcnt_hi;		/* RW: transfer counter (hi byte) */
#define	esp_id_code esp_xcnt_hi		/* R: part-unique id code */
					uint8_t _pad57, _pad58, _pad59;

	uint8_t	esp_fifo_bottom;	/* RW: fifo data bottom */
					uint8_t _pad61, _pad62, _pad63;
};


/*
 * ESP command register definitions
 */

/*
 * These commands may be used at any time with the ESP chip.
 * None generate an interrupt, per se, although if you have
 * enabled detection of SCSI reset in setting the configuration
 * register, a CMD_RESET_SCSI will generate an interrupt.
 * Therefore, it is recommended that if you use the CMD_RESET_SCSI
 * command, you at least temporarily disable recognition of
 * SCSI reset in the configuration register.
 */

#define	CMD_NOP		0x0
#define	CMD_FLUSH	0x1
#define	CMD_RESET_ESP	0x2
#define	CMD_RESET_SCSI	0x3

/*
 * These commands will only work if the ESP is in the
 * 'disconnected' state:
 */

#define	CMD_RESEL_SEQ	0x40
#define	CMD_SEL_NOATN	0x41
#define	CMD_SEL_ATN	0x42
#define	CMD_SEL_STOP	0x43
#define	CMD_EN_RESEL	0x44	/* (no interrupt generated) */
#define	CMD_DIS_RESEL	0x45
#define	CMD_SEL_ATN3	0x46	/* (ESP100A/200, ESP236 only) */

/*
 * These commands will only work if the ESP is connected as
 * an initiator to a target:
 */

#define	CMD_TRAN_INFO	0x10
#define	CMD_COMP_SEQ	0x11
#define	CMD_MSG_ACPT	0x12
#define	CMD_TRAN_PAD	0x18
#define	CMD_SET_ATN	0x1a	/* (no interrupt generated) */
#define	CMD_CLR_ATN	0x1b	/* (no interrupt generated) (ESP236 only) */

/*
 * These commands will only work if the ESP is connected as
 * a target to an initiator:
 */
#define	CMD_DISCONNECT	0x27	/* (no interrupt generated) */

/*
 * DMA enable bit
 */

#define	CMD_DMA		0x80

/*
 * ESP fifo register definitions (read only)
 *
 * The first four bits are the count of bytes
 * in the fifo.
 *
 * Bit 5 is a 'offset counter not zero' flag for
 * the ESP100 only. On the ESP100A, the top 3 bits
 * of the fifo register are the 3 bits of the Sequence
 * Step register (if the ESP100A is not in TEST mode.
 * If the ESP100A is in TEST mode, then bit 5 has
 * the 'offset counter not zero' function). At least,
 * so states the documentation.
 *
 */

#define	FIFOSIZE		16
#define	MAX_FIFO_FLAG		(FIFOSIZE-1)
#define	ESP_FIFO_ONZ		0x20


/*
 * ESP status register definitions (read only)
 */

#define	ESP_STAT_RES	0x80	/* reserved (ESP100, ESP100A) */
#define	ESP_STAT_IPEND	0x80	/* interrupt pending (ESP-236 only) */
#define	ESP_STAT_GERR	0x40	/* gross error */
#define	ESP_STAT_PERR	0x20	/* parity error */
#define	ESP_STAT_XZERO	0x10	/* transfer counter zero */
#define	ESP_STAT_XCMP	0x8	/* transfer completed (target mode only) */
#define	ESP_STAT_MSG	0x4	/* scsi phase bit: MSG */
#define	ESP_STAT_CD	0x2	/* scsi phase bit: CD */
#define	ESP_STAT_IO	0x1	/* scsi phase bit: IO */

#define	ESP_STAT_BITS	\
	"\20\10IPND\07GERR\06PERR\05XZERO\04XCMP\03MSG\02CD\01IO"

/*
 * settings of status to reflect different information transfer phases
 */

#define	ESP_PHASE_MASK		(ESP_STAT_MSG | ESP_STAT_CD | ESP_STAT_IO)
#define	ESP_PHASE_DATA_OUT	0
#define	ESP_PHASE_DATA_IN	(ESP_STAT_IO)
#define	ESP_PHASE_COMMAND	(ESP_STAT_CD)
#define	ESP_PHASE_STATUS	(ESP_STAT_CD | ESP_STAT_IO)
#define	ESP_PHASE_MSG_OUT	(ESP_STAT_MSG | ESP_STAT_CD)
#define	ESP_PHASE_MSG_IN	(ESP_STAT_MSG | ESP_STAT_CD | ESP_STAT_IO)

/*
 * ESP interrupt status register definitions (read only)
 */

#define	ESP_INT_RESET	0x80	/* SCSI reset detected */
#define	ESP_INT_ILLEGAL 0x40	/* illegal cmd */
#define	ESP_INT_DISCON	0x20	/* disconnect */
#define	ESP_INT_BUS	0x10	/* bus service */
#define	ESP_INT_FCMP	0x8	/* function completed */
#define	ESP_INT_RESEL	0x4	/* reselected */
#define	ESP_INT_SELATN	0x2	/* selected with ATN */
#define	ESP_INT_SEL	0x1	/* selected without ATN */

#define	ESP_INT_BITS	\
	"\20\10RST\07ILL\06DISC\05BUS\04FCMP\03RESEL\02SATN\01SEL"

/*
 * ESP step register- only the least significant 3 bits are valid
 */

#define	ESP_STEP_MASK	0x7

#define	ESP_STEP_ARBSEL 0	/* Arbitration and select completed. */
				/* Not MESSAGE OUT phase. ATN* asserted. */

#define	ESP_STEP_SENTID 1	/* Sent one message byte. ATN* asserted. */
				/* (SELECT AND STOP command only). */

#define	ESP_STEP_NOTCMD 2	/* For SELECT WITH ATN command: */
				/*	Sent one message byte. ATN* off. */
				/*	Not COMMAND phase. */
				/* For SELECT WITHOUT ATN command: */
				/*	Not COMMAND phase. */
				/* For SELECT WITH ATN3 command: */
				/*	Sent one to three message bytes. */
				/*	Stopped due to unexpected phase */
				/*	change. If third message byte */
				/*	not sent, ATN* asserted.  */

#define	ESP_STEP_PCMD	3	/* Not all of command bytes transferred */
				/* due to premature phase change. */

#define	ESP_STEP_DONE	4	/* Complete sequence. */
#define	ESP_STEP_DONE5	5	/* Sometimes 5,6,7 occur on FAS101 instead */
#define	ESP_STEP_DONE6	6	/* of step == 4 due to flaky signals or */
#define	ESP_STEP_DONE7	7	/* bug in the chip */


/*
 * ESP configuration register definitions (read/write)
 */

#define	ESP_CONF_SLOWMODE	0x80	/* slow cable mode */
#define	ESP_CONF_DISRINT	0x40	/* disable reset int */
#define	ESP_CONF_PARTEST	0x20	/* parity test mode */
#define	ESP_CONF_PAREN		0x10	/* enable parity */
#define	ESP_CONF_CHIPTEST	0x8	/* chip test mode */
#define	ESP_CONF_BUSID		0x7	/* last 3 bits to be host id */

#define	DEFAULT_HOSTID		7

/*
 * ESP test register definitions (read/write)
 */

#define	ESP_TEST_TGT		0x1	/* target test mode */
#define	ESP_TEST_INI		0x2	/* initiator test mode */
#define	ESP_TEST_TRI		0x4	/* tristate test mode */

/*
 * ESP configuration register #2 definitions (read/write)
 * (ESP100A, ESP200, or ESP236 only)
 */

#define	ESP_CONF2_RESETF	0x80	/* Reserve FIFO byte (ESP-236 only) */

#define	ESP_CONF2_FENABLE	0x40	/* Features Enable (FAS100,216 only) */

#define	ESP_CONF2_STATPL	0x40	/* Enable Status Phase Latch */
					/* (ESP-236 only) */

#define	ESP_CONF2_BYTECM	0x20	/* Enable Byte Control Mode */
					/* (ESP-236 only) */

#define	ESP_CONF2_TRIDMA	0x10	/* Tristate DMA REQ */
#define	ESP_CONF2_SCSI2		0x8	/* SCSI-2 mode (target mode only) */
#define	ESP_CONF2_TBADPAR	0x4	/* Target Bad Parity Abort */

#define	ESP_CONF2_REGPAR	0x2	/* Register Parity Enable */
					/* (ESP200, ESP236 only) */

#define	ESP_CONF2_DMAPAR	0x1	/* DMA parity enable */
					/* (ESP200, ESP236 only) */

/*
 * ESP configuration #3 register definitions (read/write)
 * (ESP236, FAS236, and FAS100A)
 * Unfortunately, emulex has not been very consistent here
 */

#define	ESP_CONF3_236_IDRESCHK	0x80	/* ID message checking */
#define	ESP_CONF3_236_QUENB	0x40	/* 3-byte msg support */
#define	ESP_CONF3_236_CDB10	0x20	/* group 2 scsi-2 support */
#define	ESP_CONF3_236_FASTSCSI	0x10	/* 10 MB/S fast scsi mode */
#define	ESP_CONF3_236_FASTCLK	0x8	/* fast clock mode */
#define	ESP_CONF3_236_SAVERESB	0x4	/* save residual byte */
#define	ESP_CONF3_236_ALTDMA	0x2	/* enable alternate DMA mode */
#define	ESP_CONF3_236_THRESH8	0x1	/* enable threshold-8 mode */

#define	ESP_CONF3_100A_IDRESCHK 0x10	/* ID message checking */
#define	ESP_CONF3_100A_QUENB	0x8	/* 3-byte msg support */
#define	ESP_CONF3_100A_CDB10	0x4	/* group 2 scsi-2 support */
#define	ESP_CONF3_100A_FASTSCSI 0x2	/* 10 MB/S fast scsi mode */
#define	ESP_CONF3_100A_FASTCLK	0x1	/* fast clock mode */


/*
 * ESP part-unique id code definitions (read only)
 * (FAS236 and FAS100A only)
 */

#define	ESP_FAS100A		0x0	/* chip family code 0 */
#define	ESP_FAS236		0x2	/* chip family code 2 */
#define	ESP_REV_MASK		0x7	/* revision level mask */
#define	ESP_FCODE_MASK		0xf8	/* revision family code mask */


/*
 * Macros to get/set an integer (long or short) word into the 2 or 3  8-bit
 * registers that constitute the ESP's counter register.
 */

#define	SET_ESP_COUNT_16(ep, val)	\
	(ep)->esp_xcnt_lo = (uint8_t)(val), \
	(ep)->esp_xcnt_mid = (uint8_t)((val) >> 8)
#define	GET_ESP_COUNT_16(ep, val)	\
	(val) = (uint32_t)(ep)->esp_xcnt_lo |\
	(((uint32_t)(ep)->esp_xcnt_mid) << 8)
#define	SET_ESP_COUNT_24(ep, val)	\
	(ep)->esp_xcnt_lo = (uint8_t)(val), \
	(ep)->esp_xcnt_mid = (uint8_t)((val) >> 8), \
	(ep)->esp_xcnt_hi = (uint8_t)((val) >> 16)
#define	GET_ESP_COUNT_24(ep, val)	\
	(val) = (uint32_t)(ep)->esp_xcnt_lo | \
	(((uint32_t)(ep)->esp_xcnt_mid) << 8) | \
	(((uint32_t)(ep)->esp_xcnt_hi) << 16)

#define	GET_ESP_COUNT(ep, val)	\
	if (esp->e_espconf2 & ESP_CONF2_FENABLE) \
		GET_ESP_COUNT_24(ep, val); \
	else \
		GET_ESP_COUNT_16(ep, val);

#define	SET_ESP_COUNT(ep, val)	\
	if (esp->e_espconf2 & ESP_CONF2_FENABLE) \
		SET_ESP_COUNT_24(ep, val); \
	else \
		SET_ESP_COUNT_16(ep, val);

/*
 * The counter is a 16 bit counter only for the ESP.
 * If loaded with zero, it will do the full 64kb. If
 * we define maxcount to be 64kb, then the low order
 * 16 bits will be zero, and the register will be
 * properly loaded.
 * For FAS chips we can use the 24 bit counter
 */
#define	ESP_MAX_DMACOUNT \
	((esp->e_espconf2 & ESP_CONF2_FENABLE) ? 0x1000000 : 0x10000)

/*
 * ESP Clock constants
 */

/*
 * The probe routine will select amongst these values
 * and stuff it into the tag e_clock_conv in the private host
 * adapter structure (see below) (as well as the the register esp_clock_conv
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
 * This yields nanoseconds per input clock tick
 */

#define	CLOCK_PERIOD(mhz)	(1000 * MEG) / (mhz / 1000)
#define	CONVERT_PERIOD(time)	((time) + 3) >> 2

/*
 * Formula to compute the select/reselect timeout register value:
 *
 *	Time_unit = 7682 * CCF * Input_Clock_Period
 *
 * where Time_unit && Input_Clock_Period should be in the same units.
 * CCF = Clock Conversion Factor from CLOCK_XMHZ above.
 * Desired_Timeout_Period = 250 ms.
 *
 */

#define	ESP_CLOCK_DELAY 7682
#define	ESP_CLOCK_TICK(esp)	\
	((uint_t)ESP_CLOCK_DELAY * (uint_t)(esp)->e_clock_conv * \
	(uint_t)(esp)->e_clock_cycle) / (uint_t)1000
#define	ESP_SEL_TIMEOUT (250 * MEG)
#define	ESP_CLOCK_TIMEOUT(tick, selection_timeout) \
	(((selection_timeout) * MEG) + (tick) - 1) / (tick)

/*
 * Max/Min number of clock cycles for synchronous period
 */

#define	MIN_SYNC_FAST(esp)	4
#define	MIN_SYNC_SLOW(esp)	\
	(((esp)->e_espconf & ESP_CONF_SLOWMODE)? 5 : 4)
#define	MIN_SYNC(esp)	\
	(((esp)->e_options & ESP_OPT_FAS) ? \
	(MIN_SYNC_FAST((esp))) :  (MIN_SYNC_SLOW((esp))))
#define	MAX_SYNC(esp)		35
#define	SYNC_PERIOD_MASK	0x1F

/*
 * Max/Min time (in nanoseconds) between successive Req/Ack
 */

#define	MIN_SYNC_TIME(esp)	\
	((uint_t)MIN_SYNC((esp)) * (uint_t)((esp)->e_clock_cycle)) / \
	    (uint_t)1000
#define	MAX_SYNC_TIME(esp)	\
	((uint_t)MAX_SYNC((esp)) * (uint_t)((esp)->e_clock_cycle)) / \
	    (uint_t)1000

/*
 * Max/Min Period values (appropriate for SYNCHRONOUS message).
 * We round up here to make sure that we are always slower
 * (longer time period).
 */

#define	MIN_SYNC_PERIOD(esp)	(CONVERT_PERIOD(MIN_SYNC_TIME((esp))))
#define	MAX_SYNC_PERIOD(esp)	(CONVERT_PERIOD(MAX_SYNC_TIME((esp))))

/*
 * According to the Emulex application notes for this part,
 * the ability to receive synchronous data is independent
 * of the ESP chip's input clock rate, and is fixed at
 * a maximum 5.6 mb/s (180 ns/byte).
 *
 * Therefore, we could tell targets that we can *receive*
 * synchronous data this fast.
 * However, the rest of the transfer is still at 5.0 MB/sec so to keep it
 * simple, we negotiate 200 ns
 * On a c2,  a period of 45 and 50 result in the same register value (8) and
 * consequently 5 MB/sec.
 */

#define	DEFAULT_SYNC_PERIOD		200		/* 5.0 MB/s */
#define	DEFAULT_FASTSYNC_PERIOD		100		/* 10.0 MB/s */

#define	FASTSCSI_THRESHOLD		50		/* 5.0 MB/s */


/*
 * Short hand macro convert parameter in
 * nanoseconds/byte into k-bytes/second.
 */

#define	ESP_SYNC_KBPS(ns)	((((1000 * MEG) / (ns)) + 999) / 1000)


/*
 * Default Synchronous offset.
 * (max # of allowable outstanding REQ)
 */

#define	DEFAULT_OFFSET	15

/*
 * Chip type defines && macros
 */

#define	ESP100		0
#define	NCR53C90	0
#define	ESP100A		1
#define	NCR53C90A	1
#define	ESP236		2
#define	FAS100		3
#define	FAS100A		3
#define	FAS236		4
#define	FAST		5

#define	IS_53C90(esp)	((esp)->e_type == NCR53C90)

/*
 * Compatibility hacks
 */

#define	ESP_SIZE		0x2000		/* ESP and DVMA space */

#define	DMAGA_OFFSET		0x1000		/* Offset of DMA registers */
						/* for STINGRAY && HYDRA. */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_ESPREG_H */
